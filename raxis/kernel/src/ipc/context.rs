// raxis-kernel::ipc::context — HandlerContext shared state for IPC handlers.
//
// Normative reference: kernel-core.md §2.2 `src/handlers/context.rs`.
//
// HandlerContext is the dependency-injected read-only (or Arc-shared) context
// passed to every IPC handler. It is constructed once in main.rs after all
// startup steps complete and cloned (via Arc) into each connection task.
//
// Fields added vs the minimal v1 starter:
//   witness_dir — absolute path to <data_dir>/witness/ blob store. Required
//                 by handlers/witness.rs per spec §2.3 witness.rs: "blob bytes
//                 and WitnessIndexCtx are mandatory".

use std::path::PathBuf;
use std::sync::Arc;

use arc_swap::ArcSwap;
use raxis_audit_tools::AuditSink;
use raxis_credential_proxy_manager::CredentialProxyManager;
use raxis_credentials::CredentialBackend;
use raxis_domain::DomainAdapter;
use raxis_domain_git::{SeIntentKind, SeTerminalArtefact};
use raxis_image_cache::{ImageResolver, PrePopulatedResolver};
use raxis_isolation::Backend as IsolationBackend;
use raxis_policy::PolicyBundle;
use raxis_session_spawn::SessionSpawnService;
use raxis_store::Store;

use crate::authority::cert_check::CertEnforcer;
use crate::authority::keys::KeyRegistry;
use crate::gateway::client::GatewayClient;
use crate::initiatives::PlanRegistry;
use crate::prompt::EpochBinding;
use crate::session_spawn_orchestrator::{ExecutorSpawnContext, OrchestratorSpawn};

/// Shared, read-only context for all IPC handlers.
///
/// All fields are `Arc`-wrapped so each connection task gets a cheap clone.
/// The `store` is behind `Store` which itself contains a `tokio::sync::Mutex`.
pub struct HandlerContext {
    /// Validated policy bundle, behind an `ArcSwap` so the kernel can flip
    /// the visible epoch in-process from `policy_manager::advance_epoch`
    /// without a kernel restart (kernel-core.md §`policy_manager.rs`).
    ///
    /// **Read pattern:** all callers use `ctx.policy.load()` which returns
    /// a cheap `arc_swap::Guard<Arc<PolicyBundle>>` that can be deref'd to
    /// `&PolicyBundle`. Long-lived borrows should `policy.load_full()` to
    /// hold an owned `Arc<PolicyBundle>`. Because reads are wait-free,
    /// holding a guard across an `await` boundary is safe — the underlying
    /// `Arc` is detached from the `ArcSwap`'s read counter the moment a
    /// new bundle is `store()`'d, so the swap will not block on us.
    pub policy: Arc<ArcSwap<PolicyBundle>>,
    /// Kernel key registry — authority + quality keypairs + verifier token key.
    pub registry: Arc<KeyRegistry>,
    /// SQLite state store (WAL mode, synchronous=FULL, foreign_keys=ON).
    pub store: Arc<Store>,
    /// Append-only audit sink. Production wiring is `FileAuditSink` over
    /// the JSONL segment under `<data_dir>/audit/`. Tests use
    /// `FakeAuditSink`.
    ///
    /// Per kernel-store.md §2.5.2, every audit emission MUST follow a
    /// successful SQLite commit; the trait does not enforce this — the
    /// kernel review process does. See `lifecycle::approve_plan` for a
    /// canonical use site (commit → drop store mutex → emit).
    pub audit: Arc<dyn AuditSink>,
    /// Absolute path to the kernel data directory (e.g. `~/.raxis`).
    pub data_dir: PathBuf,
    /// Absolute path to the witness blob store (`<data_dir>/witness/`).
    ///
    /// Spec §2.3 witness.rs: all witness blob writes go through
    /// `witness_index::write(record, blob, &ctx.witness_dir, store)`.
    /// The directory is created at bootstrap time and always exists by
    /// the time the IPC server starts (startup step 5, store open).
    pub witness_dir: PathBuf,
    /// In-memory per-task plan-fields registry.
    ///
    /// Per kernel-store.md §2.5.8 line 1911, the four path-scope fields
    /// (`path_allowlist`, `path_export_to_successors`, `path_export_globs`,
    /// `path_scope_override`) are NOT persisted to the `tasks` table —
    /// they are parsed from the signed plan artifact at `approve_plan`
    /// time and held here. Read by `path_scope::effective_allow` on
    /// every intent admission and at CompleteTask. Refilled at boot by
    /// `initiatives::lifecycle::repopulate_plan_registry`.
    pub plan_registry: Arc<PlanRegistry>,

    /// Active gateway client. Cheap to clone; shared with the
    /// `gateway::supervisor` (which writes `set_expected_token` before
    /// each spawn) and with `gateway::accept` (which calls
    /// `install_connection` on a successful handshake). Handlers that
    /// need to forward provider calls (data fetch, inference) call
    /// `ctx.gateway.fetch(...)`. When no gateway is connected the
    /// fetch returns `GatewayCallError::Unavailable`; handlers MUST
    /// surface this as a planner-facing rejection rather than block.
    pub gateway: Arc<GatewayClient>,

    /// In-memory tracker for session-prompt epoch validity (kernel-core.md
    /// §2.3 `prompt::epoch_binding`). Read by `prompt::assemble` to log
    /// `PromptReassembled { reason: EpochAdvance }` when an epoch advance
    /// happens between assembly rounds. Written by
    /// `policy_manager::advance_epoch` which calls `mark_all_invalid`
    /// over the current set of active session IDs.
    pub epoch_binding: Arc<EpochBinding>,

    /// Operator-cert four-zone runtime gate (kernel-core.md
    /// §`authority/cert_check.rs`). Owns the in-process dedupe set
    /// for `OperatorCertExpiringSoon` / `OperatorCertInGracePeriod`
    /// audits so a chatty operator cannot flood the chain with
    /// expiry warnings. Used by the operator IPC dispatcher between
    /// the `permitted_ops` gate and handler dispatch — see
    /// `ipc::operator::accept_operator_loop` for the call site.
    pub cert_enforcer: Arc<CertEnforcer>,

    /// V2 agent-runtime substrate selected at boot. Always
    /// present — `kernel/src/main.rs` exits with
    /// `BOOT_ERR_ISOLATION_UNAVAILABLE` (code 64) when
    /// `isolation_select::select_isolation_backend` returns
    /// `Err`, so by the time any IPC handler is dispatched the
    /// kernel is guaranteed to have an admissible
    /// substrate (Linux+KVM ⇒ Firecracker; macOS ⇒ AVF).
    ///
    /// **Why non-Option** (vs. the V1 `Option<Arc<...>>` shape):
    /// session-spawn code paths can dispatch through this field
    /// directly without a `None` guard at every call site. The
    /// substrate-unavailable failure mode is moved entirely into
    /// kernel boot — there is no longer a degraded-mode kernel
    /// that admits operator queries while refusing every spawn.
    ///
    /// Threaded into `HandlerContext` per `extensibility-traits.md
    /// §3.8` boot-order step 6a so every IPC handler dispatches
    /// through the same `Arc<dyn Backend>` clone.
    pub isolation: Arc<dyn IsolationBackend>,

    /// V2 credential-store backend selected at boot.
    ///
    /// Always present — the kernel boot path constructs a default
    /// [`raxis_credentials_file::FileCredentialBackend`] when
    /// `policy.toml` omits `[credential_backend]`, then wraps it in
    /// `raxis_credentials::AuditingBackend` so every resolve emits
    /// the spec-mandated `CredentialAccessed` event. Consumed by
    /// the credential proxy (per session) and the gateway (provider
    /// API keys). Per `extensibility-traits.md §4.4`.
    ///
    /// **Why non-Option** (unlike `isolation`): a kernel without a
    /// credential backend cannot spawn any session that declares
    /// `[[tasks.credentials]]` and cannot dispatch any
    /// `FetchRequest` because the gateway needs provider API keys.
    /// The `File` default is universally available (it just reads
    /// from `<data_dir>/credentials/`), so there is no degraded
    /// boot mode that could legitimately leave this `None`.
    pub credentials: Arc<dyn CredentialBackend>,

    /// V2 per-session credential-proxy lifecycle manager.
    ///
    /// Constructed once at kernel boot from the same
    /// `Arc<dyn CredentialBackend>` as `credentials` above (so the
    /// proxy resolves the same names through the same audit
    /// chain) plus the same `Arc<dyn AuditSink>` as `audit` (so the
    /// `CredentialProxyStarted` / `CredentialProxyStopped` lifecycle
    /// events land in the canonical chain rather than a side
    /// channel). The kernel calls
    /// `proxy_manager.start_for_session(session_id, task_id,
    /// &task_decls)` at session-spawn time AFTER `tx.commit()` and
    /// BEFORE the in-VM agent process is started, so the loopback
    /// addresses returned by the manager are the values the kernel
    /// injects into the VM environment (`DATABASE_URL`, `KUBECONFIG`,
    /// etc.). At teardown the kernel calls `handles.shutdown()` to
    /// abort the listeners and emit one `CredentialProxyStopped`
    /// per proxy with the final counter snapshot.
    ///
    /// **Why non-Option**: a kernel without a proxy manager cannot
    /// admit any session that declares `[[tasks.credentials]]` —
    /// failing closed at session-spawn would be a worse user
    /// experience than failing closed at boot. The constructor
    /// is universally available (it just needs the
    /// `Arc<dyn CredentialBackend>` we already have), so there is
    /// no degraded boot mode that could legitimately leave this
    /// `None`.
    pub proxy_manager: Arc<CredentialProxyManager>,

    /// V2 per-session VM-spawn composer.
    ///
    /// Wraps the `(isolation, proxy_manager, audit)` tuple plus a
    /// per-spawn `Box<dyn AdmissionService>` into the single async
    /// surface the kernel calls when an orchestrator-driven trigger
    /// fires (`spawn_session`) and at session teardown
    /// (`terminate_session`). Owns the per-session admission-loop
    /// listener lifetime + the live `Box<dyn IsolationSession>`
    /// handle table.
    ///
    /// Constructed once at kernel boot from the same trios this
    /// `HandlerContext` already carries — there is no other
    /// independent state. The service ALONE knows which sessions
    /// have a live VM right now (`SessionSpawnService::is_active`);
    /// the SQLite `sessions` table is the operator-visible row, the
    /// service's in-memory table is the substrate-visible row.
    /// Both are reconciled at boot through the spawn callsite (see
    /// `extensibility-traits.md §3.5`).
    ///
    /// **Why non-Option**: the kernel cannot drive any production
    /// session-spawn without it. Failing closed at session-spawn
    /// time would be a worse user experience than failing closed at
    /// boot, and the constructor only needs the `Arc`s we already
    /// have, so there is no degraded boot mode that could
    /// legitimately leave this `None`.
    pub session_spawn: Arc<SessionSpawnService>,

    /// V2 orchestrator-spawn surface — the trait `handle_approve_plan`
    /// calls to drive the canonical Orchestrator VM boot after the
    /// SQL transaction has committed.
    ///
    /// Production wires `LiveOrchestratorSpawn` (delegates to
    /// `SessionSpawnService::spawn_session` against the real
    /// canonical image bytes resolved via the boot-time install-dir).
    /// In-process unit tests that exercise the IPC dispatch tree but
    /// do NOT need a real substrate boot wire `NoopOrchestratorSpawn`
    /// (cfg-gated) which records the call in a counter and returns
    /// `Ok(())` without touching the substrate. Behaviour-shaped
    /// tests that DO need a real spawn (e.g.
    /// `session_spawn_orchestrator::tests::*`) wire
    /// `LiveOrchestratorSpawn` themselves against a tempdir-built
    /// fake image.
    ///
    /// **Why a trait** (vs. an `Option<OrchestratorSpawnContext>`):
    /// avoids a degraded "missing context" mode in `HandlerContext`
    /// and lets test fixtures wire a no-op impl with the same shape
    /// as the production impl. Mirrors the existing
    /// `Arc<dyn IsolationBackend>` /
    /// `Arc<dyn CredentialBackend>` pattern.
    pub orchestrator_spawn: Arc<dyn OrchestratorSpawn>,

    /// V2 executor / reviewer spawn-context — shared boot-time
    /// install-dir + kernel-version + per-agent VM resource
    /// budgets used by the `IntentKind::ActivateSubTask` handler.
    ///
    /// The activation handler does NOT go through a trait surface
    /// for executor / reviewer spawn (deliberately — see
    /// `session_spawn_orchestrator::spawn_executor_for_task` doc
    /// comment). It calls the free function with this context plus
    /// `Arc::clone(&ctx.session_spawn)`. Production wires the
    /// same install-dir + kernel-version pair that
    /// `OrchestratorSpawnContext` uses; the budgets default to
    /// `host-capacity.md §4.1` reference values and can be
    /// overridden at boot when the relevant `[isolation]` policy
    /// keys land.
    ///
    /// **Why a separate struct** (vs. extracting fields from
    /// `Arc<dyn OrchestratorSpawn>`): the orchestrator-spawn trait
    /// hides its concrete impl behind a `dyn` pointer, so the
    /// install-dir/kernel-version are not directly readable from
    /// the trait surface. The activation handler keeps its own
    /// view here so the trait abstraction stays intact and the
    /// activation callsite has zero coupling to the orchestrator
    /// trait.
    pub executor_spawn: Arc<ExecutorSpawnContext>,

    /// V2 domain adapter selected at boot.
    ///
    /// `extensibility-traits.md §2` — the single seam between the
    /// domain-agnostic kernel core and the domain-specific state
    /// primitives that vary per problem domain. The kernel boot
    /// path constructs `Arc::new(GitAdapter::new(...))` (the
    /// SE-domain reference impl) and stores it here. Future trading
    /// / healthcare / robotics adapters plug into the same field
    /// behind a `cfg`-gated boot-time selector.
    ///
    /// **Why a concrete `IntentKind = SeIntentKind` binding**: the
    /// kernel's IPC handlers compile against a single domain at a
    /// time — there is no run-time dispatch over multiple
    /// `IntentKind` enums. The trait's associated types are
    /// monomorphised at the kernel binary boundary; per-domain
    /// kernels are produced by swapping the `cfg` flag at build.
    /// V2 ships only the SE binding.
    ///
    /// **Why non-Option**: the kernel cannot admit any intent
    /// without a domain adapter to compute the touched-set against
    /// (`R-9` admission gate). A degraded boot without a domain
    /// adapter would refuse every spawn, which is identical to
    /// failing closed at boot — so we fail closed at boot instead.
    pub domain: Arc<
        dyn DomainAdapter<
            IntentKind       = SeIntentKind,
            TerminalArtefact = SeTerminalArtefact,
        >,
    >,

    /// V2 OCI image resolver — turns a policy- / plan-pinned
    /// `oci_digest` into the on-disk path the isolation backend
    /// boots.
    ///
    /// Production wires `raxis_image_cache::ProductionResolver`
    /// rooted at `<data_dir>/oci-cache/` (`image-cache.md §4` on-
    /// disk layout). Boot constructs it after `data_dir` is known
    /// and after the shared `reqwest::Client` is built; tests use
    /// `PrePopulatedResolver` (the default this field is
    /// constructed with) which resolves only digests pre-staged
    /// on disk.
    ///
    /// **Why a trait** (vs. an `Option<...>`): mirrors every other
    /// `Arc<dyn ...>` substrate field. The kernel's session-spawn
    /// path (when V3 routes operator `[[vm_images]]` resolution
    /// through this hook) MUST always have a resolver to call —
    /// failing closed at boot is preferable to a runtime "no
    /// resolver was configured" surprise.
    ///
    /// **V2 consumer surface.** Currently consumed only by the
    /// `raxis doctor cache prune` subcommand which exercises
    /// [`ImageResolver::prune_unreferenced`]; the
    /// session-spawn-path consumer is the V3 deferred work tracked
    /// in `image-cache.md §11`. The field is wired now so the
    /// V3 plumbing change is a one-line callsite swap (replace
    /// the canonical-image path resolution with
    /// `ctx.image_resolver.resolve(...)`) rather than a
    /// HandlerContext signature churn.
    pub image_resolver: Arc<dyn ImageResolver>,

    /// V2_GAPS §D2 — host-capacity disk-full watchdog.
    ///
    /// `None` means "no watchdog wired" — the production boot path
    /// in `kernel/src/main.rs` always wires one (defaulting to a
    /// 5-second poll on `<data_dir>` per `host-capacity.md §7.1`),
    /// but the in-process unit-test fixtures can opt out by leaving
    /// this `None` and the write-class handlers treat that as
    /// "always healthy" (the watchdog otherwise refuses
    /// write-class admission below `min_free_disk_mb`). Set after
    /// construction via [`with_disk_watchdog`].
    ///
    /// [`with_disk_watchdog`]: HandlerContext::with_disk_watchdog
    pub disk_watchdog: Option<Arc<crate::capacity::DiskWatchdog>>,
}

impl HandlerContext {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        policy: Arc<ArcSwap<PolicyBundle>>,
        registry: Arc<KeyRegistry>,
        store: Arc<Store>,
        audit: Arc<dyn AuditSink>,
        data_dir: PathBuf,
        plan_registry: Arc<PlanRegistry>,
        gateway: Arc<GatewayClient>,
        epoch_binding: Arc<EpochBinding>,
        credentials: Arc<dyn CredentialBackend>,
        isolation: Arc<dyn IsolationBackend>,
        orchestrator_spawn: Arc<dyn OrchestratorSpawn>,
        executor_spawn: Arc<ExecutorSpawnContext>,
        domain: Arc<
            dyn DomainAdapter<
                IntentKind       = SeIntentKind,
                TerminalArtefact = SeTerminalArtefact,
            >,
        >,
    ) -> Self {
        let witness_dir = data_dir.join("witness");
        let proxy_manager = Arc::new(CredentialProxyManager::new(
            Arc::clone(&credentials),
            Arc::clone(&audit),
        ));
        let session_spawn = Arc::new(SessionSpawnService::new(
            Arc::clone(&isolation),
            Arc::clone(&proxy_manager),
            Arc::clone(&audit),
        ));
        // Default `image_resolver` is the offline-friendly
        // `PrePopulatedResolver` rooted at `<data_dir>/oci-cache/`.
        // Production overrides this in main.rs via
        // `with_image_resolver(ProductionResolver::new(...))` so
        // operator-defined `[[vm_images]]` resolve through the OCI
        // distribution-spec wire format. The default keeps every
        // existing kernel test compatible — any test that doesn't
        // exercise the resolver consumes the no-op offline path
        // and pays no behaviour change.
        let image_resolver: Arc<dyn ImageResolver> =
            Arc::new(PrePopulatedResolver::new(data_dir.join("oci-cache")));

        // V2_GAPS §D1 — load the operator-cert revocation store
        // from `<data_dir>/revocations/`. A missing directory
        // returns an empty store; tampered records are skipped
        // with a stderr warning. Both signals propagate to the
        // operator via `raxis status`.
        let cert_enforcer = {
            let (rev_store, rev_stats) =
                crate::authority::revocations::RevocationStore::open(data_dir.as_path());
            if rev_stats.loaded > 0 || rev_stats.rejected > 0 {
                eprintln!(
                    "{{\"level\":\"info\",\"event\":\"RevocationStoreLoaded\",\
                     \"loaded\":{},\"rejected\":{}}}",
                    rev_stats.loaded, rev_stats.rejected,
                );
            }
            Arc::new(CertEnforcer::new().with_revocation_store(rev_store))
        };

        Self {
            policy,
            registry,
            store,
            audit,
            data_dir,
            witness_dir,
            plan_registry,
            gateway,
            epoch_binding,
            cert_enforcer,
            isolation,
            credentials,
            proxy_manager,
            session_spawn,
            orchestrator_spawn,
            executor_spawn,
            domain,
            image_resolver,
            disk_watchdog: None,
        }
    }

    /// V2_GAPS §D2 — install the boot-time disk-full watchdog.
    /// Production wires this from `main.rs` after the audit sink
    /// is open; tests can leave the field `None` to opt out of
    /// disk-pressure gating.
    pub fn with_disk_watchdog(mut self, w: Arc<crate::capacity::DiskWatchdog>) -> Self {
        self.disk_watchdog = Some(w);
        self
    }

    /// Construct with an explicit witness_dir (useful in tests that use a
    /// non-standard layout or a temporary directory).
    pub fn with_witness_dir(mut self, witness_dir: PathBuf) -> Self {
        self.witness_dir = witness_dir;
        self
    }

    /// Replace the OCI image resolver after construction. Production
    /// boot uses this to swap the default offline-only
    /// `PrePopulatedResolver` for a `ProductionResolver` configured
    /// with the kernel's shared `reqwest::Client`, the policy-derived
    /// default registry, and any operator-supplied bearer token. See
    /// `main.rs` step 8 for the canonical use site.
    pub fn with_image_resolver(mut self, image_resolver: Arc<dyn ImageResolver>) -> Self {
        self.image_resolver = image_resolver;
        self
    }

    /// Replace the credential backend after construction. Used by
    /// kernel boot (when `policy.toml [credential_backend]` selects
    /// a non-default backend) and by tests that want to inject a
    /// stub backend for negative-path coverage.
    ///
    /// IMPORTANT: this also rebuilds `proxy_manager` so the proxy
    /// resolves credentials through the same backend the rest of
    /// the kernel uses. Tests that swap the credentials backend
    /// AND inspect proxy-emitted audit events should rely on the
    /// rebuilt manager.
    pub fn with_credentials(mut self, credentials: Arc<dyn CredentialBackend>) -> Self {
        self.credentials = Arc::clone(&credentials);
        self.proxy_manager = Arc::new(CredentialProxyManager::new(
            credentials,
            Arc::clone(&self.audit),
        ));
        // Rebuild the session-spawn composer over the new
        // proxy_manager (and the existing isolation + audit) so
        // production session-spawns route through the new backend
        // too. The composer holds no per-session state at
        // construction time, so a swap is safe outside an active
        // spawn.
        self.session_spawn = Arc::new(SessionSpawnService::new(
            Arc::clone(&self.isolation),
            Arc::clone(&self.proxy_manager),
            Arc::clone(&self.audit),
        ));
        self
    }
}

/// Build a default file-backed credential backend (without uid check)
/// for tests. Centralised here so every test fixture in the kernel
/// crate constructs the same shape — and a future migration to a
/// different default for tests only needs to touch this one helper.
///
/// The backend is wrapped in `AuditingBackend` against the supplied
/// `Arc<dyn AuditSink>` so audit-sensitive tests can assert on
/// `CredentialAccessed` / `CredentialRotated` events emitted through
/// the same path production uses.
#[cfg(any(debug_assertions, test))]
pub fn build_default_test_credentials(
    data_dir: &std::path::Path,
    audit: Arc<dyn AuditSink>,
) -> Arc<dyn CredentialBackend> {
    use raxis_credentials::AuditingBackend;
    let inner: Arc<dyn CredentialBackend> =
        Arc::new(raxis_credentials_file::FileCredentialBackend::open_without_uid_check(data_dir));
    Arc::new(AuditingBackend::new(inner, audit))
}

/// Build a default `GitAdapter`-backed [`DomainAdapter`] for in-process
/// kernel unit tests. The adapter operates against three
/// kernel-test-temporary directories under `data_dir`. Every adapter
/// method is a no-op or a deterministic pure computation; tests that
/// exercise the actual `commit_merge_to_main` ceremony override
/// these paths to point at a fixture-built repo.
#[cfg(any(debug_assertions, test))]
pub fn build_default_test_domain(
    data_dir: &std::path::Path,
) -> Arc<
    dyn DomainAdapter<
        IntentKind       = SeIntentKind,
        TerminalArtefact = SeTerminalArtefact,
    >,
> {
    Arc::new(raxis_domain_git::GitAdapter::new(
        data_dir.join("repositories").join("main"),
        data_dir.join("worktrees"),
        data_dir.join("transfer"),
    ))
}

/// Build a fail-closed isolation substrate placeholder for in-process
/// kernel unit tests. Every method returns a typed error — these
/// tests don't exercise spawn paths; they only need the trait
/// surface to satisfy the non-Option `HandlerContext::isolation`
/// field.
///
/// The placeholder self-reports `IsolationLevel::TestOnly` so the
/// kernel's `verify_admission_tier` would refuse it in production
/// — it lives here purely to satisfy the trait surface in
/// non-spawn-driving in-process unit tests. Production binaries
/// never construct this; they go through
/// `isolation_select::select_isolation_backend` which returns the
/// real Firecracker / AVF backend.
#[cfg(any(debug_assertions, test))]
pub fn build_fail_closed_test_isolation() -> Arc<dyn IsolationBackend> {
    Arc::new(FailClosedTestIsolation)
}

/// Helper substrate used only by `build_fail_closed_test_isolation`.
/// Hidden inside this `cfg(any(debug_assertions, test))` module so
/// it never reaches a release binary.
#[cfg(any(debug_assertions, test))]
struct FailClosedTestIsolation;

#[cfg(any(debug_assertions, test))]
impl raxis_isolation::Backend for FailClosedTestIsolation {
    fn spawn(
        &self,
        _image:  &raxis_isolation::VerifiedImage,
        _mounts: &[raxis_isolation::WorkspaceMount],
        _spec:   &raxis_isolation::VmSpec,
    ) -> Result<Box<dyn raxis_isolation::Session>, raxis_isolation::IsolationError> {
        Err(raxis_isolation::IsolationError::BackendInternal(
            "FailClosedTestIsolation refuses every spawn — \
             this substrate exists only to satisfy the trait \
             surface in in-process unit tests; tests that need a \
             real spawn path use SubprocessIsolation behind \
             RAXIS_TEST_HARNESS=1".to_owned(),
        ))
    }
    fn verify_isolation_guarantee(&self)
        -> Result<raxis_isolation::IsolationLevel, raxis_isolation::IsolationError>
    {
        Ok(raxis_isolation::IsolationLevel::TestOnly)
    }
    fn capability(
        &self,
        _kind: raxis_isolation::CapabilityKind,
    ) -> raxis_isolation::CapabilityValue {
        raxis_isolation::CapabilityValue::Bool(false)
    }
    fn backend_id(&self) -> &'static str {
        "fail-closed-test-isolation"
    }
}

/// Build a no-op [`OrchestratorSpawn`] for in-process kernel unit
/// tests that exercise the IPC dispatch tree without driving a
/// real substrate boot.
///
/// Returns a counter-backed implementation that:
///
/// * Accepts every `spawn_for_initiative` call.
/// * Records the `(session_id, initiative_id)` pair so tests can
///   assert the IPC handler reached the substrate-spawn callsite.
/// * Returns `Ok(())` without binding any credential proxy or
///   admission listener.
///
/// Mirrors the cfg-gated `build_fail_closed_test_isolation` /
/// `build_default_test_credentials` / `build_default_test_domain`
/// pattern: production binaries never construct this — they wire
/// `LiveOrchestratorSpawn` from `main.rs`. The cfg gate
/// (`debug_assertions || test`) is the same Layer-1 guard that keeps
/// `FakeAuditSink` / `MockBackend` / `FailClosedTestIsolation` out of
/// release artefacts.
#[cfg(any(debug_assertions, test))]
pub fn build_test_orchestrator_spawn() -> Arc<dyn OrchestratorSpawn> {
    Arc::new(crate::session_spawn_orchestrator::NoopOrchestratorSpawn::new())
}

/// Build a default [`ExecutorSpawnContext`] for in-process kernel
/// unit tests.
///
/// The context points at a never-existing install dir
/// (`/tmp/raxis-test-executor-spawn-non-existent`) and a
/// deterministic-but-fake kernel version. Production binaries
/// never construct this — they wire the boot-time real values from
/// `main.rs`. Mirrors the cfg-gated `build_fail_closed_test_isolation`
/// / `build_test_orchestrator_spawn` discipline.
///
/// **Why a known-bad path.** Activation handlers that resolve the
/// canonical Executor / Reviewer image will fail-closed with
/// `OrchestratorSpawnError::ExecutorStarterImageMissing` /
/// `OrchestratorSpawnError::ReviewerImageMissing`. Tests that
/// exercise the spawn callsite happy-path override `install_dir` to
/// a tempfile that holds the fake image (see
/// `session_spawn_orchestrator::tests::write_canonical_image_fake`
/// for the helper).
#[cfg(any(debug_assertions, test))]
pub fn build_test_executor_spawn()
    -> Arc<crate::session_spawn_orchestrator::ExecutorSpawnContext>
{
    Arc::new(
        crate::session_spawn_orchestrator::ExecutorSpawnContext::new(
            std::path::PathBuf::from("/tmp/raxis-test-executor-spawn-non-existent"),
            "test-only-fake-version".to_owned(),
        ),
    )
}

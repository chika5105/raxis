// raxis-kernel::ipc::context — HandlerContext shared state for IPC handlers.
// Normative reference: kernel-core.md §2.2 `src/handlers/context.rs`.
// HandlerContext is the dependency-injected read-only (or Arc-shared) context
// passed to every IPC handler. It is constructed once in main.rs after all
// startup steps complete and cloned (via Arc) into each connection task.
// Fields added vs the minimal v1 starter:
//   witness_dir — absolute path to <data_dir>/witness/ blob store. Required
//                 by handlers/witness.rs per spec §2.3 witness.rs: "blob bytes
//                 and WitnessIndexCtx are mandatory".

use std::path::PathBuf;
use std::sync::Arc;

use arc_swap::ArcSwap;
use raxis_artifact_store::ArtifactStore;
use raxis_audit_tools::AuditSink;
use raxis_credential_proxy_manager::CredentialProxyManager;
use raxis_credentials::CredentialBackend;
use raxis_domain::DomainAdapter;
use raxis_domain_git::{SeIntentKind, SeTerminalArtefact};
use raxis_image_cache::{ImageResolver, PrePopulatedResolver};
use raxis_isolation::Backend as IsolationBackend;
use raxis_observability::ObservabilityHub;
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
/// All fields are `Arc`-wrapped so each connection task gets a cheap clone.
/// The `store` is behind `Store` which itself contains a `tokio::sync::Mutex`.
#[derive(Clone)]
pub struct HandlerContext {
    /// Validated policy bundle, behind an `ArcSwap` so the kernel can flip
    /// the visible epoch in-process from `policy_manager::advance_epoch`
    /// without a kernel restart (kernel-core.md §`policy_manager.rs`).
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
    /// Per kernel-store.md §2.5.2, every audit emission MUST follow a
    /// successful SQLite commit; the trait does not enforce this — the
    /// kernel review process does. See `lifecycle::approve_plan` for a
    /// canonical use site (commit → drop store mutex → emit).
    pub audit: Arc<dyn AuditSink>,
    /// Absolute path to the kernel data directory (e.g. `~/.raxis`).
    pub data_dir: PathBuf,
    /// Absolute path to the witness blob store (`<data_dir>/witness/`).
    /// Spec §2.3 witness.rs: all witness blob writes go through the
    /// `witness_index::write_blob_to_disk` + `insert_witness_index_in_tx`
    /// pair (both inside the verifier-token consume transaction per
    /// Pattern C, kernel-store.md §2.5.1.1). The directory is created
    /// at bootstrap time and always exists by the time the IPC server
    /// starts (startup step 5, store open).
    pub witness_dir: PathBuf,
    /// In-memory per-task plan-fields registry.
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
    /// **Why non-Option** (vs. the V1 `Option<Arc<...>>` shape):
    /// session-spawn code paths can dispatch through this field
    /// directly without a `None` guard at every call site. The
    /// substrate-unavailable failure mode is moved entirely into
    /// kernel boot — there is no longer a degraded-mode kernel
    /// that admits operator queries while refusing every spawn.
    /// Threaded into `HandlerContext` per `extensibility-traits.md
    /// §3.8` boot-order step 6a so every IPC handler dispatches
    /// through the same `Arc<dyn Backend>` clone.
    pub isolation: Arc<dyn IsolationBackend>,

    /// V2 credential-store backend selected at boot.
    /// Always present — the kernel boot path constructs a default
    /// [`raxis_credentials_file::FileCredentialBackend`] when
    /// `policy.toml` omits `[credential_backend]`, then wraps it in
    /// `raxis_credentials::AuditingBackend` so every resolve emits
    /// the spec-mandated `CredentialAccessed` event. Consumed by
    /// the credential proxy (per session) and the gateway (provider
    /// API keys). Per `extensibility-traits.md §4.4`.
    /// **Why non-Option** (unlike `isolation`): a kernel without a
    /// credential backend cannot spawn any session that declares
    /// `[[tasks.credentials]]` and cannot dispatch any
    /// `FetchRequest` because the gateway needs provider API keys.
    /// The `File` default is universally available (it just reads
    /// from `<data_dir>/credentials/`), so there is no degraded
    /// boot mode that could legitimately leave this `None`.
    pub credentials: Arc<dyn CredentialBackend>,

    /// V2 per-session credential-proxy lifecycle manager.
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
    /// Wraps the `(isolation, proxy_manager, audit)` tuple plus a
    /// per-spawn `Box<dyn AdmissionService>` into the single async
    /// surface the kernel calls when an orchestrator-driven trigger
    /// fires (`spawn_session`) and at session teardown
    /// (`terminate_session`). Owns the per-session admission-loop
    /// listener lifetime + the live `Box<dyn IsolationSession>`
    /// handle table.
    /// Constructed once at kernel boot from the same trios this
    /// `HandlerContext` already carries — there is no other
    /// independent state. The service ALONE knows which sessions
    /// have a live VM right now (`SessionSpawnService::is_active`);
    /// the SQLite `sessions` table is the operator-visible row, the
    /// service's in-memory table is the substrate-visible row.
    /// Both are reconciled at boot through the spawn callsite (see
    /// `extensibility-traits.md §3.5`).
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
    /// `extensibility-traits.md §2` — the single seam between the
    /// domain-agnostic kernel core and the domain-specific state
    /// primitives that vary per problem domain. The kernel boot
    /// path constructs `Arc::new(GitAdapter::new(...))` (the
    /// SE-domain reference impl) and stores it here. Future trading
    /// / healthcare / robotics adapters plug into the same field
    /// behind a `cfg`-gated boot-time selector.
    /// **Why a concrete `IntentKind = SeIntentKind` binding**: the
    /// kernel's IPC handlers compile against a single domain at a
    /// time — there is no run-time dispatch over multiple
    /// `IntentKind` enums. The trait's associated types are
    /// monomorphised at the kernel binary boundary; per-domain
    /// kernels are produced by swapping the `cfg` flag at build.
    /// V2 ships only the SE binding.
    /// **Why non-Option**: the kernel cannot admit any intent
    /// without a domain adapter to compute the touched-set against
    /// (`R-9` admission gate). A degraded boot without a domain
    /// adapter would refuse every spawn, which is identical to
    /// failing closed at boot — so we fail closed at boot instead.
    pub domain:
        Arc<dyn DomainAdapter<IntentKind = SeIntentKind, TerminalArtefact = SeTerminalArtefact>>,

    /// V2 OCI image resolver — turns a policy- / plan-pinned
    /// `oci_digest` into the on-disk path the isolation backend
    /// boots.
    /// Production wires `raxis_image_cache::ProductionResolver`
    /// rooted at `<data_dir>/oci-cache/` (`image-cache.md §4` on-
    /// disk layout). Boot constructs it after `data_dir` is known
    /// and after the shared `reqwest::Client` is built; tests use
    /// `PrePopulatedResolver` (the default this field is
    /// constructed with) which resolves only digests pre-staged
    /// on disk.
    /// **Why a trait** (vs. an `Option<...>`): mirrors every other
    /// `Arc<dyn ...>` substrate field. The kernel's session-spawn
    /// path (when V3 routes operator `[[vm_images]]` resolution
    /// through this hook) MUST always have a resolver to call —
    /// failing closed at boot is preferable to a runtime "no
    /// resolver was configured" surprise.
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

    /// host-capacity disk-full watchdog.
    /// `None` means "no watchdog wired" — the production boot path
    /// in `kernel/src/main.rs` always wires one (defaulting to a
    /// 5-second poll on `<data_dir>` per `host-capacity.md §7.1`),
    /// but the in-process unit-test fixtures can opt out by leaving
    /// this `None` and the write-class handlers treat that as
    /// "always healthy" (the watchdog otherwise refuses
    /// write-class admission below `min_free_disk_mb`). Set after
    /// construction via [`with_disk_watchdog`].
    /// [`with_disk_watchdog`]: HandlerContext::with_disk_watchdog
    pub disk_watchdog: Option<Arc<crate::capacity::DiskWatchdog>>,

    /// Kernel-side `KernelPush` dispatcher
    /// (V2.3 in-memory MVP). Handlers call
    /// `push_dispatcher.enqueue(session_id, KernelPush::*, now)`
    /// at the spec-correct call sites; the dispatcher allocates
    /// the per-session monotonic `push_id`, mirrors the push to
    /// the audit chain (`AuditEventKind::KernelPushEnqueued`), and
    /// fans out to any `Subscriber` currently bound to the
    /// session. The full session-addressed VSock/UDS transport
    /// with the `pending_pushes` SQL queue is V3 (§12.1).
    pub push_dispatcher: Arc<crate::push::KernelPushDispatcher>,

    /// per-channel `SidecarChannelState` registry for
    /// the V2.4 `Sidecar` notification kind. Each
    /// `[[notifications.channels]]` of kind `Sidecar` lazily
    /// allocates one entry on first dispatch; the entry holds the
    /// concurrency permit pool (semaphore), the circuit-breaker
    /// state, and observability counters surfaced through
    /// `raxis status`. See `notifications::handler::sidecar`.
    pub sidecar_registry: Arc<crate::notifications::handler::sidecar::SidecarRegistry>,

    /// Per-initiative realtime
    /// event bus. The audit sink stored in `Self::audit` is wrapped
    /// in [`crate::push::BroadcastingAuditSink`] so every successful
    /// audit emit that carries an `initiative_id` AND maps to a
    /// public-wire `InitiativeEvent` (per
    /// `crate::push::audit_kind_to_initiative_event`) is mirrored
    /// onto this bus. The operator-side `SubscribeInitiative`
    /// streaming handler (`ipc::operator_ergonomics_stream::run`)
    /// holds one subscriber per attached operator and forwards
    /// each frame as a length-prefixed JSON record.
    pub initiative_bus: Arc<crate::push::InitiativeEventBus>,

    /// content-addressed immutable artifact store
    /// rooted at `<data_dir>/artifacts/`. Writes are
    /// `<root>/<category>/<sha256>.<ext>` with `O_CREAT|O_EXCL`
    /// and on-read SHA-256 verification (the spec's §1.3 tamper
    /// detector).
    /// Wired call sites:
    /// * `policy_manager::advance_epoch` writes the verified
    ///   policy bytes to `Category::Policy` AFTER signature
    ///   verification and BEFORE the SQL transaction. The store's
    ///   idempotency contract makes this safe to retry; the
    ///   chain entry that the same epoch advance emits is the
    ///   audit-side anchor that points at the on-disk artifact.
    /// * `initiatives::lifecycle::approve_plan` writes the plan
    ///   bytes to `Category::Plans` and the operator signature
    ///   as a companion `.sig` AFTER signature verification and
    ///   BEFORE BEGIN TRANSACTION. Both writes are idempotent
    ///   on identical bytes.
    /// * Operator-cert ingest in the same `advance_epoch` path
    ///   writes each operator public key to `Category::Keys`
    ///   so a future `raxis keys list` can enumerate every
    ///   public key the kernel ever trusted, byte-for-byte.
    ///   **Why `Option`:** test fixtures that don't exercise the
    ///   store leave this `None`; the production boot path always
    ///   wires it. The `advance_epoch` / `approve_plan` callsites
    ///   degrade silently (skip the artifact write) when this is
    ///   `None` so that test handlers continue to pass without a
    ///   per-test tempdir for the artifact root.
    pub artifact_store: Option<Arc<ArtifactStore>>,

    /// V3 — authority-side OpenTelemetry observability hub.
    /// Held as `Arc<ObservabilityHub>` so handlers can call
    /// `ctx.observability.start_span(...)` / `record_counter(...)`
    /// without paying for a clone on every call. The hub is
    /// constructed once at kernel boot from `policy().observability()`;
    /// when the operator omits the section the field is still
    /// populated with a [`ObservabilityHub::disabled`] instance so
    /// emit sites can be unconditional (the disabled hub
    /// short-circuits before sanitisation).
    /// Production wiring: `kernel/src/main.rs` reads
    /// `[observability].enabled`, builds a `RingFileExporter` rooted
    /// at `<data_dir>/observability/`, constructs the hub, and
    /// passes it to `HandlerContext::with_observability`. The
    /// separate `raxis-otel-pusher` binary tails the same ring
    /// directory and ships OTLP — the kernel itself never imports
    /// OTLP transport per `INV-OTEL-03`.
    /// **Why non-Option**: emit sites are pervasive (intent
    /// admission, gateway fetch, verifier execution, notification
    /// dispatch, operator IPC, escalation, session spawn). Threading
    /// `Option<Arc<ObservabilityHub>>` would litter the codebase
    /// with `if let Some(hub) = ...` guards; the disabled hub is
    /// equivalent and ~free at the call site.
    pub observability: Arc<ObservabilityHub>,

    /// V1 Tier 4 — emergency operator override (break-glass) state.
    /// Held as `Arc<BreakglassState>` so handlers can call
    /// `ctx.breakglass.check()` on the gate-evaluation hot path
    /// without paying for a clone. Production wiring opens the
    /// state from `<data_dir>/breakglass/active.toml` at boot
    /// (see `main.rs`); tests construct
    /// [`crate::breakglass::BreakglassState::disabled`] which keeps
    /// the cache empty and skips all on-disk persistence.
    /// **Why non-Option**: the gate-evaluation path
    /// (`gates::evaluate_claims` step 1) checks this on every
    /// admission. A disabled instance behaves identically to an
    /// inactive activation — the fast-path read is a single
    /// `RwLock::read` of an empty `Option`, which costs ~nothing.
    pub breakglass: Arc<crate::breakglass::BreakglassState>,

    /// V2 reviewer-egress-defaults-decision.md §7 — kernel-wide
    /// sliding-window egress-stall tracker.
    /// Shared across both egress chokepoints:
    ///   - `raxis-egress-admission::run_admission_loop` (Tier-1
    ///     transparent-proxy admission), wired through
    ///     `SessionSpawnService::with_egress_stall_tracker`.
    ///   - `crate::handlers::planner_fetch::handle` (kernel-mediated
    ///     `PlannerFetchRequest` `DomainNotAllowed` rejections).
    ///     Each chokepoint feeds the tracker on every denial and emits
    ///     one `SessionEgressStallDetected` audit event per
    ///     (session, destination) bucket per sliding window. The
    ///     `source` field on the event tags which chokepoint observed
    ///     the stall.
    ///     **Why `Arc`**: the tracker is shared concurrently across
    ///     every per-session admission task and every planner_fetch
    ///     dispatch; cloning the `Arc` is cheap and the inner
    ///     `Mutex<HashMap>` already serialises mutations.
    pub egress_stall_tracker: Arc<raxis_egress_admission::EgressStallTracker>,

    /// `INV-FAILURE-REASON-MANDATORY-01` (clean-exit-no-terminal-
    /// intent sub-case) — per-session in-memory tracker of the
    /// last `IntentRequest` each substrate-spawned planner
    /// submitted before its IPC channel went to EOF.
    /// Written by [`crate::ipc::server::drive_planner_stream`] on
    /// every IntentRequest arm; read (and consumed) by the Mode-B
    /// post-exit synthesis hook in
    /// [`crate::session_spawn_orchestrator::spawn_planner_dispatcher`]
    /// when the planner-dispatch task returned `Ok(())` — i.e.
    /// the planner dialed its socket cleanly to EOF — but never
    /// landed a terminal intent. The synthesised `block_reason`
    /// the hook writes inlines the recorded
    /// `(intent_kind, sequence_number, outcome, timestamp)`
    /// tuple verbatim, so the dashboard's `<FailureReasonPanel>`
    /// surfaces a non-generic reason instead of the pre-fix
    // SWEEP-IGNORE-BEGIN
    /// umbrella `"MaxTurnsExceeded / TokensExceeded /
    /// DispatchIdle / process death"` placeholder
    // SWEEP-IGNORE-END
    /// (the iter56 regression baseline that
    /// `INV-FAILURE-REASON-CONCRETE-01` now forbids).
    /// **Why non-Option**: the tracker is forensic, never gates
    /// admission, and the default-empty state is a no-op for
    /// every code path that doesn't write to it. Threading
    /// `Option<Arc<...>>` would litter the session-spawn /
    /// IPC-server callsites with a no-op guard for zero benefit.
    pub session_activity: Arc<crate::session_activity::SessionActivityTracker>,
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
            dyn DomainAdapter<IntentKind = SeIntentKind, TerminalArtefact = SeTerminalArtefact>,
        >,
    ) -> Self {
        let witness_dir = data_dir.join("witness");

        // Install the per-initiative
        // realtime bus and wrap the inbound audit sink so every
        // successful audit emit fans an `InitiativeEvent` out to
        // `SubscribeInitiative` subscribers. The wrapper is
        // transparent to existing callers — `AuditSink::emit`
        // semantics + Result types are unchanged. The bus is
        // shared (Arc-cloned) into `Self::initiative_bus` so the
        // streaming handler can subscribe by initiative_id.
        let initiative_bus = crate::push::InitiativeEventBus::new();
        let audit: Arc<dyn AuditSink> =
            crate::push::BroadcastingAuditSink::new(audit, Arc::clone(&initiative_bus));

        let proxy_manager = Arc::new(CredentialProxyManager::new(
            Arc::clone(&credentials),
            Arc::clone(&audit),
        ));
        // V2 reviewer-egress-defaults-decision.md §7 — kernel-wide
        // shared `EgressStallTracker`. The same `Arc` is wired
        // into both the Tier-1 admission loop (via
        // `SessionSpawnService::with_egress_stall_tracker`) and
        // the kernel-mediated `planner_fetch` handler (via
        // `HandlerContext::egress_stall_tracker`) so a stall
        // observed at either chokepoint shares the same sliding-
        // window state. Production boot (`main.rs`) keeps this
        // default; tests that need a deterministic clock
        // construct their own tracker and call
        // `with_egress_stall_tracker`.
        let egress_stall_tracker =
            Arc::new(raxis_egress_admission::EgressStallTracker::with_defaults());
        let session_spawn = Arc::new(
            SessionSpawnService::new(
                Arc::clone(&isolation),
                Arc::clone(&proxy_manager),
                Arc::clone(&audit),
            )
            .with_egress_stall_tracker(Arc::clone(&egress_stall_tracker))
            // `INV-KERNEL-STATELESS-VM-CONCURRENCY-CAP-01` (iter65)
            // derive `active_count` from the `sessions` table,
            // not the leaky in-memory live-handle map.
            .with_store(Arc::clone(&store)),
        );
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

        // load the operator-cert revocation store
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

        let push_dispatcher = crate::push::KernelPushDispatcher::new(Arc::clone(&audit));
        let sidecar_registry =
            Arc::new(crate::notifications::handler::sidecar::SidecarRegistry::new());
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
            push_dispatcher,
            sidecar_registry,
            initiative_bus,
            artifact_store: None,
            // V3 — default disabled hub. Production main.rs swaps
            // this for the policy-derived hub via
            // `with_observability`. Keeping the default disabled
            // means tests pay zero cost and existing fixtures keep
            // compiling without churn.
            observability: Arc::new(ObservabilityHub::disabled()),
            // V1 Tier 4 — default `disabled()` state means
            // `check()` returns `Inactive`. Production main.rs
            // swaps this for an on-disk-backed instance via
            // `with_breakglass`. Tests that don't exercise
            // breakglass keep the default.
            breakglass: Arc::new(crate::breakglass::BreakglassState::disabled()),
            // V2 reviewer-egress-defaults-decision.md §7 — same
            // shared tracker the in-VM admission loop is wired
            // against. See the `egress_stall_tracker` binding
            // earlier in this constructor.
            egress_stall_tracker,
            // INV-FAILURE-REASON-MANDATORY-01 — fresh per-process
            // tracker. Production boot in `main.rs` keeps this
            // default; tests get a fresh empty tracker per
            // `HandlerContext::new` call. The tracker holds at
            // most one entry per active substrate-spawned VM
            // session, so production memory footprint is
            // negligible.
            session_activity: Arc::new(crate::session_activity::SessionActivityTracker::new()),
        }
    }

    /// install the boot-time artifact store after
    /// `HandlerContext::new`. Production boot in `main.rs` opens
    /// the store at `<data_dir>/artifacts/` and calls this
    /// setter; tests that exercise the store wire it from a
    /// `tempfile::tempdir`. Tests that don't touch the store
    /// leave the field `None`.
    pub fn with_artifact_store(mut self, store: Arc<ArtifactStore>) -> Self {
        self.artifact_store = Some(store);
        self
    }

    /// V3 — install the boot-time `ObservabilityHub`. Production
    /// boot in `main.rs` constructs the hub from
    /// `policy.observability()` (a `RingFileExporter` rooted at
    /// `<data_dir>/observability/`) and calls this setter. Tests
    /// that exercise the observability surface inject an
    /// `InMemoryExporter`-backed hub via this same setter; tests
    /// that don't keep the default disabled hub.
    pub fn with_observability(mut self, hub: Arc<ObservabilityHub>) -> Self {
        // V3 perf-telemetry: rebuild SessionSpawnService with the
        // hub so the four-tier VM cold-boot histograms are stamped
        // from the very first spawn. The hub is shared (Arc-cloned)
        // between the HandlerContext and the inner SessionSpawnService.
        let hub_for_spawn = hub.clone();
        self.observability = hub;
        // V2 reviewer-egress-defaults-decision.md §7: preserve the
        // shared `EgressStallTracker` across the rebuild so the
        // Tier-1 admission-loop chokepoint keeps emitting
        // `SessionEgressStallDetected` after a hub install.
        let new_spawn = SessionSpawnService::new(
            self.isolation.clone(),
            self.proxy_manager.clone(),
            self.audit.clone(),
        )
        .with_observability(hub_for_spawn)
        .with_egress_stall_tracker(Arc::clone(&self.egress_stall_tracker))
        // `INV-KERNEL-STATELESS-VM-CONCURRENCY-CAP-01` (iter65) —
        // preserve the store handle so the cap-admission gate
        // keeps reading audit-truth after a hub install.
        .with_store(Arc::clone(&self.store));
        self.session_spawn = Arc::new(new_spawn);
        self
    }

    /// V1 Tier 4 — install the boot-time
    /// [`crate::breakglass::BreakglassState`]. Production boot in
    /// `main.rs` opens the state from
    /// `<data_dir>/breakglass/active.toml`; tests that exercise the
    /// break-glass code path inject a fixture-built state.
    pub fn with_breakglass(mut self, state: Arc<crate::breakglass::BreakglassState>) -> Self {
        self.breakglass = state;
        self
    }

    /// V2 reviewer-egress-defaults-decision.md §7 — replace the
    /// auto-allocated [`raxis_egress_admission::EgressStallTracker`]
    /// (e.g. tests want a synthetic clock for deterministic timing).
    /// Also rebuilds the inner `SessionSpawnService` so the new
    /// tracker is the one wired into the Tier-1 admission loop —
    /// keeping the two chokepoints in lock-step is the whole point.
    pub fn with_egress_stall_tracker(
        mut self,
        tracker: Arc<raxis_egress_admission::EgressStallTracker>,
    ) -> Self {
        self.egress_stall_tracker = Arc::clone(&tracker);
        self.session_spawn = Arc::new(
            SessionSpawnService::new(
                Arc::clone(&self.isolation),
                Arc::clone(&self.proxy_manager),
                Arc::clone(&self.audit),
            )
            .with_egress_stall_tracker(tracker)
            // `INV-KERNEL-STATELESS-VM-CONCURRENCY-CAP-01` (iter65)
            // preserve the store handle on rebuild.
            .with_store(Arc::clone(&self.store)),
        );
        self
    }

    /// replace the auto-allocated `SidecarRegistry`
    /// with one shared from `main.rs`. Production calls this so the
    /// `NotifyingAuditSink` and the `HandlerContext` point at the
    /// same registry (one set of counters, one circuit-breaker
    /// state per channel). Tests that don't exercise sidecars can
    /// omit the call.
    pub fn with_sidecar_registry(
        mut self,
        registry: Arc<crate::notifications::handler::sidecar::SidecarRegistry>,
    ) -> Self {
        self.sidecar_registry = registry;
        self
    }

    /// install the boot-time disk-full watchdog.
    /// Production wires this from `main.rs` after the audit sink
    /// is open; tests can leave the field `None` to opt out of
    /// disk-pressure gating.
    pub fn with_disk_watchdog(mut self, w: Arc<crate::capacity::DiskWatchdog>) -> Self {
        self.disk_watchdog = Some(w);
        self
    }

    /// Replace the session-spawn service after construction.
    ///
    /// Production boot uses this to install the exact
    /// [`SessionSpawnService`] instance handed to
    /// `LiveOrchestratorSpawn`. The service owns the in-memory live
    /// VM-handle table used by executor/reviewer spawns, orchestrator
    /// spawns, explicit termination, and Firecracker workspace sync.
    /// If those paths each construct their own service, the SQL
    /// `sessions` rows still agree but the live-handle table does not:
    /// a planner intent can arrive for a perfectly valid VM while
    /// `sync_session_workspace` sees `SessionNotActive` in the wrong
    /// table. Keeping one Arc is the runtime authority boundary.
    pub fn with_session_spawn(mut self, session_spawn: Arc<SessionSpawnService>) -> Self {
        self.session_spawn = session_spawn;
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
        // V2 reviewer-egress-defaults-decision.md §7: re-inject
        // the shared `EgressStallTracker` so the Tier-1 admission
        // loop keeps emitting `SessionEgressStallDetected` after
        // a credential-backend swap.
        self.session_spawn = Arc::new(
            SessionSpawnService::new(
                Arc::clone(&self.isolation),
                Arc::clone(&self.proxy_manager),
                Arc::clone(&self.audit),
            )
            .with_egress_stall_tracker(Arc::clone(&self.egress_stall_tracker))
            // `INV-KERNEL-STATELESS-VM-CONCURRENCY-CAP-01` (iter65)
            // preserve the store handle across credential-backend
            // swaps so the cap-admission gate keeps reading
            // audit-truth.
            .with_store(Arc::clone(&self.store)),
        );
        self
    }
}

/// Build a default file-backed credential backend (without uid check)
/// for tests. Centralised here so every test fixture in the kernel
/// crate constructs the same shape — and a future migration to a
/// different default for tests only needs to touch this one helper.
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
) -> Arc<dyn DomainAdapter<IntentKind = SeIntentKind, TerminalArtefact = SeTerminalArtefact>> {
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
/// The placeholder self-reports `IsolationLevel::TestOnly` so the
/// kernel's `verify_admission_tier` would refuse it in production
/// it lives here purely to satisfy the trait surface in
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
        _image: &raxis_isolation::VerifiedImage,
        _mounts: &[raxis_isolation::WorkspaceMount],
        _spec: &raxis_isolation::VmSpec,
    ) -> Result<Box<dyn raxis_isolation::Session>, raxis_isolation::IsolationError> {
        Err(raxis_isolation::IsolationError::BackendInternal(
            "FailClosedTestIsolation refuses every spawn — \
             this substrate exists only to satisfy the trait \
             surface in in-process unit tests; tests that need a \
             real spawn path use SubprocessIsolation behind \
             RAXIS_TEST_HARNESS=1"
                .to_owned(),
        ))
    }
    fn verify_isolation_guarantee(
        &self,
    ) -> Result<raxis_isolation::IsolationLevel, raxis_isolation::IsolationError> {
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
/// Returns a counter-backed implementation that:
/// * Accepts every `spawn_for_initiative` call.
/// * Records the `(session_id, initiative_id)` pair so tests can
///   assert the IPC handler reached the substrate-spawn callsite.
/// * Returns `Ok(())` without binding any credential proxy or
///   admission listener.
///   Mirrors the cfg-gated `build_fail_closed_test_isolation` /
///   `build_default_test_credentials` / `build_default_test_domain`
///   pattern: production binaries never construct this — they wire
///   `LiveOrchestratorSpawn` from `main.rs`. The cfg gate
///   (`debug_assertions || test`) is the same Layer-1 guard that keeps
///   `FakeAuditSink` / `MockBackend` / `FailClosedTestIsolation` out of
///   release artefacts.
#[cfg(any(debug_assertions, test))]
pub fn build_test_orchestrator_spawn() -> Arc<dyn OrchestratorSpawn> {
    Arc::new(crate::session_spawn_orchestrator::NoopOrchestratorSpawn::new())
}

/// Build a default [`ExecutorSpawnContext`] for in-process kernel
/// unit tests.
/// The context points at a never-existing install dir
/// (`/tmp/raxis-test-executor-spawn-non-existent`) and a
/// deterministic-but-fake kernel version. Production binaries
/// never construct this — they wire the boot-time real values from
/// `main.rs`. Mirrors the cfg-gated `build_fail_closed_test_isolation`
/// `build_test_orchestrator_spawn` discipline.
/// **Why a known-bad path.** Activation handlers that resolve the
/// canonical Executor / Reviewer image will fail-closed with
/// `OrchestratorSpawnError::ExecutorStarterImageMissing` /
/// `OrchestratorSpawnError::ReviewerImageMissing`. Tests that
/// exercise the spawn callsite happy-path override `install_dir` to
/// a tempfile that holds the fake image (see
/// `session_spawn_orchestrator::tests::write_canonical_image_fake`
/// for the helper).
#[cfg(any(debug_assertions, test))]
pub fn build_test_executor_spawn() -> Arc<crate::session_spawn_orchestrator::ExecutorSpawnContext> {
    Arc::new(
        crate::session_spawn_orchestrator::ExecutorSpawnContext::new(
            std::path::PathBuf::from("/tmp/raxis-test-executor-spawn-non-existent"),
            "test-only-fake-version".to_owned(),
        ),
    )
}

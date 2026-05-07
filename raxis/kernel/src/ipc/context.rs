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
use raxis_credentials::CredentialBackend;
use raxis_isolation::Backend as IsolationBackend;
use raxis_policy::PolicyBundle;
use raxis_store::Store;

use crate::authority::cert_check::CertEnforcer;
use crate::authority::keys::KeyRegistry;
use crate::gateway::client::GatewayClient;
use crate::initiatives::PlanRegistry;
use crate::prompt::EpochBinding;

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
    ) -> Self {
        let witness_dir = data_dir.join("witness");
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
            cert_enforcer: Arc::new(CertEnforcer::new()),
            isolation,
            credentials,
        }
    }

    /// Construct with an explicit witness_dir (useful in tests that use a
    /// non-standard layout or a temporary directory).
    pub fn with_witness_dir(mut self, witness_dir: PathBuf) -> Self {
        self.witness_dir = witness_dir;
        self
    }

    /// Replace the credential backend after construction. Used by
    /// kernel boot (when `policy.toml [credential_backend]` selects
    /// a non-default backend) and by tests that want to inject a
    /// stub backend for negative-path coverage.
    pub fn with_credentials(mut self, credentials: Arc<dyn CredentialBackend>) -> Self {
        self.credentials = credentials;
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

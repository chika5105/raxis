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

    /// V2 agent-runtime substrate selected at boot.
    ///
    /// `Some(...)` when `isolation_select::select_isolation_backend`
    /// admitted a substrate (Linux+KVM ⇒ Firecracker; macOS ⇒ AVF).
    /// `None` indicates **degraded boot** — the host has no admissible
    /// substrate and the kernel is up only to serve operator queries.
    /// Every code path that reaches into the substrate to spawn a
    /// session MUST handle `None` by surfacing a typed
    /// `FAIL_ISOLATION_UNAVAILABLE`-style rejection rather than
    /// panicking.
    ///
    /// Threaded into `HandlerContext` per `extensibility-traits.md
    /// §3.8` boot-order step 6a so every IPC handler dispatches
    /// through the same `Arc<dyn Backend>` clone.
    pub isolation: Option<Arc<dyn IsolationBackend>>,
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
            isolation: None,
        }
    }

    /// Construct with an explicit witness_dir (useful in tests that use a
    /// non-standard layout or a temporary directory).
    pub fn with_witness_dir(mut self, witness_dir: PathBuf) -> Self {
        self.witness_dir = witness_dir;
        self
    }

    /// Attach the V2 isolation substrate (Firecracker / AVF) selected
    /// at boot. Required before any session-spawning handler is
    /// reached; absence means degraded mode and every spawn is
    /// expected to fail closed.
    pub fn with_isolation(mut self, isolation: Arc<dyn IsolationBackend>) -> Self {
        self.isolation = Some(isolation);
        self
    }
}

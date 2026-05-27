//! `raxis-dashboard-kernel` — kernel-side glue for the dashboard.
//!
//! Normative reference:
//!
//! Lives in its own crate (rather than `kernel/src/dashboard.rs`)
//! so the integration suite can link the production
//! [`KernelDashboardData`] directly and exercise it against a
//! real on-disk store + audit chain. The kernel binary depends on
//! this crate; the dashboard server lifecycle is otherwise
//! identical to having the module live in `kernel/`.

#![deny(unsafe_code)]
#![warn(missing_docs)]
//
// What this module does
// ─────────────────────
// 1. Defines `KernelDashboardData` — the production
//    `raxis_dashboard::DashboardData` impl that fans out to:
//      - `raxis_store::ro` for read-only snapshots of every
//        kernel.db row the dashboard surfaces,
//      - `raxis_audit_tools::reader::ChainReader` for paginated
//        audit-chain access,
//      - `Arc<ArcSwap<PolicyBundle>>::load()` for the operator
//        roster + current `[notifications]` snapshot,
//      - the operator's on-disk `policy.toml` for the raw editor
//        surface (`/api/policy/toml`).
// 2. Loads the optional `[dashboard]` block out of `policy.toml`
//    on boot so operators can declare bind address / port / TLS
//    paths / JWT TTL / challenge bounds without us having to
//    extend the strongly-typed `PolicyBundle` shape.
// 3. Spawns the axum HTTP server and returns a graceful-shutdown
//    handle the kernel's main loop holds.
//
// Why the policy.toml is parsed twice
// ───────────────────────────────────
// `raxis_policy::PolicyBundle` is the kernel's source of truth
// for everything that needs validation, signing, and epoch
// pinning. The dashboard config (port, JWT TTL, etc.) is a
// runtime knob with no security semantics — duplicating it into
// every test fixture is more harm than good. We re-parse the
// file once at boot to extract the optional block; absence ⇒
// dashboard disabled (zero runtime cost per spec §4.3).

use std::path::{Path, PathBuf};
use std::sync::Arc;

use arc_swap::ArcSwap;
use serde::Deserialize;

use raxis_audit_tools::reader::ChainReader;
use raxis_dashboard::auth::DashboardRole;
use raxis_dashboard::config::DashboardConfig;
use raxis_dashboard::data::{
    AuditEntryView, BuilderValidationIssue, BuilderValidationResponse, BuilderValidationSeverity,
    ChainStatusView, CredentialMetadata, CredentialReveal, DagEdge, DashboardData, EscalationView,
    HealthCheck, HealthSnapshot, InitiativeListEntry, InitiativePlanView, InitiativeView,
    NotificationView, OperatorAuthResolution, OrchestratorGapsResponse, PolicyAdvancement,
    PolicyOperatorView, PolicySnapshotView, RecentSessionEntry, ReviewerPanelEntry,
    ReviewerVerdictView, SessionView, SessionVmEnvView, StructuredOutputView, SubsystemDetailRow,
    SubsystemHealthCard, SubsystemHealthResponse, TaskView, WorktreeDetail, WorktreeDiff,
    WorktreeFile, WorktreeListEntry, WorktreeLogEntry, WorktreeTree, WorktreeTreeEntry,
    SUBSYSTEM_CATALOG,
};
use raxis_dashboard::error::ApiError;
use raxis_dashboard::server::{DashboardServer, ServerHandle};
use raxis_dashboard::stream::{StreamEvent, StreamSubscription};
use raxis_policy::PolicyBundle;
use raxis_store::{Store, Table};

// Typed table-name constants for the iter68 PR 1-5 read paths.
// `INV-STORE-03`: no raw table-name string literals in any crate
// that touches `kernel.db`. These are `const &'static str` so they
// compose seamlessly with `format!` in `prepare()` strings.
const TBL_WITNESS_RECORDS: &str = Table::WitnessRecords.as_str();
const TBL_VERIFIER_RUN_TOKENS: &str = Table::VerifierRunTokens.as_str();
const TBL_WORKTREE_SNAPSHOTS: &str = Table::WorktreeSnapshots.as_str();
const TBL_TASKS: &str = Table::Tasks.as_str();
const TBL_TASK_DAG_EDGES: &str = Table::TaskDagEdges.as_str();
const TBL_SUBTASK_ACTIVATIONS: &str = Table::SubtaskActivations.as_str();
const TBL_SESSIONS: &str = Table::Sessions.as_str();

mod git;
pub mod lifecycle;
pub mod notification_filter;
pub mod session_capture;
pub mod stream_capture;
pub mod streaming_audit;
pub mod task_llm_capture;

pub use lifecycle::{
    classify_for_session, classify_for_task, classify_orchestrator_gaps, ActivationRow,
    AuditRow as LifecycleAuditRow, TaskRow as LifecycleTaskRow,
};
pub use notification_filter::{
    notification_priority, notification_priority_for_kind_str, NotificationPriority,
};
pub use session_capture::{
    SessionCapture, SessionCaptureConfig, SessionCaptureRecord, SessionLifecycleObserver,
    SessionStateView,
};
pub use stream_capture::{CaptureConfig, SessionStreamCapture};
pub use streaming_audit::StreamingAuditSink;
pub use task_llm_capture::{LlmTurnRecord, TaskCaptureConfig, TaskLlmCapture};

// ---------------------------------------------------------------------------
// PolicyAdvancer — kernel-side write callback for the dashboard
// ---------------------------------------------------------------------------

/// Result the kernel impl returns when it has staged the new
/// policy bytes + signature on disk and successfully advanced
/// the in-memory + on-disk epoch.
#[derive(Debug, Clone)]
pub struct AdvanceResult {
    /// Epoch the kernel was running before the call.
    pub previous_epoch: u64,
    /// Epoch the kernel is running after the call.
    pub new_epoch: u64,
    /// SHA-256 of the new policy artifact bytes.
    pub policy_sha256: String,
    /// Operator id from `meta.signed_by` on the new artifact.
    pub signed_by_authority: String,
    /// Pending delegations marked stale by the swap.
    pub n_delegations_marked_stale: u64,
    /// Active sessions invalidated by the swap.
    pub n_sessions_invalidated: u64,
    /// Unix-seconds timestamp recorded on the new history row.
    pub advanced_at: u64,
}

/// Failure surface for [`PolicyAdvancer::advance`].
///
/// The dashboard maps `Validation` to `ApiError::PolicyInvalid`
/// (HTTP 400) and `Internal` to `ApiError::Internal` (HTTP 500);
/// no kernel-internal state ever reaches the wire body.
#[derive(Debug, Clone, thiserror::Error)]
pub enum AdvanceError {
    /// Validator (signature, replay, malformed TOML, path containment).
    /// The contained string is operator-safe — it is the same
    /// short message the CLI prints.
    #[error("policy validation failed: {0}")]
    Validation(String),
    /// IO trouble (write, rename, fsync, etc.). Logged via
    /// `tracing::error!` and suppressed on the wire.
    #[error("internal error: {0}")]
    Internal(String),
}

/// Kernel-side callback the dashboard uses to install a new
/// signed policy artifact. Implemented in the kernel binary
/// (`kernel/src/dashboard_glue.rs`) which has the
/// `KeyRegistry`, `AuditSink`, `EpochBinding`, etc. needed to
/// drive `policy_manager::advance_epoch`.
///
/// The trait is intentionally tiny so tests can stub it
/// without booting the kernel — see [`ClosurePolicyAdvancer`]
/// for the test-only adapter.
pub trait PolicyAdvancer: Send + Sync + 'static {
    /// Atomically install the supplied TOML + signature and
    /// drive the kernel's `advance_epoch` pipeline.
    ///
    /// Implementation contract:
    ///   1. Stage the bytes onto the canonical
    ///      `policy.toml` / `policy.toml.sig` paths via
    ///      `tempfile::persist` (atomic rename) so a partial
    ///      write never leaves the canonical files inconsistent.
    ///   2. Call `raxis_kernel::policy_manager::advance_epoch`
    ///      to verify + commit. On failure, restore the previous
    ///      bytes (best-effort) and surface
    ///      `AdvanceError::Validation`.
    ///   3. Emit `AuditEventKind::PolicyUpdatedViaDashboard`
    ///      with the operator's pubkey fingerprint.
    ///
    /// Returns the structured outcome the dashboard renders to
    /// the operator UI.
    fn advance(
        &self,
        toml_bytes: &[u8],
        sig_bytes: &[u8],
        operator_fingerprint: &str,
    ) -> Result<AdvanceResult, AdvanceError>;
}

/// Closure-backed [`PolicyAdvancer`] for tests. Wraps a
/// `Fn(&[u8], &[u8], &str) -> Result<AdvanceResult,
/// AdvanceError>` so test code can stub the advancer behaviour
/// without standing up a full `KeyRegistry` + `Store` +
/// `EpochBinding` rig.
///
/// This is NOT for production use — the real production
/// advancer lives in the kernel binary
/// (`kernel/src/dashboard_glue::KernelPolicyAdvancer`).
pub struct ClosurePolicyAdvancer<F>
where
    F: Fn(&[u8], &[u8], &str) -> Result<AdvanceResult, AdvanceError> + Send + Sync + 'static,
{
    inner: F,
}

impl<F> ClosurePolicyAdvancer<F>
where
    F: Fn(&[u8], &[u8], &str) -> Result<AdvanceResult, AdvanceError> + Send + Sync + 'static,
{
    /// Wrap a closure into a `PolicyAdvancer`.
    pub fn new(f: F) -> Self {
        Self { inner: f }
    }
}

impl<F> PolicyAdvancer for ClosurePolicyAdvancer<F>
where
    F: Fn(&[u8], &[u8], &str) -> Result<AdvanceResult, AdvanceError> + Send + Sync + 'static,
{
    fn advance(
        &self,
        toml_bytes: &[u8],
        sig_bytes: &[u8],
        operator_fingerprint: &str,
    ) -> Result<AdvanceResult, AdvanceError> {
        (self.inner)(toml_bytes, sig_bytes, operator_fingerprint)
    }
}

/// Kernel-wired implementation of the dashboard data trait.
///
/// Construction is cheap (just `Arc` clones); every read method
/// opens a fresh short-lived `RoConn` per call so the dashboard
/// never holds a WAL snapshot across UI ticks (mirrors the
/// CLI's discipline in `cli-readonly.md §5.4.3`).
pub struct KernelDashboardData {
    /// Live policy bundle (used for operator resolution + policy
    /// snapshot rendering).
    policy: Arc<ArcSwap<PolicyBundle>>,
    /// Path to the kernel data directory. We open a fresh
    /// `RoConn` from here per request rather than caching one,
    /// since the `RoConn` is `!Send + !Sync` (rusqlite handle
    /// uses interior mutability).
    data_dir: PathBuf,
    /// Path to the operator's policy.toml. Read for
    /// `/api/policy/toml` (write-policy role only).
    policy_path: PathBuf,
    /// Audit segment directory (`<data_dir>/audit`).
    audit_dir: PathBuf,
    /// Boot time in unix seconds for the health snapshot.
    booted_at: u64,
    /// Kernel store handle. Reserved for write surfaces that
    /// directly mutate kernel.db. The read trait fans out
    /// through `RoConn`s; the only current write surface
    /// (`PUT /api/policy/toml`) goes through `policy_advancer`
    /// which holds its own `Arc<Store>`.
    #[allow(dead_code)]
    store: Arc<Store>,
    /// Per-session agent-output capture. The kernel's gateway
    /// bridge writes to this; the dashboard's SSE handler
    /// subscribes to it.
    stream_capture: Arc<SessionStreamCapture>,
    /// Optional policy-write callback. Wired by the kernel main
    /// loop with [`KernelDashboardData::with_advancer`]. When
    /// `None`, `update_policy_toml` returns
    /// `ApiError::Forbidden` so the integration test fixtures
    /// (which don't boot the kernel) can opt out without
    /// silently exposing a no-op write surface.
    policy_advancer: Option<Arc<dyn PolicyAdvancer>>,
    /// Cached audit-chain integrity verdict + the
    /// monotonic-millis timestamp it was produced at, used by
    /// `audit_chain_status` to rate-limit chain re-walks per
    /// `INV-AUDIT-DASHBOARD-01`.
    chain_status_cache: parking_lot::Mutex<Option<ChainStatusView>>,
    /// Audit sink the kernel binary wires to the production
    /// chain. The dashboard pushes every `Operator*` event
    /// through this sink for `INV-AUDIT-OPERATOR-ACTION-01`.
    /// `None` when the host did not wire one (tests, read-only
    /// fixtures); attempts to emit return a hard error so the
    /// invariant is not silently violated.
    audit_sink: Option<Arc<dyn raxis_audit_tools::AuditSink>>,
    /// Per-operator rate-limit state for the credential reveal
    /// endpoints. `INV-DASHBOARD-CREDENTIAL-REVEAL-AUDITED-01`
    /// caps each operator at 5 reveals per 60-second sliding
    /// window so a script-against-the-endpoint attack can't
    /// silently page through the credential set.
    reveal_rate_limit: parking_lot::Mutex<RevealRateLimitState>,
    /// Optional per-task raw-LLM-turn capture. When set, the
    /// `GET /api/tasks/:task_id/llm-turns` route reads from the
    /// task's bounded file ring; when `None` (older test
    /// fixtures or read-only data dirs) the route returns
    /// `404 NotFound` so the absent capability is observable.
    task_llm_capture: Option<Arc<TaskLlmCapture>>,
    /// Optional per-session lifecycle capture. When set, the
    /// `GET /api/sessions/:session_id/capture` route reads from
    /// the session's bounded file ring; when `None` (older
    /// test fixtures or earlier hosts) the route falls back
    /// to the trait's default `Ok(vec![])` so the absent
    /// capability surfaces as an empty post-mortem list.
    /// `INV-DASHBOARD-SESSION-CAPTURE-PERSIST-AFTER-TERMINATION-01`.
    session_capture: Option<Arc<SessionCapture>>,
    /// iter61 — `INV-OBSERVABILITY-DATAPLANE-LATENCY-01`. When
    /// `Some(_)`, every read method funnels its store query
    /// through `raxis_store::observability::time_query` so the
    /// `raxis.store.query.duration` histogram observes one
    /// sample per dashboard query, tagged with `query_class`
    /// and `outcome`. The kernel main loop wires this in
    /// `start_dashboard_with_advancer`; when `None` (older
    /// integration / unit fixtures) the helper short-circuits
    /// and the queries run untimed.
    observability_hub: Option<Arc<raxis_observability::ObservabilityHub>>,
}

/// Sliding-window rate-limit state for the credential reveal
/// endpoints. One vec per operator fingerprint; we GC entries
/// older than `WINDOW` on every check so the map never grows
/// unboundedly even under churn.
#[derive(Debug, Default)]
struct RevealRateLimitState {
    /// Per-operator timestamp ring.
    by_operator: std::collections::HashMap<String, Vec<std::time::Instant>>,
}

/// Maximum reveals per operator per `REVEAL_RATE_LIMIT_WINDOW`.
/// `INV-DASHBOARD-CREDENTIAL-REVEAL-AUDITED-01`.
const REVEAL_RATE_LIMIT_MAX: u32 = 5;
/// Sliding-window length for the credential reveal rate limiter.
const REVEAL_RATE_LIMIT_WINDOW: std::time::Duration = std::time::Duration::from_secs(60);
/// Auto-hide deadline added to every per-initiative reveal
/// response. `INV-DASHBOARD-CREDENTIAL-AUTO-HIDE-01`.
const REVEAL_AUTOHIDE_INITIATIVE_SECS: u64 = 30;
/// Auto-hide deadline for system-credential reveals (Anthropic).
/// Shorter than the per-initiative default — the spec calls out
/// 15 seconds explicitly.
const REVEAL_AUTOHIDE_SYSTEM_SECS: u64 = 15;

impl KernelDashboardData {
    /// Build a new kernel-wired data layer.
    ///
    /// Returns an error when the streams directory cannot be
    /// created (e.g. read-only `data_dir`, a non-directory file
    /// already at `<data_dir>/streams`, ENOSPC). The previous
    /// implementation panicked here via `expect`, which would
    /// take the kernel down at dashboard-bind time on any of
    /// these cases — the caller now decides whether to disable
    /// the dashboard or surface the IO error.
    pub fn new(
        store: Arc<Store>,
        policy: Arc<ArcSwap<PolicyBundle>>,
        data_dir: PathBuf,
        policy_path: PathBuf,
        booted_at: u64,
    ) -> std::io::Result<Self> {
        let audit_dir = data_dir.join("audit");
        let stream_capture = SessionStreamCapture::new(&data_dir, CaptureConfig::default())?;
        Ok(Self {
            policy,
            data_dir,
            policy_path,
            audit_dir,
            booted_at,
            store,
            stream_capture,
            policy_advancer: None,
            chain_status_cache: parking_lot::Mutex::new(None),
            audit_sink: None,
            reveal_rate_limit: parking_lot::Mutex::new(RevealRateLimitState::default()),
            task_llm_capture: None,
            session_capture: None,
            observability_hub: None,
        })
    }

    /// Same as [`Self::new`] but with a caller-supplied capture
    /// (lets the kernel main loop share a single capture
    /// instance with the gateway bridge).
    pub fn with_capture(
        store: Arc<Store>,
        policy: Arc<ArcSwap<PolicyBundle>>,
        data_dir: PathBuf,
        policy_path: PathBuf,
        booted_at: u64,
        stream_capture: Arc<SessionStreamCapture>,
    ) -> Self {
        let audit_dir = data_dir.join("audit");
        Self {
            policy,
            data_dir,
            policy_path,
            audit_dir,
            booted_at,
            store,
            stream_capture,
            policy_advancer: None,
            chain_status_cache: parking_lot::Mutex::new(None),
            audit_sink: None,
            reveal_rate_limit: parking_lot::Mutex::new(RevealRateLimitState::default()),
            task_llm_capture: None,
            session_capture: None,
            observability_hub: None,
        }
    }

    /// iter61 — wire the observability hub so dashboard read
    /// methods funnel their store queries through
    /// `raxis_store::observability::time_query`. Builder-style.
    /// `INV-OBSERVABILITY-DATAPLANE-LATENCY-01`.
    pub fn with_observability_hub(
        mut self,
        hub: Arc<raxis_observability::ObservabilityHub>,
    ) -> Self {
        self.observability_hub = Some(hub);
        self
    }

    /// Wire the per-task raw-LLM-turn capture (`task_llm_capture.rs`).
    /// Builder-style: returns `Self` so the kernel main can
    /// chain the call onto `with_capture(...).with_task_llm_capture(...)`.
    pub fn with_task_llm_capture(mut self, capture: Arc<TaskLlmCapture>) -> Self {
        self.task_llm_capture = Some(capture);
        self
    }

    /// Wire the per-session lifecycle capture
    /// (`session_capture.rs`). Builder-style. Mirror of
    /// [`Self::with_task_llm_capture`] for the post-mortem
    /// surface — `INV-DASHBOARD-SESSION-CAPTURE-PERSIST-
    /// AFTER-TERMINATION-01`.
    pub fn with_session_capture(mut self, capture: Arc<SessionCapture>) -> Self {
        self.session_capture = Some(capture);
        self
    }

    /// Wire the kernel's audit sink onto the data layer so
    /// dashboard handlers can route `Operator*` events through
    /// `INV-AUDIT-OPERATOR-ACTION-01`. The sink is the SAME
    /// `Arc<dyn AuditSink>` the kernel main loop uses for every
    /// other audit emit, so chain order / sequence are preserved.
    ///
    /// Builder-style: returns `Self` so the kernel main can
    /// chain the call onto a `KernelDashboardData::with_capture(...)`.
    pub fn with_audit_sink(mut self, sink: Arc<dyn raxis_audit_tools::AuditSink>) -> Self {
        self.audit_sink = Some(sink);
        self
    }

    /// Wire a [`PolicyAdvancer`] callback. The kernel main loop
    /// calls this before handing the data layer to the
    /// dashboard server so `PUT /api/policy/toml` can drive
    /// `policy_manager::advance_epoch`.
    ///
    /// Builder-style: returns `Self` so the kernel main can
    /// chain the call onto a `KernelDashboardData::new(...)`.
    pub fn with_advancer(mut self, advancer: Arc<dyn PolicyAdvancer>) -> Self {
        self.policy_advancer = Some(advancer);
        self
    }

    /// Cloneable handle to the agent-stream capture. The
    /// kernel's gateway bridge holds this clone and writes to
    /// it via [`SessionStreamCapture::append`].
    pub fn stream_capture(&self) -> Arc<SessionStreamCapture> {
        Arc::clone(&self.stream_capture)
    }

    fn open_ro(&self) -> Result<raxis_store::ro::RoConn, ApiError> {
        raxis_store::ro::open(&self.data_dir).map_err(|e| ApiError::Internal {
            log_only: format!("ro::open failed: {e}"),
        })
    }
}

/// Map an `OperatorEntry::permitted_ops` set to the dashboard's
/// role triplet. The mapping is conservative: every operator
/// has `Read`; `RotateEpoch`-class permissions imply
/// `WritePolicy`; `RotateEpoch` + `OperatorCertInstall` imply
/// `Admin`.
///
/// Why bake this into kernel-side glue rather than the
/// dashboard crate: the canonical permitted-op vocabulary
/// belongs to `raxis-policy` (see kernel-store.md §2.5.5) —
/// the dashboard crate stays generic so tests can plug in
/// mock role sets without standing up the policy crate.
fn roles_from_permitted_ops(permitted: &[String]) -> Vec<DashboardRole> {
    let mut out = vec![DashboardRole::Read];
    let has = |op: &str| permitted.iter().any(|p| p == op);
    if has("RotateEpoch") || has("UpdatePolicy") {
        out.push(DashboardRole::WritePolicy);
    }
    if has("RotateEpoch") && has("OperatorCertInstall") {
        out.push(DashboardRole::Admin);
    }
    out
}

impl DashboardData for KernelDashboardData {
    fn lookup_operator_roles(&self, fingerprint: &str) -> Option<OperatorAuthResolution> {
        let bundle = self.policy.load_full();
        let entry = bundle.operator_entry(fingerprint)?;
        Some(OperatorAuthResolution {
            display_name: entry.display_name.clone(),
            roles: roles_from_permitted_ops(&entry.permitted_ops),
        })
    }

    fn health(&self) -> HealthSnapshot {
        let bundle = self.policy.load_full();
        let policy_epoch = bundle.epoch();
        let (active_initiatives, active_sessions, pending_escalations) = match self.open_ro() {
            Ok(conn) => {
                // INV-OBSERVABILITY-DATAPLANE-LATENCY-01 — the
                // dashboard polls `/api/health` every 5 s, so
                // these three counts are the heaviest-traffic
                // store reads in the system. Per-class timing
                // localises a slow health refresh to the
                // initiative / session / escalation counter.
                let hub = self.observability_hub.as_ref();
                let inits = raxis_store::observability::time_query(
                    hub,
                    raxis_store::observability::QUERY_CLASS_INITIATIVE_COUNT,
                    || {
                        raxis_store::views::initiatives::counts_by_state(&conn)
                            .map(|c| (c.draft + c.approved_plan + c.executing + c.blocked) as u32)
                            .unwrap_or(0)
                    },
                );
                let sess = raxis_store::observability::time_query(
                    hub,
                    raxis_store::observability::QUERY_CLASS_SESSION_COUNT,
                    || {
                        raxis_store::views::sessions::active_counts(&conn)
                            .map(|c| c.active as u32)
                            .unwrap_or(0)
                    },
                );
                let esc = raxis_store::observability::time_query(
                    hub,
                    raxis_store::observability::QUERY_CLASS_ESCALATION_COUNT,
                    || {
                        raxis_store::views::escalations::pending_count(&conn)
                            .map(|n| n as u32)
                            .unwrap_or(0)
                    },
                );
                (inits, sess, esc)
            }
            Err(_) => (0, 0, 0),
        };
        // Coarse status:
        //   - chain readable + store readable + policy loaded ⇒ "ok"
        //   - any one absent ⇒ "degraded"
        // We deliberately surface the per-check list only to
        // `admin` (the route handler degrades for `read` roles).
        let mut checks = Vec::new();
        match raxis_store::ro::open(&self.data_dir) {
            Ok(_) => checks.push(HealthCheck {
                id: "store_open".into(),
                status: "ok".into(),
                message: "kernel.db opened read-only".into(),
            }),
            Err(e) => checks.push(HealthCheck {
                id: "store_open".into(),
                status: "failing".into(),
                message: format!("kernel.db unreadable: {e}"),
            }),
        }
        match ChainReader::open(&self.audit_dir) {
            Ok(r) => checks.push(HealthCheck {
                id: "audit_chain".into(),
                status: "ok".into(),
                message: format!("{} segment(s) discovered", r.segment_count()),
            }),
            Err(e) => checks.push(HealthCheck {
                id: "audit_chain".into(),
                status: "failing".into(),
                message: format!("chain unreadable: {e}"),
            }),
        }
        let status = if checks.iter().all(|c| c.status == "ok") {
            "ok"
        } else if checks.iter().any(|c| c.status == "failing") {
            "failing"
        } else {
            "degraded"
        };
        HealthSnapshot {
            status: status.into(),
            checks,
            kernel_booted_at: self.booted_at,
            policy_epoch,
            active_initiatives,
            active_sessions,
            pending_escalations,
        }
    }

    fn subsystem_health(&self) -> Result<SubsystemHealthResponse, ApiError> {
        // Build one card per enumerated subsystem. Each branch
        // derives its verdict from the kernel's own bookkeeping
        // — `INV-DASHBOARD-VALIDATE-01` (dashboard does not
        // invent statuses). When the kernel has not surfaced a
        // signal for a subsystem yet (`booted_at` window, store
        // unreadable, etc.) we roll the card to `"unknown"`
        // with a short reason rather than guessing `"ok"`.
        // `now_ms` populates `SubsystemHealthResponse.generated_at_ms`
        // (correctly `_ms`-suffixed on the wire). `now_s` populates
        // `SubsystemHealthCard.last_observed_at`, which is documented
        // as unix-seconds in `crates/dashboard/src/data.rs:802-804`
        // and consumed as seconds by the FE's `fmtRelative`. Mixing
        // the two yielded "in 56,347 years" on every Health card
        // until we split the helpers; pinned by
        // `INV-DASHBOARD-WIRE-UNITS-CONSISTENT-01`.
        let now_ms = unix_now_ms();
        let now_s = unix_now_s();
        let store_ok = raxis_store::ro::open(&self.data_dir).is_ok();
        let chain_ok = ChainReader::open(&self.audit_dir).is_ok();
        // Best-effort kernel-main-loop heartbeat: read the live
        // `<data_dir>/runtime/heartbeat.json` the kernel's
        // `runtime::heartbeat::run_loop` rewrites every
        // `HEARTBEAT_INTERVAL`. `last_heartbeat_at` (NOT
        // `booted_at`) is the real liveness signal — the CLI's
        // `raxis status` already branches on this; the dashboard
        // now mirrors it via the same `Snapshot::is_live`
        // predicate so both surfaces stay in sync.
        let heartbeat = raxis_runtime::read(&self.data_dir).ok();
        let kernel_alive = self.booted_at > 0;
        let heartbeat_status = match heartbeat.as_ref() {
            Some(snap) if snap.is_live(now_s) => "ok",
            Some(_) => "degraded",
            None if kernel_alive => "degraded",
            None => "unknown",
        };
        let heartbeat_summary = match heartbeat.as_ref() {
            Some(snap) if snap.is_live(now_s) => {
                format!("Heartbeat fresh — state={state}.", state = snap.state)
            }
            Some(snap) => format!(
                "Heartbeat stale (last_heartbeat_at={ts}); kernel may be hung.",
                ts = snap.last_heartbeat_at,
            ),
            None if kernel_alive => {
                "Heartbeat file missing — kernel has not yet written `runtime/heartbeat.json`."
                    .to_owned()
            }
            None => "Kernel boot timestamp not yet recorded.".to_owned(),
        };
        let heartbeat_observed_at: u64 = heartbeat
            .as_ref()
            .map(|s| s.last_heartbeat_at)
            .unwrap_or_else(|| if kernel_alive { self.booted_at } else { 0 });
        let heartbeat_details: Vec<SubsystemDetailRow> = if let Some(snap) = heartbeat.as_ref() {
            vec![
                SubsystemDetailRow {
                    label: "Last heartbeat (unix-s)".into(),
                    value: snap.last_heartbeat_at.to_string(),
                },
                SubsystemDetailRow {
                    label: "Booted at (unix-s)".into(),
                    value: snap.started_at.to_string(),
                },
                SubsystemDetailRow {
                    label: "State".into(),
                    value: snap.state.clone(),
                },
                SubsystemDetailRow {
                    label: "PID".into(),
                    value: snap.kernel_pid.to_string(),
                },
                SubsystemDetailRow {
                    label: "Active verifiers".into(),
                    value: format!(
                        "{}/{}",
                        snap.active_verifiers, snap.max_concurrent_verifiers
                    ),
                },
            ]
        } else {
            vec![SubsystemDetailRow {
                label: "Booted at (unix-s)".into(),
                value: self.booted_at.to_string(),
            }]
        };

        let mut cards: Vec<SubsystemHealthCard> = SUBSYSTEM_CATALOG
            .iter()
            .map(|(id, label)| {
                let (status, summary, details, last_observed_at, grafana_url) = match *id {
                    "kernel_main_loop" => (
                        heartbeat_status,
                        heartbeat_summary.clone(),
                        heartbeat_details.clone(),
                        heartbeat_observed_at,
                        grafana_dashboard_url("kernel"),
                    ),
                    "audit_writer" => {
                        let s = if chain_ok { "ok" } else { "failing" };
                        let summary = if chain_ok {
                            "Audit segments readable; chain reader opens cleanly.".to_owned()
                        } else {
                            "Chain reader could not open audit directory.".to_owned()
                        };
                        let details = match ChainReader::open(&self.audit_dir) {
                            Ok(r) => vec![SubsystemDetailRow {
                                label: "Segments discovered".into(),
                                value: r.segment_count().to_string(),
                            }],
                            Err(e) => vec![SubsystemDetailRow {
                                label: "Reader error".into(),
                                value: e.to_string(),
                            }],
                        };
                        (s, summary, details, now_s, grafana_dashboard_url("audit"))
                    }
                    "credential_proxies" => (
                        if store_ok { "ok" } else { "unknown" },
                        "Credential-proxy registry tracked in kernel.db.".to_owned(),
                        vec![],
                        if store_ok { now_s } else { 0 },
                        grafana_dashboard_url("credentials"),
                    ),
                    "egress_admission" => (
                        if store_ok { "ok" } else { "unknown" },
                        "Egress-admission decisions surfaced via audit chain.".to_owned(),
                        vec![],
                        if store_ok { now_s } else { 0 },
                        grafana_dashboard_url("egress"),
                    ),
                    "session_spawn_pool" => (
                        if store_ok { "ok" } else { "unknown" },
                        "Session spawn / lifecycle visible through sessions view.".to_owned(),
                        vec![],
                        if store_ok { now_s } else { 0 },
                        grafana_dashboard_url("sessions"),
                    ),
                    "planner_registry" => (
                        if store_ok { "ok" } else { "unknown" },
                        "Planner registry health derives from planner-core.".to_owned(),
                        vec![],
                        if store_ok { now_s } else { 0 },
                        grafana_dashboard_url("planner"),
                    ),
                    "observability_pusher" => {
                        let obs = self.policy.load().observability().clone();
                        let card = classify_observability_pusher(&self.data_dir, &obs, now_s);
                        (
                            card.status,
                            card.summary,
                            card.details,
                            card.last_observed_at,
                            grafana_dashboard_url("observability"),
                        )
                    }
                    "git_worktree_pool" => (
                        if store_ok { "ok" } else { "unknown" },
                        "Git worktree pool tracked in initiatives view.".to_owned(),
                        vec![],
                        if store_ok { now_s } else { 0 },
                        None,
                    ),
                    "dashboard_sse_pump" => (
                        "ok",
                        "SSE pump active — this request was served by it.".to_owned(),
                        vec![],
                        now_s,
                        None,
                    ),
                    _ => (
                        "unknown",
                        "No reporter wired for this subsystem.".to_owned(),
                        vec![],
                        0,
                        None,
                    ),
                };
                // `last_error` mirrors the subsystem's hard-failure
                // reason when the kernel has one. V2 reporters route
                // their human-readable failure string through the
                // `summary` field; we promote it to `last_error` on
                // `failing` / `degraded` cards so the FE's shared
                // `<FailureReasonPanel>` renders a uniform surface
                // (`INV-DASHBOARD-FAILURE-VISIBILITY-01`). Healthy /
                // unknown cards keep `last_error = None`.
                let last_error = match status {
                    "failing" | "degraded" if !summary.is_empty() => Some(summary.clone()),
                    _ => None,
                };
                SubsystemHealthCard {
                    id: (*id).to_owned(),
                    label: (*label).to_owned(),
                    status: status.to_owned(),
                    summary,
                    details,
                    grafana_url,
                    last_observed_at,
                    last_error,
                }
            })
            .collect();

        // Aggregate the per-card statuses into a single banner
        // tone the FE renders without re-walking the cards.
        let aggregate_status = aggregate_subsystem_status(&cards);

        // Sort kernel-canonical order (catalog order) and let
        // the FE render the grid in that order.
        cards.sort_by_key(|c| {
            SUBSYSTEM_CATALOG
                .iter()
                .position(|(id, _)| *id == c.id)
                .unwrap_or(usize::MAX)
        });

        Ok(SubsystemHealthResponse {
            aggregate_status,
            cards,
            generated_at_ms: now_ms,
        })
    }

    fn list_initiatives(
        &self,
        limit: u32,
        state_filter: Option<&str>,
    ) -> Result<Vec<InitiativeListEntry>, ApiError> {
        let conn = self.open_ro()?;
        // INV-OBSERVABILITY-DATAPLANE-LATENCY-01.
        let rows = raxis_store::observability::time_query_result(
            self.observability_hub.as_ref(),
            raxis_store::observability::QUERY_CLASS_INITIATIVE_LIST,
            || raxis_store::views::initiatives::list(&conn, state_filter, limit.min(200) as usize),
        )
        .map_err(|e| ApiError::Internal {
            log_only: format!("initiatives::list: {e}"),
        })?;
        // Per-initiative task counts (one extra read per row — bounded
        // by `limit` so worst-case is 200 lookups).
        let mut out = Vec::with_capacity(rows.len());
        for r in rows {
            let tasks = raxis_store::views::tasks::list_by_initiative(&conn, &r.initiative_id, 500)
                .map_err(|e| ApiError::Internal {
                    log_only: format!("tasks::list_by_initiative: {e}"),
                })?;
            let task_count = tasks.len() as u32;
            let completed_tasks = tasks.iter().filter(|t| t.state == "Completed").count() as u32;
            let failed_tasks = tasks.iter().filter(|t| t.state == "Failed").count() as u32;
            let updated_at = tasks
                .iter()
                .map(|t| t.transitioned_at)
                .max()
                .unwrap_or(r.created_at);
            // The operator-visible name is exactly `[workspace].name`.
            // There is intentionally no read-side UUID fallback:
            // missing or invalid names are plan-quality errors the
            // operator should see.
            let display_name = initiative_name_for_id(&conn, &r.initiative_id)?;
            out.push(InitiativeListEntry {
                initiative_id: r.initiative_id,
                display_name,
                state: r.state,
                task_count,
                completed_tasks,
                failed_tasks,
                created_at: r.created_at,
                updated_at,
            });
        }
        Ok(out)
    }

    fn get_initiative(&self, id: &str) -> Result<InitiativeView, ApiError> {
        let conn = self.open_ro()?;
        // INV-OBSERVABILITY-DATAPLANE-LATENCY-07.
        let row = raxis_store::observability::time_query_result(
            self.observability_hub.as_ref(),
            raxis_store::observability::QUERY_CLASS_INITIATIVE_GET,
            || raxis_store::views::initiatives::by_id(&conn, id),
        )
        .map_err(|e| ApiError::Internal {
            log_only: format!("initiatives::by_id: {e}"),
        })?
        .ok_or(ApiError::NotFound {
            kind: "initiative".into(),
        })?;
        let bundle = self.policy.load_full();
        let task_rows =
            raxis_store::views::tasks::list_by_initiative(&conn, id, 500).map_err(|e| {
                ApiError::Internal {
                    log_only: format!("tasks::list_by_initiative: {e}"),
                }
            })?;
        let task_count = task_rows.len() as u32;
        let completed_tasks = task_rows.iter().filter(|t| t.state == "Completed").count() as u32;
        let failed_tasks = task_rows.iter().filter(|t| t.state == "Failed").count() as u32;
        let updated_at = task_rows
            .iter()
            .map(|t| t.transitioned_at)
            .max()
            .unwrap_or(row.created_at);
        let mut tasks = Vec::with_capacity(task_rows.len());
        let edges = raxis_store::views::tasks::dag_edges_for_initiative(&conn, id)
            .map(|rows| {
                rows.into_iter()
                    .map(|e| DagEdge {
                        from: e.predecessor_task_id,
                        to: e.successor_task_id,
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        // Pre-load the audit chain ONCE for the whole initiative
        // and index it so per-task classification doesn't
        // re-filter / re-sort the same chain per row.
        let audit_chain = collect_lifecycle_audit_rows(&self.audit_dir);
        let audit_index = LifecycleAuditIndex::new(&audit_chain);
        for t in &task_rows {
            tasks.push(task_row_to_view_with_lifecycle_indexed(
                &conn,
                &audit_index,
                t,
            )?);
        }
        let display_name = initiative_name_for_id(&conn, &row.initiative_id)?;
        // INV-DASHBOARD-FAILURE-VISIBILITY-01: when the initiative
        // is in a terminal-failure state, surface the most recent
        // failure-bearing audit row as `failure`. V2.5 ships the
        // wire shape; the kernel-side projection is best-effort —
        // V3 will widen this to a richer audit-chain walker. Until
        // then, `None` here causes the FE to render "No reason
        // supplied — kernel bug" so the gap is visible.
        let failure = None;
        Ok(InitiativeView {
            summary: InitiativeListEntry {
                initiative_id: row.initiative_id.clone(),
                display_name,
                state: row.state,
                task_count,
                completed_tasks,
                failed_tasks,
                created_at: row.created_at,
                updated_at,
            },
            approved_by: None, // not stored on initiatives row
            plan_sha256: Some(row.plan_artifact_sha256),
            target_ref: None,
            policy_epoch: bundle.epoch(),
            tasks,
            edges,
            failure,
        })
    }

    fn list_tasks(&self, initiative_id: &str) -> Result<Vec<TaskView>, ApiError> {
        let conn = self.open_ro()?;
        // Pre-load the audit chain ONCE per request so the
        // per-row classifier can use task-scoped slices without
        // re-walking / re-sorting the chain per task.
        // `INV-DASHBOARD-LIFECYCLE-CAUSALITY-01`.
        let audit_chain = collect_lifecycle_audit_rows(&self.audit_dir);
        let audit_index = LifecycleAuditIndex::new(&audit_chain);
        // INV-OBSERVABILITY-DATAPLANE-LATENCY-01.
        let rows = raxis_store::observability::time_query_result(
            self.observability_hub.as_ref(),
            raxis_store::observability::QUERY_CLASS_TASK_LIST,
            || raxis_store::views::tasks::list_by_initiative(&conn, initiative_id, 500),
        )
        .map_err(|e| ApiError::Internal {
            log_only: format!("tasks::list_by_initiative: {e}"),
        })?;
        rows.iter()
            .map(|t| task_row_to_view_with_lifecycle_indexed(&conn, &audit_index, t))
            .collect()
    }

    /// `GET /api/initiatives/:id/plan` —
    /// `INV-DASHBOARD-INITIATIVE-PLAN-VISIBLE-01`.
    ///
    /// Walks the production V1 → V2.1 fallback chain via
    /// [`raxis_store::views::plan_fields::submitted_toml_for_initiative`]
    /// so the dashboard surfaces the EXACT bytes the operator
    /// sealed (no re-parse / re-serialize). 404 vs 410 is the
    /// distinction between "unknown initiative" and "plan
    /// archived" — the FE renders different copy for each.
    fn get_initiative_plan(&self, id: &str) -> Result<InitiativePlanView, ApiError> {
        let conn = self.open_ro()?;

        // Step 1 — initiative existence (404 vs 410 disambiguation).
        let init_row = raxis_store::views::initiatives::by_id(&conn, id)
            .map_err(|e| ApiError::Internal {
                log_only: format!("initiatives::by_id: {e}"),
            })?
            .ok_or(ApiError::NotFound {
                kind: "initiative".into(),
            })?;

        // Step 2 — original submitted TOML (V1 + V2.1 fallback).
        // INV-OBSERVABILITY-DATAPLANE-LATENCY-07 — the plan
        // bundle materialisation is the dominant SQLite read on
        // the plan-detail surface; tag it with `plan_bundle_get`
        // so a slow plan TOML walk lights up here independently
        // of the cheap existence check above.
        let raw = raxis_store::observability::time_query_result(
            self.observability_hub.as_ref(),
            raxis_store::observability::QUERY_CLASS_PLAN_BUNDLE_GET,
            || raxis_store::views::plan_fields::submitted_toml_for_initiative(&conn, id),
        )
        .map_err(|e| ApiError::Internal {
            log_only: format!("plan_fields::submitted_toml_for_initiative: {e}"),
        })?
        .ok_or(ApiError::Gone {
            kind: "plan".into(),
        })?;

        // The DDL pins both `signed_plan_artifacts.plan_bytes` and
        // `plan_bundle_artifacts.artifact_bytes` to BLOB; every
        // production producer writes UTF-8 (the codec validates).
        // A non-UTF-8 row is a kernel bug — surface it as a
        // structured 500 rather than corrupt the wire body.
        let toml_string = String::from_utf8(raw).map_err(|e| ApiError::Internal {
            log_only: format!("plan TOML for initiative {id} is not valid UTF-8: {e}",),
        })?;
        let toml_len = toml_string.len() as u64;

        // Step 3 — V2.1 bundle metadata (best-effort; V1 plans
        // return None and we fall through to the V1 header).
        let mut bundle_sha256_hex: Option<String> = None;
        let mut submitted_at_unix: i64 = init_row.created_at as i64;
        let mut submitted_by: Option<String> = None;
        if let Some(sha) = raxis_store::views::initiatives::plan_bundle_sha256_by_id(&conn, id)
            .map_err(|e| ApiError::Internal {
                log_only: format!("initiatives::plan_bundle_sha256_by_id: {e}"),
            })?
        {
            bundle_sha256_hex = Some(hex::encode(sha.as_bytes()));
            if let Some(header) = raxis_store::views::plan_bundles::header_by_sha256(&conn, &sha)
                .map_err(|e| ApiError::Internal {
                    log_only: format!("plan_bundles::header_by_sha256: {e}"),
                })?
            {
                // Prefer the operator-supplied signed_at_unix_secs
                // (V2.1 envelope) when present; fall back to the
                // store-side sealed_at otherwise. Either is a real
                // wall-clock timestamp the operator can correlate
                // against the audit chain.
                submitted_at_unix = header
                    .signed_at_unix_secs
                    .unwrap_or(header.sealed_at_unix_secs);
                submitted_by = Some(hex::encode(header.signed_by.as_bytes()));
            }
        } else {
            // V1 fallback — read the signed_plan_artifacts header
            // for the stored_at + fingerprint surface. The plan
            // itself was already loaded above; this is only for
            // forensic metadata.
            if let Some(header) = raxis_store::views::signed_plan_artifacts::header_by_initiative(
                &conn, id,
            )
            .map_err(|e| ApiError::Internal {
                log_only: format!("signed_plan_artifacts::header_by_initiative: {e}"),
            })? {
                submitted_at_unix = header.stored_at;
                submitted_by = header.signed_by_fingerprint;
            }
        }

        // Step 4 — approval verdict from the FSM state. Mirrors
        // kernel-store.md §2.5.1 Table 2: `Draft` is the only
        // pre-approval state; everything else means the kernel
        // accepted the plan (terminal `Failed` / `Aborted` stay
        // approved unless the failure happened in admission, in
        // which case `approved_at` is None and we surface
        // "rejected" so the FE can render a distinct copy).
        let approval_status = match (init_row.state.as_str(), init_row.approved_at) {
            ("Draft", _) => "pending",
            (_, Some(_)) => "approved",
            (_, None) => "rejected",
        }
        .to_owned();

        Ok(InitiativePlanView {
            initiative_id: init_row.initiative_id,
            plan_sha256: if init_row.plan_artifact_sha256.is_empty() {
                None
            } else {
                Some(init_row.plan_artifact_sha256)
            },
            bundle_sha256: bundle_sha256_hex,
            submitted_toml: toml_string,
            submitted_toml_bytes: toml_len,
            submitted_at_unix,
            submitted_by,
            approval_status,
            approved_at_unix: init_row.approved_at.map(|v| v as i64),
        })
    }

    fn get_task(&self, task_id: &str) -> Result<TaskView, ApiError> {
        let conn = self.open_ro()?;
        // Pull the audit chain once + classify into structured
        // annotations so `<LifecycleTimeline>` and
        // `<ReviewerVerdictPanel>` on TaskDetail render without
        // a second round-trip.
        // `INV-DASHBOARD-LIFECYCLE-CAUSALITY-01`.
        let audit_chain = collect_lifecycle_audit_rows(&self.audit_dir);
        // INV-OBSERVABILITY-DATAPLANE-LATENCY-07.
        let row = raxis_store::observability::time_query_result(
            self.observability_hub.as_ref(),
            raxis_store::observability::QUERY_CLASS_TASK_GET,
            || raxis_store::views::tasks::by_id(&conn, task_id),
        )
        .map_err(|e| ApiError::Internal {
            log_only: format!("tasks::by_id: {e}"),
        })?
        .ok_or(ApiError::NotFound {
            kind: "task".into(),
        })?;
        task_row_to_view_with_lifecycle(&conn, &audit_chain, &row)
    }

    /// `INV-DASHBOARD-TASK-LLM-CAPTURE-01`,
    /// `INV-DASHBOARD-LLM-TURN-PANEL-WIRE-SHAPE-01`. Tail the
    /// per-task raw-LLM-turn ring and project each
    /// [`crate::LlmTurnRecord`] to the dashboard's
    /// [`raxis_dashboard::data::TaskLlmTurnView`]. Returns
    /// `Err(ApiError::NotFound { kind: "task_llm_turns" })` when
    /// the kernel did not wire a capture (read-only data dir /
    /// EROFS / ENOSPC at boot) so the absent capability is
    /// observable to the operator.
    ///
    /// `tail()` returns records in disk-append order; we
    /// thread the index through `record_to_view` as
    /// `turn_number = i + 1` so the FE can render "Turn 1",
    /// "Turn 2", … without sorting.
    fn tail_task_llm_turns(
        &self,
        task_id: &str,
        n: u32,
    ) -> Result<Vec<raxis_dashboard::data::TaskLlmTurnView>, ApiError> {
        let cap = self.task_llm_capture.as_ref().ok_or(ApiError::NotFound {
            kind: "task_llm_turns".into(),
        })?;
        let n = (n.min(500)) as usize;
        let records = cap.tail(task_id, n);
        Ok(records
            .into_iter()
            .enumerate()
            .map(|(i, r)| record_to_view(r, (i as u32).saturating_add(1)))
            .collect())
    }

    /// `INV-DASHBOARD-SESSION-CAPTURE-FIXED-RING-01` /
    /// `INV-DASHBOARD-SESSION-CAPTURE-PERSIST-AFTER-TERMINATION-01`.
    /// Tail the per-session lifecycle ring and project each
    /// [`SessionCaptureRecord`] to the dashboard's
    /// [`raxis_dashboard::data::SessionCaptureView`]. Returns
    /// `Ok(vec![])` when the kernel did not wire a capture
    /// (older fixtures, read-only data dir at boot). The
    /// post-mortem path stays available even after the session
    /// terminates — the ring is keyed by `session_id`, the
    /// observer is the kernel (not the planner VM), and
    /// `tail` reads from disk so an in-memory eviction does
    /// not lose records.
    fn tail_session_capture(
        &self,
        session_id: &str,
        n: u32,
    ) -> Result<Vec<raxis_dashboard::data::SessionCaptureView>, ApiError> {
        let Some(cap) = self.session_capture.as_ref() else {
            return Ok(Vec::new());
        };
        let n = (n.min(500)) as usize;
        let records = cap.tail(session_id, n);
        Ok(records.into_iter().map(session_record_to_view).collect())
    }

    /// `INV-DASHBOARD-LIFECYCLE-CAUSALITY-01`. Walk the
    /// `subtask_activations` table for every row in
    /// `PendingActivation` whose `created_at` is older than
    /// the 120-second cutoff AND every predecessor task is
    /// `Completed`. The pure
    /// [`lifecycle::classify_orchestrator_gaps`] classifier
    /// owns the policy.
    fn list_orchestrator_gaps(&self) -> Result<OrchestratorGapsResponse, ApiError> {
        let conn = self.open_ro()?;
        let activations = read_activations_all(&conn);
        let tasks = read_tasks_with_predecessors(&conn);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        let gaps = lifecycle::classify_orchestrator_gaps(&activations, &tasks, now);
        Ok(OrchestratorGapsResponse {
            gaps,
            generated_at: now,
        })
    }

    /// V3 — `INV-DASHBOARD-GATE-STATS-PER-GATE-ROLLUP-01`.
    ///
    /// Roll up `witness_records` by `gate_type`, joining
    /// `tasks.gate_fixup_attempts` so the dashboard can render
    /// the fixup-loop dimension without a second round-trip.
    /// One read-only connection, two grouped scans, no joins
    /// (we aggregate in two passes and stitch in Rust to keep
    /// the SQL trivially auditable and to avoid the cartesian
    /// blow-up of a window-function over both tables).
    /// Per-task latest state per mechanical witness gate for every
    /// task in `initiative_id`.
    ///
    /// This intentionally starts from `verifier_run_tokens`, not
    /// `witness_records`, so a gate appears in the DAG as soon as
    /// the kernel spawns the verifier. If a matching witness row
    /// exists, its `result_class` wins; otherwise the verdict is
    /// `"Pending"`. The FE renders these as dashed gate nodes rather
    /// than hiding them in a tiny dot strip.
    fn list_dag_gate_summaries(
        &self,
        initiative_id: &str,
    ) -> Result<
        std::collections::HashMap<String, Vec<raxis_dashboard::data::DagGateVerdictChip>>,
        ApiError,
    > {
        use std::collections::{BTreeMap, HashMap};
        let conn = self.open_ro()?;
        let sql = format!(
            "SELECT v.task_id, v.gate_type, \
                    COALESCE(w.result_class, 'Pending') AS latest_verdict, \
                    COALESCE(w.recorded_at, v.issued_at) AS observed_at \
             FROM {TBL_VERIFIER_RUN_TOKENS} v \
             JOIN {TBL_TASKS} t ON t.task_id = v.task_id \
             LEFT JOIN {TBL_WITNESS_RECORDS} w \
                    ON w.verifier_run_id = v.verifier_run_id \
             WHERE t.initiative_id = ?1 \
             ORDER BY v.task_id, v.gate_type, observed_at ASC"
        );
        let mut stmt = conn.prepare(&sql).map_err(|e| ApiError::Internal {
            log_only: format!("dag_gate_summaries prepare: {e}"),
        })?;
        let rows = stmt
            .query_map(rusqlite::params![initiative_id], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    raxis_dashboard::data::DagGateVerdictChip {
                        gate_type: row.get(1)?,
                        latest_verdict: row.get(2)?,
                        recorded_at: row.get::<_, i64>(3)?.max(0),
                    },
                ))
            })
            .map_err(|e| ApiError::Internal {
                log_only: format!("dag_gate_summaries query: {e}"),
            })?;
        let mut out: HashMap<String, Vec<raxis_dashboard::data::DagGateVerdictChip>> =
            HashMap::new();
        let mut grouped: HashMap<
            String,
            BTreeMap<String, raxis_dashboard::data::DagGateVerdictChip>,
        > = HashMap::new();
        for r in rows {
            let (task_id, chip) = r.map_err(|e| ApiError::Internal {
                log_only: format!("dag_gate_summaries row: {e}"),
            })?;
            grouped
                .entry(task_id)
                .or_default()
                .insert(chip.gate_type.clone(), chip);
        }
        for (task_id, by_gate) in grouped {
            out.insert(task_id, by_gate.into_values().collect());
        }
        Ok(out)
    }

    /// iter68 PR 5 — `GET /api/witnesses?limit=N`.
    ///
    /// Newest-first cross-task witness timeline. One ORDER BY +
    /// LIMIT scan; no joins. Capped at 500 by the route handler.
    fn list_recent_witnesses(
        &self,
        limit: u32,
    ) -> Result<Vec<raxis_dashboard::data::WitnessView>, ApiError> {
        let conn = self.open_ro()?;
        let sql = format!(
            "SELECT verifier_run_id, task_id, gate_type, result_class, \
                    evaluation_sha, blob_sha256, recorded_at \
             FROM {TBL_WITNESS_RECORDS} \
             ORDER BY recorded_at DESC, verifier_run_id DESC \
             LIMIT ?1"
        );
        let mut stmt = conn.prepare(&sql).map_err(|e| ApiError::Internal {
            log_only: format!("recent_witnesses prepare: {e}"),
        })?;
        let rows = stmt
            .query_map(rusqlite::params![limit as i64], |r| {
                Ok(raxis_dashboard::data::WitnessView {
                    verifier_run_id: r.get(0)?,
                    task_id: r.get(1)?,
                    gate_type: r.get(2)?,
                    result_class: r.get(3)?,
                    evaluation_sha: r.get(4)?,
                    blob_sha256: r.get(5)?,
                    recorded_at: r.get::<_, i64>(6)?.max(0),
                })
            })
            .map_err(|e| ApiError::Internal {
                log_only: format!("recent_witnesses query: {e}"),
            })?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| ApiError::Internal {
                log_only: format!("recent_witnesses collect: {e}"),
            })?;
        Ok(rows)
    }

    /// iter68 — `GET /api/tasks/:task_id/witnesses`.
    ///
    /// Read-side wrapper around
    /// `raxis_store::views::witnesses::for_task`. The store
    /// projection is already shaped correctly; we only need to
    /// convert the `WitnessRow` → `WitnessView` and forward
    /// SQL errors as `ApiError::Internal`.
    fn list_witnesses_for_task(
        &self,
        task_id: &str,
    ) -> Result<Vec<raxis_dashboard::data::WitnessView>, ApiError> {
        let conn = self.open_ro()?;
        let rows = raxis_store::views::witnesses::for_task(&conn, task_id).map_err(|e| {
            ApiError::Internal {
                log_only: format!("witnesses for_task: {e}"),
            }
        })?;
        Ok(rows
            .into_iter()
            .map(|r| raxis_dashboard::data::WitnessView {
                verifier_run_id: r.verifier_run_id,
                task_id: r.task_id,
                gate_type: r.gate_type,
                result_class: r.result_class,
                evaluation_sha: r.evaluation_sha,
                blob_sha256: r.blob_sha256,
                recorded_at: r.recorded_at.min(i64::MAX as u64) as i64,
            })
            .collect())
    }

    /// iter68 — `specs/v3/worktree-snapshots.md` §5.
    ///
    /// List every snapshot row for the task. The SQL query is
    /// pinned to the column order produced by migration 24;
    /// adding / removing a column there requires a parallel edit
    /// here. The query MUST stay in lockstep with
    /// `raxis-kernel::worktree_snapshot::list_for_task` — these
    /// are the two production read paths. We could share via a
    /// helper crate (TODO when a third caller appears).
    fn list_worktree_snapshots(
        &self,
        task_id: &str,
    ) -> Result<Vec<raxis_dashboard::data::WorktreeSnapshotView>, ApiError> {
        let conn = self.open_ro()?;
        let sql = format!(
            "SELECT DISTINCT snapshot_id, task_id, session_id, initiative_id, \
                    trigger, taken_at, base_sha, head_sha, commit_count, \
                    diff_blob_sha256, log_blob_sha256, tree_blob_sha256, \
                    porcelain_blob_sha256, diff_bytes_total, diff_truncated \
             FROM {TBL_WORKTREE_SNAPSHOTS} \
             WHERE task_id = ?1 \
                OR (session_id IS NOT NULL \
                    AND session_id = (SELECT session_id FROM {TBL_TASKS} WHERE task_id = ?1)) \
                OR (task_id = (SELECT initiative_id FROM {TBL_TASKS} WHERE task_id = ?1) \
                    AND initiative_id = (SELECT initiative_id FROM {TBL_TASKS} WHERE task_id = ?1)) \
             ORDER BY taken_at DESC, snapshot_id DESC"
        );
        let mut stmt = conn.prepare(&sql).map_err(|e| ApiError::Internal {
            log_only: format!("worktree_snapshots prepare: {e}"),
        })?;
        let rows = stmt
            .query_map(rusqlite::params![task_id], parse_worktree_snapshot_row)
            .map_err(|e| ApiError::Internal {
                log_only: format!("worktree_snapshots query: {e}"),
            })?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| ApiError::Internal {
                log_only: format!("worktree_snapshots collect: {e}"),
            })?;
        Ok(rows)
    }

    /// iter68 — fetch one snapshot row.
    fn get_worktree_snapshot(
        &self,
        snapshot_id: &str,
    ) -> Result<raxis_dashboard::data::WorktreeSnapshotView, ApiError> {
        let conn = self.open_ro()?;
        let sql = format!(
            "SELECT snapshot_id, task_id, session_id, initiative_id, \
                    trigger, taken_at, base_sha, head_sha, commit_count, \
                    diff_blob_sha256, log_blob_sha256, tree_blob_sha256, \
                    porcelain_blob_sha256, diff_bytes_total, diff_truncated \
             FROM {TBL_WORKTREE_SNAPSHOTS} WHERE snapshot_id = ?1"
        );
        match conn.query_row(
            &sql,
            rusqlite::params![snapshot_id],
            parse_worktree_snapshot_row,
        ) {
            Ok(v) => Ok(v),
            Err(rusqlite::Error::QueryReturnedNoRows) => Err(ApiError::NotFound {
                kind: "worktree_snapshot".into(),
            }),
            Err(e) => Err(ApiError::Internal {
                log_only: format!("worktree_snapshot get: {e}"),
            }),
        }
    }

    /// iter68 — read a body blob off disk. The shape of the
    /// on-disk path MUST match `kernel::worktree_snapshot::
    /// blob_path` exactly; the literal `<data_dir>/worktree-
    /// snapshots/blobs/<sha>` is pinned here so a rename on the
    /// kernel side requires a parallel edit (and the integration
    /// test in PR 2 catches the drift).
    fn read_worktree_snapshot_blob(
        &self,
        snapshot_id: &str,
        kind: raxis_dashboard::data::WorktreeSnapshotBlobKind,
    ) -> Result<Vec<u8>, ApiError> {
        let view = self.get_worktree_snapshot(snapshot_id)?;
        let sha = kind.sha256_of(&view).ok_or(ApiError::NotFound {
            kind: "worktree_snapshot_blob_empty".into(),
        })?;
        if !is_sha256_hex(sha) {
            return Err(ApiError::Internal {
                log_only: format!(
                    "worktree snapshot {snapshot_id} carries invalid {} blob sha",
                    kind.as_path_segment()
                ),
            });
        }
        let path = self
            .data_dir
            .join("worktree-snapshots")
            .join("blobs")
            .join(sha);
        std::fs::read(&path).map_err(|_| ApiError::NotFound {
            kind: "worktree_snapshot_blob".into(),
        })
    }

    fn gate_stats(&self) -> Result<raxis_dashboard::data::GateStatsResponse, ApiError> {
        use raxis_dashboard::data::{GateStatRow, GateStatsResponse};
        let conn = self.open_ro()?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);

        // Pass 1 — per-gate witness counts + last-seen
        // timestamp. Ordered by gate_type so the rollup is
        // stable across polls (a sparkline view diffs row-by-
        // row across requests).
        let mut stmt = conn
            .prepare(&format!(
                "SELECT gate_type, result_class, \
                        COUNT(*) AS n, \
                        MAX(recorded_at) AS last_seen \
                   FROM {TBL_WITNESS_RECORDS} \
                  GROUP BY gate_type, result_class \
                  ORDER BY gate_type"
            ))
            .map_err(|e| ApiError::Internal {
                log_only: format!("gate_stats: prepare witness rollup: {e}"),
            })?;
        let mut rows_iter = stmt
            .query_map([], |r| {
                let gate_type: String = r.get(0)?;
                let result_class: String = r.get(1)?;
                let n: i64 = r.get(2)?;
                let last_seen: i64 = r.get(3)?;
                Ok((gate_type, result_class, n, last_seen))
            })
            .map_err(|e| ApiError::Internal {
                log_only: format!("gate_stats: query witness rollup: {e}"),
            })?;

        // Aggregate into a BTreeMap so iteration order is
        // alphabetically stable — the contract documented in
        // `DashboardData::gate_stats`'s docstring.
        let mut acc: std::collections::BTreeMap<String, GateStatRow> =
            std::collections::BTreeMap::new();
        for row in rows_iter.by_ref() {
            let (gate_type, result_class, n, last_seen) = row.map_err(|e| ApiError::Internal {
                log_only: format!("gate_stats: scan witness row: {e}"),
            })?;
            let entry = acc.entry(gate_type.clone()).or_insert_with(|| GateStatRow {
                gate_type,
                pass_count: 0,
                fail_count: 0,
                inconclusive_count: 0,
                last_seen_at: None,
                fixup_loop_count: 0,
            });
            let n_u64 = u64::try_from(n).unwrap_or(0);
            match result_class.as_str() {
                "Pass" => entry.pass_count = entry.pass_count.saturating_add(n_u64),
                "Fail" => entry.fail_count = entry.fail_count.saturating_add(n_u64),
                "Inconclusive" => {
                    entry.inconclusive_count = entry.inconclusive_count.saturating_add(n_u64);
                }
                // Any other `result_class` value would be a DDL
                // CHECK violation; surface zeros rather than
                // panic. The check constraint is enforced at
                // INSERT time so this branch is unreachable in
                // a non-corrupted DB.
                _ => {}
            }
            // Track the most-recent `recorded_at` across all
            // outcome classes for this gate.
            let prev = entry.last_seen_at.unwrap_or(0);
            if last_seen > prev {
                entry.last_seen_at = Some(last_seen);
            }
        }
        drop(rows_iter);
        drop(stmt);

        // Pass 2 — cumulative fixup-loop count per gate. We
        // sum `tasks.gate_fixup_attempts` grouped by
        // `last_gate_type`, which is the column the witness
        // handler populates when a gate rejects. Tasks that
        // never failed a gate have NULL `last_gate_type` and
        // are dropped from the rollup by the GROUP BY.
        let mut stmt2 = conn
            .prepare(&format!(
                "SELECT last_gate_type, SUM(gate_fixup_attempts) AS attempts \
                   FROM {TBL_TASKS} \
                  WHERE last_gate_type IS NOT NULL \
                    AND gate_fixup_attempts > 0 \
                  GROUP BY last_gate_type"
            ))
            .map_err(|e| ApiError::Internal {
                log_only: format!("gate_stats: prepare fixup rollup: {e}"),
            })?;
        let mut rows_iter2 = stmt2
            .query_map([], |r| {
                let gate_type: String = r.get(0)?;
                let attempts: i64 = r.get(1)?;
                Ok((gate_type, attempts))
            })
            .map_err(|e| ApiError::Internal {
                log_only: format!("gate_stats: query fixup rollup: {e}"),
            })?;
        for row in rows_iter2.by_ref() {
            let (gate_type, attempts) = row.map_err(|e| ApiError::Internal {
                log_only: format!("gate_stats: scan fixup row: {e}"),
            })?;
            let entry = acc.entry(gate_type.clone()).or_insert_with(|| GateStatRow {
                gate_type,
                pass_count: 0,
                fail_count: 0,
                inconclusive_count: 0,
                last_seen_at: None,
                fixup_loop_count: 0,
            });
            entry.fixup_loop_count = u64::try_from(attempts).unwrap_or(0);
        }

        Ok(GateStatsResponse {
            gates: acc.into_values().collect(),
            generated_at: now,
        })
    }

    /// `INV-DASHBOARD-RECENT-SESSIONS-RING-01`. Surface the
    /// dashboard-kernel `SessionStreamCapture` ring contents so
    /// summary panels can show ended sessions alongside the main
    /// durable sessions table.
    fn list_recent_sessions(&self, limit: u32) -> Result<Vec<RecentSessionEntry>, ApiError> {
        let conn = self.open_ro()?;
        let cap = limit.min(200) as usize;
        // Walk every session row regardless of `revoked` so the
        // overview panel can surface revoked + expired alongside
        // active. `active_list` filters to `revoked = 0`; we
        // need the wider set here.
        let mut rows = read_sessions_all_for_recent(&conn, cap)?;
        // Sort newest by either `revoked_at` (when set) or
        // `created_at` so the most recently terminated rows
        // appear at the top.
        rows.sort_by(|a, b| {
            let a_at = a.terminated_at.unwrap_or(a.created_at);
            let b_at = b.terminated_at.unwrap_or(b.created_at);
            b_at.cmp(&a_at)
        });
        rows.truncate(cap);
        // Annotate every row with the session's final lifecycle
        // event from the audit chain.
        let audit_chain = collect_lifecycle_audit_rows(&self.audit_dir);
        let audit_index = LifecycleAuditIndex::new(&audit_chain);
        for row in rows.iter_mut() {
            let anns =
                lifecycle::classify_for_session_rows(audit_index.session_rows(&row.session_id));
            row.final_annotation = anns.into_iter().last();
            // Capture-bytes from the file ring on disk.
            let path = self.stream_capture.session_path(&row.session_id);
            row.capture_bytes = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        }
        Ok(rows)
    }

    fn list_sessions(
        &self,
        limit: u32,
        initiative_id: Option<&str>,
    ) -> Result<Vec<SessionView>, ApiError> {
        let conn = self.open_ro()?;
        let cap = limit.min(200) as usize;
        // `initiative_id` is applied through the tasks table below.
        // Pull a wider durable-session window first so an older but
        // still-relevant initiative row does not disappear merely
        // because unrelated sessions are newer.
        let fetch_cap = if initiative_id.is_some() { 2_000 } else { cap };
        // INV-OBSERVABILITY-DATAPLANE-LATENCY-01.
        //
        // List sessions from the durable catalog, not the active-only
        // projection. A session row must not disappear from the main
        // dashboard table just because its VM exited and the kernel
        // revoked the token; the UI renders live vs past as a filter
        // and badge on one surface.
        let rows = raxis_store::observability::time_query_result(
            self.observability_hub.as_ref(),
            raxis_store::observability::QUERY_CLASS_SESSION_LIST,
            || raxis_store::views::sessions::list_all(&conn, fetch_cap),
        )
        .map_err(|e| ApiError::Internal {
            log_only: format!("sessions::list_all: {e}"),
        })?;
        // Resolve the optional `?initiative_id=…` filter by
        // walking the initiative's tasks and collecting any
        // `session_id` they reference. The `sessions` catalog
        // itself does not carry an initiative FK — tasks own
        // the link — so this is the only consistent way to
        // narrow without a schema change.
        let allowed: Option<std::collections::HashSet<String>> = match initiative_id {
            None => None,
            Some(i) => {
                let tasks = raxis_store::views::tasks::list_by_initiative(&conn, i, 2_000)
                    .map_err(|e| ApiError::Internal {
                        log_only: format!("tasks::list_by_initiative: {e}"),
                    })?;
                Some(tasks.into_iter().filter_map(|t| t.session_id).collect())
            }
        };
        // Pre-load the audit chain so the per-session
        // classifier sees the SessionRevoked rows without a
        // re-walk / re-sort per response.
        let audit_chain = collect_lifecycle_audit_rows(&self.audit_dir);
        let audit_index = LifecycleAuditIndex::new(&audit_chain);
        // iter69 — owning-task enrichment for the list view.
        // The list page renders per-row `initiative_id` /
        // `task_id` / token totals; pre-iter69 every row
        // hardcoded `None`/`0`, which made the list visually
        // empty even when the underlying tasks had cumulative
        // token data. We materialise the projection once per
        // session via `owning_task_for_session` (a single
        // indexed-PK lookup per session).
        //
        // `provider` / `model` flow through directly from the
        // `sessions` columns added by migration 25; the read-
        // side fallback (latest LLM turn capture) is deferred to
        // the *detail* path to keep the list cheap on a long
        // session catalog.
        let rows: Vec<_> = rows
            .into_iter()
            .filter(|s| match &allowed {
                Some(set) => set.contains(&s.session_id),
                None => true,
            })
            .take(cap)
            .collect();
        let session_ids: Vec<String> = rows.iter().map(|s| s.session_id.clone()).collect();
        let owning_by_session = owning_tasks_for_sessions(&conn, &session_ids);
        rows.into_iter()
            .map(|s| -> Result<SessionView, ApiError> {
                let state = session_row_state(&s);
                let owning = owning_by_session
                    .get(&s.session_id)
                    .cloned()
                    .unwrap_or_default();
                let role = semantic_agent_type_for_session(
                    &conn,
                    &s.session_id,
                    &s.role_id,
                    Some(&owning),
                );
                let initiative_display_name =
                    initiative_name_for_id_opt(&conn, owning.initiative_id.as_deref())?;
                let view = SessionView {
                    session_id: s.session_id,
                    role,
                    initiative_id: None,
                    initiative_display_name,
                    task_id: None,
                    state,
                    provider: s.provider,
                    model: s.model,
                    input_tokens: 0,
                    output_tokens: 0,
                    created_at: s.created_at,
                    updated_at: s.revoked_at.unwrap_or(s.created_at),
                    // INV-DASHBOARD-FAILURE-VISIBILITY-01: V2.5
                    // ships the wire shape; a Revoked session
                    // here lacks an explicit reason string in
                    // the store-side view, so the kernel emits
                    // `None` and the FE renders "No reason
                    // supplied — kernel bug" so the gap is
                    // visible. V3 widens this to walk the audit
                    // chain for the matching `SessionRevoked` /
                    // `SessionVmFailedFinal` row.
                    failure: None,
                    annotations: Vec::new(),
                    latest_annotation: None,
                    env: Vec::new(),
                };
                // List view stays cheap on both fallback channels:
                // the model fallback reads ONE turn per row and the
                // token fallback reads ALL turns per row, both of
                // which would multiply IO by the list cap. The list
                // surfaces what the kernel has persisted; the detail
                // page (`get_session`) pays for the per-task ring
                // tail and renders the richer view.
                let view = enrich_session_view_with_owning_task(view, owning, None, None, None);
                Ok(enrich_session_view_with_lifecycle_indexed(
                    &audit_index,
                    view,
                ))
            })
            .collect()
    }

    fn get_session(&self, session_id: &str) -> Result<SessionView, ApiError> {
        // `INV-DASHBOARD-SESSION-DETAIL-FORENSIC-01`: the detail
        // surface MUST return a row for any session that exists in
        // the catalog, including ones that have already terminated
        // (revoked or expired). The previous implementation walked
        // `active_list` and silently 404'd terminated sessions —
        // that produced a `FAIL_DASHBOARD_NOT_FOUND` for rows the
        // operator literally just clicked in the list page (any
        // session whose `expires_at` had elapsed between the list
        // fetch and the click).
        //
        // `by_id` ignores the active-window filter and the 200-row
        // cap so the response shape matches the contract: a session
        // that ever existed is forever-renderable in a read-only
        // forensic detail view. The state column carries the
        // terminal classification (`Revoked`, `Expired`, `Active`)
        // so the FE can render the appropriate badge.
        let conn = self.open_ro()?;
        // INV-OBSERVABILITY-DATAPLANE-LATENCY-07.
        let s = raxis_store::observability::time_query_result(
            self.observability_hub.as_ref(),
            raxis_store::observability::QUERY_CLASS_SESSION_GET,
            || raxis_store::views::sessions::by_id(&conn, session_id),
        )
        .map_err(|e| ApiError::Internal {
            log_only: format!("sessions::by_id: {e}"),
        })?
        .ok_or(ApiError::NotFound {
            kind: "session".into(),
        })?;
        let state = session_row_state(&s);
        let audit_chain = collect_lifecycle_audit_rows(&self.audit_dir);
        // iter69 — owning-task projection + LLM-turn fallback for
        // the detail panel. The detail page is the one place where
        // we are willing to pay for the per-task ring tail (one
        // file open + one line parse for the *latest* turn) so the
        // dashboard renders a real model id even on pre-iter69
        // sessions whose `sessions.model` column is still NULL.
        // The list view skips this fallback to stay cheap.
        let owning = owning_task_for_session(&conn, s.session_id.as_str()).unwrap_or_default();
        let fallback_model = owning
            .task_id
            .as_deref()
            .and_then(|tid| latest_model_for_task(self.task_llm_capture.as_ref(), tid));
        let fallback_provider = owning
            .task_id
            .as_deref()
            .and_then(|tid| latest_provider_for_task(self.task_llm_capture.as_ref(), tid));
        // iter74 — orchestrator-session token visibility. Mirror
        // the model-fallback pattern above and lift cumulative
        // `(input, output)` token totals from the per-task LLM
        // turn capture when the kernel-persisted columns
        // (`tasks.cumulative_input_tokens` /
        // `cumulative_output_tokens`) are still zero. The
        // orchestrator's terminal intents
        // (`ActivateSubTask` / `RetrySubTask` /
        // `BatchActivateSubTasks`) early-dispatch in
        // `handle_inner` before the shared `pre_gate` runs, so
        // the pre-gate token UPDATE never fires for orchestrator
        // coordinator tasks; this fallback closes that gap
        // without changing kernel admission semantics. See
        // `cumulative_tokens_for_task` for the full rationale.
        let fallback_tokens = owning
            .task_id
            .as_deref()
            .and_then(|tid| cumulative_tokens_for_task(self.task_llm_capture.as_ref(), tid));
        let role = semantic_agent_type_for_session(
            &conn,
            s.session_id.as_str(),
            &s.role_id,
            Some(&owning),
        );
        let initiative_display_name =
            initiative_name_for_id_opt(&conn, owning.initiative_id.as_deref())?;
        let env = session_vm_env_view_for_session(&conn, s.session_id.as_str())?;
        let view = SessionView {
            session_id: s.session_id,
            role,
            initiative_id: None,
            initiative_display_name,
            task_id: None,
            state,
            provider: s.provider,
            model: s.model,
            input_tokens: 0,
            output_tokens: 0,
            created_at: s.created_at,
            // V2.5 stores only `created_at` + `revoked_at` on the
            // sessions row; surface `revoked_at` (when present) as
            // the updated timestamp so the FE's "updated N min ago"
            // line reflects the most-recent state change.
            updated_at: s.revoked_at.unwrap_or(s.created_at),
            // INV-DASHBOARD-FAILURE-VISIBILITY-01: see
            // `list_sessions` for the V2.5 best-effort
            // rationale. V3 promotes this to a real audit
            // chain walk.
            failure: None,
            annotations: Vec::new(),
            latest_annotation: None,
            env,
        };
        let view = enrich_session_view_with_owning_task(
            view,
            owning,
            fallback_provider,
            fallback_model,
            fallback_tokens,
        );
        Ok(enrich_session_view_with_lifecycle(&audit_chain, view))
    }

    fn list_escalations(&self) -> Result<Vec<EscalationView>, ApiError> {
        let conn = self.open_ro()?;
        // INV-OBSERVABILITY-DATAPLANE-LATENCY-01.
        let rows = raxis_store::observability::time_query_result(
            self.observability_hub.as_ref(),
            raxis_store::observability::QUERY_CLASS_ESCALATION_LIST,
            || {
                raxis_store::views::escalations::list(
                    &conn,
                    raxis_store::views::escalations::EscalationStatusFilter::Pending,
                    200,
                )
            },
        )
        .map_err(|e| ApiError::Internal {
            log_only: format!("escalations::list: {e}"),
        })?;
        Ok(rows
            .into_iter()
            .map(|e| EscalationView {
                escalation_id: e.escalation_id,
                initiative_id: e.initiative_id,
                task_id: Some(e.task_id),
                severity: severity_from_class(&e.class),
                reason: e.justification,
                action_required: e.class,
                created_at: e.created_at,
            })
            .collect())
    }

    fn get_escalation(&self, id: &str) -> Result<EscalationView, ApiError> {
        let conn = self.open_ro()?;
        // INV-OBSERVABILITY-DATAPLANE-LATENCY-07 — the detail
        // page walks `escalations::list(All, 500)` and filters
        // for the matching id; tag the read so a slow
        // escalation table surfaces under the dedicated
        // `escalation_get` series.
        let rows = raxis_store::observability::time_query_result(
            self.observability_hub.as_ref(),
            raxis_store::observability::QUERY_CLASS_ESCALATION_GET,
            || {
                raxis_store::views::escalations::list(
                    &conn,
                    raxis_store::views::escalations::EscalationStatusFilter::All,
                    500,
                )
            },
        )
        .map_err(|e| ApiError::Internal {
            log_only: format!("escalations::list: {e}"),
        })?;
        rows.into_iter()
            .find(|e| e.escalation_id == id)
            .map(|e| EscalationView {
                escalation_id: e.escalation_id,
                initiative_id: e.initiative_id,
                task_id: Some(e.task_id),
                severity: severity_from_class(&e.class),
                reason: e.justification,
                action_required: e.class,
                created_at: e.created_at,
            })
            .ok_or(ApiError::NotFound {
                kind: "escalation".into(),
            })
    }

    fn list_audit(
        &self,
        cursor_seq: Option<u64>,
        limit: u32,
        highlight_initiative_id: Option<&str>,
    ) -> Result<Vec<AuditEntryView>, ApiError> {
        // INV-OBSERVABILITY-DATAPLANE-LATENCY-07 — the audit
        // tail read is bounded but not free; tag it under
        // `audit_chain_walk` so a slow chain lights up its own
        // series rather than being hidden inside the generic
        // `dashboard_http_request` duration histogram.
        let hub_for_walk = self.observability_hub.clone();
        raxis_store::observability::time_query_result(
            hub_for_walk.as_ref(),
            raxis_store::observability::QUERY_CLASS_AUDIT_CHAIN_WALK,
            || -> Result<Vec<AuditEntryView>, ApiError> {
                let reader =
                    ChainReader::open(&self.audit_dir).map_err(|e| ApiError::Internal {
                        log_only: format!("ChainReader::open: {e}"),
                    })?;
                let cap = limit.min(500) as usize;
                if cap == 0 {
                    return Ok(Vec::new());
                }

                // Fast newest-first pagination. The audit chain is
                // still kernel-wide: initiative focus annotates rows
                // only, never filters unrelated events out of the
                // forensic ledger.
                let mut out = Vec::with_capacity(cap);
                for rec in reader.records_desc() {
                    let rec = match rec {
                        Ok(r) => r,
                        Err(_) => continue, // tolerate one malformed line per spec
                    };
                    // Cursor filter: caller already saw everything ≥ cursor.
                    if let Some(c) = cursor_seq {
                        if rec.seq >= c {
                            continue;
                        }
                    }
                    let payload = rec
                        .parsed_value
                        .as_ref()
                        .and_then(|v| v.get("payload").cloned())
                        .unwrap_or(serde_json::Value::Null);
                    let mut entry = AuditEntryView {
                        seq: rec.seq,
                        event_id: rec
                            .parsed_value
                            .as_ref()
                            .and_then(|v| v.get("event_id"))
                            .and_then(|s| s.as_str())
                            .unwrap_or("")
                            .to_owned(),
                        event_kind: rec.event_kind,
                        initiative_id: rec.initiative_id,
                        task_id: rec.task_id,
                        session_id: rec.session_id,
                        at: rec.emitted_at.unwrap_or(0).max(0) as u64,
                        payload,
                        is_highlighted: false,
                        highlight_reasons: Vec::new(),
                    };
                    entry.apply_initiative_highlight(highlight_initiative_id);
                    out.push(entry);
                    if out.len() == cap {
                        break;
                    }
                }
                Ok(out)
            },
        )
    }

    fn audit_chain_status(&self, reverify: bool) -> Result<(bool, ChainStatusView), ApiError> {
        // Cache discipline (INV-AUDIT-DASHBOARD-01): full
        // verifies are expensive (the walker scans every JSONL
        // segment end-to-end), and a chatty UI mounted on a
        // session-detail page should not pin a worker thread on
        // chain re-walks. Honour `reverify` for an explicit
        // "Re-verify chain" button click; otherwise return the
        // cached verdict if it is fresher than
        // `CHAIN_STATUS_TTL_MS` and run a fresh walk otherwise.
        const CHAIN_STATUS_TTL_MS: u64 = 30_000;
        let now_ms = unix_now_ms();
        if !reverify {
            let g = self.chain_status_cache.lock();
            if let Some(cached) = g.as_ref() {
                if now_ms.saturating_sub(cached.verified_at_ms) < CHAIN_STATUS_TTL_MS {
                    return Ok((false, cached.clone()));
                }
            }
        }
        // Drive the kernel-owned walker — never a FE re-
        // implementation. Audit-tools is the single source of
        // truth for chain integrity.
        //
        // INV-OBSERVABILITY-DATAPLANE-LATENCY-07 — tag the
        // verify walk under the same `audit_chain_walk` series
        // the paginated `list_audit` uses; both paths walk the
        // same bytes and pivoting on outcome separates ok-walks
        // (cache miss → fresh walk) from broken-chain walks.
        let verify_outcome = raxis_store::observability::time_query_result(
            self.observability_hub.as_ref(),
            raxis_store::observability::QUERY_CLASS_AUDIT_CHAIN_WALK,
            || raxis_audit_tools::verify_chain_from(&self.audit_dir, 0),
        );
        let view = match verify_outcome {
            Ok(stats) => ChainStatusView {
                status: "ok".into(),
                last_verified_seq: stats.last_seq,
                total_records: stats.total_records,
                segment_count: stats.segment_count as u64,
                verified_at_ms: now_ms,
                last_error: None,
            },
            Err(e) => {
                let (seq, msg) = describe_chain_error(&e);
                ChainStatusView {
                    status: "broken".into(),
                    last_verified_seq: seq,
                    total_records: 0,
                    segment_count: 0,
                    verified_at_ms: now_ms,
                    last_error: Some(msg),
                }
            }
        };
        *self.chain_status_cache.lock() = Some(view.clone());
        Ok((true, view))
    }

    fn list_inbox(&self) -> Result<Vec<AuditEntryView>, ApiError> {
        // Unified inbox: merge kernel-owned notifications (from
        // the `notifications` SQLite table) with pending escalations.
        // Both are surfaced as AuditEntryView so the frontend
        // renders them with one component.
        let mut inbox = Vec::new();

        // 1. Unread notifications from SQLite.
        if let Ok(conn) = self.open_ro() {
            if let Ok(rows) = raxis_store::views::notifications::list_unread(&conn, 100) {
                for r in rows {
                    let payload =
                        serde_json::from_str(&r.payload_json).unwrap_or(serde_json::json!({}));
                    inbox.push(AuditEntryView {
                        seq: 0,
                        event_id: r.notification_id,
                        event_kind: r.event_kind,
                        initiative_id: r.initiative_id,
                        task_id: r.task_id,
                        session_id: r.session_id,
                        at: r.created_at,
                        payload,
                        is_highlighted: false,
                        highlight_reasons: Vec::new(),
                    });
                }
            }
        }

        // 2. Pending escalations.
        if let Ok(escs) = self.list_escalations() {
            for e in escs {
                inbox.push(AuditEntryView {
                    seq: 0,
                    event_id: e.escalation_id.clone(),
                    event_kind: "EscalationPending".to_owned(),
                    initiative_id: Some(e.initiative_id),
                    task_id: e.task_id,
                    session_id: None,
                    at: e.created_at,
                    payload: serde_json::json!({
                        "severity":        e.severity,
                        "reason":          e.reason,
                        "action_required": e.action_required,
                    }),
                    is_highlighted: false,
                    highlight_reasons: Vec::new(),
                });
            }
        }

        // Newest first, deduplicate by event_id.
        inbox.sort_by(|a, b| b.at.cmp(&a.at));
        let mut seen = std::collections::HashSet::new();
        inbox.retain(|e| seen.insert(e.event_id.clone()));
        Ok(inbox)
    }

    fn policy_snapshot(&self) -> Result<PolicySnapshotView, ApiError> {
        // INV-OBSERVABILITY-DATAPLANE-LATENCY-07 — the policy
        // snapshot is the dashboard's policy-tab read path. Even
        // though the bundle lives in an `ArcSwap` (cheap clone),
        // the operator + notification-channel projection grows
        // with the operator count; tag the assembly under
        // `policy_snapshot` so a regression in either pivot
        // (operator count or channel fan-out) lights up here
        // independently of any SQLite read.
        raxis_store::observability::time_query_result(
            self.observability_hub.as_ref(),
            raxis_store::observability::QUERY_CLASS_POLICY_SNAPSHOT,
            || -> Result<PolicySnapshotView, ApiError> {
                let bundle = self.policy.load_full();
                let operators = bundle
                    .operators()
                    .iter()
                    .map(|o| PolicyOperatorView {
                        fingerprint: o.pubkey_fingerprint.clone(),
                        display_name: o.display_name.clone(),
                        permitted_ops: o.permitted_ops.clone(),
                    })
                    .collect();
                let mut routes = std::collections::HashMap::new();
                for ch in bundle.notification_channels() {
                    routes
                        .entry("default".to_owned())
                        .or_insert_with(Vec::new)
                        .push(ch.id.clone());
                }
                Ok(PolicySnapshotView {
                    epoch: bundle.epoch(),
                    policy_sha256: bundle.policy_sha256().to_owned(),
                    signed_by: bundle.signed_by().to_owned(),
                    signed_at: bundle.signed_at(),
                    operators,
                    notification_routes: routes,
                })
            },
        )
    }

    fn policy_toml_bytes(&self) -> Result<String, ApiError> {
        std::fs::read_to_string(&self.policy_path).map_err(|e| ApiError::Internal {
            log_only: format!("policy.toml read: {e}"),
        })
    }

    fn validate_plan_builder_toml(
        &self,
        _operator_fingerprint: &str,
        toml: &str,
    ) -> Result<BuilderValidationResponse, ApiError> {
        Ok(validate_plan_draft_with_policy(
            toml,
            &self.policy.load_full(),
        ))
    }

    fn validate_policy_builder_toml(
        &self,
        operator_fingerprint: &str,
        toml: &str,
    ) -> Result<BuilderValidationResponse, ApiError> {
        Ok(validate_policy_draft_with_loader(
            toml,
            &self.policy.load_full(),
            operator_fingerprint,
        ))
    }

    fn list_worktrees(&self) -> Result<Vec<WorktreeListEntry>, ApiError> {
        let worktrees = self.collect_worktrees()?;
        Ok(worktrees.into_iter().map(|w| w.summary).collect())
    }

    fn get_worktree(&self, name: &str) -> Result<WorktreeDetail, ApiError> {
        let resolved = self.resolve_worktree(name)?;
        let path = std::path::PathBuf::from(&resolved.summary.path);
        if !path.exists() {
            return Err(ApiError::NotFound {
                kind: "worktree-path".into(),
            });
        }
        // `INV-DASHBOARD-WORKTREE-LATENCY-BUDGET-01`
        // (`specs/v2/dashboard-hardening.md §1.9`): run the four
        // read-only probes (`rev-parse HEAD`, `symbolic-ref --short
        // HEAD`, `status --porcelain=v1`, `rev-list --left-right`)
        // in parallel under `std::thread::scope`. They are mutually
        // independent — serially they sum to 60–300 ms on a clean
        // machine; in parallel the wall-clock cost is bounded by the
        // slowest single probe. The route layer wraps this call in
        // `tokio::task::spawn_blocking` so even the parallel
        // blocking wait does not pin a tokio worker.
        let probe_base = if resolved.summary.comparison_head_sha.is_some() {
            None
        } else {
            resolved.summary.base_sha.as_deref()
        };
        let summary = git::probe_worktree_summary(&path, probe_base);
        let git::WorktreeProbeSummary {
            head_sha,
            branch,
            status_lines,
            ahead_behind,
        } = summary;
        let review_head_sha = resolved
            .summary
            .comparison_head_sha
            .clone()
            .or_else(|| head_sha.clone());
        let (ahead, behind) = match (resolved.summary.base_sha.as_ref(), review_head_sha.as_ref()) {
            (Some(base), Some(head)) => {
                let counts = match resolved.summary.comparison_head_sha.as_ref() {
                    Some(_) => git::ahead_behind_between(&path, base, head),
                    None => ahead_behind,
                };
                match counts {
                    Some((behind, ahead)) => (Some(ahead), Some(behind)),
                    None => (None, None),
                }
            }
            _ => (None, None),
        };
        Ok(WorktreeDetail {
            summary: resolved.summary,
            head_sha: review_head_sha,
            branch,
            ahead,
            behind,
            status_lines,
        })
    }

    fn worktree_log(&self, name: &str, limit: u32) -> Result<Vec<WorktreeLogEntry>, ApiError> {
        let resolved = self.resolve_worktree(name)?;
        let path = std::path::PathBuf::from(&resolved.summary.path);
        if !path.exists() {
            return Err(ApiError::NotFound {
                kind: "worktree-path".into(),
            });
        }
        match (
            resolved.summary.base_sha.as_deref(),
            resolved.summary.comparison_head_sha.as_deref(),
        ) {
            (Some(base), Some(head)) => {
                git::log_entries_between(&path, base, head, limit.clamp(1, 200))
                    .map_err(map_git_error_to_api)
            }
            (Some(base), None) => git::log_entries_since_base(&path, base, limit.clamp(1, 200))
                .map_err(map_git_error_to_api),
            (None, _) => git::log_entries(&path, limit.clamp(1, 200)).map_err(map_git_error_to_api),
        }
    }

    fn worktree_diff_default(&self, name: &str) -> Result<WorktreeDiff, ApiError> {
        let resolved = self.resolve_worktree(name)?;
        let path = std::path::PathBuf::from(&resolved.summary.path);
        if !path.exists() {
            return Err(ApiError::NotFound {
                kind: "worktree-path".into(),
            });
        }
        let from = resolved
            .summary
            .base_sha
            .clone()
            .ok_or(ApiError::NotFound {
                kind: "default-diff".into(),
            })?;
        let to = match resolved.summary.comparison_head_sha.clone() {
            Some(head) => head,
            None => git::head_sha(&path).ok_or(ApiError::NotFound {
                kind: "head-sha".into(),
            })?,
        };
        let files = git::diff_files(&path, &from, &to).map_err(map_git_error_to_api)?;
        Ok(WorktreeDiff {
            name: resolved.summary.name,
            from_sha: from,
            to_sha: to,
            files,
        })
    }

    fn worktree_diff_range(
        &self,
        name: &str,
        from_sha: &str,
        to_sha: &str,
    ) -> Result<WorktreeDiff, ApiError> {
        let resolved = self.resolve_worktree(name)?;
        let path = std::path::PathBuf::from(&resolved.summary.path);
        if !path.exists() {
            return Err(ApiError::NotFound {
                kind: "worktree-path".into(),
            });
        }
        let files = git::diff_files(&path, from_sha, to_sha).map_err(map_git_error_to_api)?;
        Ok(WorktreeDiff {
            name: resolved.summary.name,
            from_sha: from_sha.to_owned(),
            to_sha: to_sha.to_owned(),
            files,
        })
    }

    fn worktree_tree(&self, name: &str, sub_path: Option<&str>) -> Result<WorktreeTree, ApiError> {
        let resolved = self.resolve_worktree(name)?;
        let root = std::path::PathBuf::from(&resolved.summary.path);
        if !root.exists() {
            return Err(ApiError::NotFound {
                kind: "worktree-path".into(),
            });
        }
        let target = resolve_within_root(&root, sub_path.unwrap_or(""))?;
        let meta = std::fs::metadata(&target).map_err(|_| ApiError::NotFound {
            kind: "tree-entry".into(),
        })?;
        if !meta.is_dir() {
            return Err(ApiError::BadRequest {
                detail: "path is not a directory".into(),
            });
        }
        let read_dir = std::fs::read_dir(&target).map_err(|e| ApiError::Internal {
            log_only: format!("read_dir: {e}"),
        })?;
        let mut entries: Vec<WorktreeTreeEntry> = Vec::new();
        let mut truncated = false;
        let prefix = sub_path.unwrap_or("").trim_matches('/');
        for ent in read_dir {
            // Cap directory listings so a worktree with a
            // pathologically-large directory (e.g. a
            // node_modules with 50K direntries) cannot pin
            // the request thread for an unbounded time.
            if entries.len() >= MAX_TREE_ENTRIES {
                truncated = true;
                break;
            }
            let Ok(ent) = ent else { continue };
            let file_name = ent.file_name();
            let Some(name_str) = file_name.to_str() else {
                continue; // refuse non-UTF-8 entry names
            };
            // Hide repo internals.
            if name_str == ".git" {
                continue;
            }
            let rel_path = if prefix.is_empty() {
                name_str.to_owned()
            } else {
                format!("{prefix}/{name_str}")
            };
            // ent.metadata() does NOT follow symlinks on
            // Unix, so a symlink in the directory listing
            // surfaces as kind="symlink" with the target
            // never dereferenced.
            let kind_meta = match ent.metadata() {
                Ok(m) => m,
                Err(_) => continue,
            };
            let ft = kind_meta.file_type();
            let (kind, size) = if ft.is_symlink() {
                ("symlink".to_owned(), None)
            } else if ft.is_dir() {
                ("dir".to_owned(), None)
            } else if ft.is_file() {
                ("file".to_owned(), Some(kind_meta.len()))
            } else {
                ("other".to_owned(), None)
            };
            entries.push(WorktreeTreeEntry {
                name: name_str.to_owned(),
                path: rel_path,
                kind,
                size,
            });
        }
        // Directories first, then alpha within each bucket.
        entries.sort_by(|a, b| {
            let dir_a = a.kind == "dir";
            let dir_b = b.kind == "dir";
            dir_b.cmp(&dir_a).then_with(|| {
                a.name
                    .to_ascii_lowercase()
                    .cmp(&b.name.to_ascii_lowercase())
            })
        });
        Ok(WorktreeTree {
            name: resolved.summary.name,
            path: prefix.to_owned(),
            entries,
            truncated,
        })
    }

    fn worktree_file(&self, name: &str, file_path: &str) -> Result<WorktreeFile, ApiError> {
        let resolved = self.resolve_worktree(name)?;
        let root = std::path::PathBuf::from(&resolved.summary.path);
        if !root.exists() {
            return Err(ApiError::NotFound {
                kind: "worktree-path".into(),
            });
        }
        let target = resolve_within_root(&root, file_path)?;
        // Refuse symlinks outright (do not follow). Defends
        // against a tree where the operator inadvertently
        // committed a symlink to /etc/shadow. resolve_within_root
        // already rejected symlinks at every depth; this is
        // a belt-and-braces re-check on the leaf.
        let lmeta = std::fs::symlink_metadata(&target).map_err(|_| ApiError::NotFound {
            kind: "file".into(),
        })?;
        if lmeta.file_type().is_symlink() {
            return Err(ApiError::BadRequest {
                detail: "symlinks are not browsable".into(),
            });
        }
        if !lmeta.is_file() {
            return Err(ApiError::BadRequest {
                detail: "path is not a regular file".into(),
            });
        }
        let size = lmeta.len();
        if size > MAX_FILE_INLINE_BYTES as u64 {
            return Err(ApiError::BadRequest {
                detail: format!(
                    "file size {size} bytes exceeds inline cap of {} bytes",
                    MAX_FILE_INLINE_BYTES
                ),
            });
        }
        let bytes = std::fs::read(&target).map_err(|e| ApiError::Internal {
            log_only: format!("read file: {e}"),
        })?;
        let (encoding, content) = match std::str::from_utf8(&bytes) {
            Ok(_) => (
                "utf8".to_owned(),
                // SAFETY: we just verified `bytes` is valid UTF-8.
                String::from_utf8(bytes).unwrap_or_default(),
            ),
            Err(_) => {
                use base64::Engine as _;
                (
                    "base64".to_owned(),
                    base64::engine::general_purpose::STANDARD.encode(&bytes),
                )
            }
        };
        let trimmed = file_path.trim_matches('/').to_owned();
        Ok(WorktreeFile {
            name: std::path::Path::new(&trimmed)
                .file_name()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_default(),
            path: trimmed,
            size,
            encoding,
            content,
        })
    }

    fn stream_tail(&self, session_id: &str, n: usize) -> Result<Vec<StreamEvent>, ApiError> {
        Ok(self.stream_capture.tail(session_id, n))
    }

    fn stream_subscribe(&self, session_id: &str) -> Result<StreamSubscription, ApiError> {
        // Lazily allocate the session state so a subscriber
        // that connects before the first append still attaches
        // to a real broadcast channel (events that arrive after
        // attach flow through normally).
        self.stream_capture
            .ensure_session(session_id)
            .map_err(|e| ApiError::Internal {
                log_only: format!("stream ensure_session: {e}"),
            })?;
        self.stream_capture
            .subscribe(session_id)
            .ok_or(ApiError::NotFound {
                kind: "stream".into(),
            })
    }

    fn update_policy_toml(
        &self,
        operator_fingerprint: &str,
        toml_bytes: &[u8],
        signature_bytes: &[u8],
    ) -> Result<PolicyAdvancement, ApiError> {
        // The route layer already enforces `write_policy`. Defence
        // in depth: when the kernel main loop did NOT wire a
        // PolicyAdvancer (e.g. the dashboard was started for a
        // read-only workspace), reject the write so we never
        // silently accept and discard the new bytes.
        let advancer = self
            .policy_advancer
            .as_ref()
            .cloned()
            .ok_or(ApiError::Forbidden {
                required: "policy-advance capability".into(),
            })?;
        // Move to a blocking-safe context. The advancer takes a
        // `&Store` lock and runs the full `advance_epoch`
        // pipeline (SQL transaction, audit-after-commit, in-memory
        // swap). spawn_blocking would normally be the right tool,
        // but the trait method is sync so we run inline — the
        // dashboard's HTTP handler already wraps this call in
        // `tokio::task::spawn_blocking` (see
        // crates/dashboard/src/routes/policy.rs).
        let outcome = advancer
            .advance(toml_bytes, signature_bytes, operator_fingerprint)
            .map_err(|e| match e {
                AdvanceError::Validation(msg) => ApiError::PolicyInvalid { detail: msg },
                AdvanceError::Internal(msg) => ApiError::Internal { log_only: msg },
            })?;
        Ok(PolicyAdvancement {
            previous_epoch: outcome.previous_epoch,
            new_epoch: outcome.new_epoch,
            policy_sha256: outcome.policy_sha256,
            signed_by_authority: outcome.signed_by_authority,
            n_sessions_invalidated: outcome.n_sessions_invalidated,
            n_delegations_marked_stale: outcome.n_delegations_marked_stale,
            advanced_at: outcome.advanced_at,
        })
    }

    fn list_notifications(
        &self,
        limit: u32,
        unread_only: bool,
        initiative_id: Option<&str>,
    ) -> Result<Vec<NotificationView>, ApiError> {
        let conn = self.open_ro()?;
        let cap = limit.min(200) as usize;
        // INV-OBSERVABILITY-DATAPLANE-LATENCY-07.
        let rows = raxis_store::observability::time_query_result(
            self.observability_hub.as_ref(),
            raxis_store::observability::QUERY_CLASS_NOTIFICATIONS_INBOX,
            || {
                if unread_only {
                    raxis_store::views::notifications::list_unread(&conn, cap)
                } else {
                    raxis_store::views::notifications::list_all(&conn, cap, initiative_id)
                }
            },
        )
        .map_err(|e| ApiError::Internal {
            log_only: format!("notification list: {e}"),
        })?;

        Ok(rows
            .into_iter()
            .map(|r| {
                let payload =
                    serde_json::from_str(&r.payload_json).unwrap_or(serde_json::json!({}));
                // INV-NOTIF-SCOPE-01 — project the canonical
                // `notification_priority` taxonomy onto every row
                // so the dashboard FE can group + filter without
                // mirroring the audit→notification map in TS.
                // Pre-filter rows (legacy data from before the
                // Phase 1 worker shipped) come back as `None`;
                // the FE renders those as "unclassified" rather
                // than dropping them, since they were already
                // emitted under the old policy.
                // INV-NOTIF-SCOPE-01 — qualified path so the
                // pub-use re-export stays the canonical entry
                // point for downstream callers.
                let priority =
                    notification_filter::notification_priority_for_kind_str(&r.event_kind)
                        .map(|p| p.as_str().to_string());
                NotificationView {
                    notification_id: r.notification_id,
                    event_kind: r.event_kind,
                    initiative_id: r.initiative_id,
                    task_id: r.task_id,
                    session_id: r.session_id,
                    summary: r.summary,
                    payload,
                    read: r.read,
                    source_event_id: r.source_event_id,
                    created_at: r.created_at,
                    priority,
                }
            })
            .collect())
    }

    fn notification_count_unread(&self) -> Result<u64, ApiError> {
        let conn = self.open_ro()?;
        // INV-OBSERVABILITY-DATAPLANE-LATENCY-07.
        raxis_store::observability::time_query_result(
            self.observability_hub.as_ref(),
            raxis_store::observability::QUERY_CLASS_NOTIFICATIONS_INBOX,
            || raxis_store::views::notifications::unread_count(&conn),
        )
        .map_err(|e| ApiError::Internal {
            log_only: format!("notification unread count: {e}"),
        })
    }

    fn mark_notification_read(&self, notification_id: &str) -> Result<bool, ApiError> {
        let guard = self.store.lock_sync();
        guard
            .execute_batch("BEGIN IMMEDIATE")
            .map_err(|e| ApiError::Internal {
                log_only: format!("mark_notification_read BEGIN: {e}"),
            })?;
        let result = raxis_store::views::notifications::mark_read(&guard, notification_id);
        match result {
            Ok(updated) => {
                guard
                    .execute_batch("COMMIT")
                    .map_err(|e| ApiError::Internal {
                        log_only: format!("mark_notification_read COMMIT: {e}"),
                    })?;
                Ok(updated)
            }
            Err(e) => {
                let _ = guard.execute_batch("ROLLBACK");
                Err(ApiError::Internal {
                    log_only: format!("mark_notification_read: {e}"),
                })
            }
        }
    }

    fn mark_all_notifications_read(&self) -> Result<u64, ApiError> {
        let guard = self.store.lock_sync();
        guard
            .execute_batch("BEGIN IMMEDIATE")
            .map_err(|e| ApiError::Internal {
                log_only: format!("mark_all_notifications_read BEGIN: {e}"),
            })?;
        let result = raxis_store::views::notifications::mark_all_read(&guard);
        match result {
            Ok(count) => {
                guard
                    .execute_batch("COMMIT")
                    .map_err(|e| ApiError::Internal {
                        log_only: format!("mark_all_notifications_read COMMIT: {e}"),
                    })?;
                Ok(count)
            }
            Err(e) => {
                let _ = guard.execute_batch("ROLLBACK");
                Err(ApiError::Internal {
                    log_only: format!("mark_all_notifications_read: {e}"),
                })
            }
        }
    }

    fn list_initiative_credentials(
        &self,
        initiative_id: &str,
    ) -> Result<Vec<CredentialMetadata>, ApiError> {
        let conn = self.open_ro()?;
        // Step 1: confirm the initiative exists. We use the
        // initiatives view rather than relying on a 404 from the
        // credential-table walk so the wire shape mirrors every
        // other per-initiative endpoint.
        let _row = raxis_store::views::initiatives::by_id(&conn, initiative_id)
            .map_err(|e| ApiError::Internal {
                log_only: format!("initiatives::by_id: {e}"),
            })?
            .ok_or(ApiError::NotFound {
                kind: "initiative".into(),
            })?;
        // Step 2: enumerate task ids for the initiative.
        let task_rows = raxis_store::views::tasks::list_by_initiative(&conn, initiative_id, 500)
            .map_err(|e| ApiError::Internal {
                log_only: format!("tasks::list_by_initiative: {e}"),
            })?;
        // Step 3: union credential decls across every task,
        // dedup by name (the same credential may be bound by
        // multiple tasks; the dashboard listing surface shows
        // each unique credential once).
        let mut seen: std::collections::BTreeMap<
            String,
            raxis_plan_credentials::TaskCredentialDecl,
        > = std::collections::BTreeMap::new();
        for t in &task_rows {
            let decls = read_task_credential_proxies_via_dashboard_glue(&conn, &t.task_id)?;
            for d in decls {
                seen.entry(d.name.as_str().to_owned()).or_insert(d);
            }
        }
        // Step 4: project to wire shape.
        let mut out: Vec<CredentialMetadata> = seen
            .into_values()
            .map(|d| project_credential_metadata(d, &self.data_dir))
            .collect();
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }

    fn reveal_initiative_credential(
        &self,
        initiative_id: &str,
        credential_name: &str,
    ) -> Result<CredentialReveal, ApiError> {
        let conn = self.open_ro()?;
        // Same existence check: a 404 response surfaces "I don't
        // know this initiative" before we touch the credential
        // backend.
        let _row = raxis_store::views::initiatives::by_id(&conn, initiative_id)
            .map_err(|e| ApiError::Internal {
                log_only: format!("initiatives::by_id: {e}"),
            })?
            .ok_or(ApiError::NotFound {
                kind: "initiative".into(),
            })?;
        let task_rows = raxis_store::views::tasks::list_by_initiative(&conn, initiative_id, 500)
            .map_err(|e| ApiError::Internal {
                log_only: format!("tasks::list_by_initiative: {e}"),
            })?;
        // Walk every task once; first match wins. We do not need
        // to dedup here because a found-decl is enough.
        let mut found: Option<raxis_plan_credentials::TaskCredentialDecl> = None;
        for t in &task_rows {
            let decls = read_task_credential_proxies_via_dashboard_glue(&conn, &t.task_id)?;
            if let Some(d) = decls
                .into_iter()
                .find(|d| d.name.as_str() == credential_name)
            {
                found = Some(d);
                break;
            }
        }
        let decl = found.ok_or(ApiError::NotFound {
            kind: "credential".into(),
        })?;
        // Drop the conn before the (potentially blocking) read.
        drop(conn);
        let reveal = read_credential_bytes(
            &self.data_dir,
            decl.name.as_str(),
            REVEAL_AUTOHIDE_INITIATIVE_SECS,
        )?;
        Ok(reveal)
    }

    fn list_system_credentials(&self) -> Result<Vec<CredentialMetadata>, ApiError> {
        list_system_credential_metadata(&self.data_dir)
    }

    fn reveal_system_credential(
        &self,
        credential_name: &str,
    ) -> Result<CredentialReveal, ApiError> {
        // Defence-in-depth: the route layer requires admin role +
        // rate-limits; this layer additionally rejects any name
        // that doesn't carry the `providers.` scope prefix. The
        // current system-credential set is provider-only; future
        // system credentials will bring their own prefix.
        if !credential_name.starts_with("providers.") {
            return Err(ApiError::NotFound {
                kind: "system-credential".into(),
            });
        }
        read_credential_bytes(&self.data_dir, credential_name, REVEAL_AUTOHIDE_SYSTEM_SECS)
    }

    fn enforce_reveal_rate_limit(&self, operator_fingerprint: &str) -> Result<(), ApiError> {
        let mut g = self.reveal_rate_limit.lock();
        let now = std::time::Instant::now();
        let window = REVEAL_RATE_LIMIT_WINDOW;
        let entry = g
            .by_operator
            .entry(operator_fingerprint.to_owned())
            .or_default();
        // GC entries that have aged out of the window.
        entry.retain(|ts| now.duration_since(*ts) < window);
        if (entry.len() as u32) >= REVEAL_RATE_LIMIT_MAX {
            let oldest = entry.first().copied().unwrap_or(now);
            let elapsed = now.duration_since(oldest);
            let retry_after = window.saturating_sub(elapsed);
            return Err(ApiError::TooManyRequests {
                max: REVEAL_RATE_LIMIT_MAX,
                window_secs: window.as_secs() as u32,
                retry_after_secs: retry_after.as_secs().max(1) as u32,
            });
        }
        entry.push(now);
        Ok(())
    }

    fn emit_operator_audit(
        &self,
        event: raxis_audit_tools::AuditEventKind,
    ) -> Result<(), ApiError> {
        // INV-AUDIT-OPERATOR-ACTION-01: route every operator-
        // initiated dashboard action through the kernel audit sink
        // before the handler returns. The sink is the SAME
        // `Arc<dyn AuditSink>` the rest of the kernel uses, so
        // chain order / sequence are preserved.
        //
        // No-sink path: an audit emit attempt with no wired sink
        // is a hard error rather than a silent drop, because
        // dropping operator-audit events would silently violate
        // the invariant. Production always wires a sink; the
        // narrow path here only fires in test fixtures that
        // construct `KernelDashboardData` directly without
        // calling `with_audit_sink`.
        let sink = self.audit_sink.as_ref().ok_or(ApiError::Internal {
            log_only: "operator audit emit: no audit sink wired".into(),
        })?;
        // Surface the `session_id`/`task_id`/`initiative_id`
        // correlation fields on a best-effort basis from the
        // event payload — `Operator*` events do not strictly
        // require them, but when present they let the chain
        // walker associate the audit row with an existing
        // session/task surface in the dashboard.
        let (session_id, task_id, initiative_id) = correlation_fields_for_operator_event(&event);
        sink.emit(
            event,
            session_id.as_deref(),
            task_id.as_deref(),
            initiative_id.as_deref(),
        )
        .map(|_| ())
        .map_err(|e| ApiError::Internal {
            log_only: format!("operator audit emit: {e}"),
        })
    }
}

fn is_sha256_hex(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[cfg(test)]
mod snapshot_blob_path_tests {
    use super::is_sha256_hex;

    #[test]
    fn sha256_blob_names_must_be_lower_hex_only() {
        assert!(is_sha256_hex(&"a".repeat(64)));
        assert!(!is_sha256_hex(&"A".repeat(64)));
        assert!(!is_sha256_hex(&"g".repeat(64)));
        assert!(!is_sha256_hex("../escape"));
        assert!(!is_sha256_hex(&"a".repeat(63)));
    }
}

#[cfg(all(test, unix))]
mod credential_metadata_security_tests {
    use super::stat_credential_bytes;
    use raxis_credentials::CredentialName;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn credential_metadata_hash_requires_backend_file_security_checks() {
        let dir = tempfile::tempdir().unwrap();
        let name = CredentialName::new("providers.anthropic-test");
        let path = raxis_credentials_file::credential_file_path(dir.path(), &name);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, b"api_key = \"test\"\n").unwrap();

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(
            stat_credential_bytes(dir.path(), &name),
            (0, None),
            "metadata listing must not hash or size loose-mode credential files",
        );

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let (size, prefix) = stat_credential_bytes(dir.path(), &name);
        assert_eq!(size, b"api_key = \"test\"\n".len() as u64);
        assert!(
            prefix.is_some(),
            "0600 credential should expose metadata hash"
        );
    }
}

/// Pulls best-effort `(session_id, task_id, initiative_id)`
/// correlation fields out of a freshly-built `Operator*` audit
/// event so the chain row carries the existing dashboard
/// surface links when the event payload happens to know them.
///
/// The `Operator*` event family lives entirely on the dashboard
/// surface and does not require correlation fields, so missing
/// links are not an error — they just mean the resulting audit
/// row has those columns NULL.
///
/// Deprecated `OperatorViewed*` (round 1) and
/// `OperatorWorktreeAccessed` / `OperatorDiffViewed` /
/// `OperatorFileContentFetched` / `OperatorAuditChainReverified` /
/// `OperatorHealthQueried` / `OperatorListedCredentials` /
/// `OperatorListedSystemCredentials` /
/// `OperatorOpenedSessionStream` / `OperatorNotificationViewed`
/// (round 2) variants are still matched here for backwards-compat:
/// emit sites for those variants have been retired, but already-
/// persisted chains may still carry them and a replay harness that
/// constructs one should still hit the correct correlation columns.
#[allow(deprecated)]
fn correlation_fields_for_operator_event(
    event: &raxis_audit_tools::AuditEventKind,
) -> (Option<String>, Option<String>, Option<String>) {
    use raxis_audit_tools::AuditEventKind as K;
    match event {
        K::OperatorWorktreeAccessed { worktree_id, .. } => {
            // Worktree slugs frequently encode `initiative-N` or
            // similar; we surface the raw slug only on the
            // `worktree_id` payload — not as the audit row's
            // `initiative_id` correlation column, since the
            // mapping is not 1:1.
            let _ = worktree_id;
            (None, None, None)
        }
        // Per-initiative credential viewer events carry the
        // initiative id directly; promote it to the audit row's
        // `initiative_id` correlation column so the chain walker
        // can group by initiative for forensic review
        // (`INV-DASHBOARD-CREDENTIAL-REVEAL-AUDITED-01`).
        K::OperatorListedCredentials { initiative_id, .. }
        | K::OperatorRevealedCredential { initiative_id, .. } => {
            (None, None, Some(initiative_id.clone()))
        }
        // Likewise for any operator-action gap-closer event that
        // carries an initiative / task / session id. We promote
        // a single best-fit field; multi-id events stay on the
        // payload only.
        K::OperatorViewedInitiative { initiative_id, .. }
        | K::OperatorViewedInitiativeDag { initiative_id, .. }
        | K::OperatorViewedInitiativeTasks { initiative_id, .. }
        | K::OperatorViewedPlanToml { initiative_id, .. } => {
            (None, None, Some(initiative_id.clone()))
        }
        K::OperatorViewedTask { task_id, .. } | K::OperatorViewedTaskOutputs { task_id, .. } => {
            (None, Some(task_id.clone()), None)
        }
        K::OperatorViewedSession { session_id, .. }
        | K::OperatorOpenedSessionStream { session_id, .. } => {
            (Some(session_id.clone()), None, None)
        }
        K::OperatorViewedAuditChain {
            initiative_id_filter,
            ..
        }
        | K::OperatorViewedSessionList {
            initiative_id_filter,
            ..
        } => (None, None, initiative_id_filter.clone()),
        K::OperatorDiffViewed { .. }
        | K::OperatorFileContentFetched { .. }
        | K::OperatorNotificationMarkedRead { .. }
        | K::OperatorNotificationsMarkedAllRead { .. }
        | K::OperatorAuditChainReverified { .. }
        | K::OperatorNotificationViewed { .. }
        | K::OperatorHealthQueried { .. }
        | K::OperatorListedSystemCredentials { .. }
        | K::OperatorRevealedSystemCredential { .. }
        | K::OperatorViewedInitiativeList { .. }
        | K::OperatorViewedEscalation { .. }
        | K::OperatorViewedEscalationList { .. }
        | K::OperatorViewedInbox { .. }
        | K::OperatorViewedNotifications { .. }
        | K::OperatorViewedPolicySnapshot { .. }
        | K::OperatorViewedPolicyToml { .. }
        | K::OperatorViewedWorktreeList { .. }
        | K::OperatorViewedWorktreeLog { .. } => (None, None, None),
        _ => (None, None, None),
    }
}

// ---------------------------------------------------------------------------
// Credential viewer helpers (INV-DASHBOARD-CREDENTIAL-*)
// ---------------------------------------------------------------------------

/// SQL table name for the per-task credential proxy registry.
/// Mirrors `raxis_kernel::initiatives::lifecycle::TASK_CREDENTIAL_PROXIES`
/// — duplicated here because the dashboard-kernel crate cannot
/// depend on `raxis-kernel` without a circular dep. The schema is
/// pinned by `raxis-store` migration 10.
const TASK_CREDENTIAL_PROXIES_TABLE: &str = "task_credential_proxies";

/// Re-implementation of
/// `raxis_kernel::initiatives::lifecycle::read_task_credential_proxies_in_tx`
/// scoped to the dashboard-kernel crate. The kernel's version
/// runs inside the approve-plan transaction; ours runs against
/// the dashboard's read-only `RoConn::raw()`.
///
/// Why we duplicate rather than depending on `raxis-kernel`:
/// the dashboard-kernel → raxis-kernel direction would close a
/// dependency cycle (the kernel depends on dashboard-kernel for
/// the dashboard surface). Pinning the schema in
/// `migration_sql_dumps` and this helper gives us the same wire
/// shape with a tiny code duplication budget. Drift is caught by
/// `tests::credential_proxies_table_round_trips_through_dashboard_view`
/// in the kernel-side e2e suite.
fn read_task_credential_proxies_via_dashboard_glue(
    conn: &raxis_store::ro::RoConn,
    task_id: &str,
) -> Result<Vec<raxis_plan_credentials::TaskCredentialDecl>, ApiError> {
    use raxis_credentials::CredentialName;
    // `&RoConn` Derefs to `&rusqlite::Connection`; we call
    // `prepare` through that. The crate carries a direct
    // `rusqlite` dep solely to spell the closure's `Row::get::<T>(idx)`
    // type witnesses below.
    let mut stmt = conn
        .prepare(&format!(
            "SELECT credential_name, mount_as, proxy_json
               FROM {table}
              WHERE task_id = ?1
           ORDER BY created_at_unix_secs ASC, credential_name ASC",
            table = TASK_CREDENTIAL_PROXIES_TABLE,
        ))
        .map_err(|e| ApiError::Internal {
            log_only: format!("prepare task_credential_proxies: {e}"),
        })?;

    let rows: Vec<(String, String, String)> = stmt
        .query_map([task_id], |row| {
            let credential_name = row.get::<_, String>(0)?;
            let mount_as = row.get::<_, String>(1)?;
            let proxy_json = row.get::<_, String>(2)?;
            Ok((credential_name, mount_as, proxy_json))
        })
        .map_err(|e| ApiError::Internal {
            log_only: format!("query task_credential_proxies: {e}"),
        })?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| ApiError::Internal {
            log_only: format!("rusqlite row decode: {e}"),
        })?;

    let mut out = Vec::with_capacity(rows.len());
    for (credential_name, mount_as, proxy_json) in rows {
        let proxy: raxis_plan_credentials::ProxyDecl =
            serde_json::from_str(&proxy_json).map_err(|e| ApiError::Internal {
                log_only: format!(
                    "task `{task_id}` credential `{credential_name}`: \
                     ProxyDecl re-deserialise failed (schema drift?): {e}",
                ),
            })?;
        out.push(raxis_plan_credentials::TaskCredentialDecl {
            name: CredentialName::new(credential_name),
            mount_as,
            proxy,
        });
    }
    Ok(out)
}

/// Project a parsed [`raxis_plan_credentials::TaskCredentialDecl`]
/// onto the wire-shape [`CredentialMetadata`]. The on-disk file
/// is `stat`d so the response carries `byte_size + sha256_prefix`
/// for the FE; missing files surface as `byte_size = 0` and
/// `sha256_prefix = None` (the FE renders this in red).
fn project_credential_metadata(
    decl: raxis_plan_credentials::TaskCredentialDecl,
    data_dir: &std::path::Path,
) -> CredentialMetadata {
    use raxis_plan_credentials::ProxyDecl;
    let name = decl.name.as_str().to_owned();
    let proxy_type = match &decl.proxy {
        ProxyDecl::Postgres { .. } => "postgres",
        ProxyDecl::Http { .. } => "http",
        ProxyDecl::K8s { .. } => "k8s",
        ProxyDecl::Smtp { .. } => "smtp",
        ProxyDecl::Redis { .. } => "redis",
        ProxyDecl::Aws { .. } => "aws",
        ProxyDecl::Gcp { .. } => "gcp",
        ProxyDecl::Azure { .. } => "azure",
        ProxyDecl::Mysql { .. } => "mysql",
        ProxyDecl::Mssql { .. } => "mssql",
        ProxyDecl::Mongodb { .. } => "mongodb",
        ProxyDecl::Unknown => "unknown",
    };
    let format_hint = match &decl.proxy {
        ProxyDecl::Postgres { .. } => "libpq URL (postgresql://user:pass@host:port/db)".to_owned(),
        ProxyDecl::Mysql { .. } => "MySQL URL (mysql://user:pass@host:port/db)".to_owned(),
        ProxyDecl::Mssql { .. } => "MSSQL URL (mssql://user:pass@host:port/db)".to_owned(),
        ProxyDecl::Mongodb { .. } => "MongoDB URI (mongodb://user:pass@host:port/db)".to_owned(),
        ProxyDecl::Redis { .. } => "Redis password (single-line plaintext)".to_owned(),
        ProxyDecl::Smtp { .. } => "SMTP relay password (raw bytes)".to_owned(),
        ProxyDecl::Http { .. } => "HTTP credential (Bearer token / Basic password)".to_owned(),
        ProxyDecl::K8s { .. } => "Kubeconfig YAML".to_owned(),
        ProxyDecl::Aws { .. } => {
            "AWS access-key TOML (access_key_id + secret_access_key)".to_owned()
        }
        ProxyDecl::Gcp { .. } => "GCP service-account JSON".to_owned(),
        ProxyDecl::Azure { .. } => {
            "Azure service-principal TOML (client_id + client_secret)".to_owned()
        }
        ProxyDecl::Unknown => "(unknown proxy type — see plan TOML)".to_owned(),
    };
    let upstream_host_port = upstream_host_port_for_decl(&decl.proxy);
    let path = raxis_credentials_file::credential_file_path(data_dir, &decl.name);
    let (byte_size, sha256_prefix) = stat_credential_bytes(data_dir, &decl.name);
    CredentialMetadata {
        name,
        proxy_type: proxy_type.to_owned(),
        mount_as: Some(decl.mount_as),
        format_hint,
        upstream_host_port,
        byte_size,
        sha256_prefix,
        loaded_from_path: Some(path.to_string_lossy().into_owned()),
        is_revealable: true,
        reveal_required_role: "admin".into(),
    }
}

/// Extract the upstream `host:port` (when applicable) from a
/// proxy variant. Variants with no upstream concept (k8s, aws,
/// gcp, azure, mysql, mssql, mongodb) return `None` — the FE
/// hides the row in those cases.
fn upstream_host_port_for_decl(proxy: &raxis_plan_credentials::ProxyDecl) -> Option<String> {
    use raxis_plan_credentials::ProxyDecl;
    match proxy {
        ProxyDecl::Smtp {
            upstream_host_port, ..
        }
        | ProxyDecl::Redis {
            upstream_host_port, ..
        } => Some(upstream_host_port.clone()),
        ProxyDecl::Http { upstream_url, .. } => {
            // `upstream_url` is a full URL; we surface `host:port`
            // when the URL parses cleanly. Otherwise we surface
            // the raw URL so the FE can still render it.
            Some(upstream_url.clone())
        }
        _ => None,
    }
}

/// Resolve the credential through the same file backend used for
/// actual reveals, then compute a byte-size + SHA-256 prefix.
/// Returns `(0, None)` for missing, malformed, loose-mode,
/// foreign-owned, or otherwise unreadable files so the FE can
/// render a clear "missing/invalid on disk" affordance without
/// leaking metadata for a file that would fail closed on reveal.
///
/// Reads the full bytes once — credential files are bounded at
/// < 1 MiB each by the kernel admission pipeline.
fn stat_credential_bytes(
    data_dir: &std::path::Path,
    name: &raxis_credentials::CredentialName,
) -> (u64, Option<String>) {
    use raxis_credentials::{ConsumerIdentity, CredentialBackend};

    let backend = raxis_credentials_file::FileCredentialBackend::open(data_dir);
    let value = match backend.resolve(name, ConsumerIdentity::new("dashboard", "metadata-stat")) {
        Ok(v) => v,
        Err(_) => return (0, None),
    };
    value.with_bytes(|bytes| {
        use sha2::Digest;
        let mut h = sha2::Sha256::new();
        h.update(bytes);
        let digest = h.finalize();
        let mut hex_prefix = String::with_capacity(8);
        for b in &digest[..4] {
            use std::fmt::Write;
            let _ = write!(&mut hex_prefix, "{b:02x}");
        }
        (bytes.len() as u64, Some(hex_prefix))
    })
}

/// Read the credential bytes and project them onto the wire
/// shape [`CredentialReveal`]. `auto_hide_secs` is added to the
/// current unix-seconds clock to compute `expires_at_unix`. The
/// caller (route layer) is responsible for the role gate, the
/// rate limit, and emitting the audit row BEFORE this is
/// invoked — `INV-DASHBOARD-CREDENTIAL-REVEAL-AUDITED-01`.
fn read_credential_bytes(
    data_dir: &std::path::Path,
    credential_name: &str,
    auto_hide_secs: u64,
) -> Result<CredentialReveal, ApiError> {
    use raxis_credentials::{ConsumerIdentity, CredentialBackend, CredentialError, CredentialName};
    let cn = CredentialName::new(credential_name.to_owned());
    // Run the same backend the kernel uses to resolve credentials
    // for proxy injection. This routes through the shared
    // path-shape + chmod-0600 + uid validator, so a tampered
    // file fails the reveal closed without us re-implementing
    // the security check on the dashboard side.
    let backend = raxis_credentials_file::FileCredentialBackend::open(data_dir);
    let consumer = ConsumerIdentity::new("dashboard", "operator-reveal");
    let value = match backend.resolve(&cn, consumer) {
        Ok(v) => v,
        Err(CredentialError::NotFound(_)) => {
            return Err(ApiError::NotFound {
                kind: "credential".into(),
            });
        }
        Err(e) => {
            return Err(ApiError::Internal {
                log_only: format!("resolve credential {credential_name}: {e}"),
            });
        }
    };
    // Project the bytes onto the wire shape inside the
    // `with_bytes` closure so the secret never escapes the
    // SecretBox unnecessarily. UTF-8 credentials surface as
    // `encoding=utf8`; binary blobs surface as base64 (the FE
    // labels them so the operator knows to decode).
    let (encoding, plaintext, byte_size, sha_prefix) = value.with_bytes(|bytes| {
        let (encoding, plaintext) = match std::str::from_utf8(bytes) {
            Ok(s) => ("utf8".to_owned(), s.to_owned()),
            Err(_) => {
                use base64::Engine as _;
                let s = base64::engine::general_purpose::STANDARD.encode(bytes);
                ("base64".to_owned(), s)
            }
        };
        use sha2::Digest;
        let mut h = sha2::Sha256::new();
        h.update(bytes);
        let digest = h.finalize();
        let mut sha_prefix = String::with_capacity(8);
        for b in &digest[..4] {
            use std::fmt::Write;
            let _ = write!(&mut sha_prefix, "{b:02x}");
        }
        (encoding, plaintext, bytes.len() as u64, sha_prefix)
    });
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    Ok(CredentialReveal {
        name: credential_name.to_owned(),
        plaintext,
        encoding,
        byte_size,
        expires_at_unix: now.saturating_add(auto_hide_secs),
        sha256_prefix: sha_prefix,
    })
}

/// Enumerate `<data_dir>/providers/*.toml` and surface metadata
/// only. Provider credentials are gateway-bound; the listing
/// surface here is the operator-visible counterpart so an admin
/// can see WHICH providers the kernel is configured against
/// without revealing any plaintext.
fn list_system_credential_metadata(
    data_dir: &std::path::Path,
) -> Result<Vec<CredentialMetadata>, ApiError> {
    let providers_dir = data_dir.join("providers");
    let entries = match std::fs::read_dir(&providers_dir) {
        Ok(e) => e,
        // No providers/ dir ⇒ kernel has no system credentials.
        // Empty list, NOT an error (the dashboard surface should
        // still render so the operator can see the absence).
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(Vec::new());
        }
        Err(e) => {
            return Err(ApiError::Internal {
                log_only: format!("read_dir providers: {e}"),
            });
        }
    };
    let mut out: Vec<CredentialMetadata> = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("toml") {
            continue;
        }
        let stem = match path.file_stem().and_then(|s| s.to_str()) {
            Some(s) => s,
            None => continue,
        };
        let name = format!("providers.{stem}");
        let credential_name = raxis_credentials::CredentialName::new(name.clone());
        let (byte_size, sha256_prefix) = stat_credential_bytes(data_dir, &credential_name);
        // The Anthropic credential is the canonical example; we
        // hint at the wire format so operators can sanity-check
        // before they reveal.
        let format_hint = if stem.contains("anthropic") {
            "Anthropic provider TOML (api_key = \"sk-ant-…\")".to_owned()
        } else if stem.contains("openai") {
            "OpenAI provider TOML (api_key = \"sk-…\")".to_owned()
        } else {
            "Provider TOML (api_key + auth_header + auth_prefix)".to_owned()
        };
        out.push(CredentialMetadata {
            name,
            proxy_type: "provider".to_owned(),
            mount_as: None,
            format_hint,
            upstream_host_port: None,
            byte_size,
            sha256_prefix,
            loaded_from_path: Some(path.to_string_lossy().into_owned()),
            is_revealable: true,
            reveal_required_role: "admin".into(),
        });
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(out)
}

// ---------------------------------------------------------------------------
// Git-error → ApiError classification
// ---------------------------------------------------------------------------

/// Map a [`git::GitError`] to the most appropriate [`ApiError`].
///
/// Discrimination matters because the operator dashboard renders 5xx
/// responses as a red "Internal Server Error" banner — every misclassified
/// 4xx-class condition becomes an apparent kernel bug to the operator.
/// The cases:
///
/// * [`git::GitError::NotARepo`] — the worktree slug points at a directory
///   that exists on disk but is not (or no longer) a git repository.
///   Common in V2 because the operator-allowed worktree root may name a
///   parent directory of session worktrees rather than the main repo
///   itself. Surfaced as `404 FAIL_DASHBOARD_NOT_FOUND` with
///   `kind: "worktree-history"` so the frontend can render an empty-state
///   page (no commits, no diffs) instead of an error.
/// * [`git::GitError::MissingPath`] — the path itself is gone. 404 with
///   `kind: "worktree-path"`.
/// * [`git::GitError::Timeout`] — the git subprocess exceeded its hard
///   wall-clock cap. Surface as a structured 500 with a `tracing::warn!`
///   (not error) since this is an expected occasional failure mode under
///   pathological inputs (corrupted pack file, fs stall) rather than a
///   kernel bug.
/// * [`git::GitError::Spawn`] / [`git::GitError::NonZero`] — kernel-side
///   trouble. 500.
// ---------------------------------------------------------------
// Health-tab subsystem aggregator.
//
// Aggregate per-card statuses into the single banner tone the FE
// Health tab renders above the grid. Worst-case wins: any
// `failing` ⇒ `failing`; otherwise any `degraded` ⇒ `degraded`;
// otherwise any `unknown` ⇒ `unknown`; otherwise `ok`. Matches
// the `INV-DASHBOARD-VALIDATE-01` contract that the dashboard
// surfaces the kernel's worst-known signal without re-classifying.
fn aggregate_subsystem_status(cards: &[SubsystemHealthCard]) -> String {
    let mut has_failing = false;
    let mut has_degraded = false;
    let mut has_unknown = false;
    for c in cards {
        match c.status.as_str() {
            "failing" => has_failing = true,
            "degraded" => has_degraded = true,
            "unknown" => has_unknown = true,
            _ => {}
        }
    }
    if has_failing {
        "failing".into()
    } else if has_degraded {
        "degraded".into()
    } else if has_unknown {
        "unknown".into()
    } else {
        "ok".into()
    }
}

/// iter69 — observability-pusher health classification.
///
/// Returns the (status, summary, details, last_observed_at)
/// tuple the dashboard's Health card renders for the
/// `observability_pusher` subsystem. The three branches:
///
///   1. **Policy disabled** → `"ok"`, no mtime tracking.
///      Operators turn the stack off deliberately; the dashboard
///      MUST NOT yellow-card a disabled subsystem.
///   2. **Enabled + ring directory recent** → `"ok"` with the
///      latest segment mtime in `last_observed_at`. The kernel
///      writes to `<data_dir>/observability/{spans,metrics}/`
///      on every emit; a recent mtime there is the
///      cheapest proof the in-process hub + ring file exporter
///      pair is alive.
///   3. **Enabled + ring missing or stale** → `"degraded"` /
///      `"failing"` with a human-readable reason in `summary`.
///
/// The pusher binary's own `/healthz` probe is intentionally
/// NOT contacted here — the dashboard is a read-only surface
/// over `data_dir`. The ring mtime is the closest local proxy.
struct PusherHealthCard {
    status: &'static str,
    summary: String,
    details: Vec<SubsystemDetailRow>,
    last_observed_at: u64,
}

fn classify_observability_pusher(
    data_dir: &std::path::Path,
    obs: &raxis_policy::ObservabilityConfig,
    now_s: u64,
) -> PusherHealthCard {
    if !obs.enabled {
        return PusherHealthCard {
            status: "ok",
            summary: "Observability disabled in policy.toml; pusher not required.".to_owned(),
            details: vec![SubsystemDetailRow {
                label: "Policy".into(),
                value: "[observability].enabled = false".into(),
            }],
            last_observed_at: now_s,
        };
    }
    let ring_root = if obs.ring.dir.is_empty() {
        data_dir.join("observability")
    } else {
        std::path::PathBuf::from(&obs.ring.dir)
    };
    let spans_dir = ring_root.join("spans");
    let metrics_dir = ring_root.join("metrics");
    let pusher_events = ring_root.join("pusher-events.jsonl");
    let spans_mtime = newest_mtime_in(&spans_dir).unwrap_or(0);
    let metrics_mtime = newest_mtime_in(&metrics_dir).unwrap_or(0);
    let pusher_mtime = mtime_of(&pusher_events).unwrap_or(0);
    let kernel_side_mtime = spans_mtime.max(metrics_mtime);
    let age_kernel = now_s.saturating_sub(kernel_side_mtime);
    // 60s is the conservative ceiling: the kernel's heartbeat
    // loop emits once every 5s by default; `HEARTBEAT_INTERVAL`
    // bumps that to up to 30s on busy systems; a full minute of
    // silence means the kernel-side hub is genuinely idle.
    const FRESH_SECS: u64 = 60;
    let kernel_side_fresh = kernel_side_mtime > 0 && age_kernel <= FRESH_SECS;
    let pusher_ever_ran = pusher_mtime > 0;
    let age_pusher = now_s.saturating_sub(pusher_mtime);
    let pusher_events_fresh = pusher_mtime > 0 && age_pusher <= FRESH_SECS;
    let details = vec![
        SubsystemDetailRow {
            label: "Ring root".into(),
            value: ring_root.display().to_string(),
        },
        SubsystemDetailRow {
            label: "Spans last write".into(),
            value: format_health_time(spans_mtime, now_s),
        },
        SubsystemDetailRow {
            label: "Metrics last write".into(),
            value: format_health_time(metrics_mtime, now_s),
        },
        SubsystemDetailRow {
            label: "Pusher events last write".into(),
            value: format_health_time(pusher_mtime, now_s),
        },
    ];
    let (status, summary, last_observed_at) = if kernel_side_fresh && pusher_events_fresh {
        (
            "ok",
            format!("Kernel ring written {age_kernel}s ago; pusher events file present."),
            kernel_side_mtime.max(pusher_mtime),
        )
    } else if kernel_side_fresh && pusher_ever_ran {
        (
            "degraded",
            format!(
                "Kernel ring fresh ({age_kernel}s) but pusher events are stale \
                 (last write {age_pusher}s ago) — pusher binary may have exited."
            ),
            kernel_side_mtime,
        )
    } else if kernel_side_fresh {
        (
            "degraded",
            format!(
                "Kernel ring fresh ({age_kernel}s) but no \
                 `pusher-events.jsonl` — pusher binary may not be running."
            ),
            kernel_side_mtime,
        )
    } else if kernel_side_mtime > 0 {
        (
            "degraded",
            format!(
                "Kernel ring stale (last write {age_kernel}s ago) — hub may be \
                 disabled or starved."
            ),
            kernel_side_mtime,
        )
    } else {
        (
            "unknown",
            "No observability segments on disk yet; kernel ring not initialised.".to_owned(),
            0,
        )
    };
    PusherHealthCard {
        status,
        summary,
        details,
        last_observed_at,
    }
}

fn format_health_time(unix_s: u64, now_s: u64) -> String {
    if unix_s == 0 {
        return "never".to_owned();
    }
    let age = now_s.saturating_sub(unix_s);
    if age < 60 {
        return format!("{} ago", plural_unit(age, "second"));
    }
    let minutes = age / 60;
    if minutes < 60 {
        return format!("{} ago", plural_unit(minutes, "minute"));
    }
    let hours = minutes / 60;
    if hours < 24 {
        return format!("{} ago", plural_unit(hours, "hour"));
    }
    let days = hours / 24;
    format!("{} ago", plural_unit(days, "day"))
}

fn plural_unit(n: u64, singular: &str) -> String {
    if n == 1 {
        format!("1 {singular}")
    } else {
        format!("{n} {singular}s")
    }
}

/// Return the most-recent mtime (unix-seconds) of any direct
/// child of `dir`, or `None` when the directory is missing /
/// empty / unreadable.
fn newest_mtime_in(dir: &std::path::Path) -> Option<u64> {
    let entries = std::fs::read_dir(dir).ok()?;
    let mut newest: u64 = 0;
    for e in entries.flatten() {
        let meta = match e.metadata() {
            Ok(m) => m,
            Err(_) => continue,
        };
        if let Ok(mt) = meta.modified() {
            if let Ok(d) = mt.duration_since(std::time::UNIX_EPOCH) {
                let s = d.as_secs();
                if s > newest {
                    newest = s;
                }
            }
        }
    }
    if newest == 0 {
        None
    } else {
        Some(newest)
    }
}

fn mtime_of(path: &std::path::Path) -> Option<u64> {
    let meta = std::fs::metadata(path).ok()?;
    let mt = meta.modified().ok()?;
    let d = mt.duration_since(std::time::UNIX_EPOCH).ok()?;
    Some(d.as_secs())
}

/// Compute the Grafana deep-link for one subsystem if the
/// observability stack URL has been provisioned. The
/// observability worker just landed `cargo xtask observability`
/// which exposes a single base URL via the env var
/// `RAXIS_GRAFANA_BASE_URL`; we surface that as a per-tile link
/// when present, so the FE Health tab cards can deep-link to
/// the matching Grafana dashboard. `None` ⇒ no observability
/// stack provisioned — the FE hides the button.
fn grafana_dashboard_url(slug: &str) -> Option<String> {
    let base = std::env::var("RAXIS_GRAFANA_BASE_URL").ok()?;
    grafana_dashboard_url_from_base(&base, slug)
}

fn grafana_dashboard_url_from_base(base: &str, slug: &str) -> Option<String> {
    let trimmed = base.trim_end_matches('/');
    let uid = match slug {
        "kernel" => "raxis-00-overview",
        "observability" => "raxis-05-otel-pipeline",
        "sessions" => "raxis-20-lifecycle",
        "audit" => "raxis-30-audit",
        "planner" => "raxis-40-planner",
        "credentials" => "raxis-50-credential-proxies",
        "egress" => "raxis-60-egress",
        "dashboard" => "raxis-70-dashboard",
        "budget" => "raxis-80-budget-reviewer",
        "git" => "raxis-90-git",
        _ => return None,
    };
    Some(format!("{trimmed}/d/{uid}"))
}

/// Wall-clock now in milliseconds-since-Unix-epoch. The audit
/// chain status cache uses this as a coarse freshness clock; we
/// deliberately do NOT use `Instant` because the cache is also
/// surfaced on the wire (`verified_at_ms`), so the FE has to be
/// able to render it as a human timestamp.
fn unix_now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Wall-clock now in seconds-since-Unix-epoch as `u64`. Used by
/// every dashboard wire field documented as unix-seconds (e.g.
/// `SubsystemHealthCard.last_observed_at`,
/// `HealthSnapshot.kernel_booted_at`).
///
/// Pinned by `INV-DASHBOARD-WIRE-UNITS-CONSISTENT-01`: producers
/// of seconds-typed fields MUST go through this helper (or the
/// equivalent `raxis_types::clock::unix_now_secs`) so we never
/// silently feed milliseconds into a seconds-typed field. The
/// `u64` return matches the wire types in
/// `crates/dashboard/src/data.rs` without an intermediate `i64
/// → u64` cast at every call site.
fn unix_now_s() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Render a `ChainReadError` into the `(last_verified_seq, msg)`
/// tuple the dashboard wants on a broken-chain verdict. We
/// pick the seq the error names whenever the variant carries
/// one so the FE can highlight the broken record; otherwise we
/// fall back to `0`.
fn describe_chain_error(err: &raxis_audit_tools::ChainReadError) -> (u64, String) {
    use raxis_audit_tools::ChainReadError as E;
    let seq = match err {
        E::ChainBreak { seq, .. } => *seq,
        E::SequenceGap { expected, .. } => expected.saturating_sub(1),
        _ => 0,
    };
    (seq, err.to_string())
}

fn map_git_error_to_api(err: git::GitError) -> ApiError {
    match err {
        git::GitError::NotARepo { path } => {
            tracing::warn!(
                target = "raxis_dashboard",
                worktree_path = %path,
                "git: worktree directory is not a repository; surfacing 404"
            );
            ApiError::NotFound {
                kind: "worktree-history".into(),
            }
        }
        git::GitError::MissingPath { path } => {
            tracing::warn!(
                target = "raxis_dashboard",
                worktree_path = %path,
                "git: worktree path missing; surfacing 404"
            );
            ApiError::NotFound {
                kind: "worktree-path".into(),
            }
        }
        git::GitError::Timeout { secs } => {
            tracing::warn!(
                target = "raxis_dashboard",
                timeout_secs = secs,
                "git: subprocess timed out"
            );
            ApiError::Internal {
                log_only: format!("git timed out after {secs}s"),
            }
        }
        e @ git::GitError::Spawn(_) | e @ git::GitError::NonZero { .. } => ApiError::Internal {
            log_only: format!("git: {e}"),
        },
    }
}

// ---------------------------------------------------------------------------
// Worktree resolution helpers
// ---------------------------------------------------------------------------

/// Internal type the resolver returns — wraps a populated
/// [`WorktreeListEntry`] with no extra state. Kept opaque so
/// future fields (e.g. `path_prefix_match`) can be added
/// without breaking call sites.
#[derive(Debug, Clone)]
struct ResolvedWorktree {
    summary: WorktreeListEntry,
}

impl KernelDashboardData {
    /// Walk `policy.allowed_worktree_roots()` (kind=Main) +
    /// the durable session worktree list (kind=Session) and produce a
    /// stable, slug-keyed worktree directory for the route
    /// layer to look up.
    ///
    /// Slug discipline:
    ///   * Main roots: `main-<idx>` where `<idx>` is the
    ///     position in `allowed_worktree_roots()`. Stable
    ///     across reloads as long as the operator does not
    ///     reshuffle the list.
    ///   * Session roots: `session-<short-id>` where
    ///     `<short-id>` is the first 12 hex chars of the
    ///     session id (or the whole session id if shorter).
    fn collect_worktrees(&self) -> Result<Vec<ResolvedWorktree>, ApiError> {
        let mut out = Vec::new();
        let main_repo_path = self.internal_main_repo_path();
        out.push(main_worktree_entry(
            "main-repository".to_owned(),
            "repositories/main".to_owned(),
            main_repo_path.clone(),
            None,
            None,
            None,
            None,
        ));
        let bundle = self.policy.load_full();
        for (idx, raw) in bundle.allowed_worktree_roots().iter().enumerate() {
            let path = raw.trim_end_matches('/').to_owned();
            if same_display_path(&path, &main_repo_path) {
                continue;
            }
            let label = std::path::Path::new(&path)
                .file_name()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_else(|| path.clone());
            let entry = main_worktree_entry(
                format!("main-{idx}"),
                if label.is_empty() {
                    format!("main-{idx}")
                } else {
                    label
                },
                path,
                None,
                None,
                None,
                None,
            );
            if entry.summary.observed_head_sha.is_some() {
                out.push(entry);
            }
        }
        if let Ok(conn) = self.open_ro() {
            let mut seen_main_initiatives = std::collections::HashSet::new();
            if let Ok(mut stmt) = conn.prepare(&format!(
                "SELECT snapshot_id, task_id, initiative_id, base_sha, head_sha \
                 FROM {TBL_WORKTREE_SNAPSHOTS} \
                 WHERE trigger = 'IntegrationMerge' \
                   AND initiative_id IS NOT NULL \
                 ORDER BY taken_at DESC, snapshot_id DESC \
                 LIMIT 200"
            )) {
                let rows = stmt.query_map([], |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, String>(2)?,
                        r.get::<_, String>(3)?,
                        r.get::<_, String>(4)?,
                    ))
                });
                if let Ok(rows) = rows {
                    for row in rows.flatten() {
                        let (_snapshot_id, task_id, initiative_id, base_sha, head_sha) = row;
                        if !seen_main_initiatives.insert(initiative_id.clone()) {
                            continue;
                        }
                        let review_base_sha =
                            initiative_review_base_sha(&conn, &initiative_id)?.unwrap_or(base_sha);
                        let initiative_display_name =
                            initiative_name_for_id_opt(&conn, Some(&initiative_id))?;
                        let short = short_stable_id(&initiative_id, 12);
                        let label = match initiative_display_name.as_deref() {
                            Some(name) if !name.trim().is_empty() => {
                                format!("Main:{name}")
                            }
                            _ => format!("Main:{short}"),
                        };
                        // Use the full initiative id in the route slug.
                        // UUIDv7 initiatives admitted in the same moment can
                        // share their first timestamp-heavy characters; a
                        // short slug would collapse multiple main review rows
                        // onto one `/git/:name` route.
                        out.push(main_worktree_entry(
                            format!("main-integration-{initiative_id}"),
                            label,
                            main_repo_path.clone(),
                            Some(task_id),
                            Some(initiative_id),
                            initiative_display_name,
                            Some((review_base_sha, head_sha)),
                        ));
                    }
                }
            }
        }
        // Session overlay — include active, revoked, and expired rows.
        //
        // Worktree review is forensic, not just "currently live VM" state:
        // the most useful moment to inspect a diff is often after the
        // executor/reviewer has cleanly exited and revoked its session. The
        // old path used `views::sessions::active_list`, which dropped those
        // rows and also omitted `base_sha`, causing session worktrees to render
        // as browse-only even though the session table had the exact base
        // needed for a PR-style diff.
        if let Ok(conn) = self.open_ro() {
            if let Ok(mut stmt) = conn.prepare(&format!(
                "SELECT s.session_id, COALESCE(s.session_agent_type, ''), s.role_id, \
                        s.worktree_root, s.base_sha, \
                        s.created_at, s.expires_at, s.revoked, s.revoked_at, \
                        (SELECT t.task_id FROM {TBL_TASKS} t \
                          WHERE t.session_id = s.session_id \
                          ORDER BY t.admitted_at DESC LIMIT 1) AS task_id, \
                        COALESCE(\
                          s.initiative_id, \
                          (SELECT t.initiative_id FROM {TBL_TASKS} t \
                           WHERE t.session_id = s.session_id \
                           ORDER BY t.admitted_at DESC LIMIT 1)\
                        ) AS initiative_id \
                 FROM {TBL_SESSIONS} s \
                 WHERE s.worktree_root IS NOT NULL \
                 ORDER BY COALESCE(s.revoked_at, s.created_at) DESC, \
                          s.created_at DESC, \
                          s.session_id ASC \
                 LIMIT 500"
            )) {
                let rows = stmt.query_map([], |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, String>(2)?,
                        r.get::<_, String>(3)?,
                        r.get::<_, Option<String>>(4)?,
                        r.get::<_, i64>(5)?.max(0) as u64,
                        r.get::<_, i64>(6)?.max(0) as u64,
                        r.get::<_, i64>(7)? != 0,
                        r.get::<_, Option<i64>>(8)?.map(|v| v.max(0) as u64),
                        r.get::<_, Option<String>>(9)?,
                        r.get::<_, Option<String>>(10)?,
                    ))
                });
                if let Ok(rows) = rows {
                    for row in rows.flatten() {
                        let (
                            session_id,
                            raw_agent_type,
                            role_id,
                            wt,
                            base_sha,
                            created_at,
                            expires_at,
                            revoked,
                            revoked_at,
                            task_id,
                            initiative_id,
                        ) = row;
                        if wt.trim().is_empty() {
                            continue;
                        }
                        let short = if session_id.len() >= 12 {
                            session_id[..12].to_owned()
                        } else {
                            session_id.clone()
                        };
                        let owning = SessionOwningTask {
                            initiative_id: initiative_id.clone(),
                            task_id: task_id.clone(),
                            input_tokens: 0,
                            output_tokens: 0,
                        };
                        let agent_type = if raw_agent_type.trim().is_empty() {
                            semantic_agent_type_for_session(
                                &conn,
                                &session_id,
                                &role_id,
                                Some(&owning),
                            )
                        } else {
                            raw_agent_type
                        };
                        let initiative_display_name =
                            initiative_name_for_id_opt(&conn, initiative_id.as_deref())?;
                        out.push(ResolvedWorktree {
                            summary: WorktreeListEntry {
                                name: format!("session-{short}"),
                                label: format!("{agent_type}:{short}"),
                                kind: "Session".into(),
                                path: wt,
                                session_id: Some(session_id),
                                task_id,
                                initiative_id,
                                initiative_display_name,
                                agent_type: Some(agent_type),
                                session_state: Some(session_state_from_columns(
                                    revoked, revoked_at, created_at, expires_at,
                                )),
                                observed_head_sha: None,
                                observed_branch: None,
                                observed_dirty_paths: None,
                                base_sha,
                                comparison_head_sha: None,
                            },
                        });
                    }
                }
            }
        }
        Ok(out)
    }

    /// Look one slug up in the resolved set.
    /// Returns `Err(NotFound)` if the slug is unknown OR if the
    /// resolved path is not under any
    /// `policy.allowed_worktree_roots()` (defense-in-depth).
    fn resolve_worktree(&self, name: &str) -> Result<ResolvedWorktree, ApiError> {
        let bundle = self.policy.load_full();
        let resolved = self
            .collect_worktrees()?
            .into_iter()
            .find(|w| w.summary.name == name)
            .ok_or(ApiError::NotFound {
                kind: "worktree".into(),
            })?;
        if !bundle.worktree_root_allowed(&resolved.summary.path) {
            let is_internal_main = resolved.summary.kind == "Main"
                && same_display_path(&resolved.summary.path, &self.internal_main_repo_path());
            if !is_internal_main {
                return Err(ApiError::NotFound {
                    kind: "worktree".into(),
                });
            }
        }
        Ok(resolved)
    }

    fn internal_main_repo_path(&self) -> String {
        self.data_dir
            .join("repositories")
            .join("main")
            .display()
            .to_string()
    }
}

fn main_worktree_entry(
    name: String,
    label: String,
    path: String,
    task_id: Option<String>,
    initiative_id: Option<String>,
    initiative_display_name: Option<String>,
    review_range: Option<(String, String)>,
) -> ResolvedWorktree {
    let observed = std::path::Path::new(&path)
        .exists()
        .then(|| git::probe_worktree_summary(std::path::Path::new(&path), None));
    let (base_sha, comparison_head_sha) = review_range
        .map(|(base, head)| (Some(base), Some(head)))
        .unwrap_or((None, None));
    ResolvedWorktree {
        summary: WorktreeListEntry {
            name,
            label,
            kind: "Main".into(),
            path,
            session_id: None,
            task_id,
            initiative_id,
            initiative_display_name,
            agent_type: None,
            session_state: None,
            observed_head_sha: comparison_head_sha
                .clone()
                .or_else(|| observed.as_ref().and_then(|s| s.head_sha.clone())),
            observed_branch: observed.as_ref().and_then(|s| s.branch.clone()),
            observed_dirty_paths: observed
                .as_ref()
                .map(|s| u32::try_from(s.status_lines.len()).unwrap_or(u32::MAX)),
            base_sha,
            comparison_head_sha,
        },
    }
}

fn short_stable_id(id: &str, max_chars: usize) -> String {
    id.chars().take(max_chars).collect()
}

fn same_display_path(a: &str, b: &str) -> bool {
    a.trim_end_matches('/') == b.trim_end_matches('/')
}

// ---------------------------------------------------------------------------
// Repo-browsing sandbox helpers (worktree_tree / worktree_file)
// ---------------------------------------------------------------------------

/// Maximum number of dirent rows surfaced for one
/// `GET /api/git/worktrees/:name/tree` call. Generous for any
/// real source tree; tight enough that a worktree containing a
/// pathologically-large directory (e.g. `node_modules` with
/// 50K entries) cannot pin a request thread for unbounded time.
/// When tripped the response carries `truncated = true`.
const MAX_TREE_ENTRIES: usize = 5_000;

/// Maximum file size the inline `worktree_file` endpoint will
/// serve. Anything larger gets a `BadRequest` and the operator
/// is expected to use a future streaming-download endpoint.
/// 2 MiB is enough for source files (a 100 KLOC Rust file is
/// ~3 MiB compressed), small images, JSON manifests, etc., but
/// blocks accidental dumps of database files and binaries.
const MAX_FILE_INLINE_BYTES: usize = 2 * 1024 * 1024;

/// Resolve a forward-slash separated, root-relative `sub_path`
/// against `root` and verify that:
///   * no component of the joined path is a symlink, AND
///   * the canonical (symlink-followed) form of the joined
///     path is still under the canonical form of `root`.
///
/// The first check is the load-bearing one — refusing
/// symlinks at every depth means `worktree_file` can hand
/// the resolved path back to `std::fs::read` without ever
/// dereferencing a link. The second check is a redundant
/// defence: even if a future change relaxes the symlink
/// rule, a path that escapes the canonical root is still
/// rejected.
///
/// Returns `Err(BadRequest)` when the path escapes or
/// crosses a symlink; `Err(NotFound)` when the path does
/// not exist.
fn resolve_within_root(
    root: &std::path::Path,
    sub_path: &str,
) -> Result<std::path::PathBuf, ApiError> {
    let canonical_root = std::fs::canonicalize(root).map_err(|_| ApiError::NotFound {
        kind: "worktree-path".into(),
    })?;
    let trimmed = sub_path.trim_matches('/');
    let mut joined = canonical_root.clone();
    if !trimmed.is_empty() {
        for component in trimmed.split('/') {
            // Belt-and-braces — the route-layer validator
            // already rejects these; refusing them here
            // closes the door if a future caller bypasses
            // the route layer (e.g. an internal helper).
            if component.is_empty() || component == "." || component == ".." || component == ".git"
            {
                return Err(ApiError::BadRequest {
                    detail: "path contains forbidden component".into(),
                });
            }
            joined.push(component);
            // Refuse symlinks at every depth. We cannot defer
            // this to the canonicalize check below because
            // canonicalize FOLLOWS symlinks and the caller
            // wants to apply `symlink_metadata` to the
            // returned path; if we returned the canonical
            // (followed) form, a downstream `is_symlink()`
            // check would always say "no".
            match std::fs::symlink_metadata(&joined) {
                Ok(m) if m.file_type().is_symlink() => {
                    return Err(ApiError::BadRequest {
                        detail: "path crosses a symlink".into(),
                    });
                }
                Ok(_) => {}
                Err(_) => {
                    // Final-component miss is NotFound; an
                    // earlier-component miss is unusual but we
                    // surface NotFound either way (no need to
                    // distinguish for the operator UI).
                    return Err(ApiError::NotFound {
                        kind: "tree-entry".into(),
                    });
                }
            }
        }
    }
    // Defence-in-depth: even with no symlinks on the path,
    // verify the canonical form is under the canonical root.
    let canonical = std::fs::canonicalize(&joined).map_err(|_| ApiError::NotFound {
        kind: "tree-entry".into(),
    })?;
    if !canonical.starts_with(&canonical_root) {
        return Err(ApiError::BadRequest {
            detail: "path escapes worktree root".into(),
        });
    }
    // Return the JOINED (non-canonicalized-from-symlinks)
    // path; the caller will run `symlink_metadata` on it and
    // must see the actual entry, not a followed link.
    Ok(joined)
}

/// Classify a `SessionRow` into the wire-state string the
/// dashboard surfaces — one of `Active`, `Revoked`, or `Expired`.
///
/// `INV-DASHBOARD-SESSION-DETAIL-FORENSIC-01`: the detail view
/// MUST surface terminated rows (the operator clicked one in the
/// list — refusing to render its detail is a contract violation,
/// even when the row has just terminated). `Revoked` takes
/// precedence over `Expired` because a revocation is a deliberate
/// operator / kernel action; an expiry is the passive lapse of
/// `expires_at`. A row that is BOTH revoked and past `expires_at`
/// is reported as `Revoked` so the operator sees the deliberate
/// terminal cause.
fn session_row_state(s: &raxis_store::views::sessions::SessionRow) -> String {
    session_state_from_columns(s.revoked, s.revoked_at, s.created_at, s.expires_at)
}

fn session_state_from_columns(
    revoked: bool,
    _revoked_at: Option<u64>,
    _created_at: u64,
    expires_at: u64,
) -> String {
    if revoked {
        "Revoked".into()
    } else {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        if expires_at <= now {
            "Expired".into()
        } else {
            "Active".into()
        }
    }
}

/// Common task-row → TaskView projection. Pulls structured
/// outputs from the V2 §3.2 table; reviewer verdicts are not
/// surfaced yet (the store does not own that read view today).
///
/// The `path_allowlist` projection delegates to
/// `raxis_store::views::plan_fields::reveal_for_task`, which parses
/// the immutable `signed_plan_artifacts.plan_bytes` blob owned by
/// the task's initiative. The reveal is fail-soft for the dashboard:
/// any failure (missing artifact, malformed plan, task absent from
/// plan TOML) collapses to an empty allowlist so the operator UI
/// keeps rendering — `cli/src/reveal.rs` is the gated path that
/// surfaces the typed forensic error variants.
///
/// `title` falls back to the `task_id` because the `tasks` table
/// does not store a human title; rendering an empty `<h1>` was a
/// blank-view paper-cut on every drill-in.
///
/// **IntegrationMerge coordinator carve-out
/// (`INV-DASHBOARD-INTEGRATION-MERGE-VISIBLE-OR-EXCLUDED-01`).** When
/// `task_id == initiative_id` the row is the synthetic
/// orchestrator-coordinator task that
/// `initiatives::lifecycle::auto_spawn_orchestrator_session_in_tx`
/// admits in lockstep with the Orchestrator session
/// (`v2-deep-spec.md §Step 11 IntegrationMerge`). Without an
/// override the dashboard renders both `title` and `task_id` as
/// the same UUID, which reads like a duplicate of the initiative
/// row and hides the row's actual FSM state (`Admitted → Running`
/// for the lifetime of the merge) behind an opaque hex string.
/// We pick option (A) — "first-class visible task" — by stamping
/// a fixed human title `Integration merge` here. The wire
/// `task_id` stays the real UUID so the FE can route to
/// `/tasks/<initiative_id>` and the kernel-store joins
/// (`task_intent_ranges`, `lane_budget_reservations`) remain
/// referentially valid; the FE is responsible for substituting
/// the stable display id (`«integration-merge»`) at render time.
pub(crate) const INTEGRATION_MERGE_TITLE: &str = "Integration merge";

/// iter69 — per-session "owning task" projection used by the
/// dashboard's session detail / list panels.
///
/// A session belongs to AT MOST one running task at any moment
/// (a planner / executor / reviewer VM is bound to a single task
/// for its whole lifetime), but the `tasks` table allows a
/// session id to recur across task rows in two narrow cases:
///
///   1. Sub-task replays in a merge initiative — the
///      orchestrator session can drive several follow-up tasks
///      sequentially.
///   2. Test fixtures that pin a single session id across
///      multiple synthetic tasks for ergonomics.
///
/// The shape this struct returns is "the most recently
/// transitioned task" for the session. That mirrors the dashboard
/// display semantics: an operator looking at session detail wants
/// the *current* task's identifier and token totals, not a
/// stale earlier row. Ordering uses
/// `transitioned_at DESC, task_id ASC` so the projection is
/// deterministic even when two rows share a transition stamp.
#[derive(Debug, Clone, Default)]
pub(crate) struct SessionOwningTask {
    pub initiative_id: Option<String>,
    pub task_id: Option<String>,
    pub input_tokens: u64,
    pub output_tokens: u64,
}

/// Look up the most-recent task owning the given session id and
/// project the columns the dashboard's `SessionView` enrichment
/// needs (`initiative_id`, `task_id`, `cumulative_input_tokens`,
/// `cumulative_output_tokens`). Returns
/// [`SessionOwningTask::default()`] when no task references the
/// session — this is normal for orchestrator-only sessions
/// before their first admitted intent and for sessions that
/// short-circuit on a deterministic check.
///
/// Pinned column order against the tasks DDL (migration 1 / 12 /
/// 21) — adding new columns to the SELECT is safe but reorderin
/// existing ones requires updating the `r.get(N)` calls below.
pub(crate) fn owning_task_for_session(
    conn: &rusqlite::Connection,
    session_id: &str,
) -> rusqlite::Result<SessionOwningTask> {
    let sql = format!(
        "SELECT initiative_id, task_id, \
                cumulative_input_tokens, cumulative_output_tokens \
         FROM {tasks} \
         WHERE session_id = ?1 \
         ORDER BY transitioned_at DESC, task_id ASC \
         LIMIT 1",
        tasks = raxis_store::Table::Tasks.as_str(),
    );
    let mut stmt = conn.prepare(&sql)?;
    let row = stmt.query_row(rusqlite::params![session_id], |r| {
        Ok(SessionOwningTask {
            initiative_id: r.get::<_, Option<String>>(0)?,
            task_id: r.get::<_, Option<String>>(1)?,
            input_tokens: r.get::<_, i64>(2)?.max(0) as u64,
            output_tokens: r.get::<_, i64>(3)?.max(0) as u64,
        })
    });
    match row {
        Ok(v) => Ok(v),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(SessionOwningTask::default()),
        Err(e) => Err(e),
    }
}

/// Batch form of [`owning_task_for_session`] for session lists.
/// The SQL orders rows so the first row encountered for a
/// `session_id` is the same "most recently transitioned task"
/// that the scalar helper would return.
fn owning_tasks_for_sessions(
    conn: &rusqlite::Connection,
    session_ids: &[String],
) -> std::collections::HashMap<String, SessionOwningTask> {
    let mut out: std::collections::HashMap<String, SessionOwningTask> =
        std::collections::HashMap::new();
    if session_ids.is_empty() {
        return out;
    }
    let placeholders = std::iter::repeat("?")
        .take(session_ids.len())
        .collect::<Vec<_>>()
        .join(", ");
    let sql = format!(
        "SELECT session_id, initiative_id, task_id, \
                cumulative_input_tokens, cumulative_output_tokens \
         FROM {tasks} \
         WHERE session_id IN ({placeholders}) \
         ORDER BY session_id ASC, transitioned_at DESC, task_id ASC",
        tasks = raxis_store::Table::Tasks.as_str(),
    );
    let Ok(mut stmt) = conn.prepare(&sql) else {
        return out;
    };
    let rows = stmt.query_map(
        rusqlite::params_from_iter(session_ids.iter().map(String::as_str)),
        |r| {
            Ok((
                r.get::<_, String>(0)?,
                SessionOwningTask {
                    initiative_id: r.get::<_, Option<String>>(1)?,
                    task_id: r.get::<_, Option<String>>(2)?,
                    input_tokens: r.get::<_, i64>(3)?.max(0) as u64,
                    output_tokens: r.get::<_, i64>(4)?.max(0) as u64,
                },
            ))
        },
    );
    if let Ok(rows) = rows {
        for row in rows.flatten() {
            let (session_id, owning) = row;
            out.entry(session_id).or_insert(owning);
        }
    }
    out
}

fn session_agent_type_for_session(conn: &rusqlite::Connection, session_id: &str) -> Option<String> {
    conn.query_row(
        &format!(
            "SELECT session_agent_type FROM {} \
             WHERE session_id = ?1 AND session_agent_type IS NOT NULL \
             LIMIT 1",
            raxis_store::Table::Sessions.as_str(),
        ),
        rusqlite::params![session_id],
        |r| r.get::<_, String>(0),
    )
    .ok()
}

fn initiative_name_for_id(
    conn: &raxis_store::ro::RoConn,
    initiative_id: &str,
) -> Result<String, ApiError> {
    raxis_store::views::plan_fields::reveal_initiative_meta(conn, initiative_id)
        .map(|m| m.name)
        .map_err(|e| ApiError::Internal {
            log_only: format!("plan_fields::reveal_initiative_meta({initiative_id}): {e}"),
        })
}

fn initiative_name_for_id_opt(
    conn: &raxis_store::ro::RoConn,
    initiative_id: Option<&str>,
) -> Result<Option<String>, ApiError> {
    initiative_id
        .map(|id| initiative_name_for_id(conn, id).map(Some))
        .unwrap_or(Ok(None))
}

fn initiative_review_base_sha(
    conn: &raxis_store::ro::RoConn,
    initiative_id: &str,
) -> Result<Option<String>, ApiError> {
    let mut stmt = conn
        .prepare(&format!(
            "SELECT base_sha \
             FROM {TBL_SESSIONS} \
             WHERE initiative_id = ?1 \
               AND base_sha IS NOT NULL \
               AND base_tracking_ref IS NOT NULL \
             ORDER BY \
               CASE WHEN session_agent_type = 'Orchestrator' THEN 0 ELSE 1 END, \
               created_at ASC, \
               session_id ASC \
             LIMIT 1"
        ))
        .map_err(|e| ApiError::Internal {
            log_only: format!("initiative review-base query prepare: {e}"),
        })?;
    match stmt.query_row([initiative_id], |r| r.get::<_, String>(0)) {
        Ok(base_sha) => Ok(Some(base_sha)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(ApiError::Internal {
            log_only: format!("initiative review-base query: {e}"),
        }),
    }
}

fn session_vm_env_view_for_session(
    conn: &raxis_store::ro::RoConn,
    session_id: &str,
) -> Result<Vec<SessionVmEnvView>, ApiError> {
    raxis_store::views::sessions::vm_env_for_session(conn, session_id)
        .map(|rows| {
            rows.into_iter()
                .map(|r| SessionVmEnvView {
                    key: r.key,
                    value: r.value,
                    redacted: r.redacted,
                    source: r.source,
                    captured_at: r.captured_at,
                })
                .collect()
        })
        .map_err(|e| ApiError::Internal {
            log_only: format!("sessions::vm_env_for_session({session_id}): {e}"),
        })
}

fn semantic_agent_type_for_task(
    conn: &raxis_store::ro::RoConn,
    task_id: &str,
    initiative_id: &str,
) -> Result<String, ApiError> {
    if task_id == initiative_id {
        return Ok("Orchestrator".to_owned());
    }
    raxis_store::views::plan_fields::reveal_for_task(conn, task_id)
        .map(|f| f.session_agent_type)
        .map_err(|e| ApiError::Internal {
            log_only: format!("plan_fields::reveal_for_task({task_id}) agent type: {e}"),
        })
}

fn semantic_agent_type_for_session(
    conn: &raxis_store::ro::RoConn,
    session_id: &str,
    role_id: &str,
    owning_task: Option<&SessionOwningTask>,
) -> String {
    if let Some(role) = session_agent_type_for_session(conn, session_id) {
        if !role.trim().is_empty() {
            return role;
        }
    }
    if let Some(owning) = owning_task {
        if let (Some(task_id), Some(initiative_id)) =
            (owning.task_id.as_deref(), owning.initiative_id.as_deref())
        {
            if let Ok(role) = semantic_agent_type_for_task(conn, task_id, initiative_id) {
                return role;
            }
        }
    }
    if role_id == "Planner" {
        "Orchestrator".to_owned()
    } else {
        role_id.to_owned()
    }
}

/// iter69 — extract a model id from the most-recent LLM turn
/// capture for the given task. Prefer `response.model`, then fall
/// back to `request.model` / `request.model_id` so failed upstream
/// calls still surface the model the planner attempted to use.
/// Returns `None` when the capture is unwired (read-only data dir),
/// the file is missing (task never round-tripped through the
/// gateway), and neither payload carries a model.
///
/// The dashboard calls this from `enrich_session_view_with_owning_task`
/// when the `sessions.model` column is NULL (the kernel did not
/// yet persist a model — see migration 25 and the
/// `set_session_provider_model_if_unset` writer in
/// `crates/store/src/views/sessions.rs`). The lookup is
/// O(1) on the per-task ring tail; even on a hot session detail
/// fetch the cost is dominated by the SQLite round-trip above,
/// not the file read.
pub(crate) fn latest_model_for_task(
    capture: Option<&Arc<TaskLlmCapture>>,
    task_id: &str,
) -> Option<String> {
    let cap = capture?;
    let mut recs = cap.tail(task_id, 1);
    let last = recs.pop()?;
    model_from_turn_record(&last)
}

/// Best-effort provider fallback for legacy sessions whose
/// `sessions.provider` column is still NULL. This cannot recover the
/// policy-level provider id for every historic record (the capture ring
/// did not store the gateway URL), but it does recover the common direct
/// provider labels from captured request / response payloads so the detail
/// page stops rendering a blank provider when the evidence is already on
/// disk.
pub(crate) fn latest_provider_for_task(
    capture: Option<&Arc<TaskLlmCapture>>,
    task_id: &str,
) -> Option<String> {
    let cap = capture?;
    let mut recs = cap.tail(task_id, 1);
    let last = recs.pop()?;
    provider_from_turn_record(&last)
}

fn model_from_turn_record(last: &crate::LlmTurnRecord) -> Option<String> {
    let response = serde_json::from_str::<serde_json::Value>(&last.body).ok();
    let request = serde_json::from_str::<serde_json::Value>(&last.request_body).ok();
    response
        .as_ref()
        .and_then(model_from_json_value)
        .or_else(|| request.as_ref().and_then(model_from_json_value))
}

fn provider_from_turn_record(last: &crate::LlmTurnRecord) -> Option<String> {
    let response = serde_json::from_str::<serde_json::Value>(&last.body).ok();
    let request = serde_json::from_str::<serde_json::Value>(&last.request_body).ok();
    provider_from_turn_payloads(request.as_ref(), response.as_ref())
}

fn model_from_json_value(v: &serde_json::Value) -> Option<String> {
    v.get("model")
        .or_else(|| v.get("model_id"))
        .or_else(|| v.get("model_id_actual"))
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
}

fn provider_from_turn_payloads(
    request: Option<&serde_json::Value>,
    response: Option<&serde_json::Value>,
) -> Option<String> {
    if let Some(provider_id) = request
        .and_then(|v| v.get("provider_id"))
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        return Some(provider_id.to_owned());
    }
    let model = response
        .and_then(model_from_json_value)
        .or_else(|| request.and_then(model_from_json_value))?;
    provider_from_model_id(model.as_str())
}

fn provider_from_model_id(model: &str) -> Option<String> {
    let m = model.to_ascii_lowercase();
    if m.starts_with("claude-") {
        return Some("anthropic".to_owned());
    }
    if m.starts_with("gpt-") || m.starts_with("o1") || m.starts_with("o3") || m.starts_with("o4") {
        return Some("openai".to_owned());
    }
    if m.starts_with("gemini-") {
        return Some("gemini".to_owned());
    }
    if m.starts_with("anthropic.") || m.starts_with("amazon.") || m.contains(".bedrock.") {
        return Some("bedrock".to_owned());
    }
    None
}

/// iter74 — sum `usage.input_tokens` / `usage.output_tokens`
/// across every captured LLM turn for the given task and return
/// the totals. Mirrors the per-turn extraction in `record_to_view`:
/// Anthropic emits `usage.input_tokens` / `usage.output_tokens`;
/// OpenAI's `chat.completion` envelope uses
/// `usage.prompt_tokens` / `usage.completion_tokens`; both are
/// folded into the canonical input/output totals here.
///
/// Why a read-side helper rather than a kernel-side UPDATE:
/// Orchestrator-role sessions emit terminal intents
/// (`ActivateSubTask`, `RetrySubTask`, `BatchActivateSubTasks`)
/// that early-dispatch in `handle_inner` BEFORE the shared
/// `pre_gate` runs (see `kernel/src/handlers/intent.rs`, the
/// `match req.intent_kind { ... ActivateSubTask ... }` block
/// that returns directly into `handle_activate_sub_task` etc).
/// Pre-gate is the ONLY place that persists
/// `tokens_used` into `tasks.cumulative_input_tokens` /
/// `cumulative_output_tokens`, so an orchestrator coordinator
/// task's token columns stay at zero for the entire initiative
/// lifecycle. Executor / Reviewer sessions are unaffected — their
/// terminal intents (`SingleCommit`, `CompleteTask`,
/// `ReportFailure`, `SubmitReview`) all flow through pre-gate.
///
/// This fallback closes the visibility gap without changing any
/// kernel admission semantics. It also gives the dashboard
/// "streaming" token semantics — totals refresh on every
/// LLM-turn capture rather than only at terminal-intent time —
/// which is what the model fallback already provides for the
/// model id.
///
/// Returns `None` when the capture is unwired (read-only data
/// dir / EROFS bind mount) or when no captured turn carries
/// a parseable `usage.*` object — both totals being zero would
/// be indistinguishable from "no turns yet" and would suppress
/// the kernel-persisted values that ARE the truth for executor /
/// reviewer sessions, so we return `None` rather than `Some((0,0))`.
pub(crate) fn cumulative_tokens_for_task(
    capture: Option<&Arc<TaskLlmCapture>>,
    task_id: &str,
) -> Option<(u64, u64)> {
    let cap = capture?;
    // `tail(.., usize::MAX)` is the existing all-records read path;
    // it parses every line of the per-task JSONL ring. Cost is
    // bounded by `TaskCaptureConfig::max_records_per_task` (today
    // a few hundred), so even an O(N) sum here is cheap on a
    // detail-page render and does not materially extend the
    // session-detail handler's tail latency.
    let recs = cap.tail(task_id, usize::MAX);
    if recs.is_empty() {
        return None;
    }
    let mut total_in: u64 = 0;
    let mut total_out: u64 = 0;
    let mut any_usage = false;
    for r in &recs {
        let Ok(body) = serde_json::from_str::<serde_json::Value>(&r.body) else {
            continue;
        };
        let Some(usage) = body.get("usage").and_then(|v| v.as_object()) else {
            continue;
        };
        any_usage = true;
        let in_tok = usage
            .get("input_tokens")
            .or_else(|| usage.get("prompt_tokens"))
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let out_tok = usage
            .get("output_tokens")
            .or_else(|| usage.get("completion_tokens"))
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        total_in = total_in.saturating_add(in_tok);
        total_out = total_out.saturating_add(out_tok);
    }
    if !any_usage {
        return None;
    }
    Some((total_in, total_out))
}

/// iter69 — fold the `owning_task_for_session` projection plus
/// (optionally) a fallback model from the LLM turn capture into
/// a partially-built `SessionView`. The fields touched are the
/// ones that pre-iter69 hardcoded to `None` / `0`:
///   * `initiative_id`
///   * `task_id`
///   * `input_tokens`
///   * `output_tokens`
///   * `model` — only when the session row carried NULL (the
///     kernel had not yet persisted it).
///
/// `provider` is populated only when the row itself is NULL and the
/// caller supplied a legacy capture fallback. The fetch-time kernel
/// writer is still the authoritative source for policy-level provider
/// ids; this fallback keeps historic/session-detail rows useful when
/// the capture ring already contains enough evidence to derive a
/// best-effort provider label.
pub(crate) fn enrich_session_view_with_owning_task(
    mut view: raxis_dashboard::data::SessionView,
    owning_task: SessionOwningTask,
    fallback_provider: Option<String>,
    fallback_model: Option<String>,
    fallback_tokens: Option<(u64, u64)>,
) -> raxis_dashboard::data::SessionView {
    if view.initiative_id.is_none() {
        view.initiative_id = owning_task.initiative_id;
    }
    if view.task_id.is_none() {
        view.task_id = owning_task.task_id;
    }
    if view.input_tokens == 0 {
        view.input_tokens = owning_task.input_tokens;
    }
    if view.output_tokens == 0 {
        view.output_tokens = owning_task.output_tokens;
    }
    // iter74 — orchestrator-session token visibility fallback.
    //
    // Apply ONLY when BOTH `input_tokens` and `output_tokens` are
    // still zero. Either pre-populated (kernel-persisted via the
    // pre-gate UPDATE) value sticks: the LLM-turn-capture sum has
    // a different semantic than the kernel's per-intent stamp
    // (the latter is the planner's running-total snapshot at
    // terminal-submit time, the former is a per-turn aggregate),
    // and Mixing the two would silently inflate the dashboard's
    // reported totals on hybrid paths. Pairs with
    // `cumulative_tokens_for_task` above — see the rationale
    // doc-comment there for the orchestrator early-dispatch gap
    // this closes.
    if view.input_tokens == 0 && view.output_tokens == 0 {
        if let Some((in_tok, out_tok)) = fallback_tokens {
            view.input_tokens = in_tok;
            view.output_tokens = out_tok;
        }
    }
    if view.model.is_none() {
        view.model = fallback_model;
    }
    if view.provider.is_none() {
        view.provider = fallback_provider;
    }
    view
}

/// Compute the dashboard-visible title for a kernel task row.
///
/// Returns `Integration merge` for the synthetic coordinator
/// row whose `task_id == initiative_id`
/// (`INV-DASHBOARD-INTEGRATION-MERGE-VISIBLE-OR-EXCLUDED-01`),
/// otherwise echoes the operator-authored `task_id` (the
/// `tasks` table has no separate name column, so the id is the
/// best human label we have).
pub(crate) fn task_display_title(task_id: &str, initiative_id: &str) -> String {
    if task_id == initiative_id {
        INTEGRATION_MERGE_TITLE.to_owned()
    } else {
        task_id.to_owned()
    }
}

/// Project a kernel-glue [`crate::LlmTurnRecord`] to the
/// dashboard-side [`raxis_dashboard::data::TaskLlmTurnView`].
///
/// `INV-DASHBOARD-LLM-TURN-PANEL-WIRE-SHAPE-01`. The FE's
/// per-task LLM turns panel reads `turn_number`, `ts_unix`,
/// `model`, `role`, `request`, `response`, and per-turn token
/// usage; we lift each from the on-disk `LlmTurnRecord` here:
///
/// * `turn_number` — passed in by the caller (the
///   `tail()`-side enumeration, 1-indexed in disk-append
///   order).
/// * `ts_unix` — `at_ms / 1000`.
/// * `response` — `serde_json::from_str(&record.body)` on
///   success; on parse failure falls back to
///   `Value::String(body)` so the operator still sees the
///   raw bytes (e.g. partial SSE stream / transport-error
///   string).
/// * `model` / `role` — `body.model` / `body.role` when the
///   parse succeeds (Anthropic's response envelope shape;
///   OpenAI uses the same field names in `chat.completion`).
///   Empty string when absent or the body is non-JSON.
/// * `input_tokens` / `output_tokens` /
///   `cache_creation_input_tokens` / `cache_read_input_tokens`
///   — lifted from `body.usage.*`. Anthropic's field names
///   are the canonical shape; OpenAI's `prompt_tokens` /
///   `completion_tokens` are mapped onto `input_tokens` /
///   `output_tokens` (cache fields stay `None` — OpenAI
///   doesn't expose prompt-cache hit/miss counts).
/// * `request` — `serde_json::from_str(&record.request_body)`
///   when iter64+ kernels recorded one; legacy records (or
///   parse failures) → `Value::Null`.
///
/// Public so the integration test at
/// `tests/task_llm_turn_view_projection.rs` can witness the
/// projection contract end-to-end without the full
/// `KernelDashboardData` scaffold.
pub fn record_to_view(
    r: crate::LlmTurnRecord,
    turn_number: u32,
) -> raxis_dashboard::data::TaskLlmTurnView {
    let response = match serde_json::from_str::<serde_json::Value>(&r.body) {
        Ok(v) => v,
        Err(_) => serde_json::Value::String(r.body.clone()),
    };
    let request = if r.request_body.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_str::<serde_json::Value>(&r.request_body)
            .unwrap_or(serde_json::Value::Null)
    };

    let model = model_from_json_value(&response)
        .or_else(|| model_from_json_value(&request))
        .unwrap_or_default();
    let provider = provider_from_turn_payloads(Some(&request), Some(&response));

    let (role, input_tokens, output_tokens, cache_creation, cache_read) = match &response {
        serde_json::Value::Object(_) => {
            let role = response
                .get("role")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_owned();
            let usage = response.get("usage").and_then(|v| v.as_object());
            // Anthropic uses `input_tokens` / `output_tokens`
            // `cache_creation_input_tokens` /
            // `cache_read_input_tokens`. OpenAI uses
            // `prompt_tokens` / `completion_tokens` and does
            // not expose cache-hit counts; map the
            // OpenAI-shape names onto the canonical fields
            // and leave cache_* `None` so the FE's cache
            // ratio falls back to "N/A".
            let input_tokens = usage
                .and_then(|u| {
                    u.get("input_tokens")
                        .or_else(|| u.get("prompt_tokens"))
                        .and_then(|v| v.as_u64())
                })
                .map(|n| n as u32);
            let output_tokens = usage
                .and_then(|u| {
                    u.get("output_tokens")
                        .or_else(|| u.get("completion_tokens"))
                        .and_then(|v| v.as_u64())
                })
                .map(|n| n as u32);
            let cache_creation = usage
                .and_then(|u| {
                    u.get("cache_creation_input_tokens")
                        .and_then(|v| v.as_u64())
                })
                .map(|n| n as u32);
            let cache_read = usage
                .and_then(|u| u.get("cache_read_input_tokens").and_then(|v| v.as_u64()))
                .map(|n| n as u32);
            (
                role,
                input_tokens,
                output_tokens,
                cache_creation,
                cache_read,
            )
        }
        _ => (String::new(), None, None, None, None),
    };

    raxis_dashboard::data::TaskLlmTurnView {
        turn_number,
        ts_unix: r.at_ms / 1000,
        model,
        provider,
        role,
        agent_role: r.agent_role,
        request,
        response,
        input_tokens,
        output_tokens,
        cache_creation_input_tokens: cache_creation,
        cache_read_input_tokens: cache_read,
        latency_ms: Some(r.latency_ms),
        task_id: r.task_id,
        session_id: r.session_id,
        fetch_id: r.fetch_id,
        status_code: r.status_code,
        original_body_bytes: r.original_body_bytes,
        body_truncated: r.body_truncated,
        error: r.error,
    }
}

/// Project a [`SessionCaptureRecord`] (kernel-side) to the
/// dashboard's wire view. `INV-DASHBOARD-SESSION-CAPTURE-
/// PERSIST-AFTER-TERMINATION-01`.
fn session_record_to_view(
    r: crate::SessionCaptureRecord,
) -> raxis_dashboard::data::SessionCaptureView {
    raxis_dashboard::data::SessionCaptureView {
        session_id: r.session_id,
        kind: r.kind,
        ts_unix: r.ts_unix,
        payload: r.payload,
    }
}

/// iter68 — parse a `worktree_snapshots` SQL row into the
/// dashboard wire view. The column order MUST match the SELECT
/// list in `list_worktree_snapshots` / `get_worktree_snapshot`
/// exactly; reordering one without the other is a silent
/// classifier crash at runtime.
fn parse_worktree_snapshot_row(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<raxis_dashboard::data::WorktreeSnapshotView> {
    let diff_truncated_int: i64 = row.get(14)?;
    let diff_bytes_total_int: i64 = row.get(13)?;
    let commit_count_int: i64 = row.get(8)?;
    Ok(raxis_dashboard::data::WorktreeSnapshotView {
        snapshot_id: row.get(0)?,
        task_id: row.get(1)?,
        session_id: row.get(2)?,
        initiative_id: row.get(3)?,
        trigger: row.get(4)?,
        taken_at: row.get(5)?,
        base_sha: row.get(6)?,
        head_sha: row.get(7)?,
        commit_count: commit_count_int.max(0) as u32,
        diff_blob_sha256: row.get(9)?,
        log_blob_sha256: row.get(10)?,
        tree_blob_sha256: row.get(11)?,
        porcelain_blob_sha256: row.get(12)?,
        diff_bytes_total: diff_bytes_total_int.max(0) as u64,
        diff_truncated: diff_truncated_int != 0,
    })
}

fn task_row_to_view(
    conn: &raxis_store::ro::RoConn,
    t: &raxis_store::views::tasks::TaskRow,
) -> Result<TaskView, ApiError> {
    let outputs = raxis_store::views::structured_outputs::list_for_task(conn, &t.task_id)
        .unwrap_or_default()
        .into_iter()
        .map(|o| StructuredOutputView {
            kind: o.kind,
            payload: serde_json::from_str(&o.payload_json).unwrap_or(serde_json::Value::Null),
            at: o.emitted_at.max(0) as u64,
        })
        .collect();
    let plan_fields = if t.task_id == t.initiative_id {
        None
    } else {
        Some(
            raxis_store::views::plan_fields::reveal_for_task(conn, &t.task_id).map_err(|e| {
                ApiError::Internal {
                    log_only: format!("plan_fields::reveal_for_task({}): {e}", t.task_id),
                }
            })?,
        )
    };
    let path_allowlist = plan_fields
        .as_ref()
        .map(|f| f.path_allowlist.clone())
        .unwrap_or_default();
    let max_review_rejections = plan_fields
        .as_ref()
        .map(|f| f.max_review_rejections)
        .unwrap_or(raxis_store::views::plan_fields::DEFAULT_MAX_REVIEW_REJECTIONS);
    let max_crash_retries = plan_fields
        .as_ref()
        .map(|f| f.max_crash_retries)
        .unwrap_or(raxis_store::views::plan_fields::DEFAULT_MAX_CRASH_RETRIES);
    let retry_counts = read_retry_counts_for_task(conn, &t.task_id);
    let agent_type = if t.task_id == t.initiative_id {
        "Orchestrator".to_owned()
    } else {
        plan_fields
            .as_ref()
            .map(|f| f.session_agent_type.clone())
            .unwrap_or_else(|| "Executor".to_owned())
    };
    let initiative_display_name = initiative_name_for_id(conn, &t.initiative_id)?;
    // `is_active` mirrors whether there's any `Active`
    // `subtask_activations` row bound to this task. The FE renders
    // this as the dashboard's "really running" signal even when
    // `tasks.state` has flickered to `Admitted` between VM hops —
    // see `TaskView::is_active` doc.
    let is_active: bool = conn
        .query_row(
            &format!(
                "SELECT 1 FROM {TBL_SUBTASK_ACTIVATIONS} \
                 WHERE task_id = ?1 AND activation_state = 'Active' \
                 LIMIT 1"
            ),
            rusqlite::params![&t.task_id],
            |_| Ok(true),
        )
        .unwrap_or(false);
    // INV-DASHBOARD-INTEGRATION-MERGE-VISIBLE-OR-EXCLUDED-01:
    // detect the synthetic coordinator row by the
    // `task_id == initiative_id` predicate and stamp a stable
    // human title. The detection is exact — sub-task ids are
    // operator-authored strings and live in a disjoint space
    // from UUID-shaped initiative ids by construction
    // (`initiatives::lifecycle::auto_spawn_orchestrator_session_in_tx`
    // doc comment §"task_id == initiative_id by construction").
    let title = task_display_title(&t.task_id, &t.initiative_id);
    Ok(TaskView {
        task_id: t.task_id.clone(),
        initiative_id: t.initiative_id.clone(),
        initiative_display_name,
        agent_type,
        title,
        state: t.state.clone(),
        session_id: t.session_id.clone(),
        reviewer_verdicts: Vec::<ReviewerVerdictView>::new(),
        structured_outputs: outputs,
        path_allowlist,
        created_at: t.admitted_at,
        updated_at: t.transitioned_at,
        // INV-DASHBOARD-FAILURE-VISIBILITY-01: V2.5 ships the
        // wire shape; the kernel-side projection that walks the
        // audit chain for the matching `TaskBlockedForRecovery` /
        // `WitnessRejected` / `VerifierProcessFailed` row lands
        // in V3. Until then `None` here causes the FE to render
        // "No reason supplied — kernel bug" so the gap is visible.
        failure: None,
        blocked_downstream: Vec::new(),
        // Lifecycle annotations are populated lazily by the
        // detail / list paths that own the audit chain handle.
        // The list-of-tasks under an initiative populates them
        // via `task_row_to_view_with_lifecycle` so the global
        // index gets `latest_annotation` without re-reading
        // audit per row.
        annotations: Vec::new(),
        latest_annotation: None,
        review_verdict: None,
        last_critique: None,
        reviewer_panel_results: Vec::new(),
        review_reject_count: retry_counts.review_reject_count,
        max_review_rejections,
        review_retry_exhausted: false,
        crash_retry_count: retry_counts.crash_retry_count,
        max_crash_retries,
        is_active,
    })
}

/// Lifecycle-aware projection used by `get_task` /
/// `list_tasks` / `get_initiative` so the FE renders structured
/// retry / revoke / block cards without making the operator
/// hand-correlate audit seq numbers.
///
/// The audit chain `audit_chain` is shared across calls in the
/// same HTTP request — the caller pre-loads it via
/// [`collect_lifecycle_audit_rows`] so a multi-task initiative
/// page does not re-walk the chain per row.
fn task_row_to_view_with_lifecycle(
    conn: &raxis_store::ro::RoConn,
    audit_chain: &[lifecycle::AuditRow],
    t: &raxis_store::views::tasks::TaskRow,
) -> Result<TaskView, ApiError> {
    let mut view = task_row_to_view(conn, t)?;
    let activations = read_activations_for_task(conn, &t.task_id);
    let (own_review_verdict, own_last_critique) = read_review_state(conn, &t.task_id);
    let mut reviewer_verdicts = read_reviewer_verdicts_for_task(conn, &t.task_id);
    if reviewer_verdicts.is_empty() {
        if let Some(verdict) = own_review_verdict.clone() {
            reviewer_verdicts.push(ReviewerVerdictView {
                verdict,
                critique: own_last_critique.clone().unwrap_or_default(),
                reviewer_task_id: t.task_id.clone(),
                reviewer_session_id: t.session_id.clone().unwrap_or_default(),
                at: t.transitioned_at,
            });
        }
    }
    let (review_verdict, last_critique) =
        aggregate_review_state(own_review_verdict, own_last_critique, &reviewer_verdicts);
    let annotations = lifecycle::classify_for_task(
        audit_chain,
        &t.task_id,
        &activations,
        last_critique.as_deref(),
    );
    let latest = annotations.last().cloned();
    let mut panel = extract_reviewer_panel_results(audit_chain, &t.task_id);
    if panel.is_empty() {
        panel = reviewer_panel_entries_from_verdicts(&reviewer_verdicts);
    }
    view.annotations = annotations;
    view.latest_annotation = latest;
    view.review_retry_exhausted = review_retry_exhausted(
        review_verdict.as_deref(),
        view.review_reject_count,
        view.max_review_rejections,
    );
    view.review_verdict = review_verdict;
    view.last_critique = last_critique;
    view.reviewer_verdicts = reviewer_verdicts;
    view.reviewer_panel_results = panel;
    Ok(view)
}

/// Indexed variant for list surfaces. The DB lookups stay
/// task-scoped, but audit-chain work is O(rows) once per request
/// instead of O(rows × tasks).
fn task_row_to_view_with_lifecycle_indexed(
    conn: &raxis_store::ro::RoConn,
    audit_index: &LifecycleAuditIndex<'_>,
    t: &raxis_store::views::tasks::TaskRow,
) -> Result<TaskView, ApiError> {
    let mut view = task_row_to_view(conn, t)?;
    let activations = read_activations_for_task(conn, &t.task_id);
    let (own_review_verdict, own_last_critique) = read_review_state(conn, &t.task_id);
    let mut reviewer_verdicts = read_reviewer_verdicts_for_task(conn, &t.task_id);
    if reviewer_verdicts.is_empty() {
        if let Some(verdict) = own_review_verdict.clone() {
            reviewer_verdicts.push(ReviewerVerdictView {
                verdict,
                critique: own_last_critique.clone().unwrap_or_default(),
                reviewer_task_id: t.task_id.clone(),
                reviewer_session_id: t.session_id.clone().unwrap_or_default(),
                at: t.transitioned_at,
            });
        }
    }
    let (review_verdict, last_critique) =
        aggregate_review_state(own_review_verdict, own_last_critique, &reviewer_verdicts);
    let annotations = lifecycle::classify_for_task_rows(
        audit_index.task_rows(&t.task_id),
        &t.task_id,
        &activations,
        last_critique.as_deref(),
    );
    let latest = annotations.last().cloned();
    let mut panel =
        extract_reviewer_panel_results_from_rows(audit_index.reviewer_panel_rows(&t.task_id));
    if panel.is_empty() {
        panel = reviewer_panel_entries_from_verdicts(&reviewer_verdicts);
    }
    view.annotations = annotations;
    view.latest_annotation = latest;
    view.review_retry_exhausted = review_retry_exhausted(
        review_verdict.as_deref(),
        view.review_reject_count,
        view.max_review_rejections,
    );
    view.review_verdict = review_verdict;
    view.last_critique = last_critique;
    view.reviewer_verdicts = reviewer_verdicts;
    view.reviewer_panel_results = panel;
    Ok(view)
}

/// Lifecycle-aware projection for [`SessionView`]. Mirrors
/// [`task_row_to_view_with_lifecycle`] for the per-session
/// timeline (operator-revoke vs self-exit, initiative-block).
fn enrich_session_view_with_lifecycle(
    audit_chain: &[lifecycle::AuditRow],
    mut view: SessionView,
) -> SessionView {
    let annotations = lifecycle::classify_for_session(audit_chain, &view.session_id);
    view.latest_annotation = annotations.last().cloned();
    view.annotations = annotations;
    view
}

/// Indexed variant for session list/recent surfaces.
fn enrich_session_view_with_lifecycle_indexed(
    audit_index: &LifecycleAuditIndex<'_>,
    mut view: SessionView,
) -> SessionView {
    let annotations =
        lifecycle::classify_for_session_rows(audit_index.session_rows(&view.session_id));
    view.latest_annotation = annotations.last().cloned();
    view.annotations = annotations;
    view
}

// ---------------------------------------------------------------------------
// Lifecycle annotation helpers
// (INV-DASHBOARD-LIFECYCLE-CAUSALITY-01 — paired with Worker 1)
// ---------------------------------------------------------------------------

/// Walk every audit chain segment and project rows into the
/// classifier-friendly [`lifecycle::AuditRow`] shape, capped at
/// `MAX_AUDIT_WALK_RECORDS` so a runaway chain cannot pin a
/// request thread. The walker returns rows in chain `seq`
/// order — the classifier resorts as needed.
///
/// The walk is deliberately not filtered at the I/O layer: the
/// classifier expects a session-or-task-scoped slice, but a
/// `task_id` filter at the segment-iterator level would scan the
/// chain twice for `(get_task, get_session)` co-renders. We pull
/// once per HTTP request and let the (cheap) Rust-side filter on
/// `task_id` / `session_id` do the narrowing.
fn collect_lifecycle_audit_rows(audit_dir: &Path) -> Vec<lifecycle::AuditRow> {
    const MAX_AUDIT_WALK_RECORDS: usize = 200_000;
    let Ok(reader) = ChainReader::open(audit_dir) else {
        return Vec::new();
    };
    let mut out: Vec<lifecycle::AuditRow> = Vec::new();
    let mut walked: usize = 0;
    for rec in reader.records() {
        walked += 1;
        if walked > MAX_AUDIT_WALK_RECORDS {
            eprintln!(
                "{{\"level\":\"warn\",\
                  \"event\":\"dashboard_lifecycle_audit_walk_capped\",\
                  \"limit_records\":{MAX_AUDIT_WALK_RECORDS}}}"
            );
            break;
        }
        let Ok(rec) = rec else { continue };
        let payload = rec
            .parsed_value
            .as_ref()
            .and_then(|v| v.get("payload").cloned())
            .unwrap_or(serde_json::Value::Null);
        out.push(lifecycle::AuditRow {
            seq: rec.seq,
            event_kind: rec.event_kind,
            initiative_id: rec.initiative_id,
            task_id: rec.task_id,
            session_id: rec.session_id,
            at: rec.emitted_at.unwrap_or(0),
            payload,
        });
    }
    out
}

/// Per-request index over lifecycle audit rows.
///
/// `collect_lifecycle_audit_rows` already pays the I/O cost once;
/// this index keeps list endpoints from repeatedly scanning and
/// sorting the same in-memory chain for each task/session row.
struct LifecycleAuditIndex<'a> {
    by_task: std::collections::HashMap<&'a str, Vec<&'a lifecycle::AuditRow>>,
    by_session: std::collections::HashMap<&'a str, Vec<&'a lifecycle::AuditRow>>,
    reviewer_panel_by_executor: std::collections::HashMap<&'a str, Vec<&'a lifecycle::AuditRow>>,
}

impl<'a> LifecycleAuditIndex<'a> {
    fn new(chain: &'a [lifecycle::AuditRow]) -> Self {
        let mut out = Self {
            by_task: std::collections::HashMap::new(),
            by_session: std::collections::HashMap::new(),
            reviewer_panel_by_executor: std::collections::HashMap::new(),
        };
        for row in chain {
            if let Some(task_id) = row.task_id.as_deref() {
                Self::push_dedup(&mut out.by_task, task_id, row);
            }
            for key in ["task_id", "parent_task_id", "fixup_task_id"] {
                if let Some(task_id) = payload_str(row, key) {
                    Self::push_dedup(&mut out.by_task, task_id, row);
                }
            }
            if let Some(session_id) = row.session_id.as_deref() {
                Self::push_dedup(&mut out.by_session, session_id, row);
            }
            if let Some(executor_task_id) = payload_str(row, "executor_task_id") {
                Self::push_dedup(&mut out.reviewer_panel_by_executor, executor_task_id, row);
            }
        }
        out
    }

    fn task_rows(&self, task_id: &str) -> &[&'a lifecycle::AuditRow] {
        self.by_task.get(task_id).map(Vec::as_slice).unwrap_or(&[])
    }

    fn session_rows(&self, session_id: &str) -> &[&'a lifecycle::AuditRow] {
        self.by_session
            .get(session_id)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    fn reviewer_panel_rows(&self, executor_task_id: &str) -> &[&'a lifecycle::AuditRow] {
        self.reviewer_panel_by_executor
            .get(executor_task_id)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    fn push_dedup(
        map: &mut std::collections::HashMap<&'a str, Vec<&'a lifecycle::AuditRow>>,
        key: &'a str,
        row: &'a lifecycle::AuditRow,
    ) {
        let rows = map.entry(key).or_default();
        if rows.last().map(|prev| prev.seq) != Some(row.seq) {
            rows.push(row);
        }
    }
}

fn payload_str<'a>(row: &'a lifecycle::AuditRow, key: &str) -> Option<&'a str> {
    row.payload.get(key).and_then(|v| v.as_str())
}

/// Read `tasks.review_verdict` and `tasks.last_critique` for the
/// given task id. Both columns are migration-6/-7 additions; an
/// older DB silently returns `(None, None)`.
fn read_review_state(
    conn: &raxis_store::ro::RoConn,
    task_id: &str,
) -> (Option<String>, Option<String>) {
    let row = conn.query_row(
        &format!("SELECT review_verdict, last_critique FROM {TBL_TASKS} WHERE task_id = ?1"),
        [task_id],
        |r| {
            let v: Option<String> = r.get(0)?;
            let c: Option<String> = r.get(1)?;
            Ok((v, c))
        },
    );
    row.unwrap_or((None, None))
}

#[derive(Debug, Clone, Copy, Default)]
struct RetryCounts {
    review_reject_count: u32,
    crash_retry_count: u32,
}

fn read_retry_counts_for_task(conn: &raxis_store::ro::RoConn, task_id: &str) -> RetryCounts {
    let row = conn.query_row(
        &format!(
            "SELECT COALESCE(MAX(review_reject_count), 0), \
                    COALESCE(MAX(crash_retry_count), 0) \
             FROM {TBL_SUBTASK_ACTIVATIONS} WHERE task_id = ?1"
        ),
        [task_id],
        |r| {
            let review: i64 = r.get(0)?;
            let crash: i64 = r.get(1)?;
            Ok(RetryCounts {
                review_reject_count: review.max(0) as u32,
                crash_retry_count: crash.max(0) as u32,
            })
        },
    );
    row.unwrap_or_default()
}

fn aggregate_review_state(
    own_verdict: Option<String>,
    own_critique: Option<String>,
    reviewer_verdicts: &[ReviewerVerdictView],
) -> (Option<String>, Option<String>) {
    if own_verdict.is_some() {
        return (own_verdict, own_critique);
    }
    if reviewer_verdicts.is_empty() {
        return (None, own_critique);
    }
    if let Some(rejected) = reviewer_verdicts
        .iter()
        .rev()
        .find(|v| is_rejected_review_verdict(&v.verdict))
    {
        let critique = own_critique.or_else(|| {
            let trimmed = rejected.critique.trim();
            (!trimmed.is_empty()).then(|| rejected.critique.clone())
        });
        return (Some("Rejected".to_owned()), critique);
    }
    if reviewer_verdicts
        .iter()
        .all(|v| is_approved_review_verdict(&v.verdict))
    {
        let critique = own_critique.or_else(|| {
            reviewer_verdicts
                .iter()
                .rev()
                .map(|v| v.critique.trim())
                .find(|c| !c.is_empty())
                .map(str::to_owned)
        });
        return (Some("Approved".to_owned()), critique);
    }
    (None, own_critique)
}

fn review_retry_exhausted(
    verdict: Option<&str>,
    review_reject_count: u32,
    max_review_rejections: u32,
) -> bool {
    verdict.map(is_rejected_review_verdict).unwrap_or(false)
        && max_review_rejections > 0
        && review_reject_count >= max_review_rejections
}

fn is_rejected_review_verdict(verdict: &str) -> bool {
    matches!(
        verdict.trim().to_ascii_lowercase().as_str(),
        "rejected" | "reject" | "atleastonerejected"
    )
}

fn is_approved_review_verdict(verdict: &str) -> bool {
    matches!(
        verdict.trim().to_ascii_lowercase().as_str(),
        "approved" | "approve"
    )
}

/// Read the concrete downstream reviewer tasks for an executor task.
/// `tasks.review_verdict` is stored on the reviewer row itself, while
/// the executor row carries only the aggregate critique. Joining
/// through the DAG makes completed reviewer verdicts visible on the
/// executor task page instead of rendering a misleading empty panel.
fn read_reviewer_verdicts_for_task(
    conn: &raxis_store::ro::RoConn,
    task_id: &str,
) -> Vec<ReviewerVerdictView> {
    let mut out = Vec::new();
    let Ok(mut stmt) = conn.prepare(&format!(
        "SELECT rt.review_verdict, COALESCE(rt.last_critique, ''), \
                rt.task_id, \
                COALESCE(rt.session_id, ''), rt.transitioned_at \
         FROM {TBL_TASK_DAG_EDGES} e \
         JOIN {TBL_TASKS} rt ON rt.task_id = e.successor_task_id \
         WHERE e.predecessor_task_id = ?1 \
           AND rt.review_verdict IS NOT NULL \
         ORDER BY rt.transitioned_at ASC, rt.task_id ASC"
    )) else {
        return out;
    };
    let rows = stmt.query_map([task_id], |r| {
        Ok(ReviewerVerdictView {
            verdict: r.get(0)?,
            critique: r.get(1)?,
            reviewer_task_id: r.get(2)?,
            reviewer_session_id: r.get(3)?,
            at: r.get::<_, i64>(4)?.max(0) as u64,
        })
    });
    if let Ok(rows) = rows {
        for row in rows.flatten() {
            out.push(row);
        }
    }
    out
}

/// Read every `subtask_activations` row for `task_id` and
/// project to the classifier's [`lifecycle::ActivationRow`].
fn read_activations_for_task(
    conn: &raxis_store::ro::RoConn,
    task_id: &str,
) -> Vec<lifecycle::ActivationRow> {
    let mut out: Vec<lifecycle::ActivationRow> = Vec::new();
    let Ok(mut stmt) = conn.prepare(&format!(
        "SELECT activation_id, task_id, activation_state, created_at, \
                COALESCE(crash_retry_count, 0), \
                COALESCE(review_reject_count, 0), \
                COALESCE(validation_reject_count, 0), \
                COALESCE(max_validation_rejections, 3) \
             FROM {TBL_SUBTASK_ACTIVATIONS} WHERE task_id = ?1 ORDER BY created_at ASC"
    )) else {
        return out;
    };
    let rows = stmt.query_map([task_id], |r| {
        Ok(lifecycle::ActivationRow {
            activation_id: r.get(0)?,
            task_id: r.get(1)?,
            activation_state: r.get(2)?,
            created_at: r.get::<_, i64>(3)?,
            crash_retry_count: r.get::<_, i64>(4)?.max(0) as u32,
            review_reject_count: r.get::<_, i64>(5)?.max(0) as u32,
            validation_reject_count: r.get::<_, i64>(6)?.max(0) as u32,
            max_validation_rejections: r.get::<_, i64>(7)?.max(0) as u32,
        })
    });
    if let Ok(rows) = rows {
        for row in rows.flatten() {
            out.push(row);
        }
    }
    out
}

/// Read every `subtask_activations` row across the database and
/// project to the classifier's shape. Used by
/// `list_orchestrator_gaps` where the gap detector needs the
/// global `PendingActivation` set.
fn read_activations_all(conn: &raxis_store::ro::RoConn) -> Vec<lifecycle::ActivationRow> {
    let mut out: Vec<lifecycle::ActivationRow> = Vec::new();
    let Ok(mut stmt) = conn.prepare(&format!(
        "SELECT activation_id, task_id, activation_state, created_at, \
                COALESCE(crash_retry_count, 0), \
                COALESCE(review_reject_count, 0), \
                COALESCE(validation_reject_count, 0), \
                COALESCE(max_validation_rejections, 3) \
             FROM {TBL_SUBTASK_ACTIVATIONS} ORDER BY created_at ASC"
    )) else {
        return out;
    };
    let rows = stmt.query_map([], |r| {
        Ok(lifecycle::ActivationRow {
            activation_id: r.get(0)?,
            task_id: r.get(1)?,
            activation_state: r.get(2)?,
            created_at: r.get::<_, i64>(3)?,
            crash_retry_count: r.get::<_, i64>(4)?.max(0) as u32,
            review_reject_count: r.get::<_, i64>(5)?.max(0) as u32,
            validation_reject_count: r.get::<_, i64>(6)?.max(0) as u32,
            max_validation_rejections: r.get::<_, i64>(7)?.max(0) as u32,
        })
    });
    if let Ok(rows) = rows {
        for row in rows.flatten() {
            out.push(row);
        }
    }
    out
}

/// Project every `tasks` row into the classifier's
/// [`lifecycle::TaskRow`]. The DAG edges are read via
/// `task_dag_edges` joined into `predecessors`. `completed_at`
/// is populated from `tasks.transitioned_at` when the task is in
/// a `Completed` state.
fn read_tasks_with_predecessors(conn: &raxis_store::ro::RoConn) -> Vec<lifecycle::TaskRow> {
    let mut out: Vec<lifecycle::TaskRow> = Vec::new();
    let mut predecessors_by_successor = read_predecessors_by_successor(conn);
    let Ok(mut stmt) = conn.prepare(&format!(
        "SELECT task_id, state, transitioned_at FROM {TBL_TASKS}"
    )) else {
        return out;
    };
    let rows = stmt.query_map([], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, i64>(2)?,
        ))
    });
    if let Ok(rows) = rows {
        for row in rows.flatten() {
            let (task_id, state, transitioned_at) = row;
            let completed_at = if state == "Completed" {
                Some(transitioned_at)
            } else {
                None
            };
            let preds = predecessors_by_successor
                .remove(&task_id)
                .unwrap_or_default();
            out.push(lifecycle::TaskRow {
                task_id,
                state,
                predecessors: preds,
                completed_at,
            });
        }
    }
    out
}

/// Read every DAG predecessor edge in one pass and group by
/// successor. This keeps the orchestrator-gap dashboard endpoint
/// from doing one SQLite query per task while preserving stable
/// predecessor ordering inside each task.
fn read_predecessors_by_successor(
    conn: &raxis_store::ro::RoConn,
) -> std::collections::HashMap<String, Vec<String>> {
    let mut out: std::collections::HashMap<String, Vec<String>> = std::collections::HashMap::new();
    let Ok(mut stmt) = conn.prepare(&format!(
        "SELECT successor_task_id, predecessor_task_id \
         FROM {TBL_TASK_DAG_EDGES} \
         ORDER BY successor_task_id ASC, predecessor_task_id ASC"
    )) else {
        return out;
    };
    let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)));
    if let Ok(rows) = rows {
        for row in rows.flatten() {
            let (successor, predecessor) = row;
            out.entry(successor).or_default().push(predecessor);
        }
    }
    out
}

#[derive(Debug, Clone)]
struct PlanDraftTask {
    id: String,
    agent_type: String,
    predecessors: Vec<String>,
}

fn validate_plan_draft_with_policy(
    toml_text: &str,
    policy: &PolicyBundle,
) -> BuilderValidationResponse {
    let mut issues = Vec::new();
    let mut resolved_target_ref = None;
    let parsed = match toml_text.parse::<toml::Value>() {
        Ok(value) => value,
        Err(e) => {
            issues.push(builder_issue(
                BuilderValidationSeverity::Error,
                "PLAN_TOML_PARSE",
                "plan.toml is not valid TOML.",
                format!("Fix the TOML syntax error before submitting: {e}"),
            ));
            return builder_response("plan", policy.epoch(), None, issues, plan_next_steps());
        }
    };

    let Some(root) = parsed.as_table() else {
        issues.push(builder_issue(
            BuilderValidationSeverity::Error,
            "PLAN_ROOT",
            "plan.toml must be a TOML table.",
            "Use [plan.initiative], [workspace], and one or more [[tasks]] blocks.",
        ));
        return builder_response("plan", policy.epoch(), None, issues, plan_next_steps());
    };

    if table_path(root, &["plan", "initiative"])
        .and_then(|v| v.as_table())
        .and_then(|t| string_field(t, "description"))
        .is_none_or(str::is_empty)
    {
        issues.push(builder_issue(
            BuilderValidationSeverity::Error,
            "PLAN_INITIATIVE_DESCRIPTION",
            "[plan.initiative].description is required.",
            "Add a short operator-facing summary of the initiative.",
        ));
    }

    let workspace = root.get("workspace").and_then(|v| v.as_table());
    match workspace.and_then(|t| string_field(t, "name")) {
        Some(name) if !name.is_empty() => {}
        _ => issues.push(builder_issue(
            BuilderValidationSeverity::Error,
            "PLAN_WORKSPACE_NAME",
            "[workspace].name is required.",
            "Name the workspace so operators can recognize it in the dashboard.",
        )),
    }
    match workspace.and_then(|t| string_field(t, "lane_id")) {
        Some(lane) if policy.lane_config(lane).is_some() => {}
        Some(lane) if !lane.is_empty() => issues.push(builder_issue(
            BuilderValidationSeverity::Warning,
            "PLAN_UNKNOWN_LANE",
            format!("lane_id {lane:?} is not present in the active policy."),
            "Add the lane in Policy Builder and advance the policy epoch, or choose an existing lane.",
        )),
        _ => issues.push(builder_issue(
            BuilderValidationSeverity::Error,
            "PLAN_WORKSPACE_LANE",
            "[workspace].lane_id is required.",
            "Use a lane_id from the active policy, commonly \"default\".",
        )),
    }
    if let Some(repository) = workspace.and_then(|t| string_field(t, "repository")) {
        if !is_path_safe_id(repository) {
            issues.push(builder_issue(
                BuilderValidationSeverity::Error,
                "PLAN_REPOSITORY_ID",
                "repository must be a path-safe id.",
                "Use the actual repository name, like acme-api, frontend, or docs; avoid slashes and spaces.",
            ));
        }
    }
    let target_ref = workspace
        .and_then(|t| string_field(t, "target_ref"))
        .unwrap_or_else(|| policy.git_default_target_ref());
    if let Err(reason) = raxis_policy::validate_target_ref_format(target_ref) {
        issues.push(builder_issue(
            BuilderValidationSeverity::Error,
            "PLAN_TARGET_REF",
            format!("target_ref {target_ref:?} is invalid."),
            format!("Use a branch ref such as refs/heads/main. Details: {reason}"),
        ));
    } else {
        resolved_target_ref = Some(target_ref.to_owned());
    }
    if policy.git_target_ref_locked() && target_ref != policy.git_default_target_ref() {
        issues.push(builder_issue(
            BuilderValidationSeverity::Error,
            "PLAN_TARGET_REF_LOCKED",
            "The active policy locks target_ref overrides.",
            format!(
                "Use {} or advance policy with [git].target_ref_locked = false.",
                policy.git_default_target_ref()
            ),
        ));
    }

    let tasks = root.get("tasks").and_then(|v| v.as_array());
    let Some(tasks) = tasks.filter(|arr| !arr.is_empty()) else {
        issues.push(builder_issue(
            BuilderValidationSeverity::Error,
            "PLAN_TASKS_REQUIRED",
            "At least one [[tasks]] block is required.",
            "Add an Executor task, or an Executor plus Reviewer pair.",
        ));
        return builder_response(
            "plan",
            policy.epoch(),
            resolved_target_ref,
            issues,
            plan_next_steps(),
        );
    };

    let mut task_drafts = Vec::with_capacity(tasks.len());
    let mut seen = std::collections::HashSet::new();
    for (idx, task_value) in tasks.iter().enumerate() {
        let Some(task) = task_value.as_table() else {
            issues.push(builder_issue(
                BuilderValidationSeverity::Error,
                "PLAN_TASK_TABLE",
                format!("tasks[{idx}] is not a table."),
                "Use [[tasks]] table blocks for every task.",
            ));
            continue;
        };
        let id = string_field(task, "task_id").unwrap_or_default().to_owned();
        if id.is_empty() {
            issues.push(builder_issue(
                BuilderValidationSeverity::Error,
                "PLAN_TASK_ID",
                format!("tasks[{idx}] is missing task_id."),
                "Add a stable task_id such as implement-auth or review-auth.",
            ));
        } else {
            if !is_task_id(&id) {
                issues.push(builder_issue(
                    BuilderValidationSeverity::Error,
                    "PLAN_TASK_ID_FORMAT",
                    format!("task_id {id:?} has an invalid shape."),
                    "Start with a letter and use only letters, digits, underscores, and hyphens.",
                ));
            }
            if !seen.insert(id.clone()) {
                issues.push(builder_issue(
                    BuilderValidationSeverity::Error,
                    "PLAN_TASK_ID_DUPLICATE",
                    format!("task_id {id:?} appears more than once."),
                    "Rename one task so every task_id is unique.",
                ));
            }
        }
        let agent_type = string_field(task, "session_agent_type").unwrap_or_default();
        match agent_type {
            "Executor" | "Reviewer" => {}
            "Orchestrator" => issues.push(builder_issue(
                BuilderValidationSeverity::Error,
                "PLAN_ORCHESTRATOR_DECLARED",
                "Do not declare Orchestrator tasks.",
                "The kernel creates the Orchestrator automatically; remove this task or change it to Executor/Reviewer.",
            )),
            _ => issues.push(builder_issue(
                BuilderValidationSeverity::Error,
                "PLAN_AGENT_TYPE",
                format!("task {id:?} must use session_agent_type Executor or Reviewer."),
                "Choose Executor for file changes or Reviewer for review-only work.",
            )),
        }
        if string_field(task, "description").is_none_or(str::is_empty) {
            issues.push(builder_issue(
                BuilderValidationSeverity::Error,
                "PLAN_TASK_DESCRIPTION",
                format!("task {id:?} is missing description."),
                "Add a short dashboard-facing description.",
            ));
        }
        if task.contains_key("context") {
            issues.push(builder_issue(
                BuilderValidationSeverity::Error,
                "PLAN_CONTEXT_DEPRECATED",
                format!("task {id:?} uses deprecated context."),
                "Move the main instruction into prompt; keep description as the short summary.",
            ));
        }
        if string_field(task, "prompt").is_none_or(str::is_empty) {
            issues.push(builder_issue(
                BuilderValidationSeverity::Warning,
                "PLAN_TASK_PROMPT",
                format!("task {id:?} has no prompt."),
                "Add prompt for the executor/reviewer instruction; description should stay brief.",
            ));
        }
        let clone_strategy = string_field(task, "clone_strategy").unwrap_or_default();
        if !matches!(clone_strategy, "blobless" | "full" | "sparse") {
            issues.push(builder_issue(
                BuilderValidationSeverity::Error,
                "PLAN_CLONE_STRATEGY",
                format!("task {id:?} has an invalid clone_strategy."),
                "Use blobless, sparse, or full.",
            ));
        }
        let paths = string_array_field(task, "path_allowlist", &id, &mut issues);
        let allowed_egress = string_array_field(task, "allowed_egress", &id, &mut issues);
        if agent_type == "Executor" && paths.is_empty() {
            issues.push(builder_issue(
                BuilderValidationSeverity::Error,
                "PLAN_EXECUTOR_PATHS",
                format!("Executor task {id:?} needs path_allowlist."),
                "Keep it narrow: exact files or directory prefixes such as src/api/.",
            ));
        }
        if agent_type == "Reviewer" {
            if task.contains_key("vm_image") {
                issues.push(builder_issue(
                    BuilderValidationSeverity::Error,
                    "PLAN_REVIEWER_VM_IMAGE",
                    format!("Reviewer task {id:?} cannot declare vm_image."),
                    "Remove vm_image; reviewer images are kernel-canonical.",
                ));
            }
            if !allowed_egress.is_empty() {
                issues.push(builder_issue(
                    BuilderValidationSeverity::Warning,
                    "PLAN_REVIEWER_EGRESS",
                    format!("Reviewer task {id:?} declares allowed_egress."),
                    "Remove reviewer egress; reviewers have no network device.",
                ));
            }
        }
        for field in [
            "max_turns",
            "max_turns_step",
            "cumulative_max_seconds",
            "min_vcpus",
            "max_vcpus",
            "min_memory_mb",
            "max_memory_mb",
        ] {
            if let Some(value) = task.get(field) {
                match value.as_integer() {
                    Some(n) if n > 0 => {}
                    _ => issues.push(builder_issue(
                        BuilderValidationSeverity::Error,
                        "PLAN_POSITIVE_INTEGER",
                        format!("task {id:?} field {field} must be a positive integer."),
                        "Use a whole number greater than zero or remove the field.",
                    )),
                }
            }
        }
        let predecessors = string_array_field(task, "predecessors", &id, &mut issues);
        task_drafts.push(PlanDraftTask {
            id,
            agent_type: agent_type.to_owned(),
            predecessors,
        });
    }

    validate_task_dag(&task_drafts, &mut issues);
    if !task_drafts.iter().any(|t| t.agent_type == "Reviewer") {
        issues.push(builder_issue(
            BuilderValidationSeverity::Info,
            "PLAN_NO_REVIEWER",
            "This plan has no Reviewer task.",
            "That can be fine for trivial work; add a Reviewer for production changes.",
        ));
    }

    builder_response(
        "plan",
        policy.epoch(),
        resolved_target_ref,
        issues,
        plan_next_steps(),
    )
}

fn validate_policy_draft_with_loader(
    toml_text: &str,
    active_policy: &PolicyBundle,
    operator_fingerprint: &str,
) -> BuilderValidationResponse {
    let mut issues = Vec::new();
    if toml_text.trim().is_empty() {
        issues.push(builder_issue(
            BuilderValidationSeverity::Error,
            "POLICY_EMPTY",
            "policy.toml is empty.",
            "Load the current policy or paste a complete policy.toml before validating.",
        ));
        return builder_response(
            "policy",
            active_policy.epoch(),
            None,
            issues,
            policy_next_steps(),
        );
    }
    match toml_text.parse::<toml::Value>() {
        Ok(value) => {
            let new_epoch = value
                .as_table()
                .and_then(|root| table_path(root, &["meta"]))
                .and_then(|meta| meta.as_table())
                .and_then(|meta| meta.get("epoch"))
                .and_then(|epoch| epoch.as_integer())
                .and_then(|epoch| u64::try_from(epoch).ok());
            match new_epoch {
                Some(epoch) if epoch > active_policy.epoch() => {}
                Some(epoch) => issues.push(builder_issue(
                    BuilderValidationSeverity::Error,
                    "POLICY_EPOCH_NOT_FORWARD",
                    format!(
                        "policy epoch {epoch} is not greater than active epoch {}.",
                        active_policy.epoch()
                    ),
                    "Bump [meta].epoch before signing and advancing the policy.",
                )),
                None => issues.push(builder_issue(
                    BuilderValidationSeverity::Error,
                    "POLICY_EPOCH_MISSING",
                    "[meta].epoch is missing or invalid.",
                    "Set [meta].epoch to a number greater than the active policy epoch.",
                )),
            }
        }
        Err(e) => issues.push(builder_issue(
            BuilderValidationSeverity::Error,
            "POLICY_TOML_PARSE",
            "policy.toml is not valid TOML.",
            format!("Fix the TOML syntax error before signing: {e}"),
        )),
    }

    let path = std::env::temp_dir().join(format!(
        "raxis-policy-builder-{}-{}.toml",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    match std::fs::write(&path, toml_text.as_bytes()) {
        Ok(()) => {
            match raxis_policy::load_policy(&path) {
                Ok((_bundle, _raw, _sha)) => {}
                Err(e) => issues.push(builder_issue(
                    BuilderValidationSeverity::Error,
                    "POLICY_LOAD",
                    "raxis-policy rejected this policy.toml.",
                    format!("Fix the loader error before signing: {e}"),
                )),
            }
            let _ = std::fs::remove_file(&path);
        }
        Err(e) => issues.push(builder_issue(
            BuilderValidationSeverity::Error,
            "POLICY_VALIDATE_IO",
            "The dashboard could not stage the draft for validation.",
            format!("Retry validation. If it persists, check host temp-dir permissions: {e}"),
        )),
    }

    if let Some(entry) = active_policy.operator_entry(operator_fingerprint) {
        let has_rotate = entry.permitted_ops.iter().any(|op| op == "RotateEpoch");
        let has_cert_install = entry
            .permitted_ops
            .iter()
            .any(|op| op == "OperatorCertInstall");
        if has_rotate && !has_cert_install {
            issues.push(builder_issue(
                BuilderValidationSeverity::Warning,
                "POLICY_OPERATOR_NOT_ADMIN",
                "Your operator can advance policy but is not a dashboard admin.",
                "Grant both RotateEpoch and OperatorCertInstall for admin-only dashboard actions such as credential reveal.",
            ));
        }
    }

    builder_response(
        "policy",
        active_policy.epoch(),
        None,
        issues,
        policy_next_steps(),
    )
}

fn builder_response(
    artifact_kind: &str,
    policy_epoch: u64,
    resolved_target_ref: Option<String>,
    issues: Vec<BuilderValidationIssue>,
    next_steps: Vec<String>,
) -> BuilderValidationResponse {
    let ok = !issues
        .iter()
        .any(|i| matches!(i.severity, BuilderValidationSeverity::Error));
    BuilderValidationResponse {
        artifact_kind: artifact_kind.to_owned(),
        authority: "kernel".to_owned(),
        policy_epoch,
        resolved_target_ref,
        ok,
        issues,
        next_steps,
    }
}

fn builder_issue(
    severity: BuilderValidationSeverity,
    code: impl Into<String>,
    message: impl Into<String>,
    remediation: impl Into<String>,
) -> BuilderValidationIssue {
    BuilderValidationIssue {
        code: code.into(),
        severity,
        message: message.into(),
        remediation: remediation.into(),
    }
}

fn plan_next_steps() -> Vec<String> {
    vec![
        "raxis plan validate plan.toml".to_owned(),
        "raxis submit plan plan.toml --no-dry-run".to_owned(),
        "raxis plan approve <initiative_id>".to_owned(),
    ]
}

fn policy_next_steps() -> Vec<String> {
    vec![
        r#"raxis policy sign "$RAXIS_DATA_DIR/policy/policy.toml" --key "$RAXIS_DATA_DIR/keys/authority_keypair.pem""#.to_owned(),
        r#"raxis epoch advance --policy "$RAXIS_DATA_DIR/policy/policy.toml" --sig "$RAXIS_DATA_DIR/policy/policy.sig""#.to_owned(),
    ]
}

fn table_path<'a>(
    root: &'a toml::map::Map<String, toml::Value>,
    path: &[&str],
) -> Option<&'a toml::Value> {
    let mut current: Option<&toml::Value> = None;
    for (idx, part) in path.iter().enumerate() {
        current = if idx == 0 {
            root.get(*part)
        } else {
            current?.as_table()?.get(*part)
        };
    }
    current
}

fn string_field<'a>(
    table: &'a toml::map::Map<String, toml::Value>,
    field: &str,
) -> Option<&'a str> {
    table.get(field).and_then(|v| v.as_str()).map(str::trim)
}

fn string_array_field(
    table: &toml::map::Map<String, toml::Value>,
    field: &str,
    task_id: &str,
    issues: &mut Vec<BuilderValidationIssue>,
) -> Vec<String> {
    match table.get(field) {
        None => Vec::new(),
        Some(value) => match value.as_array() {
            Some(values) => {
                let mut out = Vec::new();
                for value in values {
                    match value.as_str() {
                        Some(s) if !s.trim().is_empty() => out.push(s.trim().to_owned()),
                        _ => issues.push(builder_issue(
                            BuilderValidationSeverity::Error,
                            "PLAN_STRING_ARRAY",
                            format!("task {task_id:?} field {field} must contain only strings."),
                            "Use a TOML array such as [\"src/\", \"README.md\"].",
                        )),
                    }
                }
                out
            }
            None => {
                issues.push(builder_issue(
                    BuilderValidationSeverity::Error,
                    "PLAN_STRING_ARRAY",
                    format!("task {task_id:?} field {field} must be an array of strings."),
                    "Use a TOML array such as [\"src/\", \"README.md\"].",
                ));
                Vec::new()
            }
        },
    }
}

fn validate_task_dag(tasks: &[PlanDraftTask], issues: &mut Vec<BuilderValidationIssue>) {
    let ids: std::collections::HashSet<&str> = tasks
        .iter()
        .filter_map(|t| (!t.id.is_empty()).then_some(t.id.as_str()))
        .collect();
    for task in tasks {
        for pred in &task.predecessors {
            if !ids.contains(pred.as_str()) {
                issues.push(builder_issue(
                    BuilderValidationSeverity::Error,
                    "PLAN_DAG_DANGLING",
                    format!(
                        "task {:?} references unknown predecessor {pred:?}.",
                        task.id
                    ),
                    "Rename the predecessor or add the missing task.",
                ));
            }
            if pred == &task.id {
                issues.push(builder_issue(
                    BuilderValidationSeverity::Error,
                    "PLAN_DAG_SELF_LOOP",
                    format!("task {:?} depends on itself.", task.id),
                    "Remove the self-dependency.",
                ));
            }
        }
        if task.agent_type == "Reviewer" && task.predecessors.is_empty() {
            issues.push(builder_issue(
                BuilderValidationSeverity::Error,
                "PLAN_REVIEWER_PREDECESSOR",
                format!("Reviewer task {:?} has no predecessor.", task.id),
                "Make the Reviewer depend on the Executor it reviews.",
            ));
        }
    }
    let by_id: std::collections::HashMap<&str, &PlanDraftTask> = tasks
        .iter()
        .filter_map(|task| (!task.id.is_empty()).then_some((task.id.as_str(), task)))
        .collect();
    let mut visiting = std::collections::HashSet::new();
    let mut visited = std::collections::HashSet::new();
    for task in tasks {
        if !task.id.is_empty()
            && dag_has_cycle(task.id.as_str(), &by_id, &mut visiting, &mut visited)
        {
            issues.push(builder_issue(
                BuilderValidationSeverity::Error,
                "PLAN_DAG_CYCLE",
                "Task predecessors contain a cycle.",
                "Remove one predecessor edge so the graph is acyclic.",
            ));
            break;
        }
    }
}

fn dag_has_cycle<'a>(
    id: &'a str,
    tasks: &std::collections::HashMap<&'a str, &'a PlanDraftTask>,
    visiting: &mut std::collections::HashSet<&'a str>,
    visited: &mut std::collections::HashSet<&'a str>,
) -> bool {
    if visited.contains(id) {
        return false;
    }
    if !visiting.insert(id) {
        return true;
    }
    if let Some(task) = tasks.get(id) {
        for pred in &task.predecessors {
            if tasks.contains_key(pred.as_str()) && dag_has_cycle(pred, tasks, visiting, visited) {
                return true;
            }
        }
    }
    visiting.remove(id);
    visited.insert(id);
    false
}

fn is_task_id(value: &str) -> bool {
    let mut chars = value.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_alphabetic())
        && value.len() <= 64
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

fn is_path_safe_id(value: &str) -> bool {
    let mut chars = value.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_alphanumeric())
        && value.len() <= 64
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')
}

/// Read every `sessions` row regardless of `revoked` so the
/// recent-list page surfaces revoked + expired alongside active.
/// `session_agent_type` is the migration-5 addition (nullable on
/// V1 rows). The `task_id` / `initiative_id` are populated from
/// `tasks.session_id` if available, otherwise NULL.
///
/// Returns a partly-populated [`RecentSessionEntry`] — fields
/// that depend on the audit chain (`final_annotation`) and the
/// stream-capture ring (`capture_bytes`) are filled by the
/// caller.
fn read_sessions_all_for_recent(
    conn: &raxis_store::ro::RoConn,
    limit: usize,
) -> Result<Vec<RecentSessionEntry>, ApiError> {
    let mut out: Vec<RecentSessionEntry> = Vec::new();
    // Sub-select avoids LEFT JOIN multi-row ambiguity when one
    // session backs multiple tasks. We pick the lowest task_id
    // alphabetically — deterministic for the FE.
    let sql = format!(
        "SELECT s.session_id, \
                       COALESCE(s.session_agent_type, ''), \
                       s.role_id, \
                       s.created_at, \
                       s.revoked_at, \
                       (SELECT t.task_id FROM {TBL_TASKS} t \
                          WHERE t.session_id = s.session_id \
                          ORDER BY t.task_id ASC LIMIT 1) AS task_id, \
                       (SELECT t.initiative_id FROM {TBL_TASKS} t \
                          WHERE t.session_id = s.session_id \
                          ORDER BY t.task_id ASC LIMIT 1) AS initiative_id \
                FROM {TBL_SESSIONS} s \
                ORDER BY COALESCE(s.revoked_at, s.created_at) DESC \
                LIMIT ?1"
    );
    let Ok(mut stmt) = conn.prepare(&sql) else {
        return Ok(out);
    };
    let rows = stmt.query_map([limit as i64], |r| {
        let session_id: String = r.get(0)?;
        let agent_type: String = r.get(1)?;
        let role_id: String = r.get(2)?;
        let created_at: i64 = r.get(3)?;
        let revoked_at: Option<i64> = r.get(4)?;
        let task_id: Option<String> = r.get(5)?;
        let init_id: Option<String> = r.get(6)?;
        Ok((
            session_id, agent_type, role_id, task_id, init_id, created_at, revoked_at,
        ))
    });
    if let Ok(rows) = rows {
        for row in rows.flatten() {
            let (session_id, raw_agent_type, role_id, task_id, init_id, created_at, revoked_at) =
                row;
            let owning = SessionOwningTask {
                initiative_id: init_id.clone(),
                task_id: task_id.clone(),
                input_tokens: 0,
                output_tokens: 0,
            };
            let agent_type = if raw_agent_type.trim().is_empty() {
                semantic_agent_type_for_session(conn, &session_id, &role_id, Some(&owning))
            } else {
                raw_agent_type
            };
            let initiative_display_name = initiative_name_for_id_opt(conn, init_id.as_deref())?;
            out.push(RecentSessionEntry {
                session_id,
                agent_type,
                task_id,
                initiative_id: init_id,
                initiative_display_name,
                created_at: created_at.max(0) as u64,
                terminated_at: revoked_at.map(|v| v.max(0) as u64),
                terminated_reason: None,
                final_annotation: None,
                capture_bytes: 0,
            });
        }
    }
    Ok(out)
}

/// Build the per-reviewer panel results table for one executor
/// task by projecting every `SubmitReview`-shaped audit row
/// downstream of `executor_task_id` (`reviewer_count` and verdict
/// and critique excerpt). This is the structured surface that
/// powers the `<ReviewerVerdictPanel>` on the FE.
///
/// We accept payload kinds named `SubmitReview`,
/// `ReviewerSubmittedVerdict`, and the existing
/// `ReviewAggregationCompleted` row whose payload carries each
/// reviewer's verdict — different kernel revisions emit
/// different shapes; we tolerate all three.
fn extract_reviewer_panel_results(
    audit_chain: &[lifecycle::AuditRow],
    executor_task_id: &str,
) -> Vec<ReviewerPanelEntry> {
    let rows: Vec<&lifecycle::AuditRow> = audit_chain
        .iter()
        .filter(|row| {
            row.payload.get("executor_task_id").and_then(|v| v.as_str()) == Some(executor_task_id)
        })
        .collect();
    extract_reviewer_panel_results_from_rows(&rows)
}

fn extract_reviewer_panel_results_from_rows(
    rows: &[&lifecycle::AuditRow],
) -> Vec<ReviewerPanelEntry> {
    let mut out: Vec<ReviewerPanelEntry> = Vec::new();
    for row in rows.iter() {
        match row.event_kind.as_str() {
            "ReviewAggregationCompleted" => {
                // Inspect every "reviewer_results" entry for
                // this executor's aggregation row.
                if let Some(arr) = row
                    .payload
                    .get("reviewer_results")
                    .and_then(|v| v.as_array())
                {
                    for r in arr {
                        let reviewer_task_id = r
                            .get("reviewer_task_id")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_owned();
                        let verdict = r
                            .get("verdict")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_owned();
                        let critique = r.get("critique").and_then(|v| v.as_str()).unwrap_or("");
                        out.push(ReviewerPanelEntry {
                            reviewer_task_id,
                            verdict,
                            critique_excerpt: first_n_lines_helper(critique, 3),
                            completed_at: row.at,
                        });
                    }
                } else {
                    let reviewer_task_id = row
                        .payload
                        .get("triggered_by_reviewer_task_id")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_owned();
                    let verdict = row
                        .payload
                        .get("verdict")
                        .and_then(|v| v.as_str())
                        .map(aggregate_verdict_to_review_verdict)
                        .unwrap_or_default();
                    if !reviewer_task_id.is_empty() || !verdict.is_empty() {
                        out.push(ReviewerPanelEntry {
                            reviewer_task_id,
                            verdict,
                            critique_excerpt: row
                                .payload
                                .get("critique")
                                .and_then(|v| v.as_str())
                                .map(|s| first_n_lines_helper(s, 3))
                                .unwrap_or_default(),
                            completed_at: row.at,
                        });
                    }
                }
            }
            "SubmitReview" | "ReviewerSubmittedVerdict" => {
                let reviewer_task_id = row
                    .task_id
                    .clone()
                    .or_else(|| {
                        row.payload
                            .get("reviewer_task_id")
                            .and_then(|v| v.as_str())
                            .map(str::to_owned)
                    })
                    .unwrap_or_default();
                let verdict = row
                    .payload
                    .get("verdict")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_owned();
                let critique = row
                    .payload
                    .get("critique")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                out.push(ReviewerPanelEntry {
                    reviewer_task_id,
                    verdict,
                    critique_excerpt: first_n_lines_helper(critique, 3),
                    completed_at: row.at,
                });
            }
            _ => {}
        }
    }
    out
}

fn reviewer_panel_entries_from_verdicts(
    verdicts: &[ReviewerVerdictView],
) -> Vec<ReviewerPanelEntry> {
    verdicts
        .iter()
        .map(|v| ReviewerPanelEntry {
            reviewer_task_id: v.reviewer_task_id.clone(),
            verdict: v.verdict.clone(),
            critique_excerpt: first_n_lines_helper(&v.critique, 3),
            completed_at: v.at as i64,
        })
        .collect()
}

fn aggregate_verdict_to_review_verdict(verdict: &str) -> String {
    match verdict {
        "AllPassed" => "Approved".to_owned(),
        "AtLeastOneRejected" => "Rejected".to_owned(),
        other => other.to_owned(),
    }
}

/// Local copy of the lifecycle-internal `first_n_lines` helper
/// (the lifecycle module's helper is private). Inlined here to
/// avoid re-exporting an internal helper.
fn first_n_lines_helper(s: &str, n: usize) -> String {
    let mut acc = String::new();
    for (i, line) in s.lines().enumerate() {
        if i >= n {
            break;
        }
        if i > 0 {
            acc.push('\n');
        }
        acc.push_str(line);
    }
    acc
}

/// Map an escalation `class` discriminator to a coarse
/// `Low/Normal/High` severity for the dashboard. Mirrors the CLI
/// `raxis escalations` rendering.
fn severity_from_class(class: &str) -> String {
    match class {
        "PolicyViolation" | "SecurityViolation" => "High",
        "CapabilityUpgrade" => "Normal",
        _ => "Low",
    }
    .into()
}

// ---------------------------------------------------------------------------
// policy.toml [dashboard] block parser
// ---------------------------------------------------------------------------

/// Minimal struct used to extract only the `[dashboard]` block
/// out of policy.toml without re-validating the entire bundle.
/// Everything is `Option` so a missing block produces
/// `Outer { dashboard: None }`.
#[derive(Debug, Deserialize)]
struct OuterPolicy {
    #[serde(default)]
    dashboard: Option<DashboardConfig>,
}

/// Read the optional `[dashboard]` block from `policy_path`.
/// Returns `Ok(None)` when:
///   - the file is missing,
///   - the file is unreadable,
///   - the `[dashboard]` block is absent,
///   - `enabled = false`.
///
/// Any other parse failure surfaces as `Err`.
pub fn load_dashboard_config(policy_path: &Path) -> Result<Option<DashboardConfig>, String> {
    let raw = match std::fs::read_to_string(policy_path) {
        Ok(s) => s,
        Err(_) => return Ok(None),
    };
    let outer: OuterPolicy = toml::from_str(&raw).map_err(|e| e.to_string())?;
    let cfg = match outer.dashboard {
        Some(c) if c.enabled => c,
        _ => return Ok(None),
    };
    Ok(Some(cfg))
}

// ---------------------------------------------------------------------------
// Server lifecycle
// ---------------------------------------------------------------------------

/// Spawn the dashboard server in the background WITHOUT a
/// policy-write capability. `PUT /api/policy/toml` will return
/// `403 FAIL_DASHBOARD_FORBIDDEN`. Reserved for read-only
/// deployments / smoke tests.
///
/// Caller is responsible for awaiting `handle.shutdown()`
/// during the orderly exit path.
///
/// Returns an `Err(String)` for both the streams-directory
/// IO failure surfaced by `KernelDashboardData::new` AND any
/// downstream `DashboardServer::bind_with_observability`
/// failure — the caller chooses whether to disable the
/// dashboard or take the kernel down. The previous version
/// panicked on the streams-dir failure and only surfaced bind
/// errors.
///
/// The `observability` argument is the kernel's boot-time
/// `Arc<ObservabilityHub>` (the same one that backs
/// `with_observability` / `spawn_periodic_flush`). When `Some`,
/// the dashboard HTTP middleware + SSE handlers fire the V3
/// §3.14 `record_dashboard_*` helpers; when `None` (tests,
/// embedded harnesses that never instantiate a hub) the
/// helpers degrade to the standard noop path — preserving the
/// pre-V3 behaviour for callers that don't care.
pub async fn start_dashboard(
    cfg: DashboardConfig,
    store: Arc<Store>,
    policy: Arc<ArcSwap<PolicyBundle>>,
    data_dir: PathBuf,
    policy_path: PathBuf,
    booted_at: u64,
    observability: Option<Arc<raxis_observability::ObservabilityHub>>,
) -> Result<ServerHandle, String> {
    let data = Arc::new(
        KernelDashboardData::new(store, policy, data_dir, policy_path, booted_at)
            .map_err(|e| format!("dashboard streams dir init failed: {e}"))?,
    );
    let server = DashboardServer::bind_with_observability(cfg, data, observability)
        .await
        .map_err(|e| format!("dashboard bind failed: {e}"))?;
    Ok(ServerHandle::spawn(server))
}

/// Spawn the dashboard server with a wired policy-write
/// callback. The supplied `advancer` is invoked from
/// `PUT /api/policy/toml` (write_policy role) inside a
/// `tokio::task::spawn_blocking` closure.
///
/// The capture handle lets the caller share a single
/// `SessionStreamCapture` instance with the gateway bridge so
/// SSE subscribers see the same events the kernel persists to
/// `<data_dir>/streams/<session>.jsonl`.
///
/// The `observability` argument is the kernel's boot-time
/// `Arc<ObservabilityHub>` (the same one that backs
/// `with_observability` / `spawn_periodic_flush`). When `Some`,
/// the dashboard HTTP middleware + SSE handlers fire the V3
/// §3.14 `record_dashboard_*` helpers in the live boot path;
/// when `None` (older test fixtures that build the dashboard
/// without a hub) the helpers degrade to the standard noop
/// path. Production boot in `kernel/src/main.rs` MUST pass
/// `Some(_)` — that's the seam the V3 Part 2 wiring closes.
// 11-argument boot path mirrors the dashboard-spec contract
// (every collaborator that flows through `KernelDashboardData` is
// passed positionally so call sites at `kernel/src/main.rs` can
// opt out of any single seam by passing `None` / a no-op without
// touching the others). Wrapping the lot in a builder struct
// would obscure that contract for marginal stylistic gain.
#[allow(clippy::too_many_arguments)]
pub async fn start_dashboard_with_advancer(
    cfg: DashboardConfig,
    store: Arc<Store>,
    policy: Arc<ArcSwap<PolicyBundle>>,
    data_dir: PathBuf,
    policy_path: PathBuf,
    booted_at: u64,
    stream_capture: Arc<SessionStreamCapture>,
    advancer: Arc<dyn PolicyAdvancer>,
    audit_sink: Arc<dyn raxis_audit_tools::AuditSink>,
    observability: Option<Arc<raxis_observability::ObservabilityHub>>,
    task_llm_capture: Option<Arc<TaskLlmCapture>>,
    session_capture: Option<Arc<SessionCapture>>,
) -> Result<ServerHandle, String> {
    let mut data = KernelDashboardData::with_capture(
        store,
        policy,
        data_dir,
        policy_path,
        booted_at,
        stream_capture,
    )
    .with_advancer(advancer)
    .with_audit_sink(audit_sink);
    if let Some(cap) = task_llm_capture {
        data = data.with_task_llm_capture(cap);
    }
    // INV-OBSERVABILITY-DATAPLANE-LATENCY-01 — when the kernel
    // wires an observability hub, plumb it onto the data layer so
    // every dashboard read funnels its store query through
    // `raxis_store::observability::time_query` and lands one
    // `raxis.store.query.duration` sample per call.
    if let Some(hub) = observability.clone() {
        data = data.with_observability_hub(hub);
    }
    if let Some(cap) = session_capture {
        data = data.with_session_capture(cap);
    }
    let data = Arc::new(data);
    let server = DashboardServer::bind_with_observability(cfg, data, observability)
        .await
        .map_err(|e| format!("dashboard bind failed: {e}"))?;
    Ok(ServerHandle::spawn(server))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roles_from_permitted_ops_default_is_read() {
        let r = roles_from_permitted_ops(&[]);
        assert_eq!(r, vec![DashboardRole::Read]);
    }

    #[test]
    fn rotate_epoch_implies_write_policy() {
        let r = roles_from_permitted_ops(&["RotateEpoch".into()]);
        assert!(r.contains(&DashboardRole::Read));
        assert!(r.contains(&DashboardRole::WritePolicy));
        assert!(!r.contains(&DashboardRole::Admin));
    }

    #[test]
    fn admin_requires_both_rotate_and_cert_install() {
        let r = roles_from_permitted_ops(&["RotateEpoch".into(), "OperatorCertInstall".into()]);
        assert!(r.contains(&DashboardRole::Admin));
    }

    #[test]
    fn load_dashboard_config_returns_none_when_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let r = load_dashboard_config(&tmp.path().join("does-not-exist.toml")).unwrap();
        assert!(r.is_none());
    }

    #[test]
    fn load_dashboard_config_returns_none_when_disabled() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("policy.toml");
        std::fs::write(
            &p,
            "[dashboard]\nenabled = false\nbind_address = \"127.0.0.1\"\nbind_port = 9820\n",
        )
        .unwrap();
        assert!(load_dashboard_config(&p).unwrap().is_none());
    }

    #[test]
    fn load_dashboard_config_parses_enabled_block() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("policy.toml");
        std::fs::write(
            &p,
            "[dashboard]\n\
             enabled = true\n\
             bind_address = \"127.0.0.1\"\n\
             bind_port = 0\n\
             jwt_ttl_secs = 1800\n",
        )
        .unwrap();
        let cfg = load_dashboard_config(&p).unwrap().unwrap();
        assert_eq!(cfg.bind_address, "127.0.0.1");
        assert_eq!(cfg.bind_port, 0);
        assert_eq!(cfg.jwt_ttl_secs, 1800);
        assert!(cfg.enabled);
    }

    #[test]
    fn severity_mapping_matches_class_set() {
        assert_eq!(severity_from_class("PolicyViolation"), "High");
        assert_eq!(severity_from_class("CapabilityUpgrade"), "Normal");
        assert_eq!(severity_from_class("Other"), "Low");
    }

    // `INV-DASHBOARD-SESSION-DETAIL-FORENSIC-01`: the wire-state
    // discriminator the dashboard surfaces for a terminated row
    // MUST distinguish revoked / expired / active so the operator
    // sees the right badge in a read-only forensic detail view.
    // The dashboard FE state-color map (in
    // `dashboard-fe/src/lib/state-color.ts`) is the matching
    // consumer side — adding a new variant here means adding a
    // tone mapping there in the same commit.
    fn mk_row(revoked: bool, expires_at: u64) -> raxis_store::views::sessions::SessionRow {
        raxis_store::views::sessions::SessionRow {
            session_id: "sess".into(),
            role_id: "Executor".into(),
            lineage_id: "lin".into(),
            worktree_root: None,
            sequence_number: 0,
            created_at: 100,
            expires_at,
            revoked,
            revoked_at: if revoked { Some(150) } else { None },
            provider: None,
            model: None,
        }
    }

    #[test]
    fn session_row_state_active_when_not_revoked_and_in_window() {
        let row = mk_row(false, u64::MAX);
        assert_eq!(session_row_state(&row), "Active");
    }

    #[test]
    fn session_row_state_revoked_takes_precedence_over_expiry() {
        // A row that is BOTH revoked AND past `expires_at` reports
        // `Revoked` — the deliberate kernel/operator action wins
        // over the passive timeout.
        let row = mk_row(true, 200);
        assert_eq!(session_row_state(&row), "Revoked");
    }

    #[test]
    fn session_row_state_expired_when_past_window_and_not_revoked() {
        // Far-in-the-past `expires_at` ⇒ Expired regardless of
        // wall clock at test time.
        let row = mk_row(false, 200);
        assert_eq!(session_row_state(&row), "Expired");
    }

    // ── INV-DASHBOARD-INTEGRATION-MERGE-VISIBLE-OR-EXCLUDED-01 ──────────
    //
    // The synthetic IntegrationMerge coordinator row
    // (`auto_spawn_orchestrator_session_in_tx` inserts it with
    // `task_id == initiative_id`) MUST surface a human title in the
    // dashboard, not the raw initiative UUID. The projection
    // helper `task_display_title` is the single seam — the
    // exhaustive variants below pin that seam against:
    //
    //   * the coordinator carve-out fires when the predicate
    //     holds (option A: first-class visible task),
    //   * sub-task rows fall back to the operator-authored
    //     `task_id` (forbidden current behaviour: opaque UUID
    //     row in the per-initiative task list).

    #[test]
    fn inv_integration_merge_visible_coordinator_renames_to_human_title() {
        let init_id = "019e254f-c2b1-7db2-8733-72753668a5d8";
        // task_id == initiative_id ⇒ Integration merge.
        assert_eq!(
            task_display_title(init_id, init_id),
            INTEGRATION_MERGE_TITLE,
            "coordinator row MUST stamp the stable human title, not the UUID",
        );
        // Stability: the title string is exactly the spec-pinned
        // value — the FE renders `«integration-merge»` as the
        // display id alongside this title, and a drift here
        // would break the operator-visible contract.
        assert_eq!(INTEGRATION_MERGE_TITLE, "Integration merge");
    }

    #[test]
    fn inv_integration_merge_visible_subtask_keeps_authored_id() {
        let init_id = "019e254f-c2b1-7db2-8733-72753668a5d8";
        let sub_id = "sibling-materialize-records";
        assert_eq!(
            task_display_title(sub_id, init_id),
            sub_id,
            "sub-task rows MUST echo the operator-authored task_id (no rename)",
        );
    }

    // ── INV-DASHBOARD-TASK-STATE-COMPLETENESS-01 ───────────────────────
    //
    // Wire-shape witness: for every variant of the kernel
    // `TaskState` enum the dashboard projection must emit the
    // canonical SQL string on `TaskView.state`. The FE's
    // `state-color.ts` MAP and its companion
    // `state-color.test.ts` exhaustiveness witness consume these
    // strings verbatim; a typo on either side would collapse a
    // distinct state into the `muted` fallback bucket and hide
    // it from the operator (the iter53 `Running` invisibility
    // bug).
    //
    // We synthesize a `TaskRow` per variant and pass it through
    // `task_row_to_view` against an empty store so the
    // projection sees no `structured_outputs` / `path_allowlist`
    // — the shape of those auxiliary lookups doesn't affect the
    // state-string projection we're pinning.

    fn synth_task_row(state: raxis_types::TaskState) -> raxis_store::views::tasks::TaskRow {
        raxis_store::views::tasks::TaskRow {
            task_id: "t-state".into(),
            initiative_id: "init-state".into(),
            initiative_state: "Executing".into(),
            lane_id: "default".into(),
            state: state.as_sql_str().into(),
            block_reason: None,
            actor: "kernel".into(),
            policy_epoch: 1,
            admitted_at: 100,
            transitioned_at: 200,
            session_id: None,
            evaluation_sha: None,
            base_sha: None,
            admission_reserved_units: None,
            actual_cost: 0,
        }
    }

    #[test]
    fn inv_dashboard_task_state_completeness_projection_round_trips_every_variant() {
        // Open an in-memory store + RoConn just so the
        // auxiliary lookups inside `task_row_to_view` have a
        // valid connection to no-op against. Every variant
        // round-trips through the SQL CHECK strings.
        let tmp = tempfile::tempdir().unwrap();
        // The RO open needs a kernel.db file in the data dir;
        // create one with the standard migrations applied.
        let store_path = tmp.path().join("kernel.db");
        {
            let store = raxis_store::Store::open(&store_path).unwrap();
            let g = store.lock_sync();
            g.execute(
                &format!(
                    "INSERT INTO {init} \
                     (initiative_id, state, terminal_criteria_json, plan_artifact_sha256, created_at) \
                     VALUES ('init-state', 'Executing', '{{}}', 'sha-state', 1)",
                    init = raxis_store::Table::Initiatives.as_str()
                ),
                [],
            )
            .unwrap();
            g.execute(
                &format!(
                    "INSERT INTO {tasks} \
                     (task_id, initiative_id, lane_id, state, actor, \
                      policy_epoch, admitted_at, transitioned_at) \
                     VALUES ('t-state', 'init-state', 'default', 'Running', 'kernel', 1, 1, 1)",
                    tasks = raxis_store::Table::Tasks.as_str()
                ),
                [],
            )
            .unwrap();
            g.execute(
                &format!(
                    "INSERT INTO {plans} \
                     (initiative_id, plan_bytes, plan_sig, stored_at) \
                     VALUES ('init-state', ?1, x'00', 1)",
                    plans = raxis_store::Table::SignedPlanArtifacts.as_str()
                ),
                [br#"[plan.initiative]
description = "fixture"

[workspace]
name = "State projection"
lane_id = "default"

[[tasks]]
task_id = "t-state"
"# as &[u8]],
            )
            .unwrap();
        }
        let conn = raxis_store::ro::open(tmp.path()).unwrap();
        for &variant in &raxis_types::TaskState::ALL {
            let row = synth_task_row(variant);
            let view = task_row_to_view(&conn, &row).unwrap();
            assert_eq!(
                view.state,
                variant.as_sql_str(),
                "task_row_to_view MUST preserve the canonical SQL string \
                 for variant {variant:?} — the FE state-color map keys \
                 against these literals.",
            );
            // The wire state string is non-empty — `StateBadge`
            // and `stateTone` both treat empty/null as the
            // muted fallback, which would silently hide a
            // legitimate FSM state.
            assert!(
                !view.state.is_empty(),
                "task_row_to_view emitted an empty state string for {variant:?}",
            );
        }
        // Spec-drift trip-wire: bumping `TaskState::ALL` must be
        // matched by an entry on the FE side (state-color.ts
        // KERNEL_TASK_STATES + its exhaustiveness test). The
        // length pin here is the simplest cross-language witness
        // we can express without parsing the TS source.
        assert_eq!(
            raxis_types::TaskState::ALL.len(),
            8,
            "TaskState enum length drift — update KERNEL_TASK_STATES in \
             dashboard-fe/src/lib/state-color.ts in the same commit \
             (INV-DASHBOARD-TASK-STATE-COMPLETENESS-01).",
        );
    }

    // ── iter69 — observability-pusher health classification ─────────────
    //
    // These tests pin the three operator-visible branches of
    // `classify_observability_pusher` so future edits cannot
    // silently regress the Health card back to "unknown forever".

    fn disabled_obs_config() -> raxis_policy::ObservabilityConfig {
        raxis_policy::ObservabilityConfig::disabled_default()
    }

    #[test]
    fn pusher_card_is_ok_when_observability_is_disabled_in_policy() {
        let tmp = tempfile::tempdir().unwrap();
        let card = classify_observability_pusher(tmp.path(), &disabled_obs_config(), 1_700_000_000);
        assert_eq!(card.status, "ok");
        assert!(card.summary.contains("disabled in policy"));
        assert_eq!(card.last_observed_at, 1_700_000_000);
    }

    #[test]
    fn pusher_card_is_unknown_when_enabled_but_ring_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let mut cfg = disabled_obs_config();
        cfg.enabled = true;
        let card = classify_observability_pusher(tmp.path(), &cfg, 1_700_000_000);
        assert_eq!(card.status, "unknown");
        assert!(card.summary.contains("No observability segments"));
        assert_eq!(card.last_observed_at, 0);
    }

    #[test]
    fn pusher_card_is_ok_when_kernel_ring_is_fresh_and_pusher_events_exist() {
        let tmp = tempfile::tempdir().unwrap();
        let obs_root = tmp.path().join("observability");
        std::fs::create_dir_all(obs_root.join("spans")).unwrap();
        std::fs::write(obs_root.join("spans").join("seg-001.bin"), b"x").unwrap();
        std::fs::write(obs_root.join("pusher-events.jsonl"), b"{}").unwrap();

        let mut cfg = disabled_obs_config();
        cfg.enabled = true;
        // Pass a `now_s` close to the file mtimes so the card
        // sees the ring as "fresh" (< FRESH_SECS old). We use
        // the actual file mtime as the clock so we don't
        // depend on system clock resolution.
        let now_s = newest_mtime_in(&obs_root.join("spans")).unwrap();
        let card = classify_observability_pusher(tmp.path(), &cfg, now_s);
        assert_eq!(card.status, "ok", "summary={}", card.summary);
        assert!(card.last_observed_at > 0);
        assert!(
            card.details
                .iter()
                .all(|d| !d.label.contains("unix") && !d.value.chars().all(|c| c.is_ascii_digit())),
            "health card details must not expose raw unix timestamps: {:?}",
            card.details
        );
    }

    #[test]
    fn pusher_card_is_degraded_when_events_file_is_stale() {
        let tmp = tempfile::tempdir().unwrap();
        let obs_root = tmp.path().join("observability");
        std::fs::create_dir_all(obs_root.join("spans")).unwrap();
        let span_path = obs_root.join("spans").join("seg-001.bin");
        let pusher_path = obs_root.join("pusher-events.jsonl");
        std::fs::write(&span_path, b"x").unwrap();
        std::fs::write(&pusher_path, b"{}").unwrap();
        let base = 1_700_000_000u64;
        std::fs::OpenOptions::new()
            .write(true)
            .open(&pusher_path)
            .unwrap()
            .set_modified(std::time::UNIX_EPOCH + std::time::Duration::from_secs(base))
            .unwrap();
        std::fs::OpenOptions::new()
            .write(true)
            .open(&span_path)
            .unwrap()
            .set_modified(std::time::UNIX_EPOCH + std::time::Duration::from_secs(base + 120))
            .unwrap();

        let mut cfg = disabled_obs_config();
        cfg.enabled = true;
        let card = classify_observability_pusher(tmp.path(), &cfg, base + 121);

        assert_eq!(card.status, "degraded", "summary={}", card.summary);
        assert!(card.summary.contains("pusher events are stale"));
        assert!(card.last_observed_at > 0);
    }

    #[test]
    fn grafana_deep_links_resolve_to_provisioned_dashboard_uids() {
        let base = "http://127.0.0.1:3000/";
        assert_eq!(
            grafana_dashboard_url_from_base(base, "observability").as_deref(),
            Some("http://127.0.0.1:3000/d/raxis-05-otel-pipeline")
        );
        assert_eq!(
            grafana_dashboard_url_from_base(base, "audit").as_deref(),
            Some("http://127.0.0.1:3000/d/raxis-30-audit")
        );
        assert_eq!(
            grafana_dashboard_url_from_base(base, "egress").as_deref(),
            Some("http://127.0.0.1:3000/d/raxis-60-egress")
        );
        assert!(grafana_dashboard_url_from_base(base, "unknown").is_none());
    }

    // ── iter69 — kernel main-loop heartbeat parsing ─────────────────────
    //
    // The dashboard's `kernel_main_loop` card MUST consume the
    // live `last_heartbeat_at` from `runtime/heartbeat.json`,
    // NOT the kernel's `booted_at`. This test exercises the
    // freshness arithmetic + the JSON read path directly.

    #[test]
    fn heartbeat_is_live_within_stale_window() {
        let now = 1_700_000_005u64;
        let snap = raxis_runtime::Snapshot::new(
            42,
            1_700_000_000,
            1_700_000_004,
            raxis_runtime::KernelLifecycleState::Running,
            7,
            0,
            8,
            0,
            0,
            0,
            0,
        );
        assert!(snap.is_live(now));
    }

    #[test]
    fn heartbeat_is_stale_past_window() {
        let now = 1_700_001_000u64;
        let snap = raxis_runtime::Snapshot::new(
            42,
            1_700_000_000,
            1_700_000_004,
            raxis_runtime::KernelLifecycleState::Running,
            7,
            0,
            8,
            0,
            0,
            0,
            0,
        );
        assert!(!snap.is_live(now));
    }

    // ── iter69 — session detail enrichment helpers ──────────────────────
    //
    // The `KernelDashboardData::get_session` / `list_sessions`
    // panels used to hardcode `initiative_id = None`, `task_id =
    // None`, `provider = None`, `model = None`, `input_tokens =
    // 0`, `output_tokens = 0` — every value was a stub. The
    // helpers below own the population. The tests pin the
    // contract so a regression here surfaces empty dashboard
    // headers immediately (instead of waiting for a manual click
    // through the live dashboard).

    /// Seed a kernel.db with the minimum schema the enrichment
    /// helper exercises: one task referencing one session, with
    /// token counters populated. Migration 25 (the iter69 schema
    /// bump) is part of the standard `apply_pending` path so the
    /// fresh DB already has the `sessions.provider` / `model`
    /// columns.
    fn seed_session_with_task() -> tempfile::TempDir {
        const TASKS: &str = raxis_store::Table::Tasks.as_str();
        const SESSIONS: &str = raxis_store::Table::Sessions.as_str();
        const INITIATIVES: &str = raxis_store::Table::Initiatives.as_str();
        let tmp = tempfile::tempdir().unwrap();
        let store = raxis_store::Store::open(&tmp.path().join("kernel.db")).unwrap();
        let g = store.lock_sync();
        g.execute(
            &format!(
                "INSERT INTO {INITIATIVES} \
                    (initiative_id, state, terminal_criteria_json, \
                     plan_artifact_sha256, created_at) \
                 VALUES ('init-a', 'Executing', '{{}}', 'deadbeef', 100)"
            ),
            [],
        )
        .unwrap();
        g.execute(
            &format!(
                "INSERT INTO {SESSIONS} \
                    (session_id, role_id, session_token, lineage_id, \
                     fetch_quota, created_at, expires_at, revoked) \
                 VALUES ('sess-a', 'Executor', 'tok-a', 'lin', 0, \
                         100, 9999999999, 0)"
            ),
            [],
        )
        .unwrap();
        g.execute(
            &format!(
                "INSERT INTO {TASKS} \
                    (task_id, initiative_id, lane_id, state, actor, \
                     policy_epoch, admitted_at, transitioned_at, \
                     session_id, cumulative_input_tokens, \
                     cumulative_output_tokens) \
                 VALUES ('task-a', 'init-a', 'lane-1', 'Running', 'orch', \
                         1, 100, 200, 'sess-a', 1234, 567)"
            ),
            [],
        )
        .unwrap();
        drop(g);
        tmp
    }

    /// `owning_task_for_session` projects the most-recent task
    /// owning the session into the per-row fields the dashboard
    /// needs. The seed has exactly one task → all four fields
    /// MUST come back populated.
    #[test]
    fn owning_task_for_session_returns_task_columns_when_present() {
        let tmp = seed_session_with_task();
        let conn = raxis_store::ro::open(tmp.path()).unwrap();
        let r = owning_task_for_session(&conn, "sess-a").unwrap();
        assert_eq!(r.initiative_id.as_deref(), Some("init-a"));
        assert_eq!(r.task_id.as_deref(), Some("task-a"));
        assert_eq!(r.input_tokens, 1234);
        assert_eq!(r.output_tokens, 567);
    }

    /// Planner VMs all carry `role_id = Planner` at the IPC layer.
    /// The dashboard must render the semantic role stamped by the
    /// session spawner, otherwise every Recent sessions / Sessions row
    /// collapses to "Planner" and hides executor/reviewer activity.
    #[test]
    fn session_agent_type_helpers_prefer_semantic_role_over_wire_role() {
        const SESSIONS: &str = raxis_store::Table::Sessions.as_str();
        let tmp = seed_session_with_task();
        let store = raxis_store::Store::open(&tmp.path().join("kernel.db")).unwrap();
        {
            let g = store.lock_sync();
            g.execute(
                &format!(
                    "UPDATE {SESSIONS} \
                     SET role_id = 'Planner', session_agent_type = 'Reviewer' \
                     WHERE session_id = 'sess-a'"
                ),
                [],
            )
            .unwrap();
        }
        let conn = raxis_store::ro::open(tmp.path()).unwrap();
        assert_eq!(
            session_agent_type_for_session(&conn, "sess-a").as_deref(),
            Some("Reviewer")
        );
    }

    #[test]
    fn integration_review_base_prefers_original_orchestrator_anchor() {
        const SESSIONS: &str = raxis_store::Table::Sessions.as_str();
        let tmp = seed_session_with_task();
        let store = raxis_store::Store::open(&tmp.path().join("kernel.db")).unwrap();
        let executor_base = "1".repeat(40);
        let original_base = "a".repeat(40);
        let late_base = "b".repeat(40);
        {
            let g = store.lock_sync();
            g.execute(
                &format!(
                    "INSERT INTO {SESSIONS} \
                        (session_id, role_id, session_token, lineage_id, \
                         worktree_root, base_sha, base_tracking_ref, \
                         fetch_quota, created_at, expires_at, revoked, \
                         session_agent_type, can_delegate, initiative_id) \
                     VALUES ('exec-early', 'Planner', 'tok-exec-early', 'lin', \
                             '/work/exec-early', ?1, 'refs/heads/main', \
                             0, 50, 9999999999, 0, 'Executor', 0, 'init-a')",
                ),
                [&executor_base],
            )
            .unwrap();
            g.execute(
                &format!(
                    "INSERT INTO {SESSIONS} \
                        (session_id, role_id, session_token, lineage_id, \
                         worktree_root, base_sha, base_tracking_ref, \
                         fetch_quota, created_at, expires_at, revoked, \
                         session_agent_type, can_delegate, initiative_id) \
                     VALUES ('orch-original', 'Planner', 'tok-orch-original', 'lin', \
                             '/work/orch-original', ?1, 'refs/heads/main', \
                             0, 100, 9999999999, 0, 'Orchestrator', 1, 'init-a')",
                ),
                [&original_base],
            )
            .unwrap();
            g.execute(
                &format!(
                    "INSERT INTO {SESSIONS} \
                        (session_id, role_id, session_token, lineage_id, \
                         worktree_root, base_sha, base_tracking_ref, \
                         fetch_quota, created_at, expires_at, revoked, \
                         session_agent_type, can_delegate, initiative_id) \
                     VALUES ('orch-late', 'Planner', 'tok-orch-late', 'lin', \
                             '/work/orch-late', ?1, 'refs/heads/main', \
                             0, 200, 9999999999, 0, 'Orchestrator', 1, 'init-a')",
                ),
                [&late_base],
            )
            .unwrap();
        }
        let conn = raxis_store::ro::open(tmp.path()).unwrap();
        assert_eq!(
            initiative_review_base_sha(&conn, "init-a").unwrap(),
            Some(original_base),
            "integration-main diff reviews must anchor at the initiative's original target ref, not a late merge-hop SHA",
        );
    }

    /// A session without any tasks (orchestrator-only,
    /// pre-spawn, post-revoke without follow-up): the projection
    /// must default-collapse — `None`/`0` everywhere — so the
    /// dashboard renders "—" / "0" instead of crashing the
    /// classifier with a `QueryReturnedNoRows` propagated all
    /// the way out.
    #[test]
    fn owning_task_for_session_collapses_to_default_when_no_task() {
        let tmp = seed_session_with_task();
        let conn = raxis_store::ro::open(tmp.path()).unwrap();
        let r = owning_task_for_session(&conn, "no-such-session").unwrap();
        assert!(r.initiative_id.is_none());
        assert!(r.task_id.is_none());
        assert_eq!(r.input_tokens, 0);
        assert_eq!(r.output_tokens, 0);
    }

    /// When more than one task references the same session, the
    /// projection returns the row with the highest
    /// `transitioned_at` (and `task_id ASC` as the tie-breaker).
    /// This mirrors the dashboard's "show the current task"
    /// rendering choice.
    #[test]
    fn owning_task_for_session_returns_most_recent_task() {
        const TASKS: &str = raxis_store::Table::Tasks.as_str();
        let tmp = seed_session_with_task();
        let store = raxis_store::Store::open(&tmp.path().join("kernel.db")).unwrap();
        // Insert a SECOND task for the same session, with an
        // OLDER `transitioned_at`. The lookup must still pick
        // the newer row from the seed (transitioned_at=200).
        {
            let g = store.lock_sync();
            g.execute(
                &format!(
                    "INSERT INTO {TASKS} \
                        (task_id, initiative_id, lane_id, state, actor, \
                         policy_epoch, admitted_at, transitioned_at, \
                         session_id, cumulative_input_tokens, \
                         cumulative_output_tokens) \
                     VALUES ('task-z', 'init-a', 'lane-1', 'Completed', 'orch', \
                             1, 50, 100, 'sess-a', 99, 33)"
                ),
                [],
            )
            .unwrap();
        }
        let conn = raxis_store::ro::open(tmp.path()).unwrap();
        let r = owning_task_for_session(&conn, "sess-a").unwrap();
        assert_eq!(r.task_id.as_deref(), Some("task-a"));
        assert_eq!(r.input_tokens, 1234);
    }

    /// The session-view fold MUST overwrite the hardcoded stub
    /// values from the original code path. Build a stub view,
    /// call the fold, and assert every populated field made it
    /// through.
    #[test]
    fn enrich_session_view_with_owning_task_populates_stub_fields() {
        let view = raxis_dashboard::data::SessionView {
            session_id: "sess-a".into(),
            role: "Executor".into(),
            initiative_id: None,
            initiative_display_name: None,
            task_id: None,
            state: "Active".into(),
            provider: None,
            model: None,
            input_tokens: 0,
            output_tokens: 0,
            created_at: 100,
            updated_at: 200,
            failure: None,
            annotations: Vec::new(),
            latest_annotation: None,
            env: Vec::new(),
        };
        let owning = SessionOwningTask {
            initiative_id: Some("init-a".into()),
            task_id: Some("task-a".into()),
            input_tokens: 1234,
            output_tokens: 567,
        };
        let fallback_provider = Some("anthropic".into());
        let fallback_model = Some("claude-3-5-sonnet".into());
        let out = enrich_session_view_with_owning_task(
            view,
            owning,
            fallback_provider,
            fallback_model,
            None,
        );
        assert_eq!(out.initiative_id.as_deref(), Some("init-a"));
        assert_eq!(out.task_id.as_deref(), Some("task-a"));
        assert_eq!(out.input_tokens, 1234);
        assert_eq!(out.output_tokens, 567);
        assert_eq!(out.model.as_deref(), Some("claude-3-5-sonnet"));
        assert_eq!(out.provider.as_deref(), Some("anthropic"));
    }

    /// When the session's `provider` / `model` columns are
    /// already populated (the kernel intent handler ran), the
    /// fold must NOT overwrite them with the fallback. The first
    /// observed value sticks at every layer.
    #[test]
    fn enrich_session_view_with_owning_task_preserves_pre_populated_model() {
        let view = raxis_dashboard::data::SessionView {
            session_id: "sess-a".into(),
            role: "Executor".into(),
            initiative_id: Some("init-existing".into()),
            initiative_display_name: Some("Existing initiative".into()),
            task_id: Some("task-existing".into()),
            state: "Active".into(),
            provider: Some("anthropic-prod".into()),
            model: Some("claude-3-haiku".into()),
            input_tokens: 99,
            output_tokens: 88,
            created_at: 100,
            updated_at: 200,
            failure: None,
            annotations: Vec::new(),
            latest_annotation: None,
            env: Vec::new(),
        };
        let owning = SessionOwningTask {
            initiative_id: Some("init-other".into()),
            task_id: Some("task-other".into()),
            input_tokens: 1234,
            output_tokens: 567,
        };
        let fallback_provider = Some("openai".into());
        let fallback_model = Some("claude-3-5-sonnet".into());
        let out = enrich_session_view_with_owning_task(
            view,
            owning,
            fallback_provider,
            fallback_model,
            None,
        );
        // All five pre-populated fields must stick.
        assert_eq!(out.initiative_id.as_deref(), Some("init-existing"));
        assert_eq!(out.task_id.as_deref(), Some("task-existing"));
        assert_eq!(out.input_tokens, 99);
        assert_eq!(out.output_tokens, 88);
        assert_eq!(out.provider.as_deref(), Some("anthropic-prod"));
        assert_eq!(out.model.as_deref(), Some("claude-3-haiku"));
    }

    /// `latest_model_for_task` is fail-soft when the capture is
    /// unwired — operators on a read-only data dir (EROFS bind
    /// mount, ENOSPC at boot) still get a renderable dashboard,
    /// just without the model fallback.
    #[test]
    fn latest_model_for_task_returns_none_when_capture_is_unwired() {
        let m = latest_model_for_task(None, "task-a");
        assert!(m.is_none());
    }

    /// When the capture is wired and the latest record parses,
    /// the helper lifts `body.model`. Synthesise a turn via the
    /// public `TaskLlmCapture` surface.
    #[test]
    fn latest_model_for_task_lifts_body_model_from_latest_turn() {
        let tmp = tempfile::tempdir().unwrap();
        let cap =
            crate::TaskLlmCapture::new(tmp.path(), crate::TaskCaptureConfig::default()).unwrap();
        let body = serde_json::json!({
            "model": "claude-3-5-sonnet-20241022",
            "role": "assistant",
            "usage": {"input_tokens": 1, "output_tokens": 2},
        })
        .to_string();
        let rec = crate::LlmTurnRecord {
            at_ms: 100,
            task_id: "task-a".into(),
            session_id: Some("sess-a".into()),
            fetch_id: "f1".into(),
            status_code: Some(200),
            latency_ms: 10,
            request_body: String::new(),
            body,
            body_truncated: false,
            original_body_bytes: 0,
            error: None,
            agent_role: None,
        };
        cap.append("task-a", rec).unwrap();
        let m = latest_model_for_task(Some(&cap), "task-a").unwrap();
        assert_eq!(m, "claude-3-5-sonnet-20241022");
    }

    #[test]
    fn latest_model_for_task_returns_none_when_body_is_non_json() {
        let tmp = tempfile::tempdir().unwrap();
        let cap =
            crate::TaskLlmCapture::new(tmp.path(), crate::TaskCaptureConfig::default()).unwrap();
        let rec = crate::LlmTurnRecord {
            at_ms: 100,
            task_id: "task-a".into(),
            session_id: Some("sess-a".into()),
            fetch_id: "f1".into(),
            status_code: Some(500),
            latency_ms: 10,
            request_body: String::new(),
            body: "Internal Server Error".into(),
            body_truncated: false,
            original_body_bytes: 0,
            error: None,
            agent_role: None,
        };
        cap.append("task-a", rec).unwrap();
        assert!(latest_model_for_task(Some(&cap), "task-a").is_none());
    }

    #[test]
    fn latest_model_for_task_falls_back_to_request_body_model() {
        let tmp = tempfile::tempdir().unwrap();
        let cap =
            crate::TaskLlmCapture::new(tmp.path(), crate::TaskCaptureConfig::default()).unwrap();
        let rec = crate::LlmTurnRecord {
            at_ms: 100,
            task_id: "task-a".into(),
            session_id: Some("sess-a".into()),
            fetch_id: "f1".into(),
            status_code: Some(500),
            latency_ms: 10,
            request_body: serde_json::json!({
                "model": "claude-sonnet-4-5-20250929"
            })
            .to_string(),
            body: "not json".into(),
            body_truncated: false,
            original_body_bytes: 0,
            error: Some("NetworkError".into()),
            agent_role: None,
        };
        cap.append("task-a", rec).unwrap();
        let m = latest_model_for_task(Some(&cap), "task-a").unwrap();
        assert_eq!(m, "claude-sonnet-4-5-20250929");
    }

    #[test]
    fn latest_provider_for_task_derives_from_captured_payloads() {
        let tmp = tempfile::tempdir().unwrap();
        let cap =
            crate::TaskLlmCapture::new(tmp.path(), crate::TaskCaptureConfig::default()).unwrap();
        let rec = crate::LlmTurnRecord {
            at_ms: 100,
            task_id: "task-a".into(),
            session_id: Some("sess-a".into()),
            fetch_id: "f1".into(),
            status_code: Some(200),
            latency_ms: 10,
            request_body: serde_json::json!({
                "model": "claude-sonnet-4-5-20250929"
            })
            .to_string(),
            body: anthropic_turn_body(1, 1),
            body_truncated: false,
            original_body_bytes: 0,
            error: None,
            agent_role: None,
        };
        cap.append("task-a", rec).unwrap();
        let provider = latest_provider_for_task(Some(&cap), "task-a").unwrap();
        assert_eq!(provider, "anthropic");
    }

    // ── iter74 — `cumulative_tokens_for_task` read-side fallback ────────

    /// Helper for the iter74 token-fallback tests below: build an
    /// Anthropic-shaped response body carrying `usage.input_tokens`
    /// / `usage.output_tokens`.
    fn anthropic_turn_body(in_tok: u64, out_tok: u64) -> String {
        serde_json::json!({
            "model": "claude-3-5-sonnet-20241022",
            "role": "assistant",
            "usage": {"input_tokens": in_tok, "output_tokens": out_tok},
        })
        .to_string()
    }

    /// Same as `anthropic_turn_body` but with the OpenAI
    /// `chat.completion`-style field names. The helper folds both
    /// shapes onto the canonical `(input, output)` totals.
    fn openai_turn_body(prompt: u64, completion: u64) -> String {
        serde_json::json!({
            "model": "gpt-4o",
            "role": "assistant",
            "usage": {"prompt_tokens": prompt, "completion_tokens": completion},
        })
        .to_string()
    }

    fn mk_rec(body: String, at_ms: u64) -> crate::LlmTurnRecord {
        crate::LlmTurnRecord {
            at_ms,
            task_id: "task-a".into(),
            session_id: Some("sess-a".into()),
            fetch_id: format!("f{at_ms}"),
            status_code: Some(200),
            latency_ms: 10,
            request_body: String::new(),
            body,
            body_truncated: false,
            original_body_bytes: 0,
            error: None,
            agent_role: None,
        }
    }

    /// `cumulative_tokens_for_task` returns `None` (not `Some((0,0))`)
    /// when the capture is unwired so callers can distinguish
    /// "no fallback available" from "fallback was zero" — the
    /// enrichment treats `None` as "preserve kernel-persisted
    /// value" and `Some((0,0))` would have the same effect but
    /// would also paper over a future bug that drops kernel
    /// writes silently.
    #[test]
    fn cumulative_tokens_for_task_returns_none_when_capture_is_unwired() {
        assert!(cumulative_tokens_for_task(None, "task-a").is_none());
    }

    /// No turns captured yet → `None`. Distinct from "captured
    /// turn that lacked a usage object" so the helper does not
    /// pretend visibility it does not have.
    #[test]
    fn cumulative_tokens_for_task_returns_none_when_no_turns_captured() {
        let tmp = tempfile::tempdir().unwrap();
        let cap =
            crate::TaskLlmCapture::new(tmp.path(), crate::TaskCaptureConfig::default()).unwrap();
        assert!(cumulative_tokens_for_task(Some(&cap), "task-never-seen").is_none());
    }

    /// Two Anthropic-shape turns: the helper sums both
    /// `input_tokens` and `output_tokens`. This is the dominant
    /// real-world path — every orchestrator session today
    /// terminates through the Anthropic-backed planner.
    #[test]
    fn cumulative_tokens_for_task_sums_anthropic_usage_across_all_turns() {
        let tmp = tempfile::tempdir().unwrap();
        let cap =
            crate::TaskLlmCapture::new(tmp.path(), crate::TaskCaptureConfig::default()).unwrap();
        cap.append("task-a", mk_rec(anthropic_turn_body(100, 50), 1))
            .unwrap();
        cap.append("task-a", mk_rec(anthropic_turn_body(200, 75), 2))
            .unwrap();
        let (in_tok, out_tok) = cumulative_tokens_for_task(Some(&cap), "task-a").unwrap();
        assert_eq!(in_tok, 300);
        assert_eq!(out_tok, 125);
    }

    /// The dispatch-loop fold sums both Anthropic
    /// (`input_tokens` / `output_tokens`) and OpenAI
    /// (`prompt_tokens` / `completion_tokens`) shapes onto the
    /// canonical channels. Both must contribute to the
    /// dashboard's `(input, output)` totals.
    #[test]
    fn cumulative_tokens_for_task_handles_mixed_provider_shapes() {
        let tmp = tempfile::tempdir().unwrap();
        let cap =
            crate::TaskLlmCapture::new(tmp.path(), crate::TaskCaptureConfig::default()).unwrap();
        cap.append("task-a", mk_rec(anthropic_turn_body(10, 5), 1))
            .unwrap();
        cap.append("task-a", mk_rec(openai_turn_body(20, 15), 2))
            .unwrap();
        let (in_tok, out_tok) = cumulative_tokens_for_task(Some(&cap), "task-a").unwrap();
        assert_eq!(in_tok, 30);
        assert_eq!(out_tok, 20);
    }

    /// Non-JSON or `usage`-less turns are skipped without
    /// poisoning the running total. The helper still surfaces
    /// the parseable turns' contributions.
    #[test]
    fn cumulative_tokens_for_task_skips_malformed_turns() {
        let tmp = tempfile::tempdir().unwrap();
        let cap =
            crate::TaskLlmCapture::new(tmp.path(), crate::TaskCaptureConfig::default()).unwrap();
        cap.append("task-a", mk_rec("not json at all".into(), 1))
            .unwrap();
        cap.append(
            "task-a",
            mk_rec(serde_json::json!({"model": "x"}).to_string(), 2),
        )
        .unwrap();
        cap.append("task-a", mk_rec(anthropic_turn_body(7, 3), 3))
            .unwrap();
        let (in_tok, out_tok) = cumulative_tokens_for_task(Some(&cap), "task-a").unwrap();
        assert_eq!(in_tok, 7);
        assert_eq!(out_tok, 3);
    }

    /// Captured turns that ALL lack a `usage` object → `None`
    /// rather than `Some((0,0))`. Pre-iter74 callers that
    /// pre-populated `view.input_tokens` from the kernel-persisted
    /// `tasks` row MUST not see the fallback overwrite a real
    /// zero (which can be legitimate for a session that
    /// short-circuited before any LLM turn fired); pairing
    /// `Some((0,0))` with the `view.input_tokens == 0 &&
    /// view.output_tokens == 0` enrichment guard would be a
    /// no-op, but returning `None` is semantically clearer.
    #[test]
    fn cumulative_tokens_for_task_returns_none_when_no_turn_carries_usage() {
        let tmp = tempfile::tempdir().unwrap();
        let cap =
            crate::TaskLlmCapture::new(tmp.path(), crate::TaskCaptureConfig::default()).unwrap();
        cap.append(
            "task-a",
            mk_rec(
                serde_json::json!({"model": "x", "role": "assistant"}).to_string(),
                1,
            ),
        )
        .unwrap();
        assert!(cumulative_tokens_for_task(Some(&cap), "task-a").is_none());
    }

    /// End-to-end of the orchestrator-session token-visibility
    /// fix: `view.input_tokens == 0` AND `owning_task.input_tokens
    /// == 0` (the orchestrator coordinator's kernel-persisted
    /// columns are stuck at zero because the orchestrator's
    /// terminal intents early-dispatch past `pre_gate`) — the
    /// fold must lift the LLM-turn-capture sum into the view so
    /// the dashboard renders real numbers.
    #[test]
    fn enrich_session_view_with_owning_task_uses_token_fallback_when_kernel_zero() {
        let view = raxis_dashboard::data::SessionView {
            session_id: "sess-a".into(),
            role: "Orchestrator".into(),
            initiative_id: None,
            initiative_display_name: None,
            task_id: None,
            state: "Active".into(),
            provider: None,
            model: None,
            input_tokens: 0,
            output_tokens: 0,
            created_at: 100,
            updated_at: 200,
            failure: None,
            annotations: Vec::new(),
            latest_annotation: None,
            env: Vec::new(),
        };
        let owning = SessionOwningTask {
            initiative_id: Some("init-a".into()),
            task_id: Some("task-coordinator".into()),
            input_tokens: 0,
            output_tokens: 0,
        };
        let out =
            enrich_session_view_with_owning_task(view, owning, None, None, Some((9_999, 4_321)));
        assert_eq!(out.input_tokens, 9_999);
        assert_eq!(out.output_tokens, 4_321);
    }

    /// Executor/Reviewer sessions DO get kernel-persisted token
    /// columns. The fallback must NOT overwrite them, even when
    /// the capture sum disagrees — the kernel-side value carries
    /// the planner's running-total snapshot at terminal-submit
    /// time and is the authoritative billing surface.
    #[test]
    fn enrich_session_view_with_owning_task_preserves_kernel_persisted_tokens() {
        let view = raxis_dashboard::data::SessionView {
            session_id: "sess-a".into(),
            role: "Executor".into(),
            initiative_id: None,
            initiative_display_name: None,
            task_id: None,
            state: "Active".into(),
            provider: None,
            model: None,
            input_tokens: 0,
            output_tokens: 0,
            created_at: 100,
            updated_at: 200,
            failure: None,
            annotations: Vec::new(),
            latest_annotation: None,
            env: Vec::new(),
        };
        let owning = SessionOwningTask {
            initiative_id: Some("init-a".into()),
            task_id: Some("task-a".into()),
            input_tokens: 1_111,
            output_tokens: 222,
        };
        // Owning-task contribution should land first; the
        // fallback then sees a non-zero view and stays out.
        let out =
            enrich_session_view_with_owning_task(view, owning, None, None, Some((9_999, 4_321)));
        assert_eq!(out.input_tokens, 1_111);
        assert_eq!(out.output_tokens, 222);
    }
}

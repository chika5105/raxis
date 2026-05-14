//! `raxis-dashboard-kernel` — kernel-side glue for the dashboard.
//!
//! Normative reference: specs/v2/v2_extended_gaps.md §4.
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
    AuditEntryView, ChainStatusView, CredentialMetadata, CredentialReveal, DagEdge,
    DashboardData, EscalationView, HealthCheck, HealthSnapshot, InitiativeListEntry,
    InitiativePlanView, InitiativeView, NotificationView, OperatorAuthResolution,
    PolicyAdvancement, PolicyOperatorView, PolicySnapshotView, ReviewerVerdictView,
    SessionView, StructuredOutputView, SubsystemDetailRow, SubsystemHealthCard,
    SubsystemHealthResponse, TaskView, WorktreeDetail, WorktreeDiff, WorktreeFile,
    WorktreeListEntry, WorktreeLogEntry, WorktreeTree, WorktreeTreeEntry, SUBSYSTEM_CATALOG,
};
use raxis_dashboard::error::ApiError;
use raxis_dashboard::server::{DashboardServer, ServerHandle};
use raxis_dashboard::stream::{StreamEvent, StreamSubscription};
use raxis_policy::PolicyBundle;
use raxis_store::Store;

mod git;
pub mod notification_filter;
pub mod stream_capture;
pub mod streaming_audit;
pub mod task_llm_capture;

pub use notification_filter::{
    notification_priority, notification_priority_for_kind_str, NotificationPriority,
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
    F: Fn(&[u8], &[u8], &str) -> Result<AdvanceResult, AdvanceError>
        + Send + Sync + 'static,
{
    inner: F,
}

impl<F> ClosurePolicyAdvancer<F>
where
    F: Fn(&[u8], &[u8], &str) -> Result<AdvanceResult, AdvanceError>
        + Send + Sync + 'static,
{
    /// Wrap a closure into a `PolicyAdvancer`.
    pub fn new(f: F) -> Self {
        Self { inner: f }
    }
}

impl<F> PolicyAdvancer for ClosurePolicyAdvancer<F>
where
    F: Fn(&[u8], &[u8], &str) -> Result<AdvanceResult, AdvanceError>
        + Send + Sync + 'static,
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
        let stream_capture = SessionStreamCapture::new(
            &data_dir,
            CaptureConfig::default(),
        )?;
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
        }
    }

    /// Wire the per-task raw-LLM-turn capture (`task_llm_capture.rs`).
    /// Builder-style: returns `Self` so the kernel main can
    /// chain the call onto `with_capture(...).with_task_llm_capture(...)`.
    pub fn with_task_llm_capture(
        mut self,
        capture: Arc<TaskLlmCapture>,
    ) -> Self {
        self.task_llm_capture = Some(capture);
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
    pub fn with_audit_sink(
        mut self,
        sink: Arc<dyn raxis_audit_tools::AuditSink>,
    ) -> Self {
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
        let (active_initiatives, active_sessions, pending_escalations) =
            match self.open_ro() {
                Ok(conn) => {
                    let inits = raxis_store::views::initiatives::counts_by_state(&conn)
                        .map(|c| (c.draft + c.approved_plan + c.executing + c.blocked) as u32)
                        .unwrap_or(0);
                    let sess = raxis_store::views::sessions::active_counts(&conn)
                        .map(|c| c.active as u32)
                        .unwrap_or(0);
                    let esc = raxis_store::views::escalations::pending_count(&conn)
                        .map(|n| n as u32)
                        .unwrap_or(0);
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
                message: format!(
                    "{} segment(s) discovered",
                    r.segment_count()
                ),
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
        // Best-effort kernel-main-loop heartbeat: we use boot
        // time as a proxy — without a real heartbeat surface the
        // dashboard cannot tell more than "kernel is up enough
        // to respond to a dashboard request" — that is a fact
        // by construction; the audit chain + store-readable
        // bools below carry the actual liveness signal.
        let kernel_alive = self.booted_at > 0;

        let mut cards: Vec<SubsystemHealthCard> = SUBSYSTEM_CATALOG
            .iter()
            .map(|(id, label)| {
                let (status, summary, details, last_observed_at, grafana_url) = match *id {
                    "kernel_main_loop" => (
                        if kernel_alive { "ok" } else { "unknown" },
                        if kernel_alive {
                            "Kernel responding to dashboard requests."
                        } else {
                            "Kernel boot timestamp not yet recorded."
                        }
                        .to_owned(),
                        vec![SubsystemDetailRow {
                            label: "Booted at (unix-s)".into(),
                            value: self.booted_at.to_string(),
                        }],
                        if kernel_alive { self.booted_at } else { 0 },
                        grafana_dashboard_url("kernel"),
                    ),
                    "audit_writer" => {
                        let s = if chain_ok { "ok" } else { "failing" };
                        let summary = if chain_ok {
                            "Audit segments readable; chain reader opens cleanly."
                                .to_owned()
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
                        "Egress-admission decisions surfaced via audit chain."
                            .to_owned(),
                        vec![],
                        if store_ok { now_s } else { 0 },
                        grafana_dashboard_url("egress"),
                    ),
                    "session_spawn_pool" => (
                        if store_ok { "ok" } else { "unknown" },
                        "Session spawn / lifecycle visible through sessions view."
                            .to_owned(),
                        vec![],
                        if store_ok { now_s } else { 0 },
                        grafana_dashboard_url("sessions"),
                    ),
                    "planner_registry" => (
                        if store_ok { "ok" } else { "unknown" },
                        "Planner registry health derives from planner-core."
                            .to_owned(),
                        vec![],
                        if store_ok { now_s } else { 0 },
                        grafana_dashboard_url("planner"),
                    ),
                    "observability_pusher" => (
                        "unknown",
                        "Observability stack signal not yet wired into dashboard."
                            .to_owned(),
                        vec![],
                        0,
                        grafana_dashboard_url("observability"),
                    ),
                    "git_worktree_pool" => (
                        if store_ok { "ok" } else { "unknown" },
                        "Git worktree pool tracked in initiatives view.".to_owned(),
                        vec![],
                        if store_ok { now_s } else { 0 },
                        None,
                    ),
                    "dashboard_sse_pump" => (
                        "ok",
                        "SSE pump active — this request was served by it."
                            .to_owned(),
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
                    "failing" | "degraded" if !summary.is_empty() => {
                        Some(summary.clone())
                    }
                    _ => None,
                };
                SubsystemHealthCard {
                    id:               (*id).to_owned(),
                    label:            (*label).to_owned(),
                    status:           status.to_owned(),
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
        let rows = raxis_store::views::initiatives::list(
            &conn,
            state_filter,
            limit.min(200) as usize,
        )
        .map_err(|e| ApiError::Internal { log_only: format!("initiatives::list: {e}") })?;
        // Per-initiative task counts (one extra read per row — bounded
        // by `limit` so worst-case is 200 lookups).
        let mut out = Vec::with_capacity(rows.len());
        for r in rows {
            let tasks = raxis_store::views::tasks::list_by_initiative(
                &conn,
                &r.initiative_id,
                500,
            )
            .map_err(|e| ApiError::Internal { log_only: format!("tasks::list_by_initiative: {e}") })?;
            let task_count = tasks.len() as u32;
            let completed_tasks = tasks.iter().filter(|t| t.state == "Completed").count() as u32;
            let failed_tasks = tasks.iter().filter(|t| t.state == "Failed").count() as u32;
            let updated_at = tasks.iter().map(|t| t.transitioned_at).max().unwrap_or(r.created_at);
            // `initiatives` table has no `display_name` column —
            // the operator-visible title lives in
            // `[plan.initiative].title` inside the plan TOML
            // (`02-first-initiative.md §"Define the plan"`). Fall
            // back to `initiative_id` so the list view never
            // renders an invisible <Link> row.
            let title = raxis_store::views::plan_fields::reveal_initiative_meta(
                &conn,
                &r.initiative_id,
            )
            .map(|m| m.title)
            .unwrap_or_default();
            let display_name = if title.is_empty() {
                r.initiative_id.clone()
            } else {
                title
            };
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
        let row = raxis_store::views::initiatives::by_id(&conn, id)
            .map_err(|e| ApiError::Internal { log_only: format!("initiatives::by_id: {e}") })?
            .ok_or(ApiError::NotFound { kind: "initiative".into() })?;
        let bundle = self.policy.load_full();
        let task_rows = raxis_store::views::tasks::list_by_initiative(&conn, id, 500)
            .map_err(|e| ApiError::Internal { log_only: format!("tasks::list_by_initiative: {e}") })?;
        let task_count = task_rows.len() as u32;
        let completed_tasks = task_rows.iter().filter(|t| t.state == "Completed").count() as u32;
        let failed_tasks = task_rows.iter().filter(|t| t.state == "Failed").count() as u32;
        let updated_at = task_rows.iter().map(|t| t.transitioned_at).max().unwrap_or(row.created_at);
        let mut tasks = Vec::with_capacity(task_rows.len());
        let mut edges: Vec<DagEdge> = Vec::new();
        for t in &task_rows {
            // Pull DAG edges (downstream) for the edge list.
            if let Ok(downstream) = raxis_store::views::tasks::dag_edges_for_task(
                &conn,
                &t.task_id,
                raxis_store::views::tasks::EdgeDirection::Downstream,
            ) {
                for e in downstream {
                    edges.push(DagEdge {
                        from: t.task_id.clone(),
                        to: e.other_task_id,
                    });
                }
            }
            tasks.push(task_row_to_view(&conn, t));
        }
        let title = raxis_store::views::plan_fields::reveal_initiative_meta(
            &conn,
            &row.initiative_id,
        )
        .map(|m| m.title)
        .unwrap_or_default();
        let display_name = if title.is_empty() {
            row.initiative_id.clone()
        } else {
            title
        };
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
        let rows = raxis_store::views::tasks::list_by_initiative(&conn, initiative_id, 500)
            .map_err(|e| ApiError::Internal { log_only: format!("tasks::list_by_initiative: {e}") })?;
        Ok(rows.iter().map(|t| task_row_to_view(&conn, t)).collect())
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
            .ok_or(ApiError::NotFound { kind: "initiative".into() })?;

        // Step 2 — original submitted TOML (V1 + V2.1 fallback).
        let raw = raxis_store::views::plan_fields::submitted_toml_for_initiative(
            &conn, id,
        )
        .map_err(|e| ApiError::Internal {
            log_only: format!("plan_fields::submitted_toml_for_initiative: {e}"),
        })?
        .ok_or(ApiError::Gone { kind: "plan".into() })?;

        // The DDL pins both `signed_plan_artifacts.plan_bytes` and
        // `plan_bundle_artifacts.artifact_bytes` to BLOB; every
        // production producer writes UTF-8 (the codec validates).
        // A non-UTF-8 row is a kernel bug — surface it as a
        // structured 500 rather than corrupt the wire body.
        let toml_string = String::from_utf8(raw).map_err(|e| ApiError::Internal {
            log_only: format!(
                "plan TOML for initiative {id} is not valid UTF-8: {e}",
            ),
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
            })?
            {
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
            initiative_id:        init_row.initiative_id,
            plan_sha256:          if init_row.plan_artifact_sha256.is_empty() {
                None
            } else {
                Some(init_row.plan_artifact_sha256)
            },
            bundle_sha256:        bundle_sha256_hex,
            submitted_toml:       toml_string,
            submitted_toml_bytes: toml_len,
            submitted_at_unix,
            submitted_by,
            approval_status,
            approved_at_unix:     init_row.approved_at.map(|v| v as i64),
        })
    }

    fn get_task(&self, task_id: &str) -> Result<TaskView, ApiError> {
        let conn = self.open_ro()?;
        let row = raxis_store::views::tasks::by_id(&conn, task_id)
            .map_err(|e| ApiError::Internal { log_only: format!("tasks::by_id: {e}") })?
            .ok_or(ApiError::NotFound { kind: "task".into() })?;
        Ok(task_row_to_view(&conn, &row))
    }

    /// `INV-DASHBOARD-TASK-LLM-CAPTURE-01`. Tail the per-task
    /// raw-LLM-turn ring and project each
    /// [`crate::LlmTurnRecord`] to the dashboard's
    /// [`raxis_dashboard::data::TaskLlmTurnView`]. Returns
    /// `Err(ApiError::NotFound { kind: "task_llm_turns" })` when
    /// the kernel did not wire a capture (read-only data dir /
    /// EROFS / ENOSPC at boot) so the absent capability is
    /// observable to the operator.
    fn tail_task_llm_turns(
        &self,
        task_id: &str,
        n: u32,
    ) -> Result<Vec<raxis_dashboard::data::TaskLlmTurnView>, ApiError> {
        let cap = self.task_llm_capture.as_ref().ok_or(
            ApiError::NotFound { kind: "task_llm_turns".into() },
        )?;
        let n = (n.min(500)) as usize;
        let records = cap.tail(task_id, n);
        Ok(records.into_iter().map(record_to_view).collect())
    }

    fn list_sessions(
        &self,
        limit: u32,
        initiative_id: Option<&str>,
    ) -> Result<Vec<SessionView>, ApiError> {
        let conn = self.open_ro()?;
        let cap = limit.min(200) as usize;
        let rows = raxis_store::views::sessions::active_list(&conn, cap).map_err(|e| {
            ApiError::Internal {
                log_only: format!("sessions::active_list: {e}"),
            }
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
                let tasks = raxis_store::views::tasks::list_by_initiative(&conn, i, 500)
                    .map_err(|e| ApiError::Internal {
                        log_only: format!("tasks::list_by_initiative: {e}"),
                    })?;
                Some(
                    tasks
                        .into_iter()
                        .filter_map(|t| t.session_id)
                        .collect(),
                )
            }
        };
        Ok(rows
            .into_iter()
            .filter(|s| match &allowed {
                Some(set) => set.contains(&s.session_id),
                None => true,
            })
            .map(|s| {
                let state = session_row_state(&s);
                SessionView {
                    session_id: s.session_id,
                    role: s.role_id,
                    initiative_id: None,
                    task_id: None,
                    state,
                    provider: None,
                    model: None,
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
                }
            })
            .collect())
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
        let s = raxis_store::views::sessions::by_id(&conn, session_id)
            .map_err(|e| ApiError::Internal {
                log_only: format!("sessions::by_id: {e}"),
            })?
            .ok_or(ApiError::NotFound { kind: "session".into() })?;
        let state = session_row_state(&s);
        Ok(SessionView {
            session_id: s.session_id,
            role: s.role_id,
            initiative_id: None,
            task_id: None,
            state,
            provider: None,
            model: None,
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
        })
    }

    fn list_escalations(&self) -> Result<Vec<EscalationView>, ApiError> {
        let conn = self.open_ro()?;
        let rows = raxis_store::views::escalations::list(
            &conn,
            raxis_store::views::escalations::EscalationStatusFilter::Pending,
            200,
        )
        .map_err(|e| ApiError::Internal { log_only: format!("escalations::list: {e}") })?;
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
        let rows = raxis_store::views::escalations::list(
            &conn,
            raxis_store::views::escalations::EscalationStatusFilter::All,
            500,
        )
        .map_err(|e| ApiError::Internal { log_only: format!("escalations::list: {e}") })?;
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
            .ok_or(ApiError::NotFound { kind: "escalation".into() })
    }

    fn list_audit(
        &self,
        cursor_seq: Option<u64>,
        limit: u32,
        initiative_id: Option<&str>,
    ) -> Result<Vec<AuditEntryView>, ApiError> {
        // Walk the audit chain in segment order (oldest → newest)
        // and keep only the most recent `cap` records that match
        // the caller's filter, in a bounded ring buffer. Memory
        // is O(cap) ≤ 500 entries regardless of how long the
        // chain is, and the iteration is wall-bounded by
        // `MAX_AUDIT_WALK_RECORDS` so a degenerate chain (e.g.
        // millions of rows after sustained e2e churn) cannot
        // pin a request thread for unbounded time.
        //
        // Why a ring buffer instead of "collect everything, sort,
        // paginate": the previous implementation accumulated
        // every matched record into a Vec, sorted by seq desc,
        // then sliced. That is O(N) memory + O(N log N) CPU per
        // request — fine for a 100-event chain, fatal during the
        // live e2e where the chain grows monotonically and many
        // operators may hit `/api/audit` concurrently.
        const MAX_AUDIT_WALK_RECORDS: usize = 200_000;

        let reader = ChainReader::open(&self.audit_dir).map_err(|e| ApiError::Internal {
            log_only: format!("ChainReader::open: {e}"),
        })?;
        let cap = limit.min(500) as usize;
        if cap == 0 {
            return Ok(Vec::new());
        }

        // Bounded sliding window of "newest matched records seen
        // so far that are strictly older than the cursor".
        let mut tail: std::collections::VecDeque<AuditEntryView> =
            std::collections::VecDeque::with_capacity(cap);
        let mut walked: usize = 0;
        for rec in reader.records() {
            walked += 1;
            if walked > MAX_AUDIT_WALK_RECORDS {
                // Hard cap: stop walking. The caller still gets
                // the newest matching records seen so far. The
                // structured warn line lets ops know the chain
                // grew past the per-request budget so they can
                // rotate / archive.
                eprintln!(
                    "{{\"level\":\"warn\",\
                      \"event\":\"dashboard_audit_walk_capped\",\
                      \"limit_records\":{MAX_AUDIT_WALK_RECORDS}}}"
                );
                break;
            }
            let rec = match rec {
                Ok(r) => r,
                Err(_) => continue, // tolerate one malformed line per spec
            };
            if let Some(want) = initiative_id {
                if rec.initiative_id.as_deref() != Some(want) {
                    continue;
                }
            }
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
            let entry = AuditEntryView {
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
            };
            if tail.len() == cap {
                // Drop the oldest matched record we've buffered;
                // it falls outside the page-of-newest we'll return.
                tail.pop_front();
            }
            tail.push_back(entry);
        }
        // Newest first.
        let mut matched: Vec<AuditEntryView> = tail.into_iter().collect();
        matched.reverse();
        Ok(matched)
    }

    fn audit_chain_status(
        &self,
        reverify: bool,
    ) -> Result<(bool, ChainStatusView), ApiError> {
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
        let view = match raxis_audit_tools::verify_chain_from(&self.audit_dir, 0) {
            Ok(stats) => ChainStatusView {
                status:            "ok".into(),
                last_verified_seq: stats.last_seq,
                total_records:     stats.total_records,
                segment_count:     stats.segment_count as u64,
                verified_at_ms:    now_ms,
                last_error:        None,
            },
            Err(e) => {
                let (seq, msg) = describe_chain_error(&e);
                ChainStatusView {
                    status:            "broken".into(),
                    last_verified_seq: seq,
                    total_records:     0,
                    segment_count:     0,
                    verified_at_ms:    now_ms,
                    last_error:        Some(msg),
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
                    let payload = serde_json::from_str(&r.payload_json)
                        .unwrap_or(serde_json::json!({}));
                    inbox.push(AuditEntryView {
                        seq: 0,
                        event_id: r.notification_id,
                        event_kind: r.event_kind,
                        initiative_id: r.initiative_id,
                        task_id: r.task_id,
                        session_id: r.session_id,
                        at: r.created_at,
                        payload,
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
    }

    fn policy_toml_bytes(&self) -> Result<String, ApiError> {
        std::fs::read_to_string(&self.policy_path)
            .map_err(|e| ApiError::Internal { log_only: format!("policy.toml read: {e}") })
    }

    fn list_worktrees(&self) -> Result<Vec<WorktreeListEntry>, ApiError> {
        let worktrees = self.collect_worktrees()?;
        Ok(worktrees.into_iter().map(|w| w.summary).collect())
    }

    fn get_worktree(&self, name: &str) -> Result<WorktreeDetail, ApiError> {
        let resolved = self.resolve_worktree(name)?;
        let path = std::path::PathBuf::from(&resolved.summary.path);
        if !path.exists() {
            return Err(ApiError::NotFound { kind: "worktree-path".into() });
        }
        let head_sha = git::head_sha(&path);
        let branch = git::branch(&path);
        let status_lines = git::status_lines(&path);
        let (ahead, behind) = match (&resolved.summary.base_sha, head_sha.as_ref()) {
            (Some(base), Some(_)) => git::ahead_behind(&path, base)
                .map(|(b, a)| (Some(a), Some(b)))
                .unwrap_or((None, None)),
            _ => (None, None),
        };
        Ok(WorktreeDetail {
            summary: resolved.summary,
            head_sha,
            branch,
            ahead,
            behind,
            status_lines,
        })
    }

    fn worktree_log(
        &self,
        name: &str,
        limit: u32,
    ) -> Result<Vec<WorktreeLogEntry>, ApiError> {
        let resolved = self.resolve_worktree(name)?;
        let path = std::path::PathBuf::from(&resolved.summary.path);
        if !path.exists() {
            return Err(ApiError::NotFound { kind: "worktree-path".into() });
        }
        git::log_entries(&path, limit.clamp(1, 200)).map_err(map_git_error_to_api)
    }

    fn worktree_diff_default(
        &self,
        name: &str,
    ) -> Result<WorktreeDiff, ApiError> {
        let resolved = self.resolve_worktree(name)?;
        let path = std::path::PathBuf::from(&resolved.summary.path);
        if !path.exists() {
            return Err(ApiError::NotFound { kind: "worktree-path".into() });
        }
        let from = resolved
            .summary
            .base_sha
            .clone()
            .ok_or(ApiError::NotFound { kind: "default-diff".into() })?;
        let to = git::head_sha(&path)
            .ok_or(ApiError::NotFound { kind: "head-sha".into() })?;
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
            return Err(ApiError::NotFound { kind: "worktree-path".into() });
        }
        let files = git::diff_files(&path, from_sha, to_sha).map_err(map_git_error_to_api)?;
        Ok(WorktreeDiff {
            name: resolved.summary.name,
            from_sha: from_sha.to_owned(),
            to_sha: to_sha.to_owned(),
            files,
        })
    }

    fn worktree_tree(
        &self,
        name: &str,
        sub_path: Option<&str>,
    ) -> Result<WorktreeTree, ApiError> {
        let resolved = self.resolve_worktree(name)?;
        let root = std::path::PathBuf::from(&resolved.summary.path);
        if !root.exists() {
            return Err(ApiError::NotFound { kind: "worktree-path".into() });
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
            dir_b
                .cmp(&dir_a)
                .then_with(|| a.name.to_ascii_lowercase().cmp(&b.name.to_ascii_lowercase()))
        });
        Ok(WorktreeTree {
            name: resolved.summary.name,
            path: prefix.to_owned(),
            entries,
            truncated,
        })
    }

    fn worktree_file(
        &self,
        name: &str,
        file_path: &str,
    ) -> Result<WorktreeFile, ApiError> {
        let resolved = self.resolve_worktree(name)?;
        let root = std::path::PathBuf::from(&resolved.summary.path);
        if !root.exists() {
            return Err(ApiError::NotFound { kind: "worktree-path".into() });
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

    fn stream_tail(
        &self,
        session_id: &str,
        n: usize,
    ) -> Result<Vec<StreamEvent>, ApiError> {
        Ok(self.stream_capture.tail(session_id, n))
    }

    fn stream_subscribe(
        &self,
        session_id: &str,
    ) -> Result<StreamSubscription, ApiError> {
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
            .ok_or(ApiError::NotFound { kind: "stream".into() })
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
        let rows = if unread_only {
            raxis_store::views::notifications::list_unread(&conn, cap)
        } else {
            raxis_store::views::notifications::list_all(&conn, cap, initiative_id)
        }
        .map_err(|e| ApiError::Internal {
            log_only: format!("notification list: {e}"),
        })?;

        Ok(rows
            .into_iter()
            .map(|r| {
                let payload = serde_json::from_str(&r.payload_json)
                    .unwrap_or(serde_json::json!({}));
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
                let priority = notification_filter::notification_priority_for_kind_str(
                    &r.event_kind,
                )
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
        raxis_store::views::notifications::unread_count(&conn).map_err(|e| {
            ApiError::Internal {
                log_only: format!("notification unread count: {e}"),
            }
        })
    }

    fn mark_notification_read(&self, notification_id: &str) -> Result<bool, ApiError> {
        let guard = self.store.lock_sync();
        guard
            .execute_batch("BEGIN IMMEDIATE")
            .map_err(|e| ApiError::Internal {
                log_only: format!("mark_notification_read BEGIN: {e}"),
            })?;
        let result =
            raxis_store::views::notifications::mark_read(&guard, notification_id);
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
            .ok_or(ApiError::NotFound { kind: "initiative".into() })?;
        // Step 2: enumerate task ids for the initiative.
        let task_rows =
            raxis_store::views::tasks::list_by_initiative(&conn, initiative_id, 500)
                .map_err(|e| ApiError::Internal {
                    log_only: format!("tasks::list_by_initiative: {e}"),
                })?;
        // Step 3: union credential decls across every task,
        // dedup by name (the same credential may be bound by
        // multiple tasks; the dashboard listing surface shows
        // each unique credential once).
        let mut seen: std::collections::BTreeMap<String, raxis_plan_credentials::TaskCredentialDecl> =
            std::collections::BTreeMap::new();
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
            .ok_or(ApiError::NotFound { kind: "initiative".into() })?;
        let task_rows =
            raxis_store::views::tasks::list_by_initiative(&conn, initiative_id, 500)
                .map_err(|e| ApiError::Internal {
                    log_only: format!("tasks::list_by_initiative: {e}"),
                })?;
        // Walk every task once; first match wins. We do not need
        // to dedup here because a found-decl is enough.
        let mut found: Option<raxis_plan_credentials::TaskCredentialDecl> = None;
        for t in &task_rows {
            let decls = read_task_credential_proxies_via_dashboard_glue(&conn, &t.task_id)?;
            if let Some(d) = decls.into_iter().find(|d| d.name.as_str() == credential_name) {
                found = Some(d);
                break;
            }
        }
        let decl = found.ok_or(ApiError::NotFound { kind: "credential".into() })?;
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
            return Err(ApiError::NotFound { kind: "system-credential".into() });
        }
        read_credential_bytes(
            &self.data_dir,
            credential_name,
            REVEAL_AUTOHIDE_SYSTEM_SECS,
        )
    }

    fn enforce_reveal_rate_limit(
        &self,
        operator_fingerprint: &str,
    ) -> Result<(), ApiError> {
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
        let (session_id, task_id, initiative_id) =
            correlation_fields_for_operator_event(&event);
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
        K::OperatorViewedTask { task_id, .. }
        | K::OperatorViewedTaskOutputs { task_id, .. } => {
            (None, Some(task_id.clone()), None)
        }
        K::OperatorViewedSession { session_id, .. }
        | K::OperatorOpenedSessionStream { session_id, .. } => {
            (Some(session_id.clone()), None, None)
        }
        K::OperatorViewedAuditChain { initiative_id_filter, .. }
        | K::OperatorViewedSessionList { initiative_id_filter, .. } => {
            (None, None, initiative_id_filter.clone())
        }
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
/// the dashboard surface). Pinning the schema in `migration_sql_dumps`
/// + this helper gives us the same wire shape with a tiny code
/// duplication budget. Drift is caught by
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
        ProxyDecl::Postgres { .. } => {
            "libpq URL (postgresql://user:pass@host:port/db)".to_owned()
        }
        ProxyDecl::Mysql { .. } => "MySQL URL (mysql://user:pass@host:port/db)".to_owned(),
        ProxyDecl::Mssql { .. } => "MSSQL URL (mssql://user:pass@host:port/db)".to_owned(),
        ProxyDecl::Mongodb { .. } => {
            "MongoDB URI (mongodb://user:pass@host:port/db)".to_owned()
        }
        ProxyDecl::Redis { .. } => "Redis password (single-line plaintext)".to_owned(),
        ProxyDecl::Smtp { .. } => "SMTP relay password (raw bytes)".to_owned(),
        ProxyDecl::Http { .. } => {
            "HTTP credential (Bearer token / Basic password)".to_owned()
        }
        ProxyDecl::K8s { .. } => "Kubeconfig YAML".to_owned(),
        ProxyDecl::Aws { .. } => "AWS access-key TOML (access_key_id + secret_access_key)".to_owned(),
        ProxyDecl::Gcp { .. } => "GCP service-account JSON".to_owned(),
        ProxyDecl::Azure { .. } => {
            "Azure service-principal TOML (client_id + client_secret)".to_owned()
        }
        ProxyDecl::Unknown => "(unknown proxy type — see plan TOML)".to_owned(),
    };
    let upstream_host_port = upstream_host_port_for_decl(&decl.proxy);
    let path = raxis_credentials_file::credential_file_path(
        data_dir,
        &decl.name,
    );
    let (byte_size, sha256_prefix) = stat_credential_bytes(&path);
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
fn upstream_host_port_for_decl(
    proxy: &raxis_plan_credentials::ProxyDecl,
) -> Option<String> {
    use raxis_plan_credentials::ProxyDecl;
    match proxy {
        ProxyDecl::Smtp { upstream_host_port, .. }
        | ProxyDecl::Redis { upstream_host_port, .. } => Some(upstream_host_port.clone()),
        ProxyDecl::Http { upstream_url, .. } => {
            // `upstream_url` is a full URL; we surface `host:port`
            // when the URL parses cleanly. Otherwise we surface
            // the raw URL so the FE can still render it.
            Some(upstream_url.clone())
        }
        _ => None,
    }
}

/// `stat(2)` the credential file and compute the SHA-256 prefix.
/// Returns `(0, None)` for a missing or unreadable file so the
/// FE can render a clear "missing on disk" affordance. Reads the
/// full bytes once — credential files are bounded at < 1 MiB
/// each by the kernel admission pipeline.
fn stat_credential_bytes(path: &std::path::Path) -> (u64, Option<String>) {
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(_) => return (0, None),
    };
    use sha2::Digest;
    let mut h = sha2::Sha256::new();
    h.update(&bytes);
    let digest = h.finalize();
    let mut hex_prefix = String::with_capacity(8);
    for b in &digest[..4] {
        use std::fmt::Write;
        let _ = write!(&mut hex_prefix, "{b:02x}");
    }
    (bytes.len() as u64, Some(hex_prefix))
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
    use raxis_credentials::{CredentialBackend, CredentialError, ConsumerIdentity, CredentialName};
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
            return Err(ApiError::NotFound { kind: "credential".into() });
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
        let (byte_size, sha256_prefix) = stat_credential_bytes(&path);
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
/// Aggregate per-card statuses into the single banner tone
/// the FE Health tab renders above the grid. Worst-case wins:
/// any `failing` ⇒ `failing`; otherwise any `degraded` ⇒
/// `degraded`; otherwise any `unknown` ⇒ `unknown`; otherwise
/// `ok`. Matches the `INV-DASHBOARD-VALIDATE-01` contract that
/// the dashboard surfaces the kernel's worst-known signal
/// without re-classifying.
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
    let trimmed = base.trim_end_matches('/');
    Some(format!("{trimmed}/d/raxis-{slug}"))
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
    /// the active-session list (kind=Session) and produce a
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
        let bundle = self.policy.load_full();
        let mut out = Vec::new();
        for (idx, raw) in bundle.allowed_worktree_roots().iter().enumerate() {
            let path = raw.trim_end_matches('/').to_owned();
            let label = std::path::Path::new(&path)
                .file_name()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_else(|| path.clone());
            out.push(ResolvedWorktree {
                summary: WorktreeListEntry {
                    name: format!("main-{idx}"),
                    label: if label.is_empty() { format!("main-{idx}") } else { label },
                    kind: "Main".into(),
                    path,
                    session_id: None,
                    task_id: None,
                    base_sha: None,
                },
            });
        }
        // Active sessions overlay — pull worktree_root + base_sha
        // from the read-only sessions view.
        if let Ok(conn) = self.open_ro() {
            if let Ok(rows) = raxis_store::views::sessions::active_list(&conn, 200) {
                for s in rows {
                    let Some(wt) = s.worktree_root else { continue };
                    let short = if s.session_id.len() >= 12 {
                        s.session_id[..12].to_owned()
                    } else {
                        s.session_id.clone()
                    };
                    out.push(ResolvedWorktree {
                        summary: WorktreeListEntry {
                            name: format!("session-{short}"),
                            label: format!("{}:{short}", s.role_id),
                            kind: "Session".into(),
                            path: wt,
                            session_id: Some(s.session_id),
                            task_id: None,
                            base_sha: None, // active_list does not surface base_sha today
                        },
                    });
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
            .ok_or(ApiError::NotFound { kind: "worktree".into() })?;
        if !bundle.worktree_root_allowed(&resolved.summary.path) {
            return Err(ApiError::NotFound { kind: "worktree".into() });
        }
        Ok(resolved)
    }
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
            if component.is_empty()
                || component == "."
                || component == ".."
                || component == ".git"
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
    if s.revoked {
        "Revoked".into()
    } else {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        if s.expires_at <= now {
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
/// Field order MUST stay identity — the FE consumes the
/// dashboard view shape and the JSON wire shape is pinned by
/// `INV-DASHBOARD-TASK-LLM-CAPTURE-01`.
fn record_to_view(
    r: crate::LlmTurnRecord,
) -> raxis_dashboard::data::TaskLlmTurnView {
    raxis_dashboard::data::TaskLlmTurnView {
        at_ms:               r.at_ms,
        task_id:             r.task_id,
        session_id:          r.session_id,
        fetch_id:            r.fetch_id,
        status_code:         r.status_code,
        latency_ms:          r.latency_ms,
        body:                r.body,
        body_truncated:      r.body_truncated,
        original_body_bytes: r.original_body_bytes,
        error:               r.error,
    }
}

fn task_row_to_view(
    conn: &raxis_store::ro::RoConn,
    t: &raxis_store::views::tasks::TaskRow,
) -> TaskView {
    let outputs = raxis_store::views::structured_outputs::list_for_task(conn, &t.task_id)
        .unwrap_or_default()
        .into_iter()
        .map(|o| StructuredOutputView {
            kind: o.kind,
            payload: serde_json::from_str(&o.payload_json).unwrap_or(serde_json::Value::Null),
            at: o.emitted_at.max(0) as u64,
        })
        .collect();
    let path_allowlist = raxis_store::views::plan_fields::reveal_for_task(conn, &t.task_id)
        .map(|f| f.path_allowlist)
        .unwrap_or_default();
    // INV-DASHBOARD-INTEGRATION-MERGE-VISIBLE-OR-EXCLUDED-01:
    // detect the synthetic coordinator row by the
    // `task_id == initiative_id` predicate and stamp a stable
    // human title. The detection is exact — sub-task ids are
    // operator-authored strings and live in a disjoint space
    // from UUID-shaped initiative ids by construction
    // (`initiatives::lifecycle::auto_spawn_orchestrator_session_in_tx`
    // doc comment §"task_id == initiative_id by construction").
    let title = task_display_title(&t.task_id, &t.initiative_id);
    TaskView {
        task_id: t.task_id.clone(),
        initiative_id: t.initiative_id.clone(),
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
    }
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
        KernelDashboardData::new(
            store,
            policy,
            data_dir,
            policy_path,
            booted_at,
        )
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
        let r = roles_from_permitted_ops(&[
            "RotateEpoch".into(),
            "OperatorCertInstall".into(),
        ]);
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
            session_id:      "sess".into(),
            role_id:         "Executor".into(),
            lineage_id:      "lin".into(),
            worktree_root:   None,
            sequence_number: 0,
            created_at:      100,
            expires_at,
            revoked,
            revoked_at:      if revoked { Some(150) } else { None },
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
            task_id:                  "t-state".into(),
            initiative_id:            "init-state".into(),
            initiative_state:         "Executing".into(),
            lane_id:                  "default".into(),
            state:                    state.as_sql_str().into(),
            block_reason:             None,
            actor:                    "kernel".into(),
            policy_epoch:             1,
            admitted_at:              100,
            transitioned_at:          200,
            session_id:               None,
            evaluation_sha:           None,
            base_sha:                 None,
            admission_reserved_units: None,
            actual_cost:              0,
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
            let _store = raxis_store::Store::open(&store_path).unwrap();
        }
        let conn = raxis_store::ro::open(tmp.path()).unwrap();
        for &variant in &raxis_types::TaskState::ALL {
            let row = synth_task_row(variant);
            let view = task_row_to_view(&conn, &row);
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
}

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
    AuditEntryView, ChainStatusView, DagEdge, DashboardData, EscalationView, HealthCheck,
    HealthSnapshot, InitiativeListEntry, InitiativeView, NotificationView,
    OperatorAuthResolution, PolicyAdvancement, PolicyOperatorView, PolicySnapshotView,
    ReviewerVerdictView, SessionView, StructuredOutputView, TaskView, WorktreeDetail,
    WorktreeDiff, WorktreeFile, WorktreeListEntry, WorktreeLogEntry, WorktreeTree,
    WorktreeTreeEntry,
};
use raxis_dashboard::error::ApiError;
use raxis_dashboard::server::{DashboardServer, ServerHandle};
use raxis_dashboard::stream::{StreamEvent, StreamSubscription};
use raxis_policy::PolicyBundle;
use raxis_store::Store;

mod git;
pub mod stream_capture;
pub mod streaming_audit;

pub use stream_capture::{CaptureConfig, SessionStreamCapture};
pub use streaming_audit::StreamingAuditSink;

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
}

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
        }
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
        })
    }

    fn list_tasks(&self, initiative_id: &str) -> Result<Vec<TaskView>, ApiError> {
        let conn = self.open_ro()?;
        let rows = raxis_store::views::tasks::list_by_initiative(&conn, initiative_id, 500)
            .map_err(|e| ApiError::Internal { log_only: format!("tasks::list_by_initiative: {e}") })?;
        Ok(rows.iter().map(|t| task_row_to_view(&conn, t)).collect())
    }

    fn get_task(&self, task_id: &str) -> Result<TaskView, ApiError> {
        let conn = self.open_ro()?;
        let row = raxis_store::views::tasks::by_id(&conn, task_id)
            .map_err(|e| ApiError::Internal { log_only: format!("tasks::by_id: {e}") })?
            .ok_or(ApiError::NotFound { kind: "task".into() })?;
        Ok(task_row_to_view(&conn, &row))
    }

    fn list_sessions(&self, limit: u32) -> Result<Vec<SessionView>, ApiError> {
        let conn = self.open_ro()?;
        let rows = raxis_store::views::sessions::active_list(&conn, limit.min(200) as usize)
            .map_err(|e| ApiError::Internal { log_only: format!("sessions::active_list: {e}") })?;
        Ok(rows
            .into_iter()
            .map(|s| SessionView {
                session_id: s.session_id,
                role: s.role_id,
                initiative_id: None,
                task_id: None,
                state: if s.revoked { "Revoked".into() } else { "Active".into() },
                provider: None,
                model: None,
                input_tokens: 0,
                output_tokens: 0,
                created_at: s.created_at,
                updated_at: s.created_at,
            })
            .collect())
    }

    fn get_session(&self, session_id: &str) -> Result<SessionView, ApiError> {
        // The store's session catalog is keyed by token; we walk
        // the active list as an O(N) lookup (N ≤ 200). For V2.5 this
        // is the most truthful surface — the kernel does not expose a
        // by_id session view yet because every other consumer either
        // filters by FK (tasks.session_id) or scans the active list.
        let conn = self.open_ro()?;
        let rows = raxis_store::views::sessions::active_list(&conn, 200)
            .map_err(|e| ApiError::Internal { log_only: format!("sessions::active_list: {e}") })?;
        rows.into_iter()
            .find(|s| s.session_id == session_id)
            .map(|s| SessionView {
                session_id: s.session_id,
                role: s.role_id,
                initiative_id: None,
                task_id: None,
                state: if s.revoked { "Revoked".into() } else { "Active".into() },
                provider: None,
                model: None,
                input_tokens: 0,
                output_tokens: 0,
                created_at: s.created_at,
                updated_at: s.created_at,
            })
            .ok_or(ApiError::NotFound { kind: "session".into() })
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
    TaskView {
        task_id: t.task_id.clone(),
        initiative_id: t.initiative_id.clone(),
        title: t.task_id.clone(),
        state: t.state.clone(),
        session_id: t.session_id.clone(),
        reviewer_verdicts: Vec::<ReviewerVerdictView>::new(),
        structured_outputs: outputs,
        path_allowlist,
        created_at: t.admitted_at,
        updated_at: t.transitioned_at,
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
/// downstream `DashboardServer::bind` failure — the caller
/// chooses whether to disable the dashboard or take the
/// kernel down. The previous version panicked on the streams-
/// dir failure and only surfaced bind errors.
pub async fn start_dashboard(
    cfg: DashboardConfig,
    store: Arc<Store>,
    policy: Arc<ArcSwap<PolicyBundle>>,
    data_dir: PathBuf,
    policy_path: PathBuf,
    booted_at: u64,
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
    let server = DashboardServer::bind(cfg, data)
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
pub async fn start_dashboard_with_advancer(
    cfg: DashboardConfig,
    store: Arc<Store>,
    policy: Arc<ArcSwap<PolicyBundle>>,
    data_dir: PathBuf,
    policy_path: PathBuf,
    booted_at: u64,
    stream_capture: Arc<SessionStreamCapture>,
    advancer: Arc<dyn PolicyAdvancer>,
) -> Result<ServerHandle, String> {
    let data = Arc::new(
        KernelDashboardData::with_capture(
            store,
            policy,
            data_dir,
            policy_path,
            booted_at,
            stream_capture,
        )
        .with_advancer(advancer),
    );
    let server = DashboardServer::bind(cfg, data)
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
}

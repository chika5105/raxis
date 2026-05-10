//! Read-only data trait the kernel implements + an in-process
//! [`InMemoryDashboardData`] fixture for tests.
//!
//! Spec: `v2_extended_gaps.md §4.3` — every dashboard endpoint
//! is a pure read except `PUT /api/policy/toml`. The kernel owns
//! the SQLite store + audit chain + plan registry; this trait is
//! the seam through which those reads flow into the HTTP handler
//! without binding the dashboard crate to the kernel binary.
//!
//! Production wires `KernelDashboardData` (defined in
//! `kernel/src/dashboard_glue.rs`) which fans out to:
//!
//! * `raxis_store::views::initiatives::*` for initiatives,
//! * `raxis_store::views::tasks::*` for tasks,
//! * `raxis_store::views::sessions::*` for sessions,
//! * `raxis_audit_tools::ChainReader` for audit-chain pagination,
//! * `Arc<ArcSwap<PolicyBundle>>::load()` for policy.

use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::RwLock;
use serde::Serialize;

use crate::auth::DashboardRole;
use crate::error::ApiError;

/// Operator role decoded from the cert. Mirrors
/// [`DashboardRole`] but lives on the data layer so impls can
/// surface their own role strings without a dependency cycle.
pub type OperatorRole = DashboardRole;

/// Concise initiative listing entry returned by
/// `GET /api/initiatives`.
#[derive(Debug, Clone, Serialize)]
pub struct InitiativeListEntry {
    /// Initiative id (`init_…`).
    pub initiative_id: String,
    /// Operator-supplied display label.
    pub display_name: String,
    /// FSM state (`Pending`, `Active`, `Paused`, `Closed`,
    /// `Failed`, …). Wire string matches the kernel's enum.
    pub state: String,
    /// Total task count.
    pub task_count: u32,
    /// Tasks in `Completed` state.
    pub completed_tasks: u32,
    /// Tasks in `Failed` state.
    pub failed_tasks: u32,
    /// Unix-seconds creation timestamp.
    pub created_at: u64,
    /// Unix-seconds latest-update timestamp.
    pub updated_at: u64,
}

/// Detailed initiative view.
#[derive(Debug, Clone, Serialize)]
pub struct InitiativeView {
    /// Same fields as [`InitiativeListEntry`].
    #[serde(flatten)]
    pub summary: InitiativeListEntry,
    /// Operator id who approved the plan.
    pub approved_by: Option<String>,
    /// Plan SHA-256 fingerprint.
    pub plan_sha256: Option<String>,
    /// Target ref (Git branch / sha).
    pub target_ref: Option<String>,
    /// Policy epoch the initiative is pinned to.
    pub policy_epoch: u64,
    /// Tasks belonging to this initiative.
    pub tasks: Vec<TaskView>,
    /// Predecessor → successor adjacency for the DAG view.
    pub edges: Vec<DagEdge>,
}

/// One DAG edge.
#[derive(Debug, Clone, Serialize)]
pub struct DagEdge {
    /// Predecessor task id.
    pub from: String,
    /// Successor task id.
    pub to: String,
}

/// Task detail view.
#[derive(Debug, Clone, Serialize)]
pub struct TaskView {
    /// Task id (`task_…`).
    pub task_id: String,
    /// Owning initiative id.
    pub initiative_id: String,
    /// Display title.
    pub title: String,
    /// Task FSM state.
    pub state: String,
    /// Active / most recent session id.
    pub session_id: Option<String>,
    /// Reviewer verdicts in chronological order.
    pub reviewer_verdicts: Vec<ReviewerVerdictView>,
    /// Structured outputs surfaced via `task outputs`.
    pub structured_outputs: Vec<StructuredOutputView>,
    /// Path-scope allowlist (effective).
    pub path_allowlist: Vec<String>,
    /// Unix-seconds creation timestamp.
    pub created_at: u64,
    /// Unix-seconds latest-update timestamp.
    pub updated_at: u64,
}

/// Reviewer verdict surface for the dashboard.
#[derive(Debug, Clone, Serialize)]
pub struct ReviewerVerdictView {
    /// `Approved` / `Rejected`.
    pub verdict: String,
    /// Free-form critique text.
    pub critique: String,
    /// Reviewer session id.
    pub reviewer_session_id: String,
    /// Unix-seconds emit timestamp.
    pub at: u64,
}

/// Structured-output surface for the dashboard.
#[derive(Debug, Clone, Serialize)]
pub struct StructuredOutputView {
    /// Output kind (matches the planner's enum).
    pub kind: String,
    /// JSON-encoded output payload.
    pub payload: serde_json::Value,
    /// Unix-seconds emit timestamp.
    pub at: u64,
}

/// Session row.
#[derive(Debug, Clone, Serialize)]
pub struct SessionView {
    /// Session id.
    pub session_id: String,
    /// `Orchestrator` / `Executor` / `Reviewer`.
    pub role: String,
    /// Owning initiative id.
    pub initiative_id: Option<String>,
    /// Owning task id (None for orchestrator).
    pub task_id: Option<String>,
    /// FSM state.
    pub state: String,
    /// Provider id (e.g. `anthropic`, `openai`, `bedrock`).
    pub provider: Option<String>,
    /// Model id (e.g. `claude-3-5-sonnet`, `gpt-4o`).
    pub model: Option<String>,
    /// Total input tokens consumed so far.
    pub input_tokens: u64,
    /// Total output tokens emitted so far.
    pub output_tokens: u64,
    /// Unix-seconds creation timestamp.
    pub created_at: u64,
    /// Unix-seconds latest-update timestamp.
    pub updated_at: u64,
}

/// Pending escalation visible to operators.
#[derive(Debug, Clone, Serialize)]
pub struct EscalationView {
    /// Escalation id.
    pub escalation_id: String,
    /// Owning initiative id.
    pub initiative_id: String,
    /// Owning task id (optional — some escalations are
    /// initiative-wide).
    pub task_id: Option<String>,
    /// `Low` / `Normal` / `High`.
    pub severity: String,
    /// Escalation reason text.
    pub reason: String,
    /// Action requested from the operator.
    pub action_required: String,
    /// Unix-seconds creation timestamp.
    pub created_at: u64,
}

/// Audit chain entry (paginated).
#[derive(Debug, Clone, Serialize)]
pub struct AuditEntryView {
    /// Monotonic chain sequence number.
    pub seq: u64,
    /// Chain-local event id (UUIDv7).
    pub event_id: String,
    /// Event kind discriminant string.
    pub event_kind: String,
    /// Owning initiative id (if any).
    pub initiative_id: Option<String>,
    /// Owning task id (if any).
    pub task_id: Option<String>,
    /// Owning session id (if any).
    pub session_id: Option<String>,
    /// Unix-seconds emit timestamp.
    pub at: u64,
    /// Full structured payload (JSON).
    pub payload: serde_json::Value,
}

/// Snapshot of the policy bundle the dashboard surfaces (read).
#[derive(Debug, Clone, Serialize)]
pub struct PolicySnapshotView {
    /// Active policy epoch.
    pub epoch: u64,
    /// SHA-256 of the on-disk `policy.toml`.
    pub policy_sha256: String,
    /// Operator id who signed the policy.
    pub signed_by: String,
    /// Unix-seconds policy issuance timestamp.
    pub signed_at: i64,
    /// Operator entries (display name + fingerprint + role
    /// summary). Pubkey bytes are omitted from the read surface
    /// — operators who need them can query the operator UDS.
    pub operators: Vec<PolicyOperatorView>,
    /// Notification routes (event_kind → channel ids).
    pub notification_routes: HashMap<String, Vec<String>>,
}

/// Per-operator summary in [`PolicySnapshotView`].
#[derive(Debug, Clone, Serialize)]
pub struct PolicyOperatorView {
    /// SHA-256[:16] hex fingerprint.
    pub fingerprint: String,
    /// Display name.
    pub display_name: String,
    /// Permitted operator-IPC operations.
    pub permitted_ops: Vec<String>,
}

// ---------------------------------------------------------------------------
// Git worktree views (§4.3 git worktree API)
// ---------------------------------------------------------------------------

/// One worktree row returned by `GET /api/git/worktrees`.
#[derive(Debug, Clone, Serialize)]
pub struct WorktreeListEntry {
    /// URL-safe slug identifying the worktree (e.g. `main-0`,
    /// `session-abc123de`). Used as the `:name` path component
    /// for downstream worktree endpoints.
    pub name: String,
    /// Friendly label suitable for table rendering. For main
    /// worktrees this is the path basename; for session
    /// worktrees this is `<role>:<short-session-id>`.
    pub label: String,
    /// `Main` for operator-allowed roots, `Session` for
    /// per-session VM clones.
    pub kind: String,
    /// Absolute on-disk path of the worktree (loopback-only —
    /// this is the same path the kernel reads).
    pub path: String,
    /// Owning session id when `kind == "Session"`, else `None`.
    pub session_id: Option<String>,
    /// Owning task id when `kind == "Session"`, else `None`.
    pub task_id: Option<String>,
    /// Recorded base SHA (sessions only — `None` when the
    /// session never recorded one or for main roots).
    pub base_sha: Option<String>,
}

/// Worktree detail surfaced by `GET /api/git/worktrees/:name`.
#[derive(Debug, Clone, Serialize)]
pub struct WorktreeDetail {
    /// Same fields as [`WorktreeListEntry`].
    #[serde(flatten)]
    pub summary: WorktreeListEntry,
    /// Current `HEAD` commit SHA (40-char hex). `None` when
    /// the worktree path is missing or `git rev-parse HEAD`
    /// failed (empty repo, broken worktree).
    pub head_sha: Option<String>,
    /// Active branch (`git symbolic-ref --short HEAD`). `None`
    /// when HEAD is detached.
    pub branch: Option<String>,
    /// Commits ahead/behind the recorded base SHA. `None` when
    /// no base is recorded or the comparison failed.
    pub ahead: Option<u32>,
    /// Commits behind the recorded base SHA. See above.
    pub behind: Option<u32>,
    /// `git status --porcelain=v1` lines. Empty ⇒ clean.
    pub status_lines: Vec<String>,
}

/// One commit returned by `GET /api/git/worktrees/:name/log`.
#[derive(Debug, Clone, Serialize)]
pub struct WorktreeLogEntry {
    /// 40-char hex commit SHA.
    pub sha: String,
    /// Short SHA (first 8 chars).
    pub short_sha: String,
    /// `<author name> <author email>`.
    pub author: String,
    /// First non-empty line of the commit message (subject).
    pub subject: String,
    /// Author timestamp in unix seconds (UTC).
    pub at: i64,
}

/// One file changed in a diff returned by
/// `GET /api/git/worktrees/:name/diff{,/:range}`.
#[derive(Debug, Clone, Serialize)]
pub struct WorktreeDiffFile {
    /// Path relative to the worktree root.
    pub path: String,
    /// `A` (added) / `M` (modified) / `D` (deleted) /
    /// `T` (type-change) — same vocabulary as
    /// `git diff --name-status`.
    pub status: String,
    /// Number of inserted lines.
    pub insertions: u32,
    /// Number of deleted lines.
    pub deletions: u32,
    /// Unified-diff hunk text for the file. Bounded to
    /// 64 KiB per file by the kernel-side wrapper to keep
    /// the JSON payload small enough to render.
    pub hunk: String,
}

/// Diff envelope returned by the dashboard.
#[derive(Debug, Clone, Serialize)]
pub struct WorktreeDiff {
    /// Worktree slug the diff was computed against.
    pub name: String,
    /// Base side of the diff (`from`).
    pub from_sha: String,
    /// Head side of the diff (`to`).
    pub to_sha: String,
    /// One entry per changed file. Sorted by path.
    pub files: Vec<WorktreeDiffFile>,
}

/// Health snapshot returned by `GET /api/health`.
#[derive(Debug, Clone, Serialize)]
pub struct HealthSnapshot {
    /// Coarse status: `ok`, `degraded`, or `failing`.
    pub status: String,
    /// Per-category checks.
    pub checks: Vec<HealthCheck>,
    /// Unix-seconds when the kernel boot completed.
    pub kernel_booted_at: u64,
    /// Active policy epoch.
    pub policy_epoch: u64,
    /// Active initiative count.
    pub active_initiatives: u32,
    /// Active session count.
    pub active_sessions: u32,
    /// Outstanding escalation count.
    pub pending_escalations: u32,
}

/// One named check.
#[derive(Debug, Clone, Serialize)]
pub struct HealthCheck {
    /// Stable check id (`gateway_connected`, `disk_free`,
    /// `audit_chain_intact`, …).
    pub id: String,
    /// Coarse status.
    pub status: String,
    /// Operator-safe short message.
    pub message: String,
}

/// Trait the kernel implements. Default impls are NOT provided
/// — the kernel-glue code MUST wire every method.
pub trait DashboardData: Send + Sync + 'static {
    /// Resolve an operator's roles by pubkey fingerprint. Used
    /// by the dashboard auth layer to fold the cert's
    /// permitted-ops into a [`OperatorRole`] list before the
    /// JWT is minted. `None` ⇒ unknown operator (HTTP 401).
    fn lookup_operator_roles(
        &self,
        fingerprint: &str,
    ) -> Option<OperatorAuthResolution>;

    /// Health snapshot for `GET /api/health`.
    fn health(&self) -> HealthSnapshot;

    /// Paginated initiative list (newest first). `limit ≤ 200`.
    fn list_initiatives(
        &self,
        limit: u32,
        state_filter: Option<&str>,
    ) -> Result<Vec<InitiativeListEntry>, ApiError>;

    /// Initiative detail (with task list + DAG edges).
    fn get_initiative(&self, id: &str) -> Result<InitiativeView, ApiError>;

    /// Tasks for one initiative.
    fn list_tasks(&self, initiative_id: &str) -> Result<Vec<TaskView>, ApiError>;

    /// One task by id.
    fn get_task(&self, task_id: &str) -> Result<TaskView, ApiError>;

    /// Sessions newest first. `limit ≤ 200`.
    fn list_sessions(&self, limit: u32) -> Result<Vec<SessionView>, ApiError>;

    /// One session.
    fn get_session(&self, session_id: &str) -> Result<SessionView, ApiError>;

    /// Pending escalations.
    fn list_escalations(&self) -> Result<Vec<EscalationView>, ApiError>;

    /// One escalation.
    fn get_escalation(&self, id: &str) -> Result<EscalationView, ApiError>;

    /// Paginated audit. `cursor_seq` selects the chain
    /// sequence number to start from (newest first); `limit`
    /// caps the page size at ≤ 500.
    fn list_audit(
        &self,
        cursor_seq: Option<u64>,
        limit: u32,
        initiative_id: Option<&str>,
    ) -> Result<Vec<AuditEntryView>, ApiError>;

    /// Operator inbox: union of pending escalations + reviews
    /// awaiting acknowledgement + initiatives waiting on operator
    /// input. Returned as audit-shaped rows so the frontend can
    /// render them with the same component as the audit page.
    fn list_inbox(&self) -> Result<Vec<AuditEntryView>, ApiError>;

    /// Read-only policy snapshot.
    fn policy_snapshot(&self) -> Result<PolicySnapshotView, ApiError>;

    /// Raw `policy.toml` bytes (UTF-8). Returned for the
    /// `write_policy`-role policy editor.
    fn policy_toml_bytes(&self) -> Result<String, ApiError>;

    /// All worktrees the operator may inspect (main +
    /// per-session). Returned newest-first when a sort order
    /// applies.
    fn list_worktrees(&self) -> Result<Vec<WorktreeListEntry>, ApiError>;

    /// One worktree by slug. `Err(NotFound)` ⇒ unknown slug.
    fn get_worktree(&self, name: &str) -> Result<WorktreeDetail, ApiError>;

    /// `git log -n <limit>` for the worktree, newest first.
    /// `limit` is clamped to `[1, 200]` by the route layer.
    fn worktree_log(
        &self,
        name: &str,
        limit: u32,
    ) -> Result<Vec<WorktreeLogEntry>, ApiError>;

    /// Diff between the worktree's `HEAD` and its recorded
    /// base SHA. `Err(NotFound)` ⇒ no base recorded for the
    /// worktree (e.g. main worktrees with no upstream pin).
    fn worktree_diff_default(
        &self,
        name: &str,
    ) -> Result<WorktreeDiff, ApiError>;

    /// Diff between two arbitrary commit SHAs in the worktree.
    /// Both SHAs must be 40-char lowercase hex; the route layer
    /// rejects malformed input before it reaches the data layer.
    fn worktree_diff_range(
        &self,
        name: &str,
        from_sha: &str,
        to_sha: &str,
    ) -> Result<WorktreeDiff, ApiError>;
}

/// Output of [`DashboardData::lookup_operator_roles`].
#[derive(Debug, Clone)]
pub struct OperatorAuthResolution {
    /// Display name from the operator entry.
    pub display_name: String,
    /// Roles granted to the operator (derived from cert).
    pub roles: Vec<DashboardRole>,
}

/// In-process [`DashboardData`] fixture. Backed by `RwLock`-
/// protected vectors; cheap to mutate from tests via the
/// builder methods.
#[derive(Debug, Default)]
pub struct InMemoryDashboardData {
    inner: RwLock<InMemoryInner>,
}

#[derive(Debug, Default)]
struct InMemoryInner {
    operators: HashMap<String, OperatorAuthResolution>,
    initiatives: Vec<InitiativeView>,
    sessions: Vec<SessionView>,
    escalations: Vec<EscalationView>,
    audit: Vec<AuditEntryView>,
    inbox: Vec<AuditEntryView>,
    policy: Option<PolicySnapshotView>,
    policy_toml: String,
    health: Option<HealthSnapshot>,
    /// (entry, detail, log entries, default-diff, ranged-diff store)
    worktrees: Vec<WorktreeFixture>,
}

/// One worktree shape held by the in-memory fixture. Tests
/// construct this via [`InMemoryDashboardData::push_worktree`]
/// and downstream lookups walk the vec by `summary.name`.
#[derive(Debug, Clone)]
pub struct WorktreeFixture {
    /// Detail surface — the listing surface is derived from
    /// `detail.summary`, so callers only need to populate the
    /// detail once.
    pub detail: WorktreeDetail,
    /// Log surface returned by `worktree_log` (already
    /// newest-first).
    pub log: Vec<WorktreeLogEntry>,
    /// Diff returned when no explicit range is requested.
    pub default_diff: Option<WorktreeDiff>,
    /// Per-`(from, to)` diff lookups for the ranged endpoint.
    pub range_diffs: HashMap<(String, String), WorktreeDiff>,
}

impl InMemoryDashboardData {
    /// Empty fixture with sensible defaults.
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Register an operator + role list for the auth layer.
    pub fn with_operator(
        self: &Arc<Self>,
        fingerprint: impl Into<String>,
        display_name: impl Into<String>,
        roles: Vec<DashboardRole>,
    ) -> &Arc<Self> {
        self.inner.write().operators.insert(
            fingerprint.into(),
            OperatorAuthResolution { display_name: display_name.into(), roles },
        );
        self
    }

    /// Push an initiative into the fixture.
    pub fn push_initiative(self: &Arc<Self>, view: InitiativeView) -> &Arc<Self> {
        self.inner.write().initiatives.push(view);
        self
    }

    /// Push a session.
    pub fn push_session(self: &Arc<Self>, view: SessionView) -> &Arc<Self> {
        self.inner.write().sessions.push(view);
        self
    }

    /// Push an escalation.
    pub fn push_escalation(self: &Arc<Self>, view: EscalationView) -> &Arc<Self> {
        self.inner.write().escalations.push(view);
        self
    }

    /// Push an audit entry.
    pub fn push_audit(self: &Arc<Self>, view: AuditEntryView) -> &Arc<Self> {
        self.inner.write().audit.push(view);
        self
    }

    /// Push an inbox entry.
    pub fn push_inbox(self: &Arc<Self>, view: AuditEntryView) -> &Arc<Self> {
        self.inner.write().inbox.push(view);
        self
    }

    /// Set the policy snapshot.
    pub fn set_policy(
        self: &Arc<Self>,
        snap: PolicySnapshotView,
        toml: impl Into<String>,
    ) -> &Arc<Self> {
        let mut g = self.inner.write();
        g.policy = Some(snap);
        g.policy_toml = toml.into();
        self
    }

    /// Set the health snapshot.
    pub fn set_health(self: &Arc<Self>, h: HealthSnapshot) -> &Arc<Self> {
        self.inner.write().health = Some(h);
        self
    }

    /// Push a worktree fixture. The slug used by lookups is
    /// `fix.detail.summary.name`.
    pub fn push_worktree(self: &Arc<Self>, fix: WorktreeFixture) -> &Arc<Self> {
        self.inner.write().worktrees.push(fix);
        self
    }
}

impl DashboardData for InMemoryDashboardData {
    fn lookup_operator_roles(
        &self,
        fingerprint: &str,
    ) -> Option<OperatorAuthResolution> {
        self.inner.read().operators.get(fingerprint).cloned()
    }

    fn health(&self) -> HealthSnapshot {
        self.inner.read().health.clone().unwrap_or(HealthSnapshot {
            status: "ok".into(),
            checks: vec![],
            kernel_booted_at: 0,
            policy_epoch: 0,
            active_initiatives: 0,
            active_sessions: 0,
            pending_escalations: 0,
        })
    }

    fn list_initiatives(
        &self,
        limit: u32,
        state_filter: Option<&str>,
    ) -> Result<Vec<InitiativeListEntry>, ApiError> {
        let g = self.inner.read();
        let mut out: Vec<InitiativeListEntry> = g.initiatives
            .iter()
            .filter(|i| match state_filter {
                Some(s) => i.summary.state.eq_ignore_ascii_case(s),
                None => true,
            })
            .map(|i| i.summary.clone())
            .collect();
        out.sort_by(|a, b| b.updated_at.cmp(&a.updated_at));
        out.truncate(limit.min(200) as usize);
        Ok(out)
    }

    fn get_initiative(&self, id: &str) -> Result<InitiativeView, ApiError> {
        self.inner.read().initiatives.iter()
            .find(|i| i.summary.initiative_id == id)
            .cloned()
            .ok_or(ApiError::NotFound { kind: "initiative".into() })
    }

    fn list_tasks(&self, initiative_id: &str) -> Result<Vec<TaskView>, ApiError> {
        let g = self.inner.read();
        let init = g.initiatives.iter()
            .find(|i| i.summary.initiative_id == initiative_id)
            .ok_or(ApiError::NotFound { kind: "initiative".into() })?;
        Ok(init.tasks.clone())
    }

    fn get_task(&self, task_id: &str) -> Result<TaskView, ApiError> {
        let g = self.inner.read();
        for init in g.initiatives.iter() {
            if let Some(t) = init.tasks.iter().find(|t| t.task_id == task_id) {
                return Ok(t.clone());
            }
        }
        Err(ApiError::NotFound { kind: "task".into() })
    }

    fn list_sessions(&self, limit: u32) -> Result<Vec<SessionView>, ApiError> {
        let mut out: Vec<SessionView> = self.inner.read().sessions.clone();
        out.sort_by(|a, b| b.updated_at.cmp(&a.updated_at));
        out.truncate(limit.min(200) as usize);
        Ok(out)
    }

    fn get_session(&self, session_id: &str) -> Result<SessionView, ApiError> {
        self.inner.read().sessions.iter()
            .find(|s| s.session_id == session_id)
            .cloned()
            .ok_or(ApiError::NotFound { kind: "session".into() })
    }

    fn list_escalations(&self) -> Result<Vec<EscalationView>, ApiError> {
        Ok(self.inner.read().escalations.clone())
    }

    fn get_escalation(&self, id: &str) -> Result<EscalationView, ApiError> {
        self.inner.read().escalations.iter()
            .find(|e| e.escalation_id == id)
            .cloned()
            .ok_or(ApiError::NotFound { kind: "escalation".into() })
    }

    fn list_audit(
        &self,
        cursor_seq: Option<u64>,
        limit: u32,
        initiative_id: Option<&str>,
    ) -> Result<Vec<AuditEntryView>, ApiError> {
        let g = self.inner.read();
        let mut out: Vec<AuditEntryView> = g.audit.iter()
            .filter(|e| match cursor_seq {
                Some(c) => e.seq < c,
                None => true,
            })
            .filter(|e| match initiative_id {
                Some(i) => e.initiative_id.as_deref() == Some(i),
                None => true,
            })
            .cloned()
            .collect();
        out.sort_by(|a, b| b.seq.cmp(&a.seq));
        out.truncate(limit.min(500) as usize);
        Ok(out)
    }

    fn list_inbox(&self) -> Result<Vec<AuditEntryView>, ApiError> {
        Ok(self.inner.read().inbox.clone())
    }

    fn policy_snapshot(&self) -> Result<PolicySnapshotView, ApiError> {
        self.inner.read().policy.clone()
            .ok_or(ApiError::Internal { log_only: "policy snapshot not set in fixture".into() })
    }

    fn policy_toml_bytes(&self) -> Result<String, ApiError> {
        let g = self.inner.read();
        if g.policy_toml.is_empty() {
            return Err(ApiError::Internal { log_only: "policy.toml not set in fixture".into() });
        }
        Ok(g.policy_toml.clone())
    }

    fn list_worktrees(&self) -> Result<Vec<WorktreeListEntry>, ApiError> {
        Ok(self
            .inner
            .read()
            .worktrees
            .iter()
            .map(|w| w.detail.summary.clone())
            .collect())
    }

    fn get_worktree(&self, name: &str) -> Result<WorktreeDetail, ApiError> {
        self.inner
            .read()
            .worktrees
            .iter()
            .find(|w| w.detail.summary.name == name)
            .map(|w| w.detail.clone())
            .ok_or(ApiError::NotFound { kind: "worktree".into() })
    }

    fn worktree_log(
        &self,
        name: &str,
        limit: u32,
    ) -> Result<Vec<WorktreeLogEntry>, ApiError> {
        let g = self.inner.read();
        let w = g
            .worktrees
            .iter()
            .find(|w| w.detail.summary.name == name)
            .ok_or(ApiError::NotFound { kind: "worktree".into() })?;
        let cap = limit.clamp(1, 200) as usize;
        let mut out = w.log.clone();
        out.truncate(cap);
        Ok(out)
    }

    fn worktree_diff_default(
        &self,
        name: &str,
    ) -> Result<WorktreeDiff, ApiError> {
        let g = self.inner.read();
        let w = g
            .worktrees
            .iter()
            .find(|w| w.detail.summary.name == name)
            .ok_or(ApiError::NotFound { kind: "worktree".into() })?;
        w.default_diff
            .clone()
            .ok_or(ApiError::NotFound { kind: "default-diff".into() })
    }

    fn worktree_diff_range(
        &self,
        name: &str,
        from_sha: &str,
        to_sha: &str,
    ) -> Result<WorktreeDiff, ApiError> {
        let g = self.inner.read();
        let w = g
            .worktrees
            .iter()
            .find(|w| w.detail.summary.name == name)
            .ok_or(ApiError::NotFound { kind: "worktree".into() })?;
        w.range_diffs
            .get(&(from_sha.to_owned(), to_sha.to_owned()))
            .cloned()
            .ok_or(ApiError::NotFound { kind: "diff-range".into() })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_initiative(id: &str) -> InitiativeView {
        InitiativeView {
            summary: InitiativeListEntry {
                initiative_id: id.into(),
                display_name: format!("Initiative {id}"),
                state: "Active".into(),
                task_count: 2,
                completed_tasks: 1,
                failed_tasks: 0,
                created_at: 100,
                updated_at: 200,
            },
            approved_by: Some("alice".into()),
            plan_sha256: Some("deadbeef".into()),
            target_ref: Some("main".into()),
            policy_epoch: 7,
            tasks: vec![
                TaskView {
                    task_id: format!("{id}-t1"),
                    initiative_id: id.into(),
                    title: "first".into(),
                    state: "Completed".into(),
                    session_id: Some("s-1".into()),
                    reviewer_verdicts: vec![],
                    structured_outputs: vec![],
                    path_allowlist: vec!["src/".into()],
                    created_at: 100,
                    updated_at: 150,
                },
                TaskView {
                    task_id: format!("{id}-t2"),
                    initiative_id: id.into(),
                    title: "second".into(),
                    state: "Running".into(),
                    session_id: Some("s-2".into()),
                    reviewer_verdicts: vec![],
                    structured_outputs: vec![],
                    path_allowlist: vec!["src/".into()],
                    created_at: 150,
                    updated_at: 200,
                },
            ],
            edges: vec![DagEdge { from: format!("{id}-t1"), to: format!("{id}-t2") }],
        }
    }

    #[test]
    fn list_initiatives_filters_and_paginates() {
        let d = InMemoryDashboardData::new();
        d.push_initiative(sample_initiative("init1"))
         .push_initiative({
             let mut i = sample_initiative("init2");
             i.summary.state = "Closed".into();
             i.summary.updated_at = 50;
             i
         });
        let all = d.list_initiatives(10, None).unwrap();
        assert_eq!(all.len(), 2);
        // Newest-first ordering.
        assert_eq!(all[0].initiative_id, "init1");
        let active = d.list_initiatives(10, Some("Active")).unwrap();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].initiative_id, "init1");
    }

    #[test]
    fn get_task_searches_across_initiatives() {
        let d = InMemoryDashboardData::new();
        d.push_initiative(sample_initiative("init1"))
         .push_initiative(sample_initiative("init2"));
        let t = d.get_task("init2-t1").unwrap();
        assert_eq!(t.task_id, "init2-t1");
        assert_eq!(t.initiative_id, "init2");
    }

    #[test]
    fn list_audit_paginates_with_cursor() {
        let d = InMemoryDashboardData::new();
        for seq in 1..=10 {
            d.push_audit(AuditEntryView {
                seq, event_id: format!("ev{seq}"), event_kind: "X".into(),
                initiative_id: None, task_id: None, session_id: None,
                at: seq, payload: serde_json::json!({"seq": seq}),
            });
        }
        let page1 = d.list_audit(None, 4, None).unwrap();
        assert_eq!(page1.len(), 4);
        assert_eq!(page1[0].seq, 10);
        let page2 = d.list_audit(Some(page1.last().unwrap().seq), 4, None).unwrap();
        assert_eq!(page2.first().unwrap().seq, 6);
    }

    #[test]
    fn worktree_lookups_round_trip_through_fixture() {
        let d = InMemoryDashboardData::new();
        let from = "a".repeat(40);
        let to = "b".repeat(40);
        let summary = WorktreeListEntry {
            name: "main-0".into(),
            label: "raxis".into(),
            kind: "Main".into(),
            path: "/srv/work/raxis".into(),
            session_id: None,
            task_id: None,
            base_sha: Some(from.clone()),
        };
        let detail = WorktreeDetail {
            summary: summary.clone(),
            head_sha: Some(to.clone()),
            branch: Some("main".into()),
            ahead: Some(0),
            behind: Some(0),
            status_lines: vec![],
        };
        let log = vec![WorktreeLogEntry {
            sha: to.clone(),
            short_sha: to[..8].into(),
            author: "alice <alice@example>".into(),
            subject: "first".into(),
            at: 100,
        }];
        let default_diff = WorktreeDiff {
            name: "main-0".into(),
            from_sha: from.clone(),
            to_sha: to.clone(),
            files: vec![],
        };
        let mut range_diffs = HashMap::new();
        range_diffs.insert(
            (from.clone(), to.clone()),
            WorktreeDiff {
                name: "main-0".into(),
                from_sha: from.clone(),
                to_sha: to.clone(),
                files: vec![WorktreeDiffFile {
                    path: "src/lib.rs".into(),
                    status: "M".into(),
                    insertions: 1,
                    deletions: 0,
                    hunk: "@@ -1 +1,2 @@\n line\n+more\n".into(),
                }],
            },
        );
        d.push_worktree(WorktreeFixture { detail, log, default_diff: Some(default_diff), range_diffs });

        let listed = d.list_worktrees().unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].name, "main-0");

        let det = d.get_worktree("main-0").unwrap();
        assert_eq!(det.head_sha.as_deref(), Some(to.as_str()));

        let log = d.worktree_log("main-0", 10).unwrap();
        assert_eq!(log.len(), 1);
        assert_eq!(log[0].subject, "first");

        let dd = d.worktree_diff_default("main-0").unwrap();
        assert_eq!(dd.from_sha, from);

        let rd = d.worktree_diff_range("main-0", &from, &to).unwrap();
        assert_eq!(rd.files.len(), 1);
        assert_eq!(rd.files[0].path, "src/lib.rs");

        // Unknown name → 404 family.
        let err = d.get_worktree("bogus").unwrap_err();
        assert!(matches!(err, ApiError::NotFound { .. }));
    }

    #[test]
    fn lookup_operator_returns_none_for_missing() {
        let d = InMemoryDashboardData::new();
        assert!(d.lookup_operator_roles("absent").is_none());
        d.with_operator("F", "alice", vec![DashboardRole::Read]);
        let r = d.lookup_operator_roles("F").unwrap();
        assert_eq!(r.display_name, "alice");
        assert_eq!(r.roles, vec![DashboardRole::Read]);
    }
}

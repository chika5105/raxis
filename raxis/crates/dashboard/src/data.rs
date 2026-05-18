//! Read-only data trait the kernel implements + an in-process
//! [`InMemoryDashboardData`] fixture for tests.
//!
//! Every dashboard endpoint is a pure read except
//! `PUT /api/policy/toml`. The kernel owns the SQLite store +
//! audit chain + plan registry; this trait is the seam through
//! which those reads flow into the HTTP handler
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
use std::time::Duration;

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

use crate::auth::DashboardRole;
use crate::error::ApiError;
use crate::stream::{SimpleStreamSource, StreamEvent, StreamSubscription};

// ---------------------------------------------------------------------------
// Lifecycle annotations — INV-DASHBOARD-LIFECYCLE-CAUSALITY-01 (paired)
// ---------------------------------------------------------------------------

/// One structured causality annotation rendered by the
/// dashboard's lifecycle timeline. The wire shape uses the
/// `kind` discriminator so the FE can dispatch to a per-kind
/// component without re-parsing audit JSON.
///
/// The PRODUCTION classifier lives in
/// `raxis_dashboard_kernel::lifecycle::classify_*` (paired with
/// Worker 1's `INV-DASHBOARD-LIFECYCLE-CAUSALITY-01` invariant).
/// The wire enum lives here so the dashboard crate owns the
/// serialised contract — kernel-glue produces values, route
/// handlers serialise them, frontend renders them — and the
/// fixture data layer can synthesise annotations directly for
/// route-level tests.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum LifecycleAnnotation {
    /// A retry triggered by a reviewer-panel rejection — paired
    /// `ReviewAggregationCompleted{verdict=AtLeastOneRejected}`
    /// `ExecutorRespawnFromReviewRejection` audit rows.
    RetryReviewReject {
        /// One-based retry number (the first retry is `1`).
        retry_number: u32,
        /// Reviewer task that triggered the rejection
        /// aggregation.
        triggered_by_reviewer_task_id: String,
        /// Aggregated verdict string from the
        /// `ReviewAggregationCompleted` row.
        verdict: String,
        /// First-line excerpt of the captured aggregated
        /// critique (typically `tasks.last_critique`). Empty
        /// when no critique was captured for this retry.
        critique: String,
        /// Cumulative review-reject count after this retry.
        review_reject_count: u32,
        /// Per-task max review rejections (V2 default 3).
        max_review_rejections: u32,
        /// Cumulative crash-retry count carried through.
        crash_retry_count: u32,
        /// Per-task max crash retries (V2 default 3).
        max_crash_retries: u32,
        /// Activation id that was just torn down.
        prior_activation_id: String,
        /// Activation id that took its place.
        new_activation_id: String,
        /// Worktree HEAD sha at the prior activation.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        prior_head_sha: Option<String>,
        /// Worktree HEAD sha at the new activation.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        new_head_sha: Option<String>,
        /// Unix-seconds timestamp of the
        /// `ExecutorRespawnFromReviewRejection` audit row.
        ts_unix: i64,
    },
    /// A retry triggered by the executor VM's premature exit.
    RetryCrash {
        /// One-based retry number.
        retry_number: u32,
        /// Exit code reported by the guest.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        exit_code: Option<i32>,
        /// Last terminal-tool the agent invoked before crash.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        terminal_tool: Option<String>,
        /// `max_turns` value the prior activation ran with.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        max_turns_scaled_from: Option<u32>,
        /// `max_turns` value scaled to for the new activation.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        max_turns_scaled_to: Option<u32>,
        /// Cumulative crash-retry count after this retry.
        crash_retry_count: u32,
        /// Per-task max crash retries (V2 default 3).
        max_crash_retries: u32,
        /// Unix-seconds timestamp of the
        /// `RetrySubTaskAdmitted` audit row.
        ts_unix: i64,
    },
    /// A retry triggered by the planner's intent-validator
    /// (Worker 1 C7).
    RetryValidationReject {
        /// One-based retry number.
        retry_number: u32,
        /// Validator's short reason string.
        validator_reason: String,
        /// Validator's structured detail blob.
        validator_detail: serde_json::Value,
        /// Cumulative validation-reject count after this retry.
        validation_reject_count: u32,
        /// Per-task max validation rejections.
        max_validation_rejections: u32,
        /// Unix-seconds timestamp of the
        /// `IntentValidationRejected` audit row.
        ts_unix: i64,
    },
    /// Operator-initiated session revocation. Anything whose
    /// `revoked_by` does NOT start with the `kernel://` marker
    /// pattern lands here.
    SessionRevokedOperator {
        /// Verbatim `revoked_by` field.
        revoked_by: String,
        /// Display name from the audit row, when populated.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        revoked_by_display_name: Option<String>,
        /// Intent kind that drove the revocation
        /// (`UserCommand` / `IntentEnded` / …) when known.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        intent_kind: Option<String>,
        /// Unix-seconds timestamp of the `SessionRevoked` row.
        ts_unix: i64,
    },
    /// Self-exit revocation — the kernel ended the session in
    /// response to a clean planner exit. Worker 1's C1 marker
    /// (`revoked_by = "kernel://self-exit/..."`) is the
    /// authoritative pattern.
    SessionRevokedSelfExit {
        /// Last terminal-tool the planner invoked before
        /// graceful exit.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        terminal_tool: Option<String>,
        /// Exit code captured from the guest, when available.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        exit_code: Option<i32>,
        /// Path to `kernel.stderr.log` for operator drill-down.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        console_log_path: Option<String>,
        /// Unix-seconds timestamp of the `SessionRevoked` row.
        ts_unix: i64,
    },
    /// Initiative entered the `Blocked` state.
    InitiativeBlocked {
        /// Free-form block reason from the
        /// `InitiativeStateChanged` payload.
        block_reason: String,
        /// Task that triggered the block, when populated.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        blocking_task_id: Option<String>,
        /// Unix-seconds timestamp of the audit row.
        ts_unix: i64,
    },
    /// Stale `PendingActivation` row whose predecessors are all
    /// `Completed` and whose `created_at` is older than the
    /// 120-second cutoff. Surfaces orchestrator-side starvation
    /// or scheduler gaps that would otherwise be invisible.
    OrchestratorGap {
        /// Activation id that has been waiting.
        activation_id: String,
        /// Owning task id.
        task_id: String,
        /// Predecessor task → completion-timestamp pairs. Empty
        /// when the task is a root.
        predecessors_completed_at: Vec<(String, i64)>,
        /// `now_unix - activation.created_at` in seconds.
        wait_seconds: i64,
    },
}

impl LifecycleAnnotation {
    /// Unix-seconds timestamp the FE uses to merge annotations
    /// into the session live-stream by ordering. Each variant
    /// exposes its own `ts_unix`; this helper centralises the
    /// read so route-layer projections don't have to pattern-
    /// match exhaustively.
    pub fn ts_unix(&self) -> i64 {
        match self {
            Self::RetryReviewReject { ts_unix, .. }
            | Self::RetryCrash { ts_unix, .. }
            | Self::RetryValidationReject { ts_unix, .. }
            | Self::SessionRevokedOperator { ts_unix, .. }
            | Self::SessionRevokedSelfExit { ts_unix, .. }
            | Self::InitiativeBlocked { ts_unix, .. } => *ts_unix,
            Self::OrchestratorGap { .. } => 0,
        }
    }

    /// Wire `kind` discriminant — useful for filter knobs (e.g.
    /// "show retries only") that the FE wants to apply without
    /// pattern-matching on the typed variants.
    pub fn kind_str(&self) -> &'static str {
        match self {
            Self::RetryReviewReject { .. } => "retry_review_reject",
            Self::RetryCrash { .. } => "retry_crash",
            Self::RetryValidationReject { .. } => "retry_validation_reject",
            Self::SessionRevokedOperator { .. } => "session_revoked_operator",
            Self::SessionRevokedSelfExit { .. } => "session_revoked_self_exit",
            Self::InitiativeBlocked { .. } => "initiative_blocked",
            Self::OrchestratorGap { .. } => "orchestrator_gap",
        }
    }
}

/// One row in the per-task reviewer-panel results table.
/// Parsed from the audit chain's `SubmitReview` events for
/// reviewer tasks downstream of one executor task.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct ReviewerPanelEntry {
    /// Reviewer task id (e.g. `review-lint-defect-rust`).
    pub reviewer_task_id: String,
    /// Verdict the reviewer issued (`Approved` / `Rejected`).
    pub verdict: String,
    /// First-line excerpt of the reviewer's critique.
    pub critique_excerpt: String,
    /// Unix-seconds timestamp the reviewer completed.
    pub completed_at: i64,
}

/// `GET /api/orchestrator-gaps` response envelope. Carries the
/// list of currently stuck `PendingActivation` rows so the home
/// view "Warnings" pane can render them without drilling into
/// per-task pages.
#[derive(Debug, Clone, Serialize)]
pub struct OrchestratorGapsResponse {
    /// One [`LifecycleAnnotation::OrchestratorGap`] per stuck
    /// activation.
    pub gaps: Vec<LifecycleAnnotation>,
    /// Unix-seconds timestamp the gap detector ran. Mirrors
    /// `now_unix` from the data-layer call so the FE can show
    /// staleness when the operator parks the page.
    pub generated_at: i64,
}

/// One row in `GET /api/gates/stats` — per-`gate_type` rollup of
/// witness outcomes, with a fixup-loop counter so the dashboard
/// can render the cumulative health of every operator-configured
/// `[[gates]]` entry at a glance.
///
/// **Why per-gate, not per-task.** Operators iterate on verifier
/// authoring; the per-task view is too narrow to spot a noisy
/// `NoSecretStrings` verifier whose false-positive rate is
/// drifting upward. Bucketing by `gate_type` surfaces the
/// gate-author signal directly.
///
/// **`fixup_loop_count` semantics.** Sum of
/// `tasks.gate_fixup_attempts` over every task that ran (or is
/// running) this gate AND for whom the kernel auto-admitted at
/// least one gate-fixup row via
/// `kernel::gate_fixup::auto_admit_gate_fixup_task`. This is the
/// "how often did this gate force a repair loop?" signal —
/// a high value relative to `pass_count` is the operator's cue
/// that the gate is over-strict, the hint is misleading, or the
/// agent cannot satisfy the gate in this loop budget.
#[derive(Debug, Clone, Serialize)]
pub struct GateStatRow {
    /// Operator-defined gate name (matches
    /// `[[gates]].gate_type` in `policy.toml`).
    pub gate_type: String,
    /// Number of `WitnessResultClass::Pass` outcomes recorded
    /// in `witness_records` for this gate.
    pub pass_count: u64,
    /// Number of `WitnessResultClass::Fail` outcomes recorded.
    pub fail_count: u64,
    /// Number of `WitnessResultClass::Inconclusive` outcomes.
    pub inconclusive_count: u64,
    /// Unix-seconds timestamp of the most-recent witness for
    /// this gate (`MAX(witness_records.recorded_at)`). `None`
    /// when the gate has never run.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_seen_at: Option<i64>,
    /// Cumulative count of gate-fixup rows admitted for this
    /// gate by the kernel-authoritative auto-admit pipeline (i.e.
    /// `SUM(tasks.gate_fixup_attempts) WHERE
    ///  tasks.last_gate_type = <gate_type>`).
    pub fixup_loop_count: u64,
}

/// iter68 PR 4 — one entry in a DAG node's `gate_verdict_summary`.
///
/// Renders as a colour-coded chip under each DAG node so an
/// operator scanning the initiative DAG can pivot on "which task
/// has a failing gate" without drilling into each node. Pinned to
/// the latest witness verdict per `(task_id, gate_type)` —
/// historical verdicts live on the per-task witness panel.
///
/// `latest_verdict` is one of `"Pass" | "Fail" | "Inconclusive"`
/// (matches `WitnessResultClass`). Adding a fourth class requires
/// a parallel edit on the FE chip palette so the new verdict has
/// a colour assignment.
#[derive(Debug, Clone, Serialize)]
pub struct DagGateVerdictChip {
    /// The gate this verdict applies to (e.g. `tests`, `coverage`).
    pub gate_type: String,
    /// One of `"Pass" | "Fail" | "Inconclusive"`.
    pub latest_verdict: String,
    /// Unix-seconds wall-clock of the latest witness for this gate.
    pub recorded_at: i64,
}

/// iter68 — `GET /api/tasks/:task_id/witnesses` wire view.
///
/// Projection of the `witness_records` row the dashboard renders
/// on the per-task page (one collapsible card per gate-type
/// outcome). Mirrors `raxis-store::views::witnesses::WitnessRow`
/// but with `recorded_at` as a signed Unix-seconds timestamp for
/// JSON-typed FE consumption.
///
/// **Wire-stable.** Schema changes to `witness_records` require a
/// parallel edit here so the FE does not silently start receiving
/// rows it cannot render. The route handler MUST NOT join across
/// `verifier_run_tokens` or read body blobs — those are kept
/// out-of-band (the body lives at `<data_dir>/witness/<sha256>`
/// and the dashboard offers a separate route for streaming it).
#[derive(Debug, Clone, Serialize)]
pub struct WitnessView {
    /// Stable id of the `VerifierRunToken` that this witness
    /// submission redeemed.
    pub verifier_run_id: String,
    /// Owning task.
    pub task_id: String,
    /// Gate the witness was attached to (e.g. `tests`, `coverage`).
    pub gate_type: String,
    /// One of `Pass | Fail | Inconclusive`. The FE renders this
    /// as a colour-coded pill.
    pub result_class: String,
    /// HEAD sha the verifier evaluated against. Pinned by the
    /// kernel-side `verifier_run_tokens.evaluation_sha`.
    pub evaluation_sha: String,
    /// SHA-256 of the verifier body blob on disk
    /// (`<data_dir>/witness/<blob_sha256>`).
    pub blob_sha256: String,
    /// Unix-seconds wall-clock when the witness was recorded.
    pub recorded_at: i64,
}

/// One row in `GET /api/tasks/:task_id/worktree-snapshots`.
///
/// iter68 — `specs/v3/worktree-snapshots.md` §3. Each row is a
/// point-in-time projection of the task's worktree. The four
/// `*_blob_sha256` fields are nullable (empty body → no blob);
/// the dashboard renders them as "view diff / log / tree / status"
/// links that hit `/api/worktree-snapshots/:id/blob/:kind`.
///
/// Wire-stable: this is exactly the shape the kernel-side
/// `worktree_snapshots` row projects to. Adding a column to the
/// SQL table requires bumping a new migration AND adding a field
/// here so the dashboard can render it.
#[derive(Debug, Clone, Serialize)]
pub struct WorktreeSnapshotView {
    /// Stable id; opaque to the FE.
    pub snapshot_id: String,
    /// The task this snapshot belongs to.
    pub task_id: String,
    /// Owning session id, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    /// Owning initiative id, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub initiative_id: Option<String>,
    /// One of `ExecutorActivate | ExecutorIdle | ExecutorCommitCopy |
    /// WitnessPass | WitnessFail | WitnessInconclusive |
    /// IntegrationMerge | PreGc`. Pinned to the kernel-side enum.
    pub trigger: String,
    /// Unix-seconds wall-clock when the snapshot was taken.
    pub taken_at: i64,
    /// Base commit the diff is rooted at.
    pub base_sha: String,
    /// Worktree HEAD commit at snapshot time.
    pub head_sha: String,
    /// Number of commits in `base..HEAD`.
    pub commit_count: u32,
    /// SHA-256 of `git diff <base>..HEAD` body, or null when the
    /// body is empty.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub diff_blob_sha256: Option<String>,
    /// SHA-256 of `git log <base>..HEAD --format=...`, or null.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub log_blob_sha256: Option<String>,
    /// SHA-256 of `git ls-tree -r HEAD --name-only`, or null.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tree_blob_sha256: Option<String>,
    /// SHA-256 of `git status --porcelain`, or null.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub porcelain_blob_sha256: Option<String>,
    /// Pre-truncation byte count of the diff body.
    pub diff_bytes_total: u64,
    /// `true` when the diff body was truncated at the 1 MiB cap
    /// (`INV-WORKTREE-SNAPSHOT-BOUNDED-DIFF-01`).
    pub diff_truncated: bool,
}

/// Body-kind selector for `GET /api/worktree-snapshots/:id/blob/:kind`.
///
/// iter68 — `specs/v3/worktree-snapshots.md` §5. The route handler
/// resolves the requested kind back onto the matching
/// `*_blob_sha256` column on the snapshot row, then streams the
/// blob body from `<data_dir>/worktree-snapshots/blobs/<sha256>`.
/// Pinning the enum here (rather than accepting an arbitrary
/// string) means a malformed URL surfaces as a 400 at axum's
/// extractor layer before the handler runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WorktreeSnapshotBlobKind {
    /// `git diff <base>..HEAD`. May be truncated.
    Diff,
    /// `git log <base>..HEAD --format=%H\t%an\t%at\t%s`.
    Log,
    /// `git ls-tree -r HEAD --name-only` — full tracked file
    /// listing at HEAD.
    Tree,
    /// `git status --porcelain` — uncommitted changes (usually
    /// empty for an executor at idle).
    Porcelain,
}

impl WorktreeSnapshotBlobKind {
    /// Round-trip with the route extractor.
    pub fn as_path_segment(self) -> &'static str {
        match self {
            Self::Diff => "diff",
            Self::Log => "log",
            Self::Tree => "tree",
            Self::Porcelain => "porcelain",
        }
    }

    /// Project the corresponding `*_blob_sha256` off a snapshot view.
    pub fn sha256_of(self, view: &WorktreeSnapshotView) -> Option<&str> {
        match self {
            Self::Diff => view.diff_blob_sha256.as_deref(),
            Self::Log => view.log_blob_sha256.as_deref(),
            Self::Tree => view.tree_blob_sha256.as_deref(),
            Self::Porcelain => view.porcelain_blob_sha256.as_deref(),
        }
    }
}

/// `GET /api/gates/stats` response envelope.
///
/// Rendered by the dashboard's Gates page (a minimal table
/// + sparkline panel). Stable, ordered by `gate_type` so a
///   future sparkline view can diff row-by-row without
///   reconciling positions.
#[derive(Debug, Clone, Serialize)]
pub struct GateStatsResponse {
    /// One row per `gate_type` observed in `witness_records`.
    /// Ordered alphabetically by `gate_type` for stable
    /// rendering.
    pub gates: Vec<GateStatRow>,
    /// Unix-seconds timestamp the rollup was computed.
    pub generated_at: i64,
}

/// One row in `GET /api/recent-sessions`. Surfaces sessions the
/// active list filtered out (revoked / expired) so an operator
/// can replay what the kernel last did before the session ended.
///
/// Backed by the `SessionStreamCapture` bounded ring buffer —
/// the kernel writes one ndjson per session as the agent runs;
/// when the session terminates the file persists for the ring's
/// lifetime. The dashboard reads file metadata + the capture's
/// sidecar lifecycle annotation to populate the row.
///
/// `INV-DASHBOARD-RECENT-SESSIONS-RING-01`.
#[derive(Debug, Clone, Serialize)]
pub struct RecentSessionEntry {
    /// Session id (matches `sessions.session_id`).
    pub session_id: String,
    /// Session role (`Orchestrator` / `Executor` / `Reviewer`).
    pub agent_type: String,
    /// Owning task id, when the kernel recorded one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task_id: Option<String>,
    /// Owning initiative id, when the kernel recorded one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub initiative_id: Option<String>,
    /// Unix-seconds timestamp the session was created.
    pub created_at: u64,
    /// Unix-seconds timestamp the session terminated.
    /// `None` when the session is still in the ring but has not
    /// been observed terminating yet (the capture file's mtime
    /// is the latest signal; kernel state is the authoritative
    /// truth and is reflected in `sessions.revoked` once
    /// `INV-DASHBOARD-SESSION-DETAIL-FORENSIC-01` lands).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terminated_at: Option<u64>,
    /// Free-form termination reason. `None` until the C1 marker
    /// pattern lands (Worker 1).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terminated_reason: Option<String>,
    /// Final lifecycle annotation for this session — typically
    /// one of `SessionRevokedSelfExit`, `SessionRevokedOperator`,
    /// or absent when the session is still nominally active.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub final_annotation: Option<LifecycleAnnotation>,
    /// Total bytes the capture ring is currently holding for
    /// this session. Useful for the operator to gauge whether
    /// the capture has been compacted.
    pub capture_bytes: u64,
}

// ---------------------------------------------------------------------------
// Operator failure visibility — INV-DASHBOARD-FAILURE-VISIBILITY-01
// ---------------------------------------------------------------------------

/// Structured failure detail surfaced alongside any entity the
/// dashboard renders in a `Failed` / `Rejected` / `Denied` state.
///
/// `INV-DASHBOARD-FAILURE-VISIBILITY-01` (see
/// `raxis/specs/invariants.md`): every failure or rejection event
/// surfaced via the dashboard MUST display its reason to the
/// operator. This shape is the wire-side carrier — the FE consumes
/// it through a single `<FailureReasonPanel>` component so every
/// failure surface in the dashboard renders the SAME way (kind,
/// message, structured fields, artifact links, copy-blob).
///
/// Shape rationale:
///   * `kind` — the audit-event discriminant or substrate-side
///     classification (`"SessionVmFailedFinal"`, `"PushFailed"`,
///     `"WitnessRejected"`, …). Stable, PascalCase. Operators
///     filter / group on this.
///   * `message` — the raw free-form message the kernel captured.
///     Operator-safe text — already truncated at the audit-event
///     emission site to 4 KiB max, and FORENSIC FIDELITY: the
///     dashboard MUST NOT re-truncate it (the operator needs the
///     whole reason to act).
///   * `fields` — definition-list rows for the structured payload
///     (`exit_code`, `target_host`, `worktree_path`, …). Each row
///     is a `(label, value)` pair so the FE never has to choose
///     the shape — extension is purely additive.
///   * `artifacts` — operator-actionable links (`kernel.stderr.log`,
///     audit-chain row, worktree path). Each is a
///     `(label, href)` pair. `href` is whatever the operator's
///     environment understands — relative dashboard paths
///     (`/audit#seq=42`), file-scheme paths
///     (`file:///var/raxis/sessions/.../kernel.stderr.log`), or
///     plain anchor text the FE renders as a non-link.
///   * `event_id` — when this failure is anchored to a specific
///     audit-chain row, the chain's `event_id` so the FE can deep-
///     link `/audit#evt=<id>`. None when the failure is synthesised
///     from a non-audit source (e.g. a substrate-side spawn
///     fail-final the dashboard reconstructed from kernel state).
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct FailureInfo {
    /// Stable kind / class discriminant (`"SessionVmFailedFinal"`,
    /// `"PushFailed"`, …). Always present.
    pub kind: String,
    /// Free-form operator-safe message. Always present (the kernel
    /// MUST supply a reason; an empty string indicates a kernel
    /// bug the FE surfaces as "No reason supplied — kernel bug").
    pub message: String,
    /// Structured payload rows (`(label, value)`). Empty when the
    /// failure has no structured fields beyond the message.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fields: Vec<FailureField>,
    /// Operator-actionable links (`(label, href)`). Empty when the
    /// failure has no artifact references.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub artifacts: Vec<FailureArtifact>,
    /// Audit-chain `event_id` (when the failure was projected from
    /// an audit row). `None` for substrate-side synthesised
    /// failures.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_id: Option<String>,
    /// Audit-chain `seq` (when the failure was projected from an
    /// audit row). `None` when `event_id` is `None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seq: Option<u64>,
    /// Unix-seconds when the failure was observed. `0` if unknown
    /// (the FE hides the timestamp row in that case).
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub observed_at: u64,
}

fn is_zero_u64(n: &u64) -> bool {
    *n == 0
}

/// One row inside [`FailureInfo::fields`]. Always a
/// `(label, value)` pair so the FE renders a uniform `<dl>`.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct FailureField {
    /// Row label (e.g. `"Exit code"`, `"Target host"`).
    pub label: String,
    /// Row value rendered as plain text (e.g. `"137"`,
    /// `"api.example.com"`).
    pub value: String,
}

/// One row inside [`FailureInfo::artifacts`]. The FE renders these
/// as anchor links when `href` looks navigable; plain text
/// otherwise. The dashboard MUST NOT validate / resolve hrefs —
/// they are operator-environment-specific.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct FailureArtifact {
    /// Link label (e.g. `"kernel.stderr.log"`,
    /// `"Audit chain row"`).
    pub label: String,
    /// Link target. Forward-slash separated when relative; full
    /// URL/URI when absolute.
    pub href: String,
}

impl FailureInfo {
    /// Minimal constructor: just a kind + message. Operators see
    /// the `kind` as a badge and the `message` as the body. Used
    /// by call sites that don't have structured fields or
    /// artifacts to attach.
    pub fn new(kind: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            kind: kind.into(),
            message: message.into(),
            fields: Vec::new(),
            artifacts: Vec::new(),
            event_id: None,
            seq: None,
            observed_at: 0,
        }
    }

    /// Builder: attach a structured field row.
    pub fn with_field(mut self, label: impl Into<String>, value: impl Into<String>) -> Self {
        self.fields.push(FailureField {
            label: label.into(),
            value: value.into(),
        });
        self
    }

    /// Builder: attach an operator-actionable artifact link.
    pub fn with_artifact(mut self, label: impl Into<String>, href: impl Into<String>) -> Self {
        self.artifacts.push(FailureArtifact {
            label: label.into(),
            href: href.into(),
        });
        self
    }

    /// Builder: pin this failure to a specific audit-chain row.
    pub fn with_audit(mut self, event_id: impl Into<String>, seq: u64) -> Self {
        self.event_id = Some(event_id.into());
        self.seq = Some(seq);
        self
    }

    /// Builder: stamp the observation timestamp (unix seconds).
    pub fn at(mut self, observed_at: u64) -> Self {
        self.observed_at = observed_at;
        self
    }
}

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
    /// Structured failure detail when the initiative is in a
    /// terminal `Failed` / `Aborted` / `Quarantined` state.
    /// `None` when the initiative is healthy. The FE renders
    /// this through a single `<FailureReasonPanel>` component;
    /// see `INV-DASHBOARD-FAILURE-VISIBILITY-01`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure: Option<FailureInfo>,
}

/// One DAG edge.
#[derive(Debug, Clone, Serialize)]
pub struct DagEdge {
    /// Predecessor task id.
    pub from: String,
    /// Successor task id.
    pub to: String,
}

// ---------------------------------------------------------------------------
// Initiative plan view — `GET /api/initiatives/:id/plan`
//
// `INV-DASHBOARD-INITIATIVE-PLAN-VISIBLE-01`: the dashboard surfaces
// the **original submitted** `plan.toml` for any approved initiative
// (V1: `signed_plan_artifacts.plan_bytes`; V2.1: the
// `plan_bundle_artifacts` row at `artifact_seq=0`,
// `artifact_name='plan.toml'`). The wire shape carries the bytes
// verbatim — the dashboard does NOT re-parse / re-serialize the TOML
// (forensic fidelity: a re-serialized plan would not match the
// audit-chain hash the operator pre-approved).
// ---------------------------------------------------------------------------

/// `GET /api/initiatives/:id/plan` response body.
///
/// `submitted_toml` is the byte-for-byte TOML the operator submitted
/// (decoded as UTF-8 — every plan TOML is UTF-8 by construction; a
/// malformed-UTF-8 row surfaces as
/// [`ApiError::Internal`] rather than mojibake on the wire).
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct InitiativePlanView {
    /// Owning initiative id.
    pub initiative_id: String,
    /// SHA-256 of the on-disk plan artifact (mirrors
    /// `InitiativeView::plan_sha256`). `None` for legacy V1 rows
    /// where the `plan_artifact_sha256` column was empty.
    pub plan_sha256: Option<String>,
    /// SHA-256 of the V2.1 plan bundle the operator sealed and
    /// submitted, lowercase hex. `None` for V1 plans (which used
    /// `signed_plan_artifacts` and did not seal a bundle).
    pub bundle_sha256: Option<String>,
    /// The original submitted `plan.toml` bytes decoded as UTF-8.
    /// **Byte-for-byte identical** to what the operator submitted —
    /// the dashboard does NOT re-parse or re-serialize the TOML.
    pub submitted_toml: String,
    /// Number of bytes in the submitted TOML (helps the FE size
    /// the editor + decide whether to virtualize).
    pub submitted_toml_bytes: u64,
    /// Unix-seconds timestamp the plan was submitted (V2.1: the
    /// bundle's `signed_at_unix_secs`; V1: `created_at` on the
    /// initiative row, since V1 had no separate sealed-at field).
    pub submitted_at_unix: i64,
    /// Operator pubkey fingerprint (lowercase hex, 16 bytes / 32
    /// hex chars) of whoever sealed the bundle. `None` for V1
    /// plans (which carried a detached signature on
    /// `signed_plan_artifacts.plan_sig` but not a separated
    /// fingerprint).
    pub submitted_by: Option<String>,
    /// Approval verdict:
    ///   * `"approved"` — initiative state has advanced past
    ///     `Draft` (`ApprovedPlan` / `Executing` / `Blocked` /
    ///     terminal). The plan is immutable from this point on,
    ///     and the FE caches aggressively (60 s).
    ///   * `"pending"` — initiative is still in `Draft`. The plan
    ///     can change; the FE should not aggressively cache.
    ///   * `"rejected"` — initiative reached a terminal-failure
    ///     state without ever advancing past `Draft` (e.g. the
    ///     plan failed admission validation).
    pub approval_status: String,
    /// Unix-seconds timestamp the plan was approved (initiative
    /// row's `approved_at`). `None` until approval lands.
    pub approved_at_unix: Option<i64>,
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
    /// Structured failure detail when the task is in a terminal
    /// `Failed` / `Blocked` state. `None` when the task is
    /// healthy. The FE renders this through a single
    /// `<FailureReasonPanel>` component; see
    /// `INV-DASHBOARD-FAILURE-VISIBILITY-01`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure: Option<FailureInfo>,
    /// Downstream task ids that are `Blocked` / `Pending` because
    /// of this task's failure. Empty when the task is healthy OR
    /// when no downstream task is currently blocked on it. The
    /// FE surfaces this on the DAG side-panel so an operator can
    /// see the failure cascade without re-walking the graph.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub blocked_downstream: Vec<String>,
    /// Causality annotations rendered by the dashboard's
    /// lifecycle timeline (retries, validator rejections,
    /// initiative-block markers, orchestrator gaps that name
    /// this task). Ordered by `ts_unix` ascending.
    /// `INV-DASHBOARD-LIFECYCLE-CAUSALITY-01`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub annotations: Vec<LifecycleAnnotation>,
    /// Most recent annotation, surfaced on the global tasks
    /// index for the "Lifecycle" column. `None` when the task
    /// has no annotations.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latest_annotation: Option<LifecycleAnnotation>,
    /// Most recent reviewer-panel verdict — `Approved`,
    /// `Rejected`, or absent. Mirrors `tasks.review_verdict`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub review_verdict: Option<String>,
    /// Captured aggregated reviewer critique. Mirrors
    /// `tasks.last_critique`. The FE renders this as a
    /// collapsible block beneath the verdict badge.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_critique: Option<String>,
    /// Per-reviewer panel results — one row per reviewer task
    /// downstream of this executor task — parsed from the audit
    /// chain's `SubmitReview` events.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reviewer_panel_results: Vec<ReviewerPanelEntry>,
    /// True when the task currently holds an `Active`
    /// `subtask_activations` row — i.e. an executor / reviewer
    /// VM is actively bound to the task in this very moment.
    ///
    /// The dashboard uses this as the "really running" signal
    /// because `tasks.state` flickers between `Running` and
    /// `Admitted` faster than the polling interval can observe
    /// (the FSM may transition through `Admitted` between VM
    /// hops while the activation row stays `Active` the whole
    /// time). Without this field operators see "Admitted" tasks
    /// in the dashboard for executors that ARE in fact running —
    /// the per-task lifecycle timeline shows the `SessionVmSpawned`
    /// row, but the index pages don't.
    ///
    /// `INV-DASHBOARD-PUSH-FSM-COMPLETENESS-01` covers the audit-
    /// emit completeness; this field covers the polling-resolution
    /// gap on the read side. Both are necessary because the
    /// dashboard polls at ~2s intervals while FSM hops can land
    /// in <100ms.
    #[serde(default)]
    pub is_active: bool,
}

/// One captured raw LLM turn surfaced via
/// `GET /api/tasks/:task_id/llm-turns`.
///
/// Iter64 wire shape — matches `dashboard-fe/src/types/api.ts ::
/// TaskLlmTurnView` field-for-field so the dashboard's per-task
/// LLM turns panel renders without an FE-side mapper. Previously
/// the wire emitted `at_ms` + `body: String` + no
/// `model`/`role`/`request`/usage breakdown, which left every
/// FE field except `latency_ms` rendering empty / `undefined`
/// `0` even though the kernel was capturing real data on
/// disk.
///
/// `INV-DASHBOARD-TASK-LLM-CAPTURE-01`,
/// `INV-DASHBOARD-LLM-TURN-PANEL-WIRE-SHAPE-01`.
#[derive(Debug, Clone, Serialize)]
pub struct TaskLlmTurnView {
    /// 1-indexed monotonic turn number per task (position in
    /// the per-task ring file). The dashboard renders this as
    /// "Turn 1", "Turn 2", … without sorting client-side.
    pub turn_number: u32,
    /// Unix-seconds capture timestamp (= `at_ms / 1000`).
    pub ts_unix: u64,
    /// Provider model id, lifted from the parsed response body
    /// (`body.model` for Anthropic; OpenAI / others follow the
    /// same field name). Empty string when the body is non-JSON
    /// or the field is absent.
    pub model: String,
    /// **LLM provider role** assignment: `"system"` / `"user"` /
    /// `"assistant"` / `"tool"`. Lifted from `body.role` for
    /// Anthropic; empty string when unknown. Distinct from
    /// [`Self::agent_role`] below — provider role is the
    /// upstream LLM speaker, agent role is which raxis agent
    /// originated the call.
    pub role: String,
    /// **Originating agent role**: `"Orchestrator"` /
    /// `"Executor"` / `"Reviewer"`. Set by the kernel-side
    /// [`raxis_kernel::handlers::planner_fetch`] at fetch-
    /// dispatch time from
    /// `session.session_agent_type`. Allows the dashboard to
    /// render a role badge per turn so operators can tell
    /// orchestrator planner_fetches apart from executor /
    /// reviewer rounds at a glance — crucial on an
    /// initiative's coordinator-task page where all three
    /// session types may interleave in the same `.jsonl`. `None`
    /// for legacy records that pre-date this field, or for the
    /// rare kernel-internal fetch issued without a planner
    /// session attribution.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_role: Option<String>,
    /// Fully-parsed REQUEST payload as a `serde_json::Value`.
    /// `Value::Null` when the kernel-side tap could not parse
    /// the bytes (or when no request was captured for this
    /// record — e.g. earlier records reloaded from disk).
    pub request: serde_json::Value,
    /// Fully-parsed RESPONSE payload as a `serde_json::Value`.
    /// On parse failure the projection falls back to
    /// `Value::String(raw_body)` so the operator still sees
    /// the bytes (e.g. an SSE stream that only partially
    /// arrived, or a transport error string).
    pub response: serde_json::Value,
    /// Per-turn token usage, lifted from `body.usage.*`.
    /// Anthropic: `input_tokens` / `output_tokens` /
    /// `cache_creation_input_tokens` / `cache_read_input_tokens`.
    /// OpenAI: `prompt_tokens` / `completion_tokens` (mapped
    /// onto `input_tokens` / `output_tokens`); cache fields
    /// remain `None`. Absent / non-JSON bodies leave all four
    /// fields `None`.
    pub input_tokens: Option<u32>,
    /// Output-token count for this turn (see `input_tokens`
    /// for the per-provider mapping).
    pub output_tokens: Option<u32>,
    /// Anthropic-only cache-write tokens (`body.usage.cache_creation_input_tokens`).
    /// `None` for OpenAI bodies and for absent / non-JSON
    /// bodies; see `input_tokens` for the cross-provider rule.
    pub cache_creation_input_tokens: Option<u32>,
    /// Anthropic-only cache-read tokens (`body.usage.cache_read_input_tokens`).
    /// `None` for OpenAI bodies and for absent / non-JSON
    /// bodies; see `input_tokens` for the cross-provider rule.
    pub cache_read_input_tokens: Option<u32>,
    /// Wall-clock latency from gateway outbound write to first
    /// response byte. Optional only because future capture
    /// shapes (e.g. streaming inference where the kernel
    /// records partial-completion turns) may not have a single
    /// "round-trip done" instant. Today the kernel always sets
    /// it.
    pub latency_ms: Option<u32>,
    /// Carry-overs that are useful for the dashboard but not
    /// in the FE TaskLlmTurnView contract today; serialise
    /// them so future FE views can pick them up without
    /// another wire bump (global "recent LLM activity" cross-
    /// task views are the canonical consumer).
    pub task_id: String,
    /// Owning session id for this turn; `None` when the turn
    /// fired before a session was bound (e.g. early bootstrap
    /// fetches the kernel issues to the planner endpoint).
    pub session_id: Option<String>,
    /// Per-fetch correlation id (`raxis_gateway::FetchId` hex)
    /// linking this dashboard row to the audit chain's
    /// `LlmFetchStarted` / `LlmFetchCompleted` pair.
    pub fetch_id: String,
    /// HTTP status from the upstream provider response.
    /// `None` for transport-level failures that never produced
    /// a status (DNS, connect, TLS handshake errors).
    pub status_code: Option<u16>,
    /// Original response body length, before per-record body
    /// cap truncation. `body_truncated` flips when the
    /// projection saw the kernel-side truncation marker.
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub original_body_bytes: u64,
    /// `true` when the projection truncated the response body
    /// (`response` is shorter than `original_body_bytes`); the
    /// dashboard surfaces a "[truncated]" badge in that case.
    #[serde(default, skip_serializing_if = "is_false")]
    pub body_truncated: bool,
    /// Structured upstream error category from the gateway
    /// (e.g. `"transport_timeout"`). `None` on success.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[allow(dead_code)]
fn is_false(b: &bool) -> bool {
    !*b
}

/// One on-disk record from the per-session capture ring
/// (`raxis-dashboard-kernel::SessionCapture`). Surfaced by
/// `GET /api/sessions/:session_id/capture`. The record kinds
/// the kernel observer appends are open-ended (`fsm_transition`,
/// `audit_event`, `ksb_snapshot`, and any future addition);
/// the FE renders the payload generically so a new kind lands
/// without a wire-shape bump.
///
/// `INV-DASHBOARD-SESSION-CAPTURE-FIXED-RING-01`,
/// `INV-DASHBOARD-SESSION-CAPTURE-PERSIST-AFTER-TERMINATION-01`,
/// `INV-DASHBOARD-SESSION-CAPTURE-NAMESPACED-PER-SESSION-01`
/// (`specs/v3/session-capture.md`).
#[derive(Debug, Clone, Serialize)]
pub struct SessionCaptureView {
    /// Owning session id (matches the URL path parameter).
    pub session_id: String,
    /// Record kind discriminator — `fsm_transition`,
    /// `audit_event`, `ksb_snapshot`, etc.
    pub kind: String,
    /// Unix seconds when the observer appended the record.
    pub ts_unix: i64,
    /// Free-form payload. The kernel observer encodes the
    /// per-kind shape; the dashboard renders it generically.
    pub payload: serde_json::Value,
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
    /// Structured failure detail when the session is in a
    /// terminal `Failed` / `Revoked` state. `None` when the
    /// session is healthy. The FE renders this through a single
    /// `<FailureReasonPanel>` component; see
    /// `INV-DASHBOARD-FAILURE-VISIBILITY-01`.
    ///
    /// Common kinds the kernel populates here:
    ///   * `"SessionVmFailedFinal"` — VM scaling exhausted retries.
    ///     `fields` carries `(failure_class, total_attempts,
    ///     final_reason)`; `artifacts` carries the
    ///     `kernel.stderr.log` path when available.
    ///   * `"SessionVmExited"` — non-graceful guest exit.
    ///     `fields` carries `(signal_class, exit_code,
    ///     backend_error)`.
    ///   * `"SessionRevoked"` — operator-initiated revocation.
    ///     `fields` carries `(revoked_by, revoked_by_display_name)`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure: Option<FailureInfo>,
    /// Causality annotations from the dashboard's lifecycle
    /// classifier — every `SessionRevoked{*}` /
    /// `InitiativeStateChanged{to=Blocked}` row whose
    /// `session_id` matches this row. The FE merges these
    /// inline with the live audit stream so an operator sees
    /// the structured "self-exit" / "operator-revoked by Foo"
    /// card alongside the raw frames.
    /// `INV-DASHBOARD-LIFECYCLE-CAUSALITY-01`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub annotations: Vec<LifecycleAnnotation>,
    /// Most recent annotation. The Sessions index renders this
    /// in the "Lifecycle" column so a list of terminated
    /// sessions immediately discloses self-exit vs operator-
    /// revoke without a click-through.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latest_annotation: Option<LifecycleAnnotation>,
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

/// Audit-chain integrity verdict surfaced by
/// `GET /api/audit/chain-status` — `INV-AUDIT-DASHBOARD-01`.
///
/// The verdict comes from the kernel's own
/// `raxis_audit_tools::verify_chain_from` walker; the dashboard
/// surfaces it but MUST NOT recompute it. `status` is one of:
///   * `"ok"` — every record's `prev_sha256` chains back to
///     genesis and `seq` is monotone.
///   * `"broken"` — at least one link mismatch or seq gap was
///     observed; `last_error` carries the short operator-safe
///     reason.
///   * `"unknown"` — verification has not run yet (the kernel
///     just booted, or the audit directory is absent). Treated
///     as a soft warn in the FE rather than a hard red.
#[derive(Debug, Clone, Serialize)]
pub struct ChainStatusView {
    /// Verdict discriminant — `"ok"` / `"broken"` / `"unknown"`.
    pub status: String,
    /// Highest seq the walker observed end-to-end. For
    /// `status = "ok"` this is the chain tail; for
    /// `status = "broken"` this is the seq the break was
    /// observed at (or the seq immediately before).
    pub last_verified_seq: u64,
    /// Number of records walked during the latest verify (only
    /// meaningful when `status = "ok"`; for broken / unknown
    /// chains the walker may have aborted early).
    pub total_records: u64,
    /// Number of distinct segment files contributing records.
    pub segment_count: u64,
    /// Unix-milliseconds timestamp when this verdict was
    /// produced. `0` ⇒ the data layer has not run a verify
    /// yet (`status = "unknown"`).
    pub verified_at_ms: u64,
    /// Operator-safe reason string when `status = "broken"`.
    /// `None` on `ok` / `unknown`.
    pub last_error: Option<String>,
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
    /// `SHA-256[:16]` hex fingerprint.
    pub fingerprint: String,
    /// Display name.
    pub display_name: String,
    /// Permitted operator-IPC operations.
    pub permitted_ops: Vec<String>,
}

/// Outcome of `PUT /api/policy/toml`. Mirrors the kernel's
/// `policy_manager::AdvanceOutcome` for the dashboard wire
/// surface — every field comes straight off the verified
/// artifact + the write transaction's return values.
#[derive(Debug, Clone, Serialize)]
pub struct PolicyAdvancement {
    /// Epoch the kernel was running before the advance.
    pub previous_epoch: u64,
    /// Epoch the kernel is running after the advance.
    pub new_epoch: u64,
    /// SHA-256 of the new policy artifact bytes (lowercase hex).
    pub policy_sha256: String,
    /// Operator id from `meta.signed_by` on the new artifact.
    /// Mirrors `policy_manager::AdvanceOutcome::signed_by_authority`
    /// — the FIELD NAME is preserved so wire-shape consumers
    /// don't have to special-case the dashboard surface.
    pub signed_by_authority: String,
    /// Number of session-prompt cache entries marked stale by
    /// the epoch swap (forensic visibility for the operator UI).
    pub n_sessions_invalidated: u64,
    /// Number of pending delegations marked stale by the epoch
    /// swap (forensic visibility for the operator UI).
    pub n_delegations_marked_stale: u64,
    /// Unix-seconds timestamp recorded on the
    /// `policy_epoch_history` row.
    pub advanced_at: u64,
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

/// One entry in a worktree directory listing returned by
/// `GET /api/git/worktrees/:name/tree`.
///
/// Symlinks are reported as `kind = "symlink"` and never
/// followed for sizing/listing — the kernel-side
/// implementation refuses to surface symlink targets that
/// resolve outside the worktree root.
#[derive(Debug, Clone, Serialize)]
pub struct WorktreeTreeEntry {
    /// Basename of the entry (no path separators).
    pub name: String,
    /// Path relative to the worktree root (forward-slash
    /// separated, no leading slash).
    pub path: String,
    /// `"file"`, `"dir"`, `"symlink"`, or `"other"`.
    pub kind: String,
    /// Size in bytes (regular files only). `None` for
    /// directories / symlinks / other.
    pub size: Option<u64>,
}

/// Directory listing returned by
/// `GET /api/git/worktrees/:name/tree`.
#[derive(Debug, Clone, Serialize)]
pub struct WorktreeTree {
    /// Worktree slug.
    pub name: String,
    /// Path relative to the worktree root that was listed
    /// (`""` ⇒ root). Forward-slash separated.
    pub path: String,
    /// Entries in the directory, sorted directories-first then
    /// alphabetical.
    pub entries: Vec<WorktreeTreeEntry>,
    /// `true` when the listing was capped by the per-request
    /// entry budget; the caller should refine the path.
    pub truncated: bool,
}

/// File content returned by
/// `GET /api/git/worktrees/:name/file`.
///
/// `encoding = "utf8"` ⇒ `content` is the literal file body.
/// `encoding = "base64"` ⇒ `content` is standard-base64
/// (no padding stripped) of the raw bytes; the frontend
/// can decide whether to render as a hex dump, image
/// preview, or "binary file" placeholder.
#[derive(Debug, Clone, Serialize)]
pub struct WorktreeFile {
    /// Worktree slug.
    pub name: String,
    /// Path relative to the worktree root.
    pub path: String,
    /// Size in bytes of the underlying file.
    pub size: u64,
    /// `"utf8"` or `"base64"`.
    pub encoding: String,
    /// File content (UTF-8 string or base64 of raw bytes).
    pub content: String,
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

/// Per-subsystem health card surfaced on the dashboard Health
/// tab (`GET /api/health/subsystems`). One card per kernel
/// subsystem the dashboard enumerates: kernel main loop, audit
/// writer, credential proxies, egress admission, session-spawn
/// pool, planner registry, observability pusher, git worktree
/// pool, dashboard SSE pump.
///
/// The verdict comes from the kernel's own bookkeeping — the
/// dashboard never invents a status. When the kernel has not
/// reported recently the data layer rolls the card to
/// `"unknown"` with a short reason; broken-status pinning is
/// for hard failures the kernel actively reported.
#[derive(Debug, Clone, Serialize)]
pub struct SubsystemHealthCard {
    /// Stable subsystem identifier matching the kernel-side
    /// taxonomy. One of:
    ///   * `"kernel_main_loop"`
    ///   * `"audit_writer"`
    ///   * `"credential_proxies"`
    ///   * `"egress_admission"`
    ///   * `"session_spawn_pool"`
    ///   * `"planner_registry"`
    ///   * `"observability_pusher"`
    ///   * `"git_worktree_pool"`
    ///   * `"dashboard_sse_pump"`
    pub id: String,
    /// Human-readable card title (e.g. `"Kernel main loop"`).
    pub label: String,
    /// Status discriminant — `"ok"` / `"degraded"` / `"failing"`
    /// `"unknown"`.
    pub status: String,
    /// One-line operator-safe summary surfaced on the card.
    pub summary: String,
    /// Structured per-card detail rows the FE renders inside
    /// the drill-down. Each entry is a `(label, value)` pair so
    /// the FE never has to choose the shape — extension is
    /// purely additive.
    pub details: Vec<SubsystemDetailRow>,
    /// Optional Grafana deep-link the FE renders as a button on
    /// the card. `None` ⇒ no live dashboard for this subsystem;
    /// the FE hides the button. The observability worker just
    /// landed the URL block; this field carries the resolved
    /// dashboard link.
    pub grafana_url: Option<String>,
    /// Unix-seconds when the kernel last reported on this
    /// subsystem. `0` ⇒ never reported.
    pub last_observed_at: u64,
    /// Operator-safe error string when the subsystem is
    /// `degraded` / `failing`. `None` on `ok` / `unknown`.
    ///
    /// `INV-DASHBOARD-FAILURE-VISIBILITY-01`: a degraded or
    /// failing subsystem MUST surface a reason — the FE renders
    /// this through the `<FailureReasonPanel>` shared component
    /// inside the card body. An empty / missing `last_error`
    /// when `status != "ok"` is operator-actionable: the kernel
    /// bookkeeping owes a reason and the FE surfaces
    /// `"No reason supplied — kernel bug"` so the gap is
    /// visible rather than silently swallowed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
}

/// One row inside a [`SubsystemHealthCard`]'s drill-down.
#[derive(Debug, Clone, Serialize)]
pub struct SubsystemDetailRow {
    /// Row label (e.g. `"Backlog depth"`).
    pub label: String,
    /// Row value (e.g. `"42"` / `"online"` / `"2 retries"`).
    pub value: String,
}

/// Canonical list of every kernel subsystem the dashboard
/// enumerates on the Health tab. Order is the order the FE
/// renders the grid in. Append-only — new subsystems land at
/// the bottom so the FE's per-tile DOM keys stay stable.
pub const SUBSYSTEM_CATALOG: &[(&str, &str)] = &[
    ("kernel_main_loop", "Kernel main loop"),
    ("audit_writer", "Audit writer"),
    ("credential_proxies", "Credential proxies"),
    ("egress_admission", "Egress admission"),
    ("session_spawn_pool", "Session-spawn pool"),
    ("planner_registry", "Planner registry"),
    ("observability_pusher", "Observability pusher"),
    ("git_worktree_pool", "Git worktree pool"),
    ("dashboard_sse_pump", "Dashboard SSE pump"),
];

/// Response envelope returned by `GET /api/health/subsystems`.
///
/// Coarse `aggregate_status` is the worst per-card status,
/// surfaced separately so the FE Health tab can render a
/// single banner tone without re-computing.
#[derive(Debug, Clone, Serialize)]
pub struct SubsystemHealthResponse {
    /// Aggregate status across all cards (`ok` / `degraded`
    /// `failing` / `unknown`).
    pub aggregate_status: String,
    /// One card per kernel subsystem the dashboard enumerates.
    pub cards: Vec<SubsystemHealthCard>,
    /// Unix-millis when this snapshot was assembled. The FE
    /// uses this for "Last refreshed at …" affordance.
    pub generated_at_ms: u64,
}

// ---------------------------------------------------------------------------
// Credential viewer surfaces — INV-DASHBOARD-CREDENTIAL-* family
// ---------------------------------------------------------------------------

/// Metadata for a single credential surfaced on the dashboard. The
/// shape is identical for per-initiative and system credentials —
/// the routing layer carries the scope context separately. NEVER
/// carries plaintext bytes; the `reveal` endpoint is the only
/// surface that returns `bytes` and it does so on a separate JSON
/// shape ([`CredentialReveal`]).
///
/// `INV-DASHBOARD-CREDENTIAL-DEFAULT-MASKED-01`: a listing endpoint
/// that ever returned plaintext would silently violate this
/// invariant. The struct deliberately has no `bytes` / `value` /
/// `plaintext` field so a future refactor cannot accidentally add
/// one.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct CredentialMetadata {
    /// Stable credential name as declared in the plan
    /// (`<name>` for per-initiative credentials,
    /// `providers.<id>` for system credentials). Matches
    /// `task_credential_proxies.credential_name`.
    pub name: String,
    /// Stable proxy-type discriminant (`postgres` / `http` /
    /// `k8s` / `redis` / `aws` / `gcp` / `azure` / `mysql` /
    /// `mssql` / `mongodb` / `smtp` / `provider`). For
    /// system credentials this is always `"provider"`; for
    /// per-initiative credentials this mirrors the proxy
    /// declaration.
    pub proxy_type: String,
    /// Env-var name the credential is mounted as inside the agent
    /// VM (e.g. `DATABASE_URL`). `None` for system credentials
    /// (gateway-bound, never reaches an agent VM).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mount_as: Option<String>,
    /// Operator-safe hint about the on-disk wire format
    /// (e.g. `"libpq URL (postgresql://user:pass@host:port/db)"`,
    /// `"Anthropic provider TOML (api_key = \"…\")"`). Used by the
    /// FE to render a "what to expect" line above the reveal
    /// modal so the operator can confirm they're about to look
    /// at the right shape.
    pub format_hint: String,
    /// Optional upstream `host:port` derived from the proxy
    /// declaration (e.g. `127.0.0.1:5432` for a Postgres proxy).
    /// `None` when the proxy variant has no upstream concept
    /// (k8s, aws, gcp, azure, system credentials).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upstream_host_port: Option<String>,
    /// Size of the credential file in bytes. `0` when the file
    /// does not yet exist on disk (the kernel surfaced a
    /// declaration without a backing file). The FE renders the
    /// missing-file case in red so the operator can see the gap.
    pub byte_size: u64,
    /// First 8 lowercase hex chars of the SHA-256 of the
    /// credential bytes. `None` when the file does not yet
    /// exist. The full digest is NEVER surfaced — 8 hex chars
    /// is enough fingerprint to recognise a rotation; more
    /// would let a low-privilege observer correlate against
    /// known plaintext.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256_prefix: Option<String>,
    /// Absolute on-disk path the credential was loaded from
    /// (e.g. `/var/raxis/credentials/test-pg-dev.env`). `None`
    /// for backends that don't have a file path concept (Vault,
    /// AWS-SM, Azure KV, HSM). Operators use this to verify
    /// they're looking at the right file before they reveal.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub loaded_from_path: Option<String>,
    /// `true` iff the dashboard has a reveal endpoint for this
    /// credential. Always `true` today (every backend supports
    /// reveal); reserved for future backends (HSM-only) that
    /// expose the credential to the kernel but not to the
    /// dashboard.
    pub is_revealable: bool,
    /// Wire-stable role string the caller MUST hold to reveal
    /// (`"admin"` per `INV-DASHBOARD-CREDENTIAL-REVEAL-ROLE-GATED-01`).
    /// The FE consumes this verbatim to disable the reveal
    /// button for `read`-role operators with the right tooltip.
    pub reveal_required_role: String,
}

/// Wire shape returned by the per-initiative listing endpoint
/// `GET /api/initiatives/:id/credentials`.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct CredentialListResponse {
    /// Credentials bound to this initiative's plan (or, for the
    /// system endpoint, every system credential the kernel
    /// knows about). Ordered by `name` for deterministic
    /// rendering.
    pub credentials: Vec<CredentialMetadata>,
}

/// Wire shape returned by a successful reveal call. Carries the
/// plaintext (UTF-8 string), the byte size, and the unix-seconds
/// timestamp the FE should auto-hide at (`expires_at_unix`).
///
/// `INV-DASHBOARD-CREDENTIAL-AUTO-HIDE-01`: the response includes
/// the auto-hide deadline so the FE doesn't have to track which
/// kind of credential it just revealed (per-initiative auto-hides
/// at 30s; system at 15s).
#[derive(Clone, Serialize, PartialEq, Eq)]
pub struct CredentialReveal {
    /// Credential name (echoed for FE state validation).
    pub name: String,
    /// Plaintext bytes as a UTF-8 string. Binary credentials are
    /// surfaced as `encoding = "base64"` and the `plaintext` field
    /// holds the standard-base64 encoding (no padding stripped).
    ///
    /// `INV-DASHBOARD-ANTHROPIC-CREDENTIAL-SEVERITY-01` defence-
    /// in-depth: this field is REDACTED in the manual `Debug` impl
    /// below so a future `tracing::debug!("{reveal:?}")` cannot
    /// accidentally leak the bytes. Serialisation (the only sanctioned
    /// exfil path) goes through the `Serialize` derive, which IS
    /// allowed to surface the value.
    pub plaintext: String,
    /// `"utf8"` (the credential parsed as UTF-8) or `"base64"`
    /// (binary, base64-encoded). The FE renders binary as a hex
    /// dump.
    pub encoding: String,
    /// Size of the underlying credential bytes (NOT the encoded
    /// representation).
    pub byte_size: u64,
    /// Unix-seconds timestamp the FE should auto-hide the
    /// plaintext at. The FE MUST honour this even if the user
    /// has the page open — every reveal is on a deadline.
    pub expires_at_unix: u64,
    /// First 8 lowercase hex chars of the SHA-256 of the
    /// credential bytes. The FE shows this in the reveal banner
    /// so the operator can sanity-check what they're looking at
    /// without saving the plaintext.
    pub sha256_prefix: String,
}

// `INV-DASHBOARD-ANTHROPIC-CREDENTIAL-SEVERITY-01` defence-in-
// depth — the manual `Debug` impl REPLACES the value with
// `<redacted>` so log lines that accidentally interpolate a
// `CredentialReveal` (`tracing::error!("{reveal:?}")`,
// `panic!("{reveal:?}")`, `dbg!(reveal)`, …) cannot leak the
// plaintext.
impl std::fmt::Debug for CredentialReveal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CredentialReveal")
            .field("name", &self.name)
            .field("plaintext", &"<redacted>")
            .field("encoding", &self.encoding)
            .field("byte_size", &self.byte_size)
            .field("expires_at_unix", &self.expires_at_unix)
            .field("sha256_prefix", &self.sha256_prefix)
            .finish()
    }
}

/// Stable wire-string label for the dashboard's credential rate
/// limiter. The route layer captures the limit + window from
/// `crate::config::DashboardConfig::reveal_rate_limit_per_window`
/// and `reveal_rate_limit_window_secs`; the data layer enforces
/// it via `enforce_reveal_rate_limit` so a future test fixture or
/// a future second backend (Vault) can re-use the same throttle
/// surface.
pub const REVEAL_RATE_LIMIT_LABEL: &str = "credential_reveal";

/// Notification row surfaced by `GET /api/notifications`.
#[derive(Debug, Clone, Serialize)]
pub struct NotificationView {
    /// UUID notification id.
    pub notification_id: String,
    /// Event kind that triggered this notification.
    pub event_kind: String,
    /// Owning initiative id (if any).
    pub initiative_id: Option<String>,
    /// Owning task id (if any).
    pub task_id: Option<String>,
    /// Owning session id (if any).
    pub session_id: Option<String>,
    /// Human-readable summary.
    pub summary: String,
    /// Structured JSON payload.
    pub payload: serde_json::Value,
    /// Whether the operator has marked this notification as read.
    pub read: bool,
    /// Source audit event id for correlation.
    pub source_event_id: String,
    /// Unix-seconds creation timestamp.
    pub created_at: u64,
    /// `INV-NOTIF-SCOPE-01` projection of `event_kind` through
    /// `raxis_dashboard_kernel::notification_priority_for_kind_str`.
    /// One of `"Critical"`, `"High"`, `"Medium"`, `"Low"`, or
    /// `null`. The kernel-glue layer
    /// (`dashboard-kernel::KernelDashboardData::list_notifications`)
    /// is the single producer; the dashboard FE consumes the
    /// string verbatim to render priority icons and the filter
    /// pills. `None` here means the row pre-dates the
    /// `notification_priority` filter (legacy data), in which
    /// case the FE renders it as an "unclassified" Low-tier
    /// fallback rather than dropping it. The taxonomy itself
    /// lives in `crates/dashboard-kernel/src/notification_filter.rs`
    /// and is exhaustive over `AuditEventKind`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub priority: Option<String>,
}

/// Trait the kernel implements. Default impls are NOT provided
/// — the kernel-glue code MUST wire every method.
pub trait DashboardData: Send + Sync + 'static {
    /// Resolve an operator's roles by pubkey fingerprint. Used
    /// by the dashboard auth layer to fold the cert's
    /// permitted-ops into a [`OperatorRole`] list before the
    /// JWT is minted. `None` ⇒ unknown operator (HTTP 401).
    fn lookup_operator_roles(&self, fingerprint: &str) -> Option<OperatorAuthResolution>;

    /// Health snapshot for `GET /api/health`.
    fn health(&self) -> HealthSnapshot;

    /// Per-subsystem health snapshot for the dashboard Health
    /// tab. Returns one [`SubsystemHealthCard`] per kernel
    /// subsystem the dashboard enumerates. Verdicts come from
    /// the kernel's own bookkeeping — the dashboard never
    /// invents a status (`INV-DASHBOARD-VALIDATE-01`).
    fn subsystem_health(&self) -> Result<SubsystemHealthResponse, ApiError>;

    /// Paginated initiative list (newest first). `limit ≤ 200`.
    fn list_initiatives(
        &self,
        limit: u32,
        state_filter: Option<&str>,
    ) -> Result<Vec<InitiativeListEntry>, ApiError>;

    /// Initiative detail (with task list + DAG edges).
    fn get_initiative(&self, id: &str) -> Result<InitiativeView, ApiError>;

    /// Original submitted `plan.toml` for one initiative.
    /// `INV-DASHBOARD-INITIATIVE-PLAN-VISIBLE-01`.
    ///
    /// Implementations:
    ///   * MUST return the **byte-for-byte original** TOML the
    ///     operator submitted (no re-parse / re-serialize).
    ///   * MUST return `Err(ApiError::NotFound { kind: "initiative" })`
    ///     when the initiative id does not exist.
    ///   * MUST return `Err(ApiError::Gone { kind: "plan" })` when
    ///     the initiative exists but the on-disk plan artifact has
    ///     been archived / purged — distinct from 404 so the FE
    ///     can render an "archived" copy rather than "not found".
    ///   * MUST return `Err(ApiError::Internal { .. })` ONLY for
    ///     genuine infrastructure failures (DB read, malformed
    ///     UTF-8 in a column the DDL pinned to TEXT). Errors on
    ///     this path are forensically loud — the operator action
    ///     route layer surfaces a structured envelope.
    fn get_initiative_plan(&self, id: &str) -> Result<InitiativePlanView, ApiError>;

    /// Tasks for one initiative.
    fn list_tasks(&self, initiative_id: &str) -> Result<Vec<TaskView>, ApiError>;

    /// One task by id.
    fn get_task(&self, task_id: &str) -> Result<TaskView, ApiError>;

    /// Tail the last `n` raw LLM-turn records captured for a
    /// task. The records are the upstream provider's raw
    /// response envelopes (status + body + latency), keyed by
    /// `task_id` so the buffer survives VM restarts within the
    /// same task. Backed by the kernel's per-task on-disk file
    /// ring (see `raxis-dashboard-kernel::TaskLlmCapture`).
    ///
    /// Default impl returns `Ok(vec![])` so older test fixtures
    /// (and the in-memory data layer used by the auth /
    /// integration tests) compile without the new capability.
    /// The kernel-glue impl in `raxis-dashboard-kernel`
    /// overrides this to call the file-ring tail.
    ///
    /// `INV-DASHBOARD-TASK-LLM-CAPTURE-01` (raxis/specs/invariants.md).
    fn tail_task_llm_turns(
        &self,
        _task_id: &str,
        _n: u32,
    ) -> Result<Vec<TaskLlmTurnView>, ApiError> {
        Ok(Vec::new())
    }

    /// List currently-stuck `PendingActivation` rows whose
    /// predecessors are all `Completed` and whose `created_at`
    /// is older than the 120-second cutoff. Backed by the pure
    /// `lifecycle::classify_orchestrator_gaps` classifier.
    ///
    /// Default impl returns an empty response so older test
    /// fixtures + the in-memory data layer compile without the
    /// new capability. Production wires this through
    /// `KernelDashboardData`.
    ///
    /// `INV-DASHBOARD-LIFECYCLE-CAUSALITY-01`.
    fn list_orchestrator_gaps(&self) -> Result<OrchestratorGapsResponse, ApiError> {
        Ok(OrchestratorGapsResponse {
            gaps: Vec::new(),
            generated_at: 0,
        })
    }

    /// V3 — `INV-DASHBOARD-GATE-STATS-PER-GATE-ROLLUP-01`.
    ///
    /// Per-gate rollup of witness outcomes + cumulative fixup
    /// loop count. Default impl returns an empty response so the
    /// in-memory data layer + older test fixtures continue to
    /// compile without the new capability. The production
    /// `KernelDashboardData` overrides this to read the
    /// `witness_records` + `tasks` tables.
    ///
    /// **Authoring contract.**
    /// - Implementations MUST return rows alphabetically sorted
    ///   by `gate_type` so a sparkline panel can diff row-by-row
    ///   across polls.
    /// - `generated_at` MUST be set to the wall-clock at which
    ///   the rollup was computed (not 0); callers use it to
    ///   render a "last refreshed" badge.
    /// - On store errors the implementation MUST surface
    ///   `Err(ApiError::Internal)` rather than an empty
    ///   response — a silent zero would mask a stuck rollup.
    fn gate_stats(&self) -> Result<GateStatsResponse, ApiError> {
        Ok(GateStatsResponse {
            gates: Vec::new(),
            generated_at: 0,
        })
    }

    /// iter68 PR 5 — `GET /api/witnesses?limit=N`.
    ///
    /// Returns the most-recent N witnesses across every task,
    /// newest first. Powers the standalone Witnesses page (a
    /// cross-task timeline operators use when investigating
    /// gate-rejection patterns spanning multiple initiatives).
    ///
    /// Default impl returns `Ok(vec![])`. Production wires this
    /// through `KernelDashboardData::list_recent_witnesses`. The
    /// implementation MUST cap `limit` at 500 (mirrors the LLM
    /// turns endpoint's contract) to keep the wire response
    /// bounded; the route handler enforces the cap server-side
    /// rather than trusting the FE.
    fn list_recent_witnesses(&self, _limit: u32) -> Result<Vec<WitnessView>, ApiError> {
        Ok(Vec::new())
    }

    /// iter68 — `GET /api/tasks/:task_id/witnesses`.
    ///
    /// Returns every witness recorded against the task, newest
    /// first, projected onto [`WitnessView`]. Default impl returns
    /// `Ok(vec![])` so older fixtures + the in-memory data layer
    /// compile without the new capability; production wires this
    /// through `KernelDashboardData::list_witnesses_for_task`.
    ///
    /// **Wire contract.** Ordered by `recorded_at DESC` so the
    /// most-recent verdict is row 0 — the dashboard renders the
    /// timeline top-down. Rows where `result_class != "Pass"`
    /// carry the gate-rejection critique implicitly through the
    /// `blob_sha256` body file (operator opens the body via a
    /// separate route).
    fn list_witnesses_for_task(&self, _task_id: &str) -> Result<Vec<WitnessView>, ApiError> {
        Ok(Vec::new())
    }

    /// iter68 PR 4 — per-task latest-verdict-per-gate rollup for
    /// every task in `initiative_id`. Returns a map
    /// `task_id → Vec<DagGateVerdictChip>`. Used by the DAG handler
    /// to attach colour-coded gate chips to each `DagNode` without
    /// issuing N queries (one per task).
    ///
    /// Default impl returns an empty map; production wires this
    /// through `KernelDashboardData::list_dag_gate_summaries`
    /// using a single aggregating SQL query.
    ///
    /// **Wire contract.** Each `Vec<DagGateVerdictChip>` is
    /// alphabetically ordered by `gate_type` so the FE renders
    /// chips in a stable column order. Tasks with no witnesses
    /// are absent from the map (callers default to `Vec::new()`).
    fn list_dag_gate_summaries(
        &self,
        _initiative_id: &str,
    ) -> Result<std::collections::HashMap<String, Vec<DagGateVerdictChip>>, ApiError> {
        Ok(std::collections::HashMap::new())
    }

    /// iter68 — `specs/v3/worktree-snapshots.md` §5.
    ///
    /// List every worktree snapshot the kernel captured for the
    /// task, newest first. Powers `GET
    /// /api/tasks/:task_id/worktree-snapshots`.
    ///
    /// Default impl returns `Ok(vec![])` so older fixtures
    /// continue compiling without the new capability. Production
    /// wires this through `KernelDashboardData::list_worktree_snapshots`.
    fn list_worktree_snapshots(
        &self,
        _task_id: &str,
    ) -> Result<Vec<WorktreeSnapshotView>, ApiError> {
        Ok(Vec::new())
    }

    /// iter68 — `specs/v3/worktree-snapshots.md` §5.
    ///
    /// Look up one snapshot row by id. Powers `GET
    /// /api/worktree-snapshots/:snapshot_id`. Returns
    /// `Err(NotFound { kind: "worktree_snapshot" })` for an
    /// unknown id so the route returns 404 with a stable shape.
    fn get_worktree_snapshot(&self, _snapshot_id: &str) -> Result<WorktreeSnapshotView, ApiError> {
        Err(ApiError::NotFound {
            kind: "worktree_snapshot".into(),
        })
    }

    /// iter68 — `specs/v3/worktree-snapshots.md` §5.
    ///
    /// Stream a body blob (`diff` / `log` / `tree` / `porcelain`)
    /// for the requested snapshot. The route handler resolves
    /// `kind` back onto the matching `*_blob_sha256` column,
    /// then this method reads the on-disk blob.
    ///
    /// Returns `Err(NotFound)` when:
    ///   * the snapshot id is unknown, OR
    ///   * the requested body kind was empty (no `*_blob_sha256`
    ///     value on the row — there is genuinely nothing to
    ///     stream), OR
    ///   * the blob file is missing on disk (operator manually
    ///     deleted; orphan-detection log will surface it).
    ///
    /// Default impl returns `NotFound`. Production wires this
    /// through `KernelDashboardData`.
    fn read_worktree_snapshot_blob(
        &self,
        _snapshot_id: &str,
        _kind: WorktreeSnapshotBlobKind,
    ) -> Result<Vec<u8>, ApiError> {
        Err(ApiError::NotFound {
            kind: "worktree_snapshot_blob".into(),
        })
    }

    /// List the most-recent N completed / terminated sessions
    /// the dashboard's `SessionStreamCapture` ring is still
    /// holding. Powers the Recent Sessions view (C3) so an
    /// operator sees ended sessions previously dropped from the
    /// active session list.
    ///
    /// Default impl returns `Ok(vec![])` so older fixtures
    /// continue compiling. Production wires this through the
    /// kernel-glue layer.
    fn list_recent_sessions(&self, _limit: u32) -> Result<Vec<RecentSessionEntry>, ApiError> {
        Ok(Vec::new())
    }

    /// Sessions newest first. `limit ≤ 200`.
    /// Active session list. When `initiative_id` is `Some(_)` the
    /// data layer narrows the result to sessions associated with
    /// that initiative (via the `tasks.session_id` join — the
    /// `sessions` catalog itself does not carry initiative FK).
    /// Routed from `GET /api/sessions?initiative_id=…`.
    fn list_sessions(
        &self,
        limit: u32,
        initiative_id: Option<&str>,
    ) -> Result<Vec<SessionView>, ApiError>;

    /// One session.
    fn get_session(&self, session_id: &str) -> Result<SessionView, ApiError>;

    /// Tail the last `n` records from the per-session lifecycle
    /// capture ring (`raxis-dashboard-kernel::SessionCapture`).
    /// Backs `GET /api/sessions/:session_id/capture?limit=N`.
    ///
    /// Default impl returns `Ok(vec![])` so older test
    /// fixtures (and the in-memory data layer used by the
    /// auth / integration tests) compile without the new
    /// capability. The kernel-glue impl in
    /// `raxis-dashboard-kernel` overrides this to call the
    /// file-ring tail.
    ///
    /// `INV-DASHBOARD-SESSION-CAPTURE-FIXED-RING-01`,
    /// `INV-DASHBOARD-SESSION-CAPTURE-PERSIST-AFTER-TERMINATION-01`,
    /// `INV-DASHBOARD-SESSION-CAPTURE-NAMESPACED-PER-SESSION-01`
    /// (`specs/v3/session-capture.md`).
    fn tail_session_capture(
        &self,
        _session_id: &str,
        _n: u32,
    ) -> Result<Vec<SessionCaptureView>, ApiError> {
        Ok(Vec::new())
    }

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

    /// Return the kernel's audit-chain integrity verdict per
    /// `INV-AUDIT-DASHBOARD-01`. Implementations MUST drive the
    /// verdict through `raxis_audit_tools::verify_chain_from`
    /// (or an equivalent kernel-side walker); the dashboard
    /// MUST NOT reimplement the chain walk.
    ///
    /// `reverify = false` ⇒ return the cached verdict if it is
    /// fresh enough (the implementation defines "fresh enough" —
    /// the production kernel rate-limits to one walk per
    /// 30 seconds). `reverify = true` ⇒ force a fresh walk.
    ///
    /// Returns `(fresh, view)` — `fresh` is `true` iff the
    /// implementation actually walked the chain for this call
    /// (vs returning a cached verdict); `view` is the verdict.
    fn audit_chain_status(&self, reverify: bool) -> Result<(bool, ChainStatusView), ApiError>;

    /// List notifications from the kernel's `notifications` table.
    /// `unread_only = true` filters to unread only.
    /// `limit` caps the result set (≤ 200).
    fn list_notifications(
        &self,
        limit: u32,
        unread_only: bool,
        initiative_id: Option<&str>,
    ) -> Result<Vec<NotificationView>, ApiError>;

    /// Count of unread notifications (for badge rendering).
    fn notification_count_unread(&self) -> Result<u64, ApiError>;

    /// Mark a single notification as read. Returns `true` if a
    /// row was actually updated.
    fn mark_notification_read(&self, notification_id: &str) -> Result<bool, ApiError>;

    /// Mark all notifications as read. Returns the count of
    /// rows updated.
    fn mark_all_notifications_read(&self) -> Result<u64, ApiError>;

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
    fn worktree_log(&self, name: &str, limit: u32) -> Result<Vec<WorktreeLogEntry>, ApiError>;

    /// Diff between the worktree's `HEAD` and its recorded
    /// base SHA. `Err(NotFound)` ⇒ no base recorded for the
    /// worktree (e.g. main worktrees with no upstream pin).
    fn worktree_diff_default(&self, name: &str) -> Result<WorktreeDiff, ApiError>;

    /// Diff between two arbitrary commit SHAs in the worktree.
    /// Both SHAs must be 40-char lowercase hex; the route layer
    /// rejects malformed input before it reaches the data layer.
    fn worktree_diff_range(
        &self,
        name: &str,
        from_sha: &str,
        to_sha: &str,
    ) -> Result<WorktreeDiff, ApiError>;

    /// Directory listing under the worktree.
    ///
    /// `sub_path` is a forward-slash separated path relative to
    /// the worktree root. `None` / `Some("")` ⇒ the worktree
    /// root itself.
    ///
    /// The implementation MUST refuse path-traversal (`..`),
    /// absolute paths, NUL bytes, and symlink targets that
    /// resolve outside the worktree root. A `.git` directory
    /// at any depth MUST be skipped — never surface repo
    /// internals to the operator UI.
    ///
    /// Returns `Err(NotFound)` for unknown worktree slugs OR
    /// when the resolved path does not exist; `Err(BadRequest)`
    /// for malformed input. When the entry count is capped, the
    /// result's `truncated` flag is `true` and the caller is
    /// expected to refine the path.
    fn worktree_tree(&self, name: &str, sub_path: Option<&str>) -> Result<WorktreeTree, ApiError>;

    /// File content from the worktree.
    ///
    /// `file_path` is required (no listing-by-default), forward-
    /// slash separated, relative to the worktree root. The
    /// implementation MUST apply the same sandbox as
    /// [`Self::worktree_tree`] AND refuse symlinks (do not
    /// follow), refuse non-regular files, and cap the inline
    /// payload at the implementation-defined maximum (the
    /// kernel impl uses 2 MiB and surfaces oversize requests
    /// as `BadRequest`).
    ///
    /// `encoding` is `"utf8"` if the bytes parse as UTF-8 and
    /// `"base64"` otherwise.
    fn worktree_file(&self, name: &str, file_path: &str) -> Result<WorktreeFile, ApiError>;

    /// Replay the last `n` events captured for the session's
    /// stream from the on-disk file ring. Used by the SSE
    /// handler before it attaches the live subscription so
    /// freshly-connected clients see recent context.
    fn stream_tail(&self, session_id: &str, n: usize) -> Result<Vec<StreamEvent>, ApiError>;

    /// Subscribe to a session's live event stream. The returned
    /// [`StreamSubscription`] yields events emitted AFTER the
    /// subscribe call. Lagged subscribers receive `Err(n)` on
    /// the next recv and remain usable.
    ///
    /// `Err(NotFound)` ⇒ the session never recorded any output
    /// (no broadcast channel exists yet). The SSE handler
    /// surfaces this as a 404; the frontend can fall back to
    /// the `stream_tail` snapshot and poll.
    fn stream_subscribe(&self, session_id: &str) -> Result<StreamSubscription, ApiError>;

    /// Apply a new policy artifact + detached signature.
    ///
    /// Routed from `PUT /api/policy/toml` (write_policy role).
    /// The handler:
    ///   1. Stages the new TOML + signature bytes on disk
    ///      (atomic temp-then-rename onto the canonical
    ///      `policy.toml` / `policy.toml.sig` paths).
    ///   2. Calls `raxis_kernel::policy_manager::advance_epoch`
    ///      which Phase-0 verifies the Ed25519 signature against
    ///      the authority key and Phase-1 commits the
    ///      `policy_epoch_history` row.
    ///   3. Emits `AuditEventKind::PolicyUpdatedViaDashboard`
    ///      with the operator's pubkey fingerprint.
    ///
    /// On any failure (signature invalid, replay, malformed
    /// TOML, IO trouble) the handler MUST roll the on-disk
    /// files back to their previous content so a partial write
    /// never leaves the canonical files out-of-sync with the
    /// in-memory `Arc<ArcSwap<PolicyBundle>>`.
    ///
    /// The trait method is synchronous because the production
    /// implementation already wraps `advance_epoch` in
    /// `tokio::task::spawn_blocking` — calling it from inside
    /// an async handler is safe.
    fn update_policy_toml(
        &self,
        operator_fingerprint: &str,
        toml_bytes: &[u8],
        signature_bytes: &[u8],
    ) -> Result<PolicyAdvancement, ApiError>;

    /// List the credentials bound to one initiative's plan. The
    /// data layer joins `task_credential_proxies` with the
    /// kernel's credential backend to surface metadata only —
    /// NEVER plaintext. Credentials are de-duplicated by name
    /// (one initiative may have multiple tasks binding the same
    /// credential) and ordered alphabetically.
    ///
    /// Returns `Err(NotFound)` for unknown initiative ids.
    /// Returns an empty list for initiatives whose plan declares
    /// no credentials. `INV-DASHBOARD-CREDENTIAL-DEFAULT-MASKED-01`:
    /// the wire shape carries no `bytes` / `plaintext` field by
    /// construction.
    fn list_initiative_credentials(
        &self,
        initiative_id: &str,
    ) -> Result<Vec<CredentialMetadata>, ApiError>;

    /// Reveal the plaintext bytes of one initiative-bound
    /// credential. Returns the bytes wrapped in [`CredentialReveal`]
    /// with the auto-hide deadline pre-computed (default 30s).
    ///
    /// Returns `Err(NotFound)` when the credential name is not
    /// declared by any task on this initiative. The route layer
    /// is responsible for the role gate (`admin` only) and the
    /// rate limit; the data layer assumes both have been honoured
    /// before the call.
    ///
    /// `INV-DASHBOARD-CREDENTIAL-REVEAL-AUDITED-01` is enforced
    /// at the route layer — the data layer MUST NOT emit the
    /// audit row from inside this call (the route layer needs
    /// to emit BEFORE the response and the operator-fingerprint
    /// is only available in the `AuthorizedOperator` extractor).
    fn reveal_initiative_credential(
        &self,
        initiative_id: &str,
        credential_name: &str,
    ) -> Result<CredentialReveal, ApiError>;

    /// List system-wide credentials (provider keys, etc.). The
    /// data layer enumerates `<data_dir>/providers/*.toml` plus
    /// any other credential the kernel exposes via the system
    /// scope.
    ///
    /// Admin-only at the route layer; the data layer does not
    /// re-check the role.
    fn list_system_credentials(&self) -> Result<Vec<CredentialMetadata>, ApiError>;

    /// Reveal the plaintext bytes of one system-wide credential.
    /// Auto-hide deadline is 15s (vs 30s for per-initiative
    /// credentials) per
    /// `INV-DASHBOARD-CREDENTIAL-AUTO-HIDE-01`.
    fn reveal_system_credential(&self, credential_name: &str)
        -> Result<CredentialReveal, ApiError>;

    /// Enforce the per-operator rate limit on the credential
    /// reveal endpoints. Returns `Err(TooManyRequests)` when the
    /// caller has exceeded the configured limit; returns `Ok(())`
    /// after registering the call. The window is sliding (we use
    /// a tail-of-N timestamps per operator); the route layer
    /// passes the operator fingerprint AFTER the role check
    /// passed.
    ///
    /// Default impl returns `Ok(())` so test fixtures can opt
    /// out without standing up a clock; production
    /// `KernelDashboardData` overrides with the real throttle.
    fn enforce_reveal_rate_limit(&self, _operator_fingerprint: &str) -> Result<(), ApiError> {
        Ok(())
    }

    /// Emit a single `Operator*` audit event for an operator-
    /// initiated dashboard action (mutating OR privileged-read).
    /// Implements `INV-AUDIT-OPERATOR-ACTION-01`.
    ///
    /// Handlers MUST call this AFTER mechanical validation (auth,
    /// permission, schema, path-safety) and BEFORE returning. The
    /// `outcome` field on the event tells dashboards whether the
    /// action succeeded (`Accepted`) or which rejection class it
    /// fell into. The data layer is responsible for appending the
    /// event to the kernel's audit chain — the dashboard never
    /// touches the chain bytes directly.
    ///
    /// Failure mode: a non-`Ok` return MUST be a hard error. We
    /// do NOT silently drop operator-audit events — the
    /// `INV-AUDIT-OPERATOR-ACTION-01` invariant is a "before
    /// returning success" contract, so a failing emit forces
    /// the handler into the `InternalError` branch.
    ///
    /// `InMemoryDashboardData` records emissions on an internal
    /// vector so tests can assert handlers actually fired the
    /// expected event.
    fn emit_operator_audit(&self, event: raxis_audit_tools::AuditEventKind)
        -> Result<(), ApiError>;
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
    /// Per-initiative original-plan TOML seeded by tests via
    /// [`InMemoryDashboardData::push_initiative_plan`]. Keyed by
    /// `initiative_id`. The fixture mirrors the production rule:
    /// missing entry ⇒ `ApiError::Gone { kind: "plan" }` so route
    /// tests can exercise the 410 path without standing up a real
    /// `plan_bundle_artifacts` table.
    initiative_plans: HashMap<String, InitiativePlanView>,
    sessions: Vec<SessionView>,
    escalations: Vec<EscalationView>,
    audit: Vec<AuditEntryView>,
    inbox: Vec<AuditEntryView>,
    notifications: Vec<NotificationView>,
    policy: Option<PolicySnapshotView>,
    policy_toml: String,
    health: Option<HealthSnapshot>,
    /// (entry, detail, log entries, default-diff, ranged-diff store)
    worktrees: Vec<WorktreeFixture>,
    /// Per-session stream capture surfaces. Tests register a
    /// source via [`InMemoryDashboardData::install_stream_source`]
    /// then push events onto it; the trait routes
    /// `stream_subscribe` / `stream_tail` to the matching source.
    streams: HashMap<String, StreamFixture>,
    /// Capture of every `Operator*` audit event the handler
    /// layer routed through `emit_operator_audit`. Lets tests
    /// assert `INV-AUDIT-OPERATOR-ACTION-01` is honoured by
    /// every operator-initiated route — read or mutate.
    recorded_operator_audits: Vec<raxis_audit_tools::AuditEventKind>,
    /// Per-initiative credential listings for the credential
    /// viewer surface. Keyed by initiative id; values are the
    /// metadata + plaintext bytes (the latter is reserved for
    /// the test reveal path — production reads come through
    /// `KernelDashboardData::reveal_initiative_credential`). When
    /// an initiative id is not present the listing endpoint
    /// returns `NotFound`.
    initiative_credentials: HashMap<String, Vec<CredentialFixture>>,
    /// System-wide credential listings.
    system_credentials: Vec<CredentialFixture>,
    /// Per-operator timestamp ring used by the in-memory rate
    /// limiter (`enforce_reveal_rate_limit`). Operators that hit
    /// the limit get a synthetic `TooManyRequests` so route-layer
    /// integration tests can exercise the throttle without
    /// standing up a real clock.
    reveal_rate_limit_state: HashMap<String, Vec<std::time::Instant>>,
    /// In-memory rate-limit ceiling. `0` ⇒ disabled (default for
    /// most tests). Tests that exercise the throttle bump this
    /// via [`InMemoryDashboardData::with_reveal_rate_limit`].
    reveal_rate_limit_max: u32,
    /// In-memory rate-limit window. Defaults to 60 seconds when
    /// the limit is enabled.
    reveal_rate_limit_window: Duration,
}

/// In-memory credential fixture used by tests to seed the
/// credential viewer surface. Carries the metadata the listing
/// endpoint surfaces plus the plaintext bytes the reveal endpoint
/// returns. NEVER appears in the wire shape — this is purely an
/// in-process test affordance.
#[derive(Debug, Clone)]
pub struct CredentialFixture {
    /// Metadata returned from the listing endpoint.
    pub metadata: CredentialMetadata,
    /// Plaintext bytes returned from the reveal endpoint. Stored
    /// as a `String` because tests only ever exercise UTF-8
    /// credentials; binary credentials are out of scope for the
    /// in-memory fixture.
    pub plaintext: String,
}

#[derive(Debug, Clone, Default)]
struct StreamFixture {
    /// Persistent tail returned by `stream_tail`. Tests append
    /// to this via [`InMemoryDashboardData::push_stream_tail`].
    tail: Vec<StreamEvent>,
    /// Live broadcast source returned by `stream_subscribe`.
    /// `None` ⇒ subscribe returns `NotFound`.
    source: Option<SimpleStreamSource>,
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
            OperatorAuthResolution {
                display_name: display_name.into(),
                roles,
            },
        );
        self
    }

    /// Push an initiative into the fixture.
    pub fn push_initiative(self: &Arc<Self>, view: InitiativeView) -> &Arc<Self> {
        self.inner.write().initiatives.push(view);
        self
    }

    /// Seed the original submitted plan TOML for an initiative so
    /// `get_initiative_plan` returns it (rather than 410 Gone).
    /// Mirrors the production write path: tests that exercise the
    /// happy path of `GET /api/initiatives/:id/plan` MUST seed
    /// here, while tests that exercise the 410-on-purge branch
    /// MUST leave the entry absent.
    pub fn push_initiative_plan(self: &Arc<Self>, view: InitiativePlanView) -> &Arc<Self> {
        let id = view.initiative_id.clone();
        self.inner.write().initiative_plans.insert(id, view);
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

    /// Push a notification entry.
    pub fn push_notification(self: &Arc<Self>, view: NotificationView) -> &Arc<Self> {
        self.inner.write().notifications.push(view);
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

    /// Snapshot of every `Operator*` audit event the dashboard
    /// has routed through `emit_operator_audit` since boot. Used
    /// by integration tests that assert
    /// `INV-AUDIT-OPERATOR-ACTION-01` — every operator-initiated
    /// route emits an audit row with the right outcome.
    pub fn recorded_operator_audits(self: &Arc<Self>) -> Vec<raxis_audit_tools::AuditEventKind> {
        self.inner.read().recorded_operator_audits.clone()
    }

    /// Install a live broadcast source for `session_id`. Future
    /// `stream_subscribe` calls return a fresh subscription
    /// against this source; future `push_stream_event` calls
    /// fan out to active subscribers.
    pub fn install_stream_source(
        self: &Arc<Self>,
        session_id: impl Into<String>,
        source: SimpleStreamSource,
    ) -> &Arc<Self> {
        let mut g = self.inner.write();
        let entry = g.streams.entry(session_id.into()).or_default();
        entry.source = Some(source);
        self
    }

    /// Append an event to the persistent tail returned by
    /// `stream_tail` for `session_id`. Does NOT broadcast —
    /// tests that want both should also push to the source via
    /// `SimpleStreamSource::push`.
    pub fn push_stream_tail(
        self: &Arc<Self>,
        session_id: impl Into<String>,
        evt: StreamEvent,
    ) -> &Arc<Self> {
        let mut g = self.inner.write();
        g.streams
            .entry(session_id.into())
            .or_default()
            .tail
            .push(evt);
        self
    }

    /// Seed an initiative-scoped credential into the in-memory
    /// fixture. The listing endpoint surfaces every credential
    /// pushed for the given initiative id; the reveal endpoint
    /// returns the plaintext.
    pub fn push_initiative_credential(
        self: &Arc<Self>,
        initiative_id: impl Into<String>,
        fix: CredentialFixture,
    ) -> &Arc<Self> {
        let mut g = self.inner.write();
        g.initiative_credentials
            .entry(initiative_id.into())
            .or_default()
            .push(fix);
        self
    }

    /// Seed a system-wide credential fixture (provider key, etc.).
    pub fn push_system_credential(self: &Arc<Self>, fix: CredentialFixture) -> &Arc<Self> {
        self.inner.write().system_credentials.push(fix);
        self
    }

    /// Configure the in-memory rate limiter for the credential
    /// reveal endpoints. `max = 0` disables the throttle (the
    /// default). Tests that exercise the throttle pass
    /// `(5, Duration::from_secs(60))` to mirror the production
    /// default.
    pub fn with_reveal_rate_limit(self: &Arc<Self>, max: u32, window: Duration) -> &Arc<Self> {
        let mut g = self.inner.write();
        g.reveal_rate_limit_max = max;
        g.reveal_rate_limit_window = window;
        self
    }
}

impl DashboardData for InMemoryDashboardData {
    fn lookup_operator_roles(&self, fingerprint: &str) -> Option<OperatorAuthResolution> {
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

    fn subsystem_health(&self) -> Result<SubsystemHealthResponse, ApiError> {
        // In-memory fixture: every enumerated subsystem reports
        // `ok` so route-layer integration tests can assert the
        // endpoint surface without standing up a real kernel.
        let cards = SUBSYSTEM_CATALOG
            .iter()
            .map(|(id, label)| SubsystemHealthCard {
                id: (*id).to_owned(),
                label: (*label).to_owned(),
                status: "ok".into(),
                summary: "no kernel signal — in-memory fixture".into(),
                details: vec![],
                grafana_url: None,
                last_observed_at: 0,
                last_error: None,
            })
            .collect();
        Ok(SubsystemHealthResponse {
            aggregate_status: "ok".into(),
            cards,
            generated_at_ms: 0,
        })
    }

    fn list_initiatives(
        &self,
        limit: u32,
        state_filter: Option<&str>,
    ) -> Result<Vec<InitiativeListEntry>, ApiError> {
        let g = self.inner.read();
        let mut out: Vec<InitiativeListEntry> = g
            .initiatives
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
        self.inner
            .read()
            .initiatives
            .iter()
            .find(|i| i.summary.initiative_id == id)
            .cloned()
            .ok_or(ApiError::NotFound {
                kind: "initiative".into(),
            })
    }

    fn get_initiative_plan(&self, id: &str) -> Result<InitiativePlanView, ApiError> {
        let g = self.inner.read();
        // Mirror production: 404 when the initiative itself is
        // absent, 410 when the initiative exists but the plan
        // artifact was archived/purged.
        let known = g.initiatives.iter().any(|i| i.summary.initiative_id == id);
        if !known {
            return Err(ApiError::NotFound {
                kind: "initiative".into(),
            });
        }
        g.initiative_plans.get(id).cloned().ok_or(ApiError::Gone {
            kind: "plan".into(),
        })
    }

    fn list_tasks(&self, initiative_id: &str) -> Result<Vec<TaskView>, ApiError> {
        let g = self.inner.read();
        let init = g
            .initiatives
            .iter()
            .find(|i| i.summary.initiative_id == initiative_id)
            .ok_or(ApiError::NotFound {
                kind: "initiative".into(),
            })?;
        Ok(init.tasks.clone())
    }

    fn get_task(&self, task_id: &str) -> Result<TaskView, ApiError> {
        let g = self.inner.read();
        for init in g.initiatives.iter() {
            if let Some(t) = init.tasks.iter().find(|t| t.task_id == task_id) {
                return Ok(t.clone());
            }
        }
        Err(ApiError::NotFound {
            kind: "task".into(),
        })
    }

    fn list_sessions(
        &self,
        limit: u32,
        initiative_id: Option<&str>,
    ) -> Result<Vec<SessionView>, ApiError> {
        let mut out: Vec<SessionView> = self
            .inner
            .read()
            .sessions
            .iter()
            .filter(|s| match initiative_id {
                Some(i) => s.initiative_id.as_deref() == Some(i),
                None => true,
            })
            .cloned()
            .collect();
        out.sort_by(|a, b| b.updated_at.cmp(&a.updated_at));
        out.truncate(limit.min(200) as usize);
        Ok(out)
    }

    fn get_session(&self, session_id: &str) -> Result<SessionView, ApiError> {
        self.inner
            .read()
            .sessions
            .iter()
            .find(|s| s.session_id == session_id)
            .cloned()
            .ok_or(ApiError::NotFound {
                kind: "session".into(),
            })
    }

    fn list_escalations(&self) -> Result<Vec<EscalationView>, ApiError> {
        Ok(self.inner.read().escalations.clone())
    }

    fn get_escalation(&self, id: &str) -> Result<EscalationView, ApiError> {
        self.inner
            .read()
            .escalations
            .iter()
            .find(|e| e.escalation_id == id)
            .cloned()
            .ok_or(ApiError::NotFound {
                kind: "escalation".into(),
            })
    }

    fn list_audit(
        &self,
        cursor_seq: Option<u64>,
        limit: u32,
        initiative_id: Option<&str>,
    ) -> Result<Vec<AuditEntryView>, ApiError> {
        let g = self.inner.read();
        let mut out: Vec<AuditEntryView> = g
            .audit
            .iter()
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

    fn audit_chain_status(&self, _reverify: bool) -> Result<(bool, ChainStatusView), ApiError> {
        // In-memory fixture: derive a trivial verdict from the
        // seeded audit rows so the route-layer tests can assert
        // both shape and the verdict string without standing up
        // a real audit chain walker.
        let g = self.inner.read();
        let last = g.audit.iter().map(|e| e.seq).max().unwrap_or(0);
        let total = g.audit.len() as u64;
        Ok((
            true,
            ChainStatusView {
                status: "ok".into(),
                last_verified_seq: last,
                total_records: total,
                segment_count: if total > 0 { 1 } else { 0 },
                verified_at_ms: g.audit.iter().map(|e| e.at).max().unwrap_or(0) * 1_000,
                last_error: None,
            },
        ))
    }

    fn list_notifications(
        &self,
        limit: u32,
        unread_only: bool,
        initiative_id: Option<&str>,
    ) -> Result<Vec<NotificationView>, ApiError> {
        let g = self.inner.read();
        let mut out: Vec<NotificationView> = g
            .notifications
            .iter()
            .filter(|n| {
                if unread_only && n.read {
                    return false;
                }
                if let Some(iid) = initiative_id {
                    if n.initiative_id.as_deref() != Some(iid) {
                        return false;
                    }
                }
                true
            })
            .cloned()
            .collect();
        out.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        out.truncate(limit.min(200) as usize);
        Ok(out)
    }

    fn notification_count_unread(&self) -> Result<u64, ApiError> {
        let g = self.inner.read();
        Ok(g.notifications.iter().filter(|n| !n.read).count() as u64)
    }

    fn mark_notification_read(&self, notification_id: &str) -> Result<bool, ApiError> {
        let mut g = self.inner.write();
        if let Some(n) = g
            .notifications
            .iter_mut()
            .find(|n| n.notification_id == notification_id)
        {
            if !n.read {
                n.read = true;
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn mark_all_notifications_read(&self) -> Result<u64, ApiError> {
        let mut g = self.inner.write();
        let mut count = 0u64;
        for n in g.notifications.iter_mut() {
            if !n.read {
                n.read = true;
                count += 1;
            }
        }
        Ok(count)
    }

    fn policy_snapshot(&self) -> Result<PolicySnapshotView, ApiError> {
        self.inner.read().policy.clone().ok_or(ApiError::Internal {
            log_only: "policy snapshot not set in fixture".into(),
        })
    }

    fn policy_toml_bytes(&self) -> Result<String, ApiError> {
        let g = self.inner.read();
        if g.policy_toml.is_empty() {
            return Err(ApiError::Internal {
                log_only: "policy.toml not set in fixture".into(),
            });
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
            .ok_or(ApiError::NotFound {
                kind: "worktree".into(),
            })
    }

    fn worktree_log(&self, name: &str, limit: u32) -> Result<Vec<WorktreeLogEntry>, ApiError> {
        let g = self.inner.read();
        let w = g
            .worktrees
            .iter()
            .find(|w| w.detail.summary.name == name)
            .ok_or(ApiError::NotFound {
                kind: "worktree".into(),
            })?;
        let cap = limit.clamp(1, 200) as usize;
        let mut out = w.log.clone();
        out.truncate(cap);
        Ok(out)
    }

    fn worktree_diff_default(&self, name: &str) -> Result<WorktreeDiff, ApiError> {
        let g = self.inner.read();
        let w = g
            .worktrees
            .iter()
            .find(|w| w.detail.summary.name == name)
            .ok_or(ApiError::NotFound {
                kind: "worktree".into(),
            })?;
        w.default_diff.clone().ok_or(ApiError::NotFound {
            kind: "default-diff".into(),
        })
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
            .ok_or(ApiError::NotFound {
                kind: "worktree".into(),
            })?;
        w.range_diffs
            .get(&(from_sha.to_owned(), to_sha.to_owned()))
            .cloned()
            .ok_or(ApiError::NotFound {
                kind: "diff-range".into(),
            })
    }

    fn worktree_tree(&self, name: &str, _sub_path: Option<&str>) -> Result<WorktreeTree, ApiError> {
        // The in-memory fixture has no real on-disk worktree; we
        // only validate that the slug exists. Tests that need
        // tree contents go through the kernel impl.
        let g = self.inner.read();
        if !g.worktrees.iter().any(|w| w.detail.summary.name == name) {
            return Err(ApiError::NotFound {
                kind: "worktree".into(),
            });
        }
        Ok(WorktreeTree {
            name: name.to_owned(),
            path: String::new(),
            entries: Vec::new(),
            truncated: false,
        })
    }

    fn worktree_file(&self, name: &str, _file_path: &str) -> Result<WorktreeFile, ApiError> {
        let g = self.inner.read();
        if !g.worktrees.iter().any(|w| w.detail.summary.name == name) {
            return Err(ApiError::NotFound {
                kind: "worktree".into(),
            });
        }
        // Fixture has no real bytes — return NotFound so route
        // tests can still assert the 404 path without seeding
        // file contents into the in-memory store.
        Err(ApiError::NotFound {
            kind: "worktree-file".into(),
        })
    }

    fn stream_tail(&self, session_id: &str, n: usize) -> Result<Vec<StreamEvent>, ApiError> {
        let g = self.inner.read();
        let fix = g.streams.get(session_id).ok_or(ApiError::NotFound {
            kind: "stream".into(),
        })?;
        let cap = n.min(2_000);
        let start = fix.tail.len().saturating_sub(cap);
        Ok(fix.tail[start..].to_vec())
    }

    fn stream_subscribe(&self, session_id: &str) -> Result<StreamSubscription, ApiError> {
        let g = self.inner.read();
        let fix = g.streams.get(session_id).ok_or(ApiError::NotFound {
            kind: "stream".into(),
        })?;
        let src = fix.source.as_ref().ok_or(ApiError::NotFound {
            kind: "stream-source".into(),
        })?;
        Ok(src.subscribe())
    }

    fn update_policy_toml(
        &self,
        operator_fingerprint: &str,
        toml_bytes: &[u8],
        signature_bytes: &[u8],
    ) -> Result<PolicyAdvancement, ApiError> {
        // The in-memory fixture has no real policy validator; it
        // just performs the side-effects a real impl would so
        // route-layer tests can assert end-to-end behaviour:
        //   - reject when the operator is not pre-registered as
        //     a write_policy role (callers with no entry here
        //     hit the auth layer first, but defence-in-depth);
        //   - reject empty TOML + zero-length signatures (the
        //     real validator rejects both unconditionally);
        //   - install the new bytes into the read surface (so
        //     a follow-up GET /api/policy/toml returns the new
        //     bytes the same way production would after a
        //     successful advance);
        //   - bump the epoch counter on the cached snapshot so
        //     callers can observe the advance through
        //     /api/policy too.
        if toml_bytes.is_empty() {
            return Err(ApiError::PolicyInvalid {
                detail: "policy TOML is empty".into(),
            });
        }
        if signature_bytes.len() != 64 {
            return Err(ApiError::PolicyInvalid {
                detail: format!(
                    "signature must be exactly 64 bytes (got {})",
                    signature_bytes.len(),
                ),
            });
        }
        let mut g = self.inner.write();
        let prev_epoch = g.policy.as_ref().map(|p| p.epoch).unwrap_or(0);
        let new_epoch = prev_epoch.saturating_add(1);
        let policy_sha256 = hex_sha256(toml_bytes);
        let prev_toml_len = g.policy_toml.len() as i64;
        if let Some(p) = g.policy.as_mut() {
            p.epoch = new_epoch;
            p.policy_sha256 = policy_sha256.clone();
            p.signed_by = operator_fingerprint.to_owned();
            p.signed_at = prev_toml_len + 1; // monotone for tests
        }
        g.policy_toml = String::from_utf8_lossy(toml_bytes).into_owned();
        let signed_by_authority = g
            .policy
            .as_ref()
            .map(|p| p.signed_by.clone())
            .unwrap_or_else(|| operator_fingerprint.to_owned());
        Ok(PolicyAdvancement {
            previous_epoch: prev_epoch,
            new_epoch,
            policy_sha256,
            signed_by_authority,
            n_sessions_invalidated: 0,
            n_delegations_marked_stale: 0,
            advanced_at: 0,
        })
    }

    fn emit_operator_audit(
        &self,
        event: raxis_audit_tools::AuditEventKind,
    ) -> Result<(), ApiError> {
        // The in-memory fixture has no audit chain; we just
        // capture the event so tests can assert handlers fire
        // the expected operator-action records.
        let mut g = self.inner.write();
        g.recorded_operator_audits.push(event);
        Ok(())
    }

    fn list_initiative_credentials(
        &self,
        initiative_id: &str,
    ) -> Result<Vec<CredentialMetadata>, ApiError> {
        let g = self.inner.read();
        // The listing endpoint distinguishes "initiative does not
        // exist" (NotFound) from "initiative exists but has no
        // credentials" (empty list). We use the seeded initiative
        // table as the source of truth: an entry with an empty
        // vec ⇒ initiative-with-no-creds; a missing key ⇒ NotFound.
        if g.initiatives
            .iter()
            .any(|i| i.summary.initiative_id == initiative_id)
            || g.initiative_credentials.contains_key(initiative_id)
        {
            Ok(g.initiative_credentials
                .get(initiative_id)
                .map(|v| v.iter().map(|f| f.metadata.clone()).collect())
                .unwrap_or_default())
        } else {
            Err(ApiError::NotFound {
                kind: "initiative".into(),
            })
        }
    }

    fn reveal_initiative_credential(
        &self,
        initiative_id: &str,
        credential_name: &str,
    ) -> Result<CredentialReveal, ApiError> {
        let g = self.inner.read();
        let creds = g
            .initiative_credentials
            .get(initiative_id)
            .ok_or(ApiError::NotFound {
                kind: "initiative".into(),
            })?;
        let fix = creds
            .iter()
            .find(|f| f.metadata.name == credential_name)
            .ok_or(ApiError::NotFound {
                kind: "credential".into(),
            })?;
        let bytes = fix.plaintext.as_bytes();
        Ok(CredentialReveal {
            name: fix.metadata.name.clone(),
            plaintext: fix.plaintext.clone(),
            encoding: "utf8".into(),
            byte_size: bytes.len() as u64,
            // 30s default for per-initiative reveals.
            expires_at_unix: now_secs_for_reveal().saturating_add(30),
            sha256_prefix: hex_sha256_prefix(bytes),
        })
    }

    fn list_system_credentials(&self) -> Result<Vec<CredentialMetadata>, ApiError> {
        Ok(self
            .inner
            .read()
            .system_credentials
            .iter()
            .map(|f| f.metadata.clone())
            .collect())
    }

    fn reveal_system_credential(
        &self,
        credential_name: &str,
    ) -> Result<CredentialReveal, ApiError> {
        let g = self.inner.read();
        let fix = g
            .system_credentials
            .iter()
            .find(|f| f.metadata.name == credential_name)
            .ok_or(ApiError::NotFound {
                kind: "system-credential".into(),
            })?;
        let bytes = fix.plaintext.as_bytes();
        Ok(CredentialReveal {
            name: fix.metadata.name.clone(),
            plaintext: fix.plaintext.clone(),
            encoding: "utf8".into(),
            byte_size: bytes.len() as u64,
            // 15s default for system reveals (shorter — Anthropic
            // is the canonical motivating case).
            expires_at_unix: now_secs_for_reveal().saturating_add(15),
            sha256_prefix: hex_sha256_prefix(bytes),
        })
    }

    fn enforce_reveal_rate_limit(&self, operator_fingerprint: &str) -> Result<(), ApiError> {
        let mut g = self.inner.write();
        let max = g.reveal_rate_limit_max;
        if max == 0 {
            return Ok(());
        }
        let window = g.reveal_rate_limit_window;
        let now = std::time::Instant::now();
        let entry = g
            .reveal_rate_limit_state
            .entry(operator_fingerprint.to_owned())
            .or_default();
        // Drop timestamps that have aged out of the window.
        entry.retain(|ts| now.duration_since(*ts) < window);
        if (entry.len() as u32) >= max {
            // Caller is over the limit; the oldest entry tells
            // us how long until the window slides forward enough
            // to free a slot.
            let oldest = entry.first().copied().unwrap_or(now);
            let elapsed = now.duration_since(oldest);
            let retry_after = window.saturating_sub(elapsed);
            return Err(ApiError::TooManyRequests {
                max,
                window_secs: window.as_secs() as u32,
                retry_after_secs: retry_after.as_secs().max(1) as u32,
            });
        }
        entry.push(now);
        Ok(())
    }
}

/// Wall-clock unix-seconds helper for the in-memory reveal path.
/// `KernelDashboardData` re-implements with the same semantics —
/// keeping a tiny helper here lets the in-memory tests assert
/// `expires_at_unix > 0` without standing up a clock fixture.
fn now_secs_for_reveal() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Lowercase-hex first 8 chars of SHA-256(`bytes`). Used by the
/// in-memory reveal path so wire-shape tests can assert the
/// digest prefix without parsing the full 64-char hex.
fn hex_sha256_prefix(bytes: &[u8]) -> String {
    use sha2::Digest;
    let mut h = sha2::Sha256::new();
    h.update(bytes);
    let digest = h.finalize();
    let mut s = String::with_capacity(8);
    for b in &digest[..4] {
        use std::fmt::Write;
        let _ = write!(&mut s, "{b:02x}");
    }
    s
}

/// Audit-chain curation for the dashboard Overview "Recent
/// activity" widget.
///
/// **Why this lives server-side.** The dashboard is a read-only
/// projection of kernel state; it must not encode policy
/// decisions about which audit events "matter". The kernel owns
/// the forensic chain and the kernel owns the curated feed.
///
/// **Signal vs noise.** After an earlier audit-noise sweep
/// retired the read-only `OperatorViewed*` emissions (see
/// `specs/v2/dashboard-operator-action-audit-coverage.md
/// §signal-vs-noise`), the chain still carries plenty of
/// per-operator clicks (mark-read, credential-list, health-
/// query, worktree-access) that are forensically interesting
/// but not what an operator wants to see in a 10-row "what
/// changed?" widget. The allow-list below is the *additional*
/// filter the Overview applies: ONLY state-affecting,
/// initiative-affecting, or security events are surfaced.
///
/// **Append-only.** Every new state-affecting audit variant
/// MUST be added here if it should surface on the Overview. The
/// list lives in one place so a forensic reviewer can audit the
/// curation policy at a glance.
pub mod recent_activity_filter {
    /// Allow-list of audit `event_kind` discriminants surfaced
    /// by `GET /api/audit/recent`.
    ///
    /// Each entry corresponds to a [`raxis_audit_tools::AuditEventKind`]
    /// variant's stable wire string (the `as_str()` value the
    /// chain row carries on its `event_kind` column).
    ///
    /// Categories (organised for the reviewer's benefit; the
    /// runtime filter is a flat membership check):
    ///
    /// 1. **Initiative lifecycle** — admit, approve, fail,
    ///    close. The Overview's primary value is "what
    ///    initiatives moved today?"
    /// 2. **Plan + task transitions** — plan approval, task
    ///    admit/state change, intent accept/reject. The
    ///    granular FSM events an operator wants on the
    ///    timeline.
    /// 3. **Session lifecycle (terminal only)** — spawn,
    ///    final-failure, revoke. We surface the spawn (a
    ///    state-creating event) and the terminal failure (a
    ///    state-affecting outcome) but NOT every respawn /
    ///    scale event (those flood the timeline; the audit
    ///    chain still records them for forensic walks).
    /// 4. **Security events** — egress denied, tproxy admit
    ///    denied, kernel deadlock, supervisor refused
    ///    restart, security violation, JWT-secret rotation.
    /// 5. **Integration merge** — push complete, merge
    ///    landed, push failed.
    /// 6. **Operator-mutating actions** — plan approve, plan
    ///    reject, dry-run admit, credential reveal, policy
    ///    update. The "the operator did something that
    ///    changed kernel state" rows.
    /// 7. **Kernel lifecycle (boot/shutdown only)** — start,
    ///    stop, supervisor restart. Audited once per
    ///    occurrence; heartbeat / health-tick events are
    ///    NEVER in this list.
    pub const IMPORTANT_EVENT_KINDS: &[&str] = &[
        // 1. Initiative lifecycle.
        "InitiativeCreated",
        "InitiativeAdmitted",
        "InitiativeAdmissionRejected",
        "InitiativeStateChanged",
        "InitiativeClosed",
        "InitiativeFailed",
        // 2. Plan + task transitions.
        "PlanApproved",
        "PlanRejected",
        "TaskAdmitted",
        "TaskStateChanged",
        "TaskTransitioned",
        "TaskCompleted",
        "TaskFailed",
        "IntentAccepted",
        "IntentRejected",
        // 3. Session lifecycle (creation + terminal failure
        //    only — routine respawn / scale events stay out
        //    of the curated feed but remain in the chain).
        "SessionCreated",
        "SessionVmSpawned",
        "SessionVmFailedFinal",
        "SessionRevoked",
        // 4. Security events.
        "SecurityViolationDetected",
        "EgressDenied",
        "TproxyAdmissionDenied",
        "TransparentProxyDenied",
        "KernelDeadlockDetected",
        "KernelCrashedBySignal",
        "SupervisorRefusedRestart",
        // Terminal supervisor-circuit-open event: kernel reached
        // its restart ceiling and the supervisor halted further
        // restarts. Semantic peer of `SupervisorRefusedRestart`
        // and `KernelBootedFromSupervisorRestart` — operators
        // need this row in the curated feed to see that the
        // self-healing path bottomed out.
        "KernelRestartHaltedCircuitOpen",
        "OrchestratorRespawnCeilingExceeded",
        "CredentialProxyUpstreamFailed",
        "OperatorRotatedDashboardJwtSecret",
        // 5. Integration merge.
        "IntegrationMergeCompleted",
        "IntegrationMergeFailed",
        "PushFailed",
        // 6. Operator-mutating actions.
        "OperatorApprovedPlan",
        "OperatorRejectedPlan",
        "OperatorApprovedRespawnEscalation",
        "OperatorDeniedRespawnEscalation",
        "OperatorRevealedCredential",
        "OperatorRevealedSystemCredential",
        "PolicyUpdatedViaDashboard",
        "PolicyEpochAdvanced",
        "DryRunAdmitted",
        "PathScopeOverrideApplied",
        // 7. Kernel lifecycle (boot/shutdown).
        "KernelStarted",
        "KernelStopped",
        "KernelRestartInitiated",
        "KernelRestartCompleted",
        "KernelBootedFromSupervisorRestart",
        // Per-task auto-resume row emitted once per surviving
        // task after a supervisor-driven kernel restart. Operator-
        // relevant ("did MY task come back?"). Potentially noisy
        // on many-task recoveries (one row per resumed task);
        // trade-off accepted for operator visibility into
        // per-task post-restart status.
        "TaskAutoResumedAfterSupervisorRestart",
        "ExecutorRespawnFromReviewRejection",
        // 8. iter65 gate-rejection orchestrator-fixup family.
        // `specs/v3/gate-rejection-orchestrator-fixup.md §4.9`.
        // These row the operator-facing "what just happened?"
        // feed for the new fixup loop:
        //   * Witness verdict surfaced from the kernel-side
        //     verifier subprocess (already curated; pinned here
        //     so the loop is visible end-to-end).
        //   * Acceptance + push to orchestrator on a recoverable
        //     gate rejection (loop in progress).
        //   * Terminal failure when the loop ran out of road
        //     (no profile, budget exhausted, or every fixup
        //     executor task failed).
        //   * Spawn + completion anchors for individual fixup
        //     subtasks — operators need to see attempts as
        //     they accumulate against the budget.
        //   * Weak-verifier-author signal (tier-2 fallback fired,
        //     or wire-invalid agent_hint rejected).
        "VerifierWitnessReceived",
        "GateRejectionAccepted",
        "GateRejectionTerminal",
        "GateFixupSpawned",
        "GateFixupCompleted",
        "WitnessMissingAgentHint",
    ];

    /// Returns `true` iff `event_kind` should appear in the
    /// curated Overview recent-activity feed.
    pub fn is_important(event_kind: &str) -> bool {
        IMPORTANT_EVENT_KINDS.contains(&event_kind)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn allow_list_admits_state_affecting_events() {
            assert!(is_important("InitiativeCreated"));
            assert!(is_important("PlanApproved"));
            assert!(is_important("TaskCompleted"));
            assert!(is_important("OperatorRevealedCredential"));
            assert!(is_important("SecurityViolationDetected"));
            assert!(is_important("KernelStarted"));
            // Supervisor-circuit terminal + per-task auto-resume:
            // the iter49 dashboards must surface both so the
            // self-healing path stays observable to operators.
            assert!(is_important("KernelRestartHaltedCircuitOpen"));
            assert!(is_important("TaskAutoResumedAfterSupervisorRestart"));
        }

        #[test]
        fn allow_list_excludes_operator_viewed_pageviews() {
            assert!(!is_important("OperatorViewedInitiativeList"));
            assert!(!is_important("OperatorViewedSessionList"));
            assert!(!is_important("OperatorViewedAuditChain"));
            assert!(!is_important("OperatorViewedEscalationList"));
            assert!(!is_important("OperatorViewedInbox"));
            assert!(!is_important("OperatorViewedNotifications"));
            assert!(!is_important("OperatorViewedPolicySnapshot"));
            assert!(!is_important("OperatorViewedPolicyToml"));
            assert!(!is_important("OperatorViewedWorktreeList"));
            assert!(!is_important("OperatorViewedTask"));
            assert!(!is_important("OperatorViewedSession"));
            assert!(!is_important("OperatorViewedInitiative"));
            assert!(!is_important("OperatorViewedInitiativeDag"));
            assert!(!is_important("OperatorViewedInitiativeTasks"));
            assert!(!is_important("OperatorViewedPlanToml"));
        }

        #[test]
        fn allow_list_excludes_operator_pageview_class_events() {
            // Per-click read-only events that the dashboard used
            // to mirror onto the chain. The second audit-noise sweep
            // stops emitting these entirely; the Overview filter
            // remains a defensive backstop against any stray
            // already-persisted row (or replay harness) that
            // surfaces one. The two notification-mutation events
            // continue to emit (state mutations) but stay out of
            // the curated Overview to keep its "what changed?"
            // feel focused on initiative-affecting work.
            assert!(!is_important("OperatorHealthQueried"));
            assert!(!is_important("OperatorNotificationMarkedRead"));
            assert!(!is_important("OperatorNotificationsMarkedAllRead"));
            assert!(!is_important("OperatorWorktreeAccessed"));
            assert!(!is_important("OperatorDiffViewed"));
            assert!(!is_important("OperatorFileContentFetched"));
            assert!(!is_important("OperatorListedCredentials"));
            assert!(!is_important("OperatorListedSystemCredentials"));
            assert!(!is_important("OperatorOpenedSessionStream"));
            // `OperatorAuditChainReverified` was previously in the
            // allow-list back when the dashboard emitted it on
            // every reverify click; round-2 of the audit-tightening
            // sweep retired the emit site, so it stays out of the
            // curated feed too. The variant remains on the enum as
            // `#[deprecated]` so old chains still decode.
            assert!(!is_important("OperatorAuditChainReverified"));
        }
    }
}

/// Stable-wire `outcome` discriminants for `Operator*` audit
/// events per `INV-AUDIT-OPERATOR-ACTION-01`. Each is a single
/// JSON string the dashboard surfaces verbatim — extension here
/// is append-only.
pub mod operator_outcome {
    /// Action ran to completion.
    pub const ACCEPTED: &str = "Accepted";
    /// Schema / path-safety / similar mechanical-validation failure.
    pub const REJECTED_VALIDATION: &str = "RejectedValidation";
    /// Auth OK, but role / policy permission check failed.
    pub const REJECTED_PERMISSION: &str = "RejectedPermission";
    /// Server-side failure after the request was validated.
    pub const INTERNAL_ERROR: &str = "InternalError";

    /// Map an `ApiError` into the appropriate stable-wire outcome
    /// string. The mapping is deliberately conservative — `NotFound`
    /// counts as a validation failure (operator referenced a
    /// resource that does not exist), `Forbidden` as permission,
    /// `Internal` / `BadRequest` (other) as internal-error /
    /// validation respectively.
    pub fn outcome_from_api_error(err: &super::ApiError) -> &'static str {
        use super::ApiError::*;
        match err {
            MissingAuth
            | InvalidJwt
            | JwtRevoked
            | ChallengeExpired
            | SignatureInvalid
            | UnknownOperator
            | CertRejected { .. } => REJECTED_PERMISSION,
            Forbidden { .. } => REJECTED_PERMISSION,
            NotFound { .. } => REJECTED_VALIDATION,
            Gone { .. } => REJECTED_VALIDATION,
            BadRequest { .. } => REJECTED_VALIDATION,
            PolicyInvalid { .. } => REJECTED_VALIDATION,
            // A rate-limit refusal is not a permission failure
            // (the operator does have the role) — it's a
            // mechanical-validation refusal expressed as 429 on the
            // wire. Surfacing it as `RejectedValidation` lets
            // forensic dashboards distinguish "operator doesn't
            // have role" (`RejectedPermission`) from "operator
            // hammered the reveal endpoint".
            TooManyRequests { .. } => REJECTED_VALIDATION,
            Internal { .. } => INTERNAL_ERROR,
        }
    }
}

/// Lowercase-hex SHA-256 helper used by the in-memory fixture
/// only. Avoids pulling another digest crate into the dashboard
/// surface (the kernel side uses `raxis_policy::load_policy`
/// which already hashes the artifact).
fn hex_sha256(bytes: &[u8]) -> String {
    use sha2::Digest;
    let mut h = sha2::Sha256::new();
    h.update(bytes);
    let out = h.finalize();
    out.iter().fold(String::with_capacity(64), |mut s, b| {
        use std::fmt::Write;
        let _ = write!(&mut s, "{b:02x}");
        s
    })
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
                    failure: None,
                    blocked_downstream: vec![],
                    annotations: vec![],
                    latest_annotation: None,
                    review_verdict: None,
                    last_critique: None,
                    reviewer_panel_results: vec![],
                    is_active: false,
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
                    failure: None,
                    blocked_downstream: vec![],
                    annotations: vec![],
                    latest_annotation: None,
                    review_verdict: None,
                    last_critique: None,
                    reviewer_panel_results: vec![],
                    is_active: true,
                },
            ],
            edges: vec![DagEdge {
                from: format!("{id}-t1"),
                to: format!("{id}-t2"),
            }],
            failure: None,
        }
    }

    // --- INV-DASHBOARD-FAILURE-VISIBILITY-01 wire-shape tests ------------

    /// `FailureInfo::new` produces a minimal-but-renderable shape:
    /// kind + message present; everything else defaulted to empty
    /// so the FE's empty-state copy paths are exercised.
    #[test]
    fn failure_info_new_carries_minimum_fields() {
        let f = FailureInfo::new("PushFailed", "remote rejected push");
        assert_eq!(f.kind, "PushFailed");
        assert_eq!(f.message, "remote rejected push");
        assert!(f.fields.is_empty());
        assert!(f.artifacts.is_empty());
        assert!(f.event_id.is_none());
        assert!(f.seq.is_none());
        assert_eq!(f.observed_at, 0);
    }

    /// Builder chaining attaches structured fields + artifact
    /// links + audit-row anchor + timestamp. The FE consumes all
    /// of these — every one of them has to round-trip through
    /// `serde_json::to_value`.
    #[test]
    fn failure_info_builder_round_trips_through_serde() {
        let f = FailureInfo::new("SessionVmFailedFinal", "Permanent")
            .with_field("Failure class", "Permanent")
            .with_field("Total attempts", "3")
            .with_artifact(
                "kernel.stderr.log",
                "file:///var/raxis/sessions/abc/kernel.stderr.log",
            )
            .with_audit("ev-42", 42)
            .at(1_700_000_000);
        let v = serde_json::to_value(&f).expect("serialises");
        assert_eq!(v["kind"], "SessionVmFailedFinal");
        assert_eq!(v["message"], "Permanent");
        assert_eq!(v["fields"][0]["label"], "Failure class");
        assert_eq!(v["fields"][0]["value"], "Permanent");
        assert_eq!(v["fields"][1]["label"], "Total attempts");
        assert_eq!(v["artifacts"][0]["label"], "kernel.stderr.log");
        assert_eq!(v["event_id"], "ev-42");
        assert_eq!(v["seq"], 42);
        assert_eq!(v["observed_at"], 1_700_000_000_u64);
    }

    /// Empty optional fields are dropped from the wire so a
    /// freshly-constructed `FailureInfo::new(...)` doesn't ship
    /// noise (`"fields":[]`, `"event_id":null`, …) to the FE.
    /// `skip_serializing_if` keeps the JSON shape tight.
    #[test]
    fn failure_info_empty_optional_fields_skipped() {
        let f = FailureInfo::new("PushFailed", "boom");
        let s = serde_json::to_string(&f).expect("serialises");
        assert!(!s.contains("\"fields\""));
        assert!(!s.contains("\"artifacts\""));
        assert!(!s.contains("\"event_id\""));
        assert!(!s.contains("\"seq\""));
        assert!(!s.contains("\"observed_at\""));
    }

    /// A `failure = None` on the wire must omit the field
    /// entirely so consumers that pre-date the addition (older
    /// FE bundles, CLI tooling that mirrors the wire shape) keep
    /// parsing the response without panicking on the new key.
    #[test]
    fn task_view_omits_failure_field_when_none() {
        let t = TaskView {
            task_id: "t-1".into(),
            initiative_id: "i-1".into(),
            title: "t".into(),
            state: "Completed".into(),
            session_id: None,
            reviewer_verdicts: vec![],
            structured_outputs: vec![],
            path_allowlist: vec![],
            created_at: 0,
            updated_at: 0,
            failure: None,
            blocked_downstream: vec![],
            annotations: vec![],
            latest_annotation: None,
            review_verdict: None,
            last_critique: None,
            reviewer_panel_results: vec![],
            is_active: false,
        };
        let s = serde_json::to_string(&t).expect("serialises");
        assert!(!s.contains("\"failure\""));
        assert!(!s.contains("\"blocked_downstream\""));
        assert!(!s.contains("\"annotations\""));
        assert!(!s.contains("\"latest_annotation\""));
        assert!(!s.contains("\"review_verdict\""));
        assert!(!s.contains("\"last_critique\""));
        assert!(!s.contains("\"reviewer_panel_results\""));
    }

    /// A `failure = Some(_)` carries through to the JSON wire so
    /// the FE's `<FailureReasonPanel>` has every audit-projected
    /// field available without a second roundtrip.
    #[test]
    fn task_view_with_failure_serialises_full_shape() {
        let t = TaskView {
            task_id: "t-1".into(),
            initiative_id: "i-1".into(),
            title: "t".into(),
            state: "Failed".into(),
            session_id: None,
            reviewer_verdicts: vec![],
            structured_outputs: vec![],
            path_allowlist: vec![],
            created_at: 0,
            updated_at: 0,
            failure: Some(
                FailureInfo::new("WitnessRejected", "reviewer flagged path scope")
                    .with_field("Reviewer", "rev-1")
                    .with_audit("ev-9", 9),
            ),
            blocked_downstream: vec!["t-2".into()],
            annotations: vec![],
            latest_annotation: None,
            review_verdict: None,
            last_critique: None,
            reviewer_panel_results: vec![],
            is_active: false,
        };
        let v = serde_json::to_value(&t).expect("serialises");
        assert_eq!(v["failure"]["kind"], "WitnessRejected");
        assert_eq!(v["failure"]["message"], "reviewer flagged path scope");
        assert_eq!(v["failure"]["event_id"], "ev-9");
        assert_eq!(v["blocked_downstream"][0], "t-2");
    }

    /// `get_initiative_plan` (fixture path) MUST return 404 when
    /// the initiative is unknown, 410 when the initiative exists
    /// but the plan was purged, and the seeded view byte-for-byte
    /// when the plan is present. Mirrors the production contract
    /// per `INV-DASHBOARD-INITIATIVE-PLAN-VISIBLE-01`.
    #[test]
    fn get_initiative_plan_distinguishes_404_410_and_present() {
        let d = InMemoryDashboardData::new();
        d.push_initiative(sample_initiative("init1"));

        // No plan seeded yet → 410 Gone (initiative exists).
        let err = d.get_initiative_plan("init1").unwrap_err();
        assert!(matches!(err, ApiError::Gone { ref kind } if kind == "plan"));

        // Unknown initiative → 404.
        let err = d.get_initiative_plan("missing").unwrap_err();
        assert!(matches!(err, ApiError::NotFound { ref kind } if kind == "initiative"));

        // Seed → byte-for-byte round-trip.
        let plan_toml = "# original\n[plan.initiative]\ntitle = \"x\"\n";
        d.push_initiative_plan(InitiativePlanView {
            initiative_id: "init1".into(),
            plan_sha256: Some("deadbeef".into()),
            bundle_sha256: Some("a".repeat(64)),
            submitted_toml: plan_toml.into(),
            submitted_toml_bytes: plan_toml.len() as u64,
            submitted_at_unix: 1_700_000_000,
            submitted_by: Some("op-fingerprint".into()),
            approval_status: "approved".into(),
            approved_at_unix: Some(1_700_000_001),
        });
        let got = d.get_initiative_plan("init1").unwrap();
        assert_eq!(got.submitted_toml, plan_toml);
        assert_eq!(got.submitted_toml_bytes, plan_toml.len() as u64);
        assert_eq!(got.approval_status, "approved");
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
                seq,
                event_id: format!("ev{seq}"),
                event_kind: "X".into(),
                initiative_id: None,
                task_id: None,
                session_id: None,
                at: seq,
                payload: serde_json::json!({"seq": seq}),
            });
        }
        let page1 = d.list_audit(None, 4, None).unwrap();
        assert_eq!(page1.len(), 4);
        assert_eq!(page1[0].seq, 10);
        let page2 = d
            .list_audit(Some(page1.last().unwrap().seq), 4, None)
            .unwrap();
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
        d.push_worktree(WorktreeFixture {
            detail,
            log,
            default_diff: Some(default_diff),
            range_diffs,
        });

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

    // ── Notification tests ────────────────────────────────────────

    fn sample_notification(id: &str, kind: &str, read: bool, ts: u64) -> NotificationView {
        NotificationView {
            notification_id: id.into(),
            event_kind: kind.into(),
            initiative_id: Some("init-1".into()),
            task_id: None,
            session_id: None,
            summary: format!("{kind} happened"),
            payload: serde_json::json!({"k": "v"}),
            read,
            source_event_id: "evt-1".into(),
            created_at: ts,
            // Tests in this crate don't exercise the priority
            // projection (that's a `dashboard-kernel` concern);
            // leave `None` so legacy callers stay untouched.
            priority: None,
        }
    }

    #[test]
    fn list_notifications_returns_all_when_no_filter() {
        let d = InMemoryDashboardData::new();
        d.push_notification(sample_notification("n-1", "EscalationPending", false, 300))
            .push_notification(sample_notification("n-2", "PolicyAdvanced", true, 200))
            .push_notification(sample_notification("n-3", "EscalationApproved", false, 100));
        let all = d.list_notifications(10, false, None).unwrap();
        assert_eq!(all.len(), 3);
        // Newest first.
        assert_eq!(all[0].notification_id, "n-1");
        assert_eq!(all[2].notification_id, "n-3");
    }

    #[test]
    fn list_notifications_filters_unread_only() {
        let d = InMemoryDashboardData::new();
        d.push_notification(sample_notification("n-1", "EscalationPending", false, 300))
            .push_notification(sample_notification("n-2", "PolicyAdvanced", true, 200))
            .push_notification(sample_notification("n-3", "EscalationApproved", false, 100));
        let unread = d.list_notifications(10, true, None).unwrap();
        assert_eq!(unread.len(), 2);
        assert!(unread.iter().all(|n| !n.read));
    }

    #[test]
    fn list_notifications_filters_by_initiative() {
        let d = InMemoryDashboardData::new();
        d.push_notification(sample_notification("n-1", "X", false, 300))
            .push_notification({
                let mut n = sample_notification("n-2", "Y", false, 200);
                n.initiative_id = Some("init-other".into());
                n
            });
        let filtered = d.list_notifications(10, false, Some("init-1")).unwrap();
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].notification_id, "n-1");
    }

    #[test]
    fn list_notifications_respects_limit() {
        let d = InMemoryDashboardData::new();
        for i in 0..10 {
            d.push_notification(sample_notification(&format!("n-{i}"), "X", false, i as u64));
        }
        let page = d.list_notifications(3, false, None).unwrap();
        assert_eq!(page.len(), 3);
    }

    #[test]
    fn notification_count_unread_counts_only_unread() {
        let d = InMemoryDashboardData::new();
        d.push_notification(sample_notification("n-1", "X", false, 300))
            .push_notification(sample_notification("n-2", "Y", true, 200))
            .push_notification(sample_notification("n-3", "Z", false, 100));
        assert_eq!(d.notification_count_unread().unwrap(), 2);
    }

    #[test]
    fn mark_notification_read_flips_unread_to_read() {
        let d = InMemoryDashboardData::new();
        d.push_notification(sample_notification("n-1", "X", false, 300));
        let updated = d.mark_notification_read("n-1").unwrap();
        assert!(updated);
        // Now it should be read.
        assert_eq!(d.notification_count_unread().unwrap(), 0);
        let all = d.list_notifications(10, false, None).unwrap();
        assert!(all[0].read);
    }

    #[test]
    fn mark_notification_read_is_idempotent() {
        let d = InMemoryDashboardData::new();
        d.push_notification(sample_notification("n-1", "X", true, 300));
        // Already read — returns false.
        let updated = d.mark_notification_read("n-1").unwrap();
        assert!(!updated);
    }

    #[test]
    fn mark_notification_read_returns_false_for_unknown() {
        let d = InMemoryDashboardData::new();
        let updated = d.mark_notification_read("nonexistent").unwrap();
        assert!(!updated);
    }

    #[test]
    fn mark_all_notifications_read_clears_unread() {
        let d = InMemoryDashboardData::new();
        d.push_notification(sample_notification("n-1", "X", false, 300))
            .push_notification(sample_notification("n-2", "Y", false, 200))
            .push_notification(sample_notification("n-3", "Z", true, 100));
        let count = d.mark_all_notifications_read().unwrap();
        assert_eq!(count, 2);
        assert_eq!(d.notification_count_unread().unwrap(), 0);
    }

    #[test]
    fn mark_all_notifications_read_returns_zero_when_none_unread() {
        let d = InMemoryDashboardData::new();
        d.push_notification(sample_notification("n-1", "X", true, 300));
        let count = d.mark_all_notifications_read().unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn push_notification_builder_appends() {
        let d = InMemoryDashboardData::new();
        d.push_notification(sample_notification("n-1", "A", false, 100))
            .push_notification(sample_notification("n-2", "B", false, 200));
        assert_eq!(d.list_notifications(10, false, None).unwrap().len(), 2);
    }
}

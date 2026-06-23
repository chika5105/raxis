//! Lifecycle annotation classifier (`v3 ITERPOST §iter62`).
//!
//! The dashboard's per-task / per-session forensic surface
//! historically dumped raw audit JSON one-liners and forced an
//! operator to reverse-engineer cause→effect by hand. iter62
//! made that pain concrete: every `lint-runner-js` retry was a
//! reviewer rejection, but the dashboard never said so — the
//! operator had to manually correlate `seq` numbers across
//! several audit rows to figure out *why* a task was retrying
//! or *why* a session had been revoked.
//!
//! This module owns the **pure-function classifier** that walks
//! the audit chain + activation rows + task rows and emits
//! structured [`LifecycleAnnotation`]s. The dashboard data
//! layer attaches the result on every task / session / global
//! response so the FE can render boxed cards instead of raw
//! JSON.
//!
//! ## Design contract
//!
//! * **Pure.** No kernel state, no I/O, no clock — `now_unix`
//!   for the orchestrator-gap detector is passed in. This makes
//!   the classifier trivially testable from synthesised audit
//!   slices and lets the dashboard run it on every read without
//!   pinning a mutex.
//! * **Idempotent.** Running the classifier twice over the same
//!   input produces the same annotations. Annotations carry the
//!   audit-chain timestamps verbatim so the FE can render an
//!   ordered timeline without re-deriving causality.
//! * **Best-effort.** A malformed audit payload (missing field,
//!   wrong type) does not panic — the classifier silently skips
//!   the annotation rather than poisoning the response. The
//!   audit chain is still the authoritative ledger; this layer
//!   only renders.
//!
//! ## Invariants
//!
//! See `INV-DASHBOARD-LIFECYCLE-CAUSALITY-01` — the spec lives
//! in `specs/invariants.md`.

use raxis_dashboard::data::LifecycleAnnotation;

/// Minimal projection of `audit.jsonl` rows the classifier
/// reads. The shape mirrors
/// [`raxis_dashboard::data::AuditEntryView`] but is **owned**
/// here so the classifier can be exercised against synthesised
/// fixtures without standing up a `ChainReader`.
///
/// Concrete adapters (`From<AuditEntryView>` / `From<&Audit
/// EntryView>`) live alongside the kernel-glue impl that calls
/// the classifier so the runtime conversion is one-shot.
#[derive(Debug, Clone)]
pub struct AuditRow {
    /// Monotonic chain sequence number.
    pub seq: u64,
    /// Audit event id, when present on the chain row.
    pub event_id: String,
    /// Audit event kind discriminant string.
    pub event_kind: String,
    /// Owning initiative id (if any).
    pub initiative_id: Option<String>,
    /// Owning task id (if any).
    pub task_id: Option<String>,
    /// Owning session id (if any).
    pub session_id: Option<String>,
    /// Unix-seconds emit timestamp.
    pub at: i64,
    /// Full structured payload (JSON).
    pub payload: serde_json::Value,
}

/// Minimal projection of `subtask_activations` rows the
/// orchestrator-gap detector reads. Mirrors the migration-5 DDL
/// fields the detector cares about.
#[derive(Debug, Clone)]
pub struct ActivationRow {
    /// `subtask_activations.activation_id`.
    pub activation_id: String,
    /// `subtask_activations.task_id`.
    pub task_id: String,
    /// `subtask_activations.activation_state` —
    /// `PendingActivation` / `Active` / `Completed` / `Failed`.
    pub activation_state: String,
    /// Unix-seconds creation timestamp.
    pub created_at: i64,
    /// `subtask_activations.crash_retry_count` carried across
    /// respawns by the kernel retry handlers.
    pub crash_retry_count: u32,
    /// `subtask_activations.review_reject_count` carried across
    /// review-rejection respawns.
    pub review_reject_count: u32,
    /// `subtask_activations.validation_reject_count` for
    /// mechanically rejected planner intents.
    pub validation_reject_count: u32,
    /// Per-activation mechanical validation ceiling. Older DBs
    /// default to the dashboard constant below.
    pub max_validation_rejections: u32,
}

/// Minimal projection of `tasks` rows the orchestrator-gap
/// detector needs (state + predecessor edges).
#[derive(Debug, Clone)]
pub struct TaskRow {
    /// Task identifier.
    pub task_id: String,
    /// Task FSM state — typically `Completed` / `Failed` /
    /// `Running` / `Admitted` / etc.
    pub state: String,
    /// Per-task predecessor edges (read from
    /// `task_dag_edges.predecessor_task_id` for rows where this
    /// task is the successor). May be empty for root tasks.
    pub predecessors: Vec<String>,
    /// Unix-seconds completion timestamp (`Completed` /
    /// `Failed` transition). `None` when the task has not yet
    /// reached a terminal state. Used to populate the
    /// `predecessors_completed_at` field on
    /// [`LifecycleAnnotation::OrchestratorGap`].
    pub completed_at: Option<i64>,
    /// True when every direct predecessor may be `Completed`, but
    /// one predecessor Executor still has an open Reviewer gate. The
    /// kernel will reject downstream activation in that state, so it
    /// is not an orchestrator gap.
    pub predecessor_review_gate_open: bool,
}

// `LifecycleAnnotation` lives on the dashboard wire-shape layer
// (`raxis_dashboard::data::LifecycleAnnotation`) so the route
// layer can serialize it directly. The classifier here owns the
// PRODUCTION semantics — when a payload pattern matches, it
// emits one of the variants from the dashboard crate.

// ---------------------------------------------------------------------------
// Per-task classifier
// ---------------------------------------------------------------------------

/// V2 default budgets — mirror the kernel's
/// `subtask_activations` retry policy (2 review rejections + 3
/// crash retries by default). The dashboard does not own these
/// numbers; we surface the cumulative counter and the cap so
/// the operator can see "2 of 2 used" at a glance.
const DEFAULT_MAX_REVIEW_REJECTIONS: u32 = 2;
const DEFAULT_MAX_CRASH_RETRIES: u32 = 3;
const DEFAULT_MAX_VALIDATION_REJECTIONS: u32 = 3;

/// Stale-`PendingActivation` cutoff (seconds). Mirrors the
/// orchestrator's heartbeat budget — anything that has been
/// waiting longer than this is a "gap" the operator should see.
const ORCHESTRATOR_GAP_CUTOFF_SECS: i64 = 120;

/// Walk the audit chain in `seq` order and emit one
/// [`LifecycleAnnotation`] for every retry / revocation /
/// initiative-block that mentions `task_id`.
///
/// `last_critique` is the kernel's most-recent aggregated
/// reviewer critique (`tasks.last_critique`). We surface its
/// first 3 lines as the `RetryReviewReject.critique` excerpt
/// for the *latest* retry only — earlier retries report an
/// empty excerpt because the per-retry critique is not stored
/// (only the latest one is, by design — see
/// `migration_6_adds_last_critique_column_to_tasks`).
pub fn classify_for_task(
    audit_chain: &[AuditRow],
    task_id: &str,
    activations: &[ActivationRow],
    last_critique: Option<&str>,
) -> Vec<LifecycleAnnotation> {
    // Sort audit by seq so the pairing scan is monotonic.
    let mut chain: Vec<&AuditRow> = audit_chain
        .iter()
        .filter(|r| audit_row_mentions_task(r, task_id))
        .collect();
    chain.sort_by_key(|r| r.seq);
    classify_for_task_rows(&chain, task_id, activations, last_critique)
}

/// Walk a pre-filtered, `seq`-ordered audit-chain slice for one
/// task and emit the same lifecycle annotations as
/// [`classify_for_task`].
///
/// This is the dashboard list/detail fast path: callers that
/// already indexed the audit chain can avoid re-filtering and
/// re-sorting the full chain once per task. The caller must pass
/// only rows that mention `task_id`, in monotonic `seq` order.
pub fn classify_for_task_rows(
    chain: &[&AuditRow],
    task_id: &str,
    activations: &[ActivationRow],
    last_critique: Option<&str>,
) -> Vec<LifecycleAnnotation> {
    let mut out: Vec<LifecycleAnnotation> = Vec::new();

    // Pending pair state: most-recent
    // `ReviewAggregationCompleted{AtLeastOneRejected}` for this
    // task that has not yet been consumed by an
    // `ExecutorRespawnFromReviewRejection`.
    let mut pending_review_reject: Option<&AuditRow> = None;
    // Most-recent `TaskFailedOnWorkerPrematureExit` for this
    // task that has not yet been consumed by a
    // `RetrySubTaskAdmitted`.
    let mut pending_crash: Option<&AuditRow> = None;
    let mut review_retry_n: u32 = 0;
    let mut crash_retry_n: u32 = 0;
    let mut validation_retry_n: u32 = 0;

    // Index activations by id so the respawn pair can carry
    // worktree / crash-retry-count metadata when present.
    let activation_for =
        |id: &str| -> Option<&ActivationRow> { activations.iter().find(|a| a.activation_id == id) };

    // Pre-compute the last (most recent) `ReviewAggregationCompleted` row
    // whose verdict was `AtLeastOneRejected`. The `is_latest` test in the
    // critique-excerpt branch below MUST compare against the LAST reject
    // in the entire chain, NOT against the running max — incrementally
    // updating the seq within the loop made every retry look like the
    // latest, populating earlier retries' critique excerpts in
    // violation of the singleton-column contract documented next to
    // `tasks.last_critique` (migration 6).
    let last_review_reject_seq: u64 = chain
        .iter()
        .filter(|r| r.event_kind == "ReviewAggregationCompleted")
        .filter(|r| {
            r.payload
                .get("verdict")
                .and_then(|v| v.as_str())
                .map(|v| v == "AtLeastOneRejected")
                .unwrap_or(false)
        })
        .map(|r| r.seq)
        .max()
        .unwrap_or(0);

    for row in chain.iter() {
        match row.event_kind.as_str() {
            "ReviewAggregationCompleted" => {
                let verdict = row
                    .payload
                    .get("verdict")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                if verdict == "AtLeastOneRejected" {
                    pending_review_reject = Some(row);
                }
            }
            "ExecutorRespawnFromReviewRejection" => {
                let pair = pending_review_reject.take();
                review_retry_n += 1;
                let prior_act = row
                    .payload
                    .get("prior_activation_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_owned();
                let new_act = row
                    .payload
                    .get("new_activation_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_owned();
                let triggered_by = pair
                    .and_then(|p| p.payload.get("triggered_by_reviewer_task_id"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_owned();
                let verdict = pair
                    .and_then(|p| p.payload.get("verdict"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("AtLeastOneRejected")
                    .to_owned();
                let review_reject_count =
                    row.payload
                        .get("review_reject_count")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(review_retry_n as u64) as u32;
                // Surface the captured aggregated critique only
                // on the LATEST retry so the operator drill-down
                // sees the freshest text. Earlier retries get an
                // empty excerpt — `tasks.last_critique` is a
                // singleton column, see migration 6.
                let is_latest = pair
                    .map(|p| p.seq == last_review_reject_seq)
                    .unwrap_or(false);
                let critique_excerpt = if is_latest {
                    last_critique
                        .map(|c| first_n_lines(c, 3))
                        .unwrap_or_default()
                } else {
                    String::new()
                };
                let crash_count = activation_for(&new_act)
                    .map(|a| a.crash_retry_count)
                    .unwrap_or(0);
                out.push(LifecycleAnnotation::RetryReviewReject {
                    retry_number: review_retry_n,
                    triggered_by_reviewer_task_id: triggered_by,
                    verdict,
                    critique: critique_excerpt,
                    review_reject_count,
                    max_review_rejections: DEFAULT_MAX_REVIEW_REJECTIONS,
                    crash_retry_count: crash_count,
                    max_crash_retries: DEFAULT_MAX_CRASH_RETRIES,
                    prior_activation_id: prior_act,
                    new_activation_id: new_act,
                    prior_head_sha: row
                        .payload
                        .get("prior_head_sha")
                        .and_then(|v| v.as_str())
                        .map(str::to_owned),
                    new_head_sha: row
                        .payload
                        .get("new_head_sha")
                        .and_then(|v| v.as_str())
                        .map(str::to_owned),
                    ts_unix: row.at,
                });
            }
            "TaskFailedOnWorkerPrematureExit" => {
                pending_crash = Some(row);
            }
            "RetrySubTaskAdmitted" => {
                let pair = pending_crash.take();
                crash_retry_n += 1;
                let crash_retry_count = row
                    .payload
                    .get("crash_retry_count")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(crash_retry_n as u64) as u32;
                let exit_code = pair
                    .and_then(|p| p.payload.get("exit_code"))
                    .and_then(|v| v.as_i64())
                    .map(|v| v as i32);
                let terminal_tool = pair
                    .and_then(|p| p.payload.get("terminal_tool"))
                    .and_then(|v| v.as_str())
                    .map(str::to_owned);
                let scaled_from = row
                    .payload
                    .get("max_turns_scaled_from")
                    .and_then(|v| v.as_u64())
                    .map(|v| v as u32);
                let scaled_to = row
                    .payload
                    .get("max_turns_scaled_to")
                    .and_then(|v| v.as_u64())
                    .map(|v| v as u32);
                out.push(LifecycleAnnotation::RetryCrash {
                    retry_number: crash_retry_n,
                    exit_code,
                    terminal_tool,
                    max_turns_scaled_from: scaled_from,
                    max_turns_scaled_to: scaled_to,
                    crash_retry_count,
                    max_crash_retries: DEFAULT_MAX_CRASH_RETRIES,
                    ts_unix: row.at,
                });
            }
            "IntentValidationRejected" => {
                validation_retry_n += 1;
                let validator_reason = row
                    .payload
                    .get("validator_reason")
                    .or_else(|| row.payload.get("reason"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_owned();
                let validator_detail = row
                    .payload
                    .get("validator_detail")
                    .or_else(|| row.payload.get("detail"))
                    .cloned()
                    .unwrap_or(serde_json::Value::Null);
                let n = row
                    .payload
                    .get("validation_reject_count")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(validation_retry_n as u64) as u32;
                let max_validation_rejections = activations
                    .iter()
                    .rev()
                    .find(|a| a.task_id == task_id)
                    .map(|a| a.max_validation_rejections)
                    .unwrap_or(DEFAULT_MAX_VALIDATION_REJECTIONS);
                out.push(LifecycleAnnotation::RetryValidationReject {
                    retry_number: validation_retry_n,
                    validator_reason,
                    validator_detail,
                    validation_reject_count: n,
                    max_validation_rejections,
                    ts_unix: row.at,
                });
            }
            "GateRejectionAccepted" => {
                out.push(LifecycleAnnotation::GateRejectionAccepted {
                    gate_type: row
                        .payload
                        .get("gate_type")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_owned(),
                    evaluation_sha: row
                        .payload
                        .get("evaluation_sha")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_owned(),
                    verifier_run_id: row
                        .payload
                        .get("verifier_run_id")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_owned(),
                    critique: row
                        .payload
                        .get("critique")
                        .and_then(|v| v.as_str())
                        .map(|s| first_n_lines(s, 4))
                        .unwrap_or_default(),
                    attempt_index: row
                        .payload
                        .get("attempt_index")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0) as u32,
                    max_attempts: row
                        .payload
                        .get("max_attempts")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0) as u32,
                    ts_unix: row.at,
                });
            }
            "GateFixupSpawned" => {
                out.push(LifecycleAnnotation::GateFixupSpawned {
                    fixup_task_id: row
                        .payload
                        .get("fixup_task_id")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_owned(),
                    parent_task_id: row
                        .payload
                        .get("parent_task_id")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_owned(),
                    gate_type: row
                        .payload
                        .get("gate_type")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_owned(),
                    parent_evaluation_sha: row
                        .payload
                        .get("parent_evaluation_sha")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_owned(),
                    attempt_index: row
                        .payload
                        .get("attempt_index")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0) as u32,
                    ts_unix: row.at,
                });
            }
            "GateRejectionTerminal" => {
                out.push(LifecycleAnnotation::GateRejectionTerminal {
                    gate_type: row
                        .payload
                        .get("gate_type")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_owned(),
                    terminal_reason: row
                        .payload
                        .get("terminal_reason")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_owned(),
                    attempts_used: row
                        .payload
                        .get("attempts_used")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0) as u32,
                    ts_unix: row.at,
                });
            }
            "GateFixupCompleted" => {
                out.push(LifecycleAnnotation::GateFixupCompleted {
                    fixup_task_id: row
                        .payload
                        .get("fixup_task_id")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_owned(),
                    parent_task_id: row
                        .payload
                        .get("parent_task_id")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_owned(),
                    gate_type: row
                        .payload
                        .get("gate_type")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_owned(),
                    outcome: row
                        .payload
                        .get("outcome")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_owned(),
                    new_evaluation_sha: row
                        .payload
                        .get("new_evaluation_sha")
                        .and_then(|v| v.as_str())
                        .map(str::to_owned),
                    ts_unix: row.at,
                });
            }
            "WitnessRejected" => {
                out.push(LifecycleAnnotation::WitnessRejected {
                    verifier_run_id: row
                        .payload
                        .get("verifier_run_id")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_owned(),
                    reason: row
                        .payload
                        .get("reason")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_owned(),
                    ts_unix: row.at,
                });
            }
            "VerifierProcessFailed" => {
                out.push(LifecycleAnnotation::VerifierProcessFailed {
                    gate_type: row
                        .payload
                        .get("gate_type")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_owned(),
                    exit_code: row
                        .payload
                        .get("exit_code")
                        .and_then(|v| v.as_i64())
                        .map(|v| v as i32),
                    ts_unix: row.at,
                });
            }
            "InitiativeStateChanged" => {
                let to_state = row
                    .payload
                    .get("to_state")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                if to_state == "Blocked" {
                    let block_reason = row
                        .payload
                        .get("block_reason")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_owned();
                    let blocking = row
                        .payload
                        .get("blocking_task_id")
                        .and_then(|v| v.as_str())
                        .map(str::to_owned)
                        .or_else(|| Some(task_id.to_owned()));
                    out.push(LifecycleAnnotation::InitiativeBlocked {
                        block_reason,
                        blocking_task_id: blocking,
                        ts_unix: row.at,
                    });
                }
            }
            _ => {}
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Per-session classifier
// ---------------------------------------------------------------------------

/// `kernel://` marker prefix that distinguishes self-exit
/// revocations from operator-initiated ones. Pins the
/// canonical `revoked_by = "kernel://self-exit
/// /<short-id>"` pattern; the prefix match here decouples the
/// dashboard release cadence from the kernel's exact suffix
/// scheme.
pub const KERNEL_SELF_EXIT_REVOKED_BY_PREFIX: &str = "kernel://";

/// Walk the audit chain (filtered to one session) and emit
/// annotations for every `SessionRevoked` event. The operator
/// vs self-exit branch is decided by whether `revoked_by`
/// starts with [`KERNEL_SELF_EXIT_REVOKED_BY_PREFIX`].
pub fn classify_for_session(
    audit_chain: &[AuditRow],
    session_id: &str,
) -> Vec<LifecycleAnnotation> {
    let mut chain: Vec<&AuditRow> = audit_chain
        .iter()
        .filter(|r| r.session_id.as_deref() == Some(session_id))
        .collect();
    chain.sort_by_key(|r| r.seq);
    classify_for_session_rows(&chain)
}

/// Walk a pre-filtered, `seq`-ordered audit-chain slice for one
/// session and emit the same lifecycle annotations as
/// [`classify_for_session`].
///
/// Callers that already indexed audit rows by `session_id` use
/// this to avoid scanning the whole audit chain once per list row.
pub fn classify_for_session_rows(chain: &[&AuditRow]) -> Vec<LifecycleAnnotation> {
    let mut out: Vec<LifecycleAnnotation> = Vec::new();

    for row in chain.iter() {
        match row.event_kind.as_str() {
            "SessionRevoked" => {
                let revoked_by = row
                    .payload
                    .get("revoked_by")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_owned();
                let display = row
                    .payload
                    .get("revoked_by_display_name")
                    .and_then(|v| v.as_str())
                    .map(str::to_owned);
                if revoked_by.starts_with(KERNEL_SELF_EXIT_REVOKED_BY_PREFIX) {
                    let terminal_tool = row
                        .payload
                        .get("terminal_tool")
                        .and_then(|v| v.as_str())
                        .map(str::to_owned);
                    let exit_code = row
                        .payload
                        .get("exit_code")
                        .and_then(|v| v.as_i64())
                        .map(|v| v as i32);
                    let console_log_path = row
                        .payload
                        .get("console_log_path")
                        .and_then(|v| v.as_str())
                        .map(str::to_owned);
                    out.push(LifecycleAnnotation::SessionRevokedSelfExit {
                        terminal_tool,
                        exit_code,
                        console_log_path,
                        ts_unix: row.at,
                    });
                } else {
                    let intent_kind = row
                        .payload
                        .get("intent_kind")
                        .and_then(|v| v.as_str())
                        .map(str::to_owned);
                    out.push(LifecycleAnnotation::SessionRevokedOperator {
                        revoked_by,
                        revoked_by_display_name: display,
                        intent_kind,
                        ts_unix: row.at,
                    });
                }
            }
            "InitiativeStateChanged" => {
                let to_state = row
                    .payload
                    .get("to_state")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                if to_state == "Blocked" {
                    let block_reason = row
                        .payload
                        .get("block_reason")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_owned();
                    out.push(LifecycleAnnotation::InitiativeBlocked {
                        block_reason,
                        blocking_task_id: row.task_id.clone(),
                        ts_unix: row.at,
                    });
                }
            }
            _ => {}
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Orchestrator-gap detector
// ---------------------------------------------------------------------------

/// Walk the activation rows and emit
/// [`LifecycleAnnotation::OrchestratorGap`] for every
/// `PendingActivation` row whose `created_at` is older than
/// `now_unix - 120s` AND every predecessor task is `Completed`.
///
/// `tasks` MUST include every predecessor referenced by a
/// candidate activation; missing rows are treated as
/// "not-Completed" and the activation is skipped. (A real gap
/// against an unknown predecessor is a forensic noise: it
/// would point at a DB-side referential issue that the kernel
/// owns.)
pub fn classify_orchestrator_gaps(
    activations: &[ActivationRow],
    tasks: &[TaskRow],
    now_unix: i64,
) -> Vec<LifecycleAnnotation> {
    let mut out: Vec<LifecycleAnnotation> = Vec::new();
    let by_id = |id: &str| tasks.iter().find(|t| t.task_id == id);

    for act in activations.iter() {
        if act.activation_state != "PendingActivation" {
            continue;
        }
        let wait = now_unix - act.created_at;
        if wait < ORCHESTRATOR_GAP_CUTOFF_SECS {
            continue;
        }
        let Some(task) = by_id(&act.task_id) else {
            continue;
        };
        if task.predecessor_review_gate_open {
            continue;
        }
        if task.predecessors.is_empty() {
            // Root task: still emit a gap — a stuck root is an
            // orchestrator-startup issue.
            out.push(LifecycleAnnotation::OrchestratorGap {
                activation_id: act.activation_id.clone(),
                task_id: act.task_id.clone(),
                predecessors_completed_at: Vec::new(),
                wait_seconds: wait,
            });
            continue;
        }
        // All predecessors must be Completed for this to count
        // as a gap. Anything still Running / Failed elsewhere
        // is the explanation, not a gap.
        let mut completed_pairs: Vec<(String, i64)> = Vec::new();
        let mut all_completed = true;
        for pid in task.predecessors.iter() {
            match by_id(pid) {
                Some(p) if p.state == "Completed" => {
                    completed_pairs.push((p.task_id.clone(), p.completed_at.unwrap_or(0)));
                }
                _ => {
                    all_completed = false;
                    break;
                }
            }
        }
        if !all_completed {
            continue;
        }
        out.push(LifecycleAnnotation::OrchestratorGap {
            activation_id: act.activation_id.clone(),
            task_id: act.task_id.clone(),
            predecessors_completed_at: completed_pairs,
            wait_seconds: wait,
        });
    }
    out
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn audit_row_mentions_task(row: &AuditRow, task_id: &str) -> bool {
    row.task_id.as_deref() == Some(task_id)
        || payload_str_eq(&row.payload, "task_id", task_id)
        || payload_str_eq(&row.payload, "parent_task_id", task_id)
        || payload_str_eq(&row.payload, "fixup_task_id", task_id)
}

fn payload_str_eq(payload: &serde_json::Value, key: &str, expected: &str) -> bool {
    payload
        .get(key)
        .and_then(|v| v.as_str())
        .map(|v| v == expected)
        .unwrap_or(false)
}

fn first_n_lines(s: &str, n: usize) -> String {
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn audit(
        seq: u64,
        kind: &str,
        task: Option<&str>,
        session: Option<&str>,
        payload: serde_json::Value,
    ) -> AuditRow {
        AuditRow {
            seq,
            event_id: format!("event-{seq}"),
            event_kind: kind.into(),
            initiative_id: None,
            task_id: task.map(str::to_owned),
            session_id: session.map(str::to_owned),
            at: 1_700_000_000 + seq as i64,
            payload,
        }
    }

    /// **iter62 lint-runner-js fixture.** Two reviewer-reject
    /// retries for `lint-runner-js` mirror the audit slice we
    /// observed in the forensics work-dir
    /// (`/var/folders/.../audit/segment-000.jsonl`):
    /// `ReviewAggregationCompleted{AtLeastOneRejected}` (seq=N)
    /// followed by `ExecutorRespawnFromReviewRejection` (seq=N+3).
    /// The classifier MUST emit one `RetryReviewReject` per
    /// pair, with the latest retry carrying the captured
    /// `last_critique` excerpt.
    #[test]
    fn classify_for_task_emits_retry_review_reject_for_lint_runner_js_audit_slice() {
        let task = "lint-runner-js";
        let chain = vec![
            audit(
                343,
                "ReviewAggregationCompleted",
                Some(task),
                None,
                json!({
                    "executor_task_id": task,
                    "kind":             "ReviewAggregationCompleted",
                    "reviewer_count":   2,
                    "triggered_by_reviewer_task_id": "review-lint-defect-A",
                    "verdict":          "AtLeastOneRejected",
                }),
            ),
            audit(
                346,
                "ExecutorRespawnFromReviewRejection",
                Some(task),
                None,
                json!({
                    "kind":               "ExecutorRespawnFromReviewRejection",
                    "new_activation_id":  "act-2",
                    "prior_activation_id":"act-1",
                    "review_reject_count":1,
                    "task_id":            task,
                }),
            ),
            audit(
                351,
                "ReviewAggregationCompleted",
                Some(task),
                None,
                json!({
                    "executor_task_id": task,
                    "kind":             "ReviewAggregationCompleted",
                    "reviewer_count":   2,
                    "triggered_by_reviewer_task_id": "review-lint-defect-B",
                    "verdict":          "AtLeastOneRejected",
                }),
            ),
            audit(
                354,
                "ExecutorRespawnFromReviewRejection",
                Some(task),
                None,
                json!({
                    "kind":               "ExecutorRespawnFromReviewRejection",
                    "new_activation_id":  "act-3",
                    "prior_activation_id":"act-2",
                    "review_reject_count":2,
                    "task_id":            task,
                }),
            ),
        ];
        let critique = "REJECT — JS lint failed\n3 violations remain\n…\n(detailed body follows)";
        let out = classify_for_task(&chain, task, &[], Some(critique));
        assert_eq!(
            out.len(),
            2,
            "classifier MUST emit one RetryReviewReject per audit pair; got {out:?}"
        );
        match &out[0] {
            LifecycleAnnotation::RetryReviewReject {
                retry_number,
                review_reject_count,
                prior_activation_id,
                new_activation_id,
                triggered_by_reviewer_task_id,
                critique,
                ..
            } => {
                assert_eq!(*retry_number, 1);
                assert_eq!(*review_reject_count, 1);
                assert_eq!(prior_activation_id, "act-1");
                assert_eq!(new_activation_id, "act-2");
                assert_eq!(triggered_by_reviewer_task_id, "review-lint-defect-A");
                assert_eq!(
                    critique, "",
                    "earlier retries MUST carry an empty critique excerpt — \
                     `tasks.last_critique` is a singleton column"
                );
            }
            other => panic!("expected RetryReviewReject, got {other:?}"),
        }
        match &out[1] {
            LifecycleAnnotation::RetryReviewReject {
                retry_number,
                review_reject_count,
                critique,
                ..
            } => {
                assert_eq!(*retry_number, 2);
                assert_eq!(*review_reject_count, 2);
                assert_eq!(
                    critique, "REJECT — JS lint failed\n3 violations remain\n…",
                    "latest retry MUST carry the first-3-lines excerpt of the \
                     captured `last_critique`"
                );
            }
            other => panic!("expected RetryReviewReject, got {other:?}"),
        }
    }

    #[test]
    fn classify_for_task_surfaces_gate_fixup_lifecycle_from_parent_and_fixup_rows() {
        let parent = "materialize-records";
        let fixup = "materialize-records--gatefixup-1";
        let chain = vec![
            audit(
                10,
                "GateRejectionAccepted",
                Some(parent),
                None,
                json!({
                    "task_id": parent,
                    "gate_type": "coverage",
                    "evaluation_sha": "abc123",
                    "verifier_run_id": "run-1",
                    "critique": "line 1\nline 2\nline 3\nline 4\nline 5",
                    "attempt_index": 0,
                    "max_attempts": 2,
                }),
            ),
            audit(
                11,
                "GateFixupSpawned",
                Some(fixup),
                None,
                json!({
                    "fixup_task_id": fixup,
                    "parent_task_id": parent,
                    "gate_type": "coverage",
                    "parent_evaluation_sha": "abc123",
                    "attempt_index": 1,
                }),
            ),
            audit(
                12,
                "GateFixupCompleted",
                Some(fixup),
                None,
                json!({
                    "fixup_task_id": fixup,
                    "parent_task_id": parent,
                    "gate_type": "coverage",
                    "outcome": "completed_with_commit",
                    "new_evaluation_sha": "def456",
                }),
            ),
        ];

        let out = classify_for_task(&chain, parent, &[], None);
        assert_eq!(
            out.len(),
            3,
            "parent timeline must include fixup child rows"
        );
        assert!(matches!(
            &out[0],
            LifecycleAnnotation::GateRejectionAccepted {
                gate_type,
                attempt_index: 0,
                max_attempts: 2,
                critique,
                ..
            } if gate_type == "coverage"
                && critique == "line 1\nline 2\nline 3\nline 4"
        ));
        assert!(matches!(
            &out[1],
            LifecycleAnnotation::GateFixupSpawned {
                fixup_task_id,
                parent_task_id,
                attempt_index: 1,
                ..
            } if fixup_task_id == fixup && parent_task_id == parent
        ));
        assert!(matches!(
            &out[2],
            LifecycleAnnotation::GateFixupCompleted {
                outcome,
                new_evaluation_sha: Some(sha),
                ..
            } if outcome == "completed_with_commit" && sha == "def456"
        ));
    }

    #[test]
    fn classify_for_task_surfaces_intent_validation_reject_reason_and_detail() {
        let task = "integration-coordinator";
        let chain = vec![audit(
            20,
            "IntentValidationRejected",
            Some(task),
            Some("orch-session"),
            json!({
                "task_id": task,
                "intent_kind": "IntegrationMerge",
                "validator_reason": "diff_validation_failed",
                "validator_detail": {
                    "base_sha": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "head_sha": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                    "missing_executor_task_id": "allowlist-positive-codegen",
                    "missing_executor_sha": "cccccccccccccccccccccccccccccccccccccccc",
                    "diagnostic": "candidate head does not contain a completed executor artifact"
                },
                "validation_reject_count": 1
            }),
        )];

        let out = classify_for_task(&chain, task, &[], None);
        assert_eq!(out.len(), 1);
        match &out[0] {
            LifecycleAnnotation::RetryValidationReject {
                validator_reason,
                validator_detail,
                validation_reject_count,
                ..
            } => {
                assert_eq!(validator_reason, "diff_validation_failed");
                assert_eq!(*validation_reject_count, 1);
                assert_eq!(
                    validator_detail
                        .get("missing_executor_task_id")
                        .and_then(|v| v.as_str()),
                    Some("allowlist-positive-codegen")
                );
                assert_eq!(
                    validator_detail
                        .get("missing_executor_sha")
                        .and_then(|v| v.as_str()),
                    Some("cccccccccccccccccccccccccccccccccccccccc")
                );
            }
            other => panic!("expected RetryValidationReject, got {other:?}"),
        }
    }

    /// **iter62 review-lint-defect-rust fixture.** A
    /// `PendingActivation` row that has been waiting > 120s
    /// past its single `Completed` predecessor MUST surface as
    /// one `OrchestratorGap` annotation.
    #[test]
    fn classify_orchestrator_gaps_flags_review_lint_defect_rust() {
        let now = 1_700_004_020; // Activation has waited 4020s.
        let activation = ActivationRow {
            activation_id: "act-stuck".into(),
            task_id: "review-lint-defect-rust".into(),
            activation_state: "PendingActivation".into(),
            created_at: 1_700_000_000,
            crash_retry_count: 0,
            review_reject_count: 0,
            validation_reject_count: 0,
            max_validation_rejections: DEFAULT_MAX_VALIDATION_REJECTIONS,
        };
        let tasks = vec![
            TaskRow {
                task_id: "review-lint-defect-rust".into(),
                state: "Admitted".into(),
                predecessors: vec!["lint-runner-rust".into()],
                completed_at: None,
                predecessor_review_gate_open: false,
            },
            TaskRow {
                task_id: "lint-runner-rust".into(),
                state: "Completed".into(),
                predecessors: Vec::new(),
                completed_at: Some(1_700_000_010),
                predecessor_review_gate_open: false,
            },
        ];
        let out = classify_orchestrator_gaps(&[activation], &tasks, now);
        assert_eq!(
            out.len(),
            1,
            "expected exactly one orchestrator gap; got {out:?}"
        );
        match &out[0] {
            LifecycleAnnotation::OrchestratorGap {
                activation_id,
                task_id,
                wait_seconds,
                predecessors_completed_at,
            } => {
                assert_eq!(activation_id, "act-stuck");
                assert_eq!(task_id, "review-lint-defect-rust");
                assert!(
                    *wait_seconds > 120,
                    "wait_seconds MUST exceed the 120s cutoff; got {wait_seconds}"
                );
                assert_eq!(predecessors_completed_at.len(), 1);
                assert_eq!(predecessors_completed_at[0].0, "lint-runner-rust");
            }
            other => panic!("expected OrchestratorGap, got {other:?}"),
        }
    }

    /// **C1 self-exit marker fixture.** A `SessionRevoked` row
    /// whose `revoked_by` starts with `kernel://` MUST classify
    /// as `SessionRevokedSelfExit`. Operator-initiated
    /// revocations (non-`kernel://` `revoked_by`) MUST classify
    /// as `SessionRevokedOperator`. This test pins the marker
    /// pattern the kernel-side self-exit path populates.
    #[test]
    fn classify_for_session_emits_self_exit_when_revoked_by_kernel_marker() {
        let session = "sess-revoke-1";
        let chain = vec![audit(
            900,
            "SessionRevoked",
            None,
            Some(session),
            json!({
                "kind":               "SessionRevoked",
                "revoked_by":         "kernel://self-exit/abcd1234",
                "session_id":         session,
                "terminal_tool":      "submit_review",
                "exit_code":          0,
                "console_log_path":   "/var/folders/foo/kernel.stderr.log",
            }),
        )];
        let out = classify_for_session(&chain, session);
        assert_eq!(out.len(), 1);
        match &out[0] {
            LifecycleAnnotation::SessionRevokedSelfExit {
                terminal_tool,
                exit_code,
                console_log_path,
                ..
            } => {
                assert_eq!(terminal_tool.as_deref(), Some("submit_review"));
                assert_eq!(*exit_code, Some(0));
                assert!(console_log_path.is_some());
            }
            other => panic!("expected SessionRevokedSelfExit, got {other:?}"),
        }
        // Operator branch.
        let chain_op = vec![audit(
            901,
            "SessionRevoked",
            None,
            Some(session),
            json!({
                "kind":                    "SessionRevoked",
                "revoked_by":              "0192-some-other-session",
                "revoked_by_display_name": "Foo Bar",
                "session_id":              session,
            }),
        )];
        let out_op = classify_for_session(&chain_op, session);
        assert_eq!(out_op.len(), 1);
        match &out_op[0] {
            LifecycleAnnotation::SessionRevokedOperator {
                revoked_by_display_name,
                ..
            } => {
                assert_eq!(revoked_by_display_name.as_deref(), Some("Foo Bar"));
            }
            other => panic!("expected SessionRevokedOperator, got {other:?}"),
        }
    }

    #[test]
    fn classify_for_task_emits_retry_crash_for_premature_exit_pair() {
        let task = "lint-runner-py";
        let chain = vec![
            audit(
                100,
                "TaskFailedOnWorkerPrematureExit",
                Some(task),
                None,
                json!({
                    "exit_code":     137,
                    "terminal_tool": "shell",
                }),
            ),
            audit(
                101,
                "RetrySubTaskAdmitted",
                Some(task),
                None,
                json!({
                    "crash_retry_count":     1,
                    "max_turns_scaled_from": 80,
                    "max_turns_scaled_to":   120,
                }),
            ),
        ];
        let out = classify_for_task(&chain, task, &[], None);
        assert_eq!(out.len(), 1);
        match &out[0] {
            LifecycleAnnotation::RetryCrash {
                retry_number,
                exit_code,
                terminal_tool,
                max_turns_scaled_from,
                max_turns_scaled_to,
                crash_retry_count,
                ..
            } => {
                assert_eq!(*retry_number, 1);
                assert_eq!(*exit_code, Some(137));
                assert_eq!(terminal_tool.as_deref(), Some("shell"));
                assert_eq!(*max_turns_scaled_from, Some(80));
                assert_eq!(*max_turns_scaled_to, Some(120));
                assert_eq!(*crash_retry_count, 1);
            }
            other => panic!("expected RetryCrash, got {other:?}"),
        }
    }

    #[test]
    fn classify_orchestrator_gaps_skips_when_predecessor_not_completed() {
        let now = 1_700_005_000;
        let activation = ActivationRow {
            activation_id: "act-stuck".into(),
            task_id: "B".into(),
            activation_state: "PendingActivation".into(),
            created_at: 1_700_000_000,
            crash_retry_count: 0,
            review_reject_count: 0,
            validation_reject_count: 0,
            max_validation_rejections: DEFAULT_MAX_VALIDATION_REJECTIONS,
        };
        let tasks = vec![
            TaskRow {
                task_id: "B".into(),
                state: "Admitted".into(),
                predecessors: vec!["A".into()],
                completed_at: None,
                predecessor_review_gate_open: false,
            },
            TaskRow {
                task_id: "A".into(),
                state: "Running".into(),
                predecessors: Vec::new(),
                completed_at: None,
                predecessor_review_gate_open: false,
            },
        ];
        let out = classify_orchestrator_gaps(&[activation], &tasks, now);
        assert!(
            out.is_empty(),
            "PendingActivation whose predecessor is still Running is NOT a gap"
        );
    }

    #[test]
    fn classify_orchestrator_gaps_skips_when_reviewer_gate_open() {
        let now = 1_700_005_000;
        let activation = ActivationRow {
            activation_id: "act-wait-review".into(),
            task_id: "downstream".into(),
            activation_state: "PendingActivation".into(),
            created_at: 1_700_000_000,
            crash_retry_count: 0,
            review_reject_count: 0,
            validation_reject_count: 0,
            max_validation_rejections: DEFAULT_MAX_VALIDATION_REJECTIONS,
        };
        let tasks = vec![
            TaskRow {
                task_id: "downstream".into(),
                state: "Admitted".into(),
                predecessors: vec!["producer".into()],
                completed_at: None,
                predecessor_review_gate_open: true,
            },
            TaskRow {
                task_id: "producer".into(),
                state: "Completed".into(),
                predecessors: Vec::new(),
                completed_at: Some(1_700_000_010),
                predecessor_review_gate_open: false,
            },
        ];
        let out = classify_orchestrator_gaps(&[activation], &tasks, now);
        assert!(
            out.is_empty(),
            "PendingActivation blocked by an open reviewer gate is NOT an orchestrator gap"
        );
    }

    #[test]
    fn classify_orchestrator_gaps_skips_under_cutoff() {
        let now = 1_700_000_060; // Only 60s elapsed — under 120s cutoff.
        let activation = ActivationRow {
            activation_id: "act-fresh".into(),
            task_id: "B".into(),
            activation_state: "PendingActivation".into(),
            created_at: 1_700_000_000,
            crash_retry_count: 0,
            review_reject_count: 0,
            validation_reject_count: 0,
            max_validation_rejections: DEFAULT_MAX_VALIDATION_REJECTIONS,
        };
        let tasks = vec![TaskRow {
            task_id: "B".into(),
            state: "Admitted".into(),
            predecessors: Vec::new(),
            completed_at: None,
            predecessor_review_gate_open: false,
        }];
        let out = classify_orchestrator_gaps(&[activation], &tasks, now);
        assert!(
            out.is_empty(),
            "fresh PendingActivation under the 120s cutoff is NOT a gap"
        );
    }
}

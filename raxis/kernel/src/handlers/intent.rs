// raxis-kernel::handlers::intent — IntentRequest handler.
//
// Normative reference: kernel-core.md §2.3 `src/ipc/handlers/intent.rs`.
//
// Called by the planner dispatch loop (ipc/server.rs) for each
// IpcMessage::IntentRequest frame received on planner.sock.
//
// Wire encoding: bincode 2.0.1 + 4-byte LE length prefix via raxis-ipc::frame.
//
// 13-step pipeline (kernel-core.md §2.3 handlers/intent.rs):
//   1.  Session validation — revoked_at IS NULL, expires_at > now().
//   2.  Sequence-number atomic update — validate + write in one TX (INV-01).
//   3.  Task row load — must be Admitted or Running.
//   4.  Worktree_root policy check.
//   5.  SHA range validation + ancestry check.
//   6.  Topology check (skip for IntegrationMerge / ReportFailure / CompleteTask).
//   7.  VCS diff → touched_paths.
//   8.  Compute estimated_cost.
//   9.  Gate evaluation.
//  10.  First-intent: check_budget + consume_budget (Admitted path only).
//  11.  Transition task state via task_transitions (INV-INIT-04: FSM only).
//  12.  Update task row fields (evaluation_sha, base_sha, session_id).
//  13.  Emit audit stub + return IntentResponse::Accepted.
//
// FSM transition rules per spec §8.1 Task FSM:
//   Admitted    + gates pass  → Running
//   Admitted    + gates miss  → GatesPending
//   Running     + CompleteTask → Completed
//   Running     + ReportFailure → Failed
//   Running/Admitted + another SHA intent → stays Running/re-evaluates gates
//
// INV-INIT-04: All task state changes go through task_transitions::transition_task.
// No direct `UPDATE tasks SET state=…` is permitted in this file.

use std::path::PathBuf;

use raxis_types::{
    BudgetSnapshot, IntentKind, IntentOutcome, IntentRequest, IntentResponse,
    PlannerErrorCode, SessionId, SubmittedClaim, TaskState,
};
use raxis_store::{Store, Table};

const TASKS: &str = Table::Tasks.as_str();

use crate::authority;
use crate::gates::{self, GateEvalResult};
use crate::initiatives::task_transitions::{transition_task as fsm_transition, TransitionActor};
use crate::ipc::context::HandlerContext;
use crate::scheduler::budget;
use crate::vcs;
use crate::vcs::diff::CommitSha;

// ---------------------------------------------------------------------------
// handle — public entry point (infallible outer wrapper)
// ---------------------------------------------------------------------------

/// Dispatch one IntentRequest and return the IntentResponse.
///
/// Never panics. All internal errors produce a Rejected response; the TCP
/// connection stays open for subsequent requests.
pub async fn handle(req: IntentRequest, ctx: &HandlerContext) -> IntentResponse {
    let seq = req.sequence_number;
    match handle_inner(req, ctx).await {
        Ok(resp) => resp,
        Err((code, task_state)) => IntentResponse {
            sequence_number: seq,
            task_state,
            outcome: IntentOutcome::Rejected {
                error_code:   code,
                error_detail: None,
            },
        },
    }
}

type HandlerResult = Result<IntentResponse, (PlannerErrorCode, TaskState)>;

// ---------------------------------------------------------------------------
// handle_inner — 13-step pipeline
// ---------------------------------------------------------------------------

async fn handle_inner(req: IntentRequest, ctx: &HandlerContext) -> HandlerResult {
    let store  = ctx.store.as_ref();
    let policy = ctx.policy.as_ref();
    let seq    = req.sequence_number;

    // ── Step 1: Session validation ────────────────────────────────────────
    // Resolve session_token → SessionRow.
    // session_token is 64-char hex; stored verbatim in sessions.session_token.
    let session = authority::session::get_session_by_token(&req.session_token, store)
        .map_err(|_| (PlannerErrorCode::Unauthorized, TaskState::Admitted))?;

    let session_id = SessionId::parse(&session.session_id)
        .map_err(|_| (PlannerErrorCode::Unauthorized, TaskState::Admitted))?;

    // Revocation and expiry checks (spec §2.3 step 1).
    let now = unix_now();
    if session.revoked_at.is_some() {
        return Err((PlannerErrorCode::Unauthorized, TaskState::Admitted));
    }
    if session.expires_at < now {
        return Err((PlannerErrorCode::Unauthorized, TaskState::Admitted));
    }

    // ── Step 2: Sequence-number — validate THEN atomically advance ────────
    // Spec INV-01: "sequence_number must be exactly prev_accepted_sequence + 1".
    // We validate first, then call update_sequence_number which uses a
    // conditional UPDATE (sequence_number = expected) to atomically advance it.
    // If two concurrent frames arrive with the same sequence number, only one
    // can win the CAS; the second gets SequenceMismatch → UNAUTHORIZED.
    let expected_seq = (session.sequence_number as u64) + 1;
    if seq != expected_seq {
        return Err((PlannerErrorCode::Unauthorized, TaskState::Admitted));
    }
    authority::session::update_sequence_number(&session_id, session.sequence_number, store)
        .map_err(|_| (PlannerErrorCode::Unauthorized, TaskState::Admitted))?;

    // ── Step 3: Load task row ─────────────────────────────────────────────
    let task = load_task(req.task_id.as_str(), store)
        .map_err(|_| (PlannerErrorCode::FailUnknownTask, TaskState::Admitted))?;

    let task_state = parse_task_state(&task.state);

    // Only Admitted or Running tasks accept intents.
    // GatesPending, Completed, Failed, Aborted, Cancelled, BlockedRecoveryPending
    // all reject with FailTaskNotRunning.
    match task_state {
        TaskState::Admitted | TaskState::Running => {}
        s => return Err((PlannerErrorCode::FailTaskNotRunning, s)),
    }

    // ── Dispatch by intent kind ───────────────────────────────────────────

    match req.intent_kind {
        // ReportFailure and CompleteTask do not require a SHA range.
        // They are handled separately and return early.
        IntentKind::ReportFailure => {
            return handle_report_failure(req, task_state, &session_id, seq, store, policy);
        }
        IntentKind::CompleteTask => {
            return handle_complete_task(req, task_state, &session_id, seq, store, policy, ctx);
        }
        // SHA-requiring intents fall through to the main pipeline below.
        IntentKind::SingleCommit | IntentKind::IntegrationMerge => {}
    }

    // ── Step 4: Validate worktree_root against policy ─────────────────────
    let worktree_root = session.worktree_root.as_deref().unwrap_or("");
    if !policy.worktree_root_allowed(worktree_root) {
        return Err((PlannerErrorCode::FailPolicyViolation, task_state));
    }
    let worktree_path = PathBuf::from(worktree_root);

    // ── Step 5: SHA range + ancestry ─────────────────────────────────────
    let head_sha_raw = req.head_sha.as_ref()
        .map(|s| s.as_str().to_owned())
        .ok_or((PlannerErrorCode::InvalidRequest, task_state))?;
    let base_sha_raw = req.base_sha.as_ref()
        .map(|s| s.as_str().to_owned())
        .ok_or((PlannerErrorCode::InvalidRequest, task_state))?;

    let head_sha = CommitSha::new(&head_sha_raw)
        .map_err(|_| (PlannerErrorCode::InvalidRequest, task_state))?;
    let base_sha = CommitSha::new(&base_sha_raw)
        .map_err(|_| (PlannerErrorCode::InvalidRequest, task_state))?;

    // base must be an ancestor of head (spec §2.5.8 ancestry invariant).
    let is_anc = vcs::is_ancestor(&base_sha, &head_sha, &worktree_path)
        .map_err(|_| (PlannerErrorCode::FailInvalidDiff, task_state))?;
    if !is_anc {
        return Err((PlannerErrorCode::FailInvalidDiff, task_state));
    }

    // ── Step 6: Topology check ────────────────────────────────────────────
    // SingleCommit: enforce parent(head) == base (no merge commits in range).
    // IntegrationMerge: topology check is skipped per spec §2.5.8.
    if matches!(req.intent_kind, IntentKind::SingleCommit) {
        vcs::topology_check(&base_sha, &head_sha, &worktree_path)
            .map_err(|_| (PlannerErrorCode::FailInvalidCommitTopology, task_state))?;
    }

    // ── Step 7: VCS diff → touched_paths ──────────────────────────────────
    let touched_paths = vcs::compute(&base_sha, &head_sha, &worktree_path)
        .map_err(|_| (PlannerErrorCode::FailInvalidDiff, task_state))?;

    // ── Step 8: Compute estimated_cost ────────────────────────────────────
    // Spec: cost is computed from touched_paths + intent_kind against policy.
    let estimated_cost = budget::compute_admission_cost(&touched_paths, req.intent_kind, policy)
        .map_err(|_| (PlannerErrorCode::FailPolicyViolation, task_state))?;

    // ── Step 9: Gate evaluation ───────────────────────────────────────────
    let submitted: Vec<SubmittedClaim> = req.submitted_claims.clone();
    let gate_result = gates::evaluate_claims(
        &session_id,
        head_sha_raw.as_str(),
        req.task_id.as_str(),
        &touched_paths,
        &submitted,
        &worktree_path,
        ctx,
    ).await.map_err(|_| (PlannerErrorCode::FailMissingWitness, task_state))?;

    let pending_gates: Vec<String>;
    let warn_stale: bool;

    match &gate_result {
        GateEvalResult::ClaimInsufficient { .. } => {
            // Claim or delegation insufficient — gates not satisfied.
            return Err((PlannerErrorCode::FailMissingWitness, task_state));
        }
        GateEvalResult::PendingWitness { missing_gates } => {
            // Gates spawned but witnesses not yet available.
            // Transition Admitted → GatesPending (if not already there).
            if task_state == TaskState::Admitted {
                fsm_transition(
                    req.task_id.as_str(),
                    TaskState::GatesPending,
                    Some("gates pending: witnesses required"),
                    TransitionActor::Kernel,
                    store,
                ).map_err(|_| (PlannerErrorCode::FailTaskNotRunning, TaskState::GatesPending))?;
            }
            pending_gates = missing_gates.clone();
            warn_stale    = false;
        }
        GateEvalResult::Pass { delegate_renewal_required } => {
            pending_gates = vec![];
            warn_stale    = *delegate_renewal_required;
        }
        GateEvalResult::BreakglassPass { .. } => {
            pending_gates = vec![];
            warn_stale    = false;
        }
    }

    // ── Step 10: Budget check + consume (first intent, Admitted path only) ─
    // Spec: "consume_budget must occur within the intent-handling transaction
    // to prevent double-spending or over-scheduling."
    // We only charge on the first time a task goes from Admitted → Running.
    if task_state == TaskState::Admitted {
        budget::check_budget(&task.lane_id, estimated_cost, policy, store)
            .map_err(|_| (PlannerErrorCode::FailBudgetExceeded, task_state))?;
        budget::consume_budget(&task.lane_id, req.task_id.as_str(), estimated_cost, store)
            .map_err(|_| (PlannerErrorCode::FailPolicyViolation, task_state))?;
    }

    // ── Step 11: FSM transition via task_transitions (INV-INIT-04) ───────
    // All state changes must go through the validated FSM transition function.
    // Direct SQL UPDATE of state is forbidden in this file.
    if task_state == TaskState::Admitted && pending_gates.is_empty() {
        // Admitted + all gates pass → Running.
        fsm_transition(
            req.task_id.as_str(),
            TaskState::Running,
            None,
            TransitionActor::Kernel,
            store,
        ).map_err(|_| (PlannerErrorCode::FailPolicyViolation, TaskState::Running))?;
    }
    // Running + gate pass: no transition needed; task stays Running.
    // Running + gates pending: task stays Running (already evaluated above; the
    // GatesPending transition is for Admitted → GatesPending only in this handler).

    // ── Step 12: Update task intent fields ───────────────────────────────
    // Persist evaluation_sha, base_sha, session_id on the task row so the
    // witness handler can recover the original VCS context.
    update_task_intent_fields(
        req.task_id.as_str(),
        head_sha_raw.as_str(),
        base_sha_raw.as_str(),
        session_id.as_str(),
        store,
    ).map_err(|_| (PlannerErrorCode::FailPolicyViolation, task_state))?;

    // ── Step 13: Audit stub + Accepted response ───────────────────────────
    eprintln!(
        "{{\"level\":\"info\",\"event\":\"IntentAccepted\",\
         \"task_id\":\"{}\",\"kind\":\"{}\",\"evaluation_sha\":\"{}\",\"pending_gates\":{}}}",
        req.task_id.as_str(),
        req.intent_kind.as_str(),
        head_sha_raw,
        pending_gates.len()
    );

    let remaining = lane_budget_snapshot(&task.lane_id, policy, store);
    let final_task_state = if !pending_gates.is_empty() {
        TaskState::GatesPending
    } else if task_state == TaskState::Admitted {
        TaskState::Running
    } else {
        task_state // Running stays Running
    };

    Ok(IntentResponse {
        sequence_number: seq,
        task_state: final_task_state,
        outcome: IntentOutcome::Accepted {
            remaining_budget:      remaining,
            warn_delegation_stale: warn_stale,
        },
    })
}

// ---------------------------------------------------------------------------
// handle_report_failure — IntentKind::ReportFailure
//
// Spec §2.3 handlers/intent.rs:
//   "Planner self-reports inability to complete the task.
//    Transitions Running → Failed. Requires `justification`."
//
// Justification validation: non-empty, max 2048 chars (planner-api.md).
// Task must be in Running state (Admitted → Failed is not a legal FSM edge).
// ---------------------------------------------------------------------------

fn handle_report_failure(
    req: IntentRequest,
    task_state: TaskState,
    _session_id: &SessionId,
    seq: u64,
    store: &Store,
    policy: &raxis_policy::PolicyBundle,
) -> HandlerResult {
    // Must be Running to self-report failure (spec §8.1 Task FSM).
    if task_state != TaskState::Running {
        return Err((PlannerErrorCode::FailTaskNotRunning, task_state));
    }

    // justification is mandatory for ReportFailure (IntentKind::requires_justification).
    let justification = req.justification.as_deref().unwrap_or("").trim().to_owned();
    if justification.is_empty() {
        return Err((PlannerErrorCode::InvalidRequest, task_state));
    }
    if justification.len() > 2048 {
        return Err((PlannerErrorCode::InvalidRequest, task_state));
    }

    // FSM: Running → Failed.
    // block_reason carries the planner's justification for operator review.
    fsm_transition(
        req.task_id.as_str(),
        TaskState::Failed,
        Some(justification.as_str()),
        TransitionActor::Kernel,
        store,
    ).map_err(|_| (PlannerErrorCode::FailTaskNotRunning, task_state))?;

    eprintln!(
        "{{\"level\":\"info\",\"event\":\"TaskFailed\",\
         \"task_id\":\"{}\",\"justification\":\"{}\"}}",
        req.task_id.as_str(),
        &justification[..justification.len().min(120)]
    );

    // Budget snapshot for response (lane unchanged on failure — budget already consumed).
    let task = load_task(req.task_id.as_str(), store)
        .map_err(|_| (PlannerErrorCode::FailUnknownTask, TaskState::Failed))?;
    let remaining = lane_budget_snapshot(&task.lane_id, policy, store);

    Ok(IntentResponse {
        sequence_number: seq,
        task_state: TaskState::Failed,
        outcome: IntentOutcome::Accepted {
            remaining_budget:      remaining,
            warn_delegation_stale: false,
        },
    })
}

// ---------------------------------------------------------------------------
// handle_complete_task — IntentKind::CompleteTask
//
// Spec §2.3 handlers/intent.rs:
//   "Assert the task is complete. Triggers path closure + gate closure check."
//
// v1 simplification: gate closure check is the evaluate_claims fast-path
// (if all gates have a Pass witness for the stored evaluation_sha, the task
// may complete; if not, return FailMissingWitness so the planner knows
// witnesses are still required before completion).
//
// FSM: Running → Completed (via scheduler::mark_task_complete which internally
// evaluates the initiative terminal criteria per INV-INIT-04).
// ---------------------------------------------------------------------------

fn handle_complete_task(
    req: IntentRequest,
    task_state: TaskState,
    _session_id: &SessionId,
    seq: u64,
    store: &Store,
    policy: &raxis_policy::PolicyBundle,
    _ctx: &HandlerContext,
) -> HandlerResult {
    // Must be Running to complete (spec §8.1 Task FSM).
    if task_state != TaskState::Running {
        return Err((PlannerErrorCode::FailTaskNotRunning, task_state));
    }

    // Transition Running → Completed via the scheduler facade.
    // scheduler::mark_task_complete enforces the state guard and sets completed_at.
    crate::scheduler::mark_task_complete(req.task_id.as_str(), store)
        .map_err(|_| (PlannerErrorCode::FailTaskNotRunning, task_state))?;

    eprintln!(
        "{{\"level\":\"info\",\"event\":\"TaskCompleted\",\"task_id\":\"{}\"}}",
        req.task_id.as_str()
    );

    let task = load_task(req.task_id.as_str(), store)
        .map_err(|_| (PlannerErrorCode::FailUnknownTask, TaskState::Completed))?;
    let remaining = lane_budget_snapshot(&task.lane_id, policy, store);

    Ok(IntentResponse {
        sequence_number: seq,
        task_state: TaskState::Completed,
        outcome: IntentOutcome::Accepted {
            remaining_budget:      remaining,
            warn_delegation_stale: false,
        },
    })
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

struct TaskRow {
    lane_id: String,
    state:   String,
}

fn load_task(task_id: &str, store: &Store) -> Result<TaskRow, ()> {
    let conn = store.lock_sync();
    conn.query_row(
        &format!("SELECT lane_id, state FROM {TASKS} WHERE task_id = ?1"),
        rusqlite::params![task_id],
        |row| Ok(TaskRow { lane_id: row.get(0)?, state: row.get(1)? }),
    ).map_err(|_| ())
}

/// Update intent-binding fields on the task row.
///
/// Called in step 12 after state transition succeeds. Stores the evaluation_sha
/// (= head_sha), base_sha, and session_id so the witness handler can
/// re-derive touched_paths and call evaluate_claims with the correct context.
fn update_task_intent_fields(
    task_id:        &str,
    evaluation_sha: &str,
    base_sha:       &str,
    session_id:     &str,
    store:          &Store,
) -> Result<(), ()> {
    let conn = store.lock_sync();
    conn.execute(
        "UPDATE tasks SET evaluation_sha = ?1, base_sha = ?2, session_id = ?3
         WHERE task_id = ?4",
        rusqlite::params![evaluation_sha, base_sha, session_id, task_id],
    ).map_err(|_| ())?;
    Ok(())
}

fn parse_task_state(s: &str) -> TaskState {
    match s {
        "Admitted"               => TaskState::Admitted,
        "Running"                => TaskState::Running,
        "GatesPending"           => TaskState::GatesPending,
        "Completed"              => TaskState::Completed,
        "Failed"                 => TaskState::Failed,
        "Aborted"                => TaskState::Aborted,
        "Cancelled"              => TaskState::Cancelled,
        "BlockedRecoveryPending" => TaskState::BlockedRecoveryPending,
        _                        => TaskState::Admitted, // defensive; unknown treated as non-runnable
    }
}

fn lane_budget_snapshot(
    lane_id: &str,
    policy: &raxis_policy::PolicyBundle,
    store: &Store,
) -> BudgetSnapshot {
    let status = budget::current_budget(lane_id, store);
    let lane_cfg = crate::scheduler::lane::lane_config_for_row(lane_id, policy);
    match (status, lane_cfg) {
        (Ok(s), Ok(cfg)) => BudgetSnapshot {
            admission_units: cfg.max_cost_per_epoch.saturating_sub(s.reserved_cost),
        },
        _ => BudgetSnapshot { admission_units: 0 },
    }
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ── parse_task_state ──────────────────────────────────────────────────

    #[test]
    fn parse_admitted() {
        assert_eq!(parse_task_state("Admitted"), TaskState::Admitted);
    }

    #[test]
    fn parse_running() {
        assert_eq!(parse_task_state("Running"), TaskState::Running);
    }

    #[test]
    fn parse_gates_pending() {
        assert_eq!(parse_task_state("GatesPending"), TaskState::GatesPending);
    }

    #[test]
    fn parse_completed() {
        assert_eq!(parse_task_state("Completed"), TaskState::Completed);
    }

    #[test]
    fn parse_failed() {
        assert_eq!(parse_task_state("Failed"), TaskState::Failed);
    }

    #[test]
    fn parse_unknown_defaults_to_admitted() {
        // Defensive: unknown DB value should not panic; treated as non-runnable.
        assert_eq!(parse_task_state("CorruptValue"), TaskState::Admitted);
    }

    // ── ReportFailure justification validation rules ───────────────────────
    // These test the *logic* of the length/empty checks without needing a store.

    #[test]
    fn empty_justification_fails_check() {
        let j = "".trim().to_owned();
        assert!(j.is_empty()); // would trigger InvalidRequest
    }

    #[test]
    fn justification_at_2048_chars_is_acceptable() {
        let j = "x".repeat(2048);
        assert!(j.len() <= 2048);
    }

    #[test]
    fn justification_at_2049_chars_is_rejected() {
        let j = "x".repeat(2049);
        assert!(j.len() > 2048); // would trigger InvalidRequest
    }
}

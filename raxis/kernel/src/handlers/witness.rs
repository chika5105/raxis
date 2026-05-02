// raxis-kernel::handlers::witness — WitnessSubmission handler.
//
// Normative reference: kernel-core.md §2.3 `src/ipc/handlers/witness.rs`.
//
// Purpose: Handles `WitnessSubmission` from verifier subprocesses on the
// planner socket (planner.sock — there is no separate witness.sock in v1;
// the dispatcher routes by message variant per §2.2 startup step 7).
//
// Pipeline (per spec §2.3 witness.rs):
//   1.  Token validation  — validate_verifier_token; single-use, TTL-gated.
//   2.  Evaluation-SHA binding check — sub.evaluation_sha must match
//       task.evaluation_sha; mismatch returns Ok(Rejected::EvaluationShaMismatch)
//       WITHOUT consuming the token (verifier may resubmit).
//   3.  Body hash computation — sha256(sub.body JSON bytes).
//   4.  Witness write      — write to witness_index (filesystem blob + SQL row).
//   5.  Token consume      — mark token consumed AFTER successful write.
//   6.  Gate-recheck       — re-run evaluate_claims for the task's gates.
//       Pass   → transition GatesPending → Admitted (next_ready_tasks eligible).
//       Pending → spawn remaining verifiers; task stays GatesPending.
//       Claim fail → task stays GatesPending; planner must act.
//   7.  Return WitnessAck::Accepted { remaining_gates } or Rejected { reason }.
//
// Error vs Rejected contract:
//   Err(HandlerError) — transport/auth failures (connection dies, bad token).
//   Ok(WitnessAck::Rejected { reason }) — well-formed submission with typed
//       application-level refusal (SHA mismatch). Distinct from errors so the
//       verifier gets a typed response and the transport stays alive.
//
// INV references:
//   INV-INIT-04 — transition_task always calls evaluate_terminal_criteria.
//   INV-01      — token path; sequence/nonce rules do not apply to verifier
//                 messages; only token validity matters.

use std::path::PathBuf;

use raxis_types::{GateType, TaskId, WitnessSubmission};
use raxis_store::Table;
use raxis_types::TaskState;

use crate::authority::verifier_token;
use crate::gates::{self, GateEvalResult};
use crate::ipc::context::HandlerContext;
use crate::vcs;
use crate::witness_index::{self, ResultClass, WitnessRecord};

const TASKS: &str = Table::Tasks.as_str();

// ---------------------------------------------------------------------------
// Public outcome types
// ---------------------------------------------------------------------------

/// Application-level outcome of a WitnessSubmission.
///
/// This is *not* a `Result` error — both variants are *successful* responses
/// from the handler's perspective; `Rejected` simply means the submission
/// was refused for a typed application reason, and the transport stays open.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WitnessAck {
    /// Submission accepted and written.
    /// `run_id` echoes the verifier_run_id from the token lookup for correlation.
    /// `remaining_gates` lists any gates still needing witnesses.
    Accepted { run_id: String, remaining_gates: Vec<GateType> },

    /// Submission refused at the application level. Token is NOT consumed.
    Rejected { reason: WitnessRejectionReason },
}

/// Typed refusal reasons returned inside `WitnessAck::Rejected`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WitnessRejectionReason {
    /// sub.evaluation_sha != task.evaluation_sha. Spec §2.3 witness.rs:
    /// "no witness write, no token consume, no WitnessAccepted audit".
    EvaluationShaMismatch {
        expected: String,
        presented: String,
    },
    /// The task is not in GatesPending state — the submission arrived too late
    /// (task already recovered/aborted) or for the wrong task state.
    TaskNotGatesPending { current_state: String },
}

// ---------------------------------------------------------------------------
// Handler errors (transport / auth level)
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum HandlerError {
    #[error("verifier token invalid: {reason}")]
    Unauthorized { reason: String },

    #[error("task not found: {task_id}")]
    InvalidTask { task_id: String },

    #[error("witness index write failed: {0}")]
    WitnessWrite(String),

    #[error("gate recheck failed: {0}")]
    GateRecheck(String),

    #[error("store error: {0}")]
    Store(String),
}

// ---------------------------------------------------------------------------
// handle — public entry point
// ---------------------------------------------------------------------------

/// Handle one `WitnessSubmission` arriving on the planner socket.
///
/// Returns `Ok(WitnessAck)` for both accepted and typed-rejected submissions.
/// Returns `Err(HandlerError)` only for transport/auth-level failures.
pub async fn handle(
    sub: WitnessSubmission,
    ctx: &HandlerContext,
) -> Result<WitnessAck, HandlerError> {
    let store = ctx.store.as_ref();

    // ── Step 1: Token validation ──────────────────────────────────────────
    // Validates raw token hex against `verifier_run_tokens` table.
    // Returns the `run_id` (UUID) that identifies this verifier run on success.
    // Spec: "returns HandlerError::Unauthorized if invalid, expired, or consumed".
    let run_id = verifier_token::validate_verifier_token(sub.verifier_token.as_str(), store)
        .map_err(|e| HandlerError::Unauthorized { reason: e.to_string() })?;

    // ── Step 2: Load task row and evaluation-SHA binding check ────────────
    // Spec: "loads the task row by sub.task_id. If no row → HandlerError::InvalidTask."
    // "Compares sub.evaluation_sha to task.evaluation_sha ... If they differ,
    //  returns Ok(WitnessAck::Rejected { reason: EvaluationShaMismatch }) —
    //  no witness write, no token consume, no WitnessAccepted audit."
    let task_row = load_task_row(sub.task_id.as_str(), store)?;

    // Gate state check: only accept witness for tasks actually in GatesPending.
    // This prevents poisoning the witness index for tasks that have already been
    // swept to BlockedRecoveryPending by recovery.rs.
    if task_row.state != TaskState::GatesPending.as_sql_str() {
        return Ok(WitnessAck::Rejected {
            reason: WitnessRejectionReason::TaskNotGatesPending {
                current_state: task_row.state.clone(),
            },
        });
    }

    // Evaluation-SHA binding: submitted SHA must exactly match the one stored
    // when the intent handler bound the task to this evaluation cycle.
    let presented_sha = sub.evaluation_sha.as_str().to_owned();
    let stored_sha = task_row.evaluation_sha.clone().unwrap_or_default();
    if presented_sha != stored_sha {
        return Ok(WitnessAck::Rejected {
            reason: WitnessRejectionReason::EvaluationShaMismatch {
                expected: stored_sha,
                presented: presented_sha,
            },
        });
    }

    // ── Step 3: Body hash ─────────────────────────────────────────────────
    // Hash the raw JSON body bytes to get the content-address for the blob.
    let body_bytes = serde_json::to_vec(&sub.body).unwrap_or_default();
    let blob_sha256 = raxis_crypto::token::sha256_hex(&body_bytes);

    // Map WitnessResultClass → witness_index::ResultClass (same semantics,
    // different type so witness_index stays independent of raxis-types).
    let result_class = map_result_class(sub.result_class);

    // ── Step 4: Witness write ─────────────────────────────────────────────
    // "Routes through witness_index facade only." (boundary rule)
    // Write blob to filesystem first, then insert SQL index row.
    let record = WitnessRecord {
        verifier_run_id: run_id.clone(),
        evaluation_sha:  presented_sha.clone(),
        task_id:         sub.task_id.as_str().to_owned(),
        gate_type:       sub.gate_type.as_str().to_owned(),
        result_class:    result_class.clone(),
        blob_sha256:     blob_sha256.clone(),
        blob_path:       blob_sha256.clone(), // content-addressed; path == sha256 per witness_index
        recorded_at:     unix_now(),
    };

    witness_index::write(&record, &body_bytes, &ctx.witness_dir, store)
        .map_err(|e| HandlerError::WitnessWrite(e.to_string()))?;

    // ── Step 5: Token consume ─────────────────────────────────────────────
    // Spec ordering: "write-then-consume: if the write fails, the token is not
    // consumed and the verifier may resubmit." We consume only after success.
    verifier_token::consume_verifier_token(sub.verifier_token.as_str(), store)
        .map_err(|e| HandlerError::Unauthorized { reason: format!("consume failed: {e}") })?;

    // Structured audit log (full audit integration is v2; structured stderr for now).
    eprintln!(
        "{{\"level\":\"info\",\"event\":\"WitnessAccepted\",\
         \"run_id\":\"{run_id}\",\"task_id\":\"{}\",\"evaluation_sha\":\"{presented_sha}\",\
         \"gate_type\":\"{}\",\"result_class\":\"{}\",\"blob_sha256\":\"{blob_sha256}\"}}",
        sub.task_id.as_str(),
        sub.gate_type.as_str(),
        result_class.as_str(),
    );

    // ── Step 6: Gate-recheck ──────────────────────────────────────────────
    // Only recheck if the witness was a Pass — Fail/Inconclusive can't clear
    // the gate, so skip the evaluation round-trip for those cases.
    if result_class != ResultClass::Pass {
        eprintln!(
            "{{\"level\":\"info\",\"event\":\"WitnessNonPass\",\
             \"task_id\":\"{}\",\"result_class\":\"{}\"}}",
            sub.task_id.as_str(),
            result_class.as_str(),
        );
        // Task stays GatesPending. No verifier spawn.
        return Ok(WitnessAck::Accepted { run_id: run_id.clone(), remaining_gates: vec![] });
    }

    let remaining_gates = gate_recheck(
        sub.task_id.as_str(),
        &presented_sha,
        &task_row,
        ctx,
    ).await?;

    Ok(WitnessAck::Accepted { run_id, remaining_gates })
}

// ---------------------------------------------------------------------------
// gate_recheck — post-witness gate evaluation loop
// ---------------------------------------------------------------------------

/// Re-run gate evaluation after a witness write and, if all gates clear,
/// transition the task GatesPending → Admitted.
///
/// Spec §2.3 witness.rs gate-recheck rules:
///   - Re-derives touched_paths from VCS using task.base_sha / evaluation_sha.
///   - Uses task.session_id for evaluate_claims (NOT the verifier's session).
///   - Pass   → transition_to_admitted + emit TaskGatesCleared.
///   - Pending → spawn remaining verifiers; return remaining gate list.
///   - Claim fail → task stays GatesPending; planner must act.
async fn gate_recheck(
    task_id: &str,
    evaluation_sha: &str,
    task_row: &TaskRowData,
    ctx: &HandlerContext,
) -> Result<Vec<GateType>, HandlerError> {
    // Resolve worktree_root from session if available, else fall back to data_dir.
    let worktree_root = resolve_worktree_root(task_row, ctx);

    // Re-derive touched_paths using the stored base/head SHAs.
    // This mirrors exactly what handlers/intent.rs computed at intent time.
    let touched_paths: Vec<PathBuf> = if let (Some(base), Some(head)) =
        (&task_row.base_sha, &task_row.evaluation_sha)
    {
        let base_sha = vcs::diff::CommitSha::new(base)
            .map_err(|e| HandlerError::GateRecheck(format!("invalid base_sha: {e}")))?;
        let head_sha = vcs::diff::CommitSha::new(head)
            .map_err(|e| HandlerError::GateRecheck(format!("invalid evaluation_sha: {e}")))?;
        vcs::compute(&base_sha, &head_sha, &worktree_root)
            .map_err(|e| HandlerError::GateRecheck(format!("vcs diff failed: {e}")))?
    } else {
        // No SHA range — no touched paths, no gate requirements.
        vec![]
    };

    // Parse session_id from task row (used for gate evaluation, not the verifier session).
    let session_id = {
        let sid_str = task_row.session_id.as_deref().unwrap_or("");
        raxis_types::SessionId::parse(sid_str)
            .map_err(|_| HandlerError::Store("task has no session_id".to_owned()))?
    };

    // Gate evaluation — uses the planner session's delegation context.
    // Spec: "task.session_id is used, not sub.session_id — the verifier's
    // ValidatedSession carries no planner delegations."
    let gate_result = gates::evaluate_claims(
        &session_id,
        evaluation_sha,
        task_id,
        &touched_paths,
        &[], // submitted_claims: re-loaded from task row in production; empty stub for v1
        &worktree_root,
        ctx,
    ).await
    .map_err(|e| HandlerError::GateRecheck(e.to_string()))?;

    match gate_result {
        GateEvalResult::Pass { .. } | GateEvalResult::BreakglassPass { .. } => {
            // All gates satisfied — transition GatesPending → Admitted.
            // Uses scheduler::transition_to_admitted which enforces the FSM edge
            // and calls evaluate_terminal_criteria (INV-INIT-04).
            crate::scheduler::transition_to_admitted(task_id, ctx.store.as_ref())
                .map_err(|e| HandlerError::Store(e.to_string()))?;

            eprintln!(
                "{{\"level\":\"info\",\"event\":\"TaskGatesCleared\",\
                 \"task_id\":\"{task_id}\",\"final_witness_run_id\":\"(recheck-pass)\"}}",
            );

            Ok(vec![])
        }

        GateEvalResult::PendingWitness { missing_gates } => {
            // Some gates still outstanding. The intent handler already spawned
            // the original verifiers; on recheck we re-spawn for whichever are
            // still missing (e.g. the one that just passed was the last before
            // others finish).
            eprintln!(
                "{{\"level\":\"info\",\"event\":\"GatesStillPending\",\
                 \"task_id\":\"{task_id}\",\"remaining\":{}}}",
                missing_gates.len()
            );

            // Re-spawn verifiers for remaining missing gates.
            for gate_type_str in &missing_gates {
                if let Some(vconfig) = crate::gates::verifier_runner::VerifierConfig::from_policy(
                    ctx.policy.as_ref(),
                    gate_type_str,
                    &ctx.data_dir,
                ) {
                    let _ = crate::gates::verifier_runner::spawn_verifier(
                        task_id,
                        gate_type_str,
                        evaluation_sha,
                        &worktree_root,
                        &vconfig,
                        ctx.store.as_ref(),
                    ).await;
                }
            }

            // Return GateType instances for each remaining gate.
            let remaining: Vec<GateType> = missing_gates
                .iter()
                .filter_map(|s| raxis_types::GateType::parse(s).ok())
                .collect();

            Ok(remaining)
        }

        GateEvalResult::ClaimInsufficient { reason } => {
            // Claim/delegation failure. Witness is in the index and token is
            // consumed, but the task stays GatesPending. Planner must act.
            // Spec: "the kernel does NOT auto-spawn further verifiers".
            eprintln!(
                "{{\"level\":\"warn\",\"event\":\"WitnessClaimInsufficient\",\
                 \"task_id\":\"{task_id}\",\"reason\":\"{reason}\"}}",
            );
            Ok(vec![])
        }
    }
}

// ---------------------------------------------------------------------------
// Task row helper
// ---------------------------------------------------------------------------

/// Subset of task columns needed by the witness handler.
#[derive(Debug)]
struct TaskRowData {
    state:          String,
    evaluation_sha: Option<String>,
    base_sha:       Option<String>,
    session_id:     Option<String>,
    worktree_root:  Option<String>, // denormalised from sessions at admit time (v1 simplification)
    lane_id:        String,
}

fn load_task_row(task_id: &str, store: &raxis_store::Store) -> Result<TaskRowData, HandlerError> {
    let conn = store.lock_sync();
    conn.query_row(
        &format!("SELECT state, evaluation_sha, base_sha, session_id, lane_id FROM {TASKS} WHERE task_id = ?1"),
        rusqlite::params![task_id],
        |row| Ok(TaskRowData {
            state:          row.get(0)?,
            evaluation_sha: row.get(1)?,
            base_sha:       row.get(2)?,
            session_id:     row.get(3)?,
            worktree_root:  None, // resolved via session join below
            lane_id:        row.get(4)?,
        }),
    ).map_err(|e| match e {
        rusqlite::Error::QueryReturnedNoRows => HandlerError::InvalidTask {
            task_id: task_id.to_owned(),
        },
        other => HandlerError::Store(other.to_string()),
    })
}

fn resolve_worktree_root(task_row: &TaskRowData, ctx: &HandlerContext) -> PathBuf {
    // Attempt to load worktree_root from the session row.
    // Falls back to data_dir on failure (safe: VCS calls will fail gracefully
    // if the path does not contain a git repo).
    if let Some(session_id) = &task_row.session_id {
        if let Ok(sid) = raxis_types::SessionId::parse(session_id) {
            if let Ok(sess) = crate::authority::session::get_session(&sid, ctx.store.as_ref()) {
                if let Some(wt) = sess.worktree_root {
                    return PathBuf::from(wt);
                }
            }
        }
    }
    ctx.data_dir.clone()
}

fn map_result_class(rc: raxis_types::WitnessResultClass) -> ResultClass {
    match rc {
        raxis_types::WitnessResultClass::Pass        => ResultClass::Pass,
        raxis_types::WitnessResultClass::Fail        => ResultClass::Fail,
        raxis_types::WitnessResultClass::Inconclusive => ResultClass::Inconclusive,
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
    use raxis_types::{WitnessResultClass, WitnessSubmission, CommitSha, TaskId, GateType};

    // ── WitnessRejectionReason equality sanity check ──────────────────────

    #[test]
    fn evaluation_sha_mismatch_reason_carries_both_values() {
        let reason = WitnessRejectionReason::EvaluationShaMismatch {
            expected:  "aaaa".to_owned(),
            presented: "bbbb".to_owned(),
        };
        match reason {
            WitnessRejectionReason::EvaluationShaMismatch { expected, presented } => {
                assert_eq!(expected,  "aaaa");
                assert_eq!(presented, "bbbb");
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn task_not_gates_pending_reason_carries_state() {
        let reason = WitnessRejectionReason::TaskNotGatesPending {
            current_state: "Running".to_owned(),
        };
        match reason {
            WitnessRejectionReason::TaskNotGatesPending { current_state } => {
                assert_eq!(current_state, "Running");
            }
            _ => panic!("wrong variant"),
        }
    }

    // ── map_result_class ──────────────────────────────────────────────────

    #[test]
    fn pass_maps_to_pass() {
        assert_eq!(map_result_class(WitnessResultClass::Pass), ResultClass::Pass);
    }

    #[test]
    fn fail_maps_to_fail() {
        assert_eq!(map_result_class(WitnessResultClass::Fail), ResultClass::Fail);
    }

    #[test]
    fn inconclusive_maps_to_inconclusive() {
        assert_eq!(
            map_result_class(WitnessResultClass::Inconclusive),
            ResultClass::Inconclusive,
        );
    }

    // ── WitnessAck variants ───────────────────────────────────────────────

    #[test]
    fn accepted_empty_remaining_gates_means_all_clear() {
        let ack = WitnessAck::Accepted { run_id: "r-1".to_owned(), remaining_gates: vec![] };
        match ack {
            WitnessAck::Accepted { remaining_gates, .. } => assert!(remaining_gates.is_empty()),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn rejected_carries_typed_reason() {
        let ack = WitnessAck::Rejected {
            reason: WitnessRejectionReason::TaskNotGatesPending {
                current_state: "Admitted".to_owned(),
            },
        };
        assert!(matches!(ack, WitnessAck::Rejected { .. }));
    }

    // ── HandlerError display ──────────────────────────────────────────────

    #[test]
    fn handler_error_unauthorized_includes_reason() {
        let err = HandlerError::Unauthorized {
            reason: "token expired".to_owned(),
        };
        assert!(err.to_string().contains("token expired"));
    }

    #[test]
    fn handler_error_invalid_task_includes_id() {
        let err = HandlerError::InvalidTask { task_id: "t-99".to_owned() };
        assert!(err.to_string().contains("t-99"));
    }
}

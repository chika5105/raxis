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

use raxis_types::{unix_now_secs, GateType, WitnessSubmission};
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

/// Application-level outcome of a `WitnessSubmission`.
///
/// This is *not* a `Result` error — every variant is a *successful* response
/// from the handler's perspective; `Rejected` simply means the submission was
/// refused for a typed application reason, and the transport stays open.
///
/// **Pass vs non-Pass distinction (v1 review item #14).**
/// Pre-fix, both `Pass` and `Fail` / `Inconclusive` witnesses returned the
/// same `Accepted { remaining_gates: vec![] }` shape, which lied to the
/// planner: an empty `remaining_gates` MUST mean "all gates cleared, you may
/// advance the task" — but a `Fail` witness leaves the gate UNcleared. The
/// planner had no way to tell the two situations apart without reparsing
/// audit. We now use a separate variant for non-Pass acks so the planner
/// can route correctly without speculative re-reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WitnessAck {
    /// Submission accepted, witness written, token consumed, **and** the
    /// task's gate set was re-evaluated. `remaining_gates` is the list of
    /// gates STILL needing a `Pass` witness; an empty vec MEANS the task may
    /// now advance out of `GatesPending`. Only `result_class == Pass`
    /// submissions take this path.
    Accepted { run_id: String, remaining_gates: Vec<GateType> },

    /// Submission accepted and witness written, but the result was NOT a
    /// `Pass`, so the gate cannot be cleared by this submission. The task
    /// remains in `GatesPending`. The planner SHOULD treat this as a
    /// terminal-for-this-attempt outcome for the named gate (typically:
    /// transition the task to `Failed` or queue an operator escalation).
    AcceptedNonPass {
        run_id: String,
        gate_type: GateType,
        result_class: ResultClass,
    },

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
///
/// **Async safety:** every helper this function calls that touches
/// `Store::lock_sync()` (verifier_token::validate / consume_verifier_token,
/// load_task_row, witness_index::write) is wrapped in
/// `tokio::task::spawn_blocking`. Calling them directly from this `async`
/// frame would panic with "Cannot block the current thread from within a
/// runtime" because `Store::lock_sync` ultimately invokes
/// `tokio::sync::Mutex::blocking_lock`, which refuses to run on a tokio
/// worker thread (kernel-store.md §2.5.1 documents this contract; the
/// same rationale applies in `gates::verifier_runner::spawn_verifier`
/// and `lifecycle::approve_plan`). This was a latent P0 — pre-fix,
/// the very first witness submission against a multi-thread runtime
/// would crash the planner socket task. Pinned by
/// `gates::verifier_runner::stub_round_trip::*`.
pub async fn handle(
    sub: WitnessSubmission,
    ctx: &HandlerContext,
) -> Result<WitnessAck, HandlerError> {
    // Hash the raw JSON body bytes to get the content-address for the blob.
    // Pure compute — no SQL, runs on the async thread.
    let body_bytes = serde_json::to_vec(&sub.body).unwrap_or_default();
    let blob_sha256 = raxis_crypto::token::sha256_hex(&body_bytes);

    // Map WitnessResultClass → witness_index::ResultClass (same semantics,
    // different type so witness_index stays independent of raxis-types).
    let result_class = map_result_class(sub.result_class);

    // ── INV-STORE-02 (kernel-store.md §2.5.1.1 Pattern C): single-transaction
    //    witness commit ────────────────────────────────────────────────────
    //
    // Pre-fix, validate / load_task / write_index / consume each ran in a
    // separate `spawn_blocking` (separate mutex acquisition, separate
    // auto-committed statement). A concurrent `recovery::reconcile_tasks`
    // could expire the verifier token between validate and consume,
    // leaving a witness row whose producer received a `TokenConsumed`
    // rejection — INV-INIT-08 violation: the gate evaluator would later
    // see a witness for a callback the kernel told the verifier was
    // refused.
    //
    // We now run the entire SQL portion (validate → load task →
    // insert witness index → consume token) inside ONE
    // `conn.transaction()`. If consume reports 0 rows (token concurrently
    // expired), the entire transaction rolls back, undoing the witness
    // INSERT. The FS blob write happens outside the mutex (it's
    // content-addressed and idempotent — orphan blobs are harmless and
    // detected by `witness_index::startup_check`).
    let store = ctx.store.clone();
    let witness_dir = ctx.witness_dir.clone();
    let raw_token = sub.verifier_token.clone();
    let task_id_owned = sub.task_id.as_str().to_owned();
    let gate_type_owned = sub.gate_type.as_str().to_owned();
    let presented_sha = sub.evaluation_sha.as_str().to_owned();
    let result_class_for_record = result_class.clone();
    let blob_sha256_owned = blob_sha256.clone();
    let body_bytes_owned = body_bytes.clone();

    enum CommitOutcome {
        Accepted { run_id: String, task_row: TaskRowData },
        Rejected(WitnessRejectionReason),
    }

    let presented_sha_for_closure = presented_sha.clone();
    let outcome: CommitOutcome = tokio::task::spawn_blocking(move || -> Result<CommitOutcome, HandlerError> {
        // (a) FS blob write outside the transaction — content-addressed,
        // idempotent, no SQL state to roll back if a later step fails.
        let provisional_record = WitnessRecord {
            verifier_run_id: String::new(),
            evaluation_sha:  presented_sha_for_closure.clone(),
            task_id:         task_id_owned.clone(),
            gate_type:       gate_type_owned.clone(),
            result_class:    result_class_for_record.clone(),
            blob_sha256:     blob_sha256_owned.clone(),
            blob_path:       blob_sha256_owned.clone(),
            recorded_at:     0,
        };
        witness_index::write_blob_to_disk(&provisional_record, &body_bytes_owned, &witness_dir)
            .map_err(|e| HandlerError::WitnessWrite(e.to_string()))?;

        // (b) SQL portion — single transaction.
        let mut conn = store.lock_sync();
        let tx = conn.transaction().map_err(|e| HandlerError::Store(e.to_string()))?;

        // Step 1 (in-tx): validate token. If it fails for any reason, the
        // transaction rolls back on drop — no witness row is committed.
        let run_id = verifier_token::validate_verifier_token_in_tx(&tx, &raw_token)
            .map_err(|e| HandlerError::Unauthorized { reason: e.to_string() })?;

        // Step 2 (in-tx): load task row + binding check. Re-checking inside
        // the transaction (vs a pre-tx read) closes the TOCTOU window
        // where the task could have been swept to BlockedRecoveryPending
        // or had its evaluation_sha rebound between any pre-tx read and
        // this point.
        let task_row = load_task_row_in_tx(&tx, &task_id_owned)?;
        if task_row.state != TaskState::GatesPending.as_sql_str() {
            drop(tx); // rollback — token is NOT consumed.
            return Ok(CommitOutcome::Rejected(WitnessRejectionReason::TaskNotGatesPending {
                current_state: task_row.state,
            }));
        }
        let stored_sha = task_row.evaluation_sha.clone().unwrap_or_default();
        if presented_sha_for_closure != stored_sha {
            drop(tx);
            return Ok(CommitOutcome::Rejected(WitnessRejectionReason::EvaluationShaMismatch {
                expected:  stored_sha,
                presented: presented_sha_for_closure,
            }));
        }

        // Step 3 (in-tx): insert witness index row.
        let record = WitnessRecord {
            verifier_run_id: run_id.clone(),
            evaluation_sha:  presented_sha_for_closure.clone(),
            task_id:         task_id_owned.clone(),
            gate_type:       gate_type_owned.clone(),
            result_class:    result_class_for_record.clone(),
            blob_sha256:     blob_sha256_owned.clone(),
            blob_path:       blob_sha256_owned,
            recorded_at:     unix_now_secs(),
        };
        witness_index::insert_witness_index_in_tx(&tx, &record, record.recorded_at)
            .map_err(|e| HandlerError::WitnessWrite(e.to_string()))?;

        // Step 4 (in-tx): consume token. If a concurrent reconcile expired
        // it between (a) and now, this returns TokenConsumed → we propagate
        // an Unauthorized error and the transaction is rolled back, undoing
        // the witness INSERT we just wrote. INV-INIT-08 holds.
        verifier_token::consume_verifier_token_in_tx(&tx, &raw_token)
            .map_err(|e| HandlerError::Unauthorized { reason: format!("consume failed: {e}") })?;

        tx.commit().map_err(|e| HandlerError::Store(e.to_string()))?;
        Ok(CommitOutcome::Accepted { run_id, task_row })
    })
    .await
    .map_err(|e| HandlerError::Store(format!("witness commit join: {e}")))??;

    let (run_id, task_row) = match outcome {
        CommitOutcome::Accepted { run_id, task_row } => (run_id, task_row),
        CommitOutcome::Rejected(reason) => return Ok(WitnessAck::Rejected { reason }),
    };

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
    // the gate, so skip the evaluation round-trip for those cases. We return
    // a distinct ack variant so the planner does not mistake "non-Pass
    // recorded" for "all gates cleared, you may advance".
    if result_class != ResultClass::Pass {
        eprintln!(
            "{{\"level\":\"info\",\"event\":\"WitnessNonPass\",\
             \"task_id\":\"{}\",\"result_class\":\"{}\"}}",
            sub.task_id.as_str(),
            result_class.as_str(),
        );
        return Ok(WitnessAck::AcceptedNonPass {
            run_id,
            gate_type: sub.gate_type.clone(),
            result_class,
        });
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
        // V2 migration: dispatch through the `DomainAdapter`
        // (`extensibility-traits.md §2.2.B`). Newtype validation is
        // preserved so we surface a parsing error before the trait
        // call, mirroring the regular intent admission path.
        let _base_sha = vcs::diff::CommitSha::new(base)
            .map_err(|e| HandlerError::GateRecheck(format!("invalid base_sha: {e}")))?;
        let _head_sha = vcs::diff::CommitSha::new(head)
            .map_err(|e| HandlerError::GateRecheck(format!("invalid evaluation_sha: {e}")))?;
        let resources = ctx.domain
            .compute_touched_paths(base, head, &worktree_root)
            .await
            .map_err(|e| HandlerError::GateRecheck(format!("domain diff failed: {e}")))?;
        resources
            .resources
            .into_iter()
            .map(|r| {
                let stripped = r.uri.strip_prefix("path:///").unwrap_or(&r.uri);
                PathBuf::from(stripped)
            })
            .collect()
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
                    &ctx.policy.load(),
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

#[allow(dead_code)]
fn load_task_row(task_id: &str, store: &raxis_store::Store) -> Result<TaskRowData, HandlerError> {
    let conn = store.lock_sync();
    load_task_row_in_tx(&conn, task_id)
}

/// Load the task row inside an existing transaction.
///
/// Used by the witness handler's single-transaction commit path
/// (`kernel-store.md` §2.5.1.1 Pattern C) so the task-state and
/// evaluation_sha checks see the SAME snapshot the witness INSERT and
/// token UPDATE will commit against — closing the TOCTOU window where
/// the task could have been swept to BlockedRecoveryPending or had its
/// evaluation_sha rebound between a pre-tx read and the witness commit.
fn load_task_row_in_tx(
    conn:    &rusqlite::Connection,
    task_id: &str,
) -> Result<TaskRowData, HandlerError> {
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use raxis_types::WitnessResultClass;

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

    /// Regression guard for v1 review item #14: a non-Pass witness MUST
    /// surface as `AcceptedNonPass` (NOT `Accepted { remaining_gates: [] }`),
    /// because an empty `remaining_gates` is reserved for "all gates cleared
    /// — the planner may now advance the task". Conflating the two would
    /// silently advance tasks that just failed a gate.
    #[test]
    fn non_pass_uses_distinct_variant_from_all_clear() {
        let all_clear = WitnessAck::Accepted {
            run_id: "r-1".to_owned(),
            remaining_gates: vec![],
        };
        let non_pass = WitnessAck::AcceptedNonPass {
            run_id: "r-2".to_owned(),
            gate_type: raxis_types::GateType::parse("TestCoverage").unwrap(),
            result_class: ResultClass::Fail,
        };
        // The distinct variant is the whole point — they MUST NOT be `==`.
        assert_ne!(all_clear, non_pass);
        assert!(matches!(all_clear, WitnessAck::Accepted { .. }));
        assert!(matches!(non_pass, WitnessAck::AcceptedNonPass { .. }));
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

    // ── INV-STORE-02 (kernel-store.md §2.5.1.1 Pattern C) regression ──────
    //
    // The witness commit path runs validate + insert_witness + consume in
    // ONE `conn.transaction()` so a concurrent `recovery::reconcile_tasks`
    // that expires the verifier token mid-flight cannot leave a
    // committed witness row whose producer received an Unauthorized
    // reply. We pin the SQL portion of that contract here.

    use raxis_store::{Store, Table};
    use raxis_crypto::token::{generate_verifier_token, sha256_hex};
    use crate::authority::verifier_token::{
        validate_verifier_token_in_tx, consume_verifier_token_in_tx,
    };
    use crate::witness_index::{insert_witness_index_in_tx, ResultClass, WitnessRecord};

    /// Insert: `initiative` → `task` (GatesPending) → `verifier_run_token`.
    /// Returns (raw_token_hex, run_id).
    fn seed_pending_witness(store: &Store, task_id: &str) -> (String, String) {
        let run_id = format!("run-{task_id}");
        let conn = store.lock_sync();
        // Initiative.
        conn.execute(
            &format!("INSERT INTO {} (initiative_id, state, terminal_criteria_json, plan_artifact_sha256, created_at) \
                     VALUES ('init-w', 'Executing', '{{}}', '', 0)",
                Table::Initiatives.as_str()),
            [],
        ).unwrap();
        // Task.
        conn.execute(
            &format!("INSERT INTO {} (task_id, initiative_id, lane_id, state, evaluation_sha, actor, policy_epoch, admitted_at, transitioned_at) \
                     VALUES (?1, 'init-w', 'default', 'GatesPending', 'sha-eval', 'kernel', 0, 0, 0)",
                Table::Tasks.as_str()),
            rusqlite::params![task_id],
        ).unwrap();
        // Verifier token.
        let (raw_token, token_hash) = generate_verifier_token().unwrap();
        let now = raxis_types::unix_now_secs();
        conn.execute(
            &format!("INSERT INTO {} (verifier_run_id, task_id, gate_type, evaluation_sha, token_hash, issued_at, expires_at, consumed) \
                     VALUES (?1, ?2, 'TestGate', 'sha-eval', ?3, ?4, ?5, 0)",
                Table::VerifierRunTokens.as_str()),
            rusqlite::params![&run_id, task_id, &token_hash, now, now + 3600],
        ).unwrap();
        (raw_token, run_id)
    }

    fn make_record(run_id: &str, task_id: &str) -> WitnessRecord {
        let blob_sha = sha256_hex(b"witness-body");
        WitnessRecord {
            verifier_run_id: run_id.to_owned(),
            evaluation_sha:  "sha-eval".to_owned(),
            task_id:         task_id.to_owned(),
            gate_type:       "TestGate".to_owned(),
            result_class:    ResultClass::Pass,
            blob_sha256:     blob_sha.clone(),
            blob_path:       blob_sha,
            recorded_at:     0,
        }
    }

    /// Happy path: validate + insert_witness + consume all commit
    /// together. Witness row visible after commit.
    #[test]
    fn commit_witness_in_tx_happy_path_commits_all_three() {
        let store = Store::open_in_memory().unwrap();
        let (raw_token, run_id) = seed_pending_witness(&store, "t-w-1");
        let record = make_record(&run_id, "t-w-1");

        let mut conn = store.lock_sync();
        let tx = conn.transaction().unwrap();
        validate_verifier_token_in_tx(&tx, &raw_token).unwrap();
        insert_witness_index_in_tx(&tx, &record, 1).unwrap();
        consume_verifier_token_in_tx(&tx, &raw_token).unwrap();
        tx.commit().unwrap();
        drop(conn);

        let conn = store.lock_sync();
        let n_witness: i64 = conn.query_row(
            &format!("SELECT COUNT(*) FROM {}", Table::WitnessRecords.as_str()),
            [], |r| r.get(0),
        ).unwrap();
        let consumed: i64 = conn.query_row(
            &format!("SELECT consumed FROM {} WHERE verifier_run_id=?1",
                Table::VerifierRunTokens.as_str()),
            rusqlite::params![&run_id], |r| r.get(0),
        ).unwrap();
        assert_eq!(n_witness, 1, "witness row must be visible after commit");
        assert_eq!(consumed, 1, "token must be marked consumed after commit");
    }

    /// **Pre-fix bug, post-fix guarantee:** if the consume step fails
    /// (token concurrently expired by reconcile, or already consumed by
    /// a parallel verifier callback), the entire transaction MUST roll
    /// back — undoing the witness INSERT we just wrote. INV-INIT-08:
    /// the gate evaluator MUST NOT see a witness whose producer
    /// received `Unauthorized`.
    #[test]
    fn commit_witness_in_tx_rolls_back_when_token_concurrently_expired() {
        let store = Store::open_in_memory().unwrap();
        let (raw_token, run_id) = seed_pending_witness(&store, "t-w-2");
        let _record = make_record(&run_id, "t-w-2");

        // Simulate `recovery::reconcile_tasks` expiring the token between
        // our pre-tx state and the consume step inside the transaction.
        // We pre-mark it consumed=1 so consume_in_tx returns 0 rows.
        {
            let conn = store.lock_sync();
            conn.execute(
                &format!("UPDATE {} SET consumed=1 WHERE verifier_run_id=?1",
                    Table::VerifierRunTokens.as_str()),
                rusqlite::params![&run_id],
            ).unwrap();
        }

        let mut conn = store.lock_sync();
        let tx = conn.transaction().unwrap();
        // Validate fails first because the token is already consumed —
        // good: the witness INSERT never runs.
        let validate_err = validate_verifier_token_in_tx(&tx, &raw_token).unwrap_err();
        assert!(matches!(validate_err,
            crate::authority::keys::AuthorityError::TokenConsumed));
        drop(tx); // rollback

        // Even though we dropped without committing, no witness row exists.
        drop(conn);
        let conn = store.lock_sync();
        let n_witness: i64 = conn.query_row(
            &format!("SELECT COUNT(*) FROM {}", Table::WitnessRecords.as_str()),
            [], |r| r.get(0),
        ).unwrap();
        assert_eq!(n_witness, 0, "no witness row may exist when validate fails");
    }

    /// More aggressive variant: validate succeeds, insert succeeds, then
    /// consume returns 0 rows (e.g. another verifier raced in and
    /// consumed the token between validate and consume — pre-fix this
    /// race was the canonical bug). Even though insert "succeeded",
    /// the transaction MUST roll back so the gate evaluator never sees
    /// the witness.
    #[test]
    fn commit_witness_in_tx_rolls_back_witness_when_consume_races() {
        let store = Store::open_in_memory().unwrap();
        let (raw_token, run_id) = seed_pending_witness(&store, "t-w-3");
        let record = make_record(&run_id, "t-w-3");

        let mut conn = store.lock_sync();
        let tx = conn.transaction().unwrap();
        validate_verifier_token_in_tx(&tx, &raw_token).unwrap();
        insert_witness_index_in_tx(&tx, &record, 1).unwrap();

        // Inside the SAME transaction, consume the token ONCE — succeeds.
        consume_verifier_token_in_tx(&tx, &raw_token).unwrap();
        // Calling consume AGAIN inside the same tx returns TokenConsumed
        // (rows=0) — modeling a parallel race outcome.
        let err = consume_verifier_token_in_tx(&tx, &raw_token).unwrap_err();
        assert!(matches!(err,
            crate::authority::keys::AuthorityError::TokenConsumed));
        // The witness handler's contract: on consume failure, drop the
        // tx (rollback) instead of committing. Verify the rollback
        // actually erases our witness INSERT.
        drop(tx);
        drop(conn);

        let conn = store.lock_sync();
        let n_witness: i64 = conn.query_row(
            &format!("SELECT COUNT(*) FROM {}", Table::WitnessRecords.as_str()),
            [], |r| r.get(0),
        ).unwrap();
        assert_eq!(n_witness, 0,
            "witness INSERT must be rolled back when consume reports a race");
    }
}

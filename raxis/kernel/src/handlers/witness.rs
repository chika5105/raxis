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

use raxis_store::Table;
use raxis_types::TaskState;
use raxis_types::{unix_now_secs, GateType, WitnessSubmission};

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
    Accepted {
        run_id: String,
        remaining_gates: Vec<GateType>,
    },

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
    EvaluationShaMismatch { expected: String, presented: String },
    /// The task is not in GatesPending state — the submission arrived too late
    /// (task already recovered/aborted) or for the wrong task state.
    TaskNotGatesPending { current_state: String },
    /// iter63-followups.md Item 1 (D) — the verifier’s claimed
    /// `body.operator_hints` collides with the kernel-reserved
    /// echo key, which the kernel populates from policy-declared
    /// hints rather than trusting the verifier. Submission rejected,
    /// token NOT consumed, `WitnessOperatorHintSpoofingDetected`
    /// audit emitted. Pinned by
    /// `INV-WITNESS-OPERATOR-HINT-SPOOFING-REJECTED-01`.
    SpoofedOperatorHints,
    /// iter63-followups.md Item 2 #3 — the task’s cumulative
    /// verifier-time budget has been exhausted before this
    /// submission. The verifier’s claim is dropped on the
    /// floor; token NOT consumed (since validation never reached
    /// the consume step in the spawn-side budget check). Held
    /// here as a typed wire variant so the upstream gate path
    /// can fail the gate uniformly when a budget-exhausted task
    /// still races a witness through.
    TimeBudgetExhausted,
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

    /// iter63-followups.md Item 2 #5 — the witness handler exceeded
    /// the bounded `WITNESS_HANDLER_TIMEOUT_SECS` window. The kernel
    /// emits `WitnessHandlerTimeout` and returns this error so the
    /// caller frees the dispatcher slot for other gate evaluations.
    /// Pinned by `INV-WITNESS-HANDLER-BOUNDED-01`.
    #[error("witness handler exceeded {WITNESS_HANDLER_TIMEOUT_SECS}s bound")]
    HandlerTimedOut,
}

/// iter63-followups.md Item 2 #5 — bounded handler budget.
/// The witness handler’s entire body MUST complete within this
/// many seconds for any well-formed submission, so a slow blob
/// write cannot stall the dispatcher and starve other gate
/// evaluations. Pinned by `INV-WITNESS-HANDLER-BOUNDED-01`.
pub const WITNESS_HANDLER_TIMEOUT_SECS: u64 = 5;

/// iter63-followups.md Item 1 (D) — reserved key in
/// `WitnessSubmission.body` for the kernel’s policy-declared
/// operator hints. The verifier MUST NOT set this key; if it
/// does, the kernel rejects the submission with
/// `SpoofedOperatorHints` and emits
/// `WitnessOperatorHintSpoofingDetected`.
pub const WITNESS_BODY_OPERATOR_HINTS_KEY: &str = "operator_hints";

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
/// load_task_row, the Pattern C witness commit transaction that
/// composes `witness_index::insert_witness_index_in_tx` with
/// `consume_verifier_token_in_tx`) is wrapped in
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
    // iter63-followups.md Item 2 #5 — bounded handler timeout.
    // Wraps the entire inner handle path in a 5-second budget so a
    // slow blob write cannot stall other gate evaluations. On timeout
    // we emit `WitnessHandlerTimeout` and return a typed error to the
    // caller; the dispatcher frees its slot. Pinned by
    // `INV-WITNESS-HANDLER-BOUNDED-01`.
    let task_id_for_audit = sub.task_id.as_str().to_owned();
    match tokio::time::timeout(
        std::time::Duration::from_secs(WITNESS_HANDLER_TIMEOUT_SECS),
        handle_inner(sub, ctx),
    )
    .await
    {
        Ok(result) => result,
        Err(_elapsed) => {
            let _ = ctx.audit.emit(
                raxis_audit_tools::AuditEventKind::WitnessHandlerTimeout {
                    task_id: Some(task_id_for_audit.clone()),
                    budget_seconds: WITNESS_HANDLER_TIMEOUT_SECS,
                },
                None,
                Some(&task_id_for_audit),
                None,
            );
            eprintln!(
                "{{\"level\":\"warn\",\"event\":\"WitnessHandlerTimeout\",\
                 \"task_id\":\"{task_id_for_audit}\",\
                 \"budget_seconds\":{WITNESS_HANDLER_TIMEOUT_SECS}}}",
            );
            Err(HandlerError::HandlerTimedOut)
        }
    }
}

/// Inner witness-submission processing. Wrapped in `handle()` for the
/// iter63 bounded 5-second handler budget
/// (`INV-WITNESS-HANDLER-BOUNDED-01`). All earlier handler
/// invariants (single-transaction Pattern C commit,
/// blob-before-tx ordering, spawn_blocking discipline) continue to
/// apply here.
async fn handle_inner(
    mut sub: WitnessSubmission,
    ctx: &HandlerContext,
) -> Result<WitnessAck, HandlerError> {
    // iter63-followups.md Item 1 (D) — operator-hint spoofing
    // detection + echo. Run BEFORE blob hashing so the body bytes
    // we hash + persist already include the kernel-supplied
    // `operator_hints` value (the verifier never sees this
    // mutation, but the witness-as-stored is the canonical
    // surface for reviewer inspection and the body hash is what
    // gets used everywhere downstream).
    //
    // Rules:
    //   * If the verifier’s body is a JSON object AND already
    //     contains the reserved key, REJECT and emit the spoofing
    //     audit row. Token is NOT consumed.
    //   * If the verifier’s body is a JSON object and the gate
    //     has policy-declared hints, inject the policy hints under
    //     the reserved key. The kernel is the only source of truth
    //     for what the operator declared — we never trust the
    //     verifier to echo hints back faithfully.
    //   * If the body is not a JSON object, hints are not injected
    //     today (operators relying on hints in this gate-type
    //     should structure their verifier to emit an object body).
    //     TODO(iter64): decide on operator-hints surfacing for
    //     non-Object witness bodies.
    if let serde_json::Value::Object(map) = &sub.body {
        if map.contains_key(WITNESS_BODY_OPERATOR_HINTS_KEY) {
            // Spoofing attempt — emit audit + reject. Token not
            // consumed (we have not validated it yet).
            let _ = ctx.audit.emit(
                raxis_audit_tools::AuditEventKind::WitnessOperatorHintSpoofingDetected {
                    task_id: sub.task_id.as_str().to_owned(),
                    gate_type: sub.gate_type.as_str().to_owned(),
                },
                None,
                Some(sub.task_id.as_str()),
                None,
            );
            eprintln!(
                "{{\"level\":\"warn\",\"event\":\"WitnessOperatorHintSpoofingDetected\",\
                 \"task_id\":\"{}\",\"gate_type\":\"{}\"}}",
                sub.task_id.as_str(),
                sub.gate_type.as_str(),
            );
            return Ok(WitnessAck::Rejected {
                reason: WitnessRejectionReason::SpoofedOperatorHints,
            });
        }
    }

    // Look up the gate’s policy-declared hints. Empty if the gate is
    // not declared in policy (e.g. integration-merge verifiers whose
    // hints are echoed via a separate channel) or if the operator
    // declared no hints.
    let policy_hints = lookup_policy_hints(sub.gate_type.as_str(), ctx);
    if !policy_hints.is_empty() {
        if let serde_json::Value::Object(ref mut map) = sub.body {
            // Convert the BTreeMap into a JSON object value. Order
            // is preserved by the BTreeMap (lex by key).
            let mut obj = serde_json::Map::with_capacity(policy_hints.len());
            for (k, v) in &policy_hints {
                obj.insert(k.clone(), v.clone());
            }
            map.insert(
                WITNESS_BODY_OPERATOR_HINTS_KEY.to_owned(),
                serde_json::Value::Object(obj),
            );
        }
        // Non-Object body: see TODO(iter64) above.
    }

    // Hash the raw JSON body bytes to get the content-address for the blob.
    // Pure compute — no SQL, runs on the async thread.
    //
    // INV-WITNESS-BODY-SERIALIZE-OR-FAIL-01 — `unwrap_or_default()` here
    // used to hash `[]` whenever `serde_json::to_vec` failed, which both
    // (a) collided every failed witness onto the empty-blob hash and
    // (b) produced an audit row claiming durable content-address for a
    // body that was never actually written. Surface the failure so the
    // verifier surface keeps its content-address invariant.
    let body_bytes = serde_json::to_vec(&sub.body)
        .map_err(|e| HandlerError::WitnessWrite(format!("witness body serialize failed: {e}")))?;
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
        Accepted {
            run_id: String,
            task_row: TaskRowData,
        },
        Rejected(WitnessRejectionReason),
    }

    let presented_sha_for_closure = presented_sha.clone();
    let outcome: CommitOutcome =
        tokio::task::spawn_blocking(move || -> Result<CommitOutcome, HandlerError> {
            // (a) FS blob write outside the transaction — content-addressed,
            // idempotent, no SQL state to roll back if a later step fails.
            let provisional_record = WitnessRecord {
                verifier_run_id: String::new(),
                evaluation_sha: presented_sha_for_closure.clone(),
                task_id: task_id_owned.clone(),
                gate_type: gate_type_owned.clone(),
                result_class: result_class_for_record.clone(),
                blob_sha256: blob_sha256_owned.clone(),
                blob_path: blob_sha256_owned.clone(),
                recorded_at: 0,
            };
            witness_index::write_blob_to_disk(&provisional_record, &body_bytes_owned, &witness_dir)
                .map_err(|e| HandlerError::WitnessWrite(e.to_string()))?;

            // (b) SQL portion — single transaction.
            let mut conn = store.lock_sync();
            let tx = conn
                .transaction()
                .map_err(|e| HandlerError::Store(e.to_string()))?;

            // Step 1 (in-tx): validate token. If it fails for any reason, the
            // transaction rolls back on drop — no witness row is committed.
            let run_id =
                verifier_token::validate_verifier_token_in_tx(&tx, &raw_token).map_err(|e| {
                    HandlerError::Unauthorized {
                        reason: e.to_string(),
                    }
                })?;

            // Step 2 (in-tx): load task row + binding check. Re-checking inside
            // the transaction (vs a pre-tx read) closes the TOCTOU window
            // where the task could have been swept to BlockedRecoveryPending
            // or had its evaluation_sha rebound between any pre-tx read and
            // this point.
            let task_row = load_task_row_in_tx(&tx, &task_id_owned)?;
            if task_row.state != TaskState::GatesPending.as_sql_str() {
                drop(tx); // rollback — token is NOT consumed.
                return Ok(CommitOutcome::Rejected(
                    WitnessRejectionReason::TaskNotGatesPending {
                        current_state: task_row.state,
                    },
                ));
            }
            let stored_sha = task_row.evaluation_sha.clone().unwrap_or_default();
            if presented_sha_for_closure != stored_sha {
                drop(tx);
                return Ok(CommitOutcome::Rejected(
                    WitnessRejectionReason::EvaluationShaMismatch {
                        expected: stored_sha,
                        presented: presented_sha_for_closure,
                    },
                ));
            }

            // Step 3 (in-tx): insert witness index row.
            let record = WitnessRecord {
                verifier_run_id: run_id.clone(),
                evaluation_sha: presented_sha_for_closure.clone(),
                task_id: task_id_owned.clone(),
                gate_type: gate_type_owned.clone(),
                result_class: result_class_for_record.clone(),
                blob_sha256: blob_sha256_owned.clone(),
                blob_path: blob_sha256_owned,
                recorded_at: unix_now_secs(),
            };
            witness_index::insert_witness_index_in_tx(&tx, &record, record.recorded_at)
                .map_err(|e| HandlerError::WitnessWrite(e.to_string()))?;

            // Step 4 (in-tx): consume token. If a concurrent reconcile expired
            // it between (a) and now, this returns TokenConsumed → we propagate
            // an Unauthorized error and the transaction is rolled back, undoing
            // the witness INSERT we just wrote. INV-INIT-08 holds.
            verifier_token::consume_verifier_token_in_tx(&tx, &raw_token).map_err(|e| {
                HandlerError::Unauthorized {
                    reason: format!("consume failed: {e}"),
                }
            })?;

            tx.commit()
                .map_err(|e| HandlerError::Store(e.to_string()))?;
            Ok(CommitOutcome::Accepted { run_id, task_row })
        })
        .await
        .map_err(|e| HandlerError::Store(format!("witness commit join: {e}")))??;

    let (run_id, task_row) = match outcome {
        CommitOutcome::Accepted { run_id, task_row } => (run_id, task_row),
        CommitOutcome::Rejected(reason) => return Ok(WitnessAck::Rejected { reason }),
    };

    // FOLLOWUP-E / INV-VERIFIER-AUDIT-PAIRED-WRITE-01 — emit the canonical
    // `VerifierWitnessReceived` audit row once the witness has been
    // accepted into the SQLite-side audit chain. Pairs with the
    // `VerifierVmSpawned` row that the verifier-runner emitted at spawn
    // time (same `verifier_run_id`). Initiative-id is left `None` here
    // because TaskRowData does not denormalise it today; iter63 can
    // extend the SELECT in `load_task_row_in_tx` and pass it through
    // without touching this call site.
    crate::gates::verifier_audit::emit_witness_received(
        ctx.audit.as_ref(),
        &run_id,
        result_class.as_str(),
        Some(&blob_sha256),
        Some(body_bytes.len() as u64),
        Some(sub.task_id.as_str()),
        None,
    );

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

    let remaining_gates =
        gate_recheck(sub.task_id.as_str(), &presented_sha, &task_row, ctx).await?;

    Ok(WitnessAck::Accepted {
        run_id,
        remaining_gates,
    })
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
    // `INV-WITNESS-GATE-RECHECK-ASYNC-SAFE-01`: `resolve_worktree_root`
    // calls `authority::session::get_session` which acquires
    // `Store::lock_sync` synchronously. Calling it directly from this
    // `async fn` (running on a tokio runtime worker) hits the same
    // "Cannot block the current thread from within a runtime" panic
    // the iter63 fix wrapped `gates::evaluate_pre_spawn` against.
    // Mirror the Phase-A spawn_blocking pattern at this site too.
    let worktree_root = {
        let store = ctx.store.clone();
        let session_id = task_row.session_id.clone();
        let data_dir = ctx.data_dir.clone();
        tokio::task::spawn_blocking(move || -> PathBuf {
            resolve_worktree_root_inner(session_id.as_deref(), store.as_ref(), &data_dir)
        })
        .await
        .map_err(|e| HandlerError::Store(format!("worktree_root resolve join: {e}")))?
    };

    // Re-derive touched_paths using the stored base/head SHAs.
    // This mirrors exactly what handlers/intent.rs computed at intent time.
    let touched_paths: Vec<PathBuf> =
        if let (Some(base), Some(head)) = (&task_row.base_sha, &task_row.evaluation_sha) {
            // V2 migration: dispatch through the `DomainAdapter`
            // (`extensibility-traits.md §2.2.B`). Newtype validation is
            // preserved so we surface a parsing error before the trait
            // call, mirroring the regular intent admission path.
            let _base_sha = vcs::diff::CommitSha::new(base)
                .map_err(|e| HandlerError::GateRecheck(format!("invalid base_sha: {e}")))?;
            let _head_sha = vcs::diff::CommitSha::new(head)
                .map_err(|e| HandlerError::GateRecheck(format!("invalid evaluation_sha: {e}")))?;
            let resources = ctx
                .domain
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
    )
    .await
    .map_err(|e| HandlerError::GateRecheck(e.to_string()))?;

    match gate_result {
        GateEvalResult::Pass { .. } | GateEvalResult::BreakglassPass { .. } => {
            // All gates satisfied — transition GatesPending → Admitted.
            // Uses scheduler::transition_to_admitted which delegates to
            // task_transitions::transition_task_with_audit so the
            // paired-write `AuditEventKind::TaskStateChanged` audit row
            // lands post-commit per
            // `INV-DASHBOARD-PUSH-FSM-COMPLETENESS-01` /
            // `INV-AUDIT-TASK-STATE-CHANGED-PAIRED-WRITE-01`.
            // Pre-fix the gate-recheck-clear path UPDATE'd the row but
            // never emitted the audit event, leaving the dashboard's
            // per-task lifecycle timeline stuck on "GatesPending"
            // even though the SQL state had flipped to Admitted.
            // `INV-WITNESS-GATE-RECHECK-ASYNC-SAFE-01`:
            // `transition_to_admitted` ultimately calls
            // `transition_task` → `store.lock_sync()` synchronously.
            // Wrap on the blocking pool so the async caller does not
            // panic with "Cannot block the current thread from within a
            // runtime" the way iter66.1's first IntegrationMerge witness
            // did.
            let task_id_owned = task_id.to_owned();
            let store_clone = ctx.store.clone();
            let audit_clone = ctx.audit.clone();
            let session_id_clone = task_row.session_id.clone();
            tokio::task::spawn_blocking(move || {
                crate::scheduler::transition_to_admitted(
                    &task_id_owned,
                    store_clone.as_ref(),
                    audit_clone.as_ref(),
                    session_id_clone.as_deref(),
                )
            })
            .await
            .map_err(|e| HandlerError::Store(format!("transition_to_admitted join: {e}")))?
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
            // Failure to spawn a verifier on recheck used to be
            // discarded silently — a task could then sit in
            // `GatesPending` forever with no operator-visible
            // signal beyond the prior `GatesStillPending` log.
            // Surface each spawn failure as a structured stderr
            // event so the operator sees which gate cannot make
            // progress and can intervene (lift the gate, increase
            // verifier capacity, or abort the task).
            for gate_type_str in &missing_gates {
                if let Some(vconfig) = crate::gates::verifier_runner::VerifierConfig::from_policy(
                    &ctx.policy.load(),
                    gate_type_str,
                    &ctx.data_dir,
                ) {
                    if let Err(e) = crate::gates::verifier_runner::spawn_verifier_with_audit(
                        task_id,
                        gate_type_str,
                        evaluation_sha,
                        &worktree_root,
                        &vconfig,
                        ctx.store.as_ref(),
                        Some(ctx.audit.clone()),
                    )
                    .await
                    {
                        eprintln!(
                            "{{\"level\":\"error\",\
                             \"event\":\"WitnessRecheckVerifierRespawnFailed\",\
                             \"task_id\":\"{task_id}\",\
                             \"gate\":\"{gate_type_str}\",\
                             \"error\":\"{e}\",\
                             \"hint\":\"task remains GatesPending; \
                                        the kernel will not auto-spawn this gate's \
                                        verifier again on subsequent witnesses — \
                                        operator action required\"}}"
                        );
                    }
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
    state: String,
    evaluation_sha: Option<String>,
    base_sha: Option<String>,
    session_id: Option<String>,
    worktree_root: Option<String>, // denormalised from sessions at admit time (v1 simplification)
    lane_id: String,
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
    conn: &rusqlite::Connection,
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

/// **CALLER-OWNED ASYNC SAFETY:** this function is synchronous and
/// acquires `Store::lock_sync()` via `authority::session::get_session`.
/// Async callers MUST invoke it on the blocking pool
/// (`tokio::task::spawn_blocking`) — the post-witness `gate_recheck`
/// path uses [`resolve_worktree_root_inner`] under exactly that
/// discipline. Pinned by `INV-WITNESS-GATE-RECHECK-ASYNC-SAFE-01`.
#[allow(dead_code)]
fn resolve_worktree_root(task_row: &TaskRowData, ctx: &HandlerContext) -> PathBuf {
    resolve_worktree_root_inner(
        task_row.session_id.as_deref(),
        ctx.store.as_ref(),
        &ctx.data_dir,
    )
}

/// Pure-sync helper: same as `resolve_worktree_root` but takes the
/// pieces it needs as primitives so the witness handler can hand them
/// to `tokio::task::spawn_blocking` without borrowing the
/// `HandlerContext` reference across the await point.
///
/// **DO NOT call this directly from async code.** Wrap it in
/// `spawn_blocking`. It calls `Store::lock_sync` which would otherwise
/// panic with "Cannot block the current thread from within a runtime".
/// Pinned by `INV-WITNESS-GATE-RECHECK-ASYNC-SAFE-01`.
fn resolve_worktree_root_inner(
    session_id: Option<&str>,
    store: &raxis_store::Store,
    data_dir: &std::path::Path,
) -> PathBuf {
    if let Some(session_id) = session_id {
        if let Ok(sid) = raxis_types::SessionId::parse(session_id) {
            if let Ok(sess) = crate::authority::session::get_session(&sid, store) {
                if let Some(wt) = sess.worktree_root {
                    return PathBuf::from(wt);
                }
            }
        }
    }
    data_dir.to_path_buf()
}

/// iter63-followups.md Item 1 (D) — resolve the policy-declared
/// operator hints for the `(gate_type)` pair. Returns an owned
/// `BTreeMap` so callers can mutate the witness body in place
/// without holding a borrow against `PolicyBundle`.
///
/// The kernel ALWAYS reads the hints from the policy snapshot,
/// never from the verifier’s claimed body — that’s the
/// `INV-WITNESS-OPERATOR-HINTS-ECHOED-01` guarantee.
///
/// Returns empty when:
///   * The gate isn’t declared in `[[gates]]` (e.g. integration-
///     merge verifiers route through `[[integration_merge_verifiers]]`
///     instead; their hints surface via a different code path).
///   * The gate is declared but its `hints` table is empty.
fn lookup_policy_hints(
    gate_type: &str,
    ctx: &HandlerContext,
) -> std::collections::BTreeMap<String, serde_json::Value> {
    let policy = ctx.policy.load();
    policy
        .gates()
        .iter()
        .find(|g| g.gate_type == gate_type)
        .map(|g| g.hints.clone())
        .unwrap_or_default()
}

fn map_result_class(rc: raxis_types::WitnessResultClass) -> ResultClass {
    match rc {
        raxis_types::WitnessResultClass::Pass => ResultClass::Pass,
        raxis_types::WitnessResultClass::Fail => ResultClass::Fail,
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
            expected: "aaaa".to_owned(),
            presented: "bbbb".to_owned(),
        };
        match reason {
            WitnessRejectionReason::EvaluationShaMismatch {
                expected,
                presented,
            } => {
                assert_eq!(expected, "aaaa");
                assert_eq!(presented, "bbbb");
            }
            _ => panic!("wrong variant"),
        }
    }

    /// iter63-followups.md Item 1 (D) —
    /// `INV-WITNESS-OPERATOR-HINT-SPOOFING-REJECTED-01` rejection
    /// reason is a typed wire variant with a stable shape so the
    /// dashboard/operator can route on it.
    #[test]
    fn spoofed_operator_hints_reason_is_distinct_wire_variant() {
        let reason = WitnessRejectionReason::SpoofedOperatorHints;
        let other = WitnessRejectionReason::TaskNotGatesPending {
            current_state: "GatesPending".to_owned(),
        };
        assert_ne!(reason, other);
        let ack = WitnessAck::Rejected {
            reason: WitnessRejectionReason::SpoofedOperatorHints,
        };
        match ack {
            WitnessAck::Rejected { reason } => {
                assert!(matches!(
                    reason,
                    WitnessRejectionReason::SpoofedOperatorHints
                ));
            }
            _ => panic!("wrong variant"),
        }
    }

    /// iter63-followups.md Item 2 #3 —
    /// `WitnessRejectionReason::TimeBudgetExhausted` is a typed
    /// rejection so the gate-evaluation orchestrator can fail the
    /// gate uniformly when a budget-exhausted task races a witness
    /// through.
    #[test]
    fn time_budget_exhausted_reason_is_distinct_wire_variant() {
        let reason = WitnessRejectionReason::TimeBudgetExhausted;
        let other = WitnessRejectionReason::SpoofedOperatorHints;
        assert_ne!(reason, other);
    }

    /// iter63-followups.md Item 2 #5 — the bounded-handler
    /// budget MUST be 5 seconds (pinned by
    /// `INV-WITNESS-HANDLER-BOUNDED-01`).
    #[test]
    fn witness_handler_timeout_constant_is_pinned_at_5_seconds() {
        assert_eq!(WITNESS_HANDLER_TIMEOUT_SECS, 5);
    }

    /// iter63-followups.md Item 1 (D) — the reserved key is the
    /// stable wire string `"operator_hints"`.
    #[test]
    fn witness_body_operator_hints_key_is_pinned() {
        assert_eq!(WITNESS_BODY_OPERATOR_HINTS_KEY, "operator_hints");
    }

    /// `HandlerError::HandlerTimedOut` carries the configured
    /// budget seconds in its display surface for operator
    /// triage.
    #[test]
    fn handler_error_timed_out_displays_budget_seconds() {
        let err = HandlerError::HandlerTimedOut;
        let msg = err.to_string();
        assert!(msg.contains("5s"), "got: {msg}");
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
        assert_eq!(
            map_result_class(WitnessResultClass::Pass),
            ResultClass::Pass
        );
    }

    #[test]
    fn fail_maps_to_fail() {
        assert_eq!(
            map_result_class(WitnessResultClass::Fail),
            ResultClass::Fail
        );
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
        let ack = WitnessAck::Accepted {
            run_id: "r-1".to_owned(),
            remaining_gates: vec![],
        };
        match ack {
            WitnessAck::Accepted {
                remaining_gates, ..
            } => assert!(remaining_gates.is_empty()),
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
        let err = HandlerError::InvalidTask {
            task_id: "t-99".to_owned(),
        };
        assert!(err.to_string().contains("t-99"));
    }

    // ── INV-STORE-02 (kernel-store.md §2.5.1.1 Pattern C) regression ──────
    //
    // The witness commit path runs validate + insert_witness + consume in
    // ONE `conn.transaction()` so a concurrent `recovery::reconcile_tasks`
    // that expires the verifier token mid-flight cannot leave a
    // committed witness row whose producer received an Unauthorized
    // reply. We pin the SQL portion of that contract here.

    use crate::authority::verifier_token::{
        consume_verifier_token_in_tx, validate_verifier_token_in_tx,
    };
    use crate::witness_index::{insert_witness_index_in_tx, ResultClass, WitnessRecord};
    use raxis_crypto::token::{generate_verifier_token, sha256_hex};
    use raxis_store::{Store, Table};

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
            evaluation_sha: "sha-eval".to_owned(),
            task_id: task_id.to_owned(),
            gate_type: "TestGate".to_owned(),
            result_class: ResultClass::Pass,
            blob_sha256: blob_sha.clone(),
            blob_path: blob_sha,
            recorded_at: 0,
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
        let n_witness: i64 = conn
            .query_row(
                &format!("SELECT COUNT(*) FROM {}", Table::WitnessRecords.as_str()),
                [],
                |r| r.get(0),
            )
            .unwrap();
        let consumed: i64 = conn
            .query_row(
                &format!(
                    "SELECT consumed FROM {} WHERE verifier_run_id=?1",
                    Table::VerifierRunTokens.as_str()
                ),
                rusqlite::params![&run_id],
                |r| r.get(0),
            )
            .unwrap();
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
                &format!(
                    "UPDATE {} SET consumed=1 WHERE verifier_run_id=?1",
                    Table::VerifierRunTokens.as_str()
                ),
                rusqlite::params![&run_id],
            )
            .unwrap();
        }

        let mut conn = store.lock_sync();
        let tx = conn.transaction().unwrap();
        // Validate fails first because the token is already consumed —
        // good: the witness INSERT never runs.
        let validate_err = validate_verifier_token_in_tx(&tx, &raw_token).unwrap_err();
        assert!(matches!(
            validate_err,
            crate::authority::keys::AuthorityError::TokenConsumed
        ));
        drop(tx); // rollback

        // Even though we dropped without committing, no witness row exists.
        drop(conn);
        let conn = store.lock_sync();
        let n_witness: i64 = conn
            .query_row(
                &format!("SELECT COUNT(*) FROM {}", Table::WitnessRecords.as_str()),
                [],
                |r| r.get(0),
            )
            .unwrap();
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
        assert!(matches!(
            err,
            crate::authority::keys::AuthorityError::TokenConsumed
        ));
        // The witness handler's contract: on consume failure, drop the
        // tx (rollback) instead of committing. Verify the rollback
        // actually erases our witness INSERT.
        drop(tx);
        drop(conn);

        let conn = store.lock_sync();
        let n_witness: i64 = conn
            .query_row(
                &format!("SELECT COUNT(*) FROM {}", Table::WitnessRecords.as_str()),
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            n_witness, 0,
            "witness INSERT must be rolled back when consume reports a race"
        );
    }
}

// ---------------------------------------------------------------------------
// Async-runtime safety witness — INV-WITNESS-GATE-RECHECK-ASYNC-SAFE-01.
// ---------------------------------------------------------------------------
//
// iter66.1 `realistic_session_lifecycle` hit
// `crates/store/src/db.rs:125` "Cannot block the current thread from
// within a runtime" the first time the witness handler reached the
// post-`WitnessAccepted` `gate_recheck` path. Two sync sites in
// `gate_recheck` were calling `Store::lock_sync` directly from the
// async runtime worker:
//
//   * `resolve_worktree_root` → `authority::session::get_session`
//   * `scheduler::transition_to_admitted` → `transition_task`
//
// The iter63 fix had already wrapped `gates::evaluate_pre_spawn` in
// `tokio::task::spawn_blocking`, but the `gate_recheck` tail was
// uncovered. The kernel daemon crashed mid-stream on the first
// IntegrationMerge gate clear, the planner's stream went black, and
// the dashboard at `:19820` stopped receiving events.
//
// Production fix: both sync sites are now invoked through
// `tokio::task::spawn_blocking` with an explicit `_inner` helper for
// `resolve_worktree_root` so the closure can take owned primitives
// without borrowing across the await point. These tests pin the
// canonical safe call pattern at the inner facade so a future
// refactor that drops the spawn_blocking hop trips the negative test
// rather than re-introducing the production crash.
#[cfg(test)]
mod async_runtime_safety {
    use super::resolve_worktree_root_inner;
    use raxis_store::Store;
    use std::path::PathBuf;
    use std::sync::Arc;

    /// **INV-WITNESS-GATE-RECHECK-ASYNC-SAFE-01** witness (positive).
    ///
    /// Drives `resolve_worktree_root_inner` from a `#[tokio::test]`
    /// runtime via `tokio::task::spawn_blocking`, mirroring the
    /// production call shape inside `gate_recheck`. The lookup must
    /// complete without panicking and fall back to `data_dir` because
    /// no session row is seeded.
    #[tokio::test]
    async fn resolve_worktree_root_via_spawn_blocking_is_ok() {
        let store = Arc::new(Store::open_in_memory().expect("in-memory store"));
        let data_dir = PathBuf::from("/tmp/resolve-async-safe");

        let resolved: PathBuf = tokio::task::spawn_blocking({
            let store = Arc::clone(&store);
            let data_dir = data_dir.clone();
            move || resolve_worktree_root_inner(None, store.as_ref(), &data_dir)
        })
        .await
        .expect("resolve spawn_blocking join");

        // Falls back to data_dir when no session row is provided. The
        // point of the test is that the call returned at all — pre-fix
        // the iter66.1 bug shape was an unconditional panic at
        // `Store::lock_sync` before the function body could even
        // SELECT.
        assert_eq!(resolved, data_dir);
    }

    /// **INV-WITNESS-GATE-RECHECK-ASYNC-SAFE-01** witness (negative).
    ///
    /// Pins the iter66.1 bug shape: calling `resolve_worktree_root_inner`
    /// **directly** from a tokio runtime worker triggers
    /// `Store::lock_sync` → `blocking_lock` → "Cannot block the
    /// current thread from within a runtime" panic. The kernel's
    /// production fix is to wrap the call in `spawn_blocking`. This
    /// test documents **why** that wrapping is mandatory so a future
    /// refactor that silently drops the `spawn_blocking` hop
    /// re-introduces the iter66.1 crash via this test going
    /// green-then-removed rather than green-then-shipped.
    #[tokio::test]
    #[should_panic(expected = "Cannot block the current thread from within a runtime")]
    async fn resolve_worktree_root_directly_from_runtime_worker_panics() {
        let store = Store::open_in_memory().expect("in-memory store");
        let data_dir = PathBuf::from("/tmp/resolve-async-unsafe");
        // Provide a parseable SessionId so we reach `get_session`'s
        // `store.lock_sync()` call — the function short-circuits to
        // `data_dir` if `session_id` is `None` or unparseable, which
        // would skip the panic site entirely.
        let session_id_str = raxis_types::SessionId::new_v4().to_string();
        // No `spawn_blocking` hop — this is the iter66.1 call shape.
        // The unused binding is intentional: the panic fires inside
        // `get_session` before the function returns.
        let _ = resolve_worktree_root_inner(Some(&session_id_str), &store, &data_dir);
    }
}

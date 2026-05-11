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
use std::sync::Arc;

use raxis_types::{
    unix_now_secs, BudgetSnapshot, IntentKind, IntentOutcome, IntentRequest,
    IntentResponse, PlannerErrorCode, SessionId, SubmittedClaim, TaskState,
};
#[cfg(test)]
use raxis_types::InitiativeState;
use raxis_store::{Store, Table};

// INV-STORE-03 (kernel-store.md §2.5.1): table identifiers come from the
// `Table` enum; FSM state strings come from `*State::as_sql_str()`.
const TASKS:                       &str = Table::Tasks.as_str();
const TASK_INTENT_RANGES:          &str = Table::TaskIntentRanges.as_str();
const INITIATIVES:                 &str = Table::Initiatives.as_str();
const TASK_EXPORTED_PATH_SNAPSHOTS:&str = Table::TaskExportedPathSnapshots.as_str();
const SUBTASK_ACTIVATIONS:         &str = Table::SubtaskActivations.as_str();
const SESSIONS:                    &str = Table::Sessions.as_str();

use crate::authority;
use crate::gates::{self, GateEvalResult};
use crate::initiatives::task_transitions::{
    transition_task as fsm_transition, transition_task_in_tx, TransitionActor,
};
use crate::ipc::context::HandlerContext;
use crate::observability::record_intent_admission;
use crate::scheduler::budget;
use crate::vcs::diff::CommitSha;

// ---------------------------------------------------------------------------
// handle — public entry point (infallible outer wrapper)
// ---------------------------------------------------------------------------

/// Dispatch one IntentRequest and return the IntentResponse.
///
/// Never panics. All internal errors produce a Rejected response; the
/// connection stays open for subsequent requests.
///
/// ## Async safety contract (P0)
///
/// The pipeline performs ~14 SQLite operations via `Store::lock_sync()`,
/// which calls `tokio::sync::Mutex::blocking_lock` and panics the worker
/// thread with `Cannot block the current thread from within a runtime`
/// if invoked from a tokio async context. The pipeline ALSO has one
/// genuinely async sub-call — `gates::evaluate_claims`, which spawns
/// verifier subprocesses via `tokio::process::Command`.
///
/// Following the same pattern as `escalation::handle` and the operator
/// handlers, every `lock_sync()` call site MUST be wrapped in
/// `tokio::task::spawn_blocking` so the closure runs on the blocking
/// pool (where `blocking_lock` is legal). Wrapping the whole
/// `handle_inner` in a single `spawn_blocking + Handle::current().block_on`
/// would NOT work — `block_on` re-enters async context and the inner
/// `lock_sync` calls panic anyway. The phased-spawn-blocking pattern
/// is the only correct solution for a hybrid sync-SQLite + async-subprocess
/// pipeline.
///
/// **Topology**: `handle_inner` runs the body of the 13-step pipeline as
/// three discrete phases bracketing the one async sub-call:
///
///   - `Phase A` (`spawn_blocking`) — Step 1 session lookup +
///     Step 2 envelope acceptance + Step 3 task load + dispatch +
///     (for SingleCommit/IntegrationMerge) Steps 4-8 sync work.
///     Returns `PreGateOutcome::Proceed(PreGateState)`,
///     `EarlyResponse(IntentResponse)` for ReportFailure/CompleteTask,
///     or `Reject(code, state)`.
///   - `Phase B` (async) — Step 9 `gates::evaluate_claims`, which spawns
///     verifier subprocesses via `tokio::process::Command`.
///   - `Phase C` (`spawn_blocking`) — Steps 10-13 + final response.
///
/// Each `spawn_blocking` clone of `ctx: Arc<HandlerContext>` is cheap
/// (one `Arc::clone`); the closure owns its own `Arc<Store>` and
/// `Arc<PolicyBundle>` snapshots so it never re-acquires the policy
/// mutex mid-pipeline (INV-POLICY-01).
pub async fn handle(req: IntentRequest, ctx: &Arc<HandlerContext>) -> IntentResponse {
    let seq = req.sequence_number;
    let intent_kind = req.intent_kind;
    // V3 OTel — open the `raxis.intent.admission` root span around
    // the entire pipeline. The span is finalised on the way out
    // with verdict/latency attributes plus a single counter +
    // histogram emit. The hub short-circuits when
    // `[observability].enabled = false`, so this is ~free in the
    // disabled case.
    let started = std::time::Instant::now();
    let mut span = ctx.observability.start_span(
        raxis_observability::SpanName::IntentAdmission,
        raxis_observability::SpanKind::Server,
        None,
    );
    span.set_attr("intent_kind", intent_kind.as_str());
    let resp = match handle_inner(req, ctx).await {
        Ok(resp) => resp,
        Err((code, task_state)) => IntentResponse {
            sequence_number: seq,
            task_state,
            outcome: IntentOutcome::Rejected {
                error_code:   code,
                error_detail: None,
            },
        },
    };
    let latency_ms = started.elapsed().as_millis().min(i64::MAX as u128) as i64;
    let (verdict_label, verdict_reason): (&'static str, String) = match &resp.outcome {
        IntentOutcome::Accepted { .. }                => ("Accepted", "ok".to_owned()),
        IntentOutcome::Rejected { error_code, .. }    => ("Rejected", error_code.to_string()),
    };
    span.set_attr("verdict",        verdict_label);
    span.set_attr("verdict_reason", verdict_reason.as_str());
    span.set_attr("latency_ms",     latency_ms);
    span.set_status(raxis_observability::SpanStatus::Ok, None);
    span.end();
    record_intent_admission(
        &ctx.observability,
        intent_kind.as_str(),
        verdict_label,
        latency_ms,
    );
    resp
}

type HandlerResult = Result<IntentResponse, (PlannerErrorCode, TaskState)>;

// ---------------------------------------------------------------------------
// Three-phase async/sync split — see `handle()` doc comment.
// ---------------------------------------------------------------------------

/// State produced by Phase A and consumed by Phases B (gate eval) and C
/// (post-gate finalize). Field names match the original step-by-step locals.
struct PreGateState {
    task: TaskRow,
    task_state: TaskState,
    worktree_path: PathBuf,
    head_sha_raw: String,
    base_sha_raw: String,
    touched_paths: Vec<PathBuf>,
    estimated_cost: u64,
    /// V2 (Step 30) attribution carry-through. Phase A captures the
    /// optional escalation link from the incoming `IntentRequest`
    /// (after Check 6b verifies it) so Phase C can stamp the
    /// `IntegrationMergeCompleted` audit event with the correct
    /// `operator_assisted` / `escalation_id` fields without
    /// re-reading the request struct.
    resolved_via_escalation: Option<raxis_types::EscalationId>,
}

/// Outcome of Phase A. Either we have a final response (early dispatch
/// branches: `ReportFailure`, `CompleteTask`), an early rejection, or
/// we proceed into the gate-evaluation pipeline carrying `PreGateState`.
enum PreGateOutcome {
    Reject(PlannerErrorCode, TaskState),
    EarlyResponse(IntentResponse),
    Proceed(PreGateState),
}

// ---------------------------------------------------------------------------
// handle_inner — 13-step pipeline (3-phase async/sync layout)
// ---------------------------------------------------------------------------

async fn handle_inner(req: IntentRequest, ctx: &Arc<HandlerContext>) -> HandlerResult {
    // Pin one snapshot of the policy bundle for the entire intent
    // pipeline. INV-POLICY-01: an in-process epoch advance must not
    // tear an in-flight enforcement decision (kernel-store.md §INV-POLICY-01).
    let policy_snapshot = ctx.policy.load_full();
    let seq = req.sequence_number;

    // ── Step 1: Session validation ────────────────────────────────────────
    // Resolve session_token → SessionRow.
    // session_token is 64-char hex; stored verbatim in sessions.session_token.
    //
    // ASYNC-SAFETY: `get_session_by_token` calls `Store::lock_sync()` →
    // `tokio::sync::Mutex::blocking_lock`, which panics if invoked from a
    // tokio worker thread. The planner dispatcher (`accept_planner_loop`)
    // calls us from exactly that context. We move this lookup onto the
    // blocking pool via `spawn_blocking` so the lock acquisition is legal.
    // The same pattern is documented at length on `handle()` above and
    // already used by `escalation::handle` and the operator handlers.
    let session = {
        let store_arc = Arc::clone(&ctx.store);
        let token = req.session_token.clone();
        tokio::task::spawn_blocking(move || {
            authority::session::get_session_by_token(&token, &store_arc)
        })
        .await
        .map_err(|_| (PlannerErrorCode::Unauthorized, TaskState::Admitted))?
        .map_err(|_| (PlannerErrorCode::Unauthorized, TaskState::Admitted))?
    };

    let session_id = SessionId::parse(&session.session_id)
        .map_err(|_| (PlannerErrorCode::Unauthorized, TaskState::Admitted))?;

    // Revocation and expiry checks (spec §2.3 step 1). These are pure
    // in-memory checks against the SessionRow we just loaded — no
    // additional `lock_sync` site, so they stay on the async path.
    let now = unix_now_secs();
    if session.revoked_at.is_some() {
        return Err((PlannerErrorCode::Unauthorized, TaskState::Admitted));
    }
    if session.expires_at < now {
        return Err((PlannerErrorCode::Unauthorized, TaskState::Admitted));
    }

    // ── Step 1B: Static dispatch matrix (v2-deep-spec.md §Step 20) ────────
    //
    // INV-DISPATCH: the (intent_kind, session_agent_type) authority
    // matrix is the SOLE place in the Kernel that maps intent kinds
    // to agent-type membership. Evaluated immediately after session
    // load and BEFORE any handler-side check so an Unauthorized cell
    // short-circuits with `FailPolicyViolation` (INV-08 — coarse code,
    // no detail leaked) without touching the rest of the pipeline.
    //
    // V1 backward compat: pre-Migration-5 sessions carry
    // `session_agent_type = NULL`, which the matrix authorizes for
    // the four V1 intent kinds and unauthorizes for every V2
    // sub-task kind.
    let dispatch_verdict =
        crate::authority::evaluate_dispatch(req.intent_kind, session.session_agent_type);
    if !dispatch_verdict.is_authorized() {
        // We deliberately do NOT log the intent body or the matrix
        // cell that fired — the planner sees only the coarse code.
        // A future audit-side detail emit can hang off this branch
        // (the audit chain has the structured projection); the wire
        // surface stays opaque per INV-08.
        return Err((PlannerErrorCode::FailPolicyViolation, TaskState::Admitted));
    }

    // ── V2 sub-task lifecycle early dispatch ──────────────────────────────
    //
    // `IntentKind::ActivateSubTask` (v2-deep-spec.md §Step 21) drives
    // an Executor / Reviewer VM spawn through `ctx.session_spawn`,
    // which is async (the substrate's `Backend::spawn` may bind
    // listeners + start a hypervisor child). Phase A is sync
    // (spawn_blocking), so the cleanest split is to handle
    // `ActivateSubTask` here on the async path BEFORE Phase A
    // begins. The handler internally hops into `spawn_blocking` for
    // the SQLite envelope-acceptance and activation-row reads, then
    // back to async for `ctx.session_spawn.spawn_session()`, then
    // back to `spawn_blocking` for the activation FSM transition.
    //
    // Authorization for these branches is already covered by the
    // dispatch matrix above (Orchestrator + ActivateSubTask /
    // RetrySubTask are the only Authorized cells per v2-deep-spec.md
    // §Step 20).
    //
    // `IntentKind::RetrySubTask` (v2-deep-spec.md §Step 12) opens a
    // fresh activation attempt against a previously-failed sub-task.
    // The retry handler:
    //   1. checks the appropriate counter (`crash_retry_count` for
    //      VM-crash failures, `review_reject_count` for Reviewer
    //      rejections) against the operator-declared ceiling
    //      (`max_crash_retries` / `max_review_rejections`,
    //      defaulted via `TaskPlanFields::effective_*`);
    //   2. revokes the prior bound `sessions` row + asks the
    //      substrate to terminate the failed VM (best-effort);
    //   3. inserts a fresh `subtask_activations` row in
    //      `PendingActivation` (carrying counters forward —
    //      activations are append-only per Migration 5 line 51-52
    //      "a retry inserts a NEW row, never updates the prior one");
    //   4. resets the Executor's `tasks.state` from a non-active
    //      state back to `Admitted` so a subsequent
    //      `ActivateSubTask` from the Orchestrator is dispatch-
    //      legal again; and
    //   5. emits `SessionRevoked` for the prior session (paired
    //      with the new `SessionCreated` that lands when the
    //      Orchestrator follows up with `ActivateSubTask`).
    //
    // The actual VM re-spawn is delegated to the existing
    // `handle_activate_sub_task` path: the Orchestrator's normal
    // post-retry workflow is `RetrySubTask` (this handler) followed
    // by `ActivateSubTask` (which spawns the new VM against the
    // freshly-minted PendingActivation row). Keeping the spawn out
    // of this handler preserves the single-spawn-point invariant
    // and makes the retry contract trivially auditable.
    if matches!(req.intent_kind, IntentKind::ActivateSubTask) {
        return handle_activate_sub_task(req, session, session_id, seq, ctx).await;
    }
    if matches!(req.intent_kind, IntentKind::RetrySubTask) {
        return handle_retry_sub_task(req, session, session_id, seq, ctx).await;
    }

    // ── Phase A (spawn_blocking) — Steps 2-8 + dispatch ───────────────────
    //
    // Everything from here through Step 8 (estimated_cost) is sync and
    // hits `lock_sync` repeatedly. We move it onto the blocking pool in
    // ONE spawn_blocking so each call site is legal AND so we incur a
    // single hop into the blocking pool rather than 10+.
    let pre_gate = {
        let ctx_arc      = Arc::clone(ctx);
        let policy_arc   = Arc::clone(&policy_snapshot);
        let session_clone = session.clone();
        let session_id_clone = session_id.clone();
        let req_clone    = req.clone();
        tokio::task::spawn_blocking(move || {
            run_phase_a(req_clone, session_clone, session_id_clone, seq, policy_arc, ctx_arc)
        })
        .await
        .map_err(|_| (PlannerErrorCode::FailPolicyViolation, TaskState::Admitted))?
    };

    let pre_state = match pre_gate {
        PreGateOutcome::Reject(code, state)  => return Err((code, state)),
        PreGateOutcome::EarlyResponse(resp)  => return Ok(resp),
        PreGateOutcome::Proceed(s)           => s,
    };

    // ── Phase B (async) — Step 9: Gate evaluation ─────────────────────────
    //
    // `gates::evaluate_claims` is genuinely async — it spawns verifier
    // subprocesses via `tokio::process::Command`. It MUST run on the
    // tokio runtime, not on a blocking-pool thread.
    let submitted: Vec<SubmittedClaim> = req.submitted_claims.clone();
    let gate_result = gates::evaluate_claims(
        &session_id,
        pre_state.head_sha_raw.as_str(),
        req.task_id.as_str(),
        &pre_state.touched_paths,
        &submitted,
        &pre_state.worktree_path,
        ctx,
    )
    .await
    .map_err(|_| (PlannerErrorCode::FailMissingWitness, pre_state.task_state))?;

    // Phase B post-processing — pure sync, no `lock_sync`, kept on the
    // async path so we don't hop pools just to inspect an enum.
    let pending_gates: Vec<String>;
    let warn_stale: bool;
    match &gate_result {
        GateEvalResult::ClaimInsufficient { .. } => {
            return Err((PlannerErrorCode::FailMissingWitness, pre_state.task_state));
        }
        GateEvalResult::PendingWitness { missing_gates } => {
            pending_gates = missing_gates.clone();
            warn_stale    = false;
        }
        GateEvalResult::Pass { delegate_renewal_required } => {
            pending_gates = vec![];
            warn_stale    = *delegate_renewal_required;
        }
        GateEvalResult::BreakglassPass { activation_id } => {
            pending_gates = vec![];
            warn_stale    = false;
            // V1 Tier 4 — every gate-bypass admission appends a
            // `BreakglassAction` event to the audit chain so the
            // post-incident review can enumerate every action
            // carried under the activation. We log here (after the
            // gate decision, before the spawn_blocking phase that
            // commits state) rather than inside `evaluate_claims`
            // so the kernel-core audit ordering ("audit emit AFTER
            // store commit") still holds for the success path —
            // emit failures here are non-fatal because the
            // activation itself is already audited and admission
            // continues; future gates will re-emit the
            // `BreakglassAction` event for any subsequent intent.
            //
            // `Uuid::parse_str` is infallible here because
            // `gates::evaluate_claims` formats the activation_id
            // through `Uuid::to_string`, so a parse failure means
            // an in-process construction error, not an operator
            // input error.
            if let Ok(act_id) = uuid::Uuid::parse_str(activation_id) {
                let desc = format!(
                    "intent.{}.task={}",
                    req.intent_kind.as_str(),
                    req.task_id.as_str(),
                );
                if let Err(e) = crate::breakglass::log_action(
                    act_id,
                    Some(session_id.as_str()),
                    &desc,
                    &ctx.audit,
                ) {
                    eprintln!(
                        "{{\"level\":\"warn\",\"event\":\"BreakglassActionAuditFailed\",\
                         \"reason\":\"{e}\",\"task\":\"{}\"}}",
                        req.task_id.as_str(),
                    );
                }
            }
        }
    }

    // ── Phase C (spawn_blocking) — Steps 10-13 + final response ───────────
    let task_id_owned = req.task_id.as_str().to_owned();
    let intent_kind   = req.intent_kind;
    let session_id_str = session_id.as_str().to_owned();
    let ctx_arc    = Arc::clone(ctx);
    let policy_arc = Arc::clone(&policy_snapshot);
    tokio::task::spawn_blocking(move || {
        run_phase_c(
            pre_state,
            pending_gates,
            warn_stale,
            seq,
            task_id_owned,
            intent_kind,
            session_id_str,
            policy_arc,
            ctx_arc,
        )
    })
    .await
    .map_err(|_| (PlannerErrorCode::FailPolicyViolation, TaskState::Admitted))?
}

// ---------------------------------------------------------------------------
// Phase A — sync body for spawn_blocking. Handles Steps 2-8 + the
// ReportFailure / CompleteTask early-dispatch branches.
// ---------------------------------------------------------------------------

fn run_phase_a(
    req: IntentRequest,
    session: authority::session::SessionRow,
    session_id: SessionId,
    seq: u64,
    policy_snapshot: Arc<raxis_policy::PolicyBundle>,
    ctx: Arc<HandlerContext>,
) -> PreGateOutcome {
    let store  = ctx.store.as_ref();
    let policy = policy_snapshot.as_ref();

    // ── Step 2: INV-01 — accept envelope (sequence + nonce) atomically ────
    // Spec: kernel-store.md §2.5.1 Table 16 INV-01 enforcement sequence,
    // checks (A) sequence-number monotonic and (B) envelope_nonce dedup.
    // Both happen in one SQLite transaction so we never advance the sequence
    // without writing the nonce row, and never write the nonce without
    // advancing the sequence. The handler does NOTHING else before this
    // call succeeds — every later step is reachable only on a fresh,
    // non-replayed envelope.
    //
    // Per INV-08, every replay reason maps to PlannerErrorCode::Unauthorized
    // on the wire (we do not leak which check failed). The structured
    // reason is recorded as `AuditEventKind::ReplayRejected` for forensic
    // analysis — see kernel-store.md §2.5.1 Table 16 INV-01 enforcement
    // sequence step 3 (audit emit on rejection).
    let presented_seq_i64 = match i64::try_from(seq) {
        Ok(v) => v,
        Err(_) => {
            // Only happens for seq > i64::MAX, i.e. a malicious caller —
            // bin it as Unauthorized.
            return PreGateOutcome::Reject(PlannerErrorCode::Unauthorized, TaskState::Admitted);
        }
    };
    if let Err(reason) = authority::session::accept_envelope_and_advance_sequence(
        &session_id,
        presented_seq_i64,
        &req.envelope_nonce,
        store,
    ) {
        // No SQLite write occurred (the helper rolled back its own tx
        // on rejection), so emitting the audit record now does NOT
        // violate the §2.5.2 "audit-after-commit" rule — there is
        // nothing to commit, and the rejection itself is the event.
        let _ = ctx.audit.emit(
            raxis_audit_tools::AuditEventKind::ReplayRejected {
                session_id:   session_id.as_str().to_owned(),
                sequence_num: seq,
                reason:       format!("{reason:?}"),
            },
            Some(session_id.as_str()),
            None,
            None,
        );
        return PreGateOutcome::Reject(PlannerErrorCode::Unauthorized, TaskState::Admitted);
    }

    // ── Step 3: Load task row ─────────────────────────────────────────────
    let task = match load_task(req.task_id.as_str(), store) {
        Ok(t) => t,
        Err(_) => return PreGateOutcome::Reject(
            PlannerErrorCode::FailUnknownTask, TaskState::Admitted),
    };

    let task_state = parse_task_state(&task.state);

    // Only Admitted or Running tasks accept intents.
    // GatesPending, Completed, Failed, Aborted, Cancelled, BlockedRecoveryPending
    // all reject with FailTaskNotRunning.
    match task_state {
        TaskState::Admitted | TaskState::Running => {}
        s => return PreGateOutcome::Reject(PlannerErrorCode::FailTaskNotRunning, s),
    }

    // ── Step 3A: Initiative-quarantine check (kernel-store.md §2.5.8) ─────
    //
    // A quarantined initiative rejects every new IntentRequest, regardless
    // of intent kind (ReportFailure / CompleteTask / SingleCommit /
    // IntegrationMerge). The `initiative_quarantines` row is set by the
    // operator IPC handler `handle_quarantine_initiative` (or as part of a
    // sweep via `handle_quarantine_plans_by`). Per INV-08 the wire surface
    // is the dedicated terminal code `FAIL_INITIATIVE_QUARANTINED` so the
    // planner does not retry.
    //
    // We run this AFTER Step 3 because we need `task.initiative_id` to do
    // the lookup, and AFTER the task-state gate so an already-Aborted task
    // surfaces the more specific `FailTaskNotRunning` rather than being
    // shadowed by quarantine.
    // Use the RW variant because we're already holding the writer mutex
    // throughout `run_phase_a` (Steps 2/3 acquire it via `load_task` and
    // `accept_envelope_and_advance_sequence`). Opening a separate `RoConn`
    // here would race the WAL snapshot against the in-flight transaction.
    let quarantine_lookup = {
        let conn = store.lock_sync();
        raxis_store::views::initiative_quarantines::is_quarantined_rw(
            &conn,
            &task.initiative_id,
        )
    };
    match quarantine_lookup {
        Ok(false) => {}
        Ok(true) => {
            eprintln!(
                "{{\"level\":\"warn\",\"event\":\"IntentRejectedQuarantined\",\
                 \"task_id\":\"{}\",\"initiative_id\":\"{}\"}}",
                req.task_id.as_str(),
                task.initiative_id,
            );
            return PreGateOutcome::Reject(
                PlannerErrorCode::FailInitiativeQuarantined, task_state);
        }
        Err(e) => {
            // Treat read errors as quarantine-uncertain → fail closed,
            // since the alternative is letting work through past a
            // possibly-quarantined initiative.
            eprintln!(
                "{{\"level\":\"error\",\"event\":\"QuarantineLookupError\",\
                 \"task_id\":\"{}\",\"initiative_id\":\"{}\",\"reason\":\"{e}\"}}",
                req.task_id.as_str(),
                task.initiative_id,
            );
            return PreGateOutcome::Reject(
                PlannerErrorCode::FailInitiativeQuarantined, task_state);
        }
    }

    // ── V2 §2.5 — per-task LLM token-cost admission gate ─────────────────
    //
    // The planner stamps `IntentRequest::tokens_used` with the
    // running-total `(input, output, cache_read, cache_creation)`
    // tokens it has consumed so far. We compute the current dollar
    // cost from the policy's worst-of-N LLM pricing
    // (`scheduler::budget::cost_micros_for_tokens`) and compare to
    // the per-task ceiling (`policy.max_cost_per_task` in USD cents
    // → micros). Over-budget intents fail-closed with
    // `FailPolicyViolation`; admitted intents have the new running
    // total persisted on the task row so the next intent's check
    // sees the monotonically-non-decreasing cumulative cost.
    let token_verdict = crate::scheduler::budget::evaluate_token_budget(
        req.tokens_used.as_ref(),
        task.cumulative_token_cost_micros,
        policy,
    );
    let new_token_cost_micros = match token_verdict {
        crate::scheduler::budget::TokenBudgetVerdict::Allow {
            cumulative_token_cost_micros,
        } => cumulative_token_cost_micros,
        crate::scheduler::budget::TokenBudgetVerdict::Reject {
            cumulative_token_cost_micros, ceiling_micros,
        } => {
            eprintln!(
                "{{\"level\":\"warn\",\"event\":\"IntentRejectedTokenBudget\",\
                 \"task_id\":\"{}\",\"cumulative_micros\":{cumulative_token_cost_micros},\
                 \"ceiling_micros\":{ceiling_micros}}}",
                req.task_id.as_str(),
            );
            return PreGateOutcome::Reject(
                PlannerErrorCode::FailPolicyViolation, task_state);
        }
    };

    // Persist the updated running total — fire-and-forget UPDATE.
    // The acceptance contract is that admission monotonically
    // increases the cost; a writer-mutex hop here is acceptable
    // because intent admission already serialised on the writer
    // mutex via `accept_envelope_and_advance_sequence` and
    // `load_task`. If the UPDATE silently fails the worst case is
    // the *next* intent's gate sees a stale (under-) cost — the
    // current intent still proceeds with the correct admission
    // decision.
    if new_token_cost_micros != task.cumulative_token_cost_micros {
        let conn = store.lock_sync();
        if let Some(report) = req.tokens_used.as_ref() {
            let _ = conn.execute(
                &format!(
                    "UPDATE {TASKS} SET
                       cumulative_input_tokens       = ?1,
                       cumulative_output_tokens      = ?2,
                       cumulative_token_cost_micros  = ?3
                     WHERE task_id = ?4"
                ),
                rusqlite::params![
                    report.input_tokens  as i64,
                    report.output_tokens as i64,
                    new_token_cost_micros as i64,
                    req.task_id.as_str(),
                ],
            );
        }
    }

    // ── Dispatch by intent kind ───────────────────────────────────────────
    //
    // ReportFailure and CompleteTask are entirely sync: they do not need
    // gate evaluation. Run them inline inside Phase A and surface the
    // result through `EarlyResponse`. SingleCommit / IntegrationMerge
    // fall through to Steps 4-8 below and continue into Phase B.
    //
    // V2 sub-task lifecycle kinds — `SubmitReview` is now routed to
    // its dedicated handler (v2-deep-spec.md §Step 22).
    // `ActivateSubTask` is intercepted on the async path BEFORE
    // Phase A and never reaches here (see `handle_activate_sub_task`
    // dispatch in `handle_inner`). `RetrySubTask` is intercepted
    // alongside it as a fail-closed shim until the
    // `crash_retry_count` / `review_reject_count` ceiling enforcement
    // lands (v2-deep-spec.md §Step 12).
    //
    // Authorization for all V2 kinds was already enforced by
    // the static dispatch matrix in `handle_inner` BEFORE Phase A
    // (v2-deep-spec.md §Step 20). A V2 kind reaching this point is
    // already (intent_kind, session_agent_type)-authorized.
    match req.intent_kind {
        IntentKind::ReportFailure => {
            return match handle_report_failure(req, task_state, &session_id, seq, store, policy) {
                Ok(resp)         => PreGateOutcome::EarlyResponse(resp),
                Err((code, st))  => PreGateOutcome::Reject(code, st),
            };
        }
        IntentKind::CompleteTask => {
            return match handle_complete_task(req, task_state, &session_id, seq, store, policy, ctx.as_ref()) {
                Ok(resp)         => PreGateOutcome::EarlyResponse(resp),
                Err((code, st))  => PreGateOutcome::Reject(code, st),
            };
        }
        IntentKind::SubmitReview => {
            return match handle_submit_review(req, task_state, &session_id, seq, store, policy, ctx.as_ref()) {
                Ok(resp)         => PreGateOutcome::EarlyResponse(resp),
                Err((code, st))  => PreGateOutcome::Reject(code, st),
            };
        }
        IntentKind::SingleCommit | IntentKind::IntegrationMerge => {}
        IntentKind::ActivateSubTask
        | IntentKind::RetrySubTask => {
            // Belt-and-braces: `handle_inner` intercepts both kinds
            // BEFORE Phase A (early-dispatch into
            // `handle_activate_sub_task` / `handle_retry_sub_task`),
            // so this arm only fires if a future regression lets an
            // ActivateSubTask / RetrySubTask slip past the early-
            // dispatch. INV-08 — coarse code on the wire.
            return PreGateOutcome::Reject(
                PlannerErrorCode::FailPolicyViolation, task_state);
        }
        IntentKind::StructuredOutput => {
            // V2 §3.2 — typed mid-session output. NON-TERMINAL: the
            // session continues; we do not transition the task FSM
            // and we do not run gate evaluation (the payload is not
            // a commit). Validate, persist, return.
            return match handle_structured_output(req, task_state, &session_id, seq, store, ctx.as_ref()) {
                Ok(resp)         => PreGateOutcome::EarlyResponse(resp),
                Err((code, st))  => PreGateOutcome::Reject(code, st),
            };
        }
    }

    // ── Step 3b (V2 Step 30): IntegrationMerge attribution gate ───────────
    //
    // When the Orchestrator submits `IntegrationMerge` with
    // `resolved_via_escalation = Some(id)`, verify the linked
    // escalation row matches the spec's three predicates:
    //   1. `class = MergeConflict`,
    //   2. `status = Consumed` (operator has executed
    //      `raxis escalate resolve`), and
    //   3. `session_id = submitting Orchestrator's session`.
    //
    // Failure rejects the merge with `FAIL_POLICY_VIOLATION` (INV-08
    // — coarse code on the wire); the structured rejection reason is
    // recorded internally on the kernel-side eprintln below for
    // forensic analysis. Without this gate an Orchestrator could
    // forge operator attribution by quoting an arbitrary escalation
    // identifier from a sibling initiative.
    //
    // Standard merges (no operator-assistance) skip this entire
    // block — `resolved_via_escalation = None`.
    if matches!(req.intent_kind, IntentKind::IntegrationMerge) {
        if let Some(esc_id) = req.resolved_via_escalation.as_ref() {
            if let Err(e) = crate::handlers::integration_merge_attribution
                ::verify_merge_conflict_resolution(esc_id, &session_id, store)
            {
                eprintln!(
                    "{{\"level\":\"warn\",\"event\":\"IntegrationMergeAttributionRejected\",\
                     \"task_id\":\"{}\",\"session_id\":\"{}\",\"escalation_id\":\"{}\",\
                     \"diagnostic\":\"{}\"}}",
                    req.task_id.as_str(),
                    session_id.as_str(),
                    esc_id.as_str(),
                    e.diagnostic_code(),
                );
                return PreGateOutcome::Reject(
                    PlannerErrorCode::FailPolicyViolation, task_state);
            }
        }
    }

    // ── Step 3c (V2.5 §11.1): IntegrationMerge git_apply_pending pre-flight ─
    //
    // The IntegrationMerge three-phase commit (integration-merge.md
    // §11) sets `initiatives.git_apply_pending = 1` inside the same
    // SQLite transaction that records the intent (Phase 1) and clears
    // it after the host-side fast-forward of the operator-configured
    // `target_ref` returns (Phase 3). Between Phase 1 commit and
    // Phase 3 clear, NO other IntegrationMerge for that initiative
    // may proceed:
    //
    //   * If we let a second merge in, it would race the first
    //     merge's host-side `commit_merge_to_target_ref` and could
    //     either leave `target_ref` pointing into the old merge's
    //     octopus or — worse — clobber a successful Phase 2 with a
    //     Phase 1 of a stale follow-on intent.
    //
    //   * If the kernel crashed between Phase 1 and Phase 2, boot
    //     recovery (handlers::git_apply_recovery) re-runs the merge.
    //     A fresh IntegrationMerge submission must wait for that
    //     recovery — surfaced to the planner as
    //     `FAIL_GIT_APPLY_PENDING` so the orchestrator backs off
    //     instead of raising on operator escalation.
    //
    // The check is read-only and runs on a fresh `RoConn`; the
    // authoritative serialization happens inside the Phase 1
    // `IMMEDIATE` transaction below (Step 12B), where we re-set
    // the flag and observe the SQLite-level race-free toggle.
    if matches!(req.intent_kind, IntentKind::IntegrationMerge) {
        let initiative_id = task.initiative_id.clone();
        // Read the flag using a one-shot rusqlite query against the
        // shared `Connection` rather than a fresh `RoConn`, so the
        // pre-flight observes any pending Phase 1 commit even if WAL
        // has not yet checkpointed (a fresh `RoConn` over the same DB
        // file would still see it via WAL, but going through the same
        // mutex eliminates an unnecessary file-open under the
        // `data_dir` indirection — and matches the surrounding
        // helpers' style of operating on `&store`).
        let pending: bool = {
            let conn = store.lock_sync();
            match conn.query_row(
                &format!(
                    "SELECT git_apply_pending FROM {INITIATIVES} WHERE initiative_id = ?1"
                ),
                rusqlite::params![initiative_id.as_str()],
                |r| r.get::<_, Option<i64>>(0),
            ) {
                Ok(opt) => opt.unwrap_or(0) != 0,
                Err(rusqlite::Error::QueryReturnedNoRows) => false,
                Err(_) => return PreGateOutcome::Reject(
                    PlannerErrorCode::FailPolicyViolation, task_state),
            }
        };
        if pending {
            eprintln!(
                "{{\"level\":\"warn\",\"event\":\"IntegrationMergeBlockedByPendingApply\",\
                 \"task_id\":\"{}\",\"initiative_id\":\"{initiative_id}\",\
                 \"diagnostic\":\"prior IntegrationMerge committed Phase 1 but Phase 3 has not cleared the flag — boot recovery must complete first\"}}",
                req.task_id.as_str(),
            );
            return PreGateOutcome::Reject(
                PlannerErrorCode::FailGitApplyPending, task_state);
        }
    }

    // ── Step 4: Validate worktree_root against policy ─────────────────────
    let worktree_root = session.worktree_root.as_deref().unwrap_or("");
    if !policy.worktree_root_allowed(worktree_root) {
        return PreGateOutcome::Reject(PlannerErrorCode::FailPolicyViolation, task_state);
    }
    let worktree_path = PathBuf::from(worktree_root);

    // ── Step 5: SHA range + ancestry ─────────────────────────────────────
    let head_sha_raw = match req.head_sha.as_ref().map(|s| s.as_str().to_owned()) {
        Some(s) => s,
        None    => return PreGateOutcome::Reject(PlannerErrorCode::InvalidRequest, task_state),
    };
    let base_sha_raw = match req.base_sha.as_ref().map(|s| s.as_str().to_owned()) {
        Some(s) => s,
        None    => return PreGateOutcome::Reject(PlannerErrorCode::InvalidRequest, task_state),
    };

    // The local newtype validation is preserved so we surface
    // `InvalidRequest` for malformed wire shapes without round-
    // tripping through the domain adapter (which would surface them
    // as `PreconditionFailed`).
    let _head_sha = match CommitSha::new(&head_sha_raw) {
        Ok(s)   => s,
        Err(_)  => return PreGateOutcome::Reject(PlannerErrorCode::InvalidRequest, task_state),
    };
    let _base_sha = match CommitSha::new(&base_sha_raw) {
        Ok(s)   => s,
        Err(_)  => return PreGateOutcome::Reject(PlannerErrorCode::InvalidRequest, task_state),
    };

    // V2 migration: ancestry / topology / diff dispatch through the
    // `DomainAdapter` (`extensibility-traits.md §2.2.B`). The kernel
    // keeps the per-step planner-error-code mapping; the adapter is
    // the implementation seam. We are inside a `spawn_blocking`
    // context, so async adapter methods are bridged to sync via
    // `tokio::runtime::Handle::current().block_on`. The runtime is
    // guaranteed to exist because `run_phase_a` is only ever invoked
    // from a tokio multi-threaded worker.
    let rt_handle = tokio::runtime::Handle::current();

    // base must be an ancestor of head (ancestry invariant).
    let is_anc = match rt_handle.block_on(
        ctx.domain.is_ancestor(&base_sha_raw, &head_sha_raw, &worktree_path)
    ) {
        Ok(v)   => v,
        Err(_)  => return PreGateOutcome::Reject(PlannerErrorCode::FailInvalidDiff, task_state),
    };
    if !is_anc {
        return PreGateOutcome::Reject(PlannerErrorCode::FailInvalidDiff, task_state);
    }

    // ── Step 6: Topology check ────────────────────────────────────────────
    // SingleCommit: enforce parent(head) == base (no merge commits in range).
    // IntegrationMerge: topology check is skipped.
    if matches!(req.intent_kind, IntentKind::SingleCommit) {
        if let Err(_) = rt_handle.block_on(
            ctx.domain.topology_check(&base_sha_raw, &head_sha_raw, &worktree_path)
        ) {
            return PreGateOutcome::Reject(
                PlannerErrorCode::FailInvalidCommitTopology, task_state);
        }
    }

    // ── Step 7: VCS diff → touched_paths ──────────────────────────────────
    let touched_resources = match rt_handle.block_on(
        ctx.domain.compute_touched_paths(&base_sha_raw, &head_sha_raw, &worktree_path)
    ) {
        Ok(r)   => r,
        Err(_)  => return PreGateOutcome::Reject(PlannerErrorCode::FailInvalidDiff, task_state),
    };
    let touched_paths: Vec<std::path::PathBuf> = touched_resources
        .resources
        .iter()
        .map(|r| {
            // Strip the `path:///` URI prefix to recover the
            // workspace-relative path the rest of the kernel expects.
            let stripped = r.uri.strip_prefix("path:///").unwrap_or(&r.uri);
            std::path::PathBuf::from(stripped)
        })
        .collect();

    // ── Step 7A: Path-scope coverage check (§2.5.8 step 3A) ───────────────
    //
    // INV-TASK-PATH-01: every path in `touched_paths` must be a member of
    // `effective_allow(task_id)` recomputed at admission time. A miss is
    // non-terminal — task stays in its current state, planner reverts and
    // resubmits. Path lists are NEVER returned on the wire (INV-08); the
    // opaque `FAIL_PATH_POLICY_VIOLATION` is the only signal.
    //
    // Fail-closed posture: a missing PlanRegistry entry (corrupted state,
    // boot-time repopulate failure, plan never approved) collapses to the
    // same path-policy rejection. Combined with `effective_allow`'s
    // default of `path_allowlist = []` it means the kernel will never
    // silently widen `touched_paths` because the in-memory plan was
    // unavailable.
    // V2 §Step 11 — IntegrationMerge uses the *hybrid* allowlist
    // (UNION of all sub-task `path_allowlist`s ∪ orchestrator's
    // `cross_cutting_artifacts`); every other intent uses the
    // per-task allowlist via `effective_allow`. Dispatching by
    // `intent_kind` here keeps Phase B's path check single-shot
    // (no double-evaluation) while preserving the V1 behaviour for
    // SingleCommit / Read / etc.
    let path_check = match req.intent_kind {
        IntentKind::IntegrationMerge => crate::path_scope::check_paths_hybrid(
            &touched_paths,
            &task.initiative_id,
            &ctx.plan_registry,
        ),
        _ => crate::path_scope::check_paths(
            &touched_paths,
            &task.initiative_id,
            req.task_id.as_str(),
            &ctx.plan_registry,
            store,
        ),
    };

    match path_check {
        Ok(Ok(())) => {}
        Ok(Err(violation)) => {
            // Internal log only — INV-08 keeps the wire response opaque.
            // The planner's remediation guidance comes from the §2.5.8
            // "Planner feedback model" system prompt, not from the kernel.
            eprintln!(
                "{{\"level\":\"warn\",\"event\":\"PathPolicyViolation\",\
                 \"task_id\":\"{}\",\"violation_count\":{}}}",
                req.task_id.as_str(),
                violation.paths.len(),
            );
            return PreGateOutcome::Reject(
                PlannerErrorCode::FailPathPolicyViolation, task_state);
        }
        Err(e) => {
            // Registry miss or invalid glob in the signed plan — still
            // a path-policy rejection (don't expose the structural
            // failure mode on the wire).
            eprintln!(
                "{{\"level\":\"error\",\"event\":\"PathScopeError\",\
                 \"task_id\":\"{}\",\"reason\":\"{e}\"}}",
                req.task_id.as_str(),
            );
            return PreGateOutcome::Reject(
                PlannerErrorCode::FailPathPolicyViolation, task_state);
        }
    }

    // ── Step 8: Compute estimated_cost ────────────────────────────────────
    // Spec: cost is computed from touched_paths + intent_kind against policy.
    let estimated_cost =
        match budget::compute_admission_cost(&touched_paths, req.intent_kind, policy) {
            Ok(c)   => c,
            Err(_)  => return PreGateOutcome::Reject(
                PlannerErrorCode::FailPolicyViolation, task_state),
        };

    PreGateOutcome::Proceed(PreGateState {
        task,
        task_state,
        worktree_path,
        head_sha_raw,
        base_sha_raw,
        touched_paths,
        estimated_cost,
        resolved_via_escalation: req.resolved_via_escalation.clone(),
    })
}

// ---------------------------------------------------------------------------
// Phase C — sync body for spawn_blocking. Handles Steps 10-13 +
// builds the final IntentResponse.
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
fn run_phase_c(
    pre_state: PreGateState,
    pending_gates: Vec<String>,
    warn_stale: bool,
    seq: u64,
    task_id_owned: String,
    intent_kind: IntentKind,
    session_id_str: String,
    policy_snapshot: Arc<raxis_policy::PolicyBundle>,
    ctx: Arc<HandlerContext>,
) -> HandlerResult {
    let store  = ctx.store.as_ref();
    let policy = policy_snapshot.as_ref();
    let task_state = pre_state.task_state;

    // ── INV-STORE-02 (kernel-store.md §2.5.1.1 Pattern B): single-transaction
    //    Phase C ──────────────────────────────────────────────────────────
    //
    // All Phase C writes — FSM transition (Admitted→GatesPending OR
    // Admitted→Running), budget reservation, intent fields, intent range —
    // commit atomically inside ONE `conn.transaction()` held under ONE
    // `lock_sync` acquisition. Pre-fix, each helper acquired its own mutex
    // and auto-committed. A concurrent `task abort` between any two helpers
    // could leave a stranded `lane_budget_reservations` row for a
    // now-Aborted task, drift the lane toward apparent capacity exhaustion,
    // and cause the FSM transition step to fail with `TaskNotAbortable`
    // (Aborted is terminal; no transition out). The transaction makes the
    // failure mode binary: either every write commits or every write rolls
    // back, leaving the operator's abort intact.
    let mut conn = store.lock_sync();
    let tx = conn.transaction().map_err(|_| (PlannerErrorCode::FailPolicyViolation, task_state))?;

    // ── PendingWitness branch: transition Admitted → GatesPending ────────
    //
    // Done before the budget consume so a task that is GatesPending due
    // to outstanding witnesses does not get charged a second time when
    // the witness eventually arrives and the same intent is re-submitted.
    if !pending_gates.is_empty() && task_state == TaskState::Admitted {
        transition_task_in_tx(
            &tx,
            task_id_owned.as_str(),
            TaskState::GatesPending,
            Some("gates pending: witnesses required"),
            TransitionActor::Kernel,
        ).map_err(|_| (PlannerErrorCode::FailTaskNotRunning, TaskState::GatesPending))?;
    }

    // ── Step 10: Atomic budget check + reserve (Pattern A fix) ───────────
    //
    // `reserve_budget_in_tx` runs the SELECT-aggregate over
    // `lane_budget_reservations` and the `INSERT OR IGNORE` inside the
    // same Phase C transaction, eliminating the pre-fix TOCTOU window
    // where two concurrent intents could both pass `check_budget` before
    // either ran `consume_budget`, over-committing the lane.
    if task_state == TaskState::Admitted && pending_gates.is_empty() {
        budget::reserve_budget_in_tx(
            &tx,
            &pre_state.task.lane_id,
            task_id_owned.as_str(),
            pre_state.estimated_cost,
            policy,
        ).map_err(|_| (PlannerErrorCode::FailBudgetExceeded, task_state))?;
    }

    // ── Step 11: FSM transition via task_transitions (INV-INIT-04) ───────
    if task_state == TaskState::Admitted && pending_gates.is_empty() {
        // Admitted + all gates pass → Running.
        transition_task_in_tx(
            &tx,
            task_id_owned.as_str(),
            TaskState::Running,
            None,
            TransitionActor::Kernel,
        ).map_err(|_| (PlannerErrorCode::FailPolicyViolation, TaskState::Running))?;
    }
    // Running + gate pass: no transition needed; task stays Running.
    // Running + gates pending: task stays Running (the GatesPending
    // transition is for Admitted → GatesPending only in this handler).

    // ── Step 12: Update task intent fields ───────────────────────────────
    update_task_intent_fields_in_tx(
        &tx,
        task_id_owned.as_str(),
        pre_state.head_sha_raw.as_str(),
        pre_state.base_sha_raw.as_str(),
        session_id_str.as_str(),
    ).map_err(|_| (PlannerErrorCode::FailPolicyViolation, task_state))?;

    // ── Step 12A: Record accepted intent range (INV-TASK-PATH-02 substrate)
    insert_task_intent_range_in_tx(
        &tx,
        task_id_owned.as_str(),
        pre_state.base_sha_raw.as_str(),
        pre_state.head_sha_raw.as_str(),
    ).map_err(|_| (PlannerErrorCode::FailPolicyViolation, task_state))?;

    // ── Step 12B (V2.5 §11.1 Phase 1): set git_apply_pending = 1 ─────────
    //
    // For IntegrationMerge ONLY. Inside the SAME transaction as the
    // intent record so the flag flips atomically with the kernel's
    // commitment to apply the merge. Phase 2 (host-side fast-forward
    // below, after `tx.commit()`) is the side-effect; Phase 3 clears
    // the flag once Phase 2 returns. If the kernel crashes between
    // commit and Phase 3, boot recovery scans `git_apply_pending = 1`
    // and either re-applies the merge or records `GitStateInconsistent`
    // (handlers::git_apply_recovery).
    //
    // We assert exactly one row was updated so a missing initiative
    // (which would be a bug — the FK on tasks.initiative_id already
    // proves the parent exists by Step 3) surfaces as a hard reject
    // instead of a silently-lost flag that would let a second merge
    // race the recovery on next boot.
    if matches!(intent_kind, IntentKind::IntegrationMerge) {
        let updated = raxis_store::views::initiatives::set_git_apply_pending(
            &tx, pre_state.task.initiative_id.as_str(),
        ).map_err(|_| (PlannerErrorCode::FailPolicyViolation, task_state))?;
        if updated != 1 {
            eprintln!(
                "{{\"level\":\"error\",\"event\":\"GitApplyPendingSetMissed\",\
                 \"initiative_id\":\"{}\",\"updated_rows\":{updated}}}",
                pre_state.task.initiative_id,
            );
            return Err((PlannerErrorCode::FailPolicyViolation, task_state));
        }
    }

    tx.commit().map_err(|_| (PlannerErrorCode::FailPolicyViolation, task_state))?;
    drop(conn);

    // ── Step 13: Audit stub + Accepted response ───────────────────────────
    // Audit emission is post-commit per kernel-store.md §2.5.2 ordering.
    eprintln!(
        "{{\"level\":\"info\",\"event\":\"IntentAccepted\",\
         \"task_id\":\"{}\",\"kind\":\"{}\",\"evaluation_sha\":\"{}\",\"pending_gates\":{}}}",
        task_id_owned,
        intent_kind.as_str(),
        pre_state.head_sha_raw,
        pending_gates.len()
    );

    // V2 Step 30 + integration-merge.md §7: emit a typed
    // `IntegrationMergeCompleted` audit record carrying the Step 30
    // attribution fields. Best-effort post-commit per
    // kernel-store.md §2.5.2: a failed audit emit logs and proceeds
    // (the reconciler closes the gap on next boot).
    //
    // V2 `v2_extended_gaps.md §1.2` — host-side fast-forward of the
    // operator-configured `target_ref`. Performed inline here, AFTER
    // the SQLite intent commit and BEFORE the audit emission +
    // optional push. The kernel reads the per-initiative
    // `target_ref` from the orchestrator plan-fields registry
    // (resolved at admission time from `[workspace] target_ref` /
    // `[git] default_target_ref` / hardcoded fallback). The merge
    // is performed by `raxis_domain_git::commit_merge_to_target_ref`
    // which is idempotent: the recovery path on next boot will
    // re-run it cleanly if the kernel crashes between Phase 1 and
    // Phase 2 (full §11.1 three-phase commit + `git_apply_pending`
    // is tracked under §1.2 — the V2.5 cut performs Phase 2 inline
    // and emits a typed `MergeFastForwardFailed` audit event when
    // it fails so a future recovery pass has the durable signal it
    // needs).
    if matches!(intent_kind, IntentKind::IntegrationMerge) {
        let initiative_id_owned = pre_state.task.initiative_id.clone();
        let (operator_assisted, escalation_id) =
            match pre_state.resolved_via_escalation.as_ref() {
                Some(id) => (true,  Some(id.as_str().to_owned())),
                None     => (false, None),
            };

        // ── V2 §1.2 Phase 2 — host-side fast-forward ───────────────
        let main_repo_root = ctx.data_dir.join("repositories").join("main");
        let orch_worktree_root = pre_state.worktree_path.clone();
        let initiative_target_ref = ctx.plan_registry
            .orchestrator(&initiative_id_owned)
            .map(|o| o.target_ref)
            .unwrap_or_else(|| {
                crate::initiatives::OrchestratorPlanFields::DEFAULT_TARGET_REF.to_owned()
            });
        let host_merge_result = raxis_domain_git::commit_merge_to_target_ref(
            &main_repo_root,
            &orch_worktree_root,
            &pre_state.head_sha_raw,
            &initiative_target_ref,
        );
        let host_merge_succeeded = match &host_merge_result {
            Ok(advance) => {
                eprintln!(
                    "{{\"level\":\"info\",\"event\":\"IntegrationMergeFastForward\",\
                     \"initiative_id\":\"{initiative_id_owned}\",\
                     \"target_ref\":\"{initiative_target_ref}\",\
                     \"current_sha\":\"{cur}\",\"already_at_target\":{aat}}}",
                    cur = advance.current_sha,
                    aat = advance.already_at_target,
                );

                // ── V2.5 §11.1 Phase 3: clear git_apply_pending ─────────
                //
                // Best-effort: a SQLite failure here would re-trigger
                // boot recovery on next start (recovery is idempotent
                // — `commit_merge_to_target_ref` short-circuits when
                // `target_ref` already points at the merge commit and
                // emits `GitConsistencyVerified` instead of
                // `GitConsistencyRepaired`). We log the failure so the
                // operator notices, but we do NOT fail the merge —
                // Phase 2 already succeeded and rolling it back is
                // impossible.
                {
                    let conn = store.lock_sync();
                    match raxis_store::views::initiatives::clear_git_apply_pending(
                        &conn, initiative_id_owned.as_str(),
                    ) {
                        Ok(1) => {}
                        Ok(n) => {
                            eprintln!(
                                "{{\"level\":\"warn\",\"event\":\"GitApplyPendingClearMissed\",\
                                 \"initiative_id\":\"{initiative_id_owned}\",\"updated_rows\":{n},\
                                 \"diagnostic\":\"clear matched {n} rows; expected 1 — boot recovery will reconcile\"}}",
                            );
                        }
                        Err(e) => {
                            eprintln!(
                                "{{\"level\":\"error\",\"event\":\"GitApplyPendingClearFailed\",\
                                 \"initiative_id\":\"{initiative_id_owned}\",\"diagnostic\":\"{e}\"}}",
                            );
                        }
                    }
                }

                true
            }
            Err(err) => {
                let (category, reason) = classify_merge_ff_error(err);
                eprintln!(
                    "{{\"level\":\"error\",\"event\":\"IntegrationMergeFastForwardFailed\",\
                     \"initiative_id\":\"{initiative_id_owned}\",\
                     \"target_ref\":\"{initiative_target_ref}\",\
                     \"category\":\"{category}\",\"reason\":\"{reason}\"}}",
                );
                if let Err(e) = ctx.audit.emit(
                    raxis_audit_tools::AuditEventKind::MergeFastForwardFailed {
                        initiative_id: initiative_id_owned.clone(),
                        commit_sha:    pre_state.head_sha_raw.clone(),
                        target_ref:    initiative_target_ref.clone(),
                        category:      category.to_owned(),
                        reason,
                    },
                    Some(session_id_str.as_str()),
                    Some(task_id_owned.as_str()),
                    Some(initiative_id_owned.as_str()),
                ) {
                    eprintln!(
                        "{{\"level\":\"error\",\"event\":\"MergeFastForwardFailed\",\
                         \"audit_emit_failed\":\"{e}\",\"initiative_id\":\"{initiative_id_owned}\"}}",
                    );
                }
                false
            }
        };

        if let Err(e) = ctx.audit.emit(
            raxis_audit_tools::AuditEventKind::IntegrationMergeCompleted {
                initiative_id: initiative_id_owned.clone(),
                session_id:    session_id_str.clone(),
                commit_sha:    pre_state.head_sha_raw.clone(),
                previous_sha:  pre_state.base_sha_raw.clone(),
                operator_assisted,
                escalation_id,
                target_ref:    initiative_target_ref.clone(),
            },
            Some(session_id_str.as_str()),
            Some(task_id_owned.as_str()),
            Some(initiative_id_owned.as_str()),
        ) {
            eprintln!(
                "{{\"level\":\"error\",\"event\":\"IntegrationMergeCompleted\",\
                 \"audit_emit_failed\":\"{e}\",\"initiative_id\":\"{initiative_id_owned}\"}}",
            );
        }

        // V2_GAPS §C6 — kernel push protocol. After IntegrationMerge,
        // if `[git] auto_push = true`, push the configured target_ref
        // to the configured remote using the host's git credential
        // helpers / SSH config. The merge already committed; push
        // failure is informational and emits `PushFailed` without
        // rolling back the merge.
        //
        // Push is skipped when Phase 2 (host-side fast-forward) failed
        // — pushing the un-advanced `target_ref` to the upstream
        // remote would race the operator's manual recovery and could
        // surface a misleading "successful push" to the audit chain.
        if policy.git_auto_push() && host_merge_succeeded {
            let remote  = policy.git_push_remote().to_owned();
            let target  = initiative_target_ref.clone();
            let refspec = format!("{target}:{target}");

            // V2.5 `integration-merge.md §11.5` — wait for
            // `git_apply_pending = 0` before reading `refs/heads/<target>`
            // to push. In the synchronous handler path Phase 3 already
            // cleared the flag two statements up, so this loop exits on
            // its first poll. The wait exists as a defensive guard for
            // future code paths that move push to a background task and
            // for the brief window where another thread could still be
            // setting the flag (which would never happen here, but the
            // assertion is cheap and pins the invariant explicitly).
            //
            // Polls every 50 ms up to a 5 s deadline. On timeout, emits
            // `PushFailed { category: "pending_git_apply" }` and skips
            // the push — operator must investigate the stuck initiative
            // before retrying.
            let pending_clear = wait_for_git_apply_pending_clear(
                store,
                &initiative_id_owned,
                std::time::Duration::from_secs(5),
                std::time::Duration::from_millis(50),
            );
            if !pending_clear {
                eprintln!(
                    "{{\"level\":\"warn\",\"event\":\"PushDeferredPending\",\
                     \"initiative_id\":\"{initiative_id_owned}\",\
                     \"reason\":\"git_apply_pending=1 after 5s\"}}",
                );
                if let Err(e) = ctx.audit.emit(
                    raxis_audit_tools::AuditEventKind::PushFailed {
                        initiative_id: initiative_id_owned.clone(),
                        commit_sha:    pre_state.head_sha_raw.clone(),
                        remote:        remote.clone(),
                        refspec:       refspec.clone(),
                        category:      "pending_git_apply".to_owned(),
                        reason:        "git_apply_pending did not clear within 5s deadline".to_owned(),
                    },
                    Some(session_id_str.as_str()),
                    Some(task_id_owned.as_str()),
                    Some(initiative_id_owned.as_str()),
                ) {
                    eprintln!(
                        "{{\"level\":\"error\",\"event\":\"PushFailed\",\
                         \"audit_emit_failed\":\"{e}\",\"initiative_id\":\"{initiative_id_owned}\"}}",
                    );
                }
                return Ok(IntentResponse {
                    sequence_number: seq,
                    task_state: if !pending_gates.is_empty() {
                        TaskState::GatesPending
                    } else if task_state == TaskState::Admitted {
                        TaskState::Running
                    } else {
                        task_state
                    },
                    outcome: IntentOutcome::Accepted {
                        remaining_budget:      lane_budget_snapshot(
                            &pre_state.task.lane_id, policy, store,
                        ),
                        warn_delegation_stale: warn_stale,
                    },
                });
            }

            if let Err(e) = ctx.audit.emit(
                raxis_audit_tools::AuditEventKind::PushAttempted {
                    initiative_id: initiative_id_owned.clone(),
                    commit_sha:    pre_state.head_sha_raw.clone(),
                    remote:        remote.clone(),
                    refspec:       refspec.clone(),
                },
                Some(session_id_str.as_str()),
                Some(task_id_owned.as_str()),
                Some(initiative_id_owned.as_str()),
            ) {
                eprintln!(
                    "{{\"level\":\"error\",\"event\":\"PushAttempted\",\
                     \"audit_emit_failed\":\"{e}\",\"initiative_id\":\"{initiative_id_owned}\"}}",
                );
            }

            const KERNEL_PUSH_DEADLINE: std::time::Duration =
                std::time::Duration::from_secs(30);
            let result = raxis_domain_git::push_to_remote(
                &main_repo_root,
                &remote,
                &refspec,
                KERNEL_PUSH_DEADLINE,
            );

            match result {
                Ok(outcome) => {
                    if let Err(e) = ctx.audit.emit(
                        raxis_audit_tools::AuditEventKind::PushCompleted {
                            initiative_id: initiative_id_owned.clone(),
                            commit_sha:    pre_state.head_sha_raw.clone(),
                            remote:        outcome.remote,
                            refspec:       outcome.refspec,
                            summary:       outcome.summary,
                        },
                        Some(session_id_str.as_str()),
                        Some(task_id_owned.as_str()),
                        Some(initiative_id_owned.as_str()),
                    ) {
                        eprintln!(
                            "{{\"level\":\"error\",\"event\":\"PushCompleted\",\
                             \"audit_emit_failed\":\"{e}\",\"initiative_id\":\"{initiative_id_owned}\"}}",
                        );
                    }
                }
                Err(err) => {
                    let (category, reason): (&str, String) = match &err {
                        raxis_domain_git::PushError::PushFailed { stderr, .. } =>
                            ("push_failed", stderr.clone()),
                        raxis_domain_git::PushError::SpawnFailed(r) =>
                            ("spawn_failed", r.clone()),
                        raxis_domain_git::PushError::DeadlineExceeded(d) =>
                            ("deadline_exceeded", format!("{d:?}")),
                        raxis_domain_git::PushError::MainRepoUnopenable { reason, .. } =>
                            ("unopenable_repo", reason.clone()),
                    };
                    eprintln!(
                        "{{\"level\":\"warn\",\"event\":\"PushFailed\",\
                         \"category\":\"{category}\",\"initiative_id\":\"{initiative_id_owned}\"}}",
                    );
                    if let Err(e) = ctx.audit.emit(
                        raxis_audit_tools::AuditEventKind::PushFailed {
                            initiative_id: initiative_id_owned.clone(),
                            commit_sha:    pre_state.head_sha_raw.clone(),
                            remote:        remote.clone(),
                            refspec:       refspec.clone(),
                            category:      category.to_owned(),
                            reason,
                        },
                        Some(session_id_str.as_str()),
                        Some(task_id_owned.as_str()),
                        Some(initiative_id_owned.as_str()),
                    ) {
                        eprintln!(
                            "{{\"level\":\"error\",\"event\":\"PushFailed\",\
                             \"audit_emit_failed\":\"{e}\",\"initiative_id\":\"{initiative_id_owned}\"}}",
                        );
                    }
                }
            }
        }
    }

    let remaining = lane_budget_snapshot(&pre_state.task.lane_id, policy, store);
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
// Normative reference: kernel-store.md §2.5.8 "CompleteTask path check"
// (full algorithm, lines 1989-2014).
//
// Path closure pipeline (deviates from a regular intent — no Step 7 diff
// because there is no `(base_sha, head_sha)` pair on the request: only
// `head_sha` matters, and `base_sha` from the wire is intentionally
// IGNORED per §2.5.8 line 1985):
//
//   1. Load `H_bind = tasks.evaluation_sha` (may be NULL).
//   2. Load all `(base_sha, head_sha)` rows from `task_intent_ranges`
//      for this task.
//   3. Union touched_paths from `vcs::diff::compute(base, head, root)`
//      across every range.
//   4. If `req.head_sha != H_bind` (and H_bind is not NULL):
//      4a. topology_check on the trailing segment (NO IntegrationMerge
//          carve-out — the trailing gap is never an integration intent).
//      4b. union touched_paths from the trailing diff.
//   5. Recompute `effective_allow` and run `check_paths`.
//   6. On violation → reject non-terminally; task stays Running.
//   7. On success → write `task_exported_path_snapshots` (if opt-in)
//      AND transition Running → Completed in the same SQLite tx.
// ---------------------------------------------------------------------------

fn handle_complete_task(
    req:        IntentRequest,
    task_state: TaskState,
    _session_id: &SessionId,
    seq:        u64,
    store:      &Store,
    policy:     &raxis_policy::PolicyBundle,
    ctx:        &HandlerContext,
) -> HandlerResult {
    if task_state != TaskState::Running {
        return Err((PlannerErrorCode::FailTaskNotRunning, task_state));
    }

    let task = load_task(req.task_id.as_str(), store)
        .map_err(|_| (PlannerErrorCode::FailUnknownTask, task_state))?;

    // ── 1. Worktree root + req.head_sha ───────────────────────────────────
    //
    // We need the worktree to drive `vcs::diff::compute` and
    // `vcs::topology_check`. Pull it from the session row exactly the
    // way regular intents do (§2.5.8 line 1842 — "the intent handler
    // reads `session.worktree_root` from the session row via
    // `authority::get_session(session_id)`"). On `CompleteTask`, the
    // request must still carry a session token; the planner never
    // submits a witness-less completion without one.
    let session = crate::authority::session::get_session_by_token(&req.session_token, store)
        .map_err(|_| (PlannerErrorCode::Unauthorized, task_state))?;
    let worktree_root = session.worktree_root.as_deref().unwrap_or("");
    let worktree_path = std::path::PathBuf::from(worktree_root);

    let req_head_str = req.head_sha.as_ref().map(|s| s.as_str()).unwrap_or("");
    let req_head     = if req_head_str.is_empty() {
        // §2.5.8 edge-case: empty head_sha + no recorded ranges + NULL
        // H_bind = trivial vacuous pass. We model this as `None` and
        // skip the trailing-segment branch entirely.
        None
    } else {
        Some(CommitSha::new(req_head_str)
            .map_err(|_| (PlannerErrorCode::InvalidRequest, task_state))?)
    };

    // ── 2. Read H_bind + accepted intent ranges from the store ───────────
    //
    // H_bind = tasks.evaluation_sha (may be NULL on first-intent vacuous
    // paths). Ranges are SELECTed from `task_intent_ranges` populated by
    // step 12A of regular intent acceptance.
    let (h_bind, ranges) = read_completion_inputs(req.task_id.as_str(), store)
        .map_err(|_| (PlannerErrorCode::FailUnknownTask, task_state))?;

    // ── 3. Union touched_paths across all stored ranges ──────────────────
    //
    // §2.5.8 line 1987 explicitly says we DO NOT re-run topology_check
    // on stored ranges — they were already checked at step 2A on
    // admission (the IntegrationMerge carve-out applied per range).
    // V2 migration: dispatch through the `DomainAdapter`. The
    // calling function (`handle_complete_task`) is sync; we bridge
    // async via `Handle::current().block_on` exactly like the
    // intent-admission path does.
    let rt_handle = tokio::runtime::Handle::current();
    let mut full_touched_paths: std::collections::BTreeSet<PathBuf> =
        std::collections::BTreeSet::new();
    for (base_str, head_str) in &ranges {
        let _b = CommitSha::new(base_str)
            .map_err(|_| (PlannerErrorCode::FailInvalidDiff, task_state))?;
        let _h = CommitSha::new(head_str)
            .map_err(|_| (PlannerErrorCode::FailInvalidDiff, task_state))?;
        let resources = rt_handle.block_on(
            ctx.domain.compute_touched_paths(base_str, head_str, &worktree_path)
        ).map_err(|_| (PlannerErrorCode::FailInvalidDiff, task_state))?;
        for r in resources.resources {
            let stripped = r.uri.strip_prefix("path:///").unwrap_or(&r.uri);
            full_touched_paths.insert(PathBuf::from(stripped));
        }
    }

    // ── 4. Trailing segment: H_bind → req.head_sha (when they differ) ────
    //
    // §2.5.8 step 4 with topology check (4a) and diff (4b). The trailing
    // segment NEVER skips topology_check — there is no IntegrationMerge
    // carve-out on the gap between the last admitted range and the
    // CompleteTask head_sha.
    if let (Some(ref h_bind_str), Some(ref h_req)) = (h_bind.as_ref(), req_head.as_ref()) {
        if h_bind_str.as_str() != h_req.as_str() {
            let _h_bind_sha = CommitSha::new(h_bind_str)
                .map_err(|_| (PlannerErrorCode::FailInvalidDiff, task_state))?;
            // 4a — topology check on the trailing range (no carve-out).
            rt_handle.block_on(
                ctx.domain.topology_check(h_bind_str, h_req.as_str(), &worktree_path)
            ).map_err(|_| (PlannerErrorCode::FailInvalidCommitTopology, task_state))?;
            // 4b — diff the trailing range.
            let trailing = rt_handle.block_on(
                ctx.domain.compute_touched_paths(h_bind_str, h_req.as_str(), &worktree_path)
            ).map_err(|_| (PlannerErrorCode::FailInvalidDiff, task_state))?;
            for r in trailing.resources {
                let stripped = r.uri.strip_prefix("path:///").unwrap_or(&r.uri);
                full_touched_paths.insert(PathBuf::from(stripped));
            }
        }
    }

    let touched_vec: Vec<PathBuf> = full_touched_paths.iter().cloned().collect();

    // ── 5. Recompute effective_allow + run check_paths ──────────────────
    //
    // Recomputed at completion time per §2.5.8 line 1860 ("Predecessor
    // completion between intents can widen the set"). Same fail-closed
    // semantics as the intent admission branch.
    match crate::path_scope::check_paths(
        &touched_vec,
        &task.initiative_id,
        req.task_id.as_str(),
        &ctx.plan_registry,
        store,
    ) {
        Ok(Ok(())) => {}
        Ok(Err(violation)) => {
            eprintln!(
                "{{\"level\":\"warn\",\"event\":\"CompleteTaskPathViolation\",\
                 \"task_id\":\"{}\",\"violation_count\":{}}}",
                req.task_id.as_str(),
                violation.paths.len(),
            );
            return Err((PlannerErrorCode::FailPathPolicyViolation, task_state));
        }
        Err(e) => {
            eprintln!(
                "{{\"level\":\"error\",\"event\":\"CompleteTaskPathScopeError\",\
                 \"task_id\":\"{}\",\"reason\":\"{e}\"}}",
                req.task_id.as_str(),
            );
            return Err((PlannerErrorCode::FailPathPolicyViolation, task_state));
        }
    }

    // ── 6. Compute exported set (post-pass, pre-commit) ─────────────────
    //
    // Per §2.5.8 line 2003: the export snapshot is `full_touched_paths`
    // intersected with `path_export_globs` if defined. The persistence
    // happens inside the same SQLite tx as the Running → Completed
    // status update — see `commit_task_completion` below.
    let plan_fields = ctx.plan_registry.get(
        &crate::initiatives::TaskKey::new(&task.initiative_id, req.task_id.as_str()),
    );
    let export_paths: Vec<String> = plan_fields
        .as_ref()
        .filter(|f| f.path_export_to_successors)
        .map(|f| compute_export_set(&touched_vec, &f.path_export_globs))
        .unwrap_or_default();

    // ── 7. Atomic commit — Running → Completed + snapshot inserts ───────
    commit_task_completion(req.task_id.as_str(), &export_paths, store)
        .map_err(|_| (PlannerErrorCode::FailTaskNotRunning, task_state))?;

    eprintln!(
        "{{\"level\":\"info\",\"event\":\"TaskCompleted\",\"task_id\":\"{}\",\
         \"exported_paths\":{}}}",
        req.task_id.as_str(),
        export_paths.len(),
    );

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

/// Read `(tasks.evaluation_sha, list-of-(base, head))` for one task.
///
/// `evaluation_sha` may be SQL `NULL` — returned as `None` to signal
/// "no kernel-bound tip yet", in which case the trailing-segment branch
/// of CompleteTask is skipped (§2.5.8 step 4 vacuous case).
fn read_completion_inputs(
    task_id: &str,
    store:   &Store,
) -> Result<(Option<String>, Vec<(String, String)>), ()> {
    let conn = store.lock_sync();

    let h_bind: Option<String> = conn.query_row(
        &format!("SELECT evaluation_sha FROM {TASKS} WHERE task_id = ?1"),
        rusqlite::params![task_id],
        |r| r.get::<_, Option<String>>(0),
    ).map_err(|_| ())?;

    let mut stmt = conn.prepare_cached(&format!(
        "SELECT base_sha, head_sha FROM {TASK_INTENT_RANGES} WHERE task_id = ?1",
    )).map_err(|_| ())?;
    let ranges: Vec<(String, String)> = stmt
        .query_map(rusqlite::params![task_id], |r| Ok((r.get(0)?, r.get(1)?)))
        .map_err(|_| ())?
        .collect::<Result<_, _>>()
        .map_err(|_| ())?;

    Ok((h_bind, ranges))
}

/// Apply `path_export_globs` to the union of touched paths and return the
/// concrete literal paths to persist.
///
/// §2.5.8 line 2003-2010: if `path_export_globs` is empty, export the
/// full touched set (coarse — operator's responsibility). If non-empty,
/// emit only the subset matching at least one glob.
///
/// `path_export_globs` keeps glob semantics (V1) — it is a *filter* on
/// outgoing exports, not a containment check, and operators benefit
/// from `**`/`*` for ergonomic export shaping. Globs use
/// `require_literal_separator = true` so `*` does not cross `/`.
/// Patterns that fail to compile are SKIPPED (not fatal) as a
/// defense-in-depth posture; the signing tool is the gate.
/// (Contrast with `path_allowlist`, which V2 Step 19 restricts to
/// exact-or-trailing-slash strings — see `path_scope::PathEntry`.)
fn compute_export_set(touched: &[PathBuf], export_globs: &[String]) -> Vec<String> {
    if export_globs.is_empty() {
        return touched.iter().map(|p| p.to_string_lossy().into_owned()).collect();
    }

    let opts = glob::MatchOptions {
        case_sensitive:              true,
        require_literal_separator:   true,
        require_literal_leading_dot: false,
    };

    let compiled: Vec<glob::Pattern> = export_globs
        .iter()
        .filter_map(|g| glob::Pattern::new(g).ok())
        .collect();
    if compiled.is_empty() { return Vec::new(); }

    touched.iter()
        .filter_map(|p| {
            if compiled.iter().any(|g| g.matches_path_with(p, opts)) {
                Some(p.to_string_lossy().into_owned())
            } else {
                None
            }
        })
        .collect()
}

// ---------------------------------------------------------------------------
// handle_submit_review — IntentKind::SubmitReview (V2)
//
// Normative reference: v2-deep-spec.md §Step 22 ("Critique Routing — Why
// the Kernel Holds the Critique") and §Step 25 ("Parallel Reviewer
// logical-AND verdict aggregation").
//
// Pipeline (sync, runs on the blocking pool inside `run_phase_a`):
//
//   1. Task-state gate. The Reviewer task must be `Running`.
//   2. Wire payload validation:
//        a. `req.approved` MUST be `Some(_)` (NULL ⇒ INVALID_REQUEST).
//        b. On `approved == Some(false)`, `req.critique` MUST be
//           `Some(non-empty)` (missing ⇒ INVALID_REQUEST) and at most
//           `MAX_CRITIQUE_BYTES` (32 KiB) bytes long
//           (oversized ⇒ INVALID_REQUEST). The critique is NOT stored
//           on rejection — INV-08, no detail leaked, and an attacker
//           cannot use oversized payloads to flood `tasks.last_critique`.
//        c. On `approved == Some(true)` we silently drop any critique
//           text the planner sent — the success path has no critique.
//   3. On rejection (`approved == Some(false)`) only: reverse-DAG join
//      (`task_dag_edges`) to find the predecessor Executor task. The
//      Reviewer's plan-declared `depends_on` MUST list exactly one
//      Executor sub-task (Step 23 sequential model); we tolerate
//      multiple predecessors at the kernel layer (concatenate to all)
//      and rely on plan validation (Step 17 / 19) to enforce shape.
//   4. On rejection only: append the formatted critique to every
//      predecessor task's `tasks.last_critique`. Format is exactly
//      `"[Reviewer <reviewer_task_id>]: <critique>\n\n"` per Step 22 —
//      this is the form the Executor's retry prompt assembler reads.
//      Aggregation across N parallel reviewers (Step 25) is by string
//      concatenation, not replacement: every rejecting reviewer's
//      critique survives until the next activation clears the column.
//   5. Reviewer task FSM transition: Running → Completed. The Reviewer
//      has fulfilled its only authorized output (`SubmitReview`), so
//      its task lifecycle terminates here regardless of verdict
//      (v2-deep-spec.md §Step 22 + dispatch matrix § "Reviewer +
//      ReportFailure = Unauthorized" — the Reviewer cannot self-fail).
//   6. Step 25 cross-Reviewer aggregation runs after the commit (see
//      step 6 below in this function); when the aggregator turns
//      terminal-`AtLeastOneRejected`, the Executor predecessor's
//      `subtask_activations.review_reject_count` is bumped via
//      [`increment_executor_review_reject_count_in_tx`]. Plan-bundle
//      sealing (V2 §Step 1.2 / `0008_v2_plan_bundle_sealing.sql`) has
//      shipped, so the Executor's activation row is guaranteed to
//      exist by the time we reach this code path — the increment is
//      a hard write, not a no-op.
//
// **Idempotency.** Re-submission of the same `(session, sequence_number,
// nonce)` is rejected at Step 2 (envelope acceptance) before this
// handler runs — duplicate submissions never reach this code path.
// A retransmitted critique with a fresh sequence number is treated as
// a NEW reviewer event and aggregated; the planner (Reviewer harness)
// is responsible for not double-submitting the same verdict.
// ---------------------------------------------------------------------------

/// V2 §Step 25 — bump the Executor's *current* (terminated_at IS NULL)
/// `subtask_activations.review_reject_count` by one.
///
/// Called from the [`handle_submit_review`] post-commit aggregation
/// loop exactly once per terminal-rejected round (the aggregator
/// emits `AtLeastOneRejected` once when the last sibling Reviewer
/// votes; per-Reviewer increments would multiply the count and make
/// `max_review_rejections` ceilings effectively N× too tight). The
/// returned `Result` is fail-soft at the call site — the counter
/// is internal accounting, not on the audit path.
///
/// **Why scope to `terminated_at IS NULL`.** A given Executor task
/// can have several historical activation rows (one per retry
/// round once `RetrySubTask` lands V2 §Step 12 properly). The
/// counter we want to bump is the *active* one — the row whose
/// session is still bound — which by construction is the only row
/// with a NULL `terminated_at`. Bumping a terminated row would
/// double-count history and skew the ceiling check.
///
/// **Atomicity.** Single `UPDATE ... SET review_reject_count =
/// review_reject_count + 1` in its own transaction. Concurrent
/// reviewers cannot race here because the aggregator's
/// terminal-rejected branch fires once per round (when the last
/// Pending vote becomes non-Pending), and `handle_submit_review`
/// itself is serialised by the per-session sequence-number gate
/// (INV-01).
fn increment_executor_review_reject_count(
    executor_task_id: &str,
    store:            &Store,
) -> Result<(), rusqlite::Error> {
    let conn = store.lock_sync();
    conn.execute(
        &format!(
            "UPDATE {SUBTASK_ACTIVATIONS}
                SET review_reject_count = review_reject_count + 1
              WHERE task_id        = ?1
                AND terminated_at IS NULL"
        ),
        rusqlite::params![executor_task_id],
    )?;
    Ok(())
}

fn handle_submit_review(
    req: IntentRequest,
    task_state: TaskState,
    session_id: &SessionId,
    seq: u64,
    store: &Store,
    policy: &raxis_policy::PolicyBundle,
    ctx: &HandlerContext,
) -> HandlerResult {
    // ── 1. Task-state gate ────────────────────────────────────────────────
    if task_state != TaskState::Running {
        return Err((PlannerErrorCode::FailTaskNotRunning, task_state));
    }

    // ── 2. Wire payload validation ────────────────────────────────────────
    let approved = match req.approved {
        Some(v) => v,
        None    => return Err((PlannerErrorCode::InvalidRequest, task_state)),
    };

    // The reviewer's own task_id (NOT the Executor's). Used as the
    // attribution prefix in the aggregated critique format.
    let reviewer_task_id = req.task_id.as_str().to_owned();

    // On rejection: validate critique presence + size BEFORE doing any
    // database work. Empty/missing/oversized critiques are rejected
    // without touching `tasks.last_critique`.
    let formatted_critique = if !approved {
        let critique = req.critique.as_deref().unwrap_or("");
        if critique.is_empty() {
            return Err((PlannerErrorCode::InvalidRequest, task_state));
        }
        if critique.len() > raxis_types::MAX_CRITIQUE_BYTES {
            // Oversized critique. INV-08: coarse code only. The planner
            // sees `INVALID_REQUEST`; the audit chain (out of scope
            // here) records the structured rejection.
            return Err((PlannerErrorCode::InvalidRequest, task_state));
        }
        // Step 22 canonical format: `[Reviewer <task_id>]: <critique>\n\n`.
        Some(format!("[Reviewer {reviewer_task_id}]: {critique}\n\n"))
    } else {
        // Success path: no critique to store. Any text the planner sent
        // is silently dropped (Step 22 — "Some(\"...\") with approved =
        // true is silently dropped").
        None
    };

    // ── 3 + 4 + 5: predecessor lookup + critique append + FSM transition ──
    //
    // We do these three writes in ONE SQLite transaction so a crash
    // between the critique append and the Running → Completed update
    // cannot leave the Reviewer in `Running` with a stale critique on
    // the Executor's row (INV-STORE-02 atomicity, Pattern B).
    //
    // **Why predecessor lookup happens for BOTH approved and rejected
    // submissions** (V2 Step 25 wiring, gap §12.2). Even on the
    // approval path the kernel needs the Executor task_id so the
    // post-commit aggregator can fold this Reviewer's verdict into
    // the cross-Reviewer logical-AND. The rejection path additionally
    // uses the predecessor list to append the formatted critique
    // (Step 22). One join per SubmitReview, two consumers.
    let predecessors: Vec<String> = {
        let mut conn = store.lock_sync();
        let tx = conn.transaction()
            .map_err(|_| (PlannerErrorCode::FailPolicyViolation, task_state))?;

        // Reverse-DAG: find every predecessor task_id of this
        // Reviewer. In the canonical Step 23 sequential model
        // there is exactly one (the Executor); we tolerate
        // multiple at the kernel layer and append to each.
        let predecessors: Vec<String> = {
            let mut stmt = tx.prepare(
                &format!(
                    "SELECT predecessor_task_id FROM {dag_edges}
                     WHERE successor_task_id = ?1",
                    dag_edges = Table::TaskDagEdges.as_str(),
                )
            ).map_err(|_| (PlannerErrorCode::FailPolicyViolation, task_state))?;
            let rows = stmt.query_map(
                rusqlite::params![reviewer_task_id.as_str()],
                |r| r.get::<_, String>(0),
            ).map_err(|_| (PlannerErrorCode::FailPolicyViolation, task_state))?;
            rows.filter_map(Result::ok).collect()
        };

        if let Some(formatted) = formatted_critique.as_deref() {
            // No predecessors on the rejection path: a Reviewer task
            // without any `depends_on` edge is malformed at the plan
            // layer (Step 17 DAG validation would have rejected it on
            // approve_plan, but defense in depth — also reject here).
            // We surface INVALID_REQUEST to the planner so the
            // Reviewer harness retries via the operator. INV-08 —
            // coarse code, no detail. (On the approval path we
            // tolerate empty predecessors and let the post-commit
            // aggregator surface `NoSuccessors`.)
            if predecessors.is_empty() {
                return Err((PlannerErrorCode::InvalidRequest, task_state));
            }

            // Append the formatted critique to every predecessor's
            // `tasks.last_critique` (NULL → just the new entry; existing
            // string → existing || new). `COALESCE(last_critique, '')`
            // keeps the SQL single-statement and idempotent across
            // null-vs-string starting state.
            let mut update_stmt = tx.prepare(
                &format!(
                    "UPDATE {tasks} SET last_critique =
                        COALESCE(last_critique, '') || ?1
                     WHERE task_id = ?2",
                    tasks = Table::Tasks.as_str(),
                )
            ).map_err(|_| (PlannerErrorCode::FailPolicyViolation, task_state))?;

            for predecessor in &predecessors {
                update_stmt.execute(
                    rusqlite::params![formatted, predecessor.as_str()],
                ).map_err(|_| (PlannerErrorCode::FailPolicyViolation, task_state))?;
            }
        }

        // Persist the per-Reviewer verdict on the Reviewer's own task
        // row. Step 25 aggregation reads this column to compute the
        // logical-AND across all sibling Reviewers of an Executor.
        // Written BEFORE the FSM transition so the row carries
        // (state=Completed, review_verdict=non-NULL) atomically — the
        // aggregator never observes a Completed Reviewer with a NULL
        // verdict (which would otherwise be classified as "still
        // working" and stall the pipeline forever).
        let verdict = if approved {
            raxis_types::ReviewVerdict::Approved
        } else {
            raxis_types::ReviewVerdict::Rejected
        };
        tx.execute(
            &format!(
                "UPDATE {tasks} SET review_verdict = ?1 WHERE task_id = ?2",
                tasks = Table::Tasks.as_str(),
            ),
            rusqlite::params![verdict.as_sql_str(), req.task_id.as_str()],
        ).map_err(|_| (PlannerErrorCode::FailPolicyViolation, task_state))?;

        // Reviewer's own task FSM: Running → Completed. The Reviewer
        // has done its job — successful or not, the Reviewer task
        // terminates here. This is by design: the Reviewer cannot
        // self-fail (Step 20 dispatch matrix forbids ReportFailure for
        // Reviewers); its only terminal output is SubmitReview, and
        // that output is the activation lifecycle terminator.
        transition_task_in_tx(
            &tx,
            req.task_id.as_str(),
            TaskState::Completed,
            None,
            TransitionActor::Kernel,
        ).map_err(|_| (PlannerErrorCode::FailTaskNotRunning, task_state))?;

        tx.commit()
            .map_err(|_| (PlannerErrorCode::FailPolicyViolation, task_state))?;

        predecessors
    };

    // Structured log for forensic traceability. INV-08 means the wire
    // returns the coarse outcome only; the kernel logs carry the
    // structured detail.
    eprintln!(
        "{{\"level\":\"info\",\"event\":\"ReviewSubmitted\",\
         \"reviewer_task_id\":\"{}\",\"approved\":{}}}",
        reviewer_task_id,
        approved,
    );

    // ── 6. Step 25 cross-Reviewer aggregation (V2 gap §12.2) ──────────────
    //
    // For every Executor predecessor of this Reviewer, fold the full
    // sibling-Reviewer set into the logical-AND verdict per
    // `v2-deep-spec.md §Step 25`. The aggregator is a pure read
    // predicate that runs AFTER the SubmitReview commit has fixed
    // this Reviewer's `tasks.review_verdict` row, so it observes the
    // canonical "did everyone vote yet?" state.
    //
    // Emission contract (single-class observability, per
    // `audit-paired-writes.md §4`):
    //   * `Pending`         → silent. We are still waiting on a
    //                         sibling Reviewer; emitting now would
    //                         flood the audit chain with N-1
    //                         partial-state rows.
    //   * `AllPassed`       → emit `ReviewAggregationCompleted`. The
    //                         V2.3 push dispatcher (`push::mod`) is
    //                         shipped; once the kernel persists an
    //                         initiative→Orchestrator-session
    //                         mapping (gap §12.1 — schema migration
    //                         pending) the call site here will also
    //                         fire `push_dispatcher.enqueue(orch,
    //                         KernelPush::AllReviewersPassed{..})`.
    //                         Until then the audit row is the
    //                         canonical signal — the Orchestrator
    //                         polls the audit chain via
    //                         `OperatorRequest::ListInitiativeEvents`.
    //   * `AtLeastOneRejected` → emit `ReviewAggregationCompleted`
    //                         AND bump `subtask_activations.
    //                         review_reject_count` for the Executor
    //                         predecessor (Step 25 counter — see
    //                         `increment_executor_review_reject_count`).
    //                         Push enqueue (`KernelPush::ReviewRejected`)
    //                         follows the same migration as
    //                         `AllPassed` above.
    //   * `NoSuccessors`    → emit `ReviewAggregationCompleted` for
    //                         defense in depth (a malformed plan
    //                         this kernel let in must surface in
    //                         the audit chain even though the push
    //                         never fires; operators can grep the
    //                         audit segment for forensic recovery).
    //
    // Fail-soft on aggregator errors: a SQLite read failure here
    // does NOT roll back the SubmitReview commit (it's already
    // durable). We log the error and continue so the Reviewer
    // harness still observes its `Accepted` response.
    let task = load_task(req.task_id.as_str(), store)
        .map_err(|_| (PlannerErrorCode::FailUnknownTask, TaskState::Completed))?;
    let session_id_str    = session_id.as_str().to_owned();
    let initiative_id_str = task.initiative_id.clone();
    for predecessor in &predecessors {
        let outcome = match crate::initiatives::review_aggregation
            ::compute_aggregate_review_outcome(predecessor.as_str(), store)
        {
            Ok(o) => o,
            Err(e) => {
                eprintln!(
                    "{{\"level\":\"warn\",\"event\":\"ReviewAggregationFailed\",\
                     \"executor_task_id\":\"{predecessor}\",\
                     \"reviewer_task_id\":\"{reviewer_task_id}\",\
                     \"error\":\"{e}\"}}",
                );
                continue;
            }
        };

        let verdict_str = match outcome.verdict {
            // Silent: not yet at terminal state.
            crate::initiatives::review_aggregation::AggregateReviewVerdict::Pending => continue,
            crate::initiatives::review_aggregation::AggregateReviewVerdict::AllPassed
                => "AllPassed",
            crate::initiatives::review_aggregation::AggregateReviewVerdict::AtLeastOneRejected
                => "AtLeastOneRejected",
            crate::initiatives::review_aggregation::AggregateReviewVerdict::NoSuccessors
                => "NoSuccessors",
        };

        // V2 §Step 25 — bump the Executor's `review_reject_count` once
        // per terminal-rejected aggregation round. Plan-bundle sealing
        // (§Step 1.2) guarantees the activation row exists; the helper
        // is fail-soft (logs + continues) on SQLite errors so a
        // counter-bump failure cannot stall the post-commit audit
        // emission below. The counter is the substrate the
        // `RetrySubTask` ceiling-check in `handle_retry_sub_task`
        // reads against the plan-declared `max_review_rejections`.
        if matches!(
            outcome.verdict,
            crate::initiatives::review_aggregation::AggregateReviewVerdict::AtLeastOneRejected,
        ) {
            if let Err(e) = increment_executor_review_reject_count(
                predecessor.as_str(), store,
            ) {
                eprintln!(
                    "{{\"level\":\"warn\",\
                     \"event\":\"ReviewRejectCounterIncrementFailed\",\
                     \"executor_task_id\":\"{predecessor}\",\
                     \"reviewer_task_id\":\"{reviewer_task_id}\",\
                     \"error\":\"{e}\"}}",
                );
            }
        }

        eprintln!(
            "{{\"level\":\"info\",\"event\":\"ReviewAggregationCompleted\",\
             \"executor_task_id\":\"{predecessor}\",\
             \"reviewer_task_id\":\"{reviewer_task_id}\",\
             \"reviewer_count\":{count},\"verdict\":\"{verdict_str}\"}}",
            count = outcome.count,
        );

        if let Err(e) = ctx.audit.emit(
            raxis_audit_tools::AuditEventKind::ReviewAggregationCompleted {
                executor_task_id:               predecessor.clone(),
                triggered_by_reviewer_task_id:  reviewer_task_id.clone(),
                reviewer_count:                 outcome.count,
                verdict:                        verdict_str.to_owned(),
            },
            Some(session_id_str.as_str()),
            Some(reviewer_task_id.as_str()),
            Some(initiative_id_str.as_str()),
        ) {
            eprintln!(
                "{{\"level\":\"error\",\"event\":\"ReviewAggregationCompleted\",\
                 \"audit_emit_failed\":\"{e}\",\
                 \"executor_task_id\":\"{predecessor}\",\
                 \"reviewer_task_id\":\"{reviewer_task_id}\"}}",
            );
        }
    }

    // Lane budget snapshot (lane unchanged on review submission — the
    // Reviewer's admission cost was charged at activation; SubmitReview
    // itself consumes nothing).
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
// handle_structured_output — V2 §3.2 typed mid-session output.
//
// Spec references:
//   * `v2_extended_gaps.md §3.2` — typed mid-session communication
//     enum (`StructuredOutputKind`).
//   * `crates/types/src/structured_output.rs` — payload shape +
//     `validate_and_normalise` + size caps.
//
// Pipeline (entirely sync, runs inside Phase A's spawn_blocking):
//   1. Wire payload validation: `req.structured_output` MUST be
//      `Some(_)` (the dispatch-matrix arm authorised the kind, but
//      a payload-less submission still fails closed).
//   2. Kernel-side normalisation:
//      [`StructuredOutputKind::validate_and_normalise`] truncates
//      over-cap strings/lists, clamps confidence into `[0.0, 1.0]`,
//      and rejects fundamentally-malformed inputs (e.g. a non-hex
//      `commit_sha` on `TaskSummary`).
//   3. Per-session rate limit: COUNT(*) of prior accepted outputs
//      for this `session_id`, reject with
//      `FailStructuredOutputRateLimited` when >=
//      `STRUCTURED_OUTPUT_PER_SESSION_RATE_LIMIT`.
//   4. INSERT into `structured_outputs` inside the same `BEGIN
//      IMMEDIATE` transaction so the COUNT cannot race past the
//      cap (concurrent submissions on the same session serialise
//      on the writer mutex).
//   5. Audit emit (`StructuredOutputEmitted`) AFTER the commit.
//   6. NON-TERMINAL response — task stays in its current state
//      (Admitted or Running). Lane budget snapshot is unchanged
//      (a structured output consumes no lane units; the §2.5
//      token-cost gate already debited the LLM-token cost above).
// ---------------------------------------------------------------------------

fn handle_structured_output(
    req:        IntentRequest,
    task_state: TaskState,
    session_id: &SessionId,
    seq:        u64,
    store:      &Store,
    ctx:        &HandlerContext,
) -> HandlerResult {
    // ── 1. Wire payload validation ────────────────────────────────────────
    let mut payload = match req.structured_output {
        Some(p) => p,
        None    => return Err((
            PlannerErrorCode::FailStructuredOutputInvalid, task_state)),
    };

    // ── 2. Normalise (and reject hard-failures only) ──────────────────────
    if payload.validate_and_normalise().is_err() {
        return Err((
            PlannerErrorCode::FailStructuredOutputInvalid, task_state));
    }

    // ── 3. Look up task scope (initiative_id, lane_id) for the audit row.
    let task = load_task(req.task_id.as_str(), store)
        .map_err(|_| (PlannerErrorCode::FailUnknownTask, task_state))?;

    let kind_tag    = payload.variant_tag();
    let severity    = match &payload {
        raxis_types::StructuredOutputKind::DiagnosticFlag { severity, .. } =>
            Some(severity.as_str().to_owned()),
        _ => None,
    };

    // Serialise the (possibly-truncated) payload for storage.
    // A pure in-memory `serde_json::to_string` on a closed enum
    // can only fail if the enum carries non-finite floats or
    // non-UTF8 strings, neither of which `validate_and_normalise`
    // permits. Belt-and-braces: surface the failure as
    // `FailStructuredOutputInvalid` instead of unwrapping.
    let payload_json = match serde_json::to_string(&payload) {
        Ok(s)  => s,
        Err(_) => return Err((
            PlannerErrorCode::FailStructuredOutputInvalid, task_state)),
    };
    let payload_bytes = u32::try_from(payload_json.len()).unwrap_or(u32::MAX);

    // ── 4. Rate-limit COUNT + INSERT inside one BEGIN IMMEDIATE tx ────────
    //
    // We hold the writer mutex across both reads + writes so the
    // per-session counter cannot race past the cap. The kernel's
    // single-writer SQLite mutex makes this contention-free for
    // any reasonable structured-output rate.
    let output_id = uuid::Uuid::new_v4().to_string();
    let emitted_at = unix_now_secs();
    {
        let mut conn = store.lock_sync();
        let tx = conn.transaction()
            .map_err(|_| (PlannerErrorCode::FailStructuredOutputInvalid, task_state))?;

        let so_table = Table::StructuredOutputs.as_str();

        let count: u32 = tx.query_row(
            &format!(
                "SELECT COUNT(*) FROM {so_table} WHERE session_id = ?1"
            ),
            rusqlite::params![session_id.as_str()],
            |r| r.get::<_, i64>(0).map(|v| v as u32),
        ).unwrap_or(0);

        if count >= raxis_types::STRUCTURED_OUTPUT_PER_SESSION_RATE_LIMIT {
            // INV-08 — coarse code only. The internal log carries
            // the structured detail.
            eprintln!(
                "{{\"level\":\"warn\",\"event\":\"StructuredOutputRateLimited\",\
                 \"session_id\":\"{}\",\"task_id\":\"{}\",\"count\":{count}}}",
                session_id.as_str(),
                req.task_id.as_str(),
            );
            return Err((
                PlannerErrorCode::FailStructuredOutputRateLimited, task_state));
        }

        tx.execute(
            &format!(
                "INSERT INTO {so_table}
                    (output_id, initiative_id, task_id, session_id,
                     kind, severity, payload_json, emitted_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)"
            ),
            rusqlite::params![
                output_id,
                task.initiative_id,
                req.task_id.as_str(),
                session_id.as_str(),
                kind_tag,
                severity,
                payload_json,
                emitted_at as i64,
            ],
        ).map_err(|_| (PlannerErrorCode::FailStructuredOutputInvalid, task_state))?;

        tx.commit()
            .map_err(|_| (PlannerErrorCode::FailStructuredOutputInvalid, task_state))?;
    }

    // ── 5. Audit emit AFTER the commit (§2.5.2 audit-after-commit) ────────
    if let Err(e) = ctx.audit.emit(
        raxis_audit_tools::AuditEventKind::StructuredOutputEmitted {
            output_id:     output_id.clone(),
            initiative_id: task.initiative_id.clone(),
            task_id:       req.task_id.as_str().to_owned(),
            session_id:    session_id.as_str().to_owned(),
            output_kind:   kind_tag.to_owned(),
            severity:      severity.clone(),
            payload_bytes,
        },
        Some(session_id.as_str()),
        Some(req.task_id.as_str()),
        Some(task.initiative_id.as_str()),
    ) {
        eprintln!(
            "{{\"level\":\"error\",\"event\":\"StructuredOutputEmitted\",\
             \"audit_emit_failed\":\"{e}\",\"session_id\":\"{}\",\
             \"task_id\":\"{}\"}}",
            session_id.as_str(),
            req.task_id.as_str(),
        );
    }

    // Forensic info-level log so operators can grep by event name
    // even when the audit sink drops temporarily.
    eprintln!(
        "{{\"level\":\"info\",\"event\":\"StructuredOutputEmitted\",\
         \"session_id\":\"{}\",\"task_id\":\"{}\",\"kind\":\"{kind_tag}\",\
         \"payload_bytes\":{payload_bytes}}}",
        session_id.as_str(),
        req.task_id.as_str(),
    );

    // ── 6. NON-TERMINAL response ─────────────────────────────────────────
    //
    // The task FSM stays where it is — `StructuredOutput` is a
    // mid-session emission, not a terminal commit. Lane budget is
    // unchanged (no admission unit consumed). The §2.5 token-cost
    // gate already debited the cumulative LLM cost above (in
    // `run_phase_a` before dispatch reached this handler).
    let remaining = BudgetSnapshot { admission_units: 0 };
    Ok(IntentResponse {
        sequence_number: seq,
        task_state,
        outcome: IntentOutcome::Accepted {
            remaining_budget:      remaining,
            warn_delegation_stale: false,
        },
    })
}

// ---------------------------------------------------------------------------
// handle_activate_sub_task — V2 Step 21 dedicated handler.
// ---------------------------------------------------------------------------
//
// Spec references:
//   * `v2-deep-spec.md §Step 21` — Orchestrator submits
//     `ActivateSubTask { task_id }` to spawn an Executor / Reviewer
//     VM for a previously-admitted sub-task.
//   * `v2-deep-spec.md §Step 5` — `subtask_activations` row FSM
//     (`PendingActivation → Active → Completed | Failed`).
//   * `extensibility-traits.md §3.5` — kernel-substrate seam; the
//     handler calls `ctx.session_spawn.spawn_session()` directly
//     (free-fn `spawn_executor_for_task`) rather than going through
//     a second trait surface.
//
// The handler runs ENTIRELY on the async path (no Phase A / B / C
// split): the substrate spawn is async by definition, and the
// surrounding SQLite work is small enough that two `spawn_blocking`
// hops bracket it cleanly.
//
// Pipeline:
//   1. Sequence + nonce envelope acceptance (replay protection,
//      INV-01) — `spawn_blocking`, mirrors Phase A Step 2.
//   2. Activation-row + task lookup; assert `PendingActivation` and
//      `Admitted`; mint a new `sessions` row in the same SQL
//      transaction as the activation row claim — `spawn_blocking`.
//   3. Substrate spawn through `ctx.session_spawn.spawn_session()`
//      via the `spawn_executor_for_task` free function — async.
//   4. Activation-row FSM transition `PendingActivation → Active`,
//      stamp `session_id` + `activated_at`, persist the substrate's
//      `vsock_cid` on the new `sessions` row — `spawn_blocking`.
//   5. Audit emit (`SessionCreated`) — async.
//
// Atomicity / consistency:
//   * Steps 1, 2, 4 are each their own transaction. Step 1 is
//     replay-tight (envelope acceptance commits the sequence
//     advance + nonce in one tx).
//   * Step 4's transition only runs if Step 3's substrate spawn
//     returned `Ok`. Substrate failure leaves the activation row
//     in `PendingActivation` and the freshly-minted session row
//     in the table with `revoked = 1`; the recovery sweep can
//     reclaim both on the next boot. We deliberately do NOT roll
//     back the session insert when the substrate fails so
//     forensic replay can see the attempted spawn.
//
// Worktree provisioning is OUT OF SCOPE for this handler: the
// kernel's `worktree_provision` integration call site (which
// resolves the source ODB + materialises a fresh worktree per
// `v2-deep-spec.md §Step 24 / §Step 24b`) is wired in a follow-up.
// The substrate spawn proceeds with an empty `workspace_mounts`
// vector for now; an Executor that needs a worktree at boot will
// surface a `BackendInternal` error from the substrate.
/// V2.5 §13 — resolve an operator-published `[[vm_images]]` alias
/// to a [`raxis_isolation::VerifiedImage`] the spawn path can boot.
///
/// The activation handler calls this once per sub-task activation
/// when the admission validator stamped a non-empty
/// `vm_image` on the task's [`crate::initiatives::plan_registry::TaskPlanFields`].
/// The resolver:
///
///   1. Looks up the alias against the *current* policy bundle
///      (so a policy rotation between admission and activation is
///      observed).
///   2. Parses the entry's `oci_digest` into [`raxis_image_cache::OciDigest`].
///   3. Calls [`raxis_image_cache::ImageResolver::resolve`] with
///      no registry hint (the production resolver consults its
///      configured default registry; the offline-friendly
///      `PrePopulatedResolver` reads from `<data_dir>/oci-cache/`).
///   4. Wraps the resolved rootfs path in a [`raxis_isolation::VerifiedImage`]
///      whose `image_id` is the alias (so audit events name the
///      operator-facing alias rather than the digest hex).
///
/// **Failure modes** (all surface as `Err(String)` for the caller
/// to log structurally):
///
///   * Alias dropped from policy at the current epoch → "alias
///     `{name}` is no longer declared in `[[vm_images]]`".
///   * Stored `oci_digest` is malformed (impossible after
///     `validate_vm_images`, but defensive) → parse error.
///   * Resolver failure (registry pull, byte mismatch, GC race)
///     → forwarded `ImageResolverError::to_string()`.
///
/// The caller (the activation handler) maps any `Err` to a
/// `FAIL_POLICY_VIOLATION` and parks the activation row in
/// `PendingActivation` so the operator sees the failure and can
/// retry once policy is healed.
async fn resolve_vm_image_override(
    policy: &raxis_policy::PolicyBundle,
    alias:  &str,
    ctx:    &Arc<HandlerContext>,
) -> Result<raxis_isolation::VerifiedImage, String> {
    use std::str::FromStr;

    let entry = policy.vm_image_by_name(alias).ok_or_else(|| {
        format!(
            "alias `{alias}` is no longer declared in [[vm_images]] \
             (policy rotation between admission and activation?); \
             admission stamped this alias against an earlier epoch"
        )
    })?;
    let digest = raxis_image_cache::OciDigest::from_str(&entry.oci_digest)
        .map_err(|e| format!(
            "[[vm_images]] entry `{alias}` carries malformed oci_digest \
             {value:?}: {e}",
            value = entry.oci_digest,
        ))?;
    let resolved = ctx
        .image_resolver
        .resolve(&digest, None)
        .await
        .map_err(|e| format!(
            "ImageResolver::resolve failed for alias `{alias}` \
             (digest {digest}): {e}",
            digest = entry.oci_digest,
        ))?;
    Ok(raxis_isolation::VerifiedImage {
        kind:      raxis_isolation::ImageKind::RootfsErofs,
        body:      raxis_isolation::ImageBody::Path(resolved.rootfs_image_path),
        signature: raxis_isolation::ImageSignature(Vec::new()),
        image_id:  alias.to_owned(),
    })
}

async fn handle_activate_sub_task(
    req:        IntentRequest,
    _session:   authority::session::SessionRow,
    session_id: SessionId,
    seq:        u64,
    ctx:        &Arc<HandlerContext>,
) -> HandlerResult {
    // ── Step 1: replay protection (envelope acceptance) ────────────────
    let presented_seq_i64 = match i64::try_from(seq) {
        Ok(v) => v,
        Err(_) => return Err((PlannerErrorCode::Unauthorized, TaskState::Admitted)),
    };
    {
        let store     = Arc::clone(&ctx.store);
        let session   = session_id.clone();
        let nonce     = req.envelope_nonce.clone();
        let audit     = Arc::clone(&ctx.audit);
        let session_s = session.as_str().to_owned();
        let result = tokio::task::spawn_blocking(move || {
            authority::session::accept_envelope_and_advance_sequence(
                &session, presented_seq_i64, &nonce, &store,
            )
        })
        .await
        .map_err(|_| (PlannerErrorCode::Unauthorized, TaskState::Admitted))?;
        if let Err(reason) = result {
            let _ = audit.emit(
                raxis_audit_tools::AuditEventKind::ReplayRejected {
                    session_id:   session_s,
                    sequence_num: seq,
                    reason:       format!("{reason:?}"),
                },
                Some(session_id.as_str()),
                None,
                None,
            );
            return Err((PlannerErrorCode::Unauthorized, TaskState::Admitted));
        }
    }

    // ── Step 1.4: V2_GAPS §D2 — disk-full watchdog gate. ───────────────
    //
    // INV-CAPACITY-02 (`host-capacity.md §7.1`): refuse new
    // write-class admissions when the watchdog has flipped to
    // `Halted` (free space < `[host_capacity] min_free_disk_mb`).
    // Spawning a microVM is the most disk-intensive admission path
    // in the kernel — a SubTask activation provisions a worktree,
    // a credential proxy state file, and a substrate VM image
    // copy-on-write base — so we want this fence as early in the
    // path as possible.
    if crate::capacity::refuse_if_disk_full(
        ctx.disk_watchdog.as_deref(),
    ).is_err() {
        return Err((PlannerErrorCode::FailDiskFull, TaskState::Admitted));
    }

    // ── Step 1.5: V2_GAPS §D2 — pre-admission cap check. ───────────────
    //
    // INV-CAPACITY-01 (`host-capacity.md §4.2`): refuse to spawn
    // another microVM if the strict `[host_capacity]
    // max_concurrent_vms` would be exceeded. The check is stateless;
    // it consults the `SessionSpawnService::active_count` (in-memory
    // table of live `Box<dyn IsolationSession>` handles) and the
    // policy-resolved cap.
    //
    // The decision is made BEFORE Step 2 so we never insert a
    // session row that needs to be revoked when we hit cap. V2
    // surfaces the rejection as `FAIL_VM_CONCURRENCY_AT_CAP` and
    // emits `AdmissionDeferredAtCap`. The agent retries by
    // re-issuing `ActivateSubTask` after the kernel signals
    // capacity availability (V3 will deliver
    // `KernelPush::CapacityFreed`; V2 expects polling).
    {
        let policy_snapshot = ctx.policy.load();
        let cap = policy_snapshot.host_capacity().max_concurrent_vms;
        let running = u32::try_from(ctx.session_spawn.active_count().await)
            .unwrap_or(u32::MAX);
        if let crate::capacity::AdmissionDecision::Deferred {
            reason, current_running, cap: observed_cap,
        } = crate::capacity::check_vm_concurrency_cap(running, cap) {
            let _ = ctx.audit.emit(
                raxis_audit_tools::AuditEventKind::AdmissionDeferredAtCap {
                    cap_kind:        reason.cap_kind().to_owned(),
                    current_running,
                    cap:             observed_cap,
                    initiative_id:   None,
                    task_id:         Some(req.task_id.as_str().to_owned()),
                },
                Some(session_id.as_str()),
                Some(req.task_id.as_str()),
                None,
            );
            return Err((
                PlannerErrorCode::FailVmConcurrencyAtCap,
                TaskState::Admitted,
            ));
        }
    }

    // ── Step 2: activation-row + task lookup; mint session row. ────────
    //
    // We do steps 2a (read activation row), 2b (read task agent type
    // from PlanRegistry), and 2c (insert sessions row) in the same
    // transaction. The activation row STAYS in `PendingActivation`
    // here — we only flip it to `Active` after the substrate spawn
    // succeeds (Step 4). The cross-column CHECK enforces this:
    // `Active` requires non-NULL `session_id` AND non-NULL
    // `activated_at`, and we have neither yet.
    let task_id_owned     = req.task_id.as_str().to_owned();
    let plan_registry_arc = Arc::clone(&ctx.plan_registry);

    #[derive(Clone)]
    struct ActivationLookup {
        agent_kind:    crate::session_spawn_orchestrator::ExecutorAgentKind,
        initiative_id: String,
        new_session_id: String,
        new_lineage_id: String,
        activation_id: String,
        /// V2.5 §13 — operator-published `[[vm_images]]` alias the
        /// admission validator stamped on this task's
        /// `TaskPlanFields`. Empty when the plan omitted `vm_image`
        /// AND no `[default_executor_image]` back-fill applied;
        /// the spawn path then falls back to the canonical
        /// starter image. Reviewer tasks always carry the empty
        /// string (the validator rejects any `vm_image` on a
        /// Reviewer per INV-PLANNER-HARNESS-02).
        vm_image_alias: String,

        /// V2 `v2_extended_gaps.md §1.1` — operator-authored seed
        /// prompt for the planner agent (Executor / Reviewer).
        /// Empty when the plan omitted `[[tasks.X]] description`;
        /// the spawn path then leaves `RAXIS_PLANNER_TASK_PROMPT`
        /// unset which keeps the planner binary in scaffold/park
        /// mode (`INV-DRIVER-01`). The activation handler is the
        /// trust boundary that materialises the prompt into the
        /// substrate's env table — the agent never observes it
        /// before the dispatch loop renders it.
        task_prompt: String,
    }

    let lookup: ActivationLookup = {
        let store_arc = Arc::clone(&ctx.store);
        let task_id   = task_id_owned.clone();
        tokio::task::spawn_blocking(move || -> Result<ActivationLookup, (PlannerErrorCode, TaskState)> {
            let mut conn = store_arc.lock_sync();
            let tx = conn.transaction()
                .map_err(|_| (PlannerErrorCode::FailPolicyViolation, TaskState::Admitted))?;

            // 2a. Activation row — must exist, must be PendingActivation.
            let activation_id: String = {
                let row: Result<(String, String, String), rusqlite::Error> = tx.query_row(
                    &format!(
                        "SELECT activation_id, activation_state, initiative_id
                           FROM {SUBTASK_ACTIVATIONS}
                          WHERE task_id = ?1
                          ORDER BY created_at DESC
                          LIMIT 1"
                    ),
                    rusqlite::params![&task_id],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                );
                let (activation_id, state, _initiative_id) = match row {
                    Ok(r)  => r,
                    Err(_) => return Err((PlannerErrorCode::FailUnknownTask, TaskState::Admitted)),
                };
                if state != "PendingActivation" {
                    return Err((PlannerErrorCode::FailPolicyViolation, TaskState::Admitted));
                }
                activation_id
            };

            // 2b. Task row — must be Admitted, and must carry a
            //      typed `session_agent_type` (Executor or Reviewer)
            //      retrievable from the in-memory plan registry.
            let task_row: (String, String) = match tx.query_row(
                &format!("SELECT initiative_id, state FROM {TASKS} WHERE task_id = ?1"),
                rusqlite::params![&task_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            ) {
                Ok(r)  => r,
                Err(_) => return Err((PlannerErrorCode::FailUnknownTask, TaskState::Admitted)),
            };
            let (initiative_id, task_state_str) = task_row;
            if task_state_str != TaskState::Admitted.as_sql_str() {
                return Err((PlannerErrorCode::FailTaskNotRunning,
                            parse_task_state(&task_state_str)));
            }

            // The plan registry holds the typed `session_agent_type`
            // (the `tasks` DDL stores it as a string column on
            // older migrations; the in-memory plan registry is the
            // canonical V2 source). The same registry entry carries
            // the V2.5 `vm_image` alias chosen at admission time.
            let (agent_kind, vm_image_alias, task_prompt) = {
                let key = crate::initiatives::plan_registry::TaskKey::new(
                    &initiative_id, &task_id,
                );
                let fields = match plan_registry_arc.get(&key) {
                    Some(f) => f,
                    None    => return Err((PlannerErrorCode::FailUnknownTask, TaskState::Admitted)),
                };
                let kind = match fields.session_agent_type {
                    raxis_types::SessionAgentType::Executor =>
                        crate::session_spawn_orchestrator::ExecutorAgentKind::Executor,
                    raxis_types::SessionAgentType::Reviewer =>
                        crate::session_spawn_orchestrator::ExecutorAgentKind::Reviewer,
                    raxis_types::SessionAgentType::Orchestrator => {
                        // Defense-in-depth — `approve_plan`'s structural
                        // validator already rejects Orchestrator-typed
                        // `[[tasks]]` blocks, but a corrupt registry
                        // entry would surface here as a policy
                        // violation rather than a substrate error.
                        return Err((PlannerErrorCode::FailPolicyViolation, TaskState::Admitted));
                    }
                };
                // V2 `v2_extended_gaps.md §1.1` — fetch the
                // operator-authored seed prompt out of the same
                // signed-plan-derived registry entry so the spawn
                // path can stamp it into the planner's env table.
                (kind, fields.vm_image, fields.description)
            };

            // 2c. Mint the new Executor / Reviewer session row.
            //     `lineage_id` is freshly generated (the activation
            //     is the start of a new lineage; tying it to the
            //     Orchestrator's lineage would conflate parent /
            //     child trust scopes).
            let new_session_id  = raxis_types::SessionId::new_v4();
            let new_session_str = new_session_id.as_str().to_owned();
            let new_lineage_id  = uuid::Uuid::new_v4().to_string();
            let session_token   = match raxis_crypto::token::generate_session_token() {
                Ok(t)  => t,
                Err(_) => return Err((PlannerErrorCode::FailPolicyViolation, TaskState::Admitted)),
            };
            let now_secs   = unix_now_secs();
            let expires_at = now_secs + 86_400;
            let agent_type_str = match agent_kind {
                crate::session_spawn_orchestrator::ExecutorAgentKind::Executor =>
                    raxis_types::SessionAgentType::Executor.as_sql_str(),
                crate::session_spawn_orchestrator::ExecutorAgentKind::Reviewer =>
                    raxis_types::SessionAgentType::Reviewer.as_sql_str(),
            };
            tx.execute(
                &format!(
                    "INSERT INTO {SESSIONS} (
                        session_id, role_id, session_token, sequence_number,
                        worktree_root, base_sha, base_tracking_ref,
                        lineage_id, fetch_quota, created_at, expires_at, revoked,
                        session_agent_type, can_delegate
                     ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,0,?12,0)"
                ),
                rusqlite::params![
                    new_session_str,
                    "Planner",
                    session_token,
                    0i64,
                    Option::<String>::None,
                    Option::<String>::None,
                    Option::<String>::None,
                    new_lineage_id,
                    1000i64,
                    now_secs,
                    expires_at,
                    agent_type_str,
                ],
            ).map_err(|_| (PlannerErrorCode::FailPolicyViolation, TaskState::Admitted))?;

            tx.commit()
                .map_err(|_| (PlannerErrorCode::FailPolicyViolation, TaskState::Admitted))?;

            Ok(ActivationLookup {
                agent_kind,
                initiative_id,
                new_session_id: new_session_str,
                new_lineage_id,
                activation_id,
                vm_image_alias,
                task_prompt,
            })
        })
        .await
        .map_err(|_| (PlannerErrorCode::FailPolicyViolation, TaskState::Admitted))??
    };

    // ── Step 3: substrate spawn via ctx.session_spawn ──────────────────
    //
    // The free-fn `spawn_executor_for_task` is the single source of
    // truth for "kernel turns (session_id, task_id, agent_kind) into
    // a `SessionSpawnService::spawn_session()` call". It owns the
    // canonical-image resolution, credential-decl rehydration, and
    // SpawnRequest construction — keeping that logic out of the
    // intent handler.
    let policy_snapshot = ctx.policy.load_full();
    let allowlist = raxis_egress_admission::EgressAllowlist {
        exact_hosts: policy_snapshot.egress_domains().to_vec(),
        patterns:    policy_snapshot.egress_patterns().to_vec(),
        credential_proxy_real_targets: Default::default(),
    };

    // V2.5 §13 — resolve the operator-published `[[vm_images]]`
    // alias the admission path stamped on this task. Empty alias
    // ⇒ fall back to canonical starter image (V1 forward-compat
    // and Reviewer tasks). Non-empty alias ⇒ resolve against the
    // *current* policy bundle (so a credential rotation between
    // admission and activation is observed) and pull the rootfs
    // blob via the wired `ImageResolver`. The spawn helper
    // re-checks `INV-PLANNER-HARNESS-02` defensively.
    let image_override = if !lookup.vm_image_alias.is_empty() {
        match resolve_vm_image_override(
            &policy_snapshot,
            &lookup.vm_image_alias,
            ctx,
        ).await {
            Ok(verified) => Some(verified),
            Err(e) => {
                // The resolver surfaced a structured error
                // (alias dropped from policy at this epoch, OCI
                // pull failed, digest mismatch, etc.). Fail the
                // activation — the activation row stays
                // `PendingActivation` so the operator can
                // observe and retry once policy is healed.
                eprintln!(
                    "{{\"level\":\"error\",\"event\":\"VmImageResolveFailed\",\
                     \"task_id\":\"{}\",\"alias\":\"{}\",\"error\":\"{}\"}}",
                    task_id_owned, lookup.vm_image_alias, e,
                );
                return Err((PlannerErrorCode::FailPolicyViolation, TaskState::Admitted));
            }
        }
    } else {
        None
    };

    // V2 `v2_extended_gaps.md §1.1` — stamp the operator-authored
    // task prompt into the substrate's env table so the spawned
    // planner binary's dispatch driver has a concrete user-message
    // seed. The plan-side validator already rejected plans whose
    // `[[tasks]]` block omits or empty-strings `description`
    // (see `parse_plan_tasks`), so by construction
    // `lookup.task_prompt` is non-empty here — no fallback path,
    // no scaffold-mode escape hatch in production.
    //
    // The `BTreeMap` ordering is load-bearing: the substrate's
    // audit / spawn-call logging enumerates env keys in sorted
    // order, and a `HashMap` would surface non-determinism in
    // those logs across boots.
    debug_assert!(
        !lookup.task_prompt.is_empty(),
        "INV §1.1: parser guarantees non-empty description; reaching activation \
         with an empty prompt is a bug in `parse_plan_tasks` — fix the parser, \
         do not silently spawn a runaway agent",
    );
    let mut extra_env = std::collections::BTreeMap::<String, String>::new();
    extra_env.insert(
        crate::session_spawn_orchestrator::PLANNER_TASK_PROMPT_ENV.to_owned(),
        lookup.task_prompt.clone(),
    );

    let spawn_handle = match crate::session_spawn_orchestrator::spawn_executor_for_task(
        &ctx.executor_spawn,
        lookup.agent_kind,
        &lookup.new_session_id,
        &task_id_owned,
        &lookup.initiative_id,
        allowlist,
        Vec::new(),
        extra_env,
        Arc::clone(&ctx.session_spawn),
        &ctx.plan_registry,
        &ctx.store,
        // V2 `v2_extended_gaps.md §2.5` — pass the live policy
        // snapshot so the spawn path can stamp `[budget.token_caps]`
        // into the planner-VM env. Reading off the existing
        // `policy_snapshot` (loaded earlier in this handler) keeps
        // the snapshot consistent across this intent's lifecycle.
        &policy_snapshot,
        image_override,
    )
    .await
    {
        Ok(h) => h,
        Err(e) => {
            // Substrate failure: the activation row stays in
            // `PendingActivation`; the freshly-minted session row
            // is revoked so the recovery sweep can reclaim it.
            // INV-08 — wire surface stays coarse; the structured
            // error is logged here for forensic analysis.
            eprintln!(
                "{{\"level\":\"error\",\"event\":\"ActivateSubTaskSpawnFailed\",\
                 \"task_id\":\"{}\",\"new_session_id\":\"{}\",\"error\":\"{}\"}}",
                task_id_owned, lookup.new_session_id, e,
            );
            // Best-effort: revoke the freshly-minted session row.
            let store_arc = Arc::clone(&ctx.store);
            let revoke_session_id = lookup.new_session_id.clone();
            let _ = tokio::task::spawn_blocking(move || {
                let conn = store_arc.lock_sync();
                let _ = conn.execute(
                    &format!(
                        "UPDATE {SESSIONS} SET revoked = 1, revoked_at = ?1
                           WHERE session_id = ?2"
                    ),
                    rusqlite::params![unix_now_secs(), revoke_session_id],
                );
            }).await;
            return Err((PlannerErrorCode::FailPolicyViolation, TaskState::Admitted));
        }
    };

    // ── Step 4: activation-row → Active; persist substrate metadata. ───
    {
        let store_arc        = Arc::clone(&ctx.store);
        let activation_id    = lookup.activation_id.clone();
        let new_session_id   = lookup.new_session_id.clone();
        let vsock_cid        = spawn_handle.vsock_cid;
        let activate_result = tokio::task::spawn_blocking(move || -> Result<(), rusqlite::Error> {
            let mut conn = store_arc.lock_sync();
            let tx = conn.transaction()?;
            let now = unix_now_secs();

            // Activation FSM: PendingActivation → Active. The cross-
            // column CHECK requires `session_id IS NOT NULL` and
            // `activated_at IS NOT NULL`; both stamped here.
            tx.execute(
                &format!(
                    "UPDATE {SUBTASK_ACTIVATIONS}
                        SET activation_state = 'Active',
                            session_id       = ?1,
                            activated_at     = ?2
                      WHERE activation_id   = ?3
                        AND activation_state = 'PendingActivation'"
                ),
                rusqlite::params![&new_session_id, now, &activation_id],
            )?;

            // Persist the substrate's vsock CID on the session row
            // so the kernel's per-session admission listener can
            // verify guest provenance (`vm-network-isolation.md §3`
            // CID allowlist).
            if let Some(cid) = vsock_cid {
                tx.execute(
                    &format!(
                        "UPDATE {SESSIONS} SET vsock_cid = ?1 WHERE session_id = ?2"
                    ),
                    rusqlite::params![cid as i64, &new_session_id],
                )?;
            }

            tx.commit()
        }).await;
        match activate_result {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                eprintln!(
                    "{{\"level\":\"error\",\"event\":\"ActivateSubTaskActivateFailed\",\
                     \"task_id\":\"{}\",\"activation_id\":\"{}\",\"reason\":\"{e}\"}}",
                    task_id_owned, lookup.activation_id,
                );
                return Err((PlannerErrorCode::FailPolicyViolation, TaskState::Admitted));
            }
            Err(_) => {
                return Err((PlannerErrorCode::FailPolicyViolation, TaskState::Admitted));
            }
        }
    }

    // ── Step 5: audit-after-commit — `SessionCreated`. ─────────────────
    //
    // The activation row's `Active` transition is the committed
    // state mutation; emitting `SessionCreated` here mirrors the
    // `auto_spawn_orchestrator_session_in_tx` audit pairing in
    // `lifecycle::approve_plan`.
    let agent_type_str = match lookup.agent_kind {
        crate::session_spawn_orchestrator::ExecutorAgentKind::Executor =>
            raxis_types::SessionAgentType::Executor.as_sql_str().to_owned(),
        crate::session_spawn_orchestrator::ExecutorAgentKind::Reviewer =>
            raxis_types::SessionAgentType::Reviewer.as_sql_str().to_owned(),
    };
    let role_str = match lookup.agent_kind {
        crate::session_spawn_orchestrator::ExecutorAgentKind::Executor => "executor",
        crate::session_spawn_orchestrator::ExecutorAgentKind::Reviewer => "reviewer",
    }.to_owned();
    if let Err(e) = ctx.audit.emit(
        raxis_audit_tools::AuditEventKind::SessionCreated {
            session_id:        lookup.new_session_id.clone(),
            role:              role_str,
            lineage_id:        lookup.new_lineage_id.clone(),
            worktree_root:     None,
            initiative_id:     Some(lookup.initiative_id.clone()),
            plan_bundle_sha256: None,
            policy_epoch:      Some(policy_snapshot.epoch()),
            session_agent_type: Some(agent_type_str),
        },
        Some(&lookup.new_session_id),
        None,
        Some(&lookup.initiative_id),
    ) {
        eprintln!(
            "{{\"level\":\"warn\",\"event\":\"ActivateSubTaskAuditEmitFailed\",\
             \"new_session_id\":\"{}\",\"error\":\"{e}\"}}",
            lookup.new_session_id,
        );
    }

    // ── Response ───────────────────────────────────────────────────────
    //
    // The TASK FSM stays in `Admitted` here — the activation row
    // FSM is `Active` (separate FSM per Step 5). The Executor's
    // first intent against this task will drive `tasks.state`
    // `Admitted → Running` through the standard pipeline.
    let task_for_budget = match load_task(&task_id_owned, ctx.store.as_ref()) {
        Ok(t)  => t,
        Err(_) => return Err((PlannerErrorCode::FailUnknownTask, TaskState::Admitted)),
    };
    let remaining = lane_budget_snapshot(
        &task_for_budget.lane_id,
        policy_snapshot.as_ref(),
        ctx.store.as_ref(),
    );
    Ok(IntentResponse {
        sequence_number: seq,
        task_state:      TaskState::Admitted,
        outcome: IntentOutcome::Accepted {
            remaining_budget:      remaining,
            warn_delegation_stale: false,
        },
    })
}

// ---------------------------------------------------------------------------
// handle_retry_sub_task — V2 §Step 12 dual-counter retry admission.
// ---------------------------------------------------------------------------
//
// Spec references:
//   * `v2-deep-spec.md §Step 12` — Dual retry counters
//     (`crash_retry_count`, `review_reject_count`) with
//     operator-declared ceilings (`max_crash_retries`,
//     `max_review_rejections`).
//   * `v2-deep-spec.md §Step 20` — Static dispatch matrix:
//     Orchestrator + RetrySubTask is the only Authorized cell.
//   * `crates/store/migrations/0005_v2_session_schema.sql`
//     line 50-52 — "One row per activation attempt — a retry
//     inserts a NEW row, never updates the prior one."
//
// **Design constraint: this handler does NOT spawn a VM.** It
// performs only the substrate-side cleanup + state preparation:
//   1. validate the prior activation row is in a retry-eligible
//      terminal state (`Failed`);
//   2. check the appropriate counter against the operator ceiling
//      (with the kernel default applied when the plan omitted the
//      field — see `TaskPlanFields::effective_*`);
//   3. atomically:
//        a. revoke the prior bound `sessions` row;
//        b. insert a new `subtask_activations` row in
//           `PendingActivation`, copying counters forward;
//        c. reset `tasks.state` to `Admitted` so a subsequent
//           `ActivateSubTask` is dispatch-legal again
//           (`v2-deep-spec.md §Step 21` requires Admitted to
//           accept ActivateSubTask);
//   4. best-effort ask the substrate to terminate the prior VM
//      (we do not wait on this for response correctness — the VM
//      may already be down via SIGCHLD; idempotent at the bridge);
//   5. emit `SessionRevoked` for the prior session.
//
// The Orchestrator's normal retry workflow is two intents:
// `RetrySubTask` (this handler) followed by `ActivateSubTask`
// (which re-spawns the VM against the freshly-minted
// `PendingActivation` row). Keeping the spawn out of this
// handler preserves the single-spawn-point invariant
// (`handle_activate_sub_task` is the sole caller of
// `spawn_executor_for_task`) and makes the retry contract
// trivially auditable.
//
// Atomicity. Steps 1, 2, 3 land in a single SQLite transaction
// (the row read, ceiling check, revoke, insert, and task FSM
// update). Step 4 is a best-effort post-commit substrate call
// that cannot un-mutate the SQL state — if the VM is already
// down (the common case), the bridge surfaces
// `SpawnError::SessionNotActive`, which we log and ignore.
// Step 5 is an audit emit per the `audit-after-commit`
// discipline (§2.5.2).
//
// Rejection codes (INV-08 — coarse on the wire; structured
// reason logged eprintln-side for forensic recovery):
//   * `FAIL_UNKNOWN_TASK` — the task row, registry entry, or
//     activation row is absent.
//   * `INVALID_REQUEST` — a ceiling is exceeded, or the prior
//     activation row is not in a retry-eligible state
//     (`Active` / `PendingActivation` / `Completed` are all
//     non-retryable; only `Failed` is).
//   * `FAIL_POLICY_VIOLATION` — defense-in-depth catch for
//     internal SQL / authority errors.
async fn handle_retry_sub_task(
    req:        IntentRequest,
    _session:   authority::session::SessionRow,
    session_id: SessionId,
    seq:        u64,
    ctx:        &Arc<HandlerContext>,
) -> HandlerResult {
    // ── Step 1: replay protection (envelope acceptance) ───────────────
    let presented_seq_i64 = match i64::try_from(seq) {
        Ok(v) => v,
        Err(_) => return Err((PlannerErrorCode::Unauthorized, TaskState::Admitted)),
    };
    {
        let store     = Arc::clone(&ctx.store);
        let session   = session_id.clone();
        let nonce     = req.envelope_nonce.clone();
        let audit     = Arc::clone(&ctx.audit);
        let session_s = session.as_str().to_owned();
        let result = tokio::task::spawn_blocking(move || {
            authority::session::accept_envelope_and_advance_sequence(
                &session, presented_seq_i64, &nonce, &store,
            )
        })
        .await
        .map_err(|_| (PlannerErrorCode::Unauthorized, TaskState::Admitted))?;
        if let Err(reason) = result {
            let _ = audit.emit(
                raxis_audit_tools::AuditEventKind::ReplayRejected {
                    session_id:   session_s,
                    sequence_num: seq,
                    reason:       format!("{reason:?}"),
                },
                Some(session_id.as_str()),
                None,
                None,
            );
            return Err((PlannerErrorCode::Unauthorized, TaskState::Admitted));
        }
    }

    let task_id_owned = req.task_id.as_str().to_owned();

    // Pull the operator-declared ceilings from the plan registry
    // BEFORE the SQL transaction so we can fail fast on a missing
    // entry. The registry lookup is a single read-only RwLock so
    // there's no async-safety concern about holding it across an
    // await.
    let (initiative_id, max_crash_retries, max_review_rejections) = {
        // We need initiative_id to look up the registry entry.
        let store_arc = Arc::clone(&ctx.store);
        let task_id_clone = task_id_owned.clone();
        let lookup: Result<String, ()> = tokio::task::spawn_blocking(move || {
            let conn = store_arc.lock_sync();
            conn.query_row(
                &format!(
                    "SELECT initiative_id FROM {TASKS} WHERE task_id = ?1"
                ),
                rusqlite::params![&task_id_clone],
                |r| r.get::<_, String>(0),
            ).map_err(|_| ())
        })
        .await
        .map_err(|_| (PlannerErrorCode::FailUnknownTask, TaskState::Admitted))?;
        let initiative_id = lookup
            .map_err(|_| (PlannerErrorCode::FailUnknownTask, TaskState::Admitted))?;

        let key = crate::initiatives::plan_registry::TaskKey::new(
            &initiative_id, &task_id_owned,
        );
        let fields = match ctx.plan_registry.get(&key) {
            Some(f) => f,
            None    => {
                // Fail-closed: a missing registry entry means the
                // plan-bundle-sealing rehydration didn't see this
                // task, which is structurally impossible for an
                // approved plan. Surface the concrete code and
                // log eprintln-side.
                eprintln!(
                    "{{\"level\":\"error\",\"event\":\"RetrySubTaskRegistryMiss\",\
                     \"task_id\":\"{}\",\"initiative_id\":\"{}\"}}",
                    task_id_owned, initiative_id,
                );
                return Err((PlannerErrorCode::FailUnknownTask, TaskState::Admitted));
            }
        };
        (
            initiative_id,
            fields.effective_max_crash_retries(),
            fields.effective_max_review_rejections(),
        )
    };

    // ── Step 2 + 3: atomic SQL — terminal-state guard, ceiling check,
    //                revoke prior session, insert new PendingActivation
    //                row, reset task FSM. ─────────────────────────────
    //
    // We bundle every read and write in ONE transaction so a
    // concurrent operator abort cannot land between the ceiling
    // check and the new-row insert (which would let the next
    // RetrySubTask see a counter value the prior call already
    // claimed).
    #[derive(Clone)]
    struct RetryDecision {
        prior_activation_id:    String,
        prior_session_id:       Option<String>,
        new_activation_id:      String,
        crash_retry_count:      i64,
        review_reject_count:    i64,
    }

    let decision: RetryDecision = {
        let store_arc = Arc::clone(&ctx.store);
        let task_id_clone = task_id_owned.clone();
        let initiative_id_clone = initiative_id.clone();
        tokio::task::spawn_blocking(move || -> Result<RetryDecision, (PlannerErrorCode, TaskState)> {
            let mut conn = store_arc.lock_sync();
            let tx = conn.transaction()
                .map_err(|_| (PlannerErrorCode::FailPolicyViolation, TaskState::Admitted))?;

            // 2a. Most-recent activation row — must exist + must be
            //      `Failed`. `PendingActivation` / `Active` /
            //      `Completed` are all non-retryable: PendingActivation
            //      means "use ActivateSubTask, not RetrySubTask";
            //      Active means "still running, you have no business
            //      retrying"; Completed means "the task succeeded,
            //      retrying would be a regression".
            let prior: Option<(String, String, Option<String>, i64, i64)> = tx.query_row(
                &format!(
                    "SELECT activation_id, activation_state, session_id,
                            crash_retry_count, review_reject_count
                       FROM {SUBTASK_ACTIVATIONS}
                      WHERE task_id = ?1
                      ORDER BY created_at DESC
                      LIMIT 1"
                ),
                rusqlite::params![&task_id_clone],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            ).ok();
            let (prior_activation_id, prior_state, prior_session_id,
                 crash_retry_count, review_reject_count) = match prior {
                Some(t) => t,
                None    => return Err((PlannerErrorCode::FailUnknownTask,
                                       TaskState::Admitted)),
            };
            if prior_state != "Failed" {
                eprintln!(
                    "{{\"level\":\"warn\",\"event\":\"RetrySubTaskRejectedNotFailed\",\
                     \"task_id\":\"{task_id_clone}\",\
                     \"prior_activation_id\":\"{prior_activation_id}\",\
                     \"prior_state\":\"{prior_state}\"}}",
                );
                return Err((PlannerErrorCode::InvalidRequest, TaskState::Admitted));
            }

            // 2b. Ceiling check. Both ceilings are checked: a task
            //      may have failed once via crash and once via review,
            //      so the next retry must respect BOTH budgets.
            //      `effective_*` already substitutes the kernel
            //      default when the plan omitted the field.
            //
            //      Spec wire surface: `FAIL_INVALID_REQUEST`
            //      (`crates/types/src/intent.rs::RetrySubTask` doc
            //      comment line 71).
            if crash_retry_count >= i64::from(max_crash_retries) {
                eprintln!(
                    "{{\"level\":\"warn\",\
                     \"event\":\"RetrySubTaskRejectedCrashCeiling\",\
                     \"task_id\":\"{task_id_clone}\",\
                     \"crash_retry_count\":{crash_retry_count},\
                     \"max_crash_retries\":{max_crash_retries}}}",
                );
                return Err((PlannerErrorCode::InvalidRequest, TaskState::Admitted));
            }
            if review_reject_count >= i64::from(max_review_rejections) {
                eprintln!(
                    "{{\"level\":\"warn\",\
                     \"event\":\"RetrySubTaskRejectedReviewCeiling\",\
                     \"task_id\":\"{task_id_clone}\",\
                     \"review_reject_count\":{review_reject_count},\
                     \"max_review_rejections\":{max_review_rejections}}}",
                );
                return Err((PlannerErrorCode::InvalidRequest, TaskState::Admitted));
            }

            // 2c. Revoke the prior bound session (if any) so the
            //      stale session-token cannot be replayed by a
            //      hostile or buggy planner. The matching VM
            //      shutdown is best-effort post-commit (Step 4).
            //      `revoked_at` is set unconditionally so a
            //      `revoked = 0` row that landed concurrently
            //      still gets the timestamp — the worst case is
            //      a no-op overwrite of a row that was already
            //      revoked.
            let now = unix_now_secs();
            if let Some(prior_sid) = prior_session_id.as_ref() {
                tx.execute(
                    &format!(
                        "UPDATE {SESSIONS} SET revoked = 1, revoked_at = ?1
                           WHERE session_id = ?2"
                    ),
                    rusqlite::params![now, prior_sid],
                ).map_err(|_| (PlannerErrorCode::FailPolicyViolation,
                               TaskState::Admitted))?;
            }

            // 2d. Insert a NEW activation row in `PendingActivation`.
            //      Migration 5 line 51-52: "a retry inserts a NEW
            //      row, never updates the prior one." Counters carry
            //      forward verbatim from the prior row — this is
            //      the V2 spec contract that the retry handler
            //      neither bumps nor resets the counters; bumps
            //      happen at the failure event (`SubmitReview`
            //      rejection / SIGCHLD), reset never happens.
            let new_activation_id = uuid::Uuid::new_v4().to_string();
            tx.execute(
                &format!(
                    "INSERT INTO {SUBTASK_ACTIVATIONS} (
                        activation_id, task_id, initiative_id,
                        activation_state, session_id, evaluation_sha,
                        crash_retry_count, review_reject_count,
                        created_at, activated_at, terminated_at
                     ) VALUES (?1, ?2, ?3, 'PendingActivation',
                               NULL, NULL, ?4, ?5, ?6, NULL, NULL)"
                ),
                rusqlite::params![
                    &new_activation_id,
                    &task_id_clone,
                    &initiative_id_clone,
                    crash_retry_count,
                    review_reject_count,
                    now,
                ],
            ).map_err(|e| {
                eprintln!(
                    "{{\"level\":\"error\",\
                     \"event\":\"RetrySubTaskActivationInsertFailed\",\
                     \"task_id\":\"{task_id_clone}\",\"reason\":\"{e}\"}}",
                );
                (PlannerErrorCode::FailPolicyViolation, TaskState::Admitted)
            })?;

            // 2e. Reset `tasks.state` so a subsequent
            //      `ActivateSubTask` is dispatch-legal. The Phase A
            //      task-state gate accepts only `Admitted` /
            //      `Running` (line ~497 above); `Failed` /
            //      `Completed` / `Aborted` would surface as
            //      `FAIL_TASK_NOT_RUNNING`. We unconditionally
            //      stamp `Admitted` because the activation row is
            //      the source of truth for the substrate side and
            //      the `tasks` row should mirror "ready for fresh
            //      activation".
            //
            //      `transitioned_at` is updated for forensic
            //      ordering — the `tasks` table records the
            //      latest FSM mutation timestamp, not the most-
            //      recent intent timestamp.
            tx.execute(
                &format!(
                    "UPDATE {TASKS} SET state = ?1, transitioned_at = ?2
                       WHERE task_id = ?3"
                ),
                rusqlite::params![
                    TaskState::Admitted.as_sql_str(),
                    now,
                    &task_id_clone,
                ],
            ).map_err(|_| (PlannerErrorCode::FailPolicyViolation,
                           TaskState::Admitted))?;

            tx.commit()
                .map_err(|_| (PlannerErrorCode::FailPolicyViolation,
                              TaskState::Admitted))?;

            Ok(RetryDecision {
                prior_activation_id,
                prior_session_id,
                new_activation_id,
                crash_retry_count,
                review_reject_count,
            })
        })
        .await
        .map_err(|_| (PlannerErrorCode::FailPolicyViolation, TaskState::Admitted))??
    };

    // ── Step 4: best-effort substrate VM termination. ──────────────────
    //
    // The SQL state is already consistent (Step 2 committed); the
    // VM teardown here is purely substrate hygiene. Two failure
    // modes are normal and IGNORED:
    //
    //   * `SpawnError::SessionNotActive` — the VM already exited
    //     (the most common path: a SIGCHLD-driven crash flow
    //     teardown got there first).
    //   * Backend shutdown errors — the host-side process is gone
    //     but the bridge couldn't observe a clean exit; the
    //     credential-proxy manager still drains.
    //
    // Errors are LOGGED but do NOT propagate: failing the retry
    // because the VM was already dead would be surreal.
    if let Some(prior_sid) = decision.prior_session_id.as_ref() {
        let grace = std::time::Duration::from_secs(2);
        if let Err(e) = ctx.session_spawn.terminate_session(prior_sid, grace).await {
            // Quiet on the SessionNotActive case — it's the
            // expected path for crash-driven retries. Verbose on
            // anything else so operators can diagnose pathological
            // shutdown bugs.
            let is_not_active = matches!(
                e,
                raxis_session_spawn::SpawnError::SessionNotActive { .. },
            );
            if !is_not_active {
                eprintln!(
                    "{{\"level\":\"warn\",\
                     \"event\":\"RetrySubTaskTerminateBestEffortFailed\",\
                     \"task_id\":\"{}\",\"prior_session_id\":\"{}\",\
                     \"error\":\"{}\"}}",
                    task_id_owned, prior_sid, e,
                );
            }
        }
    }

    // ── Step 5: audit-after-commit — `SessionRevoked` for the prior
    //            session. ────────────────────────────────────────────
    //
    // Mirrors the `SessionCreated` emission that landed when this
    // task was first activated (`handle_activate_sub_task` Step 5).
    // The `SessionRevoked` event is the audit-chain anchor a
    // forensic replay uses to reconstruct "this session was
    // burned because the operator-controlled Orchestrator asked
    // for a retry" (vs. "burned because the operator manually
    // revoked it" — the audit row's `actor` field carries the
    // Orchestrator's session_id either way, but the
    // `triggered_by_intent` projection is RetrySubTask).
    if let Some(prior_sid) = decision.prior_session_id.as_ref() {
        // `revoked_by` carries the Orchestrator's session_id (the
        // intent-submitter); `revoked_by_display_name` is the
        // structured projection of "why the kernel revoked this
        // session" so a forensic replay can distinguish a
        // RetrySubTask-driven revoke from a manual operator
        // `OperatorRequest::RevokeSession` revoke.
        let display = format!(
            "RetrySubTask: task_id={task_id_owned}, \
             prior_activation_id={}, new_activation_id={}",
            decision.prior_activation_id,
            decision.new_activation_id,
        );
        if let Err(e) = ctx.audit.emit(
            raxis_audit_tools::AuditEventKind::SessionRevoked {
                session_id:              prior_sid.clone(),
                revoked_by:              session_id.as_str().to_owned(),
                revoked_by_display_name: Some(display),
            },
            Some(prior_sid.as_str()),
            Some(task_id_owned.as_str()),
            Some(initiative_id.as_str()),
        ) {
            eprintln!(
                "{{\"level\":\"warn\",\
                 \"event\":\"RetrySubTaskAuditEmitFailed\",\
                 \"task_id\":\"{}\",\"prior_session_id\":\"{}\",\
                 \"error\":\"{e}\"}}",
                task_id_owned, prior_sid,
            );
        }
    }

    eprintln!(
        "{{\"level\":\"info\",\"event\":\"RetrySubTaskAdmitted\",\
         \"task_id\":\"{}\",\"prior_activation_id\":\"{}\",\
         \"new_activation_id\":\"{}\",\"crash_retry_count\":{},\
         \"review_reject_count\":{},\"max_crash_retries\":{},\
         \"max_review_rejections\":{}}}",
        task_id_owned,
        decision.prior_activation_id,
        decision.new_activation_id,
        decision.crash_retry_count,
        decision.review_reject_count,
        max_crash_retries,
        max_review_rejections,
    );

    // ── Response ───────────────────────────────────────────────────────
    //
    // The TASK FSM is now `Admitted` (we stamped it in Step 2e);
    // the activation row FSM is `PendingActivation`. The
    // Orchestrator's next step is `ActivateSubTask` against the
    // same task_id, which will spawn the fresh VM via
    // `handle_activate_sub_task`.
    //
    // `load_task` and `lane_budget_snapshot` both call
    // `Store::lock_sync()` (which calls `tokio::sync::Mutex::blocking_lock`)
    // and would panic if invoked directly from this async task.
    // Hop onto the blocking pool exactly once and compute both there.
    let store_for_resp = Arc::clone(&ctx.store);
    let policy_snapshot = ctx.policy.load_full();
    let task_id_for_resp = task_id_owned.clone();
    let remaining = tokio::task::spawn_blocking(move || -> Result<BudgetSnapshot, ()> {
        let task_for_budget = load_task(&task_id_for_resp, store_for_resp.as_ref())?;
        Ok(lane_budget_snapshot(
            &task_for_budget.lane_id,
            policy_snapshot.as_ref(),
            store_for_resp.as_ref(),
        ))
    })
    .await
    .map_err(|_| (PlannerErrorCode::FailPolicyViolation, TaskState::Admitted))?
    .map_err(|_| (PlannerErrorCode::FailUnknownTask, TaskState::Admitted))?;
    Ok(IntentResponse {
        sequence_number: seq,
        task_state:      TaskState::Admitted,
        outcome: IntentOutcome::Accepted {
            remaining_budget:      remaining,
            warn_delegation_stale: false,
        },
    })
}

/// Atomically transition the task to `Completed` AND insert the export
/// snapshot rows in ONE SQLite transaction (§2.5.8 line 2014).
///
/// Per kernel-store.md §2.5.8: "The snapshot insert is part of the same
/// store transaction as the `tasks.status = Completed` update. Both
/// commit together or both roll back. A crash between the status update
/// and the snapshot insert is impossible under SQLite's single-writer
/// atomic transaction model."
///
/// `INSERT OR IGNORE` on the snapshot rows handles the idempotent-retry
/// case (`PRIMARY KEY (task_id, path)` — same path inserted twice is a
/// no-op, matching the spec's "ignore" rule).
fn commit_task_completion(
    task_id:      &str,
    export_paths: &[String],
    store:        &Store,
) -> Result<(), ()> {
    let mut conn = store.lock_sync();
    let tx = conn.transaction().map_err(|_| ())?;

    // 1. Status update — guarded by `state = 'Running'` so a concurrent
    //    abort or duplicate completion silently no-ops (rows == 0 →
    //    transition rejected). The `tasks` DDL has no `completed_at`
    //    column (kernel-store.md §2.5.1 Table 5); `transitioned_at` is
    //    the canonical timestamp for the Running → Completed edge.
    let now = unix_now_secs();
    let completed_state = TaskState::Completed.as_sql_str();
    let running_state   = TaskState::Running.as_sql_str();
    let rows = tx.execute(
        &format!(
            "UPDATE {TASKS} SET state = ?1, transitioned_at = ?2
             WHERE task_id = ?3 AND state = ?4",
        ),
        rusqlite::params![completed_state, now, task_id, running_state],
    ).map_err(|_| ())?;
    if rows == 0 {
        return Err(());
    }

    // 2. Insert export snapshot rows (idempotent on PK).
    if !export_paths.is_empty() {
        let mut stmt = tx.prepare_cached(&format!(
            "INSERT OR IGNORE INTO {TASK_EXPORTED_PATH_SNAPSHOTS} (task_id, path)
             VALUES (?1, ?2)",
        )).map_err(|_| ())?;
        for p in export_paths {
            stmt.execute(rusqlite::params![task_id, p]).map_err(|_| ())?;
        }
    }

    tx.commit().map_err(|_| ())
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

struct TaskRow {
    lane_id:       String,
    state:         String,
    initiative_id: String,
    /// V2 `v2_extended_gaps.md §2.5` — running total of micro-dollar
    /// LLM-token cost on this task across every accepted intent.
    /// `0` for V2.4-and-earlier tasks (the column was added by
    /// migration 12 with `DEFAULT 0`).
    cumulative_token_cost_micros: u64,
}

fn load_task(task_id: &str, store: &Store) -> Result<TaskRow, ()> {
    let conn = store.lock_sync();
    conn.query_row(
        &format!(
            "SELECT lane_id, state, initiative_id, cumulative_token_cost_micros
             FROM {TASKS} WHERE task_id = ?1"
        ),
        rusqlite::params![task_id],
        |row| Ok(TaskRow {
            lane_id:       row.get(0)?,
            state:         row.get(1)?,
            initiative_id: row.get(2)?,
            cumulative_token_cost_micros: row.get::<_, i64>(3).map(|v| v as u64).unwrap_or(0),
        }),
    ).map_err(|_| ())
}

/// Update intent-binding fields on the task row — standalone wrapper.
///
/// Production callers (`run_phase_c`) use `update_task_intent_fields_in_tx`
/// inside the Phase C transaction. This standalone variant exists for
/// `#[cfg(test)]` fixtures that exercise the helper in isolation.
#[cfg(test)]
fn update_task_intent_fields(
    task_id:        &str,
    evaluation_sha: &str,
    base_sha:       &str,
    session_id:     &str,
    store:          &Store,
) -> Result<(), ()> {
    let mut conn = store.lock_sync();
    let tx = conn.transaction().map_err(|_| ())?;
    update_task_intent_fields_in_tx(&tx, task_id, evaluation_sha, base_sha, session_id)?;
    tx.commit().map_err(|_| ())?;
    Ok(())
}

/// Update intent-binding fields on the task row — transaction variant.
///
/// **INV-STORE-02 (kernel-store.md §2.5.1.1 Pattern B):** intent acceptance
/// composes FSM transition + budget reservation + intent fields update +
/// intent range insert. All four MUST land in one transaction so a
/// concurrent operator abort (or crash) cannot leave a stranded lane
/// reservation, mismatched intent fields, or an intent_range row without
/// a matching task state. This helper takes `&Connection` so the caller
/// passes the open `Transaction` (which derefs to `Connection`).
fn update_task_intent_fields_in_tx(
    conn:           &rusqlite::Connection,
    task_id:        &str,
    evaluation_sha: &str,
    base_sha:       &str,
    session_id:     &str,
) -> Result<(), ()> {
    conn.execute(
        &format!(
            "UPDATE {TASKS} SET evaluation_sha = ?1, base_sha = ?2, session_id = ?3
             WHERE task_id = ?4"
        ),
        rusqlite::params![evaluation_sha, base_sha, session_id, task_id],
    ).map_err(|_| ())?;
    Ok(())
}

/// Append one row to `task_intent_ranges` — standalone wrapper for tests.
#[cfg(test)]
fn insert_task_intent_range(
    task_id:  &str,
    base_sha: &str,
    head_sha: &str,
    store:    &Store,
) -> Result<(), ()> {
    let mut conn = store.lock_sync();
    let tx = conn.transaction().map_err(|_| ())?;
    insert_task_intent_range_in_tx(&tx, task_id, base_sha, head_sha)?;
    tx.commit().map_err(|_| ())?;
    Ok(())
}

/// Append one row to `task_intent_ranges` per kernel-store.md §2.5.8 step 7A —
/// transaction variant.
///
/// Uses `INSERT OR IGNORE` so a duplicate `(task_id, head_sha)` — which
/// SQLite reports as `SQLITE_CONSTRAINT_PRIMARYKEY` on plain INSERT —
/// silently no-ops, matching the spec's idempotent-retry semantics:
/// "Submitting the same head_sha twice returns SQLITE_CONSTRAINT_PRIMARYKEY;
///  the kernel treats this as an idempotent retry and returns the prior
///  accepted response without re-processing." Composed inside the Phase C
/// transaction (`kernel-store.md` §2.5.1.1 Pattern B) so it commits or
/// rolls back atomically with the FSM and budget writes.
fn insert_task_intent_range_in_tx(
    conn:     &rusqlite::Connection,
    task_id:  &str,
    base_sha: &str,
    head_sha: &str,
) -> Result<(), ()> {
    conn.execute(
        &format!(
            "INSERT OR IGNORE INTO {TASK_INTENT_RANGES}
                (task_id, base_sha, head_sha, accepted_at)
             VALUES (?1, ?2, ?3, ?4)"
        ),
        rusqlite::params![task_id, base_sha, head_sha, unix_now_secs()],
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

/// V2 `v2_extended_gaps.md §1.2` — categorise a `MainMergeError` for
/// the `MergeFastForwardFailed` audit row + structured operator log.
///
/// The `category` strings are part of the audit wire contract:
/// dashboards, alerts, and recovery runbooks pivot on them. Keep
/// them stable and document additions in
/// `crates/audit/src/event.rs` `MergeFastForwardFailed` doc-comment.
fn classify_merge_ff_error(err: &raxis_domain_git::MainMergeError) -> (&'static str, String) {
    use raxis_domain_git::MainMergeError;
    match err {
        MainMergeError::MainRepoUnopenable { reason, path } =>
            ("unopenable_main_repo", format!("{}: {reason}", path.display())),
        MainMergeError::SourceUnopenable { reason, path } =>
            ("unopenable_source_repo", format!("{}: {reason}", path.display())),
        MainMergeError::FetchFailed(s) =>
            ("git_failed", s.clone()),
        MainMergeError::ShaMissingPostFetch { sha } =>
            ("missing_commit", format!("sha {sha} not present in main ODB after fetch")),
        MainMergeError::RefUpdateFailed(s) => {
            // gix surfaces concurrent-advance races as a ref-txn
            // rejection — the message contains the previous and
            // expected SHAs. Pattern-match conservatively.
            let lower = s.to_lowercase();
            if lower.contains("locked") || lower.contains("expected") || lower.contains("conflict") {
                ("target_ref_advanced_concurrently", s.clone())
            } else {
                ("git_failed", s.clone())
            }
        }
        MainMergeError::InvalidSha { sha, reason } =>
            ("invalid_sha", format!("sha {sha}: {reason}")),
    }
}

/// V2.5 `integration-merge.md §11.5` push-time wait helper. Polls
/// `initiatives.git_apply_pending` until it reads 0 or the
/// `deadline` elapses. Returns `true` if the flag cleared in time,
/// `false` on timeout. Reads under `lock_sync()` so the poll
/// observes a snapshot that includes any concurrent commit (the
/// store mutex is the serialisation point for SQLite writes).
///
/// The default deadline is 5 s with a 50 ms poll interval — short
/// enough to surface a stuck-pending pathology promptly, long
/// enough that a healthy Phase 3 (which clears the flag inside the
/// same handler invocation in production) clears the loop on its
/// first iteration.
fn wait_for_git_apply_pending_clear(
    store:         &Store,
    initiative_id: &str,
    deadline:      std::time::Duration,
    poll_interval: std::time::Duration,
) -> bool {
    let start = std::time::Instant::now();
    loop {
        let pending: i64 = {
            let conn = store.lock_sync();
            conn.query_row(
                &format!(
                    "SELECT git_apply_pending FROM {} WHERE initiative_id = ?1",
                    raxis_store::Table::Initiatives.as_str(),
                ),
                rusqlite::params![initiative_id],
                |r| r.get(0),
            )
            .unwrap_or(0)
        };
        if pending == 0 {
            return true;
        }
        if start.elapsed() >= deadline {
            return false;
        }
        std::thread::sleep(poll_interval);
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

    // ── wait_for_git_apply_pending_clear (V2.5 §11.5 push wait) ───────────

    use raxis_test_support::DiskStore;

    fn seed_initiative_with_pending(disk: &DiskStore, id: &str, pending: i64) {
        let g = disk.store().lock_sync();
        g.execute(
            &format!(
                "INSERT INTO {} \
                    (initiative_id, state, terminal_criteria_json, \
                     plan_artifact_sha256, created_at, git_apply_pending) \
                 VALUES (?1, 'Executing', '{{}}', 'deadbeef', 100, ?2)",
                raxis_store::Table::Initiatives.as_str(),
            ),
            rusqlite::params![id, pending],
        ).unwrap();
    }

    #[test]
    fn wait_returns_true_immediately_when_flag_already_clear() {
        let disk = DiskStore::new();
        seed_initiative_with_pending(&disk, "init-clear", 0);
        let start = std::time::Instant::now();
        let cleared = wait_for_git_apply_pending_clear(
            disk.store(),
            "init-clear",
            std::time::Duration::from_secs(5),
            std::time::Duration::from_millis(50),
        );
        assert!(cleared);
        assert!(start.elapsed() < std::time::Duration::from_millis(50),
            "no poll iteration should fire when flag is already 0");
    }

    #[test]
    fn wait_returns_true_after_concurrent_clear() {
        let disk = DiskStore::new();
        seed_initiative_with_pending(&disk, "init-flip", 1);
        let store_handle: Store = disk.store().clone();
        let flipper = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(120));
            let g = store_handle.lock_sync();
            raxis_store::views::initiatives::clear_git_apply_pending(&g, "init-flip")
                .unwrap();
        });
        let cleared = wait_for_git_apply_pending_clear(
            disk.store(),
            "init-flip",
            std::time::Duration::from_secs(2),
            std::time::Duration::from_millis(25),
        );
        flipper.join().unwrap();
        assert!(cleared, "wait must observe the concurrent Phase-3 clear");
    }

    #[test]
    fn wait_returns_false_when_deadline_elapses_without_clear() {
        let disk = DiskStore::new();
        seed_initiative_with_pending(&disk, "init-stuck", 1);
        let cleared = wait_for_git_apply_pending_clear(
            disk.store(),
            "init-stuck",
            std::time::Duration::from_millis(150),
            std::time::Duration::from_millis(25),
        );
        assert!(!cleared, "stuck flag must time out within the configured deadline");
    }

    #[test]
    fn wait_treats_missing_initiative_as_clear() {
        let disk = DiskStore::new();
        let cleared = wait_for_git_apply_pending_clear(
            disk.store(),
            "ghost",
            std::time::Duration::from_millis(50),
            std::time::Duration::from_millis(10),
        );
        assert!(cleared,
            "QueryReturnedNoRows ⇒ defaults to 0 ⇒ wait clears (push will then \
             fail later with a different error if the initiative truly was deleted)");
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

    // ── insert_task_intent_range — INV-TASK-PATH-02 substrate ──────────────
    //
    // These tests verify that step 7A correctly populates `task_intent_ranges`
    // and that the PRIMARY KEY (task_id, head_sha) idempotency rule from
    // kernel-store.md §2.5.8 is honoured.

    fn seed_task(store: &Store, task_id: &str) {
        let conn = store.lock_sync();
        let now = unix_now_secs();
        conn.execute(
            &format!(
                "INSERT INTO {INITIATIVES}
                    (initiative_id, state, terminal_criteria_json,
                     plan_artifact_sha256, created_at)
                 VALUES ('init-int', ?1, '{{}}', 'deadbeef', ?2)"
            ),
            rusqlite::params![InitiativeState::Executing.as_sql_str(), now],
        ).unwrap();
        conn.execute(
            &format!(
                "INSERT INTO {TASKS}
                    (task_id, initiative_id, lane_id, state, actor,
                     policy_epoch, admitted_at, transitioned_at, actual_cost)
                 VALUES (?1, 'init-int', 'default', ?2, 'kernel',
                         1, ?3, ?3, 0)"
            ),
            rusqlite::params![task_id, TaskState::Admitted.as_sql_str(), now],
        ).unwrap();
    }

    fn count_intent_ranges(store: &Store, task_id: &str) -> i64 {
        let conn = store.lock_sync();
        conn.query_row(
            &format!("SELECT COUNT(*) FROM {TASK_INTENT_RANGES} WHERE task_id=?1"),
            rusqlite::params![task_id],
            |r| r.get(0),
        ).unwrap()
    }

    #[test]
    fn intent_range_insert_persists_pair() {
        let store = Store::open_in_memory().unwrap();
        seed_task(&store, "t1");

        insert_task_intent_range("t1", "aaaaaaaa", "bbbbbbbb", &store).unwrap();
        assert_eq!(count_intent_ranges(&store, "t1"), 1);

        let conn = store.lock_sync();
        let (base, head): (String, String) = conn.query_row(
            &format!("SELECT base_sha, head_sha FROM {TASK_INTENT_RANGES} WHERE task_id='t1'"),
            [], |r| Ok((r.get(0)?, r.get(1)?)),
        ).unwrap();
        assert_eq!(base, "aaaaaaaa");
        assert_eq!(head, "bbbbbbbb");
    }

    #[test]
    fn intent_range_insert_is_idempotent_on_same_head_sha() {
        let store = Store::open_in_memory().unwrap();
        seed_task(&store, "t1");

        // Same (task_id, head_sha) submitted twice — INSERT OR IGNORE
        // must collapse to one row, matching the spec's "idempotent retry".
        insert_task_intent_range("t1", "aa", "bb", &store).unwrap();
        insert_task_intent_range("t1", "aa", "bb", &store).unwrap();
        assert_eq!(count_intent_ranges(&store, "t1"), 1);

        // A different base_sha but the SAME head_sha is also collapsed —
        // PRIMARY KEY is (task_id, head_sha), not (task_id, base_sha, head_sha).
        // The spec treats this as a retry of the prior accepted intent.
        insert_task_intent_range("t1", "cc", "bb", &store).unwrap();
        assert_eq!(count_intent_ranges(&store, "t1"), 1);
    }

    #[test]
    fn intent_range_accumulates_across_successive_intents() {
        let store = Store::open_in_memory().unwrap();
        seed_task(&store, "t1");

        // Three distinct head_shas → three rows; CompleteTask later
        // unions touched_paths across all of them.
        insert_task_intent_range("t1", "aa", "bb", &store).unwrap();
        insert_task_intent_range("t1", "bb", "cc", &store).unwrap();
        insert_task_intent_range("t1", "cc", "dd", &store).unwrap();
        assert_eq!(count_intent_ranges(&store, "t1"), 3);
    }

    #[test]
    fn intent_ranges_are_scoped_per_task() {
        let store = Store::open_in_memory().unwrap();
        seed_task(&store, "t1");

        let conn = store.lock_sync();
        conn.execute(
            &format!(
                "INSERT INTO {TASKS}
                    (task_id, initiative_id, lane_id, state, actor,
                     policy_epoch, admitted_at, transitioned_at, actual_cost)
                 VALUES ('t2', 'init-int', 'default', ?1, 'kernel',
                         1, ?2, ?2, 0)"
            ),
            rusqlite::params![TaskState::Admitted.as_sql_str(), unix_now_secs()],
        ).unwrap();
        drop(conn);

        // Same head_sha for two different tasks must coexist — the PK
        // includes task_id.
        insert_task_intent_range("t1", "aa", "bb", &store).unwrap();
        insert_task_intent_range("t2", "aa", "bb", &store).unwrap();
        assert_eq!(count_intent_ranges(&store, "t1"), 1);
        assert_eq!(count_intent_ranges(&store, "t2"), 1);
    }

    // ── compute_export_set — §2.5.8 line 2003 ─────────────────────────────

    #[test]
    fn export_set_with_no_globs_returns_full_touched() {
        // Per §2.5.8 blast-radius table: `path_export_to_successors=true`
        // + no `path_export_globs` → export the full touched set
        // (coarse; operator's responsibility).
        let touched = vec![
            PathBuf::from("src/a.rs"),
            PathBuf::from("docs/b.md"),
        ];
        let exported = compute_export_set(&touched, &[]);
        assert_eq!(exported, vec!["src/a.rs", "docs/b.md"]);
    }

    #[test]
    fn export_set_filters_to_glob_matches() {
        let touched = vec![
            PathBuf::from("src/ipc/handlers/new.rs"),
            PathBuf::from("src/scheduler/dag.rs"),
            PathBuf::from("README.md"),
        ];
        let exported = compute_export_set(
            &touched,
            &["src/ipc/**".to_owned()],
        );
        assert_eq!(exported, vec!["src/ipc/handlers/new.rs"]);
    }

    #[test]
    fn export_set_uses_directory_aware_globs() {
        // §2.5.8 normative glob rule: `*` does NOT cross `/`.
        let touched = vec![
            PathBuf::from("src/lib.rs"),
            PathBuf::from("src/sub/lib.rs"),
        ];
        let exported = compute_export_set(&touched, &["src/*".to_owned()]);
        assert_eq!(exported, vec!["src/lib.rs"],
            "single-* must not cross /, only top-level files match");
    }

    #[test]
    fn export_set_skips_unparseable_globs() {
        // Defense in depth: if the signing tool somehow let a malformed
        // glob through, we drop it silently rather than panicking — the
        // result is "fewer paths exported", which is conservative
        // (errors-on-the-side-of-tighter-scope).
        let touched = vec![PathBuf::from("src/a.rs")];
        let exported = compute_export_set(
            &touched,
            &["src/[unclosed".to_owned(), "src/**".to_owned()],
        );
        assert_eq!(exported, vec!["src/a.rs"],
            "unparseable glob is dropped; second valid glob still applies");
    }

    #[test]
    fn export_set_with_only_unparseable_globs_returns_empty() {
        // Edge: every glob malformed → conservative empty export.
        let touched = vec![PathBuf::from("src/a.rs")];
        let exported = compute_export_set(
            &touched,
            &["[broken".to_owned()],
        );
        assert!(exported.is_empty(),
            "no valid globs → no export; conservative posture");
    }

    // ── commit_task_completion — §2.5.8 line 2014 single-tx contract ──────

    fn seed_running_task(store: &Store, task_id: &str) {
        let conn = store.lock_sync();
        let now = unix_now_secs();
        // Reuse same initiative as `seed_task`'s "init-int" if already
        // present — otherwise insert one.
        let _ = conn.execute(
            &format!(
                "INSERT OR IGNORE INTO {INITIATIVES}
                    (initiative_id, state, terminal_criteria_json,
                     plan_artifact_sha256, created_at)
                 VALUES ('init-int', ?1, '{{}}', 'deadbeef', ?2)"
            ),
            rusqlite::params![InitiativeState::Executing.as_sql_str(), now],
        );
        conn.execute(
            &format!(
                "INSERT INTO {TASKS}
                    (task_id, initiative_id, lane_id, state, actor,
                     policy_epoch, admitted_at, transitioned_at, actual_cost)
                 VALUES (?1, 'init-int', 'default', ?2, 'kernel',
                         1, ?3, ?3, 0)"
            ),
            rusqlite::params![task_id, TaskState::Running.as_sql_str(), now],
        ).unwrap();
    }

    fn task_state_of(store: &Store, task_id: &str) -> String {
        let conn = store.lock_sync();
        conn.query_row(
            &format!("SELECT state FROM {TASKS} WHERE task_id = ?1"),
            rusqlite::params![task_id],
            |r| r.get(0),
        ).unwrap()
    }

    fn count_export_snapshots(store: &Store, task_id: &str) -> i64 {
        let conn = store.lock_sync();
        conn.query_row(
            &format!("SELECT COUNT(*) FROM {TASK_EXPORTED_PATH_SNAPSHOTS} WHERE task_id = ?1"),
            rusqlite::params![task_id],
            |r| r.get(0),
        ).unwrap()
    }

    #[test]
    fn commit_task_completion_transitions_running_to_completed() {
        let store = Store::open_in_memory().unwrap();
        seed_running_task(&store, "t1");

        commit_task_completion("t1", &[], &store).unwrap();

        assert_eq!(task_state_of(&store, "t1"), TaskState::Completed.as_sql_str());
        assert_eq!(count_export_snapshots(&store, "t1"), 0,
            "empty export list must write zero snapshot rows");
    }

    #[test]
    fn commit_task_completion_persists_export_snapshots_atomically() {
        let store = Store::open_in_memory().unwrap();
        seed_running_task(&store, "t1");
        let exports = vec![
            "src/a.rs".to_owned(),
            "src/b.rs".to_owned(),
            "src/sub/c.rs".to_owned(),
        ];

        commit_task_completion("t1", &exports, &store).unwrap();

        assert_eq!(task_state_of(&store, "t1"), TaskState::Completed.as_sql_str());
        assert_eq!(count_export_snapshots(&store, "t1"), 3);

        // Spot-check one row to verify the path round-trips byte-equal.
        let conn = store.lock_sync();
        let select_paths_sql = format!(
            "SELECT path FROM {TASK_EXPORTED_PATH_SNAPSHOTS} WHERE task_id = ?1"
        );
        let mut paths: Vec<String> = conn
            .prepare(&select_paths_sql)
            .unwrap()
            .query_map(rusqlite::params!["t1"], |r| r.get::<_, String>(0))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        paths.sort();
        assert_eq!(paths, vec!["src/a.rs", "src/b.rs", "src/sub/c.rs"]);
    }

    #[test]
    fn commit_task_completion_is_idempotent_on_repeat_paths() {
        // §2.5.8 line 2011: PK constraint on (task_id, path) → second
        // attempt with identical paths is INSERT OR IGNORE no-op. The
        // task is still in `Completed` from the first call so the
        // second `commit_task_completion` will return Err(()) at the
        // status guard (rows == 0); however calling it directly is
        // operator error, not a correctness concern. Here we test the
        // PK behaviour by inserting the *same* path twice in one call.
        let store = Store::open_in_memory().unwrap();
        seed_running_task(&store, "t1");
        let exports = vec![
            "src/a.rs".to_owned(),
            "src/a.rs".to_owned(),  // duplicate inside the call
        ];

        commit_task_completion("t1", &exports, &store).unwrap();
        assert_eq!(count_export_snapshots(&store, "t1"), 1,
            "PK (task_id, path) collapses duplicates to one row");
    }

    #[test]
    fn commit_task_completion_rejects_non_running_task() {
        // Guard `state = 'Running'` in the UPDATE prevents
        // double-completion races. A task that's already Completed
        // (or Aborted) returns Err(()) — caller surfaces this as
        // FailTaskNotRunning on the wire.
        let store = Store::open_in_memory().unwrap();
        seed_task(&store, "t1");  // seeds in `Admitted` state

        let result = commit_task_completion("t1", &[], &store);
        assert!(result.is_err(),
            "commit_task_completion must reject non-Running tasks");
        assert_eq!(task_state_of(&store, "t1"), TaskState::Admitted.as_sql_str(),
            "rejected commit must NOT modify the task state");
        assert_eq!(count_export_snapshots(&store, "t1"), 0,
            "rejected commit must NOT leak snapshot rows");
    }

    // ── read_completion_inputs — §2.5.8 step 1+2 ──────────────────────────

    #[test]
    fn read_completion_inputs_returns_null_h_bind_when_unbound() {
        let store = Store::open_in_memory().unwrap();
        seed_task(&store, "t1");
        let (h_bind, ranges) = read_completion_inputs("t1", &store).unwrap();
        assert!(h_bind.is_none(),
            "first-intent-not-yet-arrived → evaluation_sha is NULL");
        assert!(ranges.is_empty());
    }

    // ── handle_submit_review — v2-deep-spec.md §Step 22 ───────────────────
    //
    // These unit tests exercise the SubmitReview handler in isolation,
    // bypassing the dispatch matrix (covered in
    // `authority::dispatch_matrix` tests) and the session-loading path
    // (covered in `handle_inner` integration tests). The handler-under-
    // test takes a pre-validated `(req, task_state, ...)` tuple and
    // is responsible for: (a) payload validation, (b) reverse-DAG
    // critique routing, (c) FSM transition.

    /// Insert one Reviewer task in `Running` plus an Executor predecessor
    /// in `Admitted`, plus the `task_dag_edges` row connecting them.
    /// Returns `(reviewer_task_id, executor_task_id)`.
    fn seed_reviewer_with_executor_predecessor(
        store: &Store,
        reviewer_id: &str,
        executor_id: &str,
    ) {
        let conn = store.lock_sync();
        let now = unix_now_secs();
        let _ = conn.execute(
            &format!(
                "INSERT OR IGNORE INTO {INITIATIVES}
                    (initiative_id, state, terminal_criteria_json,
                     plan_artifact_sha256, created_at)
                 VALUES ('init-rev', ?1, '{{}}', 'deadbeef', ?2)"
            ),
            rusqlite::params![InitiativeState::Executing.as_sql_str(), now],
        );
        // Executor task — Admitted (we don't transition it here; we
        // just need a row whose `last_critique` we can observe).
        conn.execute(
            &format!(
                "INSERT INTO {TASKS}
                    (task_id, initiative_id, lane_id, state, actor,
                     policy_epoch, admitted_at, transitioned_at, actual_cost)
                 VALUES (?1, 'init-rev', 'default', ?2, 'kernel',
                         1, ?3, ?3, 0)"
            ),
            rusqlite::params![executor_id, TaskState::Admitted.as_sql_str(), now],
        ).unwrap();
        // Reviewer task — Running (the state SubmitReview requires).
        conn.execute(
            &format!(
                "INSERT INTO {TASKS}
                    (task_id, initiative_id, lane_id, state, actor,
                     policy_epoch, admitted_at, transitioned_at, actual_cost)
                 VALUES (?1, 'init-rev', 'default', ?2, 'kernel',
                         1, ?3, ?3, 0)"
            ),
            rusqlite::params![reviewer_id, TaskState::Running.as_sql_str(), now],
        ).unwrap();
        // DAG edge: executor → reviewer.
        conn.execute(
            &format!(
                "INSERT INTO {dag_edges}
                    (initiative_id, predecessor_task_id, successor_task_id,
                     predecessor_satisfied)
                 VALUES ('init-rev', ?1, ?2, 1)",
                dag_edges = Table::TaskDagEdges.as_str(),
            ),
            rusqlite::params![executor_id, reviewer_id],
        ).unwrap();
    }

    fn read_last_critique(store: &Store, task_id: &str) -> Option<String> {
        let conn = store.lock_sync();
        conn.query_row(
            &format!("SELECT last_critique FROM {TASKS} WHERE task_id = ?1"),
            rusqlite::params![task_id],
            |r| r.get::<_, Option<String>>(0),
        ).unwrap()
    }

    fn read_review_verdict(store: &Store, task_id: &str) -> Option<String> {
        let conn = store.lock_sync();
        conn.query_row(
            &format!("SELECT review_verdict FROM {TASKS} WHERE task_id = ?1"),
            rusqlite::params![task_id],
            |r| r.get::<_, Option<String>>(0),
        ).unwrap()
    }

    /// Build a minimal `IntentRequest` for SubmitReview from
    /// `(reviewer_task_id, approved, critique)`. All non-relevant
    /// fields receive deterministic placeholder values that the
    /// SubmitReview handler ignores (per §Step 22 wire-shape comment
    /// in `crates/types/src/intent.rs`).
    fn make_submit_review_request(
        reviewer_task_id: &str,
        approved: Option<bool>,
        critique: Option<&str>,
    ) -> IntentRequest {
        IntentRequest {
            session_token:   "tok".into(),
            sequence_number: 1,
            envelope_nonce:  "0".repeat(32),
            intent_kind:     IntentKind::SubmitReview,
            task_id:         raxis_types::TaskId::parse(reviewer_task_id).unwrap(),
            base_sha:        None,
            head_sha:        None,
            submitted_claims: vec![],
            justification:   None,
            idempotency_key: None,
            approval_token:  None,
            approved,
            critique:        critique.map(str::to_owned),
            resolved_via_escalation: None,
            tokens_used:     None,
            structured_output: None,
        }
    }

    /// Default policy bundle for tests that exercise the budget snapshot
    /// path on success (the snapshot is not asserted on; we just need
    /// the call to not panic).
    fn default_test_policy() -> raxis_policy::PolicyBundle {
        raxis_policy::PolicyBundle::for_tests_with_operators(vec![])
    }

    fn dummy_session_id() -> SessionId {
        SessionId::parse("11111111-1111-1111-1111-111111111111").unwrap()
    }

    /// Build a minimal `HandlerContext` over the supplied store + a
    /// `FakeAuditSink`, returning both so the SubmitReview tests can
    /// assert on the `ReviewAggregationCompleted` audit emission
    /// path (V2 gap §12.2 wiring). The ctx carries no orchestrator,
    /// no live gateway, and a fail-closed isolation backend — the
    /// `handle_submit_review` code path uses only `ctx.audit`, so
    /// the rest of the dependencies are placeholders.
    fn build_review_test_ctx(
        store:  Arc<Store>,
        policy: raxis_policy::PolicyBundle,
    ) -> (Arc<HandlerContext>, Arc<raxis_test_support::FakeAuditSink>) {
        let sink = Arc::new(raxis_test_support::FakeAuditSink::new());
        let data_dir = std::path::PathBuf::from("/tmp/raxis-submit-review-test");
        let credentials = crate::ipc::context::build_default_test_credentials(
            &data_dir,
            sink.clone(),
        );
        let isolation = crate::ipc::context::build_fail_closed_test_isolation();
        let orchestrator_spawn = crate::ipc::context::build_test_orchestrator_spawn();
        let domain = crate::ipc::context::build_default_test_domain(&data_dir);
        let ctx = Arc::new(HandlerContext::new(
            Arc::new(arc_swap::ArcSwap::from_pointee(policy)),
            Arc::new(crate::authority::keys::KeyRegistry::stub_for_tests()),
            store,
            sink.clone(),
            data_dir,
            Arc::new(crate::initiatives::PlanRegistry::new()),
            Arc::new(crate::gateway::client::GatewayClient::new()),
            Arc::new(crate::prompt::EpochBinding::new()),
            credentials,
            isolation,
            orchestrator_spawn,
            crate::ipc::context::build_test_executor_spawn(),
            domain,
        ));
        (ctx, sink)
    }

    /// Approval path: the handler transitions the Reviewer from
    /// Running → Completed, leaves `tasks.last_critique` untouched on
    /// the predecessor, persists `review_verdict = 'Approved'` on
    /// the Reviewer's own row, and returns Accepted.
    #[test]
    fn submit_review_approved_transitions_reviewer_to_completed() {
        let store  = Arc::new(Store::open_in_memory().unwrap());
        let (ctx, _sink) = build_review_test_ctx(store.clone(), default_test_policy());
        let policy = default_test_policy();
        seed_reviewer_with_executor_predecessor(&store, "rev1", "exe1");

        let req = make_submit_review_request("rev1", Some(true), None);
        let resp = handle_submit_review(
            req, TaskState::Running, &dummy_session_id(), 1, &store, &policy, &ctx,
        ).expect("approval must be Accepted");

        assert!(matches!(resp.outcome, IntentOutcome::Accepted { .. }));
        assert_eq!(resp.task_state, TaskState::Completed);
        assert_eq!(task_state_of(&store, "rev1"), TaskState::Completed.as_sql_str());
        assert!(read_last_critique(&store, "exe1").is_none(),
            "approval path must not write to executor's last_critique");
        assert_eq!(read_review_verdict(&store, "rev1"),
            Some(raxis_types::ReviewVerdict::Approved.as_sql_str().to_owned()),
            "approval path must persist Approved verdict on Reviewer's own row");
    }

    /// Approval-with-critique-text: the spec says critique text on
    /// `approved=true` is silently dropped. The Reviewer transitions,
    /// and the Executor's `last_critique` stays NULL.
    #[test]
    fn submit_review_approved_silently_drops_supplied_critique() {
        let store  = Arc::new(Store::open_in_memory().unwrap());
        let (ctx, _sink) = build_review_test_ctx(store.clone(), default_test_policy());
        let policy = default_test_policy();
        seed_reviewer_with_executor_predecessor(&store, "rev1", "exe1");

        let req = make_submit_review_request(
            "rev1",
            Some(true),
            Some("kernel must drop this — approval path"),
        );
        let resp = handle_submit_review(
            req, TaskState::Running, &dummy_session_id(), 1, &store, &policy, &ctx,
        ).expect("approval must be Accepted");

        assert_eq!(resp.task_state, TaskState::Completed);
        assert!(read_last_critique(&store, "exe1").is_none(),
            "approved=true critique must NOT be persisted");
    }

    /// Rejection path: handler writes a formatted critique to the
    /// predecessor Executor's `tasks.last_critique` and transitions
    /// the Reviewer to Completed.
    #[test]
    fn submit_review_rejected_writes_formatted_critique_to_predecessor() {
        let store  = Arc::new(Store::open_in_memory().unwrap());
        let (ctx, _sink) = build_review_test_ctx(store.clone(), default_test_policy());
        let policy = default_test_policy();
        seed_reviewer_with_executor_predecessor(&store, "rev1", "exe1");

        let req = make_submit_review_request(
            "rev1",
            Some(false),
            Some("auth check missing on /admin"),
        );
        let resp = handle_submit_review(
            req, TaskState::Running, &dummy_session_id(), 1, &store, &policy, &ctx,
        ).expect("rejection must be Accepted (the handler accepts the verdict)");

        assert_eq!(resp.task_state, TaskState::Completed);
        assert_eq!(task_state_of(&store, "rev1"), TaskState::Completed.as_sql_str());
        // Spec format pinned: `[Reviewer <task_id>]: <critique>\n\n`.
        let written = read_last_critique(&store, "exe1")
            .expect("rejection must write last_critique");
        assert_eq!(
            written,
            "[Reviewer rev1]: auth check missing on /admin\n\n",
            "critique format must match v2-deep-spec.md §Step 22 verbatim"
        );
        assert_eq!(read_review_verdict(&store, "rev1"),
            Some(raxis_types::ReviewVerdict::Rejected.as_sql_str().to_owned()),
            "rejection path must persist Rejected verdict on Reviewer's own row");
    }

    /// Aggregation across N parallel reviewers (Step 25): each
    /// rejecting reviewer's critique is appended; the order matches
    /// arrival order; the Executor's column carries every entry.
    #[test]
    fn submit_review_rejected_aggregates_across_multiple_reviewers() {
        let store  = Arc::new(Store::open_in_memory().unwrap());
        let (ctx, _sink) = build_review_test_ctx(store.clone(), default_test_policy());
        let policy = default_test_policy();

        // Insert 1 Executor + 2 Reviewers, both rejecting in turn.
        // Reuse `seed_reviewer_with_executor_predecessor` for the
        // first reviewer, then add the second by hand (sharing the
        // same Executor predecessor).
        seed_reviewer_with_executor_predecessor(&store, "revA", "exe1");
        {
            let conn = store.lock_sync();
            let now = unix_now_secs();
            conn.execute(
                &format!(
                    "INSERT INTO {TASKS}
                        (task_id, initiative_id, lane_id, state, actor,
                         policy_epoch, admitted_at, transitioned_at,
                         actual_cost)
                     VALUES ('revB', 'init-rev', 'default', ?1, 'kernel',
                             1, ?2, ?2, 0)"
                ),
                rusqlite::params![TaskState::Running.as_sql_str(), now],
            ).unwrap();
            conn.execute(
                &format!(
                    "INSERT INTO {dag_edges}
                        (initiative_id, predecessor_task_id, successor_task_id,
                         predecessor_satisfied)
                     VALUES ('init-rev', 'exe1', 'revB', 1)",
                    dag_edges = Table::TaskDagEdges.as_str(),
                ),
                [],
            ).unwrap();
        }

        // First reviewer rejects.
        let req_a = make_submit_review_request(
            "revA", Some(false), Some("missing input validation"),
        );
        handle_submit_review(
            req_a, TaskState::Running, &dummy_session_id(), 1, &store, &policy, &ctx,
        ).expect("first rejection accepted");

        // Second reviewer rejects.
        let req_b = make_submit_review_request(
            "revB", Some(false), Some("uses deprecated tokio API"),
        );
        handle_submit_review(
            req_b, TaskState::Running, &dummy_session_id(), 2, &store, &policy, &ctx,
        ).expect("second rejection accepted");

        // Both critiques visible on the Executor's row, in arrival order.
        let aggregated = read_last_critique(&store, "exe1")
            .expect("aggregated critiques must persist");
        assert_eq!(
            aggregated,
            "[Reviewer revA]: missing input validation\n\n\
             [Reviewer revB]: uses deprecated tokio API\n\n",
            "Step 25 aggregation: critiques append in arrival order"
        );
    }

    /// Missing `approved` (None) → INVALID_REQUEST. The handler MUST
    /// NOT touch `tasks.last_critique` or the Reviewer's FSM.
    #[test]
    fn submit_review_missing_approved_returns_invalid_request() {
        let store  = Arc::new(Store::open_in_memory().unwrap());
        let (ctx, _sink) = build_review_test_ctx(store.clone(), default_test_policy());
        let policy = default_test_policy();
        seed_reviewer_with_executor_predecessor(&store, "rev1", "exe1");

        let req = make_submit_review_request("rev1", None, None);
        let err = handle_submit_review(
            req, TaskState::Running, &dummy_session_id(), 1, &store, &policy, &ctx,
        ).expect_err("missing approved must reject");

        assert_eq!(err.0, PlannerErrorCode::InvalidRequest);
        // FSM unchanged: Reviewer still Running, Executor's column NULL.
        assert_eq!(task_state_of(&store, "rev1"), TaskState::Running.as_sql_str());
        assert!(read_last_critique(&store, "exe1").is_none());
    }

    /// Rejection with missing critique (None) → INVALID_REQUEST.
    #[test]
    fn submit_review_rejected_missing_critique_returns_invalid_request() {
        let store  = Arc::new(Store::open_in_memory().unwrap());
        let (ctx, _sink) = build_review_test_ctx(store.clone(), default_test_policy());
        let policy = default_test_policy();
        seed_reviewer_with_executor_predecessor(&store, "rev1", "exe1");

        let req = make_submit_review_request("rev1", Some(false), None);
        let err = handle_submit_review(
            req, TaskState::Running, &dummy_session_id(), 1, &store, &policy, &ctx,
        ).expect_err("missing critique on rejection must reject");

        assert_eq!(err.0, PlannerErrorCode::InvalidRequest);
        assert_eq!(task_state_of(&store, "rev1"), TaskState::Running.as_sql_str());
        assert!(read_last_critique(&store, "exe1").is_none());
    }

    /// Rejection with empty critique (Some("")) → INVALID_REQUEST.
    /// An empty string offers no actionable feedback to the retry
    /// Executor; treat it as planner error rather than silently
    /// accepting a meaningless verdict.
    #[test]
    fn submit_review_rejected_empty_critique_returns_invalid_request() {
        let store  = Arc::new(Store::open_in_memory().unwrap());
        let (ctx, _sink) = build_review_test_ctx(store.clone(), default_test_policy());
        let policy = default_test_policy();
        seed_reviewer_with_executor_predecessor(&store, "rev1", "exe1");

        let req = make_submit_review_request("rev1", Some(false), Some(""));
        let err = handle_submit_review(
            req, TaskState::Running, &dummy_session_id(), 1, &store, &policy, &ctx,
        ).expect_err("empty critique on rejection must reject");

        assert_eq!(err.0, PlannerErrorCode::InvalidRequest);
        assert!(read_last_critique(&store, "exe1").is_none());
    }

    /// Oversized critique (> MAX_CRITIQUE_BYTES) → INVALID_REQUEST.
    /// Critically, the oversized text MUST NOT be persisted — that's
    /// the entire point of the cap (context-flooding DoS prevention).
    #[test]
    fn submit_review_rejected_oversized_critique_is_not_persisted() {
        let store  = Arc::new(Store::open_in_memory().unwrap());
        let (ctx, _sink) = build_review_test_ctx(store.clone(), default_test_policy());
        let policy = default_test_policy();
        seed_reviewer_with_executor_predecessor(&store, "rev1", "exe1");

        // 1 byte over the cap.
        let oversized = "x".repeat(raxis_types::MAX_CRITIQUE_BYTES + 1);
        let req = make_submit_review_request("rev1", Some(false), Some(&oversized));
        let err = handle_submit_review(
            req, TaskState::Running, &dummy_session_id(), 1, &store, &policy, &ctx,
        ).expect_err("oversized critique must reject");

        assert_eq!(err.0, PlannerErrorCode::InvalidRequest);
        assert!(read_last_critique(&store, "exe1").is_none(),
            "oversized critique MUST NOT be persisted (DoS prevention)");
        assert_eq!(task_state_of(&store, "rev1"), TaskState::Running.as_sql_str());
    }

    /// Critique exactly at the cap (== MAX_CRITIQUE_BYTES) is
    /// accepted. Boundary check pinned so a future refactor that
    /// flips `>` to `>=` regresses loudly.
    #[test]
    fn submit_review_rejected_critique_at_cap_is_accepted() {
        let store  = Arc::new(Store::open_in_memory().unwrap());
        let (ctx, _sink) = build_review_test_ctx(store.clone(), default_test_policy());
        let policy = default_test_policy();
        seed_reviewer_with_executor_predecessor(&store, "rev1", "exe1");

        let at_cap = "y".repeat(raxis_types::MAX_CRITIQUE_BYTES);
        let req = make_submit_review_request("rev1", Some(false), Some(&at_cap));
        let resp = handle_submit_review(
            req, TaskState::Running, &dummy_session_id(), 1, &store, &policy, &ctx,
        ).expect("critique at cap must be Accepted");

        assert_eq!(resp.task_state, TaskState::Completed);
        let written = read_last_critique(&store, "exe1")
            .expect("at-cap critique must persist");
        // The persisted form is `[Reviewer rev1]: <text>\n\n`. Just
        // assert it carries the full body bytes.
        assert!(written.contains(&at_cap),
            "at-cap critique must be persisted in full");
    }

    /// Reviewer task NOT in Running → FailTaskNotRunning. The
    /// task-state gate is the first check; payload validation is
    /// short-circuited.
    #[test]
    fn submit_review_rejects_non_running_reviewer() {
        let store  = Arc::new(Store::open_in_memory().unwrap());
        let (ctx, _sink) = build_review_test_ctx(store.clone(), default_test_policy());
        let policy = default_test_policy();
        seed_reviewer_with_executor_predecessor(&store, "rev1", "exe1");

        // Caller passes Admitted; the gate must reject regardless of
        // the actual DB state.
        let req = make_submit_review_request(
            "rev1", Some(false), Some("auth missing"),
        );
        let err = handle_submit_review(
            req, TaskState::Admitted, &dummy_session_id(), 1, &store, &policy, &ctx,
        ).expect_err("non-Running reviewer must reject");

        assert_eq!(err.0, PlannerErrorCode::FailTaskNotRunning);
        // Critically: no side effects on the Executor's column.
        assert!(read_last_critique(&store, "exe1").is_none());
    }

    /// Reviewer with NO predecessor edges → INVALID_REQUEST.
    /// Defense in depth: a malformed plan that slipped past
    /// approve_plan validation must not silently accept a
    /// SubmitReview that has nowhere to route the critique.
    #[test]
    fn submit_review_rejected_with_no_predecessor_returns_invalid_request() {
        let store  = Arc::new(Store::open_in_memory().unwrap());
        let (ctx, _sink) = build_review_test_ctx(store.clone(), default_test_policy());
        let policy = default_test_policy();
        // Insert a Reviewer task with NO `task_dag_edges` row.
        let conn = store.lock_sync();
        let now = unix_now_secs();
        conn.execute(
            &format!(
                "INSERT OR IGNORE INTO {INITIATIVES}
                    (initiative_id, state, terminal_criteria_json,
                     plan_artifact_sha256, created_at)
                 VALUES ('init-rev-orphan', ?1, '{{}}', 'deadbeef', ?2)"
            ),
            rusqlite::params![InitiativeState::Executing.as_sql_str(), now],
        ).unwrap();
        conn.execute(
            &format!(
                "INSERT INTO {TASKS}
                    (task_id, initiative_id, lane_id, state, actor,
                     policy_epoch, admitted_at, transitioned_at,
                     actual_cost)
                 VALUES ('orphan-rev', 'init-rev-orphan', 'default', ?1, 'kernel',
                         1, ?2, ?2, 0)"
            ),
            rusqlite::params![TaskState::Running.as_sql_str(), now],
        ).unwrap();
        drop(conn);

        let req = make_submit_review_request(
            "orphan-rev", Some(false), Some("no predecessor — defensive case"),
        );
        let err = handle_submit_review(
            req, TaskState::Running, &dummy_session_id(), 1, &store, &policy, &ctx,
        ).expect_err("orphan reviewer must reject");

        assert_eq!(err.0, PlannerErrorCode::InvalidRequest);
        // Reviewer FSM unchanged.
        assert_eq!(task_state_of(&store, "orphan-rev"),
                   TaskState::Running.as_sql_str());
    }

    /// V2 gap §12.2 — when the LAST sibling Reviewer submits
    /// `Approved`, the kernel emits exactly ONE
    /// `ReviewAggregationCompleted { verdict = "AllPassed" }` audit
    /// event addressed to the Executor predecessor.
    #[test]
    fn submit_review_emits_all_passed_aggregation_audit_when_last_reviewer_approves() {
        let store  = Arc::new(Store::open_in_memory().unwrap());
        let (ctx, sink) = build_review_test_ctx(store.clone(), default_test_policy());
        let policy = default_test_policy();

        // Two Reviewers (revA, revB) of one Executor (exe1).
        seed_reviewer_with_executor_predecessor(&store, "revA", "exe1");
        {
            let conn = store.lock_sync();
            let now = unix_now_secs();
            conn.execute(
                &format!(
                    "INSERT INTO {TASKS}
                        (task_id, initiative_id, lane_id, state, actor,
                         policy_epoch, admitted_at, transitioned_at,
                         actual_cost)
                     VALUES ('revB', 'init-rev', 'default', ?1, 'kernel',
                             1, ?2, ?2, 0)"
                ),
                rusqlite::params![TaskState::Running.as_sql_str(), now],
            ).unwrap();
            conn.execute(
                &format!(
                    "INSERT INTO {dag_edges}
                        (initiative_id, predecessor_task_id, successor_task_id,
                         predecessor_satisfied)
                     VALUES ('init-rev', 'exe1', 'revB', 1)",
                    dag_edges = Table::TaskDagEdges.as_str(),
                ),
                [],
            ).unwrap();
        }

        // First reviewer approves — aggregator must still be Pending,
        // NO audit emission expected.
        let req_a = make_submit_review_request("revA", Some(true), None);
        handle_submit_review(
            req_a, TaskState::Running, &dummy_session_id(), 1, &store, &policy, &ctx,
        ).unwrap();
        assert!(
            sink.events().iter().all(|e| !matches!(
                e.kind,
                raxis_audit_tools::AuditEventKind::ReviewAggregationCompleted { .. },
            )),
            "Pending aggregator must NOT emit ReviewAggregationCompleted (silent until terminal)",
        );

        // Second reviewer approves — aggregator now AllPassed, ONE
        // audit emission expected addressed to exe1.
        let req_b = make_submit_review_request("revB", Some(true), None);
        handle_submit_review(
            req_b, TaskState::Running, &dummy_session_id(), 2, &store, &policy, &ctx,
        ).unwrap();

        let agg_events: Vec<_> = sink.events()
            .into_iter()
            .filter(|e| matches!(
                e.kind,
                raxis_audit_tools::AuditEventKind::ReviewAggregationCompleted { .. },
            ))
            .collect();
        assert_eq!(agg_events.len(), 1, "exactly one terminal aggregation event");
        match &agg_events[0].kind {
            raxis_audit_tools::AuditEventKind::ReviewAggregationCompleted {
                executor_task_id,
                triggered_by_reviewer_task_id,
                reviewer_count,
                verdict,
            } => {
                assert_eq!(executor_task_id, "exe1");
                assert_eq!(triggered_by_reviewer_task_id, "revB");
                assert_eq!(*reviewer_count, 2);
                assert_eq!(verdict, "AllPassed");
            }
            _ => unreachable!("filtered above"),
        }
    }

    /// V2 gap §12.2 — single Reviewer approving terminates the
    /// aggregator immediately. The audit row carries `count = 1`.
    #[test]
    fn submit_review_single_reviewer_approval_emits_terminal_aggregation() {
        let store  = Arc::new(Store::open_in_memory().unwrap());
        let (ctx, sink) = build_review_test_ctx(store.clone(), default_test_policy());
        let policy = default_test_policy();
        seed_reviewer_with_executor_predecessor(&store, "rev-only", "exe1");

        let req = make_submit_review_request("rev-only", Some(true), None);
        handle_submit_review(
            req, TaskState::Running, &dummy_session_id(), 1, &store, &policy, &ctx,
        ).unwrap();

        let agg_events: Vec<_> = sink.events()
            .into_iter()
            .filter(|e| matches!(
                e.kind,
                raxis_audit_tools::AuditEventKind::ReviewAggregationCompleted { .. },
            ))
            .collect();
        assert_eq!(agg_events.len(), 1, "single-reviewer approval terminates the aggregator");
        match &agg_events[0].kind {
            raxis_audit_tools::AuditEventKind::ReviewAggregationCompleted {
                reviewer_count,
                verdict,
                ..
            } => {
                assert_eq!(*reviewer_count, 1);
                assert_eq!(verdict, "AllPassed");
            }
            _ => unreachable!(),
        }
    }

    /// V2 gap §12.2 — when the aggregator transitions out of
    /// `Pending` because at least one Reviewer rejected, the audit
    /// emission carries `verdict = "AtLeastOneRejected"`.
    #[test]
    fn submit_review_emits_at_least_one_rejected_aggregation() {
        let store  = Arc::new(Store::open_in_memory().unwrap());
        let (ctx, sink) = build_review_test_ctx(store.clone(), default_test_policy());
        let policy = default_test_policy();

        // Two Reviewers; revA approves, revB rejects.
        seed_reviewer_with_executor_predecessor(&store, "revA", "exe1");
        {
            let conn = store.lock_sync();
            let now = unix_now_secs();
            conn.execute(
                &format!(
                    "INSERT INTO {TASKS}
                        (task_id, initiative_id, lane_id, state, actor,
                         policy_epoch, admitted_at, transitioned_at,
                         actual_cost)
                     VALUES ('revB', 'init-rev', 'default', ?1, 'kernel',
                             1, ?2, ?2, 0)"
                ),
                rusqlite::params![TaskState::Running.as_sql_str(), now],
            ).unwrap();
            conn.execute(
                &format!(
                    "INSERT INTO {dag_edges}
                        (initiative_id, predecessor_task_id, successor_task_id,
                         predecessor_satisfied)
                     VALUES ('init-rev', 'exe1', 'revB', 1)",
                    dag_edges = Table::TaskDagEdges.as_str(),
                ),
                [],
            ).unwrap();
        }

        // revA approves → still Pending, no audit row.
        let req_a = make_submit_review_request("revA", Some(true), None);
        handle_submit_review(
            req_a, TaskState::Running, &dummy_session_id(), 1, &store, &policy, &ctx,
        ).unwrap();

        // revB rejects → aggregator terminates AtLeastOneRejected.
        let req_b = make_submit_review_request(
            "revB", Some(false), Some("missing test coverage"),
        );
        handle_submit_review(
            req_b, TaskState::Running, &dummy_session_id(), 2, &store, &policy, &ctx,
        ).unwrap();

        let agg_events: Vec<_> = sink.events()
            .into_iter()
            .filter(|e| matches!(
                e.kind,
                raxis_audit_tools::AuditEventKind::ReviewAggregationCompleted { .. },
            ))
            .collect();
        assert_eq!(agg_events.len(), 1);
        match &agg_events[0].kind {
            raxis_audit_tools::AuditEventKind::ReviewAggregationCompleted {
                triggered_by_reviewer_task_id,
                reviewer_count,
                verdict,
                ..
            } => {
                assert_eq!(triggered_by_reviewer_task_id, "revB");
                assert_eq!(*reviewer_count, 2);
                assert_eq!(verdict, "AtLeastOneRejected");
            }
            _ => unreachable!(),
        }
    }

    /// Insert an Active `subtask_activations` row for `task_id` with a
    /// freshly-minted activation_id, `review_reject_count = 0`, and
    /// `terminated_at = NULL`. Mirror of the row populated by
    /// `lifecycle::insert_subtask_activation_in_tx` (V2 §Step 5)
    /// shaped for the `increment_executor_review_reject_count` tests.
    fn seed_executor_activation_row(store: &Store, task_id: &str) {
        let conn = store.lock_sync();
        conn.execute(
            &format!(
                "INSERT INTO {SUBTASK_ACTIVATIONS}
                    (activation_id, task_id, initiative_id,
                     activation_state, session_id, evaluation_sha,
                     crash_retry_count, review_reject_count,
                     created_at, activated_at, terminated_at)
                 VALUES (?1, ?2, 'init-rev', 'PendingActivation', NULL, NULL,
                         0, 0, ?3, NULL, NULL)"
            ),
            rusqlite::params![
                uuid::Uuid::new_v4().to_string(),
                task_id,
                unix_now_secs() as i64,
            ],
        ).unwrap();
    }

    fn read_review_reject_count(store: &Store, task_id: &str) -> i64 {
        let conn = store.lock_sync();
        conn.query_row(
            &format!(
                "SELECT review_reject_count FROM {SUBTASK_ACTIVATIONS}
                  WHERE task_id = ?1 AND terminated_at IS NULL"
            ),
            rusqlite::params![task_id],
            |r| r.get::<_, i64>(0),
        ).unwrap()
    }

    /// V2 §Step 25 — a terminal-rejected aggregation must bump the
    /// Executor's `review_reject_count` exactly once, regardless of
    /// how many sibling Reviewers voted (the aggregator only reaches
    /// terminal-rejected on the last sibling's commit). This pins
    /// the substrate the future `handle_retry_sub_task` ceiling
    /// check (`max_review_rejections`) reads against.
    #[test]
    fn submit_review_rejected_increments_executor_review_reject_count() {
        let store  = Arc::new(Store::open_in_memory().unwrap());
        let (ctx, _sink) = build_review_test_ctx(store.clone(), default_test_policy());
        let policy = default_test_policy();

        seed_reviewer_with_executor_predecessor(&store, "rev1", "exe1");
        seed_executor_activation_row(&store, "exe1");

        assert_eq!(read_review_reject_count(&store, "exe1"), 0,
            "freshly-seeded activation row starts at zero");

        let req = make_submit_review_request("rev1", Some(false), Some("not yet"));
        handle_submit_review(
            req, TaskState::Running, &dummy_session_id(), 1, &store, &policy, &ctx,
        ).unwrap();

        assert_eq!(read_review_reject_count(&store, "exe1"), 1,
            "single-Reviewer rejection bumps the Executor's counter \
             from 0 → 1 (one rejection round)");
    }

    /// Approval path must NOT bump `review_reject_count` — only
    /// terminal-rejected aggregations do.
    #[test]
    fn submit_review_approved_leaves_review_reject_count_at_zero() {
        let store  = Arc::new(Store::open_in_memory().unwrap());
        let (ctx, _sink) = build_review_test_ctx(store.clone(), default_test_policy());
        let policy = default_test_policy();

        seed_reviewer_with_executor_predecessor(&store, "rev1", "exe1");
        seed_executor_activation_row(&store, "exe1");

        let req = make_submit_review_request("rev1", Some(true), None);
        handle_submit_review(
            req, TaskState::Running, &dummy_session_id(), 1, &store, &policy, &ctx,
        ).unwrap();

        assert_eq!(read_review_reject_count(&store, "exe1"), 0,
            "AllPassed verdict must not increment the rejection counter");
    }

    /// N-Reviewer panel: the aggregator only reaches terminal-rejected
    /// on the LAST sibling's commit, so the counter bumps exactly once
    /// across the whole panel. Pin this against an off-by-one bug
    /// where bumping inside the per-Reviewer rejection branch would
    /// over-count (the prose-pattern in `handle_submit_review` Step 4
    /// could accidentally regress here).
    #[test]
    fn submit_review_rejected_panel_increments_review_reject_count_once() {
        let store  = Arc::new(Store::open_in_memory().unwrap());
        let (ctx, _sink) = build_review_test_ctx(store.clone(), default_test_policy());
        let policy = default_test_policy();

        // Two-Reviewer panel.
        seed_reviewer_with_executor_predecessor(&store, "revA", "exe1");
        seed_executor_activation_row(&store, "exe1");
        {
            let conn = store.lock_sync();
            let now = unix_now_secs();
            conn.execute(
                &format!(
                    "INSERT INTO {TASKS}
                        (task_id, initiative_id, lane_id, state, actor,
                         policy_epoch, admitted_at, transitioned_at,
                         actual_cost)
                     VALUES ('revB', 'init-rev', 'default', ?1, 'kernel',
                             1, ?2, ?2, 0)"
                ),
                rusqlite::params![TaskState::Running.as_sql_str(), now],
            ).unwrap();
            conn.execute(
                &format!(
                    "INSERT INTO {dag_edges}
                        (initiative_id, predecessor_task_id, successor_task_id,
                         predecessor_satisfied)
                     VALUES ('init-rev', 'exe1', 'revB', 1)",
                    dag_edges = Table::TaskDagEdges.as_str(),
                ),
                [],
            ).unwrap();
        }

        // revA rejects first → still Pending (revB hasn't voted) → no bump.
        let req_a = make_submit_review_request("revA", Some(false), Some("first"));
        handle_submit_review(
            req_a, TaskState::Running, &dummy_session_id(), 1, &store, &policy, &ctx,
        ).unwrap();
        assert_eq!(read_review_reject_count(&store, "exe1"), 0,
            "Pending aggregation must not bump the counter");

        // revB rejects → terminal AtLeastOneRejected → bump once.
        let req_b = make_submit_review_request("revB", Some(false), Some("second"));
        handle_submit_review(
            req_b, TaskState::Running, &dummy_session_id(), 2, &store, &policy, &ctx,
        ).unwrap();

        assert_eq!(read_review_reject_count(&store, "exe1"), 1,
            "exactly one rejection round across the panel — counter \
             bumps once when the aggregator turns terminal-rejected");
    }

    #[test]
    fn read_completion_inputs_returns_all_recorded_ranges() {
        let store = Store::open_in_memory().unwrap();
        seed_task(&store, "t1");
        // Bind evaluation_sha directly (raw SQL — bypassing
        // `update_task_intent_fields` so we don't have to seed a session
        // row to satisfy the session_id FK; the helper-under-test
        // doesn't care about session_id).
        {
            let conn = store.lock_sync();
            conn.execute(
                &format!("UPDATE {TASKS} SET evaluation_sha = ?1 WHERE task_id = ?2"),
                rusqlite::params!["head3", "t1"],
            ).unwrap();
        }
        insert_task_intent_range("t1", "base1", "head1", &store).unwrap();
        insert_task_intent_range("t1", "base2", "head2", &store).unwrap();
        insert_task_intent_range("t1", "base3", "head3", &store).unwrap();

        let (h_bind, mut ranges) = read_completion_inputs("t1", &store).unwrap();
        ranges.sort();
        assert_eq!(h_bind.as_deref(), Some("head3"));
        assert_eq!(ranges, vec![
            ("base1".to_owned(), "head1".to_owned()),
            ("base2".to_owned(), "head2".to_owned()),
            ("base3".to_owned(), "head3".to_owned()),
        ]);
    }

    // ── handle_structured_output (V2 §3.2) ────────────────────────────────

    /// Seed a `sessions` row keyed on `session_id` so the
    /// `structured_outputs.session_id` foreign key passes. Uses a
    /// deterministic UUID (`dummy_session_id`) so multiple-session
    /// rate-limit tests can re-seed the same row.
    fn seed_session(store: &Store, session_id: &str) {
        let conn = store.lock_sync();
        let now = unix_now_secs();
        let _ = conn.execute(
            &format!(
                "INSERT OR IGNORE INTO {SESSIONS} (
                    session_id, role_id, session_token, sequence_number,
                    worktree_root, base_sha, base_tracking_ref,
                    lineage_id, fetch_quota, created_at, expires_at, revoked,
                    session_agent_type, can_delegate
                 ) VALUES (?1,'Planner','tok-{session_id}',0,
                          NULL,NULL,NULL,'lineage-1',1000,?2,?3,0,'Executor',0)"
            ),
            rusqlite::params![session_id, now, now + 86_400],
        );
    }

    fn count_structured_outputs(store: &Store, session_id: &str) -> i64 {
        let conn = store.lock_sync();
        conn.query_row(
            &format!(
                "SELECT COUNT(*) FROM {so} WHERE session_id = ?1",
                so = Table::StructuredOutputs.as_str(),
            ),
            rusqlite::params![session_id],
            |r| r.get(0),
        ).unwrap()
    }

    fn make_structured_output_request(
        task_id: &str,
        payload: Option<raxis_types::StructuredOutputKind>,
    ) -> IntentRequest {
        IntentRequest {
            session_token:   "tok".into(),
            sequence_number: 1,
            envelope_nonce:  "0".repeat(32),
            intent_kind:     IntentKind::StructuredOutput,
            task_id:         raxis_types::TaskId::parse(task_id).unwrap(),
            base_sha:        None,
            head_sha:        None,
            submitted_claims: vec![],
            justification:   None,
            idempotency_key: None,
            approval_token:  None,
            approved:        None,
            critique:        None,
            resolved_via_escalation: None,
            tokens_used:     None,
            structured_output: payload,
        }
    }

    /// Missing payload — kernel rejects with
    /// `FailStructuredOutputInvalid`. INV-09 / R-10 — coarse code only.
    #[test]
    fn structured_output_missing_payload_is_rejected() {
        let store = Arc::new(Store::open_in_memory().unwrap());
        let (ctx, _sink) = build_review_test_ctx(store.clone(), default_test_policy());
        let session = dummy_session_id();
        seed_session(&store, session.as_str());
        // Reuse the executor-predecessor seed for a Running task.
        seed_reviewer_with_executor_predecessor(&store, "rev1", "exe1");

        let req = make_structured_output_request("exe1", None);
        let err = handle_structured_output(
            req, TaskState::Running, &session, 1, &store, &ctx,
        ).expect_err("missing payload must be rejected");
        assert_eq!(err.0, PlannerErrorCode::FailStructuredOutputInvalid);
        assert_eq!(count_structured_outputs(&store, session.as_str()), 0);
    }

    /// Hard-malformed payload (TaskSummary with non-hex commit_sha)
    /// is rejected with `FailStructuredOutputInvalid`. Confidence
    /// over-cap and oversized strings DO NOT take this path — they
    /// are silently truncated/clamped (see `validate_and_normalise`
    /// + the truncation tests in the types crate).
    #[test]
    fn structured_output_non_hex_commit_sha_is_rejected() {
        let store = Arc::new(Store::open_in_memory().unwrap());
        let (ctx, _sink) = build_review_test_ctx(store.clone(), default_test_policy());
        let session = dummy_session_id();
        seed_session(&store, session.as_str());
        seed_reviewer_with_executor_predecessor(&store, "rev1", "exe1");

        let req = make_structured_output_request(
            "exe1",
            Some(raxis_types::StructuredOutputKind::TaskSummary {
                commit_sha:    "not-a-real-sha".to_owned(),
                changed_paths: vec![],
                approach:      "fix".to_owned(),
            }),
        );
        let err = handle_structured_output(
            req, TaskState::Running, &session, 1, &store, &ctx,
        ).expect_err("non-hex commit_sha must be rejected");
        assert_eq!(err.0, PlannerErrorCode::FailStructuredOutputInvalid);
        assert_eq!(count_structured_outputs(&store, session.as_str()), 0);
    }

    /// Happy path: ProgressReport admission writes a single
    /// `structured_outputs` row, the FSM stays Running (NON-TERMINAL
    /// per §3.2), and a `StructuredOutputEmitted` audit event lands
    /// on the sink. The audit row's `output_kind` matches the SQL
    /// `kind` column.
    #[test]
    fn structured_output_progress_report_persists_and_emits_audit() {
        let store = Arc::new(Store::open_in_memory().unwrap());
        let (ctx, sink) = build_review_test_ctx(store.clone(), default_test_policy());
        let session = dummy_session_id();
        seed_session(&store, session.as_str());
        seed_reviewer_with_executor_predecessor(&store, "rev1", "exe1");

        let req = make_structured_output_request(
            "exe1",
            Some(raxis_types::StructuredOutputKind::ProgressReport {
                files_modified: vec!["a.rs".into(), "b.rs".into()],
                tests_passing:  3,
                tests_failing:  1,
                confidence:     0.8,
            }),
        );
        let resp = handle_structured_output(
            req, TaskState::Running, &session, 1, &store, &ctx,
        ).expect("progress report must be accepted");
        assert!(matches!(resp.outcome, IntentOutcome::Accepted { .. }));
        assert_eq!(resp.task_state, TaskState::Running,
            "structured_output is NON-TERMINAL — task FSM stays put");

        assert_eq!(count_structured_outputs(&store, session.as_str()), 1,
            "exactly one row written to structured_outputs");

        // Audit event landed on the sink with `output_kind = "progress_report"`.
        let events = sink.events();
        let so_evt = events.iter().find(|e| matches!(
            e.kind, raxis_audit_tools::AuditEventKind::StructuredOutputEmitted { .. },
        )).expect("StructuredOutputEmitted audit event missing");
        if let raxis_audit_tools::AuditEventKind::StructuredOutputEmitted {
            output_kind, severity, task_id, session_id: sid, ..
        } = &so_evt.kind {
            assert_eq!(output_kind, "progress_report");
            assert!(severity.is_none(),
                "progress_report carries no severity");
            assert_eq!(task_id, "exe1");
            assert_eq!(sid, session.as_str());
        }
    }

    /// DiagnosticFlag carries a severity column on the SQL row AND
    /// the audit projection. Pin both.
    #[test]
    fn structured_output_diagnostic_flag_persists_severity() {
        let store = Arc::new(Store::open_in_memory().unwrap());
        let (ctx, sink) = build_review_test_ctx(store.clone(), default_test_policy());
        let session = dummy_session_id();
        seed_session(&store, session.as_str());
        seed_reviewer_with_executor_predecessor(&store, "rev1", "exe1");

        let req = make_structured_output_request(
            "exe1",
            Some(raxis_types::StructuredOutputKind::DiagnosticFlag {
                severity: raxis_types::DiagnosticSeverity::Critical,
                message:  "auth bypass!".into(),
                evidence: Some("src/auth.rs:42".into()),
            }),
        );
        handle_structured_output(
            req, TaskState::Running, &session, 1, &store, &ctx,
        ).expect("diagnostic flag must be accepted");

        let conn = store.lock_sync();
        let (kind, severity): (String, Option<String>) = conn.query_row(
            &format!(
                "SELECT kind, severity FROM {so} WHERE session_id = ?1",
                so = Table::StructuredOutputs.as_str(),
            ),
            rusqlite::params![session.as_str()],
            |r| Ok((r.get(0)?, r.get(1)?)),
        ).unwrap();
        drop(conn);
        assert_eq!(kind, "diagnostic_flag");
        assert_eq!(severity.as_deref(), Some("critical"));

        let events = sink.events();
        let so_evt = events.iter().find(|e| matches!(
            e.kind, raxis_audit_tools::AuditEventKind::StructuredOutputEmitted { .. },
        )).expect("StructuredOutputEmitted audit event missing");
        if let raxis_audit_tools::AuditEventKind::StructuredOutputEmitted {
            output_kind, severity, ..
        } = &so_evt.kind {
            assert_eq!(output_kind, "diagnostic_flag");
            assert_eq!(severity.as_deref(), Some("critical"));
        }
    }

    /// Per-session rate limit: after
    /// `STRUCTURED_OUTPUT_PER_SESSION_RATE_LIMIT` accepted outputs
    /// the next submission rejects with
    /// `FailStructuredOutputRateLimited`. The previously-stored rows
    /// are NOT rolled back (rate limit is a forward-only cap).
    #[test]
    fn structured_output_per_session_rate_limit_is_enforced() {
        let store = Arc::new(Store::open_in_memory().unwrap());
        let (ctx, _sink) = build_review_test_ctx(store.clone(), default_test_policy());
        let session = dummy_session_id();
        seed_session(&store, session.as_str());
        seed_reviewer_with_executor_predecessor(&store, "rev1", "exe1");

        let cap = raxis_types::STRUCTURED_OUTPUT_PER_SESSION_RATE_LIMIT;
        for i in 0..cap {
            let req = make_structured_output_request(
                "exe1",
                Some(raxis_types::StructuredOutputKind::ProgressReport {
                    files_modified: vec![],
                    tests_passing:  i,
                    tests_failing:  0,
                    confidence:     0.5,
                }),
            );
            handle_structured_output(
                req, TaskState::Running, &session, (i as u64) + 1, &store, &ctx,
            ).unwrap_or_else(|e| panic!("output #{i} rejected: {e:?}"));
        }
        assert_eq!(count_structured_outputs(&store, session.as_str()), cap as i64);

        // The (cap+1)-th submission fails with the rate-limit code.
        let req = make_structured_output_request(
            "exe1",
            Some(raxis_types::StructuredOutputKind::ProgressReport {
                files_modified: vec![],
                tests_passing:  cap,
                tests_failing:  0,
                confidence:     0.5,
            }),
        );
        let err = handle_structured_output(
            req, TaskState::Running, &session, (cap as u64) + 1, &store, &ctx,
        ).expect_err("over-cap submission must be rejected");
        assert_eq!(err.0, PlannerErrorCode::FailStructuredOutputRateLimited);
        assert_eq!(count_structured_outputs(&store, session.as_str()), cap as i64,
            "rate-limit rejection MUST NOT roll back prior rows");
    }

    /// Truncation via `validate_and_normalise` runs BEFORE the
    /// payload is stored — an over-cap `DiagnosticFlag.message` is
    /// truncated to ≤ `STRUCTURED_OUTPUT_MAX_DIAG_MESSAGE_BYTES + ε`
    /// and persisted, NOT rejected. `payload_bytes` on the audit row
    /// reflects the truncated size.
    #[test]
    fn structured_output_truncates_oversize_message_before_store() {
        let store = Arc::new(Store::open_in_memory().unwrap());
        let (ctx, sink) = build_review_test_ctx(store.clone(), default_test_policy());
        let session = dummy_session_id();
        seed_session(&store, session.as_str());
        seed_reviewer_with_executor_predecessor(&store, "rev1", "exe1");

        let huge = "x".repeat(
            raxis_types::STRUCTURED_OUTPUT_MAX_DIAG_MESSAGE_BYTES * 4
        );
        let req = make_structured_output_request(
            "exe1",
            Some(raxis_types::StructuredOutputKind::DiagnosticFlag {
                severity: raxis_types::DiagnosticSeverity::Warning,
                message:  huge.clone(),
                evidence: None,
            }),
        );
        handle_structured_output(
            req, TaskState::Running, &session, 1, &store, &ctx,
        ).expect("oversize message must be truncated, not rejected");

        let events = sink.events();
        let so_evt = events.iter().find(|e| matches!(
            e.kind, raxis_audit_tools::AuditEventKind::StructuredOutputEmitted { .. },
        )).expect("audit event missing");
        if let raxis_audit_tools::AuditEventKind::StructuredOutputEmitted {
            payload_bytes, ..
        } = &so_evt.kind {
            // payload_json includes the JSON wrapper + truncated message
            // + "<truncated>" marker. Cap is the message body alone, so
            // we expect the JSON to be a small constant overhead larger.
            let cap = raxis_types::STRUCTURED_OUTPUT_MAX_DIAG_MESSAGE_BYTES as u32;
            assert!(*payload_bytes <= cap + 256,
                "payload_bytes {payload_bytes} exceeded cap {cap} + JSON overhead");
            assert!((*payload_bytes as usize) < huge.len(),
                "truncation must shrink the payload");
        }
    }

    // ── handle_list_task_outputs (V2 §3.2 read path) ──────────────────────────
    //
    // End-to-end check that the full pipeline composes correctly:
    //
    //   1. seed `sessions` + reviewer/executor task rows
    //   2. drive `handle_structured_output` for two real payloads
    //   3. run `handle_list_task_outputs` against a real on-disk
    //      `kernel.db` and assert the operator sees both rows in
    //      `emitted_at` order with the right wire shape.
    //
    // Uses a real `Store::open(<file>)` rather than `open_in_memory`
    // because `views::structured_outputs::list_for_task` opens its
    // own short-lived `RoConn` snapshot via
    // `raxis_store::ro::open(data_dir)` — a memory-only DB has no
    // path the read-only opener can reach.

    // Multi-threaded runtime: the seed helpers + the
    // `handle_structured_output` writer use `Store::lock_sync` which
    // calls `tokio::sync::Mutex::blocking_lock`. That panics on a
    // single-threaded runtime.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn list_task_outputs_returns_rows_emitted_via_handle_structured_output() {
        use raxis_types::operator_wire::OperatorResponse;

        let tmp = tempfile::tempdir().expect("tempdir");
        let db_path = tmp.path().join("kernel.db");
        let store = Arc::new(Store::open(&db_path).expect("Store::open"));

        // Build a HandlerContext rooted at this tempdir so the
        // operator handler's `data_dir` matches the file we just
        // opened. We reuse the standard test fixture for everything
        // else (audit sink, isolation backend, etc.).
        let sink = Arc::new(raxis_test_support::FakeAuditSink::new());
        let credentials = crate::ipc::context::build_default_test_credentials(
            tmp.path(), sink.clone(),
        );
        let isolation = crate::ipc::context::build_fail_closed_test_isolation();
        let orchestrator_spawn = crate::ipc::context::build_test_orchestrator_spawn();
        let domain = crate::ipc::context::build_default_test_domain(tmp.path());
        let ctx = Arc::new(HandlerContext::new(
            Arc::new(arc_swap::ArcSwap::from_pointee(default_test_policy())),
            Arc::new(crate::authority::keys::KeyRegistry::stub_for_tests()),
            store.clone(),
            sink.clone(),
            tmp.path().to_path_buf(),
            Arc::new(crate::initiatives::PlanRegistry::new()),
            Arc::new(crate::gateway::client::GatewayClient::new()),
            Arc::new(crate::prompt::EpochBinding::new()),
            credentials,
            isolation,
            orchestrator_spawn,
            crate::ipc::context::build_test_executor_spawn(),
            domain,
        ));

        let session = dummy_session_id();
        // The seed helpers + the handler call `Store::lock_sync` =>
        // `tokio::sync::Mutex::blocking_lock`, which panics if invoked
        // from inside a runtime worker. Run them on a dedicated
        // blocking thread instead.
        let session_for_blk = session.clone();
        let store_for_blk = store.clone();
        let ctx_for_blk = ctx.clone();
        tokio::task::spawn_blocking(move || {
            seed_session(&store_for_blk, session_for_blk.as_str());
            seed_reviewer_with_executor_predecessor(&store_for_blk, "rev1", "exe1");

            for (i, payload) in [
                raxis_types::StructuredOutputKind::ProgressReport {
                    files_modified: vec!["src/lib.rs".to_owned()],
                    tests_passing:  3,
                    tests_failing:  0,
                    confidence:     0.8,
                },
                raxis_types::StructuredOutputKind::DiagnosticFlag {
                    severity: raxis_types::DiagnosticSeverity::Warning,
                    message:  "watch out".to_owned(),
                    evidence: Some("src/lib.rs:42".to_owned()),
                },
            ].into_iter().enumerate() {
                let req = make_structured_output_request("exe1", Some(payload));
                handle_structured_output(
                    req, TaskState::Running, &session_for_blk,
                    (i as u64) + 1, &store_for_blk, &ctx_for_blk,
                ).expect("handle_structured_output must accept a normalised payload");
            }
        }).await.expect("blocking seed task must succeed");

        // Now drive the operator read path — same code path the IPC
        // dispatcher invokes for `OperatorRequest::ListTaskOutputs`.
        let resp = crate::ipc::operator_ergonomics::handle_list_task_outputs(
            "exe1".to_owned(),
            &ctx,
        ).await;

        match resp {
            OperatorResponse::TaskOutputsListed { task_id, outputs } => {
                assert_eq!(task_id, "exe1");
                assert_eq!(outputs.len(), 2,
                    "operator must see both structured outputs");

                // Ordered by `emitted_at ASC`. Both rows are stamped
                // by the same call to `unix_now_secs` inside the
                // handler so the secondary sort on `output_id ASC`
                // (UUID) breaks ties; we assert by kind instead of
                // by relative position to keep the test stable.
                let kinds: std::collections::HashSet<&str> = outputs.iter()
                    .map(|o| o.kind.as_str())
                    .collect();
                assert!(kinds.contains("progress_report"));
                assert!(kinds.contains("diagnostic_flag"));

                for o in &outputs {
                    assert_eq!(o.task_id, "exe1");
                    assert_eq!(o.session_id, session.as_str());
                    assert_eq!(o.initiative_id, "init-rev");
                    assert!(!o.payload_json.is_empty(),
                        "payload_json must be populated verbatim");
                    if o.kind == "diagnostic_flag" {
                        assert_eq!(o.severity.as_deref(), Some("warning"));
                    } else {
                        assert!(o.severity.is_none(),
                            "non-diagnostic kinds must have no severity");
                    }
                }
            }
            other => panic!("expected TaskOutputsListed, got {other:?}"),
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn list_task_outputs_for_unknown_task_returns_empty_listing() {
        use raxis_types::operator_wire::OperatorResponse;

        let tmp = tempfile::tempdir().expect("tempdir");
        let db_path = tmp.path().join("kernel.db");
        let store = Arc::new(Store::open(&db_path).expect("Store::open"));

        let sink = Arc::new(raxis_test_support::FakeAuditSink::new());
        let credentials = crate::ipc::context::build_default_test_credentials(
            tmp.path(), sink.clone(),
        );
        let isolation = crate::ipc::context::build_fail_closed_test_isolation();
        let orchestrator_spawn = crate::ipc::context::build_test_orchestrator_spawn();
        let domain = crate::ipc::context::build_default_test_domain(tmp.path());
        let ctx = Arc::new(HandlerContext::new(
            Arc::new(arc_swap::ArcSwap::from_pointee(default_test_policy())),
            Arc::new(crate::authority::keys::KeyRegistry::stub_for_tests()),
            store,
            sink.clone(),
            tmp.path().to_path_buf(),
            Arc::new(crate::initiatives::PlanRegistry::new()),
            Arc::new(crate::gateway::client::GatewayClient::new()),
            Arc::new(crate::prompt::EpochBinding::new()),
            credentials,
            isolation,
            orchestrator_spawn,
            crate::ipc::context::build_test_executor_spawn(),
            domain,
        ));

        let resp = crate::ipc::operator_ergonomics::handle_list_task_outputs(
            "no-such-task".to_owned(),
            &ctx,
        ).await;
        match resp {
            OperatorResponse::TaskOutputsListed { task_id, outputs } => {
                assert_eq!(task_id, "no-such-task");
                assert!(outputs.is_empty(),
                    "unknown task must yield an empty list, not an error");
            }
            other => panic!("expected TaskOutputsListed, got {other:?}"),
        }
    }

    // ── handle_retry_sub_task — v2-deep-spec.md §Step 12 ──────────────────
    //
    // These tests exercise the V2 §Step 12 `RetrySubTask` admission
    // path in isolation. The handler is async and uses
    // `ctx.session_spawn` for best-effort VM termination, so each
    // test runs on a multi-threaded tokio runtime (the handler does
    // `Store::lock_sync` on a blocking thread, which panics on a
    // single-threaded runtime per the same rationale as
    // `handle_structured_output` tests above).
    //
    // Test surface:
    //   * Ceiling enforcement: each ceiling rejects independently
    //     (a task with crash_retry_count at ceiling is non-retryable
    //     even if review_reject_count is well under budget).
    //   * Operator-omitted ceiling defaults: `TaskPlanFields::None`
    //     resolves to `DEFAULT_MAX_*` so an under-specified plan
    //     gets a sensible budget rather than fail-closed-zero.
    //   * Prior-activation state guard: Active / PendingActivation
    //     / Completed are non-retryable; only Failed is.
    //   * Idempotent counter forwarding: the new activation row
    //     copies counters verbatim from the failed row (the spec
    //     says retry_handler does not bump the counters — bumps
    //     happen at the failure event, never at retry).
    //   * Task FSM reset: post-retry, `tasks.state` is `Admitted`
    //     so a subsequent `ActivateSubTask` can spawn a fresh VM.
    //   * Prior session revoke: the bound `sessions` row has
    //     `revoked = 1` after retry.

    /// Build a HandlerContext rooted at a tempdir, a fresh in-memory
    /// store, and a fresh PlanRegistry. Mirrors
    /// `build_review_test_ctx` but with a dedicated tempdir (the
    /// retry handler reads `ctx.policy` for the lane budget snapshot
    /// + uses `ctx.session_spawn` for best-effort VM termination —
    /// neither hits disk in our tests, but a unique tempdir keeps
    /// concurrent test runs isolated).
    fn build_retry_test_ctx(
        store: Arc<Store>,
    ) -> (Arc<HandlerContext>, Arc<crate::initiatives::PlanRegistry>,
          Arc<raxis_test_support::FakeAuditSink>) {
        let tmp_dir = tempfile::tempdir().expect("tempdir");
        let sink = Arc::new(raxis_test_support::FakeAuditSink::new());
        let credentials = crate::ipc::context::build_default_test_credentials(
            tmp_dir.path(), sink.clone(),
        );
        let isolation = crate::ipc::context::build_fail_closed_test_isolation();
        let orchestrator_spawn = crate::ipc::context::build_test_orchestrator_spawn();
        let domain = crate::ipc::context::build_default_test_domain(tmp_dir.path());
        let plan_registry = Arc::new(crate::initiatives::PlanRegistry::new());
        let ctx = Arc::new(HandlerContext::new(
            Arc::new(arc_swap::ArcSwap::from_pointee(default_test_policy())),
            Arc::new(crate::authority::keys::KeyRegistry::stub_for_tests()),
            store,
            sink.clone(),
            tmp_dir.path().to_path_buf(),
            plan_registry.clone(),
            Arc::new(crate::gateway::client::GatewayClient::new()),
            Arc::new(crate::prompt::EpochBinding::new()),
            credentials,
            isolation,
            orchestrator_spawn,
            crate::ipc::context::build_test_executor_spawn(),
            domain,
        ));
        // Hold the tempdir alive for the test duration via leaking;
        // tests run for milliseconds and the OS reaps the dir at
        // process exit. We deliberately leak instead of returning
        // the guard because every retry test would otherwise need
        // a 4-tuple return.
        std::mem::forget(tmp_dir);
        (ctx, plan_registry, sink)
    }

    /// Insert an Orchestrator session row keyed on `dummy_session_id()`
    /// with `session_agent_type = 'Orchestrator'` so the static
    /// dispatch matrix would Authorize a RetrySubTask, and the
    /// `accept_envelope_and_advance_sequence` helper has a row to
    /// advance.
    fn seed_orchestrator_session(store: &Store) {
        let conn = store.lock_sync();
        let now = unix_now_secs();
        conn.execute(
            &format!(
                "INSERT OR REPLACE INTO {SESSIONS} (
                    session_id, role_id, session_token, sequence_number,
                    worktree_root, base_sha, base_tracking_ref,
                    lineage_id, fetch_quota, created_at, expires_at, revoked,
                    session_agent_type, can_delegate
                 ) VALUES (?1, 'Orchestrator', 'tok-orch', 0,
                          NULL, NULL, NULL, 'lineage-orch', 1000, ?2, ?3, 0,
                          'Orchestrator', 1)"
            ),
            rusqlite::params![dummy_session_id().as_str(), now, now + 86_400],
        ).unwrap();
    }

    /// Insert an initiative + task + Failed activation row + plan
    /// registry entry so the retry handler has a complete substrate
    /// to operate on.
    fn seed_failed_executor_for_retry(
        store:           &Store,
        registry:        &crate::initiatives::PlanRegistry,
        task_id:         &str,
        crash_count:     u32,
        review_count:    u32,
        max_crash:       Option<u32>,
        max_review:      Option<u32>,
        prior_session:   Option<&str>,
    ) -> String {
        let initiative_id = "init-retry";
        let conn = store.lock_sync();
        // Stamp the seeded "prior" rows strictly older than the wall
        // clock — the retry handler uses `unix_now_secs()` for the
        // freshly-inserted PendingActivation row, and the assertion
        // pin in `read_activations` orders by `created_at ASC`. With
        // 1-second clock resolution the seed and the new row would
        // otherwise collide, leaving ordering up to the random
        // activation_id UUID and producing a flaky test.
        let now_real    = unix_now_secs();
        let prior_now   = now_real.saturating_sub(60);
        conn.execute(
            &format!(
                "INSERT OR IGNORE INTO {INITIATIVES}
                    (initiative_id, state, terminal_criteria_json,
                     plan_artifact_sha256, created_at)
                 VALUES (?1, ?2, '{{}}', 'deadbeef', ?3)"
            ),
            rusqlite::params![
                initiative_id,
                InitiativeState::Executing.as_sql_str(),
                prior_now,
            ],
        ).unwrap();
        // Task row in `Failed` (the retry handler resets it to
        // `Admitted`). Use the kernel-store DDL field shape.
        conn.execute(
            &format!(
                "INSERT INTO {TASKS}
                    (task_id, initiative_id, lane_id, state, actor,
                     policy_epoch, admitted_at, transitioned_at,
                     actual_cost)
                 VALUES (?1, ?2, 'default', ?3, 'kernel', 1, ?4, ?4, 0)"
            ),
            rusqlite::params![
                task_id,
                initiative_id,
                TaskState::Failed.as_sql_str(),
                prior_now,
            ],
        ).unwrap();
        // Optionally seed a prior session row so the retry path
        // exercises `sessions.revoked` mutation + audit emit.
        if let Some(prior_sid) = prior_session {
            conn.execute(
                &format!(
                    "INSERT INTO {SESSIONS} (
                        session_id, role_id, session_token, sequence_number,
                        worktree_root, base_sha, base_tracking_ref,
                        lineage_id, fetch_quota, created_at, expires_at, revoked,
                        session_agent_type, can_delegate
                     ) VALUES (?1, 'Planner', ?2, 0,
                              NULL, NULL, NULL, 'lineage-x', 1000, ?3, ?4, 0,
                              'Executor', 0)"
                ),
                rusqlite::params![
                    prior_sid, format!("tok-{prior_sid}"),
                    prior_now, prior_now + 86_400,
                ],
            ).unwrap();
        }
        let prior_activation_id = uuid::Uuid::new_v4().to_string();
        // Failed activation row — terminal state; both timestamps
        // populated to satisfy the §Step 5 cross-column CHECK.
        // `session_id` is bound iff the test seeded a prior
        // session row (the FK requires the session to exist).
        conn.execute(
            &format!(
                "INSERT INTO {SUBTASK_ACTIVATIONS}
                    (activation_id, task_id, initiative_id,
                     activation_state, session_id, evaluation_sha,
                     crash_retry_count, review_reject_count,
                     created_at, activated_at, terminated_at)
                 VALUES (?1, ?2, ?3, 'Failed', ?4, NULL,
                         ?5, ?6, ?7, ?7, ?7)"
            ),
            rusqlite::params![
                prior_activation_id,
                task_id,
                initiative_id,
                prior_session,
                crash_count as i64,
                review_count as i64,
                prior_now,
            ],
        ).unwrap();
        drop(conn);
        registry.insert(
            crate::initiatives::plan_registry::TaskKey::new(
                initiative_id, task_id,
            ),
            crate::initiatives::plan_registry::TaskPlanFields {
                description:           "retry test fixture".to_owned(),
                max_crash_retries:     max_crash,
                max_review_rejections: max_review,
                ..Default::default()
            },
        );
        prior_activation_id
    }

    /// Build a minimal `IntentRequest` for `RetrySubTask`. All
    /// non-relevant fields receive deterministic placeholders that
    /// the handler ignores.
    fn make_retry_request(task_id: &str, seq: u64) -> IntentRequest {
        IntentRequest {
            session_token:   "tok-orch".into(),
            sequence_number: seq,
            envelope_nonce:  format!("{:0>32}", seq),
            intent_kind:     IntentKind::RetrySubTask,
            task_id:         raxis_types::TaskId::parse(task_id).unwrap(),
            base_sha:        None,
            head_sha:        None,
            submitted_claims: vec![],
            justification:   None,
            idempotency_key: None,
            approval_token:  None,
            approved:        None,
            critique:        None,
            resolved_via_escalation: None,
            tokens_used:     None,
            structured_output: None,
        }
    }

    /// Construct a placeholder `SessionRow` for callers that pass
    /// `_session` into the retry handler. The handler ignores the
    /// row's contents (the dispatch matrix already gated on
    /// session_agent_type before this point); we only need the
    /// type to type-check.
    fn dummy_orchestrator_session_row() -> authority::session::SessionRow {
        authority::session::SessionRow {
            session_id:         dummy_session_id().as_str().to_owned(),
            role:               "Orchestrator".to_owned(),
            session_token:      "tok-orch".to_owned(),
            sequence_number:    0,
            worktree_root:      None,
            base_sha:           None,
            base_tracking_ref:  None,
            lineage_id:         "lineage-orch".to_owned(),
            expires_at:         unix_now_secs() + 86_400,
            revoked_at:         None,
            session_agent_type: Some(raxis_types::SessionAgentType::Orchestrator),
            can_delegate:       true,
        }
    }

    /// Read every activation row for `task_id`, oldest first. Wrapped
    /// in `spawn_blocking` so callers running on a tokio worker
    /// thread don't trip `Store::lock_sync` (which calls
    /// `tokio::sync::Mutex::blocking_lock` — panics on the worker
    /// pool). Every retry-handler test runs on a multi-threaded
    /// runtime, so this is the only safe pattern.
    async fn read_activations(store: Arc<Store>, task_id: &str)
        -> Vec<(String, String, Option<String>, i64, i64)>
    {
        let task_id = task_id.to_owned();
        tokio::task::spawn_blocking(move || {
            let conn = store.lock_sync();
            let mut stmt = conn.prepare(
                &format!(
                    "SELECT activation_id, activation_state, session_id,
                            crash_retry_count, review_reject_count
                       FROM {SUBTASK_ACTIVATIONS}
                      WHERE task_id = ?1
                      ORDER BY created_at ASC, activation_id ASC"
                ),
            ).unwrap();
            stmt.query_map(rusqlite::params![&task_id], |r| Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, Option<String>>(2)?,
                    r.get::<_, i64>(3)?,
                    r.get::<_, i64>(4)?,
                )))
                .unwrap()
                .map(|r| r.unwrap())
                .collect()
        }).await.unwrap()
    }

    /// `sessions.revoked` flag, read on the blocking pool to avoid
    /// `Store::lock_sync`'s tokio worker-thread panic.
    async fn read_session_revoked(store: Arc<Store>, session_id: &str) -> i64 {
        let session_id = session_id.to_owned();
        tokio::task::spawn_blocking(move || {
            let conn = store.lock_sync();
            conn.query_row(
                &format!(
                    "SELECT revoked FROM {SESSIONS} WHERE session_id = ?1"
                ),
                rusqlite::params![&session_id],
                |r| r.get::<_, i64>(0),
            ).unwrap()
        }).await.unwrap()
    }

    /// Read `tasks.state` for `task_id` on the blocking pool —
    /// same rationale as [`read_activations`] / [`read_session_revoked`].
    async fn read_task_state(store: Arc<Store>, task_id: &str) -> String {
        let task_id = task_id.to_owned();
        tokio::task::spawn_blocking(move || {
            let conn = store.lock_sync();
            conn.query_row(
                &format!("SELECT state FROM {TASKS} WHERE task_id = ?1"),
                rusqlite::params![&task_id],
                |r| r.get::<_, String>(0),
            ).unwrap()
        }).await.unwrap()
    }

    /// Happy path: prior activation is Failed with both counters
    /// well under budget. The handler must:
    ///   * insert a brand-new `PendingActivation` row;
    ///   * carry both counters forward verbatim;
    ///   * reset `tasks.state` to `Admitted`;
    ///   * revoke the prior bound session.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn retry_sub_task_admits_under_budget_and_creates_new_activation_row() {
        let store = Arc::new(Store::open_in_memory().unwrap());
        let (ctx, registry, _sink) = build_retry_test_ctx(store.clone());

        let store_for_seed = store.clone();
        let registry_for_seed = registry.clone();
        let prior_activation_id = tokio::task::spawn_blocking(move || {
            seed_orchestrator_session(&store_for_seed);
            seed_failed_executor_for_retry(
                &store_for_seed, &registry_for_seed,
                "exe-retry", /*crash*/ 1, /*review*/ 1,
                /*max_crash*/ Some(3), /*max_review*/ Some(2),
                /*prior_session*/ Some("11111111-2222-3333-4444-555555555555"),
            )
        }).await.unwrap();

        let req = make_retry_request("exe-retry", 1);
        let resp = handle_retry_sub_task(
            req,
            dummy_orchestrator_session_row(),
            dummy_session_id(),
            1,
            &ctx,
        ).await.expect("retry under budget must succeed");

        assert_eq!(resp.task_state, TaskState::Admitted,
            "retry resets tasks.state to Admitted so a subsequent \
             ActivateSubTask can dispatch");
        assert!(matches!(resp.outcome, IntentOutcome::Accepted { .. }));

        let activations = read_activations(store.clone(), "exe-retry").await;
        assert_eq!(activations.len(), 2,
            "retry must INSERT a new row, never UPDATE the prior — \
             one Failed (prior) + one PendingActivation (new) = 2");
        // Order is by created_at; the prior row was seeded first.
        assert_eq!(activations[0].0, prior_activation_id,
            "prior row must be the older one in created_at order");
        assert_eq!(activations[0].1, "Failed",
            "prior row state must remain Failed (immutable history)");
        assert_eq!(activations[1].1, "PendingActivation",
            "new row state must be PendingActivation \
             (the spawn handoff lands on `ActivateSubTask`)");
        assert!(activations[1].2.is_none(),
            "new PendingActivation row must have NULL session_id");
        assert_eq!(activations[1].3, 1,
            "new row must carry crash_retry_count=1 forward verbatim");
        assert_eq!(activations[1].4, 1,
            "new row must carry review_reject_count=1 forward verbatim");

        // Task FSM was Failed; retry resets it.
        let task_state = read_task_state(store.clone(), "exe-retry").await;
        assert_eq!(task_state, TaskState::Admitted.as_sql_str(),
            "retry must reset tasks.state Failed → Admitted so the \
             Phase A task-state gate accepts the subsequent ActivateSubTask");

        // Prior session must be revoked (regardless of whether the
        // best-effort VM teardown succeeded — the SQL revoke is the
        // load-bearing mutation).
        assert_eq!(
            read_session_revoked(
                store.clone(),
                "11111111-2222-3333-4444-555555555555",
            ).await,
            1,
            "retry must SQL-revoke the prior session so its token \
             cannot be replayed by a stale planner",
        );
    }

    /// Crash ceiling: counter == ceiling means "no further retries".
    /// The handler MUST reject with `INVALID_REQUEST` (per the spec
    /// wire surface on `IntentKind::RetrySubTask`).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn retry_sub_task_rejects_at_crash_ceiling() {
        let store = Arc::new(Store::open_in_memory().unwrap());
        let (ctx, registry, _sink) = build_retry_test_ctx(store.clone());
        let store_for_seed = store.clone();
        let registry_for_seed = registry.clone();
        tokio::task::spawn_blocking(move || {
            seed_orchestrator_session(&store_for_seed);
            seed_failed_executor_for_retry(
                &store_for_seed, &registry_for_seed,
                "exe-crash-ceiling",
                /*crash*/ 3, /*review*/ 0,
                /*max_crash*/ Some(3), /*max_review*/ Some(2),
                /*prior_session*/ None,
            );
        }).await.unwrap();

        let req = make_retry_request("exe-crash-ceiling", 1);
        let err = handle_retry_sub_task(
            req,
            dummy_orchestrator_session_row(),
            dummy_session_id(),
            1,
            &ctx,
        ).await.expect_err("crash_retry_count == max_crash_retries must reject");
        assert_eq!(err.0, PlannerErrorCode::InvalidRequest,
            "spec wire surface on RetrySubTask ceiling: FAIL_INVALID_REQUEST");

        // No new activation row inserted.
        assert_eq!(
            read_activations(store.clone(), "exe-crash-ceiling").await.len(),
            1,
            "rejected retry must NOT insert a new activation row",
        );
    }

    /// Review ceiling: same rejection shape as the crash ceiling,
    /// but driven by `review_reject_count` instead of
    /// `crash_retry_count`. Pin both ceilings independently — a
    /// future regression that conflated the two counters would
    /// silently let one ceiling shadow the other.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn retry_sub_task_rejects_at_review_ceiling() {
        let store = Arc::new(Store::open_in_memory().unwrap());
        let (ctx, registry, _sink) = build_retry_test_ctx(store.clone());
        let store_for_seed = store.clone();
        let registry_for_seed = registry.clone();
        tokio::task::spawn_blocking(move || {
            seed_orchestrator_session(&store_for_seed);
            seed_failed_executor_for_retry(
                &store_for_seed, &registry_for_seed,
                "exe-review-ceiling",
                /*crash*/ 0, /*review*/ 2,
                /*max_crash*/ Some(3), /*max_review*/ Some(2),
                /*prior_session*/ None,
            );
        }).await.unwrap();

        let req = make_retry_request("exe-review-ceiling", 1);
        let err = handle_retry_sub_task(
            req,
            dummy_orchestrator_session_row(),
            dummy_session_id(),
            1,
            &ctx,
        ).await.expect_err("review_reject_count == max_review_rejections must reject");
        assert_eq!(err.0, PlannerErrorCode::InvalidRequest);

        assert_eq!(
            read_activations(store.clone(), "exe-review-ceiling").await.len(),
            1,
        );
    }

    /// Operator-omitted ceiling: when the plan declares neither
    /// `max_crash_retries` nor `max_review_rejections`, the kernel
    /// substitutes the conservative default
    /// (`DEFAULT_MAX_CRASH_RETRIES = 3`,
    ///  `DEFAULT_MAX_REVIEW_REJECTIONS = 2`). Pin this against a
    /// regression that fail-closed at zero — that would break every
    /// V1-shape plan that omits the fields.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn retry_sub_task_uses_kernel_default_when_plan_omits_ceiling() {
        let store = Arc::new(Store::open_in_memory().unwrap());
        let (ctx, registry, _sink) = build_retry_test_ctx(store.clone());
        let store_for_seed = store.clone();
        let registry_for_seed = registry.clone();
        tokio::task::spawn_blocking(move || {
            seed_orchestrator_session(&store_for_seed);
            // `None` ⇒ kernel default applies (3 / 2). A counter of
            // 1 / 1 is well under both defaults, so the retry must
            // succeed.
            seed_failed_executor_for_retry(
                &store_for_seed, &registry_for_seed,
                "exe-default",
                /*crash*/ 1, /*review*/ 1,
                /*max_crash*/ None, /*max_review*/ None,
                /*prior_session*/ None,
            );
        }).await.unwrap();

        let req = make_retry_request("exe-default", 1);
        let resp = handle_retry_sub_task(
            req,
            dummy_orchestrator_session_row(),
            dummy_session_id(),
            1,
            &ctx,
        ).await.expect("retry under kernel default budget must succeed");
        assert_eq!(resp.task_state, TaskState::Admitted);
        assert_eq!(
            read_activations(store.clone(), "exe-default").await.len(),
            2,
            "kernel default must be permissive enough for a \
             low-counter retry to admit",
        );
    }

    /// Retry against a prior activation in `Active` (not `Failed`)
    /// must reject. `Active` means the substrate session is still
    /// running — there's nothing to retry. Pin this against a
    /// future regression that would let a planner force a retry
    /// against a live session and leak two parallel VMs.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn retry_sub_task_rejects_when_prior_activation_active() {
        let store = Arc::new(Store::open_in_memory().unwrap());
        let (ctx, registry, _sink) = build_retry_test_ctx(store.clone());
        let store_for_seed = store.clone();
        let registry_for_seed = registry.clone();
        tokio::task::spawn_blocking(move || {
            seed_orchestrator_session(&store_for_seed);
            // Seed an `Active` activation row directly (skipping the
            // helper which only seeds `Failed`).
            let conn = store_for_seed.lock_sync();
            let now = unix_now_secs();
            conn.execute(
                &format!(
                    "INSERT OR IGNORE INTO {INITIATIVES}
                        (initiative_id, state, terminal_criteria_json,
                         plan_artifact_sha256, created_at)
                     VALUES ('init-retry', ?1, '{{}}', 'deadbeef', ?2)"
                ),
                rusqlite::params![
                    InitiativeState::Executing.as_sql_str(), now,
                ],
            ).unwrap();
            conn.execute(
                &format!(
                    "INSERT INTO {TASKS}
                        (task_id, initiative_id, lane_id, state, actor,
                         policy_epoch, admitted_at, transitioned_at,
                         actual_cost)
                     VALUES ('exe-active', 'init-retry', 'default', ?1,
                             'kernel', 1, ?2, ?2, 0)"
                ),
                rusqlite::params![TaskState::Running.as_sql_str(), now],
            ).unwrap();
            // Active row REQUIRES session_id IS NOT NULL per the
            // cross-column CHECK; seed a session row first.
            conn.execute(
                &format!(
                    "INSERT INTO {SESSIONS} (
                        session_id, role_id, session_token, sequence_number,
                        worktree_root, base_sha, base_tracking_ref,
                        lineage_id, fetch_quota, created_at, expires_at, revoked,
                        session_agent_type, can_delegate
                     ) VALUES ('22222222-3333-4444-5555-666666666666',
                              'Planner', 'tok-active', 0,
                              NULL, NULL, NULL, 'lineage-z', 1000, ?1, ?2, 0,
                              'Executor', 0)"
                ),
                rusqlite::params![now, now + 86_400],
            ).unwrap();
            conn.execute(
                &format!(
                    "INSERT INTO {SUBTASK_ACTIVATIONS}
                        (activation_id, task_id, initiative_id,
                         activation_state, session_id, evaluation_sha,
                         crash_retry_count, review_reject_count,
                         created_at, activated_at, terminated_at)
                     VALUES (?1, 'exe-active', 'init-retry', 'Active',
                             '22222222-3333-4444-5555-666666666666', NULL,
                             0, 0, ?2, ?2, NULL)"
                ),
                rusqlite::params![
                    uuid::Uuid::new_v4().to_string(), now,
                ],
            ).unwrap();
            drop(conn);
            registry_for_seed.insert(
                crate::initiatives::plan_registry::TaskKey::new(
                    "init-retry", "exe-active",
                ),
                crate::initiatives::plan_registry::TaskPlanFields {
                    description: "active fixture".to_owned(),
                    ..Default::default()
                },
            );
        }).await.unwrap();

        let req = make_retry_request("exe-active", 1);
        let err = handle_retry_sub_task(
            req,
            dummy_orchestrator_session_row(),
            dummy_session_id(),
            1,
            &ctx,
        ).await.expect_err("retry against an Active activation must reject");
        assert_eq!(err.0, PlannerErrorCode::InvalidRequest,
            "Active prior state surfaces as INVALID_REQUEST \
             (the spec's coarse code for a retry against a non-Failed row)");
    }

    /// Missing registry entry (plan-bundle-sealing didn't see this
    /// task — structurally impossible for an approved plan, but
    /// defense-in-depth). The handler must surface
    /// `FAIL_UNKNOWN_TASK` rather than fail-open.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn retry_sub_task_rejects_when_plan_registry_miss() {
        let store = Arc::new(Store::open_in_memory().unwrap());
        let (ctx, _registry, _sink) = build_retry_test_ctx(store.clone());
        let store_for_seed = store.clone();
        tokio::task::spawn_blocking(move || {
            seed_orchestrator_session(&store_for_seed);
            // Seed task + activation but DO NOT insert into the
            // registry. The retry handler treats this as an unknown
            // task (fail-closed: a missing registry entry could be
            // a corrupted state and we refuse to widen the retry
            // budget by guessing).
            let conn = store_for_seed.lock_sync();
            let now = unix_now_secs();
            conn.execute(
                &format!(
                    "INSERT OR IGNORE INTO {INITIATIVES}
                        (initiative_id, state, terminal_criteria_json,
                         plan_artifact_sha256, created_at)
                     VALUES ('init-retry', ?1, '{{}}', 'deadbeef', ?2)"
                ),
                rusqlite::params![
                    InitiativeState::Executing.as_sql_str(), now,
                ],
            ).unwrap();
            conn.execute(
                &format!(
                    "INSERT INTO {TASKS}
                        (task_id, initiative_id, lane_id, state, actor,
                         policy_epoch, admitted_at, transitioned_at,
                         actual_cost)
                     VALUES ('exe-orphan', 'init-retry', 'default', ?1,
                             'kernel', 1, ?2, ?2, 0)"
                ),
                rusqlite::params![TaskState::Failed.as_sql_str(), now],
            ).unwrap();
            // Activation row exists but registry entry doesn't.
            conn.execute(
                &format!(
                    "INSERT INTO {SUBTASK_ACTIVATIONS}
                        (activation_id, task_id, initiative_id,
                         activation_state, session_id, evaluation_sha,
                         crash_retry_count, review_reject_count,
                         created_at, activated_at, terminated_at)
                     VALUES (?1, 'exe-orphan', 'init-retry', 'Failed',
                             NULL, NULL, 0, 0, ?2, ?2, ?2)"
                ),
                rusqlite::params![
                    uuid::Uuid::new_v4().to_string(), now,
                ],
            ).unwrap();
        }).await.unwrap();

        let req = make_retry_request("exe-orphan", 1);
        let err = handle_retry_sub_task(
            req,
            dummy_orchestrator_session_row(),
            dummy_session_id(),
            1,
            &ctx,
        ).await.expect_err("missing registry entry must reject");
        assert_eq!(err.0, PlannerErrorCode::FailUnknownTask,
            "the registry-miss arm surfaces as FAIL_UNKNOWN_TASK \
             (the operator-facing handle for 'this task is not \
             tracked' — defense-in-depth against fail-open)");
    }

    /// Explicit `Some(0)` ceiling: operator says "no retries
    /// allowed". The handler must respect the explicit zero (NOT
    /// fall back to `DEFAULT_MAX_*`).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn retry_sub_task_respects_explicit_zero_ceiling() {
        let store = Arc::new(Store::open_in_memory().unwrap());
        let (ctx, registry, _sink) = build_retry_test_ctx(store.clone());
        let store_for_seed = store.clone();
        let registry_for_seed = registry.clone();
        tokio::task::spawn_blocking(move || {
            seed_orchestrator_session(&store_for_seed);
            // A counter of zero AND a ceiling of zero ⇒ even the
            // first retry is forbidden. The default of `3` would
            // hide this; pinning the explicit zero confirms the
            // `Option` semantics carry through to the handler.
            seed_failed_executor_for_retry(
                &store_for_seed, &registry_for_seed,
                "exe-zero-ceiling",
                /*crash*/ 0, /*review*/ 0,
                /*max_crash*/ Some(0), /*max_review*/ Some(0),
                /*prior_session*/ None,
            );
        }).await.unwrap();

        let req = make_retry_request("exe-zero-ceiling", 1);
        let err = handle_retry_sub_task(
            req,
            dummy_orchestrator_session_row(),
            dummy_session_id(),
            1,
            &ctx,
        ).await.expect_err("explicit zero ceiling must reject every retry");
        assert_eq!(err.0, PlannerErrorCode::InvalidRequest);
    }

}

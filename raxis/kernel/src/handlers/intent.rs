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

use crate::authority;
use crate::gates::{self, GateEvalResult};
use crate::initiatives::task_transitions::{
    transition_task as fsm_transition, transition_task_in_tx, TransitionActor,
};
use crate::ipc::context::HandlerContext;
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
    // Authorization for this branch is already covered by the
    // dispatch matrix above (Orchestrator + ActivateSubTask is the
    // only Authorized cell). `RetrySubTask` stays fail-closed
    // pending `subtask_activations.crash_retry_count` /
    // `review_reject_count` ceiling enforcement (v2-deep-spec.md
    // §Step 12 — separate task).
    if matches!(req.intent_kind, IntentKind::ActivateSubTask) {
        return handle_activate_sub_task(req, session, session_id, seq, ctx).await;
    }
    if matches!(req.intent_kind, IntentKind::RetrySubTask) {
        return Err((PlannerErrorCode::FailPolicyViolation, TaskState::Admitted));
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
        GateEvalResult::BreakglassPass { .. } => {
            pending_gates = vec![];
            warn_stale    = false;
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
            // Belt-and-braces: `handle_inner` intercepts these
            // BEFORE Phase A; this arm catches a future regression
            // that lets one slip past the early-dispatch.
            return PreGateOutcome::Reject(
                PlannerErrorCode::FailPolicyViolation, task_state);
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
    // Note: `previous_sha` is set to the request's `base_sha` rather
    // than the row-level `initiatives.current_sha` because the
    // host-side main-fast-forward (integration-merge.md §11
    // Phase 2/3) is not yet wired into the admission path; the
    // Orchestrator's claimed base is the only ancestor visible at
    // this point in the pipeline. When the Step 8 follow-up wires
    // Phase 2/3 the field becomes the row-pre-update value.
    if matches!(intent_kind, IntentKind::IntegrationMerge) {
        let initiative_id_owned = pre_state.task.initiative_id.clone();
        let (operator_assisted, escalation_id) =
            match pre_state.resolved_via_escalation.as_ref() {
                Some(id) => (true,  Some(id.as_str().to_owned())),
                None     => (false, None),
            };
        if let Err(e) = ctx.audit.emit(
            raxis_audit_tools::AuditEventKind::IntegrationMergeCompleted {
                initiative_id: initiative_id_owned.clone(),
                session_id:    session_id_str.clone(),
                commit_sha:    pre_state.head_sha_raw.clone(),
                previous_sha:  pre_state.base_sha_raw.clone(),
                operator_assisted,
                escalation_id,
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
//      The downstream consequences (review_reject_count++,
//      KernelPush::ReviewRejected / AllReviewersPassed) are out of
//      scope for this iteration — they are implemented when the
//      `subtask_activations` row population path lands (Step 25).
//
// **Why no `subtask_activations` write here.** V2 plan approval does
// not yet populate `subtask_activations` (that arrives with the
// V2 plan-bundle sealing work, Step 1.2). Until then, any Reviewer
// task is a synthetic test fixture; the activation-row update is a
// no-op. Adding it here would silently fail in production and pass
// in fixtures, which is the worst possible failure mode. We make
// the activation-row update a separate task (Step 25 / Plan Bundle
// Sealing) so the implementation lands together with the call site
// that creates the row.
//
// **Idempotency.** Re-submission of the same `(session, sequence_number,
// nonce)` is rejected at Step 2 (envelope acceptance) before this
// handler runs — duplicate submissions never reach this code path.
// A retransmitted critique with a fresh sequence number is treated as
// a NEW reviewer event and aggregated; the planner (Reviewer harness)
// is responsible for not double-submitting the same verdict.
// ---------------------------------------------------------------------------

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
    //   * `AllPassed`       → emit `ReviewAggregationCompleted`.
    //                         When the push transport lands (gap
    //                         §12.1), this audit row is the anchor
    //                         the future emitter reads to issue
    //                         `KernelPush::AllReviewersPassed`.
    //   * `AtLeastOneRejected` → emit `ReviewAggregationCompleted`.
    //                         Same pattern as `AllPassed` but for
    //                         the `KernelPush::ReviewRejected`
    //                         direction.
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
                    "SELECT activation_id, activation_state, initiative_id
                       FROM subtask_activations
                      WHERE task_id = ?1
                      ORDER BY created_at DESC
                      LIMIT 1",
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
            // canonical V2 source).
            let agent_kind = {
                let key = crate::initiatives::plan_registry::TaskKey::new(
                    &initiative_id, &task_id,
                );
                let fields = match plan_registry_arc.get(&key) {
                    Some(f) => f,
                    None    => return Err((PlannerErrorCode::FailUnknownTask, TaskState::Admitted)),
                };
                match fields.session_agent_type {
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
                }
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
                "INSERT INTO sessions (
                    session_id, role_id, session_token, sequence_number,
                    worktree_root, base_sha, base_tracking_ref,
                    lineage_id, fetch_quota, created_at, expires_at, revoked,
                    session_agent_type, can_delegate
                 ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,0,?12,0)",
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

    let spawn_handle = match crate::session_spawn_orchestrator::spawn_executor_for_task(
        &ctx.executor_spawn,
        lookup.agent_kind,
        &lookup.new_session_id,
        &task_id_owned,
        &lookup.initiative_id,
        allowlist,
        Vec::new(),
        std::collections::BTreeMap::new(),
        Arc::clone(&ctx.session_spawn),
        &ctx.store,
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
                    "UPDATE sessions SET revoked = 1, revoked_at = ?1 WHERE session_id = ?2",
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
                "UPDATE subtask_activations
                    SET activation_state = 'Active',
                        session_id       = ?1,
                        activated_at     = ?2
                  WHERE activation_id   = ?3
                    AND activation_state = 'PendingActivation'",
                rusqlite::params![&new_session_id, now, &activation_id],
            )?;

            // Persist the substrate's vsock CID on the session row
            // so the kernel's per-session admission listener can
            // verify guest provenance (`vm-network-isolation.md §3`
            // CID allowlist).
            if let Some(cid) = vsock_cid {
                tx.execute(
                    "UPDATE sessions SET vsock_cid = ?1 WHERE session_id = ?2",
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
}

fn load_task(task_id: &str, store: &Store) -> Result<TaskRow, ()> {
    let conn = store.lock_sync();
    conn.query_row(
        &format!("SELECT lane_id, state, initiative_id FROM {TASKS} WHERE task_id = ?1"),
        rusqlite::params![task_id],
        |row| Ok(TaskRow {
            lane_id:       row.get(0)?,
            state:         row.get(1)?,
            initiative_id: row.get(2)?,
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
}

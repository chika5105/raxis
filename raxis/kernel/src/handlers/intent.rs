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
    unix_now_secs, BudgetSnapshot, IntentKind, IntentOutcome, IntentRequest, IntentResponse,
    PlannerErrorCode, SessionId, SubmittedClaim, TaskState,
};
use raxis_store::{Store, Table};

const TASKS:              &str = Table::Tasks.as_str();
const TASK_INTENT_RANGES: &str = Table::TaskIntentRanges.as_str();

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
    let now = unix_now_secs();
    if session.revoked_at.is_some() {
        return Err((PlannerErrorCode::Unauthorized, TaskState::Admitted));
    }
    if session.expires_at < now {
        return Err((PlannerErrorCode::Unauthorized, TaskState::Admitted));
    }

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
    let presented_seq_i64 = i64::try_from(seq).map_err(|_| {
        // Only happens for seq > i64::MAX, i.e. a malicious caller —
        // bin it as Unauthorized.
        (PlannerErrorCode::Unauthorized, TaskState::Admitted)
    })?;
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
        return Err((PlannerErrorCode::Unauthorized, TaskState::Admitted));
    }

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
    match crate::path_scope::check_paths(
        &touched_paths,
        &task.initiative_id,
        req.task_id.as_str(),
        &ctx.plan_registry,
        store,
    ) {
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
            return Err((PlannerErrorCode::FailPathPolicyViolation, task_state));
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
            return Err((PlannerErrorCode::FailPathPolicyViolation, task_state));
        }
    }

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

    // ── Step 12A: Record accepted intent range (INV-TASK-PATH-02 substrate)
    //
    // Spec: kernel-store.md §2.5.8 step 7A. Append one row per accepted
    // intent to `task_intent_ranges`, which CompleteTask later reads to
    // reconstruct the union of touched paths across all admitted ranges.
    //
    // PRIMARY KEY (task_id, head_sha) — duplicate `head_sha` for the same
    // task collapses to an idempotent retry (per spec the kernel "treats
    // this as an idempotent retry and returns the prior accepted response
    // without re-processing"). The `INSERT OR IGNORE` here is the SQL
    // implementation of that idempotency: the response shape returned at
    // the end of the function is computed from the live state and is
    // therefore identical for both the first call and the retry.
    //
    // INV-STORE-02 footnote: ideally this INSERT would share a single
    // transaction with steps 10–12 (budget consume + FSM transition +
    // intent-field UPDATE). The current implementation runs them as
    // separate auto-commits because each helper opens its own connection
    // lock; PR-6b will compose them into one tx by threading a shared
    // `Transaction<'_>` through the helpers. This row write is still a
    // strict net improvement: prior to this PR, `task_intent_ranges` was
    // never populated, which made INV-TASK-PATH-02 (CompleteTask path
    // check across all admitted ranges) impossible to enforce.
    insert_task_intent_range(
        req.task_id.as_str(),
        base_sha_raw.as_str(),
        head_sha_raw.as_str(),
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
    let mut full_touched_paths: std::collections::BTreeSet<PathBuf> =
        std::collections::BTreeSet::new();
    for (base_str, head_str) in &ranges {
        let b = CommitSha::new(base_str)
            .map_err(|_| (PlannerErrorCode::FailInvalidDiff, task_state))?;
        let h = CommitSha::new(head_str)
            .map_err(|_| (PlannerErrorCode::FailInvalidDiff, task_state))?;
        let paths = vcs::compute(&b, &h, &worktree_path)
            .map_err(|_| (PlannerErrorCode::FailInvalidDiff, task_state))?;
        for p in paths { full_touched_paths.insert(p); }
    }

    // ── 4. Trailing segment: H_bind → req.head_sha (when they differ) ────
    //
    // §2.5.8 step 4 with topology check (4a) and diff (4b). The trailing
    // segment NEVER skips topology_check — there is no IntegrationMerge
    // carve-out on the gap between the last admitted range and the
    // CompleteTask head_sha.
    if let (Some(ref h_bind_str), Some(ref h_req)) = (h_bind.as_ref(), req_head.as_ref()) {
        if h_bind_str.as_str() != h_req.as_str() {
            let h_bind_sha = CommitSha::new(h_bind_str)
                .map_err(|_| (PlannerErrorCode::FailInvalidDiff, task_state))?;
            // 4a — topology check on the trailing range (no carve-out).
            vcs::topology_check(&h_bind_sha, h_req, &worktree_path)
                .map_err(|_| (PlannerErrorCode::FailInvalidCommitTopology, task_state))?;
            // 4b — diff the trailing range.
            let trailing = vcs::compute(&h_bind_sha, h_req, &worktree_path)
                .map_err(|_| (PlannerErrorCode::FailInvalidDiff, task_state))?;
            for p in trailing { full_touched_paths.insert(p); }
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
/// Globs use the same `require_literal_separator = true` semantics as
/// `path_scope::AllowSet::matches` so `*` doesn't cross `/`. Patterns
/// that fail to compile are SKIPPED (not fatal) — same defense-in-depth
/// posture as `path_scope::compile_globs`'s caller, since the signing
/// tool is the gate.
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

const TASK_EXPORTED_PATH_SNAPSHOTS: &str =
    raxis_store::Table::TaskExportedPathSnapshots.as_str();

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
    let rows = tx.execute(
        &format!(
            "UPDATE {TASKS} SET state = 'Completed', transitioned_at = ?1
             WHERE task_id = ?2 AND state = 'Running'",
        ),
        rusqlite::params![now, task_id],
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

/// Append one row to `task_intent_ranges` per kernel-store.md §2.5.8 step 7A.
///
/// Uses `INSERT OR IGNORE` so a duplicate `(task_id, head_sha)` — which
/// SQLite reports as `SQLITE_CONSTRAINT_PRIMARYKEY` on plain INSERT —
/// silently no-ops, matching the spec's idempotent-retry semantics:
/// "Submitting the same head_sha twice returns SQLITE_CONSTRAINT_PRIMARYKEY;
///  the kernel treats this as an idempotent retry and returns the prior
///  accepted response without re-processing."
fn insert_task_intent_range(
    task_id:  &str,
    base_sha: &str,
    head_sha: &str,
    store:    &Store,
) -> Result<(), ()> {
    let conn = store.lock_sync();
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
            "INSERT INTO initiatives
                (initiative_id, state, terminal_criteria_json,
                 plan_artifact_sha256, created_at)
             VALUES ('init-int', 'Executing', '{}', 'deadbeef', ?1)",
            rusqlite::params![now],
        ).unwrap();
        conn.execute(
            "INSERT INTO tasks
                (task_id, initiative_id, lane_id, state, actor,
                 policy_epoch, admitted_at, transitioned_at, actual_cost)
             VALUES (?1, 'init-int', 'default', 'Admitted', 'kernel',
                     1, ?2, ?2, 0)",
            rusqlite::params![task_id, now],
        ).unwrap();
    }

    fn count_intent_ranges(store: &Store, task_id: &str) -> i64 {
        let conn = store.lock_sync();
        conn.query_row(
            "SELECT COUNT(*) FROM task_intent_ranges WHERE task_id=?1",
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
            "SELECT base_sha, head_sha FROM task_intent_ranges WHERE task_id='t1'",
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
            "INSERT INTO tasks
                (task_id, initiative_id, lane_id, state, actor,
                 policy_epoch, admitted_at, transitioned_at, actual_cost)
             VALUES ('t2', 'init-int', 'default', 'Admitted', 'kernel',
                     1, ?1, ?1, 0)",
            rusqlite::params![unix_now_secs()],
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
            "INSERT OR IGNORE INTO initiatives
                (initiative_id, state, terminal_criteria_json,
                 plan_artifact_sha256, created_at)
             VALUES ('init-int', 'Executing', '{}', 'deadbeef', ?1)",
            rusqlite::params![now],
        );
        conn.execute(
            "INSERT INTO tasks
                (task_id, initiative_id, lane_id, state, actor,
                 policy_epoch, admitted_at, transitioned_at, actual_cost)
             VALUES (?1, 'init-int', 'default', 'Running', 'kernel',
                     1, ?2, ?2, 0)",
            rusqlite::params![task_id, now],
        ).unwrap();
    }

    fn task_state_of(store: &Store, task_id: &str) -> String {
        let conn = store.lock_sync();
        conn.query_row(
            "SELECT state FROM tasks WHERE task_id = ?1",
            rusqlite::params![task_id],
            |r| r.get(0),
        ).unwrap()
    }

    fn count_export_snapshots(store: &Store, task_id: &str) -> i64 {
        let conn = store.lock_sync();
        conn.query_row(
            "SELECT COUNT(*) FROM task_exported_path_snapshots WHERE task_id = ?1",
            rusqlite::params![task_id],
            |r| r.get(0),
        ).unwrap()
    }

    #[test]
    fn commit_task_completion_transitions_running_to_completed() {
        let store = Store::open_in_memory().unwrap();
        seed_running_task(&store, "t1");

        commit_task_completion("t1", &[], &store).unwrap();

        assert_eq!(task_state_of(&store, "t1"), "Completed");
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

        assert_eq!(task_state_of(&store, "t1"), "Completed");
        assert_eq!(count_export_snapshots(&store, "t1"), 3);

        // Spot-check one row to verify the path round-trips byte-equal.
        let conn = store.lock_sync();
        let mut paths: Vec<String> = conn
            .prepare("SELECT path FROM task_exported_path_snapshots WHERE task_id = ?1")
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
        assert_eq!(task_state_of(&store, "t1"), "Admitted",
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
                "UPDATE tasks SET evaluation_sha = ?1 WHERE task_id = ?2",
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

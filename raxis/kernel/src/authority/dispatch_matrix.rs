// raxis-kernel::authority::dispatch_matrix — Static (intent_kind, agent_type)
// authorization table.
//
// Normative reference: v2-deep-spec.md §Step 20 ("Static Dispatch Matrix —
// Pre-Routing Before Handler Invocation").
//
// ## Why a static matrix?
//
// V1 routed intents on `IntentKind` alone. In V2 the same kind can be
// authorized OR unauthorized depending on the submitting session's
// `session_agent_type` (Orchestrator / Executor / Reviewer). Discovering
// that authorization mismatch inside individual handlers — after parsing
// the full request body, loading the session, joining tables — wastes
// cycles and exposes a wide attack surface. A single static matrix
// evaluated immediately after deserialization closes the gap.
//
// **Authority property (INV-DISPATCH):** This matrix is the *sole* place
// in the Kernel that maps `(IntentKind, SessionAgentType)` to an
// authorization verdict. Handlers do NOT consult `session_agent_type`
// for authorization. The only handler-side gate that touches agent
// identity is `can_delegate` on `ActivateSubTask` / `RetrySubTask`,
// which is a boolean field gate — not an agent-type membership test
// (INV-DELEGATE-01 enforces the boolean ⇔ Orchestrator equivalence
// at the DB CHECK constraint).
//
// ## V1 backward compatibility
//
// Sessions created before Migration 5 have `session_agent_type = NULL`
// (see `kernel-store.md` Migration 5; `agent_type` is a nullable column).
// We model that on the Rust side as `agent_type: Option<SessionAgentType>`.
// `None` ⇒ V1 session: the matrix authorizes the four V1-era intent
// kinds (`SingleCommit`, `IntegrationMerge`, `CompleteTask`,
// `ReportFailure`) and unauthorizes every V2 sub-task kind. A V1
// session that somehow tries an `ActivateSubTask` is fail-closed.
//
// ## Wire-shape contract
//
// `Unauthorized` MUST surface to the planner as
// `PlannerErrorCode::FailPolicyViolation` with NO error_detail
// (INV-08 — coarse codes; we never leak which check fired). The
// matrix is internal-only — no projection of cell decisions appears
// on any wire surface.
//
// ## Test obligations
//
// 1. Exhaustive coverage: every `(IntentKind, agent_type)` cell tested
//    once. The compiler enforces the IntentKind match exhaustively;
//    `IntentKind::ALL` and `SessionAgentType::ALL` keep the test
//    helpers in lock-step with future additions.
// 2. INV-DISPATCH symmetry: a property-style test asserts that
//    `Reviewer` cannot submit any commit-pathway intent (SingleCommit,
//    IntegrationMerge), and `Executor` cannot submit any delegation
//    intent (ActivateSubTask, RetrySubTask). Reviewer cannot
//    SubmitReview-on-behalf-of-others, etc.
// 3. V1 NULL-agent-type compatibility row.

use raxis_types::{IntentKind, SessionAgentType};

/// The verdict of `evaluate_dispatch`. `Unauthorized` is a coarse
/// rejection — the caller is expected to translate it into
/// `PlannerErrorCode::FailPolicyViolation` and emit the
/// `IntentResponse::Rejected` envelope. The verdict carries no further
/// detail because INV-08 forbids leaking matrix internals on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DispatchVerdict {
    /// The session may submit this intent kind. Handler invocation
    /// proceeds. Note: this verdict ONLY confirms type-level authority;
    /// the handler is still responsible for boolean-field gates
    /// (`can_delegate` for `ActivateSubTask` / `RetrySubTask`), session
    /// liveness (revoked / expired), and per-task FSM rules.
    Authorized,

    /// The session is forbidden to submit this intent kind. The IPC
    /// dispatcher MUST short-circuit to `FailPolicyViolation` without
    /// invoking the handler.
    Unauthorized,
}

impl DispatchVerdict {
    pub fn is_authorized(self) -> bool {
        matches!(self, Self::Authorized)
    }
}

/// Evaluate the static dispatch matrix for one
/// `(intent_kind, session_agent_type)` pair.
///
/// `session_agent_type = None` ⇒ V1 backward-compat row.
///
/// Compile-time complete: the inner `match` is exhaustive on both
/// `IntentKind` and `SessionAgentType`; adding a variant to either
/// enum forces a recompile here, surfacing the matrix-update
/// requirement at type-check time.
pub fn evaluate_dispatch(
    intent_kind: IntentKind,
    session_agent_type: Option<SessionAgentType>,
) -> DispatchVerdict {
    use DispatchVerdict::*;
    use IntentKind::*;
    use SessionAgentType::*;

    match (intent_kind, session_agent_type) {
        // ── V1 backward-compat row (NULL `session_agent_type`) ────────
        // Pre-Migration-5 sessions carry the four V1 intent kinds;
        // V2 sub-task kinds are unauthorized.
        (SingleCommit, None) => Authorized,
        (IntegrationMerge, None) => Authorized,
        (CompleteTask, None) => Authorized,
        (ReportFailure, None) => Authorized,
        (ActivateSubTask, None) => Unauthorized,
        (RetrySubTask, None) => Unauthorized,
        (SubmitReview, None) => Unauthorized,
        // V2 §3.2: V1 sessions cannot emit StructuredOutput.
        (StructuredOutput, None) => Unauthorized,
        // V3 — same authority pattern as the other sub-task
        // lifecycle kinds: V1 NULL sessions cannot delegate.
        (AddSubTask, None) => Unauthorized,
        // V3 iter70 — batch-admit primitive: same authority shape
        // as singular ActivateSubTask. V1 NULL sessions cannot
        // delegate, so the batch wrapper is fail-closed too.
        (BatchActivateSubTasks, None) => Unauthorized,

        // ── Orchestrator row ─────────────────────────────────────────
        // Step 8: Orchestrator owns IntegrationMerge (and only the
        // Orchestrator submits it).
        // Step 6 / INV-DELEGATE-01: Orchestrator is the unique
        // delegator (ActivateSubTask, RetrySubTask, AddSubTask).
        // SingleCommit is rejected: the Orchestrator is the merger,
        // not a code-author. ReportFailure is allowed so the
        // Orchestrator can self-fail an initiative when its DAG
        // surfaces a ceiling breach. CompleteTask is allowed for
        // the orchestrator's own task closure.
        // SubmitReview is Reviewer-only.
        (SingleCommit, Some(Orchestrator)) => Unauthorized,
        (IntegrationMerge, Some(Orchestrator)) => Authorized,
        (CompleteTask, Some(Orchestrator)) => Authorized,
        (ReportFailure, Some(Orchestrator)) => Authorized,
        (ActivateSubTask, Some(Orchestrator)) => Authorized,
        (RetrySubTask, Some(Orchestrator)) => Authorized,
        (SubmitReview, Some(Orchestrator)) => Unauthorized,
        // V2 §3.2: Orchestrator can emit a TaskSummary handoff /
        // ProgressReport / DiagnosticFlag mid-DAG.
        (StructuredOutput, Some(Orchestrator)) => Authorized,
        // V3
        // (`specs/v3/gate-rejection-orchestrator-fixup.md` §4.3):
        // Orchestrator is the SOLE authority that may admit a
        // runtime sub-task row not declared in the signed plan
        // (gate-fixup task). Reviewer / Executor / V1 sessions
        // are fail-closed at the matrix.
        (AddSubTask, Some(Orchestrator)) => Authorized,
        // V3 iter70 — batch-admit primitive: the Orchestrator
        // is the unique delegator and therefore the unique
        // submitter of the bulk variant. Same authority as
        // singular `ActivateSubTask` (per-id admission machinery
        // is the singular path re-used unchanged; INV-IPC-BATCH-
        // REUSE-SINGULAR-MACHINERY-01).
        (BatchActivateSubTasks, Some(Orchestrator)) => Authorized,

        // ── Executor row ─────────────────────────────────────────────
        // The Executor's job is to produce commits and complete
        // its sub-task. It does NOT delegate (no ActivateSubTask /
        // RetrySubTask / AddSubTask) and it does NOT integrate
        // (Step 8 — IntegrationMerge is Orchestrator-only). Reviewer
        // intent is also off-limits.
        (SingleCommit, Some(Executor)) => Authorized,
        (IntegrationMerge, Some(Executor)) => Unauthorized,
        (CompleteTask, Some(Executor)) => Authorized,
        (ReportFailure, Some(Executor)) => Authorized,
        (ActivateSubTask, Some(Executor)) => Unauthorized,
        (RetrySubTask, Some(Executor)) => Unauthorized,
        (SubmitReview, Some(Executor)) => Unauthorized,
        // V2 §3.2: Executor emits ProgressReport / DiagnosticFlag /
        // TaskSummary mid-task.
        (StructuredOutput, Some(Executor)) => Authorized,
        (AddSubTask, Some(Executor)) => Unauthorized,
        // V3 iter70: Executors do not delegate; the batch primitive
        // is Orchestrator-only.
        (BatchActivateSubTasks, Some(Executor)) => Unauthorized,

        // ── Reviewer row ─────────────────────────────────────────────
        // The Reviewer's only authorized intent is SubmitReview.
        // INV-PLANNER-HARNESS-01 + planner-harness.md §3 (tool surface
        // table) + planner-harness.md §6: the Reviewer has no
        // commit-pathway intent (no SingleCommit, no IntegrationMerge),
        // no delegation, no completion (its lifecycle is governed by
        // subtask_activations, not the V1 task FSM), and no
        // ReportFailure (the canonical "I cannot review this" path is
        // SubmitReview { approved: false, critique: ... }, NOT a
        // V1-style failure self-report).
        (SingleCommit, Some(Reviewer)) => Unauthorized,
        (IntegrationMerge, Some(Reviewer)) => Unauthorized,
        (CompleteTask, Some(Reviewer)) => Unauthorized,
        (ReportFailure, Some(Reviewer)) => Unauthorized,
        (ActivateSubTask, Some(Reviewer)) => Unauthorized,
        (RetrySubTask, Some(Reviewer)) => Unauthorized,
        (SubmitReview, Some(Reviewer)) => Authorized,
        // V2 §3.2 / INV-PLANNER-HARNESS-02: Reviewer is a
        // Pure-Static actor and NEVER emits structured output.
        (StructuredOutput, Some(Reviewer)) => Unauthorized,
        (AddSubTask, Some(Reviewer)) => Unauthorized,
        // V3 iter70: Reviewer is Pure-Static; no delegation,
        // no batch primitive.
        (BatchActivateSubTasks, Some(Reviewer)) => Unauthorized,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// The matrix is a 10×4 grid (10 intent kinds × 3 agent types
    /// + 1 NULL backward-compat row) with each cell labelled
    /// `Authorized` or `Unauthorized`. We enumerate every cell
    /// explicitly so that any future table-edit silently breaks
    /// this test instead of silently widening or tightening
    /// authority.
    #[test]
    fn matrix_authorizes_exactly_the_expected_cells() {
        // (kind, agent_type, expected_verdict)
        let expectations = [
            // V1 NULL row
            (IntentKind::SingleCommit, None, true),
            (IntentKind::IntegrationMerge, None, true),
            (IntentKind::CompleteTask, None, true),
            (IntentKind::ReportFailure, None, true),
            (IntentKind::ActivateSubTask, None, false),
            (IntentKind::RetrySubTask, None, false),
            (IntentKind::SubmitReview, None, false),
            (IntentKind::StructuredOutput, None, false),
            (IntentKind::AddSubTask, None, false),
            (IntentKind::BatchActivateSubTasks, None, false),
            // Orchestrator
            (
                IntentKind::SingleCommit,
                Some(SessionAgentType::Orchestrator),
                false,
            ),
            (
                IntentKind::IntegrationMerge,
                Some(SessionAgentType::Orchestrator),
                true,
            ),
            (
                IntentKind::CompleteTask,
                Some(SessionAgentType::Orchestrator),
                true,
            ),
            (
                IntentKind::ReportFailure,
                Some(SessionAgentType::Orchestrator),
                true,
            ),
            (
                IntentKind::ActivateSubTask,
                Some(SessionAgentType::Orchestrator),
                true,
            ),
            (
                IntentKind::RetrySubTask,
                Some(SessionAgentType::Orchestrator),
                true,
            ),
            (
                IntentKind::SubmitReview,
                Some(SessionAgentType::Orchestrator),
                false,
            ),
            (
                IntentKind::StructuredOutput,
                Some(SessionAgentType::Orchestrator),
                true,
            ),
            (
                IntentKind::AddSubTask,
                Some(SessionAgentType::Orchestrator),
                true,
            ),
            (
                IntentKind::BatchActivateSubTasks,
                Some(SessionAgentType::Orchestrator),
                true,
            ),
            // Executor
            (
                IntentKind::SingleCommit,
                Some(SessionAgentType::Executor),
                true,
            ),
            (
                IntentKind::IntegrationMerge,
                Some(SessionAgentType::Executor),
                false,
            ),
            (
                IntentKind::CompleteTask,
                Some(SessionAgentType::Executor),
                true,
            ),
            (
                IntentKind::ReportFailure,
                Some(SessionAgentType::Executor),
                true,
            ),
            (
                IntentKind::ActivateSubTask,
                Some(SessionAgentType::Executor),
                false,
            ),
            (
                IntentKind::RetrySubTask,
                Some(SessionAgentType::Executor),
                false,
            ),
            (
                IntentKind::SubmitReview,
                Some(SessionAgentType::Executor),
                false,
            ),
            (
                IntentKind::StructuredOutput,
                Some(SessionAgentType::Executor),
                true,
            ),
            (
                IntentKind::AddSubTask,
                Some(SessionAgentType::Executor),
                false,
            ),
            (
                IntentKind::BatchActivateSubTasks,
                Some(SessionAgentType::Executor),
                false,
            ),
            // Reviewer
            (
                IntentKind::SingleCommit,
                Some(SessionAgentType::Reviewer),
                false,
            ),
            (
                IntentKind::IntegrationMerge,
                Some(SessionAgentType::Reviewer),
                false,
            ),
            (
                IntentKind::CompleteTask,
                Some(SessionAgentType::Reviewer),
                false,
            ),
            (
                IntentKind::ReportFailure,
                Some(SessionAgentType::Reviewer),
                false,
            ),
            (
                IntentKind::ActivateSubTask,
                Some(SessionAgentType::Reviewer),
                false,
            ),
            (
                IntentKind::RetrySubTask,
                Some(SessionAgentType::Reviewer),
                false,
            ),
            (
                IntentKind::SubmitReview,
                Some(SessionAgentType::Reviewer),
                true,
            ),
            (
                IntentKind::StructuredOutput,
                Some(SessionAgentType::Reviewer),
                false,
            ),
            (
                IntentKind::AddSubTask,
                Some(SessionAgentType::Reviewer),
                false,
            ),
            (
                IntentKind::BatchActivateSubTasks,
                Some(SessionAgentType::Reviewer),
                false,
            ),
        ];

        // 10 kinds × (3 agent types + 1 NULL) = 40 cells.
        assert_eq!(
            expectations.len(),
            10 * 4,
            "matrix coverage: 10 IntentKind variants × 4 agent-type \
             buckets (Orchestrator/Executor/Reviewer/None) = 40 cells. \
             A mismatch here is a test-data drift, not a matrix bug."
        );

        for (kind, agent_type, expected) in expectations {
            let v = evaluate_dispatch(kind, agent_type);
            assert_eq!(
                v.is_authorized(),
                expected,
                "matrix({kind:?}, {agent_type:?}) = {v:?}; expected \
                 authorized={expected}",
            );
        }
    }

    /// Cross-check the matrix against `IntentKind::ALL` and
    /// `SessionAgentType::ALL` so a future variant addition fails
    /// the matrix-coverage test until a row is added above.
    #[test]
    fn every_intent_kind_and_agent_type_is_covered_by_the_matrix() {
        for &k in &IntentKind::ALL {
            // Each (kind, NONE) row must have a verdict (compile
            // would already reject otherwise; the runtime call is
            // belt-and-suspenders against future macro-expansion
            // tricks that could collapse cases).
            let _ = evaluate_dispatch(k, None);
            for &a in &SessionAgentType::ALL {
                let _ = evaluate_dispatch(k, Some(a));
            }
        }

        // Pin both enum lengths so a future variant addition trips
        // this test rather than silently expanding the table outside
        // the explicit coverage above.
        assert_eq!(
            IntentKind::ALL.len(),
            10,
            "matrix sized for 10 IntentKind variants (V2 base 7 + V2.5 \
             `StructuredOutput` + V3 `AddSubTask` + V3 iter70 \
             `BatchActivateSubTasks`); bumping requires a new row in \
             `evaluate_dispatch` AND a new line in \
             `matrix_authorizes_exactly_the_expected_cells`."
        );
        assert_eq!(
            SessionAgentType::ALL.len(),
            3,
            "matrix sized for 3 SessionAgentType variants; bumping \
             requires a new column."
        );
    }

    /// INV-DISPATCH structural property: the Reviewer's authorized
    /// set is exactly `{SubmitReview}`. Pinned independently of the
    /// expectation table above so a careless Reviewer-row widening
    /// (e.g., re-introducing ReportFailure for "I can't review")
    /// fails this test even if the perpetrator forgot to update the
    /// expectation table.
    #[test]
    fn reviewer_only_authorized_for_submit_review() {
        for &k in &IntentKind::ALL {
            let v = evaluate_dispatch(k, Some(SessionAgentType::Reviewer));
            let expected = matches!(k, IntentKind::SubmitReview);
            assert_eq!(
                v.is_authorized(),
                expected,
                "Reviewer authorization for {k:?}: got {v:?}, expected \
                 authorized={expected}"
            );
        }
    }

    /// INV-DISPATCH structural property: only the Orchestrator may
    /// submit delegation intents (`ActivateSubTask`, `RetrySubTask`,
    /// `AddSubTask`, `BatchActivateSubTasks`). The boolean-field
    /// gate `can_delegate` is the SECOND line of defence
    /// (INV-DELEGATE-01); the matrix is the FIRST.
    #[test]
    fn only_orchestrator_authorized_for_delegation() {
        for delegation in [
            IntentKind::ActivateSubTask,
            IntentKind::RetrySubTask,
            IntentKind::AddSubTask,
            IntentKind::BatchActivateSubTasks,
        ] {
            for &a in &SessionAgentType::ALL {
                let v = evaluate_dispatch(delegation, Some(a));
                let expected = matches!(a, SessionAgentType::Orchestrator);
                assert_eq!(
                    v.is_authorized(),
                    expected,
                    "Delegation kind {delegation:?} authorization for \
                     agent {a:?}: got {v:?}, expected authorized={expected}"
                );
            }
            // V1 NULL row also rejects delegation.
            assert!(
                !evaluate_dispatch(delegation, None).is_authorized(),
                "V1 NULL session must not submit V2 delegation kind \
                 {delegation:?}"
            );
        }
    }

    /// INV-DISPATCH structural property: only the Orchestrator may
    /// submit `IntegrationMerge` (Step 8). V1 sessions retain access
    /// for backward compat.
    #[test]
    fn only_orchestrator_authorized_for_integration_merge_in_v2() {
        // V2 row: Orchestrator yes, others no.
        for &a in &SessionAgentType::ALL {
            let v = evaluate_dispatch(IntentKind::IntegrationMerge, Some(a));
            let expected = matches!(a, SessionAgentType::Orchestrator);
            assert_eq!(
                v.is_authorized(),
                expected,
                "IntegrationMerge for {a:?}: got {v:?}, expected \
                 authorized={expected}"
            );
        }
        // V1 row: NULL keeps IntegrationMerge.
        assert!(evaluate_dispatch(IntentKind::IntegrationMerge, None).is_authorized());
    }

    /// `is_authorized` predicate reflects the variant tag.
    #[test]
    fn verdict_predicate_matches_variant() {
        assert!(DispatchVerdict::Authorized.is_authorized());
        assert!(!DispatchVerdict::Unauthorized.is_authorized());
    }
}

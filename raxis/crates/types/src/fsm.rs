// raxis-types::fsm — Task and Initiative finite-state machine types.
//
// Normative reference:
//   - kernel-core.md §2.4 "Initiative FSM" and "Task FSM" tables.
//   - kernel-store.md §2.5.1 Table 2 (`initiatives.status`) and
//     Table 5 (`tasks.state`).
//
// The CHECK constraints in the DDL are the canonical allowed values; this
// Rust enum must be kept in bijection with those SQL strings.

use serde::{Deserialize, Serialize};
use std::fmt;

// ---------------------------------------------------------------------------
// InitiativeState
// DDL: CHECK (status IN ('Draft','ApprovedPlan','Executing','Blocked',
//                        'Completed','Failed','Aborted'))
// kernel-store.md §2.5.1 Table 2
// ---------------------------------------------------------------------------

/// The lifecycle state of an initiative.
///
/// Transitions (kernel-core.md §2.4 initiative FSM):
///   Draft → ApprovedPlan (approve_plan)
///   Draft → Aborted (reject_plan)
///   ApprovedPlan → Executing (first task Running)
///   Executing → Blocked (evaluate_terminal_criteria under partial-failure policies)
///   Executing → Completed (evaluate_terminal_criteria: all success criteria met)
///   Executing → Failed (evaluate_terminal_criteria: failure criterion met)
///   Executing / Blocked → Aborted (abort_initiative)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum InitiativeState {
    Draft,
    ApprovedPlan,
    Executing,
    Blocked,
    Completed,
    Failed,
    Aborted,
}

impl InitiativeState {
    /// All variants in v1 — the canonical set referenced by the
    /// `initiatives.state` SQL CHECK constraint
    /// (kernel-store.md §2.5.1 Table 2).
    ///
    /// **Spec drift contract.** The array length is part of the v1
    /// schema contract; bumping it (i.e. adding a new variant) MUST be
    /// accompanied by a schema migration that ALTERs the CHECK
    /// constraint on already-installed databases. The
    /// `migration::tests::migration_1_ddl_fingerprint_is_pinned` hash
    /// guard catches any silent drift between this array and the
    /// rendered Migration 1 DDL.
    pub const ALL: [Self; 7] = [
        Self::Draft,
        Self::ApprovedPlan,
        Self::Executing,
        Self::Blocked,
        Self::Completed,
        Self::Failed,
        Self::Aborted,
    ];

    /// Returns true for terminal states (no further transitions possible).
    /// kernel-core.md: "terminal state" = Completed | Failed | Aborted.
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Failed | Self::Aborted)
    }

    /// Canonical SQL string used in CHECK constraints and at-rest storage.
    pub fn as_sql_str(self) -> &'static str {
        match self {
            Self::Draft => "Draft",
            Self::ApprovedPlan => "ApprovedPlan",
            Self::Executing => "Executing",
            Self::Blocked => "Blocked",
            Self::Completed => "Completed",
            Self::Failed => "Failed",
            Self::Aborted => "Aborted",
        }
    }

    /// Parse from the SQL at-rest string.
    pub fn from_sql_str(s: &str) -> Option<Self> {
        match s {
            "Draft" => Some(Self::Draft),
            "ApprovedPlan" => Some(Self::ApprovedPlan),
            "Executing" => Some(Self::Executing),
            "Blocked" => Some(Self::Blocked),
            "Completed" => Some(Self::Completed),
            "Failed" => Some(Self::Failed),
            "Aborted" => Some(Self::Aborted),
            _ => None,
        }
    }
}

impl fmt::Display for InitiativeState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_sql_str())
    }
}

// ---------------------------------------------------------------------------
// TaskState
// DDL: CHECK (state IN ('Admitted','Running','GatesPending','Completed',
//                       'Failed','Aborted','Cancelled','BlockedRecoveryPending'))
// kernel-store.md §2.5.1 Table 5
// ---------------------------------------------------------------------------

/// The lifecycle state of a task within an initiative.
///
/// Transitions (kernel-core.md §2.4 task FSM):
///   Admitted → Running (first intent accepted for this task)
///   Running → GatesPending (gate evaluation in progress)
///   GatesPending → Running (all gates cleared, next intent accepted)
///   Running / GatesPending → Failed (ReportFailure intent)
///   Running / GatesPending → Aborted (abort_task / abort_initiative / WitnessTimeout)
///   Running / GatesPending → BlockedRecoveryPending (kernel crash recovery)
///   BlockedRecoveryPending → Running (resume_task operator command)
///   Running → Completed (CompleteTask intent accepted with path+gate closure)
///   Admitted / Running / GatesPending → Cancelled (bulk cancel from abort_initiative)
///   Failed → Admitted (retry_task operator command)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum TaskState {
    Admitted,
    Running,
    GatesPending,
    Completed,
    Failed,
    Aborted,
    Cancelled,
    BlockedRecoveryPending,
}

impl TaskState {
    /// All variants in v1 — the canonical set referenced by the
    /// `tasks.state` SQL CHECK constraint
    /// (kernel-store.md §2.5.1 Table 5).
    ///
    /// Order matches `tasks.state` CHECK in v1 DDL so the rendered
    /// Migration 1 SQL is byte-stable across builds (the
    /// `migration::tests::migration_1_ddl_fingerprint_is_pinned` hash
    /// guard relies on this ordering).
    ///
    /// **Spec drift contract.** Adding a new variant requires both a
    /// length bump here AND a new migration that ALTERs the CHECK
    /// constraint on already-installed databases.
    pub const ALL: [Self; 8] = [
        Self::Admitted,
        Self::GatesPending,
        Self::Running,
        Self::Completed,
        Self::Failed,
        Self::Aborted,
        Self::Cancelled,
        Self::BlockedRecoveryPending,
    ];

    /// Terminal task states from which no transition is possible (except
    /// Failed → Admitted via retry_task).
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Aborted | Self::Cancelled)
    }

    /// Returns true when the task is in a non-terminal, non-runnable state —
    /// i.e. the planner cannot submit intents right now but the task is not
    /// terminal. Used for FAIL_TASK_NOT_RUNNING discrimination.
    pub fn is_blocked(self) -> bool {
        matches!(self, Self::BlockedRecoveryPending | Self::GatesPending)
    }

    /// Canonical SQL string used in CHECK constraints and at-rest storage.
    pub fn as_sql_str(self) -> &'static str {
        match self {
            Self::Admitted => "Admitted",
            Self::Running => "Running",
            Self::GatesPending => "GatesPending",
            Self::Completed => "Completed",
            Self::Failed => "Failed",
            Self::Aborted => "Aborted",
            Self::Cancelled => "Cancelled",
            Self::BlockedRecoveryPending => "BlockedRecoveryPending",
        }
    }

    /// Parse from the SQL at-rest string.
    pub fn from_sql_str(s: &str) -> Option<Self> {
        match s {
            "Admitted" => Some(Self::Admitted),
            "Running" => Some(Self::Running),
            "GatesPending" => Some(Self::GatesPending),
            "Completed" => Some(Self::Completed),
            "Failed" => Some(Self::Failed),
            "Aborted" => Some(Self::Aborted),
            "Cancelled" => Some(Self::Cancelled),
            "BlockedRecoveryPending" => Some(Self::BlockedRecoveryPending),
            _ => None,
        }
    }
}

impl fmt::Display for TaskState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_sql_str())
    }
}

// ---------------------------------------------------------------------------
// BlockReason — why a task entered Aborted or BlockedRecoveryPending.
// kernel-core.md §2.4 FSM and §4.6 lifecycle handlers.
// ---------------------------------------------------------------------------

/// The reason a task was aborted or blocked for recovery.
/// Stored in `tasks.block_reason TEXT` (nullable; NULL when state is not
/// Aborted/BlockedRecoveryPending).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "PascalCase")]
pub enum BlockReason {
    /// Operator issued `task abort` or `initiative abort`.
    OperatorAbort,
    /// Verifier subprocess did not submit a witness before its token TTL expired.
    WitnessTimeout,
    /// Kernel crashed with this task in-flight; task pending operator `task resume`.
    KernelCrash,
    /// Budget exhausted before task could complete (v1: enforced at admit time,
    /// so this fires if the lane budget drops to zero between admission and
    /// CompleteTask acceptance).
    BudgetExhausted,
}

impl BlockReason {
    pub fn as_sql_str(&self) -> &'static str {
        match self {
            Self::OperatorAbort => "OperatorAbort",
            Self::WitnessTimeout => "WitnessTimeout",
            Self::KernelCrash => "KernelCrash",
            Self::BudgetExhausted => "BudgetExhausted",
        }
    }

    pub fn from_sql_str(s: &str) -> Option<Self> {
        match s {
            "OperatorAbort" => Some(Self::OperatorAbort),
            "WitnessTimeout" => Some(Self::WitnessTimeout),
            "KernelCrash" => Some(Self::KernelCrash),
            "BudgetExhausted" => Some(Self::BudgetExhausted),
            _ => None,
        }
    }
}

impl fmt::Display for BlockReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_sql_str())
    }
}

// ---------------------------------------------------------------------------
// SessionAgentType — V2 hierarchical orchestration agent kind.
// v2-deep-spec.md §1.2 (Step 6) and INV-DELEGATE-01 (Step 18).
// DDL: sessions.session_agent_type TEXT NULL (V1 rows: NULL ⇒ V1-flat planner;
//      V2 rows: 'Orchestrator' | 'Executor' | 'Reviewer').
//
// Why this enum is in fsm.rs alongside TaskState/InitiativeState rather than
// in a dedicated module: it is a pure data discriminant whose lifecycle is
// tied to the session row's lifetime (set at create_session, read at every
// intent dispatch, never updated). Co-locating it with the other tightly-
// scoped session/task enums keeps the type module surface small.
// ---------------------------------------------------------------------------

/// V2 agent type for a planner session.
///
/// V2 introduces hierarchical orchestration: a single Orchestrator decomposes
/// the plan into sub-tasks, each executed by an Executor; some sub-tasks are
/// reviewed by a Reviewer. The agent type drives:
///
///   1. The static dispatch matrix (v2-deep-spec.md §Step 20) — which intent
///      kinds this session may submit.
///   2. The Kernel Prompt Assembler — selects the prompt template family.
///   3. Reverse-DAG queries that identify Reviewer successor tasks.
///
/// The companion field is `sessions.can_delegate INTEGER NOT NULL DEFAULT 0`.
/// INV-DELEGATE-01: `can_delegate = 1` if and only if `session_agent_type =
/// Orchestrator`. The kernel enforces this at create_session time, AND at
/// approve_plan check #2 ("exactly one Orchestrator per plan"). Handlers
/// MUST read `can_delegate` from the session row directly; they MUST NOT
/// re-derive it from `session_agent_type` at runtime (so that this enum can
/// gain a new variant in a future spec without silently flipping
/// `can_delegate` for old rows).
///
/// V1 backward compatibility: legacy V1 sessions store NULL in this column.
/// Kernel handlers that did not exist in V1 (e.g. `handlers/activate_subtask.rs`)
/// reject NULL with a typed error; legacy V1 handlers do not consult this
/// field at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum SessionAgentType {
    /// Schedules sub-tasks declared in the operator-signed plan.
    /// Submits `ActivateSubTask`, `RetrySubTask`, `CancelSubTask`,
    /// `IntegrationMerge`, `CompleteTask`. Owns `cross_cutting_artifacts`
    /// during integration-merge (v2-deep-spec.md §Step 11).
    Orchestrator,

    /// Executes a single sub-task. Submits `SingleCommit`, `CompleteTask`,
    /// `ReportFailure`. Cannot delegate.
    Executor,

    /// Evaluates an Executor's `evaluation_sha` (post-CompleteTask).
    /// Submits `SubmitReview { approved, critique }`. Cannot delegate.
    /// Pure-static reviewer image — no `git` binary in the VM
    /// (planner-harness.md §4.5; INV-PLANNER-HARNESS-02).
    Reviewer,
}

impl SessionAgentType {
    /// All variants in V2 — referenced by the
    /// `sessions.session_agent_type` SQL CHECK constraint
    /// (v2-deep-spec.md §Step 6, store migration 5).
    ///
    /// **Spec drift contract.** Adding a new variant requires (a) bumping
    /// this array, (b) a new migration that ALTERs the CHECK constraint
    /// on already-installed databases, AND (c) refreshing the static
    /// dispatch matrix in `raxis-kernel` (v2-deep-spec.md §Step 20).
    pub const ALL: [Self; 3] = [
        Self::Orchestrator,
        Self::Executor,
        Self::Reviewer,
    ];

    /// Canonical SQL string used in CHECK constraints and at-rest storage.
    pub fn as_sql_str(self) -> &'static str {
        match self {
            Self::Orchestrator => "Orchestrator",
            Self::Executor     => "Executor",
            Self::Reviewer     => "Reviewer",
        }
    }

    /// Parse from the SQL at-rest string.
    pub fn from_sql_str(s: &str) -> Option<Self> {
        match s {
            "Orchestrator" => Some(Self::Orchestrator),
            "Executor"     => Some(Self::Executor),
            "Reviewer"     => Some(Self::Reviewer),
            _ => None,
        }
    }

    /// INV-DELEGATE-01: `can_delegate` is `true` iff
    /// `session_agent_type = Orchestrator`.
    ///
    /// **Important.** Handlers MUST read the persisted `can_delegate`
    /// column directly rather than calling this helper at the
    /// authorization point — see the v2-deep-spec.md §Step 18 reasoning
    /// (handler robustness across future enum changes). This helper is
    /// the single source of truth used by `create_session` to set the
    /// column, by `approve_plan` to validate plan check #2, and by tests.
    pub fn implies_can_delegate(self) -> bool {
        matches!(self, Self::Orchestrator)
    }
}

impl fmt::Display for SessionAgentType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_sql_str())
    }
}

// ---------------------------------------------------------------------------
// SubtaskActivationState — V2 sub-task pre-activation lifecycle.
// v2-deep-spec.md §1.2 (Step 5).
// DDL: subtask_activations.activation_state TEXT NOT NULL CHECK (...).
//
// Why a separate FSM from `tasks.state`:
//   - `tasks.state` is the V1 operational FSM (Admitted → Running → ...).
//   - V2 sub-tasks need a pre-activation state ("declared in plan, no VM yet")
//     that does not pollute the V1 FSM. Adding a `PendingActivation` variant
//     to TaskState would force every V1 state-machine handler to be aware of
//     the new state and risk recovery::reconcile_tasks sweeping it into
//     `BlockedRecoveryPending` (no VM has been provisioned yet, so there is
//     nothing to recover).
// ---------------------------------------------------------------------------

/// Sub-task activation lifecycle. Only Executor and Reviewer tasks have a
/// row in `subtask_activations`; the Orchestrator is activated by the Kernel
/// at initiative start, not by another agent (no row).
///
/// Transitions:
///   `PendingActivation` → `Active` (Orchestrator submits `ActivateSubTask`,
///                                    Kernel admits & spawns VM)
///   `Active`            → `Completed` (Executor: CompleteTask accepted with
///                                       valid `head_sha`; Reviewer:
///                                       SubmitReview accepted)
///   `Active`            → `Failed`    (VM crash, Reviewer rejected, or
///                                       budget/retry ceiling hit)
///
/// `Completed | Failed` are terminal w.r.t. this FSM (the Orchestrator may
/// still issue `RetrySubTask` which inserts a NEW `subtask_activations` row,
/// not a transition on the old one — each retry is a fresh activation).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum SubtaskActivationState {
    /// Declared in the signed plan; no VM provisioned yet. Inserted by
    /// `approve_plan` alongside the `tasks` row in the same transaction
    /// (INV-STORE-02 atomicity).
    PendingActivation,
    /// Orchestrator submitted `ActivateSubTask`, Kernel spawned the VM,
    /// session is bound and the planner is running.
    Active,
    /// Sub-task reached a successful terminal: Executor's CompleteTask
    /// accepted, or Reviewer's SubmitReview accepted (both `approved=true`
    /// and `approved=false` are kernel-acceptances of the review verdict —
    /// the rejection signal lives in `tasks.last_critique`, not here).
    Completed,
    /// Sub-task failed terminally for THIS activation. The Orchestrator
    /// may submit `RetrySubTask` to insert a fresh `PendingActivation` row
    /// subject to the dual retry counters in v2-deep-spec.md §Step 12.
    Failed,
}

impl SubtaskActivationState {
    /// All variants — referenced by the
    /// `subtask_activations.activation_state` SQL CHECK constraint
    /// (v2-deep-spec.md §Step 5, store migration 5).
    pub const ALL: [Self; 4] = [
        Self::PendingActivation,
        Self::Active,
        Self::Completed,
        Self::Failed,
    ];

    /// Canonical SQL string used in CHECK constraints and at-rest storage.
    pub fn as_sql_str(self) -> &'static str {
        match self {
            Self::PendingActivation => "PendingActivation",
            Self::Active            => "Active",
            Self::Completed         => "Completed",
            Self::Failed            => "Failed",
        }
    }

    /// Parse from the SQL at-rest string.
    pub fn from_sql_str(s: &str) -> Option<Self> {
        match s {
            "PendingActivation" => Some(Self::PendingActivation),
            "Active"            => Some(Self::Active),
            "Completed"         => Some(Self::Completed),
            "Failed"            => Some(Self::Failed),
            _ => None,
        }
    }

    /// True for terminal activation states. Note: `Failed` is terminal w.r.t.
    /// this FSM — a retry creates a new `subtask_activations` row.
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Failed)
    }
}

impl fmt::Display for SubtaskActivationState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_sql_str())
    }
}

// ---------------------------------------------------------------------------
// TerminalCriteria — the initiative terminal policy in force.
// kernel-core.md §2.4 "evaluate_terminal_criteria" and §4.5.
// DDL: initiatives.terminal_criteria TEXT NOT NULL.
// ---------------------------------------------------------------------------

/// The criterion by which the kernel decides when an initiative becomes terminal.
/// Set at plan-load time from the signed plan TOML `terminal_criteria` field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum TerminalCriteria {
    /// Initiative succeeds when every task reaches Completed.
    /// Fails when any task reaches Failed (strict).
    AllTasksSucceeded,
    /// Initiative succeeds when every task reaches a terminal state
    /// (Completed, Failed, Aborted, or Cancelled).
    AllTasksTerminal,
    /// Initiative succeeds when at least `n` tasks reach Completed.
    /// The count `n` is stored alongside the enum in the DDL as a separate
    /// column (`min_success_count`) — this variant is the discriminant only.
    MinSuccessCount,
}

impl TerminalCriteria {
    pub fn as_sql_str(self) -> &'static str {
        match self {
            Self::AllTasksSucceeded => "AllTasksSucceeded",
            Self::AllTasksTerminal => "AllTasksTerminal",
            Self::MinSuccessCount => "MinSuccessCount",
        }
    }

    pub fn from_sql_str(s: &str) -> Option<Self> {
        match s {
            "AllTasksSucceeded" => Some(Self::AllTasksSucceeded),
            "AllTasksTerminal" => Some(Self::AllTasksTerminal),
            "MinSuccessCount" => Some(Self::MinSuccessCount),
            _ => None,
        }
    }
}

impl fmt::Display for TerminalCriteria {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_sql_str())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ── SessionAgentType ─────────────────────────────────────────────────────

    /// SQL round-trip on every variant. The CHECK constraint in migration 5
    /// uses these strings verbatim; a typo here would render the constraint
    /// non-bijective with the enum.
    #[test]
    fn session_agent_type_sql_round_trip_is_total() {
        for &variant in &SessionAgentType::ALL {
            let s = variant.as_sql_str();
            assert!(!s.is_empty(), "SessionAgentType::{variant:?} → empty string");
            assert_eq!(SessionAgentType::from_sql_str(s), Some(variant),
                "round-trip failed for {variant:?}: as_sql_str → {s}");
        }
    }

    #[test]
    fn session_agent_type_unknown_sql_returns_none() {
        assert_eq!(SessionAgentType::from_sql_str(""), None);
        assert_eq!(SessionAgentType::from_sql_str("orchestrator"), None,
            "case-sensitive match: lowercase must NOT round-trip");
        assert_eq!(SessionAgentType::from_sql_str("Planner"), None,
            "V1 'Planner' role MUST NOT decode as a V2 agent type");
    }

    /// INV-DELEGATE-01: only the Orchestrator may delegate.
    /// This is the single source of truth for `can_delegate` derivation
    /// at create_session and approve_plan; runtime handlers MUST consult
    /// the persisted `can_delegate` column instead.
    #[test]
    fn inv_delegate_01_orchestrator_only_implies_can_delegate() {
        assert!(SessionAgentType::Orchestrator.implies_can_delegate());
        assert!(!SessionAgentType::Executor.implies_can_delegate());
        assert!(!SessionAgentType::Reviewer.implies_can_delegate());
    }

    /// V2 has exactly three agent types. Bumping this requires the
    /// dispatch matrix and migration to be updated in lock-step.
    #[test]
    fn session_agent_type_variant_count_is_pinned_to_v2() {
        assert_eq!(SessionAgentType::ALL.len(), 3,
            "V2 has exactly 3 SessionAgentType variants \
             (Orchestrator, Executor, Reviewer); bumping this requires \
             a new migration AND dispatch-matrix refresh.");
    }

    #[test]
    fn session_agent_type_display_equals_as_sql_str() {
        for &variant in &SessionAgentType::ALL {
            assert_eq!(variant.to_string(), variant.as_sql_str());
        }
    }

    /// Bincode/JSON round-trip via serde must use the exact PascalCase
    /// strings — these are the same strings used in the audit-event
    /// JSONL projection (audit-paired-writes.md §3) and the SQL CHECK
    /// constraint. A future serde-rename refactor that changes the
    /// projection silently would break audit-replay tooling.
    #[test]
    fn session_agent_type_serde_uses_pascal_case() {
        let json = serde_json::to_string(&SessionAgentType::Orchestrator).unwrap();
        assert_eq!(json, r#""Orchestrator""#);
        let parsed: SessionAgentType =
            serde_json::from_str(r#""Reviewer""#).unwrap();
        assert_eq!(parsed, SessionAgentType::Reviewer);
    }

    // ── SubtaskActivationState ───────────────────────────────────────────────

    #[test]
    fn subtask_activation_state_sql_round_trip_is_total() {
        for &variant in &SubtaskActivationState::ALL {
            let s = variant.as_sql_str();
            assert!(!s.is_empty(), "SubtaskActivationState::{variant:?} → empty string");
            assert_eq!(SubtaskActivationState::from_sql_str(s), Some(variant),
                "round-trip failed for {variant:?}: as_sql_str → {s}");
        }
    }

    #[test]
    fn subtask_activation_state_unknown_sql_returns_none() {
        assert_eq!(SubtaskActivationState::from_sql_str(""), None);
        // V1 task states must NOT decode as activation states; the two
        // FSMs are deliberately separate (v2-deep-spec.md §Step 5).
        assert_eq!(SubtaskActivationState::from_sql_str("Admitted"), None);
        assert_eq!(SubtaskActivationState::from_sql_str("BlockedRecoveryPending"), None);
    }

    #[test]
    fn subtask_activation_state_terminal_predicate() {
        assert!(!SubtaskActivationState::PendingActivation.is_terminal());
        assert!(!SubtaskActivationState::Active.is_terminal());
        assert!(SubtaskActivationState::Completed.is_terminal());
        assert!(SubtaskActivationState::Failed.is_terminal(),
            "Failed is terminal w.r.t. THIS activation; retries insert a \
             new subtask_activations row, not a transition.");
    }

    #[test]
    fn subtask_activation_state_variant_count_is_pinned_to_v2() {
        assert_eq!(SubtaskActivationState::ALL.len(), 4,
            "V2 has exactly 4 SubtaskActivationState variants; \
             bumping this requires a new migration that ALTERs the \
             CHECK constraint on already-installed databases.");
    }

    #[test]
    fn subtask_activation_state_display_equals_as_sql_str() {
        for &variant in &SubtaskActivationState::ALL {
            assert_eq!(variant.to_string(), variant.as_sql_str());
        }
    }
}

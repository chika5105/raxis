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

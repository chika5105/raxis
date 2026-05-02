// raxis-kernel::scheduler — Lane admission, DAG ordering, budget enforcement.
//
// Normative reference: kernel-core.md §2.3 `src/scheduler/`.
//
// Role: decides whether a task may enter the execution pipeline (admission)
// and in what order ready tasks are surfaced to the planner.
//
// The scheduler NEVER calls:
//   - gates/ authority/ vcs/ (structural invariant per §2.3)
//
// Public API re-exports per scheduler/mod.rs spec:
//   pub use admit::{admit_in_tx, PlanTask};
//   pub use dag::{next_ready_tasks, mark_task_complete, transition_to_admitted};
//   pub use lane::{lane_config_for_row, get_lane_status};
//   pub use budget::{check_budget, current_budget};
//
// Note: `admit_in_tx` (formerly `admit`) takes a borrowed `&Connection` so the
// caller — exclusively `lifecycle::approve_plan` — can compose all task admits
// for one initiative inside one transaction, as required by INV-STORE-02.

pub mod admit;
pub mod dag;
pub mod lane;
pub mod budget;

pub use admit::{admit_in_tx, PlanTask};
pub use dag::{next_ready_tasks, mark_task_complete, transition_to_admitted};
pub use lane::{lane_config_for_row, get_lane_status};
pub use budget::{check_budget, current_budget};

// ---------------------------------------------------------------------------
// SchedulerError — shared error type for all scheduler sub-modules
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum SchedulerError {
    #[error("unknown lane: {lane_id}")]
    UnknownLane { lane_id: String },

    #[error("no lane assigned to task")]
    NoLaneAssigned,

    #[error("task has a cyclic dependency")]
    CyclicDependency,

    #[error("DAG depth limit exceeded (max 64)")]
    DagDepthExceeded,

    #[error("budget exceeded: {kind}")]
    BudgetExceeded { kind: String },

    #[error("corrupt reservation state for task {task_id}")]
    CorruptReservationState { task_id: String },

    #[error("invalid state transition for task {task_id}: {reason}")]
    InvalidStateTransition { task_id: String, reason: String },

    #[error("task not found: {task_id}")]
    TaskNotFound { task_id: String },

    #[error("SQL error: {0}")]
    Sql(#[from] rusqlite::Error),
}

/// Budget-specific error returned by compute_admission_cost.
#[derive(Debug, thiserror::Error)]
pub enum BudgetError {
    #[error("unknown intent kind cost for: {intent_kind}")]
    UnknownIntentKindCost { intent_kind: String },

    #[error("scheduler error: {0}")]
    Scheduler(#[from] SchedulerError),
}

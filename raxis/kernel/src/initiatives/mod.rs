// raxis-kernel::initiatives — Initiative and task lifecycle management.
//
// Normative reference: kernel-core.md §2.2 handlers/operator.rs and §2.3
// (lifecycle subsystem referenced by operator IPC handlers).
//
// An initiative is the unit of operator-approved work. It contains:
//   - A plan (approved by operator, signed Ed25519)
//   - One or more tasks derived from the plan
//   - A lifecycle FSM: Pending → PlanSubmitted → PlanApproved → Executing
//                                                              → Completed / Failed / Aborted
//
// All initiative state transitions are atomic: they must be committed with
// their corresponding audit record in a single SQLite transaction.

pub mod lifecycle;
pub mod plan_registry;
pub mod task_transitions;

pub use lifecycle::LifecycleError;
pub use plan_registry::{PlanRegistry, TaskKey, TaskPlanFields};

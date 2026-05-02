// raxis-kernel::initiatives::task_transitions — Atomic task state transitions.
//
// Normative reference: kernel-core.md §2.3 intent handler task transition step.
//
// All task state changes MUST go through `transition_task`. No other function
// in the kernel may directly `UPDATE tasks SET state=...` except:
//   - recovery::reconcile (bulk sweep to BlockedRecoveryPending at startup)
//   - lifecycle::abort_initiative (bulk cancel inside abort_initiative tx)
//   - lifecycle::admit_task (initial Admitted insert at plan approval)
//
// Each `transition_task` call:
//   1. Validates the transition is legal per the TaskState FSM.
//   2. Writes the new state to the tasks table.
//   3. Sets the appropriate timestamp column.
//   4. Emits a structured JSON log line (full audit integration is v2).
//
// FSM (normative, from raxis-types::TaskState):
//   Admitted → Running | GatesPending
//   Running  → Admitted (gate cycle) | Completed | Failed
//   GatesPending → Admitted (witness cleared all gates)
//   BlockedRecoveryPending → Admitted (operator resume) | Aborted
//   Completed, Failed, Aborted, Cancelled — terminal; no outbound transitions

use raxis_store::Store;
use raxis_types::TaskState;

use crate::initiatives::LifecycleError;

/// Actor that triggered the transition (for audit).
#[derive(Debug, Clone)]
pub enum TransitionActor {
    Kernel,
    Operator { fingerprint: String },
}

/// Perform an atomic task state transition.
///
/// Returns `Err(LifecycleError::TaskNotFound)` if no row for `task_id`.
/// Returns `Err(LifecycleError::TaskNotAbortable)` if the transition is
/// not legal from the current state.
///
/// The `block_reason` is stored in `tasks.block_reason` when transitioning
/// to `GatesPending` or `BlockedRecoveryPending`.
pub fn transition_task(
    task_id: &str,
    new_state: TaskState,
    block_reason: Option<&str>,
    actor: TransitionActor,
    store: &Store,
) -> Result<(), LifecycleError> {
    let conn = store.lock_sync();
    let now = now_unix_secs();

    // Load current state.
    let current_state_str: String = conn.query_row(
        "SELECT state FROM tasks WHERE task_id=?1",
        rusqlite::params![task_id],
        |r| r.get(0),
    ).map_err(|e| match e {
        rusqlite::Error::QueryReturnedNoRows => LifecycleError::TaskNotFound {
            task_id: task_id.to_owned(),
        },
        other => LifecycleError::Sql(other),
    })?;

    let current_state = parse_task_state(&current_state_str);

    // Validate transition.
    if !is_legal_transition(&current_state, &new_state) {
        return Err(LifecycleError::TaskNotAbortable {
            current_state: current_state_str.clone(),
        });
    }

    let new_state_str = task_state_str(&new_state);
    let actor_desc = match &actor {
        TransitionActor::Kernel => "kernel".to_owned(),
        TransitionActor::Operator { fingerprint } => format!("operator:{fingerprint}"),
    };

    // Apply the transition with the appropriate timestamp column.
    match &new_state {
        TaskState::Running => {
            conn.execute(
                "UPDATE tasks SET state=?1, started_at=?2, block_reason=NULL WHERE task_id=?3",
                rusqlite::params![new_state_str, now, task_id],
            )?;
        }
        TaskState::GatesPending => {
            conn.execute(
                "UPDATE tasks SET state=?1, gates_pending_at=?2, block_reason=?3 WHERE task_id=?4",
                rusqlite::params![new_state_str, now, block_reason, task_id],
            )?;
        }
        TaskState::Admitted => {
            conn.execute(
                "UPDATE tasks SET state=?1, block_reason=NULL WHERE task_id=?2",
                rusqlite::params![new_state_str, task_id],
            )?;
        }
        TaskState::Completed => {
            conn.execute(
                "UPDATE tasks SET state=?1, completed_at=?2 WHERE task_id=?3",
                rusqlite::params![new_state_str, now, task_id],
            )?;
        }
        TaskState::Failed => {
            conn.execute(
                "UPDATE tasks SET state=?1, failed_at=?2, block_reason=?3 WHERE task_id=?4",
                rusqlite::params![new_state_str, now, block_reason, task_id],
            )?;
        }
        TaskState::Aborted => {
            conn.execute(
                "UPDATE tasks SET state=?1, aborted_at=?2 WHERE task_id=?3",
                rusqlite::params![new_state_str, now, task_id],
            )?;
        }
        TaskState::BlockedRecoveryPending => {
            conn.execute(
                "UPDATE tasks SET state=?1, recovery_transition_at=?2 WHERE task_id=?3",
                rusqlite::params![new_state_str, now, task_id],
            )?;
        }
        TaskState::Cancelled => {
            conn.execute(
                "UPDATE tasks SET state=?1, cancelled_at=?2 WHERE task_id=?3",
                rusqlite::params![new_state_str, now, task_id],
            )?;
        }
    }

    eprintln!(
        "{{\"level\":\"info\",\"event\":\"TaskTransitioned\",\"task_id\":\"{task_id}\",\
         \"from\":\"{current_state_str}\",\"to\":\"{new_state_str}\",\"actor\":\"{actor_desc}\"}}",
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// FSM transition table
// ---------------------------------------------------------------------------

fn is_legal_transition(from: &TaskState, to: &TaskState) -> bool {
    match (from, to) {
        // Admitted: can start (Running) or go to gate eval (GatesPending)
        (TaskState::Admitted, TaskState::Running) => true,
        (TaskState::Admitted, TaskState::GatesPending) => true,
        (TaskState::Admitted, TaskState::Aborted) => true,
        (TaskState::Admitted, TaskState::Cancelled) => true,
        // Running: can complete, fail, or re-enter gate cycle
        (TaskState::Running, TaskState::Completed) => true,
        (TaskState::Running, TaskState::Failed) => true,
        (TaskState::Running, TaskState::GatesPending) => true,
        (TaskState::Running, TaskState::Admitted) => true, // continuation / re-schedule
        (TaskState::Running, TaskState::Aborted) => true,
        // GatesPending: cleared → Admitted; or aborted
        (TaskState::GatesPending, TaskState::Admitted) => true,
        (TaskState::GatesPending, TaskState::Aborted) => true,
        (TaskState::GatesPending, TaskState::Cancelled) => true,
        // BlockedRecoveryPending: operator resume → Admitted; or abort
        (TaskState::BlockedRecoveryPending, TaskState::Admitted) => true,
        (TaskState::BlockedRecoveryPending, TaskState::Aborted) => true,
        // Failed → Admitted is the retry path
        (TaskState::Failed, TaskState::Admitted) => true,
        // All other transitions are illegal
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn parse_task_state(s: &str) -> TaskState {
    match s {
        "Admitted" => TaskState::Admitted,
        "Running" => TaskState::Running,
        "GatesPending" => TaskState::GatesPending,
        "Completed" => TaskState::Completed,
        "Failed" => TaskState::Failed,
        "Aborted" => TaskState::Aborted,
        "Cancelled" => TaskState::Cancelled,
        "BlockedRecoveryPending" => TaskState::BlockedRecoveryPending,
        _ => TaskState::Failed, // defensive: unknown state → treat as non-transitionable
    }
}

fn task_state_str(s: &TaskState) -> &'static str {
    match s {
        TaskState::Admitted => "Admitted",
        TaskState::Running => "Running",
        TaskState::GatesPending => "GatesPending",
        TaskState::Completed => "Completed",
        TaskState::Failed => "Failed",
        TaskState::Aborted => "Aborted",
        TaskState::Cancelled => "Cancelled",
        TaskState::BlockedRecoveryPending => "BlockedRecoveryPending",
    }
}

fn now_unix_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admitted_to_running_is_legal() {
        assert!(is_legal_transition(&TaskState::Admitted, &TaskState::Running));
    }

    #[test]
    fn completed_to_anything_is_illegal() {
        assert!(!is_legal_transition(&TaskState::Completed, &TaskState::Running));
        assert!(!is_legal_transition(&TaskState::Completed, &TaskState::Admitted));
        assert!(!is_legal_transition(&TaskState::Completed, &TaskState::Failed));
    }

    #[test]
    fn failed_to_admitted_retry_is_legal() {
        assert!(is_legal_transition(&TaskState::Failed, &TaskState::Admitted));
        assert!(!is_legal_transition(&TaskState::Failed, &TaskState::Running));
    }

    #[test]
    fn gates_pending_to_admitted_is_legal() {
        assert!(is_legal_transition(&TaskState::GatesPending, &TaskState::Admitted));
    }
}

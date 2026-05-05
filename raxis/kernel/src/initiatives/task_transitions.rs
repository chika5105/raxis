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
// Type-safety rule: all state strings in SQL use TaskState::as_sql_str().
// No raw string literals for enum values — the compiler catches misspellings.

use raxis_store::{Store, Table};
use raxis_types::{unix_now_secs, TaskState};

use crate::initiatives::LifecycleError;

const TASKS: &str = Table::Tasks.as_str();

/// Actor that triggered the transition (for audit).
#[derive(Debug, Clone)]
pub enum TransitionActor {
    Kernel,
    Operator { fingerprint: String },
}

/// Perform an atomic task state transition.
///
/// Standalone wrapper that opens its own mutex acquisition and runs the
/// SELECT-then-UPDATE under one mutex hold. Suitable for one-shot
/// transitions (operator abort, retry, etc.). Composing helpers — most
/// notably `handlers/intent::run_phase_c` — MUST use
/// `transition_task_in_tx` instead so the FSM update commits atomically
/// with the surrounding writes (budget reservation, intent fields,
/// intent range). See `kernel-store.md` §2.5.1.1 Pattern B.
///
/// Returns `Err(LifecycleError::TaskNotFound)` if no row for `task_id`.
/// Returns `Err(LifecycleError::TaskNotAbortable)` if the transition is not
/// legal from the current state.
pub fn transition_task(
    task_id:      &str,
    new_state:    TaskState,
    block_reason: Option<&str>,
    actor:        TransitionActor,
    store:        &Store,
) -> Result<(), LifecycleError> {
    let mut conn = store.lock_sync();
    let tx = conn.transaction()?;
    transition_task_in_tx(&tx, task_id, new_state, block_reason, actor)?;
    tx.commit()?;
    Ok(())
}

/// Atomic task state transition — transaction variant for callers
/// composing the FSM update into a larger atomic operation.
///
/// **INV-STORE-02 (kernel-store.md §2.5.1.1 Pattern B):** the SELECT
/// (current state) and the UPDATE (new state) MUST run inside the same
/// transaction, and the caller is responsible for ensuring any
/// surrounding writes (lane reservation, intent fields, intent range)
/// also live inside the same transaction so they all commit or none do.
///
/// The `block_reason` string is stored in `tasks.block_reason` when
/// transitioning to `GatesPending`, `Failed`, or `BlockedRecoveryPending`.
pub fn transition_task_in_tx(
    conn:         &rusqlite::Connection,
    task_id:      &str,
    new_state:    TaskState,
    block_reason: Option<&str>,
    actor:        TransitionActor,
) -> Result<(), LifecycleError> {
    let now = unix_now_secs();

    // Load current state string and parse it through the enum.
    let current_state_str: String = conn.query_row(
        &format!("SELECT state FROM {TASKS} WHERE task_id=?1"),
        rusqlite::params![task_id],
        |r| r.get(0),
    ).map_err(|e| match e {
        rusqlite::Error::QueryReturnedNoRows => LifecycleError::TaskNotFound {
            task_id: task_id.to_owned(),
        },
        other => LifecycleError::Sql(other),
    })?;

    let current_state = TaskState::from_sql_str(&current_state_str)
        .ok_or_else(|| LifecycleError::TaskNotAbortable {
            current_state: current_state_str.clone(),
        })?;

    if !is_legal_transition(&current_state, &new_state) {
        return Err(LifecycleError::TaskNotAbortable {
            current_state: current_state_str.clone(),
        });
    }

    let new_state_str = new_state.as_sql_str();
    let actor_desc = match &actor {
        TransitionActor::Kernel => "kernel".to_owned(),
        TransitionActor::Operator { fingerprint } => format!("operator:{fingerprint}"),
    };

    // All transitions use the same DDL-canonical columns:
    //   state, transitioned_at, actor — always written.
    //   block_reason — written for GatesPending / Failed / BlockedRecoveryPending,
    //                  cleared (NULL) for Running / Admitted / Completed / terminal.
    match &new_state {
        TaskState::Running | TaskState::Admitted | TaskState::Completed => {
            conn.execute(
                &format!(
                    "UPDATE {TASKS} SET state=?1, transitioned_at=?2, block_reason=NULL, actor=?3
                     WHERE task_id=?4"
                ),
                rusqlite::params![new_state_str, now, &actor_desc, task_id],
            )?;
        }
        TaskState::GatesPending | TaskState::Failed | TaskState::BlockedRecoveryPending => {
            conn.execute(
                &format!(
                    "UPDATE {TASKS} SET state=?1, transitioned_at=?2, block_reason=?3, actor=?4
                     WHERE task_id=?5"
                ),
                rusqlite::params![new_state_str, now, block_reason, &actor_desc, task_id],
            )?;
        }
        TaskState::Aborted | TaskState::Cancelled => {
            conn.execute(
                &format!(
                    "UPDATE {TASKS} SET state=?1, transitioned_at=?2, actor=?3
                     WHERE task_id=?4"
                ),
                rusqlite::params![new_state_str, now, &actor_desc, task_id],
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
// FSM transition table — canonical allowed edges per kernel-core.md §2.4
// ---------------------------------------------------------------------------

fn is_legal_transition(from: &TaskState, to: &TaskState) -> bool {
    match (from, to) {
        // Admitted: start running, wait for gates, or operator cancel
        (TaskState::Admitted, TaskState::Running)          => true,
        (TaskState::Admitted, TaskState::GatesPending)     => true,
        (TaskState::Admitted, TaskState::Aborted)          => true,
        (TaskState::Admitted, TaskState::Cancelled)        => true,
        // Running: complete, fail, enter gate cycle, re-admit (continuation), abort
        (TaskState::Running,  TaskState::Completed)        => true,
        (TaskState::Running,  TaskState::Failed)           => true,
        (TaskState::Running,  TaskState::GatesPending)     => true,
        (TaskState::Running,  TaskState::Admitted)         => true,
        (TaskState::Running,  TaskState::Aborted)          => true,
        (TaskState::Running,  TaskState::Cancelled)        => true,
        // GatesPending: gates cleared → Admitted; or aborted / cancelled
        (TaskState::GatesPending, TaskState::Admitted)     => true,
        (TaskState::GatesPending, TaskState::Aborted)      => true,
        (TaskState::GatesPending, TaskState::Cancelled)    => true,
        // BlockedRecoveryPending: operator resume → Admitted; or abort
        (TaskState::BlockedRecoveryPending, TaskState::Admitted) => true,
        (TaskState::BlockedRecoveryPending, TaskState::Aborted)  => true,
        // Failed → Admitted is the retry path (retry_task operator command)
        (TaskState::Failed, TaskState::Admitted)           => true,
        // All other transitions are illegal (terminal states have no outbound edges)
        _ => false,
    }
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

    #[test]
    fn blocked_recovery_to_admitted_is_legal() {
        assert!(is_legal_transition(&TaskState::BlockedRecoveryPending, &TaskState::Admitted));
    }

    #[test]
    fn terminal_states_have_no_outbound_edges() {
        for terminal in &[TaskState::Aborted, TaskState::Cancelled, TaskState::Completed] {
            for any in &[
                TaskState::Admitted, TaskState::Running, TaskState::GatesPending,
                TaskState::Completed, TaskState::Failed, TaskState::Aborted,
                TaskState::Cancelled, TaskState::BlockedRecoveryPending,
            ] {
                assert!(
                    !is_legal_transition(terminal, any),
                    "{:?} → {:?} should be illegal",
                    terminal, any
                );
            }
        }
    }

    #[test]
    fn as_sql_str_round_trips() {
        for state in &[
            TaskState::Admitted, TaskState::Running, TaskState::GatesPending,
            TaskState::Completed, TaskState::Failed, TaskState::Aborted,
            TaskState::Cancelled, TaskState::BlockedRecoveryPending,
        ] {
            let s = state.as_sql_str();
            assert_eq!(
                TaskState::from_sql_str(s),
                Some(*state),
                "round-trip failed for {:?}",
                state
            );
        }
    }
}

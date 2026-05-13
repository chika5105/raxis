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
const SUBTASK_ACTIVATIONS: &str = Table::SubtaskActivations.as_str();

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

    // INV-STORE-02 — close out the matching active sub-task activation row
    // when the task reaches a terminal state. Migration 5 schema invariant
    // requires `activation_state IN ('Completed','Failed') ⇒ terminated_at
    // IS NOT NULL`, and `RetrySubTask` (handlers/intent.rs §Step 12) refuses
    // to admit a fresh activation unless the prior row is `'Failed'`. Without
    // this side-effect the kernel deadlocks: when an Executor's
    // `ReportFailure` (or `CompleteTask`) drives the task to Failed/
    // Completed, the activation row stays `'Active'`, the Orchestrator's
    // subsequent `RetrySubTask` is rejected with `InvalidRequest`, and
    // because RetrySubTask is not in `respawn_kinds` (handlers/intent.rs
    // ~line 372) no orchestrator respawn fires — the DAG silently stalls.
    //
    // Mapping (task → activation):
    //   Completed → Completed
    //   Failed | Aborted | Cancelled → Failed
    //     (the activation FSM has only `Completed` and `Failed` as terminal
    //     states; aborts/cancels collapse into `Failed` from the activation
    //     ledger's perspective. The richer reason lives on the task row's
    //     `block_reason` and `actor` columns.)
    //
    // The `WHERE activation_state = 'Active'` filter is the idempotency
    // guard: a transition that fires twice (e.g. recovery sweep on top
    // of a normal Completed) is a no-op. `PendingActivation` rows are
    // intentionally untouched — those have NULL `activated_at` so the
    // CHECK constraint forbids stamping them as terminal directly.
    if matches!(
        new_state,
        TaskState::Completed | TaskState::Failed
            | TaskState::Aborted | TaskState::Cancelled
    ) {
        let activation_state_terminal = match new_state {
            TaskState::Completed => "Completed",
            // Failed | Aborted | Cancelled all map to the activation
            // FSM's `Failed` (see doc comment above).
            _                    => "Failed",
        };
        conn.execute(
            &format!(
                "UPDATE {SUBTASK_ACTIVATIONS}
                    SET activation_state = ?1,
                        terminated_at    = ?2
                  WHERE task_id          = ?3
                    AND activation_state = 'Active'"
            ),
            rusqlite::params![activation_state_terminal, now, task_id],
        )?;
    }

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

    // ── Activation row close-out side-effect (Migration 5 invariant) ────────

    use raxis_types::InitiativeState;

    const INITIATIVES: &str = Table::Initiatives.as_str();

    /// Seed an initiative + a task in `Running` + a `subtask_activations`
    /// row in `Active`. Mirrors the post-`spawn_executor_for_task`
    /// substrate state right before the executor submits its terminal
    /// intent.
    fn seed_active_executor(store: &Store, task_id: &str, activation_id: &str) {
        let conn = store.lock_sync();
        let now = unix_now_secs();
        let _ = conn.execute(
            &format!(
                "INSERT OR IGNORE INTO {INITIATIVES}
                    (initiative_id, state, terminal_criteria_json,
                     plan_artifact_sha256, created_at)
                 VALUES ('init-fsm', ?1, '{{}}', 'deadbeef', ?2)"
            ),
            rusqlite::params![InitiativeState::Executing.as_sql_str(), now],
        );
        conn.execute(
            &format!(
                "INSERT INTO {TASKS}
                    (task_id, initiative_id, lane_id, state, actor,
                     policy_epoch, admitted_at, transitioned_at, actual_cost)
                 VALUES (?1, 'init-fsm', 'default', ?2, 'kernel',
                         1, ?3, ?3, 0)"
            ),
            rusqlite::params![task_id, TaskState::Running.as_sql_str(), now],
        ).unwrap();
        // Seed a session row so the activation's CHECK constraint
        // (`Active ⇒ session_id IS NOT NULL`) holds.
        conn.execute(
            "INSERT INTO sessions (
                session_id, role_id, session_token, sequence_number,
                worktree_root, base_sha, base_tracking_ref,
                lineage_id, fetch_quota, created_at, expires_at, revoked,
                session_agent_type, can_delegate, initiative_id
             ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,0,?12,0,'init-fsm')",
            rusqlite::params![
                "11111111-1111-1111-1111-111111111111",
                "Planner",
                "stub-token",
                0i64,
                Option::<String>::None,
                Option::<String>::None,
                Option::<String>::None,
                "lineage-1",
                1000i64,
                now,
                now + 86400,
                "Executor",
            ],
        ).unwrap();
        conn.execute(
            &format!(
                "INSERT INTO {SUBTASK_ACTIVATIONS} (
                    activation_id, task_id, initiative_id, activation_state,
                    session_id, evaluation_sha,
                    crash_retry_count, review_reject_count,
                    created_at, activated_at, terminated_at
                 ) VALUES (?1, ?2, 'init-fsm', 'Active',
                           '11111111-1111-1111-1111-111111111111', NULL,
                           0, 0, ?3, ?3, NULL)"
            ),
            rusqlite::params![activation_id, task_id, now],
        ).unwrap();
    }

    fn read_activation(store: &Store, activation_id: &str)
        -> (String, Option<i64>)
    {
        let conn = store.lock_sync();
        conn.query_row(
            &format!(
                "SELECT activation_state, terminated_at FROM {SUBTASK_ACTIVATIONS}
                  WHERE activation_id = ?1"
            ),
            rusqlite::params![activation_id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        ).unwrap()
    }

    /// Regression: Running → Failed must close the matching active
    /// activation row to `'Failed'` with a non-NULL `terminated_at`,
    /// so the Orchestrator's subsequent `RetrySubTask` (which gates
    /// on `prior_state == 'Failed'`) can admit a fresh activation.
    /// Without this side-effect the kernel deadlocks after the first
    /// failed executor — confirmed via live e2e iter 2 hang.
    #[test]
    fn running_to_failed_closes_active_activation_row() {
        let store = Store::open_in_memory().unwrap();
        seed_active_executor(&store, "t-fail", "act-fail");

        transition_task(
            "t-fail",
            TaskState::Failed,
            Some("executor surrendered"),
            TransitionActor::Kernel,
            &store,
        ).unwrap();

        let (state, terminated_at) = read_activation(&store, "act-fail");
        assert_eq!(state, "Failed",
            "activation row must transition Active → Failed when task fails");
        assert!(terminated_at.is_some(),
            "Migration 5 CHECK requires terminated_at IS NOT NULL on terminal activations");
    }

    /// Mirror: Running → Completed closes the active activation row to
    /// `'Completed'`. Guards the symmetric path for the success case
    /// (without it, completed-task activation rows accumulate as
    /// orphans and skew downstream activation analytics).
    #[test]
    fn running_to_completed_closes_active_activation_row() {
        let store = Store::open_in_memory().unwrap();
        seed_active_executor(&store, "t-done", "act-done");

        transition_task(
            "t-done",
            TaskState::Completed,
            None,
            TransitionActor::Kernel,
            &store,
        ).unwrap();

        let (state, terminated_at) = read_activation(&store, "act-done");
        assert_eq!(state, "Completed");
        assert!(terminated_at.is_some());
    }

    /// Aborted / Cancelled (operator-driven terminal transitions) also
    /// collapse the activation row into `'Failed'` — the activation
    /// FSM only has Completed/Failed; the operator-driven distinction
    /// is preserved on the `tasks.actor` and `tasks.block_reason`
    /// columns. Test guards both edges from `Running`.
    #[test]
    fn running_to_aborted_marks_activation_as_failed() {
        let store = Store::open_in_memory().unwrap();
        seed_active_executor(&store, "t-abort", "act-abort");

        transition_task(
            "t-abort",
            TaskState::Aborted,
            None,
            TransitionActor::Operator { fingerprint: "op-fp".to_owned() },
            &store,
        ).unwrap();

        let (state, terminated_at) = read_activation(&store, "act-abort");
        assert_eq!(state, "Failed",
            "activation FSM has no Aborted variant; collapse to Failed");
        assert!(terminated_at.is_some());
    }

    /// Idempotency: a second terminal transition on the same task is a
    /// no-op for the activation row (the WHERE filter rejects rows
    /// already in a terminal state). Exercises the recovery-sweep
    /// scenario where the kernel might re-emit the transition.
    #[test]
    fn second_terminal_transition_is_no_op_for_activation() {
        let store = Store::open_in_memory().unwrap();
        seed_active_executor(&store, "t-once", "act-once");

        transition_task(
            "t-once",
            TaskState::Failed,
            Some("first-fail"),
            TransitionActor::Kernel,
            &store,
        ).unwrap();

        let (_, first_term) = read_activation(&store, "act-once");
        // The task FSM rejects Failed→Failed (terminal-states-have-no-
        // outbound-edges), but the activation-side filter is what we
        // care about: even if a hypothetical retry path tried, it
        // would see `activation_state != 'Active'` and skip.
        let result = transition_task(
            "t-once",
            TaskState::Failed,
            Some("second-fail"),
            TransitionActor::Kernel,
            &store,
        );
        assert!(result.is_err(),
            "task FSM must reject Failed → Failed (terminal invariant)");

        let (state, term) = read_activation(&store, "act-once");
        assert_eq!(state, "Failed");
        assert_eq!(term, first_term,
            "terminated_at must be untouched by the failed retry");
    }
}

// raxis-kernel::scheduler::dag — Task DAG management.
//
// Normative reference: kernel-core.md §2.3 `src/scheduler/dag.rs`.
//
// Type-safety rules:
//   - Table names: use `Table::X.as_str()` — no raw "table_name" literals.
//   - State strings: use `TaskState::X.as_sql_str()` — no raw "'Admitted'" etc.

use raxis_store::{Store, Table};
use raxis_types::TaskState;

use crate::scheduler::SchedulerError;

const MAX_DAG_DEPTH: usize = 64;

// Table name shorthands — defined once so each SQL string is readable.
const TASKS: &str          = Table::Tasks.as_str();
const DAG_EDGES: &str      = Table::TaskDagEdges.as_str();

pub fn add_task(
    task_id:      &str,
    dependencies: &[String],
    store:        &Store,
) -> Result<(), SchedulerError> {
    detect_cycle(task_id, dependencies, store)?;
    insert_edges(task_id, dependencies, store)
}

pub fn insert_edges(
    task_id:      &str,
    dependencies: &[String],
    store:        &Store,
) -> Result<(), SchedulerError> {
    if dependencies.is_empty() {
        return Ok(());
    }
    let conn = store.lock_sync();
    for dep_id in dependencies {
        conn.execute(
            &format!(
                "INSERT OR IGNORE INTO {DAG_EDGES}
                    (predecessor_task_id, successor_task_id)
                 VALUES (?1, ?2)"
            ),
            rusqlite::params![dep_id, task_id],
        )?;
    }
    Ok(())
}

pub fn detect_cycle(
    new_task:      &str,
    proposed_deps: &[String],
    store:         &Store,
) -> Result<(), SchedulerError> {
    for dep in proposed_deps {
        let mut visited = std::collections::HashSet::new();
        let mut stack   = vec![(dep.to_owned(), 0usize)];

        while let Some((node, depth)) = stack.pop() {
            if depth > MAX_DAG_DEPTH {
                return Err(SchedulerError::DagDepthExceeded);
            }
            if node == new_task {
                return Err(SchedulerError::CyclicDependency);
            }
            if visited.contains(&node) {
                continue;
            }
            visited.insert(node.clone());

            for pred in get_predecessors(&node, store)? {
                stack.push((pred, depth + 1));
            }
        }
    }
    Ok(())
}

/// Return all task IDs ready for the planner in `initiative_id`.
///
/// Ready = state Admitted + all predecessors Completed.
pub fn next_ready_tasks(
    initiative_id: &str,
    store:         &Store,
) -> Result<Vec<String>, SchedulerError> {
    let admitted  = TaskState::Admitted.as_sql_str();
    let completed = TaskState::Completed.as_sql_str();

    let conn = store.lock_sync();
    let mut stmt = conn.prepare(&format!(
        "SELECT t.task_id FROM {TASKS} t
         WHERE t.initiative_id = ?1
           AND t.state = '{admitted}'
           AND NOT EXISTS (
               SELECT 1 FROM {DAG_EDGES} e
               JOIN {TASKS} pred ON pred.task_id = e.predecessor_task_id
               WHERE e.successor_task_id = t.task_id
                 AND pred.state != '{completed}'
           )"
    ))?;

    let ids: Vec<String> = stmt
        .query_map(rusqlite::params![initiative_id], |r| r.get::<_, String>(0))?
        .filter_map(|r| r.ok())
        .collect();

    Ok(ids)
}

/// Transition a task from `GatesPending` → `Admitted`.
///
/// Called by `handlers/witness.rs` after a gate-recheck returns Pass.
pub fn transition_to_admitted(task_id: &str, store: &Store) -> Result<(), SchedulerError> {
    let to_state   = TaskState::Admitted.as_sql_str();
    let from_state = TaskState::GatesPending.as_sql_str();
    let now        = now_unix_secs();

    let conn = store.lock_sync();
    let rows = conn.execute(
        &format!(
            "UPDATE {TASKS} SET state=?1, transitioned_at=?2, block_reason=NULL
             WHERE task_id=?3 AND state='{from_state}'"
        ),
        rusqlite::params![to_state, now, task_id],
    )?;
    if rows == 0 {
        return Err(SchedulerError::InvalidStateTransition {
            task_id: task_id.to_owned(),
            reason:  format!("task is not in {from_state} state"),
        });
    }
    Ok(())
}

/// Transition a task to `Completed` state.
pub fn mark_task_complete(task_id: &str, store: &Store) -> Result<(), SchedulerError> {
    let completed      = TaskState::Completed.as_sql_str();
    let terminal_not_in = terminal_states_not_in_sql();
    let now            = now_unix_secs();

    let conn = store.lock_sync();
    let rows = conn.execute(
        &format!(
            "UPDATE {TASKS} SET state=?1, transitioned_at=?2
             WHERE task_id=?3 AND state NOT IN ({terminal_not_in})"
        ),
        rusqlite::params![completed, now, task_id],
    )?;
    if rows == 0 {
        return Err(SchedulerError::InvalidStateTransition {
            task_id: task_id.to_owned(),
            reason:  "task is already in a terminal state".to_owned(),
        });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

fn get_predecessors(task_id: &str, store: &Store) -> Result<Vec<String>, SchedulerError> {
    let conn = store.lock_sync();
    let mut stmt = conn.prepare(&format!(
        "SELECT predecessor_task_id FROM {DAG_EDGES} WHERE successor_task_id=?1"
    ))?;
    let ids: Vec<String> = stmt
        .query_map(rusqlite::params![task_id], |r| r.get::<_, String>(0))?
        .filter_map(|r| r.ok())
        .collect();
    Ok(ids)
}

/// Builds the SQL `'State1', 'State2', ...` literal for NOT IN clauses.
/// Derived entirely from the TaskState enum — no raw strings.
fn terminal_states_not_in_sql() -> String {
    [
        TaskState::Completed,
        TaskState::Aborted,
        TaskState::Cancelled,
        TaskState::Failed,
    ]
    .iter()
    .map(|s| format!("'{}'", s.as_sql_str()))
    .collect::<Vec<_>>()
    .join(", ")
}

fn now_unix_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

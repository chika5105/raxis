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
    initiative_id: &str,
    task_id:       &str,
    dependencies:  &[String],
    store:         &Store,
) -> Result<(), SchedulerError> {
    let conn = store.lock_sync();
    detect_cycle_in(&conn, task_id, dependencies)?;
    insert_edges_in(&conn, initiative_id, task_id, dependencies)
}

/// Insert DAG edges for a single task using the supplied connection.
///
/// Takes `&Connection` so the caller can supply either a raw connection
/// (auto-commit) or a `Transaction<'_>`. Per kernel-store.md §2.5.1 INV-STORE-02
/// row "approve_plan", task rows and edge rows MUST be written in one
/// transaction — so production callers always pass a `Transaction<'_>`.
///
/// `initiative_id` populates the `task_dag_edges.initiative_id` column,
/// which is `NOT NULL REFERENCES initiatives(initiative_id)` per
/// kernel-store.md §2.5.1 Table 6.
pub fn insert_edges_in(
    conn:          &rusqlite::Connection,
    initiative_id: &str,
    task_id:       &str,
    dependencies:  &[String],
) -> Result<(), SchedulerError> {
    if dependencies.is_empty() {
        return Ok(());
    }
    for dep_id in dependencies {
        conn.execute(
            &format!(
                "INSERT OR IGNORE INTO {DAG_EDGES}
                    (initiative_id, predecessor_task_id, successor_task_id)
                 VALUES (?1, ?2, ?3)"
            ),
            rusqlite::params![initiative_id, dep_id, task_id],
        )?;
    }
    Ok(())
}

/// Cycle detection over the proposed dependency edges.
///
/// Reads `task_dag_edges` only — it does not write — but it MUST run inside
/// the same transaction that will insert the new edges, otherwise a
/// concurrent `admit` could insert a counter-edge between the check and
/// our insert and turn the resulting graph into a cycle.
///
/// The implementation is iterative DFS bounded by `MAX_DAG_DEPTH`.
pub fn detect_cycle_in(
    conn:          &rusqlite::Connection,
    new_task:      &str,
    proposed_deps: &[String],
) -> Result<(), SchedulerError> {
    let mut stmt = conn.prepare_cached(&format!(
        "SELECT predecessor_task_id FROM {DAG_EDGES} WHERE successor_task_id=?1"
    ))?;

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
            if !visited.insert(node.clone()) {
                continue;
            }

            let preds: Vec<String> = stmt
                .query_map(rusqlite::params![&node], |r| r.get::<_, String>(0))?
                .filter_map(|r| r.ok())
                .collect();
            for pred in preds {
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

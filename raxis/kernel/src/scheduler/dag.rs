// raxis-kernel::scheduler::dag — Task DAG management.
//
// Normative reference: kernel-core.md §2.3 `src/scheduler/dag.rs`.
//
// The DAG is persisted in `task_dag_edges` (predecessor_task_id, successor_task_id).
// No live in-memory DAG is maintained between requests — rebuilt from store on demand.
// This avoids state divergence after recovery.
//
// MAX_DAG_DEPTH = 64 — cycle detection DFS is bounded to this depth.

use raxis_store::Store;

use crate::scheduler::SchedulerError;

const MAX_DAG_DEPTH: usize = 64;

/// Add a task to the DAG with its declared dependencies.
///
/// - Runs cycle detection (pure read DFS).
/// - Inserts edges into `task_dag_edges`.
/// Called by `admit.rs` Step 3 after the task row is inserted (Step 2).
pub fn add_task(
    task_id: &str,
    dependencies: &[String],
    store: &Store,
) -> Result<(), SchedulerError> {
    detect_cycle(task_id, dependencies, store)?;
    insert_edges(task_id, dependencies, store)
}

/// Insert `(predecessor_task_id, successor_task_id)` edges for `task_id`.
///
/// Called by `admit` in Step 3, after the task row exists. Does NOT run cycle
/// detection — that is the caller's responsibility (admit Step 1).
pub fn insert_edges(
    task_id: &str,
    dependencies: &[String],
    store: &Store,
) -> Result<(), SchedulerError> {
    if dependencies.is_empty() {
        return Ok(());
    }
    let conn = store.lock_sync();
    for dep_id in dependencies {
        conn.execute(
            "INSERT OR IGNORE INTO task_dag_edges
                (predecessor_task_id, successor_task_id)
             VALUES (?1, ?2)",
            rusqlite::params![dep_id, task_id],
        )?;
    }
    Ok(())
}

/// Detect whether adding `proposed_deps → new_task` edges would create a cycle.
///
/// Pure read DFS from `new_task` following proposed edges backward through the
/// existing `task_dag_edges` table. Returns `SchedulerError::CyclicDependency`
/// if `new_task` is already reachable from any proposed dep.
/// Bounded to `MAX_DAG_DEPTH = 64` levels.
pub fn detect_cycle(
    new_task: &str,
    proposed_deps: &[String],
    store: &Store,
) -> Result<(), SchedulerError> {
    // DFS: starting from each proposed dep, follow existing edges backward.
    // If we ever reach `new_task`, a cycle would form.
    for dep in proposed_deps {
        let mut visited = std::collections::HashSet::new();
        let mut stack = vec![(dep.to_owned(), 0usize)];

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

            // Follow existing predecessors of this node.
            let predecessors = get_predecessors(&node, store)?;
            for pred in predecessors {
                stack.push((pred, depth + 1));
            }
        }
    }
    Ok(())
}

/// Return all `TaskId`s that are ready for the planner to pick up in `initiative_id`.
///
/// Ready = in `Admitted` state + all predecessor edges satisfied (predecessor Completed).
///
/// Note: `GatesPending` tasks are explicitly excluded — they are not schedulable
/// until a witness clears their gates and transitions them to `Admitted`.
pub fn next_ready_tasks(
    initiative_id: &str,
    store: &Store,
) -> Result<Vec<String>, SchedulerError> {
    let conn = store.lock_sync();

    // Tasks in Admitted state where either:
    //   (a) no predecessor edges exist, OR
    //   (b) ALL predecessor tasks are in Completed state.
    let mut stmt = conn.prepare(
        "SELECT t.task_id FROM tasks t
         WHERE t.initiative_id = ?1
           AND t.state = 'Admitted'
           AND NOT EXISTS (
               SELECT 1 FROM task_dag_edges e
               JOIN tasks pred ON pred.task_id = e.predecessor_task_id
               WHERE e.successor_task_id = t.task_id
                 AND pred.state != 'Completed'
           )",
    )?;

    let ids: Vec<String> = stmt
        .query_map(rusqlite::params![initiative_id], |r| r.get::<_, String>(0))?
        .filter_map(|r| r.ok())
        .collect();

    Ok(ids)
}

/// Transition a task from `GatesPending` → `Admitted`.
///
/// Called by `handlers/witness.rs` after a gate-recheck returns Pass.
/// Returns `SchedulerError::InvalidStateTransition` if current state is not `GatesPending`.
pub fn transition_to_admitted(task_id: &str, store: &Store) -> Result<(), SchedulerError> {
    let conn = store.lock_sync();
    let rows = conn.execute(
        "UPDATE tasks SET state='Admitted', block_reason=NULL
         WHERE task_id=?1 AND state='GatesPending'",
        rusqlite::params![task_id],
    )?;
    if rows == 0 {
        return Err(SchedulerError::InvalidStateTransition {
            task_id: task_id.to_owned(),
            reason: "task is not in GatesPending state".to_owned(),
        });
    }
    Ok(())
}

/// Transition a task to `Completed` state.
///
/// Called when the planner reports task completion. Subsequent `next_ready_tasks`
/// calls will surface tasks that depended on this one.
pub fn mark_task_complete(task_id: &str, store: &Store) -> Result<(), SchedulerError> {
    let conn = store.lock_sync();
    let now = now_unix_secs();
    let rows = conn.execute(
        "UPDATE tasks SET state='Completed', completed_at=?1
         WHERE task_id=?2 AND state NOT IN ('Completed', 'Aborted', 'Cancelled', 'Failed')",
        rusqlite::params![now, task_id],
    )?;
    if rows == 0 {
        return Err(SchedulerError::InvalidStateTransition {
            task_id: task_id.to_owned(),
            reason: "task is already in a terminal state".to_owned(),
        });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

fn get_predecessors(task_id: &str, store: &Store) -> Result<Vec<String>, SchedulerError> {
    let conn = store.lock_sync();
    let mut stmt = conn.prepare(
        "SELECT predecessor_task_id FROM task_dag_edges WHERE successor_task_id=?1",
    )?;
    let ids: Vec<String> = stmt
        .query_map(rusqlite::params![task_id], |r| r.get::<_, String>(0))?
        .filter_map(|r| r.ok())
        .collect();
    Ok(ids)
}

fn now_unix_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

// No unit tests in this file — all dag logic depends on a live Store connection.
// Integration tests live in tests/ and use a real on-disk or provided Store instance.
// The empty-dep fast-path is proven by code inspection: the for-loop body is
// unreachable when proposed_deps is empty, so detect_cycle trivially returns Ok(()).

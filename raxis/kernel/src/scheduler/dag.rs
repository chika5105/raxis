// raxis-kernel::scheduler::dag — Task DAG management.
//
// Normative reference: kernel-core.md §2.3 `src/scheduler/dag.rs`.
//
// Type-safety rules:
//   - Table names: use `Table::X.as_str()` — no raw "table_name" literals.
//   - State strings: use `TaskState::X.as_sql_str()` — no raw "'Admitted'" etc.

use raxis_audit_tools::AuditSink;
use raxis_store::{Store, Table};
use raxis_types::TaskState;

use crate::initiatives::task_transitions::{transition_task_with_audit, TransitionActor};
use crate::initiatives::LifecycleError;
use crate::scheduler::SchedulerError;

const MAX_DAG_DEPTH: usize = 64;

// Table name shorthands — defined once so each SQL string is readable.
const TASKS: &str = Table::Tasks.as_str();
const DAG_EDGES: &str = Table::TaskDagEdges.as_str();

pub fn add_task(
    initiative_id: &str,
    task_id: &str,
    dependencies: &[String],
    store: &Store,
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
    conn: &rusqlite::Connection,
    initiative_id: &str,
    task_id: &str,
    dependencies: &[String],
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
    conn: &rusqlite::Connection,
    new_task: &str,
    proposed_deps: &[String],
) -> Result<(), SchedulerError> {
    let mut stmt = conn.prepare_cached(&format!(
        "SELECT predecessor_task_id FROM {DAG_EDGES} WHERE successor_task_id=?1"
    ))?;

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
pub fn next_ready_tasks(initiative_id: &str, store: &Store) -> Result<Vec<String>, SchedulerError> {
    let admitted = TaskState::Admitted.as_sql_str();
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

/// Transition a task from `GatesPending` → `Admitted` AND emit the
/// paired `AuditEventKind::TaskStateChanged` audit row so the
/// dashboard's `SubscribeInitiative` push stream observes the
/// transition without polling.
///
/// Called by `handlers/witness.rs` after a gate-recheck returns Pass.
///
/// **`INV-DASHBOARD-PUSH-FSM-COMPLETENESS-01` / `INV-AUDIT-TASK-STATE-CHANGED-PAIRED-WRITE-01`.**
/// Previously this helper performed a raw `UPDATE tasks SET state=Admitted`
/// that bypassed the kernel-wide FSM-transition pipeline at
/// `task_transitions::transition_task_with_audit`, which meant the
/// audit chain carried a `GatesPending` task with no
/// `TaskStateChanged GatesPending → Admitted` row even though the
/// SQLite-side state did flip. The dashboard's per-task lifecycle
/// timeline therefore showed "GatesPending" indefinitely after the
/// gate-recheck cleared. The fix delegates the transition + audit
/// emit to the canonical helper, which validates the FSM edge,
/// performs the SQL UPDATE, and emits `TaskStateChanged` post-commit
/// in one call.
///
/// `session_id` is the originating planner session — surfaced on the
/// audit row's `session_id` column for cross-correlation. Pass
/// `None` only from tests that are exercising this helper in
/// isolation.
pub fn transition_to_admitted(
    task_id: &str,
    store: &Store,
    audit: &dyn AuditSink,
    session_id: Option<&str>,
) -> Result<(), SchedulerError> {
    transition_task_with_audit(
        task_id,
        TaskState::Admitted,
        None,
        TransitionActor::Kernel,
        store,
        audit,
        session_id,
    )
    .map(|_| ())
    .map_err(|e| match e {
        LifecycleError::TaskNotFound { task_id } => SchedulerError::TaskNotFound { task_id },
        LifecycleError::TaskNotAbortable { current_state } => {
            SchedulerError::InvalidStateTransition {
                task_id: task_id.to_owned(),
                reason: format!(
                    "task is not in {} state (current: {current_state})",
                    TaskState::GatesPending.as_sql_str()
                ),
            }
        }
        LifecycleError::Sql(e) => SchedulerError::Sql(e),
        other => SchedulerError::InvalidStateTransition {
            task_id: task_id.to_owned(),
            reason: format!("transition_task failed: {other}"),
        },
    })
}

#[cfg(test)]
mod tests {
    //! `INV-AUDIT-TASK-STATE-CHANGED-PAIRED-WRITE-01` /
    //! `INV-DASHBOARD-PUSH-FSM-COMPLETENESS-01` witness for the
    //! gate-recheck `GatesPending → Admitted` edge.
    //!
    //! Previously `transition_to_admitted` performed a raw
    //! `UPDATE tasks SET state = 'Admitted' WHERE state = 'GatesPending'`
    //! and never emitted the corresponding `TaskStateChanged`
    //! audit row. The iter62 audit chain therefore showed
    //! `GatesPending` tasks flipping to `Admitted` invisibly:
    //! the SQLite-side state changed, the dashboard-side
    //! `<LifecycleTimeline>` did not. This witness pins the
    //! post-fix paired-write contract.

    use super::*;
    use raxis_audit_tools::AuditEventKind;
    use raxis_test_support::FakeAuditSink;
    use raxis_types::{unix_now_secs, InitiativeState};

    /// Seed one initiative + one task in `GatesPending` so we can
    /// drive the canonical recheck-cleared edge.
    fn seed_gates_pending_task(store: &Store, task_id: &str) {
        let initiatives = Table::Initiatives.as_str();
        let tasks = Table::Tasks.as_str();
        let conn = store.lock_sync();
        let now = unix_now_secs();
        let _ = conn.execute(
            &format!(
                "INSERT OR IGNORE INTO {initiatives}
                    (initiative_id, state, terminal_criteria_json,
                     plan_artifact_sha256, created_at)
                 VALUES ('init-gp', ?1, '{{}}', 'deadbeef', ?2)"
            ),
            rusqlite::params![InitiativeState::Executing.as_sql_str(), now],
        );
        conn.execute(
            &format!(
                "INSERT INTO {tasks}
                    (task_id, initiative_id, lane_id, state, actor,
                     policy_epoch, admitted_at, transitioned_at, actual_cost,
                     block_reason)
                 VALUES (?1, 'init-gp', 'default', ?2, 'kernel',
                         1, ?3, ?3, 0, 'awaiting witness')"
            ),
            rusqlite::params![task_id, TaskState::GatesPending.as_sql_str(), now],
        )
        .unwrap();
    }

    #[test]
    fn inv_audit_task_state_changed_paired_write_01_gates_pending_to_admitted_emits_audit() {
        let store = Store::open_in_memory().unwrap();
        let task_id = "t-gates-clear";
        seed_gates_pending_task(&store, task_id);

        let audit = FakeAuditSink::new();
        transition_to_admitted(task_id, &store, &audit, Some("session-iter63"))
            .expect("recheck-cleared transition must succeed for GatesPending → Admitted");

        // SQL state flipped.
        let observed: String = {
            let conn = store.lock_sync();
            let tasks = Table::Tasks.as_str();
            conn.query_row(
                &format!("SELECT state FROM {tasks} WHERE task_id=?1"),
                rusqlite::params![task_id],
                |r| r.get(0),
            )
            .unwrap()
        };
        assert_eq!(observed, "Admitted", "task SQL state MUST flip to Admitted",);

        // Audit chain carries exactly one paired-write
        // `TaskStateChanged GatesPending → Admitted` row.
        let events = audit.events();
        let candidates: Vec<&AuditEventKind> = events
            .iter()
            .filter_map(|e| match &e.kind {
                k @ AuditEventKind::TaskStateChanged { task_id: t, .. } if t == task_id => Some(k),
                _ => None,
            })
            .collect();
        assert_eq!(
            candidates.len(),
            1,
            "INV-AUDIT-TASK-STATE-CHANGED-PAIRED-WRITE-01: exactly \
             one TaskStateChanged audit row per gate-recheck-clear; \
             observed {} matching events",
            candidates.len(),
        );
        match candidates[0] {
            AuditEventKind::TaskStateChanged {
                from_state,
                to_state,
                actor,
                ..
            } => {
                assert_eq!(
                    from_state, "GatesPending",
                    "from_state MUST be GatesPending"
                );
                assert_eq!(to_state, "Admitted", "to_state MUST be Admitted");
                assert_eq!(
                    actor, "kernel",
                    "gate-recheck-cleared transitions are kernel-driven"
                );
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn transition_to_admitted_rejects_non_gates_pending_state() {
        let store = Store::open_in_memory().unwrap();
        let task_id = "t-not-gates";
        let initiatives = Table::Initiatives.as_str();
        let tasks = Table::Tasks.as_str();
        {
            let conn = store.lock_sync();
            let now = unix_now_secs();
            let _ = conn.execute(
                &format!(
                    "INSERT OR IGNORE INTO {initiatives}
                        (initiative_id, state, terminal_criteria_json,
                         plan_artifact_sha256, created_at)
                     VALUES ('init-ng', ?1, '{{}}', 'deadbeef', ?2)"
                ),
                rusqlite::params![InitiativeState::Executing.as_sql_str(), now],
            );
            conn.execute(
                &format!(
                    "INSERT INTO {tasks}
                        (task_id, initiative_id, lane_id, state, actor,
                         policy_epoch, admitted_at, transitioned_at, actual_cost)
                     VALUES (?1, 'init-ng', 'default', ?2, 'kernel',
                             1, ?3, ?3, 0)"
                ),
                rusqlite::params![task_id, TaskState::Completed.as_sql_str(), now],
            )
            .unwrap();
        }

        let audit = FakeAuditSink::new();
        let err = transition_to_admitted(task_id, &store, &audit, None)
            .expect_err("Completed → Admitted MUST be rejected");
        match err {
            SchedulerError::InvalidStateTransition { reason, .. } => {
                assert!(
                    reason.contains(TaskState::GatesPending.as_sql_str()),
                    "rejection MUST name the expected source state; got {reason}",
                );
            }
            other => panic!("unexpected error: {other:?}"),
        }
        // No audit row emitted on rejection.
        assert!(
            audit.events().is_empty(),
            "rejected transitions MUST NOT emit audit",
        );
    }
}

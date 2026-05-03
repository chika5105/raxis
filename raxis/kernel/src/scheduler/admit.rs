// raxis-kernel::scheduler::admit — Plan-time task instantiation.
//
// Normative reference: kernel-core.md §2.3 `src/scheduler/admit.rs`.
//
// Called exclusively from `initiatives::lifecycle::approve_plan`.
// NOT called from the intent handler.
//
// Transaction model (kernel-store.md §2.5.1 INV-STORE-02 row "approve_plan"):
//   The caller owns the SQLite transaction. `admit_in_tx` takes a borrowed
//   `&Connection` (which `Transaction<'_>` derefs to) so the caller can
//   compose many `admit_in_tx` calls + the initiative UPDATE inside a single
//   `BEGIN`/`COMMIT`.
//
// Per-task work performed inside the transaction:
//   Step 1: detect_cycle_in — pure read, returns CyclicDependency on violation
//   Step 2: INSERT task row in Admitted state (before edges, due to FK)
//   Step 3: insert_edges_in — insert task_dag_edges rows
//
// Does NOT check or consume budget — that happens at intent time.
// Does NOT emit audit events — the caller (`approve_plan`) collects every
// admitted task and emits one batched audit record after the transaction
// commits, per §2.5.2 ("SQLite committed → JSONL appended").
//
// Type-safety rule: Table::X.as_str() for table names, TaskState::X.as_sql_str()
// for state strings — no raw string literals.

use raxis_store::Table;
use raxis_types::{unix_now_secs, TaskState};

use crate::scheduler::{dag, SchedulerError};

const TASKS: &str = Table::Tasks.as_str();

/// A task as derived from the plan artifact at approve_plan time.
///
/// Does NOT carry estimated_cost, touched_paths, or submitted_claims —
/// those are intent-time fields.
#[derive(Debug, Clone)]
pub struct PlanTask {
    pub task_id:      String,
    pub initiative_id: String,
    pub lane_id:      String,
    pub name:         String,
    pub dependencies: Vec<String>,
}

/// Admit a task inside an open transaction.
///
/// `conn` is `&Connection` so the caller can pass either a raw connection
/// or a `Transaction<'_>` (which derefs to `&Connection`). For approve_plan
/// it MUST be a transaction; passing a raw connection would violate
/// INV-STORE-02 because the task INSERT and the edge INSERTs would land
/// as two separate auto-commits.
///
/// `policy_epoch` is the epoch from the currently loaded PolicyBundle.
///
/// Returns the admitted `task_id` on success. On any error, the caller
/// MUST roll back the surrounding transaction (this function performs no
/// rollback of its own — the borrow checker enforces that the transaction
/// is owned outside).
pub fn admit_in_tx(
    conn:         &rusqlite::Connection,
    task:         PlanTask,
    policy_epoch: u64,
) -> Result<String, SchedulerError> {
    dag::detect_cycle_in(conn, &task.task_id, &task.dependencies)?;

    let now   = unix_now_secs();
    let state = TaskState::Admitted.as_sql_str();

    // Insert the task row first; the FK on task_dag_edges requires the
    // task row to exist before any edge mentioning it can be inserted.
    //
    // Column set is exhaustive vs kernel-store.md §2.5.1 Table 5:
    // task_id, initiative_id, lane_id, state, actor, policy_epoch,
    // admitted_at, transitioned_at, actual_cost. All other columns
    // (block_reason, session_id, evaluation_sha, base_sha,
    // submitted_claims_json, admission_reserved_units) are nullable
    // and stay NULL until the intent handler populates them.
    //
    // `name` is held on PlanTask for audit-event readability but the
    // DDL has no `name` column — it's deliberately not persisted.
    conn.execute(
        &format!(
            "INSERT OR IGNORE INTO {TASKS}
                (task_id, initiative_id, lane_id, state, actor,
                 policy_epoch, admitted_at, transitioned_at, actual_cost)
             VALUES (?1, ?2, ?3, ?4, 'kernel', ?5, ?6, ?6, 0)"
        ),
        rusqlite::params![
            &task.task_id,
            &task.initiative_id,
            &task.lane_id,
            state,
            policy_epoch as i64,
            now,
        ],
    ).map_err(SchedulerError::Sql)?;

    dag::insert_edges_in(conn, &task.initiative_id, &task.task_id, &task.dependencies)?;

    Ok(task.task_id)
}

// ---------------------------------------------------------------------------
// Tests — admit_in_tx schema conformance + transactional behavior
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use raxis_store::Store;

    fn fresh_store_with_initiative(init_id: &str) -> Store {
        let store = Store::open_in_memory().unwrap();
        let now = unix_now_secs();
        let conn = store.lock_sync();
        conn.execute(
            "INSERT INTO initiatives
                (initiative_id, state, terminal_criteria_json,
                 plan_artifact_sha256, created_at)
             VALUES (?1, 'Draft', '{}', 'deadbeef', ?2)",
            rusqlite::params![init_id, now],
        ).unwrap();
        drop(conn);
        store
    }

    /// Regression guard: the previous `scheduler::admit::admit` wrote a
    /// non-existent `name` column and omitted the required `actor` and
    /// `transitioned_at` columns. Running once must produce a row that
    /// fully validates against the v1 DDL.
    #[test]
    fn admit_in_tx_writes_all_required_columns() {
        let store = fresh_store_with_initiative("init-x");
        let mut conn = store.lock_sync();
        let tx = conn.transaction().unwrap();
        tx.execute_batch("PRAGMA defer_foreign_keys = 1;").unwrap();

        let task = PlanTask {
            task_id:       "t1".into(),
            initiative_id: "init-x".into(),
            lane_id:       "default".into(),
            name:          "first".into(),
            dependencies:  vec![],
        };
        admit_in_tx(&tx, task, 7).unwrap();
        tx.commit().unwrap();
        drop(conn);

        let conn = store.lock_sync();
        let (state, actor, epoch, admitted_at, transitioned_at): (String, String, i64, i64, i64) =
            conn.query_row(
                "SELECT state, actor, policy_epoch, admitted_at, transitioned_at
                   FROM tasks WHERE task_id='t1'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            ).unwrap();
        assert_eq!(state, "Admitted");
        assert_eq!(actor, "kernel");
        assert_eq!(epoch, 7);
        assert!(admitted_at > 0);
        assert_eq!(admitted_at, transitioned_at,
                   "transitioned_at and admitted_at must coincide on initial insert");
    }

    /// Edge insertion must include the initiative_id column (NOT NULL FK
    /// per kernel-store.md §2.5.1 Table 6). Pre-fix code omitted it and
    /// would have failed schema validation if anyone had called it.
    #[test]
    fn admit_in_tx_persists_dag_edges_with_initiative_id() {
        let store = fresh_store_with_initiative("init-edges");
        let mut conn = store.lock_sync();
        let tx = conn.transaction().unwrap();
        tx.execute_batch("PRAGMA defer_foreign_keys = 1;").unwrap();

        // First a predecessor with no deps.
        admit_in_tx(&tx, PlanTask {
            task_id:       "p1".into(),
            initiative_id: "init-edges".into(),
            lane_id:       "default".into(),
            name:          "pred".into(),
            dependencies:  vec![],
        }, 1).unwrap();

        // Then a successor depending on p1.
        admit_in_tx(&tx, PlanTask {
            task_id:       "s1".into(),
            initiative_id: "init-edges".into(),
            lane_id:       "default".into(),
            name:          "succ".into(),
            dependencies:  vec!["p1".into()],
        }, 1).unwrap();

        tx.commit().unwrap();
        drop(conn);

        let conn = store.lock_sync();
        let (init_id, pred, succ): (String, String, String) = conn.query_row(
            "SELECT initiative_id, predecessor_task_id, successor_task_id
               FROM task_dag_edges",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        ).unwrap();
        assert_eq!(init_id, "init-edges");
        assert_eq!(pred,    "p1");
        assert_eq!(succ,    "s1");
    }
}

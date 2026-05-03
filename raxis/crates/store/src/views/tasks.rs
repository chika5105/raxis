//! Task-table query catalog (cli-readonly.md §5.4.1 `tasks.rs`).
//!
//! Surface:
//!
//!   * [`counts_by_state`] — `raxis status` workload-summary block.
//!   * [`by_id`] — single-task lookup for `raxis inspect <task_id>`.
//!   * [`ready_set`] — "what could the scheduler pick up next" for
//!     `raxis queue`.
//!   * [`blocked_set`] — `raxis queue --blocked-only`.
//!
//! Every function:
//!   - takes `&RoConn` (no writes possible),
//!   - materialises owned types into a `Vec<_>`,
//!   - does a single `query_*` call (no per-row I/O fan-out).

use rusqlite::OptionalExtension;
use thiserror::Error;

use crate::ro::RoConn;
use crate::Table;

/// One row's worth of task data in the shape `raxis inspect` needs.
///
/// Field choice mirrors the `tasks` DDL (kernel-store.md §2.5.1
/// Table 5) plus a denormalised `initiative_state` for convenience —
/// the CLI nearly always wants both side-by-side.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskRow {
    pub task_id:                  String,
    pub initiative_id:            String,
    pub initiative_state:         String,
    pub lane_id:                  String,
    pub state:                    String,
    pub block_reason:             Option<String>,
    pub actor:                    String,
    pub policy_epoch:             u64,
    pub admitted_at:              u64,
    pub transitioned_at:          u64,
    pub session_id:               Option<String>,
    pub evaluation_sha:           Option<String>,
    pub base_sha:                 Option<String>,
    pub admission_reserved_units: Option<i64>,
    pub actual_cost:              i64,
}

/// One row's worth of "what's ready" — the smaller projection
/// `raxis queue` needs for its top-of-list summary.
///
/// Distinct from [`TaskRow`] so the queue command does not pay for
/// the full row at every poll.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadyTaskRow {
    pub task_id:       String,
    pub initiative_id: String,
    pub lane_id:       String,
    pub admitted_at:   u64,
}

/// Per-state row count used by `raxis status`.
///
/// All eight FSM states from kernel-store.md §2.5.1 Table 5 + a
/// `total` so the operator does not have to add up by hand. Fields
/// default to `0` for states with no rows so a JSON consumer always
/// sees the same key set.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
pub struct TaskStateCounts {
    pub admitted:                 u64,
    pub gates_pending:            u64,
    pub running:                  u64,
    pub completed:                u64,
    pub failed:                   u64,
    pub aborted:                  u64,
    pub cancelled:                u64,
    pub blocked_recovery_pending: u64,
    pub total:                    u64,
}

/// Failure modes for the task views.
#[derive(Debug, Error)]
pub enum TaskViewError {
    #[error("sqlite error during task view read: {0}")]
    Sqlite(#[from] rusqlite::Error),
}

/// One-shot per-state row counter for the entire `tasks` table.
///
/// One scan with a `GROUP BY state` aggregate; cheap on any v1 task
/// volume (operators with thousands of tasks should be on v2 anyway).
pub fn counts_by_state(conn: &RoConn) -> Result<TaskStateCounts, TaskViewError> {
    let mut counts = TaskStateCounts::default();
    let mut stmt = conn.prepare(&format!(
        "SELECT state, COUNT(*) FROM {} GROUP BY state",
        Table::Tasks.as_str(),
    ))?;
    let rows = stmt.query_map([], |r| {
        let state: String = r.get(0)?;
        let count: i64 = r.get(1)?;
        Ok((state, count))
    })?;

    for row in rows {
        let (state, count) = row?;
        let n = count.max(0) as u64;
        match state.as_str() {
            "Admitted"               => counts.admitted = n,
            "GatesPending"           => counts.gates_pending = n,
            "Running"                => counts.running = n,
            "Completed"              => counts.completed = n,
            "Failed"                 => counts.failed = n,
            "Aborted"                => counts.aborted = n,
            "Cancelled"              => counts.cancelled = n,
            "BlockedRecoveryPending" => counts.blocked_recovery_pending = n,
            // CHECK constraint on the `state` column already restricts
            // the universe, but a future schema migration could add a
            // new state. We drop unknowns silently rather than fail
            // — the CLI's `total` line keeps the row honest.
            _ => {}
        }
        counts.total = counts.total.saturating_add(n);
    }
    Ok(counts)
}

/// Look up a single task by `task_id`. Returns `None` when no such
/// task exists — the CLI then renders `task <id> not found` rather
/// than treating it as an error.
pub fn by_id(conn: &RoConn, task_id: &str) -> Result<Option<TaskRow>, TaskViewError> {
    let sql = format!(
        "SELECT t.task_id, t.initiative_id, i.state, t.lane_id, t.state, \
                t.block_reason, t.actor, t.policy_epoch, t.admitted_at, \
                t.transitioned_at, t.session_id, t.evaluation_sha, \
                t.base_sha, t.admission_reserved_units, t.actual_cost \
         FROM {tasks} t \
         JOIN {initiatives} i ON i.initiative_id = t.initiative_id \
         WHERE t.task_id = ?1",
        tasks = Table::Tasks.as_str(),
        initiatives = Table::Initiatives.as_str(),
    );
    let row = conn.query_row(&sql, rusqlite::params![task_id], |r| {
        Ok(TaskRow {
            task_id:                  r.get(0)?,
            initiative_id:            r.get(1)?,
            initiative_state:         r.get(2)?,
            lane_id:                  r.get(3)?,
            state:                    r.get(4)?,
            block_reason:             r.get(5)?,
            actor:                    r.get(6)?,
            policy_epoch:             r.get::<_, i64>(7)?.max(0) as u64,
            admitted_at:              r.get::<_, i64>(8)?.max(0) as u64,
            transitioned_at:          r.get::<_, i64>(9)?.max(0) as u64,
            session_id:               r.get(10)?,
            evaluation_sha:           r.get(11)?,
            base_sha:                 r.get(12)?,
            admission_reserved_units: r.get(13)?,
            actual_cost:              r.get(14)?,
        })
    }).optional()?;
    Ok(row)
}

/// Tasks the scheduler could pick up right now: state IN
/// (`Admitted`, `GatesPending`).
///
/// Ordered by `admitted_at ASC` so the CLI shows oldest-waiting first
/// — the "longest queued" task is the one operator attention should
/// focus on.
///
/// `lane_filter` narrows to a single lane when provided; pass `None`
/// to see all lanes.
pub fn ready_set(
    conn: &RoConn,
    lane_filter: Option<&str>,
    limit: usize,
) -> Result<Vec<ReadyTaskRow>, TaskViewError> {
    let mut sql = format!(
        "SELECT task_id, initiative_id, lane_id, admitted_at \
         FROM {} \
         WHERE state IN ('Admitted', 'GatesPending')",
        Table::Tasks.as_str(),
    );
    if lane_filter.is_some() {
        sql.push_str(" AND lane_id = ?1");
    }
    sql.push_str(" ORDER BY admitted_at ASC LIMIT ?");
    sql.push_str(if lane_filter.is_some() { "2" } else { "1" });

    let mut stmt = conn.prepare(&sql)?;
    let limit_i = limit as i64;
    let rows = if let Some(lane) = lane_filter {
        stmt.query_map(rusqlite::params![lane, limit_i], map_ready_row)?
            .collect::<Result<Vec<_>, _>>()?
    } else {
        stmt.query_map(rusqlite::params![limit_i], map_ready_row)?
            .collect::<Result<Vec<_>, _>>()?
    };
    Ok(rows)
}

/// Tasks the scheduler considers blocked: state =
/// `BlockedRecoveryPending` (the only `Blocked*` state in v1's
/// FSM). Same ordering + paging contract as [`ready_set`].
pub fn blocked_set(
    conn: &RoConn,
    limit: usize,
) -> Result<Vec<TaskRow>, TaskViewError> {
    let sql = format!(
        "SELECT t.task_id, t.initiative_id, i.state, t.lane_id, t.state, \
                t.block_reason, t.actor, t.policy_epoch, t.admitted_at, \
                t.transitioned_at, t.session_id, t.evaluation_sha, \
                t.base_sha, t.admission_reserved_units, t.actual_cost \
         FROM {tasks} t \
         JOIN {initiatives} i ON i.initiative_id = t.initiative_id \
         WHERE t.state = 'BlockedRecoveryPending' \
         ORDER BY t.transitioned_at ASC LIMIT ?1",
        tasks = Table::Tasks.as_str(),
        initiatives = Table::Initiatives.as_str(),
    );
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(rusqlite::params![limit as i64], |r| {
        Ok(TaskRow {
            task_id:                  r.get(0)?,
            initiative_id:            r.get(1)?,
            initiative_state:         r.get(2)?,
            lane_id:                  r.get(3)?,
            state:                    r.get(4)?,
            block_reason:             r.get(5)?,
            actor:                    r.get(6)?,
            policy_epoch:             r.get::<_, i64>(7)?.max(0) as u64,
            admitted_at:              r.get::<_, i64>(8)?.max(0) as u64,
            transitioned_at:          r.get::<_, i64>(9)?.max(0) as u64,
            session_id:               r.get(10)?,
            evaluation_sha:           r.get(11)?,
            base_sha:                 r.get(12)?,
            admission_reserved_units: r.get(13)?,
            actual_cost:              r.get(14)?,
        })
    })?.collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

fn map_ready_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<ReadyTaskRow> {
    Ok(ReadyTaskRow {
        task_id:       r.get(0)?,
        initiative_id: r.get(1)?,
        lane_id:       r.get(2)?,
        admitted_at:   r.get::<_, i64>(3)?.max(0) as u64,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ro::open as open_ro, Store};
    use tempfile::TempDir;

    fn fresh_store_with_seed_tasks() -> (TempDir, std::path::PathBuf) {
        let tmp = TempDir::new().unwrap();
        let db = tmp.path().join("kernel.db");
        {
            let store = Store::open(&db).unwrap();
            let guard = store.lock_sync();
            // Initiative the tasks point at.
            guard.execute(
                "INSERT INTO initiatives \
                 (initiative_id, state, terminal_criteria_json, plan_artifact_sha256, created_at) \
                 VALUES ('init-1', 'Executing', '{}', 'sha-1', 1)",
                [],
            ).unwrap();
            // 4 tasks — Running, Admitted, Admitted (different lane),
            // BlockedRecoveryPending. Cover the counter and ready/blocked
            // selectors all at once.
            for (id, state, lane, admitted_at, block) in [
                ("t-1", "Running", "default", 100_i64, None::<&str>),
                ("t-2", "Admitted", "default", 200, None),
                ("t-3", "Admitted", "fast", 50, None),
                ("t-4", "BlockedRecoveryPending", "default", 10, Some("waiting on t-1")),
            ] {
                guard.execute(
                    "INSERT INTO tasks \
                     (task_id, initiative_id, lane_id, state, actor, \
                      policy_epoch, admitted_at, transitioned_at, block_reason) \
                     VALUES (?1, 'init-1', ?2, ?3, 'op', 1, ?4, ?4, ?5)",
                    rusqlite::params![id, lane, state, admitted_at, block],
                ).unwrap();
            }
        }
        (tmp, db)
    }

    #[test]
    fn counts_by_state_aggregates_every_state_label() {
        let (tmp, _) = fresh_store_with_seed_tasks();
        let conn = open_ro(tmp.path()).unwrap();
        let counts = counts_by_state(&conn).unwrap();
        assert_eq!(counts.running, 1);
        assert_eq!(counts.admitted, 2);
        assert_eq!(counts.blocked_recovery_pending, 1);
        assert_eq!(counts.total, 4);
        assert_eq!(counts.completed, 0);
    }

    #[test]
    fn by_id_returns_none_for_missing_task() {
        let (tmp, _) = fresh_store_with_seed_tasks();
        let conn = open_ro(tmp.path()).unwrap();
        assert!(by_id(&conn, "t-does-not-exist").unwrap().is_none());
    }

    #[test]
    fn by_id_returns_full_row_for_known_task() {
        let (tmp, _) = fresh_store_with_seed_tasks();
        let conn = open_ro(tmp.path()).unwrap();
        let row = by_id(&conn, "t-4").unwrap().expect("present");
        assert_eq!(row.state, "BlockedRecoveryPending");
        assert_eq!(row.initiative_id, "init-1");
        assert_eq!(row.initiative_state, "Executing");
        assert_eq!(row.block_reason.as_deref(), Some("waiting on t-1"));
    }

    #[test]
    fn ready_set_orders_by_admitted_at_ascending() {
        let (tmp, _) = fresh_store_with_seed_tasks();
        let conn = open_ro(tmp.path()).unwrap();
        let rows = ready_set(&conn, None, 10).unwrap();
        // Two Admitted tasks: t-3 (admitted_at=50) before t-2 (200).
        let ids: Vec<&str> = rows.iter().map(|r| r.task_id.as_str()).collect();
        assert_eq!(ids, vec!["t-3", "t-2"], "expected oldest-first ordering");
    }

    #[test]
    fn ready_set_filters_by_lane() {
        let (tmp, _) = fresh_store_with_seed_tasks();
        let conn = open_ro(tmp.path()).unwrap();
        let only_default = ready_set(&conn, Some("default"), 10).unwrap();
        assert_eq!(only_default.len(), 1);
        assert_eq!(only_default[0].task_id, "t-2");
    }

    #[test]
    fn ready_set_respects_limit() {
        let (tmp, _) = fresh_store_with_seed_tasks();
        let conn = open_ro(tmp.path()).unwrap();
        let only_one = ready_set(&conn, None, 1).unwrap();
        assert_eq!(only_one.len(), 1);
        assert_eq!(only_one[0].task_id, "t-3"); // Oldest Admitted task.
    }

    #[test]
    fn blocked_set_returns_only_blocked_recovery_pending() {
        let (tmp, _) = fresh_store_with_seed_tasks();
        let conn = open_ro(tmp.path()).unwrap();
        let rows = blocked_set(&conn, 10).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].task_id, "t-4");
        assert_eq!(rows[0].state, "BlockedRecoveryPending");
    }
}

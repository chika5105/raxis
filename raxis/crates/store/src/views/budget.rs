//! Lane-budget query catalog (cli-readonly.md §5.4.1 `budget.rs`).
//!
//! Surface:
//!   * [`per_lane`] — aggregated reserved_cost per lane_id with the
//!     count of in-flight tasks. Joined with the policy bundle on the
//!     CLI side to compute pressure (reserved / max_cost_per_epoch).
//!   * [`reservations_for_lane`] — every active reservation row for
//!     one lane, newest-first.
//!
//! These are the "what's pinned right now?" reads. The historical
//! "how did we get here?" view lives in `views::tasks::counts_by_state`
//! (Completed + Aborted + Failed counts) and the audit log
//! (`LaneBudgetCharged` events) — neither is duplicated here.

use thiserror::Error;

use crate::ro::RoConn;
use crate::Table;

/// One row of the per-lane aggregate. `reserved_cost` is the SUM of
/// `lane_budget_reservations.reserved_cost`; `task_count` is the
/// COUNT.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaneBudgetRow {
    pub lane_id:       String,
    pub reserved_cost: u64,
    pub task_count:    u64,
}

/// One row of `lane_budget_reservations`, projected for the CLI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReservationRow {
    pub lane_id:       String,
    pub task_id:       String,
    pub reserved_cost: u64,
    pub reserved_at:   u64,
}

#[derive(Debug, Error)]
pub enum BudgetViewError {
    #[error("sqlite error during budget view read: {0}")]
    Sqlite(#[from] rusqlite::Error),
}

/// One row per lane that has at least one active reservation.
/// Ordered by `reserved_cost DESC` so the most pressured lane is
/// line 1.
pub fn per_lane(conn: &RoConn) -> Result<Vec<LaneBudgetRow>, BudgetViewError> {
    let mut stmt = conn.prepare(&format!(
        "SELECT lane_id, COALESCE(SUM(reserved_cost), 0), COUNT(*) \
         FROM {} \
         GROUP BY lane_id \
         ORDER BY SUM(reserved_cost) DESC",
        Table::LaneBudgetReservations.as_str(),
    ))?;
    let rows = stmt
        .query_map([], |r| {
            Ok(LaneBudgetRow {
                lane_id:       r.get(0)?,
                reserved_cost: r.get::<_, i64>(1)?.max(0) as u64,
                task_count:    r.get::<_, i64>(2)?.max(0) as u64,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

/// Every active reservation for `lane_id`, newest-first. Empty `Vec`
/// for an unknown lane (the function does NOT distinguish "lane has
/// zero reservations" from "lane does not appear in the policy" —
/// callers cross-check against `PolicyBundle::lanes()` if they need
/// that signal).
pub fn reservations_for_lane(
    conn:    &RoConn,
    lane_id: &str,
    limit:   usize,
) -> Result<Vec<ReservationRow>, BudgetViewError> {
    let mut stmt = conn.prepare(&format!(
        "SELECT lane_id, task_id, reserved_cost, reserved_at \
         FROM {} \
         WHERE lane_id = ?1 \
         ORDER BY reserved_at DESC LIMIT ?2",
        Table::LaneBudgetReservations.as_str(),
    ))?;
    let rows = stmt
        .query_map(rusqlite::params![lane_id, limit as i64], |r| {
            Ok(ReservationRow {
                lane_id:       r.get(0)?,
                task_id:       r.get(1)?,
                reserved_cost: r.get::<_, i64>(2)?.max(0) as u64,
                reserved_at:   r.get::<_, i64>(3)?.max(0) as u64,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ro::open as open_ro, Store};
    use tempfile::TempDir;

    fn fresh_store_with_seed_reservations() -> TempDir {
        const INITIATIVES:              &str = Table::Initiatives.as_str();
        const TASKS:                    &str = Table::Tasks.as_str();
        const LANE_BUDGET_RESERVATIONS: &str = Table::LaneBudgetReservations.as_str();
        let tmp = TempDir::new().unwrap();
        let db = tmp.path().join("kernel.db");
        let store = Store::open(&db).unwrap();
        let guard = store.lock_sync();
        guard.execute(
            &format!(
                "INSERT INTO {INITIATIVES} \
                 (initiative_id, state, terminal_criteria_json, plan_artifact_sha256, created_at) \
                 VALUES ('init-1', 'Executing', '{{}}', 'sha-1', 1)"
            ),
            [],
        ).unwrap();
        // Tasks (FK target).
        for id in ["t-a", "t-b", "t-c"] {
            guard.execute(
                &format!(
                    "INSERT INTO {TASKS} \
                     (task_id, initiative_id, lane_id, state, actor, \
                      policy_epoch, admitted_at, transitioned_at) \
                     VALUES (?1, 'init-1', 'd', 'Running', 'op', 1, 1, 1)"
                ),
                rusqlite::params![id],
            ).unwrap();
        }
        // Reservations: lane "default" gets 30 across 2 tasks; lane
        // "high" gets 100 across 1 task.
        for (lane, task, cost, at) in [
            ("default", "t-a", 10_i64, 100_i64),
            ("default", "t-b", 20,     200),
            ("high",    "t-c", 100,    300),
        ] {
            guard.execute(
                &format!(
                    "INSERT INTO {LANE_BUDGET_RESERVATIONS} \
                     (lane_id, task_id, reserved_cost, reserved_at) \
                     VALUES (?1, ?2, ?3, ?4)"
                ),
                rusqlite::params![lane, task, cost, at],
            ).unwrap();
        }
        tmp
    }

    #[test]
    fn per_lane_sums_reserved_cost_and_counts_tasks() {
        let tmp = fresh_store_with_seed_reservations();
        let conn = open_ro(tmp.path()).unwrap();
        let rows = per_lane(&conn).unwrap();
        // Ordered by reserved_cost DESC: "high" (100) first.
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].lane_id, "high");
        assert_eq!(rows[0].reserved_cost, 100);
        assert_eq!(rows[0].task_count, 1);
        assert_eq!(rows[1].lane_id, "default");
        assert_eq!(rows[1].reserved_cost, 30);
        assert_eq!(rows[1].task_count, 2);
    }

    #[test]
    fn reservations_for_lane_returns_only_requested_lane_newest_first() {
        let tmp = fresh_store_with_seed_reservations();
        let conn = open_ro(tmp.path()).unwrap();
        let rows = reservations_for_lane(&conn, "default", 100).unwrap();
        assert_eq!(rows.len(), 2);
        assert!(rows.iter().all(|r| r.lane_id == "default"));
        // newest-first by reserved_at: t-b (200) then t-a (100).
        assert_eq!(rows[0].task_id, "t-b");
        assert_eq!(rows[1].task_id, "t-a");
    }

    #[test]
    fn reservations_for_lane_returns_empty_for_unknown_lane() {
        let tmp = fresh_store_with_seed_reservations();
        let conn = open_ro(tmp.path()).unwrap();
        assert!(reservations_for_lane(&conn, "no-such-lane", 100).unwrap().is_empty());
    }
}

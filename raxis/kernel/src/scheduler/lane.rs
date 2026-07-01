// raxis-kernel::scheduler::lane — Lane configuration and status.
//
// Normative reference: kernel-core.md §2.3 `src/scheduler/lane.rs`.
//
// Type-safety rule: Table::X.as_str() for table names; TaskState::X.as_sql_str()
// for state strings — no raw string literals.

use raxis_policy::PolicyBundle;
use raxis_store::{Store, Table};
use raxis_types::TaskState;

use crate::scheduler::SchedulerError;

const TASKS: &str = Table::Tasks.as_str();
const BUDGET: &str = Table::LaneBudgetReservations.as_str();

/// Lane configuration loaded from policy.
#[derive(Debug, Clone)]
pub struct LaneConfig {
    pub lane_id: String,
    pub max_concurrent_tasks: u32,
    pub max_cost_per_epoch: u64,
    pub priority: u8,
}

/// Live lane status from the store.
#[derive(Debug, Clone)]
pub struct LaneStatus {
    pub active_tasks: u32,
    pub reserved_cost: u64,
}

/// Get the configuration for a lane from the policy bundle.
pub fn lane_config_for_row(
    lane_id: &str,
    policy: &PolicyBundle,
) -> Result<LaneConfig, SchedulerError> {
    policy
        .lane_config(lane_id)
        .map(|lc| LaneConfig {
            lane_id: lane_id.to_owned(),
            max_concurrent_tasks: lc.max_concurrent_tasks,
            max_cost_per_epoch: lc.max_cost_per_epoch,
            priority: lc.priority,
        })
        .ok_or(SchedulerError::NoLaneAssigned)
}

/// Get current live status for a lane (active tasks + reserved cost).
///
/// Convenience wrapper around `get_lane_status_in_tx` that opens its own
/// mutex acquisition and runs the two SELECTs auto-committed (read-only,
/// so atomicity vs other writers is not required for callers that only
/// need a snapshot for reporting). Write paths that gate on this status
/// MUST use `get_lane_status_in_tx` inside a single transaction with the
/// follow-up write — see `scheduler::budget::reserve_budget_in_tx` and
/// `kernel-store.md` §2.5.1.1 Pattern A for why.
pub fn get_lane_status(lane_id: &str, store: &Store) -> Result<LaneStatus, SchedulerError> {
    let conn = store.lock_sync();
    get_lane_status_in_tx(&conn, lane_id)
}

/// Compute lane status from inside an existing transaction.
///
/// **INV-STORE-02 (kernel-store.md §2.5.1.1 Pattern A):** any write that
/// uses this status to make an admission decision MUST run both this read
/// and the follow-up write inside the same transaction held under one
/// mutex acquisition. The pre-fix code had a TOCTOU window where two
/// concurrent intents could both pass `check_budget` before either ran
/// `consume_budget`, over-committing the lane.
pub fn get_lane_status_in_tx(
    conn: &rusqlite::Connection,
    lane_id: &str,
) -> Result<LaneStatus, SchedulerError> {
    // Build NOT IN from enum — no raw state strings (INV-STORE-03).
    let terminal = [
        TaskState::Completed,
        TaskState::Failed,
        TaskState::Aborted,
        TaskState::Cancelled,
    ]
    .iter()
    .map(|s| format!("'{}'", s.as_sql_str()))
    .collect::<Vec<_>>()
    .join(", ");

    // INV-SCHED-LANE-STATUS-FAIL-CLOSED-01 — propagate SQL errors instead
    // of coercing them to `0`. `reserve_budget_in_tx` calls this inside
    // its admission transaction; a transient `database is locked` or a
    // corrupted ledger row MUST NOT silently admit work as if the lane
    // were empty.
    let active_tasks: u32 = conn.query_row(
        &format!("SELECT COUNT(*) FROM {TASKS} WHERE lane_id=?1 AND state NOT IN ({terminal})"),
        rusqlite::params![lane_id],
        |r| r.get(0),
    )?;

    let reserved_cost: u64 = conn.query_row(
        &format!(
            "SELECT COALESCE(SUM(b.reserved_cost), 0)
               FROM {BUDGET} b
               JOIN {TASKS} t ON t.task_id = b.task_id
              WHERE b.lane_id = ?1
                AND t.state NOT IN ({terminal})"
        ),
        rusqlite::params![lane_id],
        |r| r.get(0),
    )?;

    Ok(LaneStatus {
        active_tasks,
        reserved_cost,
    })
}

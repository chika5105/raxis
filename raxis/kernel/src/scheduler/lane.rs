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

const TASKS:  &str = Table::Tasks.as_str();
const BUDGET: &str = Table::LaneBudgetReservations.as_str();

/// Lane configuration loaded from policy.
#[derive(Debug, Clone)]
pub struct LaneConfig {
    pub lane_id:              String,
    pub max_concurrent_tasks: u32,
    pub max_cost_per_epoch:   u64,
    pub priority:             u8,
}

/// Live lane status from the store.
#[derive(Debug, Clone)]
pub struct LaneStatus {
    pub active_tasks:  u32,
    pub reserved_cost: u64,
}

/// Get the configuration for a lane from the policy bundle.
pub fn lane_config_for_row(lane_id: &str, policy: &PolicyBundle) -> Result<LaneConfig, SchedulerError> {
    policy.lane_config(lane_id)
        .map(|lc| LaneConfig {
            lane_id:              lane_id.to_owned(),
            max_concurrent_tasks: lc.max_concurrent_tasks,
            max_cost_per_epoch:   lc.max_cost_per_epoch,
            priority:             lc.priority,
        })
        .ok_or(SchedulerError::NoLaneAssigned)
}

/// Get current live status for a lane (active tasks + reserved cost).
pub fn get_lane_status(lane_id: &str, store: &Store) -> Result<LaneStatus, SchedulerError> {
    // Build NOT IN from enum — no raw state strings.
    let terminal = [TaskState::Completed, TaskState::Failed, TaskState::Aborted, TaskState::Cancelled]
        .iter()
        .map(|s| format!("'{}'", s.as_sql_str()))
        .collect::<Vec<_>>()
        .join(", ");

    let conn = store.lock_sync();
    let active_tasks: u32 = conn.query_row(
        &format!("SELECT COUNT(*) FROM {TASKS} WHERE lane_id=?1 AND state NOT IN ({terminal})"),
        rusqlite::params![lane_id],
        |r| r.get(0),
    ).unwrap_or(0);

    let reserved_cost: u64 = conn.query_row(
        &format!("SELECT COALESCE(SUM(reserved_cost), 0) FROM {BUDGET} WHERE lane_id=?1"),
        rusqlite::params![lane_id],
        |r| r.get(0),
    ).unwrap_or(0);

    Ok(LaneStatus { active_tasks, reserved_cost })
}

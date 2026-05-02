// raxis-kernel::scheduler::lane — Lane configuration and status.
//
// Normative reference: kernel-core.md §2.3 `src/scheduler/lane.rs`.
//
// A lane is a named execution channel with a concurrency cap and cost ceiling.
// Lane definitions are part of the signed policy artifact — the scheduler reads
// but never writes lane configuration.

use raxis_policy::PolicyBundle;
use raxis_store::Store;

use crate::scheduler::SchedulerError;

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
///
/// Returns `SchedulerError::NoLaneAssigned` if the lane is not in the policy.
pub fn lane_config_for_row(lane_id: &str, policy: &PolicyBundle) -> Result<LaneConfig, SchedulerError> {
    policy.lane_config(lane_id)
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
/// Used by `raxis-cli status` and `scheduler::budget::check_budget`.
pub fn get_lane_status(lane_id: &str, store: &Store) -> Result<LaneStatus, SchedulerError> {
    let conn = store.lock_sync();

    let active_tasks: u32 = conn.query_row(
        "SELECT COUNT(*) FROM tasks
         WHERE lane_id=?1 AND state NOT IN ('Completed', 'Failed', 'Aborted', 'Cancelled')",
        rusqlite::params![lane_id],
        |r| r.get(0),
    ).unwrap_or(0);

    let reserved_cost: u64 = conn.query_row(
        "SELECT COALESCE(SUM(reserved_cost), 0) FROM lane_budget_reservations WHERE lane_id=?1",
        rusqlite::params![lane_id],
        |r| r.get(0),
    ).unwrap_or(0);

    Ok(LaneStatus { active_tasks, reserved_cost })
}

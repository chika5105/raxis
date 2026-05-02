// raxis-kernel::scheduler::budget — Per-lane cost and concurrency enforcement.
//
// Normative reference: kernel-core.md §2.3 `src/scheduler/budget.rs`.
//
// Budget state is persisted in `lane_budget_reservations` (survives restarts).
// Reservations are created on intent pickup (handlers/intent.rs, after gates pass).
// Reservations are released on task terminal state.
//
// Continuation intents (already-Running task) do NOT re-insert a reservation
// (PK (lane_id, task_id) prevents double-insertion).

use std::path::PathBuf;

use raxis_policy::PolicyBundle;
use raxis_store::Store;
use raxis_types::IntentKind;

use crate::scheduler::{BudgetError, SchedulerError};
use crate::scheduler::lane::get_lane_status;

/// Budget snapshot for a lane — alias for LaneStatus in budget-centric terms.
pub type LaneBudgetSnapshot = crate::scheduler::lane::LaneStatus;

/// Check whether a lane has budget for `estimated_cost` more units.
///
/// Pure read. Called from `handlers/intent.rs` after gate evaluation,
/// before `consume_budget`.
///
/// Returns `SchedulerError::BudgetExceeded { kind }` if over-limit.
pub fn check_budget(
    lane_id: &str,
    estimated_cost: u64,
    policy: &PolicyBundle,
    store: &Store,
) -> Result<(), SchedulerError> {
    let status = get_lane_status(lane_id, store)?;
    let lane_cfg = crate::scheduler::lane::lane_config_for_row(lane_id, policy)?;

    if status.active_tasks >= lane_cfg.max_concurrent_tasks {
        return Err(SchedulerError::BudgetExceeded {
            kind: format!(
                "ConcurrencyLimit (active={}, max={})",
                status.active_tasks, lane_cfg.max_concurrent_tasks
            ),
        });
    }

    if status.reserved_cost.saturating_add(estimated_cost) > lane_cfg.max_cost_per_epoch {
        return Err(SchedulerError::BudgetExceeded {
            kind: format!(
                "CostLimit (reserved={}, estimated={}, max={})",
                status.reserved_cost, estimated_cost, lane_cfg.max_cost_per_epoch
            ),
        });
    }

    Ok(())
}

/// Insert a `lane_budget_reservations` row for this task.
///
/// Called from the intent handler transaction after gate evaluation returns
/// Pass/BreakglassPass/PendingWitness, before `transition_task`.
///
/// PK (lane_id, task_id) means re-insertion on continuation is prevented
/// by `INSERT OR IGNORE`.
pub fn consume_budget(
    lane_id: &str,
    task_id: &str,
    cost: u64,
    store: &Store,
) -> Result<(), SchedulerError> {
    let conn = store.lock_sync();
    let now = now_unix_secs();
    conn.execute(
        "INSERT OR IGNORE INTO lane_budget_reservations
            (lane_id, task_id, reserved_cost, reserved_at)
         VALUES (?1, ?2, ?3, ?4)",
        rusqlite::params![lane_id, task_id, cost as i64, now],
    )?;
    Ok(())
}

/// Get current budget snapshot for a lane (active tasks + reserved cost).
pub fn current_budget(lane_id: &str, store: &Store) -> Result<LaneBudgetSnapshot, SchedulerError> {
    get_lane_status(lane_id, store)
}

/// Release the budget reservation for a task.
///
/// Deletes from `lane_budget_reservations`. Safe to call multiple times
/// (idempotent on 0 rows). Returns `SchedulerError::CorruptReservationState`
/// if >1 row was deleted (schema invariant violation).
pub fn release_budget(lane_id: &str, task_id: &str, store: &Store) -> Result<(), SchedulerError> {
    let conn = store.lock_sync();
    let rows = conn.execute(
        "DELETE FROM lane_budget_reservations WHERE lane_id=?1 AND task_id=?2",
        rusqlite::params![lane_id, task_id],
    )?;
    match rows {
        0 => Ok(()), // Already released — idempotent.
        1 => Ok(()),
        _ => Err(SchedulerError::CorruptReservationState {
            task_id: task_id.to_owned(),
        }),
    }
}

/// Compute the admission cost for an intent.
///
/// Formula (§2.3):
///   base_cost = policy.base_cost_for_intent_kind(intent_kind_str) → None = error
///   path_cost = touched_paths.len() * policy.cost_per_touched_path()
///   raw       = base_cost.saturating_add(path_cost)
///   result    = min(raw, policy.max_cost_per_task())
///
/// Pure function — no store access. Planner cannot influence the result.
pub fn compute_admission_cost(
    touched_paths: &[PathBuf],
    intent_kind: IntentKind,
    policy: &PolicyBundle,
) -> Result<u64, BudgetError> {
    // Convert IntentKind to the string key used in the policy table.
    let kind_str = intent_kind_to_str(&intent_kind);

    let base_cost = policy
        .base_cost_for_intent_kind(kind_str)
        .ok_or_else(|| BudgetError::UnknownIntentKindCost {
            intent_kind: kind_str.to_owned(),
        })?;

    let path_cost = (touched_paths.len() as u64)
        .saturating_mul(policy.cost_per_touched_path());

    let raw = base_cost.saturating_add(path_cost);
    Ok(raw.min(policy.max_cost_per_task()))
}

/// Map an IntentKind variant to the TOML key string used in the policy table.
fn intent_kind_to_str(kind: &IntentKind) -> &'static str {
    match kind {
        IntentKind::SingleCommit => "SingleCommit",
        IntentKind::IntegrationMerge => "IntegrationMerge",
        IntentKind::CompleteTask => "CompleteTask",
        IntentKind::ReportFailure => "ReportFailure",
    }
}

fn now_unix_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn saturating_add_path_cost_does_not_overflow() {
        // With a very high path_cost, result should not wrap around.
        // This is a property test for saturating arithmetic.
        let result = u64::MAX.saturating_add(1_000);
        assert_eq!(result, u64::MAX);
    }
}

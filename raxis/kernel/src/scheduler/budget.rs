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
use raxis_store::{Store, Table};
use raxis_types::{unix_now_secs, IntentKind};

use crate::scheduler::{BudgetError, SchedulerError};
use crate::scheduler::lane::{get_lane_status, get_lane_status_in_tx};

// INV-STORE-03 (kernel-store.md §2.5.1): all SQL identifiers in this
// module flow through the typed `Table` enum.
const LANE_BUDGET_RESERVATIONS: &str = Table::LaneBudgetReservations.as_str();

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
/// **Standalone wrapper** that opens its own mutex acquisition and
/// auto-commits the INSERT. Pre-fix this was the only entry point and was
/// paired with a separate `check_budget` call — that pairing is the
/// canonical Pattern A TOCTOU bug documented in `kernel-store.md`
/// §2.5.1.1. **New write paths MUST use `reserve_budget_in_tx` instead**
/// so the check and the insert run inside the same transaction.
///
/// PK (lane_id, task_id) means re-insertion on continuation is prevented
/// by `INSERT OR IGNORE`.
///
/// Kept for the (rare) case where a caller has already validated the
/// budget under the same transaction by other means and just needs to
/// drop the reservation row in. New callers should prefer
/// `reserve_budget_in_tx`.
pub fn consume_budget(
    lane_id: &str,
    task_id: &str,
    cost: u64,
    store: &Store,
) -> Result<(), SchedulerError> {
    let conn = store.lock_sync();
    consume_budget_in_tx(&conn, lane_id, task_id, cost)
}

/// Insert a `lane_budget_reservations` row for this task — transaction
/// variant for callers composing this write into a larger atomic operation.
pub fn consume_budget_in_tx(
    conn:    &rusqlite::Connection,
    lane_id: &str,
    task_id: &str,
    cost:    u64,
) -> Result<(), SchedulerError> {
    let now = unix_now_secs();
    conn.execute(
        &format!(
            "INSERT OR IGNORE INTO {LANE_BUDGET_RESERVATIONS}
                (lane_id, task_id, reserved_cost, reserved_at)
             VALUES (?1, ?2, ?3, ?4)"
        ),
        rusqlite::params![lane_id, task_id, cost as i64, now],
    )?;
    Ok(())
}

/// Atomically check budget and reserve in one transaction.
///
/// **INV-STORE-02 (kernel-store.md §2.5.1.1 Pattern A):** this is the
/// canonical write path that closes the budget TOCTOU. The pre-fix code
/// called `check_budget` (acquired the mutex, computed `reserved_cost`,
/// released the mutex) followed later by `consume_budget` (re-acquired,
/// inserted). Two concurrent intents on the same lane could both pass
/// the check before either inserted, over-committing the operator's
/// `max_cost_per_epoch` cap.
///
/// This helper runs the SELECT-aggregate (`get_lane_status_in_tx`) and
/// the `INSERT OR IGNORE` inside the **same** `conn.transaction()` (which
/// the caller has already opened) so no other tokio task can interleave
/// between them. The mutex is held continuously across both, satisfying
/// INV-STORE-01.
///
/// Returns `BudgetExceeded { kind: "ConcurrencyLimit"|"CostLimit" }` if
/// the lane cannot accommodate `estimated_cost`. Returns `NoLaneAssigned`
/// if `lane_id` is not declared in the policy. Idempotent on `(lane_id,
/// task_id)` PK conflict (continuation intents do not double-charge).
pub fn reserve_budget_in_tx(
    conn:           &rusqlite::Connection,
    lane_id:        &str,
    task_id:        &str,
    estimated_cost: u64,
    policy:         &PolicyBundle,
) -> Result<(), SchedulerError> {
    let lane_cfg = crate::scheduler::lane::lane_config_for_row(lane_id, policy)?;
    let status   = get_lane_status_in_tx(conn, lane_id)?;

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

    consume_budget_in_tx(conn, lane_id, task_id, estimated_cost)
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
        &format!(
            "DELETE FROM {LANE_BUDGET_RESERVATIONS} WHERE lane_id=?1 AND task_id=?2"
        ),
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
///
/// V2 sub-task lifecycle kinds (`ActivateSubTask`, `RetrySubTask`,
/// `SubmitReview`) reuse the same `IntentKind::as_str` projection so
/// operators can configure per-kind costs in `[lanes.<name>.intent_costs]`
/// the same way as V1 kinds. The static dispatch matrix
/// (v2-deep-spec.md §Step 20) is the authority on whether a session may
/// submit each kind; the budget mapper just charges the configured cost
/// once admission succeeds.
fn intent_kind_to_str(kind: &IntentKind) -> &'static str {
    kind.as_str()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use raxis_policy::{LaneEntry, PolicyBundle, OperatorEntry};
    use raxis_store::Store;

    #[test]
    fn saturating_add_path_cost_does_not_overflow() {
        let result = u64::MAX.saturating_add(1_000);
        assert_eq!(result, u64::MAX);
    }

    /// Build a minimal policy with a single lane configured for the test.
    fn policy_with_lane(lane_id: &str, max_concurrent: u32, max_cost: u64) -> PolicyBundle {
        let mut bundle = PolicyBundle::for_tests_with_operators(Vec::<OperatorEntry>::new());
        bundle.set_lanes_for_tests(vec![LaneEntry {
            lane_id: lane_id.to_owned(),
            max_concurrent_tasks: max_concurrent,
            max_cost_per_epoch: max_cost,
            priority: 0,
        }]);
        bundle
    }

    /// Seed one initiative + N tasks (with the FK columns the schema
    /// requires) so `lane_budget_reservations` INSERTs (FK on
    /// `tasks.task_id`) and `tasks` SELECTs (used by lane status) have
    /// rows to point at.
    fn seed_initiative_and_tasks(
        store:         &Store,
        initiative_id: &str,
        tasks:         &[(&str, &str, &str)], // (task_id, lane_id, state)
    ) {
        use raxis_store::Table;
        let conn = store.lock_sync();
        conn.execute(
            &format!("INSERT INTO {} (initiative_id, state, terminal_criteria_json, plan_artifact_sha256, created_at) \
                     VALUES (?1, 'Draft', '{{}}', '', 0)",
                Table::Initiatives.as_str()),
            rusqlite::params![initiative_id],
        ).expect("seed initiative row");
        for (task_id, lane_id, state) in tasks {
            conn.execute(
                &format!("INSERT INTO {} (task_id, initiative_id, lane_id, state, actor, policy_epoch, admitted_at, transitioned_at) \
                         VALUES (?1, ?2, ?3, ?4, 'kernel', 0, 0, 0)",
                    Table::Tasks.as_str()),
                rusqlite::params![task_id, initiative_id, lane_id, state],
            ).expect("seed task row");
        }
    }

    /// **INV-STORE-02 (kernel-store.md §2.5.1.1 Pattern A) regression
    /// test.** Pre-fix, two intents could each pass `check_budget` while
    /// each saw `reserved_cost = 0`, then both consume — over-committing
    /// the lane cap. Post-fix, `reserve_budget_in_tx` runs the check and
    /// the INSERT inside the same transaction; the second caller sees
    /// the first caller's reservation reflected in `get_lane_status_in_tx`
    /// and is rejected with `BudgetExceeded`.
    ///
    /// We simulate the post-fix invariant by serially running two
    /// reservations inside the same connection: under the new helper,
    /// the second one MUST be rejected. (The pre-fix code, by splitting
    /// across two mutex acquisitions, could let both succeed — so this
    /// test pins the regression: any future PR that re-introduces the
    /// split will fail it.)
    #[test]
    fn reserve_in_tx_serialises_concurrent_lane_writes() {
        let store = Store::open_in_memory().unwrap();
        let policy = policy_with_lane("lane-A", /*max_concurrent=*/ 8, /*max_cost=*/ 100);
        seed_initiative_and_tasks(&store, "init-A", &[
            ("task-1", "lane-A", "Admitted"),
            ("task-2", "lane-A", "Admitted"),
        ]);

        let mut conn = store.lock_sync();
        let tx = conn.transaction().unwrap();
        reserve_budget_in_tx(&tx, "lane-A", "task-1", 80, &policy)
            .expect("first reservation should fit under cap");
        let err = reserve_budget_in_tx(&tx, "lane-A", "task-2", 30, &policy)
            .expect_err("second reservation must be rejected as over-cap");
        match err {
            SchedulerError::BudgetExceeded { kind } => {
                assert!(kind.starts_with("CostLimit"),
                    "expected CostLimit rejection, got {kind}");
            }
            other => panic!("unexpected error variant: {other:?}"),
        }
        tx.commit().unwrap();
    }

    /// Continuation intents (re-running the same task on the same lane)
    /// MUST NOT double-charge — INSERT OR IGNORE on the (lane_id, task_id)
    /// PK is the load-bearing piece. This test pins that idempotency
    /// inside the new transactional helper.
    #[test]
    fn reserve_in_tx_is_idempotent_on_same_task_pk() {
        let store = Store::open_in_memory().unwrap();
        let policy = policy_with_lane("lane-B", 8, 100);
        seed_initiative_and_tasks(&store, "init-B", &[
            ("task-1", "lane-B", "Admitted"),
        ]);

        let mut conn = store.lock_sync();
        let tx = conn.transaction().unwrap();
        reserve_budget_in_tx(&tx, "lane-B", "task-1", 50, &policy).unwrap();
        reserve_budget_in_tx(&tx, "lane-B", "task-1", 50, &policy)
            .expect("continuation intent must not double-charge");
        let status = get_lane_status_in_tx(&tx, "lane-B").unwrap();
        assert_eq!(status.reserved_cost, 50,
            "PK collision must collapse to single reservation");
        tx.commit().unwrap();
    }

    /// Concurrency-cap is also enforced inside the transaction.
    #[test]
    fn reserve_in_tx_enforces_concurrency_cap() {
        let store = Store::open_in_memory().unwrap();
        let policy = policy_with_lane("lane-C", /*max_concurrent=*/ 1, /*max_cost=*/ 1_000);
        seed_initiative_and_tasks(&store, "init-C", &[
            ("t-existing", "lane-C", "Running"),
            ("task-new",   "lane-C", "Admitted"),
        ]);

        let mut conn = store.lock_sync();
        let tx = conn.transaction().unwrap();
        let err = reserve_budget_in_tx(&tx, "lane-C", "task-new", 10, &policy)
            .expect_err("concurrency cap must reject when active >= max");
        match err {
            SchedulerError::BudgetExceeded { kind } => {
                assert!(kind.starts_with("ConcurrencyLimit"),
                    "expected ConcurrencyLimit rejection, got {kind}");
            }
            other => panic!("unexpected error variant: {other:?}"),
        }
    }
}

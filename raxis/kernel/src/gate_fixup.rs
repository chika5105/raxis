// raxis-kernel::gate_fixup — kernel-authoritative gate-fixup spawn.
//
// **Iter72 — replaces V3 `AddSubTask{kind:GateFixup}`.**
//
// The kernel now owns the entire gate-fixup admit pipeline:
//
//   1. A `[[gates]]` verifier emits a non-`Pass` result for a task.
//   2. The witness handler (`crates/kernel/src/handlers/witness.rs`)
//      observes the non-Pass, persists `last_gate_critique` /
//      `last_gate_type`, and consults the live policy snapshot.
//   3. If `[gate_fixup]` is enabled AND `parent.gate_fixup_attempts <
//      [gate_fixup].max_attempts`, the witness handler invokes
//      [`auto_admit_gate_fixup_task`] directly. The kernel:
//        a. INSERTs a fresh `tasks` row with `is_gate_fixup = 1`,
//           `parent_gate_failure_task_id = parent`,
//           `parent_gate_failure_type = gate_type`, `state = 'Admitted'`,
//        b. INSERTs a `task_dag_edges` row anchoring the fixup
//           lineage to the parent, and
//        c. UPDATEs `parent.gate_fixup_attempts += 1`,
//      all in a single SQLite transaction
//      (`INV-GATE-FIXUP-ADMIT-ATOMIC-01`).
//   4. The kernel emits a `GateFixupSpawned` audit event so the
//      dashboard renders the lineage without joining tables.
//   5. The orchestrator's next KSB fetch surfaces the new fixup task
//      via the standard `ready_now` projection (it has no
//      predecessors that aren't yet `Completed`-eligible — the
//      `predecessor_satisfied` flag on the parent edge starts at
//      `0` so the fixup task only becomes ready when the parent
//      reaches a terminal state, the kernel handles transitions
//      itself). The orchestrator dispatches it with a normal
//      `ActivateSubTask` — the same machinery as any other plan
//      task.
//   6. If `[gate_fixup]` is absent OR the budget is exhausted, the
//      witness handler transitions the parent task directly to
//      `Failed` with a structured `terminal_reason`
//      (`gate_rejected_no_fixup_profile` /
//      `gate_rejected_fixup_budget_exhausted`).
//
// Why kernel-authoritative:
//
// * **Eliminates an orchestrator-mediated round-trip.** Pre-iter72
//   the orchestrator received `KernelPush::GateRejected`, emitted
//   `AddSubTask{kind:GateFixup, ..}`, and then `ActivateSubTask`
//   against the new id. Three asynchronous hops mediated by a
//   non-deterministic LLM agent for what is structurally a
//   policy-driven, parameter-free admission.
// * **The recipe is operator policy, not agent intent.** The
//   fixup-task shape (image alias, max-turns, cost cap, wall-clock
//   cap) is fully declared in `[gate_fixup]`. Letting the
//   orchestrator submit the admit means trusting a probabilistic
//   agent to faithfully reproduce a deterministic operator
//   contract — a needless attack surface and source of
//   hallucination loops.
// * **The kernel already owns the budget.** Pre-iter72 the kernel
//   read `parent.gate_fixup_attempts >= max_attempts` at admit
//   time and rejected the orchestrator's `AddSubTask` with
//   `FailGateFixupBudgetExhausted`. With the kernel as authority,
//   the budget check is internal — no wire-error surface that
//   conflates "this orchestrator is hallucinating" with "the
//   operator's budget is genuinely exhausted."
//
// Reference: `specs/invariants.md INV-GATE-FIXUP-BUDGET-KERNEL-ENFORCED-01`,
// `specs/invariants.md INV-GATE-FIXUP-ADMIT-ATOMIC-01`,
// `specs/v3/gate-rejection-orchestrator-fixup.md` (now superseded
// by kernel-authoritative spawn).

use std::sync::Arc;

use raxis_audit_tools::AuditEventKind;
use rusqlite::Connection;

use crate::ipc::context::HandlerContext;

/// Outcome of [`auto_admit_gate_fixup_task`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AutoAdmitOutcome {
    /// A new fixup `tasks` row was admitted. `attempt_index` is the
    /// post-increment value of `parent.gate_fixup_attempts` (i.e.
    /// the 1-based ordinal of this fixup attempt). The orchestrator
    /// will discover the row on its next KSB fetch.
    Spawned {
        fixup_task_id: String,
        attempt_index: u32,
    },
    /// `[gate_fixup]` is disabled (or the section is absent). The
    /// witness handler should transition the parent to `Failed`
    /// with `terminal_reason = gate_rejected_no_fixup_profile`.
    NoFixupProfile,
    /// The budget is exhausted. The witness handler should
    /// transition the parent to `Failed` with `terminal_reason =
    /// gate_rejected_fixup_budget_exhausted`. `attempts_used`
    /// matches `[gate_fixup].max_attempts`.
    BudgetExhausted { attempts_used: u32 },
    /// The parent task row was missing or otherwise un-readable.
    /// Diagnostic only — the witness handler should already have
    /// looked up the parent's columns before reaching this path.
    ParentMissing,
    /// SQL fault during admit. Diagnostic only.
    SqlError(String),
}

/// Admit one fixup task in a single SQLite transaction.
///
/// `INV-GATE-FIXUP-ADMIT-ATOMIC-01` — the three writes (INSERT the
/// fixup `tasks` row, INSERT the `task_dag_edges` lineage row, UPDATE
/// `parent.gate_fixup_attempts`) MUST land in one transaction so a
/// crash mid-admit never leaves the parent's counter incremented
/// without a corresponding fixup row, nor orphans a fixup row from
/// the DAG.
///
/// Returns the post-increment `gate_fixup_attempts` so the caller's
/// audit row carries the 1-based attempt index.
pub(crate) fn admit_fixup_task_in_tx(
    conn: &mut Connection,
    new_task_id: &str,
    parent_task_id: &str,
    parent_gate_type: &str,
    initiative_id: &str,
    parent_attempts_pre: i64,
    now_secs: i64,
) -> Result<AdmitOutcome, AdmitError> {
    let tx = conn.transaction().map_err(|_| AdmitError::SqlError)?;

    let parent_eval_sha: Option<String> = tx
        .query_row(
            "SELECT evaluation_sha FROM tasks WHERE task_id = ?1",
            rusqlite::params![parent_task_id],
            |r| r.get(0),
        )
        .map_err(|_| AdmitError::ParentMissing)?;
    let parent_eval_sha_owned = parent_eval_sha.unwrap_or_default();

    let inserted = tx
        .execute(
            "INSERT INTO tasks \
               (task_id, initiative_id, lane_id, state, \
                actor, policy_epoch, admitted_at, \
                transitioned_at, actual_cost, \
                evaluation_sha, is_gate_fixup, \
                parent_gate_failure_task_id, \
                parent_gate_failure_type) \
             VALUES (?1, ?2, 'default', 'Admitted', \
                     'kernel', 0, ?3, ?3, 0, ?4, 1, ?5, ?6)",
            rusqlite::params![
                new_task_id,
                initiative_id,
                now_secs,
                if parent_eval_sha_owned.is_empty() {
                    None
                } else {
                    Some(&parent_eval_sha_owned)
                },
                parent_task_id,
                parent_gate_type,
            ],
        )
        .map_err(|_| AdmitError::InsertConflict)?;
    if inserted != 1 {
        return Err(AdmitError::InsertConflict);
    }

    tx.execute(
        "INSERT INTO task_dag_edges \
           (initiative_id, predecessor_task_id, \
            successor_task_id, predecessor_satisfied) \
         VALUES (?1, ?2, ?3, 0)",
        rusqlite::params![initiative_id, parent_task_id, new_task_id],
    )
    .map_err(|_| AdmitError::SqlError)?;

    let new_attempts: i64 = parent_attempts_pre + 1;
    tx.execute(
        "UPDATE tasks SET gate_fixup_attempts = ?1 \
          WHERE task_id = ?2",
        rusqlite::params![new_attempts, parent_task_id],
    )
    .map_err(|_| AdmitError::SqlError)?;

    tx.commit().map_err(|_| AdmitError::SqlError)?;
    Ok(AdmitOutcome {
        parent_evaluation_sha: parent_eval_sha_owned,
        attempt_index: u32::try_from(new_attempts).unwrap_or(u32::MAX),
    })
}

#[derive(Debug, Clone)]
pub(crate) struct AdmitOutcome {
    pub parent_evaluation_sha: String,
    pub attempt_index: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AdmitError {
    ParentMissing,
    InsertConflict,
    SqlError,
}

/// Kernel-authoritative gate-fixup admission pipeline.
///
/// Called from the witness handler when a `[[gates]]` verifier
/// returns a non-`Pass` result. Looks up the parent task's current
/// `gate_fixup_attempts`, consults policy, and either:
///
/// * admits a new fixup task (returns `Spawned`),
/// * surfaces the no-profile branch (returns `NoFixupProfile`),
/// * surfaces the budget-exhausted branch (returns `BudgetExhausted`).
///
/// The witness handler interprets the outcome and runs the matching
/// parent-state transition (`Failed` with structured `terminal_reason`
/// on the two terminal branches, or leaves the parent in
/// `GatesPending` while the fixup executes).
///
/// The new fixup task id is generated as
/// `"{parent_task_id}--gatefixup-{attempt_index}"` for deterministic
/// dashboard rendering and audit-chain readability.
pub async fn auto_admit_gate_fixup_task(
    ctx: &HandlerContext,
    parent_task_id: &str,
    parent_initiative_id: &str,
    parent_gate_type: &str,
    parent_gate_fixup_attempts_pre: u32,
) -> AutoAdmitOutcome {
    // ── Step 1: policy profile lookup ─────────────────────────────
    let policy_snapshot = ctx.policy.load();
    let Some(profile) = policy_snapshot.gate_fixup() else {
        return AutoAdmitOutcome::NoFixupProfile;
    };

    // ── Step 2: budget gate (INV-GATE-FIXUP-BUDGET-KERNEL-ENFORCED-01) ──
    if parent_gate_fixup_attempts_pre >= profile.max_attempts {
        return AutoAdmitOutcome::BudgetExhausted {
            attempts_used: parent_gate_fixup_attempts_pre,
        };
    }

    // ── Step 3: atomic admit (INV-GATE-FIXUP-ADMIT-ATOMIC-01) ─────
    let attempt_index_1based = parent_gate_fixup_attempts_pre + 1;
    let new_task_id = format!("{parent_task_id}--gatefixup-{attempt_index_1based}");
    let parent_task_id_owned = parent_task_id.to_owned();
    let parent_gate_type_owned = parent_gate_type.to_owned();
    let initiative_id_owned = parent_initiative_id.to_owned();
    let store_arc = Arc::clone(&ctx.store);
    let now_secs_i64 = raxis_types::unix_now_secs();
    let new_task_id_for_admit = new_task_id.clone();
    let attempts_pre_i64 = i64::from(parent_gate_fixup_attempts_pre);
    let admit_result = tokio::task::spawn_blocking(move || -> Result<AdmitOutcome, AdmitError> {
        let mut conn = store_arc.lock_sync();
        admit_fixup_task_in_tx(
            &mut conn,
            &new_task_id_for_admit,
            &parent_task_id_owned,
            &parent_gate_type_owned,
            &initiative_id_owned,
            attempts_pre_i64,
            now_secs_i64,
        )
    })
    .await;

    let outcome = match admit_result {
        Ok(Ok(o)) => o,
        Ok(Err(AdmitError::ParentMissing)) => return AutoAdmitOutcome::ParentMissing,
        Ok(Err(AdmitError::InsertConflict)) => {
            return AutoAdmitOutcome::SqlError(format!(
                "fixup task id collision: {new_task_id} already exists (attempt_index={attempt_index_1based})"
            ));
        }
        Ok(Err(AdmitError::SqlError)) => {
            return AutoAdmitOutcome::SqlError("admit pipeline SQL fault".to_owned());
        }
        Err(join_err) => {
            return AutoAdmitOutcome::SqlError(format!("admit spawn_blocking join: {join_err}"));
        }
    };

    // ── Step 4: emit GateFixupSpawned audit event ─────────────────
    //
    // Post-commit emission so the audit row only lands when the
    // SQL admit is durable. The `session_id` on the event is the
    // synthetic `kernel://gate_fixup_auto_spawn` urn — there is no
    // submitting planner session for this admission (the kernel is
    // the actor), so we use the same scheme the worktree-GC and
    // capacity-watchdog modules use to encode "kernel actor" in
    // the audit `session_id` slot.
    let _ = ctx.audit.emit(
        AuditEventKind::GateFixupSpawned {
            fixup_task_id: new_task_id.clone(),
            parent_task_id: parent_task_id.to_owned(),
            gate_type: parent_gate_type.to_owned(),
            parent_evaluation_sha: outcome.parent_evaluation_sha,
            attempt_index: outcome.attempt_index,
        },
        Some("kernel://gate_fixup_auto_spawn"),
        Some(&new_task_id),
        Some(parent_initiative_id),
    );

    AutoAdmitOutcome::Spawned {
        fixup_task_id: new_task_id,
        attempt_index: outcome.attempt_index,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use raxis_store::Store;
    use raxis_store::Table;

    fn seed_parent(store: &Store, initiative_id: &str, parent_task_id: &str, eval_sha: &str) {
        let now = raxis_types::unix_now_secs();
        let conn = store.lock_sync();
        let initiatives_t = Table::Initiatives.as_str();
        conn.execute(
            &format!(
                "INSERT INTO {initiatives_t} \
                    (initiative_id, state, terminal_criteria_json, \
                     plan_artifact_sha256, created_at) \
                 VALUES (?1, 'Executing', '{{}}', 'deadbeef', ?2)"
            ),
            rusqlite::params![initiative_id, now],
        )
        .unwrap();

        let tasks_t = Table::Tasks.as_str();
        conn.execute(
            &format!(
                "INSERT INTO {tasks_t} \
                    (task_id, initiative_id, lane_id, state, actor, \
                     policy_epoch, admitted_at, transitioned_at, \
                     evaluation_sha, gate_fixup_attempts, \
                     last_gate_type) \
                 VALUES (?1, ?2, 'default', 'GatesPending', 'planner', \
                         1, ?3, ?3, ?4, 0, 'CrossCuttingPolicy')"
            ),
            rusqlite::params![parent_task_id, initiative_id, now, eval_sha],
        )
        .unwrap();
    }

    /// Atomic admit-pipeline contract: the three writes (INSERT
    /// fixup task row, INSERT dag edge, UPDATE parent counter) all
    /// land in one transaction, observable post-commit.
    #[test]
    fn admit_fixup_task_in_tx_pins_three_writes_atomically() {
        let store = Store::open_in_memory().unwrap();
        seed_parent(&store, "init-a", "parent-1", "deadbeef00");
        let now = raxis_types::unix_now_secs();
        {
            let mut conn = store.lock_sync();
            let outcome = admit_fixup_task_in_tx(
                &mut conn,
                "parent-1--gatefixup-1",
                "parent-1",
                "CrossCuttingPolicy",
                "init-a",
                0,
                now,
            )
            .unwrap();
            assert_eq!(outcome.attempt_index, 1);
            assert_eq!(outcome.parent_evaluation_sha, "deadbeef00");
        }
        let conn = store.lock_sync();
        let tasks_t = Table::Tasks.as_str();
        let (state, is_fixup, parent_id, gate_type): (String, i64, String, String) = conn
            .query_row(
                &format!(
                    "SELECT state, is_gate_fixup, parent_gate_failure_task_id, \
                            parent_gate_failure_type \
                       FROM {tasks_t} WHERE task_id = ?1"
                ),
                rusqlite::params!["parent-1--gatefixup-1"],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .unwrap();
        assert_eq!(state, "Admitted");
        assert_eq!(is_fixup, 1);
        assert_eq!(parent_id, "parent-1");
        assert_eq!(gate_type, "CrossCuttingPolicy");

        let edges_t = Table::TaskDagEdges.as_str();
        let edge_count: i64 = conn
            .query_row(
                &format!(
                    "SELECT COUNT(*) FROM {edges_t} \
                       WHERE predecessor_task_id = ?1 \
                         AND successor_task_id = ?2"
                ),
                rusqlite::params!["parent-1", "parent-1--gatefixup-1"],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(edge_count, 1);

        let attempts: i64 = conn
            .query_row(
                &format!(
                    "SELECT gate_fixup_attempts FROM {tasks_t} WHERE task_id = ?1"
                ),
                rusqlite::params!["parent-1"],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(attempts, 1);
    }

    /// A duplicate fixup `task_id` returns `InsertConflict` and
    /// does NOT bump the parent counter (the transaction rolls back).
    #[test]
    fn admit_fixup_task_in_tx_rolls_back_on_id_collision() {
        let store = Store::open_in_memory().unwrap();
        seed_parent(&store, "init-a", "parent-1", "deadbeef00");
        let now = raxis_types::unix_now_secs();
        {
            let mut conn = store.lock_sync();
            admit_fixup_task_in_tx(
                &mut conn,
                "fixup-1",
                "parent-1",
                "CrossCuttingPolicy",
                "init-a",
                0,
                now,
            )
            .unwrap();
        }
        {
            let mut conn = store.lock_sync();
            let err = admit_fixup_task_in_tx(
                &mut conn,
                "fixup-1",
                "parent-1",
                "CrossCuttingPolicy",
                "init-a",
                1,
                now,
            )
            .unwrap_err();
            assert_eq!(err, AdmitError::InsertConflict);
        }
        let conn = store.lock_sync();
        let tasks_t = Table::Tasks.as_str();
        let attempts: i64 = conn
            .query_row(
                &format!(
                    "SELECT gate_fixup_attempts FROM {tasks_t} WHERE task_id = ?1"
                ),
                rusqlite::params!["parent-1"],
                |r| r.get(0),
            )
            .unwrap();
        // Counter is 1 from the first successful admit; the
        // collided second admit MUST NOT have bumped it again.
        assert_eq!(attempts, 1);
    }
}

//! Orchestrator no-progress respawn ceiling
//! (`INV-ORCH-RESPAWN-NO-PROGRESS-CEILING-01`).
//!
//! ## Why this exists
//!
//! V2.4's Orchestrator is short-lived: each spawn boots, reads the
//! KSB, calls one terminal DAG tool, and exits cleanly. The kernel's
//! post-exit hook in `session_spawn_orchestrator::spawn_planner_dispatcher`
//! observes the clean exit and respawns the orchestrator to make the
//! next DAG-progressing decision.
//!
//! Existing bounded-capability invariants do NOT cover one class of
//! loop:
//!
//!   * `INV-CONVERGENCE-01` (review-round cap) — bumps on Reviewer
//!     verdicts, not on Orchestrator respawn.
//!   * `crash_count` ceiling — bumps only when the Executor's task FSM
//!     transitions to `Failed`. A clean orchestrator exit with a
//!     kernel-rejected intent never increments this counter.
//!   * `max_orch_turns` (planner harness fetch quota) — caps fetches
//!     PER session. A fresh respawn gets a fresh quota.
//!
//! Iter42-second-run reproduced the missing-ceiling failure mode:
//! 45 `SessionVmSpawned` events in 18 min, zero
//! `ReviewAggregationCompleted`, zero
//! `ExecutorRespawnFromReviewRejection`, zero Failed transitions, zero
//! `crash_count` bumps. The orchestrator was firing `retry_subtask`
//! against an executor whose `review_reject_count == 0` (sibling
//! reviewer still unvoted; see `INV-RETRY-FROM-COMPLETED-REVIEW-REJECTED-01`
//! for the kernel-side admission predicate); the kernel correctly
//! rejected; the orchestrator exited cleanly; the post-exit hook
//! respawned; the new orchestrator re-read the same un-changed KSB
//! and fired the same retry. Infinite loop.
//!
//! ## The ceiling
//!
//! `MAX_ORCH_NO_PROGRESS_RESPAWNS` (default 3) is the cap on
//! orchestrator respawns WITHOUT an intervening task FSM transition.
//! When the counter reaches the ceiling, the kernel:
//!
//!   1. Emits `AuditEventKind::OrchestratorRespawnCeilingExceeded`
//!      with the offending `initiative_id`, the counter value, and
//!      the ceiling.
//!   2. Marks the initiative `Failed` with
//!      `reason = "orchestrator no-progress respawn ceiling exceeded"`.
//!   3. Refuses further respawns for that initiative — the
//!      `is_executing` preflight in
//!      `respawn_orchestrator_for_initiative` already short-circuits
//!      once the initiative is not in `Executing`.
//!
//! ## Increment / reset rules
//!
//! * **Increment** in [`increment_no_progress_count_in_tx`]: called
//!   from `respawn_orchestrator_for_initiative` BEFORE the substrate
//!   spawn. The increment + ceiling check + initiative-Failed
//!   transition all run in one transaction so a race against an
//!   operator abort cannot leave a half-finished bookkeeping state.
//!
//! * **Reset** in [`reset_no_progress_count_in_tx`]: called from
//!   `initiatives::task_transitions::transition_task_in_tx` on every
//!   legal task FSM transition (Admitted → Running, Running → Completed,
//!   Running → Failed, …). A successful FSM step IS the "progress"
//!   signal — the orchestrator's last decision moved the DAG, so
//!   the loop counter has no reason to persist.
//!
//! Resetting on `subtask_activations` row inserts is structurally
//! equivalent: every fresh activation row comes from one of
//! `ApprovePlan`, `ActivateSubTask`, or `RetrySubTask`, and each of
//! those handlers either creates a new activation row (which the
//! caller resets the counter alongside) or surfaces an admission
//! failure (which does NOT advance the DAG and should NOT reset).
//! See `handlers/intent.rs::handle_activate_sub_task` and
//! `handle_retry_sub_task` for the call sites.
//!
//! ## Schema
//!
//! Counter lives on `initiatives.orchestrator_no_progress_respawn_count`
//! (Migration 19; see
//! `crates/store/src/migration.rs::render_migration_19_ddl`). Default 0
//! at insert (the `ApprovePlan` path doesn't need to touch the column).
//! Type is `INTEGER NOT NULL` SQLite-side; the kernel narrows to
//! `u32` on read with `u32::try_from(.).unwrap_or(u32::MAX)` so a
//! pathological i64 overflow does not panic the increment path.
//!
//! ## Spec parity
//!
//! `INV-ORCH-RESPAWN-NO-PROGRESS-CEILING-01` — `specs/invariants.md`
//! §6 (Scheduler / lifecycle limits) and `specs/v2/v2-deep-spec.md`
//! §Step 12 (Crash Recovery — Dual Retry Counters) extension.

use raxis_audit_tools::AuditEventKind;
use raxis_store::Table;
use rusqlite::{Connection, OptionalExtension};

/// The structural backstop ceiling for orchestrator no-progress
/// respawns per initiative. Chosen at 3 because the legitimate
/// orchestrator decision-cycle never needs more than two consecutive
/// rejected intents to resolve into progress (e.g. one
/// `activate_subtask` race-loser before the active session revokes,
/// then a second non-racing call). Three or more consecutive
/// no-progress respawns is structural loop, not honest contention.
pub const MAX_ORCH_NO_PROGRESS_RESPAWNS: u32 = 3;

/// Outcome of the increment-and-check step. Returned by
/// [`increment_no_progress_count_in_tx`] so the caller can branch
/// on ceiling exceedance without re-reading the column.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CeilingOutcome {
    /// The increment landed; the orchestrator may proceed to spawn.
    /// `count_after_increment` is the post-increment value, surfaced
    /// for structured logging.
    Permitted { count_after_increment: u32 },
    /// The post-increment count strictly exceeds
    /// [`MAX_ORCH_NO_PROGRESS_RESPAWNS`]. The caller MUST mark the
    /// initiative `Failed`, emit
    /// `OrchestratorRespawnCeilingExceeded`, and refuse the spawn.
    /// `count_after_increment` is always `> max_attempts`.
    Exceeded {
        count_after_increment: u32,
        max_attempts:          u32,
    },
}

/// Increment `initiatives.orchestrator_no_progress_respawn_count` by
/// one and compare the post-increment value against
/// [`MAX_ORCH_NO_PROGRESS_RESPAWNS`].
///
/// **Atomicity.** Caller passes an open SQLite transaction. The
/// increment + read happen inside one transaction; a concurrent
/// reset (from a `transition_task_in_tx` racing on a different
/// connection) is serialized by SQLite's write-mode lock. The
/// ceiling decision is therefore monotonic from the caller's
/// perspective.
///
/// **Error mode.** Propagates `rusqlite::Error` on SQL failure. The
/// caller MUST fail-closed (refuse the respawn) on error — a
/// silent retry would burn the ceiling without observing it.
///
/// **No-op on missing row.** If the initiative doesn't exist (e.g.
/// raced against operator abort + delete), the function returns
/// `Permitted { count_after_increment: 0 }` so the caller's
/// downstream preflight (`is_executing` check) is the structural
/// gate. Defensive — pre-Migration-19 rows always exist for any
/// `Executing` initiative.
pub fn increment_no_progress_count_in_tx(
    tx:            &Connection,
    initiative_id: &str,
) -> Result<CeilingOutcome, rusqlite::Error> {
    let initiatives = Table::Initiatives.as_str();

    let rows = tx.execute(
        &format!(
            "UPDATE {initiatives}
                SET orchestrator_no_progress_respawn_count =
                        orchestrator_no_progress_respawn_count + 1
              WHERE initiative_id = ?1"
        ),
        rusqlite::params![initiative_id],
    )?;
    if rows == 0 {
        return Ok(CeilingOutcome::Permitted { count_after_increment: 0 });
    }

    let count_i64: i64 = tx.query_row(
        &format!(
            "SELECT orchestrator_no_progress_respawn_count
               FROM {initiatives} WHERE initiative_id = ?1"
        ),
        rusqlite::params![initiative_id],
        |r| r.get(0),
    )?;
    let count = u32::try_from(count_i64).unwrap_or(u32::MAX);

    Ok(if count > MAX_ORCH_NO_PROGRESS_RESPAWNS {
        CeilingOutcome::Exceeded {
            count_after_increment: count,
            max_attempts:          MAX_ORCH_NO_PROGRESS_RESPAWNS,
        }
    } else {
        CeilingOutcome::Permitted { count_after_increment: count }
    })
}

/// Reset the per-initiative orchestrator no-progress respawn counter
/// to zero. Called from `transition_task_in_tx` on every legal task
/// FSM transition so honest DAG progress observably clears the
/// loop counter.
///
/// Called as a side-effect of FSM-step persistence so the reset is
/// atomic with the underlying state mutation — a concurrent ceiling
/// check sees either the pre-progress count (and may exceed) or the
/// post-progress count (zero), never an intermediate.
///
/// **No-op on missing column.** Pre-Migration-19 stores reject the
/// UPDATE with `no such column`; the caller swallows the error and
/// emits a structured-log line. This keeps `raxis-kernel` boot-
/// compatible with stores opened from a pre-Migration-19 snapshot
/// during the upgrade window (Migration 19 runs synchronously at
/// boot, so the window is bounded to one process start). The
/// boot-time migration sequence is the structural gate.
pub fn reset_no_progress_count_in_tx(
    tx:            &Connection,
    initiative_id: &str,
) -> Result<(), rusqlite::Error> {
    let initiatives = Table::Initiatives.as_str();

    tx.execute(
        &format!(
            "UPDATE {initiatives}
                SET orchestrator_no_progress_respawn_count = 0
              WHERE initiative_id = ?1
                AND orchestrator_no_progress_respawn_count > 0"
        ),
        rusqlite::params![initiative_id],
    )?;
    Ok(())
}

/// Resolve the parent `initiative_id` for a given `task_id`. Used by
/// `transition_task_in_tx`'s reset hook (which has the `task_id` in
/// hand but not the initiative).
///
/// Returns `Ok(None)` when the task row is missing — the caller's
/// FSM-update query would itself have failed first, so this is a
/// defensive belt-and-braces guard.
pub fn lookup_initiative_id_for_task_in_tx(
    tx:      &Connection,
    task_id: &str,
) -> Result<Option<String>, rusqlite::Error> {
    let tasks = Table::Tasks.as_str();
    tx.query_row(
        &format!("SELECT initiative_id FROM {tasks} WHERE task_id = ?1"),
        rusqlite::params![task_id],
        |r| r.get::<_, String>(0),
    ).optional()
}

/// Build an `OrchestratorRespawnCeilingExceeded` audit event from a
/// `CeilingOutcome::Exceeded`. Returns `None` for `Permitted`
/// outcomes (the caller never wants to emit on the permitted path).
///
/// Pulled into a tiny constructor here so the
/// `respawn_orchestrator_for_initiative` call site stays readable.
pub fn build_ceiling_event(
    initiative_id: &str,
    outcome:       CeilingOutcome,
) -> Option<AuditEventKind> {
    match outcome {
        CeilingOutcome::Exceeded { count_after_increment, max_attempts } => {
            Some(AuditEventKind::OrchestratorRespawnCeilingExceeded {
                initiative_id: initiative_id.to_owned(),
                attempts:      count_after_increment,
                max_attempts,
            })
        }
        CeilingOutcome::Permitted { .. } => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use raxis_store::migration::apply_pending;

    fn fresh_conn_with_initiative(initiative_id: &str) -> Connection {
        let conn = Connection::open_in_memory().expect("open in-memory");
        apply_pending(&conn).expect("apply migrations");

        // Seed one initiative row in `Executing` state. Mirrors the
        // shape `ApprovePlan` writes; the V2 baseline schema
        // (kernel-store.md §2.5.1 Table 2) carries
        // `initiative_id`, `state`, `terminal_criteria_json`,
        // `plan_artifact_sha256`, and `created_at` as the NOT-NULL
        // surface; later migrations only ADD nullable columns so
        // this minimal seed is forward-compatible.
        let initiatives = Table::Initiatives.as_str();
        conn.execute(
            &format!(
                "INSERT INTO {initiatives}
                    (initiative_id, state, terminal_criteria_json,
                     plan_artifact_sha256, created_at)
                 VALUES (?1, 'Executing', '{{}}', '', strftime('%s','now'))"
            ),
            rusqlite::params![initiative_id],
        ).expect("seed initiative");
        conn
    }

    fn read_count(conn: &Connection, initiative_id: &str) -> u32 {
        let initiatives = Table::Initiatives.as_str();
        conn.query_row(
            &format!(
                "SELECT orchestrator_no_progress_respawn_count
                   FROM {initiatives} WHERE initiative_id = ?1"
            ),
            rusqlite::params![initiative_id],
            |r| r.get::<_, i64>(0).map(|v| u32::try_from(v).unwrap_or(u32::MAX)),
        ).expect("read count")
    }

    #[test]
    fn fresh_initiative_increments_from_zero_to_one() {
        let mut conn = fresh_conn_with_initiative("init-A");
        let tx = conn.transaction().unwrap();
        let outcome = increment_no_progress_count_in_tx(&tx, "init-A").unwrap();
        assert_eq!(outcome, CeilingOutcome::Permitted { count_after_increment: 1 });
        tx.commit().unwrap();
        assert_eq!(read_count(&conn, "init-A"), 1);
    }

    #[test]
    fn ceiling_exceeded_after_max_plus_one_increments() {
        let mut conn = fresh_conn_with_initiative("init-A");
        for expected in 1..=MAX_ORCH_NO_PROGRESS_RESPAWNS {
            let tx = conn.transaction().unwrap();
            let outcome = increment_no_progress_count_in_tx(&tx, "init-A").unwrap();
            assert_eq!(
                outcome,
                CeilingOutcome::Permitted { count_after_increment: expected },
                "increment #{expected} should be Permitted",
            );
            tx.commit().unwrap();
        }
        // The (MAX + 1)-th increment trips the ceiling.
        let tx = conn.transaction().unwrap();
        let outcome = increment_no_progress_count_in_tx(&tx, "init-A").unwrap();
        assert_eq!(
            outcome,
            CeilingOutcome::Exceeded {
                count_after_increment: MAX_ORCH_NO_PROGRESS_RESPAWNS + 1,
                max_attempts:          MAX_ORCH_NO_PROGRESS_RESPAWNS,
            },
            "post-ceiling increment MUST report Exceeded",
        );
        tx.commit().unwrap();
    }

    #[test]
    fn reset_drops_count_back_to_zero() {
        let mut conn = fresh_conn_with_initiative("init-A");
        for _ in 0..2 {
            let tx = conn.transaction().unwrap();
            increment_no_progress_count_in_tx(&tx, "init-A").unwrap();
            tx.commit().unwrap();
        }
        assert_eq!(read_count(&conn, "init-A"), 2);

        let tx = conn.transaction().unwrap();
        reset_no_progress_count_in_tx(&tx, "init-A").unwrap();
        tx.commit().unwrap();
        assert_eq!(read_count(&conn, "init-A"), 0);
    }

    #[test]
    fn increment_against_missing_initiative_is_permitted_no_op() {
        let mut conn = fresh_conn_with_initiative("init-A");
        let tx = conn.transaction().unwrap();
        let outcome =
            increment_no_progress_count_in_tx(&tx, "init-MISSING").unwrap();
        assert_eq!(outcome, CeilingOutcome::Permitted { count_after_increment: 0 });
        tx.commit().unwrap();
        // The real initiative's count is unaffected.
        assert_eq!(read_count(&conn, "init-A"), 0);
    }

    #[test]
    fn reset_against_zero_count_is_idempotent() {
        let mut conn = fresh_conn_with_initiative("init-A");
        let tx = conn.transaction().unwrap();
        reset_no_progress_count_in_tx(&tx, "init-A").unwrap();
        tx.commit().unwrap();
        assert_eq!(read_count(&conn, "init-A"), 0);
    }

    #[test]
    fn lookup_initiative_id_for_task_resolves_existing_task() {
        let mut conn = fresh_conn_with_initiative("init-A");
        let tasks = Table::Tasks.as_str();
        conn.execute(
            &format!(
                "INSERT INTO {tasks}
                    (task_id, initiative_id, lane_id, state, actor,
                     policy_epoch, admitted_at, transitioned_at)
                 VALUES (?1, ?2, 'lane-test', 'Admitted', 'kernel',
                         0, strftime('%s','now'), strftime('%s','now'))"
            ),
            rusqlite::params!["t-1", "init-A"],
        ).expect("seed task");
        let tx = conn.transaction().unwrap();
        let resolved =
            lookup_initiative_id_for_task_in_tx(&tx, "t-1").unwrap();
        assert_eq!(resolved.as_deref(), Some("init-A"));
        tx.commit().unwrap();
    }

    #[test]
    fn lookup_initiative_id_for_missing_task_returns_none() {
        let mut conn = fresh_conn_with_initiative("init-A");
        let tx = conn.transaction().unwrap();
        let resolved =
            lookup_initiative_id_for_task_in_tx(&tx, "t-MISSING").unwrap();
        assert!(resolved.is_none());
        tx.commit().unwrap();
    }

    #[test]
    fn build_ceiling_event_returns_none_on_permitted() {
        let event = build_ceiling_event(
            "init-A",
            CeilingOutcome::Permitted { count_after_increment: 2 },
        );
        assert!(event.is_none());
    }

    #[test]
    fn build_ceiling_event_returns_some_on_exceeded() {
        let event = build_ceiling_event(
            "init-A",
            CeilingOutcome::Exceeded {
                count_after_increment: MAX_ORCH_NO_PROGRESS_RESPAWNS + 1,
                max_attempts:          MAX_ORCH_NO_PROGRESS_RESPAWNS,
            },
        );
        match event {
            Some(AuditEventKind::OrchestratorRespawnCeilingExceeded {
                initiative_id, attempts, max_attempts,
            }) => {
                assert_eq!(initiative_id, "init-A");
                assert_eq!(attempts, MAX_ORCH_NO_PROGRESS_RESPAWNS + 1);
                assert_eq!(max_attempts, MAX_ORCH_NO_PROGRESS_RESPAWNS);
            }
            other => panic!(
                "expected OrchestratorRespawnCeilingExceeded, got {other:?}"
            ),
        }
    }
}

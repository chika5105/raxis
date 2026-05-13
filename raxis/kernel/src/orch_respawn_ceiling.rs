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
use raxis_types::{
    EscalationClass, EscalationStatus, RequestedEscalationScope,
    MAX_LOGICAL_DEADLOCK_REASON_LEN,
};
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

/// `INV-ESCALATION-AUTO-LOGICAL-DEADLOCK-01` — auto-create a
/// kernel-initiated `LogicalDeadlock` escalation row inside the
/// SAME SQLite transaction as the ceiling-exceeded
/// initiative-`Failed` flip. The escalation lets the operator
/// decide whether to (a) approve the reset + retry path
/// (transitioning the initiative back to `Executing`) or (b)
/// preserve the `Failed` terminal state by denying.
///
/// **Paired-write order.** Per
/// `audit-paired-writes.md §4`:
///
///   1. INSERT escalations row (status `'Pending'`, initiator
///      `'Kernel'`, class `'LogicalDeadlock'`)
///   2. UPDATE initiatives state = 'Failed'
///   3. COMMIT
///   4. (post-commit) emit
///      `AuditEventKind::OrchestratorRespawnCeilingExceeded`
///
/// This function performs Step 1; the caller (in
/// `session_spawn_orchestrator::respawn_orchestrator_for_initiative`)
/// performs Steps 2–4. The two writes share one transaction so a
/// crash between them leaves the store internally consistent
/// (either both pending or both rolled back; never an
/// initiative-`Failed` without an operator-actionable escalation
/// row).
///
/// **FK satisfaction strategy.** The `escalations` table requires
/// `session_id` / `task_id` / `lineage_id` to be `NOT NULL` and to
/// reference real rows. For a kernel-initiated escalation the
/// triple is harvested from the most recently FSM-touched task on
/// the failing initiative whose `session_id` is non-NULL — by
/// construction of the iter42 pathology there is always one
/// (the orchestrator/executor session that loop-spawned). If no
/// eligible task exists (defensive: pre-Migration-19 stores or
/// raced operator-abort + delete), the function returns
/// `Ok(None)` and the caller skips Step 1 but still performs
/// Steps 2–4 so the operator at least sees the audit event.
///
/// **idempotency_key.** Deterministic
/// `kernel-orch-respawn-ceiling:{initiative_id}` so the
/// `UNIQUE (session_id, idempotency_key)` index naturally
/// short-circuits a second attempt for the same initiative within
/// one kernel-process lifetime. Subsequent re-tries of the same
/// auto-create after `escalations.status` has been resolved
/// (Approved/Denied) are blocked by the
/// `ceiling-exceeded → state=Failed` short-circuit at the top of
/// `respawn_orchestrator_for_initiative` (the second auto-create
/// never runs because the first respawn refused to spawn).
///
/// **Field truncation.** `last_intent_kind` and
/// `last_rejection_reason` are truncated to
/// `MAX_LOGICAL_DEADLOCK_REASON_LEN` bytes (1 KiB) so a hostile
/// orchestrator that loops on a pathologically long intent shape
/// cannot blow the audit row size past the bound.
///
/// Returns the freshly-inserted `escalation_id` on success, or
/// `Ok(None)` on the no-eligible-FK fallback path. Propagates
/// `rusqlite::Error` on SQL failure; the caller MUST fail-closed
/// (treat the error as if the insert never happened, so the
/// initiative still transitions to `Failed`).
#[allow(clippy::too_many_arguments)]
pub fn insert_logical_deadlock_escalation_in_tx(
    tx:                    &Connection,
    initiative_id:         &str,
    attempts:              u32,
    window_secs:           u64,
    last_intent_kind:      &str,
    last_rejection_reason: &str,
    timeout_at_unix:       i64,
    now_unix:              i64,
    policy_epoch:          i64,
) -> Result<Option<String>, rusqlite::Error> {
    let tasks       = Table::Tasks.as_str();
    let sessions    = Table::Sessions.as_str();
    let escalations = Table::Escalations.as_str();

    // Resolve a (task_id, session_id, lineage_id) triple from the
    // most recently FSM-touched task on the initiative whose
    // session_id is non-NULL. The JOIN against `sessions` enforces
    // the FK on `escalations.session_id`. If no row matches the
    // initiative carries no live task with a session — defensive
    // path; auto-escalation skipped.
    let triple: Option<(String, String, String)> = tx.query_row(
        &format!(
            "SELECT t.task_id, s.session_id, s.lineage_id
               FROM {tasks} t
               JOIN {sessions} s ON s.session_id = t.session_id
              WHERE t.initiative_id = ?1
                AND t.session_id IS NOT NULL
              ORDER BY t.transitioned_at DESC
              LIMIT 1"
        ),
        rusqlite::params![initiative_id],
        |r| Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, String>(2)?,
        )),
    ).optional()?;

    let Some((task_id, session_id, lineage_id)) = triple else {
        return Ok(None);
    };

    let escalation_id = uuid::Uuid::new_v4().to_string();

    let initiative_uuid = match raxis_types::InitiativeId::parse(initiative_id) {
        Ok(id) => id,
        Err(_) => return Ok(None),
    };

    let last_intent_kind_trunc = truncate_for_scope(last_intent_kind);
    let last_rejection_reason_trunc = truncate_for_scope(last_rejection_reason);

    let scope = RequestedEscalationScope::LogicalDeadlock {
        initiative_id:         initiative_uuid,
        attempts,
        window_secs,
        last_intent_kind:      last_intent_kind_trunc.clone(),
        last_rejection_reason: last_rejection_reason_trunc.clone(),
    };
    let scope_json = serde_json::to_string(&scope)
        .expect("RequestedEscalationScope is always JSON-serialisable");

    let justification = format!(
        "Orchestrator respawn-no-progress ceiling exceeded \
         ({attempts} respawns within {window_secs}s with zero \
         subtask FSM transitions). Last orchestrator intent: \
         {last_intent_kind_trunc} rejected as \
         {last_rejection_reason_trunc}. Operator approval required \
         to reset the respawn counter and retry, or deny to \
         preserve the Failed terminal state."
    );

    let idem_key = format!("kernel-orch-respawn-ceiling:{initiative_id}");

    let inserted = tx.execute(
        &format!(
            "INSERT INTO {escalations} (
                escalation_id, session_id, task_id, lineage_id, initiative_id,
                class, requested_scope_json, justification, idempotency_key,
                status, created_at, timeout_at, initiator
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, 'Kernel')
             ON CONFLICT(session_id, idempotency_key) DO NOTHING"
        ),
        rusqlite::params![
            escalation_id,
            session_id,
            task_id,
            lineage_id,
            initiative_id,
            EscalationClass::LogicalDeadlock.as_sql_str(),
            scope_json,
            justification,
            idem_key,
            EscalationStatus::Pending.as_sql_str(),
            now_unix,
            timeout_at_unix,
        ],
    )?;
    let _ = policy_epoch; // surfaced for symmetry with planner-side handler

    if inserted == 0 {
        return Ok(None);
    }

    Ok(Some(escalation_id))
}

/// `INV-ESCALATION-AUTO-LOGICAL-DEADLOCK-01` — operator-approval
/// path for the kernel-initiated `LogicalDeadlock` escalation. In
/// one SQLite transaction:
///
///   1. Verify the row exists, has class `'LogicalDeadlock'`,
///      initiator `'Kernel'`, status `'Pending'`. (Defense-in-
///      depth: a `LogicalDeadlock` row with initiator `'Planner'`
///      would be a planner-side admission bug; we refuse to act
///      on it here even though the planner-side admission also
///      rejects.)
///   2. UPDATE escalations SET status = 'Approved', resolved_at = now.
///   3. UPDATE initiatives SET orchestrator_no_progress_respawn_count = 0.
///   4. UPDATE initiatives SET state = 'Executing' (transition back
///      from `Failed`).
///
/// Returns `Ok(initiative_id)` on success so the caller can
/// schedule the orchestrator respawn outside the SQL transaction.
/// Returns `Ok(None)` when the row is not in the expected state
/// (the FSM mismatch is the operator's signal that the escalation
/// has already been resolved or the row never existed). Propagates
/// `rusqlite::Error` on SQL failure; the caller MUST surface as
/// an operator-facing error.
///
/// **Why not via `authority::escalation::approve_escalation`.**
/// The standard approve path mints an `approval_tokens` row whose
/// `scope_json` carries a `CapabilityClass` the planner later
/// presents on a downstream intent. `LogicalDeadlock` has no
/// capability semantics — the operator's approval IS the action;
/// no token is consumed, no scope is bound. A separate path keeps
/// the wire shape minimal and avoids polluting the
/// `approval_tokens` table with rows the planner can never
/// consume.
pub fn approve_logical_deadlock_escalation_in_tx(
    tx:            &Connection,
    escalation_id: &str,
    now_unix:      i64,
) -> Result<Option<String>, rusqlite::Error> {
    let escalations = Table::Escalations.as_str();
    let initiatives = Table::Initiatives.as_str();

    let approved_state = EscalationStatus::Approved.as_sql_str();
    let pending_state  = EscalationStatus::Pending.as_sql_str();
    let class_str      = EscalationClass::LogicalDeadlock.as_sql_str();

    let row: Option<(String, String, String, String)> = tx.query_row(
        &format!(
            "SELECT initiative_id, class, initiator, status
               FROM {escalations} WHERE escalation_id = ?1"
        ),
        rusqlite::params![escalation_id],
        |r| Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, String>(2)?,
            r.get::<_, String>(3)?,
        )),
    ).optional()?;

    let Some((initiative_id, class, initiator, status)) = row else {
        return Ok(None);
    };

    if class != class_str || initiator != "Kernel" || status != pending_state {
        return Ok(None);
    }

    let updated = tx.execute(
        &format!(
            "UPDATE {escalations}
                SET status = ?1, resolved_at = ?2
              WHERE escalation_id = ?3 AND status = ?4"
        ),
        rusqlite::params![approved_state, now_unix, escalation_id, pending_state],
    )?;
    if updated != 1 {
        return Ok(None);
    }

    tx.execute(
        &format!(
            "UPDATE {initiatives}
                SET orchestrator_no_progress_respawn_count = 0
              WHERE initiative_id = ?1"
        ),
        rusqlite::params![&initiative_id],
    )?;

    tx.execute(
        &format!(
            "UPDATE {initiatives}
                SET state = 'Executing', completed_at = NULL
              WHERE initiative_id = ?1 AND state = 'Failed'"
        ),
        rusqlite::params![&initiative_id],
    )?;

    Ok(Some(initiative_id))
}

/// `INV-ESCALATION-AUTO-LOGICAL-DEADLOCK-01` — operator-deny path
/// for the kernel-initiated `LogicalDeadlock` escalation. UPDATEs
/// `escalations.status = 'Denied'`; the initiative stays `Failed`
/// and the orch-respawn counter stays at its post-ceiling value
/// (the operator's deny signals "do not retry; the failure mode
/// requires manual intervention").
///
/// Returns `Ok(initiative_id)` on success for audit attribution,
/// `Ok(None)` on FSM mismatch (already resolved or not found),
/// `Err` on SQL failure.
pub fn deny_logical_deadlock_escalation_in_tx(
    tx:               &Connection,
    escalation_id:    &str,
    now_unix:         i64,
    deny_reason_note: Option<&str>,
) -> Result<Option<String>, rusqlite::Error> {
    let escalations = Table::Escalations.as_str();

    let denied_state  = EscalationStatus::Denied.as_sql_str();
    let pending_state = EscalationStatus::Pending.as_sql_str();
    let class_str     = EscalationClass::LogicalDeadlock.as_sql_str();

    let row: Option<(String, String, String, String)> = tx.query_row(
        &format!(
            "SELECT initiative_id, class, initiator, status
               FROM {escalations} WHERE escalation_id = ?1"
        ),
        rusqlite::params![escalation_id],
        |r| Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, String>(2)?,
            r.get::<_, String>(3)?,
        )),
    ).optional()?;

    let Some((initiative_id, class, initiator, status)) = row else {
        return Ok(None);
    };

    if class != class_str || initiator != "Kernel" || status != pending_state {
        return Ok(None);
    }

    let updated = tx.execute(
        &format!(
            "UPDATE {escalations}
                SET status = ?1, resolved_at = ?2,
                    resolution_notes = COALESCE(?3, resolution_notes)
              WHERE escalation_id = ?4 AND status = ?5"
        ),
        rusqlite::params![
            denied_state, now_unix, deny_reason_note, escalation_id, pending_state
        ],
    )?;
    if updated != 1 {
        return Ok(None);
    }

    Ok(Some(initiative_id))
}

/// Bound either `last_intent_kind` or `last_rejection_reason` to
/// [`MAX_LOGICAL_DEADLOCK_REASON_LEN`] bytes. Chooses a UTF-8
/// boundary truncation so the resulting `String` is always valid
/// UTF-8 even if the input was a multi-byte sequence near the
/// limit.
fn truncate_for_scope(s: &str) -> String {
    if s.len() <= MAX_LOGICAL_DEADLOCK_REASON_LEN {
        return s.to_owned();
    }
    let mut end = MAX_LOGICAL_DEADLOCK_REASON_LEN;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_owned()
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

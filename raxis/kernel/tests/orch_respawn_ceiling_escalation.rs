//! Integration witness for
//! `INV-ESCALATION-AUTO-LOGICAL-DEADLOCK-01`
//! (auto-create + operator approve / deny path for the
//! kernel-initiated `LogicalDeadlock` escalation that pairs with
//! `OrchestratorRespawnCeilingExceeded`).
//!
//! ## What this pins
//!
//! `INV-ESCALATION-AUTO-LOGICAL-DEADLOCK-01` requires that every
//! emission of `OrchestratorRespawnCeilingExceeded` is preceded —
//! in the SAME SQLite transaction as the
//! `initiatives.state = 'RecoveryRequired'` flip — by an INSERT into
//! `escalations` with `class = 'LogicalDeadlock'`,
//! `initiator = 'Kernel'`, `status = 'Pending'`. The companion
//! invariant covers two operator-decision paths:
//!
//!   * **Approve** ⇒ `escalations.status = 'Approved'` AND
//!     `initiatives.orchestrator_no_progress_respawn_count = 0`
//!     AND `initiatives.state = 'Executing'` — all three under
//!     one tx.
//!   * **Deny** ⇒ `escalations.status = 'Denied'` AND
//!     `initiatives.state = 'Failed'`; counter NOT reset.
//!
//! ## Why this lives in `kernel/tests/` rather than
//!    `orch_respawn_ceiling::tests`
//!
//! `raxis-kernel` is a binary crate (no `lib.rs`); integration
//! tests therefore cannot call the in-tree helpers in
//! `kernel/src/orch_respawn_ceiling.rs` directly. The inline
//! `#[cfg(test)] mod tests` in that file covers the rust-API
//! happy-path; this witness exercises the SAME on-disk contract
//! against a real `raxis-store::Store`-backed sqlite file by
//! issuing the equivalent SQL inline, mirroring the kernel's
//! paired-write order. A regression in Migration 20, the
//! `EscalationClass::LogicalDeadlock` round-trip, the
//! `RequestedEscalationScope::LogicalDeadlock` JSON shape, or the
//! `escalations.initiator` column wiring will fail this witness
//! before any live-e2e dryrun has to wait for the harness
//! deadline.

#![cfg(test)]

use raxis_audit_tools::AuditEventKind;
use raxis_dashboard_kernel::notification_filter::{notification_priority, NotificationPriority};
use raxis_store::{migration::apply_pending, Table};
use rusqlite::{params, Connection};

const MAX_ORCH_NO_PROGRESS_RESPAWNS: u32 = 3;

// ---------------------------------------------------------------------------
// Fixture helpers
// ---------------------------------------------------------------------------

fn fresh_disk_conn() -> (tempfile::TempDir, Connection) {
    let tmp = tempfile::tempdir().expect("tempdir");
    let path = tmp.path().join("kernel.db");
    let conn = Connection::open(&path).expect("open sqlite file");
    conn.pragma_update(None, "journal_mode", "WAL").ok();
    conn.pragma_update(None, "foreign_keys", "ON").ok();
    apply_pending(&conn).expect("apply migrations");
    (tmp, conn)
}

/// Seed the rows the auto-escalation needs: one initiative in
/// `Executing` state with a bound session + task. The session
/// shape mirrors what `ApprovePlan` writes; the task carries
/// `session_id` + a recent `transitioned_at` so the
/// most-recently-touched-task-with-session lookup the kernel's
/// auto-creator runs finds it.
fn seed_initiative_with_anchor_task(
    conn: &Connection,
    initiative_id: &str,
    session_id: &str,
    task_id: &str,
    lineage_id: &str,
) {
    let initiatives = Table::Initiatives.as_str();
    let sessions = Table::Sessions.as_str();
    let tasks = Table::Tasks.as_str();

    let now = raxis_types::unix_now_secs();

    conn.execute(
        &format!(
            "INSERT INTO {initiatives}
                (initiative_id, state, terminal_criteria_json,
                 plan_artifact_sha256, created_at)
             VALUES (?1, 'Executing', '{{}}', '', ?2)"
        ),
        params![initiative_id, now],
    )
    .expect("seed initiative");

    conn.execute(
        &format!(
            "INSERT INTO {sessions}
                (session_id, role_id, session_token, lineage_id,
                 fetch_quota, created_at, expires_at)
             VALUES (?1, 'Orchestrator', ?2, ?3, 0, ?4, ?5)"
        ),
        params![
            session_id,
            format!("tok-{session_id}"),
            lineage_id,
            now,
            now + 3600,
        ],
    )
    .expect("seed session");

    conn.execute(
        &format!(
            "INSERT INTO {tasks}
                (task_id, initiative_id, lane_id, state, actor,
                 policy_epoch, admitted_at, transitioned_at, session_id)
             VALUES (?1, ?2, 'workspace', 'Running', 'Orchestrator',
                     0, ?3, ?3, ?4)"
        ),
        params![task_id, initiative_id, now, session_id],
    )
    .expect("seed task");
}

/// Drive the per-initiative respawn counter past
/// `MAX_ORCH_NO_PROGRESS_RESPAWNS` and emit the SAME paired-write
/// sequence the kernel's `respawn_orchestrator_for_initiative`
/// runs at Step 1b: INSERT escalations(class='LogicalDeadlock',
/// initiator='Kernel', status='Pending') → UPDATE
/// initiatives state='RecoveryRequired' → COMMIT. Returns the inserted
/// `escalation_id`.
fn drive_to_ceiling_and_insert_escalation(conn: &mut Connection, initiative_id: &str) -> String {
    let initiatives = Table::Initiatives.as_str();
    let sessions = Table::Sessions.as_str();
    let tasks = Table::Tasks.as_str();
    let escalations = Table::Escalations.as_str();

    // Walk the counter past the ceiling.
    for _ in 0..(MAX_ORCH_NO_PROGRESS_RESPAWNS + 1) {
        conn.execute(
            &format!(
                "UPDATE {initiatives}
                    SET orchestrator_no_progress_respawn_count =
                            orchestrator_no_progress_respawn_count + 1
                  WHERE initiative_id = ?1"
            ),
            params![initiative_id],
        )
        .expect("increment counter");
    }
    let count_after: i64 = conn
        .query_row(
            &format!(
                "SELECT orchestrator_no_progress_respawn_count
               FROM {initiatives} WHERE initiative_id = ?1"
            ),
            params![initiative_id],
            |r| r.get(0),
        )
        .expect("read counter");
    assert!(
        count_after as u32 > MAX_ORCH_NO_PROGRESS_RESPAWNS,
        "post-walk counter must strictly exceed ceiling; got {count_after}",
    );

    // Resolve anchor task / session / lineage inside a tx (mirror
    // of the kernel's lookup_anchor_task query).
    let now = raxis_types::unix_now_secs();
    let escalation_id = uuid::Uuid::new_v4().to_string();
    let tx = conn.transaction().expect("tx");
    let (task_id, session_id, lineage_id): (String, String, String) = tx
        .query_row(
            &format!(
                "SELECT t.task_id, s.session_id, s.lineage_id
               FROM {tasks} t
               JOIN {sessions} s ON s.session_id = t.session_id
              WHERE t.initiative_id = ?1
                AND t.session_id IS NOT NULL
              ORDER BY t.transitioned_at DESC
              LIMIT 1"
            ),
            params![initiative_id],
            |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                ))
            },
        )
        .expect("anchor task present");

    let scope_json = serde_json::json!({
        "LogicalDeadlock": {
            "initiative_id":         initiative_id,
            "attempts":              4,
            "window_secs":           120,
            "last_intent_kind":      "RetrySubTask",
            "last_rejection_reason": "RetrySubTaskRejectedNotRetryable",
        }
    })
    .to_string();

    let justification = "Orchestrator respawn-no-progress ceiling exceeded \
         (4 respawns within 120s with zero subtask FSM transitions). \
         Last orchestrator intent: RetrySubTask rejected as \
         RetrySubTaskRejectedNotRetryable. Operator approval required \
         to reset the respawn counter and retry, or deny to \
         close the initiative as Failed."
        .to_string();

    tx.execute(
        &format!(
            "INSERT INTO {escalations} (
                escalation_id, session_id, task_id, lineage_id, initiative_id,
                class, requested_scope_json, justification, idempotency_key,
                status, created_at, timeout_at, initiator
             ) VALUES (?1, ?2, ?3, ?4, ?5, 'LogicalDeadlock',
                       ?6, ?7, ?8, 'Pending', ?9, ?10, 'Kernel')
             ON CONFLICT(session_id, idempotency_key) DO NOTHING"
        ),
        params![
            escalation_id,
            session_id,
            task_id,
            lineage_id,
            initiative_id,
            scope_json,
            justification,
            format!("kernel-orch-respawn-ceiling:{initiative_id}"),
            now,
            now + 24 * 60 * 60,
        ],
    )
    .expect("insert escalation");

    tx.execute(
        &format!(
            "UPDATE {initiatives} SET state = 'RecoveryRequired', completed_at = NULL
              WHERE initiative_id = ?2"
        ),
        params![now, initiative_id],
    )
    .expect("flip RecoveryRequired");
    tx.commit().expect("commit insert + flip");

    escalation_id
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Ceiling exceedance MUST insert a `LogicalDeadlock` row with the
/// kernel-initiated marker AND flip the initiative to `RecoveryRequired` in
/// the same transaction (`INV-ESCALATION-AUTO-LOGICAL-DEADLOCK-01`
/// paired-write order).
#[test]
fn ceiling_exceedance_inserts_pending_logical_deadlock_kernel_escalation() {
    let (_tmp, mut conn) = fresh_disk_conn();
    let initiative_id = "init-led-1";
    seed_initiative_with_anchor_task(
        &conn,
        initiative_id,
        "sess-led-1",
        "task-led-1",
        "lineage-led-1",
    );

    let escalation_id = drive_to_ceiling_and_insert_escalation(&mut conn, initiative_id);

    // Exactly one escalation row for this initiative, class
    // LogicalDeadlock, initiator Kernel, status Pending.
    let escalations = Table::Escalations.as_str();
    let (class, initiator, status, scope_json, justification): (
        String,
        String,
        String,
        String,
        String,
    ) = conn
        .query_row(
            &format!(
                "SELECT class, initiator, status, requested_scope_json, justification
               FROM {escalations}
              WHERE initiative_id = ?1"
            ),
            params![initiative_id],
            |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, String>(4)?,
                ))
            },
        )
        .expect("escalation row present");

    assert_eq!(class, "LogicalDeadlock");
    assert_eq!(initiator, "Kernel");
    assert_eq!(status, "Pending");
    assert!(
        scope_json.contains("LogicalDeadlock") && scope_json.contains("RetrySubTask"),
        "requested_scope_json carries scope shape + last_intent_kind: {scope_json}",
    );
    assert!(
        justification.contains("4 respawns within 120s")
            && justification.contains("RetrySubTaskRejectedNotRetryable"),
        "operator-facing justification carries failure context: {justification}",
    );

    // Initiative is waiting for signed recovery approval.
    let initiatives = Table::Initiatives.as_str();
    let init_state: String = conn
        .query_row(
            &format!("SELECT state FROM {initiatives} WHERE initiative_id = ?1"),
            params![initiative_id],
            |r| r.get(0),
        )
        .expect("initiative row present");
    assert_eq!(init_state, "RecoveryRequired");

    // Escalation IDs round-trip as UUIDs.
    assert_eq!(escalation_id.len(), 36, "escalation_id is a UUIDv4 string");
}

/// Operator approve resets the orch-respawn counter, transitions
/// the initiative back to `Executing`, and flips the escalation
/// to `Approved` — all in one transaction. Mirrors the contract
/// `orch_respawn_ceiling::approve_logical_deadlock_escalation_in_tx`
/// implements.
#[test]
fn operator_approve_resets_counter_and_resumes_initiative() {
    let (_tmp, mut conn) = fresh_disk_conn();
    let initiative_id = "init-led-2";
    seed_initiative_with_anchor_task(
        &conn,
        initiative_id,
        "sess-led-2",
        "task-led-2",
        "lineage-led-2",
    );

    let escalation_id = drive_to_ceiling_and_insert_escalation(&mut conn, initiative_id);

    let initiatives = Table::Initiatives.as_str();
    let escalations = Table::Escalations.as_str();
    let pre_count: i64 = conn
        .query_row(
            &format!(
                "SELECT orchestrator_no_progress_respawn_count
               FROM {initiatives} WHERE initiative_id = ?1"
            ),
            params![initiative_id],
            |r| r.get(0),
        )
        .expect("read counter");
    assert!(
        pre_count as u32 > MAX_ORCH_NO_PROGRESS_RESPAWNS,
        "pre-approve counter must be above ceiling; got {pre_count}",
    );

    // Drive the operator-approve contract: status flip + counter
    // reset + state flip, all under one transaction.
    let now = raxis_types::unix_now_secs();
    let tx = conn.transaction().expect("tx for approve");
    let updated = tx
        .execute(
            &format!(
                "UPDATE {escalations}
                SET status = 'Approved', resolved_at = ?1
              WHERE escalation_id = ?2
                AND class = 'LogicalDeadlock'
                AND initiator = 'Kernel'
                AND status = 'Pending'"
            ),
            params![now, escalation_id],
        )
        .expect("flip Approved");
    assert_eq!(updated, 1, "approve targets exactly one Pending row");

    tx.execute(
        &format!(
            "UPDATE {initiatives}
                SET orchestrator_no_progress_respawn_count = 0
              WHERE initiative_id = ?1"
        ),
        params![initiative_id],
    )
    .expect("reset counter");
    tx.execute(
        &format!(
            "UPDATE {initiatives}
                SET state = 'Executing', completed_at = NULL
              WHERE initiative_id = ?1 AND state = 'RecoveryRequired'"
        ),
        params![initiative_id],
    )
    .expect("flip Executing");
    tx.commit().expect("commit approve");

    // Counter is back to zero.
    let post_count: i64 = conn
        .query_row(
            &format!(
                "SELECT orchestrator_no_progress_respawn_count
               FROM {initiatives} WHERE initiative_id = ?1"
            ),
            params![initiative_id],
            |r| r.get(0),
        )
        .expect("read counter post-approve");
    assert_eq!(
        post_count, 0,
        "operator approve resets the orch-respawn counter to 0"
    );

    // Initiative state flipped back to Executing.
    let post_state: String = conn
        .query_row(
            &format!("SELECT state FROM {initiatives} WHERE initiative_id = ?1"),
            params![initiative_id],
            |r| r.get(0),
        )
        .expect("read state post-approve");
    assert_eq!(post_state, "Executing");

    // Escalation flipped to Approved with resolved_at stamped.
    let (status, resolved_at): (String, Option<i64>) = conn
        .query_row(
            &format!(
                "SELECT status, resolved_at FROM {escalations}
              WHERE escalation_id = ?1"
            ),
            params![escalation_id],
            |r| Ok((r.get::<_, String>(0)?, r.get::<_, Option<i64>>(1)?)),
        )
        .expect("read escalation post-approve");
    assert_eq!(status, "Approved");
    assert!(resolved_at.is_some(), "resolved_at stamped on approve");
}

/// Operator deny closes `RecoveryRequired` as terminal `Failed` and
/// does NOT reset the counter.
/// The escalations row flips to `Denied` and the operator's
/// reason note (if present) lands in `resolution_notes`.
#[test]
fn operator_deny_closes_recovery_required_and_records_reason() {
    let (_tmp, mut conn) = fresh_disk_conn();
    let initiative_id = "init-led-3";
    seed_initiative_with_anchor_task(
        &conn,
        initiative_id,
        "sess-led-3",
        "task-led-3",
        "lineage-led-3",
    );

    let escalation_id = drive_to_ceiling_and_insert_escalation(&mut conn, initiative_id);

    // Drive deny: status flip with reason + RecoveryRequired -> Failed.
    let now = raxis_types::unix_now_secs();
    let escalations = Table::Escalations.as_str();
    let initiatives = Table::Initiatives.as_str();
    conn.execute(
        &format!(
            "UPDATE {escalations}
                SET status = 'Denied', resolved_at = ?1,
                    resolution_notes = ?2
              WHERE escalation_id = ?3
                AND class = 'LogicalDeadlock'
                AND initiator = 'Kernel'
                AND status = 'Pending'"
        ),
        params![now, "upstream cause unfixable", escalation_id],
    )
    .expect("flip Denied");
    conn.execute(
        &format!(
            "UPDATE {initiatives}
                SET state = 'Failed', completed_at = ?1
              WHERE initiative_id = ?2 AND state = 'RecoveryRequired'"
        ),
        params![now, initiative_id],
    )
    .expect("close initiative as Failed");

    // Counter unchanged.
    let post_count: i64 = conn
        .query_row(
            &format!(
                "SELECT orchestrator_no_progress_respawn_count
               FROM {initiatives} WHERE initiative_id = ?1"
            ),
            params![initiative_id],
            |r| r.get(0),
        )
        .expect("read counter post-deny");
    assert!(
        post_count as u32 > MAX_ORCH_NO_PROGRESS_RESPAWNS,
        "operator deny does NOT reset the counter; got {post_count}",
    );

    // Initiative is now closed Failed.
    let post_state: String = conn
        .query_row(
            &format!("SELECT state FROM {initiatives} WHERE initiative_id = ?1"),
            params![initiative_id],
            |r| r.get(0),
        )
        .expect("read state post-deny");
    assert_eq!(post_state, "Failed");

    // Escalation flipped to Denied with reason.
    let (status, notes): (String, Option<String>) = conn
        .query_row(
            &format!(
                "SELECT status, resolution_notes FROM {escalations}
              WHERE escalation_id = ?1"
            ),
            params![escalation_id],
            |r| Ok((r.get::<_, String>(0)?, r.get::<_, Option<String>>(1)?)),
        )
        .expect("read escalation post-deny");
    assert_eq!(status, "Denied");
    assert_eq!(notes.as_deref(), Some("upstream cause unfixable"));
}

/// `escalations.UNIQUE (session_id, idempotency_key)` is the
/// structural backstop against double-trigger from a pathological
/// caller — a second auto-create with the same deterministic
/// idempotency key (`kernel-orch-respawn-ceiling:{initiative_id}`)
/// is silently no-opped by the kernel's `ON CONFLICT DO NOTHING`
/// clause. Mirror that contract here.
#[test]
fn auto_escalation_is_idempotent_on_repeat_trigger() {
    let (_tmp, mut conn) = fresh_disk_conn();
    let initiative_id = "init-led-5";
    seed_initiative_with_anchor_task(
        &conn,
        initiative_id,
        "sess-led-5",
        "task-led-5",
        "lineage-led-5",
    );

    let _first = drive_to_ceiling_and_insert_escalation(&mut conn, initiative_id);

    // Second auto-create attempt → ON CONFLICT DO NOTHING fires.
    let escalations = Table::Escalations.as_str();
    let now = raxis_types::unix_now_secs();
    let inserted = conn
        .execute(
            &format!(
                "INSERT INTO {escalations} (
                escalation_id, session_id, task_id, lineage_id, initiative_id,
                class, requested_scope_json, justification, idempotency_key,
                status, created_at, timeout_at, initiator
             ) VALUES (?1, 'sess-led-5', 'task-led-5', 'lineage-led-5', ?2,
                       'LogicalDeadlock', '{{}}', 'second', ?3, 'Pending',
                       ?4, ?5, 'Kernel')
             ON CONFLICT(session_id, idempotency_key) DO NOTHING"
            ),
            params![
                uuid::Uuid::new_v4().to_string(),
                initiative_id,
                format!("kernel-orch-respawn-ceiling:{initiative_id}"),
                now,
                now + 24 * 60 * 60,
            ],
        )
        .expect("second insert with same idem key");
    assert_eq!(inserted, 0, "second insert is a no-op via ON CONFLICT");

    // Exactly one escalation row for the initiative.
    let count: i64 = conn
        .query_row(
            &format!("SELECT COUNT(*) FROM {escalations} WHERE initiative_id = ?1"),
            params![initiative_id],
            |r| r.get(0),
        )
        .expect("count");
    assert_eq!(
        count, 1,
        "auto-create is idempotent — the second trigger does not duplicate the row"
    );
}

/// The new `OperatorApprovedRespawnEscalation` and
/// `OperatorDeniedRespawnEscalation` audit variants must be
/// routed through the dashboard notification filter at `Medium`
/// priority — the operator already responded to the upstream
/// `Critical` ceiling event; the resolution surface is
/// observability, not a page.
#[test]
fn approve_deny_audit_variants_route_to_medium_priority() {
    let approved = AuditEventKind::OperatorApprovedRespawnEscalation {
        initiative_id: "init-led-6".into(),
        escalation_id: uuid::Uuid::new_v4().to_string(),
        operator_id: "op-fp".into(),
    };
    let denied = AuditEventKind::OperatorDeniedRespawnEscalation {
        initiative_id: "init-led-6".into(),
        escalation_id: uuid::Uuid::new_v4().to_string(),
        operator_id: "op-fp".into(),
    };
    assert_eq!(
        notification_priority(&approved),
        Some(NotificationPriority::Medium)
    );
    assert_eq!(
        notification_priority(&denied),
        Some(NotificationPriority::Medium)
    );
}

/// The class round-trips through `EscalationClass::from_sql_str`
/// (the `escalations.class` column is a free TEXT but the kernel's
/// only legal admission path back into a typed enum is this
/// parser). Pinning the round-trip here surfaces drift between
/// the SQL string and the wire enum.
#[test]
fn logical_deadlock_class_round_trips_through_sql_string() {
    use raxis_types::EscalationClass;
    let s = EscalationClass::LogicalDeadlock.as_sql_str();
    assert_eq!(s, "LogicalDeadlock");
    assert_eq!(
        EscalationClass::from_sql_str(s),
        Some(EscalationClass::LogicalDeadlock),
    );
}

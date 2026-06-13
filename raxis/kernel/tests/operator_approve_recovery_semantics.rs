//! `INV-OPERATOR-APPROVE-RECOVERY-SEMANTICS-01` (iter65-review).
//!
//! Schema-level witness for the operator-approve recovery path
//! that handles the iter65 + iter65-review escalation classes.
//! Mirrors `kernel/src/orch_respawn_ceiling.rs::approve_logical_deadlock_escalation_in_tx`
//! to pin the on-disk contract that approve always:
//!
//!   1. Flips `escalations.status: Pending → Approved`.
//!   2. Resets `initiatives.orchestrator_no_progress_respawn_count`
//!      to 0.
//!   3. Flips `initiatives.state: RecoveryRequired → Executing`
//!      only when the initiative is still `RecoveryRequired`.
//!      Terminal `Failed` initiatives are deliberately not resumable
//!      in place and stale pending recovery escalations do not get
//!      approved.
//!   4. Deny on a stale pending recovery escalation attached to an
//!      already terminal `Failed` initiative is allowed: it marks the
//!      escalation `Denied` and preserves the failed initiative state.
//!
//! The anti-loop guarantee is exercised separately: a re-fire
//! of the helper after approve writes a NEW escalation row
//! (different idempotency key — `cause_seq` advanced), NOT a
//! silent dedup against the just-approved row.

#![cfg(test)]

use raxis_store::{migration::apply_pending, Table};
use rusqlite::{params, Connection};

fn fresh_disk_conn() -> (tempfile::TempDir, Connection) {
    let tmp = tempfile::tempdir().expect("tempdir");
    let path = tmp.path().join("kernel.db");
    let conn = Connection::open(&path).expect("open sqlite file");
    conn.pragma_update(None, "journal_mode", "WAL").ok();
    conn.pragma_update(None, "foreign_keys", "ON").ok();
    apply_pending(&conn).expect("apply migrations");
    (tmp, conn)
}

fn seed_recovery_required_initiative_with_escalation(
    conn: &mut Connection,
    initiative_id: &str,
    session_id: &str,
    task_id: &str,
    lineage_id: &str,
    idempotency_key: &str,
    counter_value: i64,
) -> String {
    let initiatives = Table::Initiatives.as_str();
    let sessions = Table::Sessions.as_str();
    let tasks = Table::Tasks.as_str();
    let escalations = Table::Escalations.as_str();
    let now = raxis_types::unix_now_secs();

    conn.execute(
        &format!(
            "INSERT INTO {initiatives}
                (initiative_id, state, terminal_criteria_json,
                 plan_artifact_sha256, created_at, completed_at,
                 orchestrator_no_progress_respawn_count)
             VALUES (?1, 'RecoveryRequired', '{{}}', '', ?2, NULL, ?3)"
        ),
        params![initiative_id, now, counter_value],
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
             VALUES (?1, ?2, 'workspace', 'Failed', 'Orchestrator',
                     0, ?3, ?3, ?4)"
        ),
        params![task_id, initiative_id, now, session_id],
    )
    .expect("seed task");

    let escalation_id = uuid::Uuid::new_v4().to_string();
    conn.execute(
        &format!(
            "INSERT INTO {escalations} (
                escalation_id, session_id, task_id, lineage_id, initiative_id,
                class, requested_scope_json, justification, idempotency_key,
                status, created_at, timeout_at, initiator
             ) VALUES (?1, ?2, ?3, ?4, ?5, 'LogicalDeadlock',
                       '{{}}', 'permanent-failure escalation', ?6,
                       'Pending', ?7, ?8, 'Kernel')"
        ),
        params![
            escalation_id,
            session_id,
            task_id,
            lineage_id,
            initiative_id,
            idempotency_key,
            now,
            now + 3600,
        ],
    )
    .expect("seed escalation");

    escalation_id
}

/// Schema-level mirror of `approve_logical_deadlock_escalation_in_tx`.
/// Returns `(approved_status, counter_after, state_after,
/// transitioned_from_recovery_required)`.
fn schema_approve_logical_deadlock(
    conn: &mut Connection,
    escalation_id: &str,
) -> (String, i64, String, bool) {
    let escalations = Table::Escalations.as_str();
    let initiatives = Table::Initiatives.as_str();
    let now = raxis_types::unix_now_secs();
    let tx = conn.transaction().expect("tx");

    let (initiative_id, initiative_state): (String, String) = tx
        .query_row(
            &format!(
                "SELECT e.initiative_id, i.state
                   FROM {escalations} e
                   JOIN {initiatives} i ON i.initiative_id = e.initiative_id
                  WHERE e.escalation_id = ?1
                    AND e.class = 'LogicalDeadlock'
                    AND e.initiator = 'Kernel'
                    AND e.status = 'Pending'"
            ),
            params![escalation_id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .expect("escalation row exists in approvable shape");

    if initiative_state != "RecoveryRequired" {
        tx.commit().expect("commit no-op");
        let status: String = conn
            .query_row(
                &format!("SELECT status FROM {escalations} WHERE escalation_id = ?1"),
                params![escalation_id],
                |r| r.get(0),
            )
            .expect("read status");
        let counter: i64 = conn
            .query_row(
                &format!(
                    "SELECT orchestrator_no_progress_respawn_count
                       FROM {initiatives} WHERE initiative_id = ?1"
                ),
                params![&initiative_id],
                |r| r.get(0),
            )
            .expect("read counter");
        return (status, counter, initiative_state, false);
    }

    tx.execute(
        &format!(
            "UPDATE {escalations}
                SET status = 'Approved', resolved_at = ?2
              WHERE escalation_id = ?1 AND status = 'Pending'"
        ),
        params![escalation_id, now],
    )
    .expect("flip status");

    tx.execute(
        &format!(
            "UPDATE {initiatives}
                SET orchestrator_no_progress_respawn_count = 0
              WHERE initiative_id = ?1"
        ),
        params![&initiative_id],
    )
    .expect("reset counter");

    let state_change_rows = tx
        .execute(
            &format!(
                "UPDATE {initiatives}
                    SET state = 'Executing', completed_at = NULL
                  WHERE initiative_id = ?1 AND state = 'RecoveryRequired'"
            ),
            params![&initiative_id],
        )
        .expect("flip state");

    tx.commit().expect("commit");

    let approved: String = conn
        .query_row(
            &format!("SELECT status FROM {escalations} WHERE escalation_id = ?1"),
            params![escalation_id],
            |r| r.get(0),
        )
        .expect("read status");
    let counter: i64 = conn
        .query_row(
            &format!(
                "SELECT orchestrator_no_progress_respawn_count
                   FROM {initiatives} WHERE initiative_id = ?1"
            ),
            params![&initiative_id],
            |r| r.get(0),
        )
        .expect("read counter");
    let state: String = conn
        .query_row(
            &format!("SELECT state FROM {initiatives} WHERE initiative_id = ?1"),
            params![&initiative_id],
            |r| r.get(0),
        )
        .expect("read state");

    (approved, counter, state, state_change_rows == 1)
}

/// Schema-level mirror of `deny_logical_deadlock_escalation_in_tx`.
/// Returns `(denied_status, state_after, transitioned_to_failed)`.
fn schema_deny_logical_deadlock(
    conn: &mut Connection,
    escalation_id: &str,
    reason: Option<&str>,
) -> (String, String, bool) {
    let escalations = Table::Escalations.as_str();
    let initiatives = Table::Initiatives.as_str();
    let now = raxis_types::unix_now_secs();
    let tx = conn.transaction().expect("tx");

    let row: Option<(String, String)> = tx
        .query_row(
            &format!(
                "SELECT e.initiative_id, i.state
                   FROM {escalations} e
                   JOIN {initiatives} i ON i.initiative_id = e.initiative_id
                  WHERE e.escalation_id = ?1
                    AND e.class = 'LogicalDeadlock'
                    AND e.initiator = 'Kernel'
                    AND e.status = 'Pending'"
            ),
            params![escalation_id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .ok();

    let Some((initiative_id, initiative_state)) = row else {
        tx.commit().expect("commit no-op");
        let status: String = conn
            .query_row(
                &format!("SELECT status FROM {escalations} WHERE escalation_id = ?1"),
                params![escalation_id],
                |r| r.get(0),
            )
            .expect("read status");
        return (status, String::new(), false);
    };

    if initiative_state != "RecoveryRequired" && initiative_state != "Failed" {
        tx.commit().expect("commit no-op");
        let status: String = conn
            .query_row(
                &format!("SELECT status FROM {escalations} WHERE escalation_id = ?1"),
                params![escalation_id],
                |r| r.get(0),
            )
            .expect("read status");
        return (status, initiative_state, false);
    }

    tx.execute(
        &format!(
            "UPDATE {escalations}
                SET status = 'Denied', resolved_at = ?2,
                    resolution_notes = COALESCE(?3, resolution_notes)
              WHERE escalation_id = ?1 AND status = 'Pending'"
        ),
        params![escalation_id, now, reason],
    )
    .expect("flip status");

    let state_change_rows = if initiative_state == "RecoveryRequired" {
        tx.execute(
            &format!(
                "UPDATE {initiatives}
                    SET state = 'Failed',
                        completed_at = ?2
                  WHERE initiative_id = ?1 AND state = 'RecoveryRequired'"
            ),
            params![&initiative_id, now],
        )
        .expect("transition recovery to failed")
    } else {
        0
    };

    tx.commit().expect("commit");

    let denied: String = conn
        .query_row(
            &format!("SELECT status FROM {escalations} WHERE escalation_id = ?1"),
            params![escalation_id],
            |r| r.get(0),
        )
        .expect("read status");
    let state: String = conn
        .query_row(
            &format!("SELECT state FROM {initiatives} WHERE initiative_id = ?1"),
            params![&initiative_id],
            |r| r.get(0),
        )
        .expect("read state");

    (denied, state, state_change_rows == 1)
}

#[test]
fn approve_refuses_terminal_failed_initiative_without_mutating_escalation() {
    let (_tmp, mut conn) = fresh_disk_conn();
    let escalation_id = seed_recovery_required_initiative_with_escalation(
        &mut conn,
        "init-terminal-failed",
        "sess-terminal",
        "task-terminal",
        "lin-terminal",
        "kernel-initiative-permanent-failure:init-terminal-failed:PushFailed:remote=origin;ref=refs/heads/main",
        7,
    );

    let initiatives = Table::Initiatives.as_str();
    conn.execute(
        &format!(
            "UPDATE {initiatives}
                SET state = 'Failed', completed_at = ?2
              WHERE initiative_id = ?1"
        ),
        params!["init-terminal-failed", raxis_types::unix_now_secs()],
    )
    .expect("close initiative as terminal Failed");

    let (status, counter, state, transitioned) =
        schema_approve_logical_deadlock(&mut conn, &escalation_id);
    assert_eq!(
        status, "Pending",
        "stale recovery approval MUST NOT approve escalation once initiative is terminal Failed",
    );
    assert_eq!(
        counter, 7,
        "stale recovery approval MUST NOT reset no-progress counter on terminal Failed",
    );
    assert_eq!(state, "Failed");
    assert!(
        !transitioned,
        "terminal Failed must not report a RecoveryRequired -> Executing transition",
    );
}

#[test]
fn deny_allows_stale_pending_recovery_escalation_on_failed_initiative() {
    let (_tmp, mut conn) = fresh_disk_conn();
    let escalation_id = seed_recovery_required_initiative_with_escalation(
        &mut conn,
        "init-terminal-failed-deny",
        "sess-terminal-deny",
        "task-terminal-deny",
        "lin-terminal-deny",
        "kernel-initiative-permanent-failure:init-terminal-failed-deny:PushFailed:remote=origin;ref=refs/heads/main",
        7,
    );

    let initiatives = Table::Initiatives.as_str();
    conn.execute(
        &format!(
            "UPDATE {initiatives}
                SET state = 'Failed', completed_at = ?2
              WHERE initiative_id = ?1"
        ),
        params!["init-terminal-failed-deny", raxis_types::unix_now_secs()],
    )
    .expect("close initiative as terminal Failed");

    let (status, state, transitioned) =
        schema_deny_logical_deadlock(&mut conn, &escalation_id, Some("preserve failed state"));
    assert_eq!(
        status, "Denied",
        "operator denial MUST close stale pending recovery escalations even when the initiative is already Failed",
    );
    assert_eq!(
        state, "Failed",
        "denying a stale escalation must preserve the terminal Failed initiative state",
    );
    assert!(
        !transitioned,
        "already-Failed initiative must not report a RecoveryRequired -> Failed transition",
    );
}

/// `INV-OPERATOR-APPROVE-RECOVERY-SEMANTICS-01`. Approve on a
/// Pending kernel-initiated LogicalDeadlock escalation MUST:
///
///   * Flip `escalations.status: Pending → Approved`.
///   * Reset `initiatives.orchestrator_no_progress_respawn_count`
///     to 0.
///   * Flip `initiatives.state: RecoveryRequired → Executing`.
///   * Report `transitioned_from_recovery_required = true` so the operator
///     handler emits the paired `InitiativeStateChanged` audit.
#[test]
fn approve_happy_path_flips_status_resets_counter_unfails_initiative() {
    let (_tmp, mut conn) = fresh_disk_conn();
    let escalation_id = seed_recovery_required_initiative_with_escalation(
        &mut conn,
        "init-approve-1",
        "sess-1",
        "task-1",
        "lin-1",
        "kernel-initiative-permanent-failure:init-approve-1:PushFailed:remote=origin;ref=refs/heads/main",
        4,
    );
    let (status, counter, state, transitioned) =
        schema_approve_logical_deadlock(&mut conn, &escalation_id);
    assert_eq!(status, "Approved", "approve MUST flip status to Approved");
    assert_eq!(counter, 0, "approve MUST reset NNSP counter to 0");
    assert_eq!(
        state, "Executing",
        "approve MUST flip RecoveryRequired → Executing for the next decision-cycle to pick up",
    );
    assert!(
        transitioned,
        "approve MUST report transitioned_from_recovery_required=true so the operator handler emits paired InitiativeStateChanged",
    );
}

/// Anti-loop guarantee. After approve, a fresh permanent-failure
/// helper invocation with a DIFFERENT `cause_seq` writes a NEW
/// escalation row (the operator sees the cycle and can choose
/// Deny). Same `cause_seq` would dedup against the
/// already-Approved row — but the
/// `INV-INITIATIVE-PERMANENT-FAILURE-ESCALATION-COVERAGE-01`
/// invariant guarantees that re-fires after a real-world
/// re-failure carry an advanced cause_seq (attempt counters,
/// reason hashes, timestamps).
#[test]
fn refailure_after_approve_inserts_new_escalation_row_not_dedup() {
    let (_tmp, mut conn) = fresh_disk_conn();
    let first_escalation_id = seed_recovery_required_initiative_with_escalation(
        &mut conn,
        "init-refail",
        "sess-1",
        "task-1",
        "lin-1",
        "kernel-initiative-permanent-failure:init-refail:SessionVmFailedFinal:attempts=3",
        4,
    );
    // Operator approves the first escalation.
    let (status, _counter, state, _transitioned) =
        schema_approve_logical_deadlock(&mut conn, &first_escalation_id);
    assert_eq!(status, "Approved");
    assert_eq!(state, "Executing");

    // Underlying cause is still present — next decision-cycle
    // re-spawns and the VM permanent-fails AGAIN, attempt count
    // advances. Helper fires with `attempts=6` (not 3 → fresh
    // cause_seq).
    let escalations = Table::Escalations.as_str();
    let now = raxis_types::unix_now_secs();
    let second_escalation_id = uuid::Uuid::new_v4().to_string();
    conn.execute(
        &format!(
            "INSERT INTO {escalations} (
                escalation_id, session_id, task_id, lineage_id, initiative_id,
                class, requested_scope_json, justification, idempotency_key,
                status, created_at, timeout_at, initiator
             ) VALUES (?1, ?2, ?3, ?4, ?5, 'LogicalDeadlock',
                       '{{}}', 'permanent-failure re-escalation', ?6,
                       'Pending', ?7, ?8, 'Kernel')
             ON CONFLICT(session_id, idempotency_key) DO NOTHING"
        ),
        params![
            second_escalation_id,
            "sess-1",
            "task-1",
            "lin-1",
            "init-refail",
            // DIFFERENT cause_seq (attempts advanced).
            "kernel-initiative-permanent-failure:init-refail:SessionVmFailedFinal:attempts=6",
            now,
            now + 3600,
        ],
    )
    .expect("re-fire insert MUST succeed (different idempotency key)");

    let initiatives = Table::Initiatives.as_str();
    conn.execute(
        &format!(
            "UPDATE {initiatives}
                SET state = 'RecoveryRequired',
                    orchestrator_no_progress_respawn_count = 6,
                    completed_at = NULL
              WHERE initiative_id = ?1"
        ),
        params!["init-refail"],
    )
    .expect("re-failure must pause initiative in RecoveryRequired before approval");

    let count: i64 = conn
        .query_row(
            &format!("SELECT COUNT(*) FROM {escalations} WHERE initiative_id = ?1"),
            params!["init-refail"],
            |r| r.get(0),
        )
        .expect("count");
    assert_eq!(
        count, 2,
        "re-failure with advanced cause_seq MUST yield 2 distinct escalation rows; \
         operator MUST NOT silently lose the re-failure signal",
    );

    // Approving the second row exercises the same handler ⇒
    // proves the recovery path works for re-failures too (no
    // special-case re-failure handler needed, the existing
    // approve handler is idempotent across multiple per-cause
    // escalations).
    let (status2, counter2, state2, _t2) =
        schema_approve_logical_deadlock(&mut conn, &second_escalation_id);
    assert_eq!(status2, "Approved");
    assert_eq!(counter2, 0);
    assert_eq!(state2, "Executing");
}

/// The approve handler refuses to act on rows that aren't the
/// canonical kernel-initiated LogicalDeadlock shape. Pinned
/// here so a future refactor that loosens the SELECT WHERE
/// clause (e.g. drops the `initiator = 'Kernel'` check) is
/// caught — operator-initiated escalations have a different
/// approve path and MUST NOT ride this handler.
#[test]
fn approve_refuses_planner_initiated_escalation() {
    let (_tmp, conn) = fresh_disk_conn();
    let escalations = Table::Escalations.as_str();
    let initiatives = Table::Initiatives.as_str();
    let sessions = Table::Sessions.as_str();
    let tasks = Table::Tasks.as_str();
    let now = raxis_types::unix_now_secs();
    conn.execute(
        &format!(
            "INSERT INTO {initiatives}
                (initiative_id, state, terminal_criteria_json,
                 plan_artifact_sha256, created_at)
             VALUES ('init-planner', 'Executing', '{{}}', '', ?1)"
        ),
        params![now],
    )
    .expect("seed initiative");
    conn.execute(
        &format!(
            "INSERT INTO {sessions}
                (session_id, role_id, session_token, lineage_id,
                 fetch_quota, created_at, expires_at)
             VALUES ('sess-p', 'Orchestrator', 'tok', 'lin', 0, ?1, ?2)"
        ),
        params![now, now + 3600],
    )
    .expect("seed session");
    conn.execute(
        &format!(
            "INSERT INTO {tasks}
                (task_id, initiative_id, lane_id, state, actor,
                 policy_epoch, admitted_at, transitioned_at, session_id)
             VALUES ('task-p', 'init-planner', 'workspace', 'Running',
                     'Orchestrator', 0, ?1, ?1, 'sess-p')"
        ),
        params![now],
    )
    .expect("seed task");
    let planner_id = uuid::Uuid::new_v4().to_string();
    conn.execute(
        &format!(
            "INSERT INTO {escalations} (
                escalation_id, session_id, task_id, lineage_id, initiative_id,
                class, requested_scope_json, justification, idempotency_key,
                status, created_at, timeout_at, initiator
             ) VALUES (?1, 'sess-p', 'task-p', 'lin', 'init-planner',
                       'LogicalDeadlock', '{{}}', 'planner-asked',
                       'planner-key-1', 'Pending', ?2, ?3, 'Planner')"
        ),
        params![planner_id, now, now + 3600],
    )
    .expect("seed planner-initiated escalation");

    // Schema-level mirror of the `WHERE initiator = 'Kernel'`
    // skip-check inside the production handler.
    let row: Option<String> = conn
        .query_row(
            &format!(
                "SELECT escalation_id FROM {escalations}
                  WHERE escalation_id = ?1
                    AND class = 'LogicalDeadlock'
                    AND initiator = 'Kernel'
                    AND status = 'Pending'"
            ),
            params![&planner_id],
            |r| r.get(0),
        )
        .ok();
    assert!(
        row.is_none(),
        "approve handler's WHERE clause MUST refuse planner-initiated escalations \
         (initiator='Planner') — they have a different approve path",
    );
}

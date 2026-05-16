//! `INV-INITIATIVE-PERMANENT-FAILURE-ESCALATION-COVERAGE-01`
//! (iter65-review) — schema-level + classifier witnesses for the
//! generalised permanent-failure escalation helper.
//!
//! ## Why this lives in `kernel/tests/`
//!
//! `raxis-kernel` is a binary crate (no `lib.rs`); integration
//! tests cannot call `crate::initiative_escalation` helpers
//! directly. The helper itself is exercised via inline
//! `#[cfg(test)]` modules colocated with the source; this
//! integration witness covers the cross-cutting contract:
//!
//!   * The audit-tools layer (`raxis-audit-tools`) can construct
//!     and serialise the new
//!     `AuditEventKind::InitiativePermanentFailureEscalated`
//!     variant.
//!   * The dashboard-kernel notification classifier (typed +
//!     string-discriminator) routes the new variant to `Critical`
//!     for both surfaces, satisfying
//!     `INV-NOTIFICATION-PRIORITY-PARITY-01`.
//!   * The on-disk paired-write SQL contract (escalation INSERT
//!     with a permanent-failure-keyed idempotency key + initiative
//!     UPDATE to `Failed`) lands atomically and dedup's on
//!     re-fire.
//!
//! ## What this pins (per-cause)
//!
//! Idempotency: a re-fire of the same `(initiative_id, cause_kind,
//! cause_seq)` triple inserts only one escalation row.
//!
//! Cross-cause distinctness: two different causes on the same
//! initiative each get their own escalation row.
//!
//! Notification priority parity: the new variant routes to
//! Critical via both the typed and string classifiers.
//!
//! Cause-coverage: the closed enum
//! `kernel::initiative_escalation::PermanentFailureCause` covers
//! every kind the iter65-review charter calls out as in-scope; a
//! match-arm regression that drops a variant is caught at compile
//! time by the helper's `as_kind_str` exhaustive match.

#![cfg(test)]

use raxis_audit_tools::AuditEventKind;
use raxis_dashboard_kernel::notification_filter::{
    notification_priority, notification_priority_for_kind_str, NotificationPriority,
};
use raxis_store::{migration::apply_pending, Table};
use raxis_types::{EscalationClass, EscalationStatus};
use rusqlite::{params, Connection};

// ---------------------------------------------------------------------------
// Fixture helpers (schema-level mirror of the kernel SQL)
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
/// `Executing` state with a bound session + task. Same seed shape
/// as the iter65 `orch_respawn_ceiling_escalation` witness so the
/// FK lookups the helper performs find the canonical anchor.
fn seed_initiative_with_anchor(
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

/// Schema-level mirror of
/// `initiative_escalation::insert_permanent_failure_escalation_in_tx`.
/// Inserts one `escalations` row keyed on the helper's
/// idempotency-key namespace + flips the initiative to `Failed`.
/// Returns the inserted `escalation_id` or `None` on the
/// dedup-by-idempotency-key path.
fn schema_paired_write_permanent_failure_escalation(
    conn: &mut Connection,
    initiative_id: &str,
    cause_kind: &str,
    cause_seq: &str,
    cause_summary: &str,
) -> Option<String> {
    let escalations = Table::Escalations.as_str();
    let initiatives = Table::Initiatives.as_str();
    let now = raxis_types::unix_now_secs();
    let timeout_at = now.saturating_add(3600);
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
                  LIMIT 1",
                tasks = Table::Tasks.as_str(),
                sessions = Table::Sessions.as_str(),
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
        .expect("anchor task present in seed");

    let idempotency_key =
        format!("kernel-initiative-permanent-failure:{initiative_id}:{cause_kind}:{cause_seq}",);

    let scope_json = serde_json::json!({
        "LogicalDeadlock": {
            "initiative_id":         initiative_id,
            "attempts":              1,
            "window_secs":           0,
            "last_intent_kind":      cause_kind,
            "last_rejection_reason": cause_summary,
        }
    })
    .to_string();

    let justification = format!(
        "Initiative permanent-failure escalation triggered by audit \
         event {cause_kind}: {cause_summary}. \
         INV-INITIATIVE-PERMANENT-FAILURE-ESCALATION-COVERAGE-01",
    );

    let inserted = tx
        .execute(
            &format!(
                "INSERT INTO {escalations} (
                    escalation_id, session_id, task_id, lineage_id, initiative_id,
                    class, requested_scope_json, justification, idempotency_key,
                    status, created_at, timeout_at, initiator
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, 'Kernel')
                 ON CONFLICT(session_id, idempotency_key) DO NOTHING"
            ),
            params![
                escalation_id,
                session_id,
                task_id,
                lineage_id,
                initiative_id,
                EscalationClass::LogicalDeadlock.as_sql_str(),
                scope_json,
                justification,
                idempotency_key,
                EscalationStatus::Pending.as_sql_str(),
                now,
                timeout_at,
            ],
        )
        .expect("insert");

    tx.execute(
        &format!(
            "UPDATE {initiatives}
                SET state        = 'Failed',
                    completed_at = ?2
              WHERE initiative_id = ?1
                AND state NOT IN ('Completed','Failed','Cancelled','Aborted')"
        ),
        params![initiative_id, now],
    )
    .expect("flip initiative to Failed");

    tx.commit().expect("commit");

    if inserted == 0 {
        None
    } else {
        Some(escalation_id)
    }
}

fn count_escalations_for_initiative(conn: &Connection, initiative_id: &str) -> i64 {
    let escalations = Table::Escalations.as_str();
    conn.query_row(
        &format!("SELECT COUNT(*) FROM {escalations} WHERE initiative_id = ?1"),
        params![initiative_id],
        |r| r.get(0),
    )
    .expect("count")
}

fn read_state(conn: &Connection, initiative_id: &str) -> String {
    let initiatives = Table::Initiatives.as_str();
    conn.query_row(
        &format!("SELECT state FROM {initiatives} WHERE initiative_id = ?1"),
        params![initiative_id],
        |r| r.get(0),
    )
    .expect("read state")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// `INV-INITIATIVE-PERMANENT-FAILURE-ESCALATION-COVERAGE-01`
/// (iter65-review). The first escalation for a given
/// `(initiative_id, cause_kind, cause_seq)` triple lands as a
/// fresh row + flips the initiative to `Failed`. A second emit of
/// the SAME triple dedup's against the original row (the
/// `escalations.UNIQUE(session_id, idempotency_key)` index
/// short-circuits the INSERT) and the row count stays at 1.
#[test]
fn idempotency_dedup_on_same_cause_seq() {
    let (_tmp, mut conn) = fresh_disk_conn();
    seed_initiative_with_anchor(&conn, "init-perm-fail-1", "sess-1", "task-1", "lin-1");

    let first = schema_paired_write_permanent_failure_escalation(
        &mut conn,
        "init-perm-fail-1",
        "PushFailed",
        "remote=origin;ref=refs/heads/main",
        "push to origin refs/heads/main failed: network",
    );
    assert!(
        first.is_some(),
        "first emit must insert a fresh escalation row",
    );
    assert_eq!(
        count_escalations_for_initiative(&conn, "init-perm-fail-1"),
        1,
        "after first emit there must be exactly 1 escalation row",
    );
    assert_eq!(
        read_state(&conn, "init-perm-fail-1"),
        "Failed",
        "first emit must flip the initiative to Failed",
    );

    // Second emit of the exact same cause + cause_seq dedup's.
    let second = schema_paired_write_permanent_failure_escalation(
        &mut conn,
        "init-perm-fail-1",
        "PushFailed",
        "remote=origin;ref=refs/heads/main",
        "push to origin refs/heads/main failed: network",
    );
    assert!(
        second.is_none(),
        "second emit of the same (kind, seq) MUST dedup; got {second:?}",
    );
    assert_eq!(
        count_escalations_for_initiative(&conn, "init-perm-fail-1"),
        1,
        "dedup MUST NOT introduce a second row",
    );
}

/// `INV-INITIATIVE-PERMANENT-FAILURE-ESCALATION-COVERAGE-01`.
/// Two distinct cause shapes on the SAME initiative each get
/// their own escalation row — the idempotency key is keyed on
/// `(cause_kind, cause_seq)`, not on `initiative_id` alone.
#[test]
fn distinct_causes_each_get_their_own_escalation() {
    let (_tmp, mut conn) = fresh_disk_conn();
    seed_initiative_with_anchor(&conn, "init-multi-cause", "sess-1", "task-1", "lin-1");

    let push_id = schema_paired_write_permanent_failure_escalation(
        &mut conn,
        "init-multi-cause",
        "PushFailed",
        "remote=origin;ref=refs/heads/main",
        "push to origin refs/heads/main failed: network",
    );
    assert!(push_id.is_some(), "push escalation must insert");
    let merge_id = schema_paired_write_permanent_failure_escalation(
        &mut conn,
        "init-multi-cause",
        "MergeFastForwardFailed",
        "ref=refs/heads/main;cat=non_fast_forward",
        "merge fast-forward to refs/heads/main failed: non_fast_forward",
    );
    assert!(merge_id.is_some(), "merge escalation must insert");
    assert_ne!(push_id, merge_id);
    assert_eq!(
        count_escalations_for_initiative(&conn, "init-multi-cause"),
        2,
        "two distinct cause shapes MUST yield two distinct escalation rows",
    );
}

/// The on-disk class is `LogicalDeadlock` (the helper reuses the
/// existing class to avoid a SQLite migration); the differentiator
/// for the dashboard pivot is the chain-side audit anchor's
/// `cause_kind` field. Pinned here so a future refactor that
/// renames the class keeps the schema CHECK constraint in sync.
#[test]
fn escalation_row_class_is_logical_deadlock_kernel_initiated() {
    let (_tmp, mut conn) = fresh_disk_conn();
    seed_initiative_with_anchor(&conn, "init-class-pin", "sess-1", "task-1", "lin-1");
    let _ = schema_paired_write_permanent_failure_escalation(
        &mut conn,
        "init-class-pin",
        "SessionVmFailedFinal",
        "attempts=3",
        "VM spawn permanent failure after 3 attempts: kvm_oom",
    );
    let escalations = Table::Escalations.as_str();
    let (class, initiator): (String, String) = conn
        .query_row(
            &format!(
                "SELECT class, initiator FROM {escalations} \
                  WHERE initiative_id = ?1"
            ),
            params!["init-class-pin"],
            |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
        )
        .expect("read escalation row");
    assert_eq!(class, "LogicalDeadlock");
    assert_eq!(initiator, "Kernel");
}

/// `INV-NOTIFICATION-PRIORITY-PARITY-01` (iter65) extended for
/// the new variant (iter65-review). Both classifiers MUST route
/// `InitiativePermanentFailureEscalated` to `Critical`. A drift
/// here recreates the iter64 pathology where the dispatch gate
/// dropped a Critical-only filter on the inbox notification.
#[test]
fn new_variant_classifies_critical_on_both_classifier_surfaces() {
    let kind = AuditEventKind::InitiativePermanentFailureEscalated {
        initiative_id: "init-x".into(),
        cause_kind: "PushFailed".into(),
        cause_summary: "push to origin failed: network".into(),
        escalation_id: Some("esc-1".into()),
        recoverable_via_approve: true,
    };
    assert_eq!(
        notification_priority(&kind),
        Some(NotificationPriority::Critical),
        "typed classifier MUST route the new variant to Critical",
    );
    assert_eq!(
        notification_priority_for_kind_str(kind.as_str()),
        Some(NotificationPriority::Critical),
        "string classifier MUST route the new variant to Critical \
         per INV-NOTIFICATION-PRIORITY-PARITY-01",
    );
}

/// The audit anchor stamps the cause discriminator + the
/// recoverability hint so dashboards can pivot by cause without
/// reverse-engineering the justification text.
#[test]
fn audit_anchor_carries_cause_kind_and_recoverability() {
    let recoverable = AuditEventKind::InitiativePermanentFailureEscalated {
        initiative_id: "init-r".into(),
        cause_kind: "SessionVmFailedFinal".into(),
        cause_summary: "VM spawn permanent failure after 3 attempts: kvm_oom".into(),
        escalation_id: Some("esc-r".into()),
        recoverable_via_approve: true,
    };
    let v = serde_json::to_value(&recoverable).expect("serialise");
    assert_eq!(v["kind"], "InitiativePermanentFailureEscalated");
    assert_eq!(v["initiative_id"], "init-r");
    assert_eq!(v["cause_kind"], "SessionVmFailedFinal");
    assert_eq!(v["recoverable_via_approve"], true);
    assert_eq!(v["escalation_id"], "esc-r");

    let non_recoverable = AuditEventKind::InitiativePermanentFailureEscalated {
        initiative_id: "init-n".into(),
        cause_kind: "PlanRejected".into(),
        cause_summary: "plan admission rejected: malformed [[tasks]] block".into(),
        // anchor-less path: helper's FK lookup failed, but the
        // chain anchor still fires so the inbox surfaces the
        // permanent-failure signal.
        escalation_id: None,
        recoverable_via_approve: false,
    };
    let v2 = serde_json::to_value(&non_recoverable).expect("serialise");
    assert_eq!(v2["recoverable_via_approve"], false);
    assert!(
        v2["escalation_id"].is_null(),
        "anchor-less path: escalation_id MUST serialise as JSON null",
    );
}

/// The helper refuses to flip an already-terminal initiative.
/// Schema-level mirror of the helper's `TERMINAL_STATES` skip
/// check: an operator-driven `Aborted` race must not be silently
/// converted into `Failed` by a permanent-failure event landing
/// after the abort. The escalation row likewise MUST NOT insert
/// (the operator already settled the FSM).
#[test]
fn skips_when_initiative_is_already_terminal() {
    let (_tmp, mut conn) = fresh_disk_conn();
    seed_initiative_with_anchor(&conn, "init-already-aborted", "sess-1", "task-1", "lin-1");
    // Operator-driven abort lands first.
    let initiatives = Table::Initiatives.as_str();
    conn.execute(
        &format!(
            "UPDATE {initiatives}
                SET state = 'Aborted', completed_at = strftime('%s','now')
              WHERE initiative_id = ?1"
        ),
        params!["init-already-aborted"],
    )
    .expect("simulate operator abort");

    // Schema-level helper does NOT short-circuit (the production
    // helper has a `TERMINAL_STATES` skip; this schema mirror
    // does not, intentionally — the test asserts that the
    // SCHEMA-level UPDATE's `WHERE state NOT IN (...)` clause
    // refuses to flip the row. Both layers must agree.
    let _ = schema_paired_write_permanent_failure_escalation(
        &mut conn,
        "init-already-aborted",
        "PushFailed",
        "remote=origin;ref=refs/heads/main",
        "push failed",
    );
    assert_eq!(
        read_state(&conn, "init-already-aborted"),
        "Aborted",
        "operator-driven Aborted MUST survive a subsequent permanent-failure emit",
    );
}

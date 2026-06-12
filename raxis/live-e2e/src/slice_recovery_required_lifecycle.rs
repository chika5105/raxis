//! Live-e2e slice for the initiative recovery boundary.
//!
//! This is intentionally a real persisted-store slice rather than a
//! unit fixture: it applies the current SQLite migrations, seeds the
//! same `LogicalDeadlock` escalation shape the kernel writes, and
//! drives the operator approval/denial SQL contract against the
//! migrated schema. It pins the user-visible rule:
//!
//! * recoverable stalls pause as `RecoveryRequired`
//! * approval resumes `RecoveryRequired -> Executing`
//! * denial closes `RecoveryRequired -> Failed`
//! * terminal `Failed` is not resumable in place

use anyhow::{bail, Context, Result};
use raxis_store::{migration::apply_pending, Table};
use rusqlite::{params, Connection};

pub async fn run() -> Result<()> {
    let tmp = tempfile::tempdir().context("create temp data dir")?;
    let db = tmp.path().join("kernel.db");
    let mut conn = Connection::open(&db).with_context(|| format!("open {}", db.display()))?;
    conn.pragma_update(None, "journal_mode", "WAL")
        .context("enable WAL")?;
    conn.pragma_update(None, "foreign_keys", "ON")
        .context("enable FKs")?;
    apply_pending(&conn).context("apply store migrations")?;

    let approve_id = seed_initiative_with_logical_deadlock(
        &conn,
        "live-recovery-approve",
        "RecoveryRequired",
        None,
        4,
    )?;
    approve_logical_deadlock(&mut conn, &approve_id)?;
    assert_initiative(&conn, "live-recovery-approve", "Executing", Some(0), None)?;

    let deny_id = seed_initiative_with_logical_deadlock(
        &conn,
        "live-recovery-deny",
        "RecoveryRequired",
        None,
        5,
    )?;
    deny_logical_deadlock(&mut conn, &deny_id, "operator chose forensic close")?;
    assert_initiative(&conn, "live-recovery-deny", "Failed", Some(5), Some(true))?;

    let failed_id =
        seed_initiative_with_logical_deadlock(&conn, "live-recovery-failed", "Failed", Some(1), 7)?;
    let transitioned = approve_logical_deadlock(&mut conn, &failed_id)?;
    if transitioned {
        bail!("terminal Failed initiative was resurrected by recovery approval");
    }
    assert_initiative(&conn, "live-recovery-failed", "Failed", Some(7), Some(true))?;
    assert_escalation_status(&conn, &failed_id, "Pending")?;

    tracing::info!(
        "recovery-required lifecycle slice passed: approve resumes, deny closes, Failed stays closed"
    );
    Ok(())
}

fn seed_initiative_with_logical_deadlock(
    conn: &Connection,
    initiative_id: &str,
    state: &str,
    completed_at: Option<i64>,
    counter: i64,
) -> Result<String> {
    let initiatives = Table::Initiatives.as_str();
    let sessions = Table::Sessions.as_str();
    let tasks = Table::Tasks.as_str();
    let escalations = Table::Escalations.as_str();
    let now = raxis_types::unix_now_secs();
    let session_id = format!("sess-{initiative_id}");
    let task_id = format!("task-{initiative_id}");
    let lineage_id = format!("lin-{initiative_id}");

    conn.execute(
        &format!(
            "INSERT INTO {initiatives}
                (initiative_id, state, terminal_criteria_json,
                 plan_artifact_sha256, created_at, completed_at,
                 orchestrator_no_progress_respawn_count)
             VALUES (?1, ?2, '{{}}', '', ?3, ?4, ?5)"
        ),
        params![initiative_id, state, now, completed_at, counter],
    )
    .with_context(|| format!("seed initiative {initiative_id}"))?;

    conn.execute(
        &format!(
            "INSERT INTO {sessions}
                (session_id, role_id, session_token, lineage_id,
                 fetch_quota, created_at, expires_at)
             VALUES (?1, 'Orchestrator', ?2, ?3, 0, ?4, ?5)"
        ),
        params![
            session_id,
            format!("tok-{initiative_id}"),
            lineage_id,
            now,
            now + 3600,
        ],
    )
    .with_context(|| format!("seed session for {initiative_id}"))?;

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
    .with_context(|| format!("seed task for {initiative_id}"))?;

    let escalation_id = uuid::Uuid::new_v4().to_string();
    conn.execute(
        &format!(
            "INSERT INTO {escalations} (
                escalation_id, session_id, task_id, lineage_id, initiative_id,
                class, requested_scope_json, justification, idempotency_key,
                status, created_at, timeout_at, initiator
             ) VALUES (?1, ?2, ?3, ?4, ?5, 'LogicalDeadlock',
                       '{{}}', 'live recovery-required lifecycle slice', ?6,
                       'Pending', ?7, ?8, 'Kernel')"
        ),
        params![
            escalation_id,
            session_id,
            task_id,
            lineage_id,
            initiative_id,
            format!("live-recovery-required:{initiative_id}"),
            now,
            now + 3600,
        ],
    )
    .with_context(|| format!("seed escalation for {initiative_id}"))?;

    Ok(escalation_id)
}

fn approve_logical_deadlock(conn: &mut Connection, escalation_id: &str) -> Result<bool> {
    let escalations = Table::Escalations.as_str();
    let initiatives = Table::Initiatives.as_str();
    let now = raxis_types::unix_now_secs();
    let tx = conn.transaction().context("begin approve tx")?;

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
        .context("pending kernel LogicalDeadlock escalation must exist")?;

    if initiative_state != "RecoveryRequired" {
        tx.commit().context("commit no-op approve tx")?;
        return Ok(false);
    }

    tx.execute(
        &format!(
            "UPDATE {escalations}
                SET status = 'Approved', resolved_at = ?2
              WHERE escalation_id = ?1 AND status = 'Pending'"
        ),
        params![escalation_id, now],
    )
    .context("approve escalation")?;

    tx.execute(
        &format!(
            "UPDATE {initiatives}
                SET orchestrator_no_progress_respawn_count = 0
              WHERE initiative_id = ?1"
        ),
        params![&initiative_id],
    )
    .context("reset no-progress counter")?;

    let rows = tx
        .execute(
            &format!(
                "UPDATE {initiatives}
                    SET state = 'Executing', completed_at = NULL
                  WHERE initiative_id = ?1 AND state = 'RecoveryRequired'"
            ),
            params![&initiative_id],
        )
        .context("resume RecoveryRequired initiative")?;
    tx.commit().context("commit approve tx")?;
    Ok(rows == 1)
}

fn deny_logical_deadlock(conn: &mut Connection, escalation_id: &str, note: &str) -> Result<bool> {
    let escalations = Table::Escalations.as_str();
    let initiatives = Table::Initiatives.as_str();
    let now = raxis_types::unix_now_secs();
    let tx = conn.transaction().context("begin deny tx")?;

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
        .context("pending kernel LogicalDeadlock escalation must exist")?;

    if initiative_state != "RecoveryRequired" {
        tx.commit().context("commit no-op deny tx")?;
        return Ok(false);
    }

    tx.execute(
        &format!(
            "UPDATE {escalations}
                SET status = 'Denied',
                    resolved_at = ?2,
                    resolution_notes = ?3
              WHERE escalation_id = ?1 AND status = 'Pending'"
        ),
        params![escalation_id, now, note],
    )
    .context("deny escalation")?;

    let rows = tx
        .execute(
            &format!(
                "UPDATE {initiatives}
                    SET state = 'Failed', completed_at = ?2
                  WHERE initiative_id = ?1 AND state = 'RecoveryRequired'"
            ),
            params![&initiative_id, now],
        )
        .context("close RecoveryRequired initiative")?;
    tx.commit().context("commit deny tx")?;
    Ok(rows == 1)
}

fn assert_initiative(
    conn: &Connection,
    initiative_id: &str,
    expected_state: &str,
    expected_counter: Option<i64>,
    completed_at_present: Option<bool>,
) -> Result<()> {
    let initiatives = Table::Initiatives.as_str();
    let (state, counter, completed_at): (String, i64, Option<i64>) = conn
        .query_row(
            &format!(
                "SELECT state, orchestrator_no_progress_respawn_count, completed_at
                   FROM {initiatives}
                  WHERE initiative_id = ?1"
            ),
            params![initiative_id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .with_context(|| format!("read initiative {initiative_id}"))?;

    if state != expected_state {
        bail!("initiative {initiative_id} state: expected {expected_state}, got {state}");
    }
    if let Some(expected) = expected_counter {
        if counter != expected {
            bail!("initiative {initiative_id} counter: expected {expected}, got {counter}");
        }
    }
    if let Some(should_be_present) = completed_at_present {
        if completed_at.is_some() != should_be_present {
            bail!(
                "initiative {initiative_id} completed_at presence: expected {should_be_present}, got {:?}",
                completed_at
            );
        }
    }
    Ok(())
}

fn assert_escalation_status(conn: &Connection, escalation_id: &str, expected: &str) -> Result<()> {
    let escalations = Table::Escalations.as_str();
    let status: String = conn
        .query_row(
            &format!("SELECT status FROM {escalations} WHERE escalation_id = ?1"),
            params![escalation_id],
            |r| r.get(0),
        )
        .with_context(|| format!("read escalation {escalation_id} status"))?;
    if status != expected {
        bail!("escalation {escalation_id} status: expected {expected}, got {status}");
    }
    Ok(())
}

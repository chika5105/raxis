//! Escalation-table query catalog (cli-readonly.md §5.4.1
//! `escalations.rs`).
//!
//! Surface:
//!   * [`pending_count`] — `raxis status` "pending escalations" line.
//!   * [`list`] — `raxis escalations` paged + filtered list.

use thiserror::Error;

use crate::ro::RoConn;
use crate::Table;

/// One escalation row in the shape `raxis escalations` needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EscalationRow {
    pub escalation_id:    String,
    pub session_id:       String,
    pub task_id:          String,
    pub lineage_id:       String,
    pub initiative_id:    String,
    pub class:            String,
    pub justification:    String,
    pub idempotency_key:  String,
    pub status:           String,
    pub created_at:       u64,
    pub timeout_at:       u64,
    pub resolved_at:      Option<u64>,
    pub resolution_notes: Option<String>,
}

/// Filter options for [`list`].
///
/// Mirrors the spec's `--status` flag on `raxis escalations`. We
/// model the filter as a Rust enum (not a string) so the CLI parser
/// fails-closed on typos.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EscalationStatusFilter {
    /// All statuses (no `WHERE` predicate).
    All,
    /// Only `Pending` — operator-visible "needs my attention".
    Pending,
    /// Only `Approved` — already resolved positively, may not be
    /// consumed yet.
    Approved,
    /// Only `Denied` — already resolved negatively.
    Denied,
}

impl EscalationStatusFilter {
    /// Wire string used in the SQL `WHERE status = ?`. `None` for
    /// the `All` variant means "no predicate".
    fn as_sql_status(self) -> Option<&'static str> {
        match self {
            Self::All      => None,
            Self::Pending  => Some("Pending"),
            Self::Approved => Some("Approved"),
            Self::Denied   => Some("Denied"),
        }
    }
}

#[derive(Debug, Error)]
pub enum EscalationViewError {
    #[error("sqlite error during escalation view read: {0}")]
    Sqlite(#[from] rusqlite::Error),
}

/// Count rows currently in `Pending` status.
pub fn pending_count(conn: &RoConn) -> Result<u64, EscalationViewError> {
    let n: i64 = conn.query_row(
        &format!(
            "SELECT COUNT(*) FROM {} WHERE status = 'Pending'",
            Table::Escalations.as_str(),
        ),
        [],
        |r| r.get(0),
    )?;
    Ok(n.max(0) as u64)
}

/// List escalations with the chosen filter, newest-first.
pub fn list(
    conn:   &RoConn,
    filter: EscalationStatusFilter,
    limit:  usize,
) -> Result<Vec<EscalationRow>, EscalationViewError> {
    let mut sql = format!(
        "SELECT escalation_id, session_id, task_id, lineage_id, initiative_id, \
                class, justification, idempotency_key, status, \
                created_at, timeout_at, resolved_at, resolution_notes \
         FROM {}",
        Table::Escalations.as_str(),
    );
    if filter.as_sql_status().is_some() {
        sql.push_str(" WHERE status = ?1");
    }
    sql.push_str(" ORDER BY created_at DESC LIMIT ?");
    sql.push_str(if filter.as_sql_status().is_some() { "2" } else { "1" });

    let mut stmt = conn.prepare(&sql)?;
    let limit_i = limit as i64;
    let rows = if let Some(status) = filter.as_sql_status() {
        stmt.query_map(rusqlite::params![status, limit_i], map_row)?
            .collect::<Result<Vec<_>, _>>()?
    } else {
        stmt.query_map(rusqlite::params![limit_i], map_row)?
            .collect::<Result<Vec<_>, _>>()?
    };
    Ok(rows)
}

fn map_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<EscalationRow> {
    Ok(EscalationRow {
        escalation_id:    r.get(0)?,
        session_id:       r.get(1)?,
        task_id:          r.get(2)?,
        lineage_id:       r.get(3)?,
        initiative_id:    r.get(4)?,
        class:            r.get(5)?,
        justification:    r.get(6)?,
        idempotency_key:  r.get(7)?,
        status:           r.get(8)?,
        created_at:       r.get::<_, i64>(9)?.max(0) as u64,
        timeout_at:       r.get::<_, i64>(10)?.max(0) as u64,
        resolved_at:      r.get::<_, Option<i64>>(11)?.map(|v| v.max(0) as u64),
        resolution_notes: r.get(12)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ro::open as open_ro, Store};
    use tempfile::TempDir;

    fn fresh_store_with_seed_escalations() -> TempDir {
        const INITIATIVES: &str = Table::Initiatives.as_str();
        const SESSIONS:    &str = Table::Sessions.as_str();
        const TASKS:       &str = Table::Tasks.as_str();
        const ESCALATIONS: &str = Table::Escalations.as_str();
        let tmp = TempDir::new().unwrap();
        let db = tmp.path().join("kernel.db");
        let store = Store::open(&db).unwrap();
        let guard = store.lock_sync();
        // Seed an initiative + a task + a session so FKs pass.
        guard.execute(
            &format!(
                "INSERT INTO {INITIATIVES} \
                 (initiative_id, state, terminal_criteria_json, plan_artifact_sha256, created_at) \
                 VALUES ('init-1', 'Executing', '{{}}', 'sha-1', 1)"
            ),
            [],
        ).unwrap();
        guard.execute(
            &format!(
                "INSERT INTO {SESSIONS} \
                 (session_id, role_id, session_token, lineage_id, fetch_quota, \
                  created_at, expires_at, revoked) \
                 VALUES ('sess-1', 'planner', 'tok-1', 'lin-1', 0, 1, 9999, 0)"
            ),
            [],
        ).unwrap();
        guard.execute(
            &format!(
                "INSERT INTO {TASKS} \
                 (task_id, initiative_id, lane_id, state, actor, \
                  policy_epoch, admitted_at, transitioned_at) \
                 VALUES ('task-1', 'init-1', 'default', 'Running', 'op', 1, 1, 1)"
            ),
            [],
        ).unwrap();

        // Three escalations — one Pending, one Approved, one Denied.
        for (id, status, created_at, idem) in [
            ("esc-pending",  "Pending",  300_i64, "i-pending"),
            ("esc-approved", "Approved", 200,     "i-approved"),
            ("esc-denied",   "Denied",   100,     "i-denied"),
        ] {
            guard.execute(
                &format!(
                    "INSERT INTO {ESCALATIONS} \
                     (escalation_id, session_id, task_id, lineage_id, initiative_id, \
                      class, requested_scope_json, justification, idempotency_key, \
                      status, created_at, timeout_at) \
                     VALUES (?1, 'sess-1', 'task-1', 'lin-1', 'init-1', \
                             'CapabilityUpgrade', '{{}}', 'why', ?4, \
                             ?2, ?3, ?3 + 3600)"
                ),
                rusqlite::params![id, status, created_at, idem],
            ).unwrap();
        }
        tmp
    }

    #[test]
    fn pending_count_returns_only_pending_rows() {
        let tmp = fresh_store_with_seed_escalations();
        let conn = open_ro(tmp.path()).unwrap();
        assert_eq!(pending_count(&conn).unwrap(), 1);
    }

    #[test]
    fn list_all_returns_every_status_newest_first() {
        let tmp = fresh_store_with_seed_escalations();
        let conn = open_ro(tmp.path()).unwrap();
        let rows = list(&conn, EscalationStatusFilter::All, 10).unwrap();
        let ids: Vec<&str> = rows.iter().map(|r| r.escalation_id.as_str()).collect();
        assert_eq!(ids, vec!["esc-pending", "esc-approved", "esc-denied"]);
    }

    #[test]
    fn list_pending_excludes_resolved_rows() {
        let tmp = fresh_store_with_seed_escalations();
        let conn = open_ro(tmp.path()).unwrap();
        let rows = list(&conn, EscalationStatusFilter::Pending, 10).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].escalation_id, "esc-pending");
        assert_eq!(rows[0].status, "Pending");
    }

    #[test]
    fn list_approved_returns_only_approved() {
        let tmp = fresh_store_with_seed_escalations();
        let conn = open_ro(tmp.path()).unwrap();
        let rows = list(&conn, EscalationStatusFilter::Approved, 10).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].status, "Approved");
    }

    #[test]
    fn list_denied_returns_only_denied() {
        let tmp = fresh_store_with_seed_escalations();
        let conn = open_ro(tmp.path()).unwrap();
        let rows = list(&conn, EscalationStatusFilter::Denied, 10).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].status, "Denied");
    }

    #[test]
    fn list_respects_limit() {
        let tmp = fresh_store_with_seed_escalations();
        let conn = open_ro(tmp.path()).unwrap();
        let rows = list(&conn, EscalationStatusFilter::All, 2).unwrap();
        assert_eq!(rows.len(), 2);
    }
}

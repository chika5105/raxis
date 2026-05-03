//! Initiative-table query catalog (cli-readonly.md §5.4.1
//! `initiatives.rs`).
//!
//! Surface:
//!   * [`counts_by_state`] — the second block of `raxis status`.
//!   * [`by_id`] — `raxis inspect <initiative_id>`.
//!   * [`list`] — paged list with optional state filter.

use rusqlite::OptionalExtension;
use thiserror::Error;

use crate::ro::RoConn;
use crate::Table;

/// One initiative row in the shape `inspect` and `list` need. Fields
/// 1:1 with the `initiatives` DDL (kernel-store.md §2.5.1 Table 2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InitiativeRow {
    pub initiative_id:           String,
    pub state:                   String,
    pub plan_artifact_sha256:    String,
    pub created_at:              u64,
    pub approved_at:             Option<u64>,
    pub completed_at:            Option<u64>,
}

/// Per-state row count. All seven FSM states from kernel-store.md
/// §2.5.1 Table 2 + a `total` aggregate.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
pub struct InitiativeStateCounts {
    pub draft:         u64,
    pub approved_plan: u64,
    pub executing:     u64,
    pub blocked:       u64,
    pub completed:     u64,
    pub failed:        u64,
    pub aborted:       u64,
    pub total:         u64,
}

#[derive(Debug, Error)]
pub enum InitiativeViewError {
    #[error("sqlite error during initiative view read: {0}")]
    Sqlite(#[from] rusqlite::Error),
}

/// One-shot per-state row counter for `initiatives`.
pub fn counts_by_state(conn: &RoConn) -> Result<InitiativeStateCounts, InitiativeViewError> {
    let mut counts = InitiativeStateCounts::default();
    let mut stmt = conn.prepare(&format!(
        "SELECT state, COUNT(*) FROM {} GROUP BY state",
        Table::Initiatives.as_str(),
    ))?;
    let rows = stmt.query_map([], |r| {
        Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?))
    })?;

    for row in rows {
        let (state, count) = row?;
        let n = count.max(0) as u64;
        match state.as_str() {
            "Draft"        => counts.draft = n,
            "ApprovedPlan" => counts.approved_plan = n,
            "Executing"    => counts.executing = n,
            "Blocked"      => counts.blocked = n,
            "Completed"    => counts.completed = n,
            "Failed"       => counts.failed = n,
            "Aborted"      => counts.aborted = n,
            // Future states migrate gracefully — see tasks.rs note.
            _ => {}
        }
        counts.total = counts.total.saturating_add(n);
    }
    Ok(counts)
}

/// Look up a single initiative by id. Returns `None` when missing.
pub fn by_id(conn: &RoConn, initiative_id: &str) -> Result<Option<InitiativeRow>, InitiativeViewError> {
    let row = conn.query_row(
        &format!(
            "SELECT initiative_id, state, plan_artifact_sha256, \
                    created_at, approved_at, completed_at \
             FROM {} WHERE initiative_id = ?1",
            Table::Initiatives.as_str(),
        ),
        rusqlite::params![initiative_id],
        |r| Ok(InitiativeRow {
            initiative_id:        r.get(0)?,
            state:                r.get(1)?,
            plan_artifact_sha256: r.get(2)?,
            created_at:           r.get::<_, i64>(3)?.max(0) as u64,
            approved_at:          r.get::<_, Option<i64>>(4)?.map(|v| v.max(0) as u64),
            completed_at:         r.get::<_, Option<i64>>(5)?.map(|v| v.max(0) as u64),
        }),
    ).optional()?;
    Ok(row)
}

/// List initiatives. When `state_filter` is `Some`, restrict to that
/// state. Ordered by `created_at DESC` so the newest initiative
/// appears first in CLI output (operators almost always want "what's
/// been kicked off lately").
pub fn list(
    conn: &RoConn,
    state_filter: Option<&str>,
    limit: usize,
) -> Result<Vec<InitiativeRow>, InitiativeViewError> {
    let mut sql = format!(
        "SELECT initiative_id, state, plan_artifact_sha256, \
                created_at, approved_at, completed_at \
         FROM {}",
        Table::Initiatives.as_str(),
    );
    if state_filter.is_some() {
        sql.push_str(" WHERE state = ?1");
    }
    sql.push_str(" ORDER BY created_at DESC LIMIT ?");
    sql.push_str(if state_filter.is_some() { "2" } else { "1" });

    let mut stmt = conn.prepare(&sql)?;
    let limit_i = limit as i64;
    let rows = if let Some(state) = state_filter {
        stmt.query_map(rusqlite::params![state, limit_i], map_row)?
            .collect::<Result<Vec<_>, _>>()?
    } else {
        stmt.query_map(rusqlite::params![limit_i], map_row)?
            .collect::<Result<Vec<_>, _>>()?
    };
    Ok(rows)
}

fn map_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<InitiativeRow> {
    Ok(InitiativeRow {
        initiative_id:        r.get(0)?,
        state:                r.get(1)?,
        plan_artifact_sha256: r.get(2)?,
        created_at:           r.get::<_, i64>(3)?.max(0) as u64,
        approved_at:          r.get::<_, Option<i64>>(4)?.map(|v| v.max(0) as u64),
        completed_at:         r.get::<_, Option<i64>>(5)?.map(|v| v.max(0) as u64),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ro::open as open_ro, Store};
    use tempfile::TempDir;

    fn fresh_store_with_seed() -> TempDir {
        let tmp = TempDir::new().unwrap();
        let db = tmp.path().join("kernel.db");
        let store = Store::open(&db).unwrap();
        let guard = store.lock_sync();
        for (id, state, created) in [
            ("init-old",   "Completed",    100_i64),
            ("init-mid",   "Executing",    200),
            ("init-fresh", "Draft",        300),
            ("init-fail",  "Failed",       150),
            ("init-other", "Executing",    250),
        ] {
            guard.execute(
                "INSERT INTO initiatives \
                 (initiative_id, state, terminal_criteria_json, plan_artifact_sha256, created_at) \
                 VALUES (?1, ?2, '{}', 'sha-' || ?1, ?3)",
                rusqlite::params![id, state, created],
            ).unwrap();
        }
        tmp
    }

    #[test]
    fn counts_by_state_aggregates_each_label_independently() {
        let tmp = fresh_store_with_seed();
        let conn = open_ro(tmp.path()).unwrap();
        let counts = counts_by_state(&conn).unwrap();
        assert_eq!(counts.executing, 2);
        assert_eq!(counts.draft, 1);
        assert_eq!(counts.completed, 1);
        assert_eq!(counts.failed, 1);
        assert_eq!(counts.total, 5);
        assert_eq!(counts.aborted, 0);
    }

    #[test]
    fn by_id_returns_none_for_missing_initiative() {
        let tmp = fresh_store_with_seed();
        let conn = open_ro(tmp.path()).unwrap();
        assert!(by_id(&conn, "nope").unwrap().is_none());
    }

    #[test]
    fn by_id_returns_initiative_with_correct_fields() {
        let tmp = fresh_store_with_seed();
        let conn = open_ro(tmp.path()).unwrap();
        let row = by_id(&conn, "init-fresh").unwrap().expect("present");
        assert_eq!(row.state, "Draft");
        assert_eq!(row.created_at, 300);
        assert_eq!(row.completed_at, None);
    }

    #[test]
    fn list_orders_by_created_at_descending() {
        let tmp = fresh_store_with_seed();
        let conn = open_ro(tmp.path()).unwrap();
        let rows = list(&conn, None, 10).unwrap();
        let ids: Vec<&str> = rows.iter().map(|r| r.initiative_id.as_str()).collect();
        assert_eq!(ids, vec!["init-fresh", "init-other", "init-mid", "init-fail", "init-old"]);
    }

    #[test]
    fn list_filters_by_state_when_requested() {
        let tmp = fresh_store_with_seed();
        let conn = open_ro(tmp.path()).unwrap();
        let rows = list(&conn, Some("Executing"), 10).unwrap();
        assert_eq!(rows.len(), 2);
        // Newest-first inside the filter too.
        assert_eq!(rows[0].initiative_id, "init-other");
        assert_eq!(rows[1].initiative_id, "init-mid");
    }
}

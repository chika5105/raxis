//! Notification-table query catalog.
//!
//! Read surfaces for the kernel-owned `notifications` table
//! (migration 14). All functions take `&RoConn` except
//! `mark_read` and `mark_all_read` which require a write
//! connection (`&rusqlite::Connection`) since they mutate rows.
//!
//! Surface:
//!   * [`unread_count`] — badge count for dashboard / CLI.
//!   * [`list_unread`] — unread notifications, newest first.
//!   * [`list_all`]    — all notifications, optional initiative filter.
//!   * [`mark_read`]   — set `read = 1` for a single notification.
//!   * [`mark_all_read`] — set `read = 1` for all unread rows.

use thiserror::Error;

use crate::ro::RoConn;
use crate::Table;

/// One notification row in the shape the dashboard / CLI needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotificationRow {
    pub notification_id: String,
    pub event_kind:      String,
    pub initiative_id:   Option<String>,
    pub task_id:         Option<String>,
    pub session_id:      Option<String>,
    pub summary:         String,
    pub payload_json:    String,
    pub read:            bool,
    pub source_event_id: String,
    pub created_at:      u64,
}

#[derive(Debug, Error)]
pub enum NotificationViewError {
    #[error("sqlite error during notification view read: {0}")]
    Sqlite(#[from] rusqlite::Error),
}

/// Count unread notifications.
pub fn unread_count(conn: &RoConn) -> Result<u64, NotificationViewError> {
    let n: i64 = conn.query_row(
        &format!(
            "SELECT COUNT(*) FROM {} WHERE read = 0",
            Table::Notifications.as_str(),
        ),
        [],
        |r| r.get(0),
    )?;
    Ok(n.max(0) as u64)
}

/// List unread notifications, newest first, capped at `limit`.
pub fn list_unread(
    conn:  &RoConn,
    limit: usize,
) -> Result<Vec<NotificationRow>, NotificationViewError> {
    let sql = format!(
        "SELECT notification_id, event_kind, initiative_id, task_id, \
                session_id, summary, payload_json, read, source_event_id, \
                created_at \
         FROM {} \
         WHERE read = 0 \
         ORDER BY created_at DESC \
         LIMIT ?1",
        Table::Notifications.as_str(),
    );
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt
        .query_map(rusqlite::params![limit as i64], map_row)?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

/// List all notifications, newest first, capped at `limit`.
/// Optionally filter by `initiative_id`.
pub fn list_all(
    conn:          &RoConn,
    limit:         usize,
    initiative_id: Option<&str>,
) -> Result<Vec<NotificationRow>, NotificationViewError> {
    let (sql, has_filter) = if initiative_id.is_some() {
        (
            format!(
                "SELECT notification_id, event_kind, initiative_id, task_id, \
                        session_id, summary, payload_json, read, source_event_id, \
                        created_at \
                 FROM {} \
                 WHERE initiative_id = ?1 \
                 ORDER BY created_at DESC \
                 LIMIT ?2",
                Table::Notifications.as_str(),
            ),
            true,
        )
    } else {
        (
            format!(
                "SELECT notification_id, event_kind, initiative_id, task_id, \
                        session_id, summary, payload_json, read, source_event_id, \
                        created_at \
                 FROM {} \
                 ORDER BY created_at DESC \
                 LIMIT ?1",
                Table::Notifications.as_str(),
            ),
            false,
        )
    };
    let mut stmt = conn.prepare(&sql)?;
    let rows = if has_filter {
        stmt.query_map(
            rusqlite::params![initiative_id.unwrap_or(""), limit as i64],
            map_row,
        )?
        .collect::<Result<Vec<_>, _>>()?
    } else {
        stmt.query_map(rusqlite::params![limit as i64], map_row)?
            .collect::<Result<Vec<_>, _>>()?
    };
    Ok(rows)
}

/// Mark a single notification as read. Returns `true` if a row
/// was actually updated (i.e. the notification existed and was
/// previously unread). Idempotent — calling twice on the same
/// row is a no-op.
///
/// Takes a raw `&rusqlite::Connection` because this is a write
/// operation. Callers MUST wrap this in a `BEGIN IMMEDIATE`
/// transaction if they need atomicity with other writes.
pub fn mark_read(
    conn:            &rusqlite::Connection,
    notification_id: &str,
) -> Result<bool, NotificationViewError> {
    let n = conn.execute(
        &format!(
            "UPDATE {} SET read = 1 WHERE notification_id = ?1 AND read = 0",
            Table::Notifications.as_str(),
        ),
        rusqlite::params![notification_id],
    )?;
    Ok(n > 0)
}

/// Mark ALL unread notifications as read. Returns the number of
/// rows updated.
pub fn mark_all_read(
    conn: &rusqlite::Connection,
) -> Result<u64, NotificationViewError> {
    let n = conn.execute(
        &format!(
            "UPDATE {} SET read = 1 WHERE read = 0",
            Table::Notifications.as_str(),
        ),
        [],
    )?;
    Ok(n as u64)
}

fn map_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<NotificationRow> {
    Ok(NotificationRow {
        notification_id: r.get(0)?,
        event_kind:      r.get(1)?,
        initiative_id:   r.get(2)?,
        task_id:         r.get(3)?,
        session_id:      r.get(4)?,
        summary:         r.get(5)?,
        payload_json:    r.get(6)?,
        read:            r.get::<_, i64>(7)? != 0,
        source_event_id: r.get(8)?,
        created_at:      r.get::<_, i64>(9)?.max(0) as u64,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ro::open as open_ro, Store};
    use tempfile::TempDir;

    fn fresh_store_with_notifications() -> TempDir {
        let tmp = TempDir::new().unwrap();
        let db = tmp.path().join("kernel.db");
        let store = Store::open(&db).unwrap();
        let guard = store.lock_sync();

        // Seed three notifications — two unread, one read.
        for (id, kind, init, read, ts) in [
            ("n-1", "EscalationPending",   Some("init-1"), 0, 300_i64),
            ("n-2", "PolicyEpochAdvanced", None,           0, 200),
            ("n-3", "EscalationApproved",  Some("init-1"), 1, 100),
        ] {
            guard.execute(
                &format!(
                    "INSERT INTO {} \
                     (notification_id, event_kind, initiative_id, task_id, \
                      session_id, summary, payload_json, read, source_event_id, created_at) \
                     VALUES (?1, ?2, ?3, NULL, NULL, ?2, '{{}}', ?4, 'evt-1', ?5)",
                    Table::Notifications.as_str(),
                ),
                rusqlite::params![id, kind, init, read, ts],
            ).unwrap();
        }
        tmp
    }

    #[test]
    fn unread_count_returns_only_unread() {
        let tmp = fresh_store_with_notifications();
        let conn = open_ro(tmp.path()).unwrap();
        assert_eq!(unread_count(&conn).unwrap(), 2);
    }

    #[test]
    fn list_unread_returns_newest_first() {
        let tmp = fresh_store_with_notifications();
        let conn = open_ro(tmp.path()).unwrap();
        let rows = list_unread(&conn, 10).unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].notification_id, "n-1");
        assert_eq!(rows[1].notification_id, "n-2");
        assert!(rows.iter().all(|r| !r.read));
    }

    #[test]
    fn list_all_returns_every_row() {
        let tmp = fresh_store_with_notifications();
        let conn = open_ro(tmp.path()).unwrap();
        let rows = list_all(&conn, 10, None).unwrap();
        assert_eq!(rows.len(), 3);
    }

    #[test]
    fn list_all_filters_by_initiative() {
        let tmp = fresh_store_with_notifications();
        let conn = open_ro(tmp.path()).unwrap();
        let rows = list_all(&conn, 10, Some("init-1")).unwrap();
        assert_eq!(rows.len(), 2);
        assert!(rows.iter().all(|r| r.initiative_id.as_deref() == Some("init-1")));
    }

    #[test]
    fn list_all_respects_limit() {
        let tmp = fresh_store_with_notifications();
        let conn = open_ro(tmp.path()).unwrap();
        let rows = list_all(&conn, 1, None).unwrap();
        assert_eq!(rows.len(), 1);
    }

    #[test]
    fn mark_read_updates_unread_row() {
        let tmp = fresh_store_with_notifications();
        let db = tmp.path().join("kernel.db");
        let store = Store::open(&db).unwrap();
        let guard = store.lock_sync();
        assert!(mark_read(&guard, "n-1").unwrap());

        let conn = open_ro(tmp.path()).unwrap();
        assert_eq!(unread_count(&conn).unwrap(), 1);
    }

    #[test]
    fn mark_read_is_idempotent() {
        let tmp = fresh_store_with_notifications();
        let db = tmp.path().join("kernel.db");
        let store = Store::open(&db).unwrap();
        let guard = store.lock_sync();
        // n-3 is already read.
        assert!(!mark_read(&guard, "n-3").unwrap());
    }

    #[test]
    fn mark_read_returns_false_for_unknown_id() {
        let tmp = fresh_store_with_notifications();
        let db = tmp.path().join("kernel.db");
        let store = Store::open(&db).unwrap();
        let guard = store.lock_sync();
        assert!(!mark_read(&guard, "n-nonexistent").unwrap());
    }

    #[test]
    fn mark_all_read_clears_all_unread() {
        let tmp = fresh_store_with_notifications();
        let db = tmp.path().join("kernel.db");
        let store = Store::open(&db).unwrap();
        let guard = store.lock_sync();
        let n = mark_all_read(&guard).unwrap();
        assert_eq!(n, 2);

        let conn = open_ro(tmp.path()).unwrap();
        assert_eq!(unread_count(&conn).unwrap(), 0);
    }
}

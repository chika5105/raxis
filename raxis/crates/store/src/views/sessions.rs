//! Session-table query catalog (cli-readonly.md §5.4.1 `sessions.rs`).
//!
//! Surface:
//!   * [`active_counts`] — Active vs Revoked vs Expired count for the
//!     `raxis status` workload-summary block.
//!   * [`active_list`] — `raxis sessions` paged list.
//!
//! Note: the kernel does not maintain a per-channel
//! (planner / gateway / verifier) session-type tag in v1 — every row
//! shares the same `sessions` table. The CLI-spec `active_planner_sessions`
//! / `active_gateway_sessions` heartbeat fields are best-effort and
//! published from the kernel's in-memory IPC accept loops; the SQL
//! view here only knows "active vs not".

use std::time::{SystemTime, UNIX_EPOCH};

use thiserror::Error;

use crate::ro::RoConn;
use crate::Table;

/// One session row in the shape `raxis sessions` needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionRow {
    pub session_id:      String,
    pub role_id:         String,
    pub lineage_id:      String,
    pub worktree_root:   Option<String>,
    pub sequence_number: u64,
    pub created_at:      u64,
    pub expires_at:      u64,
    pub revoked:         bool,
    pub revoked_at:      Option<u64>,
}

/// Three-bucket projection of all session rows.
///
/// `active = revoked == 0 AND expires_at > now`,
/// `expired = revoked == 0 AND expires_at <= now`,
/// `revoked = revoked == 1`.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
pub struct SessionStateCounts {
    pub active:  u64,
    pub expired: u64,
    pub revoked: u64,
    pub total:   u64,
}

#[derive(Debug, Error)]
pub enum SessionViewError {
    #[error("sqlite error during session view read: {0}")]
    Sqlite(#[from] rusqlite::Error),
}

/// Count sessions split into active / expired / revoked using `now`
/// as the cut-off. `now` is a parameter (not `SystemTime::now()`
/// internal) so tests can drive the function deterministically.
pub fn active_counts_at(conn: &RoConn, now_secs: u64) -> Result<SessionStateCounts, SessionViewError> {
    let mut counts = SessionStateCounts::default();
    let now_i = now_secs.min(i64::MAX as u64) as i64;

    // One scan with a CASE to bucket; faster than three separate
    // queries on any v1 table size.
    let mut stmt = conn.prepare(&format!(
        "SELECT \
            CASE \
                WHEN revoked = 1 THEN 'revoked' \
                WHEN expires_at <= ?1 THEN 'expired' \
                ELSE 'active' \
            END AS bucket, \
            COUNT(*) \
         FROM {} GROUP BY bucket",
        Table::Sessions.as_str(),
    ))?;
    let rows = stmt.query_map(rusqlite::params![now_i], |r| {
        Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?))
    })?;
    for row in rows {
        let (bucket, count) = row?;
        let n = count.max(0) as u64;
        match bucket.as_str() {
            "active"  => counts.active = n,
            "expired" => counts.expired = n,
            "revoked" => counts.revoked = n,
            _ => {}
        }
        counts.total = counts.total.saturating_add(n);
    }
    Ok(counts)
}

/// Convenience wrapper that uses the host `SystemTime`. Tests that
/// need determinism call [`active_counts_at`] directly.
pub fn active_counts(conn: &RoConn) -> Result<SessionStateCounts, SessionViewError> {
    active_counts_at(conn, unix_now_secs())
}

/// List currently-active sessions, ordered newest-first.
///
/// Active = `revoked == 0 AND expires_at > now`. The CLI uses this
/// for the `raxis sessions` table; revoked / expired rows are
/// excluded because they are not actionable.
pub fn active_list(conn: &RoConn, limit: usize) -> Result<Vec<SessionRow>, SessionViewError> {
    let now_i = unix_now_secs().min(i64::MAX as u64) as i64;
    let mut stmt = conn.prepare(&format!(
        "SELECT session_id, role_id, lineage_id, worktree_root, \
                sequence_number, created_at, expires_at, revoked, revoked_at \
         FROM {} \
         WHERE revoked = 0 AND expires_at > ?1 \
         ORDER BY created_at DESC LIMIT ?2",
        Table::Sessions.as_str(),
    ))?;
    let rows = stmt.query_map(
        rusqlite::params![now_i, limit as i64],
        |r| Ok(SessionRow {
            session_id:      r.get(0)?,
            role_id:         r.get(1)?,
            lineage_id:      r.get(2)?,
            worktree_root:   r.get(3)?,
            sequence_number: r.get::<_, i64>(4)?.max(0) as u64,
            created_at:      r.get::<_, i64>(5)?.max(0) as u64,
            expires_at:      r.get::<_, i64>(6)?.max(0) as u64,
            revoked:         r.get::<_, i64>(7)? != 0,
            revoked_at:      r.get::<_, Option<i64>>(8)?.map(|v| v.max(0) as u64),
        }),
    )?.collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

fn unix_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ro::open as open_ro, Store};
    use tempfile::TempDir;

    /// Three sessions: active, expired (in the past), revoked. Each
    /// is created with explicit timestamps so the test does not race
    /// the wall clock.
    fn fresh_store_with_seed_sessions() -> TempDir {
        const SESSIONS: &str = Table::Sessions.as_str();
        let tmp = TempDir::new().unwrap();
        let db = tmp.path().join("kernel.db");
        let store = Store::open(&db).unwrap();
        let guard = store.lock_sync();
        // SQLite does not accept Rust-style `_` digit separators
        // inside numeric literals (`9_999_999_999` parses as a token,
        // not an integer); spell out big numbers instead.
        guard.execute(
            &format!(
                "INSERT INTO {SESSIONS} \
                 (session_id, role_id, session_token, lineage_id, fetch_quota, \
                  created_at, expires_at, revoked) \
                 VALUES \
                 ('s-active',  'planner', 'tok-a', 'lin', 0, 100, 9999999999, 0), \
                 ('s-expired', 'planner', 'tok-e', 'lin', 0, 100, 200,        0), \
                 ('s-revoked', 'planner', 'tok-r', 'lin', 0, 100, 9999999999, 1)"
            ),
            [],
        ).unwrap();
        guard.execute(
            &format!("UPDATE {SESSIONS} SET revoked_at = 150 WHERE session_id = 's-revoked'"),
            [],
        ).unwrap();
        tmp
    }

    #[test]
    fn active_counts_at_buckets_each_session_correctly() {
        let tmp = fresh_store_with_seed_sessions();
        let conn = open_ro(tmp.path()).unwrap();
        let counts = active_counts_at(&conn, 500).unwrap();
        assert_eq!(counts.active, 1);
        assert_eq!(counts.expired, 1);
        assert_eq!(counts.revoked, 1);
        assert_eq!(counts.total, 3);
    }

    #[test]
    fn active_list_excludes_expired_and_revoked() {
        let tmp = fresh_store_with_seed_sessions();
        let conn = open_ro(tmp.path()).unwrap();
        let rows = active_list(&conn, 10).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].session_id, "s-active");
        assert!(!rows[0].revoked);
    }
}

//! Persistent metadata for operator-adopted source repositories.
//!
//! The managed repository row is the durable boundary between "a directory
//! Git can open" and "a repository RAXIS is allowed to treat as governed
//! source". Directory scanning may be used as a legacy fallback, but the
//! authoritative path is `raxis repo adopt` -> this table.

use std::path::Path;

use rusqlite::{params, Connection, OptionalExtension};

use crate::Table;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedRepositoryRow {
    pub repository_id: String,
    pub managed_path: String,
    pub source_url: Option<String>,
    pub default_remote: Option<String>,
    pub default_target_ref: String,
    pub tracking_ref: Option<String>,
    pub lifecycle_state: String,
    pub publish_state: String,
    pub head_sha: Option<String>,
    pub remote_sha: Option<String>,
    pub ahead_count: Option<i64>,
    pub behind_count: Option<i64>,
    pub dirty: bool,
    pub last_fetch_at: Option<i64>,
    pub last_push_at: Option<i64>,
    pub last_status_at: Option<i64>,
    pub last_error: Option<String>,
    pub adopted_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone)]
pub struct UpsertManagedRepository<'a> {
    pub repository_id: &'a str,
    pub managed_path: &'a Path,
    pub source_url: Option<&'a str>,
    pub default_remote: Option<&'a str>,
    pub default_target_ref: &'a str,
    pub tracking_ref: Option<&'a str>,
    pub lifecycle_state: &'a str,
    pub publish_state: &'a str,
    pub head_sha: Option<&'a str>,
    pub remote_sha: Option<&'a str>,
    pub ahead_count: Option<i64>,
    pub behind_count: Option<i64>,
    pub dirty: bool,
    pub last_error: Option<&'a str>,
}

#[derive(Debug, Clone)]
pub struct RepositoryStatusUpdate<'a> {
    pub repository_id: &'a str,
    pub lifecycle_state: &'a str,
    pub publish_state: Option<&'a str>,
    pub head_sha: Option<&'a str>,
    pub remote_sha: Option<&'a str>,
    pub ahead_count: Option<i64>,
    pub behind_count: Option<i64>,
    pub dirty: bool,
    pub fetched: bool,
    pub last_error: Option<&'a str>,
}

pub const STATE_UNKNOWN: &str = "unknown";
pub const STATE_CLEAN: &str = "clean";
pub const STATE_DIRTY: &str = "dirty";
pub const STATE_AHEAD: &str = "ahead";
pub const STATE_BEHIND: &str = "behind";
pub const STATE_DIVERGED: &str = "diverged";
pub const STATE_LOCAL_ONLY: &str = "local_only";
pub const STATE_REMOTE_UNREACHABLE: &str = "remote_unreachable";
pub const STATE_MISSING: &str = "missing";
pub const STATE_NOT_A_GIT_ROOT: &str = "not_a_git_root";

pub const PUBLISH_UNKNOWN: &str = "unknown";
pub const PUBLISH_LOCAL_ONLY: &str = "local_only";
pub const PUBLISH_PENDING: &str = "pending";
pub const PUBLISH_PUBLISHED: &str = "published";
pub const PUBLISH_FAILED: &str = "failed";

const TABLE: &str = Table::ManagedRepositories.as_str();

pub fn upsert(conn: &Connection, row: &UpsertManagedRepository<'_>) -> rusqlite::Result<()> {
    conn.execute(
        &format!(
            "INSERT INTO {TABLE} (
                repository_id, managed_path, source_url, default_remote,
                default_target_ref, tracking_ref, lifecycle_state, publish_state,
                head_sha, remote_sha, ahead_count, behind_count, dirty,
                last_status_at, last_error, adopted_at, updated_at
             )
             VALUES (
                ?1, ?2, ?3, ?4,
                ?5, ?6, ?7, ?8,
                ?9, ?10, ?11, ?12, ?13,
                strftime('%s','now'), ?14, strftime('%s','now'), strftime('%s','now')
             )
             ON CONFLICT(repository_id) DO UPDATE SET
                managed_path = excluded.managed_path,
                source_url = excluded.source_url,
                default_remote = excluded.default_remote,
                default_target_ref = excluded.default_target_ref,
                tracking_ref = excluded.tracking_ref,
                lifecycle_state = excluded.lifecycle_state,
                publish_state = excluded.publish_state,
                head_sha = excluded.head_sha,
                remote_sha = excluded.remote_sha,
                ahead_count = excluded.ahead_count,
                behind_count = excluded.behind_count,
                dirty = excluded.dirty,
                last_status_at = excluded.last_status_at,
                last_error = excluded.last_error,
                updated_at = excluded.updated_at"
        ),
        params![
            row.repository_id,
            row.managed_path.display().to_string(),
            row.source_url,
            row.default_remote,
            row.default_target_ref,
            row.tracking_ref,
            row.lifecycle_state,
            row.publish_state,
            row.head_sha,
            row.remote_sha,
            row.ahead_count,
            row.behind_count,
            if row.dirty { 1 } else { 0 },
            row.last_error,
        ],
    )?;
    Ok(())
}

pub fn list(conn: &Connection) -> rusqlite::Result<Vec<ManagedRepositoryRow>> {
    let mut stmt = conn.prepare(&format!(
        "SELECT repository_id, managed_path, source_url, default_remote,
                default_target_ref, tracking_ref, lifecycle_state, publish_state,
                head_sha, remote_sha, ahead_count, behind_count, dirty,
                last_fetch_at, last_push_at, last_status_at, last_error,
                adopted_at, updated_at
           FROM {TABLE}
          ORDER BY repository_id ASC"
    ))?;
    let rows = stmt.query_map([], row_from)?;
    rows.collect()
}

pub fn by_id(
    conn: &Connection,
    repository_id: &str,
) -> rusqlite::Result<Option<ManagedRepositoryRow>> {
    conn.query_row(
        &format!(
            "SELECT repository_id, managed_path, source_url, default_remote,
                    default_target_ref, tracking_ref, lifecycle_state, publish_state,
                    head_sha, remote_sha, ahead_count, behind_count, dirty,
                    last_fetch_at, last_push_at, last_status_at, last_error,
                    adopted_at, updated_at
               FROM {TABLE}
              WHERE repository_id = ?1"
        ),
        [repository_id],
        row_from,
    )
    .optional()
}

pub fn record_status(
    conn: &Connection,
    update: &RepositoryStatusUpdate<'_>,
) -> rusqlite::Result<usize> {
    conn.execute(
        &format!(
            "UPDATE {TABLE}
                SET lifecycle_state = ?2,
                    publish_state = COALESCE(?3, publish_state),
                    head_sha = ?4,
                    remote_sha = ?5,
                    ahead_count = ?6,
                    behind_count = ?7,
                    dirty = ?8,
                    last_fetch_at = CASE WHEN ?9 THEN strftime('%s','now') ELSE last_fetch_at END,
                    last_status_at = strftime('%s','now'),
                    last_error = ?10,
                    updated_at = strftime('%s','now')
              WHERE repository_id = ?1"
        ),
        params![
            update.repository_id,
            update.lifecycle_state,
            update.publish_state,
            update.head_sha,
            update.remote_sha,
            update.ahead_count,
            update.behind_count,
            if update.dirty { 1 } else { 0 },
            update.fetched,
            update.last_error,
        ],
    )
}

pub fn record_publish_pending(
    conn: &Connection,
    repository_id: &str,
    head_sha: Option<&str>,
) -> rusqlite::Result<usize> {
    conn.execute(
        &format!(
            "UPDATE {TABLE}
                SET publish_state = ?2,
                    head_sha = COALESCE(?3, head_sha),
                    last_error = NULL,
                    updated_at = strftime('%s','now')
              WHERE repository_id = ?1"
        ),
        params![repository_id, PUBLISH_PENDING, head_sha],
    )
}

pub fn record_publish_success(
    conn: &Connection,
    repository_id: &str,
    head_sha: Option<&str>,
) -> rusqlite::Result<usize> {
    conn.execute(
        &format!(
            "UPDATE {TABLE}
                SET publish_state = ?2,
                    head_sha = COALESCE(?3, head_sha),
                    last_push_at = strftime('%s','now'),
                    last_status_at = strftime('%s','now'),
                    last_error = NULL,
                    updated_at = strftime('%s','now')
              WHERE repository_id = ?1"
        ),
        params![repository_id, PUBLISH_PUBLISHED, head_sha],
    )
}

pub fn record_publish_failure(
    conn: &Connection,
    repository_id: &str,
    head_sha: Option<&str>,
    reason: &str,
) -> rusqlite::Result<usize> {
    conn.execute(
        &format!(
            "UPDATE {TABLE}
                SET publish_state = ?2,
                    head_sha = COALESCE(?3, head_sha),
                    last_status_at = strftime('%s','now'),
                    last_error = ?4,
                    updated_at = strftime('%s','now')
              WHERE repository_id = ?1"
        ),
        params![repository_id, PUBLISH_FAILED, head_sha, reason],
    )
}

fn row_from(row: &rusqlite::Row<'_>) -> rusqlite::Result<ManagedRepositoryRow> {
    Ok(ManagedRepositoryRow {
        repository_id: row.get(0)?,
        managed_path: row.get(1)?,
        source_url: row.get(2)?,
        default_remote: row.get(3)?,
        default_target_ref: row.get(4)?,
        tracking_ref: row.get(5)?,
        lifecycle_state: row.get(6)?,
        publish_state: row.get(7)?,
        head_sha: row.get(8)?,
        remote_sha: row.get(9)?,
        ahead_count: row.get(10)?,
        behind_count: row.get(11)?,
        dirty: row.get::<_, i64>(12)? != 0,
        last_fetch_at: row.get(13)?,
        last_push_at: row.get(14)?,
        last_status_at: row.get(15)?,
        last_error: row.get(16)?,
        adopted_at: row.get(17)?,
        updated_at: row.get(18)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Store;

    #[test]
    fn adopted_repo_round_trips() {
        let store = Store::open_in_memory().unwrap();
        let conn = store.lock_sync();
        upsert(
            &conn,
            &UpsertManagedRepository {
                repository_id: "gtm",
                managed_path: Path::new("/tmp/raxis/repositories/gtm"),
                source_url: Some("git@example.com:org/gtm.git"),
                default_remote: Some("origin"),
                default_target_ref: "refs/heads/main",
                tracking_ref: Some("refs/remotes/origin/main"),
                lifecycle_state: STATE_CLEAN,
                publish_state: PUBLISH_PUBLISHED,
                head_sha: Some("a"),
                remote_sha: Some("a"),
                ahead_count: Some(0),
                behind_count: Some(0),
                dirty: false,
                last_error: None,
            },
        )
        .unwrap();

        let row = by_id(&conn, "gtm").unwrap().unwrap();
        assert_eq!(row.repository_id, "gtm");
        assert_eq!(row.lifecycle_state, STATE_CLEAN);
        assert_eq!(row.publish_state, PUBLISH_PUBLISHED);
    }
}

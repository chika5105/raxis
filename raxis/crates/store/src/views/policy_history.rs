//! Policy-epoch-history queries (cli-readonly.md §5.4.1 — implied by
//! `raxis policy show` / `raxis policy diff`).
//!
//! Exposes:
//!   * [`current_epoch`] — `MAX(epoch_id)` shortcut for `raxis status`.
//!   * [`list`] — full append-only log for `raxis policy show`.

use thiserror::Error;

use crate::ro::RoConn;
use crate::Table;

/// One row of `policy_epoch_history`. Field shape is identical to the
/// DDL (kernel-store.md §2.5.1 Table 19); we keep it here as a typed
/// struct so CLI consumers don't need to know the column order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyEpochRow {
    pub epoch_id: u64,
    pub policy_sha256: String,
    pub signed_by_authority: String,
    pub triggered_by_operator: String,
    pub advanced_at: u64,
}

#[derive(Debug, Error)]
pub enum PolicyHistoryViewError {
    #[error("sqlite error during policy_history view read: {0}")]
    Sqlite(#[from] rusqlite::Error),
}

/// `MAX(epoch_id)` as a typed `u64`. `None` for an unbootstrapped
/// store. Equivalent to [`crate::views::kernel_meta::read`]'s
/// `policy_epoch` field but cheaper when the caller doesn't need the
/// schema_version too.
pub fn current_epoch(conn: &RoConn) -> Result<Option<u64>, PolicyHistoryViewError> {
    let row: Option<i64> = conn.query_row(
        &format!(
            "SELECT MAX(epoch_id) FROM {}",
            Table::PolicyEpochHistory.as_str(),
        ),
        [],
        |r| r.get::<_, Option<i64>>(0),
    )?;
    Ok(row.map(|v| v.max(0) as u64))
}

/// List every epoch advance, newest-first.
///
/// `raxis policy show --history` consumes this. The list is unbounded
/// in v1 because the table is small (one row per genesis + one per
/// `policy rotate-epoch`); v2 may add paging once operators
/// accumulate dozens of rotations.
pub fn list(conn: &RoConn, limit: usize) -> Result<Vec<PolicyEpochRow>, PolicyHistoryViewError> {
    let mut stmt = conn.prepare(&format!(
        "SELECT epoch_id, policy_sha256, signed_by_authority, \
                triggered_by_operator, advanced_at \
         FROM {} ORDER BY advanced_at DESC LIMIT ?1",
        Table::PolicyEpochHistory.as_str(),
    ))?;
    let rows = stmt
        .query_map(rusqlite::params![limit as i64], |r| {
            Ok(PolicyEpochRow {
                epoch_id: r.get::<_, i64>(0)?.max(0) as u64,
                policy_sha256: r.get(1)?,
                signed_by_authority: r.get(2)?,
                triggered_by_operator: r.get(3)?,
                advanced_at: r.get::<_, i64>(4)?.max(0) as u64,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ro::open as open_ro, Store};
    use tempfile::TempDir;

    fn fresh_store_with_seed_history() -> TempDir {
        const POLICY_EPOCH_HISTORY: &str = Table::PolicyEpochHistory.as_str();
        let tmp = TempDir::new().unwrap();
        let db = tmp.path().join("kernel.db");
        let store = Store::open(&db).unwrap();
        let guard = store.lock_sync();
        for (epoch, sha, by, at) in [
            (1_i64, "sha-genesis", "fp-1", 100_i64),
            (2, "sha-two", "fp-1", 200),
            (3, "sha-three", "fp-2", 300),
        ] {
            guard
                .execute(
                    &format!(
                        "INSERT INTO {POLICY_EPOCH_HISTORY} \
                     (epoch_id, policy_sha256, signed_by_authority, \
                      triggered_by_operator, advanced_at) \
                     VALUES (?1, ?2, 'auth-fp', ?3, ?4)"
                    ),
                    rusqlite::params![epoch, sha, by, at],
                )
                .unwrap();
        }
        tmp
    }

    #[test]
    fn current_epoch_returns_none_on_empty_history() {
        let tmp = TempDir::new().unwrap();
        let _store = Store::open(&tmp.path().join("kernel.db")).unwrap();
        let conn = open_ro(tmp.path()).unwrap();
        assert_eq!(current_epoch(&conn).unwrap(), None);
    }

    #[test]
    fn current_epoch_returns_max_epoch_id() {
        let tmp = fresh_store_with_seed_history();
        let conn = open_ro(tmp.path()).unwrap();
        assert_eq!(current_epoch(&conn).unwrap(), Some(3));
    }

    #[test]
    fn list_orders_newest_first_and_returns_all_columns() {
        let tmp = fresh_store_with_seed_history();
        let conn = open_ro(tmp.path()).unwrap();
        let rows = list(&conn, 10).unwrap();
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0].epoch_id, 3);
        assert_eq!(rows[0].policy_sha256, "sha-three");
        assert_eq!(rows[2].epoch_id, 1);
    }

    #[test]
    fn list_respects_limit() {
        let tmp = fresh_store_with_seed_history();
        let conn = open_ro(tmp.path()).unwrap();
        let rows = list(&conn, 1).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].epoch_id, 3);
    }
}

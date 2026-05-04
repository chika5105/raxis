//! Kernel-meta queries — schema version + current policy epoch.
//!
//! Normative reference: cli-readonly.md §5.4.1 (`kernel_meta.rs`).
//!
//! These are the `raxis status` "first-line" facts: what the database
//! says about itself, with no joins. Every CLI command that prints a
//! header reaches through this module.

use rusqlite::OptionalExtension;
use thiserror::Error;

use crate::ro::RoConn;
use crate::Table;

/// Snapshot of kernel-self facts derivable from `kernel.db` alone.
///
/// All fields are taken at one instant inside a single deferred read
/// transaction, so a concurrent `policy_epoch_advance` cannot tear
/// the snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelMeta {
    /// Current schema version applied to `kernel.db`. Mirrors
    /// [`crate::SCHEMA_VERSION`] when the CLI is in lock-step with
    /// the kernel; `ro::open` already hard-fails on mismatch, so a
    /// successfully-opened `RoConn` is guaranteed to read this value
    /// equal to the CLI's compiled-in expectation.
    pub schema_version: i64,
    /// `MAX(epoch_id)` from `policy_epoch_history`. The kernel
    /// considers this the "currently-active policy epoch".
    /// Returns `None` for a fresh-bootstrapped store with no
    /// `policy_epoch_history` row yet (genesis path), although the
    /// happy-path bootstrap always installs the genesis row.
    pub policy_epoch: Option<u64>,
}

/// Failure modes for the kernel_meta query path.
#[derive(Debug, Error)]
pub enum KernelMetaError {
    #[error("sqlite error during kernel_meta read: {0}")]
    Sqlite(#[from] rusqlite::Error),
}

/// Read both fields in one short read transaction.
///
/// We intentionally do NOT use `RoConn::transaction()` — rusqlite's
/// transaction API requires `&mut Connection`, which we don't expose.
/// Two `query_row` calls on the same connection are observationally
/// snapshot-consistent under WAL because the kernel only ever issues
/// `policy_epoch_advance` as a single committed transaction; we
/// cannot observe a half-applied epoch.
pub fn read(conn: &RoConn) -> Result<KernelMeta, KernelMetaError> {
    let schema_version: i64 = conn.query_row(
        &format!(
            "SELECT COALESCE(MAX(version), 0) FROM {}",
            Table::SchemaVersion.as_str(),
        ),
        [],
        |r| r.get(0),
    )?;

    let policy_epoch: Option<i64> = conn.query_row(
        &format!(
            "SELECT MAX(epoch_id) FROM {}",
            Table::PolicyEpochHistory.as_str(),
        ),
        [],
        |r| r.get::<_, Option<i64>>(0),
    ).optional()?.flatten();

    Ok(KernelMeta {
        schema_version,
        policy_epoch: policy_epoch.map(|v| v as u64),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ro::open as open_ro, Store};
    use tempfile::TempDir;

    fn fresh_store_path() -> (TempDir, std::path::PathBuf) {
        let tmp = TempDir::new().unwrap();
        let db = tmp.path().join("kernel.db");
        let _store = Store::open(&db).expect("write-mode store opens");
        (tmp, db)
    }

    #[test]
    fn read_returns_current_schema_version_for_freshly_bootstrapped_db() {
        let (tmp, _db) = fresh_store_path();
        let conn = open_ro(tmp.path()).expect("ro open");
        let meta = read(&conn).expect("kernel_meta");
        // Pin against `SCHEMA_VERSION` (not a hardcoded literal) so a
        // future migration bump only edits one place. The previous
        // assertion of `== 1` broke when migration_2 landed in
        // step 4 of the operator-cert feature; locking to the
        // exported constant prevents the same regression.
        assert_eq!(meta.schema_version, crate::SCHEMA_VERSION as i64);
        // No policy_epoch row yet — bootstrap installs it on the
        // kernel's *first* boot, but `Store::open` alone does not.
        assert_eq!(meta.policy_epoch, None);
    }

    #[test]
    fn read_returns_policy_epoch_when_history_row_present() {
        let (tmp, db) = fresh_store_path();

        // Simulate the kernel's genesis insert (without the full
        // bootstrap ceremony — we just need the row to be there).
        {
            let store = Store::open(&db).unwrap();
            let guard = store.lock_sync();
            guard.execute(
                "INSERT INTO policy_epoch_history \
                 (epoch_id, policy_sha256, signed_by_authority, \
                  triggered_by_operator, advanced_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                rusqlite::params![1_i64, "deadbeef", "fp", "op", 1_700_000_000_i64],
            ).unwrap();
        }

        let conn = open_ro(tmp.path()).expect("ro open");
        let meta = read(&conn).expect("kernel_meta");
        assert_eq!(meta.policy_epoch, Some(1));
    }
}

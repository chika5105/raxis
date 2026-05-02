// raxis-store::db — Store handle, connection open, and runtime pragma setup.
//
// Normative reference: kernel-store.md §2.5.1 "Isolation model"
//
// Key invariants enforced here:
//   INV-STORE-01: single tokio::sync::Mutex over the Connection;
//                 held continuously from BEGIN through COMMIT.
//   WAL + synchronous=FULL: mandatory; non-negotiable per §2.5.1.
//   foreign_keys=ON: referential integrity at runtime.

use rusqlite::Connection;
use std::path::Path;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::Mutex;

use crate::migration;

// ---------------------------------------------------------------------------
// StoreError
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("SQLite error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    /// Direct rusqlite::Error — used when callers handle rusqlite errors before
    /// wrapping them into StoreError (e.g. authority subsystem's `?` conversions).
    #[error("SQLite error (raw): {0}")]
    Rusqlite(rusqlite::Error),

    #[error("migration error: {0}")]
    Migration(String),

    #[error("store invariant violated: {0}")]
    Invariant(String),
}

// ---------------------------------------------------------------------------
// Store — the primary kernel store handle.
//
// Arc<Mutex<Connection>> per kernel-store.md §2.5.1 "Single connection per
// kernel process". The Mutex is tokio::sync::Mutex (INV-STORE-01).
// ---------------------------------------------------------------------------

/// The kernel's SQLite store handle.
///
/// Cloning `Store` is cheap (Arc clone). All kernel subsystems that need DB
/// access receive a `Store` clone. There is exactly one underlying
/// `rusqlite::Connection` shared across all clones.
#[derive(Clone)]
pub struct Store {
    conn: Arc<Mutex<Connection>>,
}

impl Store {
    /// Open the kernel database at `path`, apply runtime pragmas, and run all
    /// pending migrations. Creates the file if it does not exist.
    ///
    /// This function is called once during kernel bootstrap
    /// (`bootstrap::run` step 3 per kernel-core.md §2.1).
    pub fn open(path: &Path) -> Result<Self, StoreError> {
        // rusqlite::Connection::open creates the file if it does not exist.
        let conn = Connection::open(path)?;

        // Apply runtime pragmas — ALL are mandatory per §2.5.1.
        // These must run before any migration DDL.
        Self::apply_pragmas(&conn)?;

        // Run pending migrations (idempotent; CREATE TABLE IF NOT EXISTS).
        migration::apply_pending(&conn)?;

        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    /// Open an in-memory database for tests. Applies the same pragmas and
    /// migrations as a real store so test code exercises the real schema.
    #[cfg(test)]
    pub fn open_in_memory() -> Result<Self, StoreError> {
        let conn = Connection::open_in_memory()?;
        Self::apply_pragmas(&conn)?;
        migration::apply_pending(&conn)?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    /// Acquire the store mutex and return the guard.
    ///
    /// Callers MUST hold the guard for the entire duration of any transaction:
    ///   let guard = store.lock().await;
    ///   let tx = guard.transaction()?;
    ///   // ... writes ...
    ///   tx.commit()?;
    ///   drop(guard);  // or let scope end
    ///
    /// Releasing the guard while a transaction is open is an INV-STORE-01
    /// violation. The borrow checker enforces this: `Transaction<'_>` borrows
    /// from `Connection`, which is behind the guard, so the guard cannot be
    /// dropped while `tx` is alive.
    /// Acquire the store mutex asynchronously.
    ///
    /// Callers MUST hold the guard for the entire duration of any transaction.
    pub async fn lock(&self) -> tokio::sync::MutexGuard<'_, Connection> {
        self.conn.lock().await
    }

    /// Acquire the store mutex from a synchronous (non-async) context.
    ///
    /// Used by the authority subsystem which is sync (no tokio). This calls
    /// `blocking_lock()` on the tokio Mutex — safe as long as the caller is NOT
    /// running inside a tokio async task (it will deadlock if called from async
    /// context while another task holds the lock). Authority subsystem code is
    /// called from IPC handler tasks via `tokio::task::spawn_blocking`, so this
    /// is safe for the v1 execution model.
    pub fn lock_sync(&self) -> tokio::sync::MutexGuard<'_, Connection> {
        self.conn.blocking_lock()
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    /// Apply the four mandatory SQLite runtime pragmas.
    /// kernel-store.md §2.5.1 "Runtime pragmas".
    fn apply_pragmas(conn: &Connection) -> Result<(), StoreError> {
        // WAL mode: crash-safe, non-blocking for concurrent readers.
        conn.execute_batch("PRAGMA journal_mode = WAL;")?;

        // FULL sync: every commit is fdatasynced before returning.
        // Mandatory for the crash-recovery guarantees in §2.5.2.
        conn.execute_batch("PRAGMA synchronous = FULL;")?;

        // FK enforcement: catches implementation bugs at the schema level.
        conn.execute_batch("PRAGMA foreign_keys = ON;")?;

        // Temp storage in memory: avoid disk I/O for query scratch space.
        conn.execute_batch("PRAGMA temp_store = MEMORY;")?;

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn open_in_memory_applies_schema() {
        let store = Store::open_in_memory().expect("in-memory store");
        let guard = store.lock().await;

        // Verify schema_version table exists and migration 1 was applied.
        let version: i64 = guard
            .query_row(
                "SELECT MAX(version) FROM schema_version",
                [],
                |row| row.get(0),
            )
            .expect("schema_version query");

        assert_eq!(version, 1, "migration 1 should be applied");
    }

    #[tokio::test]
    async fn pragmas_are_active() {
        let store = Store::open_in_memory().expect("in-memory store");
        let guard = store.lock().await;

        // Foreign keys should be ON.
        let fk: i64 = guard
            .query_row("PRAGMA foreign_keys", [], |r| r.get(0))
            .expect("pragma query");
        assert_eq!(fk, 1, "foreign_keys must be ON");

        // WAL mode (in-memory DB reports 'memory' — that's fine for :memory:;
        // only check that the pragma round-trip doesn't error).
        let _mode: String = guard
            .query_row("PRAGMA journal_mode", [], |r| r.get(0))
            .expect("journal_mode pragma");
    }
}

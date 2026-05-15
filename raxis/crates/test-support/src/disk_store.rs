// DiskStore — TempDir-backed file-backed `raxis_store::Store` fixture
// with explicit `close()` / `reopen()` lifecycle.
//
// Why this exists:
//   Every existing `raxis_store::Store` test uses
//   `Store::open_in_memory()`, which is a different SQLite mode than
//   the file-backed `Store::open(path)` the kernel actually runs in
//   production. In particular, `:memory:` databases:
//
//     - never enter WAL mode (the pragma is a no-op),
//     - never flush to disk, so fsync ordering bugs are invisible,
//     - cannot exercise the "open-existing-populated-DB" path that
//       schema migration goes through on every kernel restart,
//     - cannot exercise the "close → reopen → reconcile" recovery
//       sequence the kernel runs at boot.
//
//   `DiskStore` closes that gap: it owns a `TempDir` and a
//   file-backed `Store`, exposes `close()` to drop the inner `Store`
//   (releasing the SQLite connection so the WAL gets checkpointed),
//   and `reopen()` to re-open the SAME file. That gives integration
//   tests an honest "kernel shutdown / kernel restart" simulation.
//
// What this fixture is NOT:
//   - Not a substitute for `mem_store()` in unit tests where you only
//     need a fresh isolated store. `mem_store()` is faster and avoids
//     touching the filesystem at all.
//   - Not a multi-process simulator. SQLite locks at the file level,
//     and `close() + reopen()` happens in-process; tests that need to
//     exercise concurrent kernel processes against the same DB
//     belong in a different fixture.

use std::path::{Path, PathBuf};

use raxis_store::Store;
use tempfile::TempDir;

/// File name the kernel uses for its state DB (kernel-store.md §2.5.1).
/// Mirrored here so production code paths (e.g. `Store::open(path)`)
/// can be pointed at `DiskStore::db_path()` without translation.
const DB_FILENAME: &str = "kernel.db";

// ---------------------------------------------------------------------------
// DiskStore
// ---------------------------------------------------------------------------

/// A file-backed `Store` inside a temp directory.
///
/// Construction opens a fresh DB at `<tmp>/kernel.db` with the same
/// pragmas and migrations the production `Store::open(path)` applies.
///
/// The underlying [`TempDir`] is recursively removed on drop, so test
/// bodies do not need explicit cleanup.
pub struct DiskStore {
    /// Held to extend the temp directory's lifetime to the fixture's.
    /// Kept private so callers cannot drop the dir out from under the
    /// `Store` connection (which would leave the test in a state the
    /// production kernel could never reach).
    _tmp: TempDir,
    db_path: PathBuf,

    /// `None` after `close()`; `Some(_)` while the connection is open.
    /// Boxed in an `Option` (rather than the `Store` itself) so the
    /// fixture can simulate "kernel shutdown" without consuming `self`.
    store: Option<Store>,
}

impl DiskStore {
    /// Create a fresh disk-backed Store in a new temp directory. The
    /// underlying file is newly created on construction and migrations
    /// are applied — exactly the path `kernel::main::main` step 5 takes.
    pub fn new() -> Self {
        let tmp = TempDir::new().expect("DiskStore: TempDir::new failed");
        let db_path = tmp.path().join(DB_FILENAME);
        let store =
            Store::open(&db_path).expect("DiskStore: Store::open failed for fresh disk store");
        Self {
            _tmp: tmp,
            db_path,
            store: Some(store),
        }
    }

    /// Borrow the open `Store`. Panics if the fixture has been
    /// `close()`d but not yet `reopen()`ed — that's a test bug.
    pub fn store(&self) -> &Store {
        self.store
            .as_ref()
            .expect("DiskStore::store(): store is closed; call reopen() first")
    }

    /// Path to the on-disk database file (`<tmp>/kernel.db`).
    pub fn db_path(&self) -> &Path {
        &self.db_path
    }

    /// Path to the temp directory itself. Useful for tests that want
    /// to also place an `audit/` subdirectory next to `kernel.db` to
    /// mirror the kernel's `data_dir` layout.
    pub fn data_dir(&self) -> &Path {
        self._tmp.path()
    }

    /// Drop the underlying `Store` so the SQLite connection closes
    /// and any pending WAL data is checkpointed. After this returns,
    /// `store()` will panic until `reopen()` is called.
    ///
    /// This simulates a graceful kernel shutdown.
    ///
    /// Safety note: this only works if no OTHER `Store` clones outlive
    /// the call. The fixture holds the only clone by default. Tests
    /// that hand out additional clones (e.g. into spawned tasks) MUST
    /// drop those before calling `close()`, otherwise the underlying
    /// connection stays open and the call is a no-op.
    pub fn close(&mut self) {
        self.store = None;
    }

    /// Re-open the same DB file. Applies migrations again (idempotent
    /// for an already-migrated schema; this is exactly what
    /// `kernel::main::main` step 5 does on every restart). Panics if
    /// the file has been deleted between `close()` and `reopen()`.
    pub fn reopen(&mut self) {
        assert!(
            self.db_path.exists(),
            "DiskStore::reopen(): {} does not exist; \
             cannot simulate kernel restart on a missing DB",
            self.db_path.display(),
        );
        let store = Store::open(&self.db_path).expect("DiskStore::reopen: Store::open failed");
        self.store = Some(store);
    }

    /// Returns `true` if the inner `Store` is currently open.
    /// Useful for assertions in tests that exercise the close/reopen
    /// state machine.
    pub fn is_open(&self) -> bool {
        self.store.is_some()
    }
}

impl Default for DiskStore {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests — fixture self-tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_creates_a_db_file_on_disk() {
        let ds = DiskStore::new();
        assert!(ds.db_path().exists(), "kernel.db must exist after new()");
        assert_eq!(ds.db_path().file_name().unwrap(), "kernel.db");
        assert!(ds.is_open());
    }

    #[test]
    fn close_drops_the_inner_store() {
        let mut ds = DiskStore::new();
        assert!(ds.is_open());
        ds.close();
        assert!(!ds.is_open());
    }

    #[test]
    #[should_panic(expected = "store is closed")]
    fn store_panics_when_closed() {
        let mut ds = DiskStore::new();
        ds.close();
        let _ = ds.store(); // must panic
    }

    #[test]
    fn reopen_restores_an_open_store_at_the_same_path() {
        let mut ds = DiskStore::new();
        let p1 = ds.db_path().to_path_buf();
        ds.close();
        ds.reopen();
        assert!(ds.is_open());
        assert_eq!(ds.db_path(), p1.as_path());
    }

    #[test]
    fn db_file_persists_across_close_and_reopen() {
        // Sanity: the SAME file is reopened, not a new one — so any
        // state written before close() is observable after reopen().
        const INITIATIVES: &str = raxis_store::Table::Initiatives.as_str();

        let mut ds = DiskStore::new();

        {
            let conn = ds.store().lock_sync();
            conn.execute(
                &format!(
                    "INSERT INTO {INITIATIVES} \
                        (initiative_id, state, terminal_criteria_json, \
                         plan_artifact_sha256, created_at) \
                     VALUES ('init-disk-persist', 'Executing', '{{}}', 'deadbeef', 0)"
                ),
                [],
            )
            .expect("seed insert failed");
        }

        ds.close();
        ds.reopen();

        let conn = ds.store().lock_sync();
        let count: i64 = conn
            .query_row(
                &format!(
                    "SELECT COUNT(*) FROM {INITIATIVES} \
                     WHERE initiative_id='init-disk-persist'"
                ),
                [],
                |r| r.get(0),
            )
            .expect("query after reopen failed");
        assert_eq!(count, 1, "row written before close must survive reopen");
    }
}

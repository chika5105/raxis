// raxis-store::db — Store handle, connection open, and runtime pragma setup.
//
// Normative reference: kernel-store.md §2.5.1 "Isolation model"
//
// Key invariants enforced here:
//   INV-STORE-01: single tokio::sync::Mutex over the Connection;
//                 held continuously from BEGIN through COMMIT.
//   INV-KERNEL-STORE-LOCK-SYNC-NEVER-FROM-ASYNC-01: callers MUST NOT
//                 invoke `Store::lock_sync` from inside an `async fn`
//                 frame or `tokio::spawn(async move { ... })`
//                 closure without an intervening
//                 `tokio::task::spawn_blocking` hop. This module
//                 enforces the contract at the boundary:
//                   * debug builds  → `mutex.blocking_lock()` panics
//                                     when invoked from a worker
//                                     thread (the canonical tokio
//                                     panic), making the regression
//                                     loud in CI;
//                   * release builds → if a runtime is current, we
//                                     wrap the lock acquisition in
//                                     `tokio::task::block_in_place`
//                                     so the kernel daemon survives
//                                     the misuse rather than crashing
//                                     mid-handler. The recovery is
//                                     silent — production observability
//                                     into "did this fire" lives in
//                                     debug-build CI runs and the
//                                     supervisor restart history, not
//                                     in the audit chain (a per-call
//                                     audit event would over-classify
//                                     every legitimate
//                                     `spawn_blocking + lock_sync`
//                                     site once tokio's worker /
//                                     blocking-pool threads share a
//                                     name, as they do under
//                                     `#[tokio::main]` /
//                                     `#[tokio::test]`).
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
    ///
    /// Not gated by `#[cfg(test)]` because downstream crates
    /// (`raxis-kernel`, `raxis-policy`, etc.) need it from their own test
    /// builds. The `raxis-test-support` crate (PR-11) will eventually wrap
    /// this as `FakeStore::new()`; until then, callers are expected to use
    /// it only from `#[cfg(test)]` modules.
    pub fn open_in_memory() -> Result<Self, StoreError> {
        let conn = Connection::open_in_memory()?;
        Self::apply_pragmas(&conn)?;
        migration::apply_pending(&conn)?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    /// Acquire the store mutex asynchronously — the **preferred path**
    /// for any `async fn` body that needs the connection.
    ///
    /// Callers MUST hold the guard for the entire duration of any transaction:
    ///
    ///   let mut guard = store.lock().await;
    ///   let tx = guard.transaction()?;
    ///   // ... writes ...
    ///   tx.commit()?;
    ///   drop(guard);  // or let scope end
    ///
    /// Releasing the guard while a transaction is open is an INV-STORE-01
    /// violation. The borrow checker enforces this: `Transaction<'_>` borrows
    /// from `Connection`, which is behind the guard, so the guard cannot be
    /// dropped while `tx` is alive.
    ///
    /// **Async-safety contract** (`INV-KERNEL-STORE-LOCK-SYNC-NEVER-FROM-
    /// ASYNC-01`). New async-context call sites SHOULD use `lock().await`
    /// rather than `tokio::task::spawn_blocking(|| store.lock_sync())`. The
    /// older `spawn_blocking + lock_sync` pattern remains correct (the boundary
    /// defense in [`Self::lock_sync`] keeps it safe), but `lock().await` is
    /// shorter and avoids the closure-captures-`Send` dance. See the kernel-
    /// resident migration example in
    /// `kernel/src/notifications/mod.rs::dispatch_blocking_for_tests_with_registry`
    /// (the test-only async helper that was previously a HAZARD; migrated to
    /// `lock().await` under this invariant).
    pub async fn lock(&self) -> tokio::sync::MutexGuard<'_, Connection> {
        self.conn.lock().await
    }

    /// Acquire the store mutex from a synchronous (non-async) context.
    ///
    /// **Async-safety contract** (`INV-KERNEL-STORE-LOCK-SYNC-NEVER-FROM-
    /// ASYNC-01`). This function MUST NOT be called from inside an
    /// `async fn` body or a `tokio::spawn(async move { ... })` closure
    /// without an intervening `tokio::task::spawn_blocking` hop. The
    /// underlying `tokio::sync::Mutex::blocking_lock` panics with
    /// `"Cannot block the current thread from within a runtime"` when
    /// invoked on a tokio worker thread, which historically took two
    /// live E2E runs to the floor (iter63 / iter66.1) before the
    /// boundary defense landed.
    ///
    /// **Boundary defense.**
    ///
    /// * Debug builds (`cfg(debug_assertions)`): calls `blocking_lock()`
    ///   directly. The original tokio panic fires when invoked from a
    ///   worker thread, making the regression loud in CI. This is the
    ///   canonical teeth of the invariant.
    ///
    /// * Release builds (`cfg(not(debug_assertions))`): if a tokio
    ///   runtime is current on the calling thread, the lock acquisition
    ///   is wrapped in `tokio::task::block_in_place(...)` so the
    ///   kernel daemon survives the misuse without panicking
    ///   mid-handler (the supervisor will still see process restarts
    ///   if a hot loop trips the boundary at high frequency, but the
    ///   single-call shape no longer brings the kernel down). The
    ///   recovery is silent on the wire — observability into "did
    ///   this fire" lives in debug-build CI panics, supervisor restart
    ///   history, and the kernel-debugger's per-call backtrace; we
    ///   deliberately do NOT emit a per-call audit event for it
    ///   because tokio names the worker and blocking-pool threads
    ///   identically under `#[tokio::main]` / `#[tokio::test]`, which
    ///   would over-classify every legitimate
    ///   `spawn_blocking + lock_sync` site as a violation.
    ///
    /// * `block_in_place` is unavailable on `current_thread` runtimes
    ///   (where it panics). For that edge case we fall back to a plain
    ///   `blocking_lock()` and let it panic; production kernel daemons
    ///   are multi-thread, so this path only fires for misconfigured
    ///   tests / CLI commands that built a `current_thread` runtime
    ///   AND then tried to call `lock_sync` from async without
    ///   `spawn_blocking`.
    ///
    /// `#[track_caller]` propagates the *caller's* source location
    /// into any resulting panic message, so the operator can jump
    /// straight to the offending call site rather than the `lock_sync`
    /// definition.
    #[track_caller]
    pub fn lock_sync(&self) -> tokio::sync::MutexGuard<'_, Connection> {
        // Outside any tokio runtime — recovery sweepers, bootstrap,
        // CLI commands, tests outside `#[tokio::test]`. Plain
        // `blocking_lock` is legal and contention-free.
        if tokio::runtime::Handle::try_current().is_err() {
            return self.conn.blocking_lock();
        }

        // Inside a runtime. Debug builds keep the canonical tokio
        // panic so CI trips loudly on a worker-thread misuse;
        // release builds attempt `block_in_place` recovery so the
        // daemon survives the misuse without crashing.
        #[cfg(debug_assertions)]
        {
            self.conn.blocking_lock()
        }
        #[cfg(not(debug_assertions))]
        {
            // `block_in_place` panics on `current_thread` runtimes
            // (no second worker to absorb the blocking work). Catch
            // that rare edge case and fall back to `blocking_lock`
            // so the canonical tokio panic still surfaces — at least
            // the operator sees the underlying contract failure
            // rather than an opaque `block_in_place` panic.
            //
            // SAFETY: `block_in_place` runs the closure on the
            // current thread (it does NOT migrate it). The closure
            // captures `&self.conn` by reference; the returned
            // `MutexGuard<'_, Connection>` borrows from `self.conn`,
            // which lives at least as long as `&self`. No raw
            // pointers, no unsafe blocks, no transmutes.
            let recovery: Result<tokio::sync::MutexGuard<'_, Connection>, _> =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    tokio::task::block_in_place(|| self.conn.blocking_lock())
                }));
            match recovery {
                Ok(guard) => guard,
                Err(_) => self.conn.blocking_lock(),
            }
        }
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

        // Verify schema_version table exists and ALL migrations were
        // applied. Pin to the exported `SCHEMA_VERSION` (not a literal)
        // so a future migration bump only edits one place; the previous
        // hardcoded `== 1` regressed when migration_2 landed in step 4
        // of the operator-cert feature.
        let version: i64 = guard
            .query_row(
                &format!(
                    "SELECT MAX(version) FROM {}",
                    crate::Table::SchemaVersion.as_str(),
                ),
                [],
                |row| row.get(0),
            )
            .expect("schema_version query");

        assert_eq!(
            version,
            crate::SCHEMA_VERSION as i64,
            "all pending migrations should be applied",
        );
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

// ---------------------------------------------------------------------------
// `INV-KERNEL-STORE-LOCK-SYNC-NEVER-FROM-ASYNC-01` boundary witnesses.
// ---------------------------------------------------------------------------
//
// Three witnesses pin the contract:
//
//   1. POSITIVE — `lock_sync_via_spawn_blocking_is_ok` (always-on):
//      the canonical safe pattern (`spawn_blocking + lock_sync`)
//      completes without panicking and the runtime stays healthy
//      afterwards.
//
//   2. NEGATIVE — `lock_sync_directly_from_runtime_worker_panics`
//      (`cfg(debug_assertions)`): the debug-build teeth. Calling
//      `lock_sync` directly from a `#[tokio::test]` body panics
//      with the canonical tokio message so CI trips loudly.
//
//   3. RECOVERY — `lock_sync_release_build_recovers`
//      (`cfg(not(debug_assertions))`): the release-build recovery
//      path. Calling `lock_sync` from a multi-thread runtime worker
//      succeeds (the `block_in_place` hop saves us) and the runtime
//      keeps serving work afterwards.
#[cfg(test)]
mod async_runtime_safety {
    use super::*;
    use std::sync::Arc;

    /// **INV-KERNEL-STORE-LOCK-SYNC-NEVER-FROM-ASYNC-01** witness
    /// (positive). Drives `lock_sync` from a `#[tokio::test]`
    /// runtime via `tokio::task::spawn_blocking`, mirroring the
    /// canonical safe pattern every iter63 / iter66.1 fix follows.
    /// The witness pins that the call completes without panicking
    /// AND that the runtime stays healthy afterwards.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn lock_sync_via_spawn_blocking_is_ok() {
        let store = Arc::new(Store::open_in_memory().expect("in-memory store"));

        tokio::task::spawn_blocking({
            let store = Arc::clone(&store);
            move || {
                // Returns a real guard; if the boundary were broken
                // (deadlock, double-panic) the join below would
                // hang or panic.
                let _g = store.lock_sync();
            }
        })
        .await
        .expect("spawn_blocking join");

        // Runtime-healthy probe — assert the runtime kept serving
        // work after the spawn_blocking + lock_sync round-trip.
        let probe = tokio::spawn(async { 11u32 })
            .await
            .expect("runtime alive after spawn_blocking + lock_sync");
        assert_eq!(probe, 11);
    }

    /// **INV-KERNEL-STORE-LOCK-SYNC-NEVER-FROM-ASYNC-01** witness
    /// (negative, debug-build only). Calling `lock_sync` directly
    /// from a runtime worker on a debug build panics with the
    /// canonical tokio message so CI catches regressions loudly.
    ///
    /// Gated to debug builds because release builds intentionally
    /// recover via `block_in_place` instead of panicking — see
    /// `lock_sync_release_build_recovers` for the release-build
    /// counterpart.
    #[cfg(debug_assertions)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[should_panic(expected = "Cannot block the current thread from within a runtime")]
    async fn lock_sync_directly_from_runtime_worker_panics() {
        let store = Store::open_in_memory().expect("in-memory store");
        // No `spawn_blocking` hop — iter66.1 production crash shape.
        // `#[track_caller]` on `lock_sync` places the panic site at
        // the call below, so a future reader of the panic location
        // lands in this test rather than in `db.rs:lock_sync`.
        let _g = store.lock_sync();
    }

    /// **INV-KERNEL-STORE-LOCK-SYNC-NEVER-FROM-ASYNC-01** witness
    /// (release build only). Calling `lock_sync` from a runtime
    /// worker on a release build does NOT panic — the boundary
    /// transparently recovers via `block_in_place(|| blocking_lock())`
    /// and returns a valid guard; the runtime keeps serving work
    /// afterwards.
    #[cfg(not(debug_assertions))]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn lock_sync_release_build_recovers() {
        let store = Store::open_in_memory().expect("in-memory store");

        // No `spawn_blocking` hop — boundary must transparently
        // recover via `block_in_place`.
        {
            let _g = store.lock_sync();
        }
        // Recovery-functional witness: a second sequential async-
        // context call ALSO succeeds, and the runtime keeps serving
        // work after the recovery.
        {
            let _g = store.lock_sync();
        }

        let probe = tokio::spawn(async { 7u32 }).await.expect("runtime alive");
        assert_eq!(probe, 7);
    }

    /// **INV-KERNEL-STORE-LOCK-SYNC-NEVER-FROM-ASYNC-01** witness
    /// (no-false-positive). A pure-sync caller — no tokio runtime
    /// current on this thread — calls `lock_sync` and the boundary
    /// must succeed without entering the recovery path. Mirrors
    /// the recovery sweeper / bootstrap / CLI call shapes.
    #[test]
    fn lock_sync_outside_runtime_succeeds() {
        let store = Store::open_in_memory().expect("in-memory store");
        let _g = store.lock_sync();
    }
}

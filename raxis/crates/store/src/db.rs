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
//                                     (the canonical tokio panic),
//                                     making the regression loud in
//                                     CI;
//                   * release builds → detect the async context,
//                                     emit `eprintln!` +
//                                     `KernelStoreLockSyncFromAsync
//                                     Detected` audit + bump the
//                                     `raxis_kernel_store_lock_sync_
//                                     from_async_total` counter,
//                                     then recover via
//                                     `tokio::task::block_in_place`
//                                     so the kernel daemon stays
//                                     alive.
//                 Recovery is correct but bug-signal — sustained
//                 non-zero counter values are operator-actionable.
//   WAL + synchronous=FULL: mandatory; non-negotiable per §2.5.1.
//   foreign_keys=ON: referential integrity at runtime.

use rusqlite::Connection;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
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
// `INV-KERNEL-STORE-LOCK-SYNC-NEVER-FROM-ASYNC-01` boundary telemetry
// ---------------------------------------------------------------------------
//
// Process-global state for the `Store::lock_sync` boundary:
//
//   * `LOCK_SYNC_FROM_ASYNC_COUNTER` — bumped once per detection on
//     release builds. Exposed via `lock_sync_from_async_count()` so
//     the dashboard / Prometheus exporter / tests can read it.
//     The Prometheus name we promise to expose is
//     `raxis_kernel_store_lock_sync_from_async_total`; the kernel
//     wires it through whatever observability registry is current
//     (see `FOLLOWUP-LIST` in `RETURN_NOTE_TO_PARENT.md`).
//
//   * `LOCK_SYNC_FROM_ASYNC_EMITTER` — process-global closure the
//     kernel installs at boot via
//     `install_lock_sync_from_async_emitter`. The boundary calls it
//     after the eprintln + counter increment; the closure typically
//     emits a `KernelStoreLockSyncFromAsyncDetected` audit event.
//     The closure is best-effort: if not installed (CLI commands,
//     boot before the audit sink is wired) the boundary still
//     emits the eprintln + bumps the counter — those are the
//     durable signals.
//
//   * `TELEMETRY_UNAVAILABLE_REPORTED` — `AtomicBool` flag toggled
//     the first time the boundary detects a release-build async-
//     context violation but the emitter slot was empty. We log
//     `KernelStoreLockSyncTelemetryUnavailable` exactly ONCE per
//     process so the operator can confirm the kernel observed the
//     gap; sustained spam would dwarf the canonical detection log.

static LOCK_SYNC_FROM_ASYNC_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Closure signature for the kernel-installed best-effort audit emitter.
///
/// Arguments:
/// * `caller_file` — `std::panic::Location::file()` string of the
///   offending `lock_sync` call site.
/// * `caller_line` — `std::panic::Location::line()` of the call site.
/// * `thread_name` — best-effort thread name (`<unknown>` if no name).
/// * `cumulative_detections` — the counter value AFTER the bump that
///   triggered this emit (so the audit row records "this is the Nth
///   detection in this process").
///
/// Implementations MUST be cheap (best-effort emit; failure is
/// swallowed by the closure itself) and MUST NOT recursively call
/// any method that could re-enter `Store::lock_sync`. The kernel's
/// canonical installer captures an `Arc<dyn AuditSink>` and a clone
/// of the `Store` handle so the audit row lands on the chain.
pub type LockSyncFromAsyncEmitter =
    Arc<dyn Fn(&'static str, u32, &str, u64) + Send + Sync + 'static>;

static LOCK_SYNC_FROM_ASYNC_EMITTER: OnceLock<LockSyncFromAsyncEmitter> = OnceLock::new();

static TELEMETRY_UNAVAILABLE_REPORTED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Read the cumulative count of `Store::lock_sync` detections (the
/// number of times release-build callers hit the boundary while a
/// tokio runtime was current).
///
/// Exposed for tests, the dashboard's kernel-health widget, and the
/// Prometheus-shaped `raxis_kernel_store_lock_sync_from_async_total`
/// counter. Zero on a healthy kernel; sustained non-zero is
/// operator-actionable kernel-bug signal per
/// `INV-KERNEL-STORE-LOCK-SYNC-NEVER-FROM-ASYNC-01`.
pub fn lock_sync_from_async_count() -> u64 {
    LOCK_SYNC_FROM_ASYNC_COUNTER.load(Ordering::Relaxed)
}

/// Test-only helper: reset the counter to zero. NOT exposed in
/// production — tests that need a clean slate call this in
/// `#[tokio::test]` setup. Gated behind `cfg(any(test,
/// feature = "test-support"))` so a stray release-build call site
/// cannot accidentally zero the kernel's running detection
/// history.
#[cfg(any(test, feature = "test-support"))]
pub fn reset_lock_sync_from_async_count_for_tests() {
    LOCK_SYNC_FROM_ASYNC_COUNTER.store(0, Ordering::Relaxed);
    TELEMETRY_UNAVAILABLE_REPORTED.store(false, Ordering::Relaxed);
}

/// Install the kernel-side best-effort audit emitter the boundary
/// invokes after detection + counter bump. Idempotent — only the
/// first call wins (returns `Err(())` on a second-install attempt).
///
/// The kernel installs this exactly once at boot, immediately after
/// the audit sink is wired and BEFORE the IPC dispatcher accepts
/// any frames (so no async-runtime `lock_sync` detection can land
/// before the emitter exists, in the common boot path). If a
/// detection somehow fires earlier, the boundary still emits the
/// eprintln + bumps the counter and additionally logs
/// `KernelStoreLockSyncTelemetryUnavailable` (once per process) so
/// the operator can spot the gap.
//
// `clippy::result_unit_err` is silenced intentionally: this seam
// has exactly ONE failure mode (the `OnceLock` already holds a
// value), the call site (`kernel/src/main.rs`) discards the
// result with `let _ =`, and the idempotency contract is
// witness-tested by
// `async_runtime_safety::install_emitter_is_idempotent_first_install_wins`.
// A custom error type would add ceremony without any new
// information for callers.
#[allow(clippy::result_unit_err)]
pub fn install_lock_sync_from_async_emitter(emitter: LockSyncFromAsyncEmitter) -> Result<(), ()> {
    LOCK_SYNC_FROM_ASYNC_EMITTER.set(emitter).map_err(|_| ())
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
    ///   directly. The original tokio panic fires; tests trip; CI
    ///   surfaces regressions loudly. This is the canonical CI-side
    ///   teeth of the invariant.
    ///
    /// * Release builds (`cfg(not(debug_assertions))`): detect the
    ///   runtime context with `tokio::runtime::Handle::try_current()`.
    ///     - If `Err`, the caller is on a sync thread (recovery sweeper,
    ///       bootstrap, CLI command, test outside a tokio runtime).
    ///       Use `blocking_lock()` directly — legal, no telemetry fires.
    ///     - If `Ok`, the caller is inside a tokio runtime. Emit the
    ///       structured `KernelStoreLockSyncFromAsyncDetected`
    ///       eprintln, bump the
    ///       `raxis_kernel_store_lock_sync_from_async_total` counter,
    ///       and best-effort emit the audit event, THEN recover via
    ///       `tokio::task::block_in_place(|| mutex.blocking_lock())`.
    ///       The daemon survives; the operator sees the bug telemetry.
    ///
    /// * `block_in_place` is unavailable on `current_thread` runtimes
    ///   (where it panics). For that edge case we fall back to
    ///   `blocking_lock()` and let it panic; production kernel daemons
    ///   are multi-thread, so this path only fires for misconfigured
    ///   tests / CLI commands that built a `current_thread` runtime
    ///   AND then tried to call `lock_sync` from async without
    ///   `spawn_blocking`. The `KernelStoreLockSyncFromAsyncDetected`
    ///   eprintln + counter increment still land BEFORE the panic so
    ///   forensic readers see both signals.
    ///
    /// **Safety-preserving telemetry.** The eprintln, counter
    /// increment, and audit emit all happen BEFORE the recovery call.
    /// If the audit emitter slot is empty (kernel boot ordering edge
    /// case), the boundary additionally emits
    /// `KernelStoreLockSyncTelemetryUnavailable` (once per process)
    /// so we never silently recover — "the recovery happened but no
    /// one knows" is itself an invariant violation.
    ///
    /// `#[track_caller]` propagates the *caller's* source location
    /// into the emitted log / audit event, so the operator can jump
    /// straight to the offending call site rather than the `lock_sync`
    /// definition.
    #[track_caller]
    pub fn lock_sync(&self) -> tokio::sync::MutexGuard<'_, Connection> {
        let caller = std::panic::Location::caller();
        self.lock_sync_at(caller)
    }

    /// Inner of `lock_sync` that takes the caller location as an
    /// explicit argument. Split out so the `#[track_caller]` site
    /// stays at the public API boundary while the detection logic is
    /// easy to unit-test by passing a synthesised
    /// `&std::panic::Location` rather than going through a real call
    /// stack.
    fn lock_sync_at(
        &self,
        caller: &'static std::panic::Location<'static>,
    ) -> tokio::sync::MutexGuard<'_, Connection> {
        // Fast-path: outside any tokio runtime, the call is legal and
        // we skip every detection step. Recovery sweepers, bootstrap,
        // CLI commands, and tests outside `#[tokio::test]` all land
        // here. `Handle::try_current` returns `Err(TryCurrentError)`
        // when no runtime is current on this thread.
        let async_context = tokio::runtime::Handle::try_current().is_ok();
        if !async_context {
            return self.conn.blocking_lock();
        }

        // From here on, we are inside a tokio runtime context. Debug
        // builds keep the canonical tokio panic so tests trip; release
        // builds emit telemetry + recover.
        #[cfg(debug_assertions)]
        {
            // CI / dev path: keep the tokio panic. The
            // `track_caller` attribute on `lock_sync` propagates the
            // caller's file:line into the panic message
            // (`crates/store/src/db.rs:N` becomes the user-visible
            // pointer). Adding our own panic! here would mask the
            // `Cannot block the current thread from within a
            // runtime` message that tests and operators already
            // recognise.
            self.conn.blocking_lock()
        }

        #[cfg(not(debug_assertions))]
        {
            // Release path: emit telemetry FIRST, then recover. The
            // ordering matters — if the recovery itself were to fail
            // somehow (it cannot, on multi-thread runtimes, but the
            // principle stands) we want the operator to see the
            // detection record before the kernel state diverges.
            let cumulative = LOCK_SYNC_FROM_ASYNC_COUNTER.fetch_add(1, Ordering::Relaxed) + 1;
            let thread_name = std::thread::current()
                .name()
                .unwrap_or("<unknown>")
                .to_owned();
            // Established kernel JSON shape — single line, no
            // pretty-print. The `caller` is reported as
            // `<file>:<line>` so a log aggregator can group on it.
            eprintln!(
                "{{\"level\":\"error\",\"event\":\"KernelStoreLockSyncFromAsyncDetected\",\
                 \"caller\":\"{file}:{line}\",\"thread\":\"{thread}\",\
                 \"cumulative_detections\":{cumulative},\
                 \"invariant\":\"INV-KERNEL-STORE-LOCK-SYNC-NEVER-FROM-ASYNC-01\"}}",
                file = caller.file(),
                line = caller.line(),
                thread = thread_name,
            );

            // Best-effort audit emit. If the kernel never installed an
            // emitter (CLI commands, boot before the audit sink is
            // wired), eprintln a one-shot
            // `KernelStoreLockSyncTelemetryUnavailable` so the
            // operator can confirm the gap. The eprintln + counter
            // already landed above; this is the additional structured
            // surface.
            match LOCK_SYNC_FROM_ASYNC_EMITTER.get() {
                Some(emitter) => emitter(caller.file(), caller.line(), &thread_name, cumulative),
                None => {
                    if !TELEMETRY_UNAVAILABLE_REPORTED.swap(true, Ordering::Relaxed) {
                        eprintln!(
                            "{{\"level\":\"warn\",\"event\":\
                             \"KernelStoreLockSyncTelemetryUnavailable\",\
                             \"reason\":\"emitter_not_installed\",\
                             \"caller\":\"{file}:{line}\",\
                             \"cumulative_detections\":{cumulative}}}",
                            file = caller.file(),
                            line = caller.line(),
                        );
                    }
                }
            }

            // Recovery: hop the worker thread off the runtime so the
            // mutex acquisition doesn't deadlock. We borrow
            // `&self.conn` directly inside the closure so the
            // returned guard's lifetime is `&self`-bound — no Arc
            // cloning and no lifetime gymnastics needed.
            //
            // `tokio::task::block_in_place` panics on `current_thread`
            // runtimes (where there is no second worker to absorb the
            // blocking work). We catch that rare edge case and fall
            // back to a plain `blocking_lock()` (which will then
            // panic with the canonical tokio message — at least the
            // telemetry above already landed, so the operator sees
            // the detection record + the recovery-unavailable
            // signal). Production kernel daemons use multi-thread
            // runtimes; this fallback exists for CLI / test
            // mis-configurations.
            //
            // `Runtime::runtime_flavor()` would let us check before
            // calling, but it requires a `Handle` we already have —
            // we'd just be deciding which way to fail. The
            // `catch_unwind` approach is one line and survives a
            // future tokio change in how `block_in_place` rejects
            // unsupported flavors.
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
                Err(_) => {
                    // `block_in_place` panicked — most likely because
                    // the current runtime is `current_thread` (where
                    // `block_in_place` is not supported). Log a
                    // distinct telemetry signal so the operator knows
                    // the recovery branch was unavailable, then fall
                    // through to the canonical `blocking_lock()`
                    // panic so the regression is still loud.
                    eprintln!(
                        "{{\"level\":\"error\",\"event\":\
                         \"KernelStoreLockSyncRecoveryUnavailable\",\
                         \"reason\":\"block_in_place_panicked\",\
                         \"caller\":\"{file}:{line}\",\
                         \"cumulative_detections\":{cumulative}}}",
                        file = caller.file(),
                        line = caller.line(),
                    );
                    self.conn.blocking_lock()
                }
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
// Four witnesses pin the contract:
//
//   1. POSITIVE — `lock_sync_via_spawn_blocking_is_ok` (always-on):
//      the canonical safe pattern works end-to-end. Counter does
//      NOT increment because `spawn_blocking` lifts us off the
//      runtime worker before `lock_sync` runs.
//
//   2. NEGATIVE — `lock_sync_directly_from_runtime_worker_panics`
//      (`cfg(debug_assertions)`): the debug-build teeth. Calling
//      `lock_sync` from a `#[tokio::test]` body panics with the
//      canonical tokio message.
//
//   3. RECOVERY — `lock_sync_release_build_recovers_and_counts`
//      (`cfg(not(debug_assertions))`): the release-build recovery
//      path. Calling `lock_sync` from a multi-thread runtime worker
//      succeeds (the `block_in_place` hop saves us) AND the counter
//      increments by exactly 1 per detection.
//
//   4. NO-FALSE-POSITIVE — `lock_sync_outside_runtime_does_not_count`
//      (always-on): a sync-thread call (no runtime current) does
//      NOT bump the counter. Recovery sweepers, bootstrap, CLI
//      commands, and pure-sync tests fall into this bucket.
//
// The tests live in this file because the boundary's static state
// (`LOCK_SYNC_FROM_ASYNC_COUNTER`, the emitter `OnceLock`) is
// crate-private; pinning it from another file would require a
// public surface we deliberately want to keep narrow.
#[cfg(test)]
mod async_runtime_safety {
    use super::*;
    use std::sync::atomic::Ordering;
    use std::sync::Arc;

    /// Mutex shared by every test in this module — the counter and
    /// emitter slot are process-global, so serialising the tests
    /// prevents the counter assertions from racing each other.
    /// `tokio::test` does NOT guarantee single-threaded test
    /// execution.
    static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// **INV-KERNEL-STORE-LOCK-SYNC-NEVER-FROM-ASYNC-01** witness
    /// (positive). Drives `lock_sync` from a `#[tokio::test]`
    /// runtime via `tokio::task::spawn_blocking`, mirroring the
    /// canonical safe pattern every iter63 / iter66.1 fix follows.
    /// The lookup completes without panicking AND the boundary
    /// counter is NOT bumped (we are off the runtime worker
    /// thanks to `spawn_blocking`).
    //
    // `clippy::await_holding_lock` is silenced intentionally here:
    // `TEST_LOCK` is a std::sync::Mutex held across `.await` ON
    // PURPOSE — the boundary counter and emitter slot are
    // process-global, so async witnesses MUST serialise against
    // each other. The lock has zero in-test contention (one
    // witness per test, and the runtime is multi-thread with two
    // workers, so the lock-holding task is never starved). The
    // alternative — a tokio::sync::Mutex held across .await —
    // would silence the lint but adds runtime ceremony around a
    // serialisation primitive that is otherwise correct.
    #[allow(clippy::await_holding_lock)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn lock_sync_via_spawn_blocking_is_ok() {
        let _serialise = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset_lock_sync_from_async_count_for_tests();
        let store = Arc::new(Store::open_in_memory().expect("in-memory store"));

        let before = lock_sync_from_async_count();
        let _ok: () = tokio::task::spawn_blocking({
            let store = Arc::clone(&store);
            move || {
                let _g = store.lock_sync();
            }
        })
        .await
        .expect("spawn_blocking join");
        let after = lock_sync_from_async_count();

        assert_eq!(
            before, after,
            "spawn_blocking hop MUST NOT trip the boundary detector"
        );
    }

    /// **INV-KERNEL-STORE-LOCK-SYNC-NEVER-FROM-ASYNC-01** witness
    /// (negative, debug-build only). Calling `lock_sync` directly
    /// from a runtime worker on a debug build panics with the
    /// canonical tokio message so CI catches regressions loudly.
    ///
    /// Gated to debug builds because release builds intentionally
    /// recover via `block_in_place` instead of panicking — see
    /// `lock_sync_release_build_recovers_and_counts` for the
    /// release-build counterpart.
    #[cfg(debug_assertions)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[should_panic(expected = "Cannot block the current thread from within a runtime")]
    async fn lock_sync_directly_from_runtime_worker_panics() {
        let _serialise = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset_lock_sync_from_async_count_for_tests();
        let store = Store::open_in_memory().expect("in-memory store");
        // No `spawn_blocking` hop — iter66.1 production crash shape.
        // `#[track_caller]` on `lock_sync` places the panic site at
        // the call below, so a future reader of the panic location
        // lands in this test rather than in `db.rs:lock_sync`.
        let _g = store.lock_sync();
    }

    /// **INV-KERNEL-STORE-LOCK-SYNC-NEVER-FROM-ASYNC-01** witness
    /// (release recovery + counter increment, release-build only).
    ///
    /// On a multi-thread runtime worker the boundary detects the
    /// async context, emits the eprintln + audit + counter, then
    /// recovers via `tokio::task::block_in_place`. The call
    /// returns a valid guard and the counter increments by
    /// exactly the number of detections.
    // `clippy::await_holding_lock`: see the parallel allow on
    // `lock_sync_via_spawn_blocking_is_ok` above for the
    // rationale. Same `TEST_LOCK` serialisation contract.
    #[allow(clippy::await_holding_lock)]
    #[cfg(not(debug_assertions))]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn lock_sync_release_build_recovers_and_counts() {
        let _serialise = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset_lock_sync_from_async_count_for_tests();
        let store = Store::open_in_memory().expect("in-memory store");

        let before = lock_sync_from_async_count();
        // No `spawn_blocking` hop — boundary recovers and counts.
        {
            let _g = store.lock_sync();
        }
        let after_one = lock_sync_from_async_count();
        assert_eq!(
            after_one,
            before + 1,
            "release-build boundary MUST count exactly one detection",
        );

        // Recovery-functional witness: a second sequential async-
        // context call ALSO succeeds, and the runtime keeps serving
        // work after the recovery. If `block_in_place` orphaned a
        // worker we'd see a hang here rather than a clean second
        // acquisition.
        {
            let _g = store.lock_sync();
        }
        let after_two = lock_sync_from_async_count();
        assert_eq!(
            after_two,
            before + 2,
            "consecutive async-context calls each increment the counter",
        );

        // Runtime-still-healthy probe: spawn a task and await it.
        let probe = tokio::spawn(async { 7u32 }).await.expect("runtime alive");
        assert_eq!(probe, 7);
    }

    /// **INV-KERNEL-STORE-LOCK-SYNC-NEVER-FROM-ASYNC-01** witness
    /// (no-false-positive). A pure-sync caller — no tokio runtime
    /// current on this thread — calls `lock_sync` and the boundary
    /// must NOT bump the counter. Mirrors the recovery sweeper /
    /// bootstrap / CLI call shapes.
    #[test]
    fn lock_sync_outside_runtime_does_not_count() {
        let _serialise = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset_lock_sync_from_async_count_for_tests();
        let store = Store::open_in_memory().expect("in-memory store");
        let before = lock_sync_from_async_count();
        {
            let _g = store.lock_sync();
        }
        let after = lock_sync_from_async_count();
        assert_eq!(
            before, after,
            "pure-sync caller MUST NOT trip the async-context detector",
        );
    }

    /// Pins the emitter installation contract: only the first
    /// `install_lock_sync_from_async_emitter` call wins; a second
    /// install returns `Err(())` so the kernel boot path can detect
    /// double-installation as a bug.
    #[test]
    fn install_emitter_is_idempotent_first_install_wins() {
        // This test relies on the process-global `OnceLock`. We
        // CANNOT reliably reset it between tests, so we run this
        // exactly once per process and use `try_install` semantics
        // to assert idempotency. If another test already installed
        // an emitter, the first call here returns `Err(())` and we
        // still assert the second install returns `Err(())` too —
        // the contract holds either way.
        let _serialise = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let counted: Arc<std::sync::atomic::AtomicU64> =
            Arc::new(std::sync::atomic::AtomicU64::new(0));
        let counted_first = Arc::clone(&counted);
        let _ignored =
            install_lock_sync_from_async_emitter(Arc::new(move |_file, _line, _thread, _cum| {
                counted_first.fetch_add(1, Ordering::Relaxed);
            }));
        // The second install MUST fail — `OnceLock::set` returns
        // `Err` once a value is present.
        let second =
            install_lock_sync_from_async_emitter(Arc::new(move |_file, _line, _thread, _cum| {
                counted.fetch_add(1, Ordering::Relaxed);
            }));
        assert!(
            second.is_err(),
            "second emitter install MUST fail per OnceLock contract",
        );
    }
}

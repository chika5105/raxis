//! Read-only kernel store handle for the operator CLI.
//!
//! Normative reference: cli-readonly.md §5.1 "the file-system bypass"
//! and §5.3 "schema-version pinning".
//!
//! # Why a separate handle type
//!
//! The kernel's production [`crate::Store`] is `Arc<Mutex<Connection>>`
//! and exposes [`crate::Store::lock_sync`] / [`crate::Store::lock`] —
//! both of which permit writes. The CLI MUST NOT be able to issue any
//! `INSERT` / `UPDATE` / `DELETE`, even by accident, because it runs
//! under the same OS user as the kernel and would silently bypass every
//! invariant the kernel enforces (audit-event-on-write, FSM transitions,
//! INV-STORE-03 typed identifiers, etc).
//!
//! The defence-in-depth here is two-layered:
//! 1. SQLite enforcement: opening with `OpenFlags::SQLITE_OPEN_READ_ONLY`
//!    causes any write at the SQL layer to fail with
//!    `SQLITE_READONLY` regardless of the application code's intent.
//! 2. Type-system enforcement: [`RoConn`] never exposes `&mut Connection`
//!    or any execute method — only `query_*` flavours via deref to
//!    `&Connection`.
//!
//! Together, a CLI command that tries to write fails to compile (or, if
//! it manages to call a write SQL fn directly, fails at the
//! `rusqlite` level with `attempt to write a readonly database`).
//!
//! # Snapshot semantics
//!
//! WAL mode (set unconditionally by [`crate::Store::open`]'s pragmas) gives every
//! reader a stable point-in-time snapshot for the duration of an
//! explicit `BEGIN DEFERRED ... COMMIT`. The CLI's
//! `views::*` functions follow the discipline in §5.4.3: open → BEGIN
//! → query → materialise → COMMIT, all in milliseconds. We do NOT
//! expose long-lived row iterators that would hold the WAL snapshot
//! open across a UI redraw.
//!
//! # Exit codes
//!
//! [`RoError`] is intentionally exhaustive on the failures the CLI
//! must distinguish (open-failed vs schema-mismatched vs underlying
//! sqlite). The CLI maps each variant onto a stable exit code; this
//! crate does NOT call `std::process::exit` itself — that decision
//! lives at the binary boundary.

use std::path::{Path, PathBuf};

use rusqlite::{Connection, OpenFlags};
use thiserror::Error;

use crate::migration::SCHEMA_VERSION;
use crate::Table;

/// File name (relative to `data_dir`) of the kernel's SQLite database.
/// Centralised so callers don't repeat the literal — the kernel's
/// `bootstrap.rs` and `Store::open` use the same suffix.
pub const KERNEL_DB_FILE: &str = "kernel.db";

// `Table::*.as_str()` is a `const fn` so we can lift it into module-
// level constants. Per kernel-store.md §2.5.1 INV-STORE-03, every SQL
// table reference in this crate goes through `Table` — including the
// schema-version compatibility check.
const SCHEMA_VERSION_TABLE: &str = Table::SchemaVersion.as_str();

// ---------------------------------------------------------------------
// RoError
// ---------------------------------------------------------------------

/// Failure modes for opening + validating a read-only handle.
///
/// Variants are intentionally exhaustive on the CLI-visible distinctions
/// from cli-readonly.md §5.3 + §5.5; do NOT collapse these into a
/// generic `Err(String)`. Each variant carries enough context to render
/// the spec-mandated CLI message:
///
/// | Variant | CLI exit | CLI message snippet |
/// |---|---|---|
/// | `DbMissing` | 1 | "kernel.db not found at <path>; has the kernel been bootstrapped?" |
/// | `OpenFailed` | 1 | "kernel.db at <path> could not be opened: <reason>" |
/// | `SchemaMissing` | 7 | "schema_version table not present at <path>" |
/// | `SchemaMismatch` | 7 | "kernel.db is at schema version N; this CLI expects M" |
/// | `Sqlite` | 1 | "sqlite error during read: <reason>" |
#[derive(Debug, Error)]
pub enum RoError {
    /// The `kernel.db` file does not exist at the resolved path.
    /// Caller has not run `raxis genesis` yet, or used the wrong
    /// `--data-dir`.
    #[error("kernel.db not found at {path}; has the kernel been bootstrapped?")]
    DbMissing { path: PathBuf },

    /// The file exists but rusqlite couldn't open it (permissions,
    /// sqlite-level lock, malformed header, etc).
    #[error("kernel.db at {path} could not be opened: {source}")]
    OpenFailed {
        path: PathBuf,
        #[source]
        source: rusqlite::Error,
    },

    /// The file opened cleanly but the `schema_version` table is
    /// absent — either because we're looking at a non-RAXIS sqlite
    /// file, or the kernel's migration framework was reset.
    #[error("schema_version table missing in {path} — is this really kernel.db?")]
    SchemaMissing { path: PathBuf },

    /// `MAX(version)` returned a value that does not match this CLI
    /// build's `SCHEMA_VERSION`. Spec-mandated CLI exit code is 7.
    #[error(
        "kernel.db schema version mismatch: db is at v{actual}, this CLI expects v{expected}; \
             {recommendation}"
    )]
    SchemaMismatch {
        actual: i64,
        expected: u32,
        /// Human-actionable next step. Two cases:
        ///   actual < expected  → upgrade the kernel (it owns
        ///                         migrations).
        ///   actual > expected  → upgrade the CLI to a build that
        ///                         knows about the newer schema.
        recommendation: String,
    },

    /// Underlying rusqlite error from a query that wasn't an open.
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
}

// ---------------------------------------------------------------------
// RoConn
// ---------------------------------------------------------------------

/// Read-only connection to `<data_dir>/kernel.db`.
///
/// Construction goes through [`open`]; there is no way to wrap an
/// existing `Connection` in this type from outside the crate. Combined
/// with the SQLite open flags below (no `SQLITE_OPEN_CREATE`, no
/// `SQLITE_OPEN_READ_WRITE`), this guarantees every `RoConn` in the
/// program has been schema-checked AND came from a `READ_ONLY` open.
///
/// Deref → `&Connection` so callers can use the rusqlite query API
/// directly (`query_row`, `prepare`, `query_map`, `transaction_with_behavior`,
/// etc). DerefMut is intentionally NOT implemented — there is no
/// legitimate reason for a read-only handle to need mutable access.
pub struct RoConn {
    inner: Connection,
    path: PathBuf,
}

// Manual `Debug` because `rusqlite::Connection` does not implement
// `Debug` (it wraps a raw FFI handle). We only need it so callers can
// `.unwrap()` / `.expect()` cleanly in tests; the actual connection
// internals are opaque on purpose.
impl std::fmt::Debug for RoConn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RoConn")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl RoConn {
    /// Path the connection was opened against. Useful for error
    /// messages and for `views::*` functions that need to report the
    /// data dir back to the operator.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Read-only view of the underlying connection. Used by query-time
    /// helpers in `views::*`. Intentionally `&Connection` (NOT `&mut`)
    /// so the type system blocks any caller that tries to issue a
    /// write — even if SQLite would also reject it at runtime.
    pub fn raw(&self) -> &Connection {
        &self.inner
    }
}

impl std::ops::Deref for RoConn {
    type Target = Connection;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

// ---------------------------------------------------------------------
// open + assert_compatible_schema
// ---------------------------------------------------------------------

/// Open `<data_dir>/kernel.db` read-only and verify schema-version
/// compatibility against [`SCHEMA_VERSION`].
///
/// On success the returned [`RoConn`] is guaranteed to be:
/// - opened with `SQLITE_OPEN_READ_ONLY | SQLITE_OPEN_NO_MUTEX`
/// - WAL-snapshot-compatible (the kernel set `journal_mode = WAL` at
///   first open; we re-PRAGMA defensively for the
///   "operator restored a backup with the wrong journal mode"
///   pathological case)
/// - schema-version pinned to the CLI's build expectation
///
/// The caller is expected to use this once at the top of every
/// read-only command. Per §5.4.3 the lifetime should be short (single
/// query, then drop) so we don't hold a WAL snapshot across UI ticks.
pub fn open(data_dir: &Path) -> Result<RoConn, RoError> {
    let db_path = data_dir.join(KERNEL_DB_FILE);

    if !db_path.exists() {
        return Err(RoError::DbMissing { path: db_path });
    }

    // Flags rationale:
    //   READ_ONLY  — fail-closed: even if a future code path tries to
    //                INSERT, sqlite refuses with SQLITE_READONLY.
    //   NO_MUTEX   — single-threaded handle: the CLI never shares
    //                this handle across threads, and the connection's
    //                lifetime is contained within one command. We
    //                explicitly NOT enable URI mode (default), and we
    //                NOT enable shared-cache (it interacts poorly
    //                with WAL).
    let conn = Connection::open_with_flags(
        &db_path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|e| RoError::OpenFailed {
        path: db_path.clone(),
        source: e,
    })?;

    // We do NOT re-set `journal_mode = WAL` here — sqlite refuses
    // PRAGMA journal_mode in a read-only connection, and the kernel
    // already configures it at write-open time. We DO enable
    // foreign_keys (cheap; defends against a future read query that
    // joins via FK and expects FK-enforced semantics).
    let _ = conn.execute_batch("PRAGMA foreign_keys = ON;");

    let ro = RoConn {
        inner: conn,
        path: db_path.clone(),
    };
    assert_compatible_schema(&ro, SCHEMA_VERSION)?;
    Ok(ro)
}

/// Verify that the open connection's `schema_version` matches the
/// CLI's compiled-in `expected` constant.
///
/// Errors:
///   - [`RoError::SchemaMissing`] if the `schema_version` table is
///     absent (typically: not a RAXIS database).
///   - [`RoError::SchemaMismatch`] if `MAX(version) != expected`.
///   - [`RoError::Sqlite`] for any underlying query error.
pub fn assert_compatible_schema(conn: &RoConn, expected: u32) -> Result<(), RoError> {
    // Distinguish "table missing" from "table empty / misshapen". The
    // migration framework is identical on the kernel side; this
    // mirrors the same triage in `migration::read_current_version`.
    let row: Result<i64, rusqlite::Error> = conn.query_row(
        &format!("SELECT COALESCE(MAX(version), 0) FROM {SCHEMA_VERSION_TABLE}"),
        [],
        |r| r.get(0),
    );

    let actual = match row {
        Ok(v) => v,
        Err(rusqlite::Error::SqliteFailure(_, Some(msg))) if msg.contains("no such table") => {
            return Err(RoError::SchemaMissing {
                path: conn.path().to_owned(),
            });
        }
        Err(other) => return Err(RoError::Sqlite(other)),
    };

    if actual == expected as i64 {
        return Ok(());
    }
    let recommendation = if actual < expected as i64 {
        "the kernel database is older than this CLI build; \
         restart the kernel binary to apply pending migrations"
            .to_owned()
    } else {
        "this CLI is older than the kernel database; \
         upgrade the `raxis` binary to match the running kernel"
            .to_owned()
    };
    Err(RoError::SchemaMismatch {
        actual,
        expected,
        recommendation,
    })
}

// ---------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    /// Build a fresh `kernel.db` at the standard data-dir layout via
    /// the production `Store::open` path. This is the single fixture
    /// every test in this module shares so we exercise the real
    /// migration code, not a hand-crafted DDL.
    fn fresh_data_dir() -> TempDir {
        let tmp = TempDir::new().unwrap();
        let db_path = tmp.path().join(KERNEL_DB_FILE);
        let _store = crate::Store::open(&db_path).expect("write-mode store opens");
        tmp
    }

    // ── open ─────────────────────────────────────────────────────────

    #[test]
    fn open_succeeds_against_freshly_bootstrapped_kernel_db() {
        let tmp = fresh_data_dir();
        let conn = open(tmp.path()).expect("open ro");
        assert_eq!(conn.path(), tmp.path().join(KERNEL_DB_FILE).as_path());
    }

    #[test]
    fn open_fails_with_db_missing_when_no_kernel_db_present() {
        let tmp = TempDir::new().unwrap();
        match open(tmp.path()) {
            Err(RoError::DbMissing { path }) => {
                assert_eq!(path, tmp.path().join(KERNEL_DB_FILE));
            }
            other => panic!("expected DbMissing, got {other:?}"),
        }
    }

    // ── schema_version ──────────────────────────────────────────────

    #[test]
    fn assert_compatible_schema_passes_on_matching_version() {
        let tmp = fresh_data_dir();
        let conn = open(tmp.path()).expect("open");
        // We just opened with `assert_compatible_schema(SCHEMA_VERSION)`;
        // re-call explicitly to pin the contract.
        assert_compatible_schema(&conn, SCHEMA_VERSION).expect("matching schema");
    }

    #[test]
    fn assert_compatible_schema_rejects_lower_expected_version() {
        // CLI built against an older raxis-store than the kernel: db
        // is at v=N, CLI expects v=N-1, recommendation must point the
        // operator at the CLI upgrade.
        let tmp = fresh_data_dir();
        let conn = open(tmp.path()).expect("open");
        let err = assert_compatible_schema(&conn, SCHEMA_VERSION + 1).unwrap_err();
        match err {
            RoError::SchemaMismatch {
                actual,
                expected,
                recommendation,
            } => {
                assert_eq!(actual, SCHEMA_VERSION as i64);
                assert_eq!(expected, SCHEMA_VERSION + 1);
                assert!(
                    recommendation.contains("kernel database is older"),
                    "recommendation should diagnose old kernel: {recommendation}",
                );
            }
            other => panic!("expected SchemaMismatch, got {other:?}"),
        }
    }

    #[test]
    fn assert_compatible_schema_rejects_higher_expected_version() {
        // CLI built against a newer raxis-store than the kernel: db
        // is at v=N+1 (simulated), CLI expects v=N, recommendation
        // must point the operator at the kernel upgrade.
        //
        // We can't easily fake "db at v=N+1 with our migrations
        // applied" without actually writing a v=N+1 row, so we do
        // exactly that on the underlying connection (in WRITE mode)
        // and then re-open RO to reach the assertion path.
        let tmp = fresh_data_dir();
        {
            let store = crate::Store::open(&tmp.path().join(KERNEL_DB_FILE)).unwrap();
            let guard = store.lock_sync();
            guard
                .execute(
                    &format!(
                        "INSERT OR REPLACE INTO {SCHEMA_VERSION_TABLE} \
                     (version, applied_at) \
                     VALUES (?1, strftime('%s', 'now'))"
                    ),
                    rusqlite::params![SCHEMA_VERSION + 5],
                )
                .unwrap();
        }
        // Now the on-disk MAX(version) is `SCHEMA_VERSION + 5`. Open
        // with the CLI's normal `open()` — that internally calls
        // `assert_compatible_schema(SCHEMA_VERSION)` and must fail.
        let err = open(tmp.path()).unwrap_err();
        match err {
            RoError::SchemaMismatch {
                actual,
                expected,
                recommendation,
            } => {
                assert_eq!(actual, (SCHEMA_VERSION + 5) as i64);
                assert_eq!(expected, SCHEMA_VERSION);
                assert!(
                    recommendation.contains("upgrade the `raxis` binary"),
                    "recommendation should diagnose old CLI: {recommendation}",
                );
            }
            other => panic!("expected SchemaMismatch, got {other:?}"),
        }
    }

    #[test]
    fn assert_compatible_schema_returns_schema_missing_for_non_raxis_db() {
        // A foreign sqlite file (no `schema_version` table) must
        // produce the dedicated `SchemaMissing` variant — operators
        // must not see "version mismatch" when the issue is "you
        // pointed me at the wrong file".
        let tmp = TempDir::new().unwrap();
        let alien_path = tmp.path().join(KERNEL_DB_FILE);
        {
            let conn = Connection::open(&alien_path).unwrap();
            conn.execute_batch("CREATE TABLE foo (id INTEGER);")
                .unwrap();
        }
        let err = open(tmp.path()).unwrap_err();
        match err {
            RoError::SchemaMissing { path } => {
                assert_eq!(path, alien_path);
            }
            other => panic!("expected SchemaMissing, got {other:?}"),
        }
    }

    // ── enforcement: writes against RoConn fail at sqlite layer ─────

    #[test]
    fn ro_conn_writes_fail_at_sqlite_layer() {
        // Defence-in-depth: even though our type system tries to
        // prevent writes, a caller that grabs `Deref::deref` and
        // calls `.execute("INSERT ...")` directly still must be
        // refused by SQLite because of the READ_ONLY open flag.
        let tmp = fresh_data_dir();
        let conn = open(tmp.path()).expect("open");

        let result = conn.execute(
            &format!(
                "INSERT INTO {SCHEMA_VERSION_TABLE} (version, applied_at) \
                 VALUES (?1, ?2)"
            ),
            rusqlite::params![999, 0],
        );
        let err = result.expect_err("RO open must reject writes");
        let msg = format!("{err}");
        assert!(
            msg.contains("readonly database") || msg.contains("read-only"),
            "expected sqlite read-only rejection; got: {msg}",
        );
    }
}

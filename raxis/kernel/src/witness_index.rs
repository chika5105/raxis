// raxis-kernel::witness_index — Witness blob store + SQL index facade.
//
// Normative reference: kernel-core.md §2.3 `src/witness_index.rs`.
//
// All kernel code that reads or writes witness records MUST go through this
// module. No other module may access `witness_records` SQL table or the
// `$RAXIS_DATA_DIR/witness/` filesystem directory directly.
//
// Write order contract (crash safety):
//   1. Write blob to filesystem (content-addressed: path = sha256 of content)
//   2. Insert SQL index row in witness_records
// If step 1 succeeds but step 2 fails → orphaned blob (no index row).
// startup_check detects and reports orphans. Safe because lookup requires
// an index row; an orphaned blob is invisible to queries.

use std::path::Path;

use raxis_crypto::token::sha256_hex;
use raxis_store::{Store, Table};
use rusqlite::OptionalExtension;
use thiserror::Error;

const WR: &str = Table::WitnessRecords.as_str();

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum WitnessError {
    #[error("blob SHA-256 mismatch: claimed {claimed}, computed {computed}")]
    BlobHashMismatch { claimed: String, computed: String },

    #[error("witness blob not found: {sha256}")]
    BlobNotFound { sha256: String },

    #[error("SQL error: {0}")]
    Sql(#[from] rusqlite::Error),

    #[error("IO error writing witness blob {path}: {source}")]
    Io {
        path: String,
        source: std::io::Error,
    },

    #[error("store error: {0}")]
    Store(#[from] raxis_store::StoreError),
}

// ---------------------------------------------------------------------------
// WitnessRecord — matches witness_records columns
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct WitnessRecord {
    pub verifier_run_id: String,
    pub evaluation_sha: String,
    pub task_id: String,
    pub gate_type: String,
    pub result_class: ResultClass,
    pub blob_sha256: String,
    pub blob_path: String,
    pub recorded_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResultClass {
    Pass,
    Fail,
    Inconclusive,
}

impl ResultClass {
    pub fn as_str(&self) -> &'static str {
        match self {
            ResultClass::Pass => "Pass",
            ResultClass::Fail => "Fail",
            ResultClass::Inconclusive => "Inconclusive",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "Pass" => Some(ResultClass::Pass),
            "Fail" => Some(ResultClass::Fail),
            "Inconclusive" => Some(ResultClass::Inconclusive),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// WitnessStartupReport
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub struct WitnessStartupReport {
    pub orphaned_blobs: usize,
    pub orphaned_index_rows: usize,
}

// ---------------------------------------------------------------------------
// write
// ---------------------------------------------------------------------------

/// Write the witness blob to the content-addressed FS store.
///
/// Pure FS operation — no SQL, no mutex acquisition. Idempotent on
/// `<witness_dir>/<blob_sha256>` (no overwrite). Verifies the
/// claimed/computed blob hash before writing so a corrupted
/// content-address can never collide with a real witness.
///
/// Splitting this off from the SQL portion lets the witness handler do
/// (a) FS write outside the mutex, (b) SQL writes (witness index +
/// token consume) inside one transaction — closing the
/// validate-write-consume race documented in `kernel-store.md`
/// §2.5.1.1 Pattern C.
pub fn write_blob_to_disk(
    record: &WitnessRecord,
    blob: &[u8],
    witness_dir: &Path,
) -> Result<(), WitnessError> {
    let computed = sha256_hex(blob);
    if computed != record.blob_sha256 {
        return Err(WitnessError::BlobHashMismatch {
            claimed: record.blob_sha256.clone(),
            computed,
        });
    }

    let blob_path = witness_dir.join(&record.blob_sha256);
    if !blob_path.exists() {
        std::fs::write(&blob_path, blob).map_err(|e| WitnessError::Io {
            path: blob_path.display().to_string(),
            source: e,
        })?;
    }
    Ok(())
}

/// Insert the witness index row inside an existing transaction.
///
/// **INV-STORE-02 (kernel-store.md §2.5.1.1 Pattern C):** the canonical
/// witness commit path runs `validate_verifier_token_in_tx` →
/// `insert_witness_index_in_tx` → `consume_verifier_token_in_tx` all
/// inside one `conn.transaction()`. If consume reports 0 rows (token
/// expired by a concurrent reconcile, or already consumed by a
/// duplicate verifier callback), the entire transaction rolls back
/// including this INSERT — preventing the case where the gate
/// evaluator sees a witness for a callback the kernel told its
/// producer was rejected (INV-INIT-08).
///
/// `INSERT OR IGNORE` keeps duplicate `verifier_run_id` (PK) safe
/// against the concurrent-double-callback case.
pub fn insert_witness_index_in_tx(
    conn: &rusqlite::Connection,
    record: &WitnessRecord,
    recorded_at: i64,
) -> Result<(), WitnessError> {
    conn.execute(
        &format!(
            "INSERT OR IGNORE INTO {WR}
                (verifier_run_id, evaluation_sha, task_id, gate_type,
                 result_class, blob_sha256, blob_path, recorded_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)"
        ),
        rusqlite::params![
            record.verifier_run_id,
            record.evaluation_sha,
            record.task_id,
            record.gate_type,
            record.result_class.as_str(),
            record.blob_sha256,
            record.blob_path,
            recorded_at,
        ],
    )?;
    Ok(())
}

// ---------------------------------------------------------------------------
// lookup
// ---------------------------------------------------------------------------

/// Look up a witness record by (evaluation_sha, task_id, gate_type).
/// If `verifier_run_id` is Some, returns that specific run.
/// If None, returns the most recently recorded row for the triple.
pub fn lookup(
    evaluation_sha: &str,
    task_id: &str,
    gate_type: &str,
    verifier_run_id: Option<&str>,
    store: &Store,
) -> Result<Option<WitnessRecord>, WitnessError> {
    let conn = store.lock_sync();
    let row = if let Some(run_id) = verifier_run_id {
        conn.query_row(
            &format!(
                "SELECT verifier_run_id, evaluation_sha, task_id, gate_type,
                        result_class, blob_sha256, blob_path, recorded_at
                 FROM {WR} WHERE verifier_run_id = ?1"
            ),
            rusqlite::params![run_id],
            parse_row,
        )
        .optional()?
    } else {
        conn.query_row(
            &format!(
                "SELECT verifier_run_id, evaluation_sha, task_id, gate_type,
                        result_class, blob_sha256, blob_path, recorded_at
                 FROM {WR}
                 WHERE evaluation_sha = ?1 AND task_id = ?2 AND gate_type = ?3
                 ORDER BY recorded_at DESC
                 LIMIT 1"
            ),
            rusqlite::params![evaluation_sha, task_id, gate_type],
            parse_row,
        )
        .optional()?
    };
    Ok(row)
}

fn parse_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<WitnessRecord> {
    let result_class_str: String = row.get(4)?;
    // INV-WITNESS-INDEX-RESULT-CLASS-EXHAUSTIVE-01 — refuse to coerce an
    // unknown `result_class` to `Inconclusive`. A corrupt or future-version
    // string here is a kernel-bug or migration-drift signal, not a
    // legitimate "treat as inconclusive" verdict. Surfacing the parse
    // failure as a `FromSqlError` lets the lookup return a real error
    // instead of silently degrading a possibly-failed witness into the
    // inconclusive bucket.
    let result_class = ResultClass::from_str(&result_class_str).ok_or_else(|| {
        rusqlite::Error::FromSqlConversionFailure(
            4,
            rusqlite::types::Type::Text,
            Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("unknown witness result_class: {result_class_str:?}"),
            )),
        )
    })?;
    Ok(WitnessRecord {
        verifier_run_id: row.get(0)?,
        evaluation_sha: row.get(1)?,
        task_id: row.get(2)?,
        gate_type: row.get(3)?,
        result_class,
        blob_sha256: row.get(5)?,
        blob_path: row.get(6)?,
        recorded_at: row.get(7)?,
    })
}

// ---------------------------------------------------------------------------
// get_blob
// ---------------------------------------------------------------------------

/// Read raw blob bytes from the filesystem.
/// Used by audit tooling and any path needing raw verifier output.
pub fn get_blob(blob_sha256: &str, witness_dir: &Path) -> Result<Vec<u8>, WitnessError> {
    let path = witness_dir.join(blob_sha256);
    std::fs::read(&path).map_err(|_| WitnessError::BlobNotFound {
        sha256: blob_sha256.to_owned(),
    })
}

// ---------------------------------------------------------------------------
// startup_check
// ---------------------------------------------------------------------------

/// Detect orphaned blobs (file exists, no index row) and orphaned index rows
/// (row exists, file missing). Does NOT delete anything — reports counts only.
pub fn startup_check(
    store: &Store,
    witness_dir: &Path,
) -> Result<WitnessStartupReport, WitnessError> {
    // Collect all blob files.
    let mut blob_files: std::collections::HashSet<String> = std::collections::HashSet::new();
    if witness_dir.exists() {
        for entry in std::fs::read_dir(witness_dir).map_err(|e| WitnessError::Io {
            path: witness_dir.display().to_string(),
            source: e,
        })? {
            let entry = entry.map_err(|e| WitnessError::Io {
                path: witness_dir.display().to_string(),
                source: e,
            })?;
            if let Some(name) = entry.file_name().to_str() {
                blob_files.insert(name.to_owned());
            }
        }
    }

    // Collect all blob_sha256 values from the SQL index.
    let conn = store.lock_sync();
    let select_blobs_sql = format!("SELECT DISTINCT blob_sha256 FROM {WR}");
    let mut stmt = conn.prepare(&select_blobs_sql)?;
    let index_shas: Vec<String> = stmt
        .query_map([], |row| row.get(0))?
        .filter_map(|r| r.ok())
        .collect();
    let index_set: std::collections::HashSet<String> = index_shas.iter().cloned().collect();

    // Orphaned blobs: file exists but not in index.
    let orphaned_blobs = blob_files
        .iter()
        .filter(|f| !index_set.contains(*f))
        .count();

    // Orphaned index rows: SHA in index but file missing.
    let orphaned_index_rows = index_shas
        .iter()
        .filter(|sha| !blob_files.contains(*sha))
        .count();

    Ok(WitnessStartupReport {
        orphaned_blobs,
        orphaned_index_rows,
    })
}

// ---------------------------------------------------------------------------
// Unit tests (in-memory store)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir() -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!(
            "raxis-witness-test-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .subsec_nanos()
        ));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn write_blob_to_disk_rejects_hash_mismatch() {
        let base = temp_dir();
        let blob_dir = base.join("blobs");
        std::fs::create_dir_all(&blob_dir).unwrap();

        let blob = b"some witness blob";
        let wrong_sha = "a".repeat(64); // wrong hash

        let rec = WitnessRecord {
            verifier_run_id: "run1".to_owned(),
            evaluation_sha: "aaaa".to_owned(),
            task_id: "t1".to_owned(),
            gate_type: "TestGate".to_owned(),
            result_class: ResultClass::Pass,
            blob_sha256: wrong_sha,
            blob_path: "does_not_matter".to_owned(),
            recorded_at: 0,
        };

        let result = write_blob_to_disk(&rec, blob, &blob_dir);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            WitnessError::BlobHashMismatch { .. }
        ));

        std::fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn get_blob_missing_returns_err() {
        let dir = temp_dir();
        let result = get_blob("nonexistent_sha", &dir);
        assert!(matches!(
            result.unwrap_err(),
            WitnessError::BlobNotFound { .. }
        ));
        std::fs::remove_dir_all(&dir).ok();
    }
}

// ---------------------------------------------------------------------------
// Async-runtime safety witness — INV-WITNESS-INDEX-LOOKUP-ASYNC-SAFE-01.
// ---------------------------------------------------------------------------
//
// iter63 realistic_session_lifecycle hit
// `crates/store/src/db.rs:125` "Cannot block the current thread from
// within a runtime" the first time `gates::evaluate_claims` (async,
// runs on a tokio runtime worker) reached `gates::witness::lookup` →
// `witness_index::lookup` → `Store::lock_sync` →
// `tokio::sync::Mutex::blocking_lock`. The kernel daemon crashed
// mid-planner-stream and the dashboard at :19820 went unreachable.
//
// The broader fix lives at the `evaluate_claims` boundary (a single
// `tokio::task::spawn_blocking` wraps every sync DB-touching step;
// see `kernel::gates::evaluate_pre_spawn`). This test pins the
// canonical safe call pattern at the inner facade so a future change
// to `witness_index::lookup` (e.g. removing this comment block or
// inlining the lookup into a fn that gets called raw from async) can
// never regress the invariant without the regression test going red.

#[cfg(test)]
mod async_runtime_safety {
    use std::sync::Arc;

    use raxis_store::Store;

    use super::{lookup, WitnessError, WitnessRecord};

    /// **INV-WITNESS-INDEX-LOOKUP-ASYNC-SAFE-01** witness (positive).
    ///
    /// Drives `witness_index::lookup` from a `#[tokio::test]` async
    /// runtime via the canonical `tokio::task::spawn_blocking` hop.
    /// Pre-fix the broader bug (`evaluate_claims` calling this
    /// function directly on a runtime worker) panicked; post-fix the
    /// canonical wrapping must work and return `Ok(None)` against
    /// an empty index (no rows seeded — the test isolates the
    /// async-safety question from FK / schema concerns).
    #[tokio::test]
    async fn lookup_from_runtime_worker_via_spawn_blocking_is_ok() {
        let store = Arc::new(Store::open_in_memory().expect("in-memory store"));
        let evaluation_sha = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
        let task_id = "task-async-safe";
        let gate_type = "TestGate";

        let result: Result<Option<WitnessRecord>, WitnessError> = tokio::task::spawn_blocking({
            let store = Arc::clone(&store);
            move || lookup(evaluation_sha, task_id, gate_type, None, &store)
        })
        .await
        .expect("lookup spawn_blocking join");

        // The lookup must complete without panicking and return Ok
        // (empty index ⇒ no record). The point of this test is that
        // the call returned at all — the iter63 bug shape was an
        // unconditional panic before the function body could query
        // the empty table.
        let record = result.expect("lookup must not error");
        assert!(record.is_none(), "no rows seeded → no record returned");
    }

    /// **INV-WITNESS-INDEX-LOOKUP-ASYNC-SAFE-01** witness (negative).
    ///
    /// Pins the underlying iter63 bug shape: invoking
    /// `witness_index::lookup` **directly** from a tokio runtime
    /// worker triggers `Store::lock_sync` → `blocking_lock` →
    /// "Cannot block the current thread from within a runtime"
    /// panic. The kernel's production fix is to wrap the call chain
    /// in `spawn_blocking` (see
    /// `kernel::gates::evaluate_pre_spawn`); this test documents
    /// **why** that wrapping is mandatory so a future refactor that
    /// silently drops the `spawn_blocking` reintroduces the iter63
    /// crash via this test going green-then-removed rather than
    /// going green-then-shipped.
    #[tokio::test]
    #[should_panic(expected = "Cannot block the current thread from within a runtime")]
    async fn lookup_directly_from_runtime_worker_panics() {
        let store = Store::open_in_memory().expect("in-memory store");
        // No `spawn_blocking` hop — this is the iter63 call shape.
        // The unused binding is intentional: the panic fires inside
        // `lookup` before it returns.
        let _ = lookup(
            "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            "task-async-unsafe",
            "TestGate",
            None,
            &store,
        );
    }
}

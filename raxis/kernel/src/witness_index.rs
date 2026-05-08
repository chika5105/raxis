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
use raxis_types::unix_now_secs;
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
    Io { path: String, source: std::io::Error },

    #[error("store error: {0}")]
    Store(#[from] raxis_store::StoreError),
}

// ---------------------------------------------------------------------------
// WitnessRecord — matches witness_records columns
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct WitnessRecord {
    pub verifier_run_id: String,
    pub evaluation_sha:  String,
    pub task_id:         String,
    pub gate_type:       String,
    pub result_class:    ResultClass,
    pub blob_sha256:     String,
    pub blob_path:       String,
    pub recorded_at:     i64,
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
            ResultClass::Pass        => "Pass",
            ResultClass::Fail        => "Fail",
            ResultClass::Inconclusive => "Inconclusive",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "Pass"        => Some(ResultClass::Pass),
            "Fail"        => Some(ResultClass::Fail),
            "Inconclusive" => Some(ResultClass::Inconclusive),
            _             => None,
        }
    }
}

// ---------------------------------------------------------------------------
// WitnessStartupReport
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub struct WitnessStartupReport {
    pub orphaned_blobs:      usize,
    pub orphaned_index_rows: usize,
}

// ---------------------------------------------------------------------------
// write
// ---------------------------------------------------------------------------

/// Write a witness record.
///
/// - Verifies that `sha256(blob) == record.blob_sha256`.
/// - Writes blob to `<witness_dir>/<blob_sha256>` (idempotent if file exists).
/// - Inserts SQL index row into `witness_records`.
///
/// Returns `Ok(verifier_run_id)` on success.
///
/// **Standalone wrapper** that opens its own mutex acquisition for the SQL
/// INSERT. New code paths that need to atomically commit the witness +
/// consume the verifier token MUST use `write_blob_to_disk` followed by
/// `insert_witness_index_in_tx` inside the same `conn.transaction()` —
/// see `kernel-store.md` §2.5.1.1 Pattern C and INV-INIT-08 for why.
/// Kept for callers (mostly tests) that don't need to compose with a
/// token-consume in the same transaction.
pub fn write(
    record: &WitnessRecord,
    blob: &[u8],
    witness_dir: &Path,
    store: &Store,
) -> Result<String, WitnessError> {
    write_blob_to_disk(record, blob, witness_dir)?;

    let recorded_at = unix_now_secs();
    let conn = store.lock_sync();
    insert_witness_index_in_tx(&conn, record, recorded_at)?;

    Ok(record.verifier_run_id.clone())
}

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
    record:      &WitnessRecord,
    blob:        &[u8],
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
    conn:        &rusqlite::Connection,
    record:      &WitnessRecord,
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
    evaluation_sha:  &str,
    task_id:         &str,
    gate_type:       &str,
    verifier_run_id: Option<&str>,
    store:           &Store,
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
    let result_class = ResultClass::from_str(&result_class_str)
        .unwrap_or(ResultClass::Inconclusive);
    Ok(WitnessRecord {
        verifier_run_id: row.get(0)?,
        evaluation_sha:  row.get(1)?,
        task_id:         row.get(2)?,
        gate_type:       row.get(3)?,
        result_class,
        blob_sha256:     row.get(5)?,
        blob_path:       row.get(6)?,
        recorded_at:     row.get(7)?,
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
    store:       &Store,
    witness_dir: &Path,
) -> Result<WitnessStartupReport, WitnessError> {
    // Collect all blob files.
    let mut blob_files: std::collections::HashSet<String> = std::collections::HashSet::new();
    if witness_dir.exists() {
        for entry in std::fs::read_dir(witness_dir)
            .map_err(|e| WitnessError::Io { path: witness_dir.display().to_string(), source: e })?
        {
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
    let select_blobs_sql =
        format!("SELECT DISTINCT blob_sha256 FROM {WR}");
    let mut stmt = conn.prepare(&select_blobs_sql)?;
    let index_shas: Vec<String> = stmt
        .query_map([], |row| row.get(0))?
        .filter_map(|r| r.ok())
        .collect();
    let index_set: std::collections::HashSet<String> = index_shas.iter().cloned().collect();

    // Orphaned blobs: file exists but not in index.
    let orphaned_blobs = blob_files.iter().filter(|f| !index_set.contains(*f)).count();

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
    fn write_rejects_hash_mismatch() {
        let base = temp_dir();
        let db_path = base.join("kernel.db");
        let store = Store::open(&db_path).unwrap();
        let blob_dir = base.join("blobs");
        std::fs::create_dir_all(&blob_dir).unwrap();

        let blob = b"some witness blob";
        let wrong_sha = "a".repeat(64); // wrong hash

        let rec = WitnessRecord {
            verifier_run_id: "run1".to_owned(),
            evaluation_sha:  "aaaa".to_owned(),
            task_id:         "t1".to_owned(),
            gate_type:       "TestGate".to_owned(),
            result_class:    ResultClass::Pass,
            blob_sha256:     wrong_sha,
            blob_path:       "does_not_matter".to_owned(),
            recorded_at:     0,
        };

        let result = write(&rec, blob, &blob_dir, &store);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), WitnessError::BlobHashMismatch { .. }));

        std::fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn get_blob_missing_returns_err() {
        let dir = temp_dir();
        let result = get_blob("nonexistent_sha", &dir);
        assert!(matches!(result.unwrap_err(), WitnessError::BlobNotFound { .. }));
        std::fs::remove_dir_all(&dir).ok();
    }
}

//! Witness query catalog (cli-readonly.md §5.4.1 `witnesses.rs`).
//!
//! Surface:
//!   * [`for_task`] — witness rows for one task, newest-first.
//!     Powers `raxis inspect <task_id>`'s "Witnesses (N):" block
//!     and `raxis witnesses <task_id>` (which is a strict subset).
//!
//! v1 does NOT join across `verifier_run_tokens.token_hash` or read
//! the on-disk blob files — those are filesystem reads outside this
//! module's read-only contract. The `raxis inspect` command renders
//! the index metadata only and points operators at the
//! `<data_dir>/witness/<blob_sha256>` filename when they need the
//! raw verifier output.

use thiserror::Error;

use crate::ro::RoConn;
use crate::Table;

/// One witness row, projected onto the fields `raxis inspect /
/// raxis witnesses` need. Mirrors the on-disk DDL minus the blob
/// blob_path (which is always equal to `blob_sha256` in v1, per the
/// schema comment).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WitnessRow {
    pub verifier_run_id: String,
    pub task_id: String,
    pub gate_type: String,
    pub result_class: String,
    pub evaluation_sha: String,
    pub blob_sha256: String,
    pub recorded_at: u64,
}

#[derive(Debug, Error)]
pub enum WitnessViewError {
    #[error("sqlite error during witness view read: {0}")]
    Sqlite(#[from] rusqlite::Error),
}

/// Return every witness recorded for `task_id`, ordered newest first.
///
/// Ordered by `recorded_at DESC` so the CLI's "most recent witness"
/// row is line 1 — operators investigating a failure want the latest
/// gate result up top.
pub fn for_task(conn: &RoConn, task_id: &str) -> Result<Vec<WitnessRow>, WitnessViewError> {
    let mut stmt = conn.prepare(&format!(
        "SELECT verifier_run_id, task_id, gate_type, result_class, \
                evaluation_sha, blob_sha256, recorded_at \
         FROM {} \
         WHERE task_id = ?1 \
         ORDER BY recorded_at DESC",
        Table::WitnessRecords.as_str(),
    ))?;
    let rows = stmt
        .query_map(rusqlite::params![task_id], |r| {
            Ok(WitnessRow {
                verifier_run_id: r.get(0)?,
                task_id: r.get(1)?,
                gate_type: r.get(2)?,
                result_class: r.get(3)?,
                evaluation_sha: r.get(4)?,
                blob_sha256: r.get(5)?,
                recorded_at: r.get::<_, i64>(6)?.max(0) as u64,
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

    /// Seed: one task with three witnesses spanning two gate types
    /// and one Inconclusive result, plus a sibling task with one
    /// witness so we can confirm the WHERE filter.
    fn fresh_store_with_seed_witnesses() -> TempDir {
        const INITIATIVES: &str = Table::Initiatives.as_str();
        const TASKS: &str = Table::Tasks.as_str();
        const VERIFIER_RUN_TOKENS: &str = Table::VerifierRunTokens.as_str();
        const WITNESS_RECORDS: &str = Table::WitnessRecords.as_str();
        let tmp = TempDir::new().unwrap();
        let db = tmp.path().join("kernel.db");
        let store = Store::open(&db).unwrap();
        let guard = store.lock_sync();
        guard
            .execute(
                &format!(
                    "INSERT INTO {INITIATIVES} \
                     (initiative_id, state, terminal_criteria_json, plan_artifact_sha256, created_at) \
                     VALUES ('init-1', 'Executing', '{{}}', 'sha-1', 1)"
                ),
                [],
            )
            .unwrap();
        for (id, state) in [("t-1", "Running"), ("t-2", "Running")] {
            guard
                .execute(
                    &format!(
                        "INSERT INTO {TASKS} \
                         (task_id, initiative_id, lane_id, state, actor, \
                          policy_epoch, admitted_at, transitioned_at) \
                         VALUES (?1, 'init-1', 'd', ?2, 'op', 1, 1, 1)"
                    ),
                    rusqlite::params![id, state],
                )
                .unwrap();
        }
        // Verifier tokens (witness_records FKs to verifier_run_tokens).
        for (run_id, task_id, gate, sha) in [
            ("run-a", "t-1", "tests", "sha-aa"),
            ("run-b", "t-1", "tests", "sha-bb"),
            ("run-c", "t-1", "coverage", "sha-cc"),
            ("run-d", "t-2", "tests", "sha-dd"),
        ] {
            guard
                .execute(
                    &format!(
                        "INSERT INTO {VERIFIER_RUN_TOKENS} \
                         (verifier_run_id, task_id, gate_type, evaluation_sha, \
                          token_hash, issued_at, expires_at, consumed) \
                         VALUES (?1, ?2, ?3, ?4, 'th', 1, 9999999999, 1)"
                    ),
                    rusqlite::params![run_id, task_id, gate, sha],
                )
                .unwrap();
        }
        // Witnesses with intentionally interleaved recorded_at so
        // the order test catches any default ordering.
        for (run_id, task_id, gate, sha, result, recorded) in [
            ("run-a", "t-1", "tests", "sha-aa", "Pass", 100i64),
            ("run-b", "t-1", "tests", "sha-bb", "Fail", 300),
            ("run-c", "t-1", "coverage", "sha-cc", "Inconclusive", 200),
            ("run-d", "t-2", "tests", "sha-dd", "Pass", 500),
        ] {
            guard
                .execute(
                    &format!(
                        "INSERT INTO {WITNESS_RECORDS} \
                         (verifier_run_id, evaluation_sha, task_id, gate_type, \
                          result_class, blob_sha256, blob_path, recorded_at) \
                         VALUES (?1, ?4, ?2, ?3, ?5, ?4, ?4, ?6)"
                    ),
                    rusqlite::params![run_id, task_id, gate, sha, result, recorded],
                )
                .unwrap();
        }
        tmp
    }

    #[test]
    fn for_task_returns_only_rows_for_requested_task() {
        let tmp = fresh_store_with_seed_witnesses();
        let conn = open_ro(tmp.path()).unwrap();
        let rows = for_task(&conn, "t-1").unwrap();
        assert_eq!(rows.len(), 3);
        assert!(rows.iter().all(|r| r.task_id == "t-1"));
    }

    #[test]
    fn for_task_orders_by_recorded_at_descending() {
        let tmp = fresh_store_with_seed_witnesses();
        let conn = open_ro(tmp.path()).unwrap();
        let ids: Vec<String> = for_task(&conn, "t-1")
            .unwrap()
            .into_iter()
            .map(|r| r.verifier_run_id)
            .collect();
        // recorded_at desc: run-b (300), run-c (200), run-a (100).
        assert_eq!(ids, vec!["run-b", "run-c", "run-a"]);
    }

    #[test]
    fn for_task_returns_empty_when_no_witnesses() {
        let tmp = fresh_store_with_seed_witnesses();
        let conn = open_ro(tmp.path()).unwrap();
        assert!(for_task(&conn, "no-such-task").unwrap().is_empty());
    }
}

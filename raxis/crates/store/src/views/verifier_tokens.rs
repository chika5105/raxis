//! Verifier-token query catalog (cli-readonly.md §5.4.1
//! `verifier_tokens.rs`).
//!
//! Surface:
//!   * [`outstanding`] — issued tokens that have not yet been
//!     consumed AND have not yet expired.
//!   * [`recent_runs`] — last N issued tokens regardless of state,
//!     for a "show me what verifiers ran today" view.
//!
//! Why two functions and not one paged query?
//! `outstanding` is the operator's "what is currently in flight?"
//! question; `recent_runs` is the historian's "what did we just
//! run?" question. They have different ORDER BYs and different
//! WHERE clauses, and folding them into one helper would force the
//! caller to learn an enum filter — strictly worse than two
//! one-liner functions.

use std::time::{SystemTime, UNIX_EPOCH};

use thiserror::Error;

use crate::ro::RoConn;
use crate::Table;

/// One row of `verifier_run_tokens`, projected for the CLI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifierTokenRow {
    pub verifier_run_id: String,
    pub task_id:         String,
    pub gate_type:       String,
    pub evaluation_sha:  String,
    pub issued_at:       u64,
    pub expires_at:      u64,
    pub consumed:        bool,
    pub consumed_at:     Option<u64>,
}

#[derive(Debug, Error)]
pub enum VerifierTokenViewError {
    #[error("sqlite error during verifier_tokens view read: {0}")]
    Sqlite(#[from] rusqlite::Error),
}

/// Tokens issued, not yet consumed, AND not yet expired (relative to
/// `now_secs`). Ordered by `issued_at DESC` so the operator sees
/// freshly-spawned verifiers at the top.
pub fn outstanding_at(
    conn:     &RoConn,
    now_secs: u64,
    limit:    usize,
) -> Result<Vec<VerifierTokenRow>, VerifierTokenViewError> {
    let now_i = now_secs.min(i64::MAX as u64) as i64;
    let mut stmt = conn.prepare(&format!(
        "SELECT verifier_run_id, task_id, gate_type, evaluation_sha, \
                issued_at, expires_at, consumed, consumed_at \
         FROM {} \
         WHERE consumed = 0 AND expires_at > ?1 \
         ORDER BY issued_at DESC LIMIT ?2",
        Table::VerifierRunTokens.as_str(),
    ))?;
    let rows = stmt
        .query_map(
            rusqlite::params![now_i, limit as i64],
            map_row,
        )?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

/// Convenience wrapper that uses host wall clock. Tests use
/// [`outstanding_at`] for determinism.
pub fn outstanding(
    conn:  &RoConn,
    limit: usize,
) -> Result<Vec<VerifierTokenRow>, VerifierTokenViewError> {
    outstanding_at(conn, unix_now_secs(), limit)
}

/// Last N issued tokens regardless of consumed / expired state.
/// Ordered by `issued_at DESC`.
pub fn recent_runs(
    conn:  &RoConn,
    limit: usize,
) -> Result<Vec<VerifierTokenRow>, VerifierTokenViewError> {
    let mut stmt = conn.prepare(&format!(
        "SELECT verifier_run_id, task_id, gate_type, evaluation_sha, \
                issued_at, expires_at, consumed, consumed_at \
         FROM {} \
         ORDER BY issued_at DESC LIMIT ?1",
        Table::VerifierRunTokens.as_str(),
    ))?;
    let rows = stmt
        .query_map(rusqlite::params![limit as i64], map_row)?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

fn map_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<VerifierTokenRow> {
    Ok(VerifierTokenRow {
        verifier_run_id: r.get(0)?,
        task_id:         r.get(1)?,
        gate_type:       r.get(2)?,
        evaluation_sha:  r.get(3)?,
        issued_at:       r.get::<_, i64>(4)?.max(0) as u64,
        expires_at:      r.get::<_, i64>(5)?.max(0) as u64,
        consumed:        r.get::<_, i64>(6)? != 0,
        consumed_at:     r.get::<_, Option<i64>>(7)?.map(|v| v.max(0) as u64),
    })
}

fn unix_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ro::open as open_ro, Store};
    use tempfile::TempDir;

    fn fresh_store_with_seed_tokens() -> TempDir {
        const INITIATIVES:         &str = Table::Initiatives.as_str();
        const TASKS:               &str = Table::Tasks.as_str();
        const VERIFIER_RUN_TOKENS: &str = Table::VerifierRunTokens.as_str();
        let tmp = TempDir::new().unwrap();
        let db = tmp.path().join("kernel.db");
        let store = Store::open(&db).unwrap();
        let guard = store.lock_sync();
        // Seed an initiative + a task so FKs pass.
        guard.execute(
            &format!(
                "INSERT INTO {INITIATIVES} \
                 (initiative_id, state, terminal_criteria_json, plan_artifact_sha256, created_at) \
                 VALUES ('init-1', 'Executing', '{{}}', 'sha-1', 1)"
            ),
            [],
        ).unwrap();
        guard.execute(
            &format!(
                "INSERT INTO {TASKS} \
                 (task_id, initiative_id, lane_id, state, actor, \
                  policy_epoch, admitted_at, transitioned_at) \
                 VALUES ('t-1', 'init-1', 'd', 'Running', 'op', 1, 1, 1)"
            ),
            [],
        ).unwrap();
        // Three tokens:
        //   active   — consumed=0, expires_at > NOW
        //   expired  — consumed=0, expires_at < NOW
        //   consumed — consumed=1, expires_at > NOW
        for (id, gate, issued, expires, consumed) in [
            ("v-active",   "tests", 100_i64, 9999999999_i64, 0_i64),
            ("v-expired",  "tests", 100,     200,            0),
            ("v-consumed", "tests", 100,     9999999999,     1),
        ] {
            guard.execute(
                &format!(
                    "INSERT INTO {VERIFIER_RUN_TOKENS} \
                     (verifier_run_id, task_id, gate_type, evaluation_sha, \
                      token_hash, issued_at, expires_at, consumed) \
                     VALUES (?1, 't-1', ?2, 'eval-sha', 'th', ?3, ?4, ?5)"
                ),
                rusqlite::params![id, gate, issued, expires, consumed],
            ).unwrap();
        }
        tmp
    }

    #[test]
    fn outstanding_at_excludes_consumed_and_expired() {
        let tmp = fresh_store_with_seed_tokens();
        let conn = open_ro(tmp.path()).unwrap();
        let rows = outstanding_at(&conn, /*now=*/ 500, 100).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].verifier_run_id, "v-active");
        assert!(!rows[0].consumed);
    }

    #[test]
    fn recent_runs_returns_every_row_regardless_of_state() {
        let tmp = fresh_store_with_seed_tokens();
        let conn = open_ro(tmp.path()).unwrap();
        let rows = recent_runs(&conn, 100).unwrap();
        assert_eq!(rows.len(), 3);
    }

    #[test]
    fn recent_runs_respects_limit() {
        let tmp = fresh_store_with_seed_tokens();
        let conn = open_ro(tmp.path()).unwrap();
        let rows = recent_runs(&conn, 1).unwrap();
        assert_eq!(rows.len(), 1);
    }
}

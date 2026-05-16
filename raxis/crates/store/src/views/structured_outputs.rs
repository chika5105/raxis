//! Read-only view over the `structured_outputs` table
//! (` StructuredOutput tool`).
//! # Scope
//! Powers two surfaces today:
//! * `OperatorRequest::ListTaskOutputs` → `raxis task outputs <task_id>`
//!   (operator IPC; see `kernel/src/ipc/operator_ergonomics.rs::handle_list_task_outputs`).
//! * Future dashboard read paths (`raxis-dashboard` crate, V2 §4.4).
//! # Hard rules (inherited from `views/mod.rs`)
//! 1. No raw SQL leaks past this module.
//! 2. Reader functions take `&RoConn` — write attempts are a type
//!    error.
//! 3. Each function opens its own short-lived snapshot and returns
//!    owned `Vec<T>` so the caller does not hold a WAL snapshot
//!    open across UI ticks.
//! 4. Identifiers come from the typed [`crate::Table`] enum. The
//!    column shape mirrors migration 13 exactly (see
//!    `migration::render_migration_13_ddl`).

use rusqlite::params;
use thiserror::Error;

use crate::ro::RoConn;
use crate::Table;

// ---------------------------------------------------------------------------
// Row + error types
// ---------------------------------------------------------------------------

/// One row of the `structured_outputs` table. Mirrors the
/// migration-13 column shape exactly.
/// `payload_json` is the verbatim JSON the kernel persisted at
/// `IntentKind::StructuredOutput` admission time, AFTER
/// `StructuredOutputKind::validate_and_normalise` has clamped /
/// truncated over-cap fields. Callers (CLI, dashboard) MUST treat
/// it as the source of truth and pretty-print directly without
/// re-validating.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StructuredOutputRow {
    pub output_id: String,
    pub initiative_id: String,
    /// `Some(task_id)` for outputs emitted by an Executor or
    /// Reviewer session whose enclosing `tasks` row is still alive
    /// (FK-enforced by the migration-18 schema). `None` for
    /// **Orchestrator-emitted outputs** which are scoped to the
    /// initiative but are NOT bound to any single sub-task —
    /// see .
    pub task_id: Option<String>,
    pub session_id: String,
    /// `progress_report` | `diagnostic_flag` | `task_summary`.
    /// Matches the wire `kind` discriminator the executor emits.
    pub kind: String,
    /// `Some("info" | "warning" | "critical")` for
    /// `diagnostic_flag` rows; `None` otherwise. The CHECK
    /// constraint in migration 13 pins the value set.
    pub severity: Option<String>,
    /// Verbatim JSON the kernel persisted (already validated /
    /// normalised at admission time by
    /// `StructuredOutputKind::validate_and_normalise`).
    pub payload_json: String,
    /// Unix-epoch seconds, recorded by the kernel handler when
    /// the row was written.
    pub emitted_at: i64,
}

#[derive(Debug, Error)]
pub enum StructuredOutputViewError {
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),
}

// ---------------------------------------------------------------------------
// Reads
// ---------------------------------------------------------------------------

const SELECT_ALL_COLS: &str = "output_id, initiative_id, task_id, session_id, \
                               kind, severity, payload_json, emitted_at";

fn row_to_struct(row: &rusqlite::Row<'_>) -> rusqlite::Result<StructuredOutputRow> {
    Ok(StructuredOutputRow {
        output_id: row.get::<_, String>(0)?,
        initiative_id: row.get::<_, String>(1)?,
        task_id: row.get::<_, Option<String>>(2)?,
        session_id: row.get::<_, String>(3)?,
        kind: row.get::<_, String>(4)?,
        severity: row.get::<_, Option<String>>(5)?,
        payload_json: row.get::<_, String>(6)?,
        emitted_at: row.get::<_, i64>(7)?,
    })
}

fn collect<I>(rows: I) -> Result<Vec<StructuredOutputRow>, StructuredOutputViewError>
where
    I: Iterator<Item = rusqlite::Result<StructuredOutputRow>>,
{
    let mut out = Vec::new();
    for r in rows {
        out.push(r?);
    }
    Ok(out)
}

/// All structured outputs emitted under `task_id`, ordered by
/// `emitted_at ASC` (oldest → newest, matches the operator's
/// "what happened during this task?" reading order). Index probe
/// via `idx_structured_outputs_task`.
pub fn list_for_task(
    conn: &RoConn,
    task_id: &str,
) -> Result<Vec<StructuredOutputRow>, StructuredOutputViewError> {
    let table = Table::StructuredOutputs.as_str();
    let mut stmt = conn.prepare(&format!(
        "SELECT {SELECT_ALL_COLS}
           FROM {table}
          WHERE task_id = ?1
          ORDER BY emitted_at ASC, output_id ASC"
    ))?;
    let mapped = stmt.query_map(params![task_id], row_to_struct)?;
    collect(mapped)
}

/// All structured outputs emitted under `initiative_id`, ordered
/// by `emitted_at ASC`. Index probe via
/// `idx_structured_outputs_initiative`.
pub fn list_for_initiative(
    conn: &RoConn,
    initiative_id: &str,
) -> Result<Vec<StructuredOutputRow>, StructuredOutputViewError> {
    let table = Table::StructuredOutputs.as_str();
    let mut stmt = conn.prepare(&format!(
        "SELECT {SELECT_ALL_COLS}
           FROM {table}
          WHERE initiative_id = ?1
          ORDER BY emitted_at ASC, output_id ASC"
    ))?;
    let mapped = stmt.query_map(params![initiative_id], row_to_struct)?;
    collect(mapped)
}

// ---------------------------------------------------------------------------
// Tests — exercise real `Store` + `RoConn` against migration 13
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ro::open as open_ro, Store};
    use rusqlite::params as r_params;
    use tempfile::TempDir;

    /// Spin up a fresh on-disk store (migrations applied), seed
    /// `initiatives` / `tasks` / `sessions` rows that
    /// `structured_outputs` foreign-keys against, and return the
    /// tempdir + the seeded ids.
    fn fresh_store_with_seed() -> (TempDir, &'static str, &'static str, &'static str) {
        let tmp = tempfile::tempdir().expect("tempdir");
        let db_path = tmp.path().join("kernel.db");
        let store = Store::open(&db_path).expect("Store::open");
        let mut conn = store.lock_sync();
        let tx = conn.transaction().unwrap();

        let initiatives_t = Table::Initiatives.as_str();
        let tasks_t = Table::Tasks.as_str();
        let sessions_t = Table::Sessions.as_str();

        tx.execute_batch(&format!(
            "INSERT INTO {initiatives_t} \
                (initiative_id, state, terminal_criteria_json, plan_artifact_sha256, created_at) \
             VALUES \
                ('init-1', 'Executing', '{{}}', 'aa', 0); \
             INSERT INTO {sessions_t} \
                (session_id, role_id, session_token, lineage_id, fetch_quota, \
                 created_at, expires_at, revoked) \
             VALUES \
                ('sess-1', 'planner', 'tok-1', 'lin-1', 0, 100, 9999999999, 0); \
             INSERT INTO {tasks_t} \
                (task_id, initiative_id, lane_id, state, actor, \
                 policy_epoch, admitted_at, transitioned_at, session_id) \
             VALUES \
                ('task-1', 'init-1', 'lane-1', 'Running', 'op', 1, 100, 100, 'sess-1');"
        ))
        .unwrap();
        tx.commit().unwrap();

        drop(conn);
        drop(store);
        (tmp, "init-1", "task-1", "sess-1")
    }

    /// Test-only fixture row spec — keeps the `insert_row` helper
    /// at one argument so `clippy::too_many_arguments` doesn't
    /// fire while preserving named call sites.
    struct InsertRowSpec<'a> {
        output_id: &'a str,
        initiative_id: &'a str,
        task_id: &'a str,
        session_id: &'a str,
        kind: &'a str,
        severity: Option<&'a str>,
        payload_json: &'a str,
        emitted_at: i64,
    }

    fn insert_row(tmp: &TempDir, row: InsertRowSpec<'_>) {
        let store = Store::open(&tmp.path().join("kernel.db")).unwrap();
        let conn = store.lock_sync();
        let table = Table::StructuredOutputs.as_str();
        conn.execute(
            &format!(
                "INSERT INTO {table} \
                    (output_id, initiative_id, task_id, session_id, \
                     kind, severity, payload_json, emitted_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)"
            ),
            r_params![
                row.output_id,
                row.initiative_id,
                row.task_id,
                row.session_id,
                row.kind,
                row.severity,
                row.payload_json,
                row.emitted_at,
            ],
        )
        .unwrap();
        drop(conn);
        drop(store);
    }

    #[test]
    fn fresh_db_has_no_outputs() {
        let (tmp, init, task, _sess) = fresh_store_with_seed();
        let ro = open_ro(tmp.path()).unwrap();
        assert!(list_for_task(&ro, task).unwrap().is_empty());
        assert!(list_for_initiative(&ro, init).unwrap().is_empty());
    }

    #[test]
    fn list_for_task_returns_rows_oldest_first() {
        let (tmp, init, task, sess) = fresh_store_with_seed();

        insert_row(
            &tmp,
            InsertRowSpec {
                output_id: "out-2",
                initiative_id: init,
                task_id: task,
                session_id: sess,
                kind: "diagnostic_flag",
                severity: Some("warning"),
                payload_json: r#"{"DiagnosticFlag":{"severity":"warning","message":"x"}}"#,
                emitted_at: 200,
            },
        );
        insert_row(
            &tmp,
            InsertRowSpec {
                output_id: "out-1",
                initiative_id: init,
                task_id: task,
                session_id: sess,
                kind: "progress_report",
                severity: None,
                payload_json: r#"{"ProgressReport":{"files_modified":[],"tests_passing":1,"tests_failing":0,"confidence":0.9}}"#,
                emitted_at: 100,
            },
        );
        insert_row(
            &tmp,
            InsertRowSpec {
                output_id: "out-3",
                initiative_id: init,
                task_id: task,
                session_id: sess,
                kind: "task_summary",
                severity: None,
                payload_json: r#"{"TaskSummary":{"commit_sha":"deadbeef","changed_paths":[],"approach":"x"}}"#,
                emitted_at: 300,
            },
        );

        let ro = open_ro(tmp.path()).unwrap();
        let rows = list_for_task(&ro, task).unwrap();
        assert_eq!(rows.len(), 3);

        assert_eq!(rows[0].output_id, "out-1");
        assert_eq!(rows[0].kind, "progress_report");
        assert!(rows[0].severity.is_none());

        assert_eq!(rows[1].output_id, "out-2");
        assert_eq!(rows[1].kind, "diagnostic_flag");
        assert_eq!(rows[1].severity.as_deref(), Some("warning"));

        assert_eq!(rows[2].output_id, "out-3");
        assert_eq!(rows[2].kind, "task_summary");
        assert!(rows[2].severity.is_none());
    }

    #[test]
    fn list_for_initiative_aggregates_across_tasks() {
        let (tmp, init, task, sess) = fresh_store_with_seed();

        let store = Store::open(&tmp.path().join("kernel.db")).unwrap();
        {
            let conn = store.lock_sync();
            let tasks_t = Table::Tasks.as_str();
            let sessions_t = Table::Sessions.as_str();
            conn.execute_batch(&format!(
                "INSERT INTO {sessions_t} \
                    (session_id, role_id, session_token, lineage_id, fetch_quota, \
                     created_at, expires_at, revoked) \
                 VALUES \
                    ('sess-2', 'planner', 'tok-2', 'lin-1', 0, 100, 9999999999, 0); \
                 INSERT INTO {tasks_t} \
                    (task_id, initiative_id, lane_id, state, actor, \
                     policy_epoch, admitted_at, transitioned_at, session_id) \
                 VALUES \
                    ('task-2', '{init}', 'lane-1', 'Running', 'op', 1, 200, 200, 'sess-2');"
            ))
            .unwrap();
        }
        drop(store);

        insert_row(
            &tmp,
            InsertRowSpec {
                output_id: "a",
                initiative_id: init,
                task_id: task,
                session_id: sess,
                kind: "progress_report",
                severity: None,
                payload_json: "{}",
                emitted_at: 100,
            },
        );
        insert_row(
            &tmp,
            InsertRowSpec {
                output_id: "b",
                initiative_id: init,
                task_id: "task-2",
                session_id: "sess-2",
                kind: "task_summary",
                severity: None,
                payload_json: "{}",
                emitted_at: 200,
            },
        );

        let ro = open_ro(tmp.path()).unwrap();
        let by_init = list_for_initiative(&ro, init).unwrap();
        assert_eq!(by_init.len(), 2);
        assert_eq!(by_init[0].output_id, "a");
        assert_eq!(by_init[1].output_id, "b");

        let by_task1 = list_for_task(&ro, task).unwrap();
        assert_eq!(by_task1.len(), 1);
        assert_eq!(by_task1[0].output_id, "a");

        let by_task2 = list_for_task(&ro, "task-2").unwrap();
        assert_eq!(by_task2.len(), 1);
        assert_eq!(by_task2[0].output_id, "b");
    }
}

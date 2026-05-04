//! Plan-field reveal view (cli-readonly.md §5.4.2 / §5.5.6).
//!
//! # Why this lives in `views/` despite holding the redaction-sensitive
//! data
//!
//! `task_plan_fields` is a logical view, not a real table. The §2.5.8
//! path-scope fields (`path_allowlist`, `path_export_to_successors`,
//! `path_export_globs`, `path_scope_override`) are stored on the
//! immutable `signed_plan_artifacts.plan_bytes` BLOB, NOT in a
//! materialised column on `tasks`. To answer "what paths can task X
//! touch?" the kernel parses the plan TOML once at boot
//! (`initiatives::lifecycle::repopulate_plan_registry`); the read-only
//! CLI does the same parse on demand here.
//!
//! Returning the underlying values unwrapped (no `Redactable<T>`
//! wrapper at this layer) is the pattern documented in
//! [`crate::views`] §"Redaction": redaction is enforced by the CLI's
//! `--reveal-paths` gate, not by hiding bytes from the typed view.
//! The CLI MUST emit a `PathReadAccessed` audit event before calling
//! [`reveal_for_task`] (cli-readonly.md §5.7.2 / §5.7.3); that
//! invariant is checked in `cli/src/reveal.rs`, not here.
//!
//! # Failure semantics
//!
//! `reveal_for_task` is **fail-closed for safety**: it returns
//! `Ok(None)` only when the task's initiative has **no**
//! `signed_plan_artifacts` row at all (which means there are no
//! fields to reveal). Every other miss path — task missing, plan
//! TOML missing the `[[tasks]]` array, malformed TOML — returns
//! `Err(...)` so the CLI surfaces the operator-visible diagnostic
//! rather than silently rendering "all-deny" defaults that an auditor
//! would mistake for "the kernel approved a lockdown plan".

use rusqlite::OptionalExtension;
use thiserror::Error;

use crate::ro::RoConn;
use crate::Table;

// ────────────────────────────────────────────────────────────────────
// Public types
// ────────────────────────────────────────────────────────────────────

/// The four §2.5.8 path-scope fields from a single task entry inside
/// `signed_plan_artifacts.plan_bytes`. Same shape as the kernel's
/// in-memory `TaskPlanFields` struct (deliberately not shared, to
/// keep `raxis-store` independent from `raxis-kernel` per the
/// dependency-direction rule in `views/mod.rs`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PlanPathFields {
    pub path_allowlist:            Vec<String>,
    pub path_export_to_successors: bool,
    pub path_export_globs:         Vec<String>,
    pub path_scope_override:       bool,
}

/// Failure modes specific to the plan-fields reveal view.
#[derive(Debug, Error)]
pub enum PlanFieldsError {
    #[error("sqlite error during plan_fields read: {0}")]
    Sqlite(#[from] rusqlite::Error),

    #[error("task {task_id:?} is not in kernel.db (no row in `tasks`)")]
    TaskNotFound { task_id: String },

    #[error(
        "task {task_id:?} (initiative {initiative_id:?}) has no signed_plan_artifacts \
         row — the plan blob is missing or the initiative has not been admitted yet"
    )]
    PlanArtifactMissing {
        task_id:       String,
        initiative_id: String,
    },

    #[error(
        "plan TOML for initiative {initiative_id:?} could not be parsed: {reason}"
    )]
    PlanInvalid {
        initiative_id: String,
        reason:        String,
    },

    #[error(
        "plan TOML for initiative {initiative_id:?} has no `[[tasks]]` entry \
         matching task_id={task_id:?}"
    )]
    TaskNotInPlan {
        initiative_id: String,
        task_id:       String,
    },
}

// ────────────────────────────────────────────────────────────────────
// Reveal entry point
// ────────────────────────────────────────────────────────────────────

/// Look up a task's §2.5.8 path-scope fields by parsing the immutable
/// `signed_plan_artifacts.plan_bytes` blob for its initiative.
///
/// **Returns:**
/// - `Ok(fields)` — every reveal field present in the plan; missing
///   fields default to the spec lockdown (`path_allowlist = []`,
///   `path_export_to_successors = false`, `path_export_globs = []`,
///   `path_scope_override = false`). Identical defaults to the
///   kernel's [`raxis_kernel::initiatives::plan_registry::TaskPlanFields`]
///   struct.
/// - `Err(...)` — see [`PlanFieldsError`] for the typed failure cases.
pub fn reveal_for_task(
    conn:    &RoConn,
    task_id: &str,
) -> Result<PlanPathFields, PlanFieldsError> {
    let initiative_id = lookup_initiative_id(conn, task_id)?;
    let plan_bytes    = lookup_plan_bytes(conn, &initiative_id, task_id)?;

    let plan_toml = String::from_utf8_lossy(&plan_bytes);
    parse_plan_path_fields(&plan_toml, &initiative_id, task_id)
}

// ────────────────────────────────────────────────────────────────────
// Internals — kept private; tests below pin contracts via the public
//             entry point.
// ────────────────────────────────────────────────────────────────────

fn lookup_initiative_id(
    conn:    &RoConn,
    task_id: &str,
) -> Result<String, PlanFieldsError> {
    let sql = format!(
        "SELECT initiative_id FROM {} WHERE task_id = ?1",
        Table::Tasks.as_str(),
    );
    let row: Option<String> = conn
        .query_row(&sql, rusqlite::params![task_id], |r| r.get::<_, String>(0))
        .optional()?;
    row.ok_or_else(|| PlanFieldsError::TaskNotFound {
        task_id: task_id.to_owned(),
    })
}

fn lookup_plan_bytes(
    conn:          &RoConn,
    initiative_id: &str,
    task_id:       &str,
) -> Result<Vec<u8>, PlanFieldsError> {
    let sql = format!(
        "SELECT plan_bytes FROM {} WHERE initiative_id = ?1",
        Table::SignedPlanArtifacts.as_str(),
    );
    let row: Option<Vec<u8>> = conn
        .query_row(&sql, rusqlite::params![initiative_id], |r| r.get::<_, Vec<u8>>(0))
        .optional()?;
    row.ok_or_else(|| PlanFieldsError::PlanArtifactMissing {
        task_id:       task_id.to_owned(),
        initiative_id: initiative_id.to_owned(),
    })
}

/// Parse the `[[tasks]]` array out of the plan TOML and pluck the
/// entry whose `task_id` matches. Defaults match the spec lockdown
/// (deny-everything) for any field the operator omitted.
///
/// Kept in lockstep with the kernel's `parse_plan_tasks` in
/// `raxis/kernel/src/initiatives/lifecycle.rs` — the two parsers MUST
/// agree byte-for-byte on what counts as `path_allowlist`. The kernel
/// parser is the production path; this one exists so the read-only
/// CLI doesn't have to depend on `raxis-kernel`.
fn parse_plan_path_fields(
    plan_toml:     &str,
    initiative_id: &str,
    task_id:       &str,
) -> Result<PlanPathFields, PlanFieldsError> {
    let doc: toml::Value = toml::from_str(plan_toml).map_err(|e| {
        PlanFieldsError::PlanInvalid {
            initiative_id: initiative_id.to_owned(),
            reason:        format!("TOML parse error: {e}"),
        }
    })?;

    let tasks_array = doc
        .get("tasks")
        .and_then(|v| v.as_array())
        .ok_or_else(|| PlanFieldsError::PlanInvalid {
            initiative_id: initiative_id.to_owned(),
            reason:        "plan TOML missing [[tasks]] array".to_owned(),
        })?;

    let entry = tasks_array
        .iter()
        .find(|t| t.get("task_id").and_then(|v| v.as_str()) == Some(task_id))
        .ok_or_else(|| PlanFieldsError::TaskNotInPlan {
            initiative_id: initiative_id.to_owned(),
            task_id:       task_id.to_owned(),
        })?;

    Ok(PlanPathFields {
        path_allowlist:            string_array(entry, "path_allowlist"),
        path_export_to_successors: entry
            .get("path_export_to_successors")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
        path_export_globs:         string_array(entry, "path_export_globs"),
        path_scope_override:       entry
            .get("path_scope_override")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
    })
}

/// Read an optional TOML field as a `Vec<String>`. Missing field,
/// wrong type, or non-string array entries all fall back to the empty
/// vec — matches the kernel's `string_array` helper exactly.
fn string_array(entry: &toml::Value, field: &str) -> Vec<String> {
    entry
        .get(field)
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|p| p.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

// ────────────────────────────────────────────────────────────────────
// Tests
// ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ro::open as open_ro, Store};
    use tempfile::TempDir;

    /// Build a fresh kernel.db with one initiative + one task + a
    /// signed_plan_artifacts row holding the supplied TOML. Returns
    /// the tempdir (kept alive for the test) and the (initiative,
    /// task) ids.
    fn fresh_store_with_plan(plan_toml: &str) -> (TempDir, String, String) {
        const INITIATIVES:           &str = Table::Initiatives.as_str();
        const TASKS:                 &str = Table::Tasks.as_str();
        const SIGNED_PLAN_ARTIFACTS: &str = Table::SignedPlanArtifacts.as_str();
        let tmp           = TempDir::new().unwrap();
        let db            = tmp.path().join("kernel.db");
        let initiative_id = "init-1".to_owned();
        let task_id       = "t-1".to_owned();
        {
            let store = Store::open(&db).unwrap();
            let guard = store.lock_sync();
            guard.execute(
                &format!(
                    "INSERT INTO {INITIATIVES} \
                     (initiative_id, state, terminal_criteria_json, plan_artifact_sha256, created_at) \
                     VALUES (?1, 'Executing', '{{}}', 'sha-1', 1)"
                ),
                rusqlite::params![&initiative_id],
            ).unwrap();
            guard.execute(
                &format!(
                    "INSERT INTO {TASKS} \
                     (task_id, initiative_id, lane_id, state, actor, \
                      policy_epoch, admitted_at, transitioned_at) \
                     VALUES (?1, ?2, 'default', 'Running', 'op', 1, 1, 1)"
                ),
                rusqlite::params![&task_id, &initiative_id],
            ).unwrap();
            guard.execute(
                &format!(
                    "INSERT INTO {SIGNED_PLAN_ARTIFACTS} \
                     (initiative_id, plan_bytes, plan_sig, stored_at) \
                     VALUES (?1, ?2, x'00', 1)"
                ),
                rusqlite::params![&initiative_id, plan_toml.as_bytes()],
            ).unwrap();
        }
        (tmp, initiative_id, task_id)
    }

    #[test]
    fn reveal_returns_lockdown_defaults_when_plan_omits_path_fields() {
        // Spec §2.5.8 default: deny-everything when the operator did
        // not declare any path-scope fields. Mirrors the kernel's
        // `parse_plan_tasks_path_scope_defaults_are_lockdown` test.
        let plan = r#"
            [meta]
            version = 1
            [[tasks]]
            task_id = "t-1"
        "#;
        let (tmp, _init, task) = fresh_store_with_plan(plan);
        let conn = open_ro(tmp.path()).unwrap();

        let f = reveal_for_task(&conn, &task).expect("present");
        assert!(f.path_allowlist.is_empty(), "default allowlist must deny");
        assert!(!f.path_export_to_successors);
        assert!(f.path_export_globs.is_empty());
        assert!(!f.path_scope_override);
    }

    #[test]
    fn reveal_round_trips_every_path_scope_field_in_order() {
        let plan = r#"
            [[tasks]]
            task_id                   = "t-1"
            path_allowlist            = ["src/**", "tests/**", "README.md"]
            path_export_to_successors = true
            path_export_globs         = ["src/ipc/**", "src/auth/**"]
            path_scope_override       = true
        "#;
        let (tmp, _init, task) = fresh_store_with_plan(plan);
        let conn = open_ro(tmp.path()).unwrap();

        let f = reveal_for_task(&conn, &task).expect("present");
        assert_eq!(f.path_allowlist,    vec!["src/**", "tests/**", "README.md"]);
        assert!(f.path_export_to_successors);
        assert_eq!(f.path_export_globs, vec!["src/ipc/**", "src/auth/**"]);
        assert!(f.path_scope_override);
    }

    #[test]
    fn reveal_silently_ignores_non_string_array_entries() {
        // Defense-in-depth parity with the kernel parser's
        // `parse_plan_tasks_silently_ignores_non_string_array_entries`.
        let plan = r#"
            [[tasks]]
            task_id        = "t-1"
            path_allowlist = ["src/**", 42, "ok.rs"]
        "#;
        let (tmp, _init, task) = fresh_store_with_plan(plan);
        let conn = open_ro(tmp.path()).unwrap();
        let f    = reveal_for_task(&conn, &task).unwrap();
        assert_eq!(f.path_allowlist, vec!["src/**", "ok.rs"]);
    }

    #[test]
    fn reveal_returns_task_not_found_for_missing_task() {
        let plan = "[[tasks]]\ntask_id = \"t-1\"\n";
        let (tmp, _init, _task) = fresh_store_with_plan(plan);
        let conn = open_ro(tmp.path()).unwrap();

        let err = reveal_for_task(&conn, "t-does-not-exist").unwrap_err();
        match err {
            PlanFieldsError::TaskNotFound { task_id } => {
                assert_eq!(task_id, "t-does-not-exist");
            }
            other => panic!("expected TaskNotFound; got {other:?}"),
        }
    }

    #[test]
    fn reveal_returns_plan_artifact_missing_when_task_has_no_signed_plan_row() {
        // Build a task without the matching signed_plan_artifacts
        // row. The CLI surface is "the operator can see this task in
        // `tasks` but the plan blob is gone" — every other miss path
        // should fail loud, not silently render lockdown defaults.
        const INITIATIVES: &str = Table::Initiatives.as_str();
        const TASKS:       &str = Table::Tasks.as_str();
        let tmp = TempDir::new().unwrap();
        let db  = tmp.path().join("kernel.db");
        {
            let store = Store::open(&db).unwrap();
            let guard = store.lock_sync();
            guard.execute(
                &format!(
                    "INSERT INTO {INITIATIVES} \
                     (initiative_id, state, terminal_criteria_json, plan_artifact_sha256, created_at) \
                     VALUES ('init-x', 'Draft', '{{}}', 'sha-x', 1)"
                ),
                [],
            ).unwrap();
            guard.execute(
                &format!(
                    "INSERT INTO {TASKS} \
                     (task_id, initiative_id, lane_id, state, actor, \
                      policy_epoch, admitted_at, transitioned_at) \
                     VALUES ('t-x', 'init-x', 'default', 'Admitted', 'op', 1, 1, 1)"
                ),
                [],
            ).unwrap();
        }
        let conn = open_ro(tmp.path()).unwrap();
        let err  = reveal_for_task(&conn, "t-x").unwrap_err();
        match err {
            PlanFieldsError::PlanArtifactMissing { task_id, initiative_id } => {
                assert_eq!(task_id, "t-x");
                assert_eq!(initiative_id, "init-x");
            }
            other => panic!("expected PlanArtifactMissing; got {other:?}"),
        }
    }

    #[test]
    fn reveal_returns_plan_invalid_for_bogus_toml() {
        let plan_bytes = "this !! is not toml";
        let (tmp, init, task) = fresh_store_with_plan(plan_bytes);
        let conn = open_ro(tmp.path()).unwrap();

        let err = reveal_for_task(&conn, &task).unwrap_err();
        match err {
            PlanFieldsError::PlanInvalid { initiative_id, reason } => {
                assert_eq!(initiative_id, init);
                assert!(reason.contains("TOML parse error"), "got: {reason}");
            }
            other => panic!("expected PlanInvalid; got {other:?}"),
        }
    }

    #[test]
    fn reveal_returns_plan_invalid_when_tasks_array_missing() {
        let plan = "[meta]\nversion = 1\n";
        let (tmp, init, task) = fresh_store_with_plan(plan);
        let conn = open_ro(tmp.path()).unwrap();

        let err = reveal_for_task(&conn, &task).unwrap_err();
        match err {
            PlanFieldsError::PlanInvalid { initiative_id, reason } => {
                assert_eq!(initiative_id, init);
                assert!(reason.contains("[[tasks]] array"), "got: {reason}");
            }
            other => panic!("expected PlanInvalid; got {other:?}"),
        }
    }

    #[test]
    fn reveal_returns_task_not_in_plan_when_plan_lacks_matching_entry() {
        // Task row exists in `tasks` but the plan TOML has only some
        // OTHER task. This is the genuine "kernel admitted a task
        // outside the signed plan" forensic case — must surface
        // distinctly from `TaskNotFound`.
        let plan = "[[tasks]]\ntask_id = \"t-other\"\n";
        let (tmp, init, task) = fresh_store_with_plan(plan);
        let conn = open_ro(tmp.path()).unwrap();

        let err = reveal_for_task(&conn, &task).unwrap_err();
        match err {
            PlanFieldsError::TaskNotInPlan { initiative_id, task_id } => {
                assert_eq!(initiative_id, init);
                assert_eq!(task_id, task);
            }
            other => panic!("expected TaskNotInPlan; got {other:?}"),
        }
    }
}

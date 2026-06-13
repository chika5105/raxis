//! Plan-field reveal view (cli-readonly.md §5.4.2 / §5.5.6).
//!
//! # Why this lives in `views/` despite holding the redaction-sensitive
//! data
//!
//! `task_plan_fields` is a logical view, not a real table. The §2.5.8
//! path-scope fields (`path_allowlist`, `path_export_to_successors`,
//! `path_export_globs`, `path_scope_override`) and the semantic
//! `session_agent_type` are stored on the immutable
//! `signed_plan_artifacts.plan_bytes` BLOB, NOT in a materialised
//! column on `tasks`. To answer "what paths can task X touch?" the
//! kernel parses the plan TOML once at boot
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
//!
//! Historical note: v0.2.x sealed plans used operator-authored
//! `task_id` fields directly. New plans use kernel-owned runtime
//! `task_id` plus operator-authored `task_name`. This view is read-only
//! and forensic, so it accepts the old `task_id` field when reading
//! already-admitted historical plans. Admission remains strict in the
//! kernel/parser path; this is not a compatibility mode for new plans.

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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanPathFields {
    pub task_kind: String,
    pub workspace_merge_on_conflict: String,
    pub path_allowlist: Vec<String>,
    pub path_export_to_successors: bool,
    pub path_export_globs: Vec<String>,
    pub path_scope_override: bool,
    pub description: String,
    pub prompt: Option<String>,
    pub predecessors: Vec<String>,
    /// Plan-declared semantic agent type for this task. Defaults to
    /// `"Executor"` when omitted, matching the kernel admission
    /// parser.
    pub session_agent_type: String,
    pub clone_strategy: Option<String>,
    pub vm_image: Option<String>,
    pub profiles: Vec<String>,
    pub credentials: Vec<PlanCredentialRef>,
    pub allowed_egress: Vec<String>,
    pub task_verifiers: Vec<PlanTaskVerifierRef>,
    /// Plan-declared review rejection ceiling for this task.
    /// Defaults mirror the kernel admission parser.
    pub max_review_rejections: u32,
    /// Plan-declared crash retry ceiling for this task. Defaults
    /// mirror the kernel admission parser.
    pub max_crash_retries: u32,
    pub max_turns: Option<u32>,
    pub max_turns_step: Option<u32>,
    pub elastic: Option<bool>,
    pub min_vcpus: Option<u32>,
    pub max_vcpus: Option<u32>,
    pub min_memory_mb: Option<u32>,
    pub max_memory_mb: Option<u32>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PlanCredentialRef {
    pub name: String,
    pub proxy_type: String,
    pub mount_as: Option<String>,
    pub upstream_host_port: Option<String>,
    pub upstream_url: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PlanTaskVerifierRef {
    pub name: String,
    pub image: String,
    pub command: String,
    pub timeout: String,
    pub on_failure: String,
    pub artifact: Option<String>,
    pub artifact_max_bytes: Option<u64>,
    pub allowed_egress: Vec<String>,
}

impl Default for PlanPathFields {
    fn default() -> Self {
        Self {
            task_kind: "agent".to_owned(),
            workspace_merge_on_conflict: "orchestrator_then_operator".to_owned(),
            path_allowlist: Vec::new(),
            path_export_to_successors: false,
            path_export_globs: Vec::new(),
            path_scope_override: false,
            description: String::new(),
            prompt: None,
            predecessors: Vec::new(),
            session_agent_type: "Executor".to_owned(),
            clone_strategy: None,
            vm_image: None,
            profiles: Vec::new(),
            credentials: Vec::new(),
            allowed_egress: Vec::new(),
            task_verifiers: Vec::new(),
            max_review_rejections: DEFAULT_MAX_REVIEW_REJECTIONS,
            max_crash_retries: DEFAULT_MAX_CRASH_RETRIES,
            max_turns: None,
            max_turns_step: None,
            elastic: None,
            min_vcpus: None,
            max_vcpus: None,
            min_memory_mb: None,
            max_memory_mb: None,
        }
    }
}

/// Keep in sync with `kernel::initiatives::plan_registry`.
pub const DEFAULT_MAX_REVIEW_REJECTIONS: u32 = 2;
pub const DEFAULT_MAX_CRASH_RETRIES: u32 = 3;

/// Dashboard-facing initiative metadata pulled out of the same plan
/// TOML blob. The operator-visible label is `[workspace].name`; the
/// kernel-owned `initiative_id` remains the uniqueness boundary.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InitiativeMeta {
    pub name: String,
    pub description: String,
}

/// Dashboard-visible initiative name budget. Counted in Unicode
/// scalar values, not bytes, because this is an operator-facing label.
pub const WORKSPACE_NAME_MAX_CHARS: usize = 64;

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
        task_id: String,
        initiative_id: String,
    },

    #[error("plan TOML for initiative {initiative_id:?} could not be parsed: {reason}")]
    PlanInvalid {
        initiative_id: String,
        reason: String,
    },

    #[error(
        "plan TOML for initiative {initiative_id:?} has no `[[tasks]]` entry \
         matching task_name={task_name:?} for runtime task_id={task_id:?}"
    )]
    TaskNotInPlan {
        initiative_id: String,
        task_id: String,
        task_name: String,
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
///   kernel's `raxis_kernel::initiatives::plan_registry::TaskPlanFields`
///   struct.
/// - `Err(...)` — see [`PlanFieldsError`] for the typed failure cases.
pub fn reveal_for_task(conn: &RoConn, task_id: &str) -> Result<PlanPathFields, PlanFieldsError> {
    let (initiative_id, task_name) = lookup_task_identity(conn, task_id)?;
    let plan_bytes = lookup_plan_bytes(conn, &initiative_id, task_id)?;

    let plan_toml = String::from_utf8_lossy(&plan_bytes);
    parse_plan_path_fields(&plan_toml, &initiative_id, task_id, &task_name)
}

/// Read the **original submitted** `plan.toml` bytes for one
/// initiative, byte-for-byte as the operator sealed them.
///
/// Walks the same V1 → V2.1 fallback chain as [`reveal_for_task`]:
///   1. V1 path: `signed_plan_artifacts.plan_bytes` keyed by
///      `initiative_id`.
///   2. V2.1 path: `initiatives.plan_bundle_sha256` →
///      `plan_bundle_artifacts` row whose `artifact_name = 'plan.toml'`
///      (per `plan-bundle-sealing.md §8.3`).
///
/// Returns:
///   * `Ok(Some(bytes))` — the canonical sealed bytes. The dashboard
///     does NOT re-parse / re-serialize these (forensic fidelity per
///     `INV-DASHBOARD-INITIATIVE-PLAN-VISIBLE-01`).
///   * `Ok(None)` — the initiative exists in some indirect way (e.g.
///     the caller already validated existence) but has no
///     `signed_plan_artifacts` row AND no `plan_bundle_artifacts`
///     `plan.toml` row. Distinct from the underlying initiative's
///     existence — callers MUST check `views::initiatives::by_id`
///     to disambiguate "unknown initiative" (404) from "plan
///     archived" (410).
///   * `Err(_)` — sqlite trouble.
///
/// Why a sibling of [`reveal_initiative_meta`] / [`reveal_for_task`]
/// rather than an inline helper inside the dashboard glue: the
/// V1 → V2.1 lookup is already encapsulated in this module's
/// private `lookup_plan_bytes`; exposing it once at the views
/// boundary keeps every caller consistent (no second ad-hoc SQL
/// path drifting against `lookup_plan_bytes`).
pub fn submitted_toml_for_initiative(
    conn: &RoConn,
    initiative_id: &str,
) -> Result<Option<Vec<u8>>, PlanFieldsError> {
    match lookup_plan_bytes(conn, initiative_id, initiative_id) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(PlanFieldsError::PlanArtifactMissing { .. }) => Ok(None),
        Err(e) => Err(e),
    }
}

/// Read the dashboard-visible initiative metadata out of the plan
/// TOML for `initiative_id`. Same V1 → V2.1 fallback chain as
/// [`reveal_for_task`]. `[workspace].name` is required and bounded;
/// no read-side UUID fallback is applied because this label is the
/// operator-facing initiative identity.
///
/// Returns `Err(_)` on sqlite trouble, malformed TOML, missing plan
/// blob, or an invalid/missing name — those are operator-visible
/// diagnostics, not blank-view paper-cuts.
pub fn reveal_initiative_meta(
    conn: &RoConn,
    initiative_id: &str,
) -> Result<InitiativeMeta, PlanFieldsError> {
    // `task_id` is only used in the error variants below — pass the
    // initiative_id as a stand-in so the diagnostic is still useful.
    let plan_bytes = lookup_plan_bytes(conn, initiative_id, initiative_id)?;
    let plan_toml = String::from_utf8_lossy(&plan_bytes);
    parse_initiative_meta(&plan_toml, initiative_id)
}

// ────────────────────────────────────────────────────────────────────
// Internals — kept private; tests below pin contracts via the public
//             entry point.
// ────────────────────────────────────────────────────────────────────

fn lookup_task_identity(conn: &RoConn, task_id: &str) -> Result<(String, String), PlanFieldsError> {
    let sql = format!(
        "SELECT initiative_id, COALESCE(task_name, task_id) FROM {} WHERE task_id = ?1",
        Table::Tasks.as_str(),
    );
    let row: Option<(String, String)> = conn
        .query_row(&sql, rusqlite::params![task_id], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
        })
        .optional()?;
    row.ok_or_else(|| PlanFieldsError::TaskNotFound {
        task_id: task_id.to_owned(),
    })
}

fn lookup_plan_bytes(
    conn: &RoConn,
    initiative_id: &str,
    task_id: &str,
) -> Result<Vec<u8>, PlanFieldsError> {
    // V1 (legacy `signed_plan_artifacts`): every pre-V2 plan
    // wrote here. Try this first because it's a single-row
    // primary-key lookup.
    let sql_v1 = format!(
        "SELECT plan_bytes FROM {} WHERE initiative_id = ?1",
        Table::SignedPlanArtifacts.as_str(),
    );
    let v1: Option<Vec<u8>> = conn
        .query_row(&sql_v1, rusqlite::params![initiative_id], |r| {
            r.get::<_, Vec<u8>>(0)
        })
        .optional()?;
    if let Some(bytes) = v1 {
        return Ok(bytes);
    }

    // V2.1 sealed-bundle path (`plan-bundle-sealing.md §8.2`):
    // initiatives.plan_bundle_sha256 → plan_bundle_artifacts row
    // whose `artifact_name = 'plan.toml'`. The §8.3 contract is
    // that the plan TOML lives at artifact_seq=0, but we look up
    // by name so a future bundle layout that relocates plan.toml
    // continues to work without changing this view.
    let sql_v2 = format!(
        "SELECT pba.artifact_bytes \
         FROM {init} AS i \
         JOIN {pba} AS pba ON pba.bundle_sha256 = i.plan_bundle_sha256 \
         WHERE i.initiative_id = ?1 AND pba.artifact_name = 'plan.toml' \
         LIMIT 1",
        init = Table::Initiatives.as_str(),
        pba = Table::PlanBundleArtifacts.as_str(),
    );
    let v2: Option<Vec<u8>> = conn
        .query_row(&sql_v2, rusqlite::params![initiative_id], |r| {
            r.get::<_, Vec<u8>>(0)
        })
        .optional()?;
    if let Some(bytes) = v2 {
        return Ok(bytes);
    }

    Err(PlanFieldsError::PlanArtifactMissing {
        task_id: task_id.to_owned(),
        initiative_id: initiative_id.to_owned(),
    })
}

/// Parse the `[[tasks]]` array out of the plan TOML and pluck the
/// entry whose `task_name` matches. For historical sealed plans,
/// fallback to the old operator-authored `task_id` field so dashboard
/// and readonly CLI views can still inspect completed runs admitted
/// before runtime task ids became kernel-owned. Defaults match the spec
/// lockdown (deny-everything) for any field the operator omitted.
///
/// Kept in lockstep with the kernel's `parse_plan_tasks` in
/// `raxis/kernel/src/initiatives/lifecycle.rs` — the two parsers MUST
/// agree byte-for-byte on what counts as `path_allowlist`. The kernel
/// parser is the production path; this one exists so the read-only
/// CLI doesn't have to depend on `raxis-kernel`.
fn parse_plan_path_fields(
    plan_toml: &str,
    initiative_id: &str,
    task_id: &str,
    task_name: &str,
) -> Result<PlanPathFields, PlanFieldsError> {
    let doc: toml::Value = toml::from_str(plan_toml).map_err(|e| PlanFieldsError::PlanInvalid {
        initiative_id: initiative_id.to_owned(),
        reason: format!("TOML parse error: {e}"),
    })?;

    let tasks_array = doc.get("tasks").and_then(|v| v.as_array()).ok_or_else(|| {
        PlanFieldsError::PlanInvalid {
            initiative_id: initiative_id.to_owned(),
            reason: "plan TOML missing [[tasks]] array".to_owned(),
        }
    })?;

    let entry = tasks_array
        .iter()
        .find(|t| task_entry_matches_identity(t, task_id, task_name))
        .ok_or_else(|| PlanFieldsError::TaskNotInPlan {
            initiative_id: initiative_id.to_owned(),
            task_id: task_id.to_owned(),
            task_name: task_name.to_owned(),
        })?;

    Ok(PlanPathFields {
        task_kind: string_field(entry, "task_kind").unwrap_or_else(|| "agent".to_owned()),
        workspace_merge_on_conflict: string_field(entry, "on_conflict")
            .unwrap_or_else(|| "orchestrator_then_operator".to_owned()),
        path_allowlist: string_array(entry, "path_allowlist"),
        path_export_to_successors: entry
            .get("path_export_to_successors")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
        path_export_globs: string_array(entry, "path_export_globs"),
        path_scope_override: entry
            .get("path_scope_override")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
        description: string_field(entry, "description").unwrap_or_default(),
        prompt: string_field(entry, "prompt"),
        predecessors: string_array(entry, "predecessors"),
        session_agent_type: entry
            .get("session_agent_type")
            .and_then(|v| v.as_str())
            .unwrap_or("Executor")
            .to_owned(),
        clone_strategy: string_field(entry, "clone_strategy"),
        vm_image: string_field(entry, "vm_image").filter(|s| !s.is_empty()),
        profiles: string_array(entry, "profiles"),
        credentials: credential_refs(entry),
        allowed_egress: string_array(entry, "allowed_egress"),
        task_verifiers: task_verifier_refs(entry),
        max_review_rejections: u32_field(
            entry,
            "max_review_rejections",
            DEFAULT_MAX_REVIEW_REJECTIONS,
        ),
        max_crash_retries: u32_field(entry, "max_crash_retries", DEFAULT_MAX_CRASH_RETRIES),
        max_turns: optional_u32_field(entry, "max_turns"),
        max_turns_step: optional_u32_field(entry, "max_turns_step"),
        elastic: entry.get("elastic").and_then(|v| v.as_bool()),
        min_vcpus: optional_u32_field(entry, "min_vcpus"),
        max_vcpus: optional_u32_field(entry, "max_vcpus"),
        min_memory_mb: optional_u32_field(entry, "min_memory_mb"),
        max_memory_mb: optional_u32_field(entry, "max_memory_mb"),
    })
}

fn task_entry_matches_identity(entry: &toml::Value, task_id: &str, task_name: &str) -> bool {
    if entry.get("task_name").and_then(|v| v.as_str()) == Some(task_name) {
        return true;
    }

    // Read-only historical fallback: pre-kernel-owned-task-id plans
    // used `task_id` as the operator-facing task identity. Migration
    // 0030 populated `tasks.task_name = tasks.task_id` for those rows,
    // so matching either value recovers the sealed plan fields without
    // accepting legacy syntax in the admission parser.
    entry
        .get("task_id")
        .and_then(|v| v.as_str())
        .is_some_and(|legacy| legacy == task_name || legacy == task_id)
}

/// Pull `[workspace].name` plus `[plan.initiative].description` out
/// of the plan TOML. The workspace name is mandatory for the
/// dashboard identity contract; malformed historical/test rows surface as
/// [`PlanFieldsError::PlanInvalid`] instead of falling back to a UUID
/// label.
fn parse_initiative_meta(
    plan_toml: &str,
    initiative_id: &str,
) -> Result<InitiativeMeta, PlanFieldsError> {
    let doc: toml::Value = toml::from_str(plan_toml).map_err(|e| PlanFieldsError::PlanInvalid {
        initiative_id: initiative_id.to_owned(),
        reason: format!("TOML parse error: {e}"),
    })?;

    let initiative_block = doc
        .get("plan")
        .and_then(|p| p.get("initiative"))
        .and_then(|i| i.as_table());
    let workspace_block = doc.get("workspace").and_then(|w| w.as_table());

    let name = match workspace_block.and_then(|t| t.get("name")) {
        Some(toml::Value::String(s)) => normalize_workspace_name(s, initiative_id)?,
        Some(other) => {
            return Err(PlanFieldsError::PlanInvalid {
                initiative_id: initiative_id.to_owned(),
                reason: format!(
                    "[workspace] name must be a TOML string, got {}",
                    other.type_str()
                ),
            });
        }
        None => {
            return Err(PlanFieldsError::PlanInvalid {
                initiative_id: initiative_id.to_owned(),
                reason: "[workspace] is missing required `name` field".to_owned(),
            });
        }
    };
    let description = initiative_block
        .and_then(|t| t.get("description"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_owned();

    Ok(InitiativeMeta { name, description })
}

fn normalize_workspace_name(raw: &str, initiative_id: &str) -> Result<String, PlanFieldsError> {
    let name = raw.trim().to_owned();
    if name.is_empty() {
        return Err(PlanFieldsError::PlanInvalid {
            initiative_id: initiative_id.to_owned(),
            reason: "[workspace] name is empty".to_owned(),
        });
    }
    if name.chars().any(|c| c.is_control()) {
        return Err(PlanFieldsError::PlanInvalid {
            initiative_id: initiative_id.to_owned(),
            reason: "[workspace] name must be a single line with no control characters".to_owned(),
        });
    }
    let count = name.chars().count();
    if count > WORKSPACE_NAME_MAX_CHARS {
        return Err(PlanFieldsError::PlanInvalid {
            initiative_id: initiative_id.to_owned(),
            reason: format!(
                "[workspace] name is {count} characters, exceeds cap {WORKSPACE_NAME_MAX_CHARS}"
            ),
        });
    }
    Ok(name)
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

fn string_field(entry: &toml::Value, field: &str) -> Option<String> {
    entry
        .get(field)
        .and_then(|v| v.as_str())
        .map(str::trim_end)
        .map(str::to_owned)
}

fn u32_field(entry: &toml::Value, field: &str, default: u32) -> u32 {
    entry
        .get(field)
        .and_then(|v| v.as_integer())
        .and_then(|v| u32::try_from(v).ok())
        .unwrap_or(default)
}

fn optional_u32_field(entry: &toml::Value, field: &str) -> Option<u32> {
    entry
        .get(field)
        .and_then(|v| v.as_integer())
        .and_then(|v| u32::try_from(v).ok())
}

fn credential_refs(entry: &toml::Value) -> Vec<PlanCredentialRef> {
    entry
        .get("credentials")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|credential| {
                    let name = string_field(credential, "name")?;
                    Some(PlanCredentialRef {
                        name,
                        proxy_type: string_field(credential, "proxy_type").unwrap_or_default(),
                        mount_as: string_field(credential, "mount_as"),
                        upstream_host_port: string_field(credential, "upstream_host_port"),
                        upstream_url: string_field(credential, "upstream_url"),
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

fn task_verifier_refs(entry: &toml::Value) -> Vec<PlanTaskVerifierRef> {
    entry
        .get("verifiers")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|verifier| {
                    let name = string_field(verifier, "name")?;
                    Some(PlanTaskVerifierRef {
                        name,
                        image: string_field(verifier, "image").unwrap_or_default(),
                        command: string_field(verifier, "command").unwrap_or_default(),
                        timeout: string_field(verifier, "timeout").unwrap_or_default(),
                        on_failure: string_field(verifier, "on_failure")
                            .unwrap_or_else(|| "block_review".to_owned()),
                        artifact: string_field(verifier, "artifact"),
                        artifact_max_bytes: verifier
                            .get("artifact_max_bytes")
                            .and_then(|v| v.as_integer())
                            .and_then(|v| u64::try_from(v).ok()),
                        allowed_egress: string_array(verifier, "allowed_egress"),
                    })
                })
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
        const INITIATIVES: &str = Table::Initiatives.as_str();
        const TASKS: &str = Table::Tasks.as_str();
        const SIGNED_PLAN_ARTIFACTS: &str = Table::SignedPlanArtifacts.as_str();
        let tmp = TempDir::new().unwrap();
        let db = tmp.path().join("kernel.db");
        let initiative_id = "init-1".to_owned();
        let task_id = "00000000-0000-4000-8000-000000000001".to_owned();
        let task_name = "t-1".to_owned();
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
            guard
                .execute(
                    &format!(
                        "INSERT INTO {TASKS} \
                     (task_id, task_name, initiative_id, lane_id, state, actor, \
                      policy_epoch, admitted_at, transitioned_at) \
                     VALUES (?1, ?2, ?3, 'default', 'Running', 'op', 1, 1, 1)"
                    ),
                    rusqlite::params![&task_id, &task_name, &initiative_id],
                )
                .unwrap();
            guard
                .execute(
                    &format!(
                        "INSERT INTO {SIGNED_PLAN_ARTIFACTS} \
                     (initiative_id, plan_bytes, plan_sig, stored_at) \
                     VALUES (?1, ?2, x'00', 1)"
                    ),
                    rusqlite::params![&initiative_id, plan_toml.as_bytes()],
                )
                .unwrap();
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
            task_name = "t-1"
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
            task_name = "t-1"
            path_allowlist            = ["src/**", "tests/**", "README.md"]
            path_export_to_successors = true
            path_export_globs         = ["src/ipc/**", "src/auth/**"]
            path_scope_override       = true
            session_agent_type        = "Reviewer"
        "#;
        let (tmp, _init, task) = fresh_store_with_plan(plan);
        let conn = open_ro(tmp.path()).unwrap();

        let f = reveal_for_task(&conn, &task).expect("present");
        assert_eq!(f.path_allowlist, vec!["src/**", "tests/**", "README.md"]);
        assert!(f.path_export_to_successors);
        assert_eq!(f.path_export_globs, vec!["src/ipc/**", "src/auth/**"]);
        assert!(f.path_scope_override);
        assert_eq!(f.session_agent_type, "Reviewer");
    }

    #[test]
    fn reveal_matches_historical_task_id_field_for_readonly_views() {
        // v0.2.x sealed plans used `task_id` as the operator-facing
        // task identity. Migration 0030 preserves those rows by setting
        // `tasks.task_name = tasks.task_id`; the readonly reveal view
        // must still recover the original plan fields so historical
        // initiative/task dashboard pages do not 500. This does NOT
        // relax the new admission parser, which rejects legacy task ids.
        let plan = r#"
            [[tasks]]
            task_id = "t-1"
            path_allowlist = ["gtm/analysis/web_discovery/"]
            session_agent_type = "Reviewer"
            clone_strategy = "blobless"
        "#;
        let (tmp, _init, task) = fresh_store_with_plan(plan);
        let conn = open_ro(tmp.path()).unwrap();

        let f = reveal_for_task(&conn, &task).expect("historical task_id fallback");
        assert_eq!(f.path_allowlist, vec!["gtm/analysis/web_discovery/"]);
        assert_eq!(f.session_agent_type, "Reviewer");
        assert_eq!(f.clone_strategy.as_deref(), Some("blobless"));
    }

    #[test]
    fn reveal_round_trips_retry_limits_and_uses_kernel_defaults() {
        let defaults_plan = r#"
            [[tasks]]
            task_name = "t-1"
        "#;
        let (tmp, _init, task) = fresh_store_with_plan(defaults_plan);
        let conn = open_ro(tmp.path()).unwrap();
        let f = reveal_for_task(&conn, &task).expect("present");
        assert_eq!(f.max_review_rejections, DEFAULT_MAX_REVIEW_REJECTIONS);
        assert_eq!(f.max_crash_retries, DEFAULT_MAX_CRASH_RETRIES);

        let explicit_plan = r#"
            [[tasks]]
            task_name = "t-1"
            max_review_rejections  = 4
            max_crash_retries      = 5
        "#;
        let (tmp, _init, task) = fresh_store_with_plan(explicit_plan);
        let conn = open_ro(tmp.path()).unwrap();
        let f = reveal_for_task(&conn, &task).expect("present");
        assert_eq!(f.max_review_rejections, 4);
        assert_eq!(f.max_crash_retries, 5);
    }

    #[test]
    fn reveal_initiative_meta_requires_workspace_name_and_returns_it() {
        let plan = r#"
            [plan.initiative]
            description = "Make operator review faster"

            [workspace]
            name = "Ship dashboard polish"

            [[tasks]]
            task_name = "t-1"
        "#;
        let (tmp, init, _task) = fresh_store_with_plan(plan);
        let conn = open_ro(tmp.path()).unwrap();

        let meta = reveal_initiative_meta(&conn, &init).unwrap();
        assert_eq!(meta.name, "Ship dashboard polish");
        assert_eq!(meta.description, "Make operator review faster");
    }

    #[test]
    fn reveal_initiative_meta_rejects_missing_workspace_name() {
        let plan = r#"
            [plan.initiative]
            description = "No workspace label"

            [workspace]
            lane_id = "default"

            [[tasks]]
            task_name = "t-1"
        "#;
        let (tmp, init, _task) = fresh_store_with_plan(plan);
        let conn = open_ro(tmp.path()).unwrap();

        let err = reveal_initiative_meta(&conn, &init).unwrap_err();
        match err {
            PlanFieldsError::PlanInvalid { reason, .. } => {
                assert!(reason.contains("[workspace]"), "got: {reason}");
                assert!(reason.contains("name"), "got: {reason}");
            }
            other => panic!("expected PlanInvalid; got {other:?}"),
        }
    }

    #[test]
    fn reveal_silently_ignores_non_string_array_entries() {
        // Defense-in-depth parity with the kernel parser's
        // `parse_plan_tasks_silently_ignores_non_string_array_entries`.
        let plan = r#"
            [[tasks]]
            task_name = "t-1"
            path_allowlist = ["src/**", 42, "ok.rs"]
        "#;
        let (tmp, _init, task) = fresh_store_with_plan(plan);
        let conn = open_ro(tmp.path()).unwrap();
        let f = reveal_for_task(&conn, &task).unwrap();
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
        const TASKS: &str = Table::Tasks.as_str();
        let tmp = TempDir::new().unwrap();
        let db = tmp.path().join("kernel.db");
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
            guard
                .execute(
                    &format!(
                        "INSERT INTO {TASKS} \
                     (task_id, task_name, initiative_id, lane_id, state, actor, \
                      policy_epoch, admitted_at, transitioned_at) \
                     VALUES ('t-x', 't-x', 'init-x', 'default', 'Admitted', 'op', 1, 1, 1)"
                    ),
                    [],
                )
                .unwrap();
        }
        let conn = open_ro(tmp.path()).unwrap();
        let err = reveal_for_task(&conn, "t-x").unwrap_err();
        match err {
            PlanFieldsError::PlanArtifactMissing {
                task_id,
                initiative_id,
            } => {
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
            PlanFieldsError::PlanInvalid {
                initiative_id,
                reason,
            } => {
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
            PlanFieldsError::PlanInvalid {
                initiative_id,
                reason,
            } => {
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
        let plan = "[[tasks]]\ntask_name = \"t-other\"\n";
        let (tmp, init, task) = fresh_store_with_plan(plan);
        let conn = open_ro(tmp.path()).unwrap();

        let err = reveal_for_task(&conn, &task).unwrap_err();
        match err {
            PlanFieldsError::TaskNotInPlan {
                initiative_id,
                task_id,
                task_name,
            } => {
                assert_eq!(initiative_id, init);
                assert_eq!(task_id, task);
                assert_eq!(task_name, "t-1");
            }
            other => panic!("expected TaskNotInPlan; got {other:?}"),
        }
    }

    // ── submitted_toml_for_initiative ──────────────────────────────────

    /// `submitted_toml_for_initiative` MUST return the V1 plan bytes
    /// byte-for-byte. The dashboard plan-view endpoint surfaces these
    /// directly to the operator (no re-parse / re-serialize) per
    /// `INV-DASHBOARD-INITIATIVE-PLAN-VISIBLE-01`.
    #[test]
    fn submitted_toml_returns_v1_plan_bytes_byte_for_byte() {
        let plan = "[workspace]\nname = \"original\"\n[[tasks]]\ntask_id = \"t-1\"\n";
        let (tmp, init, _task) = fresh_store_with_plan(plan);
        let conn = open_ro(tmp.path()).unwrap();
        let bytes = submitted_toml_for_initiative(&conn, &init).unwrap();
        assert_eq!(bytes.as_deref(), Some(plan.as_bytes()));
    }

    /// `Ok(None)` when no plan row exists for the initiative — the
    /// caller (kernel-side glue) MUST translate this to `Gone {kind:
    /// "plan"}` rather than `NotFound`, distinguishing
    /// "archived/purged" from "unknown initiative".
    #[test]
    fn submitted_toml_returns_none_when_no_plan_artifact_row_exists() {
        const INITIATIVES: &str = Table::Initiatives.as_str();
        let tmp = TempDir::new().unwrap();
        let db = tmp.path().join("kernel.db");
        {
            let store = Store::open(&db).unwrap();
            let guard = store.lock_sync();
            guard
                .execute(
                    &format!(
                        "INSERT INTO {INITIATIVES} \
                     (initiative_id, state, terminal_criteria_json, \
                      plan_artifact_sha256, created_at) \
                     VALUES ('init-empty', 'Draft', '{{}}', 'sha-x', 1)"
                    ),
                    [],
                )
                .unwrap();
        }
        let conn = open_ro(tmp.path()).unwrap();
        assert_eq!(
            submitted_toml_for_initiative(&conn, "init-empty").unwrap(),
            None,
        );
    }
}

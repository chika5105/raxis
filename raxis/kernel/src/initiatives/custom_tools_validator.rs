//! kernel-side validation of operator-declared custom
//! tools at plan-approve time.
//!
//! Closes the kernel-side leg of `custom-tools.md` so a plan that
//! declares a structurally malformed `[[profiles.<name>.custom_tool]]`
//! block is rejected BEFORE the kernel's plan-bundle write
//! transaction opens. The matching planner-side wire shape lives
//! in `crates/planner-core/src/custom_tools.rs` and is what the
//! Executor binary uses to register the tool at session start.
//!
//! ## Validation rules (per `custom-tools.md`)
//!
//! 1. `name` matches `^[a-z][a-z0-9_]{0,47}$` (`§5.3`).
//! 2. `name` is NOT in [`RESERVED_TOOL_NAMES`] (`§5.1`).
//! 3. Within a single profile, `name` is unique (`§5.2`).
//! 4. `description` length ∈ [8, 800] chars (`§3.2`).
//! 5. `command` is a non-empty array of non-empty strings, with
//!    `command[0]` an absolute path (the spec's "first element is
//!    an absolute path inside the VM filesystem"; `§3.2`).
//! 6. `timeout_seconds` ≤ `policy.toml`
//!    `max_custom_tool_timeout_seconds` (default 300; `§3.2`).
//! 7. `[plan.tasks.<name>.custom_tool]` is rejected with
//!    `FAIL_CUSTOM_TOOL_TASK_LEVEL_NOT_ALLOWED` (`§3.4`).
//!
//! V2 deliberately stops short of the full Draft-07 schema
//! validation (`§4`) — that's a separate JSON-Schema validator
//! crate the V3 follow-up will land. The MVP rejects the obvious
//! shape errors so a typo never round-trips into a session.

use std::collections::{BTreeMap, HashMap, HashSet};

use serde_json::json;
use thiserror::Error;

// ---------------------------------------------------------------------------
// Reserved tool names (per custom-tools.md §5.1)
// ---------------------------------------------------------------------------

/// Names a custom tool MUST NOT use, per `custom-tools.md §5.1`.
/// Mirrors the spec's verbatim list. Adding a new base tool or
/// kernel-mediated intent that the LLM sees by name requires a
/// matching entry here AND a `custom-tools.md §5.1` spec update.
pub const RESERVED_TOOL_NAMES: &[&str] = &[
    // Base tools the planner-core registry ships
    "read_file",
    "write_file",
    "edit_file",
    "glob_search",
    "grep_search",
    "bash",
    "TodoWrite",
    "SubmitReview",
    // Kernel-mediated intents (PascalCase per planner-api.md)
    "ActivateSubTask",
    "CompleteTask",
    "SingleCommit",
    "IntegrationMerge",
    "EscalationRequest",
    "InferenceRequest",
    "InitiativeCompleted",
    "ResolveSubEscalation",
    "ApprovePlan",
    "ApprovePolicy",
    "ApproveWarning",
    // Reserved for future base tools
    "WebFetch",
    "WebSearch",
    "StructuredOutput",
    "Sleep",
];

/// Hard cap on `timeout_seconds` when the policy doesn't specify
/// one. Per `custom-tools.md §3.2`'s default for
/// `max_custom_tool_timeout_seconds`.
pub const DEFAULT_MAX_CUSTOM_TOOL_TIMEOUT_SECONDS: u32 = 300;
pub const MAX_EFFECTIVE_CUSTOM_TOOLS_PER_TASK: usize = 25;
const DEFAULT_STDIN_MAX_BYTES: u64 = 262_144;
const DEFAULT_STDOUT_MAX_BYTES: u64 = 65_536;
const DEFAULT_STDERR_MAX_BYTES: u64 = 16_384;
const HARD_MAX_STDIN_BYTES: u64 = 1_048_576;
const HARD_MAX_STDOUT_BYTES: u64 = 1_048_576;
const HARD_MAX_STDERR_BYTES: u64 = 262_144;
const LOCALITY_GUEST_SUBPROCESS: &str = "guest_subprocess";
const LOCALITY_HOST_SUBPROCESS: &str = "host_subprocess";
const LOCALITY_HOST_MCP: &str = "host_mcp";
const LOCALITY_REMOTE_MCP: &str = "remote_mcp";

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Structured failure codes for custom-tool admission.
///
/// These map onto the `FAIL_CUSTOM_TOOL_*` codes called out in
/// `custom-tools.md §4.3, §5.1, §5.2, §5.3` and the operator-
/// ergonomics audit surface. Surface as
/// `LifecycleError::PlanInvalid { reason: format!("{err}") }` at
/// the lifecycle boundary — keeping the typed enum here lets the
/// kernel's higher-level handler match on the variant for richer
/// audit output without losing the wire-stable string projection.
#[derive(Debug, Error)]
pub enum CustomToolValidationError {
    /// `name` does not match `^[a-z][a-z0-9_]{0,47}$`.
    #[error("FAIL_CUSTOM_TOOL_NAME_INVALID: profile={profile}, name={name:?} (must match ^[a-z][a-z0-9_]{{0,47}}$)")]
    NameInvalid {
        /// Profile the offending entry sits on.
        profile: String,
        /// Offending tool name.
        name: String,
    },
    /// `name` collides with a reserved tool name.
    #[error("FAIL_CUSTOM_TOOL_NAME_RESERVED: profile={profile}, name={name:?} is reserved")]
    NameReserved {
        /// Profile the offending entry sits on.
        profile: String,
        /// Offending tool name.
        name: String,
    },
    /// Two tools in the same profile share a name.
    #[error("FAIL_CUSTOM_TOOL_NAME_COLLISION: profile={profile}, name={name:?} declared twice")]
    NameCollision {
        /// Profile the collision was observed on.
        profile: String,
        /// Offending tool name.
        name: String,
    },
    /// `description` length is outside [8, 800].
    #[error("FAIL_CUSTOM_TOOL_DESCRIPTION_LENGTH: profile={profile}, name={name:?} length={len} (must be 8..=800)")]
    DescriptionLength {
        /// Profile the offending entry sits on.
        profile: String,
        /// Offending tool name.
        name: String,
        /// Observed length.
        len: usize,
    },
    /// `command` array is empty or contains an empty / non-absolute
    /// first element.
    #[error("FAIL_CUSTOM_TOOL_COMMAND_INVALID: profile={profile}, name={name:?}: {reason}")]
    CommandInvalid {
        /// Profile the offending entry sits on.
        profile: String,
        /// Offending tool name.
        name: String,
        /// Free-form reason.
        reason: String,
    },
    /// `execution_locality` is not one of the supported locality labels.
    #[error("FAIL_CUSTOM_TOOL_LOCALITY_INVALID: profile={profile}, name={name:?}, locality={locality:?}")]
    LocalityInvalid {
        /// Profile the offending entry sits on.
        profile: String,
        /// Offending tool name.
        name: String,
        /// Operator-supplied locality.
        locality: String,
    },
    /// `timeout_seconds` exceeds the policy hard cap.
    #[error("FAIL_CUSTOM_TOOL_TIMEOUT_EXCEEDED: profile={profile}, name={name:?}, got={got}s, cap={cap}s")]
    TimeoutExceeded {
        /// Profile the offending entry sits on.
        profile: String,
        /// Offending tool name.
        name: String,
        /// Operator-supplied timeout.
        got: u32,
        /// Policy hard cap.
        cap: u32,
    },
    /// Effective profile or task-level merged bundle exceeds the V2 count cap.
    #[error("FAIL_CUSTOM_TOOL_COUNT_EXCEEDED: scope={scope}, count={count}, limit={limit}")]
    CountExceeded {
        /// Profile or plan task name being validated.
        scope: String,
        /// Effective tool count.
        count: usize,
        /// Hard limit.
        limit: usize,
    },
    /// `[plan.tasks.<name>.custom_tool]` is declared (custom tools
    /// must live at the profile level only).
    #[error("FAIL_CUSTOM_TOOL_TASK_LEVEL_NOT_ALLOWED: task_name={task_id} declares custom_tool; custom tools must live at the profile level")]
    TaskLevelNotAllowed {
        /// Offending plan task name.
        task_id: String,
    },
    /// A task references a profile that is not declared.
    #[error("FAIL_CUSTOM_TOOL_PROFILE_UNKNOWN: task_name={task_id} references unknown profile={profile:?}")]
    ProfileUnknown {
        /// Offending plan task name.
        task_id: String,
        /// Missing profile name.
        profile: String,
    },
    /// A profile inheritance chain contains a cycle.
    #[error("FAIL_CUSTOM_TOOL_PROFILE_CYCLE: profile inheritance cycle includes {profile:?}")]
    ProfileCycle {
        /// Profile where cycle was detected.
        profile: String,
    },
    /// Orchestrator profiles are kernel-owned and never
    /// operator-configurable.
    #[error(
        "FAIL_ORCHESTRATOR_PROFILE_NOT_ALLOWED: profile={profile:?} attempts to use Orchestrator"
    )]
    OrchestratorProfileNotAllowed {
        /// Offending profile.
        profile: String,
    },
    /// Reviewer profiles cannot carry custom tools directly or via
    /// inheritance.
    #[error("FAIL_REVIEWER_CUSTOM_TOOL_NOT_ALLOWED: profile={profile:?} is Reviewer-effective but declares custom tools")]
    ReviewerCustomToolNotAllowed {
        /// Offending profile.
        profile: String,
    },
    /// Task profile role and task session_agent_type disagree.
    #[error("FAIL_CUSTOM_TOOL_PROFILE_AGENT_MISMATCH: task_name={task_id}, profile={profile:?} is {profile_role}, task is {task_role}")]
    ProfileAgentMismatch {
        /// Offending plan task name.
        task_id: String,
        /// Referenced profile.
        profile: String,
        /// Profile's effective role.
        profile_role: &'static str,
        /// Task's declared role.
        task_role: &'static str,
    },
    /// Inherited profile merge produced a duplicate tool name.
    #[error("FAIL_CUSTOM_TOOL_NAME_COLLISION: profile={profile}, name={name:?} declared more than once after inheritance")]
    InheritedNameCollision {
        /// Effective profile being resolved.
        profile: String,
        /// Duplicate name.
        name: String,
    },
    /// TOML structural error (missing required field, wrong type).
    #[error("FAIL_CUSTOM_TOOL_SCHEMA_INVALID: {reason}")]
    SchemaInvalid {
        /// Free-form parse-error reason.
        reason: String,
    },
}

// ---------------------------------------------------------------------------
// Validator entry point
// ---------------------------------------------------------------------------

/// Validate every `[[profiles.<profile>.custom_tool]]` block in
/// `plan_toml`, plus refuse `[[plan.tasks.<id>.custom_tool]]` per
/// `custom-tools.md §3.4`.
///
/// `policy_max_timeout_seconds` is the policy's
/// `max_custom_tool_timeout_seconds` (default 300 when absent).
///
/// On success, returns the number of tools validated (so the
/// caller can include the count in the `PlanApproved` audit
/// record).
pub fn validate_plan_custom_tools(
    plan_toml: &str,
    policy_max_timeout_seconds: u32,
) -> Result<u32, CustomToolValidationError> {
    let doc: toml::Value =
        toml::from_str(plan_toml).map_err(|e| CustomToolValidationError::SchemaInvalid {
            reason: format!("plan TOML parse error: {e}"),
        })?;

    reject_task_level_custom_tools(&doc)?;
    let profiles = parse_profiles(&doc, policy_max_timeout_seconds)?;
    let mut total = 0u32;
    for (profile_name, profile) in &profiles {
        total = total.saturating_add(profile.tools.len() as u32);
        let resolved = resolve_profile(&profiles, profile_name)?;
        if resolved.tools.len() > MAX_EFFECTIVE_CUSTOM_TOOLS_PER_TASK {
            return Err(CustomToolValidationError::CountExceeded {
                scope: profile_name.clone(),
                count: resolved.tools.len(),
                limit: MAX_EFFECTIVE_CUSTOM_TOOLS_PER_TASK,
            });
        }
        if resolved.role == ProfileRole::Orchestrator {
            return Err(CustomToolValidationError::OrchestratorProfileNotAllowed {
                profile: profile_name.clone(),
            });
        }
        if resolved.role == ProfileRole::Reviewer && !resolved.tools.is_empty() {
            return Err(CustomToolValidationError::ReviewerCustomToolNotAllowed {
                profile: profile_name.clone(),
            });
        }
    }

    Ok(total)
}

/// Resolve the kernel-stamped custom-tool JSON bundle for one task.
/// `None` means the task has no `profiles = [...]` or the referenced
/// profiles have no effective tools. Errors mirror admission
/// validation failures.
pub fn custom_tool_bundle_json_for_task(
    plan_toml: &str,
    task_name: &str,
    task_role: &'static str,
) -> Result<Option<String>, CustomToolValidationError> {
    let doc: toml::Value =
        toml::from_str(plan_toml).map_err(|e| CustomToolValidationError::SchemaInvalid {
            reason: format!("plan TOML parse error: {e}"),
        })?;
    let profile_names = task_profile_names(&doc, task_name)?;
    if profile_names.is_empty() {
        return Ok(None);
    }
    let profiles = parse_profiles(&doc, DEFAULT_MAX_CUSTOM_TOOL_TIMEOUT_SECONDS)?;
    let mut merged_tools = Vec::new();
    let mut seen_tools: HashMap<String, ValidatedTool> = HashMap::new();
    for profile_name in profile_names {
        let resolved = resolve_profile(&profiles, &profile_name).map_err(|e| match e {
            CustomToolValidationError::SchemaInvalid { .. } => {
                CustomToolValidationError::ProfileUnknown {
                    task_id: task_name.to_owned(),
                    profile: profile_name.clone(),
                }
            }
            other => other,
        })?;
        if resolved.role == ProfileRole::Reviewer && !resolved.tools.is_empty() {
            return Err(CustomToolValidationError::ReviewerCustomToolNotAllowed {
                profile: profile_name,
            });
        }
        if resolved.role.as_str() != task_role {
            return Err(CustomToolValidationError::ProfileAgentMismatch {
                task_id: task_name.to_owned(),
                profile: profile_name,
                profile_role: resolved.role.as_str(),
                task_role,
            });
        }
        for tool in resolved.tools {
            if let Some(previous) = seen_tools.get(&tool.name) {
                if tool_defs_equivalent(previous, &tool) {
                    continue;
                }
                return Err(CustomToolValidationError::InheritedNameCollision {
                    profile: tool.profile_name,
                    name: tool.name,
                });
            }
            seen_tools.insert(tool.name.clone(), tool.clone());
            merged_tools.push(tool.json);
        }
    }
    if merged_tools.len() > MAX_EFFECTIVE_CUSTOM_TOOLS_PER_TASK {
        return Err(CustomToolValidationError::CountExceeded {
            scope: format!("task:{task_name}"),
            count: merged_tools.len(),
            limit: MAX_EFFECTIVE_CUSTOM_TOOLS_PER_TASK,
        });
    }
    if merged_tools.is_empty() {
        return Ok(None);
    }
    let json = serde_json::to_string(&json!({ "tools": merged_tools })).map_err(|e| {
        CustomToolValidationError::SchemaInvalid {
            reason: format!("custom tool bundle JSON serialize failed: {e}"),
        }
    })?;
    Ok(Some(json))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProfileRole {
    Executor,
    Reviewer,
    Orchestrator,
}

impl ProfileRole {
    fn as_str(self) -> &'static str {
        match self {
            ProfileRole::Executor => "Executor",
            ProfileRole::Reviewer => "Reviewer",
            ProfileRole::Orchestrator => "Orchestrator",
        }
    }
}

#[derive(Debug, Clone)]
struct ProfileDef {
    inherits_from: Option<String>,
    tools: Vec<ValidatedTool>,
}

#[derive(Debug, Clone)]
struct ValidatedTool {
    name: String,
    profile_name: String,
    json: serde_json::Value,
}

#[derive(Debug, Clone)]
struct ResolvedProfile {
    role: ProfileRole,
    tools: Vec<ValidatedTool>,
}

fn reject_task_level_custom_tools(doc: &toml::Value) -> Result<(), CustomToolValidationError> {
    if let Some(tasks) = doc.get("tasks").and_then(|v| v.as_array()) {
        for (idx, task) in tasks.iter().enumerate() {
            if let Some(table) = task.as_table() {
                if table.contains_key("custom_tool") {
                    let task_id = table
                        .get("task_name")
                        .and_then(|v| v.as_str())
                        .map(str::to_owned)
                        .unwrap_or_else(|| format!("tasks[{idx}]"));
                    return Err(CustomToolValidationError::TaskLevelNotAllowed { task_id });
                }
            }
        }
    }
    // Older spec drafts used [plan.tasks.<id>.custom_tool]; reject it
    // too so stale plans fail with the same operator-facing code.
    if let Some(tasks_root) = doc
        .get("plan")
        .and_then(|p| p.as_table())
        .and_then(|p| p.get("tasks"))
        .and_then(|t| t.as_table())
    {
        for (task_id, body) in tasks_root {
            if let Some(table) = body.as_table() {
                if table.contains_key("custom_tool") {
                    return Err(CustomToolValidationError::TaskLevelNotAllowed {
                        task_id: task_id.clone(),
                    });
                }
            }
        }
    }
    Ok(())
}

fn parse_profiles(
    doc: &toml::Value,
    policy_max_timeout_seconds: u32,
) -> Result<HashMap<String, ProfileDef>, CustomToolValidationError> {
    let mut out = HashMap::new();
    let Some(profiles) = doc.get("profiles").and_then(|v| v.as_table()) else {
        return Ok(out);
    };
    for (profile_name, profile_body) in profiles {
        if !is_valid_profile_name(profile_name) {
            return Err(CustomToolValidationError::SchemaInvalid {
                reason: format!(
                    "profile {profile_name:?} is invalid; use ^[A-Za-z][A-Za-z0-9_-]{{0,63}}$"
                ),
            });
        }
        let Some(table) = profile_body.as_table() else {
            continue;
        };
        let role_parent = match table.get("role") {
            None => None,
            Some(toml::Value::String(s)) if s == "Orchestrator" => {
                return Err(CustomToolValidationError::OrchestratorProfileNotAllowed {
                    profile: profile_name.clone(),
                });
            }
            Some(toml::Value::String(s)) if s == "Executor" || s == "Reviewer" => Some(s.clone()),
            Some(toml::Value::String(s)) => {
                return Err(CustomToolValidationError::SchemaInvalid {
                    reason: format!(
                        "profile {profile_name:?} role={s:?} is invalid; valid values: Executor, Reviewer",
                    ),
                });
            }
            Some(other) => {
                return Err(CustomToolValidationError::SchemaInvalid {
                    reason: format!(
                        "profile {profile_name:?} role must be a string; got {:?}",
                        other.type_str()
                    ),
                });
            }
        };
        let inherits_from = match table.get("inherits_from") {
            None => None,
            Some(toml::Value::String(s)) if s == "Orchestrator" => {
                return Err(CustomToolValidationError::OrchestratorProfileNotAllowed {
                    profile: profile_name.clone(),
                });
            }
            Some(toml::Value::String(s)) => Some(s.clone()),
            Some(other) => {
                return Err(CustomToolValidationError::SchemaInvalid {
                    reason: format!(
                        "profile {profile_name:?} inherits_from must be a string; got {:?}",
                        other.type_str()
                    ),
                });
            }
        };
        let inherits_from = match (inherits_from, role_parent) {
            (Some(parent), _) => Some(parent),
            (None, role) => role,
        };
        let tools = parse_profile_tools(profile_name, table, policy_max_timeout_seconds)?;
        out.insert(
            profile_name.clone(),
            ProfileDef {
                inherits_from,
                tools,
            },
        );
    }
    Ok(out)
}

fn parse_profile_tools(
    profile_name: &str,
    table: &toml::map::Map<String, toml::Value>,
    policy_max_timeout_seconds: u32,
) -> Result<Vec<ValidatedTool>, CustomToolValidationError> {
    let Some(tools_raw) = table.get("custom_tool") else {
        return Ok(Vec::new());
    };
    let Some(tools_arr) = tools_raw.as_array() else {
        return Err(CustomToolValidationError::SchemaInvalid {
            reason: format!(
                "profile {profile_name:?} custom_tool field must be an array of tables; got {:?}",
                tools_raw.type_str(),
            ),
        });
    };
    let mut out = Vec::with_capacity(tools_arr.len());
    let mut seen_names = HashSet::new();
    for entry in tools_arr {
        let Some(t) = entry.as_table() else {
            return Err(CustomToolValidationError::SchemaInvalid {
                reason: format!(
                    "profile {profile_name:?} custom_tool entries must be tables, got {:?}",
                    entry.type_str(),
                ),
            });
        };
        let tool = validate_profile_tool(profile_name, t, policy_max_timeout_seconds)?;
        if !seen_names.insert(tool.name.clone()) {
            return Err(CustomToolValidationError::NameCollision {
                profile: profile_name.to_owned(),
                name: tool.name,
            });
        }
        out.push(tool);
    }
    Ok(out)
}

fn validate_profile_tool(
    profile_name: &str,
    t: &toml::map::Map<String, toml::Value>,
    policy_max_timeout_seconds: u32,
) -> Result<ValidatedTool, CustomToolValidationError> {
    let name = t.get("name").and_then(|v| v.as_str()).ok_or_else(|| {
        CustomToolValidationError::SchemaInvalid {
            reason: format!(
                "profile {profile_name:?} custom_tool missing required string field `name`",
            ),
        }
    })?;
    let description = t
        .get("description")
        .and_then(|v| v.as_str())
        .ok_or_else(|| CustomToolValidationError::SchemaInvalid {
            reason: format!(
                "profile {profile_name:?} custom_tool {name:?} missing required string field `description`",
            ),
        })?;
    let command_raw = t
        .get("command")
        .ok_or_else(|| CustomToolValidationError::SchemaInvalid {
            reason: format!(
                "profile {profile_name:?} custom_tool {name:?} missing required field `command`",
            ),
        })?;
    let timeout_secs: u32 = match t.get("timeout_seconds") {
        None => 60,
        Some(v) => v
            .as_integer()
            .and_then(|n| u32::try_from(n).ok())
            .ok_or_else(|| CustomToolValidationError::SchemaInvalid {
                reason: format!(
                    "profile {profile_name:?} custom_tool {name:?} timeout_seconds must be a non-negative integer",
                ),
            })?,
    };
    let parse_byte_cap = |field: &'static str,
                          default: u64,
                          hard_cap: u64|
     -> Result<u64, CustomToolValidationError> {
        match t.get(field) {
            None => Ok(default),
            Some(v) => {
                let cap = v.as_integer().and_then(|n| u64::try_from(n).ok()).ok_or_else(|| {
                    CustomToolValidationError::SchemaInvalid {
                        reason: format!(
                            "profile {profile_name:?} custom_tool {name:?} {field} must be a positive integer",
                        ),
                    }
                })?;
                if cap == 0 {
                    return Err(CustomToolValidationError::SchemaInvalid {
                        reason: format!(
                            "profile {profile_name:?} custom_tool {name:?} {field} must be at least 1 byte",
                        ),
                    });
                }
                if cap > hard_cap {
                    return Err(CustomToolValidationError::SchemaInvalid {
                        reason: format!(
                            "profile {profile_name:?} custom_tool {name:?} {field}={cap} exceeds hard cap {hard_cap}",
                        ),
                    });
                }
                Ok(cap)
            }
        }
    };
    let stdin_max_bytes = parse_byte_cap(
        "stdin_max_bytes",
        DEFAULT_STDIN_MAX_BYTES,
        HARD_MAX_STDIN_BYTES,
    )?;
    let stdout_max_bytes = parse_byte_cap(
        "stdout_max_bytes",
        DEFAULT_STDOUT_MAX_BYTES,
        HARD_MAX_STDOUT_BYTES,
    )?;
    let stderr_max_bytes = parse_byte_cap(
        "stderr_max_bytes",
        DEFAULT_STDERR_MAX_BYTES,
        HARD_MAX_STDERR_BYTES,
    )?;
    let expose_stderr = t
        .get("expose_stderr")
        .map(|v| {
            v.as_bool()
                .ok_or_else(|| CustomToolValidationError::SchemaInvalid {
                    reason: format!(
                    "profile {profile_name:?} custom_tool {name:?} expose_stderr must be a boolean",
                ),
                })
        })
        .transpose()?
        .unwrap_or(false);
    let execution_locality = match t.get("execution_locality") {
        None => LOCALITY_GUEST_SUBPROCESS.to_owned(),
        Some(toml::Value::String(s)) if is_supported_execution_locality(s) => s.clone(),
        Some(toml::Value::String(s)) => {
            return Err(CustomToolValidationError::LocalityInvalid {
                profile: profile_name.to_owned(),
                name: name.to_owned(),
                locality: s.clone(),
            });
        }
        Some(other) => {
            return Err(CustomToolValidationError::SchemaInvalid {
                reason: format!(
                    "profile {profile_name:?} custom_tool {name:?} execution_locality must be a string; got {:?}",
                    other.type_str(),
                ),
            });
        }
    };

    if !is_valid_custom_tool_name(name) {
        return Err(CustomToolValidationError::NameInvalid {
            profile: profile_name.to_owned(),
            name: name.to_owned(),
        });
    }
    if RESERVED_TOOL_NAMES.contains(&name) {
        return Err(CustomToolValidationError::NameReserved {
            profile: profile_name.to_owned(),
            name: name.to_owned(),
        });
    }
    let len = description.chars().count();
    if !(8..=800).contains(&len) {
        return Err(CustomToolValidationError::DescriptionLength {
            profile: profile_name.to_owned(),
            name: name.to_owned(),
            len,
        });
    }
    let cmd_arr =
        command_raw
            .as_array()
            .ok_or_else(|| CustomToolValidationError::CommandInvalid {
                profile: profile_name.to_owned(),
                name: name.to_owned(),
                reason: format!(
                    "command must be an array of strings; got {:?}",
                    command_raw.type_str(),
                ),
            })?;
    if cmd_arr.is_empty() {
        return Err(CustomToolValidationError::CommandInvalid {
            profile: profile_name.to_owned(),
            name: name.to_owned(),
            reason: "command must have at least one element".to_owned(),
        });
    }
    let mut command = Vec::with_capacity(cmd_arr.len());
    for (i, c) in cmd_arr.iter().enumerate() {
        let s = c
            .as_str()
            .ok_or_else(|| CustomToolValidationError::CommandInvalid {
                profile: profile_name.to_owned(),
                name: name.to_owned(),
                reason: format!("command[{i}] must be a string; got {:?}", c.type_str()),
            })?;
        if s.is_empty() {
            return Err(CustomToolValidationError::CommandInvalid {
                profile: profile_name.to_owned(),
                name: name.to_owned(),
                reason: format!("command[{i}] must be non-empty"),
            });
        }
        if i == 0 && !s.starts_with('/') {
            let path_scope = if execution_locality == LOCALITY_GUEST_SUBPROCESS {
                "inside the VM filesystem"
            } else {
                "on the kernel host"
            };
            return Err(CustomToolValidationError::CommandInvalid {
                profile: profile_name.to_owned(),
                name: name.to_owned(),
                reason: format!("command[0]={s:?} must be an absolute path {path_scope}",),
            });
        }
        command.push(s.to_owned());
    }
    if timeout_secs > policy_max_timeout_seconds {
        return Err(CustomToolValidationError::TimeoutExceeded {
            profile: profile_name.to_owned(),
            name: name.to_owned(),
            got: timeout_secs,
            cap: policy_max_timeout_seconds,
        });
    }

    let schema = t
        .get("schema")
        .map(toml_value_to_json)
        .unwrap_or_else(|| json!({ "type": "object", "additionalProperties": true }));
    let mut json_obj = BTreeMap::new();
    json_obj.insert("name".to_owned(), json!(name));
    json_obj.insert("profile_name".to_owned(), json!(profile_name));
    json_obj.insert("description".to_owned(), json!(description));
    json_obj.insert("command".to_owned(), json!(command));
    json_obj.insert("execution_locality".to_owned(), json!(execution_locality));
    json_obj.insert("schema".to_owned(), schema);
    json_obj.insert("timeout_seconds".to_owned(), json!(timeout_secs));
    json_obj.insert("stdin_max_bytes".to_owned(), json!(stdin_max_bytes));
    json_obj.insert("stdout_max_bytes".to_owned(), json!(stdout_max_bytes));
    json_obj.insert("stderr_max_bytes".to_owned(), json!(stderr_max_bytes));
    json_obj.insert("expose_stderr".to_owned(), json!(expose_stderr));

    Ok(ValidatedTool {
        name: name.to_owned(),
        profile_name: profile_name.to_owned(),
        json: json!(json_obj),
    })
}

fn resolve_profile(
    profiles: &HashMap<String, ProfileDef>,
    profile_name: &str,
) -> Result<ResolvedProfile, CustomToolValidationError> {
    let mut visiting = HashSet::new();
    resolve_profile_inner(profiles, profile_name, &mut visiting)
}

fn resolve_profile_inner(
    profiles: &HashMap<String, ProfileDef>,
    profile_name: &str,
    visiting: &mut HashSet<String>,
) -> Result<ResolvedProfile, CustomToolValidationError> {
    let Some(profile) = profiles.get(profile_name) else {
        return Err(CustomToolValidationError::SchemaInvalid {
            reason: format!("unknown profile {profile_name:?}"),
        });
    };
    if !visiting.insert(profile_name.to_owned()) {
        return Err(CustomToolValidationError::ProfileCycle {
            profile: profile_name.to_owned(),
        });
    }
    let mut resolved = match profile.inherits_from.as_deref() {
        None => ResolvedProfile {
            role: ProfileRole::Executor,
            tools: Vec::new(),
        },
        Some("Executor") => ResolvedProfile {
            role: ProfileRole::Executor,
            tools: Vec::new(),
        },
        Some("Reviewer") => ResolvedProfile {
            role: ProfileRole::Reviewer,
            tools: Vec::new(),
        },
        Some("Orchestrator") => {
            return Err(CustomToolValidationError::OrchestratorProfileNotAllowed {
                profile: profile_name.to_owned(),
            });
        }
        Some(parent) => resolve_profile_inner(profiles, parent, visiting)?,
    };
    visiting.remove(profile_name);

    let mut tools_by_name: HashMap<String, ValidatedTool> = resolved
        .tools
        .iter()
        .map(|t| (t.name.clone(), t.clone()))
        .collect();
    for tool in &profile.tools {
        if let Some(previous) = tools_by_name.get(&tool.name) {
            if tool_defs_equivalent(previous, tool) {
                continue;
            }
            return Err(CustomToolValidationError::InheritedNameCollision {
                profile: tool.profile_name.clone(),
                name: tool.name.clone(),
            });
        }
        tools_by_name.insert(tool.name.clone(), tool.clone());
        resolved.tools.push(tool.clone());
    }
    Ok(resolved)
}

fn tool_defs_equivalent(a: &ValidatedTool, b: &ValidatedTool) -> bool {
    comparable_tool_json(&a.json) == comparable_tool_json(&b.json)
}

fn comparable_tool_json(value: &serde_json::Value) -> serde_json::Value {
    let mut value = value.clone();
    if let Some(obj) = value.as_object_mut() {
        obj.remove("profile_name");
    }
    value
}

fn task_profile_names(
    doc: &toml::Value,
    task_name: &str,
) -> Result<Vec<String>, CustomToolValidationError> {
    let Some(tasks) = doc.get("tasks").and_then(|v| v.as_array()) else {
        return Ok(Vec::new());
    };
    for task in tasks {
        let Some(table) = task.as_table() else {
            continue;
        };
        if table.get("task_name").and_then(|v| v.as_str()) == Some(task_name) {
            if table.contains_key("profile") {
                return Err(CustomToolValidationError::SchemaInvalid {
                    reason: format!(
                        "[[tasks]] (task `{task_name}`) uses deprecated `profile`; use profiles = [\"...\"]"
                    ),
                });
            }
            return match table.get("profiles") {
                None => Ok(Vec::new()),
                Some(toml::Value::Array(values)) => {
                    let mut out = Vec::with_capacity(values.len());
                    let mut seen = HashSet::new();
                    for value in values {
                        match value {
                            toml::Value::String(s) if !s.trim().is_empty() => {
                                let profile = s.trim().to_owned();
                                if !seen.insert(profile.clone()) {
                                    return Err(CustomToolValidationError::SchemaInvalid {
                                        reason: format!(
                                            "[[tasks]] (task `{task_name}`) declares duplicate profile {profile:?}"
                                        ),
                                    });
                                }
                                out.push(profile);
                            }
                            _ => {
                                return Err(CustomToolValidationError::SchemaInvalid {
                                    reason: format!(
                                        "[[tasks]] (task `{task_name}`) profiles must be an array of non-empty strings"
                                    ),
                                });
                            }
                        }
                    }
                    Ok(out)
                }
                Some(_) => Err(CustomToolValidationError::SchemaInvalid {
                    reason: format!(
                        "[[tasks]] (task `{task_name}`) profiles must be an array of non-empty strings"
                    ),
                }),
            };
        }
    }
    Ok(Vec::new())
}

fn is_supported_execution_locality(locality: &str) -> bool {
    matches!(
        locality,
        LOCALITY_GUEST_SUBPROCESS
            | LOCALITY_HOST_SUBPROCESS
            | LOCALITY_HOST_MCP
            | LOCALITY_REMOTE_MCP
    )
}

fn toml_value_to_json(value: &toml::Value) -> serde_json::Value {
    serde_json::to_value(value).unwrap_or(serde_json::Value::Null)
}

/// Pure-byte name regex check. Faster than pulling in a regex
/// crate for one expression.
pub fn is_valid_custom_tool_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    if bytes.is_empty() || bytes.len() > 48 {
        return false;
    }
    if !bytes[0].is_ascii_lowercase() {
        return false;
    }
    bytes[1..]
        .iter()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'_')
}

/// Profile identifiers are operator-facing labels that also become
/// kernel-stamped audit metadata, so keep them compact and shell-neutral.
pub fn is_valid_profile_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    if bytes.is_empty() || bytes.len() > 64 {
        return false;
    }
    if !bytes[0].is_ascii_alphabetic() {
        return false;
    }
    bytes[1..]
        .iter()
        .all(|b| b.is_ascii_alphanumeric() || *b == b'_' || *b == b'-')
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn plan_with_tool(profile: &str, body: &str) -> String {
        format!(
            r#"
[plan]

[[plan.tasks.t1]]
session_agent_type = "Executor"

[profiles.{profile}]
inherits_from = "Executor"

[[profiles.{profile}.custom_tool]]
{body}
"#,
        )
    }

    #[test]
    fn name_regex_accepts_canonical_examples() {
        assert!(is_valid_custom_tool_name("query_telemetry"));
        assert!(is_valid_custom_tool_name("a1"));
        assert!(is_valid_custom_tool_name("frontend_lint_v2"));
    }

    #[test]
    fn name_regex_rejects_uppercase_or_digits_at_start() {
        assert!(!is_valid_custom_tool_name(""));
        assert!(!is_valid_custom_tool_name("Foo"));
        assert!(!is_valid_custom_tool_name("1foo"));
        assert!(!is_valid_custom_tool_name("foo-bar"));
        assert!(!is_valid_custom_tool_name("a".repeat(49).as_str()));
    }

    #[test]
    fn validates_minimum_well_formed_tool() {
        let plan = plan_with_tool(
            "frontend",
            r#"
name        = "query_telemetry"
description = "Query the internal telemetry service for a target"
command     = ["/usr/local/bin/query.sh"]
"#,
        );
        let count = validate_plan_custom_tools(&plan, 300).unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn stamps_kernel_owned_execution_locality_into_task_bundle() {
        let plan = r#"
[[tasks]]
task_name            = "unity-build"
session_agent_type = "Executor"
profiles          = ["unity_mobile"]

[profiles.unity_mobile]
inherits_from = "Executor"

[[profiles.unity_mobile.custom_tool]]
name               = "unity_list_scenes"
description        = "List Unity editor scenes through a host MCP adapter"
command            = ["/usr/local/bin/raxis-tool-mcp", "unity", "list-scenes"]
execution_locality = "host_mcp"
"#;
        assert_eq!(validate_plan_custom_tools(plan, 300).unwrap(), 1);
        let bundle = custom_tool_bundle_json_for_task(plan, "unity-build", "Executor")
            .unwrap()
            .unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&bundle).unwrap();
        assert_eq!(parsed["tools"][0]["profile_name"], "unity_mobile");
        assert_eq!(parsed["tools"][0]["execution_locality"], "host_mcp");
    }

    #[test]
    fn rejects_invalid_profile_name() {
        let plan = r#"
[profiles."bad space"]
inherits_from = "Executor"
"#;
        let err = validate_plan_custom_tools(plan, 300).unwrap_err();
        assert!(err.to_string().contains("profile \"bad space\" is invalid"));
    }

    #[test]
    fn rejects_unknown_execution_locality() {
        let plan = plan_with_tool(
            "frontend",
            r#"
name               = "ok_tool"
description        = "valid description here"
command            = ["/usr/local/bin/dummy"]
execution_locality = "browser_extension"
"#,
        );
        match validate_plan_custom_tools(&plan, 300).unwrap_err() {
            CustomToolValidationError::LocalityInvalid { locality, .. } => {
                assert_eq!(locality, "browser_extension");
            }
            other => panic!("expected LocalityInvalid, got {other:?}"),
        }
    }

    #[test]
    fn resolves_inherited_executor_profile_bundle_for_task() {
        let plan = r#"
[[tasks]]
task_name            = "unity-build"
session_agent_type = "Executor"
profiles          = ["unity_mobile"]

[profiles.unity_base]
inherits_from = "Executor"

[[profiles.unity_base.custom_tool]]
name        = "unity_list_scenes"
description = "List Unity editor scenes through a local MCP adapter"
command     = ["/usr/local/bin/raxis-tool-mcp", "unity", "list-scenes"]

[profiles.unity_mobile]
inherits_from = "unity_base"

[[profiles.unity_mobile.custom_tool]]
name            = "unity_build_player"
description     = "Build the local Unity mobile player through a local MCP adapter"
command         = ["/usr/local/bin/raxis-tool-mcp", "unity", "build-player"]
timeout_seconds = 120

[profiles.unity_mobile.custom_tool.schema]
type = "object"
"#;
        assert_eq!(validate_plan_custom_tools(plan, 300).unwrap(), 2);
        let bundle = custom_tool_bundle_json_for_task(plan, "unity-build", "Executor")
            .unwrap()
            .unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&bundle).unwrap();
        let tools = parsed["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 2);
        assert_eq!(tools[0]["name"], "unity_list_scenes");
        assert_eq!(tools[1]["name"], "unity_build_player");
        assert_eq!(tools[1]["timeout_seconds"], 120);
    }

    #[test]
    fn resolves_multiple_executor_profiles_for_task_in_declared_order() {
        let plan = r#"
[[tasks]]
task_name            = "repo-db"
session_agent_type = "Executor"
profiles          = ["repo_tools", "db_tools"]

[profiles.repo_tools]
inherits_from = "Executor"

[[profiles.repo_tools.custom_tool]]
name        = "repo_search"
description = "Search repository files through a local wrapper"
command     = ["/usr/local/bin/raxis-tool", "repo-search"]

[profiles.db_tools]
inherits_from = "Executor"

[[profiles.db_tools.custom_tool]]
name        = "db_schema_lookup"
description = "Look up one database schema through a local wrapper"
command     = ["/usr/local/bin/raxis-tool", "db-schema"]
"#;
        assert_eq!(validate_plan_custom_tools(plan, 300).unwrap(), 2);
        let bundle = custom_tool_bundle_json_for_task(plan, "repo-db", "Executor")
            .unwrap()
            .unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&bundle).unwrap();
        let tools = parsed["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 2);
        assert_eq!(tools[0]["name"], "repo_search");
        assert_eq!(tools[1]["name"], "db_schema_lookup");
        assert_eq!(tools[0]["profile_name"], "repo_tools");
        assert_eq!(tools[1]["profile_name"], "db_tools");
    }

    #[test]
    fn rejects_merged_task_bundle_above_effective_tool_cap() {
        let mut plan = String::from(
            r#"
[[tasks]]
task_name            = "repo-db"
session_agent_type = "Executor"
profiles          = [
"#,
        );
        for idx in 0..=MAX_EFFECTIVE_CUSTOM_TOOLS_PER_TASK {
            plan.push_str(&format!("  \"p{idx}\",\n"));
        }
        plan.push_str("]\n");
        for idx in 0..=MAX_EFFECTIVE_CUSTOM_TOOLS_PER_TASK {
            plan.push_str(&format!(
                r#"
[profiles.p{idx}]
inherits_from = "Executor"

[[profiles.p{idx}.custom_tool]]
name        = "tool_{idx}"
description = "Lookup helper for profile {idx}"
command     = ["/usr/local/bin/raxis-tool", "tool-{idx}"]
"#
            ));
        }

        match custom_tool_bundle_json_for_task(&plan, "repo-db", "Executor").unwrap_err() {
            CustomToolValidationError::CountExceeded {
                scope,
                count,
                limit,
            } => {
                assert_eq!(scope, "task:repo-db");
                assert_eq!(count, MAX_EFFECTIVE_CUSTOM_TOOLS_PER_TASK + 1);
                assert_eq!(limit, MAX_EFFECTIVE_CUSTOM_TOOLS_PER_TASK);
            }
            other => panic!("expected CountExceeded, got {other:?}"),
        }
    }

    #[test]
    fn rejects_duplicate_tool_name_across_selected_task_profiles() {
        let plan = r#"
[[tasks]]
task_name            = "repo-db"
session_agent_type = "Executor"
profiles          = ["repo_tools", "db_tools"]

[profiles.repo_tools]
inherits_from = "Executor"

[[profiles.repo_tools.custom_tool]]
name        = "lookup"
description = "Search repository files through a local wrapper"
command     = ["/usr/local/bin/raxis-tool", "repo-search"]

[profiles.db_tools]
inherits_from = "Executor"

[[profiles.db_tools.custom_tool]]
name        = "lookup"
description = "Look up one database schema through a local wrapper"
command     = ["/usr/local/bin/raxis-tool", "db-schema"]
"#;
        match custom_tool_bundle_json_for_task(plan, "repo-db", "Executor").unwrap_err() {
            CustomToolValidationError::InheritedNameCollision { profile, name } => {
                assert_eq!(profile, "db_tools");
                assert_eq!(name, "lookup");
            }
            other => panic!("expected InheritedNameCollision, got {other:?}"),
        }
    }

    #[test]
    fn deduplicates_identical_tool_name_across_selected_task_profiles() {
        let plan = r#"
[[tasks]]
task_name            = "repo-db"
session_agent_type = "Executor"
profiles          = ["repo_tools", "db_tools"]

[profiles.repo_tools]
inherits_from = "Executor"

[[profiles.repo_tools.custom_tool]]
name        = "lookup"
description = "Search repository files through a local wrapper"
command     = ["/usr/local/bin/raxis-tool", "lookup"]

[profiles.db_tools]
inherits_from = "Executor"

[[profiles.db_tools.custom_tool]]
name        = "lookup"
description = "Search repository files through a local wrapper"
command     = ["/usr/local/bin/raxis-tool", "lookup"]
"#;
        assert_eq!(validate_plan_custom_tools(plan, 300).unwrap(), 2);
        let bundle = custom_tool_bundle_json_for_task(plan, "repo-db", "Executor")
            .unwrap()
            .unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&bundle).unwrap();
        let tools = parsed["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0]["name"], "lookup");
        assert_eq!(tools[0]["profile_name"], "repo_tools");
    }

    #[test]
    fn rejects_deprecated_singular_task_profile() {
        let plan = r#"
[[tasks]]
task_name            = "repo-db"
session_agent_type = "Executor"
profile            = "repo_tools"

[profiles.repo_tools]
inherits_from = "Executor"
"#;
        let err = custom_tool_bundle_json_for_task(plan, "repo-db", "Executor").unwrap_err();
        assert!(err.to_string().contains("deprecated `profile`"));
    }

    #[test]
    fn rejects_duplicate_task_profile_selection() {
        let plan = r#"
[[tasks]]
task_name            = "repo-db"
session_agent_type = "Executor"
profiles          = ["repo_tools", "repo_tools"]

[profiles.repo_tools]
inherits_from = "Executor"
"#;
        let err = custom_tool_bundle_json_for_task(plan, "repo-db", "Executor").unwrap_err();
        assert!(err.to_string().contains("duplicate profile"));
    }

    #[test]
    fn reviewer_effective_profile_rejects_custom_tools() {
        let plan = r#"
[profiles.review_local]
role = "Reviewer"

[[profiles.review_local.custom_tool]]
name        = "unity_review"
description = "Inspect Unity assets through a local adapter"
command     = ["/usr/local/bin/raxis-tool-mcp", "unity", "inspect"]
"#;
        match validate_plan_custom_tools(plan, 300).unwrap_err() {
            CustomToolValidationError::ReviewerCustomToolNotAllowed { profile } => {
                assert_eq!(profile, "review_local");
            }
            other => panic!("expected ReviewerCustomToolNotAllowed, got {other:?}"),
        }
    }

    #[test]
    fn task_profile_role_must_match_task_agent_type() {
        let plan = r#"
[[tasks]]
task_name            = "review-unity"
session_agent_type = "Reviewer"
profiles          = ["unity_mobile"]

[profiles.unity_mobile]
inherits_from = "Executor"

[[profiles.unity_mobile.custom_tool]]
name        = "unity_build_player"
description = "Build the local Unity mobile player through a local MCP adapter"
command     = ["/usr/local/bin/raxis-tool-mcp", "unity", "build-player"]
"#;
        match custom_tool_bundle_json_for_task(plan, "review-unity", "Reviewer").unwrap_err() {
            CustomToolValidationError::ProfileAgentMismatch {
                task_id,
                profile,
                profile_role,
                task_role,
            } => {
                assert_eq!(task_id, "review-unity");
                assert_eq!(profile, "unity_mobile");
                assert_eq!(profile_role, "Executor");
                assert_eq!(task_role, "Reviewer");
            }
            other => panic!("expected ProfileAgentMismatch, got {other:?}"),
        }
    }

    #[test]
    fn rejects_reserved_name() {
        let plan = plan_with_tool(
            "frontend",
            r#"
name        = "bash"
description = "shadow the base tool"
command     = ["/usr/local/bin/dummy"]
"#,
        );
        match validate_plan_custom_tools(&plan, 300).unwrap_err() {
            CustomToolValidationError::NameReserved { name, profile } => {
                assert_eq!(name, "bash");
                assert_eq!(profile, "frontend");
            }
            other => panic!("expected NameReserved, got {other:?}"),
        }
    }

    #[test]
    fn rejects_invalid_name_format() {
        let plan = plan_with_tool(
            "frontend",
            r#"
name        = "Has-Dash"
description = "wrong shape"
command     = ["/usr/local/bin/dummy"]
"#,
        );
        match validate_plan_custom_tools(&plan, 300).unwrap_err() {
            CustomToolValidationError::NameInvalid { name, .. } => {
                assert_eq!(name, "Has-Dash");
            }
            other => panic!("expected NameInvalid, got {other:?}"),
        }
    }

    #[test]
    fn rejects_short_description() {
        let plan = plan_with_tool(
            "frontend",
            r#"
name        = "ok"
description = "tiny"
command     = ["/usr/local/bin/dummy"]
"#,
        );
        match validate_plan_custom_tools(&plan, 300).unwrap_err() {
            CustomToolValidationError::DescriptionLength { len, .. } => {
                assert_eq!(len, 4);
            }
            other => panic!("expected DescriptionLength, got {other:?}"),
        }
    }

    #[test]
    fn rejects_long_description() {
        let body = format!(
            "name = \"ok\"\ndescription = \"{}\"\ncommand = [\"/usr/local/bin/dummy\"]\n",
            "x".repeat(801),
        );
        let plan = plan_with_tool("frontend", &body);
        match validate_plan_custom_tools(&plan, 300).unwrap_err() {
            CustomToolValidationError::DescriptionLength { len, .. } => {
                assert_eq!(len, 801);
            }
            other => panic!("expected DescriptionLength, got {other:?}"),
        }
    }

    #[test]
    fn rejects_relative_command_path() {
        let plan = plan_with_tool(
            "frontend",
            r#"
name        = "ok_tool"
description = "valid description here"
command     = ["query.sh"]
"#,
        );
        match validate_plan_custom_tools(&plan, 300).unwrap_err() {
            CustomToolValidationError::CommandInvalid { reason, .. } => {
                assert!(reason.contains("absolute"));
            }
            other => panic!("expected CommandInvalid(absolute), got {other:?}"),
        }
    }

    #[test]
    fn rejects_timeout_above_policy_cap() {
        let plan = plan_with_tool(
            "frontend",
            r#"
name            = "slow_tool"
description     = "valid description here"
command         = ["/usr/local/bin/dummy"]
timeout_seconds = 999
"#,
        );
        match validate_plan_custom_tools(&plan, 300).unwrap_err() {
            CustomToolValidationError::TimeoutExceeded { got, cap, .. } => {
                assert_eq!(got, 999);
                assert_eq!(cap, 300);
            }
            other => panic!("expected TimeoutExceeded, got {other:?}"),
        }
    }

    #[test]
    fn rejects_io_cap_above_hard_limit() {
        let plan = plan_with_tool(
            "frontend",
            r#"
name             = "large_output"
description      = "valid description here"
command          = ["/usr/local/bin/dummy"]
stdout_max_bytes = 1048577
"#,
        );
        match validate_plan_custom_tools(&plan, 300).unwrap_err() {
            CustomToolValidationError::SchemaInvalid { reason } => {
                assert!(reason.contains("stdout_max_bytes"));
                assert!(reason.contains("exceeds hard cap"));
            }
            other => panic!("expected SchemaInvalid(cap), got {other:?}"),
        }
    }

    #[test]
    fn rejects_profile_internal_collision() {
        // Two custom_tool entries on the same profile sharing a name.
        let plan = r#"
[plan]

[[plan.tasks.t1]]
session_agent_type = "Executor"

[profiles.frontend]
inherits_from = "Executor"

[[profiles.frontend.custom_tool]]
name        = "shared"
description = "first declaration"
command     = ["/usr/local/bin/a"]

[[profiles.frontend.custom_tool]]
name        = "shared"
description = "second declaration"
command     = ["/usr/local/bin/b"]
"#;
        match validate_plan_custom_tools(plan, 300).unwrap_err() {
            CustomToolValidationError::NameCollision { name, .. } => {
                assert_eq!(name, "shared");
            }
            other => panic!("expected NameCollision, got {other:?}"),
        }
    }

    #[test]
    fn task_level_custom_tool_is_rejected() {
        let plan = r#"
[plan]

[plan.tasks.t1]
session_agent_type = "Executor"

[[plan.tasks.t1.custom_tool]]
name        = "should_not_compile"
description = "task-level decl is forbidden"
command     = ["/usr/local/bin/x"]
"#;
        match validate_plan_custom_tools(plan, 300).unwrap_err() {
            CustomToolValidationError::TaskLevelNotAllowed { task_id } => {
                assert_eq!(task_id, "t1");
            }
            other => panic!("expected TaskLevelNotAllowed, got {other:?}"),
        }
    }

    #[test]
    fn no_profiles_returns_zero() {
        let plan = r#"
[plan]

[[plan.tasks.t1]]
session_agent_type = "Executor"
"#;
        let count = validate_plan_custom_tools(plan, 300).unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn reserved_names_constants_are_in_sync_with_spec() {
        // Spot-check a few canonical entries from custom-tools.md §5.1
        for n in [
            "read_file",
            "bash",
            "SubmitReview",
            "IntegrationMerge",
            "WebFetch",
        ] {
            assert!(
                RESERVED_TOOL_NAMES.contains(&n),
                "RESERVED_TOOL_NAMES must contain {n:?} per custom-tools.md §5.1"
            );
        }
    }
}

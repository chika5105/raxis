//! V2_GAPS §B2 — kernel-side validation of operator-declared custom
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
//! 7. `[plan.tasks.<id>.custom_tool]` is rejected with
//!    `FAIL_CUSTOM_TOOL_TASK_LEVEL_NOT_ALLOWED` (`§3.4`).
//!
//! V2 deliberately stops short of the full Draft-07 schema
//! validation (`§4`) — that's a separate JSON-Schema validator
//! crate the V3 follow-up will land. The MVP rejects the obvious
//! shape errors so a typo never round-trips into a session.

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
        name:    String,
    },
    /// `name` collides with a reserved tool name.
    #[error("FAIL_CUSTOM_TOOL_NAME_RESERVED: profile={profile}, name={name:?} is reserved")]
    NameReserved {
        /// Profile the offending entry sits on.
        profile: String,
        /// Offending tool name.
        name:    String,
    },
    /// Two tools in the same profile share a name.
    #[error("FAIL_CUSTOM_TOOL_NAME_COLLISION: profile={profile}, name={name:?} declared twice")]
    NameCollision {
        /// Profile the collision was observed on.
        profile: String,
        /// Offending tool name.
        name:    String,
    },
    /// `description` length is outside [8, 800].
    #[error("FAIL_CUSTOM_TOOL_DESCRIPTION_LENGTH: profile={profile}, name={name:?} length={len} (must be 8..=800)")]
    DescriptionLength {
        /// Profile the offending entry sits on.
        profile: String,
        /// Offending tool name.
        name:    String,
        /// Observed length.
        len:     usize,
    },
    /// `command` array is empty or contains an empty / non-absolute
    /// first element.
    #[error("FAIL_CUSTOM_TOOL_COMMAND_INVALID: profile={profile}, name={name:?}: {reason}")]
    CommandInvalid {
        /// Profile the offending entry sits on.
        profile: String,
        /// Offending tool name.
        name:    String,
        /// Free-form reason.
        reason:  String,
    },
    /// `timeout_seconds` exceeds the policy hard cap.
    #[error("FAIL_CUSTOM_TOOL_TIMEOUT_EXCEEDED: profile={profile}, name={name:?}, got={got}s, cap={cap}s")]
    TimeoutExceeded {
        /// Profile the offending entry sits on.
        profile: String,
        /// Offending tool name.
        name:    String,
        /// Operator-supplied timeout.
        got:     u32,
        /// Policy hard cap.
        cap:     u32,
    },
    /// `[plan.tasks.<id>.custom_tool]` is declared (custom tools
    /// must live at the profile level only).
    #[error("FAIL_CUSTOM_TOOL_TASK_LEVEL_NOT_ALLOWED: task_id={task_id} declares custom_tool; custom tools must live at the profile level")]
    TaskLevelNotAllowed {
        /// Offending task id.
        task_id: String,
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
    plan_toml:                  &str,
    policy_max_timeout_seconds: u32,
) -> Result<u32, CustomToolValidationError> {
    let doc: toml::Value = toml::from_str(plan_toml).map_err(|e| {
        CustomToolValidationError::SchemaInvalid {
            reason: format!("plan TOML parse error: {e}"),
        }
    })?;

    let mut total: u32 = 0;

    // 1. Refuse [plan.tasks.<id>.custom_tool] (§3.4).
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

    // 2. Walk profiles. The TOML shape is `[profiles.<name>]` with
    //    optional `[[profiles.<name>.custom_tool]]` array-of-tables.
    let Some(profiles) = doc.get("profiles").and_then(|v| v.as_table()) else {
        return Ok(0);
    };

    for (profile_name, profile_body) in profiles {
        let Some(table) = profile_body.as_table() else { continue; };
        let Some(tools_raw) = table.get("custom_tool") else { continue; };
        let Some(tools_arr) = tools_raw.as_array() else {
            return Err(CustomToolValidationError::SchemaInvalid {
                reason: format!(
                    "profile {profile_name:?} custom_tool field must be \
                     an array of tables; got {:?}", tools_raw.type_str(),
                ),
            });
        };

        let mut seen_names: std::collections::HashSet<String>
            = std::collections::HashSet::new();

        for entry in tools_arr {
            let Some(t) = entry.as_table() else {
                return Err(CustomToolValidationError::SchemaInvalid {
                    reason: format!(
                        "profile {profile_name:?} custom_tool entries \
                         must be tables, got {:?}", entry.type_str(),
                    ),
                });
            };

            // Required fields — name, description, command.
            let name = t.get("name").and_then(|v| v.as_str()).ok_or_else(|| {
                CustomToolValidationError::SchemaInvalid {
                    reason: format!(
                        "profile {profile_name:?} custom_tool missing \
                         required string field `name`",
                    ),
                }
            })?;
            let description = t.get("description").and_then(|v| v.as_str()).ok_or_else(|| {
                CustomToolValidationError::SchemaInvalid {
                    reason: format!(
                        "profile {profile_name:?} custom_tool {name:?} \
                         missing required string field `description`",
                    ),
                }
            })?;
            let command_raw = t.get("command").ok_or_else(|| {
                CustomToolValidationError::SchemaInvalid {
                    reason: format!(
                        "profile {profile_name:?} custom_tool {name:?} \
                         missing required field `command`",
                    ),
                }
            })?;
            let timeout_secs: u32 = match t.get("timeout_seconds") {
                None    => 60, // spec default
                Some(v) => v.as_integer().and_then(|n| u32::try_from(n).ok())
                    .ok_or_else(|| CustomToolValidationError::SchemaInvalid {
                        reason: format!(
                            "profile {profile_name:?} custom_tool {name:?} \
                             timeout_seconds must be a non-negative integer",
                        ),
                    })?,
            };

            // §5.3 name format.
            if !is_valid_custom_tool_name(name) {
                return Err(CustomToolValidationError::NameInvalid {
                    profile: profile_name.clone(),
                    name:    name.to_owned(),
                });
            }
            // §5.1 reserved.
            if RESERVED_TOOL_NAMES.iter().any(|r| *r == name) {
                return Err(CustomToolValidationError::NameReserved {
                    profile: profile_name.clone(),
                    name:    name.to_owned(),
                });
            }
            // §5.2 profile-internal uniqueness.
            if !seen_names.insert(name.to_owned()) {
                return Err(CustomToolValidationError::NameCollision {
                    profile: profile_name.clone(),
                    name:    name.to_owned(),
                });
            }
            // §3.2 description length.
            let len = description.chars().count();
            if !(8..=800).contains(&len) {
                return Err(CustomToolValidationError::DescriptionLength {
                    profile: profile_name.clone(),
                    name:    name.to_owned(),
                    len,
                });
            }
            // §3.2 command shape.
            let cmd_arr = command_raw.as_array().ok_or_else(|| {
                CustomToolValidationError::CommandInvalid {
                    profile: profile_name.clone(),
                    name:    name.to_owned(),
                    reason:  format!(
                        "command must be an array of strings; got {:?}",
                        command_raw.type_str(),
                    ),
                }
            })?;
            if cmd_arr.is_empty() {
                return Err(CustomToolValidationError::CommandInvalid {
                    profile: profile_name.clone(),
                    name:    name.to_owned(),
                    reason:  "command must have at least one element".to_owned(),
                });
            }
            for (i, c) in cmd_arr.iter().enumerate() {
                let s = c.as_str().ok_or_else(|| {
                    CustomToolValidationError::CommandInvalid {
                        profile: profile_name.clone(),
                        name:    name.to_owned(),
                        reason:  format!(
                            "command[{i}] must be a string; got {:?}",
                            c.type_str(),
                        ),
                    }
                })?;
                if s.is_empty() {
                    return Err(CustomToolValidationError::CommandInvalid {
                        profile: profile_name.clone(),
                        name:    name.to_owned(),
                        reason:  format!("command[{i}] must be non-empty"),
                    });
                }
                if i == 0 && !s.starts_with('/') {
                    return Err(CustomToolValidationError::CommandInvalid {
                        profile: profile_name.clone(),
                        name:    name.to_owned(),
                        reason:  format!(
                            "command[0]={s:?} must be an absolute path inside the VM filesystem",
                        ),
                    });
                }
            }
            // §3.2 timeout cap.
            if timeout_secs > policy_max_timeout_seconds {
                return Err(CustomToolValidationError::TimeoutExceeded {
                    profile: profile_name.clone(),
                    name:    name.to_owned(),
                    got:     timeout_secs,
                    cap:     policy_max_timeout_seconds,
                });
            }
            total = total.saturating_add(1);
        }
    }

    Ok(total)
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
        for n in ["read_file", "bash", "SubmitReview", "IntegrationMerge", "WebFetch"] {
            assert!(RESERVED_TOOL_NAMES.iter().any(|r| *r == n),
                "RESERVED_TOOL_NAMES must contain {n:?} per custom-tools.md §5.1");
        }
    }
}

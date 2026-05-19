//! `vm_capabilities` Tool — the LLM-callable surface for the
//! `INV-EXEC-DISCOVERY-01` capability manifest.
//!
//! The manifest itself (probes + caching + redaction + projection)
//! lives in [`crate::vm_capabilities`]; this module is the thin
//! [`Tool`] wrapper that surfaces it to the dispatch loop.
//!
//! ## Why a separate module
//!
//! The `vm_capabilities` module is pure data + sync probes (no
//! `async`, no [`Tool`] dependency). Keeping the [`Tool`] impl in
//! its own file means the manifest types stay independently
//! testable (the manifest crate's tests don't pull in the
//! dispatch-loop fixtures), and the planner-harness keeps a
//! one-file-per-tool layout that mirrors `tools.rs`'s shape.
//!
//! ## Wire shape (input)
//!
//! ```json
//! {
//!   "categories": ["binaries"|"python"|"node"|"rust"|"go"|"env"|"filesystem"|"all"]?,
//!   "filter": {
//!     "binary_name":    string?,
//!     "python_package": string?,
//!     "node_package":   string?,
//!     "env_var":        string?
//!   }?
//! }
//! ```
//!
//! Defaults: `categories = ["all"]`, no filters. Any unknown
//! category string surfaces as a structured tool error so the
//! model can recover (rather than silently swallowing the
//! request).
//!
//! ## Wire shape (output)
//!
//! Pretty-printed JSON serialisation of `CapabilityManifest`
//! after applying the LLM-supplied categories + filter. Always a
//! success [`ToolOutput::ok`] — a missing interpreter / probe
//! failure is real information about the VM, not an error.
//!
//! ## Caching + audit
//!
//! The probe is cached per-process via
//! [`crate::vm_capabilities::cached_capabilities`], so repeat
//! invocations are O(1). The dispatch loop's existing tool-
//! invocation audit chain records every call (`ToolAuditEvent`
//! with the canonical query envelope); we deliberately do NOT
//! emit a custom audit event from inside `execute` because the
//! manifest body is non-sensitive (the env-redaction filter is
//! the load-bearing privacy boundary), and a duplicated audit
//! event would just bloat the chain.

use crate::tools::{Tool, ToolContext, ToolError, ToolOutput};
use crate::vm_capabilities::{
    cached_capabilities, project_manifest, CapabilityCategory, CapabilityFilter,
};

/// The `vm_capabilities` LLM-callable tool. Returns the
/// per-process cached [`crate::vm_capabilities::CapabilityManifest`]
/// (filtered when the input requested a slice), serialised as
/// pretty JSON.
///
/// **Available to every role** (executor, reviewer,
/// orchestrator). The reviewer is read-only by construction —
/// this tool only reads — so including it does not violate
/// `INV-PLANNER-HARNESS-04`.
pub struct VmCapabilitiesTool;

#[async_trait::async_trait]
impl Tool for VmCapabilitiesTool {
    fn name(&self) -> &'static str {
        "vm_capabilities"
    }

    fn description(&self) -> &'static str {
        "Return deterministic JSON for installed binaries/runtimes/packages, \
         credential-proxy env names, and workdir state. Use for focused \
         capability checks; prefer baked packages, but install normally \
         when the task requires it."
    }

    fn input_schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "categories": {
                    "type":        "array",
                    "description": "Subset to return; defaults to all.",
                    "items": {
                        "type": "string",
                        "enum": [
                            "binaries", "python", "node", "rust",
                            "go", "env", "filesystem", "all",
                        ],
                    },
                },
                "filter": {
                    "type": "object",
                    "description": "Optional filters to scope the response.",
                    "properties": {
                        "binary_name": {
                            "type":        "string",
                            "description": "Substring filter for binary names.",
                        },
                        "python_package": {
                            "type":        "string",
                            "description": "Look up one Python package.",
                        },
                        "node_package": {
                            "type":        "string",
                            "description": "Look up one global Node package.",
                        },
                        "env_var": {
                            "type":        "string",
                            "description": "Look up one non-private env var.",
                        },
                    }
                }
            }
        })
    }

    async fn execute(
        &self,
        input: &serde_json::Value,
        _ctx: &ToolContext,
    ) -> Result<ToolOutput, ToolError> {
        let categories = parse_categories(input)?;
        let filter = parse_filter(input)?;

        // The probe cache is process-wide (cached_capabilities
        // memoizes on first call), so this is O(1) on every
        // invocation after the first.
        let base = cached_capabilities();
        let projected = project_manifest(base.as_ref(), &categories, &filter);

        let json = serde_json::to_string_pretty(&projected).map_err(|e| ToolError::Internal {
            tool: "vm_capabilities".to_owned(),
            reason: format!("manifest serialise: {e}"),
        })?;
        Ok(ToolOutput::ok(json))
    }
}

/// Parse the `categories: [...]` array. Defaults to `[All]` when
/// absent / null / empty (matches the schema's `description`).
fn parse_categories(input: &serde_json::Value) -> Result<Vec<CapabilityCategory>, ToolError> {
    match input.get("categories") {
        None | Some(serde_json::Value::Null) => Ok(vec![CapabilityCategory::All]),
        Some(serde_json::Value::Array(arr)) if arr.is_empty() => Ok(vec![CapabilityCategory::All]),
        Some(serde_json::Value::Array(arr)) => {
            let mut out = Vec::with_capacity(arr.len());
            for v in arr {
                let s = v.as_str().ok_or_else(|| ToolError::InvalidInput {
                    tool: "vm_capabilities".to_owned(),
                    reason: format!("`categories[]` entries must be strings, got {v:?}"),
                })?;
                let cat =
                    CapabilityCategory::from_wire(s).ok_or_else(|| ToolError::InvalidInput {
                        tool: "vm_capabilities".to_owned(),
                        reason: format!(
                            "unknown category {s:?} (allowed: binaries, \
                             python, node, rust, go, env, filesystem, all)"
                        ),
                    })?;
                out.push(cat);
            }
            Ok(out)
        }
        Some(other) => Err(ToolError::InvalidInput {
            tool: "vm_capabilities".to_owned(),
            reason: format!("`categories` must be an array of strings, got {other:?}"),
        }),
    }
}

/// Parse the `filter: { ... }` object. Defaults to all-fields-
/// `None` when absent / null.
fn parse_filter(input: &serde_json::Value) -> Result<CapabilityFilter, ToolError> {
    match input.get("filter") {
        None | Some(serde_json::Value::Null) => Ok(CapabilityFilter::default()),
        Some(serde_json::Value::Object(map)) => {
            let mut f = CapabilityFilter::default();
            if let Some(v) = map.get("binary_name") {
                f.binary_name = string_or_err(v, "binary_name")?;
            }
            if let Some(v) = map.get("python_package") {
                f.python_package = string_or_err(v, "python_package")?;
            }
            if let Some(v) = map.get("node_package") {
                f.node_package = string_or_err(v, "node_package")?;
            }
            if let Some(v) = map.get("env_var") {
                f.env_var = string_or_err(v, "env_var")?;
            }
            Ok(f)
        }
        Some(other) => Err(ToolError::InvalidInput {
            tool: "vm_capabilities".to_owned(),
            reason: format!("`filter` must be an object, got {other:?}"),
        }),
    }
}

fn string_or_err(v: &serde_json::Value, field: &str) -> Result<Option<String>, ToolError> {
    match v {
        serde_json::Value::Null => Ok(None),
        serde_json::Value::String(s) => Ok(Some(s.clone())),
        other => Err(ToolError::InvalidInput {
            tool: "vm_capabilities".to_owned(),
            reason: format!("filter `{field}` must be a string, got {other:?}"),
        }),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// Default categories ⇒ `[All]` so the LLM that submits
    /// `{}` still gets the full manifest.
    #[test]
    fn parse_categories_defaults_to_all() {
        let v = serde_json::json!({});
        let cats = parse_categories(&v).unwrap();
        assert_eq!(cats, vec![CapabilityCategory::All]);
    }

    #[test]
    fn parse_categories_empty_array_defaults_to_all() {
        let v = serde_json::json!({ "categories": [] });
        let cats = parse_categories(&v).unwrap();
        assert_eq!(cats, vec![CapabilityCategory::All]);
    }

    #[test]
    fn parse_categories_known_strings_round_trip() {
        let v = serde_json::json!({ "categories": ["python", "env"] });
        let cats = parse_categories(&v).unwrap();
        assert_eq!(
            cats,
            vec![CapabilityCategory::Python, CapabilityCategory::Env]
        );
    }

    /// Unknown category ⇒ structured error mentioning the bad
    /// token AND the allowed alternatives so the LLM can recover.
    #[test]
    fn parse_categories_rejects_unknown() {
        let v = serde_json::json!({ "categories": ["python", "moo"] });
        let err = parse_categories(&v).unwrap_err();
        match err {
            ToolError::InvalidInput { tool, reason } => {
                assert_eq!(tool, "vm_capabilities");
                assert!(
                    reason.contains("moo"),
                    "error must cite the bad token: {reason}"
                );
                assert!(
                    reason.contains("binaries"),
                    "error must cite the allowed alternatives: {reason}"
                );
            }
            other => panic!("expected InvalidInput, got {other:?}"),
        }
    }

    #[test]
    fn parse_filter_round_trips_python_package() {
        let v = serde_json::json!({
            "filter": { "python_package": "numpy" }
        });
        let f = parse_filter(&v).unwrap();
        assert_eq!(f.python_package.as_deref(), Some("numpy"));
        assert!(f.binary_name.is_none());
    }

    #[test]
    fn parse_filter_rejects_non_string_field() {
        let v = serde_json::json!({
            "filter": { "binary_name": 42 }
        });
        let err = parse_filter(&v).unwrap_err();
        assert!(matches!(err, ToolError::InvalidInput { .. }));
    }

    /// `to_spec` is what the dispatch loop ships to the model in
    /// `MessageRequest::tools`. The schema MUST advertise the
    /// `vm_capabilities` name and the documented categories enum
    /// — a regression that drops a category leaves the LLM unable
    /// to ask for it.
    #[test]
    fn tool_spec_advertises_categories_enum() {
        let spec = VmCapabilitiesTool.to_spec();
        assert_eq!(spec.name, "vm_capabilities");
        assert!(spec.description.contains("prefer baked packages"));
        assert!(spec.description.contains("install normally"));
        assert!(!spec.description.contains("usually fail"));
        assert!(!spec.description.contains("without egress"));
        let enum_arr = spec
            .input_schema
            .pointer("/properties/categories/items/enum")
            .and_then(|v| v.as_array())
            .expect("schema must declare /properties/categories/items/enum");
        let names: Vec<&str> = enum_arr.iter().filter_map(|v| v.as_str()).collect();
        for required in [
            "binaries",
            "python",
            "node",
            "rust",
            "go",
            "env",
            "filesystem",
            "all",
        ] {
            assert!(
                names.contains(&required),
                "schema enum missing {required}: {names:?}"
            );
        }
    }

    /// `execute` returns parseable JSON and the requested-only
    /// category surfaces.
    #[tokio::test]
    async fn execute_returns_parseable_filtered_json() {
        let ctx = ToolContext::for_workspace(
            std::env::current_dir().unwrap_or_else(|_| PathBuf::from("/tmp")),
        );
        let out = VmCapabilitiesTool
            .execute(&serde_json::json!({"categories": ["filesystem"]}), &ctx)
            .await
            .unwrap();
        assert_eq!(out.is_error, None);
        let parsed: serde_json::Value = serde_json::from_str(&out.content).unwrap();
        // Filesystem is requested → `workdir` must be populated.
        let workdir = parsed
            .pointer("/filesystem/workdir")
            .and_then(|v| v.as_str())
            .expect("filesystem.workdir must be present");
        assert!(!workdir.is_empty(), "workdir must be a non-empty path");
        // Python is NOT requested → must be `null`.
        match parsed.get("python") {
            None | Some(serde_json::Value::Null) => {}
            other => panic!("expected python null when not requested, got {other:?}"),
        }
    }

    /// `execute` with no input fields returns the FULL manifest
    /// (default categories = `[all]`). Smoke check that the tool's
    /// "no args" path works on the live host env.
    #[tokio::test]
    async fn execute_no_args_returns_all_categories() {
        let ctx = ToolContext::for_workspace(
            std::env::current_dir().unwrap_or_else(|_| PathBuf::from("/tmp")),
        );
        let out = VmCapabilitiesTool
            .execute(&serde_json::json!({}), &ctx)
            .await
            .unwrap();
        assert_eq!(out.is_error, None);
        let parsed: serde_json::Value = serde_json::from_str(&out.content).unwrap();
        // Filesystem MUST be present (every host has a cwd).
        assert!(parsed.pointer("/filesystem/workdir").is_some());
        // Binaries section present (may or may not be empty
        // depending on host PATH).
        assert!(parsed.get("binaries").is_some());
        // Env section present (filtered).
        assert!(parsed.get("env").is_some());
    }

    /// Negative test: unknown category produces a structured
    /// tool error the model can recover from (not a hard
    /// `ToolError::Internal`). Pinpoints the LLM-recovery contract.
    #[tokio::test]
    async fn execute_unknown_category_surfaces_invalid_input() {
        let ctx = ToolContext::for_workspace(
            std::env::current_dir().unwrap_or_else(|_| PathBuf::from("/tmp")),
        );
        let err = VmCapabilitiesTool
            .execute(
                &serde_json::json!({"categories": ["totally-bogus-category"]}),
                &ctx,
            )
            .await
            .unwrap_err();
        match err {
            ToolError::InvalidInput { tool, reason } => {
                assert_eq!(tool, "vm_capabilities");
                assert!(reason.contains("totally-bogus-category"));
            }
            other => panic!("expected InvalidInput, got {other:?}"),
        }
    }
}

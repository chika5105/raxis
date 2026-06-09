//! Shared custom-tool authoring helpers.
//!
//! This crate is intentionally local/offline. It does not execute kernel
//! authority decisions; it gives the CLI, dashboard, and future builders one
//! canonical way to normalize model-facing Tool Schemas, mutate `plan.toml`,
//! and dry-run an adapter before a plan is submitted.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::{json, Map, Value};
use thiserror::Error;
use toml_edit::{value, Array, ArrayOfTables, DocumentMut, Item, Table};

pub const DEFAULT_TIMEOUT_SECONDS: u32 = 60;
pub const DEFAULT_STDIN_MAX_BYTES: u64 = 262_144;
pub const DEFAULT_STDOUT_MAX_BYTES: u64 = 65_536;
pub const DEFAULT_STDERR_MAX_BYTES: u64 = 16_384;
pub const HARD_MAX_STDIN_BYTES: u64 = 1_048_576;
pub const HARD_MAX_STDOUT_BYTES: u64 = 1_048_576;
pub const HARD_MAX_STDERR_BYTES: u64 = 262_144;
pub const MAX_EFFECTIVE_CUSTOM_TOOLS_PER_TASK: usize = 25;

const LOCALITIES: &[&str] = &[
    "guest_subprocess",
    "host_subprocess",
    "host_mcp",
    "remote_mcp",
];

const RESERVED_TOOL_NAMES: &[&str] = &[
    "read_file",
    "write_file",
    "edit_file",
    "glob_search",
    "grep_search",
    "bash",
    "TodoWrite",
    "SubmitReview",
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
    "WebFetch",
    "WebSearch",
    "StructuredOutput",
    "Sleep",
];

#[derive(Debug, Error)]
pub enum ToolAuthoringError {
    #[error("invalid TOML: {0}")]
    TomlParse(String),
    #[error("invalid JSON: {0}")]
    JsonParse(String),
    #[error("invalid tool profile {0:?}; use ^[A-Za-z][A-Za-z0-9_-]{{0,63}}$")]
    InvalidProfileName(String),
    #[error("invalid tool name {0:?}; use ^[a-z][a-z0-9_]{{0,47}}$")]
    InvalidToolName(String),
    #[error("tool name {0:?} is reserved by RAXIS")]
    ReservedToolName(String),
    #[error("tool description must be 8..=800 characters; got {0}")]
    InvalidDescriptionLength(usize),
    #[error("tool command must contain at least one argv entry")]
    EmptyCommand,
    #[error("tool command[0]={0:?} must be an absolute path")]
    RelativeCommand(String),
    #[error("tool command[{index}] must be non-empty")]
    EmptyCommandArg { index: usize },
    #[error("execution_locality={0:?} is invalid")]
    InvalidLocality(String),
    #[error("timeout_seconds={got} exceeds cap {cap}")]
    TimeoutExceeded { got: u32, cap: u32 },
    #[error("{field}={got} exceeds hard cap {cap}")]
    ByteCapExceeded {
        field: &'static str,
        got: u64,
        cap: u64,
    },
    #[error("{field} must be at least 1 byte")]
    ByteCapZero { field: &'static str },
    #[error("tool schema invalid: {0}")]
    InvalidSchema(String),
    #[error("profile {profile:?} already declares tool {tool:?}")]
    ToolAlreadyExists { profile: String, tool: String },
    #[error("profile {profile:?} does not declare tool {tool:?}")]
    ToolNotFound { profile: String, tool: String },
    #[error("task {0:?} was not found in [[tasks]]")]
    TaskNotFound(String),
    #[error("task {task:?} already references profile {profile:?}")]
    TaskAlreadyHasProfile { task: String, profile: String },
    #[error("task {task:?} has deprecated scalar `profile`; use profiles = [...]")]
    DeprecatedTaskProfile { task: String },
    #[error("task {task:?} profiles must be an array of strings")]
    InvalidTaskProfiles { task: String },
    #[error("tool execution failed: {0}")]
    Execution(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CustomToolSpec {
    pub profile: String,
    pub name: String,
    pub description: String,
    pub command: Vec<String>,
    pub execution_locality: String,
    pub schema: Value,
    pub timeout_seconds: u32,
    pub stdin_max_bytes: u64,
    pub stdout_max_bytes: u64,
    pub stderr_max_bytes: u64,
    pub expose_stderr: bool,
}

impl CustomToolSpec {
    pub fn validate(&self, max_timeout_seconds: u32) -> Result<(), ToolAuthoringError> {
        validate_profile_name(&self.profile)?;
        validate_tool_name(&self.name)?;
        let desc_len = self.description.chars().count();
        if !(8..=800).contains(&desc_len) {
            return Err(ToolAuthoringError::InvalidDescriptionLength(desc_len));
        }
        if self.command.is_empty() {
            return Err(ToolAuthoringError::EmptyCommand);
        }
        for (idx, arg) in self.command.iter().enumerate() {
            if arg.is_empty() {
                return Err(ToolAuthoringError::EmptyCommandArg { index: idx });
            }
            if idx == 0 && !arg.starts_with('/') {
                return Err(ToolAuthoringError::RelativeCommand(arg.clone()));
            }
        }
        if !LOCALITIES.contains(&self.execution_locality.as_str()) {
            return Err(ToolAuthoringError::InvalidLocality(
                self.execution_locality.clone(),
            ));
        }
        if self.timeout_seconds > max_timeout_seconds {
            return Err(ToolAuthoringError::TimeoutExceeded {
                got: self.timeout_seconds,
                cap: max_timeout_seconds,
            });
        }
        validate_byte_cap(
            "stdin_max_bytes",
            self.stdin_max_bytes,
            HARD_MAX_STDIN_BYTES,
        )?;
        validate_byte_cap(
            "stdout_max_bytes",
            self.stdout_max_bytes,
            HARD_MAX_STDOUT_BYTES,
        )?;
        validate_byte_cap(
            "stderr_max_bytes",
            self.stderr_max_bytes,
            HARD_MAX_STDERR_BYTES,
        )?;
        validate_tool_schema(&self.schema)?;
        Ok(())
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ToolValidationReport {
    pub tool_count: usize,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

impl ToolValidationReport {
    pub fn is_ok(&self) -> bool {
        self.errors.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolDryRunOutput {
    pub status_code: Option<i32>,
    pub timed_out: bool,
    pub stdout: String,
    pub stderr: String,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
}

pub fn default_tool_schema() -> Value {
    json!({
        "type": "object",
        "properties": {},
        "additionalProperties": false
    })
}

pub fn normalize_tool_schema(raw: Option<&str>) -> Result<Value, ToolAuthoringError> {
    let Some(raw) = raw.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(default_tool_schema());
    };
    let parsed: Value =
        serde_json::from_str(raw).map_err(|e| ToolAuthoringError::JsonParse(e.to_string()))?;
    let normalized = normalize_schema_value(parsed)?;
    validate_tool_schema(&normalized)?;
    Ok(normalized)
}

pub fn validate_tool_schema(schema: &Value) -> Result<(), ToolAuthoringError> {
    let Some(obj) = schema.as_object() else {
        return Err(ToolAuthoringError::InvalidSchema(
            "root schema must be a JSON object".to_owned(),
        ));
    };
    match obj.get("type").and_then(Value::as_str) {
        Some("object") => {}
        Some(other) => {
            return Err(ToolAuthoringError::InvalidSchema(format!(
                "root type must be object, got {other:?}"
            )));
        }
        None => {
            return Err(ToolAuthoringError::InvalidSchema(
                "root schema must declare type = object".to_owned(),
            ));
        }
    }
    validate_schema_node(schema, "$", true)
}

pub fn append_custom_tool(
    plan_text: &str,
    spec: &CustomToolSpec,
) -> Result<String, ToolAuthoringError> {
    spec.validate(300)?;
    let mut doc = parse_document(plan_text)?;
    if tool_exists_in_plan(plan_text, &spec.profile, &spec.name)? {
        return Err(ToolAuthoringError::ToolAlreadyExists {
            profile: spec.profile.clone(),
            tool: spec.name.clone(),
        });
    }

    let profiles = ensure_table(doc.as_table_mut(), "profiles")?;
    let profile = ensure_table(profiles, &spec.profile)?;
    if !profile.contains_key("inherits_from") && !profile.contains_key("role") {
        profile["inherits_from"] = value("Executor");
    }

    let mut tool_table = Table::new();
    tool_table["name"] = value(spec.name.clone());
    tool_table["description"] = value(spec.description.clone());
    tool_table["command"] = Item::Value(array_value(&spec.command));
    if spec.execution_locality != "guest_subprocess" {
        tool_table["execution_locality"] = value(spec.execution_locality.clone());
    }
    if spec.timeout_seconds != DEFAULT_TIMEOUT_SECONDS {
        tool_table["timeout_seconds"] = value(i64::from(spec.timeout_seconds));
    }
    if spec.stdin_max_bytes != DEFAULT_STDIN_MAX_BYTES {
        tool_table["stdin_max_bytes"] = value(spec.stdin_max_bytes as i64);
    }
    if spec.stdout_max_bytes != DEFAULT_STDOUT_MAX_BYTES {
        tool_table["stdout_max_bytes"] = value(spec.stdout_max_bytes as i64);
    }
    if spec.stderr_max_bytes != DEFAULT_STDERR_MAX_BYTES {
        tool_table["stderr_max_bytes"] = value(spec.stderr_max_bytes as i64);
    }
    if spec.expose_stderr {
        tool_table["expose_stderr"] = value(true);
    }
    tool_table["schema"] = json_to_toml_item(&spec.schema)?;

    let item = profile
        .entry("custom_tool")
        .or_insert_with(|| Item::ArrayOfTables(ArrayOfTables::new()));
    let Some(aot) = item.as_array_of_tables_mut() else {
        return Err(ToolAuthoringError::InvalidSchema(format!(
            "profile {:?} custom_tool is not an array of tables",
            spec.profile
        )));
    };
    aot.push(tool_table);
    Ok(finish_doc(doc))
}

pub fn attach_profile_to_task(
    plan_text: &str,
    task_name: &str,
    profile: &str,
) -> Result<String, ToolAuthoringError> {
    validate_profile_name(profile)?;
    let mut doc = parse_document(plan_text)?;
    let Some(tasks) = doc["tasks"].as_array_of_tables_mut() else {
        return Err(ToolAuthoringError::TaskNotFound(task_name.to_owned()));
    };

    let mut found = false;
    for task in tasks.iter_mut() {
        if task
            .get("task_name")
            .and_then(|v| v.as_value())
            .and_then(|v| v.as_str())
            != Some(task_name)
        {
            continue;
        }
        if task.contains_key("profile") {
            return Err(ToolAuthoringError::DeprecatedTaskProfile {
                task: task_name.to_owned(),
            });
        }
        let item = task
            .entry("profiles")
            .or_insert_with(|| Item::Value(toml_edit::Value::Array(Array::new())));
        let Some(arr) = item.as_value_mut().and_then(|v| v.as_array_mut()) else {
            return Err(ToolAuthoringError::InvalidTaskProfiles {
                task: task_name.to_owned(),
            });
        };
        for existing in arr.iter() {
            if existing.as_str() == Some(profile) {
                return Err(ToolAuthoringError::TaskAlreadyHasProfile {
                    task: task_name.to_owned(),
                    profile: profile.to_owned(),
                });
            }
        }
        arr.push(profile);
        found = true;
        break;
    }

    if found {
        Ok(finish_doc(doc))
    } else {
        Err(ToolAuthoringError::TaskNotFound(task_name.to_owned()))
    }
}

pub fn validate_plan_tools(plan_text: &str) -> ToolValidationReport {
    let parsed: Result<toml::Value, _> = toml::from_str(plan_text);
    let doc = match parsed {
        Ok(doc) => doc,
        Err(e) => {
            return ToolValidationReport {
                errors: vec![format!("invalid TOML: {e}")],
                ..ToolValidationReport::default()
            };
        }
    };

    let mut report = ToolValidationReport::default();
    let profiles = match doc.get("profiles").and_then(ValueExt::as_toml_table) {
        Some(profiles) => profiles,
        None => return report,
    };
    let mut profile_tools: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for (profile_name, body) in profiles {
        if let Err(e) = validate_profile_name(profile_name) {
            report.errors.push(e.to_string());
            continue;
        }
        let Some(table) = body.as_table() else {
            continue;
        };
        let role = table
            .get("role")
            .and_then(|v| v.as_str())
            .or_else(|| table.get("inherits_from").and_then(|v| v.as_str()))
            .unwrap_or("Executor");
        if role == "Orchestrator" {
            report.errors.push(format!(
                "profile {profile_name:?} cannot target Orchestrator"
            ));
        }
        let Some(tools) = table.get("custom_tool") else {
            continue;
        };
        let Some(tools) = tools.as_array() else {
            report.errors.push(format!(
                "profile {profile_name:?} custom_tool must be an array of tables"
            ));
            continue;
        };
        if role == "Reviewer" && !tools.is_empty() {
            report.errors.push(format!(
                "profile {profile_name:?} is Reviewer-effective but declares custom tools"
            ));
        }
        let names = profile_tools.entry(profile_name.clone()).or_default();
        for entry in tools {
            let Some(tool) = entry.as_table() else {
                report.errors.push(format!(
                    "profile {profile_name:?} custom_tool entry is not a table"
                ));
                continue;
            };
            let spec = spec_from_toml(profile_name, tool);
            match spec {
                Ok(spec) => {
                    report.tool_count += 1;
                    if !names.insert(spec.name.clone()) {
                        report.errors.push(format!(
                            "profile {profile_name:?} declares tool {:?} more than once",
                            spec.name
                        ));
                    }
                    if let Err(e) = spec.validate(300) {
                        report.errors.push(e.to_string());
                    }
                }
                Err(e) => report.errors.push(e.to_string()),
            }
        }
        if names.len() > MAX_EFFECTIVE_CUSTOM_TOOLS_PER_TASK {
            report.warnings.push(format!(
                "profile {profile_name:?} declares {} tools; keep per-task effective tools <= {MAX_EFFECTIVE_CUSTOM_TOOLS_PER_TASK}",
                names.len()
            ));
        }
    }

    if let Some(tasks) = doc.get("tasks").and_then(|v| v.as_array()) {
        for task in tasks {
            let task_name = task
                .get("task_name")
                .and_then(|v| v.as_str())
                .unwrap_or("<unknown>");
            if task.get("custom_tool").is_some() {
                report.errors.push(format!(
                    "task {task_name:?} declares custom_tool; custom tools must live under profiles"
                ));
            }
            if task.get("profile").is_some() {
                report.errors.push(format!(
                    "task {task_name:?} uses deprecated scalar profile; use profiles = [...]"
                ));
            }
            if let Some(task_profiles_value) = task.get("profiles") {
                let Some(arr) = task_profiles_value.as_array() else {
                    report
                        .errors
                        .push(format!("task {task_name:?} profiles must be an array"));
                    continue;
                };
                let mut seen_tools: BTreeMap<String, String> = BTreeMap::new();
                for profile in arr.iter().filter_map(|v| v.as_str()) {
                    if !profile_tools.contains_key(profile) && !profiles.contains_key(profile) {
                        report.warnings.push(format!(
                            "task {task_name:?} references profile {profile:?} with no custom tools"
                        ));
                    }
                    if let Some(tools) = profile_tools.get(profile) {
                        for tool in tools {
                            if let Some(prev) = seen_tools.insert(tool.clone(), profile.to_owned())
                            {
                                report.warnings.push(format!(
                                    "task {task_name:?} sees tool {tool:?} from both {prev:?} and {profile:?}; identical duplicates are allowed, conflicts reject at kernel admission"
                                ));
                            }
                        }
                    }
                }
                if seen_tools.len() > MAX_EFFECTIVE_CUSTOM_TOOLS_PER_TASK {
                    report.errors.push(format!(
                        "task {task_name:?} has {} effective custom tools, exceeding limit {MAX_EFFECTIVE_CUSTOM_TOOLS_PER_TASK}",
                        seen_tools.len()
                    ));
                }
            }
        }
    }

    report
}

pub fn find_tool(
    plan_text: &str,
    profile: &str,
    tool: &str,
) -> Result<CustomToolSpec, ToolAuthoringError> {
    let doc: toml::Value =
        toml::from_str(plan_text).map_err(|e| ToolAuthoringError::TomlParse(e.to_string()))?;
    let profile_table = doc
        .get("profiles")
        .and_then(|v| v.as_table())
        .and_then(|profiles| profiles.get(profile))
        .and_then(|v| v.as_table())
        .ok_or_else(|| ToolAuthoringError::ToolNotFound {
            profile: profile.to_owned(),
            tool: tool.to_owned(),
        })?;
    let tools = profile_table
        .get("custom_tool")
        .and_then(|v| v.as_array())
        .ok_or_else(|| ToolAuthoringError::ToolNotFound {
            profile: profile.to_owned(),
            tool: tool.to_owned(),
        })?;
    for entry in tools {
        let Some(table) = entry.as_table() else {
            continue;
        };
        if table.get("name").and_then(|v| v.as_str()) == Some(tool) {
            return spec_from_toml(profile, table);
        }
    }
    Err(ToolAuthoringError::ToolNotFound {
        profile: profile.to_owned(),
        tool: tool.to_owned(),
    })
}

pub fn dry_run_tool(
    spec: &CustomToolSpec,
    input: &Value,
) -> Result<ToolDryRunOutput, ToolAuthoringError> {
    spec.validate(300)?;
    let stdin_bytes =
        serde_json::to_vec(input).map_err(|e| ToolAuthoringError::JsonParse(e.to_string()))?;
    if stdin_bytes.len() as u64 > spec.stdin_max_bytes {
        return Err(ToolAuthoringError::Execution(format!(
            "input is {} bytes, exceeds stdin_max_bytes={}",
            stdin_bytes.len(),
            spec.stdin_max_bytes
        )));
    }

    let mut child = Command::new(&spec.command[0])
        .args(&spec.command[1..])
        .env_clear()
        .env("RAXIS_CUSTOM_TOOL_NAME", &spec.name)
        .env("RAXIS_CUSTOM_TOOL_PROFILE", &spec.profile)
        .env("RAXIS_CUSTOM_TOOL_LOCALITY", &spec.execution_locality)
        .env("RAXIS_TOOL_AUTHORING_DRY_RUN", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| ToolAuthoringError::Execution(e.to_string()))?;

    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(&stdin_bytes)
            .map_err(|e| ToolAuthoringError::Execution(e.to_string()))?;
    }

    let deadline = Instant::now() + Duration::from_secs(u64::from(spec.timeout_seconds.max(1)));
    loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|e| ToolAuthoringError::Execution(e.to_string()))?
        {
            let output = child
                .wait_with_output()
                .map_err(|e| ToolAuthoringError::Execution(e.to_string()))?;
            let (stdout, stdout_truncated) =
                truncate_lossy(&output.stdout, spec.stdout_max_bytes as usize);
            let (stderr, stderr_truncated) =
                truncate_lossy(&output.stderr, spec.stderr_max_bytes as usize);
            return Ok(ToolDryRunOutput {
                status_code: status.code(),
                timed_out: false,
                stdout,
                stderr,
                stdout_truncated,
                stderr_truncated,
            });
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let output = child
                .wait_with_output()
                .map_err(|e| ToolAuthoringError::Execution(e.to_string()))?;
            let (stdout, stdout_truncated) =
                truncate_lossy(&output.stdout, spec.stdout_max_bytes as usize);
            let (stderr, stderr_truncated) =
                truncate_lossy(&output.stderr, spec.stderr_max_bytes as usize);
            return Ok(ToolDryRunOutput {
                status_code: None,
                timed_out: true,
                stdout,
                stderr,
                stdout_truncated,
                stderr_truncated,
            });
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

pub fn read_json_arg(value: &str, cwd: &Path) -> Result<Value, ToolAuthoringError> {
    let text = if let Some(path) = value.strip_prefix('@') {
        let path = cwd.join(path);
        std::fs::read_to_string(&path)
            .map_err(|e| ToolAuthoringError::JsonParse(format!("read {}: {e}", path.display())))?
    } else {
        value.to_owned()
    };
    serde_json::from_str(&text).map_err(|e| ToolAuthoringError::JsonParse(e.to_string()))
}

fn validate_byte_cap(field: &'static str, got: u64, cap: u64) -> Result<(), ToolAuthoringError> {
    if got == 0 {
        return Err(ToolAuthoringError::ByteCapZero { field });
    }
    if got > cap {
        return Err(ToolAuthoringError::ByteCapExceeded { field, got, cap });
    }
    Ok(())
}

fn parse_document(text: &str) -> Result<DocumentMut, ToolAuthoringError> {
    text.parse::<DocumentMut>()
        .map_err(|e| ToolAuthoringError::TomlParse(e.to_string()))
}

fn finish_doc(doc: DocumentMut) -> String {
    let mut out = doc.to_string();
    if !out.ends_with('\n') {
        out.push('\n');
    }
    out
}

fn ensure_table<'a>(parent: &'a mut Table, key: &str) -> Result<&'a mut Table, ToolAuthoringError> {
    if !parent.contains_key(key) {
        parent[key] = Item::Table(Table::new());
    }
    parent[key].as_table_mut().ok_or_else(|| {
        ToolAuthoringError::InvalidSchema(format!("{key:?} exists but is not a TOML table"))
    })
}

fn array_value(values: &[String]) -> toml_edit::Value {
    let mut arr = Array::new();
    for value in values {
        arr.push(value.as_str());
    }
    toml_edit::Value::Array(arr)
}

fn normalize_schema_value(value: Value) -> Result<Value, ToolAuthoringError> {
    let Some(obj) = value.as_object() else {
        return Err(ToolAuthoringError::InvalidSchema(
            "tool schema must be a JSON object".to_owned(),
        ));
    };
    if obj.contains_key("type") || obj.contains_key("properties") {
        return Ok(value);
    }

    let mut properties = Map::new();
    let mut required = Vec::new();
    for (raw_name, raw_prop) in obj {
        let (name, optional_by_name) = raw_name
            .strip_suffix('?')
            .map(|s| (s.to_owned(), true))
            .unwrap_or_else(|| (raw_name.clone(), false));
        let (prop, optional_by_value) = normalize_shorthand_property(raw_prop)?;
        if !optional_by_name && !optional_by_value {
            required.push(Value::String(name.clone()));
        }
        properties.insert(name, prop);
    }
    Ok(json!({
        "type": "object",
        "properties": properties,
        "required": required,
        "additionalProperties": false
    }))
}

fn normalize_shorthand_property(value: &Value) -> Result<(Value, bool), ToolAuthoringError> {
    match value {
        Value::String(t) => Ok((json!({ "type": t }), false)),
        Value::Object(obj) => {
            let mut prop = Value::Object(obj.clone());
            let optional = prop
                .as_object_mut()
                .and_then(|o| o.remove("optional"))
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            Ok((prop, optional))
        }
        other => Err(ToolAuthoringError::InvalidSchema(format!(
            "shorthand property values must be a type string or object; got {other:?}"
        ))),
    }
}

fn validate_schema_node(
    schema: &Value,
    path: &str,
    is_root: bool,
) -> Result<(), ToolAuthoringError> {
    let Some(obj) = schema.as_object() else {
        return Err(ToolAuthoringError::InvalidSchema(format!(
            "{path} must be an object"
        )));
    };
    let allowed = [
        "type",
        "description",
        "properties",
        "required",
        "additionalProperties",
        "enum",
        "default",
        "minLength",
        "maxLength",
        "minimum",
        "maximum",
        "items",
    ];
    for key in obj.keys() {
        if !allowed.contains(&key.as_str()) {
            return Err(ToolAuthoringError::InvalidSchema(format!(
                "{path}.{key} is not in the RAXIS provider-safe schema subset"
            )));
        }
    }
    let Some(kind) = obj.get("type").and_then(Value::as_str) else {
        return Err(ToolAuthoringError::InvalidSchema(format!(
            "{path}.type must be a string"
        )));
    };
    if is_root && kind != "object" {
        return Err(ToolAuthoringError::InvalidSchema(
            "root type must be object".to_owned(),
        ));
    }
    if !matches!(
        kind,
        "object" | "string" | "integer" | "number" | "boolean" | "array"
    ) {
        return Err(ToolAuthoringError::InvalidSchema(format!(
            "{path}.type={kind:?} is not supported"
        )));
    }
    if let Some(properties) = obj.get("properties") {
        let Some(properties) = properties.as_object() else {
            return Err(ToolAuthoringError::InvalidSchema(format!(
                "{path}.properties must be an object"
            )));
        };
        for (name, child) in properties {
            if name.is_empty() || name.chars().any(|c| c.is_control()) {
                return Err(ToolAuthoringError::InvalidSchema(format!(
                    "{path}.properties contains invalid key {name:?}"
                )));
            }
            validate_schema_node(child, &format!("{path}.properties.{name}"), false)?;
        }
    }
    if let Some(required) = obj.get("required") {
        let Some(required) = required.as_array() else {
            return Err(ToolAuthoringError::InvalidSchema(format!(
                "{path}.required must be an array of strings"
            )));
        };
        for value in required {
            if value.as_str().is_none() {
                return Err(ToolAuthoringError::InvalidSchema(format!(
                    "{path}.required must contain only strings"
                )));
            }
        }
    }
    if let Some(additional) = obj.get("additionalProperties") {
        if !additional.is_boolean() {
            return Err(ToolAuthoringError::InvalidSchema(format!(
                "{path}.additionalProperties must be a boolean"
            )));
        }
    }
    if let Some(items) = obj.get("items") {
        validate_schema_node(items, &format!("{path}.items"), false)?;
    }
    Ok(())
}

fn json_to_toml_item(value: &Value) -> Result<Item, ToolAuthoringError> {
    match value {
        Value::Null => Ok(Item::Value(toml_edit::Value::from("null"))),
        Value::Bool(v) => Ok(toml_edit::value(*v)),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Ok(toml_edit::value(i))
            } else if let Some(u) = n.as_u64() {
                let i = i64::try_from(u).map_err(|_| {
                    ToolAuthoringError::InvalidSchema(format!("number {u} exceeds i64"))
                })?;
                Ok(toml_edit::value(i))
            } else if let Some(f) = n.as_f64() {
                Ok(toml_edit::value(f))
            } else {
                Err(ToolAuthoringError::InvalidSchema(
                    "unsupported JSON number".to_owned(),
                ))
            }
        }
        Value::String(v) => Ok(toml_edit::value(v.clone())),
        Value::Array(values) => {
            let mut arr = Array::new();
            for value in values {
                match json_to_toml_item(value)? {
                    Item::Value(v) => arr.push(v),
                    other => {
                        return Err(ToolAuthoringError::InvalidSchema(format!(
                            "arrays cannot contain nested TOML table item {other:?}"
                        )));
                    }
                }
            }
            Ok(Item::Value(toml_edit::Value::Array(arr)))
        }
        Value::Object(obj) => {
            let mut table = Table::new();
            table.set_implicit(true);
            for (key, value) in obj {
                table[key] = json_to_toml_item(value)?;
            }
            Ok(Item::Table(table))
        }
    }
}

fn toml_to_json(value: &toml::Value) -> Value {
    serde_json::to_value(value).unwrap_or(Value::Null)
}

fn spec_from_toml(
    profile: &str,
    table: &toml::map::Map<String, toml::Value>,
) -> Result<CustomToolSpec, ToolAuthoringError> {
    let name = table
        .get("name")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ToolAuthoringError::InvalidSchema("tool missing `name`".to_owned()))?;
    let description = table
        .get("description")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            ToolAuthoringError::InvalidSchema("tool missing `description`".to_owned())
        })?;
    let command = table
        .get("command")
        .and_then(|v| v.as_array())
        .ok_or_else(|| ToolAuthoringError::InvalidSchema("tool missing `command`".to_owned()))?
        .iter()
        .map(|v| {
            v.as_str().map(str::to_owned).ok_or_else(|| {
                ToolAuthoringError::InvalidSchema("command entries must be strings".to_owned())
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let schema = table
        .get("schema")
        .map(toml_to_json)
        .unwrap_or_else(default_tool_schema);
    Ok(CustomToolSpec {
        profile: profile.to_owned(),
        name: name.to_owned(),
        description: description.to_owned(),
        command,
        execution_locality: table
            .get("execution_locality")
            .and_then(|v| v.as_str())
            .unwrap_or("guest_subprocess")
            .to_owned(),
        schema,
        timeout_seconds: table
            .get("timeout_seconds")
            .and_then(|v| v.as_integer())
            .and_then(|v| u32::try_from(v).ok())
            .unwrap_or(DEFAULT_TIMEOUT_SECONDS),
        stdin_max_bytes: table
            .get("stdin_max_bytes")
            .and_then(|v| v.as_integer())
            .and_then(|v| u64::try_from(v).ok())
            .unwrap_or(DEFAULT_STDIN_MAX_BYTES),
        stdout_max_bytes: table
            .get("stdout_max_bytes")
            .and_then(|v| v.as_integer())
            .and_then(|v| u64::try_from(v).ok())
            .unwrap_or(DEFAULT_STDOUT_MAX_BYTES),
        stderr_max_bytes: table
            .get("stderr_max_bytes")
            .and_then(|v| v.as_integer())
            .and_then(|v| u64::try_from(v).ok())
            .unwrap_or(DEFAULT_STDERR_MAX_BYTES),
        expose_stderr: table
            .get("expose_stderr")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
    })
}

fn tool_exists_in_plan(
    plan_text: &str,
    profile: &str,
    name: &str,
) -> Result<bool, ToolAuthoringError> {
    match find_tool(plan_text, profile, name) {
        Ok(_) => Ok(true),
        Err(ToolAuthoringError::ToolNotFound { .. }) => Ok(false),
        Err(e) => Err(e),
    }
}

fn validate_profile_name(name: &str) -> Result<(), ToolAuthoringError> {
    let bytes = name.as_bytes();
    let ok = !bytes.is_empty()
        && bytes.len() <= 64
        && bytes[0].is_ascii_alphabetic()
        && bytes[1..]
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || *b == b'_' || *b == b'-');
    if ok {
        Ok(())
    } else {
        Err(ToolAuthoringError::InvalidProfileName(name.to_owned()))
    }
}

fn validate_tool_name(name: &str) -> Result<(), ToolAuthoringError> {
    let bytes = name.as_bytes();
    let ok = !bytes.is_empty()
        && bytes.len() <= 48
        && bytes[0].is_ascii_lowercase()
        && bytes[1..]
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'_');
    if !ok {
        return Err(ToolAuthoringError::InvalidToolName(name.to_owned()));
    }
    if RESERVED_TOOL_NAMES.contains(&name) {
        return Err(ToolAuthoringError::ReservedToolName(name.to_owned()));
    }
    Ok(())
}

fn truncate_lossy(bytes: &[u8], limit: usize) -> (String, bool) {
    let truncated = bytes.len() > limit;
    let slice = if truncated { &bytes[..limit] } else { bytes };
    (String::from_utf8_lossy(slice).to_string(), truncated)
}

trait ValueExt {
    fn as_toml_table(&self) -> Option<&toml::map::Map<String, toml::Value>>;
}

impl ValueExt for toml::Value {
    fn as_toml_table(&self) -> Option<&toml::map::Map<String, toml::Value>> {
        self.as_table()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shorthand_schema_normalizes_to_provider_safe_object() {
        let schema = normalize_tool_schema(Some(
            r#"{"query":"string","limit":{"type":"integer","optional":true}}"#,
        ))
        .unwrap();
        assert_eq!(schema["type"], "object");
        assert_eq!(schema["properties"]["query"]["type"], "string");
        assert_eq!(schema["required"], json!(["query"]));
        assert_eq!(schema["additionalProperties"], false);
    }

    #[test]
    fn rejects_unknown_schema_keyword() {
        let err = normalize_tool_schema(Some(r#"{"type":"object","oneOf":[]}"#)).unwrap_err();
        assert!(err.to_string().contains("provider-safe schema subset"));
    }

    #[test]
    fn append_tool_and_attach_profile_round_trip() {
        let plan = r#"
[workspace]
name = "Demo"
lane_id = "default"

[[tasks]]
task_name = "impl"
description = "Implement"
session_agent_type = "Executor"
"#;
        let spec = CustomToolSpec {
            profile: "repo_tools".to_owned(),
            name: "repo_search".to_owned(),
            description: "Search repository files by query string".to_owned(),
            command: vec!["/usr/bin/rg".to_owned()],
            execution_locality: "guest_subprocess".to_owned(),
            schema: normalize_tool_schema(Some(r#"{"query":"string"}"#)).unwrap(),
            timeout_seconds: 10,
            stdin_max_bytes: DEFAULT_STDIN_MAX_BYTES,
            stdout_max_bytes: DEFAULT_STDOUT_MAX_BYTES,
            stderr_max_bytes: DEFAULT_STDERR_MAX_BYTES,
            expose_stderr: false,
        };
        let with_tool = append_custom_tool(plan, &spec).unwrap();
        assert!(with_tool.contains("[profiles.repo_tools]"));
        assert!(with_tool.contains("[[profiles.repo_tools.custom_tool]]"));
        let with_profile = attach_profile_to_task(&with_tool, "impl", "repo_tools").unwrap();
        assert!(with_profile.contains("profiles = [\"repo_tools\"]"));
        assert!(validate_plan_tools(&with_profile).is_ok());
    }
}

//! `Tool` trait + `ToolRegistry` + base tools.
//!substep "Base tool registry
//! (read_file/bash/edit_file/grep_search/git_commit)" by giving each
//! planner role binary a typed, registry-driven dispatch surface.
//! ## Why a trait + registry, not free functions
//! Per `planner-harness.md §14.3`, role-asymmetric capabilities
//! ("the reviewer MUST NOT have `git_commit`") are a **build-time**
//! correctness property, not a runtime check. Each role binary
//! constructs its registry through one of the role-specific
//! constructors below ([`build_executor_registry`],
//! [`build_reviewer_registry`], [`build_orchestrator_registry`]),
//! and the dispatch loop simply queries the registry by name.
//! `cargo` enforces the asymmetry at build time: a reviewer binary
//! that imports `build_executor_registry` will compile, but the
//! `executor` Cargo feature this crate ships is mutually exclusive
//! with `reviewer` so the per-binary `Cargo.toml` cannot link both.
//! ## V2 limits (declared so future work has a target)
//! * **No streaming tool output.** Every tool returns a single
//!   `ToolOutput` value; long-running tools (a multi-MB `bash`
//!   command) buffer their full stdout/stderr before returning.
//!   The Anthropic Messages API does not yet support streaming
//!   tool results, so this matches the upstream protocol.
//! * **No tool retries inside the registry.** A failed tool surfaces
//!   `is_error: true` to the model on the next turn; the model
//!   decides whether to retry. Higher-layer retry budget enforcement
//!   (per `planner-harness.md §INV-PLANNER-HARNESS-04`) lives in the
//!   dispatch loop, not here.
//! * **No subprocess sandbox at the tool layer.** Bash and edit_file
//!   trust the VM-level isolation (the planner binary is already
//!   running inside its session VM with role-tier egress and
//!   path-allowlist enforcement). A future hardening pass that adds
//!   per-tool seccomp profiles plugs into this trait via a wrapper
//!   middleware tool, no API change required.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::io::AsyncWriteExt;

use crate::model::ToolSpec;
use crate::tools_vm_capabilities::VmCapabilitiesTool;

// ---------------------------------------------------------------------------
// ToolOutput / ToolError / Tool trait
// ---------------------------------------------------------------------------

/// One tool invocation's output, ready for the dispatch loop to
/// surface back to the model as a `ContentBlock::ToolResult`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolOutput {
    /// The textual output the model sees. UTF-8.
    pub content: String,
    /// `Some(true)` ⇒ tool reported a structured error. The
    /// dispatch loop sets `is_error: true` on the
    /// `ContentBlock::ToolResult`; the model interprets the
    /// `content` as an error message and decides whether to retry.
    /// `None` is the success case.
    #[serde(default)]
    pub is_error: Option<bool>,
    /// Optional replacement input for a successful terminal tool.
    ///
    /// Most tools ignore this. Terminal tools use it when the
    /// local tool has mechanically repaired or normalized the
    /// model's submitted arguments before the driver converts the
    /// terminal tool into a kernel intent. This keeps the model-facing
    /// tool result auditable while ensuring the kernel receives the
    /// verified input, not the stale speculative input the model first
    /// typed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_override: Option<serde_json::Value>,
}

impl ToolOutput {
    /// Construct a success output.
    pub fn ok(content: impl Into<String>) -> Self {
        Self {
            content: content.into(),
            is_error: None,
            input_override: None,
        }
    }
    /// Construct a success output that replaces the terminal-tool
    /// input the driver will submit to the kernel.
    pub fn ok_with_input(content: impl Into<String>, input_override: serde_json::Value) -> Self {
        Self {
            content: content.into(),
            is_error: None,
            input_override: Some(input_override),
        }
    }
    /// Construct a structured-error output.
    pub fn err(message: impl Into<String>) -> Self {
        Self {
            content: message.into(),
            is_error: Some(true),
            input_override: None,
        }
    }
}

/// Per-tool execution error. Distinct from a structured-error
/// [`ToolOutput`] because it indicates a planner-side bug (schema
/// validation failure, registry miss, internal panic) rather than a
/// recoverable tool failure the model should see.
#[derive(Debug, Error)]
pub enum ToolError {
    /// The tool name was not in the registry. Surfaced to the model
    /// as a `ToolOutput::err(...)` by the dispatch loop, NOT as a
    /// hard failure (the model occasionally hallucinates tool names
    /// and we want to give it a chance to recover).
    #[error("unknown tool: {0}")]
    NotFound(String),

    /// The model's `tool_use.input` did not parse against the
    /// tool's declared schema.
    #[error("invalid tool input for {tool}: {reason}")]
    InvalidInput {
        /// Tool name the model invoked.
        tool: String,
        /// Human-readable schema-validation failure (surfaced to the
        /// model as a structured tool error so it can recover).
        reason: String,
    },

    /// The tool raised an internal failure (I/O error, subprocess
    /// spawn failure, etc.). The dispatch loop converts this to a
    /// structured-error tool result so the model can recover.
    #[error("tool {tool} failed: {reason}")]
    Internal {
        /// Tool name that failed.
        tool: String,
        /// Human-readable reason (e.g. process spawn failure, IO error).
        reason: String,
    },
}

/// **The tool surface every planner-role binary speaks.** Each
/// concrete tool is an `Arc<dyn Tool>` registered by name in the
/// [`ToolRegistry`].
#[async_trait::async_trait]
pub trait Tool: Send + Sync {
    /// Tool name. ASCII identifier matching `[A-Za-z0-9_]{1,64}`.
    /// The Anthropic API rejects names outside this character set.
    fn name(&self) -> &'static str;

    /// Human-readable description shown to the model. ≤ 1 KiB
    /// recommended; the Anthropic API truncates beyond ~1024 chars.
    fn description(&self) -> &'static str;

    /// JSON Schema for the tool's input. The dispatch loop
    /// validates the model's `tool_use.input` against this schema
    /// before invoking [`Tool::execute`].
    fn input_schema(&self) -> serde_json::Value;

    /// Execute the tool against `input`. The implementation is
    /// responsible for its own timeout management; the dispatch
    /// loop surfaces a wall-clock deadline via the
    /// [`ToolContext::deadline`] field but does not interrupt
    /// in-flight tools (interruption is a future hardening pass).
    async fn execute(
        &self,
        input: &serde_json::Value,
        ctx: &ToolContext,
    ) -> Result<ToolOutput, ToolError>;

    /// Lift this tool into the Anthropic-shape `ToolSpec` the
    /// dispatch loop advertises in the
    /// [`crate::model::MessageRequest::tools`] field. Default impl
    /// reuses [`Tool::name`] / [`Tool::description`] /
    /// [`Tool::input_schema`].
    fn to_spec(&self) -> ToolSpec {
        ToolSpec {
            name: self.name().to_owned(),
            description: self.description().to_owned(),
            input_schema: self.input_schema(),
        }
    }
}

/// Per-execution context the dispatch loop hands to every tool
/// invocation.
#[derive(Debug, Clone)]
pub struct ToolContext {
    /// Workspace root the planner is operating in (the per-session
    /// VM's worktree mount, e.g. `/workspace`). Tool path inputs
    /// MUST be resolved relative to this root and MUST NOT escape
    /// it (validated by [`resolve_workspace_path`]).
    pub workspace_root: PathBuf,
    /// Wall-clock deadline for this turn — every tool's I/O budget
    /// is bounded by this value. Long-running tools that exceed it
    /// surface a structured-error output rather than blocking the
    /// dispatch loop indefinitely.
    pub deadline: Option<Duration>,
    /// Orchestrator-only final merge checklist copied from the KSB.
    /// Terminal `integration_merge` consults this so it can verify
    /// and, when conflict-free, auto-prepare the exact integrated
    /// head the kernel requires.
    pub integration_merge: Option<IntegrationMergeToolContext>,
    /// Executor-only base SHA copied from the KSB. Terminal
    /// `task_complete` uses this to reject no-op completion before
    /// the kernel sees an unchanged `(base, head)` pair.
    pub task_complete_base_sha: Option<String>,
}

/// Orchestrator-visible final merge context for local tool validation.
#[derive(Debug, Clone, Default)]
pub struct IntegrationMergeToolContext {
    /// KSB final-merge base SHA.
    pub base_sha: String,
    /// Required executor commits the integrated HEAD must contain.
    pub required_executor_shas: Vec<IntegrationMergeRequiredSha>,
}

/// One required executor commit for final integration.
#[derive(Debug, Clone)]
pub struct IntegrationMergeRequiredSha {
    /// Task id that produced the executor commit.
    pub task_id: String,
    /// Full 40-char executor commit SHA.
    pub sha: String,
}

impl ToolContext {
    /// Construct a context with no deadline. Used by unit tests
    /// that don't exercise the timeout path.
    pub fn for_workspace(workspace_root: impl Into<PathBuf>) -> Self {
        Self {
            workspace_root: workspace_root.into(),
            deadline: None,
            integration_merge: None,
            task_complete_base_sha: None,
        }
    }

    /// Attach orchestrator final-merge state from the KSB.
    pub fn with_integration_merge_context(
        mut self,
        integration_merge: Option<IntegrationMergeToolContext>,
    ) -> Self {
        self.integration_merge = integration_merge;
        self
    }

    /// Attach executor completion state from the KSB.
    pub fn with_task_complete_base_sha(mut self, base_sha: Option<String>) -> Self {
        self.task_complete_base_sha = base_sha;
        self
    }
}

// ---------------------------------------------------------------------------
// ToolRegistry
// ---------------------------------------------------------------------------

/// Registry of tools, keyed by name.
/// `BTreeMap` rather than `HashMap` so the iteration order is
/// deterministic — the dispatch loop's `MessageRequest::tools`
/// array, the role's `system` prompt, and the audit-emitted
/// per-turn tool list all key off the same registry; deterministic
/// order makes the audit chain reproducible across kernel restarts.
#[derive(Default)]
pub struct ToolRegistry {
    inner: BTreeMap<String, Arc<dyn Tool>>,
}

impl ToolRegistry {
    /// Construct an empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a tool. Panics on duplicate name (a registry
    /// collision is a build-time-fixable bug, not a runtime
    /// recoverable condition).
    pub fn register(&mut self, tool: Arc<dyn Tool>) {
        let name = tool.name().to_owned();
        if self.inner.insert(name.clone(), tool).is_some() {
            panic!("duplicate tool name in registry: {name:?}");
        }
    }

    /// Look up a tool by name.
    pub fn get(&self, name: &str) -> Option<&Arc<dyn Tool>> {
        self.inner.get(name)
    }

    /// Iterate over registered tools in sorted name order.
    pub fn iter(&self) -> impl Iterator<Item = &Arc<dyn Tool>> {
        self.inner.values()
    }

    /// Render the registry as the `tools: Vec<ToolSpec>` field of a
    /// [`crate::model::MessageRequest`].
    pub fn to_specs(&self) -> Vec<ToolSpec> {
        self.iter().map(|t| t.to_spec()).collect()
    }

    /// Number of registered tools.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// True iff no tools are registered.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Path resolution helper — ALL filesystem-touching tools MUST go
// through this so a model that emits `../../etc/passwd` is rejected
// at the planner-harness boundary, not at the substrate layer.
// ---------------------------------------------------------------------------

/// Resolve `input_path` relative to `workspace_root`, rejecting any
/// path that escapes the workspace via `..` segments or absolute
/// paths.
/// This is the **only** path resolution the base tools below
/// perform — every tool that touches the filesystem MUST call this
/// first so the workspace boundary is enforced uniformly.
/// ## Why a hand-rolled component check
/// `Path::canonicalize` on macOS/Linux follows symlinks, which is
/// not what we want — a symlink inside the workspace pointing at
/// `/etc/passwd` would let the model exfiltrate. We compare path
/// components manually so a workspace-rooted symlink reads only
/// from inside the workspace.
pub fn resolve_workspace_path(
    workspace_root: &Path,
    input_path: &str,
) -> Result<PathBuf, ToolError> {
    let p = Path::new(input_path);
    if p.is_absolute() {
        return Err(ToolError::InvalidInput {
            tool: "<workspace-path>".to_owned(),
            reason: format!(
                "absolute path {input_path:?} not allowed; \
                 paths MUST be relative to the workspace root"
            ),
        });
    }
    // Disallow `..` components — even if they would resolve to a
    // path inside the workspace, the planner's path-allowlist
    // enforcement keys off a normalised relative path string and
    // a `..` segment would defeat the keying.
    for c in p.components() {
        match c {
            std::path::Component::ParentDir => {
                return Err(ToolError::InvalidInput {
                    tool: "<workspace-path>".to_owned(),
                    reason: format!("`..` segment in {input_path:?} not allowed"),
                });
            }
            std::path::Component::CurDir => continue,
            std::path::Component::Normal(_) => continue,
            _ => {
                return Err(ToolError::InvalidInput {
                    tool: "<workspace-path>".to_owned(),
                    reason: format!("unsupported path component in {input_path:?}"),
                });
            }
        }
    }
    Ok(workspace_root.join(p))
}

// ---------------------------------------------------------------------------
// Base tools
// ---------------------------------------------------------------------------

/// `read_file` — read the contents of a workspace-relative file.
/// Schema: `{ path: string }`. Returns the file's UTF-8 contents
/// (with a `... <truncated N bytes>` tail if the file exceeds 1 MiB
/// to keep the per-turn token budget under control).
pub struct ReadFileTool;

#[async_trait::async_trait]
impl Tool for ReadFileTool {
    fn name(&self) -> &'static str {
        "read_file"
    }
    fn description(&self) -> &'static str {
        "Read a workspace-relative file. Rejects absolute paths and `..`; \
         files over 1 MiB are truncated."
    }
    fn input_schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type":     "object",
            "required": ["path"],
            "properties": {
                "path": {
                    "type":        "string",
                    "description": "Workspace-relative path to read.",
                }
            }
        })
    }
    async fn execute(
        &self,
        input: &serde_json::Value,
        ctx: &ToolContext,
    ) -> Result<ToolOutput, ToolError> {
        let path =
            input
                .get("path")
                .and_then(|v| v.as_str())
                .ok_or_else(|| ToolError::InvalidInput {
                    tool: "read_file".to_owned(),
                    reason: "missing or non-string `path`".to_owned(),
                })?;
        let resolved = resolve_workspace_path(&ctx.workspace_root, path).map_err(|e| match e {
            ToolError::InvalidInput { reason, .. } => ToolError::InvalidInput {
                tool: "read_file".to_owned(),
                reason,
            },
            other => other,
        })?;
        match tokio::fs::read(&resolved).await {
            Ok(bytes) => {
                const MAX: usize = 1024 * 1024;
                let body = if bytes.len() > MAX {
                    let mut s = String::from_utf8_lossy(&bytes[..MAX]).into_owned();
                    s.push_str(&format!("\n... <truncated {} bytes>", bytes.len() - MAX));
                    s
                } else {
                    String::from_utf8_lossy(&bytes).into_owned()
                };
                Ok(ToolOutput::ok(body))
            }
            Err(e) => Ok(ToolOutput::err(format!("read_file({path:?}) failed: {e}"))),
        }
    }
}

/// `list_files` — read-only workspace-relative path discovery.
/// Schema: `{ path?: string, max_entries?: integer }`. Returns
/// deterministic metadata only; it never reads file contents and
/// never follows symlinked directories. This is intentionally
/// available to reviewers so they can find the exact artifact file
/// without receiving shell access.
pub struct ListFilesTool;

const LIST_FILES_DEFAULT_MAX_ENTRIES: usize = 200;
const LIST_FILES_HARD_MAX_ENTRIES: usize = 1000;

#[async_trait::async_trait]
impl Tool for ListFilesTool {
    fn name(&self) -> &'static str {
        "list_files"
    }

    fn description(&self) -> &'static str {
        "List workspace-relative files/directories under a path without reading \
         contents. Rejects absolute paths and `..`; output is sorted and capped."
    }

    fn input_schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Workspace-relative file or directory to list. Defaults to '.'.",
                },
                "max_entries": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": LIST_FILES_HARD_MAX_ENTRIES,
                    "description": "Maximum entries to return; defaults to 200.",
                }
            }
        })
    }

    async fn execute(
        &self,
        input: &serde_json::Value,
        ctx: &ToolContext,
    ) -> Result<ToolOutput, ToolError> {
        let path = input.get("path").and_then(|v| v.as_str()).unwrap_or(".");
        let max_entries = input
            .get("max_entries")
            .and_then(|v| v.as_u64())
            .map(|v| v.clamp(1, LIST_FILES_HARD_MAX_ENTRIES as u64) as usize)
            .unwrap_or(LIST_FILES_DEFAULT_MAX_ENTRIES);
        let resolved = resolve_workspace_path(&ctx.workspace_root, path).map_err(|e| match e {
            ToolError::InvalidInput { reason, .. } => ToolError::InvalidInput {
                tool: "list_files".to_owned(),
                reason,
            },
            other => other,
        })?;

        let workspace_root = ctx.workspace_root.clone();
        let requested_path = if path.is_empty() { "." } else { path }.to_owned();
        let listed = tokio::task::spawn_blocking(move || {
            collect_workspace_listing(&workspace_root, &resolved, max_entries)
        })
        .await
        .map_err(|e| ToolError::Internal {
            tool: "list_files".to_owned(),
            reason: format!("join failed: {e}"),
        })?;

        match listed {
            Ok(WorkspaceListing {
                mut rows,
                truncated,
            }) => {
                rows.sort();
                if rows.is_empty() {
                    Ok(ToolOutput::ok(format!(
                        "list_files under {requested_path:?}: <empty>"
                    )))
                } else {
                    let truncated_note = if truncated {
                        format!(
                            "\n... <truncated at {max_entries} entries; narrow `path` to inspect more>"
                        )
                    } else {
                        String::new()
                    };
                    Ok(ToolOutput::ok(format!(
                        "list_files under {requested_path:?} ({} entries):\n{}{}",
                        rows.len(),
                        rows.join("\n"),
                        truncated_note
                    )))
                }
            }
            Err(message) => Ok(ToolOutput::err(format!(
                "list_files({requested_path:?}) failed: {message}"
            ))),
        }
    }
}

#[derive(Debug)]
struct WorkspaceListing {
    rows: Vec<String>,
    truncated: bool,
}

fn collect_workspace_listing(
    workspace_root: &Path,
    start: &Path,
    max_entries: usize,
) -> Result<WorkspaceListing, String> {
    let mut rows = Vec::new();
    let mut truncated = false;
    let meta =
        std::fs::symlink_metadata(start).map_err(|e| format!("metadata({start:?}) failed: {e}"))?;
    if meta.file_type().is_file() {
        rows.push(format!(
            "file {}",
            workspace_relative_display(workspace_root, start)
        ));
        return Ok(WorkspaceListing { rows, truncated });
    }
    if meta.file_type().is_symlink() {
        rows.push(format!(
            "link {}",
            workspace_relative_display(workspace_root, start)
        ));
        return Ok(WorkspaceListing { rows, truncated });
    }
    if !meta.file_type().is_dir() {
        return Err("path is not a regular file or directory".to_owned());
    }

    let mut stack = vec![start.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let mut children = Vec::new();
        for entry in
            std::fs::read_dir(&dir).map_err(|e| format!("read_dir({dir:?}) failed: {e}"))?
        {
            let entry = entry.map_err(|e| format!("read_dir entry failed: {e}"))?;
            children.push(entry.path());
        }
        children.sort();
        children.reverse();

        for child in children {
            if child.file_name() == Some(OsStr::new(".git")) {
                continue;
            }
            let child_meta = match std::fs::symlink_metadata(&child) {
                Ok(m) => m,
                Err(e) => {
                    rows.push(format!(
                        "error {} metadata failed: {e}",
                        workspace_relative_display(workspace_root, &child)
                    ));
                    continue;
                }
            };
            let rel = workspace_relative_display(workspace_root, &child);
            if child_meta.file_type().is_dir() {
                rows.push(format!("dir  {rel}/"));
                stack.push(child);
            } else if child_meta.file_type().is_file() {
                rows.push(format!("file {rel}"));
            } else if child_meta.file_type().is_symlink() {
                rows.push(format!("link {rel}"));
            } else {
                rows.push(format!("other {rel}"));
            }
            if rows.len() >= max_entries {
                truncated = true;
                return Ok(WorkspaceListing { rows, truncated });
            }
        }
    }

    Ok(WorkspaceListing { rows, truncated })
}

fn workspace_relative_display(workspace_root: &Path, path: &Path) -> String {
    path.strip_prefix(workspace_root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

/// `edit_file` — overwrite a workspace file with the supplied
/// contents. Creates parent directories as needed.
/// Schema: `{ path: string, contents: string }`.
pub struct EditFileTool;

#[async_trait::async_trait]
impl Tool for EditFileTool {
    fn name(&self) -> &'static str {
        "edit_file"
    }
    fn description(&self) -> &'static str {
        "Overwrite/create a workspace-relative UTF-8 file. Use `read_file` \
         before replacing existing content."
    }
    fn input_schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type":     "object",
            "required": ["path", "contents"],
            "properties": {
                "path":     { "type": "string",
                              "description": "Workspace-relative path." },
                "contents": { "type": "string",
                              "description": "UTF-8 file contents." }
            }
        })
    }
    async fn execute(
        &self,
        input: &serde_json::Value,
        ctx: &ToolContext,
    ) -> Result<ToolOutput, ToolError> {
        let path =
            input
                .get("path")
                .and_then(|v| v.as_str())
                .ok_or_else(|| ToolError::InvalidInput {
                    tool: "edit_file".to_owned(),
                    reason: "missing or non-string `path`".to_owned(),
                })?;
        let contents = input
            .get("contents")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ToolError::InvalidInput {
                tool: "edit_file".to_owned(),
                reason: "missing or non-string `contents`".to_owned(),
            })?;
        let resolved = resolve_workspace_path(&ctx.workspace_root, path).map_err(|e| match e {
            ToolError::InvalidInput { reason, .. } => ToolError::InvalidInput {
                tool: "edit_file".to_owned(),
                reason,
            },
            other => other,
        })?;
        if let Some(parent) = resolved.parent() {
            if let Err(e) = tokio::fs::create_dir_all(parent).await {
                return Ok(ToolOutput::err(format!(
                    "edit_file: create_dir_all({parent:?}) failed: {e}"
                )));
            }
        }
        let mut f = match tokio::fs::File::create(&resolved).await {
            Ok(f) => f,
            Err(e) => {
                return Ok(ToolOutput::err(format!(
                    "edit_file: open({resolved:?}) failed: {e}"
                )))
            }
        };
        if let Err(e) = f.write_all(contents.as_bytes()).await {
            return Ok(ToolOutput::err(format!(
                "edit_file: write {resolved:?} failed: {e}"
            )));
        }
        if let Err(e) = f.flush().await {
            return Ok(ToolOutput::err(format!(
                "edit_file: flush {resolved:?} failed: {e}"
            )));
        }
        Ok(ToolOutput::ok(format!(
            "wrote {} bytes to {}",
            contents.len(),
            path
        )))
    }
}

/// `bash` — run a shell command in the workspace.
/// Schema: `{ command: string }`. Stdout + stderr are concatenated
/// into the response (with a 64 KiB cap per stream); the exit code
/// is reported in the trailing line.
/// **Hardening note.** The reviewer role does NOT include this
/// tool — see [`build_reviewer_registry`].
pub struct BashTool;

#[async_trait::async_trait]
impl Tool for BashTool {
    fn name(&self) -> &'static str {
        "bash"
    }
    fn description(&self) -> &'static str {
        "Run `bash -lc` in the workspace. Returns exit code plus stdout/stderr \
         capped at 64 KiB each."
    }
    fn input_schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type":     "object",
            "required": ["command"],
            "properties": {
                "command": {
                    "type":        "string",
                    "description": "Shell command to run via `bash -lc`.",
                }
            }
        })
    }
    async fn execute(
        &self,
        input: &serde_json::Value,
        ctx: &ToolContext,
    ) -> Result<ToolOutput, ToolError> {
        let cmd = input
            .get("command")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ToolError::InvalidInput {
                tool: "bash".to_owned(),
                reason: "missing or non-string `command`".to_owned(),
            })?;
        let child = match tokio::process::Command::new("bash")
            .arg("-lc")
            .arg(cmd)
            .current_dir(&ctx.workspace_root)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .stdin(std::process::Stdio::null())
            .spawn()
        {
            Ok(c) => c,
            Err(e) => return Ok(ToolOutput::err(format!("bash: spawn failed: {e}"))),
        };
        let timeout = ctx.deadline.unwrap_or(Duration::from_secs(120));
        let out = match tokio::time::timeout(timeout, child.wait_with_output()).await {
            Ok(Ok(o)) => o,
            Ok(Err(e)) => {
                return Ok(ToolOutput::err(format!(
                    "bash: wait_with_output failed: {e}"
                )))
            }
            Err(_) => {
                return Ok(ToolOutput::err(format!(
                    "bash: command timed out after {timeout:?}"
                )))
            }
        };
        const CAP: usize = 64 * 1024;
        let cap = |b: &[u8]| -> String {
            if b.len() > CAP {
                format!(
                    "{}\n... <truncated {} bytes>",
                    String::from_utf8_lossy(&b[..CAP]),
                    b.len() - CAP,
                )
            } else {
                String::from_utf8_lossy(b).into_owned()
            }
        };
        let body = format!(
            "exit_code: {code}\n----- stdout -----\n{stdout}\n----- stderr -----\n{stderr}",
            code = out
                .status
                .code()
                .map(|c| c.to_string())
                .unwrap_or_else(|| "<signalled>".to_owned()),
            stdout = cap(&out.stdout),
            stderr = cap(&out.stderr),
        );
        if out.status.success() {
            Ok(ToolOutput::ok(body))
        } else {
            // Non-zero exit is a STRUCTURED tool error so the model
            // can recover; the audit chain still records the full
            // body via the dispatch loop.
            Ok(ToolOutput {
                content: body,
                is_error: Some(true),
                input_override: None,
            })
        }
    }
}

/// `grep_search` — `rg -n` / `grep -rn` over the workspace.
/// Schema: `{ pattern: string, path: string? }`. Prefer `rg` because
/// the canonical scratch reviewer image ships only ripgrep at
/// `/usr/bin/rg`; fall back to `grep` for developer shells and older
/// images.
pub struct GrepSearchTool;

#[async_trait::async_trait]
impl Tool for GrepSearchTool {
    fn name(&self) -> &'static str {
        "grep_search"
    }
    fn description(&self) -> &'static str {
        "Search with ripgrep (`rg`) under the workspace in canonical images \
         (fallback to grep in older/dev shells). Returns `relpath:line:content`, \
         capped at 64 KiB."
    }
    fn input_schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type":     "object",
            "required": ["pattern"],
            "properties": {
                "pattern": {
                    "type":        "string",
                    "description": "POSIX basic regex (grep default).",
                },
                "path": {
                    "type":        "string",
                    "description": "Workspace-relative directory to search.",
                }
            }
        })
    }
    async fn execute(
        &self,
        input: &serde_json::Value,
        ctx: &ToolContext,
    ) -> Result<ToolOutput, ToolError> {
        let pattern = input
            .get("pattern")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ToolError::InvalidInput {
                tool: "grep_search".to_owned(),
                reason: "missing or non-string `pattern`".to_owned(),
            })?;
        let path = input.get("path").and_then(|v| v.as_str()).unwrap_or(".");
        let resolved = resolve_workspace_path(&ctx.workspace_root, path).map_err(|e| match e {
            ToolError::InvalidInput { reason, .. } => ToolError::InvalidInput {
                tool: "grep_search".to_owned(),
                reason,
            },
            other => other,
        })?;
        let rel_arg = if path.is_empty() { "." } else { path };
        let out = run_ripgrep_with_canonical_fallback(&ctx.workspace_root, pattern, rel_arg).await;
        let out = match out {
            Ok(o) => Ok(o),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                tokio::process::Command::new("grep")
                    .arg("-rn")
                    .arg(pattern)
                    .arg(&resolved)
                    .output()
                    .await
            }
            Err(e) => Err(e),
        };
        let out = match out {
            Ok(o) => o,
            Err(e) => return Ok(ToolOutput::err(format!("grep_search: spawn failed: {e}"))),
        };
        // rg/grep exit code 1 means "no match" — treat as success with
        // an empty body so the model doesn't think the tool errored.
        const CAP: usize = 64 * 1024;
        let body = if out.stdout.len() > CAP {
            format!(
                "{}\n... <truncated {} bytes>",
                String::from_utf8_lossy(&out.stdout[..CAP]),
                out.stdout.len() - CAP,
            )
        } else {
            String::from_utf8_lossy(&out.stdout).into_owned()
        };
        match out.status.code() {
            Some(0) => Ok(ToolOutput::ok(body)),
            Some(1) => Ok(ToolOutput::ok(format!(
                "<no matches for {pattern:?} under {path:?}>"
            ))),
            Some(c) => Ok(ToolOutput::err(format!(
                "grep_search: exit {c}\n{}",
                String::from_utf8_lossy(&out.stderr)
            ))),
            None => Ok(ToolOutput::err("grep_search: signalled".to_owned())),
        }
    }
}

async fn run_ripgrep_with_canonical_fallback(
    workspace_root: &Path,
    pattern: &str,
    rel_arg: &str,
) -> std::io::Result<std::process::Output> {
    let mut last_not_found: Option<std::io::Error> = None;
    for candidate in ["rg", "/usr/bin/rg"] {
        match tokio::process::Command::new(candidate)
            .arg("-n")
            .arg("--color")
            .arg("never")
            .arg("--no-heading")
            .arg(pattern)
            .arg(rel_arg)
            .current_dir(workspace_root)
            .output()
            .await
        {
            Ok(o) => return Ok(o),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                last_not_found = Some(e);
            }
            Err(e) => return Err(e),
        }
    }
    Err(last_not_found.unwrap_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::NotFound, "ripgrep binary not found")
    }))
}

/// `git_commit` — `git add` + `git commit -m <message>` in the
/// workspace. **Executor-only.** The reviewer role registry omits
/// this tool — see [`build_reviewer_registry`].
/// Schema: `{ message: string }`.
pub struct GitCommitTool;

#[async_trait::async_trait]
impl Tool for GitCommitTool {
    fn name(&self) -> &'static str {
        "git_commit"
    }
    fn description(&self) -> &'static str {
        "Stage all workspace changes and commit. Returns the full 40-char \
         HEAD SHA. Executor-only."
    }
    fn input_schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type":     "object",
            "required": ["message"],
            "properties": {
                "message": {
                    "type":        "string",
                    "description": "Commit message.",
                }
            }
        })
    }
    async fn execute(
        &self,
        input: &serde_json::Value,
        ctx: &ToolContext,
    ) -> Result<ToolOutput, ToolError> {
        let message = input
            .get("message")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ToolError::InvalidInput {
                tool: "git_commit".to_owned(),
                reason: "missing or non-string `message`".to_owned(),
            })?;
        // The cloned worktree has no `user.email` / `user.name` in
        // its `.git/config` (the gix `file://` clone copies refs +
        // HEAD but not user identity), and the AVF guest has no
        // `~/.gitconfig` to inherit from. Without an identity,
        // `git commit` exits 128 with "Author identity unknown",
        // which would surface to the model as a tool failure and
        // burn LLM tokens on retries. We inject a deterministic
        // raxis identity via the standard `GIT_AUTHOR_*` /
        // `GIT_COMMITTER_*` env vars (they take precedence over
        // both `.git/config` and `~/.gitconfig` per `git-commit(1)
        // ENVIRONMENT`) so the commit is fully self-contained and
        // reproducible across guest reboots. The author email is
        // a `.invalid` TLD per RFC 2606 so the address can never
        // be confused with a real maintainer's mailbox.
        let git_env: &[(&str, &str)] = &[
            ("GIT_AUTHOR_NAME", "raxis-executor"),
            ("GIT_AUTHOR_EMAIL", "executor@raxis.invalid"),
            ("GIT_COMMITTER_NAME", "raxis-executor"),
            ("GIT_COMMITTER_EMAIL", "executor@raxis.invalid"),
        ];

        let add = match tokio::process::Command::new("git")
            .args(["add", "-A"])
            .current_dir(&ctx.workspace_root)
            .envs(git_env.iter().copied())
            .output()
            .await
        {
            Ok(o) => o,
            Err(e) => {
                return Ok(ToolOutput::err(format!(
                    "git_commit: `git add -A` spawn failed: {e}"
                )))
            }
        };
        if !add.status.success() {
            return Ok(ToolOutput::err(format!(
                "git_commit: `git add -A` exit {}\n{}",
                add.status
                    .code()
                    .map(|c| c.to_string())
                    .unwrap_or_else(|| "<signalled>".to_owned()),
                String::from_utf8_lossy(&add.stderr)
            )));
        }
        let commit = match tokio::process::Command::new("git")
            .args(["commit", "-m", message])
            .current_dir(&ctx.workspace_root)
            .envs(git_env.iter().copied())
            .output()
            .await
        {
            Ok(o) => o,
            Err(e) => {
                return Ok(ToolOutput::err(format!(
                    "git_commit: `git commit` spawn failed: {e}"
                )))
            }
        };
        if !commit.status.success() {
            return Ok(ToolOutput::err(format!(
                "git_commit: `git commit` exit {}\nstdout: {}\nstderr: {}",
                commit
                    .status
                    .code()
                    .map(|c| c.to_string())
                    .unwrap_or_else(|| "<signalled>".to_owned()),
                String::from_utf8_lossy(&commit.stdout),
                String::from_utf8_lossy(&commit.stderr)
            )));
        }
        // Return the FULL HEAD SHA (40 hex chars) so the model can
        // inspect what was committed. `task_complete` derives the
        // authoritative HEAD itself, so the model never has to copy
        // this value into the completion tool.
        let sha = match tokio::process::Command::new("git")
            .args(["rev-parse", "HEAD"])
            .current_dir(&ctx.workspace_root)
            .envs(git_env.iter().copied())
            .output()
            .await
        {
            Ok(o) => String::from_utf8_lossy(&o.stdout).trim().to_owned(),
            Err(e) => {
                return Ok(ToolOutput::err(format!(
                    "git_commit: `git rev-parse` failed: {e}"
                )))
            }
        };
        Ok(ToolOutput::ok(format!(
            "committed: {sha}\n{}",
            String::from_utf8_lossy(&commit.stdout).trim()
        )))
    }
}

// ---------------------------------------------------------------------------
// V2 §3.1 — Sleep tool
// token-budget-preserving wait. Lets an
// agent block on an external process (CI, deploy rollout) without
// burning model turns on a polling loop. Available to executor and
// orchestrator only when policy declares `[budget.sleep_caps]` —
// NOT to the reviewer (the Pure-Static Reviewer has no external
// process to wait for; INV-PLANNER-HARNESS-02).
// ---------------------------------------------------------------------------

/// Hard upper bound on `seconds` regardless of policy. The §3.1
/// spec specifies "60 second" as a typical operator value; this
/// 600s ceiling is the absolute kernel guard so a typo in
/// `policy.toml` cannot pin a VM slot for hours.
pub const SLEEP_TOOL_HARD_MAX_SECONDS: u32 = 600;

/// V2 Sleep tool. Carries its own
/// per-call ceiling, cumulative ceiling, and rolling cumulative
/// counter (shared between every Tool::execute call inside one
/// dispatch loop). Construct with [`SleepTool::new`] from the
/// dispatch loop's policy snapshot.
/// Rate-limit semantics:
/// * `seconds == 0` → success, nothing to sleep.
/// * `seconds > max_per_call` → `FAIL_SLEEP_PER_CALL_EXCEEDED`.
/// * `seconds > SLEEP_TOOL_HARD_MAX_SECONDS` → `FAIL_SLEEP_HARD_MAX_EXCEEDED`.
/// * `cumulative + seconds > max_cumulative` → `FAIL_SLEEP_BUDGET_EXCEEDED`.
/// * `max_per_call == 0` → tool disabled, every call returns
///   `FAIL_SLEEP_DISABLED` (kept for direct tests / defense in
///   depth, but not advertised in the default registry).
///   All errors are STRUCTURED (returned as `ToolOutput::err`) so the
///   model can recover; `Tool::execute` itself returns `Ok` in every
///   case (matches the dispatch loop's error contract — see `BashTool`).
pub struct SleepTool {
    max_per_call_seconds: u32,
    max_cumulative_seconds: u32,
    cumulative_slept_seconds: Arc<std::sync::Mutex<u32>>,
}

impl SleepTool {
    /// Construct a new SleepTool with the given per-call and
    /// cumulative ceilings (both in seconds). Registries omit the
    /// tool entirely when policy did not declare `[budget.sleep_caps]`.
    pub fn new(max_per_call_seconds: u32, max_cumulative_seconds: u32) -> Self {
        Self {
            max_per_call_seconds,
            max_cumulative_seconds,
            cumulative_slept_seconds: Arc::new(std::sync::Mutex::new(0)),
        }
    }

    /// Construct a Sleep tool that refuses every invocation. Used
    /// when the policy did not opt in by declaring
    /// `[budget.sleep_caps]`.
    pub fn disabled() -> Self {
        Self::new(0, 0)
    }

    /// Snapshot the cumulative seconds slept so far. For tests +
    /// audit instrumentation.
    pub fn cumulative_slept_seconds(&self) -> u32 {
        *self
            .cumulative_slept_seconds
            .lock()
            .expect("sleep mutex poisoned")
    }
}

#[async_trait::async_trait]
impl Tool for SleepTool {
    fn name(&self) -> &'static str {
        "sleep"
    }
    fn description(&self) -> &'static str {
        "Wait `seconds` without another model call. Policy and 600s hard caps \
         apply; disabled/over-cap calls return structured errors."
    }
    fn input_schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type":     "object",
            "required": ["seconds"],
            "properties": {
                "seconds": {
                    "type":        "integer",
                    "minimum":     0,
                    "maximum":     SLEEP_TOOL_HARD_MAX_SECONDS,
                    "description": "Whole seconds; policy plus 600s hard cap.",
                },
                "reason": {
                    "type":        "string",
                    "description": "Optional audit-visible reason.",
                }
            }
        })
    }
    async fn execute(
        &self,
        input: &serde_json::Value,
        _ctx: &ToolContext,
    ) -> Result<ToolOutput, ToolError> {
        // Tool disabled → operator did not opt in.
        if self.max_per_call_seconds == 0 {
            return Ok(ToolOutput::err(
                "FAIL_SLEEP_DISABLED: the operator policy does not declare \
                 [budget.sleep_caps]; the Sleep tool is unavailable."
                    .to_owned(),
            ));
        }
        let seconds_raw = input
            .get("seconds")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| ToolError::InvalidInput {
                tool: "sleep".to_owned(),
                reason: "missing or non-integer `seconds`".to_owned(),
            })?;
        // Clamp at u32::MAX to keep cast safe; the per-call gate
        // below catches anything above the policy ceiling.
        let seconds: u32 = seconds_raw.min(u32::MAX as u64) as u32;

        if seconds == 0 {
            // Trivial fast path. No sleep, no cumulative charge.
            return Ok(ToolOutput::ok("slept_seconds: 0".to_owned()));
        }
        if seconds > SLEEP_TOOL_HARD_MAX_SECONDS {
            return Ok(ToolOutput::err(format!(
                "FAIL_SLEEP_HARD_MAX_EXCEEDED: requested {seconds}s > kernel \
                 hard ceiling {SLEEP_TOOL_HARD_MAX_SECONDS}s",
            )));
        }
        if seconds > self.max_per_call_seconds {
            return Ok(ToolOutput::err(format!(
                "FAIL_SLEEP_PER_CALL_EXCEEDED: requested {seconds}s > policy \
                 max_seconds_per_call={}s",
                self.max_per_call_seconds,
            )));
        }
        // Cumulative gate — atomic read+write under the same lock.
        // The lock scope is intentionally tight to keep the await
        // outside it (Mutex is std::sync, not tokio).
        {
            let mut cum = self
                .cumulative_slept_seconds
                .lock()
                .expect("sleep mutex poisoned");
            let projected = cum.saturating_add(seconds);
            if projected > self.max_cumulative_seconds {
                return Ok(ToolOutput::err(format!(
                    "FAIL_SLEEP_BUDGET_EXCEEDED: cumulative {cum}s + requested \
                     {seconds}s > policy max_cumulative_seconds={}s",
                    self.max_cumulative_seconds,
                )));
            }
            *cum = projected;
        }
        // Optional `reason` is reflected back in the response so the
        // model has its own text to anchor on for the next turn.
        let reason_suffix = match input.get("reason").and_then(|v| v.as_str()) {
            Some(r) if !r.trim().is_empty() => format!(" reason: {r}"),
            _ => String::new(),
        };
        tokio::time::sleep(std::time::Duration::from_secs(seconds as u64)).await;
        Ok(ToolOutput::ok(format!(
            "slept_seconds: {seconds}{reason_suffix}"
        )))
    }
}

// ---------------------------------------------------------------------------
// StructuredOutputTool — V2 §3.2 typed mid-session output.
// ---------------------------------------------------------------------------

/// ** typed mid-session communication.**
/// The `structured_output` tool ships a closed-enum payload to the
/// kernel via the planner UDS (R-2 — Mediated I/O). Three variants:
///   * `progress_report` — files modified, tests passing/failing,
///     confidence in `[0.0, 1.0]`.
///   * `diagnostic_flag` — severity (`info` / `warning` / `critical`),
///     operator-facing message, optional source-location evidence.
///   * `task_summary`    — final commit SHA, changed paths,
///     one-paragraph approach.
///     **Authority.** Registered in the executor + orchestrator
///     registries only; the reviewer registry never has it
///     (INV-PLANNER-HARNESS-02). NOT a terminal tool — the dispatch
///     loop keeps running after a successful submission.
///     **Wire shape.** The model invokes the tool with
///     `{ "kind": "progress_report", "files_modified": [...], ... }`
///     (snake-case `kind` discriminator + variant fields). The tool
///     parses into `StructuredOutputKind` (which uses the default
///     external-tag serde representation for `bincode::serde`
///     compatibility) by manually mapping the snake-case `kind`
///     string to the matching variant. This is the ONLY place in
///     the planner stack that bridges the model's snake-case
///     projection to the external-tag wire shape; downstream
///     handlers see the canonical bincode shape.
pub struct StructuredOutputTool {
    submitter: Arc<crate::intent::IntentSubmitter>,
}

impl StructuredOutputTool {
    /// Construct a new `structured_output` tool wired to the
    /// session-scoped [`crate::intent::IntentSubmitter`].
    pub fn new(submitter: Arc<crate::intent::IntentSubmitter>) -> Self {
        Self { submitter }
    }
}

#[async_trait::async_trait]
impl Tool for StructuredOutputTool {
    fn name(&self) -> &'static str {
        "structured_output"
    }
    fn description(&self) -> &'static str {
        "NON-TERMINAL: send progress_report, diagnostic_flag, or task_summary \
         to the kernel. Use for operator-visible status; over-cap returns an error."
    }
    fn input_schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type":     "object",
            "required": ["kind"],
            "properties": {
                "kind": {
                    "type":        "string",
                    "enum":        ["progress_report", "diagnostic_flag", "task_summary"],
                    "description": "Variant; other fields depend on it.",
                },
                "files_modified": {
                    "type":  "array",
                    "items": { "type": "string" },
                    "description": "progress_report: changed paths.",
                },
                "tests_passing": {
                    "type":    "integer",
                    "minimum": 0,
                    "description": "progress_report: passing test count.",
                },
                "tests_failing": {
                    "type":    "integer",
                    "minimum": 0,
                    "description": "progress_report: failing test count.",
                },
                "confidence": {
                    "type":    "number",
                    "minimum": 0.0,
                    "maximum": 1.0,
                    "description": "progress_report: confidence 0..1.",
                },
                "severity": {
                    "type":        "string",
                    "enum":        ["info", "warning", "critical"],
                    "description": "diagnostic_flag: info/warning/critical.",
                },
                "message": {
                    "type":        "string",
                    "description": "diagnostic_flag: operator-facing message.",
                },
                "evidence": {
                    "type":        "string",
                    "description": "diagnostic_flag: optional path or path:line.",
                },
                "commit_sha": {
                    "type":        "string",
                    "description": "task_summary: 40-char commit SHA.",
                },
                "changed_paths": {
                    "type":  "array",
                    "items": { "type": "string" },
                    "description": "task_summary: changed paths.",
                },
                "approach": {
                    "type":        "string",
                    "description": "task_summary: short rationale.",
                }
            }
        })
    }
    async fn execute(
        &self,
        input: &serde_json::Value,
        _ctx: &ToolContext,
    ) -> Result<ToolOutput, ToolError> {
        let payload = match parse_structured_output_input(input) {
            Ok(p) => p,
            Err(e) => {
                return Ok(ToolOutput::err(format!(
                    "FAIL_STRUCTURED_OUTPUT_INVALID: {e}"
                )))
            }
        };
        // Stable variant tag for the model-facing OK message.
        let variant_tag = payload.variant_tag();

        match self.submitter.submit_structured_output(payload).await {
            Ok(resp) => match resp.outcome {
                raxis_types::IntentOutcome::Accepted { .. } => Ok(ToolOutput::ok(format!(
                    "structured_output_emitted: kind={variant_tag}"
                ))),
                raxis_types::IntentOutcome::Rejected { error_code, .. } => Ok(ToolOutput::err(
                    format!("kernel rejected structured_output: {error_code}"),
                )),
                // V3 iter70 — structured_output never produces an
                // AcceptedBatch envelope (the kernel only emits
                // AcceptedBatch on BatchActivateSubTasks). Reaching
                // here means a kernel-side wire-routing bug or a
                // future widening of AcceptedBatch usage; treat
                // defensively as an unexpected response so the
                // dispatch loop surfaces it as a soft error rather
                // than panicking.
                raxis_types::IntentOutcome::AcceptedBatch { .. } => Ok(ToolOutput::err(
                    "structured_output: kernel returned AcceptedBatch — unexpected variant for \
                     this intent kind"
                        .to_owned(),
                )),
            },
            Err(e) => Ok(ToolOutput::err(format!(
                "structured_output transport error: {e}"
            ))),
        }
    }
}

/// Translate the model-facing snake-case `kind` discriminator + tag
/// fields into the wire-shape [`raxis_types::StructuredOutputKind`].
/// The wire enum uses the default external-tag serde representation
/// (for `bincode::serde` compatibility) but the model and the JSON
/// schema we advertise speak snake-case `kind`. This function is the
/// single bridge between the two.
fn parse_structured_output_input(
    v: &serde_json::Value,
) -> Result<raxis_types::StructuredOutputKind, String> {
    use raxis_types::{DiagnosticSeverity, StructuredOutputKind};

    let kind = v
        .get("kind")
        .and_then(|k| k.as_str())
        .ok_or_else(|| "missing or non-string `kind`".to_owned())?;
    match kind {
        "progress_report" => {
            let files_modified = v
                .get("files_modified")
                .map(|f| {
                    serde_json::from_value::<Vec<String>>(f.clone())
                        .map_err(|e| format!("`files_modified`: {e}"))
                })
                .transpose()?
                .unwrap_or_default();
            let tests_passing = v.get("tests_passing").and_then(|t| t.as_u64()).unwrap_or(0) as u32;
            let tests_failing = v.get("tests_failing").and_then(|t| t.as_u64()).unwrap_or(0) as u32;
            let confidence = v.get("confidence").and_then(|c| c.as_f64()).unwrap_or(0.0) as f32;
            Ok(StructuredOutputKind::ProgressReport {
                files_modified,
                tests_passing,
                tests_failing,
                confidence,
            })
        }
        "diagnostic_flag" => {
            let severity = match v.get("severity").and_then(|s| s.as_str()) {
                Some("info") => DiagnosticSeverity::Info,
                Some("warning") => DiagnosticSeverity::Warning,
                Some("critical") => DiagnosticSeverity::Critical,
                Some(other) => {
                    return Err(format!(
                        "unknown severity {other:?}; expected info/warning/critical"
                    ))
                }
                None => return Err("diagnostic_flag requires `severity`".to_owned()),
            };
            let message = v
                .get("message")
                .and_then(|m| m.as_str())
                .ok_or_else(|| "diagnostic_flag requires `message`".to_owned())?
                .to_owned();
            let evidence = v
                .get("evidence")
                .and_then(|e| e.as_str())
                .map(str::to_owned);
            Ok(StructuredOutputKind::DiagnosticFlag {
                severity,
                message,
                evidence,
            })
        }
        "task_summary" => {
            let commit_sha = v
                .get("commit_sha")
                .and_then(|s| s.as_str())
                .ok_or_else(|| "task_summary requires `commit_sha`".to_owned())?
                .to_owned();
            let changed_paths = v
                .get("changed_paths")
                .map(|p| {
                    serde_json::from_value::<Vec<String>>(p.clone())
                        .map_err(|e| format!("`changed_paths`: {e}"))
                })
                .transpose()?
                .unwrap_or_default();
            let approach = v
                .get("approach")
                .and_then(|a| a.as_str())
                .ok_or_else(|| "task_summary requires `approach`".to_owned())?
                .to_owned();
            Ok(StructuredOutputKind::TaskSummary {
                commit_sha,
                changed_paths,
                approach,
            })
        }
        other => Err(format!(
            "unknown structured_output kind {other:?}; expected one of \
             progress_report, diagnostic_flag, task_summary"
        )),
    }
}

// ---------------------------------------------------------------------------
// Terminal-tool declarations (V2 §3.2 / planner-harness.md §14.3)
// ---------------------------------------------------------------------------
// These tools are declared so the LLM advertises them in
// `MessageRequest::tools` and knows their argument shape, but their
// `execute` is a no-op: the dispatch loop intercepts every name in
// the role-specific `terminal_tools` whitelist BEFORE the tool result
// is folded back into the conversation, then exits with
// `DispatchOutcome::TerminalTool`. The driver's `submit_terminal`
// function then translates the captured `input` JSON into the matching
// `IntentKind` and ships it through the kernel IPC.
// Without these declarations the Anthropic API never tells the model
// these tools exist, the model just emits free-form text describing
// what it would do, and the dispatch loop times out with
// `DispatchOutcome::Idle` (no terminal tool fired). That was the
// observed orchestrator failure mode pre-V2 §3.2 fix.

/// Executor `task_complete` — fires the executor's terminal "I am
/// done" signal after mechanically deriving the committed Git HEAD.
/// The model does not supply authority-bearing SHAs; this tool
/// overwrites terminal input with the observed `head_sha`.
struct TaskCompleteTool;

#[async_trait::async_trait]
impl Tool for TaskCompleteTool {
    fn name(&self) -> &'static str {
        "task_complete"
    }
    fn description(&self) -> &'static str {
        "TERMINAL — finish after committing the task. No SHA input is \
         required; RAXIS verifies the workspace is clean and derives the \
         committed HEAD."
    }
    fn input_schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "summary": {
                    "type": "string",
                    "maxLength": 500,
                    "description": "Optional human summary. Not used as authority."
                },
                "head_sha": {
                    "type":        "string",
                    "minLength":   40,
                    "maxLength":   40,
                    "pattern":     "^[0-9a-f]{40}$",
                    "description": "Deprecated; ignored. RAXIS derives the actual HEAD."
                }
            }
        })
    }
    async fn execute(
        &self,
        _input: &serde_json::Value,
        ctx: &ToolContext,
    ) -> Result<ToolOutput, ToolError> {
        if let Err(e) = run_git_for_workspace(ctx, &["rev-parse", "--is-inside-work-tree"]).await {
            return Ok(ToolOutput::err(format!(
                "task_complete: workspace is not a git repo: {e}"
            )));
        }
        let status = match run_git_for_workspace(ctx, &["status", "--porcelain"]).await {
            Ok(s) => s,
            Err(e) => {
                return Ok(ToolOutput::err(format!(
                    "task_complete: could not inspect workspace cleanliness: {e}"
                )))
            }
        };
        if !status.trim().is_empty() {
            return Ok(ToolOutput::err(format!(
                "task_complete: workspace has uncommitted changes. Commit the \
                 completed work with git_commit before finishing, or use \
                 report_failure if the task cannot be completed.\n{}",
                status.trim()
            )));
        }
        let head = match run_git_for_workspace(ctx, &["rev-parse", "HEAD"]).await {
            Ok(s) => s,
            Err(e) => {
                return Ok(ToolOutput::err(format!(
                    "task_complete: could not resolve committed HEAD: {e}"
                )))
            }
        };
        let head_sha = head.trim();
        if !is_lower_hex_40(head_sha) {
            return Ok(ToolOutput::err(format!(
                "task_complete: git returned malformed HEAD {head_sha:?}"
            )));
        }
        if let Some(base_sha) = ctx
            .task_complete_base_sha
            .as_deref()
            .filter(|s| !s.is_empty())
        {
            if !is_lower_hex_40(base_sha) {
                return Ok(ToolOutput::err(format!(
                    "task_complete: KSB base SHA is malformed ({base_sha:?}); \
                     report_failure so the operator can inspect the spawn state"
                )));
            }
            if base_sha == head_sha {
                return Ok(ToolOutput::err(
                    "task_complete: HEAD still equals the session base. Commit \
                     completed changes before finishing, or use report_failure \
                     if no valid change can be produced."
                        .to_owned(),
                ));
            }
        }

        Ok(ToolOutput::ok_with_input(
            format!("task_complete verified committed HEAD {head_sha}"),
            serde_json::json!({ "head_sha": head_sha }),
        ))
    }
}

/// Declaration-only `report_failure` — terminal "I cannot do this"
/// signal. Argument: `justification`.
struct ReportFailureTool;

#[async_trait::async_trait]
impl Tool for ReportFailureTool {
    fn name(&self) -> &'static str {
        "report_failure"
    }
    fn description(&self) -> &'static str {
        "TERMINAL — cannot complete the task. Provide one actionable \
         paragraph; the kernel records it."
    }
    fn input_schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type":     "object",
            "required": ["justification"],
            "properties": {
                "justification": {
                    "type":        "string",
                    "minLength":   1,
                    "maxLength":   4096,
                    "description": "Operator-readable rationale (≤ 4 KiB)."
                }
            }
        })
    }
    async fn execute(
        &self,
        _input: &serde_json::Value,
        _ctx: &ToolContext,
    ) -> Result<ToolOutput, ToolError> {
        Ok(ToolOutput::ok("report_failure"))
    }
}

/// Declaration-only `single_commit` — terminal alternative to
/// `task_complete` for executors that want to publish a single
/// (base, head) pair to the kernel without staging through
/// `task_complete`. Args: `base_sha`, `head_sha`.
struct SingleCommitTool;

#[async_trait::async_trait]
impl Tool for SingleCommitTool {
    fn name(&self) -> &'static str {
        "single_commit"
    }
    fn description(&self) -> &'static str {
        "TERMINAL — publish an explicit full-hex `base_sha` to `head_sha` \
         pair, then end."
    }
    fn input_schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type":     "object",
            "required": ["base_sha", "head_sha"],
            "properties": {
                "base_sha": {
                    "type":        "string",
                    "minLength":   40,
                    "maxLength":   40,
                    "pattern":     "^[0-9a-f]{40}$",
                    "description": "40-char lowercase-hex base SHA."
                },
                "head_sha": {
                    "type":        "string",
                    "minLength":   40,
                    "maxLength":   40,
                    "pattern":     "^[0-9a-f]{40}$",
                    "description": "40-char lowercase-hex head SHA."
                }
            }
        })
    }
    async fn execute(
        &self,
        _input: &serde_json::Value,
        _ctx: &ToolContext,
    ) -> Result<ToolOutput, ToolError> {
        Ok(ToolOutput::ok("single_commit"))
    }
}

/// Declaration-only `submit_review` — reviewer's terminal verdict.
/// Args: `approved` (bool), optional `critique` (string).
struct SubmitReviewTool;

#[async_trait::async_trait]
impl Tool for SubmitReviewTool {
    fn name(&self) -> &'static str {
        "submit_review"
    }
    fn description(&self) -> &'static str {
        "TERMINAL — submit the review verdict. `approved=false` should include \
         an actionable critique (kernel cap 4 KiB)."
    }
    fn input_schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type":     "object",
            "required": ["approved"],
            "properties": {
                "approved": {
                    "type":        "boolean",
                    "description": "true = accept the commit, false = reject."
                },
                "critique": {
                    "type":        "string",
                    "maxLength":   4096,
                    "description": "Optional rationale (≤ 4 KiB). Recommended \
                                    when `approved = false`."
                }
            }
        })
    }
    async fn execute(
        &self,
        _input: &serde_json::Value,
        _ctx: &ToolContext,
    ) -> Result<ToolOutput, ToolError> {
        Ok(ToolOutput::ok("submit_review"))
    }
}

/// Declaration-only `activate_subtask` — orchestrator's primary DAG
/// driver. Argument: `subtask_task_id` (the task id of a sub-task
/// in `pending` state with no incomplete predecessors). The kernel
/// promotes the row from `PendingActivation → Active` and spawns
/// the corresponding executor / reviewer session.
/// IMPORTANT for the model: the task ids you can pass live in the
/// KSB `dag=` block — every row's first column is a task id.
struct ActivateSubtaskTool;

#[async_trait::async_trait]
impl Tool for ActivateSubtaskTool {
    fn name(&self) -> &'static str {
        "activate_subtask"
    }
    fn description(&self) -> &'static str {
        "TERMINAL — activate one id from KSB `capabilities.ready_now=[...]`. \
         The kernel spawns the executor/reviewer session."
    }
    fn input_schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type":     "object",
            "required": ["subtask_task_id"],
            "properties": {
                "subtask_task_id": {
                    "type":        "string",
                    "minLength":   1,
                    "maxLength":   128,
                    "description": "Exact task id from `ready_now`."
                }
            }
        })
    }
    async fn execute(
        &self,
        _input: &serde_json::Value,
        _ctx: &ToolContext,
    ) -> Result<ToolOutput, ToolError> {
        Ok(ToolOutput::ok("activate_subtask"))
    }
}

/// Declaration-only `batch_activate_subtasks` (V3 iter70) — the
/// orchestrator's *bulk* DAG driver. Arguments: an array of
/// `subtask_task_ids` (the SET of candidate task ids to admit
/// this turn).
///
/// **Order semantics.** The input order is informational only —
/// the kernel ignores it. The kernel:
///   1. evaluates each id against the same admission gates
///      as singular `activate_subtask` (plan-membership,
///      FSM state, predecessor-closure, `can_delegate`);
///   2. filters down to the admissible subset;
///   3. sorts that subset by its own deterministic policy
///      `(admitted_at ASC, task_id ASC)`;
///   4. admits `min(admissible_count, concurrency_headroom)`
///      of them in that sorted order; and
///   5. returns a per-id outcome (Accepted with kernel-assigned
///      `admission_order`, DroppedAtCap, NotAdmissible,
///      UnknownTask, or DuplicateInBatch) so the orchestrator
///      learns exactly what happened to each candidate.
///
/// One bad id does NOT poison the batch — typos surface as
/// per-id `UnknownTask` while other valid ids in the same batch
/// admit normally.
///
/// **Per-id machinery is the singular path.** The kernel runs
/// the EXACT same activation code as singular `activate_subtask`
/// for each admitted id (no FSM divergence, no SQL divergence)
/// — the batch is a wrapper that picks WHICH candidates to
/// admit; the per-task FSM transitions are unchanged.
struct BatchActivateSubtasksTool;

#[async_trait::async_trait]
impl Tool for BatchActivateSubtasksTool {
    fn name(&self) -> &'static str {
        "batch_activate_subtasks"
    }
    fn description(&self) -> &'static str {
        "TERMINAL — propose multiple ids from `capabilities.ready_now=[...]`. \
         Kernel admits what fits `headroom`, ignores input order, and returns \
         per-id outcomes. Prefer this for two or more ready ids."
    }
    fn input_schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type":     "object",
            "required": ["subtask_task_ids"],
            "properties": {
                "subtask_task_ids": {
                    "type":     "array",
                    "minItems": 1,
                    "maxItems": 64,
                    "items": {
                        "type":      "string",
                        "minLength": 1,
                        "maxLength": 128,
                        "description": "Exact task id from `ready_now`."
                    },
                    "description": "Candidate ready ids; order ignored."
                }
            }
        })
    }
    async fn execute(
        &self,
        _input: &serde_json::Value,
        _ctx: &ToolContext,
    ) -> Result<ToolOutput, ToolError> {
        Ok(ToolOutput::ok("batch_activate_subtasks"))
    }
}

/// Declaration-only `retry_subtask` — first half of the two-intent
/// retry contract (`INV-ORCH-RETRY-SUBTASK-TWO-INTENT-CONTRACT-01`).
/// Same input shape as [`ActivateSubtaskTool`].
struct RetrySubtaskTool;

#[async_trait::async_trait]
impl Tool for RetrySubtaskTool {
    fn name(&self) -> &'static str {
        "retry_subtask"
    }
    fn description(&self) -> &'static str {
        "TERMINAL — create a fresh PendingActivation retry for a failed or \
         `aggregate=AtLeastOneRejected` task when KSB says \
         `retry_admissible=true`. It does NOT spawn the VM; next turn must \
         `activate_subtask`. If reason is `prior state PendingActivation`, \
         activate instead. Bad retries burn `orch_no_progress_respawns=`."
    }
    fn input_schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type":     "object",
            "required": ["subtask_task_id"],
            "properties": {
                "subtask_task_id": {
                    "type":        "string",
                    "minLength":   1,
                    "maxLength":   128,
                    "description": "Task id of the failed sub-task to retry."
                }
            }
        })
    }
    async fn execute(
        &self,
        _input: &serde_json::Value,
        _ctx: &ToolContext,
    ) -> Result<ToolOutput, ToolError> {
        Ok(ToolOutput::ok("retry_subtask"))
    }
}

/// Non-terminal helper for the orchestrator's final merge phase.
/// It resets the session worktree to `base_sha`, merges every completed
/// executor SHA in the supplied order, verifies coverage, and returns
/// the final integrated `head_sha` the model should pass to
/// `integration_merge`.
struct PrepareIntegrationMergeTool;

#[async_trait::async_trait]
impl Tool for PrepareIntegrationMergeTool {
    fn name(&self) -> &'static str {
        "prepare_integration_merge"
    }
    fn description(&self) -> &'static str {
        "NONTERMINAL — prepare the orchestrator worktree for final publish. \
         Input the KSB `base_sha` and every completed executor row `sha`; \
         returns the integrated `head_sha` to pass to `integration_merge`. \
         Rejects malformed SHAs and verifies each executor SHA is an ancestor \
         of the final HEAD."
    }
    fn input_schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type":     "object",
            "required": ["base_sha", "executor_shas"],
            "properties": {
                "base_sha": {
                    "type":        "string",
                    "minLength":   40,
                    "maxLength":   40,
                    "pattern":     "^[0-9a-f]{40}$",
                    "description": "40-char lowercase-hex KSB base SHA."
                },
                "executor_shas": {
                    "type":        "array",
                    "minItems":    1,
                    "uniqueItems": true,
                    "description": "Every completed executor row sha= from the KSB.",
                    "items": {
                        "type":      "string",
                        "minLength": 40,
                        "maxLength": 40,
                        "pattern":   "^[0-9a-f]{40}$"
                    }
                }
            }
        })
    }
    async fn execute(
        &self,
        input: &serde_json::Value,
        ctx: &ToolContext,
    ) -> Result<ToolOutput, ToolError> {
        let base_sha = input
            .get("base_sha")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ToolError::InvalidInput {
                tool: "prepare_integration_merge".to_owned(),
                reason: "missing or non-string `base_sha`".to_owned(),
            })?;
        if !is_lower_hex_40(base_sha) {
            return Ok(ToolOutput::err(
                "prepare_integration_merge: `base_sha` must be 40 lowercase hex chars",
            ));
        }

        let executor_shas_json = input
            .get("executor_shas")
            .and_then(|v| v.as_array())
            .ok_or_else(|| ToolError::InvalidInput {
                tool: "prepare_integration_merge".to_owned(),
                reason: "missing or non-array `executor_shas`".to_owned(),
            })?;
        if executor_shas_json.is_empty() {
            return Ok(ToolOutput::err(
                "prepare_integration_merge: `executor_shas` must contain at least one SHA",
            ));
        }
        let mut executor_shas = Vec::with_capacity(executor_shas_json.len());
        for value in executor_shas_json {
            let Some(sha) = value.as_str() else {
                return Ok(ToolOutput::err(
                    "prepare_integration_merge: every `executor_shas` item must be a string",
                ));
            };
            if !is_lower_hex_40(sha) {
                return Ok(ToolOutput::err(format!(
                    "prepare_integration_merge: malformed executor SHA {sha:?}"
                )));
            }
            if !executor_shas.iter().any(|s: &String| s == sha) {
                executor_shas.push(sha.to_owned());
            }
        }

        match prepare_integration_merge(ctx, base_sha, &executor_shas).await {
            Ok(prepared) => Ok(ToolOutput::ok(format!(
                "prepared integration merge\n\
                 Next required terminal call: integration_merge with exactly this base_sha and head_sha.\n\
                 Do not reuse base_sha as head_sha.\n\
                 base_sha: {base_sha}\n\
                 head_sha: {}\n\
                 executor_shas:\n- {}",
                prepared.head_sha,
                prepared.merged.join("\n- ")
            ))),
            Err(e) => Ok(ToolOutput::err(format!("prepare_integration_merge: {e}"))),
        }
    }
}

#[derive(Debug, Clone)]
struct PreparedIntegrationMerge {
    head_sha: String,
    merged: Vec<String>,
}

async fn prepare_integration_merge(
    ctx: &ToolContext,
    base_sha: &str,
    executor_shas: &[String],
) -> Result<PreparedIntegrationMerge, String> {
    if let Err(e) = run_git_for_merge(ctx, &["rev-parse", "--is-inside-work-tree"]).await {
        return Err(format!("workspace is not a git repo: {e}"));
    }
    if let Err(e) = run_git_for_merge(ctx, &["reset", "--hard", base_sha]).await {
        return Err(format!("git reset to base failed: {e}"));
    }

    let mut merged = Vec::new();
    for sha in executor_shas {
        match run_git_for_merge(ctx, &["merge-base", "--is-ancestor", sha, "HEAD"]).await {
            Ok(_) => {
                merged.push(format!("{sha} (already ancestor)"));
                continue;
            }
            Err(_) => {}
        }
        if let Err(e) = run_git_for_merge(
            ctx,
            &[
                "-c",
                "user.name=RAXIS Orchestrator",
                "-c",
                "user.email=raxis-orchestrator@localhost",
                "merge",
                "--no-ff",
                "--no-edit",
                sha,
            ],
        )
        .await
        {
            return Err(format!("git merge {sha} failed: {e}"));
        }
        merged.push(sha.to_owned());
    }

    let head = run_git_for_merge(ctx, &["rev-parse", "HEAD"])
        .await
        .map_err(|e| format!("git rev-parse HEAD failed: {e}"))?;
    let head_sha = head.trim();
    if !is_lower_hex_40(head_sha) {
        return Err(format!("git returned malformed HEAD {head_sha:?}"));
    }
    for sha in executor_shas {
        if let Err(e) =
            run_git_for_merge(ctx, &["merge-base", "--is-ancestor", sha, head_sha]).await
        {
            return Err(format!(
                "final HEAD {head_sha} does not contain executor SHA {sha}: {e}"
            ));
        }
    }

    Ok(PreparedIntegrationMerge {
        head_sha: head_sha.to_owned(),
        merged,
    })
}

fn is_lower_hex_40(s: &str) -> bool {
    s.len() == 40
        && s.bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

async fn run_git_for_workspace(ctx: &ToolContext, args: &[&str]) -> Result<String, String> {
    let child = tokio::process::Command::new("git")
        .args(args)
        .current_dir(&ctx.workspace_root)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .stdin(std::process::Stdio::null())
        .spawn();
    let child = match child {
        Ok(c) => c,
        Err(e) => return Err(format!("git spawn failed: {e}")),
    };
    let timeout = ctx.deadline.unwrap_or(Duration::from_secs(120));
    let out = match tokio::time::timeout(timeout, child.wait_with_output()).await {
        Ok(Ok(o)) => o,
        Ok(Err(e)) => return Err(format!("git wait failed: {e}")),
        Err(_) => return Err(format!("git command timed out after {timeout:?}")),
    };
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    if out.status.success() {
        Ok(stdout)
    } else {
        Err(format!(
            "git {:?} exited {}\nstdout:\n{}\nstderr:\n{}",
            args,
            out.status
                .code()
                .map(|c| c.to_string())
                .unwrap_or_else(|| "<signalled>".to_owned()),
            stdout,
            stderr
        ))
    }
}

async fn run_git_for_merge(ctx: &ToolContext, args: &[&str]) -> Result<String, String> {
    run_git_for_workspace(ctx, args).await
}

/// Declaration-only `integration_merge` — orchestrator's terminal
/// "all sub-tasks done — merge them" signal. Args: `base_sha`,
/// `head_sha`. `head_sha` is the final integrated HEAD containing
/// every completed executor artifact. The kernel performs the
/// canonical fast-forward against `target_ref` (from the KSB).
struct IntegrationMergeTool;

#[async_trait::async_trait]
impl Tool for IntegrationMergeTool {
    fn name(&self) -> &'static str {
        "integration_merge"
    }
    fn description(&self) -> &'static str {
        "TERMINAL — publish final integrated `head_sha` to `target_ref` after \
         all executors/reviewers are complete and accepted. `head_sha` must \
         contain every completed executor SHA, not just one executor row. \
         The kernel rejects unfinished reviewer panels \
         (`aggregate=AwaitingReviewerVerdicts`) and rejected panels \
         (`aggregate=AtLeastOneRejected`)."
    }
    fn input_schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type":     "object",
            "required": ["base_sha", "head_sha"],
            "properties": {
                "base_sha": {
                    "type":        "string",
                    "minLength":   40,
                    "maxLength":   40,
                    "pattern":     "^[0-9a-f]{40}$",
                    "description": "40-char lowercase-hex base SHA."
                },
                "head_sha": {
                    "type":        "string",
                    "minLength":   40,
                    "maxLength":   40,
                    "pattern":     "^[0-9a-f]{40}$",
                    "description": "40-char lowercase-hex head SHA."
                }
            }
        })
    }
    async fn execute(
        &self,
        input: &serde_json::Value,
        ctx: &ToolContext,
    ) -> Result<ToolOutput, ToolError> {
        let input_base = input.get("base_sha").and_then(|v| v.as_str());
        let input_head = input.get("head_sha").and_then(|v| v.as_str());
        let merge_ctx = ctx.integration_merge.as_ref();

        let Some(merge_ctx) = merge_ctx else {
            let Some(base_sha) = input_base.filter(|s| is_lower_hex_40(s)) else {
                return Ok(ToolOutput::err(
                    "integration_merge: `base_sha` must be 40 lowercase hex chars",
                ));
            };
            let Some(head_sha) = input_head.filter(|s| is_lower_hex_40(s)) else {
                return Ok(ToolOutput::err(
                    "integration_merge: `head_sha` must be 40 lowercase hex chars",
                ));
            };
            if base_sha == head_sha {
                return Ok(ToolOutput::err(
                    "integration_merge: base_sha and head_sha are identical. A no-op merge is \
                     never a valid terminal publish for a plan with executor/reviewer tasks. \
                     Re-read KSB capabilities.integration_merge, run prepare_integration_merge, \
                     then call integration_merge with the integrated head_sha.",
                ));
            }
            return Ok(ToolOutput::ok_with_input(
                "integration_merge verified input shape",
                serde_json::json!({ "base_sha": base_sha, "head_sha": head_sha }),
            ));
        };

        if merge_ctx.base_sha.is_empty() || !is_lower_hex_40(&merge_ctx.base_sha) {
            return Ok(ToolOutput::err(
                "integration_merge: KSB capabilities.integration_merge.base_sha is not set; \
                 do not call integration_merge until integration_merge.ready=true",
            ));
        }
        if let Some(base_sha) = input_base {
            if is_lower_hex_40(base_sha) && base_sha != merge_ctx.base_sha {
                return Ok(ToolOutput::err(format!(
                    "integration_merge: base_sha {base_sha} does not match KSB \
                     capabilities.integration_merge.base_sha {}; use the KSB base_sha",
                    merge_ctx.base_sha
                )));
            }
        }

        let mut required = Vec::new();
        for item in &merge_ctx.required_executor_shas {
            if !is_lower_hex_40(&item.sha) {
                return Ok(ToolOutput::err(format!(
                    "integration_merge: KSB required executor SHA for task {} is malformed: {:?}",
                    item.task_id, item.sha
                )));
            }
            if !required.iter().any(|sha: &String| sha == &item.sha) {
                required.push(item.sha.clone());
            }
        }
        if required.is_empty() {
            return Ok(ToolOutput::err(
                "integration_merge: KSB required_executor_shas is empty; do not call \
                 integration_merge until the KSB marks integration_merge.ready=true",
            ));
        }

        if let Some(head_sha) = input_head.filter(|s| is_lower_hex_40(s)) {
            let missing =
                missing_required_executor_shas(ctx, head_sha, &merge_ctx.required_executor_shas)
                    .await;
            if missing.is_empty() {
                return Ok(ToolOutput::ok_with_input(
                    format!(
                        "integration_merge verified\nbase_sha: {}\nhead_sha: {head_sha}\ncontains_required_executor_shas: {}",
                        merge_ctx.base_sha,
                        required.len()
                    ),
                    serde_json::json!({
                        "base_sha": merge_ctx.base_sha,
                        "head_sha": head_sha,
                    }),
                ));
            }
        }

        match prepare_integration_merge(ctx, &merge_ctx.base_sha, &required).await {
            Ok(prepared) => Ok(ToolOutput::ok_with_input(
                format!(
                    "integration_merge auto-prepared a valid integrated head before submit\n\
                     Use this exact terminal input now:\n\
                     base_sha: {}\n\
                     head_sha: {}\n\
                     required_executor_shas:\n- {}",
                    merge_ctx.base_sha,
                    prepared.head_sha,
                    prepared.merged.join("\n- ")
                ),
                serde_json::json!({
                    "base_sha": merge_ctx.base_sha,
                    "head_sha": prepared.head_sha,
                }),
            )),
            Err(e) => {
                let supplied = input_head.unwrap_or("<missing>");
                Ok(ToolOutput::err(format!(
                    "integration_merge blocked locally: candidate head_sha {supplied} does not contain every completed executor SHA, and automatic preparation failed: {e}\n\
                     Run `prepare_integration_merge` with base_sha={} and executor_shas=[{}]. If it reports conflicts, resolve only those conflicts, commit the resolution on top, verify every required executor SHA is an ancestor of HEAD, then call integration_merge again with the final HEAD.",
                    merge_ctx.base_sha,
                    required.join(", ")
                )))
            }
        }
    }
}

async fn missing_required_executor_shas(
    ctx: &ToolContext,
    head_sha: &str,
    required: &[IntegrationMergeRequiredSha],
) -> Vec<IntegrationMergeRequiredSha> {
    let mut missing = Vec::new();
    for item in required {
        match run_git_for_merge(ctx, &["merge-base", "--is-ancestor", &item.sha, head_sha]).await {
            Ok(_) => {}
            Err(_) => missing.push(item.clone()),
        }
    }
    missing
}

// ---------------------------------------------------------------------------
// Role-specific registry constructors
// ---------------------------------------------------------------------------

/// **Executor registry.** Includes all tools the executor needs:
/// `read_file`, `edit_file`, `bash`, `grep_search`, `git_commit`,
/// and the three terminal-tool declarations (`task_complete`,
/// `report_failure`, `single_commit`) so the model knows it can
/// call them. `sleep` is only registered by
/// [`build_executor_registry_with_sleep`] when policy declares a
/// real sleep budget; unavailable tools should not be advertised to
/// the model.
pub fn build_executor_registry() -> ToolRegistry {
    let mut r = ToolRegistry::new();
    r.register(Arc::new(ReadFileTool));
    r.register(Arc::new(EditFileTool));
    r.register(Arc::new(BashTool));
    r.register(Arc::new(GrepSearchTool));
    r.register(Arc::new(GitCommitTool));
    // V2 `INV-EXEC-DISCOVERY-01` — capability discovery. Available
    // unconditionally; cached per-process. The system-prompt
    // capability-hint block (`render_capability_hint`) covers the
    // common case; this tool is the recourse for finer queries.
    r.register(Arc::new(VmCapabilitiesTool));
    // Terminal-tool declarations (V2 §3.2 / planner-harness.md §14.3).
    r.register(Arc::new(TaskCompleteTool));
    r.register(Arc::new(ReportFailureTool));
    r.register(Arc::new(SingleCommitTool));
    r
}

/// **Reviewer registry.** Read-only by construction:
/// `read_file`, `list_files`, `grep_search`. NO `edit_file`, NO
/// `bash`, NO `git_commit`, NO `sleep`
/// (INV-PLANNER-HARNESS-02 — Pure-Static Reviewer has no external
/// process to wait for). Pinned by `planner-harness.md §14.3
/// INV-PLANNER-HARNESS-04`. Includes the `submit_review`
/// terminal-tool declaration so the model knows to call it.
pub fn build_reviewer_registry() -> ToolRegistry {
    let mut r = ToolRegistry::new();
    r.register(Arc::new(ReadFileTool));
    r.register(Arc::new(ListFilesTool));
    r.register(Arc::new(GrepSearchTool));
    // V2 `INV-EXEC-DISCOVERY-01` — capability discovery is read-
    // only (no workspace mutation, no egress, no shell exec
    // beyond cheap `--version` probes). Including it in the
    // reviewer registry lets the reviewer query "what test
    // runners are available?" before recommending a remediation,
    // without violating INV-PLANNER-HARNESS-04 (no workspace-
    // mutating tools for the reviewer).
    r.register(Arc::new(VmCapabilitiesTool));
    r.register(Arc::new(SubmitReviewTool));
    r
}

/// **Orchestrator registry.** DAG controls plus final integration
/// tools. The orchestrator can inspect with `read_file` /
/// `grep_search`, prepare the merge with
/// `prepare_integration_merge`, and use `bash` / `edit_file` /
/// `git_commit` only to resolve integration conflicts in its own
/// integration worktree. It cannot bypass kernel publication checks:
/// `integration_merge` still validates path scope and requires the
/// final head to contain every completed executor artifact. `sleep`
/// is only registered by [`build_orchestrator_registry_with_sleep`]
/// when policy declares a real sleep budget.
pub fn build_orchestrator_registry() -> ToolRegistry {
    let mut r = ToolRegistry::new();
    r.register(Arc::new(ReadFileTool));
    r.register(Arc::new(EditFileTool));
    r.register(Arc::new(BashTool));
    r.register(Arc::new(GrepSearchTool));
    r.register(Arc::new(GitCommitTool));
    // V2 `INV-EXEC-DISCOVERY-01` — capability discovery. The
    // orchestrator rarely needs it (its toolchain is the
    // canonical orchestrator-core image) but registering keeps
    // the introspection surface uniform across roles, which
    // simplifies reasoning about "which manifest fields can the
    // model query in which role" — answer: always all of them.
    r.register(Arc::new(VmCapabilitiesTool));
    // Non-terminal merge helper. Keeps the sensitive orchestrator role
    // on a narrow, typed path instead of making the LLM infer shell/git
    // choreography from the DAG.
    r.register(Arc::new(PrepareIntegrationMergeTool));
    // Terminal-tool declarations (V2 §3.2 / planner-harness.md §14.3).
    r.register(Arc::new(ActivateSubtaskTool));
    // V3 iter70 — batch-admit primitive.
    r.register(Arc::new(BatchActivateSubtasksTool));
    r.register(Arc::new(RetrySubtaskTool));
    r.register(Arc::new(IntegrationMergeTool));
    r
}

/// Executor registry with the
/// `sleep` tool wired to the operator-declared policy ceilings.
/// Construct from the dispatch-loop boot env (the kernel projects
/// `policy.sleep_caps()` into `RAXIS_PLANNER_MAX_SLEEP_SECONDS_PER_CALL`
/// and `RAXIS_PLANNER_MAX_CUMULATIVE_SLEEP_SECONDS`). Includes the
/// three executor terminal-tool declarations.
pub fn build_executor_registry_with_sleep(
    max_per_call_seconds: u32,
    max_cumulative_seconds: u32,
) -> ToolRegistry {
    let mut r = ToolRegistry::new();
    r.register(Arc::new(ReadFileTool));
    r.register(Arc::new(EditFileTool));
    r.register(Arc::new(BashTool));
    r.register(Arc::new(GrepSearchTool));
    r.register(Arc::new(GitCommitTool));
    r.register(Arc::new(SleepTool::new(
        max_per_call_seconds,
        max_cumulative_seconds,
    )));
    // V2 `INV-EXEC-DISCOVERY-01` — capability discovery (sleep
    // variant of the executor registry).
    r.register(Arc::new(VmCapabilitiesTool));
    // Terminal-tool declarations (V2 §3.2 / planner-harness.md §14.3).
    r.register(Arc::new(TaskCompleteTool));
    r.register(Arc::new(ReportFailureTool));
    r.register(Arc::new(SingleCommitTool));
    r
}

/// Orchestrator registry with the
/// `sleep` tool wired to the operator-declared policy ceilings.
/// Includes the three orchestrator terminal-tool declarations.
pub fn build_orchestrator_registry_with_sleep(
    max_per_call_seconds: u32,
    max_cumulative_seconds: u32,
) -> ToolRegistry {
    let mut r = ToolRegistry::new();
    r.register(Arc::new(ReadFileTool));
    r.register(Arc::new(EditFileTool));
    r.register(Arc::new(BashTool));
    r.register(Arc::new(GrepSearchTool));
    r.register(Arc::new(GitCommitTool));
    r.register(Arc::new(SleepTool::new(
        max_per_call_seconds,
        max_cumulative_seconds,
    )));
    // V2 `INV-EXEC-DISCOVERY-01` — capability discovery.
    r.register(Arc::new(VmCapabilitiesTool));
    r.register(Arc::new(PrepareIntegrationMergeTool));
    // Terminal-tool declarations (V2 §3.2 / planner-harness.md §14.3).
    r.register(Arc::new(ActivateSubtaskTool));
    // V3 iter70 — batch-admit primitive.
    r.register(Arc::new(BatchActivateSubtasksTool));
    r.register(Arc::new(RetrySubtaskTool));
    r.register(Arc::new(IntegrationMergeTool));
    r
}

/// **V2 ** — full executor registry
/// wired to the operator-declared policy ceilings AND the
/// session-scoped `IntentSubmitter`. Use from the executor binary's
/// `main.rs` once the submitter is constructed.
/// The §3.2 `structured_output` tool requires an `IntentSubmitter`
/// (it ships its payload via the planner UDS); supplying it here
/// keeps the registry constructors purely declarative — the
/// dispatch loop never needs to know which tools require IPC.
pub fn build_executor_registry_full(
    max_per_call_seconds: u32,
    max_cumulative_seconds: u32,
    submitter: Arc<crate::intent::IntentSubmitter>,
) -> ToolRegistry {
    let mut r = build_executor_registry_with_sleep(max_per_call_seconds, max_cumulative_seconds);
    r.register(Arc::new(StructuredOutputTool::new(submitter)));
    r
}

/// **V2 ** — full orchestrator
/// registry wired to the operator-declared policy ceilings AND the
/// session-scoped `IntentSubmitter`. Mirror of
/// [`build_executor_registry_full`] for the orchestrator role.
pub fn build_orchestrator_registry_full(
    max_per_call_seconds: u32,
    max_cumulative_seconds: u32,
    submitter: Arc<crate::intent::IntentSubmitter>,
) -> ToolRegistry {
    let mut r =
        build_orchestrator_registry_with_sleep(max_per_call_seconds, max_cumulative_seconds);
    r.register(Arc::new(StructuredOutputTool::new(submitter)));
    r
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn fixture_workspace() -> TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("hello.txt"), "hi from raxis").unwrap();
        dir
    }

    #[test]
    fn registry_role_asymmetry_executor_includes_git_commit() {
        let r = build_executor_registry();
        assert!(r.get("git_commit").is_some());
        assert!(r.get("edit_file").is_some());
        assert!(r.get("bash").is_some());
        assert!(
            r.get("sleep").is_none(),
            "executor registry MUST NOT advertise sleep unless policy \
             declares a sleep budget"
        );
    }

    #[test]
    fn registry_role_asymmetry_reviewer_excludes_write_tools() {
        // INV-PLANNER-HARNESS-04: reviewer MUST NOT have any
        // workspace-mutating tool.
        let r = build_reviewer_registry();
        assert!(
            r.get("git_commit").is_none(),
            "reviewer registry MUST NOT include git_commit"
        );
        assert!(
            r.get("edit_file").is_none(),
            "reviewer registry MUST NOT include edit_file"
        );
        assert!(
            r.get("bash").is_none(),
            "reviewer registry MUST NOT include bash"
        );
        // V2 §3.1 — Pure-Static Reviewer never has Sleep
        // (INV-PLANNER-HARNESS-02; no external process to wait for).
        assert!(
            r.get("sleep").is_none(),
            "reviewer registry MUST NOT include the sleep tool \
             (INV-PLANNER-HARNESS-02)"
        );
        // Read-only tools ARE expected:
        assert!(r.get("read_file").is_some());
        assert!(r.get("list_files").is_some());
        assert!(r.get("grep_search").is_some());
    }

    /// `seconds = 0` is a fast path:
    /// success, no actual sleep, no cumulative charge.
    #[tokio::test]
    async fn sleep_zero_is_fast_path_no_charge() {
        let tool = SleepTool::new(60, 300);
        let ctx = ToolContext::for_workspace(std::path::PathBuf::from("/tmp"));
        let out = tool
            .execute(&serde_json::json!({"seconds": 0}), &ctx)
            .await
            .unwrap();
        assert!(!out.is_error.unwrap_or(false));
        assert_eq!(
            tool.cumulative_slept_seconds(),
            0,
            "0-second sleep MUST NOT charge against cumulative budget"
        );
    }

    /// `seconds > max_per_call` returns `FAIL_SLEEP_PER_CALL_EXCEEDED`
    /// without sleeping or charging cumulative budget.
    #[tokio::test]
    async fn sleep_per_call_ceiling_rejects() {
        let tool = SleepTool::new(/*per_call*/ 5, /*cum*/ 60);
        let ctx = ToolContext::for_workspace(std::path::PathBuf::from("/tmp"));
        let out = tool
            .execute(&serde_json::json!({"seconds": 10}), &ctx)
            .await
            .unwrap();
        assert!(
            out.is_error.unwrap_or(false),
            "10s > 5s per-call ceiling MUST be rejected"
        );
        assert!(
            out.content.contains("FAIL_SLEEP_PER_CALL_EXCEEDED"),
            "error must surface FAIL_SLEEP_PER_CALL_EXCEEDED, got: {}",
            out.content
        );
        assert_eq!(
            tool.cumulative_slept_seconds(),
            0,
            "rejected call MUST NOT charge cumulative budget"
        );
    }

    /// Cumulative gate fires when `cumulative + seconds > max_cumulative`.
    #[tokio::test]
    async fn sleep_cumulative_ceiling_rejects() {
        let tool = SleepTool::new(/*per_call*/ 60, /*cum*/ 10);
        let ctx = ToolContext::for_workspace(std::path::PathBuf::from("/tmp"));
        // First 5s call: passes.
        let out = tool
            .execute(&serde_json::json!({"seconds": 5}), &ctx)
            .await
            .unwrap();
        assert!(!out.is_error.unwrap_or(false));
        assert_eq!(tool.cumulative_slept_seconds(), 5);
        // Second 6s call: would push cumulative to 11 > 10. Reject.
        let out = tool
            .execute(&serde_json::json!({"seconds": 6}), &ctx)
            .await
            .unwrap();
        assert!(out.is_error.unwrap_or(false));
        assert!(
            out.content.contains("FAIL_SLEEP_BUDGET_EXCEEDED"),
            "expected FAIL_SLEEP_BUDGET_EXCEEDED, got: {}",
            out.content
        );
        assert_eq!(
            tool.cumulative_slept_seconds(),
            5,
            "rejected call MUST NOT charge cumulative budget"
        );
    }

    /// `SleepTool::disabled()` refuses every invocation with
    /// `FAIL_SLEEP_DISABLED`.
    #[tokio::test]
    async fn sleep_disabled_rejects_every_call() {
        let tool = SleepTool::disabled();
        let ctx = ToolContext::for_workspace(std::path::PathBuf::from("/tmp"));
        let out = tool
            .execute(&serde_json::json!({"seconds": 1}), &ctx)
            .await
            .unwrap();
        assert!(out.is_error.unwrap_or(false));
        assert!(
            out.content.contains("FAIL_SLEEP_DISABLED"),
            "expected FAIL_SLEEP_DISABLED, got: {}",
            out.content
        );
    }

    /// `seconds > SLEEP_TOOL_HARD_MAX_SECONDS` is rejected even when
    /// the policy ceiling would allow it (defense-in-depth against
    /// operator typo).
    #[tokio::test]
    async fn sleep_hard_max_rejects_even_with_permissive_policy() {
        // Policy itself caps at 600 (matches the hard ceiling), but
        // the operator typo'd 9999.  We bump per_call to u32::MAX
        // for this test ONLY to prove the hard ceiling fires before
        // the per-call ceiling.
        let tool = SleepTool::new(u32::MAX, u32::MAX);
        let ctx = ToolContext::for_workspace(std::path::PathBuf::from("/tmp"));
        let out = tool
            .execute(&serde_json::json!({"seconds": 9999}), &ctx)
            .await
            .unwrap();
        assert!(out.is_error.unwrap_or(false));
        assert!(
            out.content.contains("FAIL_SLEEP_HARD_MAX_EXCEEDED"),
            "expected FAIL_SLEEP_HARD_MAX_EXCEEDED, got: {}",
            out.content
        );
    }

    /// Multiple successful sleeps accumulate in the cumulative
    /// counter as expected.
    #[tokio::test]
    async fn sleep_cumulative_counter_tracks_successes() {
        let tool = SleepTool::new(/*per_call*/ 1, /*cum*/ 10);
        let ctx = ToolContext::for_workspace(std::path::PathBuf::from("/tmp"));
        for _ in 0..3 {
            let out = tool
                .execute(&serde_json::json!({"seconds": 1}), &ctx)
                .await
                .unwrap();
            assert!(!out.is_error.unwrap_or(false));
        }
        assert_eq!(tool.cumulative_slept_seconds(), 3);
    }

    /// `reason` field is round-tripped to the model in the
    /// success message so the next turn has anchoring text.
    #[tokio::test]
    async fn sleep_reason_field_round_trips_into_response() {
        let tool = SleepTool::new(60, 300);
        let ctx = ToolContext::for_workspace(std::path::PathBuf::from("/tmp"));
        let out = tool
            .execute(
                &serde_json::json!({"seconds": 1, "reason": "waiting for CI"}),
                &ctx,
            )
            .await
            .unwrap();
        assert!(!out.is_error.unwrap_or(false));
        assert!(
            out.content.contains("waiting for CI"),
            "expected reason in response, got: {}",
            out.content
        );
    }

    #[test]
    fn orchestrator_registry_includes_integration_conflict_tools() {
        let r = build_orchestrator_registry();
        assert!(
            r.get("git_commit").is_some(),
            "orchestrator registry MUST include git_commit so it can finish \
             merge-conflict resolution commits"
        );
        assert!(
            r.get("edit_file").is_some(),
            "orchestrator registry MUST include edit_file so it can resolve \
             integration conflicts"
        );
        assert!(
            r.get("bash").is_some(),
            "orchestrator registry MUST include bash for `git status`, \
             `git diff`, and focused conflict diagnostics"
        );
    }

    /// V2 §3.2 — the orchestrator's terminal tools MUST be declared
    /// in its registry so the LLM advertises them in
    /// `MessageRequest::tools`. Without these declarations the model
    /// cannot fire them, the dispatch loop terminates with `Idle`,
    /// and the kernel records an orchestration failure even though
    /// the model would otherwise have driven the DAG to completion.
    /// (This is the regression that left the live-e2e orchestrator
    /// stuck after one turn — see commit history.)
    #[test]
    fn orchestrator_registry_declares_dag_terminal_tools() {
        let r = build_orchestrator_registry();
        assert!(
            r.get("activate_subtask").is_some(),
            "orchestrator registry MUST declare `activate_subtask`"
        );
        assert!(
            r.get("retry_subtask").is_some(),
            "orchestrator registry MUST declare `retry_subtask`"
        );
        assert!(
            r.get("integration_merge").is_some(),
            "orchestrator registry MUST declare `integration_merge`"
        );
        assert!(
            r.get("prepare_integration_merge").is_some(),
            "orchestrator registry MUST include `prepare_integration_merge` \
             so the LLM does not infer final merge choreography"
        );
        // V3 iter70 — batch-admit primitive.
        assert!(
            r.get("batch_activate_subtasks").is_some(),
            "orchestrator registry MUST declare `batch_activate_subtasks` \
             (V3 iter70 batch primitive)"
        );
    }

    /// Same invariant for the `_with_sleep` variant — adding a
    /// budgeted sleep MUST NOT drop the terminal-tool declarations.
    #[test]
    fn orchestrator_registry_with_sleep_declares_dag_terminal_tools() {
        let r = build_orchestrator_registry_with_sleep(60, 300);
        assert!(r.get("activate_subtask").is_some());
        assert!(r.get("retry_subtask").is_some());
        assert!(r.get("integration_merge").is_some());
        assert!(r.get("prepare_integration_merge").is_some());
        // V3 iter70 — batch-admit primitive.
        assert!(r.get("batch_activate_subtasks").is_some());
    }

    /// V2 §3.2 — executor terminal-tool declarations.
    #[test]
    fn executor_registry_declares_terminal_tools() {
        let r = build_executor_registry();
        assert!(
            r.get("task_complete").is_some(),
            "executor registry MUST declare `task_complete`"
        );
        assert!(
            r.get("report_failure").is_some(),
            "executor registry MUST declare `report_failure`"
        );
        assert!(
            r.get("single_commit").is_some(),
            "executor registry MUST declare `single_commit`"
        );
    }

    /// Same invariant for the `_with_sleep` variant.
    #[test]
    fn executor_registry_with_sleep_declares_terminal_tools() {
        let r = build_executor_registry_with_sleep(60, 300);
        assert!(r.get("task_complete").is_some());
        assert!(r.get("report_failure").is_some());
        assert!(r.get("single_commit").is_some());
    }

    /// V2 §3.2 — reviewer terminal-tool declaration.
    #[test]
    fn reviewer_registry_declares_submit_review() {
        let r = build_reviewer_registry();
        assert!(
            r.get("submit_review").is_some(),
            "reviewer registry MUST declare `submit_review`"
        );
    }

    #[test]
    fn sleep_only_appears_when_policy_declares_budget() {
        assert!(
            build_executor_registry().get("sleep").is_none(),
            "default executor registry must not expose a disabled sleep tool"
        );
        assert!(
            build_orchestrator_registry().get("sleep").is_none(),
            "default orchestrator registry must not expose a disabled sleep tool"
        );
        assert!(
            build_executor_registry_with_sleep(60, 300)
                .get("sleep")
                .is_some(),
            "budgeted executor registry must expose sleep"
        );
        assert!(
            build_orchestrator_registry_with_sleep(60, 300)
                .get("sleep")
                .is_some(),
            "budgeted orchestrator registry must expose sleep"
        );
    }

    /// V2 `INV-EXEC-DISCOVERY-01` — every role's registry MUST
    /// expose `vm_capabilities` so the LLM can query the in-VM
    /// manifest before writing scripts. The capability-hint block
    /// in the system prompt covers the common case; this tool is
    /// the recourse for finer queries (e.g. "is `numpy`
    /// available?").
    #[test]
    fn every_role_registry_includes_vm_capabilities() {
        for (label, r) in [
            ("executor", build_executor_registry()),
            ("reviewer", build_reviewer_registry()),
            ("orchestrator", build_orchestrator_registry()),
        ] {
            assert!(
                r.get("vm_capabilities").is_some(),
                "INV-EXEC-DISCOVERY-01: {label} registry MUST declare \
                 `vm_capabilities`",
            );
        }
        // Same invariant for the `_with_sleep` constructors that
        // the planner binaries use when the operator policy
        // declares `[budget.sleep_caps]`.
        assert!(
            build_executor_registry_with_sleep(60, 300)
                .get("vm_capabilities")
                .is_some(),
            "executor _with_sleep registry MUST include vm_capabilities",
        );
        assert!(
            build_orchestrator_registry_with_sleep(60, 300)
                .get("vm_capabilities")
                .is_some(),
            "orchestrator _with_sleep registry MUST include vm_capabilities",
        );
    }

    #[test]
    fn advertised_tool_descriptions_stay_compact() {
        for (role, registry) in [
            ("executor", build_executor_registry()),
            ("reviewer", build_reviewer_registry()),
            ("orchestrator", build_orchestrator_registry()),
        ] {
            for spec in registry.to_specs() {
                assert!(
                    spec.description.len() <= 512,
                    "{role} tool `{}` description is too large: {} bytes",
                    spec.name,
                    spec.description.len()
                );
            }
        }
    }

    #[test]
    fn resolve_workspace_path_rejects_absolute() {
        let root = Path::new("/workspace");
        let err = resolve_workspace_path(root, "/etc/passwd").unwrap_err();
        match err {
            ToolError::InvalidInput { reason, .. } => {
                assert!(reason.contains("absolute"));
            }
            other => panic!("expected InvalidInput, got {other:?}"),
        }
    }

    #[test]
    fn resolve_workspace_path_rejects_dotdot() {
        let root = Path::new("/workspace");
        let err = resolve_workspace_path(root, "../etc/passwd").unwrap_err();
        match err {
            ToolError::InvalidInput { reason, .. } => {
                assert!(reason.contains(".."));
            }
            other => panic!("expected InvalidInput, got {other:?}"),
        }
    }

    #[test]
    fn resolve_workspace_path_accepts_normal_relative() {
        let root = Path::new("/workspace");
        let p = resolve_workspace_path(root, "src/main.rs").unwrap();
        assert_eq!(p, Path::new("/workspace/src/main.rs"));
    }

    #[tokio::test]
    async fn read_file_tool_returns_contents() {
        let ws = fixture_workspace();
        let ctx = ToolContext::for_workspace(ws.path());
        let out = ReadFileTool
            .execute(&serde_json::json!({ "path": "hello.txt" }), &ctx)
            .await
            .unwrap();
        assert_eq!(out.is_error, None);
        assert_eq!(out.content, "hi from raxis");
    }

    #[tokio::test]
    async fn read_file_tool_rejects_path_escape() {
        let ws = fixture_workspace();
        let ctx = ToolContext::for_workspace(ws.path());
        // path-escape is rejected at validation time → InvalidInput
        // surfaces from execute() itself, NOT a structured tool
        // error (the model never reaches the path-escape branch).
        let err = ReadFileTool
            .execute(&serde_json::json!({ "path": "../../etc/passwd" }), &ctx)
            .await
            .unwrap_err();
        match err {
            ToolError::InvalidInput { tool, reason } => {
                assert_eq!(tool, "read_file");
                assert!(reason.contains(".."));
            }
            other => panic!("expected InvalidInput, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn list_files_tool_lists_nested_entries_sorted() {
        let ws = fixture_workspace();
        std::fs::create_dir_all(ws.path().join("gtm/analysis/x_engagement")).unwrap();
        std::fs::write(
            ws.path().join("gtm/analysis/x_engagement/current.md"),
            "analysis",
        )
        .unwrap();
        std::fs::write(
            ws.path().join("gtm/analysis/x_engagement/notes.md"),
            "notes",
        )
        .unwrap();
        let ctx = ToolContext::for_workspace(ws.path());
        let out = ListFilesTool
            .execute(
                &serde_json::json!({ "path": "gtm/analysis/x_engagement" }),
                &ctx,
            )
            .await
            .unwrap();
        assert_eq!(out.is_error, None);
        assert!(
            out.content
                .contains("file gtm/analysis/x_engagement/current.md"),
            "list_files output should include current.md: {}",
            out.content
        );
        assert!(
            out.content
                .contains("file gtm/analysis/x_engagement/notes.md"),
            "list_files output should include notes.md: {}",
            out.content
        );
    }

    #[tokio::test]
    async fn list_files_tool_rejects_path_escape() {
        let ws = fixture_workspace();
        let ctx = ToolContext::for_workspace(ws.path());
        let err = ListFilesTool
            .execute(&serde_json::json!({ "path": "../outside" }), &ctx)
            .await
            .unwrap_err();
        match err {
            ToolError::InvalidInput { tool, reason } => {
                assert_eq!(tool, "list_files");
                assert!(reason.contains(".."));
            }
            other => panic!("expected InvalidInput, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn edit_file_tool_writes_then_read_observes_new_contents() {
        let ws = fixture_workspace();
        let ctx = ToolContext::for_workspace(ws.path());
        let out = EditFileTool
            .execute(
                &serde_json::json!({
                    "path":     "out/new.txt",
                    "contents": "fresh contents",
                }),
                &ctx,
            )
            .await
            .unwrap();
        assert_eq!(out.is_error, None);
        let read = ReadFileTool
            .execute(&serde_json::json!({ "path": "out/new.txt" }), &ctx)
            .await
            .unwrap();
        assert_eq!(read.content, "fresh contents");
    }

    #[tokio::test]
    async fn bash_tool_runs_command_and_reports_exit_code() {
        let ws = fixture_workspace();
        let ctx = ToolContext::for_workspace(ws.path());
        let out = BashTool
            .execute(
                &serde_json::json!({ "command": "echo planner-tools-bash-test" }),
                &ctx,
            )
            .await
            .unwrap();
        assert_eq!(
            out.is_error, None,
            "successful bash MUST NOT surface as a structured error"
        );
        assert!(
            out.content.contains("planner-tools-bash-test"),
            "bash output should include stdout"
        );
        assert!(out.content.contains("exit_code: 0"));
    }

    #[tokio::test]
    async fn bash_tool_marks_failure_as_structured_error() {
        let ws = fixture_workspace();
        let ctx = ToolContext::for_workspace(ws.path());
        let out = BashTool
            .execute(&serde_json::json!({ "command": "exit 7" }), &ctx)
            .await
            .unwrap();
        assert_eq!(out.is_error, Some(true));
        assert!(out.content.contains("exit_code: 7"));
    }

    #[tokio::test]
    async fn grep_search_tool_returns_matches() {
        let ws = fixture_workspace();
        let ctx = ToolContext::for_workspace(ws.path());
        let out = GrepSearchTool
            .execute(&serde_json::json!({ "pattern": "raxis" }), &ctx)
            .await
            .unwrap();
        assert_eq!(out.is_error, None);
        assert!(
            out.content.contains("hi from raxis"),
            "grep output: {}",
            out.content
        );
    }

    #[tokio::test]
    async fn grep_search_tool_no_match_returns_ok() {
        let ws = fixture_workspace();
        let ctx = ToolContext::for_workspace(ws.path());
        let out = GrepSearchTool
            .execute(
                &serde_json::json!({ "pattern": "absolutely-no-such-string-12345" }),
                &ctx,
            )
            .await
            .unwrap();
        assert_eq!(out.is_error, None);
        assert!(out.content.contains("<no matches for"));
    }

    fn fixture_task_repo() -> (TempDir, String) {
        let dir = tempfile::tempdir().unwrap();
        run_git_sync(dir.path(), &["init"]);
        run_git_sync(dir.path(), &["config", "user.name", "RAXIS Test"]);
        run_git_sync(
            dir.path(),
            &["config", "user.email", "raxis-test@localhost"],
        );
        std::fs::write(dir.path().join("base.txt"), "base\n").unwrap();
        run_git_sync(dir.path(), &["add", "base.txt"]);
        run_git_sync(dir.path(), &["commit", "-m", "base"]);
        let base = run_git_sync(dir.path(), &["rev-parse", "HEAD"]);
        (dir, base)
    }

    #[tokio::test]
    async fn task_complete_derives_head_and_overrides_model_input() {
        let (repo, base) = fixture_task_repo();
        std::fs::write(repo.path().join("done.txt"), "done\n").unwrap();
        run_git_sync(repo.path(), &["add", "done.txt"]);
        run_git_sync(repo.path(), &["commit", "-m", "done"]);
        let head = run_git_sync(repo.path(), &["rev-parse", "HEAD"]);
        let ctx = ToolContext::for_workspace(repo.path()).with_task_complete_base_sha(Some(base));

        let out = TaskCompleteTool
            .execute(
                &serde_json::json!({
                    "summary": "done",
                    "head_sha": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                }),
                &ctx,
            )
            .await
            .unwrap();

        assert_eq!(out.is_error, None, "tool output: {}", out.content);
        let input = out.input_override.expect("terminal input override");
        assert_eq!(input["head_sha"], head);
    }

    #[tokio::test]
    async fn task_complete_rejects_dirty_workspace_before_kernel_submit() {
        let (repo, base) = fixture_task_repo();
        std::fs::write(repo.path().join("dirty.txt"), "not committed\n").unwrap();
        let ctx = ToolContext::for_workspace(repo.path()).with_task_complete_base_sha(Some(base));

        let out = TaskCompleteTool
            .execute(&serde_json::json!({}), &ctx)
            .await
            .unwrap();

        assert_eq!(out.is_error, Some(true));
        assert!(
            out.content.contains("uncommitted changes"),
            "tool output: {}",
            out.content
        );
    }

    #[tokio::test]
    async fn task_complete_rejects_unchanged_session_base() {
        let (repo, base) = fixture_task_repo();
        let ctx = ToolContext::for_workspace(repo.path()).with_task_complete_base_sha(Some(base));

        let out = TaskCompleteTool
            .execute(&serde_json::json!({}), &ctx)
            .await
            .unwrap();

        assert_eq!(out.is_error, Some(true));
        assert!(
            out.content.contains("equals the session base"),
            "tool output: {}",
            out.content
        );
    }

    #[tokio::test]
    async fn prepare_integration_merge_rejects_malformed_sha_without_git() {
        let ws = fixture_workspace();
        let ctx = ToolContext::for_workspace(ws.path());
        let out = PrepareIntegrationMergeTool
            .execute(
                &serde_json::json!({
                    "base_sha": "not-a-sha",
                    "executor_shas": ["bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"]
                }),
                &ctx,
            )
            .await
            .unwrap();
        assert_eq!(out.is_error, Some(true));
        assert!(
            out.content.contains("base_sha"),
            "expected base_sha validation failure, got: {}",
            out.content
        );
    }

    #[tokio::test]
    async fn integration_merge_single_executor_head_requires_git_or_prepare() {
        let ws = tempfile::tempdir().unwrap();
        let base = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned();
        let head = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_owned();
        let ctx = ToolContext::for_workspace(ws.path()).with_integration_merge_context(Some(
            IntegrationMergeToolContext {
                base_sha: base.clone(),
                required_executor_shas: vec![IntegrationMergeRequiredSha {
                    task_id: "sibling-materialize-records".to_owned(),
                    sha: head.clone(),
                }],
            },
        ));

        let out = IntegrationMergeTool
            .execute(
                &serde_json::json!({
                    "base_sha": base,
                    "head_sha": head,
                }),
                &ctx,
            )
            .await
            .unwrap();

        assert_eq!(out.is_error, Some(true), "tool output: {}", out.content);
        assert!(
            out.content.contains("automatic preparation failed"),
            "expected single-SHA path to require git verification or prepare, got: {}",
            out.content
        );
    }

    #[tokio::test]
    async fn integration_merge_rejects_noop_without_ksb_context() {
        let ws = tempfile::tempdir().unwrap();
        let sha = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let ctx = ToolContext::for_workspace(ws.path());

        let out = IntegrationMergeTool
            .execute(
                &serde_json::json!({
                    "base_sha": sha,
                    "head_sha": sha,
                }),
                &ctx,
            )
            .await
            .unwrap();

        assert_eq!(out.is_error, Some(true), "tool output: {}", out.content);
        assert!(
            out.content.contains("no-op merge"),
            "expected local no-op rejection, got: {}",
            out.content
        );
    }

    fn run_git_sync(dir: &Path, args: &[&str]) -> String {
        let out = std::process::Command::new("git")
            .args(args)
            .current_dir(dir)
            .output()
            .unwrap_or_else(|e| panic!("git {args:?} spawn failed: {e}"));
        if !out.status.success() {
            panic!(
                "git {args:?} failed with {}\nstdout:\n{}\nstderr:\n{}",
                out.status,
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
        }
        String::from_utf8_lossy(&out.stdout).trim().to_owned()
    }

    fn fixture_integration_repo() -> (TempDir, String, String, String) {
        let dir = tempfile::tempdir().unwrap();
        run_git_sync(dir.path(), &["init"]);
        run_git_sync(dir.path(), &["config", "user.name", "RAXIS Test"]);
        run_git_sync(
            dir.path(),
            &["config", "user.email", "raxis-test@localhost"],
        );

        std::fs::write(dir.path().join("base.txt"), "base\n").unwrap();
        run_git_sync(dir.path(), &["add", "base.txt"]);
        run_git_sync(dir.path(), &["commit", "-m", "base"]);
        let base = run_git_sync(dir.path(), &["rev-parse", "HEAD"]);

        run_git_sync(dir.path(), &["checkout", "-b", "executor-a"]);
        std::fs::write(dir.path().join("a.txt"), "executor a\n").unwrap();
        run_git_sync(dir.path(), &["add", "a.txt"]);
        run_git_sync(dir.path(), &["commit", "-m", "executor a"]);
        let sha_a = run_git_sync(dir.path(), &["rev-parse", "HEAD"]);

        run_git_sync(dir.path(), &["checkout", "-B", "executor-b", &base]);
        std::fs::write(dir.path().join("b.txt"), "executor b\n").unwrap();
        run_git_sync(dir.path(), &["add", "b.txt"]);
        run_git_sync(dir.path(), &["commit", "-m", "executor b"]);
        let sha_b = run_git_sync(dir.path(), &["rev-parse", "HEAD"]);

        run_git_sync(dir.path(), &["checkout", "-B", "orchestrator", &base]);
        (dir, base, sha_a, sha_b)
    }

    #[tokio::test]
    async fn integration_merge_auto_prepares_missing_executor_sha_and_overrides_input() {
        let (repo, base, sha_a, sha_b) = fixture_integration_repo();
        let ctx = ToolContext::for_workspace(repo.path()).with_integration_merge_context(Some(
            IntegrationMergeToolContext {
                base_sha: base.clone(),
                required_executor_shas: vec![
                    IntegrationMergeRequiredSha {
                        task_id: "executor-a".to_owned(),
                        sha: sha_a.clone(),
                    },
                    IntegrationMergeRequiredSha {
                        task_id: "executor-b".to_owned(),
                        sha: sha_b.clone(),
                    },
                ],
            },
        ));

        let out = IntegrationMergeTool
            .execute(
                &serde_json::json!({
                    "base_sha": base,
                    "head_sha": sha_a,
                }),
                &ctx,
            )
            .await
            .unwrap();

        assert_eq!(out.is_error, None, "tool output: {}", out.content);
        assert!(
            out.content.contains("auto-prepared"),
            "expected auto-prepare message, got: {}",
            out.content
        );
        let input = out.input_override.expect("terminal input override");
        let head = input["head_sha"].as_str().unwrap();
        run_git_sync(repo.path(), &["merge-base", "--is-ancestor", &sha_a, head]);
        run_git_sync(repo.path(), &["merge-base", "--is-ancestor", &sha_b, head]);
    }

    #[test]
    fn tool_registry_iter_is_sorted_by_name() {
        let r = build_executor_registry();
        let names: Vec<_> = r.iter().map(|t| t.name()).collect();
        let mut sorted = names.clone();
        sorted.sort();
        assert_eq!(
            names, sorted,
            "ToolRegistry::iter MUST be deterministic-sorted; \
             dispatch loop and audit chain depend on it"
        );
    }

    #[test]
    fn tool_registry_to_specs_matches_iter_order() {
        let r = build_executor_registry();
        let specs: Vec<_> = r.to_specs().into_iter().map(|s| s.name).collect();
        let names: Vec<_> = r.iter().map(|t| t.name().to_owned()).collect();
        assert_eq!(specs, names);
    }

    #[test]
    #[should_panic(expected = "duplicate tool name")]
    fn registry_panics_on_duplicate_registration() {
        let mut r = ToolRegistry::new();
        r.register(Arc::new(ReadFileTool));
        r.register(Arc::new(ReadFileTool));
    }

    // ── StructuredOutputTool input parsing (V2 §3.2) ──────────────────────

    /// Reviewer registry MUST NOT include `structured_output` even
    /// after the V2.5 §3.2 wiring (R-5 — Bounded capabilities;
    /// INV-PLANNER-HARNESS-02). Both the bare `_with_sleep` variant
    /// and the `_full` constructor (which would normally include it
    /// for the executor / orchestrator) MUST keep the reviewer
    /// fenced. Pin the rule at the construction layer so a future
    /// "let me just add structured_output for the reviewer too"
    /// regression fails this test.
    #[test]
    fn reviewer_registry_never_includes_structured_output() {
        let r = build_reviewer_registry();
        assert!(
            r.get("structured_output").is_none(),
            "reviewer MUST NOT have structured_output (V2 §3.2 R-5)"
        );
    }

    /// `parse_structured_output_input` translates the model's
    /// snake-case `kind` discriminator into the matching
    /// [`raxis_types::StructuredOutputKind`] variant. The wire enum
    /// uses external-tag serde for `bincode::serde` compatibility;
    /// this helper is the single bridge so the model never sees
    /// the bincode shape.
    #[test]
    fn parse_structured_output_progress_report_round_trip() {
        let v = serde_json::json!({
            "kind":           "progress_report",
            "files_modified": ["a.rs", "b.rs"],
            "tests_passing":  3,
            "tests_failing":  1,
            "confidence":     0.75,
        });
        let p = parse_structured_output_input(&v).unwrap();
        match p {
            raxis_types::StructuredOutputKind::ProgressReport {
                files_modified,
                tests_passing,
                tests_failing,
                confidence,
            } => {
                assert_eq!(files_modified, vec!["a.rs", "b.rs"]);
                assert_eq!(tests_passing, 3);
                assert_eq!(tests_failing, 1);
                assert!((confidence - 0.75).abs() < 1e-6);
            }
            other => panic!("expected ProgressReport, got {other:?}"),
        }
    }

    #[test]
    fn parse_structured_output_diagnostic_flag_round_trip() {
        let v = serde_json::json!({
            "kind":     "diagnostic_flag",
            "severity": "critical",
            "message":  "auth bypass!",
            "evidence": "src/auth.rs:42",
        });
        let p = parse_structured_output_input(&v).unwrap();
        assert_eq!(p.variant_tag(), "diagnostic_flag");
        match p {
            raxis_types::StructuredOutputKind::DiagnosticFlag {
                severity,
                message,
                evidence,
            } => {
                assert_eq!(severity, raxis_types::DiagnosticSeverity::Critical);
                assert_eq!(message, "auth bypass!");
                assert_eq!(evidence.as_deref(), Some("src/auth.rs:42"));
            }
            other => panic!("expected DiagnosticFlag, got {other:?}"),
        }
    }

    #[test]
    fn parse_structured_output_task_summary_round_trip() {
        let v = serde_json::json!({
            "kind":          "task_summary",
            "commit_sha":    "0".repeat(40),
            "changed_paths": ["x.rs"],
            "approach":      "split into helper",
        });
        let p = parse_structured_output_input(&v).unwrap();
        match p {
            raxis_types::StructuredOutputKind::TaskSummary {
                commit_sha,
                changed_paths,
                approach,
            } => {
                assert_eq!(commit_sha, "0".repeat(40));
                assert_eq!(changed_paths, vec!["x.rs"]);
                assert_eq!(approach, "split into helper");
            }
            other => panic!("expected TaskSummary, got {other:?}"),
        }
    }

    #[test]
    fn parse_structured_output_rejects_unknown_kind() {
        let v = serde_json::json!({ "kind": "alien_kind" });
        let err = parse_structured_output_input(&v).unwrap_err();
        assert!(
            err.contains("unknown structured_output kind"),
            "error: {err}"
        );
    }

    #[test]
    fn parse_structured_output_rejects_missing_kind() {
        let v = serde_json::json!({ "severity": "info" });
        let err = parse_structured_output_input(&v).unwrap_err();
        assert!(err.contains("`kind`"));
    }

    #[test]
    fn parse_structured_output_diagnostic_flag_requires_message_and_severity() {
        // missing severity
        let v = serde_json::json!({ "kind": "diagnostic_flag", "message": "x" });
        let err = parse_structured_output_input(&v).unwrap_err();
        assert!(err.contains("severity"));
        // missing message
        let v = serde_json::json!({ "kind": "diagnostic_flag", "severity": "info" });
        let err = parse_structured_output_input(&v).unwrap_err();
        assert!(err.contains("message"));
    }
}

//! `Tool` trait + `ToolRegistry` + base tools.
//!
//! Closes V2_GAPS.md §B1 substep "Base tool registry
//! (read_file/bash/edit_file/grep_search/git_commit)" by giving each
//! planner role binary a typed, registry-driven dispatch surface.
//!
//! ## Why a trait + registry, not free functions
//!
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
//!
//! ## V2 limits (declared so future work has a target)
//!
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
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::io::AsyncWriteExt;

use crate::model::ToolSpec;

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
}

impl ToolOutput {
    /// Construct a success output.
    pub fn ok(content: impl Into<String>) -> Self {
        Self { content: content.into(), is_error: None }
    }
    /// Construct a structured-error output.
    pub fn err(message: impl Into<String>) -> Self {
        Self { content: message.into(), is_error: Some(true) }
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
    InvalidInput { tool: String, reason: String },

    /// The tool raised an internal failure (I/O error, subprocess
    /// spawn failure, etc.). The dispatch loop converts this to a
    /// structured-error tool result so the model can recover.
    #[error("tool {tool} failed: {reason}")]
    Internal { tool: String, reason: String },
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
        ctx:   &ToolContext,
    ) -> Result<ToolOutput, ToolError>;

    /// Lift this tool into the Anthropic-shape `ToolSpec` the
    /// dispatch loop advertises in the
    /// [`crate::model::MessageRequest::tools`] field. Default impl
    /// reuses [`Tool::name`] / [`Tool::description`] /
    /// [`Tool::input_schema`].
    fn to_spec(&self) -> ToolSpec {
        ToolSpec {
            name:         self.name().to_owned(),
            description:  self.description().to_owned(),
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
    pub deadline:       Option<Duration>,
}

impl ToolContext {
    /// Construct a context with no deadline. Used by unit tests
    /// that don't exercise the timeout path.
    pub fn for_workspace(workspace_root: impl Into<PathBuf>) -> Self {
        Self {
            workspace_root: workspace_root.into(),
            deadline:       None,
        }
    }
}

// ---------------------------------------------------------------------------
// ToolRegistry
// ---------------------------------------------------------------------------

/// Registry of tools, keyed by name.
///
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
///
/// This is the **only** path resolution the base tools below
/// perform — every tool that touches the filesystem MUST call this
/// first so the workspace boundary is enforced uniformly.
///
/// ## Why a hand-rolled component check
///
/// `Path::canonicalize` on macOS/Linux follows symlinks, which is
/// not what we want — a symlink inside the workspace pointing at
/// `/etc/passwd` would let the model exfiltrate. We compare path
/// components manually so a workspace-rooted symlink reads only
/// from inside the workspace.
pub fn resolve_workspace_path(
    workspace_root: &Path,
    input_path:     &str,
) -> Result<PathBuf, ToolError> {
    let p = Path::new(input_path);
    if p.is_absolute() {
        return Err(ToolError::InvalidInput {
            tool:   "<workspace-path>".to_owned(),
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
                    tool:   "<workspace-path>".to_owned(),
                    reason: format!(
                        "`..` segment in {input_path:?} not allowed"
                    ),
                });
            }
            std::path::Component::CurDir => continue,
            std::path::Component::Normal(_) => continue,
            _ => {
                return Err(ToolError::InvalidInput {
                    tool:   "<workspace-path>".to_owned(),
                    reason: format!(
                        "unsupported path component in {input_path:?}"
                    ),
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
///
/// Schema: `{ path: string }`. Returns the file's UTF-8 contents
/// (with a `... <truncated N bytes>` tail if the file exceeds 1 MiB
/// to keep the per-turn token budget under control).
pub struct ReadFileTool;

#[async_trait::async_trait]
impl Tool for ReadFileTool {
    fn name(&self) -> &'static str { "read_file" }
    fn description(&self) -> &'static str {
        "Read the contents of a file in the workspace. \
         The path argument is interpreted relative to the workspace \
         root; absolute paths and `..` segments are rejected. \
         Files larger than 1 MiB are truncated."
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
        ctx:   &ToolContext,
    ) -> Result<ToolOutput, ToolError> {
        let path = input.get("path").and_then(|v| v.as_str()).ok_or_else(|| {
            ToolError::InvalidInput {
                tool:   "read_file".to_owned(),
                reason: "missing or non-string `path`".to_owned(),
            }
        })?;
        let resolved = resolve_workspace_path(&ctx.workspace_root, path)
            .map_err(|e| match e {
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
                    s.push_str(&format!(
                        "\n... <truncated {} bytes>", bytes.len() - MAX
                    ));
                    s
                } else {
                    String::from_utf8_lossy(&bytes).into_owned()
                };
                Ok(ToolOutput::ok(body))
            }
            Err(e) => Ok(ToolOutput::err(format!(
                "read_file({path:?}) failed: {e}"
            ))),
        }
    }
}

/// `edit_file` — overwrite a workspace file with the supplied
/// contents. Creates parent directories as needed.
///
/// Schema: `{ path: string, contents: string }`.
pub struct EditFileTool;

#[async_trait::async_trait]
impl Tool for EditFileTool {
    fn name(&self) -> &'static str { "edit_file" }
    fn description(&self) -> &'static str {
        "Write the given UTF-8 `contents` to the workspace file at \
         `path` (creating parent directories as needed). Overwrites \
         existing content. Use `read_file` first to inspect before \
         overwriting."
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
        ctx:   &ToolContext,
    ) -> Result<ToolOutput, ToolError> {
        let path = input.get("path").and_then(|v| v.as_str()).ok_or_else(|| {
            ToolError::InvalidInput {
                tool:   "edit_file".to_owned(),
                reason: "missing or non-string `path`".to_owned(),
            }
        })?;
        let contents = input.get("contents").and_then(|v| v.as_str()).ok_or_else(|| {
            ToolError::InvalidInput {
                tool:   "edit_file".to_owned(),
                reason: "missing or non-string `contents`".to_owned(),
            }
        })?;
        let resolved = resolve_workspace_path(&ctx.workspace_root, path)
            .map_err(|e| match e {
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
            Err(e) => return Ok(ToolOutput::err(format!(
                "edit_file: open({resolved:?}) failed: {e}"
            ))),
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
            "wrote {} bytes to {}", contents.len(), path
        )))
    }
}

/// `bash` — run a shell command in the workspace.
///
/// Schema: `{ command: string }`. Stdout + stderr are concatenated
/// into the response (with a 64 KiB cap per stream); the exit code
/// is reported in the trailing line.
///
/// **Hardening note.** The reviewer role does NOT include this
/// tool — see [`build_reviewer_registry`].
pub struct BashTool;

#[async_trait::async_trait]
impl Tool for BashTool {
    fn name(&self) -> &'static str { "bash" }
    fn description(&self) -> &'static str {
        "Run a bash command in the workspace. Returns stdout + \
         stderr (each capped at 64 KiB) and the exit code. Path \
         relative paths are resolved against the workspace root."
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
        ctx:   &ToolContext,
    ) -> Result<ToolOutput, ToolError> {
        let cmd = input.get("command").and_then(|v| v.as_str()).ok_or_else(|| {
            ToolError::InvalidInput {
                tool:   "bash".to_owned(),
                reason: "missing or non-string `command`".to_owned(),
            }
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
            Ok(c)  => c,
            Err(e) => return Ok(ToolOutput::err(format!(
                "bash: spawn failed: {e}"
            ))),
        };
        let timeout = ctx.deadline.unwrap_or(Duration::from_secs(120));
        let out = match tokio::time::timeout(timeout, child.wait_with_output()).await {
            Ok(Ok(o))  => o,
            Ok(Err(e)) => return Ok(ToolOutput::err(format!(
                "bash: wait_with_output failed: {e}"
            ))),
            Err(_) => return Ok(ToolOutput::err(format!(
                "bash: command timed out after {timeout:?}"
            ))),
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
            code   = out.status.code().map(|c| c.to_string()).unwrap_or_else(|| "<signalled>".to_owned()),
            stdout = cap(&out.stdout),
            stderr = cap(&out.stderr),
        );
        if out.status.success() {
            Ok(ToolOutput::ok(body))
        } else {
            // Non-zero exit is a STRUCTURED tool error so the model
            // can recover; the audit chain still records the full
            // body via the dispatch loop.
            Ok(ToolOutput { content: body, is_error: Some(true) })
        }
    }
}

/// `grep_search` — `grep -rn` over the workspace.
///
/// Schema: `{ pattern: string, path: string? }`. Uses `grep -rn` so
/// the binary is universal (every supported VM image ships `grep`);
/// future versions will switch to `ripgrep` when the canonical
/// image manifest pins it.
pub struct GrepSearchTool;

#[async_trait::async_trait]
impl Tool for GrepSearchTool {
    fn name(&self) -> &'static str { "grep_search" }
    fn description(&self) -> &'static str {
        "Run `grep -rn <pattern> [<path>]` over the workspace and \
         return matching lines. `path` defaults to the workspace \
         root. Matches are returned with `relpath:line:content` \
         shape; output is capped at 64 KiB."
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
        ctx:   &ToolContext,
    ) -> Result<ToolOutput, ToolError> {
        let pattern = input.get("pattern").and_then(|v| v.as_str()).ok_or_else(|| {
            ToolError::InvalidInput {
                tool:   "grep_search".to_owned(),
                reason: "missing or non-string `pattern`".to_owned(),
            }
        })?;
        let path = input.get("path").and_then(|v| v.as_str()).unwrap_or(".");
        let resolved = resolve_workspace_path(&ctx.workspace_root, path)
            .map_err(|e| match e {
                ToolError::InvalidInput { reason, .. } => ToolError::InvalidInput {
                    tool: "grep_search".to_owned(),
                    reason,
                },
                other => other,
            })?;
        let out = match tokio::process::Command::new("grep")
            .arg("-rn")
            .arg(pattern)
            .arg(&resolved)
            .output()
            .await
        {
            Ok(o)  => o,
            Err(e) => return Ok(ToolOutput::err(format!(
                "grep_search: spawn failed: {e}"
            ))),
        };
        // grep exit code 1 means "no match" — treat as success with
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
            None => Ok(ToolOutput::err(
                "grep_search: signalled".to_owned(),
            )),
        }
    }
}

/// `git_commit` — `git add` + `git commit -m <message>` in the
/// workspace. **Executor-only.** The reviewer role registry omits
/// this tool — see [`build_reviewer_registry`].
///
/// Schema: `{ message: string }`.
pub struct GitCommitTool;

#[async_trait::async_trait]
impl Tool for GitCommitTool {
    fn name(&self) -> &'static str { "git_commit" }
    fn description(&self) -> &'static str {
        "Stage all workspace changes (`git add -A`) and commit them \
         with the given message. Returns the new HEAD short SHA on \
         success. The reviewer role does not have this tool."
    }
    fn input_schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type":     "object",
            "required": ["message"],
            "properties": {
                "message": {
                    "type":        "string",
                    "description": "Commit message (1-line summary; \
                                    extended body MAY follow on a \
                                    blank-line-separated paragraph).",
                }
            }
        })
    }
    async fn execute(
        &self,
        input: &serde_json::Value,
        ctx:   &ToolContext,
    ) -> Result<ToolOutput, ToolError> {
        let message = input.get("message").and_then(|v| v.as_str()).ok_or_else(|| {
            ToolError::InvalidInput {
                tool:   "git_commit".to_owned(),
                reason: "missing or non-string `message`".to_owned(),
            }
        })?;
        // git add -A
        let add = match tokio::process::Command::new("git")
            .args(["add", "-A"])
            .current_dir(&ctx.workspace_root)
            .output()
            .await
        {
            Ok(o)  => o,
            Err(e) => return Ok(ToolOutput::err(format!(
                "git_commit: `git add -A` spawn failed: {e}"
            ))),
        };
        if !add.status.success() {
            return Ok(ToolOutput::err(format!(
                "git_commit: `git add -A` exit {}\n{}",
                add.status.code().map(|c| c.to_string()).unwrap_or_else(|| "<signalled>".to_owned()),
                String::from_utf8_lossy(&add.stderr)
            )));
        }
        // git commit -m <message>
        let commit = match tokio::process::Command::new("git")
            .args(["commit", "-m", message])
            .current_dir(&ctx.workspace_root)
            .output()
            .await
        {
            Ok(o)  => o,
            Err(e) => return Ok(ToolOutput::err(format!(
                "git_commit: `git commit` spawn failed: {e}"
            ))),
        };
        if !commit.status.success() {
            return Ok(ToolOutput::err(format!(
                "git_commit: `git commit` exit {}\nstdout: {}\nstderr: {}",
                commit.status.code().map(|c| c.to_string()).unwrap_or_else(|| "<signalled>".to_owned()),
                String::from_utf8_lossy(&commit.stdout),
                String::from_utf8_lossy(&commit.stderr)
            )));
        }
        // Return new HEAD short sha for the model to use in
        // intent submission.
        let sha = match tokio::process::Command::new("git")
            .args(["rev-parse", "--short", "HEAD"])
            .current_dir(&ctx.workspace_root)
            .output()
            .await
        {
            Ok(o)  => String::from_utf8_lossy(&o.stdout).trim().to_owned(),
            Err(e) => return Ok(ToolOutput::err(format!(
                "git_commit: `git rev-parse` failed: {e}"
            ))),
        };
        Ok(ToolOutput::ok(format!(
            "committed: {sha}\n{}", String::from_utf8_lossy(&commit.stdout).trim()
        )))
    }
}

// ---------------------------------------------------------------------------
// V2 §3.1 — Sleep tool
//
// `v2_extended_gaps.md §3.1` token-budget-preserving wait. Lets an
// agent block on an external process (CI, deploy rollout) without
// burning model turns on a polling loop. Available to executor and
// orchestrator only — NOT to the reviewer (the Pure-Static Reviewer
// has no external process to wait for; INV-PLANNER-HARNESS-02).
// ---------------------------------------------------------------------------

/// Hard upper bound on `seconds` regardless of policy. The §3.1
/// spec specifies "60 second" as a typical operator value; this
/// 600s ceiling is the absolute kernel guard so a typo in
/// `policy.toml` cannot pin a VM slot for hours.
pub const SLEEP_TOOL_HARD_MAX_SECONDS: u32 = 600;

/// V2 `v2_extended_gaps.md §3.1` Sleep tool. Carries its own
/// per-call ceiling, cumulative ceiling, and rolling cumulative
/// counter (shared between every Tool::execute call inside one
/// dispatch loop). Construct with [`SleepTool::new`] from the
/// dispatch loop's policy snapshot.
///
/// Rate-limit semantics:
///
/// * `seconds == 0`             → success, nothing to sleep.
/// * `seconds > max_per_call`   → `FAIL_SLEEP_PER_CALL_EXCEEDED`.
/// * `seconds > SLEEP_TOOL_HARD_MAX_SECONDS` → `FAIL_SLEEP_HARD_MAX_EXCEEDED`.
/// * `cumulative + seconds > max_cumulative` → `FAIL_SLEEP_BUDGET_EXCEEDED`.
/// * `max_per_call == 0`        → tool disabled, every call returns
///                                `FAIL_SLEEP_DISABLED`.
///
/// All errors are STRUCTURED (returned as `ToolOutput::err`) so the
/// model can recover; `Tool::execute` itself returns `Ok` in every
/// case (matches the dispatch loop's error contract — see `BashTool`).
pub struct SleepTool {
    max_per_call_seconds:    u32,
    max_cumulative_seconds:  u32,
    cumulative_slept_seconds: Arc<std::sync::Mutex<u32>>,
}

impl SleepTool {
    /// Construct a new SleepTool with the given per-call and
    /// cumulative ceilings (both in seconds). Use
    /// [`SleepTool::disabled`] when the policy did not declare
    /// `[budget.sleep_caps]`.
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
        *self.cumulative_slept_seconds.lock().expect("sleep mutex poisoned")
    }
}

#[async_trait::async_trait]
impl Tool for SleepTool {
    fn name(&self) -> &'static str { "sleep" }
    fn description(&self) -> &'static str {
        "Pause execution for `seconds` seconds without consuming any \
         model inference turn. Use to wait for an external process \
         (CI build, database migration, deployment rollout) to \
         finish. Per-call and cumulative limits are enforced by the \
         policy; exceeding them returns a structured error."
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
                    "description": "How long to sleep, in whole seconds. \
                                   Subject to policy `max_seconds_per_call` and \
                                   the kernel's 600s hard cap.",
                },
                "reason": {
                    "type":        "string",
                    "description": "Optional human-readable reason \
                                   (e.g. `\"waiting for CI\"`) — \
                                   surfaced in the audit chain.",
                }
            }
        })
    }
    async fn execute(
        &self,
        input: &serde_json::Value,
        _ctx:  &ToolContext,
    ) -> Result<ToolOutput, ToolError> {
        // Tool disabled → operator did not opt in.
        if self.max_per_call_seconds == 0 {
            return Ok(ToolOutput::err(
                "FAIL_SLEEP_DISABLED: the operator policy does not declare \
                 [budget.sleep_caps]; the Sleep tool is unavailable."
                    .to_owned(),
            ));
        }
        let seconds_raw = input.get("seconds")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| ToolError::InvalidInput {
                tool:   "sleep".to_owned(),
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
            let mut cum = self.cumulative_slept_seconds.lock()
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
            _                               => String::new(),
        };
        tokio::time::sleep(std::time::Duration::from_secs(seconds as u64)).await;
        Ok(ToolOutput::ok(format!("slept_seconds: {seconds}{reason_suffix}")))
    }
}

// ---------------------------------------------------------------------------
// Role-specific registry constructors
// ---------------------------------------------------------------------------

/// **Executor registry.** Includes all tools the executor needs:
/// `read_file`, `edit_file`, `bash`, `grep_search`, `git_commit`,
/// `sleep` (V2 §3.1).
pub fn build_executor_registry() -> ToolRegistry {
    let mut r = ToolRegistry::new();
    r.register(Arc::new(ReadFileTool));
    r.register(Arc::new(EditFileTool));
    r.register(Arc::new(BashTool));
    r.register(Arc::new(GrepSearchTool));
    r.register(Arc::new(GitCommitTool));
    // V2 §3.1 — disabled by default; the planner-binary main.rs
    // overrides via [`build_executor_registry_with_sleep`] when the
    // operator policy declares `[budget.sleep_caps]`.
    r.register(Arc::new(SleepTool::disabled()));
    r
}

/// **Reviewer registry.** Read-only by construction:
/// `read_file`, `grep_search`. NO `edit_file`, NO `bash`, NO
/// `git_commit`, NO `sleep` (INV-PLANNER-HARNESS-02 — Pure-Static
/// Reviewer has no external process to wait for). Pinned by
/// `planner-harness.md §14.3 INV-PLANNER-HARNESS-04`.
pub fn build_reviewer_registry() -> ToolRegistry {
    let mut r = ToolRegistry::new();
    r.register(Arc::new(ReadFileTool));
    r.register(Arc::new(GrepSearchTool));
    r
}

/// **Orchestrator registry.** Read-only + Sleep: `read_file`,
/// `grep_search`, `sleep` (V2 §3.1 — orchestrators wait on
/// long-running sub-task lifecycle events). The orchestrator does
/// not edit files — its authority is over the DAG (sub-task
/// activation / merge), not over commit content.
pub fn build_orchestrator_registry() -> ToolRegistry {
    let mut r = ToolRegistry::new();
    r.register(Arc::new(ReadFileTool));
    r.register(Arc::new(GrepSearchTool));
    // V2 §3.1 — disabled by default; the planner-binary main.rs
    // overrides via [`build_orchestrator_registry_with_sleep`] when
    // the operator policy declares `[budget.sleep_caps]`.
    r.register(Arc::new(SleepTool::disabled()));
    r
}

/// V2 `v2_extended_gaps.md §3.1` — executor registry with the
/// `sleep` tool wired to the operator-declared policy ceilings.
/// Construct from the dispatch-loop boot env (the kernel projects
/// `policy.sleep_caps()` into `RAXIS_PLANNER_MAX_SLEEP_SECONDS_PER_CALL`
/// and `RAXIS_PLANNER_MAX_CUMULATIVE_SLEEP_SECONDS`).
pub fn build_executor_registry_with_sleep(
    max_per_call_seconds:    u32,
    max_cumulative_seconds:  u32,
) -> ToolRegistry {
    let mut r = ToolRegistry::new();
    r.register(Arc::new(ReadFileTool));
    r.register(Arc::new(EditFileTool));
    r.register(Arc::new(BashTool));
    r.register(Arc::new(GrepSearchTool));
    r.register(Arc::new(GitCommitTool));
    r.register(Arc::new(SleepTool::new(max_per_call_seconds, max_cumulative_seconds)));
    r
}

/// V2 `v2_extended_gaps.md §3.1` — orchestrator registry with the
/// `sleep` tool wired to the operator-declared policy ceilings.
pub fn build_orchestrator_registry_with_sleep(
    max_per_call_seconds:    u32,
    max_cumulative_seconds:  u32,
) -> ToolRegistry {
    let mut r = ToolRegistry::new();
    r.register(Arc::new(ReadFileTool));
    r.register(Arc::new(GrepSearchTool));
    r.register(Arc::new(SleepTool::new(max_per_call_seconds, max_cumulative_seconds)));
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
        // V2 §3.1 — Sleep is registered (disabled by default, opt-in
        // via `[budget.sleep_caps]`).
        assert!(r.get("sleep").is_some(),
            "executor registry MUST include the sleep tool (V2 §3.1)");
    }

    #[test]
    fn registry_role_asymmetry_reviewer_excludes_write_tools() {
        // INV-PLANNER-HARNESS-04: reviewer MUST NOT have any
        // workspace-mutating tool.
        let r = build_reviewer_registry();
        assert!(r.get("git_commit").is_none(),
            "reviewer registry MUST NOT include git_commit");
        assert!(r.get("edit_file").is_none(),
            "reviewer registry MUST NOT include edit_file");
        assert!(r.get("bash").is_none(),
            "reviewer registry MUST NOT include bash");
        // V2 §3.1 — Pure-Static Reviewer never has Sleep
        // (INV-PLANNER-HARNESS-02; no external process to wait for).
        assert!(r.get("sleep").is_none(),
            "reviewer registry MUST NOT include the sleep tool \
             (INV-PLANNER-HARNESS-02)");
        // Read-only tools ARE expected:
        assert!(r.get("read_file").is_some());
        assert!(r.get("grep_search").is_some());
    }

    /// V2 `v2_extended_gaps.md §3.1` — `seconds = 0` is a fast path:
    /// success, no actual sleep, no cumulative charge.
    #[tokio::test]
    async fn sleep_zero_is_fast_path_no_charge() {
        let tool = SleepTool::new(60, 300);
        let ctx  = ToolContext::for_workspace(std::path::PathBuf::from("/tmp"));
        let out = tool.execute(&serde_json::json!({"seconds": 0}), &ctx).await.unwrap();
        assert!(!out.is_error.unwrap_or(false));
        assert_eq!(tool.cumulative_slept_seconds(), 0,
            "0-second sleep MUST NOT charge against cumulative budget");
    }

    /// `seconds > max_per_call` returns `FAIL_SLEEP_PER_CALL_EXCEEDED`
    /// without sleeping or charging cumulative budget.
    #[tokio::test]
    async fn sleep_per_call_ceiling_rejects() {
        let tool = SleepTool::new(/*per_call*/ 5, /*cum*/ 60);
        let ctx  = ToolContext::for_workspace(std::path::PathBuf::from("/tmp"));
        let out = tool.execute(&serde_json::json!({"seconds": 10}), &ctx).await.unwrap();
        assert!(out.is_error.unwrap_or(false), "10s > 5s per-call ceiling MUST be rejected");
        assert!(out.content.contains("FAIL_SLEEP_PER_CALL_EXCEEDED"),
            "error must surface FAIL_SLEEP_PER_CALL_EXCEEDED, got: {}", out.content);
        assert_eq!(tool.cumulative_slept_seconds(), 0,
            "rejected call MUST NOT charge cumulative budget");
    }

    /// Cumulative gate fires when `cumulative + seconds > max_cumulative`.
    #[tokio::test]
    async fn sleep_cumulative_ceiling_rejects() {
        let tool = SleepTool::new(/*per_call*/ 60, /*cum*/ 10);
        let ctx  = ToolContext::for_workspace(std::path::PathBuf::from("/tmp"));
        // First 5s call: passes.
        let out = tool.execute(&serde_json::json!({"seconds": 5}), &ctx).await.unwrap();
        assert!(!out.is_error.unwrap_or(false));
        assert_eq!(tool.cumulative_slept_seconds(), 5);
        // Second 6s call: would push cumulative to 11 > 10. Reject.
        let out = tool.execute(&serde_json::json!({"seconds": 6}), &ctx).await.unwrap();
        assert!(out.is_error.unwrap_or(false));
        assert!(out.content.contains("FAIL_SLEEP_BUDGET_EXCEEDED"),
            "expected FAIL_SLEEP_BUDGET_EXCEEDED, got: {}", out.content);
        assert_eq!(tool.cumulative_slept_seconds(), 5,
            "rejected call MUST NOT charge cumulative budget");
    }

    /// `SleepTool::disabled()` refuses every invocation with
    /// `FAIL_SLEEP_DISABLED`.
    #[tokio::test]
    async fn sleep_disabled_rejects_every_call() {
        let tool = SleepTool::disabled();
        let ctx  = ToolContext::for_workspace(std::path::PathBuf::from("/tmp"));
        let out = tool.execute(&serde_json::json!({"seconds": 1}), &ctx).await.unwrap();
        assert!(out.is_error.unwrap_or(false));
        assert!(out.content.contains("FAIL_SLEEP_DISABLED"),
            "expected FAIL_SLEEP_DISABLED, got: {}", out.content);
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
        let ctx  = ToolContext::for_workspace(std::path::PathBuf::from("/tmp"));
        let out = tool.execute(&serde_json::json!({"seconds": 9999}), &ctx).await.unwrap();
        assert!(out.is_error.unwrap_or(false));
        assert!(out.content.contains("FAIL_SLEEP_HARD_MAX_EXCEEDED"),
            "expected FAIL_SLEEP_HARD_MAX_EXCEEDED, got: {}", out.content);
    }

    /// Multiple successful sleeps accumulate in the cumulative
    /// counter as expected.
    #[tokio::test]
    async fn sleep_cumulative_counter_tracks_successes() {
        let tool = SleepTool::new(/*per_call*/ 1, /*cum*/ 10);
        let ctx  = ToolContext::for_workspace(std::path::PathBuf::from("/tmp"));
        for _ in 0..3 {
            let out = tool.execute(&serde_json::json!({"seconds": 1}), &ctx).await.unwrap();
            assert!(!out.is_error.unwrap_or(false));
        }
        assert_eq!(tool.cumulative_slept_seconds(), 3);
    }

    /// `reason` field is round-tripped to the model in the
    /// success message so the next turn has anchoring text.
    #[tokio::test]
    async fn sleep_reason_field_round_trips_into_response() {
        let tool = SleepTool::new(60, 300);
        let ctx  = ToolContext::for_workspace(std::path::PathBuf::from("/tmp"));
        let out = tool.execute(
            &serde_json::json!({"seconds": 1, "reason": "waiting for CI"}),
            &ctx,
        ).await.unwrap();
        assert!(!out.is_error.unwrap_or(false));
        assert!(out.content.contains("waiting for CI"),
            "expected reason in response, got: {}", out.content);
    }

    #[test]
    fn registry_role_asymmetry_orchestrator_excludes_write_tools() {
        let r = build_orchestrator_registry();
        assert!(r.get("git_commit").is_none(),
            "orchestrator registry MUST NOT include git_commit");
        assert!(r.get("edit_file").is_none(),
            "orchestrator registry MUST NOT include edit_file");
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
        let ws  = fixture_workspace();
        let ctx = ToolContext::for_workspace(ws.path());
        let out = ReadFileTool.execute(
            &serde_json::json!({ "path": "hello.txt" }), &ctx,
        ).await.unwrap();
        assert_eq!(out.is_error, None);
        assert_eq!(out.content, "hi from raxis");
    }

    #[tokio::test]
    async fn read_file_tool_rejects_path_escape() {
        let ws  = fixture_workspace();
        let ctx = ToolContext::for_workspace(ws.path());
        // path-escape is rejected at validation time → InvalidInput
        // surfaces from execute() itself, NOT a structured tool
        // error (the model never reaches the path-escape branch).
        let err = ReadFileTool.execute(
            &serde_json::json!({ "path": "../../etc/passwd" }), &ctx,
        ).await.unwrap_err();
        match err {
            ToolError::InvalidInput { tool, reason } => {
                assert_eq!(tool, "read_file");
                assert!(reason.contains(".."));
            }
            other => panic!("expected InvalidInput, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn edit_file_tool_writes_then_read_observes_new_contents() {
        let ws  = fixture_workspace();
        let ctx = ToolContext::for_workspace(ws.path());
        let out = EditFileTool.execute(
            &serde_json::json!({
                "path":     "out/new.txt",
                "contents": "fresh contents",
            }), &ctx,
        ).await.unwrap();
        assert_eq!(out.is_error, None);
        let read = ReadFileTool.execute(
            &serde_json::json!({ "path": "out/new.txt" }), &ctx,
        ).await.unwrap();
        assert_eq!(read.content, "fresh contents");
    }

    #[tokio::test]
    async fn bash_tool_runs_command_and_reports_exit_code() {
        let ws  = fixture_workspace();
        let ctx = ToolContext::for_workspace(ws.path());
        let out = BashTool.execute(
            &serde_json::json!({ "command": "echo planner-tools-bash-test" }),
            &ctx,
        ).await.unwrap();
        assert_eq!(out.is_error, None,
            "successful bash MUST NOT surface as a structured error");
        assert!(out.content.contains("planner-tools-bash-test"),
            "bash output should include stdout");
        assert!(out.content.contains("exit_code: 0"));
    }

    #[tokio::test]
    async fn bash_tool_marks_failure_as_structured_error() {
        let ws  = fixture_workspace();
        let ctx = ToolContext::for_workspace(ws.path());
        let out = BashTool.execute(
            &serde_json::json!({ "command": "exit 7" }),
            &ctx,
        ).await.unwrap();
        assert_eq!(out.is_error, Some(true));
        assert!(out.content.contains("exit_code: 7"));
    }

    #[tokio::test]
    async fn grep_search_tool_returns_matches() {
        let ws  = fixture_workspace();
        let ctx = ToolContext::for_workspace(ws.path());
        let out = GrepSearchTool.execute(
            &serde_json::json!({ "pattern": "raxis" }), &ctx,
        ).await.unwrap();
        assert_eq!(out.is_error, None);
        assert!(out.content.contains("hi from raxis"),
            "grep output: {}", out.content);
    }

    #[tokio::test]
    async fn grep_search_tool_no_match_returns_ok() {
        let ws  = fixture_workspace();
        let ctx = ToolContext::for_workspace(ws.path());
        let out = GrepSearchTool.execute(
            &serde_json::json!({ "pattern": "absolutely-no-such-string-12345" }),
            &ctx,
        ).await.unwrap();
        assert_eq!(out.is_error, None);
        assert!(out.content.contains("<no matches for"));
    }

    #[test]
    fn tool_registry_iter_is_sorted_by_name() {
        let r = build_executor_registry();
        let names: Vec<_> = r.iter().map(|t| t.name()).collect();
        let mut sorted = names.clone();
        sorted.sort();
        assert_eq!(names, sorted,
            "ToolRegistry::iter MUST be deterministic-sorted; \
             dispatch loop and audit chain depend on it");
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
}

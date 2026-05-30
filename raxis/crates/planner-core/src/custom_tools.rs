//! Custom-tool loader — reads kernel-approved
//! `[[profiles.<name>.custom_tool]]` declarations from a
//! plan-profile bundle and registers them as Executor
//! [`crate::tools::Tool`]s.
//!
//! The kernel is the authority: it validates the signed `plan.toml`,
//! resolves the task's `profiles = [...]`, merges inherited profile
//! tools, and stamps only the effective tool bundle into the spawned
//! Executor session. Reviewer and Orchestrator sessions never receive
//! this bundle.
//! ## Wire shape
//! Each custom tool decl carries:
//! * `name` — ASCII identifier matching `[A-Za-z0-9_]{1,64}`.
//! * `description` — Human-readable description (≤ 1 KiB).
//! * `command` — Absolute argv stamped by the kernel. For
//!   `guest_subprocess` this points inside the planner VM. For
//!   `host_subprocess`, `host_mcp`, and `remote_mcp` the planner never
//!   spawns it; the kernel resolves and executes the host-owned adapter.
//! * `schema` / `input_schema` — JSON Schema for the input.
//! * `timeout_seconds` / `timeout_secs` — Per-invocation deadline. Hard-capped at 300s
//!   (5 minutes) by the loader; values above the cap are rejected at
//!   registration time.
//! * `stdin_max_bytes`, `stdout_max_bytes`, `stderr_max_bytes` —
//!   per-invocation I/O caps enforced before data is forwarded to
//!   the tool or model.
//!   The subprocess receives the model's `tool_use.input` as JSON on
//!   stdin, and is expected to write a `ToolOutput`-shaped JSON
//!   response to stdout (`{ "content": "...", "is_error": bool? }`).
//!   Non-zero exit codes are surfaced as
//!   [`crate::tools::ToolOutput::err`] without further interpretation.

use std::process::Stdio;
use std::sync::Arc;
use std::time::{Duration, Instant};

use raxis_ipc::IpcMessage;
use raxis_types::{
    CustomToolByteReport, CustomToolExecutionRequest, CustomToolExecutionResponse,
    CustomToolInvocationAck, CustomToolInvocationOutcome, CustomToolInvocationRequest,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;
use uuid::Uuid;

use crate::tools::{Tool, ToolContext, ToolError, ToolOutput, ToolRegistry};
use crate::transport::KernelTransport;

const DEFAULT_STDIN_MAX_BYTES: u64 = 262_144;
const DEFAULT_STDOUT_MAX_BYTES: u64 = 65_536;
const DEFAULT_STDERR_MAX_BYTES: u64 = 16_384;
const HARD_MAX_STDIN_BYTES: u64 = 1_048_576;
const HARD_MAX_STDOUT_BYTES: u64 = 1_048_576;
const HARD_MAX_STDERR_BYTES: u64 = 262_144;
const MAX_ERROR_BYTES: usize = 512;
const LOCALITY_GUEST_SUBPROCESS: &str = "guest_subprocess";
const LOCALITY_HOST_SUBPROCESS: &str = "host_subprocess";
const LOCALITY_HOST_MCP: &str = "host_mcp";
const LOCALITY_REMOTE_MCP: &str = "remote_mcp";

/// Kernel-stamped custom-tool bundle for one Executor session.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct CustomToolBundle {
    /// Effective tools resolved from the task's selected profiles.
    #[serde(default)]
    pub tools: Vec<CustomToolDecl>,
}

/// One operator-declared custom tool decl. Matches one
/// `[[profiles.<name>.custom_tool]]` table after the kernel has
/// resolved the task's selected profiles.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CustomToolDecl {
    /// Tool name (registered into the planner registry under this key).
    pub name: String,
    /// Profile that contributed this tool to the task's effective bundle.
    /// The kernel stamps this from the signed plan after resolving
    /// `profiles = [...]` and inheritance. The planner reports it back only
    /// for audit correlation; the kernel verifies it against the signed
    /// bundle before accepting a guest-side audit row.
    pub profile_name: String,
    /// Human-readable description shown to the model.
    pub description: String,
    /// argv. argv`0` is the path to the executable; subsequent
    /// entries are static prefix arguments. The model's input
    /// arrives on stdin, NOT in argv.
    pub command: Vec<String>,
    /// Execution locality selected by the operator. `guest_subprocess`
    /// executes inside the VM and reports bounded metadata back to the
    /// kernel. Host and MCP localities are executed by the kernel from the
    /// signed declaration; the planner only forwards JSON input.
    #[serde(default = "default_execution_locality")]
    pub execution_locality: String,
    /// JSON Schema for the input. Forwarded verbatim to the model
    /// API as the tool's `input_schema`. The kernel emits the
    /// canonical plan field name (`schema`); older test fixtures may
    /// still use `input_schema`.
    #[serde(
        default = "default_input_schema",
        alias = "schema",
        skip_serializing_if = "serde_json::Value::is_null"
    )]
    pub input_schema: serde_json::Value,
    /// Per-invocation deadline, in seconds. Capped at 300.
    #[serde(default = "default_timeout_secs", alias = "timeout_seconds")]
    pub timeout_secs: u32,
    /// Maximum JSON stdin bytes accepted from the model.
    #[serde(default = "default_stdin_max_bytes")]
    pub stdin_max_bytes: u64,
    /// Maximum stdout bytes retained for model/audit output.
    #[serde(default = "default_stdout_max_bytes")]
    pub stdout_max_bytes: u64,
    /// Maximum stderr bytes retained for model/audit output.
    #[serde(default = "default_stderr_max_bytes")]
    pub stderr_max_bytes: u64,
    /// Whether non-zero exit stderr may be surfaced back to the model.
    /// The audit event always records size/digest/truncation metadata.
    #[serde(default)]
    pub expose_stderr: bool,
}

fn default_input_schema() -> serde_json::Value {
    serde_json::json!({
        "type": "object",
        "additionalProperties": true
    })
}

fn default_timeout_secs() -> u32 {
    60
}

fn default_stdin_max_bytes() -> u64 {
    DEFAULT_STDIN_MAX_BYTES
}

fn default_stdout_max_bytes() -> u64 {
    DEFAULT_STDOUT_MAX_BYTES
}

fn default_stderr_max_bytes() -> u64 {
    DEFAULT_STDERR_MAX_BYTES
}

fn default_execution_locality() -> String {
    LOCALITY_GUEST_SUBPROCESS.to_owned()
}

/// Errors raised at custom-tool registration time.
#[derive(Debug, Error)]
pub enum CustomToolError {
    /// Name failed the ASCII identifier rule.
    #[error(
        "custom-tool name {0:?} is not a valid identifier (allowed: ^[a-z][a-z0-9_]{{0,47}}$)"
    )]
    InvalidName(String),
    /// Description exceeded the 1 KiB cap.
    #[error("custom-tool {0} description exceeds 1024 bytes")]
    DescriptionTooLong(String),
    /// argv was empty.
    #[error("custom-tool {0} command argv must contain at least one entry (the executable path)")]
    EmptyCommand(String),
    /// Profile attribution was missing or malformed.
    #[error("custom-tool {tool} profile_name={profile_name:?} is invalid")]
    InvalidProfileName {
        /// Offending custom-tool name.
        tool: String,
        /// Kernel-stamped profile name.
        profile_name: String,
    },
    /// timeout_secs exceeded the policy hard cap.
    #[error("custom-tool {tool} timeout_secs={got} exceeds the policy hard cap (300s)")]
    TimeoutTooLong {
        /// Offending custom-tool name.
        tool: String,
        /// Operator-supplied timeout (seconds) that exceeded the cap.
        got: u32,
    },
    /// An I/O cap was zero, which would make every real invocation fail.
    #[error("custom-tool {tool} {field} must be at least 1 byte")]
    IoCapTooSmall {
        /// Offending custom-tool name.
        tool: String,
        /// Cap field that was invalid.
        field: &'static str,
    },
    /// An I/O cap exceeded the harness hard ceiling.
    #[error("custom-tool {tool} {field} cap {got} exceeds hard cap {cap}")]
    IoCapTooLarge {
        /// Offending custom-tool name.
        tool: String,
        /// Cap field that was invalid.
        field: &'static str,
        /// Operator-supplied cap.
        got: u64,
        /// Harness hard ceiling.
        cap: u64,
    },
    /// Name collision with an already-registered tool. The loader
    /// fails closed; operators must rename the custom tool or
    /// disable the colliding base tool via the role registry.
    #[error("custom-tool {tool} name collides with an already-registered tool")]
    NameCollision {
        /// Offending custom-tool name that collided with a built-in.
        tool: String,
    },
    /// Locality is not one of the shipped execution modes.
    #[error("custom-tool {tool} execution_locality={locality:?} is invalid")]
    InvalidExecutionLocality {
        /// Offending custom-tool name.
        tool: String,
        /// Operator-supplied locality.
        locality: String,
    },
    /// Kernel-stamped JSON bundle was malformed.
    #[error("custom-tool bundle JSON is invalid: {0}")]
    BundleJsonInvalid(String),
    /// Kernel-stamped bundle sidecar path could not be read.
    #[error("custom-tool bundle sidecar read failed for {path:?}: {error}")]
    BundleSidecarRead {
        /// Guest-visible path the driver tried to read.
        path: String,
        /// I/O error text.
        error: String,
    },
}

/// Validate one decl. Returns the decl unchanged on success.
pub fn validate_custom_tool(decl: &CustomToolDecl) -> Result<(), CustomToolError> {
    let bytes = decl.name.as_bytes();
    let name_ok = !bytes.is_empty()
        && bytes.len() <= 48
        && bytes[0].is_ascii_lowercase()
        && bytes[1..]
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'_');
    if !name_ok {
        return Err(CustomToolError::InvalidName(decl.name.clone()));
    }
    if !is_valid_profile_name(&decl.profile_name) {
        return Err(CustomToolError::InvalidProfileName {
            tool: decl.name.clone(),
            profile_name: decl.profile_name.clone(),
        });
    }
    if decl.description.len() > 1024 {
        return Err(CustomToolError::DescriptionTooLong(decl.name.clone()));
    }
    if decl.command.is_empty() {
        return Err(CustomToolError::EmptyCommand(decl.name.clone()));
    }
    if !is_supported_execution_locality(&decl.execution_locality) {
        return Err(CustomToolError::InvalidExecutionLocality {
            tool: decl.name.clone(),
            locality: decl.execution_locality.clone(),
        });
    }
    if decl.timeout_secs > 300 {
        return Err(CustomToolError::TimeoutTooLong {
            tool: decl.name.clone(),
            got: decl.timeout_secs,
        });
    }
    for (field, value, cap) in [
        (
            "stdin_max_bytes",
            decl.stdin_max_bytes,
            HARD_MAX_STDIN_BYTES,
        ),
        (
            "stdout_max_bytes",
            decl.stdout_max_bytes,
            HARD_MAX_STDOUT_BYTES,
        ),
        (
            "stderr_max_bytes",
            decl.stderr_max_bytes,
            HARD_MAX_STDERR_BYTES,
        ),
    ] {
        if value == 0 {
            return Err(CustomToolError::IoCapTooSmall {
                tool: decl.name.clone(),
                field,
            });
        }
        if value > cap {
            return Err(CustomToolError::IoCapTooLarge {
                tool: decl.name.clone(),
                field,
                got: value,
                cap,
            });
        }
    }
    Ok(())
}

/// Session-scoped custom-tool audit reporter. Stored on each custom
/// subprocess wrapper so the tool result is not returned to the model
/// until the kernel has durably recorded the invocation.
#[derive(Clone)]
pub struct CustomToolAuditEmitter {
    transport: Arc<dyn KernelTransport>,
    session_id: String,
    task_id: String,
    initiative_id: String,
}

impl CustomToolAuditEmitter {
    /// Build an emitter for one planner session.
    #[must_use]
    pub fn new(
        transport: Arc<dyn KernelTransport>,
        session_id: impl Into<String>,
        task_id: impl Into<String>,
        initiative_id: impl Into<String>,
    ) -> Self {
        Self {
            transport,
            session_id: session_id.into(),
            task_id: task_id.into(),
            initiative_id: initiative_id.into(),
        }
    }

    async fn emit(&self, mut req: CustomToolInvocationRequest) -> Result<(), String> {
        req.session_id = self.session_id.clone();
        req.task_id = self.task_id.clone();
        req.initiative_id = self.initiative_id.clone();
        match self
            .transport
            .request(&IpcMessage::CustomToolInvocation(req))
            .await
            .map_err(|e| e.to_string())?
        {
            IpcMessage::KernelCustomToolInvocationAck(CustomToolInvocationAck {
                accepted: true,
                ..
            }) => Ok(()),
            IpcMessage::KernelCustomToolInvocationAck(CustomToolInvocationAck {
                accepted: false,
                reason,
                ..
            }) => Err(format!(
                "kernel rejected custom tool audit report: {}",
                reason.unwrap_or_else(|| "unknown".to_owned())
            )),
            other => Err(format!(
                "unexpected custom tool audit response variant: {}",
                ipc_message_variant_name(&other)
            )),
        }
    }

    async fn execute_kernel_tool(
        &self,
        tool_name: &str,
        input: &serde_json::Value,
    ) -> Result<CustomToolExecutionResponse, String> {
        let req = CustomToolExecutionRequest {
            request_id: Uuid::new_v4(),
            session_token: String::new(),
            session_id: self.session_id.clone(),
            task_id: self.task_id.clone(),
            initiative_id: self.initiative_id.clone(),
            tool_name: tool_name.to_owned(),
            input: input.clone(),
        };
        match self
            .transport
            .request(&IpcMessage::CustomToolExecution(req))
            .await
            .map_err(|e| e.to_string())?
        {
            IpcMessage::KernelCustomToolExecutionResponse(resp) => Ok(resp),
            other => Err(format!(
                "unexpected custom tool execution response variant: {}",
                ipc_message_variant_name(&other)
            )),
        }
    }
}

/// Load + register a list of custom-tool decls into `registry`.
/// Each decl is validated, wrapped in a [`SubprocessTool`], and
/// inserted into the registry. Name collisions surface as
/// [`CustomToolError::NameCollision`] BEFORE the registry is
/// mutated, so a partial-load failure is observable but never
/// leaves the registry in a half-populated state.
pub fn load_custom_tools(
    registry: &mut ToolRegistry,
    decls: &[CustomToolDecl],
) -> Result<(), CustomToolError> {
    load_custom_tools_with_audit(registry, decls, None)
}

/// Same as [`load_custom_tools`], with an optional kernel audit emitter.
pub fn load_custom_tools_with_audit(
    registry: &mut ToolRegistry,
    decls: &[CustomToolDecl],
    audit: Option<CustomToolAuditEmitter>,
) -> Result<(), CustomToolError> {
    // Pass 1 — validate everything (and check name collisions
    // against the registry's current contents).
    for decl in decls {
        validate_custom_tool(decl)?;
        if registry.get(&decl.name).is_some() {
            return Err(CustomToolError::NameCollision {
                tool: decl.name.clone(),
            });
        }
    }
    // Pass 2 — register everything.
    for decl in decls {
        let common = CustomToolRuntimeConfig {
            name: leak_static(decl.name.clone()),
            profile_name: decl.profile_name.clone(),
            description: leak_static(decl.description.clone()),
            command: decl.command.clone(),
            input_schema: decl.input_schema.clone(),
            timeout: Duration::from_secs(decl.timeout_secs as u64),
            stdin_max_bytes: decl.stdin_max_bytes,
            stdout_max_bytes: decl.stdout_max_bytes,
            stderr_max_bytes: decl.stderr_max_bytes,
            expose_stderr: decl.expose_stderr,
            audit: audit.clone(),
        };
        if decl.execution_locality == LOCALITY_GUEST_SUBPROCESS {
            registry.register(Arc::new(SubprocessTool { common }));
        } else {
            registry.register(Arc::new(KernelExecutedTool {
                common,
                execution_locality: decl.execution_locality.clone(),
            }));
        }
    }
    Ok(())
}

/// Parse the JSON bundle the kernel stamps into one Executor
/// session. The stable envelope is:
///
/// ```json
/// { "tools": [ { "name": "...", "profile_name": "...", "description": "...", "command": ["..."] } ] }
/// ```
///
/// A bare array of tool declarations is also accepted for older
/// fixture files and small local harnesses. The operator-facing plan
/// schema remains profile-scoped TOML.
pub fn parse_custom_tool_bundle_json(raw: &str) -> Result<Vec<CustomToolDecl>, CustomToolError> {
    match serde_json::from_str::<CustomToolBundle>(raw) {
        Ok(bundle) => return Ok(bundle.tools),
        Err(bundle_err) => match serde_json::from_str::<Vec<CustomToolDecl>>(raw) {
            Ok(tools) => Ok(tools),
            Err(array_err) => Err(CustomToolError::BundleJsonInvalid(format!(
                "as envelope: {bundle_err}; as array: {array_err}"
            ))),
        },
    }
}

/// Read custom-tool declarations from the kernel-stamped env
/// contract. The path channel wins over the inline channel so large
/// schemas do not pressure AVF's cmdline-sized env transport.
pub fn read_custom_tool_decls_from_env_fn<F>(f: &F) -> Result<Vec<CustomToolDecl>, CustomToolError>
where
    F: Fn(&str) -> Option<String>,
{
    let var = |k: &str| f(k).filter(|v| !v.is_empty());
    if let Some(path) = var(raxis_types::planner_env::PLANNER_CUSTOM_TOOLS_PATH_ENV) {
        let raw =
            std::fs::read_to_string(&path).map_err(|e| CustomToolError::BundleSidecarRead {
                path: path.clone(),
                error: e.to_string(),
            })?;
        return parse_custom_tool_bundle_json(&raw);
    }
    match var(raxis_types::planner_env::PLANNER_CUSTOM_TOOLS_ENV) {
        Some(raw) => parse_custom_tool_bundle_json(&raw),
        None => Ok(Vec::new()),
    }
}

/// Shared custom-tool runtime metadata after registration.
struct CustomToolRuntimeConfig {
    name: &'static str,
    profile_name: String,
    description: &'static str,
    command: Vec<String>,
    input_schema: serde_json::Value,
    timeout: Duration,
    stdin_max_bytes: u64,
    stdout_max_bytes: u64,
    stderr_max_bytes: u64,
    expose_stderr: bool,
    audit: Option<CustomToolAuditEmitter>,
}

/// Concrete [`Tool`] impl that shells out to a configured argv with
/// the model's input on stdin inside the executor VM.
pub struct SubprocessTool {
    common: CustomToolRuntimeConfig,
}

#[async_trait::async_trait]
impl Tool for SubprocessTool {
    fn name(&self) -> &'static str {
        self.common.name
    }
    fn description(&self) -> &'static str {
        self.common.description
    }
    fn input_schema(&self) -> serde_json::Value {
        self.common.input_schema.clone()
    }

    async fn execute(
        &self,
        input: &serde_json::Value,
        ctx: &ToolContext,
    ) -> Result<ToolOutput, ToolError> {
        let started = Instant::now();
        let argv0 = self
            .common
            .command
            .first()
            .ok_or_else(|| ToolError::Internal {
                tool: self.common.name.to_owned(),
                reason: "command argv was empty at execute time \
                     (registration-time guard regressed)"
                    .to_owned(),
            })?;
        let argv_rest: &[String] = &self.common.command[1..];
        let stdin_body = match serde_json::to_vec(input) {
            Ok(b) => b,
            Err(e) => {
                return self
                    .finish_after_audit(
                        CustomToolInvocationOutcome::SchemaRejected,
                        started,
                        None,
                        None,
                        CaptureReport::from_bytes(&[]),
                        ByteCapture::empty(),
                        ByteCapture::empty(),
                        Some(format!("stdin JSON encode failed: {e}")),
                        ToolOutput::err(format!(
                            "{}: stdin JSON encode failed: {e}",
                            self.common.name
                        )),
                    )
                    .await;
            }
        };
        let stdin_report = CaptureReport::from_bytes(&stdin_body);
        if stdin_body.len() as u64 > self.common.stdin_max_bytes {
            return self
                .finish_after_audit(
                    CustomToolInvocationOutcome::InputTooLarge,
                    started,
                    None,
                    None,
                    stdin_report,
                    ByteCapture::empty(),
                    ByteCapture::empty(),
                    Some(format!(
                        "stdin {} bytes exceeds stdin_max_bytes {}",
                        stdin_body.len(),
                        self.common.stdin_max_bytes
                    )),
                    ToolOutput::err(format!(
                        "{}: CustomToolInputTooLarge: stdin JSON is {} bytes; limit is {} bytes",
                        self.common.name,
                        stdin_body.len(),
                        self.common.stdin_max_bytes
                    )),
                )
                .await;
        }
        if let Err(reason) = validate_input_against_schema(input, &self.common.input_schema) {
            return self
                .finish_after_audit(
                    CustomToolInvocationOutcome::SchemaRejected,
                    started,
                    None,
                    None,
                    stdin_report,
                    ByteCapture::empty(),
                    ByteCapture::empty(),
                    Some(reason.clone()),
                    ToolOutput::err(format!(
                        "{}: CustomToolSchemaRejected: {reason}",
                        self.common.name
                    )),
                )
                .await;
        }

        let mut cmd = Command::new(argv0);
        cmd.args(argv_rest)
            .current_dir(&ctx.workspace_root)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let mut child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) => {
                return self
                    .finish_after_audit(
                        CustomToolInvocationOutcome::SpawnFailed,
                        started,
                        None,
                        None,
                        stdin_report,
                        ByteCapture::empty(),
                        ByteCapture::empty(),
                        Some(format!("spawn {argv0:?} failed: {e}")),
                        ToolOutput::err(format!(
                            "{}: spawn {argv0:?} failed: {e}",
                            self.common.name
                        )),
                    )
                    .await;
            }
        };
        // Pipe the model's input to stdin, drop the writer, then
        // wait for output.
        if let Some(mut stdin) = child.stdin.take() {
            match stdin.write_all(&stdin_body).await {
                Ok(()) => {}
                // EPIPE / BrokenPipe means the subprocess exited (or
                // closed its stdin) before consuming input. This is
                // normal — many tools ignore stdin entirely. Drop the
                // writer and fall through to wait_with_output so the
                // real exit code and stderr are captured.
                Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => {}
                Err(e) => {
                    let _ = child.kill().await;
                    let _ = child.wait().await;
                    return self
                        .finish_after_audit(
                            CustomToolInvocationOutcome::StdinWriteFailed,
                            started,
                            None,
                            None,
                            stdin_report,
                            ByteCapture::empty(),
                            ByteCapture::empty(),
                            Some(format!("stdin write failed: {e}")),
                            ToolOutput::err(format!(
                                "{}: stdin write failed: {e}",
                                self.common.name
                            )),
                        )
                        .await;
                }
            }
            // Drop closes stdin so the subprocess sees EOF.
            drop(stdin);
        }
        let timeout = ctx
            .deadline
            .map(|deadline| deadline.min(self.common.timeout))
            .unwrap_or(self.common.timeout);
        let stdout = child.stdout.take();
        let stderr = child.stderr.take();
        let stdout_cap = self.common.stdout_max_bytes;
        let stderr_cap = self.common.stderr_max_bytes;
        let stdout_task = tokio::spawn(async move { read_pipe_capped(stdout, stdout_cap).await });
        let stderr_task = tokio::spawn(async move { read_pipe_capped(stderr, stderr_cap).await });

        let status = tokio::select! {
            status = child.wait() => match status {
                Ok(status) => status,
                Err(e) => {
                    stdout_task.abort();
                    stderr_task.abort();
                    return self
                        .finish_after_audit(
                            CustomToolInvocationOutcome::WaitFailed,
                            started,
                            None,
                            None,
                            stdin_report,
                            ByteCapture::empty(),
                            ByteCapture::empty(),
                            Some(format!("wait failed: {e}")),
                            ToolOutput::err(format!("{}: wait failed: {e}", self.common.name)),
                        )
                        .await;
                }
            },
            _ = tokio::time::sleep(timeout) => {
                let _ = child.kill().await;
                let _ = child.wait().await;
                stdout_task.abort();
                stderr_task.abort();
                return self
                    .finish_after_audit(
                        CustomToolInvocationOutcome::Timeout,
                        started,
                        None,
                        None,
                        stdin_report,
                        ByteCapture::empty(),
                        ByteCapture::empty(),
                        Some(format!("subprocess timed out after {timeout:?}")),
                        ToolOutput::err(format!(
                            "{}: CustomToolTimeout after {timeout:?}",
                            self.common.name,
                        )),
                    )
                    .await;
            }
        };

        let stdout = match stdout_task.await {
            Ok(Ok(bytes)) => bytes,
            Ok(Err(e)) => {
                return self
                    .finish_after_audit(
                        CustomToolInvocationOutcome::StdoutReadFailed,
                        started,
                        status.code(),
                        exit_signal(&status),
                        stdin_report,
                        ByteCapture::empty(),
                        ByteCapture::empty(),
                        Some(format!("stdout read failed: {e}")),
                        ToolOutput::err(format!("{}: stdout read failed: {e}", self.common.name)),
                    )
                    .await;
            }
            Err(e) => {
                return self
                    .finish_after_audit(
                        CustomToolInvocationOutcome::StdoutReadFailed,
                        started,
                        status.code(),
                        exit_signal(&status),
                        stdin_report,
                        ByteCapture::empty(),
                        ByteCapture::empty(),
                        Some(format!("stdout task failed: {e}")),
                        ToolOutput::err(format!("{}: stdout task failed: {e}", self.common.name)),
                    )
                    .await;
            }
        };
        let stderr = match stderr_task.await {
            Ok(Ok(bytes)) => bytes,
            Ok(Err(e)) => {
                return self
                    .finish_after_audit(
                        CustomToolInvocationOutcome::StderrReadFailed,
                        started,
                        status.code(),
                        exit_signal(&status),
                        stdin_report,
                        stdout,
                        ByteCapture::empty(),
                        Some(format!("stderr read failed: {e}")),
                        ToolOutput::err(format!("{}: stderr read failed: {e}", self.common.name)),
                    )
                    .await;
            }
            Err(e) => {
                return self
                    .finish_after_audit(
                        CustomToolInvocationOutcome::StderrReadFailed,
                        started,
                        status.code(),
                        exit_signal(&status),
                        stdin_report,
                        stdout,
                        ByteCapture::empty(),
                        Some(format!("stderr task failed: {e}")),
                        ToolOutput::err(format!("{}: stderr task failed: {e}", self.common.name)),
                    )
                    .await;
            }
        };
        if !status.success() {
            let exit_info = match status.code() {
                Some(code) => format!("exit code {code}"),
                None => {
                    #[cfg(unix)]
                    {
                        use std::os::unix::process::ExitStatusExt;
                        match status.signal() {
                            Some(sig) => format!("killed by signal {sig}"),
                            None => "unknown exit status".to_owned(),
                        }
                    }
                    #[cfg(not(unix))]
                    {
                        "unknown exit status".to_owned()
                    }
                }
            };
            let stderr_text = String::from_utf8_lossy(&stderr.bytes).into_owned();
            let content = if self.common.expose_stderr {
                format!(
                    "{name}: {exit_info}\nstderr:\n{stderr}",
                    name = self.common.name,
                    stderr = stderr_text,
                )
            } else {
                format!(
                    "{name}: {exit_info}; stderr captured in audit digest ({bytes} bytes)",
                    name = self.common.name,
                    bytes = stderr.bytes_total,
                )
            };
            return self
                .finish_after_audit(
                    CustomToolInvocationOutcome::NonZeroExit,
                    started,
                    status.code(),
                    exit_signal(&status),
                    stdin_report,
                    stdout,
                    stderr,
                    Some(exit_info),
                    ToolOutput::err(content),
                )
                .await;
        }
        // Try to parse stdout as a JSON ToolOutput envelope. Fall
        // back to wrapping the raw stdout as a success body if the
        // tool didn't emit JSON.
        if let Ok(parsed) = serde_json::from_slice::<ToolOutput>(&stdout.bytes) {
            let outcome = if parsed.is_error == Some(true) {
                CustomToolInvocationOutcome::ToolError
            } else {
                CustomToolInvocationOutcome::Success
            };
            self.finish_after_audit(
                outcome,
                started,
                status.code(),
                exit_signal(&status),
                stdin_report,
                stdout,
                stderr,
                None,
                parsed,
            )
            .await
        } else {
            let mut content = String::from_utf8_lossy(&stdout.bytes).into_owned();
            if stdout.truncated {
                content.push_str("\n[CUSTOM_TOOL_STDOUT_TRUNCATED]");
            }
            self.finish_after_audit(
                CustomToolInvocationOutcome::Success,
                started,
                status.code(),
                exit_signal(&status),
                stdin_report,
                stdout,
                stderr,
                None,
                ToolOutput::ok(content),
            )
            .await
        }
    }
}

/// [`Tool`] implementation for host-owned localities. The executor VM never
/// receives the host command, MCP endpoint, or credentials; it forwards only
/// the operator-declared tool name and validated JSON input to the kernel.
pub struct KernelExecutedTool {
    common: CustomToolRuntimeConfig,
    execution_locality: String,
}

#[async_trait::async_trait]
impl Tool for KernelExecutedTool {
    fn name(&self) -> &'static str {
        self.common.name
    }

    fn description(&self) -> &'static str {
        self.common.description
    }

    fn input_schema(&self) -> serde_json::Value {
        self.common.input_schema.clone()
    }

    async fn execute(
        &self,
        input: &serde_json::Value,
        _ctx: &ToolContext,
    ) -> Result<ToolOutput, ToolError> {
        let stdin_body = match serde_json::to_vec(input) {
            Ok(b) => b,
            Err(e) => {
                return Ok(ToolOutput::err(format!(
                    "{}: stdin JSON encode failed: {e}",
                    self.common.name
                )));
            }
        };
        if stdin_body.len() as u64 > self.common.stdin_max_bytes {
            return Ok(ToolOutput::err(format!(
                "{}: CustomToolInputTooLarge: stdin JSON is {} bytes; limit is {} bytes",
                self.common.name,
                stdin_body.len(),
                self.common.stdin_max_bytes
            )));
        }
        if let Err(reason) = validate_input_against_schema(input, &self.common.input_schema) {
            return Ok(ToolOutput::err(format!(
                "{}: CustomToolSchemaRejected: {reason}",
                self.common.name
            )));
        }
        let Some(audit) = &self.common.audit else {
            return Ok(ToolOutput::err(format!(
                "{}: kernel-executed custom tool is unavailable: no kernel transport",
                self.common.name
            )));
        };
        let resp = match audit.execute_kernel_tool(self.common.name, input).await {
            Ok(resp) => resp,
            Err(e) => {
                return Ok(ToolOutput::err(format!(
                    "{}: kernel custom tool execution failed before reply: {e}",
                    self.common.name
                )));
            }
        };
        if !resp.accepted {
            return Ok(ToolOutput::err(format!(
                "{}: kernel rejected {} execution: {}",
                self.common.name,
                self.execution_locality,
                resp.reason.unwrap_or_else(|| "unknown".to_owned())
            )));
        }
        let content = resp.content.unwrap_or_default();
        if resp.is_error == Some(true) {
            Ok(ToolOutput::err(content))
        } else {
            Ok(ToolOutput::ok(content))
        }
    }
}

impl SubprocessTool {
    #[allow(clippy::too_many_arguments)]
    async fn finish_after_audit(
        &self,
        outcome: CustomToolInvocationOutcome,
        started: Instant,
        exit_code: Option<i32>,
        signal: Option<i32>,
        stdin: CaptureReport,
        stdout: ByteCapture,
        stderr: ByteCapture,
        error: Option<String>,
        output: ToolOutput,
    ) -> Result<ToolOutput, ToolError> {
        if let Some(audit) = &self.common.audit {
            let req = CustomToolInvocationRequest {
                request_id: Uuid::new_v4(),
                session_token: String::new(),
                session_id: String::new(),
                task_id: String::new(),
                initiative_id: String::new(),
                tool_name: self.common.name.to_owned(),
                profile_name: self.common.profile_name.clone(),
                execution_locality: LOCALITY_GUEST_SUBPROCESS.to_owned(),
                command_argv_sha256: sha256_hex(
                    &serde_json::to_vec(&self.common.command).unwrap_or_default(),
                ),
                timeout_ms: self
                    .common
                    .timeout
                    .as_millis()
                    .try_into()
                    .unwrap_or(u64::MAX),
                outcome,
                duration_ms: started.elapsed().as_millis().try_into().unwrap_or(u64::MAX),
                exit_code,
                signal,
                stdin: stdin.into_wire(),
                stdout: stdout.report.into_wire(),
                stderr: stderr.report.into_wire(),
                error: error.map(|s| truncate_text(&s, MAX_ERROR_BYTES)),
            };
            if let Err(e) = audit.emit(req).await {
                return Ok(ToolOutput::err(format!(
                    "{}: custom tool audit emission failed; tool response withheld: {e}",
                    self.common.name
                )));
            }
        }
        Ok(output)
    }
}

#[derive(Debug, Clone)]
struct CaptureReport {
    bytes_total: u64,
    bytes_captured: u64,
    sha256: String,
    truncated: bool,
}

impl CaptureReport {
    fn from_bytes(bytes: &[u8]) -> Self {
        Self {
            bytes_total: bytes.len() as u64,
            bytes_captured: bytes.len() as u64,
            sha256: sha256_hex(bytes),
            truncated: false,
        }
    }

    fn into_wire(self) -> CustomToolByteReport {
        CustomToolByteReport {
            bytes_total: self.bytes_total,
            bytes_captured: self.bytes_captured,
            sha256: self.sha256,
            truncated: self.truncated,
        }
    }
}

#[derive(Debug, Clone)]
struct ByteCapture {
    bytes: Vec<u8>,
    bytes_total: u64,
    truncated: bool,
    report: CaptureReport,
}

impl ByteCapture {
    fn empty() -> Self {
        let report = CaptureReport::from_bytes(&[]);
        Self {
            bytes: Vec::new(),
            bytes_total: 0,
            truncated: false,
            report,
        }
    }

    fn from_parts(bytes: Vec<u8>, bytes_total: u64, sha256: String, truncated: bool) -> Self {
        let bytes_captured = bytes.len() as u64;
        Self {
            bytes,
            bytes_total,
            truncated,
            report: CaptureReport {
                bytes_total,
                bytes_captured,
                sha256,
                truncated,
            },
        }
    }
}

async fn read_pipe_capped<R>(pipe: Option<R>, cap: u64) -> std::io::Result<ByteCapture>
where
    R: tokio::io::AsyncRead + Unpin + Send + 'static,
{
    let Some(mut pipe) = pipe else {
        return Ok(ByteCapture::empty());
    };
    let cap = cap.min(usize::MAX as u64) as usize;
    let mut captured = Vec::with_capacity(cap.min(8192));
    let mut total = 0_u64;
    let mut hasher = Sha256::new();
    let mut buf = [0_u8; 8192];
    loop {
        let n = pipe.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        total = total.saturating_add(n as u64);
        hasher.update(&buf[..n]);
        if captured.len() < cap {
            let remaining = cap - captured.len();
            let take = remaining.min(n);
            captured.extend_from_slice(&buf[..take]);
        }
    }
    let truncated = total > captured.len() as u64;
    Ok(ByteCapture::from_parts(
        captured,
        total,
        hex::encode(hasher.finalize()),
        truncated,
    ))
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

fn truncate_text(s: &str, max_bytes: usize) -> String {
    if s.len() <= max_bytes {
        return s.to_owned();
    }
    let mut out = String::new();
    for ch in s.chars() {
        if out.len() + ch.len_utf8() > max_bytes {
            break;
        }
        out.push(ch);
    }
    out.push_str("...");
    out
}

fn exit_signal(status: &std::process::ExitStatus) -> Option<i32> {
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        status.signal()
    }
    #[cfg(not(unix))]
    {
        let _ = status;
        None
    }
}

fn validate_input_against_schema(
    input: &serde_json::Value,
    schema: &serde_json::Value,
) -> Result<(), String> {
    validate_value_against_schema(input, schema, "$")
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

fn is_valid_profile_name(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 64
        && bytes[0].is_ascii_alphabetic()
        && bytes[1..]
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || *b == b'_' || *b == b'-')
}

fn validate_value_against_schema(
    value: &serde_json::Value,
    schema: &serde_json::Value,
    path: &str,
) -> Result<(), String> {
    if let Some(expected) = schema.get("type").and_then(|v| v.as_str()) {
        let ok = match expected {
            "object" => value.is_object(),
            "array" => value.is_array(),
            "string" => value.is_string(),
            "boolean" => value.is_boolean(),
            "integer" => value.as_i64().is_some() || value.as_u64().is_some(),
            "number" => value.is_number(),
            "null" => value.is_null(),
            _ => true,
        };
        if !ok {
            return Err(format!(
                "{path}: expected {expected}, got {}",
                json_type(value)
            ));
        }
    }

    if let Some(allowed) = schema.get("enum").and_then(|v| v.as_array()) {
        if !allowed.iter().any(|allowed_value| allowed_value == value) {
            return Err(format!("{path}: value not in enum"));
        }
    }

    if let (Some(s), Some(max)) = (
        value.as_str(),
        schema.get("maxLength").and_then(|v| v.as_u64()),
    ) {
        if s.chars().count() as u64 > max {
            return Err(format!("{path}: string length exceeds maxLength {max}"));
        }
    }
    if let (Some(s), Some(min)) = (
        value.as_str(),
        schema.get("minLength").and_then(|v| v.as_u64()),
    ) {
        if (s.chars().count() as u64) < min {
            return Err(format!("{path}: string length is below minLength {min}"));
        }
    }

    if let Some(n) = value.as_f64() {
        if let Some(min) = schema.get("minimum").and_then(|v| v.as_f64()) {
            if n < min {
                return Err(format!("{path}: number is below minimum {min}"));
            }
        }
        if let Some(max) = schema.get("maximum").and_then(|v| v.as_f64()) {
            if n > max {
                return Err(format!("{path}: number exceeds maximum {max}"));
            }
        }
    }

    if let (Some(obj), Some(required)) = (
        value.as_object(),
        schema.get("required").and_then(|v| v.as_array()),
    ) {
        for req in required.iter().filter_map(|v| v.as_str()) {
            if !obj.contains_key(req) {
                return Err(format!("{path}: missing required property {req:?}"));
            }
        }
    }

    if let (Some(obj), Some(props)) = (
        value.as_object(),
        schema.get("properties").and_then(|v| v.as_object()),
    ) {
        if schema.get("additionalProperties").and_then(|v| v.as_bool()) == Some(false) {
            for key in obj.keys() {
                if !props.contains_key(key) {
                    return Err(format!("{path}: unknown property {key:?}"));
                }
            }
        }
        for (key, prop_schema) in props {
            if let Some(child) = obj.get(key) {
                validate_value_against_schema(child, prop_schema, &format!("{path}.{key}"))?;
            }
        }
    }

    Ok(())
}

fn ipc_message_variant_name(msg: &IpcMessage) -> &'static str {
    match msg {
        IpcMessage::IntentRequest(_) => "IntentRequest",
        IpcMessage::EscalationRequest(_) => "EscalationRequest",
        IpcMessage::PlannerFetchRequest(_) => "PlannerFetchRequest",
        IpcMessage::CustomToolInvocation(_) => "CustomToolInvocation",
        IpcMessage::CustomToolExecution(_) => "CustomToolExecution",
        IpcMessage::PlannerExitNotice { .. } => "PlannerExitNotice",
        IpcMessage::KernelIntentResponse(_) => "KernelIntentResponse",
        IpcMessage::KernelEscalationResponse(_) => "KernelEscalationResponse",
        IpcMessage::KernelPlannerFetchResponse(_) => "KernelPlannerFetchResponse",
        IpcMessage::KernelCustomToolInvocationAck(_) => "KernelCustomToolInvocationAck",
        IpcMessage::KernelCustomToolExecutionResponse(_) => "KernelCustomToolExecutionResponse",
        IpcMessage::KernelPlannerExitNoticeAck => "KernelPlannerExitNoticeAck",
        IpcMessage::WitnessSubmission(_) => "WitnessSubmission",
        IpcMessage::WitnessAck { .. } => "WitnessAck",
        IpcMessage::OperatorRequest(_) => "OperatorRequest",
        IpcMessage::OperatorResponse(_) => "OperatorResponse",
        IpcMessage::TproxyAdmissionRequest(_) => "TproxyAdmissionRequest",
        IpcMessage::KernelTproxyAdmissionResponse(_) => "KernelTproxyAdmissionResponse",
        IpcMessage::DnsResolveRequest(_) => "DnsResolveRequest",
        IpcMessage::KernelDnsResolveResponse(_) => "KernelDnsResolveResponse",
    }
}

fn json_type(value: &serde_json::Value) -> &'static str {
    match value {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "boolean",
        serde_json::Value::Number(n) if n.is_i64() || n.is_u64() => "integer",
        serde_json::Value::Number(_) => "number",
        serde_json::Value::String(_) => "string",
        serde_json::Value::Array(_) => "array",
        serde_json::Value::Object(_) => "object",
    }
}

/// Leak `s` for the `'static` lifetime required by [`Tool::name`] /
/// [`Tool::description`]. Per-tool one-shot leak — each custom tool
/// registers exactly once per planner-role binary lifetime, so the
/// memory footprint is bounded by the operator-declared decl count
/// (typically < 20).
fn leak_static(s: String) -> &'static str {
    Box::leak(s.into_boxed_str())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn fixture_workspace() -> TempDir {
        tempfile::tempdir().unwrap()
    }

    fn custom_tool_decl(
        name: impl Into<String>,
        description: impl Into<String>,
        command: Vec<String>,
        input_schema: serde_json::Value,
        timeout_secs: u32,
    ) -> CustomToolDecl {
        CustomToolDecl {
            name: name.into(),
            profile_name: "repo_tools".to_owned(),
            description: description.into(),
            command,
            execution_locality: LOCALITY_GUEST_SUBPROCESS.to_owned(),
            input_schema,
            timeout_secs,
            stdin_max_bytes: DEFAULT_STDIN_MAX_BYTES,
            stdout_max_bytes: DEFAULT_STDOUT_MAX_BYTES,
            stderr_max_bytes: DEFAULT_STDERR_MAX_BYTES,
            expose_stderr: true,
        }
    }

    #[test]
    fn validate_rejects_invalid_name() {
        let bad = custom_tool_decl(
            "has-dash",
            "x",
            vec!["/bin/true".to_owned()],
            serde_json::json!({}),
            10,
        );
        match validate_custom_tool(&bad).unwrap_err() {
            CustomToolError::InvalidName(n) => assert_eq!(n, "has-dash"),
            other => panic!("expected InvalidName, got {other:?}"),
        }
    }

    #[test]
    fn validate_rejects_uppercase_or_digit_start() {
        for name in ["Tool".to_owned(), "1tool".to_owned(), "a".repeat(49)] {
            let bad = custom_tool_decl(
                name,
                "valid custom tool description",
                vec!["/bin/true".to_owned()],
                serde_json::json!({}),
                10,
            );
            assert!(matches!(
                validate_custom_tool(&bad),
                Err(CustomToolError::InvalidName(_))
            ));
        }
    }

    #[test]
    fn validate_rejects_empty_command() {
        let bad = custom_tool_decl("x", "y", vec![], serde_json::json!({}), 10);
        match validate_custom_tool(&bad).unwrap_err() {
            CustomToolError::EmptyCommand(_) => {}
            other => panic!("expected EmptyCommand, got {other:?}"),
        }
    }

    #[test]
    fn validate_rejects_timeout_above_300s() {
        let bad = custom_tool_decl(
            "x",
            "y",
            vec!["/bin/true".to_owned()],
            serde_json::json!({}),
            600,
        );
        match validate_custom_tool(&bad).unwrap_err() {
            CustomToolError::TimeoutTooLong { got, .. } => {
                assert_eq!(got, 600);
            }
            other => panic!("expected TimeoutTooLong, got {other:?}"),
        }
    }

    #[test]
    fn validate_rejects_output_cap_above_hard_limit() {
        let mut bad = custom_tool_decl(
            "large_output",
            "valid custom tool description",
            vec!["/bin/true".to_owned()],
            serde_json::json!({}),
            10,
        );
        bad.stdout_max_bytes = HARD_MAX_STDOUT_BYTES + 1;
        match validate_custom_tool(&bad).unwrap_err() {
            CustomToolError::IoCapTooLarge {
                field, got, cap, ..
            } => {
                assert_eq!(field, "stdout_max_bytes");
                assert_eq!(got, HARD_MAX_STDOUT_BYTES + 1);
                assert_eq!(cap, HARD_MAX_STDOUT_BYTES);
            }
            other => panic!("expected IoCapTooLarge, got {other:?}"),
        }
    }

    #[test]
    fn validate_rejects_description_too_long() {
        let bad = custom_tool_decl(
            "x",
            "y".repeat(1025),
            vec!["/bin/true".to_owned()],
            serde_json::json!({}),
            10,
        );
        match validate_custom_tool(&bad).unwrap_err() {
            CustomToolError::DescriptionTooLong(_) => {}
            other => panic!("expected DescriptionTooLong, got {other:?}"),
        }
    }

    #[test]
    fn load_rejects_name_collision_with_base_tool() {
        // `read_file` is registered by `build_executor_registry`.
        let mut registry = crate::tools::build_executor_registry();
        let decls = vec![custom_tool_decl(
            "read_file",
            "operator collision",
            vec!["/bin/echo".to_owned()],
            serde_json::json!({}),
            10,
        )];
        match load_custom_tools(&mut registry, &decls).unwrap_err() {
            CustomToolError::NameCollision { tool } => assert_eq!(tool, "read_file"),
            other => panic!("expected NameCollision, got {other:?}"),
        }
    }

    #[test]
    fn env_reader_prefers_sidecar_path_and_accepts_canonical_names() {
        let dir = fixture_workspace();
        let path = dir.path().join("tools.json");
        std::fs::write(
            &path,
            r#"{"tools":[{"name":"unity_build_player","profile_name":"unity_tools","description":"Build Unity player through local adapter","command":["/usr/local/bin/raxis-tool-mcp","unity","build-player"],"schema":{"type":"object"},"timeout_seconds":120}]}"#,
        )
        .unwrap();
        let path_str = path.display().to_string();
        let decls = read_custom_tool_decls_from_env_fn(&|key| match key {
            raxis_types::planner_env::PLANNER_CUSTOM_TOOLS_PATH_ENV => Some(path_str.clone()),
            raxis_types::planner_env::PLANNER_CUSTOM_TOOLS_ENV => Some("not json".to_owned()),
            _ => None,
        })
        .unwrap();
        assert_eq!(decls.len(), 1);
        assert_eq!(decls[0].name, "unity_build_player");
        assert_eq!(decls[0].timeout_secs, 120);
        validate_custom_tool(&decls[0]).unwrap();
    }

    #[test]
    fn env_reader_rejects_malformed_bundle() {
        match read_custom_tool_decls_from_env_fn(&|key| match key {
            raxis_types::planner_env::PLANNER_CUSTOM_TOOLS_ENV => Some("{not-json".to_owned()),
            _ => None,
        })
        .unwrap_err()
        {
            CustomToolError::BundleJsonInvalid(_) => {}
            other => panic!("expected BundleJsonInvalid, got {other:?}"),
        }
    }

    #[test]
    fn load_partial_failure_does_not_register_first_decl() {
        // First decl is valid, second collides → NEITHER must be
        // registered (atomicity invariant).
        let mut registry = ToolRegistry::new();
        let decls = vec![
            custom_tool_decl(
                "valid_a",
                "ok",
                vec!["/bin/true".to_owned()],
                serde_json::json!({}),
                10,
            ),
            custom_tool_decl(
                "has-dash", // invalid
                "ok",
                vec!["/bin/true".to_owned()],
                serde_json::json!({}),
                10,
            ),
        ];
        let _ = load_custom_tools(&mut registry, &decls).unwrap_err();
        assert!(
            registry.get("valid_a").is_none(),
            "atomicity: a partial failure must not register the first \
             decl, otherwise the operator's debug surface is half-applied"
        );
    }

    #[tokio::test]
    async fn host_locality_requests_kernel_execution_instead_of_spawning() {
        #[derive(Default)]
        struct StubTransport {
            saw_kernel_execution: std::sync::Mutex<bool>,
        }

        #[async_trait::async_trait]
        impl KernelTransport for StubTransport {
            async fn request(
                &self,
                outbound: &IpcMessage,
            ) -> Result<IpcMessage, crate::transport::TransportError> {
                match outbound {
                    IpcMessage::CustomToolExecution(req) => {
                        assert_eq!(req.session_id, "session-1");
                        assert_eq!(req.task_id, "task-1");
                        assert_eq!(req.initiative_id, "initiative-1");
                        assert_eq!(req.tool_name, "host_probe");
                        assert_eq!(req.input["query"], "ok");
                        *self.saw_kernel_execution.lock().unwrap() = true;
                        Ok(IpcMessage::KernelCustomToolExecutionResponse(
                            CustomToolExecutionResponse {
                                request_id: req.request_id,
                                accepted: true,
                                content: Some("host-result".to_owned()),
                                is_error: Some(false),
                                reason: None,
                            },
                        ))
                    }
                    other => panic!(
                        "unexpected outbound variant: {}",
                        ipc_message_variant_name(other)
                    ),
                }
            }
        }

        let transport = Arc::new(StubTransport::default());
        let audit =
            CustomToolAuditEmitter::new(transport.clone(), "session-1", "task-1", "initiative-1");
        let mut decl = custom_tool_decl(
            "host_probe",
            "query a host-owned telemetry adapter",
            vec!["/path/that/must/not/spawn/in/guest".to_owned()],
            serde_json::json!({
                "type": "object",
                "required": ["query"],
                "properties": {
                    "query": { "type": "string" }
                },
                "additionalProperties": false
            }),
            5,
        );
        decl.execution_locality = LOCALITY_HOST_SUBPROCESS.to_owned();
        let mut registry = ToolRegistry::new();
        load_custom_tools_with_audit(&mut registry, &[decl], Some(audit)).unwrap();
        let tool = registry.get("host_probe").unwrap().clone();
        let ws = fixture_workspace();
        let ctx = ToolContext::for_workspace(ws.path());
        let out = tool
            .execute(&serde_json::json!({"query": "ok"}), &ctx)
            .await
            .unwrap();
        assert_ne!(out.is_error, Some(true));
        assert_eq!(out.content, "host-result");
        assert!(*transport.saw_kernel_execution.lock().unwrap());
    }

    #[tokio::test]
    async fn subprocess_tool_returns_stdout_as_ok_when_not_json() {
        let mut registry = ToolRegistry::new();
        let decl = custom_tool_decl(
            "echo_tool",
            "echo stdin to stdout",
            vec!["/bin/cat".to_owned()],
            serde_json::json!({}),
            5,
        );
        load_custom_tools(&mut registry, &[decl]).unwrap();
        let tool = registry.get("echo_tool").unwrap().clone();
        let ws = fixture_workspace();
        let ctx = ToolContext::for_workspace(ws.path());
        let out = tool
            .execute(&serde_json::json!({"hello": "raxis"}), &ctx)
            .await
            .unwrap();
        assert_eq!(out.is_error, None);
        // /bin/cat echoes the JSON-encoded input verbatim.
        assert!(out.content.contains("\"hello\""));
        assert!(out.content.contains("\"raxis\""));
    }

    #[tokio::test]
    async fn subprocess_tool_parses_json_envelope_when_emitted() {
        // Tool that emits a structured JSON ToolOutput on stdout.
        let mut registry = ToolRegistry::new();
        let decl = custom_tool_decl(
            "json_emitter",
            "emit a JSON ToolOutput envelope",
            vec![
                "/bin/sh".to_owned(),
                "-c".to_owned(),
                r#"echo '{"content":"hello-from-tool","is_error":false}'"#.to_owned(),
            ],
            serde_json::json!({}),
            5,
        );
        load_custom_tools(&mut registry, &[decl]).unwrap();
        let tool = registry.get("json_emitter").unwrap().clone();
        let ws = fixture_workspace();
        let ctx = ToolContext::for_workspace(ws.path());
        let out = tool.execute(&serde_json::json!({}), &ctx).await.unwrap();
        // is_error: false in the JSON should round-trip as Some(false),
        // NOT None — the envelope is preserved verbatim.
        assert_eq!(out.is_error, Some(false));
        assert_eq!(out.content, "hello-from-tool");
    }

    #[tokio::test]
    async fn subprocess_tool_non_zero_exit_surfaces_structured_error() {
        let mut registry = ToolRegistry::new();
        let decl = custom_tool_decl(
            "fail_tool",
            "always fails",
            vec![
                "/bin/sh".to_owned(),
                "-c".to_owned(),
                "echo 'oh no' >&2; exit 7".to_owned(),
            ],
            serde_json::json!({}),
            5,
        );
        load_custom_tools(&mut registry, &[decl]).unwrap();
        let tool = registry.get("fail_tool").unwrap().clone();
        let ws = fixture_workspace();
        let ctx = ToolContext::for_workspace(ws.path());
        let out = tool.execute(&serde_json::json!({}), &ctx).await.unwrap();
        assert_eq!(out.is_error, Some(true));
        assert!(
            out.content.contains("exit code 7"),
            "expected 'exit code 7' in output, got: {}",
            out.content
        );
        assert!(out.content.contains("oh no"));
    }
}

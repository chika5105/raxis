//! Kernel-owned custom-tool execution.
//!
//! Guest-local custom tools (`guest_subprocess`) execute in the executor VM and
//! report bounded metadata back to this kernel. Host-owned localities execute
//! here instead: the guest sends only `{ tool_name, input }`, and this module
//! resolves the signed declaration from [`crate::initiatives::PlanRegistry`].
//! That keeps host paths, MCP endpoints, adapter configuration, and credentials
//! outside the untrusted VM while preserving the same audit envelope.

use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;
use std::time::{Duration, Instant};

use raxis_audit_tools::AuditEventKind;
use raxis_types::{
    CustomToolExecutionRequest, CustomToolExecutionResponse, CustomToolInvocationOutcome,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;
use uuid::Uuid;

use crate::ipc::context::HandlerContext;

const DEFAULT_STDIN_MAX_BYTES: u64 = 262_144;
const DEFAULT_STDOUT_MAX_BYTES: u64 = 65_536;
const DEFAULT_STDERR_MAX_BYTES: u64 = 16_384;
const MAX_ERROR_BYTES: usize = 512;
const LOCALITY_GUEST_SUBPROCESS: &str = "guest_subprocess";
const LOCALITY_HOST_SUBPROCESS: &str = "host_subprocess";
const LOCALITY_HOST_MCP: &str = "host_mcp";
const LOCALITY_REMOTE_MCP: &str = "remote_mcp";

/// Execute a kernel-owned custom tool request and return a model-facing result
/// only after the audit event lands.
pub async fn handle_kernel_execution(
    req: CustomToolExecutionRequest,
    ctx: &Arc<HandlerContext>,
) -> CustomToolExecutionResponse {
    let request_id = req.request_id;
    match handle_kernel_execution_inner(req, ctx).await {
        Ok(resp) => resp,
        Err(reason) => reject(request_id, reason),
    }
}

async fn handle_kernel_execution_inner(
    req: CustomToolExecutionRequest,
    ctx: &Arc<HandlerContext>,
) -> Result<CustomToolExecutionResponse, String> {
    if req.session_token.is_empty() {
        return Err(
            "custom tool execution requires a session-bound stream or session token".into(),
        );
    }
    if !is_lower_tool_name(&req.tool_name) {
        return Err("custom tool execution carried invalid tool_name".into());
    }

    let token = req.session_token.clone();
    let store = Arc::clone(&ctx.store);
    let session = tokio::task::spawn_blocking(move || {
        crate::authority::session::get_active_session_by_token(&token, &store)
    })
    .await
    .map_err(|e| format!("custom tool execution session auth task failed: {e}"))?
    .map_err(|e| format!("custom tool execution session auth failed: {e}"))?;

    if req.session_id != session.session_id {
        return Err("custom tool execution session_id mismatch".into());
    }
    if session.session_agent_type != Some(raxis_types::SessionAgentType::Executor) {
        return Err("custom tools are executor-session only".into());
    }
    match session.initiative_id.as_deref() {
        Some(initiative_id) if initiative_id == req.initiative_id => {}
        Some(_) => return Err("custom tool execution initiative_id mismatch".into()),
        None => return Err("custom tool execution session has no initiative binding".into()),
    }

    let task_lookup = {
        let store = Arc::clone(&ctx.store);
        let task_id = req.task_id.clone();
        tokio::task::spawn_blocking(move || {
            let conn = store.lock_sync();
            conn.query_row(
                &format!(
                    "SELECT initiative_id, session_id FROM {tasks} WHERE task_id = ?1",
                    tasks = raxis_store::Table::Tasks.as_str(),
                ),
                rusqlite::params![task_id],
                |r| Ok((r.get::<_, String>(0)?, r.get::<_, Option<String>>(1)?)),
            )
            .map_err(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => "task not found".to_owned(),
                other => format!("task lookup failed: {other}"),
            })
        })
        .await
    };
    let (task_initiative_id, task_session_id) = match task_lookup {
        Ok(Ok(row)) => row,
        Ok(Err(e)) => return Err(e),
        Err(e) => return Err(format!("task lookup task failed: {e}")),
    };
    if task_initiative_id != req.initiative_id {
        return Err("custom tool execution task initiative mismatch".into());
    }
    match task_session_id.as_deref() {
        Some(sid) if sid == session.session_id => {}
        Some(_) => return Err("custom tool execution task session mismatch".into()),
        None => return Err("custom tool execution task has no session binding".into()),
    }

    let key = crate::initiatives::plan_registry::TaskKey::new(&req.initiative_id, &req.task_id);
    let fields = ctx
        .plan_registry
        .get(&key)
        .ok_or_else(|| "custom tool execution plan registry miss".to_owned())?;
    let bundle_json = fields
        .custom_tools_json
        .as_deref()
        .ok_or_else(|| "task has no custom-tool bundle".to_owned())?;
    let decl = find_tool_decl(bundle_json, &req.tool_name)?;
    if decl.execution_locality == LOCALITY_GUEST_SUBPROCESS {
        return Err("guest_subprocess custom tools must execute inside the executor VM".into());
    }
    if !is_kernel_owned_locality(&decl.execution_locality) {
        return Err(format!(
            "unsupported custom tool execution_locality {:?}",
            decl.execution_locality
        ));
    }

    let workdir = session
        .worktree_root
        .as_ref()
        .map(PathBuf::from)
        .unwrap_or_else(|| ctx.data_dir.clone());
    let executed = execute_decl(req.request_id, &req, &decl, workdir).await;
    let audit_result = emit_custom_tool_audit(ctx, &session.session_id, &req, &decl, &executed);
    match audit_result {
        Ok(()) => Ok(CustomToolExecutionResponse {
            request_id: req.request_id,
            accepted: true,
            content: Some(executed.output_content.clone()),
            is_error: Some(executed.output_is_error),
            reason: None,
        }),
        Err(e) => Err(format!("custom tool audit sink write failed: {e}")),
    }
}

#[derive(Debug, Deserialize)]
struct KernelCustomToolBundle {
    #[serde(default)]
    tools: Vec<KernelCustomToolDecl>,
}

#[derive(Debug, Clone, Deserialize)]
struct KernelCustomToolDecl {
    name: String,
    profile_name: String,
    command: Vec<String>,
    #[serde(default = "default_execution_locality")]
    execution_locality: String,
    #[serde(default = "default_input_schema", alias = "input_schema")]
    schema: serde_json::Value,
    #[serde(default = "default_timeout_secs", alias = "timeout_seconds")]
    timeout_secs: u32,
    #[serde(default = "default_stdin_max_bytes")]
    stdin_max_bytes: u64,
    #[serde(default = "default_stdout_max_bytes")]
    stdout_max_bytes: u64,
    #[serde(default = "default_stderr_max_bytes")]
    stderr_max_bytes: u64,
    #[serde(default)]
    expose_stderr: bool,
}

fn default_execution_locality() -> String {
    LOCALITY_GUEST_SUBPROCESS.to_owned()
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

fn find_tool_decl(raw: &str, tool_name: &str) -> Result<KernelCustomToolDecl, String> {
    let bundle = serde_json::from_str::<KernelCustomToolBundle>(raw)
        .or_else(|bundle_err| {
            serde_json::from_str::<Vec<KernelCustomToolDecl>>(raw)
                .map(|tools| KernelCustomToolBundle { tools })
                .map_err(|array_err| {
                    format!("custom-tool bundle JSON invalid: as envelope: {bundle_err}; as array: {array_err}")
                })
        })?;
    bundle
        .tools
        .into_iter()
        .find(|t| t.name == tool_name)
        .ok_or_else(|| format!("custom tool {tool_name:?} is not in the signed task bundle"))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedCustomToolMetadata {
    pub profile_name: String,
    pub execution_locality: String,
    pub command_argv_sha256: String,
    pub timeout_ms: u64,
}

/// Return the signed metadata the kernel expects a guest-local custom tool to
/// report. The guest may include the same fields for correlation, but the
/// planner socket handler treats this bundle-derived value as authoritative.
pub fn signed_custom_tool_metadata(
    raw: &str,
    tool_name: &str,
) -> Result<SignedCustomToolMetadata, String> {
    let decl = find_tool_decl(raw, tool_name)?;
    Ok(SignedCustomToolMetadata {
        profile_name: decl.profile_name,
        execution_locality: decl.execution_locality,
        command_argv_sha256: sha256_hex(&serde_json::to_vec(&decl.command).unwrap_or_default()),
        timeout_ms: Duration::from_secs(decl.timeout_secs as u64)
            .as_millis()
            .try_into()
            .unwrap_or(u64::MAX),
    })
}

#[derive(Debug)]
struct ExecutedCustomTool {
    outcome: CustomToolInvocationOutcome,
    duration_ms: u64,
    exit_code: Option<i32>,
    signal: Option<i32>,
    stdin: CaptureReport,
    stdout: ByteCapture,
    stderr: ByteCapture,
    error: Option<String>,
    output_content: String,
    output_is_error: bool,
}

async fn execute_decl(
    request_id: Uuid,
    req: &CustomToolExecutionRequest,
    decl: &KernelCustomToolDecl,
    workdir: PathBuf,
) -> ExecutedCustomTool {
    let started = Instant::now();
    let stdin_body = match serde_json::to_vec(&req.input) {
        Ok(b) => b,
        Err(e) => {
            return executed_error(
                CustomToolInvocationOutcome::SchemaRejected,
                started,
                CaptureReport::from_bytes(&[]),
                format!("stdin JSON encode failed: {e}"),
                format!("{}: stdin JSON encode failed: {e}", decl.name),
            );
        }
    };
    let stdin_report = CaptureReport::from_bytes(&stdin_body);
    if stdin_body.len() as u64 > decl.stdin_max_bytes {
        let reason = format!(
            "stdin {} bytes exceeds stdin_max_bytes {}",
            stdin_body.len(),
            decl.stdin_max_bytes
        );
        return executed_error(
            CustomToolInvocationOutcome::InputTooLarge,
            started,
            stdin_report,
            reason.clone(),
            format!(
                "{}: CustomToolInputTooLarge: stdin JSON is {} bytes; limit is {} bytes",
                decl.name,
                stdin_body.len(),
                decl.stdin_max_bytes
            ),
        );
    }
    if let Err(reason) = validate_input_against_schema(&req.input, &decl.schema) {
        return executed_error(
            CustomToolInvocationOutcome::SchemaRejected,
            started,
            stdin_report,
            reason.clone(),
            format!("{}: CustomToolSchemaRejected: {reason}", decl.name),
        );
    }

    let Some(argv0) = decl.command.first() else {
        return executed_error(
            CustomToolInvocationOutcome::SpawnFailed,
            started,
            stdin_report,
            "signed command argv was empty".to_owned(),
            format!("{}: signed command argv was empty", decl.name),
        );
    };
    let mut cmd = Command::new(argv0);
    cmd.args(&decl.command[1..])
        .current_dir(workdir)
        .env_clear()
        .env(
            "PATH",
            "/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin:/opt/homebrew/bin",
        )
        .env("RAXIS_CUSTOM_TOOL_NAME", &decl.name)
        .env("RAXIS_CUSTOM_TOOL_LOCALITY", &decl.execution_locality)
        .env("RAXIS_CUSTOM_TOOL_REQUEST_ID", request_id.to_string())
        .env("RAXIS_SESSION_ID", &req.session_id)
        .env("RAXIS_TASK_ID", &req.task_id)
        .env("RAXIS_INITIATIVE_ID", &req.initiative_id)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            return executed_error(
                CustomToolInvocationOutcome::SpawnFailed,
                started,
                stdin_report,
                format!("spawn {argv0:?} failed: {e}"),
                format!("{}: spawn {argv0:?} failed: {e}", decl.name),
            );
        }
    };
    if let Some(mut stdin) = child.stdin.take() {
        match stdin.write_all(&stdin_body).await {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => {}
            Err(e) => {
                let _ = child.kill().await;
                let _ = child.wait().await;
                return executed_error(
                    CustomToolInvocationOutcome::StdinWriteFailed,
                    started,
                    stdin_report,
                    format!("stdin write failed: {e}"),
                    format!("{}: stdin write failed: {e}", decl.name),
                );
            }
        }
        drop(stdin);
    }

    let timeout = Duration::from_secs(decl.timeout_secs as u64);
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let stdout_cap = decl.stdout_max_bytes;
    let stderr_cap = decl.stderr_max_bytes;
    let stdout_task = tokio::spawn(async move { read_pipe_capped(stdout, stdout_cap).await });
    let stderr_task = tokio::spawn(async move { read_pipe_capped(stderr, stderr_cap).await });

    let status = tokio::select! {
        status = child.wait() => match status {
            Ok(status) => status,
            Err(e) => {
                stdout_task.abort();
                stderr_task.abort();
                return executed_error(
                    CustomToolInvocationOutcome::WaitFailed,
                    started,
                    stdin_report,
                    format!("wait failed: {e}"),
                    format!("{}: wait failed: {e}", decl.name),
                );
            }
        },
        _ = tokio::time::sleep(timeout) => {
            let _ = child.kill().await;
            let _ = child.wait().await;
            stdout_task.abort();
            stderr_task.abort();
            return executed_error(
                CustomToolInvocationOutcome::Timeout,
                started,
                stdin_report,
                format!("subprocess timed out after {timeout:?}"),
                format!("{}: CustomToolTimeout after {timeout:?}", decl.name),
            );
        }
    };

    let stdout = match stdout_task.await {
        Ok(Ok(bytes)) => bytes,
        Ok(Err(e)) => {
            return executed_error_with_status(
                CustomToolInvocationOutcome::StdoutReadFailed,
                started,
                status.code(),
                exit_signal(&status),
                stdin_report,
                format!("stdout read failed: {e}"),
                format!("{}: stdout read failed: {e}", decl.name),
            );
        }
        Err(e) => {
            return executed_error_with_status(
                CustomToolInvocationOutcome::StdoutReadFailed,
                started,
                status.code(),
                exit_signal(&status),
                stdin_report,
                format!("stdout task failed: {e}"),
                format!("{}: stdout task failed: {e}", decl.name),
            );
        }
    };
    let stderr = match stderr_task.await {
        Ok(Ok(bytes)) => bytes,
        Ok(Err(e)) => {
            return executed_error_with_streams(
                CustomToolInvocationOutcome::StderrReadFailed,
                started,
                status.code(),
                exit_signal(&status),
                stdin_report,
                stdout,
                ByteCapture::empty(),
                format!("stderr read failed: {e}"),
                format!("{}: stderr read failed: {e}", decl.name),
            );
        }
        Err(e) => {
            return executed_error_with_streams(
                CustomToolInvocationOutcome::StderrReadFailed,
                started,
                status.code(),
                exit_signal(&status),
                stdin_report,
                stdout,
                ByteCapture::empty(),
                format!("stderr task failed: {e}"),
                format!("{}: stderr task failed: {e}", decl.name),
            );
        }
    };

    if !status.success() {
        let exit_info = exit_info(&status);
        let stderr_text = String::from_utf8_lossy(&stderr.bytes).into_owned();
        let content = if decl.expose_stderr {
            format!("{}: {exit_info}\nstderr:\n{stderr_text}", decl.name)
        } else {
            format!(
                "{}: {exit_info}; stderr captured in audit digest ({} bytes)",
                decl.name, stderr.bytes_total
            )
        };
        return ExecutedCustomTool {
            outcome: CustomToolInvocationOutcome::NonZeroExit,
            duration_ms: elapsed_ms(started),
            exit_code: status.code(),
            signal: exit_signal(&status),
            stdin: stdin_report,
            stdout,
            stderr,
            error: Some(exit_info),
            output_content: content,
            output_is_error: true,
        };
    }

    match serde_json::from_slice::<AdapterOutput>(&stdout.bytes) {
        Ok(parsed) => ExecutedCustomTool {
            outcome: if parsed.is_error == Some(true) {
                CustomToolInvocationOutcome::ToolError
            } else {
                CustomToolInvocationOutcome::Success
            },
            duration_ms: elapsed_ms(started),
            exit_code: status.code(),
            signal: exit_signal(&status),
            stdin: stdin_report,
            stdout,
            stderr,
            error: None,
            output_content: parsed.content,
            output_is_error: parsed.is_error.unwrap_or(false),
        },
        Err(_) => {
            let mut content = String::from_utf8_lossy(&stdout.bytes).into_owned();
            if stdout.truncated {
                content.push_str("\n[CUSTOM_TOOL_STDOUT_TRUNCATED]");
            }
            ExecutedCustomTool {
                outcome: CustomToolInvocationOutcome::Success,
                duration_ms: elapsed_ms(started),
                exit_code: status.code(),
                signal: exit_signal(&status),
                stdin: stdin_report,
                stdout,
                stderr,
                error: None,
                output_content: content,
                output_is_error: false,
            }
        }
    }
}

#[derive(Debug, Deserialize)]
struct AdapterOutput {
    content: String,
    #[serde(default)]
    is_error: Option<bool>,
}

fn executed_error(
    outcome: CustomToolInvocationOutcome,
    started: Instant,
    stdin: CaptureReport,
    error: String,
    output_content: String,
) -> ExecutedCustomTool {
    executed_error_with_status(outcome, started, None, None, stdin, error, output_content)
}

fn executed_error_with_status(
    outcome: CustomToolInvocationOutcome,
    started: Instant,
    exit_code: Option<i32>,
    signal: Option<i32>,
    stdin: CaptureReport,
    error: String,
    output_content: String,
) -> ExecutedCustomTool {
    executed_error_with_streams(
        outcome,
        started,
        exit_code,
        signal,
        stdin,
        ByteCapture::empty(),
        ByteCapture::empty(),
        error,
        output_content,
    )
}

#[allow(clippy::too_many_arguments)]
fn executed_error_with_streams(
    outcome: CustomToolInvocationOutcome,
    started: Instant,
    exit_code: Option<i32>,
    signal: Option<i32>,
    stdin: CaptureReport,
    stdout: ByteCapture,
    stderr: ByteCapture,
    error: String,
    output_content: String,
) -> ExecutedCustomTool {
    ExecutedCustomTool {
        outcome,
        duration_ms: elapsed_ms(started),
        exit_code,
        signal,
        stdin,
        stdout,
        stderr,
        error: Some(error),
        output_content,
        output_is_error: true,
    }
}

fn emit_custom_tool_audit(
    ctx: &Arc<HandlerContext>,
    session_id: &str,
    req: &CustomToolExecutionRequest,
    decl: &KernelCustomToolDecl,
    executed: &ExecutedCustomTool,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let kind = AuditEventKind::CustomToolInvoked {
        tool_name: req.tool_name.clone(),
        profile_name: decl.profile_name.clone(),
        execution_locality: decl.execution_locality.clone(),
        outcome: executed.outcome.as_str().to_owned(),
        duration_ms: executed.duration_ms,
        exit_code: executed.exit_code,
        signal: executed.signal,
        timeout_ms: Duration::from_secs(decl.timeout_secs as u64)
            .as_millis()
            .try_into()
            .unwrap_or(u64::MAX),
        command_argv_sha256: sha256_hex(&serde_json::to_vec(&decl.command).unwrap_or_default()),
        stdin_bytes_total: executed.stdin.bytes_total,
        stdin_sha256: executed.stdin.sha256.clone(),
        stdout_bytes_total: executed.stdout.bytes_total,
        stdout_bytes_captured: executed.stdout.report.bytes_captured,
        stdout_sha256: executed.stdout.report.sha256.clone(),
        stdout_truncated: executed.stdout.truncated,
        stderr_bytes_total: executed.stderr.bytes_total,
        stderr_bytes_captured: executed.stderr.report.bytes_captured,
        stderr_sha256: executed.stderr.report.sha256.clone(),
        stderr_truncated: executed.stderr.truncated,
        error: executed
            .error
            .as_ref()
            .map(|s| truncate_text(s, MAX_ERROR_BYTES)),
    };
    let _ = ctx.audit.emit(
        kind,
        Some(session_id),
        Some(&req.task_id),
        Some(&req.initiative_id),
    )?;
    Ok(())
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
    R: AsyncRead + Unpin + Send + 'static,
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

fn validate_input_against_schema(
    input: &serde_json::Value,
    schema: &serde_json::Value,
) -> Result<(), String> {
    validate_value_against_schema(input, schema, "$")
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

fn reject(request_id: Uuid, reason: impl Into<String>) -> CustomToolExecutionResponse {
    CustomToolExecutionResponse {
        request_id,
        accepted: false,
        content: None,
        is_error: None,
        reason: Some(reason.into()),
    }
}

fn is_kernel_owned_locality(locality: &str) -> bool {
    matches!(
        locality,
        LOCALITY_HOST_SUBPROCESS | LOCALITY_HOST_MCP | LOCALITY_REMOTE_MCP
    )
}

fn is_lower_tool_name(s: &str) -> bool {
    let bytes = s.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 64
        && bytes[0].is_ascii_lowercase()
        && bytes[1..]
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'_')
}

fn elapsed_ms(started: Instant) -> u64 {
    started.elapsed().as_millis().try_into().unwrap_or(u64::MAX)
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

fn exit_info(status: &std::process::ExitStatus) -> String {
    match status.code() {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_host_mcp_decl_from_signed_bundle_shape() {
        let raw = serde_json::json!({
            "tools": [{
                "name": "docs_search",
                "profile_name": "docs_tools",
                "command": ["/usr/local/bin/raxis-mcp-stdio-bridge", "search"],
                "execution_locality": "host_mcp",
                "schema": {
                    "type": "object",
                    "required": ["query"],
                    "properties": {
                        "query": { "type": "string", "maxLength": 80 }
                    },
                    "additionalProperties": false
                },
                "timeout_seconds": 15
            }]
        })
        .to_string();
        let decl = find_tool_decl(&raw, "docs_search").unwrap();
        assert_eq!(decl.profile_name, "docs_tools");
        assert_eq!(decl.execution_locality, "host_mcp");
        assert_eq!(decl.command[0], "/usr/local/bin/raxis-mcp-stdio-bridge");
        validate_input_against_schema(&serde_json::json!({"query": "raxis"}), &decl.schema)
            .unwrap();
        assert!(validate_input_against_schema(
            &serde_json::json!({"query": "x", "url": "no"}),
            &decl.schema
        )
        .unwrap_err()
        .contains("unknown property"));
    }

    #[test]
    fn rejects_missing_tool_in_bundle_lookup() {
        let raw = r#"{"tools":[{"name":"only_tool","profile_name":"repo_tools","command":["/bin/true"]}]}"#;
        let err = find_tool_decl(raw, "other_tool").unwrap_err();
        assert!(err.contains("not in the signed task bundle"));
    }
}

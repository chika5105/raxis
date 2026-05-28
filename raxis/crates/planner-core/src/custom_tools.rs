//! Custom-tool loader — reads kernel-approved
//! `[[profiles.<name>.custom_tool]]` declarations from a
//! plan-profile bundle and registers them as subprocess-executor
//! [`crate::tools::Tool`]s in the Executor registry.
//!
//! The kernel is the authority: it validates the signed `plan.toml`,
//! resolves the task's `profile = "..."`, merges inherited profile
//! tools, and stamps only the effective tool bundle into the spawned
//! Executor session. Reviewer and Orchestrator sessions never receive
//! this bundle.
//! ## Wire shape
//! Each custom tool decl carries:
//! * `name` — ASCII identifier matching `[A-Za-z0-9_]{1,64}`.
//! * `description` — Human-readable description (≤ 1 KiB).
//! * `command` — Absolute path to an executable inside the planner VM
//!   (typically `/usr/local/bin/<name>`), plus argv[1..]. The executor
//!   invokes it with the model-supplied JSON input on stdin.
//! * `schema` / `input_schema` — JSON Schema for the input.
//! * `timeout_seconds` / `timeout_secs` — Per-invocation deadline. Hard-capped at 300s
//!   (5 minutes) by the loader; values above the cap are rejected at
//!   registration time.
//!   The subprocess receives the model's `tool_use.input` as JSON on
//!   stdin, and is expected to write a `ToolOutput`-shaped JSON
//!   response to stdout (`{ "content": "...", "is_error": bool? }`).
//!   Non-zero exit codes are surfaced as
//!   [`crate::tools::ToolOutput::err`] without further interpretation.

use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;

use crate::tools::{Tool, ToolContext, ToolError, ToolOutput, ToolRegistry};

/// Kernel-stamped custom-tool bundle for one Executor session.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct CustomToolBundle {
    /// Effective tools resolved from the task profile inheritance chain.
    #[serde(default)]
    pub tools: Vec<CustomToolDecl>,
}

/// One operator-declared custom tool decl. Matches one
/// `[[profiles.<name>.custom_tool]]` table after the kernel has
/// resolved the task's profile.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CustomToolDecl {
    /// Tool name (registered into the planner registry under this key).
    pub name: String,
    /// Human-readable description shown to the model.
    pub description: String,
    /// argv. argv`0` is the path to the executable; subsequent
    /// entries are static prefix arguments. The model's input
    /// arrives on stdin, NOT in argv.
    pub command: Vec<String>,
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
    /// timeout_secs exceeded the policy hard cap.
    #[error("custom-tool {tool} timeout_secs={got} exceeds the policy hard cap (300s)")]
    TimeoutTooLong {
        /// Offending custom-tool name.
        tool: String,
        /// Operator-supplied timeout (seconds) that exceeded the cap.
        got: u32,
    },
    /// Name collision with an already-registered tool. The loader
    /// fails closed; operators must rename the custom tool or
    /// disable the colliding base tool via the role registry.
    #[error("custom-tool {tool} name collides with an already-registered tool")]
    NameCollision {
        /// Offending custom-tool name that collided with a built-in.
        tool: String,
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
    if decl.description.len() > 1024 {
        return Err(CustomToolError::DescriptionTooLong(decl.name.clone()));
    }
    if decl.command.is_empty() {
        return Err(CustomToolError::EmptyCommand(decl.name.clone()));
    }
    if decl.timeout_secs > 300 {
        return Err(CustomToolError::TimeoutTooLong {
            tool: decl.name.clone(),
            got: decl.timeout_secs,
        });
    }
    Ok(())
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
        registry.register(Arc::new(SubprocessTool {
            name: leak_static(decl.name.clone()),
            description: leak_static(decl.description.clone()),
            command: decl.command.clone(),
            input_schema: decl.input_schema.clone(),
            timeout: Duration::from_secs(decl.timeout_secs as u64),
        }));
    }
    Ok(())
}

/// Parse the JSON bundle the kernel stamps into one Executor
/// session. The stable envelope is:
///
/// ```json
/// { "tools": [ { "name": "...", "description": "...", "command": ["..."] } ] }
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

/// Concrete [`Tool`] impl that shells out to a configured argv with
/// the model's input on stdin.
pub struct SubprocessTool {
    name: &'static str,
    description: &'static str,
    command: Vec<String>,
    input_schema: serde_json::Value,
    timeout: Duration,
}

#[async_trait::async_trait]
impl Tool for SubprocessTool {
    fn name(&self) -> &'static str {
        self.name
    }
    fn description(&self) -> &'static str {
        self.description
    }
    fn input_schema(&self) -> serde_json::Value {
        self.input_schema.clone()
    }

    async fn execute(
        &self,
        input: &serde_json::Value,
        ctx: &ToolContext,
    ) -> Result<ToolOutput, ToolError> {
        let argv0 = self.command.first().ok_or_else(|| ToolError::Internal {
            tool: self.name.to_owned(),
            reason: "command argv was empty at execute time \
                     (registration-time guard regressed)"
                .to_owned(),
        })?;
        let argv_rest: &[String] = &self.command[1..];

        let mut cmd = Command::new(argv0);
        cmd.args(argv_rest)
            .current_dir(&ctx.workspace_root)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let mut child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) => {
                return Ok(ToolOutput::err(format!(
                    "{}: spawn {argv0:?} failed: {e}",
                    self.name,
                )))
            }
        };
        // Pipe the model's input to stdin, drop the writer, then
        // wait for output.
        if let Some(mut stdin) = child.stdin.take() {
            let body = match serde_json::to_vec(input) {
                Ok(b) => b,
                Err(e) => {
                    return Ok(ToolOutput::err(format!(
                        "{}: stdin JSON encode failed: {e}",
                        self.name,
                    )))
                }
            };
            match stdin.write_all(&body).await {
                Ok(()) => {}
                // EPIPE / BrokenPipe means the subprocess exited (or
                // closed its stdin) before consuming input. This is
                // normal — many tools ignore stdin entirely. Drop the
                // writer and fall through to wait_with_output so the
                // real exit code and stderr are captured.
                Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => {}
                Err(e) => {
                    return Ok(ToolOutput::err(format!(
                        "{}: stdin write failed: {e}",
                        self.name,
                    )));
                }
            }
            // Drop closes stdin so the subprocess sees EOF.
            drop(stdin);
        }
        let timeout = ctx.deadline.unwrap_or(self.timeout);
        let stdout = child.stdout.take();
        let stderr = child.stderr.take();
        let stdout_task = tokio::spawn(async move { read_pipe(stdout).await });
        let stderr_task = tokio::spawn(async move { read_pipe(stderr).await });

        let status = tokio::select! {
            status = child.wait() => match status {
                Ok(status) => status,
                Err(e) => {
                    stdout_task.abort();
                    stderr_task.abort();
                    return Ok(ToolOutput::err(format!(
                        "{}: wait failed: {e}",
                        self.name,
                    )));
                }
            },
            _ = tokio::time::sleep(timeout) => {
                let _ = child.kill().await;
                let _ = child.wait().await;
                stdout_task.abort();
                stderr_task.abort();
                return Ok(ToolOutput::err(format!(
                    "{}: subprocess timed out after {timeout:?}",
                    self.name,
                )));
            }
        };

        let stdout = match stdout_task.await {
            Ok(Ok(bytes)) => bytes,
            Ok(Err(e)) => {
                return Ok(ToolOutput::err(format!(
                    "{}: stdout read failed: {e}",
                    self.name,
                )));
            }
            Err(e) => {
                return Ok(ToolOutput::err(format!(
                    "{}: stdout task failed: {e}",
                    self.name,
                )));
            }
        };
        let stderr = match stderr_task.await {
            Ok(Ok(bytes)) => bytes,
            Ok(Err(e)) => {
                return Ok(ToolOutput::err(format!(
                    "{}: stderr read failed: {e}",
                    self.name,
                )));
            }
            Err(e) => {
                return Ok(ToolOutput::err(format!(
                    "{}: stderr task failed: {e}",
                    self.name,
                )));
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
            return Ok(ToolOutput::err(format!(
                "{name}: {exit_info}\nstderr:\n{stderr}",
                name = self.name,
                stderr = String::from_utf8_lossy(&stderr),
            )));
        }
        // Try to parse stdout as a JSON ToolOutput envelope. Fall
        // back to wrapping the raw stdout as a success body if the
        // tool didn't emit JSON.
        if let Ok(parsed) = serde_json::from_slice::<ToolOutput>(&stdout) {
            Ok(parsed)
        } else {
            Ok(ToolOutput::ok(
                String::from_utf8_lossy(&stdout).into_owned(),
            ))
        }
    }
}

async fn read_pipe<R>(pipe: Option<R>) -> std::io::Result<Vec<u8>>
where
    R: tokio::io::AsyncRead + Unpin + Send + 'static,
{
    let mut bytes = Vec::new();
    if let Some(mut pipe) = pipe {
        pipe.read_to_end(&mut bytes).await?;
    }
    Ok(bytes)
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

    #[test]
    fn validate_rejects_invalid_name() {
        let bad = CustomToolDecl {
            name: "has-dash".to_owned(),
            description: "x".to_owned(),
            command: vec!["/bin/true".to_owned()],
            input_schema: serde_json::json!({}),
            timeout_secs: 10,
        };
        match validate_custom_tool(&bad).unwrap_err() {
            CustomToolError::InvalidName(n) => assert_eq!(n, "has-dash"),
            other => panic!("expected InvalidName, got {other:?}"),
        }
    }

    #[test]
    fn validate_rejects_uppercase_or_digit_start() {
        for name in ["Tool".to_owned(), "1tool".to_owned(), "a".repeat(49)] {
            let bad = CustomToolDecl {
                name,
                description: "valid custom tool description".to_owned(),
                command: vec!["/bin/true".to_owned()],
                input_schema: serde_json::json!({}),
                timeout_secs: 10,
            };
            assert!(matches!(
                validate_custom_tool(&bad),
                Err(CustomToolError::InvalidName(_))
            ));
        }
    }

    #[test]
    fn validate_rejects_empty_command() {
        let bad = CustomToolDecl {
            name: "x".to_owned(),
            description: "y".to_owned(),
            command: vec![],
            input_schema: serde_json::json!({}),
            timeout_secs: 10,
        };
        match validate_custom_tool(&bad).unwrap_err() {
            CustomToolError::EmptyCommand(_) => {}
            other => panic!("expected EmptyCommand, got {other:?}"),
        }
    }

    #[test]
    fn validate_rejects_timeout_above_300s() {
        let bad = CustomToolDecl {
            name: "x".to_owned(),
            description: "y".to_owned(),
            command: vec!["/bin/true".to_owned()],
            input_schema: serde_json::json!({}),
            timeout_secs: 600,
        };
        match validate_custom_tool(&bad).unwrap_err() {
            CustomToolError::TimeoutTooLong { got, .. } => {
                assert_eq!(got, 600);
            }
            other => panic!("expected TimeoutTooLong, got {other:?}"),
        }
    }

    #[test]
    fn validate_rejects_description_too_long() {
        let bad = CustomToolDecl {
            name: "x".to_owned(),
            description: "y".repeat(1025),
            command: vec!["/bin/true".to_owned()],
            input_schema: serde_json::json!({}),
            timeout_secs: 10,
        };
        match validate_custom_tool(&bad).unwrap_err() {
            CustomToolError::DescriptionTooLong(_) => {}
            other => panic!("expected DescriptionTooLong, got {other:?}"),
        }
    }

    #[test]
    fn load_rejects_name_collision_with_base_tool() {
        // `read_file` is registered by `build_executor_registry`.
        let mut registry = crate::tools::build_executor_registry();
        let decls = vec![CustomToolDecl {
            name: "read_file".to_owned(),
            description: "operator collision".to_owned(),
            command: vec!["/bin/echo".to_owned()],
            input_schema: serde_json::json!({}),
            timeout_secs: 10,
        }];
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
            r#"{"tools":[{"name":"unity_build_player","description":"Build Unity player through local adapter","command":["/usr/local/bin/raxis-tool-mcp","unity","build-player"],"schema":{"type":"object"},"timeout_seconds":120}]}"#,
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
            CustomToolDecl {
                name: "valid_a".to_owned(),
                description: "ok".to_owned(),
                command: vec!["/bin/true".to_owned()],
                input_schema: serde_json::json!({}),
                timeout_secs: 10,
            },
            CustomToolDecl {
                name: "has-dash".to_owned(), // invalid
                description: "ok".to_owned(),
                command: vec!["/bin/true".to_owned()],
                input_schema: serde_json::json!({}),
                timeout_secs: 10,
            },
        ];
        let _ = load_custom_tools(&mut registry, &decls).unwrap_err();
        assert!(
            registry.get("valid_a").is_none(),
            "atomicity: a partial failure must not register the first \
             decl, otherwise the operator's debug surface is half-applied"
        );
    }

    #[tokio::test]
    async fn subprocess_tool_returns_stdout_as_ok_when_not_json() {
        let mut registry = ToolRegistry::new();
        let decl = CustomToolDecl {
            name: "echo_tool".to_owned(),
            description: "echo stdin to stdout".to_owned(),
            command: vec!["/bin/cat".to_owned()],
            input_schema: serde_json::json!({}),
            timeout_secs: 5,
        };
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
        let decl = CustomToolDecl {
            name: "json_emitter".to_owned(),
            description: "emit a JSON ToolOutput envelope".to_owned(),
            command: vec![
                "/bin/sh".to_owned(),
                "-c".to_owned(),
                r#"echo '{"content":"hello-from-tool","is_error":false}'"#.to_owned(),
            ],
            input_schema: serde_json::json!({}),
            timeout_secs: 5,
        };
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
        let decl = CustomToolDecl {
            name: "fail_tool".to_owned(),
            description: "always fails".to_owned(),
            command: vec![
                "/bin/sh".to_owned(),
                "-c".to_owned(),
                "echo 'oh no' >&2; exit 7".to_owned(),
            ],
            input_schema: serde_json::json!({}),
            timeout_secs: 5,
        };
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

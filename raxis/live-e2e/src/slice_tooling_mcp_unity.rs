//! Live-e2e slice for BYO tools wrapping existing scripts and MCP-style
//! local services.
//!
//! This deliberately models a Unity Editor MCP server without making
//! MCP a first-class authority channel. The operator-facing pattern is
//! one narrow custom tool per existing operation, executor-only, with
//! short timeouts. There is no `mcp_call_anything`,
//! `run_any_script`, or discovery tool.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use raxis_planner_core::{
    build_executor_registry, build_reviewer_registry, load_custom_tools, CustomToolDecl,
    ToolContext, ToolOutput,
};
use serde_json::json;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Mutex;

pub async fn run() -> Result<()> {
    let workspace = tempfile::tempdir().context("temp workspace")?;
    let socket_path = workspace.path().join("unity-editor-mcp.sock");
    let calls = Arc::new(Mutex::new(Vec::new()));
    let server = spawn_unity_mcp_fixture(&socket_path, 3, Arc::clone(&calls))?;

    let mut registry = build_executor_registry();
    let exe = std::env::current_exe().context("current executable path")?;
    let decls = unity_tool_decls(&exe, &socket_path);
    load_custom_tools(&mut registry, &decls).context("load executor custom tools")?;

    // Defense in depth around INV-PLANNER-HARNESS-04/06: custom tools
    // appear only when the kernel stamps an Executor bundle.
    let reviewer_registry = build_reviewer_registry();
    for decl in &decls {
        if reviewer_registry.get(&decl.name).is_some() {
            bail!("reviewer registry unexpectedly contains {}", decl.name);
        }
    }
    if registry.get("mcp_discover").is_some() || registry.get("mcp_call").is_some() {
        bail!("generic MCP tool surfaced; tooling must stay operation-specific");
    }

    let ctx = ToolContext::for_workspace(workspace.path());
    assert_generic_script_tool_round_trip(workspace.path(), &ctx).await?;

    let scenes = invoke(
        &registry,
        &ctx,
        "unity_list_scenes",
        json!({ "include_disabled": false }),
    )
    .await?;
    assert_content_contains(&scenes, "Assets/Scenes/Main.unity")?;

    let tests = invoke(
        &registry,
        &ctx,
        "unity_run_playmode_tests",
        json!({ "filter": "smoke" }),
    )
    .await?;
    assert_content_contains(&tests, "\"failed\": 0")?;

    let build = invoke(
        &registry,
        &ctx,
        "unity_build_player",
        json!({
            "target": "ios",
            "scene": "Assets/Scenes/Main.unity"
        }),
    )
    .await?;
    assert_content_contains(&build, "Builds/iOS/RaxisDemo.ipa")?;

    server
        .await
        .context("unity mcp fixture join")?
        .context("unity mcp fixture")?;
    let observed = calls.lock().await.clone();
    if observed
        != [
            "unity.listScenes",
            "unity.runPlaymodeTests",
            "unity.buildPlayer",
        ]
    {
        bail!("unexpected MCP call sequence: {observed:?}");
    }

    tracing::info!("tooling-mcp-unity slice passed");
    Ok(())
}

async fn assert_generic_script_tool_round_trip(
    workspace_path: &Path,
    ctx: &ToolContext,
) -> Result<()> {
    let script_path = workspace_path.join("repo-codegen-check");
    fs::write(
        &script_path,
        r#"#!/bin/sh
set -eu
payload="$(cat)"
case "$payload" in
  *\"scope\"*) ;;
  *) printf '{"content":"missing scope","is_error":true}\n'; exit 0 ;;
esac
printf '{"content":"generic script wrapper received a bounded request","is_error":false}\n'
"#,
    )
    .with_context(|| format!("write {}", script_path.display()))?;
    let mut perms = fs::metadata(&script_path)
        .with_context(|| format!("stat {}", script_path.display()))?
        .permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&script_path, perms)
        .with_context(|| format!("chmod {}", script_path.display()))?;

    let mut registry = build_executor_registry();
    let decl = custom_tool_decl(
        "repo_tools",
        "repo_codegen_check",
        "Run a pre-existing repository code-generation check wrapper.",
        vec![script_path.display().to_string()],
        json!({
            "type": "object",
            "properties": {
                "scope": { "type": "string", "maxLength": 120 }
            },
            "additionalProperties": false
        }),
        5,
    );
    load_custom_tools(&mut registry, &[decl]).context("load generic script custom tool")?;
    if registry.get("run_any_script").is_some() {
        bail!("generic script launcher surfaced; custom tools must stay operation-specific");
    }

    let output = invoke(
        &registry,
        ctx,
        "repo_codegen_check",
        json!({ "scope": "mobile-client" }),
    )
    .await?;
    assert_content_contains(&output, "generic script wrapper received a bounded request")?;
    Ok(())
}

pub async fn run_wrapper_from_env() -> Result<()> {
    let mut args = std::env::args().skip(2);
    let socket_path = args
        .next()
        .ok_or_else(|| anyhow!("missing socket path argument"))?;
    let method = args
        .next()
        .ok_or_else(|| anyhow!("missing MCP method argument"))?;
    if args.next().is_some() {
        bail!("unexpected extra wrapper arguments");
    }

    let mut stdin = Vec::new();
    tokio::io::stdin()
        .read_to_end(&mut stdin)
        .await
        .context("read wrapper stdin")?;
    let params = if stdin.is_empty() {
        json!({})
    } else {
        serde_json::from_slice(&stdin).context("parse wrapper JSON stdin")?
    };

    let output = match tokio::time::timeout(
        Duration::from_secs(3),
        call_unity_mcp(Path::new(&socket_path), &method, params),
    )
    .await
    {
        Ok(Ok(result)) => ToolOutput::ok(format!(
            "Unity MCP {method} result:\n{}",
            serde_json::to_string_pretty(&result).unwrap_or_else(|_| result.to_string())
        )),
        Ok(Err(e)) => ToolOutput::err(format!("Unity MCP {method} failed: {e}")),
        Err(_) => ToolOutput::err(format!("Unity MCP {method} timed out after 3s")),
    };

    let stdout = serde_json::to_vec(&output).context("encode ToolOutput")?;
    tokio::io::stdout()
        .write_all(&stdout)
        .await
        .context("write ToolOutput")?;
    Ok(())
}

fn unity_tool_decls(exe: &Path, socket_path: &Path) -> Vec<CustomToolDecl> {
    let base_command = |method: &str| {
        vec![
            exe.display().to_string(),
            "__tooling_mcp_wrapper".to_owned(),
            socket_path.display().to_string(),
            method.to_owned(),
        ]
    };
    vec![
        custom_tool_decl(
            "unity_mcp_tools",
            "unity_list_scenes",
            "List scenes known to the local Unity Editor MCP adapter.",
            base_command("unity.listScenes"),
            json!({
                "type": "object",
                "properties": {
                    "include_disabled": { "type": "boolean" }
                },
                "additionalProperties": false
            }),
            5,
        ),
        custom_tool_decl(
            "unity_mcp_tools",
            "unity_run_playmode_tests",
            "Run bounded Unity playmode tests through the local MCP adapter.",
            base_command("unity.runPlaymodeTests"),
            json!({
                "type": "object",
                "properties": {
                    "filter": { "type": "string", "maxLength": 80 }
                },
                "additionalProperties": false
            }),
            10,
        ),
        custom_tool_decl(
            "unity_mcp_tools",
            "unity_build_player",
            "Build one Unity player target through the local MCP adapter.",
            base_command("unity.buildPlayer"),
            json!({
                "type": "object",
                "required": ["target", "scene"],
                "properties": {
                    "target": {
                        "type": "string",
                        "enum": ["ios", "android"]
                    },
                    "scene": {
                        "type": "string",
                        "maxLength": 240
                    }
                },
                "additionalProperties": false
            }),
            30,
        ),
    ]
}

fn custom_tool_decl(
    profile_name: impl Into<String>,
    name: impl Into<String>,
    description: impl Into<String>,
    command: Vec<String>,
    input_schema: serde_json::Value,
    timeout_secs: u32,
) -> CustomToolDecl {
    CustomToolDecl {
        name: name.into(),
        profile_name: profile_name.into(),
        description: description.into(),
        command,
        execution_locality: "guest_subprocess".to_owned(),
        input_schema,
        timeout_secs,
        stdin_max_bytes: 262_144,
        stdout_max_bytes: 65_536,
        stderr_max_bytes: 16_384,
        expose_stderr: true,
    }
}

async fn invoke(
    registry: &raxis_planner_core::ToolRegistry,
    ctx: &ToolContext,
    name: &str,
    input: serde_json::Value,
) -> Result<ToolOutput> {
    let tool = registry
        .get(name)
        .ok_or_else(|| anyhow!("custom tool {name:?} not registered"))?;
    let output = tool
        .execute(&input, ctx)
        .await
        .map_err(|e| anyhow!("custom tool {name:?} failed internally: {e}"))?;
    if output.is_error == Some(true) {
        bail!("custom tool {name:?} returned error: {}", output.content);
    }
    Ok(output)
}

fn assert_content_contains(output: &ToolOutput, needle: &str) -> Result<()> {
    if !output.content.contains(needle) {
        bail!(
            "tool output did not contain {needle:?}; content was:\n{}",
            output.content
        );
    }
    Ok(())
}

fn spawn_unity_mcp_fixture(
    socket_path: &Path,
    expected_calls: usize,
    calls: Arc<Mutex<Vec<String>>>,
) -> Result<tokio::task::JoinHandle<Result<()>>> {
    let _ = std::fs::remove_file(socket_path);
    let listener = UnixListener::bind(socket_path)
        .with_context(|| format!("bind {}", socket_path.display()))?;
    Ok(tokio::spawn(async move {
        for _ in 0..expected_calls {
            let (stream, _) = listener.accept().await.context("accept MCP client")?;
            handle_mcp_connection(stream, Arc::clone(&calls)).await?;
        }
        Ok(())
    }))
}

async fn handle_mcp_connection(stream: UnixStream, calls: Arc<Mutex<Vec<String>>>) -> Result<()> {
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .await
        .context("read MCP request")?;
    let request: serde_json::Value = serde_json::from_str(&line).context("parse MCP request")?;
    let method = request
        .get("method")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("MCP request missing string method"))?;
    calls.lock().await.push(method.to_owned());

    let params = request.get("params").cloned().unwrap_or_else(|| json!({}));
    let result = match method {
        "unity.listScenes" => json!({
            "scenes": [
                "Assets/Scenes/Main.unity",
                "Assets/Scenes/CombatArena.unity"
            ],
            "active": "Assets/Scenes/Main.unity"
        }),
        "unity.runPlaymodeTests" => json!({
            "filter": params.get("filter").and_then(|v| v.as_str()).unwrap_or("all"),
            "passed": 12,
            "failed": 0,
            "duration_ms": 824
        }),
        "unity.buildPlayer" => json!({
            "target": params.get("target").and_then(|v| v.as_str()).unwrap_or("unknown"),
            "scene": params.get("scene").and_then(|v| v.as_str()).unwrap_or("unknown"),
            "artifact": "Builds/iOS/RaxisDemo.ipa",
            "duration_ms": 1432
        }),
        other => json!({
            "error": format!("unknown Unity MCP method {other}")
        }),
    };
    let response = json!({ "result": result });
    let mut stream = reader.into_inner();
    stream
        .write_all(response.to_string().as_bytes())
        .await
        .context("write MCP response")?;
    stream.write_all(b"\n").await.context("write newline")?;
    Ok(())
}

async fn call_unity_mcp(
    socket_path: &Path,
    method: &str,
    params: serde_json::Value,
) -> Result<serde_json::Value> {
    let mut stream = UnixStream::connect(socket_path)
        .await
        .with_context(|| format!("connect {}", socket_path.display()))?;
    let request = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params,
    });
    stream
        .write_all(request.to_string().as_bytes())
        .await
        .context("write MCP request")?;
    stream.write_all(b"\n").await.context("write newline")?;

    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .await
        .context("read MCP response")?;
    let response: serde_json::Value = serde_json::from_str(&line).context("parse MCP response")?;
    if let Some(error) = response.get("error") {
        bail!("MCP error: {error}");
    }
    let result = response
        .get("result")
        .cloned()
        .ok_or_else(|| anyhow!("MCP response missing result"))?;
    if let Some(error) = result.get("error") {
        bail!("{error}");
    }
    Ok(result)
}

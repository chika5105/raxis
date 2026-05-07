//! Slice 1 — real `raxis-gateway` + real Anthropic API.
//!
//! Goal: prove that the gateway round-trip path the kernel relies on
//! actually delivers a real LLM response from Anthropic with the dev
//! API key, end-to-end.
//!
//! Wire shape (mirrors what the kernel's gateway supervisor does):
//!
//!   1. Mint an ephemeral data dir with a real `policy.toml` + a
//!      real `providers/anthropic-prod.toml` (mode 0600) populated
//!      with the dev key from `.env`.
//!   2. Bind a `UnixListener` on a tempdir (this stands in for the
//!      kernel's `gateway.sock`) and run `run_gateway_with_backend`
//!      in-process with a REAL `HttpBackend` (the production
//!      backend; not `MockBackend`).
//!   3. Drive a real `FetchRequest { url:
//!      "https://api.anthropic.com/v1/messages", body: <messages-API
//!      JSON> }` through the gateway.
//!   4. Read the `FetchResponse` and assert:
//!      * `status_code == Some(200)` — Anthropic accepted the call.
//!      * Body parses as JSON with a non-empty `content[0].text`.
//!      * `error.is_none()`.
//!   5. Drop the listener; the gateway run-future returns `Ok(())`.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Result};
use raxis_gateway::{parse_gateway_env, run_gateway_with_backend};
use raxis_gateway_substrate::Backend;
use raxis_ipc::message::{FetchKind, GatewayMessage};
use raxis_ipc::{read_frame, write_frame};
use tokio::net::UnixListener;
use uuid::Uuid;

use crate::env_file::EnvMap;
use crate::require_env;

const GATEWAY_TOKEN: &str =
    "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";

pub(crate) async fn run(env: &EnvMap) -> Result<()> {
    let api_key = require_env(env, "ANTHROPIC-API-DEV-KEY")?;
    tracing::info!("slice gateway-anthropic: starting");

    // 1. Build data dir.
    let data_tmp = build_data_dir(api_key)?;
    let data_dir = data_tmp.path().to_owned();

    // 2. Bind kernel-side socket.
    // macOS UDS paths are capped at ~104 chars; keep the basename
    // short and use the system temp dir (NOT cargo target dir).
    let kernel_sock = std::env::temp_dir().join(format!(
        "rxe2e-{}.sock",
        Uuid::new_v4().simple(),
    ));
    let _ = std::fs::remove_file(&kernel_sock);
    let listener = UnixListener::bind(&kernel_sock)
        .map_err(|e| anyhow!("bind kernel sock: {e}"))?;

    // 3. Spawn gateway with real HttpBackend.
    let env_parsed = parse_gateway_env(
        GATEWAY_TOKEN,
        &kernel_sock.display().to_string(),
        &data_dir.display().to_string(),
    )
    .map_err(|e| anyhow!("parse_gateway_env: {e:?}"))?;
    let backend: Arc<dyn Backend> = Arc::new(raxis_gateway::HttpBackend::new());
    let gateway_task = tokio::spawn(async move {
        run_gateway_with_backend(env_parsed, backend).await
    });

    // 4. Accept the gateway's client connection.
    let (mut stream, _addr) = tokio::time::timeout(
        Duration::from_secs(5),
        listener.accept(),
    )
    .await
    .map_err(|_| anyhow!("gateway never connected within 5s"))?
    .map_err(|e| anyhow!("accept: {e}"))?;

    // 5. Drain handshake.
    let ready = tokio::time::timeout(
        Duration::from_secs(5),
        read_frame::<_, GatewayMessage>(&mut stream),
    )
    .await
    .map_err(|_| anyhow!("gateway handshake timeout"))?
    .map_err(|e| anyhow!("read handshake: {e}"))?;
    match ready {
        GatewayMessage::GatewayReady { gateway_token } => {
            if gateway_token != GATEWAY_TOKEN {
                return Err(anyhow!("handshake token mismatch: got {gateway_token:?}"));
            }
        }
        other => return Err(anyhow!("first frame must be GatewayReady, got {other:?}")),
    }
    tracing::info!("slice gateway-anthropic: handshake ok");

    // 6. Real Anthropic call. The `messages` API spec requires
    // `model`, `max_tokens`, `messages`. Use a minuscule prompt
    // / max_tokens to keep cost negligible.
    let body = serde_json::json!({
        "model":      "claude-haiku-4-5",
        "max_tokens": 32,
        "messages": [{
            "role":    "user",
            "content": "Reply with exactly the word: ok",
        }],
    });
    let body_bytes = serde_json::to_vec(&body)?;
    let req = GatewayMessage::FetchRequest {
        gateway_token: GATEWAY_TOKEN.to_owned(),
        fetch_id:      Uuid::new_v4(),
        fetch_kind:    FetchKind::Inference,
        url:           "https://api.anthropic.com/v1/messages".to_owned(),
        method:        "POST".to_owned(),
        headers: vec![
            ("anthropic-version".to_owned(), "2023-06-01".to_owned()),
            ("content-type".to_owned(),      "application/json".to_owned()),
        ],
        body_bytes,
        timeout_ms: 30_000,
        session_id: None,
        task_id:    None,
    };
    let req_id = match &req {
        GatewayMessage::FetchRequest { fetch_id, .. } => *fetch_id,
        _ => unreachable!(),
    };
    write_frame(&mut stream, &req).await
        .map_err(|e| anyhow!("write FetchRequest: {e}"))?;

    // 7. Read the response.
    let resp = tokio::time::timeout(
        Duration::from_secs(40),
        read_frame::<_, GatewayMessage>(&mut stream),
    )
    .await
    .map_err(|_| anyhow!("Anthropic response timeout (40s)"))?
    .map_err(|e| anyhow!("read FetchResponse: {e}"))?;

    match resp {
        GatewayMessage::FetchResponse {
            fetch_id, status_code, body_bytes, error, ..
        } => {
            if fetch_id != req_id {
                return Err(anyhow!("fetch_id round-trip mismatch"));
            }
            if let Some(e) = error {
                return Err(anyhow!("Anthropic call returned error: {e}"));
            }
            let code = status_code.ok_or_else(|| anyhow!("no status_code"))?;
            if code != 200 {
                let body_str = body_bytes
                    .as_ref()
                    .map(|b| String::from_utf8_lossy(b).into_owned())
                    .unwrap_or_default();
                return Err(anyhow!(
                    "Anthropic returned status {code}; body: {body_str}",
                ));
            }
            let body = body_bytes.ok_or_else(|| anyhow!("no body"))?;
            let json: serde_json::Value = serde_json::from_slice(&body)
                .map_err(|e| anyhow!("body is not JSON: {e}; body={:?}",
                    String::from_utf8_lossy(&body)))?;
            // Validate the response shape.
            let content = json.get("content")
                .and_then(|c| c.as_array())
                .ok_or_else(|| anyhow!("no `content` array in {json}"))?;
            if content.is_empty() {
                return Err(anyhow!("`content` is empty in {json}"));
            }
            let text = content[0].get("text")
                .and_then(|t| t.as_str())
                .ok_or_else(|| anyhow!("first content has no `text`: {json}"))?;
            tracing::info!(
                "slice gateway-anthropic: Anthropic replied: {:?}",
                text.chars().take(80).collect::<String>(),
            );
            if text.trim().is_empty() {
                return Err(anyhow!("response text is empty"));
            }
        }
        other => return Err(anyhow!("expected FetchResponse, got {other:?}")),
    }

    // 8. Cleanup.
    drop(stream);
    drop(listener);
    let _ = std::fs::remove_file(&kernel_sock);
    let _ = tokio::time::timeout(Duration::from_secs(5), gateway_task).await;
    tracing::info!("slice gateway-anthropic: PASS");
    Ok(())
}

// ---------------------------------------------------------------------------
// Data-dir builder — mirrors `gateway/tests/gateway_roundtrip.rs::build_data_dir`
// but uses the real Anthropic dev key.
// ---------------------------------------------------------------------------

/// Public alias used by `slice_egress_enforcement` so it can lean on
/// the same fixture (egress allowlist already pins to
/// `*.anthropic.com`).
pub(crate) fn build_data_dir_for_egress(api_key: &str) -> Result<tempfile::TempDir> {
    build_data_dir(api_key)
}

fn build_data_dir(api_key: &str) -> Result<tempfile::TempDir> {
    let tmp = tempfile::tempdir()?;
    let dd = tmp.path();
    std::fs::create_dir_all(dd.join("policy"))?;
    std::fs::create_dir_all(dd.join("providers"))?;

    let op_key   = raxis_test_support::ephemeral_signing_key([0xCCu8; 32]);
    let op_pk_hex = raxis_test_support::pubkey_hex(&op_key);
    let op_fp    = raxis_genesis_tools::pubkey_fingerprint(
        &hex::decode(&op_pk_hex).map_err(|e| anyhow!("decode op pk: {e}"))?,
    );
    let op_cert  = raxis_test_support::ephemeral_cert_with_key(
        &op_key,
        raxis_test_support::CertOpts {
            display_name: "raxis-live-e2e-operator".to_owned(),
            permitted_ops: vec!["CreateInitiative".into()],
            ..raxis_test_support::CertOpts::default()
        },
    );
    let cert_subtable = toml::to_string(&op_cert).map_err(|e| anyhow!("serialise cert: {e}"))?;
    let policy = format!(
        r#"[meta]
epoch     = 1
signed_by = "{op_fp}"
signed_at = 1700000000

[authority]
authority_pubkey = "{a}"
quality_pubkey   = "{b}"

[escalation_policy]
timeout_secs         = 3600
window_secs          = 300
max_per_window       = 5
quarantine_threshold = 3

[sessions]
default_ttl_secs       = 86400
max_ttl_secs           = 604800
allowed_worktree_roots = ["/tmp/raxis-live-e2e"]

[delegations]
max_ttl_secs = 86400

[budget]
cost_per_touched_path = 1
max_cost_per_task     = 10000

[budget.base_cost_per_intent_kind]
SingleCommit     = 10
IntegrationMerge = 50
CompleteTask     = 5
ReportFailure    = 1

[[operators.entries]]
pubkey_fingerprint = "{op_fp}"
display_name       = "raxis-live-e2e-operator"
pubkey_hex         = "{op_pk_hex}"
permitted_ops      = ["CreateInitiative"]

[operators.entries.cert]
{cert_subtable}

[[lanes]]
lane_id              = "default"
max_concurrent_tasks = 4
max_cost_per_epoch   = 10000
priority             = 100

[egress]
domains  = []
patterns = ["*.anthropic.com"]
max_fetches_per_window = 100

[[providers]]
provider_id      = "anthropic-prod"
kind             = "Anthropic"
credentials_file = "anthropic-prod.toml"
"#,
        a = "a".repeat(64),
        b = "b".repeat(64),
    );
    std::fs::write(dd.join("policy/policy.toml"), policy)?;

    // Real provider credentials with the dev key. mode 0600 — the
    // V2 `FileCredentialBackend` rejects 0644.
    let creds_path: PathBuf = dd.join("providers/anthropic-prod.toml");
    std::fs::write(
        &creds_path,
        format!(
            "api_key = \"{}\"\n\
             auth_header = \"x-api-key\"\n\
             auth_prefix = \"\"\n",
            api_key,
        ),
    )?;
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&creds_path)?.permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(&creds_path, perms)?;
    }
    Ok(tmp)
}

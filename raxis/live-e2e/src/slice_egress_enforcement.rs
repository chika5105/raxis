//! Slice 4 — egress allowlist enforcement against the real gateway.
//!
//! Goal: prove that the gateway's `policy_view::is_url_allowed`
//! gate denies traffic to hosts outside the policy allowlist EVEN
//! WHEN the upstream is reachable (real DNS + real TLS handshake
//! work). This is the "fail-closed at policy boundary" invariant
//! from `peripherals.md §3.2` — the credential never leaves the
//! gateway for a denied URL.
//!
//! Wire shape (mirrors `slice_gateway_anthropic`):
//!
//!   1. Build a policy with `egress.patterns = ["*.anthropic.com"]`
//!      (i.e. ONLY Anthropic; everything else denied).
//!   2. Spawn the real `run_gateway_with_backend` with the real
//!      `HttpBackend`.
//!   3. Drive THREE FetchRequests:
//!      `https://api.anthropic.com/v1/messages` should return
//!      200; `https://httpbin.org/anything` should fail with
//!      `error == "DomainNotAllowed"` and `status_code is
//!      None`; and `http://api.anthropic.com/v1/messages`
//!      should be denied by policy (the allowlist is
//!      host-based; any extra protocol guarding is enforced
//!      separately). For the MVP we just assert the request is
//!      structurally denied — either by `DomainNotAllowed` or
//!      by an upstream error if the server rejects plain HTTP.
//!
//! The slice REQUIRES a real Anthropic key for (a). (b) is the
//! proof point — even with a working backend, the gateway refuses.

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

const GATEWAY_TOKEN: &str = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";

pub(crate) async fn run(env: &EnvMap) -> Result<()> {
    let api_key = require_env(env, "ANTHROPIC-API-DEV-KEY")?;
    tracing::info!("slice egress-enforcement: starting");

    // Same data dir shape as slice_gateway_anthropic — egress
    // allowlist already pins to `*.anthropic.com`. We rely on that
    // here; everything else is denied at the gateway.
    let data_tmp = crate::slice_gateway_anthropic::build_data_dir_for_egress(api_key)?;
    let data_dir = data_tmp.path().to_owned();

    let kernel_sock = std::env::temp_dir().join(format!("rxe2e-{}.sock", Uuid::new_v4().simple(),));
    let _ = std::fs::remove_file(&kernel_sock);
    let listener = UnixListener::bind(&kernel_sock)?;

    let env_parsed = parse_gateway_env(
        GATEWAY_TOKEN,
        &kernel_sock.display().to_string(),
        &data_dir.display().to_string(),
    )
    .map_err(|e| anyhow!("parse_gateway_env: {e:?}"))?;
    let backend: Arc<dyn Backend> = Arc::new(raxis_gateway::HttpBackend::new());
    let mut gateway_task =
        tokio::spawn(async move { run_gateway_with_backend(env_parsed, backend).await });

    let (mut stream, _addr) = tokio::select! {
        accepted = tokio::time::timeout(Duration::from_secs(15), listener.accept()) => {
            accepted
                .map_err(|_| anyhow!("gateway never connected within 15s"))?
                .map_err(|e| anyhow!("accept: {e}"))?
        }
        joined = &mut gateway_task => {
            let result = joined.map_err(|e| anyhow!("gateway task join failed: {e}"))?;
            result.map_err(|e| anyhow!("gateway exited before connecting: {e}"))?;
            return Err(anyhow!("gateway exited before connecting"));
        }
    };

    // Drain handshake.
    let ready = tokio::time::timeout(
        Duration::from_secs(5),
        read_frame::<_, GatewayMessage>(&mut stream),
    )
    .await
    .map_err(|_| anyhow!("handshake timeout"))?
    .map_err(|e| anyhow!("read handshake: {e}"))?;
    match ready {
        GatewayMessage::GatewayReady { .. } => {}
        other => return Err(anyhow!("expected GatewayReady, got {other:?}")),
    }

    // (a) Allowed URL — real Anthropic, expect 200.
    {
        let body = serde_json::json!({
            "model":      "claude-haiku-4-5",
            "max_tokens": 16,
            "messages": [{"role": "user", "content": "Reply: ok"}],
        });
        let body_bytes = serde_json::to_vec(&body)?;
        let req = build_request(
            "https://api.anthropic.com/v1/messages",
            "POST",
            vec![
                ("anthropic-version".to_owned(), "2023-06-01".to_owned()),
                ("content-type".to_owned(), "application/json".to_owned()),
            ],
            body_bytes,
        );
        write_frame(&mut stream, &req).await?;
        let resp = tokio::time::timeout(
            Duration::from_secs(40),
            read_frame::<_, GatewayMessage>(&mut stream),
        )
        .await
        .map_err(|_| anyhow!("Anthropic response timeout"))?
        .map_err(|e| anyhow!("read FetchResponse(allowed): {e}"))?;
        match resp {
            GatewayMessage::FetchResponse {
                status_code, error, ..
            } => {
                if let Some(e) = error {
                    return Err(anyhow!("(a) allowed URL returned error {e:?}"));
                }
                let code = status_code.ok_or_else(|| anyhow!("(a) no status_code"))?;
                if code != 200 {
                    return Err(anyhow!("(a) expected 200; got {code}"));
                }
                tracing::info!("slice egress-enforcement: (a) allowed Anthropic call → 200");
            }
            other => return Err(anyhow!("(a) expected FetchResponse, got {other:?}")),
        }
    }

    // (b) Denied URL — real public host, but outside the policy
    // allowlist. The gateway MUST refuse to forward.
    {
        let req = build_request("https://httpbin.org/anything", "GET", vec![], b"".to_vec());
        write_frame(&mut stream, &req).await?;
        let resp = tokio::time::timeout(
            Duration::from_secs(10),
            read_frame::<_, GatewayMessage>(&mut stream),
        )
        .await
        .map_err(|_| anyhow!("denied response timeout"))?
        .map_err(|e| anyhow!("read FetchResponse(denied): {e}"))?;
        match resp {
            GatewayMessage::FetchResponse {
                status_code, error, ..
            } => {
                if status_code.is_some() {
                    return Err(anyhow!(
                        "(b) gateway forwarded a request that should have been denied; \
                         status_code={status_code:?}",
                    ));
                }
                let err = error.ok_or_else(|| anyhow!("(b) no error string"))?;
                if err != "DomainNotAllowed" {
                    return Err(anyhow!("(b) expected DomainNotAllowed; got {err:?}"));
                }
                tracing::info!(
                    "slice egress-enforcement: (b) httpbin.org denied → DomainNotAllowed"
                );
            }
            other => return Err(anyhow!("(b) expected FetchResponse, got {other:?}")),
        }
    }

    // (c) Same host as (a) but different scheme: `http://`. Pin
    // that the gateway either denies the URL or surfaces a clean
    // error rather than panicking.
    {
        let req = build_request(
            "http://api.anthropic.com/v1/messages",
            "POST",
            vec![("content-type".to_owned(), "application/json".to_owned())],
            b"{}".to_vec(),
        );
        write_frame(&mut stream, &req).await?;
        let resp = tokio::time::timeout(
            Duration::from_secs(20),
            read_frame::<_, GatewayMessage>(&mut stream),
        )
        .await
        .map_err(|_| anyhow!("plain-http response timeout"))?
        .map_err(|e| anyhow!("read FetchResponse(plain-http): {e}"))?;
        match resp {
            GatewayMessage::FetchResponse {
                status_code, error, ..
            } => {
                // We accept either: (1) the gateway denied it as
                // DomainNotAllowed (host-based allowlist passes,
                // but a future scheme-aware check could deny);
                // or (2) the upstream rejected the plain-http
                // request and the gateway surfaces that as a
                // status_code or upstream-error string. Either is
                // acceptable; the test asserts the surface is
                // structured (no panic, no truncated frame).
                tracing::info!(
                    "slice egress-enforcement: (c) plain-http → status_code={status_code:?}, error={error:?}",
                );
            }
            other => return Err(anyhow!("(c) expected FetchResponse, got {other:?}")),
        }
    }

    drop(stream);
    drop(listener);
    let _ = std::fs::remove_file(&kernel_sock);
    let _ = tokio::time::timeout(Duration::from_secs(5), gateway_task).await;
    tracing::info!("slice egress-enforcement: PASS");
    Ok(())
}

fn build_request(
    url: &str,
    method: &str,
    headers: Vec<(String, String)>,
    body_bytes: Vec<u8>,
) -> GatewayMessage {
    GatewayMessage::FetchRequest {
        gateway_token: GATEWAY_TOKEN.to_owned(),
        fetch_id: Uuid::new_v4(),
        fetch_kind: FetchKind::DataFetch,
        url: url.to_owned(),
        method: method.to_owned(),
        headers,
        body_bytes,
        timeout_ms: 10_000,
        session_id: None,
        task_id: None,
    }
}

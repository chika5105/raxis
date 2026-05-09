// raxis-kernel::notifications::handler::webhook — Webhook channel
// handler.
//
// Closes V2_GAPS.md §C4 (gap-c4-webhook).
//
// ## Wire shape
//
// ```text
//   POST <channel.target> HTTP/1.1
//   Content-Type: application/json
//   User-Agent: raxis-kernel/<version>
//   X-RAXIS-Event-Kind: <event.event_kind>
//   X-RAXIS-Event-Seq:  <event.seq>
//   X-RAXIS-Event-Id:   <event.event_id>
//
//   { "notified_at": ..., "event_kind": ..., "event_seq": ...,
//     "payload": { ... }, "human_summary": ... }
// ```
//
// The body is the same `ShellRecord` shape the file handler writes,
// so a sidecar that ingests both `inbox.jsonl` and the webhook POSTs
// can use a single deserialiser.
//
// ## Authentication
//
// V2 ships **no built-in HMAC signing** — the URL itself is the
// shared secret (matches Slack / Discord / GitHub webhook UX). A
// future iteration will surface the full HMAC-SHA256 timestamping
// scheme described in `email-and-notification-channels.md §2.3.4`.
//
// ## Failure mapping
//
// * Connection refused, DNS failure, TLS handshake error → `Network(_)`
// * HTTP status >= 400                                    → `UpstreamRejected(_)`
// * URL is malformed (not http:// or https://)            → `TargetInvalid`
// * Request timeout (default 10s)                         → `Network("timeout: ...")`

use std::time::Duration;

use raxis_audit_tools::AuditEvent;
use raxis_policy::NotificationChannel;
use serde::Serialize;

use super::super::{summary, DeliveryError};

/// Per-event-kind HTTP timeout. Bounded so a slow webhook endpoint
/// never wedges the dispatcher's per-channel worker.
const WEBHOOK_TIMEOUT: Duration = Duration::from_secs(10);

/// Maximum body size accepted from the upstream response (we don't
/// care about the response body, but we read it to surface a useful
/// failure reason).
const MAX_RESPONSE_BODY_BYTES: usize = 4096;

/// Wire shape of the JSON body POSTed to the webhook URL.
#[derive(Debug, Serialize)]
struct WebhookRecord<'a> {
    notified_at:   i64,
    event_kind:    &'a str,
    event_seq:     u64,
    event_id:      String,
    payload:       &'a serde_json::Value,
    human_summary: String,
}

/// POST one notification to `channel.target`. Returns `Ok(())` on
/// HTTP `2xx` / `3xx`, otherwise classifies the failure into the
/// matching `DeliveryError` variant.
pub async fn deliver(
    channel: &NotificationChannel,
    event:   &AuditEvent,
) -> Result<(), DeliveryError> {
    if channel.target.trim().is_empty() {
        return Err(DeliveryError::TargetInvalid);
    }
    let url = channel.target.trim();
    if !url.starts_with("http://") && !url.starts_with("https://") {
        return Err(DeliveryError::TargetInvalid);
    }
    let body = WebhookRecord {
        notified_at:   raxis_types::unix_now_secs() as i64,
        event_kind:    &event.event_kind,
        event_seq:     event.seq,
        event_id:      event.event_id.to_string(),
        payload:       &event.payload,
        human_summary: summary::render(event),
    };

    let client = reqwest::Client::builder()
        .timeout(WEBHOOK_TIMEOUT)
        .user_agent(concat!("raxis-kernel/", env!("CARGO_PKG_VERSION")))
        // Enable both HTTP/1 and HTTP/2 so the operator's proxy /
        // CDN of choice works without additional knobs.
        .build()
        .map_err(|e| DeliveryError::Network(format!("client build failed: {e}")))?;

    let resp = client.post(url)
        .header("Content-Type",        "application/json")
        .header("X-RAXIS-Event-Kind",  &event.event_kind)
        .header("X-RAXIS-Event-Seq",   event.seq.to_string())
        .header("X-RAXIS-Event-Id",    event.event_id.to_string())
        .json(&body)
        .send()
        .await
        .map_err(|e| {
            // Distinguish "DNS / TCP / TLS" from "we got a response
            // we didn't like" by checking whether it's a status error.
            if e.is_timeout() {
                DeliveryError::Network(format!("timeout: {e}"))
            } else if e.is_connect() {
                DeliveryError::Network(format!("connect: {e}"))
            } else if e.is_request() {
                DeliveryError::Network(format!("request: {e}"))
            } else {
                DeliveryError::Network(e.to_string())
            }
        })?;

    let status = resp.status();
    if status.is_success() || status.is_redirection() {
        return Ok(());
    }

    // Non-2xx: include the first 4 KiB of the response body in the
    // audit reason so the operator can debug without rerunning. We
    // intentionally swallow body-read failures — if the upstream
    // returned 500 with no body, we still want to land the audit.
    let body = match resp.bytes().await {
        Ok(b)  => {
            let n = b.len().min(MAX_RESPONSE_BODY_BYTES);
            String::from_utf8_lossy(&b[..n]).into_owned()
        }
        Err(_) => String::new(),
    };
    Err(DeliveryError::UpstreamRejected(format!(
        "HTTP {} from {url}: {body}", status.as_u16(),
    )))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use raxis_audit_tools::AuditEvent;
    use raxis_policy::{NotificationChannel, NotificationChannelKind};
    use serde_json::json;
    use uuid::Uuid;

    fn make_event(kind: &str, seq: u64, payload: serde_json::Value) -> AuditEvent {
        AuditEvent {
            seq,
            event_id:      Uuid::new_v4(),
            event_kind:    kind.to_owned(),
            session_id:    None,
            task_id:       None,
            initiative_id: None,
            payload,
            emitted_at:    1_700_000_000,
            prev_sha256:   "0".repeat(64),
        }
    }

    fn webhook(target: impl Into<String>) -> NotificationChannel {
        NotificationChannel {
            id:     "wh".into(),
            kind:   NotificationChannelKind::Webhook,
            target: target.into(),
            max_in_flight: 8,
        }
    }

    #[tokio::test]
    async fn empty_target_returns_target_invalid() {
        let chan = webhook("");
        let e    = make_event("EscalationApproved", 1, json!({}));
        match deliver(&chan, &e).await {
            Err(DeliveryError::TargetInvalid) => {}
            other => panic!("expected TargetInvalid, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn non_http_target_returns_target_invalid() {
        let chan = webhook("ftp://example.com/hook");
        let e    = make_event("EscalationApproved", 1, json!({}));
        match deliver(&chan, &e).await {
            Err(DeliveryError::TargetInvalid) => {}
            other => panic!("expected TargetInvalid, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn unreachable_target_returns_network_error() {
        // 127.0.0.1:1 is reserved + connection-refused on every
        // sane host. We get a Network(connect|request|timeout)
        // depending on the platform + reqwest version.
        let chan = webhook("http://127.0.0.1:1/hook");
        let e    = make_event("EscalationApproved", 1, json!({}));
        match deliver(&chan, &e).await {
            Err(DeliveryError::Network(reason)) => {
                assert!(
                    reason.contains("connect")
                        || reason.contains("request")
                        || reason.contains("timeout"),
                    "expected a network-class failure reason, got: {reason}",
                );
            }
            other => panic!("expected Network, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn happy_path_against_local_test_server() {
        // Spin up a tiny tokio TCP listener that consumes one HTTP
        // request, returns 204 No Content. Avoids pulling in axum /
        // hyper as a dev-dep just for one test.
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            // Read until "\r\n\r\n" so we know headers ended; then
            // drain any body bytes the client wrote.
            let mut buf = vec![0u8; 8192];
            loop {
                let n = sock.read(&mut buf).await.unwrap();
                if n == 0 { break; }
                if buf[..n].windows(4).any(|w| w == b"\r\n\r\n") { break; }
            }
            let _ = sock.write_all(
                b"HTTP/1.1 204 No Content\r\n\
                  Content-Length: 0\r\n\
                  Connection: close\r\n\r\n",
            ).await;
        });

        let chan = webhook(format!("http://127.0.0.1:{port}/hook"));
        let e    = make_event("EscalationApproved", 7, json!({"x":1}));
        deliver(&chan, &e).await.expect("happy path must succeed");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn upstream_4xx_surfaces_upstream_rejected() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 8192];
            loop {
                let n = sock.read(&mut buf).await.unwrap();
                if n == 0 { break; }
                if buf[..n].windows(4).any(|w| w == b"\r\n\r\n") { break; }
            }
            let _ = sock.write_all(
                b"HTTP/1.1 401 Unauthorized\r\n\
                  Content-Length: 18\r\n\
                  Connection: close\r\n\r\n\
                  bad shared-secret\n",
            ).await;
        });

        let chan = webhook(format!("http://127.0.0.1:{port}/hook"));
        let e    = make_event("EscalationApproved", 7, json!({}));
        match deliver(&chan, &e).await {
            Err(DeliveryError::UpstreamRejected(reason)) => {
                assert!(reason.contains("401"));
                assert!(reason.contains("bad shared-secret"));
            }
            other => panic!("expected UpstreamRejected, got {other:?}"),
        }
        server.await.unwrap();
    }

    #[test]
    fn delivery_error_categories_added_for_v2() {
        // Pin the wire short-strings new in V2 so downstream tooling
        // keying off `reason` doesn't break silently.
        assert_eq!(
            DeliveryError::Network("x".into()).category(),
            "network",
        );
        assert_eq!(
            DeliveryError::UpstreamRejected("x".into()).category(),
            "upstream_rejected",
        );
        assert_eq!(
            DeliveryError::CredentialUnavailable("x".into()).category(),
            "credential_unavailable",
        );
    }
}

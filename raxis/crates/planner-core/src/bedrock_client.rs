//! V2_GAPS §C2/C3 — `BedrockClient`: AWS Bedrock Runtime InvokeModel.
//!
//! Supports **Anthropic-on-Bedrock only** in V2. The full Bedrock
//! `Converse` API lands in V3 alongside the gateway-side SigV4 plug-in
//! that lets non-Claude models (Titan, Llama, Mistral) flow through.
//!
//! ## Wire shape (normative reference: `provider-client-impls.md §4`)
//!
//! Bedrock hosts Anthropic Claude with the **same** Messages API
//! body as direct Anthropic — the only deltas are:
//!
//! 1. The model id moves from the body to the URL path:
//!    `POST /model/<model>/invoke` against
//!    `<base_url>/model/<model>/invoke`.
//! 2. The body adds an `anthropic_version` field with the
//!    Bedrock-required value `"bedrock-2023-05-31"`.
//! 3. The body **omits** the `model` field (the model is in the URL).
//!
//! Everything else (`max_tokens`, `messages`, `tools`, `system`,
//! `stop_reason`, `usage`) is byte-for-byte identical to the
//! Anthropic Messages API.
//!
//! ## SigV4 — gateway leg
//!
//! AWS SigV4 request signing is performed by the **gateway**, not the
//! planner. The planner POSTs the unsigned body; the gateway
//! recognises the destination as `bedrock-runtime.<region>.amazonaws.com`
//! and injects the `Authorization` header via SigV4 immediately
//! before egress. This mirrors the credential-injection precedence
//! for Anthropic (`x-api-key`) and OpenAI (`Bearer`).
//!
//! See `gateway-substrate.md §6.2 "Region-aware credential injection"`
//! for the gateway-side plug-in.

use std::time::Duration;

use async_trait::async_trait;
use serde::Serialize;

use crate::model::{
    MessageRequest, MessageResponse, ModelClient, ModelError,
};

/// Bedrock-required version string. Pinned by AWS — bumping requires
/// a Bedrock release coordinated with Anthropic.
pub const ANTHROPIC_VERSION_BEDROCK: &str = "bedrock-2023-05-31";

/// Production AWS Bedrock InvokeModel client. The gateway's tproxy
/// redirect is transparent; this struct does not need to know
/// whether it's talking to Bedrock directly or through the gateway.
pub struct BedrockClient {
    http: reqwest::Client,
    /// Region-specific Bedrock runtime endpoint, e.g.
    /// `https://bedrock-runtime.us-east-1.amazonaws.com`.
    base_url: String,
    request_timeout: Duration,
}

fn skip_if_slice_empty<T>(s: &&[T]) -> bool { s.is_empty() }

#[derive(Serialize)]
struct BedrockRequestBody<'a> {
    anthropic_version: &'static str,
    max_tokens: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    temperature: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    system: Option<&'a str>,
    messages: &'a [crate::model::Message],
    #[serde(skip_serializing_if = "skip_if_slice_empty")]
    tools: &'a [crate::model::ToolSpec],
}

impl BedrockClient {
    pub fn new(base_url: impl Into<String>) -> Self {
        let http = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .pool_idle_timeout(Duration::from_secs(30))
            .build()
            .expect("reqwest::Client::build is infallible with default config");
        Self {
            http,
            base_url: base_url.into(),
            request_timeout: Duration::from_secs(300),
        }
    }

    pub fn with_request_timeout(mut self, d: Duration) -> Self {
        self.request_timeout = d;
        self
    }
}

#[async_trait]
impl ModelClient for BedrockClient {
    async fn create_message(
        &self,
        req: &MessageRequest,
    ) -> Result<MessageResponse, ModelError> {
        let url = format!("{}/model/{}/invoke", self.base_url, req.model);
        let body = BedrockRequestBody {
            anthropic_version: ANTHROPIC_VERSION_BEDROCK,
            max_tokens: req.max_tokens,
            temperature: req.temperature,
            system: req.system.as_deref(),
            messages: &req.messages,
            tools: &req.tools,
        };
        let body_bytes = serde_json::to_vec(&body)
            .map_err(|e| ModelError::Json(e.to_string()))?;

        let resp = self.http.post(&url)
            .timeout(self.request_timeout)
            .header("content-type", "application/json")
            .header("accept",       "application/json")
            .body(body_bytes)
            .send()
            .await
            .map_err(|e| {
                if e.is_timeout() {
                    ModelError::Timeout(self.request_timeout)
                } else {
                    ModelError::Transport(e.to_string())
                }
            })?;

        let status = resp.status();
        let bytes  = resp.bytes().await.map_err(|e| ModelError::Transport(e.to_string()))?;

        if !status.is_success() {
            let snippet = if bytes.len() <= 4096 {
                String::from_utf8_lossy(&bytes).into_owned()
            } else {
                format!(
                    "{}…<truncated {} bytes>",
                    String::from_utf8_lossy(&bytes[..4096]),
                    bytes.len() - 4096,
                )
            };
            return Err(ModelError::Upstream { status: status.as_u16(), body: snippet });
        }

        // The InvokeModel response for Anthropic-on-Bedrock IS the
        // Anthropic MessageResponse shape — same `id`, `content`,
        // `stop_reason`, `usage`. Parse directly.
        let parsed: MessageResponse = serde_json::from_slice(&bytes)
            .map_err(|e| ModelError::Json(e.to_string()))?;
        Ok(parsed)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{ContentBlock, Message};

    fn req() -> MessageRequest {
        MessageRequest {
            model: "anthropic.claude-3-5-sonnet-20241022-v2:0".to_owned(),
            max_tokens: 256,
            temperature: Some(0.5),
            system: Some("be helpful".to_owned()),
            messages: vec![Message {
                role: "user".to_owned(),
                content: vec![ContentBlock::Text { text: "hello".to_owned() }],
            }],
            tools: vec![],
            stream: false,
        }
    }

    #[test]
    fn body_omits_model_field_and_includes_anthropic_version() {
        let r = req();
        let body = BedrockRequestBody {
            anthropic_version: ANTHROPIC_VERSION_BEDROCK,
            max_tokens: r.max_tokens,
            temperature: r.temperature,
            system: r.system.as_deref(),
            messages: &r.messages,
            tools: &r.tools,
        };
        let json = serde_json::to_value(&body).unwrap();
        assert!(json.get("model").is_none(),
            "Bedrock body MUST NOT include `model` (it's in the URL); got {json}");
        assert_eq!(json["anthropic_version"], ANTHROPIC_VERSION_BEDROCK);
        assert_eq!(json["max_tokens"], 256);
        assert_eq!(json["system"], "be helpful");
        assert_eq!(json["messages"][0]["role"], "user");
    }

    #[tokio::test]
    async fn unreachable_url_surfaces_transport_error() {
        let client = BedrockClient::new("http://127.0.0.1:1");
        let err = client.create_message(&req()).await.unwrap_err();
        match err {
            ModelError::Transport(_) | ModelError::Timeout(_) => {}
            other => panic!("expected transport/timeout, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn happy_path_against_local_test_server() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 16384];
            let mut total = 0;
            loop {
                let n = sock.read(&mut buf[total..]).await.unwrap();
                if n == 0 { break; }
                total += n;
                if total > 200 && buf[..total].windows(4).any(|w| w == b"\r\n\r\n") { break; }
            }
            // The Anthropic-on-Bedrock response IS the Anthropic
            // MessageResponse shape.
            let body = br#"{"id":"msg_b","type":"message","role":"assistant","content":[{"type":"text","text":"hi"}],"stop_reason":"end_turn","usage":{"input_tokens":3,"output_tokens":1},"model":"anthropic.claude-3-5-sonnet-20241022-v2:0"}"#;
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len(),
            );
            sock.write_all(resp.as_bytes()).await.unwrap();
            sock.write_all(body).await.unwrap();
        });

        let client = BedrockClient::new(format!("http://127.0.0.1:{port}"));
        let resp = client.create_message(&req()).await.unwrap();
        assert_eq!(resp.id, "msg_b");
        assert_eq!(resp.stop_reason.as_deref(), Some("end_turn"));
        match &resp.content[0] {
            ContentBlock::Text { text } => assert_eq!(text, "hi"),
            other => panic!("expected text, got {other:?}"),
        }
        server.await.unwrap();
    }

    #[tokio::test]
    async fn upstream_4xx_is_classified_as_upstream_error() {
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
                b"HTTP/1.1 403 Forbidden\r\nContent-Length: 12\r\nConnection: close\r\n\r\nAccessDenied",
            ).await;
        });

        let client = BedrockClient::new(format!("http://127.0.0.1:{port}"));
        let err = client.create_message(&req()).await.unwrap_err();
        match err {
            ModelError::Upstream { status, body } => {
                assert_eq!(status, 403);
                assert!(body.contains("AccessDenied"));
            }
            other => panic!("expected Upstream, got {other:?}"),
        }
        server.await.unwrap();
    }
}

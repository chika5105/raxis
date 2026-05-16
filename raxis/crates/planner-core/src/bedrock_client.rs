//! `BedrockClient`: AWS Bedrock Runtime InvokeModel.
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
    CacheControl, CacheTtl, MessageRequest, MessageResponse, ModelClient, ModelError,
};

/// Bedrock-required version string. Pinned by AWS — bumping requires
/// a Bedrock release coordinated with Anthropic.
pub const ANTHROPIC_VERSION_BEDROCK: &str = "bedrock-2023-05-31";

/// Production AWS Bedrock InvokeModel client. The buffered call
/// path goes through an [`crate::http_fetch::HttpFetch`] so the
/// same client works under direct egress and the kernel-mediated
/// substrate transparently.
pub struct BedrockClient {
    http_fetch: std::sync::Arc<dyn crate::http_fetch::HttpFetch>,
    /// Region-specific Bedrock runtime endpoint, e.g.
    /// `https://bedrock-runtime.us-east-1.amazonaws.com`.
    base_url: String,
    request_timeout: Duration,
}

/// Manual `Serialize` impl that mirrors the Anthropic-on-Bedrock
/// wire shape **and** honors the [`MessageRequest::cache_*`]
/// flags. Bedrock proxies the Anthropic Messages API verbatim, so
/// the projection rules are identical to the Anthropic native
/// client — with two exceptions:
///
/// 1. `model` is omitted (it lives in the URL path).
/// 2. `anthropic_version` is added (the Bedrock-required pin).
/// 3. The top-level **automatic-caching** breakpoint
///    (`MessageRequest::cache_messages`) is suppressed: per
///    `prompt-caching.md §"Provider parity"`, Bedrock + Vertex
///    AI do NOT support automatic caching. The system + tools
///    explicit breakpoints still serialize because Bedrock
///    supports per-block `cache_control` markers at the same
///    Anthropic shape.
struct BedrockRequestBody<'a> {
    req: &'a MessageRequest,
}

impl<'a> Serialize for BedrockRequestBody<'a> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use crate::model::{Message, ToolSpec};
        use serde::ser::SerializeMap;

        // Fixed Anthropic-shape system block view local to this
        // impl. We re-implement it (rather than re-export the
        // `model.rs` private one) to keep `BedrockRequestBody`
        // self-contained and to make the wire-shape contract
        // visible in the file that owns the Bedrock client.
        #[derive(Serialize)]
        struct SystemBlock<'b> {
            #[serde(rename = "type")]
            kind: &'static str,
            text: &'b str,
            #[serde(skip_serializing_if = "Option::is_none")]
            cache_control: Option<CacheControl>,
        }
        struct ToolView<'b> {
            spec: &'b ToolSpec,
            cache_control: Option<CacheControl>,
        }
        impl<'b> Serialize for ToolView<'b> {
            fn serialize<S2: serde::Serializer>(&self, ser: S2) -> Result<S2::Ok, S2::Error> {
                use serde::ser::SerializeMap;
                let len = 3 + usize::from(self.cache_control.is_some());
                let mut m = ser.serialize_map(Some(len))?;
                m.serialize_entry("name", &self.spec.name)?;
                m.serialize_entry("description", &self.spec.description)?;
                m.serialize_entry("input_schema", &self.spec.input_schema)?;
                if let Some(cc) = self.cache_control {
                    m.serialize_entry("cache_control", &cc)?;
                }
                m.end()
            }
        }

        let cache_payload = self.req.cache_ttl.unwrap_or(CacheTtl::Short);

        // Pre-count the map size for serializers that benefit from
        // a known length (e.g. CBOR via `bincode`); JSON is
        // length-agnostic but cheap to compute.
        let mut len = 2; // anthropic_version, max_tokens
        if self.req.system.is_some() {
            len += 1;
        }
        let _: () = (); /* messages always present */
        len += 1;
        if !self.req.tools.is_empty() {
            len += 1;
        }
        if self.req.temperature.is_some() {
            len += 1;
        }

        let mut m = serializer.serialize_map(Some(len))?;
        m.serialize_entry("anthropic_version", ANTHROPIC_VERSION_BEDROCK)?;
        m.serialize_entry("max_tokens", &self.req.max_tokens)?;

        if let Some(t) = self.req.temperature {
            m.serialize_entry("temperature", &t)?;
        }

        if let Some(sys) = &self.req.system {
            if self.req.cache_system {
                let block = SystemBlock {
                    kind: "text",
                    text: sys.as_str(),
                    cache_control: Some(CacheControl::Ephemeral {
                        ttl: Some(cache_payload),
                    }),
                };
                m.serialize_entry("system", &[block])?;
            } else {
                m.serialize_entry("system", sys.as_str())?;
            }
        }

        let messages: &[Message] = &self.req.messages;
        m.serialize_entry("messages", messages)?;

        if !self.req.tools.is_empty() {
            if self.req.cache_tools {
                let projected: Vec<ToolView<'_>> = self
                    .req
                    .tools
                    .iter()
                    .enumerate()
                    .map(|(i, t)| ToolView {
                        spec: t,
                        cache_control: if i + 1 == self.req.tools.len() {
                            Some(CacheControl::Ephemeral {
                                ttl: Some(cache_payload),
                            })
                        } else {
                            None
                        },
                    })
                    .collect();
                m.serialize_entry("tools", &projected)?;
            } else {
                m.serialize_entry("tools", &self.req.tools)?;
            }
        }

        m.end()
    }
}

impl BedrockClient {
    /// Construct a Bedrock-compatible chat client targeting the given base URL.
    ///
    /// `base_url` MUST be the bedrock-runtime endpoint root (e.g.
    /// `https://bedrock-runtime.us-east-1.amazonaws.com`); per-model paths are
    /// appended internally.  The client uses a default 10s connect timeout and
    /// a 300s request timeout, both overridable via [`Self::with_request_timeout`].
    pub fn new(base_url: impl Into<String>) -> Self {
        Self::with_http_fetch(
            base_url,
            std::sync::Arc::new(crate::http_fetch::DirectHttpFetch::new()),
        )
    }

    /// Construct a new client backed by the supplied
    /// [`crate::http_fetch::HttpFetch`]. The planner-core driver
    /// uses this constructor to swap in
    /// [`crate::http_fetch::KernelMediatedHttpFetch`] for guests
    /// running in `EgressTier::None`.
    pub fn with_http_fetch(
        base_url: impl Into<String>,
        http_fetch: std::sync::Arc<dyn crate::http_fetch::HttpFetch>,
    ) -> Self {
        Self {
            http_fetch,
            base_url: base_url.into(),
            request_timeout: Duration::from_secs(300),
        }
    }

    /// Override the per-request timeout (default 300s).
    ///
    /// Bedrock long-running prompts can take >60s; tests usually shorten this.
    pub fn with_request_timeout(mut self, d: Duration) -> Self {
        self.request_timeout = d;
        self
    }
}

#[async_trait]
impl ModelClient for BedrockClient {
    async fn create_message(&self, req: &MessageRequest) -> Result<MessageResponse, ModelError> {
        let url = format!("{}/model/{}/invoke", self.base_url, req.model);
        let body = BedrockRequestBody { req };
        let body_bytes = serde_json::to_vec(&body).map_err(|e| ModelError::Json(e.to_string()))?;

        let fetch_req = crate::http_fetch::HttpFetchRequest {
            url: &url,
            method: "POST",
            headers: vec![
                ("content-type", "application/json".to_owned()),
                ("accept", "application/json".to_owned()),
            ],
            body: body_bytes,
            timeout: self.request_timeout,
        };

        let resp = self
            .http_fetch
            .fetch(fetch_req)
            .await
            .map_err(|e| match e {
                crate::http_fetch::HttpFetchError::Timeout(d) => ModelError::Timeout(d),
                crate::http_fetch::HttpFetchError::Transport(s) => ModelError::Transport(s),
            })?;

        if !(200..300).contains(&resp.status) {
            let snippet = if resp.body.len() <= 4096 {
                String::from_utf8_lossy(&resp.body).into_owned()
            } else {
                format!(
                    "{}…<truncated {} bytes>",
                    String::from_utf8_lossy(&resp.body[..4096]),
                    resp.body.len() - 4096,
                )
            };
            return Err(ModelError::Upstream {
                status: resp.status,
                body: snippet,
            });
        }

        // The InvokeModel response for Anthropic-on-Bedrock IS the
        // Anthropic MessageResponse shape — same `id`, `content`,
        // `stop_reason`, `usage`. Parse directly.
        let parsed: MessageResponse =
            serde_json::from_slice(&resp.body).map_err(|e| ModelError::Json(e.to_string()))?;
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
                content: vec![ContentBlock::Text {
                    text: "hello".to_owned(),
                }],
            }],
            ..Default::default()
        }
    }

    #[test]
    fn body_omits_model_field_and_includes_anthropic_version() {
        let r = req();
        let body = BedrockRequestBody { req: &r };
        let json = serde_json::to_value(&body).unwrap();
        assert!(
            json.get("model").is_none(),
            "Bedrock body MUST NOT include `model` (it's in the URL); got {json}"
        );
        assert_eq!(json["anthropic_version"], ANTHROPIC_VERSION_BEDROCK);
        assert_eq!(json["max_tokens"], 256);
        assert_eq!(json["system"], "be helpful");
        assert_eq!(json["messages"][0]["role"], "user");
    }

    /// Pin the cache-on Bedrock wire shape: when caller opts into
    /// `cache_system` + `cache_tools`, the body emits the
    /// Anthropic-on-Bedrock cache_control markers exactly the way
    /// AWS proxies the Anthropic Messages API. Top-level
    /// `cache_control` (Anthropic automatic caching) is suppressed
    /// because Bedrock does not support it (per
    /// `prompt-caching.md §"Provider parity"`).
    #[test]
    fn body_emits_cache_control_when_flags_opted_in() {
        let mut r = req();
        r.cache_system = true;
        r.cache_tools = true;
        r.cache_messages = true; // intentionally true to assert suppression
        r.tools = vec![crate::model::ToolSpec {
            name: "read_file".to_owned(),
            description: "read".to_owned(),
            input_schema: serde_json::json!({"type":"object"}),
        }];
        let body = BedrockRequestBody { req: &r };
        let json = serde_json::to_value(&body).unwrap();

        // System projected as block array carrying cache_control.
        let sys = json["system"]
            .as_array()
            .expect("cache_system=true MUST project system to a block array");
        assert_eq!(sys[0]["type"], "text");
        assert_eq!(sys[0]["text"], "be helpful");
        assert_eq!(sys[0]["cache_control"]["type"], "ephemeral");

        // Last tool carries cache_control.
        let tools = json["tools"].as_array().unwrap();
        assert_eq!(tools[0]["cache_control"]["type"], "ephemeral");

        // Bedrock MUST NOT emit a top-level cache_control (it does
        // not support Anthropic automatic caching).
        assert!(
            json.get("cache_control").is_none(),
            "Bedrock MUST NOT emit top-level cache_control; got {json}"
        );
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
                if n == 0 {
                    break;
                }
                total += n;
                if total > 200 && buf[..total].windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
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
                if n == 0 {
                    break;
                }
                if buf[..n].windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
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

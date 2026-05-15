//! V2_GAPS §C2/C3 — `GeminiClient`: Google Gemini `generateContent`.
//!
//! Translates the canonical Anthropic-flavoured [`MessageRequest`] /
//! [`MessageResponse`] (defined in `crate::model`) into the Gemini
//! `v1beta/models/<model>:generateContent` wire shape and back.
//!
//! ## Wire shape (normative reference: `provider-client-impls.md §3`)
//!
//! Request body:
//! ```json
//! {
//!   "system_instruction": { "parts": [{ "text": "..." }] },
//!   "contents": [
//!     { "role": "user",
//!       "parts": [
//!         { "text": "..." },
//!         { "functionResponse": {
//!             "name": "calc", "response": { "result": "2" } } }
//!       ] },
//!     { "role": "model",
//!       "parts": [
//!         { "text": "..." },
//!         { "functionCall": { "name": "calc", "args": { ... } } }
//!       ] }
//!   ],
//!   "tools": [
//!     { "functionDeclarations": [
//!         { "name": "calc",
//!           "description": "evaluate",
//!           "parameters": { ... } } ] }
//!   ],
//!   "generationConfig": { "maxOutputTokens": 1024, "temperature": 0.5 }
//! }
//! ```
//!
//! Response body:
//! ```json
//! {
//!   "candidates": [{
//!     "content": { "role": "model", "parts": [...] },
//!     "finishReason": "STOP" | "MAX_TOKENS" | ...
//!   }],
//!   "usageMetadata": {
//!     "promptTokenCount":     N,
//!     "candidatesTokenCount": M
//!   }
//! }
//! ```

use std::time::Duration;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::model::{
    ContentBlock, MessageRequest, MessageResponse, ModelClient, ModelError, ToolSpec, Usage,
};

// ---------------------------------------------------------------------------
// Gemini wire types — request side
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
struct GeminiRequest<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    system_instruction: Option<GeminiSystemInstruction>,
    contents: Vec<GeminiContent>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    tools: Vec<GeminiTools<'a>>,
    #[serde(rename = "generationConfig")]
    generation_config: GeminiGenerationConfig,
}

#[derive(Debug, Serialize)]
struct GeminiSystemInstruction {
    parts: Vec<GeminiPart>,
}

#[derive(Debug, Serialize)]
struct GeminiContent {
    role: String,
    parts: Vec<GeminiPart>,
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
enum GeminiPart {
    Text {
        text: String,
    },
    FunctionCall {
        #[serde(rename = "functionCall")]
        function_call: GeminiFunctionCall,
    },
    FunctionResponse {
        #[serde(rename = "functionResponse")]
        function_response: GeminiFunctionResponse,
    },
}

#[derive(Debug, Serialize)]
struct GeminiFunctionCall {
    name: String,
    args: serde_json::Value,
}

#[derive(Debug, Serialize)]
struct GeminiFunctionResponse {
    name: String,
    response: serde_json::Value,
}

#[derive(Debug, Serialize)]
struct GeminiTools<'a> {
    #[serde(rename = "functionDeclarations")]
    function_declarations: Vec<GeminiFunctionDecl<'a>>,
}

#[derive(Debug, Serialize)]
struct GeminiFunctionDecl<'a> {
    name: &'a str,
    description: &'a str,
    parameters: &'a serde_json::Value,
}

#[derive(Debug, Serialize)]
struct GeminiGenerationConfig {
    #[serde(rename = "maxOutputTokens")]
    max_output_tokens: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    temperature: Option<f32>,
}

// ---------------------------------------------------------------------------
// Gemini wire types — response side
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct GeminiResponse {
    #[serde(default)]
    candidates: Vec<GeminiCandidate>,
    #[serde(rename = "usageMetadata", default)]
    usage_metadata: GeminiUsageMetadata,
}

#[derive(Debug, Deserialize)]
struct GeminiCandidate {
    #[serde(default)]
    content: Option<GeminiResponseContent>,
    #[serde(rename = "finishReason", default)]
    finish_reason: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GeminiResponseContent {
    #[serde(default)]
    role: String,
    #[serde(default)]
    parts: Vec<GeminiResponsePart>,
}

#[derive(Debug, Deserialize)]
struct GeminiResponsePart {
    #[serde(default)]
    text: Option<String>,
    #[serde(rename = "functionCall", default)]
    function_call: Option<GeminiResponseFunctionCall>,
}

#[derive(Debug, Deserialize)]
struct GeminiResponseFunctionCall {
    name: String,
    #[serde(default)]
    args: serde_json::Value,
}

#[derive(Debug, Default, Deserialize)]
struct GeminiUsageMetadata {
    #[serde(rename = "promptTokenCount", default)]
    prompt_token_count: u32,
    #[serde(rename = "candidatesTokenCount", default)]
    candidates_token_count: u32,
    /// **Prompt-caching attribution.** Gemini 2.5+ does
    /// **implicit caching** (no explicit `cache_control` opt-in)
    /// on prompts above a model-dependent floor (typically 1024
    /// tokens for Flash, 4096 for Pro). The cache-hit count is
    /// reported in `usageMetadata.cachedContentTokenCount` per
    /// the Generative Language API reference. Folded into
    /// canonical `Usage::cache_read_input_tokens` so operator
    /// telemetry is uniform across providers.
    ///
    /// Gemini also supports **explicit context caching** via the
    /// separate `cachedContents` resource (pre-create cache, then
    /// reference by name). That path is not wired here — it
    /// requires a sibling resource lifecycle that must live in
    /// the gateway, not the planner. See
    /// `prompt-caching.md §"Provider parity"`.
    #[serde(rename = "cachedContentTokenCount", default)]
    cached_content_token_count: u32,
}

// ---------------------------------------------------------------------------
// Translation: canonical → Gemini
// ---------------------------------------------------------------------------

fn build_contents(req: &MessageRequest) -> Vec<GeminiContent> {
    let mut out: Vec<GeminiContent> = Vec::new();
    for m in &req.messages {
        let role = match m.role.as_str() {
            "assistant" => "model",
            "user" => "user",
            other => other,
        }
        .to_owned();
        let mut parts: Vec<GeminiPart> = Vec::new();
        for b in &m.content {
            match b {
                ContentBlock::Text { text } => {
                    parts.push(GeminiPart::Text { text: text.clone() });
                }
                ContentBlock::ToolUse { name, input, .. } => {
                    // Gemini does not surface tool-call ids; the canonical
                    // round-trip uses tool_use.id only on the response side.
                    parts.push(GeminiPart::FunctionCall {
                        function_call: GeminiFunctionCall {
                            name: name.clone(),
                            args: input.clone(),
                        },
                    });
                }
                ContentBlock::ToolResult {
                    tool_use_id: _,
                    content,
                    ..
                } => {
                    // Gemini's functionResponse needs a structured object.
                    // Wrap the canonical string in `{ "result": <content> }`.
                    let response = serde_json::json!({ "result": content });
                    // Gemini uses the function NAME (not an id) for
                    // matching. Use a synthetic name when the
                    // canonical type doesn't carry one. The canonical
                    // ToolResult does not carry the function name; we
                    // pass `tool_use_id` as a stand-in so the response
                    // is at least addressable.
                    parts.push(GeminiPart::FunctionResponse {
                        function_response: GeminiFunctionResponse {
                            name: "tool".to_owned(),
                            response,
                        },
                    });
                }
                ContentBlock::Other(_) => { /* skip */ }
            }
        }
        if !parts.is_empty() {
            out.push(GeminiContent { role, parts });
        }
    }
    out
}

fn build_tools<'a>(tools: &'a [ToolSpec]) -> Vec<GeminiTools<'a>> {
    if tools.is_empty() {
        return Vec::new();
    }
    vec![GeminiTools {
        function_declarations: tools
            .iter()
            .map(|t| GeminiFunctionDecl {
                name: t.name.as_str(),
                description: t.description.as_str(),
                parameters: &t.input_schema,
            })
            .collect(),
    }]
}

fn build_request_body<'a>(req: &'a MessageRequest) -> GeminiRequest<'a> {
    GeminiRequest {
        system_instruction: req.system.as_ref().map(|s| GeminiSystemInstruction {
            parts: vec![GeminiPart::Text { text: s.clone() }],
        }),
        contents: build_contents(req),
        tools: build_tools(&req.tools),
        generation_config: GeminiGenerationConfig {
            max_output_tokens: req.max_tokens,
            temperature: req.temperature,
        },
    }
}

// ---------------------------------------------------------------------------
// Translation: Gemini → canonical
// ---------------------------------------------------------------------------

fn map_finish_reason(s: &str) -> String {
    match s {
        "STOP" => "end_turn".to_owned(),
        "MAX_TOKENS" => "max_tokens".to_owned(),
        "SAFETY" => "safety".to_owned(),
        "RECITATION" => "recitation".to_owned(),
        other => other.to_ascii_lowercase(),
    }
}

fn synthetic_id() -> String {
    // Wall-clock millis dominate the uniqueness budget here, but the
    // 32-bit suffix exists to break ties between IDs minted in the
    // same millisecond. The prior implementation seeded the suffix
    // with `Instant::now().elapsed().as_nanos() as u32`, which is
    // the duration between two adjacent instructions (~tens of ns)
    // and produces near-constant values across calls — so two IDs
    // minted in the same millisecond would collide on the suffix
    // too. Switch to the wall-clock sub-second nanosecond field,
    // which varies on every call. Matches the entropy-fix in
    // `planner-core/src/retry.rs::backoff_for`.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    format!("gemini-resp-{now}-{:08x}", nanos)
}

fn synthetic_tool_call_id(seq: usize) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("gemini-tool-{seq}-{now:x}")
}

fn parse_response(raw: &GeminiResponse, model_id: &str) -> Result<MessageResponse, ModelError> {
    let candidate = raw
        .candidates
        .first()
        .ok_or_else(|| ModelError::Json("Gemini response had no candidates".to_owned()))?;
    let parts = candidate
        .content
        .as_ref()
        .map(|c| &c.parts[..])
        .unwrap_or(&[]);

    let mut content: Vec<ContentBlock> = Vec::new();
    let mut tool_call_seq: usize = 0;
    for p in parts {
        if let Some(text) = p.text.as_ref().filter(|s| !s.is_empty()) {
            content.push(ContentBlock::Text { text: text.clone() });
        }
        if let Some(fc) = p.function_call.as_ref() {
            content.push(ContentBlock::ToolUse {
                id: synthetic_tool_call_id(tool_call_seq),
                name: fc.name.clone(),
                input: fc.args.clone(),
            });
            tool_call_seq += 1;
        }
    }

    let role = candidate
        .content
        .as_ref()
        .map(|c| {
            if c.role == "model" {
                "assistant".to_owned()
            } else {
                c.role.clone()
            }
        })
        .unwrap_or_else(|| "assistant".to_owned());
    let stop_reason = candidate.finish_reason.as_deref().map(map_finish_reason);
    Ok(MessageResponse {
        id: synthetic_id(),
        kind: "message".to_owned(),
        role,
        content,
        stop_reason,
        usage: Usage {
            input_tokens: raw.usage_metadata.prompt_token_count,
            output_tokens: raw.usage_metadata.candidates_token_count,
            cache_creation_input_tokens: 0,
            // Gemini 2.5+ implicit caching surfaces hit counts in
            // `usageMetadata.cachedContentTokenCount`; fold into
            // the canonical `cache_read_input_tokens` so dispatch
            // / operator telemetry is provider-agnostic.
            cache_read_input_tokens: raw.usage_metadata.cached_content_token_count,
        },
        model: model_id.to_owned(),
    })
}

// ---------------------------------------------------------------------------
// GeminiClient
// ---------------------------------------------------------------------------

/// Production Gemini `generateContent` client. The buffered call
/// path goes through an [`crate::http_fetch::HttpFetch`] so the
/// same client works under direct egress and the kernel-mediated
/// substrate transparently.
pub struct GeminiClient {
    http_fetch: std::sync::Arc<dyn crate::http_fetch::HttpFetch>,
    base_url: String,
    request_timeout: Duration,
}

impl GeminiClient {
    /// Construct a Gemini chat client over the default
    /// direct-egress HTTP transport. Equivalent to
    /// `GeminiClient::with_http_fetch(base_url, Arc::new(DirectHttpFetch::new()))`.
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

    /// Override the per-request timeout (default 300s); tests usually
    /// shorten this.
    pub fn with_request_timeout(mut self, d: Duration) -> Self {
        self.request_timeout = d;
        self
    }
}

#[async_trait]
impl ModelClient for GeminiClient {
    async fn create_message(&self, req: &MessageRequest) -> Result<MessageResponse, ModelError> {
        let url = format!(
            "{}/v1beta/models/{}:generateContent",
            self.base_url, req.model,
        );
        let body = build_request_body(req);
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

        let raw: GeminiResponse =
            serde_json::from_slice(&resp.body).map_err(|e| ModelError::Json(e.to_string()))?;
        parse_response(&raw, &req.model)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Message;

    fn req() -> MessageRequest {
        MessageRequest {
            model: "gemini-1.5-pro".to_owned(),
            max_tokens: 256,
            temperature: Some(0.5),
            system: Some("be helpful".to_owned()),
            messages: vec![
                Message {
                    role: "user".to_owned(),
                    content: vec![ContentBlock::Text {
                        text: "what is 1+1?".to_owned(),
                    }],
                },
                Message {
                    role: "assistant".to_owned(),
                    content: vec![ContentBlock::ToolUse {
                        id: "call-A".to_owned(),
                        name: "calc".to_owned(),
                        input: serde_json::json!({"expr": "1+1"}),
                    }],
                },
            ],
            ..Default::default()
        }
    }

    #[test]
    fn request_translation_includes_system_instruction() {
        let r = req();
        let body = build_request_body(&r);
        let json = serde_json::to_value(&body).unwrap();
        assert_eq!(json["system_instruction"]["parts"][0]["text"], "be helpful");
        assert_eq!(json["generationConfig"]["maxOutputTokens"], 256);
        assert_eq!(json["generationConfig"]["temperature"], 0.5);
    }

    #[test]
    fn request_translation_maps_assistant_role_to_model() {
        let r = req();
        let body = build_request_body(&r);
        let json = serde_json::to_value(&body).unwrap();
        let contents = json["contents"].as_array().unwrap();
        assert_eq!(contents[0]["role"], "user");
        assert_eq!(contents[1]["role"], "model");
    }

    #[test]
    fn request_translation_emits_function_call_part() {
        let r = req();
        let body = build_request_body(&r);
        let json = serde_json::to_value(&body).unwrap();
        let contents = json["contents"].as_array().unwrap();
        let parts = contents[1]["parts"].as_array().unwrap();
        let fc = &parts[0]["functionCall"];
        assert_eq!(fc["name"], "calc");
        assert_eq!(fc["args"]["expr"], "1+1");
    }

    #[test]
    fn response_translation_mints_synthetic_id_and_maps_finish_reason() {
        let raw = serde_json::json!({
            "candidates": [{
                "content": {
                    "role": "model",
                    "parts": [
                        { "text": "let me compute" },
                        { "functionCall": { "name": "calc", "args": {"expr": "1+2"} } }
                    ]
                },
                "finishReason": "STOP"
            }],
            "usageMetadata": { "promptTokenCount": 10, "candidatesTokenCount": 4 }
        });
        let raw: GeminiResponse = serde_json::from_value(raw).unwrap();
        let canonical = parse_response(&raw, "gemini-1.5-pro").unwrap();
        assert!(
            canonical.id.starts_with("gemini-resp-"),
            "synthetic id must carry the gemini-resp- prefix; got {}",
            canonical.id
        );
        assert_eq!(canonical.role, "assistant");
        assert_eq!(canonical.stop_reason.as_deref(), Some("end_turn"));
        assert_eq!(canonical.usage.input_tokens, 10);
        assert_eq!(canonical.usage.output_tokens, 4);
        assert_eq!(canonical.model, "gemini-1.5-pro");
        match &canonical.content[0] {
            ContentBlock::Text { text } => assert_eq!(text, "let me compute"),
            other => panic!("expected text, got {other:?}"),
        }
        match &canonical.content[1] {
            ContentBlock::ToolUse { id, name, input } => {
                assert!(
                    id.starts_with("gemini-tool-"),
                    "synthetic tool-call id must carry the prefix; got {id}"
                );
                assert_eq!(name, "calc");
                assert_eq!(input["expr"], "1+2");
            }
            other => panic!("expected tool_use, got {other:?}"),
        }
    }

    #[test]
    fn synthetic_ids_are_distinct_across_calls() {
        let id1 = synthetic_id();
        // tiny pause + rerun
        std::thread::sleep(std::time::Duration::from_millis(2));
        let id2 = synthetic_id();
        assert_ne!(
            id1, id2,
            "two consecutive synthetic ids must differ; got {id1} == {id2}"
        );
    }

    #[test]
    fn finish_reason_table_is_complete() {
        assert_eq!(map_finish_reason("STOP"), "end_turn");
        assert_eq!(map_finish_reason("MAX_TOKENS"), "max_tokens");
        assert_eq!(map_finish_reason("SAFETY"), "safety");
        assert_eq!(map_finish_reason("RECITATION"), "recitation");
        assert_eq!(map_finish_reason("OTHER"), "other");
    }

    /// **Prompt-caching attribution — Gemini implicit caching.**
    ///
    /// Gemini 2.5+ does implicit context caching with no opt-in;
    /// the cache-hit count is reported via
    /// `usageMetadata.cachedContentTokenCount`. Fold into the
    /// canonical `Usage::cache_read_input_tokens` so dispatch /
    /// operator telemetry is uniform with the Anthropic /
    /// Bedrock / OpenAI clients.
    #[test]
    fn cached_content_token_count_folds_into_canonical_usage() {
        let raw = serde_json::json!({
            "candidates": [{
                "content": { "role": "model", "parts": [{"text": "hi"}] },
                "finishReason": "STOP"
            }],
            "usageMetadata": {
                "promptTokenCount":         5000,
                "candidatesTokenCount":     12,
                "cachedContentTokenCount":  4500
            }
        });
        let raw: GeminiResponse = serde_json::from_value(raw).unwrap();
        let canonical = parse_response(&raw, "gemini-2.5-pro").unwrap();
        assert_eq!(canonical.usage.input_tokens, 5000);
        assert_eq!(
            canonical.usage.cache_read_input_tokens, 4500,
            "Gemini cachedContentTokenCount MUST fold into \
             Usage::cache_read_input_tokens for provider-agnostic \
             dispatch-side budget accounting"
        );
        assert_eq!(canonical.usage.cache_creation_input_tokens, 0);
    }

    #[tokio::test]
    async fn unreachable_url_surfaces_transport_error() {
        let client = GeminiClient::new("http://127.0.0.1:1");
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
            let body = br#"{"candidates":[{"content":{"role":"model","parts":[{"text":"hi"}]},"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":3,"candidatesTokenCount":1}}"#;
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len(),
            );
            sock.write_all(resp.as_bytes()).await.unwrap();
            sock.write_all(body).await.unwrap();
        });

        let client = GeminiClient::new(format!("http://127.0.0.1:{port}"));
        let resp = client.create_message(&req()).await.unwrap();
        assert!(resp.id.starts_with("gemini-resp-"));
        assert_eq!(resp.stop_reason.as_deref(), Some("end_turn"));
        match &resp.content[0] {
            ContentBlock::Text { text } => assert_eq!(text, "hi"),
            other => panic!("expected text, got {other:?}"),
        }
        server.await.unwrap();
    }
}

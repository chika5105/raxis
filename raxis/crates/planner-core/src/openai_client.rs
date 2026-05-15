//! V2_GAPS §C2/C3 — `OpenAiClient`: OpenAI Chat Completions API.
//!
//! Translates the canonical Anthropic-flavoured [`MessageRequest`] /
//! [`MessageResponse`] types (defined in `crate::model`) into the
//! OpenAI `/v1/chat/completions` wire shape and back.
//!
//! ## Wire shape (normative reference: `provider-client-impls.md §2`)
//!
//! Request body:
//! ```json
//! {
//!   "model": "gpt-4o-mini",
//!   "max_tokens": 1024,
//!   "temperature": 0.7,
//!   "messages": [
//!     { "role": "system", "content": "..." },
//!     { "role": "user",   "content": "say hi" },
//!     { "role": "assistant",
//!       "content": null,
//!       "tool_calls": [
//!         { "id": "call_x", "type": "function",
//!           "function": { "name": "...", "arguments": "{...}" } }
//!       ] },
//!     { "role": "tool", "tool_call_id": "call_x", "content": "..." }
//!   ],
//!   "tools": [
//!     { "type": "function",
//!       "function": { "name": "...", "description": "...",
//!                     "parameters": { ... schema ... } } }
//!   ]
//! }
//! ```
//!
//! Response body:
//! ```json
//! {
//!   "id": "chatcmpl-...",
//!   "object": "chat.completion",
//!   "created": 1700000000,
//!   "model": "gpt-4o-mini",
//!   "choices": [
//!     {
//!       "index": 0,
//!       "message": {
//!         "role": "assistant",
//!         "content": "...",
//!         "tool_calls": [...]
//!       },
//!       "finish_reason": "stop" | "length" | "tool_calls" | ...
//!     }
//!   ],
//!   "usage": {
//!     "prompt_tokens":     12,
//!     "completion_tokens": 5,
//!     "total_tokens":      17
//!   }
//! }
//! ```
//!
//! ## Credential precedence
//!
//! `OpenAiClient` does NOT set the `Authorization` header. The
//! gateway injects the `Authorization: Bearer <api_key>` at egress
//! per `peripherals.md §3.2`. A planner-supplied auth header would
//! short-circuit the gateway's audit chain and would be rejected.

use std::time::Duration;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::model::{
    ContentBlock, MessageRequest, MessageResponse, ModelClient, ModelError, ToolSpec, Usage,
};

// ---------------------------------------------------------------------------
// OpenAI wire types
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
struct OpenAiRequest<'a> {
    model: &'a str,
    max_tokens: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    temperature: Option<f32>,
    messages: Vec<OpenAiMessage>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    tools: Vec<OpenAiToolWrapper<'a>>,
}

#[derive(Debug, Serialize)]
struct OpenAiMessage {
    role: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    content: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    tool_calls: Vec<OpenAiToolCall>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tool_call_id: Option<String>,
}

#[derive(Debug, Serialize)]
struct OpenAiToolCall {
    id: String,
    #[serde(rename = "type")]
    kind: String,
    function: OpenAiFunctionCall,
}

#[derive(Debug, Serialize)]
struct OpenAiFunctionCall {
    name: String,
    /// JSON-encoded arguments (OpenAI requires a STRING, not an object).
    arguments: String,
}

#[derive(Debug, Serialize)]
struct OpenAiToolWrapper<'a> {
    #[serde(rename = "type")]
    kind: &'static str,
    function: OpenAiFunctionDef<'a>,
}

#[derive(Debug, Serialize)]
struct OpenAiFunctionDef<'a> {
    name: &'a str,
    description: &'a str,
    parameters: &'a serde_json::Value,
}

// Response side
#[derive(Debug, Deserialize)]
struct OpenAiResponse {
    id: String,
    #[serde(default)]
    model: String,
    choices: Vec<OpenAiChoice>,
    #[serde(default)]
    usage: OpenAiUsage,
}

#[derive(Debug, Deserialize)]
struct OpenAiChoice {
    #[serde(default)]
    finish_reason: Option<String>,
    message: OpenAiResponseMessage,
}

#[derive(Debug, Deserialize)]
struct OpenAiResponseMessage {
    #[serde(default)]
    role: String,
    #[serde(default)]
    content: Option<String>,
    #[serde(default)]
    tool_calls: Option<Vec<OpenAiResponseToolCall>>,
}

#[derive(Debug, Deserialize)]
struct OpenAiResponseToolCall {
    id: String,
    #[allow(dead_code)]
    #[serde(rename = "type", default)]
    kind: String,
    function: OpenAiResponseFunctionCall,
}

#[derive(Debug, Deserialize)]
struct OpenAiResponseFunctionCall {
    name: String,
    #[serde(default)]
    arguments: String,
}

#[derive(Debug, Default, Deserialize)]
struct OpenAiUsage {
    #[serde(default)]
    prompt_tokens: u32,
    #[serde(default)]
    completion_tokens: u32,
    /// **Prompt-caching attribution.** OpenAI nests cache-hit
    /// counts under `prompt_tokens_details.cached_tokens` (since
    /// gpt-4o, gpt-4o-mini, o1-mini, o1-preview, and the o3
    /// family). Older deployments may surface a top-level
    /// `cached_tokens` (none observed in production responses,
    /// but the field is documented at the top level by some
    /// SDK versions). We accept either shape and the parser
    /// (`parse_response`) folds whichever is non-zero into
    /// canonical [`Usage::cache_read_input_tokens`].
    ///
    /// Per OpenAI's caching docs, prompts ≥ 1024 tokens are
    /// cached automatically with no opt-in field; this counter
    /// is the only operator-observable signal that caching is
    /// working.
    #[serde(default, rename = "prompt_tokens_details")]
    prompt_tokens_details: OpenAiPromptTokensDetails,
    /// Legacy top-level field — empty in current responses.
    #[serde(default)]
    cached_tokens: u32,
}

#[derive(Debug, Default, Deserialize)]
struct OpenAiPromptTokensDetails {
    /// Number of prompt tokens served from cache. 0 if cache was
    /// missed or the prompt was below the (model-dependent)
    /// caching threshold.
    #[serde(default)]
    cached_tokens: u32,
}

// ---------------------------------------------------------------------------
// Translation: canonical → OpenAI
// ---------------------------------------------------------------------------

fn join_text_blocks(blocks: &[ContentBlock]) -> Option<String> {
    let mut parts: Vec<&str> = Vec::new();
    for b in blocks {
        if let ContentBlock::Text { text } = b {
            parts.push(text);
        }
    }
    if parts.is_empty() {
        None
    } else {
        Some(parts.join("\n\n"))
    }
}

fn collect_tool_calls(blocks: &[ContentBlock]) -> Vec<OpenAiToolCall> {
    let mut out = Vec::new();
    for b in blocks {
        if let ContentBlock::ToolUse { id, name, input } = b {
            out.push(OpenAiToolCall {
                id: id.clone(),
                kind: "function".to_owned(),
                function: OpenAiFunctionCall {
                    name: name.clone(),
                    arguments: input.to_string(),
                },
            });
        }
    }
    out
}

fn build_messages(req: &MessageRequest) -> Vec<OpenAiMessage> {
    let mut out: Vec<OpenAiMessage> = Vec::new();
    if let Some(sys) = req.system.as_ref() {
        out.push(OpenAiMessage {
            role: "system".to_owned(),
            content: Some(sys.clone()),
            tool_calls: Vec::new(),
            tool_call_id: None,
        });
    }
    for m in &req.messages {
        match m.role.as_str() {
            "assistant" => {
                let text = join_text_blocks(&m.content);
                let tool_calls = collect_tool_calls(&m.content);
                out.push(OpenAiMessage {
                    role: "assistant".to_owned(),
                    content: text,
                    tool_calls,
                    tool_call_id: None,
                });
            }
            "user" => {
                // OpenAI requires every tool result to be its own
                // message (`role: "tool"`). Anthropic packs them
                // into a single user message; split them here.
                let mut text_blocks: Vec<&str> = Vec::new();
                let mut tool_results: Vec<(&str, String)> = Vec::new();
                for b in &m.content {
                    match b {
                        ContentBlock::Text { text } => text_blocks.push(text),
                        ContentBlock::ToolResult {
                            tool_use_id,
                            content,
                            ..
                        } => {
                            tool_results.push((tool_use_id.as_str(), content.clone()));
                        }
                        _ => { /* tool_use cannot appear in a user role on egress */ }
                    }
                }
                if !text_blocks.is_empty() {
                    out.push(OpenAiMessage {
                        role: "user".to_owned(),
                        content: Some(text_blocks.join("\n\n")),
                        tool_calls: Vec::new(),
                        tool_call_id: None,
                    });
                }
                for (tid, body) in tool_results {
                    out.push(OpenAiMessage {
                        role: "tool".to_owned(),
                        content: Some(body),
                        tool_calls: Vec::new(),
                        tool_call_id: Some(tid.to_owned()),
                    });
                }
            }
            other => {
                // Forward unknown roles verbatim; OpenAI will reject
                // them, surfacing as `Upstream`.
                out.push(OpenAiMessage {
                    role: other.to_owned(),
                    content: join_text_blocks(&m.content),
                    tool_calls: Vec::new(),
                    tool_call_id: None,
                });
            }
        }
    }
    out
}

fn build_tools<'a>(tools: &'a [ToolSpec]) -> Vec<OpenAiToolWrapper<'a>> {
    tools
        .iter()
        .map(|t| OpenAiToolWrapper {
            kind: "function",
            function: OpenAiFunctionDef {
                name: t.name.as_str(),
                description: t.description.as_str(),
                parameters: &t.input_schema,
            },
        })
        .collect()
}

fn build_request_body<'a>(req: &'a MessageRequest) -> OpenAiRequest<'a> {
    OpenAiRequest {
        model: req.model.as_str(),
        max_tokens: req.max_tokens,
        temperature: req.temperature,
        messages: build_messages(req),
        tools: build_tools(&req.tools),
    }
}

// ---------------------------------------------------------------------------
// Translation: OpenAI → canonical
// ---------------------------------------------------------------------------

fn map_finish_reason(s: &str) -> String {
    match s {
        "stop" => "end_turn".to_owned(),
        "length" => "max_tokens".to_owned(),
        "tool_calls" => "tool_use".to_owned(),
        other => other.to_owned(),
    }
}

fn parse_response(raw: &OpenAiResponse) -> Result<MessageResponse, ModelError> {
    let choice = raw
        .choices
        .first()
        .ok_or_else(|| ModelError::Json("OpenAI response had no choices".to_owned()))?;
    let msg = &choice.message;

    let mut content: Vec<ContentBlock> = Vec::new();
    if let Some(text) = msg.content.as_ref().filter(|s| !s.is_empty()) {
        content.push(ContentBlock::Text { text: text.clone() });
    }
    if let Some(calls) = msg.tool_calls.as_ref() {
        for c in calls {
            let input = serde_json::from_str::<serde_json::Value>(&c.function.arguments)
                .unwrap_or_else(|_| serde_json::json!({ "raw": c.function.arguments }));
            content.push(ContentBlock::ToolUse {
                id: c.id.clone(),
                name: c.function.name.clone(),
                input,
            });
        }
    }

    let role = if msg.role.is_empty() {
        "assistant".to_owned()
    } else {
        msg.role.clone()
    };
    let stop_reason = choice.finish_reason.as_deref().map(map_finish_reason);
    // OpenAI surfaces cache-hit counts at
    // `prompt_tokens_details.cached_tokens` per the current
    // API; some SDK versions document a top-level `cached_tokens`
    // field. Take whichever is non-zero (canonical = nested) so a
    // caller sees a consistent `Usage::cache_read_input_tokens`
    // regardless of the OpenAI-side surface.
    let cache_read = std::cmp::max(
        raw.usage.prompt_tokens_details.cached_tokens,
        raw.usage.cached_tokens,
    );
    Ok(MessageResponse {
        id: raw.id.clone(),
        kind: "message".to_owned(),
        role,
        content,
        stop_reason,
        usage: Usage {
            input_tokens: raw.usage.prompt_tokens,
            output_tokens: raw.usage.completion_tokens,
            cache_creation_input_tokens: 0,
            cache_read_input_tokens: cache_read,
        },
        model: raw.model.clone(),
    })
}

// ---------------------------------------------------------------------------
// OpenAiClient
// ---------------------------------------------------------------------------

/// Production OpenAI Chat Completions client. The buffered call
/// path goes through an [`crate::http_fetch::HttpFetch`] so the
/// same client works under direct egress and the kernel-mediated
/// substrate transparently.
pub struct OpenAiClient {
    http_fetch: std::sync::Arc<dyn crate::http_fetch::HttpFetch>,
    base_url: String,
    request_timeout: Duration,
}

impl OpenAiClient {
    /// Construct an OpenAI-compatible client over the default
    /// direct-egress HTTP transport. Equivalent to
    /// `OpenAiClient::with_http_fetch(base_url, Arc::new(DirectHttpFetch::new()))`.
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
impl ModelClient for OpenAiClient {
    async fn create_message(&self, req: &MessageRequest) -> Result<MessageResponse, ModelError> {
        let url = format!("{}/v1/chat/completions", self.base_url);
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

        let raw: OpenAiResponse =
            serde_json::from_slice(&resp.body).map_err(|e| ModelError::Json(e.to_string()))?;
        parse_response(&raw)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Message, ToolSpec};

    fn req_with_history() -> MessageRequest {
        MessageRequest {
            model: "gpt-4o-mini".to_owned(),
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
                    content: vec![
                        ContentBlock::Text {
                            text: "let me compute".to_owned(),
                        },
                        ContentBlock::ToolUse {
                            id: "call-A".to_owned(),
                            name: "calc".to_owned(),
                            input: serde_json::json!({"expr": "1+1"}),
                        },
                    ],
                },
                Message {
                    role: "user".to_owned(),
                    content: vec![ContentBlock::ToolResult {
                        tool_use_id: "call-A".to_owned(),
                        content: "2".to_owned(),
                        is_error: None,
                    }],
                },
            ],
            tools: vec![ToolSpec {
                name: "calc".to_owned(),
                description: "evaluate".to_owned(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": { "expr": { "type": "string" } },
                    "required": ["expr"],
                }),
            }],
            ..Default::default()
        }
    }

    #[test]
    fn request_translation_includes_system_message() {
        let req = req_with_history();
        let body = build_request_body(&req);
        let json = serde_json::to_value(&body).unwrap();
        assert_eq!(json["model"], "gpt-4o-mini");
        assert_eq!(json["max_tokens"], 256);
        let msgs = json["messages"].as_array().unwrap();
        assert_eq!(msgs[0]["role"], "system");
        assert_eq!(msgs[0]["content"], "be helpful");
    }

    #[test]
    fn request_translation_unpacks_tool_result_into_separate_tool_message() {
        let req = req_with_history();
        let body = build_request_body(&req);
        let json = serde_json::to_value(&body).unwrap();
        let msgs = json["messages"].as_array().unwrap();
        // Order: system, user (q), assistant (text+toolcall), tool (result)
        assert_eq!(msgs[0]["role"], "system");
        assert_eq!(msgs[1]["role"], "user");
        assert_eq!(msgs[2]["role"], "assistant");
        let tool_calls = msgs[2]["tool_calls"].as_array().unwrap();
        assert_eq!(tool_calls.len(), 1);
        assert_eq!(tool_calls[0]["id"], "call-A");
        assert_eq!(tool_calls[0]["function"]["name"], "calc");
        // Arguments must be a STRING, not an object (OpenAI quirk).
        assert!(tool_calls[0]["function"]["arguments"].is_string());
        assert_eq!(msgs[3]["role"], "tool");
        assert_eq!(msgs[3]["tool_call_id"], "call-A");
        assert_eq!(msgs[3]["content"], "2");
    }

    #[test]
    fn request_translation_wraps_tools_with_function_envelope() {
        let req = req_with_history();
        let body = build_request_body(&req);
        let json = serde_json::to_value(&body).unwrap();
        let tools = json["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0]["type"], "function");
        assert_eq!(tools[0]["function"]["name"], "calc");
        assert_eq!(tools[0]["function"]["description"], "evaluate");
        assert!(tools[0]["function"]["parameters"]["properties"]["expr"].is_object());
    }

    #[test]
    fn response_translation_maps_finish_reason_and_tool_calls() {
        let raw = serde_json::json!({
            "id": "chatcmpl-x",
            "model": "gpt-4o-mini",
            "choices": [{
                "index": 0,
                "finish_reason": "tool_calls",
                "message": {
                    "role": "assistant",
                    "content": "let me compute",
                    "tool_calls": [{
                        "id": "call_2",
                        "type": "function",
                        "function": { "name": "calc", "arguments": "{\"expr\":\"1+2\"}" }
                    }]
                }
            }],
            "usage": { "prompt_tokens": 10, "completion_tokens": 4 }
        });
        let raw: OpenAiResponse = serde_json::from_value(raw).unwrap();
        let canonical = parse_response(&raw).unwrap();
        assert_eq!(canonical.id, "chatcmpl-x");
        assert_eq!(canonical.model, "gpt-4o-mini");
        assert_eq!(canonical.role, "assistant");
        assert_eq!(canonical.stop_reason.as_deref(), Some("tool_use"));
        assert_eq!(canonical.usage.input_tokens, 10);
        assert_eq!(canonical.usage.output_tokens, 4);
        // First text, then tool_use
        match &canonical.content[0] {
            ContentBlock::Text { text } => assert_eq!(text, "let me compute"),
            other => panic!("expected text, got {other:?}"),
        }
        match &canonical.content[1] {
            ContentBlock::ToolUse { id, name, input } => {
                assert_eq!(id, "call_2");
                assert_eq!(name, "calc");
                assert_eq!(input["expr"], "1+2");
            }
            other => panic!("expected tool_use, got {other:?}"),
        }
    }

    #[test]
    fn response_translation_preserves_unparseable_arguments_as_raw() {
        let raw = serde_json::json!({
            "id": "chatcmpl-y",
            "model": "gpt-4o",
            "choices": [{
                "index": 0,
                "finish_reason": "tool_calls",
                "message": {
                    "role": "assistant",
                    "content": null,
                    "tool_calls": [{
                        "id": "call_y",
                        "type": "function",
                        "function": { "name": "shell", "arguments": "ls -la /tmp" }
                    }]
                }
            }]
        });
        let raw: OpenAiResponse = serde_json::from_value(raw).unwrap();
        let canonical = parse_response(&raw).unwrap();
        match &canonical.content[0] {
            ContentBlock::ToolUse { input, .. } => {
                assert_eq!(input["raw"], "ls -la /tmp");
            }
            other => panic!("expected tool_use with raw fallback, got {other:?}"),
        }
    }

    #[test]
    fn maps_finish_reason_table_is_complete() {
        assert_eq!(map_finish_reason("stop"), "end_turn");
        assert_eq!(map_finish_reason("length"), "max_tokens");
        assert_eq!(map_finish_reason("tool_calls"), "tool_use");
        assert_eq!(map_finish_reason("safety"), "safety");
    }

    /// **Prompt-caching attribution — nested `prompt_tokens_details`.**
    ///
    /// OpenAI surfaces cache-hit counts at
    /// `usage.prompt_tokens_details.cached_tokens` (since gpt-4o,
    /// gpt-4o-mini, o1-*, o3-*). The canonical
    /// `Usage::cache_read_input_tokens` MUST reflect that count so
    /// dispatch / operator telemetry stays provider-agnostic.
    #[test]
    fn cached_tokens_from_prompt_tokens_details_folds_into_canonical_usage() {
        let raw = serde_json::json!({
            "id": "chatcmpl-cache",
            "model": "gpt-4o-mini",
            "choices": [{
                "index": 0,
                "finish_reason": "stop",
                "message": { "role": "assistant", "content": "hi" }
            }],
            "usage": {
                "prompt_tokens":     2006,
                "completion_tokens": 5,
                "prompt_tokens_details": { "cached_tokens": 1920 }
            }
        });
        let raw: OpenAiResponse = serde_json::from_value(raw).unwrap();
        let canonical = parse_response(&raw).unwrap();
        assert_eq!(canonical.usage.input_tokens, 2006);
        assert_eq!(
            canonical.usage.cache_read_input_tokens, 1920,
            "OpenAI cached_tokens MUST fold into Usage::cache_read_input_tokens \
             so dispatch-side budget accounting matches Anthropic semantics"
        );
        // OpenAI does not surface a per-call cache-write counter.
        assert_eq!(canonical.usage.cache_creation_input_tokens, 0);
    }

    /// **Prompt-caching attribution — legacy top-level `cached_tokens`.**
    ///
    /// Some SDK versions document a top-level `usage.cached_tokens`.
    /// The parser accepts either shape (max-of-two) so a gateway
    /// that flattens the nested counter to top-level is honored.
    #[test]
    fn cached_tokens_from_top_level_field_also_folds_into_canonical_usage() {
        let raw = serde_json::json!({
            "id": "chatcmpl-flat",
            "model": "gpt-4o-mini",
            "choices": [{
                "index": 0,
                "finish_reason": "stop",
                "message": { "role": "assistant", "content": "hi" }
            }],
            "usage": {
                "prompt_tokens":     500,
                "completion_tokens": 10,
                "cached_tokens":     400
            }
        });
        let raw: OpenAiResponse = serde_json::from_value(raw).unwrap();
        let canonical = parse_response(&raw).unwrap();
        assert_eq!(canonical.usage.cache_read_input_tokens, 400);
    }

    #[tokio::test]
    async fn unreachable_url_surfaces_transport_error() {
        let client = OpenAiClient::new("http://127.0.0.1:1");
        let req = req_with_history();
        let err = client.create_message(&req).await.unwrap_err();
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
            // Read until headers + a small body land
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
            let body = br#"{"id":"chatcmpl-1","model":"gpt-4o-mini","choices":[{"index":0,"finish_reason":"stop","message":{"role":"assistant","content":"hi"}}],"usage":{"prompt_tokens":3,"completion_tokens":1}}"#;
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len(),
            );
            sock.write_all(resp.as_bytes()).await.unwrap();
            sock.write_all(body).await.unwrap();
        });

        let client = OpenAiClient::new(format!("http://127.0.0.1:{port}"));
        let req = req_with_history();
        let resp = client.create_message(&req).await.unwrap();
        assert_eq!(resp.id, "chatcmpl-1");
        assert_eq!(resp.stop_reason.as_deref(), Some("end_turn"));
        match &resp.content[0] {
            ContentBlock::Text { text } => assert_eq!(text, "hi"),
            other => panic!("expected text, got {other:?}"),
        }
        server.await.unwrap();
    }
}

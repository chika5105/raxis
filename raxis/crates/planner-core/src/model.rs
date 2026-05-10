//! `ModelClient` — guest-side LLM API surface.
//!
//! Closes V2_GAPS.md §B1 substep "Model API client via Gateway" by
//! giving each planner role binary a single, transport-agnostic
//! Anthropic Messages API client. Per `e2e-live-test-gap.md` the
//! production egress path is:
//!
//! ```text
//!   planner binary
//!      │  HTTPS POST https://api.anthropic.com/v1/messages
//!      ▼
//!   tproxy (intra-VM iptables redirect)
//!      │  routes to host-side gateway loopback
//!      ▼
//!   raxis-gateway (host-side)
//!      │  injects `x-api-key`, validates allowlist, forwards
//!      ▼
//!   api.anthropic.com:443
//! ```
//!
//! From the planner's POV, the model client is just a `reqwest`
//! HTTPS client targeting the upstream URL. The Anthropic API key
//! is held by the kernel/gateway — the planner binary itself never
//! sees the credential bytes (which is why
//! `AnthropicClient::new(...)` does NOT take an `api_key`
//! parameter; the gateway will reject any request that includes a
//! planner-supplied `x-api-key` header per `peripherals.md §3.2`
//! "Credential injection precedence").
//!
//! ## Why Anthropic-shaped types live in `planner-core`
//!
//! The Anthropic Messages API is the **only** model API V2 ships
//! against — we do not abstract the on-the-wire shape behind a
//! provider-agnostic enum because:
//!
//! 1. Tool-use semantics differ enough between Anthropic / OpenAI /
//!    Gemini that any "lowest common denominator" type would lose
//!    information (tool-result blocks, structured tool errors, etc).
//! 2. The static dispatch matrix (`v2-deep-spec.md §Step 20`)
//!    pins the planner-side behaviour to one provider per
//!    `[providers]` entry; runtime polymorphism over provider shape
//!    is policy-layer concern, not planner-binary concern.
//! 3. A future `OpenAiClient` impl plugs into the same
//!    [`ModelClient`] trait without touching the dispatch loop.
//!
//! ## V2 limits (declared so future work has a target)
//!
//! * **No streaming.** V2 uses non-streaming Messages API
//!   responses — the planner waits for the full response before
//!   running tool dispatch. Streaming changes the dispatch-loop
//!   shape (mid-stream `tool_use` events) and is deferred.
//!
//!   This is the **structural enforcement of
//!   `INV-GATEWAY-STREAM-ATOMICITY`** (V2_GAPS.md §13 Category 1):
//!   because the V2 [`ModelClient::create_message`] call is one
//!   request → one fully-buffered response, every assistant
//!   turn (`stop_reason`, `content`, `usage`) is observed
//!   atomically by the dispatch loop. There is no partial-frame
//!   or interleaved-tool-use code path that could violate
//!   atomicity. When streaming is added in V3, this annotation
//!   must move to the streaming aggregator.
//! * **No vision / files.** `content` blocks are text-only; tool
//!   outputs are bytes (UTF-8 strings). The Anthropic schema
//!   supports image blocks; the planner does not emit them.
//! * **No prompt caching.** The `cache_control` field on system /
//!   user blocks is supported by Anthropic but the planner does
//!   not opt in (every turn re-renders the system prompt). Adding
//!   prompt caching is a B2 follow-up after the dispatch loop's
//!   per-turn token telemetry lands.

use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;

// ---------------------------------------------------------------------------
// Anthropic Messages API — request shape
// ---------------------------------------------------------------------------

/// One Anthropic message in the conversation history.
///
/// **Wire shape.** Matches the Anthropic Messages API exactly so the
/// JSON serialisation `cargo` produces is the on-the-wire body. We
/// do NOT round-trip through a generic `serde_json::Value` to keep
/// the type checker honest about which fields the planner reads vs.
/// writes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    /// `"user"` or `"assistant"`. The Anthropic API rejects any
    /// other string — encoded as a `String` rather than an enum so
    /// future role values (e.g. `"system"` is currently disallowed
    /// as a message role; system goes in the top-level `system`
    /// field) don't require a planner rebuild.
    pub role:    String,
    /// Conversation block list. Mixed text + tool_use + tool_result
    /// blocks; see [`ContentBlock`].
    pub content: Vec<ContentBlock>,
}

/// One content block within a [`Message`].
///
/// `serde(tag = "type", rename_all = "snake_case")` matches the
/// Anthropic-side discriminator. The block-shape variants here are
/// the subset the V2 dispatch loop reads / writes:
///
/// * `text` — plain text, both directions.
/// * `tool_use` — assistant requests a tool call.
/// * `tool_result` — user (planner) returns the tool's output.
///
/// Other block kinds (`image`, `document`) round-trip as
/// [`ContentBlock::Other`] so an upstream payload that adds new
/// kinds doesn't break the planner's deserialisation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ContentBlock {
    /// Plain text block. Round-trips both inbound (assistant
    /// reasoning) and outbound (user instructions / KSB).
    Text {
        /// The text content. UTF-8.
        text: String,
    },

    /// Assistant's tool-use block. Inbound only (the planner never
    /// emits this); the dispatch loop pattern-matches on
    /// `ToolUse { id, name, input }`, executes the named tool from
    /// the registry, and emits a matching `ToolResult { tool_use_id }`
    /// back into the next turn's `Message::User`.
    ToolUse {
        /// Anthropic-minted tool-use ID. The planner echoes this
        /// verbatim into the matching `tool_result` so the model's
        /// next turn correlates the result with the request.
        id:    String,
        /// Tool name, looked up in the planner's registry. Unknown
        /// names surface as a tool error, NOT a hard failure (the
        /// model occasionally emits hallucinated tool names; the
        /// dispatch loop returns an error string and lets the model
        /// recover).
        name:  String,
        /// Tool input, schema-validated by the registry before the
        /// tool runs.
        input: serde_json::Value,
    },

    /// User-side tool-result block. Outbound only (the model never
    /// emits this); the dispatch loop appends it to the next
    /// `Message::User` for every assistant `ToolUse` block in the
    /// previous turn.
    ToolResult {
        /// MUST equal the `id` of the assistant's `ToolUse` block
        /// being responded to.
        tool_use_id: String,
        /// Tool output. UTF-8 string for text-shaped tool results;
        /// future binary-result tools (image diff, etc.) will need
        /// the Anthropic-side `content: [...]` shape, not yet wired.
        content:     String,
        /// `Some(true)` ⇔ the tool reported a structured error and
        /// the model should treat the content as an error message.
        /// Anthropic-side default is `false`; we surface it as
        /// `Option<bool>` so we can omit the field on success
        /// (matching the Anthropic example payloads).
        #[serde(skip_serializing_if = "Option::is_none")]
        is_error:    Option<bool>,
    },

    /// Catch-all for block kinds the planner does not understand.
    /// Round-trips through `serde_json::Value` so a future Anthropic
    /// schema extension does not break deserialisation; the dispatch
    /// loop ignores these blocks.
    #[serde(untagged)]
    Other(serde_json::Value),
}

/// Tool definition the planner advertises to the model.
///
/// `name` MUST match a registered tool in the dispatch loop's
/// [`crate::tools::ToolRegistry`]; `input_schema` is the JSON Schema
/// the model uses to construct the `tool_use.input` payload.
///
/// Anthropic's API rejects names containing characters outside
/// `[A-Za-z0-9_]`; the planner-side registry enforces the same rule
/// at registration time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolSpec {
    /// ASCII identifier, must match the registry entry.
    pub name:         String,
    /// Human-readable description shown to the model. The Anthropic
    /// API truncates to ~1024 chars; we surface long descriptions
    /// verbatim so the truncation is observable end-to-end.
    pub description:  String,
    /// JSON Schema for the tool's input parameters. The dispatch
    /// loop also validates against this schema before invoking the
    /// tool to fail-closed on a model that hallucinates input shape.
    pub input_schema: serde_json::Value,
}

/// Top-level request body for Anthropic's
/// `POST /v1/messages` endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageRequest {
    /// Anthropic model identifier (e.g. `"claude-sonnet-4-5-20250929"`).
    /// Per provider-model-selection.md the planner reads the value
    /// from the kernel-stamped `RAXIS_MODEL_ID` env var.
    pub model:       String,

    /// Maximum tokens the model may emit. Hard-capped on the
    /// kernel side via the per-provider `max_tokens_per_request`
    /// in `policy.toml`; the planner-side default is 4096 and the
    /// kernel rejects requests above the policy ceiling at the
    /// gateway.
    pub max_tokens:  u32,

    /// Top-level system prompt. The dispatch loop renders the KSB
    /// + role-specific NNSP into this field once per session;
    /// individual turn-level system blocks are not used.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub system:      Option<String>,

    /// Conversation history. The dispatch loop appends one `user`
    /// + one `assistant` message per turn.
    pub messages:    Vec<Message>,

    /// Tools the model may call this turn. Empty ⇒ pure-text
    /// dialogue (used by reviewer post-hoc summary, not by the
    /// dispatch loop).
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub tools:       Vec<ToolSpec>,

    /// Per-turn temperature. Anthropic's default is 1.0; the V2
    /// planner pins 0.7 for executor / 0.3 for reviewer — tighter
    /// reviewer temperature reduces flake on the verdict tool. See
    /// `provider-model-selection.md §6.2`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f32>,

    /// V2_GAPS §C9 — opt into Anthropic's SSE streaming endpoint.
    ///
    /// When `true`, the upstream returns a `text/event-stream`
    /// body with incremental events; consumers go through
    /// [`ModelClient::create_message_stream`] (see also
    /// `crate::streaming`). When `false` (default), the upstream
    /// returns a single buffered JSON envelope and consumers go
    /// through [`ModelClient::create_message`].
    ///
    /// `#[serde(skip_serializing_if = "is_false")]` keeps the
    /// on-the-wire shape stable for callers that haven't opted into
    /// streaming — adding the field would otherwise change the
    /// serialized JSON for every request and risk breaking the
    /// `request_serialises_to_anthropic_wire_shape` golden test.
    #[serde(skip_serializing_if = "is_false", default)]
    pub stream:      bool,
}

/// Helper: matches the `MessageRequest::stream` skip predicate.
/// Free function so the `#[serde(skip_serializing_if)]` attribute
/// can name it without leaking trait surface.
#[inline]
fn is_false(b: &bool) -> bool {
    !*b
}

impl Default for MessageRequest {
    /// V2_GAPS §C9 — convenience constructor used by tests + the
    /// retry / fallback / circuit breaker shells. `..Default::default()`
    /// at construction sites avoids cascade-edit churn whenever a
    /// new optional field lands.
    fn default() -> Self {
        Self {
            model:       String::new(),
            max_tokens:  4096,
            system:      None,
            messages:    Vec::new(),
            tools:       Vec::new(),
            temperature: None,
            stream:      false,
        }
    }
}

// ---------------------------------------------------------------------------
// Anthropic Messages API — response shape
// ---------------------------------------------------------------------------

/// Top-level response from `POST /v1/messages`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageResponse {
    /// Anthropic-minted message id. Round-tripped into
    /// `gateway.audit.fetch_completed.upstream_message_id` so the
    /// audit chain links back to the upstream provider's logs.
    pub id:            String,
    /// Always `"message"`.
    #[serde(rename = "type")]
    pub kind:          String,
    /// Always `"assistant"` for V2 — the planner does not currently
    /// use the (Anthropic-internal) `"user"` synthesis path.
    pub role:          String,
    /// The assistant's content blocks for this turn — mixed
    /// `text` + `tool_use`. The dispatch loop dispatches every
    /// `tool_use` block in declaration order.
    pub content:       Vec<ContentBlock>,
    /// Why the model stopped emitting. Values:
    /// `"end_turn"` (normal), `"max_tokens"` (truncated),
    /// `"stop_sequence"`, `"tool_use"` (assistant emitted ≥1
    /// `tool_use` block; dispatch loop drives the next turn).
    pub stop_reason:   Option<String>,
    /// Token usage for telemetry. Surfaced into the per-task
    /// `tokens_used` budget snapshot via the dispatch loop.
    pub usage:         Usage,
    /// Echo of the model id from the request. Useful for routing
    /// audit / cost-estimation paths when a provider does silent
    /// upgrades (e.g. `claude-sonnet-4-5-20250929` → newer).
    pub model:         String,
}

/// Token-usage counters from one Anthropic response. Wire shape
/// matches the Anthropic API exactly.
///
/// **Streaming-friendly defaults.** All four fields carry
/// `#[serde(default)]` so partial-usage payloads (Anthropic's
/// mid-stream `message_delta` event surfaces only `output_tokens`;
/// OpenAI's terminal chunk surfaces `prompt_tokens` /
/// `completion_tokens` mapped onto these names) deserialize
/// cleanly into a `Usage` struct without us having to branch on
/// the provider's incremental schema. The aggregator in
/// `crate::streaming::AnthropicStreamAggregator` carries the
/// authoritative pre-stream values forward across deltas, so a
/// missing field reads as "unchanged" rather than "zero".
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Usage {
    /// Input tokens consumed (system + user history).
    #[serde(default)]
    pub input_tokens:               u32,
    /// Output tokens emitted (assistant content this turn).
    #[serde(default)]
    pub output_tokens:              u32,
    /// Cache-read input tokens (Anthropic prompt-caching). 0
    /// when caching is disabled (V2 default).
    #[serde(default)]
    pub cache_creation_input_tokens: u32,
    /// Cache-creation input tokens. 0 when caching is disabled.
    #[serde(default)]
    pub cache_read_input_tokens:    u32,
}

// ---------------------------------------------------------------------------
// Error taxonomy
// ---------------------------------------------------------------------------

/// Errors surfaced by [`ModelClient::chat`] implementations.
///
/// Variants are mapped onto a stable [`crate::PlannerError::exit_code`] in
/// the planner binary's `main`; tests assert on the discriminant rather than
/// the wrapped error text.
#[derive(Debug, Error)]
pub enum ModelError {
    /// HTTP transport failure (TLS, DNS, connection refused, etc.).
    #[error("transport error: {0}")]
    Transport(String),
    /// HTTP timeout for this request.
    #[error("timeout after {0:?}")]
    Timeout(Duration),
    /// Anthropic returned a non-2xx status. The body is preserved so
    /// the dispatch loop can surface a structured `error.type` /
    /// `error.message` to the operator-side audit chain.
    #[error("upstream HTTP {status}: {body}")]
    Upstream {
        /// HTTP status code from the gateway.
        status: u16,
        /// Up to 4 KiB of response body (truncated to keep the
        /// audit-event size in check).
        body:   String,
    },
    /// JSON encode/decode failure. The Anthropic API occasionally
    /// returns content blocks the planner does not understand; that
    /// path is handled by `ContentBlock::Other`, NOT by this error.
    /// Reaching this variant means the wire bytes did not parse as
    /// JSON at all.
    #[error("malformed JSON: {0}")]
    Json(String),
}

impl From<reqwest::Error> for ModelError {
    fn from(e: reqwest::Error) -> Self {
        if e.is_timeout() {
            ModelError::Timeout(Duration::from_secs(0))
        } else {
            ModelError::Transport(e.to_string())
        }
    }
}

// ---------------------------------------------------------------------------
// ModelClient trait + AnthropicClient impl
// ---------------------------------------------------------------------------

/// **Guest-side LLM client surface.** The dispatch loop holds an
/// `Arc<dyn ModelClient>` so it can swap between the production
/// Anthropic impl, in-process test fakes, and (a future)
/// OpenAiClient without re-monomorphising.
#[async_trait::async_trait]
pub trait ModelClient: Send + Sync {
    /// Send one Messages API request and read the full response
    /// (buffered). The dispatch loop calls this once per turn.
    async fn create_message(
        &self,
        req: &MessageRequest,
    ) -> Result<MessageResponse, ModelError>;

    /// V2_GAPS §C9 — start a streaming Messages API request and
    /// return a [`tokio::sync::mpsc::Receiver`] that yields
    /// [`crate::streaming::StreamEvent`]s as the upstream
    /// generates content.
    ///
    /// The terminal event on a successful stream is always
    /// [`crate::streaming::StreamEvent::Complete`] carrying the
    /// fully-aggregated [`MessageResponse`]. Intermediate events
    /// (`MessageStart`, `ContentBlockDelta`, `Usage`, `Stop`) are
    /// observability-only — the dispatch loop's tool-execution
    /// logic consumes only the terminal `Complete` (per
    /// `INV-PROVIDER-04`).
    ///
    /// **Default impl.** Calls [`Self::create_message`] and emits
    /// a synthetic four-event stream
    /// (`MessageStart`, `Usage`, `Stop`, `Complete`). Providers
    /// that support real SSE streaming (V2.4: AnthropicClient)
    /// override this to wire the upstream chunk reader.
    ///
    /// **Idle-timeout.** Implementors that override this method
    /// MUST surface
    /// [`ModelError::Timeout`] when no chunk arrives for longer
    /// than [`crate::streaming::DEFAULT_STREAM_IDLE_TIMEOUT`]
    /// (default 30 s) so a stalled provider does not park the
    /// dispatch loop for the full request_timeout ceiling.
    async fn create_message_stream(
        &self,
        req: &MessageRequest,
    ) -> Result<
        tokio::sync::mpsc::Receiver<crate::streaming::StreamEvent>,
        ModelError,
    > {
        // Default forwarder: buffered call, then synthesize a
        // four-event stream so the consumer can use the same
        // event-loop shape regardless of whether the impl
        // really supports streaming.
        let resp = self.create_message(req).await?;
        let (tx, rx) = tokio::sync::mpsc::channel(crate::streaming::DEFAULT_STREAM_CHANNEL_CAP);
        let _ = tx
            .send(crate::streaming::StreamEvent::MessageStart {
                id:    resp.id.clone(),
                model: resp.model.clone(),
            })
            .await;
        let _ = tx
            .send(crate::streaming::StreamEvent::Usage(resp.usage.clone()))
            .await;
        let _ = tx
            .send(crate::streaming::StreamEvent::Stop {
                stop_reason: resp.stop_reason.clone(),
            })
            .await;
        let _ = tx
            .send(crate::streaming::StreamEvent::Complete(resp))
            .await;
        Ok(rx)
    }
}

/// Production Anthropic Messages API client. POSTs to
/// `<base_url>/v1/messages` (default
/// `https://api.anthropic.com`); the gateway's tproxy redirect is
/// transparent — this struct does not need to know whether it's
/// talking to Anthropic directly or through the gateway proxy.
pub struct AnthropicClient {
    http:           reqwest::Client,
    base_url:       String,
    /// Anthropic-required `anthropic-version` header. Stamped at
    /// build time from a constant; future API versions land as a
    /// new field plumbed through `AnthropicClient::new_with_version`.
    anthropic_version: &'static str,
    /// Per-request total deadline (connect + transfer + read).
    /// The dispatch loop's parent deadline is policy-driven (see
    /// `provider-model-selection.md §6.4`); the client-level value
    /// here is a hard-coded fallback (5 min) for the case where the
    /// caller forgets to wrap in `tokio::time::timeout`.
    request_timeout: Duration,
}

impl AnthropicClient {
    /// Anthropic stable API version pin. Bumped together with the
    /// minimum supported model id in `provider-model-selection.md`.
    pub const ANTHROPIC_VERSION: &'static str = "2023-06-01";

    /// Construct a new client.
    ///
    /// The `api_key` parameter is **deliberately absent** — the
    /// gateway injects credentials into the outbound request per
    /// `peripherals.md §3.2 "Credential injection precedence"`. A
    /// planner-side API key would short-circuit the gateway's audit
    /// chain (the gateway's allowlist + per-provider quota
    /// enforcement keys off the credential it injects, not the one
    /// the request arrives with).
    pub fn new(base_url: impl Into<String>) -> Self {
        let http = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .pool_idle_timeout(Duration::from_secs(30))
            .build()
            .expect("reqwest::Client::build is infallible with default config");

        Self {
            http,
            base_url: base_url.into(),
            anthropic_version: Self::ANTHROPIC_VERSION,
            request_timeout: Duration::from_secs(300),
        }
    }

    /// Override the client-level fallback timeout. Production
    /// dispatch loops should always wrap `create_message(...)` in
    /// `tokio::time::timeout(...)` against the policy-derived
    /// deadline; this just bounds the failure mode if a caller
    /// forgets.
    pub fn with_request_timeout(mut self, d: Duration) -> Self {
        self.request_timeout = d;
        self
    }
}

#[async_trait::async_trait]
impl ModelClient for AnthropicClient {
    async fn create_message(
        &self,
        req: &MessageRequest,
    ) -> Result<MessageResponse, ModelError> {
        let url = format!("{}/v1/messages", self.base_url);
        let body = serde_json::to_vec(req).map_err(|e| ModelError::Json(e.to_string()))?;

        let resp = self
            .http
            .post(&url)
            .timeout(self.request_timeout)
            .header("content-type", "application/json")
            .header("anthropic-version", self.anthropic_version)
            // We intentionally do NOT set `x-api-key`. The gateway
            // injects it at the egress hop; setting it here would
            // be (a) a credential-leak risk and (b) potentially
            // ignored by the gateway depending on its
            // injection-precedence config.
            .body(body)
            .send()
            .await?;

        let status = resp.status();
        let bytes  = resp.bytes().await.map_err(|e| ModelError::Transport(e.to_string()))?;

        if !status.is_success() {
            // Cap the body at 4 KiB so a misbehaving upstream cannot
            // blow up the audit-event payload.
            let snippet = if bytes.len() <= 4096 {
                String::from_utf8_lossy(&bytes).into_owned()
            } else {
                format!(
                    "{}…<truncated {} bytes>",
                    String::from_utf8_lossy(&bytes[..4096]),
                    bytes.len() - 4096,
                )
            };
            return Err(ModelError::Upstream {
                status: status.as_u16(),
                body:   snippet,
            });
        }

        let parsed: MessageResponse = serde_json::from_slice(&bytes)
            .map_err(|e| ModelError::Json(e.to_string()))?;
        Ok(parsed)
    }

    /// V2_GAPS §C9 — real Anthropic SSE streaming.
    ///
    /// Sets `stream: true` on the outbound request, opens an SSE
    /// connection to `<base_url>/v1/messages`, and reads chunks
    /// through the [`crate::streaming::SseParser`] /
    /// [`crate::streaming::AnthropicStreamAggregator`] pair on a
    /// dedicated `tokio::spawn`ed reader task. Per-chunk idle
    /// timeout is [`crate::streaming::DEFAULT_STREAM_IDLE_TIMEOUT`]
    /// (30 s); silence beyond that closes the channel cleanly with
    /// a final `Stop { stop_reason: "stream_idle_timeout_after_30_s" }`
    /// event so the buffered consumer sees a deterministic close
    /// shape rather than a torn channel.
    ///
    /// The reader task closes the receiver cleanly on:
    ///
    /// * Anthropic emitting `event: message_stop` (normal close).
    /// * The HTTP connection ending (graceful upstream EOF).
    ///
    /// And surfaces a synthesized terminal `Stop` event then closes on:
    ///
    /// * Per-chunk idle timeout.
    /// * Transport / connection errors.
    /// * Aggregator rejecting a malformed frame.
    ///
    /// Pre-stream errors (non-2xx response, transport refusal)
    /// surface synchronously as `Err(ModelError::*)` from this
    /// function; the consumer never sees a half-open receiver in
    /// that case.
    async fn create_message_stream(
        &self,
        req: &MessageRequest,
    ) -> Result<
        tokio::sync::mpsc::Receiver<crate::streaming::StreamEvent>,
        ModelError,
    > {
        // Force the stream flag on the outbound request — Anthropic
        // returns SSE only when `stream: true` is explicitly set.
        let mut streaming_req = req.clone();
        streaming_req.stream = true;

        let url = format!("{}/v1/messages", self.base_url);
        let body = serde_json::to_vec(&streaming_req)
            .map_err(|e| ModelError::Json(e.to_string()))?;

        let mut resp = self
            .http
            .post(&url)
            .timeout(self.request_timeout)
            .header("content-type", "application/json")
            .header("anthropic-version", self.anthropic_version)
            .header("accept", "text/event-stream")
            .body(body)
            .send()
            .await?;

        // Pre-stream status check — Anthropic returns an SSE body
        // only on a 2xx. Errors arrive as a single JSON envelope
        // with the same buffered shape we already know how to
        // surface.
        let status = resp.status();
        if !status.is_success() {
            let bytes = resp
                .bytes()
                .await
                .map_err(|e| ModelError::Transport(e.to_string()))?;
            let snippet = if bytes.len() <= 4096 {
                String::from_utf8_lossy(&bytes).into_owned()
            } else {
                format!(
                    "{}…<truncated {} bytes>",
                    String::from_utf8_lossy(&bytes[..4096]),
                    bytes.len() - 4096,
                )
            };
            return Err(ModelError::Upstream {
                status: status.as_u16(),
                body:   snippet,
            });
        }

        let (tx, rx) = tokio::sync::mpsc::channel(
            crate::streaming::DEFAULT_STREAM_CHANNEL_CAP,
        );
        let idle = crate::streaming::DEFAULT_STREAM_IDLE_TIMEOUT;

        tokio::spawn(async move {
            let mut parser   = crate::streaming::SseParser::new();
            let mut agg      = crate::streaming::AnthropicStreamAggregator::new();
            let mut saw_stop = false;

            loop {
                let chunk = tokio::time::timeout(idle, resp.chunk()).await;
                match chunk {
                    Err(_) => {
                        // Idle timeout — synthesize a terminal Stop
                        // event so consumers see a deterministic
                        // close shape.
                        let _ = tx
                            .send(crate::streaming::StreamEvent::Stop {
                                stop_reason: Some(format!(
                                    "stream_idle_timeout_after_{}_s",
                                    idle.as_secs(),
                                )),
                            })
                            .await;
                        return;
                    }
                    Ok(Err(e)) => {
                        let _ = tx
                            .send(crate::streaming::StreamEvent::Stop {
                                stop_reason: Some(format!(
                                    "stream_transport_error: {e}"
                                )),
                            })
                            .await;
                        return;
                    }
                    Ok(Ok(None)) => break, // graceful EOF
                    Ok(Ok(Some(bytes))) => {
                        for frame in parser.push(&bytes) {
                            match agg.ingest(&frame) {
                                Ok(events) => {
                                    for ev in events {
                                        if matches!(
                                            ev,
                                            crate::streaming::StreamEvent::Stop { .. }
                                        ) {
                                            saw_stop = true;
                                        }
                                        if tx.send(ev).await.is_err() {
                                            // Consumer dropped the
                                            // receiver — bail rather
                                            // than keep an orphaned
                                            // upstream connection
                                            // pinned open.
                                            return;
                                        }
                                    }
                                }
                                Err(e) => {
                                    let _ = tx
                                        .send(crate::streaming::StreamEvent::Stop {
                                            stop_reason: Some(format!(
                                                "stream_aggregator_error: {e}"
                                            )),
                                        })
                                        .await;
                                    return;
                                }
                            }
                        }
                    }
                }
            }

            // Stream EOF reached. If the aggregator collected a
            // complete response, emit Complete; otherwise emit a
            // terminal Stop with `stream_eof_before_message_stop`
            // so the buffered consumer can distinguish a clean
            // close from a torn one without reading channel state.
            if !saw_stop {
                let _ = tx
                    .send(crate::streaming::StreamEvent::Stop {
                        stop_reason: Some("stream_eof_before_message_stop".to_owned()),
                    })
                    .await;
            }
            if agg.is_complete() {
                if let Ok(resp) = agg.into_response() {
                    let _ = tx
                        .send(crate::streaming::StreamEvent::Complete(resp))
                        .await;
                }
            }
        });

        Ok(rx)
    }
}

// ---------------------------------------------------------------------------
// Test fakes
//
// Gated on `debug_assertions || test` per the workspace's mock-isolation
// discipline (see `raxis-test-support/src/lib.rs` Layer 1). In a release
// build of any crate that depends on `raxis-planner-core`, `MockModelClient`
// does not exist and any reference to it fails to compile with E0432.
//
// This is an interim measure. The clean long-term path is to extract the
// `ModelClient` trait into a `raxis-planner-substrate` crate (like
// `raxis-gateway-substrate`) so `raxis-test-support` can host the mock
// without creating a circular dependency. Until then, gating here achieves
// the same production-safety guarantee.
// ---------------------------------------------------------------------------

/// In-memory test fake — pre-canned responses driven by the test.
///
/// The dispatch-loop unit tests construct one `MockModelClient`
/// queued with a sequence of `MessageResponse` values and verify
/// the dispatch behaviour against each turn's response.
#[cfg(any(debug_assertions, test))]
pub struct MockModelClient {
    pending: Arc<tokio::sync::Mutex<Vec<MessageResponse>>>,
    /// Captured inbound requests, in order. Tests assert against
    /// this to pin the dispatch-loop's per-turn message
    /// construction.
    pub seen: Arc<tokio::sync::Mutex<Vec<MessageRequest>>>,
}

#[cfg(any(debug_assertions, test))]
impl MockModelClient {
    /// Construct from a queue of pre-canned responses (FIFO).
    pub fn new(responses: Vec<MessageResponse>) -> Self {
        Self {
            pending: Arc::new(tokio::sync::Mutex::new(responses)),
            seen:    Arc::new(tokio::sync::Mutex::new(Vec::new())),
        }
    }
}

#[cfg(any(debug_assertions, test))]
#[async_trait::async_trait]
impl ModelClient for MockModelClient {
    async fn create_message(
        &self,
        req: &MessageRequest,
    ) -> Result<MessageResponse, ModelError> {
        self.seen.lock().await.push(req.clone());
        let mut q = self.pending.lock().await;
        if q.is_empty() {
            return Err(ModelError::Transport(
                "MockModelClient: response queue exhausted".to_owned(),
            ));
        }
        Ok(q.remove(0))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_text_response() -> MessageResponse {
        MessageResponse {
            id:    "msg_01".to_owned(),
            kind:  "message".to_owned(),
            role:  "assistant".to_owned(),
            content: vec![ContentBlock::Text {
                text: "hello world".to_owned(),
            }],
            stop_reason: Some("end_turn".to_owned()),
            usage: Usage {
                input_tokens:                12,
                output_tokens:               5,
                cache_creation_input_tokens: 0,
                cache_read_input_tokens:     0,
            },
            model: "claude-sonnet-4-5-20250929".to_owned(),
        }
    }

    #[test]
    fn message_request_serialises_to_anthropic_wire_shape() {
        let req = MessageRequest {
            model:       "claude-sonnet-4-5-20250929".to_owned(),
            max_tokens:  1024,
            system:      Some("You are a helpful assistant.".to_owned()),
            messages: vec![Message {
                role:    "user".to_owned(),
                content: vec![ContentBlock::Text {
                    text: "say hi".to_owned(),
                }],
            }],
            tools:       vec![],
            temperature: Some(0.7),
            stream:      false,
        };
        let json = serde_json::to_value(&req).unwrap();
        // Pin the on-the-wire shape against the Anthropic API
        // contract — a future serde refactor that drops a
        // `#[serde(rename_all=...)]` etc. would break this.
        assert_eq!(json["model"],      "claude-sonnet-4-5-20250929");
        assert_eq!(json["max_tokens"], 1024);
        assert_eq!(json["system"],     "You are a helpful assistant.");
        assert_eq!(json["messages"][0]["role"], "user");
        assert_eq!(json["messages"][0]["content"][0]["type"], "text");
        assert_eq!(json["messages"][0]["content"][0]["text"], "say hi");
        // `tools: []` is skipped on serialisation per the
        // `skip_serializing_if = "Vec::is_empty"` attribute.
        assert!(json.get("tools").is_none(),
            "empty tools array MUST be omitted (matches Anthropic schema)");
        // `stream: false` is the default and MUST be skipped from
        // the wire so existing call sites that opted-out of
        // streaming see no on-the-wire diff (V2_GAPS §C9).
        assert!(json.get("stream").is_none(),
            "stream=false (default) MUST be omitted from the wire");
    }

    /// Pin the streaming-on wire shape: when callers opt in by
    /// setting `stream = true`, the serialized JSON must surface
    /// the field so Anthropic returns SSE rather than a buffered
    /// envelope.
    #[test]
    fn message_request_serialises_stream_true_when_opted_in() {
        let req = MessageRequest {
            stream: true,
            ..Default::default()
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["stream"], true);
    }

    #[test]
    fn tool_use_response_round_trips_through_serde() {
        let payload = serde_json::json!({
            "id":   "msg_02",
            "type": "message",
            "role": "assistant",
            "content": [
                { "type": "text", "text": "calling tool" },
                { "type": "tool_use", "id": "tool_x",
                  "name": "read_file",
                  "input": { "path": "/tmp/foo.txt" } }
            ],
            "stop_reason": "tool_use",
            "model": "claude-sonnet-4-5-20250929",
            "usage": { "input_tokens": 10, "output_tokens": 8 }
        });
        let parsed: MessageResponse = serde_json::from_value(payload).unwrap();
        assert_eq!(parsed.stop_reason.as_deref(), Some("tool_use"));
        assert_eq!(parsed.content.len(), 2);
        match &parsed.content[1] {
            ContentBlock::ToolUse { id, name, input } => {
                assert_eq!(id, "tool_x");
                assert_eq!(name, "read_file");
                assert_eq!(input["path"], "/tmp/foo.txt");
            }
            other => panic!("expected ToolUse block at index 1, got {other:?}"),
        }
    }

    #[test]
    fn unknown_content_block_round_trips_via_other_variant() {
        let payload = serde_json::json!({
            "id":   "msg_03",
            "type": "message",
            "role": "assistant",
            "content": [
                { "type": "image", "source": { "type": "base64", "data": "..." } }
            ],
            "stop_reason": "end_turn",
            "model": "claude-sonnet-4-5-20250929",
            "usage": { "input_tokens": 1, "output_tokens": 1 }
        });
        let parsed: MessageResponse = serde_json::from_value(payload).unwrap();
        assert_eq!(parsed.content.len(), 1);
        match &parsed.content[0] {
            ContentBlock::Other(v) => {
                assert_eq!(v["type"], "image");
            }
            other => panic!("expected Other block, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn mock_model_client_returns_queued_response_then_errors() {
        let client = MockModelClient::new(vec![fixture_text_response()]);
        let req = MessageRequest {
            model:       "claude-sonnet-4-5-20250929".to_owned(),
            max_tokens:  256,
            system:      None,
            messages:    vec![],
            tools:       vec![],
            temperature: None,
            stream:      false,
        };
        let resp = client.create_message(&req).await.unwrap();
        assert_eq!(resp.id, "msg_01");
        // Queue exhausted ⇒ transport error.
        match client.create_message(&req).await {
            Err(ModelError::Transport(_)) => {}
            other => panic!("expected exhausted-queue error, got {other:?}"),
        }
        let seen = client.seen.lock().await;
        assert_eq!(seen.len(), 2,
            "MockModelClient must record EVERY inbound request, even \
             those that error (so the dispatch loop's per-turn \
             message construction is observable in tests)");
    }

    /// Pin AnthropicClient construction against the documented
    /// no-credentials contract. A future refactor that adds an
    /// `api_key` parameter would break the audit-chain invariant
    /// described in `peripherals.md §3.2`.
    #[test]
    fn anthropic_client_constructor_takes_no_credential() {
        let _client = AnthropicClient::new("https://api.anthropic.com");
    }

    /// V2_GAPS §C9 — drive AnthropicClient::create_message_stream
    /// end-to-end against a local SSE mock. Verifies that:
    ///
    /// 1. The outgoing request carries `stream: true` (so Anthropic
    ///    returns SSE rather than a buffered JSON envelope).
    /// 2. The receiver yields the expected sequence of events
    ///    (`MessageStart`, deltas, `Stop`, `Complete`).
    /// 3. The terminal `Complete(MessageResponse)` reconstructs the
    ///    exact wire shape a buffered call would have returned, so
    ///    consumers that read only the terminal event stay
    ///    bug-compatible with the non-streaming path
    ///    (INV-PROVIDER-04).
    #[tokio::test]
    async fn create_message_stream_against_local_sse_server_emits_full_event_sequence() {
        use crate::streaming::{ContentBlockDeltaPayload, StreamEvent};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        // Mock server: respond with an Anthropic-shaped SSE stream
        // (message_start → content_block_start → two deltas →
        // content_block_stop → message_delta with stop_reason →
        // message_stop). Pin both the request shape (stream=true)
        // and the response shape (full event sequence) so a future
        // refactor of either side flags as a P0.
        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf   = vec![0u8; 16384];
            let mut total = 0;
            loop {
                let n = sock.read(&mut buf[total..]).await.unwrap();
                if n == 0 { break; }
                total += n;
                if total > 64
                    && buf[..total].windows(4).any(|w| w == b"\r\n\r\n")
                {
                    break;
                }
            }
            let req_str = String::from_utf8_lossy(&buf[..total]);
            assert!(
                req_str.contains("\"stream\":true"),
                "outgoing request must set stream=true; req body={req_str}",
            );

            let head = b"HTTP/1.1 200 OK\r\n\
                         Content-Type: text/event-stream\r\n\
                         Cache-Control: no-cache\r\n\
                         Connection: close\r\n\r\n";
            sock.write_all(head).await.unwrap();

            let body = "\
event: message_start\n\
data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_test_01\",\"type\":\"message\",\"role\":\"assistant\",\"content\":[],\"model\":\"claude-sonnet-4-5-20250929\",\"stop_reason\":null,\"stop_sequence\":null,\"usage\":{\"input_tokens\":7,\"output_tokens\":1}}}\n\
\n\
event: content_block_start\n\
data: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\
\n\
event: content_block_delta\n\
data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"hi \"}}\n\
\n\
event: content_block_delta\n\
data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"there\"}}\n\
\n\
event: content_block_stop\n\
data: {\"type\":\"content_block_stop\",\"index\":0}\n\
\n\
event: message_delta\n\
data: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\",\"stop_sequence\":null},\"usage\":{\"output_tokens\":3}}\n\
\n\
event: message_stop\n\
data: {\"type\":\"message_stop\"}\n\
\n";
            sock.write_all(body.as_bytes()).await.unwrap();
            sock.flush().await.unwrap();
        });

        let client = AnthropicClient::new(format!("http://127.0.0.1:{port}"));
        let req = MessageRequest {
            messages: vec![Message {
                role: "user".to_owned(),
                content: vec![ContentBlock::Text {
                    text: "say hi".to_owned(),
                }],
            }],
            model: "claude-sonnet-4-5-20250929".to_owned(),
            max_tokens: 64,
            ..Default::default()
        };
        let mut rx = client.create_message_stream(&req).await.unwrap();

        let mut saw_message_start = false;
        let mut saw_block_start   = false;
        let mut deltas            = Vec::new();
        let mut saw_block_stop    = false;
        let mut saw_stop          = false;
        let mut final_resp:        Option<MessageResponse> = None;

        while let Some(ev) = rx.recv().await {
            match ev {
                StreamEvent::MessageStart { id, model } => {
                    assert_eq!(id, "msg_test_01");
                    assert_eq!(model, "claude-sonnet-4-5-20250929");
                    saw_message_start = true;
                }
                StreamEvent::ContentBlockStart { index, block_kind } => {
                    assert_eq!(index, 0);
                    assert_eq!(block_kind, "text");
                    saw_block_start = true;
                }
                StreamEvent::ContentBlockDelta { delta, .. } => {
                    if let ContentBlockDeltaPayload::TextDelta { text } = delta {
                        deltas.push(text);
                    }
                }
                StreamEvent::ContentBlockStop { index } => {
                    assert_eq!(index, 0);
                    saw_block_stop = true;
                }
                StreamEvent::Usage(_) => {}
                StreamEvent::Stop { stop_reason } => {
                    assert_eq!(stop_reason.as_deref(), Some("end_turn"));
                    saw_stop = true;
                }
                StreamEvent::Complete(resp) => {
                    final_resp = Some(resp);
                }
            }
        }

        assert!(saw_message_start, "MessageStart must arrive");
        assert!(saw_block_start,   "ContentBlockStart must arrive");
        assert_eq!(deltas, vec!["hi ".to_owned(), "there".to_owned()]);
        assert!(saw_block_stop,    "ContentBlockStop must arrive");
        assert!(saw_stop,          "Stop must arrive");

        let resp = final_resp.expect("Complete must arrive on a successful stream");
        assert_eq!(resp.id, "msg_test_01");
        assert_eq!(resp.model, "claude-sonnet-4-5-20250929");
        assert_eq!(resp.stop_reason.as_deref(), Some("end_turn"));
        assert_eq!(resp.content.len(), 1);
        match &resp.content[0] {
            ContentBlock::Text { text } => assert_eq!(text, "hi there"),
            other => panic!("expected Text block, got {other:?}"),
        }

        server.await.unwrap();
    }
}

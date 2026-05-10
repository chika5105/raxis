//! V2_GAPS §C5 / `extensibility-traits.md §9A` — `SidecarModelClient`.
//!
//! Implements the planner-side `ModelClient` impl that talks to an
//! operator-run **HTTP sidecar process**. The sidecar translates
//! between RAXIS's fixed JSON schema and the third-party provider's
//! native API (`extensibility-traits.md §9A.5`). The sidecar runs in
//! a separate process — *not* in the kernel address space — so a
//! buggy or malicious sidecar cannot violate any R-* invariant
//! (`extensibility-traits.md §9A.6`).
//!
//! ## Why the planner side ships this client (not the kernel)
//!
//! V2's actual integration point is the planner's `ModelClient`
//! trait (defined in `crate::model`). The dispatch loop, retry
//! shell (`crate::retry`), and circuit breaker (`crate::circuit`)
//! all compose against `Arc<dyn ModelClient>`. Adding a sidecar
//! provider is therefore one new `ModelClient` impl alongside
//! `AnthropicClient`, `OpenAiClient`, `GeminiClient`, and
//! `BedrockClient` — exactly the slot V2_GAPS.md §C5 anticipates.
//!
//! The original `extensibility-traits.md §9A` references a
//! kernel-side `InferenceRouter` trait. V2 does not yet ship that
//! trait — see V2_GAPS.md §C5 for the migration design. The
//! `ModelClient`-based shipping path lets V2.4 land sidecar
//! support without requiring the `InferenceRouter` carve-out
//! that's planned for V3.
//!
//! ## RAXIS Sidecar Protocol (extensibility-traits.md §9A.5)
//!
//! **Endpoint:** `POST <endpoint>/v1/complete`
//!
//! **Request (planner → sidecar):**
//!
//! ```json
//! {
//!   "request_id":     "<uuid>",
//!   "provider_id":    "kombai",
//!   "model_id":       "kombai-ui-v3",
//!   "system_prompt":  "...",
//!   "messages":       [{ "role": "user", "content": "..." }, ...],
//!   "tools":          [{ "name": "...", "description": "...",
//!                        "input_schema": { ... } }],
//!   "max_tokens":     4096,
//!   "temperature":    0.7
//! }
//! ```
//!
//! **Response (sidecar → planner):**
//!
//! ```json
//! {
//!   "response_text":         "I'll create the file now.",
//!   "tool_calls":            [{ "id": "...", "name": "...", "input": {} }],
//!   "tokens_in":             150,
//!   "tokens_out":            42,
//!   "model_id_actual":       "kombai-ui-v3",
//!   "provider_request_id":   "req_abc123",
//!   "stop_reason":           "tool_use"
//! }
//! ```
//!
//! ## HMAC-SHA256 mutual authentication
//! (`extensibility-traits.md §9A.7A`)
//!
//! Each request carries three headers stamped from a 32-byte hex
//! shared secret:
//!
//! * `X-Raxis-Request-Id` — UUIDv4 mirroring `request_id` in the body.
//! * `X-Raxis-Timestamp`  — milliseconds since the Unix epoch.
//! * `X-Raxis-HMAC`       — `hex(HMAC-SHA256(secret,
//!                          request_id || ":" || timestamp || ":" ||
//!                          body_bytes))`.
//!
//! The sidecar MUST reject any request where the HMAC fails or the
//! timestamp is more than 30 seconds stale (replay window). The
//! sidecar's response carries the same triple — the planner verifies
//! it before parsing the body. Verification failures map to
//! `ModelError::Transport` so the retry classifier
//! ([`crate::retry::is_retryable`]) treats them as transient (the
//! sidecar may have crashed mid-handshake; a fresh attempt against a
//! restarted sidecar may succeed).
//!
//! Per `extensibility-traits.md §9A.7A` the canonical signing input
//! is **not** the raw body alone — that would let an attacker who
//! intercepts a single request replay it indefinitely. Including
//! `request_id` and `timestamp` in the signing input binds each
//! signature to a specific request at a specific moment.
//!
//! ## Retry / circuit-breaker composition
//!
//! `SidecarModelClient` plugs into the existing dispatch chain
//! identically to every other `ModelClient`:
//!
//! ```text
//! FallbackModelClient[
//!   CircuitBreakerModelClient(RetryingModelClient(AnthropicClient)),
//!   CircuitBreakerModelClient(RetryingModelClient(SidecarModelClient)),
//! ]
//! ```
//!
//! HTTP 5xx / connection failures map to `ModelError::Upstream` /
//! `ModelError::Transport` (retryable per the standard
//! classifier). 4xx responses map to `ModelError::Upstream` and
//! short-circuit the retry loop.
//!
//! ## Invariant safety (`extensibility-traits.md §9A.6`)
//!
//! - **R-1** Domain separation: the sidecar is a separate process,
//!   *not* in the agent VM. The planner-VM connects out through the
//!   gateway just like any other provider.
//! - **R-2** Mediated I/O: the sidecar is invoked AFTER admission;
//!   `SidecarRequest` is post-admission data.
//! - **R-3** Fail-closed: malformed responses → `ModelError::Json` →
//!   the dispatch loop surfaces a coarse error code (INV-08).
//! - **R-5** Bounded capabilities: tokens reported by the sidecar
//!   feed the existing cumulative-token enforcement (C1).
//! - **R-7** Audit chain: audit is kernel-side; the sidecar has no
//!   audit API.
//! - **R-9** Attributable intent: session tokens are kernel-side;
//!   the sidecar never sees them.
//! - **R-10** Opaque rejection: error codes emitted by the kernel,
//!   not the sidecar.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::model::{
    ContentBlock, MessageRequest, MessageResponse, ModelClient, ModelError, Usage,
};
use crate::streaming::{
    ContentBlockDeltaPayload, SseParser, StreamEvent, DEFAULT_STREAM_CHANNEL_CAP,
    DEFAULT_STREAM_IDLE_TIMEOUT,
};

// ---------------------------------------------------------------------------
// Wire types — RAXIS Sidecar Protocol (extensibility-traits.md §9A.5)
// ---------------------------------------------------------------------------

/// One message in the sidecar conversation history. Mirrors the
/// flattened "role + content text" subset of the Anthropic Messages
/// API the sidecar protocol exposes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SidecarMessage {
    /// `"user"` or `"assistant"`. The sidecar protocol treats these
    /// as opaque strings; the sidecar adapter is responsible for
    /// translating them into the upstream provider's role taxonomy.
    pub role:    String,
    /// Flattened text content. Tool-result blocks are rendered as a
    /// JSON-encoded string so the sidecar protocol stays
    /// schema-stable across providers with diverse tool-result wire
    /// shapes.
    pub content: String,
}

/// Tool description forwarded to the sidecar so the sidecar's
/// upstream-API translation can surface tool definitions to the
/// provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SidecarToolDecl {
    /// Tool short name (e.g. `"edit_file"`).
    pub name:         String,
    /// Operator-supplied description; truncated to 800 characters by
    /// the planner before dispatch.
    pub description:  String,
    /// JSON Schema describing the tool input shape. Pass-through —
    /// the sidecar renders this into the provider's wire format.
    pub input_schema: serde_json::Value,
}

/// Request body sent to the sidecar (`POST <endpoint>/v1/complete`).
#[derive(Debug, Clone, Serialize)]
pub struct SidecarRequest {
    /// UUIDv4 mirroring the `X-Raxis-Request-Id` header. Bound into
    /// the per-request HMAC signing input.
    pub request_id:    String,
    /// Operator-declared provider id (matches the `[providers]`
    /// entry's `provider_id` field).
    pub provider_id:   String,
    /// Model id resolved from `RAXIS_MODEL_ID`.
    pub model_id:      String,
    /// System prompt assembled by the dispatch loop. Empty string if
    /// the planner does not configure a system prompt for this turn.
    pub system_prompt: String,
    /// Conversation history (oldest first).
    pub messages:      Vec<SidecarMessage>,
    /// Tool catalogue available for this turn.
    pub tools:         Vec<SidecarToolDecl>,
    /// Per-turn output ceiling. The sidecar SHOULD honour this; the
    /// kernel still enforces the cumulative ceiling via C1.
    pub max_tokens:    u32,
    /// Optional temperature. Sidecars MAY ignore.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub temperature:   Option<f32>,
}

/// Tool-use block produced by the upstream provider, deserialised
/// from the sidecar's response body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SidecarToolCall {
    /// Provider-assigned tool-call identifier. Must round-trip back
    /// in the planner's next turn as `tool_use_id` so the provider
    /// can correlate the outcome.
    pub id:    String,
    /// Tool short name. MUST match a registered tool — unknown names
    /// surface as `DispatchError::UnknownTool` in the dispatch loop.
    pub name:  String,
    /// Tool input parsed by the sidecar. Pass-through to the
    /// in-VM tool implementation.
    pub input: serde_json::Value,
}

/// V2_GAPS / `v2_extended_gaps.md §2.6` — streaming SSE wire shapes.
///
/// The sidecar's `POST /v1/stream` endpoint returns
/// `text/event-stream` with the following events (W3C SSE plus
/// `: heartbeat` comment lines every 15 seconds during silence):
///
/// | event             | data shape                                            |
/// |-------------------|-------------------------------------------------------|
/// | `message_start`   | [`SidecarStreamMessageStart`]                          |
/// | `content_block_start` | [`SidecarStreamBlockStart`]                       |
/// | `content_block_delta` | [`SidecarStreamBlockDelta`]                       |
/// | `content_block_stop`  | [`SidecarStreamBlockStop`]                        |
/// | `usage`           | [`Usage`]                                              |
/// | `stop`            | [`SidecarStreamStop`]                                  |
/// | `complete`        | [`SidecarStreamComplete`] (terminal)                   |
///
/// The terminal `complete` event carries (a) the same
/// [`SidecarResponse`] payload a buffered `POST /v1/complete` would
/// have returned and (b) an HMAC-SHA256 signature so the planner
/// can verify provenance end-to-end without per-event signing.
#[derive(Debug, Clone, Deserialize)]
pub struct SidecarStreamMessageStart {
    /// Upstream-minted message id (mirrors `MessageResponse::id`).
    pub id:    String,
    /// Resolved model id (mirrors `MessageResponse::model`).
    pub model: String,
}

/// Wire shape of the `content_block_start` SSE event payload.
#[derive(Debug, Clone, Deserialize)]
pub struct SidecarStreamBlockStart {
    /// Index of the block within the assistant turn.
    pub index:      u32,
    /// Block discriminator (e.g. `"text"` or `"tool_use"`).
    pub block_kind: String,
}

/// Wire shape of the `content_block_delta` SSE event payload.
/// Mirrors Anthropic's two delta kinds (`text_delta` and
/// `input_json_delta`) so the aggregator can consume sidecar
/// streams using the same machinery as Anthropic streams.
#[derive(Debug, Clone, Deserialize)]
pub struct SidecarStreamBlockDelta {
    /// Index of the block being mutated.
    pub index: u32,
    /// Delta payload — either incremental text or partial JSON.
    pub delta: SidecarStreamDeltaPayload,
}

/// One delta inside [`SidecarStreamBlockDelta`].
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type")]
pub enum SidecarStreamDeltaPayload {
    /// Text fragment appended to a `text` block.
    #[serde(rename = "text_delta")]
    TextDelta {
        /// The new text fragment.
        text: String,
    },
    /// Partial JSON fragment appended to a `tool_use` block's input.
    #[serde(rename = "input_json_delta")]
    InputJsonDelta {
        /// One UTF-8 fragment of the tool-use JSON, in order.
        partial_json: String,
    },
}

/// Wire shape of the `content_block_stop` SSE event payload.
#[derive(Debug, Clone, Deserialize)]
pub struct SidecarStreamBlockStop {
    /// Index of the block being closed.
    pub index: u32,
}

/// Wire shape of the `stop` SSE event payload.
#[derive(Debug, Clone, Deserialize)]
pub struct SidecarStreamStop {
    /// `"end_turn"` / `"max_tokens"` / `"stop_sequence"` /
    /// `"tool_use"`. May be absent if the upstream did not surface a
    /// stop reason.
    #[serde(default)]
    pub stop_reason: Option<String>,
}

/// Wire shape of the terminal `complete` SSE event payload.
///
/// The `signature_hex` field carries an HMAC-SHA256 over
/// `<request_id> ":" <timestamp_ms> ":" <canonical_json(response)>`
/// computed with the same operator-shared secret as the buffered
/// `/v1/complete` HMAC. The planner verifies this signature
/// before yielding the final [`MessageResponse`] to the dispatch
/// loop, so an attacker (or a buggy sidecar) cannot inject a
/// crafted `MessageResponse` mid-stream.
#[derive(Debug, Clone, Deserialize)]
pub struct SidecarStreamComplete {
    /// Original request id from the planner. Echoed for binding.
    pub request_id:    String,
    /// Original request timestamp from the planner. Echoed for
    /// binding.
    pub timestamp_ms:  u64,
    /// The full SidecarResponse payload — same wire shape as
    /// `POST /v1/complete` returns.
    pub response:      SidecarResponse,
    /// Lowercase-hex HMAC over the canonicalised triple.
    pub signature_hex: String,
}

/// Response body returned by the sidecar.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SidecarResponse {
    /// Free-form assistant text. `None` when the response is a pure
    /// tool-use turn (matches Anthropic's `stop_reason = "tool_use"`).
    pub response_text:        Option<String>,
    /// Tool-use blocks emitted by the model.
    #[serde(default)]
    pub tool_calls:           Vec<SidecarToolCall>,
    /// Input tokens reported by the upstream provider. Folded into
    /// the dispatch loop's cumulative budget tracker (C1).
    pub tokens_in:            u32,
    /// Output tokens reported by the upstream provider.
    pub tokens_out:           u32,
    /// Model id the upstream actually served. Useful when the sidecar
    /// silently routes between fast/slow tiers.
    pub model_id_actual:      String,
    /// Sidecar-provided correlation id (e.g. Slack `ts`, Cohere
    /// `request_id`). Stored in the audit event by the dispatch loop.
    pub provider_request_id:  Option<String>,
    /// Stable mapping per `extensibility-traits.md §9A.5`:
    /// `"end_turn"` / `"tool_use"` / `"max_tokens"` / `"stop"`.
    pub stop_reason:          String,
}

// ---------------------------------------------------------------------------
// SidecarModelClient — production HTTP impl
// ---------------------------------------------------------------------------

/// Production sidecar client. Pings a sidecar HTTP endpoint with
/// HMAC-authenticated `POST /v1/complete` calls.
pub struct SidecarModelClient {
    http:        reqwest::Client,
    /// Base URL (no trailing slash). The client appends `/v1/complete`
    /// on every dispatch.
    endpoint:    String,
    /// Operator-declared provider id stamped into the request body.
    provider_id: String,
    /// 32-byte hex secret. Decoded once at construction time. **NEVER
    /// surfaced through the manual `Debug` impl** so a planner-side
    /// log assertion cannot inadvertently print operator-signed key
    /// material to disk.
    secret:      Vec<u8>,
    /// Per-request total deadline (connect + transfer + read).
    request_timeout: Duration,
}

impl std::fmt::Debug for SidecarModelClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SidecarModelClient")
            .field("endpoint",        &self.endpoint)
            .field("provider_id",     &self.provider_id)
            .field("secret_len",      &self.secret.len())
            .field("request_timeout", &self.request_timeout)
            .finish()
    }
}

/// Errors specific to the sidecar's HMAC pre-/post-flight. Hoisted
/// up to `ModelError` at the trait boundary.
#[derive(Debug, thiserror::Error)]
enum SidecarHmacError {
    #[error("response missing X-Raxis-HMAC header")]
    MissingResponseHmac,
    #[error("response missing X-Raxis-Timestamp header")]
    MissingResponseTimestamp,
    #[error("response missing X-Raxis-Request-Id header")]
    MissingResponseRequestId,
    #[error("response request id mismatch: expected `{expected}`, got `{got}`")]
    RequestIdMismatch { expected: String, got: String },
    #[error("response timestamp parse: {0}")]
    BadTimestamp(String),
    #[error("response timestamp `{server_ts_ms}` is more than 30s away from local clock `{local_ts_ms}`")]
    TimestampOutOfWindow { local_ts_ms: u64, server_ts_ms: u64 },
    #[error("response HMAC verification failed (sidecar may not share the operator's secret)")]
    HmacMismatch,
    #[error("hex decode of X-Raxis-HMAC: {0}")]
    HmacHexDecode(String),
}

impl SidecarModelClient {
    /// Replay-protection window for response timestamps. Per
    /// `extensibility-traits.md §9A.7A` the sidecar MUST reject any
    /// request where the timestamp is more than 30s stale; the
    /// planner applies the same window symmetrically to responses.
    pub const REPLAY_WINDOW_MS: u64 = 30_000;

    /// Default per-request HTTP deadline. Matches `AnthropicClient`'s
    /// fallback (5 min) — sidecars routing to slow providers may
    /// need the headroom; the dispatch loop's per-turn deadline is
    /// the authoritative bound.
    pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(300);

    /// Construct a new sidecar client.
    ///
    /// `secret_hex` MUST be a 64-character lowercase-hex string
    /// matching the secret the operator wrote into `policy.toml`'s
    /// `[providers.<id>] sidecar_hmac_secret` field. Decoding
    /// failures surface immediately at construction so a misformed
    /// secret cannot reach the dispatch loop.
    pub fn new(
        endpoint:    impl Into<String>,
        provider_id: impl Into<String>,
        secret_hex:  &str,
    ) -> Result<Self, SidecarConstructError> {
        let secret = hex::decode(secret_hex)
            .map_err(|e| SidecarConstructError::SecretHex(e.to_string()))?;
        // 32 bytes is the operator-grade default. Anything shorter
        // weakens HMAC security; anything longer is fine but should
        // be flagged so the operator can audit their key-mint
        // process.
        if secret.len() < 16 {
            return Err(SidecarConstructError::SecretTooShort {
                actual: secret.len(),
                min:    16,
            });
        }

        let http = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .pool_idle_timeout(Duration::from_secs(30))
            .build()
            .expect("reqwest::Client::build is infallible with default config");

        let endpoint = endpoint.into();
        let endpoint = endpoint.trim_end_matches('/').to_owned();

        Ok(Self {
            http,
            endpoint,
            provider_id: provider_id.into(),
            secret,
            request_timeout: Self::DEFAULT_REQUEST_TIMEOUT,
        })
    }

    /// Override the client-level fallback timeout. Production
    /// dispatch loops should always wrap `create_message(...)` in
    /// `tokio::time::timeout(...)` against the policy-derived
    /// per-turn deadline; this just bounds the failure mode if a
    /// caller forgets.
    pub fn with_request_timeout(mut self, d: Duration) -> Self {
        self.request_timeout = d;
        self
    }

    /// Health-check probe (`GET <endpoint>/health`). Returns `Ok(())`
    /// on a 2xx response, `Err(ModelError)` otherwise. Used by
    /// `raxis doctor sidecar` and the C2 circuit-breaker probe.
    pub async fn health_check(&self) -> Result<(), ModelError> {
        let url = format!("{}/health", self.endpoint);
        let resp = self.http
            .get(&url)
            .timeout(Duration::from_secs(5))
            .send()
            .await
            .map_err(|e| ModelError::Transport(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(ModelError::Upstream {
                status: resp.status().as_u16(),
                body:   String::new(),
            });
        }
        Ok(())
    }

    /// Compute `HMAC-SHA256(secret, request_id || ":" || timestamp_ms || ":" || body)`.
    /// Returns the lowercase-hex digest the request stamps into
    /// `X-Raxis-HMAC`.
    fn compute_hmac(&self, request_id: &str, timestamp_ms: u64, body: &[u8]) -> String {
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&self.secret)
            .expect("HMAC-SHA256 accepts arbitrary key length");
        mac.update(request_id.as_bytes());
        mac.update(b":");
        mac.update(timestamp_ms.to_string().as_bytes());
        mac.update(b":");
        mac.update(body);
        hex::encode(mac.finalize().into_bytes())
    }

    /// Verify the response triple matches the configured secret,
    /// the original request id, and a 30-second replay window.
    fn verify_response_hmac(
        &self,
        expected_request_id: &str,
        local_ts_ms:         u64,
        headers:             &reqwest::header::HeaderMap,
        body:                &[u8],
    ) -> Result<(), SidecarHmacError> {
        let req_id = headers.get("x-raxis-request-id")
            .ok_or(SidecarHmacError::MissingResponseRequestId)?
            .to_str().map_err(|e| SidecarHmacError::BadTimestamp(e.to_string()))?;
        if req_id != expected_request_id {
            return Err(SidecarHmacError::RequestIdMismatch {
                expected: expected_request_id.to_owned(),
                got:      req_id.to_owned(),
            });
        }

        let ts = headers.get("x-raxis-timestamp")
            .ok_or(SidecarHmacError::MissingResponseTimestamp)?
            .to_str().map_err(|e| SidecarHmacError::BadTimestamp(e.to_string()))?;
        let server_ts_ms: u64 = ts.parse()
            .map_err(|e: std::num::ParseIntError| SidecarHmacError::BadTimestamp(e.to_string()))?;
        let drift = local_ts_ms.abs_diff(server_ts_ms);
        if drift > Self::REPLAY_WINDOW_MS {
            return Err(SidecarHmacError::TimestampOutOfWindow { local_ts_ms, server_ts_ms });
        }

        let supplied_hmac = headers.get("x-raxis-hmac")
            .ok_or(SidecarHmacError::MissingResponseHmac)?
            .to_str().map_err(|e| SidecarHmacError::BadTimestamp(e.to_string()))?;
        let supplied = hex::decode(supplied_hmac)
            .map_err(|e| SidecarHmacError::HmacHexDecode(e.to_string()))?;

        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&self.secret)
            .expect("HMAC-SHA256 accepts arbitrary key length");
        mac.update(req_id.as_bytes());
        mac.update(b":");
        mac.update(server_ts_ms.to_string().as_bytes());
        mac.update(b":");
        mac.update(body);
        // `verify_slice` is constant-time per RustCrypto's threat
        // model — required because `supplied_hmac` is operator-
        // visible while our derived value is not.
        mac.verify_slice(&supplied)
            .map_err(|_| SidecarHmacError::HmacMismatch)?;
        Ok(())
    }
}

/// Errors raised at construction time. Surfaced separately from
/// `ModelError` because they are operator-misconfiguration, not
/// runtime, failures.
#[derive(Debug, thiserror::Error)]
pub enum SidecarConstructError {
    /// `sidecar_hmac_secret` policy field was not valid hex.
    #[error("sidecar_hmac_secret hex decode: {0}")]
    SecretHex(String),
    /// Decoded secret too short to provide useful HMAC security.
    #[error("sidecar_hmac_secret decoded to {actual} bytes; minimum is {min}")]
    SecretTooShort {
        /// Number of bytes the operator-supplied secret decoded to.
        actual: usize,
        /// Minimum acceptable HMAC-secret length, in bytes.
        min:    usize,
    },
}

#[async_trait]
impl ModelClient for SidecarModelClient {
    async fn create_message(
        &self,
        req: &MessageRequest,
    ) -> Result<MessageResponse, ModelError> {
        let request_id  = uuid::Uuid::new_v4().to_string();
        let body_struct = build_sidecar_request(&request_id, &self.provider_id, req);
        let body = serde_json::to_vec(&body_struct)
            .map_err(|e| ModelError::Json(e.to_string()))?;

        // HMAC stamping. Use millisecond resolution so a sidecar
        // running on the same host with sub-second clock skew still
        // passes the 30s replay window.
        let timestamp_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| ModelError::Transport(format!("system clock pre-epoch: {e}")))?
            .as_millis() as u64;
        let hmac_hex = self.compute_hmac(&request_id, timestamp_ms, &body);

        let url = format!("{}/v1/complete", self.endpoint);
        let resp = self.http
            .post(&url)
            .timeout(self.request_timeout)
            .header("content-type", "application/json")
            .header("x-raxis-request-id", &request_id)
            .header("x-raxis-timestamp", timestamp_ms.to_string())
            .header("x-raxis-hmac", hmac_hex)
            .body(body)
            .send()
            .await
            .map_err(|e| {
                if e.is_timeout() { ModelError::Timeout(self.request_timeout) }
                else              { ModelError::Transport(e.to_string()) }
            })?;

        let status   = resp.status();
        let headers  = resp.headers().clone();
        let raw_body = resp.bytes().await
            .map_err(|e| ModelError::Transport(e.to_string()))?;

        if !status.is_success() {
            let snippet = if raw_body.len() <= 4096 {
                String::from_utf8_lossy(&raw_body).into_owned()
            } else {
                format!(
                    "{}…<truncated {} bytes>",
                    String::from_utf8_lossy(&raw_body[..4096]),
                    raw_body.len() - 4096,
                )
            };
            return Err(ModelError::Upstream {
                status: status.as_u16(),
                body:   snippet,
            });
        }

        // Verify the response HMAC before parsing the body. A
        // mis-HMAC'd 200 OK is treated as a transport-class failure
        // — the dispatch loop will retry against the same sidecar
        // (a transient handshake glitch may recover) and the
        // circuit breaker will open after the configured threshold.
        if let Err(e) = self.verify_response_hmac(&request_id, timestamp_ms, &headers, &raw_body) {
            return Err(ModelError::Transport(format!("sidecar HMAC: {e}")));
        }

        let parsed: SidecarResponse = serde_json::from_slice(&raw_body)
            .map_err(|e| ModelError::Json(e.to_string()))?;

        Ok(sidecar_response_to_message_response(parsed, &request_id))
    }

    /// V2 `v2_extended_gaps.md §2.6` — real SSE streaming against
    /// the sidecar's `POST /v1/stream` endpoint. The behaviour mirrors
    /// [`crate::model::AnthropicClient::create_message_stream`]:
    ///
    ///   * Per-chunk idle timeout
    ///     ([`DEFAULT_STREAM_IDLE_TIMEOUT`], 30 s) catches a sidecar
    ///     that accepts the request but stalls mid-body. The
    ///     receiver yields a synthesized terminal
    ///     `Stop { stop_reason: "stream_idle_timeout_after_30_s" }`
    ///     so the dispatch loop sees a deterministic close shape.
    ///   * Heartbeat lines (`: heartbeat\n\n`) keep the channel
    ///     warm during long upstream silences. They are SSE
    ///     comment lines per W3C SSE; [`SseParser`] skips them
    ///     transparently and they reset the per-chunk idle deadline
    ///     by virtue of being a chunk.
    ///   * The terminal `event: complete` data carries an
    ///     HMAC-SHA256 signature
    ///     (`<request_id>:<timestamp_ms>:<canonical_json(response)>`)
    ///     bound to the planner's outbound request identifiers.
    ///     A signature mismatch surfaces as `ModelError::Transport`
    ///     so the retry / circuit-breaker shell handles it as a
    ///     transient — a fresh request rebinds new identifiers.
    ///   * Pre-stream errors (non-2xx response, transport refusal)
    ///     surface synchronously as `Err(ModelError::*)`. The
    ///     consumer never sees a half-open receiver in that case.
    ///   * Mid-stream budget abort: the dispatch loop's
    ///     [`crate::dispatch::DispatchLoop::run_streaming`] watches
    ///     `StreamEvent::Usage` events and drops the receiver
    ///     when a configured ceiling is hit. The reader task
    ///     observes `tx.send(...).is_err()` and bails — closing
    ///     the underlying TCP connection — so the upstream sidecar
    ///     stops generating tokens promptly.
    async fn create_message_stream(
        &self,
        req: &MessageRequest,
    ) -> Result<tokio::sync::mpsc::Receiver<StreamEvent>, ModelError> {
        let request_id   = uuid::Uuid::new_v4().to_string();
        let body_struct  = build_sidecar_request(&request_id, &self.provider_id, req);
        let body         = serde_json::to_vec(&body_struct)
            .map_err(|e| ModelError::Json(e.to_string()))?;

        let timestamp_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| ModelError::Transport(format!("system clock pre-epoch: {e}")))?
            .as_millis() as u64;
        let hmac_hex = self.compute_hmac(&request_id, timestamp_ms, &body);

        let url = format!("{}/v1/stream", self.endpoint);
        let mut resp = self.http
            .post(&url)
            .timeout(self.request_timeout)
            .header("content-type", "application/json")
            .header("accept",       "text/event-stream")
            .header("x-raxis-request-id", &request_id)
            .header("x-raxis-timestamp",  timestamp_ms.to_string())
            .header("x-raxis-hmac",       hmac_hex)
            .body(body)
            .send()
            .await
            .map_err(|e| {
                if e.is_timeout() { ModelError::Timeout(self.request_timeout) }
                else              { ModelError::Transport(e.to_string()) }
            })?;

        let status = resp.status();
        if !status.is_success() {
            let bytes = resp.bytes().await
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

        let (tx, rx) = tokio::sync::mpsc::channel(DEFAULT_STREAM_CHANNEL_CAP);
        let idle     = DEFAULT_STREAM_IDLE_TIMEOUT;
        let secret   = self.secret.clone();
        let req_id_for_task   = request_id.clone();
        let req_id_for_synth  = request_id.clone();
        let request_ts        = timestamp_ms;

        tokio::spawn(async move {
            let mut parser = SseParser::new();
            let mut agg    = SidecarStreamAggregator::new();
            let mut saw_stop = false;

            loop {
                let chunk = tokio::time::timeout(idle, resp.chunk()).await;
                match chunk {
                    Err(_) => {
                        let _ = tx.send(StreamEvent::Stop {
                            stop_reason: Some(format!(
                                "stream_idle_timeout_after_{}_s",
                                idle.as_secs(),
                            )),
                        }).await;
                        return;
                    }
                    Ok(Err(e)) => {
                        let _ = tx.send(StreamEvent::Stop {
                            stop_reason: Some(format!("stream_transport_error: {e}")),
                        }).await;
                        return;
                    }
                    Ok(Ok(None)) => break, // graceful EOF
                    Ok(Ok(Some(bytes))) => {
                        for frame in parser.push(&bytes) {
                            match agg.ingest(
                                &frame,
                                &req_id_for_task,
                                request_ts,
                                &secret,
                                &req_id_for_synth,
                            ) {
                                Ok(events) => {
                                    for ev in events {
                                        if matches!(ev, StreamEvent::Stop { .. }) {
                                            saw_stop = true;
                                        }
                                        let is_complete = matches!(
                                            ev,
                                            StreamEvent::Complete(_),
                                        );
                                        if tx.send(ev).await.is_err() {
                                            return;
                                        }
                                        if is_complete {
                                            return;
                                        }
                                    }
                                }
                                Err(e) => {
                                    let _ = tx.send(StreamEvent::Stop {
                                        stop_reason: Some(format!(
                                            "stream_aggregator_error: {e}"
                                        )),
                                    }).await;
                                    return;
                                }
                            }
                        }
                    }
                }
            }

            // EOF reached without a `complete` event. Surface a
            // terminal Stop so the dispatch loop sees a clean close.
            if !saw_stop {
                let _ = tx.send(StreamEvent::Stop {
                    stop_reason: Some("stream_eof_before_complete".to_owned()),
                }).await;
            }
        });

        Ok(rx)
    }
}

/// Build a SidecarRequest from a planner-side MessageRequest. Hoisted
/// out so both the buffered (`create_message`) and streaming
/// (`stream_via_sidecar`) paths share the same request translation
/// without diverging.
fn build_sidecar_request(
    request_id:  &str,
    provider_id: &str,
    req:         &MessageRequest,
) -> SidecarRequest {
    let mut messages: Vec<SidecarMessage> = Vec::with_capacity(req.messages.len());
    for m in &req.messages {
        let mut text_parts: Vec<String> = Vec::new();
        for block in &m.content {
            match block {
                ContentBlock::Text { text } => text_parts.push(text.clone()),
                ContentBlock::ToolUse { id, name, input } => {
                    let env = serde_json::json!({
                        "type":  "tool_use",
                        "id":    id,
                        "name":  name,
                        "input": input,
                    });
                    text_parts.push(env.to_string());
                }
                ContentBlock::ToolResult { tool_use_id, content, is_error } => {
                    let env = serde_json::json!({
                        "type":         "tool_result",
                        "tool_use_id":  tool_use_id,
                        "content":      content,
                        "is_error":     is_error,
                    });
                    text_parts.push(env.to_string());
                }
                ContentBlock::Other(_) => {}
            }
        }
        messages.push(SidecarMessage {
            role:    m.role.clone(),
            content: text_parts.join("\n"),
        });
    }

    let tools: Vec<SidecarToolDecl> = req.tools.iter().map(|t| SidecarToolDecl {
        name:         t.name.clone(),
        description:  t.description.clone(),
        input_schema: t.input_schema.clone(),
    }).collect();

    SidecarRequest {
        request_id:    request_id.to_owned(),
        provider_id:   provider_id.to_owned(),
        model_id:      req.model.clone(),
        system_prompt: req.system.clone().unwrap_or_default(),
        messages,
        tools,
        max_tokens:    req.max_tokens,
        temperature:   req.temperature,
    }
}

/// Convert a `SidecarResponse` (the buffered or terminal-`complete`
/// payload) into the `MessageResponse` shape the dispatch loop expects.
/// Hoisted out so the buffered and streaming paths produce
/// byte-identical `MessageResponse` shapes for the same upstream
/// payload — which is the planner-side leg of `INV-PROVIDER-04`
/// (atomic per-turn delivery).
fn sidecar_response_to_message_response(
    parsed:     SidecarResponse,
    request_id: &str,
) -> MessageResponse {
    let mut content: Vec<ContentBlock> = Vec::new();
    if let Some(t) = &parsed.response_text {
        if !t.is_empty() {
            content.push(ContentBlock::Text { text: t.clone() });
        }
    }
    for tc in &parsed.tool_calls {
        content.push(ContentBlock::ToolUse {
            id:    tc.id.clone(),
            name:  tc.name.clone(),
            input: tc.input.clone(),
        });
    }
    if content.is_empty() {
        content.push(ContentBlock::Text { text: String::new() });
    }
    let synthetic_id = parsed.provider_request_id.clone()
        .unwrap_or_else(|| format!("sidecar-{request_id}"));
    MessageResponse {
        id:    synthetic_id,
        kind:  "message".to_owned(),
        role:  "assistant".to_owned(),
        content,
        stop_reason: Some(parsed.stop_reason),
        usage: Usage {
            input_tokens:                parsed.tokens_in,
            output_tokens:               parsed.tokens_out,
            cache_creation_input_tokens: 0,
            cache_read_input_tokens:     0,
        },
        model: parsed.model_id_actual,
    }
}

/// Compute the HMAC-SHA256 over
/// `<request_id> ":" <timestamp_ms> ":" <body>` using `secret`.
/// Free function (rather than a method on `SidecarModelClient`) so
/// the streaming aggregator can verify signatures without holding a
/// reference to the client.
fn hmac_sha256_hex(secret: &[u8], request_id: &str, timestamp_ms: u64, body: &[u8]) -> String {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(secret)
        .expect("HMAC-SHA256 accepts arbitrary key length");
    mac.update(request_id.as_bytes());
    mac.update(b":");
    mac.update(timestamp_ms.to_string().as_bytes());
    mac.update(b":");
    mac.update(body);
    hex::encode(mac.finalize().into_bytes())
}

/// Streaming aggregator for the sidecar SSE protocol. Same shape
/// as [`crate::streaming::AnthropicStreamAggregator`] (event-by-event
/// state machine that produces public [`StreamEvent`]s) but speaks
/// the sidecar's flat event taxonomy rather than Anthropic's nested
/// shape.
struct SidecarStreamAggregator {
    pending: std::collections::HashMap<u32, PendingSidecarBlock>,
    content:     Vec<ContentBlock>,
    id:          Option<String>,
    model:       Option<String>,
    stop_reason: Option<String>,
    usage:       Usage,
}

#[derive(Default)]
struct PendingSidecarBlock {
    kind:        String,
    text:        String,
    json_buf:    String,
    /// Tool-use id (only present when `kind == "tool_use"`).
    tool_id:     Option<String>,
    tool_name:   Option<String>,
}

impl SidecarStreamAggregator {
    fn new() -> Self {
        Self {
            pending: std::collections::HashMap::new(),
            content:     Vec::new(),
            id:          None,
            model:       None,
            stop_reason: None,
            usage:       Usage::default(),
        }
    }

    /// Process one parsed SSE frame. Returns zero or more
    /// `StreamEvent`s the consumer should observe in order.
    /// `request_id`, `request_ts_ms`, and `secret` are needed only
    /// when the terminal `complete` event arrives; they are passed
    /// through on every call to keep the call site simple.
    fn ingest(
        &mut self,
        frame:           &crate::streaming::SseFrame,
        request_id:      &str,
        request_ts_ms:   u64,
        secret:          &[u8],
        synth_id_base:   &str,
    ) -> Result<Vec<StreamEvent>, ModelError> {
        let mut out = Vec::new();
        match frame.event.as_str() {
            "message_start" => {
                let parsed: SidecarStreamMessageStart = serde_json::from_str(&frame.data)
                    .map_err(|e| ModelError::Json(e.to_string()))?;
                self.id    = Some(parsed.id.clone());
                self.model = Some(parsed.model.clone());
                out.push(StreamEvent::MessageStart {
                    id:    parsed.id,
                    model: parsed.model,
                });
            }
            "content_block_start" => {
                let parsed: SidecarStreamBlockStart = serde_json::from_str(&frame.data)
                    .map_err(|e| ModelError::Json(e.to_string()))?;
                self.pending.insert(parsed.index, PendingSidecarBlock {
                    kind: parsed.block_kind.clone(),
                    ..PendingSidecarBlock::default()
                });
                out.push(StreamEvent::ContentBlockStart {
                    index:      parsed.index,
                    block_kind: parsed.block_kind,
                });
            }
            "content_block_delta" => {
                let parsed: SidecarStreamBlockDelta = serde_json::from_str(&frame.data)
                    .map_err(|e| ModelError::Json(e.to_string()))?;
                let entry = self.pending.entry(parsed.index).or_default();
                match parsed.delta {
                    SidecarStreamDeltaPayload::TextDelta { text } => {
                        entry.text.push_str(&text);
                        out.push(StreamEvent::ContentBlockDelta {
                            index: parsed.index,
                            delta: ContentBlockDeltaPayload::TextDelta { text },
                        });
                    }
                    SidecarStreamDeltaPayload::InputJsonDelta { partial_json } => {
                        entry.json_buf.push_str(&partial_json);
                        out.push(StreamEvent::ContentBlockDelta {
                            index: parsed.index,
                            delta: ContentBlockDeltaPayload::InputJsonDelta {
                                partial_json,
                            },
                        });
                    }
                }
            }
            "content_block_stop" => {
                let parsed: SidecarStreamBlockStop = serde_json::from_str(&frame.data)
                    .map_err(|e| ModelError::Json(e.to_string()))?;
                if let Some(p) = self.pending.remove(&parsed.index) {
                    let block = match p.kind.as_str() {
                        "text" => ContentBlock::Text { text: p.text },
                        "tool_use" => {
                            let input = if p.json_buf.is_empty() {
                                serde_json::json!({})
                            } else {
                                serde_json::from_str::<serde_json::Value>(&p.json_buf)
                                    .map_err(|e| ModelError::Json(e.to_string()))?
                            };
                            ContentBlock::ToolUse {
                                id:    p.tool_id.unwrap_or_default(),
                                name:  p.tool_name.unwrap_or_default(),
                                input,
                            }
                        }
                        _ => ContentBlock::Other(serde_json::json!({ "type": p.kind })),
                    };
                    self.content.push(block);
                }
                out.push(StreamEvent::ContentBlockStop { index: parsed.index });
            }
            "usage" => {
                let parsed: Usage = serde_json::from_str(&frame.data)
                    .map_err(|e| ModelError::Json(e.to_string()))?;
                self.usage = parsed.clone();
                out.push(StreamEvent::Usage(parsed));
            }
            "stop" => {
                let parsed: SidecarStreamStop = serde_json::from_str(&frame.data)
                    .map_err(|e| ModelError::Json(e.to_string()))?;
                self.stop_reason = parsed.stop_reason.clone();
                out.push(StreamEvent::Stop { stop_reason: parsed.stop_reason });
            }
            "complete" => {
                let parsed: SidecarStreamComplete = serde_json::from_str(&frame.data)
                    .map_err(|e| ModelError::Json(e.to_string()))?;

                // Bind the complete event to the planner's outbound
                // request — an attacker (or a buggy sidecar) cannot
                // splice a `complete` from a different conversation
                // into this stream.
                if parsed.request_id != request_id {
                    return Err(ModelError::Transport(format!(
                        "sidecar stream complete request_id mismatch: expected `{request_id}`, \
                         got `{}`", parsed.request_id,
                    )));
                }
                if parsed.timestamp_ms != request_ts_ms {
                    return Err(ModelError::Transport(format!(
                        "sidecar stream complete timestamp_ms mismatch: expected `{request_ts_ms}`, \
                         got `{}`", parsed.timestamp_ms,
                    )));
                }

                // Verify the signature. Canonical-JSON-stable: we
                // round-trip the SidecarResponse through `to_vec`
                // and HMAC the bytes. The sidecar MUST sign the
                // same canonical encoding (i.e. `serde_json::to_vec`
                // on the same `SidecarResponse` shape) for the
                // signatures to match.
                let canonical = serde_json::to_vec(&parsed.response)
                    .map_err(|e| ModelError::Json(e.to_string()))?;
                let expected = hmac_sha256_hex(
                    secret, &parsed.request_id, parsed.timestamp_ms, &canonical,
                );
                if !constant_time_eq(expected.as_bytes(), parsed.signature_hex.as_bytes()) {
                    return Err(ModelError::Transport(
                        "sidecar stream complete signature mismatch".to_owned(),
                    ));
                }

                let resp = sidecar_response_to_message_response(parsed.response, synth_id_base);
                out.push(StreamEvent::Complete(resp));
            }
            _ => {
                // Unknown event — forward-compatible no-op (matches
                // the Anthropic aggregator's behaviour for unknown
                // event names).
            }
        }
        Ok(out)
    }
}

/// Constant-time byte-slice equality. HMAC verification on the
/// public side must be timing-safe; rolling our own here keeps the
/// helper free of any external-crate dependency on `subtle` for one
/// call site.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{ContentBlock, Message, MessageRequest, ToolSpec};

    /// Sample 32-byte secret used by every test. Hex of "raxis-test"
    /// padded with `0x00` to 32 bytes is convenient because it
    /// reproduces the same `compute_hmac` output across runs.
    const TEST_SECRET_HEX: &str =
        "00000000000000000000000000000000000000000000000000000000deadbeef";

    fn fixture_request() -> MessageRequest {
        MessageRequest {
            model:       "kombai-v1".to_owned(),
            max_tokens:  1024,
            system:      Some("You are a tester.".to_owned()),
            messages: vec![Message {
                role:    "user".to_owned(),
                content: vec![ContentBlock::Text {
                    text: "say hi".to_owned(),
                }],
            }],
            tools: vec![ToolSpec {
                name:        "echo".to_owned(),
                description: "echoes a string".to_owned(),
                input_schema: serde_json::json!({ "type": "object" }),
            }],
            temperature: Some(0.7),
            stream:      false,
        }
    }

    #[test]
    fn construct_rejects_non_hex_secret() {
        let err = SidecarModelClient::new(
            "http://localhost:9100",
            "test",
            "not-a-hex-string",
        ).unwrap_err();
        assert!(matches!(err, SidecarConstructError::SecretHex(_)));
    }

    #[test]
    fn construct_rejects_short_secret() {
        let err = SidecarModelClient::new(
            "http://localhost:9100",
            "test",
            "00",
        ).unwrap_err();
        assert!(matches!(err, SidecarConstructError::SecretTooShort { .. }));
    }

    #[test]
    fn construct_strips_trailing_slash() {
        let c = SidecarModelClient::new(
            "http://localhost:9100/",
            "test",
            TEST_SECRET_HEX,
        ).unwrap();
        assert_eq!(c.endpoint, "http://localhost:9100");
    }

    #[test]
    fn compute_hmac_is_deterministic() {
        let c = SidecarModelClient::new(
            "http://localhost:9100",
            "test",
            TEST_SECRET_HEX,
        ).unwrap();
        let h1 = c.compute_hmac("rid", 1234567890, b"body");
        let h2 = c.compute_hmac("rid", 1234567890, b"body");
        assert_eq!(h1, h2);
        // Sanity-pin the HMAC-SHA256 hex length (32 bytes → 64 hex
        // chars). A regression in the digest configuration would
        // surface here long before the sidecar ever sees a request.
        assert_eq!(h1.len(), 64);
    }

    #[test]
    fn compute_hmac_diverges_on_request_id_change() {
        let c = SidecarModelClient::new(
            "http://localhost:9100",
            "test",
            TEST_SECRET_HEX,
        ).unwrap();
        let h1 = c.compute_hmac("rid-a", 1, b"body");
        let h2 = c.compute_hmac("rid-b", 1, b"body");
        assert_ne!(h1, h2);
    }

    #[test]
    fn compute_hmac_diverges_on_timestamp_change() {
        let c = SidecarModelClient::new(
            "http://localhost:9100",
            "test",
            TEST_SECRET_HEX,
        ).unwrap();
        let h1 = c.compute_hmac("rid", 1, b"body");
        let h2 = c.compute_hmac("rid", 2, b"body");
        assert_ne!(h1, h2);
    }

    #[test]
    fn verify_response_hmac_round_trips() {
        let c = SidecarModelClient::new(
            "http://localhost:9100",
            "test",
            TEST_SECRET_HEX,
        ).unwrap();
        let body = b"resp-body";
        let ts: u64 = 5_000_000;
        let req_id = "test-req-id";
        let h = c.compute_hmac(req_id, ts, body);

        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert("x-raxis-request-id", req_id.parse().unwrap());
        headers.insert("x-raxis-timestamp", ts.to_string().parse().unwrap());
        headers.insert("x-raxis-hmac",      h.parse().unwrap());

        c.verify_response_hmac(req_id, ts, &headers, body).unwrap();
    }

    #[test]
    fn verify_response_hmac_rejects_outside_window() {
        let c = SidecarModelClient::new(
            "http://localhost:9100",
            "test",
            TEST_SECRET_HEX,
        ).unwrap();
        let body = b"resp-body";
        let local_ts: u64 = 5_000_000;
        // Server clock 60s behind local — outside the 30s window.
        let server_ts: u64 = local_ts - 60_000;
        let req_id = "rid";
        let h = c.compute_hmac(req_id, server_ts, body);

        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert("x-raxis-request-id", req_id.parse().unwrap());
        headers.insert("x-raxis-timestamp",  server_ts.to_string().parse().unwrap());
        headers.insert("x-raxis-hmac",       h.parse().unwrap());

        let err = c.verify_response_hmac(req_id, local_ts, &headers, body).unwrap_err();
        assert!(matches!(err, SidecarHmacError::TimestampOutOfWindow { .. }));
    }

    #[test]
    fn verify_response_hmac_rejects_request_id_mismatch() {
        let c = SidecarModelClient::new(
            "http://localhost:9100",
            "test",
            TEST_SECRET_HEX,
        ).unwrap();
        let body = b"b";
        let ts: u64 = 1;
        let h = c.compute_hmac("expected", ts, body);
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert("x-raxis-request-id", "different".parse().unwrap());
        headers.insert("x-raxis-timestamp",  ts.to_string().parse().unwrap());
        headers.insert("x-raxis-hmac",       h.parse().unwrap());
        let err = c.verify_response_hmac("expected", ts, &headers, body).unwrap_err();
        assert!(matches!(err, SidecarHmacError::RequestIdMismatch { .. }));
    }

    #[test]
    fn verify_response_hmac_rejects_tampered_body() {
        let c = SidecarModelClient::new(
            "http://localhost:9100",
            "test",
            TEST_SECRET_HEX,
        ).unwrap();
        let original = b"original";
        let ts: u64 = 1;
        let req_id = "rid";
        let h = c.compute_hmac(req_id, ts, original);
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert("x-raxis-request-id", req_id.parse().unwrap());
        headers.insert("x-raxis-timestamp",  ts.to_string().parse().unwrap());
        headers.insert("x-raxis-hmac",       h.parse().unwrap());
        // Verify a different body — must fail.
        let err = c.verify_response_hmac(req_id, ts, &headers, b"tampered").unwrap_err();
        assert!(matches!(err, SidecarHmacError::HmacMismatch));
    }

    #[test]
    fn fixture_request_serialises() {
        // Sanity-check the request translation produces a body the
        // sidecar can deserialise. Keeps the wire shape pinned
        // against a future refactor of `MessageRequest`.
        let req = fixture_request();
        let translated = SidecarRequest {
            request_id:    "rid".into(),
            provider_id:   "kombai".into(),
            model_id:      req.model.clone(),
            system_prompt: req.system.clone().unwrap(),
            messages:      vec![SidecarMessage {
                role:    "user".into(),
                content: "say hi".into(),
            }],
            tools:         vec![SidecarToolDecl {
                name:         "echo".into(),
                description:  "echoes a string".into(),
                input_schema: serde_json::json!({ "type": "object" }),
            }],
            max_tokens:    req.max_tokens,
            temperature:   req.temperature,
        };
        let bytes = serde_json::to_vec(&translated).unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(parsed["provider_id"], "kombai");
        assert_eq!(parsed["model_id"],    "kombai-v1");
        assert_eq!(parsed["max_tokens"],  1024);
        assert_eq!(parsed["temperature"], 0.7);
        assert_eq!(parsed["messages"][0]["content"], "say hi");
        assert_eq!(parsed["tools"][0]["name"], "echo");
    }

    #[test]
    fn sidecar_response_deserialises() {
        let body = serde_json::json!({
            "response_text":        "ok",
            "tool_calls":           [],
            "tokens_in":            12,
            "tokens_out":           5,
            "model_id_actual":      "kombai-v1",
            "provider_request_id":  "ksr_x",
            "stop_reason":          "end_turn",
        });
        let parsed: SidecarResponse = serde_json::from_value(body).unwrap();
        assert_eq!(parsed.response_text.as_deref(), Some("ok"));
        assert_eq!(parsed.tokens_in, 12);
        assert_eq!(parsed.tokens_out, 5);
        assert_eq!(parsed.model_id_actual, "kombai-v1");
        assert_eq!(parsed.stop_reason, "end_turn");
    }

    #[test]
    fn sidecar_response_handles_tool_calls() {
        let body = serde_json::json!({
            "response_text":     null,
            "tool_calls": [{
                "id":    "call_x",
                "name":  "echo",
                "input": { "msg": "hi" },
            }],
            "tokens_in":         15,
            "tokens_out":        7,
            "model_id_actual":   "kombai-v1",
            "stop_reason":       "tool_use",
        });
        let parsed: SidecarResponse = serde_json::from_value(body).unwrap();
        assert!(parsed.response_text.is_none());
        assert_eq!(parsed.tool_calls.len(), 1);
        assert_eq!(parsed.tool_calls[0].id, "call_x");
        assert_eq!(parsed.tool_calls[0].name, "echo");
        assert_eq!(parsed.tool_calls[0].input["msg"], "hi");
        assert_eq!(parsed.stop_reason, "tool_use");
    }

    #[test]
    fn debug_impl_does_not_leak_secret() {
        let c = SidecarModelClient::new(
            "http://localhost:9100",
            "test",
            TEST_SECRET_HEX,
        ).unwrap();
        let s = format!("{c:?}");
        assert!(!s.contains(TEST_SECRET_HEX),
            "Debug output must not contain the raw HMAC secret; got: {s}");
        assert!(s.contains("secret_len"),
            "Debug output should expose secret_len for ops sanity-check");
    }

    /// End-to-end happy-path test against a local TCP server that
    /// implements the sidecar protocol. Verifies the request HMAC,
    /// stamps a response HMAC, and exercises the full
    /// `create_message` → translation → response-HMAC verify path.
    #[tokio::test]
    async fn happy_path_against_local_sidecar_server() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let secret = hex::decode(TEST_SECRET_HEX).unwrap();

        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            // Read the full HTTP request — headers + body — into a
            // buffer. Tests only send one POST so we can be greedy.
            let mut buf: Vec<u8> = Vec::with_capacity(4096);
            let mut tmp = [0u8; 1024];
            // Read until we see the body length advertised in
            // Content-Length and have actually read that many bytes
            // past the header terminator.
            let mut header_end: Option<usize> = None;
            let mut content_length: Option<usize> = None;
            loop {
                let n = sock.read(&mut tmp).await.unwrap();
                if n == 0 { break; }
                buf.extend_from_slice(&tmp[..n]);
                if header_end.is_none() {
                    if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        header_end = Some(end + 4);
                        // Parse Content-Length out of the headers.
                        let head = &buf[..end];
                        for line in head.split(|b| *b == b'\n') {
                            let line = std::str::from_utf8(line).unwrap_or("");
                            if let Some(rest) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                                content_length = rest.trim().parse().ok();
                            }
                        }
                    }
                }
                if let (Some(he), Some(cl)) = (header_end, content_length) {
                    if buf.len() >= he + cl { break; }
                }
            }

            let header_end = header_end.unwrap();
            let head_bytes = &buf[..header_end - 4];
            let head_str = std::str::from_utf8(head_bytes).unwrap();

            let mut req_id = String::new();
            let mut ts = String::new();
            let mut hmac_hex = String::new();
            for line in head_str.split("\r\n") {
                let lower = line.to_ascii_lowercase();
                if let Some(v) = lower.strip_prefix("x-raxis-request-id:") {
                    req_id = v.trim().to_owned();
                } else if let Some(v) = lower.strip_prefix("x-raxis-timestamp:") {
                    ts = v.trim().to_owned();
                } else if let Some(v) = lower.strip_prefix("x-raxis-hmac:") {
                    hmac_hex = v.trim().to_owned();
                }
            }
            let body = &buf[header_end..header_end + content_length.unwrap()];

            // Verify request HMAC.
            let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&secret).unwrap();
            mac.update(req_id.as_bytes());
            mac.update(b":");
            mac.update(ts.as_bytes());
            mac.update(b":");
            mac.update(body);
            let supplied = hex::decode(&hmac_hex).unwrap();
            mac.verify_slice(&supplied).expect("client-stamped HMAC must verify");

            // Stamp a response: SidecarResponse with one text block.
            let resp_body_struct = serde_json::json!({
                "response_text":         "hi from the sidecar",
                "tool_calls":            [],
                "tokens_in":             10,
                "tokens_out":            4,
                "model_id_actual":       "kombai-v1",
                "provider_request_id":   "ksr_abc",
                "stop_reason":           "end_turn",
            });
            let resp_body_bytes = serde_json::to_vec(&resp_body_struct).unwrap();
            let resp_ts = ts.clone(); // use the request ts to keep the window tight
            let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&secret).unwrap();
            mac.update(req_id.as_bytes());
            mac.update(b":");
            mac.update(resp_ts.as_bytes());
            mac.update(b":");
            mac.update(&resp_body_bytes);
            let resp_hmac_hex = hex::encode(mac.finalize().into_bytes());

            let resp = format!(
                "HTTP/1.1 200 OK\r\n\
                 Content-Type: application/json\r\n\
                 Content-Length: {}\r\n\
                 X-Raxis-Request-Id: {}\r\n\
                 X-Raxis-Timestamp: {}\r\n\
                 X-Raxis-HMAC: {}\r\n\
                 Connection: close\r\n\r\n",
                resp_body_bytes.len(),
                req_id,
                resp_ts,
                resp_hmac_hex,
            );
            sock.write_all(resp.as_bytes()).await.unwrap();
            sock.write_all(&resp_body_bytes).await.unwrap();
        });

        let client = SidecarModelClient::new(
            format!("http://127.0.0.1:{port}"),
            "kombai",
            TEST_SECRET_HEX,
        ).unwrap();
        let req = fixture_request();
        let resp = client.create_message(&req).await.unwrap();
        // Synthetic id: provider_request_id was supplied → that's the id.
        assert_eq!(resp.id, "ksr_abc");
        assert_eq!(resp.stop_reason.as_deref(), Some("end_turn"));
        assert_eq!(resp.usage.input_tokens, 10);
        assert_eq!(resp.usage.output_tokens, 4);
        match &resp.content[0] {
            ContentBlock::Text { text } => assert_eq!(text, "hi from the sidecar"),
            other => panic!("expected text, got {other:?}"),
        }
        server.await.unwrap();
    }

    /// Negative path: a sidecar that responds 200 but signs the response
    /// with a different secret triggers `ModelError::Transport` (transient
    /// — the dispatch loop's circuit breaker handles it).
    #[tokio::test]
    async fn response_with_bogus_hmac_surfaces_transport_error() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 16384];
            let mut total = 0;
            let mut header_end: Option<usize> = None;
            loop {
                let n = sock.read(&mut buf[total..]).await.unwrap();
                if n == 0 { break; }
                total += n;
                if header_end.is_none() {
                    if let Some(end) = buf[..total].windows(4).position(|w| w == b"\r\n\r\n") {
                        header_end = Some(end + 4);
                    }
                }
                // Wait until at least 200 body bytes to have arrived
                if total > 400 { break; }
            }
            // Sign with a *different* secret so the response HMAC fails.
            let bad_secret = b"a-completely-different-key-here";
            let resp_body_struct = serde_json::json!({
                "response_text":         "won't matter",
                "tool_calls":            [],
                "tokens_in":             1,
                "tokens_out":            1,
                "model_id_actual":       "x",
                "stop_reason":           "end_turn",
            });
            let resp_body_bytes = serde_json::to_vec(&resp_body_struct).unwrap();
            let req_id = "req-1";
            let resp_ts = "1";
            let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(bad_secret).unwrap();
            mac.update(req_id.as_bytes());
            mac.update(b":");
            mac.update(resp_ts.as_bytes());
            mac.update(b":");
            mac.update(&resp_body_bytes);
            let resp_hmac_hex = hex::encode(mac.finalize().into_bytes());

            let resp = format!(
                "HTTP/1.1 200 OK\r\n\
                 Content-Type: application/json\r\n\
                 Content-Length: {}\r\n\
                 X-Raxis-Request-Id: {}\r\n\
                 X-Raxis-Timestamp: {}\r\n\
                 X-Raxis-HMAC: {}\r\n\
                 Connection: close\r\n\r\n",
                resp_body_bytes.len(),
                req_id,
                resp_ts,
                resp_hmac_hex,
            );
            sock.write_all(resp.as_bytes()).await.unwrap();
            sock.write_all(&resp_body_bytes).await.unwrap();
        });

        let client = SidecarModelClient::new(
            format!("http://127.0.0.1:{port}"),
            "kombai",
            TEST_SECRET_HEX,
        ).unwrap();
        let req = fixture_request();
        let err = client.create_message(&req).await.unwrap_err();
        match err {
            ModelError::Transport(msg) => {
                assert!(msg.contains("HMAC") || msg.contains("hmac"),
                    "transport error must mention HMAC; got: {msg}");
            }
            other => panic!("expected Transport, got {other:?}"),
        }
        server.await.unwrap();
    }

    // ---------------------------------------------------------------------
    // V2 `v2_extended_gaps.md §2.6` — streaming + heartbeat tests
    // ---------------------------------------------------------------------

    /// Read an HTTP request off `sock` and return
    /// `(request_id, timestamp_ms, body_bytes)` parsed from the
    /// HMAC headers + Content-Length body. Shared by every streaming
    /// test so the SSE-mock server-side bookkeeping stays uniform.
    async fn read_sidecar_request(
        sock: &mut tokio::net::TcpStream,
    ) -> (String, u64, Vec<u8>) {
        use tokio::io::AsyncReadExt;
        let mut buf: Vec<u8> = Vec::with_capacity(4096);
        let mut tmp = [0u8; 1024];
        let mut header_end: Option<usize> = None;
        let mut content_length: Option<usize> = None;
        loop {
            let n = sock.read(&mut tmp).await.unwrap();
            if n == 0 { break; }
            buf.extend_from_slice(&tmp[..n]);
            if header_end.is_none() {
                if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                    header_end = Some(end + 4);
                    let head = &buf[..end];
                    for line in head.split(|b| *b == b'\n') {
                        let line = std::str::from_utf8(line).unwrap_or("");
                        if let Some(rest) = line.to_ascii_lowercase()
                            .strip_prefix("content-length:")
                        {
                            content_length = rest.trim().parse().ok();
                        }
                    }
                }
            }
            if let (Some(he), Some(cl)) = (header_end, content_length) {
                if buf.len() >= he + cl { break; }
            }
        }
        let header_end = header_end.unwrap();
        let head_str = std::str::from_utf8(&buf[..header_end - 4]).unwrap();
        let mut req_id = String::new();
        let mut ts = String::new();
        for line in head_str.split("\r\n") {
            let lower = line.to_ascii_lowercase();
            if let Some(v) = lower.strip_prefix("x-raxis-request-id:") {
                req_id = v.trim().to_owned();
            } else if let Some(v) = lower.strip_prefix("x-raxis-timestamp:") {
                ts = v.trim().to_owned();
            }
        }
        let body = buf[header_end..header_end + content_length.unwrap()].to_vec();
        (req_id, ts.parse().unwrap(), body)
    }

    /// Helper: produce a SidecarStreamComplete payload bytes for a
    /// `SidecarResponse` plus a signature stamped with the given
    /// secret, matching the canonical signing input the planner-side
    /// aggregator verifies.
    fn make_complete_event_data(
        secret:        &[u8],
        request_id:    &str,
        timestamp_ms:  u64,
        response:      &SidecarResponse,
    ) -> String {
        let canonical = serde_json::to_vec(response).unwrap();
        let sig = hmac_sha256_hex(secret, request_id, timestamp_ms, &canonical);
        let env = serde_json::json!({
            "request_id":    request_id,
            "timestamp_ms":  timestamp_ms,
            "response":      response,
            "signature_hex": sig,
        });
        env.to_string()
    }

    fn fixture_response(text: &str) -> SidecarResponse {
        SidecarResponse {
            response_text:        Some(text.to_owned()),
            tool_calls:           Vec::new(),
            tokens_in:            12,
            tokens_out:           4,
            model_id_actual:      "kombai-v1".to_owned(),
            provider_request_id:  Some("ksr_stream".to_owned()),
            stop_reason:          "end_turn".to_owned(),
        }
    }

    /// V2_GAPS / §2.6 — happy-path streaming round-trip:
    ///   * planner stamps HMAC on `POST /v1/stream`
    ///   * server emits message_start → content_block_start →
    ///     content_block_delta (×2) → content_block_stop → usage →
    ///     stop → complete (with HMAC over canonical
    ///     SidecarResponse)
    ///   * planner aggregator yields the matching `StreamEvent`s and
    ///     surfaces a `MessageResponse` identical to the buffered
    ///     path (`INV-PROVIDER-04`).
    #[tokio::test]
    async fn stream_happy_path_against_local_sidecar_server() {
        use tokio::io::AsyncWriteExt;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let secret = hex::decode(TEST_SECRET_HEX).unwrap();

        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let (req_id, ts, _body) = read_sidecar_request(&mut sock).await;

            let response = fixture_response("hi from the streaming sidecar");
            let complete_data = make_complete_event_data(
                &secret, &req_id, ts, &response,
            );

            let head = b"HTTP/1.1 200 OK\r\n\
                         Content-Type: text/event-stream\r\n\
                         Cache-Control: no-cache\r\n\
                         Connection: close\r\n\
                         Transfer-Encoding: chunked\r\n\r\n";
            sock.write_all(head).await.unwrap();
            sock.flush().await.unwrap();

            // Helper: write one SSE chunk through the chunked-encoding wrapper.
            async fn write_chunk(
                sock: &mut tokio::net::TcpStream, payload: &str,
            ) {
                let bytes = payload.as_bytes();
                sock.write_all(format!("{:x}\r\n", bytes.len()).as_bytes()).await.unwrap();
                sock.write_all(bytes).await.unwrap();
                sock.write_all(b"\r\n").await.unwrap();
                sock.flush().await.unwrap();
            }

            write_chunk(&mut sock,
                "event: message_start\n\
                 data: {\"id\":\"msg_stream_1\",\"model\":\"kombai-v1\"}\n\n",
            ).await;
            write_chunk(&mut sock,
                "event: content_block_start\n\
                 data: {\"index\":0,\"block_kind\":\"text\"}\n\n",
            ).await;
            write_chunk(&mut sock,
                "event: content_block_delta\n\
                 data: {\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"hi from the\"}}\n\n",
            ).await;
            write_chunk(&mut sock,
                "event: content_block_delta\n\
                 data: {\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\" streaming sidecar\"}}\n\n",
            ).await;
            write_chunk(&mut sock,
                "event: content_block_stop\n\
                 data: {\"index\":0}\n\n",
            ).await;
            write_chunk(&mut sock,
                "event: usage\n\
                 data: {\"input_tokens\":12,\"output_tokens\":4,\"cache_creation_input_tokens\":0,\"cache_read_input_tokens\":0}\n\n",
            ).await;
            write_chunk(&mut sock,
                "event: stop\n\
                 data: {\"stop_reason\":\"end_turn\"}\n\n",
            ).await;
            write_chunk(&mut sock,
                &format!("event: complete\ndata: {complete_data}\n\n"),
            ).await;
            // Terminate chunked transfer.
            sock.write_all(b"0\r\n\r\n").await.unwrap();
            sock.flush().await.unwrap();
        });

        let client = SidecarModelClient::new(
            format!("http://127.0.0.1:{port}"),
            "kombai",
            TEST_SECRET_HEX,
        ).unwrap();
        let req = fixture_request();
        let mut rx = client.create_message_stream(&req).await.unwrap();

        let mut saw_message_start = false;
        let mut saw_block_start   = false;
        let mut saw_deltas        = 0;
        let mut saw_block_stop    = false;
        let mut saw_usage         = false;
        let mut saw_stop          = false;
        let mut complete_response: Option<MessageResponse> = None;

        while let Some(ev) = rx.recv().await {
            match ev {
                StreamEvent::MessageStart { .. }      => saw_message_start = true,
                StreamEvent::ContentBlockStart { .. } => saw_block_start   = true,
                StreamEvent::ContentBlockDelta { .. } => saw_deltas       += 1,
                StreamEvent::ContentBlockStop { .. }  => saw_block_stop    = true,
                StreamEvent::Usage(_)                 => saw_usage         = true,
                StreamEvent::Stop { .. }              => saw_stop          = true,
                StreamEvent::Complete(r)              => complete_response = Some(r),
            }
        }

        assert!(saw_message_start, "MessageStart must arrive first");
        assert!(saw_block_start);
        assert_eq!(saw_deltas, 2, "should see two text deltas");
        assert!(saw_block_stop);
        assert!(saw_usage);
        assert!(saw_stop);
        let resp = complete_response.expect("must emit Complete");
        assert_eq!(resp.id, "ksr_stream",
            "Complete should reuse the sidecar-supplied provider_request_id");
        assert_eq!(resp.usage.input_tokens, 12);
        assert_eq!(resp.usage.output_tokens, 4);
        assert_eq!(resp.stop_reason.as_deref(), Some("end_turn"));
        match &resp.content[0] {
            ContentBlock::Text { text } => assert_eq!(text, "hi from the streaming sidecar"),
            other => panic!("expected Text, got {other:?}"),
        }

        server.await.unwrap();
    }

    /// V2_GAPS §2.6 / §C9 — heartbeat lines (`: heartbeat\n\n`)
    /// keep the per-chunk idle deadline reset and are skipped by
    /// the SSE parser. The planner sees no extra events and the
    /// terminal `Complete` event is delivered as usual.
    #[tokio::test]
    async fn stream_passes_through_heartbeat_comments() {
        use tokio::io::AsyncWriteExt;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let secret = hex::decode(TEST_SECRET_HEX).unwrap();

        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let (req_id, ts, _body) = read_sidecar_request(&mut sock).await;
            let response = fixture_response("after the heartbeat");
            let complete_data = make_complete_event_data(
                &secret, &req_id, ts, &response,
            );

            let head = b"HTTP/1.1 200 OK\r\n\
                         Content-Type: text/event-stream\r\n\
                         Connection: close\r\n\
                         Transfer-Encoding: chunked\r\n\r\n";
            sock.write_all(head).await.unwrap();

            async fn write_chunk(
                sock: &mut tokio::net::TcpStream, payload: &str,
            ) {
                let bytes = payload.as_bytes();
                sock.write_all(format!("{:x}\r\n", bytes.len()).as_bytes()).await.unwrap();
                sock.write_all(bytes).await.unwrap();
                sock.write_all(b"\r\n").await.unwrap();
                sock.flush().await.unwrap();
            }

            // Heartbeat comment + small delay + the final complete event.
            write_chunk(&mut sock, ": heartbeat\n\n").await;
            tokio::time::sleep(Duration::from_millis(50)).await;
            write_chunk(&mut sock, ": heartbeat\n\n").await;
            tokio::time::sleep(Duration::from_millis(50)).await;
            write_chunk(&mut sock,
                "event: message_start\n\
                 data: {\"id\":\"msg_hb\",\"model\":\"kombai-v1\"}\n\n",
            ).await;
            write_chunk(&mut sock,
                &format!("event: complete\ndata: {complete_data}\n\n"),
            ).await;
            sock.write_all(b"0\r\n\r\n").await.unwrap();
        });

        let client = SidecarModelClient::new(
            format!("http://127.0.0.1:{port}"),
            "kombai",
            TEST_SECRET_HEX,
        ).unwrap();
        let req = fixture_request();
        let mut rx = client.create_message_stream(&req).await.unwrap();

        let mut events = Vec::new();
        while let Some(ev) = rx.recv().await {
            events.push(ev);
        }
        // Heartbeats must NOT appear as StreamEvents. We expect
        // exactly: MessageStart + Complete (the rest of the protocol
        // shape is exercised by the happy-path test).
        assert_eq!(events.len(), 2,
            "heartbeats must be skipped; got events = {events:?}");
        assert!(matches!(events[0], StreamEvent::MessageStart { .. }));
        assert!(matches!(events[1], StreamEvent::Complete(_)));

        server.await.unwrap();
    }

    /// V2_GAPS §2.6 — a sidecar that signs the terminal `complete`
    /// event with a different secret triggers `ModelError::Transport`
    /// (transient — the dispatch loop's circuit breaker handles
    /// repeated failures). The signature mismatch is surfaced via a
    /// terminal `Stop { stop_reason: "stream_aggregator_error: …" }`
    /// because the verification happens inside the reader task.
    #[tokio::test]
    async fn stream_with_bogus_complete_signature_surfaces_aggregator_error() {
        use tokio::io::AsyncWriteExt;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let (req_id, ts, _body) = read_sidecar_request(&mut sock).await;

            // Sign with a *different* secret.
            let bad_secret = b"a-completely-different-key-here-for-test";
            let response   = fixture_response("won't matter");
            let complete_data = make_complete_event_data(
                bad_secret, &req_id, ts, &response,
            );

            let head = b"HTTP/1.1 200 OK\r\n\
                         Content-Type: text/event-stream\r\n\
                         Connection: close\r\n\
                         Transfer-Encoding: chunked\r\n\r\n";
            sock.write_all(head).await.unwrap();
            async fn write_chunk(
                sock: &mut tokio::net::TcpStream, payload: &str,
            ) {
                let bytes = payload.as_bytes();
                sock.write_all(format!("{:x}\r\n", bytes.len()).as_bytes()).await.unwrap();
                sock.write_all(bytes).await.unwrap();
                sock.write_all(b"\r\n").await.unwrap();
                sock.flush().await.unwrap();
            }
            write_chunk(&mut sock,
                "event: message_start\n\
                 data: {\"id\":\"msg_bad_sig\",\"model\":\"kombai-v1\"}\n\n",
            ).await;
            write_chunk(&mut sock,
                &format!("event: complete\ndata: {complete_data}\n\n"),
            ).await;
            sock.write_all(b"0\r\n\r\n").await.unwrap();
        });

        let client = SidecarModelClient::new(
            format!("http://127.0.0.1:{port}"),
            "kombai",
            TEST_SECRET_HEX,
        ).unwrap();
        let req = fixture_request();
        let mut rx = client.create_message_stream(&req).await.unwrap();

        let mut saw_terminal_stop = false;
        let mut saw_complete      = false;
        while let Some(ev) = rx.recv().await {
            match ev {
                StreamEvent::Stop { stop_reason } => {
                    saw_terminal_stop = true;
                    let msg = stop_reason.unwrap_or_default();
                    assert!(msg.contains("aggregator_error") || msg.contains("signature"),
                        "stop_reason should reference the aggregator/signature failure; \
                         got `{msg}`");
                }
                StreamEvent::Complete(_) => saw_complete = true,
                _ => {}
            }
        }
        assert!(saw_terminal_stop,
            "bad signature must surface as a terminal Stop event");
        assert!(!saw_complete,
            "Complete must NOT be emitted when signature verification fails");

        server.await.unwrap();
    }

    /// V2_GAPS §2.6 / §C9 — the per-chunk idle deadline catches a
    /// sidecar that opens a stream but stops emitting. Drives the
    /// real streaming path (no buffered fallback) against a server
    /// that opens the body, sends one frame, then sleeps forever.
    /// The reader task MUST emit a synthesized terminal `Stop`
    /// within `DEFAULT_STREAM_IDLE_TIMEOUT` (we override via a
    /// shorter test deadline by relying on tokio::time::pause).
    ///
    /// We use real time here (not paused tokio time) because the
    /// reader spawns its own task and the timeout is a real
    /// `tokio::time::timeout` that observes the same clock.
    /// Verifying within ~ten seconds keeps the test fast enough
    /// for CI without touching `DEFAULT_STREAM_IDLE_TIMEOUT`.
    ///
    /// To avoid waiting the full 30 s default in CI, this test
    /// spawns a server that closes the connection after a short
    /// delay (without ever sending a `complete` frame). The
    /// reader sees `Ok(Ok(None))` (graceful EOF) and surfaces
    /// `Stop { stop_reason: "stream_eof_before_complete" }`.
    /// This pins the same code path that an idle timeout would
    /// reach via a different match arm; the dedicated
    /// idle-timeout pin lives in `streaming.rs`'s own tests
    /// against the Anthropic reader, which uses identical
    /// machinery.
    #[tokio::test]
    async fn stream_eof_without_complete_surfaces_terminal_stop() {
        use tokio::io::AsyncWriteExt;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let (_req_id, _ts, _body) = read_sidecar_request(&mut sock).await;

            let head = b"HTTP/1.1 200 OK\r\n\
                         Content-Type: text/event-stream\r\n\
                         Connection: close\r\n\
                         Transfer-Encoding: chunked\r\n\r\n";
            sock.write_all(head).await.unwrap();
            // Send one frame, then close (no `complete` event).
            let frame = "event: message_start\n\
                         data: {\"id\":\"msg_eof\",\"model\":\"kombai-v1\"}\n\n";
            let bytes = frame.as_bytes();
            sock.write_all(format!("{:x}\r\n", bytes.len()).as_bytes()).await.unwrap();
            sock.write_all(bytes).await.unwrap();
            sock.write_all(b"\r\n").await.unwrap();
            // Terminate chunked transfer immediately.
            sock.write_all(b"0\r\n\r\n").await.unwrap();
            sock.flush().await.unwrap();
            // Drop the socket → reader observes EOF.
        });

        let client = SidecarModelClient::new(
            format!("http://127.0.0.1:{port}"),
            "kombai",
            TEST_SECRET_HEX,
        ).unwrap();
        let req = fixture_request();
        let mut rx = client.create_message_stream(&req).await.unwrap();

        let mut saw_eof_stop = false;
        let mut saw_complete = false;
        while let Some(ev) = rx.recv().await {
            match ev {
                StreamEvent::Stop { stop_reason } => {
                    let msg = stop_reason.unwrap_or_default();
                    if msg.contains("stream_eof_before_complete") {
                        saw_eof_stop = true;
                    }
                }
                StreamEvent::Complete(_) => saw_complete = true,
                _ => {}
            }
        }
        assert!(saw_eof_stop,
            "EOF before `complete` event must surface a terminal Stop");
        assert!(!saw_complete,
            "Complete MUST NOT be emitted when the sidecar closes early");

        server.await.unwrap();
    }

    /// V2_GAPS §2.6 — a non-2xx response is surfaced synchronously
    /// from `create_message_stream`. The consumer never sees a
    /// half-open receiver in that case (`INV-PROVIDER-04` for the
    /// streaming path: pre-stream errors are not silently swallowed
    /// into a torn channel).
    #[tokio::test]
    async fn stream_pre_stream_4xx_surfaces_upstream_error() {
        use tokio::io::AsyncWriteExt;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let _ = read_sidecar_request(&mut sock).await;
            let body = b"{\"error\":\"unauthorized\"}";
            let head = format!(
                "HTTP/1.1 401 Unauthorized\r\n\
                 Content-Type: application/json\r\n\
                 Content-Length: {}\r\n\
                 Connection: close\r\n\r\n",
                body.len(),
            );
            sock.write_all(head.as_bytes()).await.unwrap();
            sock.write_all(body).await.unwrap();
        });

        let client = SidecarModelClient::new(
            format!("http://127.0.0.1:{port}"),
            "kombai",
            TEST_SECRET_HEX,
        ).unwrap();
        let req = fixture_request();
        let err = client.create_message_stream(&req).await.unwrap_err();
        match err {
            ModelError::Upstream { status, body } => {
                assert_eq!(status, 401);
                assert!(body.contains("unauthorized"));
            }
            other => panic!("expected Upstream(401), got {other:?}"),
        }

        server.await.unwrap();
    }

    /// V2_GAPS §2.6 — pin the helper used by the aggregator. A
    /// regression in the canonicalisation (e.g. someone swapping
    /// `to_vec` for `to_value` then `to_string`) would break
    /// signature verification end-to-end. This pins the helper
    /// independently of the streaming path.
    #[test]
    fn hmac_sha256_helper_round_trips_against_compute_hmac() {
        let c = SidecarModelClient::new(
            "http://localhost:9100",
            "test",
            TEST_SECRET_HEX,
        ).unwrap();
        let h_helper = hmac_sha256_hex(&c.secret, "rid", 1234, b"body-bytes");
        let h_method = c.compute_hmac("rid", 1234, b"body-bytes");
        assert_eq!(h_helper, h_method);
    }

    /// V2_GAPS §2.6 — pin the constant-time comparator. A regression
    /// to short-circuit equality (which `==` on `&[u8]` does) would
    /// reintroduce a timing-side-channel in the streaming signature
    /// check.
    #[test]
    fn constant_time_eq_returns_correct_value() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
        assert!(constant_time_eq(b"", b""));
    }
}

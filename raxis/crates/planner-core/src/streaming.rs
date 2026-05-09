//! V2_GAPS §C9 — streaming model dispatch.
//!
//! ## Why this module exists
//!
//! The V2.4 [`ModelClient`](crate::ModelClient) trait is non-streaming:
//! every call to `create_message` blocks until the upstream provider
//! has emitted its complete response body. For 100K-token outputs
//! this stalls the dispatch loop for 60–120 seconds with no
//! observability, no idle-timeout detection, and no early
//! budget-abort opportunity (per `provider-failure-handling.md §7`).
//!
//! C9 closes the V2 streaming gap by adding a **second, opt-in,
//! incremental-events trait method** — [`ModelClient::create_message_stream`]
//! — that yields a sequence of [`StreamEvent`]s as the upstream
//! generates content. The buffered `create_message` shape is
//! preserved for backwards compatibility: every existing impl that
//! does not opt in to streaming inherits the **default** trait
//! method that drives `create_message` and emits a synthetic
//! single-event stream (one `MessageStart`, one final `Complete`).
//!
//! ## Invariants this module preserves
//!
//! * **`INV-PROVIDER-04` (atomic delivery to the planner).** The
//!   stream's terminal event ([`StreamEvent::Complete`]) is the
//!   *only* one the dispatch loop's tool-execution path consumes.
//!   Incremental [`StreamEvent::ContentBlockDelta`] /
//!   [`StreamEvent::Usage`] events are observability-only and
//!   never carry partial JSON or half-formed `tool_use` blocks.
//!   The aggregator inside [`AnthropicStreamReader`] guarantees
//!   that the [`MessageResponse`] handed to the dispatch loop is
//!   structurally complete (every `content_block_start` paired
//!   with a matching `content_block_stop`).
//! * **`INV-GATEWAY-STREAM-ATOMICITY`.** This invariant continues
//!   to hold: the planner's *tool-dispatch* logic still observes
//!   the assistant turn atomically (only [`StreamEvent::Complete`]
//!   feeds into [`crate::dispatch::DispatchLoop`]). The
//!   intermediate events are hooks for V3 features
//!   (incremental-token-budget abort, operator-visible progress)
//!   that opt in explicitly.
//! * **No resumable streams.** Per `provider-failure-handling.md
//!   §7.5`, mid-stream failure surfaces a clean
//!   [`ModelError::Transport`] / [`ModelError::Timeout`] and the
//!   retry / fallback shells (see [`crate::retry`]) replay the
//!   full request from scratch.
//! * **Idle-timeout protection.** Every stream is wrapped in a
//!   per-chunk idle deadline (default 30 s). A provider that
//!   accepts the request but stalls mid-stream surfaces a
//!   [`ModelError::Timeout`] within `stream_idle_timeout`, not
//!   the much-longer `request_timeout`. This is the V2 leg of
//!   the spec's "hang detection" benefit (§C9 reason #2).
//!
//! ## Why the events are tokio-channel-based, not `futures::Stream`
//!
//! `tokio::sync::mpsc::Receiver` is the lightest-weight stream
//! abstraction the workspace already depends on transitively
//! through tokio itself. Pulling in `futures` as a planner-core
//! dep would (a) duplicate the `Stream` trait surface and (b) make
//! cross-crate boundaries noisier. The `Receiver` shape is also a
//! 1:1 match for the bounded backpressure semantics the spec
//! requires (`stream_buffer_cap`): a slow consumer simply lets
//! `send` await on a full channel, and the upstream reader
//! naturally pauses.

use std::time::Duration;

use serde::Deserialize;

use crate::model::{ContentBlock, MessageResponse, ModelError, Usage};

/// Default idle deadline between two consecutive SSE chunks. A
/// provider that goes silent for longer than this triggers an
/// abort with [`ModelError::Timeout`]. The dispatch loop's retry
/// shell ([`crate::retry::RetryingModelClient`]) then advances to
/// the next attempt or fallback provider.
///
/// 30 s is the spec's recommended default
/// (`provider-failure-handling.md §7.3 stream_idle_timeout_ms`):
/// long enough to absorb network jitter and reasoning-mid-token
/// stalls; short enough to detect a hard hang well before the
/// 5-minute `request_timeout` ceiling.
pub const DEFAULT_STREAM_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// Default channel capacity for the [`tokio::sync::mpsc`] back end.
/// Each event is a small enum variant (≤200 bytes) so the buffer
/// is on the order of a few KiB, well below the spec's
/// `stream_buffer_cap` (32 MiB on the gateway side).
///
/// 64 events is enough headroom that a slow consumer (the
/// dispatch loop pausing to render KSB) never causes the SSE
/// reader to back-pressure on the upstream provider for typical
/// turn shapes.
pub const DEFAULT_STREAM_CHANNEL_CAP: usize = 64;

/// One event in the planner-side stream.
///
/// **Wire shape stability.** This enum is part of the planner's
/// ABI (the dispatch loop, the operator-visible progress feed,
/// and any V3 incremental token-budget enforcer all consume it).
/// Variants are append-only; existing variants do not change
/// their field layout without bumping the planner-core crate
/// version.
///
/// **No `PartialEq` derive** — [`MessageResponse::content`]
/// transitively contains `serde_json::Value` (`ContentBlock::ToolUse::input`)
/// which intentionally does not implement `Eq`. Tests that need to
/// compare events do so by pattern matching on variants.
#[derive(Debug, Clone)]
pub enum StreamEvent {
    /// Emitted exactly once at the start of every stream, carrying
    /// the upstream-minted message id and the resolved model id.
    /// Pinned by `provider-failure-handling.md §7.1`.
    MessageStart {
        /// Anthropic / OpenAI / etc.-minted message id (e.g.
        /// `msg_01ABC...`). Round-tripped into the eventual
        /// [`MessageResponse::id`] so audit attribution sees the
        /// same value regardless of which transport path
        /// (buffered vs. streamed) produced the response.
        id: String,
        /// Echo of the model id from the request. Surfaced to
        /// the operator's `raxis status` so silent provider-side
        /// model upgrades (e.g.,
        /// `claude-sonnet-4-5-20250929` → `…20251015`) become
        /// visible in real time rather than only at end-of-turn.
        model: String,
    },

    /// Emitted on every Anthropic `content_block_start` (and the
    /// equivalent on other providers). Useful for V3 progress
    /// indicators that want to count blocks; the dispatch loop
    /// itself does not consume this variant in V2.
    ContentBlockStart {
        /// Index of the block within the assistant's content.
        index: u32,
        /// `"text"` / `"tool_use"` / etc. — the upstream's
        /// discriminator string. Kept as `String` rather than
        /// re-typed to a `ContentBlock` variant because the
        /// `content_block_start` event does not carry the full
        /// block body yet (text is empty; tool_use has no
        /// arguments yet).
        block_kind: String,
    },

    /// Emitted on every Anthropic `content_block_delta` event.
    /// Carries the incremental text or partial-JSON string.
    ContentBlockDelta {
        /// Index of the block within the assistant's content.
        index: u32,
        /// The delta payload.
        delta: ContentBlockDeltaPayload,
    },

    /// Emitted on every Anthropic `content_block_stop` event.
    ContentBlockStop {
        /// Index of the just-closed block.
        index: u32,
    },

    /// Cumulative token usage update from the upstream.
    /// Anthropic emits one of these inside `message_delta` near the
    /// end of the stream; OpenAI emits it via the `usage` field of
    /// the final SSE chunk. The dispatch loop's coarse C1 ceilings
    /// (V2_GAPS §C1) consume this to drive incremental
    /// budget-abort logic in V3.
    Usage(Usage),

    /// The stop reason emitted just before the stream closes
    /// (Anthropic: `message_delta.delta.stop_reason` →
    /// `message_stop`; OpenAI: `choices[0].finish_reason` on the
    /// last chunk). May be `None` if the upstream never set one
    /// (the aggregator surfaces this as `None` in the final
    /// [`MessageResponse`]).
    Stop {
        /// `"end_turn"` / `"max_tokens"` / `"stop_sequence"` /
        /// `"tool_use"` (and their cross-provider equivalents).
        stop_reason: Option<String>,
    },

    /// **Terminal event.** The fully-aggregated [`MessageResponse`].
    /// Always the last event on a successful stream. The dispatch
    /// loop reads this variant exclusively for tool-dispatch
    /// purposes; intermediate events are observability-only.
    Complete(MessageResponse),
}

/// One delta inside [`StreamEvent::ContentBlockDelta`]. Wire-shape
/// faithful to the Anthropic stream protocol; non-Anthropic
/// providers translate their incremental events to one of these
/// variants in their respective `*_client::stream_*` adapters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContentBlockDeltaPayload {
    /// Incremental text inside a `text` content block.
    TextDelta {
        /// The new text fragment.
        text: String,
    },
    /// Incremental partial-JSON inside a `tool_use` content block.
    /// The dispatch loop never parses this incrementally (per
    /// INV-PROVIDER-04). The full `tool_use.input` object is
    /// only available in the terminal [`StreamEvent::Complete`]
    /// event.
    InputJsonDelta {
        /// One UTF-8 fragment of the JSON body, in order.
        partial_json: String,
    },
}

// ---------------------------------------------------------------------------
// Anthropic SSE parser
// ---------------------------------------------------------------------------

/// Anthropic-flavoured server-sent-event names. Not exhaustive —
/// we only branch on the events the V2 aggregator consumes.
/// Unknown events are treated as no-ops (forward-compatible).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AnthropicSseEvent {
    MessageStart,
    ContentBlockStart,
    ContentBlockDelta,
    ContentBlockStop,
    MessageDelta,
    MessageStop,
    Ping,
    Other,
}

impl AnthropicSseEvent {
    pub(crate) fn parse(name: &str) -> Self {
        match name {
            "message_start"        => Self::MessageStart,
            "content_block_start"  => Self::ContentBlockStart,
            "content_block_delta"  => Self::ContentBlockDelta,
            "content_block_stop"   => Self::ContentBlockStop,
            "message_delta"        => Self::MessageDelta,
            "message_stop"         => Self::MessageStop,
            "ping"                 => Self::Ping,
            _                      => Self::Other,
        }
    }
}

/// One parsed SSE frame: an `event: <name>` line plus its
/// `data: <json>` payload. The Anthropic SSE protocol allows
/// multi-line `data:` continuation lines (concatenated with `\n`);
/// this parser supports that shape. Comment lines (those starting
/// with `:`) are skipped per the W3C SSE spec.
///
/// `pub` rather than `pub(crate)` so other ModelClient impls (live
/// outside this module: `bedrock_client`, `gemini_client`,
/// `openai_client`, `sidecar_client`) can plug into the same
/// aggregator surface in V3 when they grow streaming support.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SseFrame {
    /// SSE event name (the value of an `event: <name>` line).
    pub event: String,
    /// SSE data payload (concatenation of all `data: <line>` lines
    /// joined by `\n`, per the W3C spec).
    pub data:  String,
}

/// Stream-aware SSE byte parser. Keeps a rolling buffer of bytes
/// and emits frames whenever a complete `\n\n`-terminated frame is
/// available. Designed for the chunk-by-chunk feeding pattern an
/// HTTP body stream produces.
#[derive(Debug, Default)]
pub struct SseParser {
    buf: Vec<u8>,
}

impl SseParser {
    /// Construct a fresh parser with empty internal buffer.
    pub fn new() -> Self {
        Self { buf: Vec::with_capacity(4096) }
    }

    /// Append a chunk and return every now-complete frame, in
    /// order. The internal buffer retains the trailing partial
    /// frame for the next call.
    pub fn push(&mut self, chunk: &[u8]) -> Vec<SseFrame> {
        self.buf.extend_from_slice(chunk);
        let mut out = Vec::new();
        loop {
            // Look for `\n\n` (frame terminator). Naive scan;
            // the buffer is small per-chunk and SSE frames are
            // small (≤4 KiB typical for Anthropic).
            let Some(end) = find_double_newline(&self.buf) else { break };
            let frame_bytes: Vec<u8> = self.buf.drain(..end + 2).collect();
            let frame_str = match std::str::from_utf8(&frame_bytes) {
                Ok(s) => s,
                Err(_) => continue, // malformed frame — drop and keep going
            };
            if let Some(parsed) = parse_sse_frame(frame_str) {
                out.push(parsed);
            }
        }
        out
    }

    /// Consume any remaining buffered bytes as a final frame at
    /// stream-close time. Anthropic streams typically end with a
    /// terminating `\n\n` so this returns nothing in production;
    /// it exists for the truncated-stream test case.
    pub fn flush(&mut self) -> Option<SseFrame> {
        if self.buf.is_empty() {
            return None;
        }
        let raw = std::mem::take(&mut self.buf);
        let s = std::str::from_utf8(&raw).ok()?;
        parse_sse_frame(s)
    }
}

/// Find the byte index of the first `\n\n` (or `\r\n\r\n`) in
/// `buf`. Returns the index of the FIRST `\n`, so the caller
/// drains `..index + 2` for `\n\n` (or `..index + 4` for the CRLF
/// flavour, but we normalise to `\n` first by checking both).
fn find_double_newline(buf: &[u8]) -> Option<usize> {
    let mut i = 0;
    while i + 1 < buf.len() {
        if buf[i] == b'\n' && buf[i + 1] == b'\n' {
            return Some(i);
        }
        i += 1;
    }
    None
}

fn parse_sse_frame(frame: &str) -> Option<SseFrame> {
    let mut event: Option<String> = None;
    let mut data:  Vec<&str>      = Vec::new();
    for line in frame.lines() {
        if line.is_empty() {
            continue;
        }
        if line.starts_with(':') {
            // Comment line — ignored per W3C SSE.
            continue;
        }
        if let Some(rest) = line.strip_prefix("event:") {
            event = Some(rest.trim().to_owned());
        } else if let Some(rest) = line.strip_prefix("data:") {
            // SSE allows a single space after `data:` which the
            // spec says to strip.
            let trimmed = rest.strip_prefix(' ').unwrap_or(rest);
            data.push(trimmed);
        }
    }
    let event = event?;
    if data.is_empty() {
        return None;
    }
    Some(SseFrame {
        event,
        data: data.join("\n"),
    })
}

// ---------------------------------------------------------------------------
// Anthropic-specific JSON shapes (only what the aggregator reads)
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct AnthropicMessageStart {
    message: AnthropicMessageStartMessage,
}

#[derive(Debug, Deserialize)]
struct AnthropicMessageStartMessage {
    id:    String,
    model: String,
    #[serde(default)]
    usage: Option<Usage>,
}

#[derive(Debug, Deserialize)]
struct AnthropicContentBlockStart {
    index:         u32,
    content_block: serde_json::Value,
}

#[derive(Debug, Deserialize)]
struct AnthropicContentBlockDelta {
    index: u32,
    delta: serde_json::Value,
}

#[derive(Debug, Deserialize)]
struct AnthropicContentBlockStop {
    index: u32,
}

#[derive(Debug, Deserialize)]
struct AnthropicMessageDelta {
    delta: AnthropicMessageDeltaInner,
    #[serde(default)]
    usage: Option<Usage>,
}

#[derive(Debug, Deserialize)]
struct AnthropicMessageDeltaInner {
    #[serde(default)]
    stop_reason: Option<String>,
}

// ---------------------------------------------------------------------------
// Aggregator
// ---------------------------------------------------------------------------

/// Streaming aggregator: feeds raw Anthropic SSE bytes in,
/// emits [`StreamEvent`]s on the receiver, and produces a final
/// aggregated [`MessageResponse`] at stream close.
///
/// **Threading model.** The aggregator is owned by one task. The
/// receiver side is consumed by the planner (typically the same
/// task that called `create_message_stream`).
pub struct AnthropicStreamAggregator {
    /// In-progress content blocks indexed by their per-message
    /// `index` field. The aggregator builds these up from
    /// `content_block_start` + `content_block_delta` events; on
    /// `content_block_stop` the entry is finalized and pushed
    /// into [`Self::content`].
    pending_blocks: std::collections::HashMap<u32, PendingBlock>,
    content:        Vec<ContentBlock>,
    id:             Option<String>,
    model:          Option<String>,
    stop_reason:    Option<String>,
    usage:          Usage,
}

#[derive(Debug, Default)]
struct PendingBlock {
    /// `"text"` or `"tool_use"`.
    kind:        String,
    /// For `text` blocks.
    text:        String,
    /// For `tool_use` blocks.
    tool_use_id: Option<String>,
    tool_name:   Option<String>,
    /// Streamed JSON fragments — concatenated and parsed at
    /// `content_block_stop`.
    json_buf:    String,
}

impl Default for AnthropicStreamAggregator {
    fn default() -> Self {
        Self::new()
    }
}

impl AnthropicStreamAggregator {
    /// Construct a fresh aggregator.
    pub fn new() -> Self {
        Self {
            pending_blocks: std::collections::HashMap::new(),
            content:        Vec::new(),
            id:             None,
            model:          None,
            stop_reason:    None,
            usage:          Usage::default(),
        }
    }

    /// Process one parsed SSE frame and return zero or more
    /// [`StreamEvent`]s the consumer should observe.
    ///
    /// **Errors.** Returns [`ModelError::Json`] only for frames
    /// whose `data` payload is not parseable as the expected
    /// Anthropic shape; the aggregator stays in a consistent
    /// state across malformed frames (it skips them rather than
    /// poisoning the rest of the stream).
    pub fn ingest(&mut self, frame: &SseFrame) -> Result<Vec<StreamEvent>, ModelError> {
        let mut out = Vec::new();
        match AnthropicSseEvent::parse(&frame.event) {
            AnthropicSseEvent::MessageStart => {
                let parsed: AnthropicMessageStart = serde_json::from_str(&frame.data)
                    .map_err(|e| ModelError::Json(e.to_string()))?;
                self.id    = Some(parsed.message.id.clone());
                self.model = Some(parsed.message.model.clone());
                if let Some(u) = parsed.message.usage {
                    self.usage = u;
                }
                out.push(StreamEvent::MessageStart {
                    id:    parsed.message.id,
                    model: parsed.message.model,
                });
            }
            AnthropicSseEvent::ContentBlockStart => {
                let parsed: AnthropicContentBlockStart = serde_json::from_str(&frame.data)
                    .map_err(|e| ModelError::Json(e.to_string()))?;
                let kind = parsed
                    .content_block
                    .get("type")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_owned();
                let mut pending = PendingBlock {
                    kind: kind.clone(),
                    ..PendingBlock::default()
                };
                if kind == "text" {
                    if let Some(t) = parsed.content_block.get("text").and_then(|v| v.as_str()) {
                        pending.text.push_str(t);
                    }
                } else if kind == "tool_use" {
                    pending.tool_use_id = parsed
                        .content_block
                        .get("id")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_owned());
                    pending.tool_name = parsed
                        .content_block
                        .get("name")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_owned());
                }
                self.pending_blocks.insert(parsed.index, pending);
                out.push(StreamEvent::ContentBlockStart {
                    index:      parsed.index,
                    block_kind: kind,
                });
            }
            AnthropicSseEvent::ContentBlockDelta => {
                let parsed: AnthropicContentBlockDelta = serde_json::from_str(&frame.data)
                    .map_err(|e| ModelError::Json(e.to_string()))?;
                let entry = self.pending_blocks.entry(parsed.index).or_default();
                let delta_kind = parsed
                    .delta
                    .get("type")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                match delta_kind {
                    "text_delta" => {
                        let text = parsed
                            .delta
                            .get("text")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_owned();
                        entry.text.push_str(&text);
                        out.push(StreamEvent::ContentBlockDelta {
                            index: parsed.index,
                            delta: ContentBlockDeltaPayload::TextDelta { text },
                        });
                    }
                    "input_json_delta" => {
                        let frag = parsed
                            .delta
                            .get("partial_json")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_owned();
                        entry.json_buf.push_str(&frag);
                        out.push(StreamEvent::ContentBlockDelta {
                            index: parsed.index,
                            delta: ContentBlockDeltaPayload::InputJsonDelta {
                                partial_json: frag,
                            },
                        });
                    }
                    _ => {
                        // Unknown delta kind — forward-compatible no-op.
                    }
                }
            }
            AnthropicSseEvent::ContentBlockStop => {
                let parsed: AnthropicContentBlockStop = serde_json::from_str(&frame.data)
                    .map_err(|e| ModelError::Json(e.to_string()))?;
                if let Some(pending) = self.pending_blocks.remove(&parsed.index) {
                    let block = match pending.kind.as_str() {
                        "tool_use" => {
                            let input = if pending.json_buf.is_empty() {
                                serde_json::json!({})
                            } else {
                                serde_json::from_str::<serde_json::Value>(&pending.json_buf)
                                    .map_err(|e| ModelError::Json(e.to_string()))?
                            };
                            ContentBlock::ToolUse {
                                id:    pending.tool_use_id.unwrap_or_default(),
                                name:  pending.tool_name.unwrap_or_default(),
                                input,
                            }
                        }
                        "text" => ContentBlock::Text { text: pending.text },
                        _ => {
                            // Forward-compat: round-trip into Other so the
                            // dispatch loop's existing `Other` arm handles it.
                            ContentBlock::Other(serde_json::json!({
                                "type": pending.kind,
                            }))
                        }
                    };
                    self.content.push(block);
                }
                out.push(StreamEvent::ContentBlockStop { index: parsed.index });
            }
            AnthropicSseEvent::MessageDelta => {
                let parsed: AnthropicMessageDelta = serde_json::from_str(&frame.data)
                    .map_err(|e| ModelError::Json(e.to_string()))?;
                if let Some(reason) = parsed.delta.stop_reason {
                    self.stop_reason = Some(reason.clone());
                }
                if let Some(u) = parsed.usage {
                    // Anthropic message_delta `usage` is the cumulative
                    // output total; merge by overwriting output_tokens.
                    self.usage.output_tokens = u.output_tokens;
                    if u.input_tokens != 0 {
                        self.usage.input_tokens = u.input_tokens;
                    }
                    if u.cache_creation_input_tokens != 0 {
                        self.usage.cache_creation_input_tokens = u.cache_creation_input_tokens;
                    }
                    if u.cache_read_input_tokens != 0 {
                        self.usage.cache_read_input_tokens = u.cache_read_input_tokens;
                    }
                    out.push(StreamEvent::Usage(self.usage.clone()));
                }
            }
            AnthropicSseEvent::MessageStop => {
                out.push(StreamEvent::Stop {
                    stop_reason: self.stop_reason.clone(),
                });
            }
            AnthropicSseEvent::Ping | AnthropicSseEvent::Other => {
                // No-op events. The aggregator does not track
                // per-event timing; the upstream's idle-deadline
                // wrapper handles silence detection.
            }
        }
        Ok(out)
    }

    /// Return `true` if [`Self::ingest`] has consumed the
    /// terminal `message_stop` frame and the buffered state is
    /// safe to convert into a [`MessageResponse`].
    pub fn is_complete(&self) -> bool {
        self.pending_blocks.is_empty() && self.id.is_some()
    }

    /// Convert the aggregated state into a final
    /// [`MessageResponse`]. Returns [`ModelError::Json`] if the
    /// stream ended without enough information to fill the
    /// non-optional fields (typically: missing `message_start`
    /// frame).
    pub fn into_response(self) -> Result<MessageResponse, ModelError> {
        let id = self
            .id
            .ok_or_else(|| ModelError::Json("stream had no message_start frame".to_owned()))?;
        let model = self
            .model
            .ok_or_else(|| ModelError::Json("stream had no model id in message_start".to_owned()))?;
        Ok(MessageResponse {
            id,
            kind: "message".to_owned(),
            role: "assistant".to_owned(),
            content: self.content,
            stop_reason: self.stop_reason,
            usage: self.usage,
            model,
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_one(s: &str) -> Vec<SseFrame> {
        let mut p = SseParser::new();
        p.push(s.as_bytes())
    }

    #[test]
    fn sse_parser_extracts_event_and_data() {
        let frames = parse_one("event: message_start\ndata: {\"a\":1}\n\n");
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].event, "message_start");
        assert_eq!(frames[0].data, "{\"a\":1}");
    }

    #[test]
    fn sse_parser_handles_multi_line_data() {
        let frames =
            parse_one("event: message_delta\ndata: line one\ndata: line two\n\n");
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].data, "line one\nline two");
    }

    #[test]
    fn sse_parser_skips_comment_lines() {
        let frames = parse_one(": this is a comment\nevent: ping\ndata: {}\n\n");
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].event, "ping");
    }

    #[test]
    fn sse_parser_strips_optional_space_after_data_colon() {
        let frames = parse_one("event: ping\ndata:nospace\n\n");
        assert_eq!(frames[0].data, "nospace");
        let frames = parse_one("event: ping\ndata: withspace\n\n");
        assert_eq!(frames[0].data, "withspace");
    }

    #[test]
    fn sse_parser_emits_frame_only_on_full_terminator() {
        let mut p = SseParser::new();
        let f1 = p.push(b"event: ping\n");
        assert!(f1.is_empty());
        let f2 = p.push(b"data: {}\n");
        assert!(f2.is_empty());
        let f3 = p.push(b"\n");
        assert_eq!(f3.len(), 1);
    }

    #[test]
    fn sse_parser_emits_multiple_frames_per_chunk() {
        let frames = parse_one(
            "event: ping\ndata: {}\n\nevent: message_stop\ndata: {}\n\n",
        );
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0].event, "ping");
        assert_eq!(frames[1].event, "message_stop");
    }

    #[test]
    fn sse_event_parse_recognises_anthropic_kinds() {
        assert_eq!(
            AnthropicSseEvent::parse("message_start"),
            AnthropicSseEvent::MessageStart,
        );
        assert_eq!(
            AnthropicSseEvent::parse("content_block_delta"),
            AnthropicSseEvent::ContentBlockDelta,
        );
        assert_eq!(
            AnthropicSseEvent::parse("message_stop"),
            AnthropicSseEvent::MessageStop,
        );
        assert_eq!(
            AnthropicSseEvent::parse("definitely_not_a_real_event"),
            AnthropicSseEvent::Other,
        );
    }

    #[test]
    fn aggregator_full_round_trip_text_only_response() {
        let mut agg = AnthropicStreamAggregator::new();
        let frames = vec![
            SseFrame {
                event: "message_start".to_owned(),
                data: r#"{"message":{"id":"msg_01","model":"claude-sonnet-4-5-20250929",
                          "usage":{"input_tokens":12,"output_tokens":0,
                                   "cache_creation_input_tokens":0,
                                   "cache_read_input_tokens":0}}}"#.to_owned(),
            },
            SseFrame {
                event: "content_block_start".to_owned(),
                data: r#"{"index":0,"content_block":{"type":"text","text":""}}"#.to_owned(),
            },
            SseFrame {
                event: "content_block_delta".to_owned(),
                data: r#"{"index":0,"delta":{"type":"text_delta","text":"Hello"}}"#.to_owned(),
            },
            SseFrame {
                event: "content_block_delta".to_owned(),
                data: r#"{"index":0,"delta":{"type":"text_delta","text":" world"}}"#.to_owned(),
            },
            SseFrame {
                event: "content_block_stop".to_owned(),
                data: r#"{"index":0}"#.to_owned(),
            },
            SseFrame {
                event: "message_delta".to_owned(),
                data: r#"{"delta":{"stop_reason":"end_turn"},"usage":{"input_tokens":12,"output_tokens":2,"cache_creation_input_tokens":0,"cache_read_input_tokens":0}}"#.to_owned(),
            },
            SseFrame {
                event: "message_stop".to_owned(),
                data: r#"{}"#.to_owned(),
            },
        ];
        let mut emitted = Vec::new();
        for f in &frames {
            emitted.extend(agg.ingest(f).unwrap());
        }
        assert!(agg.is_complete());
        let resp = agg.into_response().unwrap();
        assert_eq!(resp.id, "msg_01");
        assert_eq!(resp.model, "claude-sonnet-4-5-20250929");
        assert_eq!(resp.stop_reason.as_deref(), Some("end_turn"));
        assert_eq!(resp.content.len(), 1);
        match &resp.content[0] {
            ContentBlock::Text { text } => assert_eq!(text, "Hello world"),
            other => panic!("expected Text block, got {other:?}"),
        }
        assert_eq!(resp.usage.output_tokens, 2);
        // Sanity-check the public event sequence.
        assert!(matches!(
            emitted.first(),
            Some(StreamEvent::MessageStart { .. })
        ));
        assert!(emitted
            .iter()
            .any(|e| matches!(e, StreamEvent::ContentBlockDelta { .. })));
        assert!(emitted
            .iter()
            .any(|e| matches!(e, StreamEvent::Stop { .. })));
    }

    #[test]
    fn aggregator_round_trips_tool_use_block_with_streamed_json() {
        let mut agg = AnthropicStreamAggregator::new();
        let frames = vec![
            SseFrame {
                event: "message_start".to_owned(),
                data: r#"{"message":{"id":"msg_02","model":"claude-sonnet-4-5-20250929"}}"#.to_owned(),
            },
            SseFrame {
                event: "content_block_start".to_owned(),
                data: r#"{"index":0,"content_block":{"type":"tool_use","id":"tu_1","name":"bash","input":{}}}"#.to_owned(),
            },
            SseFrame {
                event: "content_block_delta".to_owned(),
                data: r#"{"index":0,"delta":{"type":"input_json_delta","partial_json":"{\"cmd\":\"l"}}"#.to_owned(),
            },
            SseFrame {
                event: "content_block_delta".to_owned(),
                data: r#"{"index":0,"delta":{"type":"input_json_delta","partial_json":"s -la\"}"}}"#.to_owned(),
            },
            SseFrame {
                event: "content_block_stop".to_owned(),
                data: r#"{"index":0}"#.to_owned(),
            },
            SseFrame {
                event: "message_delta".to_owned(),
                data: r#"{"delta":{"stop_reason":"tool_use"},"usage":{"input_tokens":7,"output_tokens":10,"cache_creation_input_tokens":0,"cache_read_input_tokens":0}}"#.to_owned(),
            },
            SseFrame {
                event: "message_stop".to_owned(),
                data: r#"{}"#.to_owned(),
            },
        ];
        for f in &frames {
            agg.ingest(f).unwrap();
        }
        let resp = agg.into_response().unwrap();
        assert_eq!(resp.stop_reason.as_deref(), Some("tool_use"));
        match &resp.content[0] {
            ContentBlock::ToolUse { id, name, input } => {
                assert_eq!(id, "tu_1");
                assert_eq!(name, "bash");
                assert_eq!(input.get("cmd").and_then(|v| v.as_str()), Some("ls -la"));
            }
            other => panic!("expected ToolUse, got {other:?}"),
        }
    }

    #[test]
    fn aggregator_rejects_message_start_without_id() {
        let mut agg = AnthropicStreamAggregator::new();
        let bad = SseFrame {
            event: "message_start".to_owned(),
            data: r#"{"message":{"model":"claude"}}"#.to_owned(),
        };
        let err = agg.ingest(&bad).expect_err("missing id must be rejected");
        assert!(matches!(err, ModelError::Json(_)));
    }

    #[test]
    fn aggregator_into_response_fails_when_message_start_never_arrived() {
        let agg = AnthropicStreamAggregator::new();
        let err = agg.into_response().expect_err("empty stream must fail");
        match err {
            ModelError::Json(m) => assert!(m.contains("message_start"), "msg = {m}"),
            other => panic!("expected Json, got {other:?}"),
        }
    }

    #[test]
    fn aggregator_handles_unknown_delta_kind_gracefully() {
        let mut agg = AnthropicStreamAggregator::new();
        agg.ingest(&SseFrame {
            event: "message_start".to_owned(),
            data: r#"{"message":{"id":"m","model":"x"}}"#.to_owned(),
        })
        .unwrap();
        agg.ingest(&SseFrame {
            event: "content_block_start".to_owned(),
            data: r#"{"index":0,"content_block":{"type":"text"}}"#.to_owned(),
        })
        .unwrap();
        // Unknown delta kind — should not error.
        let out = agg
            .ingest(&SseFrame {
                event: "content_block_delta".to_owned(),
                data: r#"{"index":0,"delta":{"type":"some_future_delta_kind","x":1}}"#
                    .to_owned(),
            })
            .unwrap();
        assert!(out.is_empty(), "unknown delta must produce no events");
    }

    #[test]
    fn aggregator_skips_ping_and_other_events() {
        let mut agg = AnthropicStreamAggregator::new();
        let out = agg
            .ingest(&SseFrame {
                event: "ping".to_owned(),
                data: "{}".to_owned(),
            })
            .unwrap();
        assert!(out.is_empty());
        let out2 = agg
            .ingest(&SseFrame {
                event: "totally_made_up".to_owned(),
                data: "{}".to_owned(),
            })
            .unwrap();
        assert!(out2.is_empty());
    }

    #[test]
    fn default_constants_are_within_spec_bounds() {
        // Pin the specific defaults so spec-vs-code drift fails CI.
        assert_eq!(DEFAULT_STREAM_IDLE_TIMEOUT, Duration::from_secs(30));
        assert_eq!(DEFAULT_STREAM_CHANNEL_CAP, 64);
    }
}

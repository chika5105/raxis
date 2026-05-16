//! `INV-DASHBOARD-LLM-TURN-PANEL-WIRE-SHAPE-01` witness suite.
//!
//! Pin the iter64 BE→FE wire-shape contract for the per-task LLM
//! turns dashboard panel: `record_to_view` MUST lift `model`,
//! `role`, per-turn token usage, and the parsed request /
//! response payloads from the on-disk `LlmTurnRecord` so the
//! operator sees real values instead of empty / `undefined` /
//! `0` (the iter63-and-prior bug — the kernel was capturing real
//! Anthropic responses on disk but the wire view emitted only
//! `at_ms` + raw `body: String`, nothing the FE component reads).
//!
//! Three pinned cases:
//!
//!   1. Anthropic happy path (canonical `body.model` /
//!      `body.role` / `body.usage.{input,output,cache_*}_tokens`
//!      shape + `request_body` parses as the original prompt).
//!   2. Parse failure on the response body (non-JSON bytes — e.g.
//!      a transport-error string the gateway captured) — MUST
//!      fall back to `response = Value::String(raw_body)` and
//!      leave model / role empty + token fields `None`.
//!   3. OpenAI shape (`prompt_tokens` / `completion_tokens` —
//!      mapped onto the canonical `input_tokens` / `output_tokens`
//!      slots; cache fields stay `None` because OpenAI does not
//!      expose prompt-cache hit/miss counts).
//!
//! Tests are written but NOT executed in this iter — parent will
//! run consolidated `cargo fmt + build + clippy + test` post-merge.

use raxis_dashboard_kernel::{record_to_view, LlmTurnRecord};
use serde_json::json;

/// Construct an `LlmTurnRecord` modelling one captured Anthropic
/// `messages.create` response (Sonnet 4.5 envelope).
fn anthropic_record() -> LlmTurnRecord {
    let response_body = json!({
        "id": "msg_01SzcUAXdFVxbTRNuQUSuspM",
        "model": "claude-sonnet-4-5-20250929",
        "type": "message",
        "role": "assistant",
        "content": [
            { "type": "text", "text": "I'll execute this task step by step." }
        ],
        "stop_reason": "tool_use",
        "usage": {
            "input_tokens": 2,
            "cache_creation_input_tokens": 5586,
            "cache_read_input_tokens": 2596,
            "output_tokens": 1281
        }
    })
    .to_string();
    let request_body = json!({
        "model": "claude-sonnet-4-5-20250929",
        "messages": [
            { "role": "user", "content": "execute this task" }
        ],
        "max_tokens": 4096
    })
    .to_string();
    LlmTurnRecord {
        at_ms: 1_778_908_309_036,
        task_id: "allowlist-positive-codegen".into(),
        session_id: Some("c6648d42-f758-436e-ab6a-66ce9e627373".into()),
        fetch_id: "d6f061c9-d27f-40b4-97b2-ff9ff2b9a41c".into(),
        status_code: Some(200),
        latency_ms: 22_356,
        request_body,
        body: response_body,
        body_truncated: false,
        original_body_bytes: 770,
        error: None,
    }
}

#[test]
fn projection_lifts_anthropic_model_role_and_usage_into_wire_view() {
    let view = record_to_view(anthropic_record(), 1);

    assert_eq!(view.turn_number, 1, "1-indexed monotonic per-task");
    assert_eq!(
        view.ts_unix,
        1_778_908_309,
        "ts_unix MUST be at_ms / 1000",
    );
    assert_eq!(
        view.model, "claude-sonnet-4-5-20250929",
        "model MUST be lifted from response body.model",
    );
    assert_eq!(
        view.role, "assistant",
        "role MUST be lifted from response body.role",
    );

    // Anthropic per-turn usage breakdown. The FE renders these as
    // four side-by-side counters and computes the cache-hit ratio
    // from `cache_read / (cache_read + cache_creation + input)`.
    assert_eq!(view.input_tokens, Some(2));
    assert_eq!(view.cache_creation_input_tokens, Some(5586));
    assert_eq!(view.cache_read_input_tokens, Some(2596));
    assert_eq!(view.output_tokens, Some(1281));

    // The full parsed response payload MUST flow through so the
    // operator can read tool_use / content blocks in the panel.
    let resp = view.response.as_object().expect("response MUST be an object");
    assert_eq!(
        resp.get("model").and_then(|v| v.as_str()),
        Some("claude-sonnet-4-5-20250929"),
    );
    assert_eq!(
        resp.get("stop_reason").and_then(|v| v.as_str()),
        Some("tool_use"),
    );

    // The parsed request payload (iter64 capture) MUST also flow.
    let req = view.request.as_object().expect("request MUST be an object");
    assert_eq!(
        req.get("model").and_then(|v| v.as_str()),
        Some("claude-sonnet-4-5-20250929"),
    );

    // Carry-over fields — present so global "recent LLM activity"
    // cross-task views can merge across tasks without another wire
    // bump.
    assert_eq!(view.task_id, "allowlist-positive-codegen");
    assert_eq!(view.session_id.as_deref(), Some("c6648d42-f758-436e-ab6a-66ce9e627373"));
    assert_eq!(view.fetch_id, "d6f061c9-d27f-40b4-97b2-ff9ff2b9a41c");
    assert_eq!(view.status_code, Some(200));
    assert_eq!(view.latency_ms, Some(22_356));
    assert!(!view.body_truncated);
    assert_eq!(view.original_body_bytes, 770);
    assert!(view.error.is_none());
}

#[test]
fn projection_falls_back_to_value_string_on_response_parse_failure() {
    // A transport-error string the gateway might have captured
    // verbatim when the upstream returned malformed bytes (e.g.
    // a hardware-induced EOF mid-SSE stream). The projection MUST
    // surface the bytes via `Value::String(raw_body)` so the
    // operator still sees what the upstream actually returned —
    // dropping to `null` would hide the failure shape.
    let mut r = anthropic_record();
    r.body = "not json".into();
    r.request_body = String::new();

    let view = record_to_view(r, 7);

    assert_eq!(view.turn_number, 7);
    assert_eq!(
        view.response,
        serde_json::Value::String("not json".into()),
        "non-JSON body MUST surface as Value::String(raw)",
    );
    assert_eq!(view.model, "", "model defaults to empty when body is non-JSON");
    assert_eq!(view.role, "", "role defaults to empty when body is non-JSON");
    assert_eq!(view.input_tokens, None);
    assert_eq!(view.output_tokens, None);
    assert_eq!(view.cache_creation_input_tokens, None);
    assert_eq!(view.cache_read_input_tokens, None);

    // Empty request_body → request = Value::Null. Also pins the
    // pre-iter64-on-disk-records back-compat path: legacy lines
    // missing `request_body` deserialize via serde_default to
    // empty string, then project to Null here.
    assert_eq!(view.request, serde_json::Value::Null);
}

#[test]
fn projection_maps_openai_prompt_completion_tokens_onto_canonical_slots() {
    // OpenAI's `chat.completion` envelope uses `prompt_tokens` /
    // `completion_tokens` and does NOT expose prompt-cache
    // hit/miss counts. The projection MUST map the OpenAI names
    // onto the canonical `input_tokens` / `output_tokens` slots
    // and leave cache_* `None` so the FE's cache-hit ratio falls
    // back to the "N/A" red badge (denominator zero).
    let response_body = json!({
        "id": "chatcmpl-9wH9Pmfoo",
        "model": "gpt-4o-2024-08-06",
        "object": "chat.completion",
        // OpenAI envelopes carry `role` inside the choices array,
        // not at the top level — the projection's `body.role`
        // lookup MUST therefore return empty for OpenAI shapes.
        "choices": [
            { "message": { "role": "assistant", "content": "ok" } }
        ],
        "usage": {
            "prompt_tokens": 412,
            "completion_tokens": 88,
            "total_tokens": 500
        }
    })
    .to_string();
    let r = LlmTurnRecord {
        at_ms: 1_700_000_000_000,
        task_id: "openai-task".into(),
        session_id: None,
        fetch_id: "fetch-openai".into(),
        status_code: Some(200),
        latency_ms: 1_234,
        request_body: String::new(),
        body: response_body,
        body_truncated: false,
        original_body_bytes: 0,
        error: None,
    };

    let view = record_to_view(r, 3);

    assert_eq!(view.turn_number, 3);
    assert_eq!(view.model, "gpt-4o-2024-08-06");
    // OpenAI envelope has no top-level `role`; projection emits "".
    assert_eq!(view.role, "");
    assert_eq!(
        view.input_tokens,
        Some(412),
        "OpenAI prompt_tokens MUST map onto the canonical input_tokens slot",
    );
    assert_eq!(
        view.output_tokens,
        Some(88),
        "OpenAI completion_tokens MUST map onto the canonical output_tokens slot",
    );
    assert_eq!(
        view.cache_creation_input_tokens, None,
        "OpenAI does not expose cache-creation; field MUST be None"
    );
    assert_eq!(
        view.cache_read_input_tokens, None,
        "OpenAI does not expose cache-read; field MUST be None"
    );
}

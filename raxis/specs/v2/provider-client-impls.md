# V2 — Multi-Provider `ModelClient` Implementations

> **Status:** **CLOSED V2.4** (initial impls landed; sigv4 gateway leg deferred — see §6).
>
> **Normative references:**
> - [`provider-model-selection.md §3`](provider-model-selection.md) — provider catalogue + `ProviderId` enum
> - [`provider-failure-handling.md §6`](provider-failure-handling.md) — circuit-breaker semantics
> - `peripherals.md §3.2` — credential injection precedence
> - `gateway-substrate.md §3` — host-side gateway egress hop
> - `INV-GATEWAY-STREAM-ATOMICITY` — non-streaming response is a structural
>   invariant for V2; partial-stream recovery is V3

This document is the canonical wire-shape contract for the V2 multi-provider
`ModelClient` impls. The trait itself
(`crates/planner-core/src/model.rs`) is already provider-agnostic; this
spec pins the shapes the V2 release of `raxis-planner-core` translates
**from** the Anthropic-flavoured canonical request type and **into** for
each upstream.

## §1 — Architectural Decision: Anthropic-flavoured canonical type

The canonical [`MessageRequest`] / [`MessageResponse`] types live in
`crates/planner-core/src/model.rs` and match the Anthropic Messages API
exactly. Other provider impls translate to and from this canonical shape.

**Why Anthropic-flavoured rather than a lowest-common-denominator type:**

1. **Tool-use semantics differ.** Anthropic's `tool_use` /
   `tool_result` blocks carry richer typing than the OpenAI
   `function_call` / `tool_message` round-trip; a generic enum would
   either lose information (forcing the planner-tools layer to
   re-escape) or invent a new shape that is gratuitously different from
   every provider on the wire. We pin to Anthropic because that is the
   shape the planner-tools dispatch loop already speaks.

2. **Translation is one-way structural.** Each provider impl
   constructs its own wire body from the canonical type; the response
   is parsed into provider-shaped types and **mapped** back to the
   canonical `MessageResponse`. There is no shared "intermediate JSON"
   format. The cost is per-provider boilerplate; the gain is that no
   field of any provider's API is hidden behind an enum and the
   compiler enforces every translation explicitly.

3. **Single trait surface.** Composition (
   `Fallback[Retrying[OpenAiClient], Retrying[GeminiClient]]`
   ) requires a single `Arc<dyn ModelClient>` shape. Per-provider impls
   register against the same trait so the dispatch loop and the
   resilience shells (retry and fallback-with-cooldown) work identically
   across providers.

## §2 — `OpenAiClient` — OpenAI-compatible APIs

**Crate:** `raxis-planner-core` (`src/openai_client.rs`)
**Upstream:** usually `POST /v1/chat/completions` against `<base_url>`
(default `https://api.openai.com`). Completion-only models in the
known-model registry (for example `gpt-5.3-codex`) use
`POST /v1/completions` instead. The endpoint choice is model-owned,
not planner-owned; a planner must not discover this dynamically by
burning failed turns against the wrong endpoint.

### §2.1 — Request translation: Anthropic → OpenAI chat completions

| Canonical field | OpenAI body field | Translation |
|---|---|---|
| `model` | `model` | Verbatim. The known-model registry has already validated. |
| `max_tokens` | `max_tokens` | Verbatim. |
| `temperature` | `temperature` | Verbatim. |
| `system` | First message with `role = "system"` | Prepended to the OpenAI `messages` array. |
| `messages[].role = "user"` | `messages[].role = "user"` | Each `ContentBlock::Text` becomes `messages[].content` (string). Multiple text blocks are joined with `"\n\n"`. |
| `messages[].role = "assistant"` | `messages[].role = "assistant"` | `ContentBlock::Text` becomes `content`; `ContentBlock::ToolUse { id, name, input }` becomes a `tool_calls[]` entry with `id`, `type: "function"`, `function: { name, arguments: stringify(input) }`. |
| `ContentBlock::ToolResult { tool_use_id, content, is_error }` | A separate `messages[]` entry with `role = "tool"`, `tool_call_id = tool_use_id`, and `content = stringify(content)` | OpenAI requires tool results as their own messages. The translator splits a single Anthropic `user` message containing tool results into one OpenAI `tool` message per result. |
| `tools[].name` / `description` / `input_schema` | `tools[].function.name` / `description` / `parameters` | Wrap each `ToolSpec` in `{ "type": "function", "function": { ... } }`. |

### §2.2 — Request translation: Anthropic → OpenAI completions

For completion-only OpenAI-family models, the canonical transcript is
flattened into a single `prompt` string and sent to `/v1/completions`.
The body contains `model`, `prompt`, `max_tokens`, and optional
`temperature`; it does **not** contain `messages` or native
`tool_calls`. Tool names and schemas are rendered into the prompt as a
compact manifest so the model can still follow the same planner
contract, but there is no provider-native function-call envelope on
this surface.

Completion-only tool calls therefore use a normalized text contract.
When a model needs a tool, it is prompted to emit only compact JSON:

```json
{"tool_calls":[{"name":"tool_name","input":{}}]}
```

The adapter accepts that normalized shape and an OpenAI-like
`function.arguments` string shape, converts either into canonical
`ContentBlock::ToolUse`, and maps the stop reason to `tool_use`. This
keeps completion-only models compatible with the same dispatch loop
without granting them any planner-side provider special cases.

### §2.3 — Response translation: OpenAI → Anthropic

| OpenAI field | Canonical field | Translation |
|---|---|---|
| `id` | `id` | Verbatim. |
| `model` | `model` | Verbatim. |
| `choices[0].message.role` | `role` | Always `"assistant"` for V2; rejected if not. |
| `choices[0].finish_reason` | `stop_reason` | Mapped: `"stop"` → `"end_turn"`, `"length"` → `"max_tokens"`, `"tool_calls"` → `"tool_use"`. Other values pass through. |
| `choices[0].message.content` | `content` (single `Text` block) | If non-null, becomes the first `ContentBlock::Text`. |
| `choices[0].message.tool_calls[]` | `content` (`ToolUse` blocks appended) | Each tool call → `ContentBlock::ToolUse { id, name, input: parse(arguments) }`. The arguments string is parsed as JSON; on parse failure the call falls back to `input: { "raw": arguments }`. |
| `usage.prompt_tokens` | `usage.input_tokens` | Verbatim. |
| `usage.completion_tokens` | `usage.output_tokens` | Verbatim. |
| `usage.cached_tokens` (optional) | `usage.cache_read_input_tokens` | When present in response. |

For `/v1/completions`, `choices[0].text` becomes a single
`ContentBlock::Text`, and `choices[0].finish_reason` uses the same
stop-reason mapping.

### §2.4 — Error mapping

* HTTP non-2xx → `ModelError::Upstream { status, body (≤4KB) }`. Same
  shape as `AnthropicClient` so the retry classifier and circuit
  breaker work identically.
* Timeout → `ModelError::Timeout(d)`.
* Connection / TLS / DNS → `ModelError::Transport(s)`.
* OpenAI error envelope (`{ "error": { "type": ..., "code": ..., "message": ... } }`) is preserved verbatim in the `body` field.

### §2.5 — Headers

* `Content-Type: application/json` (always)
* `Accept: application/json`
* The planner does **not** set `Authorization`; the gateway injects the
  `Authorization: Bearer <api_key>` header at the egress hop per
  `peripherals.md §3.2`.

## §3 — `GeminiClient` — `generateContent`

**Crate:** `raxis-planner-core` (`src/gemini_client.rs`)
**Upstream:** `POST /v1beta/models/<model>:generateContent` against
`<base_url>` (default `https://generativelanguage.googleapis.com`).

### §3.1 — Request translation: Anthropic → Gemini

Gemini's request body is a `GenerateContentRequest` with these top-level
fields:

```json
{
  "system_instruction": { "parts": [{ "text": "..." }] },
  "contents": [
    {
      "role": "user" | "model",
      "parts": [
        { "text": "..." },
        { "functionCall":   { "name": "...", "args": { ... } } },
        { "functionResponse": { "name": "...", "response": { ... } } }
      ]
    }
  ],
  "tools": [
    {
      "functionDeclarations": [
        { "name": "...", "description": "...", "parameters": { ... } }
      ]
    }
  ],
  "generationConfig": { "maxOutputTokens": N, "temperature": T }
}
```

| Canonical | Gemini | Translation |
|---|---|---|
| `model` | URL path segment | The model name lands in the URL, not the body. |
| `max_tokens` | `generationConfig.maxOutputTokens` | Verbatim. |
| `temperature` | `generationConfig.temperature` | Verbatim. |
| `system` | `system_instruction.parts[0].text` | Single text part. |
| `messages[].role = "user"` | `contents[].role = "user"` | Each `ContentBlock::Text` → `parts[].text`; `ContentBlock::ToolResult` → `parts[].functionResponse.response`. |
| `messages[].role = "assistant"` | `contents[].role = "model"` | Each `ContentBlock::Text` → `parts[].text`; `ContentBlock::ToolUse` → `parts[].functionCall`. |
| `tools[]` | `tools[0].functionDeclarations[]` | All canonical tools collapse into a single `tools` entry whose `functionDeclarations` array carries every declaration. |

### §3.2 — Response translation: Gemini → Anthropic

Gemini's response shape:

```json
{
  "candidates": [
    {
      "content": {
        "role": "model",
        "parts": [ ... ]
      },
      "finishReason": "STOP" | "MAX_TOKENS" | "SAFETY" | "...",
      "index": 0
    }
  ],
  "usageMetadata": {
    "promptTokenCount":     N,
    "candidatesTokenCount": M,
    "totalTokenCount":      N+M
  }
}
```

| Gemini | Canonical | Translation |
|---|---|---|
| `candidates[0].content.parts[]` | `content` | Each part → `ContentBlock`. `text` → `Text`; `functionCall` → `ToolUse { id: synthetic UUID, name, input: args }`. Gemini does not mint tool-call ids; we generate one per call so the canonical `ToolUse.id` is non-empty. |
| `candidates[0].finishReason` | `stop_reason` | Mapped: `"STOP"` → `"end_turn"`, `"MAX_TOKENS"` → `"max_tokens"`, `"SAFETY"` → `"safety"`, others verbatim lowercased. |
| `usageMetadata.promptTokenCount` | `usage.input_tokens` | Verbatim. |
| `usageMetadata.candidatesTokenCount` | `usage.output_tokens` | Verbatim. |
| no Gemini equivalent | `id` | We mint a synthetic id of the form `gemini-resp-<unix_ms>-<rand6>` so audit chains can still key off `MessageResponse.id`. |
| no Gemini equivalent | `model` | Echoed back from the request. |

### §3.3 — Error mapping

Same shape as OpenAI (`ModelError::Upstream { status, body }`).

### §3.4 — Headers

* `Content-Type: application/json`
* `Accept: application/json`
* The planner does **not** include `?key=...` or `Authorization`. The
  gateway injects credentials at egress.

## §4 — `BedrockClient` — Bedrock Runtime `InvokeModel`

**Crate:** `raxis-planner-core` (`src/bedrock_client.rs`)
**Upstream:** `POST /model/<model>/invoke` against
`<base_url>` (region-specific, e.g.
`https://bedrock-runtime.us-east-1.amazonaws.com`).

### §4.1 — Architectural decision: Anthropic-on-Bedrock first

Bedrock hosts Anthropic Claude models with a **near-identical wire
shape** to the direct Anthropic API: the body just adds an
`anthropic_version` field and drops the `model` field (the model is in
the URL path). All other Anthropic Messages API features (tool use,
content blocks, system prompts, usage tokens) are byte-for-byte
identical.

For V2, `BedrockClient` only supports Anthropic-on-Bedrock. The full
`Converse` API (which would unify Claude / Titan / Llama on a single
provider-agnostic shape) lands in V3 alongside the streaming dispatch
work that requires it.

This is why [`provider-model-selection.md §3.4`](provider-model-selection.md) notes "no registry
entries yet" for Bedrock — the model ids will be added as a V3 PR
when `BedrockClient` ships the `Converse` translator.

### §4.2 — Request translation

| Canonical | Bedrock | Translation |
|---|---|---|
| `model` | URL path | The model id lands in `<base_url>/model/<model>/invoke`. The body's `model` field is **omitted**. |
| (everything else) | body | The remainder of the canonical request is serialised verbatim. The `anthropic_version` field is **added** with the constant `"bedrock-2023-05-31"` (Bedrock's required value). |

### §4.3 — Response translation

The Bedrock InvokeModel response is the **same shape** as the
Anthropic Messages API response — same `id`, `content`, `stop_reason`,
`usage` shape — so `BedrockClient` parses directly into the canonical
`MessageResponse`.

### §4.4 — SigV4 — gateway leg

AWS SigV4 request signing **is not done in the planner**. The
`peripherals.md §3.2` credential-injection precedence already routes
all egress through the gateway, and SigV4 is an HMAC-SHA256 signature
over the request body + headers + the AWS access key, generated
**immediately before egress**. Doing it in the planner would require
the planner to hold the AWS access key — exactly the leak the
credential-injection-at-egress design forbids.

For V2 the BedrockClient ships **without** SigV4: the planner POSTs
the unsigned body, and the gateway is expected to:

1. Recognise the destination as `bedrock-runtime.<region>.amazonaws.com`
2. Inject the `Authorization` header by computing SigV4 over the
   inbound body
3. Forward to AWS

This split lands cleanly because:

* The gateway already does credential injection for Anthropic and
  OpenAI (string-based `x-api-key` / `Bearer` injection); SigV4 is
  the same hook with a different signing function.
* The planner-side `BedrockClient` is identical in shape to
  `AnthropicClient` (one POST, one parse), so no translation
  scaffolding is needed.

The gateway-side SigV4 implementation is tracked separately under
`gateway-substrate.md §6.2 "Region-aware credential injection"`. Until
that lands, `BedrockClient` calls succeed only against a gateway built
with the SigV4 plug-in compiled in.

### §4.5 — Error mapping

Same as `AnthropicClient`.

### §4.6 — Headers

* `Content-Type: application/json`
* `Accept: application/json`
* `X-Amz-Target: ` is **not** set (InvokeModel uses RESTful URL routing,
  not the older AWS-JSON RPC pattern).

## §5 — Composition example

The role-binary `main()` constructs the dispatch chain like:

```rust
use raxis_planner_core::{
    AnthropicClient, OpenAiClient,
    RetryConfig, RetryingModelClient,
    FallbackModelClient,
    ModelClient,
};
use std::sync::Arc;

let primary_raw: Arc<dyn ModelClient> =
    Arc::new(AnthropicClient::new("https://api.anthropic.com"));
let primary: Arc<dyn ModelClient> = Arc::new(RetryingModelClient::new(
    primary_raw,
    RetryConfig::fallback_chain_provider_default(),
));

let secondary_raw: Arc<dyn ModelClient> =
    Arc::new(OpenAiClient::new("https://api.openai.com"));
let secondary: Arc<dyn ModelClient> = Arc::new(RetryingModelClient::new(
    secondary_raw,
    RetryConfig::fallback_chain_provider_default(),
));

let chain: Arc<dyn ModelClient> = Arc::new(FallbackModelClient::new(vec![
    primary,
    secondary,
]));
```

`FallbackModelClient::new` applies the production fallback cooldown:
after a provider returns a fallbackable error, later turns skip that
provider for the cooldown window instead of paying that provider's
latency before every secondary attempt. Single-provider deployments keep
`RetryConfig::anthropic_default()` so one transient provider failure can
still retry in place.

The dispatch loop holds `chain: Arc<dyn ModelClient>` and is
provider-agnostic.

## §6 — V3 deferrals

* **Streaming.** V2 ships non-streaming only. The
  `INV-GATEWAY-STREAM-ATOMICITY` invariant is structurally enforced
  because every assistant turn is one buffered response.
* **`Converse` API for Bedrock.** Unifies Claude / Titan / Llama under
  a single Bedrock wire shape; lands in V3 alongside the gateway-side
  SigV4 plug-in.
* **OpenAI `/v1/responses`.** OpenAI's newer "Responses API" with
  built-in tool routing and structured output. V2 ships against
  `chat/completions` for chat-capable models because the canonical type
  is Anthropic-flavoured and `chat/completions` is the closest OpenAI
  mirror. Completion-only models use `/v1/completions` until a
  provider-specific Responses adapter is implemented.
* **Anthropic prompt caching** (`cache_control` field on
  `system` / `user` blocks). V2 emits the field in the request when
  set but does not opt in; the canonical `Usage` shape already exposes
  `cache_read_input_tokens` / `cache_creation_input_tokens` for when
  the planner does start opting in.

## §7 — Test coverage

Each impl ships with:

| Test | What it verifies |
|---|---|
| Wire-shape translation (request) | Round-trip a canonical request through the impl's serializer and assert the resulting JSON matches the spec table. |
| Wire-shape translation (response) | Feed a canned upstream response through the impl's parser and assert the canonical `MessageResponse` matches expected. |
| Error mapping | Drive a 5xx / 4xx / connect-refused failure and assert the right `ModelError` variant lands. |
| Tool-use round-trip | Send a request with a `tool_use` history and a `tool_result`; assert the impl reconstructs the canonical wire shape on the way out and the canonical response shape on the way in. |
| Synthetic id stability (Gemini) | Two distinct calls produce two distinct `id` values (no hidden global state breaks the audit chain's per-event id). |

All tests run under `cargo test -p raxis-planner-core` against
in-process HTTP test servers (`tokio::net::TcpListener` accepting one
request and writing a canned response). No live API calls.

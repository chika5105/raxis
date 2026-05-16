# Prompt caching

> **Status.** Active. Wires Anthropic's prompt-caching feature
> into `planner-core`'s dispatch loop and surfaces equivalent
> cache-hit attribution from every other supported provider
> (Bedrock-via-Anthropic, OpenAI, Gemini).
>
> **Normative invariants.** `INV-PROVIDER-CACHE-WIRE-SHAPE-01`,
> `INV-PROVIDER-CACHE-PARITY-02`,
> `INV-PROVIDER-CACHE-OPT-OUT-BYTE-STABLE-03`,
> `INV-PROVIDER-CACHE-USAGE-FOLD-04` (see
> `specs/invariants.md §11.15`).
>
> **Code surface.**
> `raxis/crates/planner-core/src/model.rs` (canonical types +
> Anthropic native projection),
> `raxis/crates/planner-core/src/bedrock_client.rs` (Bedrock projection),
> `raxis/crates/planner-core/src/openai_client.rs` (OpenAI cache-hit
> attribution), `raxis/crates/planner-core/src/gemini_client.rs`
> (Gemini implicit-cache attribution),
> `raxis/crates/planner-core/src/dispatch.rs` (per-role default
> opt-in).

## Why

Every dispatch session re-renders a large stable prefix on every
turn:

* **Tools.** ~30 KB of tool schemas (`bash`, `read_file`,
  `apply_patch`, …) fixed for the session's lifetime.
* **System prompt.** ~10–40 KB of role NNSP + KSB (operator
  policy, allowed paths, gateway capabilities). Fixed for the
  session's lifetime.
* **Message history.** Grows monotonically across turns; each
  turn's prefix is identical to the last turn's full body.

Without prompt caching, every turn pays the full input-token
price for all of the above (Anthropic Sonnet 4.5: $3 / MTok,
Opus 4.7: $5 / MTok). With prompt caching, those same bytes
cost 10% on cache HITs (Sonnet: $0.30 / MTok, Opus: $0.50 /
MTok) — the typical agentic dispatch loop sees 50–95% cost
reduction on input tokens, plus a measurable latency win
(time-to-first-token improves because the upstream skips
re-encoding the cached prefix).

## Anthropic / Bedrock wire shape

Anthropic prompt caching is opt-in via `cache_control` markers
placed at up to **4 explicit breakpoints** per request, plus an
optional **automatic** breakpoint applied via a top-level
`cache_control` field. The hierarchy is `tools → system →
messages` — a breakpoint at the end of `system` caches both
`tools` and `system`; a breakpoint at the end of `messages`
caches all three.

raxis pins three breakpoints per request when the dispatch loop
opts in (the canonical default for every production session):

```json
{
  "model": "claude-sonnet-4-5-20250929",
  "max_tokens": 4096,
  "system": [
    {
      "type": "text",
      "text": "<role NNSP + KSB>",
      "cache_control": { "type": "ephemeral" }
    }
  ],
  "tools": [
    { "name": "bash", "description": "...", "input_schema": {...} },
    { "name": "read_file", "description": "...", "input_schema": {...} },
    {
      "name": "apply_patch",
      "description": "...",
      "input_schema": {...},
      "cache_control": { "type": "ephemeral" }
    }
  ],
  "messages": [...],
  "cache_control": { "type": "ephemeral" }
}
```

Three slots used (system breakpoint, last-tool breakpoint,
top-level automatic-on-messages), one slot held in reserve for a
future split (e.g. KSB vs. NNSP cache breakpoints).

### TTL

Anthropic exposes two ephemeral TTLs:

| TTL    | `MessageRequest::cache_ttl`    | Cache-write cost | Cache-read cost |
| ------ | ------------------------------ | ---------------- | --------------- |
| 5 min  | `None` (default) / `CacheTtl::Short` | 1.25× base | 0.10× base     |
| 1 hour | `Some(CacheTtl::Long)`         | 2.00× base       | 0.10× base     |

The 5-minute TTL is **refreshed for free** on every cache HIT,
so a steady-state agentic dispatch loop (a turn every few
seconds) effectively pins the cache for the full session
lifetime at the 1.25× write cost. The 1-hour TTL is reserved for
sessions with idle gaps > 5 min between turns (long human
follow-up loops, agentic side-tasks, paused dispatch).

The 5-minute TTL serializes as the bare `{ "type": "ephemeral" }`
shape (no `ttl` field — Anthropic's wire-shape default). The
1-hour TTL serializes as `{ "type": "ephemeral", "ttl": "long" }`.

## Provider parity

Per-provider, the three `cache_*` flags resolve as follows:

| Provider             | `cache_system` | `cache_tools` | `cache_messages` (top-level automatic) | Cache-hit attribution                              |
| -------------------- | -------------- | ------------- | -------------------------------------- | -------------------------------------------------- |
| Anthropic (native)   | wire           | wire          | wire                                   | `usage.cache_read_input_tokens`                    |
| Anthropic-on-Bedrock | wire           | wire          | **suppressed**                         | `usage.cache_read_input_tokens`                    |
| OpenAI               | ignored        | ignored       | ignored                                | `usage.prompt_tokens_details.cached_tokens` (auto) |
| Gemini               | ignored        | ignored       | ignored                                | `usageMetadata.cachedContentTokenCount` (implicit) |

### Why Bedrock suppresses `cache_messages`

AWS Bedrock proxies the Anthropic Messages API verbatim with
two deltas (`anthropic_version` field, `model` lifted to URL
path) — **and** Bedrock + Vertex AI do NOT support Anthropic's
**automatic-caching** rule (top-level `cache_control`). Per-block
breakpoints (`system`, last-tool) work identically. Emitting a
top-level `cache_control` against Bedrock would be silently
ignored upstream; suppressing it at projection time keeps the
wire shape Bedrock-valid.

### Why OpenAI / Gemini ignore the opt-in

OpenAI and Gemini both do prompt caching **automatically** on
prompts above a model-dependent floor (~1024 tokens) — there is
no opt-in field on the request side. The only operator-observable
signal is the cache-hit count in the response's usage block:

* OpenAI: `usage.prompt_tokens_details.cached_tokens` (gpt-4o,
  gpt-4o-mini, o1-*, o3-* — the field is absent on older models).
* Gemini 2.5+: `usageMetadata.cachedContentTokenCount`. Gemini
  also offers **explicit context caching** via the separate
  `cachedContents` resource lifecycle (pre-create cache, then
  reference by name in subsequent requests); that path requires
  gateway-side resource management and is intentionally out of
  scope for the planner-core opt-in (see "Future work" below).

Both providers fold their respective cache-hit count into
canonical `Usage::cache_read_input_tokens` so the dispatch loop's
budget accounting is provider-agnostic.

## Per-role defaults

The dispatch loop opts into all three flags by default in both
the buffered (`DispatchLoop::run`) and streaming
(`DispatchLoop::run_streaming`) paths:

```rust
let req = MessageRequest {
    model:          self.config.model.clone(),
    max_tokens:     self.config.max_tokens,
    system:         Some(system_prompt),
    messages:       vec![Message { role: "user", content: ... }],
    tools:          self.registry.to_specs(),
    temperature:    self.config.temperature,
    stream:         false, // or true on the streaming path
    cache_system:   true,
    cache_tools:    true,
    cache_messages: true,
    cache_ttl:      None, // 5-minute ephemeral, refreshed for free
};
```

Rationale: the system prompt + tool definitions are **stable per
session**, the message history grows **monotonically**, and the
5-min TTL refreshes for free on every cache HIT — the canonical
high-cache-hit-rate shape Anthropic recommends. There is no
per-role variation (executor / orchestrator / reviewer all
benefit identically).

## Opt-out is byte-stable

When all three cache flags are `false` (the
`MessageRequest::default()` shape and the earlier behavior),
the serialized request body is byte-identical to the legacy
wire shape:

* `system` serializes as a bare JSON string (not a block array).
* No `ToolSpec` carries `cache_control`.
* No top-level `cache_control` key.

This pin is enforced by `INV-PROVIDER-CACHE-OPT-OUT-BYTE-STABLE-03`
and witnessed by
`message_request_no_cache_flags_emits_legacy_wire_shape` in
`raxis/crates/planner-core/src/model.rs`. Every existing call
site that has not opted into caching sees zero on-the-wire delta.

## Cumulative budget fold

`INV-PROVIDER-CACHE-USAGE-FOLD-04` requires that
`MessageResponse::usage.cache_read_input_tokens` AND
`usage.cache_creation_input_tokens` count against the dispatch
loop's per-session input-token ceiling
(`DispatchConfig::max_tokens_input_total`) exactly the same way
uncached `usage.input_tokens` do. The in-code fold is:

```rust
cum_in = cum_in.saturating_add(
    u64::from(input_tokens)
        .saturating_add(u64::from(cache_creation_input_tokens))
        .saturating_add(u64::from(cache_read_input_tokens))
);
```

(See `raxis/crates/planner-core/src/dispatch.rs` lines folding
the `Usage` struct after every turn, both buffered and
streaming.)

Cache reads cost 10× less per token than uncached, but they are
NOT free, and they still count against the provider's rate-limit
budget. The fold also defends against a caching-on regression:
if the upstream silently stops caching (MISSes that should have
HIT), the cumulative counter trips
`DispatchOutcome::TokensExceeded` instead of letting the cost
balloon silently.

## Tracking cache performance in production

Per-turn cache attribution flows through the canonical `Usage`
struct on every `MessageResponse`. Operator-side telemetry
should derive:

* **Cache hit rate**:
  `cache_read_input_tokens / (cache_read_input_tokens + cache_creation_input_tokens + input_tokens)`
  per session. A healthy steady-state dispatch loop sees ≥0.7
  on Anthropic / Bedrock after the first turn.
* **Per-token cost**:
  weighted average of base price (`input_tokens`), 1.25× base
  (`cache_creation_input_tokens` for 5-min TTL — or 2× for
  1-hour), and 0.10× base (`cache_read_input_tokens`).
* **Cache effectiveness**: track turn-over-turn ratio of
  `cache_read_input_tokens` to detect when a tool-definition
  drift or KSB-shape drift is invalidating the cache silently.

## Future work

* **Gemini explicit context caching.** Pre-create a
  `cachedContents` resource via the Generative Language API,
  then reference by name on subsequent requests. Requires
  gateway-side cache-resource lifecycle management. Out of
  scope for.
* **Sidecar protocol forwarding.** The `SidecarRequest` shape
  in `crates/planner-core/src/sidecar_client.rs` does NOT
  currently forward the `cache_*` flags; sidecars are
  pass-through gateways and the underlying real provider
  handles caching today. A future iter could add explicit
  forwarding so a sidecar can apply provider-specific
  optimization (e.g. routing decisions based on cache
  expectation).
* **Per-role TTL tuning.** Reviewer sessions are short-lived
  (<2 min typical); they will rarely benefit from the 1-hour
  TTL. Executor sessions can span >5 min in steady state and
  could benefit. A follow-up could expose `cache_ttl` as a
  per-role config knob in `DispatchConfig`.
* **4th breakpoint reservation.** Anthropic allows up to 4
  explicit breakpoints; raxis uses 3 (system, last-tool,
  top-level automatic). The 4th slot is reserved for a future
  KSB-vs-NNSP split if the system prompt grows enough to
  warrant separate cache breakpoints for the two halves.

## References

* `specs/invariants.md §11.15` — `INV-PROVIDER-CACHE-*`.
* Anthropic prompt caching docs:
  <https://platform.claude.com/docs/en/build-with-claude/prompt-caching>
* OpenAI prompt caching docs:
  <https://platform.openai.com/docs/guides/prompt-caching>
* Gemini context caching (implicit + explicit):
  <https://ai.google.dev/gemini-api/docs/caching>
* AWS Bedrock prompt caching:
  <https://docs.aws.amazon.com/bedrock/latest/userguide/prompt-caching.html>

# Worker 2 (planner-core) — coordination notes

## IPC reporting (Worker 1, `crates/types/`)

`raxis_types::TokensReport` already carries `cache_read_tokens: u64`
and `cache_creation_tokens: u64` (both `#[serde(default)]`). No
schema change needed in `crates/types/`. As of this commit the
planner-core `driver` populates both fields from
`DispatchLoop::last_cumulative_cache_{creation,read}_tokens()` at
terminal-intent submission time, so every outbound
`IntentRequest::tokens_used` now carries the cumulative cache
counts the kernel needs to fold into
`tasks.cumulative_cache_{creation,read}_tokens`
(`INV-OBSERVABILITY-CACHE-TOKEN-PERSISTED-01`).

**Worker 1 action item:** when wiring the new SQLite columns at
`CompleteTask` commit time, read `tokens_used.cache_read_tokens`
and `tokens_used.cache_creation_tokens` off the IPC envelope —
they will be non-zero whenever the model client surfaced the
counters (Anthropic / Bedrock streaming + buffered paths; OpenAI /
Gemini still report 0 because their `Usage` payloads do not
expose cache breakdown).

## Per-turn structured stderr (kernel-side scraper)

The new `planner_turn_usage` lines emit one JSON line per turn to
the planner binary's stderr (which the kernel pipes into
`kernel.stderr.log` via the session-spawn substrate). Wire shape:

```json
{"event":"planner_turn_usage","task_id":"...","session_id":"...",
 "role":"executor","model":"claude-sonnet-4-5-20250929","turn":0,
 "input_tokens":10,"output_tokens":20,
 "cache_creation_input_tokens":300,"cache_read_input_tokens":4000,
 "cache_hit_ratio":0.928,"cumulative_input_tokens":4310,
 "cumulative_output_tokens":20}
```

Kernel-side scrapers / dashboard panels can `serde_json::from_str`
each line directly. The shape is pinned by the
`planner_turn_usage_log_shape` witness test in
`crates/planner-core/src/dispatch.rs#tests`.

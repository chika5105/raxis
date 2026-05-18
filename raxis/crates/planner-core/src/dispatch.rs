//! Dispatch loop — drives the
//! `LLM → parse tool_use → execute → return result` cycle every
//! planner-role binary runs at steady state.
//!substep "Tool-dispatch loop".
//! ## Loop shape
//! ```text
//!   1. Render the system prompt (KSB + role NNSP).         once-per-session
//!   2. Append the role-specific seed user message.         once-per-session
//!   3. Loop:
//!      a. Call the model.                                  one round-trip
//!      b. Walk the response's content blocks:
//!         - Text       → log to audit, optionally surface
//!                        in the conversation history.
//!         - ToolUse    → look up tool in the registry,
//!                        validate input against schema,
//!                        execute, append a ToolResult to
//!                        the next turn's user message.
//!         - Other      → ignored (forward-compat for
//!                        Anthropic schema additions).
//!      c. Append the model's full assistant turn to the
//!         conversation history.
//!      d. If the model emitted no tool_use blocks AND
//!         stop_reason ∉ {`tool_use`}, the turn is terminal
//! return [`DispatchOutcome::Idle`] and let the
//!         caller decide whether to re-run with a follow-up
//!         user message or exit cleanly.
//!      e. If a terminal-tool fired (e.g. `task_complete`,
//!         `submit_review`), short-circuit with the tool's
//!         output as the loop's final value.
//!   4. Bound the loop by a max-iteration ceiling.
//! ```
//! ## V2 limits (declared so future work has a target)
//! * **No streaming.** The dispatch loop reads one full
//!   `MessageResponse` per turn before invoking tools. Streaming
//!   tool-use events require a different parsing shape and is
//!   deferred to a future iteration.
//! * **No parallel tool execution.** Tools execute sequentially in
//!   the order Anthropic emitted them. Parallel execution requires
//!   per-tool capability flags + a per-tool-result correlation
//!   shape that is not yet wired.
//! * **No mid-turn cancellation.** A wedged tool blocks the loop;
//!   the per-tool deadline ([`crate::ToolContext::deadline`]) is
//!   the only safety net. Future work: wrap each tool call in a
//!   `tokio::select!` with a parent cancellation token.

use std::sync::Arc;
use std::time::Duration;

use thiserror::Error;

use crate::model::{
    ContentBlock, Message, MessageRequest, MessageResponse, ModelClient, ModelError, Usage,
};
use crate::tools::{ToolContext, ToolError, ToolOutput, ToolRegistry};

// ---------------------------------------------------------------------------
// `INV-OBSERVABILITY-CACHE-TOKEN-EMITTED-01` — per-turn cache-token
// telemetry emitter.
// iter62 forensics: kernel.stderr.log carried zero mentions of
// `cache_creation_input_tokens` / `cache_read_input_tokens` even
// though the dispatch loop reads both fields (folding them into
// `cum_in` for ceiling enforcement). Anthropic's billing dashboard
// reported "Prompt caching: Not enabled" — but with zero on-the-wire
// telemetry we could neither confirm the report nor refute it.
// The wire shape is correct (see `MessageRequest::serialize` in
// `crate::model` — it stamps `cache_control` per
// `prompt-caching.md`); the bug was a pure observability gap.
// `emit_turn_usage` closes it by writing one structured JSON line
// per turn to `out` (`stderr` in production paths, a `Vec<u8>` in
// tests). Pairs with
// `INV-OBSERVABILITY-CACHE-TOKEN-PERSISTED-01` which folds the same
// per-turn counts into `tasks.cumulative_cache_creation_tokens` /
// `cumulative_cache_read_tokens` at `CompleteTask` commit time.
// ---------------------------------------------------------------------------

/// Emit a single `planner_turn_usage` JSON line to `out`. Called
/// from both [`DispatchLoop::run`] and [`DispatchLoop::run_streaming`]
/// after each turn's `Usage` has been destructured but **before**
/// the running `cum_in` / `cum_out` totals fold the new counts in,
/// so the `cumulative_*` fields on the line carry the **post-fold**
/// values (i.e. what the kernel would observe after this turn).
/// The line is intentionally formatted by hand with `writeln!`
/// rather than via `serde_json::to_writer` so the emit path stays
/// allocation-free on the hot loop and so the wire shape is
/// trivially auditable from this one function (no serializer-level
/// renames or skip_if_default surprises).
/// `cache_hit_ratio` is `cache_read / (cache_read + input + cache_creation)`.
/// Returns `0.0` when the denominator is zero (no input charged
/// at all on this turn — defensive against providers that emit a
/// `Usage` with all-zero counters).
#[allow(clippy::too_many_arguments)]
pub(crate) fn emit_turn_usage(
    out: &mut dyn std::io::Write,
    task_id: &str,
    session_id: &str,
    role: &str,
    model: &str,
    turn: u32,
    input_tokens: u32,
    output_tokens: u32,
    cache_creation_input_tokens: u32,
    cache_read_input_tokens: u32,
    cum_in_so_far: u64,
    cum_out_so_far: u64,
) {
    let denom = u64::from(cache_read_input_tokens)
        .saturating_add(u64::from(input_tokens))
        .saturating_add(u64::from(cache_creation_input_tokens));
    let cache_hit_ratio = if denom == 0 {
        0.0_f64
    } else {
        // `f64::from(u32)` is lossless. The denominator fits 33
        // bits worst case (3 × u32::MAX) so the upcast through
        // `denom as f64` is also lossless for any plausible
        // single-turn count (Anthropic's per-call hard cap is
        // < 2^25 tokens).
        f64::from(cache_read_input_tokens) / (denom as f64)
    };
    let cum_in_after = cum_in_so_far
        .saturating_add(u64::from(input_tokens))
        .saturating_add(u64::from(cache_creation_input_tokens))
        .saturating_add(u64::from(cache_read_input_tokens));
    let cum_out_after = cum_out_so_far.saturating_add(u64::from(output_tokens));
    // `{:?}` on `&str` produces a JSON-compatible double-quoted
    // string with escaping — the kernel-side log scraper relies
    // on `serde_json::from_str` round-tripping this line, so the
    // quote-and-escape contract MUST go through `Debug` rather
    // than ad-hoc concatenation. (Confirmed by the witness test
    // `planner_turn_usage_log_shape` which `serde_json::from_slice`s
    // the captured bytes.)
    let _ = writeln!(
        out,
        "{{\"event\":\"planner_turn_usage\",\
\"task_id\":{:?},\
\"session_id\":{:?},\
\"role\":{:?},\
\"model\":{:?},\
\"turn\":{},\
\"input_tokens\":{},\
\"output_tokens\":{},\
\"cache_creation_input_tokens\":{},\
\"cache_read_input_tokens\":{},\
\"cache_hit_ratio\":{},\
\"cumulative_input_tokens\":{},\
\"cumulative_output_tokens\":{}}}",
        task_id,
        session_id,
        role,
        model,
        turn,
        input_tokens,
        output_tokens,
        cache_creation_input_tokens,
        cache_read_input_tokens,
        cache_hit_ratio,
        cum_in_after,
        cum_out_after,
    );
}

// ---------------------------------------------------------------------------
// DispatchConfig + DispatchError + DispatchOutcome
// ---------------------------------------------------------------------------

/// Per-session dispatch knobs. The role binary's `main` reads these
/// from the kernel-stamped env (`RAXIS_MODEL_ID`, etc.) and from
/// the policy-derived per-task budgets, then constructs one
/// [`DispatchLoop`] per session.
#[derive(Debug, Clone)]
pub struct DispatchConfig {
    /// Anthropic model id (e.g. `"claude-sonnet-4-5-20250929"`).
    pub model: String,
    /// Hard cap on assistant turns. Per
    /// `planner-harness.md §INV-PLANNER-HARNESS-04`, every dispatch
    /// loop MUST surface a structured terminal outcome before this
    /// ceiling so an infinite-loop model cannot consume the operator's
    /// token budget unbounded.
    pub max_turns: u32,
    /// Per-turn LLM `max_tokens` budget. Bounded by the policy-side
    /// `[providers.X] max_tokens_per_request` ceiling.
    pub max_tokens: u32,
    /// Sampling temperature. None ⇒ Anthropic default (1.0).
    pub temperature: Option<f32>,
    /// Per-tool deadline. Planner-side bound; the kernel-side budget
    /// is enforced separately.
    pub tool_deadline: Option<Duration>,
    /// coarse per-session cumulative *input* token
    /// ceiling (counts every Anthropic `usage.input_tokens` +
    /// `cache_creation_input_tokens` + `cache_read_input_tokens`).
    /// `None` ⇒ uncapped (matches plan.toml default — strict-by-
    /// default policy emits `WARN_UNCAPPED_TOKEN_LIMIT` at
    /// `approve_plan`; the dispatch loop itself does not duplicate
    /// that warning here).
    /// When the cumulative input-token total *after* a turn exceeds
    /// this ceiling, the loop terminates with
    /// [`DispatchOutcome::TokensExceeded`] before issuing the next
    /// model call. The role binary surfaces this as a structured
    /// failure (`ReportFailure` on the executor; review-aborted on
    /// the reviewer).
    pub max_tokens_input_total: Option<u64>,
    /// coarse per-session cumulative *output* token
    /// ceiling (counts every Anthropic `usage.output_tokens`).
    /// `None` ⇒ uncapped.
    pub max_tokens_output_total: Option<u64>,
    /// coarse per-session cumulative *combined* token
    /// ceiling (input + output). `None` ⇒ uncapped. Cheaper to set
    /// when an operator only cares about total spend rather than
    /// the input/output split.
    pub max_tokens_total: Option<u64>,
    /// `INV-OBSERVABILITY-CACHE-TOKEN-EMITTED-01` — task id stamped
    /// onto every `planner_turn_usage` stderr line so the kernel
    /// can correlate per-turn cache telemetry with the task that
    /// drove it. Empty / `"<unknown>"` for sessions that do not
    /// carry a task id (orchestrator) or for fixtures that did
    /// not stamp it. The driver populates this field from
    /// [`crate::BootArgs::task_id`].
    pub task_id_for_logs: String,
    /// `INV-OBSERVABILITY-CACHE-TOKEN-EMITTED-01` — session token
    /// stamped onto every `planner_turn_usage` line. Same fallback
    /// rules as `task_id_for_logs`. Driver populates from
    /// [`crate::BootEnv::session_token`].
    pub session_id_for_logs: String,
    /// `INV-OBSERVABILITY-CACHE-TOKEN-EMITTED-01` — role shortname
    /// (`"executor"` / `"reviewer"` / `"orchestrator"`) stamped
    /// onto every `planner_turn_usage` line. Driver populates from
    /// [`crate::Role::shortname`].
    pub role_for_logs: String,
}

impl DispatchConfig {
    /// Sensible default for production reviewer / executor. Callers
    /// override per role + per task.
    /// `max_turns = 100` mirrors
    /// [`crate::driver::DEFAULT_PLANNER_MAX_TURNS`]. See that
    /// constant's doc-comment for the rationale (Live-e2e
    /// realistic-scenario `credential-substitution-canary` tripped
    /// the original `20` ceiling, `materialize-records` tripped the
    /// `50` follow-up ceiling on the two-fanout
    /// postgres-plus-mongo path in iter31).
    pub fn new(model: impl Into<String>) -> Self {
        Self {
            model: model.into(),
            max_turns: 100,
            max_tokens: 4096,
            temperature: Some(0.7),
            tool_deadline: Some(Duration::from_secs(120)),
            max_tokens_input_total: None,
            max_tokens_output_total: None,
            max_tokens_total: None,
            // `INV-OBSERVABILITY-CACHE-TOKEN-EMITTED-01` — placeholder
            // values used when a fixture / orchestrator session does
            // not stamp a real id. Production callers (the planner
            // driver) overwrite all three immediately after
            // construction.
            task_id_for_logs: "<unknown>".to_owned(),
            session_id_for_logs: "<unknown>".to_owned(),
            role_for_logs: "<unknown>".to_owned(),
        }
    }

    /// `INV-OBSERVABILITY-CACHE-TOKEN-EMITTED-01` — read accessor
    /// the dispatch loop uses when emitting `planner_turn_usage`
    /// lines. Returns `&str` so the formatter can `{:?}`-quote it
    /// (matching the JSON-line shape) without reallocating.
    pub fn task_id_for_logs(&self) -> &str {
        &self.task_id_for_logs
    }

    /// See [`Self::task_id_for_logs`].
    pub fn session_id_for_logs(&self) -> &str {
        &self.session_id_for_logs
    }

    /// See [`Self::task_id_for_logs`].
    pub fn role_for_logs(&self) -> &str {
        &self.role_for_logs
    }
}

/// One dispatch-loop terminal outcome.
/// Every variant carries the cumulative `(input_tokens,
/// output_tokens)` totals consumed by the loop so the role binary
/// can stamp them onto its outbound `IntentRequest::tokens_used`
/// per V2 (per-intent token reporting).
/// The `TokensExceeded` variant retains its dedicated counters for
/// audit clarity (which ceiling tripped); they are identical in
/// value to the `cum_*` pair on that variant.
#[derive(Debug, Clone)]
pub enum DispatchOutcome {
    /// A terminal tool fired (e.g. `task_complete` /
    /// `submit_review`). The loop short-circuits with the tool's
    /// output.
    TerminalTool {
        /// Name of the tool that fired the terminal stop.
        tool_name: String,
        /// The tool's input as the model emitted it. Round-tripped
        /// to the dispatch caller so the caller can convert it into
        /// the matching IPC intent (see [`crate::intent`]).
        input: serde_json::Value,
        /// Tool's output.
        output: ToolOutput,
        /// V2 §2.5 — cumulative input tokens at the moment the
        /// terminal tool fired (across every model turn the loop
        /// drove). May be 0 when the terminal tool fired on the
        /// very first model turn before any input was charged.
        cum_input_tokens: u64,
        /// V2 §2.5 — cumulative output tokens at the moment the
        /// terminal tool fired.
        cum_output_tokens: u64,
    },
    /// The model said it was done (`stop_reason = "end_turn"`) and
    /// emitted no tool_use blocks. The caller decides whether to
    /// inject a new user message or exit cleanly.
    Idle {
        /// Final assistant text content (joined across all `Text`
        /// blocks in the last turn).
        final_text: String,
        /// V2 §2.5 — cumulative input tokens at idle.
        cum_input_tokens: u64,
        /// V2 §2.5 — cumulative output tokens at idle.
        cum_output_tokens: u64,
    },
    /// Hit the `max_turns` ceiling. INV-PLANNER-HARNESS-04 surfaces
    /// this as a structured failure on the role binary side.
    MaxTurnsExceeded {
        /// Number of turns the loop ran.
        turns: u32,
        /// V2 §2.5 — cumulative input tokens at the moment the
        /// turn ceiling fired.
        cum_input_tokens: u64,
        /// V2 §2.5 — cumulative output tokens at the moment the
        /// turn ceiling fired.
        cum_output_tokens: u64,
    },
    /// cumulative session token total exceeded one of
    /// the configured per-session ceilings. The loop terminates
    /// post-turn (the model already returned the offending response;
    /// the loop just refuses to issue the next request). Role
    /// binaries surface this as a structured `ReportFailure`
    /// (executor) or `submit_review { rejected, reason: "tokens
    /// exhausted" }` (reviewer).
    TokensExceeded {
        /// Stable-wire short string identifying which ceiling fired.
        /// One of: `"input"`, `"output"`, `"total"`. Maps directly
        /// to the policy/plan keys from `token-limit-enforcement.md
        /// §2 Coarse table` (`max_tokens_input_total`,
        /// `max_tokens_output_total`, `max_tokens_total`).
        which: &'static str,
        /// Cumulative input tokens consumed across all turns so far.
        input_tokens: u64,
        /// Cumulative output tokens consumed across all turns.
        output_tokens: u64,
        /// Configured ceiling that was hit (so the role binary can
        /// surface a clean operator-facing message).
        ceiling: u64,
    },
}

impl DispatchOutcome {
    /// Cumulative `(input_tokens,
    /// output_tokens)` projection across every variant. Used by the
    /// driver to stamp `IntentRequest::tokens_used` regardless of
    /// which terminal arm fired.
    pub fn cumulative_tokens(&self) -> (u64, u64) {
        match self {
            DispatchOutcome::TerminalTool {
                cum_input_tokens,
                cum_output_tokens,
                ..
            }
            | DispatchOutcome::Idle {
                cum_input_tokens,
                cum_output_tokens,
                ..
            }
            | DispatchOutcome::MaxTurnsExceeded {
                cum_input_tokens,
                cum_output_tokens,
                ..
            } => (*cum_input_tokens, *cum_output_tokens),
            DispatchOutcome::TokensExceeded {
                input_tokens,
                output_tokens,
                ..
            } => (*input_tokens, *output_tokens),
        }
    }
}

/// Terminal error surfaced by `DispatchLoop::next`; either the model client
/// failed (HTTP, rate-limit, malformed JSON) or a tool implementation reported
/// a hard error.  The caller maps these onto an `IntentKind::Failure` and ends
/// the run.
#[derive(Debug, Error)]
pub enum DispatchError {
    /// Upstream model client failure (HTTP, JSON parse, rate-limit, ...).
    #[error("model error: {0}")]
    Model(#[from] ModelError),
    /// Tool execution reported a non-recoverable error.
    #[error("tool error: {0}")]
    Tool(#[from] ToolError),
}

// ---------------------------------------------------------------------------
// DispatchLoop
// ---------------------------------------------------------------------------

/// The per-session dispatch state. One per planner role binary
/// instance. Holds:
/// * The model client (`Arc<dyn ModelClient>`) — swappable for
///   tests via [`crate::model::MockModelClient`].
/// * The role-specific tool registry.
/// * Static per-session config (model id, max_turns, ...).
/// * The per-task tool context (workspace root, deadline).
///   Dispatch is started by [`DispatchLoop::run`] which takes the
///   initial system prompt + initial user message and runs to a
///   terminal outcome.
pub struct DispatchLoop {
    model: Arc<dyn ModelClient>,
    registry: Arc<ToolRegistry>,
    config: DispatchConfig,
    ctx: ToolContext,
    /// Names of tools that, when invoked, terminate the loop with
    /// [`DispatchOutcome::TerminalTool`]. Populated by the role
    /// binary via [`DispatchLoop::with_terminal_tools`]; default is
    /// empty (the loop terminates only on `Idle` or `MaxTurnsExceeded`).
    terminal_tools: Vec<&'static str>,
    /// `INV-OBSERVABILITY-CACHE-TOKEN-PERSISTED-01` — running fold
    /// of `Usage::cache_creation_input_tokens` across every turn of
    /// the most recent `run` / `run_streaming` invocation. Reset to
    /// 0 at the top of each call. Exposed via
    /// [`Self::last_cumulative_cache_creation_tokens`] so the
    /// driver can stamp it onto the outbound
    /// [`raxis_types::TokensReport::cache_creation_tokens`] field
    /// at terminal-intent submission time. Tracked separately from
    /// the dispatch loop's `cum_in` (which folds cache + non-cache
    /// input tokens together for ceiling-enforcement purposes) so
    /// the kernel-side per-task SQLite columns
    /// (`tasks.cumulative_cache_creation_tokens` /
    /// `cumulative_cache_read_tokens`) get an unmuddied count.
    cum_cache_creation_input_tokens: u64,
    /// See [`Self::cum_cache_creation_input_tokens`]. Same shape /
    /// reset semantics, but folds
    /// `Usage::cache_read_input_tokens`.
    cum_cache_read_input_tokens: u64,
}

impl DispatchLoop {
    /// Construct a new dispatch loop. The role binary supplies all
    /// four slots up front; the loop is `&mut self` so two
    /// concurrent calls on one instance is a build-time error.
    pub fn new(
        model: Arc<dyn ModelClient>,
        registry: Arc<ToolRegistry>,
        config: DispatchConfig,
        ctx: ToolContext,
    ) -> Self {
        Self {
            model,
            registry,
            config,
            ctx,
            terminal_tools: Vec::new(),
            cum_cache_creation_input_tokens: 0,
            cum_cache_read_input_tokens: 0,
        }
    }

    /// `INV-OBSERVABILITY-CACHE-TOKEN-PERSISTED-01` — cumulative
    /// `cache_creation_input_tokens` across the most recent
    /// `run` / `run_streaming` invocation. Returns 0 before the
    /// first call. The driver reads this after the dispatch loop
    /// terminates and stamps it onto the outbound
    /// [`raxis_types::TokensReport::cache_creation_tokens`] field.
    pub fn last_cumulative_cache_creation_tokens(&self) -> u64 {
        self.cum_cache_creation_input_tokens
    }

    /// See [`Self::last_cumulative_cache_creation_tokens`]. Folds
    /// `cache_read_input_tokens` instead.
    pub fn last_cumulative_cache_read_tokens(&self) -> u64 {
        self.cum_cache_read_input_tokens
    }

    /// Declare which tool names short-circuit the loop. The role
    /// binary calls this once at construction:
    /// * Executor:    `["task_complete", "report_failure"]`
    /// * Reviewer:    `["submit_review"]`
    /// * Orchestrator: `["activate_subtask", "integration_merge", "complete_initiative"]`
    pub fn with_terminal_tools(mut self, names: Vec<&'static str>) -> Self {
        self.terminal_tools = names;
        self
    }

    /// Drive one dispatch session to a terminal outcome.
    /// `system_prompt` is the rendered KSB + role NNSP (see
    /// [`raxis_ksb`] and `kernel-mechanics-prompt.md`).
    /// `seed_user_text` is the role-specific seed message (e.g.
    /// "You are working on task task-42; the goal is …").
    pub async fn run(
        &mut self,
        system_prompt: String,
        seed_user_text: String,
    ) -> Result<DispatchOutcome, DispatchError> {
        // Build the request once and mutate `req.messages` in place
        // between turns. The previous shape constructed a fresh
        // `MessageRequest` per iteration and cloned `messages`,
        // `tool_specs`, `system_prompt`, and `model` every time. The
        // wire shape (`MessageRequest`) owns the conversation history
        // directly, so making the request the canonical owner of
        // `messages` removes those clones without changing the
        // `&MessageRequest` shape `ModelClient::create_message`
        // expects. The append-after-call semantics are preserved
        // exactly: the assistant turn and any tool_result reply are
        // pushed onto `req.messages` between calls, matching the
        // pre-refactor `messages` Vec mutations.
        let mut req = MessageRequest {
            model: self.config.model.clone(),
            max_tokens: self.config.max_tokens,
            system: Some(system_prompt),
            messages: vec![Message {
                role: "user".to_owned(),
                content: vec![ContentBlock::Text {
                    text: seed_user_text,
                }],
            }],
            tools: self.registry.to_specs(),
            temperature: self.config.temperature,
            stream: false,
            // `prompt-caching.md §"Per-role defaults"` — every
            // dispatch session's tools + system + growing message
            // history are the canonical cache-write targets.
            // Anthropic / Bedrock honor these flags via the wire
            // shape projection in `MessageRequest::Serialize`;
            // OpenAI / Gemini ignore them and rely on upstream
            // automatic / implicit caching, surfacing the cache
            // hit count through `Usage::cache_read_input_tokens`.
            cache_system: true,
            cache_tools: true,
            cache_messages: true,
            cache_ttl: None, // 5-minute ephemeral, refreshed for free
        };

        // cumulative session token totals. Updated
        // post-turn from `MessageResponse::usage` and checked against
        // the per-session ceilings before issuing the next request.
        let mut cum_in: u64 = 0;
        let mut cum_out: u64 = 0;
        // `INV-OBSERVABILITY-CACHE-TOKEN-PERSISTED-01` — reset the
        // cumulative cache trackers so a `DispatchLoop` reused
        // across calls (currently only test fixtures) starts each
        // run with a clean slate. Production binaries spawn a
        // fresh loop per session so this reset is defensive.
        self.cum_cache_creation_input_tokens = 0;
        self.cum_cache_read_input_tokens = 0;

        for turn in 0..self.config.max_turns {
            let resp = self.model.create_message(&req).await?;
            // fold this turn's `Usage` into the
            // running totals before any other side effect, so a
            // ceiling that fires post-turn still records the call.
            let Usage {
                input_tokens,
                output_tokens,
                cache_creation_input_tokens,
                cache_read_input_tokens,
            } = resp.usage;

            // `INV-OBSERVABILITY-CACHE-TOKEN-EMITTED-01` — emit the
            // structured per-turn cache telemetry line BEFORE the
            // cum_in / cum_out fold. The helper computes the
            // post-fold projection internally so the operator sees
            // the same `cumulative_*` values the next ceiling
            // check will operate on.
            emit_turn_usage(
                &mut std::io::stderr().lock(),
                self.config.task_id_for_logs(),
                self.config.session_id_for_logs(),
                self.config.role_for_logs(),
                &self.config.model,
                turn,
                input_tokens,
                output_tokens,
                cache_creation_input_tokens,
                cache_read_input_tokens,
                cum_in,
                cum_out,
            );

            cum_in = cum_in.saturating_add(
                u64::from(input_tokens)
                    .saturating_add(u64::from(cache_creation_input_tokens))
                    .saturating_add(u64::from(cache_read_input_tokens)),
            );
            cum_out = cum_out.saturating_add(u64::from(output_tokens));
            // `INV-OBSERVABILITY-CACHE-TOKEN-PERSISTED-01` — fold
            // the cache-only counts onto the dispatch loop's
            // dedicated trackers so the driver can stamp them
            // separately onto `TokensReport.cache_*_tokens` after
            // the loop terminates (the kernel's per-task SQLite
            // columns want the cache-only fold, not the combined
            // `cum_in` total used for ceiling enforcement).
            self.cum_cache_creation_input_tokens = self
                .cum_cache_creation_input_tokens
                .saturating_add(u64::from(cache_creation_input_tokens));
            self.cum_cache_read_input_tokens = self
                .cum_cache_read_input_tokens
                .saturating_add(u64::from(cache_read_input_tokens));

            // Enforce the per-session
            // token caps BEFORE inspecting the response for terminal
            // tools / Idle. The earlier version of this check sat
            // below the `Idle` and `TerminalTool` early returns,
            // which meant a session that crossed the cap on its
            // FINAL turn never surfaced `TokensExceeded` —
            // operators would see `Idle { final_text }` and the
            // budget gate would silently no-op. Promoting the check
            // here keeps the contract tight: every cap that is hit
            // reaches the role binary as a `TokensExceeded` outcome,
            // regardless of whether the model also tried to end the
            // turn.
            if let Some(exceeded) = self.check_ceilings(cum_in, cum_out) {
                return Ok(exceeded);
            }

            // Append the assistant turn to the history (verbatim so
            // tool_use blocks correlate with our tool_result reply).
            req.messages.push(Message {
                role: "assistant".to_owned(),
                content: resp.content.clone(),
            });

            // Walk content blocks: collect all tool_use, also
            // collect joined text for Idle reporting.
            let mut tool_uses: Vec<(String, String, serde_json::Value)> = Vec::new();
            let mut text_acc = String::new();
            for block in &resp.content {
                match block {
                    ContentBlock::Text { text } => {
                        if !text_acc.is_empty() {
                            text_acc.push('\n');
                        }
                        text_acc.push_str(text);
                    }
                    ContentBlock::ToolUse { id, name, input } => {
                        tool_uses.push((id.clone(), name.clone(), input.clone()));
                    }
                    ContentBlock::ToolResult { .. } | ContentBlock::Other(_) => {}
                }
            }

            if tool_uses.is_empty() {
                // No tools called — either Idle or MaxTurns will fire.
                return Ok(DispatchOutcome::Idle {
                    final_text: text_acc,
                    cum_input_tokens: cum_in,
                    cum_output_tokens: cum_out,
                });
            }

            // Execute each tool_use in declaration order, building
            // one composite user message with the matching
            // tool_result blocks.
            let mut next_user_blocks: Vec<ContentBlock> = Vec::with_capacity(tool_uses.len());
            for (tu_id, tool_name, input) in &tool_uses {
                // Terminal tool? Short-circuit with the model's input.
                if self.terminal_tools.contains(&tool_name.as_str()) {
                    // Execute the terminal tool one last time so its
                    // output is observable + auditable BEFORE we
                    // return. If the terminal tool isn't registered
                    // (e.g. in tests), surface an Idle outcome with
                    // the last text, NOT a hard error — the caller
                    // can synthesize the IPC intent from `input`.
                    let output = match self.registry.get(tool_name) {
                        Some(tool) => tool
                            .execute(input, &self.ctx)
                            .await
                            .unwrap_or_else(|e| ToolOutput::err(e.to_string())),
                        None => ToolOutput::ok(format!(
                            "<terminal tool {tool_name:?} not in registry; \
                             dispatch loop returning input verbatim>"
                        )),
                    };
                    return Ok(DispatchOutcome::TerminalTool {
                        tool_name: tool_name.clone(),
                        input: input.clone(),
                        output,
                        cum_input_tokens: cum_in,
                        cum_output_tokens: cum_out,
                    });
                }
                let output = match self.registry.get(tool_name) {
                    Some(tool) => match tool.execute(input, &self.ctx).await {
                        Ok(o) => o,
                        Err(e) => ToolOutput::err(e.to_string()),
                    },
                    None => ToolOutput::err(format!("unknown tool: {tool_name:?}")),
                };
                next_user_blocks.push(ContentBlock::ToolResult {
                    tool_use_id: tu_id.clone(),
                    content: output.content,
                    is_error: output.is_error,
                });
            }
            req.messages.push(Message {
                role: "user".to_owned(),
                content: next_user_blocks,
            });
            let _ = turn; // turn is implicit in the for-loop counter.

            // The post-turn ceiling
            // check has already fired earlier in the loop (right after
            // `cum_in` / `cum_out` were updated), so reaching the next
            // iteration is the explicit "cap not yet hit" branch.
            // Keep this comment as a tombstone so a future refactor
            // that flips the order back to "tools first, then check"
            // is forced to think about the Idle/TerminalTool early-
            // return regression that motivated the move.
        }

        Ok(DispatchOutcome::MaxTurnsExceeded {
            turns: self.config.max_turns,
            cum_input_tokens: cum_in,
            cum_output_tokens: cum_out,
        })
    }

    // -------------------------------------------------------------------
    // V2_EXTENDED_GAPS §2.6 / §2.5 — streaming dispatch with
    // mid-stream budget abort.
    // Same loop semantics as `run()` except:
    //   1. Uses `create_message_stream` instead of `create_message`.
    //   2. Monitors `StreamEvent::Usage` events *during* the stream
    //      and aborts (drops the `Receiver`, severing the upstream
    //      HTTP connection) if any cumulative ceiling is exceeded.
    //   3. Falls back to `create_message` if the provider's
    //      `create_message_stream` returns `ModelError::Unsupported`.
    // The tool-dispatch and terminal-tool logic is identical to
    // `run()` — only the model-call shape changes. This avoids
    // divergence: callers that don't need mid-stream abort keep
    // using `run()`.
    // -------------------------------------------------------------------

    /// Drive one dispatch session using streaming model calls with
    /// **mid-stream budget enforcement**.
    /// Behaves identically to [`Self::run`] in all outcomes but adds
    /// a real-time budget check on every `StreamEvent::Usage` the
    /// upstream emits. If a ceiling is hit mid-stream, the receiver
    /// is dropped (closing the channel → upstream reader drops the
    /// HTTP body → TCP connection severed → provider stops
    /// generating tokens). This reduces overspend from "one full
    /// overbudget turn" (post-turn check) to "a few chunks past the
    /// ceiling" (mid-stream check).
    pub async fn run_streaming(
        &mut self,
        system_prompt: String,
        seed_user_text: String,
    ) -> Result<DispatchOutcome, DispatchError> {
        use crate::streaming::StreamEvent;

        // Mirrors the hoist in `run()` (see commit
        // "planner-core/dispatch: hoist MessageRequest out of run()
        // loop to remove per-turn clones"). The streaming path
        // carried the same per-turn allocation shape — `messages`,
        // `tool_specs`, `system_prompt`, and `model` were cloned
        // into a fresh `MessageRequest` every iteration. Building
        // the request once and mutating `req.messages` between turns
        // removes those clones; `req.stream = true` is set once at
        // construction so the AnthropicClient SSE path receives the
        // flag without per-turn re-derivation.
        let mut req = MessageRequest {
            model: self.config.model.clone(),
            max_tokens: self.config.max_tokens,
            system: Some(system_prompt),
            messages: vec![Message {
                role: "user".to_owned(),
                content: vec![ContentBlock::Text {
                    text: seed_user_text,
                }],
            }],
            tools: self.registry.to_specs(),
            temperature: self.config.temperature,
            stream: true,
            // Same cache opt-in as the buffered path above. See
            // `prompt-caching.md §"Per-role defaults"`.
            cache_system: true,
            cache_tools: true,
            cache_messages: true,
            cache_ttl: None,
        };

        let mut cum_in: u64 = 0;
        let mut cum_out: u64 = 0;
        // `INV-OBSERVABILITY-CACHE-TOKEN-PERSISTED-01` — same reset
        // shape as `run()`. Streaming and buffered paths share the
        // accessor surface; the dispatch loop's caller (the driver)
        // does not care which path produced the cumulative count.
        self.cum_cache_creation_input_tokens = 0;
        self.cum_cache_read_input_tokens = 0;

        for turn in 0..self.config.max_turns {
            // ── Stream consumption with mid-stream budget check ──
            let mut rx = self.model.create_message_stream(&req).await?;
            let mut resp: Option<MessageResponse> = None;

            while let Some(event) = rx.recv().await {
                match event {
                    StreamEvent::Usage(usage) => {
                        // Speculatively fold mid-stream usage into
                        // temporaries. The canonical fold happens
                        // below from the `Complete` event's
                        // `resp.usage`, but checking here lets us
                        // abort before the full response arrives.
                        let speculative_in = cum_in.saturating_add(
                            u64::from(usage.input_tokens)
                                .saturating_add(u64::from(usage.cache_creation_input_tokens))
                                .saturating_add(u64::from(usage.cache_read_input_tokens)),
                        );
                        let speculative_out =
                            cum_out.saturating_add(u64::from(usage.output_tokens));

                        if let Some(budget_exceeded) =
                            self.check_ceilings(speculative_in, speculative_out)
                        {
                            // Drop rx: closes the channel, upstream
                            // reader task will observe a closed
                            // `Sender` and drop the HTTP body,
                            // severing the TCP connection to the
                            // provider. Near-zero overspend.
                            drop(rx);
                            return Ok(budget_exceeded);
                        }
                    }
                    StreamEvent::Complete(msg) => {
                        resp = Some(msg);
                        // After Complete, no more events will arrive.
                        break;
                    }
                    // Observability events — consumed by V3 progress
                    // indicators and agent-stream capture (§4.3).
                    // The dispatch loop ignores them.
                    StreamEvent::MessageStart { .. }
                    | StreamEvent::ContentBlockStart { .. }
                    | StreamEvent::ContentBlockDelta { .. }
                    | StreamEvent::ContentBlockStop { .. }
                    | StreamEvent::Stop { .. } => {}
                }
            }

            let resp = match resp {
                Some(r) => r,
                None => {
                    // Stream ended without a Complete event — treat
                    // as a transport error (upstream disconnected).
                    return Err(DispatchError::Model(ModelError::Transport(
                        "stream ended without Complete event".to_owned(),
                    )));
                }
            };

            // ── Canonical post-turn usage fold (same as `run()`) ──
            let Usage {
                input_tokens,
                output_tokens,
                cache_creation_input_tokens,
                cache_read_input_tokens,
            } = resp.usage;

            // `INV-OBSERVABILITY-CACHE-TOKEN-EMITTED-01` — emit the
            // structured per-turn cache telemetry line BEFORE the
            // cum_in / cum_out fold, mirroring the buffered `run()`
            // path. The Anthropic SSE provider also emits
            // intermediate `Usage` events mid-stream — those are
            // intentionally NOT logged here (only the canonical
            // post-`Complete` `Usage` is) so each turn produces
            // exactly one log line regardless of provider chunking.
            emit_turn_usage(
                &mut std::io::stderr().lock(),
                self.config.task_id_for_logs(),
                self.config.session_id_for_logs(),
                self.config.role_for_logs(),
                &self.config.model,
                turn,
                input_tokens,
                output_tokens,
                cache_creation_input_tokens,
                cache_read_input_tokens,
                cum_in,
                cum_out,
            );

            cum_in = cum_in.saturating_add(
                u64::from(input_tokens)
                    .saturating_add(u64::from(cache_creation_input_tokens))
                    .saturating_add(u64::from(cache_read_input_tokens)),
            );
            cum_out = cum_out.saturating_add(u64::from(output_tokens));
            // `INV-OBSERVABILITY-CACHE-TOKEN-PERSISTED-01` — see
            // `run()` for rationale; same fold shape.
            self.cum_cache_creation_input_tokens = self
                .cum_cache_creation_input_tokens
                .saturating_add(u64::from(cache_creation_input_tokens));
            self.cum_cache_read_input_tokens = self
                .cum_cache_read_input_tokens
                .saturating_add(u64::from(cache_read_input_tokens));

            // Enforce per-session token
            // caps BEFORE inspecting the response for terminal tools /
            // Idle. The earlier version of this streaming path placed
            // the ceiling check at the BOTTOM of the loop iteration,
            // after the `Idle` and `TerminalTool` early returns — that
            // meant a streaming session whose final turn crossed the
            // cap (and whose provider never emitted a mid-stream
            // `Usage` event before `Complete`) would surface as `Idle`
            // or `TerminalTool` with the cap silently bypassed. This
            // matches the regression guard already in `run()` (see
            // `input_ceiling_fires_even_on_idle_terminal_path` and
            // `input_ceiling_fires_even_on_terminal_tool_short_circuit`
            // in the buffered path's tests); promoting the check to
            // the top of the post-turn block keeps the contract tight
            // for the streaming path too: every cap that is hit
            // reaches the role binary as a `TokensExceeded` outcome,
            // regardless of whether the provider streamed an
            // intermediate `Usage` event.
            if let Some(exceeded) = self.check_ceilings(cum_in, cum_out) {
                return Ok(exceeded);
            }

            // ── From here, identical to `run()` ───────────────────
            req.messages.push(Message {
                role: "assistant".to_owned(),
                content: resp.content.clone(),
            });

            let mut tool_uses: Vec<(String, String, serde_json::Value)> = Vec::new();
            let mut text_acc = String::new();
            for block in &resp.content {
                match block {
                    ContentBlock::Text { text } => {
                        if !text_acc.is_empty() {
                            text_acc.push('\n');
                        }
                        text_acc.push_str(text);
                    }
                    ContentBlock::ToolUse { id, name, input } => {
                        tool_uses.push((id.clone(), name.clone(), input.clone()));
                    }
                    ContentBlock::ToolResult { .. } | ContentBlock::Other(_) => {}
                }
            }

            if tool_uses.is_empty() {
                return Ok(DispatchOutcome::Idle {
                    final_text: text_acc,
                    cum_input_tokens: cum_in,
                    cum_output_tokens: cum_out,
                });
            }

            let mut next_user_blocks: Vec<ContentBlock> = Vec::with_capacity(tool_uses.len());
            for (tu_id, tool_name, input) in &tool_uses {
                if self.terminal_tools.contains(&tool_name.as_str()) {
                    let output = match self.registry.get(tool_name) {
                        Some(tool) => tool
                            .execute(input, &self.ctx)
                            .await
                            .unwrap_or_else(|e| ToolOutput::err(e.to_string())),
                        None => ToolOutput::ok(format!(
                            "<terminal tool {tool_name:?} not in registry; \
                             dispatch loop returning input verbatim>"
                        )),
                    };
                    return Ok(DispatchOutcome::TerminalTool {
                        tool_name: tool_name.clone(),
                        input: input.clone(),
                        output,
                        cum_input_tokens: cum_in,
                        cum_output_tokens: cum_out,
                    });
                }
                let output = match self.registry.get(tool_name) {
                    Some(tool) => match tool.execute(input, &self.ctx).await {
                        Ok(o) => o,
                        Err(e) => ToolOutput::err(e.to_string()),
                    },
                    None => ToolOutput::err(format!("unknown tool: {tool_name:?}")),
                };
                next_user_blocks.push(ContentBlock::ToolResult {
                    tool_use_id: tu_id.clone(),
                    content: output.content,
                    is_error: output.is_error,
                });
            }
            req.messages.push(Message {
                role: "user".to_owned(),
                content: next_user_blocks,
            });
            let _ = turn;

            // Post-turn ceiling check already fired above (right after
            // the canonical usage fold), so the cap was checked
            // BEFORE the Idle/TerminalTool early returns. Reaching
            // this point is the explicit "cap not yet hit" branch.
            // Tombstone kept so a future refactor that flips the
            // order back to "tools first, then check" is forced to
            // think about the Idle/TerminalTool regression that
            // motivated promoting the check (mirrors the tombstone
            // in `run()`).
        }

        Ok(DispatchOutcome::MaxTurnsExceeded {
            turns: self.config.max_turns,
            cum_input_tokens: cum_in,
            cum_output_tokens: cum_out,
        })
    }

    /// Shared ceiling check used by both `run()` and
    /// `run_streaming()`. Returns `Some(TokensExceeded)` if any
    /// configured ceiling is exceeded, `None` otherwise.
    fn check_ceilings(&self, cum_in: u64, cum_out: u64) -> Option<DispatchOutcome> {
        if let Some(ceiling) = self.config.max_tokens_total {
            if cum_in.saturating_add(cum_out) > ceiling {
                return Some(DispatchOutcome::TokensExceeded {
                    which: "total",
                    input_tokens: cum_in,
                    output_tokens: cum_out,
                    ceiling,
                });
            }
        }
        if let Some(ceiling) = self.config.max_tokens_input_total {
            if cum_in > ceiling {
                return Some(DispatchOutcome::TokensExceeded {
                    which: "input",
                    input_tokens: cum_in,
                    output_tokens: cum_out,
                    ceiling,
                });
            }
        }
        if let Some(ceiling) = self.config.max_tokens_output_total {
            if cum_out > ceiling {
                return Some(DispatchOutcome::TokensExceeded {
                    which: "output",
                    input_tokens: cum_in,
                    output_tokens: cum_out,
                    ceiling,
                });
            }
        }
        None
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{MessageResponse, MockModelClient, Usage};

    fn empty_response_end_turn(text: &str) -> MessageResponse {
        MessageResponse {
            id: "msg-end".to_owned(),
            kind: "message".to_owned(),
            role: "assistant".to_owned(),
            content: vec![ContentBlock::Text {
                text: text.to_owned(),
            }],
            stop_reason: Some("end_turn".to_owned()),
            usage: Usage::default(),
            model: "claude-sonnet-4-5-20250929".to_owned(),
        }
    }

    /// Like `empty_response_end_turn` but with explicit usage so
    /// regression tests can pin the post-turn ceiling-check
    /// behaviour.
    fn empty_response_end_turn_with_usage(
        text: &str,
        input_tokens: u32,
        output_tokens: u32,
    ) -> MessageResponse {
        MessageResponse {
            id: "msg-end".to_owned(),
            kind: "message".to_owned(),
            role: "assistant".to_owned(),
            content: vec![ContentBlock::Text {
                text: text.to_owned(),
            }],
            stop_reason: Some("end_turn".to_owned()),
            usage: Usage {
                input_tokens,
                output_tokens,
                cache_creation_input_tokens: 0,
                cache_read_input_tokens: 0,
            },
            model: "claude-sonnet-4-5-20250929".to_owned(),
        }
    }

    fn tool_use_response(
        tool_use_id: &str,
        name: &str,
        input: serde_json::Value,
    ) -> MessageResponse {
        MessageResponse {
            id: format!("msg-call-{tool_use_id}"),
            kind: "message".to_owned(),
            role: "assistant".to_owned(),
            content: vec![ContentBlock::ToolUse {
                id: tool_use_id.to_owned(),
                name: name.to_owned(),
                input,
            }],
            stop_reason: Some("tool_use".to_owned()),
            usage: Usage::default(),
            model: "claude-sonnet-4-5-20250929".to_owned(),
        }
    }

    fn fixture_workspace() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("hello.txt"), "hi from raxis").unwrap();
        dir
    }

    #[tokio::test]
    async fn idle_outcome_when_model_emits_text_only() {
        let model = Arc::new(MockModelClient::new(vec![empty_response_end_turn("done!")]));
        let registry = Arc::new(crate::tools::build_executor_registry());
        let ws = fixture_workspace();
        let mut d = DispatchLoop::new(
            model,
            registry,
            DispatchConfig::new("test-model"),
            ToolContext::for_workspace(ws.path()),
        );
        let out = d
            .run("system prompt".to_owned(), "seed user message".to_owned())
            .await
            .unwrap();
        match out {
            DispatchOutcome::Idle { final_text, .. } => {
                assert_eq!(final_text, "done!");
            }
            other => panic!("expected Idle, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn dispatch_executes_tool_then_terminates_on_idle() {
        // Turn 1: model calls read_file
        // Turn 2: model emits text-only end_turn
        let r1 = tool_use_response(
            "tu1",
            "read_file",
            serde_json::json!({ "path": "hello.txt" }),
        );
        let r2 = empty_response_end_turn("read it");
        let model = Arc::new(MockModelClient::new(vec![r1, r2]));
        let registry = Arc::new(crate::tools::build_executor_registry());
        let ws = fixture_workspace();
        let captured = model.seen.clone();

        let mut d = DispatchLoop::new(
            model.clone(),
            registry,
            DispatchConfig::new("test-model"),
            ToolContext::for_workspace(ws.path()),
        );
        let out = d.run("sys".to_owned(), "seed".to_owned()).await.unwrap();
        assert!(matches!(out, DispatchOutcome::Idle { .. }));

        // Inspect the captured requests:
        // Turn 1 sent only the seed user message.
        // Turn 2 sent seed + assistant tool_use + user tool_result.
        let seen = captured.lock().await;
        assert_eq!(seen.len(), 2);
        let t2 = &seen[1];
        // Turn 2 must include 3 messages: user(seed), assistant(tool_use), user(tool_result).
        assert_eq!(
            t2.messages.len(),
            3,
            "turn 2 must include the tool_result reply, got {} messages",
            t2.messages.len()
        );
        let last = &t2.messages[2];
        assert_eq!(last.role, "user");
        match &last.content[0] {
            ContentBlock::ToolResult {
                tool_use_id,
                content,
                is_error,
            } => {
                assert_eq!(tool_use_id, "tu1");
                assert_eq!(
                    content, "hi from raxis",
                    "tool_result content must echo read_file output"
                );
                assert_eq!(*is_error, None);
            }
            other => panic!("expected ToolResult, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn unknown_tool_surfaces_as_structured_error_to_model() {
        let r1 = tool_use_response("tu1", "no_such_tool", serde_json::json!({}));
        let r2 = empty_response_end_turn("recovered");
        let model = Arc::new(MockModelClient::new(vec![r1, r2]));
        let captured = model.seen.clone();
        let registry = Arc::new(crate::tools::build_executor_registry());
        let ws = fixture_workspace();

        let mut d = DispatchLoop::new(
            model.clone(),
            registry,
            DispatchConfig::new("test-model"),
            ToolContext::for_workspace(ws.path()),
        );
        let out = d.run("sys".to_owned(), "seed".to_owned()).await.unwrap();
        assert!(matches!(out, DispatchOutcome::Idle { .. }));

        // Verify the unknown-tool surface as a tool_result with
        // is_error=Some(true).
        let seen = captured.lock().await;
        let last_user = seen[1].messages.last().unwrap();
        match &last_user.content[0] {
            ContentBlock::ToolResult {
                is_error, content, ..
            } => {
                assert_eq!(*is_error, Some(true));
                assert!(content.contains("unknown tool"));
            }
            other => panic!("expected error ToolResult, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn terminal_tool_short_circuits_loop() {
        let r1 = tool_use_response(
            "tu1",
            "task_complete",
            serde_json::json!({ "head_sha": "abc123def456" }),
        );
        // No second response queued: the dispatch loop must
        // short-circuit on the terminal tool BEFORE asking the
        // model again.
        let model = Arc::new(MockModelClient::new(vec![r1]));
        let registry = Arc::new(crate::tools::build_executor_registry());
        let ws = fixture_workspace();
        let mut d = DispatchLoop::new(
            model,
            registry,
            DispatchConfig::new("test-model"),
            ToolContext::for_workspace(ws.path()),
        )
        .with_terminal_tools(vec!["task_complete"]);
        let out = d.run("sys".to_owned(), "seed".to_owned()).await.unwrap();
        match out {
            DispatchOutcome::TerminalTool {
                tool_name, input, ..
            } => {
                assert_eq!(tool_name, "task_complete");
                assert_eq!(input["head_sha"], "abc123def456");
            }
            other => panic!("expected TerminalTool, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn max_turns_exceeded_surfaces_after_ceiling() {
        // Model loops forever calling read_file; dispatch loop
        // must terminate after `max_turns`.
        let mut queue = Vec::new();
        for i in 0..5 {
            queue.push(tool_use_response(
                &format!("tu{i}"),
                "read_file",
                serde_json::json!({ "path": "hello.txt" }),
            ));
        }
        let model = Arc::new(MockModelClient::new(queue));
        let registry = Arc::new(crate::tools::build_executor_registry());
        let ws = fixture_workspace();
        let mut cfg = DispatchConfig::new("test-model");
        cfg.max_turns = 3;
        let mut d = DispatchLoop::new(model, registry, cfg, ToolContext::for_workspace(ws.path()));
        let out = d.run("sys".to_owned(), "seed".to_owned()).await.unwrap();
        match out {
            DispatchOutcome::MaxTurnsExceeded { turns, .. } => {
                assert_eq!(turns, 3);
            }
            other => panic!("expected MaxTurnsExceeded, got {other:?}"),
        }
    }

    /// Build a `tool_use` response with explicit token-usage counters
    /// so the §C1 cumulative-tracking tests can drive ceiling crossings
    /// deterministically.
    fn tool_use_response_with_usage(
        tool_use_id: &str,
        name: &str,
        input: serde_json::Value,
        input_tokens: u32,
        output_tokens: u32,
    ) -> MessageResponse {
        MessageResponse {
            id: format!("msg-call-{tool_use_id}"),
            kind: "message".to_owned(),
            role: "assistant".to_owned(),
            content: vec![ContentBlock::ToolUse {
                id: tool_use_id.to_owned(),
                name: name.to_owned(),
                input,
            }],
            stop_reason: Some("tool_use".to_owned()),
            usage: Usage {
                input_tokens,
                output_tokens,
                cache_creation_input_tokens: 0,
                cache_read_input_tokens: 0,
            },
            model: "claude-sonnet-4-5-20250929".to_owned(),
        }
    }

    /// `max_tokens_input_total` ceiling fires post-turn
    /// and surfaces a structured `TokensExceeded` outcome with the
    /// `which = "input"` discriminant.
    #[tokio::test]
    async fn input_total_ceiling_surfaces_tokens_exceeded() {
        let r1 = tool_use_response_with_usage(
            "tu1",
            "read_file",
            serde_json::json!({ "path": "hello.txt" }),
            150, // input
            10,  // output
        );
        let r2 = empty_response_end_turn("done");
        let model = Arc::new(MockModelClient::new(vec![r1, r2]));
        let registry = Arc::new(crate::tools::build_executor_registry());
        let ws = fixture_workspace();
        let mut cfg = DispatchConfig::new("test-model");
        cfg.max_tokens_input_total = Some(100);
        let mut d = DispatchLoop::new(model, registry, cfg, ToolContext::for_workspace(ws.path()));
        let out = d.run("sys".to_owned(), "seed".to_owned()).await.unwrap();
        match out {
            DispatchOutcome::TokensExceeded {
                which,
                input_tokens,
                output_tokens,
                ceiling,
            } => {
                assert_eq!(which, "input");
                assert_eq!(input_tokens, 150);
                assert_eq!(output_tokens, 10);
                assert_eq!(ceiling, 100);
            }
            other => panic!("expected TokensExceeded(input), got {other:?}"),
        }
    }

    /// `max_tokens_total` (input + output) is checked
    /// FIRST so an operator-set overall budget always wins over the
    /// granular `input/output` ceilings.
    #[tokio::test]
    async fn total_ceiling_takes_precedence_over_input_only_ceiling() {
        let r1 = tool_use_response_with_usage(
            "tu1",
            "read_file",
            serde_json::json!({ "path": "hello.txt" }),
            60,
            60,
        );
        let r2 = empty_response_end_turn("done");
        let model = Arc::new(MockModelClient::new(vec![r1, r2]));
        let registry = Arc::new(crate::tools::build_executor_registry());
        let ws = fixture_workspace();
        let mut cfg = DispatchConfig::new("test-model");
        // Both ceilings would fire, but `total` is the first
        // post-turn check.
        cfg.max_tokens_total = Some(100);
        cfg.max_tokens_input_total = Some(50);
        let mut d = DispatchLoop::new(model, registry, cfg, ToolContext::for_workspace(ws.path()));
        let out = d.run("sys".to_owned(), "seed".to_owned()).await.unwrap();
        match out {
            DispatchOutcome::TokensExceeded { which, .. } => {
                assert_eq!(which, "total", "total ceiling fires before input ceiling");
            }
            other => panic!("expected TokensExceeded(total), got {other:?}"),
        }
    }

    /// When the model returns
    /// `end_turn` with no tool_use blocks AND the cumulative input
    /// total has crossed the configured cap, the loop MUST surface
    /// `TokensExceeded` and NOT `Idle`. Earlier dispatch versions
    /// gated the post-turn ceiling check behind the
    /// `tool_uses.is_empty()` continuation path, which silently
    /// no-op'd the cap when the session ended on a clean `end_turn`.
    /// This test pins the fixed contract.
    #[tokio::test]
    async fn input_ceiling_fires_even_on_idle_terminal_path() {
        let r1 = empty_response_end_turn_with_usage("done", 200, 5);
        let model = Arc::new(MockModelClient::new(vec![r1]));
        let registry = Arc::new(crate::tools::build_executor_registry());
        let ws = fixture_workspace();
        let mut cfg = DispatchConfig::new("test-model");
        cfg.max_tokens_input_total = Some(100);
        let mut d = DispatchLoop::new(model, registry, cfg, ToolContext::for_workspace(ws.path()));
        let out = d.run("sys".to_owned(), "seed".to_owned()).await.unwrap();
        match out {
            DispatchOutcome::TokensExceeded {
                which,
                input_tokens,
                ceiling,
                ..
            } => {
                assert_eq!(
                    which, "input",
                    "Idle exit MUST NOT bypass the input cap (§2.5 regression guard)"
                );
                assert_eq!(input_tokens, 200);
                assert_eq!(ceiling, 100);
            }
            other => panic!("expected TokensExceeded(input), got {other:?}"),
        }
    }

    /// Counterpart to the test above — when the model fires a
    /// terminal tool AND the cumulative cap has been crossed, the
    /// loop MUST surface `TokensExceeded` and NOT `TerminalTool`.
    /// Same regression guard, different early-return path.
    #[tokio::test]
    async fn input_ceiling_fires_even_on_terminal_tool_short_circuit() {
        // Use `task_complete` — registered as a terminal tool by
        // `build_executor_registry`. Usage explicitly busts the cap.
        let r1 = tool_use_response_with_usage(
            "tu1",
            "task_complete",
            serde_json::json!({ "summary": "done" }),
            300, // input
            5,   // output
        );
        let model = Arc::new(MockModelClient::new(vec![r1]));
        let registry = Arc::new(crate::tools::build_executor_registry());
        let ws = fixture_workspace();
        let mut cfg = DispatchConfig::new("test-model");
        cfg.max_tokens_input_total = Some(100);
        let mut d = DispatchLoop::new(model, registry, cfg, ToolContext::for_workspace(ws.path()))
            .with_terminal_tools(vec!["task_complete"]);
        let out = d.run("sys".to_owned(), "seed".to_owned()).await.unwrap();
        match out {
            DispatchOutcome::TokensExceeded { which, ceiling, .. } => {
                assert_eq!(
                    which, "input",
                    "terminal-tool short-circuit MUST NOT bypass the input cap"
                );
                assert_eq!(ceiling, 100);
            }
            other => panic!("expected TokensExceeded(input), got {other:?}"),
        }
    }

    /// None ceilings ⇒ uncapped; the loop must run to
    /// its natural terminal outcome with no token-related early exit.
    #[tokio::test]
    async fn no_ceiling_means_uncapped_dispatch_runs_to_natural_terminal() {
        let r1 = empty_response_end_turn("done");
        let model = Arc::new(MockModelClient::new(vec![r1]));
        let registry = Arc::new(crate::tools::build_executor_registry());
        let ws = fixture_workspace();
        let cfg = DispatchConfig::new("test-model");
        assert!(cfg.max_tokens_input_total.is_none());
        assert!(cfg.max_tokens_output_total.is_none());
        assert!(cfg.max_tokens_total.is_none());
        let mut d = DispatchLoop::new(model, registry, cfg, ToolContext::for_workspace(ws.path()));
        let out = d.run("sys".to_owned(), "seed".to_owned()).await.unwrap();
        assert!(
            matches!(out, DispatchOutcome::Idle { .. }),
            "uncapped dispatch must surface Idle, got {out:?}"
        );
    }

    /// cumulative tracking must include cache-read +
    /// cache-creation input tokens, not just `input_tokens`.
    #[tokio::test]
    async fn cumulative_input_includes_cache_tokens() {
        let r1 = MessageResponse {
            id: "msg-1".to_owned(),
            kind: "message".to_owned(),
            role: "assistant".to_owned(),
            content: vec![ContentBlock::ToolUse {
                id: "tu1".to_owned(),
                name: "read_file".to_owned(),
                input: serde_json::json!({ "path": "hello.txt" }),
            }],
            stop_reason: Some("tool_use".to_owned()),
            usage: Usage {
                input_tokens: 30,
                output_tokens: 5,
                cache_creation_input_tokens: 40,
                cache_read_input_tokens: 35,
            },
            model: "claude-sonnet-4-5-20250929".to_owned(),
        };
        let r2 = empty_response_end_turn("done");
        let model = Arc::new(MockModelClient::new(vec![r1, r2]));
        let registry = Arc::new(crate::tools::build_executor_registry());
        let ws = fixture_workspace();
        let mut cfg = DispatchConfig::new("test-model");
        // 30 + 40 + 35 = 105; threshold 100 must fire.
        cfg.max_tokens_input_total = Some(100);
        let mut d = DispatchLoop::new(model, registry, cfg, ToolContext::for_workspace(ws.path()));
        let out = d.run("sys".to_owned(), "seed".to_owned()).await.unwrap();
        match out {
            DispatchOutcome::TokensExceeded {
                which,
                input_tokens,
                ..
            } => {
                assert_eq!(which, "input");
                assert_eq!(
                    input_tokens, 105,
                    "cumulative input must fold input + cache-creation + cache-read"
                );
            }
            other => panic!("expected TokensExceeded, got {other:?}"),
        }
    }

    // ── Streaming dispatch tests ─────────────────────────────────────

    /// Mock model client that emits real `StreamEvent`s through the
    /// channel, including intermediate `Usage` events. This lets us
    /// test mid-stream budget abort deterministically.
    struct MockStreamingModelClient {
        /// Pre-canned responses, consumed FIFO. Each entry is a pair
        /// of (mid-stream Usage, final MessageResponse). The Usage
        /// is emitted as a `StreamEvent::Usage` *before* the
        /// `StreamEvent::Complete` so the dispatch loop can check
        /// its budget mid-stream.
        pending: Arc<tokio::sync::Mutex<Vec<(Usage, MessageResponse)>>>,
    }

    impl MockStreamingModelClient {
        fn new(responses: Vec<(Usage, MessageResponse)>) -> Self {
            Self {
                pending: Arc::new(tokio::sync::Mutex::new(responses)),
            }
        }
    }

    #[async_trait::async_trait]
    impl ModelClient for MockStreamingModelClient {
        async fn create_message(
            &self,
            _req: &MessageRequest,
        ) -> Result<MessageResponse, ModelError> {
            // Streaming mock — not used via the buffered path.
            Err(ModelError::Transport(
                "MockStreamingModelClient: use create_message_stream".to_owned(),
            ))
        }

        async fn create_message_stream(
            &self,
            _req: &MessageRequest,
        ) -> Result<tokio::sync::mpsc::Receiver<crate::streaming::StreamEvent>, ModelError>
        {
            use crate::streaming::StreamEvent;

            let mut q = self.pending.lock().await;
            if q.is_empty() {
                return Err(ModelError::Transport(
                    "MockStreamingModelClient: response queue exhausted".to_owned(),
                ));
            }
            let (mid_usage, resp) = q.remove(0);

            let (tx, rx) = tokio::sync::mpsc::channel(crate::streaming::DEFAULT_STREAM_CHANNEL_CAP);

            // Emit events in the same order a real provider would:
            // MessageStart → Usage → Complete.
            tokio::spawn(async move {
                let _ = tx
                    .send(StreamEvent::MessageStart {
                        id: resp.id.clone(),
                        model: resp.model.clone(),
                    })
                    .await;
                let _ = tx.send(StreamEvent::Usage(mid_usage)).await;
                let _ = tx.send(StreamEvent::Complete(resp)).await;
            });

            Ok(rx)
        }
    }

    #[tokio::test]
    async fn streaming_idle_outcome_when_model_emits_text_only() {
        let resp = empty_response_end_turn("streamed done!");
        let mid = Usage::default();
        let model = Arc::new(MockStreamingModelClient::new(vec![(mid, resp)]));
        let registry = Arc::new(crate::tools::build_executor_registry());
        let ws = fixture_workspace();
        let mut d = DispatchLoop::new(
            model,
            registry,
            DispatchConfig::new("test-model"),
            ToolContext::for_workspace(ws.path()),
        );
        let out = d
            .run_streaming("system".to_owned(), "seed".to_owned())
            .await
            .unwrap();
        match out {
            DispatchOutcome::Idle { final_text, .. } => {
                assert_eq!(final_text, "streamed done!");
            }
            other => panic!("expected Idle, got {other:?}"),
        }
    }

    /// V2_EXTENDED_GAPS §2.5 — mid-stream output ceiling abort.
    /// The mock emits a `Usage` event with 200 output tokens
    /// mid-stream; the ceiling is 100. The dispatch loop must
    /// abort mid-stream (drop the receiver) and return
    /// `TokensExceeded { which: "output" }` WITHOUT consuming
    /// the `Complete` event.
    #[tokio::test]
    async fn streaming_mid_stream_output_ceiling_aborts() {
        let mid_usage = Usage {
            input_tokens: 50,
            output_tokens: 200, // exceeds ceiling of 100
            cache_creation_input_tokens: 0,
            cache_read_input_tokens: 0,
        };
        // The Complete would carry these same counts, but the loop
        // should never reach it — it aborts on the Usage event.
        let resp = MessageResponse {
            id: "msg-abort".to_owned(),
            kind: "message".to_owned(),
            role: "assistant".to_owned(),
            content: vec![ContentBlock::Text {
                text: "should not reach this".to_owned(),
            }],
            stop_reason: Some("end_turn".to_owned()),
            usage: mid_usage.clone(),
            model: "claude-sonnet-4-5-20250929".to_owned(),
        };
        let model = Arc::new(MockStreamingModelClient::new(vec![(mid_usage, resp)]));
        let registry = Arc::new(crate::tools::build_executor_registry());
        let ws = fixture_workspace();
        let mut cfg = DispatchConfig::new("test-model");
        cfg.max_tokens_output_total = Some(100);
        let mut d = DispatchLoop::new(model, registry, cfg, ToolContext::for_workspace(ws.path()));
        let out = d
            .run_streaming("sys".to_owned(), "seed".to_owned())
            .await
            .unwrap();
        match out {
            DispatchOutcome::TokensExceeded {
                which,
                output_tokens,
                ceiling,
                ..
            } => {
                assert_eq!(which, "output");
                assert_eq!(output_tokens, 200);
                assert_eq!(ceiling, 100);
            }
            other => panic!("expected TokensExceeded(output), got {other:?}"),
        }
    }

    /// V2_EXTENDED_GAPS §2.5 — mid-stream total ceiling abort.
    #[tokio::test]
    async fn streaming_mid_stream_total_ceiling_aborts() {
        let mid_usage = Usage {
            input_tokens: 80,
            output_tokens: 80, // total 160 > ceiling 100
            cache_creation_input_tokens: 0,
            cache_read_input_tokens: 0,
        };
        let resp = MessageResponse {
            id: "msg-total".to_owned(),
            kind: "message".to_owned(),
            role: "assistant".to_owned(),
            content: vec![ContentBlock::Text {
                text: "over budget".to_owned(),
            }],
            stop_reason: Some("end_turn".to_owned()),
            usage: mid_usage.clone(),
            model: "claude-sonnet-4-5-20250929".to_owned(),
        };
        let model = Arc::new(MockStreamingModelClient::new(vec![(mid_usage, resp)]));
        let registry = Arc::new(crate::tools::build_executor_registry());
        let ws = fixture_workspace();
        let mut cfg = DispatchConfig::new("test-model");
        cfg.max_tokens_total = Some(100);
        let mut d = DispatchLoop::new(model, registry, cfg, ToolContext::for_workspace(ws.path()));
        let out = d
            .run_streaming("sys".to_owned(), "seed".to_owned())
            .await
            .unwrap();
        match out {
            DispatchOutcome::TokensExceeded { which, .. } => {
                assert_eq!(
                    which, "total",
                    "total ceiling must fire before input/output per check_ceilings order"
                );
            }
            other => panic!("expected TokensExceeded(total), got {other:?}"),
        }
    }

    /// Streaming under budget completes normally with tool dispatch.
    #[tokio::test]
    async fn streaming_under_budget_completes_tool_dispatch() {
        let mid1 = Usage {
            input_tokens: 20,
            output_tokens: 10,
            cache_creation_input_tokens: 0,
            cache_read_input_tokens: 0,
        };
        let r1 = tool_use_response(
            "tu1",
            "read_file",
            serde_json::json!({ "path": "hello.txt" }),
        );
        // Override usage on r1 to match mid-stream
        let r1 = MessageResponse {
            usage: mid1.clone(),
            ..r1
        };

        let mid2 = Usage::default();
        let r2 = empty_response_end_turn("file read");

        let model = Arc::new(MockStreamingModelClient::new(vec![(mid1, r1), (mid2, r2)]));
        let registry = Arc::new(crate::tools::build_executor_registry());
        let ws = fixture_workspace();
        let mut cfg = DispatchConfig::new("test-model");
        cfg.max_tokens_output_total = Some(1000); // plenty of headroom
        let mut d = DispatchLoop::new(model, registry, cfg, ToolContext::for_workspace(ws.path()));
        let out = d
            .run_streaming("sys".to_owned(), "seed".to_owned())
            .await
            .unwrap();
        assert!(
            matches!(out, DispatchOutcome::Idle { .. }),
            "under-budget streaming must complete normally, got {out:?}"
        );
    }

    // ── `INV-OBSERVABILITY-CACHE-TOKEN-EMITTED-01` witnesses ─────────
    // These tests exercise `emit_turn_usage` directly (writing into a
    // `Vec<u8>` so stderr capture is unnecessary) AND the production
    // dispatch loop (so the wire shape and the per-turn cardinality
    // are pinned end-to-end). The eprintln! production path calls
    // into the same helper, so any drift in the JSON shape fails
    // these tests deterministically.

    /// `INV-OBSERVABILITY-CACHE-TOKEN-EMITTED-01` — the
    /// `planner_turn_usage` JSON line carries the right keys and
    /// the cache-hit ratio is computed correctly. Synthetic Usage
    /// per the iter62 fix spec: `{input=10, output=20,
    /// cache_creation=300, cache_read=4000}` ⇒ ratio
    /// `4000 / (4000 + 10 + 300) = 4000 / 4310 ≈ 0.9281`.
    #[test]
    fn planner_turn_usage_log_shape() {
        let mut buf: Vec<u8> = Vec::new();
        emit_turn_usage(
            &mut buf,
            "task-iter62-shape",
            "session-token-iter62",
            "executor",
            "claude-sonnet-4-5-20250929",
            0,
            10,
            20,
            300,
            4000,
            0,
            0,
        );
        let line = std::str::from_utf8(&buf).expect("log line must be UTF-8");
        // Trim the trailing newline before parsing.
        let trimmed = line.trim_end_matches('\n');
        assert!(
            trimmed.contains("\"event\":\"planner_turn_usage\""),
            "missing event tag: {trimmed}"
        );
        assert!(
            trimmed.contains("\"cache_creation_input_tokens\":300"),
            "missing cache_creation count: {trimmed}"
        );
        assert!(
            trimmed.contains("\"cache_read_input_tokens\":4000"),
            "missing cache_read count: {trimmed}"
        );
        assert!(
            trimmed.contains("\"task_id\":\"task-iter62-shape\""),
            "missing task_id: {trimmed}"
        );
        assert!(
            trimmed.contains("\"role\":\"executor\""),
            "missing role: {trimmed}"
        );

        // Cross-check the ratio numerically by parsing the line as
        // JSON. This is what the kernel-side scraper does.
        let v: serde_json::Value =
            serde_json::from_str(trimmed).expect("emitted line must be valid JSON");
        let ratio = v["cache_hit_ratio"]
            .as_f64()
            .expect("cache_hit_ratio must be a JSON number");
        assert!(
            (0.92..=0.93).contains(&ratio),
            "cache_hit_ratio out of expected band [0.92, 0.93]: {ratio}"
        );
        // Cumulative projections fold the current turn's tokens.
        assert_eq!(
            v["cumulative_input_tokens"].as_u64(),
            Some(10 + 300 + 4000),
            "cumulative_input_tokens must include cache + non-cache input"
        );
        assert_eq!(v["cumulative_output_tokens"].as_u64(), Some(20));
    }

    /// `INV-OBSERVABILITY-CACHE-TOKEN-EMITTED-01` — every turn the
    /// dispatch loop drives MUST produce exactly one
    /// `planner_turn_usage` line. The witness drives the helper
    /// directly across three synthetic turns (matching the wire
    /// shape the production loop emits) and asserts both the
    /// cardinality and the per-turn ordering of the `turn` field.
    #[test]
    fn planner_turn_usage_emitted_per_turn() {
        let mut buf: Vec<u8> = Vec::new();
        // Three turns with distinct usage so we can pin the order.
        for (idx, (in_t, out_t, cc, cr)) in [
            (10u32, 5u32, 0u32, 0u32),
            (12, 6, 100, 200),
            (14, 7, 50, 150),
        ]
        .iter()
        .enumerate()
        {
            emit_turn_usage(
                &mut buf,
                "task-iter62-percent",
                "sess-iter62",
                "executor",
                "claude-sonnet-4-5-20250929",
                idx as u32,
                *in_t,
                *out_t,
                *cc,
                *cr,
                0,
                0,
            );
        }
        let text = std::str::from_utf8(&buf).expect("log buffer must be UTF-8");
        let lines: Vec<&str> = text.lines().filter(|l| !l.is_empty()).collect();
        assert_eq!(
            lines.len(),
            3,
            "expected exactly 3 planner_turn_usage lines, got {}: {text}",
            lines.len()
        );
        for (idx, line) in lines.iter().enumerate() {
            assert!(
                line.contains("\"event\":\"planner_turn_usage\""),
                "line {idx} missing event tag: {line}"
            );
            let v: serde_json::Value =
                serde_json::from_str(line).expect("each emitted line must be valid JSON");
            assert_eq!(
                v["turn"].as_u64(),
                Some(idx as u64),
                "turn ordering broke at line {idx}: {line}"
            );
        }
    }

    /// `INV-OBSERVABILITY-CACHE-TOKEN-EMITTED-01` — the cache-hit
    /// ratio computation MUST NOT panic when every cache counter
    /// is zero (single-turn no-cache path). Pins the
    /// `denom == 0 ⇒ 0.0` guard in `emit_turn_usage`.
    #[test]
    fn planner_turn_usage_zero_cache_does_not_panic() {
        let mut buf: Vec<u8> = Vec::new();
        emit_turn_usage(
            &mut buf,
            "task-iter62-zero",
            "sess-iter62",
            "executor",
            "claude-sonnet-4-5-20250929",
            0,
            10,
            20,
            0,
            0,
            0,
            0,
        );
        let line = std::str::from_utf8(&buf).expect("must be UTF-8");
        let trimmed = line.trim_end_matches('\n');
        let v: serde_json::Value = serde_json::from_str(trimmed).expect("must parse as JSON");
        // `input_tokens=10` is non-zero so the denominator is 10
        // (not zero) and the ratio is `0 / 10 = 0.0`. The
        // assertion is the same either way: the wire shape
        // surfaces 0.0 and emits no panic / NaN / inf.
        let ratio = v["cache_hit_ratio"]
            .as_f64()
            .expect("cache_hit_ratio must be a JSON number");
        assert_eq!(
            ratio, 0.0_f64,
            "ratio must be exactly 0.0 when cache counters are zero, got {ratio}"
        );

        // Also exercise the truly all-zero path (every counter 0)
        // to pin the explicit `denom == 0` guard.
        let mut buf2: Vec<u8> = Vec::new();
        emit_turn_usage(&mut buf2, "t", "s", "executor", "m", 0, 0, 0, 0, 0, 0, 0);
        let v2: serde_json::Value =
            serde_json::from_str(std::str::from_utf8(&buf2).unwrap().trim_end_matches('\n'))
                .expect("must parse as JSON");
        assert_eq!(
            v2["cache_hit_ratio"].as_f64(),
            Some(0.0_f64),
            "all-zero usage must yield ratio 0.0 (no division by zero)"
        );
    }
}

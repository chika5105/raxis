//! Dispatch loop — drives the
//! `LLM → parse tool_use → execute → return result` cycle every
//! planner-role binary runs at steady state.
//!
//! Closes V2_GAPS.md §B1 substep "Tool-dispatch loop".
//!
//! ## Loop shape
//!
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
//!         — return [`DispatchOutcome::Idle`] and let the
//!         caller decide whether to re-run with a follow-up
//!         user message or exit cleanly.
//!      e. If a terminal-tool fired (e.g. `task_complete`,
//!         `submit_review`), short-circuit with the tool's
//!         output as the loop's final value.
//!   4. Bound the loop by a max-iteration ceiling.
//! ```
//!
//! ## V2 limits (declared so future work has a target)
//!
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

use crate::model::{ContentBlock, Message, MessageRequest, ModelClient, ModelError};
use crate::tools::{ToolContext, ToolError, ToolOutput, ToolRegistry};

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
    pub model:         String,
    /// Hard cap on assistant turns. Per
    /// `planner-harness.md §INV-PLANNER-HARNESS-04`, every dispatch
    /// loop MUST surface a structured terminal outcome before this
    /// ceiling so an infinite-loop model cannot consume the operator's
    /// token budget unbounded.
    pub max_turns:     u32,
    /// Per-turn LLM `max_tokens` budget. Bounded by the policy-side
    /// `[providers.X] max_tokens_per_request` ceiling.
    pub max_tokens:    u32,
    /// Sampling temperature. None ⇒ Anthropic default (1.0).
    pub temperature:   Option<f32>,
    /// Per-tool deadline. Planner-side bound; the kernel-side budget
    /// is enforced separately.
    pub tool_deadline: Option<Duration>,
}

impl DispatchConfig {
    /// Sensible default for production reviewer / executor. Callers
    /// override per role + per task.
    pub fn new(model: impl Into<String>) -> Self {
        Self {
            model:         model.into(),
            max_turns:     20,
            max_tokens:    4096,
            temperature:   Some(0.7),
            tool_deadline: Some(Duration::from_secs(120)),
        }
    }
}

/// One dispatch-loop terminal outcome.
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
        input:     serde_json::Value,
        /// Tool's output.
        output:    ToolOutput,
    },
    /// The model said it was done (`stop_reason = "end_turn"`) and
    /// emitted no tool_use blocks. The caller decides whether to
    /// inject a new user message or exit cleanly.
    Idle {
        /// Final assistant text content (joined across all `Text`
        /// blocks in the last turn).
        final_text: String,
    },
    /// Hit the `max_turns` ceiling. INV-PLANNER-HARNESS-04 surfaces
    /// this as a structured failure on the role binary side.
    MaxTurnsExceeded {
        /// Number of turns the loop ran.
        turns: u32,
    },
}

#[derive(Debug, Error)]
pub enum DispatchError {
    #[error("model error: {0}")]
    Model(#[from] ModelError),
    #[error("tool error: {0}")]
    Tool(#[from] ToolError),
}

// ---------------------------------------------------------------------------
// DispatchLoop
// ---------------------------------------------------------------------------

/// The per-session dispatch state. One per planner role binary
/// instance. Holds:
///
/// * The model client (`Arc<dyn ModelClient>`) — swappable for
///   tests via [`crate::model::MockModelClient`].
/// * The role-specific tool registry.
/// * Static per-session config (model id, max_turns, ...).
/// * The per-task tool context (workspace root, deadline).
///
/// Dispatch is started by [`DispatchLoop::run`] which takes the
/// initial system prompt + initial user message and runs to a
/// terminal outcome.
pub struct DispatchLoop {
    model:    Arc<dyn ModelClient>,
    registry: Arc<ToolRegistry>,
    config:   DispatchConfig,
    ctx:      ToolContext,
    /// Names of tools that, when invoked, terminate the loop with
    /// [`DispatchOutcome::TerminalTool`]. Populated by the role
    /// binary via [`DispatchLoop::with_terminal_tools`]; default is
    /// empty (the loop terminates only on `Idle` or `MaxTurnsExceeded`).
    terminal_tools: Vec<&'static str>,
}

impl DispatchLoop {
    /// Construct a new dispatch loop. The role binary supplies all
    /// four slots up front; the loop is `&mut self` so two
    /// concurrent calls on one instance is a build-time error.
    pub fn new(
        model:    Arc<dyn ModelClient>,
        registry: Arc<ToolRegistry>,
        config:   DispatchConfig,
        ctx:      ToolContext,
    ) -> Self {
        Self {
            model,
            registry,
            config,
            ctx,
            terminal_tools: Vec::new(),
        }
    }

    /// Declare which tool names short-circuit the loop. The role
    /// binary calls this once at construction:
    ///
    /// * Executor:    `["task_complete", "report_failure"]`
    /// * Reviewer:    `["submit_review"]`
    /// * Orchestrator: `["activate_subtask", "integration_merge", "complete_initiative"]`
    pub fn with_terminal_tools(mut self, names: Vec<&'static str>) -> Self {
        self.terminal_tools = names;
        self
    }

    /// Drive one dispatch session to a terminal outcome.
    ///
    /// `system_prompt` is the rendered KSB + role NNSP (see
    /// [`crate::ksb`] and `kernel-mechanics-prompt.md`).
    ///
    /// `seed_user_text` is the role-specific seed message (e.g.
    /// "You are working on task task-42; the goal is …").
    pub async fn run(
        &mut self,
        system_prompt:  String,
        seed_user_text: String,
    ) -> Result<DispatchOutcome, DispatchError> {
        let mut messages: Vec<Message> = vec![Message {
            role:    "user".to_owned(),
            content: vec![ContentBlock::Text { text: seed_user_text }],
        }];
        let tool_specs = self.registry.to_specs();

        for turn in 0..self.config.max_turns {
            let req = MessageRequest {
                model:       self.config.model.clone(),
                max_tokens:  self.config.max_tokens,
                system:      Some(system_prompt.clone()),
                messages:    messages.clone(),
                tools:       tool_specs.clone(),
                temperature: self.config.temperature,
            };
            let resp = self.model.create_message(&req).await?;

            // Append the assistant turn to the history (verbatim so
            // tool_use blocks correlate with our tool_result reply).
            messages.push(Message {
                role:    "assistant".to_owned(),
                content: resp.content.clone(),
            });

            // Walk content blocks: collect all tool_use, also
            // collect joined text for Idle reporting.
            let mut tool_uses: Vec<(String, String, serde_json::Value)> = Vec::new();
            let mut text_acc = String::new();
            for block in &resp.content {
                match block {
                    ContentBlock::Text { text } => {
                        if !text_acc.is_empty() { text_acc.push('\n'); }
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
                return Ok(DispatchOutcome::Idle { final_text: text_acc });
            }

            // Execute each tool_use in declaration order, building
            // one composite user message with the matching
            // tool_result blocks.
            let mut next_user_blocks: Vec<ContentBlock> = Vec::with_capacity(tool_uses.len());
            for (tu_id, tool_name, input) in &tool_uses {
                // Terminal tool? Short-circuit with the model's input.
                if self.terminal_tools.iter().any(|n| *n == tool_name.as_str()) {
                    // Execute the terminal tool one last time so its
                    // output is observable + auditable BEFORE we
                    // return. If the terminal tool isn't registered
                    // (e.g. in tests), surface an Idle outcome with
                    // the last text, NOT a hard error — the caller
                    // can synthesize the IPC intent from `input`.
                    let output = match self.registry.get(tool_name) {
                        Some(tool) => tool.execute(input, &self.ctx).await
                            .unwrap_or_else(|e| ToolOutput::err(e.to_string())),
                        None => ToolOutput::ok(format!(
                            "<terminal tool {tool_name:?} not in registry; \
                             dispatch loop returning input verbatim>"
                        )),
                    };
                    return Ok(DispatchOutcome::TerminalTool {
                        tool_name: tool_name.clone(),
                        input:     input.clone(),
                        output,
                    });
                }
                let output = match self.registry.get(tool_name) {
                    Some(tool) => match tool.execute(input, &self.ctx).await {
                        Ok(o)  => o,
                        Err(e) => ToolOutput::err(e.to_string()),
                    },
                    None => ToolOutput::err(format!(
                        "unknown tool: {tool_name:?}"
                    )),
                };
                next_user_blocks.push(ContentBlock::ToolResult {
                    tool_use_id: tu_id.clone(),
                    content:     output.content,
                    is_error:    output.is_error,
                });
            }
            messages.push(Message {
                role:    "user".to_owned(),
                content: next_user_blocks,
            });
            let _ = turn; // turn is implicit in the for-loop counter.
        }

        Ok(DispatchOutcome::MaxTurnsExceeded {
            turns: self.config.max_turns,
        })
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
            id:    "msg-end".to_owned(),
            kind:  "message".to_owned(),
            role:  "assistant".to_owned(),
            content: vec![ContentBlock::Text {
                text: text.to_owned(),
            }],
            stop_reason: Some("end_turn".to_owned()),
            usage: Usage::default(),
            model: "claude-sonnet-4-5-20250929".to_owned(),
        }
    }

    fn tool_use_response(tool_use_id: &str, name: &str, input: serde_json::Value) -> MessageResponse {
        MessageResponse {
            id:    format!("msg-call-{tool_use_id}"),
            kind:  "message".to_owned(),
            role:  "assistant".to_owned(),
            content: vec![ContentBlock::ToolUse {
                id:    tool_use_id.to_owned(),
                name:  name.to_owned(),
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
        let model = Arc::new(MockModelClient::new(vec![
            empty_response_end_turn("done!"),
        ]));
        let registry = Arc::new(crate::tools::build_executor_registry());
        let ws = fixture_workspace();
        let mut d = DispatchLoop::new(
            model,
            registry,
            DispatchConfig::new("test-model"),
            ToolContext::for_workspace(ws.path()),
        );
        let out = d.run(
            "system prompt".to_owned(),
            "seed user message".to_owned(),
        ).await.unwrap();
        match out {
            DispatchOutcome::Idle { final_text } => {
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
            "tu1", "read_file",
            serde_json::json!({ "path": "hello.txt" }),
        );
        let r2 = empty_response_end_turn("read it");
        let model    = Arc::new(MockModelClient::new(vec![r1, r2]));
        let registry = Arc::new(crate::tools::build_executor_registry());
        let ws       = fixture_workspace();
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
        assert_eq!(t2.messages.len(), 3,
            "turn 2 must include the tool_result reply, got {} messages",
            t2.messages.len());
        let last = &t2.messages[2];
        assert_eq!(last.role, "user");
        match &last.content[0] {
            ContentBlock::ToolResult { tool_use_id, content, is_error } => {
                assert_eq!(tool_use_id, "tu1");
                assert_eq!(content, "hi from raxis",
                    "tool_result content must echo read_file output");
                assert_eq!(*is_error, None);
            }
            other => panic!("expected ToolResult, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn unknown_tool_surfaces_as_structured_error_to_model() {
        let r1 = tool_use_response(
            "tu1", "no_such_tool",
            serde_json::json!({}),
        );
        let r2 = empty_response_end_turn("recovered");
        let model    = Arc::new(MockModelClient::new(vec![r1, r2]));
        let captured = model.seen.clone();
        let registry = Arc::new(crate::tools::build_executor_registry());
        let ws       = fixture_workspace();

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
            ContentBlock::ToolResult { is_error, content, .. } => {
                assert_eq!(*is_error, Some(true));
                assert!(content.contains("unknown tool"));
            }
            other => panic!("expected error ToolResult, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn terminal_tool_short_circuits_loop() {
        let r1 = tool_use_response(
            "tu1", "task_complete",
            serde_json::json!({ "head_sha": "abc123def456" }),
        );
        // No second response queued: the dispatch loop must
        // short-circuit on the terminal tool BEFORE asking the
        // model again.
        let model    = Arc::new(MockModelClient::new(vec![r1]));
        let registry = Arc::new(crate::tools::build_executor_registry());
        let ws       = fixture_workspace();
        let mut d = DispatchLoop::new(
            model,
            registry,
            DispatchConfig::new("test-model"),
            ToolContext::for_workspace(ws.path()),
        ).with_terminal_tools(vec!["task_complete"]);
        let out = d.run("sys".to_owned(), "seed".to_owned()).await.unwrap();
        match out {
            DispatchOutcome::TerminalTool { tool_name, input, .. } => {
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
                &format!("tu{i}"), "read_file",
                serde_json::json!({ "path": "hello.txt" }),
            ));
        }
        let model    = Arc::new(MockModelClient::new(queue));
        let registry = Arc::new(crate::tools::build_executor_registry());
        let ws       = fixture_workspace();
        let mut cfg  = DispatchConfig::new("test-model");
        cfg.max_turns = 3;
        let mut d = DispatchLoop::new(
            model, registry, cfg,
            ToolContext::for_workspace(ws.path()),
        );
        let out = d.run("sys".to_owned(), "seed".to_owned()).await.unwrap();
        match out {
            DispatchOutcome::MaxTurnsExceeded { turns } => {
                assert_eq!(turns, 3);
            }
            other => panic!("expected MaxTurnsExceeded, got {other:?}"),
        }
    }
}

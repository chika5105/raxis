//! High-level driver — promotes the three role binaries' `main()`
//! from "boot, log, park on SIGTERM" scaffolds to a real agent
//! loop end-to-end.
//!
//! Closes V2_GAPS.md §B1 substep `gap-b1-planner-binary-wiring` by
//! giving each binary a single entry point that:
//!
//! 1. Parses the env-contract the kernel stamps at spawn time
//!    (`RAXIS_KERNEL_PLANNER_SOCKET`, `RAXIS_PLANNER_TASK_PROMPT`,
//!    optional `RAXIS_MODEL_ID`, etc.).
//! 2. Falls back to the scaffold "park on signal" behaviour when
//!    the contract is **not** populated, so the existing kernel
//!    integration tests + V2 boot path continue to work
//!    bit-for-bit. The toggle is "is `RAXIS_PLANNER_TASK_PROMPT`
//!    present and non-empty?" — if no, the binary parks; if yes,
//!    the binary runs the agent loop.
//! 3. Builds the role-specific tool registry, the
//!    [`crate::dispatch::DispatchLoop`], and an
//!    [`crate::intent::IntentSubmitter`] over a UDS connection to
//!    the kernel.
//! 4. Renders the role-specific system prompt + KSB.
//! 5. Drives one [`DispatchLoop::run`] to a terminal outcome.
//! 6. Converts the terminal tool into the matching IPC intent
//!    (executor: `task_complete` / `single_commit` /
//!    `report_failure`; reviewer: `submit_review`; orchestrator:
//!    `integration_merge` / `activate_subtask` / `retry_subtask`).
//! 7. Returns a structured [`DriverOutcome`] the binary's `main`
//!    folds into a process exit code.
//!
//! ## Why a separate module rather than three forked `main`s
//!
//! The three role binaries differ only in:
//!
//! * Argv shape (orchestrator: no `--task-id`).
//! * Tool registry (executor has write tools; reviewer is
//!   read-only; orchestrator is read-only + DAG).
//! * Terminal-tool taxonomy (executor: `task_complete` /
//!   `single_commit` / `report_failure`; reviewer: `submit_review`;
//!   orchestrator: `integration_merge` / `activate_subtask` /
//!   `retry_subtask`).
//! * Seed prompt language ("you are an executor for task X" vs
//!   "you are a reviewer of evaluation_sha Y").
//!
//! Everything else — env parsing, transport setup, loop driver,
//! intent submission, error conversion — is identical. The driver
//! concentrates the shared logic and exposes one
//! [`run_role_session`] entry point each binary calls; the result
//! is three role mains of < 30 lines each instead of three
//! 200-line copies.
//!
//! ## Live-mode env contract (kernel-stamped)
//!
//! | Variable                       | Required for live mode? | Default                              | Purpose                                    |
//! |--------------------------------|-------------------------|--------------------------------------|--------------------------------------------|
//! | `RAXIS_SESSION_TOKEN`          | yes (already in [`crate::BootEnv`]) | —                          | Session-auth token for the kernel UDS      |
//! | `RAXIS_PLANNER_TASK_PROMPT`    | **yes — toggle**        | absent ⇒ scaffold/park               | Seed user message for the dispatch loop     |
//! | `RAXIS_PLANNER_KSB`            | no (test-only fallback) | absent ⇒ NNSP-only system prompt     | JSON-encoded [`raxis_ksb::KsbSnapshot`] §2.4 |
//! | `RAXIS_KERNEL_PLANNER_SOCKET`  | yes (live mode only)    | —                                    | UDS path to `<data_dir>/sockets/planner.sock` |
//! | `RAXIS_PLANNER_BASE_URL`       | no                      | `https://api.anthropic.com`          | Model API base URL — tests override         |
//! | `RAXIS_MODEL_ID`               | no                      | [`crate::DEFAULT_MODEL`]             | Model id stamped into every request         |
//! | `RAXIS_WORKSPACE_PATH`         | no                      | `/workspace`                         | Tool sandbox root                           |
//! | `RAXIS_PLANNER_MAX_TURNS`      | no                      | `20`                                 | Hard turn ceiling per session               |
//! | `RAXIS_PLANNER_MAX_TOKENS`     | no                      | `4096`                               | Per-request `max_tokens`                    |
//!
//! When `RAXIS_PLANNER_TASK_PROMPT` is **absent or empty**, the
//! driver returns [`DriverOutcome::Scaffold`] without contacting
//! the kernel. The binary's `main` then parks on Ctrl-C/SIGTERM
//! exactly as the V2.3 scaffold did. This means:
//!
//! * Existing kernel integration tests (mock-planner harness, the
//!   `kernel/tests/mock_planner_end_to_end.rs` battery, the
//!   `live-e2e` slices that don't yet stamp the contract) keep
//!   passing without any changes.
//! * The kernel can flip a session into live mode on a per-spawn
//!   basis by populating `extra_env` — no rebuild required.
//!
//! ## Why the driver makes direct HTTPS calls (not gateway IPC)
//!
//! Per `peripherals.md §3.2` the planner role binary's
//! `AnthropicClient` makes an *unauthenticated* HTTPS call against
//! its base URL. In production the in-VM tproxy redirects that
//! call to the host-side gateway; the gateway injects the
//! credential and forwards. In subprocess-isolation tests there is
//! no tproxy, so the test harness either points
//! `RAXIS_PLANNER_BASE_URL` at a local mock or uses the gateway's
//! `FetchRequest` IPC out-of-band. **The driver never sees a
//! credential** — that is the load-bearing structural invariant
//! that lets us re-use the same dispatch path under both isolation
//! backends.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use thiserror::Error;

use raxis_types::TaskId;

use crate::dispatch::{DispatchConfig, DispatchError, DispatchLoop, DispatchOutcome};
use crate::intent::{
    executor_terminal_tool_to_intent_kind, orchestrator_terminal_tool_to_intent_kind,
    reviewer_terminal_tool_to_intent_kind, IntentSubmitter, SubmitError,
};
use crate::model::{AnthropicClient, ModelClient};
use crate::provider_model::{resolve_model_from_env_fn, ProviderModelError};
use crate::tools::{
    build_executor_registry, build_orchestrator_registry, build_reviewer_registry, ToolContext,
    ToolRegistry,
};
use crate::transport::{KernelTransport, KernelTransportConfig, TransportError};
use crate::{BootArgs, BootEnv, Role};

/// Default base URL when `RAXIS_PLANNER_BASE_URL` is unset.
///
/// Production planners hit `https://api.anthropic.com`; tproxy +
/// gateway intercept and inject credentials transparently. Tests
/// override this env var to point at a local mock server.
pub const DEFAULT_PLANNER_BASE_URL: &str = "https://api.anthropic.com";

/// Default workspace mount point — matches what the
/// `session-spawn` substrate stamps into Firecracker / Apple-VZ /
/// subprocess guests when no override is set.
pub const DEFAULT_WORKSPACE_PATH: &str = "/workspace";

/// Default per-session max turns. Mirrors
/// [`DispatchConfig::new`] so the driver and the dispatch loop
/// share one source of truth.
pub const DEFAULT_PLANNER_MAX_TURNS: u32 = 20;

/// Default per-request max-tokens. Mirrors
/// [`DispatchConfig::new`].
pub const DEFAULT_PLANNER_MAX_TOKENS: u32 = 4096;

/// V2 `v2_extended_gaps.md §2.5` — env var carrying the per-session
/// cumulative *input* token cap. Re-export of the canonical
/// declaration in [`raxis_types::planner_env`]; both crates need
/// the constant and `raxis-types` is the only one both depend on
/// without dragging the planner HTTP path into the kernel.
pub use raxis_types::planner_env::PLANNER_MAX_TOKENS_INPUT_TOTAL_ENV;

/// V2 `v2_extended_gaps.md §2.5` — env var carrying the per-session
/// cumulative *output* token cap.
pub use raxis_types::planner_env::PLANNER_MAX_TOKENS_OUTPUT_TOTAL_ENV;

/// V2 `v2_extended_gaps.md §2.5` — env var carrying the per-session
/// cumulative *combined* (input + output) token cap.
pub use raxis_types::planner_env::PLANNER_MAX_TOKENS_TOTAL_ENV;

/// What the binary's `main` does next after [`run_role_session`].
#[derive(Debug)]
pub enum DriverOutcome {
    /// `RAXIS_PLANNER_TASK_PROMPT` was unset / empty — V2 scaffold
    /// path. The binary's `main` parks on signal exactly like the
    /// V2.3 scaffolds did.
    Scaffold,
    /// Dispatch loop terminated; the matching terminal intent was
    /// submitted to the kernel and accepted. Process exits 0.
    Completed {
        /// Name of the terminal tool that fired (for stderr
        /// observability).
        tool_name: String,
    },
    /// Dispatch loop ran to `Idle` (model said it was done with no
    /// tool_use blocks). The driver does NOT auto-submit any
    /// intent; the kernel will treat this as "session ran but no
    /// terminal action was requested" — the role binary's main
    /// surfaces it as a `ReportFailure` if the role expects a
    /// terminal action, or a clean exit if `Idle` is acceptable.
    Idle {
        /// Joined assistant text from the last turn (capped to
        /// 4 KiB before logging).
        final_text: String,
    },
    /// `max_turns` ceiling tripped — we exit non-zero. Per
    /// `planner-harness.md INV-PLANNER-HARNESS-04`, this is the
    /// structured-failure surface the kernel observes when the
    /// dispatch loop runs away.
    MaxTurnsExceeded {
        /// Number of turns the loop ran (= [`DispatchConfig::max_turns`]).
        turns: u32,
    },
    /// Cumulative token ceiling tripped (see
    /// [`crate::dispatch::DispatchOutcome::TokensExceeded`]).
    TokensExceeded {
        /// `"input"` / `"output"` / `"total"` (stable wire string).
        which: &'static str,
        /// The configured ceiling.
        ceiling: u64,
    },
}

/// Anything that can go wrong before / during / after the
/// dispatch loop in live mode. Each variant maps to a stable
/// [`crate::PlannerError::exit_code`] in the binary's `main`.
#[derive(Debug, Error)]
pub enum DriverError {
    #[error("RAXIS_KERNEL_PLANNER_SOCKET is required in live mode")]
    KernelSocketMissing,

    #[error("RAXIS_PLANNER_BASE_URL must be a valid http(s) URL: got {got:?}")]
    BadBaseUrl { got: String },

    #[error("dispatch loop failed: {0}")]
    Dispatch(#[from] DispatchError),

    #[error("kernel transport: {0}")]
    Transport(#[from] TransportError),

    #[error("intent submission: {0}")]
    Submit(#[from] SubmitError),

    #[error("provider/model resolution: {0}")]
    Provider(#[from] ProviderModelError),

    #[error("terminal tool {tool_name:?} produced an unmappable intent for role {role:?}")]
    UnmappableTerminal {
        /// The tool that fired.
        tool_name: String,
        /// The role binary that invoked the driver.
        role: Role,
    },

    /// A `task_id` (or `subtask_task_id`) emitted by the planner
    /// failed `raxis_types::TaskId::parse`. We surface the raw
    /// rejection text so operators can correlate against the
    /// `TaskId`-shape rules (non-empty, ≤ 128 bytes UTF-8, no
    /// control characters).
    #[error("invalid task id: {0}")]
    InvalidTaskId(String),

    /// V2 `v2_extended_gaps.md §2.4` — `raxis_ksb::assemble_system_prompt`
    /// rejected the kernel-projected snapshot. Practically only
    /// fires on `INV-KSB-01` violations (the kernel let through a
    /// field containing the close delimiter) or on an empty NNSP
    /// (a build bug). Both are kernel-side regressions surfaced
    /// by the planner-side defense-in-depth check; the binary
    /// fails closed rather than booting the dispatch loop with a
    /// torn system prompt.
    #[error("KSB assembly failed: {0}")]
    KsbAssembleFailed(String),
}

/// **Per-role driver entry point.** Called from the role binary's
/// `main()` after it has parsed argv + env into a
/// [`crate::BootContext`].
///
/// Behaviour matrix:
///
/// 1. If `RAXIS_PLANNER_TASK_PROMPT` is **unset or empty**, returns
///    `Ok(`[`DriverOutcome::Scaffold`]`)` immediately. The role
///    binary's `main` parks on signal.
/// 2. Otherwise, runs the full dispatch loop end-to-end. The loop
///    resolves the model id (`RAXIS_MODEL_ID` or
///    [`crate::DEFAULT_MODEL`]) through the registry, connects to
///    the kernel UDS at `RAXIS_KERNEL_PLANNER_SOCKET`, builds the
///    role-specific [`ToolRegistry`] + [`DispatchLoop`], renders
///    the role-specific seed system prompt, runs the loop, and
///    converts the terminal outcome to a [`DriverOutcome`] +
///    (when applicable) submits the matching IPC intent.
pub async fn run_role_session(
    role: Role,
    args: BootArgs,
    env: BootEnv,
) -> Result<DriverOutcome, DriverError> {
    run_role_session_with_env_fn(role, args, env, |k| std::env::var(k).ok()).await
}

/// Test-friendly variant — accepts the env reader as a closure so
/// hermetic unit tests don't have to mutate process-global state
/// (which is `unsafe` under the workspace's
/// `#![deny(unsafe_code)]` lint policy). The closure shape mirrors
/// `std::env::var(_).ok()` for ergonomic parity with
/// [`BootEnv::from_env_fn`].
pub async fn run_role_session_with_env_fn<F>(
    role: Role,
    args: BootArgs,
    env: BootEnv,
    f: F,
) -> Result<DriverOutcome, DriverError>
where
    F: Fn(&str) -> Option<String>,
{
    let var = |k: &str| f(k).filter(|v| !v.is_empty());
    let task_prompt = match var("RAXIS_PLANNER_TASK_PROMPT") {
        Some(p) => p,
        // INV-DRIVER-01: scaffold/park is the *only* behaviour for
        // a session whose seed prompt was not stamped. We MUST NOT
        // synthesise a default prompt here — that would let a
        // mis-configured kernel boot a planner against a runaway
        // model with no operator-supplied instructions, which is
        // exactly what the env-contract defends against.
        None => return Ok(DriverOutcome::Scaffold),
    };

    let kernel_socket = var("RAXIS_KERNEL_PLANNER_SOCKET")
        .ok_or(DriverError::KernelSocketMissing)?;
    let base_url = var("RAXIS_PLANNER_BASE_URL")
        .unwrap_or_else(|| DEFAULT_PLANNER_BASE_URL.to_owned());
    if !(base_url.starts_with("http://") || base_url.starts_with("https://")) {
        return Err(DriverError::BadBaseUrl { got: base_url });
    }
    let workspace = var("RAXIS_WORKSPACE_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_WORKSPACE_PATH));
    let model_id = resolve_model_from_env_fn(&f)?.name.to_owned();
    let max_turns = var("RAXIS_PLANNER_MAX_TURNS")
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(DEFAULT_PLANNER_MAX_TURNS);
    let max_tokens = var("RAXIS_PLANNER_MAX_TOKENS")
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(DEFAULT_PLANNER_MAX_TOKENS);

    // V2 `v2_extended_gaps.md §2.5` — read the kernel-stamped
    // per-session token caps. Absent / unparseable → `None`, which
    // leaves the corresponding `DispatchConfig` ceiling uncapped
    // (matches today's behaviour for unmigrated policies).
    let max_tokens_input_total  = parse_u64_env(&f, PLANNER_MAX_TOKENS_INPUT_TOTAL_ENV);
    let max_tokens_output_total = parse_u64_env(&f, PLANNER_MAX_TOKENS_OUTPUT_TOTAL_ENV);
    let max_tokens_total        = parse_u64_env(&f, PLANNER_MAX_TOKENS_TOTAL_ENV);

    // V2 `v2_extended_gaps.md §2.4` — read the kernel-stamped KSB
    // env var. Absent / unparseable → `None`, which the
    // dispatch-loop seam uses to fall back to the NNSP-only system
    // prompt (test-only fallback path; in production every
    // kernel-spawned session has a parseable snapshot stamped).
    let ksb_snapshot = var(raxis_ksb::PLANNER_KSB_ENV).and_then(|raw| {
        match serde_json::from_str::<raxis_ksb::KsbSnapshot>(&raw) {
            Ok(snap) => Some(snap),
            Err(e) => {
                eprintln!(
                    "{{\"level\":\"warn\",\"event\":\"planner_ksb_parse_failed\",\
                     \"err\":\"{e}\"}}",
                );
                None
            }
        }
    });

    let model: Arc<dyn ModelClient> = Arc::new(AnthropicClient::new(base_url));
    let token_caps = TokenCaps {
        input_total:  max_tokens_input_total,
        output_total: max_tokens_output_total,
        total:        max_tokens_total,
    };
    run_role_session_with_model(
        role,
        args,
        env,
        task_prompt,
        kernel_socket,
        workspace,
        model_id,
        max_turns,
        max_tokens,
        token_caps,
        model,
        ksb_snapshot,
    )
    .await
}

/// V2 `v2_extended_gaps.md §2.5` — bundle of optional per-session
/// LLM token ceilings. Each axis is independently optional; absent
/// fields leave the corresponding `DispatchConfig` cap unbounded
/// (the in-VM dispatch loop only enforces present caps).
#[derive(Debug, Clone, Copy, Default)]
pub struct TokenCaps {
    /// Cumulative input-token cap across the session
    /// (`DispatchConfig::max_tokens_input_total`).
    pub input_total:  Option<u64>,
    /// Cumulative output-token cap across the session
    /// (`DispatchConfig::max_tokens_output_total`).
    pub output_total: Option<u64>,
    /// Cumulative combined-token cap across the session
    /// (`DispatchConfig::max_tokens_total`).
    pub total:        Option<u64>,
}

/// Helper for `run_role_session_with_env_fn` — parse a `u64` from a
/// kernel-stamped env var, returning `None` for absent or
/// unparseable values. We log the parse failure on stderr so a
/// kernel-side regression doesn't silently disable enforcement.
fn parse_u64_env<F: Fn(&str) -> Option<String>>(f: &F, name: &str) -> Option<u64> {
    let raw = f(name)?;
    match raw.parse::<u64>() {
        Ok(n) => Some(n),
        Err(e) => {
            eprintln!(
                "{{\"level\":\"warn\",\"event\":\"planner_token_cap_parse_failed\",\
                 \"env\":\"{name}\",\"raw\":\"{raw}\",\"err\":\"{e}\"}}",
            );
            None
        }
    }
}

/// Test-friendly variant — accepts the model client as an
/// `Arc<dyn ModelClient>` so unit / integration tests can pin a
/// [`crate::model::MockModelClient`] without touching the live
/// `AnthropicClient` HTTP path.
///
/// All other inputs are pre-resolved (no further env reads), so
/// this entry point is fully deterministic.
///
/// V2 `v2_extended_gaps.md §2.4` — `ksb_snapshot` carries the
/// kernel-projected per-turn KSB. When `Some(snap)`, the system
/// prompt is composed by `raxis_ksb::assemble_system_prompt(NNSP,
/// snap)` so the model sees authoritative kernel state inside the
/// `[RAXIS:KERNEL_STATE … :KERNEL_STATE_END]` delimiters every
/// turn. When `None` (test fixtures / legacy fallback), the system
/// prompt is the NNSP-only blurb.
#[allow(clippy::too_many_arguments)]
pub async fn run_role_session_with_model(
    role: Role,
    args: BootArgs,
    env: BootEnv,
    task_prompt: String,
    kernel_socket: String,
    workspace: PathBuf,
    model_id: String,
    max_turns: u32,
    max_tokens: u32,
    token_caps: TokenCaps,
    model: Arc<dyn ModelClient>,
    ksb_snapshot: Option<raxis_ksb::KsbSnapshot>,
) -> Result<DriverOutcome, DriverError> {
    // ── Step 1: connect to the kernel UDS. ──────────────────────────
    let cfg = KernelTransportConfig::Uds {
        socket_path: PathBuf::from(&kernel_socket),
    };
    let transport: Arc<dyn KernelTransport> = crate::transport::connect(&cfg).await?;

    // ── Step 2: build per-role registry + terminal tool list. ───────
    let (registry, terminal_tools) = build_role(role);
    let registry = Arc::new(registry);

    // ── Step 3: configure dispatch loop. ────────────────────────────
    let mut config = DispatchConfig::new(model_id);
    config.max_turns = max_turns;
    config.max_tokens = max_tokens;
    // V2 `v2_extended_gaps.md §2.5` — fold the per-session token caps
    // into the dispatch config. The dispatch loop already enforces
    // these via `check_ceilings` → `DispatchOutcome::TokensExceeded`;
    // we just thread the kernel-stamped values through.
    config.max_tokens_input_total  = token_caps.input_total;
    config.max_tokens_output_total = token_caps.output_total;
    config.max_tokens_total        = token_caps.total;
    let ctx = ToolContext::for_workspace(workspace);
    let mut loop_ = DispatchLoop::new(model, Arc::clone(&registry), config, ctx)
        .with_terminal_tools(terminal_tools.clone());

    // ── Step 4: render system prompt. V2 §2.4 — fold the KSB into
    //    the role-specific NNSP via `assemble_system_prompt` when
    //    the kernel stamped a snapshot. Falls back to NNSP-only when
    //    the env var is absent or failed to parse (logged upstream).
    let role_nnsp = render_system_prompt_for_role(role, &args);
    let system_prompt = match ksb_snapshot.as_ref() {
        Some(snap) => raxis_ksb::assemble_system_prompt(&role_nnsp, snap)
            .map_err(|e| DriverError::KsbAssembleFailed(e.to_string()))?,
        None => role_nnsp,
    };

    // ── Step 5: run the loop. ───────────────────────────────────────
    let outcome = loop_.run(system_prompt, task_prompt).await?;

    // ── Step 6: convert terminal outcome → IPC intent / DriverOutcome.
    // Orchestrator sessions don't carry a `--task-id`, so we fall
    // back to the initiative id — the kernel uses the session-token
    // dimension for orchestrator authority and ignores the task id
    // on `IntegrationMerge` / `ActivateSubTask` framing.
    let task_id_owned = args
        .task_id
        .clone()
        .unwrap_or_else(|| args.initiative_id.clone());
    let task_id = TaskId::parse(&task_id_owned).map_err(|e| {
        DriverError::InvalidTaskId(format!(
            "task id `{task_id_owned}` failed validation: {e}"
        ))
    })?;
    let submitter = IntentSubmitter::new(transport, env.session_token.clone(), task_id);

    match outcome {
        DispatchOutcome::TerminalTool {
            tool_name, input, output: _,
        } => {
            submit_terminal(role, &submitter, &tool_name, &input).await?;
            Ok(DriverOutcome::Completed { tool_name })
        }
        DispatchOutcome::Idle { final_text } => Ok(DriverOutcome::Idle { final_text }),
        DispatchOutcome::MaxTurnsExceeded { turns } => {
            Ok(DriverOutcome::MaxTurnsExceeded { turns })
        }
        DispatchOutcome::TokensExceeded {
            which, ceiling, ..
        } => Ok(DriverOutcome::TokensExceeded { which, ceiling }),
    }
}

/// Build the role-specific tool registry + terminal-tool name list.
fn build_role(role: Role) -> (ToolRegistry, Vec<&'static str>) {
    match role {
        Role::Executor => (
            build_executor_registry(),
            vec!["task_complete", "single_commit", "report_failure"],
        ),
        Role::Reviewer => (build_reviewer_registry(), vec!["submit_review"]),
        Role::Orchestrator => (
            build_orchestrator_registry(),
            vec!["integration_merge", "activate_subtask", "retry_subtask"],
        ),
    }
}

/// Render the role-specific system prompt prefix. Per
/// `kernel-mechanics-prompt.md`, the system prompt = NNSP +
/// (eventually) the [`crate::ksb::render_ksb`] block. The V2.4
/// driver ships the NNSP-only first leg; the in-VM KSB renderer
/// runs on the live KSB once the orchestrator-side push transport
/// (V3, V2_GAPS §12.1) lands.
fn render_system_prompt_for_role(role: Role, args: &BootArgs) -> String {
    let role_blurb = match role {
        Role::Executor => "You are the RAXIS executor agent for task `{TASK}` of \
                          initiative `{INIT}`. Make code changes that satisfy the \
                          task description, then call `task_complete` with the \
                          head SHA, or `report_failure` with a justification if you \
                          cannot complete the task.",
        Role::Reviewer => "You are the RAXIS reviewer for task `{TASK}` of \
                          initiative `{INIT}`. Evaluate the executor's commit \
                          against the task description, then call \
                          `submit_review { approved: bool, critique?: string }` \
                          to deliver your verdict.",
        Role::Orchestrator => "You are the RAXIS orchestrator for initiative \
                              `{INIT}`. Drive the DAG of tasks: activate ready \
                              sub-tasks via `activate_subtask`, retry stuck \
                              sub-tasks via `retry_subtask`, and merge completed \
                              work via `integration_merge`.",
    };
    let task_repr = args.task_id.as_deref().unwrap_or("(no task id)");
    role_blurb
        .replace("{TASK}", task_repr)
        .replace("{INIT}", &args.initiative_id)
}

/// Translate a dispatch-loop terminal tool firing into the
/// matching [`IntentKind`] and submit it through the
/// [`IntentSubmitter`].
async fn submit_terminal(
    role: Role,
    submitter: &IntentSubmitter,
    tool_name: &str,
    input: &serde_json::Value,
) -> Result<(), DriverError> {
    let kind = match role {
        Role::Executor => executor_terminal_tool_to_intent_kind(tool_name),
        Role::Reviewer => reviewer_terminal_tool_to_intent_kind(tool_name),
        Role::Orchestrator => orchestrator_terminal_tool_to_intent_kind(tool_name),
    }
    .ok_or_else(|| DriverError::UnmappableTerminal {
        tool_name: tool_name.to_owned(),
        role,
    })?;

    use raxis_types::IntentKind;
    match kind {
        IntentKind::CompleteTask => {
            let head = pick_str(input, "head_sha").unwrap_or_default();
            submitter.submit_complete_task(&head).await?;
        }
        IntentKind::SingleCommit => {
            let base = pick_str(input, "base_sha").unwrap_or_default();
            let head = pick_str(input, "head_sha").unwrap_or_default();
            submitter.submit_single_commit(&base, &head).await?;
        }
        IntentKind::ReportFailure => {
            let justification = pick_str(input, "justification").unwrap_or_default();
            submitter.submit_report_failure(justification).await?;
        }
        IntentKind::IntegrationMerge => {
            let base = pick_str(input, "base_sha").unwrap_or_default();
            let head = pick_str(input, "head_sha").unwrap_or_default();
            submitter.submit_integration_merge(&base, &head).await?;
        }
        IntentKind::ActivateSubTask => {
            let id = pick_str(input, "subtask_task_id").unwrap_or_default();
            let parsed = TaskId::parse(&id).map_err(|e| {
                DriverError::InvalidTaskId(format!(
                    "subtask_task_id `{id}` failed validation: {e}"
                ))
            })?;
            submitter.submit_activate_subtask(parsed).await?;
        }
        IntentKind::RetrySubTask => {
            let id = pick_str(input, "subtask_task_id").unwrap_or_default();
            let parsed = TaskId::parse(&id).map_err(|e| {
                DriverError::InvalidTaskId(format!(
                    "subtask_task_id `{id}` failed validation: {e}"
                ))
            })?;
            submitter.submit_retry_subtask(parsed).await?;
        }
        IntentKind::SubmitReview => {
            let approved = input
                .get("approved")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false);
            let critique = pick_str(input, "critique");
            submitter.submit_review(approved, critique).await?;
        }
    }
    let _ = role;
    Ok(())
}

fn pick_str(v: &serde_json::Value, key: &str) -> Option<String> {
    v.get(key)
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
}

/// Park on Ctrl-C / SIGTERM. The role binary's `main` calls this
/// when [`run_role_session`] returns
/// [`DriverOutcome::Scaffold`] — preserves the V2.3 scaffold
/// behaviour bit-for-bit.
pub async fn park_on_signal() {
    let _ = tokio::signal::ctrl_c().await;
    // Belt-and-braces: a 5 ms sleep so a SIGTERM-driven shutdown
    // doesn't race the structured stderr drain the kernel-side
    // log scraper expects.
    tokio::time::sleep(Duration::from_millis(5)).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{ContentBlock, MessageResponse, MockModelClient, Usage};

    #[test]
    fn build_role_executor_includes_write_tools() {
        let (reg, terminals) = build_role(Role::Executor);
        assert!(reg.get("git_commit").is_some());
        assert!(reg.get("edit_file").is_some());
        assert!(reg.get("bash").is_some());
        assert!(terminals.contains(&"task_complete"));
        assert!(terminals.contains(&"report_failure"));
        assert!(terminals.contains(&"single_commit"));
    }

    #[test]
    fn build_role_reviewer_excludes_write_tools_and_pins_terminal() {
        let (reg, terminals) = build_role(Role::Reviewer);
        // INV-PLANNER-HARNESS-04: reviewer must not have write
        // tools.
        assert!(reg.get("edit_file").is_none());
        assert!(reg.get("bash").is_none());
        assert!(reg.get("git_commit").is_none());
        // Read-only tools present:
        assert!(reg.get("read_file").is_some());
        assert!(reg.get("grep_search").is_some());
        // Single terminal: submit_review.
        assert_eq!(terminals, vec!["submit_review"]);
    }

    #[test]
    fn build_role_orchestrator_pins_dag_terminals() {
        let (reg, terminals) = build_role(Role::Orchestrator);
        assert!(reg.get("read_file").is_some());
        assert_eq!(
            terminals,
            vec!["integration_merge", "activate_subtask", "retry_subtask"]
        );
    }

    #[test]
    fn render_system_prompt_substitutes_task_and_initiative_for_executor() {
        let args = BootArgs {
            initiative_id: "init-A".to_owned(),
            task_id: Some("task-1".to_owned()),
        };
        let prompt = render_system_prompt_for_role(Role::Executor, &args);
        assert!(prompt.contains("task `task-1`"));
        assert!(prompt.contains("initiative `init-A`"));
        assert!(prompt.contains("task_complete"));
        assert!(prompt.contains("report_failure"));
    }

    #[test]
    fn render_system_prompt_for_orchestrator_uses_no_task_label() {
        let args = BootArgs {
            initiative_id: "init-A".to_owned(),
            task_id: None,
        };
        let prompt = render_system_prompt_for_role(Role::Orchestrator, &args);
        assert!(prompt.contains("initiative `init-A`"));
        assert!(prompt.contains("activate_subtask"));
        assert!(prompt.contains("integration_merge"));
    }

    #[test]
    fn pick_str_returns_inner_string() {
        let v = serde_json::json!({ "k": "value" });
        assert_eq!(pick_str(&v, "k"), Some("value".to_owned()));
        assert_eq!(pick_str(&v, "missing"), None);
        let nested = serde_json::json!({ "k": { "nested": "x" } });
        assert_eq!(pick_str(&nested, "k"), None); // not a string
    }

    /// V2 `v2_extended_gaps.md §2.4` — when the kernel stamps
    /// `RAXIS_PLANNER_KSB`, the driver folds the snapshot into the
    /// system prompt via `assemble_system_prompt`. The recorded
    /// `MockModelClient` request MUST contain the
    /// `[RAXIS:KERNEL_STATE … :KERNEL_STATE_END]` block + the
    /// snapshot's specific field values verbatim.
    #[tokio::test]
    async fn run_role_session_with_model_folds_ksb_snapshot_into_system_prompt() {
        use raxis_ksb::KsbSnapshot;

        let model = Arc::new(MockModelClient::new(vec![MessageResponse {
            id: "msg_1".to_owned(),
            kind: "message".to_owned(),
            role: "assistant".to_owned(),
            model: "mock".to_owned(),
            content: vec![ContentBlock::Text {
                text: "ack".to_owned(),
            }],
            stop_reason: Some("end_turn".to_owned()),
            usage: Usage {
                input_tokens: 1,
                output_tokens: 1,
                cache_creation_input_tokens: 0,
                cache_read_input_tokens: 0,
            },
        }]));
        let model_for_inspect: Arc<MockModelClient> = Arc::clone(&model);

        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("planner.sock");
        let listener = tokio::net::UnixListener::bind(&sock_path).unwrap();
        tokio::spawn(async move {
            while let Ok((_s, _)) = listener.accept().await {}
        });

        let snap = KsbSnapshot {
            version:                       raxis_ksb::KSB_SCHEMA_VERSION,
            initiative_id:                 "init-FOLD".to_owned(),
            task_id:                       Some("task-FOLD".to_owned()),
            role:                          "executor".to_owned(),
            evaluation_sha:                "eval-sha-fold".to_owned(),
            path_allowlist:                vec!["src/fold.rs".to_owned()],
            token_budget_remaining:        77_777,
            wallclock_budget_remaining_s:  333,
            dag_rows:                      vec![],
            task_description:              "fold-test description".to_owned(),
            target_ref:                    "refs/heads/feature/fold".to_owned(),
            reviewer_verdicts:             vec![],
            pending_escalations:           vec![],
            credential_ports:              vec![],
        };

        let _ = run_role_session_with_model(
            Role::Executor,
            BootArgs {
                initiative_id: "init-FOLD".to_owned(),
                task_id: Some("task-FOLD".to_owned()),
            },
            BootEnv { session_token: "tok".to_owned() },
            "fold prompt".to_owned(),
            sock_path.display().to_string(),
            dir.path().to_path_buf(),
            "mock".to_owned(),
            5,
            512,
            TokenCaps::default(),
            model as Arc<dyn ModelClient>,
            Some(snap),
        )
        .await
        .unwrap();

        let seen = model_for_inspect.seen.lock().await;
        let last = seen.last().expect("model received a request");
        let sys = last.system.as_deref().expect("system prompt populated");
        assert!(sys.contains(raxis_ksb::KSB_DELIMITER_OPEN),
            "system prompt MUST carry the KSB open delimiter; got: {sys}");
        assert!(sys.contains(raxis_ksb::KSB_DELIMITER_CLOSE),
            "system prompt MUST carry the KSB close delimiter; got: {sys}");
        assert!(sys.contains("initiative_id=init-FOLD"),
            "KSB block MUST stamp initiative_id verbatim; got: {sys}");
        assert!(sys.contains("task_id=task-FOLD"),
            "KSB block MUST stamp task_id verbatim; got: {sys}");
        assert!(sys.contains("target_ref=refs/heads/feature/fold"),
            "KSB block MUST stamp resolved target_ref; got: {sys}");
        assert!(sys.contains("- src/fold.rs"),
            "KSB block MUST stamp the per-task path allowlist; got: {sys}");
        assert!(sys.contains("token_budget_remaining=77777"),
            "KSB block MUST stamp the budget; got: {sys}");
        assert!(sys.contains("fold-test description"),
            "KSB block MUST stamp the task_description; got: {sys}");
    }

    /// V2 `v2_extended_gaps.md §2.4` — when no KSB snapshot is
    /// supplied (test fixtures, legacy boot path), the driver falls
    /// back to the NNSP-only system prompt. The KSB delimiters MUST
    /// NOT appear, otherwise downstream parsers would mistake an
    /// empty placeholder for a real kernel-state block.
    #[tokio::test]
    async fn run_role_session_with_model_uses_nnsp_only_when_no_ksb_supplied() {
        let model = Arc::new(MockModelClient::new(vec![MessageResponse {
            id: "msg_1".to_owned(),
            kind: "message".to_owned(),
            role: "assistant".to_owned(),
            model: "mock".to_owned(),
            content: vec![ContentBlock::Text {
                text: "ack".to_owned(),
            }],
            stop_reason: Some("end_turn".to_owned()),
            usage: Usage {
                input_tokens: 1,
                output_tokens: 1,
                cache_creation_input_tokens: 0,
                cache_read_input_tokens: 0,
            },
        }]));
        let model_for_inspect: Arc<MockModelClient> = Arc::clone(&model);

        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("planner.sock");
        let listener = tokio::net::UnixListener::bind(&sock_path).unwrap();
        tokio::spawn(async move {
            while let Ok((_s, _)) = listener.accept().await {}
        });

        let _ = run_role_session_with_model(
            Role::Executor,
            BootArgs {
                initiative_id: "init-NO-KSB".to_owned(),
                task_id: Some("task-NO-KSB".to_owned()),
            },
            BootEnv { session_token: "tok".to_owned() },
            "no-ksb prompt".to_owned(),
            sock_path.display().to_string(),
            dir.path().to_path_buf(),
            "mock".to_owned(),
            5,
            512,
            TokenCaps::default(),
            model as Arc<dyn ModelClient>,
            None,
        )
        .await
        .unwrap();

        let seen = model_for_inspect.seen.lock().await;
        let last = seen.last().expect("model received a request");
        let sys = last.system.as_deref().unwrap_or("");
        assert!(!sys.contains(raxis_ksb::KSB_DELIMITER_OPEN),
            "without a snapshot, system prompt MUST NOT contain KSB delimiters; got: {sys}");
    }

    /// Driver returns `Scaffold` when `RAXIS_PLANNER_TASK_PROMPT`
    /// is unset — the kernel's V2.3 mock-planner harness keeps
    /// working bit-for-bit. Hermetic via `_with_env_fn` so the
    /// test never touches process-global env (the workspace lints
    /// `unsafe_code = deny` and `std::env::set_var` is now unsafe
    /// on stable).
    #[tokio::test]
    async fn run_role_session_scaffolds_when_task_prompt_absent() {
        let env = BootEnv {
            session_token: "tok".to_owned(),
        };
        let args = BootArgs {
            initiative_id: "init-A".to_owned(),
            task_id: Some("task-1".to_owned()),
        };
        let outcome =
            run_role_session_with_env_fn(Role::Executor, args, env, |_| None)
                .await
                .unwrap();
        assert!(matches!(outcome, DriverOutcome::Scaffold));
    }

    /// End-to-end driver test: pinned `MockModelClient` drives the
    /// dispatch loop to `Idle` via a single `Text` block; the
    /// driver returns `Idle` (no IPC submission needed). This
    /// pins the `run_role_session_with_model` happy-path without
    /// requiring a live kernel UDS.
    #[tokio::test]
    async fn run_role_session_with_model_returns_idle_when_loop_finishes_without_terminal() {
        let model = Arc::new(MockModelClient::new(vec![MessageResponse {
            id: "msg_1".to_owned(),
            kind: "message".to_owned(),
            role: "assistant".to_owned(),
            model: "mock".to_owned(),
            content: vec![ContentBlock::Text {
                text: "all done".to_owned(),
            }],
            stop_reason: Some("end_turn".to_owned()),
            usage: Usage {
                input_tokens: 5,
                output_tokens: 7,
                cache_creation_input_tokens: 0,
                cache_read_input_tokens: 0,
            },
        }]));

        // We need a UDS socket to construct the IntentSubmitter
        // even though Idle never submits — bind a tempdir socket
        // that just accepts and drops connections.
        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("planner.sock");
        let listener = tokio::net::UnixListener::bind(&sock_path).unwrap();
        // Drain incoming connections in a background task — Idle
        // never sends a frame so the accept loop just owns the
        // listener.
        tokio::spawn(async move {
            while let Ok((_s, _)) = listener.accept().await {
                // drop the stream — driver doesn't talk to us in this test.
            }
        });

        let outcome = run_role_session_with_model(
            Role::Reviewer,
            BootArgs {
                initiative_id: "init-A".to_owned(),
                task_id: Some("task-1".to_owned()),
            },
            BootEnv {
                session_token: "tok".to_owned(),
            },
            "Please run a review.".to_owned(),
            sock_path.display().to_string(),
            dir.path().to_path_buf(),
            "mock".to_owned(),
            5,
            512,
            TokenCaps::default(),
            model,
            None,
        )
        .await
        .unwrap();

        match outcome {
            DriverOutcome::Idle { final_text } => assert_eq!(final_text, "all done"),
            other => panic!("expected Idle, got {other:?}"),
        }
    }

    /// Confirm that the driver fails fast on a clearly malformed
    /// base URL (no protocol prefix). The check fires *before* any
    /// HTTP construction, so the error is deterministic. Hermetic
    /// via `_with_env_fn` — see scaffold test rationale above.
    #[tokio::test]
    async fn run_role_session_rejects_base_url_without_scheme() {
        let env_fn = |k: &str| match k {
            "RAXIS_PLANNER_TASK_PROMPT"   => Some("do something".to_owned()),
            "RAXIS_KERNEL_PLANNER_SOCKET" => Some("/tmp/nope.sock".to_owned()),
            "RAXIS_PLANNER_BASE_URL"      => Some("ftp://api.anthropic.com".to_owned()),
            _ => None,
        };
        let res = run_role_session_with_env_fn(
            Role::Executor,
            BootArgs {
                initiative_id: "init-A".to_owned(),
                task_id: Some("task-1".to_owned()),
            },
            BootEnv {
                session_token: "tok".to_owned(),
            },
            env_fn,
        )
        .await;
        assert!(matches!(res, Err(DriverError::BadBaseUrl { .. })));
    }

    /// V2 `v2_extended_gaps.md §2.5` — `parse_u64_env` returns `None`
    /// for absent or unparseable values. Pinning the silent-skip
    /// contract: a kernel that fails to stamp the env var (because
    /// the operator omitted `[budget.token_caps]`) MUST leave the
    /// dispatch loop uncapped, not crash with a "missing env" error.
    #[test]
    fn parse_u64_env_returns_none_for_absent_and_garbage() {
        let absent  = |_: &str| None;
        let garbage = |k: &str| if k == "X" { Some("not-a-number".to_owned()) } else { None };
        let valid   = |k: &str| if k == "X" { Some("12345".to_owned()) } else { None };
        assert_eq!(parse_u64_env(&absent,  "X"), None);
        assert_eq!(parse_u64_env(&garbage, "X"), None);
        assert_eq!(parse_u64_env(&valid,   "X"), Some(12345));
    }

    /// V2 `v2_extended_gaps.md §2.5` — when the kernel stamps a
    /// per-session input-token cap into the planner env, the
    /// dispatch loop's `check_ceilings` MUST observe it and
    /// terminate post-turn with `DispatchOutcome::TokensExceeded`
    /// (which `run_role_session_with_model` lifts into
    /// `DriverOutcome::TokensExceeded`). This pins the env →
    /// `DispatchConfig` → enforcement chain end-to-end.
    #[tokio::test]
    async fn run_role_session_with_model_enforces_input_token_cap_from_token_caps() {
        // A single response that consumes 100 input tokens — well
        // above our 50-token cap. The dispatch loop must abort
        // after this one turn.
        let model = Arc::new(MockModelClient::new(vec![MessageResponse {
            id: "msg_1".to_owned(),
            kind: "message".to_owned(),
            role: "assistant".to_owned(),
            model: "mock".to_owned(),
            content: vec![ContentBlock::Text { text: "ack".to_owned() }],
            stop_reason: Some("end_turn".to_owned()),
            usage: Usage {
                input_tokens:                100,
                output_tokens:               1,
                cache_creation_input_tokens: 0,
                cache_read_input_tokens:     0,
            },
        }]));

        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("planner.sock");
        let listener = tokio::net::UnixListener::bind(&sock_path).unwrap();
        tokio::spawn(async move {
            while let Ok((_s, _)) = listener.accept().await {}
        });

        let outcome = run_role_session_with_model(
            Role::Reviewer,
            BootArgs {
                initiative_id: "init-CAP".to_owned(),
                task_id: Some("task-CAP".to_owned()),
            },
            BootEnv { session_token: "tok".to_owned() },
            "review please".to_owned(),
            sock_path.display().to_string(),
            dir.path().to_path_buf(),
            "mock".to_owned(),
            5,
            512,
            // Input cap of 50 < the 100 the model reports, so the
            // post-turn ceiling check fires.
            TokenCaps { input_total: Some(50), output_total: None, total: None },
            model as Arc<dyn ModelClient>,
            None,
        )
        .await
        .unwrap();

        match outcome {
            DriverOutcome::TokensExceeded { which, ceiling } => {
                assert_eq!(which, "input",
                    "input cap must trip first when only the input cap is configured");
                assert_eq!(ceiling, 50, "ceiling MUST be the cap we set");
            }
            other => panic!("expected TokensExceeded, got {other:?}"),
        }
    }
}

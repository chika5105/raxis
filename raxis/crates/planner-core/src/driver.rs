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
use crate::bedrock_client::BedrockClient;
use crate::gemini_client::GeminiClient;
use crate::model::{AnthropicClient, ModelClient};
use crate::openai_client::OpenAiClient;
use crate::provider_model::{
    resolve_model_from_env_fn, KnownModel, ProviderId, ProviderModelError,
};
use crate::sidecar_client::{SidecarConstructError, SidecarModelClient};
use crate::tools::{
    build_executor_registry, build_executor_registry_full, build_orchestrator_registry,
    build_orchestrator_registry_full, build_reviewer_registry, StructuredOutputTool, ToolContext,
    ToolRegistry,
};
use crate::transport::{KernelTransport, KernelTransportConfig, TransportError};
use crate::{BootArgs, BootEnv, Role};

/// V2_GAPS §C5 sidecar env vars (kernel-stamped per
/// `extensibility-traits.md §9A.5`).
///
/// The kernel resolves the operator-supplied
/// `policy.toml [[providers]] kind = "http_sidecar"` row and stamps
/// these three vars into the spawn envelope when the resolved
/// model maps to a sidecar provider; the planner uses them to
/// build a [`SidecarModelClient`] that signs every outbound body
/// with `HMAC-SHA256(secret, …)` per
/// `extensibility-traits.md §9A.7A`.
///
/// Re-exports of the canonical declarations in
/// [`raxis_types::planner_env`] so the kernel (writer) and the
/// planner-core driver (reader) stay in lock-step on the same set
/// of names.
pub use raxis_types::planner_env::{
    PLANNER_SIDECAR_ENDPOINT_ENV, PLANNER_SIDECAR_HMAC_SECRET_ENV,
    PLANNER_SIDECAR_PROVIDER_ID_ENV,
};

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
    /// None of the kernel-stamped transport env vars were set when
    /// the driver was launched in live mode (UDS path,
    /// VSock CID/port, or VSock listen-port). At least one is
    /// required so the planner knows where to find the kernel.
    #[error(
        "live-mode transport not configured: set RAXIS_KERNEL_PLANNER_SOCKET, \
         RAXIS_KERNEL_VSOCK_LISTEN_PORT, or RAXIS_KERNEL_VSOCK_CID + \
         RAXIS_KERNEL_VSOCK_PORT"
    )]
    KernelSocketMissing,

    /// `RAXIS_PLANNER_BASE_URL` did not parse as an `http(s)` URL.
    #[error("RAXIS_PLANNER_BASE_URL must be a valid http(s) URL: got {got:?}")]
    BadBaseUrl {
        /// The raw operator-supplied value that failed to parse.
        got: String,
    },

    /// The dispatch loop returned a terminal error (model or tool).
    #[error("dispatch loop failed: {0}")]
    Dispatch(#[from] DispatchError),

    /// The kernel transport (UDS framing) failed.
    #[error("kernel transport: {0}")]
    Transport(#[from] TransportError),

    /// Intent admission was rejected by the kernel.
    #[error("intent submission: {0}")]
    Submit(#[from] SubmitError),

    /// `RAXIS_PROVIDER` / `RAXIS_MODEL` resolution failed.
    #[error("provider/model resolution: {0}")]
    Provider(#[from] ProviderModelError),

    /// A terminal tool fired but its name does not map to any
    /// intent kind for this role binary.
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

    /// The planner resolved a [`ProviderId::Sidecar`] model but the
    /// per-spawn env contract was missing one of the required
    /// sidecar configuration vars (`RAXIS_PLANNER_SIDECAR_ENDPOINT`,
    /// `RAXIS_PLANNER_SIDECAR_PROVIDER_ID`,
    /// `RAXIS_PLANNER_SIDECAR_HMAC_SECRET`). Surface the missing
    /// env var by name so the operator can correlate against the
    /// kernel-side spawn audit event.
    #[error(
        "sidecar provider requires env var {var:?} (set by kernel from \
         policy.toml [[providers]] kind = \"http_sidecar\")"
    )]
    SidecarEnvMissing {
        /// Name of the missing env var.
        var: &'static str,
    },

    /// The sidecar client constructor rejected the operator-supplied
    /// HMAC secret. Wraps
    /// [`crate::sidecar_client::SidecarConstructError`] verbatim so
    /// the operator's audit trail keeps the rejection rationale.
    #[error("sidecar client construction failed: {0}")]
    SidecarConstruct(#[from] SidecarConstructError),
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

    // Resolve the kernel transport config from the same env-reader
    // closure. Supports UDS (subprocess substrate), VSock dial-out
    // (Firecracker), and VSock listen (Apple-VZ guest) — exactly the
    // three substrates the kernel ships. `NotConfigured` from
    // `from_env_fn` maps to `KernelSocketMissing` so existing
    // callers' error handling stays compatible.
    let transport_cfg = KernelTransportConfig::from_env_fn(&f)
        .map_err(|_| DriverError::KernelSocketMissing)?;
    let workspace = var("RAXIS_WORKSPACE_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_WORKSPACE_PATH));

    // Resolve model id + provider via the registry. The `provider`
    // field drives the multi-provider router below; the `name` field
    // is what gets stamped into every `MessageRequest::model`.
    let known_model = resolve_model_from_env_fn(&f)?;
    let model_id    = known_model.name.to_owned();
    let provider    = known_model.provider;

    // Base URL precedence: explicit operator override
    // (`RAXIS_PLANNER_BASE_URL`) wins for every provider. Otherwise
    // each provider has a canonical default
    // ([`ProviderId::default_base_url`]); the sidecar variant
    // returns "" because there is no well-known sidecar URL —
    // operators MUST stamp `RAXIS_PLANNER_SIDECAR_ENDPOINT` (the
    // construction path below validates that).
    let base_url = match var("RAXIS_PLANNER_BASE_URL") {
        Some(u) => u,
        None    => provider.default_base_url().to_owned(),
    };
    if provider != ProviderId::Sidecar
        && !(base_url.starts_with("http://") || base_url.starts_with("https://"))
    {
        return Err(DriverError::BadBaseUrl { got: base_url });
    }
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
    // snapshot.
    //
    // Two delivery channels are supported. The kernel chooses one
    // per spawn; the driver tries them in this order:
    //
    //   1. **Sidecar file.** When `RAXIS_PLANNER_KSB_PATH` is set
    //      the driver reads the JSON bytes from that guest-visible
    //      path (the kernel mounts a per-session virtiofs share at
    //      [`raxis_ksb::PLANNER_KSB_GUEST_MOUNT`] containing
    //      [`raxis_ksb::PLANNER_KSB_FILE_NAME`]). This is the only
    //      channel that survives the Apple-VZ substrate's
    //      `COMMAND_LINE_SIZE` ceiling once the KSB grows past
    //      ~1 KiB (e.g. the reviewer's per-initiative DAG snapshot).
    //
    //   2. **Inline env var.** When `RAXIS_PLANNER_KSB` is set the
    //      driver parses the value verbatim. Used by
    //      subprocess-isolation tests and the legacy
    //      pre-sidecar kernel path.
    //
    // Absent / unparseable on both channels → `None`, which the
    // dispatch-loop seam uses to fall back to the NNSP-only system
    // prompt (test-only fallback; in production every
    // kernel-spawned session has a parseable snapshot stamped).
    let ksb_snapshot = read_ksb_snapshot(&f);

    // ── Connect kernel transport BEFORE building the model so the
    //    model's HttpFetch can share the connection (required for
    //    `VsockListen` substrates where the guest's listener accepts
    //    exactly one host-side connection).
    let transport: Arc<dyn KernelTransport> =
        crate::transport::connect(&transport_cfg).await?;

    // ── Choose HTTP transport based on the kernel transport variant.
    //
    // Subprocess substrates dial the kernel over UDS and have full
    // host network access — direct egress is the right answer
    // (it matches the existing behaviour and lets the planner
    // exploit reqwest's HTTP/2 connection pooling).
    //
    // VM substrates (`Vsock` dial / `VsockListen`) run the planner
    // in an `EgressTier::None` (Orchestrator, Reviewer) or
    // `Tier1Tproxy` (Executor) guest. The kernel-mediated path is
    // the ONLY way out for `EgressTier::None` and a strict
    // architectural improvement for `Tier1Tproxy` (the audit chain
    // gains a single anchor on the kernel side per
    // `provider-failure-handling.md §2.1`).
    let http_fetch: Arc<dyn crate::http_fetch::HttpFetch> = match &transport_cfg {
        crate::transport::KernelTransportConfig::Uds { .. } => {
            Arc::new(crate::http_fetch::DirectHttpFetch::new())
        }
        crate::transport::KernelTransportConfig::Vsock { .. }
        | crate::transport::KernelTransportConfig::VsockListen { .. } => {
            Arc::new(crate::http_fetch::KernelMediatedHttpFetch::new(
                Arc::clone(&transport),
                env.session_token.as_str(),
            ))
        }
    };

    // ── Construct the model client by dispatching on the resolved
    //    provider (`provider-model-selection.md §4` +
    //    `v2_extended_gaps.md §C5`). All five client impls accept
    //    `Arc<dyn HttpFetch>` so the kernel-mediated transport flows
    //    through identically for every provider — the planner never
    //    holds a credential, the gateway injects per
    //    `peripherals.md §3.2`.
    let model: Arc<dyn ModelClient> =
        build_model_client(known_model, &base_url, &http_fetch, &f)?;

    let token_caps = TokenCaps {
        input_total:  max_tokens_input_total,
        output_total: max_tokens_output_total,
        total:        max_tokens_total,
    };
    run_role_session_with_connected_transport(
        role,
        args,
        env,
        task_prompt,
        transport,
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

/// **`v2_extended_gaps.md §C5` — multi-provider model client
/// router.**
///
/// Picks the right [`ModelClient`] impl for the resolved provider
/// and threads the shared [`crate::http_fetch::HttpFetch`] through
/// its `with_http_fetch` constructor. Each variant returns an
/// `Arc<dyn ModelClient>` so the dispatch loop stays
/// provider-agnostic.
///
/// Provider routing rules:
///
/// * **Anthropic** — wraps [`AnthropicClient`] against the resolved
///   `base_url` (defaults to `https://api.anthropic.com`). The
///   gateway injects `x-api-key` per `peripherals.md §3.2` so the
///   planner never sees the credential.
/// * **OpenAI** — wraps [`OpenAiClient`]; gateway injects the
///   `Authorization: Bearer …` header.
/// * **Gemini** — wraps [`GeminiClient`]; gateway injects the API
///   key as a `?key=` query param per Google's contract.
/// * **Bedrock** — wraps [`BedrockClient`]; gateway performs the
///   SigV4 signing leg before dispatch (the planner's request body
///   never carries AWS credentials).
/// * **Sidecar** — wraps [`SidecarModelClient`]. Reads
///   [`PLANNER_SIDECAR_ENDPOINT_ENV`],
///   [`PLANNER_SIDECAR_PROVIDER_ID_ENV`], and
///   [`PLANNER_SIDECAR_HMAC_SECRET_ENV`] from the kernel-stamped
///   env (each is `SidecarEnvMissing` if absent / empty). The HMAC
///   secret is per-spawn material — see `extensibility-traits.md
///   §9A.7A` for the threat-model rationale.
fn build_model_client<F>(
    known_model: &KnownModel,
    base_url:    &str,
    http_fetch:  &Arc<dyn crate::http_fetch::HttpFetch>,
    f:           &F,
) -> Result<Arc<dyn ModelClient>, DriverError>
where
    F: Fn(&str) -> Option<String>,
{
    let var = |k: &str| f(k).filter(|v| !v.is_empty());
    Ok(match known_model.provider {
        ProviderId::Anthropic => Arc::new(AnthropicClient::with_http_fetch(
            base_url.to_owned(),
            Arc::clone(http_fetch),
        )),
        ProviderId::OpenAi => Arc::new(OpenAiClient::with_http_fetch(
            base_url.to_owned(),
            Arc::clone(http_fetch),
        )),
        ProviderId::Gemini => Arc::new(GeminiClient::with_http_fetch(
            base_url.to_owned(),
            Arc::clone(http_fetch),
        )),
        ProviderId::Bedrock => Arc::new(BedrockClient::with_http_fetch(
            base_url.to_owned(),
            Arc::clone(http_fetch),
        )),
        ProviderId::Sidecar => {
            let endpoint = var(PLANNER_SIDECAR_ENDPOINT_ENV).ok_or(
                DriverError::SidecarEnvMissing { var: PLANNER_SIDECAR_ENDPOINT_ENV },
            )?;
            let provider_id = var(PLANNER_SIDECAR_PROVIDER_ID_ENV).ok_or(
                DriverError::SidecarEnvMissing { var: PLANNER_SIDECAR_PROVIDER_ID_ENV },
            )?;
            let secret_hex = var(PLANNER_SIDECAR_HMAC_SECRET_ENV).ok_or(
                DriverError::SidecarEnvMissing { var: PLANNER_SIDECAR_HMAC_SECRET_ENV },
            )?;
            Arc::new(SidecarModelClient::with_http_fetch(
                endpoint,
                provider_id,
                &secret_hex,
                Arc::clone(http_fetch),
            )?)
        }
    })
}

/// Helper for `run_role_session_with_env_fn` — read the
/// kernel-stamped KSB snapshot using whichever delivery channel the
/// kernel chose for this spawn.
///
/// Channel priority:
///
///   1. **`RAXIS_PLANNER_KSB_PATH` (sidecar file).** When set, read
///      the JSON bytes from the path and deserialise. A non-empty
///      value but a missing / unreadable / unparseable file
///      surfaces a structured-log warn and returns `None` — the
///      driver falls back to the NNSP-only prompt rather than
///      booting against an inconsistent KSB.
///
///   2. **`RAXIS_PLANNER_KSB` (inline env).** Legacy in-process
///      delivery, used by subprocess-isolation tests and pre-V2.6
///      kernel revisions. Empty / unparseable → `None` with a
///      structured-log warn.
///
///   3. Neither set → `None` (driver falls back to NNSP-only
///      system prompt).
fn read_ksb_snapshot<F: Fn(&str) -> Option<String>>(f: &F) -> Option<raxis_ksb::KsbSnapshot> {
    let var = |k: &str| f(k).filter(|v| !v.is_empty());

    if let Some(path) = var(raxis_ksb::PLANNER_KSB_PATH_ENV) {
        let bytes = match std::fs::read(&path) {
            Ok(b) => b,
            Err(e) => {
                eprintln!(
                    "{{\"level\":\"warn\",\"event\":\"planner_ksb_sidecar_read_failed\",\
                     \"path\":{:?},\"err\":\"{e}\"}}",
                    path,
                );
                return None;
            }
        };
        match serde_json::from_slice::<raxis_ksb::KsbSnapshot>(&bytes) {
            Ok(snap) => return Some(snap),
            Err(e) => {
                eprintln!(
                    "{{\"level\":\"warn\",\"event\":\"planner_ksb_sidecar_parse_failed\",\
                     \"path\":{:?},\"bytes\":{},\"err\":\"{e}\"}}",
                    path,
                    bytes.len(),
                );
                return None;
            }
        }
    }

    var(raxis_ksb::PLANNER_KSB_ENV).and_then(|raw| {
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
    })
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
    transport_cfg: KernelTransportConfig,
    workspace: PathBuf,
    model_id: String,
    max_turns: u32,
    max_tokens: u32,
    token_caps: TokenCaps,
    model: Arc<dyn ModelClient>,
    ksb_snapshot: Option<raxis_ksb::KsbSnapshot>,
) -> Result<DriverOutcome, DriverError> {
    let transport: Arc<dyn KernelTransport> =
        crate::transport::connect(&transport_cfg).await?;
    run_role_session_with_connected_transport(
        role,
        args,
        env,
        task_prompt,
        transport,
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

/// Variant of [`run_role_session_with_model`] that takes an
/// already-connected [`KernelTransport`] instead of a
/// [`KernelTransportConfig`]. The env-fn entry point uses this
/// variant so the model's `KernelMediatedHttpFetch` can share the
/// connection with the dispatch loop's `IntentSubmitter`.
///
/// Sharing the transport is mandatory under the `VsockListen`
/// substrate where the in-guest listener accepts exactly one
/// host-side connection (`tokio_vsock::VsockListener` with
/// `backlog = 1`); UDS and `Vsock` dial allow multiple connections
/// but sharing is still preferable so audit, ordering, and
/// back-pressure happen under one stream.
#[allow(clippy::too_many_arguments)]
pub async fn run_role_session_with_connected_transport(
    role: Role,
    args: BootArgs,
    env: BootEnv,
    task_prompt: String,
    transport: Arc<dyn KernelTransport>,
    workspace: PathBuf,
    model_id: String,
    max_turns: u32,
    max_tokens: u32,
    token_caps: TokenCaps,
    model: Arc<dyn ModelClient>,
    ksb_snapshot: Option<raxis_ksb::KsbSnapshot>,
) -> Result<DriverOutcome, DriverError> {
    // ── Step 1b: construct the session-scoped IntentSubmitter ──────
    //
    // V2 §3.2 wires the `structured_output` tool to the submitter so
    // it can ship typed mid-session payloads through the kernel UDS.
    // The submitter must therefore exist BEFORE the registry is
    // constructed (the registry's `StructuredOutputTool` holds an
    // `Arc<IntentSubmitter>`). The same submitter is reused for the
    // post-dispatch terminal-tool intent submission below, so we
    // build it once here and clone the `Arc` everywhere.
    let task_id_owned = args
        .task_id
        .clone()
        .unwrap_or_else(|| args.initiative_id.clone());
    let task_id = TaskId::parse(&task_id_owned).map_err(|e| {
        DriverError::InvalidTaskId(format!(
            "task id `{task_id_owned}` failed validation: {e}"
        ))
    })?;
    let submitter = Arc::new(
        IntentSubmitter::new(Arc::clone(&transport), env.session_token.clone(), task_id),
    );

    // ── Step 2: build per-role registry + terminal tool list. ───────
    let (registry, terminal_tools) = build_role(role, Arc::clone(&submitter));
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
    // on `IntegrationMerge` / `ActivateSubTask` framing. The
    // submitter was constructed at Step 1b alongside the registry
    // (V2 §3.2 wires the `structured_output` tool to it directly).

    // V2 `v2_extended_gaps.md §2.5` — relay the dispatch loop's
    // cumulative `(input, output)` totals into the submitter BEFORE
    // any submit fires, so every outbound `IntentRequest::tokens_used`
    // carries the truthful end-of-loop count. Provider id is left
    // empty: the kernel resolves the billing provider via policy
    // (worst-of-N over LLM providers with pricing) at admission
    // time, which matches the `EstimateCost` upper-bound contract.
    let (cum_in, cum_out) = outcome.cumulative_tokens();
    submitter.report_tokens(raxis_types::TokensReport {
        input_tokens:          cum_in,
        output_tokens:         cum_out,
        cache_read_tokens:     0,
        cache_creation_tokens: 0,
        provider_id:           String::new(),
    });

    match outcome {
        DispatchOutcome::TerminalTool {
            tool_name, input, output: _, ..
        } => {
            submit_terminal(role, submitter.as_ref(), &tool_name, &input).await?;
            Ok(DriverOutcome::Completed { tool_name })
        }
        DispatchOutcome::Idle { final_text, .. } => Ok(DriverOutcome::Idle { final_text }),
        DispatchOutcome::MaxTurnsExceeded { turns, .. } => {
            Ok(DriverOutcome::MaxTurnsExceeded { turns })
        }
        DispatchOutcome::TokensExceeded {
            which, ceiling, ..
        } => Ok(DriverOutcome::TokensExceeded { which, ceiling }),
    }
}

/// Build the role-specific tool registry + terminal-tool name list.
///
/// V2 `v2_extended_gaps.md §3.1` — when the spawn env declares
/// `RAXIS_PLANNER_MAX_SLEEP_SECONDS_PER_CALL` and
/// `RAXIS_PLANNER_MAX_CUMULATIVE_SLEEP_SECONDS`, the executor and
/// orchestrator registries are constructed via
/// `build_*_registry_with_sleep` so the `sleep` tool is wired with
/// the operator-declared ceilings. Absent ⇒ the disabled SleepTool
/// (refuses every invocation with `FAIL_SLEEP_DISABLED`) is
/// registered.
///
/// V2 `v2_extended_gaps.md §3.2` — the executor and orchestrator
/// registries always receive the `structured_output` tool wired
/// to the session-scoped [`crate::intent::IntentSubmitter`].
/// Reviewer NEVER receives `structured_output` or `sleep`
/// (INV-PLANNER-HARNESS-02 / R-5 — bounded capabilities).
fn build_role(
    role:      Role,
    submitter: Arc<crate::intent::IntentSubmitter>,
) -> (ToolRegistry, Vec<&'static str>) {
    use raxis_types::planner_env::{
        PLANNER_MAX_SLEEP_CUMULATIVE_ENV, PLANNER_MAX_SLEEP_PER_CALL_ENV,
    };
    let sleep_caps = match (
        std::env::var(PLANNER_MAX_SLEEP_PER_CALL_ENV).ok().and_then(|s| s.parse::<u32>().ok()),
        std::env::var(PLANNER_MAX_SLEEP_CUMULATIVE_ENV).ok().and_then(|s| s.parse::<u32>().ok()),
    ) {
        (Some(per), Some(cum)) if per > 0 && cum >= per => Some((per, cum)),
        _                                               => None,
    };
    match role {
        Role::Executor => (
            match sleep_caps {
                Some((per, cum)) => build_executor_registry_full(per, cum, submitter),
                None             => {
                    let mut r = build_executor_registry();
                    r.register(Arc::new(StructuredOutputTool::new(submitter)));
                    r
                }
            },
            vec!["task_complete", "single_commit", "report_failure"],
        ),
        Role::Reviewer => (build_reviewer_registry(), vec!["submit_review"]),
        Role::Orchestrator => (
            match sleep_caps {
                Some((per, cum)) => build_orchestrator_registry_full(per, cum, submitter),
                None             => {
                    let mut r = build_orchestrator_registry();
                    r.register(Arc::new(StructuredOutputTool::new(submitter)));
                    r
                }
            },
            vec!["integration_merge", "activate_subtask", "retry_subtask"],
        ),
    }
}

/// Render the role-specific system prompt prefix. Per
/// `kernel-mechanics-prompt.md`, the system prompt = NNSP +
/// (eventually) the [`crate::render_ksb`] block. The V2.4
/// driver ships the NNSP-only first leg; the in-VM KSB renderer
/// runs on the live KSB once the orchestrator-side push transport
/// (V3, V2_GAPS §12.1) lands.
fn render_system_prompt_for_role(role: Role, args: &BootArgs) -> String {
    let role_blurb = match role {
        Role::Executor => "You are the RAXIS executor agent for task `{TASK}` of \
                          initiative `{INIT}`. Make code changes that satisfy the \
                          task description (use `edit_file`, `bash`, `git_commit`, \
                          etc.), then call ONE of these terminal tools to end \
                          the session:\n\
                          \n\
                          - `task_complete { head_sha }` — you committed the \
                            change; supply the 40-char hex SHA of the commit.\n\
                          - `single_commit { base_sha, head_sha }` — same as \
                            `task_complete` but you want to publish a (base, \
                            head) pair explicitly.\n\
                          - `report_failure { justification }` — you cannot \
                            complete the task; supply a one-paragraph operator-\
                            actionable rationale.\n\
                          \n\
                          You MUST call one of these tools before the turn ends. \
                          Free-form text without a tool call leaves the session \
                          stuck and the kernel will record an Idle failure.",
        Role::Reviewer => "You are the RAXIS reviewer for task `{TASK}` of \
                          initiative `{INIT}`. Read the executor's commit \
                          (via `read_file` / `grep_search`) and evaluate it \
                          against the task description, then call the terminal \
                          tool `submit_review { approved: bool, critique?: \
                          string }` exactly once to deliver your verdict. \
                          You MUST call `submit_review` before ending the \
                          turn — free-form text without a tool call leaves \
                          the session stuck.",
        Role::Orchestrator => "You are the RAXIS orchestrator for initiative \
                              `{INIT}`. Your job is to drive the task DAG to \
                              completion by calling the right terminal tool \
                              on every turn:\n\
                              \n\
                              1. Look at the `dag=` block inside \
                                 `[RAXIS:KERNEL_STATE …]` (below). Each row \
                                 has the shape `<task_id> <state> reviewers=N \
                                 sha=<40-hex|<none>> \"<title>\"`. The \
                                 `sha=` field is the executor's commit SHA \
                                 once the task completes; it is `<none>` \
                                 while the task is pending / in-progress / \
                                 failed-before-commit.\n\
                              2. Find the first task whose `state` is `pending` \
                                 AND whose plan-declared predecessors are all \
                                 `complete`. Call `activate_subtask { \
                                 subtask_task_id: \"<task_id>\" }` with that \
                                 row's task id (verbatim — case-sensitive).\n\
                              3. If a row's `state` is `failed` and you judge \
                                 a retry is warranted, call `retry_subtask { \
                                 subtask_task_id: \"<task_id>\" }` instead.\n\
                              4. When EVERY executor row is `complete` AND \
                                 every reviewer row is `complete`, call \
                                 `integration_merge { base_sha, head_sha }` \
                                 to fast-forward the initiative's \
                                 `target_ref`. Source the SHAs as follows:\n\
                                  - `base_sha`: copy the value from the \
                                    `base_sha=<40-hex>` line at the top \
                                    of `[RAXIS:KERNEL_STATE …]` verbatim. \
                                    The literal `<unset>` means the \
                                    kernel could not resolve the anchor — \
                                    do NOT submit; instead `sleep 5` and \
                                    re-check on the next turn.\n\
                                  - `head_sha`: copy the `sha=<40-hex>` \
                                    field of the single executor task \
                                    whose changes you want to fast-forward \
                                    from the `dag=` block. With one \
                                    executor in the DAG this is \
                                    unambiguous; with multiple executor \
                                    tasks pick the SHA of the latest \
                                    committed executor whose associated \
                                    reviewer is `complete`. The literal \
                                    `<none>` means the executor has not \
                                    stamped a SHA yet — do NOT submit.\n\
                                  - Always pass FULL 40-char lowercase hex \
                                    SHAs verbatim. Submitting a short SHA \
                                    or the literal `<none>` / `<unset>` \
                                    is rejected as `INVALID_REQUEST`.\n\
                              \n\
                              You MUST call exactly ONE of `activate_subtask`, \
                              `retry_subtask`, or `integration_merge` per \
                              turn. Free-form text alone (no tool call) ends \
                              the session in Idle and the kernel records an \
                              orchestration failure — never do that.",
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
        IntentKind::StructuredOutput => {
            // V2 §3.2 — non-terminal tool: the dispatch loop never
            // routes through here for `structured_output` because
            // it is NOT in the role's terminal-tool list. Reaching
            // this arm means a planner-binary mis-wiring promoted
            // it to terminal; surface that as a hard `DriverError`
            // so the bug fails loud rather than silently
            // double-submitting.
            return Err(DriverError::UnmappableTerminal {
                tool_name: "structured_output".to_owned(),
                role,
            });
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
    use crate::transport::StreamTransport;
    use tokio::io::duplex;

    /// Construct a minimal `IntentSubmitter` for `build_role` tests.
    /// The transport's other end is dropped — tests that assert on
    /// the registry shape do not exercise the wire path.
    fn stub_submitter() -> Arc<crate::intent::IntentSubmitter> {
        let (planner_side, _kernel_side) = duplex(4096);
        let transport = Arc::new(StreamTransport::new(planner_side));
        Arc::new(crate::intent::IntentSubmitter::new(
            transport,
            "stub-tok".to_owned(),
            TaskId::parse("stub-task").unwrap(),
        ))
    }

    /// Stub `HttpFetch` that records the last request's URL +
    /// returns a 200 OK with the fixture body. Used by the
    /// multi-provider router tests to assert *which* client variant
    /// was constructed: we identify the variant by the URL shape it
    /// hits (`/v1/messages` for Anthropic, `/v1/chat/completions`
    /// for OpenAI, `/v1beta/models/...` for Gemini, `/model/.../invoke`
    /// for Bedrock, `/inference/messages` for Sidecar).
    ///
    /// `Debug` is required by `#[async_trait]` + the trait bound on
    /// the model clients' `http_fetch` field but contains no state
    /// worth printing.
    #[derive(Debug)]
    struct RecordingFetch {
        last_url: tokio::sync::Mutex<Option<String>>,
        body:     Vec<u8>,
    }

    impl RecordingFetch {
        fn new(body: Vec<u8>) -> Self {
            Self {
                last_url: tokio::sync::Mutex::new(None),
                body,
            }
        }
    }

    #[async_trait::async_trait]
    impl crate::http_fetch::HttpFetch for RecordingFetch {
        async fn fetch<'a>(
            &self,
            req: crate::http_fetch::HttpFetchRequest<'a>,
        ) -> Result<
            crate::http_fetch::HttpFetchResponse,
            crate::http_fetch::HttpFetchError,
        > {
            *self.last_url.lock().await = Some(req.url.to_owned());
            Ok(crate::http_fetch::HttpFetchResponse {
                status:  200,
                headers: vec![],
                body:    self.body.clone(),
            })
        }
    }

    fn known(name: &str) -> &'static crate::provider_model::KnownModel {
        crate::provider_model::find_known_model(name)
            .expect("test fixture: model id must be registered")
    }

    /// Drive one `create_message` call through the constructed client
    /// and return the URL it dialled. The trait-object surface
    /// (`Arc<dyn ModelClient>`) hides which concrete impl is
    /// underneath; we use the URL fingerprint to assert routing.
    async fn url_dialled_by(client: Arc<dyn ModelClient>, recorder: Arc<RecordingFetch>) -> String {
        use crate::model::MessageRequest;
        let req = MessageRequest {
            model: "fixture-model".to_owned(),
            ..MessageRequest::default()
        };
        // Anthropic responds with a `MessageResponse`; for the
        // other clients, the body shape doesn't match — we don't
        // assert on the parsed response here, only on the URL the
        // client requested. Errors on parse are fine.
        let _ = client.create_message(&req).await;
        let url = recorder.last_url.lock().await.clone();
        url.expect("client did not call HttpFetch::fetch")
    }

    #[tokio::test]
    async fn build_model_client_routes_anthropic_to_anthropic_url() {
        // `MessageResponse`-shaped body so the parse succeeds.
        let body = br#"{
            "id":"m_test","model":"fixture-model","role":"assistant",
            "content":[],"stop_reason":"end_turn",
            "usage":{"input_tokens":1,"output_tokens":1}
        }"#.to_vec();
        let rec = Arc::new(RecordingFetch::new(body));
        let fetch: Arc<dyn crate::http_fetch::HttpFetch> = rec.clone();
        let m = known("claude-sonnet-4-5-20250929");
        let client = build_model_client(
            m, "https://api.anthropic.com", &fetch, &|_| None,
        ).unwrap();
        let url = url_dialled_by(client, rec).await;
        assert_eq!(url, "https://api.anthropic.com/v1/messages");
    }

    #[tokio::test]
    async fn build_model_client_routes_openai_to_openai_url() {
        let rec = Arc::new(RecordingFetch::new(b"{}".to_vec()));
        let fetch: Arc<dyn crate::http_fetch::HttpFetch> = rec.clone();
        let m = known("gpt-5.5-medium");
        let client = build_model_client(m, "https://api.openai.com", &fetch, &|_| None).unwrap();
        let url = url_dialled_by(client, rec).await;
        assert_eq!(url, "https://api.openai.com/v1/chat/completions");
    }

    #[tokio::test]
    async fn build_model_client_routes_gemini_to_gemini_url() {
        let rec = Arc::new(RecordingFetch::new(b"{}".to_vec()));
        let fetch: Arc<dyn crate::http_fetch::HttpFetch> = rec.clone();
        let m = known("gemini-2.5-pro");
        let client = build_model_client(
            m, "https://generativelanguage.googleapis.com", &fetch, &|_| None,
        ).unwrap();
        let url = url_dialled_by(client, rec).await;
        // Gemini's URL embeds the model id in the path:
        //   /v1beta/models/<model>:generateContent
        assert!(
            url.starts_with("https://generativelanguage.googleapis.com/v1beta/models/"),
            "unexpected URL: {url}",
        );
        assert!(url.ends_with(":generateContent"), "unexpected URL: {url}");
    }

    #[tokio::test]
    async fn build_model_client_routes_bedrock_to_bedrock_url() {
        let rec = Arc::new(RecordingFetch::new(b"{}".to_vec()));
        let fetch: Arc<dyn crate::http_fetch::HttpFetch> = rec.clone();
        let m = known("anthropic.claude-3-5-sonnet-20241022-v2:0");
        let client = build_model_client(
            m, "https://bedrock-runtime.us-east-1.amazonaws.com", &fetch, &|_| None,
        ).unwrap();
        let url = url_dialled_by(client, rec).await;
        // Bedrock URL: <base>/model/<model>/invoke
        assert_eq!(
            url,
            "https://bedrock-runtime.us-east-1.amazonaws.com/model/fixture-model/invoke",
        );
    }

    /// Match-on-error helper: `Arc<dyn ModelClient>` doesn't impl
    /// `Debug`, so the `unwrap_err()` shorthand cannot be used
    /// against `build_model_client`'s return type.
    fn assert_sidecar_env_missing(
        result: Result<Arc<dyn ModelClient>, DriverError>,
        expected_var: &str,
    ) {
        match result {
            Ok(_) => panic!("expected SidecarEnvMissing, got Ok(_)"),
            Err(DriverError::SidecarEnvMissing { var }) => {
                assert_eq!(var, expected_var);
            }
            Err(other) => panic!("expected SidecarEnvMissing, got {other}"),
        }
    }

    #[test]
    fn build_model_client_sidecar_requires_endpoint_env() {
        // Synthesise a sidecar `KnownModel` for the router test.
        // The registry doesn't yet ship a real sidecar row (operators
        // wire those per-deployment), but the router must accept
        // any `KnownModel` whose `provider == Sidecar`.
        let m = crate::provider_model::KnownModel {
            name:           "sidecar-fixture",
            provider:       crate::provider_model::ProviderId::Sidecar,
            deprecated:     None,
            context_window: Some(8_000),
        };
        let rec = Arc::new(RecordingFetch::new(b"{}".to_vec()));
        let fetch: Arc<dyn crate::http_fetch::HttpFetch> = rec;
        assert_sidecar_env_missing(
            build_model_client(&m, "", &fetch, &|_| None),
            PLANNER_SIDECAR_ENDPOINT_ENV,
        );
    }

    #[test]
    fn build_model_client_sidecar_requires_provider_id_env() {
        let m = crate::provider_model::KnownModel {
            name:           "sidecar-fixture",
            provider:       crate::provider_model::ProviderId::Sidecar,
            deprecated:     None,
            context_window: Some(8_000),
        };
        let rec = Arc::new(RecordingFetch::new(b"{}".to_vec()));
        let fetch: Arc<dyn crate::http_fetch::HttpFetch> = rec;
        let env = |k: &str| match k {
            "RAXIS_PLANNER_SIDECAR_ENDPOINT" => Some("https://sidecar.test".to_owned()),
            _                                => None,
        };
        assert_sidecar_env_missing(
            build_model_client(&m, "", &fetch, &env),
            PLANNER_SIDECAR_PROVIDER_ID_ENV,
        );
    }

    #[test]
    fn build_model_client_sidecar_requires_hmac_secret_env() {
        let m = crate::provider_model::KnownModel {
            name:           "sidecar-fixture",
            provider:       crate::provider_model::ProviderId::Sidecar,
            deprecated:     None,
            context_window: Some(8_000),
        };
        let rec = Arc::new(RecordingFetch::new(b"{}".to_vec()));
        let fetch: Arc<dyn crate::http_fetch::HttpFetch> = rec;
        let env = |k: &str| match k {
            "RAXIS_PLANNER_SIDECAR_ENDPOINT"    => Some("https://sidecar.test".to_owned()),
            "RAXIS_PLANNER_SIDECAR_PROVIDER_ID" => Some("custom-llm".to_owned()),
            _                                   => None,
        };
        assert_sidecar_env_missing(
            build_model_client(&m, "", &fetch, &env),
            PLANNER_SIDECAR_HMAC_SECRET_ENV,
        );
    }

    #[tokio::test]
    async fn build_model_client_sidecar_succeeds_with_full_env_and_dialles_endpoint() {
        let m = crate::provider_model::KnownModel {
            name:           "sidecar-fixture",
            provider:       crate::provider_model::ProviderId::Sidecar,
            deprecated:     None,
            context_window: Some(8_000),
        };
        let rec = Arc::new(RecordingFetch::new(b"{}".to_vec()));
        let fetch: Arc<dyn crate::http_fetch::HttpFetch> = rec.clone();
        // 32-byte hex secret (64 hex chars) — well above the
        // `SidecarConstructError::SecretTooShort` floor (16 bytes).
        let secret =
            "0000000000000000000000000000000000000000000000000000000000000000";
        let env = |k: &str| match k {
            "RAXIS_PLANNER_SIDECAR_ENDPOINT"      => Some("https://sidecar.test".to_owned()),
            "RAXIS_PLANNER_SIDECAR_PROVIDER_ID"   => Some("custom-llm".to_owned()),
            "RAXIS_PLANNER_SIDECAR_HMAC_SECRET"   => Some(secret.to_owned()),
            _                                     => None,
        };
        let client = build_model_client(&m, "", &fetch, &env).unwrap();
        let url = url_dialled_by(client, rec).await;
        assert!(
            url.starts_with("https://sidecar.test/"),
            "sidecar should dial its operator-supplied endpoint, got {url}",
        );
    }

    #[test]
    fn build_role_executor_includes_write_tools() {
        let (reg, terminals) = build_role(Role::Executor, stub_submitter());
        assert!(reg.get("git_commit").is_some());
        assert!(reg.get("edit_file").is_some());
        assert!(reg.get("bash").is_some());
        // V2 §3.2 — structured_output is now part of the executor
        // tool surface.
        assert!(reg.get("structured_output").is_some(),
            "executor MUST have structured_output (V2 §3.2)");
        assert!(terminals.contains(&"task_complete"));
        assert!(terminals.contains(&"report_failure"));
        assert!(terminals.contains(&"single_commit"));
    }

    #[test]
    fn build_role_reviewer_excludes_write_tools_and_pins_terminal() {
        let (reg, terminals) = build_role(Role::Reviewer, stub_submitter());
        // INV-PLANNER-HARNESS-04: reviewer must not have write
        // tools.
        assert!(reg.get("edit_file").is_none());
        assert!(reg.get("bash").is_none());
        assert!(reg.get("git_commit").is_none());
        // V2 §3.2 — reviewer NEVER receives structured_output (R-5).
        assert!(reg.get("structured_output").is_none(),
            "reviewer MUST NOT have structured_output (V2 §3.2 R-5)");
        // Read-only tools present:
        assert!(reg.get("read_file").is_some());
        assert!(reg.get("grep_search").is_some());
        // Single terminal: submit_review.
        assert_eq!(terminals, vec!["submit_review"]);
    }

    #[test]
    fn build_role_orchestrator_pins_dag_terminals() {
        let (reg, terminals) = build_role(Role::Orchestrator, stub_submitter());
        assert!(reg.get("read_file").is_some());
        // V2 §3.2 — orchestrator also gets structured_output.
        assert!(reg.get("structured_output").is_some(),
            "orchestrator MUST have structured_output (V2 §3.2)");
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
            base_sha:                      String::new(),
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
            KernelTransportConfig::Uds { socket_path: sock_path.clone() },
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
            KernelTransportConfig::Uds { socket_path: sock_path.clone() },
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
            KernelTransportConfig::Uds { socket_path: sock_path.clone() },
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
            KernelTransportConfig::Uds { socket_path: sock_path.clone() },
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

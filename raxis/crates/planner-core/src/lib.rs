//! `raxis-planner-core` — **minimum-bootable planner-harness scaffold.**
//!
//! This crate is the shared library every planner role binary links
//! against (`raxis-planner-executor`, `raxis-planner-reviewer`,
//! `raxis-planner-orchestrator`). Per `planner-harness.md §14.1`, those
//! three binaries are the entrypoints the kernel spawns inside a
//! Reviewer / Orchestrator / Executor VM at:
//!
//! * `/usr/local/bin/raxis-executor`     (`raxis-planner-executor`)
//! * `/usr/local/bin/raxis-reviewer`     (`raxis-planner-reviewer`)
//! * `/usr/local/bin/raxis-orchestrator` (`raxis-planner-orchestrator`)
//!
//! The kernel session-spawn path
//! (`raxis-kernel::session_spawn_orchestrator::spawn_session_for_task`)
//! and `raxis-kernel::session_spawn_orchestrator::spawn_orchestrator_for_initiative`
//! both stamp those exact paths into the VM's `entrypoint_argv`. Until
//! these binaries existed the kernel could spawn a session but the VM
//! would fail to exec — V2 was non-bootable end-to-end. This scaffold
//! restores bootability by giving the kernel a real `init`-style
//! process to hand control to inside the guest.
//!
//! ## Scope of the current scaffold
//!
//! This iteration is deliberately the smallest viable piece. It pins
//! the **wire shape** (CLI argv, environment-variable contract, exit-
//! code semantics) so that future iterations can layer richer agent
//! behaviour on top without re-litigating any of the kernel-side
//! assumptions:
//!
//! * [`Role`] — the three valid planner roles, with the canonical
//!   binary path each one occupies inside the guest.
//! * [`BootArgs`] — parsed CLI surface
//!   (`--initiative-id <ID>` for orchestrator;
//!   `--task-id <ID> --initiative-id <ID>` for executor / reviewer).
//! * [`BootEnv`] — environment-variable contract
//!   (`RAXIS_SESSION_TOKEN` is mandatory; presence of the var is the
//!   guest's "I was actually launched by the kernel" check —
//!   `planner-harness.md §14.5`).
//! * [`PlannerError`] — the full error taxonomy a binary's `main` may
//!   convert to a structured exit code.
//!
//! What is **explicitly NOT** in this iteration:
//!
//! * No tool registry. `raxis-planner-tools` is a separate crate that
//!   will land next; this crate exposes only the role-asymmetric
//!   *construction surface* a binary uses to ask for a registry.
//! * No VSock kernel-IPC client. The kernel today expects the planner
//!   binary to stay alive long enough for the session-lifecycle FSM
//!   to observe a steady state; the VSock control plane is a separate
//!   implementation milestone.
//! * No model-API client. The orchestrator-VM gateway-substrate
//!   bridge lives in `raxis-gateway-substrate`; `raxis-planner-core`
//!   is concerned only with the **guest-side scaffolding** that
//!   surrounds an eventual model loop.
//!
//! ## Why three binaries instead of one multiplexed binary
//!
//! Per `planner-harness.md §14.3`, role-asymmetric tool registries
//! are a **build-time** correctness property, not a runtime check.
//! Compiling each role binary with its own `[features]` set means a
//! reviewer binary literally cannot link in a `git_commit` tool, even
//! if a planner-harness bug confused the runtime dispatch. The
//! [`Role`] enum here is therefore informational rather than
//! load-bearing — the actual capability bound is enforced by the
//! Cargo feature pinned in each binary's `Cargo.toml`.

#![deny(unsafe_code, unsafe_op_in_unsafe_fn)]
#![warn(missing_docs)]

use std::env;
use std::ffi::OsString;
use std::fmt;

mod error;
pub mod custom_tools;
pub mod dispatch;
pub mod intent;
pub mod ksb;
pub mod model;
pub mod retry;
pub mod tools;
pub mod transport;

pub use custom_tools::{
    load_custom_tools, validate_custom_tool, CustomToolDecl, CustomToolError, SubprocessTool,
};
pub use dispatch::{DispatchConfig, DispatchError, DispatchLoop, DispatchOutcome};
pub use error::PlannerError;
pub use intent::{
    executor_terminal_tool_to_intent_kind, orchestrator_terminal_tool_to_intent_kind,
    reviewer_terminal_tool_to_intent_kind, IntentSubmitter, SubmitError, SubmitReviewInput,
    TaskCompleteInput,
};
pub use ksb::{
    assemble_system_prompt, render_ksb, DagRow, KsbError, KsbSnapshot, KSB_DELIMITER_CLOSE,
    KSB_DELIMITER_OPEN,
};
pub use model::{
    AnthropicClient, ContentBlock, Message, MessageRequest, MessageResponse, MockModelClient,
    ModelClient, ModelError, ToolSpec, Usage,
};
pub use retry::{
    is_retryable, FallbackModelClient, RetryConfig, RetryingModelClient,
};
pub use tools::{
    build_executor_registry, build_orchestrator_registry, build_reviewer_registry, BashTool,
    EditFileTool, GitCommitTool, GrepSearchTool, ReadFileTool, Tool, ToolContext, ToolError,
    ToolOutput, ToolRegistry,
};
pub use transport::{
    connect, KernelTransport, KernelTransportConfig, StreamTransport, TransportError,
};

/// **The three valid planner-harness roles** — informational mirror
/// of the build-time `[features]` selector in each binary's
/// `Cargo.toml`. The kernel expects exactly one of these three
/// argv[0] values (full path) to be the `entrypoint_argv` head of a
/// spawned session.
///
/// The mapping below is the **load-bearing** binding between this
/// enum and the kernel-side spawn path; changing either side
/// requires updating both `planner-harness.md §14.1` and the
/// tests in `raxis-kernel::session_spawn_orchestrator`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Role {
    /// Spawned with `EgressTier::Tier1Tproxy`, full task-id +
    /// initiative-id pair, executor tool-registry features.
    Executor,
    /// Spawned with `EgressTier::None`, full task-id + initiative-id
    /// pair, reviewer tool-registry features (no `git_commit`,
    /// `git_push`, no `network_*` tools).
    Reviewer,
    /// Spawned with the orchestrator egress tier (currently
    /// `EgressTier::None`; `planner-harness.md §14.6` is open on
    /// whether outbound model traffic flows through tproxy or
    /// gateway-substrate). Initiative-id only; the orchestrator
    /// binary owns the per-initiative task-id minting.
    Orchestrator,
}

impl Role {
    /// **Full path** the kernel hardcodes into a session's
    /// `entrypoint_argv[0]`. Production must match these exactly,
    /// or the `execve` inside the guest fails and the kernel sees
    /// `SessionVmExited` with a non-zero status before the planner
    /// even runs `main`.
    ///
    /// Pinned by `planner-harness.md §14.1`.
    pub const fn binary_path(self) -> &'static str {
        match self {
            Self::Executor     => "/usr/local/bin/raxis-executor",
            Self::Reviewer     => "/usr/local/bin/raxis-reviewer",
            Self::Orchestrator => "/usr/local/bin/raxis-orchestrator",
        }
    }

    /// Lowercase ASCII shortname used in structured logs and the
    /// per-role audit-event taxonomy
    /// (`SessionVmSpawned { role: "executor", … }`).
    pub const fn shortname(self) -> &'static str {
        match self {
            Self::Executor     => "executor",
            Self::Reviewer     => "reviewer",
            Self::Orchestrator => "orchestrator",
        }
    }
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.shortname())
    }
}

/// **Parsed CLI surface** of every planner-role binary.
///
/// Wire shape (pinned by `planner-harness.md §14.5`):
///
/// ```text
///   raxis-orchestrator --initiative-id <ID>
///   raxis-executor     --task-id <ID> --initiative-id <ID>
///   raxis-reviewer     --task-id <ID> --initiative-id <ID>
/// ```
///
/// Both IDs are **opaque, non-validated strings** at this layer —
/// they are kernel-minted UUIDv7s in production but the planner
/// binary itself MUST NOT regex-validate them. The kernel is the
/// sole authority for ID format; the guest treats them as identifiers
/// to round-trip into the eventual VSock `Hello` frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootArgs {
    /// Always present.
    pub initiative_id: String,
    /// Present for [`Role::Executor`] / [`Role::Reviewer`]; absent
    /// for [`Role::Orchestrator`] (per `planner-harness.md §14.5`).
    pub task_id: Option<String>,
}

impl BootArgs {
    /// Parse argv for the given role.
    ///
    /// **`argv` includes the program name at index 0** — same shape
    /// as `std::env::args_os()`. The first element is consumed but
    /// not validated; binaries are free to be invoked through a
    /// trampoline / `busybox`-style multiplexer.
    pub fn parse_argv<I, S>(role: Role, argv: I) -> Result<Self, PlannerError>
    where
        I: IntoIterator<Item = S>,
        S: Into<OsString>,
    {
        let mut iter = argv.into_iter().map(Into::into);
        let _argv0 = iter.next();
        let mut initiative_id: Option<String> = None;
        let mut task_id:       Option<String> = None;

        while let Some(raw) = iter.next() {
            let s = raw.to_str()
                .ok_or(PlannerError::BadArg("non-UTF-8 argument"))?
                .to_owned();
            match s.as_str() {
                "--initiative-id" => {
                    if initiative_id.is_some() {
                        return Err(PlannerError::DuplicateFlag("--initiative-id"));
                    }
                    let v = iter.next()
                        .ok_or(PlannerError::MissingValue("--initiative-id"))?;
                    let v = v.into_string()
                        .map_err(|_| PlannerError::BadArg("non-UTF-8 --initiative-id value"))?;
                    if v.is_empty() {
                        return Err(PlannerError::EmptyValue("--initiative-id"));
                    }
                    initiative_id = Some(v);
                }
                "--task-id" => {
                    if task_id.is_some() {
                        return Err(PlannerError::DuplicateFlag("--task-id"));
                    }
                    let v = iter.next()
                        .ok_or(PlannerError::MissingValue("--task-id"))?;
                    let v = v.into_string()
                        .map_err(|_| PlannerError::BadArg("non-UTF-8 --task-id value"))?;
                    if v.is_empty() {
                        return Err(PlannerError::EmptyValue("--task-id"));
                    }
                    task_id = Some(v);
                }
                other => {
                    return Err(PlannerError::UnknownFlag(other.to_owned()));
                }
            }
        }

        let initiative_id = initiative_id
            .ok_or(PlannerError::MissingValue("--initiative-id"))?;

        match role {
            Role::Executor | Role::Reviewer => {
                let task_id = task_id
                    .ok_or(PlannerError::MissingValue("--task-id"))?;
                Ok(Self { initiative_id, task_id: Some(task_id) })
            }
            Role::Orchestrator => {
                if let Some(_t) = task_id {
                    // The orchestrator binary owns task-id minting;
                    // an inbound `--task-id` is a kernel-side bug.
                    return Err(PlannerError::UnexpectedFlag(
                        "--task-id (orchestrator does not accept a task id)",
                    ));
                }
                Ok(Self { initiative_id, task_id: None })
            }
        }
    }
}

/// Mandatory environment-variable contract the kernel sets for every
/// guest. Missing any of these is treated as a kernel-substrate bug
/// and surfaces as [`PlannerError::MissingEnv`].
///
/// Pinned by `planner-harness.md §14.5`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootEnv {
    /// Per-session opaque token. The guest copies this verbatim
    /// into the eventual VSock `Hello` frame; the kernel matches it
    /// against `sessions.session_token` to prove the connecting VM
    /// is the one it just spawned (and not an out-of-band reconnect
    /// attempt against a recycled CID).
    ///
    /// The substrate stamps this from `SpawnRequest.vm_spec.session_token`
    /// (`raxis-kernel::session_spawn_orchestrator` Step 3).
    pub session_token: String,
}

impl BootEnv {
    /// Read the contract from the process environment.
    pub fn from_process_env() -> Result<Self, PlannerError> {
        Self::from_env_fn(|k| env::var(k).ok())
    }

    /// Test-friendly override that takes a closure `&str -> Option<String>`
    /// instead of the live process environment. The closure shape mirrors
    /// `std::env::var(_).ok()`.
    pub fn from_env_fn<F>(f: F) -> Result<Self, PlannerError>
    where
        F: Fn(&str) -> Option<String>,
    {
        let session_token = f("RAXIS_SESSION_TOKEN")
            .ok_or(PlannerError::MissingEnv("RAXIS_SESSION_TOKEN"))?;
        if session_token.is_empty() {
            return Err(PlannerError::EmptyEnv("RAXIS_SESSION_TOKEN"));
        }
        Ok(Self { session_token })
    }
}

/// Combined parsed boot context — what every planner-role `main`
/// reduces its inputs to before it starts the role-specific loop.
#[derive(Debug, Clone)]
pub struct BootContext {
    /// Which role we are. Pinned at compile time by the binary's
    /// feature flag; this enum value is the runtime mirror.
    pub role: Role,
    /// Parsed argv.
    pub args: BootArgs,
    /// Parsed env.
    pub env:  BootEnv,
}

impl BootContext {
    /// Convenience: parse argv + env in one call. Used by the three
    /// planner role binaries' `main` functions.
    pub fn from_process(role: Role) -> Result<Self, PlannerError> {
        let args = BootArgs::parse_argv(role, env::args_os())?;
        let env  = BootEnv::from_process_env()?;
        Ok(Self { role, args, env })
    }
}

/// Render a `BootContext` as a single-line structured-log JSON
/// object. The shape is pinned by `planner-harness.md §14.5` and is
/// what the kernel-side log scraper expects on the guest's stderr at
/// `t=0` ("planner-boot").
///
/// Returns the rendered line **without** a trailing newline.
///
/// The session token is **redacted** (replaced with the literal
/// `"<redacted>"`); leaking it into stderr would let any host-side
/// scrape break the kernel's authentication of the guest.
pub fn render_boot_log(ctx: &BootContext) -> String {
    let task_repr = match ctx.args.task_id.as_deref() {
        Some(t) => format!("\"{}\"", t),
        None    => String::from("null"),
    };
    format!(
        "{{\"level\":\"info\",\"step\":\"planner-boot\",\
         \"role\":\"{role}\",\"initiative_id\":\"{init}\",\
         \"task_id\":{task},\"session_token\":\"<redacted>\"}}",
        role = ctx.role.shortname(),
        init = ctx.args.initiative_id,
        task = task_repr,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn role_binary_path_matches_kernel_session_spawn() {
        // These three string literals are the exact values the kernel
        // stamps into VmSpec.entrypoint_argv (see
        // `raxis-kernel::session_spawn_orchestrator`).
        // A divergence means the kernel will spawn a binary that
        // does not exist on disk and the guest's exec(2) will fail
        // before our `main` runs.
        assert_eq!(Role::Executor.binary_path(),     "/usr/local/bin/raxis-executor");
        assert_eq!(Role::Reviewer.binary_path(),     "/usr/local/bin/raxis-reviewer");
        assert_eq!(Role::Orchestrator.binary_path(), "/usr/local/bin/raxis-orchestrator");
    }

    #[test]
    fn role_shortname_is_lowercase_ascii() {
        for r in [Role::Executor, Role::Reviewer, Role::Orchestrator] {
            let s = r.shortname();
            assert!(!s.is_empty());
            assert!(
                s.bytes().all(|b| b.is_ascii_lowercase()),
                "role shortname must be lowercase ASCII (got {s:?})",
            );
        }
    }

    #[test]
    fn role_display_matches_shortname() {
        assert_eq!(format!("{}", Role::Executor),     "executor");
        assert_eq!(format!("{}", Role::Reviewer),     "reviewer");
        assert_eq!(format!("{}", Role::Orchestrator), "orchestrator");
    }

    #[test]
    fn parse_argv_executor_happy_path() {
        let argv = vec![
            "raxis-executor",
            "--task-id", "task-42",
            "--initiative-id", "init-7",
        ];
        let parsed = BootArgs::parse_argv(Role::Executor, argv).unwrap();
        assert_eq!(parsed.initiative_id, "init-7");
        assert_eq!(parsed.task_id.as_deref(), Some("task-42"));
    }

    #[test]
    fn parse_argv_reviewer_happy_path() {
        let argv = vec![
            "raxis-reviewer",
            "--initiative-id", "init-7",
            "--task-id", "task-42",
        ];
        let parsed = BootArgs::parse_argv(Role::Reviewer, argv).unwrap();
        assert_eq!(parsed.initiative_id, "init-7");
        assert_eq!(parsed.task_id.as_deref(), Some("task-42"));
    }

    #[test]
    fn parse_argv_orchestrator_no_task_id() {
        let argv = vec!["raxis-orchestrator", "--initiative-id", "init-7"];
        let parsed = BootArgs::parse_argv(Role::Orchestrator, argv).unwrap();
        assert_eq!(parsed.initiative_id, "init-7");
        assert_eq!(parsed.task_id, None);
    }

    #[test]
    fn parse_argv_orchestrator_rejects_unexpected_task_id() {
        let argv = vec![
            "raxis-orchestrator",
            "--initiative-id", "init-7",
            "--task-id", "task-42",
        ];
        let err = BootArgs::parse_argv(Role::Orchestrator, argv).unwrap_err();
        assert!(matches!(err, PlannerError::UnexpectedFlag(_)));
    }

    #[test]
    fn parse_argv_executor_requires_task_id() {
        let argv = vec!["raxis-executor", "--initiative-id", "init-7"];
        let err  = BootArgs::parse_argv(Role::Executor, argv).unwrap_err();
        assert!(matches!(err, PlannerError::MissingValue("--task-id")));
    }

    #[test]
    fn parse_argv_requires_initiative_id() {
        let argv = vec!["raxis-orchestrator"];
        let err  = BootArgs::parse_argv(Role::Orchestrator, argv).unwrap_err();
        assert!(matches!(err, PlannerError::MissingValue("--initiative-id")));
    }

    #[test]
    fn parse_argv_rejects_duplicate_initiative_id() {
        let argv = vec![
            "raxis-orchestrator",
            "--initiative-id", "init-A",
            "--initiative-id", "init-B",
        ];
        let err = BootArgs::parse_argv(Role::Orchestrator, argv).unwrap_err();
        assert!(matches!(err, PlannerError::DuplicateFlag("--initiative-id")));
    }

    #[test]
    fn parse_argv_rejects_duplicate_task_id() {
        let argv = vec![
            "raxis-executor",
            "--task-id", "task-A",
            "--task-id", "task-B",
            "--initiative-id", "init-7",
        ];
        let err = BootArgs::parse_argv(Role::Executor, argv).unwrap_err();
        assert!(matches!(err, PlannerError::DuplicateFlag("--task-id")));
    }

    #[test]
    fn parse_argv_rejects_unknown_flag() {
        let argv = vec![
            "raxis-orchestrator",
            "--initiative-id", "init-7",
            "--mystery", "value",
        ];
        let err = BootArgs::parse_argv(Role::Orchestrator, argv).unwrap_err();
        match err {
            PlannerError::UnknownFlag(s) => assert_eq!(s, "--mystery"),
            other                        => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn parse_argv_rejects_missing_value_for_initiative_id() {
        let argv = vec!["raxis-executor", "--task-id", "t-1", "--initiative-id"];
        let err  = BootArgs::parse_argv(Role::Executor, argv).unwrap_err();
        assert!(matches!(err, PlannerError::MissingValue("--initiative-id")));
    }

    #[test]
    fn parse_argv_rejects_empty_value() {
        let argv = vec!["raxis-orchestrator", "--initiative-id", ""];
        let err  = BootArgs::parse_argv(Role::Orchestrator, argv).unwrap_err();
        assert!(matches!(err, PlannerError::EmptyValue("--initiative-id")));
    }

    #[test]
    fn boot_env_reads_session_token() {
        let env = BootEnv::from_env_fn(|k| match k {
            "RAXIS_SESSION_TOKEN" => Some("opaque-1234".to_owned()),
            _                     => None,
        }).unwrap();
        assert_eq!(env.session_token, "opaque-1234");
    }

    #[test]
    fn boot_env_rejects_missing_session_token() {
        let err = BootEnv::from_env_fn(|_| None).unwrap_err();
        assert!(matches!(err, PlannerError::MissingEnv("RAXIS_SESSION_TOKEN")));
    }

    #[test]
    fn boot_env_rejects_empty_session_token() {
        let err = BootEnv::from_env_fn(|k| match k {
            "RAXIS_SESSION_TOKEN" => Some(String::new()),
            _                     => None,
        }).unwrap_err();
        assert!(matches!(err, PlannerError::EmptyEnv("RAXIS_SESSION_TOKEN")));
    }

    #[test]
    fn render_boot_log_redacts_session_token_and_includes_role_and_ids() {
        let ctx = BootContext {
            role: Role::Executor,
            args: BootArgs {
                initiative_id: "init-7".to_owned(),
                task_id:       Some("task-42".to_owned()),
            },
            env:  BootEnv { session_token: "S3CRET-TOKEN".to_owned() },
        };
        let line = render_boot_log(&ctx);
        assert!(line.contains("\"role\":\"executor\""));
        assert!(line.contains("\"initiative_id\":\"init-7\""));
        assert!(line.contains("\"task_id\":\"task-42\""));
        assert!(line.contains("\"session_token\":\"<redacted>\""));
        // Must NOT leak the actual token bytes:
        assert!(!line.contains("S3CRET-TOKEN"),
            "session_token was leaked into the boot log: {line}");
    }

    #[test]
    fn render_boot_log_for_orchestrator_emits_null_task_id() {
        let ctx = BootContext {
            role: Role::Orchestrator,
            args: BootArgs {
                initiative_id: "init-7".to_owned(),
                task_id:       None,
            },
            env:  BootEnv { session_token: "tok".to_owned() },
        };
        let line = render_boot_log(&ctx);
        assert!(line.contains("\"task_id\":null"),
            "orchestrator must emit task_id:null, got: {line}");
    }
}

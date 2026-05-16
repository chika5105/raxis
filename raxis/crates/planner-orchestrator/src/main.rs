//! `raxis-orchestrator` — guest-side planner-harness binary for the
//! [`raxis_planner_core::Role::Orchestrator`] role.
//! ## Lifecycle (V2.4)
//! 1. Kernel session-spawn lands the canonical orchestrator image,
//!    `execve`s `/usr/local/bin/raxis-orchestrator --initiative-id <ID>`
//!    inside the guest with `RAXIS_SESSION_TOKEN=<opaque>` set.
//! 2. This `main` reduces argv + env to a [`raxis_planner_core::BootContext`].
//! 3. It emits one `planner-boot` structured log line on stderr (the
//!    kernel-side log scraper keys on `step:"planner-boot"`).
//! 4. **Live mode** — when `RAXIS_PLANNER_TASK_PROMPT` is populated,
//!    the binary calls
//!    [`raxis_planner_core::run_role_session`] which runs the full
//!    dispatch loop end-to-end (model client → tool registry →
//!    [`raxis_planner_core::DispatchLoop`] → terminal intent
//!    submission via UDS) and exits with a structured exit code on
//!    completion / failure.
//!    `gap-b1-planner-binary-wiring`.
//! 5. **Scaffold mode** — when the live-mode contract is unmet (the
//!    V2.3 default for the kernel mock-planner harness), the binary
//!    parks on Ctrl-C / SIGTERM exactly like the V2.3 scaffold did.
//!    The behaviour is bit-for-bit identical, so no kernel
//!    integration test changes were required to land V2.4.
//! See `raxis-planner-core/src/driver.rs` for the env contract.

use raxis_planner_core::{
    hydrate_from_proc_cmdline, init_pid1_filesystem, mount_workspace_shares, park_on_signal,
    render_boot_log, run_role_session, shutdown_or_exit, BootContext, DriverError, DriverOutcome,
    HydrationOutcome, MountStatus, PlannerError, Role, WorkspaceMountOutcome,
};

fn main() -> ! {
    // === PRE-RUNTIME PHASE ===
    // Step 1: when running as PID 1 inside a Linux initramfs
    // (AVF / Firecracker substrates), mount /proc, /sys, /dev,
    // /tmp before anything else. Without /proc the next step
    // (cmdline_env hydration) silently no-ops and the planner
    // boots without `RAXIS_KERNEL_VSOCK_LISTEN_PORT` etc., which
    // surfaces from the host as an AVF vsock CONNECT timeout.
    // No-op on the host (PID ≠ 1) and on macOS.
    init_pid1_filesystem();

    // Step 2: hydrate the process environment from
    // `/proc/cmdline` BEFORE we start the tokio runtime —
    // `cmdline_env::hydrate_*` calls `std::env::set_var`, which is
    // documented unsafe under multi-threaded races. `tokio::main`
    // would spin the runtime (and pin worker threads) before our
    // function body runs, so we run the hydration in the
    // synchronous `main` and only then hand off to the async
    // runner.
    // The Apple-VZ substrate folds `VmSpec::env` into
    // `raxis.envb64=<base64>` on the kernel cmdline because there
    // is no `Command::env` analogue at the AVF surface. On other
    // substrates (subprocess UDS, Firecracker — both inherit env
    // through `Command::env` / the Firecracker config) the
    // hydration is a no-op (`NoProcCmdline` / `NoEnvToken`).
    let hydration = hydrate_from_proc_cmdline();
    log_hydration_outcome(&hydration);

    // Step 3: now that the env is hydrated, mount any VirtioFS
    // workspace shares the substrate declared via
    // `RAXIS_VIRTIOFS_MOUNTS`. The orchestrator role mounts
    // `/workspace` (its initiative-scoped worktree) for the
    // tools subsystem to read/write. Each share is best-effort:
    // a single mount failure is logged on stderr but does not
    // panic — the planner surfaces the missing path through its
    // normal tool-error path so the operator sees a structured
    // diagnostic in the audit chain.
    let mount_outcome = mount_workspace_shares();
    log_workspace_mount_outcome(&mount_outcome);

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime construction must not fail at orchestrator boot");
    let exit_code = runtime.block_on(async_main());
    // V2 substrate contract: when running as Linux PID 1 inside the
    // microVM (AVF / Firecracker initramfs `/init`), a plain
    // `process::exit` triggers a kernel panic ("Attempted to kill
    // init!") and the AVF substrate observes a reboot rather than
    // a clean stop, wedging the per-session VM in a re-init loop.
    // `shutdown_or_exit` issues `reboot(LINUX_REBOOT_CMD_POWER_OFF)`
    // from PID 1 so the substrate sees a clean `SessionVmExited`
    // event and the kernel can advance the lifecycle (re-spawning
    // the orchestrator on the next DAG edge per `lifecycle.rs`).
    // Outside PID 1 the function falls through to a normal
    // `process::exit`, preserving the host subprocess substrate's
    // exit-code propagation contract.
    shutdown_or_exit(exit_code)
}

async fn async_main() -> u8 {
    match run().await {
        Ok(()) => 0,
        Err(e) => {
            // stderr-only structured error. Per `planner-harness.md
            // §14.5` the kernel-side scraper keys on `step:"planner-boot-error"`.
            eprintln!(
                "{{\"level\":\"error\",\"step\":\"planner-boot-error\",\
                  \"role\":\"orchestrator\",\"message\":{:?}}}",
                e.to_string(),
            );
            e.exit_code() as u8
        }
    }
}

/// Structured-log the cmdline-env hydration outcome on stderr. The
/// kernel-side scraper keys on `step:"planner-cmdline-env"`. We
/// log all variants — even the no-op ones — so a regression where
/// the AVF substrate stopped stamping the token surfaces in the
/// kernel's audit trail rather than as a silent absence of env
/// vars.
fn log_hydration_outcome(outcome: &HydrationOutcome) {
    match outcome {
        HydrationOutcome::NoProcCmdline { reason } => eprintln!(
            "{{\"level\":\"info\",\"step\":\"planner-cmdline-env\",\
              \"role\":\"orchestrator\",\"outcome\":\"no-proc-cmdline\",\
              \"reason\":{:?}}}",
            reason,
        ),
        HydrationOutcome::NoEnvToken => eprintln!(
            "{{\"level\":\"info\",\"step\":\"planner-cmdline-env\",\
              \"role\":\"orchestrator\",\"outcome\":\"no-env-token\"}}"
        ),
        HydrationOutcome::BadEnvToken { reason } => eprintln!(
            "{{\"level\":\"warn\",\"step\":\"planner-cmdline-env\",\
              \"role\":\"orchestrator\",\"outcome\":\"bad-env-token\",\
              \"reason\":{:?}}}",
            reason,
        ),
        HydrationOutcome::Hydrated {
            applied,
            skipped_already_set,
        } => eprintln!(
            "{{\"level\":\"info\",\"step\":\"planner-cmdline-env\",\
              \"role\":\"orchestrator\",\"outcome\":\"hydrated\",\
              \"applied\":{applied},\"skipped_already_set\":{skipped_already_set}}}"
        ),
    }
}

async fn run() -> Result<(), PlannerError> {
    let ctx = BootContext::from_process(Role::Orchestrator)?;
    eprintln!("{}", render_boot_log(&ctx));

    let outcome = run_role_session(ctx.role, ctx.args.clone(), ctx.env.clone())
        .await
        .map_err(driver_to_planner_error)?;

    match outcome {
        DriverOutcome::Scaffold => {
            // V2.3 scaffold behaviour preserved when the kernel did
            // not stamp `RAXIS_PLANNER_TASK_PROMPT`. The kernel
            // mock-planner harness depends on this — do not remove
            // without coordinating with `kernel/tests/mock_planner_*`.
            park_on_signal().await;
            Ok(())
        }
        DriverOutcome::Completed { tool_name } => {
            eprintln!(
                "{{\"level\":\"info\",\"step\":\"planner-completed\",\
                  \"role\":\"orchestrator\",\"terminal_tool\":{:?}}}",
                tool_name,
            );
            Ok(())
        }
        DriverOutcome::Idle { final_text } => {
            // Orchestrator dispatch ran but emitted no terminal
            // tool — surface as a non-zero exit so the kernel sees
            // a structured failure (the orchestrator is expected to
            // always pick a DAG action).
            eprintln!(
                "{{\"level\":\"warn\",\"step\":\"planner-idle\",\
                  \"role\":\"orchestrator\",\"final_text_len\":{len}}}",
                len = final_text.len(),
            );
            Err(PlannerError::DispatchIdle)
        }
        DriverOutcome::MaxTurnsExceeded { turns } => {
            eprintln!(
                "{{\"level\":\"error\",\"step\":\"planner-max-turns\",\
                  \"role\":\"orchestrator\",\"turns\":{turns}}}",
            );
            Err(PlannerError::MaxTurnsExceeded { turns })
        }
        DriverOutcome::TokensExceeded { which, ceiling } => {
            eprintln!(
                "{{\"level\":\"error\",\"step\":\"planner-tokens-exceeded\",\
                  \"role\":\"orchestrator\",\"which\":{:?},\"ceiling\":{ceiling}}}",
                which,
            );
            Err(PlannerError::TokensExceeded { which, ceiling })
        }
    }
}

fn driver_to_planner_error(e: DriverError) -> PlannerError {
    PlannerError::DriverFailure(e.to_string())
}

/// Structured-log the VirtioFS workspace-mount outcome on stderr.
/// Mirrors the `log_hydration_outcome` shape so the kernel-side
/// scraper can correlate per-role boot phases without bespoke
/// parsers.
fn log_workspace_mount_outcome(outcome: &WorkspaceMountOutcome) {
    match outcome {
        WorkspaceMountOutcome::NoEnvVar => eprintln!(
            "{{\"level\":\"info\",\"step\":\"planner-virtiofs-mount\",\
              \"role\":\"orchestrator\",\"outcome\":\"no-env-var\"}}"
        ),
        WorkspaceMountOutcome::BadEnvVar { reason, attempts } => eprintln!(
            "{{\"level\":\"warn\",\"step\":\"planner-virtiofs-mount\",\
              \"role\":\"orchestrator\",\"outcome\":\"bad-env-var\",\
              \"reason\":{:?},\"attempts\":{}}}",
            reason,
            attempts.len(),
        ),
        WorkspaceMountOutcome::Mounted { attempts } => {
            for attempt in attempts {
                let (status_str, reason): (&str, Option<&str>) = match &attempt.status {
                    MountStatus::Ok => ("ok", None),
                    MountStatus::Already => ("already", None),
                    MountStatus::Failed { reason } => ("failed", Some(reason.as_str())),
                };
                match reason {
                    Some(r) => eprintln!(
                        "{{\"level\":\"warn\",\"step\":\"planner-virtiofs-mount\",\
                          \"role\":\"orchestrator\",\"outcome\":{:?},\
                          \"tag\":{:?},\"guest_path\":{:?},\"read_only\":{},\
                          \"reason\":{:?}}}",
                        status_str,
                        attempt.spec.tag,
                        attempt.spec.guest_path,
                        attempt.spec.read_only,
                        r,
                    ),
                    None => eprintln!(
                        "{{\"level\":\"info\",\"step\":\"planner-virtiofs-mount\",\
                          \"role\":\"orchestrator\",\"outcome\":{:?},\
                          \"tag\":{:?},\"guest_path\":{:?},\"read_only\":{}}}",
                        status_str,
                        attempt.spec.tag,
                        attempt.spec.guest_path,
                        attempt.spec.read_only,
                    ),
                }
            }
        }
    }
}

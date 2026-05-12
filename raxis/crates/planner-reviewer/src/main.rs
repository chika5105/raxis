//! `raxis-reviewer` — guest-side planner-harness binary for the
//! [`Role::Reviewer`](raxis_planner_core::Role::Reviewer) role.
//!
//! See `raxis-planner-orchestrator/src/main.rs` for the full
//! lifecycle commentary; the reviewer binary differs only in:
//!
//!   * argv contract:
//!     `--task-id <ID> --initiative-id <ID>` (both required).
//!   * compile-time tool-registry features
//!     (`raxis-planner-core/reviewer`) — explicitly **excludes**
//!     `git_commit`, `git_push`, and `network_*` tools by linkage.
//!   * egress tier the kernel pre-stamps on the VM
//!     (`EgressTier::None` per `raxis-kernel::session_spawn_orchestrator`).
//!
//! V2.4 lifecycle: the driver delegates to
//! [`raxis_planner_core::run_role_session`] which runs the full
//! dispatch loop end-to-end when `RAXIS_PLANNER_TASK_PROMPT` is
//! set. Otherwise the binary parks on signal exactly like the V2.3
//! scaffold. Note: an `Idle` outcome on the reviewer is *acceptable*
//! (the model declined to deliver a verdict) — the kernel records
//! it but does not synthesise a `submit_review` on the model's
//! behalf; the reviewer's session times out via the verifier
//! deadline path.

use raxis_planner_core::{
    hydrate_from_proc_cmdline, init_pid1_filesystem, mount_workspace_shares, park_on_signal,
    render_boot_log, run_role_session, shutdown_or_exit, BootContext, DriverError, DriverOutcome,
    HydrationOutcome, MountStatus, PlannerError, Role, WorkspaceMountOutcome,
};

fn main() -> ! {
    // Step 1: when running as PID 1 inside a Linux initramfs,
    // mount /proc, /sys, /dev, /tmp before any other I/O. See
    // `raxis-planner-core::guest_init` for the full rationale.
    // No-op on the host (PID ≠ 1) and on macOS.
    init_pid1_filesystem();

    // Step 2: pre-runtime cmdline-env hydration. See
    // `raxis-planner-orchestrator/src/main.rs` for the full
    // rationale.
    let hydration = hydrate_from_proc_cmdline();
    log_hydration_outcome(&hydration);

    // Step 3: mount any VirtioFS workspace shares the substrate
    // declared via `RAXIS_VIRTIOFS_MOUNTS`. The reviewer role
    // mounts `/workspace` (its task-scoped read-only worktree) so
    // ripgrep / read_file see exactly the bytes the executor
    // committed. See `raxis-planner-orchestrator/src/main.rs::main`
    // for the full rationale.
    let mount_outcome = mount_workspace_shares();
    log_workspace_mount_outcome(&mount_outcome);

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime construction must not fail at reviewer boot");
    let exit_code = runtime.block_on(async_main());
    // See `raxis-planner-orchestrator/src/main.rs` for the full
    // rationale: PID 1 must `reboot(POWER_OFF)` instead of plain
    // `process::exit` so the substrate observes a clean
    // `SessionVmExited` event. `shutdown_or_exit` no-ops to
    // `process::exit(code)` when not PID 1.
    shutdown_or_exit(exit_code)
}

async fn async_main() -> u8 {
    match run().await {
        Ok(())  => 0,
        Err(e)  => {
            eprintln!(
                "{{\"level\":\"error\",\"step\":\"planner-boot-error\",\
                  \"role\":\"reviewer\",\"message\":{:?}}}",
                e.to_string(),
            );
            e.exit_code() as u8
        }
    }
}

fn log_hydration_outcome(outcome: &HydrationOutcome) {
    match outcome {
        HydrationOutcome::NoProcCmdline { reason } => eprintln!(
            "{{\"level\":\"info\",\"step\":\"planner-cmdline-env\",\
              \"role\":\"reviewer\",\"outcome\":\"no-proc-cmdline\",\
              \"reason\":{:?}}}",
            reason,
        ),
        HydrationOutcome::NoEnvToken => eprintln!(
            "{{\"level\":\"info\",\"step\":\"planner-cmdline-env\",\
              \"role\":\"reviewer\",\"outcome\":\"no-env-token\"}}"
        ),
        HydrationOutcome::BadEnvToken { reason } => eprintln!(
            "{{\"level\":\"warn\",\"step\":\"planner-cmdline-env\",\
              \"role\":\"reviewer\",\"outcome\":\"bad-env-token\",\
              \"reason\":{:?}}}",
            reason,
        ),
        HydrationOutcome::Hydrated { applied, skipped_already_set } => eprintln!(
            "{{\"level\":\"info\",\"step\":\"planner-cmdline-env\",\
              \"role\":\"reviewer\",\"outcome\":\"hydrated\",\
              \"applied\":{applied},\"skipped_already_set\":{skipped_already_set}}}"
        ),
    }
}

async fn run() -> Result<(), PlannerError> {
    let ctx = BootContext::from_process(Role::Reviewer)?;
    eprintln!("{}", render_boot_log(&ctx));

    let outcome = run_role_session(ctx.role, ctx.args.clone(), ctx.env.clone())
        .await
        .map_err(driver_to_planner_error)?;

    match outcome {
        DriverOutcome::Scaffold => {
            park_on_signal().await;
            Ok(())
        }
        DriverOutcome::Completed { tool_name } => {
            eprintln!(
                "{{\"level\":\"info\",\"step\":\"planner-completed\",\
                  \"role\":\"reviewer\",\"terminal_tool\":{:?}}}",
                tool_name,
            );
            Ok(())
        }
        DriverOutcome::Idle { final_text } => {
            // Reviewer Idle is informational. The kernel-side
            // verifier deadline + admission semantics treat
            // missing-verdict as the same failure class as a
            // session crash, so we exit 0 here and let the
            // kernel observe absence of `SubmitReview`.
            eprintln!(
                "{{\"level\":\"info\",\"step\":\"planner-idle\",\
                  \"role\":\"reviewer\",\"final_text_len\":{len}}}",
                len = final_text.len(),
            );
            Ok(())
        }
        DriverOutcome::MaxTurnsExceeded { turns } => {
            eprintln!(
                "{{\"level\":\"error\",\"step\":\"planner-max-turns\",\
                  \"role\":\"reviewer\",\"turns\":{turns}}}",
            );
            Err(PlannerError::MaxTurnsExceeded { turns })
        }
        DriverOutcome::TokensExceeded { which, ceiling } => {
            eprintln!(
                "{{\"level\":\"error\",\"step\":\"planner-tokens-exceeded\",\
                  \"role\":\"reviewer\",\"which\":{:?},\"ceiling\":{ceiling}}}",
                which,
            );
            Err(PlannerError::TokensExceeded { which, ceiling })
        }
    }
}

fn driver_to_planner_error(e: DriverError) -> PlannerError {
    PlannerError::DriverFailure(e.to_string())
}

fn log_workspace_mount_outcome(outcome: &WorkspaceMountOutcome) {
    match outcome {
        WorkspaceMountOutcome::NoEnvVar => eprintln!(
            "{{\"level\":\"info\",\"step\":\"planner-virtiofs-mount\",\
              \"role\":\"reviewer\",\"outcome\":\"no-env-var\"}}"
        ),
        WorkspaceMountOutcome::BadEnvVar { reason, attempts } => eprintln!(
            "{{\"level\":\"warn\",\"step\":\"planner-virtiofs-mount\",\
              \"role\":\"reviewer\",\"outcome\":\"bad-env-var\",\
              \"reason\":{:?},\"attempts\":{}}}",
            reason,
            attempts.len(),
        ),
        WorkspaceMountOutcome::Mounted { attempts } => {
            for attempt in attempts {
                let (status_str, reason): (&str, Option<&str>) = match &attempt.status {
                    MountStatus::Ok      => ("ok", None),
                    MountStatus::Already => ("already", None),
                    MountStatus::Failed { reason } => ("failed", Some(reason.as_str())),
                };
                match reason {
                    Some(r) => eprintln!(
                        "{{\"level\":\"warn\",\"step\":\"planner-virtiofs-mount\",\
                          \"role\":\"reviewer\",\"outcome\":{:?},\
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
                          \"role\":\"reviewer\",\"outcome\":{:?},\
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

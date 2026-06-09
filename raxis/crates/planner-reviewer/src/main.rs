//! `raxis-reviewer` — guest-side planner-harness binary for the
//! [`raxis_planner_core::Role::Reviewer`] role.
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
//! dispatch loop end-to-end when the kernel-stamped prompt contract
//! is present, and fails closed when it is not. Reviewer sessions
//! get one runtime-owned corrective turn if the model answers in
//! prose instead of calling `submit_review`; if the session still
//! reaches `Idle`, the kernel classifies it as a missing-verdict
//! runtime failure rather than a semantic rejection.

use raxis_planner_core::{
    enforce_pid1_or_abort, harden_guest_for_agent, hydrate_from_proc_cmdline, init_pid1_filesystem,
    mount_workspace_shares, render_boot_log, run_role_session, scrub_sensitive_env_for_agent,
    shutdown_or_exit, BootContext, DriverError, DriverOutcome, HydrationOutcome, MountStatus,
    PlannerError, Role, WorkspaceMountOutcome,
};

fn main() -> ! {
    // Step 0: `INV-PLANNER-PID1-ONLY-EXEC-01` — refuse to start
    // when the binary is invoked as a child process inside an
    // already-running microVM. See `raxis-planner-core::guest_init`
    // for the full jailbreak-mode rationale.
    enforce_pid1_or_abort();

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

    // Step 3: mount any workspace shares the substrate declared via
    // `RAXIS_VIRTIOFS_MOUNTS` (AVF) or `RAXIS_BLOCK_MOUNTS`
    // (Firecracker). The reviewer role mounts `/workspace` (its
    // task-scoped read-only worktree) so ripgrep / read_file see
    // exactly the bytes the executor committed. See
    // `raxis-planner-orchestrator/src/main.rs::main` for the full
    // rationale.
    let mount_outcome = mount_workspace_shares();
    log_workspace_mount_outcome(&mount_outcome);

    // Step 4: `INV-PLANNER-GUEST-AGENT-JAILBREAK-DEFENSE-01` —
    // last-line hardening against an in-VM LLM agent reading
    // kernel-stamped secrets, re-executing the planner binary,
    // or powering off the VM out-of-band. See
    // `raxis_planner_core::harden_guest_for_agent`'s docstring
    // and `specs/v3/guest-agent-jailbreak-defense.md` for the
    // attack-vector replay log. MUST run BEFORE the tokio
    // runtime spins up so the procfs bind mounts and `prctl(PR_*)`
    // flags are inherited by every worker thread.
    harden_guest_for_agent();

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
        Ok(()) => 0,
        Err(e) => {
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
        HydrationOutcome::Hydrated {
            applied,
            skipped_already_set,
        } => eprintln!(
            "{{\"level\":\"info\",\"step\":\"planner-cmdline-env\",\
              \"role\":\"reviewer\",\"outcome\":\"hydrated\",\
              \"applied\":{applied},\"skipped_already_set\":{skipped_already_set}}}"
        ),
    }
}

async fn run() -> Result<(), PlannerError> {
    let ctx = BootContext::from_process(Role::Reviewer)?;
    eprintln!("{}", render_boot_log(&ctx));

    // `INV-PLANNER-GUEST-AGENT-JAILBREAK-DEFENSE-01` — scrub the
    // sensitive env vars from the process environment after
    // `BootContext::from_process` has captured the safe session id.
    // The scrubber also keeps an in-process snapshot for the driver;
    // `run_role_session` reduces that snapshot to a fixed runtime allowlist.
    // The reviewer image
    // (`raxis-reviewer-core`) explicitly excludes the `bash`,
    // `git_commit`, `git_push`, and `network_*` tools by linkage,
    // but the reviewer still ships ripgrep / read_file which
    // could in principle inherit env via a future tool addition.
    // Scrubbing here is defence-in-depth.
    scrub_sensitive_env_for_agent();

    let outcome = run_role_session(ctx.role, ctx.args.clone(), ctx.env.clone())
        .await
        .map_err(driver_to_planner_error)?;

    match outcome {
        DriverOutcome::Scaffold => Err(PlannerError::DriverFailure(
            "driver returned retired Scaffold outcome; prompt contract was not stamped".to_owned(),
        )),
        DriverOutcome::Completed { tool_name } => {
            eprintln!(
                "{{\"level\":\"info\",\"step\":\"planner-completed\",\
                  \"role\":\"reviewer\",\"terminal_tool\":{:?}}}",
                tool_name,
            );
            Ok(())
        }
        DriverOutcome::Idle { final_text } => {
            // Reviewer Idle after the dispatch loop's corrective
            // turn is a no-verdict runtime failure. We still exit
            // 0 so the kernel can preserve the distinction between
            // "VM crashed" and "reviewer ended without SubmitReview"
            // in Mode-B post-exit synthesis.
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
            "{{\"level\":\"info\",\"step\":\"planner-workspace-mount\",\
              \"role\":\"reviewer\",\"outcome\":\"no-env-var\"}}"
        ),
        WorkspaceMountOutcome::BadEnvVar { reason, attempts } => eprintln!(
            "{{\"level\":\"warn\",\"step\":\"planner-workspace-mount\",\
              \"role\":\"reviewer\",\"outcome\":\"bad-env-var\",\
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
                        "{{\"level\":\"warn\",\"step\":\"planner-workspace-mount\",\
                          \"role\":\"reviewer\",\"outcome\":{:?},\
                          \"source\":{:?},\"fs_type\":{:?},\"guest_path\":{:?},\"read_only\":{},\
                          \"reason\":{:?}}}",
                        status_str,
                        attempt.spec.tag,
                        attempt.spec.fs_type,
                        attempt.spec.guest_path,
                        attempt.spec.read_only,
                        r,
                    ),
                    None => eprintln!(
                        "{{\"level\":\"info\",\"step\":\"planner-workspace-mount\",\
                          \"role\":\"reviewer\",\"outcome\":{:?},\
                          \"source\":{:?},\"fs_type\":{:?},\"guest_path\":{:?},\"read_only\":{}}}",
                        status_str,
                        attempt.spec.tag,
                        attempt.spec.fs_type,
                        attempt.spec.guest_path,
                        attempt.spec.read_only,
                    ),
                }
            }
        }
    }
}

//! `raxis-executor` — guest-side planner-harness binary for the
//! [`Role::Executor`](raxis_planner_core::Role::Executor) role.
//!
//! See `raxis-planner-orchestrator/src/main.rs` for the full
//! lifecycle commentary; the executor binary differs only in:
//!
//!   * argv contract:
//!     `--task-id <ID> --initiative-id <ID>` (both required).
//!   * compile-time tool-registry features
//!     (`raxis-planner-core/executor`).
//!   * egress tier the kernel pre-stamps on the VM
//!     (`Tier1Tproxy` per `raxis-kernel::session_spawn_orchestrator`).
//!
//! V2.4 lifecycle: the driver delegates to
//! [`raxis_planner_core::run_role_session`] which runs the full
//! dispatch loop end-to-end when `RAXIS_PLANNER_TASK_PROMPT` is
//! set. Otherwise the binary parks on signal exactly like the V2.3
//! scaffold.

use raxis_planner_core::{
    park_on_signal, render_boot_log, run_role_session, BootContext, DriverError, DriverOutcome,
    PlannerError, Role,
};

#[tokio::main]
async fn main() -> std::process::ExitCode {
    match run().await {
        Ok(())  => std::process::ExitCode::SUCCESS,
        Err(e)  => {
            eprintln!(
                "{{\"level\":\"error\",\"step\":\"planner-boot-error\",\
                  \"role\":\"executor\",\"message\":{:?}}}",
                e.to_string(),
            );
            std::process::ExitCode::from(e.exit_code() as u8)
        }
    }
}

async fn run() -> Result<(), PlannerError> {
    let ctx = BootContext::from_process(Role::Executor)?;
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
                  \"role\":\"executor\",\"terminal_tool\":{:?}}}",
                tool_name,
            );
            Ok(())
        }
        DriverOutcome::Idle { final_text } => {
            // Executor must always pick a terminal tool
            // (`task_complete` / `single_commit` / `report_failure`).
            // An Idle outcome means the model gave up without
            // submitting either, which the kernel surfaces as a
            // structured failure.
            eprintln!(
                "{{\"level\":\"warn\",\"step\":\"planner-idle\",\
                  \"role\":\"executor\",\"final_text_len\":{len}}}",
                len = final_text.len(),
            );
            Err(PlannerError::DispatchIdle)
        }
        DriverOutcome::MaxTurnsExceeded { turns } => {
            eprintln!(
                "{{\"level\":\"error\",\"step\":\"planner-max-turns\",\
                  \"role\":\"executor\",\"turns\":{turns}}}",
            );
            Err(PlannerError::MaxTurnsExceeded { turns })
        }
        DriverOutcome::TokensExceeded { which, ceiling } => {
            eprintln!(
                "{{\"level\":\"error\",\"step\":\"planner-tokens-exceeded\",\
                  \"role\":\"executor\",\"which\":{:?},\"ceiling\":{ceiling}}}",
                which,
            );
            Err(PlannerError::TokensExceeded { which, ceiling })
        }
    }
}

fn driver_to_planner_error(e: DriverError) -> PlannerError {
    PlannerError::DriverFailure(e.to_string())
}

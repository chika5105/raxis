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

use raxis_planner_core::{render_boot_log, BootContext, PlannerError, Role};

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
    let _ = tokio::signal::ctrl_c().await;
    Ok(())
}

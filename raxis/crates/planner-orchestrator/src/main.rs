//! `raxis-orchestrator` — guest-side planner-harness binary for the
//! [`Role::Orchestrator`](raxis_planner_core::Role::Orchestrator) role.
//!
//! ## Lifecycle
//!
//! 1. Kernel session-spawn lands the canonical orchestrator image,
//!    `execve`s `/usr/local/bin/raxis-orchestrator --initiative-id <ID>`
//!    inside the guest with `RAXIS_SESSION_TOKEN=<opaque>` set.
//! 2. This `main` reduces argv + env to a [`raxis_planner_core::BootContext`].
//! 3. It emits one `planner-boot` structured log line on stderr (the
//!    kernel-side log scraper keys on `step:"planner-boot"`).
//! 4. **Minimum-bootable behaviour:** the process then waits on
//!    Ctrl-C / SIGTERM. This satisfies the kernel's "session-VM stays
//!    alive long enough for the lifecycle FSM to observe `Running`"
//!    invariant without yet implementing any orchestrator logic.
//!
//! Future iterations layer the VSock control plane, model-API loop,
//! and the orchestrator-specific tool registry on top of this
//! scaffold without changing any of the above wire contracts.

use raxis_planner_core::{render_boot_log, BootContext, PlannerError, Role};

#[tokio::main]
async fn main() -> std::process::ExitCode {
    match run().await {
        Ok(())  => std::process::ExitCode::SUCCESS,
        Err(e)  => {
            // stderr-only structured error. Per `planner-harness.md
            // §14.5` the kernel-side scraper keys on `step:"planner-boot-error"`.
            eprintln!(
                "{{\"level\":\"error\",\"step\":\"planner-boot-error\",\
                  \"role\":\"orchestrator\",\"message\":{:?}}}",
                e.to_string(),
            );
            std::process::ExitCode::from(e.exit_code() as u8)
        }
    }
}

async fn run() -> Result<(), PlannerError> {
    let ctx = BootContext::from_process(Role::Orchestrator)?;
    eprintln!("{}", render_boot_log(&ctx));

    // Park the process. tokio::signal::ctrl_c covers SIGINT;
    // the production substrate sends SIGTERM on session teardown
    // and the tokio runtime translates that into the same future
    // resolution path on Unix.
    let _ = tokio::signal::ctrl_c().await;
    Ok(())
}

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

use raxis_planner_core::{render_boot_log, BootContext, PlannerError, Role};

#[tokio::main]
async fn main() -> std::process::ExitCode {
    match run().await {
        Ok(())  => std::process::ExitCode::SUCCESS,
        Err(e)  => {
            eprintln!(
                "{{\"level\":\"error\",\"step\":\"planner-boot-error\",\
                  \"role\":\"reviewer\",\"message\":{:?}}}",
                e.to_string(),
            );
            std::process::ExitCode::from(e.exit_code() as u8)
        }
    }
}

async fn run() -> Result<(), PlannerError> {
    let ctx = BootContext::from_process(Role::Reviewer)?;
    eprintln!("{}", render_boot_log(&ctx));
    let _ = tokio::signal::ctrl_c().await;
    Ok(())
}

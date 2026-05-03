//! `raxis-gateway` binary entry point. See `lib.rs` for the design.
//!
//! This file is intentionally thin: parse env, run, exit. All testable
//! logic lives in the library so unit + integration tests can drive it
//! without spawning the binary.

use std::process::ExitCode;

use raxis_gateway::{parse_gateway_env_from_process, run_gateway};

#[tokio::main]
async fn main() -> ExitCode {
    let env = match parse_gateway_env_from_process() {
        Ok(e) => e,
        Err(e) => {
            eprintln!(
                "{{\"level\":\"error\",\"event\":\"gateway_env_parse_failed\",\
                 \"reason\":\"{e}\"}}"
            );
            // 64 = EX_USAGE: command-line usage error. The kernel
            // supervisor (Phase A.5) treats any non-zero exit as a crash
            // and respawns; this code is for operator log clarity.
            return ExitCode::from(64);
        }
    };

    if let Err(e) = run_gateway(env).await {
        eprintln!(
            "{{\"level\":\"error\",\"event\":\"gateway_run_failed\",\
             \"reason\":\"{e}\"}}"
        );
        return ExitCode::from(1);
    }

    ExitCode::SUCCESS
}

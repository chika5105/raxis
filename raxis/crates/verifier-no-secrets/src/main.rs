// raxis-verifier-no-secrets::main — mechanical checker entry point.
//
// This binary intentionally does not know how to submit a witness.
// It is launched underneath the canonical `raxis-verifier` shim via
// `RAXIS_VERIFIER_COMMAND`; the shim owns the one-use verifier token,
// captures this process's output/artifact, submits exactly one
// WitnessSubmission, and reads the kernel ack.

use std::process::ExitCode as ProcessExit;

use raxis_verifier_no_secrets::{
    parse_mechanical_env_from_process, report_json, scan_worktree_for_secrets,
    write_artifact_if_requested, ExitCode, MechanicalEnvError, ScanOpts,
};

fn main() -> ProcessExit {
    match run() {
        Ok(code) | Err(code) => ProcessExit::from(code.as_i32() as u8),
    }
}

fn run() -> Result<ExitCode, ExitCode> {
    let env = match parse_mechanical_env_from_process() {
        Ok(e) => e,
        Err(MechanicalEnvError::Missing(var)) => {
            eprintln!(
                "raxis-verifier-no-secrets: missing required env var {var}; \
                 the parent verifier shim did not set the spawn envelope correctly"
            );
            return Err(ExitCode::MissingEnv);
        }
    };

    let report = scan_worktree_for_secrets(&env.worktree_root, &ScanOpts::default());
    let summary = report_json(&report);
    println!("{summary}");

    if let Err(e) = write_artifact_if_requested(&env, &report) {
        eprintln!("raxis-verifier-no-secrets: artifact write failed: {e}");
        return Err(ExitCode::ArtifactWriteFailed);
    }

    Ok(report.exit_code())
}

// raxis-verifier::main — V2 production verifier binary entry point.
//
// Thin shim over `raxis_verifier::lib`. Every substantive code path
// is delegated to a function in `lib.rs` that has its own unit test;
// the responsibility of this file is the I/O glue:
//
//   1. Parse the spawn-envelope env vars (`parse_verifier_env_from_process`).
//   2. Run `RAXIS_VERIFIER_COMMAND` under `sh -lc` with the
//      operator-supplied wall-clock timeout (`run_verifier_command`).
//   3. Optionally load the artefact at `RAXIS_VERIFIER_ARTIFACT_PATH`
//      (size-capped, path-traversal-rejected; `load_artifact_if_present`).
//   4. Map the exit code to a `WitnessResultClass` per
//      `verifier-processes.md §6` (`map_exit_to_result_class`).
//   5. Build the `WitnessSubmission` (`build_submission`).
//   6. Connect to the kernel UDS at `RAXIS_KERNEL_SOCKET`, send the
//      submission, read the ack, and exit with the corresponding
//      `ExitCode`.
//
// Why `#[tokio::main(flavor = "current_thread")]`
// ───────────────────────────────────────────────
// Most of the wall-clock budget is the verifier command (`sh -lc`),
// which runs in its own subprocess. The shim itself does one
// command spawn, one UDS round-trip, and one process exit. A
// multi-thread runtime would just add startup latency; the
// kernel's `verifier_max_wall_secs` budget tightens to a few
// seconds in the timeout-path tests, so the lean `current_thread`
// runtime keeps the shim's overhead inside any sane envelope.

use std::process::ExitCode as ProcessExit;

use raxis_ipc::{read_frame, write_frame, IpcMessage};
use raxis_types::WitnessResultClass;
use raxis_verifier::{
    build_submission, load_artifact_if_present, map_exit_to_result_class,
    parse_verifier_env_from_process, run_verifier_command, ArtifactError, CommandOutcome,
    ExitCode, VerifierEnv, VerifierEnvError,
};
use tokio::net::UnixStream;

#[tokio::main(flavor = "current_thread")]
async fn main() -> ProcessExit {
    match run().await {
        Ok(code) => ProcessExit::from(code.as_i32() as u8),
        Err(code) => ProcessExit::from(code.as_i32() as u8),
    }
}

/// One end-to-end verifier run. Every observable side effect
/// (stderr log line, exit code) is anchored here.
async fn run() -> Result<ExitCode, ExitCode> {
    // ── Step 1: env ────────────────────────────────────────────────────────
    let env = match parse_verifier_env_from_process() {
        Ok(e) => e,
        Err(VerifierEnvError::Missing(var)) => {
            eprintln!(
                "raxis-verifier: missing required env var {var}; \
                 the kernel did not set the spawn envelope correctly"
            );
            return Err(ExitCode::MissingEnv);
        }
        Err(VerifierEnvError::Invalid { var, value, reason }) => {
            eprintln!("raxis-verifier: env var {var} has invalid value {value:?}: {reason}");
            return Err(ExitCode::MissingEnv);
        }
    };

    // ── Step 2: run the command ────────────────────────────────────────────
    let outcome = match run_verifier_command(&env).await {
        Ok(o) => o,
        Err(e) => {
            eprintln!("raxis-verifier: run_verifier_command: {e}");
            return Err(ExitCode::IoError);
        }
    };

    // ── Step 3: load artefact (optional) ───────────────────────────────────
    let (artifact, artifact_reject_reason) = match load_artifact_if_present(&env) {
        Ok(opt) => (opt, None),
        Err(e) => {
            // Per `verifier-processes.md §6`, a malformed / oversized
            // artefact must NOT silently drop the witness; we submit
            // an `ArtifactRejected`-shaped Inconclusive witness so
            // the kernel records the failure mode.
            let reason = match &e {
                ArtifactError::Io { .. } => "artifact_io",
                ArtifactError::PathEscape { .. } => "artifact_path_escape",
                ArtifactError::TooLarge { .. } => "artifact_too_large",
            };
            eprintln!("raxis-verifier: load_artifact_if_present: {e}");
            (None, Some(reason))
        }
    };

    // ── Step 4: classify the outcome ───────────────────────────────────────
    let (result_class, failure_reason): (WitnessResultClass, Option<&str>) = if outcome.timed_out {
        (WitnessResultClass::Inconclusive, Some("timeout"))
    } else if artifact_reject_reason.is_some() {
        (WitnessResultClass::Inconclusive, artifact_reject_reason)
    } else {
        let rc = map_exit_to_result_class(outcome.exit_code);
        let reason = match rc {
            WitnessResultClass::Pass => None,
            WitnessResultClass::Fail => Some("nonzero_exit"),
            WitnessResultClass::Inconclusive => Some("crashed_or_signal_terminated"),
        };
        (rc, reason)
    };

    // ── Step 5: build the submission ───────────────────────────────────────
    let submission = match build_submission(
        &env,
        &outcome,
        artifact.as_ref(),
        result_class,
        failure_reason,
    ) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("raxis-verifier: build_submission: {e}");
            return Err(ExitCode::MissingEnv);
        }
    };

    // ── Step 6: connect, send, read ack ───────────────────────────────────
    let mut stream = match UnixStream::connect(&env.socket_path).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!(
                "raxis-verifier: UnixStream::connect({}): {e}",
                env.socket_path
            );
            // Even on connect failure, surface the disposition that
            // matches the underlying classifier so the kernel-side
            // watcher's exit-code interpretation stays consistent.
            return Err(short_circuit_exit_code(&env, &outcome, artifact_reject_reason));
        }
    };

    if let Err(e) = write_frame(&mut stream, &IpcMessage::WitnessSubmission(submission)).await {
        eprintln!("raxis-verifier: write_frame: {e}");
        return Err(short_circuit_exit_code(&env, &outcome, artifact_reject_reason));
    }

    let ack: IpcMessage = match read_frame(&mut stream).await {
        Ok(m) => m,
        Err(e) => {
            eprintln!("raxis-verifier: read_frame: {e}");
            return Err(short_circuit_exit_code(&env, &outcome, artifact_reject_reason));
        }
    };

    // ── Step 7: classify the ack ───────────────────────────────────────────
    //
    // The on-stdout summary is a single JSON object so test harnesses
    // and dashboards can parse it without regex. Field set is
    // intentionally a superset of the test-only `verifier-stub`'s
    // summary — same `verifier_run_id` / `accepted` / `reason` keys,
    // plus the `result_class`, `exit_code`, and `timed_out` the
    // production binary observed.
    match ack {
        IpcMessage::WitnessAck {
            verifier_run_id,
            accepted,
            reason,
        } => {
            let summary = serde_json::json!({
                "verifier_event": "witness_ack",
                "verifier_run_id": verifier_run_id.to_string(),
                "accepted":       accepted,
                "reason":         reason,
                "result_class":   match result_class {
                    WitnessResultClass::Pass => "Pass",
                    WitnessResultClass::Fail => "Fail",
                    WitnessResultClass::Inconclusive => "Inconclusive",
                },
                "exit_code":      outcome.exit_code,
                "timed_out":      outcome.timed_out,
            });
            println!("{summary}");
            if outcome.timed_out {
                Err(ExitCode::Timeout)
            } else if artifact_reject_reason.is_some() {
                Err(ExitCode::ArtifactRejected)
            } else if accepted {
                Ok(ExitCode::AcceptedPass)
            } else {
                Err(ExitCode::Rejected)
            }
        }
        other => {
            eprintln!("raxis-verifier: expected WitnessAck, got {other:?}");
            Err(ExitCode::IoError)
        }
    }
}

/// Pick the most-honest exit code for a UDS-side failure given what
/// the verifier already observed about the command. Timeout and
/// artefact-rejection have priority over the generic IoError so the
/// kernel-side watcher can distinguish a witness path that was
/// short-circuited upstream from a real UDS failure.
fn short_circuit_exit_code(
    _env: &VerifierEnv,
    outcome: &CommandOutcome,
    artifact_reject_reason: Option<&str>,
) -> ExitCode {
    if outcome.timed_out {
        ExitCode::Timeout
    } else if artifact_reject_reason.is_some() {
        ExitCode::ArtifactRejected
    } else {
        ExitCode::IoError
    }
}

// raxis-verifier-no-secrets::main — Binary entry point.
//
// Thin shim over `raxis_verifier_no_secrets::lib`. Every substantive
// code path is delegated to a function in `lib.rs` that has its own
// unit test; the responsibility of this file is the I/O glue:
//
//   1. Parse the spawn-envelope env vars.
//   2. Run the worktree scan.
//   3. Build the WitnessSubmission.
//   4. Connect to the kernel's UDS.
//   5. Send one IpcMessage::WitnessSubmission.
//   6. Read one IpcMessage::WitnessAck.
//   7. Print a one-line summary on stdout and exit with the
//      matching `ExitCode`.
//
// Why `#[tokio::main(flavor = "current_thread")]`
// ───────────────────────────────────────────────
// Same rationale as `raxis-verifier-stub`: we do exactly one connect,
// one send, one read, then exit. A multi-thread runtime would just
// add startup latency; the kernel's wall-clock kill timer in
// `verifier_runner.rs` is not generous (default 30 s), and the
// scanner itself is sync I/O. The `current_thread` flavor finishes
// the round trip in ~1 ms on a quiet system after the scan.

use std::process::ExitCode as ProcessExit;

use raxis_ipc::{read_frame, write_frame, IpcMessage};
use raxis_verifier_no_secrets::{
    build_submission, parse_scanner_env_from_process, scan_worktree_for_secrets, ExitCode,
    ScanOpts, ScannerEnvError,
};
use tokio::net::UnixStream;

#[tokio::main(flavor = "current_thread")]
async fn main() -> ProcessExit {
    match run().await {
        Ok(code) => ProcessExit::from(code.as_i32() as u8),
        Err(code) => ProcessExit::from(code.as_i32() as u8),
    }
}

/// One end-to-end run. Every observable side effect (stderr log,
/// stdout summary, exit code) is anchored here.
async fn run() -> Result<ExitCode, ExitCode> {
    // ── Step 1: env ────────────────────────────────────────────────────────
    let env = match parse_scanner_env_from_process() {
        Ok(e) => e,
        Err(ScannerEnvError::Missing(var)) => {
            eprintln!(
                "raxis-verifier-no-secrets: missing required env var {var}; \
                 the parent process did not set the spawn envelope correctly"
            );
            return Err(ExitCode::MissingEnv);
        }
    };

    // ── Step 2: scan ───────────────────────────────────────────────────────
    // Default opts are conservative and non-tunable from the env on
    // purpose: an operator who wants to relax the secret patterns
    // should ship a different verifier binary, not a knob on this
    // one. Knobs in spawn envelopes are an attack surface a leaked
    // verifier process could exploit to weaken its own gate.
    let report = scan_worktree_for_secrets(&env.worktree_root, &ScanOpts::default());

    // ── Step 3: build submission ───────────────────────────────────────────
    let submission = match build_submission(&env, &report) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("raxis-verifier-no-secrets: build_submission failed: {e}");
            return Err(ExitCode::MissingEnv);
        }
    };

    // ── Step 4: connect ────────────────────────────────────────────────────
    let mut stream = match UnixStream::connect(&env.socket_path).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!(
                "raxis-verifier-no-secrets: UnixStream::connect({}): {e}",
                env.socket_path
            );
            return Err(ExitCode::IoError);
        }
    };

    // ── Step 5: send ───────────────────────────────────────────────────────
    if let Err(e) = write_frame(&mut stream, &IpcMessage::WitnessSubmission(submission)).await {
        eprintln!("raxis-verifier-no-secrets: write_frame: {e}");
        return Err(ExitCode::IoError);
    }

    // ── Step 6: read ack ───────────────────────────────────────────────────
    let ack: IpcMessage = match read_frame(&mut stream).await {
        Ok(m) => m,
        Err(e) => {
            eprintln!("raxis-verifier-no-secrets: read_frame: {e}");
            return Err(ExitCode::IoError);
        }
    };

    // ── Step 7: classify the ack ───────────────────────────────────────────
    match ack {
        IpcMessage::WitnessAck {
            verifier_run_id,
            accepted,
            reason,
        } => {
            // Stable JSON shape on stdout so a future operator-side
            // dashboard can `serde_json::from_str` the verifier's
            // closing line. Stderr is reserved for human diagnostics.
            let summary = serde_json::json!({
                "verifier":         "raxis-verifier-no-secrets",
                "verifier_run_id":  verifier_run_id.to_string(),
                "accepted":         accepted,
                "reason":           reason,
                "result_class":     report.result_class().as_sql_str(),
            });
            println!("{summary}");
            if accepted {
                Ok(ExitCode::AcceptedPass)
            } else {
                Err(ExitCode::Rejected)
            }
        }
        other => {
            eprintln!(
                "raxis-verifier-no-secrets: expected WitnessAck, got {other:?}"
            );
            Err(ExitCode::IoError)
        }
    }
}

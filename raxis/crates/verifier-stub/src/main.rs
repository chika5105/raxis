// raxis-verifier-stub::main — Binary entry point.
//
// Thin shim over `raxis_verifier_stub::lib`. Every substantive code path
// here is delegated to a function in `lib.rs` that has its own unit test;
// the responsibility of this file is the I/O glue:
//   1. Parse the spawn-envelope env vars.
//   2. Build the WitnessSubmission.
//   3. Connect to the kernel's UDS.
//   4. Send one IpcMessage::WitnessSubmission.
//   5. Read one IpcMessage::WitnessAck.
//   6. Print a one-line summary and exit with the matching `ExitCode`.
//
// Why `#[tokio::main(flavor = "current_thread")]`
// ───────────────────────────────────────────────
// We do exactly one connect, one send, one read, then exit. A multi-thread
// runtime would just add startup latency; the kernel's wall-clock kill
// timer in `verifier_runner.rs` is not generous (default 30 s, but
// individual tests turn it down to 1 s for the kill-path). The
// `current_thread` flavor finishes the I/O round trip in ~1 ms on a quiet
// system, leaving plenty of headroom inside any sane wall-clock budget.

use std::process::ExitCode as ProcessExit;

use raxis_ipc::{read_frame, write_frame, IpcMessage};
use raxis_verifier_stub::{
    build_submission, parse_stub_env_from_process, ExitCode, StubEnv, StubEnvError,
};
use tokio::net::UnixStream;

#[tokio::main(flavor = "current_thread")]
async fn main() -> ProcessExit {
    // We go through `run` rather than inlining everything in `main` so
    // a future test that spawns the stub in-process (e.g. a future
    // `escargot`-style runner) can call `run` directly without going
    // through `tokio::main`. Returning the lib's `ExitCode` from `run`
    // keeps the I/O glue minimal and lets the unit tests in `lib.rs`
    // own the exit-code mapping table.
    match run().await {
        Ok(code) => ProcessExit::from(code.as_i32() as u8),
        Err(code) => ProcessExit::from(code.as_i32() as u8),
    }
}

/// One end-to-end stub run. Every observable side effect (stderr log,
/// exit code) is anchored here; `main()` adds nothing beyond plumbing
/// the result to the OS.
async fn run() -> Result<ExitCode, ExitCode> {
    // ── Step 1: env ────────────────────────────────────────────────────────
    let env = match parse_stub_env_from_process() {
        Ok(e) => e,
        Err(StubEnvError::Missing(var)) => {
            eprintln!("raxis-verifier-stub: missing required env var {var}; \
                       the parent process did not set the spawn envelope correctly");
            return Err(ExitCode::MissingEnv);
        }
        Err(StubEnvError::Invalid { var, value, reason }) => {
            eprintln!("raxis-verifier-stub: env var {var} has invalid value {value:?}: {reason}");
            // Invalid optional knobs are an environment failure too;
            // surface as MissingEnv so the test harness can grep one
            // exit code rather than two for "envelope is wrong".
            return Err(ExitCode::MissingEnv);
        }
    };

    // ── Step 2: build the submission ───────────────────────────────────────
    let submission = match build_submission(&env) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("raxis-verifier-stub: build_submission failed: {e}");
            return Err(ExitCode::MissingEnv);
        }
    };

    // ── Step 3: optional pre-connect sleep (wall-clock-kill tests) ─────────
    if env.sleep_ms > 0 {
        tokio::time::sleep(std::time::Duration::from_millis(env.sleep_ms)).await;
    }

    // ── Step 4: connect ────────────────────────────────────────────────────
    // We do not retry on connect failure; the kernel's `verifier_runner`
    // assumes the verifier owns its UDS lifecycle and a connect-retry
    // loop in the verifier would mask kernel-side races (e.g. a kernel
    // shutdown during witness submission would look like flake instead
    // of being surfaced).
    let mut stream = match UnixStream::connect(&env.socket_path).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("raxis-verifier-stub: UnixStream::connect({}): {e}",
                env.socket_path);
            return Err(ExitCode::IoError);
        }
    };

    // ── Step 5: skip-send branch (kernel EOF testing) ──────────────────────
    if env.skip_send {
        // We connected, the kernel saw an accept; now drop the stream
        // so the kernel's `read_frame` returns `FrameError::Eof`. This
        // is the dial tests use to verify the kernel's clean-disconnect
        // handling on the planner socket.
        drop(stream);
        eprintln!("raxis-verifier-stub: RAXIS_STUB_SKIP_SEND=1 — connected and dropped");
        return Ok(ExitCode::SkippedSend);
    }

    // ── Step 6: send the witness submission ────────────────────────────────
    // Routes through `raxis_ipc::write_frame` so the bytes on the wire
    // are the SAME ones a production verifier would emit (4-byte LE
    // length prefix + bincode 2.0.1 standard() body). Reinventing the
    // framing here would defeat the purpose of having the stub at all.
    if let Err(e) = write_frame(
        &mut stream,
        &IpcMessage::WitnessSubmission(StubEnvSubmission(env, submission).into_message()),
    ).await {
        eprintln!("raxis-verifier-stub: write_frame: {e}");
        return Err(ExitCode::IoError);
    }

    // ── Step 7: read the kernel's ack ──────────────────────────────────────
    let ack: IpcMessage = match read_frame(&mut stream).await {
        Ok(m) => m,
        Err(e) => {
            eprintln!("raxis-verifier-stub: read_frame: {e}");
            return Err(ExitCode::IoError);
        }
    };

    // ── Step 8: classify the ack and print the one-line summary ────────────
    // The summary is a single JSON object on stdout for the test harness
    // to capture and assert against. Stderr is reserved for human
    // diagnostics; tests should not depend on stderr text.
    match ack {
        IpcMessage::WitnessAck { verifier_run_id, accepted, reason } => {
            // Print a stable JSON shape so downstream test code can
            // `serde_json::from_str` rather than regex over the line.
            // Field set is pinned by the integration test in
            // `kernel/tests/witness_round_trip_via_stub.rs`.
            let summary = serde_json::json!({
                "stub_event":      "witness_ack",
                "verifier_run_id": verifier_run_id.to_string(),
                "accepted":        accepted,
                "reason":          reason,
            });
            println!("{summary}");
            if accepted {
                Ok(ExitCode::AcceptedPass)
            } else {
                Err(ExitCode::Rejected)
            }
        }
        other => {
            // The kernel only sends WitnessAck in reply to a
            // WitnessSubmission on the planner socket; any other variant
            // means the kernel's dispatcher is confused. We surface the
            // received discriminant for debuggability.
            eprintln!("raxis-verifier-stub: expected WitnessAck, got {other:?}");
            Err(ExitCode::IoError)
        }
    }
}

// ---------------------------------------------------------------------------
// Internal helper: avoid moving `StubEnv` into the IpcMessage twice.
// ---------------------------------------------------------------------------
//
// `parse_stub_env_from_process` returns the env once; `build_submission`
// borrows it. The wire-write call above wants `WitnessSubmission` by value
// because `IpcMessage::WitnessSubmission(...)` takes ownership. We keep
// both around (the env for the eventual stderr summary, the submission
// for the wire) by wrapping them in this newtype that exposes a one-shot
// move into the `IpcMessage`. Avoids cloning the JSON body twice.
struct StubEnvSubmission(#[allow(dead_code)] StubEnv, raxis_types::WitnessSubmission);
impl StubEnvSubmission {
    fn into_message(self) -> raxis_types::WitnessSubmission {
        self.1
    }
}

// Witness tests for `INV-SUPERVISOR-EXIT-CODE-CLASSIFICATION-01`,
// `INV-SUPERVISOR-CIRCUIT-BREAKER-01`, `INV-SUPERVISOR-OPT-IN-01`.
//
// Each test spawns the real supervisor loop against a fake-child
// binary that exits with a deterministic code, and asserts the
// supervisor's `SupervisorRunReport` reflects the right
// classification + restart decision. The fake-child binaries are
// declared in this crate's `Cargo.toml [[bin]]` section.

use std::path::PathBuf;
use std::sync::Arc;

use raxis_supervisor::log::SupervisorLog;
use raxis_supervisor::sentinel::{read_sentinel, SENTINEL_FILENAME};
use raxis_supervisor::signal::IntentionalShutdownFlag;
use raxis_supervisor::supervisor::{run_supervisor_loop, FinalOutcome, SupervisorConfig};

/// Resolve the path to a fake-child binary by name. Cargo writes
/// these next to the test binary itself when the workspace is
/// built; the test discovers them via `CARGO_BIN_EXE_*` injected
/// at compile time when the test is part of a `[[bin]]`-aware
/// crate.
fn fake_child(name: &str) -> PathBuf {
    // `env!()` doesn't accept dynamic strings, so each binary
    // gets a hand-written constant lookup. Adding a new fake
    // child binary requires:
    //   1. a new `tests/bin/<name>.rs` file
    //   2. a new `[[bin]]` entry in `Cargo.toml`
    //   3. a new arm in the match below
    let path = match name {
        "exit70" => env!("CARGO_BIN_EXE_supervisor-fake-child-exit70"),
        "exit0" => env!("CARGO_BIN_EXE_supervisor-fake-child-exit0"),
        "panic" => env!("CARGO_BIN_EXE_supervisor-fake-child-panic"),
        "sleep_forever" => env!("CARGO_BIN_EXE_supervisor-fake-child-sleep-forever"),
        "slow_sigterm" => env!("CARGO_BIN_EXE_supervisor-fake-child-slow-sigterm"),
        other => panic!("unknown fake-child binary: {other}"),
    };
    PathBuf::from(path)
}

fn cfg_for(
    data_dir: &std::path::Path,
    binary: PathBuf,
    max_attempts: u32,
    max_child_runs: Option<u32>,
) -> SupervisorConfig {
    SupervisorConfig {
        data_dir: data_dir.to_path_buf(),
        kernel_binary: binary,
        kernel_args: Vec::new(),
        kernel_env: Vec::new(),
        max_attempts,
        window_secs: 60,
        shutdown_grace_secs: 1,
        restart_backoff_ms: 10,
        max_child_runs,
        require_initialized_data_dir: false,
    }
}

/// `INV-SUPERVISOR-EXIT-CODE-CLASSIFICATION-01` row "WEXITSTATUS = 0":
/// clean exit MUST NOT trigger a restart. The supervisor's
/// `final_outcome` is `OperatorStop` and `child_runs_observed` is 1.
#[tokio::test]
async fn clean_exit_zero_does_not_restart() {
    let dir = tempfile::tempdir().unwrap();
    let log = Arc::new(SupervisorLog::open(dir.path()).unwrap());
    let intent = IntentionalShutdownFlag::new();
    let notify = Arc::new(tokio::sync::Notify::new());
    let cfg = cfg_for(dir.path(), fake_child("exit0"), 3, Some(5));
    let report = run_supervisor_loop(cfg, intent, notify, log).await.unwrap();
    assert_eq!(report.child_runs_observed, 1);
    assert_eq!(report.final_outcome, FinalOutcome::OperatorStop);
    assert_eq!(report.last_exit_code, 0);
    let sentinel = read_sentinel(dir.path()).unwrap().unwrap();
    assert_eq!(sentinel.status, "Halted");
    assert_eq!(sentinel.sub_state.as_deref(), Some("OperatorStop"));
    assert!(dir.path().join(SENTINEL_FILENAME).exists());
}

/// `INV-SUPERVISOR-EXIT-CODE-CLASSIFICATION-01` row "WEXITSTATUS = 70":
/// deadlock-detected exit IS restart-eligible.
/// `INV-SUPERVISOR-CIRCUIT-BREAKER-01`: 4 deadlocks (max_attempts=3)
/// trips the breaker, supervisor halts.
#[tokio::test]
async fn exit_70_restarts_until_breaker_trips() {
    let dir = tempfile::tempdir().unwrap();
    let log = Arc::new(SupervisorLog::open(dir.path()).unwrap());
    let intent = IntentionalShutdownFlag::new();
    let notify = Arc::new(tokio::sync::Notify::new());
    // max_attempts=3 → fourth attempt trips the breaker, so we
    // expect 4 spawns before halting.
    let cfg = cfg_for(dir.path(), fake_child("exit70"), 3, Some(10));
    let report = run_supervisor_loop(cfg, intent, notify, log).await.unwrap();
    assert_eq!(report.child_runs_observed, 4);
    match report.final_outcome {
        FinalOutcome::CircuitOpen {
            attempts_in_window,
            window_secs,
        } => {
            assert_eq!(attempts_in_window, 4);
            assert_eq!(window_secs, 60);
        }
        other => panic!("expected CircuitOpen, got {other:?}"),
    }
    assert_eq!(report.last_exit_code, 70);
    let sentinel = read_sentinel(dir.path()).unwrap().unwrap();
    assert_eq!(sentinel.status, "Halted");
    assert_eq!(sentinel.sub_state.as_deref(), Some("CircuitOpen"));
    assert_eq!(
        sentinel.last_restart_reason.as_deref(),
        Some("DeadlockDetected"),
    );
    assert_eq!(sentinel.attempts_in_window, 4);
}

/// `INV-SUPERVISOR-EXIT-CODE-CLASSIFICATION-01` row "WEXITSTATUS = N (≠ 0, 70)":
/// non-zero exit IS restart-eligible (PanicAbort path). Combined
/// with `INV-SUPERVISOR-CIRCUIT-BREAKER-01` to bound the test.
#[tokio::test]
async fn exit_101_panic_restarts_until_breaker_trips() {
    let dir = tempfile::tempdir().unwrap();
    let log = Arc::new(SupervisorLog::open(dir.path()).unwrap());
    let intent = IntentionalShutdownFlag::new();
    let notify = Arc::new(tokio::sync::Notify::new());
    let cfg = cfg_for(dir.path(), fake_child("panic"), 2, Some(10));
    let report = run_supervisor_loop(cfg, intent, notify, log).await.unwrap();
    // max_attempts=2 → third attempt trips the breaker, so we
    // expect 3 spawns.
    assert_eq!(report.child_runs_observed, 3);
    match report.final_outcome {
        FinalOutcome::CircuitOpen {
            attempts_in_window, ..
        } => {
            assert_eq!(attempts_in_window, 3);
        }
        other => panic!("expected CircuitOpen, got {other:?}"),
    }
    assert_eq!(report.last_exit_code, 101);
    let sentinel = read_sentinel(dir.path()).unwrap().unwrap();
    assert_eq!(sentinel.last_restart_reason.as_deref(), Some("PanicAbort"));
}

/// Cold-start with a pre-tripped breaker MUST refuse to spawn.
/// `child_runs_observed = 0`.
#[tokio::test]
async fn cold_start_with_open_breaker_refuses_to_spawn() {
    let dir = tempfile::tempdir().unwrap();
    // Pre-trip the breaker by recording 4 attempts (max=3).
    let mut breaker = raxis_supervisor::CircuitBreaker::load_or_default(dir.path(), 3, 60);
    for _ in 0..4 {
        breaker.record_attempt(1_000, "DeadlockDetected");
    }
    breaker.save().unwrap();
    assert!(breaker.is_tripped());

    let log = Arc::new(SupervisorLog::open(dir.path()).unwrap());
    let intent = IntentionalShutdownFlag::new();
    let notify = Arc::new(tokio::sync::Notify::new());
    let cfg = cfg_for(dir.path(), fake_child("exit70"), 3, Some(10));
    let report = run_supervisor_loop(cfg, intent, notify, log).await.unwrap();
    assert_eq!(report.child_runs_observed, 0);
    matches!(report.final_outcome, FinalOutcome::CircuitOpen { .. });
    let sentinel = read_sentinel(dir.path()).unwrap().unwrap();
    assert_eq!(sentinel.status, "Halted");
    assert_eq!(sentinel.sub_state.as_deref(), Some("CircuitOpen"));
}

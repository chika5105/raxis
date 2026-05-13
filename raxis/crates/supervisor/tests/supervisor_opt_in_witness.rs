// Witness test for `INV-SUPERVISOR-OPT-IN-01`.
//
// Spawns the real `raxis-supervisor` binary against a fake-child
// kernel that exits 70 (deadlock-detected). Asserts:
//
//   * WITHOUT `RAXIS_SUPERVISOR_AUTO_RESTART=1`: the supervisor
//     spawns the kernel exactly once and forwards the exit code
//     (i.e. behaves as a passthrough). No sentinel file is
//     written. No supervisor.stderr.log is opened. No
//     supervisor_state.json. The supervisor exits with the
//     kernel's exit code (70).
//
//   * WITH `RAXIS_SUPERVISOR_AUTO_RESTART=1`: the supervisor
//     enters the spawn-wait-classify-decide loop. After the
//     breaker trips it exits with a non-zero code (75 / EX_TEMPFAIL)
//     and the sentinel file shows `Halted{CircuitOpen}`.

use std::path::PathBuf;
use std::process::Command;

fn supervisor_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_raxis-supervisor"))
}

fn fake_child(name: &str) -> PathBuf {
    let path = match name {
        "exit70" => env!("CARGO_BIN_EXE_supervisor-fake-child-exit70"),
        "exit0"  => env!("CARGO_BIN_EXE_supervisor-fake-child-exit0"),
        other => panic!("unknown fake-child binary: {other}"),
    };
    PathBuf::from(path)
}

/// `INV-SUPERVISOR-OPT-IN-01`: without the env var, the
/// supervisor is a passthrough wrapper. Live-e2e iter41+
/// behaviour MUST be bit-identical to running the kernel
/// directly.
#[test]
fn passthrough_when_opt_in_env_var_unset_writes_no_sentinel() {
    let dir = tempfile::tempdir().unwrap();
    let kernel = fake_child("exit70");
    let supervisor = supervisor_binary();
    let output = Command::new(&supervisor)
        .arg("start")
        .arg("--data-dir")
        .arg(dir.path())
        .arg("--kernel-binary")
        .arg(&kernel)
        // Explicitly clear so a developer environment that has
        // it set doesn't break this test.
        .env_remove("RAXIS_SUPERVISOR_AUTO_RESTART")
        .output()
        .expect("spawn supervisor");
    assert_eq!(
        output.status.code(),
        Some(70),
        "supervisor passthrough MUST forward the kernel's exit code (70). stderr: {}",
        String::from_utf8_lossy(&output.stderr),
    );
    // No sentinel file — passthrough mode does NOT touch the
    // data dir at all.
    assert!(
        !dir.path().join("kernel_lifecycle_status.json").exists(),
        "passthrough mode MUST NOT write the sentinel file (live-e2e expects an unchanged data dir).",
    );
    assert!(
        !dir.path().join("supervisor_state.json").exists(),
        "passthrough mode MUST NOT write the breaker state.",
    );
    assert!(
        !dir.path().join("supervisor.stderr.log").exists(),
        "passthrough mode MUST NOT open the supervisor stderr log.",
    );
}

/// `INV-SUPERVISOR-OPT-IN-01`: with the env var set, the
/// supervisor enters the spawn-wait-classify-decide loop and
/// halts on circuit-breaker trip.
#[test]
fn opt_in_env_var_engages_loop_and_writes_sentinel() {
    let dir = tempfile::tempdir().unwrap();
    let kernel = fake_child("exit70");
    let supervisor = supervisor_binary();
    // Bound the test budget: the supervisor with default
    // 250ms back-off and 4 spawns should complete in ~1.5s.
    let output = Command::new(&supervisor)
        .arg("start")
        .arg("--data-dir")
        .arg(dir.path())
        .arg("--kernel-binary")
        .arg(&kernel)
        .env("RAXIS_SUPERVISOR_AUTO_RESTART", "1")
        .output()
        .expect("spawn supervisor");
    // Exit code 75 (EX_TEMPFAIL) when circuit-open per main.rs.
    assert_eq!(
        output.status.code(),
        Some(75),
        "opt-in mode MUST exit 75 (EX_TEMPFAIL) when the breaker trips. stderr: {}",
        String::from_utf8_lossy(&output.stderr),
    );
    let sentinel_bytes = std::fs::read(dir.path().join("kernel_lifecycle_status.json"))
        .expect("opt-in mode MUST write the sentinel file");
    let sentinel: serde_json::Value =
        serde_json::from_slice(&sentinel_bytes).expect("sentinel parses");
    assert_eq!(sentinel["status"], "Halted");
    assert_eq!(sentinel["sub_state"], "CircuitOpen");
    assert_eq!(sentinel["last_restart_reason"], "DeadlockDetected");
}

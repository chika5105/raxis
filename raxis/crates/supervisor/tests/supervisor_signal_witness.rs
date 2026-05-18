// Witness tests for `INV-SUPERVISOR-SIGTERM-RESPECT-01`,
// `INV-SUPERVISOR-SIGINT-RESPECT-01`, `INV-SUPERVISOR-SHUTDOWN-GRACE-01`.
//
// **Approach.** Spawn the actual `raxis-supervisor` binary as a
// subprocess (NOT via `run_supervisor_loop` in-process — that
// approach hits a tokio::process::Child SIGCHLD reactor wedge
// when the test runtime is shared across multiple integration
// tests). Send the supervisor a real SIGTERM via `nix::kill`,
// wait up to 15 s for the supervisor to halt, then read the
// sentinel file the supervisor wrote on its way out.
//
// This is closer to production behaviour anyway: in production
// the supervisor is signalled by an external operator
// (`raxis-supervisor stop`, `launchctl stop`, `kill -TERM`),
// not by an in-process `Notify`.

#![cfg(unix)]

use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant};

use raxis_supervisor::sentinel::read_sentinel;

fn supervisor_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_raxis-supervisor"))
}

fn fake_child(name: &str) -> PathBuf {
    let path = match name {
        "sleep_forever" => env!("CARGO_BIN_EXE_supervisor-fake-child-sleep-forever"),
        "slow_sigterm" => env!("CARGO_BIN_EXE_supervisor-fake-child-slow-sigterm"),
        other => panic!("unknown fake-child binary: {other}"),
    };
    PathBuf::from(path)
}

/// Wait until the sentinel file under `data_dir` reflects the
/// supervisor having halted (status == `Halted`), or `timeout`
/// elapses. Returns the parsed sentinel on success.
fn await_sentinel_halted(
    data_dir: &std::path::Path,
    timeout: Duration,
) -> Option<raxis_supervisor::sentinel::Sentinel> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if let Ok(Some(s)) = read_sentinel(data_dir) {
            if s.status == "Halted" {
                return Some(s);
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    None
}

fn await_file(path: &std::path::Path, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if path.exists() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    false
}

fn send_sigterm(pid: u32) {
    use nix::sys::signal::{kill, Signal};
    use nix::unistd::Pid;
    kill(Pid::from_raw(pid as i32), Signal::SIGTERM)
        .unwrap_or_else(|e| panic!("kill SIGTERM pid={pid}: {e}"));
}

/// `INV-SUPERVISOR-SIGTERM-RESPECT-01`: when an external SIGTERM
/// reaches the supervisor, the supervisor forwards SIGTERM to
/// the kernel, classifies the resulting signaled exit as
/// `CleanExit` (because `intent_flag` was set first), and halts
/// without restarting.
#[test]
fn external_sigterm_to_supervisor_forwards_to_kernel_and_halts_no_restart() {
    let dir = tempfile::tempdir().unwrap();
    let supervisor = supervisor_binary();
    let kernel = fake_child("sleep_forever");
    let mut child = Command::new(&supervisor)
        .arg("start")
        .arg("--data-dir")
        .arg(dir.path())
        .arg("--kernel-binary")
        .arg(&kernel)
        .env("RAXIS_SUPERVISOR_AUTO_RESTART", "1")
        .env("RAXIS_SUPERVISOR_SHUTDOWN_GRACE_SECS", "5")
        .spawn()
        .expect("spawn supervisor");

    // Give the supervisor time to write its first sentinel +
    // spawn the kernel.
    std::thread::sleep(Duration::from_millis(800));

    // Send SIGTERM directly to the supervisor PID. The
    // supervisor's `install_handlers` task observes it, sets
    // `intent_flag`, and forwards SIGTERM to the kernel.
    send_sigterm(child.id());

    // Wait for the supervisor to write `Halted{OperatorStop}`.
    let sentinel = await_sentinel_halted(dir.path(), Duration::from_secs(15))
        .expect("supervisor must halt within 15s of SIGTERM");
    let status = child
        .wait()
        .expect("supervisor child must exit cleanly within deadline");

    assert_eq!(sentinel.status, "Halted");
    assert_eq!(
        sentinel.sub_state.as_deref(),
        Some("OperatorStop"),
        "supervisor MUST record OperatorStop when its own SIGTERM forwarding triggered the halt",
    );
    assert_eq!(
        sentinel.last_restart_reason.as_deref(),
        Some("CleanExit"),
        "supervisor MUST classify its own SIGTERM forwarding as CleanExit, not OperatorSignalExit",
    );
    // Supervisor exits 0 on operator stop.
    assert_eq!(
        status.code(),
        Some(0),
        "supervisor MUST exit 0 on OperatorStop"
    );
}

/// `INV-SUPERVISOR-SHUTDOWN-GRACE-01`: when the kernel ignores
/// SIGTERM, the supervisor escalates to SIGKILL after
/// `RAXIS_SUPERVISOR_SHUTDOWN_GRACE_SECS` and the sentinel
/// records `OperatorStopForced`.
#[test]
fn slow_sigterm_kernel_triggers_sigkill_escalation_and_operator_stop_forced() {
    let dir = tempfile::tempdir().unwrap();
    let supervisor = supervisor_binary();
    let kernel = fake_child("slow_sigterm");
    let ready_file = dir.path().join("slow-sigterm.ready");
    let mut child = Command::new(&supervisor)
        .arg("start")
        .arg("--data-dir")
        .arg(dir.path())
        .arg("--kernel-binary")
        .arg(&kernel)
        .env("RAXIS_SUPERVISOR_AUTO_RESTART", "1")
        .env("RAXIS_SUPERVISOR_SHUTDOWN_GRACE_SECS", "1")
        .env("SUPERVISOR_FAKE_READY_FILE", &ready_file)
        .spawn()
        .expect("spawn supervisor");

    assert!(
        await_file(&ready_file, Duration::from_secs(10)),
        "fake child must install SIGTERM ignore handler before test sends SIGTERM",
    );
    send_sigterm(child.id());

    // Grace 1s + slack — supervisor escalates to SIGKILL after
    // 1 s and the kernel dies immediately. Total supervisor
    // halt time is ~1.5 s in the worst case.
    let sentinel = await_sentinel_halted(dir.path(), Duration::from_secs(15))
        .expect("supervisor must halt within 15s after grace expiry");
    let _status = child
        .wait()
        .expect("supervisor child must exit cleanly within deadline");

    assert_eq!(sentinel.status, "Halted");
    assert_eq!(
        sentinel.sub_state.as_deref(),
        Some("OperatorStopForced"),
        "supervisor MUST record OperatorStopForced when grace expired and SIGKILL was used",
    );
}

/// `raxis-supervisor stop --force` must not SIGKILL the supervisor
/// directly: SIGKILL is uncatchable, so that would skip final
/// sentinel writes and can orphan the kernel child. The command
/// writes a force-stop request, wakes the supervisor with SIGTERM,
/// and the supervisor performs the child SIGKILL itself.
#[test]
fn stop_force_requests_child_sigkill_and_preserves_final_sentinel() {
    let dir = tempfile::tempdir().unwrap();
    let supervisor = supervisor_binary();
    let kernel = fake_child("slow_sigterm");
    let mut child = Command::new(&supervisor)
        .arg("start")
        .arg("--data-dir")
        .arg(dir.path())
        .arg("--kernel-binary")
        .arg(&kernel)
        .env("RAXIS_SUPERVISOR_AUTO_RESTART", "1")
        .env("RAXIS_SUPERVISOR_SHUTDOWN_GRACE_SECS", "30")
        .spawn()
        .expect("spawn supervisor");

    std::thread::sleep(Duration::from_millis(800));
    let output = Command::new(&supervisor)
        .arg("stop")
        .arg("--force")
        .arg("--data-dir")
        .arg(dir.path())
        .output()
        .expect("run supervisor stop --force");
    assert!(
        output.status.success(),
        "stop --force should return success, stderr: {}",
        String::from_utf8_lossy(&output.stderr),
    );

    let sentinel = await_sentinel_halted(dir.path(), Duration::from_secs(15))
        .expect("supervisor must halt after stop --force");
    let status = child
        .wait()
        .expect("supervisor child must exit cleanly within deadline");

    assert_eq!(status.code(), Some(0));
    assert_eq!(sentinel.status, "Halted");
    assert_eq!(
        sentinel.sub_state.as_deref(),
        Some("OperatorStopForced"),
        "force stop must be recorded as OperatorStopForced",
    );
    assert_eq!(
        sentinel.last_restart_reason.as_deref(),
        Some("CleanExit"),
        "force stop is operator intent and must not be classified as OomKilled/restartable",
    );
}

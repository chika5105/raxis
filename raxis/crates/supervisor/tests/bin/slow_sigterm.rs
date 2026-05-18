// Fake kernel binary that intentionally IGNORES SIGTERM and
// sleeps far longer than the supervisor's grace period. Used by
// `tests/supervisor_signal_witness.rs` to verify the supervisor
// escalates to SIGKILL after `RAXIS_SUPERVISOR_SHUTDOWN_GRACE_SECS`
// per `INV-SUPERVISOR-SHUTDOWN-GRACE-01`.

#[cfg(unix)]
fn main() {
    use nix::sys::signal::{sigaction, SaFlags, SigAction, SigHandler, SigSet, Signal};
    // Install SIG_IGN for SIGTERM so the default-disposition
    // exit path is suppressed; SIGKILL cannot be ignored, so the
    // supervisor's escalation is the only thing that can
    // terminate us.
    let action = SigAction::new(SigHandler::SigIgn, SaFlags::empty(), SigSet::empty());
    unsafe {
        sigaction(Signal::SIGTERM, &action).expect("ignore SIGTERM");
    }
    if let Ok(path) = std::env::var("SUPERVISOR_FAKE_READY_FILE") {
        std::fs::write(path, b"ready\n").expect("write ready marker");
    }
    std::thread::sleep(std::time::Duration::from_secs(120));
    std::process::exit(0);
}

#[cfg(not(unix))]
fn main() {
    std::thread::sleep(std::time::Duration::from_secs(120));
}

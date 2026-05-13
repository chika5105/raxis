// raxis-supervisor::signal — operator-signal contract.
//
// Normative reference: `self-healing-supervisor.md §4.5` /
// `INV-SUPERVISOR-SIGTERM-RESPECT-01` /
// `INV-SUPERVISOR-SIGINT-RESPECT-01` /
// `INV-SUPERVISOR-SHUTDOWN-GRACE-01`.
//
// **Why `intentional_shutdown` is load-bearing.** When the
// kernel exits because the supervisor sent SIGTERM, the exit-
// status discriminator alone (`status.signal() == Some(15)`) is
// NOT enough to know whether the operator intended this — an
// EXTERNAL `kill -TERM <kernel_pid>` would produce the same exit
// status. The supervisor MUST distinguish those cases so it can
// respect operator intent (no auto-restart) when the operator
// sent the signal but auto-restart on a deadlock-induced exit.
//
// `intentional_shutdown` is set to `true` BEFORE the supervisor
// sends SIGTERM / SIGINT / SIGKILL to its child kernel. The
// classifier in `classify.rs` reads this flag (via
// `Outcome::OperatorSignalExit { ... }` vs `Outcome::CleanExit`)
// to make the restart decision.
//
// The same flag is also set by the `SIGTERM` / `SIGINT` handlers
// the supervisor installs at startup — when an external operator
// sends `SIGTERM` to the SUPERVISOR itself, the handler sets
// `intentional_shutdown = true` and forwards the signal to the
// kernel before exiting.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// Shared boolean flag the classifier consults. `true` means
/// "the next signaled exit was operator-initiated; do NOT
/// restart". Always cleared back to `false` *after* the
/// classifier has read it for a given exit, so a subsequent
/// natural crash on the next kernel run is restart-eligible.
#[derive(Debug, Clone, Default)]
pub struct IntentionalShutdownFlag(Arc<AtomicBool>);

impl IntentionalShutdownFlag {
    pub fn new() -> Self {
        Self(Arc::new(AtomicBool::new(false)))
    }

    /// Mark the next signaled exit as operator-initiated.
    /// Idempotent — calling twice without an intervening
    /// `take()` is harmless.
    pub fn set(&self) {
        self.0.store(true, Ordering::SeqCst);
    }

    /// `true` iff [`set`] has been called and [`take`] has not
    /// been called since.
    pub fn is_set(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }

    /// Read-and-clear. The classifier calls this exactly once
    /// per child exit so the next child's exit starts from a
    /// clean slate.
    pub fn take(&self) -> bool {
        self.0.swap(false, Ordering::SeqCst)
    }
}

/// Install SIGTERM / SIGINT / SIGHUP handlers that set the
/// supplied [`IntentionalShutdownFlag`]. Returns a
/// `tokio::sync::Notify` the supervisor's main loop can
/// `notified().await` to react to the signal.
///
/// `SIGHUP` is included so a controlling-terminal close (the
/// operator's `ssh` session dropped, etc.) is treated as
/// operator intent rather than as a reason to restart.
///
/// **Why these three signals only.** SIGKILL cannot be caught;
/// SIGSTOP / SIGCONT are job-control and don't terminate;
/// crash signals (SIGSEGV / SIGBUS / SIGABRT) we want to NOT
/// catch — letting the supervisor crash on its own bug surfaces
/// the bug rather than masking it.
#[cfg(unix)]
pub fn install_handlers(flag: IntentionalShutdownFlag) -> Arc<tokio::sync::Notify> {
    use tokio::signal::unix::{signal, SignalKind};

    let notify = Arc::new(tokio::sync::Notify::new());
    let notify_for_handlers = Arc::clone(&notify);
    tokio::spawn(async move {
        let mut sigterm = match signal(SignalKind::terminate()) {
            Ok(s) => s,
            Err(e) => {
                eprintln!(
                    "{{\"level\":\"error\",\"event\":\"supervisor_signal_install_failed\",\
                     \"signal\":\"SIGTERM\",\"reason\":\"{e}\"}}"
                );
                return;
            }
        };
        let mut sigint = match signal(SignalKind::interrupt()) {
            Ok(s) => s,
            Err(e) => {
                eprintln!(
                    "{{\"level\":\"error\",\"event\":\"supervisor_signal_install_failed\",\
                     \"signal\":\"SIGINT\",\"reason\":\"{e}\"}}"
                );
                return;
            }
        };
        let mut sighup = match signal(SignalKind::hangup()) {
            Ok(s) => s,
            Err(e) => {
                eprintln!(
                    "{{\"level\":\"error\",\"event\":\"supervisor_signal_install_failed\",\
                     \"signal\":\"SIGHUP\",\"reason\":\"{e}\"}}"
                );
                return;
            }
        };
        loop {
            tokio::select! {
                _ = sigterm.recv() => {
                    flag.set();
                    notify_for_handlers.notify_waiters();
                    eprintln!(
                        "{{\"level\":\"info\",\"event\":\"supervisor_signal_received\",\
                         \"signal\":\"SIGTERM\"}}"
                    );
                }
                _ = sigint.recv() => {
                    flag.set();
                    notify_for_handlers.notify_waiters();
                    eprintln!(
                        "{{\"level\":\"info\",\"event\":\"supervisor_signal_received\",\
                         \"signal\":\"SIGINT\"}}"
                    );
                }
                _ = sighup.recv() => {
                    flag.set();
                    notify_for_handlers.notify_waiters();
                    eprintln!(
                        "{{\"level\":\"info\",\"event\":\"supervisor_signal_received\",\
                         \"signal\":\"SIGHUP\"}}"
                    );
                }
            }
        }
    });
    notify
}

/// Send `signal` to `pid` via `nix::sys::signal::kill`. Returns
/// `Ok(())` on success and `Err` on `ESRCH` (no such process)
/// / `EPERM` / similar.
#[cfg(unix)]
pub fn send_signal(pid: u32, signal: nix::sys::signal::Signal) -> nix::Result<()> {
    let pid = nix::unistd::Pid::from_raw(pid as i32);
    nix::sys::signal::kill(pid, signal)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flag_starts_unset() {
        let f = IntentionalShutdownFlag::new();
        assert!(!f.is_set());
    }

    #[test]
    fn set_then_is_set_returns_true() {
        let f = IntentionalShutdownFlag::new();
        f.set();
        assert!(f.is_set());
    }

    #[test]
    fn take_clears_the_flag() {
        let f = IntentionalShutdownFlag::new();
        f.set();
        assert!(f.take());
        assert!(!f.is_set());
        assert!(!f.take());
    }

    #[test]
    fn flag_is_thread_safe_via_atomic() {
        let f = IntentionalShutdownFlag::new();
        let f2 = f.clone();
        let handle = std::thread::spawn(move || {
            f2.set();
        });
        handle.join().unwrap();
        assert!(f.is_set());
    }
}

// raxis-supervisor::classify — exit-status → restart decision.
//
// Normative reference: `self-healing-supervisor.md §4.4` /
// `INV-SUPERVISOR-EXIT-CODE-CLASSIFICATION-01`.
//
// The classifier is a pure function of `(exit_status,
// supervisor_sent_signal)`. It does NOT consult the wallclock /
// circuit breaker — those are higher-layer decisions. The only
// thing this module decides is "what kind of exit was that?".
//
// Per `INV-SUPERVISOR-SIGTERM-RESPECT-01` /
// `INV-SUPERVISOR-SIGINT-RESPECT-01`, signaled exits are split by
// whether the supervisor itself sent the signal (the
// `intentional_shutdown` flag in `signal.rs`). The "external SIGTERM /
// SIGINT" case is treated as operator intent and produces
// `Outcome::CleanExit { restart: false }` — auto-restart never
// overrides operator intent.
//
// **Cross-platform note.** The signal-decoding helpers below use
// `std::os::unix::process::ExitStatusExt::signal()` which is
// UNIX-only. The crate as a whole is `cfg(unix)`-bounded via
// `Cargo.toml [target.'cfg(unix)'.dependencies] nix`; running the
// supervisor on Windows would fail at link time before reaching
// this code.

use std::process::ExitStatus;

#[cfg(unix)]
use std::os::unix::process::ExitStatusExt;

/// The outcome of a single child kernel run, from the
/// supervisor's classification perspective.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum Outcome {
    /// Child exited cleanly (`WEXITSTATUS = 0`) OR the child was
    /// killed by a signal the supervisor itself sent (operator-
    /// initiated shutdown). The supervisor MUST NOT restart.
    ///
    /// `prev_run_exit_code` is `0` for the natural-exit case and
    /// `128 + signal` for the supervisor-initiated-signal case
    /// (shell convention; matches `bash $?`).
    CleanExit { prev_run_exit_code: i32 },

    /// Deadlock detected (`WEXITSTATUS = 70`). Restart-eligible
    /// per `self-healing-supervisor.md §3.2`. The supervisor will
    /// consult the circuit breaker before deciding.
    ///
    /// `prev_run_exit_code` is always `70`.
    DeadlockDetected,

    /// Non-zero exit that wasn't 70 (e.g. a panic with `panic =
    /// "abort"` or a `BootError::*` exit code). Restart-eligible.
    PanicAbort { prev_run_exit_code: i32 },

    /// Killed by SIGSEGV / SIGBUS / SIGABRT (abrupt crash, no
    /// chance for the deadlock watcher to write a dump).
    /// Restart-eligible.
    ///
    /// `prev_run_exit_code` is `128 + signal` (shell convention).
    SignalCrash {
        prev_run_exit_code: i32,
        signal: i32,
    },

    /// Killed by SIGKILL the supervisor did NOT send. Almost
    /// certainly the OOM-killer (kernel.audit subsystem on Linux
    /// will have written a kmsg `oom-killer` line); the
    /// supervisor cannot distinguish "OOM" from "operator ran
    /// `kill -9`" so we conservatively treat both as restart-
    /// eligible — operator who actually meant `kill -9` should
    /// use `raxis-supervisor stop --force` which sets the
    /// `intentional_shutdown` flag.
    OomKilled { prev_run_exit_code: i32 },

    /// Killed by SIGTERM / SIGINT the supervisor did NOT send
    /// (external `kill` / launchd / systemd / `ctrl+c` to a
    /// foreground supervisor that's racing the kernel for the
    /// signal). Treated as operator intent per
    /// `INV-SUPERVISOR-SIGTERM-RESPECT-01` /
    /// `INV-SUPERVISOR-SIGINT-RESPECT-01`. The supervisor MUST
    /// NOT restart.
    ///
    /// `prev_run_exit_code` is `128 + signal`.
    OperatorSignalExit {
        prev_run_exit_code: i32,
        signal: i32,
    },
}

impl Outcome {
    /// `true` iff the supervisor should consult the circuit
    /// breaker to decide whether to restart this kind of exit.
    /// `false` means "STOP — operator intent or clean exit".
    pub fn restart_eligible(&self) -> bool {
        matches!(
            self,
            Outcome::DeadlockDetected
                | Outcome::PanicAbort { .. }
                | Outcome::SignalCrash { .. }
                | Outcome::OomKilled { .. }
        )
    }

    /// PascalCase reason string for the audit chain
    /// (`KernelRestartInitiated.reason` /
    /// `KernelRestartHaltedCircuitOpen.last_failure_reason`).
    /// Stable wire vocabulary.
    pub fn reason_str(&self) -> &'static str {
        match self {
            Outcome::CleanExit { .. } => "CleanExit",
            Outcome::DeadlockDetected => "DeadlockDetected",
            Outcome::PanicAbort { .. } => "PanicAbort",
            Outcome::SignalCrash { .. } => "SignalCrash",
            Outcome::OomKilled { .. } => "OomKilled",
            Outcome::OperatorSignalExit { .. } => "OperatorSignalExit",
        }
    }

    /// The numeric exit-status to record under
    /// `KernelRestartInitiated.prev_run_exit_code`.
    pub fn prev_run_exit_code(&self) -> i32 {
        match self {
            Outcome::CleanExit { prev_run_exit_code }
            | Outcome::PanicAbort { prev_run_exit_code }
            | Outcome::OomKilled { prev_run_exit_code }
            | Outcome::SignalCrash {
                prev_run_exit_code, ..
            }
            | Outcome::OperatorSignalExit {
                prev_run_exit_code, ..
            } => *prev_run_exit_code,
            Outcome::DeadlockDetected => 70,
        }
    }
}

/// Classify a child `ExitStatus` into an [`Outcome`] given
/// whether the supervisor itself sent the terminating signal
/// (the `intentional_shutdown` flag — see `signal.rs`).
///
/// **Decision table** (mirror of
/// `self-healing-supervisor.md §4.4`):
///
/// | child exit       | supervisor sent signal? | outcome              |
/// |------------------|-------------------------|----------------------|
/// | WEXITSTATUS = 0  | n/a                     | `CleanExit{0}`       |
/// | WEXITSTATUS = 70 | n/a                     | `DeadlockDetected`   |
/// | WEXITSTATUS = N  | n/a (N ≠ 0, 70)         | `PanicAbort{N}`      |
/// | SIGTERM / SIGINT | yes                     | `CleanExit{128+sig}` |
/// | SIGTERM / SIGINT | no                      | `OperatorSignalExit` |
/// | SIGKILL          | yes                     | `CleanExit{128+9}`   |
/// | SIGKILL          | no                      | `OomKilled`          |
/// | SIGSEGV/BUS/ABRT | n/a                     | `SignalCrash`        |
#[cfg(unix)]
pub fn classify_exit_status(status: ExitStatus, supervisor_sent_signal: bool) -> Outcome {
    if let Some(code) = status.code() {
        return classify_exit_code(code);
    }
    let signal = status.signal().unwrap_or(0);
    classify_signal(signal, supervisor_sent_signal)
}

/// Code-only classification (no signal context). Useful for
/// tests + the rare WTF-status case where neither `code()` nor
/// `signal()` populate (treated as `PanicAbort{-1}`).
pub fn classify_exit_code(code: i32) -> Outcome {
    match code {
        0 => Outcome::CleanExit {
            prev_run_exit_code: 0,
        },
        70 => Outcome::DeadlockDetected,
        n => Outcome::PanicAbort {
            prev_run_exit_code: n,
        },
    }
}

/// Signal-only classification with the load-bearing
/// `supervisor_sent_signal` discriminator.
pub fn classify_signal(signal: i32, supervisor_sent_signal: bool) -> Outcome {
    let prev_run_exit_code = 128_i32.saturating_add(signal);
    // POSIX signal numbers used here:
    //   2  SIGINT
    //   6  SIGABRT
    //   7  SIGBUS    (Linux)
    //   9  SIGKILL
    //   10 SIGBUS    (some BSDs; Linux uses 7)
    //   11 SIGSEGV
    //   15 SIGTERM
    match signal {
        15 | 2 => {
            if supervisor_sent_signal {
                Outcome::CleanExit { prev_run_exit_code }
            } else {
                Outcome::OperatorSignalExit {
                    prev_run_exit_code,
                    signal,
                }
            }
        }
        9 => {
            if supervisor_sent_signal {
                Outcome::CleanExit { prev_run_exit_code }
            } else {
                Outcome::OomKilled { prev_run_exit_code }
            }
        }
        // Crash signals — the supervisor never sends these, so
        // the `supervisor_sent_signal` flag is moot. Always
        // `SignalCrash`.
        6 | 7 | 10 | 11 => Outcome::SignalCrash {
            prev_run_exit_code,
            signal,
        },
        // Unknown signal — treat as `SignalCrash` so the
        // supervisor still restarts (better to over-restart on a
        // novel signal than miss an OOM the kernel renames at
        // some future date).
        other => Outcome::SignalCrash {
            prev_run_exit_code,
            signal: other,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_exit_is_not_restart_eligible() {
        let o = classify_exit_code(0);
        assert_eq!(
            o,
            Outcome::CleanExit {
                prev_run_exit_code: 0
            }
        );
        assert!(!o.restart_eligible());
        assert_eq!(o.reason_str(), "CleanExit");
        assert_eq!(o.prev_run_exit_code(), 0);
    }

    #[test]
    fn exit_70_is_deadlock_and_restart_eligible() {
        let o = classify_exit_code(70);
        assert_eq!(o, Outcome::DeadlockDetected);
        assert!(o.restart_eligible());
        assert_eq!(o.reason_str(), "DeadlockDetected");
        assert_eq!(o.prev_run_exit_code(), 70);
    }

    #[test]
    fn nonzero_exit_is_panic_abort_and_restart_eligible() {
        for code in [1, 2, 42, 137] {
            let o = classify_exit_code(code);
            assert_eq!(
                o,
                Outcome::PanicAbort {
                    prev_run_exit_code: code
                }
            );
            assert!(o.restart_eligible());
            assert_eq!(o.reason_str(), "PanicAbort");
            assert_eq!(o.prev_run_exit_code(), code);
        }
    }

    /// `INV-SUPERVISOR-SIGTERM-RESPECT-01` / `-SIGINT-RESPECT-01`:
    /// when the supervisor itself sent SIGTERM / SIGINT (operator
    /// intent), the child's signaled exit is classified as
    /// `CleanExit` and the supervisor MUST NOT restart.
    #[test]
    fn supervisor_initiated_sigterm_is_clean_exit_no_restart() {
        for sig in [15, 2] {
            let o = classify_signal(sig, true);
            match o {
                Outcome::CleanExit { prev_run_exit_code } => {
                    assert_eq!(prev_run_exit_code, 128 + sig);
                }
                other => panic!("expected CleanExit, got {other:?}"),
            }
            assert!(!classify_signal(sig, true).restart_eligible());
        }
    }

    /// `INV-SUPERVISOR-SIGTERM-RESPECT-01` / `-SIGINT-RESPECT-01`:
    /// SIGTERM / SIGINT NOT sent by the supervisor (operator-
    /// external `kill` / launchd `stop` / `ctrl+c` to a parent
    /// shell racing the supervisor) is classified as
    /// `OperatorSignalExit` and the supervisor MUST NOT restart.
    #[test]
    fn external_sigterm_is_operator_signal_exit_no_restart() {
        for sig in [15, 2] {
            let o = classify_signal(sig, false);
            match o {
                Outcome::OperatorSignalExit {
                    prev_run_exit_code,
                    signal,
                } => {
                    assert_eq!(prev_run_exit_code, 128 + sig);
                    assert_eq!(signal, sig);
                }
                other => panic!("expected OperatorSignalExit, got {other:?}"),
            }
            assert!(!o.restart_eligible());
        }
    }

    #[test]
    fn supervisor_initiated_sigkill_is_clean_exit() {
        let o = classify_signal(9, true);
        assert_eq!(
            o,
            Outcome::CleanExit {
                prev_run_exit_code: 137
            }
        );
        assert!(!o.restart_eligible());
    }

    #[test]
    fn external_sigkill_is_oom_killed_and_restart_eligible() {
        let o = classify_signal(9, false);
        assert_eq!(
            o,
            Outcome::OomKilled {
                prev_run_exit_code: 137
            }
        );
        assert!(o.restart_eligible());
        assert_eq!(o.reason_str(), "OomKilled");
    }

    #[test]
    fn crash_signals_are_signal_crash_regardless_of_intent() {
        for sig in [6, 7, 10, 11] {
            for supervisor_sent in [true, false] {
                let o = classify_signal(sig, supervisor_sent);
                match o {
                    Outcome::SignalCrash {
                        prev_run_exit_code,
                        signal,
                    } => {
                        assert_eq!(prev_run_exit_code, 128 + sig);
                        assert_eq!(signal, sig);
                    }
                    other => panic!("expected SignalCrash, got {other:?}"),
                }
                assert!(classify_signal(sig, supervisor_sent).restart_eligible());
            }
        }
    }
}

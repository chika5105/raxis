// raxis-supervisor::classify — exit-status → restart decision.
//
// Normative reference: `self-healing-supervisor.md §4.4` /
// `INV-SUPERVISOR-EXIT-CODE-CLASSIFICATION-01`.
//
// The classifier is a pure function of `(exit_status,
// intentional_shutdown)`. It does NOT consult the wallclock /
// circuit breaker — those are higher-layer decisions. The only
// thing this module decides is "what kind of exit was that?".
//
// Per `INV-SUPERVISOR-SIGTERM-RESPECT-01` /
// `INV-SUPERVISOR-SIGINT-RESPECT-01`, every exit observed after
// the supervisor's intentional-shutdown flag is set is operator
// intent. That includes a kernel that exits 70, panics, or
// segfaults during shutdown cleanup. Auto-restart never overrides
// operator intent.
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
/// whether the supervisor itself initiated shutdown (the
/// `intentional_shutdown` flag — see `signal.rs`).
///
/// **Decision table** (mirror of
/// `self-healing-supervisor.md §4.4`):
///
/// | child exit       | intentional shutdown? | outcome              |
/// |------------------|-----------------------|----------------------|
/// | anything         | yes                   | `CleanExit{status}`  |
/// | WEXITSTATUS = 0  | no                    | `CleanExit{0}`       |
/// | WEXITSTATUS = 70 | no                    | `DeadlockDetected`   |
/// | WEXITSTATUS = N  | no (N != 0, 70)       | `PanicAbort{N}`      |
/// | SIGTERM / SIGINT | no                    | `OperatorSignalExit` |
/// | SIGKILL          | no                    | `OomKilled`          |
/// | SIGSEGV/BUS/ABRT | no                    | `SignalCrash`        |
#[cfg(unix)]
pub fn classify_exit_status(status: ExitStatus, intentional_shutdown: bool) -> Outcome {
    if intentional_shutdown {
        return Outcome::CleanExit {
            prev_run_exit_code: status_to_shell_code(status),
        };
    }
    if let Some(code) = status.code() {
        return classify_exit_code(code);
    }
    let signal = status.signal().unwrap_or(0);
    classify_signal(signal, false)
}

#[cfg(unix)]
fn status_to_shell_code(status: ExitStatus) -> i32 {
    if let Some(code) = status.code() {
        return code;
    }
    128_i32.saturating_add(status.signal().unwrap_or(0))
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
        6 | 7 | 10 | 11 => {
            if supervisor_sent_signal {
                Outcome::CleanExit { prev_run_exit_code }
            } else {
                Outcome::SignalCrash {
                    prev_run_exit_code,
                    signal,
                }
            }
        }
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
    fn crash_signals_restart_without_shutdown_intent() {
        for sig in [6, 7, 10, 11] {
            let o = classify_signal(sig, false);
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
            assert!(o.restart_eligible());
        }
    }

    #[test]
    fn shutdown_intent_overrides_crash_signal_classification() {
        for sig in [6, 7, 10, 11] {
            let o = classify_signal(sig, true);
            assert_eq!(
                o,
                Outcome::CleanExit {
                    prev_run_exit_code: 128 + sig
                }
            );
            assert!(!o.restart_eligible());
        }
    }

    #[cfg(unix)]
    #[test]
    fn shutdown_intent_overrides_exit_code_classification() {
        use std::os::unix::process::ExitStatusExt;

        let deadlock_status = std::process::ExitStatus::from_raw(70 << 8);
        assert_eq!(
            classify_exit_status(deadlock_status, true),
            Outcome::CleanExit {
                prev_run_exit_code: 70
            }
        );

        let panic_status = std::process::ExitStatus::from_raw(101 << 8);
        assert_eq!(
            classify_exit_status(panic_status, true),
            Outcome::CleanExit {
                prev_run_exit_code: 101
            }
        );

        let sigsegv_status = std::process::ExitStatus::from_raw(11);
        assert_eq!(
            classify_exit_status(sigsegv_status, true),
            Outcome::CleanExit {
                prev_run_exit_code: 139
            }
        );
    }
}

// raxis-supervisor::supervisor — spawn / wait / classify / decide
// loop.
//
// Normative reference: `self-healing-supervisor.md §4.2 + §4.5 +
// §4.6`.
//
// **Loop shape** (single-line summary, full pseudocode in the
// design doc):
//
//   loop {
//     write_sentinel(Healthy);
//     spawn child;
//     wait for child OR shutdown_notify;
//     if shutdown_notify fired:
//       set intentional_shutdown
//       send SIGTERM to child
//       wait up to RAXIS_SUPERVISOR_SHUTDOWN_GRACE_SECS
//       if still alive: send SIGKILL
//       wait remaining
//       write_sentinel(Halted{OperatorStop|OperatorStopForced});
//       break;
//     classify exit;
//     if !restart_eligible:
//       write_sentinel(Halted{OperatorStop});
//       break;
//     record_attempt(now, reason);
//     if breaker tripped:
//       write_sentinel(Halted{CircuitOpen});
//       break;
//     write_sentinel(Restarting{...});
//     // back-off (~250ms) so we don't burn-loop on a fast crash
//     sleep 250ms;
//   }
//
// The critical contract (per the operator-signal addendum): when
// the shutdown_notify fires, the supervisor's `intentional_shutdown`
// flag is set BEFORE the SIGTERM is forwarded. That way, when
// the kernel's signaled exit reaches `classify_exit_status`, the
// classifier sees `intentional_shutdown=true` and returns
// `Outcome::CleanExit{...}` (NO restart), instead of
// `Outcome::OperatorSignalExit{...}`. Both end up in the no-
// restart bucket; the distinction is recorded for forensics.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use serde_json::json;

use crate::circuit_breaker::{CircuitBreaker, RecordOutcome};
use crate::classify::{Outcome, classify_exit_status};
use crate::log::SupervisorLog;
use crate::sentinel::{write_sentinel, Sentinel};
use crate::signal::IntentionalShutdownFlag;
use crate::{
    DEFAULT_MAX_ATTEMPTS, DEFAULT_RESTART_WINDOW_SECS, DEFAULT_SHUTDOWN_GRACE_SECS,
};

/// Where to find the kernel binary + the supervisor's data dir +
/// per-restart back-off knobs. Built from environment + CLI in
/// `main.rs`; tests construct it directly.
#[derive(Debug, Clone)]
pub struct SupervisorConfig {
    pub data_dir:               PathBuf,
    pub kernel_binary:          PathBuf,
    pub kernel_args:            Vec<String>,
    /// Inherits process env into the child kernel by default.
    /// Tests override per-spawn.
    pub kernel_env:             Vec<(String, String)>,
    pub max_attempts:           u32,
    pub window_secs:            u32,
    pub shutdown_grace_secs:    u64,
    /// Inter-restart back-off (default 250ms — short enough that
    /// a transient deadlock recovers within ~3s of detection,
    /// long enough that we don't burn-loop on a fast crash and
    /// rip through the breaker in milliseconds).
    pub restart_backoff_ms:     u64,
    /// Stop the supervisor after this many child runs. `None` =
    /// unbounded (production). Tests use a small value to bound
    /// the loop.
    pub max_child_runs:         Option<u32>,
}

impl SupervisorConfig {
    pub fn with_defaults(
        data_dir:      PathBuf,
        kernel_binary: PathBuf,
    ) -> Self {
        Self {
            data_dir,
            kernel_binary,
            kernel_args:         Vec::new(),
            kernel_env:          Vec::new(),
            max_attempts:        DEFAULT_MAX_ATTEMPTS,
            window_secs:         DEFAULT_RESTART_WINDOW_SECS,
            shutdown_grace_secs: DEFAULT_SHUTDOWN_GRACE_SECS,
            restart_backoff_ms:  250,
            max_child_runs:      None,
        }
    }
}

/// Outcome of a single supervisor run. Tests assert on this;
/// production reads it for the final stderr log line.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SupervisorRunReport {
    pub child_runs_observed: u32,
    pub final_outcome:       FinalOutcome,
    pub last_exit_code:      i32,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum FinalOutcome {
    /// Kernel exited cleanly on its own (clean WEXITSTATUS = 0)
    /// or operator stopped it via SIGTERM / SIGINT / SIGHUP.
    OperatorStop,
    /// Operator forced a stop with `raxis-supervisor stop --force`
    /// (SIGKILL after the supervisor's own intent was set).
    OperatorStopForced,
    /// Circuit breaker refused further restarts. Manual reset
    /// required.
    CircuitOpen { attempts_in_window: u32, window_secs: u32 },
    /// Test-only: `max_child_runs` reached. Production never
    /// hits this branch.
    MaxRunsReached,
}

fn unix_now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Run the supervisor's spawn-wait-classify-decide loop until
/// either the operator stops the kernel or the circuit breaker
/// trips. Returns a [`SupervisorRunReport`] for observability.
///
/// **Async**. The loop runs on whatever tokio runtime the caller
/// provides. The signal-handler installer (`signal::install_handlers`)
/// is the one piece that requires `cfg(unix)` + tokio; the rest
/// of the loop is portable.
#[cfg(unix)]
pub async fn run_supervisor_loop(
    cfg:           SupervisorConfig,
    intent_flag:   IntentionalShutdownFlag,
    shutdown_rx:   Arc<tokio::sync::Notify>,
    log:           Arc<SupervisorLog>,
) -> std::io::Result<SupervisorRunReport> {
    use tokio::process::Command;
    let supervisor_pid = std::process::id();
    let mut breaker = CircuitBreaker::load_or_default(
        &cfg.data_dir,
        cfg.max_attempts,
        cfg.window_secs,
    );
    if breaker.is_tripped() {
        // Cold-start with an open breaker: refuse to spawn and
        // re-write the sentinel so the dashboard reflects the
        // halted state immediately.
        let s = Sentinel {
            schema_version:      1,
            status:              "Halted".to_owned(),
            sub_state:           Some("CircuitOpen".to_owned()),
            attempt_n:           breaker.state().recent_restart_unix_ts.len() as u32,
            max_attempts:        cfg.max_attempts,
            last_restart_unix_ts: breaker
                .state()
                .recent_restart_unix_ts
                .last()
                .copied()
                .unwrap_or(0),
            last_restart_reason: breaker.state().last_failure_reason.clone(),
            prev_run_exit_code:  None,
            attempts_in_window:  breaker
                .state()
                .attempts_in_window(unix_now_secs(), cfg.window_secs),
            window_secs:         cfg.window_secs,
            supervisor_pid,
            kernel_pid:          0,
            updated_at_unix_secs: unix_now_secs(),
        };
        let _ = write_sentinel(&cfg.data_dir, &s);
        log.emit(
            "error",
            "circuit_breaker_open_on_cold_start",
            &json!({ "attempts_in_window": s.attempts_in_window, "window_secs": s.window_secs }),
        );
        return Ok(SupervisorRunReport {
            child_runs_observed: 0,
            final_outcome:       FinalOutcome::CircuitOpen {
                attempts_in_window: s.attempts_in_window,
                window_secs:        cfg.window_secs,
            },
            last_exit_code:      0,
        });
    }

    let mut child_runs_observed: u32 = 0;
    let mut last_exit_code: i32 = 0;
    loop {
        if let Some(cap) = cfg.max_child_runs {
            if child_runs_observed >= cap {
                return Ok(SupervisorRunReport {
                    child_runs_observed,
                    final_outcome: FinalOutcome::MaxRunsReached,
                    last_exit_code,
                });
            }
        }

        // Spawn the kernel.
        let mut command = Command::new(&cfg.kernel_binary);
        command.args(&cfg.kernel_args);
        for (k, v) in &cfg.kernel_env {
            command.env(k, v);
        }
        let mut child = match command.spawn() {
            Ok(c) => c,
            Err(e) => {
                log.emit(
                    "error",
                    "kernel_spawn_failed",
                    &json!({
                        "binary": cfg.kernel_binary.display().to_string(),
                        "reason": e.to_string(),
                    }),
                );
                return Err(e);
            }
        };
        let kernel_pid = child.id().unwrap_or(0);
        child_runs_observed = child_runs_observed.saturating_add(1);

        let now = unix_now_secs();
        let healthy = Sentinel {
            schema_version:      1,
            status:              "Healthy".to_owned(),
            sub_state:           None,
            attempt_n:           breaker
                .state()
                .attempts_in_window(now, cfg.window_secs),
            max_attempts:        cfg.max_attempts,
            last_restart_unix_ts: breaker
                .state()
                .recent_restart_unix_ts
                .last()
                .copied()
                .unwrap_or(0),
            last_restart_reason: breaker.state().last_failure_reason.clone(),
            prev_run_exit_code:  Some(last_exit_code),
            attempts_in_window:  breaker
                .state()
                .attempts_in_window(now, cfg.window_secs),
            window_secs:         cfg.window_secs,
            supervisor_pid,
            kernel_pid,
            updated_at_unix_secs: now,
        };
        let _ = write_sentinel(&cfg.data_dir, &healthy);
        log.emit(
            "info",
            "kernel_spawned",
            &json!({ "kernel_pid": kernel_pid, "child_run": child_runs_observed }),
        );

        // Wait for the child OR the shutdown signal.
        let waited_outcome: WaitedOutcome = tokio::select! {
            biased;
            _ = shutdown_rx.notified() => {
                log.emit(
                    "info",
                    "shutdown_signal_observed",
                    &json!({ "kernel_pid": kernel_pid }),
                );
                forward_signal_and_wait(
                    &mut child,
                    &intent_flag,
                    cfg.shutdown_grace_secs,
                    log.as_ref(),
                ).await
            }
            res = child.wait() => match res {
                Ok(status) => WaitedOutcome::Exited(status),
                Err(e) => WaitedOutcome::WaitErr(e),
            },
        };

        let (status_for_classify, force_used) = match waited_outcome {
            WaitedOutcome::Exited(s) => (Some(s), false),
            WaitedOutcome::ForwardedSignalThenExited { status, force_used } =>
                (Some(status), force_used),
            WaitedOutcome::WaitErr(e) => {
                log.emit(
                    "error",
                    "kernel_wait_failed",
                    &json!({ "reason": e.to_string() }),
                );
                return Err(e);
            }
        };
        let supervisor_sent = intent_flag.take();
        let outcome = match status_for_classify {
            Some(s) => classify_exit_status(s, supervisor_sent),
            None => Outcome::CleanExit { prev_run_exit_code: 0 },
        };
        last_exit_code = outcome.prev_run_exit_code();
        log.emit(
            "info",
            "kernel_exit_classified",
            &json!({
                "kernel_pid": kernel_pid,
                "outcome": outcome.reason_str(),
                "prev_run_exit_code": last_exit_code,
                "supervisor_sent_signal": supervisor_sent,
            }),
        );

        if !outcome.restart_eligible() {
            // Operator intent OR clean exit. Halt.
            let now = unix_now_secs();
            let sub_state = if force_used {
                Some("OperatorStopForced".to_owned())
            } else {
                Some("OperatorStop".to_owned())
            };
            let s = Sentinel {
                schema_version:      1,
                status:              "Halted".to_owned(),
                sub_state:           sub_state.clone(),
                attempt_n:           breaker
                    .state()
                    .attempts_in_window(now, cfg.window_secs),
                max_attempts:        cfg.max_attempts,
                last_restart_unix_ts: breaker
                    .state()
                    .recent_restart_unix_ts
                    .last()
                    .copied()
                    .unwrap_or(0),
                last_restart_reason: Some(outcome.reason_str().to_owned()),
                prev_run_exit_code:  Some(last_exit_code),
                attempts_in_window:  breaker
                    .state()
                    .attempts_in_window(now, cfg.window_secs),
                window_secs:         cfg.window_secs,
                supervisor_pid,
                kernel_pid:          0,
                updated_at_unix_secs: now,
            };
            let _ = write_sentinel(&cfg.data_dir, &s);
            log.emit(
                "info",
                "supervisor_halting",
                &json!({ "outcome": outcome.reason_str(), "sub_state": sub_state }),
            );
            return Ok(SupervisorRunReport {
                child_runs_observed,
                final_outcome: if force_used {
                    FinalOutcome::OperatorStopForced
                } else {
                    FinalOutcome::OperatorStop
                },
                last_exit_code,
            });
        }

        // Restart-eligible — record + check breaker.
        let now = unix_now_secs();
        let record = breaker.record_attempt(now, outcome.reason_str());
        if let Err(e) = breaker.save() {
            log.emit(
                "warn",
                "breaker_save_failed",
                &json!({ "reason": e.to_string() }),
            );
        }
        match record {
            RecordOutcome::Tripped {
                attempts_in_window,
                window_secs,
            } => {
                let now = unix_now_secs();
                let s = Sentinel {
                    schema_version:      1,
                    status:              "Halted".to_owned(),
                    sub_state:           Some("CircuitOpen".to_owned()),
                    attempt_n:           attempts_in_window,
                    max_attempts:        cfg.max_attempts,
                    last_restart_unix_ts: now,
                    last_restart_reason: Some(outcome.reason_str().to_owned()),
                    prev_run_exit_code:  Some(last_exit_code),
                    attempts_in_window,
                    window_secs,
                    supervisor_pid,
                    kernel_pid:          0,
                    updated_at_unix_secs: now,
                };
                let _ = write_sentinel(&cfg.data_dir, &s);
                log.emit(
                    "error",
                    "circuit_breaker_tripped",
                    &json!({
                        "attempts_in_window": attempts_in_window,
                        "window_secs": window_secs,
                        "last_failure_reason": outcome.reason_str(),
                    }),
                );
                return Ok(SupervisorRunReport {
                    child_runs_observed,
                    final_outcome: FinalOutcome::CircuitOpen {
                        attempts_in_window,
                        window_secs,
                    },
                    last_exit_code,
                });
            }
            RecordOutcome::Allowed {
                attempts_in_window,
                max_attempts,
            } => {
                let now = unix_now_secs();
                let s = Sentinel {
                    schema_version:      1,
                    status:              "Restarting".to_owned(),
                    sub_state:           None,
                    attempt_n:           attempts_in_window,
                    max_attempts,
                    last_restart_unix_ts: now,
                    last_restart_reason: Some(outcome.reason_str().to_owned()),
                    prev_run_exit_code:  Some(last_exit_code),
                    attempts_in_window,
                    window_secs:         cfg.window_secs,
                    supervisor_pid,
                    kernel_pid:          0,
                    updated_at_unix_secs: now,
                };
                let _ = write_sentinel(&cfg.data_dir, &s);
                log.emit(
                    "info",
                    "kernel_restart_scheduled",
                    &json!({
                        "attempts_in_window": attempts_in_window,
                        "max_attempts": max_attempts,
                        "reason": outcome.reason_str(),
                    }),
                );
                tokio::time::sleep(Duration::from_millis(cfg.restart_backoff_ms))
                    .await;
            }
        }
    }
}

#[derive(Debug)]
enum WaitedOutcome {
    Exited(std::process::ExitStatus),
    ForwardedSignalThenExited {
        status:     std::process::ExitStatus,
        force_used: bool,
    },
    WaitErr(std::io::Error),
}

#[cfg(unix)]
async fn forward_signal_and_wait(
    child:               &mut tokio::process::Child,
    intent_flag:         &IntentionalShutdownFlag,
    shutdown_grace_secs: u64,
    log:                 &SupervisorLog,
) -> WaitedOutcome {
    use nix::sys::signal::Signal;
    intent_flag.set();
    let pid = match child.id() {
        Some(p) => p,
        None => {
            // Already exited — wait will collect the status.
            match child.wait().await {
                Ok(s) => return WaitedOutcome::Exited(s),
                Err(e) => return WaitedOutcome::WaitErr(e),
            }
        }
    };
    if let Err(e) = crate::signal::send_signal(pid, Signal::SIGTERM) {
        log.emit(
            "warn",
            "kernel_sigterm_failed",
            &serde_json::json!({ "kernel_pid": pid, "reason": e.to_string() }),
        );
    } else {
        log.emit(
            "info",
            "kernel_sigterm_sent",
            &serde_json::json!({ "kernel_pid": pid }),
        );
    }
    let grace = Duration::from_secs(shutdown_grace_secs);
    match tokio::time::timeout(grace, child.wait()).await {
        Ok(Ok(status)) => WaitedOutcome::ForwardedSignalThenExited {
            status,
            force_used: false,
        },
        Ok(Err(e)) => WaitedOutcome::WaitErr(e),
        Err(_) => {
            // Grace period elapsed — escalate to SIGKILL per
            // `INV-SUPERVISOR-SHUTDOWN-GRACE-01`.
            log.emit(
                "warn",
                "kernel_grace_period_exceeded_escalating_sigkill",
                &serde_json::json!({
                    "kernel_pid": pid,
                    "shutdown_grace_secs": shutdown_grace_secs,
                }),
            );
            if let Err(e) = crate::signal::send_signal(pid, Signal::SIGKILL) {
                log.emit(
                    "error",
                    "kernel_sigkill_failed",
                    &serde_json::json!({ "kernel_pid": pid, "reason": e.to_string() }),
                );
            }
            match child.wait().await {
                Ok(status) => WaitedOutcome::ForwardedSignalThenExited {
                    status,
                    force_used: true,
                },
                Err(e) => WaitedOutcome::WaitErr(e),
            }
        }
    }
}

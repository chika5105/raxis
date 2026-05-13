// raxis-supervisor::circuit_breaker — sliding-window restart
// limiter.
//
// Normative reference: `self-healing-supervisor.md §4.3` /
// `INV-SUPERVISOR-CIRCUIT-BREAKER-01`.
//
// **Contract.** At most `max_attempts` restart attempts in a
// rolling `window_secs` second window. The window is *trailing*:
// `attempts_in_window` is the count of restart timestamps within
// the last `window_secs` seconds at the moment of the next
// `record_attempt` call. When the count would exceed
// `max_attempts`, the breaker trips and the supervisor must NOT
// spawn another kernel until the operator runs `raxis-supervisor
// reset-circuit-breaker`.
//
// **Persistence.** State is JSON-serialised to
// `<data_dir>/supervisor_state.json` so crashes / reboots of the
// supervisor itself don't leak the breaker state. Atomic write
// via tempfile + rename.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::{DEFAULT_MAX_ATTEMPTS, DEFAULT_RESTART_WINDOW_SECS};

/// Breaker filename per `self-healing-supervisor.md §4.3`.
pub const STATE_FILENAME: &str = "supervisor_state.json";

/// On-disk persisted breaker state.
///
/// **Forward compat**: every field is `serde(default)` so a
/// future supervisor revision can extend the schema without
/// breaking older binaries reading a file written by a newer
/// one.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CircuitBreakerState {
    /// Schema version of the on-disk file. Currently always `1`.
    /// A future migration would bump this and gate parsing on
    /// the value.
    #[serde(default = "default_schema_version")]
    pub schema_version: u32,
    /// Rolling window of restart timestamps (unix-seconds).
    /// Old entries (older than `window_secs`) are pruned on
    /// every `record_attempt` call.
    #[serde(default)]
    pub recent_restart_unix_ts: Vec<i64>,
    /// `true` once the breaker has tripped. Cleared by
    /// `reset()` (which the operator invokes via
    /// `raxis-supervisor reset-circuit-breaker`).
    #[serde(default)]
    pub tripped: bool,
    /// PascalCase reason for the most-recent failure that
    /// tripped the breaker. Surfaced into the
    /// `KernelRestartHaltedCircuitOpen.last_failure_reason`
    /// field.
    #[serde(default)]
    pub last_failure_reason: Option<String>,
}

fn default_schema_version() -> u32 {
    1
}

impl CircuitBreakerState {
    /// `attempts_in_window` at the supplied wallclock — used by
    /// the sentinel writer + audit emitter to record the
    /// breaker context without having to re-prune.
    pub fn attempts_in_window(&self, now_unix_secs: i64, window_secs: u32) -> u32 {
        let lo = now_unix_secs.saturating_sub(i64::from(window_secs));
        self.recent_restart_unix_ts
            .iter()
            .filter(|&&t| t >= lo)
            .count() as u32
    }
}

/// Sliding-window restart limiter.
///
/// Owns the in-memory + on-disk state. Construct via
/// [`CircuitBreaker::load_or_default`], drive via
/// [`CircuitBreaker::record_attempt`] before each
/// `Outcome::*`-restart-eligible respawn, and persist
/// interactively via [`CircuitBreaker::save`].
#[derive(Debug, Clone)]
pub struct CircuitBreaker {
    state:        CircuitBreakerState,
    max_attempts: u32,
    window_secs:  u32,
    state_path:   PathBuf,
}

impl CircuitBreaker {
    /// Load existing state (if any) from
    /// `<data_dir>/supervisor_state.json`, falling back to a
    /// fresh default. Schema-mismatch + corrupt-file paths log
    /// to stderr and reset to default — better to over-restart
    /// than refuse to boot a kernel because of a stale meta
    /// file.
    pub fn load_or_default(
        data_dir:     &Path,
        max_attempts: u32,
        window_secs:  u32,
    ) -> Self {
        let state_path = data_dir.join(STATE_FILENAME);
        let state = match std::fs::read(&state_path) {
            Ok(bytes) => match serde_json::from_slice::<CircuitBreakerState>(&bytes) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!(
                        "{{\"level\":\"warn\",\"event\":\"supervisor_state_parse_failed\",\
                         \"reason\":\"{e}\"}}"
                    );
                    CircuitBreakerState::default()
                }
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                CircuitBreakerState::default()
            }
            Err(e) => {
                eprintln!(
                    "{{\"level\":\"warn\",\"event\":\"supervisor_state_read_failed\",\
                     \"reason\":\"{e}\"}}"
                );
                CircuitBreakerState::default()
            }
        };
        Self {
            state,
            max_attempts,
            window_secs,
            state_path,
        }
    }

    /// Construct a breaker pinned to the workspace defaults
    /// (`DEFAULT_MAX_ATTEMPTS` / `DEFAULT_RESTART_WINDOW_SECS`).
    pub fn load_with_defaults(data_dir: &Path) -> Self {
        Self::load_or_default(
            data_dir,
            DEFAULT_MAX_ATTEMPTS,
            DEFAULT_RESTART_WINDOW_SECS,
        )
    }

    pub fn state(&self) -> &CircuitBreakerState {
        &self.state
    }

    pub fn max_attempts(&self) -> u32 {
        self.max_attempts
    }

    pub fn window_secs(&self) -> u32 {
        self.window_secs
    }

    pub fn state_path(&self) -> &Path {
        &self.state_path
    }

    /// `true` iff the breaker has tripped and the supervisor
    /// must refuse to spawn another kernel until reset.
    pub fn is_tripped(&self) -> bool {
        self.state.tripped
    }

    /// Outcome returned by [`CircuitBreaker::record_attempt`].
    pub fn record_attempt(
        &mut self,
        now_unix_secs:    i64,
        failure_reason:   &str,
    ) -> RecordOutcome {
        // Prune stale entries first so the count we check
        // against `max_attempts` reflects the trailing window.
        let lo = now_unix_secs.saturating_sub(i64::from(self.window_secs));
        self.state.recent_restart_unix_ts.retain(|&t| t >= lo);
        self.state.recent_restart_unix_ts.push(now_unix_secs);
        self.state.last_failure_reason = Some(failure_reason.to_owned());
        let attempts_in_window = self.state.recent_restart_unix_ts.len() as u32;
        if attempts_in_window > self.max_attempts {
            self.state.tripped = true;
            RecordOutcome::Tripped {
                attempts_in_window,
                window_secs: self.window_secs,
            }
        } else {
            RecordOutcome::Allowed {
                attempts_in_window,
                max_attempts: self.max_attempts,
            }
        }
    }

    /// Operator-initiated reset (`raxis-supervisor reset-circuit-breaker`).
    /// Clears the breaker and the rolling timestamp list.
    pub fn reset(&mut self) {
        self.state = CircuitBreakerState {
            schema_version: 1,
            ..CircuitBreakerState::default()
        };
    }

    /// Atomic-write the in-memory state to disk.
    pub fn save(&self) -> std::io::Result<()> {
        if let Some(parent) = self.state_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let bytes = serde_json::to_vec_pretty(&self.state).map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("supervisor state serialization failed: {e}"),
            )
        })?;
        let tmp = self.state_path.with_extension("json.tmp");
        std::fs::write(&tmp, &bytes)?;
        std::fs::rename(&tmp, &self.state_path)?;
        Ok(())
    }
}

/// Outcome of a [`CircuitBreaker::record_attempt`] call.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum RecordOutcome {
    /// Supervisor may proceed with the restart.
    Allowed {
        attempts_in_window: u32,
        max_attempts:       u32,
    },
    /// Supervisor MUST NOT restart further. Sentinel + stderr
    /// log + `KernelRestartHaltedCircuitOpen` audit emit on the
    /// next successful boot all carry these counters.
    Tripped {
        attempts_in_window: u32,
        window_secs:        u32,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn empty_breaker_allows_first_attempts_and_trips_on_overflow() {
        let dir = tempdir().unwrap();
        let mut cb = CircuitBreaker::load_or_default(dir.path(), 3, 60);
        assert!(!cb.is_tripped());
        // Three attempts within the window: allowed.
        for n in 1..=3 {
            let out = cb.record_attempt(1_000, "DeadlockDetected");
            match out {
                RecordOutcome::Allowed {
                    attempts_in_window,
                    max_attempts,
                } => {
                    assert_eq!(attempts_in_window, n);
                    assert_eq!(max_attempts, 3);
                }
                other => panic!("expected Allowed, got {other:?}"),
            }
        }
        // Fourth attempt: trips.
        let out = cb.record_attempt(1_001, "DeadlockDetected");
        match out {
            RecordOutcome::Tripped {
                attempts_in_window,
                window_secs,
            } => {
                assert_eq!(attempts_in_window, 4);
                assert_eq!(window_secs, 60);
            }
            other => panic!("expected Tripped, got {other:?}"),
        }
        assert!(cb.is_tripped());
        assert_eq!(
            cb.state().last_failure_reason.as_deref(),
            Some("DeadlockDetected"),
        );
    }

    #[test]
    fn out_of_window_attempts_are_pruned() {
        let dir = tempdir().unwrap();
        let mut cb = CircuitBreaker::load_or_default(dir.path(), 3, 60);
        // Three old attempts at t=0..2 (well outside the 60s
        // window from t=1000).
        cb.record_attempt(0, "DeadlockDetected");
        cb.record_attempt(1, "DeadlockDetected");
        cb.record_attempt(2, "DeadlockDetected");
        // First attempt at t=1000: prune wipes the three old
        // entries and we're back at attempts_in_window=1.
        let out = cb.record_attempt(1_000, "PanicAbort");
        assert_eq!(
            out,
            RecordOutcome::Allowed {
                attempts_in_window: 1,
                max_attempts:       3,
            },
        );
    }

    #[test]
    fn save_then_load_round_trips_breaker_state() {
        let dir = tempdir().unwrap();
        let mut cb = CircuitBreaker::load_or_default(dir.path(), 3, 60);
        for _ in 0..4 {
            cb.record_attempt(1_000, "DeadlockDetected");
        }
        assert!(cb.is_tripped());
        cb.save().expect("save");
        let cb2 = CircuitBreaker::load_or_default(dir.path(), 3, 60);
        assert!(cb2.is_tripped());
        assert_eq!(cb2.state().recent_restart_unix_ts.len(), 4);
        assert_eq!(
            cb2.state().last_failure_reason.as_deref(),
            Some("DeadlockDetected"),
        );
    }

    #[test]
    fn reset_clears_breaker_and_history() {
        let dir = tempdir().unwrap();
        let mut cb = CircuitBreaker::load_or_default(dir.path(), 3, 60);
        for _ in 0..4 {
            cb.record_attempt(1_000, "DeadlockDetected");
        }
        assert!(cb.is_tripped());
        cb.reset();
        assert!(!cb.is_tripped());
        assert!(cb.state().recent_restart_unix_ts.is_empty());
        assert!(cb.state().last_failure_reason.is_none());
    }

    #[test]
    fn corrupted_state_file_falls_back_to_default_without_panic() {
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join(STATE_FILENAME), b"{ this is not json ")
            .unwrap();
        let cb = CircuitBreaker::load_or_default(dir.path(), 3, 60);
        assert!(!cb.is_tripped());
        assert!(cb.state().recent_restart_unix_ts.is_empty());
    }
}

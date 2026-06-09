// raxis-supervisor — small external wrapper around `raxis-kernel`
// that classifies kernel exits and decides whether to restart.
//
// Normative reference: `specs/v2/self-healing-supervisor.md §4`.
//
// **Module map** (target ≤ 500 LOC of supervisor logic excluding
// tests, per the design doc's complexity budget):
//
//   * `classify`       — exit-code → `Outcome` classifier per
//                        `INV-SUPERVISOR-EXIT-CODE-CLASSIFICATION-01`.
//   * `circuit_breaker`— sliding-window restart limiter per
//                        `INV-SUPERVISOR-CIRCUIT-BREAKER-01`. Owns
//                        `<data_dir>/supervisor_state.json`.
//   * `sentinel`       — atomic-write wrapper for
//                        `<data_dir>/kernel_lifecycle_status.json`.
//   * `signal`         — UNIX SIGTERM / SIGINT handlers + the
//                        `intentional_shutdown` AtomicBool.
//   * `child`          — `tokio::process::Command` spawn / wait /
//                        signal-forward loop.
//   * `log`            — JSON-line stderr logger
//                        (`<data_dir>/supervisor.stderr.log`).
//
// The crate has NO dependency on `raxis-kernel` directly — the
// supervisor is process-isolated from the kernel by construction.
// The kernel writes the audit chain; the supervisor writes the
// sentinel. The two communicate via the on-disk sentinel file +
// the kernel's exit code, never via in-process IPC.

#![forbid(unsafe_code)]
#![deny(missing_debug_implementations)]

pub mod circuit_breaker;
pub mod classify;
pub mod fd_limit;
pub mod log;
pub mod sentinel;
pub mod signal;
pub mod supervisor;

pub use circuit_breaker::{CircuitBreaker, CircuitBreakerState};
pub use classify::{classify_exit_status, Outcome};
pub use fd_limit::{raise_nofile_soft_limit, NofileRaiseOutcome};
pub use sentinel::{Sentinel, SentinelStatus, SentinelSubState};
pub use supervisor::{SupervisorConfig, SupervisorRunReport};

/// Default sliding-window width used by `CircuitBreaker` and
/// surfaced as the `window_secs` field of every restart event.
pub const DEFAULT_RESTART_WINDOW_SECS: u32 = 60;

/// Default max restart attempts inside the sliding window before
/// the supervisor refuses further restarts and writes
/// `Halted (CircuitOpen)` to the sentinel file.
pub const DEFAULT_MAX_ATTEMPTS: u32 = 3;

/// Default grace period the supervisor waits between forwarding a
/// SIGTERM / SIGINT to the kernel and escalating to SIGKILL.
/// Configurable per `INV-SUPERVISOR-SHUTDOWN-GRACE-01` via the
/// `RAXIS_SUPERVISOR_SHUTDOWN_GRACE_SECS` env var.
pub const DEFAULT_SHUTDOWN_GRACE_SECS: u64 = 30;

/// Env var operator opt-in for auto-restart per
/// `INV-SUPERVISOR-OPT-IN-01`. When unset (the default) the
/// supervisor spawns the kernel exactly once and exits with the
/// kernel's exit code — bit-identical to running the kernel
/// directly. When set to `1` the supervisor enters the spawn-
/// wait-classify-decide loop.
pub const ENV_OPT_IN: &str = "RAXIS_SUPERVISOR_AUTO_RESTART";

/// Env var operator override for the shutdown grace period.
pub const ENV_SHUTDOWN_GRACE_SECS: &str = "RAXIS_SUPERVISOR_SHUTDOWN_GRACE_SECS";

/// Env var operator override for the kernel binary path
/// (defaults to a sibling `raxis-kernel` next to the supervisor
/// binary).
pub const ENV_KERNEL_BINARY: &str = "RAXIS_SUPERVISOR_KERNEL_BINARY";

/// Env var used by packaged service managers. When set to `1`, the
/// supervisor waits for `policy/policy.toml` and `kernel.db` before
/// spawning the kernel. This keeps `brew services start raxis` from
/// turning a pre-genesis data dir into a crash loop.
pub const ENV_REQUIRE_INITIALIZED_DATA_DIR: &str = "RAXIS_SUPERVISOR_REQUIRE_INITIALIZED_DATA_DIR";

/// Env var operator override for the supervisor's pre-kernel
/// `RLIMIT_NOFILE` soft-limit raise. Defaults to the kernel's
/// documented packaged-service floor.
pub const ENV_MIN_NOFILE: &str = "RAXIS_SUPERVISOR_MIN_NOFILE";

pub const DEFAULT_MIN_NOFILE: u64 = 4096;

/// Env var operator override for the dashboard readiness URL the
/// supervisor probes while the kernel is alive.
pub const ENV_READINESS_URL: &str = "RAXIS_SUPERVISOR_READINESS_URL";

/// Env var override for the initial boot grace before readiness
/// checks begin.
pub const ENV_READINESS_INITIAL_GRACE_SECS: &str = "RAXIS_SUPERVISOR_READINESS_INITIAL_GRACE_SECS";

/// Env var override for readiness probe interval.
pub const ENV_READINESS_INTERVAL_SECS: &str = "RAXIS_SUPERVISOR_READINESS_INTERVAL_SECS";

/// Env var override for per-probe readiness timeout.
pub const ENV_READINESS_TIMEOUT_MS: &str = "RAXIS_SUPERVISOR_READINESS_TIMEOUT_MS";

/// Env var override for consecutive readiness failures before a
/// supervised restart.
pub const ENV_READINESS_FAILURES_BEFORE_RESTART: &str =
    "RAXIS_SUPERVISOR_READINESS_FAILURES_BEFORE_RESTART";

pub const DEFAULT_READINESS_URL: &str = "http://127.0.0.1:9820/api/health";
pub const DEFAULT_READINESS_INITIAL_GRACE_SECS: u64 = 20;
pub const DEFAULT_READINESS_INTERVAL_SECS: u64 = 5;
pub const DEFAULT_READINESS_TIMEOUT_MS: u64 = 1_500;
pub const DEFAULT_READINESS_FAILURES_BEFORE_RESTART: u32 = 3;

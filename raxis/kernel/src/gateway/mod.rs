//! Kernel-side gateway supervisor.
//!
//! Normative reference: `peripherals.md` §3.2 "Spawn model" and
//! "Crash-and-respawn".
//!
//! # The single-subprocess invariant
//!
//! The kernel spawns **exactly one** `raxis-gateway` subprocess per
//! kernel-process lifetime AT A TIME. Multiplexing is the gateway's
//! job (tokio fans out to thousands of concurrent FetchRequests within
//! the single process). There is zero architectural benefit to a pool
//! on a single host. This module enforces that invariant.
//!
//! # Crash-and-respawn
//!
//! When the supervised gateway exits (panic, segfault, OOM-killed,
//! returned non-zero), the supervisor:
//!
//! 1. Emits `GatewayCrashed { token_prefix, exit_code, attempt }`.
//! 2. Sleeps `respawn_backoff_ms * 2.pow(consecutive_crashes - 1)`,
//!    capped at 60 s (operators don't want a tight respawn loop on a
//!    persistently-broken binary).
//! 3. If `consecutive_crashes > max_consecutive_respawns`, emits
//!    `GatewayQuarantined { reason, total_attempts }` and stops.
//! 4. Otherwise: mints a fresh `gateway_process_token`, spawns a new
//!    child with the same env shape (Phase A.4 contract), emits
//!    `GatewaySpawned { token_prefix, binary_path, attempt }`.
//!
//! # No `[gateway]` section
//!
//! If `policy.gateway()` is `None` the kernel runs in degraded mode:
//! the supervisor task starts but immediately exits, logging that no
//! gateway was configured. Subsequent FetchRequests will fail-closed
//! at the kernel-side `gateway::*` adapter (planned for Phase B); for
//! now this only affects the kernel boot log.

pub mod supervisor;

pub use supervisor::{spawn_and_supervise, SupervisorShutdown};

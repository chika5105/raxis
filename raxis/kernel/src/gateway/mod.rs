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
//! # No model providers
//!
//! If policy declares no model providers, the kernel runs in degraded
//! mode: the policy-aware supervisor stays alive without a child,
//! logging that no gateway is configured. Subsequent FetchRequests
//! fail-closed at the kernel-side `gateway::*` adapter. If a later
//! epoch advance installs providers, the same supervisor starts the
//! gateway without requiring a kernel restart. Gateway process wiring
//! is kernel-owned runtime config, not signed operator policy.

pub mod accept;
pub mod client;
pub mod embedded;
pub mod supervisor;

pub use client::GatewayCallError;
pub use supervisor::spawn_policy_reconciler;

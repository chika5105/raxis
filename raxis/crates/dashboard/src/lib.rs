//! `raxis-dashboard` — operator HTTP backend (V2 §4).
//!
//! Normative reference: `specs/v2/v2_extended_gaps.md §4`
//! (Operator Dashboard).
//!
//! # What this crate owns
//!
//! * Axum-based HTTP server bound to a configurable
//!   `[dashboard]` address (default `127.0.0.1:9820`).
//! * Challenge-response operator authentication using the same
//!   Ed25519 keys + operator certificates the CLI uses
//!   (`raxis_crypto::verify_ed25519` + `PolicyBundle::operator_entry`
//!   + `cert_check::CertEnforcer`). No passwords, no shared secrets.
//! * Short-lived JWT (HS256, 24 hour TTL by default; see
//!   `INV-DASHBOARD-AUTOLOGIN-VALID-AT-BOOT-01`) signed with a
//!   secret that persists across kernel restarts when a
//!   `data_dir` is configured (see
//!   `INV-DASHBOARD-JWT-SECRET-PERSISTENT-01` /
//!   `crates/dashboard/src/jwt_secret.rs`), and falls back to a
//!   process-local ephemeral key for in-memory tests. Bounded
//!   in-memory revocation set on logout.
//! * Read-only API surface backed by an injectable
//!   [`DashboardData`] trait. The kernel binary wires a concrete
//!   `KernelDashboardData` (in `kernel/src/dashboard_glue.rs`)
//!   that fans out to `raxis_store::views`,
//!   `crate::push::InitiativeEventBus`, and the audit
//!   `ChainReader`.  Tests wire `InMemoryDashboardData` so the
//!   HTTP surface can be exercised without booting the kernel.
//! * Policy view + carefully-scoped write surface
//!   (`PUT /api/policy/toml`) that delegates to
//!   `raxis_policy::load_policy` + the kernel's existing epoch-
//!   advance path.
//!
//! # What this crate deliberately does NOT own
//!
//! * The kernel boot path. `kernel/src/main.rs` constructs the
//!   `Arc<dyn DashboardData>`, the JWT secret (`OsRng` 32 bytes),
//!   and the dashboard listener address; this crate exposes only
//!   `DashboardServer::new(...)` + `DashboardServer::serve(...)`.
//! * Kernel state mutation. Every endpoint except
//!   `PUT /api/policy/toml` is a pure read. The policy update
//!   handler delegates to the same `policy_manager::advance_epoch`
//!   path the operator UDS uses, so the audit trail and cert
//!   checks are unchanged.
//! * Static asset serving. The React bundle is mounted into the
//!   axum router at the kernel level via `tower_http::services::ServeDir`
//!   — see `kernel/src/dashboard_glue.rs::serve_static`.
//!
//! # Crate layout
//!
//! * [`config`] — [`DashboardConfig`] (parsed from `[dashboard]`
//!   in `policy.toml`).
//! * [`auth`] — challenge mint, signed-challenge verification,
//!   JWT mint/verify, bounded revocation.
//! * [`data`] — the [`DashboardData`] trait the kernel implements
//!   plus an [`InMemoryDashboardData`] for in-process tests.
//! * [`server`] — the axum `Router` + `DashboardServer` lifecycle.
//! * [`routes`] — per-endpoint handlers.
//! * [`error`] — uniform JSON error envelope.

#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod auth;
pub mod config;
pub mod data;
pub mod error;
pub mod jwt_secret;
pub mod routes;
pub mod server;
pub mod stream;

pub use config::{DashboardConfig, DEFAULT_DASHBOARD_ADDR, DEFAULT_DASHBOARD_PORT};
pub use data::{
    AuditEntryView, ChainStatusView, DashboardData, EscalationView, InMemoryDashboardData,
    InitiativeListEntry, InitiativeView, OperatorRole, PolicySnapshotView, SessionView,
    SubsystemDetailRow, SubsystemHealthCard, SubsystemHealthResponse, TaskView, WorktreeFile,
    WorktreeTree, WorktreeTreeEntry,
};
pub use error::{ApiError, ApiResult};
pub use server::{DashboardServer, ServerHandle, ShutdownSignal};

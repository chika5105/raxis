//! `raxis-gateway` — Provider-call proxy spawned by the kernel.
//!
//! Normative reference: `peripherals.md` §3.2 "Gateway Wire Format".
//!
//! # What this binary is
//!
//! The kernel spawns exactly **one** `raxis-gateway` subprocess at boot
//! (per `peripherals.md` §3.2 "Spawn model"). The gateway:
//!
//! 1. Reads `RAXIS_GATEWAY_TOKEN` (32 random bytes, hex) and
//!    `RAXIS_GATEWAY_SOCKET` (UDS path) from its environment.
//! 2. Connects to `gateway.sock` and sends
//!    `GatewayMessage::GatewayReady { gateway_token }`.
//! 3. Loads `<data_dir>/policy/policy.toml` directly (the gateway is
//!    on the same host; reading the file is faster and breaks no
//!    invariants because the domain allowlist is the same source of
//!    truth). Loads each `[[providers]]` credentials file from
//!    `<data_dir>/providers/<credentials_file>` (mode 0600).
//! 4. Enters a request-reply loop:
//!    - `FetchRequest` → validate token + URL allowlist + provider →
//!      run the backend (`MockBackend` for tests, future `HttpBackend`
//!      for production) → `FetchResponse`.
//!    - `EpochAdvanced` → re-read policy.toml + credentials.
//!
//! # Single-process model
//!
//! Tokio gives one process all the concurrency we need: one task per
//! in-flight `FetchRequest`. There is **no pool** — the kernel only ever
//! spawns one gateway. If the gateway dies, the kernel respawns it
//! (Phase A.5 supervisor) with a fresh `gateway_token`.
//!
//! # Single source of truth
//!
//! Everything in this crate is testable without a kernel: the `Backend`
//! trait abstracts the HTTP call, the env-var parser is pure, the policy
//! view loader is pure. The `main.rs` binary is the I/O shim that wires
//! these pieces to a real `UnixStream`.

pub mod backend;
pub mod dispatch;
pub mod env;
#[cfg(feature = "http-backend")]
pub mod http_backend;
pub mod policy_view;
pub mod runtime;

// Re-export the most common types so callers don't need to know the
// module layout.
pub use backend::{Backend, BackendError, MockBackend};
#[cfg(feature = "http-backend")]
pub use http_backend::HttpBackend;
pub use dispatch::{handle_fetch_request, DispatchError};
pub use env::{parse_gateway_env_from_process, GatewayEnv, GatewayEnvError};
pub use policy_view::{
    load_policy_view, load_provider_credentials, PolicyView, PolicyViewError, ProviderCredentials,
};
pub use runtime::{run_gateway, GatewayRunError};

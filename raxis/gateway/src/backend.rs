//! `Backend` trait — the single side effect the gateway performs.
//!
//! Normative reference: `peripherals.md` §3.2.
//!
//! The trait, its request / response / error shapes, and the
//! runtime-resolved provider-view types all live in
//! [`raxis_gateway_substrate`] so the in-memory test fake
//! (`raxis_test_support::MockBackend`) can implement the trait
//! without dragging the rest of the gateway crate (and its
//! `reqwest`/`tokio`/`raxis-policy` dependency closure) into the
//! test-support graph. Same separation as
//! `raxis-types::Clock` (production trait) ↔
//! `raxis-test-support::FakeClock` (test fake) documented in
//! `philosophy.md` §1.6.
//!
//! v2 ships a single production implementation: `HttpBackend` (in
//! [`crate::http_backend`]). The mock fake never reaches a release
//! binary — it is gated by `cfg(any(debug_assertions, test))` inside
//! `raxis-test-support` and the `workspace_guard` test enforces that
//! crate appears only under `[dev-dependencies]`.

// Re-export the trait + types so existing call sites
// (`raxis_gateway::backend::Backend`,
// `raxis_gateway::backend::BackendError`, etc.) continue to work
// after the trait moved out into `raxis-gateway-substrate`.
pub use raxis_gateway_substrate::{Backend, BackendError, BackendRequest, BackendResponse};

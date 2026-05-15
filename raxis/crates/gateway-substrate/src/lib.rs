//! `raxis-gateway-substrate` — the gateway's outbound-call trait and
//! the runtime-resolved provider-view shapes.
//!
//! Normative reference: `peripherals.md` §3.2 ("Gateway Wire Format" /
//! "Outbound provider call").
//!
//! # Why this crate exists
//!
//! The gateway's substrate is one trait (`Backend`) plus a small set
//! of plain-old-data types describing the resolved provider that a
//! request targets. The trait + types live in this crate (rather than
//! in `raxis-gateway`) so:
//!
//!   1. The in-memory test fake (`MockBackend`) can live in
//!      `raxis-test-support` without forcing
//!      `raxis-test-support → raxis-gateway → (dev-dep) raxis-test-support`
//!      cycles. `raxis-test-support` depends on this crate; it does
//!      not need the rest of the gateway.
//!
//!   2. Future production substrates that want to wrap or layer on top
//!      of `Backend` (rate-limiting middleware, retry-budget probes,
//!      observability shims) can pull in just this crate without
//!      pulling in `reqwest`, `tokio`, etc. that the production
//!      `HttpBackend` brings.
//!
//! Same separation principle as `raxis-types::Clock` (production trait)
//! vs. `raxis-test-support::FakeClock` (test fake) documented in
//! `philosophy.md` §1.6.
//!
//! # What this crate does NOT contain
//!
//! - `HttpBackend` — the real production implementation, lives in
//!   `raxis-gateway::http_backend`. It depends on `reqwest`/`rustls`
//!   and pulling those into a "trait-only" crate would defeat the
//!   point.
//!
//! - `MockBackend` — the in-memory test fake, lives in
//!   `raxis-test-support::gateway_backend`. It is dev-dep-only by
//!   construction (the test-support crate is gated on
//!   `cfg(any(debug_assertions, test))` and the `workspace_guard` test
//!   enforces it appears only under `[dev-dependencies]`).
//!
//! - The dispatch / framing / policy-view-loading logic. That all
//!   stays in `raxis-gateway` because it depends on
//!   `raxis-policy`, the IPC frame codec, and tokio I/O.

use std::time::Duration;

use serde::Deserialize;
use thiserror::Error;

// ---------------------------------------------------------------------------
// Provider view — the runtime-resolved provider config the gateway
// consults when dispatching a `FetchRequest`.
// ---------------------------------------------------------------------------

/// One provider's gateway-relevant config + credentials. Built by
/// `raxis-gateway::policy_view::load_policy_view` from
/// `policy.toml [[providers]]` plus the matching
/// `<data_dir>/providers/<credentials_file>`.
///
/// Why the credentials live in the same struct as the other provider
/// fields: `Backend` impls receive a single `&ProviderEntryView`
/// reference that already contains everything they need to mint the
/// outbound request — no second lookup, no chance of mixing up the
/// credentials of two providers.
#[derive(Debug, Clone)]
pub struct ProviderEntryView {
    pub provider_id: String,
    pub kind: String,
    pub inference_timeout_ms: u32,
    pub data_fetch_timeout_ms: u32,
    pub max_response_bytes: u64,
    /// V2_GAPS §C9 — per-provider streaming idle timeout (ms).
    /// `None` means the gateway falls back to its hard-coded
    /// 30-second `STREAM_IDLE_TIMEOUT` default. Operators using
    /// reasoning-tier models (OpenAI o1/o3) widen this to 60–120 s
    /// for those providers; standard generation-tier providers
    /// (Claude, GPT-4) leave it `None`.
    pub stream_idle_timeout_ms: Option<u32>,
    pub credentials: ProviderCredentials,
}

/// Parsed `<data_dir>/providers/<credentials_file>`. Format is
/// intentionally minimal in v1: a single `api_key` plus optional auth
/// header overrides. v2 will likely add per-credential rotation
/// timestamps and a key-id to allow zero-downtime rolls.
#[derive(Debug, Clone, Deserialize)]
pub struct ProviderCredentials {
    /// The bearer token / API key. The gateway injects this into the
    /// outbound request via `auth_header` (default `"Authorization"`)
    /// with `auth_prefix` (default `"Bearer "`). Never logged.
    pub api_key: String,

    /// Header name to inject the credential under. Default
    /// `"Authorization"` — overridable for providers that use a
    /// custom header name (e.g. Anthropic uses `x-api-key`).
    #[serde(default = "default_auth_header")]
    pub auth_header: String,

    /// Prefix to prepend before the api_key in the header value.
    /// Default `"Bearer "`. Set to `""` for providers that pass the
    /// key bare.
    #[serde(default = "default_auth_prefix")]
    pub auth_prefix: String,
}

fn default_auth_header() -> String {
    "Authorization".to_owned()
}
fn default_auth_prefix() -> String {
    "Bearer ".to_owned()
}

// ---------------------------------------------------------------------------
// Backend trait + its request / response / error shapes.
// ---------------------------------------------------------------------------

/// Why a backend call could not produce a `BackendResponse`. Maps 1:1
/// to the `error` strings in `peripherals.md` §3.2 `FetchResponse`
/// table so the gateway's dispatch layer's error-to-string projection
/// is a one-liner.
///
/// `PartialEq + Eq` are derived so dispatch's wrapper error type can
/// derive them too — dispatch tests assert against specific variants.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum BackendError {
    /// Network reachability / TLS / DNS / connection refused.
    #[error("upstream unreachable: {reason}")]
    Upstream { reason: String },
    /// The configured per-request timeout fired.
    #[error("upstream timeout after {timeout_ms} ms")]
    Timeout { timeout_ms: u32 },
    /// The response body exceeded the per-provider `max_response_bytes`.
    #[error("response body too large: {got} bytes > {limit} bytes")]
    TooLarge { got: u64, limit: u64 },
}

/// One outbound call through the backend.
pub struct BackendRequest<'a> {
    pub provider: &'a ProviderEntryView,
    pub url: &'a str,
    pub method: &'a str,
    pub headers: &'a [(String, String)],
    pub body: &'a [u8],
    pub timeout: Duration,
    /// V2_GAPS §C9 — per-chunk idle timeout for streaming responses.
    ///
    /// When `Some(d)`, the gateway's chunk-read loop wraps each
    /// `Response::chunk()` await in `tokio::time::timeout(d, …)`.
    /// A provider that accepts the request but stalls mid-body
    /// surfaces as `BackendError::Timeout` after `d`, well below
    /// the request-level `timeout` ceiling. This is the gateway leg
    /// of the C9 "provider hang detection" benefit.
    ///
    /// When `None`, no per-chunk deadline applies; the request is
    /// bounded only by the request-level `timeout`. The dispatch
    /// layer sets this for `FetchKind::Inference` (where streaming
    /// is expected) and leaves it `None` for `FetchKind::DataFetch`.
    pub stream_idle_timeout: Option<Duration>,
}

/// Raw upstream response, ready for the gateway to wrap in a
/// `FetchResponse`.
#[derive(Debug, Clone)]
pub struct BackendResponse {
    pub status_code: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub latency_ms: u64,
}

/// One outbound HTTP call. v2 ships exactly one production impl
/// (`raxis-gateway::http_backend::HttpBackend`); the in-memory test
/// fake `raxis-test-support::MockBackend` lives in the dev-dep-only
/// support crate so it can never reach a release binary.
///
/// **Why a hand-boxed Future return rather than `async fn` in the
/// trait:** stable async-fn-in-trait (Rust 1.75+) makes traits
/// non-dyn-compatible by default, but the dispatcher holds the
/// backend behind `Arc<dyn Backend>` (so it can swap real-HTTP ↔
/// future middleware-wrapped backends without re-monomorphising
/// every call site). Returning an explicit
/// `Pin<Box<dyn Future + Send>>` recovers dyn-compatibility at the
/// cost of one heap allocation per call — negligible relative to
/// the ms-scale network round-trip we're wrapping.
pub trait Backend: Send + Sync {
    fn call<'a>(
        &'a self,
        req: BackendRequest<'a>,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<BackendResponse, BackendError>> + Send + 'a>,
    >;
}

// ---------------------------------------------------------------------------
// Tests — trait-shape compile-checks. The toml-decode round-trip for
// `ProviderCredentials` is exercised in
// `raxis-gateway::policy_view::tests` (where the loader lives); this
// crate keeps its dependency footprint minimal (no `toml` dev-dep) and
// only pins the trait-shape invariants here.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// `Backend` must be object-safe: `Arc<dyn Backend>` is what the
    /// gateway's dispatch loop holds. If a future change breaks
    /// dyn-compat (e.g. by adding a generic method), this test fails
    /// to compile.
    #[allow(dead_code)]
    fn _assert_dyn_compat() {
        fn _takes(_: &dyn Backend) {}
    }

    #[test]
    fn backend_error_variants_are_eq_for_dispatch_assertions() {
        // The gateway dispatch tests compare `BackendError` variants
        // directly; pin the equality contract here so a future
        // refactor that drops `PartialEq` flags it as a P0.
        let a = BackendError::Timeout { timeout_ms: 250 };
        let b = BackendError::Timeout { timeout_ms: 250 };
        let c = BackendError::Timeout { timeout_ms: 251 };
        assert_eq!(a, b);
        assert_ne!(a, c);
    }
}

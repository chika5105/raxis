//! `raxis-credential-proxy-cloud-shared` — V3 cloud-forwarding
//! shared infrastructure.
//!
//! Normative reference: `specs/v3/cloud-proxy-forwarding.md`.
//!
//! This crate is the shared substrate the three cloud proxies
//! (AWS, GCP, Azure) use to:
//!
//!   * Construct an HTTPS client whose dispatch target is
//!     mechanically restricted to a closed allowlist of cloud
//!     control-plane FQDNs ([`allowlist`]).
//!   * Cache short-lived tokens in-memory with a configurable
//!     safety window and async background-refresh semantics
//!     ([`cache`]).
//!   * Emit redaction-disciplined audit events that record the
//!     upstream-exchange decision without leaking credential
//!     bytes ([`audit`]).
//!   * Translate provider-specific upstream errors into the
//!     `UpstreamError` enum the proxy uses to drive denial/audit
//!     handling ([`error`]).
//!
//! The crate has NO platform-specific dependencies and NO
//! credential-resolution logic — it consumes already-resolved
//! credential bytes from `raxis-credentials::CredentialBackend`
//! through its caller. Audit emission is via the existing
//! `AuditSink`; metrics are emitted from the per-provider
//! crates (the shared crate is wire-discipline only).
//!
//! # Threat model
//!
//! The kernel address space is the trust boundary. Long-lived
//! credentials reach this crate from the `CredentialBackend`
//! resolution path; the crate then signs / form-encodes /
//! posts a request to the closed-allowlist host, parses the
//! upstream response, and returns the short-lived material
//! to the calling proxy. Long-lived material NEVER appears
//! in audit events or log lines. Short-lived material is held
//! only in `SecretBox`-wrapped fields inside the in-memory
//! cache and is zeroized on cache eviction / proxy drop.

#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod allowlist;
pub mod audit;
pub mod cache;
pub mod error;
pub mod http;
pub mod sigv4;
pub mod time;

pub use allowlist::{validate_upstream_url, AllowlistError, CloudUpstreamHost};
pub use audit::{
    emit_cloud_credential_cache_hit, emit_cloud_credential_cache_refreshed,
    emit_cloud_credential_forwarded, emit_cloud_credential_forwarding_denied, CloudExchangeKind,
    CloudForwardingDenialReason, CloudProvider,
};
pub use cache::{CacheKey, CachedToken, TokenCache};
pub use error::UpstreamError;
pub use http::CloudHttpClient;
pub use time::unix_now_seconds;

#[cfg(test)]
mod sanity_tests {
    use super::*;

    #[test]
    fn unix_now_seconds_is_monotonic_nondecreasing() {
        let a = unix_now_seconds();
        let b = unix_now_seconds();
        assert!(b >= a, "unix_now_seconds must be wall-clock non-decreasing");
    }
}

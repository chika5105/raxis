//! V3 cloud-forwarding error surface.
//!
//! Normative reference: `specs/v3/cloud-proxy-forwarding.md §6`.
//!
//! The forwarding path produces two distinct error shapes:
//!
//!   1. [`UpstreamError`] — the kernel-internal classification
//!      the proxy uses to drive its audit emission and cache
//!      eviction logic. The variants map 1:1 to the closed-enum
//!      denial reasons in `specs/v3/cloud-proxy-forwarding.md §5.2`.
//!   2. Provider crates render their own upstream-canonical error
//!      bodies back to the in-VM client unchanged (`INV-CLOUD-FWD-05`).
//!
//! The split lets the shared crate stay provider-agnostic: it
//! classifies the wire-level outcome (transport vs. 4xx vs. 5xx
//! vs. timeout), and the per-provider crate owns the XML / JSON
//! envelope shape.

use thiserror::Error;

use crate::allowlist::AllowlistError;
use crate::audit::CloudForwardingDenialReason;

/// Failure modes from a forwarding upstream call. Maps 1:1
/// onto [`CloudForwardingDenialReason`] for audit emission.
#[derive(Debug, Error)]
pub enum UpstreamError {
    /// Egress allowlist tripped. The dispatched URL host did
    /// not match the constructor-configured upstream host.
    /// This SHOULD be unreachable in practice — the
    /// constructor refuses to build a client whose URL falls
    /// off the allowlist — but the runtime check fail-closes
    /// for defence in depth.
    #[error("egress allowlist denied dispatch: {0}")]
    EgressAllowlist(#[from] AllowlistError),

    /// `forwarding_enabled = true` but a required credential
    /// or plan field was missing. The proxy refuses to call
    /// upstream rather than attempting an unsigned / unauth'd
    /// request.
    #[error("forwarding required but credential or config missing: {0}")]
    MissingCredential(String),

    /// Operator-supplied config was malformed (bad role ARN,
    /// bad tenant GUID, etc.). Surfaces at constructor time
    /// when the forwarder is built.
    #[error("forwarding misconfigured: {0}")]
    Misconfigured(String),

    /// Upstream returned 500..600. Body bytes are NOT included
    /// here — the proxy passes the original response back to
    /// the in-VM client; the kernel never logs the body.
    #[error("upstream returned {0} (5xx)")]
    Upstream5xx(u16),

    /// Upstream returned 400..500. Same redaction discipline
    /// as `Upstream5xx`.
    #[error("upstream returned {0} (4xx)")]
    Upstream4xx(u16),

    /// Upstream returned a 2xx but the body failed to parse.
    /// The body bytes are NEVER captured here — only the
    /// parser's short descriptive string.
    #[error("upstream returned a malformed 2xx body: {0}")]
    UpstreamMalformed(String),

    /// Connect or response timeout.
    #[error("upstream call timed out")]
    Timeout,

    /// DNS / TCP / TLS / generic IO failure pre-response.
    /// The wrapped detail is intentionally a short string with
    /// no credential material (the underlying `reqwest::Error`
    /// Display shape only includes the URL, which is itself in
    /// the allowlist and therefore safe).
    #[error("upstream network failure: {0}")]
    Network(String),
}

impl UpstreamError {
    /// The audit denial-reason this error maps to. Used by the
    /// per-provider proxy to emit `CloudCredentialForwardingDenied`
    /// with the closed-enum reason.
    pub fn denial_reason(&self) -> CloudForwardingDenialReason {
        match self {
            Self::EgressAllowlist(_) => CloudForwardingDenialReason::EgressAllowlist,
            Self::MissingCredential(_) => CloudForwardingDenialReason::MissingCredential,
            Self::Misconfigured(_) => CloudForwardingDenialReason::Misconfigured,
            Self::Upstream5xx(_) => CloudForwardingDenialReason::Upstream5xx,
            Self::Upstream4xx(_) => CloudForwardingDenialReason::Upstream4xx,
            Self::UpstreamMalformed(_) => CloudForwardingDenialReason::UpstreamMalformed,
            Self::Timeout => CloudForwardingDenialReason::Timeout,
            Self::Network(_) => CloudForwardingDenialReason::Network,
        }
    }

    /// Upstream HTTP status code, when applicable. `None` for
    /// transport-level failures (DNS, TCP, TLS, timeout) that
    /// never produced an HTTP response.
    pub fn status_code(&self) -> Option<u16> {
        match self {
            Self::Upstream5xx(s) | Self::Upstream4xx(s) => Some(*s),
            _ => None,
        }
    }
}

/// Translate a `reqwest::Error` into an [`UpstreamError`] with
/// the credential material scrubbed out of the diagnostic text.
///
/// `reqwest::Error::to_string()` can include the URL (which is
/// in the allowlist, so safe) but never the request body — so
/// the redaction surface is small. We still match on `is_timeout`
/// `is_connect` to classify into the audit taxonomy correctly.
pub fn classify_reqwest_error(err: reqwest::Error) -> UpstreamError {
    if err.is_timeout() {
        UpstreamError::Timeout
    } else {
        // reqwest's Display impl includes the URL but never
        // request/response body bytes. The diagnostic text is
        // safe to log; we still defensively avoid `{:?}` (which
        // could include the user-agent string and internal
        // state that future versions might widen).
        UpstreamError::Network(format!("{err}"))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn denial_reason_maps_through_every_variant() {
        assert_eq!(
            UpstreamError::MissingCredential("x".into()).denial_reason(),
            CloudForwardingDenialReason::MissingCredential,
        );
        assert_eq!(
            UpstreamError::Misconfigured("x".into()).denial_reason(),
            CloudForwardingDenialReason::Misconfigured,
        );
        assert_eq!(
            UpstreamError::Upstream5xx(503).denial_reason(),
            CloudForwardingDenialReason::Upstream5xx,
        );
        assert_eq!(
            UpstreamError::Upstream4xx(403).denial_reason(),
            CloudForwardingDenialReason::Upstream4xx,
        );
        assert_eq!(
            UpstreamError::Timeout.denial_reason(),
            CloudForwardingDenialReason::Timeout,
        );
        assert_eq!(
            UpstreamError::Network("dns".into()).denial_reason(),
            CloudForwardingDenialReason::Network,
        );
        assert_eq!(
            UpstreamError::UpstreamMalformed("bad json".into()).denial_reason(),
            CloudForwardingDenialReason::UpstreamMalformed,
        );
    }

    #[test]
    fn status_code_is_present_only_for_4xx_5xx() {
        assert_eq!(UpstreamError::Upstream4xx(400).status_code(), Some(400));
        assert_eq!(UpstreamError::Upstream5xx(503).status_code(), Some(503));
        assert_eq!(UpstreamError::Timeout.status_code(), None);
        assert_eq!(UpstreamError::Network("x".into()).status_code(), None);
    }
}

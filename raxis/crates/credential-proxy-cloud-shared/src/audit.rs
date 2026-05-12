//! Audit-emission helpers for V3 cloud-forwarding paths.
//!
//! Normative reference: `specs/v3/cloud-proxy-forwarding.md §5`.
//!
//! Every forwarding decision routes through one of the four
//! `emit_*` functions in this module. The helpers are the single
//! choke point that enforces the redaction discipline pinned in
//! INV-CLOUD-FWD-02: credential bytes — IAM keys, service-
//! account private keys, JWT assertions, response-body bytes —
//! NEVER reach the audit event payload. The helpers accept the
//! already-redacted metadata (upstream host, latency, status
//! code, response length) and route into the kernel
//! `AuditSink::emit` surface.
//!
//! ## Why a helper layer
//!
//! The per-provider proxies (`credential-proxy-aws`,
//! `credential-proxy-gcp`, `credential-proxy-azure`) construct
//! the V2 audit events (`AwsCredentialServed`,
//! `GcpMetadataServed`, `AzureTokenServed`) directly through
//! their own `AuditChannel` trait so V2 wire shape is
//! unchanged. V3 adds FOUR new events on the upstream-facing
//! side of the same in-VM request — emitted in addition to,
//! not instead of, the V2 events. A single helper layer that
//! every provider's V3 path calls into makes the redaction
//! contract reviewable in one place.

use std::sync::Arc;

use raxis_audit_tools::{AuditEventKind, AuditSink};

use crate::CloudUpstreamHost;

/// Closed enum of cloud-provider identifiers. Pinned as a
/// type rather than a free-form string so a typo cannot land
/// in audit (the V2 audit events use the V2 audit-event
/// variant name; V3 adds these stable short strings as the
/// `provider` attribute).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloudProvider {
    /// AWS — `sts:AssumeRole` exchange.
    Aws,
    /// GCP — JWT-bearer-grant OAuth2 exchange.
    Gcp,
    /// Azure — `client_credentials`-grant OAuth2 exchange.
    Azure,
}

impl CloudProvider {
    /// Stable wire string. Pinned by tests; renaming breaks
    /// downstream audit consumers.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Aws   => "aws",
            Self::Gcp   => "gcp",
            Self::Azure => "azure",
        }
    }
}

/// Closed enum of upstream-exchange kinds, mirroring the three
/// V3 grant types in `cloud-proxy-forwarding.md §2`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloudExchangeKind {
    /// AWS `sts:AssumeRole` via SigV4-signed `POST /`.
    AssumeRole,
    /// GCP JWT-bearer grant via OAuth2 form POST.
    JwtBearer,
    /// Azure `client_credentials` grant via OAuth2 form POST.
    ClientCredentials,
}

impl CloudExchangeKind {
    /// Stable wire string.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AssumeRole        => "assume_role",
            Self::JwtBearer         => "jwt_bearer",
            Self::ClientCredentials => "client_credentials",
        }
    }
}

/// Closed enum of denial reasons. Pinned in
/// `specs/v3/cloud-proxy-forwarding.md §5.2`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloudForwardingDenialReason {
    /// Construction-time refusal (defence-in-depth pin; should
    /// never appear at runtime since the allowlist is checked at
    /// proxy bind).
    EgressAllowlist,
    /// `CredentialBackend::resolve` returned `NotFound` or a body
    /// that failed to parse.
    MissingCredential,
    /// Plan declared `forwarding_enabled` without the required
    /// provider-specific fields (e.g. missing `role_arn` for AWS).
    Misconfigured,
    /// Upstream returned a 4xx with a well-formed error envelope.
    Upstream4xx,
    /// Upstream returned a 5xx.
    Upstream5xx,
    /// Upstream returned a 2xx but the body failed to parse.
    UpstreamMalformed,
    /// Request exceeded the per-request deadline.
    Timeout,
    /// DNS / TCP / TLS error before any HTTP shape was decided.
    Network,
}

impl CloudForwardingDenialReason {
    /// Stable wire string.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::EgressAllowlist   => "egress_allowlist",
            Self::MissingCredential => "missing_credential",
            Self::Misconfigured     => "misconfigured",
            Self::Upstream4xx       => "upstream_4xx",
            Self::Upstream5xx       => "upstream_5xx",
            Self::UpstreamMalformed => "upstream_malformed",
            Self::Timeout           => "timeout",
            Self::Network           => "network",
        }
    }
}

/// Emit a `CloudCredentialForwarded` audit event. Called by the
/// per-provider crate after a successful upstream exchange.
///
/// `response_bytes` is the LENGTH of the upstream response body,
/// never the body itself. The helper takes `upstream` as a
/// `CloudUpstreamHost` so the audit's `upstream_host` field is
/// the canonical allowlist-validated FQDN (no risk of partial-URL
/// leak).
///
/// Returns the audit sink's result so the caller can propagate
/// emission failures (the kernel halts the boot path on
/// unrecoverable audit failure per `R-7`).
#[allow(clippy::too_many_arguments)] // Audit shape is normative — see spec §5.1.
pub fn emit_cloud_credential_forwarded(
    audit:           &Arc<dyn AuditSink>,
    session_id:      &str,
    credential_name: &str,
    provider:        CloudProvider,
    exchange_kind:   CloudExchangeKind,
    upstream:        &CloudUpstreamHost,
    latency_ms:      u32,
    status_code:     u16,
    response_bytes:  u32,
    request_signed:  bool,
) -> Result<(), String> {
    audit
        .emit(
            AuditEventKind::CloudCredentialForwarded {
                session_id:                session_id.to_owned(),
                credential_name:           credential_name.to_owned(),
                provider:                  provider.as_str().to_owned(),
                exchange_kind:             exchange_kind.as_str().to_owned(),
                upstream_endpoint:         upstream.host().to_owned(),
                outcome:                   "success".to_owned(),
                latency_ms,
                status_code,
                redacted_response_size:    response_bytes,
                request_signature_present: request_signed,
            },
            None,
            None,
            None,
        )
        .map(|_| ())
        .map_err(|e| e.to_string())
}

/// Emit a `CloudCredentialForwardingDenied` audit event.
///
/// `status_code` is `0` when no HTTP response was received
/// (e.g. timeout / network error / construction refusal).
#[allow(clippy::too_many_arguments)] // Audit shape is normative — see spec §5.2.
pub fn emit_cloud_credential_forwarding_denied(
    audit:           &Arc<dyn AuditSink>,
    session_id:      &str,
    credential_name: &str,
    provider:        CloudProvider,
    exchange_kind:   CloudExchangeKind,
    upstream_host:   &str,
    reason:          CloudForwardingDenialReason,
    status_code:     u16,
    latency_ms:      u32,
) -> Result<(), String> {
    audit
        .emit(
            AuditEventKind::CloudCredentialForwardingDenied {
                session_id:        session_id.to_owned(),
                credential_name:   credential_name.to_owned(),
                provider:          provider.as_str().to_owned(),
                exchange_kind:     exchange_kind.as_str().to_owned(),
                upstream_endpoint: upstream_host.to_owned(),
                reason:            reason.as_str().to_owned(),
                status_code,
                latency_ms,
            },
            None,
            None,
            None,
        )
        .map(|_| ())
        .map_err(|e| e.to_string())
}

/// Emit a `CloudCredentialCacheHit` audit event.
pub fn emit_cloud_credential_cache_hit(
    audit:            &Arc<dyn AuditSink>,
    session_id:       &str,
    credential_name:  &str,
    provider:         CloudProvider,
    exchange_kind:    CloudExchangeKind,
    age_ms:           u32,
    ttl_remaining_ms: u32,
) -> Result<(), String> {
    audit
        .emit(
            AuditEventKind::CloudCredentialCacheHit {
                session_id:      session_id.to_owned(),
                credential_name: credential_name.to_owned(),
                provider:        provider.as_str().to_owned(),
                exchange_kind:   exchange_kind.as_str().to_owned(),
                age_ms,
                ttl_remaining_ms,
            },
            None,
            None,
            None,
        )
        .map(|_| ())
        .map_err(|e| e.to_string())
}

/// Emit a `CloudCredentialCacheRefreshed` audit event.
pub fn emit_cloud_credential_cache_refreshed(
    audit:           &Arc<dyn AuditSink>,
    session_id:      &str,
    credential_name: &str,
    provider:        CloudProvider,
    exchange_kind:   CloudExchangeKind,
    prior_age_ms:    u32,
    new_ttl_ms:      u32,
) -> Result<(), String> {
    audit
        .emit(
            AuditEventKind::CloudCredentialCacheRefreshed {
                session_id:      session_id.to_owned(),
                credential_name: credential_name.to_owned(),
                provider:        provider.as_str().to_owned(),
                exchange_kind:   exchange_kind.as_str().to_owned(),
                prior_age_ms,
                new_ttl_ms,
            },
            None,
            None,
            None,
        )
        .map(|_| ())
        .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_strings_pin() {
        assert_eq!(CloudProvider::Aws  .as_str(), "aws");
        assert_eq!(CloudProvider::Gcp  .as_str(), "gcp");
        assert_eq!(CloudProvider::Azure.as_str(), "azure");
    }

    #[test]
    fn exchange_kind_strings_pin() {
        assert_eq!(CloudExchangeKind::AssumeRole       .as_str(), "assume_role");
        assert_eq!(CloudExchangeKind::JwtBearer        .as_str(), "jwt_bearer");
        assert_eq!(CloudExchangeKind::ClientCredentials.as_str(), "client_credentials");
    }

    #[test]
    fn denial_reason_strings_pin() {
        for (r, s) in [
            (CloudForwardingDenialReason::EgressAllowlist,   "egress_allowlist"),
            (CloudForwardingDenialReason::MissingCredential, "missing_credential"),
            (CloudForwardingDenialReason::Misconfigured,     "misconfigured"),
            (CloudForwardingDenialReason::Upstream4xx,       "upstream_4xx"),
            (CloudForwardingDenialReason::Upstream5xx,       "upstream_5xx"),
            (CloudForwardingDenialReason::UpstreamMalformed, "upstream_malformed"),
            (CloudForwardingDenialReason::Timeout,           "timeout"),
            (CloudForwardingDenialReason::Network,           "network"),
        ] {
            assert_eq!(r.as_str(), s);
        }
    }
}

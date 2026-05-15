//! V3 cloud-forwarding upstream allowlist.
//!
//! Normative reference: `specs/v3/cloud-proxy-forwarding.md §3`.
//!
//! The set of FQDNs a V3 cloud-forwarding proxy is permitted to
//! dial is a **closed, compile-time constant**. Plan and policy
//! can opt INTO forwarding but cannot ever redirect to a
//! different upstream. This module exposes:
//!
//! * [`CloudUpstreamHost`] — typed handle for one allowlisted
//!   FQDN; carries the provider tag so audit emit knows which
//!   `provider` field to write.
//! * [`validate_upstream_url`] — case-insensitive,
//!   trailing-dot-tolerant URL check used at constructor time
//!   AND as a defence-in-depth check on every dispatch.
//!
//! AWS regional STS endpoints are enumerated against the AWS
//! `AWS_REGIONS` closed set so a misconfigured region cannot
//! synthesise an off-allowlist FQDN.

use std::fmt;

use thiserror::Error;

use crate::audit::CloudProvider;

/// Stable list of AWS regions whose regional STS endpoint
/// (`sts.{region}.amazonaws.com`) is part of the closed allowlist.
///
/// This is the AWS-published set of GA commercial regions. Adding
/// a new region is a spec amendment (it widens the allowlist) and
/// requires updating both this constant AND
/// `specs/v3/cloud-proxy-forwarding.md §3`.
const AWS_REGIONS: &[&str] = &[
    "us-east-1",
    "us-east-2",
    "us-west-1",
    "us-west-2",
    "af-south-1",
    "ap-east-1",
    "ap-south-1",
    "ap-south-2",
    "ap-southeast-1",
    "ap-southeast-2",
    "ap-southeast-3",
    "ap-southeast-4",
    "ap-northeast-1",
    "ap-northeast-2",
    "ap-northeast-3",
    "ca-central-1",
    "ca-west-1",
    "eu-central-1",
    "eu-central-2",
    "eu-north-1",
    "eu-south-1",
    "eu-south-2",
    "eu-west-1",
    "eu-west-2",
    "eu-west-3",
    "il-central-1",
    "me-central-1",
    "me-south-1",
    "sa-east-1",
];

/// One allowlisted cloud-control-plane FQDN.
///
/// Constructed only through [`Self::aws_global`], [`Self::aws_regional`],
/// [`Self::gcp_oauth2`], or [`Self::azure_login`] — every constructor
/// returns `Result<Self, AllowlistError>` so a misconfigured value
/// fails closed at construction time, never at dispatch time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloudUpstreamHost {
    provider: CloudProvider,
    host: String,
}

impl CloudUpstreamHost {
    /// `sts.amazonaws.com` (global STS, treated as `us-east-1`).
    pub fn aws_global() -> Self {
        Self {
            provider: CloudProvider::Aws,
            host: "sts.amazonaws.com".to_owned(),
        }
    }

    /// `sts.{region}.amazonaws.com`. Fails closed for unknown
    /// regions per `INV-CLOUD-FWD-01`.
    pub fn aws_regional(region: &str) -> Result<Self, AllowlistError> {
        if region.is_empty() {
            return Err(AllowlistError::EmptyAwsRegion);
        }
        let region_lower = region.to_ascii_lowercase();
        if !AWS_REGIONS.contains(&region_lower.as_str()) {
            return Err(AllowlistError::UnknownAwsRegion(region.to_owned()));
        }
        Ok(Self {
            provider: CloudProvider::Aws,
            host: format!("sts.{region_lower}.amazonaws.com"),
        })
    }

    /// `oauth2.googleapis.com`.
    pub fn gcp_oauth2() -> Self {
        Self {
            provider: CloudProvider::Gcp,
            host: "oauth2.googleapis.com".to_owned(),
        }
    }

    /// `login.microsoftonline.com`. Tenant GUID lives in the URL
    /// path, not the host — the path is validated at request-build
    /// time.
    pub fn azure_login() -> Self {
        Self {
            provider: CloudProvider::Azure,
            host: "login.microsoftonline.com".to_owned(),
        }
    }

    /// Provider tag (for audit + metrics).
    pub fn provider(&self) -> CloudProvider {
        self.provider
    }

    /// FQDN. Always ASCII lowercase.
    pub fn host(&self) -> &str {
        &self.host
    }

    /// Fully-qualified `https://` base URL.
    pub fn https_base(&self) -> String {
        format!("https://{}", self.host)
    }

    /// Match against a candidate URL host, case-insensitive and
    /// trailing-dot-tolerant. Used by the HTTP client constructor
    /// AND on every dispatch (defence in depth).
    pub fn matches(&self, candidate_host: &str) -> bool {
        let candidate = candidate_host
            .trim()
            .trim_end_matches('.')
            .to_ascii_lowercase();
        candidate == self.host
    }
}

impl fmt::Display for CloudUpstreamHost {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.host)
    }
}

/// Errors surfaced when constructing or validating an upstream.
#[derive(Debug, Error)]
pub enum AllowlistError {
    /// AWS region was unknown / not in the closed enum.
    #[error("AWS region {0:?} is not in the closed allowlist")]
    UnknownAwsRegion(String),

    /// AWS region was an empty string.
    #[error("AWS region was empty")]
    EmptyAwsRegion,

    /// Candidate URL was syntactically malformed.
    #[error("malformed upstream URL: {0}")]
    MalformedUrl(String),

    /// Candidate URL was reachable scheme-wise (https) but the
    /// host did not match the constructed upstream.
    #[error("upstream host {actual:?} does not match expected {expected:?}")]
    HostMismatch {
        /// Expected FQDN from the constructed `CloudUpstreamHost`.
        expected: String,
        /// Host parsed from the dispatched URL.
        actual: String,
    },

    /// Candidate URL was not `https://`. Plain HTTP is rejected
    /// because cloud-control-plane endpoints require TLS.
    #[error("upstream scheme must be https, got {0:?}")]
    NonHttpsScheme(String),
}

/// Validate that `url` points at the expected
/// [`CloudUpstreamHost`] over HTTPS. Used by the shared HTTP
/// client at every dispatch as defence in depth, and as a
/// constructor-time check on operator-declared exchange URLs.
///
/// Returns `Ok(())` only when:
///
/// * The URL parses through `url::Url::parse`.
/// * The scheme is exactly `https`.
/// * The host (after lowercase + trailing-dot strip) equals
///   `expected.host()`.
///
/// All other cases fail closed with a structured
/// [`AllowlistError`].
pub fn validate_upstream_url(
    expected: &CloudUpstreamHost,
    url: &str,
) -> Result<(), AllowlistError> {
    let parsed = url::Url::parse(url).map_err(|e| AllowlistError::MalformedUrl(e.to_string()))?;
    if parsed.scheme() != "https" {
        return Err(AllowlistError::NonHttpsScheme(parsed.scheme().to_owned()));
    }
    let host = parsed
        .host_str()
        .ok_or_else(|| AllowlistError::MalformedUrl("URL has no host".to_owned()))?;
    if !expected.matches(host) {
        return Err(AllowlistError::HostMismatch {
            expected: expected.host().to_owned(),
            actual: host.to_owned(),
        });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aws_global_constructs() {
        let h = CloudUpstreamHost::aws_global();
        assert_eq!(h.host(), "sts.amazonaws.com");
        assert_eq!(h.provider(), CloudProvider::Aws);
        assert_eq!(h.https_base(), "https://sts.amazonaws.com");
    }

    #[test]
    fn aws_regional_constructs_for_known_region() {
        let h = CloudUpstreamHost::aws_regional("us-east-1").unwrap();
        assert_eq!(h.host(), "sts.us-east-1.amazonaws.com");
    }

    #[test]
    fn aws_regional_is_case_insensitive() {
        let h = CloudUpstreamHost::aws_regional("US-EAST-1").unwrap();
        assert_eq!(h.host(), "sts.us-east-1.amazonaws.com");
    }

    #[test]
    fn aws_regional_rejects_unknown_region() {
        let err = CloudUpstreamHost::aws_regional("zz-north-99").unwrap_err();
        assert!(matches!(err, AllowlistError::UnknownAwsRegion(ref r) if r == "zz-north-99"));
    }

    #[test]
    fn aws_regional_rejects_empty_region() {
        let err = CloudUpstreamHost::aws_regional("").unwrap_err();
        assert!(matches!(err, AllowlistError::EmptyAwsRegion));
    }

    #[test]
    fn gcp_and_azure_construct() {
        assert_eq!(
            CloudUpstreamHost::gcp_oauth2().host(),
            "oauth2.googleapis.com"
        );
        assert_eq!(
            CloudUpstreamHost::azure_login().host(),
            "login.microsoftonline.com"
        );
    }

    #[test]
    fn matches_is_case_insensitive_and_dot_tolerant() {
        let h = CloudUpstreamHost::gcp_oauth2();
        assert!(h.matches("oauth2.googleapis.com"));
        assert!(h.matches("OAUTH2.GoogleAPIs.com"));
        assert!(h.matches("oauth2.googleapis.com."));
        assert!(!h.matches("evil.googleapis.com"));
        assert!(!h.matches("oauth2.googleapis.com.evil.example"));
    }

    #[test]
    fn validate_upstream_url_accepts_correct_host_and_scheme() {
        let h = CloudUpstreamHost::aws_regional("us-east-1").unwrap();
        validate_upstream_url(&h, "https://sts.us-east-1.amazonaws.com/").unwrap();
        validate_upstream_url(&h, "https://sts.us-east-1.amazonaws.com/path?q=1").unwrap();
    }

    #[test]
    fn validate_upstream_url_rejects_http() {
        let h = CloudUpstreamHost::aws_global();
        let err = validate_upstream_url(&h, "http://sts.amazonaws.com/").unwrap_err();
        assert!(matches!(err, AllowlistError::NonHttpsScheme(ref s) if s == "http"));
    }

    #[test]
    fn validate_upstream_url_rejects_wrong_host() {
        let h = CloudUpstreamHost::aws_global();
        let err = validate_upstream_url(&h, "https://attacker.example/").unwrap_err();
        assert!(matches!(err, AllowlistError::HostMismatch { .. }));
    }

    #[test]
    fn validate_upstream_url_rejects_malformed() {
        let h = CloudUpstreamHost::aws_global();
        let err = validate_upstream_url(&h, "not a url at all").unwrap_err();
        assert!(matches!(err, AllowlistError::MalformedUrl(_)));
    }

    #[test]
    fn aws_regions_constant_is_nontrivial() {
        // Bake a smoke check so a future refactor that empties
        // the constant fails this test.
        assert!(AWS_REGIONS.len() >= 20);
        assert!(AWS_REGIONS.contains(&"us-east-1"));
        assert!(AWS_REGIONS.contains(&"eu-west-1"));
    }
}

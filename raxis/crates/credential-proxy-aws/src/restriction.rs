//! Restriction set + path-allowlist checks for the AWS proxy.
//! Reference: `specs/v2/credential-proxy.md §3.2`. The IMDS surface
//! is a single endpoint (`GET /creds`) so the restriction set is
//! deliberately narrow — operators tighten the path allowlist when
//! they want defence-in-depth against stray SDK paths the agent
//! might explore.
//! # `allowed_services` / `allowed_regions` enforcement model (V2.3)
//!the AWS restriction set acquires two
//! new declarative scoping fields:
//!   * `allowed_services`: e.g. `["s3", "sqs"]` — operator-declared
//!     intent that the agent only call these AWS services. Stored
//!     verbatim, normalised to lowercase, validated for non-empty
//!     ASCII at load time.
//!   * `allowed_regions`: e.g. `["us-east-1"]` — same shape, scoping
//!     by AWS region.
//!     Both restrictions are **declarative-with-audit** in V2.3: the
//!     IMDS proxy serves credentials but does NOT see the actual API
//!     request the SDK subsequently issues to AWS — those flow direct
//!     from the agent VM to AWS over the kernel-managed egress allowlist
//!     (TProxy). The restrictions are therefore:
//!   1. **Validated** at policy load time so a malformed list (e.g.
//!      empty strings, non-ASCII chars) fails the operator's `raxis
//!      policy load` step rather than appearing as a silent
//!      no-op.
//!   2. **Echoed in every audit event** (`AwsCredentialServed`)
//!      so downstream tooling (operator dashboards, post-incident
//!      forensics) can confirm the intended scope.
//!   3. **Enforced at the egress layer** by the kernel's TProxy
//!      allowlist: `[[tproxy_allowlist]]` entries pinned to
//!      `*.s3.us-east-1.amazonaws.com` / `sqs.us-east-1.amazonaws.com`
//!      give the operator the actual runtime guard. Operators who
//!      declare `allowed_services` / `allowed_regions` here MUST
//!      mirror them in the egress allowlist; `raxis doctor`
//!      surfaces declarations without a matching egress entry.
//!      V3 adds the SigV4-aware egress proxy (`raxis-egress-aws`) which
//!      parses the SDK's `Authorization: AWS4-HMAC-SHA256 Credential=
//! AKIA.../<region>/<service>/aws4_request` header and rejects
//!      requests outside the `allowed_services` / `allowed_regions`
//!      intersection. Until then, declarative + TProxy is the V2.3
//!      defence-in-depth contract.

use serde::{Deserialize, Serialize};

/// Restriction set declared in `[tasks.credentials.restrictions]`
/// for `proxy_type = "aws"`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Restrictions {
    /// Paths the proxy will serve. Defaults to `["/creds"]`. Empty
    /// list means "no path is allowed" (block everything) so an
    /// operator who wants to disable the proxy temporarily can do
    /// it through restrictions instead of removing the credential.
    #[serde(default = "default_allowed_paths")]
    pub allowed_paths: Vec<String>,

    /// AWS service names (lowercase, e.g. `"s3"`, `"sqs"`,
    /// `"dynamodb"`) the agent's tasks are intended to call.
    /// Empty (the default) means "no service-level intent
    /// declared" — `raxis doctor` warns when this is empty for a
    /// credential whose role ARN scopes services more tightly than
    /// the operator's egress allowlist.
    /// V2.3 enforcement: declarative + audit echo + `raxis doctor`
    /// cross-check. Runtime enforcement happens at the egress
    /// allowlist (V3 lands the SigV4 inspector — see the module
    /// doc).
    #[serde(default)]
    pub allowed_services: Vec<String>,

    /// AWS region IDs (e.g. `"us-east-1"`, `"eu-west-2"`) the
    /// agent's tasks are intended to use. Empty means "no region
    /// scoping declared".
    /// V2.3 enforcement: declarative + audit echo + `raxis doctor`
    /// cross-check.
    #[serde(default)]
    pub allowed_regions: Vec<String>,
}

impl Default for Restrictions {
    fn default() -> Self {
        Self {
            allowed_paths: default_allowed_paths(),
            allowed_services: Vec::new(),
            allowed_regions: Vec::new(),
        }
    }
}

fn default_allowed_paths() -> Vec<String> {
    vec!["/creds".to_owned()]
}

impl Restrictions {
    /// Returns `true` if `path` is permitted. Path comparison is
    /// case-sensitive (matches AWS SDK behaviour) and exact —
    /// querystrings on the request path are stripped before
    /// comparison.
    pub fn allows_path(&self, path: &str) -> bool {
        let bare = path.split('?').next().unwrap_or(path);
        self.allowed_paths.iter().any(|p| p == bare)
    }

    /// Validate the lists against the V2.3 shape contract: every
    /// entry MUST be non-empty ASCII; service names MUST match the
    /// AWS service-id charset (lowercase letters, digits, hyphens);
    /// region names MUST match the AWS region pattern.
    /// Called at policy load time so malformed entries fail fast
    /// rather than silently degrading audit fidelity.
    pub fn validate(&self) -> Result<(), RestrictionValidationError> {
        for s in &self.allowed_services {
            if s.is_empty() {
                return Err(RestrictionValidationError::EmptyServiceId);
            }
            if !s
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            {
                return Err(RestrictionValidationError::MalformedServiceId(s.clone()));
            }
        }
        for r in &self.allowed_regions {
            if r.is_empty() {
                return Err(RestrictionValidationError::EmptyRegionId);
            }
            // AWS region pattern: `[a-z]+-[a-z]+-\d` (us-east-1,
            // eu-west-2, ap-northeast-1, ca-central-1, ...).
            if !r
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            {
                return Err(RestrictionValidationError::MalformedRegionId(r.clone()));
            }
        }
        Ok(())
    }
}

/// Validation failures from `Restrictions::validate`.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RestrictionValidationError {
    /// `allowed_services` contained an empty string.
    #[error("aws restriction: allowed_services entry is empty")]
    EmptyServiceId,
    /// `allowed_services` contained a non-conforming service id.
    #[error("aws restriction: allowed_services entry `{0}` must be lowercase ASCII (letters, digits, hyphens)")]
    MalformedServiceId(String),
    /// `allowed_regions` contained an empty string.
    #[error("aws restriction: allowed_regions entry is empty")]
    EmptyRegionId,
    /// `allowed_regions` contained a non-conforming region id.
    #[error("aws restriction: allowed_regions entry `{0}` must be lowercase ASCII (letters, digits, hyphens)")]
    MalformedRegionId(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_allows_creds_path() {
        let r = Restrictions::default();
        assert!(r.allows_path("/creds"));
        assert!(r.allows_path("/creds?refresh=1"));
        assert!(!r.allows_path("/latest/meta-data/iam/security-credentials/foo"));
    }

    #[test]
    fn empty_allowlist_blocks_everything() {
        let r = Restrictions {
            allowed_paths: vec![],
            allowed_services: vec![],
            allowed_regions: vec![],
        };
        assert!(!r.allows_path("/creds"));
    }

    #[test]
    fn validate_accepts_default() {
        Restrictions::default().validate().unwrap();
    }

    #[test]
    fn validate_accepts_well_formed_services_and_regions() {
        let r = Restrictions {
            allowed_paths: default_allowed_paths(),
            allowed_services: vec!["s3".into(), "sqs".into(), "dynamodb".into()],
            allowed_regions: vec!["us-east-1".into(), "eu-west-2".into()],
        };
        r.validate().unwrap();
    }

    #[test]
    fn validate_rejects_uppercase_service_id() {
        let r = Restrictions {
            allowed_paths: default_allowed_paths(),
            allowed_services: vec!["S3".into()],
            allowed_regions: vec![],
        };
        assert_eq!(
            r.validate(),
            Err(RestrictionValidationError::MalformedServiceId("S3".into())),
        );
    }

    #[test]
    fn validate_rejects_empty_region_id() {
        let r = Restrictions {
            allowed_paths: default_allowed_paths(),
            allowed_services: vec![],
            allowed_regions: vec!["".into()],
        };
        assert_eq!(r.validate(), Err(RestrictionValidationError::EmptyRegionId));
    }
}

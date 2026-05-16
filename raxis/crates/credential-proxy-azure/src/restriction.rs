//! Restriction set for the Azure IMDS proxy.
//! Reference: `specs/v2/credential-proxy.md §3.4`. Azure's IMDS
//! endpoint mints scoped tokens — one resource URI per call. The
//! restriction surface is therefore not a path allowlist (the wire
//! path is fixed) but a *resource* allowlist. The proxy refuses to
//! mint tokens for resources outside `allowed_resources` even when
//! the agent passes `?resource=<arbitrary-uri>` to the IMDS endpoint.
//! # Per-resource action filtering (V2.3)
//!Azure's restriction set acquires a
//! per-resource `allowed_actions` table. The Azure access-token
//! response carries a `xms_action` claim that the SDKs check
//! before issuing the actual API call (e.g. ARM Resource Manager
//! reads `Microsoft.Storage/storageAccounts/read`). V2.3 ships a
//! declarative variant of this filter:
//!   * `allowed_actions`: a `(resource, action)` pair list. When
//!     present and non-empty for a given `resource`, the proxy
//!     adds an `x-ms-allowed-actions` header to the token
//!     response (as a JSON array). Azure SDKs do not block on this
//!     header in V2.3 — runtime enforcement requires the V3
//!     ARM-aware egress proxy that parses outbound REST URLs and
//!     matches them against the action vocabulary.
//! Behaviour summary:
//!   * `allowed_resources` is the **mandatory** gate: a request
//!     for a resource not in the list gets `400 Bad Request`.
//!   * `allowed_actions` is **declarative + audit echo**: the
//!     proxy records the operator-declared scope in
//!     `AzureTokenServed.allowed_actions` so reviewers can confirm
//!     intent. Runtime gating happens at the egress proxy in V3.

use serde::{Deserialize, Serialize};

/// Restriction set declared in `[tasks.credentials.restrictions]`
/// for `proxy_type = "azure"`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Restrictions {
    /// Azure resource URIs (e.g. `"https://management.azure.com/"`,
    /// `"https://database.windows.net/"`) the proxy will mint tokens
    /// for. Empty list means "no resource is allowed" (block
    /// everything) so an operator can disable a credential through
    /// restrictions.
    #[serde(default)]
    pub allowed_resources: Vec<String>,

    /// Per-resource action vocabulary. Each entry pins a
    /// resource URI to the set of ARM action verbs the agent's
    /// task is intended to perform (e.g.
    /// `Microsoft.Storage/storageAccounts/read`). Empty means
    /// "no action-level intent declared". V2.3 enforcement is
    /// declarative + audit echo; V3 lands runtime ARM-URL gating.
    #[serde(default)]
    pub allowed_actions: Vec<ResourceActions>,
}

/// One `(resource, [action, action, ...])` association in
/// `allowed_actions`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceActions {
    /// Azure resource URI this action set applies to. MUST appear
    /// (modulo trailing slash) in the parent restriction's
    /// `allowed_resources`; mismatched entries are rejected at
    /// `validate()` time so a typo can't silently disable
    /// declarative enforcement.
    pub resource: String,
    /// ARM action verbs (e.g.
    /// `["Microsoft.Storage/storageAccounts/read",
    ///   "Microsoft.Storage/storageAccounts/listKeys/action"]`).
    /// Empty list means "no actions declared for this resource"
    /// operationally equivalent to omitting the entry; allowed
    /// for forward-compatibility with operators who want to
    /// enumerate the resource without scoping its actions.
    #[serde(default)]
    pub actions: Vec<String>,
}

impl Restrictions {
    /// Returns `true` if `resource` is permitted. The comparison
    /// matches Azure's behaviour where a request `resource` of
    /// `https://management.azure.com` is treated identically to
    /// `https://management.azure.com/` — the trailing slash is
    /// optional. We strip the trailing slash on both sides before
    /// the equality check.
    pub fn allows_resource(&self, resource: &str) -> bool {
        let want = resource.trim_end_matches('/');
        self.allowed_resources
            .iter()
            .any(|p| p.trim_end_matches('/') == want)
    }

    /// Look up the action vocabulary the operator declared for
    /// `resource`. Returns the matching list verbatim, or `None`
    /// when the operator declared no actions for this resource.
    pub fn actions_for(&self, resource: &str) -> Option<&[String]> {
        let want = resource.trim_end_matches('/');
        self.allowed_actions
            .iter()
            .find(|ra| ra.resource.trim_end_matches('/') == want)
            .map(|ra| ra.actions.as_slice())
    }

    /// Validate the V2.3 declarative shape: every
    /// `allowed_actions` entry's `resource` MUST appear in
    /// `allowed_resources`. Action verbs MUST be non-empty
    /// ASCII (the ARM action namespace uses `Provider/<segments>`
    /// with `/`, `.`, lowercase letters, digits, and `_`).
    pub fn validate(&self) -> Result<(), RestrictionValidationError> {
        for ra in &self.allowed_actions {
            if !self.allows_resource(&ra.resource) {
                return Err(RestrictionValidationError::ActionResourceNotInAllowed(
                    ra.resource.clone(),
                ));
            }
            for a in &ra.actions {
                if a.is_empty() {
                    return Err(RestrictionValidationError::EmptyAction(ra.resource.clone()));
                }
                if !a.bytes().all(|b| {
                    b.is_ascii_alphanumeric() || b == b'.' || b == b'/' || b == b'_' || b == b'-'
                }) {
                    return Err(RestrictionValidationError::MalformedAction {
                        resource: ra.resource.clone(),
                        action: a.clone(),
                    });
                }
            }
        }
        Ok(())
    }
}

/// Validation failures from `Restrictions::validate`.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RestrictionValidationError {
    /// An entry in `allowed_actions` referenced a resource that
    /// was not in `allowed_resources` — a typo that would have
    /// silently disabled the declarative filter.
    #[error("azure restriction: allowed_actions resource `{0}` is not in allowed_resources")]
    ActionResourceNotInAllowed(String),
    /// `allowed_actions[].actions` contained an empty string.
    #[error("azure restriction: action for resource `{0}` is empty")]
    EmptyAction(String),
    /// `allowed_actions[].actions` contained a non-conforming verb.
    #[error("azure restriction: action `{action}` for resource `{resource}` is malformed (expected `Provider/Path[/segment]*`)")]
    MalformedAction {
        /// Resource URI the malformed action belonged to.
        resource: String,
        /// The malformed action verb.
        action: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn r_with(resources: &[&str]) -> Restrictions {
        Restrictions {
            allowed_resources: resources.iter().map(|s| (*s).to_owned()).collect(),
            allowed_actions: Vec::new(),
        }
    }

    #[test]
    fn equality_normalises_trailing_slash() {
        let r = r_with(&["https://management.azure.com/"]);
        assert!(r.allows_resource("https://management.azure.com/"));
        assert!(r.allows_resource("https://management.azure.com"));
        assert!(!r.allows_resource("https://management.azure.com/.default"));
    }

    #[test]
    fn empty_allowlist_blocks_everything() {
        let r = r_with(&[]);
        assert!(!r.allows_resource("https://management.azure.com/"));
    }

    #[test]
    fn distinct_resources_are_independent() {
        let r = r_with(&["https://database.windows.net/"]);
        assert!(!r.allows_resource("https://management.azure.com/"));
        assert!(r.allows_resource("https://database.windows.net/"));
    }

    #[test]
    fn actions_for_returns_declared_set() {
        let r = Restrictions {
            allowed_resources: vec!["https://management.azure.com/".into()],
            allowed_actions: vec![ResourceActions {
                resource: "https://management.azure.com/".into(),
                actions: vec![
                    "Microsoft.Storage/storageAccounts/read".into(),
                    "Microsoft.Storage/storageAccounts/listKeys/action".into(),
                ],
            }],
        };
        assert_eq!(
            r.actions_for("https://management.azure.com"),
            Some(
                &[
                    "Microsoft.Storage/storageAccounts/read".to_owned(),
                    "Microsoft.Storage/storageAccounts/listKeys/action".to_owned(),
                ][..]
            ),
        );
        assert_eq!(r.actions_for("https://database.windows.net/"), None);
    }

    #[test]
    fn validate_rejects_action_resource_not_in_allowed_resources() {
        let r = Restrictions {
            allowed_resources: vec!["https://management.azure.com/".into()],
            allowed_actions: vec![ResourceActions {
                resource: "https://database.windows.net/".into(),
                actions: vec!["Microsoft.Sql/servers/read".into()],
            }],
        };
        assert_eq!(
            r.validate(),
            Err(RestrictionValidationError::ActionResourceNotInAllowed(
                "https://database.windows.net/".into(),
            )),
        );
    }

    #[test]
    fn validate_accepts_default() {
        Restrictions::default().validate().unwrap();
    }

    #[test]
    fn validate_accepts_well_formed_actions() {
        let r = Restrictions {
            allowed_resources: vec!["https://management.azure.com/".into()],
            allowed_actions: vec![ResourceActions {
                resource: "https://management.azure.com/".into(),
                actions: vec![
                    "Microsoft.Storage/storageAccounts/read".into(),
                    "Microsoft.Storage/storageAccounts/listKeys/action".into(),
                ],
            }],
        };
        r.validate().unwrap();
    }
}

//! Restriction set for the Azure IMDS proxy.
//!
//! Reference: `specs/v2/credential-proxy.md §3.4`. Azure's IMDS
//! endpoint mints scoped tokens — one resource URI per call. The
//! restriction surface is therefore not a path allowlist (the wire
//! path is fixed) but a *resource* allowlist. The proxy refuses to
//! mint tokens for resources outside `allowed_resources` even when
//! the agent passes `?resource=<arbitrary-uri>` to the IMDS endpoint.

use serde::{Deserialize, Serialize};

/// Restriction set declared in `[tasks.credentials.restrictions]`
/// for `proxy_type = "azure"`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Restrictions {
    /// Azure resource URIs (e.g. `"https://management.azure.com/"`,
    /// `"https://database.windows.net/"`) the proxy will mint tokens
    /// for. Empty list means "no resource is allowed" (block
    /// everything) so an operator can disable a credential through
    /// restrictions.
    #[serde(default)]
    pub allowed_resources: Vec<String>,
}

impl Default for Restrictions {
    fn default() -> Self {
        Self { allowed_resources: Vec::new() }
    }
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
        self.allowed_resources.iter()
            .any(|p| p.trim_end_matches('/') == want)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn equality_normalises_trailing_slash() {
        let r = Restrictions { allowed_resources: vec![
            "https://management.azure.com/".to_owned(),
        ]};
        assert!(r.allows_resource("https://management.azure.com/"));
        assert!(r.allows_resource("https://management.azure.com"));
        assert!(!r.allows_resource("https://management.azure.com/.default"));
    }

    #[test]
    fn empty_allowlist_blocks_everything() {
        let r = Restrictions { allowed_resources: vec![] };
        assert!(!r.allows_resource("https://management.azure.com/"));
    }

    #[test]
    fn distinct_resources_are_independent() {
        let r = Restrictions { allowed_resources: vec![
            "https://database.windows.net/".to_owned(),
        ]};
        assert!(!r.allows_resource("https://management.azure.com/"));
        assert!(r.allows_resource("https://database.windows.net/"));
    }
}

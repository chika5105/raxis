//! Restriction set + path-allowlist checks for the AWS proxy.
//!
//! Reference: `specs/v2/credential-proxy.md §3.2`. The IMDS surface
//! is a single endpoint (`GET /creds`) so the restriction set is
//! deliberately narrow — operators tighten the path allowlist when
//! they want defence-in-depth against stray SDK paths the agent
//! might explore.

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
}

impl Default for Restrictions {
    fn default() -> Self {
        Self { allowed_paths: default_allowed_paths() }
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
        let r = Restrictions { allowed_paths: vec![] };
        assert!(!r.allows_path("/creds"));
    }
}

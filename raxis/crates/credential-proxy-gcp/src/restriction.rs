//! Restriction set for the GCP metadata-server proxy.
//!
//! Reference: `specs/v2/credential-proxy.md §3.3`. The GCP metadata
//! server exposes a small set of well-known paths under
//! `/computeMetadata/v1/...`. The default allowlist covers exactly
//! the four endpoints `google-auth-library` and `gcloud auth
//! application-default print-access-token` walk through:
//!
//!   * `/computeMetadata/v1/instance/service-accounts/default/token`
//!   * `/computeMetadata/v1/instance/service-accounts/default/email`
//!   * `/computeMetadata/v1/project/project-id`
//!   * `/computeMetadata/v1/project/numeric-project-id`
//!
//! Operators tighten the allowlist when a task should only ever need
//! the access token (e.g. a Cloud Storage migration that has no
//! reason to read project metadata).

use serde::{Deserialize, Serialize};

/// Restriction set declared in `[tasks.credentials.restrictions]`
/// for `proxy_type = "gcp"`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Restrictions {
    /// Paths the proxy will serve. Defaults to the four canonical
    /// metadata-server endpoints. Empty list means "block everything".
    #[serde(default = "default_allowed_paths")]
    pub allowed_paths: Vec<String>,
}

impl Default for Restrictions {
    fn default() -> Self {
        Self { allowed_paths: default_allowed_paths() }
    }
}

fn default_allowed_paths() -> Vec<String> {
    vec![
        "/computeMetadata/v1/instance/service-accounts/default/token".to_owned(),
        "/computeMetadata/v1/instance/service-accounts/default/email".to_owned(),
        "/computeMetadata/v1/project/project-id".to_owned(),
        "/computeMetadata/v1/project/numeric-project-id".to_owned(),
    ]
}

impl Restrictions {
    /// Returns `true` if `path` is permitted. Path comparison is
    /// case-sensitive (matches GCP metadata-server behaviour) and
    /// exact — querystrings on the request path are stripped before
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
    fn default_allows_canonical_endpoints() {
        let r = Restrictions::default();
        assert!(r.allows_path("/computeMetadata/v1/instance/service-accounts/default/token"));
        assert!(r.allows_path("/computeMetadata/v1/instance/service-accounts/default/email"));
        assert!(r.allows_path("/computeMetadata/v1/project/project-id"));
        assert!(r.allows_path("/computeMetadata/v1/project/numeric-project-id"));
        assert!(!r.allows_path("/computeMetadata/v1/instance/network-interfaces"));
    }

    #[test]
    fn querystring_is_stripped_before_match() {
        let r = Restrictions::default();
        assert!(r.allows_path("/computeMetadata/v1/project/project-id?recursive=true"));
    }

    #[test]
    fn empty_allowlist_blocks_everything() {
        let r = Restrictions { allowed_paths: vec![] };
        assert!(!r.allows_path("/computeMetadata/v1/project/project-id"));
    }
}

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
//!
//! # `allowed_scopes` / `project` pinning enforcement model (V2.3)
//!
//! Per `V2_GAPS.md §9 Phase 2` the GCP restriction set acquires
//! two declarative scoping fields:
//!
//!   * `allowed_scopes`: e.g.
//!     `["https://www.googleapis.com/auth/devstorage.read_only"]`
//!     — operator-declared OAuth scope intent. Stored verbatim,
//!     validated for `https://` URI shape at load time.
//!   * `project`: e.g. `"my-staging-project"` — the GCP project
//!     ID the agent's tasks are intended to operate on. The
//!     proxy already has a `project_id` in `ProxyConfig` (from
//!     `ProxyDecl::Gcp::project`); when this field is non-empty
//!     the proxy enforces a hard match between
//!     `restrictions.project` and `config.project_id` at bind
//!     time so a misconfigured proxy fails fast rather than
//!     serving the wrong project's metadata.
//!
//! Both restrictions are enforced as follows:
//!
//!   1. **Validated at policy load time**: scope URIs MUST start
//!      with `https://`; project IDs MUST match GCP's
//!      `[a-z][-a-z0-9]{4,28}[a-z0-9]` shape (a relaxed shape is
//!      accepted: lowercase ASCII + digits + hyphens).
//!   2. **Echoed in every audit event** (`GcpMetadataServed`)
//!      so post-incident forensics observes the declared scope.
//!   3. **Filtered into the OAuth token response**: when the
//!      agent's request is for the `.../token` path, the proxy
//!      narrows the response's `scope` field to the
//!      intersection of the credential's actual scopes and the
//!      operator-declared `allowed_scopes`. Scopes outside the
//!      declared set are removed before the response leaves the
//!      proxy. (V2.3 only emits the declared list verbatim;
//!      the V3 path forwards through the GCP token-exchange API
//!      to mint genuinely scope-narrowed tokens.)

use serde::{Deserialize, Serialize};

/// Restriction set declared in `[tasks.credentials.restrictions]`
/// for `proxy_type = "gcp"`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Restrictions {
    /// Paths the proxy will serve. Defaults to the four canonical
    /// metadata-server endpoints. Empty list means "block everything".
    #[serde(default = "default_allowed_paths")]
    pub allowed_paths: Vec<String>,

    /// OAuth scopes the operator declares the agent will use
    /// (e.g.
    /// `"https://www.googleapis.com/auth/devstorage.read_only"`).
    /// V2.3 echoes these in the audit chain and uses the list to
    /// narrow the token response's `scope` field. Empty (the
    /// default) means "no scope-level intent declared" — the
    /// proxy returns the credential's full scope set.
    #[serde(default)]
    pub allowed_scopes: Vec<String>,

    /// GCP project ID the agent's tasks are intended to operate
    /// on (e.g. `"my-staging-project"`). When non-empty the
    /// proxy bind step asserts equality with the proxy's
    /// configured `project_id` (from `ProxyDecl::Gcp::project`).
    /// Empty means "no project pinning declared" — backwards-
    /// compatible with operators who used the `ProxyDecl`'s
    /// `project` field alone.
    #[serde(default)]
    pub project: String,
}

impl Default for Restrictions {
    fn default() -> Self {
        Self {
            allowed_paths:  default_allowed_paths(),
            allowed_scopes: Vec::new(),
            project:        String::new(),
        }
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

    /// Validate the V2.3 declarative shape: `allowed_scopes`
    /// entries MUST start with `https://`; `project` MUST be the
    /// GCP project-id charset (lowercase + digits + hyphens) when
    /// non-empty.
    pub fn validate(&self) -> Result<(), RestrictionValidationError> {
        for s in &self.allowed_scopes {
            if !s.starts_with("https://") {
                return Err(RestrictionValidationError::MalformedScope(s.clone()));
            }
        }
        if !self.project.is_empty()
            && !self.project.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return Err(RestrictionValidationError::MalformedProject(self.project.clone()));
        }
        Ok(())
    }
}

/// Validation failures from `Restrictions::validate`.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RestrictionValidationError {
    /// `allowed_scopes` entry did not start with `https://`.
    #[error("gcp restriction: allowed_scopes entry `{0}` must start with https://")]
    MalformedScope(String),
    /// `project` was non-empty but not lowercase ASCII / digits / hyphens.
    #[error("gcp restriction: project `{0}` must be lowercase ASCII (letters, digits, hyphens)")]
    MalformedProject(String),
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
        let r = Restrictions {
            allowed_paths:  vec![],
            allowed_scopes: vec![],
            project:        String::new(),
        };
        assert!(!r.allows_path("/computeMetadata/v1/project/project-id"));
    }

    #[test]
    fn validate_accepts_default() {
        Restrictions::default().validate().unwrap();
    }

    #[test]
    fn validate_accepts_well_formed_scopes_and_project() {
        let r = Restrictions {
            allowed_paths:  default_allowed_paths(),
            allowed_scopes: vec![
                "https://www.googleapis.com/auth/devstorage.read_only".into(),
                "https://www.googleapis.com/auth/cloud-platform".into(),
            ],
            project:        "my-staging-1".into(),
        };
        r.validate().unwrap();
    }

    #[test]
    fn validate_rejects_non_https_scope() {
        let r = Restrictions {
            allowed_paths:  default_allowed_paths(),
            allowed_scopes: vec!["http://insecure.example/auth".into()],
            project:        String::new(),
        };
        assert_eq!(
            r.validate(),
            Err(RestrictionValidationError::MalformedScope(
                "http://insecure.example/auth".into(),
            )),
        );
    }

    #[test]
    fn validate_rejects_uppercase_project() {
        let r = Restrictions {
            allowed_paths:  default_allowed_paths(),
            allowed_scopes: vec![],
            project:        "My-Project".into(),
        };
        assert_eq!(
            r.validate(),
            Err(RestrictionValidationError::MalformedProject(
                "My-Project".into(),
            )),
        );
    }
}

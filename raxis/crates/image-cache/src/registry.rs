//! `RegistryRef` — opaque registry handle the kernel passes as a
//! hint into [`ImageResolver::resolve`](crate::ImageResolver::resolve).
//!
//! The skeleton iteration treats this as a value type. The
//! production iteration (per `image-cache.md §10`) will extend it
//! with credential alias plumbing tied to the operator-policy
//! credential plane (`credential-proxy.md`).

use serde::{Deserialize, Serialize};

/// Identifies an OCI registry endpoint and repository path. Does
/// NOT carry credentials; those resolve via the operator-policy
/// credential plane (the `auth = "alias"` field in
/// `[[vm_images]]`, mapped through `[[vm_image_credentials]]`).
///
/// Format follows the Docker / OCI distribution convention:
///
/// * `host` — registry host (`ghcr.io`, `quay.io`,
///   `registry-1.docker.io`, an internal registry FQDN).
/// * `repository` — slash-separated repository name
///   (`operator/raxis-rust`, `library/python`).
///
/// The `tag` is intentionally NOT carried here: V2 resolves
/// strictly by digest, never by tag (per `v2-deep-spec.md
/// §1.6` "Why OCI digest pinning, not just tags").
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RegistryRef {
    /// Registry host. Must be a non-empty FQDN; the resolver does
    /// NOT validate DNS resolvability at construction time.
    pub host: String,
    /// Slash-separated repository path. Must be non-empty; the
    /// resolver does NOT validate the path against the registry's
    /// own naming rules at construction time.
    pub repository: String,
}

impl RegistryRef {
    /// Construct from owned strings. Both inputs must be non-empty
    /// or [`RegistryRefError::Empty`] is returned.
    pub fn new(
        host: impl Into<String>,
        repository: impl Into<String>,
    ) -> Result<Self, RegistryRefError> {
        let host = host.into();
        let repository = repository.into();
        if host.is_empty() || repository.is_empty() {
            return Err(RegistryRefError::Empty);
        }
        Ok(Self { host, repository })
    }
}

/// Construction failures for [`RegistryRef::new`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RegistryRefError {
    /// `host` or `repository` was the empty string. Caught here
    /// rather than at registry-call time so a malformed policy
    /// entry surfaces at admission rather than at session-spawn.
    #[error("registry host and repository must both be non-empty")]
    Empty,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_accepts_non_empty_inputs() {
        let r = RegistryRef::new("ghcr.io", "operator/raxis-rust").unwrap();
        assert_eq!(r.host, "ghcr.io");
        assert_eq!(r.repository, "operator/raxis-rust");
    }

    #[test]
    fn new_rejects_empty_host() {
        assert_eq!(
            RegistryRef::new("", "operator/raxis-rust").unwrap_err(),
            RegistryRefError::Empty,
        );
    }

    #[test]
    fn new_rejects_empty_repository() {
        assert_eq!(
            RegistryRef::new("ghcr.io", "").unwrap_err(),
            RegistryRefError::Empty,
        );
    }

    #[test]
    fn round_trip_via_serde_json() {
        let r = RegistryRef::new("ghcr.io", "op/r").unwrap();
        let s = serde_json::to_string(&r).unwrap();
        let r2: RegistryRef = serde_json::from_str(&s).unwrap();
        assert_eq!(r, r2);
    }
}

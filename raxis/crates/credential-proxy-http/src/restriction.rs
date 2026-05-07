//! Restriction set for the HTTP credential proxy.
//!
//! Reference: `specs/v2/credential-proxy.md §3.5` "HTTP Audit-Only
//! Mode" and §3.1 (k8s) for `allowed_methods` examples.

use serde::{Deserialize, Serialize};

/// Restriction set declared in `[tasks.credentials.restrictions]`.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Restrictions {
    /// Methods the proxy will forward. Empty vector = unrestricted
    /// (every method passes). Match is case-insensitive.
    #[serde(default)]
    pub allowed_methods: Vec<String>,
    /// Path prefixes the proxy will forward. Empty vector =
    /// unrestricted.
    #[serde(default)]
    pub allowed_path_prefixes: Vec<String>,
}

impl Restrictions {
    /// Convenience constructor: read-only HTTP (GET + HEAD).
    pub fn read_only() -> Self {
        Self {
            allowed_methods: vec!["GET".to_owned(), "HEAD".to_owned()],
            allowed_path_prefixes: vec![],
        }
    }

    /// Returns `true` if `method` is permitted by the policy.
    pub fn allows_method(&self, method: &str) -> bool {
        if self.allowed_methods.is_empty() {
            return true;
        }
        self.allowed_methods
            .iter()
            .any(|m| m.eq_ignore_ascii_case(method))
    }

    /// Returns `true` if `path` is permitted by the policy.
    pub fn allows_path(&self, path: &str) -> bool {
        if self.allowed_path_prefixes.is_empty() {
            return true;
        }
        self.allowed_path_prefixes.iter().any(|p| path.starts_with(p))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unrestricted_allows_everything() {
        let r = Restrictions::default();
        assert!(r.allows_method("GET"));
        assert!(r.allows_method("DELETE"));
        assert!(r.allows_path("/anything/at/all"));
    }

    #[test]
    fn read_only_blocks_writes() {
        let r = Restrictions::read_only();
        assert!( r.allows_method("GET"));
        assert!( r.allows_method("HEAD"));
        assert!( r.allows_method("get"));
        assert!(!r.allows_method("POST"));
        assert!(!r.allows_method("DELETE"));
    }

    #[test]
    fn path_prefix_filter() {
        let r = Restrictions {
            allowed_methods:        vec![],
            allowed_path_prefixes:  vec!["/api/v1/widgets".to_owned()],
        };
        assert!( r.allows_path("/api/v1/widgets"));
        assert!( r.allows_path("/api/v1/widgets/42"));
        assert!(!r.allows_path("/api/v1/users"));
    }
}

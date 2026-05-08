//! Restriction set + command-allowlist checks for the Redis proxy.
//!
//! Reference: `specs/v2/credential-proxy.md §3` ("Redis"). All
//! fields default to "unrestricted" so a minimal policy with
//! `[restrictions]` omitted produces a working proxy with no
//! command filtering (the upstream's own ACL provides the final
//! gate). Production deployments typically pin a tight allowlist
//! per `credential-proxy.md §3` guidance.

use serde::{Deserialize, Serialize};

/// Restriction set declared in `[tasks.credentials.restrictions]`
/// for `proxy_type = "redis"`.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Restrictions {
    /// Case-insensitive command allowlist. Empty list means "no
    /// restriction" (every non-AUTH command is forwarded).
    /// `AUTH` and `HELLO` are ALWAYS intercepted regardless of
    /// this list — they are part of the proxy's auth surface and
    /// never reach upstream.
    ///
    /// Typical values for an analytical workload:
    /// `["GET", "MGET", "EXISTS", "TYPE", "TTL", "PTTL"]`.
    /// For a write-allowed workload add `"SET", "DEL", "EXPIRE"`.
    #[serde(default)]
    pub allowed_commands: Vec<String>,
}

impl Restrictions {
    /// Returns `true` if `verb` (case-insensitive) is permitted
    /// by the current allowlist.
    pub fn allows_command(&self, verb: &str) -> bool {
        if self.allowed_commands.is_empty() {
            return true;
        }
        let upper = verb.to_ascii_uppercase();
        self.allowed_commands.iter().any(|c| c.eq_ignore_ascii_case(&upper))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_allowlist_permits_every_verb() {
        let r = Restrictions::default();
        assert!(r.allows_command("GET"));
        assert!(r.allows_command("FLUSHDB"));
    }

    #[test]
    fn non_empty_allowlist_is_case_insensitive() {
        let r = Restrictions { allowed_commands: vec!["GET".into(), "set".into()] };
        assert!(r.allows_command("get"));
        assert!(r.allows_command("Set"));
        assert!(!r.allows_command("DEL"));
    }
}

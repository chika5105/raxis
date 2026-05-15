// raxis-kernel::gates::policy_lookup — Maps touched paths to required claim types.
//
// Normative reference: kernel-core.md §2.3 `src/gates/policy_lookup.rs`.
//
// Declaration-order matching: first rule whose path_glob matches a path wins.
// No specificity sorting. Operator responsibility to order rules correctly.
// StrictDefault is returned for any path that matches no rule under default-deny.

use std::path::PathBuf;

use raxis_policy::PolicyBundle;
use raxis_types::SubmittedClaim;

use super::GateError;

// ---------------------------------------------------------------------------
// ClaimType — what kind of claim satisfies a gate requirement
// ---------------------------------------------------------------------------

/// A claim type required for a set of touched paths.
/// `StrictDefault` is returned when a path matches no rule under default-deny.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ClaimType {
    /// A named claim class from the policy table (e.g. "WriteCode").
    Named(String),
    /// Sentinel: path matched no rule and default_action = "deny".
    /// The planner has no claim class that satisfies this — intent is rejected.
    StrictDefault,
}

impl ClaimType {
    pub fn as_str(&self) -> &str {
        match self {
            ClaimType::Named(s) => s.as_str(),
            ClaimType::StrictDefault => "StrictDefault",
        }
    }
}

// ---------------------------------------------------------------------------
// required_claims
// ---------------------------------------------------------------------------

/// Return the deduplicated union of claim types required across all `paths`.
///
/// Per spec (kernel-core.md §2.3 `policy_lookup.rs`):
/// - Rules matched in declaration order; first match wins per path.
/// - `StrictDefault` appended for any path that matches no rule under deny.
/// - Returns `Err(GateError::PolicyMisconfigured)` if default_action is not
///   "permit" and all matched paths have empty claim_types (empty deny list =
///   operator config error).
pub fn required_claims(
    paths: &[PathBuf],
    policy: &PolicyBundle,
) -> Result<Vec<ClaimType>, GateError> {
    let rules = policy.claim_rules();
    let default_deny = policy.claim_default_action() != "permit";

    let mut result: std::collections::HashSet<ClaimType> = std::collections::HashSet::new();
    let mut any_unmatched = false;

    for path in paths {
        let path_str = path.to_string_lossy();
        let matched = rules
            .iter()
            .find(|rule| glob_matches(&rule.path_glob, &path_str));

        match matched {
            Some(rule) => {
                for ct in &rule.claim_types {
                    result.insert(ClaimType::Named(ct.clone()));
                }
            }
            None => {
                if default_deny {
                    any_unmatched = true;
                    result.insert(ClaimType::StrictDefault);
                }
                // Under permit: no claim required for unmatched path.
            }
        }
    }

    // Spec: if default_deny and result is empty after dedup (all matched paths
    // had empty claim_types) → misconfiguration.
    if default_deny && !any_unmatched && result.is_empty() {
        return Err(GateError::PolicyMisconfigured(
            "default_action=deny but all matched paths have empty claim_types".to_owned(),
        ));
    }

    let mut out: Vec<ClaimType> = result.into_iter().collect();
    out.sort_by_key(|ct| ct.as_str().to_owned());
    Ok(out)
}

// ---------------------------------------------------------------------------
// check_claim_scope
// ---------------------------------------------------------------------------

/// Verify that a submitted claim covers all `paths`.
///
/// Per spec (kernel-core.md §2.3 `policy_lookup.rs`):
///   Scope must be a superset — every path in `paths` must match the claim's
///   declared scope. In v1, scope is the `evidence_ref` field or derived from
///   the claim type's policy-allowed scope patterns.
///
/// Returns the list of paths NOT covered by the claim's scope.
/// An empty return means full coverage (claim passes scope check).
/// Used by `gates/claim.rs` to construct `ScopeInsufficient`.
pub fn check_claim_scope(
    claim: &SubmittedClaim,
    paths: &[PathBuf],
    _policy: &PolicyBundle,
) -> Vec<PathBuf> {
    // v1: scope check uses evidence_ref as a path-glob when present.
    // If evidence_ref is absent, the claim asserts global scope (all paths covered).
    let scope_glob = match &claim.evidence_ref {
        Some(s) => s.as_str(),
        None => "**",
    };
    paths
        .iter()
        .filter(|p| !glob_matches(scope_glob, &p.to_string_lossy()))
        .cloned()
        .collect()
}

// ---------------------------------------------------------------------------
// glob_matches — simple glob implementation
//
// Supports:
//   **   — any number of path segments (including zero)
//   *    — any sequence of non-separator chars within one segment
//   ?    — any single non-separator char
//   literal chars — exact match
// ---------------------------------------------------------------------------

/// Simple glob matcher supporting **, *, ? and literal chars.
/// - `**`  matches any sequence of characters including '/' (greedy, via backtracking)
/// - `*`   matches any sequence of non-'/' characters within one path segment
/// - `?`   matches any single non-'/' character
/// - literal chars match exactly
pub fn glob_matches(pattern: &str, path: &str) -> bool {
    glob_rec(pattern.as_bytes(), path.as_bytes())
}

fn glob_rec(pat: &[u8], s: &[u8]) -> bool {
    match (pat.first(), s.first()) {
        // Both exhausted.
        (None, None) => return true,
        // Pattern exhausted but path has chars left — only matches if remaining is empty.
        (None, Some(_)) => return false,
        // `**` — matches zero or more characters of any kind (including '/').
        (Some(b'*'), _) if pat.get(1) == Some(&b'*') => {
            // Consume the `**`.
            let rest_pat = &pat[2..];
            // Optionally consume a trailing separator in the pattern.
            let rest_pat = if rest_pat.first() == Some(&b'/') {
                &rest_pat[1..]
            } else {
                rest_pat
            };
            // Try matching rest_pat at every position in s (including current, i.e. ** matches empty).
            for i in 0..=s.len() {
                if glob_rec(rest_pat, &s[i..]) {
                    return true;
                }
            }
            return false;
        }
        // Single `*` — matches any run of non-'/' chars.
        (Some(b'*'), _) => {
            let rest_pat = &pat[1..];
            // Try matching rest_pat at each position until we hit '/' or end.
            let mut i = 0;
            loop {
                if glob_rec(rest_pat, &s[i..]) {
                    return true;
                }
                if i >= s.len() || s[i] == b'/' {
                    return false;
                }
                i += 1;
            }
        }
        // `?` — matches any single non-'/' char.
        (Some(b'?'), Some(sc)) if *sc != b'/' => {
            return glob_rec(&pat[1..], &s[1..]);
        }
        // Literal char match.
        (Some(pc), Some(sc)) if pc == sc => {
            return glob_rec(&pat[1..], &s[1..]);
        }
        // No match.
        _ => return false,
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn glob_exact_match() {
        assert!(glob_matches("src/main.rs", "src/main.rs"));
    }

    #[test]
    fn glob_star_star() {
        assert!(glob_matches("src/**", "src/kernel/main.rs"));
        assert!(glob_matches("src/**", "src/main.rs"));
        assert!(!glob_matches("src/**", "tests/main.rs"));
    }

    #[test]
    fn glob_single_star() {
        assert!(glob_matches("src/*.rs", "src/main.rs"));
        assert!(!glob_matches("src/*.rs", "src/sub/main.rs"));
    }

    #[test]
    fn glob_question_mark() {
        assert!(glob_matches("src/?.rs", "src/a.rs"));
        assert!(!glob_matches("src/?.rs", "src/ab.rs"));
    }

    #[test]
    fn required_claims_permit_default_empty() {
        // Under default permit with no rules, any path returns empty claims.
        use raxis_policy::load_policy;
        let dir = std::env::temp_dir().join(format!(
            "raxis-test-policy-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .subsec_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("policy.toml");
        // Cert-mandatory (INV-CERT-01): the loader's
        // `validate_operator_certs` step rejects any
        // `[[operators.entries]]` block missing a self-signed cert,
        // so we mint one from a deterministic test key and round-trip
        // through the shared genesis emitter rather than hand-rolling
        // a TOML body that the loader would refuse.
        let key = raxis_test_support::ephemeral_signing_key([0xAAu8; 32]);
        let pk = raxis_test_support::pubkey_hex(&key);
        let fp = raxis_genesis_tools::pubkey_fingerprint(&hex::decode(&pk).unwrap());
        let cert = raxis_test_support::ephemeral_cert_with_key(
            &key,
            raxis_test_support::CertOpts {
                display_name: "Test".to_owned(),
                permitted_ops: raxis_genesis_tools::PERMITTED_OPS
                    .iter()
                    .map(|s| (*s).to_owned())
                    .collect(),
                ..raxis_test_support::CertOpts::default()
            },
        );
        let toml = raxis_genesis_tools::render_genesis_policy_toml(
            raxis_genesis_tools::GenesisPolicyInputs {
                authority_pubkey_hex:
                    "1111111111111111111111111111111111111111111111111111111111111111",
                quality_pubkey_hex:
                    "2222222222222222222222222222222222222222222222222222222222222222",
                operator_pubkey_hex: &pk,
                operator_fingerprint: &fp,
                signed_at_unix_secs: 1_700_000_000,
                allowed_worktree_roots: &["/work"],
                operator_cert: &cert,
            },
        );
        std::fs::write(&p, toml).unwrap();
        let (policy, _, _) = load_policy(&p).unwrap();
        let paths = vec![PathBuf::from("src/main.rs")];
        let claims = required_claims(&paths, &policy).unwrap();
        assert!(claims.is_empty(), "permit default → no claims required");
        std::fs::remove_dir_all(&dir).ok();
    }
}

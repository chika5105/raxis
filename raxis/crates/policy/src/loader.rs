// raxis-policy::loader — load_policy: read, hash, and parse policy.toml.
//
// Normative reference: kernel-core.md §2.2 startup step 3 and kernel-store.md §2.5.3.
//
// Boot sequence (step 3):
//   1. Read raw bytes of `<data_dir>/policy/policy.toml`.
//   2. Compute SHA-256 of raw bytes.
//   3. Parse as TOML into RawPolicy.
//   4. Semantic validation → PolicyBundle (sha256 injected via with_sha256).
//
// Note: meta.policy_sha256 in the TOML is an OPTIONAL informational field that
// the signing tool may embed. This loader does NOT verify it against the computed
// hash — doing so would require a self-referential fixed-point (SHA-256 of a
// string that contains SHA-256 of itself) which has no general solution. The
// Ed25519 signature over the raw bytes (verified by bootstrap.rs) is the actual
// integrity check; the embedded meta field adds no security. The loader computes
// and returns the SHA-256 independently so the kernel can store it in
// policy_epoch_history.
//
// Signature verification (Ed25519 over policy.sig) is intentionally NOT done
// in this crate. It requires the operator's public key (loaded from .pub files)
// and raxis-crypto, which the kernel binary wires in bootstrap.rs. This crate
// owns: TOML parsing + semantic validation.

use std::path::Path;

use sha2::{Digest, Sha256};

use crate::{
    bundle::{PolicyBundle, RawPolicy},
    PolicyError,
};

/// Read and parse the policy artifact at `policy_toml_path`.
///
/// Returns `(PolicyBundle, raw_bytes, sha256_hex)` on success.
/// - `raw_bytes` — the exact file bytes; kernel passes these to the Ed25519 verifier.
/// - `sha256_hex` — SHA-256 of the raw bytes; stored in policy_epoch_history.
///
/// Does NOT verify the Ed25519 signature — that is done by the kernel's
/// bootstrap.rs using raxis-crypto after this call returns.
pub fn load_policy(policy_toml_path: &Path) -> Result<(PolicyBundle, Vec<u8>, String), PolicyError> {
    let raw_bytes = std::fs::read(policy_toml_path)?;

    let actual_sha256 = {
        let mut h = Sha256::new();
        h.update(&raw_bytes);
        hex::encode(h.finalize())
    };

    let toml_str = std::str::from_utf8(&raw_bytes).map_err(|_| {
        PolicyError::MalformedArtifact("policy.toml is not valid UTF-8".to_owned())
    })?;

    let raw: RawPolicy = toml::from_str(toml_str)?;
    let bundle = PolicyBundle::validate(raw)?.with_sha256(actual_sha256.clone());

    // Return raw bytes and the actual SHA-256 so the kernel can:
    //   1. Verify the Ed25519 signature over these bytes.
    //   2. Store the sha256 in policy_epoch_history.
    Ok((bundle, raw_bytes, actual_sha256))
}

/// Compute the SHA-256 fingerprint for an operator public key.
///
/// `fingerprint = hex(SHA-256[:16](raw_pubkey_bytes))` — 32 hex chars.
/// Matches the convention in kernel-store.md §2.5.4.
pub fn operator_pubkey_fingerprint(pubkey_hex: &str) -> Result<String, PolicyError> {
    let pubkey_bytes = hex::decode(pubkey_hex)?;
    let mut h = Sha256::new();
    h.update(&pubkey_bytes);
    let digest = h.finalize();
    Ok(hex::encode(&digest[..16]))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn write_tmp(content: &str) -> NamedTempFile {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(content.as_bytes()).unwrap();
        f.flush().unwrap();
        f
    }

    /// Build a minimal valid policy TOML for tests.
    ///
    /// `meta.policy_sha256` is intentionally omitted — it is `Option<String>`
    /// with `#[serde(default)]` so the field is not required. The loader
    /// computes the SHA-256 of the raw bytes independently and never verifies
    /// it against the embedded meta field (a self-referential hash has no
    /// fixed-point solution; the Ed25519 signature is the actual integrity
    /// check). Including the field in test fixtures would require either a
    /// wrong value (dishonest) or an infeasible convergence loop.
    ///
    /// Cert-mandatory (INV-CERT-01): the loader's `validate_operator_certs`
    /// step rejects any `[[operators.entries]]` block missing a self-signed
    /// cert whose `pubkey_hex` matches the entry's `pubkey_hex`. We mint
    /// the cert here from a deterministic operator key so the fixture
    /// passes the strict-deserialise + self-sig verification path.
    fn minimal_policy_toml() -> String {
        let op_key = raxis_test_support::ephemeral_signing_key([0xCCu8; 32]);
        let op_pk_hex = raxis_test_support::pubkey_hex(&op_key);
        let op_fp = operator_pubkey_fingerprint(&op_pk_hex).unwrap();
        let cert = raxis_test_support::ephemeral_cert_with_key(
            &op_key,
            raxis_test_support::CertOpts {
                display_name: "Alice".to_owned(),
                permitted_ops: vec!["CreateInitiative".into()],
                ..raxis_test_support::CertOpts::default()
            },
        );
        let cert_toml = ::toml::to_string(&cert).unwrap();
        let cert_block = cert_toml
            .lines()
            .map(|l| format!("             {l}"))
            .collect::<Vec<_>>()
            .join("\n");

        format!(
            "[meta]\n\
             epoch     = 1\n\
             signed_by = \"{op_fp}\"\n\
             signed_at = 1714500000\n\
             \n\
             [authority]\n\
             authority_pubkey = \"{auth}\"\n\
             quality_pubkey   = \"{qual}\"\n\
             \n\
             [escalation_policy]\n\
             timeout_secs         = 3600\n\
             window_secs          = 300\n\
             max_per_window       = 5\n\
             quarantine_threshold = 3\n\
             \n\
             [sessions]\n\
             default_ttl_secs       = 86400\n\
             max_ttl_secs           = 604800\n\
             allowed_worktree_roots = [\"/home/op/worktrees\"]\n\
             \n\
             [delegations]\n\
             max_ttl_secs = 86400\n\
             \n\
             [budget]\n\
             [budget.base_cost_per_intent_kind]\n\
             SingleCommit = 10\n\
             \n\
             [operators]\n\
             [[operators.entries]]\n\
             pubkey_fingerprint = \"{op_fp}\"\n\
             display_name       = \"Alice\"\n\
             pubkey_hex         = \"{op_pk_hex}\"\n\
             permitted_ops      = [\"CreateInitiative\"]\n\
             [operators.entries.cert]\n\
             {cert_block}\n",
            auth = "a".repeat(64),
            qual = "b".repeat(64),
        )
    }

    #[test]
    fn load_valid_policy() {
        let toml_str = minimal_policy_toml();
        let f = write_tmp(&toml_str);
        let result = load_policy(f.path());
        assert!(result.is_ok(), "load_policy failed: {:?}", result.err());
        let (bundle, raw_bytes, sha256) = result.unwrap();
        assert_eq!(bundle.epoch(), 1);
        assert!(!raw_bytes.is_empty());
        assert_eq!(sha256.len(), 64); // 32-byte SHA-256 as hex
    }

    #[test]
    fn load_policy_returns_correct_sha256() {
        let toml_str = minimal_policy_toml();
        let f = write_tmp(&toml_str);
        let (_, raw_bytes, sha256) = load_policy(f.path()).unwrap();
        // Verify the returned SHA-256 matches what we compute independently.
        let mut h = Sha256::new();
        h.update(&raw_bytes);
        let expected = hex::encode(h.finalize());
        assert_eq!(sha256, expected);
    }

    #[test]
    fn invalid_toml_rejected() {
        let f = write_tmp("this is not valid toml }{");
        let result = load_policy(f.path());
        assert!(
            matches!(result, Err(PolicyError::TomlParse(_))),
            "expected TomlParse, got {:?}",
            result
        );
    }

    #[test]
    fn missing_operators_rejected() {
        // Uses the same minimal shape as minimal_policy_toml() but with an
        // empty operators.entries list — policy_sha256 is omitted (optional).
        let toml = format!(
            "[meta]\n\
             epoch     = 1\n\
             signed_by = \"abcd1234abcd1234abcd1234abcd1234\"\n\
             signed_at = 1714500000\n\
             \n\
             [authority]\n\
             authority_pubkey = \"{auth}\"\n\
             quality_pubkey   = \"{qual}\"\n\
             \n\
             [escalation_policy]\n\
             timeout_secs         = 3600\n\
             window_secs          = 300\n\
             max_per_window       = 5\n\
             quarantine_threshold = 3\n\
             \n\
             [sessions]\n\
             default_ttl_secs       = 86400\n\
             max_ttl_secs           = 604800\n\
             allowed_worktree_roots = [\"/home/op\"]\n\
             \n\
             [delegations]\n\
             max_ttl_secs = 86400\n\
             \n\
             [budget]\n\
             [budget.base_cost_per_intent_kind]\n\
             SingleCommit = 10\n\
             \n\
             [operators]\n\
             entries = []\n",
            auth = "a".repeat(64),
            qual = "b".repeat(64),
        );
        let f = write_tmp(&toml);
        let result = load_policy(f.path());
        assert!(
            matches!(result, Err(PolicyError::MalformedArtifact(_))),
            "expected MalformedArtifact for empty operators, got {:?}",
            result
        );
    }

    #[test]
    fn operator_pubkey_fingerprint_is_32_hex_chars() {
        let pubkey_hex = "a".repeat(64);
        let fp = operator_pubkey_fingerprint(&pubkey_hex).unwrap();
        assert_eq!(fp.len(), 32);
        assert!(fp.chars().all(|c| c.is_ascii_hexdigit()));
    }
}

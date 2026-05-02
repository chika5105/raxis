// raxis-crypto::plan — Plan artifact signing domain construction.
//
// Normative reference: kernel-store.md §2.5.3 "Plan artifact signing contract"
//
// The operator CLI signs the plan; the kernel verifies. The signing domain is:
//
//   signing_input = SHA-256(canonical_bytes)
//   canonical_bytes = "RAXIS-V1-PLAN" || 0x00 || plan_bytes
//
//   operator_sig = Ed25519Sign(operator_private_key, signing_input)
//
// The domain prefix prevents a plan signature from being reused as a valid
// delegation grant or escalation approval signature.
//
// kernel-store.md §2.5.3: "plan.sig contains exactly the 64-byte Ed25519
// signature. There is no additional framing."

use sha2::{Digest, Sha256};

use crate::{CryptoError, verify_ed25519};

/// Compute the 32-byte `signing_input` for a plan artifact.
///
/// Both the CLI (to sign) and the kernel (to verify at `create_initiative`
/// and `approve_plan`) call this function.
pub fn plan_signing_input(plan_bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"RAXIS-V1-PLAN\x00");
    hasher.update(plan_bytes);
    hasher.finalize().into()
}

/// Verify the operator Ed25519 signature over a plan artifact.
///
/// `pubkey_bytes`    — 32-byte authority public key.
/// `plan_bytes`      — the raw canonical plan TOML bytes.
/// `signature_bytes` — the 64-byte detached signature from `plan.sig`.
pub fn verify_plan_signature(
    pubkey_bytes: &[u8],
    plan_bytes: &[u8],
    signature_bytes: &[u8],
) -> Result<(), CryptoError> {
    let signing_input = plan_signing_input(plan_bytes);
    verify_ed25519(pubkey_bytes, &signing_input, signature_bytes)
}

/// Compute the hex SHA-256 of `plan_bytes` for storage in
/// `initiatives.plan_artifact_sha256`.
///
/// kernel-store.md §2.5.3: "plan_artifact_sha256 is hex-encoded SHA-256
/// of plan_bytes". This is a plain hash of the raw bytes (not the signing
/// domain hash — the two are different values).
pub fn plan_artifact_sha256(plan_bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(plan_bytes);
    hex::encode(hasher.finalize())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{SigningKey, Signer};

    fn test_keypair() -> (SigningKey, [u8; 32]) {
        let seed = [0x11u8; 32];
        let sk = SigningKey::from_bytes(&seed);
        let pk = sk.verifying_key().to_bytes();
        (sk, pk)
    }

    #[test]
    fn plan_signature_round_trip() {
        let (sk, pk_bytes) = test_keypair();
        let plan_bytes = b"[initiative]\nname = \"test\"\n";

        let signing_input = plan_signing_input(plan_bytes);
        let sig = sk.sign(&signing_input);

        assert!(verify_plan_signature(&pk_bytes, plan_bytes, &sig.to_bytes()).is_ok());
    }

    #[test]
    fn plan_signature_wrong_bytes_fails() {
        let (sk, pk_bytes) = test_keypair();
        let plan_bytes = b"[initiative]\nname = \"test\"\n";
        let signing_input = plan_signing_input(plan_bytes);
        let sig = sk.sign(&signing_input);

        // Tamper with plan_bytes after signing.
        assert!(
            verify_plan_signature(&pk_bytes, b"tampered bytes", &sig.to_bytes()).is_err()
        );
    }

    #[test]
    fn plan_artifact_sha256_is_hex() {
        let sha = plan_artifact_sha256(b"hello");
        assert_eq!(sha.len(), 64, "hex SHA-256 must be 64 chars");
        assert!(sha.chars().all(|c| c.is_ascii_hexdigit()));
    }
}

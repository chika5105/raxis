// raxis-crypto::delegation — GrantDelegation signing domain construction.
//
// Normative reference: kernel-store.md §2.5.5 "Delegation grant signing domain"
//
// The operator constructs the signing domain in the CLI and signs it with
// their private key. The kernel reconstructs the same bytes here and calls
// verify::verify_ed25519 to authenticate the grant.
//
// Byte-exact canonical construction (from the spec):
//
//   canonical_bytes = "RAXIS-V1-DELEGATION-GRANT" || 0x00
//                  || session_id (UUID hyphenated form, 36 bytes) || 0x00
//                  || capability_class (enum variant name UTF-8) || 0x00
//                  || delegating_role_id (UTF-8) || 0x00
//                  || expires_at (8-byte little-endian u64) || 0x00
//                  || scope_json_present (1 byte: 0x01 if Some, 0x00 if None)
//                  || (if present: u32_le(len) || scope_json_utf8_bytes)
//
//   signing_input   = SHA-256(canonical_bytes)   // 32 bytes
//   operator_sig    = Ed25519Sign(privkey, signing_input)
//
// The SHA-256 step converts the variable-length canonical_bytes into a
// fixed-size input for Ed25519 (mirror of §2.5.3 plan signing pattern).

use sha2::{Digest, Sha256};

use crate::{verify_ed25519, CryptoError};

/// Construct the canonical `canonical_bytes` for a GrantDelegation message,
/// hash them with SHA-256, and return the 32-byte `signing_input`.
///
/// Both the CLI (to sign) and the kernel (to verify) call this function.
/// The exact byte layout is normative; any deviation is a spec violation.
pub fn delegation_signing_input(
    session_id: &str,         // UUID hyphenated form, 36 ASCII bytes
    capability_class: &str,   // enum variant name, e.g. "WriteSecrets"
    delegating_role_id: &str, // operator role id
    expires_at: u64,          // absolute Unix seconds
    scope_json: Option<&str>, // None or Some(raw JSON bytes)
) -> [u8; 32] {
    let mut buf: Vec<u8> = Vec::with_capacity(256);

    // Domain separation prefix.
    buf.extend_from_slice(b"RAXIS-V1-DELEGATION-GRANT");
    buf.push(0x00);

    // session_id: UUID hyphenated form (36 bytes).
    buf.extend_from_slice(session_id.as_bytes());
    buf.push(0x00);

    // capability_class: enum variant name UTF-8.
    buf.extend_from_slice(capability_class.as_bytes());
    buf.push(0x00);

    // delegating_role_id: raw UTF-8.
    buf.extend_from_slice(delegating_role_id.as_bytes());
    buf.push(0x00);

    // expires_at: 8-byte little-endian u64.
    buf.extend_from_slice(&expires_at.to_le_bytes());
    buf.push(0x00);

    // scope_json: discriminant byte + optional length-prefixed body.
    match scope_json {
        None => {
            buf.push(0x00); // scope_json_present = false
        }
        Some(json) => {
            buf.push(0x01); // scope_json_present = true
            let json_bytes = json.as_bytes();
            let len = json_bytes.len() as u32;
            buf.extend_from_slice(&len.to_le_bytes());
            buf.extend_from_slice(json_bytes);
        }
    }

    // SHA-256(canonical_bytes) → 32-byte signing_input.
    let mut hasher = Sha256::new();
    hasher.update(&buf);
    hasher.finalize().into()
}

/// Verify the operator Ed25519 signature over a GrantDelegation message.
///
/// `pubkey_bytes` — 32-byte Ed25519 verifying key bytes.
/// `signature_bytes` — 64-byte signature.
///
/// All other parameters are the delegation grant fields used to reconstruct
/// the canonical signing domain.
pub fn verify_delegation_grant(
    pubkey_bytes: &[u8],
    signature_bytes: &[u8],
    session_id: &str,
    capability_class: &str,
    delegating_role_id: &str,
    expires_at: u64,
    scope_json: Option<&str>,
) -> Result<(), CryptoError> {
    let signing_input = delegation_signing_input(
        session_id,
        capability_class,
        delegating_role_id,
        expires_at,
        scope_json,
    );
    verify_ed25519(pubkey_bytes, &signing_input, signature_bytes)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn make_test_keypair() -> (SigningKey, [u8; 32]) {
        // Deterministic test key — NOT for production use.
        let seed = [0xABu8; 32];
        let sk = SigningKey::from_bytes(&seed);
        let pk: [u8; 32] = sk.verifying_key().to_bytes();
        (sk, pk)
    }

    #[test]
    fn delegation_signing_round_trip() {
        let (sk, pk_bytes) = make_test_keypair();

        let session_id = "550e8400-e29b-41d4-a716-446655440000";
        let capability_class = "WriteSecrets";
        let delegating_role_id = "operator-role-1";
        let expires_at: u64 = 1_800_000_000;
        let scope_json = Some(r#"{"paths":["secrets/*"]}"#);

        let signing_input = delegation_signing_input(
            session_id,
            capability_class,
            delegating_role_id,
            expires_at,
            scope_json,
        );

        let sig = sk.sign(&signing_input);
        let sig_bytes: [u8; 64] = sig.to_bytes();

        assert!(verify_delegation_grant(
            &pk_bytes,
            &sig_bytes,
            session_id,
            capability_class,
            delegating_role_id,
            expires_at,
            scope_json,
        )
        .is_ok());
    }

    #[test]
    fn delegation_signature_wrong_key_fails() {
        let (sk, _) = make_test_keypair();
        let (_, wrong_pk) = {
            let seed = [0xCDu8; 32];
            let sk2 = SigningKey::from_bytes(&seed);
            let pk2 = sk2.verifying_key().to_bytes();
            (sk2, pk2)
        };

        let signing_input = delegation_signing_input(
            "550e8400-e29b-41d4-a716-446655440000",
            "WriteSecrets",
            "op1",
            1_800_000_000,
            None,
        );
        let sig = sk.sign(&signing_input);

        assert!(verify_delegation_grant(
            &wrong_pk,
            &sig.to_bytes(),
            "550e8400-e29b-41d4-a716-446655440000",
            "WriteSecrets",
            "op1",
            1_800_000_000,
            None,
        )
        .is_err());
    }

    #[test]
    fn scope_none_vs_some_produces_different_inputs() {
        let a = delegation_signing_input("session-id-a", "NetworkEgress", "op1", 0, None);
        let b = delegation_signing_input("session-id-a", "NetworkEgress", "op1", 0, Some("{}"));
        assert_ne!(
            a, b,
            "None and Some scope must produce distinct signing inputs"
        );
    }
}

// raxis-kernel::ipc::auth — Operator challenge-response authentication.
//
// Normative reference: kernel-core.md §2.2 `src/ipc/auth.rs` and
// peripherals.md §3 \"Operator socket\" authentication envelope.
//
// The operator socket uses a two-message handshake at connect time:
//
//   Kernel → Operator : ChallengeEnvelope { challenge_bytes: [u8; 32] }
//   Operator → Kernel : ResponseEnvelope {
//       fingerprint: String,       // SHA-256[:16] of operator pubkey
//       signed_challenge: [u8; 64] // Ed25519Sig over challenge_bytes
//   }
//
// The kernel then:
//   1. Looks up operator entry in policy by fingerprint.
//   2. Verifies the Ed25519 signature over challenge_bytes.
//   3. If valid, retains AuthenticatedOperator { fingerprint, permitted_ops }
//      for this connection's lifetime.
//   4. Returns ChallengeResult::Ok / ChallengeResult::Unauthorized.
//
// Every subsequent OperatorRequest on the connection skips re-auth;
// the permitted_ops set is checked per-request by the dispatcher.

use raxis_crypto::token::generate_operator_challenge;
use raxis_crypto::verify::verify_ed25519;
use raxis_policy::PolicyBundle;

/// Challenge envelope sent from kernel to operator at connect time.
///
/// Wire shape (JSON, length-prefixed via `raxis_ipc::write_json_frame`):
///
/// ```json
/// { "challenge_hex": "<64 hex chars>" }
/// ```
///
/// The hex form is used (rather than the default serde encoding of `[u8; 32]`,
/// which is a JSON array of integers) so that operator frames are
/// human-debuggable during ceremonies — matching the existing
/// `signed_challenge_hex` convention on `ResponseEnvelope`.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct ChallengeEnvelope {
    /// 32 CSPRNG bytes, hex-encoded to 64 lowercase characters.
    /// The operator signs the **decoded raw bytes**, not the hex string —
    /// see `verify_response`. Mirrors the spec'd behaviour for plan
    /// signatures (`raxis_crypto::plan` signs raw bytes; the hex is just a
    /// transport encoding).
    pub challenge_hex: String,
}

impl ChallengeEnvelope {
    /// Decode `challenge_hex` to its 32 raw bytes. Returns `None` if the field
    /// is malformed; callers MUST treat `None` as a fatal handshake failure.
    pub fn decoded_bytes(&self) -> Option<[u8; 32]> {
        let v = hex::decode(&self.challenge_hex).ok()?;
        v.try_into().ok()
    }
}

/// Response envelope from operator to kernel.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct ResponseEnvelope {
    /// `SHA-256[:16]` fingerprint of the operator's Ed25519 public key (32 hex chars).
    pub fingerprint: String,
    /// Ed25519 signature over `challenge_bytes` — 64 bytes, hex-encoded as 128 chars.
    pub signed_challenge_hex: String,
}

/// An authenticated operator connection — retained for the connection lifetime.
#[derive(Debug, Clone)]
pub struct AuthenticatedOperator {
    pub fingerprint: String,
    pub permitted_ops: Vec<String>,
}

/// Result of the challenge-response handshake.
#[derive(Debug)]
pub enum ChallengeResult {
    Ok(AuthenticatedOperator),
    /// Operator fingerprint not in policy, or signature invalid.
    Unauthorized {
        reason: String,
    },
}

/// Generate a fresh challenge envelope.
///
/// Returns `CryptoError::Rng` if the OS CSPRNG is unavailable; the operator
/// socket loop must close the connection rather than send a degraded challenge.
pub fn make_challenge() -> Result<ChallengeEnvelope, raxis_crypto::CryptoError> {
    let bytes = generate_operator_challenge()?;
    Ok(ChallengeEnvelope {
        challenge_hex: hex::encode(bytes),
    })
}

/// Verify the operator's response envelope against the challenge bytes and the
/// policy's registered operator entries.
///
/// Returns `ChallengeResult::Ok(AuthenticatedOperator)` if the signature is
/// valid for a registered operator. `ChallengeResult::Unauthorized` otherwise.
pub fn verify_response(
    challenge: &ChallengeEnvelope,
    response: &ResponseEnvelope,
    policy: &PolicyBundle,
) -> ChallengeResult {
    // Step 1: Look up operator entry by fingerprint.
    let operator_entry = match policy.operator_entry(&response.fingerprint) {
        Some(e) => e,
        None => {
            return ChallengeResult::Unauthorized {
                reason: format!("fingerprint '{}' not found in policy", response.fingerprint),
            }
        }
    };

    // Step 2: Decode operator pubkey.
    let pubkey_bytes = match hex::decode(&operator_entry.pubkey_hex) {
        Ok(b) => b,
        Err(e) => {
            return ChallengeResult::Unauthorized {
                reason: format!("operator pubkey_hex decode failed: {e}"),
            }
        }
    };

    // Step 3: Verify Ed25519 signature over the raw 32-byte challenge.
    // The wire carries the challenge as `challenge_hex` and the signature as
    // `signed_challenge_hex`; both are decoded back to bytes here. Signing
    // happens over the raw bytes, NOT over the hex string.
    let challenge_bytes = match challenge.decoded_bytes() {
        Some(b) => b,
        None => {
            return ChallengeResult::Unauthorized {
                reason: "challenge_hex is not 64 lowercase hex chars".to_owned(),
            };
        }
    };
    let sig_bytes = match hex::decode(&response.signed_challenge_hex) {
        Ok(b) => b,
        Err(e) => {
            return ChallengeResult::Unauthorized {
                reason: format!("signed_challenge_hex decode failed: {e}"),
            }
        }
    };
    match verify_ed25519(&pubkey_bytes, &challenge_bytes, &sig_bytes) {
        Ok(()) => ChallengeResult::Ok(AuthenticatedOperator {
            fingerprint: response.fingerprint.clone(),
            permitted_ops: operator_entry.permitted_ops.clone(),
        }),
        Err(e) => ChallengeResult::Unauthorized {
            reason: format!("signature invalid: {e}"),
        },
    }
}

/// Check if `op_name` is in the operator's permitted_ops list.
///
/// Called by the operator dispatcher before every handler invocation.
/// Returns `true` if permitted, `false` to reject.
pub fn is_permitted(op: &AuthenticatedOperator, op_name: &str) -> bool {
    op.permitted_ops.iter().any(|p| p == op_name)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Pin: the JSON wire shape of `ChallengeEnvelope`. The CLI's
    /// `OperatorConn::connect` looks up the field name `challenge_hex`; if
    /// anyone renames the struct field without renaming the JSON tag, this
    /// test breaks.
    #[test]
    fn challenge_envelope_serialises_as_challenge_hex_field() {
        let env = ChallengeEnvelope {
            challenge_hex: "ab".repeat(32), // 64 hex chars / 32 bytes
        };
        let json = serde_json::to_string(&env).unwrap();
        assert!(
            json.contains("\"challenge_hex\""),
            "expected `challenge_hex` field, got: {json}"
        );
        // No legacy `challenge_bytes` array.
        assert!(!json.contains("\"challenge_bytes\""));
    }

    /// Pin: the JSON wire shape of `ResponseEnvelope`.
    #[test]
    fn response_envelope_uses_signed_challenge_hex_field() {
        let env = ResponseEnvelope {
            fingerprint: "ff".repeat(16),
            signed_challenge_hex: "00".repeat(64),
        };
        let json = serde_json::to_string(&env).unwrap();
        assert!(json.contains("\"fingerprint\""));
        assert!(json.contains("\"signed_challenge_hex\""));
    }

    /// `decoded_bytes` returns `Some` only for a valid 64-char lowercase
    /// hex string of exactly 32 bytes.
    #[test]
    fn challenge_decoded_bytes_validates_length_and_hex() {
        // Valid: 64 hex chars.
        let ok = ChallengeEnvelope {
            challenge_hex: "ab".repeat(32),
        };
        assert!(ok.decoded_bytes().is_some());

        // Wrong length: 30 bytes / 60 hex chars.
        let short = ChallengeEnvelope {
            challenge_hex: "ab".repeat(30),
        };
        assert!(short.decoded_bytes().is_none());

        // Non-hex character.
        let bad = ChallengeEnvelope {
            challenge_hex: "z".repeat(64),
        };
        assert!(bad.decoded_bytes().is_none());
    }
}

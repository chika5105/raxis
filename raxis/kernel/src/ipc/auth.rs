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

use raxis_policy::PolicyBundle;
use raxis_crypto::verify::verify_ed25519;
use raxis_crypto::token::generate_operator_challenge;

/// Challenge envelope sent from kernel to operator at connect time.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct ChallengeEnvelope {
    /// 32 CSPRNG bytes — the operator must sign these with their private key.
    pub challenge_bytes: [u8; 32],
}

/// Response envelope from operator to kernel.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct ResponseEnvelope {
    /// SHA-256[:16] fingerprint of the operator's Ed25519 public key (32 hex chars).
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
    Unauthorized { reason: String },
}

/// Generate a fresh challenge envelope.
pub fn make_challenge() -> ChallengeEnvelope {
    ChallengeEnvelope {
        challenge_bytes: generate_operator_challenge(),
    }
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

    // Step 3: Verify Ed25519 signature over challenge_bytes.
    let sig_bytes = match hex::decode(&response.signed_challenge_hex) {
        Ok(b) => b,
        Err(e) => {
            return ChallengeResult::Unauthorized {
                reason: format!("signed_challenge_hex decode failed: {e}"),
            }
        }
    };
    match verify_ed25519(&pubkey_bytes, &challenge.challenge_bytes, &sig_bytes) {
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

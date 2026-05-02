// raxis-crypto::token — CSPRNG token generation for kernel-issued credentials.
//
// Normative reference: kernel-store.md §2.5.4 (key inventory) and the token
// generation rules for sessions, verifier run tokens, and operator challenges.
//
// All kernel-issued tokens are 32 random bytes (256-bit) from the OS CSPRNG,
// hex-encoded to 64 ASCII characters for at-rest storage and wire transport.
//
// Token types in v1:
//   - session_token: 32 CSPRNG bytes (hex 64 chars) — stored in sessions.session_token
//   - verifier_run_token: 32 CSPRNG bytes (hex 64 chars) — raw bytes sent to verifier,
//     SHA-256(raw) stored in verifier_run_tokens.token_hash
//   - approval_token_nonce: 16 CSPRNG bytes (hex 32 chars) — embedded in approval token
//   - operator challenge: 32 CSPRNG bytes — sent to operator CLI for signing
//
// None of these use kernel's Ed25519 signing key — they are opaque random values.
// The Ed25519 key is used only for ApprovalProof signatures (kernel-signed receipts).

use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------
// OS CSPRNG — portable random bytes via std (macOS: /dev/urandom).
// We do NOT pull in the `rand` crate to avoid supply-chain surface.
// std::io::Read on /dev/urandom is always available on Unix.
// ---------------------------------------------------------------------------

/// Generate `n` cryptographically random bytes using the OS CSPRNG.
/// Panics if the OS CSPRNG is unavailable (system misconfiguration).
pub fn random_bytes(n: usize) -> Vec<u8> {
    use std::io::Read;

    #[cfg(unix)]
    {
        let mut buf = vec![0u8; n];
        std::fs::File::open("/dev/urandom")
            .expect("failed to open /dev/urandom")
            .read_exact(&mut buf)
            .expect("failed to read from /dev/urandom");
        buf
    }

    #[cfg(not(unix))]
    {
        // Windows / other platforms: use getrandom crate or compile-time error.
        // v1 target is macOS/Linux; this branch is unreachable in production.
        compile_error!("raxis-crypto::token::random_bytes: non-Unix platform not supported in v1");
    }
}

// ---------------------------------------------------------------------------
// Token generation helpers
// ---------------------------------------------------------------------------

/// Generate a session token: 32 CSPRNG bytes, hex-encoded to 64 chars.
/// Stored plaintext in `sessions.session_token`.
pub fn generate_session_token() -> String {
    hex::encode(random_bytes(32))
}

/// Generate a verifier run token: 32 CSPRNG bytes.
/// Returns (raw_bytes, token_hash_hex):
///   raw_bytes: sent to verifier as RAXIS_VERIFIER_TOKEN env var (hex-encoded)
///   token_hash_hex: hex SHA-256 of raw_bytes; stored in verifier_run_tokens.token_hash
pub fn generate_verifier_token() -> (String, String) {
    let raw = random_bytes(32);
    let raw_hex = hex::encode(&raw);

    let mut hasher = Sha256::new();
    hasher.update(&raw);
    let hash_hex = hex::encode(hasher.finalize());

    (raw_hex, hash_hex)
}

/// Generate an operator challenge: 32 CSPRNG raw bytes.
/// Sent to the operator CLI in `ChallengeEnvelope.challenge_bytes`.
pub fn generate_operator_challenge() -> [u8; 32] {
    random_bytes(32)
        .try_into()
        .expect("random_bytes(32) is exactly 32 bytes")
}

/// Generate an approval token nonce: 16 CSPRNG bytes, hex-encoded to 32 chars.
/// Stored in `approval_tokens.nonce`; inserted into `approval_token_nonces` on consumption.
pub fn generate_approval_nonce() -> String {
    hex::encode(random_bytes(16))
}

/// Generate an envelope nonce: 16 CSPRNG bytes, hex-encoded to 32 chars.
/// Used by the planner CLI for `IntentRequest.envelope_nonce` (INV-01 check B).
pub fn generate_envelope_nonce() -> String {
    hex::encode(random_bytes(16))
}

// ---------------------------------------------------------------------------
// Token hash helpers (used by kernel when validating presented tokens)
// ---------------------------------------------------------------------------

/// Compute hex SHA-256 of the raw token bytes.
/// Used to reconstruct the hash for constant-time comparison against
/// `sessions.session_token` (stored plaintext — comparison is direct)
/// and `verifier_run_tokens.token_hash` (hash comparison).
pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

// ---------------------------------------------------------------------------
// Constant-time comparison
// ---------------------------------------------------------------------------

/// Compare two byte slices in constant time. Returns true iff equal.
/// Used for session_token validation to prevent timing oracle attacks.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    // XOR-accumulate: any differing bit sets at least one bit in `diff`.
    let diff: u8 = a.iter().zip(b.iter()).fold(0u8, |acc, (&x, &y)| acc | (x ^ y));
    diff == 0
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_token_is_64_lowercase_hex() {
        let tok = generate_session_token();
        assert_eq!(tok.len(), 64);
        assert!(tok.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f')));
    }

    #[test]
    fn verifier_token_hash_matches_sha256_of_raw() {
        let (raw_hex, hash_hex) = generate_verifier_token();
        let raw = hex::decode(&raw_hex).unwrap();
        let expected_hash = sha256_hex(&raw);
        assert_eq!(hash_hex, expected_hash);
    }

    #[test]
    fn ct_eq_correct() {
        assert!(ct_eq(b"hello", b"hello"));
        assert!(!ct_eq(b"hello", b"world"));
        assert!(!ct_eq(b"short", b"longer"));
    }

    #[test]
    fn tokens_are_unique() {
        let a = generate_session_token();
        let b = generate_session_token();
        assert_ne!(a, b, "two tokens should be different (collision probability ~2^-256)");
    }
}

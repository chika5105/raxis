// raxis-crypto::token — CSPRNG token generation for kernel-issued credentials.
//
// Normative reference: kernel-store.md §2.5.4 (key inventory) and
// cli-ceremony.md §4.2 (genesis ceremony — "fail closed if /dev/urandom is
// unavailable; never write a key whose bytes were not delivered by the OS
// CSPRNG").
//
// All kernel-issued tokens are 32 random bytes (256-bit) from the OS CSPRNG,
// hex-encoded to 64 ASCII characters for at-rest storage and wire transport.
//
// Token types in v1:
//   - session_token        : 32 bytes / 64 hex chars (sessions.session_token)
//   - verifier_run_token   : 32 bytes / 64 hex chars; SHA-256(raw) stored in
//                            verifier_run_tokens.token_hash
//   - approval_token_nonce : 16 bytes / 32 hex chars (approval_tokens.nonce)
//   - operator challenge   : 32 raw bytes (ChallengeEnvelope.challenge_bytes)
//
// None of these use the kernel's Ed25519 signing key — they are opaque random
// values. The Ed25519 key is used only for ApprovalProof signatures.
//
// Failure model: every helper that mints randomness returns
// `Result<_, CryptoError>` and surfaces `CryptoError::Rng(getrandom::Error)`
// when the OS CSPRNG is unavailable. There is no panicking variant and no
// silently-zero variant. Callers MUST handle the failure and refuse to
// proceed with a degraded token.

use sha2::{Digest, Sha256};

use crate::CryptoError;

// ---------------------------------------------------------------------------
// OS CSPRNG via the getrandom crate (Linux: getrandom(2); macOS: getentropy;
// Windows: BCryptGenRandom). The crate handles platform differences; we
// expose a single `try_random_bytes` shim and route every minting helper
// through it so the failure path is uniform.
// ---------------------------------------------------------------------------

/// Fill `dest` with bytes from the OS CSPRNG.
///
/// Returns `CryptoError::Rng` on any underlying failure. Does NOT retry —
/// caller decides whether retrying makes sense for the call-site.
pub fn try_random_bytes(dest: &mut [u8]) -> Result<(), CryptoError> {
    getrandom::getrandom(dest)?;
    Ok(())
}

/// Allocate and return `n` cryptographically random bytes.
///
/// Returns `CryptoError::Rng` on OS CSPRNG failure. Caller must propagate.
pub fn try_random_vec(n: usize) -> Result<Vec<u8>, CryptoError> {
    let mut buf = vec![0u8; n];
    try_random_bytes(&mut buf)?;
    Ok(buf)
}

/// Allocate and return a fixed-size array of `N` cryptographically random bytes.
///
/// Convenience around `try_random_bytes` for the common 32-byte seed case.
pub fn try_random_array<const N: usize>() -> Result<[u8; N], CryptoError> {
    let mut buf = [0u8; N];
    try_random_bytes(&mut buf)?;
    Ok(buf)
}

// ---------------------------------------------------------------------------
// Token generation helpers — all fallible
// ---------------------------------------------------------------------------

/// Generate a session token: 32 CSPRNG bytes, hex-encoded to 64 chars.
///
/// Stored plaintext in `sessions.session_token`. Comparison at validation time
/// MUST be constant-time via `ct_eq`.
pub fn generate_session_token() -> Result<String, CryptoError> {
    let raw: [u8; 32] = try_random_array()?;
    Ok(hex::encode(raw))
}

/// Generate a verifier run token: 32 CSPRNG bytes.
///
/// Returns `(raw_hex, token_hash_hex)`:
///   - `raw_hex`        : sent to verifier as `RAXIS_VERIFIER_TOKEN` env var
///   - `token_hash_hex` : hex SHA-256 of the raw bytes; stored in
///                        `verifier_run_tokens.token_hash`
pub fn generate_verifier_token() -> Result<(String, String), CryptoError> {
    let raw: [u8; 32] = try_random_array()?;
    let raw_hex = hex::encode(raw);
    let hash_hex = sha256_hex(&raw);
    Ok((raw_hex, hash_hex))
}

/// Generate an operator challenge: 32 CSPRNG raw bytes.
///
/// Sent to the operator CLI in `ChallengeEnvelope.challenge_bytes`.
pub fn generate_operator_challenge() -> Result<[u8; 32], CryptoError> {
    try_random_array::<32>()
}

/// Generate an approval token nonce: 16 CSPRNG bytes, hex-encoded to 32 chars.
///
/// Stored in `approval_tokens.nonce`; inserted into `approval_token_nonces`
/// on consumption (single-use enforcement).
pub fn generate_approval_nonce() -> Result<String, CryptoError> {
    let raw: [u8; 16] = try_random_array()?;
    Ok(hex::encode(raw))
}

/// Generate an envelope nonce: 16 CSPRNG bytes, hex-encoded to 32 chars.
///
/// Used by the planner for `IntentRequest.envelope_nonce` (INV-01 check B).
pub fn generate_envelope_nonce() -> Result<String, CryptoError> {
    let raw: [u8; 16] = try_random_array()?;
    Ok(hex::encode(raw))
}

// ---------------------------------------------------------------------------
// Token hash helpers (used by kernel when validating presented tokens)
// ---------------------------------------------------------------------------

/// Hex SHA-256 of `bytes`.
///
/// Used to (a) reconstruct verifier-token hashes for lookup against
/// `verifier_run_tokens.token_hash` and (b) compute operator pubkey
/// fingerprints (truncated to 16 bytes / 32 hex chars by the caller).
pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

// ---------------------------------------------------------------------------
// Constant-time comparison
// ---------------------------------------------------------------------------

/// Compare two byte slices in constant time. Returns `true` iff equal.
///
/// Used for session-token validation and any other place where a timing
/// oracle on a secret comparison would leak information. Length mismatch is
/// short-circuited (the length itself is not secret).
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
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
    fn try_random_bytes_fills_buffer() {
        let mut buf = [0u8; 32];
        try_random_bytes(&mut buf).expect("OS CSPRNG must succeed in test env");
        // Probability of an all-zero 32-byte buffer from a healthy CSPRNG is 2^-256.
        assert!(buf.iter().any(|&b| b != 0), "buffer should not be all zeros");
    }

    #[test]
    fn try_random_array_fills_full_array() {
        let buf: [u8; 16] = try_random_array().expect("OS CSPRNG must succeed");
        assert!(buf.iter().any(|&b| b != 0));
    }

    #[test]
    fn try_random_vec_has_requested_length() {
        let v = try_random_vec(48).expect("OS CSPRNG must succeed");
        assert_eq!(v.len(), 48);
    }

    #[test]
    fn session_token_is_64_lowercase_hex() {
        let tok = generate_session_token().expect("rng");
        assert_eq!(tok.len(), 64);
        assert!(tok.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f')));
    }

    #[test]
    fn verifier_token_hash_matches_sha256_of_raw() {
        let (raw_hex, hash_hex) = generate_verifier_token().expect("rng");
        let raw = hex::decode(&raw_hex).unwrap();
        assert_eq!(hash_hex, sha256_hex(&raw));
    }

    #[test]
    fn approval_nonce_is_32_lowercase_hex() {
        let n = generate_approval_nonce().expect("rng");
        assert_eq!(n.len(), 32);
        assert!(n.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f')));
    }

    #[test]
    fn envelope_nonce_is_32_lowercase_hex() {
        let n = generate_envelope_nonce().expect("rng");
        assert_eq!(n.len(), 32);
    }

    #[test]
    fn operator_challenge_is_32_bytes() {
        let c = generate_operator_challenge().expect("rng");
        assert_eq!(c.len(), 32);
    }

    #[test]
    fn ct_eq_correct() {
        assert!(ct_eq(b"hello", b"hello"));
        assert!(!ct_eq(b"hello", b"world"));
        assert!(!ct_eq(b"short", b"longer"));
        assert!(ct_eq(b"", b""));
    }

    #[test]
    fn tokens_are_unique() {
        let a = generate_session_token().expect("rng");
        let b = generate_session_token().expect("rng");
        assert_ne!(a, b, "two tokens should be different (collision probability ~2^-256)");
    }
}

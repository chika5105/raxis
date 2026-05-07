// raxis-crypto::verify — Core Ed25519 verify primitive and CryptoError.
//
// Normative reference: kernel-store.md §2.5.3, §2.5.5.
//
// All signature verification in the kernel routes through this module.
// Signing is done off-kernel by the operator CLI (or authority key ceremony
// tooling); the kernel only ever verifies.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use thiserror::Error;

// ---------------------------------------------------------------------------
// CryptoError
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("Ed25519 signature verification failed: {0}")]
    SignatureInvalid(#[from] ed25519_dalek::SignatureError),

    #[error("malformed public key bytes (expected 32 bytes): {0}")]
    MalformedPublicKey(String),

    #[error("malformed signature bytes (expected 64 bytes): {0}")]
    MalformedSignature(String),

    #[error("hex decode error: {0}")]
    HexDecode(#[from] hex::FromHexError),

    /// The OS CSPRNG was unavailable when minting a token / seed / nonce.
    /// Callers that hit this MUST refuse to proceed — silently filling with
    /// zeros has produced real-world key compromise. See cli-ceremony.md §4.2.
    #[error("OS CSPRNG unavailable: {0}")]
    Rng(#[from] getrandom::Error),

    /// Canonical encoding of a V2 plan bundle failed. Surfaced from
    /// `plan_bundle::canonical_encode` when the schema-version /
    /// freshness-envelope contract is violated. See
    /// `plan-bundle-sealing.md §3.2`.
    #[error("plan-bundle canonical encoding failed: {0}")]
    PlanBundleEncode(#[from] crate::plan_bundle::PlanBundleCodecError),
}

// ---------------------------------------------------------------------------
// verify_ed25519 — the single canonical entry point.
//
// All callers supply `pubkey_bytes` (32-byte raw Ed25519 public key) and
// `signature_bytes` (64-byte raw signature). The `message` is the bytes
// that were signed — the caller is responsible for constructing the correct
// canonical signing domain bytes per the spec.
// ---------------------------------------------------------------------------

/// Verify an Ed25519 signature.
///
/// - `pubkey_bytes`     — 32-byte compressed point (standard Ed25519).
/// - `message`          — the message bytes that were signed (not a digest;
///                        ed25519-dalek hashes internally with SHA-512).
/// - `signature_bytes`  — 64-byte signature (R || s).
///
/// Returns `Ok(())` on a valid signature, `Err(CryptoError::SignatureInvalid)`
/// on a bad signature, or `Err(CryptoError::MalformedPublicKey/Signature)` on
/// malformed input.
pub fn verify_ed25519(
    pubkey_bytes: &[u8],
    message: &[u8],
    signature_bytes: &[u8],
) -> Result<(), CryptoError> {
    let pk_arr: [u8; 32] = pubkey_bytes.try_into().map_err(|_| {
        CryptoError::MalformedPublicKey(format!(
            "expected 32 bytes, got {}",
            pubkey_bytes.len()
        ))
    })?;
    let sig_arr: [u8; 64] = signature_bytes.try_into().map_err(|_| {
        CryptoError::MalformedSignature(format!(
            "expected 64 bytes, got {}",
            signature_bytes.len()
        ))
    })?;

    let verifying_key = VerifyingKey::from_bytes(&pk_arr)?;
    let signature = Signature::from_bytes(&sig_arr);

    verifying_key.verify(message, &signature)?;
    Ok(())
}

/// Decode a hex-encoded public key string (64 hex chars → 32 bytes) and
/// verify the signature.
pub fn verify_ed25519_hex(
    pubkey_hex: &str,
    message: &[u8],
    signature_hex: &str,
) -> Result<(), CryptoError> {
    let pubkey_bytes = hex::decode(pubkey_hex)?;
    let sig_bytes = hex::decode(signature_hex)?;
    verify_ed25519(&pubkey_bytes, message, &sig_bytes)
}

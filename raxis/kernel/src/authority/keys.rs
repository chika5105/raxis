// raxis-kernel::authority::keys — KeyRegistry: the only in-memory holder of
// live key material in the kernel binary.
//
// Normative reference: kernel-core.md §2.3 `src/authority/keys.rs`.
//
// Rules:
//   - KeyRegistry is the sole importer of ed25519-dalek within raxis-kernel.
//   - No other kernel module may hold raw key bytes or sign directly.
//   - quality_keypair is loaded but unused in v1 (reserved for v2 witness
//     attestation). Calling quality_keypair.sign() from any v1 module is a
//     spec violation.
//
// Key file format (written by `kernel/bootstrap.rs` and `raxis` CLI `genesis` — must stay in lockstep):
//   -----BEGIN ED25519 PRIVATE KEY-----
//   <64-char hex: 32-byte seed>
//   -----END ED25519 PRIVATE KEY-----
//   -----BEGIN ED25519 PUBLIC KEY-----
//   <64-char hex: 32-byte compressed public key>
//   -----END ED25519 PUBLIC KEY-----

use std::path::Path;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::errors::KernelError;

// ---------------------------------------------------------------------------
// KeyRegistry
// ---------------------------------------------------------------------------

/// Holds all live key material for the kernel. Loaded once at startup (step 4)
/// and wrapped in `Arc<KeyRegistry>` passed through HandlerContext.
pub struct KeyRegistry {
    /// Authority signing keypair — used for Ed25519 signatures on audit records
    /// and policy verification.
    authority: SigningKey,
    /// Quality keypair — loaded for forward compatibility; unused in v1.
    /// v1 code must not call `quality.sign()`.
    #[allow(dead_code)]
    quality: SigningKey,
    /// Verifier token HMAC key — 32 raw bytes.
    verifier_token_key: [u8; 32],
}

impl std::fmt::Debug for KeyRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyRegistry")
            .field(
                "authority_pubkey",
                &hex::encode(self.authority.verifying_key().as_bytes()),
            )
            .finish_non_exhaustive()
    }
}

impl KeyRegistry {
    /// Build a `KeyRegistry` from in-memory zero-seeded keys for unit /
    /// integration tests that need a `HandlerContext` but do not
    /// exercise the signing or verifier-token-HMAC code paths.
    ///
    /// PRODUCTION CALLERS MUST USE [`load_key_registry`]: the
    /// zero-seeded authority key is publicly derivable, so any test
    /// path that emits an audit signature using this registry is
    /// signing with a known key. Caller responsibility to ensure the
    /// test does not exercise that path.
    #[cfg(test)]
    pub(crate) fn stub_for_tests() -> Self {
        // SigningKey::from_bytes(&[0u8; 32]) is the smallest valid
        // Ed25519 key — `from_bytes` does not validate strength, only
        // length, so all-zeros is accepted. The verifier_token_key is
        // also all-zeros; verifier_token::issue_verifier_token does not
        // care about its randomness for our test surface (it only HMACs
        // a deterministic input + caller-supplied bytes).
        let authority = SigningKey::from_bytes(&[0u8; 32]);
        let quality = SigningKey::from_bytes(&[1u8; 32]);
        Self {
            authority,
            quality,
            verifier_token_key: [0u8; 32],
        }
    }

    /// Build a `KeyRegistry` from a caller-supplied authority signing
    /// key. Test-only — used by `policy_manager` tests that need to
    /// produce signed policy artifacts whose signature the kernel can
    /// then verify against this same key. Quality and verifier-token
    /// keys are populated with deterministic stubs (any non-zero bytes
    /// would do; we keep them distinct from the main test authority
    /// key to surface accidental swaps).
    #[cfg(test)]
    pub(crate) fn for_tests_with_authority(authority: SigningKey) -> Self {
        let quality = SigningKey::from_bytes(&[0xA1u8; 32]);
        Self {
            authority,
            quality,
            verifier_token_key: [0xCCu8; 32],
        }
    }
}

// ---------------------------------------------------------------------------
// Loader
// ---------------------------------------------------------------------------

/// Load the KeyRegistry from the key files written by `bootstrap::run`.
///
/// Called from `main.rs` step 4. Returns `KernelError::KeyRegistry` if any
/// key file is missing, malformed, or has an invalid Ed25519 key.
pub fn load_key_registry(data_dir: &Path) -> Result<KeyRegistry, KernelError> {
    let keys_dir = data_dir.join("keys");

    let authority = load_signing_key(&keys_dir.join("authority_keypair.pem"))?;
    let quality = load_signing_key(&keys_dir.join("quality_keypair.pem"))?;
    let verifier_token_key = load_verifier_token_key(&keys_dir.join("verifier_token_key.bin"))?;

    Ok(KeyRegistry {
        authority,
        quality,
        verifier_token_key,
    })
}

fn load_signing_key(pem_path: &Path) -> Result<SigningKey, KernelError> {
    let content = std::fs::read_to_string(pem_path).map_err(|e| KernelError::KeyRegistry {
        reason: format!("cannot read {}: {e}", pem_path.display()),
    })?;

    // Extract the hex seed from between the PRIVATE KEY markers.
    let seed_hex = content
        .lines()
        .skip_while(|l| !l.contains("BEGIN ED25519 PRIVATE KEY"))
        .nth(1)
        .ok_or_else(|| KernelError::KeyRegistry {
            reason: format!(
                "malformed PEM in {}: no private key line",
                pem_path.display()
            ),
        })?
        .trim();

    let seed_bytes = hex::decode(seed_hex).map_err(|e| KernelError::KeyRegistry {
        reason: format!("cannot hex-decode seed in {}: {e}", pem_path.display()),
    })?;

    let seed: [u8; 32] = seed_bytes
        .try_into()
        .map_err(|_| KernelError::KeyRegistry {
            reason: format!("seed in {} is not 32 bytes", pem_path.display()),
        })?;

    Ok(SigningKey::from_bytes(&seed))
}

fn load_verifier_token_key(path: &Path) -> Result<[u8; 32], KernelError> {
    let bytes = std::fs::read(path).map_err(|e| KernelError::KeyRegistry {
        reason: format!("cannot read verifier_token_key.bin: {e}"),
    })?;
    bytes.try_into().map_err(|_| KernelError::KeyRegistry {
        reason: format!(
            "verifier_token_key.bin at {} must be exactly 32 bytes",
            path.display()
        ),
    })
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Sign `record_bytes` with the authority keypair using Ed25519.
///
/// Called by `raxis-audit-tools::writer` when appending authority-class events.
pub fn sign_audit_record(record_bytes: &[u8], registry: &KeyRegistry) -> Signature {
    registry.authority.sign(record_bytes)
}

/// Returns the hex-encoded SHA-256[:16] fingerprint of the authority public key.
/// Included in the `KernelStarted` audit event and genesis record.
pub fn authority_pubkey_fingerprint(registry: &KeyRegistry) -> String {
    let mut h = Sha256::new();
    h.update(registry.authority.verifying_key().as_bytes());
    hex::encode(&h.finalize()[..16])
}

/// Returns the authority `VerifyingKey` for external callers that need to
/// verify signatures (e.g. policy artifact verification in bootstrap).
pub fn authority_verifying_key(registry: &KeyRegistry) -> VerifyingKey {
    registry.authority.verifying_key()
}

/// Returns the raw verifier token HMAC key bytes. Used by
/// `authority::verifier_token` only — not exposed outside the authority module.
pub(super) fn verifier_token_key_bytes(registry: &KeyRegistry) -> &[u8; 32] {
    &registry.verifier_token_key
}

/// Verify an HMAC-SHA256 token against the authority secret key.
///
/// Spec note: the HMAC-SHA256 function uses the authority signing key's raw
/// seed bytes as the HMAC key and `session_id_bytes` as the message. Returns
/// `AuthorityError::HmacMismatch` on failure.
///
/// In v1, session tokens are CSPRNG-random (not HMAC-derived), so this
/// function is reserved for future HMAC-bound token patterns. It is kept
/// in the public API per the spec's authority/mod.rs re-export list.
pub fn verify_hmac(
    token_bytes: &[u8],
    msg_bytes: &[u8],
    registry: &KeyRegistry,
) -> Result<(), AuthorityError> {
    // Use ring-style HMAC: H(K XOR opad || H(K XOR ipad || message))
    // We implement a simple HMAC-SHA256 inline to avoid pulling in the `hmac`
    // crate outside raxis-crypto. This is acceptable because keys.rs is the
    // sole crypto implementation site in the kernel.
    let key = registry.authority.to_bytes(); // 32-byte seed
    let computed = hmac_sha256(&key, msg_bytes);
    if raxis_crypto::token::ct_eq(&computed, token_bytes) {
        Ok(())
    } else {
        Err(AuthorityError::HmacMismatch)
    }
}

/// Compute HMAC-SHA256(key, msg) returning 32-byte digest.
fn hmac_sha256(key: &[u8; 32], msg: &[u8]) -> Vec<u8> {
    const BLOCK: usize = 64;
    let mut k_ipad = [0x36u8; BLOCK];
    let mut k_opad = [0x5cu8; BLOCK];
    for i in 0..32 {
        k_ipad[i] ^= key[i];
        k_opad[i] ^= key[i];
    }
    // inner = SHA256(k_ipad || msg)
    let inner = {
        let mut h = Sha256::new();
        h.update(&k_ipad);
        h.update(msg);
        h.finalize()
    };
    // outer = SHA256(k_opad || inner)
    let mut h = Sha256::new();
    h.update(&k_opad);
    h.update(&inner);
    h.finalize().to_vec()
}

// ---------------------------------------------------------------------------
// AuthorityError (shared across all authority sub-modules)
// ---------------------------------------------------------------------------

/// Errors returned by authority subsystem functions.
#[derive(Debug, thiserror::Error)]
pub enum AuthorityError {
    #[error("session not found")]
    SessionNotFound,
    #[error("session revoked at {revoked_at}")]
    SessionRevoked { revoked_at: i64 },
    #[error("session expired")]
    SessionExpired,
    #[error("session invalid: {reason}")]
    SessionInvalid { reason: String },
    #[error("HMAC mismatch — token invalid")]
    HmacMismatch,
    #[error("sequence mismatch — message out of order")]
    SequenceMismatch,
    #[error("delegation not found for (session, capability)")]
    DelegationNotGranted,
    #[error("delegation already active for (session, capability)")]
    DelegationAlreadyActive { existing_delegation_id: String },
    #[error("delegation TTL out of range (requested={requested}, max={max})")]
    DelegationTtlOutOfRange { requested: u64, max: u64 },
    #[error("capability above role ceiling")]
    CapabilityAboveCeiling {
        role_id: String,
        capability_class: String,
    },
    #[error("delegation signature invalid")]
    DelegationSignatureInvalid,
    #[error("delegation row not in StaleOnNextUse — double-call guard")]
    DelegationNotStale,
    #[error("verifier token not found")]
    TokenNotFound,
    #[error("verifier token mismatch")]
    TokenMismatch,
    #[error("verifier token expired")]
    TokenExpired,
    #[error("verifier token already consumed")]
    TokenConsumed,
    #[error("approval token signature invalid")]
    SignatureInvalid,
    #[error("approval revoked")]
    ApprovalRevoked,
    #[error("invalid worktree path")]
    InvalidWorktree,
    #[error("store error: {0}")]
    Store(#[from] raxis_store::StoreError),
    #[error("serialization error: {0}")]
    Json(#[from] serde_json::Error),
    /// Surfaces `CryptoError::Rng` and signature/key-format errors. The kernel
    /// MUST refuse session/token issuance when the OS CSPRNG is unavailable —
    /// silently filling buffers with zeros has caused real-world key compromise.
    #[error("crypto error: {0}")]
    Crypto(#[from] raxis_crypto::CryptoError),
}

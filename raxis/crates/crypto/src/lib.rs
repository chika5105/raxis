// raxis-crypto — Ed25519 signing, SHA-256 hashing, and token generation.
//
// Normative reference:
//   - kernel-store.md §2.5.3 (plan artifact signing domain)
//   - kernel-store.md §2.5.4 (key inventory; four key families)
//   - kernel-store.md §2.5.5 (operator challenge-response; GrantDelegation
//     signing domain — byte-exact canonical concatenation)
//
// Crate rules (philosophy.md §1.5):
//   - No I/O, no SQLite, no tokio.
//   - All functions are pure (input → output); callers manage key lifecycle.
//   - Raw private key bytes are never stored in types exported from this crate.

pub mod cert;
pub mod delegation;
pub mod escalation;
pub mod plan;
pub mod plan_bundle;
pub mod pubkey;
pub mod token;
pub mod verify;

pub use cert::{
    canonicalize_ops, cert_canonical_signing_input, cert_status, sign_cert,
    validate_cert_structurally, verify_cert_self_signature, CertError, CertKind, CertStatus,
    OperatorCert,
};
pub use plan_bundle::{
    bundle_sha256, canonical_decode, canonical_encode, mint_bundle_nonce, sha256_of_artifact_bytes,
    signing_input, verify_plan_bundle_signature, PlanBundleCodecError, CANONICAL_INPUT_PREFIX,
    SIGNING_INPUT_PREFIX,
};
pub use pubkey::{parse_ed25519_public_material, PubkeyParseError};
pub use verify::{verify_ed25519, CryptoError};

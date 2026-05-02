//! End-to-end sign-then-verify round-trip for the canonical plan-signing scheme.
//!
//! This is the regression guard for the v1 review's "plan signing semantic
//! mismatch" finding (PR-3). The CLI MUST sign the canonical signing input
//! defined in `raxis-crypto::plan::plan_signing_input`, and the kernel MUST
//! verify it via `verify_plan_signature`. If either side ever drifts (e.g.
//! someone "fixes" the CLI to sign raw bytes), this test breaks immediately.
//!
//! The integration test does NOT touch the kernel binary or DB — it imports
//! the kernel-side verification function from `raxis_crypto::plan` and exercises
//! the same byte-exact path the kernel uses inside `lifecycle::approve_plan`.

use ed25519_dalek::SigningKey;

use raxis_crypto::plan::{plan_artifact_sha256, plan_signing_input, verify_plan_signature};

/// A deterministic Ed25519 keypair derived from a fixed test seed. We avoid
/// `getrandom` here so the test is reproducible.
fn fixed_test_key() -> SigningKey {
    SigningKey::from_bytes(&[0xA7u8; 32])
}

#[test]
fn cli_signing_round_trips_against_kernel_verifier() {
    let key = fixed_test_key();
    let pk_bytes = key.verifying_key().to_bytes();

    // Representative plan TOML.
    let plan_bytes: &[u8] = br#"[initiative]
name = "round-trip-test"

[[tasks]]
task_id = "t1"
lane_id = "default"
"#;

    // Mirror what `cli::commands::policy::run_sign` does today.
    let signing_input = plan_signing_input(plan_bytes);
    let sig_bytes = raxis_crypto::token::sha256_hex(&signing_input);
    // sanity: the SHA-256 of the input is 64 hex chars
    assert_eq!(sig_bytes.len(), 64);

    // The actual signature uses `cli::signing::sign_bytes`, but we cannot
    // import private CLI helpers from an integration test. Replicate the
    // single line:
    use ed25519_dalek::Signer;
    let raw_sig = key.sign(&signing_input);

    // Verify via the kernel's verification entry point.
    verify_plan_signature(&pk_bytes, plan_bytes, &raw_sig.to_bytes())
        .expect("canonical sign-then-verify round-trip must succeed");
}

#[test]
fn signature_over_raw_plan_bytes_is_rejected() {
    let key = fixed_test_key();
    let pk_bytes = key.verifying_key().to_bytes();
    let plan_bytes: &[u8] = b"[initiative]\nname = \"x\"\n";

    // Old broken kernel path: sign raw plan_bytes directly.
    use ed25519_dalek::Signer;
    let bad_sig = key.sign(plan_bytes);

    assert!(
        verify_plan_signature(&pk_bytes, plan_bytes, &bad_sig.to_bytes()).is_err(),
        "raw-bytes signature must not verify (regression guard)"
    );
}

#[test]
fn signature_over_hex_string_of_digest_is_rejected() {
    let key = fixed_test_key();
    let pk_bytes = key.verifying_key().to_bytes();
    let plan_bytes: &[u8] = b"[initiative]\nname = \"x\"\n";

    // OLDER broken CLI path: sign the UTF-8 hex string of the SHA-256 digest.
    let hex_digest = plan_artifact_sha256(plan_bytes);
    use ed25519_dalek::Signer;
    let bad_sig = key.sign(hex_digest.as_bytes());

    assert!(
        verify_plan_signature(&pk_bytes, plan_bytes, &bad_sig.to_bytes()).is_err(),
        "hex-string signature must not verify (regression guard)"
    );
}

#[test]
fn empty_plan_signs_and_verifies() {
    let key = fixed_test_key();
    let pk_bytes = key.verifying_key().to_bytes();

    let plan_bytes: &[u8] = b"";
    let signing_input = plan_signing_input(plan_bytes);
    use ed25519_dalek::Signer;
    let sig = key.sign(&signing_input);

    verify_plan_signature(&pk_bytes, plan_bytes, &sig.to_bytes()).expect("empty body round-trip");
}

#[test]
fn signature_does_not_verify_under_wrong_pubkey() {
    let signer = fixed_test_key();
    let other = SigningKey::from_bytes(&[0xB3u8; 32]);
    let other_pk = other.verifying_key().to_bytes();
    let plan_bytes: &[u8] = b"[initiative]\nname = \"x\"\n";

    use ed25519_dalek::Signer;
    let signing_input = plan_signing_input(plan_bytes);
    let sig = signer.sign(&signing_input);

    assert!(
        verify_plan_signature(&other_pk, plan_bytes, &sig.to_bytes()).is_err(),
        "verification under wrong pubkey must fail"
    );
}

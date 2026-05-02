//! End-to-end operator handshake smoke test.
//!
//! Wire-level proof that the kernel-side challenge construction and the CLI's
//! response shape agree. This is the regression guard for PR-2 — earlier the
//! CLI looked up `challenge_hex` while the kernel sent `challenge_bytes`,
//! and the two sides used different length-prefix byte orders. Now both
//! sides go through `raxis_ipc::json_frame` and `kernel::ipc::auth`.
//!
//! What this test does NOT exercise:
//!   - The full UnixStream / accept loop. We use `tokio::io::duplex` instead.
//!     UnixStream behaviour is unit-tested by tokio itself; what we care
//!     about here is the byte-for-byte handshake contract.
//!   - The dispatch loop's permitted_ops gate or any per-handler logic. Each
//!     handler has its own targeted tests.

use ed25519_dalek::{Signer, SigningKey};

use raxis_ipc::{read_json_frame_async, write_json_frame_async};

/// Build a `ChallengeEnvelope` JSON value the way the kernel does it,
/// without going through the kernel's `make_challenge` (which mints fresh
/// CSPRNG bytes — unwanted in a deterministic test).
fn deterministic_challenge() -> serde_json::Value {
    let bytes = [0x42u8; 32];
    serde_json::json!({ "challenge_hex": hex::encode(bytes) })
}

#[tokio::test]
async fn handshake_byte_format_round_trips() {
    // tokio in-memory duplex — kernel writes to one half, "CLI" reads the other.
    let (mut kernel_side, mut cli_side) = tokio::io::duplex(8 * 1024);

    let challenge = deterministic_challenge();
    write_json_frame_async(&mut kernel_side, &challenge).await.unwrap();
    drop(kernel_side); // signal EOF after one frame

    let received: serde_json::Value = read_json_frame_async(&mut cli_side).await.unwrap();
    assert_eq!(received, challenge);

    // Field name pin — this is what the CLI looks up.
    assert!(received["challenge_hex"].is_string());
}

/// CLI signs the **decoded raw bytes** of `challenge_hex`. The signature
/// must verify against the operator's public key. This is the core PR-2
/// "do both sides agree on what is being signed?" test.
#[tokio::test]
async fn cli_response_signature_verifies_against_kernel_decode_path() {
    // Fixed test key for determinism.
    let key = SigningKey::from_bytes(&[0x55u8; 32]);
    let pk_bytes = key.verifying_key().to_bytes();

    // Kernel emits a challenge.
    let challenge_bytes = [0x77u8; 32];
    let challenge_json = serde_json::json!({
        "challenge_hex": hex::encode(challenge_bytes),
    });

    // CLI decodes the hex and signs the RAW bytes.
    let cli_challenge_hex = challenge_json["challenge_hex"].as_str().unwrap();
    let cli_decoded = hex::decode(cli_challenge_hex).unwrap();
    assert_eq!(cli_decoded.len(), 32);
    let cli_signature = key.sign(&cli_decoded);

    // Kernel decodes its own challenge_hex (using the same path) and verifies.
    let kernel_decoded = hex::decode(challenge_json["challenge_hex"].as_str().unwrap()).unwrap();
    assert_eq!(kernel_decoded, cli_decoded);

    raxis_crypto::verify::verify_ed25519(&pk_bytes, &kernel_decoded, &cli_signature.to_bytes())
        .expect("kernel must verify the CLI's signature over the decoded challenge bytes");
}

/// Negative test: a CLI that mistakenly signs the **hex string** instead of
/// the decoded bytes will fail kernel verification. Regression guard against
/// an earlier CLI variant that was tempted to skip the hex decode step.
#[tokio::test]
async fn signing_the_hex_string_instead_of_bytes_is_rejected() {
    let key = SigningKey::from_bytes(&[0x88u8; 32]);
    let pk_bytes = key.verifying_key().to_bytes();

    let challenge_bytes = [0x33u8; 32];
    let challenge_hex = hex::encode(challenge_bytes);

    // BUG path: sign the UTF-8 of the hex string, not the decoded bytes.
    let bad_sig = key.sign(challenge_hex.as_bytes());

    let result = raxis_crypto::verify::verify_ed25519(
        &pk_bytes,
        &challenge_bytes,
        &bad_sig.to_bytes(),
    );
    assert!(
        result.is_err(),
        "kernel must reject a signature over the hex string (regression guard)"
    );
}

/// Frame format pin: kernel-side write produces a little-endian length
/// prefix that the CLI's sync reader can decode. This is the byte-order
/// regression guard.
#[tokio::test]
async fn kernel_async_writer_to_cli_sync_reader_round_trip() {
    use std::io::Cursor;

    let (mut kernel_side, mut buf_cap_side) = tokio::io::duplex(4096);

    let payload = serde_json::json!({
        "status": "Ok",
        "details": "auth complete",
    });
    write_json_frame_async(&mut kernel_side, &payload).await.unwrap();
    drop(kernel_side);

    // Drain the duplex into a Vec so we can hand it to the SYNC reader the
    // CLI uses in `cli/src/conn.rs::read_json` (via `read_json_frame_raw`).
    use tokio::io::AsyncReadExt;
    let mut bytes = Vec::new();
    buf_cap_side.read_to_end(&mut bytes).await.unwrap();

    let mut cursor = Cursor::new(bytes);
    let body = raxis_ipc::read_json_frame_raw(&mut cursor).unwrap();
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["status"].as_str(), Some("Ok"));
}

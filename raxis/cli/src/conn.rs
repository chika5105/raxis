// raxis-cli::conn — Operator UDS connection and challenge-response auth.
//
// Normative reference: cli-ceremony.md §4.1, peripherals.md §3 operator socket.
//
// Every kernel-connected command:
//   1. Opens the operator UDS.
//   2. Reads the ChallengeEnvelope (JSON, length-prefixed).
//   3. Computes Ed25519 signature over the decoded challenge bytes.
//   4. Sends ResponseEnvelope (JSON, length-prefixed).
//   5. Reads the ACK or error.
//   6. Sends the OperatorRequest (JSON, length-prefixed).
//   7. Reads the OperatorResponse.
//
// Wire framing routes through `raxis_ipc::json_frame::{read_json_frame,
// write_json_frame}` — the SAME helper the kernel uses on the other side
// (kernel/src/ipc/operator.rs). Earlier the CLI used a hand-rolled
// big-endian length prefix while the kernel used hand-rolled little-endian;
// the two never connected end-to-end. PR-2 unifies on one helper to make
// drift impossible — see cli/tests/operator_socket_smoke.rs and
// crates/ipc/src/json_frame.rs::tests for the regression guards.

use std::os::unix::net::UnixStream;
use std::path::Path;

use raxis_ipc::{read_json_frame_raw, write_json_frame, JsonFrameError};
use serde_json::Value;

use crate::errors::CliError;
use crate::signing::{load_operator_key, sign_bytes};

pub struct OperatorConn {
    pub stream: UnixStream,
    pub operator_fingerprint: String,
}

impl OperatorConn {
    /// Open connection to the operator socket and complete the challenge-response handshake.
    ///
    /// `key_path` is the operator's Ed25519 private key (PEM or raw hex seed).
    /// `fingerprint` is the SHA-256[:16] hex fingerprint of the operator's public key.
    pub fn connect(
        socket_path: &Path,
        key_path: &Path,
        fingerprint: &str,
    ) -> Result<Self, CliError> {
        if !socket_path.exists() {
            return Err(CliError::SocketNotFound {
                path: socket_path.display().to_string(),
            });
        }

        let mut stream = UnixStream::connect(socket_path)?;

        // Step 1: Read ChallengeEnvelope from kernel.
        let challenge: Value = read_json(&mut stream)?;
        let challenge_hex = challenge["challenge_hex"]
            .as_str()
            .ok_or_else(|| CliError::AuthFailed("missing challenge_hex".to_owned()))?;
        let challenge_bytes = hex::decode(challenge_hex)?;
        if challenge_bytes.len() != 32 {
            return Err(CliError::AuthFailed(format!(
                "challenge_hex must decode to 32 bytes, got {}",
                challenge_bytes.len()
            )));
        }

        // Step 2: Sign the raw 32-byte challenge with the operator private key.
        // The signature is over the DECODED bytes, not the hex string —
        // kernel-side `auth::verify_response` decodes `challenge_hex` and
        // verifies against those bytes.
        let signing_key = load_operator_key(key_path)?;
        let sig_hex = sign_bytes(&signing_key, &challenge_bytes);

        // Step 3: Send ResponseEnvelope. Field names MUST match
        // `raxis_kernel::ipc::auth::ResponseEnvelope`: `fingerprint` and
        // `signed_challenge_hex`. (Earlier drafts used `signed_challenge`,
        // which the kernel rejects.)
        let response = serde_json::json!({
            "fingerprint": fingerprint,
            "signed_challenge_hex": sig_hex,
        });
        write_json_frame(&mut stream, &response).map_err(map_frame_err)?;

        // Step 4: Read auth ACK.
        let ack: Value = read_json(&mut stream)?;
        if ack["status"].as_str() != Some("Ok") {
            let reason = ack["reason"].as_str().unwrap_or("unknown");
            return Err(CliError::AuthFailed(format!("kernel rejected auth: {reason}")));
        }

        Ok(OperatorConn {
            stream,
            operator_fingerprint: fingerprint.to_owned(),
        })
    }

    /// Send an OperatorRequest and receive the OperatorResponse.
    pub fn send_request(&mut self, req: &Value) -> Result<Value, CliError> {
        write_json_frame(&mut self.stream, req).map_err(map_frame_err)?;
        read_json(&mut self.stream)
    }
}

// ---------------------------------------------------------------------------
// Helpers: blocking JSON frame round-trip on a UnixStream
// ---------------------------------------------------------------------------

/// Read one length-prefixed JSON frame and parse it as `serde_json::Value`.
fn read_json(stream: &mut UnixStream) -> Result<Value, CliError> {
    let body = read_json_frame_raw(stream).map_err(map_frame_err)?;
    serde_json::from_str(&body).map_err(CliError::Json)
}

/// Translate `JsonFrameError` into the CLI's error type. We treat framing
/// errors as auth-flow failures because they universally indicate either a
/// kernel / CLI version mismatch or a corrupt UDS connection.
fn map_frame_err(e: JsonFrameError) -> CliError {
    match e {
        JsonFrameError::Io(io) => CliError::Socket(io),
        other => CliError::AuthFailed(other.to_string()),
    }
}

/// Derive the SHA-256[:16] fingerprint from a raw Ed25519 public key (32 bytes).
///
/// Used when the CLI needs to compute its operator fingerprint from a loaded key.
pub fn pubkey_fingerprint(pubkey_bytes: &[u8]) -> String {
    let hash = raxis_crypto::token::sha256_hex(pubkey_bytes);
    hash[..32].to_owned() // first 32 hex chars = 16 bytes of SHA-256
}

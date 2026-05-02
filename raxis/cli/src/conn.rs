// raxis-cli::conn — Operator UDS connection and challenge-response auth.
//
// Normative reference: cli-ceremony.md §4.1, peripherals.md §3 operator socket.
//
// Every kernel-connected command:
//   1. Opens the operator UDS.
//   2. Reads the ChallengeEnvelope (JSON, length-prefixed).
//   3. Computes Ed25519 signature over challenge_bytes.
//   4. Sends ResponseEnvelope (JSON, length-prefixed).
//   5. Reads the ACK or error.
//   6. Sends the OperatorRequest (JSON, length-prefixed).
//   7. Reads the OperatorResponse.
//
// Length-prefixed framing: 4-byte big-endian length prefix followed by JSON payload.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;

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
        let challenge_json = read_frame(&mut stream)?;
        let challenge: Value = serde_json::from_str(&challenge_json)?;
        let challenge_hex = challenge["challenge_hex"]
            .as_str()
            .ok_or_else(|| CliError::AuthFailed("missing challenge_hex".to_owned()))?;
        let challenge_bytes = hex::decode(challenge_hex)?;

        // Step 2: Sign challenge with operator private key.
        let signing_key = load_operator_key(key_path)?;
        let sig_hex = sign_bytes(&signing_key, &challenge_bytes);

        // Step 3: Send ResponseEnvelope.
        let response = serde_json::json!({
            "fingerprint": fingerprint,
            "signed_challenge_hex": sig_hex,
        });
        write_frame(&mut stream, &response.to_string())?;

        // Step 4: Read auth ACK.
        let ack_json = read_frame(&mut stream)?;
        let ack: Value = serde_json::from_str(&ack_json)?;
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
        write_frame(&mut self.stream, &req.to_string())?;
        let resp_json = read_frame(&mut self.stream)?;
        let resp: Value = serde_json::from_str(&resp_json)?;
        Ok(resp)
    }
}

// ---------------------------------------------------------------------------
// Frame codec: 4-byte big-endian length prefix + JSON payload
// ---------------------------------------------------------------------------

pub fn read_frame(stream: &mut UnixStream) -> Result<String, CliError> {
    let mut len_bytes = [0u8; 4];
    stream.read_exact(&mut len_bytes)?;
    let len = u32::from_be_bytes(len_bytes) as usize;

    // Sanity cap: 64 MiB.
    if len > 64 * 1024 * 1024 {
        return Err(CliError::AuthFailed(format!("frame too large: {len} bytes")));
    }

    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf)?;
    String::from_utf8(buf).map_err(|e| {
        CliError::AuthFailed(format!("non-UTF-8 frame: {e}"))
    })
}

pub fn write_frame(stream: &mut UnixStream, payload: &str) -> Result<(), CliError> {
    let bytes = payload.as_bytes();
    let len = bytes.len() as u32;
    stream.write_all(&len.to_be_bytes())?;
    stream.write_all(bytes)?;
    stream.flush()?;
    Ok(())
}

/// Derive the SHA-256[:16] fingerprint from a raw Ed25519 public key (32 bytes).
///
/// Used when the CLI needs to compute its operator fingerprint from a loaded key.
pub fn pubkey_fingerprint(pubkey_bytes: &[u8]) -> String {
    let hash = raxis_crypto::token::sha256_hex(pubkey_bytes);
    hash[..32].to_owned() // first 32 hex chars = 16 bytes of SHA-256
}

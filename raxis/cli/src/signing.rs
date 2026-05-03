// raxis-cli::signing — Operator Ed25519 signing utilities.
//
// Normative reference: cli-ceremony.md §4.1 (policy sign, delegation grant,
// escalation approve) and kernel-store.md §2.5.5 (delegation signing domain).
//
// The operator's private key is NEVER sent to the kernel. Signing happens
// locally in the CLI process; only the resulting Ed25519 signature is sent.

use std::path::Path;

use ed25519_dalek::VerifyingKey;

use crate::errors::CliError;

/// Parse an operator **public** Ed25519 key from file contents:
/// either **64-char lowercase/uppercase hex** (raw 32 bytes) or **`openssl`**-style
/// **PEM** (`-----BEGIN PUBLIC KEY-----` wrapping RFC 8410 SPKI DER).
///
/// Genesis and interactive pubkey paste paths use this so `--operator-pubkey
/// operator_public.pem` matches what operators generate locally.
pub fn parse_operator_public_key_material(content: &str) -> Result<[u8; 32], CliError> {
    let trimmed = content.trim();

    if trimmed.len() == 64 && trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
        let vec = hex::decode(trimmed).map_err(|e| CliError::Key(format!("hex decode error: {e}")))?;
        let arr: [u8; 32] = vec
            .try_into()
            .map_err(|_| CliError::Key("operator pubkey must be 32 bytes (64 hex chars)".to_owned()))?;
        VerifyingKey::from_bytes(&arr).map_err(|e| CliError::Key(format!("invalid Ed25519 pubkey: {e}")))?;
        return Ok(arr);
    }

    if trimmed.starts_with("-----BEGIN") {
        let b64: String = trimmed
            .lines()
            .filter(|l| !l.starts_with("-----"))
            .collect::<Vec<_>>()
            .join("");
        let der =
            base64_decode(&b64).map_err(|e| CliError::Key(format!("PEM base64 decode failed: {e}")))?;
        let pubkey: [u8; 32] = ed25519_pubkey_bytes_from_spki_der(&der)?;
        VerifyingKey::from_bytes(&pubkey)
            .map_err(|e| CliError::Key(format!("invalid Ed25519 pubkey in PEM: {e}")))?;
        return Ok(pubkey);
    }

    Err(CliError::Key(
        "operator public key: expected 64-char hex or PEM (-----BEGIN PUBLIC KEY-----); \
         for PEM files use: raxis genesis --operator-pubkey /path/to/operator_public.pem"
            .to_owned(),
    ))
}

/// OpenSSL / RFC 8410 SubjectPublicKeyInfo for Ed25519 is **44 bytes**; the raw
/// 32-byte public key starts at offset **12** (after algorithm OID + BIT STRING wrapper).
fn ed25519_pubkey_bytes_from_spki_der(der: &[u8]) -> Result<[u8; 32], CliError> {
    match der.len() {
        44 => der[12..44]
            .try_into()
            .map_err(|_| CliError::Key("internal: Ed25519 SPKI slice".to_owned())),
        32 => der
            .try_into()
            .map_err(|_| CliError::Key("internal: raw 32-byte pubkey".to_owned())),
        n => Err(CliError::Key(format!(
            "unsupported Ed25519 public key encoding: DER is {n} bytes (expected 44-byte SPKI or 32 raw)"
        ))),
    }
}

/// Load an Ed25519 keypair from a PEM file.
///
/// Expects either:
///   - A PKCS#8 v2 Ed25519 private key PEM ("BEGIN PRIVATE KEY")
///   - A raw 32-byte seed hex string (for test convenience)
pub fn load_operator_key(path: &Path) -> Result<ed25519_dalek::SigningKey, CliError> {
    let pem = std::fs::read_to_string(path).map_err(|e| CliError::Io {
        path: path.display().to_string(),
        source: e,
    })?;

    // Try raw 32-byte hex seed first (test convenience format).
    let trimmed = pem.trim();
    if trimmed.len() == 64 && trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
        let seed_bytes = hex::decode(trimmed)?;
        let seed: [u8; 32] = seed_bytes
            .try_into()
            .map_err(|_| CliError::Key("seed is not 32 bytes".to_owned()))?;
        return Ok(ed25519_dalek::SigningKey::from_bytes(&seed));
    }

    // Extract base64 payload from PEM.
    let b64: String = pem
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect::<Vec<_>>()
        .join("");

    let der = base64_decode(&b64)
        .map_err(|e| CliError::Key(format!("PEM base64 decode failed: {e}")))?;

    // PKCS#8 Ed25519 key: last 32 bytes are the raw seed.
    // A minimal PKCS#8 Ed25519 DER is 48 bytes; the seed is the last 32.
    if der.len() >= 32 {
        let seed: [u8; 32] = der[der.len() - 32..]
            .try_into()
            .map_err(|_| CliError::Key("could not extract seed from DER".to_owned()))?;
        return Ok(ed25519_dalek::SigningKey::from_bytes(&seed));
    }

    Err(CliError::Key("unsupported key format".to_owned()))
}

/// Sign `message` with the operator signing key.
///
/// Returns the 64-byte Ed25519 signature as a hex string.
pub fn sign_bytes(key: &ed25519_dalek::SigningKey, message: &[u8]) -> String {
    use ed25519_dalek::Signer;
    let sig = key.sign(message);
    hex::encode(sig.to_bytes())
}

/// Build the canonical signing-domain bytes for a delegation grant.
///
/// Format per kernel-store.md §2.5.5:
///   "RAXIS-V1-DELEGATION-GRANT" || 0x00
///   || session_id (UUID hyphenated) || 0x00
///   || capability_class || 0x00
///   || role_id || 0x00
///   || expires_at_le_u64 (8 bytes little-endian)
///   || 0x00
///   || scope_json_present_byte (0x00 = absent, 0x01 = present)
///   || (if present: scope_json_len_le_u32 as 4 bytes LE || scope_json_bytes)
pub fn delegation_grant_signing_domain(
    session_id: &str,
    capability_class: &str,
    role_id: &str,
    expires_at: u64,
    scope_json: Option<&str>,
) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(b"RAXIS-V1-DELEGATION-GRANT");
    buf.push(0x00);
    buf.extend_from_slice(session_id.as_bytes());
    buf.push(0x00);
    buf.extend_from_slice(capability_class.as_bytes());
    buf.push(0x00);
    buf.extend_from_slice(role_id.as_bytes());
    buf.push(0x00);
    buf.extend_from_slice(&expires_at.to_le_bytes());
    buf.push(0x00);
    match scope_json {
        None => buf.push(0x00),
        Some(json) => {
            buf.push(0x01);
            let json_bytes = json.as_bytes();
            buf.extend_from_slice(&(json_bytes.len() as u32).to_le_bytes());
            buf.extend_from_slice(json_bytes);
        }
    }
    buf
}

// ---------------------------------------------------------------------------
// Minimal base64 decoder (avoids adding a dep for a 30-line function)
// ---------------------------------------------------------------------------

pub(crate) fn base64_decode(s: &str) -> Result<Vec<u8>, String> {
    let table: [u8; 256] = {
        let mut t = [255u8; 256];
        for (i, &c) in b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
            .iter()
            .enumerate()
        {
            t[c as usize] = i as u8;
        }
        t['=' as usize] = 0;
        t
    };

    let bytes: Vec<u8> = s.bytes().filter(|&b| b != b'\n' && b != b'\r').collect();
    if bytes.len() % 4 != 0 {
        return Err("invalid base64 length".to_owned());
    }

    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    for chunk in bytes.chunks(4) {
        let a = table[chunk[0] as usize];
        let b = table[chunk[1] as usize];
        let c = table[chunk[2] as usize];
        let d = table[chunk[3] as usize];
        if a == 255 || b == 255 {
            return Err("invalid base64 character".to_owned());
        }
        out.push((a << 2) | (b >> 4));
        if chunk[2] != b'=' {
            out.push((b << 4) | (c >> 2));
        }
        if chunk[3] != b'=' {
            out.push((c << 6) | d);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Sample `openssl pkey -pubout` PEM (Ed25519 SPKI DER length 44).
    const SAMPLE_PEM: &str = "-----BEGIN PUBLIC KEY-----\n\
MCowBQYDK2VwAyEAB0zQxEa3aAatS9pffcLP416Kki9VPms3q15Kyl3cFEI=\n\
-----END PUBLIC KEY-----\n";

    #[test]
    fn parse_operator_public_hex_round_trip() {
        let bytes = parse_operator_public_key_material(SAMPLE_PEM).expect("pem");
        let h = hex::encode(bytes);
        let again = parse_operator_public_key_material(&h).expect("hex round-trip");
        assert_eq!(again, bytes);
    }

    #[test]
    fn parse_operator_public_pem_openssl_subject_public_key_info() {
        let bytes = parse_operator_public_key_material(SAMPLE_PEM).expect("pem");
        let _vk = VerifyingKey::from_bytes(&bytes).expect("dalek verifies");
        assert_eq!(
            hex::encode(bytes).len(),
            64,
            "stored policy form is 64-char hex"
        );
    }

    #[test]
    fn parse_operator_public_hex_accepts_uppercase() {
        let bytes = parse_operator_public_key_material(SAMPLE_PEM).expect("pem");
        let mixed = hex::encode(bytes).to_uppercase();
        let got = parse_operator_public_key_material(&mixed).expect("uppercase hex");
        assert_eq!(got, bytes);
    }

    #[test]
    fn parse_operator_public_hex_trims_surrounding_whitespace() {
        let bytes = parse_operator_public_key_material(SAMPLE_PEM).expect("pem");
        let h = hex::encode(bytes);
        let padded = format!("\n\t  {h}  \r\n");
        let got = parse_operator_public_key_material(&padded).expect("trimmed hex");
        assert_eq!(got, bytes);
    }

    #[test]
    fn parse_operator_public_pem_accepts_crlf_and_blank_lines() {
        let pem = "-----BEGIN PUBLIC KEY-----\r\n\r\nMCowBQYDK2VwAyEAB0zQxEa3aAatS9pffcLP416Kki9VPms3q15Kyl3cFEI=\r\n\r\n-----END PUBLIC KEY-----\r\n";
        let a = parse_operator_public_key_material(SAMPLE_PEM).expect("lf pem");
        let b = parse_operator_public_key_material(pem).expect("crlf pem");
        assert_eq!(a, b);
    }

    #[test]
    fn parse_operator_public_rejects_non_64_hex_without_pem_header() {
        let err = parse_operator_public_key_material(&"a".repeat(63)).expect_err("63 chars");
        let msg = format!("{err}");
        assert!(
            msg.contains("expected 64-char hex") || msg.contains("operator public key"),
            "{msg}"
        );
    }

    #[test]
    fn parse_operator_public_pem_rejects_wrong_der_length() {
        // Valid base64 that decodes to 8 bytes — not 32 raw nor 44-byte SPKI.
        let pem = "-----BEGIN PUBLIC KEY-----\n\
wjukMjM=\n\
-----END PUBLIC KEY-----\n";
        let err = parse_operator_public_key_material(pem).expect_err("short der");
        let msg = format!("{err}");
        assert!(
            msg.contains("unsupported Ed25519 public key encoding") || msg.contains("DER"),
            "{msg}"
        );
    }

    #[test]
    fn parse_operator_public_pem_rejects_invalid_base64_payload() {
        let pem = "-----BEGIN PUBLIC KEY-----\n!!!!\n-----END PUBLIC KEY-----\n";
        let err = parse_operator_public_key_material(pem).expect_err("bad b64");
        let msg = format!("{err}");
        assert!(
            msg.contains("base64") || msg.contains("PEM") || msg.contains("invalid"),
            "{msg}"
        );
    }
}

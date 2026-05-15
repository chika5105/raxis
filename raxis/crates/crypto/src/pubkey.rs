// raxis-crypto::pubkey — Operator-supplied Ed25519 public-key material parser.
//
// Normative reference:
//   * cli-ceremony.md §4.2 step 5 — `--operator-pubkey` accepted formats
//   * kernel-store.md §2.5.4   — operator key inventory (32-byte raw Ed25519)
//
// What this module does
// ─────────────────────
// Operators generate their Ed25519 keypair with `openssl pkey -pubout`,
// which produces a PEM-wrapped RFC 8410 SubjectPublicKeyInfo (SPKI). The
// rest of the kernel and CLI work with the raw 32-byte public key (or its
// 64-character hex form). This module bridges the two: it accepts either
//
//   * a 64-character lowercase/uppercase hex string (raw 32 bytes hex-encoded), or
//   * an OpenSSL-style PEM block whose payload is a 44-byte SPKI DER (the
//     standard Ed25519 public-key encoding) or a 32-byte raw key, and
//
// returns the 32-byte raw public key after a self-test through
// `ed25519_dalek::VerifyingKey::from_bytes`.
//
// Why this lives in `raxis-crypto`
// ────────────────────────────────
// Until this module landed, the parser lived only in
// `cli/src/signing.rs::parse_operator_public_key_material`, while the
// kernel's `bootstrap::load_operator_pubkey` path accepted ONLY hex.
// Operators following the README's openssl invocation got
//
//     BOOT_ERR_BOOTSTRAP_FAILED: hex decode failed: Invalid character '-' at position 0
//
// when running `RAXIS_BOOTSTRAP=1 raxis-kernel` with `RAXIS_OPERATOR_PUBKEY`
// pointed at a `.pem` file. The shared crate is the natural home: every
// crate that has to interpret operator-supplied key bytes (`raxis-cli`,
// `raxis-kernel`, future tooling) already depends on `raxis-crypto`.
//
// Stability
// ─────────
// Adding a new accepted encoding is a kernel-store §2.5.4 spec amendment
// first; this module then reflects the new shape and pins it with an
// updated round-trip test.

#![forbid(unsafe_code)]

use ed25519_dalek::VerifyingKey;
use thiserror::Error;

/// Failure modes for `parse_ed25519_public_material`. Distinct from
/// `CryptoError` because the parser deals with operator-typed input
/// formats — the diagnostics speak about hex vs PEM, not about
/// signature verification.
#[derive(Debug, Error)]
pub enum PubkeyParseError {
    /// Input was a hex string (only ASCII hex digits and the right
    /// length to maybe be hex) but `hex::decode` rejected it.
    #[error("hex decode error: {0}")]
    HexDecode(#[from] hex::FromHexError),

    /// PEM payload could not be base64-decoded. The PEM markers
    /// (`-----BEGIN ... -----`) were stripped before decoding, so any
    /// failure here is on the base64 body itself.
    #[error("PEM base64 decode failed: {0}")]
    Base64(String),

    /// Decoded DER was neither a 44-byte Ed25519 SPKI nor a raw 32-byte
    /// key. Includes the actual length so operators get an actionable
    /// hint when they pasted a different algorithm's key by mistake.
    #[error("unsupported Ed25519 public key encoding: DER is {len} bytes (expected 44-byte SPKI or 32 raw)")]
    UnsupportedDerLength { len: usize },

    /// `ed25519_dalek::VerifyingKey::from_bytes` rejected the 32 bytes —
    /// the bytes are syntactically a key but the point is invalid.
    #[error("invalid Ed25519 public key: {0}")]
    InvalidPublicKey(String),

    /// Input is neither a 64-character hex string nor a PEM block. The
    /// message names both accepted formats so the operator can pick.
    #[error("operator public key: expected 64-char hex or PEM (-----BEGIN PUBLIC KEY-----)")]
    UnknownEncoding,
}

/// Parse operator-supplied Ed25519 public-key material from a string.
///
/// Accepts:
///   * 64-character hex (lowercase or uppercase, surrounding whitespace
///     trimmed) — raw 32-byte public key hex-encoded.
///   * PEM block starting with `-----BEGIN`. The payload may be a 44-byte
///     RFC 8410 SubjectPublicKeyInfo (the standard `openssl pkey -pubout`
///     output) or a raw 32-byte public key.
///
/// Returns the 32 raw bytes after a `VerifyingKey::from_bytes` self-test
/// — callers can rely on the result being a valid Ed25519 public key.
///
/// This function is **pure** (no I/O, no logging, no clock). The kernel
/// and the CLI both invoke it after reading the file or stdin into a
/// `String`, so the I/O contract stays at the call site.
pub fn parse_ed25519_public_material(content: &str) -> Result<[u8; 32], PubkeyParseError> {
    let trimmed = content.trim();

    // Hex form first — the kernel's older bootstrap path emitted hex by
    // default, and the wire-level `policy.toml` operator entry is also
    // hex, so this is the most common input.
    if trimmed.len() == 64 && trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
        let vec = hex::decode(trimmed)?;
        let arr: [u8; 32] = vec
            .try_into()
            .expect("64 hex chars decode to exactly 32 bytes");
        VerifyingKey::from_bytes(&arr)
            .map_err(|e| PubkeyParseError::InvalidPublicKey(e.to_string()))?;
        return Ok(arr);
    }

    // PEM form — operators running `openssl pkey -pubout` get this shape.
    if trimmed.starts_with("-----BEGIN") {
        let b64: String = trimmed
            .lines()
            .filter(|l| !l.starts_with("-----"))
            .collect::<Vec<_>>()
            .join("");
        let der = base64_decode(&b64).map_err(PubkeyParseError::Base64)?;
        let pubkey = ed25519_pubkey_bytes_from_spki_der(&der)?;
        VerifyingKey::from_bytes(&pubkey)
            .map_err(|e| PubkeyParseError::InvalidPublicKey(e.to_string()))?;
        return Ok(pubkey);
    }

    Err(PubkeyParseError::UnknownEncoding)
}

/// Slice the raw 32-byte public key out of an Ed25519 SPKI DER blob.
///
/// RFC 8410 SubjectPublicKeyInfo for Ed25519 is **44 bytes**; the raw
/// 32-byte public key starts at offset **12** (after the algorithm OID
/// and the BIT STRING wrapper). We also accept a bare 32-byte input so
/// hand-crafted key files (testing, hardware import paths) work.
fn ed25519_pubkey_bytes_from_spki_der(der: &[u8]) -> Result<[u8; 32], PubkeyParseError> {
    match der.len() {
        44 => Ok(der[12..44]
            .try_into()
            .expect("slice [12..44] of a 44-byte vector is exactly 32 bytes")),
        32 => Ok(der
            .try_into()
            .expect("slice of length 32 fits exactly into [u8; 32]")),
        n => Err(PubkeyParseError::UnsupportedDerLength { len: n }),
    }
}

// ---------------------------------------------------------------------------
// Minimal base64 decoder — kept private to this module.
//
// Avoids pulling a `base64` crate dep through every workspace member that
// already depends on `raxis-crypto`. The decoder only needs to handle the
// canonical RFC 4648 alphabet plus padding; the inputs are operator-pasted
// PEM payloads (i.e. controlled by the operator), not arbitrary network
// data, so the surface area stays narrow.
// ---------------------------------------------------------------------------

fn base64_decode(s: &str) -> Result<Vec<u8>, String> {
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

    /// `openssl pkey -pubout` PEM (Ed25519 SPKI DER, 44 bytes).
    const SAMPLE_PEM: &str = "-----BEGIN PUBLIC KEY-----\n\
MCowBQYDK2VwAyEAB0zQxEa3aAatS9pffcLP416Kki9VPms3q15Kyl3cFEI=\n\
-----END PUBLIC KEY-----\n";

    #[test]
    fn pem_round_trip_through_hex() {
        let bytes = parse_ed25519_public_material(SAMPLE_PEM).expect("pem");
        let h = hex::encode(bytes);
        let again = parse_ed25519_public_material(&h).expect("hex round-trip");
        assert_eq!(again, bytes);
    }

    #[test]
    fn pem_yields_a_valid_dalek_verifying_key() {
        let bytes = parse_ed25519_public_material(SAMPLE_PEM).expect("pem");
        let _vk = VerifyingKey::from_bytes(&bytes).expect("dalek verifies");
    }

    #[test]
    fn hex_accepts_uppercase() {
        let bytes = parse_ed25519_public_material(SAMPLE_PEM).expect("pem");
        let mixed = hex::encode(bytes).to_uppercase();
        let got = parse_ed25519_public_material(&mixed).expect("uppercase hex");
        assert_eq!(got, bytes);
    }

    #[test]
    fn hex_trims_surrounding_whitespace() {
        let bytes = parse_ed25519_public_material(SAMPLE_PEM).expect("pem");
        let h = hex::encode(bytes);
        let padded = format!("\n\t  {h}  \r\n");
        let got = parse_ed25519_public_material(&padded).expect("trimmed hex");
        assert_eq!(got, bytes);
    }

    #[test]
    fn pem_accepts_crlf_and_blank_lines() {
        let pem = "-----BEGIN PUBLIC KEY-----\r\n\r\nMCowBQYDK2VwAyEAB0zQxEa3aAatS9pffcLP416Kki9VPms3q15Kyl3cFEI=\r\n\r\n-----END PUBLIC KEY-----\r\n";
        let a = parse_ed25519_public_material(SAMPLE_PEM).expect("lf pem");
        let b = parse_ed25519_public_material(pem).expect("crlf pem");
        assert_eq!(a, b);
    }

    #[test]
    fn rejects_non_64_hex_without_pem_header() {
        let err = parse_ed25519_public_material(&"a".repeat(63))
            .expect_err("63-char hex must not parse — that length is the surface check");
        match err {
            PubkeyParseError::UnknownEncoding => {}
            other => panic!("expected UnknownEncoding, got {other:?}"),
        }
    }

    #[test]
    fn pem_rejects_wrong_der_length() {
        // Valid base64 that decodes to 5 bytes (`wjukMjM=` →
        // [0xc2,0x3b,0xa4,0x32,0x33]) — neither 32 raw nor 44-byte SPKI.
        // Pin the structured error variant + the reported length so a
        // future "support raw 32 OR raw 64 OR …" change has to update
        // this test deliberately.
        let pem = "-----BEGIN PUBLIC KEY-----\n\
wjukMjM=\n\
-----END PUBLIC KEY-----\n";
        match parse_ed25519_public_material(pem).expect_err("short der") {
            PubkeyParseError::UnsupportedDerLength { len: 5 } => {}
            other => panic!("expected UnsupportedDerLength {{ len: 5 }}, got {other:?}"),
        }
    }

    #[test]
    fn pem_rejects_invalid_base64_payload() {
        let pem = "-----BEGIN PUBLIC KEY-----\n!!!!\n-----END PUBLIC KEY-----\n";
        match parse_ed25519_public_material(pem).expect_err("bad b64") {
            PubkeyParseError::Base64(_) => {}
            other => panic!("expected Base64 error, got {other:?}"),
        }
    }

    #[test]
    fn message_for_unknown_encoding_names_both_supported_formats() {
        // The error message is what the operator sees on stderr; pin it
        // so a future "make this terser" PR doesn't drop the hex/PEM
        // hint that's the whole reason the parser exists.
        let err = parse_ed25519_public_material("not-a-key").expect_err("invalid");
        let msg = err.to_string();
        assert!(msg.contains("hex"), "diagnostic must mention hex: {msg}");
        assert!(msg.contains("PEM"), "diagnostic must mention PEM: {msg}");
    }
}

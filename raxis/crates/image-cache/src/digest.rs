//! `OciDigest` typed wrapper.
//!
//! Pinned by `image-cache.md §5`: every `[[vm_images]] oci_digest`
//! reference in policy and every `task.vm_image`-derived recorded
//! digest on the initiative row arrives at the resolver as exactly
//! one shape — `sha256:<64 lowercase hex>`. This module is the
//! single place that contract is enforced.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::{SHA256_LEN_BYTES, SHA256_LEN_HEX};

/// **An OCI image digest** in the canonical
/// `algorithm:hex` form. V2 supports `sha256:` only.
///
/// Construction goes through [`FromStr`] / [`OciDigest::from_sha256_bytes`];
/// neither path lets a malformed value through. The internal
/// representation is the raw 32-byte SHA-256, so equality and
/// hashing are O(1) — the rendered form is reconstructed on
/// demand.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct OciDigest {
    bytes: [u8; SHA256_LEN_BYTES],
}

impl OciDigest {
    /// Construct from raw 32-byte SHA-256.
    pub const fn from_sha256_bytes(bytes: [u8; SHA256_LEN_BYTES]) -> Self {
        Self { bytes }
    }

    /// Borrow the raw 32 bytes.
    pub const fn as_bytes(&self) -> &[u8; SHA256_LEN_BYTES] {
        &self.bytes
    }

    /// Render the canonical `sha256:<64 lowercase hex>` form.
    pub fn to_canonical_string(&self) -> String {
        let mut s = String::with_capacity(7 + SHA256_LEN_HEX);
        s.push_str("sha256:");
        s.push_str(&hex::encode(self.bytes));
        s
    }

    /// The two-character cache shard prefix — the first two hex
    /// chars of the digest. Used by [`crate::CacheLayout`] to keep
    /// each `blobs/sha256/<aa>/` directory under a few hundred
    /// entries.
    pub fn shard_prefix(&self) -> String {
        hex::encode(&self.bytes[..1])
    }
}

impl fmt::Display for OciDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_canonical_string())
    }
}

impl FromStr for OciDigest {
    type Err = OciDigestParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let rest = s
            .strip_prefix("sha256:")
            .ok_or(OciDigestParseError::WrongAlgorithm)?;
        if rest.len() != SHA256_LEN_HEX {
            return Err(OciDigestParseError::WrongLength {
                expected_hex_chars: SHA256_LEN_HEX,
                got_hex_chars: rest.len(),
            });
        }
        // Reject uppercase. The OCI distribution spec is silent on
        // case, but every real-world registry emits lowercase and
        // case-folding silently here would let two semantically-
        // identical references hash differently.
        if rest.bytes().any(|b| matches!(b, b'A'..=b'F')) {
            return Err(OciDigestParseError::NonLowercaseHex);
        }
        let raw = hex::decode(rest).map_err(|_| OciDigestParseError::NonHexCharacter)?;
        let mut bytes = [0u8; SHA256_LEN_BYTES];
        bytes.copy_from_slice(&raw);
        Ok(Self { bytes })
    }
}

impl TryFrom<String> for OciDigest {
    type Error = OciDigestParseError;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::from_str(&s)
    }
}

impl From<OciDigest> for String {
    fn from(d: OciDigest) -> Self {
        d.to_canonical_string()
    }
}

/// Parse failures for [`OciDigest::from_str`]. Surfaced through
/// `ImageResolverError::OciDigestParse` when the kernel session-
/// spawn path receives a malformed value (which would itself be a
/// shift-left-failure-of approve_plan and the kernel maps it as
/// such).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum OciDigestParseError {
    /// Missing the `sha256:` prefix. V2 supports SHA-256 only.
    #[error("expected `sha256:` prefix")]
    WrongAlgorithm,
    /// Hex section has the wrong length.
    #[error("expected {expected_hex_chars} hex chars after `sha256:`; got {got_hex_chars}")]
    WrongLength {
        /// What we expect (constant 64).
        expected_hex_chars: usize,
        /// What the caller supplied.
        got_hex_chars: usize,
    },
    /// Hex section contains an uppercase A-F char. Rejected
    /// deliberately (see `from_str`).
    #[error("digest hex must be lowercase")]
    NonLowercaseHex,
    /// Hex section contains a non-hex character.
    #[error("digest hex contains a non-hex character")]
    NonHexCharacter,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(s: &str) -> Result<OciDigest, OciDigestParseError> {
        s.parse()
    }

    #[test]
    fn parse_accepts_canonical_form() {
        let d = parse("sha256:abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234")
            .unwrap();
        assert_eq!(d.as_bytes()[0], 0xab);
        assert_eq!(d.as_bytes()[31], 0x34);
        assert_eq!(
            d.to_canonical_string(),
            "sha256:abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234",
        );
    }

    #[test]
    fn parse_rejects_missing_algorithm_prefix() {
        let err =
            parse("abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234").unwrap_err();
        assert_eq!(err, OciDigestParseError::WrongAlgorithm);
    }

    #[test]
    fn parse_rejects_non_sha256_algorithm() {
        let err = parse("md5:abcd1234abcd1234abcd1234abcd1234").unwrap_err();
        assert_eq!(err, OciDigestParseError::WrongAlgorithm);
    }

    #[test]
    fn parse_rejects_short_hex() {
        let err = parse("sha256:abcd").unwrap_err();
        assert!(matches!(
            err,
            OciDigestParseError::WrongLength {
                expected_hex_chars: 64,
                got_hex_chars: 4
            },
        ));
    }

    #[test]
    fn parse_rejects_long_hex() {
        let s = format!("sha256:{}", "a".repeat(65));
        let err = parse(&s).unwrap_err();
        assert!(matches!(
            err,
            OciDigestParseError::WrongLength {
                expected_hex_chars: 64,
                got_hex_chars: 65
            },
        ));
    }

    #[test]
    fn parse_rejects_uppercase_hex() {
        let err = parse("sha256:ABCD1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234")
            .unwrap_err();
        assert_eq!(err, OciDigestParseError::NonLowercaseHex);
    }

    #[test]
    fn parse_rejects_non_hex_character() {
        let err = parse("sha256:gggg1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234")
            .unwrap_err();
        assert_eq!(err, OciDigestParseError::NonHexCharacter);
    }

    #[test]
    fn shard_prefix_is_first_two_hex_chars() {
        let d = parse("sha256:00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
            .unwrap();
        assert_eq!(d.shard_prefix(), "00");
        let d = parse("sha256:ab112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
            .unwrap();
        assert_eq!(d.shard_prefix(), "ab");
    }

    #[test]
    fn round_trip_via_serde_json() {
        let d = parse("sha256:abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234")
            .unwrap();
        let s = serde_json::to_string(&d).unwrap();
        assert_eq!(
            s,
            "\"sha256:abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234\""
        );
        let d2: OciDigest = serde_json::from_str(&s).unwrap();
        assert_eq!(d, d2);
    }

    #[test]
    fn equal_digests_hash_equal() {
        let a = parse("sha256:abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234")
            .unwrap();
        let b = parse("sha256:abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234")
            .unwrap();
        assert_eq!(a, b);
        let mut set = std::collections::HashSet::new();
        set.insert(a);
        assert!(set.contains(&b));
    }
}

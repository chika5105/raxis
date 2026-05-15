// raxis-crypto::plan_bundle — V2 Plan Bundle canonical-encoding +
// signing-domain logic.
//
// Normative reference: `specs/v2/plan-bundle-sealing.md` §3.2
// ("Canonical encoding for hashing"), §3.5 ("Replay protection"),
// §8.1 step 9 ("Verify Ed25519 signature against operator pubkey
// per §3.2").
//
// This module is the single source of truth for the byte stream the
// operator signs and the kernel decodes. The CLI's `submit plan`
// command (§4) and the kernel's admission decoder (§8.1 steps 1–9)
// MUST round-trip through these functions byte-for-byte.
//
// Layering:
//   - The `PlanBundle` / `BundleArtifact` shapes live in
//     `raxis-types::plan_bundle`. This crate adds the canonical
//     encoder, the SHA-256 hashing layer, the signing-input
//     construction, and the Ed25519 verification convenience.
//   - The CLI's nonce-stamping path uses `mint_bundle_nonce` (a
//     thin wrapper over `getrandom`), kept here so the CSPRNG
//     audit-trail is co-located with the rest of the §3.5 logic.
//
// Wire stability: every byte in `canonical_input` is hand-written
// here. We do NOT route through `serde` or any other reflective
// codec. Any future Rust / serde / sha2 version bump cannot drift
// the wire format. The test suite at the bottom of this file pins
// the exact bytes for a small fixture so a silent change is caught
// in code review.

use raxis_types::{BundleArtifact, BundleNonce, BundleSha256, PlanBundle, SchemaVersion};
use sha2::{Digest, Sha256};

use crate::{verify::verify_ed25519, CryptoError};

// ---------------------------------------------------------------------------
// Domain prefixes — pinned to the §3.2 byte sequences. Changing any
// of these is a wire-protocol break; bump `SchemaVersion` and add a
// migration before touching them.
// ---------------------------------------------------------------------------

/// `"RAXIS-V2-PLAN-BUNDLE\0"` — 21 bytes (§3.2 line 1). Prepended to
/// `canonical_input` before hashing so a `bundle_sha256` from one
/// protocol cannot collide with one from another (`INV-04` audit
/// chain prefix, the GrantDelegation prefix in `delegation.rs`,
/// the V1 plan signing prefix in `plan.rs`, etc.).
pub const CANONICAL_INPUT_PREFIX: &[u8] = b"RAXIS-V2-PLAN-BUNDLE\x00";

/// `"RAXIS-V2-PLAN-BUNDLE-SIG\0"` — 25 bytes (§3.2 line 5). Prepended
/// to the 32-byte `bundle_sha256` to form `signing_input`. The Ed25519
/// signature commits to this exact byte sequence; verifiers MUST
/// reconstruct it byte-for-byte.
pub const SIGNING_INPUT_PREFIX: &[u8] = b"RAXIS-V2-PLAN-BUNDLE-SIG\x00";

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Failure modes for `canonical_encode` / `canonical_decode`.
///
/// **Wire mapping.** These variants project onto the operator-facing
/// `FAIL_PLAN_BUNDLE_*` codes per `plan-bundle-sealing.md §9`. The
/// project-onto-FAIL-code rule is documented per-variant below; the
/// kernel admission path catches `PlanBundleCodecError` and emits the
/// matching code via `PlannerErrorCode` (added as part of the §8.1
/// admission wiring).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PlanBundleCodecError {
    /// Payload is shorter than the minimum well-formed bundle. Maps to
    /// `FAIL_PLAN_BUNDLE_CANONICAL_DECODE_FAILED`.
    #[error("canonical bundle bytes truncated at offset {offset}: needed {needed} more bytes")]
    Truncated { offset: usize, needed: usize },

    /// Payload does not begin with `CANONICAL_INPUT_PREFIX`. Maps to
    /// `FAIL_PLAN_BUNDLE_CANONICAL_DECODE_FAILED`.
    #[error("canonical bundle bytes missing domain prefix")]
    BadDomainPrefix,

    /// `schema_version` field is not 1 or 2. Maps to
    /// `FAIL_PLAN_BUNDLE_CANONICAL_DECODE_FAILED` for purely-malformed
    /// values; the kernel's admission step 4 separately surfaces
    /// `FAIL_PLAN_BUNDLE_SCHEMA_DEPRECATED` for the policy-gated
    /// schema-1 case.
    #[error("unknown schema_version: {0}")]
    UnknownSchemaVersion(u16),

    /// `schema_version = 1` carried freshness envelope fields, or
    /// `schema_version = 2` omitted them. Maps to
    /// `FAIL_PLAN_BUNDLE_CANONICAL_DECODE_FAILED`.
    #[error("schema_version {schema:?} envelope mismatch: {detail}")]
    SchemaEnvelopeMismatch {
        schema: SchemaVersion,
        detail: &'static str,
    },

    /// A length-prefixed UTF-8 string contains invalid UTF-8. Maps to
    /// `FAIL_PLAN_BUNDLE_CANONICAL_DECODE_FAILED`.
    #[error("invalid UTF-8 in field at offset {offset}")]
    InvalidUtf8 { offset: usize },

    /// A per-artifact `sha256` does not match `SHA-256(artifact.bytes)`.
    /// Maps to `FAIL_PLAN_BUNDLE_ARTIFACT_HASH_MISMATCH` per §8.1
    /// step 5.
    #[error("artifact[{artifact_seq}] (\"{artifact_name}\"): per-artifact sha256 mismatch")]
    ArtifactHashMismatch {
        artifact_seq: usize,
        artifact_name: String,
    },

    /// An artifact-count or string-length field would overflow `usize`
    /// on the local platform (e.g. a 32-bit target reading a u32 ≥
    /// `isize::MAX`). Maps to
    /// `FAIL_PLAN_BUNDLE_CANONICAL_DECODE_FAILED`.
    #[error("length-prefix overflow: {field} = {value}")]
    LengthOverflow { field: &'static str, value: u64 },
}

// ---------------------------------------------------------------------------
// canonical_encode
//
// §3.2 byte stream:
//
//   "RAXIS-V2-PLAN-BUNDLE\0"
//    || u16_be(schema_version)
//    || u64_be(created_at_unix_secs)
//    || u64_be(signed_at_unix_secs)        // schema_version >= 2 only
//    || bundle_nonce                       // 16 bytes; schema_version >= 2 only
//    || u32_be(plan_root_relpath.len()) || plan_root_relpath_utf8
//    || u32_be(artifacts.len())
//    || for each artifact in order:
//          u32_be(name.len()) || name_utf8
//       || u64_be(bytes.len()) || bytes
//       || artifact.sha256                 // 32 bytes
// ---------------------------------------------------------------------------

/// Produce the §3.2 canonical_input byte stream that:
/// (a) the operator hashes + signs, and
/// (b) the kernel hashes to recompute `bundle_sha256` at admission
/// time.
///
/// Returns `Err(SchemaEnvelopeMismatch)` if the bundle's
/// `schema_version` and the freshness envelope (`signed_at_unix_secs`
/// + `bundle_nonce`) disagree. This is a structural type-error caught
/// at encode time so the CLI cannot produce a malformed bundle.
pub fn canonical_encode(bundle: &PlanBundle) -> Result<Vec<u8>, PlanBundleCodecError> {
    let envelope_ok = match bundle.schema_version {
        SchemaVersion::V2_0 => {
            bundle.signed_at_unix_secs.is_none() && bundle.bundle_nonce.is_none()
        }
        SchemaVersion::V2_1 => {
            bundle.signed_at_unix_secs.is_some() && bundle.bundle_nonce.is_some()
        }
    };
    if !envelope_ok {
        return Err(PlanBundleCodecError::SchemaEnvelopeMismatch {
            schema: bundle.schema_version,
            detail: match bundle.schema_version {
                SchemaVersion::V2_0 => {
                    "schema_version = 1 must NOT carry signed_at_unix_secs / bundle_nonce"
                }
                SchemaVersion::V2_1 => {
                    "schema_version = 2 MUST carry both signed_at_unix_secs and bundle_nonce"
                }
            },
        });
    }

    let mut out = Vec::with_capacity(estimate_size(bundle));

    out.extend_from_slice(CANONICAL_INPUT_PREFIX);
    out.extend_from_slice(&bundle.schema_version.as_u16().to_be_bytes());
    out.extend_from_slice(&bundle.created_at_unix_secs.to_be_bytes());

    if bundle.schema_version.carries_freshness_envelope() {
        // The is_some() guards above prove these unwraps are safe; we
        // keep them as `expect("envelope_ok")` to make the invariant
        // self-documenting in stack traces if the contract ever
        // breaks.
        let signed_at = bundle
            .signed_at_unix_secs
            .expect("envelope_ok: V2.1 has signed_at_unix_secs");
        let nonce = bundle
            .bundle_nonce
            .expect("envelope_ok: V2.1 has bundle_nonce");
        out.extend_from_slice(&signed_at.to_be_bytes());
        out.extend_from_slice(nonce.as_bytes());
    }

    let plan_root_bytes = bundle.plan_root_relpath.as_bytes();
    out.extend_from_slice(&(plan_root_bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(plan_root_bytes);

    out.extend_from_slice(&(bundle.artifacts.len() as u32).to_be_bytes());

    for artifact in &bundle.artifacts {
        let name_bytes = artifact.name.as_bytes();
        out.extend_from_slice(&(name_bytes.len() as u32).to_be_bytes());
        out.extend_from_slice(name_bytes);

        let body_len = artifact.bytes.len() as u64;
        out.extend_from_slice(&body_len.to_be_bytes());
        out.extend_from_slice(&artifact.bytes);

        out.extend_from_slice(artifact.sha256.as_bytes());
    }

    Ok(out)
}

/// Estimate the encoded size for `Vec::with_capacity`. Conservative
/// (overshoots by at most a few hundred bytes for typical bundles)
/// — only matters for allocator efficiency.
fn estimate_size(bundle: &PlanBundle) -> usize {
    let envelope = if bundle.schema_version.carries_freshness_envelope() {
        24
    } else {
        0
    };
    let header =
        CANONICAL_INPUT_PREFIX.len() + 2 + 8 + envelope + 4 + bundle.plan_root_relpath.len() + 4;
    let artifacts = bundle
        .artifacts
        .iter()
        .map(|a| 4 + a.name.len() + 8 + a.bytes.len() + 32)
        .sum::<usize>();
    header + artifacts
}

// ---------------------------------------------------------------------------
// canonical_decode
// ---------------------------------------------------------------------------

/// Parse a canonical-encoded plan bundle back into the logical
/// `PlanBundle`. Invariants enforced:
///
/// 1. `bytes` begins with `CANONICAL_INPUT_PREFIX`.
/// 2. `schema_version` is 1 or 2 (`SchemaVersion::from_u16` total).
/// 3. The freshness-envelope fields are present iff
///    `schema_version = 2`.
/// 4. Every length prefix decodes to a `usize` on the local platform
///    (no integer overflow).
/// 5. Per-artifact `sha256` matches `SHA-256(artifact.bytes)`.
///
/// **§8.1 step alignment.** `canonical_decode` covers the §3.2
/// structural decode (admission step 4) AND the per-artifact hash
/// re-verification (admission step 5) in one pass. The kernel's
/// envelope-SHA cross-check (admission step 2: `bundle_sha256` echo)
/// is deliberately external — it operates on the same
/// canonical-input bytes whose decode we are about to perform.
pub fn canonical_decode(bytes: &[u8]) -> Result<PlanBundle, PlanBundleCodecError> {
    let mut cur = Cursor::new(bytes);

    cur.expect_prefix(
        CANONICAL_INPUT_PREFIX,
        PlanBundleCodecError::BadDomainPrefix,
    )?;

    let schema_v_u16 = cur.read_u16_be()?;
    let schema_version = SchemaVersion::from_u16(schema_v_u16)
        .ok_or(PlanBundleCodecError::UnknownSchemaVersion(schema_v_u16))?;

    let created_at_unix_secs = cur.read_u64_be()?;

    let (signed_at_unix_secs, bundle_nonce) = if schema_version.carries_freshness_envelope() {
        let signed_at = cur.read_u64_be()?;
        let mut nonce_bytes = [0u8; 16];
        cur.read_exact(&mut nonce_bytes)?;
        (Some(signed_at), Some(BundleNonce::new(nonce_bytes)))
    } else {
        (None, None)
    };

    let plan_root_relpath = cur.read_string_u32()?;

    let artifact_count = cur.read_u32_be()? as usize;
    let mut artifacts = Vec::with_capacity(artifact_count.min(1024));

    for seq in 0..artifact_count {
        let name = cur.read_string_u32()?;
        let bytes_len = cur.read_u64_be()?;
        let bytes_len_usize =
            usize::try_from(bytes_len).map_err(|_| PlanBundleCodecError::LengthOverflow {
                field: "artifact.bytes.len()",
                value: bytes_len,
            })?;
        let mut artifact_bytes = vec![0u8; bytes_len_usize];
        cur.read_exact(&mut artifact_bytes)?;

        let mut sha256_bytes = [0u8; 32];
        cur.read_exact(&mut sha256_bytes)?;
        let recorded_sha = BundleSha256::new(sha256_bytes);

        // §8.1 step 5: re-verify per-artifact sha256.
        let actual_sha = sha256_of_artifact_bytes(&artifact_bytes);
        if actual_sha != recorded_sha {
            return Err(PlanBundleCodecError::ArtifactHashMismatch {
                artifact_seq: seq,
                artifact_name: name,
            });
        }

        artifacts.push(BundleArtifact {
            name,
            bytes: artifact_bytes,
            sha256: recorded_sha,
        });
    }

    Ok(PlanBundle {
        schema_version,
        created_at_unix_secs,
        signed_at_unix_secs,
        bundle_nonce,
        plan_root_relpath,
        artifacts,
    })
}

// ---------------------------------------------------------------------------
// Hash + signing-input helpers
// ---------------------------------------------------------------------------

/// SHA-256 of an artifact's body. Used by both the encoder
/// (when stamping `BundleArtifact::sha256`) and the decoder (when
/// re-verifying that stamp at admission).
pub fn sha256_of_artifact_bytes(bytes: &[u8]) -> BundleSha256 {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    BundleSha256::new(hasher.finalize().into())
}

/// `bundle_sha256 = SHA-256(canonical_input)` per §3.2.
pub fn bundle_sha256(canonical_input: &[u8]) -> BundleSha256 {
    let mut hasher = Sha256::new();
    hasher.update(canonical_input);
    BundleSha256::new(hasher.finalize().into())
}

/// `signing_input = "RAXIS-V2-PLAN-BUNDLE-SIG\0" || bundle_sha256`
/// per §3.2. The operator's Ed25519 signature commits to *this byte
/// sequence*, NOT to `canonical_input` — the indirection lets the
/// kernel store `bundle_sha256` rather than recomputing it on every
/// audit join.
pub fn signing_input(bundle_sha256: &BundleSha256) -> Vec<u8> {
    let mut out = Vec::with_capacity(SIGNING_INPUT_PREFIX.len() + 32);
    out.extend_from_slice(SIGNING_INPUT_PREFIX);
    out.extend_from_slice(bundle_sha256.as_bytes());
    out
}

/// Verify an Ed25519 signature over a plan bundle. Convenience wrapper
/// over `canonical_encode → bundle_sha256 → signing_input →
/// verify_ed25519`. The kernel's admission step 9 calls this directly;
/// the CLI's `submit plan` does not (it signs, doesn't verify).
pub fn verify_plan_bundle_signature(
    pubkey_bytes: &[u8],
    bundle: &PlanBundle,
    signature: &[u8],
) -> Result<(), CryptoError> {
    // `canonical_encode` failure projects through `From` into
    // `CryptoError::PlanBundleEncode` — the CLI cannot construct a
    // schema-mismatch bundle, so this branch is dead in normal
    // operation (it exists for defense in depth).
    let canonical = canonical_encode(bundle)?;
    let sha = bundle_sha256(&canonical);
    let input = signing_input(&sha);
    verify_ed25519(pubkey_bytes, &input, signature)
}

// ---------------------------------------------------------------------------
// CSPRNG nonce minting (§3.5 step 2)
// ---------------------------------------------------------------------------

/// Mint a fresh CSPRNG-backed `bundle_nonce`. The CLI's `submit plan`
/// phase 6 (`§4.2 step 6`) MUST call this — never persist or reuse
/// the value across invocations. Backed by `getrandom` so the
/// platform's secure RNG (e.g. `getrandom(2)` on Linux) is used.
pub fn mint_bundle_nonce() -> Result<BundleNonce, CryptoError> {
    let mut bytes = [0u8; 16];
    getrandom::getrandom(&mut bytes)?;
    Ok(BundleNonce::new(bytes))
}

// ---------------------------------------------------------------------------
// Cursor — lightweight no-alloc byte reader. Deliberately not a full
// Read implementation; we want every read to surface a structured
// `PlanBundleCodecError` rather than `io::Error`.
// ---------------------------------------------------------------------------

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn remaining(&self) -> usize {
        self.bytes.len() - self.offset
    }

    fn ensure(&self, n: usize) -> Result<(), PlanBundleCodecError> {
        if self.remaining() < n {
            return Err(PlanBundleCodecError::Truncated {
                offset: self.offset,
                needed: n - self.remaining(),
            });
        }
        Ok(())
    }

    fn expect_prefix(
        &mut self,
        prefix: &[u8],
        if_missing: PlanBundleCodecError,
    ) -> Result<(), PlanBundleCodecError> {
        self.ensure(prefix.len())?;
        if &self.bytes[self.offset..self.offset + prefix.len()] != prefix {
            return Err(if_missing);
        }
        self.offset += prefix.len();
        Ok(())
    }

    fn read_u16_be(&mut self) -> Result<u16, PlanBundleCodecError> {
        self.ensure(2)?;
        let mut b = [0u8; 2];
        b.copy_from_slice(&self.bytes[self.offset..self.offset + 2]);
        self.offset += 2;
        Ok(u16::from_be_bytes(b))
    }

    fn read_u32_be(&mut self) -> Result<u32, PlanBundleCodecError> {
        self.ensure(4)?;
        let mut b = [0u8; 4];
        b.copy_from_slice(&self.bytes[self.offset..self.offset + 4]);
        self.offset += 4;
        Ok(u32::from_be_bytes(b))
    }

    fn read_u64_be(&mut self) -> Result<u64, PlanBundleCodecError> {
        self.ensure(8)?;
        let mut b = [0u8; 8];
        b.copy_from_slice(&self.bytes[self.offset..self.offset + 8]);
        self.offset += 8;
        Ok(u64::from_be_bytes(b))
    }

    fn read_exact(&mut self, dst: &mut [u8]) -> Result<(), PlanBundleCodecError> {
        self.ensure(dst.len())?;
        dst.copy_from_slice(&self.bytes[self.offset..self.offset + dst.len()]);
        self.offset += dst.len();
        Ok(())
    }

    fn read_string_u32(&mut self) -> Result<String, PlanBundleCodecError> {
        let len = self.read_u32_be()? as usize;
        self.ensure(len)?;
        let off_before = self.offset;
        let s = std::str::from_utf8(&self.bytes[off_before..off_before + len])
            .map_err(|_| PlanBundleCodecError::InvalidUtf8 { offset: off_before })?
            .to_owned();
        self.offset += len;
        Ok(s)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn fixture_v2_1_bundle() -> PlanBundle {
        let plan_toml = b"[orchestrator]\ncross_cutting_artifacts = []\n".to_vec();
        let plan_sha = sha256_of_artifact_bytes(&plan_toml);
        PlanBundle::new_v2_1(
            100,
            200,
            BundleNonce::new([0xAAu8; 16]),
            "myplan".to_owned(),
            vec![BundleArtifact {
                name: "plan.toml".to_owned(),
                bytes: plan_toml,
                sha256: plan_sha,
            }],
        )
    }

    fn fixture_v2_0_legacy_bundle() -> PlanBundle {
        let plan_toml = b"[initiative]\nname = \"x\"\n".to_vec();
        let plan_sha = sha256_of_artifact_bytes(&plan_toml);
        PlanBundle::new_v2_0_legacy(
            42,
            "old".to_owned(),
            vec![BundleArtifact {
                name: "plan.toml".to_owned(),
                bytes: plan_toml,
                sha256: plan_sha,
            }],
        )
    }

    // ── Domain-prefix pinning ──────────────────────────────────────────

    /// The §3.2 canonical-input prefix is part of the wire contract;
    /// changing it breaks every signed bundle anywhere on the network.
    /// Pin both the byte length AND the exact byte sequence.
    #[test]
    fn canonical_input_prefix_is_pinned() {
        assert_eq!(CANONICAL_INPUT_PREFIX, b"RAXIS-V2-PLAN-BUNDLE\x00");
        assert_eq!(CANONICAL_INPUT_PREFIX.len(), 21);
    }

    /// The §3.2 signing-input prefix is similarly contractual.
    #[test]
    fn signing_input_prefix_is_pinned() {
        assert_eq!(SIGNING_INPUT_PREFIX, b"RAXIS-V2-PLAN-BUNDLE-SIG\x00");
        assert_eq!(SIGNING_INPUT_PREFIX.len(), 25);
    }

    // ── Round-trip ────────────────────────────────────────────────────

    /// V2.1 bundle round-trips byte-for-byte through canonical_encode →
    /// canonical_decode. The recovered bundle must be `==` to the
    /// original.
    #[test]
    fn canonical_round_trip_v2_1() {
        let original = fixture_v2_1_bundle();
        let encoded = canonical_encode(&original).unwrap();
        let decoded = canonical_decode(&encoded).unwrap();
        assert_eq!(
            decoded, original,
            "V2.1 canonical_encode/decode must be an identity"
        );
    }

    /// V2.0 legacy bundle round-trips. Confirms the schema-1 envelope
    /// (no signed_at, no nonce) decodes back to `None` for both
    /// fields.
    #[test]
    fn canonical_round_trip_v2_0_legacy() {
        let original = fixture_v2_0_legacy_bundle();
        let encoded = canonical_encode(&original).unwrap();
        let decoded = canonical_decode(&encoded).unwrap();
        assert_eq!(decoded, original);
        assert!(decoded.signed_at_unix_secs.is_none());
        assert!(decoded.bundle_nonce.is_none());
    }

    /// Multiple artifacts round-trip with their declaration order
    /// preserved.
    #[test]
    fn canonical_round_trip_preserves_artifact_order() {
        let a1_bytes = b"first".to_vec();
        let a1_sha = sha256_of_artifact_bytes(&a1_bytes);
        let a2_bytes = b"second".to_vec();
        let a2_sha = sha256_of_artifact_bytes(&a2_bytes);
        let a3_bytes = b"third".to_vec();
        let a3_sha = sha256_of_artifact_bytes(&a3_bytes);

        let original = PlanBundle::new_v2_1(
            1,
            2,
            BundleNonce::new([0u8; 16]),
            String::new(),
            vec![
                BundleArtifact {
                    name: "plan.toml".into(),
                    bytes: a1_bytes,
                    sha256: a1_sha,
                },
                BundleArtifact {
                    name: "b.md".into(),
                    bytes: a2_bytes,
                    sha256: a2_sha,
                },
                BundleArtifact {
                    name: "a.md".into(),
                    bytes: a3_bytes,
                    sha256: a3_sha,
                },
            ],
        );
        let decoded = canonical_decode(&canonical_encode(&original).unwrap()).unwrap();
        assert_eq!(decoded.artifacts.len(), 3);
        assert_eq!(decoded.artifacts[0].name, "plan.toml");
        assert_eq!(decoded.artifacts[1].name, "b.md");
        assert_eq!(
            decoded.artifacts[2].name, "a.md",
            "encoder MUST preserve the operator's declaration order"
        );
    }

    /// `bundle_sha256` is determined purely by `canonical_input`.
    /// Same input → same hash, regardless of caller / Rust version /
    /// platform endianness.
    #[test]
    fn bundle_sha256_is_a_pure_function_of_canonical_input() {
        let bundle = fixture_v2_1_bundle();
        let enc = canonical_encode(&bundle).unwrap();
        let h1 = bundle_sha256(&enc);
        let h2 = bundle_sha256(&enc);
        assert_eq!(h1, h2);

        // A trivially-different bundle must hash differently.
        let mut bundle2 = bundle.clone();
        bundle2.created_at_unix_secs += 1;
        let enc2 = canonical_encode(&bundle2).unwrap();
        let h3 = bundle_sha256(&enc2);
        assert_ne!(
            h1, h3,
            "encoder MUST commit to created_at_unix_secs (covered by the signature)"
        );
    }

    // ── Envelope mismatches ───────────────────────────────────────────

    /// V2.1 bundle that's missing `signed_at_unix_secs` is rejected at
    /// encode time — the CLI cannot construct an unsigned-but-fresh
    /// bundle.
    #[test]
    fn encode_rejects_v2_1_bundle_missing_signed_at() {
        let mut b = fixture_v2_1_bundle();
        b.signed_at_unix_secs = None;
        let err = canonical_encode(&b).unwrap_err();
        assert!(matches!(
            err,
            PlanBundleCodecError::SchemaEnvelopeMismatch {
                schema: SchemaVersion::V2_1,
                ..
            }
        ));
    }

    /// V2.1 bundle that's missing `bundle_nonce` is rejected at encode
    /// time.
    #[test]
    fn encode_rejects_v2_1_bundle_missing_bundle_nonce() {
        let mut b = fixture_v2_1_bundle();
        b.bundle_nonce = None;
        let err = canonical_encode(&b).unwrap_err();
        assert!(matches!(
            err,
            PlanBundleCodecError::SchemaEnvelopeMismatch {
                schema: SchemaVersion::V2_1,
                ..
            }
        ));
    }

    /// V2.0 bundle that's carrying a freshness envelope is rejected at
    /// encode time. Symmetric to the V2.1-missing case.
    #[test]
    fn encode_rejects_v2_0_bundle_carrying_freshness_envelope() {
        let mut b = fixture_v2_0_legacy_bundle();
        b.signed_at_unix_secs = Some(99);
        let err = canonical_encode(&b).unwrap_err();
        assert!(matches!(
            err,
            PlanBundleCodecError::SchemaEnvelopeMismatch {
                schema: SchemaVersion::V2_0,
                ..
            }
        ));
    }

    // ── Decode failure modes ──────────────────────────────────────────

    #[test]
    fn decode_truncated_prefix_fails() {
        let truncated = &CANONICAL_INPUT_PREFIX[..10];
        assert!(matches!(
            canonical_decode(truncated).unwrap_err(),
            PlanBundleCodecError::Truncated { .. },
        ));
    }

    #[test]
    fn decode_bad_prefix_fails() {
        let mut bytes = CANONICAL_INPUT_PREFIX.to_vec();
        bytes[0] = b'X';
        bytes.extend_from_slice(&[0u8; 32]); // pad so we hit the prefix check, not truncation
        assert_eq!(
            canonical_decode(&bytes).unwrap_err(),
            PlanBundleCodecError::BadDomainPrefix,
        );
    }

    #[test]
    fn decode_unknown_schema_version_fails() {
        let original = fixture_v2_1_bundle();
        let mut enc = canonical_encode(&original).unwrap();
        // schema_version is the two bytes immediately after the prefix.
        let off = CANONICAL_INPUT_PREFIX.len();
        enc[off] = 0x00;
        enc[off + 1] = 0xFF;
        let err = canonical_decode(&enc).unwrap_err();
        assert!(matches!(
            err,
            PlanBundleCodecError::UnknownSchemaVersion(0xFF)
        ));
    }

    /// Tampering an artifact's `bytes` (without re-stamping its
    /// `sha256`) is rejected at decode-time per §8.1 step 5.
    #[test]
    fn decode_artifact_hash_mismatch_fails() {
        let original = fixture_v2_1_bundle();
        let mut enc = canonical_encode(&original).unwrap();

        // Corrupt the LAST byte of the artifact's `bytes` (it sits
        // immediately before the per-artifact 32-byte sha256; we
        // know the layout from §3.2 + estimate_size).
        let len = enc.len();
        enc[len - 33] ^= 0xFF;

        let err = canonical_decode(&enc).unwrap_err();
        assert!(matches!(
            err,
            PlanBundleCodecError::ArtifactHashMismatch {
                artifact_seq: 0,
                ..
            }
        ));
    }

    #[test]
    fn decode_truncated_after_artifact_count_fails() {
        let original = fixture_v2_1_bundle();
        let enc = canonical_encode(&original).unwrap();
        let cut = enc.len() - 10;
        assert!(matches!(
            canonical_decode(&enc[..cut]).unwrap_err(),
            PlanBundleCodecError::Truncated { .. },
        ));
    }

    /// Invalid UTF-8 in `plan_root_relpath` surfaces as
    /// `InvalidUtf8`, not as a generic decode error.
    #[test]
    fn decode_invalid_utf8_in_plan_root_relpath_fails() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(CANONICAL_INPUT_PREFIX);
        bytes.extend_from_slice(&SchemaVersion::V2_0.as_u16().to_be_bytes());
        bytes.extend_from_slice(&0u64.to_be_bytes()); // created_at
                                                      // V2.0 carries no envelope — straight to plan_root_relpath.
        bytes.extend_from_slice(&3u32.to_be_bytes()); // length
        bytes.extend_from_slice(&[0xFF, 0xFE, 0xFD]); // not valid UTF-8
        bytes.extend_from_slice(&0u32.to_be_bytes()); // 0 artifacts

        assert!(matches!(
            canonical_decode(&bytes).unwrap_err(),
            PlanBundleCodecError::InvalidUtf8 { .. },
        ));
    }

    // ── Signing-input + signature round-trip ─────────────────────────

    /// Operator signs `signing_input`; verifier reconstructs the same
    /// bytes from the bundle and Ed25519-verifies. End-to-end happy
    /// path.
    #[test]
    fn end_to_end_sign_and_verify_round_trip() {
        let seed = [0x33u8; 32];
        let sk = SigningKey::from_bytes(&seed);
        let pk = sk.verifying_key().to_bytes();

        let bundle = fixture_v2_1_bundle();
        let canonical = canonical_encode(&bundle).unwrap();
        let sha = bundle_sha256(&canonical);
        let input = signing_input(&sha);
        let sig = sk.sign(&input);

        assert!(verify_plan_bundle_signature(&pk, &bundle, &sig.to_bytes()).is_ok());
    }

    /// Tampering ANY byte of the bundle after signing breaks the
    /// signature. Catches the "operator signs A, kernel verifies B"
    /// attack class (§3.2's whole reason for being).
    #[test]
    fn tampering_after_signing_breaks_signature() {
        let seed = [0x44u8; 32];
        let sk = SigningKey::from_bytes(&seed);
        let pk = sk.verifying_key().to_bytes();

        let bundle = fixture_v2_1_bundle();
        let canonical = canonical_encode(&bundle).unwrap();
        let sha = bundle_sha256(&canonical);
        let sig = sk.sign(&signing_input(&sha));

        // Same operator, same key, different bundle (one byte off in
        // a field covered by the signature).
        let mut tampered = bundle.clone();
        tampered.signed_at_unix_secs = tampered.signed_at_unix_secs.map(|s| s + 1);
        assert!(verify_plan_bundle_signature(&pk, &tampered, &sig.to_bytes()).is_err());
    }

    /// Bundle-level domain separation: a signature that verifies for a
    /// V2.1 bundle MUST NOT verify against a re-cast V2.0 bundle of
    /// the same artifacts (the signing prefix is the same, but the
    /// `bundle_sha256` differs because the canonical encoding's
    /// schema-version byte changes).
    #[test]
    fn schema_recast_breaks_signature() {
        let seed = [0x55u8; 32];
        let sk = SigningKey::from_bytes(&seed);
        let pk = sk.verifying_key().to_bytes();

        let v2_1 = fixture_v2_1_bundle();
        let canonical = canonical_encode(&v2_1).unwrap();
        let sha = bundle_sha256(&canonical);
        let sig = sk.sign(&signing_input(&sha));

        // Try to re-cast as a V2.0 legacy with the same `plan.toml`.
        let v2_0 = PlanBundle::new_v2_0_legacy(
            v2_1.created_at_unix_secs,
            v2_1.plan_root_relpath.clone(),
            v2_1.artifacts.clone(),
        );
        assert!(
            verify_plan_bundle_signature(&pk, &v2_0, &sig.to_bytes()).is_err(),
            "re-casting V2.1 bundle as V2.0 must not verify under the V2.1 signature"
        );
    }

    /// Domain separation against the V1 plan signing scheme: a
    /// signature minted under `crate::plan::plan_signing_input` for
    /// `plan_bytes` must NOT verify against `verify_plan_bundle_signature`.
    /// Catches a cross-protocol replay where an attacker re-uses an
    /// older V1 plan signature.
    #[test]
    fn v1_plan_signature_does_not_cross_verify_against_v2_bundle() {
        let seed = [0x66u8; 32];
        let sk = SigningKey::from_bytes(&seed);
        let pk = sk.verifying_key().to_bytes();

        let bundle = fixture_v2_1_bundle();
        let plan_toml = &bundle.artifacts[0].bytes;

        // V1-style signature over the plan bytes alone.
        let v1_input = crate::plan::plan_signing_input(plan_toml);
        let v1_sig = sk.sign(&v1_input);

        assert!(
            verify_plan_bundle_signature(&pk, &bundle, &v1_sig.to_bytes()).is_err(),
            "V1 plan signature must not verify against the V2 bundle scheme"
        );
    }

    // ── CSPRNG nonce minting ─────────────────────────────────────────

    /// `mint_bundle_nonce` returns 16 random bytes and DOES NOT panic
    /// on the canonical platform (Linux + macOS host targets).
    #[test]
    fn mint_bundle_nonce_returns_16_bytes() {
        let n = mint_bundle_nonce().unwrap();
        assert_eq!(n.as_bytes().len(), 16);
    }

    /// Two consecutive mints produce different values with very high
    /// probability. Catches a future regression where the function is
    /// accidentally wired to a deterministic source.
    #[test]
    fn mint_bundle_nonce_yields_distinct_values_in_practice() {
        let a = mint_bundle_nonce().unwrap();
        let b = mint_bundle_nonce().unwrap();
        assert_ne!(
            a, b,
            "two CSPRNG mints must (with overwhelming probability) be distinct"
        );
    }

    // ── Wire-format pinning fixture ──────────────────────────────────

    /// A trivial all-zero V2.0 fixture lets us pin a small, exact byte
    /// sequence end-to-end. Any silent change to the §3.2 layout
    /// (re-ordering fields, switching endianness, dropping the prefix
    /// null) breaks this test in code review.
    #[test]
    fn pinned_fixture_v2_0_byte_layout() {
        let bundle = PlanBundle::new_v2_0_legacy(
            0,
            String::new(),
            vec![BundleArtifact {
                name: "plan.toml".to_owned(),
                bytes: Vec::new(),
                sha256: sha256_of_artifact_bytes(&[]),
            }],
        );
        let bytes = canonical_encode(&bundle).unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(b"RAXIS-V2-PLAN-BUNDLE\x00");
        expected.extend_from_slice(&1u16.to_be_bytes()); // schema_version = 1
        expected.extend_from_slice(&0u64.to_be_bytes()); // created_at_unix_secs
                                                         // (no envelope for V2.0)
        expected.extend_from_slice(&0u32.to_be_bytes()); // plan_root_relpath len = 0
        expected.extend_from_slice(&1u32.to_be_bytes()); // artifacts.len() = 1
        expected.extend_from_slice(&9u32.to_be_bytes()); // name.len() = 9
        expected.extend_from_slice(b"plan.toml");
        expected.extend_from_slice(&0u64.to_be_bytes()); // bytes.len() = 0
                                                         // (no body bytes)
        let empty_sha = sha256_of_artifact_bytes(&[]);
        expected.extend_from_slice(empty_sha.as_bytes());

        assert_eq!(bytes, expected, "V2.0 byte layout must match §3.2 exactly");
    }
}

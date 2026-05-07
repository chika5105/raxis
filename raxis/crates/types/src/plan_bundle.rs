// raxis-types::plan_bundle — V2 Plan Bundle data types.
//
// Normative reference: `specs/v2/plan-bundle-sealing.md` §3 (envelope
// shape, canonical encoding, IPC envelope).
//
// Crate rules (philosophy.md §1.5, INV-CRATE-01):
//   - Pure data types + serde derives + Display/Error impls only.
//   - The canonical-encoding logic (§3.2) and the SHA-256 / Ed25519
//     primitives live in `raxis-crypto::plan_bundle`. This module
//     declares the *shapes* that crate operates on, plus the small
//     enums (`SchemaVersion`) and newtypes (`BundleNonce`,
//     `BundleSha256`, `OperatorFingerprint`) that flow through both
//     the wire envelope and the SQLite store.
//
// Why these types live here and not in `raxis-crypto`:
//   - `raxis-store::migration::Migration 8` references the byte
//     widths declared here through CHECK constraints; the kernel
//     readers in `raxis-store::views::plan_bundles` need the *types*
//     without pulling in `sha2` / `ed25519-dalek` transitively.
//   - The CLI's plan-bundle build path constructs `PlanBundle` from
//     parsed TOML before the crypto crate ever touches it.
//
// Wire compatibility: `serde` is wired but the canonical-encoding
// path in `raxis-crypto::plan_bundle` does NOT consume the serde
// projection — it uses a hand-rolled length-prefixed binary
// encoding per §3.2 so the byte order, prefix domain, and field
// ordering are guaranteed stable across Rust versions, serde
// versions, and any future codec swap.

use serde::{Deserialize, Serialize};
use std::fmt;

// ---------------------------------------------------------------------------
// SchemaVersion — bundle envelope schema discriminator.
//
// V2 ships two schema versions:
//   - `V2_0` (= 1): legacy envelope that lacks `signed_at_unix_secs`
//     and `bundle_nonce`. Accepted only when
//     `[plan_signing].accept_unfresh_v2_0_bundles = true` (see §3.1).
//   - `V2_1` (= 2): default envelope with the full §3.5 freshness
//     window + per-bundle nonce.
//
// Any other on-wire value is a hard rejection (Migration 8's
// `plan_bundles.schema_version IN (1, 2)` CHECK is the second floor).
// ---------------------------------------------------------------------------

/// The on-wire envelope schema for a plan bundle. The integer
/// discriminant matches the `schema_version` field byte-for-byte
/// (`u16_be` per §3.2 canonical_input).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u16)]
pub enum SchemaVersion {
    /// V2.0 envelope — no freshness window, no per-bundle nonce.
    /// Transitional: only admissible when policy explicitly allows it.
    V2_0 = 1,
    /// V2.1 envelope — full freshness window + 16-byte CSPRNG nonce.
    /// Default for V2 production deployments.
    V2_1 = 2,
}

impl SchemaVersion {
    /// All wire-stable variants. Migration 8's CHECK constraint is
    /// pinned against these values via the
    /// `migration_8_*_check_constraint_*` test family.
    pub const ALL: [Self; 2] = [Self::V2_0, Self::V2_1];

    /// The on-wire `u16` discriminant for §3.2 canonical encoding.
    pub fn as_u16(self) -> u16 {
        self as u16
    }

    /// Decode an on-wire `u16`. `None` for any value outside the
    /// canonical set; the canonical-encoding decoder surfaces this as
    /// `FAIL_PLAN_BUNDLE_CANONICAL_DECODE_FAILED`.
    pub fn from_u16(v: u16) -> Option<Self> {
        match v {
            1 => Some(Self::V2_0),
            2 => Some(Self::V2_1),
            _ => None,
        }
    }

    /// V2.1 + later carry the §3.5 replay-protection envelope
    /// (`signed_at_unix_secs` + `bundle_nonce`). V2.0 omits both.
    pub fn carries_freshness_envelope(self) -> bool {
        matches!(self, Self::V2_1)
    }
}

impl fmt::Display for SchemaVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::V2_0 => f.write_str("V2.0"),
            Self::V2_1 => f.write_str("V2.1"),
        }
    }
}

// ---------------------------------------------------------------------------
// Newtypes for the three fixed-width byte fields.
//
// These are not just type-safety wrappers — they're the basis for
// the §3.2 canonical encoding's "no length prefix needed for these
// fields" property. Encoders write them as raw fixed-arity bytes; a
// caller that hands a wrong-length `Vec<u8>` to the encoder gets a
// type error rather than a silently-truncated wire frame.
// ---------------------------------------------------------------------------

/// 32-byte SHA-256 of a plan-bundle's canonical encoding. Stored in
/// `plan_bundles.bundle_sha256` and embedded in the §3.4 IPC envelope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BundleSha256(pub [u8; 32]);

impl BundleSha256 {
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl fmt::Display for BundleSha256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

/// 16-byte CSPRNG-generated per-bundle nonce. Carried inside the
/// signed envelope so the operator's signature commits to it; the
/// kernel persists it in `plan_bundle_nonces_seen.bundle_nonce` for
/// the §3.5 replay check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BundleNonce(pub [u8; 16]);

impl BundleNonce {
    pub const fn new(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl fmt::Display for BundleNonce {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

/// 8-byte operator fingerprint — `SHA-256(operator_pubkey)[:16]`
/// truncated to the first 8 bytes per §3.4. Embedded in the IPC
/// envelope so the kernel can resolve the operator's public key
/// from `policy.operators` before verifying the signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct OperatorFingerprint(pub [u8; 8]);

impl OperatorFingerprint {
    pub const fn new(bytes: [u8; 8]) -> Self {
        Self(bytes)
    }
    pub const fn as_bytes(&self) -> &[u8; 8] {
        &self.0
    }
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl fmt::Display for OperatorFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

// ---------------------------------------------------------------------------
// BundleArtifact / PlanBundle — the §3.1 logical structure.
// ---------------------------------------------------------------------------

/// One entry in a plan bundle's `artifacts` list. `artifacts[0]` is
/// always `plan.toml`; subsequent entries (if any — V2 has no
/// host-path-typed plan fields per §5.4) are operator-declared
/// host-path artifacts.
///
/// Equality / hashing are content-defined: two `BundleArtifact`s are
/// equal iff their name / bytes / sha256 all match. This is the
/// `BundleArtifact`-level analog of `bundle_sha256`'s
/// content-addressing.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BundleArtifact {
    /// Bundle-internal artifact name (§3.3): `"plan.toml"` for the
    /// first entry, `relative(plan_root, resolved_real_path)` for
    /// subsequent entries. NFC-normalised UTF-8, forward-slashed,
    /// no leading `/`, no `..` segments.
    pub name: String,
    /// Raw artifact bytes (§3.1: "no normalization").
    pub bytes: Vec<u8>,
    /// SHA-256 of `bytes`. Self-verification + audit aid.
    pub sha256: BundleSha256,
}

/// Logical view of a plan bundle as defined in §3.1. The §3.2
/// canonical-encoding step (`raxis-crypto::plan_bundle::canonical_input`)
/// consumes this struct and emits the byte-stable representation that
/// the operator signs and the kernel decodes.
///
/// Field order matches §3.1 verbatim — encoders rely on it for the
/// `for each artifact in order` loop.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanBundle {
    /// Schema version of the on-wire envelope. The freshness fields
    /// below MUST be `Some` for `V2_1` and `None` for `V2_0` — the
    /// canonical encoder enforces the invariant.
    pub schema_version: SchemaVersion,
    /// Operator's local clock at bundle construction time. Purely
    /// informational; not used by the kernel for any admission gate.
    pub created_at_unix_secs: u64,
    /// Operator's local clock immediately before §3.2 canonical_input
    /// is built. Covered by the signature; used by the kernel to
    /// enforce `[plan_signing].max_plan_bundle_age_secs` (§3.5, §8.1).
    /// Required for `V2_1`; absent for `V2_0`.
    pub signed_at_unix_secs: Option<u64>,
    /// 16-byte CSPRNG output set by the CLI before the signature is
    /// computed (§3.5 step 2). Required for `V2_1`; absent for `V2_0`.
    pub bundle_nonce: Option<BundleNonce>,
    /// The relative path the operator passed to `raxis-cli submit
    /// plan` (§3.1). Informational; the kernel does not re-resolve.
    pub plan_root_relpath: String,
    /// Ordered artifact list. `artifacts[0].name == "plan.toml"`
    /// (§3.3 — enforced at encode time and at admission step 6).
    pub artifacts: Vec<BundleArtifact>,
}

impl PlanBundle {
    /// Convenience constructor for V2.1 bundles (the default).
    /// Most callers should prefer this over the struct literal.
    pub fn new_v2_1(
        created_at_unix_secs: u64,
        signed_at_unix_secs:  u64,
        bundle_nonce:         BundleNonce,
        plan_root_relpath:    String,
        artifacts:            Vec<BundleArtifact>,
    ) -> Self {
        Self {
            schema_version: SchemaVersion::V2_1,
            created_at_unix_secs,
            signed_at_unix_secs: Some(signed_at_unix_secs),
            bundle_nonce: Some(bundle_nonce),
            plan_root_relpath,
            artifacts,
        }
    }

    /// Construct a legacy V2.0 bundle. Used only by the V2.0 → V2.1
    /// cutover compat path (`accept_unfresh_v2_0_bundles = true`).
    pub fn new_v2_0_legacy(
        created_at_unix_secs: u64,
        plan_root_relpath:    String,
        artifacts:            Vec<BundleArtifact>,
    ) -> Self {
        Self {
            schema_version: SchemaVersion::V2_0,
            created_at_unix_secs,
            signed_at_unix_secs: None,
            bundle_nonce:        None,
            plan_root_relpath,
            artifacts,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ── SchemaVersion round-trip ──────────────────────────────────────

    #[test]
    fn schema_version_round_trips_through_u16() {
        for &variant in &SchemaVersion::ALL {
            let v = variant.as_u16();
            assert_eq!(SchemaVersion::from_u16(v), Some(variant),
                "round-trip failed for {variant:?} (wire = {v})");
        }
        assert_eq!(SchemaVersion::V2_0.as_u16(), 1);
        assert_eq!(SchemaVersion::V2_1.as_u16(), 2);
    }

    #[test]
    fn schema_version_unknown_u16_returns_none() {
        assert_eq!(SchemaVersion::from_u16(0), None);
        assert_eq!(SchemaVersion::from_u16(3), None);
        assert_eq!(SchemaVersion::from_u16(u16::MAX), None);
    }

    #[test]
    fn schema_version_carries_freshness_envelope_only_for_v2_1() {
        assert!(!SchemaVersion::V2_0.carries_freshness_envelope());
        assert!( SchemaVersion::V2_1.carries_freshness_envelope());
    }

    #[test]
    fn schema_version_variant_count_is_pinned() {
        assert_eq!(SchemaVersion::ALL.len(), 2,
            "SchemaVersion has exactly 2 wire-stable variants \
             (V2_0 | V2_1); bumping this requires a Migration that \
             ALTERs the CHECK on plan_bundles.schema_version.");
    }

    // ── BundleSha256 / BundleNonce / OperatorFingerprint round-trip ───

    #[test]
    fn bundle_sha256_to_hex_round_trips() {
        let raw = [0xABu8; 32];
        let sha = BundleSha256::new(raw);
        assert_eq!(sha.as_bytes(), &raw);
        assert_eq!(sha.to_hex().len(), 64);
        assert_eq!(sha.to_hex(), "ab".repeat(32));
    }

    #[test]
    fn bundle_nonce_to_hex_is_32_chars() {
        let raw = [0x55u8; 16];
        let n = BundleNonce::new(raw);
        assert_eq!(n.as_bytes(), &raw);
        assert_eq!(n.to_hex().len(), 32);
        assert_eq!(n.to_hex(), "55".repeat(16));
    }

    #[test]
    fn operator_fingerprint_to_hex_is_16_chars() {
        let raw = [0x77u8; 8];
        let fp = OperatorFingerprint::new(raw);
        assert_eq!(fp.as_bytes(), &raw);
        assert_eq!(fp.to_hex().len(), 16);
        assert_eq!(fp.to_hex(), "77".repeat(8));
    }

    // ── PlanBundle constructors ───────────────────────────────────────

    #[test]
    fn new_v2_1_populates_freshness_envelope() {
        let nonce = BundleNonce::new([0x11u8; 16]);
        let pb = PlanBundle::new_v2_1(
            100, 200, nonce, "myplan".to_owned(),
            vec![BundleArtifact {
                name:   "plan.toml".to_owned(),
                bytes:  b"hello".to_vec(),
                sha256: BundleSha256::new([0u8; 32]),
            }],
        );
        assert_eq!(pb.schema_version,       SchemaVersion::V2_1);
        assert_eq!(pb.created_at_unix_secs, 100);
        assert_eq!(pb.signed_at_unix_secs,  Some(200));
        assert_eq!(pb.bundle_nonce,         Some(nonce));
        assert_eq!(pb.plan_root_relpath,    "myplan");
        assert_eq!(pb.artifacts.len(),      1);
    }

    #[test]
    fn new_v2_0_legacy_omits_freshness_envelope() {
        let pb = PlanBundle::new_v2_0_legacy(
            42, "old-plan".to_owned(),
            vec![BundleArtifact {
                name:   "plan.toml".to_owned(),
                bytes:  Vec::new(),
                sha256: BundleSha256::new([0u8; 32]),
            }],
        );
        assert_eq!(pb.schema_version,      SchemaVersion::V2_0);
        assert_eq!(pb.signed_at_unix_secs, None);
        assert_eq!(pb.bundle_nonce,        None);
        assert!(pb.schema_version.carries_freshness_envelope() == false);
    }

    /// Equality is content-defined: two artifacts with the same
    /// (name, bytes, sha256) must compare equal regardless of how
    /// they were constructed.
    #[test]
    fn bundle_artifact_equality_is_content_defined() {
        let a = BundleArtifact {
            name:   "plan.toml".to_owned(),
            bytes:  b"hello".to_vec(),
            sha256: BundleSha256::new([0xAAu8; 32]),
        };
        let b = BundleArtifact {
            name:   "plan.toml".to_owned(),
            bytes:  b"hello".to_vec(),
            sha256: BundleSha256::new([0xAAu8; 32]),
        };
        assert_eq!(a, b);

        // Different bytes → different.
        let c = BundleArtifact {
            name:   "plan.toml".to_owned(),
            bytes:  b"goodbye".to_vec(),
            sha256: BundleSha256::new([0xAAu8; 32]),
        };
        assert_ne!(a, c);
    }

    /// Display impls match the canonical hex projection used in audit
    /// rows + operator log lines.
    #[test]
    fn display_impls_match_hex() {
        let sha = BundleSha256::new([0x12u8; 32]);
        assert_eq!(format!("{}", sha), "12".repeat(32));
        let nonce = BundleNonce::new([0x34u8; 16]);
        assert_eq!(format!("{}", nonce), "34".repeat(16));
        let fp = OperatorFingerprint::new([0x56u8; 8]);
        assert_eq!(format!("{}", fp), "56".repeat(8));
        assert_eq!(format!("{}", SchemaVersion::V2_0), "V2.0");
        assert_eq!(format!("{}", SchemaVersion::V2_1), "V2.1");
    }
}

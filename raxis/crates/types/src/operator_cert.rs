// raxis-types::operator_cert — Wire types for operator certificates.
//
// Normative reference (forthcoming):
//   - kernel-store.md §2.5.7 "Operator Certificates"
//   - cli-ceremony.md §4.4 "Certificate ceremony"
//
// Why this lives in `raxis-types` and not `raxis-crypto`:
//   The crate layering rule (`philosophy.md §1.5`) is that `raxis-types`
//   is the wire/serde authority and depends on nothing in the workspace,
//   while `raxis-crypto` depends on `raxis-types` and adds signing /
//   verification primitives. This file owns the data shape (with serde
//   derives, used for TOML round-tripping inside `policy.toml` and the
//   stand-alone `*.cert.toml` artefact). The signing-input construction,
//   self-signature verification, and four-zone status helper live in
//   `raxis-crypto::cert` and operate on these types.
//
// Wire-stable contract:
//   The serde representation here IS the on-disk TOML representation.
//   Any field rename / addition / removal here is a wire-breaking change.
//   The cert format is versioned by the `raxis-cert/v1` tag baked into
//   `cert_canonical_signing_input` (raxis-crypto); a v2 format will get
//   a new struct (`OperatorCertV2`) rather than mutate this one.

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// CertKind — open enum of certificate categories.
//
// Serde uses PascalCase to match the canonical signing-input bytes
// produced by `raxis-crypto::cert::cert_canonical_signing_input`; the
// kernel ↔ CLI contract is that the on-disk string and the signed
// string are byte-identical.
// ---------------------------------------------------------------------------

/// The kind of an operator certificate. See `raxis-crypto::cert` for
/// the full lifecycle / enforcement semantics of each variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CertKind {
    /// Routine operator cert. Validity window is enforced; standard
    /// `permitted_ops` filtering applies.
    Standard,
    /// Break-glass cert. Validity window is IGNORED (always Active);
    /// `permitted_ops` is structurally pinned to `{"RotateEpoch"}`
    /// regardless of TOML declaration.
    EmergencyRecovery,
}

impl CertKind {
    /// Wire-canonical name. PascalCase. MUST match the serde
    /// representation byte-for-byte (the canonical signing input
    /// uses this string).
    pub fn as_str(self) -> &'static str {
        match self {
            CertKind::Standard => "Standard",
            CertKind::EmergencyRecovery => "EmergencyRecovery",
        }
    }

    /// Inverse of [`CertKind::as_str`]. Returns `None` for unknown
    /// kind names so callers can choose between failing loud and
    /// applying a forward-compat default.
    pub fn parse(s: &str) -> Option<CertKind> {
        match s {
            "Standard" => Some(CertKind::Standard),
            "EmergencyRecovery" => Some(CertKind::EmergencyRecovery),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// OperatorCert — the wire / on-disk struct.
//
// Serialised as TOML. Field names use snake_case (matches existing
// `policy.toml` style and the `[operators.entries.cert]` sub-table
// added by `raxis-policy::bundle` in step 3).
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// RevocationReason — V2_GAPS §D1 key/cert revocation taxonomy.
//
// `Rotation` is forward-only: the cert was retired in the normal course
// of operations. Plans signed before `revoked_at` remain valid, but
// new plan-signing operations under this cert are denied.
//
// `Compromise` is retroactive: the cert's private half may have been
// exposed. New operations are denied; live sessions admitted under
// the cert are terminated by the kernel.
//
// V2 supports exactly two values; the spec
// (`specs/v2/key-revocation.md §3.3`) explicitly forbids additional
// values without an epoch-advance ceremony.
// ---------------------------------------------------------------------------

/// Reason for a certificate revocation. Wire-stable PascalCase serde
/// projection (matches `key-revocation.md §3`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RevocationReason {
    /// Cert is being retired in the normal course of operations.
    /// Plans signed before `revoked_at` remain valid; new plans
    /// must be signed by a non-revoked cert.
    Rotation,
    /// Cert's private half has been or may have been exposed. New
    /// operations are denied permanently; in-flight sessions are
    /// torn down (V3 — V2 ships the admission-time gate only).
    Compromise,
}

impl RevocationReason {
    /// Wire-canonical name. PascalCase. MUST match the serde
    /// representation byte-for-byte.
    pub fn as_str(self) -> &'static str {
        match self {
            RevocationReason::Rotation => "Rotation",
            RevocationReason::Compromise => "Compromise",
        }
    }

    /// Inverse of [`RevocationReason::as_str`].
    pub fn parse(s: &str) -> Option<RevocationReason> {
        match s {
            "Rotation" => Some(RevocationReason::Rotation),
            "Compromise" => Some(RevocationReason::Compromise),
            _ => None,
        }
    }
}

/// Persistent record of a single operator-cert revocation. One file
/// per record under `<data_dir>/revocations/<fingerprint>.toml`.
///
/// Field semantics:
///   * `subject_pubkey_hex` — 64-char lowercase hex of the revoked
///     cert's `pubkey_hex`. Used as the on-disk filename (so a
///     single cert has at most one revocation record on disk).
///   * `subject_fingerprint` — SHA-256\[:16\]-byte 32-hex-char
///     fingerprint of `subject_pubkey_hex` bytes (matches
///     `policy.toml [meta].signed_by` and the `actor_fingerprint`
///     audit field).
///   * `reason` — see [`RevocationReason`].
///   * `revoked_at` — Unix seconds. Plans/ops attempted at or after
///     this instant are denied; for `Compromise` the time of
///     revocation is informational because rejection is
///     unconditional.
///   * `reference` — short operator-supplied string (incident id,
///     change-management ticket). Surfaces in audit logs.
///   * `revoked_by_pubkey_hex` — operator-key pubkey hex (64-char)
///     that signed the revocation. Must be a real operator entry
///     in the active policy bundle.
///   * `revoked_by_signature_hex` — Ed25519 signature over the
///     canonical signing input (`raxis-crypto::cert::revocation_canonical_signing_input`).
///   * `signing_input_version` — version tag for the canonical
///     signing input. Pinned to `"raxis-cert-revocation/v1"`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevocationRecord {
    pub subject_pubkey_hex: String,
    pub subject_fingerprint: String,
    pub reason: RevocationReason,
    pub revoked_at: i64,
    pub reference: String,
    pub revoked_by_pubkey_hex: String,
    pub revoked_by_signature_hex: String,
    pub signing_input_version: String,
}

/// On-disk representation of a single operator certificate.
///
/// Round-trips through TOML losslessly; the `permitted_ops` field
/// is stored as an unsorted array but the canonical signing input
/// (in `raxis-crypto`) sorts internally so writers don't have to
/// pre-sort.
///
/// **Field reference (mirrored, in detail, in `raxis-crypto::cert`):**
///
/// - `kind` — see [`CertKind`].
/// - `display_name` — human-readable operator label.
/// - `pubkey_hex` — 64-char lowercase hex of the operator's 32-byte raw
///   Ed25519 public key.
/// - `not_before` — Unix seconds. Cert is invalid before this for
///   `Standard` certs; IGNORED for `EmergencyRecovery`.
/// - `not_after` — Unix seconds. End of validity window for `Standard`
///   certs; IGNORED for `EmergencyRecovery`.
/// - `warn_before_expiry_days` — width of the Expiring zone.
/// - `grace_period_days` — width of the Grace zone.
/// - `permitted_ops` — list of operator op names this cert is allowed
///   to invoke.
/// - `contact_info` — optional free-form contact string.
/// - `self_sig_hex` — 128-char hex of the self-signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperatorCert {
    pub kind: CertKind,
    pub display_name: String,
    pub pubkey_hex: String,
    pub not_before: i64,
    pub not_after: i64,
    pub warn_before_expiry_days: u32,
    pub grace_period_days: u32,
    pub permitted_ops: Vec<String>,
    /// Optional. Always serialised; written as an empty string when
    /// absent so the canonical signing input has a stable shape.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contact_info: Option<String>,
    pub self_sig_hex: String,
}

// ---------------------------------------------------------------------------
// Tests — TOML round-trip.
//
// We pin the exact TOML byte shape so future serde / toml upgrades
// can't silently change the on-disk format. A change here is a
// wire-breaking change.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn standard_fixture() -> OperatorCert {
        OperatorCert {
            kind: CertKind::Standard,
            display_name: "Chika".to_owned(),
            pubkey_hex: "aa".repeat(32),
            not_before: 1_700_000_000,
            not_after: 1_731_536_000,
            warn_before_expiry_days: 30,
            grace_period_days: 7,
            permitted_ops: vec!["CreateInitiative".to_owned(), "ApprovePlan".to_owned()],
            contact_info: Some("chika@example.com".to_owned()),
            self_sig_hex: "bb".repeat(64),
        }
    }

    fn emergency_fixture() -> OperatorCert {
        OperatorCert {
            kind: CertKind::EmergencyRecovery,
            display_name: "break-glass".to_owned(),
            pubkey_hex: "cc".repeat(32),
            not_before: 0,
            not_after: 0,
            warn_before_expiry_days: 0,
            grace_period_days: 0,
            permitted_ops: vec!["RotateEpoch".to_owned()],
            contact_info: None,
            self_sig_hex: "dd".repeat(64),
        }
    }

    // ── TOML round-trip ─────────────────────────────────────────────

    #[test]
    fn standard_cert_round_trips_through_toml() {
        let original = standard_fixture();
        let s = toml::to_string(&original).expect("serialise");
        let parsed: OperatorCert = toml::from_str(&s).expect("parse");
        assert_eq!(parsed, original);
    }

    #[test]
    fn emergency_cert_round_trips_through_toml() {
        let original = emergency_fixture();
        let s = toml::to_string(&original).expect("serialise");
        let parsed: OperatorCert = toml::from_str(&s).expect("parse");
        assert_eq!(parsed, original);
    }

    #[test]
    fn cert_with_no_contact_info_round_trips() {
        let mut original = standard_fixture();
        original.contact_info = None;
        let s = toml::to_string(&original).expect("serialise");
        // contact_info is skip_serializing_if=Option::is_none, so it
        // shouldn't appear in the TOML at all.
        assert!(
            !s.contains("contact_info"),
            "contact_info should be omitted when None; got:\n{s}"
        );
        let parsed: OperatorCert = toml::from_str(&s).expect("parse");
        assert_eq!(parsed, original);
    }

    // ── kind serialisation ─────────────────────────────────────────

    #[test]
    fn cert_kind_serialises_as_pascal_case() {
        let s = toml::to_string(&standard_fixture()).unwrap();
        assert!(
            s.contains("kind = \"Standard\""),
            "kind must serialise as PascalCase; got:\n{s}"
        );
    }

    #[test]
    fn emergency_cert_kind_serialises_as_pascal_case() {
        let s = toml::to_string(&emergency_fixture()).unwrap();
        assert!(
            s.contains("kind = \"EmergencyRecovery\""),
            "kind must serialise as PascalCase; got:\n{s}"
        );
    }

    #[test]
    fn cert_kind_round_trips() {
        for kind in [CertKind::Standard, CertKind::EmergencyRecovery] {
            assert_eq!(CertKind::parse(kind.as_str()), Some(kind));
        }
    }

    #[test]
    fn cert_kind_parse_returns_none_for_unknown() {
        assert_eq!(CertKind::parse("ReadOnly"), None);
        assert_eq!(CertKind::parse(""), None);
        assert_eq!(
            CertKind::parse("standard"),
            None,
            "case-sensitive — parser must not normalise"
        );
    }

    // ── unknown-field rejection ─────────────────────────────────────

    /// Defensive: a future writer adding fields (e.g.
    /// `revocation_url`) we don't know about should NOT silently
    /// pass an older parser. We don't enable serde's
    /// `deny_unknown_fields` here (no derive attribute) on purpose
    /// — the policy bundle layer (raxis-policy) is the gate that
    /// decides forward-compat behaviour. This test pins that an
    /// extra field is currently TOLERATED (parsed and dropped).
    /// If we ever flip to `deny_unknown_fields`, this test must
    /// update with that change.
    #[test]
    fn extra_unknown_fields_are_tolerated_but_dropped() {
        let s = toml::to_string(&standard_fixture()).unwrap() + "\nfuture_field = \"ignored\"\n";
        let parsed: OperatorCert =
            toml::from_str(&s).expect("parser must tolerate forward-compat fields today");
        assert_eq!(parsed, standard_fixture());
    }

    // ── pinned TOML byte-shape for the fixture ──────────────────────

    /// Pin the on-disk TOML byte shape so future serde / toml-rs
    /// upgrades can't silently change the format. This is the exact
    /// shape `raxis cert mint` writes and `raxis cert verify` reads.
    #[test]
    fn standard_cert_toml_shape_is_pinned() {
        let s = toml::to_string(&standard_fixture()).unwrap();
        let expected = "\
kind = \"Standard\"
display_name = \"Chika\"
pubkey_hex = \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"
not_before = 1700000000
not_after = 1731536000
warn_before_expiry_days = 30
grace_period_days = 7
permitted_ops = [\"CreateInitiative\", \"ApprovePlan\"]
contact_info = \"chika@example.com\"
self_sig_hex = \"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\"
";
        assert_eq!(s, expected, "TOML byte shape drift; got:\n{s}");
    }
}

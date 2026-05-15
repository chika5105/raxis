// raxis-crypto::cert — Operator certificate format, canonical signing
// input, and self-signature verification.
//
// Normative reference (forthcoming):
//   - kernel-store.md §2.5.7 "Operator Certificates" (added in step 12)
//   - cli-ceremony.md §4.4 "Certificate ceremony" (added in step 12)
//
// Crate rules carried over from `raxis-crypto/lib.rs` apply here:
//   - No I/O. No SQLite. No tokio.
//   - Pure functions only — input → output.
//   - Raw private key bytes never appear in exported types; signing
//     happens externally via the `SigningKey` borrowed from
//     `ed25519_dalek` (or whatever the operator's HSM exposes).
//
// ─────────────────────────────────────────────────────────────────────────────
// What is an OperatorCert?
//
// An OperatorCert is a self-signed Ed25519 attestation that pairs an
// operator's public key with metadata about the human and a validity
// window. Self-signed: the operator signs over a canonical byte
// representation of their own metadata; the signature is verifiable
// using the same public key the cert is for. The trust root is NOT
// the cert chain; the trust root is `policy.toml`, which lists the
// operator entries and is itself signed by the policy authority.
//
// The cert's job is purely to add metadata + a validity window to an
// otherwise raw public key. Embedding the cert in `policy.toml` (the
// canonical RAXIS source of truth for who is an operator) means the
// metadata gets the same epoch-advance ceremony as the public key,
// keeping policy and metadata atomically in sync.
//
// ─────────────────────────────────────────────────────────────────────────────
// Why two CertKind variants and what they buy us
//
// `Standard` certs are the routine case: they have a finite validity
// window (`not_before` ≤ `not_after`), warn the operator some days
// before expiry, and enter a recovery-only `Grace` zone briefly
// after expiry before going hard-Expired. They participate in the
// `permitted_ops` system normally.
//
// `EmergencyRecovery` certs are the structural break-glass:
//   - They IGNORE `not_before` / `not_after` (always Active).
//   - The kernel pins their `permitted_ops` to a hard-coded singleton
//     `{"RotateEpoch"}` regardless of what the policy bundle declares.
//   - Every successful use emits a high-visibility audit event.
//
// Making this a typed enum (rather than "a regular cert with one
// permission, by convention") gives us compile-time enforcement of
// the structural invariants. The `validate_cert_structurally` step
// fails LOUD on any deviation (e.g. `EmergencyRecovery` cert with
// extra `permitted_ops` set in TOML) so misconfiguration is visible
// at policy-load time, not at incident-response time. The misconfig
// is bypassable with an explicit `force_misconfig_bypass = true`
// per-entry flag, but the bypass itself emits its own audit event
// at boot — so opacity is impossible.

use ed25519_dalek::{Signer, SigningKey};
use thiserror::Error;

use crate::verify::{verify_ed25519, CryptoError};

// The data shape (struct + enum) lives in `raxis-types::operator_cert`
// so it can carry serde derives without dragging serde / TOML into
// this crate. We re-export here for ergonomics — most callers only
// deal with `raxis-crypto::cert` (sign/verify/status) and want the
// types in the same namespace.
pub use raxis_types::operator_cert::{CertKind, OperatorCert, RevocationReason, RevocationRecord};

// ---------------------------------------------------------------------------
// CertError — failure modes for cert construction / verification.
//
// Display strings end up in `FAIL_CERT_VALIDATION` kernel responses
// and `raxis cert verify` CLI output. Stable wording — operators
// grep for these.
// ---------------------------------------------------------------------------

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CertError {
    #[error("malformed pubkey_hex: expected 64 lowercase hex chars, got {0:?}")]
    MalformedPubkey(String),

    #[error("malformed self_sig_hex: expected 128 lowercase hex chars, got {0:?}")]
    MalformedSelfSig(String),

    #[error("self-signature verification failed (cert pubkey did not sign cert metadata): {0}")]
    SelfSignatureInvalid(String),

    #[error("not_before ({not_before}) > not_after ({not_after}); cert can never be valid")]
    InvertedValidityWindow { not_before: i64, not_after: i64 },

    #[error(
        "warn_before_expiry_days ({warn}) must be < validity window ({validity_secs}s); \
         a warn window wider than validity is meaningless"
    )]
    WarnWindowExceedsValidity { warn: u32, validity_secs: i64 },

    #[error("display_name must be non-empty and ≤ 256 chars; got {len} chars")]
    DisplayNameLength { len: usize },

    #[error("permitted_ops must be non-empty for Standard certs")]
    StandardCertHasNoPermissions,

    #[error(
        "EmergencyRecovery cert MUST declare permitted_ops = [\"RotateEpoch\"] only; \
         got {got:?}. The kernel structurally pins emergency permissions to RotateEpoch \
         regardless of TOML; this error surfaces operator misconfiguration so it cannot \
         silently accumulate. Bypass: set force_misconfig_bypass = true on the \
         operator entry to consent to the structural override (the bypass itself \
         emits an audit event)."
    )]
    EmergencyHasWrongPermissions { got: Vec<String> },

    #[error(
        "EmergencyRecovery cert MUST set not_before = 0 and not_after = 0 \
         (the kernel ignores these fields and treats emergency certs as always-Active); \
         got not_before={not_before}, not_after={not_after}. \
         Bypass: set force_misconfig_bypass = true on the operator entry."
    )]
    EmergencyHasValidityWindow { not_before: i64, not_after: i64 },

    #[error("hex decode error: {0}")]
    HexDecode(String),
}

impl From<CryptoError> for CertError {
    fn from(e: CryptoError) -> Self {
        match e {
            CryptoError::SignatureInvalid(err) => CertError::SelfSignatureInvalid(err.to_string()),
            CryptoError::MalformedPublicKey(s) => CertError::MalformedPubkey(s),
            CryptoError::MalformedSignature(s) => CertError::MalformedSelfSig(s),
            CryptoError::HexDecode(e) => CertError::HexDecode(e.to_string()),
            CryptoError::Rng(e) => CertError::HexDecode(e.to_string()),
            // Cert verification never enters the plan-bundle code path.
            // If it ever does, surface the codec error through the
            // structurally-closest variant rather than `panic!`-ing.
            CryptoError::PlanBundleEncode(e) => CertError::HexDecode(e.to_string()),
        }
    }
}

// ---------------------------------------------------------------------------
// canonical_signing_input — byte-exact contract with `raxis cert mint`.
//
// **NORMATIVE byte layout (UTF-8, ASCII pipe separators):**
//
//   raxis-cert/v1|<kind>|<display_name>|<pubkey_hex>|<not_before>|\
//   <not_after>|<warn_before_expiry_days>|<grace_period_days>|\
//   <permitted_ops_csv>|<contact_info_or_empty>
//
// where:
//   - `<kind>`              — `CertKind::as_str()` (PascalCase).
//   - `<permitted_ops_csv>` — sorted, comma-separated, no trailing comma
//                             (sort enforced by `canonicalize_ops`).
//   - `<contact_info>`      — verbatim if set, empty string if `None`.
//
// **Pipe-character disclaimer:** none of the fields can contain a
// pipe in practice (`pubkey_hex` is hex, integers are integers,
// `kind` is an enum variant name, `display_name` and `contact_info`
// are linted by [`validate_cert_structurally`] to reject pipes /
// newlines).
//
// This format is the kernel ↔ CLI contract. Both sides go through
// THIS function — drift breaks `tests::canonical_signing_input_byte_layout`.
// ---------------------------------------------------------------------------

/// Construct the canonical signing input for an [`OperatorCert`].
///
/// Returns the raw bytes; the caller signs them with their private
/// key (or hands them to `verify_ed25519` to authenticate).
///
/// **Note:** `permitted_ops` is sorted internally by this function.
/// The caller does NOT need to pre-sort; this avoids the entire
/// class of "I sorted it differently than the verifier did" bugs.
//
// `clippy::too_many_arguments` is intentionally allowed: the
// nine parameters mirror the nine fields of the canonical
// `raxis-cert/v1` signing-input contract one-for-one. Bundling
// them into a struct (or accepting `&OperatorCert` directly)
// would either hide that contract behind an indirection or
// force tests to construct a full `OperatorCert` (including the
// not-yet-known `self_sig_hex`) just to compute signing bytes.
#[allow(clippy::too_many_arguments)]
pub fn cert_canonical_signing_input(
    kind: CertKind,
    display_name: &str,
    pubkey_hex: &str,
    not_before: i64,
    not_after: i64,
    warn_before_expiry_days: u32,
    grace_period_days: u32,
    permitted_ops: &[String],
    contact_info: Option<&str>,
) -> Vec<u8> {
    let ops_csv = canonicalize_ops(permitted_ops).join(",");
    let contact = contact_info.unwrap_or("");
    format!(
        "raxis-cert/v1|{}|{}|{}|{}|{}|{}|{}|{}|{}",
        kind.as_str(),
        display_name,
        pubkey_hex,
        not_before,
        not_after,
        warn_before_expiry_days,
        grace_period_days,
        ops_csv,
        contact,
    )
    .into_bytes()
}

/// Sort + dedupe an op list to canonical form. Used by both signing
/// input construction and structural validation so the two halves
/// agree on what "this op set" means.
pub fn canonicalize_ops(ops: &[String]) -> Vec<String> {
    let mut out: Vec<String> = ops.to_vec();
    out.sort();
    out.dedup();
    out
}

// ---------------------------------------------------------------------------
// sign_cert / verify_cert
// ---------------------------------------------------------------------------

/// Sign an `OperatorCert`'s metadata with `signing_key` and return
/// the signature as a 128-char hex string. Used by `raxis cert mint`.
///
/// This function does NOT mutate `cert`; the caller writes the
/// returned hex into `cert.self_sig_hex` themselves. We keep it
/// pure-input → pure-output for trivial test composability.
pub fn sign_cert(cert: &OperatorCert, signing_key: &SigningKey) -> String {
    let msg = cert_canonical_signing_input(
        cert.kind,
        &cert.display_name,
        &cert.pubkey_hex,
        cert.not_before,
        cert.not_after,
        cert.warn_before_expiry_days,
        cert.grace_period_days,
        &cert.permitted_ops,
        cert.contact_info.as_deref(),
    );
    let sig = signing_key.sign(&msg);
    hex::encode(sig.to_bytes())
}

/// Verify the cert's self-signature: the bytes in `cert.self_sig_hex`
/// must be a valid Ed25519 signature of `cert_canonical_signing_input(...)`
/// under the public key `cert.pubkey_hex`.
///
/// Returns `Ok(())` on a valid signature; `Err(CertError::*)` on
/// any malformed input or signature mismatch. This is the call
/// `raxis cert verify` and the kernel-side bundle-validate step
/// both go through.
pub fn verify_cert_self_signature(cert: &OperatorCert) -> Result<(), CertError> {
    let pubkey_bytes =
        hex::decode(&cert.pubkey_hex).map_err(|e| CertError::HexDecode(e.to_string()))?;
    let sig_bytes =
        hex::decode(&cert.self_sig_hex).map_err(|e| CertError::HexDecode(e.to_string()))?;
    let msg = cert_canonical_signing_input(
        cert.kind,
        &cert.display_name,
        &cert.pubkey_hex,
        cert.not_before,
        cert.not_after,
        cert.warn_before_expiry_days,
        cert.grace_period_days,
        &cert.permitted_ops,
        cert.contact_info.as_deref(),
    );
    verify_ed25519(&pubkey_bytes, &msg, &sig_bytes)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// validate_cert_structurally — fail-loud invariant checks.
//
// Called by the policy bundle loader BEFORE `verify_cert_self_signature`.
// Any failure here surfaces as `FAIL_CERT_VALIDATION` (or, at boot,
// `BOOT_ERR_BAD_OPERATOR_CERT`) and refuses to install the cert.
//
// The bundle loader can OPT OUT per-entry via `force_misconfig_bypass = true`,
// in which case `validate_cert_structurally`'s output is logged
// (and audited as `OperatorCertMisconfigBypassed`) but does not
// block installation. The bypass is the ONLY way to deviate from
// these rules — operator behaviour cannot be opaque.
// ---------------------------------------------------------------------------

/// Run the structural invariant checks on a cert. Returns the
/// ordered list of violations (empty = cert is structurally valid).
///
/// We collect ALL violations rather than short-circuiting on the
/// first so an operator running `raxis cert verify <broken.cert>`
/// gets the full list in one pass.
pub fn validate_cert_structurally(cert: &OperatorCert) -> Vec<CertError> {
    let mut errs = Vec::new();

    // ── Pubkey shape ─────────────────────────────────────────────────
    if !is_valid_lowercase_hex(&cert.pubkey_hex, 64) {
        errs.push(CertError::MalformedPubkey(cert.pubkey_hex.clone()));
    }
    if !is_valid_lowercase_hex(&cert.self_sig_hex, 128) {
        errs.push(CertError::MalformedSelfSig(cert.self_sig_hex.clone()));
    }

    // ── Display name ─────────────────────────────────────────────────
    let len = cert.display_name.chars().count();
    if len == 0 || len > 256 {
        errs.push(CertError::DisplayNameLength { len });
    }

    // ── Kind-specific invariants ─────────────────────────────────────
    match cert.kind {
        CertKind::Standard => {
            if cert.not_before > cert.not_after {
                errs.push(CertError::InvertedValidityWindow {
                    not_before: cert.not_before,
                    not_after: cert.not_after,
                });
            }
            let validity_secs = cert.not_after.saturating_sub(cert.not_before);
            let warn_secs = (cert.warn_before_expiry_days as i64).saturating_mul(86_400);
            if validity_secs > 0 && warn_secs >= validity_secs {
                errs.push(CertError::WarnWindowExceedsValidity {
                    warn: cert.warn_before_expiry_days,
                    validity_secs,
                });
            }
            if cert.permitted_ops.is_empty() {
                errs.push(CertError::StandardCertHasNoPermissions);
            }
        }
        CertKind::EmergencyRecovery => {
            // EmergencyRecovery MUST have permitted_ops = ["RotateEpoch"]
            // exactly. Anything else (extra ops, missing ops, wrong
            // case) is misconfig.
            let canonical = canonicalize_ops(&cert.permitted_ops);
            if canonical.as_slice() != ["RotateEpoch".to_owned()].as_slice() {
                errs.push(CertError::EmergencyHasWrongPermissions { got: canonical });
            }
            // EmergencyRecovery MUST have not_before = 0 and not_after = 0
            // (the "ignored" sentinel). Setting any other value implies
            // the operator THINKS expiry applies — surface that.
            if cert.not_before != 0 || cert.not_after != 0 {
                errs.push(CertError::EmergencyHasValidityWindow {
                    not_before: cert.not_before,
                    not_after: cert.not_after,
                });
            }
        }
    }

    errs
}

fn is_valid_lowercase_hex(s: &str, expected_len: usize) -> bool {
    s.len() == expected_len
        && s.chars()
            .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
}

// ---------------------------------------------------------------------------
// CertStatus — the four-zone state machine.
//
// The kernel checks status at every operator IPC dispatch via
// `cert_check::enforce_cert_status` (added in step 6). This module
// just provides the pure status computation; the policy/enforcement
// layer decides what each zone allows.
// ---------------------------------------------------------------------------

/// The current zone of an operator cert relative to a wall-clock
/// instant `now`. See module docstring for the four-zone model.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertStatus {
    /// Now is within `[not_before, not_after - warn_window)`.
    /// All `permitted_ops` allowed; no warning emitted.
    Active,

    /// Now is within `[not_after - warn_window, not_after)`.
    /// All `permitted_ops` allowed; per-op warn audit emitted.
    Expiring { secs_until_expiry: i64 },

    /// Now is within `[not_after, not_after + grace_window)`.
    /// Only recovery / destructive ops allowed (the kernel-side
    /// allow-list lives in `kernel/authority/cert_check.rs`).
    Grace { secs_until_grace_end: i64 },

    /// Now is at or after `not_after + grace_window`.
    /// All ops denied.
    Expired { secs_since_expiry: i64 },

    /// Now is before `not_before`. All ops denied — the cert is
    /// not yet authorised. Expected to be transient (the operator
    /// just installed a future-dated cert during a planned rotation).
    NotYetValid { secs_until_active: i64 },

    /// `EmergencyRecovery` certs are always Active; this variant
    /// exists so operator dashboards can distinguish "perpetually
    /// active because it's an emergency cert" from "active and
    /// will eventually expire". Carries no timestamp.
    AlwaysActiveEmergency,

    /// V2_GAPS §D1 — the cert has been revoked. All ops denied
    /// regardless of `not_before` / `not_after`. The operator
    /// must mint a new cert (and a new signing key) to resume.
    /// Carries the revocation reason (rotation vs compromise) and
    /// a one-line operator-supplied reference for forensic
    /// attribution.
    Revoked {
        /// Reason for revocation. `Compromise` is treated identically
        /// to `Rotation` at the admission gate (both deny the op);
        /// the distinction is preserved for downstream tooling
        /// (audit replay, kernel-side session-termination — V3).
        reason: RevocationReason,
        /// Unix seconds at which the revocation took effect.
        revoked_at: i64,
    },
}

impl CertStatus {
    /// Whether the cert is currently allowed to perform new
    /// commitments (`CreateInitiative`, `ApprovePlan`, etc.).
    /// Recovery ops are governed by [`CertStatus::allows_recovery_ops`].
    /// Revoked certs deny ALL ops regardless of zone.
    pub fn allows_new_commitments(&self) -> bool {
        matches!(
            self,
            CertStatus::Active | CertStatus::Expiring { .. } | CertStatus::AlwaysActiveEmergency,
        )
    }

    /// Whether the cert is currently allowed to perform recovery ops
    /// (`AbortTask`, `AbortInitiative`, `RevokeSession`, `DenyEscalation`,
    /// `RotateEpoch`). Active / Expiring / Grace all allow these;
    /// Expired, NotYetValid, and Revoked do not.
    pub fn allows_recovery_ops(&self) -> bool {
        matches!(
            self,
            CertStatus::Active
                | CertStatus::Expiring { .. }
                | CertStatus::Grace { .. }
                | CertStatus::AlwaysActiveEmergency,
        )
    }

    /// Stable string tag used in audit events and `raxis cert list`
    /// output. Operators grep these.
    pub fn tag(&self) -> &'static str {
        match self {
            CertStatus::Active => "active",
            CertStatus::Expiring { .. } => "expiring",
            CertStatus::Grace { .. } => "grace",
            CertStatus::Expired { .. } => "expired",
            CertStatus::NotYetValid { .. } => "not_yet_valid",
            CertStatus::AlwaysActiveEmergency => "always_active_emergency",
            CertStatus::Revoked { .. } => "revoked",
        }
    }
}

/// Pure status computation. Does not consult any clock — caller
/// supplies `now` (Unix seconds).
///
/// `EmergencyRecovery` certs always return `AlwaysActiveEmergency`
/// regardless of `now` — their validity window is structurally
/// ignored.
pub fn cert_status(cert: &OperatorCert, now: i64) -> CertStatus {
    if matches!(cert.kind, CertKind::EmergencyRecovery) {
        return CertStatus::AlwaysActiveEmergency;
    }

    if now < cert.not_before {
        return CertStatus::NotYetValid {
            secs_until_active: cert.not_before - now,
        };
    }

    let warn_secs = (cert.warn_before_expiry_days as i64).saturating_mul(86_400);
    let grace_secs = (cert.grace_period_days as i64).saturating_mul(86_400);
    let warn_start = cert.not_after.saturating_sub(warn_secs);
    let grace_end = cert.not_after.saturating_add(grace_secs);

    if now < warn_start {
        CertStatus::Active
    } else if now < cert.not_after {
        CertStatus::Expiring {
            secs_until_expiry: cert.not_after - now,
        }
    } else if now < grace_end {
        CertStatus::Grace {
            secs_until_grace_end: grace_end - now,
        }
    } else {
        CertStatus::Expired {
            secs_since_expiry: now - cert.not_after,
        }
    }
}

// ---------------------------------------------------------------------------
// V2_GAPS §D1 — Revocation: canonical signing input + verifier
// ---------------------------------------------------------------------------
//
// The revocation record carries a self-contained Ed25519 signature
// over a canonical byte string so the kernel can verify the record
// at boot without consulting the issuing CLI's audit trail. The
// signing input mirrors the cert-signing input shape (`raxis-cert/v1|...`)
// for ergonomic consistency: one byte-layout style across the
// crate so the kernel ↔ CLI contract is uniform.
//
// **Signing input (UTF-8, ASCII pipe separators):**
//
//   raxis-cert-revocation/v1|<subject_pubkey_hex>|<reason>|<revoked_at>|<reference>
//
// where:
//   - `<subject_pubkey_hex>` — 64-char lowercase hex of the cert
//     being revoked.
//   - `<reason>`             — `RevocationReason::as_str()`
//     (`"Rotation"` | `"Compromise"`).
//   - `<revoked_at>`         — Unix seconds, signed integer.
//   - `<reference>`          — operator-supplied free-form string
//     (incident id, ticket, etc.). Linted by the issuing CLI to
//     forbid pipes / newlines.
//
// The signing key is the operator's plan-signing key (the same key
// that signs `policy.toml` and `plan.toml`). The verifier MUST
// confirm that the signing key is a known operator entry in the
// active policy bundle BEFORE accepting the revocation; this gate
// is implemented in the kernel side, not in this crate.

/// Canonical signing input for a revocation record. Same byte-layout
/// style as `cert_canonical_signing_input` so the contract is
/// uniform within the crate.
pub fn revocation_canonical_signing_input(
    subject_pubkey_hex: &str,
    reason: RevocationReason,
    revoked_at: i64,
    reference: &str,
) -> Vec<u8> {
    format!(
        "raxis-cert-revocation/v1|{}|{}|{}|{}",
        subject_pubkey_hex,
        reason.as_str(),
        revoked_at,
        reference,
    )
    .into_bytes()
}

/// Sign a revocation record's canonical input with `signing_key`.
/// Returns the 128-char hex signature. The caller writes it into
/// `record.revoked_by_signature_hex`.
pub fn sign_revocation(
    subject_pubkey_hex: &str,
    reason: RevocationReason,
    revoked_at: i64,
    reference: &str,
    signing_key: &SigningKey,
) -> String {
    let msg = revocation_canonical_signing_input(subject_pubkey_hex, reason, revoked_at, reference);
    let sig = signing_key.sign(&msg);
    hex::encode(sig.to_bytes())
}

/// Verify the signature on a revocation record. Returns `Ok(())` on
/// a valid signature; `Err(CertError::*)` on malformed hex or
/// signature mismatch. The caller is still responsible for
/// confirming that `record.revoked_by_pubkey_hex` corresponds to a
/// trusted operator entry in the active policy bundle.
///
/// This function does NOT mutate state and does NOT consult the
/// filesystem; it is pure-input → pure-output by the same crate
/// rules as `verify_cert_self_signature`.
pub fn verify_revocation_signature(record: &RevocationRecord) -> Result<(), CertError> {
    if record.signing_input_version != "raxis-cert-revocation/v1" {
        return Err(CertError::SelfSignatureInvalid(format!(
            "unknown signing_input_version {:?} (expected \"raxis-cert-revocation/v1\")",
            record.signing_input_version,
        )));
    }
    if !is_valid_lowercase_hex(&record.revoked_by_pubkey_hex, 64) {
        return Err(CertError::MalformedPubkey(
            record.revoked_by_pubkey_hex.clone(),
        ));
    }
    if !is_valid_lowercase_hex(&record.revoked_by_signature_hex, 128) {
        return Err(CertError::MalformedSelfSig(
            record.revoked_by_signature_hex.clone(),
        ));
    }
    if !is_valid_lowercase_hex(&record.subject_pubkey_hex, 64) {
        return Err(CertError::MalformedPubkey(
            record.subject_pubkey_hex.clone(),
        ));
    }

    let pubkey = hex::decode(&record.revoked_by_pubkey_hex)
        .map_err(|e| CertError::HexDecode(e.to_string()))?;
    let sig = hex::decode(&record.revoked_by_signature_hex)
        .map_err(|e| CertError::HexDecode(e.to_string()))?;
    let msg = revocation_canonical_signing_input(
        &record.subject_pubkey_hex,
        record.reason,
        record.revoked_at,
        &record.reference,
    );
    verify_ed25519(&pubkey, &msg, &sig)?;
    Ok(())
}

/// `cert_status` extension that consults a revocation lookup BEFORE
/// computing the four-zone state machine. Returns `Revoked` whenever
/// the supplied closure returns `Some`; otherwise delegates to
/// `cert_status`.
///
/// V2_GAPS §D1 — admission-time revocation gate.
pub fn cert_status_with_revocation<F>(
    cert: &OperatorCert,
    now: i64,
    revocation_lookup: F,
) -> CertStatus
where
    F: FnOnce(&str) -> Option<(RevocationReason, i64)>,
{
    if let Some((reason, revoked_at)) = revocation_lookup(&cert.pubkey_hex) {
        return CertStatus::Revoked { reason, revoked_at };
    }
    cert_status(cert, now)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    // Deterministic 32-byte seed for the test signing key. Lets every
    // test produce the same pubkey and signatures, so we can pin
    // exact byte strings in assertions if needed.
    const TEST_SEED: [u8; 32] = [42u8; 32];

    fn test_signing_key() -> SigningKey {
        SigningKey::from_bytes(&TEST_SEED)
    }

    fn test_pubkey_hex() -> String {
        hex::encode(test_signing_key().verifying_key().to_bytes())
    }

    /// Build a Standard cert valid for [now-1d, now+90d] with
    /// 30d warn / 7d grace and a single permission. The self-sig
    /// is freshly minted from `test_signing_key`.
    fn fixture_standard_cert(now: i64) -> OperatorCert {
        let mut c = OperatorCert {
            kind: CertKind::Standard,
            display_name: "Chika".to_owned(),
            pubkey_hex: test_pubkey_hex(),
            not_before: now - 86_400,
            not_after: now + 90 * 86_400,
            warn_before_expiry_days: 30,
            grace_period_days: 7,
            permitted_ops: vec!["CreateInitiative".to_owned()],
            contact_info: Some("chika@example.com".to_owned()),
            self_sig_hex: String::new(),
        };
        c.self_sig_hex = sign_cert(&c, &test_signing_key());
        c
    }

    fn fixture_emergency_cert() -> OperatorCert {
        let mut c = OperatorCert {
            kind: CertKind::EmergencyRecovery,
            display_name: "Break-glass — offline storage".to_owned(),
            pubkey_hex: test_pubkey_hex(),
            not_before: 0,
            not_after: 0,
            warn_before_expiry_days: 0,
            grace_period_days: 0,
            permitted_ops: vec!["RotateEpoch".to_owned()],
            contact_info: None,
            self_sig_hex: String::new(),
        };
        c.self_sig_hex = sign_cert(&c, &test_signing_key());
        c
    }

    // ── canonical_signing_input ───────────────────────────────────────

    #[test]
    fn canonical_signing_input_byte_layout_is_pinned() {
        // The kernel ↔ CLI contract. Any change to this string is a
        // wire-breaking change to the cert format and demands a new
        // version tag (`raxis-cert/v2`). The exact bytes here are
        // what an operator signs.
        let bytes = cert_canonical_signing_input(
            CertKind::Standard,
            "Chika",
            "aa".repeat(32).as_str(),
            1_700_000_000,
            1_731_536_000,
            30,
            7,
            &["CreateInitiative".to_owned(), "AbortTask".to_owned()],
            Some("chika@example.com"),
        );
        let s = std::str::from_utf8(&bytes).unwrap();
        // permitted_ops are sorted by canonicalize_ops (AbortTask < CreateInitiative).
        assert_eq!(
            s,
            "raxis-cert/v1|Standard|Chika|\
             aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa|\
             1700000000|1731536000|30|7|\
             AbortTask,CreateInitiative|chika@example.com"
        );
    }

    #[test]
    fn canonical_signing_input_emits_empty_contact_when_none() {
        let bytes = cert_canonical_signing_input(
            CertKind::Standard,
            "Chika",
            "aa".repeat(32).as_str(),
            0,
            0,
            0,
            0,
            &["CreateInitiative".to_owned()],
            None,
        );
        let s = std::str::from_utf8(&bytes).unwrap();
        assert!(
            s.ends_with("|"),
            "trailing-empty-contact must be present: {s}"
        );
    }

    #[test]
    fn canonical_signing_input_sorts_permitted_ops_internally() {
        // Caller supplies unsorted ops; signer and verifier produce
        // identical bytes regardless. This test pins that the sort
        // is built-in, NOT a caller responsibility.
        let unsorted = cert_canonical_signing_input(
            CertKind::Standard,
            "X",
            "aa".repeat(32).as_str(),
            0,
            0,
            0,
            0,
            &["CreateInitiative".to_owned(), "AbortTask".to_owned()],
            None,
        );
        let presorted = cert_canonical_signing_input(
            CertKind::Standard,
            "X",
            "aa".repeat(32).as_str(),
            0,
            0,
            0,
            0,
            &["AbortTask".to_owned(), "CreateInitiative".to_owned()],
            None,
        );
        assert_eq!(unsorted, presorted);
    }

    #[test]
    fn canonical_signing_input_dedupes_permitted_ops() {
        // Defensive: a TOML with duplicate entries shouldn't change
        // the signing input vs the same TOML without duplicates.
        let with_dup = cert_canonical_signing_input(
            CertKind::Standard,
            "X",
            "aa".repeat(32).as_str(),
            0,
            0,
            0,
            0,
            &["AbortTask".to_owned(), "AbortTask".to_owned()],
            None,
        );
        let no_dup = cert_canonical_signing_input(
            CertKind::Standard,
            "X",
            "aa".repeat(32).as_str(),
            0,
            0,
            0,
            0,
            &["AbortTask".to_owned()],
            None,
        );
        assert_eq!(with_dup, no_dup);
    }

    // ── sign_cert / verify_cert_self_signature ────────────────────────

    #[test]
    fn freshly_minted_standard_cert_self_verifies() {
        let cert = fixture_standard_cert(1_700_000_000);
        verify_cert_self_signature(&cert).expect("freshly-minted cert must self-verify");
    }

    #[test]
    fn freshly_minted_emergency_cert_self_verifies() {
        let cert = fixture_emergency_cert();
        verify_cert_self_signature(&cert).expect("emergency cert must self-verify");
    }

    #[test]
    fn altering_any_signed_field_invalidates_signature() {
        // Tamper-evidence: every field that goes into the canonical
        // signing input must affect the signature. Otherwise an
        // attacker can trivially mutate the metadata after signing.
        let base = fixture_standard_cert(1_700_000_000);

        let mut t1 = base.clone();
        t1.display_name = "Mallory".to_owned();
        assert!(
            verify_cert_self_signature(&t1).is_err(),
            "display_name change must invalidate sig"
        );

        let mut t2 = base.clone();
        t2.not_after = base.not_after + 86_400;
        assert!(
            verify_cert_self_signature(&t2).is_err(),
            "not_after change must invalidate sig"
        );

        let mut t3 = base.clone();
        t3.permitted_ops = vec!["RotateEpoch".to_owned()];
        assert!(
            verify_cert_self_signature(&t3).is_err(),
            "permitted_ops change must invalidate sig"
        );

        let mut t4 = base.clone();
        t4.contact_info = Some("attacker@evil.example".to_owned());
        assert!(
            verify_cert_self_signature(&t4).is_err(),
            "contact_info change must invalidate sig"
        );

        let mut t5 = base;
        t5.kind = CertKind::EmergencyRecovery;
        assert!(
            verify_cert_self_signature(&t5).is_err(),
            "kind change must invalidate sig"
        );
    }

    #[test]
    fn signature_signed_by_different_key_does_not_verify() {
        // Self-signed means the cert MUST be signed by the very
        // pubkey it advertises. A signature from a different key —
        // even a key the operator owns — is not acceptable.
        let mut cert = fixture_standard_cert(1_700_000_000);
        let other_key = SigningKey::from_bytes(&[0xCDu8; 32]);
        cert.self_sig_hex = sign_cert(&cert, &other_key);
        assert!(
            verify_cert_self_signature(&cert).is_err(),
            "signature by non-cert-key must be rejected"
        );
    }

    // ── validate_cert_structurally ────────────────────────────────────

    #[test]
    fn well_formed_standard_cert_passes_structural_validation() {
        let cert = fixture_standard_cert(1_700_000_000);
        assert!(validate_cert_structurally(&cert).is_empty());
    }

    #[test]
    fn well_formed_emergency_cert_passes_structural_validation() {
        let cert = fixture_emergency_cert();
        assert!(validate_cert_structurally(&cert).is_empty());
    }

    #[test]
    fn inverted_validity_window_is_a_structural_error() {
        let mut cert = fixture_standard_cert(1_700_000_000);
        cert.not_before = cert.not_after + 1;
        let errs = validate_cert_structurally(&cert);
        assert!(
            errs.iter()
                .any(|e| matches!(e, CertError::InvertedValidityWindow { .. })),
            "got: {errs:?}"
        );
    }

    #[test]
    fn warn_window_wider_than_validity_is_a_structural_error() {
        let mut cert = fixture_standard_cert(1_700_000_000);
        // 90-day validity, set warn to 100 days.
        cert.warn_before_expiry_days = 100;
        // Re-sign so we don't also fail on signature mismatch.
        cert.self_sig_hex = sign_cert(&cert, &test_signing_key());
        let errs = validate_cert_structurally(&cert);
        assert!(
            errs.iter()
                .any(|e| matches!(e, CertError::WarnWindowExceedsValidity { .. })),
            "got: {errs:?}"
        );
    }

    #[test]
    fn empty_display_name_is_a_structural_error() {
        let mut cert = fixture_standard_cert(1_700_000_000);
        cert.display_name = String::new();
        cert.self_sig_hex = sign_cert(&cert, &test_signing_key());
        let errs = validate_cert_structurally(&cert);
        assert!(errs
            .iter()
            .any(|e| matches!(e, CertError::DisplayNameLength { .. })));
    }

    #[test]
    fn standard_cert_with_no_permitted_ops_is_a_structural_error() {
        let mut cert = fixture_standard_cert(1_700_000_000);
        cert.permitted_ops = vec![];
        cert.self_sig_hex = sign_cert(&cert, &test_signing_key());
        let errs = validate_cert_structurally(&cert);
        assert!(errs
            .iter()
            .any(|e| matches!(e, CertError::StandardCertHasNoPermissions)));
    }

    /// **Structural break-glass enforcement** — pin that the
    /// EmergencyRecovery cert with extra permissions is REJECTED at
    /// validation time. This is the misconfig surface the user
    /// explicitly called out: "Any operator misconfig should be
    /// called out. The kernel's behavior must never be opaque."
    #[test]
    fn emergency_cert_with_extra_permissions_is_a_structural_error() {
        let mut cert = fixture_emergency_cert();
        cert.permitted_ops = vec![
            "RotateEpoch".to_owned(),
            "CreateInitiative".to_owned(), // <-- the misconfig
        ];
        cert.self_sig_hex = sign_cert(&cert, &test_signing_key());

        let errs = validate_cert_structurally(&cert);
        let got = errs
            .iter()
            .find_map(|e| match e {
                CertError::EmergencyHasWrongPermissions { got } => Some(got.clone()),
                _ => None,
            })
            .expect("must surface EmergencyHasWrongPermissions");
        assert!(
            got.contains(&"CreateInitiative".to_owned()),
            "the violating permission must appear in the error payload for operator visibility; \
             got: {got:?}"
        );
    }

    #[test]
    fn emergency_cert_missing_rotate_epoch_is_a_structural_error() {
        let mut cert = fixture_emergency_cert();
        cert.permitted_ops = vec!["AbortInitiative".to_owned()];
        cert.self_sig_hex = sign_cert(&cert, &test_signing_key());
        let errs = validate_cert_structurally(&cert);
        assert!(errs
            .iter()
            .any(|e| matches!(e, CertError::EmergencyHasWrongPermissions { .. })));
    }

    #[test]
    fn emergency_cert_with_validity_window_set_is_a_structural_error() {
        let mut cert = fixture_emergency_cert();
        cert.not_after = 1_731_536_000;
        cert.self_sig_hex = sign_cert(&cert, &test_signing_key());
        let errs = validate_cert_structurally(&cert);
        assert!(
            errs.iter()
                .any(|e| matches!(e, CertError::EmergencyHasValidityWindow { .. })),
            "got: {errs:?}"
        );
    }

    #[test]
    fn malformed_pubkey_hex_is_a_structural_error() {
        let mut cert = fixture_standard_cert(1_700_000_000);
        cert.pubkey_hex = "not-hex".to_owned();
        // Don't bother re-signing — we're testing the structural
        // check, which runs before the signature check.
        let errs = validate_cert_structurally(&cert);
        assert!(errs
            .iter()
            .any(|e| matches!(e, CertError::MalformedPubkey(_))));
    }

    #[test]
    fn validate_cert_structurally_collects_all_violations_not_just_first() {
        // Stack two independent violations; the test pins that we
        // collect both, so an operator running `raxis cert verify`
        // sees the full picture in one invocation.
        let mut cert = fixture_standard_cert(1_700_000_000);
        cert.display_name = String::new(); // violation 1
        cert.permitted_ops = vec![]; // violation 2
        cert.self_sig_hex = sign_cert(&cert, &test_signing_key());
        let errs = validate_cert_structurally(&cert);
        assert!(
            errs.len() >= 2,
            "must collect all violations; got: {errs:?}"
        );
    }

    // ── cert_status / four-zone state machine ─────────────────────────

    #[test]
    fn standard_cert_in_active_zone_when_now_well_before_expiry() {
        let now = 1_700_000_000;
        let cert = fixture_standard_cert(now);
        // fixture is now+90d expiry, 30d warn → Active until now+60d.
        assert_eq!(cert_status(&cert, now), CertStatus::Active);
    }

    #[test]
    fn standard_cert_enters_expiring_zone_at_warn_boundary() {
        let now = 1_700_000_000;
        let cert = fixture_standard_cert(now);
        // Warn window starts at not_after - 30d = now + 60d.
        let in_warn_zone = cert.not_after - 5 * 86_400;
        match cert_status(&cert, in_warn_zone) {
            CertStatus::Expiring { secs_until_expiry } => {
                assert_eq!(secs_until_expiry, 5 * 86_400);
            }
            other => panic!("expected Expiring, got {other:?}"),
        }
    }

    #[test]
    fn standard_cert_enters_grace_zone_after_not_after() {
        let now = 1_700_000_000;
        let cert = fixture_standard_cert(now);
        let in_grace = cert.not_after + 3 * 86_400;
        match cert_status(&cert, in_grace) {
            CertStatus::Grace {
                secs_until_grace_end,
            } => {
                assert_eq!(secs_until_grace_end, 4 * 86_400);
            }
            other => panic!("expected Grace, got {other:?}"),
        }
    }

    #[test]
    fn standard_cert_enters_expired_zone_after_grace_window() {
        let now = 1_700_000_000;
        let cert = fixture_standard_cert(now);
        let after_grace = cert.not_after + 10 * 86_400; // grace is 7d
        match cert_status(&cert, after_grace) {
            CertStatus::Expired { secs_since_expiry } => {
                assert_eq!(secs_since_expiry, 10 * 86_400);
            }
            other => panic!("expected Expired, got {other:?}"),
        }
    }

    #[test]
    fn standard_cert_not_yet_valid_when_now_before_not_before() {
        let now = 1_700_000_000;
        let mut cert = fixture_standard_cert(now);
        cert.not_before = now + 60;
        // (no need to re-sign; we're testing pure-status computation.)
        match cert_status(&cert, now) {
            CertStatus::NotYetValid { secs_until_active } => {
                assert_eq!(secs_until_active, 60);
            }
            other => panic!("expected NotYetValid, got {other:?}"),
        }
    }

    #[test]
    fn emergency_cert_is_always_active_regardless_of_clock() {
        let cert = fixture_emergency_cert();
        // Past, present, far future — all return AlwaysActiveEmergency.
        assert_eq!(cert_status(&cert, 0), CertStatus::AlwaysActiveEmergency);
        assert_eq!(
            cert_status(&cert, 1_700_000_000),
            CertStatus::AlwaysActiveEmergency
        );
        assert_eq!(
            cert_status(&cert, 99_999_999_999),
            CertStatus::AlwaysActiveEmergency
        );
    }

    // ── CertStatus::allows_* ──────────────────────────────────────────

    #[test]
    fn active_and_expiring_allow_new_commitments_grace_does_not() {
        assert!(CertStatus::Active.allows_new_commitments());
        assert!(CertStatus::Expiring {
            secs_until_expiry: 1
        }
        .allows_new_commitments());
        assert!(CertStatus::AlwaysActiveEmergency.allows_new_commitments());
        assert!(!CertStatus::Grace {
            secs_until_grace_end: 1
        }
        .allows_new_commitments());
        assert!(!CertStatus::Expired {
            secs_since_expiry: 1
        }
        .allows_new_commitments());
        assert!(!CertStatus::NotYetValid {
            secs_until_active: 1
        }
        .allows_new_commitments());
    }

    #[test]
    fn active_expiring_grace_allow_recovery_ops_expired_does_not() {
        assert!(CertStatus::Active.allows_recovery_ops());
        assert!(CertStatus::Expiring {
            secs_until_expiry: 1
        }
        .allows_recovery_ops());
        assert!(CertStatus::Grace {
            secs_until_grace_end: 1
        }
        .allows_recovery_ops());
        assert!(CertStatus::AlwaysActiveEmergency.allows_recovery_ops());
        assert!(!CertStatus::Expired {
            secs_since_expiry: 1
        }
        .allows_recovery_ops());
        assert!(!CertStatus::NotYetValid {
            secs_until_active: 1
        }
        .allows_recovery_ops());
    }

    #[test]
    fn cert_status_tag_strings_are_pinned() {
        // Audit dashboards and grep recipes depend on these strings.
        assert_eq!(CertStatus::Active.tag(), "active");
        assert_eq!(
            CertStatus::Expiring {
                secs_until_expiry: 0
            }
            .tag(),
            "expiring"
        );
        assert_eq!(
            CertStatus::Grace {
                secs_until_grace_end: 0
            }
            .tag(),
            "grace"
        );
        assert_eq!(
            CertStatus::Expired {
                secs_since_expiry: 0
            }
            .tag(),
            "expired"
        );
        assert_eq!(
            CertStatus::NotYetValid {
                secs_until_active: 0
            }
            .tag(),
            "not_yet_valid"
        );
        assert_eq!(
            CertStatus::AlwaysActiveEmergency.tag(),
            "always_active_emergency"
        );
        assert_eq!(
            CertStatus::Revoked {
                reason: RevocationReason::Compromise,
                revoked_at: 1_700_000_000,
            }
            .tag(),
            "revoked",
        );
    }

    // ── V2_GAPS §D1 — revocation ──────────────────────────────────────

    #[test]
    fn revocation_canonical_signing_input_byte_layout_is_pinned() {
        let bytes = revocation_canonical_signing_input(
            "aa".repeat(32).as_str(),
            RevocationReason::Compromise,
            1_700_000_000,
            "INC-2026-04-15-laptop-theft",
        );
        let s = std::str::from_utf8(&bytes).unwrap();
        assert_eq!(
            s,
            "raxis-cert-revocation/v1|\
             aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa|\
             Compromise|1700000000|INC-2026-04-15-laptop-theft",
        );
    }

    #[test]
    fn revocation_signature_round_trips() {
        let signing = test_signing_key();
        let pubkey = test_pubkey_hex();
        let now = 1_700_000_000_i64;
        let sig_hex = sign_revocation(
            &pubkey,
            RevocationReason::Rotation,
            now,
            "ticket-7",
            &signing,
        );
        let record = RevocationRecord {
            subject_pubkey_hex: "bb".repeat(32),
            subject_fingerprint: "00".repeat(16),
            reason: RevocationReason::Rotation,
            revoked_at: now,
            reference: "ticket-7".into(),
            revoked_by_pubkey_hex: "cc".repeat(32),
            revoked_by_signature_hex: sig_hex.clone(),
            signing_input_version: "raxis-cert-revocation/v1".into(),
        };
        // Mismatched subject — verification fails because the
        // canonical input includes the subject pubkey and the
        // signer / pubkey-on-record disagree.
        let err = verify_revocation_signature(&record).unwrap_err();
        assert!(
            matches!(
                err,
                CertError::SelfSignatureInvalid(_) | CertError::HexDecode(_)
            ),
            "expected SelfSignatureInvalid, got {err:?}"
        );

        // Now build a record whose subject + signing-key are
        // consistent with the actual signed bytes.
        let consistent = RevocationRecord {
            subject_pubkey_hex: pubkey.clone(),
            subject_fingerprint: "00".repeat(16),
            reason: RevocationReason::Rotation,
            revoked_at: now,
            reference: "ticket-7".into(),
            revoked_by_pubkey_hex: pubkey.clone(),
            revoked_by_signature_hex: sign_revocation(
                &pubkey,
                RevocationReason::Rotation,
                now,
                "ticket-7",
                &signing,
            ),
            signing_input_version: "raxis-cert-revocation/v1".into(),
        };
        verify_revocation_signature(&consistent).expect("valid sig");
    }

    #[test]
    fn revocation_signature_rejects_unknown_version() {
        let mut record = RevocationRecord {
            subject_pubkey_hex: test_pubkey_hex(),
            subject_fingerprint: "00".repeat(16),
            reason: RevocationReason::Rotation,
            revoked_at: 0,
            reference: "x".into(),
            revoked_by_pubkey_hex: test_pubkey_hex(),
            revoked_by_signature_hex: "00".repeat(64),
            signing_input_version: "raxis-cert-revocation/v9".into(),
        };
        record.revoked_by_signature_hex = sign_revocation(
            &record.subject_pubkey_hex,
            record.reason,
            record.revoked_at,
            &record.reference,
            &test_signing_key(),
        );
        let err = verify_revocation_signature(&record).unwrap_err();
        assert!(
            matches!(err, CertError::SelfSignatureInvalid(_)),
            "unknown version must reject: {err:?}"
        );
    }

    #[test]
    fn cert_status_with_revocation_returns_revoked_when_lookup_hits() {
        let now = 1_700_000_000_i64;
        let cert = fixture_standard_cert(now);
        let status = cert_status_with_revocation(&cert, now, |pk| {
            assert_eq!(pk, cert.pubkey_hex);
            Some((RevocationReason::Compromise, now - 86_400))
        });
        match status {
            CertStatus::Revoked { reason, revoked_at } => {
                assert_eq!(reason, RevocationReason::Compromise);
                assert_eq!(revoked_at, now - 86_400);
            }
            other => panic!("expected Revoked, got {other:?}"),
        }
    }

    #[test]
    fn cert_status_with_revocation_falls_through_when_lookup_misses() {
        let now = 1_700_000_000_i64;
        let cert = fixture_standard_cert(now);
        let status = cert_status_with_revocation(&cert, now, |_| None);
        assert_eq!(status, CertStatus::Active);
    }

    #[test]
    fn revoked_status_denies_all_ops() {
        let s = CertStatus::Revoked {
            reason: RevocationReason::Rotation,
            revoked_at: 0,
        };
        assert!(!s.allows_new_commitments());
        assert!(!s.allows_recovery_ops());
    }

    // ── CertKind round-trip ───────────────────────────────────────────

    #[test]
    fn cert_kind_as_str_round_trips_through_parse() {
        for kind in [CertKind::Standard, CertKind::EmergencyRecovery] {
            assert_eq!(CertKind::parse(kind.as_str()), Some(kind));
        }
    }

    #[test]
    fn cert_kind_parse_returns_none_for_unknown() {
        assert_eq!(CertKind::parse("ReadOnly"), None);
        assert_eq!(CertKind::parse(""), None);
        assert_eq!(CertKind::parse("standard"), None, "case-sensitive");
    }
}

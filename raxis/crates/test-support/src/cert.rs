// raxis-test-support::cert — fixture helpers for `OperatorCert`.
//
// Why this module exists: after the cert-mandatory work (dropping the
// legacy cert-less operator entry path), every test that constructs an
// `OperatorEntry` must also produce a valid cert. Hand-rolling them at
// every call site means
//
//   - duplicating the mint-then-self-sign incantation everywhere,
//   - the temptation to short-cut with `cert.self_sig_hex = "deadbeef"
//     .to_owned()` (which makes the test pass under the type system but
//     fails the bundle's `verify_cert_self_signature` invariant), and
//   - drift between test fixtures when defaults change (e.g. the
//     1-year validity window).
//
// One helper, one source of truth.
//
// ── Determinism ──────────────────────────────────────────────────────
//
// `ephemeral_signing_key(seed)` accepts a 32-byte seed and produces a
// reproducible Ed25519 keypair. Most fixtures pass `[42u8; 32]` (the
// same constant the crypto crate's own tests use) but cert-uniqueness
// fixtures pass `[7u8; 32]` etc. The seed maps 1:1 to the pubkey, so
// a test that needs two distinct operators just supplies two seeds.
//
// `ephemeral_cert(...)` returns a freshly-minted, fully self-signed
// `OperatorCert` whose `pubkey_hex` matches the supplied signing key
// and whose `self_sig_hex` was just signed by it. The cert is
// structurally valid (passes `validate_cert_structurally`) and (for
// `Standard` certs) is in the Active zone for `now_unix_secs`.
//
// ── Lifetime model ───────────────────────────────────────────────────
//
// The signing key is dropped at the end of the helper call. The
// returned `OperatorCert` carries only the public half (pubkey + self
// sig). If a test needs to mint multiple certs from the same key (e.g.
// to exercise the `cert install` rotation path), use
// `ephemeral_signing_key(seed)` directly to obtain a `SigningKey` you
// hold across two `ephemeral_cert_with_key(&key, ...)` calls.
//
// ── Misuse enforcement ───────────────────────────────────────────────
//
// `raxis-test-support` is dev-dep-only; the `workspace_guard` `#[test]`
// in `crates/test-support/src/workspace_guard.rs` walks every
// workspace member's `Cargo.toml` at `cargo test --workspace` time
// and fails if this crate appears outside `[dev-dependencies]`. The
// crate root also carries `#![cfg_attr(not(debug_assertions),
// deprecated)]` so a release build of any consumer that does manage
// to depend on this crate emits a deprecation warning at every use
// site.

use ed25519_dalek::SigningKey;
use raxis_crypto::cert::sign_cert;
use raxis_types::operator_cert::{CertKind, OperatorCert};

/// Build a deterministic Ed25519 signing key from a 32-byte seed.
///
/// The returned `SigningKey` is the Ed25519 private half. Keep it on
/// the stack and drop it as soon as you're done — `ed25519-dalek`
/// already zeroizes its private bytes on drop.
pub fn ephemeral_signing_key(seed: [u8; 32]) -> SigningKey {
    SigningKey::from_bytes(&seed)
}

/// Hex-encode the public half of `signing_key` in the form the rest of
/// the workspace expects (64 lowercase hex chars).
pub fn pubkey_hex(signing_key: &SigningKey) -> String {
    hex::encode(signing_key.verifying_key().to_bytes())
}

// ---------------------------------------------------------------------------
// CertOpts — knobs for non-default fixtures.
//
// Most tests want "a Standard cert that's Active right now"; the
// `ephemeral_cert(seed, now)` shortcut covers that. When a test needs
// to exercise expiry / grace / specific permitted_ops / a different
// display name, build a `CertOpts` and pass it to
// `ephemeral_cert_with_opts`.
// ---------------------------------------------------------------------------

/// Knobs for [`ephemeral_cert_with_opts`]. Sensible defaults match
/// the production cert defaults (kernel-store.md §2.5.7: 30d warn,
/// 7d grace, 1y validity).
#[derive(Debug, Clone)]
pub struct CertOpts {
    /// Cert kind. Defaults to `Standard`. If `EmergencyRecovery`,
    /// the validity window and permitted_ops are pinned to their
    /// structurally-valid sentinel values (`not_before = 0`,
    /// `not_after = 0`, `permitted_ops = ["RotateEpoch"]`) regardless
    /// of the other fields below.
    pub kind: CertKind,

    /// Human-readable label. Defaults to `"test-operator"`.
    pub display_name: String,

    /// Anchor for the `Standard` validity window (Unix seconds). The
    /// cert spans `[now - 1 day, now + 1 year]` so the cert is in the
    /// Active zone at `now`. Ignored for `EmergencyRecovery`.
    pub now_unix_secs: i64,

    /// Width of the warn-before-expiry window. Defaults to 30 days.
    pub warn_before_expiry_days: u32,

    /// Width of the grace window. Defaults to 7 days.
    pub grace_period_days: u32,

    /// Permitted ops. Defaults to a single `"CreateInitiative"` for
    /// `Standard`; ignored for `EmergencyRecovery` (always
    /// `["RotateEpoch"]`).
    pub permitted_ops: Vec<String>,

    /// Optional contact info. Defaults to `None`.
    pub contact_info: Option<String>,
}

impl Default for CertOpts {
    fn default() -> Self {
        Self {
            kind:                    CertKind::Standard,
            display_name:            "test-operator".to_owned(),
            now_unix_secs:           1_700_000_000,
            warn_before_expiry_days: 30,
            grace_period_days:       7,
            permitted_ops:           vec!["CreateInitiative".to_owned()],
            contact_info:            None,
        }
    }
}

// ---------------------------------------------------------------------------
// ephemeral_cert / ephemeral_cert_with_opts
// ---------------------------------------------------------------------------

/// Mint a fresh Standard cert valid at `now_unix_secs` from a
/// deterministic-from-`seed` signing key.
///
/// Use this for the 90% case: "give me an operator entry whose cert
/// is structurally valid and in the Active zone at this moment in
/// test time". For non-default knobs (different kind / permitted_ops /
/// expiry positions), use [`ephemeral_cert_with_opts`].
pub fn ephemeral_cert(seed: [u8; 32], now_unix_secs: i64) -> OperatorCert {
    let key = ephemeral_signing_key(seed);
    ephemeral_cert_with_key(
        &key,
        CertOpts {
            now_unix_secs,
            ..CertOpts::default()
        },
    )
}

/// Mint a cert with the supplied options from a deterministic signing
/// key derived from `seed`.
pub fn ephemeral_cert_with_opts(seed: [u8; 32], opts: CertOpts) -> OperatorCert {
    let key = ephemeral_signing_key(seed);
    ephemeral_cert_with_key(&key, opts)
}

/// Mint a cert from an externally-held `SigningKey`. Used by tests
/// that need to mint two distinct certs from the same key (cert
/// rotation flows).
///
/// The returned cert satisfies:
///
///   - `cert.pubkey_hex == hex(signing_key.verifying_key())`
///   - `verify_cert_self_signature(&cert).is_ok()`
///   - `validate_cert_structurally(&cert).is_empty()` (at the
///     supplied `now_unix_secs`, for `Standard` certs)
pub fn ephemeral_cert_with_key(signing_key: &SigningKey, opts: CertOpts) -> OperatorCert {
    let pubkey = pubkey_hex(signing_key);
    let mut cert = match opts.kind {
        CertKind::Standard => OperatorCert {
            kind:                    CertKind::Standard,
            display_name:            opts.display_name,
            pubkey_hex:              pubkey,
            // Active zone: span [now - 1d, now + 365d], placing `now`
            // well before the warn window.
            not_before:              opts.now_unix_secs - 86_400,
            not_after:               opts.now_unix_secs + 365 * 86_400,
            warn_before_expiry_days: opts.warn_before_expiry_days,
            grace_period_days:       opts.grace_period_days,
            permitted_ops:           opts.permitted_ops,
            contact_info:            opts.contact_info,
            self_sig_hex:            String::new(),
        },
        CertKind::EmergencyRecovery => OperatorCert {
            kind:                    CertKind::EmergencyRecovery,
            display_name:            opts.display_name,
            pubkey_hex:              pubkey,
            // Structurally pinned for emergency certs (see
            // `validate_cert_structurally`).
            not_before:              0,
            not_after:               0,
            warn_before_expiry_days: 0,
            grace_period_days:       0,
            permitted_ops:           vec!["RotateEpoch".to_owned()],
            contact_info:            opts.contact_info,
            self_sig_hex:            String::new(),
        },
    };
    cert.self_sig_hex = sign_cert(&cert, signing_key);
    cert
}

// ---------------------------------------------------------------------------
// stub_cert_for_pubkey — non-validating cert for `for_tests_with_operators`
// fixtures that don't exercise cert validation.
// ---------------------------------------------------------------------------

/// Build a syntactically-shaped but **NOT-self-verifying** `OperatorCert`
/// pinned to the supplied `pubkey_hex`. For use ONLY in test fixtures
/// that go through `PolicyBundle::for_tests_with_operators` (which
/// skips cert validation) and need an `OperatorEntry` to exist for
/// reasons orthogonal to cert correctness — e.g. the notification-
/// routing tests in `kernel/src/notifications/`, which only care that
/// the bundle's `operators` list is non-empty.
///
/// **DO NOT use this for tests that go through `PolicyBundle::validate`
/// or `validate_operator_certs` — they will reject the placeholder
/// signature.** Use `ephemeral_cert` / `ephemeral_cert_with_key` for
/// those.
///
/// The signature placeholder is 128 zero hex chars, which structurally
/// validates (right length and shape) but cannot be a valid Ed25519
/// signature for any non-trivial message — exactly the right thing
/// to surface "this got into a real validation path by mistake".
pub fn stub_cert_for_pubkey(pubkey_hex: impl Into<String>) -> OperatorCert {
    OperatorCert {
        kind:                    CertKind::Standard,
        display_name:            "test-stub-operator".to_owned(),
        pubkey_hex:              pubkey_hex.into(),
        not_before:              0,
        not_after:               i64::MAX,
        warn_before_expiry_days: 0,
        grace_period_days:       0,
        permitted_ops:           vec!["CreateInitiative".to_owned()],
        contact_info:            None,
        // 128 hex zeros: structurally length-valid Ed25519 signature
        // shape, but cannot verify against any real message — surfaces
        // "stub leaked into a real validation path" loudly.
        self_sig_hex:            "0".repeat(128),
    }
}

// ---------------------------------------------------------------------------
// Smoke tests — keep these helpers structurally honest.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use raxis_crypto::cert::{
        cert_status, validate_cert_structurally, verify_cert_self_signature, CertStatus,
    };

    #[test]
    fn ephemeral_cert_is_structurally_valid_and_self_verifies() {
        let now = 1_700_000_000;
        let cert = ephemeral_cert([42u8; 32], now);

        assert!(
            validate_cert_structurally(&cert).is_empty(),
            "default ephemeral cert must be structurally valid"
        );
        verify_cert_self_signature(&cert)
            .expect("default ephemeral cert must self-verify");
    }

    #[test]
    fn ephemeral_cert_is_in_active_zone_at_now() {
        let now = 1_700_000_000;
        let cert = ephemeral_cert([42u8; 32], now);
        assert_eq!(cert_status(&cert, now), CertStatus::Active);
    }

    #[test]
    fn ephemeral_emergency_cert_is_always_active_and_self_verifies() {
        let cert = ephemeral_cert_with_opts(
            [7u8; 32],
            CertOpts {
                kind: CertKind::EmergencyRecovery,
                display_name: "break-glass".to_owned(),
                ..CertOpts::default()
            },
        );

        assert_eq!(cert.kind, CertKind::EmergencyRecovery);
        assert!(validate_cert_structurally(&cert).is_empty());
        verify_cert_self_signature(&cert).expect("emergency cert must self-verify");
        assert_eq!(cert_status(&cert, 0), CertStatus::AlwaysActiveEmergency);
        assert_eq!(cert_status(&cert, 99_999_999_999), CertStatus::AlwaysActiveEmergency);
    }

    #[test]
    fn distinct_seeds_produce_distinct_pubkeys() {
        // Sanity check on the determinism + uniqueness contract: two
        // different seeds MUST produce two different certs (otherwise
        // the "two operators" fixture is a lie).
        let a = ephemeral_cert([1u8; 32], 1_700_000_000);
        let b = ephemeral_cert([2u8; 32], 1_700_000_000);
        assert_ne!(a.pubkey_hex, b.pubkey_hex);
        assert_ne!(a.self_sig_hex, b.self_sig_hex);
    }

    #[test]
    fn same_seed_produces_same_pubkey_across_calls() {
        // Determinism: same seed + same opts = byte-identical cert.
        // Required for golden-file tests that pin cert artefacts.
        let a = ephemeral_cert([42u8; 32], 1_700_000_000);
        let b = ephemeral_cert([42u8; 32], 1_700_000_000);
        assert_eq!(a, b);
    }

    #[test]
    fn ephemeral_cert_with_key_lets_two_certs_share_a_pubkey() {
        // The cert-rotation use-case: same key, two certs (e.g. an
        // expiring one and its replacement). Both must self-verify.
        let key = ephemeral_signing_key([99u8; 32]);
        let cert1 = ephemeral_cert_with_key(&key, CertOpts::default());
        let cert2 = ephemeral_cert_with_key(
            &key,
            CertOpts {
                display_name: "rotated".to_owned(),
                ..CertOpts::default()
            },
        );

        assert_eq!(cert1.pubkey_hex, cert2.pubkey_hex,
            "same key MUST produce certs with the same pubkey_hex");
        assert_ne!(cert1.self_sig_hex, cert2.self_sig_hex,
            "different metadata MUST produce different signatures");
        verify_cert_self_signature(&cert1).expect("cert1 must self-verify");
        verify_cert_self_signature(&cert2).expect("cert2 must self-verify");
    }

    #[test]
    fn ephemeral_cert_with_opts_honours_permitted_ops_for_standard() {
        let cert = ephemeral_cert_with_opts(
            [42u8; 32],
            CertOpts {
                permitted_ops: vec![
                    "CreateInitiative".to_owned(),
                    "ApprovePlan".to_owned(),
                    "RevokeSession".to_owned(),
                ],
                ..CertOpts::default()
            },
        );
        // Stored unsorted in the cert (canonicalisation only happens
        // inside the signing-input construction).
        assert!(cert.permitted_ops.contains(&"CreateInitiative".to_owned()));
        assert!(cert.permitted_ops.contains(&"ApprovePlan".to_owned()));
        assert!(cert.permitted_ops.contains(&"RevokeSession".to_owned()));
        verify_cert_self_signature(&cert).expect("multi-op cert must still self-verify");
    }

    #[test]
    fn stub_cert_for_pubkey_does_not_self_verify() {
        // Sanity check on the "this is a placeholder" contract: the
        // stub MUST fail self-sig verification so any test that
        // accidentally routes it through the real validator notices.
        let key = ephemeral_signing_key([1u8; 32]);
        let stub = stub_cert_for_pubkey(pubkey_hex(&key));
        assert!(verify_cert_self_signature(&stub).is_err(),
            "stub_cert_for_pubkey must NOT self-verify (it's a placeholder, not a real cert)");
    }

    #[test]
    fn ephemeral_emergency_cert_ignores_caller_supplied_permitted_ops() {
        // An EmergencyRecovery cert that the caller tries to widen
        // gets pinned back to ["RotateEpoch"]. This protects tests
        // that copy `CertOpts::default()` then flip `kind` from
        // accidentally minting an invalid emergency cert.
        let cert = ephemeral_cert_with_opts(
            [7u8; 32],
            CertOpts {
                kind: CertKind::EmergencyRecovery,
                permitted_ops: vec!["CreateInitiative".to_owned()],
                ..CertOpts::default()
            },
        );
        assert_eq!(cert.permitted_ops, vec!["RotateEpoch".to_owned()]);
        assert_eq!(cert.not_before, 0);
        assert_eq!(cert.not_after, 0);
        assert!(validate_cert_structurally(&cert).is_empty(),
            "the helper must structurally validate even when the caller's opts disagree");
    }
}

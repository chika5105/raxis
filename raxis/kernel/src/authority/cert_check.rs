// raxis-kernel::authority::cert_check — Operator-cert runtime gate.
//
// Normative reference (forthcoming): kernel-core.md §`authority/cert_check.rs`
// (added in step 12 of the operator-cert feature; this module is the
// implementation that the spec section will document).
//
// What this module does
// ─────────────────────
// Sits in the operator IPC dispatcher between the per-op `is_permitted`
// gate and the actual handler dispatch. For every authenticated
// operator request:
//
//   1. Resolve the operator's cert (if any) from the active
//      `PolicyBundle`.
//      - No cert ⇒ legacy path; pass-through with no audit emit (the
//        legacy detection event was already emitted at policy load).
//      - Cert present ⇒ fall through to step 2.
//
//   2. Compute the four-zone status from `raxis_crypto::cert::cert_status`.
//
//   3. Apply the per-zone enforcement contract:
//
//        ┌──────────────────────────┬───────────┬────────────────────────────┐
//        │ Zone                     │ Allowed?  │ Audit emit                 │
//        ├──────────────────────────┼───────────┼────────────────────────────┤
//        │ Active                   │ yes       │ none                       │
//        │ Expiring                 │ yes       │ OperatorCertExpiringSoon   │
//        │                          │           │ (deduped per (fp, epoch))  │
//        │ Grace                    │ yes       │ OperatorCertInGracePeriod  │
//        │                          │           │ (deduped per (fp, epoch))  │
//        │ Expired                  │ NO        │ OperatorCertExpiredOpDenied│
//        │                          │           │ (per-op, NOT deduped)      │
//        │ NotYetValid              │ NO        │ OperatorCertExpiredOpDenied│
//        │                          │           │ (per-op, NOT deduped;      │
//        │                          │           │  reuses the same audit kind │
//        │                          │           │  with `expired_at` set to  │
//        │                          │           │  the cert's not_before)    │
//        │ AlwaysActiveEmergency    │ yes       │ EmergencyOperatorUsed      │
//        │                          │           │ (per-op, NOT deduped)      │
//        └──────────────────────────┴───────────┴────────────────────────────┘
//
// **Dedupe rationale.** A chatty operator could flood the audit chain
// with hundreds of `OperatorCertExpiringSoon` records in one minute if
// every op emitted one. The contract is "the operator MUST see the
// warning once per epoch; subsequent ops in the same epoch are silent
// in the audit chain". Dedupe key is `(pubkey_fingerprint, epoch_id)`
// because an epoch advance is the natural reset point for "I have
// already warned this operator about expiry".
//
// **No-dedupe rationale for `Expired` / `NotYetValid` / `Emergency`.**
// These are kernel security signals — every denied op is a forensic
// breadcrumb for an auditor reconstructing why an operator was
// suddenly powerless, and every emergency-cert use is a break-glass
// event that MUST appear in the chain regardless of how many other
// emergency calls happened in the same epoch.

use std::collections::HashSet;
use std::sync::Mutex;

use raxis_audit_tools::{AuditEventKind, AuditSink};
use raxis_crypto::cert::{cert_status, CertStatus};
use raxis_policy::PolicyBundle;
use raxis_types::operator_cert::{CertKind, OperatorCert};

// ---------------------------------------------------------------------------
// CertGuard — allow / deny outcome of one cert-check call.
// ---------------------------------------------------------------------------

/// Outcome of `enforce_cert_status`. The dispatcher pattern-matches on
/// this to either continue with handler dispatch (`Allow`) or short-
/// circuit with a `FAIL_CERT_*` operator response (`Deny`).
///
/// Carries the structured deny reason so the dispatcher can render a
/// stable wire string AND the operator's CLI can pattern-match on it
/// (e.g. `error: kernel responded with error: FAIL_CERT_EXPIRED — \
/// cert for op-fp expired 14 days ago, rotate via `raxis policy sign`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CertGuard {
    /// Pass-through. The cert is either Active, Expiring, Grace,
    /// AlwaysActiveEmergency, OR the operator is on the legacy
    /// (cert-less) flow. The dispatcher proceeds with the handler.
    Allow,

    /// Reject. The dispatcher MUST short-circuit with a wire error
    /// matching `wire_code` and `wire_detail`.
    Deny {
        /// Stable error code for the operator response — one of:
        ///   `FAIL_CERT_EXPIRED`, `FAIL_CERT_NOT_YET_VALID`.
        wire_code:    &'static str,
        /// Human-readable detail; safe to surface to the CLI directly.
        wire_detail:  String,
    },
}

// ---------------------------------------------------------------------------
// CertEnforcer — owns the dedupe set + drives per-request enforcement.
// ---------------------------------------------------------------------------

/// In-process state for cert enforcement. Held in `HandlerContext`
/// (one per kernel process) so the dedupe set survives across operator
/// connections.
///
/// **Thread safety.** The dedupe set is wrapped in a `Mutex`; every
/// `enforce` call takes the lock briefly (one HashSet insert + lookup)
/// and releases it before calling the audit sink. The audit sink is
/// invoked OUTSIDE the lock so a slow JSONL write cannot stall
/// concurrent operator dispatchers.
#[derive(Debug)]
pub struct CertEnforcer {
    /// Set of `(pubkey_fingerprint, epoch_id)` pairs we have already
    /// emitted an `OperatorCertExpiringSoon` OR `OperatorCertInGracePeriod`
    /// audit for. Cleared on epoch advance is NOT necessary because
    /// the epoch_id changes — old entries become unreachable.
    warned: Mutex<HashSet<(String, u64)>>,
}

impl Default for CertEnforcer {
    fn default() -> Self { Self::new() }
}

impl CertEnforcer {
    pub fn new() -> Self {
        Self { warned: Mutex::new(HashSet::new()) }
    }

    /// Drive the cert check for one operator IPC request.
    ///
    /// Returns `CertGuard::Allow` when the dispatcher should proceed,
    /// `CertGuard::Deny` when the dispatcher MUST short-circuit with
    /// a wire error.
    ///
    /// Audit emission is best-effort — any sink error is logged via
    /// `eprintln!` and DROPPED. Per kernel-store.md §2.5.2 the audit
    /// chain is the durable record but not the source of truth for
    /// kernel control flow; failing the dispatch on a sink hiccup
    /// would let a transient disk-full error lock operators out of
    /// their own kernel.
    pub fn enforce(
        &self,
        operator_fingerprint: &str,
        op_name:              &str,
        bundle:               &PolicyBundle,
        audit:                &dyn AuditSink,
        now_unix_secs:        i64,
    ) -> CertGuard {
        let epoch_id = bundle.epoch();
        let entry = match bundle.operator_entry(operator_fingerprint) {
            Some(e) => e,
            // Operator not in policy. The dispatcher's earlier
            // `verify_response` step already rejects unknown
            // fingerprints; reaching this point with `None` would
            // be a kernel invariant violation. Return Allow (fail-
            // open) and let the downstream handler's own auth
            // check surface the missing-operator error — that's
            // the consistent failure mode for "invariant violation
            // in cert_check" (which we'd rather not turn into
            // FAIL_CERT_*).
            None => return CertGuard::Allow,
        };

        // Cert is mandatory (INV-CERT-01 / INV-CERT-02): every
        // operator entry in the bundle carries a self-signed cert.
        // There is no permissive default — empty `operator_certificates`
        // means the boot ceremony was incomplete and the kernel
        // should not have started in the first place.
        let cert = &entry.cert;

        match cert_status(cert, now_unix_secs) {
            CertStatus::Active => CertGuard::Allow,

            CertStatus::Expiring { secs_until_expiry } => {
                self.maybe_emit_warn(
                    audit, operator_fingerprint, epoch_id,
                    AuditEventKind::OperatorCertExpiringSoon {
                        pubkey_fingerprint: operator_fingerprint.to_owned(),
                        epoch_id,
                        op:                 op_name.to_owned(),
                        not_after:          cert.not_after,
                        days_remaining:     secs_until_expiry / 86_400,
                    },
                    "OperatorCertExpiringSoon",
                );
                CertGuard::Allow
            }

            CertStatus::Grace { secs_until_grace_end } => {
                self.maybe_emit_warn(
                    audit, operator_fingerprint, epoch_id,
                    AuditEventKind::OperatorCertInGracePeriod {
                        pubkey_fingerprint: operator_fingerprint.to_owned(),
                        epoch_id,
                        op:                 op_name.to_owned(),
                        not_after:          cert.not_after,
                        grace_ends_at:      now_unix_secs + secs_until_grace_end,
                    },
                    "OperatorCertInGracePeriod",
                );
                CertGuard::Allow
            }

            CertStatus::Expired { secs_since_expiry } => {
                emit_or_log(audit, AuditEventKind::OperatorCertExpiredOpDenied {
                    pubkey_fingerprint: operator_fingerprint.to_owned(),
                    epoch_id,
                    op:                 op_name.to_owned(),
                    not_after:          cert.not_after,
                    expired_at:         cert.not_after + (secs_since_expiry / 86_400) * 86_400,
                }, "OperatorCertExpiredOpDenied");
                CertGuard::Deny {
                    wire_code:   "FAIL_CERT_EXPIRED",
                    wire_detail: format!(
                        "operator cert for {operator_fingerprint} expired {} day(s) ago; \
                         rotate via the cert-mint flow",
                        secs_since_expiry / 86_400,
                    ),
                }
            }

            CertStatus::NotYetValid { secs_until_active } => {
                // Reuse `OperatorCertExpiredOpDenied` for the
                // not-yet-valid wire shape: an auditor scanning the
                // chain just needs "this op was denied because the
                // cert window did not include `now`". `expired_at`
                // is set to `not_before` so the record names the
                // boundary the cert was outside of.
                emit_or_log(audit, AuditEventKind::OperatorCertExpiredOpDenied {
                    pubkey_fingerprint: operator_fingerprint.to_owned(),
                    epoch_id,
                    op:                 op_name.to_owned(),
                    not_after:          cert.not_after,
                    expired_at:         cert.not_before,
                }, "OperatorCertExpiredOpDenied");
                CertGuard::Deny {
                    wire_code:   "FAIL_CERT_NOT_YET_VALID",
                    wire_detail: format!(
                        "operator cert for {operator_fingerprint} not yet valid \
                         (active in {secs_until_active}s)",
                    ),
                }
            }

            CertStatus::AlwaysActiveEmergency => {
                // Break-glass cert use is ALWAYS audited per op so an
                // attacker who steals the emergency key cannot use it
                // silently. No dedupe.
                debug_assert!(matches!(cert.kind, CertKind::EmergencyRecovery));
                emit_or_log(audit, AuditEventKind::EmergencyOperatorUsed {
                    pubkey_fingerprint: operator_fingerprint.to_owned(),
                    epoch_id,
                    op:                 op_name.to_owned(),
                }, "EmergencyOperatorUsed");
                let _ = cert;  // suppress unused-binding when debug_asserts off
                CertGuard::Allow
            }
        }
    }

    /// Helper: emit the per-epoch dedupe-gated warning (Expiring or
    /// Grace). Locks the warned-set briefly to test+insert, releases
    /// the lock, then emits to the sink (which may block on disk).
    fn maybe_emit_warn(
        &self,
        audit:                &dyn AuditSink,
        operator_fingerprint: &str,
        epoch_id:             u64,
        ev:                   AuditEventKind,
        label:                &'static str,
    ) {
        let key = (operator_fingerprint.to_owned(), epoch_id);
        let already = {
            let mut set = self.warned.lock().expect("warned-set mutex poisoned");
            !set.insert(key)
        };
        if already { return; }
        emit_or_log(audit, ev, label);
    }

    /// Test helper: assert the dedupe set contains an exact key.
    /// Behind `#[cfg(test)]` so production code can't depend on it.
    #[cfg(test)]
    fn was_warned(&self, fp: &str, epoch_id: u64) -> bool {
        let set = self.warned.lock().unwrap();
        set.contains(&(fp.to_owned(), epoch_id))
    }
}

/// Drop the audit emit failure into stderr and continue. Mirrors the
/// per-handler `eprintln!` posture used elsewhere in `policy_manager`.
fn emit_or_log(audit: &dyn AuditSink, ev: AuditEventKind, label: &'static str) {
    if let Err(e) = audit.emit(ev, None, None, None) {
        eprintln!(
            "{{\"level\":\"error\",\"event\":\"{label}\",\
             \"audit_emit_failed\":\"{e}\"}}",
        );
    }
}

// `OperatorCert` is referenced in doc comments; suppress the
// unused-import lint for the `OperatorCert` import without breaking
// rustdoc cross-references.
#[allow(dead_code)]
fn _doc_anchor(_: &OperatorCert) {}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use raxis_audit_tools::FakeAuditSink;
    use raxis_crypto::cert::sign_cert;
    use raxis_policy::{OperatorEntry, PolicyBundle};
    use sha2::{Digest, Sha256};

    const TEST_SEED: [u8; 32] = [0x11u8; 32];
    const NOT_BEFORE: i64 = 1_700_000_000;
    const NOT_AFTER:  i64 = 1_731_536_000; // ~365 days later
    const WARN_DAYS:  u32 = 30;
    const GRACE_DAYS: u32 = 7;

    fn signing_key() -> SigningKey { SigningKey::from_bytes(&TEST_SEED) }
    fn pk_hex() -> String { hex::encode(signing_key().verifying_key().to_bytes()) }
    fn fp() -> String {
        let mut h = Sha256::new();
        h.update(hex::decode(pk_hex()).unwrap());
        hex::encode(&h.finalize()[..16])
    }

    fn signed_standard() -> OperatorCert {
        let mut c = OperatorCert {
            kind:                    CertKind::Standard,
            display_name:            "chika".to_owned(),
            pubkey_hex:              pk_hex(),
            not_before:              NOT_BEFORE,
            not_after:               NOT_AFTER,
            warn_before_expiry_days: WARN_DAYS,
            grace_period_days:       GRACE_DAYS,
            permitted_ops:           vec!["AbortTask".to_owned()],
            contact_info:            None,
            self_sig_hex:            String::new(),
        };
        c.self_sig_hex = sign_cert(&c, &signing_key());
        c
    }

    fn signed_emergency() -> OperatorCert {
        let mut c = OperatorCert {
            kind:                    CertKind::EmergencyRecovery,
            display_name:            "break-glass".to_owned(),
            pubkey_hex:              pk_hex(),
            not_before:              0,
            not_after:               0,
            warn_before_expiry_days: 0,
            grace_period_days:       0,
            permitted_ops:           vec!["RotateEpoch".to_owned()],
            contact_info:            None,
            self_sig_hex:            String::new(),
        };
        c.self_sig_hex = sign_cert(&c, &signing_key());
        c
    }

    fn entry(cert: OperatorCert) -> OperatorEntry {
        OperatorEntry {
            pubkey_fingerprint:     fp(),
            display_name:           "chika".to_owned(),
            pubkey_hex:             pk_hex(),
            permitted_ops:          vec!["AbortTask".to_owned()],
            cert,
            force_misconfig_bypass: false,
        }
    }

    fn bundle(cert: OperatorCert) -> PolicyBundle {
        PolicyBundle::for_tests_with_operators(vec![entry(cert)])
    }

    fn enforcer_with_sink() -> (CertEnforcer, std::sync::Arc<FakeAuditSink>) {
        let sink = std::sync::Arc::new(FakeAuditSink::new());
        (CertEnforcer::new(), sink)
    }

    // ── Active zone ───────────────────────────────────────────────

    #[test]
    fn active_zone_allows_silently() {
        let (enf, sink) = enforcer_with_sink();
        let b = bundle(signed_standard());
        let now = NOT_AFTER - 60 * 86_400; // 60 days before expiry; outside warn window
        let g = enf.enforce(&fp(), "AbortTask", &b, sink.as_ref(), now);
        assert_eq!(g, CertGuard::Allow);
        assert!(sink.event_kinds().is_empty(),
            "Active zone must not emit any audit; got {:?}", sink.event_kinds());
    }

    // ── Expiring zone (deduped) ───────────────────────────────────

    #[test]
    fn expiring_zone_emits_once_then_dedupes_within_epoch() {
        let (enf, sink) = enforcer_with_sink();
        let b = bundle(signed_standard());
        // 14 days before expiry → inside the 30-day warn window.
        let now = NOT_AFTER - 14 * 86_400;

        // First call: emits.
        assert_eq!(enf.enforce(&fp(), "AbortTask", &b, sink.as_ref(), now), CertGuard::Allow);
        // Second call (same epoch + same operator): dedupes.
        assert_eq!(enf.enforce(&fp(), "AbortTask", &b, sink.as_ref(), now), CertGuard::Allow);
        // Third call (different op, same epoch + operator): still dedupes.
        assert_eq!(enf.enforce(&fp(), "ApprovePlan", &b, sink.as_ref(), now), CertGuard::Allow);

        let n_warn = sink.event_kinds().iter()
            .filter(|k| **k == "OperatorCertExpiringSoon")
            .count();
        assert_eq!(n_warn, 1,
            "expected exactly one OperatorCertExpiringSoon for repeated ops in same epoch; got {:?}",
            sink.event_kinds());
        assert!(enf.was_warned(&fp(), b.epoch()));
    }

    // ── Grace zone (deduped, allowed) ─────────────────────────────

    #[test]
    fn grace_zone_allows_and_emits_once_per_epoch() {
        let (enf, sink) = enforcer_with_sink();
        let b = bundle(signed_standard());
        // 1 day past expiry → inside 7-day grace window.
        let now = NOT_AFTER + 86_400;
        assert_eq!(enf.enforce(&fp(), "AbortTask", &b, sink.as_ref(), now), CertGuard::Allow);
        assert_eq!(enf.enforce(&fp(), "AbortTask", &b, sink.as_ref(), now), CertGuard::Allow);
        let n = sink.event_kinds().iter()
            .filter(|k| **k == "OperatorCertInGracePeriod")
            .count();
        assert_eq!(n, 1, "Grace zone must emit exactly once per (fp, epoch)");
    }

    // ── Expired zone (denies, NOT deduped) ────────────────────────

    #[test]
    fn expired_zone_denies_with_wire_code_and_emits_per_op() {
        let (enf, sink) = enforcer_with_sink();
        let b = bundle(signed_standard());
        // 14 days past expiry → past 7-day grace window.
        let now = NOT_AFTER + 14 * 86_400;
        match enf.enforce(&fp(), "AbortTask", &b, sink.as_ref(), now) {
            CertGuard::Deny { wire_code, wire_detail } => {
                assert_eq!(wire_code, "FAIL_CERT_EXPIRED");
                assert!(wire_detail.contains("expired"),
                    "deny detail should mention expiry; got {wire_detail:?}");
            }
            other => panic!("expected Deny; got {other:?}"),
        }
        // Second call: still denies AND emits a second audit (no dedupe).
        let _ = enf.enforce(&fp(), "AbortTask", &b, sink.as_ref(), now);
        let n = sink.event_kinds().iter()
            .filter(|k| **k == "OperatorCertExpiredOpDenied")
            .count();
        assert_eq!(n, 2,
            "Expired zone MUST emit one audit per op (no dedupe); got {n} for {:?}",
            sink.event_kinds());
    }

    // ── NotYetValid zone (denies; reuses expired audit kind) ──────

    #[test]
    fn not_yet_valid_zone_denies_with_wire_code() {
        let (enf, sink) = enforcer_with_sink();
        let b = bundle(signed_standard());
        // 1 day before not_before → cert isn't valid yet.
        let now = NOT_BEFORE - 86_400;
        match enf.enforce(&fp(), "AbortTask", &b, sink.as_ref(), now) {
            CertGuard::Deny { wire_code, .. } => {
                assert_eq!(wire_code, "FAIL_CERT_NOT_YET_VALID");
            }
            other => panic!("expected Deny; got {other:?}"),
        }
        // Audit emit: kind is OperatorCertExpiredOpDenied (the catch-
        // all "cert window did not include now" event), with
        // expired_at = cert.not_before so an auditor can see the
        // boundary the request was on the wrong side of.
        let kinds = sink.event_kinds();
        assert!(kinds.iter().any(|k| *k == "OperatorCertExpiredOpDenied"),
            "expected OperatorCertExpiredOpDenied in {kinds:?}");
    }

    // ── EmergencyRecovery cert ────────────────────────────────────

    #[test]
    fn emergency_cert_allows_and_emits_per_op_no_dedupe() {
        let (enf, sink) = enforcer_with_sink();
        let b = bundle(signed_emergency());
        // Time of day doesn't matter for emergency certs; pick anything.
        let now = NOT_AFTER + 365 * 86_400;
        for _ in 0..3 {
            assert_eq!(enf.enforce(&fp(), "RotateEpoch", &b, sink.as_ref(), now),
                CertGuard::Allow);
        }
        let n = sink.event_kinds().iter()
            .filter(|k| **k == "EmergencyOperatorUsed")
            .count();
        assert_eq!(n, 3,
            "EmergencyOperatorUsed MUST emit once per op (no dedupe); got {n} for {:?}",
            sink.event_kinds());
    }

    // ── Unknown fingerprint (kernel invariant — fail-open) ─────────

    #[test]
    fn unknown_fingerprint_returns_allow_so_handler_can_surface_real_error() {
        let (enf, sink) = enforcer_with_sink();
        let b = PolicyBundle::for_tests_with_operators(vec![]);
        assert_eq!(enf.enforce("no-such-fp", "AbortTask", &b, sink.as_ref(), 0),
            CertGuard::Allow);
        assert!(sink.event_kinds().is_empty());
    }
}

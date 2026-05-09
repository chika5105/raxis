// raxis-kernel::notifications::sink — `NotifyingAuditSink` decorator.
//
// Normative reference: cli-readonly.md §5.6 "Operator notifications".
//
// What this is
// ────────────
// A thin `AuditSink` decorator that, after every successful inner
// emission, fans the freshly-materialised `AuditEvent` out to the
// notification dispatcher. Wrapping happens once at kernel boot
// (`kernel/src/main.rs`), so every kernel handler that calls
// `ctx.audit.emit(...)` automatically participates in the notification
// pipeline — handlers do NOT need to remember to call
// `notifications::dispatch` themselves.
//
// Recursion safety
// ────────────────
// `notifications::dispatch_one` writes
// `AuditEventKind::NotificationDeliveryFailed` audit events when a
// per-channel handler errors out. To avoid an infinite loop where every
// failed delivery triggers another failed delivery, the dispatcher is
// handed the **inner** sink (not `self`). Failure events therefore
// land in the audit chain but are NOT re-fanned.
//
// Performance
// ───────────
// Per emit:
//   - one `Arc::clone` of the inner sink and policy bundle reference,
//   - one `PathBuf::clone` of the data dir,
//   - one `AuditEvent::clone` (already-allocated record, ~hundreds of bytes).
//
// The fan-out itself runs on a `tokio::spawn` per channel (see
// `notifications::dispatch`), so the calling thread returns
// immediately after the inner emit completes.

use std::path::PathBuf;
use std::sync::Arc;

use arc_swap::ArcSwap;
use raxis_audit_tools::{AuditEvent, AuditEventKind, AuditSink, AuditWriterError};
use raxis_policy::PolicyBundle;

use super::SidecarRegistry;

/// Wraps any `AuditSink` (typically `FileAuditSink` in production,
/// `FakeAuditSink` in integration tests) and routes every emitted
/// event through `notifications::dispatch`.
pub struct NotifyingAuditSink {
    inner:            Arc<dyn AuditSink>,
    policy:           Arc<ArcSwap<PolicyBundle>>,
    data_dir:         PathBuf,
    sidecar_registry: Option<Arc<SidecarRegistry>>,
}

impl NotifyingAuditSink {
    /// Wrap `inner` so every successful emit is fanned out to the
    /// channels declared in the active policy bundle's `[notifications]`
    /// section. The wrapped sink is itself an `AuditSink` so it slots
    /// into `HandlerContext.audit` without any other call-site change.
    pub fn new(
        inner:    Arc<dyn AuditSink>,
        policy:   Arc<ArcSwap<PolicyBundle>>,
        data_dir: PathBuf,
    ) -> Self {
        Self { inner, policy, data_dir, sidecar_registry: None }
    }

    /// Builder-style: attach the per-kernel `SidecarRegistry` so
    /// Sidecar-kind channels can be dispatched.
    pub fn with_sidecar_registry(mut self, reg: Arc<SidecarRegistry>) -> Self {
        self.sidecar_registry = Some(reg);
        self
    }
}

impl AuditSink for NotifyingAuditSink {
    fn emit(
        &self,
        kind:          AuditEventKind,
        session_id:    Option<&str>,
        task_id:       Option<&str>,
        initiative_id: Option<&str>,
    ) -> Result<AuditEvent, AuditWriterError> {
        // 1. Inner emit FIRST. The audit chain is the source of truth;
        //    if it fails, no notification dispatch happens (the spec
        //    forbids notifications without a corresponding audit
        //    record per cli-readonly.md §5.6.2).
        let event = self.inner.emit(kind, session_id, task_id, initiative_id)?;

        // 2. Snapshot the bundle once. Holding the reference across
        //    the dispatch is fine because `ArcSwap::load_full` returns
        //    an owned `Arc` that detaches from the swap.
        let bundle = self.policy.load_full();

        // 3. Hand the event AND the inner sink to the dispatcher. We
        //    pass `inner` (NOT `self`) so any per-channel
        //    `NotificationDeliveryFailed` event goes straight to the
        //    audit chain without re-triggering notifications. Without
        //    this guard, a misconfigured policy that routed
        //    `NotificationDeliveryFailed` to a perpetually-broken
        //    channel would loop forever.
        super::dispatch(
            event.clone(),
            bundle,
            self.data_dir.clone(),
            Arc::clone(&self.inner),
            self.sidecar_registry.clone(),
        );

        Ok(event)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::notifications::dispatch_blocking_for_tests;
    use raxis_test_support::FakeAuditSink;
    use raxis_policy::{OperatorEntry, PolicyBundle};
    use serde_json::json;

    fn bundle() -> Arc<ArcSwap<PolicyBundle>> {
        // The notification sink tests don't exercise the cert-validation
        // path; they need an OperatorEntry to exist only to satisfy the
        // bundle's "operators must not be empty" rule. `stub_cert_for_pubkey`
        // returns a structurally-shaped placeholder cert that
        // `for_tests_with_operators` accepts (validation is bypassed)
        // but would loudly fail any real `verify_cert_self_signature`
        // call — which is precisely the safety net we want.
        let pubkey = "0".repeat(64);
        let b = PolicyBundle::for_tests_with_operators(vec![OperatorEntry {
            pubkey_fingerprint: "fp".into(),
            display_name:       "fp".into(),
            pubkey_hex:         pubkey.clone(),
            permitted_ops:      vec![],
            cert:                  raxis_test_support::stub_cert_for_pubkey(pubkey),
            force_misconfig_bypass: false,
        }]);
        Arc::new(ArcSwap::from_pointee(b))
    }

    /// `NotifyingAuditSink::emit` MUST forward to the inner sink and
    /// return the same `AuditEvent`, with the dispatch fan-out being
    /// the only side effect.
    #[tokio::test]
    async fn emit_forwards_to_inner_and_returns_event() {
        let tmp     = tempfile::tempdir().unwrap();
        let inner   = Arc::new(FakeAuditSink::new());
        let inner_dyn: Arc<dyn AuditSink> = inner.clone();
        let sink    = NotifyingAuditSink::new(
            Arc::clone(&inner_dyn),
            bundle(),
            tmp.path().to_path_buf(),
        );

        let evt = sink.emit(
            AuditEventKind::EscalationApproved {
                escalation_id: "esc-A".into(),
                approved_by:   "op".into(),
                approved_by_display_name: None,
            },
            None, None, None,
        ).unwrap();

        assert_eq!(evt.event_kind, "EscalationApproved");
        assert_eq!(inner.events().len(), 1, "inner sink must capture one event");
    }

    /// A handler-emit followed by `dispatch_blocking_for_tests` (the
    /// production wrapper uses `tokio::spawn` which is awkward to wait
    /// on in tests) MUST land a JSONL line in the implicit Shell inbox.
    #[tokio::test]
    async fn dispatch_writes_inbox_line_on_emit() {
        let tmp = tempfile::tempdir().unwrap();
        let inner: Arc<dyn AuditSink> = Arc::new(FakeAuditSink::new());
        let sink  = NotifyingAuditSink::new(
            Arc::clone(&inner),
            bundle(),
            tmp.path().to_path_buf(),
        );

        // Emit through the wrapper to ensure inner-side capture.
        let evt = sink.emit(
            AuditEventKind::EscalationApproved {
                escalation_id: "esc-B".into(),
                approved_by:   "op".into(),
                approved_by_display_name: None,
            },
            None, None, None,
        ).unwrap();

        // The production code path uses `tokio::spawn`; for assertion
        // determinism we replay the same dispatch synchronously.
        dispatch_blocking_for_tests(
            evt,
            &bundle().load_full(),
            tmp.path(),
            Arc::clone(&inner),
        ).await;

        let inbox = PolicyBundle::shell_inbox_path_for(tmp.path());
        let raw   = std::fs::read_to_string(&inbox).unwrap_or_default();
        assert!(raw.contains("EscalationApproved"),
            "inbox MUST carry the dispatched event; got: {raw:?}");
    }

    /// If the inner sink returns Err, the wrapper MUST propagate the
    /// error AND skip the dispatch (no audit ⇒ no notification — the
    /// audit chain is the source of truth).
    #[test]
    fn err_from_inner_skips_dispatch_and_propagates() {
        struct AlwaysFail;
        impl AuditSink for AlwaysFail {
            fn emit(
                &self,
                _kind: AuditEventKind,
                _session_id: Option<&str>,
                _task_id: Option<&str>,
                _initiative_id: Option<&str>,
            ) -> Result<AuditEvent, AuditWriterError> {
                Err(AuditWriterError::Io(std::io::Error::other("synthetic")))
            }
        }
        let tmp     = tempfile::tempdir().unwrap();
        let inner: Arc<dyn AuditSink> = Arc::new(AlwaysFail);
        let sink    = NotifyingAuditSink::new(
            Arc::clone(&inner),
            bundle(),
            tmp.path().to_path_buf(),
        );

        let result = sink.emit(
            AuditEventKind::KernelStarted {
                data_dir:        "/tmp".into(),
                policy_epoch:    1,
                schema_version:  1,
            },
            None, None, None,
        );
        assert!(matches!(result, Err(AuditWriterError::Io(_))));

        // The inbox file must NOT have been created — we never reached
        // the dispatch fan-out.
        let inbox = PolicyBundle::shell_inbox_path_for(tmp.path());
        assert!(!inbox.exists(),
            "no inbox write must occur on a failed inner emit; found {inbox:?}");
        let _ = json!({}); // keep serde_json import live for future variant assertions
    }
}

//! Audit-sink decorator that bridges every per-session audit
//! emit onto the dashboard's [`SessionStreamCapture`].
//!
//! # Why this exists
//!
//! `specs/v2/v2_extended_gaps.md §4.3` ships the **agent stream
//! capture** surface (bounded file ring + broadcast channel +
//! SSE endpoint). The capture is allocated at boot and the SSE
//! endpoint subscribes correctly, but until this decorator
//! landed there was **no producer**: no code anywhere in the
//! kernel called [`SessionStreamCapture::append`], so the SSE
//! handler attached a live subscriber and then sat forever on
//! an empty broadcast channel. The dashboard's "Waiting for
//! stream events…" placeholder was the only thing operators
//! ever saw.
//!
//! Wrapping the production audit sink with
//! [`StreamingAuditSink`] turns every kernel audit emit that
//! carries a `session_id` into a live SSE frame on that
//! session's stream — operators watching a session detail
//! page see `IntentAccepted`, `WitnessAccepted`,
//! `SessionVmExited`, etc. flow in as they happen.
//!
//! Eventually the gateway will also publish raw model token
//! chunks through the same capture (the spec's intended
//! primary source). Until then the audit-event mirror is
//! enough to make the surface visibly alive AND it carries
//! the most operator-relevant signal (state changes), not
//! just LLM tokens.
//!
//! # Invariants
//!
//! * **Audit-write ordering is preserved.** The inner sink's
//!   `append` runs to completion (and returns its `Ok` /
//!   `Err`) BEFORE the stream mirror fires. A stream-push
//!   failure NEVER propagates back to the caller — the audit
//!   chain is the source of truth; live SSE is best-effort
//!   observability.
//! * **Read-only events are mirrored too.** Every event with a
//!   `session_id` reaches the capture, including events whose
//!   audit-chain semantics are pure read (e.g. operator
//!   privileged-read events introduced for
//!   `INV-AUDIT-OPERATOR-ACTION-01`). Operators expect to see
//!   their own actions echoed back live; suppressing read
//!   events here would create a confusing partial mirror.

use std::sync::Arc;

use raxis_audit_tools::writer::AuditWriterError;
use raxis_audit_tools::{AuditEvent, AuditEventKind, AuditSink};
use raxis_dashboard::stream::StreamEvent;

use crate::stream_capture::SessionStreamCapture;

/// Audit-sink decorator. Forwards every emit to the wrapped
/// sink, then — when the event carries a `session_id` — also
/// appends a [`StreamEvent`] to the dashboard's session
/// capture. Wrap once at kernel boot, then thread the
/// resulting `Arc<dyn AuditSink>` everywhere the kernel
/// expects an audit sink.
pub struct StreamingAuditSink {
    inner: Arc<dyn AuditSink>,
    capture: Arc<SessionStreamCapture>,
}

impl StreamingAuditSink {
    /// Wrap `inner` and mirror every session-scoped emit onto
    /// `capture`.
    pub fn new(inner: Arc<dyn AuditSink>, capture: Arc<SessionStreamCapture>) -> Self {
        Self { inner, capture }
    }
}

impl AuditSink for StreamingAuditSink {
    fn emit(
        &self,
        kind: AuditEventKind,
        session_id: Option<&str>,
        task_id: Option<&str>,
        initiative_id: Option<&str>,
    ) -> Result<AuditEvent, AuditWriterError> {
        let event = self.inner.emit(kind, session_id, task_id, initiative_id)?;
        if let Some(sid) = session_id {
            mirror_to_capture(&self.capture, sid, &event);
        }
        Ok(event)
    }
}

/// Convert an audit record to a [`StreamEvent`] and append it
/// to `capture`. Errors are intentionally swallowed (and logged
/// as a single-line warning) — the audit chain already
/// captured the event durably, so dropping a live mirror only
/// degrades the dashboard's freshness, not correctness.
fn mirror_to_capture(capture: &SessionStreamCapture, session_id: &str, event: &AuditEvent) {
    // Envelope shape mirrored to the FE matches
    // `dashboard-fe/src/types/api.ts::StreamEventEnvelope`:
    //   { at_ms, kind, payload: { seq, event_id, payload,
    //     initiative_id?, task_id? } }
    //
    // We carry the audit `seq` inside the payload so the
    // operator UI can deep-link to the audit-chain row for
    // any event the SSE stream surfaced.
    let envelope = StreamEvent {
        at_ms: u128::from(event.emitted_at.max(0) as u64)
            .saturating_mul(1_000)
            .min(u128::from(u64::MAX)) as u64,
        kind: event.event_kind.clone(),
        payload: serde_json::json!({
            "seq":           event.seq,
            "event_id":      event.event_id.to_string(),
            "initiative_id": event.initiative_id,
            "task_id":       event.task_id,
            "payload":       event.payload,
        }),
    };
    if let Err(e) = capture.append(session_id, envelope) {
        eprintln!(
            "{{\"level\":\"warn\",\"event\":\"StreamingAuditMirrorFailed\",\
             \"session_id\":\"{session_id}\",\"reason\":\"{e}\"}}"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use raxis_audit_tools::AuditEvent;
    use raxis_test_support::FakeAuditSink;

    #[test]
    fn mirror_pushes_into_capture_when_session_id_present() {
        let tmp = tempfile::tempdir().unwrap();
        let capture =
            SessionStreamCapture::new(tmp.path(), crate::stream_capture::CaptureConfig::default())
                .unwrap();
        // Pre-allocate the session and grab a subscription so
        // we can observe the mirror.
        capture.ensure_session("sess-mirror").unwrap();
        let mut sub = capture.subscribe("sess-mirror").unwrap();
        let inner: Arc<dyn AuditSink> = Arc::new(FakeAuditSink::new());
        let wrapped = StreamingAuditSink::new(inner, Arc::clone(&capture));

        let event = wrapped
            .emit(
                AuditEventKind::KernelStopped {
                    reason: "test".into(),
                },
                Some("sess-mirror"),
                None,
                None,
            )
            .expect("emit ok");

        // Receive synchronously via try_recv on the underlying
        // broadcast — easier than running tokio in this small
        // unit.
        let rt = tokio::runtime::Runtime::new().unwrap();
        let received = rt
            .block_on(async {
                tokio::time::timeout(std::time::Duration::from_secs(1), sub.recv()).await
            })
            .expect("recv timed out")
            .expect("recv error");
        let received = received.expect("source closed");
        assert_eq!(received.kind, event.event_kind);
        assert_eq!(received.payload["seq"], event.seq);
        // The audit-event payload should be transparently
        // forwarded under the `payload` key (so the FE can
        // render rich event-kind-specific details).
        assert!(received.payload.get("payload").is_some());
    }

    #[test]
    fn no_mirror_when_session_id_is_none() {
        let tmp = tempfile::tempdir().unwrap();
        let capture =
            SessionStreamCapture::new(tmp.path(), crate::stream_capture::CaptureConfig::default())
                .unwrap();
        let inner: Arc<dyn AuditSink> = Arc::new(FakeAuditSink::new());
        let wrapped = StreamingAuditSink::new(inner, Arc::clone(&capture));

        wrapped
            .emit(
                AuditEventKind::KernelStarted {
                    data_dir: "/tmp/x".into(),
                    policy_epoch: 1,
                    schema_version: 1,
                },
                None,
                None,
                None,
            )
            .expect("emit ok");

        // The capture's tail for the absent session id stays
        // empty.
        let tail = capture.tail("any-session", 16);
        assert!(tail.is_empty());
    }

    /// Smoke check that the stream surface preserves enough of
    /// the audit record for the dashboard FE to render.
    #[test]
    fn envelope_carries_seq_event_id_and_payload() {
        let evt = AuditEvent {
            seq: 42,
            // Round-trip a fixed UUID through the audit-tools'
            // own `Uuid` re-export so this test doesn't pull
            // in `uuid` as a direct dev-dep.
            event_id: serde_json::from_str::<AuditEvent>(
                "{\"seq\":0,\"event_id\":\"00000000-0000-0000-0000-000000000000\",\
                 \"event_kind\":\"X\",\"session_id\":null,\"task_id\":null,\
                 \"initiative_id\":null,\"payload\":null,\"emitted_at\":0,\
                 \"prev_sha256\":\"00000000000000000000000000000000000000000000000000000000000000\
00\"}",
            )
            .unwrap()
            .event_id,
            event_kind: "TestKind".into(),
            session_id: Some("sess".into()),
            task_id: Some("task-1".into()),
            initiative_id: Some("init-1".into()),
            payload: serde_json::json!({"hello": "world"}),
            emitted_at: 1_700_000_000,
            prev_sha256: "0".repeat(64),
        };
        let tmp = tempfile::tempdir().unwrap();
        let capture =
            SessionStreamCapture::new(tmp.path(), crate::stream_capture::CaptureConfig::default())
                .unwrap();
        capture.ensure_session("sess").unwrap();
        mirror_to_capture(&capture, "sess", &evt);
        let tail = capture.tail("sess", 4);
        assert_eq!(tail.len(), 1);
        assert_eq!(tail[0].kind, "TestKind");
        assert_eq!(tail[0].payload["seq"], 42);
        assert_eq!(tail[0].payload["initiative_id"], "init-1");
        assert_eq!(tail[0].payload["task_id"], "task-1");
        assert_eq!(tail[0].payload["payload"]["hello"], "world");
    }
}

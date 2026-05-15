// raxis-test-support::audit_sink — `FakeAuditSink` for unit tests.
//
// Why this lives here, not in `raxis-audit-tools`:
//   The same discipline that keeps `FakeClock` out of `raxis-types`
//   (philosophy.md §1.6) applies to the audit-sink fake. A
//   `FakeAuditSink` shipped in the production audit crate would be
//   reachable from any release binary that links `raxis-audit-tools`
//   — and every binary in this workspace links it. The
//   `RealClock` / `FakeClock` split is the canonical pattern: the
//   trait and the production implementation (`FileAuditSink`) live in
//   `raxis-audit-tools`; the in-memory test fake lives here, where
//   the dev-dep-only gates prevent it from leaking into release
//   binaries.
//
// What this module provides:
//   - `CapturedEvent` — the same shape `FakeAuditSink` holds in
//     memory; production code never sees it (the production sink
//     writes JSONL).
//   - `FakeAuditSink` — `AuditSink` implementor that captures every
//     emitted event in a `Mutex<Vec<...>>`. Behaviour preserved
//     byte-for-byte from the prior `raxis-audit-tools::sink` location.
//
// What this module does NOT provide:
//   - A no-op sink (`NoopAuditSink`). If you need one, write
//     `impl AuditSink for ()` in your test scope; we deliberately
//     don't add a third implementor here because every audit-sensitive
//     test should assert on something the sink captured.

use raxis_audit_tools::{sink::AuditSink, AuditEvent, AuditEventKind, AuditWriterError};
use std::sync::Mutex;
use uuid::Uuid;

/// One audit event as captured by [`FakeAuditSink`]. Holds the same
/// fields the production writer would have written, minus the chain
/// hash and generated UUID (which would non-determinise tests).
#[derive(Debug, Clone)]
pub struct CapturedEvent {
    pub kind: AuditEventKind,
    pub session_id: Option<String>,
    pub task_id: Option<String>,
    pub initiative_id: Option<String>,
}

/// In-memory audit sink for unit tests. Captures every emitted event
/// in the order they were appended.
///
/// Cheap to share: tests typically wrap one in `Arc<FakeAuditSink>`
/// and clone the `Arc` into both the kernel handler context AND a
/// local handle for assertions. The `Arc<FakeAuditSink>` coerces to
/// `Arc<dyn AuditSink>` exactly the same way the production
/// `Arc<FileAuditSink>` does.
pub struct FakeAuditSink {
    events: Mutex<Vec<CapturedEvent>>,
}

impl FakeAuditSink {
    pub fn new() -> Self {
        Self {
            events: Mutex::new(Vec::new()),
        }
    }

    /// Snapshot of every captured event in the order they were
    /// emitted. Returns an owned `Vec` so callers can iterate without
    /// holding the internal lock.
    pub fn events(&self) -> Vec<CapturedEvent> {
        self.events
            .lock()
            .expect("fake audit mutex poisoned")
            .clone()
    }

    /// Convenience for tests that only care about the variant tags.
    pub fn event_kinds(&self) -> Vec<&'static str> {
        self.events().iter().map(|e| e.kind.as_str()).collect()
    }
}

impl Default for FakeAuditSink {
    fn default() -> Self {
        Self::new()
    }
}

impl AuditSink for FakeAuditSink {
    fn emit(
        &self,
        kind: AuditEventKind,
        session_id: Option<&str>,
        task_id: Option<&str>,
        initiative_id: Option<&str>,
    ) -> Result<AuditEvent, AuditWriterError> {
        // Synthesise a deterministic AuditEvent that mirrors what the
        // production writer would have produced. Tests get the same
        // shape (seq, event_id, payload) without writing to disk; the
        // `seq` is sourced from the captured-events vector length so
        // it is monotonically increasing across emits on the same
        // sink.
        let mut events = self.events.lock().expect("fake audit mutex poisoned");
        let seq = events.len() as u64;
        let payload = serde_json::to_value(&kind).map_err(AuditWriterError::Json)?;
        let event_kind_str = kind.as_str().to_owned();
        events.push(CapturedEvent {
            kind,
            session_id: session_id.map(str::to_owned),
            task_id: task_id.map(str::to_owned),
            initiative_id: initiative_id.map(str::to_owned),
        });
        Ok(AuditEvent {
            seq,
            event_id: Uuid::new_v4(),
            event_kind: event_kind_str,
            session_id: session_id.map(str::to_owned),
            task_id: task_id.map(str::to_owned),
            initiative_id: initiative_id.map(str::to_owned),
            payload,
            // `unix_now()` is private to the writer module; reaching
            // for `std::time::SystemTime::now()` here is fine because
            // the FakeAuditSink does not need to share the writer's
            // monotonic clock — tests assert on `seq`/`event_kind`,
            // not `emitted_at`.
            emitted_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0),
            prev_sha256: String::from(
                "0000000000000000000000000000000000000000000000000000000000000000",
            ),
        })
    }
}

// ---------------------------------------------------------------------------
// Tests — sink-level contracts.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn sample_kind(reason: &str) -> AuditEventKind {
        AuditEventKind::KernelStopped {
            reason: reason.to_owned(),
        }
    }

    #[test]
    fn fake_sink_captures_events_in_order() {
        let sink = FakeAuditSink::new();
        let _ = sink.emit(sample_kind("a"), None, None, None).unwrap();
        let _ = sink
            .emit(sample_kind("b"), Some("sess-1"), None, None)
            .unwrap();
        let _ = sink
            .emit(sample_kind("c"), None, Some("task-1"), Some("init-1"))
            .unwrap();

        let events = sink.events();
        assert_eq!(events.len(), 3);
        assert_eq!(events[1].session_id.as_deref(), Some("sess-1"));
        assert_eq!(events[2].task_id.as_deref(), Some("task-1"));
        assert_eq!(events[2].initiative_id.as_deref(), Some("init-1"));
        assert_eq!(sink.event_kinds(), vec!["KernelStopped"; 3]);
    }

    #[test]
    fn fake_sink_is_thread_safe_under_concurrent_emits() {
        // Verifies (a) `FakeAuditSink` meets `Send + Sync` and (b) the
        // internal Mutex correctly serialises concurrent emits.
        let sink = Arc::new(FakeAuditSink::new());

        // Compile-check that an Arc<FakeAuditSink> coerces to
        // Arc<dyn AuditSink> — this is exactly the coercion
        // `HandlerContext` performs in production.
        let _typed: Arc<dyn AuditSink> = sink.clone();

        let handles: Vec<_> = (0..8u32)
            .map(|i| {
                let s = Arc::clone(&sink);
                std::thread::spawn(move || {
                    let _ = s
                        .emit(sample_kind(&format!("t{i}")), None, None, None)
                        .unwrap();
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }

        let events = sink.events();
        assert_eq!(
            events.len(),
            8,
            "every concurrent emit must be captured exactly once"
        );
    }

    #[test]
    fn captured_event_round_trips_session_task_initiative_ids() {
        let sink = FakeAuditSink::new();
        let _ = sink
            .emit(
                sample_kind("ids-test"),
                Some("sess-id-x"),
                Some("task-id-y"),
                Some("init-id-z"),
            )
            .unwrap();
        let captured = sink.events();
        assert_eq!(captured[0].session_id.as_deref(), Some("sess-id-x"));
        assert_eq!(captured[0].task_id.as_deref(), Some("task-id-y"));
        assert_eq!(captured[0].initiative_id.as_deref(), Some("init-id-z"));
    }
}

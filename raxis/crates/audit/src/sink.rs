// raxis-audit-tools::sink — typed audit sink the kernel routes every event
// through.
//
// Normative reference: kernel-store.md §2.5.2 "Audit log transaction boundary".
//
// Why a trait?
//   The kernel previously emitted audit events via `eprintln!`, which made
//   it impossible to:
//     1. Test that a specific handler emitted a specific event after a
//        specific store commit (the test would have to scrape stderr).
//     2. Write to the canonical JSONL segment the v2 audit verifier
//        consumes — `eprintln!` does not produce a parseable chain at all.
//     3. Swap the writer for a no-op or in-memory buffer in unit tests
//        without touching the call sites.
//
// `AuditSink` is the single abstraction kernel handlers depend on. The
// production wiring is `FileAuditSink`, which holds the underlying
// `AuditWriter` behind a `std::sync::Mutex` (separate from the Store
// mutex per §2.5.2). Tests use `FakeAuditSink`, which captures emitted
// events in memory for assertions.
//
// Concurrency: `AuditSink::emit` takes `&self` so the kernel can hold
// `Arc<dyn AuditSink>` in `HandlerContext`. The implementations are
// internally synchronised — handlers do not need to wrap them in another
// mutex.
//
// **Ordering invariant** (§2.5.2): callers MUST emit only AFTER the
// corresponding `tx.commit()` has returned `Ok`. This trait does not
// enforce that — it cannot — but the kernel review process treats any
// `audit.emit(..)` call inside an open transaction as a P0 spec
// violation.

use crate::event::AuditEventKind;
use crate::writer::{AuditWriter, AuditWriterError};
use std::sync::Mutex;

// ---------------------------------------------------------------------------
// AuditSink — the trait kernel handlers depend on.
// ---------------------------------------------------------------------------

/// Append-only audit sink. Holds an `AuditWriter` (or a fake) behind
/// internal synchronisation.
///
/// Implementations: [`FileAuditSink`] (production), [`FakeAuditSink`] (tests).
pub trait AuditSink: Send + Sync {
    /// Append one audit event.
    ///
    /// MUST be called only AFTER the matching SQLite transaction has
    /// committed (kernel-store.md §2.5.2). Implementations are free to
    /// fail with [`AuditWriterError::Io`] on disk pressure; the kernel
    /// treats audit-write failure as fatal (§2.5.2 "audit-pointer is
    /// part of the consistency unit") — see `kernel/src/main.rs`.
    fn emit(
        &self,
        kind: AuditEventKind,
        session_id: Option<&str>,
        task_id: Option<&str>,
        initiative_id: Option<&str>,
    ) -> Result<(), AuditWriterError>;
}

// ---------------------------------------------------------------------------
// FileAuditSink — production sink that writes to the JSONL segment.
// ---------------------------------------------------------------------------

/// Production audit sink. Wraps a single `AuditWriter` behind a
/// `std::sync::Mutex` so kernel handlers can call `emit` from any thread.
///
/// We use `std::sync::Mutex`, not `tokio::sync::Mutex`, because:
///   - The audit append is a synchronous fsync-bounded write; holding
///     the lock for the duration of the write is exactly the desired
///     semantics.
///   - Kernel handlers either (a) run on a `spawn_blocking` task already,
///     or (b) the audit emission happens after a `lock_sync()` block so
///     the calling thread is one of those two cases. Either way, a
///     blocking std mutex is safe and lower-overhead than tokio's.
pub struct FileAuditSink {
    inner: Mutex<AuditWriter>,
}

impl FileAuditSink {
    /// Wrap an existing `AuditWriter`. The kernel constructs the writer
    /// during bootstrap (after the store opens) and then wraps it here.
    pub fn new(writer: AuditWriter) -> Self {
        Self { inner: Mutex::new(writer) }
    }
}

impl AuditSink for FileAuditSink {
    fn emit(
        &self,
        kind: AuditEventKind,
        session_id: Option<&str>,
        task_id: Option<&str>,
        initiative_id: Option<&str>,
    ) -> Result<(), AuditWriterError> {
        // Mutex poisoning here means a previous emit panicked mid-write,
        // which is itself a fatal corruption signal — the kernel cannot
        // continue with a half-flushed line. Panic with a clear message
        // so the supervisor restarts.
        let mut guard = self.inner.lock()
            .expect("audit writer mutex poisoned — previous append panicked");
        guard.append(kind, session_id, task_id, initiative_id)
    }
}

// ---------------------------------------------------------------------------
// FakeAuditSink — in-memory sink for unit tests.
// ---------------------------------------------------------------------------

/// In-memory audit sink for unit tests. Captures every emitted event in
/// the order they were appended.
///
/// Available outside `#[cfg(test)]` so downstream crates (kernel, future
/// `raxis-test-support`) can inject it from their own test code.
pub struct FakeAuditSink {
    events: Mutex<Vec<CapturedEvent>>,
}

/// One audit event as captured by `FakeAuditSink`. Holds the same fields
/// the production writer would have written, minus the chain hash and
/// generated UUID (which would non-determinise tests).
#[derive(Debug, Clone)]
pub struct CapturedEvent {
    pub kind: AuditEventKind,
    pub session_id: Option<String>,
    pub task_id: Option<String>,
    pub initiative_id: Option<String>,
}

impl FakeAuditSink {
    pub fn new() -> Self {
        Self { events: Mutex::new(Vec::new()) }
    }

    /// Snapshot of every captured event in the order they were emitted.
    /// Returns an owned `Vec` so callers can iterate without holding the
    /// internal lock.
    pub fn events(&self) -> Vec<CapturedEvent> {
        self.events.lock()
            .expect("fake audit mutex poisoned")
            .clone()
    }

    /// Convenience for tests that only care about the variant tags.
    pub fn event_kinds(&self) -> Vec<&'static str> {
        self.events()
            .iter()
            .map(|e| e.kind.as_str())
            .collect()
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
    ) -> Result<(), AuditWriterError> {
        self.events
            .lock()
            .expect("fake audit mutex poisoned")
            .push(CapturedEvent {
                kind,
                session_id: session_id.map(str::to_owned),
                task_id: task_id.map(str::to_owned),
                initiative_id: initiative_id.map(str::to_owned),
            });
        Ok(())
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
        AuditEventKind::KernelStopped { reason: reason.to_owned() }
    }

    #[test]
    fn fake_sink_captures_events_in_order() {
        let sink = FakeAuditSink::new();
        sink.emit(sample_kind("a"), None, None, None).unwrap();
        sink.emit(sample_kind("b"), Some("sess-1"), None, None).unwrap();
        sink.emit(sample_kind("c"), None, Some("task-1"), Some("init-1")).unwrap();

        let events = sink.events();
        assert_eq!(events.len(), 3);
        assert_eq!(events[1].session_id.as_deref(), Some("sess-1"));
        assert_eq!(events[2].task_id.as_deref(), Some("task-1"));
        assert_eq!(events[2].initiative_id.as_deref(), Some("init-1"));
        assert_eq!(sink.event_kinds(), vec!["KernelStopped"; 3]);
    }

    #[test]
    fn fake_sink_is_thread_safe_under_concurrent_emits() {
        // Verifies (a) FakeAuditSink meets `Send + Sync` and (b) the
        // internal Mutex correctly serialises concurrent emits.
        let sink = Arc::new(FakeAuditSink::new());

        // Compile-check that an Arc<FakeAuditSink> coerces to
        // Arc<dyn AuditSink> — this is exactly the coercion HandlerContext
        // performs in production.
        let _typed: Arc<dyn AuditSink> = sink.clone();

        let handles: Vec<_> = (0..8u32)
            .map(|i| {
                let s = Arc::clone(&sink);
                std::thread::spawn(move || {
                    s.emit(sample_kind(&format!("t{i}")), None, None, None).unwrap();
                })
            })
            .collect();
        for h in handles { h.join().unwrap(); }

        let events = sink.events();
        assert_eq!(events.len(), 8, "every concurrent emit must be captured exactly once");
    }
}

// raxis-audit-tools::sink — typed audit sink the kernel routes every
// event through.
//
// Normative reference: kernel-store.md §2.5.2 "Audit log transaction
// boundary".
//
// Why a trait?
//   The kernel previously emitted audit events via `eprintln!`, which
//   made it impossible to:
//     1. Test that a specific handler emitted a specific event after a
//        specific store commit (the test would have to scrape stderr).
//     2. Write to the canonical JSONL segment the v2 audit verifier
//        consumes — `eprintln!` does not produce a parseable chain at
//        all.
//     3. Swap the writer for an in-memory buffer in unit tests without
//        touching the call sites.
//
// `AuditSink` is the single abstraction kernel handlers depend on. The
// production wiring is `FileAuditSink`, which holds the underlying
// `AuditWriter` behind a `std::sync::Mutex` (separate from the Store
// mutex per §2.5.2). Tests use the in-memory `FakeAuditSink` from
// `raxis-test-support::audit_sink` — that crate is dev-dep-only by
// construction, so the fake never reaches a release binary. Same
// `RealClock` / `FakeClock` discipline (philosophy.md §1.6).
//
// Concurrency: `AuditSink::emit` takes `&self` so the kernel can hold
// `Arc<dyn AuditSink>` in `HandlerContext`. The implementations are
// internally synchronised — handlers do not need to wrap them in
// another mutex.
//
// **Ordering invariant** (§2.5.2): callers MUST emit only AFTER the
// corresponding `tx.commit()` has returned `Ok`. This trait does not
// enforce that — it cannot — but the kernel review process treats any
// `audit.emit(..)` call inside an open transaction as a P0 spec
// violation.

use crate::event::{AuditEvent, AuditEventKind};
use crate::writer::{AuditWriter, AuditWriterError};
use std::sync::Mutex;

// ---------------------------------------------------------------------------
// AuditSink — the trait kernel handlers depend on.
// ---------------------------------------------------------------------------

/// Append-only audit sink. Holds an `AuditWriter` (or a fake) behind
/// internal synchronisation.
///
/// Implementations: [`FileAuditSink`] (production);
/// `raxis_test_support::FakeAuditSink` for tests (dev-dep-only).
pub trait AuditSink: Send + Sync {
    /// Append one audit event and return the materialised record.
    ///
    /// MUST be called only AFTER the matching SQLite transaction has
    /// committed (kernel-store.md §2.5.2). Implementations are free to
    /// fail with [`AuditWriterError::Io`] on disk pressure; the kernel
    /// treats audit-write failure as fatal (§2.5.2 "audit-pointer is
    /// part of the consistency unit") — see `kernel/src/main.rs`.
    ///
    /// The returned [`AuditEvent`] carries the freshly-assigned `seq`
    /// and `event_id`. Downstream fanouts (notification dispatch,
    /// telemetry mirror) reuse those fields so the operator-facing
    /// inbox JSONL records can be cross-referenced against the audit
    /// chain. Callers that don't need the record can simply discard it
    /// (`let _ = audit.emit(...)?;`).
    fn emit(
        &self,
        kind: AuditEventKind,
        session_id: Option<&str>,
        task_id: Option<&str>,
        initiative_id: Option<&str>,
    ) -> Result<AuditEvent, AuditWriterError>;
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
        Self {
            inner: Mutex::new(writer),
        }
    }
}

impl AuditSink for FileAuditSink {
    fn emit(
        &self,
        kind: AuditEventKind,
        session_id: Option<&str>,
        task_id: Option<&str>,
        initiative_id: Option<&str>,
    ) -> Result<AuditEvent, AuditWriterError> {
        // Mutex poisoning here means a previous emit panicked mid-write,
        // which is itself a fatal corruption signal — the kernel cannot
        // continue with a half-flushed line. Panic with a clear message
        // so the supervisor restarts.
        let mut guard = self
            .inner
            .lock()
            .expect("audit writer mutex poisoned — previous append panicked");
        guard.append(kind, session_id, task_id, initiative_id)
    }
}

// ---------------------------------------------------------------------------
// In-memory test fake
//
// `FakeAuditSink` + `CapturedEvent` used to live in this module
// directly. They moved to `raxis-test-support::audit_sink` so the
// production audit crate has no test-only dependents and the same
// `RealClock` / `FakeClock` discipline (philosophy.md §1.6) applies
// to audit sinks. Tests that need an in-memory sink should
// `use raxis_test_support::FakeAuditSink;` from their
// `[dev-dependencies]`.
// ---------------------------------------------------------------------------

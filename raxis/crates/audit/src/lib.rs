// raxis-audit-tools — append-only JSONL audit segment writer.
//
// Normative reference: kernel-store.md §2.5.2 "Audit log transaction boundary"
//
// This crate exposes two things:
//   1. `AuditEvent` — the shared record type for every audit record kind.
//   2. `AuditWriter` — the append-only segment writer handle.
//
// Kernel rules (§2.5.2):
//   - SQLite COMMITS FIRST. AuditWriter::append is only called after Ok(()).
//   - AuditWriter is append-only: no read, no rewrite of existing lines.
//   - Chain integrity: each line carries prev_sha256 = SHA-256 of the raw
//     previous line bytes (including trailing newline).
//   - First record: prev_sha256 = "00000...000" (64 zeroes).
//   - Kernel crash between commit and JSONL write → gap at this seq;
//     recovery::reconcile appends a ReconciliationGap record.

pub mod event;
pub mod sink;
pub mod writer;

pub use event::{AuditEvent, AuditEventKind};
pub use sink::{AuditSink, CapturedEvent, FakeAuditSink, FileAuditSink};
pub use writer::{last_chain_state, AuditWriter, AuditWriterError, ChainResumeInfo};

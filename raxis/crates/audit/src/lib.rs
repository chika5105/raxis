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
//
// Invariants (V2_GAPS.md §13 Category 1, annotation-only):
//   - INV-AUDIT-PAIRED-01 (commit-before-emit): structurally enforced
//     by the contract above — `AuditWriter::append` is called only
//     after the SQLite transaction returned `Ok(())`. Callers
//     violating this would emit before commit; there is no
//     write path that bypasses `writer::AuditWriter`.
//   - INV-AUDIT-PAIRED-02 (chain-tail integrity): enforced by
//     `writer::AuditWriter` carrying the running tail and refusing
//     to write a record whose `prev_sha256` does not equal the
//     observed tail. Chain breaks surface as `AuditWriterError`.
//   - INV-AUDIT-PAIRED-03 (single-writer-per-segment): enforced
//     by the kernel holding exactly one `AuditWriter` per active
//     segment; the type is `!Sync` for append calls and the
//     kernel never clones the handle across tasks.
//   - INV-AUDIT-PAIRED-04 (no-rewrite): enforced by the
//     `AuditWriter` opening segments with `O_APPEND` only — the
//     crate exposes no public API to seek, truncate, or rewrite
//     bytes already on disk.
//   - INV-AUDIT-PAIRED-06 (gap-recovery): enforced by
//     `recovery::reconcile` appending a `ReconciliationGap`
//     record at the next `seq` whenever the durable JSONL tail
//     lags the SQLite tail at boot.
//   - INV-AUDIT-PAIRED-07 (genesis monotonicity): enforced by
//     `genesis::write_genesis_segment` writing record `seq=0`
//     with the all-zeroes `prev_sha256` literal and refusing to
//     run if a prior genesis exists.

pub mod event;
pub mod genesis;
pub mod reader;
pub mod sink;
pub mod writer;

pub use event::{AuditEvent, AuditEventKind};
pub use genesis::{write_genesis_segment, GenesisWriteError};
pub use reader::{
    quick_chain_check, verify_chain_from, verify_chain_full, ChainQuickCheck, ChainReadError,
    ChainReader, ChainRecord, ChainStats, AUDIT_DIR_NAME, GENESIS_PREV_SHA256_LITERAL,
    SEGMENT_PREFIX, SEGMENT_SUFFIX,
};
pub use sink::{AuditSink, FileAuditSink};
pub use writer::{
    last_chain_state, AuditWriter, AuditWriterError, ChainResumeInfo,
};

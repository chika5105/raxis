// raxis-audit-tools::writer — AuditWriter: append-only JSONL segment writer.
//
// Normative reference: kernel-store.md §2.5.2 "Audit record format"
//
// AuditWriter owns the open file handle to the active segment and the
// sequence counter + prev_sha256 chain state. It is the ONLY way to write
// to the audit log — no other module may open or write to the segment file.
//
// Chain invariant: every record's prev_sha256 is the SHA-256 of the raw
// bytes of the previous record's line (including its trailing '\n').
// First record in a segment uses "000...000" (64 zeroes).
//
// Thread safety: AuditWriter is NOT Sync. The kernel wraps it in a
// tokio::sync::Mutex (separate from the Store mutex) to serialise writes.
// The write-ordering invariant (SQLite commit → JSONL append) is enforced
// by the caller, not this module.

use crate::event::{AuditEvent, AuditEventKind};
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::Path;
use thiserror::Error;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// AuditWriterError
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum AuditWriterError {
    #[error("I/O error writing audit segment: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON serialisation error: {0}")]
    Json(#[from] serde_json::Error),
}

// ---------------------------------------------------------------------------
// AuditWriter
// ---------------------------------------------------------------------------

/// Append-only writer for one JSONL audit segment file.
///
/// The kernel holds one `AuditWriter` per active segment. When the segment
/// rotates, the old `AuditWriter` is dropped (closing the file handle) and
/// a new one is constructed for the next segment. The chain is unbroken
/// because the new segment's first record uses the final `prev_sha256` of the
/// preceding segment as its own `prev_sha256` — but this is not implemented
/// in v1 (single-segment, no rotation). v1 uses `prev_sha256 = "000...000"`
/// for the first record of each segment start.
pub struct AuditWriter {
    /// Buffered writer for the segment file.
    writer: BufWriter<File>,
    /// Monotonically increasing sequence counter.
    seq: u64,
    /// SHA-256 of the last written line (hex, 64 chars).
    /// "000...000" before the first write.
    prev_sha256: String,
}

impl AuditWriter {
    const GENESIS_PREV_SHA256: &'static str =
        "0000000000000000000000000000000000000000000000000000000000000000";

    /// Open or create the segment file at `path` and initialise the writer.
    ///
    /// - If the file does not exist, it is created.
    /// - If the file exists (resume after crash), `starting_seq` and
    ///   `starting_prev_sha256` must be recovered from the file by the caller
    ///   (the writer does not scan existing lines — it just appends).
    ///
    /// For fresh segments, pass `starting_seq = 0` and
    /// `starting_prev_sha256 = None` (uses genesis "000...000").
    pub fn open(
        path: &Path,
        starting_seq: u64,
        starting_prev_sha256: Option<String>,
    ) -> Result<Self, AuditWriterError> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;
        Ok(Self {
            writer: BufWriter::new(file),
            seq: starting_seq,
            prev_sha256: starting_prev_sha256
                .unwrap_or_else(|| Self::GENESIS_PREV_SHA256.to_owned()),
        })
    }

    /// Append one audit event to the segment.
    ///
    /// Constructs the full `AuditEvent` record, serialises to JSON, appends
    /// the line (with trailing '\n'), flushes, and updates chain state.
    ///
    /// This method is synchronous. The tokio runtime should call it on a
    /// `spawn_blocking` task or hold the audit mutex to avoid blocking the
    /// async runtime for long.
    pub fn append(
        &mut self,
        kind: AuditEventKind,
        session_id: Option<&str>,
        task_id: Option<&str>,
        initiative_id: Option<&str>,
    ) -> Result<(), AuditWriterError> {
        let event_kind = kind.as_str().to_owned();
        let payload = serde_json::to_value(&kind)?;

        let event = AuditEvent {
            seq: self.seq,
            event_id: Uuid::new_v4(),
            event_kind,
            session_id: session_id.map(|s| s.to_owned()),
            task_id: task_id.map(|s| s.to_owned()),
            initiative_id: initiative_id.map(|s| s.to_owned()),
            payload,
            emitted_at: unix_now(),
            prev_sha256: self.prev_sha256.clone(),
        };

        // Serialise to JSON (single line, no trailing whitespace from serde).
        let mut line = serde_json::to_string(&event)?;
        line.push('\n');

        // Compute SHA-256 of the raw line bytes for the next record.
        let next_prev = sha256_hex(line.as_bytes());

        // Write and flush.
        self.writer.write_all(line.as_bytes())?;
        self.writer.flush()?;

        // Advance chain state only after a successful flush.
        self.seq += 1;
        self.prev_sha256 = next_prev;

        Ok(())
    }

    /// The current sequence number (next event will use this value).
    pub fn current_seq(&self) -> u64 {
        self.seq
    }

    /// The SHA-256 of the last written line.
    pub fn prev_sha256(&self) -> &str {
        &self.prev_sha256
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

fn unix_now() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before Unix epoch")
        .as_secs() as i64
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader};
    use tempfile::NamedTempFile;

    fn make_writer() -> (AuditWriter, NamedTempFile) {
        let tmp = NamedTempFile::new().unwrap();
        let w = AuditWriter::open(tmp.path(), 0, None).unwrap();
        (w, tmp)
    }

    fn read_lines(path: &Path) -> Vec<serde_json::Value> {
        let f = File::open(path).unwrap();
        BufReader::new(f)
            .lines()
            .map(|l| serde_json::from_str(&l.unwrap()).unwrap())
            .collect()
    }

    #[test]
    fn first_record_has_genesis_prev_sha256() {
        let (mut w, tmp) = make_writer();
        w.append(
            AuditEventKind::KernelStarted {
                data_dir: "/tmp/test".to_owned(),
                policy_epoch: 1,
                schema_version: 1,
            },
            None,
            None,
            None,
        )
        .unwrap();

        let records = read_lines(tmp.path());
        assert_eq!(records.len(), 1);
        assert_eq!(
            records[0]["prev_sha256"].as_str().unwrap(),
            AuditWriter::GENESIS_PREV_SHA256
        );
        assert_eq!(records[0]["seq"].as_u64().unwrap(), 0);
    }

    #[test]
    fn chain_links_correctly() {
        let (mut w, tmp) = make_writer();

        for i in 0..3 {
            w.append(
                AuditEventKind::KernelStopped {
                    reason: format!("test-{}", i),
                },
                None,
                None,
                None,
            )
            .unwrap();
        }

        let records = read_lines(tmp.path());
        assert_eq!(records.len(), 3);

        // Verify chain: records[n].prev_sha256 == SHA-256 of raw line of records[n-1].
        // Re-read the raw file to get the exact bytes.
        let raw = std::fs::read_to_string(tmp.path()).unwrap();
        let raw_lines: Vec<&str> = raw.lines().collect();

        // records[0] prev = genesis
        assert_eq!(
            records[0]["prev_sha256"].as_str().unwrap(),
            AuditWriter::GENESIS_PREV_SHA256
        );

        // records[1] prev = SHA-256 of raw_lines[0] + '\n'
        let expected_1 = sha256_hex(format!("{}\n", raw_lines[0]).as_bytes());
        assert_eq!(records[1]["prev_sha256"].as_str().unwrap(), expected_1);

        // records[2] prev = SHA-256 of raw_lines[1] + '\n'
        let expected_2 = sha256_hex(format!("{}\n", raw_lines[1]).as_bytes());
        assert_eq!(records[2]["prev_sha256"].as_str().unwrap(), expected_2);
    }

    #[test]
    fn seq_increments() {
        let (mut w, tmp) = make_writer();
        for _ in 0..5 {
            w.append(
                AuditEventKind::KernelStopped {
                    reason: "x".to_owned(),
                },
                None,
                None,
                None,
            )
            .unwrap();
        }
        let records = read_lines(tmp.path());
        for (i, r) in records.iter().enumerate() {
            assert_eq!(r["seq"].as_u64().unwrap(), i as u64);
        }
    }
}

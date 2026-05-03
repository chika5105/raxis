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
use std::io::{BufRead, BufReader, BufWriter, Write};
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

    /// `last_chain_state` walked the segment and found a record whose
    /// `seq` does not equal `prev_seq + 1`. Returned with the offending
    /// values so the caller can surface a precise diagnostic. Fail-closed
    /// — the kernel must NEVER append to a chain that has visible gaps.
    #[error("audit chain has a sequence gap at line {line_number}: expected seq={expected}, got seq={got}")]
    ChainSequenceGap {
        line_number: u64,
        expected: u64,
        got: u64,
    },

    /// `last_chain_state` walked the segment and found a record whose
    /// `prev_sha256` does not equal `SHA-256(prev_line_bytes_with_newline)`.
    /// Same fail-closed posture as above.
    #[error("audit chain has a prev_sha256 break at line {line_number}: expected={expected}, got={got}")]
    ChainPrevSha256Break {
        line_number: u64,
        expected: String,
        got: String,
    },

    /// `last_chain_state` encountered a line that is not valid JSON or
    /// is missing a required field (`seq`, `prev_sha256`). Fail-closed:
    /// the kernel cannot resume from a corrupted segment.
    #[error("audit chain has malformed JSON at line {line_number}: {reason}")]
    MalformedRecord { line_number: u64, reason: String },
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
    /// First record of any segment uses 64 hex zeroes as `prev_sha256`.
    /// Public so `last_chain_state` (free function below) can reference it
    /// AND so external test code can pin the genesis byte sequence.
    pub const GENESIS_PREV_SHA256: &'static str =
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
// Chain resume — scans an existing segment file end-to-end and computes
// the (next_seq, prev_sha256) pair the writer needs to continue the chain
// across a kernel restart. Without this scan, every kernel restart would
// reset the chain to seq=0 + GENESIS_PREV_SHA256, which `recovery::
// verify_audit_chain` would then fail-close on as a chain break.
// ---------------------------------------------------------------------------

/// Position the writer should resume from when re-opening an existing
/// segment after a clean shutdown OR a crash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainResumeInfo {
    /// The sequence number the next written event MUST use. Equal to
    /// `last_seen_seq + 1`.
    pub next_seq: u64,
    /// `SHA-256` (hex, 64 chars) of the raw bytes of the LAST line of the
    /// segment, including its trailing `'\n'`. Used as the next event's
    /// `prev_sha256`.
    pub prev_sha256: String,
}

/// Walk an existing segment file end-to-end and return the
/// (next_seq, prev_sha256) pair needed to resume writing without breaking
/// the chain.
///
/// **Return contract:**
/// - `Ok(None)` — the file does not exist OR exists but is empty / contains
///   only blank lines. Caller should pass `starting_seq = 0` and
///   `starting_prev_sha256 = None` to `AuditWriter::open` (genesis case).
/// - `Ok(Some(info))` — the file exists and contains a valid chain. Caller
///   should pass `info.next_seq` and `Some(info.prev_sha256)` to
///   `AuditWriter::open`.
/// - `Err(...)` — the file exists but is corrupted (sequence gap,
///   prev_sha256 break, malformed JSON, or unreadable). Caller MUST treat
///   this as fail-closed (same posture as `recovery::verify_audit_chain`):
///   refuse to append to a corrupted chain.
///
/// **Performance:** O(file_size). v1 segments do not rotate, so this scan
/// runs once at boot. For a kernel that has emitted ~10 events/sec for a
/// week (~6M lines, ~3GB), the scan is dominated by sequential I/O on a
/// modern disk (~3 seconds). If segment rotation lands in v2, this will
/// only ever scan the active segment.
pub fn last_chain_state(path: &Path) -> Result<Option<ChainResumeInfo>, AuditWriterError> {
    let file = match File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(AuditWriterError::Io(e)),
    };

    let reader = BufReader::new(file);
    let mut last_seq: Option<u64> = None;
    let mut last_line_sha: Option<String> = None;
    let mut line_number: u64 = 0;

    for line in reader.lines() {
        let line = line?;
        line_number += 1;

        if line.trim().is_empty() {
            // Tolerated: trailing blank line at EOF on some text editors.
            // Does NOT advance the chain.
            continue;
        }

        // Parse just enough to extract `seq` and `prev_sha256`. We do NOT
        // round-trip through `AuditEvent` — that would couple this scan
        // to every payload schema change. The chain contract only needs
        // these two scalar fields.
        let parsed: serde_json::Value =
            serde_json::from_str(&line).map_err(|e| AuditWriterError::MalformedRecord {
                line_number,
                reason: format!("JSON parse error: {e}"),
            })?;

        let seq = parsed
            .get("seq")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| AuditWriterError::MalformedRecord {
                line_number,
                reason: "missing or non-integer `seq` field".to_owned(),
            })?;

        let prev_sha256 = parsed
            .get("prev_sha256")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AuditWriterError::MalformedRecord {
                line_number,
                reason: "missing or non-string `prev_sha256` field".to_owned(),
            })?;

        // Sequence monotonicity: every record's seq must be exactly
        // `prev_seq + 1`. The very first record (no prev) MUST have
        // seq == 0.
        let expected_seq = last_seq.map(|s| s + 1).unwrap_or(0);
        if seq != expected_seq {
            return Err(AuditWriterError::ChainSequenceGap {
                line_number,
                expected: expected_seq,
                got: seq,
            });
        }

        // Chain linkage: the record's `prev_sha256` must equal the SHA-256
        // of the previous line's bytes (with trailing newline). The first
        // record's `prev_sha256` must equal GENESIS_PREV_SHA256.
        let expected_prev = last_line_sha
            .clone()
            .unwrap_or_else(|| AuditWriter::GENESIS_PREV_SHA256.to_owned());
        if prev_sha256 != expected_prev {
            return Err(AuditWriterError::ChainPrevSha256Break {
                line_number,
                expected: expected_prev,
                got: prev_sha256.to_owned(),
            });
        }

        // Compute SHA-256 of the raw line bytes (with trailing '\n') —
        // this becomes the next record's `prev_sha256` AND the value the
        // resuming writer hands to `AuditWriter::open`.
        let mut bytes_with_newline = line.into_bytes();
        bytes_with_newline.push(b'\n');
        let this_sha = sha256_hex(&bytes_with_newline);

        last_seq = Some(seq);
        last_line_sha = Some(this_sha);
    }

    match (last_seq, last_line_sha) {
        (Some(seq), Some(sha)) => Ok(Some(ChainResumeInfo {
            next_seq: seq + 1,
            prev_sha256: sha,
        })),
        _ => Ok(None),
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

    // -----------------------------------------------------------------------
    // last_chain_state — chain-resume scanner
    //
    // These tests pin the contract that lets the kernel re-open an existing
    // segment without breaking the chain. Six cases are covered:
    //   1. Missing file       → Ok(None)
    //   2. Empty file         → Ok(None)
    //   3. Trailing blank line tolerated (does NOT advance)
    //   4. Valid chain        → Ok(Some(next_seq, prev_sha256))
    //   5. Resume + append round-trip pins chain integrity end-to-end
    //   6. Sequence gap, prev_sha256 break, malformed JSON → Err(...)
    // -----------------------------------------------------------------------

    #[test]
    fn last_chain_state_missing_file_returns_none() {
        let tmp = tempfile::tempdir().unwrap();
        let missing = tmp.path().join("does-not-exist.jsonl");

        let info = last_chain_state(&missing).expect("scan should succeed");
        assert!(info.is_none(),
            "missing file is the genesis case, not an error");
    }

    #[test]
    fn last_chain_state_empty_file_returns_none() {
        let tmp = NamedTempFile::new().unwrap();
        // File exists, length 0.

        let info = last_chain_state(tmp.path()).expect("scan should succeed");
        assert!(info.is_none(),
            "empty file is the genesis case, not an error");
    }

    #[test]
    fn last_chain_state_trailing_blank_line_is_tolerated() {
        let (mut w, tmp) = make_writer();
        w.append(
            AuditEventKind::KernelStarted {
                data_dir: "/tmp".to_owned(),
                policy_epoch: 1,
                schema_version: 1,
            },
            None, None, None,
        ).unwrap();
        drop(w); // close writer to flush

        // Append a stray blank line — common artefact of editor tampering.
        let mut f = OpenOptions::new()
            .append(true).open(tmp.path()).unwrap();
        f.write_all(b"\n").unwrap();
        drop(f);

        let info = last_chain_state(tmp.path()).expect("scan should tolerate blank lines");
        let info = info.expect("file is non-empty");
        assert_eq!(info.next_seq, 1, "blank line must NOT advance the seq counter");
    }

    #[test]
    fn last_chain_state_valid_chain_returns_resume_info() {
        let (mut w, tmp) = make_writer();
        for i in 0..3 {
            w.append(
                AuditEventKind::KernelStopped { reason: format!("r{i}") },
                None, None, None,
            ).unwrap();
        }
        drop(w);

        let info = last_chain_state(tmp.path())
            .expect("scan should succeed")
            .expect("file is non-empty");

        // Last written seq was 2 (third record); next must be 3.
        assert_eq!(info.next_seq, 3);

        // The returned prev_sha256 must equal SHA-256(last_line + '\n').
        let raw = std::fs::read_to_string(tmp.path()).unwrap();
        let last_line = raw.lines().last().unwrap();
        let expected_sha = sha256_hex(format!("{last_line}\n").as_bytes());
        assert_eq!(info.prev_sha256, expected_sha);
    }

    #[test]
    fn resume_and_append_preserves_chain_integrity_end_to_end() {
        // Phase 1: write 3 records, drop writer (simulates kernel exit).
        let (mut w, tmp) = make_writer();
        for i in 0..3 {
            w.append(
                AuditEventKind::KernelStopped { reason: format!("phase1-{i}") },
                None, None, None,
            ).unwrap();
        }
        drop(w);

        // Phase 2: resume via last_chain_state + AuditWriter::open, append 2 more.
        let resume = last_chain_state(tmp.path()).unwrap().unwrap();
        let mut w2 = AuditWriter::open(tmp.path(), resume.next_seq, Some(resume.prev_sha256)).unwrap();
        for i in 0..2 {
            w2.append(
                AuditEventKind::KernelStopped { reason: format!("phase2-{i}") },
                None, None, None,
            ).unwrap();
        }
        drop(w2);

        // Phase 3: re-scan — chain MUST be intact across the boundary.
        let final_info = last_chain_state(tmp.path())
            .expect("post-resume scan must not error")
            .expect("file is non-empty");
        assert_eq!(final_info.next_seq, 5,
            "5 records written total: 3 (phase 1) + 2 (phase 2)");

        // Spot-check: every line's seq is exactly its index, and every
        // prev_sha256 chains correctly.
        let records = read_lines(tmp.path());
        assert_eq!(records.len(), 5);
        for (i, r) in records.iter().enumerate() {
            assert_eq!(r["seq"].as_u64().unwrap(), i as u64,
                "seq monotonicity must hold across resume boundary");
        }
        let raw = std::fs::read_to_string(tmp.path()).unwrap();
        let lines: Vec<&str> = raw.lines().collect();
        for i in 1..lines.len() {
            let expected = sha256_hex(format!("{}\n", lines[i - 1]).as_bytes());
            assert_eq!(records[i]["prev_sha256"].as_str().unwrap(), expected,
                "chain link at line {i} must reference SHA-256 of previous line");
        }
    }

    #[test]
    fn last_chain_state_detects_sequence_gap() {
        let tmp = NamedTempFile::new().unwrap();
        // Hand-craft two records: seq=0, then seq=2 (gap).
        let mut f = OpenOptions::new()
            .write(true).truncate(true).open(tmp.path()).unwrap();
        let line0 = serde_json::json!({
            "seq": 0,
            "event_id": "00000000-0000-0000-0000-000000000000",
            "event_kind": "KernelStopped",
            "session_id": null,
            "task_id": null,
            "initiative_id": null,
            "payload": { "KernelStopped": { "reason": "x" } },
            "emitted_at": 0,
            "prev_sha256": AuditWriter::GENESIS_PREV_SHA256,
        }).to_string();
        let line0_with_nl = format!("{line0}\n");
        f.write_all(line0_with_nl.as_bytes()).unwrap();

        let line2 = serde_json::json!({
            "seq": 2, // <-- skipped seq=1
            "event_id": "00000000-0000-0000-0000-000000000000",
            "event_kind": "KernelStopped",
            "session_id": null,
            "task_id": null,
            "initiative_id": null,
            "payload": { "KernelStopped": { "reason": "y" } },
            "emitted_at": 0,
            "prev_sha256": sha256_hex(line0_with_nl.as_bytes()),
        }).to_string();
        f.write_all(line2.as_bytes()).unwrap();
        f.write_all(b"\n").unwrap();
        drop(f);

        let err = last_chain_state(tmp.path()).expect_err("gap must fail-close");
        match err {
            AuditWriterError::ChainSequenceGap { line_number, expected, got } => {
                assert_eq!(line_number, 2);
                assert_eq!(expected, 1);
                assert_eq!(got, 2);
            }
            other => panic!("expected ChainSequenceGap, got {other:?}"),
        }
    }

    #[test]
    fn last_chain_state_detects_prev_sha256_break() {
        let tmp = NamedTempFile::new().unwrap();
        let mut f = OpenOptions::new()
            .write(true).truncate(true).open(tmp.path()).unwrap();
        let line0 = serde_json::json!({
            "seq": 0,
            "event_id": "00000000-0000-0000-0000-000000000000",
            "event_kind": "KernelStopped",
            "session_id": null,
            "task_id": null,
            "initiative_id": null,
            "payload": { "KernelStopped": { "reason": "x" } },
            "emitted_at": 0,
            "prev_sha256": AuditWriter::GENESIS_PREV_SHA256,
        }).to_string();
        f.write_all(format!("{line0}\n").as_bytes()).unwrap();

        // Second record with a deliberately wrong prev_sha256.
        let line1 = serde_json::json!({
            "seq": 1,
            "event_id": "00000000-0000-0000-0000-000000000000",
            "event_kind": "KernelStopped",
            "session_id": null,
            "task_id": null,
            "initiative_id": null,
            "payload": { "KernelStopped": { "reason": "y" } },
            "emitted_at": 0,
            "prev_sha256": "deadbeef".repeat(8),
        }).to_string();
        f.write_all(format!("{line1}\n").as_bytes()).unwrap();
        drop(f);

        let err = last_chain_state(tmp.path()).expect_err("prev_sha256 mismatch must fail-close");
        match err {
            AuditWriterError::ChainPrevSha256Break { line_number, .. } => {
                assert_eq!(line_number, 2);
            }
            other => panic!("expected ChainPrevSha256Break, got {other:?}"),
        }
    }

    #[test]
    fn last_chain_state_detects_malformed_json() {
        let tmp = NamedTempFile::new().unwrap();
        let mut f = OpenOptions::new()
            .write(true).truncate(true).open(tmp.path()).unwrap();
        f.write_all(b"this is not json\n").unwrap();
        drop(f);

        let err = last_chain_state(tmp.path()).expect_err("malformed line must fail-close");
        assert!(matches!(err, AuditWriterError::MalformedRecord { line_number: 1, .. }));
    }

    #[test]
    fn last_chain_state_detects_first_record_without_genesis_prev() {
        let tmp = NamedTempFile::new().unwrap();
        let mut f = OpenOptions::new()
            .write(true).truncate(true).open(tmp.path()).unwrap();
        // First record with seq=0 but a non-genesis prev_sha256 — also a chain break.
        let line = serde_json::json!({
            "seq": 0,
            "event_id": "00000000-0000-0000-0000-000000000000",
            "event_kind": "KernelStopped",
            "session_id": null,
            "task_id": null,
            "initiative_id": null,
            "payload": { "KernelStopped": { "reason": "x" } },
            "emitted_at": 0,
            "prev_sha256": "abcdef".repeat(10) + "abcd",
        }).to_string();
        f.write_all(format!("{line}\n").as_bytes()).unwrap();
        drop(f);

        let err = last_chain_state(tmp.path()).expect_err("non-genesis first prev must fail-close");
        assert!(matches!(err, AuditWriterError::ChainPrevSha256Break { line_number: 1, .. }));
    }
}

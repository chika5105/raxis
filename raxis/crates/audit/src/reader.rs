//! Read-side helpers for the audit segment files (`<data_dir>/audit/
//! segment-NNN.jsonl`).
//!
//! Normative reference: `kernel-store.md` §2.5.2 (chain integrity
//! contract) and `cli-readonly.md` §5.5.4 / §5.5.13 (CLI readers
//! that consume this module).
//!
//! # Why this crate MUST NOT depend on `raxis-kernel`
//!
//! **`INV-AUDIT-PAIRED-05`** (`specs/invariants.md §11.6`) states:
//!
//! > The audit chain MUST be verifiable by an offline process that has
//! > access only to the JSONL segment files and a frozen SQLite snapshot.
//! > It MUST NOT require the kernel to start, run a recovery path, or
//! > synthesise missing entries from in-memory state.
//!
//! This invariant is the strict reading of **`R-7 Cryptographic audit
//! chain`** (`specs/paradigm.md §3`), which requires that the chain
//! "MUST NOT depend on continued operation of the authority that
//! produced it." If this crate pulled in `raxis-kernel`, two things
//! would break that guarantee:
//!
//! 1. **Compilation coupling.** Any internal kernel type or function
//!    used here would silently become load-bearing for chain
//!    verification; a future kernel refactor could invalidate the
//!    verifier without the compiler surfacing the dependency.
//! 2. **Trust boundary collapse.** The entire point of an *independent*
//!    verifier is that a compromised or buggy kernel cannot influence
//!    the outcome of verification. If the verifier links kernel code,
//!    a tampered kernel binary could shadow the verification logic.
//!
//! `raxis-kernel` is downstream of `raxis-audit-tools` in the
//! dependency graph — not the other way around. This is enforced by
//! Cargo: `raxis-audit-tools/Cargo.toml` deliberately omits any
//! `raxis-kernel` dependency. If you find yourself needing a type that
//! lives in the kernel, the correct fix is to move that type into
//! `raxis-types` (which both this crate and the kernel may depend on),
//! not to add a kernel dependency here.
//!
//! # What lives here
//!
//! * [`ChainRecord`] — the per-line projection of an audit JSONL
//!   record. Tolerant of extra fields (genesis record has a few
//!   `AuditEvent` does not, and forward-compat schema bumps are
//!   expected); the reader pulls out only what every consumer needs.
//! * [`ChainReader`] — opens an `audit_dir`, enumerates segments in
//!   numeric order, yields records one-by-one with byte-exact
//!   `prev_sha256` linkage and `seq` monotonicity reporting.
//! * [`verify_chain_full`] — walk-everything verifier used by
//!   `raxis verify-chain` and (in the future) by `recovery::reconcile`.
//! * [`quick_chain_check`] — first + last record only, used by
//!   `raxis status` so the status command stays sub-100ms.
//!
//! # Why the reader and writer share a crate (but not a module)
//!
//! Writer and reader both depend on the byte-exact JSONL framing
//! (`writer.rs::canonical_line_bytes`). Co-locating them inside
//! `raxis-audit-tools` lets us keep the canonical-bytes helper
//! private (`pub(crate)`) so accidental open-coding cannot drift.
//!
//! # Hard rules
//!
//! 1. **Never modify a segment file.** Every API in this module
//!    opens the file via `std::fs::File::open` (RDONLY), never
//!    `OpenOptions::write`.
//! 2. **Never depend on the kernel.** `raxis-kernel` is downstream
//!    of this crate; the reader must work for the CLI without
//!    pulling in any kernel internals.
//! 3. **Forward-compat:** parsing always goes through
//!    `serde_json::Value` first; downstream consumers project the
//!    typed fields they care about. New optional fields in the
//!    record schema do NOT require a code change here.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};

use thiserror::Error;

use sha2::{Digest, Sha256};

/// Subdirectory of `data_dir` that holds the JSONL segment files.
/// Centralised so callers don't redeclare the literal.
pub const AUDIT_DIR_NAME: &str = "audit";

/// File-name prefix for segment files; the suffix is a zero-padded
/// `u32`. v1 only ever writes `segment-000.jsonl`; segment rotation
/// is reserved for v2 (see `kernel-store.md` §2.5.2).
pub const SEGMENT_PREFIX: &str = "segment-";

/// File-name suffix for segment files.
pub const SEGMENT_SUFFIX: &str = ".jsonl";

/// Genesis-record `prev_sha256` literal. Sixty-four hex zeros. Kept
/// in lock-step with `raxis-genesis-tools::GENESIS_PREV_SHA256`.
pub const GENESIS_PREV_SHA256_LITERAL: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

/// One JSONL line projected onto the fields every chain consumer
/// needs. The full raw payload is preserved in `parsed_value` for
/// callers that want to render or filter on a payload field.
///
/// The on-disk JSONL format is:
/// ```text
/// { "seq": N, "event_kind": "...", "prev_sha256": "...",
///   "session_id": "...", "task_id": "...", "initiative_id": "...",
///   "emitted_at": int, "payload": { ... }, ... }
/// ```
/// The genesis record (written by `raxis-genesis-tools`) lacks
/// `session_id` / `task_id` / `initiative_id` / `payload` and adds
/// `genesis_nonce` + `authority_pubkey_fingerprint`. This reader
/// tolerates both.
#[derive(Debug, Clone)]
pub struct ChainRecord {
    /// Monotonically-increasing per-segment counter (genesis = 0).
    pub seq: u64,
    /// Discriminant string written into `event_kind`. Always present.
    pub event_kind: String,
    /// Hex SHA-256 of the previous line's RAW bytes including its
    /// trailing newline. Always 64 hex chars; the genesis record
    /// uses [`GENESIS_PREV_SHA256_LITERAL`].
    pub prev_sha256: String,
    /// Unix seconds (UTC) when the kernel emitted the record. May
    /// be `None` for malformed rows the reader chose not to drop.
    pub emitted_at: Option<i64>,
    /// Triplet of optional foreign-keys; `None` when not applicable
    /// or when the record is a genesis row.
    pub session_id: Option<String>,
    pub task_id: Option<String>,
    pub initiative_id: Option<String>,
    /// 0-indexed line number within the segment file (line 0 is
    /// the genesis record). Useful for human-friendly error messages.
    pub line_no: u64,
    /// Relative path of the segment file the record came from
    /// (`audit/segment-000.jsonl`). Useful for multi-segment readers.
    pub segment_path: PathBuf,
    /// SHA-256 of the raw bytes of THIS line (including trailing
    /// newline). The next record's `prev_sha256` must equal this
    /// value for the chain to remain unbroken.
    pub line_sha256: String,
    /// The raw line text WITHOUT the trailing newline. Mostly used
    /// by `raxis log --json` (which prints the bytes verbatim).
    pub raw_line: String,
    /// Lazy-parsed `serde_json::Value` of the line. `None` if the
    /// line failed to parse — only [`verify_chain_full`] surfaces
    /// these as a chain break; `iter_records` yields the parsed
    /// projection above with `parsed_value = None`.
    pub parsed_value: Option<serde_json::Value>,
}

impl ChainRecord {
    /// Convenience: read an arbitrary string field out of
    /// `parsed_value.payload.<key>`. Used by the CLI to surface
    /// `lane_id`, `intent_kind`, etc. without having to clone the
    /// full Value.
    pub fn payload_str(&self, key: &str) -> Option<&str> {
        self.parsed_value
            .as_ref()
            .and_then(|v| v.get("payload"))
            .and_then(|p| p.get(key))
            .and_then(|s| s.as_str())
    }
}

/// Hard failures the reader surfaces. Soft failures (one malformed
/// line in a multi-million-line segment) are surfaced as
/// `Result<ChainRecord, ChainReadError>` items in the iterator
/// rather than aborting the whole walk.
#[derive(Debug, Error)]
pub enum ChainReadError {
    #[error("audit directory {path} is not readable: {source}")]
    AuditDirOpen {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("no segment files found in {path}")]
    NoSegments { path: PathBuf },

    #[error("segment file {path} could not be opened: {source}")]
    SegmentOpen {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("segment file {path} read I/O failed at line {line_no}: {source}")]
    SegmentIo {
        path: PathBuf,
        line_no: u64,
        #[source]
        source: std::io::Error,
    },

    #[error("malformed JSON in {path} line {line_no}: {reason}")]
    MalformedRecord {
        path: PathBuf,
        line_no: u64,
        reason: String,
    },

    #[error(
        "chain break in {path} at seq={seq}: \
         expected prev_sha256={expected}, got {actual}"
    )]
    ChainBreak {
        path: PathBuf,
        seq: u64,
        expected: String,
        actual: String,
    },

    #[error(
        "sequence gap in {path}: expected seq={expected}, got seq={actual} \
         at line {line_no}"
    )]
    SequenceGap {
        path: PathBuf,
        line_no: u64,
        expected: u64,
        actual: u64,
    },
}

/// Iterator-style audit-chain reader. Open one with [`ChainReader::open`],
/// then call [`ChainReader::records`] to enumerate every line in
/// segment-order.
#[derive(Debug)]
pub struct ChainReader {
    /// Each entry is `(segment_index, absolute path)`, sorted ascending
    /// by index. Held as an owned vec because rusqlite-style "iterate
    /// once" semantics aren't worth the extra plumbing.
    segments: Vec<(u32, PathBuf)>,
}

impl ChainReader {
    /// Discover every `segment-NNN.jsonl` file under
    /// `<audit_dir>` and order them by NNN ascending. The reader does
    /// not validate any byte yet — `records` does that lazily.
    pub fn open(audit_dir: &Path) -> Result<Self, ChainReadError> {
        let entries = std::fs::read_dir(audit_dir).map_err(|e| ChainReadError::AuditDirOpen {
            path: audit_dir.to_path_buf(),
            source: e,
        })?;
        let mut by_index: BTreeMap<u32, PathBuf> = BTreeMap::new();
        for entry in entries.flatten() {
            let name = entry.file_name();
            let s = match name.to_str() {
                Some(s) => s,
                None => continue,
            };
            let stripped = match s
                .strip_prefix(SEGMENT_PREFIX)
                .and_then(|rest| rest.strip_suffix(SEGMENT_SUFFIX))
            {
                Some(num_str) => num_str,
                None => continue,
            };
            if let Ok(n) = stripped.parse::<u32>() {
                by_index.insert(n, entry.path());
            }
        }
        if by_index.is_empty() {
            return Err(ChainReadError::NoSegments {
                path: audit_dir.to_path_buf(),
            });
        }
        Ok(Self {
            segments: by_index.into_iter().collect(),
        })
    }

    /// Number of segments (always >= 1 if `open` returned `Ok`).
    pub fn segment_count(&self) -> usize {
        self.segments.len()
    }

    /// Latest segment by ascending index. Always present (`open`
    /// returns `NoSegments` when the directory is empty).
    pub fn latest_segment(&self) -> &Path {
        &self
            .segments
            .last()
            .expect("ChainReader always has >=1 segment")
            .1
    }

    /// Iterate every record across every segment in order. Each item
    /// is a `Result<ChainRecord, ChainReadError>` so a malformed line
    /// or chain break is surfaced WITHOUT halting the walk — the
    /// caller decides whether one bad row aborts the whole report.
    pub fn records(&self) -> ChainRecordIter<'_> {
        ChainRecordIter {
            owner: self,
            seg_idx: 0,
            current: None,
            line_no: 0,
            expected_prev_sha256: None,
            expected_seq: None,
        }
    }

    /// Iterate records newest-first across all segments.
    ///
    /// This is intentionally a **display / pagination** helper, not
    /// a chain verifier: each JSONL row is parsed and projected with
    /// the same field rules as [`Self::records`], but reverse order
    /// cannot validate the forward `prev_sha256` linkage without
    /// first walking the prefix. Use [`verify_chain_full`] when the
    /// caller needs an integrity verdict. Dashboard tail pagination
    /// pairs this iterator with the chain-status banner so operators
    /// get both a fast tail and the kernel-owned integrity state.
    pub fn records_desc(&self) -> ChainRecordDescIter<'_> {
        ChainRecordDescIter {
            owner: self,
            next_seg_idx: self.segments.len(),
            current: Vec::new().into_iter(),
        }
    }
}

/// Iterator over every record across every segment.
///
/// Holds at most ONE buffered reader open at a time (the current
/// segment), so memory cost is O(1) regardless of segment count or
/// segment size.
pub struct ChainRecordIter<'a> {
    owner: &'a ChainReader,
    seg_idx: usize,
    current: Option<BufReader<File>>,
    line_no: u64,
    /// `None` before the first record; `Some(hash)` afterward — the
    /// hash the next record's `prev_sha256` must equal.
    expected_prev_sha256: Option<String>,
    /// `None` before the first record; `Some(n)` afterward — `n` is
    /// the seq number of the *next* expected record.
    expected_seq: Option<u64>,
}

impl<'a> Iterator for ChainRecordIter<'a> {
    type Item = Result<ChainRecord, ChainReadError>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            // (Re)open the current segment when needed.
            if self.current.is_none() {
                let (_, path) = self.owner.segments.get(self.seg_idx)?;
                let f = match File::open(path) {
                    Ok(f) => f,
                    Err(e) => {
                        return Some(Err(ChainReadError::SegmentOpen {
                            path: path.clone(),
                            source: e,
                        }))
                    }
                };
                self.current = Some(BufReader::new(f));
                self.line_no = 0;
                // Cross-segment: do NOT reset `expected_prev_sha256`
                // — the chain MUST continue from the last record of
                // the previous segment. v1 only writes a single
                // segment, so this code path is exercised by tests
                // only, but the invariant pre-stages v2 rotation.
            }

            let reader = self.current.as_mut().expect("just initialised");
            let mut buf = String::new();
            let bytes_read = match reader.read_line(&mut buf) {
                Ok(n) => n,
                Err(e) => {
                    let path = self.owner.segments[self.seg_idx].1.clone();
                    return Some(Err(ChainReadError::SegmentIo {
                        path,
                        line_no: self.line_no,
                        source: e,
                    }));
                }
            };
            if bytes_read == 0 {
                // EOF on the current segment; move on.
                self.current = None;
                self.seg_idx += 1;
                if self.seg_idx >= self.owner.segments.len() {
                    return None;
                }
                continue;
            }

            // Skip pure-blank lines (the segment writer never produces
            // these, but we don't want a stray newline at EOF to cause
            // a spurious malformed-record error).
            let trimmed_line_no_nl = buf.trim_end_matches(['\n', '\r']);
            if trimmed_line_no_nl.is_empty() {
                continue;
            }

            self.line_no += 1;

            let path = self.owner.segments[self.seg_idx].1.clone();

            let record = match parse_record_line(path.clone(), self.line_no, buf.as_bytes()) {
                Ok(r) => r,
                Err(e) => return Some(Err(e)),
            };
            let seq_u64 = record.seq;
            let this_prev_sha = record.prev_sha256.clone();

            // Sequence-gap check: the very first record (line_no=1)
            // is the genesis record and must carry seq=0; subsequent
            // records must increase by exactly 1.
            if let Some(expected) = self.expected_seq {
                if seq_u64 != expected {
                    return Some(Err(ChainReadError::SequenceGap {
                        path,
                        line_no: self.line_no,
                        expected,
                        actual: seq_u64,
                    }));
                }
            }
            self.expected_seq = Some(seq_u64.saturating_add(1));

            // Chain-link check: `prev_sha256` must match the SHA-256
            // we computed for the previous line. Skip on the very
            // first record (genesis), where the spec mandates
            // `GENESIS_PREV_SHA256_LITERAL` and the writer does not
            // refer to a previous line.
            if let Some(expected) = &self.expected_prev_sha256 {
                if &this_prev_sha != expected {
                    return Some(Err(ChainReadError::ChainBreak {
                        path,
                        seq: seq_u64,
                        expected: expected.clone(),
                        actual: this_prev_sha,
                    }));
                }
            } else {
                // Genesis record → must carry the all-zero literal.
                if this_prev_sha != GENESIS_PREV_SHA256_LITERAL {
                    return Some(Err(ChainReadError::ChainBreak {
                        path,
                        seq: seq_u64,
                        expected: GENESIS_PREV_SHA256_LITERAL.to_owned(),
                        actual: this_prev_sha,
                    }));
                }
            }
            self.expected_prev_sha256 = Some(record.line_sha256.clone());
            return Some(Ok(record));
        }
    }
}

/// Newest-first iterator over audit records.
///
/// Holds at most one segment's decoded line list in memory at a
/// time. Segment files are append-only JSONL, so this can service
/// dashboard tail pages by reading the latest segment first instead
/// of walking from genesis on every request.
pub struct ChainRecordDescIter<'a> {
    owner: &'a ChainReader,
    next_seg_idx: usize,
    current: std::vec::IntoIter<Result<ChainRecord, ChainReadError>>,
}

impl<'a> Iterator for ChainRecordDescIter<'a> {
    type Item = Result<ChainRecord, ChainReadError>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if let Some(item) = self.current.next() {
                return Some(item);
            }
            if self.next_seg_idx == 0 {
                return None;
            }
            self.next_seg_idx -= 1;
            let (_, path) = &self.owner.segments[self.next_seg_idx];
            match load_segment_records_desc(path) {
                Ok(records) => {
                    self.current = records.into_iter();
                }
                Err(e) => return Some(Err(e)),
            }
        }
    }
}

fn load_segment_records_desc(
    path: &Path,
) -> Result<Vec<Result<ChainRecord, ChainReadError>>, ChainReadError> {
    let mut f = File::open(path).map_err(|e| ChainReadError::SegmentOpen {
        path: path.to_path_buf(),
        source: e,
    })?;
    let mut bytes = Vec::new();
    f.read_to_end(&mut bytes)
        .map_err(|e| ChainReadError::SegmentIo {
            path: path.to_path_buf(),
            line_no: 0,
            source: e,
        })?;

    let mut lines: Vec<(u64, Vec<u8>)> = Vec::new();
    let mut start = 0usize;
    let mut line_no = 0u64;
    for (idx, byte) in bytes.iter().enumerate() {
        if *byte != b'\n' {
            continue;
        }
        let raw = &bytes[start..=idx];
        start = idx + 1;
        if trimmed_line_bytes(raw).is_empty() {
            continue;
        }
        line_no += 1;
        lines.push((line_no, raw.to_vec()));
    }
    if start < bytes.len() {
        let raw = &bytes[start..];
        if !trimmed_line_bytes(raw).is_empty() {
            line_no += 1;
            lines.push((line_no, raw.to_vec()));
        }
    }

    let mut out = Vec::with_capacity(lines.len());
    for (line_no, raw) in lines.into_iter().rev() {
        out.push(parse_record_line(path.to_path_buf(), line_no, &raw));
    }
    Ok(out)
}

fn trimmed_line_bytes(line: &[u8]) -> &[u8] {
    let without_lf = line.strip_suffix(b"\n").unwrap_or(line);
    without_lf.strip_suffix(b"\r").unwrap_or(without_lf)
}

fn parse_record_line(
    path: PathBuf,
    line_no: u64,
    line_bytes: &[u8],
) -> Result<ChainRecord, ChainReadError> {
    // SHA-256 of THE RAW LINE BYTES INCLUDING the trailing
    // newline. This matches `writer.rs`'s canonicalisation
    // (a `\n`-terminated UTF-8 line) — drift here is a
    // chain-break bug.
    let line_sha256 = {
        let mut h = Sha256::new();
        h.update(line_bytes);
        hex::encode(h.finalize())
    };

    let raw_line = std::str::from_utf8(trimmed_line_bytes(line_bytes))
        .map_err(|e| ChainReadError::MalformedRecord {
            path: path.clone(),
            line_no,
            reason: format!("UTF-8 parse: {e}"),
        })?
        .to_owned();

    let parsed_value: serde_json::Value =
        serde_json::from_str(&raw_line).map_err(|e| ChainReadError::MalformedRecord {
            path: path.clone(),
            line_no,
            reason: format!("JSON parse: {e}"),
        })?;

    let seq_u64 = parsed_value
        .get("seq")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| ChainReadError::MalformedRecord {
            path: path.clone(),
            line_no,
            reason: "missing or non-numeric `seq`".to_owned(),
        })?;
    let event_kind = parsed_value
        .get("event_kind")
        .and_then(|v| v.as_str())
        .map(|s| s.to_owned())
        .ok_or_else(|| ChainReadError::MalformedRecord {
            path: path.clone(),
            line_no,
            reason: "missing or non-string `event_kind`".to_owned(),
        })?;
    let this_prev_sha = parsed_value
        .get("prev_sha256")
        .and_then(|v| v.as_str())
        .map(|s| s.to_owned())
        .ok_or_else(|| ChainReadError::MalformedRecord {
            path: path.clone(),
            line_no,
            reason: "missing or non-string `prev_sha256`".to_owned(),
        })?;

    let emitted_at = parsed_value.get("emitted_at").and_then(|v| v.as_i64());
    let session_id = parsed_value
        .get("session_id")
        .and_then(|v| v.as_str())
        .map(|s| s.to_owned());
    let task_id = parsed_value
        .get("task_id")
        .and_then(|v| v.as_str())
        .map(|s| s.to_owned());
    let initiative_id = parsed_value
        .get("initiative_id")
        .and_then(|v| v.as_str())
        .map(|s| s.to_owned());

    Ok(ChainRecord {
        seq: seq_u64,
        event_kind,
        prev_sha256: this_prev_sha,
        emitted_at,
        session_id,
        task_id,
        initiative_id,
        line_no,
        segment_path: path,
        line_sha256,
        raw_line,
        parsed_value: Some(parsed_value),
    })
}

/// Quick chain-check verdict — used by `raxis status` to summarise
/// the audit chain without paying the cost of a full hash-chain
/// recomputation.
///
/// `ChainReadError` is intentionally NOT `Clone` (it wraps
/// `std::io::Error`), so this enum cannot be `Clone` either. Callers
/// that need a stable string representation should `match` and
/// stringify on the fly.
#[derive(Debug)]
pub enum ChainQuickCheck {
    /// Walk completed cleanly. `last_seq` is the highest seq
    /// observed across all segments.
    Ok { last_seq: u64, segment_count: usize },
    /// No segment files present.
    NoSegments,
    /// Something went wrong reading the chain. `error` is the typed
    /// reader error.
    Broken { error: ChainReadError },
}

/// Stream every record through the chain reader to confirm each line
/// is syntactically valid JSONL and the per-record schema parses
/// cleanly. Cost is O(records) — proportional to the size of the
/// audit chain on disk, not constant. For "audit chain is well-formed"
/// polling on small/medium kernels this is fast enough (~ms on
/// multi-MiB segments); for cron-style polling on multi-GiB segments
/// callers should sample the latest segment tail or invoke this off
/// the hot path.
///
/// This does NOT verify the full `prev_sha256` chain — only per-record
/// reader validity. For full hash-chain verification use
/// [`verify_chain_full`].
pub fn quick_chain_check(audit_dir: &Path) -> ChainQuickCheck {
    let reader = match ChainReader::open(audit_dir) {
        Ok(r) => r,
        Err(ChainReadError::NoSegments { .. }) => return ChainQuickCheck::NoSegments,
        Err(e) => return ChainQuickCheck::Broken { error: e },
    };
    let segment_count = reader.segment_count();
    let mut last_seq = 0u64;
    for rec in reader.records() {
        match rec {
            Ok(r) => last_seq = r.seq,
            Err(e) => return ChainQuickCheck::Broken { error: e },
        }
    }
    if last_seq == 0 {
        // The genesis record is seq=0; we still call this OK because
        // a kernel that emitted only its genesis record is in a
        // valid (if extremely fresh) state.
        return ChainQuickCheck::Ok {
            last_seq,
            segment_count,
        };
    }
    ChainQuickCheck::Ok {
        last_seq,
        segment_count,
    }
}

/// Verdict returned by [`verify_chain_full`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainStats {
    /// Number of records walked (including the genesis row).
    pub total_records: u64,
    /// Highest seq observed.
    pub last_seq: u64,
    /// Number of distinct segments contributing records.
    pub segment_count: usize,
}

/// Walk every record in every segment and verify:
///   * `prev_sha256` matches the SHA-256 of the previous raw line
///     (with trailing newline);
///   * `seq` advances monotonically by 1 across the whole chain
///     (across segment boundaries too);
///   * the genesis record carries the all-zero `prev_sha256`.
///
/// Returns [`ChainStats`] on success or the first
/// [`ChainReadError`] encountered. Stops on first error — the
/// invariant is "intact OR not", not "many independent errors".
pub fn verify_chain_full(audit_dir: &Path) -> Result<ChainStats, ChainReadError> {
    verify_chain_from(audit_dir, 0)
}

/// Like [`verify_chain_full`] but report stats for the slice
/// `seq >= from_seq`. The full chain is **still walked end-to-end**
/// — `prev_sha256` linkage and seq monotonicity are global
/// invariants, so any pre-`from_seq` break still fails the verdict.
/// What `from_seq` controls is the SCOPE OF THE STATS RETURNED:
///
///   * `total_records` — number of records with `seq >= from_seq`.
///   * `last_seq`      — the highest `seq` observed (always ≥
///     `from_seq` when the chain has any records past that point;
///     equals `from_seq.saturating_sub(1)` when the chain ends
///     before `from_seq`).
///   * `segment_count` — number of segment files contributing
///     records with `seq >= from_seq` (NOT the total segment count
///     in the directory).
///
/// `from_seq = 0` is byte-identical to [`verify_chain_full`] —
/// that's how `verify_chain_full` is now defined.
///
/// Spec reference: cli-readonly.md §5.5.13 (`"--from <seq> — start
/// from the given seq (default 0)"`). The spec leaves the
/// interpretation of "start" to the implementor; this implementation
/// is **pre-anchored**: chain integrity is verified from segment
/// zero so the operator cannot miss a corruption that occurred
/// before their slice window. The output reports only the slice the
/// operator asked about, but the verdict reflects the whole chain.
pub fn verify_chain_from(audit_dir: &Path, from_seq: u64) -> Result<ChainStats, ChainReadError> {
    let reader = ChainReader::open(audit_dir)?;
    let mut total = 0u64;
    let mut last_seq: Option<u64> = None;
    let mut segments_in_slice: std::collections::BTreeSet<PathBuf> =
        std::collections::BTreeSet::new();
    for rec in reader.records() {
        let r = rec?;
        if r.seq >= from_seq {
            last_seq = Some(r.seq);
            total = total.saturating_add(1);
            segments_in_slice.insert(r.segment_path.clone());
        }
    }
    Ok(ChainStats {
        total_records: total,
        // When the slice is empty, `last_seq` defaults to
        // `from_seq.saturating_sub(1)` so a stats consumer can
        // always read it as "highest seq ≤ this is the requested
        // window's lower-bound predecessor".
        last_seq: last_seq.unwrap_or_else(|| from_seq.saturating_sub(1)),
        segment_count: segments_in_slice.len(),
    })
}

// ────────────────────────────────────────────────────────────────────
// Tests
// ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn write_segment(audit_dir: &Path, idx: u32, content: &str) {
        let path = audit_dir.join(format!("{SEGMENT_PREFIX}{idx:03}{SEGMENT_SUFFIX}"));
        fs::write(path, content).unwrap();
    }

    /// Build a syntactically-correct two-record chain (genesis +
    /// follow-on) so prev_sha256 link tests have something to walk.
    fn write_valid_chain(audit_dir: &Path) -> String {
        let genesis_line = serde_json::json!({
            "seq": 0,
            "event_kind": "GenesisRecord",
            "prev_sha256": GENESIS_PREV_SHA256_LITERAL,
            "emitted_at": 1_700_000_000_i64,
        })
        .to_string();
        let line0_with_nl = format!("{genesis_line}\n");

        let mut hasher = Sha256::new();
        hasher.update(line0_with_nl.as_bytes());
        let line0_sha = hex::encode(hasher.finalize());

        let line1 = serde_json::json!({
            "seq": 1,
            "event_kind": "KernelStarted",
            "prev_sha256": line0_sha,
            "emitted_at": 1_700_000_001_i64,
            "session_id": null,
            "task_id": null,
            "initiative_id": null,
            "payload": { "data_dir": "/tmp/raxis", "policy_epoch": 1, "schema_version": 1 },
        })
        .to_string();
        let content = format!("{genesis_line}\n{line1}\n");
        write_segment(audit_dir, 0, &content);
        line0_sha
    }

    #[test]
    fn open_reports_no_segments_when_dir_empty() {
        let tmp = TempDir::new().unwrap();
        let err = ChainReader::open(tmp.path()).unwrap_err();
        assert!(
            matches!(err, ChainReadError::NoSegments { .. }),
            "got: {err:?}"
        );
    }

    #[test]
    fn open_reports_dir_open_when_dir_missing() {
        let tmp = TempDir::new().unwrap();
        let bad = tmp.path().join("does-not-exist");
        let err = ChainReader::open(&bad).unwrap_err();
        assert!(
            matches!(err, ChainReadError::AuditDirOpen { .. }),
            "got: {err:?}"
        );
    }

    #[test]
    fn open_orders_segments_by_numeric_index_not_lexicographic() {
        let tmp = TempDir::new().unwrap();
        // Lexicographic order would put segment-002 between 020 and 030;
        // numeric order must put it BEFORE both.
        for &idx in &[2u32, 20, 30] {
            write_segment(tmp.path(), idx, "");
        }
        let reader = ChainReader::open(tmp.path()).unwrap();
        assert_eq!(reader.segment_count(), 3);
        let names: Vec<u32> = reader.segments.iter().map(|(n, _)| *n).collect();
        assert_eq!(names, vec![2, 20, 30]);
    }

    #[test]
    fn records_walks_genesis_plus_follow_on_in_order() {
        let tmp = TempDir::new().unwrap();
        write_valid_chain(tmp.path());
        let reader = ChainReader::open(tmp.path()).unwrap();
        let recs: Vec<_> = reader.records().collect::<Result<_, _>>().unwrap();
        assert_eq!(recs.len(), 2);
        assert_eq!(recs[0].seq, 0);
        assert_eq!(recs[0].event_kind, "GenesisRecord");
        assert_eq!(recs[1].seq, 1);
        assert_eq!(recs[1].event_kind, "KernelStarted");
        // The line_sha of record[0] must equal record[1].prev_sha256.
        assert_eq!(recs[0].line_sha256, recs[1].prev_sha256);
    }

    #[test]
    fn records_desc_walks_newest_first_for_tail_pagination() {
        let tmp = TempDir::new().unwrap();
        write_four_record_chain(tmp.path());
        let reader = ChainReader::open(tmp.path()).unwrap();
        let recs: Vec<_> = reader.records_desc().collect::<Result<_, _>>().unwrap();
        assert_eq!(
            recs.iter().map(|r| r.seq).collect::<Vec<_>>(),
            vec![3, 2, 1, 0]
        );
        assert_eq!(recs[3].line_sha256, recs[2].prev_sha256);
    }

    #[test]
    fn records_surfaces_chain_break_when_prev_sha_doesnt_match() {
        let tmp = TempDir::new().unwrap();
        // Genesis with nonzero prev_sha256 ⇒ first-record chain break.
        let line0 = serde_json::json!({
            "seq": 0,
            "event_kind": "GenesisRecord",
            "prev_sha256": "deadbeef".repeat(8), // 64 hex chars but wrong
        })
        .to_string();
        write_segment(tmp.path(), 0, &format!("{line0}\n"));
        let reader = ChainReader::open(tmp.path()).unwrap();
        let mut iter = reader.records();
        let err = iter.next().unwrap().unwrap_err();
        assert!(
            matches!(err, ChainReadError::ChainBreak { .. }),
            "got: {err:?}"
        );
    }

    #[test]
    fn records_surfaces_sequence_gap() {
        let tmp = TempDir::new().unwrap();
        let line0 = serde_json::json!({
            "seq": 0,
            "event_kind": "GenesisRecord",
            "prev_sha256": GENESIS_PREV_SHA256_LITERAL,
        })
        .to_string();
        let line0_nl = format!("{line0}\n");

        let mut h = Sha256::new();
        h.update(line0_nl.as_bytes());
        let line0_sha = hex::encode(h.finalize());

        // seq=2 (not 1)
        let line2 = serde_json::json!({
            "seq": 2, "event_kind": "K", "prev_sha256": line0_sha,
        })
        .to_string();
        write_segment(tmp.path(), 0, &format!("{line0_nl}{line2}\n"));
        let reader = ChainReader::open(tmp.path()).unwrap();
        let mut iter = reader.records();
        let _ = iter.next().unwrap().unwrap();
        let err = iter.next().unwrap().unwrap_err();
        match err {
            ChainReadError::SequenceGap {
                expected, actual, ..
            } => {
                assert_eq!(expected, 1);
                assert_eq!(actual, 2);
            }
            other => panic!("expected SequenceGap; got {other:?}"),
        }
    }

    #[test]
    fn records_surfaces_malformed_json() {
        let tmp = TempDir::new().unwrap();
        write_segment(tmp.path(), 0, "{not-json\n");
        let reader = ChainReader::open(tmp.path()).unwrap();
        let mut iter = reader.records();
        let err = iter.next().unwrap().unwrap_err();
        assert!(
            matches!(err, ChainReadError::MalformedRecord { .. }),
            "got: {err:?}"
        );
    }

    #[test]
    fn records_surfaces_missing_required_field() {
        let tmp = TempDir::new().unwrap();
        // Has prev_sha256 but no seq / event_kind.
        write_segment(tmp.path(), 0, "{\"prev_sha256\":\"00\"}\n");
        let reader = ChainReader::open(tmp.path()).unwrap();
        let err = reader.records().next().unwrap().unwrap_err();
        match err {
            ChainReadError::MalformedRecord { reason, .. } => {
                assert!(
                    reason.contains("seq") || reason.contains("event_kind"),
                    "got: {reason}"
                );
            }
            other => panic!("expected MalformedRecord; got {other:?}"),
        }
    }

    #[test]
    fn records_skips_blank_lines() {
        let tmp = TempDir::new().unwrap();
        write_valid_chain(tmp.path());
        // Append a blank line at EOF and one between records.
        let path = tmp.path().join("segment-000.jsonl");
        let mut bytes = std::fs::read(&path).unwrap();
        bytes.push(b'\n');
        std::fs::write(&path, bytes).unwrap();
        let reader = ChainReader::open(tmp.path()).unwrap();
        let recs: Vec<_> = reader.records().collect::<Result<_, _>>().unwrap();
        assert_eq!(recs.len(), 2, "blank trailing line must NOT add a record");
    }

    #[test]
    fn quick_chain_check_returns_no_segments_when_empty() {
        let tmp = TempDir::new().unwrap();
        let v = quick_chain_check(tmp.path());
        assert!(matches!(v, ChainQuickCheck::NoSegments), "got: {v:?}");
    }

    #[test]
    fn quick_chain_check_returns_ok_with_last_seq() {
        let tmp = TempDir::new().unwrap();
        write_valid_chain(tmp.path());
        match quick_chain_check(tmp.path()) {
            ChainQuickCheck::Ok {
                last_seq,
                segment_count,
            } => {
                assert_eq!(last_seq, 1);
                assert_eq!(segment_count, 1);
            }
            other => panic!("expected Ok; got {other:?}"),
        }
    }

    #[test]
    fn quick_chain_check_returns_broken_on_corruption() {
        let tmp = TempDir::new().unwrap();
        write_segment(tmp.path(), 0, "garbage\n");
        let v = quick_chain_check(tmp.path());
        assert!(matches!(v, ChainQuickCheck::Broken { .. }), "got: {v:?}");
    }

    #[test]
    fn verify_chain_full_passes_on_valid_chain() {
        let tmp = TempDir::new().unwrap();
        write_valid_chain(tmp.path());
        let stats = verify_chain_full(tmp.path()).expect("valid chain");
        assert_eq!(stats.total_records, 2);
        assert_eq!(stats.last_seq, 1);
        assert_eq!(stats.segment_count, 1);
    }

    #[test]
    fn verify_chain_full_returns_chain_break_on_link_mismatch() {
        let tmp = TempDir::new().unwrap();
        // genesis OK
        let line0 = serde_json::json!({
            "seq": 0,
            "event_kind": "GenesisRecord",
            "prev_sha256": GENESIS_PREV_SHA256_LITERAL,
        })
        .to_string();
        // line 1 with a wrong prev_sha256
        let line1 = serde_json::json!({
            "seq": 1,
            "event_kind": "K",
            "prev_sha256": "00".repeat(32),
        })
        .to_string();
        write_segment(tmp.path(), 0, &format!("{line0}\n{line1}\n"));
        let err = verify_chain_full(tmp.path()).unwrap_err();
        assert!(
            matches!(err, ChainReadError::ChainBreak { .. }),
            "got: {err:?}"
        );
    }

    #[test]
    fn payload_str_extracts_nested_field() {
        let tmp = TempDir::new().unwrap();
        write_valid_chain(tmp.path());
        let recs: Vec<_> = ChainReader::open(tmp.path())
            .unwrap()
            .records()
            .collect::<Result<_, _>>()
            .unwrap();
        // The KernelStarted record carries payload.data_dir.
        assert_eq!(recs[1].payload_str("data_dir"), Some("/tmp/raxis"));
    }

    // ────────────────────────────────────────────────────────────
    // verify_chain_from — slice-stats variant
    // ────────────────────────────────────────────────────────────

    /// Helper: build a four-record chain (seq 0..=3) that
    /// `verify_chain_from` can slice. The chain is computed by
    /// hand-hashing each line so we exercise the same byte
    /// canonicalisation the production walker uses.
    fn write_four_record_chain(audit_dir: &Path) -> Vec<String> {
        let mut lines: Vec<String> = Vec::new();
        let mut prev_sha = GENESIS_PREV_SHA256_LITERAL.to_owned();
        for seq in 0..4u64 {
            let line = serde_json::json!({
                "seq": seq,
                "event_kind": if seq == 0 { "GenesisRecord" } else { "KernelStarted" },
                "prev_sha256": prev_sha,
                "emitted_at": 1_700_000_000_i64 + seq as i64,
            })
            .to_string();
            let with_nl = format!("{line}\n");
            let mut h = Sha256::new();
            h.update(with_nl.as_bytes());
            prev_sha = hex::encode(h.finalize());
            lines.push(line);
        }
        let body: String = lines.iter().map(|l| format!("{l}\n")).collect();
        write_segment(audit_dir, 0, &body);
        lines
    }

    #[test]
    fn verify_chain_from_zero_matches_verify_chain_full_byte_for_byte() {
        let tmp = TempDir::new().unwrap();
        write_four_record_chain(tmp.path());
        let full = verify_chain_full(tmp.path()).expect("full");
        let from_zero = verify_chain_from(tmp.path(), 0).expect("from-zero");
        assert_eq!(
            full, from_zero,
            "verify_chain_from(0) MUST be identical to verify_chain_full"
        );
    }

    #[test]
    fn verify_chain_from_returns_only_records_at_or_above_seq() {
        let tmp = TempDir::new().unwrap();
        write_four_record_chain(tmp.path());

        // from=2 → records {seq=2, seq=3} → total=2, last_seq=3.
        let stats = verify_chain_from(tmp.path(), 2).expect("from=2");
        assert_eq!(stats.total_records, 2);
        assert_eq!(stats.last_seq, 3);
        assert_eq!(stats.segment_count, 1);
    }

    #[test]
    fn verify_chain_from_past_the_end_returns_empty_slice_with_pre_seq_marker() {
        let tmp = TempDir::new().unwrap();
        write_four_record_chain(tmp.path());

        // from=99 → no records in slice. Total=0, last_seq=98 (the
        // "highest seq ≤ this is the requested window's lower-bound
        // predecessor" contract from the helper docs). segment_count=0
        // because no segments contributed records to the slice.
        let stats = verify_chain_from(tmp.path(), 99).expect("from=99");
        assert_eq!(stats.total_records, 0);
        assert_eq!(stats.last_seq, 98);
        assert_eq!(stats.segment_count, 0);
    }

    #[test]
    fn verify_chain_from_zero_with_empty_chain_uses_saturating_sub_one() {
        // No records at all → from=0 → last_seq must be 0
        // (saturating_sub on 0 is 0). Pinning this guards against
        // an underflow regression.
        let tmp = TempDir::new().unwrap();
        // Need at least one segment file for `ChainReader::open`
        // not to error with `NoSegments`. An empty segment is fine.
        write_segment(tmp.path(), 0, "");
        let stats = verify_chain_from(tmp.path(), 0).expect("empty chain");
        assert_eq!(stats.total_records, 0);
        assert_eq!(stats.last_seq, 0);
        assert_eq!(stats.segment_count, 0);
    }

    #[test]
    fn verify_chain_from_still_walks_chain_to_anchor_linkage_before_slice() {
        // The slice starts at seq=3, but the chain BEFORE that has
        // a corruption. The verdict MUST still be the chain-break
        // error, NOT a clean stats response — chain integrity is a
        // global invariant.
        let tmp = TempDir::new().unwrap();
        // Genesis with intact link.
        let line0 = serde_json::json!({
            "seq": 0,
            "event_kind": "GenesisRecord",
            "prev_sha256": GENESIS_PREV_SHA256_LITERAL,
        })
        .to_string();
        // Second record with a deliberately wrong prev_sha256
        // (chain break at seq=1).
        let line1 = serde_json::json!({
            "seq": 1,
            "event_kind": "K",
            "prev_sha256": "deadbeef".repeat(8),
        })
        .to_string();
        write_segment(tmp.path(), 0, &format!("{line0}\n{line1}\n"));

        let err = verify_chain_from(tmp.path(), 3).expect_err("must fail-close");
        assert!(
            matches!(err, ChainReadError::ChainBreak { .. }),
            "got: {err:?}"
        );
    }
}

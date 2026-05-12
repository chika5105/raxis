//! Audit-chain mechanical witness for the extended e2e scenario —
//! Check A: structural integrity walk.
//!
//! ## What this file asserts
//!
//! Scenario-independent integrity walk over the on-disk JSONL audit
//! segments. Recomputes the `prev_sha256` link byte-for-byte
//! (instead of trusting the `raxis_audit_tools::ChainReader` it
//! cross-checks against) and pins the documented invariants:
//!
//!   1. `seq` starts at `0` and increments by exactly `1` per
//!      record across the whole chain.
//!   2. The first record carries `GENESIS_PREV_SHA256_LITERAL`
//!      (`64 × '0'`).
//!   3. Every subsequent record's `prev_sha256` equals
//!      `SHA-256(previous_line_bytes_with_newline)`.
//!   4. Every record parses as JSON with non-empty `event_kind`,
//!      a numeric `seq`, a 64-hex `prev_sha256`, and an `i64`
//!      `emitted_at` ≥ `1` (zero is reserved for the genesis
//!      epoch and would be a malformed clock for any real
//!      kernel-emitted record).
//!   5. `raxis_audit_tools::verify_chain_full` agrees with our
//!      own walk on `(total_records, last_seq)` — i.e. the
//!      production verifier is consistent with the explicit
//!      re-hash. Disagreement is itself a violation; either the
//!      producer or the verifier drifted.
//!
//! Scenario-specific assertions (Check B — `ExpectedEventScript`
//! + walkers) live alongside this module's structural walk in a
//! follow-up commit. Both checks share the on-disk parser and the
//! reporting infrastructure.
//!
//! ## On the JSONL ↔ SQLite cross-consistency contract
//!
//! `raxis-concepts/06-audit-chain.md` Step 5 describes a planned
//! `audit_pointer` row in SQLite that pairs with the JSONL tail
//! for crash-recovery purposes (`recovery::reconcile`). At v1 the
//! production audit chain lives **only** in the JSONL segments
//! under `<data_dir>/audit/segment-NNN.jsonl` (verified against
//! `raxis_audit_tools::reader::AUDIT_DIR_NAME`); the SQLite side
//! holds operator-facing materialised views (`sessions`, `tasks`,
//! `escalations`, ...) but no `audit` table.
//!
//! The structural walk therefore treats the JSONL as the
//! authoritative chain. If a future segment-rotating writer adds
//! an `audit_pointer` row (or v2 introduces an SQLite-side
//! `audit_log` table), this module must grow a third check that
//! asserts `(latest segment tail, audit_pointer.seq)` agree. The
//! shape of that future check is documented in
//! `audit-paired-writes.md` §INV-AUDIT-PAIRED-06.
//!
//! ## Production-fsync dependency
//!
//! Worker C added `AuditWriterOptions { sync_on_append: true }`
//! (default `true`) so a host crash between SQLite commit and
//! JSONL append no longer drops the audit row. This module does
//! NOT toggle the knob — the test runs against the production
//! `AuditWriter::open` path, which uses the safe default. We
//! observe the on-disk JSONL only.
//!
//! Spec references:
//!   * `raxis/specs/v2/audit-paired-writes.md` (paired-write
//!     invariants).
//!   * `raxis/specs/invariants.md` §11.6 (`INV-AUDIT-PAIRED-05`:
//!     "the audit chain MUST be verifiable by an offline process
//!     ... that does NOT depend on the kernel").
//!   * `raxis/raxis-concepts/06-audit-chain.md` (operator-facing
//!     overview, hash recipe, genesis sentinel).

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use raxis_audit_tools::{verify_chain_full, ChainReader, GENESIS_PREV_SHA256_LITERAL};
use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------
// AuditChainWitness — entry point.
// ---------------------------------------------------------------------------

/// Mechanical witness for the audit chain on disk.
///
/// One witness is constructed per kernel `data_dir`; it walks the
/// JSONL segments under `<data_dir>/audit/`. The structural-walk
/// API is implemented here; the scenario-walk API is implemented
/// alongside this module in a follow-up commit (it consumes a
/// `&[AuditEvent]` already parsed by the test driver and shares
/// no on-disk state with the structural walk).
pub struct AuditChainWitness {
    /// The kernel's `<data_dir>/audit/` directory (NOT `data_dir`
    /// itself). The walk discovers `segment-NNN.jsonl` files in
    /// numeric order via `raxis_audit_tools::ChainReader::open`.
    pub audit_dir: PathBuf,
}

impl AuditChainWitness {
    /// Construct a witness rooted at `<data_dir>/audit/`.
    pub fn for_data_dir(data_dir: &Path) -> Self {
        Self {
            audit_dir: data_dir.join("audit"),
        }
    }

    /// Run the structural integrity walk.
    ///
    /// Returns `Ok(report)` when every invariant holds; otherwise
    /// returns the full list of violations so callers can render
    /// them all at once instead of stopping at the first.
    pub fn walk_structural(&self) -> Result<StructuralReport, Vec<IntegrityViolation>> {
        walk_structural_impl(&self.audit_dir)
    }

    /// Convenience: run [`Self::walk_structural`] and panic with a
    /// rendered violation list on failure. Mirrors the
    /// `assert_satisfied`/`assert_all_satisfied` style used by the
    /// other extended-scenario witnesses in
    /// [`super::witnesses`].
    pub fn assert_structural(&self) -> StructuralReport {
        match self.walk_structural() {
            Ok(report) => report,
            Err(violations) => panic!(
                "AuditChainWitness::walk_structural failed ({} violation{}):\n{}",
                violations.len(),
                if violations.len() == 1 { "" } else { "s" },
                render_integrity_violations(&violations),
            ),
        }
    }
}

// ---------------------------------------------------------------------------
// Structural integrity walk — types
// ---------------------------------------------------------------------------

/// Successful structural-walk verdict.
#[derive(Debug, Clone)]
pub struct StructuralReport {
    /// Total records walked, including the genesis row.
    pub records_walked: u64,
    /// Highest `seq` observed (== `records_walked - 1` when the
    /// chain starts at `0` and is contiguous; the structural walk
    /// fail-closes if it isn't).
    pub last_seq: u64,
    /// Distinct segment files visited.
    pub segments: BTreeSet<PathBuf>,
    /// Distinct `event_kind` strings observed (handy when a
    /// follow-up scenario walker needs to know which kinds the
    /// chain actually contains).
    pub kinds_seen: BTreeSet<String>,
}

/// One integrity violation. Each variant carries enough context
/// (`segment` path, `line_no`, expected-vs-got hashes) for an
/// operator to grep the on-disk segment and reproduce the failure
/// manually.
#[derive(Debug, Clone)]
pub enum IntegrityViolation {
    /// `<data_dir>/audit/` does not exist or could not be opened.
    AuditDirMissing { path: PathBuf, reason: String },

    /// No `segment-NNN.jsonl` files under the audit dir. The
    /// kernel must always write at least one segment (the boot
    /// record) before the first operator IPC frame is accepted.
    NoSegments { path: PathBuf },

    /// I/O failure while reading a segment file.
    SegmentReadFailed { segment: PathBuf, reason: String },

    /// Line did not parse as JSON.
    MalformedJson {
        segment: PathBuf,
        line_no: u64,
        reason: String,
    },

    /// Required field missing or wrong JSON type. `field` is the
    /// JSONL key (`"seq"`, `"prev_sha256"`, ...).
    MissingField {
        segment: PathBuf,
        line_no: u64,
        field: &'static str,
    },

    /// `seq` advanced by != 1.
    SequenceGap {
        segment: PathBuf,
        line_no: u64,
        expected: u64,
        got: u64,
    },

    /// `prev_sha256` did not equal `SHA-256(prev_line_bytes_with_newline)`.
    PrevSha256Break {
        segment: PathBuf,
        line_no: u64,
        seq: u64,
        expected: String,
        got: String,
    },

    /// First record's `prev_sha256` was not the genesis
    /// `64 × '0'` literal.
    NonGenesisFirstPrev {
        segment: PathBuf,
        line_no: u64,
        got: String,
    },

    /// `event_kind` was the empty string. The discriminant must
    /// always be present.
    EmptyEventKind {
        segment: PathBuf,
        line_no: u64,
        seq: u64,
    },

    /// `emitted_at` was non-positive. The kernel's clock helper
    /// (`unix_now`) panics on a pre-epoch system clock, so any
    /// `<= 0` value on disk is a corruption signal.
    NonPositiveEmittedAt {
        segment: PathBuf,
        line_no: u64,
        seq: u64,
        value: i64,
    },

    /// `prev_sha256` was not 64 hex chars. The writer always
    /// emits lowercase 64-char hex; anything else means the
    /// record was rewritten by something other than
    /// `AuditWriter::append`.
    MalformedPrevSha256 {
        segment: PathBuf,
        line_no: u64,
        seq: u64,
        value: String,
    },

    /// `raxis_audit_tools::verify_chain_full` produced a verdict
    /// that disagrees with our own walk on either `total_records`
    /// or `last_seq`. Either the producer or the production
    /// verifier drifted away from the contract pinned in this
    /// module.
    ChainReaderDisagreement { reason: String },

    /// `raxis_audit_tools::verify_chain_full` errored. We
    /// surface the underlying string instead of trying to
    /// re-classify it; the production verifier's diagnostic is
    /// the canonical one.
    ChainReaderErrored { reason: String },
}

// ---------------------------------------------------------------------------
// Structural integrity walk — implementation
// ---------------------------------------------------------------------------

fn walk_structural_impl(audit_dir: &Path) -> Result<StructuralReport, Vec<IntegrityViolation>> {
    let mut violations: Vec<IntegrityViolation> = Vec::new();

    // ── Discover + order segment files via the production helper.
    let reader = match ChainReader::open(audit_dir) {
        Ok(r) => r,
        Err(e) => {
            let kind = format!("{e:?}");
            // Distinguish "missing directory" from "no segments"
            // for operator-friendly diagnostics.
            if kind.contains("AuditDirOpen") {
                violations.push(IntegrityViolation::AuditDirMissing {
                    path: audit_dir.to_path_buf(),
                    reason: format!("{e}"),
                });
            } else if kind.contains("NoSegments") {
                violations.push(IntegrityViolation::NoSegments {
                    path: audit_dir.to_path_buf(),
                });
            } else {
                violations.push(IntegrityViolation::ChainReaderErrored {
                    reason: format!("{e}"),
                });
            }
            return Err(violations);
        }
    };

    let segments_paths = discover_segments(&reader);

    // ── Walk the segments ourselves, byte-for-byte. We do NOT
    //    delegate to `ChainReader::records()` here — the whole
    //    point of this witness is to recompute the chain hash
    //    independently and surface a violation if the production
    //    verifier disagrees. We re-run `verify_chain_full` at
    //    the end as the cross-check.
    let mut records_walked = 0u64;
    let mut last_seq: Option<u64> = None;
    let mut last_line_sha: Option<String> = None;
    let mut segments_seen: BTreeSet<PathBuf> = BTreeSet::new();
    let mut kinds_seen: BTreeSet<String> = BTreeSet::new();

    for segment_path in &segments_paths {
        let raw = match std::fs::read(segment_path) {
            Ok(b) => b,
            Err(e) => {
                violations.push(IntegrityViolation::SegmentReadFailed {
                    segment: segment_path.clone(),
                    reason: format!("{e}"),
                });
                continue;
            }
        };
        segments_seen.insert(segment_path.clone());

        // Walk line-by-line on raw bytes so we can hash the EXACT
        // bytes the writer emitted. A `lines()` iterator that
        // strips `\r\n` would disagree with the writer's
        // canonicalisation under that pathology.
        let mut line_no: u64 = 0;
        let mut cursor = 0usize;
        while cursor < raw.len() {
            let nl_off = match raw[cursor..].iter().position(|&b| b == b'\n') {
                Some(off) => off,
                None => {
                    let tail = &raw[cursor..];
                    if !tail.iter().all(|b| b.is_ascii_whitespace()) {
                        line_no += 1;
                        violations.push(IntegrityViolation::MalformedJson {
                            segment: segment_path.clone(),
                            line_no,
                            reason: "segment ends without trailing newline; \
                                     AuditWriter::append always writes '\\n'"
                                .to_owned(),
                        });
                    }
                    break;
                }
            };
            let line_bytes_with_nl = &raw[cursor..cursor + nl_off + 1];
            cursor += nl_off + 1;

            // Skip pure-whitespace lines (matches the production
            // writer's tolerance in `last_chain_state`).
            if line_bytes_with_nl.iter().all(|b| b.is_ascii_whitespace()) {
                continue;
            }

            line_no += 1;

            let parsed: serde_json::Value = match serde_json::from_slice(line_bytes_with_nl) {
                Ok(v) => v,
                Err(e) => {
                    violations.push(IntegrityViolation::MalformedJson {
                        segment: segment_path.clone(),
                        line_no,
                        reason: format!("JSON parse error: {e}"),
                    });
                    continue;
                }
            };

            let seq = match parsed.get("seq").and_then(|v| v.as_u64()) {
                Some(n) => n,
                None => {
                    violations.push(IntegrityViolation::MissingField {
                        segment: segment_path.clone(),
                        line_no,
                        field: "seq",
                    });
                    continue;
                }
            };

            let event_kind = match parsed.get("event_kind").and_then(|v| v.as_str()) {
                Some(s) => s,
                None => {
                    violations.push(IntegrityViolation::MissingField {
                        segment: segment_path.clone(),
                        line_no,
                        field: "event_kind",
                    });
                    continue;
                }
            };
            if event_kind.is_empty() {
                violations.push(IntegrityViolation::EmptyEventKind {
                    segment: segment_path.clone(),
                    line_no,
                    seq,
                });
            } else {
                kinds_seen.insert(event_kind.to_owned());
            }

            let prev_sha256 = match parsed.get("prev_sha256").and_then(|v| v.as_str()) {
                Some(s) => s.to_owned(),
                None => {
                    violations.push(IntegrityViolation::MissingField {
                        segment: segment_path.clone(),
                        line_no,
                        field: "prev_sha256",
                    });
                    continue;
                }
            };
            if !is_64_hex(&prev_sha256) {
                violations.push(IntegrityViolation::MalformedPrevSha256 {
                    segment: segment_path.clone(),
                    line_no,
                    seq,
                    value: prev_sha256.clone(),
                });
            }

            match parsed.get("emitted_at").and_then(|v| v.as_i64()) {
                Some(t) if t > 0 => {}
                Some(t) => {
                    violations.push(IntegrityViolation::NonPositiveEmittedAt {
                        segment: segment_path.clone(),
                        line_no,
                        seq,
                        value: t,
                    });
                }
                None => {
                    violations.push(IntegrityViolation::MissingField {
                        segment: segment_path.clone(),
                        line_no,
                        field: "emitted_at",
                    });
                }
            }

            // ── Sequence monotonicity.
            let expected_seq = last_seq.map(|s| s + 1).unwrap_or(0);
            if seq != expected_seq {
                violations.push(IntegrityViolation::SequenceGap {
                    segment: segment_path.clone(),
                    line_no,
                    expected: expected_seq,
                    got: seq,
                });
            }

            // ── Chain link.
            match &last_line_sha {
                Some(expected) => {
                    if &prev_sha256 != expected {
                        violations.push(IntegrityViolation::PrevSha256Break {
                            segment: segment_path.clone(),
                            line_no,
                            seq,
                            expected: expected.clone(),
                            got: prev_sha256.clone(),
                        });
                    }
                }
                None => {
                    if prev_sha256 != GENESIS_PREV_SHA256_LITERAL {
                        violations.push(IntegrityViolation::NonGenesisFirstPrev {
                            segment: segment_path.clone(),
                            line_no,
                            got: prev_sha256.clone(),
                        });
                    }
                }
            }

            // Advance state. The next record's expected
            // `prev_sha256` is `SHA-256(this_line_bytes_with_nl)`.
            let mut h = Sha256::new();
            h.update(line_bytes_with_nl);
            last_line_sha = Some(hex::encode(h.finalize()));
            last_seq = Some(seq);
            records_walked += 1;
        }
    }

    // ── Cross-check against the production verifier. The
    //    contract is "agrees on (total_records, last_seq)"; the
    //    integrity-walk is the source of truth, the production
    //    verifier is what operators run via `raxis audit verify`.
    match verify_chain_full(audit_dir) {
        Ok(stats) => {
            if stats.total_records != records_walked {
                violations.push(IntegrityViolation::ChainReaderDisagreement {
                    reason: format!(
                        "verify_chain_full reports total_records={}, our walk \
                         reports {}",
                        stats.total_records, records_walked,
                    ),
                });
            }
            if last_seq.is_some_and(|s| s != stats.last_seq) {
                violations.push(IntegrityViolation::ChainReaderDisagreement {
                    reason: format!(
                        "verify_chain_full reports last_seq={}, our walk \
                         reports last_seq={}",
                        stats.last_seq,
                        last_seq.unwrap(),
                    ),
                });
            }
        }
        Err(e) => {
            violations.push(IntegrityViolation::ChainReaderErrored {
                reason: format!("{e}"),
            });
        }
    }

    if violations.is_empty() {
        Ok(StructuralReport {
            records_walked,
            last_seq: last_seq.unwrap_or(0),
            segments: segments_seen,
            kinds_seen,
        })
    } else {
        Err(violations)
    }
}

fn is_64_hex(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

fn render_integrity_violations(violations: &[IntegrityViolation]) -> String {
    let mut out = String::new();
    for (i, v) in violations.iter().enumerate() {
        out.push_str(&format!("  [{}] {v:?}\n", i + 1));
    }
    out
}

// ---------------------------------------------------------------------------
// Segment discovery — `ChainReader` does not currently expose the
// full segment list, only the latest. We re-scan the directory in
// the same numeric-ascending order ChainReader::open uses
// internally so the structural walk visits segments in chain
// order. Pre-stages segment rotation (v2); v1 only ever has one
// segment file under `<data_dir>/audit/`.
// ---------------------------------------------------------------------------

fn discover_segments(reader: &ChainReader) -> Vec<PathBuf> {
    let latest = reader.latest_segment().to_path_buf();
    let dir = match latest.parent() {
        Some(p) => p.to_path_buf(),
        None => return vec![latest],
    };
    let mut by_idx: std::collections::BTreeMap<u32, PathBuf> = std::collections::BTreeMap::new();
    if let Ok(entries) = std::fs::read_dir(&dir) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let s = match name.to_str() {
                Some(s) => s,
                None => continue,
            };
            let stripped = match s
                .strip_prefix("segment-")
                .and_then(|rest| rest.strip_suffix(".jsonl"))
            {
                Some(num) => num,
                None => continue,
            };
            if let Ok(n) = stripped.parse::<u32>() {
                by_idx.insert(n, entry.path());
            }
        }
    }
    if by_idx.is_empty() {
        vec![latest]
    } else {
        by_idx.into_values().collect()
    }
}

//! Audit-chain mechanical witness for the extended e2e scenario.
//!
//! ## What this module asserts
//!
//! Two complementary, independently-runnable checks:
//!
//! * **Check A — structural integrity walk** ([`AuditChainWitness::
//!   walk_structural`]). Scenario-independent walk over the on-disk
//!   JSONL audit segments. Recomputes the `prev_sha256` link
//!   byte-for-byte (instead of trusting the
//!   `raxis_audit_tools::ChainReader` it cross-checks against) and
//!   pins the documented invariants:
//!     1. `seq` starts at `0` and increments by exactly `1` per
//!        record across the whole chain.
//!     2. The first record carries `GENESIS_PREV_SHA256_LITERAL`
//!        (`64 × '0'`).
//!     3. Every subsequent record's `prev_sha256` equals
//!        `SHA-256(previous_line_bytes_with_newline)`.
//!     4. Every record parses as JSON with non-empty `event_kind`,
//!        a numeric `seq`, a 64-hex `prev_sha256`, and an `i64`
//!        `emitted_at` ≥ `1` (zero is reserved for the genesis
//!        epoch and would be a malformed clock for any real
//!        kernel-emitted record).
//!     5. `raxis_audit_tools::verify_chain_full` agrees with our
//!        own walk on `(total_records, last_seq)` — i.e. the
//!        production verifier is consistent with the explicit
//!        re-hash. Disagreement is itself a violation; either the
//!        producer or the verifier drifted.
//!
//! * **Check B — scenario event walk** ([`AuditChainWitness::
//!   walk_scenario`] + [`scripts`]). Given an
//!   [`ExpectedEventScript`] (a list of [`EventMatcher`]s), walk
//!   the loaded chain in `seq` order and verify every matcher is
//!   satisfied per its [`MatcherKind`]. `AbsentEverywhere`
//!   matchers do a complementary full-chain pass. The script
//!   library lives in [`scripts`] (one constructor per scenario:
//!   `concurrent_lifecycle`, `reviewer_disagreement`,
//!   `prompt_injection`).
//!
//! Both checks operate independently and can be composed: the test
//! driver typically runs `walk_structural` first (ensuring the
//! chain itself is trustworthy) then `walk_scenario` for each
//! script (ensuring the chain captured what the scenario drove),
//! and reports the union of failures from both.
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

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use raxis_audit_tools::{
    verify_chain_full, AuditEvent, AuditEventKind, ChainReader, GENESIS_PREV_SHA256_LITERAL,
};
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

    /// Walk the supplied chain in `seq` order and check every
    /// matcher in `script` is satisfied per its `kind`.
    ///
    /// The chain is supplied (rather than re-loaded here) so the
    /// caller can share it across multiple scenario walks without
    /// re-parsing the JSONL — the structural walk is the
    /// canonical disk-touching pass.
    ///
    /// Behaviour:
    /// * `OrderedAtLeastOnce` / `OrderedAtLeastN(n)` matchers are
    ///   checked against the chain tail starting after the
    ///   PREVIOUS ordered matcher's last match. Missing matches
    ///   become an [`ScenarioViolation::OrderedMatcherUnsatisfied`].
    /// * `AbsentEverywhere` matchers do a complementary
    ///   full-chain pass. Any record that satisfies the predicate
    ///   becomes a [`ScenarioViolation::AbsentMatcherFiredAt`].
    /// * Every violation is returned, not just the first, so a
    ///   single failed scenario sweep surfaces the complete
    ///   diagnostic.
    pub fn walk_scenario(
        &self,
        chain: &[AuditEvent],
        script: &ExpectedEventScript,
    ) -> Result<ScenarioReport, Vec<ScenarioViolation>> {
        walk_scenario_impl(chain, script)
    }

    /// Convenience: run [`Self::walk_scenario`] and panic with a
    /// rendered violation list on failure.
    pub fn assert_scenario(
        &self,
        chain: &[AuditEvent],
        script: &ExpectedEventScript,
    ) -> ScenarioReport {
        match self.walk_scenario(chain, script) {
            Ok(report) => report,
            Err(violations) => panic!(
                "AuditChainWitness::walk_scenario({:?}) failed ({} violation{}):\n{}",
                script.name,
                violations.len(),
                if violations.len() == 1 { "" } else { "s" },
                render_scenario_violations(&violations),
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

// ---------------------------------------------------------------------------
// Scenario event walk — Check B.
//
// Declarative `ExpectedEventScript`s express "the events the
// scenario must have caused to land in the audit chain, in order".
// The walker is independent of the structural walk above; both
// share only the file IO and parsing infrastructure.
// ---------------------------------------------------------------------------

/// Declarative description of "events the scenario MUST cause to
/// land in the audit chain". One script per scenario.
///
/// Built by the [`scripts`] sub-module constructors; consumed by
/// [`AuditChainWitness::walk_scenario`].
pub struct ExpectedEventScript {
    /// Human-readable name for diagnostic rendering. Surfaces in
    /// the panic message when a matcher fails.
    pub name: &'static str,
    /// Ordered matchers. `OrderedAtLeastOnce` and
    /// `OrderedAtLeastN` matchers are checked in chain order; an
    /// `AbsentEverywhere` matcher fails the script if any record
    /// in the entire chain satisfies its predicate.
    pub matchers: Vec<EventMatcher>,
}

/// One declarative matcher in an [`ExpectedEventScript`].
pub struct EventMatcher {
    /// Human-readable label rendered in the panic message; e.g.
    /// "reviewer-A SubmitReview".
    pub label: String,
    /// Matching mode. See [`MatcherKind`].
    pub kind: MatcherKind,
    /// Predicate run against each `AuditEvent`. Return `true`
    /// iff this event satisfies the matcher.
    pub predicate: Box<dyn Fn(&AuditEvent) -> bool + Send + Sync>,
}

/// How an [`EventMatcher`] is consumed by the walker.
pub enum MatcherKind {
    /// Must appear at least once in chain order, AT OR AFTER the
    /// preceding ordered matcher's match position. The default
    /// shape for "X happened, then Y happened".
    OrderedAtLeastOnce,

    /// Like `OrderedAtLeastOnce`, but `n` distinct matches are
    /// required (e.g. three SessionVmSpawned events for the
    /// fan-out group). Each successive match advances the cursor.
    OrderedAtLeastN(usize),

    /// MUST NOT match any record anywhere in the chain. Used for
    /// the strongest deny-path proofs ("no malicious egress
    /// succeeded", "no escalation was approved during the
    /// injection scenario", ...).
    AbsentEverywhere,
}

/// Successful scenario-walk verdict.
#[derive(Debug, Clone)]
pub struct ScenarioReport {
    /// Total `OrderedAtLeastOnce` / `OrderedAtLeastN` matchers
    /// satisfied.
    pub ordered_satisfied: usize,
    /// Total `AbsentEverywhere` matchers verified clean.
    pub absent_clean: usize,
    /// Per-matcher diagnostic of which records satisfied each
    /// matcher. Indexed by matcher position in the script.
    pub matched_seqs: BTreeMap<usize, Vec<u64>>,
}

/// One scenario-walk violation.
#[derive(Debug, Clone)]
pub enum ScenarioViolation {
    /// An `OrderedAtLeastOnce`/`OrderedAtLeastN` matcher did not
    /// see enough satisfying records after its predecessor's
    /// match position.
    OrderedMatcherUnsatisfied {
        script_name: &'static str,
        matcher_index: usize,
        matcher_label: String,
        required: usize,
        observed: usize,
        cursor_seq_after_predecessor: Option<u64>,
    },
    /// An `AbsentEverywhere` matcher matched at least one record.
    /// The matched seqs identify the offending rows so an
    /// operator can run `raxis inspect` against them.
    AbsentMatcherFiredAt {
        script_name: &'static str,
        matcher_index: usize,
        matcher_label: String,
        matched_seqs: Vec<u64>,
    },
}

fn walk_scenario_impl(
    chain: &[AuditEvent],
    script: &ExpectedEventScript,
) -> Result<ScenarioReport, Vec<ScenarioViolation>> {
    let mut violations: Vec<ScenarioViolation> = Vec::new();
    let mut matched_seqs: BTreeMap<usize, Vec<u64>> = BTreeMap::new();
    let mut ordered_satisfied = 0usize;
    let mut absent_clean = 0usize;

    // Cursor: the chain index strictly AFTER the most recent
    // ordered match. Advances forward only.
    let mut cursor: usize = 0;

    for (i, m) in script.matchers.iter().enumerate() {
        match m.kind {
            MatcherKind::OrderedAtLeastOnce => {
                let required = 1usize;
                let mut hits: Vec<u64> = Vec::new();
                let mut new_cursor = cursor;
                for (j, ev) in chain.iter().enumerate().skip(cursor) {
                    if (m.predicate)(ev) {
                        hits.push(ev.seq);
                        new_cursor = j + 1;
                        if hits.len() >= required {
                            break;
                        }
                    }
                }
                matched_seqs.insert(i, hits.clone());
                if hits.len() >= required {
                    ordered_satisfied += 1;
                    cursor = new_cursor;
                } else {
                    violations.push(ScenarioViolation::OrderedMatcherUnsatisfied {
                        script_name: script.name,
                        matcher_index: i,
                        matcher_label: m.label.clone(),
                        required,
                        observed: hits.len(),
                        cursor_seq_after_predecessor: chain.get(cursor).map(|e| e.seq),
                    });
                }
            }
            MatcherKind::OrderedAtLeastN(n) => {
                let mut hits: Vec<u64> = Vec::new();
                let mut new_cursor = cursor;
                for (j, ev) in chain.iter().enumerate().skip(cursor) {
                    if (m.predicate)(ev) {
                        hits.push(ev.seq);
                        new_cursor = j + 1;
                        if hits.len() >= n {
                            break;
                        }
                    }
                }
                matched_seqs.insert(i, hits.clone());
                if hits.len() >= n {
                    ordered_satisfied += 1;
                    cursor = new_cursor;
                } else {
                    violations.push(ScenarioViolation::OrderedMatcherUnsatisfied {
                        script_name: script.name,
                        matcher_index: i,
                        matcher_label: m.label.clone(),
                        required: n,
                        observed: hits.len(),
                        cursor_seq_after_predecessor: chain.get(cursor).map(|e| e.seq),
                    });
                }
            }
            MatcherKind::AbsentEverywhere => {
                let hits: Vec<u64> = chain
                    .iter()
                    .filter(|ev| (m.predicate)(ev))
                    .map(|ev| ev.seq)
                    .collect();
                matched_seqs.insert(i, hits.clone());
                if hits.is_empty() {
                    absent_clean += 1;
                } else {
                    violations.push(ScenarioViolation::AbsentMatcherFiredAt {
                        script_name: script.name,
                        matcher_index: i,
                        matcher_label: m.label.clone(),
                        matched_seqs: hits,
                    });
                }
            }
        }
    }

    if violations.is_empty() {
        Ok(ScenarioReport {
            ordered_satisfied,
            absent_clean,
            matched_seqs,
        })
    } else {
        Err(violations)
    }
}

fn render_scenario_violations(violations: &[ScenarioViolation]) -> String {
    let mut out = String::new();
    for (i, v) in violations.iter().enumerate() {
        out.push_str(&format!("  [{}] {v:?}\n", i + 1));
    }
    out
}

// ---------------------------------------------------------------------------
// Predicate helpers — a small toolkit so script constructors can
// stay declarative. Each helper builds a `Box<dyn Fn(&AuditEvent)
// -> bool + Send + Sync>` over a typed `AuditEventKind` match.
// ---------------------------------------------------------------------------

/// Decode `ev.payload` into the typed `AuditEventKind` enum.
/// Returns `None` if the payload is malformed (which would itself
/// be an audit-chain integrity bug; the structural walk already
/// fail-closes on that). Mirror of [`super::witnesses::typed`]
/// re-exported here so script constructors don't reach across
/// modules.
fn typed(ev: &AuditEvent) -> Option<AuditEventKind> {
    serde_json::from_value(ev.payload.clone()).ok()
}

/// Predicate: matches by `event_kind` discriminant string only.
pub fn pred_kind(event_kind: &'static str) -> Box<dyn Fn(&AuditEvent) -> bool + Send + Sync> {
    Box::new(move |ev| ev.event_kind == event_kind)
}

/// Predicate: matches a typed `AuditEventKind` via a closure. The
/// closure runs on the decoded payload only when the
/// `event_kind` discriminant matches; otherwise the predicate
/// returns `false` without paying the JSON-decode cost.
pub fn pred_kind_with(
    event_kind: &'static str,
    f: impl Fn(&AuditEventKind) -> bool + Send + Sync + 'static,
) -> Box<dyn Fn(&AuditEvent) -> bool + Send + Sync> {
    Box::new(move |ev| {
        if ev.event_kind != event_kind {
            return false;
        }
        match typed(ev) {
            Some(kind) => f(&kind),
            None => false,
        }
    })
}

// ---------------------------------------------------------------------------
// Scenario script constructors.
//
// Each `scripts::<scenario>` builds an `ExpectedEventScript`
// declaratively. The matchers exactly mirror what the existing
// `EnforcementWitness` set asserts for the same scenario, expressed
// through the AuditChainWitness's chain-walk API instead of
// per-witness ad-hoc loops.
// ---------------------------------------------------------------------------

pub mod scripts {
    use super::*;

    /// Concurrent-lifecycle script — asserts the audit chain
    /// captured the materializer + fan-out + reviewer aggregation
    /// + initiative-merge sequence the test scenario drove.
    ///
    /// The matchers are ORDERED — each advances the chain cursor
    /// to the position immediately after its match. The cursor is
    /// monotonic, so every matcher's chain-tail substring must
    /// contain the events the next matcher needs. The order
    /// chosen here mirrors the canonical lifecycle:
    ///
    /// 1. `OrderedAtLeastOnce` `SessionVmSpawned { task_id ==
    ///    materializer }`
    /// 2. `OrderedAtLeastN(fanout.len())` `SessionVmSpawned {
    ///    task_id ∈ fanout }`
    /// 3. `OrderedAtLeastN(fanout.len())` `SessionVmExited (any
    ///    session)` — fanout VMs exit quickly because their tasks
    ///    write only 1-2 files. Spawn shape carries `task_id`;
    ///    exit shape does not, so the matcher counts exits by
    ///    occurrence rather than discriminating per task. Counting
    ///    `>= fanout.len()` is satisfied by any combination of
    ///    fanout + materializer + reviewer exits, but every match
    ///    pins "at least N VMs reached a clean stop" which is the
    ///    invariant we care about for the fan-out group.
    /// 4. `OrderedAtLeastOnce` `ReviewAggregationCompleted {
    ///    executor_task_id == materializer, verdict ==
    ///    "AllPassed" }` — the review cycle concluded successfully.
    /// 5. `OrderedAtLeastOnce` `IntegrationMergeCompleted {
    ///    initiative_id == ours }` — the orchestrator merged the
    ///    materializer branch into the initiative trunk.
    ///
    /// The materializer's own `IntentAccepted{head_sha=Some}`
    /// (commit-admit) is intentionally NOT in the script — its
    /// position relative to the fan-out exits is timing-dependent
    /// (the materializer reads 50 records before committing,
    /// which can finish before or after the fanout group exits).
    /// The on-disk commit is pinned by `MaterializationWitness`,
    /// which is the canonical assertion for that particular fact.
    pub fn concurrent_lifecycle(
        materializer_task_id: &'static str,
        fanout_task_ids: &'static [&'static str],
        initiative_id: String,
    ) -> ExpectedEventScript {
        let materializer_for_spawn = materializer_task_id.to_owned();
        let fanout_set: BTreeSet<String> =
            fanout_task_ids.iter().map(|s| (*s).to_owned()).collect();
        let initiative_id_for_match = initiative_id.clone();
        let materializer_for_aggregation = materializer_task_id.to_owned();

        ExpectedEventScript {
            name: "concurrent-lifecycle",
            matchers: vec![
                EventMatcher {
                    label: format!("SessionVmSpawned[task_id={materializer_task_id}]"),
                    kind: MatcherKind::OrderedAtLeastOnce,
                    predicate: pred_kind_with("SessionVmSpawned", move |k| {
                        matches!(
                            k,
                            AuditEventKind::SessionVmSpawned { task_id: Some(t), .. }
                                if t == &materializer_for_spawn
                        )
                    }),
                },
                EventMatcher {
                    label: format!(
                        "SessionVmSpawned×{} [task_id ∈ fanout]",
                        fanout_task_ids.len(),
                    ),
                    kind: MatcherKind::OrderedAtLeastN(fanout_task_ids.len()),
                    predicate: {
                        let set = fanout_set.clone();
                        pred_kind_with("SessionVmSpawned", move |k| match k {
                            AuditEventKind::SessionVmSpawned {
                                task_id: Some(t), ..
                            } => set.contains(t),
                            _ => false,
                        })
                    },
                },
                EventMatcher {
                    label: format!(
                        "SessionVmExited×{} (any task — exit shape carries no task_id)",
                        fanout_task_ids.len(),
                    ),
                    kind: MatcherKind::OrderedAtLeastN(fanout_task_ids.len()),
                    predicate: pred_kind("SessionVmExited"),
                },
                EventMatcher {
                    label: format!(
                        "ReviewAggregationCompleted[executor={materializer_task_id}, verdict=AllPassed]",
                    ),
                    kind: MatcherKind::OrderedAtLeastOnce,
                    predicate: pred_kind_with("ReviewAggregationCompleted", move |k| {
                        matches!(
                            k,
                            AuditEventKind::ReviewAggregationCompleted {
                                executor_task_id, verdict, ..
                            } if executor_task_id == &materializer_for_aggregation
                                && verdict == "AllPassed"
                        )
                    }),
                },
                EventMatcher {
                    label: format!(
                        "IntegrationMergeCompleted[initiative_id={initiative_id}]",
                    ),
                    kind: MatcherKind::OrderedAtLeastOnce,
                    predicate: pred_kind_with("IntegrationMergeCompleted", move |k| {
                        matches!(
                            k,
                            AuditEventKind::IntegrationMergeCompleted {
                                initiative_id: ev_init, ..
                            } if ev_init == &initiative_id_for_match
                        )
                    }),
                },
            ],
        }
    }

    /// Reviewer-disagreement script — asserts the audit chain
    /// captured (reviewer-A SubmitReview → executor re-spawn →
    /// reviewer-B SubmitReview → ReviewAggregationCompleted with
    /// verdict AllPassed).
    ///
    /// Per-review verdicts are NOT exposed in any audit payload
    /// (they live in SQLite columns operators read via `raxis
    /// inspect`); the proxy assertion (re-spawn between two
    /// SubmitReview submissions) is the strongest claim the
    /// audit chain alone can support. This mirrors the rationale
    /// in `super::witnesses::ReviewerDisagreementWitness`.
    pub fn reviewer_disagreement(
        executor_task_id: &'static str,
        reviewer_a_task_id: &'static str,
        reviewer_b_task_id: &'static str,
    ) -> ExpectedEventScript {
        let exec_for_respawn = executor_task_id.to_owned();
        let exec_for_aggregation = executor_task_id.to_owned();
        let rev_a = reviewer_a_task_id.to_owned();
        let rev_b = reviewer_b_task_id.to_owned();

        ExpectedEventScript {
            name: "reviewer-disagreement",
            matchers: vec![
                EventMatcher {
                    label: format!(
                        "IntentAccepted[task_id={reviewer_a_task_id}, intent_kind=SubmitReview] (round 1)",
                    ),
                    kind: MatcherKind::OrderedAtLeastOnce,
                    predicate: pred_kind_with("IntentAccepted", move |k| {
                        matches!(
                            k,
                            AuditEventKind::IntentAccepted {
                                task_id, intent_kind, ..
                            } if task_id == &rev_a && intent_kind == "SubmitReview"
                        )
                    }),
                },
                EventMatcher {
                    label: format!(
                        "SessionVmSpawned[task_id={executor_task_id}] (executor re-spawn after rejection)",
                    ),
                    kind: MatcherKind::OrderedAtLeastOnce,
                    predicate: pred_kind_with("SessionVmSpawned", move |k| {
                        matches!(
                            k,
                            AuditEventKind::SessionVmSpawned { task_id: Some(t), .. }
                                if t == &exec_for_respawn
                        )
                    }),
                },
                EventMatcher {
                    label: format!(
                        "IntentAccepted[task_id={reviewer_b_task_id}, intent_kind=SubmitReview] (round 2)",
                    ),
                    kind: MatcherKind::OrderedAtLeastOnce,
                    predicate: pred_kind_with("IntentAccepted", move |k| {
                        matches!(
                            k,
                            AuditEventKind::IntentAccepted {
                                task_id, intent_kind, ..
                            } if task_id == &rev_b && intent_kind == "SubmitReview"
                        )
                    }),
                },
                EventMatcher {
                    label: format!(
                        "ReviewAggregationCompleted[executor={executor_task_id}, verdict=AllPassed]",
                    ),
                    kind: MatcherKind::OrderedAtLeastOnce,
                    predicate: pred_kind_with("ReviewAggregationCompleted", move |k| {
                        matches!(
                            k,
                            AuditEventKind::ReviewAggregationCompleted {
                                executor_task_id, verdict, ..
                            } if executor_task_id == &exec_for_aggregation
                                && verdict == "AllPassed"
                        )
                    }),
                },
            ],
        }
    }

    /// Prompt-injection script — asserts (1) the kernel emitted
    /// the expected deny rows for each malicious payload AND (2)
    /// no audit row claims the malicious action succeeded.
    ///
    /// Per-payload positive matchers are paired with global
    /// negative `AbsentEverywhere` matchers. The strongest
    /// proof the audit chain can offer that the kernel did NOT
    /// approve a forged escalation is "zero `EscalationApproved`
    /// records exist over the test run" — the test scenario
    /// itself never approves any escalation (it approves the
    /// initiative plan via a different intent kind), so any
    /// `EscalationApproved` would be a real production bypass.
    ///
    /// Caller passes `injection_session_id` so the path-breakout
    /// matcher can target the rejection by session. Pass `None`
    /// when the session id is not yet known (the matcher
    /// degenerates to "any IntentRejected with the right
    /// error_code"; still useful, less precise).
    pub fn prompt_injection(
        injection_session_id: Option<String>,
        payload_ids: &[&str],
    ) -> ExpectedEventScript {
        let mut matchers: Vec<EventMatcher> = Vec::new();

        for id in payload_ids {
            match *id {
                "egress_exfil" => {
                    matchers.push(EventMatcher {
                        label: "TransparentProxyDenied[host_or_sni~='example.evil'] OR HttpProxyRequestExecuted[blocked=true]"
                            .to_owned(),
                        kind: MatcherKind::OrderedAtLeastOnce,
                        predicate: Box::new(|ev: &AuditEvent| {
                            match typed(ev) {
                                Some(AuditEventKind::TransparentProxyDenied {
                                    host_or_sni, ..
                                }) => host_or_sni
                                    .as_deref()
                                    .map(|h| h.contains("example.evil"))
                                    .unwrap_or(false),
                                Some(AuditEventKind::HttpProxyRequestExecuted {
                                    blocked: true, ..
                                }) => true,
                                _ => false,
                            }
                        }),
                    });
                    // Strong deny-path proof: no audit record
                    // describes a successful HTTP-proxy request
                    // whose path mentions "example.evil".
                    matchers.push(EventMatcher {
                        label: "AbsentEverywhere: HttpProxyRequestExecuted[blocked=false, path~='example.evil']"
                            .to_owned(),
                        kind: MatcherKind::AbsentEverywhere,
                        predicate: pred_kind_with(
                            "HttpProxyRequestExecuted",
                            |k| matches!(
                                k,
                                AuditEventKind::HttpProxyRequestExecuted {
                                    blocked: false, path, ..
                                } if path.contains("example.evil")
                            ),
                        ),
                    });
                }
                "escalation_forgery" => {
                    matchers.push(EventMatcher {
                        label: "EscalationSubmitted[class=PathScopeOverride]".to_owned(),
                        kind: MatcherKind::OrderedAtLeastOnce,
                        predicate: pred_kind_with("EscalationSubmitted", |k| {
                            matches!(
                                k,
                                AuditEventKind::EscalationSubmitted { class, .. }
                                    if class == "PathScopeOverride"
                            )
                        }),
                    });
                    // The test scenario never approves any
                    // escalation (`OperatorIpc::approve_plan`
                    // emits `PlanApproved`, not
                    // `EscalationApproved`), so any approval row
                    // is evidence the kernel accepted a forged
                    // approval.
                    matchers.push(EventMatcher {
                        label: "AbsentEverywhere: EscalationApproved (test scenario approves no escalations)".to_owned(),
                        kind: MatcherKind::AbsentEverywhere,
                        predicate: pred_kind("EscalationApproved"),
                    });
                }
                "approval_circumvention" => {
                    // The planner can't write to <data_dir>, so
                    // a forged approval token never reaches the
                    // kernel. Defense in depth: assert that no
                    // EscalationConsumed fired during the test
                    // (the legitimate consumes are paired with
                    // EscalationApproved, which the prior
                    // matcher already asserts is absent).
                    matchers.push(EventMatcher {
                        label: "AbsentEverywhere: EscalationConsumed (no legitimate consume in this scenario)".to_owned(),
                        kind: MatcherKind::AbsentEverywhere,
                        predicate: pred_kind("EscalationConsumed"),
                    });
                }
                "path_breakout" => {
                    let session_filter = injection_session_id.clone();
                    matchers.push(EventMatcher {
                        label: "IntentRejected[error_code=FAIL_TASK_PATH_NOT_ALLOWED]".to_owned(),
                        kind: MatcherKind::OrderedAtLeastOnce,
                        predicate: pred_kind_with("IntentRejected", move |k| match k {
                            AuditEventKind::IntentRejected {
                                session_id,
                                error_code,
                                ..
                            } => {
                                if error_code != "FAIL_TASK_PATH_NOT_ALLOWED" {
                                    return false;
                                }
                                match &session_filter {
                                    Some(sid) => session_id == sid,
                                    None => true,
                                }
                            }
                            _ => false,
                        }),
                    });
                }
                other => {
                    // Unknown payload id — surface as an absent
                    // matcher that always fires so the test
                    // panics with a useful message instead of
                    // silently passing. This catches a future
                    // payload added to the seed TOML without a
                    // matching script entry.
                    let other_owned = other.to_owned();
                    matchers.push(EventMatcher {
                        label: format!(
                            "[script-gap] no script wired for payload id='{other}' \
                             — add a matcher in audit_chain::scripts::prompt_injection",
                        ),
                        kind: MatcherKind::AbsentEverywhere,
                        predicate: Box::new(move |_| {
                            // Always fires so the test panics
                            // and the operator sees the gap.
                            // Side-effect-free; doesn't read the
                            // event.
                            let _ = &other_owned;
                            true
                        }),
                    });
                }
            }
        }

        ExpectedEventScript {
            name: "prompt-injection",
            matchers,
        }
    }
}

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

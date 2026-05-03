// AuditDir — TempDir-backed real-file fixture for audit-chain integration
// tests.
//
// Why this exists:
//   The kernel's audit chain has TWO production halves:
//
//     1. WRITE side — `raxis_audit_tools::FileAuditSink` wraps an
//        `AuditWriter`, which serialises `AuditEvent`s to a JSONL segment
//        on disk and maintains the `prev_sha256` chain.
//
//     2. READ side  — `kernel::recovery::verify_audit_chain` reads the
//        segment back at boot and structurally validates the genesis
//        record (and, in v2, the full chain).
//
//   Each half has thorough unit tests against `tempfile::NamedTempFile`,
//   but no test exercises BOTH halves through the SAME on-disk artifact.
//   That is exactly the bug class the `vcs::diff` `-z` framing miss
//   belonged to: a contract pinned independently on each side, with
//   nothing to catch a drift in the actual canonical bytes the writer
//   emits versus the bytes the reader expects.
//
//   `AuditDir` closes that gap. Tests:
//     - construct an `AuditDir`,
//     - optionally seed a production-shape genesis record,
//     - write events through the production `AuditWriter`/`FileAuditSink`,
//     - read the JSONL back,
//     - run `verify_audit_chain` (or any other on-disk audit check) on
//       the fixture's path.
//
// What this fixture is NOT:
//   - Not a substitute for `FakeAuditSink` in unit tests where you just
//     want to assert "handler X emitted event Y". For that, the in-memory
//     `FakeAuditSink` (also re-exported from this crate) is faster and
//     test-isolated.
//   - Not a verifier of the chain itself. That logic lives in the
//     production code; this fixture only owns the file lifecycle.

use std::fs::OpenOptions;
use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use raxis_audit_tools::{AuditWriter, FileAuditSink};
use sha2::{Digest, Sha256};
use tempfile::TempDir;

/// File name the kernel writes to (kernel-store.md §2.5.2).
/// The fixture mirrors the production layout so production code paths
/// (e.g. `verify_audit_chain`) can be pointed at `AuditDir::path()`
/// without further configuration.
const SEGMENT_FILENAME: &str = "segment-000.jsonl";

/// SHA-256 sentinel the genesis record (and the AuditWriter's first
/// emit when no prior chain exists) uses for `prev_sha256`. 64 zeros.
/// Matches `AuditWriter::GENESIS_PREV_SHA256` in `raxis-audit-tools`.
const GENESIS_PREV_SHA256: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

// ---------------------------------------------------------------------------
// AuditDir
// ---------------------------------------------------------------------------

/// A temp directory shaped exactly like a production audit directory.
///
/// On construction the directory is empty; a typical test then either
/// (a) seeds a genesis record via [`AuditDir::write_genesis_record`] and
/// then opens an [`AuditWriter`] resuming from there, or (b) opens an
/// [`AuditWriter`] from scratch (no genesis) to test the
/// `verify_audit_chain` rejection path.
///
/// The underlying [`TempDir`] is recursively removed on drop, so test
/// bodies do not need explicit cleanup.
pub struct AuditDir {
    /// Held to extend the temp directory's lifetime to the fixture's.
    /// Kept private so callers cannot drop the dir out from under the
    /// segment path.
    _tmp: TempDir,
    path: PathBuf,
}

/// Metadata returned by [`AuditDir::write_genesis_record`] so subsequent
/// writes can chain off the genesis line correctly.
///
/// `raw_line_sha256` is the SHA-256 of the genesis line including its
/// trailing `'\n'` — i.e. exactly the value that the FIRST post-genesis
/// record's `prev_sha256` field MUST equal under the chain invariant
/// (kernel-store.md §2.5.2 "every record's prev_sha256 is the SHA-256
/// of the raw bytes of the previous line").
#[derive(Debug, Clone)]
pub struct GenesisInfo {
    pub authority_fingerprint: String,
    pub genesis_nonce:         String,
    pub raw_line_sha256:       String,
}

impl AuditDir {
    /// Create a fresh empty audit directory in a new temp dir.
    pub fn new() -> Self {
        let tmp  = TempDir::new().expect("AuditDir: TempDir::new failed");
        let path = tmp.path().to_path_buf();
        Self { _tmp: tmp, path }
    }

    /// Path to the audit directory itself. Pass this to
    /// `verify_audit_chain` or any other consumer that takes an
    /// `audit_dir: &Path`.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Path to the canonical segment file (`segment-000.jsonl`). Tests
    /// that need to perform raw I/O (e.g. byte-flip tampering) use this.
    pub fn segment_path(&self) -> PathBuf {
        self.path.join(SEGMENT_FILENAME)
    }

    /// Open a production [`AuditWriter`] on the segment, starting from
    /// `seq=0` and the genesis sentinel `prev_sha256`. This is the
    /// behaviour `kernel::main::main` itself uses today (see the v1
    /// "fresh chain on every restart" simplification in main.rs).
    ///
    /// Use [`AuditDir::open_writer_resuming_after`] if the segment
    /// already contains a genesis record and you want the writer to
    /// chain from it.
    pub fn open_writer(&self) -> AuditWriter {
        AuditWriter::open(&self.segment_path(), 0, None)
            .expect("AuditDir: AuditWriter::open failed")
    }

    /// Open a production [`AuditWriter`] resuming from the supplied
    /// `(seq, prev_sha256)`. The typical use is right after
    /// [`AuditDir::write_genesis_record`]:
    ///
    /// ```ignore
    /// let dir  = AuditDir::new();
    /// let info = dir.write_genesis_record();
    /// // Genesis is seq=0; the next event must be seq=1 chained off
    /// // the genesis line's SHA-256.
    /// let writer = dir.open_writer_resuming_after(1, &info.raw_line_sha256);
    /// ```
    pub fn open_writer_resuming_after(
        &self,
        next_seq: u64,
        prev_sha256: &str,
    ) -> AuditWriter {
        AuditWriter::open(
            &self.segment_path(),
            next_seq,
            Some(prev_sha256.to_owned()),
        )
        .expect("AuditDir: AuditWriter::open (resuming) failed")
    }

    /// Wrap an [`AuditWriter`] in the production [`FileAuditSink`].
    /// Convenience for tests that want to drive the full
    /// `Arc<dyn AuditSink>` path the kernel uses in production.
    pub fn open_sink(&self) -> FileAuditSink {
        FileAuditSink::new(self.open_writer())
    }

    /// Append a production-shape `GenesisRecord` line to the segment
    /// matching the format `kernel::bootstrap::write_genesis_audit_record`
    /// emits. Returns the metadata needed to chain subsequent writes.
    ///
    /// The shape MUST stay in lockstep with bootstrap.rs — if the
    /// bootstrap format ever changes (new field, renamed field), this
    /// helper has to change too. The kernel-side test
    /// `verify_audit_chain_accepts_real_genesis_record` (in
    /// `recovery.rs`'s integration block) is the pinning test that
    /// detects drift either way.
    pub fn write_genesis_record(&self) -> GenesisInfo {
        let authority_fingerprint = "fakefp00112233445566778899aabbcc".to_owned();
        let genesis_nonce = "00".repeat(64);

        let record = serde_json::json!({
            "seq":                          0,
            "event_id":                     "00000000-0000-0000-0000-000000000000",
            "event_kind":                   "GenesisRecord",
            "prev_sha256":                  GENESIS_PREV_SHA256,
            "genesis_nonce":                genesis_nonce,
            "authority_pubkey_fingerprint": authority_fingerprint,
            "emitted_at":                   0_u64,
        });

        let mut line = serde_json::to_string(&record)
            .expect("AuditDir::write_genesis_record: serialize failed");
        line.push('\n');

        self.append_raw_line(&line);
        let raw_line_sha256 = sha256_hex(line.as_bytes());

        GenesisInfo {
            authority_fingerprint,
            genesis_nonce: "00".repeat(64),
            raw_line_sha256,
        }
    }

    /// Append a raw line to the segment (caller-supplied trailing '\n').
    /// Used by negative tests that need to inject malformed content.
    pub fn append_raw_line(&self, line: &str) {
        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.segment_path())
            .expect("AuditDir::append_raw_line: open failed");
        f.write_all(line.as_bytes())
            .expect("AuditDir::append_raw_line: write failed");
        f.sync_all().expect("AuditDir::append_raw_line: fsync failed");
    }

    /// Read every line of the segment, parsing each as JSON. Skips
    /// blank trailing lines (which `serde_json::from_str` would reject).
    /// Panics on a malformed line — tests that want to assert
    /// malformedness should use [`AuditDir::raw_lines`] instead.
    pub fn read_records(&self) -> Vec<serde_json::Value> {
        let raw = std::fs::read_to_string(self.segment_path())
            .expect("AuditDir::read_records: read failed");
        raw.lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| {
                serde_json::from_str(l)
                    .unwrap_or_else(|e| panic!("AuditDir::read_records: bad JSON {l:?}: {e}"))
            })
            .collect()
    }

    /// Read the segment as raw lines (without trailing '\n'). Tests
    /// that walk the chain need both the parsed JSON (for fields) and
    /// the raw lines (for SHA-256 verification of `prev_sha256`).
    pub fn raw_lines(&self) -> Vec<String> {
        let raw = std::fs::read_to_string(self.segment_path())
            .expect("AuditDir::raw_lines: read failed");
        raw.lines().map(str::to_owned).collect()
    }

    /// Current size of the segment in bytes. Useful for crash-window
    /// tests that truncate part of the file.
    pub fn segment_size_bytes(&self) -> u64 {
        std::fs::metadata(self.segment_path())
            .map(|m| m.len())
            .unwrap_or(0)
    }

    /// Truncate the segment to `len` bytes — simulates a crash mid-write
    /// where the OS only persisted a prefix. Used by negative tests
    /// against `verify_audit_chain`.
    pub fn truncate_segment_to(&self, len: u64) {
        let f = OpenOptions::new()
            .write(true)
            .open(self.segment_path())
            .expect("AuditDir::truncate_segment_to: open failed");
        f.set_len(len)
            .expect("AuditDir::truncate_segment_to: set_len failed");
        f.sync_all()
            .expect("AuditDir::truncate_segment_to: fsync failed");
    }

    /// Overwrite a single byte at the given offset. Used to build
    /// "valid JSON but wrong field value" corruption scenarios.
    pub fn corrupt_byte_at(&self, offset: u64, new_byte: u8) {
        let mut f = OpenOptions::new()
            .write(true)
            .open(self.segment_path())
            .expect("AuditDir::corrupt_byte_at: open failed");
        f.seek(SeekFrom::Start(offset))
            .expect("AuditDir::corrupt_byte_at: seek failed");
        f.write_all(&[new_byte])
            .expect("AuditDir::corrupt_byte_at: write failed");
        f.sync_all().expect("AuditDir::corrupt_byte_at: fsync failed");
    }
}

impl Default for AuditDir {
    fn default() -> Self {
        Self::new()
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

// ---------------------------------------------------------------------------
// Tests — fixture self-tests, kept here so a broken fixture fails its
// own crate's `cargo test` instead of mysteriously breaking downstream
// integration tests.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use raxis_audit_tools::AuditEventKind;

    #[test]
    fn new_creates_an_empty_segment_directory() {
        let dir = AuditDir::new();
        assert!(dir.path().is_dir(), "audit dir must exist");
        assert!(!dir.segment_path().exists(), "segment must not exist yet");
        assert_eq!(dir.segment_size_bytes(), 0);
    }

    #[test]
    fn write_genesis_record_produces_a_parseable_genesis_line() {
        let dir  = AuditDir::new();
        let info = dir.write_genesis_record();

        let recs = dir.read_records();
        assert_eq!(recs.len(), 1, "exactly one genesis record");
        assert_eq!(recs[0]["seq"].as_u64().unwrap(), 0);
        assert_eq!(recs[0]["event_kind"].as_str().unwrap(), "GenesisRecord");
        assert_eq!(recs[0]["prev_sha256"].as_str().unwrap(), GENESIS_PREV_SHA256);
        assert_eq!(
            recs[0]["authority_pubkey_fingerprint"].as_str().unwrap(),
            info.authority_fingerprint,
        );
    }

    #[test]
    fn genesis_info_raw_line_sha256_matches_what_the_first_post_genesis_record_would_chain_off() {
        let dir  = AuditDir::new();
        let info = dir.write_genesis_record();

        // Read the raw line as it sits on disk (with trailing '\n')
        // and confirm the SHA-256 matches what GenesisInfo reported.
        let raw = std::fs::read(dir.segment_path()).unwrap();
        let expected = sha256_hex(&raw);
        assert_eq!(info.raw_line_sha256, expected);
    }

    #[test]
    fn open_writer_resuming_after_genesis_chains_correctly() {
        let dir  = AuditDir::new();
        let info = dir.write_genesis_record();

        // First post-genesis event is seq=1, prev = SHA-256 of genesis line.
        let mut w = dir.open_writer_resuming_after(1, &info.raw_line_sha256);
        w.append(
            AuditEventKind::KernelStarted {
                data_dir:       "/test".to_owned(),
                policy_epoch:   1,
                schema_version: 1,
            },
            None,
            None,
            None,
        )
        .unwrap();

        let recs = dir.read_records();
        assert_eq!(recs.len(), 2);
        assert_eq!(recs[0]["seq"].as_u64().unwrap(), 0);
        assert_eq!(recs[1]["seq"].as_u64().unwrap(), 1);
        assert_eq!(
            recs[1]["prev_sha256"].as_str().unwrap(),
            info.raw_line_sha256,
            "post-genesis event must chain off the genesis line",
        );
    }

    #[test]
    fn truncate_then_corrupt_round_trip() {
        let dir = AuditDir::new();
        dir.append_raw_line("hello world\n");
        assert_eq!(dir.segment_size_bytes(), 12);

        dir.truncate_segment_to(5);
        assert_eq!(dir.segment_size_bytes(), 5);
        let raw = std::fs::read(dir.segment_path()).unwrap();
        assert_eq!(&raw, b"hello");

        // Flip the second byte: 'e' (0x65) → 'X' (0x58).
        dir.corrupt_byte_at(1, b'X');
        let raw = std::fs::read(dir.segment_path()).unwrap();
        assert_eq!(&raw, b"hXllo");
    }

    #[test]
    fn read_records_skips_blank_trailing_lines() {
        let dir = AuditDir::new();
        dir.append_raw_line("{\"x\":1}\n");
        dir.append_raw_line("\n"); // pure blank line at the tail
        let recs = dir.read_records();
        assert_eq!(recs.len(), 1);
    }
}

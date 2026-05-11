//! Ring-file segment writer the kernel uses for the spans + metrics
//! streams under `<data_dir>/observability/`.
//!
//! Spec: `v3/otel-observability.md §4.3`. Writes whole JSONL frames,
//! rotates at `segment_max_bytes`, drops the oldest closed segment
//! when the cumulative size exceeds `max_total_bytes`.
//!
//! Drop-oldest GC is the only retention policy V3 ships. The
//! observability surface is best-effort by definition (`INV-OTEL-08`)
//! — when disk pressure forces a choice, we drop the oldest local
//! data and keep the kernel running.

use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};

use thiserror::Error;

use crate::protocol::Stream;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// I/O failure inside the ring writer. Callers (the hub) treat these
/// as fail-quiet — the kernel must not crash, but the operator's
/// dashboard surfaces the drop counter.
#[derive(Debug, Error)]
pub enum RingError {
    /// Underlying filesystem I/O failure.
    #[error("ring io error on {path}: {source}")]
    Io {
        /// The path the writer was trying to operate on.
        path: PathBuf,
        /// The underlying [`std::io::Error`].
        #[source]
        source: std::io::Error,
    },
    /// `max_total_bytes` is so small that a single segment cannot
    /// be persisted; the writer permanently drops frames for this
    /// stream until the operator increases the cap.
    #[error("ring max_total_bytes {0} is below the minimum (4 × segment_max_bytes)")]
    CapTooSmall(u64),
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Per-stream knobs read from `[observability.ring]`.
#[derive(Debug, Clone, Copy)]
pub struct RingConfig {
    /// Maximum bytes per segment file. Default 16 MiB; range [1 MiB, 256 MiB].
    pub segment_max_bytes: u64,
    /// Maximum cumulative bytes across all segments for one stream.
    /// Default 512 MiB; range [16 MiB, 16 GiB].
    pub max_total_bytes:   u64,
}

impl Default for RingConfig {
    fn default() -> Self {
        Self {
            segment_max_bytes: 16 * 1024 * 1024,
            max_total_bytes:   512 * 1024 * 1024,
        }
    }
}

// ---------------------------------------------------------------------------
// SegmentWriter
// ---------------------------------------------------------------------------

/// Writer for one stream's ring directory. Owned by the hub thread;
/// not `Sync` — callers serialise writes via the hub's mutex.
#[derive(Debug)]
pub struct SegmentWriter {
    /// Stream type (spans vs metrics).
    stream:        Stream,
    /// Directory holding `*.jsonl` segments for this stream.
    dir:           PathBuf,
    /// Active segment file descriptor (buffered).
    active:        BufWriter<File>,
    /// Current sequence number of the active segment.
    active_seq:    u64,
    /// Bytes written into the active segment so far.
    active_bytes:  u64,
    /// Per-stream config.
    cfg:           RingConfig,
}

impl SegmentWriter {
    /// Open (or create) the stream's directory and the active
    /// segment. If existing closed segments are present, the next
    /// segment number resumes at `max_seq + 1`.
    pub fn open(root: &Path, stream: Stream, cfg: RingConfig) -> Result<Self, RingError> {
        if cfg.max_total_bytes < cfg.segment_max_bytes.saturating_mul(4) {
            return Err(RingError::CapTooSmall(cfg.max_total_bytes));
        }
        let dir = root.join(stream.subdir());
        std::fs::create_dir_all(&dir).map_err(|e| RingError::Io {
            path: dir.clone(),
            source: e,
        })?;
        // Find the highest existing seq.
        let next_seq = highest_seq(&dir).unwrap_or(0) + 1;
        let active_path = segment_path(&dir, next_seq);
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&active_path)
            .map_err(|e| RingError::Io { path: active_path.clone(), source: e })?;
        // Pick up any existing bytes in case the kernel restarted
        // mid-segment (file existed already; defensive — open
        // cycles call `next_seq` so this is normally 0).
        let initial_bytes = file
            .metadata()
            .map(|m| m.len())
            .map_err(|e| RingError::Io { path: active_path.clone(), source: e })?;
        Ok(Self {
            stream,
            dir,
            active: BufWriter::new(file),
            active_seq: next_seq,
            active_bytes: initial_bytes,
            cfg,
        })
    }

    /// Append one JSONL line (without a trailing newline). The writer
    /// adds the newline. On rotation, opens a new segment after
    /// running the drop-oldest GC.
    pub fn write_line(&mut self, line: &str) -> Result<(), RingError> {
        let mut frame = String::with_capacity(line.len() + 1);
        frame.push_str(line);
        frame.push('\n');
        self.active
            .write_all(frame.as_bytes())
            .map_err(|e| self.io_err(e))?;
        self.active_bytes = self.active_bytes.saturating_add(frame.len() as u64);
        if self.active_bytes >= self.cfg.segment_max_bytes {
            self.rotate()?;
        }
        Ok(())
    }

    /// Flush the active segment to the OS page cache.
    pub fn flush(&mut self) -> Result<(), RingError> {
        self.active
            .flush()
            .map_err(|e| self.io_err(e))?;
        Ok(())
    }

    /// Active segment's sequence number; useful for tests and
    /// `raxis doctor observability`.
    pub fn active_segment(&self) -> u64 { self.active_seq }

    /// Active segment byte length; useful for tests.
    pub fn active_bytes(&self) -> u64 { self.active_bytes }

    /// Ring root directory.
    pub fn dir(&self) -> &Path { &self.dir }

    fn rotate(&mut self) -> Result<(), RingError> {
        // Flush current writer first.
        self.flush()?;
        // Drop-oldest GC if total size has overgrown.
        self.gc_oldest()?;
        // Open the next sequence.
        let next_seq = self.active_seq + 1;
        let next_path = segment_path(&self.dir, next_seq);
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&next_path)
            .map_err(|e| RingError::Io { path: next_path.clone(), source: e })?;
        self.active = BufWriter::new(file);
        self.active_seq = next_seq;
        self.active_bytes = 0;
        Ok(())
    }

    /// While the cumulative size exceeds `max_total_bytes`, delete
    /// the lowest-numbered closed segment. The active segment is
    /// never deleted by GC.
    fn gc_oldest(&mut self) -> Result<(), RingError> {
        let mut total = self.dir_total_bytes();
        if total <= self.cfg.max_total_bytes {
            return Ok(());
        }
        loop {
            let mut entries = collect_closed_segments(&self.dir, self.active_seq);
            if entries.is_empty() {
                break;
            }
            entries.sort();
            let (oldest_seq, oldest_path) = entries.into_iter().next().expect("non-empty checked above");
            let removed = std::fs::metadata(&oldest_path)
                .map(|m| m.len())
                .unwrap_or(0);
            std::fs::remove_file(&oldest_path)
                .map_err(|e| RingError::Io { path: oldest_path.clone(), source: e })?;
            total = total.saturating_sub(removed);
            // Belt-and-braces tracing: we don't emit through the
            // observability surface itself (would recursively
            // re-enter the writer), just a stderr line.
            eprintln!(
                "{{\"level\":\"warn\",\"event\":\"observability_segment_dropped\",\
                 \"stream\":\"{}\",\"seq\":{},\"bytes_freed\":{}}}",
                self.stream.subdir(), oldest_seq, removed,
            );
            if total <= self.cfg.max_total_bytes {
                break;
            }
        }
        Ok(())
    }

    fn dir_total_bytes(&self) -> u64 {
        let mut total = 0u64;
        let Ok(read) = std::fs::read_dir(&self.dir) else {
            return 0;
        };
        for entry in read.flatten() {
            if let Ok(meta) = entry.metadata() {
                total = total.saturating_add(meta.len());
            }
        }
        total
    }

    fn io_err(&self, source: std::io::Error) -> RingError {
        RingError::Io {
            path: segment_path(&self.dir, self.active_seq),
            source,
        }
    }
}

impl Drop for SegmentWriter {
    fn drop(&mut self) {
        let _ = self.active.flush();
    }
}

/// Compute the segment path under `dir` for sequence `seq`.
pub fn segment_path(dir: &Path, seq: u64) -> PathBuf {
    dir.join(format!("{:06}.jsonl", seq))
}

/// Highest sequence number currently in `dir`, or `None` if empty.
fn highest_seq(dir: &Path) -> Option<u64> {
    let read = std::fs::read_dir(dir).ok()?;
    let mut max: Option<u64> = None;
    for entry in read.flatten() {
        if let Some(seq) = parse_seq_from_filename(&entry.file_name()) {
            max = Some(max.map(|m| m.max(seq)).unwrap_or(seq));
        }
    }
    max
}

/// Collect every closed segment under `dir` (i.e. seq < active_seq).
fn collect_closed_segments(dir: &Path, active_seq: u64) -> Vec<(u64, PathBuf)> {
    let mut out = Vec::new();
    let Ok(read) = std::fs::read_dir(dir) else { return out; };
    for entry in read.flatten() {
        if let Some(seq) = parse_seq_from_filename(&entry.file_name()) {
            if seq < active_seq {
                out.push((seq, entry.path()));
            }
        }
    }
    out
}

fn parse_seq_from_filename(name: &std::ffi::OsStr) -> Option<u64> {
    let s = name.to_str()?;
    let stem = s.strip_suffix(".jsonl")?;
    stem.parse::<u64>().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_lines_into_active_segment() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = RingConfig::default();
        let mut w = SegmentWriter::open(tmp.path(), Stream::Spans, cfg).unwrap();
        w.write_line(r#"{"kind":"span"}"#).unwrap();
        w.flush().unwrap();
        let path = segment_path(&w.dir, 1);
        assert!(path.exists());
        let bytes = std::fs::read_to_string(&path).unwrap();
        assert_eq!(bytes, "{\"kind\":\"span\"}\n");
    }

    #[test]
    fn rotates_when_segment_exceeds_max_bytes() {
        let tmp = tempfile::tempdir().unwrap();
        // Set tiny segment size to force rotation after one write.
        let cfg = RingConfig {
            segment_max_bytes: 16,
            max_total_bytes:   16 * 8,
        };
        let mut w = SegmentWriter::open(tmp.path(), Stream::Spans, cfg).unwrap();
        // 32-byte payload (incl newline) → forces rotation.
        let line = "x".repeat(31);
        w.write_line(&line).unwrap();
        assert!(w.active_segment() >= 2, "rotated to seq {}", w.active_segment());
    }

    #[test]
    fn drops_oldest_when_total_exceeds_cap() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = RingConfig {
            segment_max_bytes: 64,
            // 4× minimum cap; tight enough to force drop after a few rotations.
            max_total_bytes:   64 * 4,
        };
        let mut w = SegmentWriter::open(tmp.path(), Stream::Spans, cfg).unwrap();
        // Write enough to trigger several rotations and a GC pass.
        for i in 0..32 {
            let payload = format!(r#"{{"kind":"span","i":{}}}"#, i);
            // Pad to ~63 bytes so each segment holds exactly one frame.
            let pad_len = 63usize.saturating_sub(payload.len());
            let line = format!("{}{}", payload, "z".repeat(pad_len));
            w.write_line(&line).unwrap();
        }
        let total = w.dir_total_bytes();
        // After GC, total ≤ max_total_bytes (modulo the active segment's
        // current bytes which are accumulating; we just check that we
        // didn't unboundedly grow).
        assert!(total <= cfg.max_total_bytes + cfg.segment_max_bytes,
            "total {total} exceeds cap+1seg {}", cfg.max_total_bytes + cfg.segment_max_bytes);
    }

    #[test]
    fn rejects_too_small_total_cap() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = RingConfig {
            segment_max_bytes: 1024,
            max_total_bytes:   2048,   // < 4× segment
        };
        let err = SegmentWriter::open(tmp.path(), Stream::Spans, cfg).unwrap_err();
        assert!(matches!(err, RingError::CapTooSmall(_)));
    }

    #[test]
    fn resumes_at_max_existing_seq_plus_one() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("spans");
        std::fs::create_dir_all(&dir).unwrap();
        // Lay down two pre-existing segments.
        std::fs::write(dir.join("000005.jsonl"), b"old\n").unwrap();
        std::fs::write(dir.join("000007.jsonl"), b"newer\n").unwrap();
        let w = SegmentWriter::open(tmp.path(), Stream::Spans, RingConfig::default()).unwrap();
        assert_eq!(w.active_seq, 8, "next seq is max+1");
    }
}

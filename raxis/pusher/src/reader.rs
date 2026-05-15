//! Per-stream segment reader.
//!
//! Spec: `v3/otel-observability.md §12.3`.
//!
//! ## Behaviour
//!
//! - Lists segment files (`*.jsonl`) under the per-stream directory
//!   sorted lexicographically (the kernel's [`SegmentWriter`]
//!   guarantees zero-padded ascending names so lex order = age
//!   order).
//! - Reads frames from the active segment starting at the cursor's
//!   offset. Returns `None` when the file's current size has been
//!   read; the caller waits and retries.
//! - When the active segment is no longer the lexicographically-
//!   highest file (kernel rotated to the next segment), the reader
//!   reports "segment exhausted" so the caller can advance the
//!   cursor to the next segment.
//! - Tracks the number of frames consumed so the main loop can
//!   surface progress on `/healthz`.
//!
//! [`SegmentWriter`]: raxis_observability::ring::SegmentWriter

use std::fs::{self, File};
use std::io::{BufRead, BufReader, Seek, SeekFrom};
#[cfg(test)]
use std::path::Path;
use std::path::PathBuf;

use raxis_observability::protocol::Frame;

use crate::cursor::CursorEntry;

/// Reader state for one stream (spans or metrics).
pub struct Reader {
    /// Per-stream directory: `<ring_root>/{spans,metrics}`.
    dir: PathBuf,
    /// Currently-open segment file. `None` ⇒ no segment opened yet
    /// (cold start) or the active segment was just exhausted.
    handle: Option<OpenSegment>,
}

struct OpenSegment {
    /// File name (just the segment file, not the parent path).
    name: String,
    /// Buffered reader.
    inner: BufReader<File>,
    /// Bytes read from the file so far.
    offset: u64,
    /// Lines yielded.
    frames_yielded: u64,
}

impl Reader {
    /// Construct a reader rooted at `<ring_root>/{spans,metrics}/`.
    /// `dir` must exist before reading; if it doesn't yet (cold
    /// boot — kernel hasn't rotated its first segment), the reader
    /// reports "no segments" until the kernel creates it.
    pub fn new(dir: PathBuf) -> Self {
        Self { dir, handle: None }
    }

    /// True iff a segment file is currently open.
    pub fn segment_open(&self) -> bool {
        self.handle.is_some()
    }

    /// Currently-open segment file name, or `""` when none open.
    pub fn current_segment(&self) -> &str {
        self.handle.as_ref().map(|h| h.name.as_str()).unwrap_or("")
    }

    /// Cursor-style snapshot of the reader's progress within the
    /// current segment. Returns `None` if no segment is open.
    pub fn entry(&self) -> Option<CursorEntry> {
        self.handle.as_ref().map(|h| CursorEntry {
            segment: h.name.clone(),
            offset: h.offset,
        })
    }

    /// Total frames yielded since the most recent segment was
    /// opened. Diagnostic only — not persisted in the cursor.
    pub fn frames_yielded(&self) -> u64 {
        self.handle.as_ref().map(|h| h.frames_yielded).unwrap_or(0)
    }

    /// Open or re-open the cursor's segment. If the cursor entry is
    /// empty (first start), open the lex-smallest segment in the
    /// directory.
    pub fn open_from_cursor(&mut self, entry: &CursorEntry) -> Result<(), ReaderError> {
        if !self.dir.exists() {
            self.handle = None;
            return Ok(());
        }
        let name = if entry.segment.is_empty() {
            match self.lowest_segment()? {
                Some(s) => s,
                None => {
                    self.handle = None;
                    return Ok(());
                }
            }
        } else {
            entry.segment.clone()
        };
        let path = self.dir.join(&name);
        if !path.exists() {
            // Kernel rotated past the cursor's segment without us
            // catching the EOF. Advance to whatever's lowest now.
            return match self.lowest_segment()? {
                Some(s) => self.open_named(&s, 0),
                None => {
                    self.handle = None;
                    Ok(())
                }
            };
        }
        self.open_named(&name, entry.offset)
    }

    /// Read the next frame from the active segment. Returns `Ok(None)`
    /// when the file's current end has been reached. Caller waits
    /// (`tokio::time::sleep`) before re-polling.
    pub fn next_frame(&mut self) -> Result<Option<Frame>, ReaderError> {
        let Some(handle) = self.handle.as_mut() else {
            return Ok(None);
        };
        let mut buf = String::new();
        let pre = handle.offset;
        let n = handle
            .inner
            .read_line(&mut buf)
            .map_err(|e| ReaderError::Io {
                path: handle.name.clone(),
                source: e,
            })?;
        if n == 0 {
            return Ok(None);
        }
        // The kernel writes complete lines + flush; if the line
        // doesn't end in `\n`, the kernel was mid-write or
        // crashed. Rewind so the next call retries.
        if !buf.ends_with('\n') {
            // BufReader has consumed bytes from the file; rewind
            // the underlying file and the buffered position so the
            // next read sees the partial line as a fresh start.
            let target = pre;
            handle
                .inner
                .get_mut()
                .seek(SeekFrom::Start(target))
                .map_err(|e| ReaderError::Io {
                    path: handle.name.clone(),
                    source: e,
                })?;
            // Replace BufReader so its internal cache is reset.
            let f = File::open(self.dir.join(&handle.name)).map_err(|e| ReaderError::Io {
                path: handle.name.clone(),
                source: e,
            })?;
            let mut new_reader = BufReader::new(f);
            new_reader
                .seek(SeekFrom::Start(target))
                .map_err(|e| ReaderError::Io {
                    path: handle.name.clone(),
                    source: e,
                })?;
            handle.inner = new_reader;
            return Ok(None);
        }
        handle.offset = pre + n as u64;
        handle.frames_yielded += 1;
        let frame: Frame =
            serde_json::from_str(buf.trim_end_matches('\n')).map_err(|e| ReaderError::Decode {
                path: handle.name.clone(),
                source: e,
            })?;
        Ok(Some(frame))
    }

    /// True when the active segment has been rotated past — i.e.
    /// there is a strictly newer segment in the directory. The
    /// caller should `advance_segment` once `next_frame` returns
    /// `None` and `is_rotated` is true.
    pub fn is_rotated(&self) -> Result<bool, ReaderError> {
        let Some(handle) = self.handle.as_ref() else {
            return Ok(false);
        };
        let Some(highest) = self.highest_segment()? else {
            return Ok(false);
        };
        Ok(handle.name.as_str() < highest.as_str())
    }

    /// Close the active segment and open the lex-next one. Returns
    /// `true` when a next segment was opened, `false` when we ran
    /// out of segments.
    pub fn advance_segment(&mut self) -> Result<bool, ReaderError> {
        let Some(handle) = self.handle.take() else {
            return Ok(false);
        };
        let next = self.next_segment_after(&handle.name)?;
        if let Some(name) = next {
            self.open_named(&name, 0)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn open_named(&mut self, name: &str, at_offset: u64) -> Result<(), ReaderError> {
        let path = self.dir.join(name);
        let mut f = File::open(&path).map_err(|e| ReaderError::Io {
            path: name.to_owned(),
            source: e,
        })?;
        if at_offset > 0 {
            f.seek(SeekFrom::Start(at_offset))
                .map_err(|e| ReaderError::Io {
                    path: name.to_owned(),
                    source: e,
                })?;
        }
        self.handle = Some(OpenSegment {
            name: name.to_owned(),
            inner: BufReader::new(f),
            offset: at_offset,
            frames_yielded: 0,
        });
        Ok(())
    }

    fn list_segments(&self) -> Result<Vec<String>, ReaderError> {
        let mut out = Vec::new();
        for entry in fs::read_dir(&self.dir).map_err(|e| ReaderError::Io {
            path: self.dir.display().to_string(),
            source: e,
        })? {
            let entry = entry.map_err(|e| ReaderError::Io {
                path: self.dir.display().to_string(),
                source: e,
            })?;
            if !entry.file_type().map(|t| t.is_file()).unwrap_or(false) {
                continue;
            }
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.ends_with(".jsonl") {
                out.push(name);
            }
        }
        out.sort();
        Ok(out)
    }

    fn lowest_segment(&self) -> Result<Option<String>, ReaderError> {
        Ok(self.list_segments()?.into_iter().next())
    }

    fn highest_segment(&self) -> Result<Option<String>, ReaderError> {
        Ok(self.list_segments()?.into_iter().last())
    }

    fn next_segment_after(&self, current: &str) -> Result<Option<String>, ReaderError> {
        Ok(self
            .list_segments()?
            .into_iter()
            .find(|n| n.as_str() > current))
    }

    /// File-size of the currently-open segment, used by the main
    /// loop to bound the read window. Required for tests that
    /// assert "the reader does not over-read into bytes the kernel
    /// hasn't flushed yet".
    pub fn current_size(&mut self) -> Result<u64, ReaderError> {
        let Some(handle) = self.handle.as_mut() else {
            return Ok(0);
        };
        let f = File::open(self.dir.join(&handle.name)).map_err(|e| ReaderError::Io {
            path: handle.name.clone(),
            source: e,
        })?;
        let len = f
            .metadata()
            .map_err(|e| ReaderError::Io {
                path: handle.name.clone(),
                source: e,
            })?
            .len();
        let _ = f; // dropped to release the FD
        Ok(len)
    }

    /// Read up to `at_most` frames in one tight call. Mostly useful
    /// for tests that drive the reader synchronously.
    pub fn drain_up_to(&mut self, at_most: usize) -> Result<Vec<Frame>, ReaderError> {
        let mut out = Vec::with_capacity(at_most);
        for _ in 0..at_most {
            match self.next_frame()? {
                Some(f) => out.push(f),
                None => break,
            }
        }
        Ok(out)
    }
}

/// Reader-side errors. Surface to the main loop, which logs and
/// either retries (transient I/O) or skips the offending segment
/// (corrupt frame).
#[derive(Debug, thiserror::Error)]
pub enum ReaderError {
    /// Filesystem error.
    #[error("io error reading segment {path}: {source}")]
    Io {
        /// Segment path or directory we were reading.
        path: String,
        /// I/O source.
        #[source]
        source: std::io::Error,
    },
    /// JSON decode error on a fully-flushed line. Indicates the
    /// kernel wrote a malformed frame; the pusher logs and skips.
    #[error("decode error in segment {path}: {source}")]
    Decode {
        /// Segment file name.
        path: String,
        /// JSON source.
        #[source]
        source: serde_json::Error,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use raxis_observability::protocol::{hex_span_id, hex_trace_id, Frame, SCHEMA_VERSION};
    use raxis_observability::types::{
        AttrMap, MetricData, MetricName, MetricType, SpanData, SpanKind, SpanName, SpanStatus, Unit,
    };
    use raxis_observability::DataPoint;
    use std::io::Write;

    fn write_segment(dir: &Path, name: &str, lines: &[&str]) {
        std::fs::create_dir_all(dir).unwrap();
        let mut f = std::fs::File::create(dir.join(name)).unwrap();
        for line in lines {
            f.write_all(line.as_bytes()).unwrap();
            f.write_all(b"\n").unwrap();
        }
        f.sync_all().unwrap();
    }

    fn span_frame() -> Frame {
        let span = SpanData {
            trace_id: [1; 16],
            span_id: [2; 8],
            parent_span_id: None,
            name: SpanName::IntentAdmission,
            kind: SpanKind::Internal,
            start_unix_nanos: 0,
            end_unix_nanos: 1,
            status: SpanStatus::Ok,
            status_message: None,
            attrs: AttrMap::new(),
            events: vec![],
        };
        Frame::Span {
            schema: SCHEMA_VERSION,
            kernel_version: "0.1.0".into(),
            trace_id: hex_trace_id([1; 16]),
            span_id: hex_span_id([2; 8]),
            span,
        }
    }

    fn metric_frame() -> Frame {
        Frame::Metric {
            schema: SCHEMA_VERSION,
            kernel_version: "0.1.0".into(),
            metric: MetricData {
                name: MetricName::IntentAdmissionTotal,
                metric_type: MetricType::Counter,
                unit: Unit::None,
                labels: AttrMap::new(),
                datapoint: DataPoint::Sum { value: 1.0 },
                unix_nanos: 0,
            },
        }
    }

    #[test]
    fn cold_dir_returns_no_segments() {
        let tmp = tempfile::tempdir().unwrap();
        let mut r = Reader::new(tmp.path().join("spans"));
        r.open_from_cursor(&CursorEntry::default()).unwrap();
        assert!(!r.segment_open());
        assert!(r.next_frame().unwrap().is_none());
    }

    #[test]
    fn opens_lowest_segment_on_cold_start() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("spans");
        let f = serde_json::to_string(&span_frame()).unwrap();
        write_segment(&dir, "000003.jsonl", &[&f]);
        write_segment(&dir, "000001.jsonl", &[&f]);
        write_segment(&dir, "000002.jsonl", &[&f]);
        let mut r = Reader::new(dir);
        r.open_from_cursor(&CursorEntry::default()).unwrap();
        assert_eq!(r.current_segment(), "000001.jsonl");
    }

    #[test]
    fn reads_frames_in_order() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("spans");
        let s = serde_json::to_string(&span_frame()).unwrap();
        write_segment(&dir, "000001.jsonl", &[&s, &s, &s]);
        let mut r = Reader::new(dir);
        r.open_from_cursor(&CursorEntry::default()).unwrap();
        let frames = r.drain_up_to(10).unwrap();
        assert_eq!(frames.len(), 3);
        assert!(matches!(frames[0], Frame::Span { .. }));
    }

    #[test]
    fn resumes_at_cursor_offset() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("metrics");
        let m = serde_json::to_string(&metric_frame()).unwrap();
        write_segment(&dir, "000001.jsonl", &[&m, &m, &m]);
        let mut r = Reader::new(dir.clone());
        // Skip the first line: offset = len(line) + 1 (newline).
        let one_line_size = (m.len() + 1) as u64;
        let entry = CursorEntry {
            segment: "000001.jsonl".into(),
            offset: one_line_size,
        };
        r.open_from_cursor(&entry).unwrap();
        let rest = r.drain_up_to(10).unwrap();
        assert_eq!(rest.len(), 2);
    }

    #[test]
    fn detects_partial_line_and_does_not_consume_it() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("spans");
        std::fs::create_dir_all(&dir).unwrap();
        // Whole frame followed by a half-written one (no \n).
        let s = serde_json::to_string(&span_frame()).unwrap();
        let half = "{\"kind\":\"span\",\"schema\":1,\"kernel_version".to_string();
        let path = dir.join("000001.jsonl");
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(s.as_bytes()).unwrap();
        f.write_all(b"\n").unwrap();
        f.write_all(half.as_bytes()).unwrap();
        f.sync_all().unwrap();
        let mut r = Reader::new(dir);
        r.open_from_cursor(&CursorEntry::default()).unwrap();
        let first = r.next_frame().unwrap();
        assert!(first.is_some(), "first complete line yields a frame");
        let second = r.next_frame().unwrap();
        assert!(second.is_none(), "partial line is held back");
        // Now finish the line — re-poll yields it.
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        // Append the rest of a valid frame.
        let rest = format!(
            r#"":"0.1.0","trace_id":"{}","span_id":"{}","span":{}}}"#,
            hex_trace_id([1; 16]),
            hex_span_id([2; 8]),
            serde_json::to_string(&match span_frame() {
                Frame::Span { span, .. } => span,
                _ => unreachable!(),
            })
            .unwrap(),
        );
        f.write_all(rest.as_bytes()).unwrap();
        f.write_all(b"\n").unwrap();
        f.sync_all().unwrap();
        let third = r.next_frame().unwrap();
        assert!(
            third.is_some(),
            "after newline arrives, the held line yields"
        );
    }

    #[test]
    fn detects_segment_rotation_and_advances() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("metrics");
        let m = serde_json::to_string(&metric_frame()).unwrap();
        write_segment(&dir, "000001.jsonl", &[&m]);
        write_segment(&dir, "000002.jsonl", &[&m]);
        let mut r = Reader::new(dir);
        r.open_from_cursor(&CursorEntry::default()).unwrap();
        let _ = r.drain_up_to(10).unwrap();
        assert!(r.is_rotated().unwrap());
        let advanced = r.advance_segment().unwrap();
        assert!(advanced);
        assert_eq!(r.current_segment(), "000002.jsonl");
        let frames = r.drain_up_to(10).unwrap();
        assert_eq!(frames.len(), 1);
    }

    #[test]
    fn corrupt_frame_returns_decode_error() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("spans");
        write_segment(&dir, "000001.jsonl", &["{ this is not valid json }"]);
        let mut r = Reader::new(dir);
        r.open_from_cursor(&CursorEntry::default()).unwrap();
        let err = r.next_frame().unwrap_err();
        matches!(err, ReaderError::Decode { .. });
    }
}

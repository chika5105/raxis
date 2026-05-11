//! `cursor.toml` — pusher's at-most-once resume bookmark.
//!
//! Spec: `v3/otel-observability.md §4.2, §12.3`.
//!
//! ## File format
//!
//! ```toml
//! schema = 1
//! pusher_version = "0.1.0"
//! last_export_unix = 1715000000
//! consecutive_failures = 0
//!
//! [spans]
//! segment = "000123.jsonl"
//! offset = 65535
//!
//! [metrics]
//! segment = "000098.jsonl"
//! offset = 12345
//! ```
//!
//! ## Persistence semantics
//!
//! Per `INV-OTEL-04`: cursor is fsynced after every successful OTLP
//! batch ack. A pusher crash before ack re-exports the un-acked
//! tail on restart. OTel collectors are idempotent on
//! `(trace_id, span_id)` so duplicate-on-replay is harmless.
//!
//! Concretely, every persist writes to `cursor.toml.tmp` then
//! `rename`s — atomic on POSIX — so a partial write never corrupts
//! the cursor.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use raxis_observability::protocol::Stream;
use serde::{Deserialize, Serialize};

/// Cursor file schema version. Bump on backwards-incompatible
/// changes. Mismatched schema ⇒ pusher logs and resets.
pub const CURSOR_SCHEMA: u32 = 1;

/// Per-stream resume position.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct CursorEntry {
    /// File name of the last partially-or-fully consumed segment;
    /// e.g. `"000001.jsonl"`. Empty ⇒ start at the lowest existing
    /// segment.
    #[serde(default)]
    pub segment: String,
    /// Byte offset within `segment`. `0` ⇒ start of file.
    #[serde(default)]
    pub offset: u64,
}

/// Top-level `cursor.toml`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Cursor {
    /// Persistence schema version.
    #[serde(default = "default_cursor_schema")]
    pub schema: u32,
    /// Pusher binary version that last persisted the cursor.
    /// Diagnostic only; never compared to ours on resume.
    #[serde(default)]
    pub pusher_version: String,
    /// Last successful OTLP-export wallclock (UNIX seconds). `0`
    /// ⇒ never exported successfully on this cursor.
    #[serde(default)]
    pub last_export_unix: i64,
    /// Number of consecutive failed export attempts. Cleared on
    /// success.
    #[serde(default)]
    pub consecutive_failures: u32,
    /// Spans stream resume point.
    #[serde(default)]
    pub spans: CursorEntry,
    /// Metrics stream resume point.
    #[serde(default)]
    pub metrics: CursorEntry,
}

fn default_cursor_schema() -> u32 { CURSOR_SCHEMA }

impl Cursor {
    /// Load the cursor from disk; if the file is missing, return a
    /// zeroed cursor (start of stream). If the file exists but
    /// fails to parse, return `Err` so the operator can repair —
    /// silently resetting would re-ship already-acked batches.
    pub fn load_or_init(path: &Path) -> Result<Self, CursorError> {
        if !path.exists() {
            return Ok(Self::default_at_zero());
        }
        let body = fs::read_to_string(path)
            .map_err(|e| CursorError::Read { path: path.to_owned(), source: e })?;
        let cur: Cursor = toml::from_str(&body)
            .map_err(|e| CursorError::Parse { path: path.to_owned(), source: e })?;
        if cur.schema != CURSOR_SCHEMA {
            return Err(CursorError::SchemaMismatch {
                path:     path.to_owned(),
                expected: CURSOR_SCHEMA,
                actual:   cur.schema,
            });
        }
        Ok(cur)
    }

    /// Atomic write: `<path>.tmp` then `rename` to `<path>`. The
    /// tempfile is `fsync`'d before the rename so a power loss
    /// between `write` and `rename` cannot leave a half-written
    /// cursor on disk.
    pub fn persist(&self, path: &Path) -> Result<(), CursorError> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| CursorError::Persist {
                    path:   path.to_owned(),
                    source: e,
                })?;
        }
        let body = toml::to_string_pretty(self)
            .map_err(|e| CursorError::Encode { path: path.to_owned(), source: e })?;
        let tmp = path.with_extension("toml.tmp");
        {
            let mut f = fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&tmp)
                .map_err(|e| CursorError::Persist { path: tmp.clone(), source: e })?;
            f.write_all(body.as_bytes())
                .map_err(|e| CursorError::Persist { path: tmp.clone(), source: e })?;
            f.sync_all()
                .map_err(|e| CursorError::Persist { path: tmp.clone(), source: e })?;
        }
        fs::rename(&tmp, path)
            .map_err(|e| CursorError::Persist { path: path.to_owned(), source: e })?;
        Ok(())
    }

    /// Mutable accessor for the per-stream entry, so the main loop
    /// can advance bytes after each successful read.
    pub fn entry_mut(&mut self, stream: Stream) -> &mut CursorEntry {
        match stream {
            Stream::Spans   => &mut self.spans,
            Stream::Metrics => &mut self.metrics,
        }
    }

    /// Read-only accessor.
    pub fn entry(&self, stream: Stream) -> &CursorEntry {
        match stream {
            Stream::Spans   => &self.spans,
            Stream::Metrics => &self.metrics,
        }
    }

    /// On a successful OTLP export ack: bump `last_export_unix`,
    /// clear the failure counter.
    pub fn record_success(&mut self, now_unix: i64) {
        self.last_export_unix = now_unix;
        self.consecutive_failures = 0;
    }

    /// On a failed OTLP export attempt: bump the failure counter.
    /// Saturates at `u32::MAX`.
    pub fn record_failure(&mut self) {
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
    }

    fn default_at_zero() -> Self {
        Self {
            schema:               CURSOR_SCHEMA,
            pusher_version:       env!("CARGO_PKG_VERSION").to_owned(),
            last_export_unix:     0,
            consecutive_failures: 0,
            spans:                CursorEntry::default(),
            metrics:              CursorEntry::default(),
        }
    }
}

/// Errors raised while loading or persisting [`Cursor`].
#[derive(Debug, thiserror::Error)]
pub enum CursorError {
    /// Filesystem read failure.
    #[error("cursor read failed: {path:?}: {source}")]
    Read {
        /// Cursor path.
        path:   PathBuf,
        /// IO source.
        #[source] source: std::io::Error,
    },
    /// TOML parse failure on a cursor file that exists.
    #[error("cursor parse failed: {path:?}: {source}")]
    Parse {
        /// Cursor path.
        path:   PathBuf,
        /// TOML source.
        #[source] source: toml::de::Error,
    },
    /// Cursor schema mismatch — refuses to load.
    #[error("cursor schema mismatch at {path:?}: expected {expected}, got {actual}")]
    SchemaMismatch {
        /// Cursor path.
        path:     PathBuf,
        /// Expected schema (current binary).
        expected: u32,
        /// Schema found on disk.
        actual:   u32,
    },
    /// Filesystem write or rename failure.
    #[error("cursor persist failed: {path:?}: {source}")]
    Persist {
        /// Path attempted (tempfile or final).
        path:   PathBuf,
        /// IO source.
        #[source] source: std::io::Error,
    },
    /// TOML serialise failure.
    #[error("cursor encode failed: {path:?}: {source}")]
    Encode {
        /// Cursor path.
        path:   PathBuf,
        /// TOML serialise source.
        #[source] source: toml::ser::Error,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_cursor_initialises_to_zero() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cursor.toml");
        let cur = Cursor::load_or_init(&path).unwrap();
        assert_eq!(cur.schema, CURSOR_SCHEMA);
        assert_eq!(cur.spans, CursorEntry::default());
        assert_eq!(cur.metrics, CursorEntry::default());
    }

    #[test]
    fn round_trip_through_disk() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cursor.toml");
        let mut cur = Cursor::default_at_zero();
        cur.spans = CursorEntry { segment: "000007.jsonl".into(), offset: 4096 };
        cur.metrics = CursorEntry { segment: "000003.jsonl".into(), offset: 1234 };
        cur.record_success(1_715_000_000);
        cur.persist(&path).unwrap();

        let back = Cursor::load_or_init(&path).unwrap();
        assert_eq!(back.spans, cur.spans);
        assert_eq!(back.metrics, cur.metrics);
        assert_eq!(back.last_export_unix, 1_715_000_000);
    }

    #[test]
    fn schema_mismatch_is_loud() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cursor.toml");
        std::fs::write(&path, "schema = 999\n").unwrap();
        let err = Cursor::load_or_init(&path).unwrap_err();
        match err {
            CursorError::SchemaMismatch { actual, expected, .. } => {
                assert_eq!(actual, 999);
                assert_eq!(expected, CURSOR_SCHEMA);
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn record_failure_saturates() {
        let mut c = Cursor::default_at_zero();
        c.consecutive_failures = u32::MAX - 1;
        c.record_failure();
        c.record_failure();
        c.record_failure();
        assert_eq!(c.consecutive_failures, u32::MAX);
    }

    #[test]
    fn record_success_resets_failure_counter() {
        let mut c = Cursor::default_at_zero();
        c.record_failure();
        c.record_failure();
        assert_eq!(c.consecutive_failures, 2);
        c.record_success(42);
        assert_eq!(c.consecutive_failures, 0);
        assert_eq!(c.last_export_unix, 42);
    }

    #[test]
    fn entry_accessors_work() {
        let mut c = Cursor::default_at_zero();
        c.entry_mut(Stream::Spans).segment = "abc".into();
        assert_eq!(c.entry(Stream::Spans).segment, "abc");
        assert_eq!(c.entry(Stream::Metrics).segment, "");
    }
}

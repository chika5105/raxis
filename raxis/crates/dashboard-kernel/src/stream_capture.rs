//! Per-session agent-output capture (`v2_extended_gaps.md §4.3`
//! "Agent stream capture").
//!
//! # What this module owns
//!
//! 1. A bounded **on-disk file ring** at
//!    `<data_dir>/streams/<session_id>.jsonl`. Each line is a
//!    JSON-serialised [`StreamEvent`]. When a file would exceed
//!    [`CaptureConfig::max_file_bytes`], the module rewrites it
//!    keeping only the most recent ~50 % of lines (see
//!    `SessionStreamCapture::compact_locked`). One compaction
//!    per overflow — not per append — keeps amortised cost flat.
//!
//! 2. A per-session **broadcast channel** sized at
//!    [`CaptureConfig::broadcast_capacity`]. The dashboard's SSE
//!    handler subscribes here for live frames; lagged subscribers
//!    receive a `RecvError::Lagged(n)` and continue (the
//!    handler's `lagged` SSE frame surfaces the lag count to the
//!    operator).
//!
//! 3. A **tail loader** ([`SessionStreamCapture::tail`]) that
//!    reads the last `n` events from disk for a session. The SSE
//!    handler calls this before attaching the live subscriber so
//!    a freshly-connected operator sees recent context.
//!
//! # Invariants
//!
//! * **No data loss between fsyncs.** Every successful
//!   [`SessionStreamCapture::append`] flushes the writer before
//!   returning; on overflow the compaction is `fsync`-ed before
//!   the new line is appended (so a crash during compaction
//!   leaves either the old file or the compacted one, never a
//!   half-rewritten state).
//! * **Bounded memory.** The capture holds nothing per-session
//!   beyond the broadcast sender; the file ring lives on disk.
//! * **Single producer per session.** The kernel's gateway
//!   bridge is the sole writer per session id; the broadcast
//!   sender is `Clone` so subscribe-side fan-out is free.

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use parking_lot::Mutex;
use raxis_dashboard::stream::{StreamEvent, StreamSubscription};
use tokio::sync::broadcast;

/// Tunables for the capture. Defaults match
/// `v2_extended_gaps.md §4.3`.
#[derive(Debug, Clone)]
pub struct CaptureConfig {
    /// Per-session file ring max size (bytes). 10 MB by default.
    pub max_file_bytes: u64,
    /// Per-session broadcast channel capacity. 500 by default.
    pub broadcast_capacity: usize,
}

impl Default for CaptureConfig {
    fn default() -> Self {
        Self {
            max_file_bytes: 10 * 1024 * 1024,
            broadcast_capacity: 500,
        }
    }
}

/// Per-session state held by the capture. Each session has its
/// own append-only file handle and broadcast sender. The
/// session map is keyed by session_id and protected by a
/// `Mutex` for cheap insert / lookup.
struct SessionState {
    file: Mutex<File>,
    file_size: Mutex<u64>,
    sender: broadcast::Sender<StreamEvent>,
}

/// Process-wide capture. Hold via `Arc` from both the kernel's
/// gateway bridge (writer) and the dashboard data layer
/// (subscriber).
pub struct SessionStreamCapture {
    streams_dir: PathBuf,
    cfg: CaptureConfig,
    sessions: Mutex<HashMap<String, Arc<SessionState>>>,
}

impl SessionStreamCapture {
    /// Build a fresh capture rooted at `<data_dir>/streams/`.
    /// The directory is created if missing.
    pub fn new(data_dir: &Path, cfg: CaptureConfig) -> std::io::Result<Arc<Self>> {
        let streams_dir = data_dir.join("streams");
        std::fs::create_dir_all(&streams_dir)?;
        Ok(Arc::new(Self {
            streams_dir,
            cfg,
            sessions: Mutex::new(HashMap::new()),
        }))
    }

    /// Append `evt` to the session's ring + broadcast it.
    ///
    /// On disk-full or other I/O errors the broadcast still
    /// fires (so live SSE subscribers do not lose the event)
    /// but the function returns `Err` so the caller can decide
    /// whether to retry or surface the failure.
    pub fn append(&self, session_id: &str, evt: StreamEvent) -> std::io::Result<()> {
        let state = self.session_state(session_id)?;
        // Broadcast first so subscribers aren't blocked on disk.
        let _ = state.sender.send(evt.clone());
        // Then persist.
        let line = serde_json::to_string(&evt).unwrap_or_else(|_| "{}".to_owned());
        let bytes = line.as_bytes();
        let line_len = bytes.len() as u64 + 1; // +1 for newline

        let mut size = state.file_size.lock();
        if *size + line_len > self.cfg.max_file_bytes {
            // Compact: rewrite keeping only the most-recent
            // half of the file (line-aligned).
            self.compact_locked(session_id, &state)?;
            *size = state.file.lock().metadata().map(|m| m.len()).unwrap_or(0);
        }
        let mut f = state.file.lock();
        f.seek(SeekFrom::End(0))?;
        f.write_all(bytes)?;
        f.write_all(b"\n")?;
        f.flush()?;
        *size += line_len;
        Ok(())
    }

    /// Read the last `n` events from the session's ring.
    /// Returns `Ok(vec![])` when the file is missing (session
    /// never produced output) — never an error.
    pub fn tail(&self, session_id: &str, n: usize) -> Vec<StreamEvent> {
        let path = self.session_path(session_id);
        let Ok(file) = File::open(&path) else {
            return Vec::new();
        };
        let reader = BufReader::new(file);
        let mut lines: Vec<String> = reader.lines().map_while(Result::ok).collect();
        if lines.len() > n {
            let cut = lines.len() - n;
            lines.drain(0..cut);
        }
        lines
            .into_iter()
            .filter_map(|l| serde_json::from_str::<StreamEvent>(&l).ok())
            .collect()
    }

    /// Subscribe to live events. Returns `None` when no session
    /// state exists yet (no append has ever been called for
    /// this id). Callers that need lazy attach should call
    /// [`Self::ensure_session`] first.
    pub fn subscribe(&self, session_id: &str) -> Option<StreamSubscription> {
        let g = self.sessions.lock();
        g.get(session_id)
            .map(|s| StreamSubscription::new(s.sender.subscribe()))
    }

    /// Allocate the session state if it does not already exist.
    /// Returns the broadcast sender for callers that want to
    /// hold a clone (e.g. the kernel's gateway bridge).
    pub fn ensure_session(
        &self,
        session_id: &str,
    ) -> std::io::Result<broadcast::Sender<StreamEvent>> {
        let state = self.session_state(session_id)?;
        Ok(state.sender.clone())
    }

    /// On-disk path for one session.
    pub fn session_path(&self, session_id: &str) -> PathBuf {
        // Sanitise session_id: only `[A-Za-z0-9_.-]`. The
        // gateway bridge owns the source of truth for session
        // ids so this is defence in depth.
        let safe: String = session_id
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '.' || *c == '-')
            .collect();
        self.streams_dir.join(format!("{safe}.jsonl"))
    }

    // -------------------------------------------------------------------
    // Internals
    // -------------------------------------------------------------------

    /// Get or create the session state. Opens the file in
    /// append mode and refreshes `file_size` from the on-disk
    /// metadata.
    fn session_state(&self, session_id: &str) -> std::io::Result<Arc<SessionState>> {
        {
            let g = self.sessions.lock();
            if let Some(s) = g.get(session_id) {
                return Ok(Arc::clone(s));
            }
        }
        let path = self.session_path(session_id);
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .append(true)
            .open(&path)?;
        let size = file.metadata().map(|m| m.len()).unwrap_or(0);
        let (tx, _) = broadcast::channel(self.cfg.broadcast_capacity);
        let state = Arc::new(SessionState {
            file: Mutex::new(file),
            file_size: Mutex::new(size),
            sender: tx,
        });
        let mut g = self.sessions.lock();
        Ok(g.entry(session_id.to_owned()).or_insert(state).clone())
    }

    /// Rewrite the session file keeping only the most recent
    /// 50 % of lines. Holds the file lock for the duration so
    /// no concurrent append slips in.
    fn compact_locked(&self, session_id: &str, state: &SessionState) -> std::io::Result<()> {
        let path = self.session_path(session_id);
        let lines: Vec<String> = {
            let mut f = state.file.lock();
            f.seek(SeekFrom::Start(0))?;
            BufReader::new(&*f).lines().map_while(Result::ok).collect()
        };
        let cut = lines.len() / 2;
        let kept = &lines[cut..];
        let tmp_path = path.with_extension("jsonl.tmp");
        {
            let mut tmp = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&tmp_path)?;
            for l in kept {
                tmp.write_all(l.as_bytes())?;
                tmp.write_all(b"\n")?;
            }
            tmp.sync_all()?;
        }
        std::fs::rename(&tmp_path, &path)?;
        // Reopen the append handle on the new file.
        let new_file = OpenOptions::new()
            .create(true)
            .read(true)
            .append(true)
            .open(&path)?;
        *state.file.lock() = new_file;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn evt(kind: &str, n: u64) -> StreamEvent {
        StreamEvent {
            at_ms: n,
            kind: kind.into(),
            payload: serde_json::json!({"n": n}),
        }
    }

    #[test]
    fn append_then_tail_round_trips() {
        let tmp = tempfile::tempdir().unwrap();
        let cap = SessionStreamCapture::new(tmp.path(), CaptureConfig::default()).unwrap();
        for i in 0..5 {
            cap.append("sess-1", evt("model_chunk", i)).unwrap();
        }
        let tail = cap.tail("sess-1", 10);
        assert_eq!(tail.len(), 5);
        assert_eq!(tail[0].at_ms, 0);
        assert_eq!(tail[4].at_ms, 4);
    }

    #[test]
    fn tail_clamps_to_recent_n() {
        let tmp = tempfile::tempdir().unwrap();
        let cap = SessionStreamCapture::new(tmp.path(), CaptureConfig::default()).unwrap();
        for i in 0..10 {
            cap.append("sess-2", evt("model_chunk", i)).unwrap();
        }
        let tail = cap.tail("sess-2", 3);
        assert_eq!(tail.len(), 3);
        assert_eq!(tail[0].at_ms, 7);
        assert_eq!(tail[2].at_ms, 9);
    }

    #[test]
    fn missing_session_tail_returns_empty() {
        let tmp = tempfile::tempdir().unwrap();
        let cap = SessionStreamCapture::new(tmp.path(), CaptureConfig::default()).unwrap();
        assert!(cap.tail("never-existed", 10).is_empty());
    }

    #[tokio::test]
    async fn append_broadcasts_to_subscribers() {
        let tmp = tempfile::tempdir().unwrap();
        let cap = SessionStreamCapture::new(tmp.path(), CaptureConfig::default()).unwrap();
        // Force the session state to exist before subscribe so
        // the channel is allocated.
        cap.ensure_session("sess-3").unwrap();
        let mut sub = cap.subscribe("sess-3").expect("subscribe");
        // Drive append on a background task so the recv future
        // has something to wait on.
        let cap_clone = Arc::clone(&cap);
        let handle = tokio::spawn(async move {
            cap_clone.append("sess-3", evt("tool_call", 7)).unwrap();
        });
        let got = sub.recv().await.unwrap().unwrap();
        assert_eq!(got.kind, "tool_call");
        assert_eq!(got.at_ms, 7);
        handle.await.unwrap();
    }

    #[test]
    fn compaction_kicks_in_when_max_file_bytes_exceeded() {
        let tmp = tempfile::tempdir().unwrap();
        // Tiny ring so compaction triggers after a handful of
        // appends.
        let cfg = CaptureConfig {
            max_file_bytes: 256,
            broadcast_capacity: 16,
        };
        let cap = SessionStreamCapture::new(tmp.path(), cfg).unwrap();
        for i in 0..50 {
            cap.append("sess-4", evt("x", i)).unwrap();
        }
        let path = cap.session_path("sess-4");
        let size = std::fs::metadata(&path).unwrap().len();
        assert!(
            size <= 256 + 64,
            "file size {size} should stay near the cap (256B); cap busted"
        );
        // Tail still returns recent events (compaction kept the
        // newer half).
        let tail = cap.tail("sess-4", 50);
        assert!(!tail.is_empty(), "tail must not be empty after compaction");
        assert!(
            tail.last().unwrap().at_ms >= 40,
            "tail must include the most recent events"
        );
    }
}

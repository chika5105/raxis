//! Per-session lifecycle capture — the operator-facing
//! post-mortem ring (`specs/v3/session-capture.md`).
//!
//! # What this module owns
//!
//! 1. A bounded **on-disk file ring** at
//!    `<data_dir>/session-capture/<session_id>.ndjson`. Each
//!    line is a JSON-serialised [`SessionCaptureRecord`]. The
//!    file is keyed by `session_id` so the buffer is local to
//!    one session for its entire lifetime AND its entire
//!    post-mortem window.
//!
//!    When a file would exceed
//!    [`SessionCaptureConfig::max_bytes_per_session`] OR
//!    [`SessionCaptureConfig::max_records_per_session`], the
//!    module compacts it in place keeping only the most recent
//!    ~50 % of records (see
//!    `SessionCapture::compact_locked`). One compaction per
//!    overflow — not per append — keeps amortised cost flat.
//!
//! 2. A per-session **broadcast channel** for live SSE
//!    subscribers (the dashboard's Post-mortem tab can show
//!    new transitions live alongside the existing audit-stream
//!    SSE without competing on key shape).
//!
//! 3. A **tail loader** ([`SessionCapture::tail`]) that reads
//!    the last `n` records from disk. The dashboard route
//!    calls this on every
//!    `GET /api/sessions/:session_id/capture` request.
//!
//! # Why a separate module from `SessionStreamCapture`
//!
//! [`crate::SessionStreamCapture`] mirrors **agent-output
//! stream events** (e.g. planner LLM bytes, tool-call
//! envelopes, audit-bridged frames) to the dashboard, keyed
//! by `session_id`. The bytes are dense and tuned for the
//! live `/api/sessions/:id/stream` SSE — a captured stream is
//! best viewed as it happened.
//!
//! This module captures **session lifecycle records**: FSM
//! transitions, KSB snapshots, and the audit-event tail. The
//! records are sparse, JSON-friendly, and tuned for the
//! Post-mortem view — what state did the session pass
//! through, in what order, with what audit signal? The two
//! surfaces serve different debug needs:
//!
//! * `SessionStreamCapture` — "show me the bytes / tool calls
//!   from this session as they happened".
//! * `SessionCapture`       — "show me the lifecycle / state
//!   transitions / audit signal from this session, including
//!   after it terminated".
//!
//! Sharing the surface would conflate the two views and force
//! one to win on record shape; keeping them parallel keeps
//! both operator-actionable.
//!
//! # Invariants
//!
//! * **Bounded disk per session.** Compaction enforces both
//!   the `max_bytes_per_session` AND `max_records_per_session`
//!   ceilings. `INV-DASHBOARD-SESSION-CAPTURE-FIXED-RING-01`.
//! * **Bounded memory.** The capture holds nothing per-session
//!   beyond the broadcast sender + a `parking_lot::Mutex<File>`
//!   pair; the file ring lives on disk.
//! * **Append survives session termination.** Because the
//!   writer is the kernel observer (NOT the planner VM),
//!   records persist after the session reaches
//!   Completed/Failed/Aborted — operators can inspect them
//!   for the lifetime of the ring, which is the primary debug
//!   use case the user asked for.
//!   `INV-DASHBOARD-SESSION-CAPTURE-PERSIST-AFTER-TERMINATION-01`.
//! * **Per-session namespace.** Records appended for session
//!   A never bleed into session B's tail.
//!   `INV-DASHBOARD-SESSION-CAPTURE-NAMESPACED-PER-SESSION-01`.
//! * **Single observer per kernel.** The kernel main loop is
//!   the sole writer; the broadcast sender is `Clone` so
//!   subscribe-side fan-out is free.

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;

/// One captured session-lifecycle datum. Three kinds, picked
/// for the smallest set that still gives an operator
/// actionable post-mortem visibility:
///
///   * `kind = "fsm_transition"` — payload is
///     `{ from, to, reason, at_ms }`.
///   * `kind = "audit_event"` — payload is the audit-event
///     summary `{ event_kind, severity, summary }` (the chain
///     itself is the source of truth; this is the debugging
///     mirror).
///   * `kind = "ksb_snapshot"` — payload is the KSB digest
///     `{ epoch, sha256 }` so an operator can correlate a
///     transition with the KSB it ran against.
///
/// Wire shape is JSON for both on-disk persistence and the
/// dashboard's `GET /api/sessions/:session_id/capture` route.
/// `kind` is a plain string (rather than an enum variant) so
/// future kinds (e.g. `"reviewer_verdict"`,
/// `"escalation_pending"`) can land without a schema bump on
/// the FE — unknown kinds collapse to a generic record in
/// `dashboard-fe`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionCaptureRecord {
    /// Owning session id. Carried in the body so global
    /// "recent session activity" views could merge across
    /// sessions without re-parsing the file path.
    pub session_id: String,
    /// Discriminator string. See module docs for the canonical
    /// set; unknown kinds are allowed on the wire.
    pub kind: String,
    /// Unix seconds when the observer appended the record.
    /// `_unix` not `_ms` to mirror the rest of the audit
    /// surface (the audit chain is unix-seconds).
    pub ts_unix: i64,
    /// Free-form payload. The kernel observer constructs this
    /// from the FSM transition / KSB snapshot / audit event
    /// it is mirroring; the dashboard renders it generically.
    pub payload: serde_json::Value,
}

/// Tunables for the per-session capture.
///
/// Both `max_bytes_per_session` AND `max_records_per_session`
/// are enforced on every append — whichever ceiling trips
/// first triggers compaction. We carry both because operators
/// can have very different worst-case payload sizes (e.g. an
/// embedded audit-event summary can be a few hundred bytes,
/// while a KSB snapshot is two short fields) and a single
/// ceiling would either over-budget disk or under-budget
/// records.
#[derive(Debug, Clone)]
pub struct SessionCaptureConfig {
    /// Per-session file ring max size in bytes. 512 KiB by
    /// default — comfortably above the worst-case per-session
    /// transition + audit tail volume for a long-running
    /// session, but small enough that a few hundred
    /// simultaneously-terminated sessions can not blow out
    /// the operator's data dir.
    pub max_bytes_per_session: u64,
    /// Per-session record-count ceiling. 2 000 by default —
    /// a session that emits ~10 transitions + 20 audit-event
    /// mirrors + a handful of KSB snapshots typically fits
    /// in 50 records; the headroom absorbs an unusually
    /// retry-heavy session without triggering compaction
    /// prematurely.
    pub max_records_per_session: usize,
    /// Per-session broadcast channel capacity for live SSE
    /// subscribers. 64 is enough for a smooth dashboard
    /// scroll without queueing under typical lifecycle
    /// dispatch (a transition every few seconds at most).
    pub broadcast_capacity: usize,
}

impl Default for SessionCaptureConfig {
    fn default() -> Self {
        Self {
            max_bytes_per_session: 512 * 1024,
            max_records_per_session: 2_000,
            broadcast_capacity: 64,
        }
    }
}

/// Per-session in-memory state. One `Arc<SessionState>` per
/// session id, stored in [`SessionCapture::sessions`]. The
/// append-only file handle is held under a
/// `parking_lot::Mutex` so concurrent observer writes (e.g.
/// FSM transition + audit-event mirror on the same wallclock
/// tick) serialise at the file level without blocking on
/// tokio's executor.
struct SessionState {
    file: Mutex<File>,
    /// Cached file size, updated on every append. Used to
    /// trip the byte-ceiling without re-stat'ing on each
    /// write. Stays consistent with the on-disk file because
    /// every mutator path that touches the file size also
    /// updates this.
    file_size: Mutex<u64>,
    /// Cached record count. Same invariant as `file_size` —
    /// updated on every append/compact path so the
    /// record-ceiling check never re-reads the file.
    record_count: Mutex<usize>,
    sender: broadcast::Sender<SessionCaptureRecord>,
}

/// Process-wide per-session capture. Hold via `Arc` from
/// both the kernel's lifecycle observer (writer) and the
/// dashboard data layer (reader / subscriber).
pub struct SessionCapture {
    sessions_dir: PathBuf,
    cfg: SessionCaptureConfig,
    sessions: Mutex<HashMap<String, Arc<SessionState>>>,
}

impl SessionCapture {
    /// Build a fresh capture rooted at
    /// `<data_dir>/session-capture/`. The directory is
    /// created if missing.
    pub fn new(data_dir: &Path, cfg: SessionCaptureConfig) -> std::io::Result<Arc<Self>> {
        let sessions_dir = data_dir.join("session-capture");
        std::fs::create_dir_all(&sessions_dir)?;
        Ok(Arc::new(Self {
            sessions_dir,
            cfg,
            sessions: Mutex::new(HashMap::new()),
        }))
    }

    /// Append `record` to the session's ring + broadcast it.
    ///
    /// Compaction is triggered when EITHER ceiling
    /// (`max_bytes_per_session` or `max_records_per_session`)
    /// would be exceeded by this write. The broadcast fires
    /// first so live subscribers never lose the event even on
    /// a disk-full append; the function still returns the
    /// `io::Error` so the caller can decide whether to log /
    /// retry.
    pub fn append(&self, session_id: &str, record: SessionCaptureRecord) -> std::io::Result<()> {
        let state = self.session_state_inner(session_id)?;
        // Broadcast first so subscribers aren't blocked on disk.
        let _ = state.sender.send(record.clone());

        // Then persist.
        let line = serde_json::to_string(&record).unwrap_or_else(|_| "{}".to_owned());
        let bytes = line.as_bytes();
        let line_len = bytes.len() as u64 + 1; // +1 for newline

        let mut size = state.file_size.lock();
        let mut count = state.record_count.lock();
        let over_bytes = *size + line_len > self.cfg.max_bytes_per_session;
        let over_records = *count + 1 > self.cfg.max_records_per_session;
        if over_bytes || over_records {
            self.compact_locked(session_id, &state)?;
            *size = state.file.lock().metadata().map(|m| m.len()).unwrap_or(0);
            // `compact_locked` rewrote the file from the kept
            // tail; the in-memory count must follow the new
            // line count.
            let new_count = count_lines(&state.file.lock())?;
            *count = new_count;
        }
        let mut f = state.file.lock();
        f.seek(SeekFrom::End(0))?;
        f.write_all(bytes)?;
        f.write_all(b"\n")?;
        f.flush()?;
        *size += line_len;
        *count += 1;
        Ok(())
    }

    /// Read the last `n` records from the session's ring.
    /// Returns `Ok(vec![])` when the file is missing (session
    /// never had a captured event) — never an error.
    pub fn tail(&self, session_id: &str, n: usize) -> Vec<SessionCaptureRecord> {
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
            .filter_map(|l| serde_json::from_str::<SessionCaptureRecord>(&l).ok())
            .collect()
    }

    /// Subscribe to live records for a session. Returns
    /// `None` when no session state exists yet — callers that
    /// want lazy attach should call
    /// [`Self::ensure_session`] first.
    pub fn subscribe(&self, session_id: &str) -> Option<broadcast::Receiver<SessionCaptureRecord>> {
        let g = self.sessions.lock();
        g.get(session_id).map(|s| s.sender.subscribe())
    }

    /// Allocate the session state if it does not already
    /// exist. Returns the broadcast sender for callers that
    /// want to hold a clone (e.g. the kernel's lifecycle
    /// observer).
    pub fn ensure_session(
        &self,
        session_id: &str,
    ) -> std::io::Result<broadcast::Sender<SessionCaptureRecord>> {
        let state = self.session_state_inner(session_id)?;
        Ok(state.sender.clone())
    }

    /// On-disk path for one session. Sanitises the session id
    /// to defend against a future writer that hands us a
    /// session id with `/` or `\` — the policy / kernel
    /// machinery already owns the source of truth for session
    /// ids so this is defence in depth.
    pub fn session_path(&self, session_id: &str) -> PathBuf {
        let safe: String = session_id
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '.' || *c == '-')
            .collect();
        self.sessions_dir.join(format!("{safe}.ndjson"))
    }

    /// Coarse on-disk state for one session — current file
    /// size + record count. Useful for the dashboard's data
    /// layer to surface a "ring fullness" indicator without
    /// re-tail'ing the file. Creates the per-session state if
    /// it doesn't already exist (so the operator can attach a
    /// post-mortem view to a session that has not yet
    /// produced a record).
    pub fn session_state(&self, session_id: &str) -> std::io::Result<SessionStateView> {
        let state = self.session_state_inner(session_id)?;
        let file_size = *state.file_size.lock();
        let record_count = *state.record_count.lock();
        Ok(SessionStateView {
            file_size,
            record_count,
        })
    }

    /// Get or create the session state. Opens the file in
    /// append mode and refreshes `file_size` from on-disk
    /// metadata.
    fn session_state_inner(&self, session_id: &str) -> std::io::Result<Arc<SessionState>> {
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
        let count = count_lines(&file)?;
        let (tx, _) = broadcast::channel(self.cfg.broadcast_capacity);
        let state = Arc::new(SessionState {
            file: Mutex::new(file),
            file_size: Mutex::new(size),
            record_count: Mutex::new(count),
            sender: tx,
        });
        let mut g = self.sessions.lock();
        Ok(g.entry(session_id.to_owned()).or_insert(state).clone())
    }

    /// Rewrite the session file keeping only the most recent
    /// 50 % of lines. Holds the file lock for the duration so
    /// no concurrent append slips in between the read and the
    /// rename. Pinned by
    /// `INV-DASHBOARD-SESSION-CAPTURE-FIXED-RING-01` — the
    /// kept tail MUST be the most-recent half, never the
    /// oldest.
    fn compact_locked(&self, session_id: &str, state: &SessionState) -> std::io::Result<()> {
        let path = self.session_path(session_id);
        let lines: Vec<String> = {
            let mut f = state.file.lock();
            f.seek(SeekFrom::Start(0))?;
            BufReader::new(&*f).lines().map_while(Result::ok).collect()
        };
        let cut = lines.len() / 2;
        let kept = &lines[cut..];
        let tmp_path = path.with_extension("ndjson.tmp");
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

/// Public view of the per-session state. Returned by
/// [`SessionCapture::session_state`] — useful for the
/// dashboard's data layer to surface a coarse "ring size"
/// indicator without re-tail'ing the whole file.
#[derive(Debug, Clone, Copy)]
pub struct SessionStateView {
    /// Current on-disk file size in bytes.
    pub file_size: u64,
    /// Current record count (the line count).
    pub record_count: usize,
}

// ---------------------------------------------------------------------------
// SessionLifecycleObserver — audit-sink decorator that mirrors every
// session-scoped audit emission into the per-session capture ring.
// ---------------------------------------------------------------------------

/// Audit-sink decorator that mirrors every session-scoped
/// audit emit onto a [`SessionCapture`] under the
/// `kind = "audit_event"` shape.
///
/// Modelled on [`crate::StreamingAuditSink`] (the existing
/// audit-→ SSE mirror) — same wrap-once-at-boot pattern, same
/// `inner.emit(...) → capture.append(...)` ordering. The two
/// differ in WHICH capture they feed and in whether their
/// records persist past session termination:
///
/// * `StreamingAuditSink` → `SessionStreamCapture` → live SSE
///   on `/api/sessions/:id/stream`. The stream ring is the
///   live-stream backbone and does not need to survive
///   termination as the post-mortem surface (it does for
///   replay-tail, but its primary contract is liveness).
/// * `SessionLifecycleObserver` → [`SessionCapture`] → post-
///   mortem on `/api/sessions/:id/capture`. Records persist
///   for the lifetime of the ring, surviving Completed /
///   Failed / Aborted.
///
/// Invariants:
///
/// * **Audit ordering preserved.** The inner sink's `emit`
///   runs to completion (and returns its `Ok` / `Err`)
///   BEFORE the post-mortem mirror fires.
/// * **Mirror failures swallowed.** A capture append failure
///   is logged as a single-line warn and discarded — the
///   audit chain is the source of truth; the post-mortem is
///   best-effort observability.
/// * **Read-only events mirrored.** Every event with a
///   `session_id` reaches the capture, including audit-chain
///   read events (operator privileged-reads). The
///   post-mortem operator expects to see every signal that
///   touched the session.
pub struct SessionLifecycleObserver {
    inner: Arc<dyn raxis_audit_tools::AuditSink>,
    capture: Arc<SessionCapture>,
}

impl SessionLifecycleObserver {
    /// Wrap `inner` and mirror every session-scoped emit
    /// onto `capture`.
    pub fn new(inner: Arc<dyn raxis_audit_tools::AuditSink>, capture: Arc<SessionCapture>) -> Self {
        Self { inner, capture }
    }
}

impl raxis_audit_tools::AuditSink for SessionLifecycleObserver {
    fn emit(
        &self,
        kind: raxis_audit_tools::AuditEventKind,
        session_id: Option<&str>,
        task_id: Option<&str>,
        initiative_id: Option<&str>,
    ) -> Result<raxis_audit_tools::AuditEvent, raxis_audit_tools::writer::AuditWriterError> {
        let event = self.inner.emit(kind, session_id, task_id, initiative_id)?;
        if let Some(sid) = session_id {
            mirror_audit_to_session_capture(&self.capture, sid, &event);
        }
        Ok(event)
    }
}

/// Convert an audit record into a `SessionCaptureRecord` and
/// append it. Single-line warn on failure; never propagates
/// back into the audit pipeline (the inner sink already
/// captured the event durably).
fn mirror_audit_to_session_capture(
    capture: &SessionCapture,
    session_id: &str,
    event: &raxis_audit_tools::AuditEvent,
) {
    let record = SessionCaptureRecord {
        session_id: session_id.to_owned(),
        kind: "audit_event".to_owned(),
        ts_unix: event.emitted_at,
        payload: serde_json::json!({
            "seq":           event.seq,
            "event_id":      event.event_id.to_string(),
            "event_kind":    event.event_kind,
            "initiative_id": event.initiative_id,
            "task_id":       event.task_id,
            "payload":       event.payload,
        }),
    };
    if let Err(e) = capture.append(session_id, record) {
        eprintln!(
            "{{\"level\":\"warn\",\"event\":\"SessionCaptureMirrorFailed\",\
             \"session_id\":\"{session_id}\",\"reason\":\"{e}\"}}"
        );
    }
}

/// Count newline-delimited records in an open append-handle.
/// Seeks back to start to count, then leaves the cursor at
/// the end so subsequent append writes go to the right place.
fn count_lines(file: &File) -> std::io::Result<usize> {
    // `&File` implements `Read` + `Seek` via its blanket impl,
    // so we don't need a `&mut File` — but we DO need to keep
    // the byte cursor controlled, so we use a local handle.
    let mut handle = file;
    handle.seek(SeekFrom::Start(0))?;
    let count = BufReader::new(handle).lines().map_while(Result::ok).count();
    Ok(count)
}

// ---------------------------------------------------------------------------
// Witness tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(session_id: &str, kind: &str, ts: i64) -> SessionCaptureRecord {
        SessionCaptureRecord {
            session_id: session_id.into(),
            kind: kind.into(),
            ts_unix: ts,
            payload: serde_json::json!({ "i": ts }),
        }
    }

    /// Core round-trip: append-then-tail returns the records
    /// in the order they were appended.
    #[test]
    fn append_then_tail_round_trips() {
        let tmp = tempfile::tempdir().unwrap();
        let cap = SessionCapture::new(tmp.path(), SessionCaptureConfig::default()).unwrap();
        for i in 0..5 {
            cap.append("sess-a", rec("sess-a", "fsm_transition", i))
                .unwrap();
        }
        let tail = cap.tail("sess-a", 10);
        assert_eq!(tail.len(), 5);
        assert_eq!(tail[0].ts_unix, 0);
        assert_eq!(tail[4].ts_unix, 4);
    }

    /// Tail clamps to the most recent `n` records.
    #[test]
    fn tail_clamps_to_recent_n() {
        let tmp = tempfile::tempdir().unwrap();
        let cap = SessionCapture::new(tmp.path(), SessionCaptureConfig::default()).unwrap();
        for i in 0..10 {
            cap.append("sess-b", rec("sess-b", "fsm_transition", i))
                .unwrap();
        }
        let tail = cap.tail("sess-b", 3);
        assert_eq!(tail.len(), 3);
        assert_eq!(tail[0].ts_unix, 7);
        assert_eq!(tail[2].ts_unix, 9);
    }

    /// **Witness for
    /// `INV-DASHBOARD-SESSION-CAPTURE-FIXED-RING-01`** (byte
    /// ceiling axis): after appending well over the byte cap,
    /// the file ring MUST stay within
    /// `max_bytes_per_session + per-record slack`.
    #[test]
    fn compaction_kicks_in_when_max_bytes_exceeded() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = SessionCaptureConfig {
            max_bytes_per_session: 2_048,
            max_records_per_session: 10_000, // record axis disabled here
            broadcast_capacity: 16,
        };
        let cap = SessionCapture::new(tmp.path(), cfg).unwrap();
        for i in 0..200 {
            cap.append("sess-bytes", rec("sess-bytes", "fsm_transition", i))
                .unwrap();
        }
        let path = cap.session_path("sess-bytes");
        let size = std::fs::metadata(&path).unwrap().len();
        assert!(
            size <= 2_048 + 1_024,
            "byte ceiling busted — got {size} bytes for a 2048-byte cap"
        );
        // Tail still surfaces the most-recent records, NOT the
        // oldest — INV-FIXED-RING-01 forbids silent mutation.
        let tail = cap.tail("sess-bytes", 500);
        assert!(!tail.is_empty(), "tail must not be empty after compaction");
        let max_ts = tail.iter().map(|r| r.ts_unix).max().unwrap();
        assert_eq!(max_ts, 199, "tail must include the most recent records");
    }

    /// **Witness for
    /// `INV-DASHBOARD-SESSION-CAPTURE-FIXED-RING-01`** (record
    /// ceiling axis): after appending well over the record
    /// cap, the file ring MUST stay near
    /// `max_records_per_session`.
    #[test]
    fn compaction_kicks_in_when_max_records_exceeded() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = SessionCaptureConfig {
            max_bytes_per_session: 10 * 1024 * 1024, // byte axis disabled
            max_records_per_session: 20,
            broadcast_capacity: 16,
        };
        let cap = SessionCapture::new(tmp.path(), cfg).unwrap();
        for i in 0..200 {
            cap.append("sess-recs", rec("sess-recs", "fsm_transition", i))
                .unwrap();
        }
        let tail = cap.tail("sess-recs", 1_000);
        assert!(
            tail.len() <= 21,
            "record ceiling busted — got {} records for a 20-record cap",
            tail.len()
        );
        // Most-recent-half retention.
        let min_ts = tail.iter().map(|r| r.ts_unix).min().unwrap();
        assert!(
            min_ts >= 180,
            "kept tail must be the most-recent half; got min ts {min_ts}"
        );
    }

    /// **Witness for
    /// `INV-DASHBOARD-SESSION-CAPTURE-PERSIST-AFTER-TERMINATION-01`**:
    /// dropping the `SessionCapture` instance and reopening
    /// against the same directory MUST surface the previously
    /// appended records. The on-disk file is the source of
    /// truth, not the in-memory `sessions` map.
    #[test]
    fn persistence_across_new_instances() {
        let tmp = tempfile::tempdir().unwrap();
        {
            let cap = SessionCapture::new(tmp.path(), SessionCaptureConfig::default()).unwrap();
            for i in 0..3 {
                cap.append("sess-p", rec("sess-p", "fsm_transition", i))
                    .unwrap();
            }
            // Drop the Arc.
        }
        let cap2 = SessionCapture::new(tmp.path(), SessionCaptureConfig::default()).unwrap();
        let tail = cap2.tail("sess-p", 10);
        assert_eq!(
            tail.len(),
            3,
            "records MUST survive a SessionCapture rebuild"
        );
        assert_eq!(tail[0].ts_unix, 0);
        assert_eq!(tail[2].ts_unix, 2);
    }

    /// **Witness for
    /// `INV-DASHBOARD-SESSION-CAPTURE-PERSIST-AFTER-TERMINATION-01`**
    /// — `tail` against a session id whose in-memory state
    /// was never resolved still returns the on-disk records
    /// (mirrors the post-mortem path: the writer has long
    /// since released the in-memory `SessionState` but the
    /// file is still there).
    #[test]
    fn tail_after_session_state_drop() {
        let tmp = tempfile::tempdir().unwrap();
        let cap = SessionCapture::new(tmp.path(), SessionCaptureConfig::default()).unwrap();
        cap.append("sess-q", rec("sess-q", "audit_event", 1))
            .unwrap();
        // Wipe the in-memory state without touching the file.
        cap.sessions.lock().remove("sess-q");
        let tail = cap.tail("sess-q", 10);
        assert_eq!(tail.len(), 1);
        assert_eq!(tail[0].kind, "audit_event");
    }

    /// **Witness for
    /// `INV-DASHBOARD-SESSION-CAPTURE-NAMESPACED-PER-SESSION-01`**:
    /// records for distinct session ids never bleed into each
    /// other's tails, INCLUDING for ids that differ only by
    /// punctuation (`sess-1` vs `sess.1` vs `sess_1`).
    #[test]
    fn session_ids_are_isolated_per_namespace() {
        let tmp = tempfile::tempdir().unwrap();
        let cap = SessionCapture::new(tmp.path(), SessionCaptureConfig::default()).unwrap();
        cap.append("sess-1", rec("sess-1", "fsm_transition", 11))
            .unwrap();
        cap.append("sess.1", rec("sess.1", "fsm_transition", 21))
            .unwrap();
        cap.append("sess_1", rec("sess_1", "fsm_transition", 31))
            .unwrap();
        let t1 = cap.tail("sess-1", 10);
        let t2 = cap.tail("sess.1", 10);
        let t3 = cap.tail("sess_1", 10);
        assert_eq!(t1.len(), 1);
        assert_eq!(t1[0].ts_unix, 11);
        assert_eq!(t2.len(), 1);
        assert_eq!(t2[0].ts_unix, 21);
        assert_eq!(t3.len(), 1);
        assert_eq!(t3[0].ts_unix, 31);
    }

    /// Subscribe-fan-out: a subscriber attached BEFORE the
    /// append MUST receive the broadcast on the next append.
    #[tokio::test]
    async fn append_broadcasts_to_subscribers() {
        let tmp = tempfile::tempdir().unwrap();
        let cap = SessionCapture::new(tmp.path(), SessionCaptureConfig::default()).unwrap();
        cap.ensure_session("sess-bcast").unwrap();
        let mut rx = cap.subscribe("sess-bcast").expect("subscribe");
        let cap2 = Arc::clone(&cap);
        let handle = tokio::spawn(async move {
            cap2.append("sess-bcast", rec("sess-bcast", "fsm_transition", 7))
                .unwrap();
        });
        let got = rx.recv().await.unwrap();
        assert_eq!(got.ts_unix, 7);
        assert_eq!(got.kind, "fsm_transition");
        handle.await.unwrap();
    }

    /// Witness for the kernel-side `SessionLifecycleObserver`
    /// wiring: every `inner.emit(...)` that carries a
    /// `session_id` MUST also land in the per-session capture
    /// ring under the `audit_event` kind. Mirrors the
    /// `streaming_audit::tests::mirror_pushes_into_capture_when_session_id_present`
    /// pattern but against the post-mortem ring.
    #[test]
    fn lifecycle_observer_mirrors_audit_events_into_capture() {
        use raxis_audit_tools::{AuditEventKind, AuditSink};
        use raxis_test_support::FakeAuditSink;

        let tmp = tempfile::tempdir().unwrap();
        let cap = SessionCapture::new(tmp.path(), SessionCaptureConfig::default()).unwrap();
        let inner: Arc<dyn AuditSink> = Arc::new(FakeAuditSink::new());
        let wrapped = SessionLifecycleObserver::new(inner, Arc::clone(&cap));

        // Two emits — one with a session_id (should mirror)
        // and one without (should NOT mirror).
        let with_sid = wrapped
            .emit(
                AuditEventKind::KernelStopped {
                    reason: "test".into(),
                },
                Some("sess-obs"),
                None,
                None,
            )
            .expect("emit ok");
        wrapped
            .emit(
                AuditEventKind::KernelStarted {
                    data_dir: "/tmp/x".into(),
                    policy_epoch: 1,
                    schema_version: 1,
                },
                None,
                None,
                None,
            )
            .expect("emit ok");

        let tail = cap.tail("sess-obs", 16);
        assert_eq!(
            tail.len(),
            1,
            "exactly one mirrored record expected for sess-obs"
        );
        let r = &tail[0];
        assert_eq!(r.kind, "audit_event");
        assert_eq!(r.payload["seq"], with_sid.seq);
        assert_eq!(r.payload["event_kind"], with_sid.event_kind);
    }

    /// Compaction-under-write race: two concurrent writers
    /// against the same session id MUST NOT tear the file
    /// (every line must round-trip serde unchanged even
    /// while a compaction is racing). The
    /// `parking_lot::Mutex<File>` serialises the writes; this
    /// test pins that property by hammering 4 writer threads
    /// against a tight ring and asserting every kept line
    /// parses back cleanly.
    #[test]
    fn compaction_under_write_race() {
        use std::thread;
        let tmp = tempfile::tempdir().unwrap();
        let cfg = SessionCaptureConfig {
            max_bytes_per_session: 2_048,
            max_records_per_session: 64,
            broadcast_capacity: 16,
        };
        let cap = SessionCapture::new(tmp.path(), cfg).unwrap();
        let cap_inner = Arc::clone(&cap);
        thread::scope(|s| {
            for w in 0..4u32 {
                let cap_w = Arc::clone(&cap_inner);
                s.spawn(move || {
                    for i in 0..80u32 {
                        let r = rec("sess-race", "fsm_transition", i64::from(w * 100 + i));
                        cap_w.append("sess-race", r).unwrap();
                    }
                });
            }
        });
        // After the race, every record on disk MUST parse —
        // a torn line would show up as a `serde_json` decode
        // error and the tail would shrink, which we assert
        // against.
        let path = cap.session_path("sess-race");
        let raw = std::fs::read_to_string(&path).unwrap();
        let total_lines = raw.lines().count();
        let parsed_lines: usize = raw
            .lines()
            .filter(|l| serde_json::from_str::<SessionCaptureRecord>(l).is_ok())
            .count();
        assert_eq!(
            parsed_lines, total_lines,
            "compaction race tore at least one record — kept {parsed_lines} of {total_lines}"
        );
    }
}

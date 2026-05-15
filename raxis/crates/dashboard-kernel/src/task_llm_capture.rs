//! Per-task LLM-turn capture
//! (`prompt-caching.md` follow-up — operator-side raw-response
//! debugging surface).
//!
//! # What this module owns
//!
//! 1. A bounded **on-disk file ring** at
//!    `<data_dir>/llm-turns/<task_id>.jsonl`. Each line is a
//!    JSON-serialised [`LlmTurnRecord`]. The file is keyed by
//!    `task_id` (NOT `session_id`) so the buffer survives VM
//!    restarts within the same task — multiple sessions of the
//!    same task append to the same file, and an operator
//!    debugging a task that bounced through several VMs sees
//!    every LLM turn end-to-end.
//!
//!    When a file would exceed [`TaskCaptureConfig::max_file_bytes`]
//!    (default 4 MiB), the module compacts it in place keeping
//!    only the most recent ~50 % of lines (see
//!    `TaskLlmCapture::compact_locked`). One compaction per
//!    overflow — not per append — keeps amortised cost flat.
//!
//! 2. A per-task **broadcast channel** for live SSE subscribers.
//!    Defaults to 64 buffered events; lagged subscribers receive
//!    a `RecvError::Lagged(n)` and continue.
//!
//! 3. A **tail loader** ([`TaskLlmCapture::tail`]) that reads the
//!    last `n` records from disk. The dashboard route calls this
//!    on every `GET /api/tasks/:task_id/llm-turns` request.
//!
//! # Why a separate module from `SessionStreamCapture`
//!
//! [`crate::SessionStreamCapture`] mirrors **audit events** to the
//! dashboard, keyed by `session_id` (one VM = one session). This
//! module captures **raw upstream LLM bytes** keyed by `task_id`
//! (one task may spawn multiple VMs — orchestrator → executor →
//! reviewer, plus retries on premature exit). The two surfaces
//! serve different debug needs:
//!
//! * `SessionStreamCapture` — "what is happening in this VM right
//!   now?" (audit-event timeline).
//! * `TaskLlmCapture` — "what did the LLM actually return for
//!   this task end-to-end?" (raw provider responses across every
//!   session that worked on this task).
//!
//! Sharing the surface would conflate the two views and force one
//! to win on key shape; keeping them parallel keeps both
//! operator-actionable.
//!
//! # Invariants
//!
//! * **Bounded disk per task.** Compaction enforces the
//!   `max_file_bytes` ceiling on every overflow append.
//! * **Bounded memory.** The capture holds nothing per-task
//!   beyond the broadcast sender + a `parking_lot::Mutex<File>`
//!   pair; the file ring lives on disk.
//! * **Append survives VM teardown.** Because the writer is the
//!   kernel (NOT the planner VM), records persist after the VM
//!   exits — operators can inspect them after the task
//!   terminates, which is the primary debug use case.
//! * **Single producer per task.** The kernel's gateway pump is
//!   the sole writer per task_id; the broadcast sender is
//!   `Clone` so subscribe-side fan-out is free.

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;

/// One captured LLM turn — the upstream provider's raw response
/// envelope plus the kernel-side metadata an operator needs to
/// correlate it with audit / Grafana.
///
/// Wire shape is JSON for both on-disk persistence and the
/// dashboard's `GET /api/tasks/:task_id/llm-turns` route.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlmTurnRecord {
    /// Unix milliseconds when the gateway returned the response.
    pub at_ms: u64,
    /// Task identifier (matches `policy.task_id` /
    /// `audit.task_id`). The on-disk file path encodes this same
    /// id; carrying it in the record body simplifies dashboard
    /// merging across tasks (e.g. global "recent LLM activity"
    /// views).
    pub task_id: String,
    /// Session identifier — the specific VM that issued the
    /// upstream request. Multiple sessions per task is the
    /// canonical case (orchestrator + executor + reviewer);
    /// retries on premature exit also bump this.
    pub session_id: Option<String>,
    /// Gateway-minted fetch identifier, useful for cross-
    /// referencing with `audit.fetch_completed.fetch_id` events
    /// and Grafana per-fetch latency drill-down.
    pub fetch_id: String,
    /// Upstream HTTP status code. `None` when the gateway never
    /// got a response (transport / DNS / timeout — the `error`
    /// field carries the structured reason in that case).
    pub status_code: Option<u16>,
    /// Observed end-to-end latency in milliseconds (gateway
    /// outbound write → first response byte received).
    pub latency_ms: u32,
    /// Raw response body, decoded as UTF-8 (LLM provider responses
    /// are always JSON or SSE text). Bodies above
    /// [`TaskCaptureConfig::max_body_bytes`] are truncated with a
    /// trailing `<truncated N bytes>` suffix so operator pages
    /// don't OOM the dashboard backend on a runaway 16 MiB
    /// response.
    pub body: String,
    /// `true` when [`Self::body`] was truncated to fit the
    /// per-record body cap. Operators see a "(truncated)" pill
    /// in the dashboard so they know the bytes are partial.
    #[serde(default)]
    pub body_truncated: bool,
    /// Original body length in bytes, before truncation. Always
    /// reflects the upstream response size so operators can
    /// gauge per-task token / bandwidth pressure even when the
    /// stored body is truncated.
    #[serde(default)]
    pub original_body_bytes: u64,
    /// Structured upstream error category from the gateway
    /// (`TimeoutExceeded`, `DomainNotAllowed`,
    /// `ResponseTooLarge`, `PolicyReloadFailed`, `NetworkError`).
    /// `None` on success.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub error: Option<String>,
}

/// Tunables for the per-task capture.
#[derive(Debug, Clone)]
pub struct TaskCaptureConfig {
    /// Per-task file ring max size in bytes. 4 MiB by default —
    /// roughly 2-3 large Anthropic Sonnet turns or 20-30 small
    /// turns. Compaction triggers at this threshold.
    pub max_file_bytes: u64,
    /// Per-record body cap. Bodies above this are truncated
    /// with a `<truncated N bytes>` suffix so a single runaway
    /// response cannot blow out the file ring on its own. 256
    /// KiB is comfortably above a typical Sonnet turn (which
    /// runs 30-150 KiB depending on tools-array size) but well
    /// below the gateway's 16 MiB hard cap.
    pub max_body_bytes: usize,
    /// Per-task broadcast channel capacity for live SSE
    /// subscribers. 64 is enough for a smooth dashboard scroll
    /// without queueing under typical agentic dispatch
    /// (one turn every few seconds).
    pub broadcast_capacity: usize,
}

impl Default for TaskCaptureConfig {
    fn default() -> Self {
        Self {
            max_file_bytes: 4 * 1024 * 1024,
            max_body_bytes: 256 * 1024,
            broadcast_capacity: 64,
        }
    }
}

/// Per-task in-memory state. One `Arc<TaskState>` per task_id,
/// stored in [`TaskLlmCapture::tasks`]. The append-only file
/// handle is held under a `parking_lot::Mutex` so concurrent
/// session writers (rare but possible — orchestrator +
/// executor sessions for the same task can overlap) serialize
/// at the file level without blocking on tokio's executor.
struct TaskState {
    file: Mutex<File>,
    file_size: Mutex<u64>,
    sender: broadcast::Sender<LlmTurnRecord>,
}

/// Process-wide per-task capture. Hold via `Arc` from both the
/// kernel's gateway pump (writer) and the dashboard data layer
/// (reader / subscriber).
pub struct TaskLlmCapture {
    turns_dir: PathBuf,
    cfg: TaskCaptureConfig,
    tasks: Mutex<HashMap<String, Arc<TaskState>>>,
}

impl TaskLlmCapture {
    /// Build a fresh capture rooted at `<data_dir>/llm-turns/`.
    /// The directory is created if missing.
    pub fn new(data_dir: &Path, cfg: TaskCaptureConfig) -> std::io::Result<Arc<Self>> {
        let turns_dir = data_dir.join("llm-turns");
        std::fs::create_dir_all(&turns_dir)?;
        Ok(Arc::new(Self {
            turns_dir,
            cfg,
            tasks: Mutex::new(HashMap::new()),
        }))
    }

    /// Append `record` to the task's ring + broadcast it.
    ///
    /// Truncates `record.body` to [`TaskCaptureConfig::max_body_bytes`]
    /// before serializing — `body_truncated` and
    /// `original_body_bytes` reflect the truncation. On
    /// disk-full the broadcast still fires (live subscribers
    /// don't lose the event) and the function returns `Err` so
    /// the caller can decide whether to retry or surface.
    pub fn append(&self, task_id: &str, mut record: LlmTurnRecord) -> std::io::Result<()> {
        // Enforce per-record body cap BEFORE serializing so the
        // file ring can never balloon from a single response.
        let max = self.cfg.max_body_bytes;
        let original_len = record.body.len();
        record.original_body_bytes = original_len as u64;
        if original_len > max {
            // Truncate at a UTF-8 char boundary so the JSON
            // serialization never produces a half-multibyte
            // sequence (the dashboard parses the JSON body and
            // a torn UTF-8 trailing byte would surface as a
            // mid-line decode error in the operator UI).
            let mut cut = max;
            while cut > 0 && !record.body.is_char_boundary(cut) {
                cut -= 1;
            }
            let extra_bytes = original_len - cut;
            record.body.truncate(cut);
            record
                .body
                .push_str(&format!("\n<truncated {extra_bytes} bytes>"));
            record.body_truncated = true;
        }

        let state = self.task_state(task_id)?;
        // Broadcast first so subscribers aren't blocked on disk.
        let _ = state.sender.send(record.clone());

        // Then persist.
        let line = serde_json::to_string(&record).unwrap_or_else(|_| "{}".to_owned());
        let bytes = line.as_bytes();
        let line_len = bytes.len() as u64 + 1; // +1 for newline

        let mut size = state.file_size.lock();
        if *size + line_len > self.cfg.max_file_bytes {
            self.compact_locked(task_id, &state)?;
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

    /// Read the last `n` records from the task's ring. Returns
    /// `Ok(vec![])` when the file is missing (task never had an
    /// LLM call) — never an error.
    pub fn tail(&self, task_id: &str, n: usize) -> Vec<LlmTurnRecord> {
        let path = self.task_path(task_id);
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
            .filter_map(|l| serde_json::from_str::<LlmTurnRecord>(&l).ok())
            .collect()
    }

    /// Subscribe to live records for a task. Returns `None`
    /// when no task state exists yet — callers that want lazy
    /// attach should call [`Self::ensure_task`] first.
    pub fn subscribe(&self, task_id: &str) -> Option<broadcast::Receiver<LlmTurnRecord>> {
        let g = self.tasks.lock();
        g.get(task_id).map(|s| s.sender.subscribe())
    }

    /// Allocate the task state if it does not already exist.
    /// Returns the broadcast sender for callers that want to
    /// hold a clone (e.g. the kernel's gateway pump).
    pub fn ensure_task(&self, task_id: &str) -> std::io::Result<broadcast::Sender<LlmTurnRecord>> {
        let state = self.task_state(task_id)?;
        Ok(state.sender.clone())
    }

    /// On-disk path for one task.
    pub fn task_path(&self, task_id: &str) -> PathBuf {
        // Sanitise task_id: only `[A-Za-z0-9_.-]`. The kernel's
        // policy / planner machinery owns the source of truth
        // for task ids so this is defence in depth.
        let safe: String = task_id
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '.' || *c == '-')
            .collect();
        self.turns_dir.join(format!("{safe}.jsonl"))
    }

    /// Get or create the task state. Opens the file in append
    /// mode and refreshes `file_size` from on-disk metadata.
    fn task_state(&self, task_id: &str) -> std::io::Result<Arc<TaskState>> {
        {
            let g = self.tasks.lock();
            if let Some(s) = g.get(task_id) {
                return Ok(Arc::clone(s));
            }
        }
        let path = self.task_path(task_id);
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .append(true)
            .open(&path)?;
        let size = file.metadata().map(|m| m.len()).unwrap_or(0);
        let (tx, _) = broadcast::channel(self.cfg.broadcast_capacity);
        let state = Arc::new(TaskState {
            file: Mutex::new(file),
            file_size: Mutex::new(size),
            sender: tx,
        });
        let mut g = self.tasks.lock();
        Ok(g.entry(task_id.to_owned()).or_insert(state).clone())
    }

    /// Rewrite the task file keeping only the most recent 50 %
    /// of lines. Holds the file lock for the duration so no
    /// concurrent append slips in.
    fn compact_locked(&self, task_id: &str, state: &TaskState) -> std::io::Result<()> {
        let path = self.task_path(task_id);
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

    fn rec(at_ms: u64, body: &str) -> LlmTurnRecord {
        LlmTurnRecord {
            at_ms,
            task_id: "task-x".into(),
            session_id: Some(format!("sess-{at_ms}")),
            fetch_id: format!("fetch-{at_ms}"),
            status_code: Some(200),
            latency_ms: 42,
            body: body.into(),
            body_truncated: false,
            original_body_bytes: body.len() as u64,
            error: None,
        }
    }

    #[test]
    fn append_then_tail_round_trips_per_task() {
        let tmp = tempfile::tempdir().unwrap();
        let cap = TaskLlmCapture::new(tmp.path(), TaskCaptureConfig::default()).unwrap();
        for i in 0..5 {
            cap.append("task-x", rec(i, &format!("body-{i}"))).unwrap();
        }
        let tail = cap.tail("task-x", 10);
        assert_eq!(tail.len(), 5);
        assert_eq!(tail[0].at_ms, 0);
        assert_eq!(tail[4].body, "body-4");
    }

    #[test]
    fn tail_clamps_to_recent_n() {
        let tmp = tempfile::tempdir().unwrap();
        let cap = TaskLlmCapture::new(tmp.path(), TaskCaptureConfig::default()).unwrap();
        for i in 0..10 {
            cap.append("task-y", rec(i, &format!("b{i}"))).unwrap();
        }
        let tail = cap.tail("task-y", 3);
        assert_eq!(tail.len(), 3);
        assert_eq!(tail[0].at_ms, 7);
        assert_eq!(tail[2].at_ms, 9);
    }

    #[test]
    fn missing_task_tail_returns_empty() {
        let tmp = tempfile::tempdir().unwrap();
        let cap = TaskLlmCapture::new(tmp.path(), TaskCaptureConfig::default()).unwrap();
        assert!(cap.tail("never-existed", 10).is_empty());
    }

    #[test]
    fn body_above_max_body_bytes_is_truncated_with_marker() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = TaskCaptureConfig {
            max_body_bytes: 32,
            ..TaskCaptureConfig::default()
        };
        let cap = TaskLlmCapture::new(tmp.path(), cfg).unwrap();
        let big = "x".repeat(1000);
        cap.append("task-trunc", rec(1, &big)).unwrap();
        let tail = cap.tail("task-trunc", 10);
        assert_eq!(tail.len(), 1);
        let r = &tail[0];
        assert!(r.body_truncated, "body MUST be flagged truncated");
        assert_eq!(r.original_body_bytes, 1000);
        assert!(
            r.body.contains("<truncated 968 bytes>"),
            "body MUST carry truncation marker; got {:?}",
            r.body
        );
        assert!(
            r.body.len() <= 32 + 64,
            "truncated body MUST be near max_body_bytes; got {} bytes",
            r.body.len()
        );
    }

    #[test]
    fn compaction_kicks_in_when_max_file_bytes_exceeded() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = TaskCaptureConfig {
            max_file_bytes: 1024,
            max_body_bytes: 256,
            broadcast_capacity: 16,
        };
        let cap = TaskLlmCapture::new(tmp.path(), cfg).unwrap();
        for i in 0..50 {
            cap.append("task-z", rec(i, &format!("body-{i}"))).unwrap();
        }
        let path = cap.task_path("task-z");
        let size = std::fs::metadata(&path).unwrap().len();
        assert!(
            size <= 1024 + 512,
            "file size {size} should stay near the cap (1024B); cap busted"
        );
        let tail = cap.tail("task-z", 100);
        assert!(!tail.is_empty(), "tail must not be empty after compaction");
        assert!(
            tail.last().unwrap().at_ms >= 40,
            "tail must include the most recent records"
        );
    }

    #[tokio::test]
    async fn append_broadcasts_to_subscribers() {
        let tmp = tempfile::tempdir().unwrap();
        let cap = TaskLlmCapture::new(tmp.path(), TaskCaptureConfig::default()).unwrap();
        cap.ensure_task("task-bcast").unwrap();
        let mut rx = cap.subscribe("task-bcast").expect("subscribe");
        let cap2 = Arc::clone(&cap);
        let handle = tokio::spawn(async move {
            cap2.append("task-bcast", rec(7, "live-body")).unwrap();
        });
        let got = rx.recv().await.unwrap();
        assert_eq!(got.at_ms, 7);
        assert_eq!(got.body, "live-body");
        handle.await.unwrap();
    }

    /// **`task_id` keying survives multiple sessions** — the
    /// canonical use case the user asked for. Two sessions of
    /// the same task append to the same file; tail returns
    /// records from both in order.
    #[test]
    fn multiple_sessions_of_same_task_share_one_file() {
        let tmp = tempfile::tempdir().unwrap();
        let cap = TaskLlmCapture::new(tmp.path(), TaskCaptureConfig::default()).unwrap();
        let mut r1 = rec(1, "from-orchestrator-vm");
        r1.session_id = Some("sess-orch".into());
        cap.append("task-shared", r1).unwrap();
        let mut r2 = rec(2, "from-executor-vm");
        r2.session_id = Some("sess-exec".into());
        cap.append("task-shared", r2).unwrap();
        let mut r3 = rec(3, "from-executor-vm-restarted");
        r3.session_id = Some("sess-exec-2".into());
        cap.append("task-shared", r3).unwrap();
        let tail = cap.tail("task-shared", 10);
        assert_eq!(
            tail.len(),
            3,
            "all 3 records (across 3 VMs of the same task) MUST be in the file"
        );
        assert_eq!(tail[0].session_id.as_deref(), Some("sess-orch"));
        assert_eq!(tail[2].session_id.as_deref(), Some("sess-exec-2"));
    }
}

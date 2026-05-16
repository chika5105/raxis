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
//! * **Per-turn durability** (`INV-TASK-LLM-CAPTURE-DURABLE-WRITE-01`).
//!   Every [`TaskLlmCapture::append`] writes the full JSON line +
//!   `\n` in a single `write_all` against an `O_APPEND` handle
//!   and then `sync_all`s the file BEFORE returning. A kernel
//!   panic, SIGKILL, or `abort()` happening at any point after
//!   `append` returns is guaranteed not to lose the captured
//!   turn. The graceful-shutdown path additionally calls
//!   [`TaskLlmCapture::drain_and_shutdown`] for safety and
//!   the kernel installs a `std::panic::set_hook` that calls
//!   [`TaskLlmCapture::flush_all`] for defense-in-depth.

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
    /// Raw upstream REQUEST body, decoded as UTF-8. The kernel
    /// gateway pump captures this from the
    /// `GatewayMessage::FetchRequest.body_bytes` it just sent so
    /// the operator's per-turn panel can surface BOTH sides of
    /// the round-trip (the pre-iter64 wire only carried the
    /// response, leaving operators staring at half-conversations
    /// in the LLM turns view). Truncated alongside
    /// [`Self::body`] when above
    /// [`TaskCaptureConfig::max_body_bytes`]; defaults to the
    /// empty string for back-compat with pre-iter64 on-disk
    /// records.
    #[serde(default)]
    pub request_body: String,
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
        //
        // `INV-TASK-LLM-CAPTURE-DURABLE-WRITE-01`. Build the
        // full line (JSON + `\n`) into a single buffer and emit
        // it via ONE `write_all` call so the kernel sees a
        // single contiguous append. Combined with the
        // `OpenOptions::append(true)` (O_APPEND) handle this
        // gives us POSIX atomic-append semantics for
        // sub-PIPE_BUF lines (concurrent writers from the
        // gateway pump for the same `task_id` can never
        // interleave halves of a record on disk). After the
        // write we `sync_all()` BEFORE returning, so a kernel
        // panic, SIGKILL, or `abort()` happening at any point
        // after `append` returns is guaranteed to preserve this
        // turn on physical disk. Cost: ~1-5 ms on macOS APFS,
        // ~0.5-2 ms on Linux ext4 — negligible vs the
        // 5-50 s Anthropic round-trip we just captured, and
        // load-bearing for post-mortem (iter63 lost the
        // post-`tool_result` turn this exact way).
        let mut line = serde_json::to_string(&record).unwrap_or_else(|_| "{}".to_owned());
        line.push('\n');
        let bytes = line.as_bytes();
        let line_len = bytes.len() as u64;

        let mut size = state.file_size.lock();
        if *size + line_len > self.cfg.max_file_bytes {
            self.compact_locked(task_id, &state)?;
            *size = state.file.lock().metadata().map(|m| m.len()).unwrap_or(0);
        }
        let mut f = state.file.lock();
        // O_APPEND on the underlying fd guarantees the write
        // lands at EOF atomically — no explicit `seek(End)`
        // needed (and the seek would race with concurrent
        // writers anyway).
        f.write_all(bytes)?;
        // Durable per-turn: fsync data + metadata so the
        // record survives a kernel panic that races with the
        // gateway pump's `observer.observe()` return path.
        // `sync_all()` is the portable choice; on Linux
        // `sync_data()` would be marginally cheaper but we
        // need the metadata flush on macOS APFS to ensure the
        // append-extended file length is durable too.
        f.sync_all()?;
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

    /// Best-effort fsync of every per-task file handle the
    /// capture currently knows about. Intended for the
    /// kernel's `std::panic::set_hook` defense-in-depth path:
    /// `append` already syncs per-turn (see
    /// `INV-TASK-LLM-CAPTURE-DURABLE-WRITE-01`), so in steady
    /// state this is a no-op — its job is to catch a panic
    /// that races mid-append (after `write_all` but before
    /// `sync_all`).
    ///
    /// Uses `try_lock` per file so the hook never deadlocks
    /// when the panicking thread was already holding the file
    /// mutex.
    pub fn flush_all(&self) {
        let g = self.tasks.lock();
        for state in g.values() {
            if let Some(f) = state.file.try_lock() {
                let _ = f.sync_all();
            }
        }
    }

    /// Graceful-shutdown drain. Flushes every per-task file
    /// handle, then clears the in-memory task map, releasing
    /// all file descriptors. Future `append` calls reopen
    /// the file on demand, so this is safe to call from
    /// SIGTERM / SIGINT handling without breaking subsequent
    /// activity in the (rare) case the shutdown is aborted.
    ///
    /// Unlike [`Self::flush_all`] this blocks on each file
    /// mutex — graceful shutdown is sequential and we can
    /// afford to wait for any in-flight `append` to release
    /// the lock so its record is durable before we exit.
    pub fn drain_and_shutdown(&self) {
        let mut g = self.tasks.lock();
        for state in g.values() {
            let f = state.file.lock();
            let _ = f.sync_all();
        }
        g.clear();
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
            request_body: String::new(),
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

    /// **Request body round-trips through append + tail.** Iter64
    /// added `LlmTurnRecord::request_body` so the operator-facing
    /// per-turn panel can surface both sides of the upstream
    /// round-trip. The kernel gateway pump fills this from the
    /// `GatewayMessage::FetchRequest.body_bytes` it just wrote.
    /// This test pins the on-disk + serde-default contract so a
    /// future refactor cannot accidentally drop the field.
    #[test]
    fn request_body_round_trips_through_append_and_tail() {
        let tmp = tempfile::tempdir().unwrap();
        let cap = TaskLlmCapture::new(tmp.path(), TaskCaptureConfig::default()).unwrap();
        let mut r = rec(1, "{\"role\":\"assistant\"}");
        r.request_body = "{\"model\":\"claude-sonnet-4-5\",\"messages\":[]}".into();
        cap.append("task-req", r).unwrap();
        let tail = cap.tail("task-req", 10);
        assert_eq!(tail.len(), 1);
        assert_eq!(
            tail[0].request_body,
            "{\"model\":\"claude-sonnet-4-5\",\"messages\":[]}"
        );
    }

    /// **Pre-iter64 on-disk records (no `request_body` key) still
    /// parse cleanly.** The on-disk file ring outlives any single
    /// kernel build (it survives VM teardown by design — see
    /// `INV-DASHBOARD-TASK-LLM-CAPTURE-03`); a fresh kernel after
    /// an upgrade MUST be able to tail records that were written
    /// before iter64 added the field.
    #[test]
    fn pre_iter64_lines_without_request_body_parse_via_serde_default() {
        let pre_iter64 = "{\"at_ms\":7,\"task_id\":\"t\",\"session_id\":null,\
                          \"fetch_id\":\"f\",\"status_code\":200,\"latency_ms\":42,\
                          \"body\":\"x\",\"body_truncated\":false,\
                          \"original_body_bytes\":1}";
        let parsed: LlmTurnRecord =
            serde_json::from_str(pre_iter64).expect("legacy line MUST parse");
        assert_eq!(
            parsed.request_body, "",
            "missing field MUST default to empty string"
        );
        assert_eq!(parsed.body, "x");
        assert_eq!(parsed.at_ms, 7);
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

    // ── INV-TASK-LLM-CAPTURE-DURABLE-WRITE-01 regression suite ────
    //
    // The witnesses below pin the three guarantees the iter63
    // forensic post-mortem demanded:
    //
    //   (a) per-turn durability across abrupt process exit (the
    //       "kernel panic mid-pipeline lost the post-`tool_result`
    //       turn" scenario);
    //   (b) `drain_and_shutdown()` flushes any in-flight metadata
    //       so SIGTERM doesn't leave a half-synced tail behind;
    //   (c) concurrent writers for the same `task_id` never
    //       interleave halves of a JSON record on disk (O_APPEND
    //       + single `write_all` atomicity).

    /// (a) **Per-turn durability across `process::exit`.**
    ///
    /// The body of this test runs in two modes:
    ///
    /// * **Child mode** (env `RAXIS_TEST_LLM_DURABLE_CHILD_DIR`
    ///   set): build a `TaskLlmCapture` at the named tmpdir,
    ///   append one well-known turn, then call
    ///   `std::process::exit(101)`. This bypasses Rust drop
    ///   glue (no destructors, no flushed buffers) — exactly
    ///   what a kernel panic / `abort()` would do as far as
    ///   userspace cleanup is concerned. The fix's
    ///   `sync_all()` is therefore the ONLY thing guaranteeing
    ///   the line lands on disk.
    /// * **Parent mode** (env unset): spawn ourselves with the
    ///   env var pointing at a fresh tmpdir, `--exact`-filtered
    ///   to this test name. Wait for the child to exit 101,
    ///   then read the per-task file from the parent and
    ///   assert the captured line is present and parses cleanly.
    ///
    /// Pre-fix the file was opened with `O_APPEND` but the
    /// writer only called `f.flush()` (a no-op on
    /// `std::fs::File`) — so the OS page cache held the bytes
    /// but a process-level abort after `append` returned could
    /// race with `close(2)` and lose the most recent record on
    /// some filesystems. Post-fix the per-turn `sync_all()`
    /// closes that window.
    #[test]
    fn record_turn_survives_process_exit_101() {
        // Child path: write one turn then exit non-zero.
        if let Ok(dir) = std::env::var("RAXIS_TEST_LLM_DURABLE_CHILD_DIR") {
            let cap = TaskLlmCapture::new(std::path::Path::new(&dir), TaskCaptureConfig::default())
                .expect("child: capture init");
            cap.append("task-fsync", rec(99, "post-mortem-line"))
                .expect("child: append");
            // `process::exit(101)` runs no Rust destructors;
            // the parking_lot Mutex<File> never drops, so any
            // buffering inside the writer would be lost. With
            // the fsync-per-turn fix the OS already has the
            // bytes durable on disk.
            std::process::exit(101);
        }

        // Parent path.
        let tmp = tempfile::tempdir().expect("parent: tempdir");
        let me = std::env::current_exe().expect("parent: current_exe");
        let status = std::process::Command::new(&me)
            .args([
                "--exact",
                "task_llm_capture::tests::record_turn_survives_process_exit_101",
                "--nocapture",
            ])
            .env("RAXIS_TEST_LLM_DURABLE_CHILD_DIR", tmp.path())
            .env("RUST_BACKTRACE", "0")
            .status()
            .expect("parent: spawn child");

        assert_eq!(
            status.code(),
            Some(101),
            "child MUST exit 101 (simulated panic); got {status:?}"
        );

        let path = tmp.path().join("llm-turns").join("task-fsync.jsonl");
        let body = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("post-exit read of {path:?} failed: {e}"));
        let lines: Vec<&str> = body.lines().collect();
        assert_eq!(
            lines.len(),
            1,
            "post-exit file MUST hold exactly one line; got {} ({:?})",
            lines.len(),
            body
        );
        let parsed: LlmTurnRecord =
            serde_json::from_str(lines[0]).expect("post-exit line MUST parse as LlmTurnRecord");
        assert_eq!(parsed.task_id, "task-fsync");
        assert_eq!(parsed.body, "post-mortem-line");
        assert_eq!(parsed.at_ms, 99);
    }

    /// (a-bis) **Per-turn durability — in-process witness.**
    ///
    /// Companion to the multi-process test above. We append a
    /// record through one `TaskLlmCapture`, drop it (releases
    /// the file handle), then open a SECOND `TaskLlmCapture`
    /// at the same data dir and assert the record is visible
    /// via `tail`. This pins the "fresh process restart on
    /// the same data dir sees every prior `append`" contract
    /// without paying the multi-process spawn cost — useful
    /// when running the suite under `cargo test --no-run`
    /// scenarios where re-exec'ing the test binary is
    /// awkward.
    #[test]
    fn record_turn_visible_to_fresh_capture_at_same_path() {
        let tmp = tempfile::tempdir().unwrap();
        {
            let cap_a = TaskLlmCapture::new(tmp.path(), TaskCaptureConfig::default()).unwrap();
            cap_a
                .append("task-restart", rec(7, "first-instance-line"))
                .unwrap();
            // Drop `cap_a` here — file handle closes. The
            // per-turn `sync_all` already pushed the bytes
            // to physical disk before append returned.
        }
        let cap_b = TaskLlmCapture::new(tmp.path(), TaskCaptureConfig::default()).unwrap();
        let tail = cap_b.tail("task-restart", 10);
        assert_eq!(tail.len(), 1, "fresh capture MUST see the prior record");
        assert_eq!(tail[0].body, "first-instance-line");
        assert_eq!(tail[0].at_ms, 7);
    }

    /// (b) **`drain_and_shutdown` flushes and clears the map.**
    ///
    /// Post-fix `append` is already durable, so this test is
    /// largely a sanity check on the drain API: it asserts
    /// the call returns cleanly after a write, the file is
    /// readable from a fresh `TaskLlmCapture` instance, and
    /// the in-memory task map is empty (forcing the next
    /// `append` to reopen the file).
    #[test]
    fn drain_and_shutdown_flushes_and_clears_map() {
        let tmp = tempfile::tempdir().unwrap();
        let cap = TaskLlmCapture::new(tmp.path(), TaskCaptureConfig::default()).unwrap();
        cap.append("task-drain", rec(1, "pre-shutdown")).unwrap();

        cap.drain_and_shutdown();

        // The map MUST be empty post-drain — future appends
        // lazy-reopen the file, which is what `task_state`
        // does. We inspect the public `subscribe` surface
        // because that is what tells us whether a `TaskState`
        // entry exists.
        assert!(
            cap.subscribe("task-drain").is_none(),
            "drain_and_shutdown MUST clear the per-task state map"
        );

        // A FRESH capture pointing at the same data dir MUST
        // see the pre-shutdown record.
        let cap2 = TaskLlmCapture::new(tmp.path(), TaskCaptureConfig::default()).unwrap();
        let tail = cap2.tail("task-drain", 10);
        assert_eq!(tail.len(), 1, "pre-shutdown record MUST be on disk");
        assert_eq!(tail[0].body, "pre-shutdown");

        // And we can still append AFTER a drain (the API is
        // idempotent — re-open on demand).
        cap.append("task-drain", rec(2, "post-shutdown")).unwrap();
        let tail2 = cap2.tail("task-drain", 10);
        assert_eq!(
            tail2.len(),
            2,
            "post-drain append MUST also be durable; got {tail2:?}"
        );
    }

    /// (c) **Concurrent writes per task never interleave.**
    ///
    /// Spawn 8 OS threads against the same `TaskLlmCapture`
    /// instance and the same `task_id`. Each thread writes
    /// 100 turns. After all threads join we assert:
    ///
    /// * the file has exactly 800 newline-terminated lines;
    /// * every line is well-formed JSON that parses as a
    ///   `LlmTurnRecord`;
    /// * the per-thread `(thread_idx, seq)` markers we
    ///   embedded in `body` form the expected multi-set (no
    ///   duplicates, no dropped records).
    ///
    /// This pins the O_APPEND + single-`write_all` atomicity
    /// contract: pre-fix the writer emitted the JSON bytes
    /// and the trailing `\n` as TWO separate `write_all`s,
    /// which on Linux can interleave with concurrent writes
    /// against the same fd in pathological scheduling. Post-
    /// fix the line + `\n` is one `write_all` and the
    /// O_APPEND fd guarantees atomic append for sub-PIPE_BUF
    /// payloads.
    #[test]
    fn concurrent_writes_per_task_never_interleave() {
        use std::thread;

        let tmp = tempfile::tempdir().unwrap();
        // Bump `max_file_bytes` well above 8 * 100 records so
        // the compaction path doesn't fire mid-test and the
        // post-condition is "exactly 800 lines on disk".
        let cfg = TaskCaptureConfig {
            max_file_bytes: 8 * 1024 * 1024,
            max_body_bytes: 4 * 1024,
            broadcast_capacity: 16,
        };
        let cap = TaskLlmCapture::new(tmp.path(), cfg).unwrap();

        let threads = 8;
        let per_thread = 100;
        let mut handles = Vec::with_capacity(threads);
        for tidx in 0..threads {
            let cap_t = Arc::clone(&cap);
            handles.push(thread::spawn(move || {
                for seq in 0..per_thread {
                    let body = format!("t{tidx}-s{seq}");
                    let at = (tidx * per_thread + seq) as u64;
                    cap_t
                        .append("task-concurrent", rec(at, &body))
                        .expect("concurrent append");
                }
            }));
        }
        for h in handles {
            h.join().expect("thread join");
        }

        // Drain + re-open from disk for the strongest possible
        // post-condition: we are reading the on-disk file, not
        // the in-memory ring.
        cap.drain_and_shutdown();

        let path = cap.task_path("task-concurrent");
        let body = std::fs::read_to_string(&path).expect("read concurrent file");
        let lines: Vec<&str> = body.lines().collect();
        assert_eq!(
            lines.len(),
            threads * per_thread,
            "expected {} lines (threads * per_thread), got {}",
            threads * per_thread,
            lines.len()
        );

        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        for (i, line) in lines.iter().enumerate() {
            let parsed: LlmTurnRecord = serde_json::from_str(line).unwrap_or_else(|e| {
                panic!("line {i} did not parse as LlmTurnRecord ({e}): {line:?}")
            });
            assert!(
                seen.insert(parsed.body.clone()),
                "duplicate body {:?} in concurrent run (line {i})",
                parsed.body
            );
        }
        assert_eq!(seen.len(), threads * per_thread);
        for tidx in 0..threads {
            for seq in 0..per_thread {
                let want = format!("t{tidx}-s{seq}");
                assert!(
                    seen.contains(&want),
                    "expected {want:?} in concurrent run; missing"
                );
            }
        }
    }
}

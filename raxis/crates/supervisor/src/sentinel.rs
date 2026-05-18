// raxis-supervisor::sentinel — atomic sentinel-file writer for
// `<data_dir>/kernel_lifecycle_status.json`.
//
// Normative reference: `self-healing-supervisor.md §4.6`.
//
// **Why a file (not a socket / shared memory).** The file is read
// by:
//
//   1. The kernel on boot
//      (`restart_lifecycle::read_sentinel_for_restart`) — needs
//      to be readable from the *child* process the supervisor
//      just spawned, before any IPC sockets are open.
//   2. The dashboard handler (`/api/health/kernel-lifecycle`) —
//      needs to be readable from the *kernel's* HTTP process,
//      which is a sibling of the supervisor.
//
// A file on a shared `<data_dir>/` works for both readers without
// inventing a new IPC channel.
//
// **Atomicity.** Every write is a unique `tempfile + rename` so a
// reader never sees a partial file. Read-modify-write transitions
// also take a small advisory lock because both the supervisor and
// the replacement kernel may update this file during restart
// handoff.

use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

/// Sentinel filename per `self-healing-supervisor.md §4.6`.
pub const SENTINEL_FILENAME: &str = "kernel_lifecycle_status.json";

/// Advisory lock filename shared with `kernel/src/restart_lifecycle.rs`.
const SENTINEL_LOCK_FILENAME: &str = ".kernel_lifecycle_status.lock";

/// One-shot force-stop request filename. `raxis-supervisor stop
/// --force` writes this file, then sends SIGTERM to the supervisor.
/// The supervisor can catch SIGTERM, consume this request, and send
/// SIGKILL to the kernel child while still writing a final sentinel.
pub const FORCE_STOP_REQUEST_FILENAME: &str = "supervisor_force_stop.request";

static TEMP_FILE_COUNTER: AtomicU64 = AtomicU64::new(0);

#[cfg(unix)]
struct SentinelLockGuard(File);

#[cfg(not(unix))]
struct SentinelLockGuard;

#[cfg(unix)]
impl Drop for SentinelLockGuard {
    fn drop(&mut self) {
        use std::os::fd::AsRawFd;
        let _ = nix::fcntl::flock(self.0.as_raw_fd(), nix::fcntl::FlockArg::Unlock);
    }
}

#[cfg(unix)]
fn lock_sentinel(data_dir: &Path) -> std::io::Result<SentinelLockGuard> {
    use std::os::fd::AsRawFd;

    std::fs::create_dir_all(data_dir)?;
    let lock = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .open(data_dir.join(SENTINEL_LOCK_FILENAME))?;
    nix::fcntl::flock(lock.as_raw_fd(), nix::fcntl::FlockArg::LockExclusive)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    Ok(SentinelLockGuard(lock))
}

#[cfg(not(unix))]
fn lock_sentinel(_data_dir: &Path) -> std::io::Result<SentinelLockGuard> {
    Ok(SentinelLockGuard)
}

fn unique_temp_path(data_dir: &Path, filename: &str) -> PathBuf {
    let counter = TEMP_FILE_COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    data_dir.join(format!(
        ".{filename}.{}.{}.{}.tmp",
        std::process::id(),
        nanos,
        counter
    ))
}

fn write_sentinel_unlocked(data_dir: &Path, sentinel: &Sentinel) -> std::io::Result<PathBuf> {
    std::fs::create_dir_all(data_dir)?;
    let final_path = data_dir.join(SENTINEL_FILENAME);
    let tmp_path = unique_temp_path(data_dir, SENTINEL_FILENAME);
    let bytes = serde_json::to_vec_pretty(sentinel).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("sentinel serialization failed: {e}"),
        )
    })?;
    {
        use std::io::Write;
        let mut f = File::create(&tmp_path)?;
        f.write_all(&bytes)?;
        f.flush()?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp_path, &final_path)?;
    Ok(final_path)
}

/// Top-level supervisor-reported status. Wire-pinned PascalCase
/// strings — both the kernel reader and the dashboard FE match
/// on these via `==`.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "status")]
pub enum SentinelStatus {
    /// Supervisor has spawned the kernel and the kernel is
    /// either booting or serving normally.
    Healthy,
    /// Supervisor is between kernel processes — either waiting
    /// the inter-restart back-off or has already spawned the
    /// replacement and is waiting for it to enter `Healthy`.
    Restarting,
    /// Supervisor has refused to spawn another kernel. Manual
    /// operator action required (`raxis-supervisor reset-circuit-breaker`
    /// for `CircuitOpen`; `raxis-supervisor start` for
    /// `OperatorStop` after the operator deliberately stopped
    /// the kernel).
    Halted,
}

/// Sub-state for `Halted`. Carried verbatim into the dashboard
/// banner copy so operators can see WHICH halt this is without
/// digging into the supervisor's stderr log.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub enum SentinelSubState {
    /// Circuit breaker tripped — too many restarts in the
    /// rolling window. Operator must run
    /// `raxis-supervisor reset-circuit-breaker`.
    CircuitOpen,
    /// Operator initiated a clean stop (`SIGTERM` / `SIGINT` /
    /// `raxis-supervisor stop`). Supervisor is gone; kernel
    /// stays down until operator re-runs `raxis-supervisor start`.
    OperatorStop,
    /// Operator initiated a forced stop
    /// (`raxis-supervisor stop --force`, which sends `SIGKILL`).
    /// Same operator-intent contract as `OperatorStop`; surfaced
    /// separately so the dashboard can render a different
    /// (more emphatic) banner copy.
    OperatorStopForced,
    /// Sentinel writer was unable to flush — the supervisor
    /// process is dead and we have stale data. The dashboard
    /// handler synthesises this when the file is older than
    /// `2 * window_secs` AND the supervisor PID is gone.
    SupervisorGone,
}

/// Full sentinel file payload. Wire-stable — every consumer
/// (kernel boot path + dashboard handler) reads this exact
/// schema. New fields MUST be `serde(default)` for forward
/// compat.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Sentinel {
    /// Schema version of the on-disk file. Currently always `1`.
    #[serde(default = "default_schema_version")]
    pub schema_version: u32,
    /// Top-level status string.
    pub status: String,
    /// Sub-state for `Halted` (`null` for `Healthy` / `Restarting`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sub_state: Option<String>,
    /// 1-indexed restart attempt within the current circuit-
    /// breaker window. `0` for the first kernel spawn after
    /// supervisor start.
    #[serde(default)]
    pub attempt_n: u32,
    /// Operator-policy ceiling at the time of the most recent
    /// restart.
    #[serde(default)]
    pub max_attempts: u32,
    /// Unix-seconds wallclock of the most recent restart
    /// attempt. `0` until the first restart.
    #[serde(default)]
    pub last_restart_unix_ts: i64,
    /// PascalCase reason for the most-recent restart attempt,
    /// matching `Outcome::reason_str()` in `classify.rs`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_restart_reason: Option<String>,
    /// Numeric exit status of the prior kernel run that
    /// triggered the most recent restart attempt.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prev_run_exit_code: Option<i32>,
    /// Number of restart attempts the supervisor has observed in
    /// the trailing `window_secs` window. Mirrors
    /// `CircuitBreakerState::attempts_in_window` so the
    /// dashboard can render `attempt 2 of 3` without re-reading
    /// the breaker file.
    #[serde(default)]
    pub attempts_in_window: u32,
    /// Sliding-window width in seconds.
    #[serde(default)]
    pub window_secs: u32,
    /// Supervisor process PID. The dashboard handler uses this
    /// to detect a dead supervisor and synthesise
    /// `SupervisorGone`. `0` is the "not yet known" sentinel.
    #[serde(default)]
    pub supervisor_pid: u32,
    /// Currently-spawned kernel process PID. `0` if none is
    /// alive.
    #[serde(default)]
    pub kernel_pid: u32,
    /// Wallclock unix-seconds of the most recent sentinel
    /// write. The dashboard handler uses this for staleness
    /// detection.
    #[serde(default)]
    pub updated_at_unix_secs: i64,
}

fn default_schema_version() -> u32 {
    1
}

impl Sentinel {
    pub fn fresh_healthy(supervisor_pid: u32, kernel_pid: u32, now_unix_secs: i64) -> Self {
        Self {
            schema_version: 1,
            status: "Healthy".to_owned(),
            sub_state: None,
            attempt_n: 0,
            max_attempts: 0,
            last_restart_unix_ts: 0,
            last_restart_reason: None,
            prev_run_exit_code: None,
            attempts_in_window: 0,
            window_secs: 0,
            supervisor_pid,
            kernel_pid,
            updated_at_unix_secs: now_unix_secs,
        }
    }
}

/// Write `sentinel` to `<data_dir>/kernel_lifecycle_status.json`
/// atomically. Per `self-healing-supervisor.md §4.6` this
/// function is the supervisor-side supported path for sentinel
/// mutation; the replacement kernel has a matching locked writer
/// for the restart-rehydrated acknowledgement.
pub fn write_sentinel(data_dir: &Path, sentinel: &Sentinel) -> std::io::Result<PathBuf> {
    let _guard = lock_sentinel(data_dir)?;
    write_sentinel_unlocked(data_dir, sentinel)
}

/// Atomically read the current sentinel under the shared
/// supervisor/kernel lock, build a replacement, and publish it via
/// rename before releasing the lock. Use this for transitions whose
/// output depends on the prior sentinel state.
pub fn update_sentinel<F>(data_dir: &Path, build: F) -> std::io::Result<PathBuf>
where
    F: FnOnce(std::io::Result<Option<Sentinel>>) -> Sentinel,
{
    let _guard = lock_sentinel(data_dir)?;
    let current = read_sentinel_unlocked(data_dir);
    let next = build(current);
    write_sentinel_unlocked(data_dir, &next)
}

/// Atomically update an existing sentinel under the shared lock.
/// Returns `Ok(None)` when no sentinel exists yet.
pub fn update_existing_sentinel<F>(data_dir: &Path, build: F) -> std::io::Result<Option<PathBuf>>
where
    F: FnOnce(Sentinel) -> Sentinel,
{
    let _guard = lock_sentinel(data_dir)?;
    match read_sentinel_unlocked(data_dir)? {
        Some(current) => write_sentinel_unlocked(data_dir, &build(current)).map(Some),
        None => Ok(None),
    }
}

/// Read the current sentinel back from disk. Returns
/// `Ok(None)` if the file is absent (expected on first boot
/// before the supervisor has had a chance to write anything).
pub fn read_sentinel(data_dir: &Path) -> std::io::Result<Option<Sentinel>> {
    read_sentinel_unlocked(data_dir)
}

fn read_sentinel_unlocked(data_dir: &Path) -> std::io::Result<Option<Sentinel>> {
    match std::fs::read(data_dir.join(SENTINEL_FILENAME)) {
        Ok(bytes) => {
            let s: Sentinel = serde_json::from_slice(&bytes).map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("sentinel deserialization failed: {e}"),
                )
            })?;
            Ok(Some(s))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

/// Atomically write a force-stop request for the running supervisor.
/// This is intentionally a file rather than a custom signal because
/// POSIX SIGKILL is not catchable; the supervisor needs a catchable
/// SIGTERM wakeup plus a durable "force" bit it can read before
/// forwarding shutdown to the child kernel.
pub fn write_force_stop_request(data_dir: &Path) -> std::io::Result<PathBuf> {
    std::fs::create_dir_all(data_dir)?;
    let final_path = data_dir.join(FORCE_STOP_REQUEST_FILENAME);
    let tmp_path = unique_temp_path(data_dir, FORCE_STOP_REQUEST_FILENAME);
    {
        use std::io::Write;
        let mut f = File::create(&tmp_path)?;
        let body = format!(
            "{{\"schema_version\":1,\"requested_at_unix_secs\":{}}}\n",
            unix_now_secs()
        );
        f.write_all(body.as_bytes())?;
        f.flush()?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp_path, &final_path)?;
    Ok(final_path)
}

/// Remove any stale force-stop request. Used at supervisor startup
/// so a crash between request creation and signal delivery cannot
/// make a future unrelated stop unexpectedly forceful.
pub fn clear_force_stop_request(data_dir: &Path) -> std::io::Result<()> {
    match std::fs::remove_file(data_dir.join(FORCE_STOP_REQUEST_FILENAME)) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

/// Consume the force-stop request if present. Returns `true` when
/// the current shutdown should skip SIGTERM grace and send SIGKILL
/// to the child kernel immediately.
pub fn consume_force_stop_request(data_dir: &Path) -> bool {
    match std::fs::remove_file(data_dir.join(FORCE_STOP_REQUEST_FILENAME)) {
        Ok(()) => true,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
        Err(e) => {
            eprintln!(
                "{{\"level\":\"warn\",\"event\":\"force_stop_request_consume_failed\",\
                 \"reason\":\"{e}\"}}"
            );
            false
        }
    }
}

fn unix_now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn write_then_read_round_trips_healthy() {
        let dir = tempdir().unwrap();
        let s = Sentinel::fresh_healthy(12345, 12346, 1_714_500_000);
        write_sentinel(dir.path(), &s).expect("write");
        let back = read_sentinel(dir.path()).expect("read").expect("present");
        assert_eq!(back.status, "Healthy");
        assert!(back.sub_state.is_none());
        assert_eq!(back.supervisor_pid, 12345);
        assert_eq!(back.kernel_pid, 12346);
        assert_eq!(back.updated_at_unix_secs, 1_714_500_000);
    }

    #[test]
    fn read_returns_none_when_missing() {
        let dir = tempdir().unwrap();
        let back = read_sentinel(dir.path()).expect("read");
        assert!(back.is_none());
    }

    #[test]
    fn write_overwrites_in_place() {
        let dir = tempdir().unwrap();
        let s1 = Sentinel::fresh_healthy(12345, 12346, 1_714_500_000);
        write_sentinel(dir.path(), &s1).unwrap();
        let mut s2 = s1.clone();
        s2.status = "Restarting".to_owned();
        s2.attempt_n = 2;
        s2.last_restart_reason = Some("DeadlockDetected".to_owned());
        s2.updated_at_unix_secs = 1_714_500_005;
        write_sentinel(dir.path(), &s2).unwrap();
        let back = read_sentinel(dir.path()).unwrap().unwrap();
        assert_eq!(back.status, "Restarting");
        assert_eq!(back.attempt_n, 2);
        assert_eq!(
            back.last_restart_reason.as_deref(),
            Some("DeadlockDetected")
        );
    }

    #[test]
    fn unknown_future_field_is_silently_ignored() {
        let dir = tempdir().unwrap();
        let raw = serde_json::json!({
            "schema_version": 1,
            "status": "Healthy",
            "supervisor_pid": 1,
            "kernel_pid": 2,
            "updated_at_unix_secs": 1_714_500_000,
            "future_field": "ignored",
        });
        std::fs::write(
            dir.path().join(SENTINEL_FILENAME),
            serde_json::to_vec(&raw).unwrap(),
        )
        .unwrap();
        let back = read_sentinel(dir.path()).expect("read").expect("present");
        assert_eq!(back.status, "Healthy");
    }

    #[test]
    fn force_stop_request_is_one_shot() {
        let dir = tempdir().unwrap();
        let path = write_force_stop_request(dir.path()).expect("write request");
        assert!(path.ends_with(FORCE_STOP_REQUEST_FILENAME));
        assert!(consume_force_stop_request(dir.path()));
        assert!(!consume_force_stop_request(dir.path()));
    }

    #[test]
    fn clear_force_stop_request_is_idempotent() {
        let dir = tempdir().unwrap();
        clear_force_stop_request(dir.path()).expect("clear missing");
        write_force_stop_request(dir.path()).expect("write request");
        clear_force_stop_request(dir.path()).expect("clear present");
        assert!(!consume_force_stop_request(dir.path()));
    }
}

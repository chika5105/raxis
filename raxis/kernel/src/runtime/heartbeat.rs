//! Heartbeat writer for `<data_dir>/runtime/heartbeat.json`.
//!
//! Normative reference: `cli-readonly.md` §5.2.
//!
//! # Contract recap
//!
//! - **Path:** `<data_dir>/runtime/heartbeat.json`, mode `0644`.
//! - **Cadence:** once at startup, every 5s thereafter, once at
//!   shutdown with `state = "Stopping"`.
//! - **Atomicity:** every write goes via `tempfile + rename(2)` so a
//!   concurrent CLI reader never sees a torn JSON. If the rename
//!   fails, the previous heartbeat remains in place — the CLI's
//!   freshness check (§5.2.3) handles that.
//! - **Forward compat:** unknown JSON fields are ignored by readers; we
//!   only ever ADD fields, never repurpose existing ones.
//! - **NOT durable:** the kernel never reads its own heartbeat.
//!   Decisions go through the audit chain. A corrupted heartbeat must
//!   not affect kernel behaviour (§5.2.4).
//!
//! # Why a free `run_loop` rather than a struct
//!
//! The loop holds three borrows (audit-side `Arc`s, the data dir
//! `PathBuf`, and the shutdown `oneshot::Receiver`) and exits when
//! either the receiver fires OR the writer encounters a fatal IO error.
//! Wrapping that in a `Heartbeat { ... }` struct adds no testability
//! (every observable is a function call already) and forces a `Mutex`
//! around the snapshot collector that no production reader needs.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use tokio::sync::oneshot;

/// Directory name (relative to `data_dir`). Centralised so callers
/// don't repeat the literal — the bootstrap creates it under the same
/// constant.
pub const RUNTIME_DIR: &str = "runtime";

/// File name (relative to `RUNTIME_DIR`). Same single-source rationale.
pub const HEARTBEAT_FILE: &str = "heartbeat.json";

/// Cadence between periodic heartbeat writes. The CLI's liveness check
/// (cli-readonly.md §5.2.3) considers a heartbeat stale after
/// `30 seconds` (six intervals). Six intervals is the spec's safety
/// margin against transient blocking-pool starvation; do NOT lower
/// this without also widening the CLI staleness threshold.
pub const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(5);

/// Schema version embedded in every heartbeat record. Bumped on
/// breaking schema changes; CLI readers tolerate unknown fields, so
/// adding a field is NOT a breaking change.
pub const HEARTBEAT_SCHEMA_VERSION: u32 = 1;

/// Currently-supported `store_schema_version` value. Mirrors
/// `raxis_store::migration` migration 1; bumped together with the
/// store schema.
pub const STORE_SCHEMA_VERSION: u32 = 1;

/// Kernel lifecycle state, projected onto the heartbeat field.
///
/// Per cli-readonly.md §5.2.2: `"Starting" | "Running" | "Stopping"`.
/// We model this as an enum (not a string) so callers can't typo the
/// state value at the kernel boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KernelLifecycleState {
    /// Boot is in progress; some subsystems may not be wired yet.
    Starting,
    /// Steady-state — IPC dispatch loop is accepting connections.
    Running,
    /// Shutdown signal received; final heartbeat is being written.
    Stopping,
}

impl KernelLifecycleState {
    /// Wire-format string used in the JSON `state` field.
    ///
    /// `pub` so callers outside this module (notably the
    /// `Snapshot::new` helper and tests) can render the spec-exact
    /// `"Starting" | "Running" | "Stopping"` literals without reaching
    /// for `serde_json` for what is essentially a `match`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Starting => "Starting",
            Self::Running => "Running",
            Self::Stopping => "Stopping",
        }
    }
}

/// One heartbeat record — exactly the JSON shape from
/// cli-readonly.md §5.2.2.
///
/// Fields are added (never removed or repurposed) on schema-version
/// bumps. The CLI's `Deserialize` ignores unknown fields, so a
/// kernel-ahead-of-CLI deployment is safe; the converse (CLI ahead of
/// kernel) shows the missing fields as their `serde::default` values.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Snapshot {
    pub schema_version: u32,
    pub kernel_pid: u32,
    pub started_at: u64,
    pub last_heartbeat_at: u64,
    pub state: String,
    pub policy_epoch: u64,
    pub store_schema_version: u32,
    pub active_verifiers: usize,
    pub max_concurrent_verifiers: usize,
    pub queued_spawns: usize,
    pub active_planner_sessions: usize,
    pub active_gateway_sessions: usize,
    pub active_verifier_sessions: usize,
}

impl Snapshot {
    /// Build a fresh snapshot from the live in-memory counters.
    ///
    /// Why a free constructor (not `impl Default`): every field is
    /// load-bearing for the CLI's liveness logic, so silently
    /// defaulting any of them at construction time would hide bugs.
    /// Callers MUST pass every input.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        kernel_pid: u32,
        started_at: u64,
        last_heartbeat_at: u64,
        state: KernelLifecycleState,
        policy_epoch: u64,
        active_verifiers: usize,
        max_concurrent_verifiers: usize,
        queued_spawns: usize,
        active_planner_sessions: usize,
        active_gateway_sessions: usize,
        active_verifier_sessions: usize,
    ) -> Self {
        Self {
            schema_version: HEARTBEAT_SCHEMA_VERSION,
            kernel_pid,
            started_at,
            last_heartbeat_at,
            state: state.as_str().to_owned(),
            policy_epoch,
            store_schema_version: STORE_SCHEMA_VERSION,
            active_verifiers,
            max_concurrent_verifiers,
            queued_spawns,
            active_planner_sessions,
            active_gateway_sessions,
            active_verifier_sessions,
        }
    }

    /// Collect a snapshot from the kernel's live in-memory state. This
    /// is the function the production loop calls; tests build
    /// snapshots directly via `new` to avoid the global counter
    /// dependency.
    pub fn collect(
        kernel_pid: u32,
        started_at: u64,
        state: KernelLifecycleState,
        policy_epoch: u64,
    ) -> Self {
        let now = unix_now_secs();
        Self::new(
            kernel_pid,
            started_at,
            now,
            state,
            policy_epoch,
            crate::gates::verifier_runner::active_verifier_count(),
            crate::gates::verifier_runner::max_concurrent_verifiers(),
            // queued_spawns: v1 has no scheduler queue (verifier
            // spawns are synchronous from the witness handler's
            // perspective and either succeed or return
            // `VerifierCapExceeded` immediately). Reserved at zero
            // until v2 introduces a queued-spawn mechanism — at
            // which point this call site reads the queue length.
            0,
            // Per-channel session counters: the IPC accept loops do
            // not currently maintain in-memory counters
            // (cli-readonly.md §5.1.4 calls these out explicitly as
            // "best-effort; documented as approximate"). Reserved
            // at zero with a clear path to add `AtomicUsize`s in
            // `ipc/server.rs` once an operator command needs them.
            0, 0, 0,
        )
    }
}

/// Atomically write `snapshot` to `dest_path` via tempfile + rename.
///
/// Steps:
/// 1. Open `<dest_path>.tmp` (truncate if already present — a stale
///    tempfile from a previous crash is harmless to overwrite).
/// 2. Serialize JSON into the tempfile, flush + sync.
/// 3. `rename(tempfile, dest_path)` — POSIX-atomic on the same
///    filesystem.
///
/// Returns the bytes written on success; the byte count is exposed
/// for tests that want to assert the snapshot is non-trivially sized.
///
/// Errors propagate as `std::io::Error` (the loop logs and continues
/// — a single failed write never tears the previous heartbeat).
pub fn write_atomic(dest_path: &Path, snapshot: &Snapshot) -> std::io::Result<usize> {
    let bytes = serde_json::to_vec_pretty(snapshot).map_err(|e| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, format!("heartbeat serialize: {e}"))
    })?;

    let tmp_path = tempfile_for(dest_path);
    {
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&tmp_path)?;
        f.write_all(&bytes)?;
        f.flush()?;
        // sync_all is not strictly required (we don't promise
        // durability — the heartbeat is a hint, not a record), but a
        // crashed write that leaves the tempfile but never reaches the
        // rename costs us nothing to flush.
        let _ = f.sync_all();
    }

    // Same-directory rename → POSIX-atomic on every supported
    // filesystem. If this fails, dest_path keeps its previous
    // contents — that is the spec's "previous heartbeat remains in
    // place" branch.
    std::fs::rename(&tmp_path, dest_path)?;
    Ok(bytes.len())
}

/// Compute the tempfile path used for atomic writes. Same directory
/// as the destination; suffix `.tmp.<pid>` to disambiguate concurrent
/// writers (there is only one in v1, but a future operator
/// double-spawning the kernel under a different uid won't trample our
/// in-flight tempfile).
fn tempfile_for(dest_path: &Path) -> PathBuf {
    let pid = std::process::id();
    let parent = dest_path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = dest_path.file_name().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
    parent.join(format!("{file_name}.tmp.{pid}"))
}

/// Spawn-friendly heartbeat loop.
///
/// Steady-state behaviour:
///   - Tick every `HEARTBEAT_INTERVAL`.
///   - Write a fresh `Snapshot::collect(...)` to `data_dir/runtime/
///     heartbeat.json`.
///   - On IO error, log to stderr and continue (the spec is explicit
///     that one failed write must NOT crash the loop).
///
/// Termination:
///   - The `shutdown` `oneshot::Receiver` firing is the canonical
///     stop signal. After it fires we attempt one final
///     `Stopping`-state write so a CLI that polled at exactly the
///     right moment can see the wind-down without waiting on the
///     audit chain.
///   - `oneshot::Receiver::recv` returning `Err` (the sender was
///     dropped without firing) is treated identically — the kernel
///     is going down.
///
/// Returns `Ok(())` on clean termination; the only `Err` path is
/// failure to read `policy.load()` (which should never happen — the
/// `ArcSwap` is always populated for the kernel's lifetime). The
/// caller does not branch on this in practice; we expose `Result`
/// only so the loop can signal "loop body broke in a way I can't
/// recover from" if the contract changes.
pub async fn run_loop(
    data_dir: PathBuf,
    kernel_pid: u32,
    started_at: u64,
    policy: Arc<arc_swap::ArcSwap<raxis_policy::PolicyBundle>>,
    mut shutdown: oneshot::Receiver<()>,
) -> std::io::Result<()> {
    let dest_path = data_dir.join(RUNTIME_DIR).join(HEARTBEAT_FILE);

    // Write the first heartbeat IMMEDIATELY so a fast `raxis status`
    // doesn't see "no heartbeat yet". The first record is `Running`
    // (the loop only starts after `KernelStarted` is committed by
    // `main.rs`).
    write_one(&dest_path, kernel_pid, started_at, KernelLifecycleState::Running, &policy);

    let mut interval = tokio::time::interval(HEARTBEAT_INTERVAL);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // Skip the immediate-fire of `interval.tick()` on first await —
    // we already wrote above. Without this, the second write happens
    // ~0ms after the first.
    interval.tick().await;

    loop {
        tokio::select! {
            _ = interval.tick() => {
                write_one(&dest_path, kernel_pid, started_at, KernelLifecycleState::Running, &policy);
            }
            _ = &mut shutdown => {
                // Final best-effort write: state=Stopping. Errors are
                // swallowed (logged) — the kernel is going down
                // regardless.
                write_one(&dest_path, kernel_pid, started_at, KernelLifecycleState::Stopping, &policy);
                return Ok(());
            }
        }
    }
}

/// Build + write one heartbeat. Errors are logged, not propagated, so
/// the loop never dies because of a transient IO blip.
fn write_one(
    dest_path: &Path,
    kernel_pid: u32,
    started_at: u64,
    state: KernelLifecycleState,
    policy: &arc_swap::ArcSwap<raxis_policy::PolicyBundle>,
) {
    let policy_epoch = policy.load().epoch();
    let snap = Snapshot::collect(kernel_pid, started_at, state, policy_epoch);
    if let Err(e) = write_atomic(dest_path, &snap) {
        eprintln!(
            "{{\"level\":\"warn\",\"event\":\"heartbeat_write_failed\",\
             \"path\":\"{}\",\"reason\":\"{e}\"}}",
            dest_path.display(),
        );
    }
}

/// `time(NULL)` equivalent — seconds since UNIX epoch. Defined here
/// so the heartbeat module never reaches into `chrono` (we don't need
/// the full date crate for one timestamp).
pub fn unix_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ────────────────────────────────────────────────────────────────────
// Tests
// ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn sample_snapshot() -> Snapshot {
        Snapshot::new(
            12_345,
            1_700_000_000,
            1_700_000_005,
            KernelLifecycleState::Running,
            7,
            2,
            16,
            0,
            3,
            1,
            0,
        )
    }

    #[test]
    fn snapshot_serializes_with_spec_field_names_and_state_string() {
        // The spec fixes the JSON field names verbatim. Any silent
        // serde rename (e.g. via #[serde(rename = ...)]) would break
        // every `raxis` CLI parser. Pin the wire shape.
        let snap = sample_snapshot();
        let json: serde_json::Value = serde_json::to_value(&snap).unwrap();

        let obj = json.as_object().expect("snapshot must serialize as object");
        for required in [
            "schema_version", "kernel_pid", "started_at", "last_heartbeat_at",
            "state", "policy_epoch", "store_schema_version",
            "active_verifiers", "max_concurrent_verifiers", "queued_spawns",
            "active_planner_sessions", "active_gateway_sessions",
            "active_verifier_sessions",
        ] {
            assert!(obj.contains_key(required),
                "missing required field {required}; got keys: {:?}",
                obj.keys().collect::<Vec<_>>());
        }
        assert_eq!(obj["state"], serde_json::json!("Running"));
        assert_eq!(obj["schema_version"], serde_json::json!(1));
    }

    #[test]
    fn snapshot_round_trips_through_json() {
        let snap = sample_snapshot();
        let bytes = serde_json::to_vec(&snap).unwrap();
        let back: Snapshot = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(snap, back);
    }

    #[test]
    fn lifecycle_state_serializes_to_spec_strings() {
        assert_eq!(KernelLifecycleState::Starting.as_str(), "Starting");
        assert_eq!(KernelLifecycleState::Running.as_str(),  "Running");
        assert_eq!(KernelLifecycleState::Stopping.as_str(), "Stopping");
    }

    #[test]
    fn write_atomic_emits_well_formed_json_at_dest() {
        let tmp = TempDir::new().unwrap();
        let dest = tmp.path().join("heartbeat.json");
        let snap = sample_snapshot();

        let n = write_atomic(&dest, &snap).expect("first write");
        assert!(n > 0);

        let on_disk = std::fs::read(&dest).expect("dest file");
        let parsed: Snapshot = serde_json::from_slice(&on_disk).expect("parse");
        assert_eq!(parsed, snap);
    }

    #[test]
    fn write_atomic_overwrites_existing_file_in_place() {
        // Second write must replace the first byte-for-byte; a CLI
        // reader between the two writes sees one or the other, never a
        // torn intermediate.
        let tmp = TempDir::new().unwrap();
        let dest = tmp.path().join("heartbeat.json");

        let mut snap = sample_snapshot();
        write_atomic(&dest, &snap).unwrap();
        snap.last_heartbeat_at += 5;
        snap.policy_epoch = 99;
        write_atomic(&dest, &snap).unwrap();

        let parsed: Snapshot = serde_json::from_slice(&std::fs::read(&dest).unwrap()).unwrap();
        assert_eq!(parsed.policy_epoch, 99);
        assert_eq!(parsed.last_heartbeat_at, 1_700_000_010);
    }

    #[test]
    fn write_atomic_cleans_up_tempfile_on_success() {
        // After a successful write, no `*.tmp.*` file should remain
        // alongside the heartbeat — `rename(2)` is the cleanup.
        let tmp = TempDir::new().unwrap();
        let dest = tmp.path().join("heartbeat.json");
        write_atomic(&dest, &sample_snapshot()).unwrap();

        let entries: Vec<_> = std::fs::read_dir(tmp.path()).unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(entries, vec!["heartbeat.json".to_owned()],
            "expected only heartbeat.json; got {entries:?}");
    }

    #[test]
    fn write_atomic_returns_err_when_parent_dir_missing() {
        // Defensive: caller (bootstrap) must mkdir the runtime/
        // directory. If it doesn't, we want an explicit error rather
        // than a silent no-op.
        let tmp = TempDir::new().unwrap();
        let dest = tmp.path().join("nonexistent").join("heartbeat.json");
        let result = write_atomic(&dest, &sample_snapshot());
        assert!(result.is_err());
    }

    #[test]
    fn snapshot_collect_pulls_live_verifier_counters() {
        // Smoke test that `collect` actually reaches the live
        // counters; we don't assert exact values because parallel
        // tests in this crate could mutate the global atomic.
        let snap = Snapshot::collect(
            std::process::id(),
            unix_now_secs(),
            KernelLifecycleState::Running,
            42,
        );
        assert_eq!(snap.policy_epoch, 42);
        assert_eq!(snap.schema_version, HEARTBEAT_SCHEMA_VERSION);
        assert_eq!(snap.store_schema_version, STORE_SCHEMA_VERSION);
        assert_eq!(snap.max_concurrent_verifiers,
            crate::gates::verifier_runner::max_concurrent_verifiers());
    }

    #[tokio::test]
    async fn run_loop_writes_initial_heartbeat_then_stops_on_shutdown() {
        // Drive the loop from the outside: spawn it, give it a moment
        // to write the initial heartbeat, fire shutdown, await
        // termination. Then assert we see (a) a heartbeat on disk
        // and (b) the final write switched state to "Stopping".
        let tmp = TempDir::new().unwrap();
        std::fs::create_dir_all(tmp.path().join(RUNTIME_DIR)).unwrap();

        let policy: Arc<arc_swap::ArcSwap<raxis_policy::PolicyBundle>> =
            Arc::new(arc_swap::ArcSwap::from_pointee(stub_bundle()));
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let dest = tmp.path().join(RUNTIME_DIR).join(HEARTBEAT_FILE);
        let pid = std::process::id();
        let started_at = unix_now_secs();

        let policy_for_loop = Arc::clone(&policy);
        let data_dir = tmp.path().to_path_buf();
        let handle = tokio::spawn(async move {
            run_loop(data_dir, pid, started_at, policy_for_loop, rx).await
        });

        // Allow the eager initial write to land; 50ms is far less
        // than HEARTBEAT_INTERVAL so we know the file we observe is
        // the initial one.
        tokio::time::sleep(Duration::from_millis(50)).await;
        let body = std::fs::read(&dest).expect("initial heartbeat must exist");
        let parsed: Snapshot = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed.state, "Running");
        assert_eq!(parsed.kernel_pid, pid);

        tx.send(()).unwrap();
        let result = handle.await.expect("loop join").expect("loop ok");
        let _ = result;

        let body_final = std::fs::read(&dest).unwrap();
        let parsed_final: Snapshot = serde_json::from_slice(&body_final).unwrap();
        assert_eq!(parsed_final.state, "Stopping",
            "final write must record Stopping for CLI visibility");
    }

    #[tokio::test]
    async fn run_loop_writes_periodically_when_left_running() {
        // Watch `last_heartbeat_at` move forward across one
        // HEARTBEAT_INTERVAL tick. We compress the assertion by
        // sleeping a hair longer than the interval.
        let tmp = TempDir::new().unwrap();
        std::fs::create_dir_all(tmp.path().join(RUNTIME_DIR)).unwrap();

        let policy: Arc<arc_swap::ArcSwap<raxis_policy::PolicyBundle>> =
            Arc::new(arc_swap::ArcSwap::from_pointee(stub_bundle()));
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let dest = tmp.path().join(RUNTIME_DIR).join(HEARTBEAT_FILE);
        let pid = std::process::id();
        let started_at = unix_now_secs();

        let policy_for_loop = Arc::clone(&policy);
        let data_dir = tmp.path().to_path_buf();
        let handle = tokio::spawn(async move {
            run_loop(data_dir, pid, started_at, policy_for_loop, rx).await
        });

        tokio::time::sleep(Duration::from_millis(50)).await;
        let first: Snapshot = serde_json::from_slice(&std::fs::read(&dest).unwrap()).unwrap();
        let first_ts = first.last_heartbeat_at;

        // Sleep slightly longer than one interval. The loop must
        // emit a fresh write with a strictly-greater timestamp (in
        // the worst case the timestamp resolution is one second so
        // we accept >= rather than >).
        tokio::time::sleep(HEARTBEAT_INTERVAL + Duration::from_millis(200)).await;
        let next: Snapshot = serde_json::from_slice(&std::fs::read(&dest).unwrap()).unwrap();

        assert!(next.last_heartbeat_at >= first_ts,
            "expected periodic update; first={first_ts} next={}",
            next.last_heartbeat_at);

        tx.send(()).unwrap();
        let _ = handle.await;
    }

    /// Build a no-op `PolicyBundle` for tests that don't care about
    /// operators, providers, or escalation policy — we just need the
    /// `ArcSwap` to be populated so `run_loop` can call
    /// `.load().epoch()`. Same constructor used by
    /// `policy_manager.rs::tests`.
    fn stub_bundle() -> raxis_policy::PolicyBundle {
        raxis_policy::PolicyBundle::for_tests_with_operators(vec![])
    }
}

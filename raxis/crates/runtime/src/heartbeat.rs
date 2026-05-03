//! Heartbeat record type and atomic file I/O used by both the kernel
//! (writer) and the CLI (reader).
//!
//! Normative reference: `cli-readonly.md` §5.2.
//!
//! # Contract recap
//!
//! - **Path:** `<data_dir>/runtime/heartbeat.json`, mode `0644`.
//! - **Cadence:** kernel writes once at startup, every
//!   `HEARTBEAT_INTERVAL` thereafter, and once at shutdown with
//!   `state = "Stopping"`.
//! - **Atomicity:** every write goes via `tempfile + rename(2)` so a
//!   concurrent CLI reader never sees a torn JSON.
//! - **Forward compat:** new JSON fields are ADDED (never removed or
//!   repurposed). Readers tolerate unknown fields via the default
//!   `serde_json::from_slice` behaviour; writers ahead of the spec
//!   keep the existing fields' meanings.
//! - **NOT durable:** the kernel never reads its own heartbeat.
//!   Decisions go through the audit chain. A corrupted heartbeat must
//!   not affect kernel behaviour (§5.2.4).
//!
//! # What lives here vs. in the kernel
//!
//! This crate owns:
//!   - the `Snapshot` struct (wire shape),
//!   - the `KernelLifecycleState` enum (typed `state` field),
//!   - the `write_atomic` writer + `read` reader (both binaries use
//!     the SAME serializer so wire shape can never drift), and
//!   - the cadence/staleness constants.
//!
//! The kernel owns the `collect`/`run_loop` glue that pulls live
//! counters out of `raxis-kernel` internals (verifier runner,
//! policy `ArcSwap`, IPC accept loops). That glue lives in
//! `raxis-kernel::runtime::heartbeat`.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

/// Directory name (relative to `data_dir`). Bootstrap creates it under
/// the same constant so the writer and the reader cannot disagree on
/// the location.
pub const RUNTIME_DIR: &str = "runtime";

/// File name (relative to `RUNTIME_DIR`). Single source of truth.
pub const HEARTBEAT_FILE: &str = "heartbeat.json";

/// Cadence between periodic heartbeat writes by the kernel. The CLI's
/// liveness check (cli-readonly.md §5.2.3) considers a heartbeat stale
/// after `HEARTBEAT_STALE_AFTER` (six intervals). Six intervals is the
/// spec's safety margin against transient blocking-pool starvation;
/// do NOT lower this without also widening the staleness threshold.
pub const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(5);

/// Maximum age of a heartbeat record before the CLI must consider the
/// kernel "stale or dead". Six intervals. Encoded here (not just in
/// the CLI) so the contract is testable from a single source.
pub const HEARTBEAT_STALE_AFTER: Duration = Duration::from_secs(30);

/// Schema version embedded in every heartbeat record. Bumped on
/// breaking schema changes; CLI readers tolerate unknown fields, so
/// adding a field is NOT a breaking change.
pub const HEARTBEAT_SCHEMA_VERSION: u32 = 1;

/// Currently-supported `store_schema_version` value. Mirrors
/// `raxis_store::SCHEMA_VERSION`; bumped together with the store
/// schema. Held here (rather than imported from `raxis-store`) to
/// keep this crate dependency-light — the CLI checks both
/// independently.
pub const STORE_SCHEMA_VERSION: u32 = 1;

/// Kernel lifecycle state, projected onto the heartbeat field.
///
/// Per cli-readonly.md §5.2.2: `"Starting" | "Running" | "Stopping"`.
/// Modeled as an enum (not a string) so callers can't typo the state
/// value at the kernel boundary.
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
/// bumps. `#[serde(default)]` on every optional-by-version field
/// means a CLI ahead of the kernel sees the new fields as defaults
/// rather than failing to parse.
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
    /// Build a fresh snapshot from raw counters.
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

    /// Return `true` if `last_heartbeat_at` is within
    /// `HEARTBEAT_STALE_AFTER` of `now_secs`. The CLI uses this
    /// (rather than rolling its own arithmetic) so the staleness
    /// rule lives in exactly one place.
    pub fn is_live(&self, now_secs: u64) -> bool {
        // Saturating_sub handles a clock skew where the heartbeat is
        // FROM the future — we treat that as fresh, not stale.
        let age = now_secs.saturating_sub(self.last_heartbeat_at);
        age <= HEARTBEAT_STALE_AFTER.as_secs()
    }
}

/// Errors the CLI can surface from `read`. Each variant maps onto a
/// distinct user-facing diagnostic — the CLI's `raxis status` exit
/// codes branch on these.
#[derive(Debug, thiserror::Error)]
pub enum ReadError {
    #[error("heartbeat file not found at {0} (kernel may not be running, or runtime/ not yet created)")]
    Missing(PathBuf),

    #[error("failed to open heartbeat file at {path}: {source}")]
    Open { path: PathBuf, #[source] source: std::io::Error },

    #[error("failed to read heartbeat file at {path}: {source}")]
    Io { path: PathBuf, #[source] source: std::io::Error },

    #[error("heartbeat file at {path} is malformed: {source}")]
    Parse { path: PathBuf, #[source] source: serde_json::Error },

    #[error(
        "heartbeat schema version mismatch at {path}: \
         file reports v{found}, this binary supports v{expected}"
    )]
    SchemaMismatch { path: PathBuf, expected: u32, found: u32 },
}

/// Atomically write `snapshot` to `dest_path` via tempfile + rename.
///
/// Steps:
/// 1. Open `<dest_path>.tmp.<pid>` (truncate if already present — a
///    stale tempfile from a previous crash is harmless to overwrite).
/// 2. Serialize JSON into the tempfile, flush + sync.
/// 3. `rename(tempfile, dest_path)` — POSIX-atomic on the same
///    filesystem.
///
/// Returns the bytes written on success. The byte count is exposed
/// for tests that want to assert the snapshot is non-trivially sized.
///
/// Errors propagate as `std::io::Error`. The kernel's loop logs and
/// continues — a single failed write never tears the previous
/// heartbeat.
pub fn write_atomic(dest_path: &Path, snapshot: &Snapshot) -> std::io::Result<usize> {
    let bytes = serde_json::to_vec_pretty(snapshot).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("heartbeat serialize: {e}"),
        )
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
        // crashed write that leaves the tempfile but never reaches
        // the rename costs us nothing to flush.
        let _ = f.sync_all();
    }

    // Same-directory rename → POSIX-atomic on every supported
    // filesystem. If this fails, dest_path keeps its previous
    // contents — that is the spec's "previous heartbeat remains in
    // place" branch.
    std::fs::rename(&tmp_path, dest_path)?;
    Ok(bytes.len())
}

/// Read the heartbeat at `<data_dir>/runtime/heartbeat.json` and
/// validate the schema-version pin.
///
/// Errors are typed (`ReadError`) so the CLI can branch on
/// "kernel not running" (`Missing`) vs. "bad version" (`SchemaMismatch`)
/// vs. "torn JSON" (`Parse`).
pub fn read(data_dir: &Path) -> Result<Snapshot, ReadError> {
    let path = data_dir.join(RUNTIME_DIR).join(HEARTBEAT_FILE);

    let body = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(ReadError::Missing(path));
        }
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            return Err(ReadError::Open { path, source: e });
        }
        Err(e) => return Err(ReadError::Io { path, source: e }),
    };

    let snap: Snapshot = serde_json::from_slice(&body)
        .map_err(|e| ReadError::Parse { path: path.clone(), source: e })?;

    if snap.schema_version != HEARTBEAT_SCHEMA_VERSION {
        return Err(ReadError::SchemaMismatch {
            path,
            expected: HEARTBEAT_SCHEMA_VERSION,
            found: snap.schema_version,
        });
    }

    Ok(snap)
}

/// `time(NULL)` equivalent — seconds since UNIX epoch. Defined here
/// so callers don't need to pull `chrono` for one timestamp.
pub fn unix_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Compute the tempfile path used for atomic writes. Same directory
/// as the destination; suffix `.tmp.<pid>` to disambiguate concurrent
/// writers (there is only one in v1, but a future operator
/// double-spawning the kernel under a different uid won't trample
/// our in-flight tempfile).
fn tempfile_for(dest_path: &Path) -> PathBuf {
    let pid = std::process::id();
    let parent = dest_path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = dest_path
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    parent.join(format!("{file_name}.tmp.{pid}"))
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
            assert!(
                obj.contains_key(required),
                "missing required field {required}; got keys: {:?}",
                obj.keys().collect::<Vec<_>>()
            );
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
        assert_eq!(KernelLifecycleState::Running.as_str(), "Running");
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
        let tmp = TempDir::new().unwrap();
        let dest = tmp.path().join("heartbeat.json");
        write_atomic(&dest, &sample_snapshot()).unwrap();

        let entries: Vec<_> = std::fs::read_dir(tmp.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            entries,
            vec!["heartbeat.json".to_owned()],
            "expected only heartbeat.json; got {entries:?}"
        );
    }

    #[test]
    fn write_atomic_returns_err_when_parent_dir_missing() {
        let tmp = TempDir::new().unwrap();
        let dest = tmp.path().join("nonexistent").join("heartbeat.json");
        let result = write_atomic(&dest, &sample_snapshot());
        assert!(result.is_err());
    }

    #[test]
    fn read_returns_missing_when_file_absent() {
        let tmp = TempDir::new().unwrap();
        std::fs::create_dir_all(tmp.path().join(RUNTIME_DIR)).unwrap();
        let err = read(tmp.path()).unwrap_err();
        assert!(matches!(err, ReadError::Missing(_)),
            "expected Missing, got {err:?}");
    }

    #[test]
    fn read_returns_missing_when_runtime_dir_absent() {
        let tmp = TempDir::new().unwrap();
        let err = read(tmp.path()).unwrap_err();
        assert!(matches!(err, ReadError::Missing(_)),
            "expected Missing (runtime/ absent), got {err:?}");
    }

    #[test]
    fn read_returns_parse_error_on_torn_json() {
        let tmp = TempDir::new().unwrap();
        std::fs::create_dir_all(tmp.path().join(RUNTIME_DIR)).unwrap();
        let dest = tmp.path().join(RUNTIME_DIR).join(HEARTBEAT_FILE);
        std::fs::write(&dest, b"{not-valid-json").unwrap();
        let err = read(tmp.path()).unwrap_err();
        assert!(matches!(err, ReadError::Parse { .. }),
            "expected Parse, got {err:?}");
    }

    #[test]
    fn read_returns_schema_mismatch_when_version_differs() {
        let tmp = TempDir::new().unwrap();
        std::fs::create_dir_all(tmp.path().join(RUNTIME_DIR)).unwrap();
        let dest = tmp.path().join(RUNTIME_DIR).join(HEARTBEAT_FILE);
        // Hand-rolled JSON with a future schema version.
        let raw = r#"{
            "schema_version": 999,
            "kernel_pid": 1,
            "started_at": 0,
            "last_heartbeat_at": 0,
            "state": "Running",
            "policy_epoch": 1,
            "store_schema_version": 1,
            "active_verifiers": 0,
            "max_concurrent_verifiers": 0,
            "queued_spawns": 0,
            "active_planner_sessions": 0,
            "active_gateway_sessions": 0,
            "active_verifier_sessions": 0
        }"#;
        std::fs::write(&dest, raw).unwrap();
        let err = read(tmp.path()).unwrap_err();
        match err {
            ReadError::SchemaMismatch { expected, found, .. } => {
                assert_eq!(expected, HEARTBEAT_SCHEMA_VERSION);
                assert_eq!(found, 999);
            }
            other => panic!("expected SchemaMismatch, got {other:?}"),
        }
    }

    #[test]
    fn read_round_trips_with_write_atomic() {
        let tmp = TempDir::new().unwrap();
        std::fs::create_dir_all(tmp.path().join(RUNTIME_DIR)).unwrap();
        let dest = tmp.path().join(RUNTIME_DIR).join(HEARTBEAT_FILE);
        let snap = sample_snapshot();
        write_atomic(&dest, &snap).unwrap();

        let back = read(tmp.path()).expect("read back");
        assert_eq!(back, snap);
    }

    #[test]
    fn is_live_returns_true_within_window_and_false_after() {
        let snap = sample_snapshot(); // last_heartbeat_at = 1_700_000_005
        assert!(snap.is_live(1_700_000_005), "exact same instant must be live");
        assert!(snap.is_live(1_700_000_005 + HEARTBEAT_STALE_AFTER.as_secs()),
            "edge of window must be live");
        assert!(!snap.is_live(1_700_000_005 + HEARTBEAT_STALE_AFTER.as_secs() + 1),
            "one second past window must be stale");
    }

    #[test]
    fn is_live_treats_future_heartbeat_as_live() {
        // Clock skew can put the heartbeat one or two seconds ahead of
        // `now_secs`. We must NOT call that stale.
        let snap = sample_snapshot();
        assert!(snap.is_live(snap.last_heartbeat_at - 2),
            "heartbeat from 'future' must be live (clock skew tolerance)");
    }
}

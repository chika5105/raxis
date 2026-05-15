// raxis-kernel::deadlock_dump — forensic-dump writer for the
// runtime deadlock watcher.
//
// Normative reference: `specs/v2/self-healing-supervisor.md §3.1`.
//
// **Why this lives in its own module.**
//
// The deadlock watcher (`spawn_deadlock_watcher` in `main.rs`)
// runs on a dedicated background thread that wakes every 2 s and
// calls `parking_lot::deadlock::check_deadlock()`. When it
// detects a cycle, it MUST write the lock-graph + per-thread
// backtraces to a sibling file BEFORE exiting non-zero — because
// the kernel's own audit pipeline may itself be wedged on the
// very mutex that deadlocked, and we cannot risk depending on
// any subsystem that takes a `parking_lot::Mutex` /
// `parking_lot::RwLock` to land the forensic record.
//
// Concretely, this module:
//
//   * has NO dependency on `raxis_audit_tools::AuditSink` (which
//     wraps the audit writer in a `std::sync::Mutex` and may
//     itself be deadlocked);
//   * has NO dependency on `raxis_store::Store` (which wraps the
//     SQLite connection in a `tokio::sync::Mutex`);
//   * does NOT take any `parking_lot::Mutex` / `parking_lot::RwLock`
//     internally — the writer only touches `std::fs` + `std::io`
//     primitives.
//
// The dump is written atomically (`tempfile + rename`) so a
// partial dump never lands at a final filename. Disk-full /
// EROFS surfaces as `std::io::Error`; the watcher logs the I/O
// error on stderr and proceeds to `process::exit(70)` regardless,
// so the *exit signal* is the unconditional contract and the
// dump is best-effort persisted forensics.

#![forbid(unsafe_code)]

use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Forensic dump payload written by the deadlock watcher.
///
/// The boot-time rehydration path in `main.rs` reads this back
/// and synthesises a [`raxis_audit_tools::AuditEventKind::KernelDeadlockDetected`]
/// event from `thread_count` + `lock_count` + `detected_at_unix_secs`
/// + the dump path. The full per-thread backtrace stays in the
/// JSON file (the audit chain is a wire-shape contract; we keep
/// the full forensic blob in a sidecar to avoid bloating every
/// chain line with thousands of bytes of backtrace).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeadlockDump {
    /// `CARGO_PKG_VERSION` at the time the dump was written.
    /// Cross-references the kernel binary that produced the
    /// cycle; useful when post-hoc analysis spans multiple
    /// kernel versions.
    pub kernel_version: String,
    /// Wall-clock unix-seconds when the watcher's
    /// `parking_lot::deadlock::check_deadlock()` returned a
    /// non-empty result.
    pub detected_at_unix_secs: i64,
    /// Number of distinct deadlock cycles in the same detection.
    /// Almost always `1` in practice; recorded for forensic
    /// completeness in the rare multi-cycle case.
    pub cycle_count: u32,
    /// Total threads across all cycles. Lifted to the top level
    /// so the synthesised audit event can carry a flat counter.
    pub thread_count: u32,
    /// Total lock acquisitions across all cycles. Lifted to the
    /// top level for the audit event's flat counter.
    pub lock_count: u32,
    /// Per-cycle thread + backtrace listing.
    pub cycles: Vec<DeadlockCycle>,
}

/// One detected deadlock cycle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeadlockCycle {
    /// 0-indexed cycle number within the detection.
    pub cycle_index: u32,
    /// Threads that participate in this cycle.
    pub threads: Vec<DeadlockThread>,
}

/// One thread participating in a detected cycle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeadlockThread {
    /// `parking_lot`'s opaque thread id (rendered via
    /// `format!("{:?}", t.thread_id())`). This matches the
    /// stderr `event="deadlock_cycle_member"` lines the watcher
    /// logs alongside the dump, so post-mortem tooling can
    /// cross-reference dump rows against stderr lines.
    pub thread_id: String,
    /// The thread's parked backtrace, rendered via
    /// `format!("{:?}", t.backtrace())`. `parking_lot`'s
    /// backtrace format is opaque; we store the rendered string
    /// so analysis is grep-friendly.
    pub backtrace: String,
}

// ---------------------------------------------------------------------------
// Filename helpers
// ---------------------------------------------------------------------------

/// Per-spec filename `<data_dir>/deadlock_dump_<unix_ts>.json`.
pub fn dump_filename(detected_at_unix_secs: i64) -> String {
    format!("deadlock_dump_{detected_at_unix_secs}.json")
}

/// Per-spec consumed-dump folder
/// `<data_dir>/deadlock_dumps_consumed/`. Boot-time rehydration
/// moves processed dumps here so the next boot does not
/// double-emit.
pub fn consumed_dir(data_dir: &Path) -> PathBuf {
    data_dir.join("deadlock_dumps_consumed")
}

/// Returns `true` iff `name` matches the
/// `deadlock_dump_<digits>.json` shape. Defensively scoped: we
/// only consume files we wrote, never anything else under the
/// data dir.
pub fn is_dump_filename(name: &str) -> bool {
    if !name.starts_with("deadlock_dump_") || !name.ends_with(".json") {
        return false;
    }
    let stem = &name["deadlock_dump_".len()..name.len() - ".json".len()];
    !stem.is_empty() && stem.bytes().all(|b| b.is_ascii_digit())
}

// ---------------------------------------------------------------------------
// write_dump
// ---------------------------------------------------------------------------

/// Atomically write `dump` to `<data_dir>/deadlock_dump_<unix_ts>.json`.
///
/// Atomicity contract: the function writes to a sibling tempfile
/// inside the same directory (so `rename` is in-fs and
/// `std::fs::rename` is atomic), `flush`+`sync_all`s the
/// tempfile, then `rename`s into the final name. A crash mid-
/// write leaves either the old file (if any) or the temp;
/// the temp's name (`.deadlock_dump_<ts>.json.tmp`) is filtered
/// by [`is_dump_filename`] so the rehydration scan ignores it.
///
/// Returns the final on-disk path on success.
///
/// **Panics:** none. All error paths surface as `Err`.
///
/// **Locks taken:** none. Safe to call from a thread holding
/// arbitrary other locks (the entire point — the watcher fires
/// while the kernel is wedged on at least one mutex).
pub fn write_dump(data_dir: &Path, dump: &DeadlockDump) -> std::io::Result<PathBuf> {
    fs::create_dir_all(data_dir)?;
    let final_path = data_dir.join(dump_filename(dump.detected_at_unix_secs));
    let tmp_path = data_dir.join(format!(
        ".deadlock_dump_{ts}.json.tmp",
        ts = dump.detected_at_unix_secs
    ));
    let bytes = serde_json::to_vec_pretty(dump).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("dump serialization failed: {e}"),
        )
    })?;
    {
        let mut f = File::create(&tmp_path)?;
        f.write_all(&bytes)?;
        f.flush()?;
        // sync_all (vs sync_data) covers the directory entry on
        // platforms where it matters; on macOS HFS+/APFS it's a
        // F_FULLFSYNC which is what we want for a forensic
        // record.
        f.sync_all()?;
    }
    fs::rename(&tmp_path, &final_path)?;
    Ok(final_path)
}

/// Read a previously-written dump back from disk. Used by the
/// boot-time rehydration path in `main.rs`.
pub fn read_dump(path: &Path) -> std::io::Result<DeadlockDump> {
    let bytes = fs::read(path)?;
    serde_json::from_slice::<DeadlockDump>(&bytes).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("dump deserialization failed: {e}"),
        )
    })
}

/// Move a processed dump into `<data_dir>/deadlock_dumps_consumed/`
/// so the next boot does not double-emit it.
pub fn move_to_consumed(data_dir: &Path, dump_path: &Path) -> std::io::Result<PathBuf> {
    let consumed = consumed_dir(data_dir);
    fs::create_dir_all(&consumed)?;
    let name = dump_path.file_name().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "dump path has no filename",
        )
    })?;
    let target = consumed.join(name);
    fs::rename(dump_path, &target)?;
    Ok(target)
}

/// Enumerate unprocessed dump files (sorted by `detected_at_unix_secs`
/// ascending) under `data_dir`. Files inside
/// `deadlock_dumps_consumed/` are NOT returned. Tempfiles
/// (`.deadlock_dump_*.json.tmp`) are NOT returned.
pub fn scan_pending_dumps(data_dir: &Path) -> std::io::Result<Vec<PathBuf>> {
    let mut out: Vec<PathBuf> = Vec::new();
    let read = match fs::read_dir(data_dir) {
        Ok(r) => r,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
        Err(e) => return Err(e),
    };
    for entry in read {
        let entry = entry?;
        let ft = entry.file_type()?;
        if !ft.is_file() {
            continue;
        }
        let name = match entry.file_name().into_string() {
            Ok(s) => s,
            Err(_) => continue, // non-UTF-8: not one of ours
        };
        if !is_dump_filename(&name) {
            continue;
        }
        out.push(entry.path());
    }
    out.sort();
    Ok(out)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn fixture(detected_at_unix_secs: i64) -> DeadlockDump {
        DeadlockDump {
            kernel_version: "0.1.0-test".to_owned(),
            detected_at_unix_secs,
            cycle_count: 1,
            thread_count: 2,
            lock_count: 2,
            cycles: vec![DeadlockCycle {
                cycle_index: 0,
                threads: vec![
                    DeadlockThread {
                        thread_id: "ThreadId(7)".to_owned(),
                        backtrace: "frame_a\nframe_b\n".to_owned(),
                    },
                    DeadlockThread {
                        thread_id: "ThreadId(11)".to_owned(),
                        backtrace: "frame_c\nframe_d\n".to_owned(),
                    },
                ],
            }],
        }
    }

    #[test]
    fn write_dump_round_trips() {
        let dir = tempdir().unwrap();
        let dump = fixture(1_714_500_000);
        let path = write_dump(dir.path(), &dump).expect("write");
        assert!(path.ends_with("deadlock_dump_1714500000.json"));
        let read_back = read_dump(&path).expect("read");
        assert_eq!(read_back.detected_at_unix_secs, 1_714_500_000);
        assert_eq!(read_back.thread_count, 2);
        assert_eq!(read_back.cycles.len(), 1);
        assert_eq!(read_back.cycles[0].threads.len(), 2);
    }

    #[test]
    fn write_dump_creates_data_dir_if_missing() {
        let dir = tempdir().unwrap();
        let nested = dir.path().join("nested").join("data");
        // Pre-condition: the nested path does NOT exist yet.
        assert!(!nested.exists());
        let dump = fixture(1_714_500_001);
        let path = write_dump(&nested, &dump).expect("write");
        assert!(path.exists());
    }

    #[test]
    fn dump_filename_shape() {
        assert_eq!(
            dump_filename(1_714_500_002),
            "deadlock_dump_1714500002.json",
        );
    }

    #[test]
    fn is_dump_filename_accepts_canonical_shape_only() {
        assert!(is_dump_filename("deadlock_dump_1714500000.json"));
        assert!(is_dump_filename("deadlock_dump_0.json"));
        assert!(!is_dump_filename("deadlock_dump_.json"));
        assert!(!is_dump_filename(".deadlock_dump_1.json.tmp"));
        assert!(!is_dump_filename("deadlock_dump_abc.json"));
        assert!(!is_dump_filename("deadlock_dump_1714500000.txt"));
        assert!(!is_dump_filename("kernel_started.json"));
    }

    #[test]
    fn scan_pending_returns_only_canonical_files_sorted() {
        let dir = tempdir().unwrap();
        // Three valid dumps + one tempfile + one unrelated file.
        write_dump(dir.path(), &fixture(20)).unwrap();
        write_dump(dir.path(), &fixture(10)).unwrap();
        write_dump(dir.path(), &fixture(30)).unwrap();
        std::fs::write(dir.path().join("kernel.db"), b"not ours").unwrap();
        std::fs::write(dir.path().join(".deadlock_dump_99.json.tmp"), b"partial").unwrap();
        let found = scan_pending_dumps(dir.path()).unwrap();
        let names: Vec<String> = found
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().to_string())
            .collect();
        assert_eq!(
            names,
            vec![
                "deadlock_dump_10.json",
                "deadlock_dump_20.json",
                "deadlock_dump_30.json",
            ],
        );
    }

    #[test]
    fn scan_pending_returns_empty_for_missing_dir() {
        let dir = tempdir().unwrap();
        let missing = dir.path().join("nope");
        assert!(scan_pending_dumps(&missing).unwrap().is_empty());
    }

    #[test]
    fn move_to_consumed_relocates_to_sibling_dir() {
        let dir = tempdir().unwrap();
        let dump = fixture(1_714_500_003);
        let path = write_dump(dir.path(), &dump).expect("write");
        assert!(path.exists());
        let target = move_to_consumed(dir.path(), &path).expect("move");
        assert!(!path.exists());
        assert!(target.exists());
        assert_eq!(
            target.parent().unwrap().file_name().unwrap(),
            "deadlock_dumps_consumed",
        );
        // Re-scan — the original is gone, so no pending entries.
        assert!(scan_pending_dumps(dir.path()).unwrap().is_empty());
    }
}

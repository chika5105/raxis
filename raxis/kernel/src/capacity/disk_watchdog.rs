// raxis-kernel::capacity::disk_watchdog — INV-CAPACITY-02 disk poll.
//
// Normative reference: `specs/v2/host-capacity.md §7.1` ("The
// watchdog").
//
// A dedicated tokio task polls `statvfs(disk_root)` every 5
// seconds and updates an atomic `DiskState`. Every write-class
// intent handler reads the state through `DiskWatchdog::is_full()`
// before issuing the write; the spec calls out only `halt_admit`
// (default) for V2.
//
// V2 vs V3:
//   * V2 — `halt_admit` only. Beyond-cap admissions return
//     `FAIL_DISK_FULL` immediately. In-flight ops continue (their
//     small writes fit inside the headroom).
//   * V3 — `gc_then_retry` (immutable artifact GC + VACUUM) and
//     `halt_all` (also halts read-class). Audit reserve +
//     `AuditWriteImpossible` total halt machinery (host-capacity
//     §7.5–§7.6) is V3.
//
// The watchdog is intentionally read-only. It does not delete
// abandoned worktrees (see `INV-CONVERGENCE-05` /
// host-capacity.md §7.8) — that requires explicit operator
// action.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::sync::Arc;
use std::time::Duration;

use raxis_audit_tools::{AuditEventKind, AuditSink};

/// Disk-watchdog poll interval (host-capacity.md §7.1).
const POLL_INTERVAL: Duration = Duration::from_secs(5);

/// Disk-pressure state. `repr(u8)` so the watchdog can store it in
/// an `AtomicU8` and every reader observes a coherent transition
/// without a mutex.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DiskState {
    /// Free space ≥ floor. New writes admitted as usual.
    Healthy = 0,
    /// Free space < floor. New write-class admissions return
    /// `FAIL_DISK_FULL` per `halt_admit` behavior.
    Halted = 1,
    /// The watchdog has not yet performed its first poll. Treated
    /// as `Healthy` by callers — boot must not deadlock waiting
    /// for the first observation.
    Pending = 2,
}

impl DiskState {
    fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::Halted,
            2 => Self::Pending,
            _ => Self::Healthy,
        }
    }
}

/// Disk-watchdog runtime handle. Cheap to clone (`Arc` internally),
/// safe to read from anywhere via `is_full()` / `current_free_mb()`.
#[derive(Debug, Clone)]
pub struct DiskWatchdog {
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    /// Watchdog state encoded as `DiskState as u8`. Touched by
    /// the watchdog task on each poll; readers use `Acquire`.
    state: AtomicU8,
    /// Last observed free space in MiB. `u64::MAX` is the sentinel
    /// for "no observation yet".
    free_mb: AtomicU64,
    /// Operator-declared floor in MiB.
    min_free_mb: u64,
    /// Path the watchdog statvfs's. Stored for diagnostic logs.
    disk_root: PathBuf,
    /// `disk_full_behavior` ("halt_admit" in V2; the `Halt`
    /// transition will eventually pick which sub-behavior to run).
    behavior: String,
}

impl DiskWatchdog {
    /// Construct a watchdog without spawning the background poll.
    /// Callers (`main.rs`) call `spawn` to start the loop.
    pub fn new(disk_root: PathBuf, min_free_mb: u64, behavior: String) -> Self {
        Self {
            inner: Arc::new(Inner {
                state: AtomicU8::new(DiskState::Pending as u8),
                free_mb: AtomicU64::new(u64::MAX),
                min_free_mb,
                disk_root,
                behavior,
            }),
        }
    }

    /// Spawn the polling task. Returns immediately — the first
    /// observation lands within ~`POLL_INTERVAL` seconds. The
    /// task is a tokio task; it lives for the kernel-process
    /// lifetime.
    pub fn spawn(&self, audit: Arc<dyn AuditSink>) {
        let inner = Arc::clone(&self.inner);
        tokio::spawn(async move {
            loop {
                poll_once(&inner, audit.as_ref());
                tokio::time::sleep(POLL_INTERVAL).await;
            }
        });
    }

    /// Reads the current state. `Pending` (boot, before first
    /// poll) is reported as not-full.
    pub fn current_state(&self) -> DiskState {
        DiskState::from_u8(self.inner.state.load(Ordering::Acquire))
    }

    /// True when the watchdog has observed pressure and entered
    /// `Halted`. Read by every write-class intent handler.
    pub fn is_full(&self) -> bool {
        self.current_state() == DiskState::Halted
    }

    /// Last observed free space in MiB, or `None` when no poll
    /// has happened yet.
    pub fn current_free_mb(&self) -> Option<u64> {
        let v = self.inner.free_mb.load(Ordering::Acquire);
        if v == u64::MAX {
            None
        } else {
            Some(v)
        }
    }

    /// Operator-declared floor.
    pub fn min_free_mb(&self) -> u64 {
        self.inner.min_free_mb
    }

    /// `disk_full_behavior` discriminator ("halt_admit" in V2).
    pub fn behavior(&self) -> &str {
        &self.inner.behavior
    }

    /// One-shot poll for tests. Production callers use [`spawn`]
    /// instead. Returns the observed `DiskState` after the poll.
    #[doc(hidden)]
    pub fn poll_for_tests(&self, audit: &dyn AuditSink) -> DiskState {
        poll_once(&self.inner, audit);
        self.current_state()
    }
}

/// One iteration of the watchdog loop. Reads `statvfs`, updates
/// the atomic state, and emits a transition audit event when the
/// state flips.
fn poll_once(inner: &Inner, audit: &dyn AuditSink) {
    let observed = match free_mib(&inner.disk_root) {
        Ok(v) => v,
        Err(e) => {
            // Report once per poll; never panic — a transiently
            // unavailable filesystem must not crash the kernel.
            eprintln!(
                "{{\"level\":\"warn\",\"event\":\"DiskWatchdogStatvfsFailed\",\
                 \"path\":\"{}\",\"error\":{}}}",
                inner.disk_root.display(),
                serde_json::Value::String(e.to_string()),
            );
            return;
        }
    };

    let prev = DiskState::from_u8(inner.state.load(Ordering::Acquire));
    let next = if observed < inner.min_free_mb {
        DiskState::Halted
    } else {
        DiskState::Healthy
    };

    inner.free_mb.store(observed, Ordering::Release);

    // First poll always lands here; emit no transition event for
    // `Pending → Healthy` (steady-state convergence — operators
    // do not need a kernel boot announcement that disk is fine).
    let entered_halt = prev != DiskState::Halted && next == DiskState::Halted;
    let exited_halt = prev == DiskState::Halted && next == DiskState::Healthy;

    inner.state.store(next as u8, Ordering::Release);

    if entered_halt {
        let _ = audit.emit(
            AuditEventKind::DiskFullHaltEntered {
                free_mb: observed,
                cap_mb: inner.min_free_mb,
                behavior: inner.behavior.clone(),
            },
            None,
            None,
            None,
        );
        let _ = audit.emit(
            AuditEventKind::OperatorAttentionRequired {
                attention_kind: "DiskFull".into(),
                details: format!(
                    "free_mb={observed}, floor={}, behavior={}",
                    inner.min_free_mb, inner.behavior,
                ),
            },
            None,
            None,
            None,
        );
    } else if exited_halt {
        let _ = audit.emit(
            AuditEventKind::DiskHealthyAfterFull {
                previous_free_mb: 0, // V2: we do not track previous-free duration; V3 will.
                current_free_mb: observed,
                halt_duration_seconds: 0,
            },
            None,
            None,
            None,
        );
    }
}

/// Cross-platform free-space query. On Unix, uses `statvfs`. On
/// non-Unix, returns a sentinel "plenty of space" so the kernel
/// never falsely halts in dev environments without `statvfs`.
fn free_mib(p: &Path) -> std::io::Result<u64> {
    #[cfg(unix)]
    {
        use std::ffi::CString;
        use std::mem::MaybeUninit;
        use std::os::unix::ffi::OsStrExt;

        let c = CString::new(p.as_os_str().as_bytes())
            .map_err(|_| std::io::Error::other("path contains NUL"))?;
        let mut sv: MaybeUninit<libc::statvfs> = MaybeUninit::uninit();
        // SAFETY: `c` outlives the call; `sv` is writable.
        let rc = unsafe { libc::statvfs(c.as_ptr(), sv.as_mut_ptr()) };
        if rc != 0 {
            return Err(std::io::Error::last_os_error());
        }
        let sv = unsafe { sv.assume_init() };
        // `f_bavail` is blocks available to non-root, `f_frsize`
        // is fundamental block size. Using saturating math to
        // protect against the multiplication overflowing on
        // pathologically large filesystems (32-bit ABIs only).
        let bytes = (sv.f_bavail as u128).saturating_mul(sv.f_frsize as u128);
        let mib = bytes / (1024 * 1024);
        Ok(mib.min(u64::MAX as u128) as u64)
    }
    #[cfg(not(unix))]
    {
        let _ = p;
        Ok(u64::MAX / 2)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use raxis_audit_tools::AuditWriter;
    use raxis_audit_tools::FileAuditSink;

    fn open_test_audit() -> Arc<dyn AuditSink> {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("seg.jsonl");
        let w = AuditWriter::open(&path, 0, None).unwrap();
        let sink = Arc::new(FileAuditSink::new(w));
        // Leak the tempdir intentionally — the audit sink uses
        // the path through the static segment file; tests stay
        // simple by not bothering with cleanup.
        Box::leak(Box::new(dir));
        sink
    }

    #[test]
    fn pending_is_not_full_at_boot() {
        let w = DiskWatchdog::new("/tmp".into(), 0, "halt_admit".into());
        assert!(!w.is_full());
        assert_eq!(w.current_state(), DiskState::Pending);
        assert_eq!(w.current_free_mb(), None);
    }

    #[test]
    fn poll_observes_free_space_on_real_filesystem() {
        let dir = tempfile::tempdir().unwrap();
        let w = DiskWatchdog::new(dir.path().into(), 0, "halt_admit".into());
        let audit = open_test_audit();
        w.poll_for_tests(audit.as_ref());
        // Either Healthy (likely) or Halted (only if /tmp is
        // *literally* full) — both are valid observations as
        // long as the watchdog moved off `Pending`.
        assert_ne!(w.current_state(), DiskState::Pending);
        assert!(w.current_free_mb().is_some());
    }

    #[test]
    fn extremely_high_floor_drives_halted() {
        let dir = tempfile::tempdir().unwrap();
        // 100 EiB floor — guaranteed above any realistic
        // filesystem free-space. Forces a Halted transition.
        let w = DiskWatchdog::new(dir.path().into(), u64::MAX / 2, "halt_admit".into());
        let audit = open_test_audit();
        w.poll_for_tests(audit.as_ref());
        assert!(w.is_full());
    }

    #[test]
    fn behavior_string_round_trips() {
        let w = DiskWatchdog::new("/tmp".into(), 0, "halt_admit".into());
        assert_eq!(w.behavior(), "halt_admit");
    }
}

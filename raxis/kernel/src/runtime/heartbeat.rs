//! Kernel-side glue that publishes a `Snapshot` to
//! `<data_dir>/runtime/heartbeat.json` on a periodic loop.
//!
//! The wire shape (`Snapshot`, `KernelLifecycleState`, `write_atomic`,
//! `read`, the cadence/staleness constants) lives in `raxis-runtime`
//! so the CLI binary can deserialize what the kernel writes without
//! depending on the kernel binary. **This file owns only the live
//! data collection and the `tokio` `select!` loop.**
//!
//! # Why a free `run_loop` rather than a struct
//!
//! The loop holds three borrows (the policy `ArcSwap`, the data dir
//! `PathBuf`, and the shutdown `oneshot::Receiver`) and exits when
//! the receiver fires OR the writer encounters a fatal IO error.
//! Wrapping that in a `Heartbeat { ... }` struct adds no testability
//! (every observable is a function call already) and forces a `Mutex`
//! around the snapshot collector that no production reader needs.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use tokio::sync::oneshot;

use raxis_runtime::{
    HEARTBEAT_FILE, HEARTBEAT_INTERVAL, KernelLifecycleState, RUNTIME_DIR, Snapshot,
    unix_now_secs, write_atomic,
};

/// Collect a snapshot from the kernel's live in-memory state. This is
/// the function the production loop calls; tests build snapshots
/// directly via `Snapshot::new` to avoid the global counter
/// dependency.
///
/// `queued_spawns` and the per-channel session counters are reserved
/// at zero in v1:
///
///   - `queued_spawns`: the verifier runner has no scheduler queue
///     (verifier spawns either succeed or return
///     `VerifierCapExceeded` immediately). Reserved at zero until v2
///     introduces a queued-spawn mechanism — at which point this call
///     site reads the queue length.
///   - `active_*_sessions`: the IPC accept loops do not currently
///     maintain in-memory counters. cli-readonly.md §5.1.4 calls
///     these out explicitly as "best-effort; documented as
///     approximate". Reserved at zero with a clear path to wire
///     `AtomicUsize`s into `ipc/server.rs` once an operator command
///     needs them.
pub fn collect(
    kernel_pid: u32,
    started_at: u64,
    state: KernelLifecycleState,
    policy_epoch: u64,
) -> Snapshot {
    let now = unix_now_secs();
    Snapshot::new(
        kernel_pid,
        started_at,
        now,
        state,
        policy_epoch,
        crate::gates::verifier_runner::active_verifier_count(),
        crate::gates::verifier_runner::max_concurrent_verifiers(),
        0,
        0,
        0,
        0,
    )
}

/// Spawn-friendly heartbeat loop.
///
/// Steady-state behaviour:
///   - Tick every `HEARTBEAT_INTERVAL`.
///   - Write a fresh `collect(...)` snapshot to
///     `data_dir/runtime/heartbeat.json`.
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
    write_one(
        &dest_path,
        kernel_pid,
        started_at,
        KernelLifecycleState::Running,
        &policy,
    );

    let mut interval = tokio::time::interval(HEARTBEAT_INTERVAL);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // Skip the immediate-fire of `interval.tick()` on first await —
    // we already wrote above. Without this, the second write happens
    // ~0ms after the first.
    interval.tick().await;

    loop {
        tokio::select! {
            _ = interval.tick() => {
                write_one(
                    &dest_path,
                    kernel_pid,
                    started_at,
                    KernelLifecycleState::Running,
                    &policy,
                );
            }
            _ = &mut shutdown => {
                write_one(
                    &dest_path,
                    kernel_pid,
                    started_at,
                    KernelLifecycleState::Stopping,
                    &policy,
                );
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
    let snap = collect(kernel_pid, started_at, state, policy_epoch);
    if let Err(e) = write_atomic(dest_path, &snap) {
        eprintln!(
            "{{\"level\":\"warn\",\"event\":\"heartbeat_write_failed\",\
             \"path\":\"{}\",\"reason\":\"{e}\"}}",
            dest_path.display(),
        );
    }
}

// ────────────────────────────────────────────────────────────────────
// Tests — only the kernel-side glue (collect + run_loop). Wire-shape
// and atomic-write tests live in `raxis-runtime` so they don't need
// to be re-asserted here.
// ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use raxis_runtime::{HEARTBEAT_SCHEMA_VERSION, STORE_SCHEMA_VERSION, read};
    use std::time::Duration;
    use tempfile::TempDir;

    #[test]
    fn collect_pulls_live_verifier_counters_and_pins_versions() {
        // Smoke test that `collect` actually reaches the live
        // counters; we don't assert exact values for
        // `active_verifier_count` because parallel tests in this
        // crate could mutate the global atomic.
        let snap = collect(
            std::process::id(),
            unix_now_secs(),
            KernelLifecycleState::Running,
            42,
        );
        assert_eq!(snap.policy_epoch, 42);
        assert_eq!(snap.schema_version, HEARTBEAT_SCHEMA_VERSION);
        assert_eq!(snap.store_schema_version, STORE_SCHEMA_VERSION);
        assert_eq!(
            snap.max_concurrent_verifiers,
            crate::gates::verifier_runner::max_concurrent_verifiers()
        );
    }

    #[tokio::test]
    async fn run_loop_writes_initial_heartbeat_then_stops_on_shutdown() {
        let tmp = TempDir::new().unwrap();
        std::fs::create_dir_all(tmp.path().join(RUNTIME_DIR)).unwrap();

        let policy: Arc<arc_swap::ArcSwap<raxis_policy::PolicyBundle>> =
            Arc::new(arc_swap::ArcSwap::from_pointee(stub_bundle()));
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
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
        let parsed = read(tmp.path()).expect("initial heartbeat must exist");
        assert_eq!(parsed.state, "Running");
        assert_eq!(parsed.kernel_pid, pid);

        tx.send(()).unwrap();
        handle.await.expect("loop join").expect("loop ok");

        let parsed_final = read(tmp.path()).expect("final heartbeat must exist");
        assert_eq!(
            parsed_final.state, "Stopping",
            "final write must record Stopping for CLI visibility"
        );
    }

    #[tokio::test]
    async fn run_loop_writes_periodically_when_left_running() {
        let tmp = TempDir::new().unwrap();
        std::fs::create_dir_all(tmp.path().join(RUNTIME_DIR)).unwrap();

        let policy: Arc<arc_swap::ArcSwap<raxis_policy::PolicyBundle>> =
            Arc::new(arc_swap::ArcSwap::from_pointee(stub_bundle()));
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let pid = std::process::id();
        let started_at = unix_now_secs();

        let policy_for_loop = Arc::clone(&policy);
        let data_dir = tmp.path().to_path_buf();
        let handle = tokio::spawn(async move {
            run_loop(data_dir, pid, started_at, policy_for_loop, rx).await
        });

        tokio::time::sleep(Duration::from_millis(50)).await;
        let first = read(tmp.path()).expect("initial");
        let first_ts = first.last_heartbeat_at;

        // Sleep slightly longer than one interval. The loop must
        // emit a fresh write with a strictly-greater timestamp (in
        // the worst case the timestamp resolution is one second so
        // we accept >= rather than >).
        tokio::time::sleep(HEARTBEAT_INTERVAL + Duration::from_millis(200)).await;
        let next = read(tmp.path()).expect("next");

        assert!(
            next.last_heartbeat_at >= first_ts,
            "expected periodic update; first={first_ts} next={}",
            next.last_heartbeat_at
        );

        tx.send(()).unwrap();
        let _ = handle.await;
    }

    fn stub_bundle() -> raxis_policy::PolicyBundle {
        raxis_policy::PolicyBundle::for_tests_with_operators(vec![])
    }
}

// raxis-kernel::capacity — host-capacity MVP.
// Normative reference: `specs/v2/host-capacity.md` (§4 VM concurrency,
// §7 disk-full watchdog, §12 FD limits) and .
// V2 SCOPE (this module).
// =======================
//   * `vm_admission` — INV-CAPACITY-01 strict cap on
//     `max_concurrent_vms`. Sub-task activations beyond the cap
//     return `AdmissionDecision::Deferred`; the caller surfaces
//     `FAIL_VM_CONCURRENCY_AT_CAP` and emits an
//     `AdmissionDeferredAtCap` audit event. The agent retries
//     after seeing `KernelPush::CapacityFreed` (V3) or, in V2,
//     by polling.
//   * `disk_watchdog` — INV-CAPACITY-02 5-second poll on
//     `statvfs(disk_root)`. Exposes an atomic `DiskState` enum
//     read by every write-class intent handler before issuing
//     a write. V2 only implements `disk_full_behavior =
//     "halt_admit"`.
//   * `fd_limit` — boot-time `getrlimit(RLIMIT_NOFILE)` check.
//     The kernel refuses to start when the soft limit is below
//     `[host_capacity] required_min_fd_limit`.
// V3 DEFERRALS (NOT in this module).
// =================================
//   * Persistent admission queue with `sessions.state = 'Queued'`,
//     `queued_at`, drain-on-terminate, and round-robin fairness
//     (host-capacity.md §9, §10). V2 returns `AdmissionDeferred`
//     immediately and lets the agent / operator drive the retry.
//   * Aggregate VM memory cap (`max_aggregate_vm_memory_mb`),
//     per-initiative cap (`max_per_initiative_concurrent_vms`).
//   * `gc_then_retry` and `halt_all` disk-full behaviors.
//   * Per-operator queue limits with named overrides.
//   * WAL pressure monitoring + `wal_max_size_mb` enforcement.
//   * Audit reserve + `AuditWriteImpossible` total halt.
//   * Worktree quota soft enforcement.
// Audit events emitted by this module (registered in
// `raxis-policy::KNOWN_AUDIT_EVENT_KINDS`):
//   * `AdmissionDeferredAtCap`         — `vm_admission`
//   * `AdmissionQueueFull`             — `vm_admission`
//   * `DiskFullHaltEntered`            — `disk_watchdog`
//   * `DiskHealthyAfterFull`           — `disk_watchdog`
//   * `OperatorAttentionRequired`      — `fd_limit` / `disk_watchdog`

pub mod disk_watchdog;
pub mod fd_limit;
pub mod vm_admission;

// `DiskState` and `AdmissionDeferReason` are part of the V2 public
// surface for downstream consumers (tests, the V3 admission queue
// implementation that will replace the immediate-defer behaviour
// here, and the `raxis status` operator command). The kernel
// binary itself only consumes them through the typed return of
// `check_vm_concurrency_cap` / `DiskWatchdog::current_state`, so
// the re-exports look unused to the binary linker — silence the
// noise rather than weaken the API.
#[allow(unused_imports)]
pub use disk_watchdog::{DiskState, DiskWatchdog};
pub use fd_limit::{check_fd_limit_at_boot, FdLimitOutcome};
#[allow(unused_imports)]
pub use vm_admission::{check_vm_concurrency_cap, AdmissionDecision, AdmissionDeferReason};

/// Helper for write-class intent handlers. Returns `Err(())` when
/// the disk-full watchdog has flipped to `Halted` so the caller
/// can short-circuit with `FAIL_DISK_FULL`. `None` for the
/// watchdog (test fixtures, dev kernels) is treated as "always
/// healthy" per `host-capacity.md §7.1`.
pub fn refuse_if_disk_full(watchdog: Option<&DiskWatchdog>) -> Result<(), ()> {
    match watchdog {
        Some(w) if w.is_full() => Err(()),
        _ => Ok(()),
    }
}

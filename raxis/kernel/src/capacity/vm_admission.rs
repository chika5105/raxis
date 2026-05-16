// raxis-kernel::capacity::vm_admission — INV-CAPACITY-01 cap check.
// Normative reference: `specs/v2/host-capacity.md §4.2` ("Pre-admission
// check").
// The V2 MVP implements the strict-cap branch only: when the kernel
// is asked to spawn another microVM and `running_vm_count >=
// max_concurrent_vms`, the caller receives `Deferred`. The full
// admission queue (with `Queued` session state, `queued_at`,
// per-operator caps, and round-robin fairness) is V3 (see
// `host-capacity.md §9` and ).
// The aggregate VM memory cap and the per-initiative VM cap from
// the spec are likewise V3. They share the same return surface
// (`Deferred { reason }`); the V2 caller only ever observes
// `AdmissionDeferReason::VmCountAtCap`.

/// Reason an admission was deferred. `cap_kind`-style discriminator
/// also surfaced by the audit event `AdmissionDeferredAtCap`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmissionDeferReason {
    /// `running_vm_count >= max_concurrent_vms` per
    /// `host-capacity.md §4.2`. INV-CAPACITY-01.
    VmCountAtCap,
}

impl AdmissionDeferReason {
    /// String discriminator written into `AdmissionDeferredAtCap`.
    /// Stable across V2; V3 may add `"VmMemory"` and
    /// `"PerInitiativeVm"`.
    pub fn cap_kind(self) -> &'static str {
        match self {
            Self::VmCountAtCap => "VmCount",
        }
    }
}

/// Outcome of the pre-admission check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmissionDecision {
    /// The caller may proceed with the substrate spawn.
    Allow,
    /// The cap fired; the caller MUST NOT spawn. The caller
    /// surfaces `FAIL_VM_CONCURRENCY_AT_CAP` to the agent and
    /// emits `AdmissionDeferredAtCap`.
    Deferred {
        reason: AdmissionDeferReason,
        current_running: u32,
        cap: u32,
    },
}

/// Pure pre-admission check. Returns `Allow` when the proposed
/// spawn would keep the running VM count strictly below the cap;
/// `Deferred` otherwise.
/// `current_running` is the number of microVMs already in flight
/// (`SessionSpawnService::active_count`). `cap` is the resolved
/// `[host_capacity] max_concurrent_vms` from `policy.toml`.
/// The check is deliberately stateless: it does not consult the
/// SQLite store, hold any lock, or do any I/O. The caller is
/// responsible for providing a current count and emitting the
/// audit event after observing `Deferred`.
pub fn check_vm_concurrency_cap(current_running: u32, cap: u32) -> AdmissionDecision {
    if current_running >= cap {
        AdmissionDecision::Deferred {
            reason: AdmissionDeferReason::VmCountAtCap,
            current_running,
            cap,
        }
    } else {
        AdmissionDecision::Allow
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allow_when_strictly_below_cap() {
        assert_eq!(check_vm_concurrency_cap(0, 16), AdmissionDecision::Allow);
        assert_eq!(check_vm_concurrency_cap(15, 16), AdmissionDecision::Allow);
    }

    #[test]
    fn defer_at_cap() {
        let d = check_vm_concurrency_cap(16, 16);
        match d {
            AdmissionDecision::Deferred {
                reason,
                current_running,
                cap,
            } => {
                assert_eq!(reason, AdmissionDeferReason::VmCountAtCap);
                assert_eq!(current_running, 16);
                assert_eq!(cap, 16);
            }
            _ => panic!("expected Deferred at exact cap"),
        }
    }

    #[test]
    fn defer_above_cap() {
        // Possible during config push that lowered the cap below
        // currently running VMs; spec §4.3 says we admit no new
        // ones until natural drain, never terminate live work.
        let d = check_vm_concurrency_cap(20, 16);
        assert!(matches!(d, AdmissionDecision::Deferred { .. }));
    }

    #[test]
    fn cap_zero_defers_unconditionally() {
        // Defensive: a misconfig that sets cap = 0 must never
        // accidentally admit. Even though the policy validator
        // forbids `max_concurrent_vms = 0`, future code paths
        // could still reach here with a derived cap of 0.
        let d = check_vm_concurrency_cap(0, 0);
        assert!(matches!(d, AdmissionDecision::Deferred { .. }));
    }

    #[test]
    fn defer_reason_cap_kind_is_stable() {
        assert_eq!(AdmissionDeferReason::VmCountAtCap.cap_kind(), "VmCount");
    }
}

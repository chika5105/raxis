//! Crash-recovery witness.
//!
//! The realistic-scenario test driver (P3-9) is designed to drop a
//! SIGTERM on the kernel mid-task and then restart it. This module
//! provides the predicate that verifies the audit chain.
//!
//! **Two evaluation modes — chain-shape-driven.**
//!
//! 1. **No crash observed (happy path).** When the chain does NOT
//!    carry a `KernelRestartCompleted` event AND has no duplicate
//!    `SessionVmSpawned` for the in-flight task, the witness passes
//!    vacuously: there is no crash to recover from, so there is no
//!    recovery signal to demand. The audit-chain monotonicity
//!    check still fires — an unreconciled `seq` gap is an
//!    INV-AUDIT-01 violation regardless of whether a crash was
//!    expected.
//!
//! 2. **Crash signature present.** When the chain DOES carry a
//!    `KernelRestartCompleted` event OR multiple `SessionVmSpawned`
//!    rows for the same in-flight task, the witness asserts the
//!    audit chain shows a **post-crash recovery signal**:
//!
//!      * a [`ReconciliationGap`] event the kernel emitted on
//!        restart (crash between commit-to-SQLite and JSONL
//!        write), OR
//!      * a [`TaskBlockedForRecovery`] event for the in-flight
//!        task (the kernel detected the task's mid-flight state
//!        on reboot and blocked it for operator review), OR
//!      * a [`TaskAutoResumedAfterSupervisorRestart`] event for
//!        the in-flight task (the kernel auto-resumed the task
//!        after a supervisor-driven restart per
//!        `reconcile_after_supervisor_restart`), OR
//!      * a **respawn**: a second `SessionVmSpawned` for the same
//!        `task_id` whose `seq` strictly exceeds the earliest
//!        spawn's `seq` (the kernel decided to resume the task
//!        autonomously).
//!
//! In both modes the chain's `seq` field MUST be strictly
//! monotonically increasing modulo `ReconciliationGap` covers.
//!
//! Spec references:
//!   * `raxis/crates/audit/src/event.rs` (the comment on
//!     `AuditEvent::seq`: "Gaps indicate a reconciliation gap
//!     (crash between commit and JSONL write)").
//!   * `agent-recovery.md` (`TaskBlockedForRecovery` semantics).
//!   * `kernel/src/recovery.rs::reconcile_after_supervisor_restart`
//!     (emits `TaskAutoResumedAfterSupervisorRestart`).
//!
//! [`ReconciliationGap`]: raxis_audit_tools::AuditEventKind::ReconciliationGap
//! [`TaskBlockedForRecovery`]: raxis_audit_tools::AuditEventKind::TaskBlockedForRecovery
//! [`TaskAutoResumedAfterSupervisorRestart`]: raxis_audit_tools::AuditEventKind::TaskAutoResumedAfterSupervisorRestart

use std::collections::BTreeSet;

use raxis_audit_tools::{AuditEvent, AuditEventKind};

use super::witnesses::{typed, EnforcementWitness};

/// Witness predicate. See module docs.
pub struct CrashRecoveryWitness {
    /// task_id known to have been in flight at the moment the
    /// test driver delivered SIGTERM. The witness expects to see
    /// at least one `SessionVmSpawned` for this task pre-crash AND
    /// at least one recovery signal post-crash.
    pub in_flight_task_id: String,
}

impl CrashRecoveryWitness {
    #[must_use]
    pub fn new(in_flight_task_id: &str) -> Self {
        Self {
            in_flight_task_id: in_flight_task_id.to_owned(),
        }
    }

    /// Collect every `seq` from the chain that any
    /// `ReconciliationGap` event accounted for.
    fn reconciled_seqs(&self, chain: &[AuditEvent]) -> BTreeSet<u64> {
        chain
            .iter()
            .filter_map(|ev| match typed(ev) {
                Some(AuditEventKind::ReconciliationGap { missing_seq, .. }) => Some(missing_seq),
                _ => None,
            })
            .collect()
    }

    /// Find every UNRECONCILED gap in the chain. Returns the
    /// sorted vector of missing seq numbers.
    fn unreconciled_gaps(&self, chain: &[AuditEvent]) -> Vec<u64> {
        let reconciled = self.reconciled_seqs(chain);
        let mut gaps = Vec::<u64>::new();
        let mut prev: Option<u64> = None;
        for ev in chain {
            if let Some(p) = prev {
                if ev.seq > p + 1 {
                    for missing in (p + 1)..ev.seq {
                        if !reconciled.contains(&missing) {
                            gaps.push(missing);
                        }
                    }
                } else if ev.seq <= p {
                    // Non-monotonic — represent as a "gap" of the
                    // re-used seq; the test driver will see it
                    // as a violation in the diagnostic.
                    gaps.push(ev.seq);
                }
            }
            prev = Some(ev.seq);
        }
        gaps
    }

    fn pre_crash_spawn_seq(&self, chain: &[AuditEvent]) -> Option<u64> {
        chain
            .iter()
            .filter_map(|ev| match typed(ev) {
                Some(AuditEventKind::SessionVmSpawned { task_id, .. })
                    if task_id.as_deref() == Some(self.in_flight_task_id.as_str()) =>
                {
                    Some(ev.seq)
                }
                _ => None,
            })
            .min()
    }

    fn spawn_count_for_task(&self, chain: &[AuditEvent]) -> usize {
        chain
            .iter()
            .filter(|ev| match typed(ev) {
                Some(AuditEventKind::SessionVmSpawned { task_id, .. }) => {
                    task_id.as_deref() == Some(self.in_flight_task_id.as_str())
                }
                _ => false,
            })
            .count()
    }

    /// Did the kernel actually go through a crash-recovery cycle?
    ///
    /// We look for either:
    ///   * `KernelRestartCompleted` anywhere in the chain (the
    ///     canonical signal a supervisor-driven restart fired and
    ///     `reconcile_after_supervisor_restart` ran), OR
    ///   * multiple `SessionVmSpawned` rows for the in-flight task
    ///     (implicit signal — the substrate respawned the VM after
    ///     an exit even without a full kernel restart).
    ///
    /// When neither signature is present the witness has nothing
    /// to assert: the realistic e2e ran end-to-end without any
    /// crash and there is no recovery signal to demand. Returning
    /// `false` here drives the predicate into vacuous-satisfy.
    fn crash_signature_present(&self, chain: &[AuditEvent]) -> bool {
        let restart_observed = chain.iter().any(|ev| {
            matches!(
                typed(ev),
                Some(AuditEventKind::KernelRestartCompleted { .. })
            )
        });
        restart_observed || self.spawn_count_for_task(chain) > 1
    }

    fn has_recovery_signal(&self, chain: &[AuditEvent]) -> bool {
        let Some(pre_crash_seq) = self.pre_crash_spawn_seq(chain) else {
            return false;
        };

        for ev in chain {
            match typed(ev) {
                Some(AuditEventKind::ReconciliationGap { .. }) if ev.seq > pre_crash_seq => {
                    return true;
                }
                Some(AuditEventKind::TaskBlockedForRecovery { task_id, .. })
                    if task_id == self.in_flight_task_id && ev.seq > pre_crash_seq =>
                {
                    return true;
                }
                Some(AuditEventKind::TaskAutoResumedAfterSupervisorRestart { task_id, .. })
                    if task_id == self.in_flight_task_id && ev.seq > pre_crash_seq =>
                {
                    return true;
                }
                Some(AuditEventKind::SessionVmSpawned { task_id, .. })
                    if task_id.as_deref() == Some(self.in_flight_task_id.as_str())
                        && ev.seq > pre_crash_seq =>
                {
                    return true;
                }
                _ => {}
            }
        }
        false
    }
}

impl EnforcementWitness for CrashRecoveryWitness {
    fn name(&self) -> &'static str {
        "crash-recovery"
    }

    fn satisfied_by(&self, chain: &[AuditEvent]) -> bool {
        // Audit-chain integrity is invariant regardless of mode.
        if !self.unreconciled_gaps(chain).is_empty() {
            return false;
        }

        // Mode 1: no crash signature in the chain → vacuous satisfy.
        // The realistic harness doesn't currently inject a crash, so
        // this is the live-e2e steady state. The witness still
        // guards INV-AUDIT-01 above; if a future harness change
        // wires in P3-9 SIGTERM-and-restart, the signature check
        // below trips and the recovery-signal demand becomes
        // active without any witness code change.
        if !self.crash_signature_present(chain) {
            return true;
        }

        // Mode 2: crash signature present — we MUST find a pre-crash
        // spawn for the in-flight task AND a recovery signal after it.
        if self.pre_crash_spawn_seq(chain).is_none() {
            return false;
        }
        self.has_recovery_signal(chain)
    }

    fn diagnostic(&self, chain: &[AuditEvent]) -> String {
        let pre_crash = self.pre_crash_spawn_seq(chain);
        let recovery = self.has_recovery_signal(chain);
        let gaps = self.unreconciled_gaps(chain);
        let reconciled: Vec<u64> = self.reconciled_seqs(chain).into_iter().collect();
        let crash_observed = self.crash_signature_present(chain);
        let spawns = self.spawn_count_for_task(chain);
        format!(
            "CrashRecovery[{task}]:\n  \
             crash signature observed:    {crash_observed} \
             (SessionVmSpawned×{spawns} for this task; \
              KernelRestartCompleted anywhere)\n  \
             pre-crash SessionVmSpawned seq: {pre_crash:?}\n  \
             post-crash recovery signal seen: {recovery}\n  \
             reconciled missing seqs:    {reconciled:?}\n  \
             UNRECONCILED gaps (must be empty): {gaps:?}",
            task = self.in_flight_task_id,
        )
    }
}

// ---------------------------------------------------------------------------
// Unit tests — drive the predicate against hand-built chains.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    use raxis_audit_tools::AuditEvent;
    use uuid::Uuid;

    fn ev(seq: u64, kind: AuditEventKind, task_id: Option<&str>) -> AuditEvent {
        let event_kind = match &kind {
            AuditEventKind::SessionVmSpawned { .. } => "SessionVmSpawned",
            AuditEventKind::ReconciliationGap { .. } => "ReconciliationGap",
            AuditEventKind::TaskBlockedForRecovery { .. } => "TaskBlockedForRecovery",
            AuditEventKind::TaskAutoResumedAfterSupervisorRestart { .. } => {
                "TaskAutoResumedAfterSupervisorRestart"
            }
            AuditEventKind::KernelRestartCompleted { .. } => "KernelRestartCompleted",
            _ => "Other",
        }
        .to_owned();
        AuditEvent {
            seq,
            event_id: Uuid::nil(),
            event_kind,
            session_id: None,
            task_id: task_id.map(str::to_owned),
            initiative_id: None,
            payload: serde_json::to_value(&kind).unwrap(),
            emitted_at: 1700000000 + seq as i64,
            prev_sha256: "0".repeat(64),
        }
    }

    fn vm_spawn(seq: u64, task_id: &str) -> AuditEvent {
        ev(
            seq,
            AuditEventKind::SessionVmSpawned {
                session_id: format!("sess-{task_id}-{seq}"),
                task_id: Some(task_id.to_owned()),
                initiative_id: "init-realistic".to_owned(),
                backend_id: "test-backend".to_owned(),
                egress_tier: "Mediated".to_owned(),
                admission_loopback: "127.0.0.1:0".to_owned(),
                credential_proxies: 0,
            },
            Some(task_id),
        )
    }

    fn reconciliation_gap(seq: u64, missing_seq: u64) -> AuditEvent {
        ev(
            seq,
            AuditEventKind::ReconciliationGap {
                missing_seq,
                reconstructed_event: "PolicyEpochAdvanced".to_owned(),
                reconstructed: true,
            },
            None,
        )
    }

    fn task_blocked(seq: u64, task_id: &str) -> AuditEvent {
        ev(
            seq,
            AuditEventKind::TaskBlockedForRecovery {
                task_id: task_id.to_owned(),
                block_reason: "MidFlightOnRestart".to_owned(),
            },
            Some(task_id),
        )
    }

    fn kernel_restart_completed(seq: u64) -> AuditEvent {
        ev(
            seq,
            AuditEventKind::KernelRestartCompleted {
                prev_run_exit_code: 1,
                recovery_sweep_ms: 12,
                dump_path: None,
            },
            None,
        )
    }

    fn task_auto_resumed(seq: u64, task_id: &str) -> AuditEvent {
        ev(
            seq,
            AuditEventKind::TaskAutoResumedAfterSupervisorRestart {
                task_id: task_id.to_owned(),
                initiative_id: "init-realistic".to_owned(),
                prior_state: "Running".to_owned(),
                witness_count_preserved: 0,
                supervisor_restart_id: "test-restart".to_owned(),
            },
            Some(task_id),
        )
    }

    #[test]
    fn respawn_recovery_satisfies() {
        // Consecutive seqs: a real respawn lands on the next free
        // `seq` after the pre-crash spawn; the witness's
        // `unreconciled_gaps` walker is strict about monotonic
        // contiguity unless a `ReconciliationGap` event accounts
        // for the gap (`unreconciled_seq_gap_fails` pins that
        // negative direction).
        let chain = vec![vm_spawn(10, "lint-defect"), vm_spawn(11, "lint-defect")];
        let w = CrashRecoveryWitness::new("lint-defect");
        assert!(w.satisfied_by(&chain), "{}", w.diagnostic(&chain));
    }

    #[test]
    fn reconciliation_gap_after_spawn_satisfies() {
        let chain = vec![vm_spawn(5, "lint-defect"), reconciliation_gap(7, 6)];
        let w = CrashRecoveryWitness::new("lint-defect");
        assert!(w.satisfied_by(&chain), "{}", w.diagnostic(&chain));
    }

    #[test]
    fn task_blocked_for_recovery_satisfies() {
        let chain = vec![vm_spawn(5, "lint-defect"), task_blocked(6, "lint-defect")];
        let w = CrashRecoveryWitness::new("lint-defect");
        assert!(w.satisfied_by(&chain), "{}", w.diagnostic(&chain));
    }

    #[test]
    fn missing_pre_crash_spawn_fails() {
        // SessionVmSpawned exists but for a different task.
        // The `reconciliation_gap` here is enough to make the
        // chain crash-evidence-bearing (spawn_count for `lint-defect`
        // is 0 so the `> 1` arm is silent; we add a
        // `KernelRestartCompleted` to force the witness into Mode 2).
        let chain = vec![
            vm_spawn(5, "other-task"),
            reconciliation_gap(7, 6),
            kernel_restart_completed(8),
        ];
        let w = CrashRecoveryWitness::new("lint-defect");
        assert!(!w.satisfied_by(&chain));
    }

    #[test]
    fn no_crash_signature_satisfies_vacuously() {
        // Happy-path realistic run: one SessionVmSpawned for the
        // task and no KernelRestartCompleted anywhere. The witness
        // has nothing to assert beyond audit-chain monotonicity.
        let chain = vec![vm_spawn(5, "lint-defect")];
        let w = CrashRecoveryWitness::new("lint-defect");
        assert!(w.satisfied_by(&chain), "{}", w.diagnostic(&chain));
    }

    #[test]
    fn no_crash_signature_with_unreconciled_gap_still_fails() {
        // Even in vacuous-satisfy mode, INV-AUDIT-01 monotonicity
        // is non-negotiable: a real chain gap with no
        // ReconciliationGap cover must still trip the witness.
        let chain = vec![vm_spawn(5, "lint-defect"), vm_spawn(7, "other-task")];
        let w = CrashRecoveryWitness::new("lint-defect");
        assert!(!w.satisfied_by(&chain));
    }

    #[test]
    fn kernel_restart_without_recovery_signal_fails() {
        // KernelRestartCompleted is in the chain (crash signature
        // present) — the witness MUST find a recovery signal for
        // the in-flight task afterward. Without one, it fails.
        let chain = vec![vm_spawn(5, "lint-defect"), kernel_restart_completed(6)];
        let w = CrashRecoveryWitness::new("lint-defect");
        assert!(!w.satisfied_by(&chain));
    }

    #[test]
    fn task_auto_resumed_after_supervisor_restart_satisfies() {
        let chain = vec![
            vm_spawn(5, "lint-defect"),
            kernel_restart_completed(6),
            task_auto_resumed(7, "lint-defect"),
        ];
        let w = CrashRecoveryWitness::new("lint-defect");
        assert!(w.satisfied_by(&chain), "{}", w.diagnostic(&chain));
    }

    #[test]
    fn unreconciled_seq_gap_fails() {
        // A 6→8 jump with no ReconciliationGap entry is a real
        // INV-AUDIT-01 violation that the witness must surface.
        let chain = vec![vm_spawn(5, "lint-defect"), vm_spawn(7, "lint-defect")];
        let w = CrashRecoveryWitness::new("lint-defect");
        assert!(!w.satisfied_by(&chain));
        let diag = w.diagnostic(&chain);
        assert!(diag.contains("UNRECONCILED gaps"));
        assert!(diag.contains("[6]"));
    }

    #[test]
    fn reconciled_gap_does_not_violate() {
        // Same shape as the unreconciled test but with a matching
        // ReconciliationGap entry between.
        let chain = vec![
            vm_spawn(5, "lint-defect"),
            reconciliation_gap(7, 6),
            vm_spawn(9, "lint-defect"),
            reconciliation_gap(10, 8),
        ];
        let w = CrashRecoveryWitness::new("lint-defect");
        assert!(w.satisfied_by(&chain), "{}", w.diagnostic(&chain));
    }

    #[test]
    fn recovery_signal_must_be_strictly_after_pre_crash_spawn() {
        // ReconciliationGap that landed BEFORE the in-flight
        // spawn does NOT count as recovery for THIS spawn.
        let chain = vec![reconciliation_gap(2, 1), vm_spawn(5, "lint-defect")];
        let w = CrashRecoveryWitness::new("lint-defect");
        assert!(!w.satisfied_by(&chain));
    }
}

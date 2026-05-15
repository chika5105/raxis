//! Crash-recovery witness.
//!
//! The realistic-scenario test driver (P3-9) drops a SIGTERM on
//! the kernel mid-task and then restarts it. This module provides
//! the predicate that verifies the audit chain after reboot
//! carries the **expected post-crash signature**:
//!
//!   * the chain must show at least one **pre-crash** event for
//!     the task that was in flight (the test driver picks a task
//!     known to be in flight by waiting for its
//!     `SessionVmSpawned` audit record before sending the
//!     signal),
//!   * the chain must show at least one **recovery signal** after
//!     the crash — either:
//!     a. a [`ReconciliationGap`] event the kernel emitted on
//!        restart (crash between commit-to-SQLite and JSONL
//!        write), OR
//!     b. a [`TaskBlockedForRecovery`] event for the in-flight
//!        task (the kernel detected the task's mid-flight state
//!        on reboot and blocked it for operator review), OR
//!     c. a **respawn**: a second `SessionVmSpawned` for the
//!        same task_id whose `seq` strictly exceeds the pre-
//!        crash spawn's `seq` (the kernel decided to resume the
//!        task autonomously),
//!   * the chain's `seq` field is strictly monotonically
//!     increasing — any unreconciled gap is a real INV-AUDIT-01
//!     violation the witness must surface loudly. A "reconciled"
//!     gap is a gap that some `ReconciliationGap{missing_seq:n}`
//!     event accounts for; an unreconciled gap is any other gap.
//!
//! Spec references:
//!   * `raxis/crates/audit/src/event.rs` (the comment on
//!     `AuditEvent::seq`: "Gaps indicate a reconciliation gap
//!     (crash between commit and JSONL write)").
//!   * `agent-recovery.md` (`TaskBlockedForRecovery` semantics).
//!
//! [`ReconciliationGap`]: raxis_audit_tools::AuditEventKind::ReconciliationGap
//! [`TaskBlockedForRecovery`]: raxis_audit_tools::AuditEventKind::TaskBlockedForRecovery

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
        if self.pre_crash_spawn_seq(chain).is_none() {
            return false;
        }
        if !self.unreconciled_gaps(chain).is_empty() {
            return false;
        }
        self.has_recovery_signal(chain)
    }

    fn diagnostic(&self, chain: &[AuditEvent]) -> String {
        let pre_crash = self.pre_crash_spawn_seq(chain);
        let recovery = self.has_recovery_signal(chain);
        let gaps = self.unreconciled_gaps(chain);
        let reconciled: Vec<u64> = self.reconciled_seqs(chain).into_iter().collect();
        format!(
            "CrashRecovery[{task}]:\n  \
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
        let chain = vec![vm_spawn(5, "other-task"), reconciliation_gap(7, 6)];
        let w = CrashRecoveryWitness::new("lint-defect");
        assert!(!w.satisfied_by(&chain));
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

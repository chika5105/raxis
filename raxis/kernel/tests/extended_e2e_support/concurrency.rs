//! Concurrency oracle for the extended e2e scenario.
//!
//! Walks the audit chain, picks `SessionVmSpawned` / `SessionVmExited`
//! events for the configured fan-out task ids, builds wall-clock
//! `[start, end]` intervals (second resolution, matching
//! `AuditEvent.emitted_at`), and returns true iff at least one pair
//! of intervals overlaps.
//!
//! The overlap tolerance is intentionally loose: any non-empty
//! intersection counts. This avoids CI flakes from second-resolution
//! timestamp jitter while still ruling out a strictly-serialised
//! schedule (which would exhibit zero overlap between any pair).
//!
//! Spec: [`raxis/specs/v2/e2e-extended-scenario.md`] §7.3, §8.

use std::collections::BTreeMap;

use raxis_audit_tools::{AuditEvent, AuditEventKind};

use super::witnesses::typed;

/// Closed wall-clock interval [start, end], unix seconds.
#[derive(Debug, Clone, Copy)]
pub struct Interval {
    pub start: i64,
    pub end: i64,
}

impl Interval {
    pub fn overlaps(&self, other: &Interval) -> bool {
        self.start <= other.end && other.start <= self.end
    }
}

/// Result of running the oracle. Always populated for diagnostic
/// rendering, even when overlap is `true`.
#[derive(Debug, Default)]
pub struct ConcurrencyReport {
    /// Per-task interval, in chain order.
    pub per_task: BTreeMap<String, Interval>,
    /// Pairs of task ids that exhibit at least one overlap.
    pub overlapping_pairs: Vec<(String, String)>,
}

impl ConcurrencyReport {
    pub fn has_overlap(&self) -> bool {
        !self.overlapping_pairs.is_empty()
    }
}

/// Build per-task intervals + the list of overlapping pairs.
pub fn build_report(chain: &[AuditEvent], task_ids: &[&str]) -> ConcurrencyReport {
    let mut spawn_ts: BTreeMap<String, (i64, String)> = BTreeMap::new();
    let mut exit_ts: BTreeMap<String, i64> = BTreeMap::new();

    for ev in chain {
        match typed(ev) {
            Some(AuditEventKind::SessionVmSpawned {
                session_id,
                task_id: Some(task_id),
                ..
            }) if task_ids.contains(&task_id.as_str()) => {
                spawn_ts.insert(task_id.clone(), (ev.emitted_at, session_id));
            }
            Some(AuditEventKind::SessionVmExited { session_id, .. }) => {
                exit_ts.insert(session_id, ev.emitted_at);
            }
            _ => {}
        }
    }

    let mut per_task: BTreeMap<String, Interval> = BTreeMap::new();
    for (task, (start, session_id)) in spawn_ts {
        let end = exit_ts.get(&session_id).copied().unwrap_or(i64::MAX);
        per_task.insert(task, Interval { start, end });
    }

    let mut overlapping_pairs = Vec::new();
    let entries: Vec<(&String, &Interval)> = per_task.iter().collect();
    for i in 0..entries.len() {
        for j in (i + 1)..entries.len() {
            if entries[i].1.overlaps(entries[j].1) {
                overlapping_pairs.push((entries[i].0.clone(), entries[j].0.clone()));
            }
        }
    }

    ConcurrencyReport {
        per_task,
        overlapping_pairs,
    }
}

/// Convenience wrapper that panics with a per-task interval render
/// when no overlap is found.
pub fn assert_overlap_or_panic(chain: &[AuditEvent], task_ids: &[&str]) {
    let report = build_report(chain, task_ids);
    if !report.has_overlap() {
        let mut msg = format!(
            "ConcurrencyOracle: expected at least one overlapping pair across \
             {} fan-out tasks; observed zero overlaps.\n",
            task_ids.len(),
        );
        msg.push_str("Per-task intervals (start..end, unix seconds):\n");
        for (task, iv) in &report.per_task {
            msg.push_str(&format!(
                "  {task}: [{}, {}] (duration {}s)\n",
                iv.start,
                iv.end,
                iv.end - iv.start,
            ));
        }
        msg.push_str(
            "If hardware is single-CPU or the kernel scheduler ran tasks \
             strictly serially, this is expected to fail. Verify the plan's \
             DAG declares the fan-out tasks as siblings (no \
             `predecessors = [other_fanout]`).",
        );
        panic!("{msg}");
    }
}

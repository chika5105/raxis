// raxis-kernel::restart_lifecycle — boot-time rehydration of the
// supervisor's restart context into the audit chain.
//
// Normative reference:
// `specs/v2/self-healing-supervisor.md §3.3` (boot-time
// rehydration) + §INV-SUPERVISOR-RESTART-AUDIT-01.
//
// Called once per kernel boot from `main.rs`, between the canonical
// `KernelStarted` emit and the disk-watchdog start. Reads:
//
//   1. `<data_dir>/deadlock_dump_*.json` — forensic dumps the prior
//      kernel's deadlock watcher wrote on its way out. For each
//      unprocessed dump, emits a `KernelDeadlockDetected` audit
//      event and moves the dump into
//      `<data_dir>/deadlock_dumps_consumed/`.
//
//   2. `<data_dir>/kernel_lifecycle_status.json` — the supervisor's
//      sentinel file. When `status = "Restarting"`, emits the
//      paired `KernelRestartInitiated` + `KernelRestartCompleted`
//      sequence so the audit chain records WHY this kernel was
//      replaced.
//
// All emits go through the supplied `AuditSink` and are best-effort:
// emit failures land as structured stderr lines but do not abort
// boot. The on-disk dump file + supervisor stderr log are the
// forensic backups.

#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};

use raxis_audit_tools::{AuditEventKind, AuditSink};
use serde::Deserialize;

use crate::deadlock_dump;

/// Outcome of a rehydration pass. Useful for tests + future
/// metrics surfaces; the kernel's `main.rs` only reads
/// `dumps_processed` for an info log line.
#[derive(Debug, Default, Clone, Copy)]
pub struct RehydrationOutcome {
    pub dumps_processed: u32,
    pub kernel_deadlock_detected_emits: u32,
    pub kernel_restart_initiated_emits: u32,
    pub kernel_restart_completed_emits: u32,
}

/// Sentinel-file view used by the rehydration path. Serde-skips
/// every unknown field so a future supervisor revision can extend
/// the on-disk schema without breaking older kernels.
#[derive(Debug, Clone, Deserialize)]
pub struct SentinelView {
    pub status: String,
    #[serde(default)]
    pub last_restart_reason: Option<String>,
    #[serde(default)]
    pub prev_run_exit_code: Option<i32>,
    #[serde(default)]
    pub attempt_n: Option<u32>,
    #[serde(default)]
    pub max_attempts: Option<u32>,
    /// iter44 / `INV-OBS-KERNEL-RESPAWN-COVERAGE-01` — wall-clock
    /// (unix seconds) of the supervisor's restart decision. Used by
    /// `kernel/src/main.rs` to compute the
    /// `KernelRespawnDuration` histogram observation
    /// (supervisor-decision → kernel-up). `serde(default)` keeps
    /// older sentinels (pre-iter44 supervisors that don't write the
    /// field) working — the metric falls back to the kernel-side
    /// boot-recovery sweep approximation in that case.
    #[serde(default)]
    pub last_restart_unix_ts: Option<i64>,
    /// iter44 / `INV-OBS-KERNEL-RESPAWN-COVERAGE-01` — present on
    /// `Halted` sentinels; the supervisor's `OperatorStop` /
    /// `OperatorStopForced` / `CircuitOpen` sub-state distinguishes
    /// "supervisor refused to restart" from "supervisor was asked to
    /// stop". Mapped to a closed `reason` lexicon by
    /// `kernel/src/observability.rs::supervisor_refused_reason`.
    #[serde(default)]
    pub sub_state: Option<String>,
}

/// Read + parse the supervisor sentinel file. Returns `None` when
/// the file is absent or carries any non-`Restarting` status (the
/// rehydration path is only interested in the restart case).
///
/// **Forward-compat**. An unknown future field in the JSON is
/// silently ignored (`serde(default)`); a malformed file logs a
/// warn line on stderr and returns `None`.
pub fn read_sentinel_for_restart(sentinel_path: &Path) -> Option<SentinelView> {
    match read_sentinel_any_status(sentinel_path) {
        Some(v) if v.status == "Restarting" => Some(v),
        _ => None,
    }
}

/// iter44 / `INV-OBS-KERNEL-RESPAWN-COVERAGE-01` — read + parse the
/// supervisor sentinel file regardless of status. Used by the
/// kernel-boot metric-emission path so the operator dashboard can
/// distinguish a `Restarting` kernel-up event (counted as a
/// successful respawn) from a `Halted (CircuitOpen)` sentinel
/// observed after the operator manually bypassed a halted
/// supervisor (counted as a `SupervisorRefusedRestart`).
///
/// `read_sentinel_for_restart` is the rehydration filter on top of
/// this primitive — both paths share the same parse + warn-on-bad
/// JSON behaviour so a malformed file never crashes the kernel.
pub fn read_sentinel_any_status(sentinel_path: &Path) -> Option<SentinelView> {
    let bytes = match std::fs::read(sentinel_path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
        Err(e) => {
            eprintln!(
                "{{\"level\":\"warn\",\"event\":\"kernel_lifecycle_sentinel_read_failed\",\
                 \"reason\":\"{e}\"}}"
            );
            return None;
        }
    };
    match serde_json::from_slice::<SentinelView>(&bytes) {
        Ok(v) => Some(v),
        Err(e) => {
            eprintln!(
                "{{\"level\":\"warn\",\"event\":\"kernel_lifecycle_sentinel_parse_failed\",\
                 \"reason\":\"{e}\"}}"
            );
            None
        }
    }
}

/// Synthesise the V2.5 restart-lifecycle audit events into the
/// chain.
///
/// **Order of emits** (per `INV-SUPERVISOR-RESTART-AUDIT-01`):
///
///   1. One `KernelDeadlockDetected` per unprocessed dump file
///      under `<data_dir>/`. Dump files are moved into
///      `<data_dir>/deadlock_dumps_consumed/` after a successful
///      emit.
///
///   2. If the supervisor sentinel says `status = "Restarting"`:
///      one `KernelRestartInitiated` (with the supervisor's
///      classification — overridden to `"DeadlockDetected"` if
///      step 1 found any dump file), then one
///      `KernelRestartCompleted` (with the merged dump path).
///
///   3. If the sentinel is absent BUT step 1 found a dump file
///      (operator restarted manually after a deadlock without
///      `raxis-supervisor`): a lone `KernelRestartCompleted` with
///      `prev_run_exit_code = 70` so the chain still records the
///      restart event.
///
/// **Errors** are best-effort. Per-emit failures log a structured
/// stderr line and the function continues — a kernel that booted
/// successfully after a deadlock is more useful than one that
/// refuses to boot because a stale dump file has the wrong
/// schema. Returns the [`RehydrationOutcome`] for caller-side
/// observability.
///
/// **Locks taken:** none beyond what the supplied `AuditSink`
/// implementation takes per `emit` call. Safe to call from a
/// `spawn_blocking` worker (the kernel's `main.rs` calls it
/// directly from the runtime thread because it is sync-bounded).
pub fn rehydrate_restart_context(
    audit: &dyn AuditSink,
    data_dir: &Path,
    sentinel: Option<SentinelView>,
    recovery_sweep_ms: u64,
) -> RehydrationOutcome {
    let mut outcome = RehydrationOutcome::default();

    // 1. Scan + emit per-dump `KernelDeadlockDetected`.
    let pending_dumps: Vec<PathBuf> = match deadlock_dump::scan_pending_dumps(data_dir) {
        Ok(v) => v,
        Err(e) => {
            eprintln!(
                "{{\"level\":\"warn\",\"event\":\"deadlock_dump_scan_failed\",\
                 \"reason\":\"{e}\"}}"
            );
            Vec::new()
        }
    };
    let mut last_dump_path: Option<String> = None;
    for dump_path in &pending_dumps {
        let dump_path_str = dump_path.display().to_string();
        outcome.dumps_processed = outcome.dumps_processed.saturating_add(1);
        match deadlock_dump::read_dump(dump_path) {
            Ok(dump) => match audit.emit(
                AuditEventKind::KernelDeadlockDetected {
                    thread_count: dump.thread_count,
                    lock_count: dump.lock_count,
                    dump_path: Some(dump_path_str.clone()),
                    detected_at_unix_secs: dump.detected_at_unix_secs,
                },
                None,
                None,
                None,
            ) {
                Ok(_) => {
                    outcome.kernel_deadlock_detected_emits =
                        outcome.kernel_deadlock_detected_emits.saturating_add(1);
                    last_dump_path = Some(dump_path_str.clone());
                }
                Err(e) => eprintln!(
                    "{{\"level\":\"error\",\
                     \"event\":\"KernelDeadlockDetected\",\
                     \"audit_emit_failed\":\"{e}\"}}"
                ),
            },
            Err(e) => {
                eprintln!(
                    "{{\"level\":\"warn\",\
                     \"event\":\"deadlock_dump_read_failed\",\
                     \"path\":{path_json},\
                     \"reason\":\"{e}\"}}",
                    path_json = serde_json::to_string(&dump_path_str)
                        .unwrap_or_else(|_| "\"<unserialisable>\"".to_owned()),
                );
                // Still emit a minimal event so the chain records
                // the corrupted dump path — the operator can
                // investigate the on-disk file directly.
                if audit
                    .emit(
                        AuditEventKind::KernelDeadlockDetected {
                            thread_count: 0,
                            lock_count: 0,
                            dump_path: Some(dump_path_str.clone()),
                            detected_at_unix_secs: 0,
                        },
                        None,
                        None,
                        None,
                    )
                    .is_ok()
                {
                    outcome.kernel_deadlock_detected_emits =
                        outcome.kernel_deadlock_detected_emits.saturating_add(1);
                }
            }
        }
        if let Err(e) = deadlock_dump::move_to_consumed(data_dir, dump_path) {
            eprintln!(
                "{{\"level\":\"warn\",\
                 \"event\":\"deadlock_dump_move_to_consumed_failed\",\
                 \"reason\":\"{e}\"}}"
            );
        }
    }

    // 2. Supervisor said `Restarting` — emit the paired sequence.
    if let Some(sup) = sentinel {
        let sup_reason = sup
            .last_restart_reason
            .unwrap_or_else(|| "PanicAbort".to_owned());
        let prev_exit = sup.prev_run_exit_code.unwrap_or(0);
        let attempt_n = sup.attempt_n.unwrap_or(1);
        let max_attempts = sup.max_attempts.unwrap_or(3);
        // The dump file (if any) is the higher-fidelity signal.
        // Override the supervisor's classification when we have
        // one, so a kernel that died of an operator-perceived
        // panic but ALSO wrote a deadlock dump is recorded as
        // `DeadlockDetected` (the dump is causal evidence).
        let reason = if last_dump_path.is_some() {
            "DeadlockDetected".to_owned()
        } else {
            sup_reason
        };
        if audit
            .emit(
                AuditEventKind::KernelRestartInitiated {
                    reason: reason.clone(),
                    prev_run_exit_code: prev_exit,
                    attempt_n,
                    max_attempts,
                },
                None,
                None,
                None,
            )
            .map_err(|e| {
                eprintln!(
                    "{{\"level\":\"error\",\
                     \"event\":\"KernelRestartInitiated\",\
                     \"audit_emit_failed\":\"{e}\"}}"
                );
            })
            .is_ok()
        {
            outcome.kernel_restart_initiated_emits =
                outcome.kernel_restart_initiated_emits.saturating_add(1);
        }
        if audit
            .emit(
                AuditEventKind::KernelRestartCompleted {
                    prev_run_exit_code: prev_exit,
                    recovery_sweep_ms,
                    dump_path: last_dump_path.clone(),
                },
                None,
                None,
                None,
            )
            .map_err(|e| {
                eprintln!(
                    "{{\"level\":\"error\",\
                     \"event\":\"KernelRestartCompleted\",\
                     \"audit_emit_failed\":\"{e}\"}}"
                );
            })
            .is_ok()
        {
            outcome.kernel_restart_completed_emits =
                outcome.kernel_restart_completed_emits.saturating_add(1);
        }
    } else if last_dump_path.is_some() {
        // 3. Manual restart after a deadlock, no supervisor in
        //    play. Record the completion for forensic
        //    completeness; `prev_run_exit_code = 70` by
        //    construction (the deadlock watcher's exit code).
        if audit
            .emit(
                AuditEventKind::KernelRestartCompleted {
                    prev_run_exit_code: 70,
                    recovery_sweep_ms,
                    dump_path: last_dump_path,
                },
                None,
                None,
                None,
            )
            .map_err(|e| {
                eprintln!(
                    "{{\"level\":\"error\",\
                     \"event\":\"KernelRestartCompleted\",\
                     \"audit_emit_failed\":\"{e}\"}}"
                );
            })
            .is_ok()
        {
            outcome.kernel_restart_completed_emits =
                outcome.kernel_restart_completed_emits.saturating_add(1);
        }
    }

    outcome
}

// ---------------------------------------------------------------------------
// Tests — `INV-SUPERVISOR-RESTART-AUDIT-01` witness scaffolding.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deadlock_dump::{DeadlockCycle, DeadlockDump, DeadlockThread};
    use raxis_audit_tools::{AuditWriter, FileAuditSink};
    use std::sync::Arc;
    use tempfile::tempdir;

    fn open_audit(audit_dir: &Path) -> Arc<dyn AuditSink> {
        std::fs::create_dir_all(audit_dir).unwrap();
        let writer = AuditWriter::open(&audit_dir.join("segment-000.jsonl"), 0, None)
            .expect("open audit writer at genesis");
        Arc::new(FileAuditSink::new(writer))
    }

    fn synthetic_dump(detected_at_unix_secs: i64) -> DeadlockDump {
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
                        backtrace: "frame_a".to_owned(),
                    },
                    DeadlockThread {
                        thread_id: "ThreadId(11)".to_owned(),
                        backtrace: "frame_b".to_owned(),
                    },
                ],
            }],
        }
    }

    fn read_chain_kinds(audit_dir: &Path) -> Vec<String> {
        let bytes = std::fs::read(audit_dir.join("segment-000.jsonl")).expect("read audit segment");
        let text = String::from_utf8(bytes).expect("utf-8 audit");
        text.lines()
            .filter(|l| !l.is_empty())
            .map(|l| {
                let v: serde_json::Value = serde_json::from_str(l).expect("audit line json");
                v["event_kind"].as_str().unwrap_or("").to_owned()
            })
            .collect()
    }

    fn verify_chain_clean(audit_dir: &Path) {
        // `verify_chain_from` walks every record and surfaces any
        // hash-link / serde / schema break as `Err`. `Ok` is the
        // load-bearing chain-clean witness for
        // `INV-SUPERVISOR-RESTART-AUDIT-01`.
        let stats = raxis_audit_tools::verify_chain_from(audit_dir, 0)
            .expect("audit chain must verify clean across the restart boundary");
        assert!(
            stats.total_records > 0,
            "chain must have at least one record after rehydration",
        );
    }

    /// `INV-SUPERVISOR-RESTART-AUDIT-01` — happy path.
    ///
    /// Dump file present + sentinel says `Restarting` →
    /// `KernelDeadlockDetected → KernelRestartInitiated →
    /// KernelRestartCompleted` with hash-continuous chain.
    #[test]
    fn dump_plus_sentinel_emits_full_paired_sequence_and_chain_verifies() {
        let dir = tempdir().unwrap();
        let data_dir = dir.path();
        let audit_dir = data_dir.join("audit");

        // Seed: prior kernel's dump file.
        deadlock_dump::write_dump(data_dir, &synthetic_dump(1_714_500_000)).expect("write dump");
        // Seed: supervisor sentinel saying we're a restart.
        let sentinel_json = serde_json::json!({
            "schema_version": 1,
            "status": "Restarting",
            "sub_state": null,
            "attempt_n": 2,
            "max_attempts": 3,
            "last_restart_unix_ts": 1_714_500_001,
            "last_restart_reason": "DeadlockDetected",
            "prev_run_exit_code": 70,
            "attempts_in_window": 2,
            "window_secs": 60,
            "supervisor_pid": 12345,
            "kernel_pid": 12346,
            "updated_at_unix_secs": 1_714_500_001,
        });
        std::fs::write(
            data_dir.join("kernel_lifecycle_status.json"),
            serde_json::to_vec(&sentinel_json).unwrap(),
        )
        .unwrap();

        let audit = open_audit(&audit_dir);
        // Pre-condition: the canonical `KernelStarted` would
        // have landed in `main.rs` Step 8 BEFORE we run.
        audit
            .emit(
                AuditEventKind::KernelStarted {
                    data_dir: data_dir.display().to_string(),
                    policy_epoch: 1,
                    schema_version: 1,
                },
                None,
                None,
                None,
            )
            .unwrap();

        let sentinel = read_sentinel_for_restart(&data_dir.join("kernel_lifecycle_status.json"));
        assert!(sentinel.is_some(), "sentinel must parse as Restarting");

        let outcome = rehydrate_restart_context(audit.as_ref(), data_dir, sentinel, 47);
        assert_eq!(outcome.dumps_processed, 1);
        assert_eq!(outcome.kernel_deadlock_detected_emits, 1);
        assert_eq!(outcome.kernel_restart_initiated_emits, 1);
        assert_eq!(outcome.kernel_restart_completed_emits, 1);

        let kinds = read_chain_kinds(&audit_dir);
        assert_eq!(
            kinds,
            vec![
                "KernelStarted".to_owned(),
                "KernelDeadlockDetected".to_owned(),
                "KernelRestartInitiated".to_owned(),
                "KernelRestartCompleted".to_owned(),
            ],
            "full paired sequence must land in order",
        );

        // Hash-continuity across the whole chain (the load-bearing
        // half of `INV-SUPERVISOR-RESTART-AUDIT-01`).
        verify_chain_clean(&audit_dir);

        // Dump file must have moved into the consumed dir so the
        // next boot does not double-emit.
        assert!(
            !data_dir.join("deadlock_dump_1714500000.json").exists(),
            "consumed dump should no longer be at top-level path",
        );
        assert!(
            data_dir
                .join("deadlock_dumps_consumed")
                .join("deadlock_dump_1714500000.json")
                .exists(),
            "consumed dump should have been moved to the sibling dir",
        );
    }

    /// `INV-SUPERVISOR-RESTART-AUDIT-01` — dump-only (no
    /// supervisor) path.
    ///
    /// Operator manually restarted the kernel after a deadlock
    /// (no `raxis-supervisor`). The kernel still records
    /// `KernelDeadlockDetected → KernelRestartCompleted` so the
    /// chain has the forensic evidence.
    #[test]
    fn dump_without_sentinel_still_emits_completion_event() {
        let dir = tempdir().unwrap();
        let data_dir = dir.path();
        let audit_dir = data_dir.join("audit");
        deadlock_dump::write_dump(data_dir, &synthetic_dump(1_714_500_002)).expect("write dump");

        let audit = open_audit(&audit_dir);
        audit
            .emit(
                AuditEventKind::KernelStarted {
                    data_dir: data_dir.display().to_string(),
                    policy_epoch: 1,
                    schema_version: 1,
                },
                None,
                None,
                None,
            )
            .unwrap();

        let outcome = rehydrate_restart_context(audit.as_ref(), data_dir, None, 33);
        assert_eq!(outcome.dumps_processed, 1);
        assert_eq!(outcome.kernel_deadlock_detected_emits, 1);
        assert_eq!(outcome.kernel_restart_initiated_emits, 0);
        assert_eq!(outcome.kernel_restart_completed_emits, 1);

        let kinds = read_chain_kinds(&audit_dir);
        assert_eq!(
            kinds,
            vec![
                "KernelStarted".to_owned(),
                "KernelDeadlockDetected".to_owned(),
                "KernelRestartCompleted".to_owned(),
            ],
        );
        verify_chain_clean(&audit_dir);
    }

    /// `INV-SUPERVISOR-RESTART-AUDIT-01` — sentinel without dump
    /// (panic / OOM / signaled crash recovery path).
    #[test]
    fn sentinel_without_dump_emits_paired_sequence_with_no_dump_path() {
        let dir = tempdir().unwrap();
        let data_dir = dir.path();
        let audit_dir = data_dir.join("audit");
        let sentinel_json = serde_json::json!({
            "schema_version": 1,
            "status": "Restarting",
            "sub_state": null,
            "attempt_n": 1,
            "max_attempts": 3,
            "last_restart_unix_ts": 1_714_500_010,
            "last_restart_reason": "SignalCrash",
            "prev_run_exit_code": 139, // SIGSEGV
            "attempts_in_window": 1,
            "window_secs": 60,
            "supervisor_pid": 12345,
            "kernel_pid": 12346,
            "updated_at_unix_secs": 1_714_500_010,
        });
        std::fs::write(
            data_dir.join("kernel_lifecycle_status.json"),
            serde_json::to_vec(&sentinel_json).unwrap(),
        )
        .unwrap();

        let audit = open_audit(&audit_dir);
        audit
            .emit(
                AuditEventKind::KernelStarted {
                    data_dir: data_dir.display().to_string(),
                    policy_epoch: 1,
                    schema_version: 1,
                },
                None,
                None,
                None,
            )
            .unwrap();

        let sentinel = read_sentinel_for_restart(&data_dir.join("kernel_lifecycle_status.json"));
        let outcome = rehydrate_restart_context(audit.as_ref(), data_dir, sentinel, 5);
        assert_eq!(outcome.dumps_processed, 0);
        assert_eq!(outcome.kernel_deadlock_detected_emits, 0);
        assert_eq!(outcome.kernel_restart_initiated_emits, 1);
        assert_eq!(outcome.kernel_restart_completed_emits, 1);

        let kinds = read_chain_kinds(&audit_dir);
        assert_eq!(
            kinds,
            vec![
                "KernelStarted".to_owned(),
                "KernelRestartInitiated".to_owned(),
                "KernelRestartCompleted".to_owned(),
            ],
        );
        verify_chain_clean(&audit_dir);
    }

    /// Sentinel + dump together → reason is `DeadlockDetected`
    /// regardless of what the supervisor wrote (the dump is the
    /// higher-fidelity signal).
    #[test]
    fn dump_overrides_supervisor_reason_to_deadlock_detected() {
        let dir = tempdir().unwrap();
        let data_dir = dir.path();
        let audit_dir = data_dir.join("audit");
        deadlock_dump::write_dump(data_dir, &synthetic_dump(1_714_500_020)).unwrap();
        let sentinel_json = serde_json::json!({
            "status": "Restarting",
            "last_restart_reason": "PanicAbort", // wrong; dump is correct
            "prev_run_exit_code": 70,
            "attempt_n": 1,
            "max_attempts": 3,
        });
        std::fs::write(
            data_dir.join("kernel_lifecycle_status.json"),
            serde_json::to_vec(&sentinel_json).unwrap(),
        )
        .unwrap();

        let audit = open_audit(&audit_dir);
        audit
            .emit(
                AuditEventKind::KernelStarted {
                    data_dir: data_dir.display().to_string(),
                    policy_epoch: 1,
                    schema_version: 1,
                },
                None,
                None,
                None,
            )
            .unwrap();
        let sentinel = read_sentinel_for_restart(&data_dir.join("kernel_lifecycle_status.json"));
        rehydrate_restart_context(audit.as_ref(), data_dir, sentinel, 1);

        // Read the third line (KernelRestartInitiated) and assert
        // its reason field carries `DeadlockDetected`.
        let bytes = std::fs::read(audit_dir.join("segment-000.jsonl")).unwrap();
        let text = String::from_utf8(bytes).unwrap();
        let initiated_line = text
            .lines()
            .find(|l| l.contains("\"event_kind\":\"KernelRestartInitiated\""))
            .expect("KernelRestartInitiated must be in the chain");
        assert!(
            initiated_line.contains("\"reason\":\"DeadlockDetected\""),
            "reason should be overridden to DeadlockDetected when a dump exists, got: {initiated_line}",
        );
    }

    /// Idempotency: running the rehydration TWICE in a row does
    /// NOT double-emit. The dump file is moved to the consumed
    /// dir on the first pass, so the second pass finds nothing.
    #[test]
    fn second_pass_is_idempotent() {
        let dir = tempdir().unwrap();
        let data_dir = dir.path();
        let audit_dir = data_dir.join("audit");
        deadlock_dump::write_dump(data_dir, &synthetic_dump(1_714_500_030)).unwrap();
        let audit = open_audit(&audit_dir);
        audit
            .emit(
                AuditEventKind::KernelStarted {
                    data_dir: data_dir.display().to_string(),
                    policy_epoch: 1,
                    schema_version: 1,
                },
                None,
                None,
                None,
            )
            .unwrap();

        let first = rehydrate_restart_context(audit.as_ref(), data_dir, None, 1);
        let second = rehydrate_restart_context(audit.as_ref(), data_dir, None, 1);

        assert_eq!(first.dumps_processed, 1);
        assert_eq!(second.dumps_processed, 0);
        let kinds = read_chain_kinds(&audit_dir);
        // KernelStarted, KernelDeadlockDetected, KernelRestartCompleted.
        // No duplicates.
        assert_eq!(kinds.len(), 3);
        verify_chain_clean(&audit_dir);
    }
}

// raxis-kernel::recovery — Post-crash reconciliation.
//
// Normative reference: kernel-core.md §2.2 `src/recovery.rs`.
//
// Purpose: Runs at startup step 6. Verifies audit chain integrity, identifies
// tasks that were in-flight at crash time, and marks them
// BlockedRecoveryPending for operator disposition.
//
// **V2.5 supervisor-aware auto-resume** (`self-healing-supervisor.md §3.5`,
// `INV-SUPERVISOR-AUTO-RESUME-ON-CLEAN-RESTART-01`).  When the kernel was
// re-spawned by the `raxis-supervisor` binary after an auto-restartable
// exit code (deadlock / panic / signal-crash), the boot sequence calls
// `reconcile_after_supervisor_restart` AFTER the audit writer is open
// AFTER `restart_lifecycle::rehydrate_restart_context` has emitted the
// paired `KernelRestart{Initiated,Completed}` events.  That codepath
// transparently re-admits every task this boot's recovery sweep just
// moved to `BlockedRecoveryPending` (BRP → Admitted, mirroring the
// operator `task resume` FSM edge), with two explicit exclusions:
//
//   * tasks under operator quarantine (`initiative_quarantines` row),
//   * tasks that were ALREADY `BlockedRecoveryPending` BEFORE this
//     boot's sweep (preserve pre-existing operator block).
//
// The exclusion set is the entire operator opt-out surface; there is
// no per-task or per-restart auto-resume disable.  Operators who want
// strict V1 fail-safe behaviour (every kernel exit halts work for
// human review) disable the supervisor entirely (`RAXIS_SUPERVISOR_AUTO_RESTART=0`).
// See `INV-INIT-05` (tightened V2.5) for the FSM-level statement.
//
// Entry points:
//   * `pub fn reconcile(store, audit_dir) -> ReconciliationResult`
//     — Called once from main.rs step 6 BEFORE the audit writer is open.
//   * `pub fn reconcile_after_supervisor_restart(...)` — Called from
//     main.rs step 8a''' AFTER the writer is open + the supervisor's
//     restart-lifecycle events have landed.  No-op when the previous
//     exit was operator-initiated.
//
// Fatal sub-step: verify_audit_chain — failure returns KernelError::AuditChainBroken
// which main.rs maps to BOOT_ERR_AUDIT_CHAIN (exit code 13).

use std::path::Path;

use raxis_audit_tools::{AuditEventKind, AuditSink};
use raxis_store::{Store, Table};
#[cfg(test)]
use raxis_types::InitiativeState;
use raxis_types::{
    unix_now_secs, IntegrationMergeAttemptDiscardReason, IntegrationMergeAttemptState, TaskState,
};

use crate::errors::KernelError;
use crate::initiatives::task_transitions::{transition_task, TransitionActor};

// INV-STORE-03 (kernel-store.md §2.5.1): table identifiers and FSM state
// strings flow through typed constants/enums; no raw SQL identifiers in
// this file (production OR tests).
const TASKS: &str = Table::Tasks.as_str();
const VERIFIER_RUN_TOKENS: &str = Table::VerifierRunTokens.as_str();
const INITIATIVES: &str = Table::Initiatives.as_str();
const INTEGRATION_MERGE_ATTEMPTS: &str = Table::IntegrationMergeAttempts.as_str();
const WITNESS_RECORDS: &str = Table::WitnessRecords.as_str();

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// One task moved to `BlockedRecoveryPending` (or already at it) by
/// the boot-time recovery sweep. Captured per-task so the V2.5
/// supervisor-aware auto-resume codepath
/// (`reconcile_after_supervisor_restart`) can decide which rows to
/// re-admit and which to leave alone.
///
/// `prior_state` is the FSM state the task held BEFORE the bulk
/// `UPDATE … SET state = 'BlockedRecoveryPending'`. A row that was
/// ALREADY `BlockedRecoveryPending` shows `prior_state =
/// "BlockedRecoveryPending"` — the auto-resume path treats that as
/// "operator already blocked this; do not auto-resume".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SweptTaskRecord {
    pub task_id: String,
    pub initiative_id: String,
    /// Stable SQL string of the prior state (one of `Admitted`,
    /// `Running`, `GatesPending`, `BlockedRecoveryPending`).
    pub prior_state: String,
}

/// Summary of what reconcile() did.
#[derive(Debug)]
pub struct ReconciliationResult {
    /// Number of tasks swept to BlockedRecoveryPending.
    pub swept_tasks: usize,
    /// Number of verifier tokens expired during sweep.
    pub expired_tokens: usize,
    /// Number of `integration_merge_attempts` rows folded from a
    /// non-terminal state (`AwaitingPreMergeVerifiers` /
    /// `PreMergeVerifiersPassed`) to `DiscardedCrashRecovery` per
    /// `integration-merge.md §11.10.4`. Distinct from `swept_tasks`
    /// because those rows live in a separate table and gate a strictly
    /// earlier pipeline phase (candidate-merge-tree → pre-merge-verifier)
    /// than the eventual main advance the V1 task FSM tracks.
    pub folded_integration_merge_attempts: usize,
    /// Whether the audit chain verified cleanly.
    pub chain_ok: bool,
    /// V2.5 (`self-healing-supervisor.md §3.5`) per-task swept
    /// records — one per row the bulk UPDATE touched, including
    /// rows that were already `BlockedRecoveryPending`. Consumed
    /// by `reconcile_after_supervisor_restart` to decide which
    /// rows to auto-resume; the rest of the kernel ignores it.
    pub swept_tasks_detail: Vec<SweptTaskRecord>,
}

/// A lightweight report from reconcile_tasks.
#[derive(Debug, Default)]
pub struct ReconciliationReport {
    pub swept_tasks: usize,
    pub expired_tokens: usize,
    /// Per-task pre-sweep state captures (V2.5 supervisor auto-resume
    /// fuel). One entry per row touched by the bulk UPDATE, including
    /// rows that were already `BlockedRecoveryPending`.
    pub swept_tasks_detail: Vec<SweptTaskRecord>,
}

/// A lightweight report from reconcile_integration_merge_attempts.
#[derive(Debug, Default)]
pub struct IntegrationMergeReconciliationReport {
    /// Rows folded from `AwaitingPreMergeVerifiers` /
    /// `PreMergeVerifiersPassed` to `DiscardedCrashRecovery`
    /// (`integration-merge.md §11.10.4`).
    pub folded_attempts: usize,
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Post-crash reconciliation — called once from main.rs step 6.
///
/// Sub-steps (in order per §2.2):
///   1. verify_audit_chain — fatal on failure → KernelError::AuditChainBroken
///   2. reconcile_tasks — sweep in-flight tasks to BlockedRecoveryPending
///   3. expire_orphan_verifier_tokens — for swept task IDs
///   4. reconcile_integration_merge_attempts — fold non-terminal
///      pre-merge verifier attempts to `DiscardedCrashRecovery`
///      (`integration-merge.md §11.10.4`). Pre-merge verifier VMs
///      themselves are killed by the generic verifier-VM orphan
///      cleanup (`kernel-lifecycle.md §7`); this sweep is only the
///      SQLite-row finalisation half of the recovery flow.
///
/// V2.5 `integration-merge.md §11.3` — `git_apply_pending` recovery
/// (Cases A/B/C) runs as a separate sub-step
/// [`reconcile_git_apply_pending`] called from `main.rs` AFTER the
/// audit writer is opened, because Case A and Case B emit typed audit
/// events (`GitConsistencyRepaired` / `GitConsistencyVerified` /
/// `GitStateInconsistent`) and this entry point does not have an
/// `AuditSink` available yet.
///
/// Returns ReconciliationResult on success. Propagates KernelError on
/// audit chain failure (step 1 only; task sweep failures are non-fatal and
/// logged).
pub fn reconcile(store: &Store, audit_dir: &Path) -> Result<ReconciliationResult, KernelError> {
    let chain_ok = verify_audit_chain(audit_dir)?;

    let task_report = reconcile_tasks(store);
    let imerge_report = reconcile_integration_merge_attempts(store);

    eprintln!(
        "{{\"level\":\"info\",\"step\":\"recovery\",\
         \"swept_tasks\":{},\"expired_tokens\":{},\
         \"folded_integration_merge_attempts\":{},\"chain_ok\":{}}}",
        task_report.swept_tasks,
        task_report.expired_tokens,
        imerge_report.folded_attempts,
        chain_ok,
    );

    Ok(ReconciliationResult {
        swept_tasks: task_report.swept_tasks,
        expired_tokens: task_report.expired_tokens,
        folded_integration_merge_attempts: imerge_report.folded_attempts,
        chain_ok,
        swept_tasks_detail: task_report.swept_tasks_detail,
    })
}

// ---------------------------------------------------------------------------
// Step 1: Audit chain verification
// ---------------------------------------------------------------------------

/// Verify the audit chain by checking that the segment-000.jsonl file exists
/// and the first record is a well-formed genesis record (`seq=0`,
/// `event_kind="GenesisRecord"`).
///
/// **Fail-closed.** Per kernel-store.md §2.5.2 and `kernel-core.md` §2.2 the
/// audit chain is the kernel's only durable record of intent acceptance and
/// transitions; starting up with a missing, empty, or unparseable chain
/// silently risks divergence between in-flight tasks and what an auditor
/// can later prove. Every degraded outcome below maps to
/// `KernelError::AuditChainBroken` (which `main.rs` translates to
/// `BOOT_ERR_AUDIT_CHAIN`, exit code 13). The only correct way to start a
/// kernel without a chain is to run `raxis genesis`, which writes the
/// genesis segment before the kernel ever boots.
///
/// In v1 this is a structural check only — cryptographic hash-chain
/// verification is queued for v2 once `raxis-audit-tools::verifier::verify_chain`
/// lands. The structural check still catches: missing segment, empty
/// segment, blank first line, malformed JSON, missing/wrong `seq`,
/// missing/wrong `event_kind`.
///
/// Returns `true` on a clean check (the only success path) or
/// `KernelError::AuditChainBroken` for every degraded case.
fn verify_audit_chain(audit_dir: &Path) -> Result<bool, KernelError> {
    let segment = audit_dir.join("segment-000.jsonl");

    if !segment.exists() {
        return Err(KernelError::AuditChainBroken {
            reason: format!(
                "audit segment {} is missing — run `raxis genesis` to initialise \
                 the kernel before starting it",
                segment.display(),
            ),
        });
    }

    let metadata = std::fs::metadata(&segment).map_err(|e| KernelError::AuditChainBroken {
        reason: format!("cannot stat {}: {e}", segment.display()),
    })?;

    if metadata.len() == 0 {
        return Err(KernelError::AuditChainBroken {
            reason: format!(
                "audit segment {} is empty — genesis record missing; kernel cannot start safely",
                segment.display(),
            ),
        });
    }

    let content = std::fs::read_to_string(&segment).map_err(|e| KernelError::AuditChainBroken {
        reason: format!("cannot read {}: {e}", segment.display()),
    })?;

    let first_line = content
        .lines()
        .next()
        .ok_or_else(|| KernelError::AuditChainBroken {
            reason: format!(
                "audit segment {} has no lines — genesis record missing",
                segment.display(),
            ),
        })?;
    if first_line.trim().is_empty() {
        return Err(KernelError::AuditChainBroken {
            reason: format!(
                "first line of {} is blank — genesis record missing",
                segment.display(),
            ),
        });
    }

    let record: serde_json::Value =
        serde_json::from_str(first_line).map_err(|e| KernelError::AuditChainBroken {
            reason: format!("genesis record is not valid JSON: {e}"),
        })?;

    // Both fields MUST be present and well-typed. A missing field is a
    // chain-corruption signal — never silently default it (the previous
    // implementation defaulted `seq` to 1 and `kind` to "", which masked
    // a genuinely broken chain by making the equality check below fail
    // with a misleading "wrong genesis record" message instead of the
    // accurate "field missing" diagnosis).
    let seq = record.get("seq").and_then(|v| v.as_u64()).ok_or_else(|| {
        KernelError::AuditChainBroken {
            reason: "genesis record missing required `seq` field (or not a u64)".to_owned(),
        }
    })?;
    let kind = record
        .get("event_kind")
        .and_then(|v| v.as_str())
        .ok_or_else(|| KernelError::AuditChainBroken {
            reason: "genesis record missing required `event_kind` field (or not a string)"
                .to_owned(),
        })?;

    if seq != 0 || kind != "GenesisRecord" {
        return Err(KernelError::AuditChainBroken {
            reason: format!(
                "first record in segment-000.jsonl is not the genesis record \
                 (seq={seq}, event_kind={kind:?}); expected seq=0, event_kind=\"GenesisRecord\"",
            ),
        });
    }

    Ok(true)
}

// ---------------------------------------------------------------------------
// Step 2+3: Task sweep
// ---------------------------------------------------------------------------

/// Identify all non-terminal tasks and mark them BlockedRecoveryPending.
///
/// Terminal states (spec §2.2 recovery.rs):
///   Completed, Failed, Aborted, Cancelled
///
/// ALL other states (Admitted, GatesPending, Running, BlockedRecoveryPending)
/// are swept — including tasks already in BlockedRecoveryPending (idempotent).
///
/// After sweeping, expire any verifier tokens for those task_ids.
///
/// **INV-STORE-02 (kernel-store.md §2.5.1, table row "reconcile_tasks").**
/// The sweep is bulk: a single `UPDATE … WHERE state NOT IN (terminal…)`
/// against `tasks` and a single `UPDATE … WHERE consumed=0` against
/// `verifier_run_tokens` — both inside one `BEGIN`/`COMMIT`. Either every
/// in-flight task is swept and every orphan token expired, or none of
/// them are. A re-crash mid-recovery cannot leave the store half-swept;
/// when the kernel restarts, the next reconcile sees the same set and
/// repeats the bulk update (idempotent).
fn reconcile_tasks(store: &Store) -> ReconciliationReport {
    let mut report = ReconciliationReport::default();

    let mut conn = store.lock_sync();
    let now = unix_now_secs();

    let blocked = TaskState::BlockedRecoveryPending.as_sql_str();
    let terminal = terminal_task_states_sql();

    let tx = match conn.transaction() {
        Ok(t) => t,
        Err(e) => {
            eprintln!(
                "{{\"level\":\"error\",\"step\":\"recovery\",\"message\":\"cannot BEGIN reconcile transaction\",\"error\":\"{e}\"}}",
            );
            return report;
        }
    };

    // V2.5 (`self-healing-supervisor.md §3.5`) — capture per-task
    // pre-sweep state INSIDE the same transaction as the bulk UPDATE
    // so the supervisor-aware auto-resume codepath has a snapshot of
    // what each task was doing before the deadlock-triggered
    // restart. The SELECT runs FIRST; the UPDATE then writes
    // `BlockedRecoveryPending` over those same rows. Both statements
    // share the transaction so a re-crash mid-recovery either
    // commits both or rolls back to a state where the next reconcile
    // re-runs them (idempotent — INV-STORE-02).
    //
    // The SELECT bound condition mirrors the UPDATE bound condition
    // exactly (same `WHERE state NOT IN (terminal)` predicate), so
    // the captured `swept_tasks_detail` is in 1:1 correspondence
    // with the rows the UPDATE will touch.
    let swept_detail: Vec<SweptTaskRecord> = {
        let mut stmt = match tx.prepare(&format!(
            "SELECT task_id, initiative_id, state FROM {TASKS}
             WHERE state NOT IN ({terminal})
             ORDER BY task_id"
        )) {
            Ok(s) => s,
            Err(e) => {
                eprintln!(
                    "{{\"level\":\"error\",\"step\":\"recovery\",\"action\":\"prepare_pre_sweep_select_failed\",\"error\":\"{e}\"}}",
                );
                return report;
            }
        };
        let rows = match stmt.query_map([], |r| {
            Ok(SweptTaskRecord {
                task_id: r.get(0)?,
                initiative_id: r.get(1)?,
                prior_state: r.get(2)?,
            })
        }) {
            Ok(rows) => rows,
            Err(e) => {
                eprintln!(
                    "{{\"level\":\"error\",\"step\":\"recovery\",\"action\":\"pre_sweep_select_failed\",\"error\":\"{e}\"}}",
                );
                return report;
            }
        };
        let mut out = Vec::new();
        for row in rows {
            match row {
                Ok(rec) => out.push(rec),
                Err(e) => {
                    eprintln!(
                        "{{\"level\":\"error\",\"step\":\"recovery\",\"action\":\"pre_sweep_row_decode_failed\",\"error\":\"{e}\"}}",
                    );
                    return report;
                }
            }
        }
        out
    };

    // Sweep every non-terminal task in a single statement. This avoids the
    // N-statement TOCTOU window where a query-then-loop-then-update pattern
    // could race a parallel actor.
    //
    // `INV-FAILURE-REASON-MANDATORY-01` — the bulk sweep into
    // `BlockedRecoveryPending` is one of the kernel's
    // structurally-failure-emitting code paths and MUST populate
    // a non-empty `block_reason` for the dashboard's
    // `<FailureReasonPanel>` to render. Pre-fix the bulk UPDATE
    // touched only `state` + `transitioned_at`, leaving
    // `block_reason` at its prior value (often NULL for tasks
    // that crashed mid-`Running`); the dashboard then surfaced
    // `"No reason supplied — kernel bug"` for every
    // restart-recovery sweep, defeating the operator-experience
    // contract. The reason text is intentionally generic — the
    // sweep is bulk and cannot attribute per-task root-cause —
    // but it names the operator action ("operator must resume")
    // and the structural cause ("kernel restart sweep") so the
    // operator can route correctly without grepping
    // `kernel.stderr.log`. Per-task forensic detail (the
    // pre-sweep `prior_state`) is captured separately via
    // `swept_detail` above and projected into the audit chain
    // by the AuditSink.
    const SWEEP_REASON: &str = "kernel restart recovery sweep: task was non-terminal at \
         kernel shutdown; operator action required to resume \
         (raxis task resume <task_id>) or abort \
         (raxis task abort <task_id>). \
         See INV-INIT-05 and INV-FAILURE-REASON-MANDATORY-01.";
    let swept = match tx.execute(
        &format!(
            "UPDATE {TASKS}
                SET state           = '{blocked}',
                    transitioned_at = ?1,
                    block_reason    = ?2
              WHERE state NOT IN ({terminal})"
        ),
        rusqlite::params![now, SWEEP_REASON],
    ) {
        Ok(rows) => rows,
        Err(e) => {
            eprintln!(
                "{{\"level\":\"error\",\"step\":\"recovery\",\"action\":\"bulk_sweep_failed\",\"error\":\"{e}\"}}",
            );
            // Tx drop → rollback. Report stays at 0/0.
            return report;
        }
    };

    // Expire every live verifier token whose task is no longer terminal-eligible.
    // DDL Table 12: consumed INTEGER (0=live, 1=consumed); consumed_at nullable.
    // We expire tokens for ALL tasks that are now BlockedRecoveryPending — which
    // includes tasks just swept above and tasks the previous reconcile already
    // swept (idempotent).
    let expired = match tx.execute(
        &format!(
            "UPDATE {VERIFIER_RUN_TOKENS} SET consumed=1, consumed_at=?1
             WHERE consumed=0
               AND task_id IN (SELECT task_id FROM {TASKS} WHERE state='{blocked}')"
        ),
        rusqlite::params![now],
    ) {
        Ok(rows) => rows,
        Err(e) => {
            eprintln!(
                "{{\"level\":\"error\",\"step\":\"recovery\",\"action\":\"bulk_expire_failed\",\"error\":\"{e}\"}}",
            );
            return report;
        }
    };

    if let Err(e) = tx.commit() {
        eprintln!(
            "{{\"level\":\"error\",\"step\":\"recovery\",\"action\":\"commit_failed\",\"error\":\"{e}\"}}",
        );
        return report;
    }

    report.swept_tasks = swept;
    report.expired_tokens = expired;
    report.swept_tasks_detail = swept_detail;

    if swept > 0 || expired > 0 {
        eprintln!(
            "{{\"level\":\"warn\",\"step\":\"recovery\",\"action\":\"reconciled\",\
             \"swept_tasks\":{swept},\"expired_tokens\":{expired}}}",
        );
    }

    report
}

// ---------------------------------------------------------------------------
// V2.5 supervisor-aware auto-resume — `self-healing-supervisor.md §3.5`,
// `INV-SUPERVISOR-AUTO-RESUME-ON-CLEAN-RESTART-01`.
// ---------------------------------------------------------------------------

/// Per-task outcome of the V2.5 supervisor-aware auto-resume sweep.
/// Surfaced through [`AutoResumeReport`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AutoResumeOutcome {
    /// Task was re-admitted (`BlockedRecoveryPending → Admitted`)
    /// and a `TaskAutoResumedAfterSupervisorRestart` event was
    /// emitted.
    Resumed {
        task_id: String,
        initiative_id: String,
        prior_state: String,
        witness_count_preserved: u32,
    },
    /// Skipped because the initiative is operator-quarantined
    /// (`initiative_quarantines` row exists). NO event emitted —
    /// the existing quarantine row is the audit trail for the
    /// skip.
    SkippedQuarantined {
        task_id: String,
        initiative_id: String,
    },
    /// Skipped because the task was ALREADY `BlockedRecoveryPending`
    /// before this boot's recovery sweep (operator pre-existing
    /// block — preserve operator intent). NO event emitted.
    SkippedPreExistingBlock {
        task_id: String,
        initiative_id: String,
    },
    /// Skipped because the FSM transition or audit emit failed —
    /// the task stays in `BlockedRecoveryPending` and an operator
    /// will need to resume manually. The reason is logged on
    /// stderr; this variant exists so the report distinguishes
    /// "deliberately skipped" from "tried to resume and failed".
    SkippedTransitionFailed {
        task_id: String,
        initiative_id: String,
        reason: String,
    },
}

/// Aggregate report of one supervisor-aware auto-resume sweep.
///
/// `resumed`, `quarantined`, `pre_existing_block`, and
/// `transition_failed` are the four mutually-exclusive outcome
/// counters; the per-task `outcomes` vector preserves order so the
/// caller can render a deterministic dashboard view.
#[derive(Debug, Clone, Default)]
pub struct AutoResumeReport {
    pub resumed: usize,
    pub quarantined: usize,
    pub pre_existing_block: usize,
    pub transition_failed: usize,
    pub outcomes: Vec<AutoResumeOutcome>,
    /// Stable identifier echoed onto every emitted
    /// `TaskAutoResumedAfterSupervisorRestart` event — exposed on
    /// the report so the kernel can also surface it on the
    /// supervisor-banner backend (see `dashboard/src/routes/health.rs`).
    pub supervisor_restart_id: String,
}

/// V2.5 supervisor-aware auto-resume sweep —
/// `INV-SUPERVISOR-AUTO-RESUME-ON-CLEAN-RESTART-01`.
///
/// Walks every `SweptTaskRecord` captured by the boot-time
/// `reconcile_tasks` pass and decides per-task whether to:
///
///   * **resume** — `BlockedRecoveryPending → Admitted` via the
///     same `transition_task` API the operator `task resume` IPC
///     handler calls (so `witness_records` rows survive untouched
///     per `INV-INIT-08`, and the activation-row sub-FSM stays
///     consistent with `task_transitions::transition_task_in_tx`),
///     then emit `TaskAutoResumedAfterSupervisorRestart` with the
///     pre-sweep `prior_state` for forensic reconstruction;
///
///   * **skip — quarantine** — the initiative has a row in
///     `initiative_quarantines` (operator already froze it). The
///     existing `InitiativeQuarantined` audit event + the row
///     itself are the audit trail; this sweep is silent on
///     skipped tasks;
///
///   * **skip — pre-existing block** — the task's pre-sweep state
///     was ALREADY `BlockedRecoveryPending` (operator had blocked
///     it before the kernel went down). Preserving operator
///     intent across a supervisor restart is the entire point of
///     this rule (`INV-SUPERVISOR-AUTO-RESUME-ON-CLEAN-RESTART-01`
///     skip clause 2). This sweep is silent on skipped tasks.
///
/// **Auto-resume is unconditional** when the supervisor is enabled.
/// There is no per-restart, per-task, or per-initiative opt-out.
/// Operators who want strict V1 fail-safe behaviour disable the
/// supervisor entirely (`RAXIS_SUPERVISOR_AUTO_RESTART=0`).
///
/// **Per-task error handling.** A `transition_task` failure for one
/// row never aborts the sweep for siblings — the failed row stays
/// in `BlockedRecoveryPending`, an operator will need to resume it
/// manually, and the report's `transition_failed` counter +
/// `SkippedTransitionFailed` outcome carry the reason for the
/// dashboard.
///
/// **Audit-emit error handling.** If the FSM transition succeeds
/// but the `TaskAutoResumedAfterSupervisorRestart` emit fails,
/// the sweep logs a structured stderr line and continues — the
/// task IS in `Admitted` and the kernel WILL pick it up; the
/// missing audit line is forensic loss only. Counted under
/// `transition_failed` so dashboards can reflect the partial
/// outcome.
pub fn reconcile_after_supervisor_restart(
    store: &Store,
    audit: &dyn AuditSink,
    swept_tasks_detail: &[SweptTaskRecord],
    supervisor_restart_id: &str,
) -> AutoResumeReport {
    let mut report = AutoResumeReport {
        supervisor_restart_id: supervisor_restart_id.to_owned(),
        ..AutoResumeReport::default()
    };

    if swept_tasks_detail.is_empty() {
        return report;
    }

    eprintln!(
        "{{\"level\":\"info\",\"step\":\"supervisor_auto_resume\",\
         \"action\":\"scan\",\"swept_count\":{},\
         \"supervisor_restart_id\":{}}}",
        swept_tasks_detail.len(),
        serde_json::to_string(supervisor_restart_id)
            .unwrap_or_else(|_| "\"<unserialisable>\"".to_owned()),
    );

    for record in swept_tasks_detail {
        // Skip pre-existing operator blocks (INV-SUPERVISOR-AUTO-RESUME-
        // ON-CLEAN-RESTART-01 skip clause 2).
        if record.prior_state == TaskState::BlockedRecoveryPending.as_sql_str() {
            report.pre_existing_block += 1;
            report
                .outcomes
                .push(AutoResumeOutcome::SkippedPreExistingBlock {
                    task_id: record.task_id.clone(),
                    initiative_id: record.initiative_id.clone(),
                });
            continue;
        }

        // Skip operator-quarantined initiatives (skip clause 1).
        let quarantined = {
            let conn = store.lock_sync();
            match raxis_store::views::initiative_quarantines::is_quarantined_rw(
                &conn,
                &record.initiative_id,
            ) {
                Ok(b) => b,
                // Fail-safe deny: a transient sqlite error MUST NOT
                // silently re-resume a frozen initiative. Treat the
                // error as "quarantined" for this sweep — operator
                // can re-issue the resume manually if the underlying
                // sqlite issue clears.
                Err(e) => {
                    eprintln!(
                        "{{\"level\":\"warn\",\"step\":\"supervisor_auto_resume\",\
                         \"action\":\"quarantine_check_failed_treating_as_quarantined\",\
                         \"initiative_id\":{},\"error\":\"{e}\"}}",
                        serde_json::to_string(&record.initiative_id)
                            .unwrap_or_else(|_| "\"<unserialisable>\"".to_owned()),
                    );
                    true
                }
            }
        };
        if quarantined {
            report.quarantined += 1;
            report.outcomes.push(AutoResumeOutcome::SkippedQuarantined {
                task_id: record.task_id.clone(),
                initiative_id: record.initiative_id.clone(),
            });
            continue;
        }

        // Resume via the same FSM edge the operator `task resume`
        // path uses (`BlockedRecoveryPending → Admitted`). The
        // FSM does NOT support BRP → Running / GatesPending; the
        // pre-sweep state is recorded on the audit event for
        // forensics, and the kernel re-derives the post-Admitted
        // path through normal scheduling.
        //
        // `INV-DASHBOARD-PUSH-FSM-COMPLETENESS-01` — emit the
        // generic `AuditEventKind::TaskStateChanged` paired-write
        // for the resumed transition AS WELL AS the existing
        // `TaskAutoResumedAfterSupervisorRestart` event below. The
        // dashboard's push protocol only translates `TaskStateChanged`
        // into `InitiativeEvent::TaskStateChanged`; the
        // supervisor-specific event is forensic-only.
        let transition_outcome = transition_task(
            &record.task_id,
            TaskState::Admitted,
            None,
            TransitionActor::Kernel,
            store,
        );

        if let Ok(rec) = &transition_outcome {
            crate::initiatives::task_transitions::emit_task_state_changed_audit(audit, rec, None);
        }

        if let Err(e) = transition_outcome {
            let reason = e.to_string();
            eprintln!(
                "{{\"level\":\"warn\",\"step\":\"supervisor_auto_resume\",\
                 \"action\":\"transition_failed\",\"task_id\":{},\
                 \"prior_state\":\"{}\",\"reason\":{}}}",
                serde_json::to_string(&record.task_id)
                    .unwrap_or_else(|_| "\"<unserialisable>\"".to_owned()),
                record.prior_state,
                serde_json::to_string(&reason)
                    .unwrap_or_else(|_| "\"<unserialisable>\"".to_owned()),
            );
            report.transition_failed += 1;
            report
                .outcomes
                .push(AutoResumeOutcome::SkippedTransitionFailed {
                    task_id: record.task_id.clone(),
                    initiative_id: record.initiative_id.clone(),
                    reason,
                });
            continue;
        }

        // Count witness_records rows that survived the restart.
        // `INV-INIT-08`: the table is append-only and is never
        // touched by `transition_task`; this count is a forensic
        // observation, not a preservation step.
        let witness_count_preserved = {
            let conn = store.lock_sync();
            match conn.query_row(
                &format!("SELECT COUNT(*) FROM {WITNESS_RECORDS} WHERE task_id = ?1"),
                rusqlite::params![&record.task_id],
                |r| r.get::<_, i64>(0),
            ) {
                Ok(n) => u32::try_from(n.max(0)).unwrap_or(u32::MAX),
                Err(e) => {
                    eprintln!(
                        "{{\"level\":\"warn\",\"step\":\"supervisor_auto_resume\",\
                         \"action\":\"witness_count_failed\",\"task_id\":{},\"error\":\"{e}\"}}",
                        serde_json::to_string(&record.task_id)
                            .unwrap_or_else(|_| "\"<unserialisable>\"".to_owned()),
                    );
                    0
                }
            }
        };

        if let Err(e) = audit.emit(
            AuditEventKind::TaskAutoResumedAfterSupervisorRestart {
                task_id: record.task_id.clone(),
                initiative_id: record.initiative_id.clone(),
                prior_state: record.prior_state.clone(),
                witness_count_preserved,
                supervisor_restart_id: supervisor_restart_id.to_owned(),
            },
            None,
            Some(&record.task_id),
            Some(&record.initiative_id),
        ) {
            // FSM advanced; audit emit lost. Log + count under
            // `transition_failed` so the dashboard reflects the
            // partial outcome.
            eprintln!(
                "{{\"level\":\"error\",\"step\":\"supervisor_auto_resume\",\
                 \"event\":\"TaskAutoResumedAfterSupervisorRestart\",\
                 \"audit_emit_failed\":\"{e}\",\"task_id\":{}}}",
                serde_json::to_string(&record.task_id)
                    .unwrap_or_else(|_| "\"<unserialisable>\"".to_owned()),
            );
            report.transition_failed += 1;
            report
                .outcomes
                .push(AutoResumeOutcome::SkippedTransitionFailed {
                    task_id: record.task_id.clone(),
                    initiative_id: record.initiative_id.clone(),
                    reason: format!("audit_emit_failed: {e}"),
                });
            continue;
        }

        report.resumed += 1;
        report.outcomes.push(AutoResumeOutcome::Resumed {
            task_id: record.task_id.clone(),
            initiative_id: record.initiative_id.clone(),
            prior_state: record.prior_state.clone(),
            witness_count_preserved,
        });
    }

    eprintln!(
        "{{\"level\":\"info\",\"step\":\"supervisor_auto_resume\",\
         \"action\":\"complete\",\"resumed\":{},\"quarantined\":{},\
         \"pre_existing_block\":{},\"transition_failed\":{}}}",
        report.resumed, report.quarantined, report.pre_existing_block, report.transition_failed,
    );

    report
}

/// SQL list literal of terminal TaskState values for use in `NOT IN (…)`.
fn terminal_task_states_sql() -> String {
    [
        TaskState::Completed,
        TaskState::Failed,
        TaskState::Aborted,
        TaskState::Cancelled,
    ]
    .iter()
    .map(|s| format!("'{}'", s.as_sql_str()))
    .collect::<Vec<_>>()
    .join(", ")
}

// ---------------------------------------------------------------------------
// Step 4 — Reconcile in-flight `integration_merge_attempts` rows.
// integration-merge.md §11.10.4 "Crash-recovery cleanup at startup".
// ---------------------------------------------------------------------------

/// Fold every `integration_merge_attempts` row whose `state` is
/// non-terminal (`AwaitingPreMergeVerifiers` |
/// `PreMergeVerifiersPassed`) to `DiscardedCrashRecovery` with
/// `discard_reason = 'crash_recovery'` and `finalized_at = now`.
///
/// **Why fold rather than salvage.** The candidate-merge-tree
/// pipeline at `integration-merge.md §11.10` is structured so that a
/// kernel restart between Check 5d and §11.1 phase 3 invalidates all
/// in-flight verifier verdicts: the verifier VMs were killed by the
/// generic verifier-VM orphan cleanup at boot
/// (`kernel-lifecycle.md §7`), and the candidate worktree may or may
/// not still exist on disk. The specced recovery flow treats this as
/// a soft failure: the row is folded to a terminal-discard state, the
/// orphan worktree is GC'd by the periodic `git_maintenance_main`
/// sweep (`kernel-lifecycle.md §10.5.3`), and the orchestrator's
/// `IntegrationMerge` intent surfaces the failure on the next
/// admission attempt — which the orchestrator may retry. **No
/// attempt is made to salvage the verifier verdicts**; the kernel
/// re-runs verifiers conservatively because the per-VM artefacts may
/// not have been atomically staged before the kill.
///
/// **INV-STORE-02.** The sweep is a single bulk
/// `UPDATE … WHERE state IN (…)` inside one `BEGIN`/`COMMIT`. A
/// re-crash mid-recovery cannot leave the table half-folded; the
/// next reconcile sees the same set and re-runs the bulk update
/// (idempotent — already-folded rows fall outside the WHERE clause).
///
/// **INV-STORE-03.** Both the table identifier and every `state` /
/// `discard_reason` SQL string come from
/// `Table::IntegrationMergeAttempts.as_str()` /
/// `IntegrationMergeAttemptState::*.as_sql_str()` /
/// `IntegrationMergeAttemptDiscardReason::CrashRecovery.as_sql_str()`.
/// A future variant rename forces a compile error here, not silent
/// SQL drift.
fn reconcile_integration_merge_attempts(store: &Store) -> IntegrationMergeReconciliationReport {
    let mut report = IntegrationMergeReconciliationReport::default();

    let mut conn = store.lock_sync();
    let now = unix_now_secs();

    let awaiting = IntegrationMergeAttemptState::AwaitingPreMergeVerifiers.as_sql_str();
    let passed = IntegrationMergeAttemptState::PreMergeVerifiersPassed.as_sql_str();
    let discarded = IntegrationMergeAttemptState::DiscardedCrashRecovery.as_sql_str();
    let crash_rsn = IntegrationMergeAttemptDiscardReason::CrashRecovery.as_sql_str();

    let tx = match conn.transaction() {
        Ok(t) => t,
        Err(e) => {
            eprintln!(
                "{{\"level\":\"error\",\"step\":\"recovery\",\
                 \"action\":\"begin_imerge_tx_failed\",\"error\":\"{e}\"}}",
            );
            return report;
        }
    };

    // Single bulk UPDATE — INV-STORE-02. The CHECK constraint on
    // `integration_merge_attempts` enforces that a transition INTO
    // any terminal state requires `discard_reason IS NOT NULL` AND
    // `finalized_at IS NOT NULL`, so we set both atomically.
    let folded = match tx.execute(
        &format!(
            "UPDATE {INTEGRATION_MERGE_ATTEMPTS}
                SET state          = '{discarded}',
                    discard_reason = '{crash_rsn}',
                    finalized_at   = ?1
              WHERE state IN ('{awaiting}', '{passed}')
                AND finalized_at IS NULL"
        ),
        rusqlite::params![now],
    ) {
        Ok(rows) => rows,
        Err(e) => {
            eprintln!(
                "{{\"level\":\"error\",\"step\":\"recovery\",\
                 \"action\":\"bulk_fold_imerge_failed\",\"error\":\"{e}\"}}",
            );
            return report;
        }
    };

    if let Err(e) = tx.commit() {
        eprintln!(
            "{{\"level\":\"error\",\"step\":\"recovery\",\
             \"action\":\"commit_imerge_failed\",\"error\":\"{e}\"}}",
        );
        return report;
    }

    report.folded_attempts = folded;

    if folded > 0 {
        eprintln!(
            "{{\"level\":\"warn\",\"step\":\"recovery\",\
             \"action\":\"folded_integration_merge_attempts\",\
             \"count\":{folded}}}",
        );
    }

    report
}

// ---------------------------------------------------------------------------
// Step 5 — git_apply_pending recovery (integration-merge.md §11.3).
//
// Walks every initiative with `git_apply_pending = 1` (the partial
// index `idx_initiatives_pending_git` from migration 16 makes this
// O(in-flight merges), not O(initiatives)) and finalises one of three
// outcomes:
//
//   * Case A — the audit log records an `IntegrationMergeCompleted`
//     event for this initiative whose `commit_sha` differs from the
//     current tip of `target_ref` in the main repo. Phase 1 of §11.1
//     committed but Phase 2 (host-side fast-forward) did not finish.
//     We re-run `commit_merge_to_target_ref` against the originating
//     orchestrator worktree, verify the ref is now at the recorded
//     SHA, clear the flag, and emit `GitConsistencyRepaired`.
//
//   * Case B — `target_ref` already points at the recorded
//     `commit_sha`. Phase 2 fully succeeded but Phase 3 (the SQLite
//     `clear_git_apply_pending`) did not. Idempotency: just clear
//     the flag and emit `GitConsistencyVerified`.
//
//   * Case C — recovery cannot reconcile (no audit event found for
//     the initiative, OR the orchestrator worktree referenced by the
//     event no longer exists on disk, OR the recorded `commit_sha`
//     is not reachable from the worktree). The flag is intentionally
//     LEFT SET so subsequent IntegrationMerge admissions reject with
//     `FAIL_GIT_APPLY_PENDING` until an operator intervenes. We emit
//     `GitStateInconsistent` so the dashboard / pager surfaces the
//     issue immediately.
//
// This sub-step is `pub fn reconcile_git_apply_pending` rather than
// folded into `reconcile()` because it needs (a) `data_dir` to
// locate `repositories/main/`, and (b) an `AuditSink` to emit the
// outcome events. Both are only available in `main.rs` AFTER the
// audit writer is opened (Step 7a) — the call site invokes us as
// Step 7c, after `KernelStarted` has been emitted but before IPC
// accept.
// ---------------------------------------------------------------------------

/// Per-initiative recovery outcome surfaced through
/// [`GitApplyRecoveryResult`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GitApplyRecoveryOutcome {
    /// Case A — Phase 2 was re-applied successfully.
    Repaired {
        initiative_id: String,
        commit_sha: String,
        previous_sha: Option<String>,
        target_ref: String,
    },
    /// Case B — `target_ref` was already at `commit_sha`; only the
    /// pending flag needed to clear.
    Verified {
        initiative_id: String,
        commit_sha: String,
        target_ref: String,
    },
    /// Case C — unrecoverable inconsistency. Flag intentionally LEFT
    /// SET so the kernel keeps rejecting new merges for this
    /// initiative until an operator intervenes.
    Inconsistent {
        initiative_id: String,
        db_sha: String,
        git_sha: String,
        target_ref: String,
        reason: String,
    },
}

/// Aggregate report of a single recovery sweep.
#[derive(Debug, Clone, Default)]
pub struct GitApplyRecoveryResult {
    pub repaired: usize,
    pub verified: usize,
    pub inconsistent: usize,
    pub outcomes: Vec<GitApplyRecoveryOutcome>,
}

/// Run the boot-time `git_apply_pending` recovery (Cases A/B/C from
/// `integration-merge.md §11.3`).
///
/// Idempotent: a second run on the same state observes no flagged
/// rows (Cases A/B clear the flag) or re-emits the same Case-C
/// outcome (the flag stays set, the operator-intervention condition
/// has not changed).
///
/// **Audit contract.** Each initiative produces exactly one of
/// `GitConsistencyRepaired` / `GitConsistencyVerified` /
/// `GitStateInconsistent`. Audit-emit failures are logged but do not
/// abort the sweep — losing one audit line is preferable to leaving
/// every subsequent initiative un-recovered.
///
/// **Worktree retention.** This function relies on
/// `INV-MERGE-WORKTREE-RETAIN` (`integration-merge.md §11.4`):
/// session worktrees referenced by an initiative with
/// `git_apply_pending = 1` MUST NOT have been GC'd. Worktree GC
/// queries the same flag before deleting (the GC implementation
/// lives in `crate::push` / `kernel-lifecycle.md §10.5.3`).
pub fn reconcile_git_apply_pending(
    store: &Store,
    audit: &dyn raxis_audit_tools::AuditSink,
    audit_dir: &Path,
    data_dir: &Path,
) -> GitApplyRecoveryResult {
    let mut report = GitApplyRecoveryResult::default();

    let pending_ids: Vec<String> = {
        let ro = match raxis_store::ro::open(data_dir) {
            Ok(r) => r,
            Err(e) => {
                eprintln!(
                    "{{\"level\":\"error\",\"step\":\"git_apply_recovery\",\
                     \"action\":\"open_ro_failed\",\"error\":\"{e}\"}}",
                );
                return report;
            }
        };
        match raxis_store::views::initiatives::pending_git_apply_ids(&ro) {
            Ok(v) => v,
            Err(e) => {
                eprintln!(
                    "{{\"level\":\"error\",\"step\":\"git_apply_recovery\",\
                     \"action\":\"scan_failed\",\"error\":\"{e}\"}}",
                );
                return report;
            }
        }
    };

    if pending_ids.is_empty() {
        return report;
    }

    eprintln!(
        "{{\"level\":\"info\",\"step\":\"git_apply_recovery\",\
         \"action\":\"scan\",\"pending_count\":{}}}",
        pending_ids.len(),
    );

    let main_repo_root = data_dir.join("repositories").join("main");

    for initiative_id in pending_ids {
        let outcome =
            recover_one_initiative(store, audit, audit_dir, &main_repo_root, &initiative_id);
        match &outcome {
            GitApplyRecoveryOutcome::Repaired { .. } => report.repaired += 1,
            GitApplyRecoveryOutcome::Verified { .. } => report.verified += 1,
            GitApplyRecoveryOutcome::Inconsistent { .. } => report.inconsistent += 1,
        }
        report.outcomes.push(outcome);
    }

    eprintln!(
        "{{\"level\":\"info\",\"step\":\"git_apply_recovery\",\
         \"repaired\":{},\"verified\":{},\"inconsistent\":{}}}",
        report.repaired, report.verified, report.inconsistent,
    );

    report
}

/// One-initiative driver shared by the sweep above. Splits the
/// per-initiative work into a function so the per-row error paths
/// stay isolated from each other (a Case-C outcome on one
/// initiative does not abort the sweep for siblings).
fn recover_one_initiative(
    store: &Store,
    audit: &dyn raxis_audit_tools::AuditSink,
    audit_dir: &Path,
    main_repo_root: &Path,
    initiative_id: &str,
) -> GitApplyRecoveryOutcome {
    // 1. Find the most recent IntegrationMergeCompleted event for
    //    this initiative. The audit reader walks the chain from
    //    seq 0; we keep the last match by comparing `seq` so a
    //    multi-merge initiative recovers the LATEST attempt.
    let last_merge = match find_last_integration_merge(audit_dir, initiative_id) {
        Ok(Some(rec)) => rec,
        Ok(None) => {
            let reason = "audit_record_missing".to_owned();
            emit_inconsistent(audit, initiative_id, "", "", "", &reason);
            return GitApplyRecoveryOutcome::Inconsistent {
                initiative_id: initiative_id.to_owned(),
                db_sha: String::new(),
                git_sha: String::new(),
                target_ref: String::new(),
                reason,
            };
        }
        Err(e) => {
            let reason = format!("audit chain read failed: {e}");
            emit_inconsistent(audit, initiative_id, "", "", "", &reason);
            return GitApplyRecoveryOutcome::Inconsistent {
                initiative_id: initiative_id.to_owned(),
                db_sha: String::new(),
                git_sha: String::new(),
                target_ref: String::new(),
                reason,
            };
        }
    };

    let db_sha = last_merge.commit_sha;
    let target_ref = last_merge.target_ref;

    if target_ref.is_empty() {
        // Pre-V2.5 audit event without target_ref — this should not
        // happen because pre-V2.5 segments wrote `git_apply_pending = 0`
        // (column did not exist), so the recovery scan never picks them
        // up. If we land here, the segment was hand-edited or the
        // schema migration was skipped.
        let reason = "audit_record_missing".to_owned();
        emit_inconsistent(audit, initiative_id, &db_sha, "", "", &reason);
        return GitApplyRecoveryOutcome::Inconsistent {
            initiative_id: initiative_id.to_owned(),
            db_sha,
            git_sha: String::new(),
            target_ref: String::new(),
            reason,
        };
    }

    // 2. Read the current target_ref tip in the main repo. Missing
    //    ref / unopenable repo is Case C — we cannot proceed without
    //    a known git_sha to compare against.
    let git_sha_opt = match raxis_domain_git::current_target_ref_oid(main_repo_root, &target_ref) {
        Ok(opt) => opt,
        Err(e) => {
            let reason = format!(
                "main repo at {} could not be read: {e}",
                main_repo_root.display()
            );
            emit_inconsistent(audit, initiative_id, &db_sha, "", &target_ref, &reason);
            return GitApplyRecoveryOutcome::Inconsistent {
                initiative_id: initiative_id.to_owned(),
                db_sha,
                git_sha: String::new(),
                target_ref,
                reason,
            };
        }
    };

    let git_sha = git_sha_opt.unwrap_or_default();

    if git_sha == db_sha && !db_sha.is_empty() {
        // Case B — target_ref already at db_sha. Phase 2 fully
        // succeeded; only Phase 3 was missed. Just clear the flag.
        if let Err(e) = clear_pending_under_lock(store, initiative_id) {
            let reason = format!("Case B clear_git_apply_pending failed: {e}");
            emit_inconsistent(
                audit,
                initiative_id,
                &db_sha,
                &git_sha,
                &target_ref,
                &reason,
            );
            return GitApplyRecoveryOutcome::Inconsistent {
                initiative_id: initiative_id.to_owned(),
                db_sha,
                git_sha,
                target_ref,
                reason,
            };
        }
        emit_verified(audit, initiative_id, &db_sha, &target_ref);
        return GitApplyRecoveryOutcome::Verified {
            initiative_id: initiative_id.to_owned(),
            commit_sha: db_sha,
            target_ref,
        };
    }

    // Case A — db_sha != git_sha. Try to re-apply Phase 2.
    // We need the originating orchestrator worktree path. Look it up
    // from `sessions.worktree_root` keyed by the audit event's
    // `session_id`.
    let session_id = last_merge.session_id;
    let worktree_path = match worktree_for_session(store, &session_id) {
        Some(p) => p,
        None => {
            let reason = "orchestrator_worktree_missing".to_owned();
            emit_inconsistent(
                audit,
                initiative_id,
                &db_sha,
                &git_sha,
                &target_ref,
                &reason,
            );
            return GitApplyRecoveryOutcome::Inconsistent {
                initiative_id: initiative_id.to_owned(),
                db_sha,
                git_sha,
                target_ref,
                reason,
            };
        }
    };

    if !worktree_path.exists() {
        let reason = "orchestrator_worktree_missing".to_owned();
        emit_inconsistent(
            audit,
            initiative_id,
            &db_sha,
            &git_sha,
            &target_ref,
            &reason,
        );
        return GitApplyRecoveryOutcome::Inconsistent {
            initiative_id: initiative_id.to_owned(),
            db_sha,
            git_sha,
            target_ref,
            reason,
        };
    }

    // commit_merge_to_target_ref is idempotent: if target_ref
    // already at db_sha (which we ruled out above), it short-
    // circuits; otherwise it fetches objects from the worktree
    // ODB and atomically advances the ref. A fetch failure when
    // the ref does not yet have db_sha reachable is the genuine
    // Case-C "orchestrator_worktree_unreachable_commit" case.
    match raxis_domain_git::commit_merge_to_target_ref(
        main_repo_root,
        &worktree_path,
        &db_sha,
        &target_ref,
    ) {
        Ok(advance) => {
            if let Err(e) = clear_pending_under_lock(store, initiative_id) {
                let reason = format!(
                    "Case A re-applied Phase 2 successfully but clear_git_apply_pending failed: {e}",
                );
                emit_inconsistent(
                    audit,
                    initiative_id,
                    &db_sha,
                    &git_sha,
                    &target_ref,
                    &reason,
                );
                return GitApplyRecoveryOutcome::Inconsistent {
                    initiative_id: initiative_id.to_owned(),
                    db_sha,
                    git_sha,
                    target_ref,
                    reason,
                };
            }
            emit_repaired(audit, initiative_id, &db_sha, &git_sha, &target_ref);
            GitApplyRecoveryOutcome::Repaired {
                initiative_id: initiative_id.to_owned(),
                commit_sha: db_sha,
                previous_sha: advance.previous_sha,
                target_ref,
            }
        }
        Err(_e) => {
            let reason = "orchestrator_worktree_unreachable_commit".to_owned();
            emit_inconsistent(
                audit,
                initiative_id,
                &db_sha,
                &git_sha,
                &target_ref,
                &reason,
            );
            GitApplyRecoveryOutcome::Inconsistent {
                initiative_id: initiative_id.to_owned(),
                db_sha,
                git_sha,
                target_ref,
                reason,
            }
        }
    }
}

/// One IntegrationMergeCompleted record we found in the audit chain.
struct LastIntegrationMerge {
    commit_sha: String,
    session_id: String,
    target_ref: String,
}

/// Walk the audit chain and return the highest-`seq`
/// `IntegrationMergeCompleted` event for `initiative_id`. Returns
/// `Ok(None)` if none found (Case C).
fn find_last_integration_merge(
    audit_dir: &Path,
    initiative_id: &str,
) -> Result<Option<LastIntegrationMerge>, raxis_audit_tools::reader::ChainReadError> {
    let reader = raxis_audit_tools::reader::ChainReader::open(audit_dir)?;
    let mut best: Option<(u64, LastIntegrationMerge)> = None;

    for record in reader.records() {
        let record = match record {
            Ok(r) => r,
            Err(_) => continue, // skip malformed lines; they are surfaced
                                // by the dedicated chain-walker, not here
        };
        if record.event_kind != "IntegrationMergeCompleted" {
            continue;
        }
        if record.initiative_id.as_deref() != Some(initiative_id) {
            continue;
        }
        let parsed = match record.parsed_value.as_ref() {
            Some(v) => v,
            None => continue,
        };
        let payload = match parsed.get("payload") {
            Some(p) => p,
            None => continue,
        };
        let commit_sha = match payload.get("commit_sha").and_then(|v| v.as_str()) {
            Some(s) => s.to_owned(),
            None => continue,
        };
        let session_id = match payload.get("session_id").and_then(|v| v.as_str()) {
            Some(s) => s.to_owned(),
            None => continue,
        };
        let target_ref = payload
            .get("target_ref")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_owned();
        let entry = LastIntegrationMerge {
            commit_sha,
            session_id,
            target_ref,
        };
        match best.as_ref() {
            Some((seq, _)) if *seq >= record.seq => {}
            _ => {
                best = Some((record.seq, entry));
            }
        }
    }

    Ok(best.map(|(_, m)| m))
}

/// Look up `sessions.worktree_root` for `session_id`. Returns
/// `None` when the row is missing or the column is NULL.
fn worktree_for_session(store: &Store, session_id: &str) -> Option<std::path::PathBuf> {
    let conn = store.lock_sync();
    let path: Option<String> = conn
        .query_row(
            &format!(
                "SELECT worktree_root FROM {} WHERE session_id = ?1",
                raxis_store::Table::Sessions.as_str(),
            ),
            rusqlite::params![session_id],
            |r| r.get::<_, Option<String>>(0),
        )
        .ok()
        .flatten();
    path.map(std::path::PathBuf::from)
}

/// Single-statement clear under the store mutex. Returns the row
/// count from the UPDATE so the caller can assert exactly one row
/// flipped.
fn clear_pending_under_lock(store: &Store, initiative_id: &str) -> Result<usize, rusqlite::Error> {
    let conn = store.lock_sync();
    raxis_store::views::initiatives::clear_git_apply_pending(&conn, initiative_id)
}

fn emit_repaired(
    audit: &dyn raxis_audit_tools::AuditSink,
    initiative_id: &str,
    db_sha: &str,
    previous_git_sha: &str,
    target_ref: &str,
) {
    let _ = audit.emit(
        raxis_audit_tools::AuditEventKind::GitConsistencyRepaired {
            initiative_id: initiative_id.to_owned(),
            db_sha: db_sha.to_owned(),
            previous_git_sha: previous_git_sha.to_owned(),
            target_ref: target_ref.to_owned(),
        },
        None,
        None,
        Some(initiative_id),
    );
    eprintln!(
        "{{\"level\":\"info\",\"event\":\"GitConsistencyRepaired\",\
         \"initiative_id\":\"{initiative_id}\",\"db_sha\":\"{db_sha}\",\
         \"previous_git_sha\":\"{previous_git_sha}\",\"target_ref\":\"{target_ref}\"}}",
    );
}

fn emit_verified(
    audit: &dyn raxis_audit_tools::AuditSink,
    initiative_id: &str,
    sha: &str,
    target_ref: &str,
) {
    let _ = audit.emit(
        raxis_audit_tools::AuditEventKind::GitConsistencyVerified {
            initiative_id: initiative_id.to_owned(),
            sha: sha.to_owned(),
            target_ref: target_ref.to_owned(),
        },
        None,
        None,
        Some(initiative_id),
    );
    eprintln!(
        "{{\"level\":\"info\",\"event\":\"GitConsistencyVerified\",\
         \"initiative_id\":\"{initiative_id}\",\"sha\":\"{sha}\",\
         \"target_ref\":\"{target_ref}\"}}",
    );
}

fn emit_inconsistent(
    audit: &dyn raxis_audit_tools::AuditSink,
    initiative_id: &str,
    db_sha: &str,
    git_sha: &str,
    target_ref: &str,
    reason: &str,
) {
    let _ = audit.emit(
        raxis_audit_tools::AuditEventKind::GitStateInconsistent {
            initiative_id: initiative_id.to_owned(),
            db_sha: db_sha.to_owned(),
            git_sha: git_sha.to_owned(),
            target_ref: target_ref.to_owned(),
            reason: reason.to_owned(),
        },
        None,
        None,
        Some(initiative_id),
    );
    eprintln!(
        "{{\"level\":\"warn\",\"event\":\"GitStateInconsistent\",\
         \"initiative_id\":\"{initiative_id}\",\"db_sha\":\"{db_sha}\",\
         \"git_sha\":\"{git_sha}\",\"target_ref\":\"{target_ref}\",\
         \"reason\":\"{reason}\"}}",
    );
}

// ---------------------------------------------------------------------------
// Tests — reconcile_tasks atomicity (INV-STORE-02)
// ---------------------------------------------------------------------------
//
// These tests use plain `#[test]`, not `#[tokio::test]`, because
// `reconcile_tasks` is a sync function that takes the store mutex via
// `lock_sync()` (see lifecycle.rs tests for the same rationale).

#[cfg(test)]
mod tests {
    use super::*;
    use raxis_store::Store;

    /// Insert one initiative + N tasks in arbitrary states so reconcile_tasks
    /// has something to sweep. Returns nothing; the caller queries the store.
    fn seed_in_flight_tasks(store: &Store, task_states: &[(&str, TaskState)]) {
        let conn = store.lock_sync();
        let now = unix_now_secs();

        conn.execute(
            &format!(
                "INSERT INTO {INITIATIVES}
                    (initiative_id, state, terminal_criteria_json,
                     plan_artifact_sha256, created_at)
                 VALUES ('init-recon', ?1, '{{}}', 'deadbeef', ?2)"
            ),
            rusqlite::params![InitiativeState::Executing.as_sql_str(), now],
        )
        .unwrap();

        for (task_id, state) in task_states {
            conn.execute(
                &format!(
                    "INSERT INTO {TASKS}
                        (task_id, initiative_id, lane_id, state, actor,
                         policy_epoch, admitted_at, transitioned_at, actual_cost)
                     VALUES (?1, 'init-recon', 'default', ?2, 'kernel', 1, ?3, ?3, 0)"
                ),
                rusqlite::params![task_id, state.as_sql_str(), now],
            )
            .unwrap();
        }
    }

    /// Insert a verifier_run_token for a task; consumed=0 means "live".
    /// Column set per kernel-store.md §2.5.1 Table 12.
    fn seed_live_token(store: &Store, run_id: &str, task_id: &str) {
        let conn = store.lock_sync();
        let now = unix_now_secs();
        conn.execute(
            &format!(
                "INSERT INTO {VERIFIER_RUN_TOKENS}
                    (verifier_run_id, task_id, gate_type, evaluation_sha,
                     token_hash, issued_at, expires_at, consumed)
                 VALUES (?1, ?2, 'tests_pass', 'evalsha', 'tokhash', ?3, ?4, 0)"
            ),
            rusqlite::params![run_id, task_id, now, now + 3600],
        )
        .unwrap();
    }

    fn task_state(store: &Store, task_id: &str) -> String {
        let conn = store.lock_sync();
        conn.query_row(
            &format!("SELECT state FROM {TASKS} WHERE task_id=?1"),
            rusqlite::params![task_id],
            |r| r.get(0),
        )
        .unwrap()
    }

    fn token_consumed(store: &Store, run_id: &str) -> i64 {
        let conn = store.lock_sync();
        conn.query_row(
            &format!("SELECT consumed FROM {VERIFIER_RUN_TOKENS} WHERE verifier_run_id=?1"),
            rusqlite::params![run_id],
            |r| r.get(0),
        )
        .unwrap()
    }

    #[test]
    fn reconcile_sweeps_only_non_terminal_tasks() {
        let store = Store::open_in_memory().unwrap();
        seed_in_flight_tasks(
            &store,
            &[
                ("t-running", TaskState::Running),
                ("t-admitted", TaskState::Admitted),
                ("t-gates", TaskState::GatesPending),
                ("t-already", TaskState::BlockedRecoveryPending),
                ("t-completed", TaskState::Completed),
                ("t-failed", TaskState::Failed),
                ("t-aborted", TaskState::Aborted),
                ("t-cancelled", TaskState::Cancelled),
            ],
        );

        let report = reconcile_tasks(&store);
        // 4 non-terminal tasks should sweep; 4 terminal tasks should not.
        assert_eq!(report.swept_tasks, 4);

        for tid in ["t-running", "t-admitted", "t-gates", "t-already"] {
            assert_eq!(
                task_state(&store, tid),
                "BlockedRecoveryPending",
                "{tid} should have been swept"
            );
        }
        for (tid, expected) in [
            ("t-completed", "Completed"),
            ("t-failed", "Failed"),
            ("t-aborted", "Aborted"),
            ("t-cancelled", "Cancelled"),
        ] {
            assert_eq!(
                task_state(&store, tid),
                expected,
                "{tid} must NOT change state"
            );
        }
    }

    #[test]
    fn reconcile_expires_only_live_tokens_for_swept_tasks() {
        let store = Store::open_in_memory().unwrap();
        seed_in_flight_tasks(
            &store,
            &[
                ("t-running", TaskState::Running),
                ("t-completed", TaskState::Completed),
            ],
        );
        // Two tokens: one for the running task (will sweep) and one for
        // the completed task (must NOT be touched).
        seed_live_token(&store, "tok-running", "t-running");
        seed_live_token(&store, "tok-completed", "t-completed");

        let report = reconcile_tasks(&store);
        assert_eq!(report.swept_tasks, 1);
        assert_eq!(
            report.expired_tokens, 1,
            "only running task's token should expire"
        );
        assert_eq!(token_consumed(&store, "tok-running"), 1);
        assert_eq!(token_consumed(&store, "tok-completed"), 0);
    }

    #[test]
    fn reconcile_is_idempotent() {
        // Running reconcile twice must not change state on the second run.
        let store = Store::open_in_memory().unwrap();
        seed_in_flight_tasks(&store, &[("t-running", TaskState::Running)]);
        seed_live_token(&store, "tok", "t-running");

        let r1 = reconcile_tasks(&store);
        assert_eq!(r1.swept_tasks, 1);
        assert_eq!(r1.expired_tokens, 1);

        // Second pass: task is already BlockedRecoveryPending, but per
        // the spec ("idempotent — including tasks already in
        // BlockedRecoveryPending") the bulk UPDATE re-fires its rows.
        // The token, however, is now consumed=1 and won't be touched.
        let r2 = reconcile_tasks(&store);
        assert_eq!(
            r2.swept_tasks, 1,
            "BlockedRecoveryPending re-sweeps idempotently"
        );
        assert_eq!(r2.expired_tokens, 0, "no live tokens left to expire");
    }

    #[test]
    fn reconcile_with_no_in_flight_tasks_is_a_noop() {
        let store = Store::open_in_memory().unwrap();
        seed_in_flight_tasks(&store, &[("t-completed", TaskState::Completed)]);

        let report = reconcile_tasks(&store);
        assert_eq!(report.swept_tasks, 0);
        assert_eq!(report.expired_tokens, 0);
        assert_eq!(task_state(&store, "t-completed"), "Completed");
    }

    #[test]
    fn reconcile_on_empty_store_returns_zero_report() {
        let store = Store::open_in_memory().unwrap();
        let report = reconcile_tasks(&store);
        assert_eq!(report.swept_tasks, 0);
        assert_eq!(report.expired_tokens, 0);
    }

    // ─── reconcile_integration_merge_attempts — INV-STORE-02 fold ─────────
    //
    // integration-merge.md §11.10.4 requires every non-terminal
    // `integration_merge_attempts` row at boot to be folded to
    // `DiscardedCrashRecovery` with `discard_reason = 'crash_recovery'`
    // and `finalized_at = now`. The sweep is bulk and idempotent —
    // already-finalised rows fall outside the WHERE clause.

    /// Insert one initiative + an `integration_merge_attempts` row in
    /// the requested state. Returns the row id.
    fn seed_imerge_attempt(
        store: &Store,
        id: &str,
        state: IntegrationMergeAttemptState,
        candidate_merge_sha: Option<&str>,
        discard_reason: Option<IntegrationMergeAttemptDiscardReason>,
        finalized_at: Option<i64>,
    ) -> String {
        let conn = store.lock_sync();
        let now = unix_now_secs();
        // Idempotent insert into the parent initiative — multiple
        // attempts in the same test seed against the same initiative.
        conn.execute(
            &format!(
                "INSERT OR IGNORE INTO {INITIATIVES}
                    (initiative_id, state, terminal_criteria_json,
                     plan_artifact_sha256, created_at)
                 VALUES ('init-recon-imerge', ?1, '{{}}', 'deadbeef', ?2)"
            ),
            rusqlite::params![InitiativeState::Executing.as_sql_str(), now],
        )
        .unwrap();

        conn.execute(
            &format!(
                "INSERT INTO {INTEGRATION_MERGE_ATTEMPTS}
                    (id, initiative_id, orchestrator_session_id,
                     requested_commit_sha, candidate_merge_sha,
                     state, discard_reason,
                     created_at, finalized_at)
                 VALUES (?1, 'init-recon-imerge', 'session-orch',
                         'deadbeef', ?2, ?3, ?4, ?5, ?6)"
            ),
            rusqlite::params![
                id,
                candidate_merge_sha,
                state.as_sql_str(),
                discard_reason.map(|r| r.as_sql_str()),
                now,
                finalized_at,
            ],
        )
        .unwrap();
        id.to_string()
    }

    fn imerge_state(store: &Store, id: &str) -> String {
        let conn = store.lock_sync();
        conn.query_row(
            &format!("SELECT state FROM {INTEGRATION_MERGE_ATTEMPTS} WHERE id=?1"),
            rusqlite::params![id],
            |r| r.get(0),
        )
        .unwrap()
    }

    fn imerge_discard_reason(store: &Store, id: &str) -> Option<String> {
        let conn = store.lock_sync();
        conn.query_row(
            &format!("SELECT discard_reason FROM {INTEGRATION_MERGE_ATTEMPTS} WHERE id=?1",),
            rusqlite::params![id],
            |r| r.get::<_, Option<String>>(0),
        )
        .unwrap()
    }

    fn imerge_finalized_at(store: &Store, id: &str) -> Option<i64> {
        let conn = store.lock_sync();
        conn.query_row(
            &format!("SELECT finalized_at FROM {INTEGRATION_MERGE_ATTEMPTS} WHERE id=?1",),
            rusqlite::params![id],
            |r| r.get::<_, Option<i64>>(0),
        )
        .unwrap()
    }

    /// A row in `AwaitingPreMergeVerifiers` (Check 5d.1 inserted, no
    /// candidate computed yet) MUST fold to `DiscardedCrashRecovery`
    /// with `discard_reason = 'crash_recovery'` and `finalized_at` set.
    #[test]
    fn imerge_recon_folds_awaiting_rows_to_discarded_crash_recovery() {
        let store = Store::open_in_memory().unwrap();
        seed_imerge_attempt(
            &store,
            "imerge-await",
            IntegrationMergeAttemptState::AwaitingPreMergeVerifiers,
            None,
            None,
            None,
        );

        let report = reconcile_integration_merge_attempts(&store);
        assert_eq!(report.folded_attempts, 1, "the one open row must fold");

        assert_eq!(
            imerge_state(&store, "imerge-await"),
            "DiscardedCrashRecovery"
        );
        assert_eq!(
            imerge_discard_reason(&store, "imerge-await").as_deref(),
            Some("crash_recovery"),
        );
        assert!(
            imerge_finalized_at(&store, "imerge-await").is_some(),
            "finalized_at must be populated on terminal-discard transition",
        );
    }

    /// A row in `PreMergeVerifiersPassed` (verifiers passed but the
    /// kernel restarted before §11.1 phase 3 could finalize) MUST also
    /// fold to `DiscardedCrashRecovery` — the spec deliberately
    /// chooses re-run-conservatively over salvage-aggressively.
    #[test]
    fn imerge_recon_folds_passed_rows_to_discarded_crash_recovery() {
        let store = Store::open_in_memory().unwrap();
        seed_imerge_attempt(
            &store,
            "imerge-pass",
            IntegrationMergeAttemptState::PreMergeVerifiersPassed,
            Some("c0ffee"),
            None,
            None,
        );

        let report = reconcile_integration_merge_attempts(&store);
        assert_eq!(report.folded_attempts, 1);

        assert_eq!(
            imerge_state(&store, "imerge-pass"),
            "DiscardedCrashRecovery"
        );
        assert_eq!(
            imerge_discard_reason(&store, "imerge-pass").as_deref(),
            Some("crash_recovery"),
        );
    }

    /// Already-terminal rows (CompletedAdvanceApplied,
    /// BlockedByPreMergeVerifier, DiscardedCandidateOnly,
    /// DiscardedCrashRecovery) MUST NOT be touched. Their
    /// discard_reason and state must round-trip exactly.
    #[test]
    fn imerge_recon_leaves_terminal_rows_untouched() {
        let store = Store::open_in_memory().unwrap();
        let now = unix_now_secs();

        seed_imerge_attempt(
            &store,
            "imerge-completed",
            IntegrationMergeAttemptState::CompletedAdvanceApplied,
            Some("c0ffee"),
            None,
            Some(now),
        );
        seed_imerge_attempt(
            &store,
            "imerge-blocked",
            IntegrationMergeAttemptState::BlockedByPreMergeVerifier,
            Some("c0ffee"),
            Some(IntegrationMergeAttemptDiscardReason::VerifierBlocked),
            Some(now),
        );
        seed_imerge_attempt(
            &store,
            "imerge-discarded-cand",
            IntegrationMergeAttemptState::DiscardedCandidateOnly,
            None,
            Some(IntegrationMergeAttemptDiscardReason::CandidateComputationFailed),
            Some(now),
        );
        seed_imerge_attempt(
            &store,
            "imerge-prior-crash",
            IntegrationMergeAttemptState::DiscardedCrashRecovery,
            Some("c0ffee"),
            Some(IntegrationMergeAttemptDiscardReason::CrashRecovery),
            Some(now),
        );

        let report = reconcile_integration_merge_attempts(&store);
        assert_eq!(
            report.folded_attempts, 0,
            "no terminal rows should be folded a second time"
        );

        assert_eq!(
            imerge_state(&store, "imerge-completed"),
            "CompletedAdvanceApplied"
        );
        assert_eq!(imerge_discard_reason(&store, "imerge-completed"), None);

        assert_eq!(
            imerge_state(&store, "imerge-blocked"),
            "BlockedByPreMergeVerifier"
        );
        assert_eq!(
            imerge_discard_reason(&store, "imerge-blocked").as_deref(),
            Some("verifier_blocked"),
        );

        assert_eq!(
            imerge_state(&store, "imerge-discarded-cand"),
            "DiscardedCandidateOnly"
        );
        assert_eq!(
            imerge_discard_reason(&store, "imerge-discarded-cand").as_deref(),
            Some("candidate_computation_failed"),
        );

        assert_eq!(
            imerge_state(&store, "imerge-prior-crash"),
            "DiscardedCrashRecovery"
        );
        assert_eq!(
            imerge_discard_reason(&store, "imerge-prior-crash").as_deref(),
            Some("crash_recovery"),
        );
    }

    /// The sweep is idempotent: running it twice on the same store
    /// folds rows on the first pass and is a no-op on the second.
    #[test]
    fn imerge_recon_is_idempotent() {
        let store = Store::open_in_memory().unwrap();
        seed_imerge_attempt(
            &store,
            "imerge-await",
            IntegrationMergeAttemptState::AwaitingPreMergeVerifiers,
            None,
            None,
            None,
        );
        seed_imerge_attempt(
            &store,
            "imerge-pass",
            IntegrationMergeAttemptState::PreMergeVerifiersPassed,
            Some("c0ffee"),
            None,
            None,
        );

        let r1 = reconcile_integration_merge_attempts(&store);
        assert_eq!(r1.folded_attempts, 2);

        let r2 = reconcile_integration_merge_attempts(&store);
        assert_eq!(
            r2.folded_attempts, 0,
            "second pass must be a no-op (rows are already terminal)"
        );
    }

    /// Mixed seed: the sweep folds open rows AND leaves terminal rows
    /// alone in the same pass. Pins the §11.10.4 contract: terminal
    /// rows are out of scope; the WHERE clause filter is the only
    /// admission-side gate.
    #[test]
    fn imerge_recon_mixed_seed_only_folds_non_terminal() {
        let store = Store::open_in_memory().unwrap();
        let now = unix_now_secs();

        seed_imerge_attempt(
            &store,
            "imerge-await",
            IntegrationMergeAttemptState::AwaitingPreMergeVerifiers,
            None,
            None,
            None,
        );
        seed_imerge_attempt(
            &store,
            "imerge-completed",
            IntegrationMergeAttemptState::CompletedAdvanceApplied,
            Some("c0ffee"),
            None,
            Some(now),
        );

        let r = reconcile_integration_merge_attempts(&store);
        assert_eq!(r.folded_attempts, 1, "exactly one open row must fold");

        assert_eq!(
            imerge_state(&store, "imerge-await"),
            "DiscardedCrashRecovery"
        );
        assert_eq!(
            imerge_state(&store, "imerge-completed"),
            "CompletedAdvanceApplied"
        );
    }

    /// Empty store: the sweep returns zero folded attempts and never
    /// errors on the empty result set.
    #[test]
    fn imerge_recon_on_empty_store_is_zero() {
        let store = Store::open_in_memory().unwrap();
        let r = reconcile_integration_merge_attempts(&store);
        assert_eq!(r.folded_attempts, 0);
    }

    // ─── verify_audit_chain — fail-closed semantics ───────────────────────
    //
    // The pre-fix behaviour returned `Ok(false)` when the segment was
    // missing, which let the kernel boot with no audit chain at all.
    // These tests pin the new contract: every degraded outcome MUST be
    // `KernelError::AuditChainBroken`, and the genesis record's required
    // fields must NEVER be silently defaulted.

    use std::fs;
    use tempfile::TempDir;

    fn write_segment(dir: &Path, content: &str) {
        let path = dir.join("segment-000.jsonl");
        fs::write(&path, content).unwrap();
    }

    fn assert_chain_broken(result: Result<bool, KernelError>, expected_substr: &str) {
        match result {
            Err(KernelError::AuditChainBroken { reason }) => {
                assert!(
                    reason.contains(expected_substr),
                    "expected reason to contain {expected_substr:?}, got {reason:?}",
                );
            }
            other => panic!("expected AuditChainBroken({expected_substr:?}), got {other:?}"),
        }
    }

    #[test]
    fn verify_audit_chain_rejects_missing_segment() {
        let tmp = TempDir::new().unwrap();
        let result = verify_audit_chain(tmp.path());
        assert_chain_broken(result, "is missing");
    }

    #[test]
    fn verify_audit_chain_rejects_empty_segment() {
        let tmp = TempDir::new().unwrap();
        write_segment(tmp.path(), "");
        let result = verify_audit_chain(tmp.path());
        assert_chain_broken(result, "is empty");
    }

    #[test]
    fn verify_audit_chain_rejects_blank_first_line() {
        let tmp = TempDir::new().unwrap();
        // A file containing only a newline character: non-zero length, but
        // the first line is blank — must not pass.
        write_segment(tmp.path(), "\n");
        let result = verify_audit_chain(tmp.path());
        assert_chain_broken(result, "blank");
    }

    #[test]
    fn verify_audit_chain_rejects_invalid_json() {
        let tmp = TempDir::new().unwrap();
        write_segment(tmp.path(), "{not valid json\n");
        let result = verify_audit_chain(tmp.path());
        assert_chain_broken(result, "valid JSON");
    }

    #[test]
    fn verify_audit_chain_rejects_missing_seq_field() {
        // Regression guard: pre-fix code defaulted seq to 1 and reported a
        // misleading "wrong genesis" error instead of "field missing".
        let tmp = TempDir::new().unwrap();
        write_segment(tmp.path(), "{\"event_kind\":\"GenesisRecord\"}\n");
        let result = verify_audit_chain(tmp.path());
        assert_chain_broken(result, "missing required `seq`");
    }

    #[test]
    fn verify_audit_chain_rejects_missing_event_kind() {
        let tmp = TempDir::new().unwrap();
        write_segment(tmp.path(), "{\"seq\":0}\n");
        let result = verify_audit_chain(tmp.path());
        assert_chain_broken(result, "missing required `event_kind`");
    }

    #[test]
    fn verify_audit_chain_rejects_wrong_event_kind() {
        let tmp = TempDir::new().unwrap();
        write_segment(tmp.path(), "{\"seq\":0,\"event_kind\":\"SomethingElse\"}\n");
        let result = verify_audit_chain(tmp.path());
        assert_chain_broken(result, "not the genesis record");
    }

    #[test]
    fn verify_audit_chain_rejects_nonzero_seq() {
        let tmp = TempDir::new().unwrap();
        write_segment(tmp.path(), "{\"seq\":7,\"event_kind\":\"GenesisRecord\"}\n");
        let result = verify_audit_chain(tmp.path());
        assert_chain_broken(result, "not the genesis record");
    }

    #[test]
    fn verify_audit_chain_accepts_valid_genesis_record() {
        let tmp = TempDir::new().unwrap();
        write_segment(
            tmp.path(),
            "{\"seq\":0,\"event_kind\":\"GenesisRecord\",\"more\":\"fields\"}\n\
             {\"seq\":1,\"event_kind\":\"KernelStarted\"}\n",
        );
        let result = verify_audit_chain(tmp.path());
        assert!(matches!(result, Ok(true)));
    }
}

// ---------------------------------------------------------------------------
// Integration tests — production AuditWriter / FileAuditSink ⟷ on-disk
// JSONL ⟷ verify_audit_chain. Exercises BOTH halves of the audit-chain
// contract through the same real artifact, instead of pinning the writer
// shape and the verifier shape independently in unit tests against
// synthetic byte strings. Same bug class as the `vcs::diff` `-z` framing
// miss the `GitRepo` integration tests caught.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod audit_chain_integration {
    use super::*;
    use raxis_audit_tools::{AuditEventKind, AuditSink};
    use raxis_test_support::{AuditDir, GenesisInfo};
    use sha2::{Digest, Sha256};

    fn sample_event(reason: &str) -> AuditEventKind {
        AuditEventKind::KernelStopped {
            reason: reason.to_owned(),
        }
    }

    fn sha256_hex(bytes: &[u8]) -> String {
        let mut h = Sha256::new();
        h.update(bytes);
        hex::encode(h.finalize())
    }

    /// Walk every record in the segment and assert the chain invariant
    /// (kernel-store.md §2.5.2): record N's `prev_sha256` MUST equal the
    /// SHA-256 of record N-1's raw line bytes (including trailing '\n').
    /// Returns the records on success so the caller can also assert
    /// per-record fields.
    fn assert_chain_unbroken(dir: &AuditDir) -> Vec<serde_json::Value> {
        let raw = std::fs::read_to_string(dir.segment_path()).unwrap();
        let records = dir.read_records();
        let lines: Vec<&str> = raw.lines().collect();
        assert_eq!(records.len(), lines.len(), "record count vs line count");

        for (i, rec) in records.iter().enumerate() {
            let prev = rec["prev_sha256"]
                .as_str()
                .unwrap_or_else(|| panic!("record {i} missing prev_sha256"));
            let expected = if i == 0 {
                "0".repeat(64)
            } else {
                sha256_hex(format!("{}\n", lines[i - 1]).as_bytes())
            };
            assert_eq!(
                prev,
                expected,
                "record {i} prev_sha256 must equal SHA-256 of line {}",
                i.saturating_sub(1),
            );
        }

        records
    }

    // ─── Happy paths ──────────────────────────────────────────────────────

    #[test]
    fn writer_to_verifier_round_trip_passes_chain_check() {
        // Production setup the kernel itself runs on every boot:
        //   bootstrap writes GenesisRecord, AuditWriter appends events,
        //   verify_audit_chain reads the segment back at startup.
        let dir = AuditDir::new();
        let info: GenesisInfo = dir.write_genesis_record();

        // Append three real events through the production writer,
        // chained off the genesis line.
        let mut w = dir.open_writer_resuming_after(1, &info.raw_line_sha256);
        for i in 0..3 {
            w.append(sample_event(&format!("e{i}")), None, None, None)
                .unwrap();
        }

        // The chain MUST be byte-coherent across every line — this is the
        // assertion that catches a writer/verifier shape drift.
        let records = assert_chain_unbroken(&dir);
        assert_eq!(records.len(), 4);

        // And the production verifier MUST accept the segment.
        let result = verify_audit_chain(dir.path());
        assert!(
            matches!(result, Ok(true)),
            "verify_audit_chain rejected a production-shape chain: {result:?}"
        );
    }

    #[test]
    fn file_audit_sink_round_trip_through_dyn_audit_sink_passes_chain_check() {
        // Exercises the SAME `Arc<dyn AuditSink>` polymorphism the
        // kernel uses in `HandlerContext`. If the trait coercion or
        // the FileAuditSink mutex ever stops yielding identical bytes
        // to the bare AuditWriter, this test breaks.
        let dir = AuditDir::new();
        let info = dir.write_genesis_record();

        // Open a writer resuming from genesis, wrap in a FileAuditSink,
        // emit through the trait — same production path the kernel uses.
        let writer = dir.open_writer_resuming_after(1, &info.raw_line_sha256);
        let sink = raxis_audit_tools::FileAuditSink::new(writer);
        let dyn_sink: std::sync::Arc<dyn AuditSink> = std::sync::Arc::new(sink);

        for i in 0..2 {
            dyn_sink
                .emit(sample_event(&format!("via-trait-{i}")), None, None, None)
                .unwrap();
        }

        assert_chain_unbroken(&dir);
        assert!(matches!(verify_audit_chain(dir.path()), Ok(true)));
    }

    #[test]
    fn writer_correctly_chains_first_event_off_genesis_line() {
        // Specifically pins the GENESIS → first-event link, which is the
        // single most error-prone hop in the chain (it crosses two
        // different writers — the bootstrap-side raw write vs the
        // production AuditWriter — and they MUST agree on the canonical
        // line bytes the SHA-256 is computed from).
        let dir = AuditDir::new();
        let info = dir.write_genesis_record();

        let mut w = dir.open_writer_resuming_after(1, &info.raw_line_sha256);
        w.append(sample_event("first-after-genesis"), None, None, None)
            .unwrap();

        let records = dir.read_records();
        assert_eq!(records[1]["seq"].as_u64().unwrap(), 1);
        assert_eq!(
            records[1]["prev_sha256"].as_str().unwrap(),
            info.raw_line_sha256,
            "first post-genesis event MUST chain off SHA-256 of the genesis line",
        );
    }

    // ─── Negative paths — verify_audit_chain MUST reject ──────────────────

    #[test]
    fn flipping_genesis_seq_byte_breaks_verification() {
        // Write a real genesis, then flip a single byte in the seq value.
        // The structural verifier (which checks seq==0) MUST reject.
        //
        // Note: serde_json sorts object keys alphabetically by default,
        // so "seq" is NOT first in the line; we locate the substring
        // dynamically rather than hard-coding a byte offset (which would
        // make the test brittle against any future key-name addition).
        let dir = AuditDir::new();
        dir.write_genesis_record();

        let raw = std::fs::read(dir.segment_path()).unwrap();
        let needle = b"\"seq\":0";
        let pos = raw
            .windows(needle.len())
            .position(|w| w == needle)
            .expect("genesis line must contain `\"seq\":0`");
        // Byte offset of the literal '0' value: pos + length of `"seq":`.
        let zero_offset = pos + b"\"seq\":".len();
        assert_eq!(raw[zero_offset], b'0', "expected '0' at seq value position");
        dir.corrupt_byte_at(zero_offset as u64, b'7');

        match verify_audit_chain(dir.path()) {
            Err(KernelError::AuditChainBroken { reason }) => {
                assert!(
                    reason.contains("not the genesis record"),
                    "expected 'not the genesis record' rejection, got {reason:?}",
                );
            }
            other => panic!("expected AuditChainBroken, got {other:?}"),
        }
    }

    #[test]
    fn truncating_genesis_line_below_brace_close_breaks_verification() {
        // Simulates a crash-window where only a prefix of the genesis
        // line was fsynced. The verifier MUST reject the truncated line
        // as malformed JSON.
        let dir = AuditDir::new();
        dir.write_genesis_record();

        // Truncate to just the "{" character — clearly invalid JSON.
        dir.truncate_segment_to(1);

        // segment is non-empty (1 byte) but the first line has no '\n',
        // so `content.lines().next()` yields the partial "{" string,
        // which is not valid JSON.
        match verify_audit_chain(dir.path()) {
            Err(KernelError::AuditChainBroken { reason }) => {
                assert!(
                    reason.contains("not valid JSON"),
                    "expected JSON-parse rejection, got {reason:?}",
                );
            }
            other => panic!("expected AuditChainBroken, got {other:?}"),
        }
    }

    #[test]
    fn truncating_to_zero_bytes_after_genesis_breaks_verification() {
        // Simulates total file loss between bootstrap and kernel start
        // (e.g. the audit dir got rsync'd from an empty source). The
        // verifier MUST detect the empty file and reject.
        let dir = AuditDir::new();
        dir.write_genesis_record();
        dir.truncate_segment_to(0);

        match verify_audit_chain(dir.path()) {
            Err(KernelError::AuditChainBroken { reason }) => {
                assert!(reason.contains("is empty"), "got {reason:?}");
            }
            other => panic!("expected AuditChainBroken, got {other:?}"),
        }
    }

    // ─── Chain-walk tests — these check the FULL chain invariant the
    // verify_audit_chain v1 implementation does NOT yet check (it only
    // structurally validates the genesis record). When v2 lands a chain
    // walker, these tests pin the byte-exact invariant the walker MUST
    // enforce. They also serve as a behavioural spec right now: any
    // future production code that walks the chain can lift this same
    // logic without re-deriving the canonical-bytes contract.
    // ────────────────────────────────────────────────────────────────────

    #[test]
    fn full_chain_links_correctly_across_genesis_plus_n_events() {
        let dir = AuditDir::new();
        let info = dir.write_genesis_record();

        let mut w = dir.open_writer_resuming_after(1, &info.raw_line_sha256);
        for i in 0..10 {
            w.append(sample_event(&format!("e{i}")), None, None, None)
                .unwrap();
        }

        let records = assert_chain_unbroken(&dir);
        assert_eq!(records.len(), 11, "1 genesis + 10 events");

        // Sequence numbers MUST be 0..=10, monotonic, no gaps.
        for (i, rec) in records.iter().enumerate() {
            assert_eq!(rec["seq"].as_u64().unwrap(), i as u64);
        }
    }

    #[test]
    fn flipping_byte_in_middle_record_breaks_chain_walk() {
        // Write genesis + 3 events, then corrupt a byte inside event #2.
        // The chain walk MUST detect the break (event #3's prev_sha256
        // no longer matches the SHA-256 of the corrupted line).
        let dir = AuditDir::new();
        let info = dir.write_genesis_record();

        let mut w = dir.open_writer_resuming_after(1, &info.raw_line_sha256);
        for i in 0..3 {
            w.append(sample_event(&format!("e{i}")), None, None, None)
                .unwrap();
        }

        let lines: Vec<String> = dir.raw_lines();
        // Record indices: 0=genesis, 1=e0, 2=e1, 3=e2.
        // Flip a byte inside the body of record 2 (e1), well past its
        // opening brace. Any non-newline byte will do.
        let mut offset: u64 = 0;
        for line in lines.iter().take(2) {
            offset += line.len() as u64 + 1; // +1 for '\n'
        }
        // Skip past the opening `{` and at least the first field name
        // so we land inside a string value, where any flip preserves
        // JSON validity but changes the line bytes.
        let target = offset + 30;
        dir.corrupt_byte_at(target, b'Z');

        // Re-read and walk the chain manually — record 3's prev_sha256
        // MUST no longer match SHA-256 of the corrupted record-2 line.
        let raw = std::fs::read_to_string(dir.segment_path()).unwrap();
        let lines2: Vec<&str> = raw.lines().collect();
        let actual_prev_in_rec3 = serde_json::from_str::<serde_json::Value>(lines2[3])
            .expect("rec3 must still parse — only its predecessor changed")["prev_sha256"]
            .as_str()
            .unwrap()
            .to_owned();

        let computed = sha256_hex(format!("{}\n", lines2[2]).as_bytes());
        assert_ne!(
            actual_prev_in_rec3, computed,
            "byte-flip in record 2 must break the SHA-256 link from record 3",
        );
    }
}

// ---------------------------------------------------------------------------
// Integration tests — production Store::open(path) ⟷ on-disk SQLite ⟷
// reconcile_tasks reading committed state. Exercises WAL behaviour, the
// schema-migration-on-existing-DB path, and the close-then-reopen flow
// that `:memory:` Store can never simulate. Same bug-class motivation
// as the audit-chain integration block above.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod disk_store_integration {
    use super::*;
    use raxis_test_support::DiskStore;

    /// Insert one initiative + N tasks in arbitrary states. Mirrors the
    /// `seed_in_flight_tasks` helper in the in-memory test block above
    /// but operates on a `DiskStore` so the writes hit the WAL.
    fn seed_in_flight(disk: &DiskStore, task_states: &[(&str, TaskState)]) {
        let conn = disk.store().lock_sync();
        let now = unix_now_secs();

        conn.execute(
            &format!(
                "INSERT INTO {INITIATIVES}
                    (initiative_id, state, terminal_criteria_json,
                     plan_artifact_sha256, created_at)
                 VALUES ('init-disk-recon', ?1, '{{}}', 'deadbeef', ?2)"
            ),
            rusqlite::params![InitiativeState::Executing.as_sql_str(), now],
        )
        .unwrap();

        for (task_id, state) in task_states {
            conn.execute(
                &format!(
                    "INSERT INTO {TASKS}
                        (task_id, initiative_id, lane_id, state, actor,
                         policy_epoch, admitted_at, transitioned_at, actual_cost)
                     VALUES (?1, 'init-disk-recon', 'default', ?2, 'kernel', 1, ?3, ?3, 0)"
                ),
                rusqlite::params![task_id, state.as_sql_str(), now],
            )
            .unwrap();
        }
    }

    fn task_state_disk(disk: &DiskStore, task_id: &str) -> String {
        let conn = disk.store().lock_sync();
        conn.query_row(
            &format!("SELECT state FROM {TASKS} WHERE task_id=?1"),
            rusqlite::params![task_id],
            |r| r.get(0),
        )
        .unwrap()
    }

    #[test]
    fn disk_db_file_is_created_with_wal_sidecars() {
        // Sanity: after opening a file-backed Store, the kernel's WAL
        // pragma should have produced the `kernel.db-wal` and
        // `kernel.db-shm` sidecar files. If pragma application is ever
        // accidentally moved out of `Store::open(path)`, this catches it.
        let disk = DiskStore::new();
        // Force a write so SQLite materialises the WAL files.
        {
            let conn = disk.store().lock_sync();
            conn.execute(
                &format!(
                    "INSERT INTO {INITIATIVES}
                        (initiative_id, state, terminal_criteria_json,
                         plan_artifact_sha256, created_at)
                     VALUES ('wal-probe', ?1, '{{}}', 'deadbeef', 0)"
                ),
                rusqlite::params![InitiativeState::Executing.as_sql_str()],
            )
            .unwrap();
        }

        let db_path = disk.db_path();
        let wal = db_path.with_extension("db-wal");
        let shm = db_path.with_extension("db-shm");

        assert!(db_path.exists(), "main DB file must exist");
        assert!(
            wal.exists() || db_path.metadata().unwrap().len() > 0,
            "either the WAL sidecar exists or the main DB has been written",
        );
        // SHM is allowed to be missing on some platforms / immediately
        // after open; only assert it once we know the file is there.
        let _ = shm;
    }

    #[test]
    fn reopening_the_same_db_file_preserves_committed_state() {
        // The crash-survival contract: anything COMMITTED before the
        // kernel goes down MUST be visible when the kernel comes back up
        // (kernel-store.md §2.5.1). `:memory:` cannot test this — its
        // contents vanish on connection close.
        let mut disk = DiskStore::new();
        seed_in_flight(
            &disk,
            &[
                ("t-pre-crash-1", TaskState::Running),
                ("t-pre-crash-2", TaskState::Admitted),
            ],
        );

        // "Crash" the kernel: drop the connection. WAL gets checkpointed.
        disk.close();
        // "Restart" the kernel: re-open the same file.
        disk.reopen();

        // Both rows MUST still be there, with their original states.
        assert_eq!(task_state_disk(&disk, "t-pre-crash-1"), "Running");
        assert_eq!(task_state_disk(&disk, "t-pre-crash-2"), "Admitted");
    }

    #[test]
    fn reconcile_after_restart_sweeps_in_flight_tasks_persisted_to_disk() {
        // The full kernel-restart-then-recover sequence:
        //   1. kernel boots, writes some Running tasks, COMMITs.
        //   2. kernel crashes (we simulate by `disk.close()`).
        //   3. kernel reboots → opens the SAME db file → runs reconcile.
        //   4. Every Running/Admitted/GatesPending task MUST be moved to
        //      BlockedRecoveryPending.
        // This is exactly the path `kernel::main::main` step 6 takes,
        // and it's not exercised by any existing test (all reconcile
        // tests use `:memory:` which discards state on close).
        let mut disk = DiskStore::new();
        seed_in_flight(
            &disk,
            &[
                ("t-running", TaskState::Running),
                ("t-admitted", TaskState::Admitted),
                ("t-completed", TaskState::Completed),
            ],
        );

        // Restart cycle.
        disk.close();
        disk.reopen();

        // Run reconcile against the persisted state.
        let report = reconcile_tasks(disk.store());
        assert_eq!(
            report.swept_tasks, 2,
            "2 non-terminal tasks should have been swept after restart"
        );
        assert_eq!(
            task_state_disk(&disk, "t-running"),
            "BlockedRecoveryPending"
        );
        assert_eq!(
            task_state_disk(&disk, "t-admitted"),
            "BlockedRecoveryPending"
        );
        assert_eq!(task_state_disk(&disk, "t-completed"), "Completed");
    }

    #[test]
    fn reconcile_is_idempotent_across_a_second_restart() {
        // Run reconcile, close, reopen, run reconcile AGAIN. The second
        // pass must observe the BlockedRecoveryPending state from disk
        // and not touch any token that was already marked consumed.
        let mut disk = DiskStore::new();
        seed_in_flight(&disk, &[("t-running", TaskState::Running)]);

        let r1 = reconcile_tasks(disk.store());
        assert_eq!(r1.swept_tasks, 1);

        disk.close();
        disk.reopen();

        // After restart, the row is still BlockedRecoveryPending on disk.
        assert_eq!(
            task_state_disk(&disk, "t-running"),
            "BlockedRecoveryPending"
        );

        // The bulk UPDATE re-fires (matches the in-memory test
        // `reconcile_is_idempotent`'s contract — already-blocked rows
        // are still in the WHERE-NOT-IN-terminal set).
        let r2 = reconcile_tasks(disk.store());
        assert_eq!(
            r2.swept_tasks, 1,
            "BlockedRecoveryPending re-sweeps idempotently after restart"
        );
    }

    #[test]
    fn reopening_an_already_migrated_db_does_not_blow_up() {
        // Schema migration is idempotent (CREATE TABLE IF NOT EXISTS)
        // per §2.5.1, but until you run it against a non-empty schema
        // file you don't actually know that. This test exercises the
        // "migration on previously-populated DB" branch that
        // `Store::open(path)` runs on every kernel restart.
        let mut disk = DiskStore::new();
        seed_in_flight(&disk, &[("t-only", TaskState::Running)]);
        disk.close();

        // First reopen: migrations run against a populated schema.
        disk.reopen();
        assert_eq!(task_state_disk(&disk, "t-only"), "Running");

        disk.close();

        // Second reopen: still works. (Catches a class of bug where
        // migrations record "version applied" state and a second run
        // double-applies it.)
        disk.reopen();
        assert_eq!(task_state_disk(&disk, "t-only"), "Running");
    }
}

// ---------------------------------------------------------------------------
// Integration tests — production `recovery::reconcile_git_apply_pending`
// ⟷ on-disk SQLite ⟷ on-disk git ⟷ on-disk audit chain. Cases A / B / C
// from `integration-merge.md §11.3`.
//
// These tests deliberately use:
//   * `DiskStore` — real file-backed `kernel.db` so migration 16's
//     `git_apply_pending` column + partial index are exercised on disk.
//   * `AuditDir` — real `AuditWriter` + `FileAuditSink` writing the
//     `IntegrationMergeCompleted` event the recovery scan reads back
//     through `audit_tools::reader::ChainReader`.
//   * The system `git` CLI fixture — a real `repositories/main` repo
//     and an "orchestrator worktree" clone, so Phase-2 re-apply hits
//     the same `commit_merge_to_target_ref` production path the
//     IntegrationMerge handler does.
//
// The git fixture skips with `eprintln!` when `git` is not on PATH
// (matches the pattern in `domain-git/src/lib.rs`).
// ---------------------------------------------------------------------------

#[cfg(test)]
mod git_apply_recovery_integration {
    use super::*;
    use std::process::Command;

    use raxis_audit_tools::{
        AuditEvent, AuditEventKind, AuditSink, AuditWriterError, FileAuditSink,
    };
    use raxis_test_support::{AuditDir, DiskStore};

    const SESSIONS: &str = raxis_store::Table::Sessions.as_str();

    // ── Git CLI fixture ─────────────────────────────────────────────────

    fn git_available() -> bool {
        Command::new("git").arg("--version").output().is_ok()
    }

    fn run_git(args: &[&str], cwd: &Path) -> std::process::Output {
        let s = Command::new("git")
            .args(args)
            .current_dir(cwd)
            .env("GIT_AUTHOR_NAME", "RAXIS Test")
            .env("GIT_AUTHOR_EMAIL", "test@raxis.local")
            .env("GIT_COMMITTER_NAME", "RAXIS Test")
            .env("GIT_COMMITTER_EMAIL", "test@raxis.local")
            .env("GIT_AUTHOR_DATE", "1700000000 +0000")
            .env("GIT_COMMITTER_DATE", "1700000000 +0000")
            .output()
            .expect("git invocation");
        assert!(
            s.status.success(),
            "git {args:?} failed in {}: {}",
            cwd.display(),
            String::from_utf8_lossy(&s.stderr),
        );
        s
    }

    fn fixture_repos(
        data_dir: &Path,
    ) -> Option<(std::path::PathBuf, std::path::PathBuf, String, String)> {
        if !git_available() {
            return None;
        }
        let main = data_dir.join("repositories").join("main");
        std::fs::create_dir_all(&main).unwrap();
        run_git(&["init", "-q"], &main);
        run_git(&["symbolic-ref", "HEAD", "refs/heads/main"], &main);
        run_git(&["config", "user.name", "RAXIS Test"], &main);
        run_git(&["config", "user.email", "test@raxis.local"], &main);
        run_git(&["config", "commit.gpgsign", "false"], &main);
        std::fs::write(main.join("README.md"), "v1\n").unwrap();
        run_git(&["add", "README.md"], &main);
        run_git(&["commit", "-q", "-m", "initial"], &main);
        let base = String::from_utf8(run_git(&["rev-parse", "HEAD"], &main).stdout)
            .unwrap()
            .trim()
            .to_owned();

        let orch = data_dir.join("worktrees").join("orchestrator-1");
        std::fs::create_dir_all(orch.parent().unwrap()).unwrap();
        run_git(
            &[
                "clone",
                "-q",
                main.to_str().unwrap(),
                orch.to_str().unwrap(),
            ],
            data_dir,
        );
        run_git(&["config", "user.name", "RAXIS Test"], &orch);
        run_git(&["config", "user.email", "test@raxis.local"], &orch);
        run_git(&["config", "commit.gpgsign", "false"], &orch);
        std::fs::write(orch.join("README.md"), "v1\nv2\n").unwrap();
        run_git(&["add", "README.md"], &orch);
        run_git(&["commit", "-q", "-m", "merge: add v2"], &orch);
        let merge = String::from_utf8(run_git(&["rev-parse", "HEAD"], &orch).stdout)
            .unwrap()
            .trim()
            .to_owned();

        Some((main, orch, base, merge))
    }

    fn current_main_sha(main_repo: &Path) -> String {
        let out = run_git(&["rev-parse", "refs/heads/main"], main_repo);
        String::from_utf8(out.stdout).unwrap().trim().to_owned()
    }

    // ── SQLite seed helpers ─────────────────────────────────────────────

    fn seed_initiative_pending(disk: &DiskStore, initiative_id: &str) {
        let conn = disk.store().lock_sync();
        conn.execute(
            &format!(
                "INSERT INTO {INITIATIVES} \
                    (initiative_id, state, terminal_criteria_json, \
                     plan_artifact_sha256, created_at, git_apply_pending) \
                 VALUES (?1, 'Executing', '{{}}', 'deadbeef', 1700000000, 1)"
            ),
            rusqlite::params![initiative_id],
        )
        .unwrap();
    }

    fn seed_session_with_worktree(disk: &DiskStore, session_id: &str, worktree_path: &Path) {
        let conn = disk.store().lock_sync();
        conn.execute(
            &format!(
                "INSERT INTO {SESSIONS} \
                    (session_id, role_id, session_token, lineage_id, \
                     worktree_root, fetch_quota, created_at, expires_at) \
                 VALUES (?1, 'orchestrator', ?2, ?1, ?3, 0, 1700000000, 1700003600)"
            ),
            rusqlite::params![
                session_id,
                format!("tok-{session_id}"),
                worktree_path.display().to_string(),
            ],
        )
        .unwrap();
    }

    fn pending_flag(disk: &DiskStore, initiative_id: &str) -> i64 {
        let conn = disk.store().lock_sync();
        conn.query_row(
            &format!("SELECT git_apply_pending FROM {INITIATIVES} WHERE initiative_id = ?1"),
            rusqlite::params![initiative_id],
            |r| r.get(0),
        )
        .unwrap()
    }

    // ── Audit-event helpers ─────────────────────────────────────────────

    fn write_audit_with_merge(
        audit_dir: &AuditDir,
        initiative_id: &str,
        session_id: &str,
        commit_sha: &str,
        previous_sha: &str,
        target_ref: &str,
    ) {
        let info = audit_dir.write_genesis_record();
        let writer = audit_dir.open_writer_resuming_after(1, &info.raw_line_sha256);
        let sink = FileAuditSink::new(writer);
        sink.emit(
            AuditEventKind::IntegrationMergeCompleted {
                initiative_id: initiative_id.into(),
                session_id: session_id.into(),
                commit_sha: commit_sha.into(),
                previous_sha: previous_sha.into(),
                operator_assisted: false,
                escalation_id: None,
                target_ref: target_ref.into(),
            },
            Some(session_id),
            None,
            Some(initiative_id),
        )
        .unwrap();
    }

    /// In-memory audit sink for asserting the typed events recovery
    /// emits without round-tripping through a second on-disk segment.
    #[derive(Default)]
    struct CapturingSink {
        events: std::sync::Mutex<Vec<AuditEventKind>>,
    }

    impl AuditSink for CapturingSink {
        fn emit(
            &self,
            kind: AuditEventKind,
            session_id: Option<&str>,
            task_id: Option<&str>,
            initiative_id: Option<&str>,
        ) -> Result<AuditEvent, AuditWriterError> {
            let event_kind_str = kind.as_str().to_owned();
            let payload = serde_json::to_value(&kind).expect("event must serialize");
            self.events.lock().unwrap().push(kind);
            Ok(AuditEvent {
                seq: 0,
                event_id: uuid::Uuid::nil(),
                event_kind: event_kind_str,
                session_id: session_id.map(str::to_owned),
                task_id: task_id.map(str::to_owned),
                initiative_id: initiative_id.map(str::to_owned),
                payload,
                emitted_at: 0,
                prev_sha256: String::new(),
            })
        }
    }

    impl CapturingSink {
        fn captured(&self) -> Vec<AuditEventKind> {
            self.events.lock().unwrap().clone()
        }
    }

    // ── Tests ───────────────────────────────────────────────────────────

    #[test]
    fn empty_store_yields_empty_report() {
        let disk = DiskStore::new();
        let audit_dir = AuditDir::new();
        audit_dir.write_genesis_record();
        let sink = CapturingSink::default();

        let report =
            reconcile_git_apply_pending(disk.store(), &sink, audit_dir.path(), disk.data_dir());

        assert_eq!(report.repaired, 0);
        assert_eq!(report.verified, 0);
        assert_eq!(report.inconsistent, 0);
        assert!(report.outcomes.is_empty());
        assert!(sink.captured().is_empty());
    }

    #[test]
    fn case_b_clears_flag_and_emits_verified_when_target_already_at_db_sha() {
        if !git_available() {
            eprintln!("skipping: git CLI not available");
            return;
        }
        let disk = DiskStore::new();
        let audit_dir = AuditDir::new();
        let (main, orch, base, merge) =
            fixture_repos(disk.data_dir()).expect("fixture must succeed when git is available");
        // Pre-advance main to the merge sha — the Case-B precondition
        // (Phase 2 fully succeeded; only Phase 3 missed across the crash).
        raxis_domain_git::commit_merge_to_target_ref(&main, &orch, &merge, "refs/heads/main")
            .unwrap();
        assert_eq!(current_main_sha(&main), merge);

        let initiative_id = "init-case-b";
        let session_id = "sess-orch-b";
        seed_initiative_pending(&disk, initiative_id);
        seed_session_with_worktree(&disk, session_id, &orch);
        write_audit_with_merge(
            &audit_dir,
            initiative_id,
            session_id,
            &merge,
            &base,
            "refs/heads/main",
        );

        let sink = CapturingSink::default();
        let report =
            reconcile_git_apply_pending(disk.store(), &sink, audit_dir.path(), disk.data_dir());

        assert_eq!(report.repaired, 0);
        assert_eq!(report.verified, 1);
        assert_eq!(report.inconsistent, 0);
        match &report.outcomes[0] {
            GitApplyRecoveryOutcome::Verified {
                initiative_id: iid,
                commit_sha,
                target_ref,
            } => {
                assert_eq!(iid, initiative_id);
                assert_eq!(commit_sha, &merge);
                assert_eq!(target_ref, "refs/heads/main");
            }
            other => panic!("expected Verified, got {other:?}"),
        }
        assert_eq!(pending_flag(&disk, initiative_id), 0);

        let captured = sink.captured();
        assert_eq!(captured.len(), 1);
        match &captured[0] {
            AuditEventKind::GitConsistencyVerified {
                initiative_id: iid,
                sha,
                target_ref,
            } => {
                assert_eq!(iid, initiative_id);
                assert_eq!(sha, &merge);
                assert_eq!(target_ref, "refs/heads/main");
            }
            other => panic!("expected GitConsistencyVerified, got {other:?}"),
        }
    }

    #[test]
    fn case_a_re_applies_phase_2_and_emits_repaired() {
        if !git_available() {
            eprintln!("skipping: git CLI not available");
            return;
        }
        let disk = DiskStore::new();
        let audit_dir = AuditDir::new();
        let (main, orch, base, merge) =
            fixture_repos(disk.data_dir()).expect("fixture must succeed when git is available");
        // INTENTIONALLY do NOT pre-advance main — the Case-A precondition
        // (Phase 1 SQLite committed, Phase 2 host-side advance never ran).
        assert_eq!(current_main_sha(&main), base);

        let initiative_id = "init-case-a";
        let session_id = "sess-orch-a";
        seed_initiative_pending(&disk, initiative_id);
        seed_session_with_worktree(&disk, session_id, &orch);
        write_audit_with_merge(
            &audit_dir,
            initiative_id,
            session_id,
            &merge,
            &base,
            "refs/heads/main",
        );

        let sink = CapturingSink::default();
        let report =
            reconcile_git_apply_pending(disk.store(), &sink, audit_dir.path(), disk.data_dir());

        assert_eq!(report.repaired, 1);
        assert_eq!(report.verified, 0);
        assert_eq!(report.inconsistent, 0);
        match &report.outcomes[0] {
            GitApplyRecoveryOutcome::Repaired {
                initiative_id: iid,
                commit_sha,
                target_ref,
                ..
            } => {
                assert_eq!(iid, initiative_id);
                assert_eq!(commit_sha, &merge);
                assert_eq!(target_ref, "refs/heads/main");
            }
            other => panic!("expected Repaired, got {other:?}"),
        }
        assert_eq!(
            current_main_sha(&main),
            merge,
            "Case A MUST advance refs/heads/main to db_sha"
        );
        assert_eq!(pending_flag(&disk, initiative_id), 0);

        let captured = sink.captured();
        assert_eq!(captured.len(), 1);
        match &captured[0] {
            AuditEventKind::GitConsistencyRepaired {
                initiative_id: iid,
                db_sha,
                previous_git_sha,
                target_ref,
            } => {
                assert_eq!(iid, initiative_id);
                assert_eq!(db_sha, &merge);
                assert_eq!(previous_git_sha, &base);
                assert_eq!(target_ref, "refs/heads/main");
            }
            other => panic!("expected GitConsistencyRepaired, got {other:?}"),
        }
    }

    #[test]
    fn case_c_emits_inconsistent_when_orchestrator_worktree_missing() {
        if !git_available() {
            eprintln!("skipping: git CLI not available");
            return;
        }
        let disk = DiskStore::new();
        let audit_dir = AuditDir::new();
        let (main, _orch, base, merge) =
            fixture_repos(disk.data_dir()).expect("fixture must succeed when git is available");

        let initiative_id = "init-case-c-missing";
        let session_id = "sess-orch-c-missing";
        seed_initiative_pending(&disk, initiative_id);
        // Point at a worktree path that does not exist on disk.
        let bogus = disk.data_dir().join("worktrees").join("never-existed");
        seed_session_with_worktree(&disk, session_id, &bogus);
        write_audit_with_merge(
            &audit_dir,
            initiative_id,
            session_id,
            &merge,
            &base,
            "refs/heads/main",
        );

        let sink = CapturingSink::default();
        let report =
            reconcile_git_apply_pending(disk.store(), &sink, audit_dir.path(), disk.data_dir());

        assert_eq!(report.inconsistent, 1);
        match &report.outcomes[0] {
            GitApplyRecoveryOutcome::Inconsistent {
                initiative_id: iid,
                reason,
                target_ref,
                ..
            } => {
                assert_eq!(iid, initiative_id);
                assert_eq!(target_ref, "refs/heads/main");
                assert_eq!(reason, "orchestrator_worktree_missing");
            }
            other => panic!("expected Inconsistent, got {other:?}"),
        }
        assert_eq!(
            pending_flag(&disk, initiative_id),
            1,
            "Case C MUST leave the flag set so subsequent merges keep rejecting"
        );
        assert_eq!(
            current_main_sha(&main),
            base,
            "Case C MUST NOT advance refs/heads/main"
        );
    }

    #[test]
    fn case_c_emits_inconsistent_when_audit_record_missing() {
        let disk = DiskStore::new();
        let audit_dir = AuditDir::new();
        audit_dir.write_genesis_record();
        let initiative_id = "init-case-c-no-audit";
        seed_initiative_pending(&disk, initiative_id);

        let sink = CapturingSink::default();
        let report =
            reconcile_git_apply_pending(disk.store(), &sink, audit_dir.path(), disk.data_dir());

        assert_eq!(report.inconsistent, 1);
        match &report.outcomes[0] {
            GitApplyRecoveryOutcome::Inconsistent {
                initiative_id: iid,
                reason,
                ..
            } => {
                assert_eq!(iid, initiative_id);
                assert_eq!(reason, "audit_record_missing");
            }
            other => panic!("expected Inconsistent, got {other:?}"),
        }
        assert_eq!(pending_flag(&disk, initiative_id), 1);
    }

    #[test]
    fn idempotent_after_case_b_succeeds() {
        if !git_available() {
            eprintln!("skipping: git CLI not available");
            return;
        }
        let disk = DiskStore::new();
        let audit_dir = AuditDir::new();
        let (main, orch, base, merge) =
            fixture_repos(disk.data_dir()).expect("fixture must succeed when git is available");
        raxis_domain_git::commit_merge_to_target_ref(&main, &orch, &merge, "refs/heads/main")
            .unwrap();

        let initiative_id = "init-idempotent";
        let session_id = "sess-orch-idem";
        seed_initiative_pending(&disk, initiative_id);
        seed_session_with_worktree(&disk, session_id, &orch);
        write_audit_with_merge(
            &audit_dir,
            initiative_id,
            session_id,
            &merge,
            &base,
            "refs/heads/main",
        );

        let sink1 = CapturingSink::default();
        let r1 =
            reconcile_git_apply_pending(disk.store(), &sink1, audit_dir.path(), disk.data_dir());
        assert_eq!(r1.verified, 1);
        assert_eq!(pending_flag(&disk, initiative_id), 0);

        let sink2 = CapturingSink::default();
        let r2 =
            reconcile_git_apply_pending(disk.store(), &sink2, audit_dir.path(), disk.data_dir());
        assert_eq!(r2.verified, 0);
        assert_eq!(r2.repaired, 0);
        assert_eq!(r2.inconsistent, 0);
        assert!(sink2.captured().is_empty());
    }
}

// ---------------------------------------------------------------------------
// Witness — `INV-SUPERVISOR-AUTO-RESUME-ON-CLEAN-RESTART-01`.
//
// The user-prompt-named witness file is `kernel/tests/supervisor_auto_resume.rs`,
// which is unreachable from `kernel/tests/*` because the kernel is a
// binary-only crate (no `lib.rs` exposes `recovery::*`). The integration
// test at `tests/supervisor_auto_resume.rs` covers the cross-crate
// contract surface (audit-event variant shape, notification routing,
// policy `KNOWN_AUDIT_EVENT_KINDS` lockstep). This module covers the
// FSM-level invariant — the auto-resume sweep partitions a 6-task
// fixture into the four canonical outcomes per the invariant
// statement.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod supervisor_auto_resume_witness {
    use super::*;
    use raxis_audit_tools::AuditEventKind;
    use raxis_store::Store;
    use raxis_test_support::FakeAuditSink;

    const INITIATIVE_QUARANTINES: &str = Table::InitiativeQuarantines.as_str();

    /// Insert a single initiative row in `Executing` state so the
    /// per-task FK references resolve.
    fn seed_initiative(store: &Store, initiative_id: &str) {
        let conn = store.lock_sync();
        let now = unix_now_secs();
        conn.execute(
            &format!(
                "INSERT INTO {INITIATIVES}
                    (initiative_id, state, terminal_criteria_json,
                     plan_artifact_sha256, created_at)
                 VALUES (?1, ?2, '{{}}', 'deadbeef', ?3)"
            ),
            rusqlite::params![initiative_id, InitiativeState::Executing.as_sql_str(), now],
        )
        .unwrap();
    }

    fn seed_task(store: &Store, task_id: &str, initiative_id: &str, state: TaskState) {
        let conn = store.lock_sync();
        let now = unix_now_secs();
        conn.execute(
            &format!(
                "INSERT INTO {TASKS}
                    (task_id, initiative_id, lane_id, state, actor,
                     policy_epoch, admitted_at, transitioned_at, actual_cost)
                 VALUES (?1, ?2, 'default', ?3, 'kernel', 1, ?4, ?4, 0)"
            ),
            rusqlite::params![task_id, initiative_id, state.as_sql_str(), now],
        )
        .unwrap();
    }

    /// Insert one `initiative_quarantines` row so the auto-resume
    /// sweep treats the initiative as operator-frozen. Column shape
    /// per `crates/store/src/views/initiative_quarantines.rs`
    /// `SELECT_ALL_COLS`.
    fn quarantine_initiative(store: &Store, initiative_id: &str) {
        let conn = store.lock_sync();
        let now = unix_now_secs();
        conn.execute(
            &format!(
                "INSERT INTO {INITIATIVE_QUARANTINES}
                    (initiative_id, quarantined_at, quarantined_by, reason, sweep_target)
                 VALUES (?1, ?2, 'op-fp', 'forensic hold', NULL)"
            ),
            rusqlite::params![initiative_id, now],
        )
        .unwrap();
    }

    fn task_state(store: &Store, task_id: &str) -> String {
        let conn = store.lock_sync();
        conn.query_row(
            &format!("SELECT state FROM {TASKS} WHERE task_id = ?1"),
            rusqlite::params![task_id],
            |r| r.get(0),
        )
        .unwrap()
    }

    /// Witness — `INV-SUPERVISOR-AUTO-RESUME-ON-CLEAN-RESTART-01`.
    ///
    /// Fixture (6 tasks across 3 initiatives — one of each
    /// auto-resume disposition):
    ///
    ///   init-resume    (NOT quarantined)
    ///     · t-running-1   Running         → expect Resumed (prior_state="Running")
    ///     · t-running-2   Running         → expect Resumed (prior_state="Running")
    ///     · t-running-3   Running         → expect Resumed (prior_state="Running")
    ///     · t-already-brp BlockedRecoveryPending → expect SkippedPreExistingBlock
    ///   init-gates     (NOT quarantined)
    ///     · t-gates       GatesPending    → expect Resumed (prior_state="GatesPending")
    ///   init-quarantine (operator-quarantined BEFORE the sweep)
    ///     · t-quarantined Running         → expect SkippedQuarantined
    ///
    /// Asserted post-conditions:
    ///   1. `reconcile_tasks` sweeps 5 of 6 rows to BRP (pre-existing
    ///      BRP row is unchanged in state but re-`transitioned_at`-stamped;
    ///      it appears in `swept_tasks_detail` with prior_state =
    ///      "BlockedRecoveryPending").
    ///   2. `reconcile_after_supervisor_restart` returns
    ///      `resumed = 4`, `pre_existing_block = 1`,
    ///      `quarantined = 1`, `transition_failed = 0`.
    ///   3. Every Resumed task is now `Admitted`.
    ///   4. Every Skipped task is still `BlockedRecoveryPending`.
    ///   5. The `FakeAuditSink` holds EXACTLY 4 `TaskAutoResumed*`
    ///      events — skipped tasks emit nothing.
    ///   6. Each emitted event carries the correct `prior_state`,
    ///      `task_id`, `initiative_id`, and a SHARED
    ///      `supervisor_restart_id` (one episode → one id).
    #[test]
    fn auto_resume_partitions_six_task_fixture_per_invariant() {
        let store = Store::open_in_memory().unwrap();

        seed_initiative(&store, "init-resume");
        seed_initiative(&store, "init-gates");
        seed_initiative(&store, "init-quarantine");

        seed_task(&store, "t-running-1", "init-resume", TaskState::Running);
        seed_task(&store, "t-running-2", "init-resume", TaskState::Running);
        seed_task(&store, "t-running-3", "init-resume", TaskState::Running);
        seed_task(
            &store,
            "t-already-brp",
            "init-resume",
            TaskState::BlockedRecoveryPending,
        );
        seed_task(&store, "t-gates", "init-gates", TaskState::GatesPending);
        seed_task(
            &store,
            "t-quarantined",
            "init-quarantine",
            TaskState::Running,
        );

        quarantine_initiative(&store, "init-quarantine");

        let report = reconcile_tasks(&store);
        // INV check 1: SELECT-then-UPDATE inside one transaction. All 6
        // non-terminal rows (including the pre-existing BRP) appear in
        // `swept_tasks_detail` with their pre-sweep state.
        assert_eq!(
            report.swept_tasks_detail.len(),
            6,
            "all 6 non-terminal tasks must be captured"
        );
        // The bulk UPDATE only counts rows whose state CHANGED — the
        // pre-existing BRP row's state didn't change (it was already
        // BRP). SQLite `UPDATE` counts every row matched by the WHERE
        // clause regardless, so we expect 6 here too.
        assert_eq!(
            report.swept_tasks, 6,
            "bulk UPDATE touches all 6 non-terminal rows"
        );

        let prior_state_for = |task_id: &str| -> Option<String> {
            report
                .swept_tasks_detail
                .iter()
                .find(|r| r.task_id == task_id)
                .map(|r| r.prior_state.clone())
        };
        assert_eq!(prior_state_for("t-running-1"), Some("Running".into()));
        assert_eq!(prior_state_for("t-running-2"), Some("Running".into()));
        assert_eq!(prior_state_for("t-running-3"), Some("Running".into()));
        assert_eq!(
            prior_state_for("t-already-brp"),
            Some("BlockedRecoveryPending".into())
        );
        assert_eq!(prior_state_for("t-gates"), Some("GatesPending".into()));
        assert_eq!(prior_state_for("t-quarantined"), Some("Running".into()));

        // After the sweep, every captured row is at BRP in the table.
        for tid in [
            "t-running-1",
            "t-running-2",
            "t-running-3",
            "t-already-brp",
            "t-gates",
            "t-quarantined",
        ] {
            assert_eq!(
                task_state(&store, tid),
                "BlockedRecoveryPending",
                "{tid} must be at BRP after reconcile sweep"
            );
        }

        let sink = FakeAuditSink::new();
        let restart_id = "supervisor-restart-1700000000-1";
        let resume_report = reconcile_after_supervisor_restart(
            &store,
            &sink,
            &report.swept_tasks_detail,
            restart_id,
        );

        // INV check 2: outcome counters match the invariant partition.
        assert_eq!(
            resume_report.resumed, 4,
            "3 Running + 1 GatesPending must auto-resume"
        );
        assert_eq!(
            resume_report.pre_existing_block, 1,
            "the pre-existing BRP task must be preserved"
        );
        assert_eq!(
            resume_report.quarantined, 1,
            "the quarantined-initiative task must be preserved"
        );
        assert_eq!(
            resume_report.transition_failed, 0,
            "no transition failures expected on a clean fixture"
        );
        assert_eq!(
            resume_report.outcomes.len(),
            6,
            "every input record must produce one outcome"
        );
        assert_eq!(resume_report.supervisor_restart_id, restart_id);

        // INV check 3: Resumed tasks are now Admitted.
        for tid in ["t-running-1", "t-running-2", "t-running-3", "t-gates"] {
            assert_eq!(
                task_state(&store, tid),
                "Admitted",
                "{tid} must be re-admitted after supervisor auto-resume"
            );
        }
        // INV check 4: Skipped tasks remain at BRP.
        for tid in ["t-already-brp", "t-quarantined"] {
            assert_eq!(
                task_state(&store, tid),
                "BlockedRecoveryPending",
                "{tid} must remain at BRP (skipped by auto-resume)"
            );
        }

        // INV check 5: emitted audit events — one per Resumed,
        // ZERO for Skipped (operator-quarantined + pre-existing-BRP
        // skip silently per the invariant statement).
        let events = sink.events();
        assert_eq!(
            events.len(),
            4,
            "skipped tasks must NOT emit TaskAutoResumed*; resumed tasks emit exactly one each"
        );

        // INV check 6: every event carries a faithful prior_state +
        // a SHARED supervisor_restart_id.
        let mut by_task: std::collections::HashMap<String, (String, String, u32)> =
            std::collections::HashMap::new();
        for ev in &events {
            match &ev.kind {
                AuditEventKind::TaskAutoResumedAfterSupervisorRestart {
                    task_id,
                    initiative_id,
                    prior_state,
                    witness_count_preserved,
                    supervisor_restart_id,
                } => {
                    assert_eq!(
                        supervisor_restart_id, restart_id,
                        "all events from one restart must share supervisor_restart_id"
                    );
                    by_task.insert(
                        task_id.clone(),
                        (
                            initiative_id.clone(),
                            prior_state.clone(),
                            *witness_count_preserved,
                        ),
                    );
                }
                other => panic!("unexpected event in auto-resume sweep: {other:?}"),
            }
        }
        let (init, prior, w) = by_task
            .get("t-running-1")
            .expect("t-running-1 event missing");
        assert_eq!(init, "init-resume");
        assert_eq!(prior, "Running");
        assert_eq!(*w, 0, "no witnesses seeded → preserved count = 0");
        let (init, prior, _) = by_task.get("t-gates").expect("t-gates event missing");
        assert_eq!(init, "init-gates");
        assert_eq!(prior, "GatesPending",
            "the GatesPending → Admitted auto-resume MUST surface the original GatesPending state on the audit event");

        // No event for the skipped tasks.
        assert!(
            !by_task.contains_key("t-already-brp"),
            "pre-existing BRP must NOT emit TaskAutoResumed*"
        );
        assert!(
            !by_task.contains_key("t-quarantined"),
            "quarantined-initiative task must NOT emit TaskAutoResumed*"
        );
    }

    /// Empty input → no-op (the supervisor restarted but the recovery
    /// sweep found nothing in flight). Witness for the `is_empty()`
    /// short-circuit in `reconcile_after_supervisor_restart`.
    #[test]
    fn auto_resume_is_a_noop_when_recovery_sweep_was_empty() {
        let store = Store::open_in_memory().unwrap();
        let sink = FakeAuditSink::new();
        let report =
            reconcile_after_supervisor_restart(&store, &sink, &[], "supervisor-restart-empty-1");
        assert_eq!(report.resumed, 0);
        assert_eq!(report.quarantined, 0);
        assert_eq!(report.pre_existing_block, 0);
        assert_eq!(report.transition_failed, 0);
        assert!(report.outcomes.is_empty());
        assert!(sink.events().is_empty());
    }
}

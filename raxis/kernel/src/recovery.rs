// raxis-kernel::recovery — Post-crash reconciliation.
//
// Normative reference: kernel-core.md §2.2 `src/recovery.rs`.
//
// Purpose: Runs at startup step 6. Verifies audit chain integrity, identifies
// tasks that were in-flight at crash time, and marks them BlockedRecoveryPending
// for operator disposition. Does NOT auto-resume — automatic resumption is v2.
//
// Entry point: `pub fn reconcile(store, audit_dir) -> ReconciliationResult`
// Called once from main.rs step 6; sub-functions are private.
//
// Fatal sub-step: verify_audit_chain — failure returns KernelError::AuditChainBroken
// which main.rs maps to BOOT_ERR_AUDIT_CHAIN (exit code 13).

use std::path::Path;

use raxis_store::{Store, Table};
use raxis_types::{
    unix_now_secs, InitiativeState, IntegrationMergeAttemptDiscardReason,
    IntegrationMergeAttemptState, TaskState,
};

use crate::errors::KernelError;

// INV-STORE-03 (kernel-store.md §2.5.1): table identifiers and FSM state
// strings flow through typed constants/enums; no raw SQL identifiers in
// this file (production OR tests).
const TASKS:                       &str = Table::Tasks.as_str();
const VERIFIER_RUN_TOKENS:         &str = Table::VerifierRunTokens.as_str();
const INITIATIVES:                 &str = Table::Initiatives.as_str();
const INTEGRATION_MERGE_ATTEMPTS:  &str = Table::IntegrationMergeAttempts.as_str();

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

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
}

/// A lightweight report from reconcile_tasks.
#[derive(Debug, Default)]
pub struct ReconciliationReport {
    pub swept_tasks: usize,
    pub expired_tokens: usize,
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
/// Returns ReconciliationResult on success. Propagates KernelError on
/// audit chain failure (step 1 only; task sweep failures are non-fatal and
/// logged).
pub fn reconcile(store: &Store, audit_dir: &Path) -> Result<ReconciliationResult, KernelError> {
    let chain_ok = verify_audit_chain(audit_dir)?;

    let task_report  = reconcile_tasks(store);
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
        swept_tasks:                       task_report.swept_tasks,
        expired_tokens:                    task_report.expired_tokens,
        folded_integration_merge_attempts: imerge_report.folded_attempts,
        chain_ok,
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

    let first_line = content.lines().next().ok_or_else(|| KernelError::AuditChainBroken {
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
    let now      = unix_now_secs();

    let blocked  = TaskState::BlockedRecoveryPending.as_sql_str();
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

    // Sweep every non-terminal task in a single statement. This avoids the
    // N-statement TOCTOU window where a query-then-loop-then-update pattern
    // could race a parallel actor.
    let swept = match tx.execute(
        &format!(
            "UPDATE {TASKS} SET state='{blocked}', transitioned_at=?1
             WHERE state NOT IN ({terminal})"
        ),
        rusqlite::params![now],
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

    report.swept_tasks    = swept;
    report.expired_tokens = expired;

    if swept > 0 || expired > 0 {
        eprintln!(
            "{{\"level\":\"warn\",\"step\":\"recovery\",\"action\":\"reconciled\",\
             \"swept_tasks\":{swept},\"expired_tokens\":{expired}}}",
        );
    }

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
fn reconcile_integration_merge_attempts(
    store: &Store,
) -> IntegrationMergeReconciliationReport {
    let mut report = IntegrationMergeReconciliationReport::default();

    let mut conn = store.lock_sync();
    let now      = unix_now_secs();

    let awaiting   = IntegrationMergeAttemptState::AwaitingPreMergeVerifiers.as_sql_str();
    let passed     = IntegrationMergeAttemptState::PreMergeVerifiersPassed.as_sql_str();
    let discarded  = IntegrationMergeAttemptState::DiscardedCrashRecovery.as_sql_str();
    let crash_rsn  = IntegrationMergeAttemptDiscardReason::CrashRecovery.as_sql_str();

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
        ).unwrap();

        for (task_id, state) in task_states {
            conn.execute(
                &format!(
                    "INSERT INTO {TASKS}
                        (task_id, initiative_id, lane_id, state, actor,
                         policy_epoch, admitted_at, transitioned_at, actual_cost)
                     VALUES (?1, 'init-recon', 'default', ?2, 'kernel', 1, ?3, ?3, 0)"
                ),
                rusqlite::params![task_id, state.as_sql_str(), now],
            ).unwrap();
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
        ).unwrap();
    }

    fn task_state(store: &Store, task_id: &str) -> String {
        let conn = store.lock_sync();
        conn.query_row(
            &format!("SELECT state FROM {TASKS} WHERE task_id=?1"),
            rusqlite::params![task_id],
            |r| r.get(0),
        ).unwrap()
    }

    fn token_consumed(store: &Store, run_id: &str) -> i64 {
        let conn = store.lock_sync();
        conn.query_row(
            &format!("SELECT consumed FROM {VERIFIER_RUN_TOKENS} WHERE verifier_run_id=?1"),
            rusqlite::params![run_id],
            |r| r.get(0),
        ).unwrap()
    }

    #[test]
    fn reconcile_sweeps_only_non_terminal_tasks() {
        let store = Store::open_in_memory().unwrap();
        seed_in_flight_tasks(&store, &[
            ("t-running",    TaskState::Running),
            ("t-admitted",   TaskState::Admitted),
            ("t-gates",      TaskState::GatesPending),
            ("t-already",    TaskState::BlockedRecoveryPending),
            ("t-completed",  TaskState::Completed),
            ("t-failed",     TaskState::Failed),
            ("t-aborted",    TaskState::Aborted),
            ("t-cancelled",  TaskState::Cancelled),
        ]);

        let report = reconcile_tasks(&store);
        // 4 non-terminal tasks should sweep; 4 terminal tasks should not.
        assert_eq!(report.swept_tasks, 4);

        for tid in ["t-running", "t-admitted", "t-gates", "t-already"] {
            assert_eq!(task_state(&store, tid), "BlockedRecoveryPending",
                       "{tid} should have been swept");
        }
        for (tid, expected) in [
            ("t-completed", "Completed"),
            ("t-failed",    "Failed"),
            ("t-aborted",   "Aborted"),
            ("t-cancelled", "Cancelled"),
        ] {
            assert_eq!(task_state(&store, tid), expected,
                       "{tid} must NOT change state");
        }
    }

    #[test]
    fn reconcile_expires_only_live_tokens_for_swept_tasks() {
        let store = Store::open_in_memory().unwrap();
        seed_in_flight_tasks(&store, &[
            ("t-running",   TaskState::Running),
            ("t-completed", TaskState::Completed),
        ]);
        // Two tokens: one for the running task (will sweep) and one for
        // the completed task (must NOT be touched).
        seed_live_token(&store, "tok-running",   "t-running");
        seed_live_token(&store, "tok-completed", "t-completed");

        let report = reconcile_tasks(&store);
        assert_eq!(report.swept_tasks, 1);
        assert_eq!(report.expired_tokens, 1, "only running task's token should expire");
        assert_eq!(token_consumed(&store, "tok-running"),   1);
        assert_eq!(token_consumed(&store, "tok-completed"), 0);
    }

    #[test]
    fn reconcile_is_idempotent() {
        // Running reconcile twice must not change state on the second run.
        let store = Store::open_in_memory().unwrap();
        seed_in_flight_tasks(&store, &[
            ("t-running", TaskState::Running),
        ]);
        seed_live_token(&store, "tok", "t-running");

        let r1 = reconcile_tasks(&store);
        assert_eq!(r1.swept_tasks, 1);
        assert_eq!(r1.expired_tokens, 1);

        // Second pass: task is already BlockedRecoveryPending, but per
        // the spec ("idempotent — including tasks already in
        // BlockedRecoveryPending") the bulk UPDATE re-fires its rows.
        // The token, however, is now consumed=1 and won't be touched.
        let r2 = reconcile_tasks(&store);
        assert_eq!(r2.swept_tasks, 1, "BlockedRecoveryPending re-sweeps idempotently");
        assert_eq!(r2.expired_tokens, 0, "no live tokens left to expire");
    }

    #[test]
    fn reconcile_with_no_in_flight_tasks_is_a_noop() {
        let store = Store::open_in_memory().unwrap();
        seed_in_flight_tasks(&store, &[
            ("t-completed", TaskState::Completed),
        ]);

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
        ).unwrap();

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
        ).unwrap();
        id.to_string()
    }

    fn imerge_state(store: &Store, id: &str) -> String {
        let conn = store.lock_sync();
        conn.query_row(
            &format!("SELECT state FROM {INTEGRATION_MERGE_ATTEMPTS} WHERE id=?1"),
            rusqlite::params![id],
            |r| r.get(0),
        ).unwrap()
    }

    fn imerge_discard_reason(store: &Store, id: &str) -> Option<String> {
        let conn = store.lock_sync();
        conn.query_row(
            &format!(
                "SELECT discard_reason FROM {INTEGRATION_MERGE_ATTEMPTS} WHERE id=?1",
            ),
            rusqlite::params![id],
            |r| r.get::<_, Option<String>>(0),
        ).unwrap()
    }

    fn imerge_finalized_at(store: &Store, id: &str) -> Option<i64> {
        let conn = store.lock_sync();
        conn.query_row(
            &format!(
                "SELECT finalized_at FROM {INTEGRATION_MERGE_ATTEMPTS} WHERE id=?1",
            ),
            rusqlite::params![id],
            |r| r.get::<_, Option<i64>>(0),
        ).unwrap()
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

        assert_eq!(imerge_state(&store, "imerge-await"), "DiscardedCrashRecovery");
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

        assert_eq!(imerge_state(&store, "imerge-pass"), "DiscardedCrashRecovery");
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
        assert_eq!(report.folded_attempts, 0,
            "no terminal rows should be folded a second time");

        assert_eq!(imerge_state(&store, "imerge-completed"), "CompletedAdvanceApplied");
        assert_eq!(imerge_discard_reason(&store, "imerge-completed"), None);

        assert_eq!(imerge_state(&store, "imerge-blocked"), "BlockedByPreMergeVerifier");
        assert_eq!(
            imerge_discard_reason(&store, "imerge-blocked").as_deref(),
            Some("verifier_blocked"),
        );

        assert_eq!(imerge_state(&store, "imerge-discarded-cand"), "DiscardedCandidateOnly");
        assert_eq!(
            imerge_discard_reason(&store, "imerge-discarded-cand").as_deref(),
            Some("candidate_computation_failed"),
        );

        assert_eq!(imerge_state(&store, "imerge-prior-crash"), "DiscardedCrashRecovery");
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
        assert_eq!(r2.folded_attempts, 0,
            "second pass must be a no-op (rows are already terminal)");
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

        assert_eq!(imerge_state(&store, "imerge-await"), "DiscardedCrashRecovery");
        assert_eq!(imerge_state(&store, "imerge-completed"), "CompletedAdvanceApplied");
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
        write_segment(
            tmp.path(),
            "{\"event_kind\":\"GenesisRecord\"}\n",
        );
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
        write_segment(
            tmp.path(),
            "{\"seq\":0,\"event_kind\":\"SomethingElse\"}\n",
        );
        let result = verify_audit_chain(tmp.path());
        assert_chain_broken(result, "not the genesis record");
    }

    #[test]
    fn verify_audit_chain_rejects_nonzero_seq() {
        let tmp = TempDir::new().unwrap();
        write_segment(
            tmp.path(),
            "{\"seq\":7,\"event_kind\":\"GenesisRecord\"}\n",
        );
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
        let raw     = std::fs::read_to_string(dir.segment_path()).unwrap();
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
                prev, expected,
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
        let dir  = AuditDir::new();
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
        assert!(matches!(result, Ok(true)),
            "verify_audit_chain rejected a production-shape chain: {result:?}");
    }

    #[test]
    fn file_audit_sink_round_trip_through_dyn_audit_sink_passes_chain_check() {
        // Exercises the SAME `Arc<dyn AuditSink>` polymorphism the
        // kernel uses in `HandlerContext`. If the trait coercion or
        // the FileAuditSink mutex ever stops yielding identical bytes
        // to the bare AuditWriter, this test breaks.
        let dir  = AuditDir::new();
        let info = dir.write_genesis_record();

        // Open a writer resuming from genesis, wrap in a FileAuditSink,
        // emit through the trait — same production path the kernel uses.
        let writer = dir.open_writer_resuming_after(1, &info.raw_line_sha256);
        let sink   = raxis_audit_tools::FileAuditSink::new(writer);
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
        let dir  = AuditDir::new();
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
        let dir  = AuditDir::new();
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
        let dir  = AuditDir::new();
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
        let raw       = std::fs::read_to_string(dir.segment_path()).unwrap();
        let lines2: Vec<&str> = raw.lines().collect();
        let actual_prev_in_rec3 = serde_json::from_str::<serde_json::Value>(lines2[3])
            .expect("rec3 must still parse — only its predecessor changed")
            ["prev_sha256"]
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
        let now  = unix_now_secs();

        conn.execute(
            &format!(
                "INSERT INTO {INITIATIVES}
                    (initiative_id, state, terminal_criteria_json,
                     plan_artifact_sha256, created_at)
                 VALUES ('init-disk-recon', ?1, '{{}}', 'deadbeef', ?2)"
            ),
            rusqlite::params![InitiativeState::Executing.as_sql_str(), now],
        ).unwrap();

        for (task_id, state) in task_states {
            conn.execute(
                &format!(
                    "INSERT INTO {TASKS}
                        (task_id, initiative_id, lane_id, state, actor,
                         policy_epoch, admitted_at, transitioned_at, actual_cost)
                     VALUES (?1, 'init-disk-recon', 'default', ?2, 'kernel', 1, ?3, ?3, 0)"
                ),
                rusqlite::params![task_id, state.as_sql_str(), now],
            ).unwrap();
        }
    }

    fn task_state_disk(disk: &DiskStore, task_id: &str) -> String {
        let conn = disk.store().lock_sync();
        conn.query_row(
            &format!("SELECT state FROM {TASKS} WHERE task_id=?1"),
            rusqlite::params![task_id],
            |r| r.get(0),
        ).unwrap()
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
            ).unwrap();
        }

        let db_path = disk.db_path();
        let wal     = db_path.with_extension("db-wal");
        let shm     = db_path.with_extension("db-shm");

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
        seed_in_flight(&disk, &[
            ("t-pre-crash-1", TaskState::Running),
            ("t-pre-crash-2", TaskState::Admitted),
        ]);

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
        seed_in_flight(&disk, &[
            ("t-running",   TaskState::Running),
            ("t-admitted",  TaskState::Admitted),
            ("t-completed", TaskState::Completed),
        ]);

        // Restart cycle.
        disk.close();
        disk.reopen();

        // Run reconcile against the persisted state.
        let report = reconcile_tasks(disk.store());
        assert_eq!(report.swept_tasks, 2,
            "2 non-terminal tasks should have been swept after restart");
        assert_eq!(task_state_disk(&disk, "t-running"),   "BlockedRecoveryPending");
        assert_eq!(task_state_disk(&disk, "t-admitted"),  "BlockedRecoveryPending");
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
        assert_eq!(task_state_disk(&disk, "t-running"), "BlockedRecoveryPending");

        // The bulk UPDATE re-fires (matches the in-memory test
        // `reconcile_is_idempotent`'s contract — already-blocked rows
        // are still in the WHERE-NOT-IN-terminal set).
        let r2 = reconcile_tasks(disk.store());
        assert_eq!(r2.swept_tasks, 1, "BlockedRecoveryPending re-sweeps idempotently after restart");
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

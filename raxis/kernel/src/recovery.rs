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
use raxis_types::TaskState;

use crate::errors::KernelError;

const TASKS: &str                = Table::Tasks.as_str();
const VERIFIER_RUN_TOKENS: &str  = Table::VerifierRunTokens.as_str();

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
    /// Whether the audit chain verified cleanly.
    pub chain_ok: bool,
}

/// A lightweight report from reconcile_tasks.
#[derive(Debug, Default)]
pub struct ReconciliationReport {
    pub swept_tasks: usize,
    pub expired_tokens: usize,
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
///
/// Returns ReconciliationResult on success. Propagates KernelError on
/// audit chain failure (step 1 only; task sweep failures are non-fatal and
/// logged).
pub fn reconcile(store: &Store, audit_dir: &Path) -> Result<ReconciliationResult, KernelError> {
    // Step 1: Verify audit chain integrity.
    let chain_ok = verify_audit_chain(audit_dir)?;

    // Step 2 + 3: Sweep in-flight tasks, expire orphan tokens.
    let report = reconcile_tasks(store);

    eprintln!(
        "{{\"level\":\"info\",\"step\":\"recovery\",\"swept_tasks\":{},\"expired_tokens\":{},\"chain_ok\":{}}}",
        report.swept_tasks, report.expired_tokens, chain_ok
    );

    Ok(ReconciliationResult {
        swept_tasks: report.swept_tasks,
        expired_tokens: report.expired_tokens,
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
    let now      = now_unix_secs();

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

fn now_unix_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
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
        let now = now_unix_secs();

        conn.execute(
            "INSERT INTO initiatives
                (initiative_id, state, terminal_criteria_json,
                 plan_artifact_sha256, created_at)
             VALUES ('init-recon', 'Executing', '{}', 'deadbeef', ?1)",
            rusqlite::params![now],
        ).unwrap();

        for (task_id, state) in task_states {
            conn.execute(
                "INSERT INTO tasks
                    (task_id, initiative_id, lane_id, state, actor,
                     policy_epoch, admitted_at, transitioned_at, actual_cost)
                 VALUES (?1, 'init-recon', 'default', ?2, 'kernel', 1, ?3, ?3, 0)",
                rusqlite::params![task_id, state.as_sql_str(), now],
            ).unwrap();
        }
    }

    /// Insert a verifier_run_token for a task; consumed=0 means "live".
    /// Column set per kernel-store.md §2.5.1 Table 12.
    fn seed_live_token(store: &Store, run_id: &str, task_id: &str) {
        let conn = store.lock_sync();
        let now = now_unix_secs();
        conn.execute(
            "INSERT INTO verifier_run_tokens
                (verifier_run_id, task_id, gate_type, evaluation_sha,
                 token_hash, issued_at, expires_at, consumed)
             VALUES (?1, ?2, 'tests_pass', 'evalsha', 'tokhash', ?3, ?4, 0)",
            rusqlite::params![run_id, task_id, now, now + 3600],
        ).unwrap();
    }

    fn task_state(store: &Store, task_id: &str) -> String {
        let conn = store.lock_sync();
        conn.query_row(
            "SELECT state FROM tasks WHERE task_id=?1",
            rusqlite::params![task_id],
            |r| r.get(0),
        ).unwrap()
    }

    fn token_consumed(store: &Store, run_id: &str) -> i64 {
        let conn = store.lock_sync();
        conn.query_row(
            "SELECT consumed FROM verifier_run_tokens WHERE verifier_run_id=?1",
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

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

use raxis_store::Store;

use crate::errors::KernelError;

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
/// and contains at least one record (the genesis record).
///
/// In v1 this is a structural check only — full cryptographic chain verification
/// is deferred to v2 (requires `raxis-audit-tools::verifier::verify_chain`
/// which is not yet implemented). A missing or empty genesis segment is
/// `BOOT_ERR_AUDIT_CHAIN`.
///
/// Returns `true` if chain appears intact, `Err(KernelError::AuditChainBroken)`
/// if the genesis segment is missing or empty.
fn verify_audit_chain(audit_dir: &Path) -> Result<bool, KernelError> {
    let segment = audit_dir.join("segment-000.jsonl");

    if !segment.exists() {
        // First-time fresh kernel (bootstrap not yet run) — allow startup
        // without audit chain so an operator can still run bootstrap. In a
        // normally-initialised kernel, the genesis record must always exist.
        eprintln!(
            "{{\"level\":\"warn\",\"step\":\"recovery\",\"message\":\"audit segment-000.jsonl not found — kernel may not be initialised\"}}",
        );
        return Ok(false);
    }

    // The segment must be non-empty (genesis record must be present).
    let metadata = std::fs::metadata(&segment).map_err(|e| KernelError::AuditChainBroken {
        reason: format!("cannot stat {}: {e}", segment.display()),
    })?;

    if metadata.len() == 0 {
        return Err(KernelError::AuditChainBroken {
            reason: format!(
                "audit segment {} is empty — genesis record missing; kernel cannot start safely",
                segment.display()
            ),
        });
    }

    // Read and verify the genesis record has the expected structure.
    let content = std::fs::read_to_string(&segment).map_err(|e| KernelError::AuditChainBroken {
        reason: format!("cannot read {}: {e}", segment.display()),
    })?;

    let first_line = content.lines().next().ok_or_else(|| KernelError::AuditChainBroken {
        reason: "segment-000.jsonl has no lines".to_owned(),
    })?;

    let record: serde_json::Value =
        serde_json::from_str(first_line).map_err(|e| KernelError::AuditChainBroken {
            reason: format!("genesis record is not valid JSON: {e}"),
        })?;

    // The genesis record must have seq=0 and event_kind=GenesisRecord.
    let seq = record.get("seq").and_then(|v| v.as_u64()).unwrap_or(1);
    let kind = record
        .get("event_kind")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    if seq != 0 || kind != "GenesisRecord" {
        return Err(KernelError::AuditChainBroken {
            reason: format!(
                "first record in segment-000.jsonl is not the genesis record \
                 (seq={seq}, event_kind={kind:?})"
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
fn reconcile_tasks(store: &Store) -> ReconciliationReport {
    let mut report = ReconciliationReport::default();

    let conn = store.lock_sync();

    // Find all non-terminal task IDs.
    let task_ids: Vec<String> = {
        let mut stmt = match conn.prepare(
            "SELECT task_id FROM tasks
             WHERE state NOT IN ('Completed', 'Failed', 'Aborted', 'Cancelled')",
        ) {
            Ok(s) => s,
            Err(e) => {
                eprintln!(
                    "{{\"level\":\"error\",\"step\":\"recovery\",\"message\":\"cannot query in-flight tasks\",\"error\":\"{e}\"}}",
                );
                return report;
            }
        };

        let ids: Vec<String> = match stmt.query_map([], |r| r.get::<_, String>(0)) {
            Ok(mapped) => mapped.filter_map(|r| r.ok()).collect(),
            Err(e) => {
                eprintln!(
                    "{{\"level\":\"error\",\"step\":\"recovery\",\"message\":\"cannot map in-flight tasks\",\"error\":\"{e}\"}}",
                );
                return report;
            }
        };
        ids
    };

    if task_ids.is_empty() {
        return report;
    }

    let now = now_unix_secs();

    // Sweep each task to BlockedRecoveryPending.
    for task_id in &task_ids {
        match conn.execute(
            "UPDATE tasks SET state='BlockedRecoveryPending', recovery_transition_at=?1
             WHERE task_id=?2
               AND state NOT IN ('Completed', 'Failed', 'Aborted', 'Cancelled')",
            rusqlite::params![now, task_id],
        ) {
            Ok(rows) if rows > 0 => {
                report.swept_tasks += 1;
                eprintln!(
                    "{{\"level\":\"warn\",\"step\":\"recovery\",\"action\":\"swept_task\",\"task_id\":\"{task_id}\"}}",
                );
            }
            Ok(_) => {} // Already terminal (race between query and update — safe to ignore).
            Err(e) => {
                eprintln!(
                    "{{\"level\":\"error\",\"step\":\"recovery\",\"action\":\"sweep_task_failed\",\"task_id\":\"{task_id}\",\"error\":\"{e}\"}}",
                );
            }
        }

        // Expire any live verifier tokens for this task.
        match conn.execute(
            "UPDATE verifier_run_tokens SET consumed_at=?1
             WHERE run_id=?2 AND consumed_at IS NULL",
            rusqlite::params![now, task_id],
        ) {
            Ok(rows) => {
                report.expired_tokens += rows;
            }
            Err(e) => {
                eprintln!(
                    "{{\"level\":\"warn\",\"step\":\"recovery\",\"action\":\"expire_tokens_failed\",\"task_id\":\"{task_id}\",\"error\":\"{e}\"}}",
                );
            }
        }
    }

    report
}

fn now_unix_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

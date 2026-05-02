// raxis-kernel::initiatives::lifecycle — Initiative and task FSM operations.
//
// Normative reference: kernel-core.md §2.3 operator IPC dispatcher and
// kernel-store.md §2.5.1 Table 2 (initiatives) + Table 5 (tasks) DDL.
//
// CANONICAL STATE NAMES from DDL Table 2 CHECK constraint:
//   'Draft', 'ApprovedPlan', 'Executing', 'Blocked', 'Completed', 'Failed', 'Aborted'
// (NOT 'PlanSubmitted' — that name appeared in draft specs only. DDL wins.)
//
// OPERATOR-DRIVEN lifecycle:
//   create_initiative() — submit plan bytes + Ed25519 sig → Draft row
//   approve_plan()      — verify sig, promote to Executing, admit all tasks
//   reject_plan()       — set state = Aborted (rejection is terminal, no dedicated state)
//   abort_initiative()  — set state = Aborted, cancel all non-terminal tasks
//   abort_task()        — cancel a single task inside an Executing initiative
//   retry_task()        — transition a Failed task back to Admitted
//
// All writes are atomic (single SQLite connection lock per operation).
//
// Separate tables:
//   initiatives   — initiative-level lifecycle (state, plan metadata)
//   signed_plan_artifacts — immutable plan bytes + sig (separate from initiatives)
//   tasks         — task rows, FK to initiatives

use raxis_audit_tools::{AuditEventKind, AuditSink};
use raxis_store::{Store, Table};
use raxis_types::{InitiativeState, TaskState};

use crate::authority::keys::AuthorityError;
use crate::scheduler::{self, SchedulerError};

// Table name consts — one definition, used everywhere below.
const INITIATIVES: &str            = Table::Initiatives.as_str();
const SIGNED_PLAN_ARTIFACTS: &str  = Table::SignedPlanArtifacts.as_str();
const TASKS: &str                  = Table::Tasks.as_str();

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum LifecycleError {
    #[error("initiative not found: {initiative_id}")]
    InitiativeNotFound { initiative_id: String },

    #[error("initiative is in terminal state: {current_state}")]
    InitiativeTerminal { current_state: String },

    #[error("task not found: {task_id}")]
    TaskNotFound { task_id: String },

    #[error("task is not in Failed state (current: {current_state})")]
    TaskNotFailed { current_state: String },

    #[error("task is not retryable (current: {current_state})")]
    TaskNotRetryable { current_state: String },

    #[error("task is not abortable (current: {current_state})")]
    TaskNotAbortable { current_state: String },

    #[error("plan signature verification failed: {reason}")]
    PlanSignatureInvalid { reason: String },

    #[error("plan TOML invalid: {reason}")]
    PlanInvalid { reason: String },

    #[error("scheduler error during admission: {0}")]
    Scheduler(#[from] SchedulerError),

    #[error("store error: {0}")]
    Store(#[from] raxis_store::StoreError),

    #[error("store SQL error: {0}")]
    Sql(#[from] rusqlite::Error),
}

impl From<AuthorityError> for LifecycleError {
    fn from(e: AuthorityError) -> Self {
        LifecycleError::Store(raxis_store::StoreError::Invariant(e.to_string()))
    }
}

// ---------------------------------------------------------------------------
// Public result types
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub struct InitiativeCreated {
    pub initiative_id: String,
    /// Always "Draft" in v1.
    pub status: String,
}

#[derive(Debug)]
pub struct PlanApproved {
    pub initiative_id: String,
    pub tasks_admitted: usize,
}

// ---------------------------------------------------------------------------
// create_initiative — submit a plan for operator review
// ---------------------------------------------------------------------------

/// Submit a plan document for this initiative.
///
/// - `plan_toml`: raw plan bytes (TOML text).
/// - `plan_sig_hex`: hex-encoded Ed25519 signature over the plan bytes.
/// - `submitted_by`: operator fingerprint for audit.
///
/// Creates:
///   - initiatives row in `Draft` state (DDL canonical; NOT 'PlanSubmitted').
///   - signed_plan_artifacts row with the raw plan bytes + signature.
///
/// Signature verification is deferred to `approve_plan` so the operator
/// can submit and inspect before approving.
pub fn create_initiative(
    plan_toml:    &str,
    plan_sig_hex: &str,
    submitted_by: &str,
    store: &Store,
) -> Result<InitiativeCreated, LifecycleError> {
    let initiative_id  = uuid::Uuid::new_v4().to_string();
    let plan_sha256    = raxis_crypto::token::sha256_hex(plan_toml.as_bytes());
    let now            = now_unix_secs();

    // terminal_criteria_json: empty JSON object in v1 (operator-driven terminal
    // criteria not yet configured at submission time).
    let terminal_criteria = "{}";

    let conn = store.lock_sync();

    conn.execute(
        &format!(
            "INSERT INTO {INITIATIVES}
                (initiative_id, state, terminal_criteria_json,
                 plan_artifact_sha256, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)"
        ),
        rusqlite::params![
            &initiative_id,
            InitiativeState::Draft.as_sql_str(),
            terminal_criteria,
            &plan_sha256,
            now,
        ],
    )?;

    // Reject malformed hex up-front rather than silently storing an empty
    // `plan_sig` (which would later fail signature verification with a
    // misleading "Ed25519 signature verification failed" error and obscure
    // the real cause). Surfaces as `PlanInvalid` so the operator sees the
    // actual problem.
    let sig_bytes = hex::decode(plan_sig_hex).map_err(|e| LifecycleError::PlanInvalid {
        reason: format!("plan signature is not valid hex: {e}"),
    })?;
    if sig_bytes.len() != 64 {
        return Err(LifecycleError::PlanInvalid {
            reason: format!(
                "plan signature must be 64 bytes (Ed25519); got {} bytes",
                sig_bytes.len()
            ),
        });
    }
    conn.execute(
        &format!(
            "INSERT INTO {SIGNED_PLAN_ARTIFACTS}
                (initiative_id, plan_bytes, plan_sig, stored_at)
             VALUES (?1, ?2, ?3, ?4)"
        ),
        rusqlite::params![
            &initiative_id,
            plan_toml.as_bytes(),
            &sig_bytes,
            now,
        ],
    )?;

    eprintln!(
        "{{\"level\":\"info\",\"event\":\"InitiativeCreated\",\
         \"initiative_id\":\"{initiative_id}\",\"submitted_by\":\"{submitted_by}\"}}",
    );

    Ok(InitiativeCreated {
        initiative_id,
        status: "Draft".to_owned(),
    })
}

// ---------------------------------------------------------------------------
// approve_plan — verify sig, admit tasks, promote to Executing
// ---------------------------------------------------------------------------

/// Approve a plan: verify the operator Ed25519 signature, parse task definitions
/// from the plan TOML, admit all tasks (insert task rows + DAG edges in
/// Admitted state), and transition the initiative from `Draft` to `Executing`.
///
/// Spec INV-INIT-01: task rows are derived from plan TOML at approval time.
///
/// **INV-STORE-02 (kernel-store.md §2.5.1, table row "approve_plan").**
/// All writes — the `initiatives` UPDATE, every `tasks` INSERT, and every
/// `task_dag_edges` INSERT — happen inside ONE `BEGIN`/`COMMIT` held under
/// ONE mutex acquisition. Failure on any task admit (cycle detected, FK
/// violation, lane validation) rolls back the entire transaction; the
/// initiative remains `Draft` and no partial task rows linger.
///
/// The audit event is intentionally emitted **after** `tx.commit()` per
/// kernel-store.md §2.5.2 ("SQLite committed first, JSONL appended second").
/// PR-8 will replace the `eprintln!` with `AuditWriter::append`.
pub fn approve_plan(
    initiative_id:         &str,
    approving_operator:    &str,
    operator_pubkey_bytes: &[u8],
    policy_epoch:          u64,
    store: &Store,
    audit: &dyn AuditSink,
) -> Result<PlanApproved, LifecycleError> {
    let mut conn = store.lock_sync();

    // ── Pre-tx reads (cheap, do not need to be in the tx) ────────────────
    // We read state + plan bytes + sig before BEGIN so a malformed sig or
    // a non-Draft initiative does not even start a transaction.
    let current_state: String = conn.query_row(
        &format!("SELECT state FROM {INITIATIVES} WHERE initiative_id=?1"),
        rusqlite::params![initiative_id],
        |r| r.get(0),
    ).map_err(|e| match e {
        rusqlite::Error::QueryReturnedNoRows => LifecycleError::InitiativeNotFound {
            initiative_id: initiative_id.to_owned(),
        },
        other => LifecycleError::Sql(other),
    })?;
    if current_state != InitiativeState::Draft.as_sql_str() {
        return Err(LifecycleError::InitiativeTerminal { current_state });
    }

    let (plan_bytes, plan_sig): (Vec<u8>, Vec<u8>) = conn.query_row(
        &format!("SELECT plan_bytes, plan_sig FROM {SIGNED_PLAN_ARTIFACTS} WHERE initiative_id=?1"),
        rusqlite::params![initiative_id],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;

    // Canonical Ed25519 verification per kernel-store.md §2.5.3 (the same
    // signing domain the CLI's `policy sign` constructs). Verifying raw
    // plan bytes — as an earlier draft did — would reject every CLI sig.
    raxis_crypto::plan::verify_plan_signature(operator_pubkey_bytes, &plan_bytes, &plan_sig)
        .map_err(|e| LifecycleError::PlanSignatureInvalid {
            reason: e.to_string(),
        })?;

    let plan_toml_str = String::from_utf8_lossy(&plan_bytes);
    let plan_tasks    = parse_plan_tasks(&plan_toml_str)?;
    let task_count    = plan_tasks.len();
    let now           = now_unix_secs();

    // ── INV-STORE-02 transaction ─────────────────────────────────────────
    // Everything below MUST commit or roll back as one unit.
    let tx = conn.transaction()?;

    // Defer FK enforcement until COMMIT. The intra-plan FK pattern is:
    //   task_dag_edges.predecessor_task_id → tasks(task_id)
    // and within a single plan, tasks frequently reference each other
    // (t2 depends on t1). We insert tasks one at a time, so the edge
    // (t1, t2) inserted while admitting t2 would fail FK if t1 were not
    // yet committed (it isn't — we're still inside the tx). Deferring
    // FK to COMMIT lets the entire plan land before validation, while
    // still rolling back on any unresolved reference at commit time.
    tx.execute_batch("PRAGMA defer_foreign_keys = 1;")?;

    // Re-check Draft inside the tx using a conditional UPDATE — this
    // closes the TOCTOU window between the pre-tx read and BEGIN. If a
    // concurrent caller already approved (or rejected) the initiative,
    // `rows == 0` and we error out cleanly.
    let rows = tx.execute(
        &format!(
            "UPDATE {INITIATIVES} SET state=?1, approved_at=?2
             WHERE initiative_id=?3 AND state=?4"
        ),
        rusqlite::params![
            InitiativeState::Executing.as_sql_str(),
            now,
            initiative_id,
            InitiativeState::Draft.as_sql_str(),
        ],
    )?;
    if rows == 0 {
        // Tx is dropped → automatic rollback. No state change.
        return Err(LifecycleError::InitiativeTerminal {
            current_state: "<changed concurrently>".to_owned(),
        });
    }

    // Admit every task. `admit_in_tx` owns no lock and no transaction; it
    // writes through the borrowed `&Connection` exposed by `tx`.
    for pt in plan_tasks {
        let task = scheduler::PlanTask {
            task_id:       pt.task_id.clone(),
            initiative_id: initiative_id.to_owned(),
            lane_id:       pt.lane_id,
            name:          pt.name,
            dependencies:  pt.predecessors,
        };
        scheduler::admit_in_tx(&tx, task, policy_epoch)?;
    }

    tx.commit()?;
    drop(conn); // release the store mutex before doing audit I/O.

    // Audit-after-commit per kernel-store.md §2.5.2. A failure here
    // produces a §2.5.2 "SQLite committed, JSONL not appended" gap that
    // recovery::reconcile detects and repairs via ReconciliationGap;
    // we therefore only log the failure here and return success — the
    // store is consistent and the operator's intent has been honoured.
    if let Err(e) = audit.emit(
        AuditEventKind::PlanApproved {
            initiative_id: initiative_id.to_owned(),
            task_count,
        },
        None,
        None,
        Some(initiative_id),
    ) {
        eprintln!(
            "{{\"level\":\"error\",\"event\":\"PlanApproved\",\"audit_emit_failed\":\"{e}\",\
             \"initiative_id\":\"{initiative_id}\",\"approving_operator\":\"{approving_operator}\"}}",
        );
    }

    Ok(PlanApproved {
        initiative_id: initiative_id.to_owned(),
        tasks_admitted: task_count,
    })
}

// ---------------------------------------------------------------------------
// reject_plan — operator explicitly rejects a Draft initiative
// ---------------------------------------------------------------------------

/// Reject a Draft initiative — transitions to Aborted (DDL has no 'Rejected' state;
/// 'Aborted' is the terminal state for operator-cancelled initiatives per the
/// DDL CHECK constraint in kernel-store.md §2.5.1 Table 2).
pub fn reject_plan(
    initiative_id: &str,
    rejected_by:   &str,
    _reason:       Option<&str>,
    store: &Store,
) -> Result<(), LifecycleError> {
    let conn = store.lock_sync();
    let rows = conn.execute(
        &format!(
            "UPDATE {INITIATIVES} SET state=?1
             WHERE initiative_id=?2 AND state=?3"
        ),
        rusqlite::params![
            InitiativeState::Aborted.as_sql_str(),
            initiative_id,
            InitiativeState::Draft.as_sql_str(),
        ],
    )?;
    if rows == 0 {
        // Could be: not found, or already past Draft state.
        return Err(LifecycleError::InitiativeNotFound {
            initiative_id: initiative_id.to_owned(),
        });
    }
    eprintln!(
        "{{\"level\":\"info\",\"event\":\"PlanRejected\",\
         \"initiative_id\":\"{initiative_id}\",\"rejected_by\":\"{rejected_by}\"}}",
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// abort_initiative — operator aborts an in-progress initiative
// ---------------------------------------------------------------------------

/// Abort an initiative — transitions to Aborted and cancels all non-terminal tasks.
pub fn abort_initiative(
    initiative_id: &str,
    aborted_by:    &str,
    store: &Store,
) -> Result<(), LifecycleError> {
    let conn = store.lock_sync();

    // Verify initiative exists and is not already terminal.
    let current_state: String = conn.query_row(
        &format!("SELECT state FROM {INITIATIVES} WHERE initiative_id=?1"),
        rusqlite::params![initiative_id],
        |r| r.get(0),
    ).map_err(|e| match e {
        rusqlite::Error::QueryReturnedNoRows => LifecycleError::InitiativeNotFound {
            initiative_id: initiative_id.to_owned(),
        },
        other => LifecycleError::Sql(other),
    })?;

    // Use InitiativeState::is_terminal() — no raw string matching.
    let parsed = InitiativeState::from_sql_str(&current_state)
        .ok_or_else(|| LifecycleError::InitiativeTerminal {
            current_state: current_state.clone(),
        })?;
    if parsed.is_terminal() {
        return Err(LifecycleError::InitiativeTerminal { current_state });
    }

    let now = now_unix_secs();

    // Cancel all non-terminal tasks atomically in the same connection lock.
    let cancel_state   = TaskState::Cancelled.as_sql_str();
    let terminal_not_in = [TaskState::Completed, TaskState::Failed, TaskState::Aborted, TaskState::Cancelled]
        .iter()
        .map(|s| format!("'{}'", s.as_sql_str()))
        .collect::<Vec<_>>()
        .join(", ");

    conn.execute(
        &format!(
            "UPDATE {TASKS} SET state='{cancel_state}', transitioned_at=?1
             WHERE initiative_id=?2 AND state NOT IN ({terminal_not_in})"
        ),
        rusqlite::params![now, initiative_id],
    )?;

    conn.execute(
        &format!(
            "UPDATE {INITIATIVES} SET state=?1, completed_at=?2
             WHERE initiative_id=?3"
        ),
        rusqlite::params![InitiativeState::Aborted.as_sql_str(), now, initiative_id],
    )?;

    eprintln!(
        "{{\"level\":\"info\",\"event\":\"InitiativeAborted\",\
         \"initiative_id\":\"{initiative_id}\",\"aborted_by\":\"{aborted_by}\"}}",
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// abort_task — operator cancels a single task
// ---------------------------------------------------------------------------

pub fn abort_task(
    task_id:    &str,
    aborted_by: &str,
    store: &Store,
) -> Result<(), LifecycleError> {
    let conn = store.lock_sync();
    let now  = now_unix_secs();

    let state: String = conn.query_row(
        &format!("SELECT state FROM {TASKS} WHERE task_id=?1"),
        rusqlite::params![task_id],
        |r| r.get(0),
    ).map_err(|e| match e {
        rusqlite::Error::QueryReturnedNoRows => LifecycleError::TaskNotFound {
            task_id: task_id.to_owned(),
        },
        other => LifecycleError::Sql(other),
    })?;

    let aborted_states = [TaskState::Completed, TaskState::Failed, TaskState::Aborted, TaskState::Cancelled]
        .map(|s| s.as_sql_str());
    if aborted_states.contains(&state.as_str()) {
        return Err(LifecycleError::TaskNotAbortable { current_state: state });
    }

    conn.execute(
        &format!(
            "UPDATE {TASKS} SET state=?1, transitioned_at=?2 WHERE task_id=?3"
        ),
        rusqlite::params![TaskState::Aborted.as_sql_str(), now, task_id],
    )?;

    eprintln!(
        "{{\"level\":\"info\",\"event\":\"TaskAborted\",\
         \"task_id\":\"{task_id}\",\"aborted_by\":\"{aborted_by}\"}}",
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// retry_task — operator retries a Failed task
// ---------------------------------------------------------------------------

/// Retry a Failed task — transition back to Admitted.
/// Uses `task_transitions::transition_task` to enforce FSM rules (INV-INIT-04).
pub fn retry_task(task_id: &str, store: &Store) -> Result<(), LifecycleError> {
    use crate::initiatives::task_transitions::{transition_task, TransitionActor};

    let conn = store.lock_sync();
    let state: String = conn.query_row(
        &format!("SELECT state FROM {TASKS} WHERE task_id=?1"),
        rusqlite::params![task_id],
        |r| r.get(0),
    ).map_err(|e| match e {
        rusqlite::Error::QueryReturnedNoRows => LifecycleError::TaskNotFound {
            task_id: task_id.to_owned(),
        },
        other => LifecycleError::Sql(other),
    })?;

    if state != TaskState::Failed.as_sql_str() {
        return Err(LifecycleError::TaskNotFailed { current_state: state });
    }
    drop(conn); // release lock before calling transition_task which re-acquires

    transition_task(task_id, TaskState::Admitted, None, TransitionActor::Kernel, store)
        .map_err(|e| LifecycleError::Store(raxis_store::StoreError::Invariant(e.to_string())))?;

    eprintln!(
        "{{\"level\":\"info\",\"event\":\"TaskRetried\",\"task_id\":\"{task_id}\"}}",
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

/// One task entry parsed from a plan TOML `[[tasks]]` array.
///
/// Spec reference: cli-ceremony.md §4.3 fixture format. `predecessors` is read
/// from the TOML; v1 implementation uses it to populate `task_dag_edges` rows
/// per INV-INIT-03 (`kernel-core.md` §8 Task DAG semantics).
#[derive(Debug, Clone, PartialEq, Eq)]
struct PlanTask {
    task_id:      String,
    name:         String,
    lane_id:      String,
    predecessors: Vec<String>,
}

/// Parse `[[tasks]]` array from plan TOML.
///
/// Required: `task_id`.
/// Optional: `name` (defaults to `task_id`), `lane_id` (defaults to `"default"`),
///           `predecessors` (defaults to empty list).
fn parse_plan_tasks(plan_toml: &str) -> Result<Vec<PlanTask>, LifecycleError> {
    let doc: toml::Value = toml::from_str(plan_toml).map_err(|e| LifecycleError::PlanInvalid {
        reason: format!("TOML parse error: {e}"),
    })?;

    let tasks_array = doc
        .get("tasks")
        .and_then(|v| v.as_array())
        .ok_or_else(|| LifecycleError::PlanInvalid {
            reason: "plan TOML missing [[tasks]] array".to_owned(),
        })?;

    let mut tasks = Vec::with_capacity(tasks_array.len());
    for (i, entry) in tasks_array.iter().enumerate() {
        let task_id = entry
            .get("task_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| LifecycleError::PlanInvalid {
                reason: format!("tasks[{i}] missing task_id"),
            })?
            .to_owned();
        let name    = entry.get("name").and_then(|v| v.as_str()).unwrap_or(&task_id).to_owned();
        let lane_id = entry.get("lane_id").and_then(|v| v.as_str()).unwrap_or("default").to_owned();

        // predecessors: optional array of task_id strings (DAG edges).
        let predecessors: Vec<String> = entry
            .get("predecessors")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|p| p.as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default();

        tasks.push(PlanTask { task_id, name, lane_id, predecessors });
    }

    Ok(tasks)
}

// `admit_task` (private helper) was removed: task insertion is now done by
// `scheduler::admit_in_tx`, which inserts both the task row AND its DAG
// edges inside the surrounding transaction. The old helper inserted only
// the task row, which silently dropped every `task_dag_edges` row a plan
// declared — a violation of kernel-store.md §2.5.1 line 384 ("All edges
// for an initiative are inserted by approve_plan alongside the task rows,
// in the same transaction").

fn now_unix_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_plan_tasks_requires_task_id() {
        // Entry without task_id must produce PlanInvalid error.
        let toml = "[[tasks]]\nname = \"no-id\"\n";
        let err = parse_plan_tasks(toml).unwrap_err();
        assert!(err.to_string().contains("task_id"));
    }

    #[test]
    fn parse_plan_tasks_empty_array_ok() {
        let toml = "[meta]\nversion = 1\n[[tasks]]\ntask_id = \"t1\"\n";
        let tasks = parse_plan_tasks(toml).unwrap();
        assert_eq!(tasks.len(), 1);
        assert_eq!(tasks[0].task_id, "t1");
    }

    #[test]
    fn parse_plan_tasks_lane_defaults_to_default() {
        let toml = "[[tasks]]\ntask_id = \"t2\"\n";
        let tasks = parse_plan_tasks(toml).unwrap();
        assert_eq!(tasks[0].lane_id, "default");
    }

    #[test]
    fn parse_plan_tasks_name_defaults_to_task_id() {
        let toml = "[[tasks]]\ntask_id = \"t3\"\n";
        let tasks = parse_plan_tasks(toml).unwrap();
        assert_eq!(tasks[0].name, "t3");
    }

    #[test]
    fn parse_plan_tasks_missing_tasks_array_is_error() {
        let toml = "[meta]\nversion = 1\n";
        assert!(parse_plan_tasks(toml).is_err());
    }

    #[test]
    fn lifecycle_error_initiative_not_found_display() {
        let e = LifecycleError::InitiativeNotFound { initiative_id: "i-1".into() };
        assert!(e.to_string().contains("i-1"));
    }

    #[test]
    fn lifecycle_error_task_not_failed_display() {
        let e = LifecycleError::TaskNotFailed { current_state: "Running".into() };
        assert!(e.to_string().contains("Running"));
    }

    // ───────────────────────────────────────────────────────────────────
    //  approve_plan — INV-STORE-02 atomicity tests
    //
    // These tests verify the spec contract from kernel-store.md §2.5.1
    // (table row "approve_plan"): every initiatives UPDATE, every tasks
    // INSERT, and every task_dag_edges INSERT either all commit together
    // or none do.
    // ───────────────────────────────────────────────────────────────────

    use ed25519_dalek::{Signer, SigningKey};
    use raxis_audit_tools::FakeAuditSink;
    use raxis_store::Store;

    /// Deterministic Ed25519 keypair for fixtures (no entropy needed).
    fn fixture_keypair() -> (SigningKey, [u8; 32]) {
        let sk = SigningKey::from_bytes(&[0x42u8; 32]);
        let pk = sk.verifying_key().to_bytes();
        (sk, pk)
    }

    /// Build a Draft initiative + signed_plan_artifacts row directly (no
    /// IPC), returning everything the test needs to call `approve_plan`.
    fn seed_draft_initiative(
        store:      &Store,
        plan_toml:  &str,
        sk:         &SigningKey,
    ) -> (String, Vec<u8>) {
        let initiative_id = "init-test".to_owned();
        let plan_bytes    = plan_toml.as_bytes().to_vec();
        let signing_input = raxis_crypto::plan::plan_signing_input(&plan_bytes);
        let sig_bytes     = sk.sign(&signing_input).to_bytes().to_vec();
        let plan_sha      = raxis_crypto::plan::plan_artifact_sha256(&plan_bytes);
        let pk_bytes      = sk.verifying_key().to_bytes();
        let now           = now_unix_secs();

        let conn = store.lock_sync();
        // initiatives row in Draft. terminal_criteria_json is NOT NULL
        // per kernel-store.md §2.5.1 Table 2; an empty JSON object is the
        // canonical "no criteria yet" placeholder.
        conn.execute(
            &format!(
                "INSERT INTO {INITIATIVES}
                    (initiative_id, state, terminal_criteria_json,
                     plan_artifact_sha256, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)"
            ),
            rusqlite::params![
                &initiative_id,
                InitiativeState::Draft.as_sql_str(),
                "{}",
                &plan_sha,
                now,
            ],
        ).unwrap();

        // signed_plan_artifacts: column set per kernel-store.md §2.5.1 Table 3
        // is exactly (initiative_id, plan_bytes, plan_sig, stored_at).
        conn.execute(
            &format!(
                "INSERT INTO {SIGNED_PLAN_ARTIFACTS}
                    (initiative_id, plan_bytes, plan_sig, stored_at)
                 VALUES (?1, ?2, ?3, ?4)"
            ),
            rusqlite::params![&initiative_id, &plan_bytes, &sig_bytes, now],
        ).unwrap();
        drop(conn);

        (initiative_id, pk_bytes.to_vec())
    }

    /// Count rows in a table where `initiative_id = ?` (for assertions).
    fn count_initiative_rows(store: &Store, table: &str, init_id: &str) -> i64 {
        let conn = store.lock_sync();
        conn.query_row(
            &format!("SELECT COUNT(*) FROM {table} WHERE initiative_id=?1"),
            rusqlite::params![init_id],
            |r| r.get(0),
        ).unwrap()
    }

    /// Count edges that mention any task in the given initiative.
    fn count_edges_for_initiative(store: &Store, init_id: &str) -> i64 {
        let conn = store.lock_sync();
        conn.query_row(
            &format!(
                "SELECT COUNT(*) FROM task_dag_edges e
                   JOIN tasks t ON t.task_id = e.successor_task_id
                  WHERE t.initiative_id = ?1"
            ),
            rusqlite::params![init_id],
            |r| r.get(0),
        ).unwrap()
    }

    fn read_initiative_state(store: &Store, init_id: &str) -> String {
        let conn = store.lock_sync();
        conn.query_row(
            &format!("SELECT state FROM {INITIATIVES} WHERE initiative_id=?1"),
            rusqlite::params![init_id],
            |r| r.get(0),
        ).unwrap()
    }

    // NOTE on test attribute choice: these tests use `#[test]`, not
    // `#[tokio::test]`, because `approve_plan` is a sync function that
    // acquires the store mutex via `Store::lock_sync()` → `blocking_lock`.
    // tokio's `blocking_lock` panics if invoked from a thread already
    // driving an async runtime. In production, the operator handler
    // wraps the call in `tokio::task::spawn_blocking`; in tests we
    // simply call from a non-async thread.
    #[test]
    fn approve_plan_happy_path_inserts_tasks_and_edges() {
        let store = Store::open_in_memory().unwrap();
        let (sk, _pk) = fixture_keypair();

        // Plan with two tasks — t2 depends on t1 (one DAG edge).
        let plan = r#"
            [meta]
            version = 1

            [[tasks]]
            task_id  = "t1"
            name     = "first"
            lane_id  = "default"

            [[tasks]]
            task_id      = "t2"
            name         = "second"
            lane_id      = "default"
            predecessors = ["t1"]
        "#;
        let (init_id, pk_bytes) = seed_draft_initiative(&store, plan, &sk);
        let audit = FakeAuditSink::new();

        let result = approve_plan(&init_id, "op-test", &pk_bytes, 1, &store, &audit).unwrap();
        assert_eq!(result.tasks_admitted, 2);

        assert_eq!(read_initiative_state(&store, &init_id), "Executing");
        assert_eq!(count_initiative_rows(&store, "tasks", &init_id), 2);
        assert_eq!(
            count_edges_for_initiative(&store, &init_id), 1,
            "one DAG edge (t1 → t2) should be inserted alongside the task rows",
        );

        // Audit-after-commit per kernel-store.md §2.5.2: PlanApproved emits
        // exactly once, with the initiative_id wired through.
        let events = audit.events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind.as_str(), "PlanApproved");
        assert_eq!(events[0].initiative_id.as_deref(), Some(init_id.as_str()));
    }

    #[test]
    fn approve_plan_rolls_back_on_cyclic_dependency() {
        // Cycle: t1 depends on t2, t2 depends on t1. detect_cycle_in must
        // reject this and the entire transaction must roll back: the
        // initiative stays Draft and no tasks/edges are persisted.
        let store = Store::open_in_memory().unwrap();
        let (sk, _) = fixture_keypair();

        let plan = r#"
            [meta]
            version = 1

            [[tasks]]
            task_id      = "t1"
            predecessors = ["t2"]

            [[tasks]]
            task_id      = "t2"
            predecessors = ["t1"]
        "#;
        let (init_id, pk_bytes) = seed_draft_initiative(&store, plan, &sk);
        let audit = FakeAuditSink::new();

        let err = approve_plan(&init_id, "op-test", &pk_bytes, 1, &store, &audit).unwrap_err();
        assert!(
            matches!(err, LifecycleError::Scheduler(SchedulerError::CyclicDependency)),
            "expected CyclicDependency, got {err:?}",
        );

        // INV-STORE-02 atomicity: nothing partial.
        assert_eq!(
            read_initiative_state(&store, &init_id), "Draft",
            "initiative must remain Draft on cycle rejection",
        );
        assert_eq!(
            count_initiative_rows(&store, "tasks", &init_id), 0,
            "no task rows may be persisted when the tx rolls back",
        );
        assert_eq!(
            count_edges_for_initiative(&store, &init_id), 0,
            "no edges may be persisted when the tx rolls back",
        );

        // Audit-after-commit invariant: a rolled-back operation MUST NOT
        // produce a PlanApproved record.
        assert!(audit.events().is_empty(),
                "no audit events may be emitted when the tx rolls back");
    }

    #[test]
    fn approve_plan_rejects_bad_signature_without_starting_tx() {
        let store = Store::open_in_memory().unwrap();
        let (sk, _) = fixture_keypair();
        let plan = r#"
            [[tasks]]
            task_id = "t1"
        "#;
        let (init_id, _correct_pk) = seed_draft_initiative(&store, plan, &sk);

        // Hand `approve_plan` a different pubkey — sig will fail to verify.
        let wrong_pk = SigningKey::from_bytes(&[0x99u8; 32]).verifying_key().to_bytes();
        let audit   = FakeAuditSink::new();
        let err = approve_plan(&init_id, "op-test", &wrong_pk, 1, &store, &audit).unwrap_err();
        assert!(
            matches!(err, LifecycleError::PlanSignatureInvalid { .. }),
            "expected PlanSignatureInvalid, got {err:?}",
        );

        // No state change at all.
        assert_eq!(read_initiative_state(&store, &init_id), "Draft");
        assert_eq!(count_initiative_rows(&store, "tasks", &init_id), 0);
        assert!(audit.events().is_empty(),
                "audit must remain silent when the signature check fails");
    }

    #[test]
    fn approve_plan_is_idempotent_under_double_call() {
        // Calling approve_plan twice on the same Draft must succeed once
        // (Draft → Executing) and fail the second time (already Executing).
        // The second failure must NOT clobber the first call's state.
        let store = Store::open_in_memory().unwrap();
        let (sk, _) = fixture_keypair();
        let plan = r#"
            [[tasks]]
            task_id = "only"
        "#;
        let (init_id, pk_bytes) = seed_draft_initiative(&store, plan, &sk);
        let audit = FakeAuditSink::new();

        approve_plan(&init_id, "op-1", &pk_bytes, 1, &store, &audit).unwrap();
        let second = approve_plan(&init_id, "op-2", &pk_bytes, 1, &store, &audit);
        assert!(second.is_err(), "second approve must fail (not Draft)");

        assert_eq!(read_initiative_state(&store, &init_id), "Executing");
        assert_eq!(count_initiative_rows(&store, "tasks", &init_id), 1);

        // Exactly ONE PlanApproved emitted, despite two attempts. The
        // second (failed) call must NOT add an audit row.
        let approved: Vec<_> = audit.events()
            .into_iter()
            .filter(|e| e.kind.as_str() == "PlanApproved")
            .collect();
        assert_eq!(approved.len(), 1,
                   "PlanApproved must emit exactly once across both attempts");
    }

    #[test]
    fn approve_plan_records_correct_policy_epoch_on_tasks() {
        // policy_epoch column on `tasks` must equal what the caller passed —
        // not the hardcoded value that the OLD `admit_task` helper used.
        let store = Store::open_in_memory().unwrap();
        let (sk, _) = fixture_keypair();
        let plan = r#"[[tasks]]
        task_id = "t1"
        "#;
        let (init_id, pk_bytes) = seed_draft_initiative(&store, plan, &sk);
        let audit = FakeAuditSink::new();

        approve_plan(&init_id, "op", &pk_bytes, 42, &store, &audit).unwrap();

        let conn = store.lock_sync();
        let epoch: i64 = conn.query_row(
            "SELECT policy_epoch FROM tasks WHERE initiative_id=?1",
            rusqlite::params![&init_id],
            |r| r.get(0),
        ).unwrap();
        assert_eq!(epoch, 42, "policy_epoch must be the value passed to approve_plan");
    }
}

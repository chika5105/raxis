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

use std::path::PathBuf;

use raxis_store::Store;
use raxis_types::{InitiativeId, TaskId, TaskState};

use crate::authority::keys::AuthorityError;

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

    // Insert initiatives row — state = 'Draft' (DDL CHECK canonical).
    conn.execute(
        "INSERT INTO initiatives
            (initiative_id, state, terminal_criteria_json,
             plan_artifact_sha256, created_at)
         VALUES (?1, 'Draft', ?2, ?3, ?4)",
        rusqlite::params![
            &initiative_id,
            terminal_criteria,
            &plan_sha256,
            now,
        ],
    )?;

    // Insert signed_plan_artifacts row — FK references initiatives.
    let sig_bytes = hex::decode(plan_sig_hex).unwrap_or_default();
    conn.execute(
        "INSERT INTO signed_plan_artifacts
            (initiative_id, plan_bytes, plan_sig, stored_at)
         VALUES (?1, ?2, ?3, ?4)",
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
/// from the plan TOML, admit all tasks (insert task rows in Admitted state),
/// and transition the initiative from `Draft` to `Executing`.
///
/// Spec INV-INIT-01: task rows are derived from plan TOML at approval time.
pub fn approve_plan(
    initiative_id:      &str,
    approving_operator: &str,
    operator_pubkey_bytes: &[u8],
    store: &Store,
) -> Result<PlanApproved, LifecycleError> {
    let conn = store.lock_sync();

    // Load initiative row — must be in Draft state.
    let current_state: String = conn.query_row(
        "SELECT state FROM initiatives WHERE initiative_id=?1",
        rusqlite::params![initiative_id],
        |r| r.get(0),
    ).map_err(|e| match e {
        rusqlite::Error::QueryReturnedNoRows => LifecycleError::InitiativeNotFound {
            initiative_id: initiative_id.to_owned(),
        },
        other => LifecycleError::Sql(other),
    })?;

    // Only Draft may be approved. Other states are terminal or already executing.
    if current_state != "Draft" {
        return Err(LifecycleError::InitiativeTerminal { current_state });
    }

    // Load plan bytes + signature from signed_plan_artifacts.
    let (plan_bytes, plan_sig): (Vec<u8>, Vec<u8>) = conn.query_row(
        "SELECT plan_bytes, plan_sig FROM signed_plan_artifacts WHERE initiative_id=?1",
        rusqlite::params![initiative_id],
        |r| Ok((r.get(0)?, r.get(1)?)),
    ).map_err(|e| LifecycleError::Sql(e))?;

    // Verify Ed25519 signature over raw plan bytes.
    raxis_crypto::verify::verify_ed25519(operator_pubkey_bytes, &plan_bytes, &plan_sig)
        .map_err(|e| LifecycleError::PlanSignatureInvalid {
            reason: e.to_string(),
        })?;

    let now  = now_unix_secs();
    let plan_toml_str = String::from_utf8_lossy(&plan_bytes);
    let tasks = parse_plan_tasks(&plan_toml_str)?;
    let task_count = tasks.len();

    // Transition initiative: Draft → Executing.
    conn.execute(
        "UPDATE initiatives SET state='Executing', approved_at=?1
         WHERE initiative_id=?2",
        rusqlite::params![now, initiative_id],
    )?;

    // Admit all tasks (insert task rows in Admitted state).
    for task in &tasks {
        admit_task(&conn, &task.task_id, initiative_id, &task.name, &task.lane_id)?;
    }

    eprintln!(
        "{{\"level\":\"info\",\"event\":\"PlanApproved\",\
         \"initiative_id\":\"{initiative_id}\",\
         \"approving_operator\":\"{approving_operator}\",\
         \"tasks_admitted\":{task_count}}}",
    );

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
        "UPDATE initiatives SET state='Aborted'
         WHERE initiative_id=?1 AND state='Draft'",
        rusqlite::params![initiative_id],
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
        "SELECT state FROM initiatives WHERE initiative_id=?1",
        rusqlite::params![initiative_id],
        |r| r.get(0),
    ).map_err(|e| match e {
        rusqlite::Error::QueryReturnedNoRows => LifecycleError::InitiativeNotFound {
            initiative_id: initiative_id.to_owned(),
        },
        other => LifecycleError::Sql(other),
    })?;

    // Terminal states per DDL: Completed, Failed, Aborted.
    match current_state.as_str() {
        "Completed" | "Failed" | "Aborted" => {
            return Err(LifecycleError::InitiativeTerminal {
                current_state,
            });
        }
        _ => {}
    }

    let now = now_unix_secs();

    // Cancel all non-terminal tasks atomically in the same connection lock.
    conn.execute(
        "UPDATE tasks SET state='Cancelled', transitioned_at=?1
         WHERE initiative_id=?2
           AND state NOT IN ('Completed', 'Failed', 'Aborted', 'Cancelled')",
        rusqlite::params![now, initiative_id],
    )?;

    // Transition initiative to Aborted.
    conn.execute(
        "UPDATE initiatives SET state='Aborted', completed_at=?1
         WHERE initiative_id=?2",
        rusqlite::params![now, initiative_id],
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
        "SELECT state FROM tasks WHERE task_id=?1",
        rusqlite::params![task_id],
        |r| r.get(0),
    ).map_err(|e| match e {
        rusqlite::Error::QueryReturnedNoRows => LifecycleError::TaskNotFound {
            task_id: task_id.to_owned(),
        },
        other => LifecycleError::Sql(other),
    })?;

    match state.as_str() {
        "Completed" | "Failed" | "Aborted" | "Cancelled" => {
            return Err(LifecycleError::TaskNotAbortable { current_state: state });
        }
        _ => {}
    }

    conn.execute(
        "UPDATE tasks SET state='Aborted', transitioned_at=?1
         WHERE task_id=?2",
        rusqlite::params![now, task_id],
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
        "SELECT state FROM tasks WHERE task_id=?1",
        rusqlite::params![task_id],
        |r| r.get(0),
    ).map_err(|e| match e {
        rusqlite::Error::QueryReturnedNoRows => LifecycleError::TaskNotFound {
            task_id: task_id.to_owned(),
        },
        other => LifecycleError::Sql(other),
    })?;

    if state != "Failed" {
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

struct PlanTask {
    task_id: String,
    name:    String,
    lane_id: String,
}

/// Parse [[tasks]] array from plan TOML.
/// Each entry requires: task_id (required), name (optional, defaults to task_id),
/// lane_id (optional, defaults to "default").
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
        tasks.push(PlanTask { task_id, name, lane_id });
    }

    Ok(tasks)
}

/// Insert a task row in `Admitted` state.
///
/// DDL Table 5 requires: task_id, initiative_id, lane_id, state, actor,
/// policy_epoch, admitted_at, transitioned_at.
fn admit_task(
    conn:         &rusqlite::Connection,
    task_id:      &str,
    initiative_id: &str,
    _name:        &str,
    lane_id:      &str,
) -> Result<(), LifecycleError> {
    let now = now_unix_secs();
    conn.execute(
        "INSERT OR IGNORE INTO tasks
            (task_id, initiative_id, lane_id, state,
             actor, policy_epoch, admitted_at, transitioned_at)
         VALUES (?1, ?2, ?3, 'Admitted', 'kernel', 1, ?4, ?4)",
        rusqlite::params![task_id, initiative_id, lane_id, now],
    )?;
    Ok(())
}

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
}

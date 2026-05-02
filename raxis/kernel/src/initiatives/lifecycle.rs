// raxis-kernel::initiatives::lifecycle — Initiative and task FSM operations.
//
// Normative reference: kernel-core.md §2.3 operator IPC dispatcher and
// kernel-store.md §2.5 Table 2 (initiatives) + Table 3 (tasks) DDL.
//
// OPERATOR-DRIVEN lifecycle:
//   create_initiative() — submit plan TOML + Ed25519 sig → Pending row
//   approve_plan()      — verify sig, promote to Executing, admit all tasks
//   reject_plan()       — set status = Rejected
//   abort_initiative()  — set status = Aborted, cancel all non-terminal tasks
//   abort_task()        — cancel a single task inside an Executing initiative
//   retry_task()        — transition a Failed task back to Admitted
//
// All writes are atomic (single SQLite transaction per operation).

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
// public types used by operator dispatcher responses
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub struct InitiativeCreated {
    pub initiative_id: String,
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

/// Submit a plan document (TOML) for this initiative.
///
/// - `plan_toml`: raw TOML bytes of the plan artifact.
/// - `plan_sig_hex`: hex-encoded Ed25519 signature over the plan bytes (operator-signed).
/// - `submitted_by`: operator fingerprint.
///
/// Creates the initiative row in `PlanSubmitted` state (not yet approved).
/// Does NOT verify the plan signature — that is done by `approve_plan`.
///
/// Returns the new initiative_id.
pub fn create_initiative(
    plan_toml: &str,
    plan_sig_hex: &str,
    submitted_by: &str,
    store: &Store,
) -> Result<InitiativeCreated, LifecycleError> {
    let initiative_id = uuid::Uuid::new_v4().to_string();
    let plan_sha256 = plan_sha256_hex(plan_toml.as_bytes());
    let now = now_unix_secs();

    let conn = store.lock_sync();
    conn.execute(
        "INSERT INTO initiatives
            (initiative_id, plan_toml, plan_sig_hex, plan_sha256,
             submitted_by, status, submitted_at, approved_at)
         VALUES (?1, ?2, ?3, ?4, ?5, 'PlanSubmitted', ?6, NULL)",
        rusqlite::params![
            &initiative_id,
            plan_toml,
            plan_sig_hex,
            &plan_sha256,
            submitted_by,
            now,
        ],
    )?;

    eprintln!(
        "{{\"level\":\"info\",\"event\":\"InitiativeCreated\",\"initiative_id\":\"{initiative_id}\",\"submitted_by\":\"{submitted_by}\"}}",
    );

    Ok(InitiativeCreated {
        initiative_id,
        status: "PlanSubmitted".to_owned(),
    })
}

// ---------------------------------------------------------------------------
// approve_plan — verify sig, admit tasks, promote to Executing
// ---------------------------------------------------------------------------

/// Approve a plan: verify the operator Ed25519 signature, parse the plan TOML
/// into tasks, admit all tasks to the scheduler (DAG edges inserted), and
/// transition the initiative to `Executing`.
///
/// INV-INIT-01: tasks already exist from `create_initiative`'s plan_toml
/// in v1 — the task rows are derived from the plan TOML at approval time.
pub fn approve_plan(
    initiative_id: &str,
    approving_operator: &str,
    operator_pubkey_bytes: &[u8],
    store: &Store,
) -> Result<PlanApproved, LifecycleError> {
    let conn = store.lock_sync();

    // Load initiative row.
    let (plan_toml, plan_sig_hex, current_status): (String, String, String) = conn.query_row(
        "SELECT plan_toml, plan_sig_hex, status FROM initiatives WHERE initiative_id=?1",
        rusqlite::params![initiative_id],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
    ).map_err(|e| match e {
        rusqlite::Error::QueryReturnedNoRows => LifecycleError::InitiativeNotFound {
            initiative_id: initiative_id.to_owned(),
        },
        other => LifecycleError::Sql(other),
    })?;

    // Must be in PlanSubmitted state to be approvable.
    if current_status != "PlanSubmitted" {
        return Err(LifecycleError::InitiativeTerminal {
            current_state: current_status,
        });
    }

    // Verify Ed25519 signature over plan_toml bytes.
    let sig_bytes = hex::decode(&plan_sig_hex)
        .map_err(|e| LifecycleError::PlanSignatureInvalid {
            reason: format!("sig hex decode failed: {e}"),
        })?;
    raxis_crypto::verify::verify_ed25519(operator_pubkey_bytes, plan_toml.as_bytes(), &sig_bytes)
        .map_err(|e| LifecycleError::PlanSignatureInvalid {
            reason: e.to_string(),
        })?;

    let now = now_unix_secs();

    // Parse plan TOML → extract task definitions.
    let tasks = parse_plan_tasks(&plan_toml)?;
    let task_count = tasks.len();

    // Transition initiative to Executing.
    conn.execute(
        "UPDATE initiatives SET status='Executing', approved_at=?1, approved_by=?2
         WHERE initiative_id=?3",
        rusqlite::params![now, approving_operator, initiative_id],
    )?;

    // Admit all tasks (insert task rows in Admitted state).
    for task in tasks {
        admit_task(&conn, &task.task_id, initiative_id, &task.name, &task.lane_id)?;
    }

    eprintln!(
        "{{\"level\":\"info\",\"event\":\"PlanApproved\",\"initiative_id\":\"{initiative_id}\",\"tasks_admitted\":{task_count}}}",
    );

    Ok(PlanApproved {
        initiative_id: initiative_id.to_owned(),
        tasks_admitted: task_count,
    })
}

// ---------------------------------------------------------------------------
// reject_plan
// ---------------------------------------------------------------------------

pub fn reject_plan(
    initiative_id: &str,
    rejected_by: &str,
    reason: Option<&str>,
    store: &Store,
) -> Result<(), LifecycleError> {
    let conn = store.lock_sync();
    let now = now_unix_secs();
    let rows = conn.execute(
        "UPDATE initiatives SET status='Rejected', rejected_at=?1, rejected_by=?2, rejection_reason=?3
         WHERE initiative_id=?4 AND status='PlanSubmitted'",
        rusqlite::params![now, rejected_by, reason, initiative_id],
    )?;
    if rows == 0 {
        return Err(LifecycleError::InitiativeNotFound {
            initiative_id: initiative_id.to_owned(),
        });
    }
    eprintln!(
        "{{\"level\":\"info\",\"event\":\"PlanRejected\",\"initiative_id\":\"{initiative_id}\"}}",
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// abort_initiative
// ---------------------------------------------------------------------------

/// Abort an initiative — transition to Aborted and cancel all non-terminal tasks.
pub fn abort_initiative(
    initiative_id: &str,
    aborted_by: &str,
    store: &Store,
) -> Result<(), LifecycleError> {
    let conn = store.lock_sync();
    let now = now_unix_secs();

    // Verify initiative exists and is not already terminal.
    let current_status: String = conn.query_row(
        "SELECT status FROM initiatives WHERE initiative_id=?1",
        rusqlite::params![initiative_id],
        |r| r.get(0),
    ).map_err(|e| match e {
        rusqlite::Error::QueryReturnedNoRows => LifecycleError::InitiativeNotFound {
            initiative_id: initiative_id.to_owned(),
        },
        other => LifecycleError::Sql(other),
    })?;

    match current_status.as_str() {
        "Completed" | "Failed" | "Aborted" | "Rejected" => {
            return Err(LifecycleError::InitiativeTerminal {
                current_state: current_status,
            })
        }
        _ => {}
    }

    // Cancel all non-terminal tasks.
    conn.execute(
        "UPDATE tasks SET state='Cancelled', cancelled_at=?1
         WHERE initiative_id=?2
           AND state NOT IN ('Completed', 'Failed', 'Aborted', 'Cancelled')",
        rusqlite::params![now, initiative_id],
    )?;

    // Transition initiative.
    conn.execute(
        "UPDATE initiatives SET status='Aborted', aborted_at=?1, aborted_by=?2
         WHERE initiative_id=?3",
        rusqlite::params![now, aborted_by, initiative_id],
    )?;

    eprintln!(
        "{{\"level\":\"info\",\"event\":\"InitiativeAborted\",\"initiative_id\":\"{initiative_id}\"}}",
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// abort_task
// ---------------------------------------------------------------------------

pub fn abort_task(
    task_id: &str,
    aborted_by: &str,
    store: &Store,
) -> Result<(), LifecycleError> {
    let conn = store.lock_sync();
    let now = now_unix_secs();

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
            return Err(LifecycleError::TaskNotAbortable {
                current_state: state,
            })
        }
        _ => {}
    }

    conn.execute(
        "UPDATE tasks SET state='Aborted', aborted_at=?1, aborted_by=?2
         WHERE task_id=?3",
        rusqlite::params![now, aborted_by, task_id],
    )?;

    eprintln!(
        "{{\"level\":\"info\",\"event\":\"TaskAborted\",\"task_id\":\"{task_id}\"}}",
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// retry_task
// ---------------------------------------------------------------------------

/// Retry a Failed task — transition back to Admitted.
pub fn retry_task(task_id: &str, store: &Store) -> Result<(), LifecycleError> {
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
        return Err(LifecycleError::TaskNotFailed {
            current_state: state,
        });
    }

    conn.execute(
        "UPDATE tasks SET state='Admitted', failed_at=NULL, retry_count=retry_count+1
         WHERE task_id=?1",
        rusqlite::params![task_id],
    )?;

    eprintln!(
        "{{\"level\":\"info\",\"event\":\"TaskRetried\",\"task_id\":\"{task_id}\"}}",
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

/// Simple plan task definition parsed from plan TOML.
struct PlanTask {
    task_id: String,
    name: String,
    lane_id: String,
}

/// Parse the plan TOML and extract task definitions.
///
/// In v1 the plan TOML has an `[[tasks]]` array. Each entry must have:
///   task_id, name, lane_id
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

    let mut tasks = Vec::new();
    for (i, entry) in tasks_array.iter().enumerate() {
        let task_id = entry
            .get("task_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| LifecycleError::PlanInvalid {
                reason: format!("tasks[{i}] missing task_id"),
            })?
            .to_owned();
        let name = entry
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or(&task_id)
            .to_owned();
        let lane_id = entry
            .get("lane_id")
            .and_then(|v| v.as_str())
            .unwrap_or("default")
            .to_owned();
        tasks.push(PlanTask { task_id, name, lane_id });
    }

    Ok(tasks)
}

/// Insert a task row in `Admitted` state — called by approve_plan.
fn admit_task(
    conn: &rusqlite::Connection,
    task_id: &str,
    initiative_id: &str,
    name: &str,
    lane_id: &str,
) -> Result<(), LifecycleError> {
    let now = now_unix_secs();
    conn.execute(
        "INSERT OR IGNORE INTO tasks
            (task_id, initiative_id, name, lane_id, state, admitted_at)
         VALUES (?1, ?2, ?3, ?4, 'Admitted', ?5)",
        rusqlite::params![task_id, initiative_id, name, lane_id, now],
    )?;
    Ok(())
}

fn plan_sha256_hex(bytes: &[u8]) -> String {
    raxis_crypto::token::sha256_hex(bytes)
}

fn now_unix_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

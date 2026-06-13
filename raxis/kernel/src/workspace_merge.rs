// raxis-kernel::workspace_merge — kernel-owned DAG fan-in materialization.
//
// A `task_kind = "workspace_merge"` task is not an LLM session. It is a
// deterministic bridge between parallel artifact-producing tasks and a
// downstream executor/reviewer that needs one concrete `/workspace` base.
// The kernel attempts a clean Git merge of every predecessor
// `evaluation_sha`. If Git reports conflicts, the conflicted worktree is
// preserved and a normal `MergeConflict` escalation points the operator at the
// exact path to resolve with standard Git commands.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;

use raxis_store::{Store, Table};
use raxis_types::{
    operator_wire::OperatorResponse, unix_now_secs, BudgetSnapshot, EscalationClass,
    EscalationStatus, IntentKind, IntentOutcome, IntentRequest, IntentResponse, PlannerErrorCode,
    RequestedEscalationScope, SessionId, TaskState,
};
use rusqlite::OptionalExtension;

use crate::initiatives::plan_registry::{TaskKey, TaskKind, WorkspaceMergeOnConflict};
use crate::initiatives::task_transitions::{
    emit_task_state_changed_audit, transition_task_in_tx, TransitionActor,
};
use crate::ipc::context::HandlerContext;

const TASKS: &str = Table::Tasks.as_str();
const SESSIONS: &str = Table::Sessions.as_str();
const ESCALATIONS: &str = Table::Escalations.as_str();
const TASK_DAG_EDGES: &str = Table::TaskDagEdges.as_str();
const SUBTASK_ACTIVATIONS: &str = Table::SubtaskActivations.as_str();
const WORKSPACE_MERGE_ATTEMPTS: &str = Table::WorkspaceMergeAttempts.as_str();

#[derive(Debug, Clone)]
struct WorkspaceMergeAdmission {
    task_id: String,
    initiative_id: String,
    repository_id: String,
    target_ref: String,
    on_conflict: WorkspaceMergeOnConflict,
    predecessor_shas: Vec<String>,
}

#[derive(Debug, Clone)]
struct WorkspaceMergeAttempt {
    attempt_id: String,
    initiative_id: String,
    task_id: String,
    state: String,
    on_conflict: WorkspaceMergeOnConflict,
    worktree_root: PathBuf,
    base_sha: String,
    predecessor_shas: Vec<String>,
}

#[derive(Debug)]
enum WorkspaceMergeAdmissionResult {
    NotWorkspaceMerge,
    Ready(WorkspaceMergeAdmission),
    Reject {
        code: PlannerErrorCode,
        state: TaskState,
    },
    DependencyNotMet {
        missing: Vec<(String, String)>,
    },
}

#[derive(Debug)]
enum MergeRunResult {
    Clean { output_sha: String },
    Conflict { paths: Vec<String>, reason: String },
    Failed { reason: String },
}

/// Route `ActivateSubTask` for `task_kind = "workspace_merge"`.
///
/// Returns `None` for ordinary Executor / Reviewer tasks so the historical VM
/// activation handler continues unchanged.
pub(crate) async fn handle_activate_if_workspace_merge(
    req: &IntentRequest,
    submitter_session_id: &SessionId,
    seq: u64,
    ctx: &Arc<HandlerContext>,
) -> Option<Result<IntentResponse, (PlannerErrorCode, TaskState)>> {
    let task_id = req.task_id.as_str().to_owned();
    let store = Arc::clone(&ctx.store);
    let plan_registry = Arc::clone(&ctx.plan_registry);
    let admission_join = tokio::task::spawn_blocking(move || {
        classify_workspace_merge_admission(&store, &plan_registry, &task_id)
    })
    .await;

    let admission = match admission_join {
        Ok(WorkspaceMergeAdmissionResult::NotWorkspaceMerge) => return None,
        Ok(WorkspaceMergeAdmissionResult::Ready(admission)) => admission,
        Ok(WorkspaceMergeAdmissionResult::Reject { code, state }) => {
            return Some(Err((code, state)))
        }
        Ok(WorkspaceMergeAdmissionResult::DependencyNotMet { missing }) => {
            emit_dependency_not_met(
                ctx,
                &req.task_id.as_str().to_owned(),
                submitter_session_id,
                seq,
                &missing,
            );
            return Some(Err((
                PlannerErrorCode::DependencyNotMet,
                TaskState::Admitted,
            )));
        }
        Err(_) => {
            return Some(Err((
                PlannerErrorCode::FailPolicyViolation,
                TaskState::Admitted,
            )))
        }
    };

    let ctx_for_run = Arc::clone(ctx);
    let session_for_run = submitter_session_id.as_str().to_owned();
    let task_id_for_response = admission.task_id.clone();
    let run_join = tokio::task::spawn_blocking(move || {
        run_workspace_merge_activation(&ctx_for_run, &session_for_run, admission)
    })
    .await;

    match run_join {
        Ok(Ok(state)) => Some(Ok(IntentResponse {
            sequence_number: seq,
            task_state: state,
            outcome: IntentOutcome::Accepted {
                remaining_budget: BudgetSnapshot { admission_units: 0 },
                warn_delegation_stale: false,
            },
        })),
        Ok(Err((code, state))) => Some(Err((code, state))),
        Err(_) => {
            eprintln!(
                "{{\"level\":\"error\",\"event\":\"WorkspaceMergeJoinFailed\",\
                 \"task_id\":\"{task_id_for_response}\"}}"
            );
            Some(Err((
                PlannerErrorCode::FailWorktreeProvision,
                TaskState::Admitted,
            )))
        }
    }
}

/// Accept an operator-resolved workspace-merge conflict.
///
/// The operator edits the preserved Git worktree directly, using normal Git
/// conflict-resolution mechanics. This handler is the audited acceptance gate:
/// it refuses unresolved conflict paths, commits staged resolutions when
/// needed, copies the resulting commit into the orchestrator object database,
/// completes the synthetic merge task, and consumes the pending escalation.
pub(crate) async fn handle_operator_workspace_merge_submit(
    attempt_id: String,
    operator_fingerprint: &str,
    ctx: &Arc<HandlerContext>,
) -> OperatorResponse {
    let ctx_for_blocking = Arc::clone(ctx);
    let attempt_for_blocking = attempt_id.clone();
    let operator_for_blocking = operator_fingerprint.to_owned();
    match tokio::task::spawn_blocking(move || {
        submit_workspace_merge_resolution(
            &ctx_for_blocking,
            &attempt_for_blocking,
            &operator_for_blocking,
        )
    })
    .await
    {
        Ok(Ok(message)) => OperatorResponse::Ack { message },
        Ok(Err((code, detail))) => OperatorResponse::Error { code, detail },
        Err(join_err) => OperatorResponse::Error {
            code: "FAIL_WORKSPACE_MERGE_SUBMIT".to_owned(),
            detail: format!("workspace merge submit join failed: {join_err}"),
        },
    }
}

/// Reset and replay a pending workspace-merge conflict.
///
/// This discards manual conflict-resolution edits and recreates the conflict
/// from the durable base/predecessor SHA set. It is deliberately an operator
/// IPC op, not a planner intent: conflict reset changes the preserved worktree
/// state that a human may be inspecting.
pub(crate) async fn handle_operator_workspace_merge_reset(
    attempt_id: String,
    operator_fingerprint: &str,
    ctx: &Arc<HandlerContext>,
) -> OperatorResponse {
    let ctx_for_blocking = Arc::clone(ctx);
    let attempt_for_blocking = attempt_id.clone();
    let operator_for_blocking = operator_fingerprint.to_owned();
    match tokio::task::spawn_blocking(move || {
        reset_workspace_merge_resolution(
            &ctx_for_blocking,
            &attempt_for_blocking,
            &operator_for_blocking,
        )
    })
    .await
    {
        Ok(Ok(message)) => OperatorResponse::Ack { message },
        Ok(Err((code, detail))) => OperatorResponse::Error { code, detail },
        Err(join_err) => OperatorResponse::Error {
            code: "FAIL_WORKSPACE_MERGE_RESET".to_owned(),
            detail: format!("workspace merge reset join failed: {join_err}"),
        },
    }
}

fn submit_workspace_merge_resolution(
    ctx: &HandlerContext,
    attempt_id: &str,
    operator_fingerprint: &str,
) -> Result<String, (String, String)> {
    let attempt = load_workspace_merge_attempt(ctx, attempt_id)?;
    ensure_attempt_pending(&attempt, "submit")?;
    ensure_worktree_root_exists(&attempt)?;

    let conflicts = conflict_paths(&attempt.worktree_root);
    if !conflicts.is_empty() {
        return Err((
            "FAIL_WORKSPACE_MERGE_UNRESOLVED_CONFLICTS".to_owned(),
            format!(
                "workspace merge attempt {attempt_id} still has unresolved conflict paths: {}. \
                 Resolve them, run `git add ...`, then retry `raxis workspace-merge submit {attempt_id}`.",
                conflicts.join(", ")
            ),
        ));
    }

    if git_has_unstaged_changes(&attempt.worktree_root)? {
        return Err((
            "FAIL_WORKSPACE_MERGE_UNSTAGED_CHANGES".to_owned(),
            format!(
                "workspace merge attempt {attempt_id} has unstaged changes. \
                 Run `git add` for the resolved files or `raxis workspace-merge reset {attempt_id}`."
            ),
        ));
    }
    if git_has_staged_changes(&attempt.worktree_root)? {
        let msg = format!(
            "raxis: resolve workspace merge {}",
            short_sha(&attempt.attempt_id)
        );
        run_git(&attempt.worktree_root, &["commit", "-m", msg.as_str()]).map_err(|reason| {
            (
                "FAIL_WORKSPACE_MERGE_COMMIT".to_owned(),
                format!("could not commit workspace merge resolution: {reason}"),
            )
        })?;
    }

    let output_sha = run_git(&attempt.worktree_root, &["rev-parse", "HEAD"])
        .map_err(|reason| {
            (
                "FAIL_WORKSPACE_MERGE_RESOLVE_HEAD".to_owned(),
                format!("could not resolve workspace merge HEAD: {reason}"),
            )
        })?
        .trim()
        .to_owned();
    if output_sha == attempt.base_sha {
        return Err((
            "FAIL_WORKSPACE_MERGE_EMPTY_RESOLUTION".to_owned(),
            format!(
                "workspace merge attempt {attempt_id} resolved to its base SHA; \
                 no predecessor output was materialized"
            ),
        ));
    }

    let anchor_root = crate::worktree_provisioning::orchestrator_worktree_path(
        &ctx.data_dir,
        &attempt.initiative_id,
    );
    crate::worktree_provisioning::copy_executor_commit_to_orchestrator_odb(
        &anchor_root,
        &attempt.worktree_root,
        &attempt.task_id,
        &output_sha,
    )
    .map_err(|reason| {
        (
            "FAIL_WORKSPACE_MERGE_OUTPUT_COPY".to_owned(),
            format!("could not copy workspace merge output into orchestrator ODB: {reason}"),
        )
    })?;

    let (records, consumed_escalation_id) = complete_workspace_merge_attempt_for_operator(
        ctx,
        &attempt,
        &output_sha,
        operator_fingerprint,
    )?;
    for record in &records {
        emit_task_state_changed_audit(ctx.audit.as_ref(), record, Some(operator_fingerprint));
    }
    if let Some(escalation_id) = consumed_escalation_id {
        let _ = ctx.audit.emit(
            raxis_audit_tools::AuditEventKind::EscalationApproved {
                escalation_id,
                approved_by: operator_fingerprint.to_owned(),
                approved_by_display_name: Some("workspace merge submit".to_owned()),
            },
            Some(operator_fingerprint),
            Some(&attempt.task_id),
            Some(&attempt.initiative_id),
        );
    }

    Ok(format!(
        "Workspace merge attempt {attempt_id} accepted at {output_sha}. \
         Task {} is Completed.",
        attempt.task_id
    ))
}

fn reset_workspace_merge_resolution(
    ctx: &HandlerContext,
    attempt_id: &str,
    operator_fingerprint: &str,
) -> Result<String, (String, String)> {
    let attempt = load_workspace_merge_attempt(ctx, attempt_id)?;
    ensure_attempt_pending(&attempt, "reset")?;
    ensure_worktree_root_exists(&attempt)?;

    let _ = run_git(&attempt.worktree_root, &["merge", "--abort"]);
    run_git(
        &attempt.worktree_root,
        &["reset", "--hard", &attempt.base_sha],
    )
    .map_err(|reason| {
        (
            "FAIL_WORKSPACE_MERGE_RESET".to_owned(),
            format!(
                "could not reset workspace merge attempt {attempt_id} to {}: {reason}",
                attempt.base_sha
            ),
        )
    })?;

    match run_git_merge_sequence(&attempt.worktree_root, &attempt.predecessor_shas) {
        MergeRunResult::Conflict { paths, reason } => {
            update_workspace_merge_attempt_conflicts(ctx, &attempt, &paths, &reason)?;
            Ok(format!(
                "Workspace merge attempt {attempt_id} reset and replayed. \
                 Conflicts remain: {}. Resolve in {} then run `raxis workspace-merge submit {attempt_id}`.",
                paths.join(", "),
                attempt.worktree_root.display()
            ))
        }
        MergeRunResult::Clean { output_sha } => {
            let anchor_root = crate::worktree_provisioning::orchestrator_worktree_path(
                &ctx.data_dir,
                &attempt.initiative_id,
            );
            crate::worktree_provisioning::copy_executor_commit_to_orchestrator_odb(
                &anchor_root,
                &attempt.worktree_root,
                &attempt.task_id,
                &output_sha,
            )
            .map_err(|reason| {
                (
                    "FAIL_WORKSPACE_MERGE_OUTPUT_COPY".to_owned(),
                    format!("workspace merge replay became clean but output copy failed: {reason}"),
                )
            })?;
            let (records, _) = complete_workspace_merge_attempt_for_operator(
                ctx,
                &attempt,
                &output_sha,
                operator_fingerprint,
            )?;
            for record in &records {
                emit_task_state_changed_audit(
                    ctx.audit.as_ref(),
                    record,
                    Some(operator_fingerprint),
                );
            }
            Ok(format!(
                "Workspace merge attempt {attempt_id} reset, replayed cleanly, and completed at {output_sha}."
            ))
        }
        MergeRunResult::Failed { reason } => Err((
            "FAIL_WORKSPACE_MERGE_REPLAY".to_owned(),
            format!("workspace merge attempt {attempt_id} reset but replay failed: {reason}"),
        )),
    }
}

fn load_workspace_merge_attempt(
    ctx: &HandlerContext,
    attempt_id: &str,
) -> Result<WorkspaceMergeAttempt, (String, String)> {
    let conn = ctx.store.lock_sync();
    let row = conn
        .query_row(
            &format!(
                "SELECT attempt_id, initiative_id, task_id, state, on_conflict,
                        worktree_root, base_sha, predecessor_shas_json
                   FROM {WORKSPACE_MERGE_ATTEMPTS}
                  WHERE attempt_id = ?1"
            ),
            rusqlite::params![attempt_id],
            |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, String>(4)?,
                    r.get::<_, String>(5)?,
                    r.get::<_, String>(6)?,
                    r.get::<_, String>(7)?,
                ))
            },
        )
        .optional()
        .map_err(|e| {
            (
                "FAIL_WORKSPACE_MERGE_LOOKUP".to_owned(),
                format!("workspace merge attempt lookup failed: {e}"),
            )
        })?;

    let Some((
        attempt_id,
        initiative_id,
        task_id,
        state,
        on_conflict_raw,
        worktree_root,
        base_sha,
        predecessor_shas_json,
    )) = row
    else {
        return Err((
            "FAIL_WORKSPACE_MERGE_NOT_FOUND".to_owned(),
            format!("workspace merge attempt {attempt_id} does not exist"),
        ));
    };

    let on_conflict = WorkspaceMergeOnConflict::from_plan_str(&on_conflict_raw).ok_or_else(|| {
        (
            "FAIL_WORKSPACE_MERGE_CORRUPT".to_owned(),
            format!("workspace merge attempt {attempt_id} has invalid on_conflict value {on_conflict_raw:?}"),
        )
    })?;
    let predecessor_shas =
        serde_json::from_str::<Vec<String>>(&predecessor_shas_json).map_err(|e| {
            (
                "FAIL_WORKSPACE_MERGE_CORRUPT".to_owned(),
                format!(
                    "workspace merge attempt {attempt_id} has malformed predecessor SHA JSON: {e}"
                ),
            )
        })?;

    Ok(WorkspaceMergeAttempt {
        attempt_id,
        initiative_id,
        task_id,
        state,
        on_conflict,
        worktree_root: PathBuf::from(worktree_root),
        base_sha,
        predecessor_shas,
    })
}

fn ensure_attempt_pending(
    attempt: &WorkspaceMergeAttempt,
    operation: &str,
) -> Result<(), (String, String)> {
    match attempt.state.as_str() {
        "ConflictPendingOperator" | "ConflictPendingOrchestrator" => Ok(()),
        other => Err((
            "FAIL_WORKSPACE_MERGE_NOT_PENDING".to_owned(),
            format!(
                "cannot {operation} workspace merge attempt {} in state {other}; \
                 expected ConflictPendingOperator or ConflictPendingOrchestrator",
                attempt.attempt_id
            ),
        )),
    }
}

fn ensure_worktree_root_exists(attempt: &WorkspaceMergeAttempt) -> Result<(), (String, String)> {
    if attempt.worktree_root.is_dir() {
        Ok(())
    } else {
        Err((
            "FAIL_WORKSPACE_MERGE_WORKTREE_MISSING".to_owned(),
            format!(
                "workspace merge attempt {} points at missing worktree {}",
                attempt.attempt_id,
                attempt.worktree_root.display()
            ),
        ))
    }
}

fn complete_workspace_merge_attempt_for_operator(
    ctx: &HandlerContext,
    attempt: &WorkspaceMergeAttempt,
    output_sha: &str,
    operator_fingerprint: &str,
) -> Result<
    (
        Vec<crate::initiatives::task_transitions::TaskTransitionRecord>,
        Option<String>,
    ),
    (String, String),
> {
    let mut conn = ctx.store.lock_sync();
    let tx = conn.transaction().map_err(|e| {
        (
            "FAIL_WORKSPACE_MERGE_COMPLETE".to_owned(),
            format!("workspace merge completion transaction failed: {e}"),
        )
    })?;
    let now = unix_now_secs();
    let mut records = Vec::new();
    let idempotency_key = format!("workspace-merge-conflict:{}", attempt.attempt_id);
    let consumed_escalation_id = tx
        .query_row(
            &format!(
                "SELECT escalation_id FROM {ESCALATIONS}
                  WHERE idempotency_key = ?1
                  ORDER BY created_at DESC
                  LIMIT 1"
            ),
            rusqlite::params![&idempotency_key],
            |r| r.get::<_, String>(0),
        )
        .optional()
        .map_err(|e| {
            (
                "FAIL_WORKSPACE_MERGE_COMPLETE".to_owned(),
                format!("workspace merge escalation lookup failed: {e}"),
            )
        })?;

    let current_state: String = tx
        .query_row(
            &format!("SELECT state FROM {TASKS} WHERE task_id = ?1"),
            rusqlite::params![&attempt.task_id],
            |r| r.get(0),
        )
        .map_err(|e| {
            (
                "FAIL_WORKSPACE_MERGE_COMPLETE".to_owned(),
                format!("workspace merge task lookup failed: {e}"),
            )
        })?;

    if current_state == TaskState::GatesPending.as_sql_str() {
        records.push(
            transition_task_in_tx(
                &tx,
                &attempt.task_id,
                TaskState::Admitted,
                None,
                TransitionActor::Operator {
                    fingerprint: operator_fingerprint.to_owned(),
                },
            )
            .map_err(|e| {
                (
                    "FAIL_WORKSPACE_MERGE_COMPLETE".to_owned(),
                    format!("workspace merge GatesPending→Admitted transition failed: {e:?}"),
                )
            })?,
        );
    }
    records.push(
        transition_task_in_tx(
            &tx,
            &attempt.task_id,
            TaskState::Running,
            None,
            TransitionActor::Operator {
                fingerprint: operator_fingerprint.to_owned(),
            },
        )
        .map_err(|e| {
            (
                "FAIL_WORKSPACE_MERGE_COMPLETE".to_owned(),
                format!("workspace merge Admitted→Running transition failed: {e:?}"),
            )
        })?,
    );
    records.push(
        transition_task_in_tx(
            &tx,
            &attempt.task_id,
            TaskState::Completed,
            None,
            TransitionActor::Operator {
                fingerprint: operator_fingerprint.to_owned(),
            },
        )
        .map_err(|e| {
            (
                "FAIL_WORKSPACE_MERGE_COMPLETE".to_owned(),
                format!("workspace merge Running→Completed transition failed: {e:?}"),
            )
        })?,
    );

    tx.execute(
        &format!(
            "UPDATE {TASKS}
                SET evaluation_sha = ?1,
                    base_sha = ?2,
                    session_id = NULL,
                    failure_reason = NULL,
                    block_reason = NULL
              WHERE task_id = ?3"
        ),
        rusqlite::params![output_sha, &attempt.base_sha, &attempt.task_id],
    )
    .map_err(|e| {
        (
            "FAIL_WORKSPACE_MERGE_COMPLETE".to_owned(),
            format!("workspace merge task output update failed: {e}"),
        )
    })?;
    tx.execute(
        &format!(
            "UPDATE {SUBTASK_ACTIVATIONS}
                SET activation_state = 'Completed',
                    evaluation_sha = ?1,
                    activated_at = COALESCE(activated_at, ?2),
                    terminated_at = ?2
              WHERE task_id = ?3
                AND initiative_id = ?4
                AND activation_state = 'PendingActivation'"
        ),
        rusqlite::params![output_sha, now, &attempt.task_id, &attempt.initiative_id],
    )
    .map_err(|e| {
        (
            "FAIL_WORKSPACE_MERGE_COMPLETE".to_owned(),
            format!("workspace merge activation update failed: {e}"),
        )
    })?;
    tx.execute(
        &format!(
            "UPDATE {WORKSPACE_MERGE_ATTEMPTS}
                SET state = 'Completed',
                    output_sha = ?1,
                    updated_at = ?2,
                    resolved_at = ?2
              WHERE attempt_id = ?3"
        ),
        rusqlite::params![output_sha, now, &attempt.attempt_id],
    )
    .map_err(|e| {
        (
            "FAIL_WORKSPACE_MERGE_COMPLETE".to_owned(),
            format!("workspace merge attempt update failed: {e}"),
        )
    })?;
    tx.execute(
        &format!(
            "UPDATE {ESCALATIONS}
                SET status = ?1,
                    resolved_at = ?2,
                    resolution_notes = ?3
              WHERE idempotency_key = ?4
                AND status IN (?5, ?6)"
        ),
        rusqlite::params![
            EscalationStatus::Consumed.as_sql_str(),
            now,
            format!("resolved by operator {operator_fingerprint} via workspace-merge submit"),
            idempotency_key,
            EscalationStatus::Pending.as_sql_str(),
            EscalationStatus::Approved.as_sql_str(),
        ],
    )
    .map_err(|e| {
        (
            "FAIL_WORKSPACE_MERGE_COMPLETE".to_owned(),
            format!("workspace merge escalation update failed: {e}"),
        )
    })?;
    tx.commit().map_err(|e| {
        (
            "FAIL_WORKSPACE_MERGE_COMPLETE".to_owned(),
            format!("workspace merge completion commit failed: {e}"),
        )
    })?;
    Ok((records, consumed_escalation_id))
}

fn update_workspace_merge_attempt_conflicts(
    ctx: &HandlerContext,
    attempt: &WorkspaceMergeAttempt,
    conflict_paths: &[String],
    reason: &str,
) -> Result<(), (String, String)> {
    let conflict_json = serde_json::to_string(conflict_paths).map_err(|e| {
        (
            "FAIL_WORKSPACE_MERGE_RESET".to_owned(),
            format!("could not serialize conflict paths: {e}"),
        )
    })?;
    let mut conn = ctx.store.lock_sync();
    let tx = conn.transaction().map_err(|e| {
        (
            "FAIL_WORKSPACE_MERGE_RESET".to_owned(),
            format!("workspace merge reset transaction failed: {e}"),
        )
    })?;
    let now = unix_now_secs();
    tx.execute(
        &format!(
            "UPDATE {WORKSPACE_MERGE_ATTEMPTS}
                SET state = ?1,
                    conflict_paths_json = ?2,
                    failure_reason = ?3,
                    updated_at = ?4
              WHERE attempt_id = ?5"
        ),
        rusqlite::params![
            attempt_conflict_state(attempt.on_conflict),
            conflict_json,
            reason,
            now,
            &attempt.attempt_id,
        ],
    )
    .map_err(|e| {
        (
            "FAIL_WORKSPACE_MERGE_RESET".to_owned(),
            format!("workspace merge reset attempt update failed: {e}"),
        )
    })?;
    tx.execute(
        &format!(
            "UPDATE {TASKS}
                SET block_reason = ?1,
                    transitioned_at = ?2
              WHERE task_id = ?3"
        ),
        rusqlite::params![
            format!(
                "Workspace merge conflict reset in {}. Run `raxis workspace-merge status {}`.",
                attempt.worktree_root.display(),
                attempt.attempt_id
            ),
            now,
            &attempt.task_id,
        ],
    )
    .map_err(|e| {
        (
            "FAIL_WORKSPACE_MERGE_RESET".to_owned(),
            format!("workspace merge reset task update failed: {e}"),
        )
    })?;
    tx.commit().map_err(|e| {
        (
            "FAIL_WORKSPACE_MERGE_RESET".to_owned(),
            format!("workspace merge reset commit failed: {e}"),
        )
    })
}

fn classify_workspace_merge_admission(
    store: &Arc<Store>,
    plan_registry: &Arc<crate::initiatives::plan_registry::PlanRegistry>,
    task_id: &str,
) -> WorkspaceMergeAdmissionResult {
    let mut conn = store.lock_sync();
    let tx = match conn.transaction() {
        Ok(tx) => tx,
        Err(_) => {
            return WorkspaceMergeAdmissionResult::Reject {
                code: PlannerErrorCode::FailPolicyViolation,
                state: TaskState::Admitted,
            }
        }
    };

    let task_row: Option<(String, String)> = match tx
        .query_row(
            &format!("SELECT initiative_id, state FROM {TASKS} WHERE task_id = ?1"),
            rusqlite::params![task_id],
            |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
        )
        .optional()
    {
        Ok(row) => row,
        Err(_) => {
            return WorkspaceMergeAdmissionResult::Reject {
                code: PlannerErrorCode::FailPolicyViolation,
                state: TaskState::Admitted,
            }
        }
    };

    let Some((initiative_id, task_state)) = task_row else {
        return WorkspaceMergeAdmissionResult::NotWorkspaceMerge;
    };
    let key = TaskKey::new(&initiative_id, task_id);
    let Some(fields) = plan_registry.get(&key) else {
        return WorkspaceMergeAdmissionResult::NotWorkspaceMerge;
    };
    if fields.task_kind != TaskKind::WorkspaceMerge {
        return WorkspaceMergeAdmissionResult::NotWorkspaceMerge;
    }

    if task_state != TaskState::Admitted.as_sql_str() {
        return WorkspaceMergeAdmissionResult::Reject {
            code: PlannerErrorCode::FailTaskNotRunning,
            state: parse_task_state_lossy(&task_state),
        };
    }

    let activation_state: Option<String> = match tx
        .query_row(
            &format!(
                "SELECT activation_state FROM {SUBTASK_ACTIVATIONS}
                  WHERE task_id = ?1
                  ORDER BY created_at DESC
                  LIMIT 1"
            ),
            rusqlite::params![task_id],
            |r| r.get(0),
        )
        .optional()
    {
        Ok(row) => row,
        Err(_) => {
            return WorkspaceMergeAdmissionResult::Reject {
                code: PlannerErrorCode::FailPolicyViolation,
                state: TaskState::Admitted,
            }
        }
    };
    if activation_state.as_deref() != Some("PendingActivation") {
        return WorkspaceMergeAdmissionResult::Reject {
            code: PlannerErrorCode::FailPolicyViolation,
            state: TaskState::Admitted,
        };
    }

    let missing = match crate::handlers::intent::missing_predecessors_for_activation(
        &tx,
        task_id,
        plan_registry.as_ref(),
    ) {
        Ok(missing) => missing,
        Err(_) => {
            return WorkspaceMergeAdmissionResult::Reject {
                code: PlannerErrorCode::FailPolicyViolation,
                state: TaskState::Admitted,
            }
        }
    };
    if !missing.is_empty() {
        return WorkspaceMergeAdmissionResult::DependencyNotMet { missing };
    }

    let predecessor_shas = match load_predecessor_shas(&tx, task_id) {
        Ok(shas) if shas.len() >= 2 => shas,
        Ok(_) => {
            return WorkspaceMergeAdmissionResult::Reject {
                code: PlannerErrorCode::FailPolicyViolation,
                state: TaskState::Admitted,
            }
        }
        Err(_) => {
            return WorkspaceMergeAdmissionResult::Reject {
                code: PlannerErrorCode::FailPolicyViolation,
                state: TaskState::Admitted,
            }
        }
    };

    let (repository_id, target_ref) =
        resolve_workspace_target(plan_registry.as_ref(), &initiative_id);
    WorkspaceMergeAdmissionResult::Ready(WorkspaceMergeAdmission {
        task_id: task_id.to_owned(),
        initiative_id,
        repository_id,
        target_ref,
        on_conflict: fields.workspace_merge_on_conflict,
        predecessor_shas,
    })
}

fn load_predecessor_shas(
    tx: &rusqlite::Transaction<'_>,
    task_id: &str,
) -> rusqlite::Result<Vec<String>> {
    let mut stmt = tx.prepare(&format!(
        "SELECT t.evaluation_sha
           FROM {TASK_DAG_EDGES} AS e
           JOIN {TASKS} AS t ON t.task_id = e.predecessor_task_id
          WHERE e.successor_task_id = ?1
          ORDER BY e.predecessor_task_id"
    ))?;
    let rows = stmt.query_map(rusqlite::params![task_id], |r| {
        r.get::<_, Option<String>>(0)
    })?;
    let mut shas = Vec::new();
    for row in rows {
        if let Some(sha) = row? {
            shas.push(sha);
        }
    }
    Ok(shas)
}

fn resolve_workspace_target(
    plan_registry: &crate::initiatives::plan_registry::PlanRegistry,
    initiative_id: &str,
) -> (String, String) {
    let orch_fields = plan_registry.orchestrator(initiative_id);
    let repository_id = orch_fields
        .as_ref()
        .map(|o| o.repository_id.clone())
        .unwrap_or_else(|| crate::managed_repositories::DEFAULT_REPOSITORY_ID.to_owned());
    let target_ref = orch_fields
        .as_ref()
        .map(|o| o.target_ref.clone())
        .unwrap_or_else(|| "refs/heads/main".to_owned());
    (repository_id, target_ref)
}

fn run_workspace_merge_activation(
    ctx: &HandlerContext,
    submitter_session_id: &str,
    admission: WorkspaceMergeAdmission,
) -> Result<TaskState, (PlannerErrorCode, TaskState)> {
    let attempt_id = uuid::Uuid::new_v4().to_string();
    let worktree_name = format!("workspace-merge-{attempt_id}");
    let anchor = crate::worktree_provisioning::provision_orchestrator_worktree(
        &ctx.data_dir,
        &admission.initiative_id,
        &admission.repository_id,
        &admission.target_ref,
    )
    .map_err(|e| {
        eprintln!(
            "{{\"level\":\"error\",\"event\":\"WorkspaceMergeAnchorProvisionFailed\",\
             \"task_id\":\"{}\",\"reason\":{}}}",
            admission.task_id,
            json_string(&e.to_string()),
        );
        (PlannerErrorCode::FailWorktreeProvision, TaskState::Admitted)
    })?;
    let provisioned = crate::worktree_provisioning::provision_executor_worktree(
        &ctx.data_dir,
        &worktree_name,
        &anchor,
        &anchor.base_sha,
    )
    .map_err(|e| {
        eprintln!(
            "{{\"level\":\"error\",\"event\":\"WorkspaceMergeWorktreeProvisionFailed\",\
             \"task_id\":\"{}\",\"reason\":{}}}",
            admission.task_id,
            json_string(&e.to_string()),
        );
        (PlannerErrorCode::FailWorktreeProvision, TaskState::Admitted)
    })?;
    let worktree_root = provisioned.mount.host_path;

    let running_record = begin_workspace_merge_attempt(
        ctx,
        &attempt_id,
        &admission,
        &worktree_root,
        &anchor.base_sha,
    )
    .map_err(|e| {
        eprintln!(
            "{{\"level\":\"error\",\"event\":\"WorkspaceMergeAttemptBeginFailed\",\
             \"task_id\":\"{}\",\"reason\":{}}}",
            admission.task_id,
            json_string(&e),
        );
        (PlannerErrorCode::FailPolicyViolation, TaskState::Admitted)
    })?;
    emit_task_state_changed_audit(
        ctx.audit.as_ref(),
        &running_record,
        Some(submitter_session_id),
    );

    let run_result = run_git_merge_sequence(&worktree_root, &admission.predecessor_shas);
    match run_result {
        MergeRunResult::Clean { output_sha } => {
            if let Err(reason) =
                crate::worktree_provisioning::copy_executor_commit_to_orchestrator_odb(
                    &anchor.worktree_root,
                    &worktree_root,
                    &admission.task_id,
                    &output_sha,
                )
            {
                fail_workspace_merge_attempt(
                    ctx,
                    &attempt_id,
                    &admission.task_id,
                    &format!("workspace merge output copy failed: {reason}"),
                    submitter_session_id,
                );
                return Err((PlannerErrorCode::FailWorktreeProvision, TaskState::Failed));
            }
            let completed_record = complete_workspace_merge_attempt(
                ctx,
                &attempt_id,
                &admission,
                &anchor.base_sha,
                &output_sha,
            )
            .map_err(|e| {
                eprintln!(
                    "{{\"level\":\"error\",\"event\":\"WorkspaceMergeAttemptCompleteFailed\",\
                     \"task_id\":\"{}\",\"reason\":{}}}",
                    admission.task_id,
                    json_string(&e),
                );
                (PlannerErrorCode::FailPolicyViolation, TaskState::Running)
            })?;
            emit_task_state_changed_audit(
                ctx.audit.as_ref(),
                &completed_record,
                Some(submitter_session_id),
            );
            Ok(TaskState::Completed)
        }
        MergeRunResult::Conflict { paths, reason } => {
            if admission.on_conflict == WorkspaceMergeOnConflict::FailClosed {
                fail_workspace_merge_attempt(
                    ctx,
                    &attempt_id,
                    &admission.task_id,
                    &reason,
                    submitter_session_id,
                );
                return Err((PlannerErrorCode::FailInvalidDiff, TaskState::Failed));
            }
            park_workspace_merge_conflict(
                ctx,
                &attempt_id,
                &admission,
                &worktree_root,
                &paths,
                &reason,
                submitter_session_id,
            )
            .map_err(|e| {
                eprintln!(
                    "{{\"level\":\"error\",\"event\":\"WorkspaceMergeConflictParkFailed\",\
                     \"task_id\":\"{}\",\"reason\":{}}}",
                    admission.task_id,
                    json_string(&e),
                );
                (PlannerErrorCode::FailPolicyViolation, TaskState::Running)
            })?;
            Ok(TaskState::GatesPending)
        }
        MergeRunResult::Failed { reason } => {
            fail_workspace_merge_attempt(
                ctx,
                &attempt_id,
                &admission.task_id,
                &reason,
                submitter_session_id,
            );
            Err((PlannerErrorCode::FailWorktreeProvision, TaskState::Failed))
        }
    }
}

fn begin_workspace_merge_attempt(
    ctx: &HandlerContext,
    attempt_id: &str,
    admission: &WorkspaceMergeAdmission,
    worktree_root: &Path,
    base_sha: &str,
) -> Result<crate::initiatives::task_transitions::TaskTransitionRecord, String> {
    let mut conn = ctx.store.lock_sync();
    let tx = conn.transaction().map_err(|e| e.to_string())?;
    let now = unix_now_secs();
    let predecessor_json =
        serde_json::to_string(&admission.predecessor_shas).map_err(|e| e.to_string())?;
    tx.execute(
        &format!(
            "INSERT INTO {WORKSPACE_MERGE_ATTEMPTS} (
                attempt_id, initiative_id, task_id, state, on_conflict,
                worktree_root, base_sha, predecessor_shas_json,
                created_at, updated_at
             ) VALUES (?1, ?2, ?3, 'Running', ?4, ?5, ?6, ?7, ?8, ?8)"
        ),
        rusqlite::params![
            attempt_id,
            &admission.initiative_id,
            &admission.task_id,
            admission.on_conflict.as_plan_str(),
            worktree_root.display().to_string(),
            base_sha,
            predecessor_json,
            now,
        ],
    )
    .map_err(|e| e.to_string())?;
    let record = transition_task_in_tx(
        &tx,
        &admission.task_id,
        TaskState::Running,
        None,
        TransitionActor::Kernel,
    )
    .map_err(|e| format!("{e:?}"))?;
    tx.commit().map_err(|e| e.to_string())?;
    Ok(record)
}

fn complete_workspace_merge_attempt(
    ctx: &HandlerContext,
    attempt_id: &str,
    admission: &WorkspaceMergeAdmission,
    base_sha: &str,
    output_sha: &str,
) -> Result<crate::initiatives::task_transitions::TaskTransitionRecord, String> {
    let mut conn = ctx.store.lock_sync();
    let tx = conn.transaction().map_err(|e| e.to_string())?;
    let now = unix_now_secs();
    let record = transition_task_in_tx(
        &tx,
        &admission.task_id,
        TaskState::Completed,
        None,
        TransitionActor::Kernel,
    )
    .map_err(|e| format!("{e:?}"))?;
    tx.execute(
        &format!(
            "UPDATE {TASKS}
                SET evaluation_sha = ?1,
                    base_sha = ?2,
                    session_id = NULL
              WHERE task_id = ?3"
        ),
        rusqlite::params![output_sha, base_sha, &admission.task_id],
    )
    .map_err(|e| e.to_string())?;
    tx.execute(
        &format!(
            "UPDATE {SUBTASK_ACTIVATIONS}
                SET activation_state = 'Completed',
                    evaluation_sha = ?1,
                    activated_at = COALESCE(activated_at, ?2),
                    terminated_at = ?2
              WHERE task_id = ?3
                AND activation_state = 'PendingActivation'"
        ),
        rusqlite::params![output_sha, now, &admission.task_id],
    )
    .map_err(|e| e.to_string())?;
    tx.execute(
        &format!(
            "UPDATE {WORKSPACE_MERGE_ATTEMPTS}
                SET state = 'Completed',
                    output_sha = ?1,
                    updated_at = ?2,
                    resolved_at = ?2
              WHERE attempt_id = ?3"
        ),
        rusqlite::params![output_sha, now, attempt_id],
    )
    .map_err(|e| e.to_string())?;
    tx.commit().map_err(|e| e.to_string())?;
    Ok(record)
}

fn park_workspace_merge_conflict(
    ctx: &HandlerContext,
    attempt_id: &str,
    admission: &WorkspaceMergeAdmission,
    worktree_root: &Path,
    conflict_paths: &[String],
    reason: &str,
    submitter_session_id: &str,
) -> Result<(), String> {
    let mut conn = ctx.store.lock_sync();
    let tx = conn.transaction().map_err(|e| e.to_string())?;
    let now = unix_now_secs();
    let block_reason = format!(
        "Workspace merge conflict pending operator resolution in {}. Run `raxis workspace-merge status {attempt_id}` for commands.",
        worktree_root.display()
    );
    let record = transition_task_in_tx(
        &tx,
        &admission.task_id,
        TaskState::GatesPending,
        Some(&block_reason),
        TransitionActor::Kernel,
    )
    .map_err(|e| format!("{e:?}"))?;
    let conflict_json = serde_json::to_string(conflict_paths).map_err(|e| e.to_string())?;
    let attempt_state = match admission.on_conflict {
        WorkspaceMergeOnConflict::OrchestratorThenOperator => "ConflictPendingOperator",
        WorkspaceMergeOnConflict::OperatorManual => "ConflictPendingOperator",
        WorkspaceMergeOnConflict::FailClosed => "Failed",
    };
    tx.execute(
        &format!(
            "UPDATE {WORKSPACE_MERGE_ATTEMPTS}
                SET state = ?1,
                    conflict_paths_json = ?2,
                    failure_reason = ?3,
                    updated_at = ?4
              WHERE attempt_id = ?5"
        ),
        rusqlite::params![attempt_state, conflict_json, reason, now, attempt_id],
    )
    .map_err(|e| e.to_string())?;

    let (lineage_id, timeout_at) = escalation_context(&tx, ctx, submitter_session_id, now)?;
    let escalation_id = uuid::Uuid::new_v4().to_string();
    let scope = RequestedEscalationScope::MergeConflict {
        conflicts: conflict_paths.to_vec(),
    };
    let scope_json = serde_json::to_string(&scope).map_err(|e| e.to_string())?;
    let justification = format!(
        "Workspace merge task `{}` could not merge predecessor artifacts cleanly.\n\n\
         Worktree: {}\n\
         Attempt: {attempt_id}\n\
         Conflicts: {}\n\n\
         Operator path:\n\
         1. cd {}\n\
         2. git status\n\
         3. resolve conflicts and git add/commit\n\
         4. raxis workspace-merge submit {attempt_id}\n\
         Reset: raxis workspace-merge reset {attempt_id}",
        admission.task_id,
        worktree_root.display(),
        conflict_paths.join(", "),
        worktree_root.display(),
    );
    let idempotency_key = format!("workspace-merge-conflict:{attempt_id}");
    tx.execute(
        &format!(
            "INSERT INTO {ESCALATIONS} (
                escalation_id, session_id, task_id, lineage_id, initiative_id,
                class, requested_scope_json, justification, idempotency_key,
                status, created_at, timeout_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
             ON CONFLICT(session_id, idempotency_key) DO NOTHING"
        ),
        rusqlite::params![
            escalation_id,
            submitter_session_id,
            &admission.task_id,
            lineage_id,
            &admission.initiative_id,
            EscalationClass::MergeConflict.as_sql_str(),
            scope_json,
            justification,
            idempotency_key,
            EscalationStatus::Pending.as_sql_str(),
            now,
            timeout_at,
        ],
    )
    .map_err(|e| e.to_string())?;
    tx.commit().map_err(|e| e.to_string())?;

    emit_task_state_changed_audit(ctx.audit.as_ref(), &record, Some(submitter_session_id));
    let _ = ctx.audit.emit(
        raxis_audit_tools::AuditEventKind::EscalationSubmitted {
            escalation_id,
            task_id: admission.task_id.clone(),
            class: EscalationClass::MergeConflict.as_sql_str().to_owned(),
            lineage_id,
        },
        Some(submitter_session_id),
        Some(&admission.task_id),
        Some(&admission.initiative_id),
    );
    Ok(())
}

fn fail_workspace_merge_attempt(
    ctx: &HandlerContext,
    attempt_id: &str,
    task_id: &str,
    reason: &str,
    submitter_session_id: &str,
) {
    let mut conn = ctx.store.lock_sync();
    let tx = match conn.transaction() {
        Ok(tx) => tx,
        Err(e) => {
            eprintln!(
                "{{\"level\":\"error\",\"event\":\"WorkspaceMergeFailTxBeginFailed\",\
                 \"task_id\":\"{task_id}\",\"reason\":\"{e}\"}}"
            );
            return;
        }
    };
    let now = unix_now_secs();
    let record = transition_task_in_tx(
        &tx,
        task_id,
        TaskState::Failed,
        Some(reason),
        TransitionActor::Kernel,
    );
    let record = match record {
        Ok(record) => record,
        Err(e) => {
            eprintln!(
                "{{\"level\":\"error\",\"event\":\"WorkspaceMergeFailTransitionFailed\",\
                 \"task_id\":\"{task_id}\",\"reason\":{}}}",
                json_string(&format!("{e:?}")),
            );
            return;
        }
    };
    let _ = tx.execute(
        &format!(
            "UPDATE {SUBTASK_ACTIVATIONS}
                SET activation_state = 'Failed',
                    activated_at = COALESCE(activated_at, ?1),
                    terminated_at = ?1
              WHERE task_id = ?2
                AND activation_state = 'PendingActivation'"
        ),
        rusqlite::params![now, task_id],
    );
    let _ = tx.execute(
        &format!(
            "UPDATE {WORKSPACE_MERGE_ATTEMPTS}
                SET state = 'Failed',
                    failure_reason = ?1,
                    updated_at = ?2,
                    resolved_at = ?2
              WHERE attempt_id = ?3"
        ),
        rusqlite::params![reason, now, attempt_id],
    );
    if tx.commit().is_ok() {
        emit_task_state_changed_audit(ctx.audit.as_ref(), &record, Some(submitter_session_id));
    }
}

fn escalation_context(
    tx: &rusqlite::Transaction<'_>,
    ctx: &HandlerContext,
    session_id: &str,
    now: i64,
) -> Result<(String, i64), String> {
    let lineage_id = tx
        .query_row(
            &format!("SELECT lineage_id FROM {SESSIONS} WHERE session_id = ?1"),
            rusqlite::params![session_id],
            |r| r.get::<_, String>(0),
        )
        .map_err(|e| format!("lookup submitter session lineage: {e}"))?;
    let timeout_at = now.saturating_add(ctx.policy.load().escalation_timeout().as_secs() as i64);
    Ok((lineage_id, timeout_at))
}

fn run_git_merge_sequence(worktree_root: &Path, predecessor_shas: &[String]) -> MergeRunResult {
    if let Err(reason) = configure_git_identity(worktree_root) {
        return MergeRunResult::Failed { reason };
    }
    for sha in predecessor_shas {
        let merge = run_git(
            worktree_root,
            &["merge", "--no-ff", "--no-commit", sha.as_str()],
        );
        match merge {
            Ok(out) => {
                let already_up_to_date = out.contains("Already up to date");
                if !already_up_to_date {
                    let message = format!("raxis: workspace merge predecessor {}", short_sha(sha));
                    if let Err(reason) = run_git(worktree_root, &["commit", "-m", message.as_str()])
                    {
                        return MergeRunResult::Failed {
                            reason: format!("commit workspace merge predecessor {sha}: {reason}"),
                        };
                    }
                }
            }
            Err(reason) => {
                let conflicts = conflict_paths(worktree_root);
                if !conflicts.is_empty() {
                    return MergeRunResult::Conflict {
                        paths: conflicts,
                        reason: format!("git merge {sha} reported conflicts: {reason}"),
                    };
                }
                return MergeRunResult::Failed {
                    reason: format!("git merge {sha}: {reason}"),
                };
            }
        }
    }
    match run_git(worktree_root, &["rev-parse", "HEAD"]) {
        Ok(out) => MergeRunResult::Clean {
            output_sha: out.trim().to_owned(),
        },
        Err(reason) => MergeRunResult::Failed { reason },
    }
}

fn configure_git_identity(worktree_root: &Path) -> Result<(), String> {
    run_git(worktree_root, &["config", "user.name", "raxis-kernel"])?;
    run_git(
        worktree_root,
        &["config", "user.email", "raxis-kernel@localhost"],
    )?;
    Ok(())
}

fn conflict_paths(worktree_root: &Path) -> Vec<String> {
    run_git(worktree_root, &["diff", "--name-only", "--diff-filter=U"])
        .unwrap_or_default()
        .lines()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

fn git_has_unstaged_changes(worktree_root: &Path) -> Result<bool, (String, String)> {
    git_diff_quiet(worktree_root, &["diff", "--quiet"])
}

fn git_has_staged_changes(worktree_root: &Path) -> Result<bool, (String, String)> {
    git_diff_quiet(worktree_root, &["diff", "--cached", "--quiet"])
}

fn git_diff_quiet(worktree_root: &Path, args: &[&str]) -> Result<bool, (String, String)> {
    let output = Command::new("git")
        .args(args)
        .current_dir(worktree_root)
        .stdin(Stdio::null())
        .output()
        .map_err(|e| {
            (
                "FAIL_WORKSPACE_MERGE_GIT_STATUS".to_owned(),
                format!("spawn git {:?}: {e}", args),
            )
        })?;
    match output.status.code() {
        Some(0) => Ok(false),
        Some(1) => Ok(true),
        _ => Err((
            "FAIL_WORKSPACE_MERGE_GIT_STATUS".to_owned(),
            format!(
                "git {:?} exited {}: {}{}",
                args,
                output.status,
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            ),
        )),
    }
}

fn run_git(cwd: &Path, args: &[&str]) -> Result<String, String> {
    let output = Command::new("git")
        .args(args)
        .current_dir(cwd)
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format!("spawn git {:?}: {e}", args))?;
    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    } else {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(format!(
            "git {:?} exited {}: {}{}",
            args, output.status, stdout, stderr
        ))
    }
}

fn attempt_conflict_state(on_conflict: WorkspaceMergeOnConflict) -> &'static str {
    match on_conflict {
        WorkspaceMergeOnConflict::OrchestratorThenOperator => "ConflictPendingOperator",
        WorkspaceMergeOnConflict::OperatorManual => "ConflictPendingOperator",
        WorkspaceMergeOnConflict::FailClosed => "Failed",
    }
}

fn emit_dependency_not_met(
    ctx: &HandlerContext,
    task_id: &str,
    session_id: &SessionId,
    seq: u64,
    missing: &[(String, String)],
) {
    let missing_json = missing
        .iter()
        .map(|(id, st)| format!("{{\"task\":\"{id}\",\"state\":\"{st}\"}}"))
        .collect::<Vec<_>>()
        .join(",");
    eprintln!(
        "{{\"level\":\"warn\",\"event\":\"WorkspaceMergeBlockedByDependencyNotMet\",\
         \"task_id\":\"{task_id}\",\"missing_predecessors\":[{missing_json}],\
         \"invariant\":\"INV-KERNEL-DAG-AUTHORITY-01\"}}",
    );
    let _ = ctx.audit.emit(
        raxis_audit_tools::AuditEventKind::IntentRejected {
            task_id: task_id.to_owned(),
            session_id: session_id.as_str().to_owned(),
            intent_kind: IntentKind::ActivateSubTask.as_str().to_owned(),
            error_code: "DEPENDENCY_NOT_MET".to_owned(),
            sequence_number: seq,
        },
        Some(session_id.as_str()),
        Some(task_id),
        None,
    );
}

fn parse_task_state_lossy(raw: &str) -> TaskState {
    TaskState::from_sql_str(raw).unwrap_or(TaskState::Admitted)
}

fn short_sha(sha: &str) -> &str {
    sha.get(..12).unwrap_or(sha)
}

fn json_string(value: &str) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "\"<unserialisable>\"".to_owned())
}

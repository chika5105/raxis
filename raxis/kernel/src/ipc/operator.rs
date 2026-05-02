// raxis-kernel::ipc::operator — Operator IPC dispatcher.
//
// Normative reference: kernel-core.md §2.3 `src/ipc/handlers/operator.rs`.
//
// Single dispatcher for every OperatorRequest variant on the operator UDS.
// Common pre-handler pipeline per §2.3:
//   1. Read one OperatorRequest frame.
//   2. permitted_ops gate — reject if op not in authenticated_operator.permitted_ops.
//   3. Invoke per-variant handler.
//   4. Write OperatorResponse frame.
//
// v1 handler implementation status:
//   CreateSession     — fully wired (authority::session::create_session)
//   RevokeSession     — fully wired (authority::session::revoke_session)
//   GrantDelegation   — fully wired (authority::delegation::grant_delegation)
//   Other 10 ops      — stub responses (domain subsystems not yet implemented)

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

use crate::authority;
use crate::initiatives::lifecycle;
use crate::ipc::auth::AuthenticatedOperator;
use crate::ipc::context::HandlerContext;

// ---------------------------------------------------------------------------
// Wire types (OperatorRequest / OperatorResponse)
// These mirror the types in raxis-types but are defined here to avoid the
// build-time dependency on the bincode wire codec for the auth handshake path.
// The operator socket uses JSON framing for its messages in v1.
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(tag = "op", content = "payload")]
pub enum OperatorRequest {
    CreateSession {
        role: String,
        worktree_root: Option<String>,
        base_sha: Option<String>,
        base_tracking_ref: Option<String>,
        lineage_id: String,
        task_id: Option<String>,
    },
    RevokeSession {
        session_id: String,
    },
    GrantDelegation {
        session_id: String,
        delegation_id: String,
        capability_class: String,
        scope_json: Option<String>,
        ttl_secs: u64,
        max_uses: Option<i64>,
        signature_hex: String,
    },
    // Initiative lifecycle — fully wired in v1:
    CreateInitiative {
        plan_toml:     String,
        plan_sig_hex:  String,
        submitted_by:  String,
    },
    ApprovePlan {
        initiative_id:        String,
        approving_operator:   String,
        /// Hex-encoded Ed25519 pubkey of the approving operator.
        operator_pubkey_hex:  String,
    },
    RejectPlan {
        initiative_id: String,
        rejected_by:   String,
        reason:        Option<String>,
    },
    RetryTask {
        task_id: String,
    },
    ResumeTask {
        /// Resume a BlockedRecoveryPending task → Admitted.
        task_id:     String,
        resumed_by:  String,
    },
    AbortTask {
        task_id:    String,
        aborted_by: String,
    },
    AbortInitiative {
        initiative_id: String,
        aborted_by:    String,
    },
    // Tier 2 stubs:
    ApproveEscalation  { payload: serde_json::Value },
    DenyEscalation     { payload: serde_json::Value },
    RotateEpoch        { payload: serde_json::Value },
}

#[derive(Debug, Serialize)]
#[serde(tag = "status", content = "payload")]
pub enum OperatorResponse {
    SessionCreated {
        session_id: String,
        session_token: String,
        role: String,
        worktree_root: Option<String>,
        base_sha: Option<String>,
        lineage_id: String,
    },
    SessionRevoked {
        session_id: String,
        revoked_at: i64,
    },
    DelegationGranted {
        delegation_id: String,
    },
    InitiativeCreated {
        initiative_id: String,
        status: String,
    },
    PlanApproved {
        initiative_id: String,
        tasks_admitted: usize,
    },
    Ack { message: String },
    Error {
        code: String,
        detail: String,
    },
}

/// Dispatch loop for one authenticated operator connection.
///
/// Reads requests in a loop, dispatches each one, writes one response.
/// Returns when the connection is closed or a fatal framing error occurs.
pub async fn dispatch_loop(
    mut stream: UnixStream,
    operator: AuthenticatedOperator,
    ctx: Arc<HandlerContext>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    loop {
        // Read length-prefixed JSON frame.
        let mut len_buf = [0u8; 4];
        match stream.read_exact(&mut len_buf).await {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                // Client closed connection — clean exit.
                return Ok(());
            }
            Err(e) => return Err(e.into()),
        }
        let msg_len = u32::from_le_bytes(len_buf) as usize;
        if msg_len > 1024 * 1024 {
            // Oversized frame — disconnect.
            return Err("operator request frame too large".into());
        }
        let mut msg_buf = vec![0u8; msg_len];
        stream.read_exact(&mut msg_buf).await?;

        let request: OperatorRequest = match serde_json::from_slice(&msg_buf) {
            Ok(r) => r,
            Err(e) => {
                let resp = OperatorResponse::Error {
                    code: "INVALID_REQUEST".to_owned(),
                    detail: e.to_string(),
                };
                write_response(&mut stream, &resp).await?;
                continue;
            }
        };

        // permitted_ops gate.
        let op_name = op_name(&request);
        if !crate::ipc::auth::is_permitted(&operator, op_name) {
            let resp = OperatorResponse::Error {
                code: "UNAUTHORIZED".to_owned(),
                detail: format!(
                    "operator '{}' not permitted to call '{op_name}'",
                    operator.fingerprint
                ),
            };
            write_response(&mut stream, &resp).await?;
            continue;
        }

        // Dispatch.
        let response = handle_request(request, &operator, &ctx).await;
        write_response(&mut stream, &response).await?;
    }
}

/// Dispatch a single request to the appropriate handler.
async fn handle_request(
    request: OperatorRequest,
    operator: &AuthenticatedOperator,
    ctx: &HandlerContext,
) -> OperatorResponse {
    match request {
        OperatorRequest::CreateSession {
            role, worktree_root, base_sha, base_tracking_ref, lineage_id, ..
        } => {
            handle_create_session(role, worktree_root, base_sha, base_tracking_ref, lineage_id, ctx).await
        }
        OperatorRequest::RevokeSession { session_id } => {
            handle_revoke_session(session_id, ctx).await
        }
        OperatorRequest::GrantDelegation {
            session_id, delegation_id, capability_class, scope_json,
            ttl_secs, max_uses, signature_hex,
        } => {
            handle_grant_delegation(
                session_id, delegation_id, capability_class, scope_json,
                ttl_secs, max_uses, signature_hex, operator, ctx,
            ).await
        }
        // Initiative lifecycle:
        OperatorRequest::CreateInitiative { plan_toml, plan_sig_hex, submitted_by } => {
            handle_create_initiative(plan_toml, plan_sig_hex, submitted_by, ctx).await
        }
        OperatorRequest::ApprovePlan { initiative_id, approving_operator, operator_pubkey_hex } => {
            handle_approve_plan(initiative_id, approving_operator, operator_pubkey_hex, ctx).await
        }
        OperatorRequest::RejectPlan { initiative_id, rejected_by, reason } => {
            handle_reject_plan(initiative_id, rejected_by, reason, ctx).await
        }
        OperatorRequest::RetryTask { task_id } => {
            handle_retry_task(task_id, ctx).await
        }
        OperatorRequest::ResumeTask { task_id, resumed_by } => {
            handle_resume_task(task_id, resumed_by, ctx).await
        }
        OperatorRequest::AbortTask { task_id, aborted_by } => {
            handle_abort_task(task_id, aborted_by, ctx).await
        }
        OperatorRequest::AbortInitiative { initiative_id, aborted_by } => {
            handle_abort_initiative(initiative_id, aborted_by, ctx).await
        }
        // Tier 2 stubs:
        OperatorRequest::ApproveEscalation { .. } | OperatorRequest::DenyEscalation { .. } => {
            OperatorResponse::Ack { message: "EscalationApproval not yet implemented (Tier 2)".to_owned() }
        }
        OperatorRequest::RotateEpoch { .. } => {
            OperatorResponse::Ack { message: "RotateEpoch not yet implemented (Tier 2)".to_owned() }
        }
    }
}

// ---------------------------------------------------------------------------
// Per-variant handlers
// ---------------------------------------------------------------------------

async fn handle_create_session(
    role_str: String,
    worktree_root: Option<String>,
    base_sha: Option<String>,
    base_tracking_ref: Option<String>,
    lineage_id_str: String,
    ctx: &HandlerContext,
) -> OperatorResponse {
    use authority::session::{Role, SessionConfig};

    let role = match role_str.as_str() {
        "Planner" => Role::Planner,
        "Gateway" => Role::Gateway,
        "Verifier" => Role::Verifier,
        other => {
            return OperatorResponse::Error {
                code: "FAIL_ROLE_NOT_OPERATOR_CREATABLE".to_owned(),
                detail: format!("role '{other}' is not operator-creatable"),
            }
        }
    };

    // Worktree containment check for Planner sessions.
    if role == Role::Planner {
        if let Some(ref wt) = worktree_root {
            let canonical = match std::fs::canonicalize(wt) {
                Ok(p) => p,
                Err(e) => {
                    return OperatorResponse::Error {
                        code: "FAIL_WORKTREE_OUTSIDE_ALLOWED_ROOTS".to_owned(),
                        detail: format!("cannot canonicalize worktree_root '{wt}': {e}"),
                    }
                }
            };
            let canonical_str = canonical.to_string_lossy();
            if !ctx.policy.worktree_root_allowed(&canonical_str) {
                return OperatorResponse::Error {
                    code: "FAIL_WORKTREE_OUTSIDE_ALLOWED_ROOTS".to_owned(),
                    detail: format!("worktree_root '{wt}' not in allowed_worktree_roots"),
                };
            }
        }
    }

    // Parse lineage_id.
    let lineage_id = match raxis_types::LineageId::parse(&lineage_id_str) {
        Ok(id) => id,
        Err(e) => {
            return OperatorResponse::Error {
                code: "FAIL_INVALID_LINEAGE_ID".to_owned(),
                detail: format!("invalid lineage_id '{lineage_id_str}': {e}"),
            }
        }
    };

    let config = SessionConfig::default();
    match authority::session::create_session(
        role.clone(),
        worktree_root.clone(),
        base_sha.clone(),
        base_tracking_ref.clone(),
        lineage_id.clone(),
        &config,
        &ctx.store,
    ) {
        Ok((session_id, session_token)) => OperatorResponse::SessionCreated {
            session_id: session_id.as_str().to_owned(),
            session_token,
            role: role.as_str().to_owned(),
            worktree_root,
            base_sha,
            lineage_id: lineage_id.as_str().to_owned(),
        },
        Err(e) => OperatorResponse::Error {
            code: "FAIL_CREATE_SESSION".to_owned(),
            detail: e.to_string(),
        },
    }
}

async fn handle_revoke_session(session_id_str: String, ctx: &HandlerContext) -> OperatorResponse {
    use raxis_types::SessionId;
    let session_id = match SessionId::parse(&session_id_str) {
        Ok(id) => id,
        Err(_) => {
            return OperatorResponse::Error {
                code: "FAIL_SESSION_NOT_FOUND".to_owned(),
                detail: format!("invalid session_id format: '{session_id_str}'"),
            }
        }
    };

    match authority::session::revoke_session(&session_id, &ctx.store) {
        Ok(()) => {
            let revoked_at = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64;
            OperatorResponse::SessionRevoked {
                session_id: session_id_str,
                revoked_at,
            }
        }
        Err(authority::keys::AuthorityError::SessionRevoked { revoked_at }) => {
            OperatorResponse::Error {
                code: "FAIL_SESSION_ALREADY_REVOKED".to_owned(),
                detail: format!("session already revoked at {revoked_at}"),
            }
        }
        Err(e) => OperatorResponse::Error {
            code: "FAIL_REVOKE_SESSION".to_owned(),
            detail: e.to_string(),
        },
    }
}

async fn handle_grant_delegation(
    session_id_str: String,
    delegation_id: String,
    capability_class: String,
    scope_json: Option<String>,
    ttl_secs: u64,
    max_uses: Option<i64>,
    signature_hex: String,
    operator: &AuthenticatedOperator,
    ctx: &HandlerContext,
) -> OperatorResponse {
    use raxis_types::SessionId;

    let session_id = match SessionId::parse(&session_id_str) {
        Ok(id) => id,
        Err(_) => {
            return OperatorResponse::Error {
                code: "FAIL_SESSION_NOT_FOUND".to_owned(),
                detail: format!("invalid session_id: '{session_id_str}'"),
            }
        }
    };

    let signature_bytes = match hex::decode(&signature_hex) {
        Ok(b) => b,
        Err(e) => {
            return OperatorResponse::Error {
                code: "FAIL_GRANT_DELEGATION".to_owned(),
                detail: format!("signature_hex decode failed: {e}"),
            }
        }
    };

    // Get operator pubkey from policy.
    let op_entry = match ctx.policy.operator_entry(&operator.fingerprint) {
        Some(e) => e,
        None => {
            return OperatorResponse::Error {
                code: "FAIL_GRANT_DELEGATION".to_owned(),
                detail: "operator not found in policy".to_owned(),
            }
        }
    };
    let pubkey_bytes = match hex::decode(&op_entry.pubkey_hex) {
        Ok(b) => b,
        Err(e) => {
            return OperatorResponse::Error {
                code: "FAIL_GRANT_DELEGATION".to_owned(),
                detail: format!("pubkey_hex decode failed: {e}"),
            }
        }
    };

    match authority::delegation::grant_delegation(
        &session_id,
        &delegation_id,
        &capability_class,
        scope_json.as_deref(),
        &operator.fingerprint,
        ttl_secs,
        max_uses,
        &signature_bytes,
        &pubkey_bytes,
        ctx.policy.max_delegation_ttl().as_secs(),
        &ctx.store,
    ) {
        Ok(()) => OperatorResponse::DelegationGranted { delegation_id },
        Err(authority::keys::AuthorityError::DelegationAlreadyActive { existing_delegation_id }) => {
            OperatorResponse::Error {
                code: "FAIL_DELEGATION_ALREADY_ACTIVE".to_owned(),
                detail: format!("delegation {existing_delegation_id} already active"),
            }
        }
        Err(e) => OperatorResponse::Error {
            code: "FAIL_GRANT_DELEGATION".to_owned(),
            detail: e.to_string(),
        },
    }
}

// ---------------------------------------------------------------------------
// Initiative lifecycle handlers
// ---------------------------------------------------------------------------

/// CreateInitiative — submit a plan TOML + Ed25519 sig → PlanSubmitted row.
/// Spec: kernel-core.md §2.3 operator handlers; initiative_id returned to operator.
async fn handle_create_initiative(
    plan_toml:    String,
    plan_sig_hex: String,
    submitted_by: String,
    ctx: &HandlerContext,
) -> OperatorResponse {
    match lifecycle::create_initiative(&plan_toml, &plan_sig_hex, &submitted_by, &ctx.store) {
        Ok(result) => OperatorResponse::InitiativeCreated {
            initiative_id: result.initiative_id,
            status:        result.status,
        },
        Err(e) => OperatorResponse::Error {
            code:   "FAIL_CREATE_INITIATIVE".to_owned(),
            detail: e.to_string(),
        },
    }
}

/// ApprovePlan — verify Ed25519 sig, parse tasks, admit all, → Executing.
/// Spec: "verify sig, promote to Executing, admit all tasks."
async fn handle_approve_plan(
    initiative_id:       String,
    approving_operator:  String,
    operator_pubkey_hex: String,
    ctx: &HandlerContext,
) -> OperatorResponse {
    let pubkey_bytes = match hex::decode(&operator_pubkey_hex) {
        Ok(b) => b,
        Err(e) => return OperatorResponse::Error {
            code:   "FAIL_APPROVE_PLAN".to_owned(),
            detail: format!("operator_pubkey_hex decode failed: {e}"),
        },
    };
    match lifecycle::approve_plan(&initiative_id, &approving_operator, &pubkey_bytes, &ctx.store) {
        Ok(result) => OperatorResponse::PlanApproved {
            initiative_id:  result.initiative_id,
            tasks_admitted: result.tasks_admitted,
        },
        Err(e) => OperatorResponse::Error {
            code:   "FAIL_APPROVE_PLAN".to_owned(),
            detail: e.to_string(),
        },
    }
}

/// RejectPlan — set status = Rejected; initiative must be in PlanSubmitted.
async fn handle_reject_plan(
    initiative_id: String,
    rejected_by:   String,
    reason:        Option<String>,
    ctx: &HandlerContext,
) -> OperatorResponse {
    match lifecycle::reject_plan(&initiative_id, &rejected_by, reason.as_deref(), &ctx.store) {
        Ok(()) => OperatorResponse::Ack {
            message: format!("initiative {initiative_id} rejected"),
        },
        Err(e) => OperatorResponse::Error {
            code:   "FAIL_REJECT_PLAN".to_owned(),
            detail: e.to_string(),
        },
    }
}

/// RetryTask — transition a Failed task back to Admitted.
/// Spec: "retry_task — transition a Failed task back to Admitted."
async fn handle_retry_task(task_id: String, ctx: &HandlerContext) -> OperatorResponse {
    match lifecycle::retry_task(&task_id, &ctx.store) {
        Ok(()) => OperatorResponse::Ack {
            message: format!("task {task_id} retried (→ Admitted)"),
        },
        Err(e) => OperatorResponse::Error {
            code:   "FAIL_RETRY_TASK".to_owned(),
            detail: e.to_string(),
        },
    }
}

/// ResumeTask — transition a BlockedRecoveryPending task → Admitted.
/// Spec: "BlockedRecoveryPending → Admitted (operator resume)".
/// Uses task_transitions directly: the FSM edge BlockedRecoveryPending→Admitted
/// is legal per the FSM table in task_transitions.rs.
async fn handle_resume_task(
    task_id:    String,
    _resumed_by: String,
    ctx: &HandlerContext,
) -> OperatorResponse {
    use crate::initiatives::task_transitions::{transition_task, TransitionActor};
    use raxis_types::TaskState;

    let actor = TransitionActor::Operator { fingerprint: _resumed_by.clone() };
    match transition_task(&task_id, TaskState::Admitted, None, actor, &ctx.store) {
        Ok(()) => OperatorResponse::Ack {
            message: format!("task {task_id} resumed (→ Admitted)"),
        },
        Err(e) => OperatorResponse::Error {
            code:   "FAIL_RESUME_TASK".to_owned(),
            detail: e.to_string(),
        },
    }
}

/// AbortTask — cancel a single non-terminal task.
async fn handle_abort_task(
    task_id:    String,
    aborted_by: String,
    ctx: &HandlerContext,
) -> OperatorResponse {
    match lifecycle::abort_task(&task_id, &aborted_by, &ctx.store) {
        Ok(()) => OperatorResponse::Ack {
            message: format!("task {task_id} aborted"),
        },
        Err(e) => OperatorResponse::Error {
            code:   "FAIL_ABORT_TASK".to_owned(),
            detail: e.to_string(),
        },
    }
}

/// AbortInitiative — set status = Aborted; cancel all non-terminal tasks.
async fn handle_abort_initiative(
    initiative_id: String,
    aborted_by:    String,
    ctx: &HandlerContext,
) -> OperatorResponse {
    match lifecycle::abort_initiative(&initiative_id, &aborted_by, &ctx.store) {
        Ok(()) => OperatorResponse::Ack {
            message: format!("initiative {initiative_id} aborted"),
        },
        Err(e) => OperatorResponse::Error {
            code:   "FAIL_ABORT_INITIATIVE".to_owned(),
            detail: e.to_string(),
        },
    }
}

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

fn op_name(req: &OperatorRequest) -> &'static str {
    match req {
        OperatorRequest::CreateSession { .. }  => "CreateSession",
        OperatorRequest::RevokeSession { .. }  => "RevokeSession",
        OperatorRequest::GrantDelegation { .. }=> "GrantDelegation",
        OperatorRequest::CreateInitiative { .. }=> "CreateInitiative",
        OperatorRequest::ApprovePlan { .. }     => "ApprovePlan",
        OperatorRequest::RejectPlan { .. }      => "RejectPlan",
        OperatorRequest::RetryTask { .. }       => "RetryTask",
        OperatorRequest::ResumeTask { .. }      => "ResumeTask",
        OperatorRequest::AbortTask { .. }       => "AbortTask",
        OperatorRequest::AbortInitiative { .. } => "AbortInitiative",
        OperatorRequest::ApproveEscalation { .. }=> "ApproveEscalation",
        OperatorRequest::DenyEscalation { .. }  => "DenyEscalation",
        OperatorRequest::RotateEpoch { .. }     => "RotateEpoch",
    }
}

async fn write_response(
    stream: &mut UnixStream,
    resp: &OperatorResponse,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let bytes = serde_json::to_vec(resp)?;
    let len = bytes.len() as u32;
    stream.write_all(&len.to_le_bytes()).await?;
    stream.write_all(&bytes).await?;
    Ok(())
}

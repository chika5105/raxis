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

use raxis_ipc::{read_json_frame_async, write_json_frame_async, JsonFrameError};
use tokio::net::UnixStream;

use crate::authority;
use crate::initiatives::lifecycle;
use crate::ipc::auth::AuthenticatedOperator;
use crate::ipc::context::HandlerContext;

// ---------------------------------------------------------------------------
// Wire types (OperatorRequest / OperatorResponse)
//
// **Single source of truth: `raxis_types::operator_wire`.** Both this
// dispatcher (deserialise) and every `cli/src/commands/*` JSON
// construction site (serialise) MUST go through that module — the CLI
// builds typed values and serialises with `serde_json::to_value`, the
// kernel deserialises into the same types. Any new operator op MUST be
// added in `operator_wire.rs` first; the wire-shape contract tests
// there will catch field-name or tag drift between the two halves.
//
// Why a JSON-shape type set co-exists with `raxis_types::operator`
// (the bincode-shape design): the planner socket uses bincode + typed
// IDs; the operator socket uses JSON + plain strings. They are
// genuinely two protocols. `operator.rs` is the v2 destination,
// `operator_wire.rs` is the v1 contract.
// ---------------------------------------------------------------------------

pub use raxis_types::operator_wire::{OperatorRequest, OperatorResponse};

/// Dispatch loop for one authenticated operator connection.
///
/// Reads requests in a loop, dispatches each one, writes one response.
/// Returns when the connection is closed or a fatal framing error occurs.
pub async fn dispatch_loop(
    mut stream: UnixStream,
    operator: AuthenticatedOperator,
    ctx: Arc<HandlerContext>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Framing routes through `raxis-ipc::json_frame` so the kernel and CLI
    // share one source of truth (PR-2 — earlier the kernel and CLI used
    // independent hand-rolled framings with different byte orders, making
    // the operator socket non-functional end-to-end).
    loop {
        let request: OperatorRequest = match read_json_frame_async(&mut stream).await {
            Ok(r) => r,
            // Clean disconnect between frames — peer closed the socket.
            Err(JsonFrameError::Eof) => return Ok(()),
            // Malformed JSON: send an error frame and keep the connection
            // open so the CLI can show a useful message.
            Err(JsonFrameError::Decode(e)) => {
                let resp = OperatorResponse::Error {
                    code: "INVALID_REQUEST".to_owned(),
                    detail: e.to_string(),
                };
                write_json_frame_async(&mut stream, &resp).await?;
                continue;
            }
            // Anything else (Io, TooLarge, Encode) is fatal for this connection.
            Err(other) => return Err(Box::new(other)),
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
            write_json_frame_async(&mut stream, &resp).await?;
            continue;
        }

        // Dispatch.
        let response = handle_request(request, &operator, &ctx).await;
        write_json_frame_async(&mut stream, &response).await?;
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
            handle_approve_plan(initiative_id, approving_operator, operator_pubkey_hex, operator, ctx).await
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
            let revoked_at = raxis_types::unix_now_secs();
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
/// Spec: kernel-store.md §2.5.3 "approve_plan call path" + v1-review item #11.
///
/// Trust model — the operator pubkey comes from **policy, not the wire**.
///
///   The connected operator is authenticated by the challenge-response
///   handshake at connection time (`AuthenticatedOperator { fingerprint, .. }`).
///   The `ApprovePlan` request also carries `approving_operator` and a legacy
///   `operator_pubkey_hex` field. Per `kernel-store.md` §2.5.3:
///
///     - `approving_operator` MUST equal the authenticated fingerprint
///       (no impersonation between operators on the wire).
///     - The pubkey used for signature verification MUST be looked up from
///       `policy.operator_entry(approving_operator).pubkey_hex`. The wire
///       field `operator_pubkey_hex` is **ignored** — accepting it would let
///       a malicious caller substitute their own key. We keep the wire field
///       in the request type only for back-compat with already-deployed
///       CLI builds; new clients SHOULD send an empty string.
///
/// Only after the identity check passes do we resolve the policy pubkey,
/// hex-decode it, and hand the bytes to `lifecycle::approve_plan`, which
/// then performs canonical Ed25519 verification over the plan signing domain.
async fn handle_approve_plan(
    initiative_id:        String,
    approving_operator:   String,
    _operator_pubkey_hex: String,
    authenticated:        &AuthenticatedOperator,
    ctx: &HandlerContext,
) -> OperatorResponse {
    if approving_operator != authenticated.fingerprint {
        return OperatorResponse::Error {
            code:   "FAIL_OPERATOR_IDENTITY_MISMATCH".to_owned(),
            detail: format!(
                "request.approving_operator='{approving_operator}' does not match \
                 authenticated operator '{}'",
                authenticated.fingerprint,
            ),
        };
    }

    // Single source of truth for trusted operators and their pubkeys.
    let entry = match ctx.policy.operator_entry(&approving_operator) {
        Some(e) => e,
        None => return OperatorResponse::Error {
            code:   "FAIL_OPERATOR_UNKNOWN".to_owned(),
            detail: format!(
                "approving_operator '{approving_operator}' has no entry in policy.operators",
            ),
        },
    };

    let pubkey_bytes = match hex::decode(&entry.pubkey_hex) {
        Ok(b) => b,
        Err(e) => return OperatorResponse::Error {
            // Policy validation should have caught this at load time; reaching
            // this branch indicates either a corrupted policy file accepted by
            // an older loader, or hand-editing of the in-memory bundle.
            code:   "FAIL_POLICY_OPERATOR_PUBKEY_INVALID".to_owned(),
            detail: format!(
                "policy entry for '{approving_operator}' has malformed pubkey_hex: {e}",
            ),
        },
    };

    let policy_epoch = ctx.policy.epoch();
    match lifecycle::approve_plan(
        &initiative_id,
        &approving_operator,
        &pubkey_bytes,
        policy_epoch,
        &ctx.store,
        &*ctx.audit,
        &ctx.plan_registry,
    ) {
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

// `write_response` was inlined into `dispatch_loop` once framing moved to
// `raxis_ipc::write_json_frame_async`. Kept this comment to explain the
// rename in case anyone diffs against the pre-PR-2 history.


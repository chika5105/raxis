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
//   CreateSession      — fully wired (authority::session::create_session)
//   RevokeSession      — fully wired (authority::session::revoke_session)
//   GrantDelegation    — fully wired (authority::delegation::grant_delegation)
//   CreateInitiative   — fully wired (initiatives::lifecycle::create_initiative)
//   ApprovePlan        — fully wired (initiatives::lifecycle::approve_plan)
//   RejectPlan         — fully wired (initiatives::lifecycle::reject_plan)
//   AbortInitiative    — fully wired (initiatives::lifecycle::abort_initiative)
//   AbortTask          — fully wired (initiatives::lifecycle::abort_task)
//   ResumeTask         — fully wired (task_transitions::transition_task)
//   RetryTask          — fully wired (initiatives::lifecycle::retry_task)
//   ApproveEscalation  — fully wired (authority::escalation::approve_escalation)
//   DenyEscalation     — fully wired (authority::escalation::deny_escalation)
//   RotateEpoch        — stub (policy_manager::advance_epoch not yet implemented)

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
        OperatorRequest::ApproveEscalation { escalation_id, approval_scope, operator_sig_hex } => {
            handle_approve_escalation(escalation_id, approval_scope, operator_sig_hex, operator, ctx).await
        }
        OperatorRequest::DenyEscalation { escalation_id, reason } => {
            handle_deny_escalation(escalation_id, reason, operator, ctx).await
        }
        // Tier 2 stub:
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
            if !ctx.policy.load().worktree_root_allowed(&canonical_str) {
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

    // FSM call goes through spawn_blocking — `authority::session::create_session`
    // takes the store mutex via `Store::lock_sync()`, which panics if
    // called directly from an async task ("Cannot block the current
    // thread from within a runtime"). Same pattern as `main.rs` Step
    // 6/7b and the escalation handlers below.
    let config           = SessionConfig::default();
    let role_for_blocking         = role.clone();
    let worktree_for_blocking     = worktree_root.clone();
    let base_sha_for_blocking     = base_sha.clone();
    let base_track_for_blocking   = base_tracking_ref.clone();
    let lineage_for_blocking      = lineage_id.clone();
    let store_for_blocking        = Arc::clone(&ctx.store);
    let join_result = tokio::task::spawn_blocking(move || {
        authority::session::create_session(
            role_for_blocking,
            worktree_for_blocking,
            base_sha_for_blocking,
            base_track_for_blocking,
            lineage_for_blocking,
            &config,
            &store_for_blocking,
        )
    }).await;
    let create_outcome = match join_result {
        Ok(r) => r,
        Err(e) => return OperatorResponse::Error {
            code:   "FAIL_CREATE_SESSION".to_owned(),
            detail: format!("create_session spawn_blocking join failed: {e}"),
        },
    };

    match create_outcome {
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

    let store_for_blocking      = Arc::clone(&ctx.store);
    let session_id_for_blocking = session_id.clone();
    let join_result = tokio::task::spawn_blocking(move || {
        authority::session::revoke_session(&session_id_for_blocking, &store_for_blocking)
    }).await;
    let revoke_outcome = match join_result {
        Ok(r) => r,
        Err(e) => return OperatorResponse::Error {
            code:   "FAIL_REVOKE_SESSION".to_owned(),
            detail: format!("revoke_session spawn_blocking join failed: {e}"),
        },
    };

    match revoke_outcome {
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

    // Get operator pubkey from policy. We pin one snapshot of the
    // bundle for the duration of this handler so the pubkey lookup and
    // the `max_delegation_ttl` read see the same epoch.
    let policy_snapshot = ctx.policy.load_full();
    let op_entry = match policy_snapshot.operator_entry(&operator.fingerprint) {
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

    let store_for_blocking         = Arc::clone(&ctx.store);
    let session_for_blocking       = session_id.clone();
    let delegation_for_blocking    = delegation_id.clone();
    let capability_for_blocking    = capability_class.clone();
    let scope_for_blocking         = scope_json.clone();
    let fp_for_blocking            = operator.fingerprint.clone();
    let max_ttl                    = policy_snapshot.max_delegation_ttl().as_secs();
    let join_result = tokio::task::spawn_blocking(move || {
        authority::delegation::grant_delegation(
            &session_for_blocking,
            &delegation_for_blocking,
            &capability_for_blocking,
            scope_for_blocking.as_deref(),
            &fp_for_blocking,
            ttl_secs,
            max_uses,
            &signature_bytes,
            &pubkey_bytes,
            max_ttl,
            &store_for_blocking,
        )
    }).await;
    let grant_outcome = match join_result {
        Ok(r) => r,
        Err(e) => return OperatorResponse::Error {
            code:   "FAIL_GRANT_DELEGATION".to_owned(),
            detail: format!("grant_delegation spawn_blocking join failed: {e}"),
        },
    };

    match grant_outcome {
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
    let store_for_blocking = Arc::clone(&ctx.store);
    let join_result = tokio::task::spawn_blocking(move || {
        lifecycle::create_initiative(&plan_toml, &plan_sig_hex, &submitted_by, &store_for_blocking)
    }).await;
    let outcome = match join_result {
        Ok(r) => r,
        Err(e) => return OperatorResponse::Error {
            code:   "FAIL_CREATE_INITIATIVE".to_owned(),
            detail: format!("create_initiative spawn_blocking join failed: {e}"),
        },
    };
    match outcome {
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
    // Pin one snapshot so the pubkey lookup and the epoch read see the
    // same bundle.
    let policy_snapshot = ctx.policy.load_full();
    let entry = match policy_snapshot.operator_entry(&approving_operator) {
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

    let policy_epoch = policy_snapshot.epoch();
    let store_for_blocking          = Arc::clone(&ctx.store);
    let audit_for_blocking          = Arc::clone(&ctx.audit);
    let plan_registry_for_blocking  = Arc::clone(&ctx.plan_registry);
    let initiative_id_for_blocking  = initiative_id.clone();
    let approving_op_for_blocking   = approving_operator.clone();
    let join_result = tokio::task::spawn_blocking(move || {
        lifecycle::approve_plan(
            &initiative_id_for_blocking,
            &approving_op_for_blocking,
            &pubkey_bytes,
            policy_epoch,
            &store_for_blocking,
            &*audit_for_blocking,
            &plan_registry_for_blocking,
        )
    }).await;
    let outcome = match join_result {
        Ok(r) => r,
        Err(e) => return OperatorResponse::Error {
            code:   "FAIL_APPROVE_PLAN".to_owned(),
            detail: format!("approve_plan spawn_blocking join failed: {e}"),
        },
    };
    match outcome {
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
    let store_for_blocking         = Arc::clone(&ctx.store);
    let initiative_id_for_blocking = initiative_id.clone();
    let rejected_by_for_blocking   = rejected_by.clone();
    let reason_for_blocking        = reason.clone();
    let join_result = tokio::task::spawn_blocking(move || {
        lifecycle::reject_plan(
            &initiative_id_for_blocking,
            &rejected_by_for_blocking,
            reason_for_blocking.as_deref(),
            &store_for_blocking,
        )
    }).await;
    let outcome = match join_result {
        Ok(r) => r,
        Err(e) => return OperatorResponse::Error {
            code:   "FAIL_REJECT_PLAN".to_owned(),
            detail: format!("reject_plan spawn_blocking join failed: {e}"),
        },
    };
    match outcome {
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
    let store_for_blocking   = Arc::clone(&ctx.store);
    let task_id_for_blocking = task_id.clone();
    let join_result = tokio::task::spawn_blocking(move || {
        lifecycle::retry_task(&task_id_for_blocking, &store_for_blocking)
    }).await;
    let outcome = match join_result {
        Ok(r) => r,
        Err(e) => return OperatorResponse::Error {
            code:   "FAIL_RETRY_TASK".to_owned(),
            detail: format!("retry_task spawn_blocking join failed: {e}"),
        },
    };
    match outcome {
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
    resumed_by: String,
    ctx: &HandlerContext,
) -> OperatorResponse {
    use crate::initiatives::task_transitions::{transition_task, TransitionActor};
    use raxis_types::TaskState;

    let store_for_blocking   = Arc::clone(&ctx.store);
    let task_id_for_blocking = task_id.clone();
    let resumed_by_for_blocking = resumed_by.clone();
    let join_result = tokio::task::spawn_blocking(move || {
        let actor = TransitionActor::Operator { fingerprint: resumed_by_for_blocking };
        transition_task(&task_id_for_blocking, TaskState::Admitted, None, actor, &store_for_blocking)
    }).await;
    let outcome = match join_result {
        Ok(r) => r,
        Err(e) => return OperatorResponse::Error {
            code:   "FAIL_RESUME_TASK".to_owned(),
            detail: format!("resume_task spawn_blocking join failed: {e}"),
        },
    };
    match outcome {
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
    let store_for_blocking      = Arc::clone(&ctx.store);
    let task_id_for_blocking    = task_id.clone();
    let aborted_by_for_blocking = aborted_by.clone();
    let join_result = tokio::task::spawn_blocking(move || {
        lifecycle::abort_task(&task_id_for_blocking, &aborted_by_for_blocking, &store_for_blocking)
    }).await;
    let outcome = match join_result {
        Ok(r) => r,
        Err(e) => return OperatorResponse::Error {
            code:   "FAIL_ABORT_TASK".to_owned(),
            detail: format!("abort_task spawn_blocking join failed: {e}"),
        },
    };
    match outcome {
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
    let store_for_blocking          = Arc::clone(&ctx.store);
    let initiative_id_for_blocking  = initiative_id.clone();
    let aborted_by_for_blocking     = aborted_by.clone();
    let join_result = tokio::task::spawn_blocking(move || {
        lifecycle::abort_initiative(
            &initiative_id_for_blocking,
            &aborted_by_for_blocking,
            &store_for_blocking,
        )
    }).await;
    let outcome = match join_result {
        Ok(r) => r,
        Err(e) => return OperatorResponse::Error {
            code:   "FAIL_ABORT_INITIATIVE".to_owned(),
            detail: format!("abort_initiative spawn_blocking join failed: {e}"),
        },
    };
    match outcome {
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
// Escalation review handlers (kernel-store.md §2.5.5)
// ---------------------------------------------------------------------------

/// `ApproveEscalation` — flips a `Pending` escalation to `Approved`,
/// inserts an `approval_tokens` row, and returns the high-entropy raw
/// token to the operator. The operator passes the token to the planner
/// out-of-band; subsequent intent submissions present the token and the
/// kernel re-derives `sha256(raw)` to look it up (kernel-core.md
/// §2.3 `validate_approval_token`).
///
/// The actual FSM call goes through `tokio::task::spawn_blocking`
/// because `authority::escalation::approve_escalation` reaches into
/// `Store::lock_sync()` (sync `tokio::sync::Mutex::blocking_lock`),
/// which panics if called directly from an async task. Same pattern
/// `main.rs` uses for `recovery::reconcile` and the verifier-token
/// issuance path in `gates::verifier_runner`.
async fn handle_approve_escalation(
    escalation_id:    String,
    approval_scope:   raxis_types::operator_wire::ApprovalScopeWire,
    operator_sig_hex: String,
    operator:         &AuthenticatedOperator,
    ctx:              &HandlerContext,
) -> OperatorResponse {
    let signature = match hex::decode(&operator_sig_hex) {
        Ok(b) => b,
        Err(e) => return OperatorResponse::Error {
            code:   "FAIL_APPROVE_ESCALATION".to_owned(),
            detail: format!("operator_sig_hex is not valid hex: {e}"),
        },
    };

    // Pin one snapshot of the bundle: the FSM call below must run
    // against the same epoch we recorded in the audit metadata.
    let policy_snapshot       = ctx.policy.load_full();
    let store_for_blocking    = Arc::clone(&ctx.store);
    let fp_for_blocking       = operator.fingerprint.clone();
    let escalation_id_blocking = escalation_id.clone();
    let scope_for_blocking    = approval_scope.clone();
    let policy_epoch          = policy_snapshot.epoch();

    let join_result = tokio::task::spawn_blocking(move || {
        crate::authority::escalation::approve_escalation(
            &escalation_id_blocking,
            &scope_for_blocking,
            &signature,
            &fp_for_blocking,
            policy_epoch,
            &policy_snapshot,
            &store_for_blocking,
        )
    }).await;

    let approve_outcome = match join_result {
        Ok(r) => r,
        Err(join_err) => return OperatorResponse::Error {
            code:   "FAIL_APPROVE_ESCALATION".to_owned(),
            detail: format!("approve_escalation spawn_blocking join failed: {join_err}"),
        },
    };

    match approve_outcome {
        Ok(result) => {
            // Audit emission MUST follow a successful SQLite commit
            // (kernel-store.md §2.5.2). `approve_escalation` already
            // returned Ok so the row is in place; failures here are
            // logged but do not propagate so the operator's intent is
            // still honoured (`recovery::reconcile` will detect any
            // §2.5.2 commit-vs-audit gap on next boot).
            if let Err(e) = ctx.audit.emit(
                raxis_audit_tools::AuditEventKind::EscalationApproved {
                    escalation_id: escalation_id.clone(),
                    approved_by:   operator.fingerprint.clone(),
                },
                None,
                None,
                None,
            ) {
                eprintln!(
                    "{{\"level\":\"error\",\"event\":\"EscalationApproved\",\
                     \"audit_emit_failed\":\"{e}\",\"escalation_id\":\"{escalation_id}\"}}",
                );
            }
            OperatorResponse::EscalationApproved {
                escalation_id,
                approval_token_id:  result.approval_token_id,
                approval_token_raw: result.approval_token_raw,
                expires_at:         result.expires_at,
            }
        }
        Err(e) => OperatorResponse::Error {
            code:   e.error_code().to_owned(),
            detail: e.to_string(),
        },
    }
}

/// `DenyEscalation` — flips a `Pending` escalation to `Denied`. No
/// approval artifact is created (no `approval_tokens` row); the audit
/// event is the only durable record per kernel-store.md §2.5.5.
async fn handle_deny_escalation(
    escalation_id: String,
    reason:        Option<String>,
    operator:      &AuthenticatedOperator,
    ctx:           &HandlerContext,
) -> OperatorResponse {
    if let Some(r) = reason.as_ref() {
        if r.chars().count() > 512 {
            return OperatorResponse::Error {
                code:   "FAIL_DENY_ESCALATION".to_owned(),
                detail: format!(
                    "reason exceeds 512-character limit (was {} chars)",
                    r.chars().count()
                ),
            };
        }
    }
    let store_for_blocking     = Arc::clone(&ctx.store);
    let fp_for_blocking        = operator.fingerprint.clone();
    let escalation_id_blocking = escalation_id.clone();
    let reason_for_blocking    = reason.clone();
    let join_result = tokio::task::spawn_blocking(move || {
        crate::authority::escalation::deny_escalation(
            &escalation_id_blocking,
            reason_for_blocking.as_deref(),
            &fp_for_blocking,
            &store_for_blocking,
        )
    }).await;
    let deny_outcome = match join_result {
        Ok(r) => r,
        Err(join_err) => return OperatorResponse::Error {
            code:   "FAIL_DENY_ESCALATION".to_owned(),
            detail: format!("deny_escalation spawn_blocking join failed: {join_err}"),
        },
    };
    match deny_outcome {
        Ok(result) => {
            if let Err(e) = ctx.audit.emit(
                raxis_audit_tools::AuditEventKind::EscalationDenied {
                    escalation_id: escalation_id.clone(),
                    denied_by:     operator.fingerprint.clone(),
                    reason:        reason.clone(),
                },
                None,
                None,
                None,
            ) {
                eprintln!(
                    "{{\"level\":\"error\",\"event\":\"EscalationDenied\",\
                     \"audit_emit_failed\":\"{e}\",\"escalation_id\":\"{escalation_id}\"}}",
                );
            }
            OperatorResponse::EscalationDenied {
                escalation_id,
                denied_at: result.denied_at,
            }
        }
        Err(e) => OperatorResponse::Error {
            code:   e.error_code().to_owned(),
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

// ---------------------------------------------------------------------------
// Tests — focused tests for the escalation dispatcher arms.
//
// The bulk of the FSM logic is unit-tested in
// `authority::escalation::tests`; what we cover here is the dispatcher-
// only behaviour:
//   * sig hex decoding,
//   * 512-char `reason` cap on DenyEscalation,
//   * `EscalationApproved` / `EscalationDenied` audit events fire after
//     a successful FSM transition, and
//   * `EscalationError` variants are mapped to the right operator
//     wire `code` strings.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod escalation_dispatch_tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::Arc;

    use ed25519_dalek::{Signer, SigningKey};
    use raxis_audit_tools::{AuditEventKind, FakeAuditSink};
    use raxis_policy::{OperatorEntry, PolicyBundle};
    use raxis_store::Store;
    use raxis_types::operator_wire::ApprovalScopeWire;

    use crate::authority::escalation::approval_scope_signing_input;
    use crate::authority::keys::KeyRegistry;
    use crate::initiatives::PlanRegistry;
    use crate::ipc::auth::AuthenticatedOperator;

    // ── shared fixtures ───────────────────────────────────────────────

    const FP: &str = "op-prime";

    fn fixture_keypair() -> SigningKey { SigningKey::from_bytes(&[7u8; 32]) }

    fn fixture_scope() -> ApprovalScopeWire {
        ApprovalScopeWire {
            capability_class:  "WriteSecrets".into(),
            max_uses:          2,
            valid_for_seconds: 600,
        }
    }

    fn build_ctx(store: Arc<Store>, sink: Arc<FakeAuditSink>, sk: &SigningKey) -> Arc<HandlerContext> {
        let policy = PolicyBundle::for_tests_with_operators(vec![OperatorEntry {
            pubkey_fingerprint: FP.to_owned(),
            display_name:       FP.to_owned(),
            pubkey_hex:         hex::encode(sk.verifying_key().to_bytes()),
            permitted_ops:      vec![],
        }]);
        Arc::new(HandlerContext::new(
            Arc::new(arc_swap::ArcSwap::from_pointee(policy)),
            Arc::new(KeyRegistry::stub_for_tests()),
            store,
            sink,
            PathBuf::from("/tmp/raxis-test"),
            Arc::new(PlanRegistry::new()),
            Arc::new(crate::gateway::client::GatewayClient::new()),
        ))
    }

    fn fixture_authenticated() -> AuthenticatedOperator {
        AuthenticatedOperator {
            fingerprint:   FP.to_owned(),
            permitted_ops: vec!["ApproveEscalation".into(), "DenyEscalation".into()],
        }
    }

    /// Insert a Pending escalation row. We MUST use `tokio::task::spawn_blocking`
    /// because the dispatcher tests run under `#[tokio::test]`, where any
    /// synchronous `Store::lock_sync()` call from the runtime thread
    /// panics with "Cannot block the current thread from within a
    /// runtime" (kernel-store.md §2.5.1 sync-store contract).
    async fn insert_pending_escalation(store: Arc<Store>, escalation_id: &str) {
        let id = escalation_id.to_owned();
        tokio::task::spawn_blocking(move || {
            let conn = store.lock_sync();
            conn.execute("PRAGMA foreign_keys = OFF", []).unwrap();
            conn.execute(
                "INSERT INTO escalations (
                    escalation_id, session_id, task_id, lineage_id, initiative_id,
                    class, requested_scope_json, justification, idempotency_key,
                    status, created_at, timeout_at
                 ) VALUES (?1, 'sess-1', 'task-1', 'lin-1', 'init-1',
                           'CapabilityUpgrade',
                           '{\"kind\":\"CapabilityUpgrade\",\"capability\":\"WriteSecrets\"}',
                           'unit-test', ?2, 'Pending', ?3, ?4)",
                rusqlite::params![
                    id, id,
                    raxis_types::unix_now_secs(),
                    raxis_types::unix_now_secs() + 3600,
                ],
            ).unwrap();
            conn.execute("PRAGMA foreign_keys = ON", []).unwrap();
        }).await.unwrap();
    }

    /// Read a column from the escalations row from inside an async test.
    /// Same `spawn_blocking` requirement as `insert_pending_escalation`.
    async fn read_status(store: Arc<Store>, escalation_id: &str) -> String {
        let id = escalation_id.to_owned();
        tokio::task::spawn_blocking(move || {
            let conn = store.lock_sync();
            conn.query_row(
                "SELECT status FROM escalations WHERE escalation_id = ?1",
                rusqlite::params![id], |r| r.get(0),
            ).unwrap()
        }).await.unwrap()
    }

    /// Force the escalation row's status (used to set up the
    /// "already-Approved" fixture for the NotPending error path).
    async fn force_status(store: Arc<Store>, escalation_id: &str, status: &str) {
        let id     = escalation_id.to_owned();
        let status = status.to_owned();
        tokio::task::spawn_blocking(move || {
            store.lock_sync().execute(
                "UPDATE escalations SET status = ?1 WHERE escalation_id = ?2",
                rusqlite::params![status, id],
            ).unwrap();
        }).await.unwrap();
    }

    // ── ApproveEscalation ─────────────────────────────────────────────

    #[tokio::test]
    async fn approve_escalation_happy_path_returns_typed_response_and_emits_audit() {
        let store = Arc::new(Store::open_in_memory().unwrap());
        let sink  = Arc::new(FakeAuditSink::new());
        let sk    = fixture_keypair();
        let ctx   = build_ctx(store.clone(), sink.clone(), &sk);
        let op    = fixture_authenticated();
        let scope = fixture_scope();

        insert_pending_escalation(store.clone(), "esc-A").await;

        let sig = sk.sign(&approval_scope_signing_input("esc-A", &scope))
            .to_bytes().to_vec();

        let resp = handle_approve_escalation(
            "esc-A".into(), scope, hex::encode(&sig), &op, &ctx,
        ).await;

        match resp {
            OperatorResponse::EscalationApproved {
                escalation_id, approval_token_id, approval_token_raw, expires_at
            } => {
                assert_eq!(escalation_id, "esc-A");
                assert!(uuid::Uuid::parse_str(&approval_token_id).is_ok());
                assert_eq!(approval_token_raw.len(), 64);
                assert!(expires_at > raxis_types::unix_now_secs());
            }
            other => panic!("expected EscalationApproved, got {other:?}"),
        }

        // Exactly one EscalationApproved audit event emitted.
        let kinds = sink.event_kinds();
        let approved_count = kinds.iter().filter(|k| **k == "EscalationApproved").count();
        assert_eq!(approved_count, 1,
            "exactly one EscalationApproved audit event must fire; got: {kinds:?}");
        // Audit payload carries the right (escalation_id, approved_by) pair.
        let evt = sink.events().into_iter()
            .find(|e| matches!(e.kind, AuditEventKind::EscalationApproved { .. }))
            .expect("EscalationApproved event present");
        match evt.kind {
            AuditEventKind::EscalationApproved { escalation_id, approved_by } => {
                assert_eq!(escalation_id, "esc-A");
                assert_eq!(approved_by, FP);
            }
            other => panic!("wrong event kind: {other:?}"),
        }
    }

    #[tokio::test]
    async fn approve_escalation_with_malformed_signature_hex_is_rejected() {
        let store = Arc::new(Store::open_in_memory().unwrap());
        let sink  = Arc::new(FakeAuditSink::new());
        let ctx   = build_ctx(store.clone(), sink.clone(), &fixture_keypair());
        let op    = fixture_authenticated();
        insert_pending_escalation(store.clone(), "esc-1").await;

        let resp = handle_approve_escalation(
            "esc-1".into(),
            fixture_scope(),
            "ZZZ_not_hex".into(),
            &op, &ctx,
        ).await;

        match resp {
            OperatorResponse::Error { code, detail } => {
                assert_eq!(code, "FAIL_APPROVE_ESCALATION");
                assert!(detail.contains("not valid hex"),
                    "detail must explain hex decode failure; got: {detail}");
            }
            other => panic!("expected Error, got {other:?}"),
        }
        // No audit event fires when hex decode fails before the FSM call.
        assert!(!sink.event_kinds().contains(&"EscalationApproved"));
    }

    #[tokio::test]
    async fn approve_escalation_maps_not_pending_to_stable_error_code() {
        let store = Arc::new(Store::open_in_memory().unwrap());
        let sink  = Arc::new(FakeAuditSink::new());
        let sk    = fixture_keypair();
        let ctx   = build_ctx(store.clone(), sink.clone(), &sk);
        let op    = fixture_authenticated();
        let scope = fixture_scope();

        insert_pending_escalation(store.clone(), "esc-1").await;
        // Force the row to Approved so the second approve attempt fails.
        force_status(store.clone(), "esc-1", "Approved").await;

        let sig = sk.sign(&approval_scope_signing_input("esc-1", &scope))
            .to_bytes().to_vec();

        let resp = handle_approve_escalation(
            "esc-1".into(), scope, hex::encode(&sig), &op, &ctx,
        ).await;

        match resp {
            OperatorResponse::Error { code, .. } => {
                assert_eq!(code, "FAIL_ESCALATION_NOT_PENDING");
            }
            other => panic!("expected NotPending Error, got {other:?}"),
        }
        // No audit event fires for failed approvals (the row never moved).
        assert!(!sink.event_kinds().contains(&"EscalationApproved"));
    }

    // ── DenyEscalation ────────────────────────────────────────────────

    #[tokio::test]
    async fn deny_escalation_happy_path_returns_typed_response_and_emits_audit() {
        let store = Arc::new(Store::open_in_memory().unwrap());
        let sink  = Arc::new(FakeAuditSink::new());
        let ctx   = build_ctx(store.clone(), sink.clone(), &fixture_keypair());
        let op    = fixture_authenticated();
        insert_pending_escalation(store.clone(), "esc-D").await;

        let resp = handle_deny_escalation(
            "esc-D".into(),
            Some("scope too broad".into()),
            &op, &ctx,
        ).await;

        match resp {
            OperatorResponse::EscalationDenied { escalation_id, denied_at } => {
                assert_eq!(escalation_id, "esc-D");
                assert!(denied_at > 0);
            }
            other => panic!("expected EscalationDenied, got {other:?}"),
        }

        let evt = sink.events().into_iter()
            .find(|e| matches!(e.kind, AuditEventKind::EscalationDenied { .. }))
            .expect("EscalationDenied event present");
        match evt.kind {
            AuditEventKind::EscalationDenied { escalation_id, denied_by, reason } => {
                assert_eq!(escalation_id, "esc-D");
                assert_eq!(denied_by, FP);
                assert_eq!(reason.as_deref(), Some("scope too broad"));
            }
            other => panic!("wrong event kind: {other:?}"),
        }
    }

    #[tokio::test]
    async fn deny_escalation_rejects_reason_over_512_chars_before_touching_store() {
        let store = Arc::new(Store::open_in_memory().unwrap());
        let sink  = Arc::new(FakeAuditSink::new());
        let ctx   = build_ctx(store.clone(), sink.clone(), &fixture_keypair());
        let op    = fixture_authenticated();
        insert_pending_escalation(store.clone(), "esc-1").await;

        let too_long: String = "x".repeat(513);
        let resp = handle_deny_escalation(
            "esc-1".into(), Some(too_long), &op, &ctx,
        ).await;

        match resp {
            OperatorResponse::Error { code, detail } => {
                assert_eq!(code, "FAIL_DENY_ESCALATION");
                assert!(detail.contains("512-character limit"),
                    "detail must call out the 512 cap; got: {detail}");
            }
            other => panic!("expected Error, got {other:?}"),
        }
        // The escalation row MUST still be Pending — the cap fires
        // before any store write.
        assert_eq!(read_status(store.clone(), "esc-1").await, "Pending");
        // No audit event for a rejected denial.
        assert!(!sink.event_kinds().contains(&"EscalationDenied"));
    }

    // ── Regression: pre-existing handlers run under spawn_blocking (B.1) ─
    //
    // The 10 pre-existing operator handlers (CreateSession, RevokeSession,
    // GrantDelegation, CreateInitiative, ApprovePlan, RejectPlan,
    // RetryTask, ResumeTask, AbortTask, AbortInitiative) were calling
    // synchronous FSM functions directly inside `async fn` bodies. Those
    // FSMs use `Store::lock_sync()`, which calls
    // `tokio::sync::Mutex::blocking_lock()` and PANICS when invoked from
    // an async task ("Cannot block the current thread from within a
    // runtime"). Phase B.1 wrapped each handler's FSM call in
    // `tokio::task::spawn_blocking`. The tests below run a representative
    // handler (`handle_revoke_session`) end-to-end under `#[tokio::test]`
    // and assert it returns a structured response — which is impossible
    // unless the spawn_blocking wrapping is in place.
    //
    // We pick `handle_revoke_session` because it has the smallest input
    // surface: just a session_id. Hitting the not-found path forces the
    // FSM down to `lock_sync` even on the error side, so "no panic" is
    // the discriminator.

    #[tokio::test]
    async fn revoke_session_runs_under_tokio_without_panic() {
        let store = Arc::new(Store::open_in_memory().unwrap());
        let sink  = Arc::new(FakeAuditSink::new());
        let ctx   = build_ctx(store, sink, &fixture_keypair());

        let resp = handle_revoke_session(
            "00000000-0000-4000-8000-000000000000".into(),
            &ctx,
        ).await;

        // Whatever the outcome, the test passing means the runtime did
        // not panic. The exact code is FAIL_REVOKE_SESSION because the
        // session row doesn't exist.
        match resp {
            OperatorResponse::Error { .. } | OperatorResponse::SessionRevoked { .. } => {},
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    #[tokio::test]
    async fn create_initiative_runs_under_tokio_without_panic() {
        let store = Arc::new(Store::open_in_memory().unwrap());
        let sink  = Arc::new(FakeAuditSink::new());
        let ctx   = build_ctx(store, sink, &fixture_keypair());

        // Empty plan TOML is rejected by the FSM, but the FSM still
        // takes the store mutex on the way to that error — same
        // spawn_blocking gate as the happy path.
        let resp = handle_create_initiative(
            "[meta]\nplan_id = \"\"\n".into(),
            "deadbeef".into(),
            "op-prime".into(),
            &ctx,
        ).await;
        match resp {
            OperatorResponse::Error { .. } | OperatorResponse::InitiativeCreated { .. } => {},
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    #[tokio::test]
    async fn deny_escalation_at_exactly_512_chars_is_accepted() {
        // Boundary: 512 is allowed, 513 is not (covered above).
        let store = Arc::new(Store::open_in_memory().unwrap());
        let sink  = Arc::new(FakeAuditSink::new());
        let ctx   = build_ctx(store.clone(), sink.clone(), &fixture_keypair());
        let op    = fixture_authenticated();
        insert_pending_escalation(store.clone(), "esc-edge").await;

        let exactly_max: String = "x".repeat(512);
        let resp = handle_deny_escalation(
            "esc-edge".into(), Some(exactly_max), &op, &ctx,
        ).await;
        assert!(matches!(resp, OperatorResponse::EscalationDenied { .. }));
    }
}


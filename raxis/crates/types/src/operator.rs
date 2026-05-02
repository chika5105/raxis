// raxis-types::operator — OperatorRequest and OperatorResponse message types.
//
// Normative reference:
//   - peripherals.md §3 "Operator socket" (wire shape, error envelope)
//   - cli-ceremony.md §4.1 (per-subcommand IPC discriminant table)
//   - kernel-core.md handlers/operator.rs (handler signatures)
//
// The operator socket uses the same bincode 2.0.1 + 4-byte LE length-prefix
// framing as the planner socket. OperatorRequest and OperatorResponse are the
// top-level IPC types on that socket.

use crate::{
    CapabilityClass, DelegationId, EscalationId, InitiativeId, InitiativeState,
    OperatorErrorCode, Role, SessionId, TaskId, TaskState, TerminalCriteria,
};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// OperatorRequest — all operator IPC variants.
// cli-ceremony.md §4.1 IPC discriminant table.
// ---------------------------------------------------------------------------

/// Every operator IPC message the kernel accepts on the operator UDS socket.
///
/// Wire: `IpcMessage::OperatorRequest(OperatorRequest)` encoded as bincode
/// 2.0.1 standard() with 4-byte LE length prefix by `raxis-ipc::frame`.
/// The `op_token` (challenge-response operator session token) is carried in
/// the envelope header by ipc/auth.rs, not inside this enum.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "PascalCase")]
pub enum OperatorRequest {
    // --- initiative lifecycle ---
    CreateInitiative {
        initiative_id: InitiativeId,
        plan_toml_path: PathBuf,
        plan_sig_path: PathBuf,
    },
    ApprovePlan {
        initiative_id: InitiativeId,
    },
    RejectPlan {
        initiative_id: InitiativeId,
    },
    AbortInitiative {
        initiative_id: InitiativeId,
    },

    // --- session management ---
    CreateSession {
        role: Role,
        worktree_root: PathBuf,
        /// If None, kernel defaults to refs/heads/main.
        base_tracking_ref: Option<String>,
        /// If Some, kernel binds the session to this task at creation time.
        task_id: Option<TaskId>,
        /// Operator-supplied lineage ID; CLI generates a fresh UUIDv4 if omitted.
        lineage_id: crate::LineageId,
    },
    RevokeSession {
        session_id: SessionId,
    },

    // --- task state operations ---
    AbortTask {
        task_id: TaskId,
    },
    ResumeTask {
        task_id: TaskId,
    },
    RetryTask {
        task_id: TaskId,
    },

    // --- capability delegation ---
    GrantDelegation {
        session_id: SessionId,
        capability_class: CapabilityClass,
        delegating_role_id: String,
        /// Absolute Unix seconds. Kernel computes from now() + ttl_seconds
        /// after this value is validated against policy.delegations.max_ttl_seconds.
        expires_at: crate::id::UnixSeconds,
        scope_json: Option<String>,
        /// Ed25519 signature (64 bytes) over the canonical signing domain
        /// defined in kernel-store.md §2.5.5.
        operator_sig: Vec<u8>,
    },

    // --- escalation ---
    ApproveEscalation {
        escalation_id: EscalationId,
        approval_scope: ApprovalScope,
        /// Ed25519 signature over (escalation_id || approval_scope_canonical_bytes).
        operator_sig: Vec<u8>,
    },
    DenyEscalation {
        escalation_id: EscalationId,
        /// Optional, max 512 chars. Stored in audit only.
        reason: Option<String>,
    },

    // --- policy epoch ---
    RotateEpoch {
        policy_path: PathBuf,
        sig_path: PathBuf,
    },
}

/// The approval scope granted by an operator for an escalation.
/// cli-ceremony.md §`escalation approve`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalScope {
    pub capability_class: CapabilityClass,
    pub max_uses: u32,
    pub valid_for_seconds: u32,
}

// ---------------------------------------------------------------------------
// OperatorResponse — all operator IPC success variants + the error envelope.
// peripherals.md §3 "Operator socket".
// ---------------------------------------------------------------------------

/// Every response the kernel sends back to the operator CLI.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "PascalCase")]
pub enum OperatorResponse {
    // --- success variants ---
    InitiativeCreated { initiative_id: InitiativeId },
    PlanApproved { initiative_id: InitiativeId },
    PlanRejected { initiative_id: InitiativeId },
    InitiativeAborted { initiative_id: InitiativeId },

    SessionCreated {
        session_id: SessionId,
        /// 64-char lowercase hex string (32 raw CSPRNG bytes).
        /// Sent in clear on the operator UDS (mode 0600).
        session_token: String,
        role: Role,
        worktree_root: Option<PathBuf>,
        base_sha: Option<crate::CommitSha>,
        base_tracking_ref: Option<String>,
        expires_at: crate::id::UnixSeconds,
        lineage_id: crate::LineageId,
        bound_task_id: Option<TaskId>,
    },
    SessionRevoked {
        session_id: SessionId,
        revoked_at: crate::id::UnixSeconds,
    },

    TaskAborted { task_id: TaskId },
    TaskResumed {
        task_id: TaskId,
        prior_state: TaskState,
        transitioned_at: crate::id::UnixSeconds,
    },
    TaskRetried {
        task_id: TaskId,
        initiative_id: InitiativeId,
        transitioned_at: crate::id::UnixSeconds,
    },

    DelegationGranted {
        delegation_id: DelegationId,
        granted_at: crate::id::UnixSeconds,
        expires_at: crate::id::UnixSeconds,
        capability_class: CapabilityClass,
    },

    EscalationApproved {
        escalation_id: EscalationId,
        /// UUID of the approval_tokens row — planner must present this.
        approval_id: Uuid,
    },
    EscalationDenied {
        escalation_id: EscalationId,
    },

    EpochAdvanced {
        new_epoch_id: Uuid,
        n_delegations_marked_stale: u64,
        n_sessions_invalidated: u64,
        policy_sha256: String,
    },

    // --- error envelope (single canonical shape for ALL operator errors) ---
    /// peripherals.md §3 "Operator socket" OperatorResponse::Error rule:
    /// every operator error MUST use this variant; the detail tag MUST match
    /// the code. An Error whose detail tag does not match code is a kernel bug
    /// and the CLI rejects it with a hard-fail.
    Error {
        code: OperatorErrorCode,
        detail: OperatorErrorDetail,
    },
}

// ---------------------------------------------------------------------------
// OperatorErrorDetail — structured detail variants; one per OperatorErrorCode.
// peripherals.md §3 "Operator socket" OperatorErrorDetail enum.
// ---------------------------------------------------------------------------

/// Structured detail for operator errors. The variant tag must match the
/// `OperatorErrorCode` in the enclosing `OperatorResponse::Error`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "PascalCase")]
pub enum OperatorErrorDetail {
    TaskNotResumable { current_state: TaskState },
    TaskNotRetryable { current_state: TaskState },
    InitiativeTerminal {
        initiative_state: InitiativeState,
        terminal_criteria: TerminalCriteria,
    },
    PolicySignatureInvalid {
        artifact_path: PathBuf,
    },
    PolicyEpochReplay {
        presented_epoch: u64,
        current_epoch: u64,
    },
    PolicyMalformed {
        parser_message: String,
    },
    PathOutsideDataDir {
        offending_path: PathBuf,
        data_dir: PathBuf,
    },
    StoreWrite {
        sql_error: String,
    },
    OperationNotPermitted {
        operator_id: String,
        attempted_op: String,
    },
    // session management errors
    SessionNotFound {
        session_id: SessionId,
    },
    SessionAlreadyRevoked {
        session_id: SessionId,
        revoked_at: crate::id::UnixSeconds,
    },
    RoleNotOperatorCreatable {
        requested_role: Role,
    },
    WorktreeOutsideAllowedRoots {
        worktree_root: PathBuf,
        allowed_roots: Vec<PathBuf>,
    },
    InvalidLineageId {
        offending_value: String,
        parse_error: String,
    },
    BaseRefUnresolved {
        ref_string: String,
        worktree_root: PathBuf,
        git_stderr: String,
    },
    InvalidTaskState {
        task_id: TaskId,
        current_state: TaskState,
    },
    // delegation errors
    SessionInvalid {
        session_id: SessionId,
        reason: String,
    },
    CapabilityAboveCeiling {
        role_id: String,
        capability_class: CapabilityClass,
    },
    DelegationSignatureInvalid {
        delegation_id_proposed: Uuid,
    },
    DelegationTtlOutOfRange {
        requested_secs: i64,
        max_secs: i64,
    },
    DelegationAlreadyActive {
        existing_delegation_id: DelegationId,
    },
    UnknownCapabilityClass {
        raw_value: String,
    },
    // escalation errors
    EscalationNotPending {
        current_status: String,
    },
}

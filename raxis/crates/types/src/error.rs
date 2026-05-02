// raxis-types::error — PlannerErrorCode and OperatorErrorCode enums.
//
// Normative reference:
//   - peripherals.md §3.1 (planner-facing retry table)
//   - peripherals.md §3 "Operator socket" (OperatorErrorCode table)
//   - planner-api.md §"Error codes and remediation"
//
// Wire form: the enum variants serialize to their SCREAMING_SNAKE_CASE string
// tag (matching the spec tables) via serde rename. bincode encodes them as
// positional u32 discriminants — the string names are for JSON projection
// and audit logging only.

use serde::{Deserialize, Serialize};
use std::fmt;

// ---------------------------------------------------------------------------
// PlannerErrorCode
// peripherals.md §3.1 retry semantics table + `error_code` field rules.
// ---------------------------------------------------------------------------

/// Coarse rejection reason returned to the planner on a Rejected IntentResponse.
///
/// INV-08: the kernel never returns more detail than this code to the planner,
/// except the fixed PlannerErrorTemplate set for FAIL_POLICY_VIOLATION.
/// Full remediation actions are in planner-api.md.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PlannerErrorCode {
    /// One or more committed files are outside the path allowlist. Retryable.
    #[serde(rename = "FAIL_PATH_POLICY_VIOLATION")]
    FailPathPolicyViolation,

    /// Commit range contains a merge commit (non-IntegrationMerge) or the
    /// SingleCommit parent check failed. Retryable.
    #[serde(rename = "FAIL_INVALID_COMMIT_TOPOLOGY")]
    FailInvalidCommitTopology,

    /// Kernel could not compute a clean diff (unresolved conflicts). Retryable.
    #[serde(rename = "FAIL_INVALID_DIFF")]
    FailInvalidDiff,

    /// Required witnesses not yet submitted or gate not cleared. Retryable.
    #[serde(rename = "FAIL_MISSING_WITNESS")]
    FailMissingWitness,

    /// Witness present but evidence below threshold (result_class: Fail). Retryable.
    #[serde(rename = "FAIL_INSUFFICIENT_WITNESS")]
    FailInsufficientWitness,

    /// Intent would exceed remaining lane/session budget. Retryable after rebudget.
    #[serde(rename = "FAIL_BUDGET_EXCEEDED")]
    FailBudgetExceeded,

    /// task_id is not in the signed plan. NOT retryable.
    #[serde(rename = "FAIL_UNKNOWN_TASK")]
    FailUnknownTask,

    /// Task is not in a runnable state (Admitted waiting on DAG, GatesPending,
    /// BlockedRecoveryPending, etc.). Retryable when task becomes runnable.
    #[serde(rename = "FAIL_TASK_NOT_RUNNING")]
    FailTaskNotRunning,

    /// Policy violation not covered by a more specific code. Context-dependent.
    /// error_detail carries a PlannerErrorTemplate string for this code only.
    #[serde(rename = "FAIL_POLICY_VIOLATION")]
    FailPolicyViolation,

    /// Session token invalid, revoked, sequence gap, or nonce replay. NOT retryable.
    #[serde(rename = "UNAUTHORIZED")]
    Unauthorized,

    /// IntegrationMerge base has advanced past session's pinned main tip. Retryable.
    #[serde(rename = "FAIL_STALE_BASE")]
    FailStaleBase,

    /// FetchRequest denied by domain allowlist or rate limit. Retryable with backoff.
    #[serde(rename = "FETCH_DENIED")]
    FetchDenied,

    /// Malformed IPC payload or unsupported combination. Maybe retryable.
    #[serde(rename = "INVALID_REQUEST")]
    InvalidRequest,

    /// Approval token presented on an intent is invalid, expired, or scope-mismatched.
    #[serde(rename = "FAIL_APPROVAL_TOKEN_INVALID")]
    FailApprovalTokenInvalid,
}

impl PlannerErrorCode {
    /// Returns true when the error is definitively non-retryable.
    /// peripherals.md §3.1 retry semantics table.
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::FailUnknownTask | Self::Unauthorized)
    }
}

impl fmt::Display for PlannerErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Use the serde string tag as the display form (matches spec tables).
        let s = match self {
            Self::FailPathPolicyViolation => "FAIL_PATH_POLICY_VIOLATION",
            Self::FailInvalidCommitTopology => "FAIL_INVALID_COMMIT_TOPOLOGY",
            Self::FailInvalidDiff => "FAIL_INVALID_DIFF",
            Self::FailMissingWitness => "FAIL_MISSING_WITNESS",
            Self::FailInsufficientWitness => "FAIL_INSUFFICIENT_WITNESS",
            Self::FailBudgetExceeded => "FAIL_BUDGET_EXCEEDED",
            Self::FailUnknownTask => "FAIL_UNKNOWN_TASK",
            Self::FailTaskNotRunning => "FAIL_TASK_NOT_RUNNING",
            Self::FailPolicyViolation => "FAIL_POLICY_VIOLATION",
            Self::Unauthorized => "UNAUTHORIZED",
            Self::FailStaleBase => "FAIL_STALE_BASE",
            Self::FetchDenied => "FETCH_DENIED",
            Self::InvalidRequest => "INVALID_REQUEST",
            Self::FailApprovalTokenInvalid => "FAIL_APPROVAL_TOKEN_INVALID",
        };
        f.write_str(s)
    }
}

// ---------------------------------------------------------------------------
// OperatorErrorCode
// peripherals.md §3 "Operator socket" operator-error table.
// ---------------------------------------------------------------------------

/// Machine-stable error identifier returned to the operator CLI on failure.
///
/// Every code has a corresponding `OperatorErrorDetail` variant (one-to-one
/// mapping enforced by the spec). The wire form is the bare code string inside
/// `OperatorResponse::Error { code, detail }`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum OperatorErrorCode {
    // --- task state operations ---
    #[serde(rename = "FAIL_TASK_NOT_RESUMABLE")]
    FailTaskNotResumable,

    #[serde(rename = "FAIL_TASK_NOT_RETRYABLE")]
    FailTaskNotRetryable,

    #[serde(rename = "FAIL_INITIATIVE_TERMINAL")]
    FailInitiativeTerminal,

    // --- policy advance ---
    #[serde(rename = "FAIL_POLICY_SIGNATURE_INVALID")]
    FailPolicySignatureInvalid,

    #[serde(rename = "FAIL_POLICY_EPOCH_REPLAY")]
    FailPolicyEpochReplay,

    #[serde(rename = "FAIL_POLICY_MALFORMED")]
    FailPolicyMalformed,

    #[serde(rename = "FAIL_PATH_OUTSIDE_DATA_DIR")]
    FailPathOutsideDataDir,

    #[serde(rename = "FAIL_STORE_WRITE")]
    FailStoreWrite,

    // --- operator auth ---
    #[serde(rename = "UNAUTHORIZED")]
    Unauthorized,

    // --- session management ---
    #[serde(rename = "FAIL_SESSION_NOT_FOUND")]
    FailSessionNotFound,

    #[serde(rename = "FAIL_SESSION_ALREADY_REVOKED")]
    FailSessionAlreadyRevoked,

    #[serde(rename = "FAIL_ROLE_NOT_OPERATOR_CREATABLE")]
    FailRoleNotOperatorCreatable,

    #[serde(rename = "FAIL_WORKTREE_OUTSIDE_ALLOWED_ROOTS")]
    FailWorktreeOutsideAllowedRoots,

    #[serde(rename = "FAIL_INVALID_LINEAGE_ID")]
    FailInvalidLineageId,

    #[serde(rename = "FAIL_BASE_REF_UNRESOLVED")]
    FailBaseRefUnresolved,

    #[serde(rename = "FAIL_INVALID_TASK_STATE")]
    FailInvalidTaskState,

    // --- delegation grant ---
    #[serde(rename = "FAIL_SESSION_INVALID")]
    FailSessionInvalid,

    #[serde(rename = "FAIL_CAPABILITY_ABOVE_CEILING")]
    FailCapabilityAboveCeiling,

    #[serde(rename = "FAIL_DELEGATION_SIGNATURE_INVALID")]
    FailDelegationSignatureInvalid,

    #[serde(rename = "FAIL_DELEGATION_TTL_OUT_OF_RANGE")]
    FailDelegationTtlOutOfRange,

    #[serde(rename = "FAIL_DELEGATION_ALREADY_ACTIVE")]
    FailDelegationAlreadyActive,

    #[serde(rename = "FAIL_UNKNOWN_CAPABILITY_CLASS")]
    FailUnknownCapabilityClass,

    // --- escalation ---
    #[serde(rename = "FAIL_ESCALATION_NOT_PENDING")]
    FailEscalationNotPending,
}

impl fmt::Display for OperatorErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::FailTaskNotResumable => "FAIL_TASK_NOT_RESUMABLE",
            Self::FailTaskNotRetryable => "FAIL_TASK_NOT_RETRYABLE",
            Self::FailInitiativeTerminal => "FAIL_INITIATIVE_TERMINAL",
            Self::FailPolicySignatureInvalid => "FAIL_POLICY_SIGNATURE_INVALID",
            Self::FailPolicyEpochReplay => "FAIL_POLICY_EPOCH_REPLAY",
            Self::FailPolicyMalformed => "FAIL_POLICY_MALFORMED",
            Self::FailPathOutsideDataDir => "FAIL_PATH_OUTSIDE_DATA_DIR",
            Self::FailStoreWrite => "FAIL_STORE_WRITE",
            Self::Unauthorized => "UNAUTHORIZED",
            Self::FailSessionNotFound => "FAIL_SESSION_NOT_FOUND",
            Self::FailSessionAlreadyRevoked => "FAIL_SESSION_ALREADY_REVOKED",
            Self::FailRoleNotOperatorCreatable => "FAIL_ROLE_NOT_OPERATOR_CREATABLE",
            Self::FailWorktreeOutsideAllowedRoots => "FAIL_WORKTREE_OUTSIDE_ALLOWED_ROOTS",
            Self::FailInvalidLineageId => "FAIL_INVALID_LINEAGE_ID",
            Self::FailBaseRefUnresolved => "FAIL_BASE_REF_UNRESOLVED",
            Self::FailInvalidTaskState => "FAIL_INVALID_TASK_STATE",
            Self::FailSessionInvalid => "FAIL_SESSION_INVALID",
            Self::FailCapabilityAboveCeiling => "FAIL_CAPABILITY_ABOVE_CEILING",
            Self::FailDelegationSignatureInvalid => "FAIL_DELEGATION_SIGNATURE_INVALID",
            Self::FailDelegationTtlOutOfRange => "FAIL_DELEGATION_TTL_OUT_OF_RANGE",
            Self::FailDelegationAlreadyActive => "FAIL_DELEGATION_ALREADY_ACTIVE",
            Self::FailUnknownCapabilityClass => "FAIL_UNKNOWN_CAPABILITY_CLASS",
            Self::FailEscalationNotPending => "FAIL_ESCALATION_NOT_PENDING",
        };
        f.write_str(s)
    }
}

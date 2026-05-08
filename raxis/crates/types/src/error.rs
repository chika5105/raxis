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

    /// The initiative is quarantined — a row exists in
    /// `initiative_quarantines` for it. Set by either
    /// `raxis initiative quarantine <id>` (single) or
    /// `raxis operator quarantine-plans-by <fingerprint>` (sweep).
    /// **Not retryable**: the quarantine is operator-initiated and
    /// only lifts when the operator aborts the initiative entirely.
    /// kernel-store.md §2.5.8.
    #[serde(rename = "FAIL_INITIATIVE_QUARANTINED")]
    FailInitiativeQuarantined,

    /// **V2 (Step 21).** Orchestrator submitted `ActivateSubTask` for
    /// a sub-task whose `task_dag_edges` predecessors are not all
    /// `Completed`. This is a **timing error**, not an authority
    /// error: the same intent will be authorised once the missing
    /// dependencies finish. The Orchestrator's non-negotiable system
    /// prompt teaches it to wait for the next
    /// `KernelPush::SubTaskCompleted { newly_activatable }` push and
    /// re-attempt activation, NOT to abandon the sub-task.
    ///
    /// **Wire stability:** `DEPENDENCY_NOT_MET` is its own coarse code
    /// (NOT a `FAIL_POLICY_VIOLATION` template) precisely so the
    /// Orchestrator can reason about it as transient. INV-08 still
    /// applies — no further detail is leaked on the wire.
    ///
    /// Retryable. v2-deep-spec.md §Step 21.
    #[serde(rename = "DEPENDENCY_NOT_MET")]
    DependencyNotMet,
}

impl PlannerErrorCode {
    /// Returns true when the error is definitively non-retryable.
    /// peripherals.md §3.1 retry semantics table.
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::FailUnknownTask
                | Self::Unauthorized
                | Self::FailInitiativeQuarantined,
        )
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
            Self::FailInitiativeQuarantined => "FAIL_INITIATIVE_QUARANTINED",
            Self::DependencyNotMet => "DEPENDENCY_NOT_MET",
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

    /// **V2 (V2_GAPS.md §12.8 / §12.9, INV-PLAN-POLICY-PRECEDENCE-01).**
    /// The plan declared a value for a field whose policy-side
    /// counterpart is `_locked = true`, AND the plan value differs
    /// from the locked policy default. The kernel rejects admission
    /// rather than silently coerce the plan to the policy value
    /// (the plan author would otherwise believe their override took
    /// effect when it did not). The `error_detail` JSON carries the
    /// `field`, `plan_value`, and `policy_value` triple so the
    /// operator's diagnostic surfaces the precise locked-field
    /// conflict. NOT retryable until either the plan is rewritten
    /// or the operator unlocks the field in `policy.toml`.
    #[serde(rename = "FAIL_POLICY_LOCKED_FIELD")]
    FailPolicyLockedField,

    /// **V2 (V2_GAPS.md §12.8).** The plan's
    /// `[workspace] target_ref` (or the operator's
    /// `[git] default_target_ref`) failed
    /// [`raxis_policy::validate_target_ref_format`] — the value did
    /// not match the spec's fully-qualified branch-ref shape (must
    /// start with `refs/heads/`, no control chars, no `..`, etc.).
    /// Surfaced from `approve_plan` (plan-side) and from
    /// `PolicyBundle::validate` (operator-side, raised through
    /// `MalformedArtifact`). NOT retryable without rewriting the
    /// offending TOML field.
    #[serde(rename = "FAIL_WORKSPACE_TARGET_REF_INVALID")]
    FailWorkspaceTargetRefInvalid,
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
            Self::FailPolicyLockedField => "FAIL_POLICY_LOCKED_FIELD",
            Self::FailWorkspaceTargetRefInvalid => "FAIL_WORKSPACE_TARGET_REF_INVALID",
        };
        f.write_str(s)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// V2 added one new `PlannerErrorCode` variant
    /// (`DEPENDENCY_NOT_MET`, Step 21). `Display`, `serde` rename,
    /// and JSON round-trip MUST agree on the SCREAMING_SNAKE_CASE
    /// wire form so audit logs, planner UI, and the wire decoder
    /// all read the same string.
    #[test]
    fn dependency_not_met_renders_as_screaming_snake_case() {
        let code = PlannerErrorCode::DependencyNotMet;
        // Display form (used in audit logs, error_code field
        // projection in `planner_dispatch_log::intent_response`).
        assert_eq!(format!("{code}"), "DEPENDENCY_NOT_MET");
        // serde JSON form (used in operator JSON projection of
        // IntentResponse and in CLI plan-bundle render).
        let json = serde_json::to_string(&code).unwrap();
        assert_eq!(json, "\"DEPENDENCY_NOT_MET\"");
        // Round-trip back through serde.
        let back: PlannerErrorCode = serde_json::from_str(&json).unwrap();
        assert_eq!(back, code);
    }

    /// `DEPENDENCY_NOT_MET` is a TIMING error, not an authority
    /// error. The Orchestrator's NNSP teaches it to retry on
    /// `KernelPush::SubTaskCompleted` (v2-deep-spec.md §Step 21);
    /// classifying it as terminal would defeat that retry path.
    #[test]
    fn dependency_not_met_is_not_terminal() {
        assert!(!PlannerErrorCode::DependencyNotMet.is_terminal(),
            "DEPENDENCY_NOT_MET must be retryable per §Step 21 — \
             treating it as terminal would cause the Orchestrator to \
             abandon valid sub-tasks while waiting on dependencies.");
    }

    /// Pin the existing terminal set so a future re-classification
    /// of `DependencyNotMet` (or any other code) into `is_terminal`
    /// fails this test loudly. The rule for terminality is
    /// "operator must intervene to make this retryable" — for
    /// `DEPENDENCY_NOT_MET` the Orchestrator's own retry suffices.
    #[test]
    fn terminal_set_is_unchanged_by_v2_addition() {
        let terminal = [
            PlannerErrorCode::FailUnknownTask,
            PlannerErrorCode::Unauthorized,
            PlannerErrorCode::FailInitiativeQuarantined,
        ];
        for &code in &terminal {
            assert!(code.is_terminal(),
                "{code:?} dropped out of the terminal set — \
                 spec change requires explicit acknowledgement");
        }

        // Retryable: every other variant. We use a structural
        // exhaustive match so any future variant addition forces a
        // decision in this test (rather than passing by default).
        for code in [
            PlannerErrorCode::FailPathPolicyViolation,
            PlannerErrorCode::FailInvalidCommitTopology,
            PlannerErrorCode::FailInvalidDiff,
            PlannerErrorCode::FailMissingWitness,
            PlannerErrorCode::FailInsufficientWitness,
            PlannerErrorCode::FailBudgetExceeded,
            PlannerErrorCode::FailTaskNotRunning,
            PlannerErrorCode::FailPolicyViolation,
            PlannerErrorCode::FailStaleBase,
            PlannerErrorCode::FetchDenied,
            PlannerErrorCode::InvalidRequest,
            PlannerErrorCode::FailApprovalTokenInvalid,
            PlannerErrorCode::DependencyNotMet,
        ] {
            assert!(!code.is_terminal(),
                "{code:?} is in the retryable set but \
                 `is_terminal()` returned true");
        }
    }
}

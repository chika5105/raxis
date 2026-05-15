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
///
/// **INV-09** (opaque rejection codes) is **structurally enforced** by
/// the variant set defined here: each variant is a coarse, named
/// failure class — no variant carries a free-form payload that
/// could leak which sub-check fired (e.g.,
/// `FailPolicyViolation` does not name the specific allowlist
/// rule that rejected it). Adding new variants requires a spec
/// update; this is the only widening surface. V2_GAPS.md §13
/// Category 1 — annotation-only enforcement site.
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

    /// **V2_GAPS §D2 — host-capacity admission cap.** The kernel
    /// refuses to spawn another microVM because
    /// `running_vm_count >= [host_capacity] max_concurrent_vms`
    /// (`host-capacity.md §4.2`). Retryable: the agent should
    /// resubmit `ActivateSubTask` after observing capacity
    /// availability. V3 will deliver `KernelPush::CapacityFreed`
    /// proactively; V2 expects the planner to poll.
    #[serde(rename = "FAIL_VM_CONCURRENCY_AT_CAP")]
    FailVmConcurrencyAtCap,

    /// **V2_GAPS §D2 — disk pressure halt.** A write-class intent
    /// arrived while the disk-full watchdog was in `Halted` state
    /// (free space below `[host_capacity] min_free_disk_mb`).
    /// `disk_full_behavior = "halt_admit"` (V2 default) refuses
    /// the intent at admission. Retryable: the operator must
    /// expand disk or wait for natural drain; the watchdog
    /// re-polls every 5 seconds and re-admits when free space
    /// recovers (`host-capacity.md §7.1`, INV-CAPACITY-02).
    #[serde(rename = "FAIL_DISK_FULL")]
    FailDiskFull,

    /// **V2 `v2_extended_gaps.md §3.2`** — the planner submitted a
    /// `StructuredOutput` intent whose payload failed kernel-side
    /// validation: `structured_output = None` on a
    /// `IntentKind::StructuredOutput`, an unparseable `commit_sha`
    /// on a `TaskSummary`, or a missing `task_id` scope. Retryable
    /// only by emitting a syntactically-correct payload — the
    /// kernel does NOT reveal which sub-check fired (INV-09 /
    /// R-10 opaque rejection).
    #[serde(rename = "FAIL_STRUCTURED_OUTPUT_INVALID")]
    FailStructuredOutputInvalid,

    /// **V2 `v2_extended_gaps.md §3.2`** — the planner exceeded
    /// `STRUCTURED_OUTPUT_PER_SESSION_RATE_LIMIT` accepted
    /// structured outputs in this session. Retryable on the next
    /// session activation; not retryable within the current
    /// session. The rate cap is per-session so an abusive agent
    /// can be sandboxed without quarantining its lineage.
    #[serde(rename = "FAIL_STRUCTURED_OUTPUT_RATE_LIMITED")]
    FailStructuredOutputRateLimited,

    /// **V2 `integration-merge.md §11.5`** — a previous
    /// `IntegrationMerge` for this initiative left
    /// `initiatives.git_apply_pending = 1` (Phase 2 host-side
    /// fast-forward incomplete or Phase 3 ack missed across a
    /// kernel restart). Check 8 Phase 1 pre-flight refuses to
    /// admit a new merge until startup recovery (§11.3 Cases A
    /// or B) clears the flag. **Retryable** with backoff: the
    /// flag clears either inline (when the previous merge's
    /// host-side fast-forward retries succeed) or on the next
    /// kernel restart. INV-MERGE-CONSISTENCY (§11.8).
    #[serde(rename = "FAIL_GIT_APPLY_PENDING")]
    FailGitApplyPending,

    /// **V2 §Step 24 / §Step 24b** — host-side worktree provisioning
    /// for an Executor or Reviewer activation failed (the `gix`
    /// clone could not open the source repository, the destination
    /// path could not be initialised, the requested SHA is missing
    /// from the orchestrator ODB, or the post-clone checkout
    /// failed). Surfaced from `handle_activate_subtask` when the
    /// `worktree_provisioning::provision_executor_worktree` /
    /// `provision_reviewer_worktree` composition errors out before
    /// the substrate spawn.
    ///
    /// Terminal — re-attempting the activation without operator
    /// intervention will hit the same gix failure on every retry.
    /// The audit chain carries a structured `ActivateSubTask*`
    /// diagnostic with the underlying cause.
    #[serde(rename = "FAIL_WORKTREE_PROVISION")]
    FailWorktreeProvision,

    /// **V2 `agent-disagreement.md §3.6`** — the orchestrator
    /// submitted `IntegrationMerge` while at least one Executor
    /// task in the initiative still carries a cross-Reviewer
    /// terminal verdict of `AtLeastOneRejected`. The orchestrator
    /// NNSP rule 3a directs `retry_subtask` for that executor
    /// BEFORE `integration_merge` is allowed; the kernel-side
    /// fail-closed gate here REFUSES to silently ship defective
    /// code despite the reviewer's objection (paradigm-`R-6`
    /// Fail-Closed Default). Retryable: the orchestrator must
    /// either retry the rejected executor (`retry_subtask`) or
    /// escalate per `agent-disagreement.md §3` before re-issuing
    /// `integration_merge`.
    #[serde(rename = "FAIL_REVIEW_OUTSTANDING")]
    FailReviewOutstanding,
}

impl PlannerErrorCode {
    /// Returns true when the error is definitively non-retryable.
    /// peripherals.md §3.1 retry semantics table.
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::FailUnknownTask
                | Self::Unauthorized
                | Self::FailInitiativeQuarantined
                | Self::FailWorktreeProvision,
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
            Self::FailVmConcurrencyAtCap => "FAIL_VM_CONCURRENCY_AT_CAP",
            Self::FailDiskFull => "FAIL_DISK_FULL",
            Self::FailStructuredOutputInvalid => "FAIL_STRUCTURED_OUTPUT_INVALID",
            Self::FailStructuredOutputRateLimited => "FAIL_STRUCTURED_OUTPUT_RATE_LIMITED",
            Self::FailGitApplyPending => "FAIL_GIT_APPLY_PENDING",
            Self::FailWorktreeProvision => "FAIL_WORKTREE_PROVISION",
            Self::FailReviewOutstanding => "FAIL_REVIEW_OUTSTANDING",
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

    /// **V2_GAPS §12.4 — Operator-ergonomics IPC stub.** The
    /// operator submitted one of the five `OperatorRequest`
    /// variants whose handler is V3 work
    /// (`ProposeDefaults`, `EstimateCost`, `DryRunAdmit`,
    /// `SubscribeInitiative`, `DescribeInitiativePause`). The
    /// kernel accepts the wire shape so the IPC contract is
    /// stable across V2 → V3, but fails closed at admission
    /// time with this code. The matching
    /// `OperatorErrorDetail::NotYetImplemented` carries the
    /// `feature` label and the `since_version` slot indicating
    /// which release will land the handler.
    #[serde(rename = "FAIL_NOT_YET_IMPLEMENTED")]
    FailNotYetImplemented,
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
            Self::FailNotYetImplemented => "FAIL_NOT_YET_IMPLEMENTED",
        };
        f.write_str(s)
    }
}

// ---------------------------------------------------------------------------
// FailureReason newtype — `INV-FAILURE-REASON-MANDATORY-01`
// ---------------------------------------------------------------------------

/// A non-empty, human-readable failure reason.
///
/// Pinned by `INV-FAILURE-REASON-MANDATORY-01` (`specs/invariants.md`):
/// every transition into a terminal-failure or operator-blocked
/// state (`TaskState::Failed`, `TaskState::Aborted`,
/// `TaskState::Cancelled`, `TaskState::BlockedRecoveryPending`,
/// `InitiativeState::Failed`, `InitiativeState::Aborted`,
/// `InitiativeState::Blocked`, `SessionRevoked`) MUST carry a
/// non-empty, human-readable reason string.
///
/// **Invariant.** `FailureReason::new(s)` rejects empty input,
/// whitespace-only input, and inputs longer than
/// [`MAX_FAILURE_REASON_LEN`] bytes. The single constructor
/// guarantees the contained string satisfies the invariant — no
/// other code path can construct a `FailureReason` that
/// violates it. Type-level enforcement of the invariant: an
/// emit site that takes `FailureReason` instead of
/// `Option<String>` cannot compile if the caller doesn't supply
/// a real reason.
///
/// **Why a newtype, not `String`.** A bare `String` permits
/// `String::new()` / `"".to_string()` / `"   ".to_string()` —
/// all three surface in the dashboard as the `"No reason
/// supplied — kernel bug"` empty-state, which IS the operator-
/// visible kernel bug this invariant catches. The newtype makes
/// those constructions a compile error at the boundary.
///
/// **Why a newtype, not `Option<String>`.** A `None` carries
/// the same semantic gap as `Some("")` — the dashboard renders
/// both as the kernel-bug empty-state. Forcing the caller to
/// produce a `FailureReason` removes the option entirely.
///
/// **Round-trips serde transparently** so the wire shape on the
/// audit chain stays a bare string — no breaking change to the
/// JSONL projection.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct FailureReason(String);

/// Maximum byte length accepted by [`FailureReason::new`].
///
/// Generous on purpose — failure reasons frequently embed a
/// stack-tail or planner-boot-error console excerpt to give the
/// operator end-to-end forensic context. 4 KiB is comfortably
/// below SQLite's 1 GiB row-blob cap and well below any audit
/// JSONL line-length concern. Inputs longer than this are
/// rejected at construction so a runaway reason payload cannot
/// poison the audit chain.
pub const MAX_FAILURE_REASON_LEN: usize = 4096;

/// Constructor failure for [`FailureReason::new`]. Returned when
/// the input is empty, whitespace-only, or exceeds
/// [`MAX_FAILURE_REASON_LEN`] bytes.
///
/// **Why a dedicated error type.** A `Result<FailureReason,
/// EmptyReasonError>` makes the constructor's contract explicit
/// at the call site — the caller MUST handle the impossible-but-
/// guarded case (and panic, or escalate, or supply a fallback
/// message). A unit return like `Option<FailureReason>` would
/// hide the failure mode behind silent `None` propagation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EmptyReasonError;

impl fmt::Display for EmptyReasonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(
            "FailureReason must be non-empty and not whitespace-only \
             (max 4096 bytes) per INV-FAILURE-REASON-MANDATORY-01 — \
             every Failed / Aborted / Cancelled / BlockedRecoveryPending \
             transition MUST carry an operator-actionable reason. If you \
             cannot determine a reason at the emit site, that's a code \
             defect — fix the call to supply one rather than passing \
             the empty string.",
        )
    }
}

impl std::error::Error for EmptyReasonError {}

impl FailureReason {
    /// Construct a `FailureReason` from any string-like input.
    /// Returns `Err(EmptyReasonError)` when the trimmed input is
    /// empty or when the byte length exceeds
    /// [`MAX_FAILURE_REASON_LEN`].
    ///
    /// **Does NOT trim.** Leading/trailing whitespace is
    /// preserved verbatim because it can carry meaningful
    /// formatting (a multi-line stack tail with leading
    /// indentation, a multi-line planner-boot-error console
    /// excerpt). Only the *whitespace-only* gate uses `trim` to
    /// reject `"   "` / `"\n"`.
    pub fn new(reason: impl Into<String>) -> Result<Self, EmptyReasonError> {
        let s = reason.into();
        if s.trim().is_empty() {
            return Err(EmptyReasonError);
        }
        if s.len() > MAX_FAILURE_REASON_LEN {
            return Err(EmptyReasonError);
        }
        Ok(Self(s))
    }

    /// Borrow the inner string (the verbatim reason text).
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consume the newtype and return the inner `String`. For
    /// callers that need to write the value into SQLite via
    /// `rusqlite::params!` or feed it through an `Option<String>`-
    /// shaped legacy API — at the call site they convert through
    /// `into_string()` so the type-system entry-point stays
    /// `FailureReason::new()`.
    pub fn into_string(self) -> String {
        self.0
    }

    /// Adapt an `Option<&str>` legacy API: `Some(non-empty)` →
    /// `Some(FailureReason)`, `Some("") | Some("   ") | None` →
    /// `None`. Used at boundaries that haven't migrated to the
    /// newtype yet — the receiving side still gets the invariant
    /// for whatever passes through, and the constructor failure case
    /// should use [`FailureReason::new`] directly.
    pub fn from_optional<S: AsRef<str>>(reason: Option<S>) -> Option<Self> {
        let s = reason?;
        Self::new(s.as_ref().to_owned()).ok()
    }
}

impl fmt::Display for FailureReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for FailureReason {
    fn as_ref(&self) -> &str {
        &self.0
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
        assert!(
            !PlannerErrorCode::DependencyNotMet.is_terminal(),
            "DEPENDENCY_NOT_MET must be retryable per §Step 21 — \
             treating it as terminal would cause the Orchestrator to \
             abandon valid sub-tasks while waiting on dependencies."
        );
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
            assert!(
                code.is_terminal(),
                "{code:?} dropped out of the terminal set — \
                 spec change requires explicit acknowledgement"
            );
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
            PlannerErrorCode::FailVmConcurrencyAtCap,
            PlannerErrorCode::FailDiskFull,
            PlannerErrorCode::FailStructuredOutputInvalid,
            PlannerErrorCode::FailStructuredOutputRateLimited,
        ] {
            assert!(
                !code.is_terminal(),
                "{code:?} is in the retryable set but \
                 `is_terminal()` returned true"
            );
        }
    }
}

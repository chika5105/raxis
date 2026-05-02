// raxis-types::intent — IntentRequest, IntentResponse, IntentKind, BudgetSnapshot.
//
// Normative reference: peripherals.md §3.1 "IntentRequest wire shape" and
// "IntentResponse wire shape". The JSON shown in the spec is a human-readable
// projection; the canonical types are defined here.
//
// Wire encoding: bincode 2.0.1 with `config::standard()` wrapped in a 4-byte
// LE length prefix by `raxis-ipc::frame`. The serde names here are used only
// for JSON projections (operator UIs, test harnesses); they are NOT transmitted
// on the wire (bincode standard() encodes positionally).

use crate::{CommitSha, SessionId, TaskId, TaskState};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// IntentKind
// peripherals.md §3.1 "intent_kind valid values (v1)"
// ---------------------------------------------------------------------------

/// The kind of action the planner is asserting with an IntentRequest.
///
/// v1 values — the kernel rejects any other string with FAIL_POLICY_VIOLATION.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum IntentKind {
    /// Exactly one committed change on top of `base_sha`.
    /// Kernel enforces `parent(head_sha) == base_sha` for non-empty ranges.
    /// Empty diff (`base_sha == head_sha`) is permitted (vacuous path check).
    SingleCommit,

    /// A merge commit integrating agent branches.
    /// Subject to the 5-predicate topology check (kernel-store.md §2.5.8).
    IntegrationMerge,

    /// Assert the task is complete. Triggers path closure + gate closure check.
    CompleteTask,

    /// Planner self-reports inability to complete the task.
    /// Transitions Running → Failed. Requires `justification`.
    ReportFailure,
}

impl IntentKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SingleCommit => "SingleCommit",
            Self::IntegrationMerge => "IntegrationMerge",
            Self::CompleteTask => "CompleteTask",
            Self::ReportFailure => "ReportFailure",
        }
    }

    /// Whether this intent kind requires `base_sha` and `head_sha`.
    /// peripherals.md §3.1: "required for all kinds except ReportFailure".
    pub fn requires_sha_range(self) -> bool {
        !matches!(self, Self::ReportFailure)
    }

    /// Whether this intent kind requires a non-empty `justification` field.
    pub fn requires_justification(self) -> bool {
        matches!(self, Self::ReportFailure)
    }
}

// ---------------------------------------------------------------------------
// SubmittedClaim — one entry in IntentRequest.submitted_claims.
// peripherals.md §3.1 wire field `submitted_claims`.
// ---------------------------------------------------------------------------

/// A claim the planner asserts alongside an intent.
/// The kernel evaluates claims against the witness records for the task.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubmittedClaim {
    /// Must match a ClaimType recognised by the policy for the touched paths.
    pub claim_type: String,
    /// Hash of the witness blob this claim references (optional in v1 —
    /// if absent the kernel derives it from the task's witness_records).
    pub evidence_ref: Option<String>,
}

// ---------------------------------------------------------------------------
// ApprovalToken — presented on IntentRequest after an escalation is approved.
// planner-api.md §"After the operator approves".
// ---------------------------------------------------------------------------

/// An operator-issued approval token presented by the planner on its next
/// intent after an escalation is approved. The kernel validates all three
/// fields together.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalToken {
    /// UUID of the approval record in `approval_tokens`.
    pub approval_id: Uuid,
    /// Must match the `escalation_id` from the EscalationResponse::Submitted.
    pub escalation_id: crate::EscalationId,
    /// Ed25519 signature from the operator (64 bytes, hex-encoded on the wire).
    pub operator_sig: String,
}

// ---------------------------------------------------------------------------
// IntentRequest
// peripherals.md §3.1 "IntentRequest wire shape"
// ---------------------------------------------------------------------------

/// The planner's intent submission message. Sent on the planner UDS socket.
///
/// Wire shape: bincode 2.0.1 standard() inside a 4-byte LE length prefix
/// frame produced by `raxis-ipc::frame`. The JSON in the spec is illustrative.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntentRequest {
    /// Kernel-issued session credential. Validated by ipc/auth.rs on every frame.
    pub session_token: String,

    /// Must be exactly `prev_accepted_sequence + 1`.
    /// Gaps or reuse → UNAUTHORIZED.
    /// peripherals.md §3.1: "sequence_number — must be exactly prev_accepted_sequence + 1"
    pub sequence_number: u64,

    /// 16 random bytes as lowercase hex (32 chars). Globally unique per
    /// (session_id, nonce) within the nonce cache TTL. Reuse → UNAUTHORIZED.
    pub envelope_nonce: String,

    /// The kind of action being asserted.
    pub intent_kind: IntentKind,

    /// The task_id from the signed plan this intent targets.
    pub task_id: TaskId,

    /// Base commit OID. Required for all intent kinds except ReportFailure.
    /// For SingleCommit non-empty: must be the immediate parent of head_sha.
    pub base_sha: Option<CommitSha>,

    /// Tip commit OID. Required for all intent kinds except ReportFailure.
    pub head_sha: Option<CommitSha>,

    /// Claims the planner submits. May be empty if the gate set has no active
    /// requirements; extra claims when none are required are silently ignored.
    #[serde(default)]
    pub submitted_claims: Vec<SubmittedClaim>,

    /// Required non-empty for ReportFailure. Ignored for all other kinds.
    /// Max 2048 chars. planner-api.md §"Reporting failure".
    pub justification: Option<String>,

    /// If provided, the kernel returns the same IntentResponse on duplicate
    /// submission with the same key within the session. Does not replace
    /// sequence_number / nonce rules.
    pub idempotency_key: Option<Uuid>,

    /// Optional: approval token from an approved escalation.
    /// planner-api.md §"After the operator approves".
    pub approval_token: Option<ApprovalToken>,
}

// ---------------------------------------------------------------------------
// BudgetSnapshot
// peripherals.md §3.1 "remaining_budget" field.
// ---------------------------------------------------------------------------

/// The lane budget snapshot returned on every Accepted IntentResponse.
/// Treat as opaque — it is NOT a token count, USD amount, or wall-clock estimate.
/// planner-api.md §"Budget awareness".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BudgetSnapshot {
    /// Admission units remaining on this task's lane after charging for this intent.
    pub admission_units: u64,
}

// ---------------------------------------------------------------------------
// PlannerErrorTemplate — fixed generic-template set for error_detail.
// peripherals.md §3.1 INV-08 rule for FAIL_POLICY_VIOLATION.
// raxis-types/src/error.rs (cross-reference).
// ---------------------------------------------------------------------------

/// Fixed, version-controlled template strings returned in `error_detail` for
/// FAIL_POLICY_VIOLATION only. No runtime interpolation; no file paths; no
/// policy rule names. INV-08 (peripherals.md §3.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PlannerErrorTemplate {
    /// The intent kind is not permitted under the current policy epoch.
    IntentKindNotPermitted,
    /// A submitted claim is malformed (wrong type, invalid evidence ref format).
    MalformedClaim,
    /// The task has a constraint in the signed plan that this intent violates.
    PlanConstraintViolation,
    /// The session's lineage is quarantined; no further intents accepted.
    LineageQuarantined,
}

// ---------------------------------------------------------------------------
// IntentResponse
// peripherals.md §3.1 "IntentResponse wire shape"
// ---------------------------------------------------------------------------

/// The kernel's response to an IntentRequest. Two variants: Accepted / Rejected.
/// The `outcome` field is the discriminant; field exclusivity rules are enforced
/// by the type system via the nested enum.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntentResponse {
    /// Matches the `sequence_number` of the IntentRequest this responds to.
    pub sequence_number: u64,

    /// The current task state at response time.
    /// Post-transition on Accepted; last-committed-state on Rejected.
    pub task_state: TaskState,

    /// The outcome variant with its exclusive payload.
    pub outcome: IntentOutcome,
}

/// The exclusive payload variants for IntentResponse.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "PascalCase")]
pub enum IntentOutcome {
    Accepted {
        /// Lane budget snapshot after budget consumption for this intent.
        remaining_budget: BudgetSnapshot,
        /// true iff evaluate_claims took the SufficientStale grace use.
        /// The planner must renew the delegation before the next gated action.
        warn_delegation_stale: bool,
    },
    Rejected {
        /// Coarse rejection reason. Full enum in error.rs.
        error_code: crate::PlannerErrorCode,
        /// Non-null only for FAIL_POLICY_VIOLATION. Fixed template set; INV-08.
        error_detail: Option<PlannerErrorTemplate>,
    },
}

impl IntentResponse {
    /// Convenience: was this intent accepted?
    pub fn is_accepted(&self) -> bool {
        matches!(self.outcome, IntentOutcome::Accepted { .. })
    }
}

// ---------------------------------------------------------------------------
// SessionId re-export for use in this module's session_token field
// ---------------------------------------------------------------------------
// Note: session_token on the wire is a hex string, not a SessionId (UUIDs are
// separate from the token bytes). The SessionId is the UUID that identifies the
// row; the token is 32 CSPRNG bytes as 64-char hex. Both are strings on the
// wire; we keep them as String here to match the wire shape exactly.
// See kernel-store.md §2.5.1 Table 4 for the column distinction.

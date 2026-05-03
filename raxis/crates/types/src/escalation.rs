// raxis-types::escalation — EscalationRequest, EscalationResponse, and related types.
//
// Normative reference:
//   - planner-api.md §"Escalating for higher authority" (planner-facing summary)
//   - peripherals.md §3.1 "EscalationRequest wire shape" (normative)
//   - philosophy.md §1.6 EscalationClass / RequestedEscalationScope types
//   - kernel-store.md §2.5.1 Table 9 `escalations` DDL
//
// The EscalationRequest is submitted on the planner UDS socket (same socket as
// IntentRequest, different IpcMessage variant). EscalationResponse is the reply.

use crate::{GateType, TaskId};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// EscalationClass
// kernel-store.md §2.5.1 Table 9 CHECK (class IN (...))
// planner-api.md §"The four classes"
// ---------------------------------------------------------------------------

/// The category of exception the planner is requesting.
/// Exactly one class per EscalationRequest; `class` must match the
/// discriminant of `requested_scope`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum EscalationClass {
    /// A gate failed because the session lacks a CapabilityClass.
    CapabilityUpgrade,
    /// A delegation is Expired or in RenewalRequired state.
    DelegationRenewal,
    /// Budget was exhausted but the task is genuinely incomplete.
    BudgetException,
    /// A quality gate cannot be satisfied for a justifiable reason;
    /// an ad-hoc bypass is needed. Distinct from pre-authorised override_rules.
    QualityGateException,
}

impl EscalationClass {
    pub fn as_sql_str(self) -> &'static str {
        match self {
            Self::CapabilityUpgrade => "CapabilityUpgrade",
            Self::DelegationRenewal => "DelegationRenewal",
            Self::BudgetException => "BudgetException",
            Self::QualityGateException => "QualityGateException",
        }
    }

    pub fn from_sql_str(s: &str) -> Option<Self> {
        match s {
            "CapabilityUpgrade" => Some(Self::CapabilityUpgrade),
            "DelegationRenewal" => Some(Self::DelegationRenewal),
            "BudgetException" => Some(Self::BudgetException),
            "QualityGateException" => Some(Self::QualityGateException),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// RequestedEscalationScope
// The `requested_scope` field; discriminant must match `class`.
// planner-api.md §"The four classes" scope shapes.
// ---------------------------------------------------------------------------

/// The scope detail for an escalation request. Tag must match EscalationClass.
///
/// **Wire format note (INV-IPC-BINCODE):** see the long comment on
/// `IntentOutcome` in `intent.rs`. The previous `#[serde(tag = "kind")]`
/// internal-tag representation breaks `bincode::config::standard()`
/// (returns `AnyNotSupported`); the default external tagging works for
/// bincode and is what the wire actually carries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RequestedEscalationScope {
    CapabilityUpgrade {
        capability: crate::CapabilityClass,
    },
    DelegationRenewal {
        delegation_id: crate::DelegationId,
    },
    BudgetException {
        additional_units: u64,
    },
    QualityGateException {
        gate_type: GateType,
        /// Must equal the outer task_id in EscalationRequest.
        task_id: TaskId,
    },
}

impl RequestedEscalationScope {
    /// The class discriminant for this scope variant.
    pub fn class(&self) -> EscalationClass {
        match self {
            Self::CapabilityUpgrade { .. } => EscalationClass::CapabilityUpgrade,
            Self::DelegationRenewal { .. } => EscalationClass::DelegationRenewal,
            Self::BudgetException { .. } => EscalationClass::BudgetException,
            Self::QualityGateException { .. } => EscalationClass::QualityGateException,
        }
    }
}

// ---------------------------------------------------------------------------
// EscalationRequest
// peripherals.md §3.1 "EscalationRequest wire shape"
// planner-api.md §"Escalating for higher authority" (planner-facing summary)
// ---------------------------------------------------------------------------

/// Submitted by the planner on the planner UDS socket when it needs a scoped
/// exception from the operator. The kernel records the escalation as Pending
/// and returns an EscalationResponse.
///
/// Wire: bincode 2.0.1 standard() + 4-byte LE length prefix.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscalationRequest {
    /// Kernel-issued session credential for the planner submitting the
    /// escalation. Same `session_token` shape as `IntentRequest` — the
    /// kernel resolves it via `authority::session::get_session_by_token`
    /// to recover the originating session_id, lineage_id, and (via
    /// task_id) initiative_id, all of which are needed to populate the
    /// `escalations` row.
    ///
    /// Phase B.5 added this field. Earlier wire versions omitted it
    /// because the spec assumed an out-of-band session-context binding;
    /// in practice the planner socket has no per-connection auth state,
    /// so the credential MUST be on every frame.
    pub session_token: String,

    /// The task the escalation is for.
    pub task_id: TaskId,

    /// Coarse category. Must match `requested_scope.class()`.
    pub class: EscalationClass,

    /// Detailed scope. Discriminant must match `class`.
    pub requested_scope: RequestedEscalationScope,

    /// Required, non-empty, max 4096 chars. Explains why the exception is needed.
    pub justification: String,

    /// Fresh UUID v4 per submission; reuse on retry (idempotency).
    /// Every new submission with a different key counts toward the rate-limit window.
    pub idempotency_key: Uuid,
}

// ---------------------------------------------------------------------------
// EscalationResponse
// planner-api.md §"The response. The three variants."
// ---------------------------------------------------------------------------

/// The kernel's reply to an EscalationRequest. Three variants.
///
/// **Wire format note (INV-IPC-BINCODE):** see the long comment on
/// `IntentOutcome` in `intent.rs`. The previous
/// `#[serde(tag = "outcome")]` internal-tag representation breaks
/// `bincode::config::standard()` (returns `AnyNotSupported`); the
/// default external tagging works for bincode and is what the wire
/// actually carries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EscalationResponse {
    /// The escalation was recorded as Pending.
    /// The planner must persist `escalation_id` to present it later.
    Submitted {
        escalation_id: crate::EscalationId,
        /// Absolute Unix seconds at which the escalation auto-transitions to TimedOut.
        timeout_at: crate::id::UnixSeconds,
    },

    /// An escalation with the same (task_id, class, idempotency_key) already exists.
    /// Treat as Submitted with the same escalation_id.
    AlreadyPending {
        escalation_id: crate::EscalationId,
    },

    /// The kernel refused to record the escalation.
    Rejected {
        reason: EscalationRejectionReason,
    },
}

/// Why the kernel refused to record the escalation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum EscalationRejectionReason {
    /// planner-api.md: "exceeded policy.escalation_max_per_window"
    RateLimitExceeded,
    /// planner-api.md: "lineage is quarantined"
    LineageQuarantined,
}

// ---------------------------------------------------------------------------
// EscalationStatus — DDL at-rest values for escalations.status
// kernel-store.md §2.5.1 Table 9
// CHECK (status IN ('Pending','Approved','Denied','TimedOut','Consumed'))
// ---------------------------------------------------------------------------

/// The lifecycle state of an escalation record. Variants are the exact
/// strings allowed by the `escalations.status` CHECK constraint
/// (kernel-store.md §2.5.1 Table 9). Keep these two in lock-step —
/// `from_sql_str` returning `None` for a value the schema permits is a
/// spec drift bug.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum EscalationStatus {
    Pending,
    Approved,
    Denied,
    TimedOut,
    /// The approval token expired before the planner consumed it.
    /// Distinct from `TimedOut` (which fires before approval) so the
    /// audit trail can tell the two failure modes apart.
    TokenExpired,
    /// The approval token was consumed (planner presented it on an intent).
    Consumed,
}

impl EscalationStatus {
    /// All variants in v1 — the canonical set referenced by the
    /// `escalations.status` SQL CHECK constraint
    /// (kernel-store.md §2.5.1 Table 9). Order matches the v1 DDL
    /// CHECK list so the rendered Migration 1 SQL is byte-stable
    /// across builds (the
    /// `migration::tests::migration_1_ddl_fingerprint_is_pinned`
    /// hash guard relies on this ordering).
    ///
    /// **Spec drift contract.** Adding a new variant requires both a
    /// length bump here AND a new migration that ALTERs the CHECK
    /// constraint on already-installed databases.
    pub const ALL: [Self; 6] = [
        Self::Pending,
        Self::Approved,
        Self::Denied,
        Self::TimedOut,
        Self::TokenExpired,
        Self::Consumed,
    ];

    pub fn as_sql_str(self) -> &'static str {
        match self {
            Self::Pending => "Pending",
            Self::Approved => "Approved",
            Self::Denied => "Denied",
            Self::TimedOut => "TimedOut",
            Self::TokenExpired => "TokenExpired",
            Self::Consumed => "Consumed",
        }
    }

    pub fn from_sql_str(s: &str) -> Option<Self> {
        match s {
            "Pending" => Some(Self::Pending),
            "Approved" => Some(Self::Approved),
            "Denied" => Some(Self::Denied),
            "TimedOut" => Some(Self::TimedOut),
            "TokenExpired" => Some(Self::TokenExpired),
            "Consumed" => Some(Self::Consumed),
            _ => None,
        }
    }
}

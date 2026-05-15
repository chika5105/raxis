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
    /// **V2 (Step 30).** Orchestrator-only. The Orchestrator has
    /// encountered a non-trivial git merge conflict during an
    /// integration wave that it cannot resolve via its in-VM
    /// `bash` / `edit_file` / `git` tools (criteria T1–T4 in the
    /// kernel-pinned NNSP). The Orchestrator submits this class
    /// after running `git merge --abort`, then waits for
    /// `KernelPush::EscalationResolved` before re-attempting the
    /// merge or, in the operator-manual-commit path
    /// (v2-deep-spec.md §Step 30 Path 2), re-submitting
    /// `IntegrationMerge { resolved_via_escalation: Some(id) }`
    /// with the operator-authored commit SHA.
    ///
    /// `requested_scope` discriminant: [`RequestedEscalationScope::MergeConflict`].
    MergeConflict,

    /// **V2.5b — Kernel-initiated.** The kernel observed an
    /// orchestrator-respawn no-progress loop on this initiative
    /// (`INV-ORCH-RESPAWN-NO-PROGRESS-CEILING-01`): the per-
    /// initiative `orchestrator_no_progress_respawn_count`
    /// crossed `MAX_ORCH_NO_PROGRESS_RESPAWNS` (default 3) without
    /// any task FSM transition resetting it. The kernel has
    /// already (a) marked the initiative `Failed`, (b) emitted
    /// `AuditEventKind::OrchestratorRespawnCeilingExceeded`, and
    /// (c) inserted this `LogicalDeadlock` escalations row so the
    /// operator can either approve a counter-reset + retry
    /// (transitioning the initiative back to `Executing` and
    /// scheduling a fresh orchestrator respawn) or deny and
    /// preserve the `Failed` terminal state.
    ///
    /// **Initiator.** This class is the FIRST `EscalationClass`
    /// whose `escalations.initiator` column is `'Kernel'` (every
    /// other class is `'Planner'`). The discriminant comes from
    /// Migration 20's `initiator` column added in the same slice
    /// as this enum variant. The auto-create path lives in
    /// `kernel/src/orch_respawn_ceiling.rs::insert_logical_deadlock_escalation_in_tx`
    /// and runs inside the same SQLite transaction as the
    /// initiative-Failed flip per
    /// `audit-paired-writes.md §4` paired-write contract.
    ///
    /// `requested_scope` discriminant: [`RequestedEscalationScope::LogicalDeadlock`].
    LogicalDeadlock,
}

impl EscalationClass {
    pub fn as_sql_str(self) -> &'static str {
        match self {
            Self::CapabilityUpgrade => "CapabilityUpgrade",
            Self::DelegationRenewal => "DelegationRenewal",
            Self::BudgetException => "BudgetException",
            Self::QualityGateException => "QualityGateException",
            Self::MergeConflict => "MergeConflict",
            Self::LogicalDeadlock => "LogicalDeadlock",
        }
    }

    pub fn from_sql_str(s: &str) -> Option<Self> {
        match s {
            "CapabilityUpgrade" => Some(Self::CapabilityUpgrade),
            "DelegationRenewal" => Some(Self::DelegationRenewal),
            "BudgetException" => Some(Self::BudgetException),
            "QualityGateException" => Some(Self::QualityGateException),
            "MergeConflict" => Some(Self::MergeConflict),
            "LogicalDeadlock" => Some(Self::LogicalDeadlock),
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
    /// **V2 (Step 30).** Orchestrator-submitted scope for an
    /// unresolvable merge conflict. The `conflicts` list carries
    /// repository-relative paths whose merge could not be resolved
    /// in-VM by the Orchestrator's NNSP-prescribed triviality
    /// criteria (T1–T4). The list is informational for the
    /// operator UI; the kernel does NOT use it as authority — the
    /// authority decision is operator-manual via
    /// `raxis escalate resolve`, and the resulting commit (in the
    /// operator-manual-commit path) is gated at IntegrationMerge
    /// admission by Check 5 (path-allowlist) and Check 6b
    /// (escalation status / class / session) regardless of which
    /// paths the Orchestrator originally listed here.
    ///
    /// Bounded at [`MAX_MERGE_CONFLICT_PATHS`] entries × 1 KiB each
    /// to keep `requested_scope_json` writable inside a single
    /// SQLite row without producing pathological audit chain bloat.
    MergeConflict {
        conflicts: Vec<String>,
    },

    /// **V2.5b — Kernel-initiated.** Scope payload for the
    /// auto-created `LogicalDeadlock` escalation. Fields:
    ///
    ///   * `initiative_id` — the initiative whose orchestrator
    ///     respawn-no-progress counter exceeded the ceiling. The
    ///     escalation row's `initiative_id` column carries the
    ///     same value; we duplicate it inside the scope JSON so
    ///     audit-replay readers can reconstruct the full failure
    ///     surface from one column.
    ///   * `attempts` — the post-increment respawn count that
    ///     tripped the ceiling. Always strictly greater than the
    ///     kernel constant
    ///     `orch_respawn_ceiling::MAX_ORCH_NO_PROGRESS_RESPAWNS`.
    ///   * `window_secs` — the wall-clock window from the FIRST
    ///     no-progress respawn (counter == 1) through the
    ///     ceiling-exceedance respawn. Operators read this to
    ///     decide whether the loop was tight (suggesting a fast
    ///     hot path the orchestrator hammered) versus drawn-out
    ///     (suggesting a slow upstream regression).
    ///   * `last_intent_kind` — the most recent kernel-rejected
    ///     intent the orchestrator submitted (e.g.
    ///     `"RetrySubTask"`). The operator UI surfaces this
    ///     literally so the rejection class is visible in the
    ///     escalation card without a separate API call.
    ///   * `last_rejection_reason` — the kernel's textual
    ///     rejection rationale for the same intent (e.g.
    ///     `"RetrySubTaskRejectedNotRetryable"` when the
    ///     activation row was `Completed` with
    ///     `review_reject_count = 0`). Pairs with
    ///     `last_intent_kind` to give the operator the full
    ///     "what-the-orchestrator-was-trying-to-do" surface.
    ///
    /// Bounded to `MAX_LOGICAL_DEADLOCK_REASON_LEN` per text
    /// field (1 KiB) so audit-chain bloat is structurally
    /// bounded — a hostile orchestrator that loops on a
    /// pathologically long intent shape can't blow the audit row
    /// size.
    LogicalDeadlock {
        initiative_id: crate::InitiativeId,
        attempts: u32,
        window_secs: u64,
        last_intent_kind: String,
        last_rejection_reason: String,
    },
}

/// V2 (Step 30) hard cap on `RequestedEscalationScope::MergeConflict`
/// `conflicts` length. Real-world merge waves rarely produce more
/// than a handful of unresolvable paths; capping prevents an
/// adversarial Orchestrator from flooding the operator UI or audit
/// chain with millions of fake conflict paths. Enforced at
/// admission of `EscalationRequest`.
pub const MAX_MERGE_CONFLICT_PATHS: usize = 64;

/// V2 (Step 30) hard cap on the byte length of any single conflict
/// path inside [`RequestedEscalationScope::MergeConflict::conflicts`].
/// 1 KiB is well above the longest path any sensible repository
/// hosts and prevents bypassing [`MAX_MERGE_CONFLICT_PATHS`] via
/// pathological single-entry payloads.
pub const MAX_MERGE_CONFLICT_PATH_LEN: usize = 1024;

/// V2.5b cap on the byte length of either `last_intent_kind` or
/// `last_rejection_reason` inside
/// [`RequestedEscalationScope::LogicalDeadlock`]. 1 KiB matches
/// [`MAX_MERGE_CONFLICT_PATH_LEN`]; a hostile orchestrator that
/// loops on a pathologically long intent shape cannot blow the
/// audit row size past this bound. Enforced at auto-create time
/// in `kernel/src/orch_respawn_ceiling.rs::truncate_for_scope`.
pub const MAX_LOGICAL_DEADLOCK_REASON_LEN: usize = 1024;

impl RequestedEscalationScope {
    /// The class discriminant for this scope variant.
    pub fn class(&self) -> EscalationClass {
        match self {
            Self::CapabilityUpgrade { .. } => EscalationClass::CapabilityUpgrade,
            Self::DelegationRenewal { .. } => EscalationClass::DelegationRenewal,
            Self::BudgetException { .. } => EscalationClass::BudgetException,
            Self::QualityGateException { .. } => EscalationClass::QualityGateException,
            Self::MergeConflict { .. } => EscalationClass::MergeConflict,
            Self::LogicalDeadlock { .. } => EscalationClass::LogicalDeadlock,
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
    AlreadyPending { escalation_id: crate::EscalationId },

    /// The kernel refused to record the escalation.
    Rejected { reason: EscalationRejectionReason },
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// V2 Step 30: `MergeConflict` joins the four V1 escalation classes.
    /// The SQL string round-trip is wire-load-bearing (the
    /// `escalations.class` column is a free TEXT column, but the
    /// `from_sql_str` parser is the only legal admission path back
    /// into a typed enum).
    #[test]
    fn merge_conflict_class_round_trips_through_sql_string() {
        for class in [
            EscalationClass::CapabilityUpgrade,
            EscalationClass::DelegationRenewal,
            EscalationClass::BudgetException,
            EscalationClass::QualityGateException,
            EscalationClass::MergeConflict,
            EscalationClass::LogicalDeadlock,
        ] {
            let s = class.as_sql_str();
            assert_eq!(
                EscalationClass::from_sql_str(s),
                Some(class),
                "{class:?} must round-trip through its as_sql_str / from_sql_str pair",
            );
        }
        // Negative case: the parser is closed.
        assert_eq!(EscalationClass::from_sql_str("NotARealClass"), None);
    }

    /// V2.5b: `LogicalDeadlock` joins the prior five classes. The
    /// kernel-initiated auto-escalation path
    /// (`kernel/src/orch_respawn_ceiling.rs`) reads
    /// `RequestedEscalationScope::LogicalDeadlock { initiative_id,
    /// attempts, window_secs, last_intent_kind, last_rejection_reason }`
    /// and projects to `EscalationClass::LogicalDeadlock`; the
    /// reverse reconstruction (audit-replay readers materialising
    /// the scope from `requested_scope_json`) round-trips through
    /// serde JSON.
    #[test]
    fn logical_deadlock_scope_round_trips_through_serde_json() {
        let scope = RequestedEscalationScope::LogicalDeadlock {
            initiative_id: crate::InitiativeId::new_v4(),
            attempts: 4,
            window_secs: 120,
            last_intent_kind: "RetrySubTask".into(),
            last_rejection_reason: "RetrySubTaskRejectedNotRetryable".into(),
        };
        assert_eq!(scope.class(), EscalationClass::LogicalDeadlock);
        let s = serde_json::to_string(&scope).expect("serde encode");
        let back = serde_json::from_str::<RequestedEscalationScope>(&s).expect("serde decode");
        match back {
            RequestedEscalationScope::LogicalDeadlock {
                attempts,
                window_secs,
                last_intent_kind,
                last_rejection_reason,
                ..
            } => {
                assert_eq!(attempts, 4);
                assert_eq!(window_secs, 120);
                assert_eq!(last_intent_kind, "RetrySubTask");
                assert_eq!(last_rejection_reason, "RetrySubTaskRejectedNotRetryable");
            }
            other => panic!("unexpected scope variant after round-trip: {other:?}"),
        }
    }

    /// `RequestedEscalationScope::MergeConflict` discriminant must
    /// project to `EscalationClass::MergeConflict` in every code
    /// path that derives the outer `class` from the scope (the
    /// existing scope variants share this guarantee — Step 30 just
    /// extends it).
    #[test]
    fn merge_conflict_scope_projects_to_merge_conflict_class() {
        let scope = RequestedEscalationScope::MergeConflict {
            conflicts: vec!["src/a.rs".into(), "src/b.rs".into()],
        };
        assert_eq!(scope.class(), EscalationClass::MergeConflict);
    }

    /// `requested_scope_json` is the on-disk projection of the scope
    /// enum; we round-trip a populated `MergeConflict` through serde
    /// to lock in the wire shape that operator UIs and audit-replay
    /// tools will consume. Bincode is the canonical IPC wire; serde
    /// JSON is what hits `requested_scope_json`.
    #[test]
    fn merge_conflict_scope_round_trips_through_serde_json() {
        let scope = RequestedEscalationScope::MergeConflict {
            conflicts: vec!["src/a.rs".into(), "src/b.rs".into()],
        };
        let s = serde_json::to_string(&scope).expect("serde encode");
        let back = serde_json::from_str::<RequestedEscalationScope>(&s).expect("serde decode");
        match back {
            RequestedEscalationScope::MergeConflict { conflicts } => {
                assert_eq!(conflicts, vec!["src/a.rs", "src/b.rs"]);
            }
            other => panic!("unexpected scope variant after round-trip: {other:?}"),
        }
    }

    /// Caps on `MergeConflict.conflicts` are wire-load-bearing: the
    /// kernel admission path enforces them before persisting the
    /// scope, and changing them would silently widen the audit
    /// chain budget. Pin the values so a future bump is visible.
    #[test]
    fn merge_conflict_caps_are_pinned() {
        assert_eq!(MAX_MERGE_CONFLICT_PATHS, 64);
        assert_eq!(MAX_MERGE_CONFLICT_PATH_LEN, 1024);
    }
}

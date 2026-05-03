// raxis-audit-tools::event — AuditEvent and AuditEventKind.
//
// Normative reference: kernel-store.md §2.5.2 "Audit record format"
//
// Every kernel state mutation that succeeds emits exactly one AuditEvent
// AFTER the SQLite commit (write ordering invariant, §2.5.2).
//
// The AuditEvent JSON wire format is:
//   {
//     "seq":           42,
//     "event_id":      "<uuid-v4>",
//     "event_kind":    "IntentAccepted",
//     "session_id":    "<uuid or null>",
//     "task_id":       "<task-id or null>",
//     "initiative_id": "<initiative-id or null>",
//     "payload":       { ... },
//     "emitted_at":    1714500000,
//     "prev_sha256":   "<hex SHA-256 of previous line bytes>"
//   }

use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// AuditEvent — the top-level record type written to JSONL.
// ---------------------------------------------------------------------------

/// A single audit record, serialised as one JSONL line.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    /// Monotonically increasing counter, kernel-local. Reset only at genesis.
    /// Gaps indicate a reconciliation gap (crash between commit and JSONL write).
    pub seq: u64,

    /// Random UUID v4 per event; never reused.
    pub event_id: Uuid,

    /// Human-readable event discriminant (matches AuditEventKind variant name).
    pub event_kind: String,

    /// The session associated with this event, if any.
    pub session_id: Option<String>,

    /// The task associated with this event, if any.
    pub task_id: Option<String>,

    /// The initiative associated with this event, if any.
    pub initiative_id: Option<String>,

    /// Event-kind-specific structured payload.
    pub payload: serde_json::Value,

    /// Unix seconds (UTC) when this record was emitted.
    pub emitted_at: i64,

    /// SHA-256 of the raw bytes of the previous JSONL line (including '\n').
    /// "0000...0000" (64 zeroes) for the first record in a segment.
    pub prev_sha256: String,
}

// ---------------------------------------------------------------------------
// AuditEventKind — structured payload constructors for every event type.
//
// These are the normative event kinds referenced throughout kernel-core.md
// and kernel-store.md. Each variant serialises into the `payload` field.
// The variant name (as_str) is written into `event_kind`.
// ---------------------------------------------------------------------------

/// Structured payload for each type of kernel audit event.
/// Serialised into `AuditEvent.payload` using serde_json.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "PascalCase")]
pub enum AuditEventKind {
    // --- Kernel lifecycle ---
    KernelStarted {
        data_dir: String,
        policy_epoch: u64,
        schema_version: i64,
    },
    KernelStopped {
        reason: String,
    },

    // --- Initiative lifecycle ---
    InitiativeCreated {
        initiative_id: String,
        plan_hash: String,
        signed_by: String,
        signed_at: i64,
    },
    PlanApproved {
        initiative_id: String,
        task_count: usize,
    },
    PlanRejected {
        initiative_id: String,
    },
    /// kernel-store.md §2.5.8 `path_scope_override` semantics:
    /// emitted by `approve_plan` for **every** task in the plan that has
    /// `path_scope_override = true`. Records the override at the moment
    /// the kernel honors it, so an auditor can reconstruct exactly which
    /// task IDs ran with `effective_allow == UNIVERSAL` and under whose
    /// operator approval. The signing tool's `--allow-path-override`
    /// acknowledgement is a separate gate (Part 4 normative) but does
    /// NOT replace this kernel-side audit emit — offline-signing
    /// workflows still produce this event when the kernel processes
    /// the plan.
    PathScopeOverrideApplied {
        initiative_id: String,
        task_id: String,
        approving_operator: String,
    },
    InitiativeStateChanged {
        initiative_id: String,
        from_state: String,
        to_state: String,
    },
    InitiativeAborted {
        initiative_id: String,
        triggered_by_operator: Option<String>,
    },

    // --- Task lifecycle ---
    TaskAdmitted {
        task_id: String,
        initiative_id: String,
        lane_id: String,
    },
    TaskStateChanged {
        task_id: String,
        from_state: String,
        to_state: String,
        actor: String,
        policy_epoch: u64,
    },

    // --- Intent acceptance ---
    IntentAccepted {
        task_id: String,
        session_id: String,
        intent_kind: String,
        base_sha: Option<String>,
        head_sha: Option<String>,
        sequence_number: u64,
        remaining_units: u64,
    },
    IntentRejected {
        task_id: String,
        session_id: String,
        intent_kind: String,
        error_code: String,
        sequence_number: u64,
    },

    // --- Session management ---
    SessionCreated {
        session_id: String,
        role: String,
        lineage_id: String,
        worktree_root: Option<String>,
    },
    SessionRevoked {
        session_id: String,
        revoked_by: String,
    },

    // --- Delegation ---
    DelegationGranted {
        delegation_id: String,
        session_id: String,
        capability_class: String,
        expires_at: i64,
        granted_by: String,
    },
    DelegationMarkedStale {
        delegation_id: String,
        session_id: String,
        capability_class: String,
        reason: String,
    },

    // --- Witness / gate ---
    WitnessAccepted {
        verifier_run_id: String,
        task_id: String,
        gate_type: String,
        result_class: String,
        evaluation_sha: String,
    },
    WitnessRejected {
        verifier_run_id: String,
        task_id: String,
        reason: String,
    },
    VerifierProcessFailed {
        task_id: String,
        exit_code: Option<i32>,
        gate_type: String,
    },

    // --- Escalation ---
    EscalationSubmitted {
        escalation_id: String,
        task_id: String,
        class: String,
        lineage_id: String,
    },
    EscalationApproved {
        escalation_id: String,
        approved_by: String,
    },
    EscalationDenied {
        escalation_id: String,
        denied_by: String,
        reason: Option<String>,
    },
    EscalationTimedOut {
        escalation_id: String,
    },
    EscalationConsumed {
        escalation_id: String,
        approval_token_id: String,
        action_hash: String,
        policy_epoch: u64,
    },
    LineageQuarantined {
        lineage_id: String,
        trigger_count: u64,
    },
    /// Emitted when a planner submission would push a lineage past
    /// `policy.escalation_max_per_window`. The submission is rejected
    /// (`EscalationResponse::Rejected { RateLimitExceeded }`) and the
    /// lineage's `quarantine_trigger_count` advances by one.
    /// philosophy.md §"Escalation — rate-limiter fires" calls this out
    /// as a required audit kind.
    EscalationRateLimitExceeded {
        lineage_id: String,
        /// The window-local count *after* the rejected attempt is logged
        /// — i.e. it is exactly `escalation_max_per_window + 1` for the
        /// first overflow and stays at the cap for the rest of the
        /// window. Useful for forensic reconstruction.
        attempted_count: u64,
        window_start: i64,
    },

    // --- Policy epoch ---
    PolicyEpochAdvanced {
        new_epoch_id: u64,
        policy_sha256: String,
        triggered_by: String,
        delegations_marked_stale: u64,
        sessions_invalidated: u64,
    },
    PolicyAdvanceRejected {
        reason: String,
        artifact_epoch: Option<u64>,
        current_epoch: u64,
    },
    PolicyAdvanceFailed {
        reason: String,
        new_epoch_id: u64,
    },

    // --- IPC auth / replay prevention ---
    ReplayRejected {
        session_id: String,
        sequence_num: u64,
        reason: String,
    },

    // --- Recovery ---
    ReconciliationGap {
        missing_seq: u64,
        reconstructed_event: String,
        reconstructed: bool,
    },
    TaskBlockedForRecovery {
        task_id: String,
        block_reason: String,
    },
    DelegationSignatureUnverifiable {
        delegation_id: String,
        expected_signer_unknown_in_current_policy: bool,
    },

    // --- Gateway supervisor (peripherals.md §3.2 "Spawn model") ---
    /// Emitted by `gateway::supervisor::spawn_and_supervise` each time
    /// it spawns a fresh `raxis-gateway` subprocess. `attempt` is
    /// 1-indexed across the kernel-process lifetime; an `attempt` > 1
    /// means a previous gateway crashed and the supervisor respawned.
    /// `token_prefix` is the first 8 hex chars of the new
    /// `gateway_process_token` — the full token never appears in
    /// audit records (it is an in-process secret).
    GatewaySpawned {
        token_prefix: String,
        binary_path: String,
        attempt: u32,
    },
    /// The supervised gateway subprocess exited (clean or otherwise).
    /// `exit_code = None` when the child was killed by a signal or
    /// could not be reaped. Followed by either another `GatewaySpawned`
    /// (back-off + respawn) or `GatewayQuarantined` (max crashes hit).
    GatewayCrashed {
        token_prefix: String,
        exit_code: Option<i32>,
        attempt: u32,
    },
    /// The supervisor exceeded `[gateway].max_consecutive_respawns`
    /// and stopped respawning. Subsequent `FetchRequest`s short-circuit
    /// to `error: "GatewayUnavailable"` until the operator restarts
    /// the kernel.
    GatewayQuarantined {
        reason: String,
        total_attempts: u32,
    },
    /// Best-effort kernel→gateway signal (e.g. `EpochAdvanced`) failed
    /// to deliver. Per kernel-core.md §`policy_manager.rs` Phase 3 this
    /// MUST NOT roll back the epoch advance — the gateway's own
    /// failure-closed contract (`peripherals.md` §3.2 "Domain allowlist
    /// re-validation") is the second line of defence (gateway returns
    /// `PolicyReloadFailed` until its on-disk reload succeeds).
    ///
    /// `signal` is the `GatewayMessage` variant short-name (e.g.
    /// `"EpochAdvanced"`). `reason` is a stable short string from
    /// `GatewayCallError::category()`: `"unavailable"`, `"dropped"`,
    /// `"gateway_error"`, `"unexpected_reply"`.
    GatewaySignalFailed {
        signal: String,
        new_epoch_id: Option<u64>,
        reason: String,
    },
}

impl AuditEventKind {
    /// The canonical event_kind string written to the `event_kind` field.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::KernelStarted { .. } => "KernelStarted",
            Self::KernelStopped { .. } => "KernelStopped",
            Self::InitiativeCreated { .. } => "InitiativeCreated",
            Self::PlanApproved { .. } => "PlanApproved",
            Self::PlanRejected { .. } => "PlanRejected",
            Self::PathScopeOverrideApplied { .. } => "PathScopeOverrideApplied",
            Self::InitiativeStateChanged { .. } => "InitiativeStateChanged",
            Self::InitiativeAborted { .. } => "InitiativeAborted",
            Self::TaskAdmitted { .. } => "TaskAdmitted",
            Self::TaskStateChanged { .. } => "TaskStateChanged",
            Self::IntentAccepted { .. } => "IntentAccepted",
            Self::IntentRejected { .. } => "IntentRejected",
            Self::SessionCreated { .. } => "SessionCreated",
            Self::SessionRevoked { .. } => "SessionRevoked",
            Self::DelegationGranted { .. } => "DelegationGranted",
            Self::DelegationMarkedStale { .. } => "DelegationMarkedStale",
            Self::WitnessAccepted { .. } => "WitnessAccepted",
            Self::WitnessRejected { .. } => "WitnessRejected",
            Self::VerifierProcessFailed { .. } => "VerifierProcessFailed",
            Self::EscalationSubmitted { .. } => "EscalationSubmitted",
            Self::EscalationApproved { .. } => "EscalationApproved",
            Self::EscalationDenied { .. } => "EscalationDenied",
            Self::EscalationTimedOut { .. } => "EscalationTimedOut",
            Self::EscalationConsumed { .. } => "EscalationConsumed",
            Self::LineageQuarantined { .. } => "LineageQuarantined",
            Self::EscalationRateLimitExceeded { .. } => "EscalationRateLimitExceeded",
            Self::PolicyEpochAdvanced { .. } => "PolicyEpochAdvanced",
            Self::PolicyAdvanceRejected { .. } => "PolicyAdvanceRejected",
            Self::PolicyAdvanceFailed { .. } => "PolicyAdvanceFailed",
            Self::ReplayRejected { .. } => "ReplayRejected",
            Self::ReconciliationGap { .. } => "ReconciliationGap",
            Self::TaskBlockedForRecovery { .. } => "TaskBlockedForRecovery",
            Self::DelegationSignatureUnverifiable { .. } => "DelegationSignatureUnverifiable",
            Self::GatewaySpawned { .. } => "GatewaySpawned",
            Self::GatewayCrashed { .. } => "GatewayCrashed",
            Self::GatewayQuarantined { .. } => "GatewayQuarantined",
            Self::GatewaySignalFailed { .. } => "GatewaySignalFailed",
        }
    }
}

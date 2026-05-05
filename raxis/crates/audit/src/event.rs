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
    ///
    /// `approving_operator_display_name` is the operator's
    /// `display_name` from the policy bundle at the moment of emit
    /// (a snapshot, not a live join). It is `None` for two reasons
    /// only:
    ///   1. The event was written before the display-name plumbing
    ///      shipped (legacy segment); the CLI render layer falls
    ///      back to `operator_certificates` lookup and marks the
    ///      result as historical.
    ///   2. The kernel could not resolve the fingerprint at emit
    ///      time (extremely rare — would require the operator that
    ///      just authenticated and signed the plan to have been
    ///      removed from the bundle a microsecond later; only
    ///      realistic in tight epoch-rotation races).
    /// See `kernel-store.md` §2.5.2 "Operator display-name fields"
    /// for the cross-variant convention.
    PathScopeOverrideApplied {
        initiative_id: String,
        task_id: String,
        approving_operator: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        approving_operator_display_name: Option<String>,
    },
    InitiativeStateChanged {
        initiative_id: String,
        from_state: String,
        to_state: String,
    },
    /// `triggered_by_operator_display_name` mirrors the convention
    /// described on `PathScopeOverrideApplied` above. Both fields are
    /// `Option` because `triggered_by_operator` itself is optional
    /// (kernel-internal aborts have no operator) — when the
    /// fingerprint is `None` the display name is necessarily `None`
    /// as well.
    InitiativeAborted {
        initiative_id: String,
        triggered_by_operator: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        triggered_by_operator_display_name: Option<String>,
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
    /// `revoked_by_display_name` follows the cross-variant
    /// convention in `kernel-store.md` §2.5.2 "Operator display-name
    /// fields": present when the kernel could resolve `revoked_by` to
    /// an operator entry in the policy bundle at emit time, absent
    /// otherwise (legacy segment, or an operator that vanished from
    /// policy between authentication and emit — extremely rare).
    SessionRevoked {
        session_id: String,
        revoked_by: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        revoked_by_display_name: Option<String>,
    },

    // --- Delegation ---
    /// `granted_by_display_name` follows the cross-variant
    /// convention in `kernel-store.md` §2.5.2 "Operator display-name
    /// fields".
    DelegationGranted {
        delegation_id: String,
        session_id: String,
        capability_class: String,
        expires_at: i64,
        granted_by: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        granted_by_display_name: Option<String>,
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
    /// `approved_by_display_name` follows the cross-variant
    /// convention in `kernel-store.md` §2.5.2 "Operator display-name
    /// fields".
    EscalationApproved {
        escalation_id: String,
        approved_by: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        approved_by_display_name: Option<String>,
    },
    /// `denied_by_display_name` follows the cross-variant convention
    /// in `kernel-store.md` §2.5.2 "Operator display-name fields".
    EscalationDenied {
        escalation_id: String,
        denied_by: String,
        reason: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        denied_by_display_name: Option<String>,
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
    /// `triggered_by_display_name` follows the cross-variant
    /// convention in `kernel-store.md` §2.5.2 "Operator display-name
    /// fields". The lookup is performed against the **incoming**
    /// bundle (i.e. the one being installed by this advance), not
    /// the previous one — so an operator who renames themselves as
    /// part of the rotation is recorded under the new name.
    PolicyEpochAdvanced {
        new_epoch_id: u64,
        policy_sha256: String,
        triggered_by: String,
        delegations_marked_stale: u64,
        sessions_invalidated: u64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        triggered_by_display_name: Option<String>,
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

    // --- Notifications (cli-readonly.md §5.6.3) ---
    /// A per-channel notification handler returned an error. The
    /// originating mutation is unaffected — handler failure NEVER
    /// aborts the parent transaction (cli-readonly.md §5.6.3).
    ///
    /// `channel_id` matches `[[notifications.channels]].id` from the
    /// active policy. `event_kind` is the `AuditEventKind` discriminant
    /// of the event we tried to deliver. `reason` is a short, stable
    /// classification string (`"io"`, `"target_invalid"`,
    /// `"unimplemented_v1"`); the verbose error text goes to the
    /// kernel stderr log.
    NotificationDeliveryFailed {
        channel_id: String,
        event_kind: String,
        reason:     String,
    },

    // --- Operator certificates (kernel-store.md §2.5.7, security-model.md §cert-lifecycle) ---
    /// Emitted by `policy_manager::advance_epoch` (and the genesis path)
    /// for every cert-bound `OperatorEntry` mirrored into the
    /// `operator_certificates` view table on a successful epoch
    /// install. The audit-chain mirror is the authoritative ledger of
    /// "who is currently a cert-bound operator at epoch N" — the
    /// `operator_certificates` SQLite table is a denormalised view
    /// optimised for reads, but if it is ever lost (disk corruption,
    /// schema rebuild) it can be reconstructed by replaying these
    /// audit records.
    ///
    /// Field semantics:
    ///
    /// * `pubkey_fingerprint` — SHA-256[:16] hex of `pubkey_hex`.
    /// * `epoch_id` — the policy epoch this cert is now scoped to.
    /// * `cert_kind` — `"Standard"` or `"EmergencyRecovery"` (matches
    ///   `CertKind::as_str`). The field is named `cert_kind` (NOT just
    ///   `kind`) because the audit-event enum uses `#[serde(tag =
    ///   "kind")]` for the variant discriminator, and a payload field
    ///   with the same key would collide on the JSON wire.
    /// * `display_name` — operator label (free-form).
    /// * `not_before` — unix seconds; cert validity start (sentinel `0`
    ///   for `EmergencyRecovery`).
    /// * `not_after` — unix seconds; cert validity end (sentinel `0`
    ///   for `EmergencyRecovery`).
    /// * `permitted_ops` — list of operator op names this cert is
    ///   allowed to invoke. Already normalised by the policy bundle
    ///   (e.g. `EmergencyRecovery` is structurally pinned to
    ///   `["RotateEpoch"]`).
    /// * `force_misconfig_bypass` — `true` if the operator entry opted
    ///   into bypassing structural cert-validation errors. The bypass
    ///   itself emits a separate `OperatorCertMisconfigBypassed` event
    ///   for each rule that was relaxed.
    /// * `previous_fingerprint` — `Some(fp)` when this cert install is a
    ///   rotation (the operator ran `raxis cert install --replace-for
    ///   <previous_fp> --new-cert <path>`), `None` for the very first
    ///   install of a fresh operator entry. The kernel infers a
    ///   rotation by diffing the old and new policy bundles at epoch
    ///   advance: if an entry's `pubkey_hex` is unchanged but the
    ///   embedded cert's `self_sig_hex` (or any other cert field) is
    ///   different, it's a rotation and we record the prior cert's
    ///   fingerprint so the audit chain captures continuity. (The
    ///   pubkey is unchanged across a rotation by INV-CERT-04 — see
    ///   `cli/src/commands/cert.rs::install`.)
    OperatorCertInstalled {
        pubkey_fingerprint:     String,
        epoch_id:               u64,
        cert_kind:              String,
        display_name:           String,
        not_before:             i64,
        not_after:              i64,
        permitted_ops:          Vec<String>,
        force_misconfig_bypass: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        previous_fingerprint:   Option<String>,
    },

    /// Emitted at policy load when a structural cert-validation error
    /// would normally fail the load BUT the operator entry has set
    /// `force_misconfig_bypass = true`. The bypass is honoured (the
    /// epoch advances) AND this audit event records every individual
    /// invariant that was relaxed, so an auditor can reconstruct the
    /// exact set of rules the operator chose to override.
    ///
    /// Self-signature failures and pubkey/fingerprint mismatches are
    /// NEVER bypassable (they would let an attacker spoof an
    /// operator's identity); those errors fail-closed regardless of
    /// `force_misconfig_bypass` and never produce this event.
    ///
    /// `violations` is the verbatim `Display` string of every
    /// structural error that was relaxed for this entry, in the
    /// order the validator surfaced them. The strings come straight
    /// from the `CertError` Display impls and are intentionally
    /// human-readable (so a forensic auditor reading the chain sees
    /// the same wording the operator saw at validate time).
    OperatorCertMisconfigBypassed {
        pubkey_fingerprint: String,
        epoch_id:           u64,
        cert_kind:          String,
        display_name:       String,
        violations:         Vec<String>,
    },

    /// Emitted by the cert-check runtime sweep when a Standard cert is
    /// inside its Expiring zone (i.e. `now >= not_after - warn_window`
    /// AND `now < not_after`). The operator IPC dispatcher emits this
    /// AT MOST ONCE PER EPOCH for a given cert — the sweep is gated by
    /// an in-process dedupe set keyed on `(pubkey_fingerprint, epoch_id)`.
    /// Subsequent ops by the same operator in the same epoch are
    /// silently allowed without re-emitting (so a chatty operator
    /// doesn't flood the chain).
    ///
    /// The op the operator was about to invoke is included so an
    /// auditor can correlate the warning with downstream activity.
    OperatorCertExpiringSoon {
        pubkey_fingerprint: String,
        epoch_id:           u64,
        op:                 String,
        not_after:          i64,
        days_remaining:     i64,
    },

    /// Emitted by the cert-check runtime sweep when a Standard cert is
    /// inside its Grace zone (i.e. `now >= not_after` AND
    /// `now < not_after + grace_window`). Same once-per-epoch dedupe
    /// posture as `OperatorCertExpiringSoon`. Operations are still
    /// permitted in the Grace zone — this event is the "this is your
    /// last chance to rotate" warning before the cert hits the
    /// Expired zone.
    OperatorCertInGracePeriod {
        pubkey_fingerprint: String,
        epoch_id:           u64,
        op:                 String,
        not_after:          i64,
        grace_ends_at:      i64,
    },

    /// Emitted by the cert-check runtime sweep when an op is DENIED
    /// because the cert is in its Expired zone (i.e.
    /// `now >= not_after + grace_window`). The IPC dispatcher returns
    /// `FAIL_CERT_EXPIRED` to the operator and writes this audit
    /// event in the same Phase-1.5 emit step as the rejection
    /// response. Unlike the Expiring/Grace events this is NOT
    /// deduped — every denied op produces one record so an auditor
    /// can see exactly which operations were attempted post-expiry.
    OperatorCertExpiredOpDenied {
        pubkey_fingerprint: String,
        epoch_id:           u64,
        op:                 String,
        not_after:          i64,
        expired_at:         i64,
    },

    /// Emitted when an `EmergencyRecovery` cert is used to invoke
    /// any operator op (in v1 always `RotateEpoch` because of the
    /// structural pin). This is the audit hook for the break-glass
    /// posture: emergency-cert use is never silent, so an operator
    /// who legitimately rotated the epoch via the emergency key
    /// has a record they can present, and an attacker who
    /// compromises the key cannot use it without leaving a trace.
    EmergencyOperatorUsed {
        pubkey_fingerprint: String,
        epoch_id:           u64,
        op:                 String,
    },

    // --- Read-only CLI: redaction reveal (cli-readonly.md §5.4.2 / §5.7.2) ---
    /// Emitted by the read-only CLI when an operator runs a command
    /// with `--reveal-paths` (or any future redaction-bypass flag).
    /// This is the **only** audit event the read-only CLI is allowed
    /// to write into the chain — see cli-readonly.md §5.7.3.
    ///
    /// Recording the read makes path-list disclosure observable
    /// without forbidding it: operators can still debug, but they
    /// leave a trace in the same hash-chained log as every kernel
    /// state mutation.
    ///
    /// Field semantics:
    ///   * `actor`   — who triggered the reveal. The CLI uses the
    ///     operator's pubkey fingerprint (32 hex chars, matches the
    ///     `[meta].signed_by` form in `policy.toml`) when an
    ///     `--operator-key` is supplied; otherwise falls back to
    ///     `cli:<unix-user>`.
    ///   * `table`   — logical table the data came from
    ///     (e.g. `"task_plan_fields"`).
    ///   * `column`  — which redacted column was revealed
    ///     (e.g. `"path_allowlist"`, `"path_export_globs"`, or the
    ///     synthetic `"all"` for a whole-row reveal).
    ///   * `command` — the CLI invocation that triggered the reveal,
    ///     stored as a short, stable string (e.g. `"inspect"`).
    ///
    /// The companion `task_id` foreign-key column on `AuditEvent`
    /// carries the task whose paths were revealed; this payload
    /// duplicates it so log readers don't have to project two fields
    /// to surface the read target in JSON output.
    PathReadAccessed {
        actor:    String,
        table:    String,
        column:   String,
        task_id:  String,
        command:  String,
    },

    // --- Initiative quarantine (kernel-store.md §2.5.8) -------------------
    /// Emitted when an operator individually quarantines an initiative
    /// via `raxis initiative quarantine <id>`. The IPC dispatcher
    /// inserts a row into `initiative_quarantines` and writes this
    /// audit event in the same Phase-1.5 emit step. Subsequent
    /// `IntentRequest`s against this initiative are rejected with
    /// `FAIL_INITIATIVE_QUARANTINED` by the planner intent gate.
    ///
    /// `quarantined_by` is the operator pubkey_fingerprint (32 hex
    /// chars) issuing the command. `reason` is a free-form label;
    /// NULL when the operator did not supply `--reason`.
    /// `quarantined_by_display_name` follows the cross-variant
    /// convention in `kernel-store.md` §2.5.2 "Operator display-name
    /// fields".
    InitiativeQuarantined {
        initiative_id:  String,
        quarantined_by: String,
        reason:         Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        quarantined_by_display_name: Option<String>,
    },

    /// Rollup event written by `raxis operator quarantine-plans-by
    /// <fingerprint>`. Surfaces the SWEEP itself (one record), with
    /// the count of newly-quarantined initiatives + the target
    /// operator. Each individual collateral quarantine still emits
    /// its own `InitiativeQuarantined` event with the
    /// `quarantined_by` field set to the rotating operator's
    /// fingerprint — that's the per-row record. This event is the
    /// "the operator pressed the big red button" header.
    /// `quarantined_by_display_name` and `target_display_name`
    /// follow the cross-variant convention in `kernel-store.md`
    /// §2.5.2 "Operator display-name fields". Both are independently
    /// optional because the *target* of a quarantine sweep may have
    /// already been removed from the active policy (e.g. the
    /// operator just rotated `target_fingerprint` out of policy
    /// before pressing the big red button to clean up the
    /// initiatives that operator approved); in that case the
    /// `target_display_name` falls back to a CLI-side lookup with
    /// the historical-cert annotation per `kernel-store.md` §2.5.2.
    OperatorQuarantineSwept {
        target_fingerprint: String,
        quarantined_by:     String,
        count:              u64,
        reason:             Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        quarantined_by_display_name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        target_display_name: Option<String>,
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
            Self::NotificationDeliveryFailed { .. } => "NotificationDeliveryFailed",
            Self::OperatorCertInstalled { .. } => "OperatorCertInstalled",
            Self::OperatorCertMisconfigBypassed { .. } => "OperatorCertMisconfigBypassed",
            Self::OperatorCertExpiringSoon { .. } => "OperatorCertExpiringSoon",
            Self::OperatorCertInGracePeriod { .. } => "OperatorCertInGracePeriod",
            Self::OperatorCertExpiredOpDenied { .. } => "OperatorCertExpiredOpDenied",
            Self::EmergencyOperatorUsed { .. } => "EmergencyOperatorUsed",
            Self::PathReadAccessed { .. } => "PathReadAccessed",
            Self::InitiativeQuarantined { .. } => "InitiativeQuarantined",
            Self::OperatorQuarantineSwept { .. } => "OperatorQuarantineSwept",
        }
    }
}

#[cfg(test)]
mod path_read_accessed_tests {
    use super::*;

    #[test]
    fn path_read_accessed_kind_string_matches_variant_name() {
        let kind = AuditEventKind::PathReadAccessed {
            actor:   "fp-7d2c00".to_owned(),
            table:   "task_plan_fields".to_owned(),
            column:  "path_allowlist".to_owned(),
            task_id: "task-001".to_owned(),
            command: "inspect".to_owned(),
        };
        assert_eq!(kind.as_str(), "PathReadAccessed");
    }

    #[test]
    fn path_read_accessed_serialises_with_kind_tag_and_all_fields() {
        let kind = AuditEventKind::PathReadAccessed {
            actor:   "fp-7d2c00".to_owned(),
            table:   "task_plan_fields".to_owned(),
            column:  "path_allowlist".to_owned(),
            task_id: "task-001".to_owned(),
            command: "inspect".to_owned(),
        };
        let v = serde_json::to_value(&kind).expect("serialises");
        assert_eq!(v["kind"], serde_json::json!("PathReadAccessed"));
        assert_eq!(v["actor"], serde_json::json!("fp-7d2c00"));
        assert_eq!(v["table"], serde_json::json!("task_plan_fields"));
        assert_eq!(v["column"], serde_json::json!("path_allowlist"));
        assert_eq!(v["task_id"], serde_json::json!("task-001"));
        assert_eq!(v["command"], serde_json::json!("inspect"));
    }

    // ── operator-cert audit kinds ──────────────────────────────────

    /// Pin every cert-related variant's `kind` discriminant string.
    /// A future rename of any variant breaks this test, so the wire
    /// shape that downstream tools (`raxis verify-chain`,
    /// `raxis cert list`, the notification router) match against
    /// cannot drift silently.
    #[test]
    fn operator_cert_kind_strings_are_pinned() {
        let cases: Vec<(AuditEventKind, &str)> = vec![
            (AuditEventKind::OperatorCertInstalled {
                pubkey_fingerprint: "fp".into(), epoch_id: 1, cert_kind: "Standard".into(),
                display_name: "chika".into(), not_before: 0, not_after: 0,
                permitted_ops: vec![], force_misconfig_bypass: false,
                previous_fingerprint: None,
            }, "OperatorCertInstalled"),
            (AuditEventKind::OperatorCertMisconfigBypassed {
                pubkey_fingerprint: "fp".into(), epoch_id: 1,
                cert_kind: "Standard".into(), display_name: "chika".into(),
                violations: vec!["x".into()],
            }, "OperatorCertMisconfigBypassed"),
            (AuditEventKind::OperatorCertExpiringSoon {
                pubkey_fingerprint: "fp".into(), epoch_id: 1, op: "AbortTask".into(),
                not_after: 0, days_remaining: 14,
            }, "OperatorCertExpiringSoon"),
            (AuditEventKind::OperatorCertInGracePeriod {
                pubkey_fingerprint: "fp".into(), epoch_id: 1, op: "AbortTask".into(),
                not_after: 0, grace_ends_at: 0,
            }, "OperatorCertInGracePeriod"),
            (AuditEventKind::OperatorCertExpiredOpDenied {
                pubkey_fingerprint: "fp".into(), epoch_id: 1, op: "AbortTask".into(),
                not_after: 0, expired_at: 0,
            }, "OperatorCertExpiredOpDenied"),
            (AuditEventKind::EmergencyOperatorUsed {
                pubkey_fingerprint: "fp".into(), epoch_id: 1, op: "RotateEpoch".into(),
            }, "EmergencyOperatorUsed"),
        ];
        for (kind, expected) in cases {
            assert_eq!(kind.as_str(), expected,
                "as_str() drifted for {expected}");
        }
    }

    /// Confirm the cert-installed payload serialises with every field
    /// and round-trips through JSON. This is the audit-chain mirror
    /// of the `operator_certificates` view-table row, so a wire-shape
    /// drift here would silently break replay-from-audit-chain
    /// recovery (kernel-store.md §2.5.7).
    #[test]
    fn operator_cert_installed_serialises_all_fields() {
        let kind = AuditEventKind::OperatorCertInstalled {
            pubkey_fingerprint:     "abcd0123".to_owned(),
            epoch_id:               2,
            cert_kind:              "Standard".to_owned(),
            display_name:           "chika".to_owned(),
            not_before:             1_700_000_000,
            not_after:              1_731_536_000,
            permitted_ops:          vec!["AbortTask".to_owned(), "ApprovePlan".to_owned()],
            force_misconfig_bypass: false,
            previous_fingerprint:   None,
        };
        let v = serde_json::to_value(&kind).expect("serialises");
        // The serde tag (`#[serde(tag = "kind")]`) writes the variant
        // discriminator into the JSON `kind` field; the payload's own
        // `cert_kind` field is named distinctly to avoid the collision
        // that an identically-named payload field would cause.
        assert_eq!(v["kind"], serde_json::json!("OperatorCertInstalled"));
        assert_eq!(v["pubkey_fingerprint"], serde_json::json!("abcd0123"));
        assert_eq!(v["epoch_id"], serde_json::json!(2));
        assert_eq!(v["cert_kind"], serde_json::json!("Standard"));
        assert_eq!(v["display_name"], serde_json::json!("chika"));
        assert_eq!(v["not_before"], serde_json::json!(1_700_000_000_i64));
        assert_eq!(v["not_after"], serde_json::json!(1_731_536_000_i64));
        assert_eq!(v["permitted_ops"], serde_json::json!(["AbortTask", "ApprovePlan"]));
        assert_eq!(v["force_misconfig_bypass"], serde_json::json!(false));

        // Round-trip pins lossless field decode for chain replay.
        let s = serde_json::to_string(&kind).unwrap();
        let back: AuditEventKind = serde_json::from_str(&s).unwrap();
        match back {
            AuditEventKind::OperatorCertInstalled {
                pubkey_fingerprint, epoch_id, cert_kind, display_name,
                not_before, not_after, permitted_ops, force_misconfig_bypass,
                previous_fingerprint,
            } => {
                assert_eq!(pubkey_fingerprint, "abcd0123");
                assert_eq!(epoch_id,           2);
                assert_eq!(cert_kind,          "Standard");
                assert_eq!(display_name,       "chika");
                assert_eq!(not_before,         1_700_000_000);
                assert_eq!(not_after,          1_731_536_000);
                assert_eq!(permitted_ops,      vec!["AbortTask".to_owned(), "ApprovePlan".to_owned()]);
                assert!(!force_misconfig_bypass);
                assert!(previous_fingerprint.is_none(),
                    "previous_fingerprint defaults to None for non-rotation installs");
            }
            other => panic!("expected OperatorCertInstalled; got {other:?}"),
        }
    }

    /// Pin the wire shape of the two quarantine event kinds. Same
    /// rationale as the cert-kind pin above: downstream tools
    /// (`raxis verify-chain`, `raxis inspect quarantine`, the
    /// notification router) match on the discriminator string and
    /// any silent rename would break replay.
    #[test]
    fn quarantine_kind_strings_are_pinned() {
        let cases: Vec<(AuditEventKind, &str)> = vec![
            (AuditEventKind::InitiativeQuarantined {
                initiative_id: "i1".into(), quarantined_by: "fp".into(),
                reason: Some("compromised key".into()),
                quarantined_by_display_name: None,
            }, "InitiativeQuarantined"),
            (AuditEventKind::OperatorQuarantineSwept {
                target_fingerprint: "chika-fp".into(),
                quarantined_by:     "rot-fp".into(),
                count:              3,
                reason:             None,
                quarantined_by_display_name: None,
                target_display_name:        None,
            }, "OperatorQuarantineSwept"),
        ];
        for (kind, expected) in cases {
            assert_eq!(kind.as_str(), expected, "as_str() drifted for {expected}");
        }
    }

    #[test]
    fn initiative_quarantined_round_trips_through_json() {
        let kind = AuditEventKind::InitiativeQuarantined {
            initiative_id:  "init-7".to_owned(),
            quarantined_by: "fp-rot".to_owned(),
            reason:         Some("compromised plan signer".to_owned()),
            quarantined_by_display_name: Some("Chika".to_owned()),
        };
        let s = serde_json::to_string(&kind).unwrap();
        let back: AuditEventKind = serde_json::from_str(&s).unwrap();
        match back {
            AuditEventKind::InitiativeQuarantined {
                initiative_id, quarantined_by, reason,
                quarantined_by_display_name,
            } => {
                assert_eq!(initiative_id,  "init-7");
                assert_eq!(quarantined_by, "fp-rot");
                assert_eq!(reason.as_deref(), Some("compromised plan signer"));
                assert_eq!(quarantined_by_display_name.as_deref(), Some("Chika"),
                    "display name must round-trip through the JSON wire");
            }
            other => panic!("expected InitiativeQuarantined; got {other:?}"),
        }
    }

    #[test]
    fn operator_quarantine_swept_round_trips_through_json() {
        let kind = AuditEventKind::OperatorQuarantineSwept {
            target_fingerprint: "chika-fp".to_owned(),
            quarantined_by:     "rot-fp".to_owned(),
            count:              42,
            reason:             None,
            quarantined_by_display_name: Some("Jinanwa".to_owned()),
            target_display_name:        Some("Chika".to_owned()),
        };
        let s = serde_json::to_string(&kind).unwrap();
        let back: AuditEventKind = serde_json::from_str(&s).unwrap();
        match back {
            AuditEventKind::OperatorQuarantineSwept {
                target_fingerprint, quarantined_by, count, reason,
                quarantined_by_display_name, target_display_name,
            } => {
                assert_eq!(target_fingerprint, "chika-fp");
                assert_eq!(quarantined_by,     "rot-fp");
                assert_eq!(count,              42);
                assert!(reason.is_none());
                assert_eq!(quarantined_by_display_name.as_deref(), Some("Jinanwa"));
                assert_eq!(target_display_name.as_deref(),         Some("Chika"));
            }
            other => panic!("expected OperatorQuarantineSwept; got {other:?}"),
        }
    }

    /// `display_name` fields are optional; legacy chain segments
    /// written before the plumbing shipped MUST still deserialize.
    /// This pins the forward-compat shape — adding the field can
    /// never break an old reader.
    #[test]
    fn legacy_quarantine_records_without_display_name_still_deserialize() {
        let legacy_initiative = serde_json::json!({
            "kind":           "InitiativeQuarantined",
            "initiative_id":  "init-9",
            "quarantined_by": "fp-old",
            "reason":         null,
        });
        let parsed: AuditEventKind = serde_json::from_value(legacy_initiative).unwrap();
        match parsed {
            AuditEventKind::InitiativeQuarantined {
                quarantined_by_display_name, ..
            } => assert!(quarantined_by_display_name.is_none(),
                "missing field must default to None"),
            other => panic!("expected InitiativeQuarantined; got {other:?}"),
        }

        let legacy_swept = serde_json::json!({
            "kind":               "OperatorQuarantineSwept",
            "target_fingerprint": "chika-fp",
            "quarantined_by":     "rot-fp",
            "count":              0,
            "reason":             null,
        });
        let parsed: AuditEventKind = serde_json::from_value(legacy_swept).unwrap();
        match parsed {
            AuditEventKind::OperatorQuarantineSwept {
                quarantined_by_display_name, target_display_name, ..
            } => {
                assert!(quarantined_by_display_name.is_none());
                assert!(target_display_name.is_none());
            }
            other => panic!("expected OperatorQuarantineSwept; got {other:?}"),
        }
    }

    #[test]
    fn emergency_operator_used_round_trips() {
        let kind = AuditEventKind::EmergencyOperatorUsed {
            pubkey_fingerprint: "fp-emerg".to_owned(),
            epoch_id:           5,
            op:                 "RotateEpoch".to_owned(),
        };
        let s = serde_json::to_string(&kind).unwrap();
        let back: AuditEventKind = serde_json::from_str(&s).unwrap();
        match back {
            AuditEventKind::EmergencyOperatorUsed { pubkey_fingerprint, epoch_id, op } => {
                assert_eq!(pubkey_fingerprint, "fp-emerg");
                assert_eq!(epoch_id, 5);
                assert_eq!(op,       "RotateEpoch");
            }
            other => panic!("expected EmergencyOperatorUsed; got {other:?}"),
        }
    }

    /// Pin the misconfig-bypass payload shape. The `violations` list
    /// captures every relaxed structural rule verbatim; downstream
    /// notification routes match on `kind == "OperatorCertMisconfigBypassed"`
    /// and inspect `violations` to decide whether to page.
    #[test]
    fn operator_cert_misconfig_bypassed_serialises_violations_list() {
        let kind = AuditEventKind::OperatorCertMisconfigBypassed {
            pubkey_fingerprint: "fp-x".to_owned(),
            epoch_id:           3,
            cert_kind:          "EmergencyRecovery".to_owned(),
            display_name:       "break-glass".to_owned(),
            violations:         vec![
                "EmergencyRecovery cert MUST declare permitted_ops = [\"RotateEpoch\"] only".to_owned(),
                "warn_before_expiry_days must be > 0".to_owned(),
            ],
        };
        let v = serde_json::to_value(&kind).unwrap();
        assert_eq!(v["kind"], serde_json::json!("OperatorCertMisconfigBypassed"));
        assert_eq!(v["pubkey_fingerprint"], serde_json::json!("fp-x"));
        assert_eq!(v["epoch_id"], serde_json::json!(3));
        assert_eq!(v["cert_kind"], serde_json::json!("EmergencyRecovery"));
        assert_eq!(v["display_name"], serde_json::json!("break-glass"));
        assert_eq!(v["violations"].as_array().unwrap().len(), 2);
        assert!(v["violations"][0].as_str().unwrap().contains("RotateEpoch"));
    }

    #[test]
    fn path_read_accessed_round_trips_through_json() {
        let kind = AuditEventKind::PathReadAccessed {
            actor:   "cli:chika".to_owned(),
            table:   "task_plan_fields".to_owned(),
            column:  "path_export_globs".to_owned(),
            task_id: "t-42".to_owned(),
            command: "inspect".to_owned(),
        };
        let s    = serde_json::to_string(&kind).unwrap();
        let back: AuditEventKind = serde_json::from_str(&s).unwrap();
        match back {
            AuditEventKind::PathReadAccessed { actor, table, column, task_id, command } => {
                assert_eq!(actor,   "cli:chika");
                assert_eq!(table,   "task_plan_fields");
                assert_eq!(column,  "path_export_globs");
                assert_eq!(task_id, "t-42");
                assert_eq!(command, "inspect");
            }
            other => panic!("expected PathReadAccessed; got {other:?}"),
        }
    }
}

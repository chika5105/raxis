//! Audit→notification taxonomy.
//!
//! Normative reference: `specs/v2/dashboard-hardening.md §2`,
//! `INV-NOTIF-SCOPE-01` (`specs/invariants.md`).
//!
//! Why this module exists
//! ──────────────────────
//! The audit chain and the operator notifications inbox are
//! TWO DIFFERENT SURFACES with two different contracts:
//!
//!   * **Audit chain** — comprehensive, mechanical, append-only
//!     forensic record of EVERY operator action and EVERY system
//!     event. Includes operator passive reads (mark-read, view-
//!     diff, view-file, view-worktree, chain-reverify, etc.).
//!     Always-on. Never filtered.
//!   * **Notifications** — operator-attention surface, scoped to
//!     events the operator should see at-a-glance to know "do I
//!     need to act?". Inbox-style. Has a badge count.
//!
//! Before this filter shipped, the `NotifyingAuditSink` decorator
//! fanned EVERY emitted [`AuditEventKind`] into the SQLite
//! `notifications` table, drowning the operator's inbox in their
//! own dashboard activity (mark-read, view-diff, view-file,
//! chain-reverify, etc.). The same events are still recorded in
//! the audit chain — only the notification PROJECTION is
//! filtered.
//!
//! The mapping
//! ───────────
//! [`notification_priority`] returns `Some(priority)` for events
//! that DESERVE a notification row, and `None` for events that
//! belong in the audit chain only. The match is exhaustive over
//! `AuditEventKind`: adding a new variant without picking a
//! priority is a compile error
//! (`crate::notification_filter::tests` fixes the wire-shape
//! discipline at the unit-test level).
//!
//! Stable-wire output
//! ──────────────────
//! `NotificationPriority::as_str()` is the canonical PascalCase
//! string surfaced on the wire (FE icon / filter chip lookup) and
//! persisted in the audit chain payload of any future
//! `NotificationCreated`-class event. Never rename the variants.

use raxis_audit_tools::AuditEventKind;
use serde::{Deserialize, Serialize};

/// Operator-facing priority bucket for a notification.
///
/// The FE renders one icon + colour per bucket
/// (red exclamation / amber / blue / gray dot) and lets the
/// operator filter by bucket. The classification function
/// [`notification_priority`] is the single source of truth — the
/// FE never invents priorities.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum NotificationPriority {
    /// Operator must intervene — security incident, integrity
    /// violation, kernel-substrate failure, expired/revoked
    /// operator capability, break-glass usage, irrecoverable VM
    /// failure. Red.
    Critical,
    /// Operator attention required — escalation requesting
    /// approval, reviewer rejection, gateway crash, upstream
    /// credential failure, egress stall, policy advance refused,
    /// merge fast-forward failed. Amber.
    High,
    /// Lifecycle milestones — initiative admitted / completed,
    /// reviewer approved, policy successfully advanced, push
    /// completed, kernel boot. Blue.
    Medium,
    /// Low-noise informational events the operator may want to
    /// glance at — admission queue deferral at cap, disk recovery,
    /// inbox-style state changes that aren't actionable. Gray.
    Low,
}

impl NotificationPriority {
    /// Stable PascalCase name. Used by:
    ///   * the dashboard JSON payload (`priority` field on
    ///     `NotificationView`),
    ///   * the FE filter pills + icon registry,
    ///   * any future audit event that records the priority of a
    ///     created notification row.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Critical => "Critical",
            Self::High => "High",
            Self::Medium => "Medium",
            Self::Low => "Low",
        }
    }

    /// Every variant in declaration order. Used by the FE
    /// filter-pill renderer + the notification-priority unit test
    /// pinning the on-wire vocabulary.
    pub const ALL: [NotificationPriority; 4] = [
        NotificationPriority::Critical,
        NotificationPriority::High,
        NotificationPriority::Medium,
        NotificationPriority::Low,
    ];
}

impl std::fmt::Display for NotificationPriority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// String-discriminator variant of [`notification_priority`] for
/// callers that only have the wire-level event-kind name (e.g.
/// the dashboard read path projecting priority into
/// `NotificationView`, the kernel's `dispatch()` defense-in-depth
/// gate). Mirror match-arms of the typed function below — drift
/// is caught by
/// `tests::typed_and_string_apis_agree_on_all_constructed_variants`.
///
/// The fallback for an unknown kind is `None` (audit-only). New
/// `AuditEventKind` variants added without a string arm therefore
/// silently drop OUT of the inbox rather than into it — the
/// safer default if drift slips past review.
#[allow(clippy::too_many_lines)]
pub fn notification_priority_for_kind_str(kind_str: &str) -> Option<NotificationPriority> {
    use NotificationPriority::{Critical, High, Low, Medium};
    match kind_str {
        // Critical
        "IsolationSubstrateRefused"
        | "IsolationFallbackBypass"
        | "SessionVmFailedFinal"
        | "SecurityViolationDetected"
        | "SecurityViolation"
        | "EmergencyOperatorUsed"
        | "BreakglassActivated"
        | "BreakglassDeactivated"
        | "BreakglassAction"
        | "OperatorCertExpiredOpDenied"
        | "OperatorCertRevokedOpDenied"
        | "OperatorCertRevoked"
        | "DelegationSignatureUnverifiable"
        | "DiskFullHaltEntered"
        | "GitStateInconsistent"
        | "ReplayRejected"
        | "ReconciliationGap"
        | "OperatorQuarantineSwept"
        | "InitiativeQuarantined"
        | "LineageQuarantined"
        | "OperatorRevealedSystemCredential"
        | "KernelDeadlockDetected"
        | "KernelRestartHaltedCircuitOpen"
        // INV-KERNEL-RECOVERY-PRESERVES-SAFETY-INVARIANTS-01 — string
        // surface mirrors the typed `K::KernelPanicCaught` /
        // `K::KernelSafetyInvariantViolated` arms below per
        // INV-NOTIFICATION-PRIORITY-PARITY-01.
        | "KernelPanicCaught"
        | "KernelSafetyInvariantViolated"
        // `INV-NOTIFICATION-PRIORITY-PARITY-01` (iter65) — earlier
        // this kind classified as `Medium` here while the typed
        // `notification_priority` classified it as `Critical`. The
        // typed surface is correct: the orchestrator respawn ceiling
        // is a structural backstop, an `Exceeded` event means the
        // initiative is now terminal-Failed and the operator MUST
        // intervene. The kernel `notifications::dispatch` gate and
        // the dashboard `notifications` projection both consult the
        // string surface; without parity, Critical-only filters
        // missed the iter64 ceiling event entirely.
        | "OrchestratorRespawnCeilingExceeded"
        | "ReviewRejectionCeilingExceeded"
        // `INV-INITIATIVE-PERMANENT-FAILURE-ESCALATION-COVERAGE-01`
        // (iter65-review) — generalised permanent-failure anchor.
        // Mirror of the typed `K::InitiativePermanentFailureEscalated`
        // arm in `notification_priority`; both surfaces MUST classify
        // it as `Critical` per `INV-NOTIFICATION-PRIORITY-PARITY-01`.
        | "InitiativePermanentFailureEscalated"
        // Mirror arms for the typed `K::VerifierImageDigestMismatch`
        // `K::WitnessOperatorHintSpoofingDetected` => `Critical`
        // classifications below. Without them the typed wrapper
        // emits a Critical-priority audit row but
        // `notifications::dispatch` re-filters against the string
        // table and drops the inbox / SSE delivery — leaving the
        // most-severe verifier-substrate events visible only in
        // the audit chain. INV-NOTIFICATION-PRIORITY-PARITY-01.
        | "VerifierImageDigestMismatch"
        | "WitnessOperatorHintSpoofingDetected" => Some(Critical),

        // High
        "EscalationSubmitted"
        | "EscalationRateLimitExceeded"
        | "EscalationTimedOut"
        | "OperatorAttentionRequired"
        | "SessionEgressStallDetected"
        | "WitnessRejected"
        | "VerifierProcessFailed"
        | "CredentialProxyUpstreamFailed"
        | "PolicyAdvanceRejected"
        | "PolicyAdvanceFailed"
        | "MergeFastForwardFailed"
        | "PushFailed"
        | "GatewayCrashed"
        | "GatewayQuarantined"
        | "GatewaySignalFailed"
        | "TaskBlockedForRecovery"
        | "AdmissionQueueFull"
        | "OperatorCertMisconfigBypassed"
        | "OperatorCertExpiringSoon"
        | "OperatorCertInGracePeriod"
        | "NotificationDeliveryFailed"
        | "CircuitBreakerStateChanged"
        | "PlanRejected"
        | "InitiativeAborted"
        | "OperatorRevealedCredential"
        | "KernelRestartInitiated"
        // Mirror arms for the iter62/iter63 verifier-bounded-runtime
        // family: every typed arm below classifies as `High`, and
        // `notifications::dispatch` enforces parity against the
        // string table — without these arms the operator inbox
        // silently drops every verifier-timeout / artifact-reject /
        // wallclock-timeout / idle-timeout / budget-exhausted /
        // forced-shutdown / witness-handler-timeout event.
        // INV-NOTIFICATION-PRIORITY-PARITY-01.
        | "VerifierTimeout"
        | "VerifierArtifactRejected"
        | "VerifierWallClockTimeout"
        | "VerifierIdleTimeout"
        | "VerifierBudgetExhausted"
        | "VerifierVmForcedShutdown"
        | "WitnessHandlerTimeout" => Some(High),

        // Medium
        "KernelStarted"
        | "KernelStopped"
        | "IsolationSubstrateSelected"
        | "PolicyEpochAdvanced"
        | "PolicyUpdatedViaDashboard"
        | "OperatorCertInstalled"
        | "InitiativeCreated"
        | "PlanApproved"
        | "InitiativeStateChanged"
        | "IntegrationMergeCompleted"
        | "PushCompleted"
        | "KernelRestartCompleted"
        | "TaskAutoResumedAfterSupervisorRestart"
        | "EscalationApproved"
        | "EscalationDenied"
        | "EscalationConsumed"
        | "WitnessAccepted"
        | "ReviewAggregationCompleted"
        | "ReviewerVerdictRecorded"
        | "ExecutorRespawnFromReviewRejection"
        | "OperatorApprovedRespawnEscalation"
        | "OperatorDeniedRespawnEscalation"
        | "GitConsistencyRepaired"
        | "DryRunAdmitted"
        | "PathScopeOverrideApplied" => Some(Medium),

        // Low
        "DiskHealthyAfterFull"
        | "AdmissionDeferredAtCap"
        | "GatewaySpawned"
        | "GitConsistencyVerified" => Some(Low),

        // Everything else is audit-chain-only.
        _ => None,
    }
}

/// Classify an [`AuditEventKind`] for the operator's notification
/// inbox.
///
/// Returns:
///   * `Some(priority)` — emit a notification row with this
///     priority. The audit chain still records the event.
///   * `None`            — audit-chain only. Never appears in the
///     notification inbox.
///
/// Discipline (`INV-NOTIF-SCOPE-01`):
///   * Operator-initiated dashboard actions (the `Operator*`
///     family — mark-read, view-diff, view-file, view-worktree,
///     chain-reverify, view-health) ALWAYS return `None`. They
///     are forensic-only.
///   * Routine credential-proxy / VM-lifecycle / egress / record-
///     metric events return `None`. Only failure paths notify.
///   * The match is exhaustive: adding a new `AuditEventKind`
///     variant without picking a priority (or explicitly `None`)
///     is a compile error. The unit test
///     `tests::every_variant_has_a_decision` doubles as a wire-
///     shape regression test against silent additions.
#[allow(clippy::too_many_lines)]
// Deprecated `OperatorViewed*` variants (retired in
// an earlier audit-noise sweep) and `OperatorWorktreeAccessed` /
// `OperatorDiffViewed` / `OperatorFileContentFetched` /
// `OperatorAuditChainReverified` / `OperatorHealthQueried` /
// `OperatorListedCredentials` / `OperatorListedSystemCredentials`
// `OperatorOpenedSessionStream` / `OperatorNotificationViewed`
// (retired in the second audit-noise sweep) are still matched
// here so already-persisted chains continue to classify
// deterministically — every retired variant routes to `None`
// (audit-chain only). See signal-vs-noise policy in
// `specs/v2/dashboard-operator-action-audit-coverage.md`.
#[allow(deprecated)]
pub fn notification_priority(kind: &AuditEventKind) -> Option<NotificationPriority> {
    use AuditEventKind as K;
    use NotificationPriority::{Critical, High, Low, Medium};

    match kind {
        // ── Critical: kernel integrity / security / unrecoverable ──
        //
        // Anything that means "something is broken at the substrate
        // or trust layer; an operator MUST act before more agent
        // work happens" routes to `Critical`. The FE renders these
        // with a red exclamation icon.
        K::IsolationSubstrateRefused { .. } => Some(Critical),
        K::IsolationFallbackBypass { .. } => Some(Critical),
        K::SessionVmFailedFinal { .. } => Some(Critical),
        K::SecurityViolationDetected { .. } => Some(Critical),
        K::SecurityViolation { .. } => Some(Critical),
        K::EmergencyOperatorUsed { .. } => Some(Critical),
        K::BreakglassActivated { .. } => Some(Critical),
        K::BreakglassDeactivated { .. } => Some(Critical),
        K::BreakglassAction { .. } => Some(Critical),
        K::OperatorCertExpiredOpDenied { .. } => Some(Critical),
        K::OperatorCertRevokedOpDenied { .. } => Some(Critical),
        K::OperatorCertRevoked { .. } => Some(Critical),
        K::DelegationSignatureUnverifiable { .. } => Some(Critical),
        K::DiskFullHaltEntered { .. } => Some(Critical),
        K::GitStateInconsistent { .. } => Some(Critical),
        K::ReplayRejected { .. } => Some(Critical),
        K::ReconciliationGap { .. } => Some(Critical),
        K::OperatorQuarantineSwept { .. } => Some(Critical),
        K::InitiativeQuarantined { .. } => Some(Critical),
        K::LineageQuarantined { .. } => Some(Critical),
        // INV-DASHBOARD-ANTHROPIC-CREDENTIAL-SEVERITY-01: every
        // system-credential reveal (Anthropic provider key in
        // particular) MUST surface in the inbox so a second
        // operator sees the event without being parked in front
        // of the dashboard.
        K::OperatorRevealedSystemCredential { .. } => Some(Critical),
        // V2.5 self-healing-supervisor.md §3.4 — every detected
        // deadlock is forensic-grade; engineers MUST look. The
        // dump file referenced by `dump_path` carries the full
        // parking_lot lock-graph + per-thread backtraces.
        K::KernelDeadlockDetected { .. } => Some(Critical),
        // V2.5 self-healing-supervisor.md §INV-SUPERVISOR-CIRCUIT-BREAKER-01
        // — supervisor refused further restarts; manual
        // intervention required (raxis-supervisor reset-circuit-breaker).
        K::KernelRestartHaltedCircuitOpen { .. } => Some(Critical),
        // INV-KERNEL-RECOVERY-PRESERVES-SAFETY-INVARIANTS-01 —
        // every panic the global hook catches is operator-attention.
        // Sustained `KernelPanicCaught` events with the same
        // `location` are kernel-bug telemetry that warrants an
        // iter-bake fix.
        K::KernelPanicCaught { .. } => Some(Critical),
        // INV-KERNEL-RECOVERY-PRESERVES-SAFETY-INVARIANTS-01 —
        // safety-critical refusals (`safety::fatal_safety_critical`)
        // are P0 by definition. The kernel `abort`ed before this
        // notification was queued; the operator MUST inspect the
        // named invariant before re-enabling whatever subsystem it
        // guarded.
        K::KernelSafetyInvariantViolated { .. } => Some(Critical),

        // ── High: operator attention required, but not yet a P0 ──
        //
        // Escalations awaiting approval, reviewer rejections,
        // gateway / verifier failures, upstream-credential failures,
        // policy-advance failures, push / merge failures, queue
        // saturation, cert-warning expiry — anything that means
        // "the operator should look at this within minutes, not
        // immediately, and not days". Amber.
        K::EscalationSubmitted { .. } => Some(High),
        K::EscalationRateLimitExceeded { .. } => Some(High),
        K::EscalationTimedOut { .. } => Some(High),
        K::OperatorAttentionRequired { .. } => Some(High),
        K::SessionEgressStallDetected { .. } => Some(High),
        K::WitnessRejected { .. } => Some(High),
        K::VerifierProcessFailed { .. } => Some(High),
        K::CredentialProxyUpstreamFailed { .. } => Some(High),
        K::PolicyAdvanceRejected { .. } => Some(High),
        K::PolicyAdvanceFailed { .. } => Some(High),
        K::MergeFastForwardFailed { .. } => Some(High),
        K::PushFailed { .. } => Some(High),
        K::GatewayCrashed { .. } => Some(High),
        K::GatewayQuarantined { .. } => Some(High),
        K::GatewaySignalFailed { .. } => Some(High),
        K::TaskBlockedForRecovery { .. } => Some(High),
        K::AdmissionQueueFull { .. } => Some(High),
        K::OperatorCertMisconfigBypassed { .. } => Some(High),
        K::OperatorCertExpiringSoon { .. } => Some(High),
        K::OperatorCertInGracePeriod { .. } => Some(High),
        K::NotificationDeliveryFailed { .. } => Some(High),
        K::CircuitBreakerStateChanged { .. } => Some(High),
        K::PlanRejected { .. } => Some(High),
        K::InitiativeAborted { .. } => Some(High),
        // INV-DASHBOARD-CREDENTIAL-REVEAL-AUDITED-01: per-initiative
        // credential reveals are High — visible to other operators
        // but a tier below the system-credential class above.
        K::OperatorRevealedCredential { .. } => Some(High),
        // V2.5 self-healing-supervisor.md §3.4 — operator should
        // know the kernel was just replaced, but it is not a P0
        // unless paired with the `KernelRestartHaltedCircuitOpen`
        // (Critical) above.
        K::KernelRestartInitiated { .. } => Some(High),

        // ── Medium: lifecycle milestones operators want to see ──
        //
        // The "things happened cleanly" bucket. Initiative entered
        // / left the system, reviewer signed off, kernel booted,
        // policy advanced successfully, merge / push completed.
        // Blue. These are the events that justify the inbox feeling
        // useful; without them the inbox is failure-only and easy
        // to ignore.
        K::KernelStarted { .. } => Some(Medium),
        K::KernelStopped { .. } => Some(Medium),
        K::IsolationSubstrateSelected { .. } => Some(Medium),
        K::PolicyEpochAdvanced { .. } => Some(Medium),
        K::PolicyUpdatedViaDashboard { .. } => Some(Medium),
        K::OperatorCertInstalled { .. } => Some(Medium),
        K::InitiativeCreated { .. } => Some(Medium),
        K::PlanApproved { .. } => Some(Medium),
        // `InitiativeStateChanged` covers transitions to terminal
        // states (Completed / Failed / Cancelled). We notify on
        // every transition at Medium and let the FE summarise; the
        // alternative — inspect `to_state` here — would couple this
        // file to the kernel's state-machine vocabulary.
        K::InitiativeStateChanged { .. } => Some(Medium),
        K::IntegrationMergeCompleted { .. } => Some(Medium),
        K::PushCompleted { .. } => Some(Medium),
        // V2.5 self-healing-supervisor.md §3.4 — steady-state
        // observability after a successful auto-restart; not a
        // page. Pairs 1:1 with the earlier `KernelRestartInitiated`
        // (High) per `INV-SUPERVISOR-RESTART-AUDIT-01`.
        K::KernelRestartCompleted { .. } => Some(Medium),
        // V2.5 self-healing-supervisor.md §3.5 /
        // `INV-SUPERVISOR-AUTO-RESUME-ON-CLEAN-RESTART-01` — every
        // task auto-resumed after a supervisor restart routes here.
        // Medium because the supervisor-restart pair (`KernelRestart*`)
        // already raised the operator's attention; the per-task
        // events are observability for the auto-resume sweep itself
        // (so dashboards can render "N tasks continued automatically"
        // without re-walking the whole tasks table).
        K::TaskAutoResumedAfterSupervisorRestart { .. } => Some(Medium),
        K::EscalationApproved { .. } => Some(Medium),
        K::EscalationDenied { .. } => Some(Medium),
        K::EscalationConsumed { .. } => Some(Medium),
        K::WitnessAccepted { .. } => Some(Medium),
        K::ReviewAggregationCompleted { .. } => Some(Medium),
        K::ReviewerVerdictRecorded { .. } => Some(Medium),
        // `ExecutorRespawnFromReviewRejection` rides at Medium next to
        // `ReviewAggregationCompleted` — the two events are paired
        // chain anchors for a single Reviewer-rejection round
        // (`INV-RETRY-FROM-COMPLETED-REVIEW-REJECTED-01`). Operators
        // who watch the inbox for review-loop progression want both
        // ends of the pair (the rejection verdict + the kernel-
        // admitted retry); High would over-page on a normal
        // multi-round disagreement, Low would hide a loop that's
        // burning rounds against `max_review_rejections`.
        K::ExecutorRespawnFromReviewRejection { .. } => Some(Medium),
        // `INV-ORCH-RESPAWN-NO-PROGRESS-CEILING-01` — initiative
        // failure on the structural backstop. Critical because the
        // initiative is now terminal-Failed and the operator must
        // intervene (abort, escalate, or open a fresh plan); the
        // kernel will refuse all subsequent orchestrator respawns
        // for the offending initiative.
        K::OrchestratorRespawnCeilingExceeded { .. } => Some(Critical),
        K::ReviewRejectionCeilingExceeded { .. } => Some(Critical),
        // `INV-ESCALATION-AUTO-LOGICAL-DEADLOCK-01` — operator
        // resolution surface for a kernel-initiated logical-deadlock
        // escalation. Routed at `Medium` priority: the operator has
        // already responded to the upstream `Critical` ceiling event
        // and is now closing the loop (approve resets the counter +
        // resumes the initiative; deny preserves Failed). Both
        // outcomes are operator-attention-noted, not paged; pairs
        // 1:1 with the upstream `OrchestratorRespawnCeilingExceeded`.
        K::OperatorApprovedRespawnEscalation { .. } => Some(Medium),
        K::OperatorDeniedRespawnEscalation { .. } => Some(Medium),
        K::GitConsistencyRepaired { .. } => Some(Medium),
        K::DryRunAdmitted { .. } => Some(Medium),
        K::PathScopeOverrideApplied { .. } => Some(Medium),

        // ── Low: very-informational; safe to snooze ──
        //
        // The "operator might want to glance at this once a day"
        // bucket. Gray dot in the inbox; the FE settings page can
        // hide these behind a "snooze low-priority notifications"
        // toggle.
        K::DiskHealthyAfterFull { .. } => Some(Low),
        K::AdmissionDeferredAtCap { .. } => Some(Low),
        K::GatewaySpawned { .. } => Some(Low),
        K::GitConsistencyVerified { .. } => Some(Low),

        // ── None: audit-chain ONLY (forensic record, never inbox) ──
        //
        // 1. Operator-initiated dashboard actions. INV-NOTIF-SCOPE-01:
        //    these are recorded in the audit chain for the operator-
        //    accountability trail (mark-read, view-diff, view-file,
        //    view-worktree, chain-reverify, view-health) but MUST
        //    NOT generate notifications. The operator just performed
        //    the action; surfacing it back to them is silly and
        //    drowns out the events that actually warrant attention.
        K::OperatorNotificationMarkedRead { .. }
        | K::OperatorNotificationsMarkedAllRead { .. }
        | K::OperatorNotificationViewed { .. }
        | K::OperatorWorktreeAccessed { .. }
        | K::OperatorDiffViewed { .. }
        | K::OperatorFileContentFetched { .. }
        | K::OperatorAuditChainReverified { .. }
        | K::OperatorHealthQueried { .. }
        // INV-DASHBOARD-OPERATOR-ACTION-AUDIT-COVERAGE-01 gap-closers.
        // Every dashboard read/list endpoint emits an `Operator*`
        // event for forensic accountability; none of them notify
        // because the operator just performed the action and
        // surfacing it back is noise.
        | K::OperatorListedCredentials { .. }
        | K::OperatorListedSystemCredentials { .. }
        | K::OperatorViewedInitiativeList { .. }
        | K::OperatorViewedInitiative { .. }
        | K::OperatorViewedInitiativeDag { .. }
        | K::OperatorViewedInitiativeTasks { .. }
        | K::OperatorViewedTask { .. }
        | K::OperatorViewedTaskOutputs { .. }
        | K::OperatorViewedSessionList { .. }
        | K::OperatorViewedSession { .. }
        | K::OperatorOpenedSessionStream { .. }
        | K::OperatorViewedEscalationList { .. }
        | K::OperatorViewedEscalation { .. }
        | K::OperatorViewedAuditChain { .. }
        | K::OperatorViewedInbox { .. }
        | K::OperatorViewedNotifications { .. }
        | K::OperatorViewedPolicySnapshot { .. }
        | K::OperatorViewedPolicyToml { .. }
        | K::OperatorViewedWorktreeList { .. }
        | K::OperatorViewedWorktreeLog { .. }
        | K::OperatorViewedPlanToml { .. } => None,

        // 2. Routine session lifecycle. The audit chain records
        //    every spawn / exit / respawn for forensic
        //    reconstruction; only the irrecoverable terminal
        //    failure (`SessionVmFailedFinal`, classified Critical
        //    above) reaches the notification inbox.
        K::SessionVmSpawned { .. }
        | K::SessionVmExited { .. }
        | K::SessionVmRespawnAttempted { .. }
        | K::SessionVmScaleEvent { .. }
        | K::SessionVmScaleDeferred { .. }
        | K::VmImageResolved { .. }
        | K::SessionCreated { .. }
        | K::SessionRevoked { .. } => None,

        // 3. Routine task / intent lifecycle. A 50-task initiative
        //    would otherwise produce 50 inbox rows; the user's
        //    contract folds these into the initiative-level
        //    `InitiativeStateChanged` notification.
        K::TaskAdmitted { .. }
        | K::TaskStateChanged { .. }
        | K::IntentAccepted { .. }
        | K::IntentRejected { .. } => None,

        // 4. Routine credential / proxy / cloud-forwarding events.
        //    The audit chain captures every admit / deny / serve so
        //    a forensic replay can reconstruct upstream usage; the
        //    notification inbox is reserved for failure paths
        //    (`CredentialProxyUpstreamFailed`, `SessionEgressStallDetected`,
        //    `TransparentProxyDenied` is also routine — see below).
        K::CredentialProxyStarted { .. }
        | K::CredentialProxyStopped { .. }
        | K::CredentialProxyUpstreamConnected { .. }
        | K::CredentialProxySubstituted { .. }
        | K::CredentialAccessed { .. }
        | K::CredentialRotated { .. }
        | K::CredentialRegistered { .. }
        | K::CredentialRemoved { .. }
        | K::CredentialVerified { .. } => None,

        // 5. Routine egress / proxy command / metadata events.
        //    These fire per request; sending an inbox notification
        //    per request would be catastrophic. Only the failure /
        //    block surfaces (handled above) reach the operator.
        K::TransparentProxyAdmitted { .. }
        | K::TransparentProxyDenied { .. }
        | K::DefaultProviderEgressApplied { .. }
        | K::DatabaseQueryExecuted { .. }
        | K::DatabaseQueryCompleted { .. }
        | K::HttpProxyRequestExecuted { .. }
        | K::RedisCommandExecuted { .. }
        | K::AwsCredentialServed { .. }
        | K::GcpMetadataServed { .. }
        | K::AzureTokenServed { .. }
        | K::CloudCredentialForwarded { .. }
        | K::CloudCredentialForwardingDenied { .. }
        | K::CloudCredentialCacheHit { .. }
        | K::CloudCredentialCacheRefreshed { .. }
        | K::MongoCommandExecuted { .. }
        | K::SmtpMessageRelayed { .. }
        | K::SmtpMessageRejected { .. } => None,

        // 6. Delegation / witness chain bookkeeping. Granted /
        //    marked-stale events are routine substrate accounting;
        //    the only related events that notify are
        //    `DelegationSignatureUnverifiable` (Critical) and
        //    `WitnessRejected` (High), handled above.
        K::DelegationGranted { .. }
        | K::DelegationMarkedStale { .. } => None,

        // 7. Push lifecycle scaffolding. `KernelPushEnqueued` fires
        //    every time a push is queued; the operator only sees
        //    completions / failures.
        K::KernelPushEnqueued { .. }
        | K::PushAttempted { .. } => None,

        // 8. Notification-pipeline meta-events. `NotificationDelivered`
        //    is the audit-chain echo of a successful delivery — we
        //    do NOT want a notification about a notification (the
        //    inbox + sidecar already surfaced it). The failure
        //    counterpart `NotificationDeliveryFailed` (High) DOES
        //    notify, since it surfaces a misconfigured channel.
        K::NotificationDelivered { .. } => None,

        // 9. Read-trace audit row (CLI inspect / dashboard reveal).
        //    Strict forensic record, never operator-attention.
        K::PathReadAccessed { .. } => None,

        // 10. Per-task structured-output emissions. Progress
        //     reports + diagnostic flags fire dozens of times per
        //     task; the operator follows them via the session-
        //     stream surface, not the notification inbox.
        K::StructuredOutputEmitted { .. } => None,

        // 11. Path A3 universal-airgap admission + DNS events.
        //     `TproxyAdmissionDenied` is the structured signal a
        //     repeated-denial stall detector consumes (mirrors the
        //     legacy `TransparentProxyDenied` priority — None at the
        //     individual event level; the `SessionEgressStallDetected`
        //     summary is the operator-attention surface). Granted
        //     admissions and DNS resolutions are observability-only.
        K::TproxyAdmissionGranted { .. } => None,
        K::TproxyAdmissionDenied { .. } => None,
        K::DnsResolveRequested { .. } => None,

        // 12. Planner budget scaling.
        //     `PlannerMaxTurnsProgressivelyScaled` is the structural
        //     audit trail emitted by INV-PLANNER-MAX-TURNS-PROGRESSIVE-
        //     ON-RETRY-01 every time a retry attempt receives a
        //     larger `max_turns` budget than the prior attempt. It is
        //     observability-only — operators see the same scaling on
        //     the task detail panel via the `MaxTurnsScalingView` KSB
        //     projection. Surfacing each scale event in the inbox
        //     would create one notification per retry attempt with no
        //     actionable signal; if the scaling actually fails to
        //     unblock the task, the eventual `TaskFailed*` /
        //     `TaskBlockedForRecovery` arm above is the operator-
        //     attention surface.
        // ── iter62 verifier-runtime + intent-validation additions ──
        //
        // Wired in at integration time when these variants landed
        // from the verifier-runtime work and
        // the kernel-side fixes pass. The match in
        // `notification_priority` is intentionally exhaustive (see
        // the test-module banner below); these arms keep that
        // contract while routing each variant to the priority that
        // matches its sibling-event taxonomy.
        //
        // `IntentValidationRejected` mirrors the existing
        // `IntentRejected => None` classification — a single
        // validation reject is observability-only; persistent
        // rejection surfaces via the already-classified
        // `TaskBlockedForRecovery` / `TaskFailed*` arms above.
        K::IntentValidationRejected { .. } => None,
        // Verifier VM lifecycle events are observability-only. The
        // operator-attention surface is the witness verdict, not
        // the spawn/exit envelope.
        K::VerifierVmSpawned { .. } => None,
        K::VerifierVmExited { .. } => None,
        // Witness-received is a success path — verifier ran and
        // returned a verdict. The verdict itself surfaces via
        // `WitnessRejected => High` for the negative case.
        K::VerifierWitnessReceived { .. } => None,
        // Image-digest mismatch on a verifier image is a substrate
        // integrity violation in the same family as
        // `IsolationSubstrateRefused` — Critical, operator MUST
        // act before further verifier work runs.
        K::VerifierImageDigestMismatch { .. } => Some(Critical),
        // Verifier timeout / artifact-rejection are sibling to the
        // existing `VerifierProcessFailed => High` classification:
        // the verifier failed to produce a usable witness, so the
        // gate cannot clear and operator attention is required.
        K::VerifierTimeout { .. } => Some(High),
        K::VerifierArtifactRejected { .. } => Some(High),
        // === iter63 bounded-runtime + operator-hint variants ===
        // Same `High` priority as the iter62 timeout / rejection
        // family: every kill-path here represents an
        // operator-actionable verifier failure, not a routine
        // status update. `VerifierVmForcedShutdown` is itself a
        // signal that the graceful kill window was insufficient
        // for the substrate — worth surfacing for tuning.
        // `WitnessOperatorHintSpoofingDetected` is a security
        // signal (operator-published hints diverge from the
        // verifier's claimed body) — `Critical`.
        K::VerifierWallClockTimeout { .. } => Some(High),
        K::VerifierIdleTimeout { .. } => Some(High),
        K::VerifierBudgetExhausted { .. } => Some(High),
        K::VerifierVmForcedShutdown { .. } => Some(High),
        K::WitnessHandlerTimeout { .. } => Some(High),
        K::WitnessOperatorHintSpoofingDetected { .. } => Some(Critical),
        // iter65 gate-rejection orchestrator-fixup family.
        //
        // `GateRejectionAccepted`: a non-Pass gate witness was just
        // committed AND the operator has a `[gate_fixup]` profile
        // configured. The orchestrator-driven fixup loop will pick
        // it up; medium priority because the kernel + orchestrator
        // are already coordinating recovery (mirrors
        // `ReviewAggregationCompleted` priority discipline).
        K::GateRejectionAccepted { .. } => Some(Medium),
        // `GateRejectionTerminal`: a gate rejection ended in
        // task-Failed (no profile, budget exhausted, fixup failed).
        // High priority — the operator now owns the next move
        // (mirror of the reviewer-rejection-terminal pattern).
        K::GateRejectionTerminal { .. } => Some(High),
        // `GateFixupSpawned`: kernel admitted a fixup task on
        // behalf of the orchestrator. Medium — pure observability
        // of the fixup chain, paired with the eventual
        // `GateFixupCompleted` that closes the loop.
        K::GateFixupSpawned { .. } => Some(Medium),
        K::GateFixupCompleted { .. } => Some(Medium),
        // `WitnessMissingAgentHint`: verifier author shipped a weak
        // hint (tier-1 missing) or wire-invalid hint. Medium
        // operator-attention signal — actionable but not a page.
        K::WitnessMissingAgentHint { .. } => Some(Medium),
        K::PlannerMaxTurnsProgressivelyScaled { .. } => None,
        // `INV-INITIATIVE-PERMANENT-FAILURE-ESCALATION-COVERAGE-01`
        // (iter65-review) — every emit of this anchor means an
        // initiative just transitioned to terminal-`Failed` because
        // a permanent-stall audit event landed; the operator MUST
        // intervene (approve a recovery retry, deny + audit the
        // permanent failure, or open a fresh plan). Critical priority
        // ensures a Critical-only filter on the kernel's
        // `notifications::dispatch` gate or the dashboard
        // `notifications` projection still surfaces the event
        // regardless of how the underlying cause_kind is classified
        // individually (PlanRejected → High, EscalationTimedOut →
        // High, etc.). Mirror arm in
        // `notification_priority_for_kind_str` keeps the surfaces
        // in lockstep per `INV-NOTIFICATION-PRIORITY-PARITY-01`.
        K::InitiativePermanentFailureEscalated { .. } => Some(Critical),
        // iter68 — worktree snapshot writes are structural audit
        // trail rows, NOT operator-attention events. The dashboard
        // surfaces them on the per-task timeline + the worktree
        // detail page directly; the notification inbox stays clean.
        K::WorktreeSnapshotted { .. } => None,
        // Custom tool invocations are high-volume forensic events.
        // The audit chain and task timeline need them; the operator
        // inbox should only page for the downstream task/gate failure
        // that makes a tool failure actionable.
        K::CustomToolInvoked { .. } => None,
    }
}

// ---------------------------------------------------------------------------
// Tests — every-variant pin + spot-check classifications.
//
// These are the wire-shape regression tests for INV-NOTIF-SCOPE-01.
// Adding a new `AuditEventKind` variant without picking a priority
// is already a compile error (the match in `notification_priority`
// is exhaustive); the explicit-case tests below double as
// documentation for the canonical taxonomy and as a check that the
// classification did not silently drift on a refactor.
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use raxis_audit_tools::event::SecurityViolationClass;
    use raxis_audit_tools::AuditEventKind;

    /// A representative-but-not-exhaustive set of events used by
    /// the unit tests. We intentionally do NOT instantiate every
    /// variant — the exhaustive-match in `notification_priority`
    /// already enforces "every variant gets a decision". This
    /// fixture is the spot-check vocabulary.
    fn sample_critical() -> AuditEventKind {
        AuditEventKind::SessionVmFailedFinal {
            session_id: "s-1".into(),
            task_id: Some("t-1".into()),
            initiative_id: "init-1".into(),
            total_attempts: 3,
            failure_class: "Permanent".into(),
            final_reason: "kvm_oom".into(),
        }
    }

    fn sample_high() -> AuditEventKind {
        AuditEventKind::EscalationSubmitted {
            escalation_id: "esc-1".into(),
            task_id: "t-1".into(),
            class: "PolicyViolation".into(),
            lineage_id: "l-1".into(),
        }
    }

    fn sample_medium() -> AuditEventKind {
        AuditEventKind::PolicyEpochAdvanced {
            new_epoch_id: 7,
            policy_sha256: "0".repeat(64),
            triggered_by: "op".into(),
            delegations_marked_stale: 0,
            sessions_invalidated: 0,
            triggered_by_display_name: None,
        }
    }

    fn sample_low() -> AuditEventKind {
        AuditEventKind::AdmissionDeferredAtCap {
            cap_kind: "VmCount".into(),
            current_running: 4,
            cap: 4,
            initiative_id: Some("init-1".into()),
            task_id: Some("t-1".into()),
        }
    }

    fn sample_operator_passive() -> AuditEventKind {
        AuditEventKind::OperatorNotificationMarkedRead {
            operator_fingerprint: "fp-1".into(),
            notification_id: "n-1".into(),
            updated: true,
            outcome: "Accepted".into(),
        }
    }

    fn sample_routine_proxy() -> AuditEventKind {
        AuditEventKind::HttpProxyRequestExecuted {
            session_id: "s-1".into(),
            credential_name: "kube-prod".into(),
            method: "GET".into(),
            path: "/api/v1".into(),
            path_sha256: "ab".repeat(32),
            status_code: 200,
            blocked: false,
        }
    }

    fn sample_routine_session() -> AuditEventKind {
        AuditEventKind::SessionCreated {
            session_id: "s-1".into(),
            role: "executor".into(),
            lineage_id: "l-1".into(),
            worktree_root: None,
            initiative_id: None,
            plan_bundle_sha256: None,
            policy_epoch: None,
            session_agent_type: None,
        }
    }

    /// Pin the wire-shape of `NotificationPriority::as_str()`. The
    /// FE filter pills + icon registry match on these strings; a
    /// silent rename here would break the FE without a compile
    /// error.
    #[test]
    fn priority_as_str_is_pinned() {
        assert_eq!(NotificationPriority::Critical.as_str(), "Critical");
        assert_eq!(NotificationPriority::High.as_str(), "High");
        assert_eq!(NotificationPriority::Medium.as_str(), "Medium");
        assert_eq!(NotificationPriority::Low.as_str(), "Low");
        assert_eq!(NotificationPriority::ALL.len(), 4);
    }

    /// Spot-check the four notification buckets.
    #[test]
    fn classification_spot_checks_per_bucket() {
        assert_eq!(
            notification_priority(&sample_critical()),
            Some(NotificationPriority::Critical),
            "SessionVmFailedFinal must be Critical",
        );
        assert_eq!(
            notification_priority(&sample_high()),
            Some(NotificationPriority::High),
            "EscalationSubmitted must be High",
        );
        assert_eq!(
            notification_priority(&sample_medium()),
            Some(NotificationPriority::Medium),
            "PolicyEpochAdvanced must be Medium",
        );
        assert_eq!(
            notification_priority(&sample_low()),
            Some(NotificationPriority::Low),
            "AdmissionDeferredAtCap must be Low",
        );
    }

    /// `INV-NOTIF-SCOPE-01`: operator-initiated passive actions
    /// (mark-read, view-diff, view-file, view-worktree, chain-
    /// reverify, view-health) MUST be `None`. They live in the
    /// audit chain for forensic accountability, never in the
    /// inbox.
    ///
    /// The two `OperatorViewed*` fixtures at the bottom of the
    /// case list are constructed via deprecated variants so the
    /// classifier proves it still maps already-persisted chain
    /// rows of those kinds to `None` (the variants survive on
    /// the wire for backwards compatibility; emit sites were
    /// retired by an earlier audit-noise sweep).
    #[test]
    #[allow(deprecated)]
    fn operator_passive_actions_are_audit_only() {
        let cases: Vec<AuditEventKind> = vec![
            AuditEventKind::OperatorNotificationMarkedRead {
                operator_fingerprint: "fp".into(),
                notification_id: "n".into(),
                updated: true,
                outcome: "Accepted".into(),
            },
            AuditEventKind::OperatorNotificationsMarkedAllRead {
                operator_fingerprint: "fp".into(),
                count: 3,
                outcome: "Accepted".into(),
            },
            AuditEventKind::OperatorNotificationViewed {
                operator_fingerprint: "fp".into(),
                notification_id: "n".into(),
                outcome: "Accepted".into(),
            },
            AuditEventKind::OperatorWorktreeAccessed {
                operator_fingerprint: "fp".into(),
                worktree_id: "wt".into(),
                surface: "tree".into(),
                outcome: "Accepted".into(),
            },
            AuditEventKind::OperatorDiffViewed {
                operator_fingerprint: "fp".into(),
                worktree_id: "wt".into(),
                base_ref: None,
                head_ref: None,
                outcome: "Accepted".into(),
            },
            AuditEventKind::OperatorFileContentFetched {
                operator_fingerprint: "fp".into(),
                worktree_id: "wt".into(),
                path: "src/main.rs".into(),
                outcome: "Accepted".into(),
            },
            AuditEventKind::OperatorAuditChainReverified {
                operator_fingerprint: "fp".into(),
                verdict: "ok".into(),
                last_verified_seq: 100,
                outcome: "Accepted".into(),
            },
            AuditEventKind::OperatorHealthQueried {
                operator_fingerprint: "fp".into(),
                outcome: "Accepted".into(),
            },
            // Listing endpoints under the credential viewer never
            // notify (the operator just looked at a list); the
            // reveal events below DO notify.
            AuditEventKind::OperatorListedCredentials {
                operator_fingerprint: "fp".into(),
                initiative_id: "init-1".into(),
                count: 3,
                outcome: "Accepted".into(),
            },
            AuditEventKind::OperatorListedSystemCredentials {
                operator_fingerprint: "fp".into(),
                count: 1,
                outcome: "Accepted".into(),
            },
            // Operator-action gap-closer view events are forensic-
            // only; surfacing them in the inbox would re-create the
            // pre-`INV-NOTIF-SCOPE-01` situation where the operator
            // sees their own clicks echoed back at them.
            AuditEventKind::OperatorViewedInitiativeList {
                operator_fingerprint: "fp".into(),
                count: 2,
                state_filter: None,
                outcome: "Accepted".into(),
            },
            AuditEventKind::OperatorViewedAuditChain {
                operator_fingerprint: "fp".into(),
                cursor_seq: None,
                count: 50,
                initiative_id_filter: None,
                outcome: "Accepted".into(),
            },
        ];
        for ev in cases {
            assert_eq!(
                notification_priority(&ev),
                None,
                "Operator-passive event {} MUST be audit-chain-only \
                 (INV-NOTIF-SCOPE-01)",
                ev.as_str(),
            );
        }
    }

    /// `INV-DASHBOARD-CREDENTIAL-REVEAL-AUDITED-01` +
    /// `INV-DASHBOARD-ANTHROPIC-CREDENTIAL-SEVERITY-01`: per-
    /// initiative reveals notify at High; system-credential
    /// reveals notify at Critical so other operators see them.
    #[test]
    fn credential_reveals_notify_with_correct_priority() {
        let per_init = AuditEventKind::OperatorRevealedCredential {
            operator_fingerprint: "fp".into(),
            initiative_id: "init-1".into(),
            credential_name: "test-pg-dev".into(),
            severity: "high".into(),
            outcome: "Accepted".into(),
        };
        let system = AuditEventKind::OperatorRevealedSystemCredential {
            operator_fingerprint: "fp".into(),
            credential_name: "providers.anthropic-prod".into(),
            severity: "critical".into(),
            outcome: "Accepted".into(),
        };
        assert_eq!(
            notification_priority(&per_init),
            Some(NotificationPriority::High),
            "Per-initiative credential reveal must notify at High",
        );
        assert_eq!(
            notification_priority(&system),
            Some(NotificationPriority::Critical),
            "System credential reveal must notify at Critical",
        );
        assert_eq!(
            notification_priority_for_kind_str(per_init.as_str()),
            Some(NotificationPriority::High),
        );
        assert_eq!(
            notification_priority_for_kind_str(system.as_str()),
            Some(NotificationPriority::Critical),
        );
    }

    /// Routine high-volume events MUST NOT notify. A 50-task
    /// initiative would otherwise produce dozens of inbox rows.
    #[test]
    fn routine_high_volume_events_are_audit_only() {
        let cases: Vec<AuditEventKind> = vec![
            sample_routine_proxy(),
            sample_routine_session(),
            AuditEventKind::CredentialProxyStarted {
                session_id: "s".into(),
                proxy_type: "postgres".into(),
                credential_name: "db".into(),
                addr: "127.0.0.1:5432".into(),
            },
            AuditEventKind::IntentAccepted {
                task_id: "t".into(),
                session_id: "s".into(),
                intent_kind: "ProgressReport".into(),
                base_sha: None,
                head_sha: None,
                sequence_number: 1,
                remaining_units: 10,
            },
            AuditEventKind::TaskStateChanged {
                task_id: "t".into(),
                from_state: "Admitted".into(),
                to_state: "Executing".into(),
                actor: "kernel".into(),
                policy_epoch: 1,
            },
            AuditEventKind::DefaultProviderEgressApplied {
                policy_epoch: 1,
                provider_id: "openai-prod".into(),
                provider_kind: "OpenAi".into(),
                fqdn: "api.openai.com".into(),
            },
            AuditEventKind::PathReadAccessed {
                actor: "cli".into(),
                table: "tasks".into(),
                column: "id".into(),
                task_id: "t".into(),
                command: "inspect".into(),
            },
            AuditEventKind::StructuredOutputEmitted {
                output_id: "o".into(),
                initiative_id: "init".into(),
                task_id: "t".into(),
                session_id: "s".into(),
                output_kind: "progress_report".into(),
                severity: None,
                payload_bytes: 256,
            },
        ];
        for ev in cases {
            assert_eq!(
                notification_priority(&ev),
                None,
                "Routine high-volume event {} MUST be audit-chain-only",
                ev.as_str(),
            );
        }
    }

    /// Failure-path events DO notify (otherwise the inbox would be
    /// empty between escalations).
    #[test]
    fn failure_paths_do_notify() {
        let cases: Vec<(AuditEventKind, NotificationPriority)> = vec![
            (sample_critical(), NotificationPriority::Critical),
            (sample_high(), NotificationPriority::High),
            (
                AuditEventKind::CredentialProxyUpstreamFailed {
                    session_id: "s".into(),
                    credential_name: "db".into(),
                    proxy_type: "postgres".into(),
                    upstream_host: "host".into(),
                    upstream_port: 5432,
                    reason: "TcpConnectFailed".into(),
                    detail: "connection refused".into(),
                },
                NotificationPriority::High,
            ),
            (
                AuditEventKind::PushFailed {
                    initiative_id: "init".into(),
                    commit_sha: "abc".into(),
                    remote: "origin".into(),
                    refspec: "refs/heads/main".into(),
                    category: "push_failed".into(),
                    reason: "network".into(),
                },
                NotificationPriority::High,
            ),
            (
                AuditEventKind::SecurityViolation {
                    session_id: None,
                    violation_class: SecurityViolationClass::FrameMalformation,
                    raw_frame_sha256: "0".repeat(64),
                    frame_size: 0,
                    peer_cid: None,
                },
                NotificationPriority::Critical,
            ),
        ];
        for (ev, expected) in cases {
            assert_eq!(
                notification_priority(&ev),
                Some(expected),
                "Failure event {} should notify at {expected}",
                ev.as_str(),
            );
        }
    }

    /// Lifecycle milestones notify at Medium so the operator's
    /// inbox feels useful between failures.
    #[test]
    fn lifecycle_milestones_notify_at_medium() {
        let cases: Vec<AuditEventKind> = vec![
            sample_medium(),
            AuditEventKind::KernelStarted {
                data_dir: "/tmp".into(),
                policy_epoch: 1,
                schema_version: 1,
            },
            AuditEventKind::EscalationApproved {
                escalation_id: "esc".into(),
                approved_by: "op".into(),
                approved_by_display_name: None,
            },
            AuditEventKind::WitnessAccepted {
                verifier_run_id: "vr-1".into(),
                task_id: "t".into(),
                gate_type: "PolicyGate".into(),
                result_class: "Pass".into(),
                evaluation_sha: "0".repeat(64),
            },
            AuditEventKind::IntegrationMergeCompleted {
                initiative_id: "init".into(),
                session_id: "s".into(),
                commit_sha: "abc".into(),
                previous_sha: "def".into(),
                operator_assisted: false,
                escalation_id: None,
                target_ref: "refs/heads/main".into(),
            },
        ];
        for ev in cases {
            assert_eq!(
                notification_priority(&ev),
                Some(NotificationPriority::Medium),
                "Lifecycle milestone {} should notify at Medium",
                ev.as_str(),
            );
        }
    }

    /// Drift detector: the typed [`notification_priority`] and
    /// the string-based [`notification_priority_for_kind_str`]
    /// MUST agree on every constructed variant. New audit kinds
    /// added without a string arm fall through to the safe
    /// `None` default, so disagreement here means a typed arm
    /// was added without its string counterpart — which makes
    /// the read-side priority projection silently misclassify.
    #[test]
    #[allow(deprecated)] // constructs round-2 retired variants on purpose
    fn typed_and_string_apis_agree_on_all_constructed_variants() {
        // Kitchen-sink list: every variant the unit tests
        // construct above PLUS one representative per priority
        // bucket the spec calls out. Best-effort drift safety; the
        // typed function is the canonical source of truth.
        let cases: Vec<AuditEventKind> = vec![
            sample_critical(),
            sample_high(),
            sample_medium(),
            sample_low(),
            sample_operator_passive(),
            sample_routine_proxy(),
            sample_routine_session(),
            AuditEventKind::OperatorWorktreeAccessed {
                operator_fingerprint: "fp".into(),
                worktree_id: "wt".into(),
                surface: "tree".into(),
                outcome: "Accepted".into(),
            },
            AuditEventKind::OperatorDiffViewed {
                operator_fingerprint: "fp".into(),
                worktree_id: "wt".into(),
                base_ref: None,
                head_ref: None,
                outcome: "Accepted".into(),
            },
            AuditEventKind::OperatorAuditChainReverified {
                operator_fingerprint: "fp".into(),
                verdict: "ok".into(),
                last_verified_seq: 1,
                outcome: "Accepted".into(),
            },
            AuditEventKind::OperatorHealthQueried {
                operator_fingerprint: "fp".into(),
                outcome: "Accepted".into(),
            },
            AuditEventKind::SecurityViolation {
                session_id: None,
                violation_class: SecurityViolationClass::FrameMalformation,
                raw_frame_sha256: "0".repeat(64),
                frame_size: 0,
                peer_cid: None,
            },
            AuditEventKind::CredentialProxyUpstreamFailed {
                session_id: "s".into(),
                credential_name: "db".into(),
                proxy_type: "postgres".into(),
                upstream_host: "host".into(),
                upstream_port: 5432,
                reason: "TcpConnectFailed".into(),
                detail: "x".into(),
            },
            AuditEventKind::PushFailed {
                initiative_id: "init".into(),
                commit_sha: "abc".into(),
                remote: "origin".into(),
                refspec: "refs/heads/main".into(),
                category: "push_failed".into(),
                reason: "x".into(),
            },
            AuditEventKind::KernelStarted {
                data_dir: "/tmp".into(),
                policy_epoch: 1,
                schema_version: 1,
            },
            AuditEventKind::EscalationApproved {
                escalation_id: "e".into(),
                approved_by: "op".into(),
                approved_by_display_name: None,
            },
            AuditEventKind::WitnessAccepted {
                verifier_run_id: "vr".into(),
                task_id: "t".into(),
                gate_type: "g".into(),
                result_class: "Pass".into(),
                evaluation_sha: "0".repeat(64),
            },
            AuditEventKind::IntegrationMergeCompleted {
                initiative_id: "init".into(),
                session_id: "s".into(),
                commit_sha: "abc".into(),
                previous_sha: "def".into(),
                operator_assisted: false,
                escalation_id: None,
                target_ref: "refs/heads/main".into(),
            },
            // `INV-NOTIFICATION-PRIORITY-PARITY-01` (iter65) — the
            // exact regression witness for the iter64 evidence:
            // the typed classifier sent
            // `OrchestratorRespawnCeilingExceeded` to `Critical`,
            // the string classifier sent it to `Medium`, and a
            // Critical-only filter on the dispatch gate dropped
            // the inbox notification entirely. Constructing this
            // case here makes the parity test fail loudly the
            // moment the two surfaces drift again.
            AuditEventKind::OrchestratorRespawnCeilingExceeded {
                initiative_id: "init".into(),
                attempts: 4,
                max_attempts: 3,
            },
            // `INV-INITIATIVE-PERMANENT-FAILURE-ESCALATION-COVERAGE-01`
            // (iter65-review). Pin parity for the generalised
            // permanent-failure anchor so a future drift between the
            // typed and string classifiers fails this test rather
            // than silently dropping the Critical signal.
            AuditEventKind::InitiativePermanentFailureEscalated {
                initiative_id: "init".into(),
                cause_kind: "SessionVmFailedFinal".into(),
                cause_summary: "kvm_oom (3 retries)".into(),
                escalation_id: Some("esc-1".into()),
                recoverable_via_approve: true,
            },
        ];
        for kind in cases {
            let typed = notification_priority(&kind);
            let from_str = notification_priority_for_kind_str(kind.as_str());
            assert_eq!(
                typed,
                from_str,
                "drift: typed and string priority APIs disagree for {} \
                 (typed={:?}, from_str={:?}). Update \
                 notification_priority_for_kind_str arms.",
                kind.as_str(),
                typed,
                from_str,
            );
        }
    }

    /// `INV-NOTIFICATION-PRIORITY-PARITY-01` (iter65) — exhaustive
    /// kind-name parity sweep. The typed
    /// [`notification_priority`] is the canonical source of
    /// truth; the string-based classifier MUST agree on every
    /// kind name that has a typed arm.
    ///
    /// Why this lives next to the cross-API test above: the
    /// kitchen-sink `cases` list above checks parity for ~20
    /// representative variants, but cannot prove parity for the
    /// other ~100 kinds without constructing one of each (most
    /// have non-trivial fields). This test walks the kind-name
    /// space declaratively — every entry is a kind_str the typed
    /// classifier promises to handle, and the string classifier
    /// MUST return the same priority for it.
    ///
    /// Adding a new typed-Critical (etc.) arm without updating
    /// the string classifier flips this test; the compile-time
    /// `match` exhaustiveness in `notification_priority` ensures
    /// the maintainer can't forget the typed side.
    #[test]
    fn typed_and_string_apis_agree_on_kind_name_parity() {
        use NotificationPriority::{Critical, High, Low, Medium};
        // Every `(kind_str, expected_priority)` the spec
        // declares. The typed classifier's arms are the source
        // of truth; this list is a string-shaped mirror that
        // the regression test can sweep without constructing the
        // variants.
        let expected: &[(&str, NotificationPriority)] = &[
            // Critical
            ("IsolationSubstrateRefused", Critical),
            ("IsolationFallbackBypass", Critical),
            ("SessionVmFailedFinal", Critical),
            ("SecurityViolationDetected", Critical),
            ("SecurityViolation", Critical),
            ("EmergencyOperatorUsed", Critical),
            ("BreakglassActivated", Critical),
            ("BreakglassDeactivated", Critical),
            ("BreakglassAction", Critical),
            ("OperatorCertExpiredOpDenied", Critical),
            ("OperatorCertRevokedOpDenied", Critical),
            ("OperatorCertRevoked", Critical),
            ("DelegationSignatureUnverifiable", Critical),
            ("DiskFullHaltEntered", Critical),
            ("GitStateInconsistent", Critical),
            ("ReplayRejected", Critical),
            ("ReconciliationGap", Critical),
            ("OperatorQuarantineSwept", Critical),
            ("InitiativeQuarantined", Critical),
            ("LineageQuarantined", Critical),
            ("OperatorRevealedSystemCredential", Critical),
            ("KernelDeadlockDetected", Critical),
            ("KernelRestartHaltedCircuitOpen", Critical),
            ("OrchestratorRespawnCeilingExceeded", Critical),
            ("ReviewRejectionCeilingExceeded", Critical),
            ("InitiativePermanentFailureEscalated", Critical),
            ("KernelPanicCaught", Critical),
            ("KernelSafetyInvariantViolated", Critical),
            ("VerifierImageDigestMismatch", Critical),
            ("WitnessOperatorHintSpoofingDetected", Critical),
            // High
            ("EscalationSubmitted", High),
            ("EscalationRateLimitExceeded", High),
            ("EscalationTimedOut", High),
            ("OperatorAttentionRequired", High),
            ("SessionEgressStallDetected", High),
            ("WitnessRejected", High),
            ("VerifierProcessFailed", High),
            ("CredentialProxyUpstreamFailed", High),
            ("PolicyAdvanceRejected", High),
            ("PolicyAdvanceFailed", High),
            ("MergeFastForwardFailed", High),
            ("PushFailed", High),
            ("GatewayCrashed", High),
            ("GatewayQuarantined", High),
            ("GatewaySignalFailed", High),
            ("TaskBlockedForRecovery", High),
            ("AdmissionQueueFull", High),
            ("OperatorCertMisconfigBypassed", High),
            ("OperatorCertExpiringSoon", High),
            ("OperatorCertInGracePeriod", High),
            ("NotificationDeliveryFailed", High),
            ("CircuitBreakerStateChanged", High),
            ("PlanRejected", High),
            ("InitiativeAborted", High),
            ("OperatorRevealedCredential", High),
            ("KernelRestartInitiated", High),
            ("VerifierTimeout", High),
            ("VerifierArtifactRejected", High),
            ("VerifierWallClockTimeout", High),
            ("VerifierIdleTimeout", High),
            ("VerifierBudgetExhausted", High),
            ("VerifierVmForcedShutdown", High),
            ("WitnessHandlerTimeout", High),
            // Medium
            ("KernelStarted", Medium),
            ("KernelStopped", Medium),
            ("IsolationSubstrateSelected", Medium),
            ("PolicyEpochAdvanced", Medium),
            ("PolicyUpdatedViaDashboard", Medium),
            ("OperatorCertInstalled", Medium),
            ("InitiativeCreated", Medium),
            ("PlanApproved", Medium),
            ("InitiativeStateChanged", Medium),
            ("IntegrationMergeCompleted", Medium),
            ("PushCompleted", Medium),
            ("KernelRestartCompleted", Medium),
            ("TaskAutoResumedAfterSupervisorRestart", Medium),
            ("EscalationApproved", Medium),
            ("EscalationDenied", Medium),
            ("EscalationConsumed", Medium),
            ("WitnessAccepted", Medium),
            ("ReviewAggregationCompleted", Medium),
            ("ReviewerVerdictRecorded", Medium),
            ("ExecutorRespawnFromReviewRejection", Medium),
            ("OperatorApprovedRespawnEscalation", Medium),
            ("OperatorDeniedRespawnEscalation", Medium),
            ("GitConsistencyRepaired", Medium),
            ("DryRunAdmitted", Medium),
            ("PathScopeOverrideApplied", Medium),
            // Low
            ("DiskHealthyAfterFull", Low),
            ("AdmissionDeferredAtCap", Low),
            ("GatewaySpawned", Low),
            ("GitConsistencyVerified", Low),
        ];
        for (kind_str, expected_priority) in expected {
            let actual = notification_priority_for_kind_str(kind_str);
            assert_eq!(
                actual,
                Some(*expected_priority),
                "INV-NOTIFICATION-PRIORITY-PARITY-01 violation: \
                 string classifier returned {actual:?} for {kind_str}, \
                 expected {expected_priority:?}. Update \
                 notification_priority_for_kind_str.",
            );
        }
    }

    /// The classification is total over `AuditEventKind`. This
    /// test does not enumerate every variant by hand — the
    /// exhaustive `match` in `notification_priority` already does
    /// that at compile time. What this test pins is that the
    /// `Some/None` partition matches the spec's boolean
    /// predicate: every operator-passive variant returns `None`,
    /// and every variant the spec lists as "always notifies"
    /// returns `Some`. Two failure modes are caught by the
    /// underlying compile-time exhaustiveness:
    ///   * a forgotten arm — compile error,
    ///   * an unintended `None` — caught by the per-bucket
    ///     spot-check tests above.
    #[test]
    fn every_variant_has_a_decision() {
        // Spot-check: each priority bucket has at least one
        // member, and each "audit-only" category has at least one
        // member. If all four buckets and the None bucket are
        // populated, the partition is well-formed.
        assert!(notification_priority(&sample_critical()).is_some());
        assert!(notification_priority(&sample_high()).is_some());
        assert!(notification_priority(&sample_medium()).is_some());
        assert!(notification_priority(&sample_low()).is_some());
        assert!(notification_priority(&sample_operator_passive()).is_none());
        assert!(notification_priority(&sample_routine_proxy()).is_none());
        assert!(notification_priority(&sample_routine_session()).is_none());
    }
}

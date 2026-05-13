//! Closed enumerations for span / metric / event names plus the
//! attribute-value shape every emit site uses.
//!
//! Spec: `v3/otel-observability.md §6`.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// AttrValue — closed shape of every attribute value
// ---------------------------------------------------------------------------

/// Closed-shape attribute value. The redactor only accepts these
/// concrete shapes; anything else is a compile-time impossibility.
///
/// In particular there is NO `Bytes` variant (would invite raw blob
/// leakage) and NO `Json` variant (would invite open-ended payload
/// leakage). Each variant has bounded size:
///
/// * `Str` — UTF-8 string. The redactor caps and sanitises every
///   string per the per-key `max_bytes` budget in
///   [`crate::redact::ATTR_ALLOW_LIST`].
/// * `I64` — covers durations in milliseconds, byte counts up to
///   8 EiB, sequence numbers, etc.
/// * `F64` — covers histogram sums and ratio values. NaN / ±Inf
///   are rejected by the redactor at sanitise time.
/// * `Bool` — flags such as `cached`, `circuit_open`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AttrValue {
    /// UTF-8 string; the redactor enforces the per-key length cap
    /// and replaces unprintable / control chars with `?`.
    Str(String),
    /// Signed 64-bit integer.
    I64(i64),
    /// 64-bit float. NaN / ±Inf rejected.
    F64(f64),
    /// Boolean flag.
    Bool(bool),
}

impl From<&str> for AttrValue {
    fn from(s: &str) -> Self { Self::Str(s.to_owned()) }
}
impl From<String> for AttrValue {
    fn from(s: String) -> Self { Self::Str(s) }
}
impl From<i64> for AttrValue {
    fn from(v: i64) -> Self { Self::I64(v) }
}
impl From<u64> for AttrValue {
    fn from(v: u64) -> Self { Self::I64(v as i64) }
}
impl From<u32> for AttrValue {
    fn from(v: u32) -> Self { Self::I64(v as i64) }
}
impl From<i32> for AttrValue {
    fn from(v: i32) -> Self { Self::I64(v as i64) }
}
impl From<usize> for AttrValue {
    fn from(v: usize) -> Self { Self::I64(v as i64) }
}
impl From<f64> for AttrValue {
    fn from(v: f64) -> Self { Self::F64(v) }
}
impl From<bool> for AttrValue {
    fn from(v: bool) -> Self { Self::Bool(v) }
}

/// Sorted attribute map. We use [`BTreeMap`] (not `HashMap`) so the
/// JSONL frame is byte-deterministic for a given input — useful for
/// snapshot tests.
pub type AttrMap = BTreeMap<String, AttrValue>;

// ---------------------------------------------------------------------------
// SpanName — closed list of authority-side span names
// ---------------------------------------------------------------------------

/// Closed enumeration of every authority-side span the kernel ever
/// emits. Adding a variant is a spec change reviewed against
/// `v3/otel-observability.md §7.1`. The `as_otel_name` projection
/// produces the canonical OTel span name (`raxis.<area>.<verb>`)
/// that the pusher sends on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SpanName {
    /// `raxis.intent.admission` — root span for one intent-handler call.
    IntentAdmission,
    /// `raxis.gateway.fetch` — outbound provider round-trip.
    GatewayFetch,
    /// `raxis.verifier.execution` — verifier-process wall-clock.
    VerifierExecution,
    /// `raxis.credential_proxy.request` — proxied per-request work.
    CredentialProxyRequest,
    /// `raxis.notification.dispatch` — operator-channel delivery.
    NotificationDispatch,
    /// `raxis.operator.ipc` — operator IPC command handling.
    OperatorIpc,
    /// `raxis.escalation.lifecycle` — escalation FSM transition.
    EscalationLifecycle,
    /// `raxis.session.spawn` — session VM spawn end-to-end.
    SessionSpawn,
    /// `raxis.policy.epoch.advance` — policy rotation.
    PolicyEpochAdvance,
    /// `raxis.audit.emit` — single audit chain append (debug only by default).
    AuditEmit,
    /// `raxis.breakglass.activation` — operator break-glass activation.
    BreakglassActivation,
    /// `raxis.breakglass.action` — single bypassed evaluation under break-glass.
    BreakglassAction,
}

impl SpanName {
    /// OTel-canonical name this span ships under.
    pub fn as_otel_name(&self) -> &'static str {
        match self {
            Self::IntentAdmission         => "raxis.intent.admission",
            Self::GatewayFetch            => "raxis.gateway.fetch",
            Self::VerifierExecution       => "raxis.verifier.execution",
            Self::CredentialProxyRequest  => "raxis.credential_proxy.request",
            Self::NotificationDispatch    => "raxis.notification.dispatch",
            Self::OperatorIpc             => "raxis.operator.ipc",
            Self::EscalationLifecycle     => "raxis.escalation.lifecycle",
            Self::SessionSpawn            => "raxis.session.spawn",
            Self::PolicyEpochAdvance      => "raxis.policy.epoch.advance",
            Self::AuditEmit               => "raxis.audit.emit",
            Self::BreakglassActivation    => "raxis.breakglass.activation",
            Self::BreakglassAction        => "raxis.breakglass.action",
        }
    }
}

// ---------------------------------------------------------------------------
// SpanKind / SpanStatus / SpanEvent / SpanData
// ---------------------------------------------------------------------------

/// OTel-aligned span kind. Authority-side spans are mostly `Internal`
/// (kernel work) or `Client` (gateway/notification outbound). `Server`
/// is reserved for the operator IPC inbound. `Producer` / `Consumer`
/// are unused in V3.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpanKind {
    /// Kernel-internal work (no remote peer).
    Internal,
    /// Inbound IPC from the operator CLI / dashboard.
    Server,
    /// Outbound to a provider / sidecar / external endpoint.
    Client,
    /// (Reserved.)
    Producer,
    /// (Reserved.)
    Consumer,
}

/// Pass / fail status. `Error` is reserved for kernel-internal
/// failures (verifier spawn fail, gateway TCP error, etc.) — NOT for
/// "intent rejected" or "claim insufficient" outcomes, which are
/// recorded as `Ok` with a `verdict` attribute.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpanStatus {
    /// Span completed normally (regardless of business-level outcome).
    Ok,
    /// Span failed due to a kernel-internal fault. The
    /// `status_message` SHOULD describe the fault; see redactor
    /// rules in `crate::redact`.
    Error,
}

/// Closed enumeration of within-span timeline annotations.
/// New variants require a spec change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EventName {
    /// Step-2 result of `evaluate_claims` — required claim list resolved.
    GateRequired,
    /// One required claim satisfied by an existing witness record.
    GateSatisfied,
    /// One required claim unsatisfied; verifier spawned.
    GateMissing,
    /// Verifier process spawned for a missing gate.
    VerifierSpawned,
    /// Lane budget reservation taken inside intent admission.
    BudgetReserved,
    /// Lane budget reservation released on terminal transition.
    BudgetReleased,
    /// Provider returned token usage on the inference response.
    InferenceTokensReported,
    /// Circuit breaker opened for a provider after consecutive failures.
    CircuitOpened,
    /// Circuit breaker returned to closed after a successful probe.
    CircuitClosed,
    /// Periodic heartbeat tick within a long-running span.
    HeartbeatTick,
}

/// One within-span event, e.g. "verifier spawned at relative t=12ms".
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SpanEvent {
    /// Closed-list event name.
    pub name:        EventName,
    /// Wallclock at event time; nanoseconds since UNIX epoch.
    pub unix_nanos:  u64,
    /// Closed-allow-list attribute map.
    #[serde(default)]
    pub attrs:       AttrMap,
}

/// One completed authority-side span. Pure data; no I/O; no time
/// retrieval. Constructed by [`crate::hub::ObservabilityHub::start_span`]
/// and finalised when [`crate::hub::RecordingSpan::end`] is called.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SpanData {
    /// 16-byte trace identifier. Zero is reserved (means "unset").
    pub trace_id:        [u8; 16],
    /// 8-byte span identifier within the trace. Zero is reserved.
    pub span_id:         [u8; 8],
    /// Optional parent span; `None` for trace roots.
    pub parent_span_id:  Option<[u8; 8]>,
    /// Closed-list span name; emitted as the OTel canonical name on the wire.
    pub name:            SpanName,
    /// OTel kind. Mostly `Internal` and `Client` on the authority side.
    pub kind:            SpanKind,
    /// Wallclock at span start; ns since UNIX epoch.
    pub start_unix_nanos: u64,
    /// Wallclock at span end; ns since UNIX epoch. Always ≥ start.
    pub end_unix_nanos:  u64,
    /// Pass / fail status. See [`SpanStatus`] semantics.
    pub status:          SpanStatus,
    /// Optional one-line human-readable status message; the redactor
    /// caps it at 256 bytes.
    pub status_message:  Option<String>,
    /// Closed-allow-list attribute map (sorted by key).
    pub attrs:           AttrMap,
    /// Optional within-span events; bounded by hub config.
    #[serde(default)]
    pub events:          Vec<SpanEvent>,
}

impl SpanData {
    /// Convenience: span duration in milliseconds, integer-rounded.
    pub fn duration_ms(&self) -> i64 {
        let ns_diff = self.end_unix_nanos.saturating_sub(self.start_unix_nanos);
        (ns_diff / 1_000_000) as i64
    }
}

// ---------------------------------------------------------------------------
// MetricName / MetricType / Unit / DataPoint / MetricData
// ---------------------------------------------------------------------------

/// Closed enumeration of every authority-side metric.
/// Spec: `v3/otel-observability.md §8`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MetricName {
    /// `raxis.intent.admission.duration` — Histogram (ms).
    IntentAdmissionDuration,
    /// `raxis.intent.admission.total` — Counter.
    IntentAdmissionTotal,
    /// `raxis.gateway.fetch.duration` — Histogram (ms).
    GatewayFetchDuration,
    /// `raxis.gateway.fetch.total` — Counter.
    GatewayFetchTotal,
    /// `raxis.verifier.execution.duration` — Histogram (ms).
    VerifierExecutionDuration,
    /// `raxis.verifier.execution.total` — Counter.
    VerifierExecutionTotal,
    /// `raxis.tokens.consumed` — Counter (tokens).
    TokensConsumed,
    /// `raxis.circuit_breaker.state` — Gauge (1/0 per state label).
    CircuitBreakerState,
    /// `raxis.credential_proxy.request.duration` — Histogram (ms).
    CredentialProxyRequestDuration,
    /// `raxis.notification.delivery.duration` — Histogram (ms).
    NotificationDeliveryDuration,
    /// `raxis.notification.delivery.total` — Counter.
    NotificationDeliveryTotal,
    /// `raxis.session.active` — Gauge (current count).
    SessionsActive,
    /// `raxis.audit.chain.length` — Gauge (highest seq).
    AuditChainLength,
    /// `raxis.escalation.open` — Gauge.
    EscalationsOpen,
    /// `raxis.escalation.closed.total` — Counter.
    EscalationsClosedTotal,
    /// `raxis.budget.reserved` — Gauge per-lane.
    BudgetReserved,
    /// `raxis.budget.exceeded.total` — Counter per-lane.
    BudgetExceededTotal,
    /// `raxis.observability.dropped.total` — Counter (per drop reason).
    ObservabilityDroppedTotal,

    // ---------- V3 perf-telemetry expansion ----------
    // (specs/v3/observability-prometheus.md §3)

    // ── Isolation / VM lifecycle ────────────────────────────────────
    /// `raxis.isolation.spawn.cold_boot.duration` — Histogram (ms).
    IsolationSpawnColdBootDuration,
    /// `raxis.isolation.spawn.host_init.duration` — Histogram (ms).
    IsolationSpawnHostInitDuration,
    /// `raxis.isolation.spawn.guest_init.duration` — Histogram (ms).
    IsolationSpawnGuestInitDuration,
    /// `raxis.isolation.spawn.vsock_handshake.duration` — Histogram (ms).
    IsolationSpawnVsockHandshakeDuration,
    /// `raxis.isolation.spawn.total` — Counter.
    IsolationSpawnTotal,
    /// `raxis.isolation.respawn_attempted.total` — Counter.
    IsolationRespawnAttemptedTotal,
    /// `raxis.intent.admit_predicate.evaluated.total` — Counter.
    /// iter44: leading indicator that the KSB-capabilities envelope
    /// is reaching the planner. Labels: `intent_kind`, `admissible`,
    /// `reason` ∈ {`ok`, `retry_inadmissible`, `budget_exhausted`,
    /// `unknown_lane`, `other`}.
    IntentAdmitPredicateEvaluatedTotal,
    /// `raxis.isolation.failed_final.total` — Counter.
    IsolationFailedFinalTotal,
    /// `raxis.isolation.scale.event.total` — Counter.
    IsolationScaleEventTotal,
    /// `raxis.isolation.scale.deferred.total` — Counter.
    IsolationScaleDeferredTotal,

    // ── Session / initiative lifecycle ──────────────────────────────
    /// `raxis.session.lifecycle.transition.total` — Counter.
    SessionLifecycleTransitionTotal,
    /// `raxis.session.duration` — Histogram (ms).
    SessionDuration,
    /// `raxis.initiative.duration` — Histogram (ms).
    InitiativeDuration,
    /// `raxis.initiative.task.in_flight` — Gauge.
    InitiativeTaskInFlight,

    // ── Audit chain ─────────────────────────────────────────────────
    /// `raxis.audit.event.append.duration` — Histogram (ms).
    AuditEventAppendDuration,
    /// `raxis.audit.event.confirmed.duration` — Histogram (ms).
    AuditEventConfirmedDuration,
    /// `raxis.audit.event.append.total` — Counter.
    AuditEventAppendTotal,
    /// `raxis.audit.fsync.failure.total` — Counter.
    AuditFsyncFailureTotal,
    /// `raxis.audit.chain.lag` — Gauge (events behind tip).
    AuditChainLag,

    // ── Planner / inference ─────────────────────────────────────────
    /// `raxis.planner.inference.duration` — Histogram (ms).
    PlannerInferenceDuration,
    /// `raxis.planner.inference.tokens.total` — Counter.
    PlannerInferenceTokensTotal,
    /// `raxis.planner.dispatch.turn.total` — Counter.
    PlannerDispatchTurnTotal,
    /// `raxis.planner.tool_call.duration` — Histogram (ms).
    PlannerToolCallDuration,
    /// `raxis.planner.retry.total` — Counter.
    PlannerRetryTotal,

    // ── Credential proxies ──────────────────────────────────────────
    /// `raxis.credential_proxy.connection.duration` — Histogram (ms).
    CredentialProxyConnectionDuration,
    /// `raxis.credential_proxy.connection.total` — Counter.
    CredentialProxyConnectionTotal,
    /// `raxis.credential_proxy.statement.duration` — Histogram (ms).
    CredentialProxyStatementDuration,
    /// `raxis.credential_proxy.bytes.total` — Counter.
    CredentialProxyBytesTotal,
    /// `raxis.credential_proxy.policy_block.total` — Counter.
    CredentialProxyPolicyBlockTotal,

    // ── Egress / gateway ────────────────────────────────────────────
    /// `raxis.egress.allowlist.check.duration` — Histogram (ms).
    EgressAllowlistCheckDuration,
    /// `raxis.egress.allowlist.block.total` — Counter.
    EgressAllowlistBlockTotal,
    /// `raxis.gateway.upstream.duration` — Histogram (ms).
    GatewayUpstreamDuration,

    // ── V3 §3 expansions — admit / deny / default-grant / stall ─────
    //
    // Mirror the audit events emitted by `worker/reviewer-orch-egress-defaults`
    // and `worker/secrets-model-realignment`. Surfaced on dashboards
    // `60-egress.json` (admit / deny / stall by chokepoint) and
    // `50-credential-proxies.json` (substitution by service).
    /// `raxis.egress.admit.total` — Counter (chokepoint).
    EgressAdmitTotal,
    /// `raxis.egress.deny.total` — Counter (chokepoint, reason).
    EgressDenyTotal,
    /// `raxis.egress.default_provider_grant.total` — Counter (provider_kind).
    EgressDefaultProviderGrantTotal,
    /// `raxis.egress.stall_detected.total` — Counter (chokepoint, reason).
    EgressStallDetectedTotal,
    /// `raxis.credential_proxy.substitution.total` — Counter (service).
    CredentialProxySubstitutionTotal,

    // ── Operator dashboard ──────────────────────────────────────────
    /// `raxis.dashboard.http.request.duration` — Histogram (ms).
    DashboardHttpRequestDuration,
    /// `raxis.dashboard.sse.connection.active` — Gauge.
    DashboardSseConnectionActive,
    /// `raxis.dashboard.sse.event.total` — Counter.
    DashboardSseEventTotal,
    /// `raxis.dashboard.sse.lag.duration` — Histogram (ms).
    DashboardSseLagDuration,

    // ── Reviewer / disagreement ─────────────────────────────────────
    /// `raxis.reviewer.review.duration` — Histogram (ms).
    ReviewerReviewDuration,
    /// `raxis.reviewer.outcome.total` — Counter.
    ReviewerOutcomeTotal,
    /// `raxis.reviewer.disagreement.total` — Counter.
    ReviewerDisagreementTotal,
    /// `raxis.review.revision_round` — Histogram (rounds).
    ReviewRevisionRound,

    // ── Git / worktree ──────────────────────────────────────────────
    /// `raxis.git.worktree.provision.duration` — Histogram (ms).
    GitWorktreeProvisionDuration,
    /// `raxis.git.merge.duration` — Histogram (ms).
    GitMergeDuration,
    /// `raxis.git.commit.total` — Counter.
    GitCommitTotal,

    // ── Process / host ──────────────────────────────────────────────
    /// `raxis.kernel.uptime.seconds` — Gauge.
    KernelUptimeSeconds,

    // ── iter44: kernel self-healing supervisor metrics ──────────────
    //
    // Counterparts to the supervisor-emitted audit events
    // (`KernelRespawnedBySupervisor`, `KernelBootedFromSupervisorRestart`,
    // `KernelCrashedBySignal`, `KernelTerminatedByOperator`,
    // `SupervisorRefusedRestart`, `SupervisorRestartCeilingExceeded`).
    // Spec: `v3/otel-observability.md §8` rows added under iter44 +
    // cross-ref from `v2/self-healing-supervisor.md §9`.
    /// `raxis.kernel.respawn.total` — Counter (per supervisor-driven
    /// kernel respawn). Labels: `trigger`, `outcome`.
    KernelRespawnTotal,
    /// `raxis.kernel.respawn.duration` — Histogram (ms). Labels:
    /// `trigger`. Wall-clock from supervisor restart-decision (sentinel
    /// `last_restart_unix_ts`) through to kernel-up-and-rehydrated. Wide
    /// bucket spread per `INV-OBS-KERNEL-RESPAWN-COVERAGE-01` because
    /// the operation can range from sub-second auto-restarts to
    /// minutes of crash-loop back-off.
    KernelRespawnDuration,
    /// `raxis.supervisor.refused_restart.total` — Counter. Labels:
    /// `reason`. Bumped when the kernel boots and observes a
    /// supervisor sentinel in `Halted (CircuitOpen)` / `Halted
    /// (OperatorStop[Forced])` state, indicating the supervisor
    /// previously refused to spawn another kernel.
    SupervisorRefusedRestartTotal,

    // ── iter44: operator IPC metrics (slice 4a) ──────────────────────
    //
    // Counterparts to the `OperatorIpc` span (`v3/otel-observability.md
    // §7.1`). Recording site is the operator UDS dispatcher in
    // `kernel/src/ipc/operator.rs::dispatch_loop`. Spec: `v3/otel-
    // observability.md §8` rows added under iter44 + invariant
    // `INV-OBS-OPERATOR-IPC-COVERAGE-01`.
    /// `raxis.operator.ipc.duration` — Histogram (ms). Labels:
    /// `command_kind` (closed allow-list = every `OperatorRequest`
    /// variant in `raxis_types::operator_wire`), `accepted: bool`.
    /// One observation per operator IPC frame the dispatcher
    /// processes — fast path; per `INV-OBS-OPERATOR-IPC-COVERAGE-01`
    /// the rate equals `OperatorIpcTotal`'s rate (one-to-one).
    OperatorIpcDuration,
    /// `raxis.operator.ipc.total` — Counter. Labels: `command_kind`,
    /// `accepted: bool`. One increment per dispatched operator IPC
    /// frame.
    OperatorIpcTotal,

    // ── iter44: kernel↔substrate vsock IPC metrics (slice 4b) ────────
    //
    // Counterparts of the planner-socket dispatcher in
    // `kernel/src/ipc/server.rs::drive_planner_stream` (the convergence
    // point for both production vsock streams and the in-process Unix-
    // socket test stream — see the rustdoc on that fn). Each
    // substrate-originated IPC frame the kernel consumes emits
    // exactly one duration sample + one counter increment, and the
    // module-global `KernelSubstrateIpcInflight` gauge tracks the
    // number of frames the kernel is currently mid-handler on. Spec:
    // `v3/otel-observability.md §8` rows added under iter44 +
    // invariant `INV-OBS-IPC-ROUNDTRIP-COVERAGE-01`.
    /// `raxis.kernel.substrate.ipc.roundtrip.duration` — Histogram (ms).
    /// Labels: `role` (closed allow-list = `{ "planner",
    /// "verifier", "gateway", "unknown" }`), `message_kind` (closed
    /// allow-list = `{ "intent_request", "witness_submission",
    /// "escalation_request", "planner_fetch_request",
    /// "unexpected" }`). Wall-clock from frame received → response
    /// frame written. iter44 IPC-bucket override
    /// `[1, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000]` ms.
    KernelSubstrateIpcRoundtripDuration,
    /// `raxis.kernel.substrate.ipc.messages.total` — Counter. Same
    /// `role` / `message_kind` labels. One increment per frame the
    /// dispatcher routes (the "unexpected" arm increments too,
    /// proving the closed lexicon stays total).
    KernelSubstrateIpcMessagesTotal,
    /// `raxis.kernel.substrate.ipc.inflight` — Gauge. Labels:
    /// `role`. Module-global counter that increments before the
    /// per-variant handler runs and decrements after the response
    /// frame is written, regardless of handler outcome. Sampled
    /// (re-emitted) on every increment / decrement so the gauge
    /// tracks actual concurrency.
    KernelSubstrateIpcInflight,
}

impl MetricName {
    /// OTel-canonical metric name on the wire.
    pub fn as_otel_name(&self) -> &'static str {
        match self {
            Self::IntentAdmissionDuration         => "raxis.intent.admission.duration",
            Self::IntentAdmissionTotal            => "raxis.intent.admission.total",
            Self::GatewayFetchDuration            => "raxis.gateway.fetch.duration",
            Self::GatewayFetchTotal               => "raxis.gateway.fetch.total",
            Self::VerifierExecutionDuration       => "raxis.verifier.execution.duration",
            Self::VerifierExecutionTotal          => "raxis.verifier.execution.total",
            Self::TokensConsumed                  => "raxis.tokens.consumed",
            Self::CircuitBreakerState             => "raxis.circuit_breaker.state",
            Self::CredentialProxyRequestDuration  => "raxis.credential_proxy.request.duration",
            Self::NotificationDeliveryDuration    => "raxis.notification.delivery.duration",
            Self::NotificationDeliveryTotal       => "raxis.notification.delivery.total",
            Self::SessionsActive                  => "raxis.session.active",
            Self::AuditChainLength                => "raxis.audit.chain.length",
            Self::EscalationsOpen                 => "raxis.escalation.open",
            Self::EscalationsClosedTotal          => "raxis.escalation.closed.total",
            Self::BudgetReserved                  => "raxis.budget.reserved",
            Self::BudgetExceededTotal             => "raxis.budget.exceeded.total",
            Self::ObservabilityDroppedTotal       => "raxis.observability.dropped.total",

            // V3 perf-telemetry expansion.
            Self::IsolationSpawnColdBootDuration       => "raxis.isolation.spawn.cold_boot.duration",
            Self::IsolationSpawnHostInitDuration       => "raxis.isolation.spawn.host_init.duration",
            Self::IsolationSpawnGuestInitDuration      => "raxis.isolation.spawn.guest_init.duration",
            Self::IsolationSpawnVsockHandshakeDuration => "raxis.isolation.spawn.vsock_handshake.duration",
            Self::IsolationSpawnTotal                  => "raxis.isolation.spawn.total",
            Self::IsolationRespawnAttemptedTotal       => "raxis.isolation.respawn_attempted.total",
            Self::IntentAdmitPredicateEvaluatedTotal   => "raxis.intent.admit_predicate.evaluated.total",
            Self::IsolationFailedFinalTotal            => "raxis.isolation.failed_final.total",
            Self::IsolationScaleEventTotal             => "raxis.isolation.scale.event.total",
            Self::IsolationScaleDeferredTotal          => "raxis.isolation.scale.deferred.total",

            Self::SessionLifecycleTransitionTotal      => "raxis.session.lifecycle.transition.total",
            Self::SessionDuration                      => "raxis.session.duration",
            Self::InitiativeDuration                   => "raxis.initiative.duration",
            Self::InitiativeTaskInFlight               => "raxis.initiative.task.in_flight",

            Self::AuditEventAppendDuration             => "raxis.audit.event.append.duration",
            Self::AuditEventConfirmedDuration          => "raxis.audit.event.confirmed.duration",
            Self::AuditEventAppendTotal                => "raxis.audit.event.append.total",
            Self::AuditFsyncFailureTotal               => "raxis.audit.fsync.failure.total",
            Self::AuditChainLag                        => "raxis.audit.chain.lag",

            Self::PlannerInferenceDuration             => "raxis.planner.inference.duration",
            Self::PlannerInferenceTokensTotal          => "raxis.planner.inference.tokens.total",
            Self::PlannerDispatchTurnTotal             => "raxis.planner.dispatch.turn.total",
            Self::PlannerToolCallDuration              => "raxis.planner.tool_call.duration",
            Self::PlannerRetryTotal                    => "raxis.planner.retry.total",

            Self::CredentialProxyConnectionDuration    => "raxis.credential_proxy.connection.duration",
            Self::CredentialProxyConnectionTotal       => "raxis.credential_proxy.connection.total",
            Self::CredentialProxyStatementDuration     => "raxis.credential_proxy.statement.duration",
            Self::CredentialProxyBytesTotal            => "raxis.credential_proxy.bytes.total",
            Self::CredentialProxyPolicyBlockTotal      => "raxis.credential_proxy.policy_block.total",

            Self::EgressAllowlistCheckDuration         => "raxis.egress.allowlist.check.duration",
            Self::EgressAllowlistBlockTotal            => "raxis.egress.allowlist.block.total",
            Self::GatewayUpstreamDuration              => "raxis.gateway.upstream.duration",

            Self::EgressAdmitTotal                     => "raxis.egress.admit.total",
            Self::EgressDenyTotal                      => "raxis.egress.deny.total",
            Self::EgressDefaultProviderGrantTotal      => "raxis.egress.default_provider_grant.total",
            Self::EgressStallDetectedTotal             => "raxis.egress.stall_detected.total",
            Self::CredentialProxySubstitutionTotal     => "raxis.credential_proxy.substitution.total",

            Self::DashboardHttpRequestDuration         => "raxis.dashboard.http.request.duration",
            Self::DashboardSseConnectionActive         => "raxis.dashboard.sse.connection.active",
            Self::DashboardSseEventTotal               => "raxis.dashboard.sse.event.total",
            Self::DashboardSseLagDuration              => "raxis.dashboard.sse.lag.duration",

            Self::ReviewerReviewDuration               => "raxis.reviewer.review.duration",
            Self::ReviewerOutcomeTotal                 => "raxis.reviewer.outcome.total",
            Self::ReviewerDisagreementTotal            => "raxis.reviewer.disagreement.total",
            Self::ReviewRevisionRound                  => "raxis.review.revision_round",

            Self::GitWorktreeProvisionDuration         => "raxis.git.worktree.provision.duration",
            Self::GitMergeDuration                     => "raxis.git.merge.duration",
            Self::GitCommitTotal                       => "raxis.git.commit.total",

            Self::KernelUptimeSeconds                  => "raxis.kernel.uptime.seconds",

            Self::KernelRespawnTotal                   => "raxis.kernel.respawn.total",
            Self::KernelRespawnDuration                => "raxis.kernel.respawn.duration",
            Self::SupervisorRefusedRestartTotal        => "raxis.supervisor.refused_restart.total",

            Self::OperatorIpcDuration                  => "raxis.operator.ipc.duration",
            Self::OperatorIpcTotal                     => "raxis.operator.ipc.total",
            Self::KernelSubstrateIpcRoundtripDuration  => "raxis.kernel.substrate.ipc.roundtrip.duration",
            Self::KernelSubstrateIpcMessagesTotal      => "raxis.kernel.substrate.ipc.messages.total",
            Self::KernelSubstrateIpcInflight           => "raxis.kernel.substrate.ipc.inflight",
        }
    }

    /// The default [`MetricType`] for this metric. Matches `§8`.
    pub fn default_type(&self) -> MetricType {
        match self {
            Self::IntentAdmissionDuration
            | Self::GatewayFetchDuration
            | Self::VerifierExecutionDuration
            | Self::CredentialProxyRequestDuration
            | Self::NotificationDeliveryDuration
            | Self::IsolationSpawnColdBootDuration
            | Self::IsolationSpawnHostInitDuration
            | Self::IsolationSpawnGuestInitDuration
            | Self::IsolationSpawnVsockHandshakeDuration
            | Self::SessionDuration
            | Self::InitiativeDuration
            | Self::AuditEventAppendDuration
            | Self::AuditEventConfirmedDuration
            | Self::PlannerInferenceDuration
            | Self::PlannerToolCallDuration
            | Self::CredentialProxyConnectionDuration
            | Self::CredentialProxyStatementDuration
            | Self::EgressAllowlistCheckDuration
            | Self::GatewayUpstreamDuration
            | Self::DashboardHttpRequestDuration
            | Self::DashboardSseLagDuration
            | Self::ReviewerReviewDuration
            | Self::ReviewRevisionRound
            | Self::GitWorktreeProvisionDuration
            | Self::GitMergeDuration
            | Self::KernelRespawnDuration
            | Self::OperatorIpcDuration
            | Self::KernelSubstrateIpcRoundtripDuration => MetricType::Histogram,

            Self::CircuitBreakerState
            | Self::SessionsActive
            | Self::AuditChainLength
            | Self::EscalationsOpen
            | Self::BudgetReserved
            | Self::InitiativeTaskInFlight
            | Self::AuditChainLag
            | Self::DashboardSseConnectionActive
            | Self::KernelUptimeSeconds
            | Self::KernelSubstrateIpcInflight => MetricType::Gauge,

            Self::IntentAdmissionTotal
            | Self::GatewayFetchTotal
            | Self::VerifierExecutionTotal
            | Self::TokensConsumed
            | Self::NotificationDeliveryTotal
            | Self::EscalationsClosedTotal
            | Self::BudgetExceededTotal
            | Self::ObservabilityDroppedTotal
            | Self::IsolationSpawnTotal
            | Self::IsolationRespawnAttemptedTotal
            | Self::IntentAdmitPredicateEvaluatedTotal
            | Self::IsolationFailedFinalTotal
            | Self::IsolationScaleEventTotal
            | Self::IsolationScaleDeferredTotal
            | Self::SessionLifecycleTransitionTotal
            | Self::AuditEventAppendTotal
            | Self::AuditFsyncFailureTotal
            | Self::PlannerInferenceTokensTotal
            | Self::PlannerDispatchTurnTotal
            | Self::PlannerRetryTotal
            | Self::CredentialProxyConnectionTotal
            | Self::CredentialProxyBytesTotal
            | Self::CredentialProxyPolicyBlockTotal
            | Self::EgressAllowlistBlockTotal
            | Self::EgressAdmitTotal
            | Self::EgressDenyTotal
            | Self::EgressDefaultProviderGrantTotal
            | Self::EgressStallDetectedTotal
            | Self::CredentialProxySubstitutionTotal
            | Self::DashboardSseEventTotal
            | Self::ReviewerOutcomeTotal
            | Self::ReviewerDisagreementTotal
            | Self::GitCommitTotal
            | Self::KernelRespawnTotal
            | Self::SupervisorRefusedRestartTotal
            | Self::OperatorIpcTotal
            | Self::KernelSubstrateIpcMessagesTotal => MetricType::Counter,
        }
    }

    /// The default [`Unit`] for this metric.
    pub fn default_unit(&self) -> Unit {
        match self {
            Self::IntentAdmissionDuration
            | Self::GatewayFetchDuration
            | Self::VerifierExecutionDuration
            | Self::CredentialProxyRequestDuration
            | Self::NotificationDeliveryDuration
            | Self::IsolationSpawnColdBootDuration
            | Self::IsolationSpawnHostInitDuration
            | Self::IsolationSpawnGuestInitDuration
            | Self::IsolationSpawnVsockHandshakeDuration
            | Self::SessionDuration
            | Self::InitiativeDuration
            | Self::AuditEventAppendDuration
            | Self::AuditEventConfirmedDuration
            | Self::PlannerInferenceDuration
            | Self::PlannerToolCallDuration
            | Self::CredentialProxyConnectionDuration
            | Self::CredentialProxyStatementDuration
            | Self::EgressAllowlistCheckDuration
            | Self::GatewayUpstreamDuration
            | Self::DashboardHttpRequestDuration
            | Self::DashboardSseLagDuration
            | Self::ReviewerReviewDuration
            | Self::GitWorktreeProvisionDuration
            | Self::GitMergeDuration
            | Self::KernelRespawnDuration
            | Self::OperatorIpcDuration
            | Self::KernelSubstrateIpcRoundtripDuration => Unit::Milliseconds,

            Self::TokensConsumed
            | Self::PlannerInferenceTokensTotal => Unit::Tokens,

            Self::SessionsActive
            | Self::DashboardSseConnectionActive => Unit::Connections,

            _ => Unit::None,
        }
    }
}

/// OTel metric type. `Counter` is monotonic-cumulative; `Gauge` is
/// last-value; `Histogram` carries explicit-boundary buckets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MetricType {
    /// Monotonic cumulative counter (resets on kernel restart per
    /// `INV-OTEL-06`).
    Counter,
    /// Distribution histogram with explicit boundaries.
    Histogram,
    /// Last-value gauge.
    Gauge,
}

/// Bounded enumeration of metric units. Avoids open-ended free-form
/// strings in the wire format — collectors that need richer units
/// can derive them from `MetricName`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Unit {
    /// Milliseconds; histograms default here.
    Milliseconds,
    /// Bytes.
    Bytes,
    /// LLM tokens (input + output).
    Tokens,
    /// Active connections / sessions / sockets.
    Connections,
    /// No unit (counters/gauges of cardinal quantities).
    None,
}

impl Unit {
    /// Stable symbol used as the OTLP `Metric.unit` field. Empty
    /// string for `Unit::None`. The pusher copies this verbatim
    /// onto every emitted metric.
    pub fn symbol(&self) -> &'static str {
        match self {
            Self::Milliseconds => "ms",
            Self::Bytes        => "By",
            Self::Tokens       => "{tokens}",
            Self::Connections  => "{connections}",
            Self::None         => "",
        }
    }
}

impl EventName {
    /// Stable string label used as the OTLP `Span.Event.name` field.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::GateRequired             => "gate.required",
            Self::GateSatisfied            => "gate.satisfied",
            Self::GateMissing              => "gate.missing",
            Self::VerifierSpawned          => "verifier.spawned",
            Self::BudgetReserved           => "budget.reserved",
            Self::BudgetReleased           => "budget.released",
            Self::InferenceTokensReported  => "inference.tokens_reported",
            Self::CircuitOpened            => "circuit.opened",
            Self::CircuitClosed            => "circuit.closed",
            Self::HeartbeatTick            => "heartbeat.tick",
        }
    }
}

/// Single metric data point — either a sum-style scalar (counter /
/// gauge) or a histogram bucket vector.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "shape", rename_all = "snake_case")]
pub enum DataPoint {
    /// Counter or gauge: a single number.
    Sum {
        /// The cardinal value of the data point.
        value: f64,
    },
    /// Histogram with explicit bucket boundaries.
    Histo {
        /// Bucket boundaries (length N).
        buckets: Vec<f64>,
        /// Bucket counts (length N+1: `[≤bucket_0, ≤bucket_1, …, >bucket_{N-1}]`).
        counts:  Vec<u64>,
        /// Sum of all observations.
        sum:     f64,
        /// Count of all observations.
        count:   u64,
        /// Minimum observation value.
        min:     f64,
        /// Maximum observation value.
        max:     f64,
    },
}

/// One aggregated metric data point.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MetricData {
    /// Closed-list metric name; emitted as the OTel canonical name.
    pub name:         MetricName,
    /// Counter / gauge / histogram.
    pub metric_type:  MetricType,
    /// Bounded enum of physical units.
    pub unit:         Unit,
    /// Stable label set (sorted by key on the wire).
    pub labels:       AttrMap,
    /// Sum or histogram payload.
    pub datapoint:    DataPoint,
    /// Wallclock at observation time; ns since UNIX epoch.
    pub unix_nanos:   u64,
}

// ---------------------------------------------------------------------------
// Tests — JSONL round-trip; closed-list assertions
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn span_data_roundtrips_as_json_line() {
        let span = SpanData {
            trace_id:         [1; 16],
            span_id:          [2; 8],
            parent_span_id:   None,
            name:             SpanName::IntentAdmission,
            kind:             SpanKind::Internal,
            start_unix_nanos: 1_000_000_000,
            end_unix_nanos:   1_500_000_000,
            status:           SpanStatus::Ok,
            status_message:   None,
            attrs:            {
                let mut a = AttrMap::new();
                a.insert("intent_kind".to_owned(), AttrValue::Str("CompleteTask".to_owned()));
                a.insert("verdict".to_owned(),     AttrValue::Str("Accepted".to_owned()));
                a.insert("latency_ms".to_owned(),  AttrValue::I64(500));
                a
            },
            events:           vec![],
        };
        let json = serde_json::to_string(&span).expect("serialise");
        let back: SpanData = serde_json::from_str(&json).expect("deserialise");
        assert_eq!(span, back);
    }

    #[test]
    fn metric_data_histogram_roundtrips() {
        let m = MetricData {
            name:         MetricName::IntentAdmissionDuration,
            metric_type:  MetricType::Histogram,
            unit:         Unit::Milliseconds,
            labels:       {
                let mut l = AttrMap::new();
                l.insert("verdict".to_owned(), AttrValue::Str("Accepted".to_owned()));
                l
            },
            datapoint:    DataPoint::Histo {
                buckets: vec![1.0, 5.0, 10.0],
                counts:  vec![0, 1, 0, 0],
                sum:     3.5,
                count:   1,
                min:     3.5,
                max:     3.5,
            },
            unix_nanos:   2_000_000_000,
        };
        let json = serde_json::to_string(&m).expect("serialise");
        let back: MetricData = serde_json::from_str(&json).expect("deserialise");
        assert_eq!(m, back);
    }

    #[test]
    fn span_name_otel_names_match_spec() {
        assert_eq!(SpanName::IntentAdmission.as_otel_name(), "raxis.intent.admission");
        assert_eq!(SpanName::GatewayFetch.as_otel_name(),    "raxis.gateway.fetch");
        assert_eq!(SpanName::BreakglassAction.as_otel_name(), "raxis.breakglass.action");
    }

    #[test]
    fn metric_name_default_types_match_spec() {
        assert_eq!(MetricName::IntentAdmissionDuration.default_type(), MetricType::Histogram);
        assert_eq!(MetricName::IntentAdmissionTotal.default_type(),    MetricType::Counter);
        assert_eq!(MetricName::SessionsActive.default_type(),          MetricType::Gauge);
        assert_eq!(MetricName::CircuitBreakerState.default_type(),     MetricType::Gauge);
    }

    #[test]
    fn span_data_duration_ms_is_correct() {
        let span = SpanData {
            trace_id:         [0; 16],
            span_id:          [0; 8],
            parent_span_id:   None,
            name:             SpanName::IntentAdmission,
            kind:             SpanKind::Internal,
            start_unix_nanos: 1_000_000_000,
            end_unix_nanos:   1_500_000_000,  // +500ms
            status:           SpanStatus::Ok,
            status_message:   None,
            attrs:            AttrMap::new(),
            events:           vec![],
        };
        assert_eq!(span.duration_ms(), 500);
    }

    #[test]
    fn span_data_duration_handles_underflow() {
        let span = SpanData {
            trace_id:         [0; 16],
            span_id:          [0; 8],
            parent_span_id:   None,
            name:             SpanName::IntentAdmission,
            kind:             SpanKind::Internal,
            start_unix_nanos: 2_000_000_000,
            end_unix_nanos:   1_000_000_000,  // intentionally inverted
            status:           SpanStatus::Ok,
            status_message:   None,
            attrs:            AttrMap::new(),
            events:           vec![],
        };
        assert_eq!(span.duration_ms(), 0, "saturating sub on inverted timestamps");
    }
}

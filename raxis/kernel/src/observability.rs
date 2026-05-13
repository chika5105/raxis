//! Kernel-side helpers around the [`raxis_observability::ObservabilityHub`].
//!
//! This module owns the **emit-site convenience layer**: short
//! functions that take a few in-flight values, build the
//! corresponding closed-allow-list attribute map, and call
//! `record_*` on the hub. Centralising the helpers here gives every
//! emit site one canonical shape per metric, which makes the
//! `raxis-otel-pusher`-side OTLP projection deterministic.
//!
//! Spec: `specs/v3/otel-observability.md §7.1, §8`.
//!
//! ## Discipline
//!
//! - Every helper here MUST use only attribute keys present in the
//!   `crates/observability/src/redact.rs::ALLOW_LIST`. The redactor
//!   drops the entire metric on the first violation, so a typo here
//!   is loud (a drop counter spike), not silent.
//! - Every helper MUST be `&` (read-only) over the hub. Hub state
//!   mutation lives inside the hub itself.
//! - Every helper MUST be cheap — never allocate when the hub is
//!   disabled.

use raxis_observability::{redact, MetricName, ObservabilityHub};

/// Record one `raxis.intent.admission.{total,duration}` data point
/// for an intent that has just left the kernel pipeline. Called once
/// from `handlers::intent::handle` after the response is built.
///
/// `intent_kind` MUST be the stable `IntentKind::as_str()` form
/// (`"SingleCommit"`, `"IntegrationMerge"`, etc.). `verdict` MUST be
/// one of the closed set `{"Accepted", "Rejected"}` — the redactor
/// caps the value at 16 bytes anyway. `latency_ms` is the wall-clock
/// admission latency, used as the histogram observation.
pub fn record_intent_admission(
    hub:         &ObservabilityHub,
    intent_kind: &str,
    verdict:     &str,
    latency_ms:  i64,
) {
    if !hub.enabled() { return; }
    let labels = redact::attrs([
        ("intent_kind", intent_kind),
        ("verdict",     verdict),
    ]);
    hub.record_counter(MetricName::IntentAdmissionTotal, labels.clone(), 1.0);
    hub.record_histogram(
        MetricName::IntentAdmissionDuration,
        labels,
        latency_ms.max(0) as f64,
    );
}

/// Record one `raxis.gateway.fetch.{total,duration}` pair plus a
/// `raxis.tokens.consumed` counter when the response carries token
/// usage. Called from the gateway-fetch outbound path.
pub fn record_gateway_fetch(
    hub:           &ObservabilityHub,
    provider:      &str,
    model:         Option<&str>,
    status_code:   i64,
    latency_ms:    i64,
    cached:        bool,
    tokens_in:     Option<i64>,
    tokens_out:    Option<i64>,
) {
    if !hub.enabled() { return; }
    let mut labels = redact::attrs([
        ("provider",   provider),
        ("status_code", "0"),         // overwritten below as I64
        ("cached",     "false"),      // overwritten below as Bool
    ]);
    labels.insert(
        "status_code".to_owned(),
        raxis_observability::AttrValue::I64(status_code),
    );
    labels.insert(
        "cached".to_owned(),
        raxis_observability::AttrValue::Bool(cached),
    );
    if let Some(m) = model {
        labels.insert(
            "model".to_owned(),
            raxis_observability::AttrValue::Str(m.to_owned()),
        );
    }
    hub.record_counter(MetricName::GatewayFetchTotal, labels.clone(), 1.0);
    hub.record_histogram(
        MetricName::GatewayFetchDuration,
        labels.clone(),
        latency_ms.max(0) as f64,
    );
    if let (Some(i_n), Some(o_n)) = (tokens_in, tokens_out) {
        let mut tlabels = redact::attrs([
            ("provider",  provider),
            ("direction", "in"),
        ]);
        if let Some(m) = model {
            tlabels.insert(
                "model".to_owned(),
                raxis_observability::AttrValue::Str(m.to_owned()),
            );
        }
        hub.record_counter(MetricName::TokensConsumed, tlabels.clone(), i_n.max(0) as f64);
        tlabels.insert(
            "direction".to_owned(),
            raxis_observability::AttrValue::Str("out".to_owned()),
        );
        hub.record_counter(MetricName::TokensConsumed, tlabels, o_n.max(0) as f64);
    }
}

/// Record one `raxis.notification.delivery.{total,duration}` pair.
/// Called by the notification dispatcher after a single channel
/// attempt completes.
pub fn record_notification_delivery(
    hub:           &ObservabilityHub,
    channel_kind:  &str,
    channel_id:    &str,
    event_kind:    &str,
    success:       bool,
    delivery_ms:   i64,
) {
    if !hub.enabled() { return; }
    let mut labels = redact::attrs([
        ("channel_kind", channel_kind),
        ("channel_id",   channel_id),
        ("event_kind",   event_kind),
    ]);
    labels.insert(
        "success".to_owned(),
        raxis_observability::AttrValue::Bool(success),
    );
    hub.record_counter(MetricName::NotificationDeliveryTotal, labels.clone(), 1.0);
    hub.record_histogram(
        MetricName::NotificationDeliveryDuration,
        labels,
        delivery_ms.max(0) as f64,
    );
}

/// Record `raxis.session.active` gauge.
pub fn record_sessions_active(
    hub:    &ObservabilityHub,
    role:   &str,
    count:  i64,
) {
    if !hub.enabled() { return; }
    let labels = redact::attrs([("role", role)]);
    hub.record_gauge(MetricName::SessionsActive, labels, count.max(0) as f64);
}

/// Record `raxis.audit.chain.length` gauge — set after every
/// successful audit chain append. The kernel calls this from
/// `policy_manager::advance_epoch` and from the audit chain warmup
/// surface during boot.
pub fn record_audit_chain_length(hub: &ObservabilityHub, seq: i64) {
    if !hub.enabled() { return; }
    let labels = raxis_observability::AttrMap::new();
    hub.record_gauge(MetricName::AuditChainLength, labels, seq.max(0) as f64);
}

// ---------------------------------------------------------------------------
// V3 perf-telemetry — `specs/v3/observability-prometheus.md §3`.
//
// These helpers are the kernel-wide convenience layer for the new
// metric families introduced by the V3 perf-data spec. They mirror
// the original §6/§7 helpers above (closed allow-list attributes, no
// allocation when the hub is disabled) and stay in this module so all
// emit sites import from one place.
//
// Cold-boot histograms (the four-tier `raxis.isolation.spawn.*`
// family) are emitted from inside `raxis-session-spawn`'s
// `perf_telemetry` module rather than here, because the cold-boot
// timer must bracket the full `spawn_session` future. Every other
// metric family lives here.
// ---------------------------------------------------------------------------

/// `raxis.session.lifecycle.transition.total` — counter bumped on
/// every session-FSM transition the lifecycle module commits.
pub fn record_session_lifecycle_transition(
    hub:        &ObservabilityHub,
    from_state: &str,
    to_state:   &str,
    agent_type: &str,
    outcome:    &str,
) {
    if !hub.enabled() { return; }
    let labels = redact::attrs([
        ("from_state", from_state),
        ("to_state",   to_state),
        ("agent_type", agent_type),
        ("outcome",    outcome),
    ]);
    hub.record_counter(MetricName::SessionLifecycleTransitionTotal, labels, 1.0);
}

/// `raxis.session.duration` histogram — total wall-clock between
/// session spawn and session terminate.
pub fn record_session_duration(
    hub:        &ObservabilityHub,
    agent_type: &str,
    outcome:    &str,
    duration_ms: i64,
) {
    if !hub.enabled() { return; }
    let labels = redact::attrs([
        ("agent_type", agent_type),
        ("outcome",    outcome),
    ]);
    hub.record_histogram(
        MetricName::SessionDuration,
        labels,
        duration_ms.max(0) as f64,
    );
}

/// `raxis.initiative.duration` histogram — full initiative wall-clock
/// from approve_plan through final terminal transition.
pub fn record_initiative_duration(
    hub:              &ObservabilityHub,
    initiative_class: &str,
    outcome:          &str,
    duration_ms:      i64,
) {
    if !hub.enabled() { return; }
    let labels = redact::attrs([
        ("initiative_class", initiative_class),
        ("outcome",          outcome),
    ]);
    hub.record_histogram(
        MetricName::InitiativeDuration,
        labels,
        duration_ms.max(0) as f64,
    );
}

/// `raxis.initiative.task.in_flight` gauge — sampled by the scheduler
/// after every admit / complete tick.
pub fn record_initiative_task_in_flight(
    hub:              &ObservabilityHub,
    initiative_class: &str,
    count:            i64,
) {
    if !hub.enabled() { return; }
    let labels = redact::attrs([("initiative_class", initiative_class)]);
    hub.record_gauge(
        MetricName::InitiativeTaskInFlight,
        labels,
        count.max(0) as f64,
    );
}

/// `raxis.audit.event.append.{total,duration}` — fired by the
/// `FileAuditSink` `append_event` path after a successful fsync.
pub fn record_audit_event_append(
    hub:        &ObservabilityHub,
    kind:       &str,
    append_ms:  i64,
    confirmed_ms: Option<i64>,
) {
    if !hub.enabled() { return; }
    let labels = redact::attrs([("kind", kind)]);
    hub.record_counter(MetricName::AuditEventAppendTotal, labels.clone(), 1.0);
    hub.record_histogram(
        MetricName::AuditEventAppendDuration,
        labels.clone(),
        append_ms.max(0) as f64,
    );
    if let Some(ms) = confirmed_ms {
        hub.record_histogram(
            MetricName::AuditEventConfirmedDuration,
            labels,
            ms.max(0) as f64,
        );
    }
}

/// `raxis.audit.fsync.failure.total` — bumped only on the `fsync` /
/// `fdatasync` failure path (NOT on every append). The kernel will
/// already be on its way to crashing fail-closed when this fires.
pub fn record_audit_fsync_failure(hub: &ObservabilityHub, reason: &str) {
    if !hub.enabled() { return; }
    let labels = redact::attrs([("reason", reason)]);
    hub.record_counter(MetricName::AuditFsyncFailureTotal, labels, 1.0);
}

/// `raxis.audit.chain.lag` gauge — events behind the in-memory tip.
pub fn record_audit_chain_lag(hub: &ObservabilityHub, lag_events: i64) {
    if !hub.enabled() { return; }
    hub.record_gauge(
        MetricName::AuditChainLag,
        raxis_observability::AttrMap::new(),
        lag_events.max(0) as f64,
    );
}

/// `raxis.planner.inference.{duration,tokens}` — fired by every
/// planner provider client after a turn completes.
#[allow(clippy::too_many_arguments)]
pub fn record_planner_inference(
    hub:           &ObservabilityHub,
    provider:      &str,
    model:         &str,
    outcome:       &str,
    streaming:     bool,
    duration_ms:   i64,
    tokens_in:     i64,
    tokens_out:    i64,
) {
    if !hub.enabled() { return; }
    let mut labels = redact::attrs([
        ("provider", provider),
        ("model",    model),
        ("outcome",  outcome),
    ]);
    labels.insert(
        "streaming".to_owned(),
        raxis_observability::AttrValue::Bool(streaming),
    );
    hub.record_histogram(
        MetricName::PlannerInferenceDuration,
        labels.clone(),
        duration_ms.max(0) as f64,
    );

    let mut labels_in = labels.clone();
    labels_in.insert(
        "direction".to_owned(),
        raxis_observability::AttrValue::Str("in".to_owned()),
    );
    hub.record_counter(
        MetricName::PlannerInferenceTokensTotal,
        labels_in,
        tokens_in.max(0) as f64,
    );

    let mut labels_out = labels;
    labels_out.insert(
        "direction".to_owned(),
        raxis_observability::AttrValue::Str("out".to_owned()),
    );
    hub.record_counter(
        MetricName::PlannerInferenceTokensTotal,
        labels_out,
        tokens_out.max(0) as f64,
    );
}

/// `raxis.planner.dispatch.turn.total` — counter for every planner
/// dispatch turn that completes (success / failure / cancel).
pub fn record_planner_dispatch_turn(
    hub:        &ObservabilityHub,
    agent_type: &str,
    outcome:    &str,
) {
    if !hub.enabled() { return; }
    let labels = redact::attrs([
        ("agent_type", agent_type),
        ("outcome",    outcome),
    ]);
    hub.record_counter(MetricName::PlannerDispatchTurnTotal, labels, 1.0);
}

/// `raxis.planner.tool_call.duration` — fired by the planner's
/// tool-dispatch substrate after every tool invocation.
pub fn record_planner_tool_call(
    hub:         &ObservabilityHub,
    tool_name:   &str,
    outcome:     &str,
    duration_ms: i64,
) {
    if !hub.enabled() { return; }
    let labels = redact::attrs([
        ("tool_name", tool_name),
        ("outcome",   outcome),
    ]);
    hub.record_histogram(
        MetricName::PlannerToolCallDuration,
        labels,
        duration_ms.max(0) as f64,
    );
}

/// `raxis.planner.retry.total` — counter for every retry the
/// planner's circuit-breaker / transient-error retry loop attempts.
pub fn record_planner_retry(
    hub:           &ObservabilityHub,
    provider:      &str,
    attempt:       i64,
    final_outcome: &str,
) {
    if !hub.enabled() { return; }
    let mut labels = redact::attrs([
        ("provider",      provider),
        ("final_outcome", final_outcome),
    ]);
    labels.insert(
        "attempt".to_owned(),
        raxis_observability::AttrValue::I64(attempt),
    );
    hub.record_counter(MetricName::PlannerRetryTotal, labels, 1.0);
}

/// `raxis.credential_proxy.connection.{total,duration}` — fired by
/// the per-protocol proxy after a client connection completes its
/// handshake (or fails).
pub fn record_credproxy_connection(
    hub:         &ObservabilityHub,
    service:     &str,
    outcome:     &str,
    duration_ms: i64,
) {
    if !hub.enabled() { return; }
    let labels = redact::attrs([
        ("service", service),
        ("outcome", outcome),
    ]);
    hub.record_counter(MetricName::CredentialProxyConnectionTotal, labels.clone(), 1.0);
    hub.record_histogram(
        MetricName::CredentialProxyConnectionDuration,
        labels,
        duration_ms.max(0) as f64,
    );
}

/// `raxis.credential_proxy.statement.duration` — fired per
/// statement / wire-protocol message the proxy processes.
pub fn record_credproxy_statement(
    hub:         &ObservabilityHub,
    service:     &str,
    operation:   &str,
    outcome:     &str,
    blocked:    bool,
    duration_ms: i64,
) {
    if !hub.enabled() { return; }
    let mut labels = redact::attrs([
        ("service",   service),
        ("operation", operation),
        ("outcome",   outcome),
    ]);
    labels.insert(
        "blocked".to_owned(),
        raxis_observability::AttrValue::Bool(blocked),
    );
    hub.record_histogram(
        MetricName::CredentialProxyStatementDuration,
        labels,
        duration_ms.max(0) as f64,
    );
}

/// `raxis.credential_proxy.bytes.total` — direction = "in" | "out".
pub fn record_credproxy_bytes(
    hub:       &ObservabilityHub,
    service:   &str,
    direction: &str,
    bytes:     i64,
) {
    if !hub.enabled() { return; }
    let labels = redact::attrs([
        ("service",   service),
        ("direction", direction),
    ]);
    hub.record_counter(
        MetricName::CredentialProxyBytesTotal,
        labels,
        bytes.max(0) as f64,
    );
}

/// `raxis.credential_proxy.policy_block.total` — fired every time a
/// statement / message is rejected by the per-credential policy.
pub fn record_credproxy_policy_block(
    hub:     &ObservabilityHub,
    service: &str,
    reason:  &str,
) {
    if !hub.enabled() { return; }
    let labels = redact::attrs([
        ("service", service),
        ("reason",  reason),
    ]);
    hub.record_counter(MetricName::CredentialProxyPolicyBlockTotal, labels, 1.0);
}

/// `raxis.egress.allowlist.check.duration` plus
/// `raxis.egress.allowlist.block.total` (the latter only on `block`).
pub fn record_egress_check(
    hub:         &ObservabilityHub,
    outcome:     &str,
    duration_ms: i64,
    block_reason: Option<&str>,
) {
    if !hub.enabled() { return; }
    let labels = redact::attrs([("outcome", outcome)]);
    hub.record_histogram(
        MetricName::EgressAllowlistCheckDuration,
        labels,
        duration_ms.max(0) as f64,
    );
    if let Some(reason) = block_reason {
        let block_labels = redact::attrs([("reason", reason)]);
        hub.record_counter(MetricName::EgressAllowlistBlockTotal, block_labels, 1.0);
    }
}

/// `raxis.gateway.upstream.duration` — gateway-side upstream RTT
/// (one observation per upstream call, success or failure).
pub fn record_gateway_upstream(
    hub:         &ObservabilityHub,
    provider:    &str,
    outcome:     &str,
    duration_ms: i64,
) {
    if !hub.enabled() { return; }
    let labels = redact::attrs([
        ("provider", provider),
        ("outcome",  outcome),
    ]);
    hub.record_histogram(
        MetricName::GatewayUpstreamDuration,
        labels,
        duration_ms.max(0) as f64,
    );
}

/// `raxis.dashboard.http.request.duration` — every dashboard HTTP
/// request, success or failure.
pub fn record_dashboard_http_request(
    hub:         &ObservabilityHub,
    route:       &str,
    http_method: &str,
    http_status: i64,
    duration_ms: i64,
) {
    if !hub.enabled() { return; }
    let mut labels = redact::attrs([
        ("route",       route),
        ("http_method", http_method),
    ]);
    labels.insert(
        "http_status".to_owned(),
        raxis_observability::AttrValue::I64(http_status),
    );
    hub.record_histogram(
        MetricName::DashboardHttpRequestDuration,
        labels,
        duration_ms.max(0) as f64,
    );
}

/// `raxis.dashboard.sse.connection.active` gauge — sampled on connect
/// and disconnect.
pub fn record_dashboard_sse_active(
    hub:   &ObservabilityHub,
    route: &str,
    count: i64,
) {
    if !hub.enabled() { return; }
    let labels = redact::attrs([("route", route)]);
    hub.record_gauge(
        MetricName::DashboardSseConnectionActive,
        labels,
        count.max(0) as f64,
    );
}

/// `raxis.dashboard.sse.event.total` plus
/// `raxis.dashboard.sse.lag.duration`.
pub fn record_dashboard_sse_event(
    hub:    &ObservabilityHub,
    route:  &str,
    lag_ms: i64,
) {
    if !hub.enabled() { return; }
    let labels = redact::attrs([("route", route)]);
    hub.record_counter(MetricName::DashboardSseEventTotal, labels.clone(), 1.0);
    hub.record_histogram(
        MetricName::DashboardSseLagDuration,
        labels,
        lag_ms.max(0) as f64,
    );
}

/// `raxis.reviewer.review.duration` plus `raxis.reviewer.outcome.total`.
pub fn record_reviewer_review(
    hub:         &ObservabilityHub,
    outcome:     &str,
    duration_ms: i64,
) {
    if !hub.enabled() { return; }
    let labels = redact::attrs([("outcome", outcome)]);
    hub.record_histogram(
        MetricName::ReviewerReviewDuration,
        labels.clone(),
        duration_ms.max(0) as f64,
    );
    hub.record_counter(MetricName::ReviewerOutcomeTotal, labels, 1.0);
}

/// `raxis.reviewer.disagreement.total` — bumped when the reviewer
/// dissents on a planner-proposed terminal artefact.
pub fn record_reviewer_disagreement(
    hub:            &ObservabilityHub,
    revision_round: i64,
) {
    if !hub.enabled() { return; }
    let mut labels = raxis_observability::AttrMap::new();
    labels.insert(
        "revision_round".to_owned(),
        raxis_observability::AttrValue::I64(revision_round),
    );
    hub.record_counter(MetricName::ReviewerDisagreementTotal, labels, 1.0);
}

/// `raxis.review.revision_round` — histogram observation per closed
/// review (so quantile pivots show how many rounds reviews typically
/// take).
pub fn record_review_revision_round(hub: &ObservabilityHub, rounds: i64) {
    if !hub.enabled() { return; }
    hub.record_histogram(
        MetricName::ReviewRevisionRound,
        raxis_observability::AttrMap::new(),
        rounds.max(0) as f64,
    );
}

/// `raxis.git.worktree.provision.duration` — wall-clock for
/// `worktree-provision::provision`.
pub fn record_git_worktree_provision(
    hub:         &ObservabilityHub,
    role:        &str,
    outcome:     &str,
    duration_ms: i64,
) {
    if !hub.enabled() { return; }
    let labels = redact::attrs([
        ("role",    role),
        ("outcome", outcome),
    ]);
    hub.record_histogram(
        MetricName::GitWorktreeProvisionDuration,
        labels,
        duration_ms.max(0) as f64,
    );
}

/// `raxis.git.merge.duration` — wall-clock for the IntegrationMerge
/// path.
pub fn record_git_merge(
    hub:         &ObservabilityHub,
    outcome:     &str,
    duration_ms: i64,
) {
    if !hub.enabled() { return; }
    let labels = redact::attrs([("outcome", outcome)]);
    hub.record_histogram(
        MetricName::GitMergeDuration,
        labels,
        duration_ms.max(0) as f64,
    );
}

/// `raxis.git.commit.total` — counter, one bump per commit recorded
/// in a worktree (planner-author, reviewer-author).
pub fn record_git_commit(hub: &ObservabilityHub, author_role: &str) {
    if !hub.enabled() { return; }
    let labels = redact::attrs([("author_role", author_role)]);
    hub.record_counter(MetricName::GitCommitTotal, labels, 1.0);
}

/// `raxis.kernel.uptime.seconds` — gauge sampled by the heartbeat task.
pub fn record_kernel_uptime(hub: &ObservabilityHub, uptime_secs: i64) {
    if !hub.enabled() { return; }
    hub.record_gauge(
        MetricName::KernelUptimeSeconds,
        raxis_observability::AttrMap::new(),
        uptime_secs.max(0) as f64,
    );
}

// ---------------------------------------------------------------------------
// V3 §3 expansions — egress admit/deny/default-grant/stall + cred-proxy substitution
//
// Companion audit events (defined in `crates/audit/src/event.rs`) and
// dashboards (`grafana/dashboards/{50-credential-proxies,60-egress}.json`)
// landed before the metric counters did; the bridge between the two is
// `kernel/src/notifications/sink.rs::NotifyingAuditSink`, which calls
// each helper below at the same moment it forwards the audit event to
// listeners. That keeps the audit log (durable, ordered) the source of
// truth and makes the metric a redundant fast-path for dashboards —
// dropping the metric never silently loses operational data.
// ---------------------------------------------------------------------------

/// `raxis.egress.admit.total` — counter, one bump per admission
/// decision the egress chokepoint accepts. Called from the
/// `NotifyingAuditSink` bridge when it observes a
/// `TransparentProxyAdmitted` event (chokepoint = `tproxy`) or any
/// kernel-side egress code-path that emits an admit (future
/// chokepoint = `kernel_mediated_fetch`).
///
/// `chokepoint` is one of the closed lexicon `{ "tproxy",
/// "kernel_mediated_fetch" }` — values defined in the dashboard
/// taxonomy at `grafana/dashboards/60-egress.json`.
pub fn record_egress_admit(hub: &ObservabilityHub, chokepoint: &str) {
    if !hub.enabled() { return; }
    let labels = redact::attrs([("chokepoint", chokepoint)]);
    hub.record_counter(MetricName::EgressAdmitTotal, labels, 1.0);
}

/// `raxis.egress.deny.total` — counter, one bump per admission
/// decision the egress chokepoint rejects. `reason` MUST be a stable
/// lexicon (e.g. `"host_not_allowlisted"`, `"port_blocked"`,
/// `"policy_strict_egress"`) — the redactor caps it at 64 bytes but
/// emit-site convention pins it to a small enumerated set.
pub fn record_egress_deny(
    hub:        &ObservabilityHub,
    chokepoint: &str,
    reason:     &str,
) {
    if !hub.enabled() { return; }
    let labels = redact::attrs([
        ("chokepoint", chokepoint),
        ("reason",     reason),
    ]);
    hub.record_counter(MetricName::EgressDenyTotal, labels, 1.0);
}

/// `raxis.egress.default_provider_grant.total` — counter, one bump
/// each time the policy manager's reviewer-orchestrator default-egress
/// path applies a `DefaultProviderEgressApplied` grant. `provider_kind`
/// matches the audit event's `provider_kind` field (`"openai"`,
/// `"anthropic"`, `"gemini"`, etc.).
pub fn record_egress_default_provider_grant(
    hub:           &ObservabilityHub,
    provider_kind: &str,
) {
    if !hub.enabled() { return; }
    let labels = redact::attrs([("provider_kind", provider_kind)]);
    hub.record_counter(MetricName::EgressDefaultProviderGrantTotal, labels, 1.0);
}

/// `raxis.egress.stall_detected.total` — counter, one bump per
/// `SessionEgressStallDetected` audit event. The egress-admission
/// stall watchdog and the planner-fetch idle-timeout path each emit
/// one of these; they label themselves with the originating
/// `chokepoint` and a stall `reason` (`"idle_timeout"`,
/// `"planner_fetch_no_progress"`).
pub fn record_egress_stall_detected(
    hub:        &ObservabilityHub,
    chokepoint: &str,
    reason:     &str,
) {
    if !hub.enabled() { return; }
    let labels = redact::attrs([
        ("chokepoint", chokepoint),
        ("reason",     reason),
    ]);
    hub.record_counter(MetricName::EgressStallDetectedTotal, labels, 1.0);
}

/// `raxis.credential_proxy.substitution.total` — counter, one bump
/// per `CredentialProxySubstituted` audit event. The credential
/// proxy substitutes a tenant secret in-line and emits both an audit
/// event (durable) and this counter (dashboard).
///
/// `service` is the closed lexicon of supported back-ends
/// (`"postgres"`, `"mysql"`, `"mssql"`, `"mongo"`, `"redis"`,
/// `"smtp"`, …) — keep aligned with `crates/credential-proxy/src/`'s
/// per-service modules.
pub fn record_credential_proxy_substitution(
    hub:     &ObservabilityHub,
    service: &str,
) {
    if !hub.enabled() { return; }
    let labels = redact::attrs([("service", service)]);
    hub.record_counter(MetricName::CredentialProxySubstitutionTotal, labels, 1.0);
}

// ---------------------------------------------------------------------------
// iter44 perf-metrics — `INV-OBS-RESPAWN-KIND-LABEL-01`.
//
// The kernel has three structurally distinct respawn paths and the
// `00-overview` operator needs to disambiguate "healthy retry on a VM
// crash" from "logical-deadlock churn (orchestrator-no-progress)" from
// "reviewer disagreement reset (review-rejection)" at a glance.
// `IsolationRespawnAttemptedTotal` carries one extra label —
// `respawn_kind` — drawn from a closed set:
//
//   * `vm_crash`               — transient VM spawn failure was retried
//                                via `spawn_with_transient_retry` (the
//                                pre-existing elastic-scaling path).
//   * `orchestrator_no_progress` — the kernel observed the post-exit
//                                hook (Mode A: orchestrator session
//                                ended with PendingActivation rows
//                                left over; Mode B: worker session
//                                ended without a terminal intent) and
//                                respawned the orchestrator to drive
//                                the DAG forward.
//   * `reviewer_rejection`      — `RetrySubTask` admitted via the
//                                `Completed`-with-`review_reject_count > 0`
//                                branch (`agent-disagreement.md §3.6`);
//                                the orchestrator continuation respawn
//                                that follows is attributable to
//                                reviewer disagreement, NOT to a VM
//                                crash.
//   * `unknown`                 — fallback for paths whose taxonomy
//                                hasn't been mapped yet; should be
//                                vanishingly rare on the dashboard.
//
// Spec parity: `specs/v3/otel-observability.md §8` row for
// `IsolationRespawnAttemptedTotal` plus the V3 Prometheus contract in
// `specs/v3/observability-prometheus.md §3.1`.
// ---------------------------------------------------------------------------

/// Allowed `respawn_kind` label values. Production emit sites MUST
/// pick exactly one of these strings; the unit-test witness for
/// `INV-OBS-RESPAWN-KIND-LABEL-01` re-asserts the closed set.
pub const RESPAWN_KIND_VM_CRASH:               &str = "vm_crash";
/// Orchestrator post-exit respawn (Mode A or Mode B).
pub const RESPAWN_KIND_ORCHESTRATOR_NO_PROGRESS: &str = "orchestrator_no_progress";
/// Reviewer-disagreement-driven `RetrySubTask` continuation respawn.
pub const RESPAWN_KIND_REVIEWER_REJECTION:     &str = "reviewer_rejection";
/// Fallback for code paths whose respawn taxonomy hasn't been mapped.
pub const RESPAWN_KIND_UNKNOWN:                &str = "unknown";

/// Closed set of every `respawn_kind` value the kernel may emit.
/// The dashboard taxonomy at `grafana/dashboards/10-isolation.json`
/// expects exactly this set; the witness test uses this slice to
/// assert no emit site smuggled in a free-form label value.
pub const RESPAWN_KIND_CLOSED_SET: &[&str] = &[
    RESPAWN_KIND_VM_CRASH,
    RESPAWN_KIND_ORCHESTRATOR_NO_PROGRESS,
    RESPAWN_KIND_REVIEWER_REJECTION,
    RESPAWN_KIND_UNKNOWN,
];

/// `raxis.isolation.respawn_attempted.total` — counter, one bump per
/// respawn the kernel schedules. `respawn_kind` MUST be drawn from
/// [`RESPAWN_KIND_CLOSED_SET`]; the redactor caps the value at 32
/// bytes anyway but the closed lexicon is the load-bearing
/// guarantee per `INV-OBS-RESPAWN-KIND-LABEL-01`.
///
/// `backend` mirrors the `IsolationSpawn*` family's `backend` label
/// so dashboards can correlate respawn rates against per-backend
/// cold-boot histograms. `attempt` (1-indexed) lets the
/// dashboard distinguish "first retry" from "third retry" inside
/// the elastic-scaling transient-retry loop; emit sites that have
/// no natural attempt counter (orchestrator post-exit / reviewer-
/// rejection respawns) pass `1`.
pub fn record_isolation_respawn_attempted(
    hub:          &ObservabilityHub,
    backend:      &str,
    image_kind:   &str,
    respawn_kind: &str,
    attempt:      i64,
) {
    if !hub.enabled() { return; }
    let mut labels = redact::attrs([
        ("backend",      backend),
        ("image_kind",   image_kind),
        ("respawn_kind", respawn_kind),
    ]);
    labels.insert(
        "attempt".to_owned(),
        raxis_observability::AttrValue::I64(attempt),
    );
    hub.record_counter(MetricName::IsolationRespawnAttemptedTotal, labels, 1.0);
}

#[cfg(test)]
mod respawn_kind_tests {
    use super::*;
    use raxis_observability::{
        exporter::InMemoryExporter, AttrValue, DataPoint, HubConfig, MetricName,
        ObservabilityExporter, ObservabilityHub,
    };
    use std::sync::Arc;

    fn enabled_hub() -> (Arc<ObservabilityHub>, Arc<InMemoryExporter>) {
        let exp = Arc::new(InMemoryExporter::new());
        let cfg = HubConfig {
            enabled:     true,
            sample_rate: 1.0,
            ..HubConfig::default()
        };
        let hub = Arc::new(ObservabilityHub::new(
            cfg,
            exp.clone() as Arc<dyn ObservabilityExporter>,
        ));
        (hub, exp)
    }

    /// `INV-OBS-RESPAWN-KIND-LABEL-01` witness: every
    /// `record_isolation_respawn_attempted` emission MUST carry a
    /// `respawn_kind` label whose value is in the closed set
    /// [`RESPAWN_KIND_CLOSED_SET`]. This exercises every constant
    /// the production sites use.
    #[test]
    fn every_closed_set_value_is_emitted_with_known_label() {
        for kind in RESPAWN_KIND_CLOSED_SET {
            let (hub, exp) = enabled_hub();
            record_isolation_respawn_attempted(
                hub.as_ref(),
                "subprocess",
                "executor",
                kind,
                1,
            );
            hub.flush();
            let metrics = exp.metrics();
            assert_eq!(
                metrics.len(), 1,
                "expected exactly one metric for kind={kind}",
            );
            let m = &metrics[0];
            assert_eq!(m.name, MetricName::IsolationRespawnAttemptedTotal);
            // Counter shape: Sum { value: 1.0 }.
            assert!(matches!(m.datapoint, DataPoint::Sum { value } if (value - 1.0).abs() < 1e-9));
            let v = m.labels.get("respawn_kind").expect("respawn_kind present");
            match v {
                AttrValue::Str(s) => {
                    assert_eq!(s, kind, "respawn_kind label round-trips verbatim");
                    assert!(
                        RESPAWN_KIND_CLOSED_SET.contains(&s.as_str()),
                        "respawn_kind {s:?} not in closed set",
                    );
                }
                other => panic!("respawn_kind must be a string, got {other:?}"),
            }
        }
    }

    /// Defence-in-depth: the closed set MUST contain exactly the four
    /// constants the spec §8 table enumerates. Adding a fifth without
    /// a spec change would let an emit site smuggle a new lexeme onto
    /// the dashboard.
    #[test]
    fn closed_set_matches_spec_table() {
        let expected = [
            "vm_crash",
            "orchestrator_no_progress",
            "reviewer_rejection",
            "unknown",
        ];
        assert_eq!(RESPAWN_KIND_CLOSED_SET.len(), expected.len());
        for &e in &expected {
            assert!(
                RESPAWN_KIND_CLOSED_SET.contains(&e),
                "spec lexeme {e:?} missing from closed set",
            );
        }
    }
}

// ---------------------------------------------------------------------------
// iter44 perf-metrics — `INV-OBS-KERNEL-RESPAWN-COVERAGE-01`.
//
// `KernelRespawn{Total,Duration}` + `SupervisorRefusedRestartTotal`
// are the operator-visible counterpart to the supervisor's audit
// events `KernelRespawnedBySupervisor` /
// `KernelBootedFromSupervisorRestart` /
// `KernelCrashedBySignal` / `KernelTerminatedByOperator` /
// `SupervisorRefusedRestart` / `SupervisorRestartCeilingExceeded`.
//
// **Recording site rationale.** The supervisor crate
// (`crates/supervisor/`) is deliberately process-isolated from the
// kernel and intentionally takes ZERO `raxis-*` dependencies (per
// `crates/supervisor/src/lib.rs` module-doc + `Cargo.toml` comment).
// Linking `raxis-observability` into the supervisor would (a) break
// that single-responsibility design, (b) introduce a second
// observability ring file owned by the supervisor process, and (c)
// require the supervisor to carry a `parking_lot` + JSONL exporter
// surface it does not otherwise need. The pragmatic alternative —
// recording from the kernel-boot codepath that already reads the
// supervisor's `kernel_lifecycle_status.json` sentinel — keeps the
// audit chain (durable, supervisor-written) the source of truth and
// uses the kernel's existing `ObservabilityHub` for the dashboard
// fast-path.
//
// **Coverage.** The kernel-boot path is a structural witness for
// every `KernelBootedFromSupervisorRestart` (the supervisor wrote
// `Restarting`, the kernel boots, sees the sentinel, emits the
// metric). The `refused_*` outcomes of `KernelRespawnTotal` are
// emitted from the same boot path when the kernel observes a
// `Halted (CircuitOpen)` sentinel — the operator manually bypassed
// the supervisor after a circuit-open episode (forensic-completeness
// counterpart to the supervisor's `SupervisorRefusedRestart` audit
// event the previous run wrote on its way out).
//
// **Closed lexicons.**
//   * `trigger ∈ { deadlock, sigsegv, sigabrt, exit_70, other }` —
//     mapped from the supervisor's `last_restart_reason` PascalCase
//     classification (`DeadlockDetected` / `SignalCrash` /
//     `OomKilled` / `PanicAbort`) plus the prior kernel's
//     `prev_run_exit_code` (128 + signal for signaled exits, the
//     literal exit code for normal exits).
//   * `outcome  ∈ { ok, refused_ceiling, refused_other }` — from
//     the kernel-boot path the value is always `ok` (the kernel did
//     boot, so the respawn succeeded); the `refused_*` outcomes are
//     a future expansion point if the supervisor later links
//     observability cleanly.
//   * `reason   ∈ { circuit_open, operator_stop, operator_stop_forced,
//                   supervisor_gone, other }` — drawn from the
//     supervisor sentinel's `sub_state` field for `Halted` rows.
// ---------------------------------------------------------------------------

/// Trigger lexicon — every `KernelRespawn{Total,Duration}` emission
/// carries `trigger` drawn from this closed set. The dashboard at
/// `grafana/dashboards/00-overview.json` ("Self-healing supervisor")
/// pivots on this label.
pub const RESPAWN_TRIGGER_DEADLOCK: &str = "deadlock";
/// Crash signal SIGSEGV / SIGBUS — load-bearing dashboard label for
/// "the kernel crashed under us, not a deadlock".
pub const RESPAWN_TRIGGER_SIGSEGV: &str = "sigsegv";
/// Crash signal SIGABRT — assertion failure / `panic = abort`.
pub const RESPAWN_TRIGGER_SIGABRT: &str = "sigabrt";
/// Process exit code 70 — the deadlock watcher's classifier exit.
/// Distinguished from `deadlock` because the supervisor's
/// `PanicAbort` classifier maps any non-zero non-70 exit to
/// `PanicAbort{n}`; `exit_70` lets the dashboard separate
/// "watcher-triggered exit" from "kernel deadlock detected by other
/// means".
pub const RESPAWN_TRIGGER_EXIT_70: &str = "exit_70";
/// Anything not covered above — OOM-kill (SIGKILL), SIGHUP, signaled
/// exits whose signal number is unknown.
pub const RESPAWN_TRIGGER_OTHER: &str = "other";

/// Closed set of every `trigger` lexeme the kernel may emit.
pub const RESPAWN_TRIGGER_CLOSED_SET: &[&str] = &[
    RESPAWN_TRIGGER_DEADLOCK,
    RESPAWN_TRIGGER_SIGSEGV,
    RESPAWN_TRIGGER_SIGABRT,
    RESPAWN_TRIGGER_EXIT_70,
    RESPAWN_TRIGGER_OTHER,
];

/// Outcome lexicon — `KernelRespawnTotal` only.
/// `ok` is the only value emitted from the kernel-boot path (the
/// kernel did boot); `refused_ceiling` / `refused_other` are
/// reserved for a future supervisor-side expansion.
pub const RESPAWN_OUTCOME_OK: &str = "ok";
/// Reserved — supervisor-side emission (circuit-breaker tripped).
pub const RESPAWN_OUTCOME_REFUSED_CEILING: &str = "refused_ceiling";
/// Reserved — supervisor-side emission (any other refusal path).
pub const RESPAWN_OUTCOME_REFUSED_OTHER: &str = "refused_other";

/// Closed set of every `outcome` lexeme `KernelRespawnTotal` may
/// carry. The witness test pins these so a future emit site that
/// adds a fifth value without a spec change fails CI.
pub const RESPAWN_OUTCOME_CLOSED_SET: &[&str] = &[
    RESPAWN_OUTCOME_OK,
    RESPAWN_OUTCOME_REFUSED_CEILING,
    RESPAWN_OUTCOME_REFUSED_OTHER,
];

/// `SupervisorRefusedRestartTotal` — `reason` lexicon. Drawn from
/// the supervisor sentinel's `sub_state` field for `Halted` rows;
/// `other` is the fallback for forward-compat with future supervisor
/// revisions that may invent new sub-states.
pub const REFUSED_REASON_CIRCUIT_OPEN:         &str = "circuit_open";
/// Operator initiated the stop (`raxis-supervisor stop` / SIGTERM /
/// SIGINT). Recorded so the dashboard can distinguish "supervisor
/// halted us because the breaker tripped" from "operator
/// deliberately stopped the supervisor".
pub const REFUSED_REASON_OPERATOR_STOP:        &str = "operator_stop";
/// Operator forced the stop (`raxis-supervisor stop --force` /
/// SIGKILL).
pub const REFUSED_REASON_OPERATOR_STOP_FORCED: &str = "operator_stop_forced";
/// Supervisor process is gone — the dashboard's
/// `kernel_lifecycle_status.json` handler synthesises this when the
/// sentinel is stale + the supervisor PID is missing
/// (`SentinelSubState::SupervisorGone`).
pub const REFUSED_REASON_SUPERVISOR_GONE:      &str = "supervisor_gone";
/// Anything else — forward-compat fallback for sub-state values not
/// covered above.
pub const REFUSED_REASON_OTHER:                &str = "other";

/// Closed set of every `reason` lexeme `SupervisorRefusedRestartTotal`
/// may carry.
pub const REFUSED_REASON_CLOSED_SET: &[&str] = &[
    REFUSED_REASON_CIRCUIT_OPEN,
    REFUSED_REASON_OPERATOR_STOP,
    REFUSED_REASON_OPERATOR_STOP_FORCED,
    REFUSED_REASON_SUPERVISOR_GONE,
    REFUSED_REASON_OTHER,
];

/// Histogram bucket boundaries (ms) for `KernelRespawnDuration`.
/// Wide spread per the prompt — kernel respawn ranges from
/// sub-second auto-restart through 5 minute crash-loop back-off.
/// The hub's global default
/// (`[1, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000]`)
/// would lose all resolution past 10 seconds.
pub const RESPAWN_DURATION_BUCKETS_MS: &[f64] = &[
    10.0, 50.0, 100.0, 500.0, 1000.0, 5000.0, 30000.0, 60000.0, 300000.0,
];

/// Map a supervisor `last_restart_reason` (PascalCase, see
/// `crates/supervisor/src/classify.rs::Outcome::reason_str`) plus the
/// prior kernel's `prev_run_exit_code` to the closed `trigger`
/// lexicon.
///
/// Decision table (mirror of
/// `crates/supervisor/src/classify.rs` + the Linux signal-number
/// shell convention `128 + signal`):
///
/// | supervisor reason     | prev_run_exit_code | trigger    |
/// |-----------------------|--------------------|------------|
/// | `DeadlockDetected`    | (any; always 70)   | `deadlock` |
/// | `SignalCrash`         | 139 = 128+11       | `sigsegv`  |
/// | `SignalCrash`         | 134 = 128+6        | `sigabrt`  |
/// | `SignalCrash`         | 135 = 128+7  (BUS) | `sigsegv`  |
/// | `SignalCrash`         | 138 = 128+10 (BUS) | `sigsegv`  |
/// | `SignalCrash`         | other              | `other`    |
/// | `PanicAbort`          | 70                 | `exit_70`  |
/// | `PanicAbort`          | other              | `other`    |
/// | `OomKilled`           | (always 137)       | `other`    |
/// | `CleanExit`           | (any)              | `other`    |
/// | `OperatorSignalExit`  | (any)              | `other`    |
/// | unknown / absent      | (any)              | `other`    |
///
/// The function is total over both inputs — every (reason,
/// exit_code) pair maps to one of [`RESPAWN_TRIGGER_CLOSED_SET`].
pub fn classify_respawn_trigger(
    supervisor_reason: Option<&str>,
    prev_run_exit_code: Option<i32>,
) -> &'static str {
    match supervisor_reason {
        Some("DeadlockDetected") => RESPAWN_TRIGGER_DEADLOCK,
        Some("SignalCrash") => match prev_run_exit_code {
            // SIGSEGV (11), SIGBUS (7 on Linux, 10 on some BSDs).
            Some(139) | Some(135) | Some(138) => RESPAWN_TRIGGER_SIGSEGV,
            // SIGABRT (6).
            Some(134) => RESPAWN_TRIGGER_SIGABRT,
            _ => RESPAWN_TRIGGER_OTHER,
        }
        Some("PanicAbort") if prev_run_exit_code == Some(70) => RESPAWN_TRIGGER_EXIT_70,
        Some("PanicAbort") => RESPAWN_TRIGGER_OTHER,
        _ => RESPAWN_TRIGGER_OTHER,
    }
}

/// Map a supervisor `Halted` sentinel `sub_state` to the closed
/// `reason` lexicon for `SupervisorRefusedRestartTotal`. Total
/// function — every input (including `None` and unknown values)
/// maps to one of [`REFUSED_REASON_CLOSED_SET`].
pub fn supervisor_refused_reason(sub_state: Option<&str>) -> &'static str {
    match sub_state {
        Some("CircuitOpen")        => REFUSED_REASON_CIRCUIT_OPEN,
        Some("OperatorStop")       => REFUSED_REASON_OPERATOR_STOP,
        Some("OperatorStopForced") => REFUSED_REASON_OPERATOR_STOP_FORCED,
        Some("SupervisorGone")     => REFUSED_REASON_SUPERVISOR_GONE,
        _                           => REFUSED_REASON_OTHER,
    }
}

/// `raxis.kernel.respawn.{total,duration}` — emit one counter
/// increment plus one histogram observation for a single
/// supervisor-driven kernel respawn. Called from `kernel/src/main.rs`
/// boot-path Step 8a' after `rehydrate_restart_context` confirms the
/// sentinel said `Restarting`.
///
/// `trigger` MUST be drawn from [`RESPAWN_TRIGGER_CLOSED_SET`];
/// `outcome` MUST be drawn from [`RESPAWN_OUTCOME_CLOSED_SET`].
/// `duration_ms` is the wall-clock supervisor-decision → kernel-up
/// (computed by the caller from the sentinel's
/// `last_restart_unix_ts` and the kernel's wallclock at the call
/// site); pass `None` when the sentinel did not surface a
/// `last_restart_unix_ts` (older supervisor binaries) — only the
/// counter is emitted in that case.
pub fn record_kernel_respawn(
    hub:         &ObservabilityHub,
    trigger:     &str,
    outcome:     &str,
    duration_ms: Option<i64>,
) {
    if !hub.enabled() { return; }
    let labels_total = redact::attrs([
        ("trigger", trigger),
        ("outcome", outcome),
    ]);
    hub.record_counter(MetricName::KernelRespawnTotal, labels_total, 1.0);
    if let Some(ms) = duration_ms {
        let labels_dur = redact::attrs([("trigger", trigger)]);
        hub.record_histogram_with_buckets(
            MetricName::KernelRespawnDuration,
            labels_dur,
            ms.max(0) as f64,
            RESPAWN_DURATION_BUCKETS_MS.to_vec(),
        );
    }
}

/// `raxis.supervisor.refused_restart.total` — emit one counter
/// increment when the kernel boots and observes a `Halted` sentinel
/// (`CircuitOpen` / `OperatorStop` / `OperatorStopForced` /
/// `SupervisorGone`). One bump per kernel boot — the kernel-boot
/// path is the structural witness for "an operator manually bypassed
/// a halted supervisor", which is the operationally interesting
/// event the operator dashboard wants to surface.
pub fn record_supervisor_refused_restart(
    hub:    &ObservabilityHub,
    reason: &str,
) {
    if !hub.enabled() { return; }
    let labels = redact::attrs([("reason", reason)]);
    hub.record_counter(MetricName::SupervisorRefusedRestartTotal, labels, 1.0);
}

#[cfg(test)]
mod kernel_respawn_tests {
    use super::*;
    use raxis_observability::{
        exporter::InMemoryExporter, AttrValue, DataPoint, HubConfig, MetricName,
        ObservabilityExporter, ObservabilityHub,
    };
    use std::sync::Arc;

    fn enabled_hub() -> (Arc<ObservabilityHub>, Arc<InMemoryExporter>) {
        let exp = Arc::new(InMemoryExporter::new());
        let cfg = HubConfig {
            enabled:     true,
            sample_rate: 1.0,
            ..HubConfig::default()
        };
        let hub = Arc::new(ObservabilityHub::new(
            cfg,
            exp.clone() as Arc<dyn ObservabilityExporter>,
        ));
        (hub, exp)
    }

    /// `INV-OBS-KERNEL-RESPAWN-COVERAGE-01` witness #1: every
    /// (`trigger`, `outcome`) pair drawn from the closed lexicons
    /// emits BOTH the counter and the histogram observation, with
    /// the labels the dashboard pivots on.
    #[test]
    fn every_trigger_outcome_pair_emits_paired_metrics() {
        for &trigger in RESPAWN_TRIGGER_CLOSED_SET {
            for &outcome in RESPAWN_OUTCOME_CLOSED_SET {
                let (hub, exp) = enabled_hub();
                record_kernel_respawn(hub.as_ref(), trigger, outcome, Some(1234));
                hub.flush();
                let metrics = exp.metrics();
                assert_eq!(
                    metrics.len(), 2,
                    "expected counter+histogram pair for trigger={trigger} outcome={outcome}",
                );
                let counter = metrics.iter().find(|m| m.name == MetricName::KernelRespawnTotal)
                    .expect("KernelRespawnTotal present");
                let histogram = metrics.iter().find(|m| m.name == MetricName::KernelRespawnDuration)
                    .expect("KernelRespawnDuration present");
                assert!(matches!(
                    counter.datapoint,
                    DataPoint::Sum { value } if (value - 1.0).abs() < 1e-9,
                ));
                match counter.labels.get("trigger").unwrap() {
                    AttrValue::Str(s) => assert_eq!(s, trigger),
                    other            => panic!("trigger must be Str, got {other:?}"),
                }
                match counter.labels.get("outcome").unwrap() {
                    AttrValue::Str(s) => assert_eq!(s, outcome),
                    other            => panic!("outcome must be Str, got {other:?}"),
                }
                match histogram.labels.get("trigger").unwrap() {
                    AttrValue::Str(s) => assert_eq!(s, trigger),
                    other            => panic!("histogram trigger must be Str, got {other:?}"),
                }
                // Histogram's bucket spread must use the iter44
                // wide-bucket override, not the hub's global default.
                if let DataPoint::Histo { ref buckets, .. } = histogram.datapoint {
                    assert_eq!(buckets, RESPAWN_DURATION_BUCKETS_MS,
                        "histogram MUST use the wide kernel-respawn buckets");
                } else {
                    panic!("histogram datapoint must be Histo, got {:?}", histogram.datapoint);
                }
            }
        }
    }

    /// `INV-OBS-KERNEL-RESPAWN-COVERAGE-01` witness #2: when the
    /// sentinel does not surface `last_restart_unix_ts` (older
    /// supervisor binaries pre-iter44) the counter still fires but
    /// the histogram observation is skipped — better to surface the
    /// rate than to lie about latency.
    #[test]
    fn missing_duration_emits_counter_only() {
        let (hub, exp) = enabled_hub();
        record_kernel_respawn(
            hub.as_ref(),
            RESPAWN_TRIGGER_DEADLOCK,
            RESPAWN_OUTCOME_OK,
            None,
        );
        hub.flush();
        let metrics = exp.metrics();
        assert_eq!(metrics.len(), 1);
        assert_eq!(metrics[0].name, MetricName::KernelRespawnTotal);
    }

    /// Defence-in-depth: the closed sets MUST contain exactly the
    /// lexemes the spec §8 table enumerates.
    #[test]
    fn closed_sets_match_spec_tables() {
        let trigger_expected = ["deadlock", "sigsegv", "sigabrt", "exit_70", "other"];
        assert_eq!(RESPAWN_TRIGGER_CLOSED_SET.len(), trigger_expected.len());
        for &e in &trigger_expected {
            assert!(RESPAWN_TRIGGER_CLOSED_SET.contains(&e));
        }
        let outcome_expected = ["ok", "refused_ceiling", "refused_other"];
        assert_eq!(RESPAWN_OUTCOME_CLOSED_SET.len(), outcome_expected.len());
        for &e in &outcome_expected {
            assert!(RESPAWN_OUTCOME_CLOSED_SET.contains(&e));
        }
        let reason_expected = [
            "circuit_open", "operator_stop", "operator_stop_forced",
            "supervisor_gone", "other",
        ];
        assert_eq!(REFUSED_REASON_CLOSED_SET.len(), reason_expected.len());
        for &e in &reason_expected {
            assert!(REFUSED_REASON_CLOSED_SET.contains(&e));
        }
    }

    /// `classify_respawn_trigger` is total — the function must
    /// return one of the closed-set lexemes for every supervisor
    /// reason / exit code combination, including `None`.
    #[test]
    fn classify_respawn_trigger_is_total_and_in_closed_set() {
        let cases: &[(Option<&str>, Option<i32>, &str)] = &[
            (Some("DeadlockDetected"), Some(70),  RESPAWN_TRIGGER_DEADLOCK),
            (Some("DeadlockDetected"), None,      RESPAWN_TRIGGER_DEADLOCK),
            (Some("SignalCrash"),      Some(139), RESPAWN_TRIGGER_SIGSEGV),
            (Some("SignalCrash"),      Some(134), RESPAWN_TRIGGER_SIGABRT),
            (Some("SignalCrash"),      Some(135), RESPAWN_TRIGGER_SIGSEGV),
            (Some("SignalCrash"),      Some(138), RESPAWN_TRIGGER_SIGSEGV),
            (Some("SignalCrash"),      Some(137), RESPAWN_TRIGGER_OTHER),
            (Some("PanicAbort"),       Some(70),  RESPAWN_TRIGGER_EXIT_70),
            (Some("PanicAbort"),       Some(1),   RESPAWN_TRIGGER_OTHER),
            (Some("OomKilled"),        Some(137), RESPAWN_TRIGGER_OTHER),
            (Some("CleanExit"),        Some(0),   RESPAWN_TRIGGER_OTHER),
            (Some("OperatorSignalExit"), Some(143), RESPAWN_TRIGGER_OTHER),
            (None,                     None,      RESPAWN_TRIGGER_OTHER),
            (Some("UnknownFutureValue"), Some(42), RESPAWN_TRIGGER_OTHER),
        ];
        for (reason, exit, want) in cases {
            let got = classify_respawn_trigger(*reason, *exit);
            assert_eq!(got, *want,
                "classify_respawn_trigger({reason:?}, {exit:?}) → {got}, want {want}");
            assert!(RESPAWN_TRIGGER_CLOSED_SET.contains(&got));
        }
    }

    /// `supervisor_refused_reason` is total — every input maps to a
    /// closed-set lexeme.
    #[test]
    fn supervisor_refused_reason_is_total_and_in_closed_set() {
        let cases: &[(Option<&str>, &str)] = &[
            (Some("CircuitOpen"),        REFUSED_REASON_CIRCUIT_OPEN),
            (Some("OperatorStop"),       REFUSED_REASON_OPERATOR_STOP),
            (Some("OperatorStopForced"), REFUSED_REASON_OPERATOR_STOP_FORCED),
            (Some("SupervisorGone"),     REFUSED_REASON_SUPERVISOR_GONE),
            (Some("UnknownFuture"),      REFUSED_REASON_OTHER),
            (None,                       REFUSED_REASON_OTHER),
        ];
        for (sub, want) in cases {
            let got = supervisor_refused_reason(*sub);
            assert_eq!(got, *want);
            assert!(REFUSED_REASON_CLOSED_SET.contains(&got));
        }
    }

    /// `record_supervisor_refused_restart` emits one counter
    /// increment per call, with the closed-lexicon `reason` label.
    #[test]
    fn refused_restart_emits_counter() {
        for &reason in REFUSED_REASON_CLOSED_SET {
            let (hub, exp) = enabled_hub();
            record_supervisor_refused_restart(hub.as_ref(), reason);
            hub.flush();
            let metrics = exp.metrics();
            assert_eq!(metrics.len(), 1);
            assert_eq!(metrics[0].name, MetricName::SupervisorRefusedRestartTotal);
            match metrics[0].labels.get("reason").unwrap() {
                AttrValue::Str(s) => assert_eq!(s, reason),
                other            => panic!("reason must be Str, got {other:?}"),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// iter44 perf-metrics — `IntentAdmitPredicateEvaluatedTotal`.
//
// Every kernel-side admit-predicate evaluation (currently the
// `RetrySubTask` retry-eligibility check; future commits broaden to
// other intents that compute server-side admissibility) emits one
// counter increment labelled with:
//
//   * `intent_kind`  — closed lexicon already pinned by `IntentKind::*`.
//   * `admissible`   — Bool; true iff the predicate accepted the
//                      intent.
//   * `reason`       — closed lexicon below.
//
// The dashboard's "LLM blind-ask rate" panel
// (`grafana/dashboards/40-planner.json`) divides
// `admissible="false"` by total to show the trend toward zero as the
// KSB-capabilities envelope (in flight on a sibling worker branch)
// teaches the planner not to submit known-inadmissible intents in
// the first place. A non-decreasing rate after that landing is a
// regression signal.
// ---------------------------------------------------------------------------

/// Predicate evaluation succeeded; the intent was accepted.
pub const ADMIT_REASON_OK:                 &str = "ok";
/// The retry was rejected because the prior activation row was in
/// a state for which retry is not legal (e.g. `Completed` without a
/// review-rejection witness).
pub const ADMIT_REASON_RETRY_INADMISSIBLE: &str = "retry_inadmissible";
/// The retry was rejected because the per-task ceiling
/// (`max_crash_retries` / `max_review_rejections`) is exhausted.
pub const ADMIT_REASON_BUDGET_EXHAUSTED:   &str = "budget_exhausted";
/// The intent referenced an unknown task / lane / activation —
/// useful for the kernel-store gate when it cannot resolve the
/// addressee row.
pub const ADMIT_REASON_UNKNOWN_LANE:       &str = "unknown_lane";
/// Anything else (DB error, FSM gate violation, transactional
/// fault). Should be vanishingly rare on the dashboard.
pub const ADMIT_REASON_OTHER:              &str = "other";

/// Closed set of admit-predicate `reason` lexemes. The dashboard
/// PromQL pivots on this set; an emit site that smuggled in a
/// free-form value would show up as a stray series.
pub const ADMIT_REASON_CLOSED_SET: &[&str] = &[
    ADMIT_REASON_OK,
    ADMIT_REASON_RETRY_INADMISSIBLE,
    ADMIT_REASON_BUDGET_EXHAUSTED,
    ADMIT_REASON_UNKNOWN_LANE,
    ADMIT_REASON_OTHER,
];

/// `raxis.intent.admit_predicate.evaluated.total` — one counter
/// increment per server-side admit-predicate evaluation. Emit
/// alongside the audit/eprintln payload, so dashboard rate ==
/// audit rate and the operator can pivot from one to the other.
pub fn record_intent_admit_predicate(
    hub:         &ObservabilityHub,
    intent_kind: &str,
    admissible:  bool,
    reason:      &str,
) {
    if !hub.enabled() { return; }
    let mut labels = redact::attrs([
        ("intent_kind", intent_kind),
        ("reason",      reason),
    ]);
    labels.insert(
        "admissible".to_owned(),
        raxis_observability::AttrValue::Bool(admissible),
    );
    hub.record_counter(
        MetricName::IntentAdmitPredicateEvaluatedTotal,
        labels,
        1.0,
    );
}

#[cfg(test)]
mod admit_predicate_tests {
    use super::*;
    use raxis_observability::{
        exporter::InMemoryExporter, AttrValue, DataPoint, HubConfig, MetricName,
        ObservabilityExporter, ObservabilityHub,
    };
    use std::sync::Arc;

    fn enabled_hub() -> (Arc<ObservabilityHub>, Arc<InMemoryExporter>) {
        let exp = Arc::new(InMemoryExporter::new());
        let cfg = HubConfig {
            enabled:     true,
            sample_rate: 1.0,
            ..HubConfig::default()
        };
        let hub = Arc::new(ObservabilityHub::new(
            cfg,
            exp.clone() as Arc<dyn ObservabilityExporter>,
        ));
        (hub, exp)
    }

    /// Every closed-set `reason` value emits with the matching label.
    /// Pins the v1 dashboard PromQL surface against accidental
    /// free-form-string drift.
    #[test]
    fn every_reason_emits_with_known_label() {
        for &reason in ADMIT_REASON_CLOSED_SET {
            let admissible = reason == ADMIT_REASON_OK;
            let (hub, exp) = enabled_hub();
            record_intent_admit_predicate(
                hub.as_ref(),
                "RetrySubTask",
                admissible,
                reason,
            );
            hub.flush();
            let metrics = exp.metrics();
            assert_eq!(metrics.len(), 1);
            let m = &metrics[0];
            assert_eq!(m.name, MetricName::IntentAdmitPredicateEvaluatedTotal);
            assert!(matches!(
                m.datapoint,
                DataPoint::Sum { value } if (value - 1.0).abs() < 1e-9,
            ));
            match m.labels.get("reason").unwrap() {
                AttrValue::Str(s) => assert_eq!(s, reason),
                other            => panic!("reason must be Str, got {other:?}"),
            }
            match m.labels.get("admissible").unwrap() {
                AttrValue::Bool(b) => assert_eq!(*b, admissible),
                other              => panic!("admissible must be Bool, got {other:?}"),
            }
            match m.labels.get("intent_kind").unwrap() {
                AttrValue::Str(s) => assert_eq!(s, "RetrySubTask"),
                other             => panic!("intent_kind must be Str, got {other:?}"),
            }
        }
    }
}

// iter44 perf-metrics — `INV-OBS-OPERATOR-IPC-COVERAGE-01`.
//
// `OperatorIpcDuration` (Histogram, ms) + `OperatorIpcTotal` (Counter)
// are emitted from `kernel/src/ipc/operator.rs::dispatch_loop` once
// per operator IPC frame — after the response is built and just before
// `write_json_frame_async` ships it back to the CLI. The dispatcher
// owns the timer that brackets the full pre-handler pipeline
// (permitted_ops gate + cert four-zone gate + handler dispatch),
// matching the latency the operator sees on the CLI side.
//
// **Closed `command_kind` lexicon.** Every `OperatorRequest` variant
// in `raxis_types::operator_wire` maps to a distinct `command_kind`
// label value drawn from [`COMMAND_KIND_CLOSED_SET`]. The mapping
// helper [`operator_command_kind`] is total over the enum (the
// compiler enforces exhaustiveness via the match arm), and the
// witness test [`operator_ipc_tests::closed_set_matches_op_name_table`]
// pins the lexemes against the dispatcher's `op_name` snake_case
// projection.
//
// **`accepted` semantics.** `accepted = true` iff the response is
// NOT `OperatorResponse::Error` — i.e. the dispatcher returned a
// structured success envelope (including `Ack`). The four pre-handler
// failure modes (`INVALID_REQUEST` from frame decode failure,
// `UNAUTHORIZED` from the `permitted_ops` gate, the cert four-zone
// `Deny` envelope, and any handler-side `Error` envelope) all map to
// `accepted = false`; the dashboard pivots on this label to surface
// rejection rate per command.
// ---------------------------------------------------------------------------

/// Closed `command_kind` lexicon for the operator IPC family. Every
/// `OperatorRequest` variant produces exactly one of these values via
/// [`operator_command_kind`]. Adding a new request variant MUST extend
/// both this slice AND the match arm; the witness tests keep them in
/// lock-step.
pub const COMMAND_KIND_CREATE_SESSION:             &str = "create_session";
/// Operator-initiated session revocation.
pub const COMMAND_KIND_REVOKE_SESSION:             &str = "revoke_session";
/// Operator-initiated delegation grant.
pub const COMMAND_KIND_GRANT_DELEGATION:           &str = "grant_delegation";
/// Plan-bundle-sealed initiative creation.
pub const COMMAND_KIND_CREATE_INITIATIVE:          &str = "create_initiative";
/// Operator approves an admission-pending plan.
pub const COMMAND_KIND_APPROVE_PLAN:               &str = "approve_plan";
/// Operator rejects an admission-pending plan.
pub const COMMAND_KIND_REJECT_PLAN:                &str = "reject_plan";
/// Operator aborts an in-flight task.
pub const COMMAND_KIND_ABORT_TASK:                 &str = "abort_task";
/// Operator resumes a paused task.
pub const COMMAND_KIND_RESUME_TASK:                &str = "resume_task";
/// Operator retries a failed task (`RetryTask` lifecycle FSM step).
pub const COMMAND_KIND_RETRY_TASK:                 &str = "retry_task";
/// Operator aborts an in-flight initiative.
pub const COMMAND_KIND_ABORT_INITIATIVE:           &str = "abort_initiative";
/// Operator approves a planner-submitted escalation.
pub const COMMAND_KIND_APPROVE_ESCALATION:         &str = "approve_escalation";
/// Operator denies a planner-submitted escalation.
pub const COMMAND_KIND_DENY_ESCALATION:            &str = "deny_escalation";
/// Operator rotates the active policy artifact in-process.
pub const COMMAND_KIND_ROTATE_EPOCH:               &str = "rotate_epoch";
/// Operator quarantines a single initiative.
pub const COMMAND_KIND_QUARANTINE_INITIATIVE:      &str = "quarantine_initiative";
/// Operator quarantines every initiative whose plan a given
/// fingerprint signed.
pub const COMMAND_KIND_QUARANTINE_PLANS_BY:        &str = "quarantine_plans_by";
/// V2_GAPS §12.4 — operator-ergonomics `propose-defaults` stub.
pub const COMMAND_KIND_PROPOSE_DEFAULTS:           &str = "propose_defaults";
/// V2_GAPS §12.4 — operator-ergonomics `cost-estimate` stub.
pub const COMMAND_KIND_ESTIMATE_COST:              &str = "estimate_cost";
/// V2_GAPS §12.4 — operator-ergonomics `submit --dry-run` stub.
pub const COMMAND_KIND_DRY_RUN_ADMIT:              &str = "dry_run_admit";
/// V2_GAPS §12.4 — operator-ergonomics `initiative watch` stub.
pub const COMMAND_KIND_SUBSCRIBE_INITIATIVE:       &str = "subscribe_initiative";
/// V2_GAPS §12.4 — operator-ergonomics `initiative resume` stub.
pub const COMMAND_KIND_DESCRIBE_INITIATIVE_PAUSE:  &str = "describe_initiative_pause";
/// V2_extended_gaps §3.2 — `task outputs` listing.
pub const COMMAND_KIND_LIST_TASK_OUTPUTS:          &str = "list_task_outputs";
/// Forward-compat fallback for any future variant the
/// [`operator_command_kind`] mapping has not yet been extended for.
/// The witness test pins this to a wire never produced by today's
/// dispatcher (the match arm is exhaustive) — its sole purpose is to
/// keep the closed lexicon stable across future variant additions
/// during the brief moment between adding the variant and updating
/// the match arm.
pub const COMMAND_KIND_UNKNOWN:                    &str = "unknown";

/// Closed set of every `command_kind` lexeme the operator IPC
/// dispatcher may emit. The dashboard PromQL pivots on this set; an
/// emit site that smuggled in a free-form value would show up as a
/// stray series.
pub const COMMAND_KIND_CLOSED_SET: &[&str] = &[
    COMMAND_KIND_CREATE_SESSION,
    COMMAND_KIND_REVOKE_SESSION,
    COMMAND_KIND_GRANT_DELEGATION,
    COMMAND_KIND_CREATE_INITIATIVE,
    COMMAND_KIND_APPROVE_PLAN,
    COMMAND_KIND_REJECT_PLAN,
    COMMAND_KIND_ABORT_TASK,
    COMMAND_KIND_RESUME_TASK,
    COMMAND_KIND_RETRY_TASK,
    COMMAND_KIND_ABORT_INITIATIVE,
    COMMAND_KIND_APPROVE_ESCALATION,
    COMMAND_KIND_DENY_ESCALATION,
    COMMAND_KIND_ROTATE_EPOCH,
    COMMAND_KIND_QUARANTINE_INITIATIVE,
    COMMAND_KIND_QUARANTINE_PLANS_BY,
    COMMAND_KIND_PROPOSE_DEFAULTS,
    COMMAND_KIND_ESTIMATE_COST,
    COMMAND_KIND_DRY_RUN_ADMIT,
    COMMAND_KIND_SUBSCRIBE_INITIATIVE,
    COMMAND_KIND_DESCRIBE_INITIATIVE_PAUSE,
    COMMAND_KIND_LIST_TASK_OUTPUTS,
    COMMAND_KIND_UNKNOWN,
];

/// Histogram bucket boundaries (ms) for `OperatorIpcDuration`.
/// Operator commands are typically fast (FSM transitions on
/// committed state) but escalation approval / plan-bundle admission
/// can take several hundred milliseconds when signature verification
/// is on the critical path. The wider 2.5s / 5s tail buckets cover
/// crash-loop and fail-closed paths where the kernel is
/// pathologically slow but still responding.
pub const OPERATOR_IPC_BUCKETS_MS: &[f64] = &[
    1.0, 5.0, 10.0, 25.0, 50.0, 100.0, 250.0, 500.0, 1000.0, 2500.0, 5000.0,
];

/// Map an `OperatorRequest` to its closed `command_kind` lexeme.
/// The match arm is exhaustive over `raxis_types::operator_wire::
/// OperatorRequest`; adding a new variant produces a compile error
/// here, which is the structural guarantee that the closed lexicon
/// stays in sync with the wire enum.
///
/// The lexeme is a `snake_case` projection of the variant name, kept
/// verbatim in [`COMMAND_KIND_CLOSED_SET`] so the witness test can
/// pin the byte shape.
pub fn operator_command_kind(
    req: &raxis_types::operator_wire::OperatorRequest,
) -> &'static str {
    use raxis_types::operator_wire::OperatorRequest as R;
    match req {
        R::CreateSession            { .. } => COMMAND_KIND_CREATE_SESSION,
        R::RevokeSession            { .. } => COMMAND_KIND_REVOKE_SESSION,
        R::GrantDelegation          { .. } => COMMAND_KIND_GRANT_DELEGATION,
        R::CreateInitiative         { .. } => COMMAND_KIND_CREATE_INITIATIVE,
        R::ApprovePlan              { .. } => COMMAND_KIND_APPROVE_PLAN,
        R::RejectPlan               { .. } => COMMAND_KIND_REJECT_PLAN,
        R::AbortInitiative          { .. } => COMMAND_KIND_ABORT_INITIATIVE,
        R::AbortTask                { .. } => COMMAND_KIND_ABORT_TASK,
        R::ResumeTask               { .. } => COMMAND_KIND_RESUME_TASK,
        R::RetryTask                { .. } => COMMAND_KIND_RETRY_TASK,
        R::ApproveEscalation        { .. } => COMMAND_KIND_APPROVE_ESCALATION,
        R::DenyEscalation           { .. } => COMMAND_KIND_DENY_ESCALATION,
        R::RotateEpoch              { .. } => COMMAND_KIND_ROTATE_EPOCH,
        R::QuarantineInitiative     { .. } => COMMAND_KIND_QUARANTINE_INITIATIVE,
        R::QuarantinePlansBy        { .. } => COMMAND_KIND_QUARANTINE_PLANS_BY,
        R::ProposeDefaults          { .. } => COMMAND_KIND_PROPOSE_DEFAULTS,
        R::EstimateCost             { .. } => COMMAND_KIND_ESTIMATE_COST,
        R::DryRunAdmit              { .. } => COMMAND_KIND_DRY_RUN_ADMIT,
        R::SubscribeInitiative      { .. } => COMMAND_KIND_SUBSCRIBE_INITIATIVE,
        R::DescribeInitiativePause  { .. } => COMMAND_KIND_DESCRIBE_INITIATIVE_PAUSE,
        R::ListTaskOutputs          { .. } => COMMAND_KIND_LIST_TASK_OUTPUTS,
    }
}

/// Map an `OperatorResponse` to the `accepted` boolean label.
///
/// `accepted = false` iff the response is `OperatorResponse::Error`
/// (the sole error envelope per `peripherals.md §3 "Operator
/// socket"`); every other variant — including the generic `Ack` —
/// is a structured success and maps to `accepted = true`.
pub fn operator_response_accepted(
    resp: &raxis_types::operator_wire::OperatorResponse,
) -> bool {
    !matches!(
        resp,
        raxis_types::operator_wire::OperatorResponse::Error { .. },
    )
}

/// `raxis.operator.ipc.{total,duration}` — emit one counter
/// increment plus one histogram observation for a single operator
/// IPC frame. Called from `kernel/src/ipc/operator.rs::dispatch_loop`
/// after the response is built and just before
/// `write_json_frame_async` ships it back to the CLI.
///
/// `command_kind` MUST be drawn from [`COMMAND_KIND_CLOSED_SET`]
/// (use [`operator_command_kind`]). `accepted` MUST be derived from
/// [`operator_response_accepted`]. `duration_ms` is the wall-clock
/// from frame-received to response-built (the dispatcher's existing
/// `started.elapsed()` timer).
pub fn record_operator_ipc(
    hub:          &ObservabilityHub,
    command_kind: &str,
    accepted:     bool,
    duration_ms:  i64,
) {
    if !hub.enabled() { return; }
    let mut labels = redact::attrs([("command_kind", command_kind)]);
    labels.insert(
        "accepted".to_owned(),
        raxis_observability::AttrValue::Bool(accepted),
    );
    hub.record_counter(MetricName::OperatorIpcTotal, labels.clone(), 1.0);
    hub.record_histogram_with_buckets(
        MetricName::OperatorIpcDuration,
        labels,
        duration_ms.max(0) as f64,
        OPERATOR_IPC_BUCKETS_MS.to_vec(),
    );
}

#[cfg(test)]
mod operator_ipc_tests {
    use super::*;
    use raxis_observability::{
        exporter::InMemoryExporter, AttrValue, DataPoint, HubConfig, MetricName,
        ObservabilityExporter, ObservabilityHub,
    };
    use raxis_types::operator_wire::{
        ApprovalScopeWire, OperatorRequest, OperatorResponse,
    };
    use std::sync::Arc;

    fn enabled_hub() -> (Arc<ObservabilityHub>, Arc<InMemoryExporter>) {
        let exp = Arc::new(InMemoryExporter::new());
        let cfg = HubConfig {
            enabled:     true,
            sample_rate: 1.0,
            ..HubConfig::default()
        };
        let hub = Arc::new(ObservabilityHub::new(
            cfg,
            exp.clone() as Arc<dyn ObservabilityExporter>,
        ));
        (hub, exp)
    }

    /// Construct one fixture instance per `OperatorRequest` variant.
    /// Adding a new variant produces a compile error in
    /// [`operator_command_kind`], which forces this list to be
    /// updated alongside the closed lexicon.
    fn every_operator_request() -> Vec<OperatorRequest> {
        vec![
            OperatorRequest::CreateSession {
                role:              "planner".into(),
                worktree_root:     None,
                base_sha:          None,
                base_tracking_ref: None,
                lineage_id:        "lin-1".into(),
                task_id:           None,
            },
            OperatorRequest::RevokeSession { session_id: "sess-1".into() },
            OperatorRequest::GrantDelegation {
                session_id:       "sess-1".into(),
                delegation_id:    "del-1".into(),
                capability_class: "FsRead".into(),
                scope_json:       None,
                ttl_secs:         3600,
                max_uses:         Some(10),
                signature_hex:    "deadbeef".into(),
            },
            OperatorRequest::CreateInitiative {
                initiative_id:     "init-1".into(),
                plan_bundle_hex:   "deadbeef".into(),
                bundle_sha256_hex: "ab".repeat(32),
                signature_hex:     "cd".repeat(64),
                signed_by_hex:     "ef".repeat(8),
            },
            OperatorRequest::ApprovePlan {
                initiative_id:      "init-1".into(),
                approving_operator: "op-prime".into(),
            },
            OperatorRequest::RejectPlan {
                initiative_id: "init-1".into(),
                rejected_by:   "op-prime".into(),
                reason:        None,
            },
            OperatorRequest::AbortInitiative {
                initiative_id: "init-1".into(),
                aborted_by:    "op-prime".into(),
            },
            OperatorRequest::AbortTask {
                task_id:    "t1".into(),
                aborted_by: "op-prime".into(),
            },
            OperatorRequest::ResumeTask {
                task_id:    "t1".into(),
                resumed_by: "op-prime".into(),
            },
            OperatorRequest::RetryTask { task_id: "t1".into() },
            OperatorRequest::ApproveEscalation {
                escalation_id:    "esc-1".into(),
                approval_scope:   ApprovalScopeWire {
                    capability_class:  "WriteSecrets".into(),
                    max_uses:          1,
                    valid_for_seconds: 3600,
                },
                operator_sig_hex: "deadbeef".into(),
            },
            OperatorRequest::DenyEscalation {
                escalation_id: "esc-1".into(),
                reason:        None,
            },
            OperatorRequest::RotateEpoch {
                policy_path: "/p".into(),
                sig_path:    "/s".into(),
            },
            OperatorRequest::QuarantineInitiative {
                initiative_id: "init-1".into(),
                reason:        None,
            },
            OperatorRequest::QuarantinePlansBy {
                target_fingerprint: "ab".repeat(8),
                reason:             None,
            },
            OperatorRequest::ProposeDefaults { initiative_id: None },
            OperatorRequest::EstimateCost {
                plan_toml:    "[[tasks]]".into(),
                plan_sig_hex: "ab".into(),
            },
            OperatorRequest::DryRunAdmit {
                plan_toml:    "[[tasks]]".into(),
                plan_sig_hex: "ab".into(),
                submitted_by: "op-prime".into(),
            },
            OperatorRequest::SubscribeInitiative {
                initiative_id: "init-1".into(),
            },
            OperatorRequest::DescribeInitiativePause {
                initiative_id: "init-1".into(),
            },
            OperatorRequest::ListTaskOutputs { task_id: "t1".into() },
        ]
    }

    /// `INV-OBS-OPERATOR-IPC-COVERAGE-01` witness #1: every
    /// `OperatorRequest` variant maps to a closed-lexicon
    /// `command_kind` and a `record_operator_ipc` call emits BOTH
    /// the counter and the histogram observation, with the labels
    /// the dashboard pivots on.
    #[test]
    fn every_variant_emits_paired_metrics() {
        for req in every_operator_request() {
            let kind = operator_command_kind(&req);
            assert!(
                COMMAND_KIND_CLOSED_SET.contains(&kind),
                "command_kind {kind:?} for {req:?} not in closed set",
            );
            let (hub, exp) = enabled_hub();
            record_operator_ipc(hub.as_ref(), kind, true, 42);
            hub.flush();
            let metrics = exp.metrics();
            assert_eq!(
                metrics.len(), 2,
                "expected counter+histogram pair for {req:?} (kind={kind})",
            );
            let counter = metrics.iter().find(|m| m.name == MetricName::OperatorIpcTotal)
                .expect("OperatorIpcTotal present");
            let histogram = metrics.iter().find(|m| m.name == MetricName::OperatorIpcDuration)
                .expect("OperatorIpcDuration present");
            assert!(matches!(
                counter.datapoint,
                DataPoint::Sum { value } if (value - 1.0).abs() < 1e-9,
            ));
            match counter.labels.get("command_kind").unwrap() {
                AttrValue::Str(s) => assert_eq!(s, kind),
                other            => panic!("command_kind must be Str, got {other:?}"),
            }
            match counter.labels.get("accepted").unwrap() {
                AttrValue::Bool(b) => assert!(*b),
                other              => panic!("accepted must be Bool, got {other:?}"),
            }
            // Histogram MUST use the iter44 operator-IPC bucket
            // override, not the hub's global default.
            if let DataPoint::Histo { ref buckets, .. } = histogram.datapoint {
                assert_eq!(buckets, OPERATOR_IPC_BUCKETS_MS,
                    "histogram MUST use the iter44 operator-IPC buckets");
            } else {
                panic!("histogram datapoint must be Histo, got {:?}", histogram.datapoint);
            }
        }
    }

    /// `INV-OBS-OPERATOR-IPC-COVERAGE-01` witness #2: rejected
    /// frames flip `accepted = false` regardless of the originating
    /// variant. Pins the `accepted` semantics — `Error` is the sole
    /// `accepted = false` response.
    #[test]
    fn rejected_response_emits_accepted_false() {
        let (hub, exp) = enabled_hub();
        let kind = COMMAND_KIND_APPROVE_PLAN;
        let resp = OperatorResponse::Error {
            code:   "FAIL_APPROVE_PLAN".into(),
            detail: "bad signature".into(),
        };
        assert!(!operator_response_accepted(&resp));
        record_operator_ipc(hub.as_ref(), kind, false, 17);
        hub.flush();
        let metrics = exp.metrics();
        assert_eq!(metrics.len(), 2);
        for m in &metrics {
            match m.labels.get("accepted").unwrap() {
                AttrValue::Bool(b) => assert!(!*b),
                other              => panic!("accepted must be Bool, got {other:?}"),
            }
        }
    }

    /// Defence-in-depth: every closed-set lexeme MUST be reachable
    /// from at least one `OperatorRequest` variant via
    /// [`operator_command_kind`] (or be `unknown` — the forward-
    /// compat reservation). Pins the closed lexicon against typos
    /// in either direction.
    #[test]
    fn closed_set_matches_op_name_table() {
        let mut covered = std::collections::HashSet::new();
        for req in every_operator_request() {
            covered.insert(operator_command_kind(&req));
        }
        for &lex in COMMAND_KIND_CLOSED_SET {
            assert!(
                lex == COMMAND_KIND_UNKNOWN || covered.contains(lex),
                "closed-set lexeme {lex:?} unreachable from any \
                 OperatorRequest variant",
            );
        }
        // And the inverse — every variant produces a closed-set
        // value (excluding `unknown`).
        for req in every_operator_request() {
            let kind = operator_command_kind(&req);
            assert!(COMMAND_KIND_CLOSED_SET.contains(&kind));
            assert_ne!(kind, COMMAND_KIND_UNKNOWN,
                "operator_command_kind MUST NOT return `unknown` for \
                 a known variant ({req:?})");
        }
    }

    /// `operator_response_accepted` is total over the response
    /// envelope; pin the boolean projection so a future variant
    /// addition cannot silently flip a success → false (or vice
    /// versa).
    #[test]
    fn response_accepted_is_total() {
        // Every non-Error envelope must flip true.
        let success = vec![
            OperatorResponse::Ack { message: "ok".into() },
            OperatorResponse::SessionRevoked {
                session_id: "s".into(), revoked_at: 0,
            },
            OperatorResponse::PlanApproved {
                initiative_id: "i".into(), tasks_admitted: 0,
            },
            OperatorResponse::EpochAdvanced {
                new_epoch_id: 1, policy_sha256: "ab".into(),
                signed_by_authority: "cd".into(),
                n_delegations_marked_stale: 0,
                n_sessions_invalidated: 0,
                advanced_at: 0,
            },
        ];
        for r in &success {
            assert!(operator_response_accepted(r),
                "non-Error response must report accepted=true ({r:?})");
        }
        let err = OperatorResponse::Error {
            code: "E".into(), detail: "d".into(),
        };
        assert!(!operator_response_accepted(&err));
    }
}

// ---------------------------------------------------------------------------
// iter44 perf-metrics — `INV-OBS-IPC-ROUNDTRIP-COVERAGE-01`.
//
// Three metrics covering every kernel↔substrate IPC frame the planner-
// socket dispatcher (`kernel/src/ipc/server.rs::drive_planner_stream`)
// consumes — the convergence point for both production vsock streams
// (AVF / Firecracker substrate per
// `crate::session_spawn_orchestrator::spawn_planner_dispatcher`) and
// the in-process Unix-socket test stream (`accept_planner_loop`).
//
//   * `KernelSubstrateIpcRoundtripDuration` (Histogram, ms) — labels:
//     `role` (closed allow-list = [`KERNEL_SUBSTRATE_IPC_ROLE_CLOSED_SET`]),
//     `message_kind` (closed allow-list =
//     [`KERNEL_SUBSTRATE_IPC_MESSAGE_KIND_CLOSED_SET`]). Wall-clock
//     from frame-received to response-frame-written (or, for the
//     `unexpected` arm, from frame-received to drop). Bucket override
//     [`KERNEL_SUBSTRATE_IPC_BUCKETS_MS`] = `[1, 5, 10, 25, 50, 100,
//     250, 500, 1000, 2500, 5000]` ms — substrate IPC round-trips are
//     typically sub-millisecond (ksb-update probes) through a few
//     hundred ms (PlannerFetchRequest tool calls to LLM providers via
//     gateway).
//   * `KernelSubstrateIpcMessagesTotal`     (Counter)       — same
//     labels. One increment per dispatched frame regardless of
//     handler outcome — the `unexpected` arm increments too, proving
//     the closed lexicon stays total over [`raxis_ipc::IpcMessage`].
//   * `KernelSubstrateIpcInflight`          (Gauge)         — labels:
//     `role` only. Module-global counter that increments before the
//     per-variant handler runs and decrements after the response
//     frame is written, regardless of handler outcome. Re-emitted on
//     every increment / decrement so the gauge tracks actual
//     concurrency across all live planner streams.
//
// **Closed `role` lexicon.** Every dispatched `IpcMessage` variant
// maps to one of `{ "planner", "verifier", "gateway", "unknown" }`.
// `planner` covers IntentRequest, EscalationRequest, and
// PlannerFetchRequest (the orchestrator subprocess's three outbound
// frame kinds). `verifier` covers WitnessSubmission (verifier
// subprocesses route through the same dispatcher per
// `v2/peripherals.md §2.2`). `gateway` is reserved for a future
// gateway-side dispatcher migration (slice 4c+); zero emission today
// keeps the closed lexicon stable. `unknown` is the forward-compat
// fallback for variants that arrive on planner.sock without an
// expected handler (`KernelIntentResponse`, `OperatorRequest`, etc.
// — wire-shape oddities that the dispatcher logs but does not
// process).
//
// **Closed `message_kind` lexicon.** Every dispatched `IpcMessage`
// variant maps to one of `{ "intent_request", "witness_submission",
// "escalation_request", "planner_fetch_request", "unexpected" }`.
// The lexeme is a `snake_case` projection of the request variant
// name; every non-dispatched variant collapses to `unexpected` so
// the dashboard's "Messages by kind" panel can pivot on a stable
// set even as new wire variants are added.
//
// **Inflight semantics.** The dispatcher increments the gauge before
// calling the handler and decrements it after writing the response
// frame, regardless of handler outcome — including frame-decode
// errors propagated via `?` from `write_frame`. The RAII guard
// [`KernelSubstrateIpcRoundtrip`] enforces this by emitting the
// histogram + counter + decrement in its `Drop`; any path that
// drops the guard (normal return, early `?` propagation, panic
// unwind) flushes the metrics.
// ---------------------------------------------------------------------------

/// Closed `role` lexicon for the kernel↔substrate IPC family. Every
/// dispatched [`raxis_ipc::IpcMessage`] variant maps to exactly one
/// of these values via [`kernel_substrate_ipc_route`].
pub const IPC_ROLE_PLANNER:  &str = "planner";
/// Verifier-subprocess role. Pairs with `message_kind =
/// witness_submission`.
pub const IPC_ROLE_VERIFIER: &str = "verifier";
/// Reserved for a future gateway-side dispatcher migration (slice
/// 4c+). Pinned in the closed set so the dashboard PromQL stays
/// stable when the gateway dispatcher starts emitting.
pub const IPC_ROLE_GATEWAY:  &str = "gateway";
/// Forward-compat fallback for any [`raxis_ipc::IpcMessage`] variant
/// that arrives on the planner socket without an expected handler.
/// Pairs with `message_kind = unexpected`.
pub const IPC_ROLE_UNKNOWN:  &str = "unknown";

/// Closed set of every `role` lexeme the kernel↔substrate IPC
/// dispatcher may emit. The dashboard PromQL pivots on this set;
/// an emit site that smuggled in a free-form value would show up as
/// a stray series.
pub const KERNEL_SUBSTRATE_IPC_ROLE_CLOSED_SET: &[&str] = &[
    IPC_ROLE_PLANNER,
    IPC_ROLE_VERIFIER,
    IPC_ROLE_GATEWAY,
    IPC_ROLE_UNKNOWN,
];

/// Closed `message_kind` lexicon. The lexeme is the snake_case
/// projection of the dispatched [`raxis_ipc::IpcMessage`] request
/// variant; every non-dispatched variant collapses to
/// [`IPC_MSG_KIND_UNEXPECTED`].
pub const IPC_MSG_KIND_INTENT_REQUEST:        &str = "intent_request";
/// Pairs with `role = verifier`. Witness submission from a verifier
/// subprocess.
pub const IPC_MSG_KIND_WITNESS_SUBMISSION:    &str = "witness_submission";
/// Pairs with `role = planner`. Escalation request from the
/// orchestrator subprocess.
pub const IPC_MSG_KIND_ESCALATION_REQUEST:    &str = "escalation_request";
/// Pairs with `role = planner`. Gateway-mediated egress request.
pub const IPC_MSG_KIND_PLANNER_FETCH_REQUEST: &str = "planner_fetch_request";
/// Pairs with `role = unknown`. Any [`raxis_ipc::IpcMessage`]
/// variant that arrives on planner.sock without an expected handler
/// (response variants, operator-socket variants routed to the wrong
/// socket, etc.). Keeps the closed lexicon stable across future
/// wire-variant additions.
pub const IPC_MSG_KIND_UNEXPECTED:            &str = "unexpected";

/// Closed set of every `message_kind` lexeme the kernel↔substrate
/// IPC dispatcher may emit.
pub const KERNEL_SUBSTRATE_IPC_MESSAGE_KIND_CLOSED_SET: &[&str] = &[
    IPC_MSG_KIND_INTENT_REQUEST,
    IPC_MSG_KIND_WITNESS_SUBMISSION,
    IPC_MSG_KIND_ESCALATION_REQUEST,
    IPC_MSG_KIND_PLANNER_FETCH_REQUEST,
    IPC_MSG_KIND_UNEXPECTED,
];

/// Histogram bucket boundaries (ms) for
/// `KernelSubstrateIpcRoundtripDuration`. Substrate IPC round-trips
/// span sub-millisecond ksb-update probes through multi-second
/// `PlannerFetchRequest` tool calls (LLM provider invocations via
/// the gateway). The 2.5s / 5s tail buckets cover provider stalls
/// and crash-loop pathologies.
pub const KERNEL_SUBSTRATE_IPC_BUCKETS_MS: &[f64] = &[
    1.0, 5.0, 10.0, 25.0, 50.0, 100.0, 250.0, 500.0, 1000.0, 2500.0, 5000.0,
];

/// Map an [`raxis_ipc::IpcMessage`] to its closed-lexicon `(role,
/// message_kind)` pair. The match arm is exhaustive over the wire
/// enum; adding a new variant produces a compile error here, which
/// is the structural guarantee that the closed lexicons stay total.
pub fn kernel_substrate_ipc_route(
    msg: &raxis_ipc::IpcMessage,
) -> (&'static str, &'static str) {
    use raxis_ipc::IpcMessage as M;
    match msg {
        // ── Dispatched on planner.sock ──
        M::IntentRequest(_)         => (IPC_ROLE_PLANNER,  IPC_MSG_KIND_INTENT_REQUEST),
        M::WitnessSubmission(_)     => (IPC_ROLE_VERIFIER, IPC_MSG_KIND_WITNESS_SUBMISSION),
        M::EscalationRequest(_)     => (IPC_ROLE_PLANNER,  IPC_MSG_KIND_ESCALATION_REQUEST),
        M::PlannerFetchRequest(_)   => (IPC_ROLE_PLANNER,  IPC_MSG_KIND_PLANNER_FETCH_REQUEST),

        // ── Response variants, operator-socket variants, tproxy /
        //    dns admission variants — all wire-shape oddities on
        //    planner.sock that the dispatcher logs but does not
        //    handle. `role = unknown` (no caller attribution),
        //    `message_kind = unexpected` (stable bucket).
        M::KernelIntentResponse(_)
        | M::KernelEscalationResponse(_)
        | M::KernelPlannerFetchResponse(_)
        | M::WitnessAck { .. }
        | M::OperatorRequest(_)
        | M::OperatorResponse(_)
        | M::TproxyAdmissionRequest(_)
        | M::KernelTproxyAdmissionResponse(_)
        | M::DnsResolveRequest(_)
        | M::KernelDnsResolveResponse(_) => (IPC_ROLE_UNKNOWN, IPC_MSG_KIND_UNEXPECTED),
    }
}

// ── Inflight gauge state ────────────────────────────────────────────
//
// Per-role atomic counters tracking the number of in-flight
// kernel↔substrate IPC handlers across all live planner streams.
// Module-global because the gauge semantic is "total in-flight
// across all concurrent streams" — a per-stream local counter would
// undercount whenever two streams overlap. The atomics are i64 so
// the underflow guard `max(0)` in the gauge emit is purely defensive
// (counted increments / decrements are always balanced by the
// RAII guard's start/Drop pairing).

use std::sync::atomic::{AtomicI64, Ordering};

static INFLIGHT_PLANNER:  AtomicI64 = AtomicI64::new(0);
static INFLIGHT_VERIFIER: AtomicI64 = AtomicI64::new(0);
static INFLIGHT_GATEWAY:  AtomicI64 = AtomicI64::new(0);
static INFLIGHT_UNKNOWN:  AtomicI64 = AtomicI64::new(0);

fn inflight_counter_for(role: &str) -> &'static AtomicI64 {
    match role {
        IPC_ROLE_PLANNER  => &INFLIGHT_PLANNER,
        IPC_ROLE_VERIFIER => &INFLIGHT_VERIFIER,
        IPC_ROLE_GATEWAY  => &INFLIGHT_GATEWAY,
        _                 => &INFLIGHT_UNKNOWN,
    }
}

/// `raxis.kernel.substrate.ipc.inflight` — emit one gauge sample
/// with the post-update count for `role`. Called by the RAII guard
/// in both `start` and `Drop`; exposed separately so tests can
/// observe the gauge shape without going through the static
/// counters.
pub fn record_kernel_substrate_ipc_inflight(
    hub:   &ObservabilityHub,
    role:  &str,
    count: i64,
) {
    if !hub.enabled() { return; }
    let labels = redact::attrs([("role", role)]);
    hub.record_gauge(
        MetricName::KernelSubstrateIpcInflight,
        labels,
        count.max(0) as f64,
    );
}

/// `raxis.kernel.substrate.ipc.{messages.total, roundtrip.duration}`
/// — emit one counter increment plus one histogram observation
/// covering a single dispatched frame. Called by the RAII guard in
/// `Drop`; exposed separately so tests can verify the metric shape
/// without managing the inflight counter.
///
/// `role` MUST be drawn from
/// [`KERNEL_SUBSTRATE_IPC_ROLE_CLOSED_SET`]. `message_kind` MUST be
/// drawn from [`KERNEL_SUBSTRATE_IPC_MESSAGE_KIND_CLOSED_SET`].
/// `duration_ms` is the wall-clock round-trip in milliseconds.
pub fn record_kernel_substrate_ipc_roundtrip(
    hub:          &ObservabilityHub,
    role:         &str,
    message_kind: &str,
    duration_ms:  i64,
) {
    if !hub.enabled() { return; }
    let labels = redact::attrs([
        ("role",         role),
        ("message_kind", message_kind),
    ]);
    hub.record_counter(
        MetricName::KernelSubstrateIpcMessagesTotal,
        labels.clone(),
        1.0,
    );
    hub.record_histogram_with_buckets(
        MetricName::KernelSubstrateIpcRoundtripDuration,
        labels,
        duration_ms.max(0) as f64,
        KERNEL_SUBSTRATE_IPC_BUCKETS_MS.to_vec(),
    );
}

/// RAII guard instrumenting one kernel↔substrate IPC round-trip.
/// Constructed at the top of each [`raxis_ipc::IpcMessage`] dispatch
/// arm in `kernel/src/ipc/server.rs::drive_planner_stream`; held
/// until the response frame is written (or the match arm exits via
/// `?` propagation).
///
/// `start` increments the module-global per-role inflight counter
/// and emits the post-increment gauge sample. `Drop` emits the
/// counter + histogram with the wall-clock round-trip duration,
/// decrements the inflight counter, and emits the post-decrement
/// gauge sample — in that order so the dashboard sees the
/// "completion" data point before the "freed slot" gauge update.
///
/// The RAII shape is load-bearing: it gives the dispatcher
/// "regardless of handler outcome" instrumentation for free. Any
/// path that drops the guard (normal return, early `?` propagation
/// from `write_frame`, panic unwind) flushes the full metric tuple
/// exactly once.
pub struct KernelSubstrateIpcRoundtrip<'a> {
    hub:          &'a ObservabilityHub,
    role:         &'static str,
    message_kind: &'static str,
    started:      std::time::Instant,
}

impl<'a> KernelSubstrateIpcRoundtrip<'a> {
    /// Begin instrumenting one kernel↔substrate IPC frame. Bumps
    /// the inflight gauge and starts the wall-clock timer.
    ///
    /// `role` and `message_kind` MUST be the static lexemes from
    /// [`kernel_substrate_ipc_route`]; the function takes `&'static
    /// str` precisely to make this guarantee load-bearing — a
    /// caller cannot pass a heap string and accidentally smuggle
    /// in a free-form lexeme.
    pub fn start(
        hub:          &'a ObservabilityHub,
        role:         &'static str,
        message_kind: &'static str,
    ) -> Self {
        if hub.enabled() {
            let cur = inflight_counter_for(role).fetch_add(1, Ordering::Relaxed) + 1;
            record_kernel_substrate_ipc_inflight(hub, role, cur);
        }
        Self {
            hub,
            role,
            message_kind,
            started: std::time::Instant::now(),
        }
    }
}

impl Drop for KernelSubstrateIpcRoundtrip<'_> {
    fn drop(&mut self) {
        if !self.hub.enabled() { return; }
        let duration_ms = self.started.elapsed().as_millis() as i64;
        record_kernel_substrate_ipc_roundtrip(
            self.hub,
            self.role,
            self.message_kind,
            duration_ms,
        );
        let cur = inflight_counter_for(self.role).fetch_sub(1, Ordering::Relaxed) - 1;
        record_kernel_substrate_ipc_inflight(self.hub, self.role, cur);
    }
}

/// Test-only: zero every per-role inflight counter so a test that
/// asserts "gauge returned to 0 after N round-trips" starts from a
/// clean baseline. Production code MUST NEVER call this — the
/// counters are append-only state that mirrors the dispatcher's
/// in-flight handlers.
#[cfg(test)]
pub fn reset_kernel_substrate_ipc_inflight_for_test() {
    INFLIGHT_PLANNER.store(0, Ordering::Relaxed);
    INFLIGHT_VERIFIER.store(0, Ordering::Relaxed);
    INFLIGHT_GATEWAY.store(0, Ordering::Relaxed);
    INFLIGHT_UNKNOWN.store(0, Ordering::Relaxed);
}

/// Test-only: snapshot the current per-role inflight count. Used by
/// the inline witness tests to assert the gauge returns to zero
/// after every round-trip Drop.
#[cfg(test)]
pub fn kernel_substrate_ipc_inflight_snapshot(role: &str) -> i64 {
    inflight_counter_for(role).load(Ordering::Relaxed)
}

#[cfg(test)]
mod substrate_ipc_tests {
    use super::*;
    use raxis_observability::{
        exporter::InMemoryExporter, AttrValue, DataPoint, HubConfig, MetricName,
        ObservabilityExporter, ObservabilityHub,
    };
    use std::sync::{Arc, Mutex};

    /// Tests share the module-global static atomics, so they MUST
    /// be serialised. A small process-local `Mutex` is enough —
    /// `serial_test` would be overkill and pulls in an extra dev-
    /// dep we don't otherwise need.
    fn serial_guard() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: Mutex<()> = Mutex::new(());
        match LOCK.lock() {
            Ok(g)  => g,
            Err(p) => p.into_inner(),
        }
    }

    fn enabled_hub() -> (Arc<ObservabilityHub>, Arc<InMemoryExporter>) {
        let exp = Arc::new(InMemoryExporter::new());
        let cfg = HubConfig {
            enabled:     true,
            sample_rate: 1.0,
            ..HubConfig::default()
        };
        let hub = Arc::new(ObservabilityHub::new(
            cfg,
            exp.clone() as Arc<dyn ObservabilityExporter>,
        ));
        (hub, exp)
    }

    /// Fixture set covering the four dispatched variants plus a
    /// representative non-dispatched variant. The compiler-
    /// exhaustive match arm in [`kernel_substrate_ipc_route`]
    /// guarantees totality over the full `IpcMessage` enum; the
    /// runtime fixtures only need to cover the two route classes
    /// (`dispatched` and `unexpected`) to pin the lexicon mapping.
    fn fixture_ipc_messages() -> Vec<raxis_ipc::IpcMessage> {
        use raxis_ipc::IpcMessage as M;
        use raxis_types::{
            IntentKind, IntentRequest, EscalationClass, EscalationRequest,
            PlannerFetchRequest, PlannerFetchKind, RequestedEscalationScope,
            WitnessSubmission, WitnessResultClass, GateType, CommitSha, TaskId,
            CapabilityClass,
        };

        let task = TaskId::parse("task-substrate-ipc").unwrap();
        let evaluation_sha = CommitSha::parse(&"a".repeat(40)).unwrap();

        vec![
            // ── Dispatched: planner / IntentRequest ──
            M::IntentRequest(IntentRequest {
                session_token:           "tok".into(),
                sequence_number:         1,
                envelope_nonce:          "00000000000000000000000000000001".into(),
                intent_kind:             IntentKind::SingleCommit,
                task_id:                 task.clone(),
                base_sha:                None,
                head_sha:                None,
                submitted_claims:        vec![],
                justification:           None,
                idempotency_key:         None,
                approval_token:          None,
                approved:                None,
                critique:                None,
                resolved_via_escalation: None,
                tokens_used:             None,
                structured_output:       None,
            }),
            // ── Dispatched: verifier / WitnessSubmission ──
            M::WitnessSubmission(WitnessSubmission {
                verifier_token: "v-tok".into(),
                task_id:        task.clone(),
                gate_type:      GateType::parse("TestCoverage").unwrap(),
                evaluation_sha,
                result_class:   WitnessResultClass::Pass,
                body:           serde_json::json!({}),
            }),
            // ── Dispatched: planner / EscalationRequest ──
            M::EscalationRequest(EscalationRequest {
                session_token:   "tok".into(),
                task_id:         task.clone(),
                class:           EscalationClass::CapabilityUpgrade,
                requested_scope: RequestedEscalationScope::CapabilityUpgrade {
                    capability: CapabilityClass::WriteSecrets,
                },
                justification:   "test fixture".into(),
                idempotency_key: uuid::Uuid::nil(),
            }),
            // ── Dispatched: planner / PlannerFetchRequest ──
            M::PlannerFetchRequest(PlannerFetchRequest {
                request_id:    uuid::Uuid::nil(),
                session_token: "tok".into(),
                fetch_kind:    PlannerFetchKind::Inference,
                url:           "https://example.invalid/v1/messages".into(),
                method:        "POST".into(),
                headers:       vec![],
                body_bytes:    vec![],
                timeout_ms:    30_000,
            }),
            // ── Unexpected: a wire-shape oddity that hits the
            //    catch-all arm. WitnessAck is convenient because it
            //    is a struct variant (different syntactic shape
            //    from the tuple variants) so the test exercises the
            //    full match-arm syntax.
            M::WitnessAck {
                verifier_run_id: uuid::Uuid::nil(),
                accepted:        true,
                reason:          None,
            },
        ]
    }

    /// `INV-OBS-IPC-ROUNDTRIP-COVERAGE-01` witness #1: every
    /// [`raxis_ipc::IpcMessage`] variant maps to a closed-lexicon
    /// `(role, message_kind)` pair via [`kernel_substrate_ipc_route`].
    /// The match arm is exhaustive over the wire enum, so the
    /// compiler enforces the invariant at every variant-addition
    /// refactor; this runtime test pins the lexicon membership for
    /// the dispatched-arm fixtures + the representative
    /// `unexpected` variant.
    #[test]
    fn every_variant_maps_to_closed_lexicons() {
        for msg in fixture_ipc_messages() {
            let (role, kind) = kernel_substrate_ipc_route(&msg);
            assert!(
                KERNEL_SUBSTRATE_IPC_ROLE_CLOSED_SET.contains(&role),
                "role {role:?} for {msg:?} not in closed set",
            );
            assert!(
                KERNEL_SUBSTRATE_IPC_MESSAGE_KIND_CLOSED_SET.contains(&kind),
                "message_kind {kind:?} for {msg:?} not in closed set",
            );
        }
    }

    /// `INV-OBS-IPC-ROUNDTRIP-COVERAGE-01` witness #2: the four
    /// dispatched variants map to their canonical `(role,
    /// message_kind)` pair; every other variant collapses to
    /// `(unknown, unexpected)`.
    #[test]
    fn dispatched_variants_have_canonical_route() {
        for msg in fixture_ipc_messages() {
            let (role, kind) = kernel_substrate_ipc_route(&msg);
            match &msg {
                raxis_ipc::IpcMessage::IntentRequest(_) => {
                    assert_eq!(role, IPC_ROLE_PLANNER);
                    assert_eq!(kind, IPC_MSG_KIND_INTENT_REQUEST);
                }
                raxis_ipc::IpcMessage::WitnessSubmission(_) => {
                    assert_eq!(role, IPC_ROLE_VERIFIER);
                    assert_eq!(kind, IPC_MSG_KIND_WITNESS_SUBMISSION);
                }
                raxis_ipc::IpcMessage::EscalationRequest(_) => {
                    assert_eq!(role, IPC_ROLE_PLANNER);
                    assert_eq!(kind, IPC_MSG_KIND_ESCALATION_REQUEST);
                }
                raxis_ipc::IpcMessage::PlannerFetchRequest(_) => {
                    assert_eq!(role, IPC_ROLE_PLANNER);
                    assert_eq!(kind, IPC_MSG_KIND_PLANNER_FETCH_REQUEST);
                }
                _ => {
                    assert_eq!(role, IPC_ROLE_UNKNOWN,
                        "unexpected variant {msg:?} must map to role=unknown");
                    assert_eq!(kind, IPC_MSG_KIND_UNEXPECTED,
                        "unexpected variant {msg:?} must map to message_kind=unexpected");
                }
            }
        }
    }

    /// `INV-OBS-IPC-ROUNDTRIP-COVERAGE-01` witness #3: each
    /// (role, message_kind) emit pair produces exactly one
    /// counter increment + one histogram observation with the
    /// iter44 bucket override.
    #[test]
    fn record_roundtrip_emits_paired_metrics() {
        let _g = serial_guard();
        for &role in KERNEL_SUBSTRATE_IPC_ROLE_CLOSED_SET {
            for &kind in KERNEL_SUBSTRATE_IPC_MESSAGE_KIND_CLOSED_SET {
                let (hub, exp) = enabled_hub();
                record_kernel_substrate_ipc_roundtrip(
                    hub.as_ref(), role, kind, 42,
                );
                hub.flush();
                let metrics = exp.metrics();
                assert_eq!(
                    metrics.len(), 2,
                    "expected counter+histogram pair for role={role} kind={kind}",
                );
                let counter = metrics.iter()
                    .find(|m| m.name == MetricName::KernelSubstrateIpcMessagesTotal)
                    .expect("KernelSubstrateIpcMessagesTotal present");
                let histogram = metrics.iter()
                    .find(|m| m.name == MetricName::KernelSubstrateIpcRoundtripDuration)
                    .expect("KernelSubstrateIpcRoundtripDuration present");
                assert!(matches!(
                    counter.datapoint,
                    DataPoint::Sum { value } if (value - 1.0).abs() < 1e-9,
                ));
                match counter.labels.get("role").unwrap() {
                    AttrValue::Str(s) => assert_eq!(s, role),
                    other            => panic!("role must be Str, got {other:?}"),
                }
                match counter.labels.get("message_kind").unwrap() {
                    AttrValue::Str(s) => assert_eq!(s, kind),
                    other            => panic!("message_kind must be Str, got {other:?}"),
                }
                if let DataPoint::Histo { ref buckets, .. } = histogram.datapoint {
                    assert_eq!(buckets, KERNEL_SUBSTRATE_IPC_BUCKETS_MS,
                        "histogram MUST use the iter44 IPC bucket override");
                } else {
                    panic!("histogram datapoint must be Histo, got {:?}", histogram.datapoint);
                }
            }
        }
    }

    /// `INV-OBS-IPC-ROUNDTRIP-COVERAGE-01` witness #4: the RAII
    /// guard increments the inflight counter on `start`, emits one
    /// gauge sample with the post-increment value, then on `Drop`
    /// emits the counter + histogram + a gauge sample with the
    /// post-decrement value. After N completed round-trips the
    /// per-role inflight counter MUST return to its pre-test
    /// baseline (zero, modulo the reset call).
    #[test]
    fn raii_guard_round_trips_inflight_to_zero() {
        let _g = serial_guard();
        reset_kernel_substrate_ipc_inflight_for_test();
        let (hub, exp) = enabled_hub();

        // Drive 5 round-trips across the planner role.
        const N: usize = 5;
        for _ in 0..N {
            let _guard = KernelSubstrateIpcRoundtrip::start(
                hub.as_ref(),
                IPC_ROLE_PLANNER,
                IPC_MSG_KIND_INTENT_REQUEST,
            );
            // Guard drops at end of iteration — emits the counter,
            // histogram, and post-decrement gauge.
        }
        hub.flush();

        // Per-role inflight counter MUST be back to 0.
        assert_eq!(
            kernel_substrate_ipc_inflight_snapshot(IPC_ROLE_PLANNER),
            0,
            "inflight counter must return to 0 after N balanced round-trips",
        );

        // Metric tape MUST contain exactly 2N gauge samples (one
        // per start, one per Drop) + N counters + N histograms.
        let metrics = exp.metrics();
        let n_gauges = metrics.iter()
            .filter(|m| m.name == MetricName::KernelSubstrateIpcInflight)
            .count();
        let n_counters = metrics.iter()
            .filter(|m| m.name == MetricName::KernelSubstrateIpcMessagesTotal)
            .count();
        let n_histograms = metrics.iter()
            .filter(|m| m.name == MetricName::KernelSubstrateIpcRoundtripDuration)
            .count();
        assert_eq!(n_gauges, 2 * N,
            "expected {} gauge samples (start+drop per round-trip), got {n_gauges}", 2 * N);
        assert_eq!(n_counters, N,
            "expected {N} counter increments, got {n_counters}");
        assert_eq!(n_histograms, N,
            "expected {N} histogram observations, got {n_histograms}");

        // Final gauge sample MUST be 0.
        let last_gauge = metrics.iter()
            .rev()
            .find(|m| m.name == MetricName::KernelSubstrateIpcInflight)
            .expect("at least one gauge sample present");
        match last_gauge.datapoint {
            DataPoint::Sum { value } => assert!(
                (value - 0.0).abs() < 1e-9,
                "final inflight gauge MUST be 0, got {value}",
            ),
            ref other => panic!("gauge datapoint must be Sum, got {other:?}"),
        }
    }

    /// Defence-in-depth: the closed sets MUST contain exactly the
    /// lexemes the spec §8 table (`INV-OBS-IPC-ROUNDTRIP-COVERAGE-01`)
    /// enumerates.
    #[test]
    fn closed_sets_match_spec_tables() {
        let role_expected: &[&str] = &["planner", "verifier", "gateway", "unknown"];
        assert_eq!(KERNEL_SUBSTRATE_IPC_ROLE_CLOSED_SET.len(), role_expected.len());
        for &e in role_expected {
            assert!(KERNEL_SUBSTRATE_IPC_ROLE_CLOSED_SET.contains(&e),
                "role lexeme {e:?} missing from closed set");
        }
        let kind_expected: &[&str] = &[
            "intent_request",
            "witness_submission",
            "escalation_request",
            "planner_fetch_request",
            "unexpected",
        ];
        assert_eq!(KERNEL_SUBSTRATE_IPC_MESSAGE_KIND_CLOSED_SET.len(), kind_expected.len());
        for &e in kind_expected {
            assert!(KERNEL_SUBSTRATE_IPC_MESSAGE_KIND_CLOSED_SET.contains(&e),
                "message_kind lexeme {e:?} missing from closed set");
        }
    }
}

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

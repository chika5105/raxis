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

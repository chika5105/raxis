//! raxis-observability — V3 OpenTelemetry-shaped observability surface.
//!
//! Normative reference: `specs/v3/otel-observability.md`.
//!
//! ## What this crate is
//!
//! The authority-side, in-process layer of the V3 observability stack.
//! This crate ships:
//!
//! 1. **Types** ([`SpanData`], [`MetricData`], [`AttrValue`],
//!    [`SpanName`], [`MetricName`], …) — closed enumerations every
//!    emit site draws from. Adding a variant is a spec change.
//! 2. **Hub** ([`ObservabilityHub`]) — per-process buffer that
//!    handlers feed via `record_span` / `record_metric`. Bounded
//!    queue; drops on overflow with a counter.
//! 3. **Exporter trait** ([`ObservabilityExporter`]) and its two
//!    in-tree impls: [`NoopExporter`] (used when
//!    `[observability].enabled = false`) and [`RingFileExporter`]
//!    (writes JSONL frames to `<data_dir>/observability/`).
//! 4. **Redactor** ([`Redactor`]) — closed allow-list /
//!    denylist enforcement; runtime fail-closed per
//!    `INV-OTEL-02`.
//! 5. **Sidecar protocol** ([`protocol`]) — the JSONL frame schema
//!    the kernel writes and the `raxis-otel-pusher` binary reads.
//!
//! ## What this crate is NOT
//!
//! - **Not an OTLP client.** The kernel never imports
//!   `opentelemetry`, `opentelemetry-otlp`, `tonic`, or `prost`
//!   (`INV-OTEL-03`). All wire-protocol code lives in the
//!   `raxis-otel-pusher` binary in `pusher/`.
//! - **Not a logs pipeline.** The audit chain (R-7) is the
//!   canonical log surface. OTel logs export is explicitly out of
//!   scope for V3; see spec §9.
//! - **Not a trust boundary for planner-side data.** Authority-side
//!   spans are root spans; the kernel never honours a planner-
//!   supplied `traceparent` (`INV-OTEL-09`).

#![forbid(unsafe_code)]
#![deny(rust_2018_idioms)]
#![warn(missing_docs)]

pub mod exporter;
pub mod hub;
pub mod protocol;
pub mod redact;
pub mod ring;
pub mod types;

pub use exporter::{NoopExporter, ObservabilityExporter, RingFileExporter};
pub use hub::{DropReason, HubConfig, ObservabilityHub, RecordingSpan};
pub use redact::{RedactError, Redactor};
pub use types::{
    AttrMap, AttrValue, DataPoint, EventName, MetricData, MetricName, MetricType,
    SpanData, SpanEvent, SpanKind, SpanName, SpanStatus, Unit,
};

// ---------------------------------------------------------------------------
// Cross-crate emit helpers (V3 Part 2 expansion)
//
// Dashboard middleware / SSE handlers live in `crates/dashboard/` and cannot
// import `raxis-kernel`. The canonical convenience helpers continue to live
// in `kernel/src/observability.rs`; the three dashboard-facing ones are
// duplicated here so non-kernel crates can call them without a circular
// dep. The kernel-side helpers in `kernel/src/observability.rs` re-export
// these three so every emit site lands in one canonical shape.
// ---------------------------------------------------------------------------

/// `raxis.dashboard.http.request.duration` — every dashboard HTTP
/// request, success or failure. Closed allow-list labels match
/// `redact::ALLOW_LIST` (`route`, `http_method`, `http_status`).
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
        AttrValue::I64(http_status),
    );
    hub.record_histogram(
        MetricName::DashboardHttpRequestDuration,
        labels,
        duration_ms.max(0) as f64,
    );
}

/// `raxis.dashboard.sse.connection.active` gauge — sampled on
/// connect and disconnect.
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

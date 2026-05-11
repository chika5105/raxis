//! `ObservabilityHub` — the in-process buffer the kernel feeds via
//! `record_span` / `record_metric` and flushes through an
//! [`crate::exporter::ObservabilityExporter`].
//!
//! Spec: `v3/otel-observability.md §3, §6, §15`.
//!
//! ## Concurrency model
//!
//! The hub is `Send + Sync` and held as `Arc<ObservabilityHub>` on
//! the kernel's `HandlerContext`. Two layers of synchronisation:
//!
//! 1. Each `record_*` call grabs a short-lived `Mutex` over the
//!    in-memory buffer, sanitises the input via the [`Redactor`],
//!    pushes the cleaned record onto the buffer, then releases.
//! 2. A separate `flush` path (called by an internal flush task or
//!    explicitly by the kernel during graceful shutdown) drains the
//!    buffer and hands the batch to the exporter.
//!
//! `record_*` is non-blocking on the exporter; export I/O is
//! serialised inside the exporter impl. If the buffer is full,
//! the record is dropped and the per-reason `DropReason` counter
//! is incremented (`INV-OTEL-01`).

use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use parking_lot::Mutex;

use crate::exporter::{NoopExporter, ObservabilityExporter};
use crate::redact::Redactor;
use crate::types::{
    AttrMap, AttrValue, DataPoint, EventName, MetricData, MetricName, MetricType,
    SpanData, SpanEvent, SpanKind, SpanName, SpanStatus,
};

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Per-process hub configuration. Read from
/// `[observability.{ring,traces,metrics}]` at boot and cloned into
/// the hub. Mutating these at runtime is not supported in V3 — they
/// take effect on the next kernel restart.
#[derive(Debug, Clone)]
pub struct HubConfig {
    /// Master switch. When `false`, the hub holds a `NoopExporter`
    /// and every `record_*` call short-circuits before sanitisation.
    pub enabled:           bool,
    /// In-memory bound: max spans + metrics queued before the hub
    /// drops on overflow. Default 8192; range [256, 1_048_576].
    pub max_queue_depth:   usize,
    /// Head sampling rate for spans. Range [0.0, 1.0]. 1.0 = always
    /// sample; 0.0 = never sample. Metrics are unsampled.
    pub sample_rate:       f64,
    /// Per-span attribute cap. Excess attributes are dropped at
    /// `RecordingSpan::set_attr` time.
    pub max_attrs_per_span: usize,
    /// Per-span event cap. Excess events are silently dropped at
    /// `RecordingSpan::add_event` time.
    pub max_events_per_span: usize,
    /// Default histogram bucket boundaries (ms). Used by every
    /// histogram metric.
    pub histogram_buckets: Vec<f64>,
}

impl Default for HubConfig {
    fn default() -> Self {
        Self {
            enabled:             false,
            max_queue_depth:     8192,
            sample_rate:         0.1,
            max_attrs_per_span:  32,
            max_events_per_span: 16,
            histogram_buckets:   vec![
                1.0, 5.0, 10.0, 25.0, 50.0, 100.0,
                250.0, 500.0, 1000.0, 2500.0, 5000.0, 10000.0,
            ],
        }
    }
}

// ---------------------------------------------------------------------------
// DropReason
// ---------------------------------------------------------------------------

/// Why a span / metric did not reach the exporter. Surfaces via the
/// `raxis.observability.dropped.total` metric.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DropReason {
    /// Hub buffer was at `max_queue_depth`; the record was dropped.
    QueueFull,
    /// Redactor rejected the record (unknown attribute, type
    /// mismatch, etc.). Per `INV-OTEL-02` the entire span/metric
    /// is dropped — never partial.
    RedactionFailure,
    /// Disabled: hub is in `enabled = false` mode (used as a
    /// counter only when a caller forces a record through the
    /// disabled hub via internal APIs).
    Disabled,
    /// Sampling decision dropped the span (`sample_rate < 1.0`).
    /// Counted separately from real drops so dashboards can
    /// distinguish "intentional sampling" from "lost data".
    Sampled,
}

impl DropReason {
    /// Stable label for the `drop_reason` attribute on the
    /// `raxis.observability.dropped.total` metric.
    pub fn label(&self) -> &'static str {
        match self {
            Self::QueueFull        => "queue_full",
            Self::RedactionFailure => "redaction_failure",
            Self::Disabled         => "disabled",
            Self::Sampled          => "sampled",
        }
    }
}

// ---------------------------------------------------------------------------
// ObservabilityHub
// ---------------------------------------------------------------------------

/// Per-process hub. One instance per kernel; held as
/// `Arc<ObservabilityHub>` on `HandlerContext`. Cheap to clone the
/// `Arc`; expensive to construct from scratch — call once in
/// `kernel/src/main.rs`.
pub struct ObservabilityHub {
    cfg:       HubConfig,
    redactor:  Redactor,
    exporter:  Arc<dyn ObservabilityExporter>,
    state:     Mutex<HubState>,
    /// Process-wide trace-id counter source. Combined with the start
    /// nanos to derive a unique 16-byte id without needing an
    /// external RNG dep.
    next_seed: AtomicU64,
    /// Drop counters by reason. Read by the exporter (when emitting
    /// the meta-metric) and by the heartbeat loop.
    drop_counts: [AtomicU64; 4],
}

#[derive(Debug, Default)]
struct HubState {
    spans:   Vec<SpanData>,
    metrics: Vec<MetricData>,
}

impl ObservabilityHub {
    /// Construct a disabled hub with a [`NoopExporter`]. Tests that
    /// don't care about observability use this.
    pub fn disabled() -> Self {
        let exporter: Arc<dyn ObservabilityExporter> = Arc::new(NoopExporter);
        Self::new(
            HubConfig::default(),
            exporter,
        )
    }

    /// Construct a hub with the given config and exporter.
    pub fn new(
        cfg:      HubConfig,
        exporter: Arc<dyn ObservabilityExporter>,
    ) -> Self {
        Self {
            cfg,
            redactor:    Redactor,
            exporter,
            state:       Mutex::new(HubState::default()),
            next_seed:   AtomicU64::new(1),
            drop_counts: [
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
            ],
        }
    }

    /// Construct a hub on top of a [`crate::exporter::RingFileExporter`]
    /// rooted at `<root>/observability/`. Returns the hub plus the
    /// exporter so callers can cleanly pipe `shutdown()` through it.
    pub fn with_ring_at(
        cfg:            HubConfig,
        root:           impl AsRef<Path>,
        ring_cfg:       crate::ring::RingConfig,
        kernel_version: impl Into<String>,
    ) -> std::io::Result<(Self, Arc<dyn ObservabilityExporter>)> {
        let exp = Arc::new(crate::exporter::RingFileExporter::open(
            root.as_ref().join("observability"),
            ring_cfg,
            kernel_version,
        )?);
        let hub = Self::new(cfg, exp.clone() as Arc<dyn ObservabilityExporter>);
        Ok((hub, exp as Arc<dyn ObservabilityExporter>))
    }

    /// Whether observability is enabled. Emit sites can short-circuit
    /// expensive attribute construction by checking this first.
    pub fn enabled(&self) -> bool { self.cfg.enabled }

    /// Effective hub config (read-only).
    pub fn config(&self) -> &HubConfig { &self.cfg }

    // ── Span API ────────────────────────────────────────────────────────

    /// Open a new span. The returned [`RecordingSpan`] is consumed by
    /// `.end()` to push the [`SpanData`] into the buffer.
    ///
    /// `parent` may be `None` for trace roots; non-`None` for nested
    /// spans (gateway under intent-admission, verifier under
    /// intent-admission, etc.).
    pub fn start_span(
        self: &Arc<Self>,
        name:   SpanName,
        kind:   SpanKind,
        parent: Option<&SpanContext>,
    ) -> RecordingSpan {
        // Disabled fast path.
        if !self.cfg.enabled {
            return RecordingSpan::disabled(name, kind);
        }
        // Derive trace + span ids.
        let (trace_id, span_id, parent_span_id) = match parent {
            Some(ctx) => {
                let span_id = self.next_id_8();
                (ctx.trace_id, span_id, Some(ctx.span_id))
            }
            None => {
                let trace_id = self.next_id_16();
                let span_id  = self.next_id_8();
                (trace_id, span_id, None)
            }
        };
        // Head sampling — deterministic per trace_id.
        let sampled = sample_decision(trace_id, self.cfg.sample_rate);
        if !sampled {
            self.bump_drop(DropReason::Sampled);
            return RecordingSpan::disabled(name, kind);
        }
        let now = unix_now_nanos();
        RecordingSpan {
            inner: Some(RecordingInner {
                hub: Arc::clone(self),
                data: SpanData {
                    trace_id,
                    span_id,
                    parent_span_id,
                    name,
                    kind,
                    start_unix_nanos: now,
                    end_unix_nanos:   now,
                    status:           SpanStatus::Ok,
                    status_message:   None,
                    attrs:            AttrMap::new(),
                    events:           Vec::new(),
                },
            }),
        }
    }

    /// Internal: push a finished `SpanData` into the buffer with
    /// redactor pre-check. Called from `RecordingSpan::end`.
    fn submit_span(&self, span: SpanData) {
        let span = match self.redactor.sanitize_span(span) {
            Ok(s)  => s,
            Err(e) => {
                self.bump_drop(DropReason::RedactionFailure);
                eprintln!(
                    "{{\"level\":\"warn\",\"event\":\"observability_redact_drop\",\
                     \"target\":\"span\",\"error\":\"{e}\"}}",
                );
                return;
            }
        };
        // If pushing would overflow the queue, drop and count.
        let mut state = self.state.lock();
        if state.spans.len() + state.metrics.len() >= self.cfg.max_queue_depth {
            self.bump_drop(DropReason::QueueFull);
            return;
        }
        state.spans.push(span);
    }

    // ── Metric API ──────────────────────────────────────────────────────

    /// Record a counter increment.
    pub fn record_counter(
        &self,
        name:   MetricName,
        labels: AttrMap,
        delta:  f64,
    ) {
        if !self.cfg.enabled { return; }
        let m = MetricData {
            name,
            metric_type:  MetricType::Counter,
            unit:         name.default_unit(),
            labels,
            datapoint:    DataPoint::Sum { value: delta },
            unix_nanos:   unix_now_nanos(),
        };
        self.submit_metric(m);
    }

    /// Record (overwrite) a gauge value.
    pub fn record_gauge(
        &self,
        name:   MetricName,
        labels: AttrMap,
        value:  f64,
    ) {
        if !self.cfg.enabled { return; }
        let m = MetricData {
            name,
            metric_type:  MetricType::Gauge,
            unit:         name.default_unit(),
            labels,
            datapoint:    DataPoint::Sum { value },
            unix_nanos:   unix_now_nanos(),
        };
        self.submit_metric(m);
    }

    /// Record one observation into a histogram.
    pub fn record_histogram(
        &self,
        name:   MetricName,
        labels: AttrMap,
        value:  f64,
    ) {
        if !self.cfg.enabled { return; }
        let buckets = self.cfg.histogram_buckets.clone();
        let mut counts = vec![0u64; buckets.len() + 1];
        let mut idx = buckets.len();
        for (i, b) in buckets.iter().enumerate() {
            if value <= *b { idx = i; break; }
        }
        counts[idx] = 1;
        let m = MetricData {
            name,
            metric_type:  MetricType::Histogram,
            unit:         name.default_unit(),
            labels,
            datapoint:    DataPoint::Histo {
                buckets,
                counts,
                sum:    value,
                count:  1,
                min:    value,
                max:    value,
            },
            unix_nanos:   unix_now_nanos(),
        };
        self.submit_metric(m);
    }

    fn submit_metric(&self, metric: MetricData) {
        let metric = match self.redactor.sanitize_metric(metric) {
            Ok(m)  => m,
            Err(e) => {
                self.bump_drop(DropReason::RedactionFailure);
                eprintln!(
                    "{{\"level\":\"warn\",\"event\":\"observability_redact_drop\",\
                     \"target\":\"metric\",\"error\":\"{e}\"}}",
                );
                return;
            }
        };
        let mut state = self.state.lock();
        if state.spans.len() + state.metrics.len() >= self.cfg.max_queue_depth {
            self.bump_drop(DropReason::QueueFull);
            return;
        }
        state.metrics.push(metric);
    }

    // ── Flush ───────────────────────────────────────────────────────────

    /// Drain the buffer and hand the batch to the exporter. Returns
    /// the count of spans + metrics dispatched.
    pub fn flush(&self) -> (usize, usize) {
        let (spans, metrics) = {
            let mut s = self.state.lock();
            (
                std::mem::take(&mut s.spans),
                std::mem::take(&mut s.metrics),
            )
        };
        let span_n = spans.len();
        let met_n  = metrics.len();
        if !spans.is_empty() {
            self.exporter.export_spans(&spans);
        }
        if !metrics.is_empty() {
            self.exporter.export_metrics(&metrics);
        }
        (span_n, met_n)
    }

    /// Drop counters since process start. Order matches
    /// [`DropReason`].
    pub fn drop_counters(&self) -> [(DropReason, u64); 4] {
        [
            (DropReason::QueueFull,        self.drop_counts[0].load(Ordering::Relaxed)),
            (DropReason::RedactionFailure, self.drop_counts[1].load(Ordering::Relaxed)),
            (DropReason::Disabled,         self.drop_counts[2].load(Ordering::Relaxed)),
            (DropReason::Sampled,          self.drop_counts[3].load(Ordering::Relaxed)),
        ]
    }

    /// Total dropped frames across all reasons since process start.
    pub fn total_dropped(&self) -> u64 {
        self.drop_counters().iter().map(|(_, n)| n).sum()
    }

    /// Clean shutdown — flushes any buffered batch and asks the
    /// exporter to release resources. Idempotent.
    pub fn shutdown(&self) {
        self.flush();
        self.exporter.shutdown();
    }

    // ── Internals ───────────────────────────────────────────────────────

    fn bump_drop(&self, reason: DropReason) {
        let i = match reason {
            DropReason::QueueFull        => 0,
            DropReason::RedactionFailure => 1,
            DropReason::Disabled         => 2,
            DropReason::Sampled          => 3,
        };
        self.drop_counts[i].fetch_add(1, Ordering::Relaxed);
    }

    fn next_id_16(&self) -> [u8; 16] {
        // Stable per-process id stream: high 8 bytes are the start
        // wallclock nanos of this kernel run XORed with a per-id
        // increment; low 8 bytes are the current seed counter.
        // Not cryptographically random — but trace_id collisions are
        // a debugging nuisance, not a security boundary, and the
        // wallclock + counter combo gives us collision-free ids
        // across hub instances on the same host.
        let seed = self.next_seed.fetch_add(1, Ordering::Relaxed);
        let now  = unix_now_nanos();
        let mut out = [0u8; 16];
        out[..8].copy_from_slice(&now.to_le_bytes());
        out[8..].copy_from_slice(&seed.to_le_bytes());
        out
    }

    fn next_id_8(&self) -> [u8; 8] {
        let seed = self.next_seed.fetch_add(1, Ordering::Relaxed);
        seed.to_le_bytes()
    }
}

// ---------------------------------------------------------------------------
// SpanContext / RecordingSpan
// ---------------------------------------------------------------------------

/// Lightweight handle to a sampled span's `(trace_id, span_id)`. Used
/// to thread parent context through nested handlers without holding
/// the recording state.
#[derive(Debug, Clone, Copy)]
pub struct SpanContext {
    /// Trace identifier.
    pub trace_id: [u8; 16],
    /// Span identifier within the trace.
    pub span_id:  [u8; 8],
}

/// Drop-on-end span recorder. Adding attributes after `.end()` is a
/// compile-time impossibility — `end` consumes `self`.
pub struct RecordingSpan {
    inner: Option<RecordingInner>,
}

struct RecordingInner {
    hub:  Arc<ObservabilityHub>,
    data: SpanData,
}

impl RecordingSpan {
    /// Disabled (sampling drop or hub disabled). All `set_*` /
    /// `add_event` calls become no-ops.
    fn disabled(name: SpanName, kind: SpanKind) -> Self {
        // Construct a placeholder so `.context()` returns deterministic
        // bytes — useful for tests that check trace topology.
        let _ = (name, kind);
        Self { inner: None }
    }

    /// Whether this span is recording. Emit sites can use this to
    /// short-circuit expensive attribute construction.
    pub fn is_recording(&self) -> bool { self.inner.is_some() }

    /// Set an attribute. Silently truncated to `max_attrs_per_span`.
    pub fn set_attr(&mut self, key: &str, value: impl Into<AttrValue>) {
        let Some(inner) = self.inner.as_mut() else { return; };
        if inner.data.attrs.len() >= inner.hub.cfg.max_attrs_per_span {
            return;
        }
        inner.data.attrs.insert(key.to_owned(), value.into());
    }

    /// Add a within-span event. Silently dropped past
    /// `max_events_per_span`.
    pub fn add_event(&mut self, name: EventName, attrs: AttrMap) {
        let Some(inner) = self.inner.as_mut() else { return; };
        if inner.data.events.len() >= inner.hub.cfg.max_events_per_span {
            return;
        }
        inner.data.events.push(SpanEvent {
            name,
            unix_nanos: unix_now_nanos(),
            attrs,
        });
    }

    /// Mark the span's status. Defaults to `Ok`.
    pub fn set_status(&mut self, status: SpanStatus, message: Option<String>) {
        let Some(inner) = self.inner.as_mut() else { return; };
        inner.data.status = status;
        inner.data.status_message = message;
    }

    /// Snapshot the (trace_id, span_id) so a child span can be
    /// linked. Cheap; safe to call on a disabled span (returns
    /// zeroed bytes).
    pub fn context(&self) -> SpanContext {
        match &self.inner {
            Some(inner) => SpanContext {
                trace_id: inner.data.trace_id,
                span_id:  inner.data.span_id,
            },
            None => SpanContext {
                trace_id: [0; 16],
                span_id:  [0; 8],
            },
        }
    }

    /// Finalise the span and submit to the hub. Consumes self —
    /// further mutation is a compile error.
    pub fn end(mut self) {
        let Some(mut inner) = self.inner.take() else { return; };
        inner.data.end_unix_nanos = unix_now_nanos();
        inner.hub.submit_span(inner.data);
    }
}

impl Drop for RecordingSpan {
    fn drop(&mut self) {
        // Auto-end on drop so a panic/early return inside the
        // handler doesn't leak a partially-recorded span.
        if let Some(mut inner) = self.inner.take() {
            inner.data.end_unix_nanos = unix_now_nanos();
            inner.hub.submit_span(inner.data);
        }
    }
}

// ---------------------------------------------------------------------------
// Time + sampling
// ---------------------------------------------------------------------------

fn unix_now_nanos() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos().min(u64::MAX as u128) as u64)
        .unwrap_or(0)
}

/// Deterministic head sampling: take the low 64 bits of the trace_id
/// and compare to `rate * u64::MAX`.
fn sample_decision(trace_id: [u8; 16], rate: f64) -> bool {
    if rate >= 1.0 { return true; }
    if rate <= 0.0 { return false; }
    let low = u64::from_le_bytes(trace_id[8..].try_into().unwrap());
    let frac = (low as f64) / (u64::MAX as f64);
    frac < rate
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exporter::InMemoryExporter;
    use crate::redact::attrs;
    use crate::types::{MetricName, SpanKind, SpanName};

    fn enabled_hub() -> (Arc<ObservabilityHub>, Arc<InMemoryExporter>) {
        let exp = Arc::new(InMemoryExporter::new());
        let cfg = HubConfig {
            enabled:             true,
            max_queue_depth:     1024,
            sample_rate:         1.0,
            max_attrs_per_span:  32,
            max_events_per_span: 16,
            ..HubConfig::default()
        };
        let hub = Arc::new(ObservabilityHub::new(
            cfg,
            exp.clone() as Arc<dyn ObservabilityExporter>,
        ));
        (hub, exp)
    }

    #[test]
    fn end_span_pushes_into_buffer() {
        let (hub, exp) = enabled_hub();
        let mut s = hub.start_span(SpanName::IntentAdmission, SpanKind::Internal, None);
        s.set_attr("intent_kind", "CompleteTask");
        s.set_attr("verdict",     "Accepted");
        s.set_attr("latency_ms",  42i64);
        s.end();
        hub.flush();
        let collected = exp.spans();
        assert_eq!(collected.len(), 1);
        assert_eq!(collected[0].name, SpanName::IntentAdmission);
        assert_eq!(collected[0].attrs.len(), 3);
    }

    #[test]
    fn disabled_hub_does_not_emit() {
        let exp = Arc::new(InMemoryExporter::new());
        let cfg = HubConfig::default(); // enabled=false by default
        let hub = Arc::new(ObservabilityHub::new(
            cfg,
            exp.clone() as Arc<dyn ObservabilityExporter>,
        ));
        let mut s = hub.start_span(SpanName::IntentAdmission, SpanKind::Internal, None);
        s.set_attr("intent_kind", "CompleteTask");
        s.end();
        hub.flush();
        assert!(exp.spans().is_empty());
    }

    #[test]
    fn child_span_inherits_trace_id() {
        let (hub, exp) = enabled_hub();
        let parent = hub.start_span(SpanName::IntentAdmission, SpanKind::Internal, None);
        let pctx = parent.context();
        let child = hub.start_span(SpanName::GatewayFetch, SpanKind::Client, Some(&pctx));
        let cctx = child.context();
        assert_eq!(pctx.trace_id, cctx.trace_id);
        assert_ne!(pctx.span_id, cctx.span_id);
        child.end();
        parent.end();
        hub.flush();
        let spans = exp.spans();
        assert_eq!(spans.len(), 2);
        let intent = spans.iter().find(|s| s.name == SpanName::IntentAdmission).unwrap();
        let fetch  = spans.iter().find(|s| s.name == SpanName::GatewayFetch).unwrap();
        assert_eq!(fetch.parent_span_id, Some(intent.span_id));
        assert_eq!(intent.trace_id, fetch.trace_id);
    }

    #[test]
    fn redaction_failure_drops_span_and_increments_counter() {
        let (hub, exp) = enabled_hub();
        let mut s = hub.start_span(SpanName::IntentAdmission, SpanKind::Internal, None);
        // Forbidden attribute name → redactor drops the entire span.
        s.set_attr("session_token", "deadbeef");
        s.end();
        hub.flush();
        assert!(exp.spans().is_empty(), "denylisted attr drops the span");
        let drops = hub.drop_counters();
        assert_eq!(drops[1].1, 1, "redaction_failure counter incremented");
    }

    #[test]
    fn queue_full_drops_records() {
        let exp = Arc::new(InMemoryExporter::new());
        let cfg = HubConfig {
            enabled:         true,
            max_queue_depth: 3,
            sample_rate:     1.0,
            max_attrs_per_span: 4,
            max_events_per_span: 4,
            ..HubConfig::default()
        };
        let hub = Arc::new(ObservabilityHub::new(
            cfg,
            exp.clone() as Arc<dyn ObservabilityExporter>,
        ));
        for _ in 0..10 {
            hub.record_counter(
                MetricName::IntentAdmissionTotal,
                attrs([("verdict", "Accepted")]),
                1.0,
            );
        }
        let drops = hub.drop_counters();
        assert!(drops[0].1 >= 7, "queue_full counter ≥7 (dropped at least 7 of 10)");
        // We never lose more than the queue depth from the actual buffer.
        let (_spans, n_metrics) = hub.flush();
        assert!(n_metrics <= 3, "flush ≤ queue depth, got {n_metrics}");
    }

    #[test]
    fn sampling_zero_drops_every_span() {
        let exp = Arc::new(InMemoryExporter::new());
        let cfg = HubConfig {
            enabled:     true,
            sample_rate: 0.0,
            ..HubConfig::default()
        };
        let hub = Arc::new(ObservabilityHub::new(
            cfg,
            exp.clone() as Arc<dyn ObservabilityExporter>,
        ));
        for _ in 0..50 {
            let s = hub.start_span(SpanName::IntentAdmission, SpanKind::Internal, None);
            s.end();
        }
        hub.flush();
        assert!(exp.spans().is_empty(), "zero sampling drops everything");
        let drops = hub.drop_counters();
        assert_eq!(drops[3].1, 50, "sampled drops counted");
    }

    #[test]
    fn histogram_buckets_one_observation() {
        let (hub, exp) = enabled_hub();
        hub.record_histogram(
            MetricName::IntentAdmissionDuration,
            attrs([("verdict", "Accepted")]),
            42.0,
        );
        hub.flush();
        let m = exp.metrics();
        assert_eq!(m.len(), 1);
        match &m[0].datapoint {
            DataPoint::Histo { count, sum, .. } => {
                assert_eq!(*count, 1);
                assert_eq!(*sum, 42.0);
            }
            _ => panic!("expected histogram"),
        }
    }

    #[test]
    fn drop_on_panic_via_drop_impl() {
        let (hub, exp) = enabled_hub();
        {
            let mut s = hub.start_span(SpanName::IntentAdmission, SpanKind::Internal, None);
            s.set_attr("verdict", "Accepted");
            // Drop without calling `.end()` — Drop impl auto-ends.
        }
        hub.flush();
        assert_eq!(exp.spans().len(), 1, "drop auto-ends");
    }

    #[test]
    fn shutdown_flushes_pending() {
        let (hub, exp) = enabled_hub();
        let s = hub.start_span(SpanName::IntentAdmission, SpanKind::Internal, None);
        s.end();
        hub.shutdown();
        assert_eq!(exp.spans().len(), 1);
        assert!(exp.shutdown_called());
    }

    #[test]
    fn sample_decision_is_deterministic_per_trace() {
        let id = [42u8; 16];
        // Same trace_id + same rate → same outcome, every time.
        let a = sample_decision(id, 0.5);
        for _ in 0..100 {
            assert_eq!(sample_decision(id, 0.5), a);
        }
    }
}

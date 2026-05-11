//! `ObservabilityExporter` trait and the two production impls
//! (`NoopExporter`, `RingFileExporter`).
//!
//! Spec: `v3/otel-observability.md §11`.
//!
//! ## Trait contract
//!
//! - `export_*` is fire-and-forget. Implementations MUST NOT block
//!   the calling thread on slow I/O; the kernel's commit path runs
//!   through these methods.
//! - `export_*` MUST NOT propagate errors. Failures are logged
//!   internally and surfaced as drop counters via the hub.
//! - `shutdown` is idempotent; the kernel calls it once during
//!   orderly shutdown after the IPC dispatch loop returns.
//!
//! ## In-tree impls
//!
//! - [`NoopExporter`] — used when `[observability].enabled = false`,
//!   so emit sites don't need to special-case the disabled path.
//! - [`RingFileExporter`] — production: writes JSONL frames into
//!   `<data_dir>/observability/{spans,metrics}/`.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use parking_lot::Mutex;

use crate::protocol::{
    hex_span_id, hex_trace_id, Frame, Stream, SCHEMA_VERSION,
};
use crate::ring::{RingConfig, SegmentWriter};
use crate::types::{MetricData, SpanData};

// ---------------------------------------------------------------------------
// Trait
// ---------------------------------------------------------------------------

/// Extensibility trait for observability export backends.
///
/// V3 ships exactly one production impl: [`RingFileExporter`].
/// Tests use [`InMemoryExporter`]. Future deployments may plug in
/// alternative impls (in-tree `TonicExporter` for trusted single-
/// process environments, or out-of-tree custom backends).
///
/// # Safety contract
///
/// - `export_spans` and `export_metrics` MUST be non-blocking.
/// - Failure MUST NOT propagate. Implementations log internally.
/// - Implementations MUST NOT log credential values, model
///   prompt/response bytes, or any field that crosses the redactor.
/// - Implementations MUST be `Send + Sync + 'static`.
pub trait ObservabilityExporter: Send + Sync + 'static {
    /// Export a batch of completed spans.
    fn export_spans(&self, spans: &[SpanData]);

    /// Export a batch of metric data points.
    fn export_metrics(&self, metrics: &[MetricData]);

    /// Graceful shutdown — flush pending batches and release any
    /// file descriptors.
    fn shutdown(&self);
}

// ---------------------------------------------------------------------------
// NoopExporter
// ---------------------------------------------------------------------------

/// No-op exporter. Used when `[observability].enabled = false`.
/// Avoids every emit site having to check a boolean — the hub holds
/// an `Arc<dyn ObservabilityExporter>` either way.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopExporter;

impl ObservabilityExporter for NoopExporter {
    fn export_spans(&self, _: &[SpanData]) {}
    fn export_metrics(&self, _: &[MetricData]) {}
    fn shutdown(&self) {}
}

// ---------------------------------------------------------------------------
// RingFileExporter
// ---------------------------------------------------------------------------

/// Production exporter. Writes one JSONL frame per call into the
/// kernel-owned ring directory under `<data_dir>/observability/`.
///
/// Internal locking: one mutex per stream (spans / metrics) so the
/// hub's two streams can flush concurrently without contention. The
/// individual mutex is `parking_lot::Mutex` (no async) — every emit
/// is bounded I/O and the hub already serialises bursts via its
/// queue.
pub struct RingFileExporter {
    spans:        Arc<Mutex<SegmentWriter>>,
    metrics:      Arc<Mutex<SegmentWriter>>,
    kernel_version: String,
}

impl RingFileExporter {
    /// Open the ring under `<root>/spans/` and `<root>/metrics/`.
    /// `kernel_version` is the value the pusher reads as the OTel
    /// `InstrumentationScope.version` label.
    pub fn open(
        root:           impl AsRef<Path>,
        cfg:            RingConfig,
        kernel_version: impl Into<String>,
    ) -> std::io::Result<Self> {
        let root = root.as_ref();
        std::fs::create_dir_all(root)?;
        let spans = SegmentWriter::open(root, Stream::Spans, cfg)
            .map_err(into_io)?;
        let metrics = SegmentWriter::open(root, Stream::Metrics, cfg)
            .map_err(into_io)?;
        Ok(Self {
            spans:          Arc::new(Mutex::new(spans)),
            metrics:        Arc::new(Mutex::new(metrics)),
            kernel_version: kernel_version.into(),
        })
    }

    /// Path to the spans subdir; useful for tests.
    pub fn spans_dir(&self) -> PathBuf { self.spans.lock().dir().to_owned() }

    /// Path to the metrics subdir; useful for tests.
    pub fn metrics_dir(&self) -> PathBuf { self.metrics.lock().dir().to_owned() }

    fn export_one_span(&self, span: &SpanData) {
        let frame = Frame::Span {
            schema:         SCHEMA_VERSION,
            kernel_version: self.kernel_version.clone(),
            trace_id:       hex_trace_id(span.trace_id),
            span_id:        hex_span_id(span.span_id),
            span:           span.clone(),
        };
        match serde_json::to_string(&frame) {
            Ok(line) => {
                let mut g = self.spans.lock();
                if let Err(e) = g.write_line(&line) {
                    eprintln!(
                        "{{\"level\":\"warn\",\"event\":\"observability_span_write_failed\",\
                         \"error\":\"{e}\"}}",
                    );
                }
            }
            Err(e) => {
                eprintln!(
                    "{{\"level\":\"warn\",\"event\":\"observability_span_serialize_failed\",\
                     \"error\":\"{e}\"}}",
                );
            }
        }
    }

    fn export_one_metric(&self, metric: &MetricData) {
        let frame = Frame::Metric {
            schema:         SCHEMA_VERSION,
            kernel_version: self.kernel_version.clone(),
            metric:         metric.clone(),
        };
        match serde_json::to_string(&frame) {
            Ok(line) => {
                let mut g = self.metrics.lock();
                if let Err(e) = g.write_line(&line) {
                    eprintln!(
                        "{{\"level\":\"warn\",\"event\":\"observability_metric_write_failed\",\
                         \"error\":\"{e}\"}}",
                    );
                }
            }
            Err(e) => {
                eprintln!(
                    "{{\"level\":\"warn\",\"event\":\"observability_metric_serialize_failed\",\
                     \"error\":\"{e}\"}}",
                );
            }
        }
    }
}

impl ObservabilityExporter for RingFileExporter {
    fn export_spans(&self, spans: &[SpanData]) {
        for s in spans {
            self.export_one_span(s);
        }
        let _ = self.spans.lock().flush();
    }

    fn export_metrics(&self, metrics: &[MetricData]) {
        for m in metrics {
            self.export_one_metric(m);
        }
        let _ = self.metrics.lock().flush();
    }

    fn shutdown(&self) {
        let _ = self.spans.lock().flush();
        let _ = self.metrics.lock().flush();
    }
}

fn into_io(err: crate::ring::RingError) -> std::io::Error {
    std::io::Error::other(err.to_string())
}

// ---------------------------------------------------------------------------
// InMemoryExporter — test-only
// ---------------------------------------------------------------------------

/// Test fixture: collects spans and metrics into in-memory vectors.
/// Used by integration tests that need to assert on emitted data
/// without touching the filesystem.
#[derive(Debug, Default)]
pub struct InMemoryExporter {
    spans:    Mutex<Vec<SpanData>>,
    metrics:  Mutex<Vec<MetricData>>,
    shutdown: Mutex<bool>,
}

impl InMemoryExporter {
    /// Create a fresh exporter with empty buffers.
    pub fn new() -> Self { Self::default() }

    /// Snapshot the spans buffer.
    pub fn spans(&self) -> Vec<SpanData> { self.spans.lock().clone() }

    /// Snapshot the metrics buffer.
    pub fn metrics(&self) -> Vec<MetricData> { self.metrics.lock().clone() }

    /// Whether `shutdown()` has been called at least once.
    pub fn shutdown_called(&self) -> bool { *self.shutdown.lock() }
}

impl ObservabilityExporter for InMemoryExporter {
    fn export_spans(&self, spans: &[SpanData]) {
        self.spans.lock().extend(spans.iter().cloned());
    }
    fn export_metrics(&self, metrics: &[MetricData]) {
        self.metrics.lock().extend(metrics.iter().cloned());
    }
    fn shutdown(&self) {
        *self.shutdown.lock() = true;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{Frame};
    use crate::types::{
        AttrMap, AttrValue, DataPoint, MetricData, MetricName, MetricType, SpanData,
        SpanKind, SpanName, SpanStatus, Unit,
    };

    fn sample_span() -> SpanData {
        SpanData {
            trace_id:         [1; 16],
            span_id:          [2; 8],
            parent_span_id:   None,
            name:             SpanName::IntentAdmission,
            kind:             SpanKind::Internal,
            start_unix_nanos: 0,
            end_unix_nanos:   100,
            status:           SpanStatus::Ok,
            status_message:   None,
            attrs:            {
                let mut m = AttrMap::new();
                m.insert("verdict".to_owned(), AttrValue::Str("Accepted".into()));
                m
            },
            events:           vec![],
        }
    }

    fn sample_metric() -> MetricData {
        MetricData {
            name:         MetricName::IntentAdmissionTotal,
            metric_type:  MetricType::Counter,
            unit:         Unit::None,
            labels:       AttrMap::new(),
            datapoint:    DataPoint::Sum { value: 1.0 },
            unix_nanos:   0,
        }
    }

    #[test]
    fn ring_file_exporter_writes_span_frames() {
        let tmp = tempfile::tempdir().unwrap();
        let exp = RingFileExporter::open(tmp.path(), RingConfig::default(), "0.1.0").unwrap();
        exp.export_spans(&[sample_span()]);
        exp.shutdown();
        let path = exp.spans_dir().join("000001.jsonl");
        let body = std::fs::read_to_string(&path).unwrap();
        assert!(body.starts_with("{\"kind\":\"span\""));
        let f: Frame = serde_json::from_str(body.trim_end()).unwrap();
        match f {
            Frame::Span { schema, span, .. } => {
                assert_eq!(schema, 1);
                assert_eq!(span.name, SpanName::IntentAdmission);
            }
            _ => panic!("expected span frame"),
        }
    }

    #[test]
    fn ring_file_exporter_writes_metric_frames() {
        let tmp = tempfile::tempdir().unwrap();
        let exp = RingFileExporter::open(tmp.path(), RingConfig::default(), "0.1.0").unwrap();
        exp.export_metrics(&[sample_metric()]);
        exp.shutdown();
        let path = exp.metrics_dir().join("000001.jsonl");
        let body = std::fs::read_to_string(&path).unwrap();
        assert!(body.starts_with("{\"kind\":\"metric\""));
    }

    #[test]
    fn noop_exporter_is_silent() {
        let exp = NoopExporter;
        exp.export_spans(&[sample_span()]);
        exp.export_metrics(&[sample_metric()]);
        exp.shutdown();
    }

    #[test]
    fn in_memory_exporter_collects_data() {
        let exp = InMemoryExporter::new();
        exp.export_spans(&[sample_span()]);
        exp.export_metrics(&[sample_metric()]);
        assert_eq!(exp.spans().len(), 1);
        assert_eq!(exp.metrics().len(), 1);
        assert!(!exp.shutdown_called());
        exp.shutdown();
        assert!(exp.shutdown_called());
    }

    #[test]
    fn ring_file_exporter_creates_subdirs() {
        let tmp = tempfile::tempdir().unwrap();
        let exp = RingFileExporter::open(tmp.path(), RingConfig::default(), "0.1.0").unwrap();
        assert!(tmp.path().join("spans").is_dir());
        assert!(tmp.path().join("metrics").is_dir());
        drop(exp);
    }
}

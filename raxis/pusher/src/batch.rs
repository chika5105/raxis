//! Bounded batcher.
//!
//! Spec: `v3/otel-observability.md §12.3`.
//!
//! Holds up to `otlp_batch_size` frames, plus a flush deadline. The
//! main loop pushes frames onto the batch, then flushes when:
//!
//! 1. `is_full()` returns true (reached `batch_size`), OR
//! 2. The flush timer ticks and `is_empty()` is false.
//!
//! The batch is *typed* by stream — spans and metrics never mix
//! into a single OTLP request because the OTLP wire-protocol uses
//! different top-level messages (`ResourceSpans` vs.
//! `ResourceMetrics`).

use raxis_observability::protocol::{Frame, Stream};
use raxis_observability::types::{MetricData, SpanData};

use crate::cursor::CursorEntry;

/// One typed batch waiting to ship.
#[derive(Debug)]
pub struct Batch {
    /// Stream this batch targets (spans or metrics).
    pub stream: Stream,
    /// Spans in the batch (only populated when `stream == Spans`).
    pub spans: Vec<SpanData>,
    /// Metrics in the batch (only populated when `stream == Metrics`).
    pub metrics: Vec<MetricData>,
    /// Bytes the batch represents on disk; used by the cursor to
    /// advance after a successful export. Tracks the total raw
    /// JSONL bytes (including the trailing newline of each frame).
    pub bytes: u64,
    /// Per-segment "tail" cursor — the highest (segment, offset)
    /// the batch has consumed. Used to advance the cursor after
    /// the OTLP ack.
    pub tail: CursorEntry,
    /// The kernel version label on the first frame in the batch;
    /// used by the OTLP encoder for the
    /// `InstrumentationScope.version` field.
    pub kernel_version: String,
    /// `otlp_batch_size` — caller-supplied cap.
    cap: usize,
}

impl Batch {
    /// Create an empty batch for `stream` with capacity `cap`.
    pub fn new(stream: Stream, cap: usize) -> Self {
        Self {
            stream,
            spans:           Vec::with_capacity(cap),
            metrics:         Vec::with_capacity(cap),
            bytes:           0,
            tail:            CursorEntry::default(),
            kernel_version:  String::new(),
            cap,
        }
    }

    /// Number of frames in the batch.
    pub fn len(&self) -> usize {
        match self.stream {
            Stream::Spans   => self.spans.len(),
            Stream::Metrics => self.metrics.len(),
        }
    }

    /// True iff the batch has no frames.
    pub fn is_empty(&self) -> bool { self.len() == 0 }

    /// True iff the batch has reached `cap`.
    pub fn is_full(&self) -> bool { self.len() >= self.cap }

    /// Push a frame into the batch. The frame's wire-bytes (length
    /// of its JSONL line + `\n`) feed `self.bytes` so the caller
    /// can advance the cursor exactly. Tail (`segment`, `offset`)
    /// is the position *after* the frame — i.e. where the next
    /// read will start.
    pub fn push(&mut self, frame: Frame, frame_bytes: u64, tail: CursorEntry) -> PushOutcome {
        let kv = match &frame {
            Frame::Span        { kernel_version, .. } => kernel_version.clone(),
            Frame::Metric      { kernel_version, .. } => kernel_version.clone(),
            Frame::PusherEvent { .. }                 => String::new(),
        };
        if self.kernel_version.is_empty() && !kv.is_empty() {
            self.kernel_version = kv;
        }
        match (self.stream, frame) {
            (Stream::Spans, Frame::Span { span, .. }) => {
                self.spans.push(span);
                self.bytes += frame_bytes;
                self.tail = tail;
            }
            (Stream::Metrics, Frame::Metric { metric, .. }) => {
                self.metrics.push(metric);
                self.bytes += frame_bytes;
                self.tail = tail;
            }
            (s, other) => return PushOutcome::WrongKind {
                expected: s,
                got:      kind_of(&other),
            },
        }
        if self.is_full() {
            PushOutcome::AcceptedFull
        } else {
            PushOutcome::Accepted
        }
    }

    /// Reset the batch in place, preserving its capacity. Called
    /// after a successful OTLP export.
    pub fn reset(&mut self) {
        self.spans.clear();
        self.metrics.clear();
        self.bytes = 0;
        self.tail = CursorEntry::default();
        self.kernel_version.clear();
    }
}

/// Outcome of a [`Batch::push`].
#[derive(Debug, PartialEq, Eq)]
pub enum PushOutcome {
    /// Frame appended; batch has room for more.
    Accepted,
    /// Frame appended; batch is now full and SHOULD be flushed.
    AcceptedFull,
    /// Frame rejected because its kind doesn't match the batch's
    /// stream. Caller logs and skips.
    WrongKind {
        /// The batch's stream.
        expected: Stream,
        /// The frame's actual kind, as a stable label.
        got: &'static str,
    },
}

fn kind_of(f: &Frame) -> &'static str {
    match f {
        Frame::Span        { .. } => "span",
        Frame::Metric      { .. } => "metric",
        Frame::PusherEvent { .. } => "pusher_event",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use raxis_observability::protocol::{hex_span_id, hex_trace_id, SCHEMA_VERSION};
    use raxis_observability::types::{
        AttrMap, DataPoint, MetricName, MetricType, SpanKind, SpanName, SpanStatus, Unit,
    };

    fn span_frame() -> Frame {
        Frame::Span {
            schema:         SCHEMA_VERSION,
            kernel_version: "0.1.0".into(),
            trace_id:       hex_trace_id([1; 16]),
            span_id:        hex_span_id([2; 8]),
            span: SpanData {
                trace_id: [1; 16],
                span_id:  [2; 8],
                parent_span_id: None,
                name:     SpanName::IntentAdmission,
                kind:     SpanKind::Internal,
                start_unix_nanos: 0,
                end_unix_nanos:   1,
                status:   SpanStatus::Ok,
                status_message: None,
                attrs:    AttrMap::new(),
                events:   vec![],
            },
        }
    }

    fn metric_frame() -> Frame {
        Frame::Metric {
            schema:         SCHEMA_VERSION,
            kernel_version: "0.1.0".into(),
            metric: MetricData {
                name:        MetricName::IntentAdmissionTotal,
                metric_type: MetricType::Counter,
                unit:        Unit::None,
                labels:      AttrMap::new(),
                datapoint:   DataPoint::Sum { value: 1.0 },
                unix_nanos:  0,
            },
        }
    }

    #[test]
    fn push_accepts_until_full() {
        let mut b = Batch::new(Stream::Spans, 2);
        let f1 = b.push(
            span_frame(),
            120,
            CursorEntry { segment: "000001.jsonl".into(), offset: 120 },
        );
        assert_eq!(f1, PushOutcome::Accepted);
        let f2 = b.push(
            span_frame(),
            120,
            CursorEntry { segment: "000001.jsonl".into(), offset: 240 },
        );
        assert_eq!(f2, PushOutcome::AcceptedFull);
        assert!(b.is_full());
        assert_eq!(b.len(), 2);
        assert_eq!(b.bytes, 240);
        assert_eq!(b.tail.offset, 240);
        assert_eq!(b.kernel_version, "0.1.0");
    }

    #[test]
    fn push_rejects_wrong_kind() {
        let mut b = Batch::new(Stream::Spans, 2);
        let res = b.push(metric_frame(), 1, CursorEntry::default());
        match res {
            PushOutcome::WrongKind { expected, got } => {
                assert_eq!(expected, Stream::Spans);
                assert_eq!(got, "metric");
            }
            other => panic!("expected wrongkind, got {other:?}"),
        }
        assert!(b.is_empty());
    }

    #[test]
    fn reset_clears_state_but_keeps_capacity() {
        let mut b = Batch::new(Stream::Metrics, 4);
        b.push(metric_frame(), 50, CursorEntry { segment: "x".into(), offset: 50 });
        b.push(metric_frame(), 50, CursorEntry { segment: "x".into(), offset: 100 });
        assert_eq!(b.len(), 2);
        b.reset();
        assert_eq!(b.len(), 0);
        assert_eq!(b.bytes, 0);
        assert_eq!(b.tail, CursorEntry::default());
        assert_eq!(b.kernel_version, "");
        // capacity preserved (Vec keeps its allocation).
    }
}

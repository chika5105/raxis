//! Sidecar JSONL frame format the kernel writes and the
//! `raxis-otel-pusher` binary reads.
//!
//! Spec: `v3/otel-observability.md §4`.
//!
//! ## Frame discipline
//!
//! Every frame is one self-contained JSON object on a single line.
//! No streaming, no continuation, no partial frames. The kernel writes
//! whole lines via `BufWriter::write_all` followed by `flush()` so a
//! crash leaves at most a trailing partial line that the pusher
//! detects (no terminating `\n`) and discards.
//!
//! Two frame kinds: `span` and `metric`. A frame's `kind` field is
//! the discriminator; `schema` is the integer schema version (`1` in
//! V3 — bump on any wire-incompatible change so the pusher can
//! reject unknown schemas instead of silently mis-shipping data).
//!
//! ## File layout
//!
//! ```text
//! <data_dir>/observability/
//! ├── spans/
//! │   ├── 0001.jsonl         ← `Frame::Span`
//! │   ├── 0002.jsonl
//! ├── metrics/
//! │   ├── 0001.jsonl         ← `Frame::Metric`
//! ├── cursor.toml            ← pusher-owned
//! └── lock                   ← advisory flock
//! ```

use serde::{Deserialize, Serialize};

use crate::types::{MetricData, SpanData};

/// Wire schema version. Increment on any backwards-incompatible
/// frame change. The pusher refuses to ship unknown schemas.
pub const SCHEMA_VERSION: u32 = 1;

/// Stream type — one underlying directory per stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Stream {
    /// Span frames live under `<data_dir>/observability/spans/`.
    Spans,
    /// Metric frames live under `<data_dir>/observability/metrics/`.
    Metrics,
}

impl Stream {
    /// Subdirectory name relative to the observability root.
    pub fn subdir(&self) -> &'static str {
        match self {
            Self::Spans => "spans",
            Self::Metrics => "metrics",
        }
    }
}

/// One frame on a single line of a `*.jsonl` segment. Tagged by
/// `kind`, versioned by `schema`. Adding fields is forwards-
/// compatible (older pushers ignore unknown fields); removing
/// fields requires a `schema` bump.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Frame {
    /// One [`SpanData`] frame.
    Span {
        /// Schema version; equals [`SCHEMA_VERSION`] for frames the
        /// kernel writes today.
        schema: u32,
        /// Kernel binary version that produced the frame; used by the
        /// pusher as the OTel `InstrumentationScope.version` label.
        kernel_version: String,
        /// Trace identifier (32-hex string).
        trace_id: String,
        /// Span identifier (16-hex string).
        span_id: String,
        /// Span payload.
        span: SpanData,
    },
    /// One [`MetricData`] frame.
    Metric {
        /// Schema version.
        schema: u32,
        /// Kernel binary version.
        kernel_version: String,
        /// Metric payload.
        metric: MetricData,
    },
    /// Pusher-emitted health back-channel frame the kernel reads
    /// during heartbeat ticks. Lives in `pusher-events.jsonl`.
    PusherEvent {
        /// Schema version.
        schema: u32,
        /// Pusher binary version.
        pusher_version: String,
        /// Wallclock at emission, ns since UNIX epoch.
        unix_nanos: u64,
        /// Event tag.
        tag: PusherEventTag,
        /// Free-form key/value annotations (sanitised by the pusher).
        attrs: std::collections::BTreeMap<String, serde_json::Value>,
    },
}

/// Closed list of pusher-emitted health events. The kernel only
/// needs to know the tag — the attributes are diagnostic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PusherEventTag {
    /// Pusher started; attaches `pusher_version`, `pid`.
    Started,
    /// Pusher about to exit cleanly.
    Stopping,
    /// One OTLP export round succeeded.
    ExportOk,
    /// One OTLP export round failed and was retried.
    ExportRetry,
    /// One batch was permanently dropped after exceeding retry budget.
    ExportPermanentFailure,
    /// Cursor advanced past one segment boundary.
    SegmentAdvanced,
}

/// Render a hex-encoded trace id (32 chars).
pub fn hex_trace_id(id: [u8; 16]) -> String {
    let mut s = String::with_capacity(32);
    for b in id {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

/// Render a hex-encoded span id (16 chars).
pub fn hex_span_id(id: [u8; 8]) -> String {
    let mut s = String::with_capacity(16);
    for b in id {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

/// Parse a 32-char hex trace id into bytes; returns `None` on shape error.
pub fn parse_trace_id(s: &str) -> Option<[u8; 16]> {
    if s.len() != 32 {
        return None;
    }
    let mut out = [0u8; 16];
    for (i, byte) in out.iter_mut().enumerate() {
        let hi = hex_digit(s.as_bytes()[i * 2])?;
        let lo = hex_digit(s.as_bytes()[i * 2 + 1])?;
        *byte = (hi << 4) | lo;
    }
    Some(out)
}

/// Parse a 16-char hex span id into bytes; returns `None` on shape error.
pub fn parse_span_id(s: &str) -> Option<[u8; 8]> {
    if s.len() != 16 {
        return None;
    }
    let mut out = [0u8; 8];
    for (i, byte) in out.iter_mut().enumerate() {
        let hi = hex_digit(s.as_bytes()[i * 2])?;
        let lo = hex_digit(s.as_bytes()[i * 2 + 1])?;
        *byte = (hi << 4) | lo;
    }
    Some(out)
}

fn hex_digit(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(10 + (b - b'a')),
        b'A'..=b'F' => Some(10 + (b - b'A')),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{
        AttrMap, DataPoint, MetricData, MetricName, MetricType, SpanData, SpanKind, SpanName,
        SpanStatus, Unit,
    };

    fn sample_span() -> SpanData {
        SpanData {
            trace_id: [1; 16],
            span_id: [2; 8],
            parent_span_id: None,
            name: SpanName::IntentAdmission,
            kind: SpanKind::Internal,
            start_unix_nanos: 0,
            end_unix_nanos: 1,
            status: SpanStatus::Ok,
            status_message: None,
            attrs: AttrMap::new(),
            events: vec![],
        }
    }

    #[test]
    fn span_frame_round_trips_jsonl() {
        let f = Frame::Span {
            schema: SCHEMA_VERSION,
            kernel_version: "0.1.0".into(),
            trace_id: hex_trace_id([1; 16]),
            span_id: hex_span_id([2; 8]),
            span: sample_span(),
        };
        let line = serde_json::to_string(&f).unwrap();
        assert!(line.starts_with("{\"kind\":\"span\""));
        let back: Frame = serde_json::from_str(&line).unwrap();
        assert_eq!(f, back);
    }

    #[test]
    fn metric_frame_round_trips_jsonl() {
        let m = MetricData {
            name: MetricName::IntentAdmissionTotal,
            metric_type: MetricType::Counter,
            unit: Unit::None,
            labels: AttrMap::new(),
            datapoint: DataPoint::Sum { value: 1.0 },
            unix_nanos: 0,
        };
        let f = Frame::Metric {
            schema: SCHEMA_VERSION,
            kernel_version: "0.1.0".into(),
            metric: m,
        };
        let line = serde_json::to_string(&f).unwrap();
        let back: Frame = serde_json::from_str(&line).unwrap();
        assert_eq!(f, back);
    }

    #[test]
    fn hex_trace_id_round_trips() {
        let id = [
            0x01, 0x95, 0x2c, 0x0f, 0xe0, 0xa0, 0x7f, 0x37, 0x81, 0xe4, 0xf5, 0xe6, 0xa2, 0xa9,
            0x1c, 0x00,
        ];
        let s = hex_trace_id(id);
        assert_eq!(s, "01952c0fe0a07f3781e4f5e6a2a91c00");
        assert_eq!(parse_trace_id(&s), Some(id));
    }

    #[test]
    fn hex_span_id_round_trips() {
        let id = [0x8e, 0x3a, 0x06, 0xb7, 0xd2, 0xc5, 0xfa, 0x11];
        let s = hex_span_id(id);
        assert_eq!(s, "8e3a06b7d2c5fa11");
        assert_eq!(parse_span_id(&s), Some(id));
    }

    #[test]
    fn parse_trace_id_rejects_wrong_length() {
        assert!(parse_trace_id("abcd").is_none());
        assert!(parse_trace_id("X".repeat(32).as_str()).is_none());
    }

    #[test]
    fn unknown_kind_field_fails_parse() {
        let bad = r#"{"kind":"unknown","schema":1}"#;
        let res: Result<Frame, _> = serde_json::from_str(bad);
        assert!(res.is_err());
    }
}

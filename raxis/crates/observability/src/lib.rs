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

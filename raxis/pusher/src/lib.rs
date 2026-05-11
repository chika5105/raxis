//! `raxis-otel-pusher` — OTel sidecar that reads kernel-emitted
//! JSONL frames from `<data_dir>/observability/{spans,metrics}/`
//! and ships them off-host via OTLP HTTP/protobuf.
//!
//! Normative reference: `specs/v3/otel-observability.md §12`.
//!
//! This crate is split into a thin `main.rs` (CLI bootstrap +
//! tokio runtime) and a library so the integration test crate can
//! drive the cursor / segment-reader / batcher / OTLP-client
//! state machines against in-tree fixtures without spawning a
//! subprocess.
//!
//! ## Trust boundary
//!
//! The pusher is the **only** process in the RAXIS workspace that
//! talks OTLP. The kernel never imports `reqwest`, `prost`, or
//! `tonic` (`INV-OTEL-03`). The pusher runs under its own UID
//! (`raxis-otel`) with read access to the observability ring and
//! network egress to the operator-configured OTLP collector — and
//! nothing else.
//!
//! ## Module layout
//!
//! - [`config`] — pusher-side view of `[observability]` policy
//!   knobs.
//! - [`cursor`] — `cursor.toml` persistence (segment + offset
//!   resume points, last-export wallclock).
//! - [`reader`] — segment + JSONL line reader.
//! - [`batch`] — bounded span/metric batcher with flush-interval.
//! - [`otlp`] — minimal OTLP HTTP/protobuf encoder + client.
//! - [`retry`] — exponential backoff + jitter helper used by the
//!   OTLP client.
//! - [`health`] — `/healthz` HTTP server.
//! - [`run`] — top-level main loop; combines the modules above.

#![forbid(unsafe_code)]
#![deny(rust_2018_idioms)]
#![warn(missing_docs)]

pub mod batch;
pub mod config;
pub mod cursor;
pub mod health;
pub mod otlp;
pub mod reader;
pub mod retry;
pub mod run;

pub use config::PusherConfig;
pub use cursor::{Cursor, CursorEntry};
pub use otlp::{OtlpClient, OtlpEndpoint};
pub use reader::{Reader, ReaderError};
pub use run::{Pusher, PusherEvent};

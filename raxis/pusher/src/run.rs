//! Top-level pusher main loop.
//!
//! Spec: `v3/otel-observability.md §12.3`.
//!
//! This is where the [`config`], [`cursor`], [`reader`], [`batch`],
//! [`otlp`], [`retry`] and [`health`] modules are wired together.
//!
//! ```text
//!     ┌──────────────┐
//!     │ Reader::Spans├──┐
//!     └──────────────┘  │  ┌─────────────┐    ┌──────────────┐
//!                       ├──▶ Batch (Spans) ├──▶ OtlpClient    │
//!     ┌──────────────┐  │  │+ Batch (Met.) │    │ HTTP/proto   │
//!     │ Reader::Met. ├──┘  └─────────────┘    └──────────────┘
//!     └──────────────┘            │                    │
//!                            cursor.persist        health.publish
//!                            after every ack       after every tick
//! ```

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use raxis_observability::protocol::Stream;
use tokio::sync::Mutex;

use crate::batch::{Batch, PushOutcome};
use crate::config::PusherConfig;
use crate::cursor::{Cursor, CursorEntry};
use crate::health::{HealthHandle, HealthSnapshot};
use crate::otlp::{OtlpClient, OtlpExportError};
use crate::reader::Reader;
use crate::retry::BackoffPolicy;

/// Per-tick events the main loop emits to the kernel via
/// `pusher-events.jsonl` (or to integration tests via a hook).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PusherEvent {
    /// Pusher started a fresh boot.
    Started,
    /// One OTLP export round succeeded with a non-empty batch.
    ExportOk {
        /// Stream the batch targeted.
        stream: Stream,
        /// Number of frames in the batch.
        frames: usize,
        /// HTTP status code from the collector.
        status: u16,
    },
    /// One OTLP export round failed and was retried.
    ExportRetry {
        /// Stream the batch targeted.
        stream: Stream,
        /// Attempt counter (0-indexed; 0 = first retry).
        attempt: u32,
        /// Stable failure tag.
        reason: String,
    },
    /// One OTLP batch was permanently dropped after exhausting
    /// retries.
    ExportPermanentFailure {
        /// Stream the batch targeted.
        stream: Stream,
        /// Frames dropped.
        frames: usize,
        /// Last failure reason.
        reason: String,
    },
    /// Cursor advanced past one segment boundary.
    SegmentAdvanced {
        /// Stream that rotated.
        stream: Stream,
        /// New segment file name.
        new_segment: String,
    },
    /// Pusher shutting down cleanly.
    Stopping,
}

/// Top-level pusher state. Owns the runtime objects (readers,
/// batches, OTLP client) and the cursor.
pub struct Pusher {
    cfg: Arc<PusherConfig>,
    client: OtlpClient,
    backoff: BackoffPolicy,
    health: Option<HealthHandle>,
    state: Arc<Mutex<PusherState>>,
}

struct PusherState {
    cursor: Cursor,
    spans: Reader,
    metrics: Reader,
    span_batch: Batch,
    metric_batch: Batch,
    spans_exported_total: u64,
    metrics_exported_total: u64,
    spans_dropped_total: u64,
}

impl Pusher {
    /// Construct a pusher from a validated config. Opens the
    /// readers + initial batches; loads (or initialises) the
    /// cursor.
    pub fn new(cfg: PusherConfig, client: OtlpClient) -> Result<Self, PusherInitError> {
        let cursor = Cursor::load_or_init(&cfg.cursor_path).map_err(PusherInitError::Cursor)?;
        let mut spans = Reader::new(cfg.segment_dir(Stream::Spans));
        let mut metrics = Reader::new(cfg.segment_dir(Stream::Metrics));
        spans
            .open_from_cursor(cursor.entry(Stream::Spans))
            .map_err(PusherInitError::Reader)?;
        metrics
            .open_from_cursor(cursor.entry(Stream::Metrics))
            .map_err(PusherInitError::Reader)?;
        let backoff = BackoffPolicy {
            initial: cfg.pusher.backoff_initial,
            max: cfg.pusher.backoff_max,
            jitter: cfg.pusher.backoff_jitter,
            max_attempts: 8,
        };
        let span_batch = Batch::new(Stream::Spans, cfg.batch_size());
        let metric_batch = Batch::new(Stream::Metrics, cfg.batch_size());
        let cfg = Arc::new(cfg);
        Ok(Self {
            cfg,
            client,
            backoff,
            health: None,
            state: Arc::new(Mutex::new(PusherState {
                cursor,
                spans,
                metrics,
                span_batch,
                metric_batch,
                spans_exported_total: 0,
                metrics_exported_total: 0,
                spans_dropped_total: 0,
            })),
        })
    }

    /// Plug a health handle so the main loop publishes snapshots
    /// to `/healthz`. Optional — tests don't need it.
    pub fn with_health(mut self, h: HealthHandle) -> Self {
        self.health = Some(h);
        self
    }

    /// Drive ONE tick of the main loop. Drains both readers up to
    /// the batch cap, flushes any batch that filled or deadline-
    /// expired, persists the cursor on success.
    ///
    /// Returns the events the tick produced (useful for tests).
    pub async fn tick(&self, deadline_passed: bool) -> Vec<PusherEvent> {
        let mut events = Vec::new();
        let mut state = self.state.lock().await;
        // 1. Pull from each stream into its batch.
        for stream in [Stream::Spans, Stream::Metrics] {
            self.pull_into_batch(&mut state, stream, &mut events).await;
        }
        // 2. Flush full or stale batches.
        for stream in [Stream::Spans, Stream::Metrics] {
            let must_flush = {
                let b = pick_batch(&mut state, stream);
                b.is_full() || (deadline_passed && !b.is_empty())
            };
            if must_flush {
                self.flush_one(&mut state, stream, &mut events).await;
            }
        }
        // 3. Update cursor + segment-rotation handling.
        self.advance_segments_if_rotated(&mut state, &mut events);
        // 4. Publish health snapshot.
        if let Some(h) = &self.health {
            h.publish(self.snapshot(&state));
        }
        events
    }

    async fn pull_into_batch(
        &self,
        state: &mut PusherState,
        stream: Stream,
        events: &mut Vec<PusherEvent>,
    ) {
        let cap = self.cfg.batch_size();
        for _ in 0..cap {
            let frame = {
                let r = pick_reader(state, stream);
                match r.next_frame() {
                    Ok(Some(f)) => f,
                    Ok(None) => return,
                    Err(e) => {
                        events.push(PusherEvent::ExportRetry {
                            stream,
                            attempt: 0,
                            reason: format!("reader error: {e}"),
                        });
                        return;
                    }
                }
            };
            let entry = pick_reader(state, stream).entry().unwrap_or_default();
            // Approximate frame_bytes by re-serialising — fine for
            // V3; future optim is to thread the actual byte count
            // out of the reader.
            let bytes = serde_json::to_string(&frame)
                .map(|s| (s.len() + 1) as u64)
                .unwrap_or(0);
            let outcome = pick_batch(state, stream).push(frame, bytes, entry);
            if let PushOutcome::AcceptedFull = outcome {
                self.flush_one(state, stream, events).await;
                if pick_batch(state, stream).is_full() {
                    break;
                }
            }
        }
    }

    async fn flush_one(
        &self,
        state: &mut PusherState,
        stream: Stream,
        events: &mut Vec<PusherEvent>,
    ) {
        if pick_batch(state, stream).is_empty() {
            return;
        }
        let kernel_version = pick_batch(state, stream).kernel_version.clone();
        let mut attempt = 0;
        let frames = pick_batch(state, stream).len();
        loop {
            let result = match stream {
                Stream::Spans => {
                    self.client
                        .export_spans(&state.span_batch.spans, &kernel_version)
                        .await
                }
                Stream::Metrics => {
                    self.client
                        .export_metrics(&state.metric_batch.metrics, &kernel_version)
                        .await
                }
            };
            match result {
                Ok(status) if (200..300).contains(&status) => {
                    events.push(PusherEvent::ExportOk {
                        stream,
                        frames,
                        status,
                    });
                    self.record_success(state, stream).await;
                    return;
                }
                Ok(status) if (status == 408 || status == 429 || status >= 500) => {
                    if !self.backoff.should_retry(attempt) {
                        let dropped = pick_batch(state, stream).len();
                        state.spans_dropped_total += dropped as u64;
                        events.push(PusherEvent::ExportPermanentFailure {
                            stream,
                            frames: dropped,
                            reason: format!("http_{status}_after_{attempt}_retries"),
                        });
                        self.advance_cursor_drop(state, stream).await;
                        return;
                    }
                    let delay = self.backoff.delay(attempt);
                    events.push(PusherEvent::ExportRetry {
                        stream,
                        attempt,
                        reason: format!("http_{status}"),
                    });
                    state.cursor.record_failure();
                    tokio::time::sleep(delay).await;
                    attempt += 1;
                }
                Ok(status) => {
                    // 4xx other than 408/429 ⇒ config error; drop.
                    let dropped = pick_batch(state, stream).len();
                    state.spans_dropped_total += dropped as u64;
                    events.push(PusherEvent::ExportPermanentFailure {
                        stream,
                        frames: dropped,
                        reason: format!("http_{status}_client_error"),
                    });
                    self.advance_cursor_drop(state, stream).await;
                    return;
                }
                Err(OtlpExportError::Network { reason, .. }) => {
                    if !self.backoff.should_retry(attempt) {
                        let dropped = pick_batch(state, stream).len();
                        state.spans_dropped_total += dropped as u64;
                        events.push(PusherEvent::ExportPermanentFailure {
                            stream,
                            frames: dropped,
                            reason: format!("network_{reason}"),
                        });
                        self.advance_cursor_drop(state, stream).await;
                        return;
                    }
                    let delay = self.backoff.delay(attempt);
                    events.push(PusherEvent::ExportRetry {
                        stream,
                        attempt,
                        reason: format!("network: {reason}"),
                    });
                    state.cursor.record_failure();
                    tokio::time::sleep(delay).await;
                    attempt += 1;
                }
            }
        }
    }

    async fn record_success(&self, state: &mut PusherState, stream: Stream) {
        let now = unix_now();
        let frames = pick_batch(state, stream).len() as u64;
        let tail = pick_batch(state, stream).tail.clone();
        match stream {
            Stream::Spans => state.spans_exported_total += frames,
            Stream::Metrics => state.metrics_exported_total += frames,
        }
        // Advance cursor to the tail of the just-shipped batch.
        if !tail.segment.is_empty() {
            *state.cursor.entry_mut(stream) = tail;
        }
        state.cursor.record_success(now);
        let _ = state.cursor.persist(&self.cfg.cursor_path);
        pick_batch(state, stream).reset();
    }

    async fn advance_cursor_drop(&self, state: &mut PusherState, stream: Stream) {
        let tail = pick_batch(state, stream).tail.clone();
        if !tail.segment.is_empty() {
            *state.cursor.entry_mut(stream) = tail;
        }
        let _ = state.cursor.persist(&self.cfg.cursor_path);
        pick_batch(state, stream).reset();
    }

    fn advance_segments_if_rotated(&self, state: &mut PusherState, events: &mut Vec<PusherEvent>) {
        for stream in [Stream::Spans, Stream::Metrics] {
            let r = pick_reader(state, stream);
            match r.is_rotated() {
                Ok(true) => {
                    if matches!(r.next_frame(), Ok(None)) {
                        if let Ok(true) = r.advance_segment() {
                            let new_seg = r.current_segment().to_owned();
                            let entry = CursorEntry {
                                segment: new_seg.clone(),
                                offset: 0,
                            };
                            *state.cursor.entry_mut(stream) = entry;
                            let _ = state.cursor.persist(&self.cfg.cursor_path);
                            events.push(PusherEvent::SegmentAdvanced {
                                stream,
                                new_segment: new_seg,
                            });
                        }
                    }
                }
                _ => {}
            }
        }
    }

    fn snapshot(&self, state: &PusherState) -> HealthSnapshot {
        let status = match state.cursor.consecutive_failures {
            0 => "ok",
            1..=4 => "degraded",
            _ => "failing",
        }
        .to_owned();
        HealthSnapshot {
            status,
            last_export_attempt_unix: unix_now(),
            last_export_success_unix: state.cursor.last_export_unix,
            consecutive_failures: state.cursor.consecutive_failures,
            spans_exported_total: state.spans_exported_total,
            metrics_exported_total: state.metrics_exported_total,
            spans_dropped_total: state.spans_dropped_total,
            cursor_lag_segments: 0,
        }
    }
}

fn pick_reader(state: &mut PusherState, stream: Stream) -> &mut Reader {
    match stream {
        Stream::Spans => &mut state.spans,
        Stream::Metrics => &mut state.metrics,
    }
}

fn pick_batch(state: &mut PusherState, stream: Stream) -> &mut Batch {
    match stream {
        Stream::Spans => &mut state.span_batch,
        Stream::Metrics => &mut state.metric_batch,
    }
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Errors raised while constructing a [`Pusher`].
#[derive(Debug, thiserror::Error)]
pub enum PusherInitError {
    /// Cursor load / initialisation failure.
    #[error("cursor: {0}")]
    Cursor(crate::cursor::CursorError),
    /// Reader open failure.
    #[error("reader: {0}")]
    Reader(crate::reader::ReaderError),
}

#[allow(dead_code)]
fn _hush_unused_duration(_: Duration) {}

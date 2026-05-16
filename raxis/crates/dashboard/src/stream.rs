//! Per-session agent-output stream surface
//! (agent stream capture).
//! The dashboard exposes the raw model-streaming output of every
//! active session via `GET /api/sessions/:id/stream` (SSE). This
//! module defines the wire-shape of one stream event and the
//! lightweight subscriber handle the SSE handler holds.
//! The underlying capture mechanism (bounded file ring + tokio
//! broadcast channel) lives in `raxis-dashboard-kernel` so the
//! dashboard crate stays decoupled from on-disk concerns. Tests
//! use [`SimpleStreamSource`] which skips the file ring entirely.

use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;

/// One frame in a session's model-output stream. `kind` is a
/// short discriminator string; `payload` is opaque JSON. The
/// SSE handler emits each event as a line of `event: <kind>\n
/// data: <json>\n\n`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamEvent {
    /// Unix milliseconds when the event was captured.
    pub at_ms: u64,
    /// Short discriminator string. Suggested vocabulary:
    /// `model_chunk`, `tool_call`, `tool_result`, `complete`,
    /// `error`. The wire is open — subscribers must tolerate
    /// new kinds.
    pub kind: String,
    /// Free-form JSON payload (the model chunk body, the tool
    /// call args, etc.). Bounded only by the file-ring's
    /// per-event size cap.
    pub payload: serde_json::Value,
}

/// One subscription to a session's stream. Wraps a tokio
/// broadcast receiver under a thin facade so the dashboard's
/// HTTP handlers do not depend on the broadcast channel API
/// (and so we can swap the transport later).
pub struct StreamSubscription {
    rx: broadcast::Receiver<StreamEvent>,
}

impl StreamSubscription {
    /// Build a new subscription from a broadcast receiver. Used
    /// by the kernel-glue capture module and the in-process
    /// fixture.
    pub fn new(rx: broadcast::Receiver<StreamEvent>) -> Self {
        Self { rx }
    }

    /// Receive the next event. Returns:
    ///   * `Ok(Some(evt))` — fresh event arrived,
    ///   * `Ok(None)` — the publisher dropped (session closed),
    ///   * `Err(lagged_count)` — slow subscriber missed
    ///     `lagged_count` events; the receiver remains usable.
    /// The SSE handler should forward `Err(_)` as an `event:
    /// lagged\n` frame and continue reading.
    pub async fn recv(&mut self) -> Result<Option<StreamEvent>, u64> {
        match self.rx.recv().await {
            Ok(evt) => Ok(Some(evt)),
            Err(broadcast::error::RecvError::Closed) => Ok(None),
            Err(broadcast::error::RecvError::Lagged(n)) => Err(n),
        }
    }
}

/// Convenience source that holds a broadcast sender and lets
/// callers append events. Used by the in-memory fixture to
/// simulate streaming without touching disk.
#[derive(Debug, Clone)]
pub struct SimpleStreamSource {
    tx: broadcast::Sender<StreamEvent>,
}

impl SimpleStreamSource {
    /// Build a fresh source with the given broadcast capacity
    /// (typical: 500).
    pub fn new(capacity: usize) -> Self {
        let (tx, _) = broadcast::channel(capacity);
        Self { tx }
    }

    /// Push one event to subscribers. Returns the number of
    /// active receivers that saw the event (for diagnostics).
    /// Lagged subscribers are discarded by the broadcast layer.
    pub fn push(&self, evt: StreamEvent) -> usize {
        self.tx.send(evt).unwrap_or(0)
    }

    /// Build a fresh subscription. Returned receivers see only
    /// events emitted AFTER this call — historical replay must
    /// come from the file-ring tail.
    pub fn subscribe(&self) -> StreamSubscription {
        StreamSubscription::new(self.tx.subscribe())
    }

    /// Number of currently-attached subscribers.
    pub fn subscriber_count(&self) -> usize {
        self.tx.receiver_count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn evt(kind: &str, n: u64) -> StreamEvent {
        StreamEvent {
            at_ms: n,
            kind: kind.into(),
            payload: serde_json::json!({"n": n}),
        }
    }

    #[tokio::test]
    async fn subscribe_then_push_delivers_to_subscriber() {
        let src = SimpleStreamSource::new(8);
        let mut sub = src.subscribe();
        src.push(evt("model_chunk", 1));
        let got = sub.recv().await.unwrap().unwrap();
        assert_eq!(got.kind, "model_chunk");
        assert_eq!(got.at_ms, 1);
    }

    #[tokio::test]
    async fn lagged_subscriber_reports_count_then_resumes() {
        let src = SimpleStreamSource::new(2);
        let mut sub = src.subscribe();
        for i in 0..5 {
            src.push(evt("x", i));
        }
        // First recv should report a lag of 3 (capacity 2 ⇒ 5
        // pushes overflows by 3).
        match sub.recv().await {
            Err(n) => assert!(n >= 1, "expected lag count, got {n}"),
            Ok(_) => panic!("expected lag"),
        }
        // After the lag report the remaining buffered events
        // should still arrive.
        let next = sub.recv().await.unwrap().unwrap();
        assert!(next.at_ms <= 4);
    }

    #[tokio::test]
    async fn dropping_source_closes_subscription() {
        let src = SimpleStreamSource::new(4);
        let mut sub = src.subscribe();
        drop(src);
        let res = sub.recv().await.unwrap();
        assert!(res.is_none(), "closed source must yield None");
    }

    #[test]
    fn stream_event_round_trips_json() {
        let e = evt("tool_call", 7);
        let s = serde_json::to_string(&e).unwrap();
        let back: StreamEvent = serde_json::from_str(&s).unwrap();
        assert_eq!(back.kind, "tool_call");
        assert_eq!(back.at_ms, 7);
    }
}

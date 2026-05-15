//! Per-initiative realtime event bus
//! (`v2_extended_gaps.md §2.1 SubscribeInitiative`).
//!
//! # Why an in-process broadcast bus
//!
//! The operator UDS is single-shot today, so before this module
//! every "subscribe" surface had to fall back to polling. The bus
//! lets the kernel publish lifecycle events (task FSM transitions,
//! escalations, integration merges, structured outputs, terminal
//! state) once, and have any number of `SubscribeInitiative`
//! sessions tap them via a `tokio::sync::broadcast` channel.
//!
//! There is no SQL-backed queue: the audit chain is the durable
//! record. Subscribers that attach late see only events emitted
//! after attach time, exactly the behaviour
//! `v2_extended_gaps.md §2.1` describes ("hold the connection
//! open … receive events as they happen"). Operators that need
//! the historical record use `raxis audit tail`.
//!
//! # Wire bridging
//!
//! The kernel does NOT publish raw `AuditEventKind` to subscribers
//! (that type lives in `raxis_audit_tools` and is too internal a
//! shape to commit to as a wire contract). Instead, the
//! [`audit_kind_to_initiative_event`] mapper translates the audit
//! enum into the public `raxis_types::InitiativeEvent` enum at
//! emit time. Adding a new operator-visible event therefore
//! requires:
//!
//! 1. An `AuditEventKind` variant (durable record).
//! 2. A mapping arm in `audit_kind_to_initiative_event`.
//! 3. A round-trip test in `initiative_event::tests`.
//! 4. A new variant in `InitiativeEvent` if no existing one fits.
//!
//! # Capacity & overflow
//!
//! Each per-initiative channel is sized to
//! [`PER_INITIATIVE_BROADCAST_CAPACITY`]. If a slow operator
//! subscriber falls more than that many events behind, it sees a
//! `RecvError::Lagged(n)` on the next recv; the streaming handler
//! surfaces a `Closed { reason: KernelShutdown }` frame and
//! disconnects so the operator can reconnect. Never crashing the
//! publisher is the property we care about.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use raxis_audit_tools::{AuditEvent, AuditEventKind, AuditSink, AuditWriterError};
use raxis_types::InitiativeEvent;
use tokio::sync::broadcast;

/// Per-initiative broadcast channel capacity. Sized for typical
/// task-DAG burst widths (V2 spec deep dive §Step 21 puts most
/// initiatives below 16 concurrent sub-tasks, with audit chatter
/// up to ~5x that). 256 leaves comfortable headroom; over-cap
/// subscribers see `Lagged` and reconnect rather than blocking
/// the publisher.
pub const PER_INITIATIVE_BROADCAST_CAPACITY: usize = 256;

/// Process-wide initiative-event bus. One instance lives in
/// `HandlerContext::initiative_bus`. Cloned via `Arc` into the
/// audit-sink wrapper and the operator-streaming handler.
///
/// Channel allocation is lazy: a publish or subscribe call
/// against an unknown initiative_id allocates the
/// `broadcast::Sender` on first touch. The bookkeeping mutex is
/// held briefly (HashMap entry insert) and never across an
/// `await` boundary, so it cannot deadlock with the runtime.
pub struct InitiativeEventBus {
    channels: Mutex<HashMap<String, broadcast::Sender<InitiativeEvent>>>,
}

impl InitiativeEventBus {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            channels: Mutex::new(HashMap::new()),
        })
    }

    /// Subscribe to events for `initiative_id`. The returned
    /// receiver yields events published AFTER subscription —
    /// historical events live on the audit chain, not in this
    /// bus. Stream lifecycle is owned by the caller; dropping the
    /// receiver decrements the subscriber count.
    pub fn subscribe(&self, initiative_id: &str) -> broadcast::Receiver<InitiativeEvent> {
        self.sender(initiative_id).subscribe()
    }

    /// Publish `event` on the channel for `initiative_id`.
    /// Best-effort: a `broadcast::Sender::send` returning `Err`
    /// means there are no live subscribers — that is the
    /// expected steady state when no operator is watching, and
    /// the audit chain remains the durable record.
    pub fn publish(&self, initiative_id: &str, event: InitiativeEvent) {
        let _ = self.sender(initiative_id).send(event);
    }

    /// Currently-attached subscriber count for `initiative_id`.
    /// Used by tests; production telemetry may eventually surface
    /// this through `raxis status`.
    pub fn subscriber_count(&self, initiative_id: &str) -> usize {
        self.channels
            .lock()
            .unwrap()
            .get(initiative_id)
            .map(|s| s.receiver_count())
            .unwrap_or(0)
    }

    fn sender(&self, initiative_id: &str) -> broadcast::Sender<InitiativeEvent> {
        let mut guard = self.channels.lock().unwrap();
        guard
            .entry(initiative_id.to_owned())
            .or_insert_with(|| {
                let (tx, _rx) = broadcast::channel(PER_INITIATIVE_BROADCAST_CAPACITY);
                tx
            })
            .clone()
    }
}

// ---------------------------------------------------------------------------
// audit_kind_to_initiative_event — kernel → public-wire mapping
// ---------------------------------------------------------------------------

/// Translate a `(AuditEventKind, task_id, emitted_at)` triple to
/// the public-wire `InitiativeEvent` shape. Returns `None` for
/// audit kinds that are not interesting to a
/// `SubscribeInitiative` stream (e.g. internal
/// cache-invalidations) — the audit chain still records them.
///
/// `task_id` comes from the `AuditSink::emit` call site (the
/// `task_id` argument). `emitted_at` is the audit row's commit
/// timestamp; the kernel mirrors the timestamp into the wire
/// frame so subscribers don't have to reconstruct it from
/// out-of-band clocks.
///
/// Adding a new wire-visible event requires:
///   1. Add the `InitiativeEvent` variant in `raxis-types`.
///   2. Add an arm here + a round-trip test in this file.
///   3. Add a round-trip test in `initiative_event::tests`.
pub fn audit_kind_to_initiative_event(
    kind: &AuditEventKind,
    task_id: Option<&str>,
    emitted_at: i64,
) -> Option<InitiativeEvent> {
    match kind {
        AuditEventKind::TaskStateChanged {
            task_id: t,
            from_state,
            to_state,
            ..
        } => Some(InitiativeEvent::TaskStateChanged {
            task_id: t.clone(),
            from_state: Some(from_state.clone()),
            to_state: to_state.clone(),
            transitioned_at: emitted_at,
        }),

        AuditEventKind::InitiativeStateChanged {
            from_state,
            to_state,
            ..
        } => Some(InitiativeEvent::InitiativeStateChanged {
            from_state: Some(from_state.clone()),
            to_state: to_state.clone(),
            transitioned_at: emitted_at,
        }),

        AuditEventKind::ReviewAggregationCompleted {
            executor_task_id,
            verdict,
            ..
        } => Some(InitiativeEvent::ReviewAggregationCompleted {
            task_id: executor_task_id.clone(),
            // Spec strings are `"AllPassed"` / `"AtLeastOneRejected"`
            // / `"NoSuccessors"` (audit-paired-writes.md §2). The
            // wire boolean is `true` iff every reviewer approved.
            all_passed: verdict == "AllPassed",
        }),

        AuditEventKind::EscalationSubmitted {
            escalation_id,
            task_id: t,
            class,
            ..
        } => Some(InitiativeEvent::EscalationRaised {
            escalation_id: escalation_id.clone(),
            task_id: Some(t.clone()),
            capability: class.clone(),
        }),

        AuditEventKind::EscalationApproved { escalation_id, .. } => {
            Some(InitiativeEvent::EscalationResolved {
                escalation_id: escalation_id.clone(),
                outcome: "Approved".into(),
            })
        }
        AuditEventKind::EscalationDenied { escalation_id, .. } => {
            Some(InitiativeEvent::EscalationResolved {
                escalation_id: escalation_id.clone(),
                outcome: "Denied".into(),
            })
        }
        AuditEventKind::EscalationTimedOut { escalation_id, .. } => {
            Some(InitiativeEvent::EscalationResolved {
                escalation_id: escalation_id.clone(),
                outcome: "Expired".into(),
            })
        }

        // The audit variant `IntegrationMergeCompleted` only fires
        // on success (a discarded merge attempt is recorded under
        // `IntegrationMergeAttemptDiscarded`); the wire frame
        // therefore stamps `outcome = "Succeeded"` unconditionally
        // and surfaces the resulting commit SHA as `head_sha`.
        AuditEventKind::IntegrationMergeCompleted { commit_sha, .. } => {
            Some(InitiativeEvent::IntegrationMergeCompleted {
                task_id: task_id.map(str::to_owned).unwrap_or_default(),
                outcome: "Succeeded".into(),
                head_sha: Some(commit_sha.clone()),
            })
        }

        AuditEventKind::StructuredOutputEmitted {
            task_id: t,
            output_kind,
            severity,
            ..
        } => Some(InitiativeEvent::StructuredOutputEmitted {
            task_id: t.clone(),
            output_kind: output_kind.clone(),
            severity: severity.clone(),
        }),

        // Everything else is internal-only.
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// BroadcastingAuditSink — wraps a real AuditSink and tees to the bus.
// ---------------------------------------------------------------------------

/// `AuditSink` decorator that mirrors operator-visible events to
/// the in-process [`InitiativeEventBus`].
///
/// The wire contract is: **broadcast happens AFTER the inner
/// sink's `emit` returns Ok**. A failed audit emit MUST NOT
/// leak onto the operator stream — operators trust the audit
/// chain to be the source of truth, so an event the chain never
/// recorded would mislead them. Mirrors the kernel's
/// `audit-paired-writes.md §2` "audit-then-broadcast" rule.
///
/// A failed downstream emit is not fatal; we propagate the inner
/// sink's `Result` unchanged so paired-write callers see exactly
/// the same error they would have without the wrapper.
pub struct BroadcastingAuditSink {
    inner: Arc<dyn AuditSink>,
    bus: Arc<InitiativeEventBus>,
}

impl BroadcastingAuditSink {
    pub fn new(inner: Arc<dyn AuditSink>, bus: Arc<InitiativeEventBus>) -> Arc<Self> {
        Arc::new(Self { inner, bus })
    }
}

impl AuditSink for BroadcastingAuditSink {
    fn emit(
        &self,
        kind: AuditEventKind,
        session_id: Option<&str>,
        task_id: Option<&str>,
        initiative_id: Option<&str>,
    ) -> Result<AuditEvent, AuditWriterError> {
        // 1. Durable write first. If this fails the broadcast
        //    MUST NOT happen.
        let result = self
            .inner
            .emit(kind.clone(), session_id, task_id, initiative_id);

        // 2. On success, translate + broadcast for any
        //    initiative-attributed audit row. We pull the
        //    canonical `emitted_at` off the returned `AuditEvent`
        //    so the wire timestamp matches the durable record
        //    bit-for-bit.
        if let Ok(event) = result.as_ref() {
            if let Some(iid) = initiative_id {
                if let Some(wire) = audit_kind_to_initiative_event(&kind, task_id, event.emitted_at)
                {
                    self.bus.publish(iid, wire);
                }
            }
        }

        result
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use raxis_audit_tools::AuditEvent;
    use raxis_types::ClosedReason;
    use std::sync::Mutex as StdMutex;
    use uuid::Uuid;

    /// Stub audit sink that succeeds and records every emit so
    /// we can assert the AFTER-emit broadcast ordering.
    #[derive(Default)]
    struct OkSink {
        emitted: StdMutex<Vec<AuditEventKind>>,
    }
    impl AuditSink for OkSink {
        fn emit(
            &self,
            kind: AuditEventKind,
            _s: Option<&str>,
            _t: Option<&str>,
            _i: Option<&str>,
        ) -> Result<AuditEvent, AuditWriterError> {
            self.emitted.lock().unwrap().push(kind.clone());
            Ok(AuditEvent {
                seq: 0,
                event_id: Uuid::nil(),
                event_kind: "test".into(),
                payload: serde_json::Value::Null,
                emitted_at: 0,
                prev_sha256: "0".repeat(64),
                session_id: None,
                task_id: None,
                initiative_id: None,
            })
        }
    }

    /// Audit sink whose `emit` always fails. Drives the
    /// "do-not-broadcast-on-error" property test. Uses the
    /// `Io` variant because it is the same arm `FileAuditSink`
    /// returns when the underlying writer reports an OS error,
    /// keeping the test close to a real failure mode.
    struct FailSink;
    impl AuditSink for FailSink {
        fn emit(
            &self,
            _k: AuditEventKind,
            _s: Option<&str>,
            _t: Option<&str>,
            _i: Option<&str>,
        ) -> Result<AuditEvent, AuditWriterError> {
            Err(AuditWriterError::Io(std::io::Error::new(
                std::io::ErrorKind::Other,
                "stub failure",
            )))
        }
    }

    fn task_state_changed_kind() -> AuditEventKind {
        AuditEventKind::TaskStateChanged {
            task_id: "t-1".into(),
            from_state: "Admitted".into(),
            to_state: "Running".into(),
            actor: "kernel".into(),
            policy_epoch: 1,
        }
    }

    #[tokio::test]
    async fn publish_fans_out_to_every_subscriber() {
        let bus = InitiativeEventBus::new();
        let mut a = bus.subscribe("i-1");
        let mut b = bus.subscribe("i-1");
        assert_eq!(bus.subscriber_count("i-1"), 2);

        let event = InitiativeEvent::Subscribed {
            initiative_id: "i-1".into(),
        };
        bus.publish("i-1", event.clone());

        assert_eq!(a.recv().await.unwrap(), event);
        assert_eq!(b.recv().await.unwrap(), event);
    }

    #[tokio::test]
    async fn publish_to_unknown_initiative_is_a_noop_for_other_channels() {
        let bus = InitiativeEventBus::new();
        let mut a = bus.subscribe("i-1");
        bus.publish(
            "i-2",
            InitiativeEvent::Closed {
                reason: ClosedReason::InitiativeTerminal,
            },
        );
        // i-1's subscriber must NOT receive the i-2 event. Use a
        // small timeout to differentiate "no message" from
        // "blocked".
        let timed = tokio::time::timeout(std::time::Duration::from_millis(50), a.recv()).await;
        assert!(timed.is_err(), "isolated initiatives must not bleed events");
    }

    #[tokio::test]
    async fn broadcasting_sink_emits_then_publishes_on_success() {
        let inner = Arc::new(OkSink::default());
        let bus = InitiativeEventBus::new();
        let sink = BroadcastingAuditSink::new(inner.clone(), bus.clone());

        let mut rx = bus.subscribe("i-1");
        sink.emit(task_state_changed_kind(), None, Some("t-1"), Some("i-1"))
            .expect("inner sink succeeds");

        // Inner sink saw exactly one emit.
        assert_eq!(inner.emitted.lock().unwrap().len(), 1);

        // Subscriber received the public-wire mapped event.
        match rx.recv().await.unwrap() {
            InitiativeEvent::TaskStateChanged {
                task_id,
                to_state,
                from_state,
                ..
            } => {
                assert_eq!(task_id, "t-1");
                assert_eq!(to_state, "Running");
                assert_eq!(from_state.as_deref(), Some("Admitted"));
            }
            other => panic!("expected TaskStateChanged, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn broadcasting_sink_does_not_publish_when_inner_emit_fails() {
        let inner = Arc::new(FailSink);
        let bus = InitiativeEventBus::new();
        let sink = BroadcastingAuditSink::new(inner, bus.clone());

        let mut rx = bus.subscribe("i-1");

        // Inner emit fails — the bus MUST stay silent so an
        // operator never sees an event the audit chain doesn't
        // record.
        let res = sink.emit(task_state_changed_kind(), None, Some("t-1"), Some("i-1"));
        assert!(res.is_err());

        let timed = tokio::time::timeout(std::time::Duration::from_millis(50), rx.recv()).await;
        assert!(
            timed.is_err(),
            "broadcast on failed audit emit would mislead operators"
        );
    }

    #[tokio::test]
    async fn audit_kinds_without_initiative_id_are_not_broadcast() {
        let inner = Arc::new(OkSink::default());
        let bus = InitiativeEventBus::new();
        let sink = BroadcastingAuditSink::new(inner.clone(), bus.clone());

        let mut rx = bus.subscribe("i-1");
        // initiative_id = None → no fan-out should reach any
        // initiative channel even though the audit kind itself
        // would otherwise map to a wire event.
        sink.emit(task_state_changed_kind(), None, Some("t-1"), None)
            .expect("inner sink succeeds");

        let timed = tokio::time::timeout(std::time::Duration::from_millis(50), rx.recv()).await;
        assert!(
            timed.is_err(),
            "audit emits without initiative_id must not land on any bus channel"
        );
    }
}

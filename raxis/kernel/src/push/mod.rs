//! Kernel-side `KernelPush` dispatcher (V2.3 MVP).
//!
//! Background
//! ──────────
//! `kernel-push-protocol.md §9` defines five outbound push variants
//! (`SubTaskActivated`, `SubTaskCompleted`, `AllReviewersPassed`,
//! `ReviewRejected`, `SubTaskSecurityViolation`) that the kernel
//! delivers over each session's VSock connection. The wire types
//! are defined in `raxis_types::push`; until V2.3, **no kernel call
//! site ever invoked them**. The transport layer (per-session push
//! queue + delivery loop + ACK protocol from §9 of the spec) is
//! V3 work.
//!
//! V2.3 MVP scope
//! ──────────────
//! This module ships the in-process publishing API + audit-trail
//! mirroring so the rest of the kernel can already publish pushes
//! at the spec-correct call sites. Concretely:
//!
//!  * **In-memory broadcast.** Each `enqueue` allocates a per-
//!    session monotonic `push_id` and fans the resulting
//!    `KernelPushFrame` out to all `Subscriber`s currently bound to
//!    that `session_id`. Subscribers are typically the future V3
//!    VSock delivery loop (which will be added without changing
//!    the publish API), but unit tests can subscribe directly.
//!  * **Audit mirror.** Every `enqueue` emits an
//!    `AuditEventKind::KernelPushEnqueued` event so the push trail
//!    is **durably observable** even when no live subscriber is
//!    attached. This is the V2.3 substitute for the V3
//!    `pending_pushes` SQL queue: at-most-once delivery is the
//!    audit chain.
//!  * **No persistence.** The dispatcher does not back the queue
//!    with SQLite; pushes that fire while no subscriber is bound
//!    are lost from in-memory delivery. Audit-mirrored events still
//!    record them. This is acceptable for V2.3 because every
//!    `KernelPush` variant is **also** observable via existing
//!    audit events (`SubTaskActivated → TaskStateChanged`,
//!    `AllReviewersPassed → ReviewAggregationCompleted`, etc.),
//!    so the audit trail stays the source of truth.
//!  * **Crash semantics.** A kernel crash drops the in-memory
//!    queue. V3 will re-derive the recovery set from
//!    `subtask_activations` + `pending_reviewers` at boot and
//!    populate `pending_pushes`. V2.3 simply re-emits the
//!    audit event — operators replay from the audit chain.
//!
//! Dispatch invariants
//! ───────────────────
//!  * **`push_id` is per-session monotonic.** Even across
//!    subscriber attach/detach the counter never resets while
//!    the kernel is running. This matches `kernel-push-protocol.md
//!    §9` line 539. (V3 persistence will hand a fresh counter on
//!    crash recovery.)
//!  * **Audit mirror happens before broadcast.** If audit emit
//!    fails the dispatcher still attempts the broadcast (audit
//!    failures are not fatal for delivery), but the audit chain
//!    is the durable record so we order it first.
//!  * **Subscriber drop is non-fatal.** A `Subscriber` that goes
//!    away mid-broadcast simply drops the message; the dispatcher
//!    does not back-pressure publishers.

pub mod initiative_bus;

// Re-export the surface the rest of the kernel uses. The two
// items pulled in here are read by `ipc::context` (wraps the audit
// sink + stores the bus). The `audit_kind_to_initiative_event`
// helper and the broadcast capacity constant are public from the
// submodule so tests / future callers can depend on them
// directly without going through the re-export.
pub use initiative_bus::{BroadcastingAuditSink, InitiativeEventBus};

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use raxis_audit_tools::{AuditEventKind, AuditSink};
use raxis_types::push::{KernelPush, KernelPushFrame};
use raxis_types::{InitiativeId, SessionId, TaskId};
use tokio::sync::broadcast;

/// Default capacity for the per-session broadcast channel. Each
/// slot holds one `KernelPushFrame`. The number is sized so a
/// burst of admit/complete activity at the spec's sub-task DAG
/// width (`v2-deep-spec.md §Step 21` — typically <16 concurrent
/// sub-tasks) is comfortably absorbed without back-pressuring
/// publishers, with headroom for review aggregation chatter.
pub const PER_SESSION_BROADCAST_CAPACITY: usize = 256;

/// Lightweight subscriber handle returned by [`KernelPushDispatcher::subscribe`].
/// V3 subscribers (the per-session VSock delivery loop) wrap a
/// `broadcast::Receiver<KernelPushFrame>` and forward each frame
/// to the wire. V2.3 unit tests use the same receiver directly.
pub type Subscriber = broadcast::Receiver<KernelPushFrame>;

/// Per-session bookkeeping: a `broadcast::Sender` that fans pushes
/// out to all currently-subscribed receivers, plus a monotonic
/// `push_id` allocator.
struct PerSession {
    sender: broadcast::Sender<KernelPushFrame>,
    next_id: AtomicU64,
}

/// Process-wide kernel-push registry. One instance lives in
/// `HandlerContext::push_dispatcher` so every IPC handler can
/// publish without re-injecting the registry.
pub struct KernelPushDispatcher {
    audit: Arc<dyn AuditSink>,
    sessions: std::sync::Mutex<HashMap<SessionId, Arc<PerSession>>>,
}

impl KernelPushDispatcher {
    /// Construct a fresh dispatcher. The audit sink is shared with
    /// the rest of the kernel so the `KernelPushEnqueued` event
    /// lands on the same chain as every other audit row.
    pub fn new(audit: Arc<dyn AuditSink>) -> Arc<Self> {
        Arc::new(Self {
            audit,
            sessions: std::sync::Mutex::new(HashMap::new()),
        })
    }

    /// Register a subscriber for `session_id`. The returned
    /// `Subscriber` resolves with the next published frame; older
    /// frames may have been dropped per the broadcast semantics.
    /// V3 callers (per-session delivery loop) will call this on
    /// VSock-accept; V2 unit tests use it directly.
    pub fn subscribe(&self, session_id: SessionId) -> Subscriber {
        self.session(session_id).sender.subscribe()
    }

    /// Number of currently-attached subscribers for `session_id`.
    /// Used by tests and by the audit log to surface "no live
    /// recipient" situations.
    pub fn subscriber_count(&self, session_id: SessionId) -> usize {
        self.sessions
            .lock()
            .unwrap()
            .get(&session_id)
            .map(|s| s.sender.receiver_count())
            .unwrap_or(0)
    }

    /// Publish `push` for delivery to `session_id`. Returns the
    /// fully-stamped `KernelPushFrame` (with the allocated
    /// `push_id` + `enqueued_at` set). The frame is mirrored to
    /// the audit chain unconditionally; in-memory broadcast
    /// happens after the audit emit so the trail is the canonical
    /// record. `now_unix` is parameterised so tests can pin
    /// timestamps.
    pub fn enqueue(
        &self,
        session_id: SessionId,
        push: KernelPush,
        now_unix: i64,
    ) -> KernelPushFrame {
        self.enqueue_with_context(session_id, push, now_unix, None)
    }

    /// Variant of [`enqueue`](Self::enqueue) carrying an optional
    /// initiative_id for audit attribution. V2 sub-task lifecycle
    /// pushes already know the initiative the task belongs to;
    /// passing it through gives the audit chain a grep-friendly
    /// `initiative_id` column without re-querying the DB.
    pub fn enqueue_with_context(
        &self,
        session_id: SessionId,
        push: KernelPush,
        now_unix: i64,
        initiative_id: Option<InitiativeId>,
    ) -> KernelPushFrame {
        let session = self.session(session_id.clone());
        let push_id = session.next_id.fetch_add(1, Ordering::SeqCst);
        let frame = KernelPushFrame {
            push_id,
            session_id: session_id.clone(),
            enqueued_at: now_unix,
            push: push.clone(),
        };

        let push_kind = push_kind_str(&push);
        let task_id_obj = push_task_id(&push).cloned();
        let task_id_str = task_id_obj.as_ref().map(|t| t.to_string());
        let init_str = initiative_id.as_ref().map(|i| i.to_string());
        let session_str = session_id.to_string();
        if let Err(e) = self.audit.emit(
            AuditEventKind::KernelPushEnqueued {
                session_id: session_str.clone(),
                push_id,
                push_kind: push_kind.to_string(),
                initiative_id: init_str.clone(),
                task_id: task_id_str.clone(),
            },
            Some(&session_str),
            task_id_str.as_deref(),
            init_str.as_deref(),
        ) {
            eprintln!(
                "{{\"level\":\"warn\",\"event\":\"kernel_push_audit_emit_failed\",\
                 \"session_id\":\"{session_str}\",\"push_kind\":\"{push_kind}\",\
                 \"reason\":\"{e}\"}}"
            );
        }

        // Best-effort fan-out. `send` returns `Err` only when the
        // channel has zero subscribers — which is the V2.3 "audit
        // is the canonical record" path; we ignore the error.
        let _ = session.sender.send(frame.clone());

        frame
    }

    fn session(&self, session_id: SessionId) -> Arc<PerSession> {
        let mut guard = self.sessions.lock().unwrap();
        guard
            .entry(session_id)
            .or_insert_with(|| {
                let (sender, _initial_rx) = broadcast::channel(PER_SESSION_BROADCAST_CAPACITY);
                Arc::new(PerSession {
                    sender,
                    next_id: AtomicU64::new(1),
                })
            })
            .clone()
    }
}

fn push_kind_str(push: &KernelPush) -> &'static str {
    match push {
        KernelPush::SubTaskActivated { .. } => "SubTaskActivated",
        KernelPush::SubTaskCompleted { .. } => "SubTaskCompleted",
        KernelPush::AllReviewersPassed { .. } => "AllReviewersPassed",
        KernelPush::ReviewRejected { .. } => "ReviewRejected",
        KernelPush::SubTaskSecurityViolation { .. } => "SubTaskSecurityViolation",
        KernelPush::GateRejected { .. } => "GateRejected",
    }
}

fn push_task_id(push: &KernelPush) -> Option<&TaskId> {
    match push {
        KernelPush::SubTaskActivated { task_id, .. } => Some(task_id),
        KernelPush::SubTaskCompleted { task_id, .. } => Some(task_id),
        KernelPush::AllReviewersPassed { task_id } => Some(task_id),
        KernelPush::ReviewRejected { task_id, .. } => Some(task_id),
        KernelPush::SubTaskSecurityViolation { task_id } => Some(task_id),
        // iter65 — `GateRejected` is the kernel→orchestrator anchor
        // for a witness-gate rejection. `parent_task_id` is the task
        // whose gate failed (the orchestrator routes the fixup
        // subtask off this id).
        KernelPush::GateRejected { parent_task_id, .. } => Some(parent_task_id),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use raxis_audit_tools::{AuditEvent, AuditWriterError};
    use std::sync::Mutex as StdMutex;
    use uuid::Uuid;

    /// Capturing audit sink for tests — records every emit kind so
    /// we can assert audit-mirror semantics. We cannot use the
    /// production `AuditEvent` directly because its fields are
    /// `pub` but the type does not implement `Default`; we keep a
    /// vector of `(kind, session_id, task_id, initiative_id)`
    /// tuples instead, which is all the dispatcher tests need.
    #[derive(Default)]
    struct CapturingSink {
        events: StdMutex<Vec<CapturedEvent>>,
    }

    struct CapturedEvent {
        kind: AuditEventKind,
        session_id: Option<String>,
        task_id: Option<String>,
        initiative_id: Option<String>,
    }

    impl AuditSink for CapturingSink {
        fn emit(
            &self,
            kind: AuditEventKind,
            session_id: Option<&str>,
            task_id: Option<&str>,
            initiative_id: Option<&str>,
        ) -> Result<AuditEvent, AuditWriterError> {
            let id = self.events.lock().unwrap().len() as u64;
            self.events.lock().unwrap().push(CapturedEvent {
                kind: kind.clone(),
                session_id: session_id.map(str::to_owned),
                task_id: task_id.map(str::to_owned),
                initiative_id: initiative_id.map(str::to_owned),
            });
            // The dispatcher only consumes the `Result` arm; the
            // returned `AuditEvent` is never read, so we hand back a
            // placeholder constructed via the public field set.
            Ok(AuditEvent {
                seq: id,
                event_id: Uuid::nil(),
                event_kind: "test".into(),
                payload: serde_json::Value::Null,
                emitted_at: 0,
                prev_sha256: "0".repeat(64),
                session_id: session_id.map(str::to_owned),
                task_id: task_id.map(str::to_owned),
                initiative_id: initiative_id.map(str::to_owned),
            })
        }
    }

    fn session_id() -> SessionId {
        SessionId::parse(&Uuid::from_bytes([7; 16]).hyphenated().to_string()).unwrap()
    }

    fn task_id(s: &str) -> TaskId {
        TaskId::parse(s).unwrap()
    }

    #[tokio::test]
    async fn enqueue_allocates_monotonic_push_ids_per_session() {
        let sink = Arc::new(CapturingSink::default());
        let dispatcher = KernelPushDispatcher::new(sink.clone());

        let s = session_id();
        let f1 = dispatcher.enqueue(
            s.clone(),
            KernelPush::SubTaskActivated {
                task_id: task_id("01956c1c-fbcd-7000-8000-000000000001"),
                base_sha: "abc".into(),
            },
            1_700_000_000,
        );
        let f2 = dispatcher.enqueue(
            s.clone(),
            KernelPush::AllReviewersPassed {
                task_id: task_id("01956c1c-fbcd-7000-8000-000000000001"),
            },
            1_700_000_001,
        );

        assert_eq!(f1.push_id, 1);
        assert_eq!(f2.push_id, 2);
        assert_eq!(f1.session_id, s);
    }

    #[tokio::test]
    async fn enqueue_mirrors_to_audit_chain() {
        let sink = Arc::new(CapturingSink::default());
        let dispatcher = KernelPushDispatcher::new(sink.clone());

        dispatcher.enqueue(
            session_id(),
            KernelPush::SubTaskCompleted {
                task_id: task_id("01956c1c-fbcd-7000-8000-000000000002"),
                completed_sha: "def".into(),
                newly_activatable: vec![],
            },
            1_700_000_002,
        );

        let events = sink.events.lock().unwrap();
        assert_eq!(events.len(), 1);
        match &events[0].kind {
            AuditEventKind::KernelPushEnqueued {
                push_id,
                push_kind,
                task_id,
                ..
            } => {
                assert_eq!(*push_id, 1u64);
                assert_eq!(push_kind, "SubTaskCompleted");
                assert_eq!(
                    task_id.as_deref(),
                    Some("01956c1c-fbcd-7000-8000-000000000002"),
                );
            }
            other => panic!("wrong audit kind: {other:?}"),
        }
    }

    #[tokio::test]
    async fn enqueue_broadcasts_to_live_subscribers() {
        let sink = Arc::new(CapturingSink::default());
        let dispatcher = KernelPushDispatcher::new(sink.clone());

        let s = session_id();
        let mut sub = dispatcher.subscribe(s.clone());
        let _frame = dispatcher.enqueue(
            s.clone(),
            KernelPush::SubTaskSecurityViolation {
                task_id: task_id("01956c1c-fbcd-7000-8000-000000000003"),
            },
            1_700_000_003,
        );

        let received = sub.recv().await.expect("subscriber should receive frame");
        assert_eq!(received.session_id, s);
        match received.push {
            KernelPush::SubTaskSecurityViolation { .. } => {}
            other => panic!("wrong push variant: {other:?}"),
        }
    }

    #[tokio::test]
    async fn enqueue_succeeds_when_no_subscribers() {
        let sink = Arc::new(CapturingSink::default());
        let dispatcher = KernelPushDispatcher::new(sink.clone());

        // Audit mirror is the canonical record when no subscriber is bound.
        let frame = dispatcher.enqueue(
            session_id(),
            KernelPush::ReviewRejected {
                task_id: task_id("01956c1c-fbcd-7000-8000-000000000004"),
                critique: "bad".into(),
                reviewer_session_id: session_id(),
            },
            1_700_000_004,
        );
        assert_eq!(frame.push_id, 1);
        assert_eq!(sink.events.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn subscriber_count_reflects_attached_receivers() {
        let sink = Arc::new(CapturingSink::default());
        let dispatcher = KernelPushDispatcher::new(sink.clone());

        let s = session_id();
        assert_eq!(dispatcher.subscriber_count(s.clone()), 0);

        let _r1 = dispatcher.subscribe(s.clone());
        let _r2 = dispatcher.subscribe(s.clone());
        assert_eq!(dispatcher.subscriber_count(s.clone()), 2);

        drop(_r2);
        assert_eq!(dispatcher.subscriber_count(s), 1);
    }
}

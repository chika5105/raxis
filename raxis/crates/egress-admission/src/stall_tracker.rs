//! V2 reviewer-egress-defaults-decision.md §7 — sliding-window
//! egress-stall detector.
//!
//! Detects the silent failure mode where an agent's VM repeatedly
//! retries an outbound connection that the egress chokepoint
//! denies — historically the dominant operator-visible symptom of
//! "I configured `[[providers]] anthropic-prod` but forgot
//! `[egress] domains = [\"api.anthropic.com\"]`". With Option C
//! defaults landed (`PolicyBundle::effective_egress_domains`) the
//! configuration root cause is largely eliminated, but stall
//! detection is the orthogonal safety net for any future stall —
//! a transient policy reload, a scoped `deny_provider` opt-out
//! the operator forgot, a cred-proxy that tipped down mid-session.
//!
//! # Contract
//!
//! - One tracker is created per kernel boot and shared across
//!   every admission loop and the kernel-mediated planner_fetch
//!   handler.
//! - Each chokepoint calls [`EgressStallTracker::record_denial`]
//!   on every denial it observes. The tracker buckets denials by
//!   the `(session_id, host_or_sni, port, reason)` tuple and
//!   tracks per-bucket timestamps in a sliding window.
//! - When the bucket's denial count inside the window exceeds the
//!   configured threshold AND we haven't already emitted a stall
//!   event for this bucket inside the current window, the tracker
//!   returns a [`StallSignal::Detected`] carrying the values the
//!   caller plumbs into [`AuditEventKind::SessionEgressStallDetected`].
//! - Subsequent denials inside the same window return
//!   [`StallSignal::Quiet`] (debounced). Once the window slides
//!   past the last emit, the tracker re-arms.
//!
//! # Time source
//!
//! Pluggable via the [`Clock`] trait so tests can drive the
//! tracker with a synthetic clock without `tokio::time::pause()`
//! (which leaks into the real-tokio test crate's reactor and is
//! awkward to combine with audit-sink mock state).
//!
//! # Concurrency
//!
//! Internally a `std::sync::Mutex<HashMap<…>>`. Critical sections
//! are O(window-entries) and the realistic hot-path window is
//! ≤ ~10 entries (3-deny threshold × small headroom), so a single
//! `Mutex` is the right shape — no need for `DashMap` or sharding.

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Default sliding-window length: 30 seconds. Pinned by
/// `specs/v2/reviewer-egress-defaults-decision.md §7 Defaults`.
pub const DEFAULT_WINDOW: Duration = Duration::from_secs(30);

/// Default denial-count threshold: 3 denials within the window
/// trigger one stall event. Pinned by the same spec §.
pub const DEFAULT_THRESHOLD: u32 = 3;

/// The tracker's stall-event payload. Returned by
/// [`EgressStallTracker::record_denial`] when a bucket trips the
/// threshold; the caller plumbs every field into
/// `AuditEventKind::SessionEgressStallDetected`. Carries
/// `source` rather than embedding it inside the tracker because
/// the same tracker fires from multiple chokepoints (Tier-1
/// transparent-proxy admission loop AND kernel-mediated
/// planner_fetch handler).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StallEmission {
    /// Session whose VM is stalling.
    pub session_id:            String,
    /// Host or SNI as reported by the chokepoint. `None` for
    /// raw-TCP destinations where the in-VM proxy could not
    /// extract an SNI.
    pub host_or_sni:           Option<String>,
    /// Original destination port the chokepoint observed.
    pub original_dst_port:     u16,
    /// Stable short reason string carried from the underlying
    /// denial event (`host_not_in_allowlist`, etc.).
    pub reason:                String,
    /// Number of denials inside the window that triggered this
    /// detection.
    pub block_count_in_window: u32,
    /// Window length in whole seconds. Mirrors the configured
    /// `Duration` rounded down — operator dashboards compare
    /// against integer seconds so the audit field stays an
    /// integer.
    pub window_seconds:        u32,
}

/// Outcome of [`EgressStallTracker::record_denial`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StallSignal {
    /// Threshold not crossed (yet) OR threshold already triggered
    /// inside the current window and the caller emitted an event
    /// — debounce until the window slides past.
    Quiet,
    /// Threshold crossed. Caller MUST emit one
    /// `AuditEventKind::SessionEgressStallDetected` with the
    /// payload, supplying the chokepoint-specific `source` tag.
    Detected(StallEmission),
}

/// Pluggable monotonic clock so tests can drive the sliding
/// window without depending on `tokio::time::pause()`.
pub trait Clock: Send + Sync + 'static {
    /// Current monotonic instant.
    fn now(&self) -> Instant;
}

/// Production clock backed by `Instant::now`.
#[derive(Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
}

#[derive(Debug, Hash, PartialEq, Eq, Clone)]
struct StallKey {
    session_id:        String,
    host_or_sni:       Option<String>,
    original_dst_port: u16,
    reason:            String,
}

#[derive(Debug)]
struct Bucket {
    /// Denial timestamps inside the window, oldest first. Pruned
    /// on every `record_denial` call.
    denials: VecDeque<Instant>,
    /// `Some(t)` when we already emitted a stall event at `t`.
    /// Cleared once `t` falls outside the window so the bucket
    /// can re-arm.
    last_emit_at: Option<Instant>,
}

/// Sliding-window egress-stall tracker.
///
/// See module docs for the contract.
pub struct EgressStallTracker {
    window:    Duration,
    threshold: u32,
    clock:     Box<dyn Clock>,
    state:     Mutex<HashMap<StallKey, Bucket>>,
}

impl std::fmt::Debug for EgressStallTracker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EgressStallTracker")
            .field("window", &self.window)
            .field("threshold", &self.threshold)
            .finish()
    }
}

impl EgressStallTracker {
    /// Tracker with the spec defaults
    /// ([`DEFAULT_THRESHOLD`] denials inside [`DEFAULT_WINDOW`])
    /// and a [`SystemClock`].
    pub fn with_defaults() -> Self {
        Self::new(DEFAULT_WINDOW, DEFAULT_THRESHOLD, Box::new(SystemClock))
    }

    /// Construct a tracker with arbitrary thresholds and clock.
    /// Tests should pass a synthetic clock to drive the window
    /// deterministically.
    pub fn new(window: Duration, threshold: u32, clock: Box<dyn Clock>) -> Self {
        // Clamp the threshold to >= 1 so `record_denial` doesn't
        // emit on the very first denial (and hence never debounce).
        let threshold = threshold.max(1);
        Self {
            window,
            threshold,
            clock,
            state: Mutex::new(HashMap::new()),
        }
    }

    /// Record one denial against the bucket identified by
    /// `(session_id, host_or_sni, port, reason)`. Returns
    /// [`StallSignal::Detected`] exactly once per
    /// (bucket, sliding window) when the threshold is crossed.
    pub fn record_denial(
        &self,
        session_id:        &str,
        host_or_sni:       Option<&str>,
        original_dst_port: u16,
        reason:            &str,
    ) -> StallSignal {
        let now = self.clock.now();
        let key = StallKey {
            session_id:        session_id.to_owned(),
            host_or_sni:       host_or_sni.map(str::to_owned),
            original_dst_port,
            reason:            reason.to_owned(),
        };
        let mut state = self.state.lock().expect("EgressStallTracker mutex poisoned");
        let bucket = state.entry(key.clone()).or_insert_with(|| Bucket {
            denials:      VecDeque::new(),
            last_emit_at: None,
        });
        // Prune denials that fell out of the window.
        while let Some(&front) = bucket.denials.front() {
            if now.duration_since(front) > self.window {
                bucket.denials.pop_front();
            } else {
                break;
            }
        }
        // Re-arm: if the previous emit slid out of the window,
        // clear the marker so a new burst can trigger again.
        if let Some(emitted_at) = bucket.last_emit_at {
            if now.duration_since(emitted_at) > self.window {
                bucket.last_emit_at = None;
            }
        }
        bucket.denials.push_back(now);
        let count = bucket.denials.len() as u32;
        if count < self.threshold {
            return StallSignal::Quiet;
        }
        if bucket.last_emit_at.is_some() {
            // Already triggered for this window — debounce.
            return StallSignal::Quiet;
        }
        bucket.last_emit_at = Some(now);
        let window_seconds = self.window.as_secs() as u32;
        StallSignal::Detected(StallEmission {
            session_id:            key.session_id,
            host_or_sni:           key.host_or_sni,
            original_dst_port:     key.original_dst_port,
            reason:                key.reason,
            block_count_in_window: count,
            window_seconds,
        })
    }

    /// Forget every bucket for `session_id`. Called by the kernel
    /// when a session terminates so a long-lived tracker doesn't
    /// hold stale per-session state forever.
    pub fn forget_session(&self, session_id: &str) {
        let mut state = self.state.lock().expect("EgressStallTracker mutex poisoned");
        state.retain(|k, _| k.session_id != session_id);
    }

    /// Test-only: number of live buckets. Lets tests pin the
    /// `forget_session` cleanup contract.
    #[doc(hidden)]
    pub fn bucket_count(&self) -> usize {
        let state = self.state.lock().expect("EgressStallTracker mutex poisoned");
        state.len()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex as StdMutex;

    /// Manually-driven clock — `set` advances it to the requested
    /// instant. Cheaper to reason about than `tokio::time::pause()`
    /// for a sync tracker.
    #[derive(Debug)]
    struct FakeClock {
        now: StdMutex<Instant>,
    }

    impl FakeClock {
        fn new() -> Self {
            Self { now: StdMutex::new(Instant::now()) }
        }
        fn advance(&self, delta: Duration) {
            let mut guard = self.now.lock().unwrap();
            *guard += delta;
        }
    }

    impl Clock for FakeClock {
        fn now(&self) -> Instant {
            *self.now.lock().unwrap()
        }
    }

    fn tracker(window: Duration, threshold: u32) -> (std::sync::Arc<FakeClock>, EgressStallTracker) {
        let clock = std::sync::Arc::new(FakeClock::new());
        let tracker = EgressStallTracker::new(
            window,
            threshold,
            Box::new(FakeClockHandle { inner: std::sync::Arc::clone(&clock) }),
        );
        (clock, tracker)
    }

    /// Newtype so we can implement `Clock` for the `Arc<FakeClock>`
    /// without orphan-rule trouble.
    #[derive(Debug)]
    struct FakeClockHandle {
        inner: std::sync::Arc<FakeClock>,
    }
    impl Clock for FakeClockHandle {
        fn now(&self) -> Instant { self.inner.now() }
    }

    #[test]
    fn first_two_denials_below_threshold_stay_quiet() {
        let (_clock, t) = tracker(Duration::from_secs(30), 3);
        for _ in 0..2 {
            assert_eq!(
                t.record_denial("sess-1", Some("api.anthropic.com"), 443, "host_not_in_allowlist"),
                StallSignal::Quiet,
            );
        }
    }

    #[test]
    fn third_denial_inside_window_emits_stall_signal() {
        let (_clock, t) = tracker(Duration::from_secs(30), 3);
        t.record_denial("s", Some("api.anthropic.com"), 443, "host_not_in_allowlist");
        t.record_denial("s", Some("api.anthropic.com"), 443, "host_not_in_allowlist");
        let signal = t.record_denial("s", Some("api.anthropic.com"), 443, "host_not_in_allowlist");
        match signal {
            StallSignal::Detected(emit) => {
                assert_eq!(emit.session_id,            "s");
                assert_eq!(emit.host_or_sni.as_deref(), Some("api.anthropic.com"));
                assert_eq!(emit.original_dst_port,     443);
                assert_eq!(emit.reason,                "host_not_in_allowlist");
                assert_eq!(emit.block_count_in_window, 3);
                assert_eq!(emit.window_seconds,        30);
            }
            other => panic!("expected Detected, got {:?}", other),
        }
    }

    #[test]
    fn fourth_and_fifth_denials_inside_window_are_debounced() {
        let (_clock, t) = tracker(Duration::from_secs(30), 3);
        for _ in 0..3 { t.record_denial("s", Some("api"), 443, "r"); }
        // Threshold already crossed; subsequent denials are quiet
        // until the window slides.
        for _ in 0..2 {
            assert_eq!(t.record_denial("s", Some("api"), 443, "r"), StallSignal::Quiet);
        }
    }

    #[test]
    fn old_denials_drop_off_window_and_threshold_resets() {
        let (clock, t) = tracker(Duration::from_secs(30), 3);
        t.record_denial("s", Some("api"), 443, "r");
        t.record_denial("s", Some("api"), 443, "r");
        // Slide everything out of the window.
        clock.advance(Duration::from_secs(31));
        assert_eq!(t.record_denial("s", Some("api"), 443, "r"), StallSignal::Quiet,
            "single fresh denial below threshold");
    }

    #[test]
    fn re_arms_after_window_slides_past_emit() {
        let (clock, t) = tracker(Duration::from_secs(30), 3);
        for _ in 0..3 { t.record_denial("s", Some("api"), 443, "r"); }
        // Slide past the window.
        clock.advance(Duration::from_secs(31));
        for _ in 0..2 {
            assert_eq!(t.record_denial("s", Some("api"), 443, "r"), StallSignal::Quiet);
        }
        // Third inside the new window re-emits.
        match t.record_denial("s", Some("api"), 443, "r") {
            StallSignal::Detected(_) => {}
            other => panic!("expected Detected on re-arm, got {:?}", other),
        }
    }

    #[test]
    fn distinct_destinations_track_independently() {
        let (_clock, t) = tracker(Duration::from_secs(30), 3);
        for _ in 0..3 { t.record_denial("s", Some("a.example"), 443, "r"); }
        // Different host — independent bucket, below threshold.
        assert_eq!(t.record_denial("s", Some("b.example"), 443, "r"), StallSignal::Quiet);
        assert_eq!(t.record_denial("s", Some("b.example"), 443, "r"), StallSignal::Quiet);
        match t.record_denial("s", Some("b.example"), 443, "r") {
            StallSignal::Detected(emit) => {
                assert_eq!(emit.host_or_sni.as_deref(), Some("b.example"));
            }
            other => panic!("expected Detected, got {:?}", other),
        }
    }

    #[test]
    fn distinct_sessions_track_independently() {
        let (_clock, t) = tracker(Duration::from_secs(30), 3);
        for _ in 0..3 { t.record_denial("s1", Some("api"), 443, "r"); }
        // s2 — fresh bucket, below threshold.
        for _ in 0..2 {
            assert_eq!(t.record_denial("s2", Some("api"), 443, "r"), StallSignal::Quiet);
        }
    }

    #[test]
    fn distinct_reasons_track_independently() {
        // Same dest, different reason → different bucket. (A
        // session that hits both `host_not_in_allowlist` and
        // `proxy_target_bypass` for the same dest is two
        // distinct stalls.)
        let (_clock, t) = tracker(Duration::from_secs(30), 3);
        for _ in 0..3 { t.record_denial("s", Some("api"), 443, "host_not_in_allowlist"); }
        for _ in 0..2 {
            assert_eq!(
                t.record_denial("s", Some("api"), 443, "proxy_target_bypass"),
                StallSignal::Quiet,
            );
        }
    }

    #[test]
    fn host_none_buckets_separately_from_named_host() {
        let (_clock, t) = tracker(Duration::from_secs(30), 3);
        for _ in 0..3 { t.record_denial("s", None, 443, "r"); }
        for _ in 0..2 {
            assert_eq!(t.record_denial("s", Some("api"), 443, "r"), StallSignal::Quiet);
        }
    }

    #[test]
    fn forget_session_clears_buckets() {
        let (_clock, t) = tracker(Duration::from_secs(30), 3);
        t.record_denial("s1", Some("api"), 443, "r");
        t.record_denial("s2", Some("api"), 443, "r");
        assert_eq!(t.bucket_count(), 2);
        t.forget_session("s1");
        assert_eq!(t.bucket_count(), 1);
    }

    #[test]
    fn threshold_one_emits_immediately() {
        let (_clock, t) = tracker(Duration::from_secs(30), 1);
        match t.record_denial("s", Some("api"), 443, "r") {
            StallSignal::Detected(emit) => assert_eq!(emit.block_count_in_window, 1),
            other => panic!("expected Detected, got {:?}", other),
        }
    }

    #[test]
    fn threshold_zero_is_clamped_to_one() {
        let (_clock, t) = tracker(Duration::from_secs(30), 0);
        // Should still take at least one denial to trigger.
        match t.record_denial("s", Some("api"), 443, "r") {
            StallSignal::Detected(_) => {}
            other => panic!("expected Detected on first denial, got {:?}", other),
        }
    }
}

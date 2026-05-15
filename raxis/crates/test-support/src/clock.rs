// FakeClock — deterministic `raxis_types::Clock` impl for tests.
//
// Why a Mutex and not an AtomicI64?
//   - The trait surface is tiny (one read), so contention is a non-issue.
//   - A `Mutex<i64>` keeps the door open for future Clock methods that
//     need atomic read-modify-write of multiple fields (e.g. a `now()`
//     that also returns a sub-second component, or a "tick once and
//     return the previous value" helper) without breaking the API.
//   - `parking_lot` would be marginally faster, but the fake is on the
//     test path only and the std mutex avoids adding a new dep.
//
// Concurrency model:
//   - Construction sets the initial timestamp.
//   - `set_now`, `advance`, and `now_unix_secs` each take the lock
//     for the duration of one i64 read or write — no observable
//     intermediate state.
//   - Implements `Clock + Send + Sync + 'static`, so kernel handlers
//     can hold `Arc<dyn Clock>` containing a `FakeClock` and the test
//     can keep a separate `Arc<FakeClock>` to drive time.

use raxis_types::Clock;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Deterministic, settable `Clock` impl. Cheap to clone (`Arc` inside).
///
/// Construct with [`FakeClock::at`] or [`FakeClock::epoch`]; advance
/// with [`FakeClock::advance`] or [`FakeClock::set_now`].
///
/// ```
/// use raxis_test_support::FakeClock;
/// use raxis_types::Clock;
///
/// let c = FakeClock::at(1_000);
/// assert_eq!(c.now_unix_secs(), 1_000);
/// c.advance_secs(5);
/// assert_eq!(c.now_unix_secs(), 1_005);
/// ```
#[derive(Debug, Clone, Default)]
pub struct FakeClock {
    inner: Arc<Mutex<i64>>,
}

impl FakeClock {
    /// Construct a `FakeClock` pinned to a specific Unix timestamp.
    ///
    /// Pick any value that is "obviously not real wall time" so test
    /// assertions are unambiguous when they fail (e.g. `1_000_000`,
    /// not the current epoch second).
    pub fn at(unix_secs: i64) -> Self {
        Self {
            inner: Arc::new(Mutex::new(unix_secs)),
        }
    }

    /// Construct a `FakeClock` pinned to the Unix epoch (`t = 0`).
    /// Convenient for "no time has passed yet" test setups.
    pub fn epoch() -> Self {
        Self::at(0)
    }

    /// Read the current value without going through the trait.
    /// Equivalent to `<Self as Clock>::now_unix_secs(self)`.
    pub fn now(&self) -> i64 {
        self.lock_or_panic().clone_inner()
    }

    /// Replace the current value. Subsequent reads return `t`.
    pub fn set_now(&self, t: i64) {
        *self.lock_or_panic().0 = t;
    }

    /// Advance time by `delta` whole seconds. May be negative
    /// (for tests that need to simulate clock skew); callers that
    /// intend to model only forward time should use `advance_secs`.
    pub fn advance_signed_secs(&self, delta: i64) {
        let mut g = self.lock_or_panic();
        *g.0 = g.0.saturating_add(delta);
    }

    /// Advance time by `delta` non-negative seconds (saturating add).
    /// Panics if `delta > i64::MAX as u64`, which would require the
    /// test to be modelling more than ~292 billion years.
    pub fn advance_secs(&self, delta: u64) {
        let delta_i: i64 = delta
            .try_into()
            .expect("FakeClock::advance_secs: delta exceeds i64::MAX");
        self.advance_signed_secs(delta_i);
    }

    /// Advance time by a `Duration`. Sub-second precision is dropped
    /// (the underlying clock has whole-second granularity per the
    /// `Clock::now_unix_secs` contract).
    pub fn advance(&self, delta: Duration) {
        self.advance_secs(delta.as_secs());
    }

    /// Internal helper. Centralised so the panic message is consistent
    /// across every entry point.
    fn lock_or_panic(&self) -> InnerGuard<'_> {
        InnerGuard(
            self.inner
                .lock()
                .expect("FakeClock mutex poisoned — a previous test panicked while holding it"),
        )
    }
}

impl Clock for FakeClock {
    fn now_unix_secs(&self) -> i64 {
        self.now()
    }
}

// Wrapper around the MutexGuard so we can expose `clone_inner` ergonomically
// without leaking the std-mutex type into the public API.
struct InnerGuard<'a>(std::sync::MutexGuard<'a, i64>);

impl<'a> InnerGuard<'a> {
    fn clone_inner(&self) -> i64 {
        *self.0
    }
}

// ---------------------------------------------------------------------------
// Tests — pin the deterministic-time contract.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc as StdArc;
    use std::thread;

    #[test]
    fn at_pins_initial_value() {
        let c = FakeClock::at(123);
        assert_eq!(c.now(), 123);
        assert_eq!(c.now_unix_secs(), 123);
    }

    #[test]
    fn epoch_starts_at_zero() {
        let c = FakeClock::epoch();
        assert_eq!(c.now_unix_secs(), 0);
    }

    #[test]
    fn default_starts_at_zero() {
        let c = FakeClock::default();
        assert_eq!(c.now_unix_secs(), 0);
    }

    #[test]
    fn set_now_replaces_value() {
        let c = FakeClock::at(100);
        c.set_now(50);
        assert_eq!(c.now_unix_secs(), 50);
        c.set_now(99_999);
        assert_eq!(c.now_unix_secs(), 99_999);
    }

    #[test]
    fn advance_secs_adds_forward() {
        let c = FakeClock::at(0);
        c.advance_secs(60);
        assert_eq!(c.now_unix_secs(), 60);
        c.advance_secs(3600);
        assert_eq!(c.now_unix_secs(), 3660);
    }

    #[test]
    fn advance_signed_secs_can_go_backward() {
        let c = FakeClock::at(1_000);
        c.advance_signed_secs(-200);
        assert_eq!(c.now_unix_secs(), 800);
    }

    #[test]
    fn advance_duration_drops_subsecond() {
        let c = FakeClock::at(0);
        c.advance(Duration::from_millis(1_999));
        // 1.999s → 1 whole second.
        assert_eq!(c.now_unix_secs(), 1);
    }

    #[test]
    fn advance_signed_saturates_at_max() {
        let c = FakeClock::at(i64::MAX - 1);
        c.advance_signed_secs(100);
        assert_eq!(c.now_unix_secs(), i64::MAX);
    }

    #[test]
    fn advance_signed_saturates_at_min() {
        let c = FakeClock::at(i64::MIN + 1);
        c.advance_signed_secs(-100);
        assert_eq!(c.now_unix_secs(), i64::MIN);
    }

    #[test]
    fn clone_shares_state_via_arc() {
        let c1 = FakeClock::at(0);
        let c2 = c1.clone();
        c1.advance_secs(7);
        // The clone observes the same advance — that's the contract.
        assert_eq!(c2.now_unix_secs(), 7);
    }

    #[test]
    fn dyn_clock_through_arc_works() {
        let fake = FakeClock::at(42);
        let dyn_clock: StdArc<dyn Clock> = StdArc::new(fake.clone());
        assert_eq!(dyn_clock.now_unix_secs(), 42);
        fake.set_now(43);
        assert_eq!(
            dyn_clock.now_unix_secs(),
            43,
            "Arc<dyn Clock> must observe set_now from the original handle"
        );
    }

    #[test]
    fn concurrent_advances_are_serialised() {
        // Spin up N threads each advancing by K seconds; final value
        // must equal N*K. If `advance_signed_secs` had a TOCTOU bug
        // (read-then-write without the lock), threads would race and
        // we'd see a smaller final value.
        const N: u64 = 16;
        const K: u64 = 100;
        let c = FakeClock::epoch();
        let mut handles = Vec::with_capacity(N as usize);
        for _ in 0..N {
            let c = c.clone();
            handles.push(thread::spawn(move || c.advance_secs(K)));
        }
        for h in handles {
            h.join().expect("worker panicked");
        }
        assert_eq!(c.now_unix_secs() as u64, N * K);
    }

    #[test]
    #[should_panic(expected = "delta exceeds i64::MAX")]
    fn advance_secs_panics_on_overflow_into_signed() {
        let c = FakeClock::epoch();
        c.advance_secs(u64::MAX);
    }
}

// Wall-clock abstraction for the RAXIS kernel and its peripherals.
//
// Why this lives in `raxis-types`:
// every implementation crate already depends on `raxis-types` and most of
// them have an inlined `fn now_unix_secs() -> i64` helper that (a) duplicates
// the same `SystemTime::now() - UNIX_EPOCH → as_secs() → i64` chain and
// (b) silently coerces clock errors via `unwrap_or_default()`, which yields
// `0` (= 1970-01-01) on system-clock failure. Centralising the conversion
// here keeps the production path consistent and gives us a single seam to
// inject a `FakeClock` from `raxis-test-support` in tests.
//
// What this module is NOT:
// - It is NOT a high-resolution timer. RAXIS persistence stores wall time
//   at second granularity (`UnixSeconds = i64` per spec id.rs), so the trait
//   surface returns whole seconds. Modules that need sub-second deltas
//   (e.g. metrics histograms) keep using `Instant::now()` directly.
// - It is NOT a monotonic clock. `SystemTime` can jump backwards on NTP
//   correction; that is the spec-mandated behaviour for the audit-log
//   `recorded_at` field, which is best-effort and is NOT used for any
//   ordering invariant (sequence numbers do that).

use std::time::{SystemTime, UNIX_EPOCH};

/// Source of wall-clock time, in whole seconds since the Unix epoch.
///
/// Implementors:
/// - `RealClock` (this crate) wraps `SystemTime::now()` and is the only
///   sane choice for production binaries.
/// - `FakeClock` (in `raxis-test-support`) holds a settable counter and
///   is the only sane choice for deterministic tests of TTL / expiry /
///   cooldown logic.
///
/// `Send + Sync` so kernel handlers can hold an `Arc<dyn Clock>` and
/// share it across the tokio runtime without locking.
pub trait Clock: Send + Sync + 'static {
    /// Whole seconds since 1970-01-01T00:00:00Z. Negative values are
    /// theoretically representable but in practice never returned by
    /// any implementor in this workspace (a fake test that sets time
    /// to before 1970 is allowed to fail).
    fn now_unix_secs(&self) -> i64;
}

/// The default `Clock` for production: reads `SystemTime::now()`.
///
/// On the (extraordinarily rare) condition that the host clock is set
/// to before 1970-01-01, `duration_since(UNIX_EPOCH)` returns `Err`
/// and we fall back to `0`. This matches the prior behaviour of the
/// nine duplicated `now_unix_secs()` helpers across the kernel and is
/// safe because every spec invariant that depends on relative time
/// (TTL, deadlines, cooldown windows) compares two clock reads from
/// the same `Clock` instance — both reads would be `0` together, so
/// the relative ordering is preserved.
#[derive(Debug, Default, Clone, Copy)]
pub struct RealClock;

impl Clock for RealClock {
    fn now_unix_secs(&self) -> i64 {
        unix_now_secs()
    }
}

/// Convenience free function: same body that was duplicated nine times
/// across the kernel as a private `now_unix_secs()`. Call sites that do
/// not (yet) take a `&dyn Clock` parameter use this; call sites that
/// have been migrated to dependency-injected `Clock` should call
/// `clock.now_unix_secs()` instead.
///
/// This function is what `RealClock::now_unix_secs` delegates to, so a
/// future change to clamping / saturation behaviour need only happen
/// in one place.
pub fn unix_now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn real_clock_and_free_fn_agree_within_a_second() {
        // Both call SystemTime::now() back-to-back; on any sane host the
        // delta is well under one whole second.
        let a = RealClock.now_unix_secs();
        let b = unix_now_secs();
        assert!(
            (a - b).abs() <= 1,
            "RealClock and unix_now_secs disagreed: a={a} b={b}"
        );
    }

    #[test]
    fn real_clock_returns_a_post_2024_value() {
        // 2024-01-01T00:00:00Z. Any host running this test in 2026+ MUST
        // return a value at least this large; if it doesn't, the host clock
        // is broken and most kernel-side TTL logic would also be broken.
        const JAN_1_2024_UTC: i64 = 1_704_067_200;
        assert!(
            RealClock.now_unix_secs() >= JAN_1_2024_UTC,
            "host clock returned a pre-2024 value — refusing to run kernel-time tests"
        );
    }

    #[test]
    fn dyn_clock_is_object_safe() {
        // Compile-time check: if `Clock` ever stops being object-safe
        // (e.g. by adding a generic method), kernel call sites that
        // hold `Arc<dyn Clock>` will fail to compile. Pin it here.
        let c: &dyn Clock = &RealClock;
        let _ = c.now_unix_secs();
    }
}

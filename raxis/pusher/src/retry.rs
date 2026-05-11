//! Exponential backoff with jitter for OTLP exports.
//!
//! Spec: `v3/otel-observability.md §12.4`.
//!
//! ```text
//! delay(n) = clamp(initial * 2^n, 0, max) ± jitter * delay(n)
//! ```
//!
//! `n` starts at 0 (first retry) and increments after each failed
//! attempt. `n == max_attempts` ⇒ give up; the caller drops the
//! batch and emits `OtlpExportPermanentFailure`.

use std::time::Duration;

/// Backoff knobs sourced from
/// `[observability.pusher].{backoff_initial, backoff_max,
/// backoff_jitter}`.
#[derive(Debug, Clone, Copy)]
pub struct BackoffPolicy {
    /// Initial delay. Doubled each step.
    pub initial: Duration,
    /// Saturating cap on the doubled delay.
    pub max:     Duration,
    /// Jitter as a fraction of the delay, in `[0.0, 1.0]`.
    pub jitter:  f64,
    /// Hard cap on retry attempts. The 9th attempt drops the
    /// batch and advances the cursor anyway. (8 attempts of
    /// retries + 1 initial = 9 total.)
    pub max_attempts: u32,
}

impl Default for BackoffPolicy {
    fn default() -> Self {
        Self {
            initial:      Duration::from_millis(500),
            max:          Duration::from_secs(30),
            jitter:       0.25,
            max_attempts: 8,
        }
    }
}

impl BackoffPolicy {
    /// Compute the delay for retry `n` (0-indexed). Uses OS
    /// randomness for the jitter; falls back to no jitter if the
    /// RNG fails (a non-fatal corner case — backoff is still
    /// monotone).
    pub fn delay(&self, n: u32) -> Duration {
        let exp = 2u128.saturating_pow(n.min(31));
        let base_ms = (self.initial.as_millis()).saturating_mul(exp);
        let cap_ms  = self.max.as_millis();
        let base_ms = base_ms.min(cap_ms);
        let with_jitter = apply_jitter(base_ms, self.jitter);
        // Clamp to u64 ms so the resulting Duration is always
        // representable without overflow.
        let ms = with_jitter.min(u64::MAX as u128) as u64;
        Duration::from_millis(ms)
    }

    /// True iff `n < max_attempts`.
    pub fn should_retry(&self, n: u32) -> bool {
        n < self.max_attempts
    }
}

fn apply_jitter(base_ms: u128, jitter: f64) -> u128 {
    if jitter <= 0.0 {
        return base_ms;
    }
    let mut buf = [0u8; 8];
    if getrandom::getrandom(&mut buf).is_err() {
        return base_ms;
    }
    let r = u64::from_le_bytes(buf);
    // Map r to [-1.0, +1.0).
    let frac = (r as f64) / (u64::MAX as f64);
    let signed = (frac - 0.5) * 2.0;
    let delta = (base_ms as f64) * jitter * signed;
    let candidate = (base_ms as i128).saturating_add(delta as i128);
    candidate.max(0) as u128
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delay_grows_exponentially_until_cap() {
        let p = BackoffPolicy {
            initial:      Duration::from_millis(100),
            max:          Duration::from_secs(5),
            jitter:       0.0,
            max_attempts: 8,
        };
        assert_eq!(p.delay(0), Duration::from_millis(100));
        assert_eq!(p.delay(1), Duration::from_millis(200));
        assert_eq!(p.delay(2), Duration::from_millis(400));
        // Past the cap ⇒ saturates.
        assert_eq!(p.delay(20), Duration::from_secs(5));
    }

    #[test]
    fn jitter_is_bounded() {
        let p = BackoffPolicy {
            initial:      Duration::from_secs(1),
            max:          Duration::from_secs(2),
            jitter:       0.5,
            max_attempts: 8,
        };
        for _ in 0..1000 {
            let d = p.delay(0);
            // 1s ± 0.5 = [500ms, 1500ms]; bracket is [0, 1.5s+ε].
            assert!(d <= Duration::from_millis(1600));
        }
    }

    #[test]
    fn should_retry_caps_at_max_attempts() {
        let p = BackoffPolicy { max_attempts: 3, ..BackoffPolicy::default() };
        assert!(p.should_retry(0));
        assert!(p.should_retry(1));
        assert!(p.should_retry(2));
        assert!(!p.should_retry(3));
    }
}

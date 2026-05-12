//! Wall-clock seconds since the Unix epoch. Tiny shim around
//! `std::time::SystemTime` so cache + audit emit a consistent
//! value across crates without each crate re-implementing
//! the duration math.

use std::time::{SystemTime, UNIX_EPOCH};

/// Wall-clock seconds since the Unix epoch. Returns `0` when
/// the system clock is before 1970-01-01 (impossible on real
/// hardware; defensive default so audit emit never panics).
pub fn unix_now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

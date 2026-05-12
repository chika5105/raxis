// raxis-kernel::ipc — IPC listener, auth, and dispatch subsystem.
//
// Normative reference: kernel-core.md §2.2 (handlers/), §2.3 (operator.rs),
// and peripherals.md §3 (wire codec, socket layout).
//
// Three UDS sockets:
//   <data_dir>/sockets/operator.sock  — operator CLI connections
//   <data_dir>/sockets/planner.sock   — planner subprocess connections
//   <data_dir>/sockets/gateway.sock   — gateway connections (v1 stub)
//
// All sockets use the raxis-ipc length-prefixed framing with bincode
// `config::standard()`.

pub mod context;
pub mod auth;
pub mod cid_blocklist;
pub mod log;
pub mod server;
pub mod operator;
pub mod operator_ergonomics;

// V2 Step 15 — pre-auth CID blocklist. Re-exported here because the
// accept layer consults it BEFORE any authenticated session lookup
// (cf. `ipc::auth`, which runs AFTER the connection is established).
// See `cid_blocklist.rs` and `v2-deep-spec.md §Step 15` for design.

// ---------------------------------------------------------------------------
// Accept-loop backoff curve — shared across the three UDS accept loops
// (operator, planner, gateway). Lives at the IPC-module root so all three
// consumers (`ipc::server::accept_operator_loop`,
// `ipc::server::accept_planner_loop`, and `gateway::accept::
// accept_gateway_loop`) import the same constants and the same step
// function.
//
// **Problem this addresses:** Pre-fix, every accept-loop slept a fixed
// 100 ms after any `accept()` failure. Under sustained kernel-side
// pressure — `EMFILE` (per-process FD exhaustion), `ENFILE` (system-wide
// FD exhaustion), kernel socket buffer pressure, or a broken peer that
// keeps initiating connections only to reset before `accept()` returns
// — the loop would retry 10×/sec while emitting one structured-stderr
// line per attempt. That is enough to fill operator journals, mask
// other diagnostics, and worsen the FD pressure (each retry consumes
// CPU and momentarily holds a half-open descriptor). It also gives the
// host no headroom to release whatever resource the kernel is waiting
// on.
//
// **Curve:** start at 100 ms, double on each successive failure, cap
// at 5 s. After a successful accept the caller resets back to the
// initial 100 ms so a single transient blip never extends into a long
// cooldown. The cap is chosen because 5 s is well within operator
// patience for "connect to a freshly-booted kernel" while bounding
// log volume to at most 12/min during a sustained outage.
//
// **Why centralise:** the three accept loops are otherwise independent
// (different message types, different auth handshakes, different
// audit policies). Sharing only the backoff curve means a future
// tuning change (e.g. raise the cap, or switch to decorrelated jitter)
// lands once and applies uniformly. The curve has no internal state —
// callers own their own `Duration` and pass it through `accept_backoff_step`
// — so this module stays trivially testable.

/// Initial sleep after the first `accept()` failure in any of the
/// kernel's UDS accept loops. Subsequent failures double the sleep
/// (capped by [`ACCEPT_BACKOFF_MAX`]); a successful accept resets to
/// this value.
pub(crate) const ACCEPT_BACKOFF_INITIAL: std::time::Duration =
    std::time::Duration::from_millis(100);

/// Upper bound on the per-iteration sleep when an accept loop has
/// failed repeatedly. Hit only after ~6 consecutive failures
/// (100, 200, 400, 800, 1600, 3200, 5000 ms).
pub(crate) const ACCEPT_BACKOFF_MAX: std::time::Duration =
    std::time::Duration::from_secs(5);

/// Compute the next backoff after a failure: double the current sleep,
/// clamped to [`ACCEPT_BACKOFF_MAX`]. Pure function; no internal state.
///
/// Sequence starting from `ACCEPT_BACKOFF_INITIAL` (100 ms):
///   100 → 200 → 400 → 800 → 1600 → 3200 → 5000 → 5000 → …
#[inline]
pub(crate) fn accept_backoff_step(current: std::time::Duration) -> std::time::Duration {
    let doubled = current.saturating_mul(2);
    if doubled > ACCEPT_BACKOFF_MAX {
        ACCEPT_BACKOFF_MAX
    } else {
        doubled
    }
}

#[cfg(test)]
mod accept_backoff_tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn initial_then_doubles_until_cap() {
        let mut d = ACCEPT_BACKOFF_INITIAL;
        let observed: Vec<u128> = (0..8)
            .map(|_| {
                let ms = d.as_millis();
                d = accept_backoff_step(d);
                ms
            })
            .collect();
        // 100, 200, 400, 800, 1600, 3200, 5000 (capped), 5000 (capped)
        assert_eq!(observed, vec![100, 200, 400, 800, 1600, 3200, 5000, 5000]);
    }

    #[test]
    fn cap_is_idempotent() {
        // Saturation must hold for any input ≥ cap, including the cap
        // itself and a saturating_mul that would otherwise overflow.
        assert_eq!(accept_backoff_step(ACCEPT_BACKOFF_MAX), ACCEPT_BACKOFF_MAX);
        assert_eq!(
            accept_backoff_step(Duration::from_secs(60)),
            ACCEPT_BACKOFF_MAX,
        );
        assert_eq!(accept_backoff_step(Duration::MAX), ACCEPT_BACKOFF_MAX);
    }

    #[test]
    fn initial_value_is_under_the_cap() {
        // Sanity: if a future edit moves the cap below the initial
        // value, the curve degenerates to a flat line. Make that a
        // compile-time-ish check (this runs in unit tests but the
        // intent is documentary).
        assert!(ACCEPT_BACKOFF_INITIAL < ACCEPT_BACKOFF_MAX);
    }
}

// raxis-kernel integration smoke-test for the `raxis-test-support`
// crate.
//
// What this test proves:
//
//   1. `raxis-test-support` is consumable from the kernel as a
//      dev-dep — i.e. the dependency graph is right and the public
//      surface compiles.
//   2. `FakeClock` plugs into anywhere a `dyn Clock` is expected,
//      including being held behind `Arc<dyn Clock>` (the shape kernel
//      handlers will eventually use to inject a clock).
//   3. The deterministic-time invariants of `FakeClock` work the way
//      kernel TTL tests will need them to: a value set BEFORE a
//      "deadline check" is observed by the check, and `advance_secs`
//      advances exactly that many seconds.
//   4. `mem_store()` returns a real, usable `raxis_store::Store`
//      with all migrations applied (smoke).
//   5. `FakeAuditSink` can capture the same audit-event variants
//      the production sink would emit.
//
// What this test does NOT do:
//
//   - It does NOT migrate any production kernel code path to take a
//     `&dyn Clock`. That migration is intentionally deferred to the
//     PR(s) that add a TTL-driven test which actually NEEDS injected
//     time. This file's job is just to pin the wiring contract so the
//     test-support crate is provably reachable from the kernel test
//     graph.

use raxis_audit_tools::event::AuditEventKind;
use raxis_audit_tools::sink::AuditSink;
use raxis_test_support::{mem_store, FakeAuditSink, FakeClock};
use raxis_types::Clock;
use std::sync::Arc;

/// Helper: pretend "this is the kernel checking a TTL". Anything that
/// returns true => "expired", false => "still fresh".
fn ttl_expired(clock: &dyn Clock, deadline_unix: i64) -> bool {
    clock.now_unix_secs() >= deadline_unix
}

#[test]
fn fake_clock_drives_a_ttl_check_through_dyn_clock() {
    // Set up a session-style TTL that expires at t=1_000_500.
    let clock = FakeClock::at(1_000_000);
    let deadline = 1_000_500_i64;

    // Inject as `Arc<dyn Clock>` — the exact shape kernel handlers
    // will use once `HandlerContext` carries a Clock.
    let dyn_clock: Arc<dyn Clock> = Arc::new(clock.clone());

    // Before the deadline → not expired.
    assert!(!ttl_expired(&*dyn_clock, deadline),
        "ttl must not be expired at t=1_000_000 with deadline=1_000_500");

    // Advance exactly 499s → still not expired.
    clock.advance_secs(499);
    assert!(!ttl_expired(&*dyn_clock, deadline),
        "ttl must not be expired at t=1_000_499 with deadline=1_000_500");

    // Advance one more second → now at the deadline → expired.
    clock.advance_secs(1);
    assert!(ttl_expired(&*dyn_clock, deadline),
        "ttl MUST be expired at t=1_000_500 with deadline=1_000_500");

    // Set time backward (clock skew simulation) → not expired again.
    clock.set_now(0);
    assert!(!ttl_expired(&*dyn_clock, deadline),
        "set_now MUST be observable through the Arc<dyn Clock> handle");
}

#[test]
fn mem_store_returns_a_usable_store() {
    // Simply opening + locking is enough to prove migrations applied.
    // The full schema is exercised by the store crate's own tests; we
    // just want a smoke check that mem_store wires correctly.
    let store = mem_store();
    let conn = store.lock_sync();
    let n: i64 = conn
        .query_row("SELECT COUNT(*) FROM sqlite_master", [], |r| r.get(0))
        .expect("query sqlite_master");
    assert!(n > 0, "mem_store returned an empty schema");
}

#[test]
fn fake_audit_sink_captures_a_real_audit_event_variant() {
    // The kernel will inject this same `Arc<dyn AuditSink>` into
    // HandlerContext during real tests. Prove it round-trips an event
    // variant from the production `AuditEventKind` enum.
    let sink = Arc::new(FakeAuditSink::new());

    let event = AuditEventKind::SessionRevoked {
        session_id: "sess-test".into(),
        revoked_by: "op-test".into(),
        revoked_by_display_name: None,
    };
    sink.emit(event, Some("sess-test"), None, None)
        .expect("FakeAuditSink::emit must not fail");

    let captured = sink.events();
    assert_eq!(captured.len(), 1, "sink must capture exactly one event");
    assert_eq!(captured[0].session_id.as_deref(), Some("sess-test"));
    assert!(matches!(captured[0].kind, AuditEventKind::SessionRevoked { .. }));
}

#[test]
fn fake_clock_clones_share_state_across_threads() {
    // Two clones of the same FakeClock — distributed across the kernel
    // (e.g. one in HandlerContext, one held by the test driver) — must
    // observe the same time. This is the property that makes
    // dependency-injected clocks usable: the test mutates the time
    // through its handle and the production code sees the change
    // through the trait object.
    let driver = FakeClock::at(0);
    let kernel_handle: Arc<dyn Clock> = Arc::new(driver.clone());

    // Spawn a "kernel worker" that polls clock.now_unix_secs() until it
    // observes a target value. With a properly shared Arc<Mutex<i64>>,
    // this completes immediately after the driver's set_now call.
    let h = std::thread::spawn(move || {
        for _ in 0..1_000 {
            if kernel_handle.now_unix_secs() >= 42 {
                return true;
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        false
    });

    driver.set_now(42);
    let observed = h.join().expect("worker panicked");
    assert!(observed, "kernel-side Arc<dyn Clock> failed to observe driver-side set_now(42)");
}

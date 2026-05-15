//! V2 Plan Bundle Sealing — periodic sweep of `plan_bundle_nonces_seen`.
//!
//! Normative reference: `specs/v2/plan-bundle-sealing.md` §8.4
//! ("Nonce-state retention and sweep").
//!
//! # What this loop does
//!
//! Per §8.4, `plan_bundle_nonces_seen` is the only `plan_bundle_*`
//! table that participates in any garbage collection. Rows whose
//! `first_seen_at_unix_secs` is older than
//!
//! ```text
//! [plan_signing].max_plan_bundle_age_secs
//! + [plan_signing].max_clock_skew_secs
//! + [plan_signing].nonce_retention_grace_secs
//! ```
//!
//! are inert: their associated `signed_at_unix_secs` is, by
//! construction, outside the freshness window already, so admission
//! step 10a (`FAIL_PLAN_BUNDLE_EXPIRED`) would reject any
//! re-submission *before* step 10b ever queries the nonce table. The
//! sweep deletes them via a single `DELETE` statement.
//!
//! # Why the kernel side, not the store side
//!
//! The actual `DELETE` lives in `raxis_store::plan_bundles::sweep_expired_nonces`
//! — that function is reusable from operator IPC ("force-sweep now"
//! ergonomics, future) and is unit-tested in isolation against a fake
//! clock. **This loop is the production driver**: it owns the periodic
//! cadence, the policy snapshot, the transaction opener, and the
//! shutdown handshake. Splitting concerns this way mirrors how
//! `runtime::heartbeat` separates `collect()` (testable) from
//! `run_loop()` (the production tokio task).
//!
//! # Termination
//!
//! Same pattern as `runtime::heartbeat::run_loop`: a
//! `oneshot::Receiver<()>` fires from `main.rs` after the IPC
//! dispatch loop returns, and the loop exits cleanly. A dropped
//! sender (e.g. a panicking `main`) is treated identically — the
//! kernel is going down, so there is no value in continuing to write.

use std::sync::Arc;

use raxis_policy::PlanSigningSection;
use raxis_store::Store;
use rusqlite::TransactionBehavior;
use tokio::sync::oneshot;

/// One sweep tick — open a `BEGIN IMMEDIATE` transaction, compute the
/// §8.4 cutoff from `now()` and the live `[plan_signing]` snapshot,
/// run the `DELETE`, commit. Returns the number of rows deleted on
/// success; `Err` on any rusqlite or transaction error.
///
/// The function is `pub(super)` so the integration test in this
/// module can drive a sweep deterministically without spinning up
/// the full tokio loop.
///
/// `now_unix_secs` is taken as a parameter so tests can inject a
/// fake clock without touching `SystemTime`. Production callers pass
/// `raxis_types::unix_now_secs() as i64`.
pub(super) fn sweep_once(
    store: &Store,
    plan_signing: &PlanSigningSection,
    now_unix_secs: i64,
) -> Result<usize, rusqlite::Error> {
    let live_window_secs = plan_signing.nonce_live_window_secs();
    let cutoff_unix_secs = now_unix_secs.saturating_sub(live_window_secs as i64);

    let mut conn = store.lock_sync();
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let n = raxis_store::sweep_expired_nonces(&tx, cutoff_unix_secs).map_err(|e| match e {
        raxis_store::PlanBundleStoreError::Sqlite(s) => s,
        other => rusqlite::Error::ToSqlConversionFailure(Box::new(other)),
    })?;
    tx.commit()?;
    Ok(n)
}

/// Spawn-friendly `plan_bundle_nonces_seen` sweep loop.
///
/// Steady-state behaviour:
///   - Tick every `[plan_signing].nonce_sweep_interval_secs`.
///   - On each tick, run `sweep_once` against the live policy
///     snapshot. The snapshot is re-read on every tick so an epoch
///     advance that lengthens the freshness window (and therefore
///     the live-nonce retention window) takes effect immediately,
///     not on the next kernel restart.
///   - On error, log to stderr and continue. A failed `DELETE` does
///     NOT crash the kernel — replay protection still works because
///     admission step 10b reads from the table directly; an unswept
///     row just costs a few bytes until the next tick succeeds.
///
/// Termination:
///   - The `shutdown` `oneshot::Receiver` firing is the canonical
///     stop signal. We do NOT run a final post-shutdown sweep —
///     unlike heartbeat (which writes a final `Stopping` snapshot
///     for operator visibility), the sweep has no externally-visible
///     "wind-down" state.
///   - `oneshot::Receiver::recv` returning `Err` (the sender was
///     dropped without firing) is treated identically.
///
/// # Why the policy snapshot is re-read on every tick
///
/// The `Arc<ArcSwap<PolicyBundle>>` exposes wait-free reads via
/// `policy.load()`. An epoch advance (`policy_manager::advance_epoch`)
/// flips the visible snapshot atomically; the next tick sees the new
/// `[plan_signing]` automatically. Sampling the cadence from the
/// snapshot at tick time means a 24-hour-cadence kernel can be
/// re-cadenced to 1 hour by an epoch advance without restart — at
/// the cost of one snapshot read per tick (cheap).
///
/// # Why we use `spawn_blocking` per tick instead of a sync loop
///
/// `Store::lock_sync()` calls `tokio::sync::Mutex::blocking_lock()`,
/// which panics with "Cannot block the current thread from within a
/// runtime" if called directly from a tokio task. The sweep itself
/// is fast (a single indexed `DELETE`, sub-millisecond on tables of
/// this size), so the cost of one `spawn_blocking` per tick is
/// negligible.
pub async fn run_loop(
    store: Arc<Store>,
    policy: Arc<arc_swap::ArcSwap<raxis_policy::PolicyBundle>>,
    mut shutdown: oneshot::Receiver<()>,
) {
    // Read the initial cadence from the policy snapshot at boot. We
    // do NOT re-read between ticks — the `tokio::time::interval`
    // owns its own clock and changing the cadence mid-flight would
    // require rebuilding it. Operators who lower
    // `nonce_sweep_interval_secs` see the new cadence on next
    // kernel restart; the live-window computation (which DOES
    // re-read on every tick) is what actually drives correctness.
    let initial_cadence_secs = policy.load().plan_signing().nonce_sweep_interval_secs;
    // Defence-in-depth: policy validation today enforces a 1-second
    // lower bound (see `plan_signing_tests`), but
    // `tokio::time::interval(Duration::ZERO)` panics with "interval
    // period must not be zero". Clamp to >= 1ms here so a future
    // policy-validator change (or a hand-edited test policy) can
    // never crash the sweeper at boot. The 1ms floor is far below
    // any realistic sweep cadence and below the policy lower bound,
    // so it never affects production behaviour.
    let cadence = std::time::Duration::from_secs(initial_cadence_secs)
        .max(std::time::Duration::from_millis(1));

    let mut interval = tokio::time::interval(cadence);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    // Skip the immediate-fire of the first `interval.tick()`. Unlike
    // heartbeat, there is no value in running a sweep at boot — the
    // table is necessarily empty (no admission has happened yet) or
    // the §8.4 window guarantees no row is yet stale.
    interval.tick().await;

    loop {
        tokio::select! {
            _ = interval.tick() => {
                let store_for_tick  = Arc::clone(&store);
                let plan_signing    = policy.load().plan_signing();
                let now             = raxis_types::unix_now_secs();
                let outcome = tokio::task::spawn_blocking(move || {
                    sweep_once(&store_for_tick, &plan_signing, now)
                }).await;

                match outcome {
                    Ok(Ok(n)) if n > 0 => {
                        eprintln!(
                            "{{\"level\":\"info\",\"event\":\"plan_bundle_nonce_sweep\",\
                             \"swept\":{n},\"now_unix_secs\":{now}}}",
                        );
                    }
                    Ok(Ok(_)) => {
                        // Zero-row sweeps are the steady-state norm.
                        // Logging at `debug` would be appropriate but
                        // the kernel does not currently ship a debug
                        // logger — silence is the right floor.
                    }
                    Ok(Err(e)) => {
                        eprintln!(
                            "{{\"level\":\"warn\",\"event\":\"plan_bundle_nonce_sweep_failed\",\
                             \"reason\":\"{e}\"}}",
                        );
                    }
                    Err(join_err) => {
                        eprintln!(
                            "{{\"level\":\"warn\",\
                             \"event\":\"plan_bundle_nonce_sweep_join_failed\",\
                             \"reason\":\"{join_err}\"}}",
                        );
                    }
                }
            }
            _ = &mut shutdown => {
                eprintln!(
                    "{{\"level\":\"info\",\"event\":\"plan_bundle_nonce_sweep_stopping\"}}",
                );
                return;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    use raxis_store::record_nonce;
    use raxis_types::{BundleNonce, BundleSha256, PlanBundleNonceOutcome};

    /// Produce an empty `Store` with all migrations applied.
    ///
    /// `Store::open_in_memory` already runs `apply_pending` to
    /// `SCHEMA_VERSION` (kernel-store.md §2.5.1) — the V2.1 nonce
    /// table from Migration 8 is created automatically.
    fn fresh_store() -> Arc<Store> {
        Arc::new(Store::open_in_memory().unwrap())
    }

    /// Insert one `plan_bundle_nonces_seen` row at a chosen
    /// `first_seen_at_unix_secs`. The §8.2 schema does NOT impose a
    /// foreign-key reference from `plan_bundle_nonces_seen.bundle_sha256`
    /// to `plan_bundles.bundle_sha256` (an explicit design choice — see
    /// `plan-bundle-sealing.md §8.2`), so we can seed the nonce row
    /// directly without populating the bundle byte store first.
    /// This keeps the test focused on sweep behaviour, not bundle
    /// construction.
    fn seed_admitted_nonce(store: &Store, seed: u8, first_seen_at_unix_secs: i64) {
        let nonce = BundleNonce::new([seed; 16]);
        let sha256 = BundleSha256::new([seed; 32]);
        let mut conn = store.lock_sync();
        let tx = conn.transaction().unwrap();
        record_nonce(
            &tx,
            &nonce,
            &sha256,
            1_700_000_000, // signed_at — not under test here
            first_seen_at_unix_secs,
            PlanBundleNonceOutcome::Admitted,
            Some("init-X"),
        )
        .unwrap();
        tx.commit().unwrap();
    }

    /// Count rows in `plan_bundle_nonces_seen`.
    fn nonce_row_count(store: &Store) -> i64 {
        let conn = store.lock_sync();
        conn.query_row("SELECT COUNT(*) FROM plan_bundle_nonces_seen", [], |r| {
            r.get(0)
        })
        .unwrap()
    }

    #[test]
    fn sweep_once_deletes_only_rows_older_than_live_window() {
        let store = fresh_store();
        let plan_signing = PlanSigningSection {
            max_plan_bundle_age_secs: 3600,
            max_clock_skew_secs: 60,
            nonce_retention_grace_secs: 300,
            nonce_sweep_interval_secs: 60,
            accept_unfresh_v2_0_bundles: false,
        };
        let live_window = plan_signing.nonce_live_window_secs() as i64;
        assert_eq!(live_window, 3600 + 60 + 300);

        let now: i64 = 2_000_000_000;

        // Stale: first_seen at now - live_window - 1 → should be reaped.
        seed_admitted_nonce(&store, 1, now - live_window - 1);
        // Boundary: first_seen at exactly now - live_window → RETAINED.
        // The §8.4 SQL is `<` cutoff, so equal-to-cutoff stays.
        seed_admitted_nonce(&store, 2, now - live_window);
        // Fresh: first_seen at now → kept.
        seed_admitted_nonce(&store, 3, now);

        assert_eq!(nonce_row_count(&store), 3);

        let n = sweep_once(&store, &plan_signing, now).unwrap();
        assert_eq!(n, 1, "exactly the stale row should be deleted");
        assert_eq!(nonce_row_count(&store), 2);
    }

    #[test]
    fn sweep_once_is_idempotent_when_no_rows_are_stale() {
        let store = fresh_store();
        let plan_signing = PlanSigningSection::default();
        let now: i64 = 2_000_000_000;

        seed_admitted_nonce(&store, 1, now - 10);
        seed_admitted_nonce(&store, 2, now - 20);
        seed_admitted_nonce(&store, 3, now - 30);
        assert_eq!(nonce_row_count(&store), 3);

        let n1 = sweep_once(&store, &plan_signing, now).unwrap();
        let n2 = sweep_once(&store, &plan_signing, now).unwrap();
        assert_eq!(
            (n1, n2),
            (0, 0),
            "sweep on fresh rows must be a no-op twice over"
        );
        assert_eq!(nonce_row_count(&store), 3);
    }

    #[test]
    fn sweep_once_handles_empty_table_cleanly() {
        let store = fresh_store();
        let plan_signing = PlanSigningSection::default();
        let n = sweep_once(&store, &plan_signing, 2_000_000_000).unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn sweep_once_uses_now_minus_live_window_as_cutoff() {
        // Verify the cutoff math: row at first_seen = (now - live_window)
        // survives, row at (now - live_window - 1) is reaped. This is
        // the §8.4 boundary contract written out as a separate test for
        // clarity (the omnibus test above mixes three rows; this one
        // makes the inequality explicit).
        let store = fresh_store();
        let plan_signing = PlanSigningSection {
            max_plan_bundle_age_secs: 100,
            max_clock_skew_secs: 10,
            nonce_retention_grace_secs: 5,
            nonce_sweep_interval_secs: 10,
            accept_unfresh_v2_0_bundles: false,
        };
        let live_window = plan_signing.nonce_live_window_secs() as i64;
        let now: i64 = 1_000_000;

        seed_admitted_nonce(&store, 1, now - live_window); // boundary, kept
        seed_admitted_nonce(&store, 2, now - live_window - 1); // stale
        let n = sweep_once(&store, &plan_signing, now).unwrap();
        assert_eq!(n, 1);
        assert_eq!(nonce_row_count(&store), 1);
    }

    /// End-to-end: spin a manually-orchestrated sweep loop with a
    /// sub-second cadence and assert a stale row is reaped before the
    /// shutdown signal fires. The production `run_loop` uses an
    /// integer-second cadence per `[plan_signing].nonce_sweep_interval_secs`
    /// (policy-validated lower bound: 1 second); using a 50 ms manual
    /// loop here lets the test complete in ~200 ms.
    ///
    /// We do not invoke `run_loop` directly because constructing a
    /// real `PolicyBundle` from this kernel-internal test module
    /// would pull in `raxis-test-support`. The behaviour under test
    /// is the cadence + shutdown handshake at the `sweep_once` boundary,
    /// not the `policy.load().plan_signing()` snapshot path (which is
    /// covered separately by `raxis-policy::plan_signing_tests`).
    #[tokio::test(flavor = "multi_thread")]
    async fn manual_sweep_loop_reaps_stale_nonce_then_exits_on_shutdown() {
        let store = fresh_store();
        let plan_signing = PlanSigningSection::default();

        // Seed a row that is ALREADY far past the live window
        // (first_seen at year ~2001, expecting now ~2026). Seeding
        // calls `store.lock_sync()` which uses
        // `tokio::sync::Mutex::blocking_lock()` — must happen inside
        // `spawn_blocking` from this async context.
        let store_for_seed = Arc::clone(&store);
        tokio::task::spawn_blocking(move || {
            seed_admitted_nonce(&store_for_seed, 0xAA, 1_000_000_000);
        })
        .await
        .unwrap();
        let store_for_count = Arc::clone(&store);
        let initial = tokio::task::spawn_blocking(move || nonce_row_count(&store_for_count))
            .await
            .unwrap();
        assert_eq!(initial, 1);

        let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();
        let store_for_loop = Arc::clone(&store);
        let signing_for_loop = plan_signing.clone();
        let handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_millis(50));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            interval.tick().await; // skip the immediate first fire
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        let store_for_tick   = Arc::clone(&store_for_loop);
                        let signing_for_tick = signing_for_loop.clone();
                        let now = raxis_types::unix_now_secs();
                        let _ = tokio::task::spawn_blocking(move || {
                            sweep_once(&store_for_tick, &signing_for_tick, now)
                        }).await;
                    }
                    _ = &mut shutdown_rx => return,
                }
            }
        });

        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        let _ = shutdown_tx.send(());
        handle.await.unwrap();

        let store_for_post = Arc::clone(&store);
        let post = tokio::task::spawn_blocking(move || nonce_row_count(&store_for_post))
            .await
            .unwrap();
        assert_eq!(
            post, 0,
            "stale row must be reaped after at least one cadence tick"
        );
    }
}

//! Boot-time `ObservabilityHub` construction.
//!
//! Hoisted out of `main.rs` so the same builder runs once and the
//! resulting `Arc<ObservabilityHub>` flows into:
//!
//!   * the orchestrator-spawn `SessionSpawnService` (V3 perf-telemetry
//!     four-tier VM cold-boot histograms emit from the very first
//!     spawn),
//!   * the executor / reviewer spawn `SessionSpawnService`,
//!   * the `HandlerContext` (every request handler's emit sites).
//!
//! When `[observability].enabled = false` the returned hub uses
//! `NoopExporter` and every emit site short-circuits before
//! sanitisation. When enabled, the kernel writes JSONL frames into
//! `<data_dir>/observability/` (or operator-supplied
//! `[observability.ring].dir`) and the out-of-process
//! `raxis-otel-pusher` reads + ships via OTLP per `INV-OTEL-03`.
//!
//! ## Periodic flush task
//!
//! When the hub is enabled, [`build_obs_hub`] also spawns a single
//! tokio task per kernel run that calls
//! [`raxis_observability::ObservabilityHub::flush`] every
//! `[observability.metrics].export_interval` (default `15s`, range
//! `[1s, 300s]`). Without this loop the in-memory buffer fills to
//! `[observability.ring].max_queue_depth` and silently drops every
//! subsequent record as `DropReason::QueueFull` — the JSONL ring
//! files stay 0 bytes for the full kernel lifetime, the
//! out-of-process pusher tails empty files, and Prometheus
//! scrapes nothing.
//!
//! The flush cadence is the kernel-side queue drain, distinct from
//! `[observability.pusher].otlp_flush_interval` which controls the
//! pusher-side OTLP batch cadence (see `pusher/`).
//!
//! Failure to open the ring directory is logged loudly to stderr but
//! does NOT abort the kernel; the kernel proceeds with a disabled
//! hub so the operator can still observe the failure via the boot
//! banner and the next normal log line.

use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use raxis_policy::PolicyBundle;

/// Build a hub from the live `PolicyBundle` snapshot. The hub is
/// disabled when `[observability].enabled = false`.
///
/// When enabled, this also spawns a periodic queue-drain task on the
/// current tokio runtime — see the module doc-comment.
pub(crate) fn build_obs_hub(
    policy: &Arc<ArcSwap<PolicyBundle>>,
    data_dir: &std::path::Path,
    kernel_version: &str,
) -> Arc<raxis_observability::ObservabilityHub> {
    let snap = policy.load();
    let oc = snap.observability();
    if !oc.enabled {
        return Arc::new(raxis_observability::ObservabilityHub::disabled());
    }
    let export_interval = oc.metrics.export_interval;
    let ring_root = if oc.ring.dir.is_empty() {
        data_dir.to_path_buf()
    } else {
        std::path::PathBuf::from(&oc.ring.dir)
    };
    let ring_cfg = raxis_observability::ring::RingConfig {
        segment_max_bytes: oc.ring.segment_max_bytes,
        max_total_bytes:   oc.ring.max_total_bytes,
    };
    let hub_cfg = raxis_observability::HubConfig {
        enabled:             true,
        max_queue_depth:     oc.ring.max_queue_depth,
        sample_rate:         oc.traces.sample_rate,
        max_attrs_per_span:  oc.traces.max_attrs_per_span,
        max_events_per_span: oc.traces.max_events_per_span,
        histogram_buckets:   oc.metrics.histogram_buckets.clone(),
    };
    match raxis_observability::ObservabilityHub::with_ring_at(
        hub_cfg,
        &ring_root,
        ring_cfg,
        kernel_version.to_owned(),
    ) {
        Ok((hub, _exp)) => {
            let hub = Arc::new(hub);
            spawn_periodic_flush(Arc::clone(&hub), export_interval);
            hub
        }
        Err(e) => {
            eprintln!(
                "{{\"level\":\"warn\",\"event\":\"ObservabilityHubInitFailed\",\"reason\":\"{e}\"}}",
            );
            Arc::new(raxis_observability::ObservabilityHub::disabled())
        }
    }
}

/// Drive the hub's queue drain on a fixed cadence so the in-memory
/// buffer empties into the exporter (ring file → pusher → OTLP).
///
/// Without this task the hub fills to `max_queue_depth` and silently
/// drops every subsequent record. The structural truth this loop
/// enforces is: an enabled hub MUST drain its queue periodically or
/// it fails closed silently. See the module doc-comment.
///
/// Guards:
///
///   * `interval.is_zero()` — config validation forbids this in
///     production (`MIN_EXPORT_INTERVAL_MS = 1000`), but we belt-and-
///     braces against a hand-constructed `HubConfig` in tests
///     (`tokio::time::interval` panics on a zero period).
///   * `!hub.enabled()` — disabled hubs have no buffer to drain;
///     spawning a tick loop just wastes a tokio task.
///
/// The loop runs on the kernel's main multi-threaded tokio runtime;
/// the per-tick `flush()` cost is bounded by `max_queue_depth` and
/// the exporter's serial I/O. Aborting the kernel cancels the task
/// via runtime drop.
fn spawn_periodic_flush(
    hub: Arc<raxis_observability::ObservabilityHub>,
    interval: Duration,
) {
    if interval.is_zero() || !hub.enabled() {
        return;
    }
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // `tokio::time::interval` fires immediately on the first
        // tick — discard it so the first real flush lands one
        // `interval` after spawn, matching the
        // `[observability.metrics].export_interval` contract
        // operators see in their dashboards.
        ticker.tick().await;
        loop {
            ticker.tick().await;
            hub.flush();
        }
    });
}

// ---------------------------------------------------------------------------
// Tests — witness for the periodic flush task.
//
// Lives inline (rather than at `kernel/tests/observability_periodic_flush.rs`)
// because the kernel package is binary-only (`[[bin]] path = "src/main.rs"`,
// no `[lib]`), so an integration test under `kernel/tests/` would not be
// able to reach `spawn_periodic_flush` (which is the actual spawn site we
// want to exercise — `build_obs_hub` itself only adds policy-bundle plumbing
// on top of the spawn). An inline `#[cfg(test)]` block compiles into the
// binary's test harness and exercises the same `spawn_periodic_flush`
// function the production `build_obs_hub` calls.
//
// Witness contract — the structural truth this guards (verbatim from the
// diagnostic worker's report):
//
//   "An enabled hub MUST drain its queue periodically or it silently fails
//   closed — the queue fills, drops all subsequent records, and the ring
//   file stays empty."
//
// `periodic_flush_drains_queue_to_ring_file_within_one_interval` asserts
// the ring file is 0 bytes BEFORE the first interval elapses (the spawn
// loop discards its immediate first tick), and that the file is non-zero
// AFTER `2 × export_interval + 50ms`. Without `spawn_periodic_flush` this
// test fails on the post-sleep size assertion — the iter48 regression
// made structural.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use raxis_observability::{
        ring::RingConfig, HubConfig, ObservabilityHub,
    };

    use super::spawn_periodic_flush;

    fn make_enabled_hub(
        ring_root: &std::path::Path,
        max_queue_depth: usize,
    ) -> Arc<ObservabilityHub> {
        let cfg = HubConfig {
            enabled:             true,
            max_queue_depth,
            sample_rate:         1.0,
            max_attrs_per_span:  32,
            max_events_per_span: 16,
            histogram_buckets:   vec![1.0, 5.0, 10.0, 25.0, 50.0, 100.0],
        };
        // Lift caps so the test never trips a rotate / GC mid-flush.
        // The witness only cares about "ring file grew past 0 bytes".
        let ring_cfg = RingConfig {
            segment_max_bytes: 16 * 1024 * 1024,
            max_total_bytes:   64 * 1024 * 1024,
        };
        let (hub, _exp) = ObservabilityHub::with_ring_at(
            cfg,
            ring_root,
            ring_cfg,
            "raxis-kernel-test".to_owned(),
        )
        .expect("RingFileExporter::open must succeed under tempdir");
        Arc::new(hub)
    }

    fn first_metrics_segment(ring_root: &std::path::Path) -> std::path::PathBuf {
        ring_root.join("observability/metrics/000001.jsonl")
    }

    /// Witness for the periodic flush task — without this loop the
    /// hub's in-memory queue fills and silently drops everything,
    /// leaving the ring file 0 bytes for the entire kernel lifetime
    /// (the iter48 regression).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn periodic_flush_drains_queue_to_ring_file_within_one_interval() {
        // Short interval so the test runs in <500 ms but still
        // exercises the "first tick is discarded" semantics of
        // `spawn_periodic_flush`.
        let interval = Duration::from_millis(100);
        let tmp = tempfile::tempdir().expect("tempdir");
        let hub = make_enabled_hub(tmp.path(), 4096);

        // Spawn the periodic drain — the literal `build_obs_hub` boot path.
        spawn_periodic_flush(Arc::clone(&hub), interval);

        // Drive a record through `record_intent_admission` (a helper
        // that's actually wired in production via
        // `handlers::intent::handle`). Use the kernel's emit-site
        // wrapper so we're not duplicating its closed-allow-list shape.
        crate::observability::record_intent_admission(
            hub.as_ref(),
            "SingleCommit",
            "Accepted",
            42,
        );

        // BEFORE one interval has elapsed: the ring file MUST still
        // be 0 bytes — the flush task discards its immediate first
        // tick, so nothing has been drained yet. We sample at half
        // the interval so we're robustly inside that window.
        let metrics_jsonl = first_metrics_segment(tmp.path());
        tokio::time::sleep(interval / 2).await;
        let pre_size = std::fs::metadata(&metrics_jsonl)
            .map(|m| m.len())
            .unwrap_or(0);
        assert_eq!(
            pre_size, 0,
            "ring file at {} should be 0 bytes before first flush \
             fires; observed {pre_size}",
            metrics_jsonl.display(),
        );

        // AFTER 2× interval + 50 ms: the flush task MUST have
        // ticked at least once (the discarded first tick + one
        // real tick) and pushed the metric to the exporter, which
        // writes JSONL frames.
        tokio::time::sleep(interval * 2 + Duration::from_millis(50)).await;

        let post_size = std::fs::metadata(&metrics_jsonl)
            .unwrap_or_else(|e| {
                panic!(
                    "ring file {} must exist after one export_interval \
                     has elapsed; periodic flush task is missing or \
                     wedged: {e}",
                    metrics_jsonl.display(),
                )
            })
            .len();
        assert!(
            post_size > 0,
            "ring file at {} stayed 0 bytes after 2 × export_interval; \
             periodic flush task did not drain the queue (the iter48 \
             regression). interval={:?}",
            metrics_jsonl.display(),
            interval,
        );
    }

    /// `spawn_periodic_flush` MUST be a no-op for a disabled hub —
    /// otherwise we'd burn a tokio task per kernel run when
    /// `[observability].enabled = false`. We can't observe "no task
    /// spawned" directly, so we observe the proxy: a disabled hub
    /// holds a `NoopExporter`, which never writes a ring file at all.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn periodic_flush_is_noop_when_hub_disabled() {
        let interval = Duration::from_millis(50);
        let tmp = tempfile::tempdir().expect("tempdir");
        let hub = Arc::new(ObservabilityHub::disabled());
        spawn_periodic_flush(Arc::clone(&hub), interval);
        tokio::time::sleep(interval * 3).await;
        let metrics_dir = tmp.path().join("observability/metrics");
        assert!(
            !metrics_dir.exists(),
            "disabled hub must not create a ring directory at {}",
            metrics_dir.display(),
        );
    }

    /// Zero-interval guard: passing `Duration::ZERO` MUST short-circuit
    /// instead of spinning a `tokio::time::interval` (which panics on
    /// zero-period). Production policy validation forbids this
    /// (`MIN_EXPORT_INTERVAL_MS = 1000`); the guard is belt-and-braces.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn periodic_flush_zero_interval_is_noop() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let hub = make_enabled_hub(tmp.path(), 256);
        spawn_periodic_flush(Arc::clone(&hub), Duration::ZERO);
        // If the guard fired, the function returned synchronously
        // and no panic happened. Sleep briefly so any errantly-
        // spawned task would have a chance to fire (and tip us off
        // via a non-empty ring file). Even with a record submitted,
        // the ring file must remain 0 bytes because no flush ever fires.
        crate::observability::record_intent_admission(
            hub.as_ref(),
            "SingleCommit",
            "Accepted",
            1,
        );
        tokio::time::sleep(Duration::from_millis(120)).await;
        let metrics_jsonl = first_metrics_segment(tmp.path());
        let size = std::fs::metadata(&metrics_jsonl)
            .map(|m| m.len())
            .unwrap_or(0);
        assert_eq!(
            size, 0,
            "zero-interval guard should suppress the flush task; \
             ring file should be 0 bytes, got {size}",
        );
    }
}

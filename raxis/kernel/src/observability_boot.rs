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
//! Failure to open the ring directory is logged loudly to stderr but
//! does NOT abort the kernel; the kernel proceeds with a disabled
//! hub so the operator can still observe the failure via the boot
//! banner and the next normal log line.

use std::sync::Arc;

use arc_swap::ArcSwap;
use raxis_policy::PolicyBundle;

/// Build a hub from the live `PolicyBundle` snapshot. The hub is
/// disabled when `[observability].enabled = false`.
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
    let ring_root = if oc.ring.dir.is_empty() {
        data_dir.to_path_buf()
    } else {
        std::path::PathBuf::from(&oc.ring.dir)
    };
    let ring_cfg = raxis_observability::ring::RingConfig {
        segment_max_bytes: oc.ring.segment_max_bytes,
        max_total_bytes: oc.ring.max_total_bytes,
    };
    let hub_cfg = raxis_observability::HubConfig {
        enabled: true,
        max_queue_depth: oc.ring.max_queue_depth,
        sample_rate: oc.traces.sample_rate,
        max_attrs_per_span: oc.traces.max_attrs_per_span,
        max_events_per_span: oc.traces.max_events_per_span,
        histogram_buckets: oc.metrics.histogram_buckets.clone(),
    };
    match raxis_observability::ObservabilityHub::with_ring_at(
        hub_cfg,
        &ring_root,
        ring_cfg,
        kernel_version.to_owned(),
    ) {
        Ok((hub, _exp)) => Arc::new(hub),
        Err(e) => {
            eprintln!(
                "{{\"level\":\"warn\",\"event\":\"ObservabilityHubInitFailed\",\"reason\":\"{e}\"}}",
            );
            Arc::new(raxis_observability::ObservabilityHub::disabled())
        }
    }
}

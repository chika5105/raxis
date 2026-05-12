//! V3 perf-telemetry helpers internal to `raxis-session-spawn`.
//!
//! These helpers fire the four-tier VM cold-boot histogram family
//! (`raxis.isolation.spawn.cold_boot.duration` plus the `host_init`,
//! `guest_init`, and `vsock_handshake` partitions) AND the per-spawn
//! counter (`raxis.isolation.spawn.total`) with the
//! `(backend, image_kind, outcome[, failure_class])` attribute set
//! mandated by `specs/v3/observability-prometheus.md §3.1`.
//!
//! Cold boot is the user-visible wall-clock from the FIRST instruction
//! of `SessionSpawnService::spawn_session` to the moment the substrate
//! has handed back a session AND its IPC stream has been wrapped. The
//! three sub-partitions cover:
//!
//!   * `host_init_ms` -- the `tokio::task::spawn_blocking` window
//!     during which the substrate booted the VM.
//!   * `guest_init_ms` -- everything between session-handed-back and
//!     IPC-stream-wrapped.
//!   * `vsock_handshake_ms` -- substrate-internal CONNECT-loop
//!     duration, left `None` until AVF / Firecracker self-report it.
//!
//! Every helper short-circuits when the optional observability hub is
//! not wired (legacy callers — live-e2e fixtures, integration tests —
//! keep paying zero cost). The helpers stay private to the
//! `session-spawn` crate so the public surface of the crate does not
//! depend on the observability metric-name catalogue.

use raxis_observability::{redact, AttrValue, MetricName, ObservabilityHub};

use crate::SessionSpawnService;

/// Record a successful four-tier VM cold-boot.
pub(crate) fn record_successful_spawn(
    svc: &SessionSpawnService,
    image_kind: &str,
    cold_boot_ms: i64,
    host_init_ms: Option<i64>,
    guest_init_ms: Option<i64>,
    vsock_handshake_ms: Option<i64>,
) {
    let Some(hub) = svc.observability_hub() else {
        return;
    };
    if !hub.enabled() {
        return;
    }
    emit(
        hub,
        svc.backend_id(),
        image_kind,
        "success",
        None,
        cold_boot_ms,
        host_init_ms,
        guest_init_ms,
        vsock_handshake_ms,
    );
}

/// Record a failed VM cold-boot. `failure_class` is the stable
/// projection from `lib::failure_class_for(&IsolationError)`.
pub(crate) fn record_failed_spawn(
    svc: &SessionSpawnService,
    image_kind: &str,
    cold_boot_ms: i64,
    host_init_ms: Option<i64>,
    guest_init_ms: Option<i64>,
    vsock_handshake_ms: Option<i64>,
    failure_class: &str,
) {
    let Some(hub) = svc.observability_hub() else {
        return;
    };
    if !hub.enabled() {
        return;
    }
    emit(
        hub,
        svc.backend_id(),
        image_kind,
        "failure",
        Some(failure_class),
        cold_boot_ms,
        host_init_ms,
        guest_init_ms,
        vsock_handshake_ms,
    );
}

#[allow(clippy::too_many_arguments)]
fn emit(
    hub: &ObservabilityHub,
    backend: &str,
    image_kind: &str,
    outcome: &str,
    failure_class: Option<&str>,
    cold_boot_ms: i64,
    host_init_ms: Option<i64>,
    guest_init_ms: Option<i64>,
    vsock_handshake_ms: Option<i64>,
) {
    let mut labels = redact::attrs([
        ("backend", backend),
        ("image_kind", image_kind),
        ("outcome", outcome),
    ]);
    if let Some(fc) = failure_class {
        labels.insert("failure_class".to_owned(), AttrValue::Str(fc.to_owned()));
    }
    hub.record_counter(MetricName::IsolationSpawnTotal, labels.clone(), 1.0);
    hub.record_histogram(
        MetricName::IsolationSpawnColdBootDuration,
        labels.clone(),
        cold_boot_ms.max(0) as f64,
    );
    if let Some(ms) = host_init_ms {
        hub.record_histogram(
            MetricName::IsolationSpawnHostInitDuration,
            labels.clone(),
            ms.max(0) as f64,
        );
    }
    if let Some(ms) = guest_init_ms {
        hub.record_histogram(
            MetricName::IsolationSpawnGuestInitDuration,
            labels.clone(),
            ms.max(0) as f64,
        );
    }
    if let Some(ms) = vsock_handshake_ms {
        hub.record_histogram(
            MetricName::IsolationSpawnVsockHandshakeDuration,
            labels,
            ms.max(0) as f64,
        );
    }
}

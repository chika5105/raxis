//! Pusher-side runtime configuration. Built from
//! `raxis_policy::ObservabilityPusherConfig` plus the operator-
//! supplied `--data-dir` argument.
//!
//! Spec: `v3/otel-observability.md §12.2`.
//!
//! The pusher does NOT re-validate the policy — the kernel's boot
//! sequence already verified the artifact signature and ran
//! `PolicyBundle::validate`. The pusher trusts whatever `policy.toml`
//! it was launched against; if an operator points it at a different
//! file, the worst case is mis-tagged dashboards (no R-invariant
//! at risk).

use std::path::PathBuf;
use std::time::Duration;

use raxis_policy::{
    ObservabilityConfig, ObservabilityPusherConfig, ObservabilityResourceConfig,
    ObservabilityRingConfig,
};

/// Pusher-side runtime configuration. Cheap to clone (`Arc`-d once
/// at boot and shared into every async task).
#[derive(Debug, Clone)]
pub struct PusherConfig {
    /// Operator-supplied `<data_dir>`. The ring directory is
    /// `<data_dir>/observability` unless the policy overrides it
    /// via `[observability.ring].dir`.
    pub data_dir: PathBuf,
    /// Resolved ring root. `<data_dir>/observability` by default;
    /// or `[observability.ring].dir` when set.
    pub ring_root: PathBuf,
    /// Cursor file path: `<ring_root>/cursor.toml`.
    pub cursor_path: PathBuf,
    /// Lock file path: `<ring_root>/lock`.
    pub lock_path: PathBuf,
    /// Pusher events file: `<ring_root>/pusher-events.jsonl`. Used
    /// by the kernel heartbeat to surface pusher-side drops.
    pub events_path: PathBuf,
    /// Validated `[observability.pusher]` section.
    pub pusher: ObservabilityPusherConfig,
    /// Validated `[observability.ring]` section.
    pub ring: ObservabilityRingConfig,
    /// Validated `[observability.resource]` section.
    pub resource: ObservabilityResourceConfig,
    /// Optional `/healthz` listen port. `0` ⇒ disabled. Operator
    /// configures via `[observability.pusher].health_port`; default
    /// `9501` per spec §12.5.
    pub health_port: u16,
    /// Pusher's own kernel-version label, used as
    /// `InstrumentationScope.version` on every batch. Sourced from
    /// the kernel-written segment header line.
    pub kernel_version: String,
}

impl PusherConfig {
    /// Build a [`PusherConfig`] from the validated
    /// `[observability]` bundle plus a `<data_dir>` from the
    /// command line.
    pub fn build(
        observability: &ObservabilityConfig,
        data_dir: PathBuf,
        kernel_version: impl Into<String>,
        health_port: u16,
    ) -> Result<Self, ConfigError> {
        if !observability.enabled {
            return Err(ConfigError::ObservabilityDisabled);
        }
        let pusher = observability
            .pusher
            .clone()
            .ok_or(ConfigError::PusherMissing)?;

        let ring_root = if observability.ring.dir.is_empty() {
            data_dir.join("observability")
        } else {
            PathBuf::from(&observability.ring.dir)
        };
        let cursor_path = ring_root.join("cursor.toml");
        let lock_path = ring_root.join("lock");
        let events_path = ring_root.join("pusher-events.jsonl");

        Ok(Self {
            data_dir,
            ring_root,
            cursor_path,
            lock_path,
            events_path,
            pusher,
            ring: observability.ring.clone(),
            resource: observability.resource.clone(),
            health_port,
            kernel_version: kernel_version.into(),
        })
    }

    /// Per-stream segment directory: `<ring_root>/{spans,metrics}/`.
    pub fn segment_dir(&self, stream: raxis_observability::protocol::Stream) -> PathBuf {
        self.ring_root.join(stream.subdir())
    }

    /// Pusher-side flush interval.
    pub fn flush_interval(&self) -> Duration {
        self.pusher.otlp_flush_interval
    }

    /// Per-batch deadline.
    pub fn export_timeout(&self) -> Duration {
        self.pusher.otlp_export_timeout
    }

    /// Spans/metrics per batch.
    pub fn batch_size(&self) -> usize {
        self.pusher.otlp_batch_size
    }
}

/// Errors raised while building a [`PusherConfig`].
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// `[observability].enabled = false` in the policy bundle. The
    /// pusher exits cleanly when started against a disabled config
    /// — there is nothing to ship.
    #[error("observability disabled in policy.toml; pusher not needed")]
    ObservabilityDisabled,
    /// `[observability]` is enabled but `[observability.pusher]`
    /// is missing. Validation should have caught this; surfaces
    /// here as a defence-in-depth check.
    #[error("[observability.pusher] missing despite [observability].enabled = true")]
    PusherMissing,
}

#[cfg(test)]
mod tests {
    use super::*;
    use raxis_policy::{
        ObservabilityMetricsConfig, ObservabilityPusherTlsConfig, ObservabilityTracesConfig,
    };
    use std::collections::BTreeMap;

    fn enabled_obs(_data_dir: &std::path::Path) -> ObservabilityConfig {
        ObservabilityConfig {
            enabled: true,
            ring: ObservabilityRingConfig {
                dir: String::new(),
                segment_max_bytes: 16 * 1024 * 1024,
                max_total_bytes: 512 * 1024 * 1024,
                max_queue_depth: 8192,
            },
            traces: ObservabilityTracesConfig {
                enabled: true,
                sample_rate: 0.1,
                max_attrs_per_span: 32,
                max_events_per_span: 16,
            },
            metrics: ObservabilityMetricsConfig {
                enabled: true,
                export_interval: Duration::from_secs(15),
                histogram_buckets: vec![1.0, 5.0, 10.0],
            },
            resource: ObservabilityResourceConfig {
                service_name: "raxis-kernel".to_owned(),
                environment: String::new(),
                extra: BTreeMap::new(),
            },
            pusher: Some(ObservabilityPusherConfig {
                otlp_endpoint: "https://otlp.example.com:4318".to_owned(),
                otlp_protocol: "http".to_owned(),
                otlp_compression: "gzip".to_owned(),
                otlp_export_timeout: Duration::from_secs(10),
                otlp_batch_size: 512,
                otlp_flush_interval: Duration::from_secs(5),
                otlp_max_inflight: 4,
                backoff_initial: Duration::from_millis(500),
                backoff_max: Duration::from_secs(30),
                backoff_jitter: 0.25,
                tls: ObservabilityPusherTlsConfig::default(),
                headers: BTreeMap::new(),
            }),
        }
    }

    #[test]
    fn build_sets_default_ring_root() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = PusherConfig::build(
            &enabled_obs(dir.path()),
            dir.path().to_owned(),
            "0.1.0",
            9501,
        )
        .unwrap();
        assert_eq!(cfg.ring_root, dir.path().join("observability"));
        assert_eq!(
            cfg.cursor_path,
            dir.path().join("observability/cursor.toml")
        );
        assert_eq!(cfg.kernel_version, "0.1.0");
        assert_eq!(cfg.batch_size(), 512);
    }

    #[test]
    fn build_honours_explicit_ring_dir() {
        let dir = tempfile::tempdir().unwrap();
        let mut obs = enabled_obs(dir.path());
        obs.ring.dir = dir.path().join("alt").to_string_lossy().into_owned();
        let cfg = PusherConfig::build(&obs, dir.path().to_owned(), "0.1.0", 9501).unwrap();
        assert_eq!(cfg.ring_root, dir.path().join("alt"));
    }

    #[test]
    fn disabled_observability_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let mut obs = enabled_obs(dir.path());
        obs.enabled = false;
        let err = PusherConfig::build(&obs, dir.path().to_owned(), "0.1.0", 9501).unwrap_err();
        matches!(err, ConfigError::ObservabilityDisabled);
    }
}

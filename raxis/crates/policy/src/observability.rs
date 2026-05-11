//! `[observability]` policy section — validated mirror of the V3
//! OTel surface knobs.
//!
//! Spec: `specs/v3/otel-observability.md §5`.
//!
//! ## Layout
//!
//! Two layers of structure:
//!
//! 1. **Raw** ([`ObservabilitySection`] and friends) — TOML-mapped
//!    structs with `serde(default)`. Used inside `RawPolicy`.
//! 2. **Validated** ([`ObservabilityConfig`]) — the read-only
//!    runtime view exposed via `PolicyBundle::observability()`.
//!    Constructed by [`ObservabilityConfig::validate`] from the
//!    raw section. Validation is a pure function — no I/O — so the
//!    same code path covers `policy_manager::advance_epoch`.
//!
//! ## Failure-code conventions
//!
//! Every validation error returns a `FAIL_OBS_*` code matching the
//! spec table at §5.2. The codes are stable and consumed by
//! `raxis-cli policy validate` to render an operator-facing
//! diagnosis.

use std::collections::BTreeMap;
use std::time::Duration;

use serde::Deserialize;

use crate::PolicyError;

// ---------------------------------------------------------------------------
// Raw TOML-mapped structs
// ---------------------------------------------------------------------------

/// `[observability]` — top-level OTel section. Optional; when
/// absent the kernel runs with `enabled = false` and a no-op
/// exporter (which still costs essentially nothing per call).
#[derive(Debug, Clone, Deserialize, Default)]
pub(crate) struct ObservabilitySection {
    /// Master switch. Default `false`.
    #[serde(default)]
    pub(crate) enabled: bool,
    /// `[observability.ring]` knobs.
    #[serde(default)]
    pub(crate) ring: ObservabilityRingSection,
    /// `[observability.traces]` knobs.
    #[serde(default)]
    pub(crate) traces: ObservabilityTracesSection,
    /// `[observability.metrics]` knobs.
    #[serde(default)]
    pub(crate) metrics: ObservabilityMetricsSection,
    /// `[observability.resource]` knobs.
    #[serde(default)]
    pub(crate) resource: ObservabilityResourceSection,
    /// `[observability.pusher]` knobs.
    #[serde(default)]
    pub(crate) pusher: Option<ObservabilityPusherSection>,
}

/// `[observability.ring]`.
#[derive(Debug, Clone, Deserialize, Default)]
pub(crate) struct ObservabilityRingSection {
    /// Local kernel-owned spool directory; `""` ⇒ default
    /// `<data_dir>/observability`.
    #[serde(default)]
    pub(crate) dir: String,
    /// Maximum bytes per JSONL segment. Default 16 MiB; range
    /// [1 MiB, 256 MiB].
    #[serde(default)]
    pub(crate) segment_max_bytes: Option<u64>,
    /// Maximum cumulative bytes across all segments per stream.
    /// Default 512 MiB; range [16 MiB, 16 GiB]; MUST be ≥ 4 ×
    /// `segment_max_bytes`.
    #[serde(default)]
    pub(crate) max_total_bytes: Option<u64>,
    /// In-memory drop threshold. Default 8192; range [256, 1_048_576].
    #[serde(default)]
    pub(crate) max_queue_depth: Option<usize>,
}

/// `[observability.traces]`.
#[derive(Debug, Clone, Deserialize, Default)]
pub(crate) struct ObservabilityTracesSection {
    /// Whether trace emission is on. Default `true` when the parent
    /// section is enabled.
    #[serde(default)]
    pub(crate) enabled: Option<bool>,
    /// Head-based sampling rate. Range [0.0, 1.0]; default 0.1.
    #[serde(default)]
    pub(crate) sample_rate: Option<f64>,
    /// Per-span attribute cap; range [4, 128].
    #[serde(default)]
    pub(crate) max_attrs_per_span: Option<usize>,
    /// Per-span event cap; range [0, 64].
    #[serde(default)]
    pub(crate) max_events_per_span: Option<usize>,
}

/// `[observability.metrics]`.
#[derive(Debug, Clone, Deserialize, Default)]
pub(crate) struct ObservabilityMetricsSection {
    /// Whether metric emission is on. Default `true`.
    #[serde(default)]
    pub(crate) enabled: Option<bool>,
    /// Pusher export cadence; parsed as a duration string.
    /// Default `"15s"`; range [1s, 300s].
    #[serde(default)]
    pub(crate) export_interval: Option<String>,
    /// Histogram bucket boundaries (ms). Default per spec §5.1;
    /// must be non-empty, finite, strictly increasing, all > 0,
    /// length ≤ 64.
    #[serde(default)]
    pub(crate) histogram_buckets: Option<Vec<f64>>,
}

/// `[observability.resource]`.
#[derive(Debug, Clone, Deserialize, Default)]
pub(crate) struct ObservabilityResourceSection {
    /// `service.name` resource attribute. Required when the parent
    /// section is enabled.
    #[serde(default)]
    pub(crate) service_name: Option<String>,
    /// `deployment.environment` resource attribute.
    #[serde(default)]
    pub(crate) environment: Option<String>,
    /// `[observability.resource.extra]` — operator-declared
    /// resource attributes. Reserved-namespace check at validate
    /// time.
    #[serde(default)]
    pub(crate) extra: BTreeMap<String, String>,
}

/// `[observability.pusher]` — the pusher binary's runtime knobs.
/// The kernel does NOT consume these; the pusher reads them
/// independently. We validate here so the operator gets one
/// failure surface.
#[derive(Debug, Clone, Deserialize, Default)]
pub(crate) struct ObservabilityPusherSection {
    /// OTLP collector endpoint (`http://`/`https://`).
    #[serde(default)]
    pub(crate) otlp_endpoint: String,
    /// `"grpc"` or `"http"`.
    #[serde(default)]
    pub(crate) otlp_protocol: Option<String>,
    /// `"none"`, `"gzip"`, or `"zstd"`.
    #[serde(default)]
    pub(crate) otlp_compression: Option<String>,
    /// Per-batch deadline. Default `"10s"`; range [1s, 60s].
    #[serde(default)]
    pub(crate) otlp_export_timeout: Option<String>,
    /// Spans/metrics per batch. Range [1, 8192].
    #[serde(default)]
    pub(crate) otlp_batch_size: Option<usize>,
    /// Batch boundary cadence. Range [100ms, 60s].
    #[serde(default)]
    pub(crate) otlp_flush_interval: Option<String>,
    /// Concurrent in-flight batches. Range [1, 64].
    #[serde(default)]
    pub(crate) otlp_max_inflight: Option<usize>,
    /// Initial backoff. Range [10ms, 5min].
    #[serde(default)]
    pub(crate) backoff_initial: Option<String>,
    /// Maximum backoff. Range [10ms, 5min]; ≥ `backoff_initial`.
    #[serde(default)]
    pub(crate) backoff_max: Option<String>,
    /// Backoff jitter fraction. Range [0.0, 1.0].
    #[serde(default)]
    pub(crate) backoff_jitter: Option<f64>,
    /// `[observability.pusher.tls]`.
    #[serde(default)]
    pub(crate) tls: ObservabilityPusherTlsSection,
    /// `[observability.pusher.headers]` — static metadata key/values.
    #[serde(default)]
    pub(crate) headers: BTreeMap<String, String>,
}

/// `[observability.pusher.tls]`.
#[derive(Debug, Clone, Deserialize, Default)]
pub(crate) struct ObservabilityPusherTlsSection {
    /// Optional client cert path.
    #[serde(default)]
    pub(crate) cert_file: String,
    /// Optional client key path.
    #[serde(default)]
    pub(crate) key_file: String,
    /// Optional CA bundle path.
    #[serde(default)]
    pub(crate) ca_file: String,
}

// ---------------------------------------------------------------------------
// Validated, public-API config
// ---------------------------------------------------------------------------

/// Validated, runtime-shape `[observability]` configuration.
/// Returned by [`crate::PolicyBundle::observability`]; constructed
/// once at policy load and replaced on every `advance_epoch`.
#[derive(Debug, Clone)]
pub struct ObservabilityConfig {
    /// Master switch. When `false`, the rest of the struct still
    /// contains validated defaults — the kernel just wires up a
    /// no-op exporter and short-circuits emit sites.
    pub enabled: bool,

    /// Ring file storage knobs.
    pub ring: ObservabilityRingConfig,

    /// Trace emission knobs.
    pub traces: ObservabilityTracesConfig,

    /// Metric emission / export knobs.
    pub metrics: ObservabilityMetricsConfig,

    /// Resource attributes attached to every span/metric.
    pub resource: ObservabilityResourceConfig,

    /// Pusher binary configuration. `None` ⇒ operator omitted the
    /// `[observability.pusher]` section (only legal when
    /// `enabled = false`).
    pub pusher: Option<ObservabilityPusherConfig>,
}

/// Validated `[observability.ring]` knobs.
#[derive(Debug, Clone)]
pub struct ObservabilityRingConfig {
    /// Operator-supplied directory; empty string means "use default
    /// `<data_dir>/observability`".
    pub dir: String,
    /// Maximum bytes per segment.
    pub segment_max_bytes: u64,
    /// Maximum cumulative bytes per stream.
    pub max_total_bytes: u64,
    /// Bounded queue depth (in-memory drop threshold).
    pub max_queue_depth: usize,
}

/// Validated `[observability.traces]` knobs.
#[derive(Debug, Clone)]
pub struct ObservabilityTracesConfig {
    /// Whether trace emission is on.
    pub enabled: bool,
    /// Head-based sampling rate, in [0.0, 1.0].
    pub sample_rate: f64,
    /// Per-span attribute cap.
    pub max_attrs_per_span: usize,
    /// Per-span event cap.
    pub max_events_per_span: usize,
}

/// Validated `[observability.metrics]` knobs.
#[derive(Debug, Clone)]
pub struct ObservabilityMetricsConfig {
    /// Whether metric emission is on.
    pub enabled: bool,
    /// Pusher export cadence.
    pub export_interval: Duration,
    /// Histogram bucket boundaries (ms).
    pub histogram_buckets: Vec<f64>,
}

/// Validated `[observability.resource]` knobs.
#[derive(Debug, Clone)]
pub struct ObservabilityResourceConfig {
    /// `service.name` resource attribute.
    pub service_name: String,
    /// `deployment.environment` resource attribute (empty when
    /// omitted).
    pub environment: String,
    /// Operator-declared extra resource attributes; reserved
    /// namespaces already filtered out at validate time.
    pub extra: BTreeMap<String, String>,
}

/// Validated `[observability.pusher]` knobs.
#[derive(Debug, Clone)]
pub struct ObservabilityPusherConfig {
    /// OTLP endpoint.
    pub otlp_endpoint: String,
    /// `"grpc"` or `"http"`.
    pub otlp_protocol: String,
    /// `"none"`, `"gzip"`, `"zstd"`.
    pub otlp_compression: String,
    /// Per-batch deadline.
    pub otlp_export_timeout: Duration,
    /// Spans/metrics per batch.
    pub otlp_batch_size: usize,
    /// Batch boundary cadence.
    pub otlp_flush_interval: Duration,
    /// Concurrent in-flight batches.
    pub otlp_max_inflight: usize,
    /// Initial backoff.
    pub backoff_initial: Duration,
    /// Maximum backoff (≥ `backoff_initial`).
    pub backoff_max: Duration,
    /// Backoff jitter fraction.
    pub backoff_jitter: f64,
    /// TLS material.
    pub tls: ObservabilityPusherTlsConfig,
    /// Headers map (validated; values starting with `@cred:`
    /// reference a `[[permitted_credentials]]` entry).
    pub headers: BTreeMap<String, String>,
}

/// Validated `[observability.pusher.tls]` knobs.
#[derive(Debug, Clone, Default)]
pub struct ObservabilityPusherTlsConfig {
    /// Client cert path; empty when not used.
    pub cert_file: String,
    /// Client key path; empty when not used.
    pub key_file: String,
    /// CA bundle path; empty when not used.
    pub ca_file: String,
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

const MIN_SEGMENT_BYTES: u64 = 1 * 1024 * 1024;
const MAX_SEGMENT_BYTES: u64 = 256 * 1024 * 1024;
const MIN_TOTAL_BYTES:   u64 = 16 * 1024 * 1024;
const MAX_TOTAL_BYTES:   u64 = 16 * 1024 * 1024 * 1024;
const MIN_QUEUE_DEPTH:   usize = 256;
const MAX_QUEUE_DEPTH:   usize = 1_048_576;

const DEFAULT_SEGMENT_BYTES: u64 = 16 * 1024 * 1024;
const DEFAULT_TOTAL_BYTES:   u64 = 512 * 1024 * 1024;
const DEFAULT_QUEUE_DEPTH:   usize = 8192;

const MIN_ATTRS_PER_SPAN: usize = 4;
const MAX_ATTRS_PER_SPAN: usize = 128;
const MAX_EVENTS_PER_SPAN: usize = 64;

const DEFAULT_ATTRS_PER_SPAN: usize = 32;
const DEFAULT_EVENTS_PER_SPAN: usize = 16;
const DEFAULT_SAMPLE_RATE:    f64 = 0.1;

const MIN_EXPORT_INTERVAL_MS: u128 = 1_000;
const MAX_EXPORT_INTERVAL_MS: u128 = 300_000;
const DEFAULT_EXPORT_INTERVAL_MS: u128 = 15_000;

const MAX_BUCKETS_LEN: usize = 64;

const MAX_RESOURCE_VALUE_BYTES: usize = 256;
const MAX_RESOURCE_KEYS:          usize = 64;

const MIN_OTLP_BATCH_SIZE:    usize = 1;
const MAX_OTLP_BATCH_SIZE:    usize = 8192;
const DEFAULT_OTLP_BATCH_SIZE: usize = 512;

const MIN_OTLP_INFLIGHT:    usize = 1;
const MAX_OTLP_INFLIGHT:    usize = 64;
const DEFAULT_OTLP_INFLIGHT: usize = 4;

const MIN_FLUSH_INTERVAL_MS: u128 = 100;
const MAX_FLUSH_INTERVAL_MS: u128 = 60_000;
const DEFAULT_FLUSH_INTERVAL_MS: u128 = 5_000;

const MIN_EXPORT_TIMEOUT_MS: u128 = 1_000;
const MAX_EXPORT_TIMEOUT_MS: u128 = 60_000;
const DEFAULT_EXPORT_TIMEOUT_MS: u128 = 10_000;

const MIN_BACKOFF_MS:        u128 = 10;
const MAX_BACKOFF_MS:        u128 = 300_000;
const DEFAULT_BACKOFF_INIT_MS: u128 = 500;
const DEFAULT_BACKOFF_MAX_MS:  u128 = 30_000;
const DEFAULT_BACKOFF_JITTER:  f64  = 0.25;

/// Reserved OTel resource-attribute prefixes operators MUST NOT
/// override. The check is case-insensitive and matches the start of
/// the attribute key.
const RESERVED_RESOURCE_PREFIXES: &[&str] = &[
    "raxis.",
    "service.",
    "host.",
    "os.",
    "process.",
    "telemetry.sdk.",
];

/// HTTP/2 / OTLP headers that are reserved and MUST NOT be set by
/// the operator. Lower-case match.
const RESERVED_HEADER_KEYS: &[&str] = &[
    "user-agent", "content-type", "content-length",
    "te", "host", "transfer-encoding", "te-trailers",
    ":method", ":path", ":scheme", ":authority",
];

const DEFAULT_HISTOGRAM_BUCKETS: &[f64] = &[
    1.0, 5.0, 10.0, 25.0, 50.0, 100.0,
    250.0, 500.0, 1000.0, 2500.0, 5000.0, 10000.0,
];

impl ObservabilityConfig {
    /// Validate a raw section into a runtime config, returning a
    /// `FAIL_OBS_*`-coded `PolicyError::MalformedArtifact` on the
    /// first violation. `permitted_credential_names` is the set of
    /// declared `[[permitted_credentials]] name` strings — used to
    /// resolve `@cred:<name>` header references.
    pub(crate) fn validate(
        raw: &ObservabilitySection,
        permitted_credential_names: &std::collections::HashSet<&str>,
    ) -> Result<Self, PolicyError> {
        let ring     = validate_ring(&raw.ring)?;
        let traces   = validate_traces(&raw.traces)?;
        let metrics  = validate_metrics(&raw.metrics)?;
        let resource = validate_resource(&raw.resource, raw.enabled)?;

        let pusher = match (raw.enabled, raw.pusher.as_ref()) {
            (true,  None) => return Err(fail("FAIL_OBS_PUSHER_REQUIRED",
                "[observability] enabled = true but [observability.pusher] is missing".to_owned())),
            (true,  Some(p)) => Some(validate_pusher(p, permitted_credential_names)?),
            (false, Some(p)) => Some(validate_pusher(p, permitted_credential_names)?),
            (false, None)    => None,
        };

        Ok(Self { enabled: raw.enabled, ring, traces, metrics, resource, pusher })
    }

    /// Default disabled config. Used by the kernel binary when the
    /// `[observability]` section is omitted entirely.
    pub fn disabled_default() -> Self {
        Self {
            enabled:  false,
            ring:     ObservabilityRingConfig {
                dir:               String::new(),
                segment_max_bytes: DEFAULT_SEGMENT_BYTES,
                max_total_bytes:   DEFAULT_TOTAL_BYTES,
                max_queue_depth:   DEFAULT_QUEUE_DEPTH,
            },
            traces:   ObservabilityTracesConfig {
                enabled:             true,
                sample_rate:         DEFAULT_SAMPLE_RATE,
                max_attrs_per_span:  DEFAULT_ATTRS_PER_SPAN,
                max_events_per_span: DEFAULT_EVENTS_PER_SPAN,
            },
            metrics:  ObservabilityMetricsConfig {
                enabled:           true,
                export_interval:   Duration::from_millis(DEFAULT_EXPORT_INTERVAL_MS as u64),
                histogram_buckets: DEFAULT_HISTOGRAM_BUCKETS.to_vec(),
            },
            resource: ObservabilityResourceConfig {
                service_name: "raxis-kernel".to_owned(),
                environment:  String::new(),
                extra:        BTreeMap::new(),
            },
            pusher:   None,
        }
    }
}

// ---------------------------------------------------------------------------
// Section validators
// ---------------------------------------------------------------------------

fn validate_ring(s: &ObservabilityRingSection) -> Result<ObservabilityRingConfig, PolicyError> {
    let segment_max_bytes = s.segment_max_bytes.unwrap_or(DEFAULT_SEGMENT_BYTES);
    if !(MIN_SEGMENT_BYTES..=MAX_SEGMENT_BYTES).contains(&segment_max_bytes) {
        return Err(fail("FAIL_OBS_RING_SEGMENT_SIZE", format!(
            "[observability.ring] segment_max_bytes ({segment_max_bytes}) must be in \
             [{MIN_SEGMENT_BYTES}, {MAX_SEGMENT_BYTES}] bytes"
        )));
    }
    let max_total_bytes = s.max_total_bytes.unwrap_or(DEFAULT_TOTAL_BYTES);
    if !(MIN_TOTAL_BYTES..=MAX_TOTAL_BYTES).contains(&max_total_bytes) {
        return Err(fail("FAIL_OBS_RING_TOTAL_SIZE", format!(
            "[observability.ring] max_total_bytes ({max_total_bytes}) must be in \
             [{MIN_TOTAL_BYTES}, {MAX_TOTAL_BYTES}] bytes"
        )));
    }
    if max_total_bytes < segment_max_bytes.saturating_mul(4) {
        return Err(fail("FAIL_OBS_RING_TOTAL_TOO_SMALL", format!(
            "[observability.ring] max_total_bytes ({max_total_bytes}) must be >= \
             4 × segment_max_bytes ({})", segment_max_bytes * 4
        )));
    }
    let max_queue_depth = s.max_queue_depth.unwrap_or(DEFAULT_QUEUE_DEPTH);
    if !(MIN_QUEUE_DEPTH..=MAX_QUEUE_DEPTH).contains(&max_queue_depth) {
        return Err(fail("FAIL_OBS_RING_QUEUE_DEPTH", format!(
            "[observability.ring] max_queue_depth ({max_queue_depth}) must be in \
             [{MIN_QUEUE_DEPTH}, {MAX_QUEUE_DEPTH}]"
        )));
    }
    Ok(ObservabilityRingConfig {
        dir: s.dir.clone(),
        segment_max_bytes,
        max_total_bytes,
        max_queue_depth,
    })
}

fn validate_traces(s: &ObservabilityTracesSection) -> Result<ObservabilityTracesConfig, PolicyError> {
    let sample_rate = s.sample_rate.unwrap_or(DEFAULT_SAMPLE_RATE);
    if !(0.0..=1.0).contains(&sample_rate) || !sample_rate.is_finite() {
        return Err(fail("FAIL_OBS_TRACES_SAMPLE_RATE", format!(
            "[observability.traces] sample_rate ({sample_rate}) must be in [0.0, 1.0]"
        )));
    }
    let max_attrs_per_span = s.max_attrs_per_span.unwrap_or(DEFAULT_ATTRS_PER_SPAN);
    if !(MIN_ATTRS_PER_SPAN..=MAX_ATTRS_PER_SPAN).contains(&max_attrs_per_span) {
        return Err(fail("FAIL_OBS_TRACES_LIMITS", format!(
            "[observability.traces] max_attrs_per_span ({max_attrs_per_span}) must be in \
             [{MIN_ATTRS_PER_SPAN}, {MAX_ATTRS_PER_SPAN}]"
        )));
    }
    let max_events_per_span = s.max_events_per_span.unwrap_or(DEFAULT_EVENTS_PER_SPAN);
    if max_events_per_span > MAX_EVENTS_PER_SPAN {
        return Err(fail("FAIL_OBS_TRACES_LIMITS", format!(
            "[observability.traces] max_events_per_span ({max_events_per_span}) must be in \
             [0, {MAX_EVENTS_PER_SPAN}]"
        )));
    }
    Ok(ObservabilityTracesConfig {
        enabled: s.enabled.unwrap_or(true),
        sample_rate,
        max_attrs_per_span,
        max_events_per_span,
    })
}

fn validate_metrics(s: &ObservabilityMetricsSection) -> Result<ObservabilityMetricsConfig, PolicyError> {
    let export_interval = match s.export_interval.as_deref() {
        Some(spec) => parse_duration_in_range(spec, MIN_EXPORT_INTERVAL_MS, MAX_EXPORT_INTERVAL_MS)
            .map_err(|reason| fail("FAIL_OBS_METRICS_INTERVAL", format!(
                "[observability.metrics] export_interval = {spec:?} {reason}"
            )))?,
        None => Duration::from_millis(DEFAULT_EXPORT_INTERVAL_MS as u64),
    };
    let histogram_buckets = match &s.histogram_buckets {
        Some(b) => b.clone(),
        None    => DEFAULT_HISTOGRAM_BUCKETS.to_vec(),
    };
    if histogram_buckets.is_empty() {
        return Err(fail("FAIL_OBS_METRICS_BUCKETS",
            "[observability.metrics] histogram_buckets must not be empty".to_owned()));
    }
    if histogram_buckets.len() > MAX_BUCKETS_LEN {
        return Err(fail("FAIL_OBS_METRICS_BUCKETS", format!(
            "[observability.metrics] histogram_buckets has {} entries; max {MAX_BUCKETS_LEN}",
            histogram_buckets.len()
        )));
    }
    let mut prev = 0.0_f64;
    for (i, b) in histogram_buckets.iter().enumerate() {
        if !b.is_finite() || *b <= 0.0 {
            return Err(fail("FAIL_OBS_METRICS_BUCKETS", format!(
                "[observability.metrics] histogram_buckets[{i}] = {b}: must be positive and finite"
            )));
        }
        if i > 0 && *b <= prev {
            return Err(fail("FAIL_OBS_METRICS_BUCKETS", format!(
                "[observability.metrics] histogram_buckets[{i}] = {b}: must be strictly increasing (prev = {prev})"
            )));
        }
        prev = *b;
    }
    Ok(ObservabilityMetricsConfig {
        enabled: s.enabled.unwrap_or(true),
        export_interval,
        histogram_buckets,
    })
}

fn validate_resource(
    s: &ObservabilityResourceSection,
    enabled: bool,
) -> Result<ObservabilityResourceConfig, PolicyError> {
    let service_name = match s.service_name.as_deref() {
        Some(v) if !v.trim().is_empty() => v.trim().to_owned(),
        _ if !enabled => "raxis-kernel".to_owned(),
        _ => return Err(fail("FAIL_OBS_RESOURCE_SERVICE_NAME",
            "[observability.resource] service_name must be a non-empty string".to_owned())),
    };
    let environment = s.environment.clone().unwrap_or_default();
    if s.extra.len() > MAX_RESOURCE_KEYS {
        return Err(fail("FAIL_OBS_RESOURCE_KEY_FORMAT", format!(
            "[observability.resource.extra] has {} keys; max {MAX_RESOURCE_KEYS}", s.extra.len()
        )));
    }
    for (key, val) in &s.extra {
        validate_resource_key(key)?;
        validate_resource_value(key, val)?;
    }
    Ok(ObservabilityResourceConfig { service_name, environment, extra: s.extra.clone() })
}

fn validate_resource_key(key: &str) -> Result<(), PolicyError> {
    if key.is_empty() {
        return Err(fail("FAIL_OBS_RESOURCE_KEY_FORMAT",
            "[observability.resource.extra] key must be non-empty".to_owned()));
    }
    if key.len() > 64 {
        return Err(fail("FAIL_OBS_RESOURCE_KEY_FORMAT", format!(
            "[observability.resource.extra] key {key:?} exceeds 64 bytes"
        )));
    }
    let lower = key.to_ascii_lowercase();
    for prefix in RESERVED_RESOURCE_PREFIXES {
        if lower.starts_with(prefix) {
            return Err(fail("FAIL_OBS_RESOURCE_RESERVED", format!(
                "[observability.resource.extra] key {key:?} starts with reserved prefix {prefix:?}"
            )));
        }
    }
    let mut chars = key.chars();
    let first = chars.next().ok_or_else(|| fail("FAIL_OBS_RESOURCE_KEY_FORMAT",
        "[observability.resource.extra] empty key".to_owned()))?;
    if !first.is_ascii_lowercase() {
        return Err(fail("FAIL_OBS_RESOURCE_KEY_FORMAT", format!(
            "[observability.resource.extra] key {key:?}: first char must match [a-z]"
        )));
    }
    for c in chars {
        if !(c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-') {
            return Err(fail("FAIL_OBS_RESOURCE_KEY_FORMAT", format!(
                "[observability.resource.extra] key {key:?} contains illegal char {c:?}; \
                 allowed: [a-z0-9_-]"
            )));
        }
    }
    Ok(())
}

fn validate_resource_value(key: &str, value: &str) -> Result<(), PolicyError> {
    if value.is_empty() {
        return Err(fail("FAIL_OBS_RESOURCE_VALUE", format!(
            "[observability.resource.extra.{key}] must be a non-empty UTF-8 string"
        )));
    }
    if value.len() > MAX_RESOURCE_VALUE_BYTES {
        return Err(fail("FAIL_OBS_RESOURCE_VALUE", format!(
            "[observability.resource.extra.{key}] exceeds {MAX_RESOURCE_VALUE_BYTES} bytes \
             (got {} bytes)", value.len()
        )));
    }
    Ok(())
}

fn validate_pusher(
    p: &ObservabilityPusherSection,
    permitted_credentials: &std::collections::HashSet<&str>,
) -> Result<ObservabilityPusherConfig, PolicyError> {
    let endpoint = p.otlp_endpoint.trim();
    if endpoint.is_empty() {
        return Err(fail("FAIL_OBS_OTLP_ENDPOINT",
            "[observability.pusher] otlp_endpoint must be a non-empty URL".to_owned()));
    }
    if !(endpoint.starts_with("http://") || endpoint.starts_with("https://")) {
        return Err(fail("FAIL_OBS_OTLP_ENDPOINT", format!(
            "[observability.pusher] otlp_endpoint = {endpoint:?} must start with http:// or https://"
        )));
    }
    let otlp_protocol = match p.otlp_protocol.as_deref().unwrap_or("grpc") {
        "grpc" => "grpc".to_owned(),
        "http" => "http".to_owned(),
        other  => return Err(fail("FAIL_OBS_OTLP_PROTOCOL", format!(
            "[observability.pusher] otlp_protocol = {other:?} must be one of {{\"grpc\", \"http\"}}"
        ))),
    };
    let otlp_compression = match p.otlp_compression.as_deref().unwrap_or("gzip") {
        "none" => "none".to_owned(),
        "gzip" => "gzip".to_owned(),
        "zstd" => "zstd".to_owned(),
        other  => return Err(fail("FAIL_OBS_OTLP_COMPRESSION", format!(
            "[observability.pusher] otlp_compression = {other:?} must be one of {{\"none\", \"gzip\", \"zstd\"}}"
        ))),
    };
    let otlp_export_timeout = match p.otlp_export_timeout.as_deref() {
        Some(spec) => parse_duration_in_range(spec, MIN_EXPORT_TIMEOUT_MS, MAX_EXPORT_TIMEOUT_MS)
            .map_err(|reason| fail("FAIL_OBS_OTLP_EXPORT_TIMEOUT", format!(
                "[observability.pusher] otlp_export_timeout = {spec:?} {reason}"
            )))?,
        None => Duration::from_millis(DEFAULT_EXPORT_TIMEOUT_MS as u64),
    };
    let otlp_batch_size = p.otlp_batch_size.unwrap_or(DEFAULT_OTLP_BATCH_SIZE);
    if !(MIN_OTLP_BATCH_SIZE..=MAX_OTLP_BATCH_SIZE).contains(&otlp_batch_size) {
        return Err(fail("FAIL_OBS_OTLP_BATCH_SIZE", format!(
            "[observability.pusher] otlp_batch_size ({otlp_batch_size}) must be in \
             [{MIN_OTLP_BATCH_SIZE}, {MAX_OTLP_BATCH_SIZE}]"
        )));
    }
    let otlp_flush_interval = match p.otlp_flush_interval.as_deref() {
        Some(spec) => parse_duration_in_range(spec, MIN_FLUSH_INTERVAL_MS, MAX_FLUSH_INTERVAL_MS)
            .map_err(|reason| fail("FAIL_OBS_OTLP_FLUSH_INTERVAL", format!(
                "[observability.pusher] otlp_flush_interval = {spec:?} {reason}"
            )))?,
        None => Duration::from_millis(DEFAULT_FLUSH_INTERVAL_MS as u64),
    };
    let otlp_max_inflight = p.otlp_max_inflight.unwrap_or(DEFAULT_OTLP_INFLIGHT);
    if !(MIN_OTLP_INFLIGHT..=MAX_OTLP_INFLIGHT).contains(&otlp_max_inflight) {
        return Err(fail("FAIL_OBS_OTLP_INFLIGHT", format!(
            "[observability.pusher] otlp_max_inflight ({otlp_max_inflight}) must be in \
             [{MIN_OTLP_INFLIGHT}, {MAX_OTLP_INFLIGHT}]"
        )));
    }
    let backoff_initial = match p.backoff_initial.as_deref() {
        Some(spec) => parse_duration_in_range(spec, MIN_BACKOFF_MS, MAX_BACKOFF_MS)
            .map_err(|reason| fail("FAIL_OBS_BACKOFF", format!(
                "[observability.pusher] backoff_initial = {spec:?} {reason}"
            )))?,
        None => Duration::from_millis(DEFAULT_BACKOFF_INIT_MS as u64),
    };
    let backoff_max = match p.backoff_max.as_deref() {
        Some(spec) => parse_duration_in_range(spec, MIN_BACKOFF_MS, MAX_BACKOFF_MS)
            .map_err(|reason| fail("FAIL_OBS_BACKOFF", format!(
                "[observability.pusher] backoff_max = {spec:?} {reason}"
            )))?,
        None => Duration::from_millis(DEFAULT_BACKOFF_MAX_MS as u64),
    };
    if backoff_initial > backoff_max {
        return Err(fail("FAIL_OBS_BACKOFF", format!(
            "[observability.pusher] backoff_initial ({backoff_initial:?}) > \
             backoff_max ({backoff_max:?})"
        )));
    }
    let backoff_jitter = p.backoff_jitter.unwrap_or(DEFAULT_BACKOFF_JITTER);
    if !(0.0..=1.0).contains(&backoff_jitter) || !backoff_jitter.is_finite() {
        return Err(fail("FAIL_OBS_JITTER", format!(
            "[observability.pusher] backoff_jitter ({backoff_jitter}) must be in [0.0, 1.0]"
        )));
    }
    // TLS: cert and key go together.
    let cert_set = !p.tls.cert_file.trim().is_empty();
    let key_set  = !p.tls.key_file.trim().is_empty();
    if cert_set != key_set {
        return Err(fail("FAIL_OBS_TLS_PARTIAL",
            "[observability.pusher.tls] cert_file and key_file must be both set or both empty".to_owned()));
    }
    let tls = ObservabilityPusherTlsConfig {
        cert_file: p.tls.cert_file.trim().to_owned(),
        key_file:  p.tls.key_file.trim().to_owned(),
        ca_file:   p.tls.ca_file.trim().to_owned(),
    };
    // Headers.
    for (k, v) in &p.headers {
        validate_header_key(k)?;
        validate_header_value(k, v, permitted_credentials)?;
    }
    Ok(ObservabilityPusherConfig {
        otlp_endpoint: endpoint.to_owned(),
        otlp_protocol,
        otlp_compression,
        otlp_export_timeout,
        otlp_batch_size,
        otlp_flush_interval,
        otlp_max_inflight,
        backoff_initial,
        backoff_max,
        backoff_jitter,
        tls,
        headers: p.headers.clone(),
    })
}

fn validate_header_key(key: &str) -> Result<(), PolicyError> {
    if key.is_empty() {
        return Err(fail("FAIL_OBS_HEADER_KEY",
            "[observability.pusher.headers] key must be non-empty".to_owned()));
    }
    if key.len() > 64 {
        return Err(fail("FAIL_OBS_HEADER_KEY", format!(
            "[observability.pusher.headers] key {key:?} exceeds 64 bytes"
        )));
    }
    let lower = key.to_ascii_lowercase();
    if RESERVED_HEADER_KEYS.contains(&lower.as_str()) {
        return Err(fail("FAIL_OBS_HEADER_KEY", format!(
            "[observability.pusher.headers] key {key:?} is reserved (HTTP/2 / OTLP framing)"
        )));
    }
    for c in key.chars() {
        if !(c.is_ascii_alphanumeric() || c == '_' || c == '-') {
            return Err(fail("FAIL_OBS_HEADER_KEY", format!(
                "[observability.pusher.headers] key {key:?} contains illegal char {c:?}; \
                 allowed: [a-zA-Z0-9_-]"
            )));
        }
    }
    Ok(())
}

fn validate_header_value(
    key:                   &str,
    value:                 &str,
    permitted_credentials: &std::collections::HashSet<&str>,
) -> Result<(), PolicyError> {
    if let Some(cred_name) = value.strip_prefix("@cred:") {
        let cred = cred_name.trim();
        if cred.is_empty() {
            return Err(fail("FAIL_OBS_HEADER_VALUE", format!(
                "[observability.pusher.headers.{key}] @cred: prefix must be followed by a credential name"
            )));
        }
        if !permitted_credentials.contains(cred) {
            return Err(fail("FAIL_OBS_HEADER_CRED_UNKNOWN", format!(
                "[observability.pusher.headers.{key}] references @cred:{cred} which is not declared in [[permitted_credentials]]"
            )));
        }
        return Ok(());
    }
    if value.is_empty() {
        return Err(fail("FAIL_OBS_HEADER_VALUE", format!(
            "[observability.pusher.headers.{key}] must be non-empty"
        )));
    }
    if value.len() > 256 {
        return Err(fail("FAIL_OBS_HEADER_VALUE", format!(
            "[observability.pusher.headers.{key}] exceeds 256 bytes (got {} bytes)", value.len()
        )));
    }
    if value.contains('\r') || value.contains('\n') {
        return Err(fail("FAIL_OBS_HEADER_VALUE", format!(
            "[observability.pusher.headers.{key}] contains illegal CR/LF (header injection guard)"
        )));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Parse a duration string like "15s", "500ms", "1m". Accepts
/// suffixes `ms`, `s`, `m`. The result must lie within
/// `[min_ms, max_ms]`.
fn parse_duration_in_range(
    spec:    &str,
    min_ms:  u128,
    max_ms:  u128,
) -> Result<Duration, String> {
    let spec = spec.trim();
    let (n_str, mult_ms): (&str, u128) =
        if let Some(rest) = spec.strip_suffix("ms") { (rest.trim(), 1) }
        else if let Some(rest) = spec.strip_suffix('s')  { (rest.trim(), 1_000) }
        else if let Some(rest) = spec.strip_suffix('m')  { (rest.trim(), 60_000) }
        else { return Err("must end in `ms`, `s`, or `m` (e.g. \"500ms\", \"15s\", \"5m\")".to_owned()); };
    let n: u64 = n_str.parse().map_err(|_| format!("could not parse {n_str:?} as a non-negative integer"))?;
    let total_ms = (n as u128).saturating_mul(mult_ms);
    if total_ms < min_ms || total_ms > max_ms {
        return Err(format!("must be in [{min_ms} ms, {max_ms} ms]; got {total_ms} ms"));
    }
    Ok(Duration::from_millis(total_ms.min(u64::MAX as u128) as u64))
}

fn fail(code: &'static str, message: String) -> PolicyError {
    PolicyError::MalformedArtifact(format!("{code}: {message}"))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    fn empty_creds() -> HashSet<&'static str> { HashSet::new() }

    fn full_section() -> ObservabilitySection {
        ObservabilitySection {
            enabled: true,
            ring: ObservabilityRingSection {
                dir: "".to_owned(),
                segment_max_bytes: Some(16 * 1024 * 1024),
                max_total_bytes:   Some(512 * 1024 * 1024),
                max_queue_depth:   Some(8192),
            },
            traces: ObservabilityTracesSection {
                enabled: Some(true),
                sample_rate: Some(0.1),
                max_attrs_per_span: Some(32),
                max_events_per_span: Some(16),
            },
            metrics: ObservabilityMetricsSection {
                enabled: Some(true),
                export_interval: Some("15s".to_owned()),
                histogram_buckets: Some(vec![1.0, 5.0, 10.0]),
            },
            resource: ObservabilityResourceSection {
                service_name: Some("raxis-kernel".to_owned()),
                environment:  Some("production".to_owned()),
                extra: BTreeMap::new(),
            },
            pusher: Some(ObservabilityPusherSection {
                otlp_endpoint: "https://otlp.example.com:4317".to_owned(),
                otlp_protocol: Some("grpc".to_owned()),
                otlp_compression: Some("gzip".to_owned()),
                otlp_export_timeout: Some("10s".to_owned()),
                otlp_batch_size: Some(512),
                otlp_flush_interval: Some("5s".to_owned()),
                otlp_max_inflight: Some(4),
                backoff_initial: Some("500ms".to_owned()),
                backoff_max: Some("30s".to_owned()),
                backoff_jitter: Some(0.25),
                tls: ObservabilityPusherTlsSection::default(),
                headers: BTreeMap::new(),
            }),
        }
    }

    #[test]
    fn disabled_default_passes_validation() {
        let cfg = ObservabilityConfig::disabled_default();
        assert!(!cfg.enabled);
        assert!(cfg.pusher.is_none());
    }

    #[test]
    fn full_section_round_trips() {
        let raw = full_section();
        let cfg = ObservabilityConfig::validate(&raw, &empty_creds()).expect("valid");
        assert!(cfg.enabled);
        assert_eq!(cfg.ring.segment_max_bytes, 16 * 1024 * 1024);
        assert_eq!(cfg.metrics.export_interval, Duration::from_secs(15));
        assert_eq!(cfg.metrics.histogram_buckets.len(), 3);
        let p = cfg.pusher.expect("pusher");
        assert_eq!(p.otlp_protocol, "grpc");
        assert_eq!(p.otlp_compression, "gzip");
        assert_eq!(p.backoff_initial, Duration::from_millis(500));
        assert_eq!(p.backoff_max, Duration::from_secs(30));
    }

    #[test]
    fn enabled_without_pusher_fails() {
        let mut raw = full_section();
        raw.pusher = None;
        let err = ObservabilityConfig::validate(&raw, &empty_creds()).unwrap_err();
        assert!(matches!(err, PolicyError::MalformedArtifact(s) if s.contains("FAIL_OBS_PUSHER_REQUIRED")),
            "expected FAIL_OBS_PUSHER_REQUIRED");
    }

    #[test]
    fn ring_segment_size_out_of_range() {
        let mut raw = full_section();
        raw.ring.segment_max_bytes = Some(512); // < 1 MiB
        let err = ObservabilityConfig::validate(&raw, &empty_creds()).unwrap_err();
        assert!(matches!(err, PolicyError::MalformedArtifact(s) if s.contains("FAIL_OBS_RING_SEGMENT_SIZE")));
    }

    #[test]
    fn ring_total_lt_4x_segment_fails() {
        let mut raw = full_section();
        raw.ring.segment_max_bytes = Some(64 * 1024 * 1024);
        raw.ring.max_total_bytes   = Some(64 * 1024 * 1024);   // = 1 × segment
        let err = ObservabilityConfig::validate(&raw, &empty_creds()).unwrap_err();
        assert!(matches!(err, PolicyError::MalformedArtifact(s) if s.contains("FAIL_OBS_RING_TOTAL_TOO_SMALL")));
    }

    #[test]
    fn traces_sample_rate_out_of_range() {
        let mut raw = full_section();
        raw.traces.sample_rate = Some(1.5);
        let err = ObservabilityConfig::validate(&raw, &empty_creds()).unwrap_err();
        assert!(matches!(err, PolicyError::MalformedArtifact(s) if s.contains("FAIL_OBS_TRACES_SAMPLE_RATE")));
    }

    #[test]
    fn traces_attr_cap_out_of_range() {
        let mut raw = full_section();
        raw.traces.max_attrs_per_span = Some(2);
        let err = ObservabilityConfig::validate(&raw, &empty_creds()).unwrap_err();
        assert!(matches!(err, PolicyError::MalformedArtifact(s) if s.contains("FAIL_OBS_TRACES_LIMITS")));
    }

    #[test]
    fn metrics_buckets_must_be_strictly_increasing() {
        let mut raw = full_section();
        raw.metrics.histogram_buckets = Some(vec![1.0, 5.0, 5.0, 10.0]);
        let err = ObservabilityConfig::validate(&raw, &empty_creds()).unwrap_err();
        assert!(matches!(err, PolicyError::MalformedArtifact(s) if s.contains("FAIL_OBS_METRICS_BUCKETS")));
    }

    #[test]
    fn metrics_buckets_must_be_positive_finite() {
        let mut raw = full_section();
        raw.metrics.histogram_buckets = Some(vec![1.0, f64::NAN]);
        let err = ObservabilityConfig::validate(&raw, &empty_creds()).unwrap_err();
        assert!(matches!(err, PolicyError::MalformedArtifact(s) if s.contains("FAIL_OBS_METRICS_BUCKETS")));
    }

    #[test]
    fn resource_extra_reserved_prefix_fails() {
        let mut raw = full_section();
        raw.resource.extra.insert("raxis.thing".to_owned(), "v".to_owned());
        let err = ObservabilityConfig::validate(&raw, &empty_creds()).unwrap_err();
        assert!(matches!(err, PolicyError::MalformedArtifact(s) if s.contains("FAIL_OBS_RESOURCE_RESERVED")));
    }

    #[test]
    fn resource_extra_bad_key_format_fails() {
        let mut raw = full_section();
        raw.resource.extra.insert("Bad-Key!".to_owned(), "v".to_owned());
        let err = ObservabilityConfig::validate(&raw, &empty_creds()).unwrap_err();
        assert!(matches!(err, PolicyError::MalformedArtifact(s) if s.contains("FAIL_OBS_RESOURCE_KEY_FORMAT")));
    }

    #[test]
    fn resource_extra_oversize_value_fails() {
        let mut raw = full_section();
        raw.resource.extra.insert("k".to_owned(), "x".repeat(257));
        let err = ObservabilityConfig::validate(&raw, &empty_creds()).unwrap_err();
        assert!(matches!(err, PolicyError::MalformedArtifact(s) if s.contains("FAIL_OBS_RESOURCE_VALUE")));
    }

    #[test]
    fn pusher_endpoint_must_be_url() {
        let mut raw = full_section();
        raw.pusher.as_mut().unwrap().otlp_endpoint = "not-a-url".to_owned();
        let err = ObservabilityConfig::validate(&raw, &empty_creds()).unwrap_err();
        assert!(matches!(err, PolicyError::MalformedArtifact(s) if s.contains("FAIL_OBS_OTLP_ENDPOINT")));
    }

    #[test]
    fn pusher_protocol_must_be_known() {
        let mut raw = full_section();
        raw.pusher.as_mut().unwrap().otlp_protocol = Some("ftp".to_owned());
        let err = ObservabilityConfig::validate(&raw, &empty_creds()).unwrap_err();
        assert!(matches!(err, PolicyError::MalformedArtifact(s) if s.contains("FAIL_OBS_OTLP_PROTOCOL")));
    }

    #[test]
    fn pusher_compression_must_be_known() {
        let mut raw = full_section();
        raw.pusher.as_mut().unwrap().otlp_compression = Some("brotli".to_owned());
        let err = ObservabilityConfig::validate(&raw, &empty_creds()).unwrap_err();
        assert!(matches!(err, PolicyError::MalformedArtifact(s) if s.contains("FAIL_OBS_OTLP_COMPRESSION")));
    }

    #[test]
    fn pusher_backoff_initial_must_be_le_max() {
        let mut raw = full_section();
        raw.pusher.as_mut().unwrap().backoff_initial = Some("60s".to_owned());
        raw.pusher.as_mut().unwrap().backoff_max     = Some("30s".to_owned());
        let err = ObservabilityConfig::validate(&raw, &empty_creds()).unwrap_err();
        assert!(matches!(err, PolicyError::MalformedArtifact(s) if s.contains("FAIL_OBS_BACKOFF")));
    }

    #[test]
    fn pusher_tls_partial_fails() {
        let mut raw = full_section();
        raw.pusher.as_mut().unwrap().tls = ObservabilityPusherTlsSection {
            cert_file: "/etc/ssl/cert.pem".to_owned(),
            key_file:  "".to_owned(),
            ca_file:   "".to_owned(),
        };
        let err = ObservabilityConfig::validate(&raw, &empty_creds()).unwrap_err();
        assert!(matches!(err, PolicyError::MalformedArtifact(s) if s.contains("FAIL_OBS_TLS_PARTIAL")));
    }

    #[test]
    fn pusher_headers_unknown_credential_fails() {
        let mut raw = full_section();
        raw.pusher.as_mut().unwrap().headers
            .insert("authorization".to_owned(), "@cred:nonexistent".to_owned());
        let err = ObservabilityConfig::validate(&raw, &empty_creds()).unwrap_err();
        assert!(matches!(err, PolicyError::MalformedArtifact(s) if s.contains("FAIL_OBS_HEADER_CRED_UNKNOWN")));
    }

    #[test]
    fn pusher_headers_known_credential_passes() {
        let mut raw = full_section();
        raw.pusher.as_mut().unwrap().headers
            .insert("authorization".to_owned(), "@cred:datadog-otel-token".to_owned());
        let mut creds = HashSet::new();
        creds.insert("datadog-otel-token");
        ObservabilityConfig::validate(&raw, &creds).expect("valid");
    }

    #[test]
    fn pusher_headers_reserved_key_fails() {
        let mut raw = full_section();
        raw.pusher.as_mut().unwrap().headers
            .insert("Content-Type".to_owned(), "application/json".to_owned());
        let err = ObservabilityConfig::validate(&raw, &empty_creds()).unwrap_err();
        assert!(matches!(err, PolicyError::MalformedArtifact(s) if s.contains("FAIL_OBS_HEADER_KEY")));
    }

    #[test]
    fn pusher_headers_crlf_value_fails() {
        let mut raw = full_section();
        raw.pusher.as_mut().unwrap().headers
            .insert("x-tenant-id".to_owned(), "platform\r\nX-Injected: 1".to_owned());
        let err = ObservabilityConfig::validate(&raw, &empty_creds()).unwrap_err();
        assert!(matches!(err, PolicyError::MalformedArtifact(s) if s.contains("FAIL_OBS_HEADER_VALUE")));
    }

    #[test]
    fn parse_duration_understands_ms_s_m() {
        assert_eq!(
            parse_duration_in_range("250ms", 100, 60_000).unwrap(),
            Duration::from_millis(250),
        );
        assert_eq!(
            parse_duration_in_range("5s", 1_000, 300_000).unwrap(),
            Duration::from_secs(5),
        );
        assert_eq!(
            parse_duration_in_range("2m", 1_000, 300_000).unwrap(),
            Duration::from_secs(120),
        );
    }

    #[test]
    fn parse_duration_rejects_bad_suffix() {
        let err = parse_duration_in_range("5h", 1_000, 300_000).unwrap_err();
        assert!(err.contains("must end in"));
    }

    #[test]
    fn metrics_export_interval_out_of_range() {
        let mut raw = full_section();
        raw.metrics.export_interval = Some("500ms".to_owned()); // < 1s floor
        let err = ObservabilityConfig::validate(&raw, &empty_creds()).unwrap_err();
        assert!(matches!(err, PolicyError::MalformedArtifact(s) if s.contains("FAIL_OBS_METRICS_INTERVAL")));
    }

    #[test]
    fn pusher_can_be_validated_when_disabled_for_dry_run() {
        let mut raw = full_section();
        raw.enabled = false;
        let cfg = ObservabilityConfig::validate(&raw, &empty_creds()).expect("valid");
        assert!(!cfg.enabled);
        assert!(cfg.pusher.is_some(), "operator-supplied pusher block is preserved for `enabled=false` dry runs");
    }
}

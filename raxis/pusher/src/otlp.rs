//! OTLP export client.
//!
//! Spec: `v3/otel-observability.md §13`.
//!
//! ## Wire format
//!
//! V3 ships **OTLP HTTP/protobuf** as the only export transport.
//! gRPC is deferred to V3.1; the feature flag is reserved in policy
//! schema (`otlp_protocol = "grpc" | "http"`) but the runtime
//! refuses to start when `"grpc"` is selected. The choice keeps
//! the dependency surface small (no `tonic` / `tower-h2` /
//! `prost-build` in the build graph) while still satisfying the
//! Prometheus-compatible-collector contract — every Prom-shaped
//! collector (Tempo, Mimir, Grafana Agent, the OTel Collector
//! itself) accepts OTLP HTTP/protobuf on `:4318`.
//!
//! ## Encoding
//!
//! We hand-write the minimal subset of the OTLP proto messages we
//! actually emit. Importing the upstream `opentelemetry-proto`
//! crate would pull in ~30 MiB of compiled bytecode for messages
//! that are out of scope for V3 (logs, profiles, etc.). The
//! [`prost::Message`] derive on each local message gives us
//! wire-compatible encoding via `prost::Message::encoded_len` /
//! `prost::Message::encode_to_vec`.
//!
//! ## Authentication
//!
//! Headers from `[observability.pusher.headers]` are resolved from
//! the policy bundle by the boot path (`@cred:<name>` references
//! are looked up in the credential store; literal values pass
//! through). The OTLP client just receives a flat `BTreeMap` and
//! writes them to every request.

use std::collections::BTreeMap;
use std::time::Duration;

use raxis_observability::types::{MetricData, SpanData};
use serde::{Deserialize, Serialize};

use crate::retry::BackoffPolicy;

/// Endpoint shape, derived from `[observability.pusher].otlp_endpoint`.
#[derive(Debug, Clone)]
pub struct OtlpEndpoint {
    /// Base URL — same string the operator wrote in policy.toml.
    /// V3 only consumes the scheme + host + port; path is appended
    /// per the OTLP spec.
    pub base: String,
    /// Optional explicit override of the spans path. Defaults to
    /// `/v1/traces`.
    pub spans_path: String,
    /// Optional explicit override of the metrics path. Defaults to
    /// `/v1/metrics`.
    pub metrics_path: String,
}

impl OtlpEndpoint {
    /// Construct an endpoint with default OTLP HTTP/protobuf paths.
    pub fn new(base: impl Into<String>) -> Self {
        Self {
            base:         base.into(),
            spans_path:   "/v1/traces".to_owned(),
            metrics_path: "/v1/metrics".to_owned(),
        }
    }

    /// URL for the spans export endpoint.
    pub fn spans_url(&self) -> String {
        join(&self.base, &self.spans_path)
    }

    /// URL for the metrics export endpoint.
    pub fn metrics_url(&self) -> String {
        join(&self.base, &self.metrics_path)
    }
}

fn join(base: &str, path: &str) -> String {
    if base.ends_with('/') && path.starts_with('/') {
        format!("{}{}", base.trim_end_matches('/'), path)
    } else if !base.ends_with('/') && !path.starts_with('/') {
        format!("{base}/{path}")
    } else {
        format!("{base}{path}")
    }
}

/// Resource-attributes payload built once at boot from the
/// validated `[observability.resource]` section. Cheap to clone.
#[derive(Debug, Clone)]
pub struct ResourceAttrs {
    /// `service.name`.
    pub service_name: String,
    /// `deployment.environment`. Empty ⇒ omitted.
    pub environment: String,
    /// Operator-supplied extras under `[observability.resource.extra]`.
    pub extra: BTreeMap<String, String>,
}

/// OTLP HTTP/protobuf export client. Cheap to clone (`reqwest::Client`
/// is internally `Arc`).
#[derive(Debug, Clone)]
pub struct OtlpClient {
    inner:    reqwest::Client,
    endpoint: OtlpEndpoint,
    headers:  BTreeMap<String, String>,
    backoff:  BackoffPolicy,
    timeout:  Duration,
    resource: ResourceAttrs,
}

impl OtlpClient {
    /// Build a client with the given knobs. `timeout` is per-batch.
    pub fn new(
        endpoint: OtlpEndpoint,
        headers:  BTreeMap<String, String>,
        backoff:  BackoffPolicy,
        timeout:  Duration,
        resource: ResourceAttrs,
    ) -> Result<Self, OtlpClientError> {
        let mut builder = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .pool_idle_timeout(Some(Duration::from_secs(60)))
            .gzip(true);
        // Every header value is enforced to ≤ 256 bytes by policy
        // validation, so `HeaderValue::from_str` can't fail unless
        // the operator stuck a `\r\n` in there — which validation
        // also rejects.
        let mut hmap = reqwest::header::HeaderMap::new();
        for (k, v) in &headers {
            let name = reqwest::header::HeaderName::from_bytes(k.as_bytes())
                .map_err(|_| OtlpClientError::InvalidHeaderName { key: k.clone() })?;
            let value = reqwest::header::HeaderValue::from_str(v)
                .map_err(|_| OtlpClientError::InvalidHeaderValue { key: k.clone() })?;
            hmap.insert(name, value);
        }
        builder = builder.default_headers(hmap);
        let client = builder.build().map_err(OtlpClientError::Build)?;
        Ok(Self {
            inner:    client,
            endpoint,
            headers,
            backoff,
            timeout,
            resource,
        })
    }

    /// Endpoint accessor — used by `/healthz`.
    pub fn endpoint(&self) -> &OtlpEndpoint { &self.endpoint }

    /// Backoff policy — used by the run loop's retry helper.
    pub fn backoff(&self) -> BackoffPolicy { self.backoff }

    /// Headers accessor (for diagnostics; never logs values).
    pub fn header_keys(&self) -> Vec<String> {
        self.headers.keys().cloned().collect()
    }

    /// Encode + POST a span batch. Returns the HTTP status code on
    /// success; surfaces `OtlpExportError::Network` on transport
    /// failure. The caller decides retry semantics based on the
    /// status (`5xx` → retry, `408 / 429` → retry, other `4xx` →
    /// drop) and on the error variant (`Network` → retry).
    pub async fn export_spans(
        &self,
        spans:          &[SpanData],
        kernel_version: &str,
    ) -> Result<u16, OtlpExportError> {
        let body = wire::encode_spans(spans, kernel_version, &self.resource);
        self.post_protobuf(&self.endpoint.spans_url(), body).await
    }

    /// Encode + POST a metric batch. See [`Self::export_spans`].
    pub async fn export_metrics(
        &self,
        metrics:        &[MetricData],
        kernel_version: &str,
    ) -> Result<u16, OtlpExportError> {
        let body = wire::encode_metrics(metrics, kernel_version, &self.resource);
        self.post_protobuf(&self.endpoint.metrics_url(), body).await
    }

    async fn post_protobuf(
        &self,
        url:  &str,
        body: Vec<u8>,
    ) -> Result<u16, OtlpExportError> {
        let req = self
            .inner
            .post(url)
            .header(reqwest::header::CONTENT_TYPE, "application/x-protobuf")
            .timeout(self.timeout)
            .body(body);
        let resp = req
            .send()
            .await
            .map_err(|e| OtlpExportError::Network {
                url: url.to_owned(),
                reason: e.to_string(),
            })?;
        let status = resp.status().as_u16();
        // Iter49: on any non-2xx we surface the collector's response
        // body to stderr in the structured-log JSON shape the rest of
        // the pusher uses. The OTel collector returns a short error
        // string for HTTP 4xx (e.g. "proto: cannot parse invalid
        // wire-format data"). Without this hook the kernel side sees
        // only "http_400_client_error" and has no way to tell whether
        // it's a config / schema / payload bug — which is exactly how
        // the `repeated fixed64 bucket_counts` vs `uint64` regression
        // stayed hidden through iter49 boot. Body is capped at 1 KiB
        // because the collector's error strings are short and we do
        // not want a misbehaving peer to drown the pusher log file.
        if !(200..300).contains(&status) {
            let body_bytes = resp
                .bytes()
                .await
                .map(|b| b.to_vec())
                .unwrap_or_else(|_| Vec::new());
            let mut body = String::from_utf8_lossy(&body_bytes).into_owned();
            if body.len() > 1024 {
                body.truncate(1024);
                body.push_str("…[truncated]");
            }
            let body_escaped = body
                .replace('\\', "\\\\")
                .replace('"',  "\\\"")
                .replace('\n', "\\n")
                .replace('\r', "\\r");
            eprintln!(
                "{{\"level\":\"warn\",\"event\":\"otel_pusher_export_http_error\",\
                  \"url\":\"{url}\",\"status\":{status},\"body\":\"{body_escaped}\"}}"
            );
        }
        Ok(status)
    }
}

/// Reasons a [`OtlpClient`] could not be constructed.
#[derive(Debug, thiserror::Error)]
pub enum OtlpClientError {
    /// `reqwest::Client::builder().build()` failed.
    #[error("otlp client build failed: {0}")]
    Build(reqwest::Error),
    /// Header key isn't a valid HTTP/2 header name.
    #[error("otlp client: header name invalid: {key}")]
    InvalidHeaderName {
        /// The offending header key.
        key: String,
    },
    /// Header value isn't a valid HTTP/2 header value (likely
    /// because it contains a `\r\n` or NUL byte).
    #[error("otlp client: header value invalid for {key}")]
    InvalidHeaderValue {
        /// The header key whose value failed.
        key: String,
    },
}

/// Reasons a single export attempt could fail. The retry helper
/// decides whether to retry based on the variant.
#[derive(Debug, thiserror::Error, Serialize, Deserialize)]
pub enum OtlpExportError {
    /// Network failure: connect refused, TLS handshake failed,
    /// timeout. Retriable.
    #[error("otlp network error to {url}: {reason}")]
    Network {
        /// Target URL.
        url:    String,
        /// Reason string from `reqwest`.
        reason: String,
    },
}

// ---------------------------------------------------------------------------
// Wire-format encoder — minimal subset of OTLP proto.
// ---------------------------------------------------------------------------

mod wire {
    //! Minimal hand-written subset of the OTLP proto messages.
    //!
    //! We define only the fields we emit; older OTel collectors
    //! ignore unknown fields and newer ones tolerate omitted
    //! optionals, so this subset is forwards-compatible.
    //!
    //! The structs here are private to the encoder; they are not
    //! re-exported. All callers go through [`encode_spans`] /
    //! [`encode_metrics`].

    use prost::Message;
    use raxis_observability::types::{
        AttrMap, AttrValue, DataPoint as RxDataPoint, MetricData, MetricType, SpanData, SpanKind,
        SpanStatus,
    };

    use super::ResourceAttrs;

    // -- Common -----------------------------------------------------------

    #[derive(Clone, PartialEq, Message)]
    pub(super) struct AnyValue {
        #[prost(oneof = "any_value::Value", tags = "1, 2, 3, 4")]
        pub value: Option<any_value::Value>,
    }

    pub(super) mod any_value {
        use prost::Oneof;
        #[derive(Clone, PartialEq, Oneof)]
        pub enum Value {
            #[prost(string, tag = "1")] StringValue(String),
            #[prost(bool,   tag = "2")] BoolValue(bool),
            #[prost(int64,  tag = "3")] IntValue(i64),
            #[prost(double, tag = "4")] DoubleValue(f64),
        }
    }

    #[derive(Clone, PartialEq, Message)]
    pub(super) struct KeyValue {
        #[prost(string, tag = "1")] pub key: String,
        #[prost(message, tag = "2")] pub value: Option<AnyValue>,
    }

    #[derive(Clone, PartialEq, Message)]
    pub(super) struct Resource {
        #[prost(message, repeated, tag = "1")]
        pub attributes: Vec<KeyValue>,
    }

    #[derive(Clone, PartialEq, Message)]
    pub(super) struct InstrumentationScope {
        #[prost(string, tag = "1")] pub name: String,
        #[prost(string, tag = "2")] pub version: String,
    }

    // -- Trace messages ---------------------------------------------------

    #[derive(Clone, PartialEq, Message)]
    pub(super) struct Status {
        #[prost(string, tag = "2")] pub message: String,
        #[prost(enumeration = "status_code::StatusCode", tag = "3")] pub code: i32,
    }

    pub(super) mod status_code {
        #[derive(Clone, Copy, Debug, PartialEq, prost::Enumeration)]
        #[repr(i32)]
        pub enum StatusCode {
            Unset = 0,
            Ok    = 1,
            Error = 2,
        }
    }

    #[derive(Clone, PartialEq, Message)]
    pub(super) struct SpanProto {
        #[prost(bytes  = "vec",   tag = "1")]  pub trace_id: Vec<u8>,
        #[prost(bytes  = "vec",   tag = "2")]  pub span_id:  Vec<u8>,
        #[prost(string,           tag = "3")]  pub trace_state: String,
        #[prost(bytes  = "vec",   tag = "4")]  pub parent_span_id: Vec<u8>,
        #[prost(string,           tag = "5")]  pub name:     String,
        #[prost(enumeration = "span_kind::SpanKindProto", tag = "6")] pub kind: i32,
        #[prost(fixed64,          tag = "7")]  pub start_time_unix_nano: u64,
        #[prost(fixed64,          tag = "8")]  pub end_time_unix_nano:   u64,
        #[prost(message, repeated, tag = "9")] pub attributes: Vec<KeyValue>,
        #[prost(uint32,           tag = "10")] pub dropped_attributes_count: u32,
        #[prost(message, repeated, tag = "11")] pub events: Vec<SpanEventProto>,
        #[prost(uint32,           tag = "12")] pub dropped_events_count: u32,
        #[prost(message,          tag = "15")] pub status: Option<Status>,
    }

    pub(super) mod span_kind {
        #[derive(Clone, Copy, Debug, PartialEq, prost::Enumeration)]
        #[repr(i32)]
        pub enum SpanKindProto {
            Unspecified = 0,
            Internal    = 1,
            Server      = 2,
            Client      = 3,
            Producer    = 4,
            Consumer    = 5,
        }
    }

    #[derive(Clone, PartialEq, Message)]
    pub(super) struct SpanEventProto {
        #[prost(fixed64,          tag = "1")] pub time_unix_nano: u64,
        #[prost(string,           tag = "2")] pub name:           String,
        #[prost(message, repeated, tag = "3")] pub attributes:    Vec<KeyValue>,
    }

    #[derive(Clone, PartialEq, Message)]
    pub(super) struct ScopeSpans {
        #[prost(message, tag = "1")] pub scope: Option<InstrumentationScope>,
        #[prost(message, repeated, tag = "2")] pub spans: Vec<SpanProto>,
    }

    #[derive(Clone, PartialEq, Message)]
    pub(super) struct ResourceSpans {
        #[prost(message, tag = "1")] pub resource: Option<Resource>,
        #[prost(message, repeated, tag = "2")] pub scope_spans: Vec<ScopeSpans>,
    }

    #[derive(Clone, PartialEq, Message)]
    pub(super) struct ExportTraceServiceRequest {
        #[prost(message, repeated, tag = "1")] pub resource_spans: Vec<ResourceSpans>,
    }

    // -- Metric messages --------------------------------------------------

    #[derive(Clone, PartialEq, Message)]
    pub(super) struct NumberDataPoint {
        #[prost(message, repeated, tag = "7")] pub attributes:        Vec<KeyValue>,
        #[prost(fixed64,            tag = "2")] pub start_time_unix_nano: u64,
        #[prost(fixed64,            tag = "3")] pub time_unix_nano:    u64,
        #[prost(oneof = "number_data_point::Value", tags = "4, 6")]
        pub value: Option<number_data_point::Value>,
    }

    pub(super) mod number_data_point {
        use prost::Oneof;
        #[derive(Clone, Copy, PartialEq, Oneof)]
        pub enum Value {
            #[prost(double, tag = "4")] AsDouble(f64),
            // OTLP `metrics.proto`: `sfixed64 as_int = 6`. We never
            // emit the `AsInt` variant today (every authority-side
            // scalar metric ships as `as_double`), but keep the wire
            // tag honest so that adding integer-flavoured counters
            // later doesn't reintroduce a wire/spec mismatch.
            #[prost(sfixed64, tag = "6")] AsInt(i64),
        }
    }

    #[derive(Clone, PartialEq, Message)]
    pub(super) struct Sum {
        #[prost(message, repeated, tag = "1")] pub data_points: Vec<NumberDataPoint>,
        #[prost(enumeration = "aggregation_temporality::AggregationTemporality", tag = "2")]
        pub aggregation_temporality: i32,
        #[prost(bool, tag = "3")] pub is_monotonic: bool,
    }

    #[derive(Clone, PartialEq, Message)]
    pub(super) struct Gauge {
        #[prost(message, repeated, tag = "1")] pub data_points: Vec<NumberDataPoint>,
    }

    pub(super) mod aggregation_temporality {
        #[derive(Clone, Copy, Debug, PartialEq, prost::Enumeration)]
        #[repr(i32)]
        pub enum AggregationTemporality {
            Unspecified = 0,
            Delta       = 1,
            Cumulative  = 2,
        }
    }

    #[derive(Clone, PartialEq, Message)]
    pub(super) struct HistogramDataPoint {
        #[prost(message, repeated, tag = "9")] pub attributes:           Vec<KeyValue>,
        #[prost(fixed64,            tag = "2")] pub start_time_unix_nano: u64,
        #[prost(fixed64,            tag = "3")] pub time_unix_nano:       u64,
        #[prost(fixed64,            tag = "4")] pub count:                u64,
        #[prost(double,             tag = "5")] pub sum:                  f64,
        // OTLP `metrics.proto`: `repeated fixed64 bucket_counts = 6`
        // (yes, fixed64 — *not* uint64; the spec switched to fixed64
        // when explicit histograms were added in 1.0 to keep packed
        // bucket arrays byte-addressable on the receiver). Encoding
        // these as uint64 (packed varint) was the iter49 OTel-collector
        // 400 root cause — the receiver tries to parse the packed
        // payload as 8-byte-stride fixed64 and rejects the request
        // when the length is not a multiple of 8.
        #[prost(fixed64, repeated, tag = "6")] pub bucket_counts:        Vec<u64>,
        #[prost(double, repeated,   tag = "7")] pub explicit_bounds:      Vec<f64>,
        #[prost(double, optional,   tag = "11")] pub min:                 Option<f64>,
        #[prost(double, optional,   tag = "12")] pub max:                 Option<f64>,
    }

    #[derive(Clone, PartialEq, Message)]
    pub(super) struct Histogram {
        #[prost(message, repeated, tag = "1")] pub data_points:           Vec<HistogramDataPoint>,
        #[prost(enumeration = "aggregation_temporality::AggregationTemporality", tag = "2")]
        pub aggregation_temporality: i32,
    }

    #[derive(Clone, PartialEq, Message)]
    pub(super) struct Metric {
        #[prost(string, tag = "1")] pub name:        String,
        #[prost(string, tag = "2")] pub description: String,
        #[prost(string, tag = "3")] pub unit:        String,
        #[prost(oneof = "metric::Data", tags = "5, 7, 9")]
        pub data: Option<metric::Data>,
    }

    pub(super) mod metric {
        use prost::Oneof;
        #[derive(Clone, PartialEq, Oneof)]
        pub enum Data {
            #[prost(message, tag = "5")] Gauge(super::Gauge),
            #[prost(message, tag = "7")] Sum(super::Sum),
            #[prost(message, tag = "9")] Histogram(super::Histogram),
        }
    }

    #[derive(Clone, PartialEq, Message)]
    pub(super) struct ScopeMetrics {
        #[prost(message, tag = "1")] pub scope: Option<InstrumentationScope>,
        #[prost(message, repeated, tag = "2")] pub metrics: Vec<Metric>,
    }

    #[derive(Clone, PartialEq, Message)]
    pub(super) struct ResourceMetrics {
        #[prost(message, tag = "1")] pub resource: Option<Resource>,
        #[prost(message, repeated, tag = "2")] pub scope_metrics: Vec<ScopeMetrics>,
    }

    #[derive(Clone, PartialEq, Message)]
    pub(super) struct ExportMetricsServiceRequest {
        #[prost(message, repeated, tag = "1")] pub resource_metrics: Vec<ResourceMetrics>,
    }

    // -- Adapters ---------------------------------------------------------

    fn attr_pb(k: &str, v: &AttrValue) -> KeyValue {
        let value = match v {
            AttrValue::Str(s) => any_value::Value::StringValue(s.clone()),
            AttrValue::I64(i) => any_value::Value::IntValue(*i),
            AttrValue::F64(f) => any_value::Value::DoubleValue(*f),
            AttrValue::Bool(b) => any_value::Value::BoolValue(*b),
        };
        KeyValue { key: k.to_owned(), value: Some(AnyValue { value: Some(value) }) }
    }

    fn attrs_pb(map: &AttrMap) -> Vec<KeyValue> {
        let mut out: Vec<KeyValue> = map.iter().map(|(k, v)| attr_pb(k, v)).collect();
        out.sort_by(|a, b| a.key.cmp(&b.key));
        out
    }

    fn span_kind_pb(k: SpanKind) -> i32 {
        use span_kind::SpanKindProto::*;
        let v = match k {
            SpanKind::Internal => Internal,
            SpanKind::Server   => Server,
            SpanKind::Client   => Client,
            SpanKind::Producer => Producer,
            SpanKind::Consumer => Consumer,
        };
        v as i32
    }

    fn status_pb(s: SpanStatus, msg: Option<&str>) -> Status {
        use status_code::StatusCode::*;
        Status {
            message: msg.unwrap_or("").to_owned(),
            code: match s {
                SpanStatus::Ok    => Ok,
                SpanStatus::Error => Error,
            } as i32,
        }
    }

    fn resource_pb(r: &ResourceAttrs) -> Resource {
        let mut attrs: Vec<KeyValue> = Vec::new();
        attrs.push(KeyValue {
            key: "service.name".to_owned(),
            value: Some(AnyValue {
                value: Some(any_value::Value::StringValue(r.service_name.clone())),
            }),
        });
        if !r.environment.is_empty() {
            attrs.push(KeyValue {
                key: "deployment.environment".to_owned(),
                value: Some(AnyValue {
                    value: Some(any_value::Value::StringValue(r.environment.clone())),
                }),
            });
        }
        for (k, v) in &r.extra {
            attrs.push(KeyValue {
                key: k.clone(),
                value: Some(AnyValue {
                    value: Some(any_value::Value::StringValue(v.clone())),
                }),
            });
        }
        attrs.sort_by(|a, b| a.key.cmp(&b.key));
        Resource { attributes: attrs }
    }

    /// Encode a span batch into an OTLP `ExportTraceServiceRequest`
    /// protobuf body.
    pub fn encode_spans(
        spans:          &[SpanData],
        kernel_version: &str,
        resource:       &ResourceAttrs,
    ) -> Vec<u8> {
        let mut out = Vec::new();
        let scope = InstrumentationScope {
            name:    "raxis-kernel".to_owned(),
            version: kernel_version.to_owned(),
        };
        let span_protos: Vec<SpanProto> = spans.iter().map(|s| SpanProto {
            trace_id:                  s.trace_id.to_vec(),
            span_id:                   s.span_id.to_vec(),
            trace_state:               String::new(),
            parent_span_id:            s.parent_span_id.map(|v| v.to_vec()).unwrap_or_default(),
            name:                      s.name.as_otel_name().to_owned(),
            kind:                      span_kind_pb(s.kind),
            start_time_unix_nano:      s.start_unix_nanos,
            end_time_unix_nano:        s.end_unix_nanos,
            attributes:                attrs_pb(&s.attrs),
            dropped_attributes_count:  0,
            events:                    s.events.iter().map(|ev| SpanEventProto {
                time_unix_nano: ev.unix_nanos,
                name:           ev.name.as_str().to_owned(),
                attributes:     attrs_pb(&ev.attrs),
            }).collect(),
            dropped_events_count:      0,
            status:                    Some(status_pb(s.status, s.status_message.as_deref())),
        }).collect();
        let req = ExportTraceServiceRequest {
            resource_spans: vec![ResourceSpans {
                resource: Some(resource_pb(resource)),
                scope_spans: vec![ScopeSpans {
                    scope: Some(scope),
                    spans: span_protos,
                }],
            }],
        };
        prost::Message::encode(&req, &mut out).expect("prost encode is infallible into Vec");
        out
    }

    /// Encode a metric batch.
    pub fn encode_metrics(
        metrics:        &[MetricData],
        kernel_version: &str,
        resource:       &ResourceAttrs,
    ) -> Vec<u8> {
        let scope = InstrumentationScope {
            name:    "raxis-kernel".to_owned(),
            version: kernel_version.to_owned(),
        };
        let metric_protos: Vec<Metric> = metrics.iter().map(|m| {
            let attrs = attrs_pb(&m.labels);
            let now = m.unix_nanos;
            let datum = match (&m.metric_type, &m.datapoint) {
                (MetricType::Counter, RxDataPoint::Sum { value }) => {
                    metric::Data::Sum(Sum {
                        data_points: vec![NumberDataPoint {
                            attributes: attrs.clone(),
                            start_time_unix_nano: now,
                            time_unix_nano: now,
                            value: Some(number_data_point::Value::AsDouble(*value)),
                        }],
                        aggregation_temporality:
                            aggregation_temporality::AggregationTemporality::Cumulative as i32,
                        is_monotonic: true,
                    })
                }
                (MetricType::Gauge, RxDataPoint::Sum { value }) => {
                    metric::Data::Gauge(Gauge {
                        data_points: vec![NumberDataPoint {
                            attributes: attrs.clone(),
                            start_time_unix_nano: now,
                            time_unix_nano: now,
                            value: Some(number_data_point::Value::AsDouble(*value)),
                        }],
                    })
                }
                (MetricType::Histogram, RxDataPoint::Histo {
                    buckets, counts, sum, count, min, max,
                }) => {
                    metric::Data::Histogram(Histogram {
                        data_points: vec![HistogramDataPoint {
                            attributes: attrs.clone(),
                            start_time_unix_nano: now,
                            time_unix_nano: now,
                            count: *count,
                            sum:   *sum,
                            bucket_counts:   counts.clone(),
                            explicit_bounds: buckets.clone(),
                            min: Some(*min),
                            max: Some(*max),
                        }],
                        aggregation_temporality:
                            aggregation_temporality::AggregationTemporality::Cumulative as i32,
                    })
                }
                // Type/datapoint mismatches are filtered upstream by
                // the redactor; if one slips through we drop it
                // silently rather than mis-shipping nonsense.
                _ => return None,
            };
            Some(Metric {
                name:        m.name.as_otel_name().to_owned(),
                description: String::new(),
                unit:        m.unit.symbol().to_owned(),
                data:        Some(datum),
            })
        }).flatten().collect();
        let req = ExportMetricsServiceRequest {
            resource_metrics: vec![ResourceMetrics {
                resource: Some(resource_pb(resource)),
                scope_metrics: vec![ScopeMetrics {
                    scope: Some(scope),
                    metrics: metric_protos,
                }],
            }],
        };
        let mut out = Vec::new();
        prost::Message::encode(&req, &mut out).expect("prost encode is infallible into Vec");
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use raxis_observability::types::{
        AttrMap, AttrValue, DataPoint, MetricData, MetricName, MetricType, SpanData,
        SpanEvent, SpanKind, SpanName, SpanStatus, Unit,
    };

    fn sample_resource() -> ResourceAttrs {
        ResourceAttrs {
            service_name: "raxis-kernel".to_owned(),
            environment:  "test".to_owned(),
            extra:        BTreeMap::new(),
        }
    }

    fn sample_span() -> SpanData {
        let mut attrs = AttrMap::new();
        attrs.insert("intent_kind".to_owned(), AttrValue::Str("CompleteTask".into()));
        attrs.insert("verdict".to_owned(),     AttrValue::Str("Accepted".into()));
        SpanData {
            trace_id:         [1; 16],
            span_id:          [2; 8],
            parent_span_id:   None,
            name:             SpanName::IntentAdmission,
            kind:             SpanKind::Server,
            start_unix_nanos: 100,
            end_unix_nanos:   200,
            status:           SpanStatus::Ok,
            status_message:   None,
            attrs,
            events:           vec![SpanEvent {
                name:       raxis_observability::types::EventName::GateRequired,
                unix_nanos: 150,
                attrs:      AttrMap::new(),
            }],
        }
    }

    fn sample_counter() -> MetricData {
        let mut labels = AttrMap::new();
        labels.insert("verdict".to_owned(), AttrValue::Str("Accepted".into()));
        MetricData {
            name:        MetricName::IntentAdmissionTotal,
            metric_type: MetricType::Counter,
            unit:        Unit::None,
            labels,
            datapoint:   DataPoint::Sum { value: 1.0 },
            unix_nanos:  500,
        }
    }

    fn sample_histogram() -> MetricData {
        let buckets = vec![1.0, 5.0, 10.0];
        let counts  = vec![0u64, 1, 0, 0];
        let mut labels = AttrMap::new();
        labels.insert("intent_kind".to_owned(), AttrValue::Str("CompleteTask".into()));
        MetricData {
            name:        MetricName::IntentAdmissionDuration,
            metric_type: MetricType::Histogram,
            unit:        Unit::Milliseconds,
            labels,
            datapoint:   DataPoint::Histo {
                buckets,
                counts,
                sum:   3.0,
                count: 1,
                min:   3.0,
                max:   3.0,
            },
            unix_nanos:  600,
        }
    }

    #[test]
    fn encode_spans_emits_non_empty_protobuf() {
        let body = wire::encode_spans(&[sample_span()], "0.1.0", &sample_resource());
        assert!(!body.is_empty(), "encoded body is non-empty");
        // Must be valid protobuf — round-trip through prost.
        let req: wire::ExportTraceServiceRequest =
            prost::Message::decode(&body[..]).expect("round-trip");
        assert_eq!(req.resource_spans.len(), 1);
        let rs = &req.resource_spans[0];
        assert_eq!(rs.scope_spans[0].spans.len(), 1);
        assert_eq!(rs.scope_spans[0].spans[0].name, "raxis.intent.admission");
        assert_eq!(rs.scope_spans[0].spans[0].attributes.len(), 2);
    }

    #[test]
    fn encode_metrics_handles_counter_and_histogram() {
        let body = wire::encode_metrics(
            &[sample_counter(), sample_histogram()],
            "0.1.0",
            &sample_resource(),
        );
        assert!(!body.is_empty());
        let req: wire::ExportMetricsServiceRequest =
            prost::Message::decode(&body[..]).expect("round-trip");
        let rm = &req.resource_metrics[0];
        let metrics = &rm.scope_metrics[0].metrics;
        assert_eq!(metrics.len(), 2);
        assert_eq!(metrics[0].name, "raxis.intent.admission.total");
        assert_eq!(metrics[1].name, "raxis.intent.admission.duration");
    }

    #[test]
    fn histogram_bucket_counts_use_packed_fixed64_wire_format() {
        // Regression for iter49: the OTel collector was returning HTTP
        // 400 on every metrics batch because the `bucket_counts` field
        // was declared as `uint64` (packed varint) instead of the
        // spec-mandated `fixed64` (packed 8-byte stride). The receiver
        // tries to read 8-byte chunks out of the packed payload and
        // rejects requests whose `bucket_counts` packed length is not
        // a multiple of 8 — which is virtually every real batch.
        //
        // This test asserts the wire format at the byte level rather
        // than just round-tripping through `prost::Message::decode`
        // (which would tolerate either encoding by virtue of going
        // through the same Rust struct).
        let body = wire::encode_metrics(
            &[sample_histogram()],
            "0.1.0",
            &sample_resource(),
        );
        // The histogram in `sample_histogram` has 3 explicit_bounds
        // and 4 bucket_counts. A correctly-encoded packed fixed64
        // bucket_counts is `0x32 0x20 ` + 4 * 8 = 32 raw little-endian
        // u64 bytes (34 bytes including the tag + length prefix).
        // A buggy uint64-packed encoding would be `0x32 0x04 ` + 4
        // single-byte varints (6 bytes total).
        let needle_fixed64 = b"\x32\x20\
            \x00\x00\x00\x00\x00\x00\x00\x00\
            \x01\x00\x00\x00\x00\x00\x00\x00\
            \x00\x00\x00\x00\x00\x00\x00\x00\
            \x00\x00\x00\x00\x00\x00\x00\x00";
        assert!(
            body.windows(needle_fixed64.len()).any(|w| w == needle_fixed64),
            "expected packed fixed64 bucket_counts (tag 6 length 32) in encoded body"
        );
        let needle_varint = [0x32u8, 0x04, 0x00, 0x01, 0x00, 0x00];
        assert!(
            !body.windows(needle_varint.len()).any(|w| w == needle_varint),
            "must not emit packed varint encoding for bucket_counts"
        );
    }

    #[test]
    fn endpoint_url_builder_handles_trailing_slash() {
        let e = OtlpEndpoint::new("https://otlp.example.com:4318");
        assert_eq!(e.spans_url(),   "https://otlp.example.com:4318/v1/traces");
        assert_eq!(e.metrics_url(), "https://otlp.example.com:4318/v1/metrics");
        let e2 = OtlpEndpoint::new("https://otlp.example.com:4318/");
        assert_eq!(e2.spans_url(), "https://otlp.example.com:4318/v1/traces");
    }

    #[test]
    fn header_keys_are_exposed() {
        let mut hdr = BTreeMap::new();
        hdr.insert("authorization".to_owned(), "secret".to_owned());
        hdr.insert("x-tenant-id".to_owned(),   "platform".to_owned());
        let client = OtlpClient::new(
            OtlpEndpoint::new("https://otlp.example.com:4318"),
            hdr,
            BackoffPolicy::default(),
            Duration::from_secs(1),
            sample_resource(),
        ).unwrap();
        let mut keys = client.header_keys();
        keys.sort();
        assert_eq!(keys, vec!["authorization", "x-tenant-id"]);
    }
}

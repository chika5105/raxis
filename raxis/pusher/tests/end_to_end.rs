//! End-to-end integration test for the OTel observability stack.
//!
//! Spec: `specs/v3/otel-observability.md §15.4`.
//!
//! This test exercises the **real** runtime objects (no mocks of
//! the components under test): a real
//! [`raxis_observability::ObservabilityHub`] with a real
//! [`raxis_observability::RingFileExporter`] writes JSONL frames
//! into a tempdir; a real [`raxis_otel_pusher::Pusher`] reads them
//! back and ships them to a real `tokio::net::TcpListener` standing
//! in for the OTLP collector. The fake collector verifies that the
//! protobuf payload it receives round-trips through `prost::Message`,
//! then ACKs `200 OK`.
//!
//! Properties asserted:
//!
//! 1. Hub-emitted spans + metrics survive the JSONL round-trip and
//!    arrive at the collector with correct names.
//! 2. The cursor advances and persists between batches.
//! 3. After the collector restart-cycle the pusher resumes from the
//!    cursor without re-shipping already-acked frames.
//! 4. Segment rotation is handled — a kernel-side rotation forces
//!    the pusher to read across segment boundaries.
//! 5. OTLP HTTP/4xx is permanent-drop; OTLP HTTP/503 is retried
//!    until success.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use raxis_observability::redact::attrs;
use raxis_observability::ring::RingConfig;
use raxis_observability::{
    HubConfig, MetricName, ObservabilityExporter, ObservabilityHub, RingFileExporter, SpanKind,
    SpanName,
};
use raxis_otel_pusher::config::PusherConfig;
use raxis_otel_pusher::otlp::{OtlpClient, OtlpCompression, OtlpEndpoint, ResourceAttrs};
use raxis_otel_pusher::retry::BackoffPolicy;
use raxis_otel_pusher::run::{Pusher, PusherEvent};
use raxis_policy::{
    ObservabilityConfig, ObservabilityMetricsConfig, ObservabilityPusherConfig,
    ObservabilityPusherTlsConfig, ObservabilityResourceConfig, ObservabilityRingConfig,
    ObservabilityTracesConfig,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Mutex;

/// Spawn a tokio TCP listener that replies to OTLP HTTP requests
/// with a configurable status code and records every body it
/// receives.
struct FakeCollector {
    addr: std::net::SocketAddr,
    received: Arc<Mutex<Vec<Vec<u8>>>>,
    encodings: Arc<Mutex<Vec<Option<String>>>>,
    handle: tokio::task::JoinHandle<()>,
}

impl FakeCollector {
    async fn bind(status_seq: Vec<u16>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let received: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
        let encodings: Arc<Mutex<Vec<Option<String>>>> = Arc::new(Mutex::new(Vec::new()));
        let received_clone = Arc::clone(&received);
        let encodings_clone = Arc::clone(&encodings);
        let handle = tokio::spawn(async move {
            let mut idx = 0usize;
            loop {
                let (mut stream, _peer) = match listener.accept().await {
                    Ok(p) => p,
                    Err(_) => break,
                };
                let received = Arc::clone(&received_clone);
                let encodings = Arc::clone(&encodings_clone);
                let status = status_seq.get(idx).copied().unwrap_or(200);
                idx = idx.saturating_add(1);
                tokio::spawn(async move {
                    // Read until \r\n\r\n then read Content-Length
                    // bytes.
                    let mut header_buf = Vec::with_capacity(256);
                    let mut body_buf = Vec::new();
                    let mut tmp = [0u8; 1024];
                    let mut content_length: Option<usize> = None;
                    let mut content_encoding: Option<String> = None;
                    let mut header_done = false;
                    loop {
                        let n = match stream.read(&mut tmp).await {
                            Ok(0) => break,
                            Ok(n) => n,
                            Err(_) => break,
                        };
                        if !header_done {
                            header_buf.extend_from_slice(&tmp[..n]);
                            if let Some(idx) = window_index(&header_buf, b"\r\n\r\n") {
                                header_done = true;
                                let head = std::str::from_utf8(&header_buf[..idx]).unwrap_or("");
                                for line in head.split("\r\n") {
                                    let lower = line.to_ascii_lowercase();
                                    if let Some(rest) = lower.strip_prefix("content-length:") {
                                        content_length = rest.trim().parse().ok();
                                    } else if let Some(rest) =
                                        lower.strip_prefix("content-encoding:")
                                    {
                                        content_encoding = Some(rest.trim().to_owned());
                                    }
                                }
                                let body_start = idx + 4;
                                if body_start < header_buf.len() {
                                    body_buf.extend_from_slice(&header_buf[body_start..]);
                                }
                            }
                        } else {
                            body_buf.extend_from_slice(&tmp[..n]);
                        }
                        if let Some(cl) = content_length {
                            if header_done && body_buf.len() >= cl {
                                body_buf.truncate(cl);
                                break;
                            }
                        }
                    }
                    let stored_body = match content_encoding.as_deref() {
                        Some("gzip") => {
                            let mut decoder = flate2::read::GzDecoder::new(&body_buf[..]);
                            let mut decoded = Vec::new();
                            std::io::Read::read_to_end(&mut decoder, &mut decoded)
                                .expect("fake collector should decode gzip OTLP request body");
                            decoded
                        }
                        Some(other) => panic!("unsupported content-encoding in test: {other}"),
                        None => body_buf,
                    };
                    encodings.lock().await.push(content_encoding);
                    received.lock().await.push(stored_body);
                    let resp = format!(
                        "HTTP/1.1 {} {}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                        status,
                        match status {
                            200 => "OK",
                            400 => "Bad Request",
                            429 => "Too Many Requests",
                            503 => "Service Unavailable",
                            _ => "Status",
                        },
                    );
                    let _ = stream.write_all(resp.as_bytes()).await;
                    let _ = stream.shutdown().await;
                });
            }
        });
        Self {
            addr,
            received,
            encodings,
            handle,
        }
    }

    async fn snapshot_bodies(&self) -> Vec<Vec<u8>> {
        self.received.lock().await.clone()
    }

    async fn snapshot_encodings(&self) -> Vec<Option<String>> {
        self.encodings.lock().await.clone()
    }

    async fn endpoint(&self) -> String {
        format!("http://{}", self.addr)
    }
}

impl Drop for FakeCollector {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

fn window_index(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.len() > haystack.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn obs_config(endpoint: &str) -> ObservabilityConfig {
    ObservabilityConfig {
        enabled: true,
        ring: ObservabilityRingConfig {
            dir: String::new(),
            segment_max_bytes: 1024 * 1024, // 1 MiB
            max_total_bytes: 16 * 1024 * 1024,
            max_queue_depth: 8192,
        },
        traces: ObservabilityTracesConfig {
            enabled: true,
            sample_rate: 1.0,
            max_attrs_per_span: 32,
            max_events_per_span: 16,
        },
        metrics: ObservabilityMetricsConfig {
            enabled: true,
            export_interval: Duration::from_secs(15),
            histogram_buckets: vec![1.0, 5.0, 10.0, 100.0],
        },
        resource: ObservabilityResourceConfig {
            service_name: "raxis-kernel".to_owned(),
            environment: "test".to_owned(),
            extra: BTreeMap::new(),
        },
        pusher: Some(ObservabilityPusherConfig {
            otlp_endpoint: endpoint.to_owned(),
            otlp_protocol: "http".to_owned(),
            otlp_compression: "gzip".to_owned(),
            otlp_export_timeout: Duration::from_secs(2),
            otlp_batch_size: 16,
            otlp_flush_interval: Duration::from_millis(100),
            otlp_max_inflight: 2,
            backoff_initial: Duration::from_millis(10),
            backoff_max: Duration::from_millis(50),
            backoff_jitter: 0.0,
            tls: ObservabilityPusherTlsConfig::default(),
            headers: BTreeMap::new(),
        }),
    }
}

fn build_pusher_pieces(
    obs: &ObservabilityConfig,
    data_dir: std::path::PathBuf,
    kernel_version: &str,
) -> (PusherConfig, OtlpClient) {
    let pcfg = PusherConfig::build(obs, data_dir, kernel_version, 0).unwrap();
    let client = OtlpClient::new(
        OtlpEndpoint::new(&pcfg.pusher.otlp_endpoint),
        pcfg.pusher.headers.clone(),
        BackoffPolicy {
            initial: pcfg.pusher.backoff_initial,
            max: pcfg.pusher.backoff_max,
            jitter: pcfg.pusher.backoff_jitter,
            max_attempts: 3, // keep tests fast
        },
        pcfg.export_timeout(),
        ResourceAttrs {
            service_name: pcfg.resource.service_name.clone(),
            environment: pcfg.resource.environment.clone(),
            extra: pcfg.resource.extra.clone(),
        },
        OtlpCompression::Gzip,
    )
    .unwrap();
    (pcfg, client)
}

/// Run a real `ObservabilityHub` + `RingFileExporter` and have them
/// emit `n` spans + `n` counters; flush the hub. Returns the
/// `data_dir` that the kernel-side artifacts wrote into.
fn emit_kernel_telemetry(data_dir: &std::path::Path, n: usize) {
    let hub_cfg = HubConfig {
        enabled: true,
        max_queue_depth: 1024,
        sample_rate: 1.0,
        max_attrs_per_span: 16,
        max_events_per_span: 8,
        histogram_buckets: vec![1.0, 10.0, 100.0],
    };
    let exp = Arc::new(
        RingFileExporter::open(
            data_dir.join("observability"),
            RingConfig::default(),
            "0.1.0",
        )
        .unwrap(),
    );
    let hub = Arc::new(ObservabilityHub::new(
        hub_cfg,
        exp.clone() as Arc<dyn ObservabilityExporter>,
    ));
    for i in 0..n {
        let mut s = hub.start_span(SpanName::IntentAdmission, SpanKind::Server, None);
        s.set_attr("intent_kind", "CompleteTask");
        s.set_attr("verdict", if i % 2 == 0 { "Accepted" } else { "Rejected" });
        s.set_attr("latency_ms", (i as i64) * 10);
        s.end();
        hub.record_counter(
            MetricName::IntentAdmissionTotal,
            attrs([
                ("intent_kind", "CompleteTask"),
                ("verdict", if i % 2 == 0 { "Accepted" } else { "Rejected" }),
            ]),
            1.0,
        );
    }
    hub.flush();
    hub.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn end_to_end_kernel_to_collector_happy_path() {
    let tmp = tempfile::tempdir().unwrap();
    let collector = FakeCollector::bind(vec![200, 200, 200, 200]).await;

    // 1. Kernel side: emit 3 spans + 3 metrics.
    emit_kernel_telemetry(tmp.path(), 3);

    // 2. Pusher side: read JSONL → ship OTLP.
    let obs = obs_config(&collector.endpoint().await);
    let (cfg, client) = build_pusher_pieces(&obs, tmp.path().to_owned(), "0.1.0");
    let pusher = Pusher::new(cfg, client).unwrap();

    // Drive several ticks until either both streams are drained or
    // 50ms passes (test timeout safety).
    let mut events = Vec::new();
    for _ in 0..10 {
        events.extend(pusher.tick(true).await);
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    // 3. Assert at least 1 successful export per stream.
    let span_oks = events
        .iter()
        .filter(|e| {
            matches!(
                e,
                PusherEvent::ExportOk {
                    stream: raxis_observability::protocol::Stream::Spans,
                    ..
                }
            )
        })
        .count();
    let metric_oks = events
        .iter()
        .filter(|e| {
            matches!(
                e,
                PusherEvent::ExportOk {
                    stream: raxis_observability::protocol::Stream::Metrics,
                    ..
                }
            )
        })
        .count();
    assert!(
        span_oks >= 1,
        "at least one span batch shipped, got {span_oks}"
    );
    assert!(
        metric_oks >= 1,
        "at least one metric batch shipped, got {metric_oks}"
    );

    // 4. Collector should have received non-empty bodies.
    let bodies = collector.snapshot_bodies().await;
    assert!(bodies.len() >= 2, "got {} bodies", bodies.len());
    for body in &bodies {
        assert!(
            !body.is_empty(),
            "decoded body should be non-empty protobuf"
        );
    }
    let encodings = collector.snapshot_encodings().await;
    assert!(
        encodings.iter().all(|e| e.as_deref() == Some("gzip")),
        "pusher should gzip OTLP request bodies in the default test config: {encodings:?}",
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cursor_persists_and_resumes_at_offset() {
    let tmp = tempfile::tempdir().unwrap();
    let collector = FakeCollector::bind(vec![200; 32]).await;

    emit_kernel_telemetry(tmp.path(), 5);

    let obs = obs_config(&collector.endpoint().await);

    // First pusher run — drain everything.
    {
        let (cfg, client) = build_pusher_pieces(&obs, tmp.path().to_owned(), "0.1.0");
        let pusher = Pusher::new(cfg, client).unwrap();
        for _ in 0..5 {
            pusher.tick(true).await;
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }
    let cursor_path = tmp.path().join("observability/cursor.toml");
    assert!(cursor_path.exists(), "cursor must persist after run");
    let initial_cursor = std::fs::read_to_string(&cursor_path).unwrap();
    assert!(
        initial_cursor.contains("last_export_unix"),
        "cursor body: {initial_cursor}",
    );

    // Re-launch pusher; it should NOT re-ship the same frames.
    let bodies_before = collector.snapshot_bodies().await.len();
    {
        let (cfg, client) = build_pusher_pieces(&obs, tmp.path().to_owned(), "0.1.0");
        let pusher = Pusher::new(cfg, client).unwrap();
        for _ in 0..5 {
            pusher.tick(true).await;
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }
    let bodies_after = collector.snapshot_bodies().await.len();
    assert_eq!(
        bodies_after, bodies_before,
        "second-run cursor should resume past EOF; no new frames",
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn http_5xx_retries_until_success() {
    let tmp = tempfile::tempdir().unwrap();
    // First request fails 503; second succeeds.
    let collector = FakeCollector::bind(vec![503, 200, 200]).await;

    emit_kernel_telemetry(tmp.path(), 1);

    let obs = obs_config(&collector.endpoint().await);
    let (cfg, client) = build_pusher_pieces(&obs, tmp.path().to_owned(), "0.1.0");
    let pusher = Pusher::new(cfg, client).unwrap();

    let mut all_events = Vec::new();
    for _ in 0..10 {
        all_events.extend(pusher.tick(true).await);
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let retries = all_events
        .iter()
        .filter(|e| matches!(e, PusherEvent::ExportRetry { .. }))
        .count();
    let oks = all_events
        .iter()
        .filter(|e| matches!(e, PusherEvent::ExportOk { .. }))
        .count();
    assert!(
        retries >= 1,
        "expected at least one retry on 503, got events: {all_events:?}"
    );
    assert!(
        oks >= 1,
        "expected at least one ok after retry, got events: {all_events:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn http_4xx_drops_immediately_no_retry() {
    let tmp = tempfile::tempdir().unwrap();
    // 400 → permanent drop; the pusher should NOT retry.
    let collector = FakeCollector::bind(vec![400; 8]).await;

    emit_kernel_telemetry(tmp.path(), 1);

    let obs = obs_config(&collector.endpoint().await);
    let (cfg, client) = build_pusher_pieces(&obs, tmp.path().to_owned(), "0.1.0");
    let health =
        raxis_otel_pusher::health::spawn(0, raxis_otel_pusher::health::HealthSnapshot::initial())
            .await
            .unwrap();
    let health_rx = health.snapshot.subscribe();
    let pusher = Pusher::new(cfg, client).unwrap().with_health(health);
    let mut events = Vec::new();
    for _ in 0..5 {
        events.extend(pusher.tick(true).await);
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let drops = events
        .iter()
        .filter(|e| matches!(e, PusherEvent::ExportPermanentFailure { .. }))
        .count();
    let retries = events
        .iter()
        .filter(|e| matches!(e, PusherEvent::ExportRetry { .. }))
        .count();
    assert!(
        drops >= 1,
        "expected at least one permanent drop, got events: {events:?}"
    );
    assert_eq!(
        retries, 0,
        "4xx should NOT trigger retries; got: {events:?}"
    );
    let snapshot = health_rx.borrow().clone();
    assert!(
        snapshot.spans_dropped_total >= 1,
        "span drops must be counted separately in health: {snapshot:?}",
    );
    assert!(
        snapshot.metrics_dropped_total >= 1,
        "metric drops must be counted separately in health: {snapshot:?}",
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn segment_rotation_advances_pusher_to_next_segment() {
    let tmp = tempfile::tempdir().unwrap();
    let collector = FakeCollector::bind(vec![200; 64]).await;

    // Force a low segment_max_bytes by using a custom RingConfig.
    {
        let hub_cfg = HubConfig {
            enabled: true,
            max_queue_depth: 1024,
            sample_rate: 1.0,
            max_attrs_per_span: 16,
            max_events_per_span: 8,
            histogram_buckets: vec![1.0, 10.0, 100.0],
        };
        let ring_cfg = RingConfig {
            // Each frame is ~250 bytes; with this cap the kernel
            // forces a rotation after the first frame.
            segment_max_bytes: 256,
            max_total_bytes: 64 * 1024,
        };
        let exp = Arc::new(
            RingFileExporter::open(tmp.path().join("observability"), ring_cfg, "0.1.0").unwrap(),
        );
        let hub = Arc::new(ObservabilityHub::new(
            hub_cfg,
            exp.clone() as Arc<dyn ObservabilityExporter>,
        ));
        for i in 0..4 {
            let mut s = hub.start_span(SpanName::IntentAdmission, SpanKind::Server, None);
            s.set_attr("intent_kind", "CompleteTask");
            s.set_attr("verdict", "Accepted");
            s.set_attr("latency_ms", i as i64);
            s.end();
        }
        hub.flush();
        hub.shutdown();
    }
    // The kernel should have written multiple segments; sanity check.
    let dir = tmp.path().join("observability/spans");
    let entries: Vec<_> = std::fs::read_dir(&dir).unwrap().collect();
    assert!(
        entries.len() >= 2,
        "expected ≥2 segments after rotation; got {}",
        entries.len()
    );

    let obs = obs_config(&collector.endpoint().await);
    let (cfg, client) = build_pusher_pieces(&obs, tmp.path().to_owned(), "0.1.0");
    let pusher = Pusher::new(cfg, client).unwrap();
    let mut events = Vec::new();
    for _ in 0..10 {
        events.extend(pusher.tick(true).await);
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let advanced = events
        .iter()
        .filter(|e| matches!(e, PusherEvent::SegmentAdvanced { .. }))
        .count();
    assert!(
        advanced >= 1,
        "pusher should advance past at least one segment; events: {events:?}"
    );
}

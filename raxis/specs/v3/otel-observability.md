# RAXIS V3 — OpenTelemetry Observability

> **Status:** V3 Planned
> **Depends on:** `audit-retention.md` (V3 Merkle audit format), `extensibility-traits.md` (trait boundaries)
> **R-invariant impact:** None — observability is additive. No R-invariant is weakened or requires amendment. R-7 (Cryptographic Audit Chain) remains the authoritative forensic record; OTel is the operational complement, not a replacement.

---

## §1 — Motivation

RAXIS V2 measures latencies per-event as structured log fields (`latency_ms` on every intent admission, gateway fetch, credential verify, witness submission, operator IPC, and notification delivery). These fields are forensically useful — they live in the audit chain or structured stderr — but operationally painful to consume. An operator answering "what is my p99 intent admission latency over the last hour?" must `raxis log --json | jq` and compute percentiles offline.

V3 adds an OpenTelemetry (OTel) export layer so operators can route RAXIS telemetry into their existing observability stack (Grafana, Datadog, Honeycomb, Jaeger, etc.) without custom tooling.

---

## §2 — Scope

### In scope (V3)

- **Traces:** distributed traces across the intent lifecycle (admission → gateway fetch → witness → completion), credential proxy requests, and verifier execution.
- **Metrics:** histograms and counters for intent admission latency, gateway round-trip, verifier execution time, token consumption, circuit breaker state transitions, notification delivery, and credential proxy latency.
- **Configuration:** `policy.toml` schema for OTel export endpoints, sampling rates, and resource attributes.
- **Trait boundary:** a new `ObservabilityExporter` trait in `extensibility-traits.md` so operators can plug custom backends without kernel code changes.

### Out of scope (V3)

- **Logs export via OTel.** The audit chain (JSONL + Merkle) remains the canonical log surface. OTel log export would create a parallel, weaker log stream that competes with R-7. Operators who want OTel-shaped logs can run a sidecar that tails the audit chain.
- **In-VM agent telemetry.** The planner/executor/reviewer VMs do not emit OTel spans. Intelligence telemetry is structurally untrusted (R-1) and mixing it with authority-side telemetry would compromise the signal. Agent-side observability is a V4 topic with its own trust boundary.
- **Replacing the audit chain.** OTel traces are best-effort, sampled, and non-cryptographic. They augment the audit chain for operational dashboards; they do not replace it for forensic verification.

---

## §3 — Architecture

```
┌─────────────────────────────────────────────────┐
│                   RAXIS Kernel                   │
│                                                  │
│  Intent Handler ──┐                              │
│  Gateway Client ──┤── OTel Span/Metric emit ──►  │
│  Verifier Runner ─┤                              │
│  Credential Proxy ┤     ┌──────────────────┐     │
│  Notification ────┘     │ OTel Batch       │     │
│                         │ Exporter         │─────┼──► OTLP endpoint
│                         │ (background task)│     │    (Grafana, Datadog,
│                         └──────────────────┘     │     Jaeger, etc.)
│                                                  │
│  Audit Writer (unchanged — R-7 chain) ──► JSONL  │
└─────────────────────────────────────────────────┘
```

Key constraints:

1. **OTel export is fire-and-forget.** Export failure NEVER blocks the kernel's commit path, intent admission, or any R-invariant enforcement. A down OTel collector means missing metrics, not missing safety.
2. **No credential leakage.** Spans and metrics MUST NOT contain credential values, API keys, session tokens, or any field marked `Zeroize` in the type system. Resource attributes are operator-declared in `policy.toml`.
3. **Sampling is operator-controlled.** Head-based sampling rate is configurable per signal type. Default: traces 10%, metrics 100% (all counters/histograms exported).
4. **Export runs in a dedicated `tokio::spawn`.** The exporter has its own budget (max batch size, flush interval, export timeout) independent of the kernel's main event loop.

---

## §4 — `policy.toml` Schema

```toml
[observability]
enabled = false                          # master switch; default off

[observability.otlp]
endpoint       = "http://localhost:4317" # gRPC OTLP endpoint
protocol       = "grpc"                 # "grpc" | "http"
export_timeout = "10s"                  # per-batch export timeout
batch_size     = 512                    # max spans/metrics per batch
flush_interval = "5s"                   # batch flush interval

[observability.traces]
enabled     = true
sample_rate = 0.1                       # 10% head-based sampling

[observability.metrics]
enabled          = true
export_interval  = "15s"                # metric export interval

[observability.resource]
# Operator-declared resource attributes (OTel ResourceAttributes)
# These appear on every span and metric as resource labels.
service_name    = "raxis-kernel"
environment     = "production"
# Extra key-value pairs:
[observability.resource.extra]
team       = "platform"
cluster_id = "us-east-1a"
```

`PolicyBundle::validate` enforces:

- `endpoint` is a valid URL with scheme `http://` or `https://`.
- `protocol` is `"grpc"` or `"http"`.
- `sample_rate` is in `[0.0, 1.0]`.
- `batch_size` is in `[1, 8192]`.
- `flush_interval` and `export_timeout` parse as valid durations.
- `service_name` is non-empty.
- No key in `[observability.resource.extra]` starts with `raxis.` (reserved namespace).

---

## §5 — Traces

### §5.1 — Span catalog

| Span name | Parent | Key attributes | Emitted by |
|---|---|---|---|
| `raxis.intent.admission` | root | `intent_kind`, `task_id`, `session_id`, `verdict` | `handlers/intent.rs` |
| `raxis.gateway.fetch` | `intent.admission` (for inference) or root (for egress) | `provider`, `model`, `status_code`, `latency_ms` | `gateway/client.rs` |
| `raxis.verifier.execution` | root | `verifier_name`, `task_id`, `gate_type`, `final_status`, `duration_ms` | `gates/verifier_runner.rs` |
| `raxis.credential_proxy.request` | root | `proxy_type`, `proxy_name`, `method`, `url_prefix`, `latency_ms` | credential proxy crates |
| `raxis.notification.dispatch` | root | `channel_kind`, `channel_id`, `event_kind`, `delivery_ms` | `notifications/mod.rs` |
| `raxis.operator.ipc` | root | `command_kind`, `latency_ms` | `ipc/operator.rs` |
| `raxis.escalation.lifecycle` | root | `escalation_id`, `task_id`, `from_state`, `to_state` | `handlers/escalation.rs` |

### §5.2 — Attribute safety

All span attributes are drawn from a closed allow-list. The following fields are **never** attached to a span:

- `session_token`, `api_key`, `credential_value`, `password`
- `plan_bytes`, `policy_sig`, `operator_key`
- `prompt_text`, `response_text` (model I/O)
- Any field whose Rust type implements `Zeroize`

A CI lint (`xtask/src/otel_attribute_check.rs`) scans all `span.set_attribute()` call sites and rejects any attribute name not in the closed allow-list.

---

## §6 — Metrics

### §6.1 — Metric catalog

| Metric name | Type | Unit | Description |
|---|---|---|---|
| `raxis.intent.admission.duration` | Histogram | `ms` | Intent admission pipeline latency |
| `raxis.intent.admission.total` | Counter | `1` | Total intents admitted (label: `verdict`) |
| `raxis.gateway.fetch.duration` | Histogram | `ms` | Gateway upstream round-trip |
| `raxis.gateway.fetch.total` | Counter | `1` | Total gateway fetches (labels: `provider`, `status_code`) |
| `raxis.verifier.execution.duration` | Histogram | `ms` | Verifier wall-clock execution time |
| `raxis.verifier.execution.total` | Counter | `1` | Total verifier runs (labels: `gate_type`, `final_status`) |
| `raxis.tokens.consumed` | Counter | `1` | Cumulative tokens (labels: `direction={input,output}`, `provider`) |
| `raxis.circuit_breaker.state` | Gauge | — | Current circuit state (labels: `provider`, `state={closed,open,half_open}`) |
| `raxis.credential_proxy.request.duration` | Histogram | `ms` | Credential proxy per-request latency |
| `raxis.notification.delivery.duration` | Histogram | `ms` | Notification channel delivery time |
| `raxis.session.active` | Gauge | — | Currently active sessions (label: `role`) |

### §6.2 — Histogram buckets

Default bucket boundaries (ms): `[1, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000]`

Operator-configurable via `[observability.metrics.histogram_buckets]` if needed.

---

## §7 — Trait Boundary

```rust
/// Extensibility trait for observability export backends.
/// 
/// The kernel ships a built-in `OtlpExporter` impl. Operators with
/// custom backends (Datadog agent, custom TSDB, etc.) implement this
/// trait and register it at boot via `KernelBuilder::observability()`.
///
/// # Safety contract
///
/// - `export_spans` and `export_metrics` MUST be non-blocking.
///   Implementations that perform I/O MUST do so in a spawned task.
/// - Export failure MUST NOT propagate as an error to the caller.
///   The kernel calls these methods fire-and-forget.
/// - Implementations MUST NOT log credential values, session tokens,
///   or any Zeroize-typed field.
pub trait ObservabilityExporter: Send + Sync + 'static {
    /// Export a batch of completed spans.
    fn export_spans(&self, spans: Vec<SpanData>);
    
    /// Export a batch of metric data points.
    fn export_metrics(&self, metrics: Vec<MetricData>);
    
    /// Graceful shutdown — flush pending batches.
    /// Called once during kernel shutdown (after all sessions are
    /// terminated but before the process exits).
    fn shutdown(&self) -> impl Future<Output = ()> + Send;
}
```

---

## §8 — Relationship to R-7

| Property | Audit chain (R-7) | OTel export |
|---|---|---|
| **Purpose** | Forensic verification | Operational dashboards |
| **Integrity** | Cryptographic (SHA-256 chain / Merkle) | None |
| **Completeness** | Every event, no sampling | Sampled (configurable) |
| **Availability** | Must survive kernel crash | Best-effort; loss is acceptable |
| **Independence** | Verifiable without the kernel | Requires OTel collector |
| **Durability** | On-disk JSONL, archived to object store | In-memory batches, flushed periodically |

The audit chain is the **proof**. OTel is the **dashboard**. They serve different audiences (auditor vs. operator) and have different reliability contracts.

---

## §9 — Implementation Roadmap

1. **`crates/observability/`** — new workspace crate. `SpanData`, `MetricData`, `ObservabilityExporter` trait, built-in `OtlpExporter` using `opentelemetry-otlp`.
2. **`policy.toml [observability]`** — schema addition + `PolicyBundle::validate` enforcement.
3. **Kernel boot** — if `observability.enabled`, construct the exporter and inject into subsystems via `Arc<dyn ObservabilityExporter>`.
4. **Instrumentation pass** — add span/metric emit calls to the 7 subsystems in §5.1.
5. **CI lint** — `xtask/src/otel_attribute_check.rs` for attribute safety.
6. **`raxis doctor`** — add `[CHECK] observability.otlp: endpoint reachable` health check.
7. **Documentation** — operator guide for connecting to Grafana/Datadog/Jaeger.

---

## §10 — Dependencies

| Crate | Version | Purpose |
|---|---|---|
| `opentelemetry` | `0.24+` | Core OTel API |
| `opentelemetry-otlp` | `0.17+` | OTLP gRPC/HTTP exporter |
| `opentelemetry_sdk` | `0.24+` | Batch span/metric processor |
| `tonic` | (already in workspace) | gRPC transport for OTLP |

---

## §11 — Testing Contracts

1. **Unit test per metric:** emit a known event, assert the metric counter/histogram was updated.
2. **Span attribute safety test:** programmatically verify no span in the catalog attaches a forbidden attribute.
3. **Export failure isolation test:** mock an unreachable OTLP endpoint, run a full intent admission, assert the intent succeeds and the audit chain is intact.
4. **Sampling test:** set `sample_rate = 0.0`, run 100 intents, assert zero spans exported.
5. **Shutdown flush test:** emit spans, call `shutdown()`, assert the batch was flushed before process exit.
6. **Policy validation test:** invalid `endpoint`, out-of-range `sample_rate`, reserved `raxis.*` resource key — all rejected at `PolicyBundle::validate`.

# RAXIS V3 — OpenTelemetry Observability

> **Status:** V3 Specified.
> **Audience:** Operators integrating RAXIS telemetry into their observability stack (Grafana / Datadog / Honeycomb / Jaeger / Tempo / Mimir / VictoriaMetrics, or any OTLP-compatible collector). Implementers extending the kernel with new spans/metrics. Reviewers verifying that observability extraction does not weaken any `R-*` invariant.
>
> **Cross-references:**
> - `paradigm.md` `R-1`, `R-7` — domain separation; cryptographic audit chain. The audit chain stays the forensic record; OTel is the operational complement.
> - `invariants.md` — adds `INV-OTEL-01..09` (this spec).
> - `v2/extensibility-traits.md §5` — `AuditSink` ordering and the trait-boundary doctrine that this spec mirrors for `ObservabilityExporter`.
> - `v2/host-capacity.md §7` — disk pressure model that the OTel sidecar's local ring buffer also obeys.
> - `v2/audit-paired-writes.md` — the guarantee surface OTel must NOT emulate or compete with.
> - `v3/audit-retention.md` — the canonical "kernel writes locally, separate process exports off-host" architecture this spec re-uses.

---

## §1 — Motivation and Problem Statement

### §1.1 What V2 measures, and what V2 cannot answer

RAXIS V2 already measures latencies, counts, and outcomes per-event as structured fields on the audit chain. Every intent admission carries `latency_ms`. Every gateway fetch carries `status_code`, `bytes`, and `duration_ms`. Every verifier run carries `wall_clock_ms`. Every notification dispatch carries `delivery_ms`. The data is forensically rich and cryptographically chained, which is exactly what `R-7` requires.

But the data is operationally **inert** without an offline pipeline:

- "What is my p99 intent admission latency over the last hour?" requires `raxis log --json | jq | python percentile.py`.
- "Is the gateway latency degraded right now?" requires a human to tail the chain and compute a moving average in their head.
- "Did the circuit breaker for `anthropic` open in the last 10 minutes?" requires a `grep CircuitBreakerStateChanged | tail`.
- "Show me a trace for intent `01J...`" — there is no "trace" object in the audit chain; the operator has to manually correlate seven event IDs to reconstruct it.

Every operator running RAXIS at any meaningful scale ends up with a custom shell pipeline that does the same five things: parse JSONL, bucket events into time windows, compute percentiles, dump them into Prometheus or InfluxDB, and graph them in Grafana. Every operator writes that pipeline differently, badly, and unobservably.

### §1.2 Why a built-in OTel exporter

OpenTelemetry is the lingua franca of operator-facing observability. Every dashboard tool worth using speaks OTLP. Every cloud telemetry vendor accepts OTLP. Every open-source TSDB has an OTLP-compatible front door (Prometheus via the `otlphttp` exporter, VictoriaMetrics via its native OTLP endpoint, Mimir via the same, Jaeger via OTLP gRPC).

By emitting OTLP-shaped traces and metrics from the kernel, we eliminate the per-operator custom pipeline. The operator runs the kernel, points an OTLP collector at it, and gets dashboards on day one.

### §1.3 Why this is V3 and not V2

V2's invariant catalogue (`INV-AUDIT-PAIRED-*`, `INV-VERIFIER-*`, `INV-CRED-KERNEL-01`) is the floor — every property the audit chain must hold under adversarial conditions. Bolting OTel onto V2 risks:

1. **Confusing the trust model.** An operator sees both "audit chain says this happened" and "OTel says this happened" and asks which one to trust. The answer is "always the audit chain", but if they have equal weight in the operator's UI, the answer is unclear.
2. **Allowing a slow OTel exporter to back-pressure admission.** A collector behind a slow VPN tunnel will blow up the kernel's commit path if the export is synchronous.
3. **Allowing a credential leak.** Every span attribute is an opportunity to leak `prompt_text`, `api_key`, or any field that crosses the credential proxy boundary. V2's audit chain has a closed schema and a single review surface; OTel attributes are open-ended by design.

V3 ships OTel only after V2's audit invariants are locked, with a strict additive contract: **OTel can never weaken or replace any audit guarantee**.

---

## §2 — Scope, Non-goals, and the Audit-Chain Boundary

### §2.1 In scope (V3)

| # | Item | Where it lives |
|---|---|---|
| 1 | **Traces** (distributed) for the intent lifecycle, gateway fetches, verifier execution, credential proxy requests, notification delivery, operator IPC commands, and escalation FSM transitions. | `crates/observability/` (new), kernel subsystems instrumented at boundaries. |
| 2 | **Metrics** (counters / histograms / gauges) for admission latency, gateway round-trip, verifier wall-clock time, token consumption, circuit-breaker state, credential proxy latency, notification delivery, active sessions, audit chain length. | Same. |
| 3 | **Configuration** in `policy.toml` (`[observability]`) with strict validation. | `crates/policy/src/bundle.rs` (extended). |
| 4 | **Trait boundary** (`ObservabilityExporter`) so operators with custom backends (Datadog Agent, custom TSDB, in-house gRPC) can plug in without kernel code changes. | `crates/observability/src/exporter.rs`. |
| 5 | **Sidecar pusher binary** (`raxis-otel-pusher`) that owns the OTLP HTTP/gRPC client, runs as a separate process under its own UID, reads kernel-emitted JSONL spans/metrics from a kernel-controlled ring directory, and pushes them off-host. | New workspace member `pusher/`. |
| 6 | **Redaction layer** with a closed attribute allow-list, CI lint, and runtime enforcement. | `crates/observability/src/redact.rs`. |
| 7 | **Health checks** in `raxis doctor` for OTel reachability and pusher liveness. | `cli/src/commands/doctor.rs` (extended). |

### §2.2 Out of scope (V3)

| # | Excluded item | Reason |
|---|---|---|
| 1 | **Logs export via OTel.** | The audit chain (JSONL + hash chain / Merkle) is the canonical log surface (`R-7`). An OTel log stream would create a parallel, weaker log surface that competes with R-7. Operators who want OTel-shaped logs run a sidecar that tails the audit chain — explicitly out-of-tree, so the audit chain stays the single source of truth. |
| 2 | **In-VM agent telemetry.** | Planner / Executor / Reviewer VMs do not emit OTel spans. Intelligence-side telemetry is structurally untrusted (`R-1`); mixing it with authority-side telemetry would compromise both surfaces. Agent-side observability is a V4 topic with its own trust boundary. |
| 3 | **Replacing the audit chain.** | OTel traces are best-effort, sampled, and non-cryptographic. They augment the chain for dashboards; they do not replace it for forensic verification. |
| 4 | **OTel collector embedded in the kernel.** | The kernel does not import any OTLP transport library. All OTLP wire-protocol code lives in `raxis-otel-pusher`. |
| 5 | **Ad-hoc operator-defined attributes.** | The attribute allow-list is closed (§10). Operators cannot inject arbitrary attributes; the only operator-controlled attributes are `[observability.resource]` (resource labels), and even that has a reserved-namespace check. |
| 6 | **Cross-process distributed tracing context propagation across the planner UDS.** | The planner is structurally untrusted. Accepting an `traceparent` header from the planner would let a compromised planner forge trace-graph topology. Authority-side spans are root spans; nothing inherits a planner-supplied trace ID. |

### §2.3 The boundary statement

> **OTel observability is additive. Every safety property of the kernel — including every `R-*` paradigm invariant and every `INV-*` reference invariant — MUST hold whether or not the OTel pipeline is configured, running, healthy, or compromised.**

This is the single rule that makes the rest of the spec coherent. Every design decision below derives from it.

---

## §3 — Architecture

### §3.1 Three-process model

```text
┌────────────────────────────┐
│        raxis-kernel        │
│                            │
│  Intent / Gateway / Vfr /  │
│  Cred Proxy / Notify /     │
│  IPC / Escalation handlers │
│            │               │
│            ▼               │
│  ObservabilityHub          │
│  (in-process)              │
│   - in-memory ring queue   │
│   - bounded by             │
│     `max_queue_depth`      │
│   - drops on overflow      │
│     (counter incremented)  │
│            ▲               │
│            │               │
│  spawn_periodic_flush task │
│  (one tokio task / kernel) │
│   - cadence =              │
│     `[observability.metrics] │
│       .export_interval`    │
│   - calls hub.flush() →    │
│     drains queue → exporter│
│   - WITHOUT THIS LOOP THE  │
│     QUEUE FILLS AND THE    │
│     RING FILE STAYS 0 BYTES│
│            │               │
│            ▼               │
│  RingFileWriter            │
│   - JSONL segments under   │
│     <data_dir>/observability/ │
│   - rotates at             │
│     segment_max_bytes      │
│   - capped at               │
│     max_total_bytes        │
│   - drop-oldest GC         │
└────────────┬───────────────┘
             │ /var/lib/raxis/observability/
             │   ├── spans-NNNN.jsonl
             │   ├── metrics-NNNN.jsonl
             │   └── cursor.toml  (held by pusher)
             │
             ▼
┌────────────────────────────┐
│    raxis-otel-pusher       │
│  (separate process, UID)   │
│                            │
│  - Tails JSONL segments    │
│  - Persists cursor file    │
│  - Batches per OTLP rules  │
│  - HTTPS/gRPC client       │
│  - Retries, jitter, backoff│
└────────────┬───────────────┘
             │ OTLP gRPC :4317  or  HTTPS :4318
             ▼
┌────────────────────────────┐
│  Operator's OTLP collector │
│  (Grafana, Datadog, ...)   │
└────────────────────────────┘
```

### §3.2 Why a separate pusher process

This mirrors `v3/audit-retention.md`'s `raxis-archiver` rationale exactly:

1. **`INV-CRED-KERNEL-01` (`v2/key-revocation.md §3`).** The kernel's outbound network surface is statically bounded to (a) provider HTTPS via the gateway subprocess, (b) `git push` per `auto_push`. Adding an OTLP HTTPS or gRPC client inside the kernel address space expands the most-privileged process's exposure to memory-safety bugs in third-party network code (`tonic`, `tower`, `rustls`, `h2`, `prost`, `opentelemetry-otlp` and its transitive graph — all together significantly larger than the kernel itself). Putting this network code in a separate, less-privileged process is consistent with the rest of the architecture.
2. **Failure isolation.** A wedged OTLP collector (slow TLS handshake, connection refused, hung response) cannot back-pressure the kernel commit path. The kernel writes to a local file; the pusher reads from a local file. The two never share a TCP socket.
3. **Restart isolation.** The pusher can be upgraded, restarted, or disabled without touching the kernel. Operators learning a new OTLP collector quirk can debug the pusher in isolation.
4. **Shared layout with `raxis-archiver`.** Both sidecars consume kernel-emitted local files; both have their own UID; both are managed by systemd / launchd as auxiliary services. One mental model covers both.

### §3.3 The four hard constraints

These are derived from §2.3 and are non-negotiable:

| # | Constraint | Enforced where |
|---|---|---|
| C1 | Export failure NEVER blocks the kernel's commit path, intent admission, or any R-invariant enforcement. | `ObservabilityHub::record_*` is `fn(&self) -> ()` (no `Result`); the underlying queue is bounded and drops on overflow. |
| C2 | No credential leakage. Spans, metrics, and resource attributes MUST NOT contain credential values, API keys, session tokens, model prompts, model responses, file contents, diff bytes, or any field whose Rust type implements `Zeroize`. | Closed allow-list in `crates/observability/src/redact.rs`; CI lint `xtask::otel_attribute_check`; runtime fail-closed redaction. |
| C3 | Sampling is operator-controlled and applied at emit time (head sampling). Tail sampling is out of scope. | `ObservabilityHub::should_sample(span_kind)` is checked before any `record_span` call; metric emission is unsampled (every histogram/counter update lands). |
| C4 | The exporter and pusher are fire-and-forget. Neither the trait nor any impl returns errors that propagate into kernel handlers. | `ObservabilityExporter::export_*` returns `()`. The trait contract is documented as "log internally on failure; never raise". |

### §3.4 What lives where

| Layer | Location | Responsibility |
|---|---|---|
| **Type system** (SpanData, MetricData, attribute schema) | `crates/observability/src/types.rs` | Pure data; no I/O; no time. |
| **Hub** (in-memory queue + ring file writer) | `crates/observability/src/hub.rs` | Owned by the kernel; one instance per process; `Arc<ObservabilityHub>` on `HandlerContext`. |
| **Hub queue-drain task** | `kernel/src/observability_boot.rs::spawn_periodic_flush` | One tokio task per kernel run, spawned by `build_obs_hub` immediately after the hub is constructed. Calls `hub.flush()` every `[observability.metrics].export_interval`. Without this task the in-memory queue fills to `max_queue_depth` and silently drops every subsequent record (`DropReason::QueueFull`); the ring file stays 0 bytes for the entire kernel lifetime. The witness test `kernel/src/observability_boot.rs::tests::periodic_flush_drains_queue_to_ring_file_within_one_interval` pins this contract; the live-e2e Tier-3 assertion in `kernel/tests/extended_e2e_realistic_scenario.rs` re-asserts it over a full realism scenario. |
| **Trait** (`ObservabilityExporter`) | `crates/observability/src/exporter.rs` | The kernel-side exporter abstraction (default impl: `RingFileExporter`). Alternative impls (`InMemoryExporter` for tests, future `TonicExporter` for embedded mode) plug in here. |
| **Redactor** (closed allow-list) | `crates/observability/src/redact.rs` | Applied unconditionally to every span and metric attribute before write. |
| **Sidecar protocol** (JSONL frame format, cursor file) | `crates/observability/src/protocol.rs` | Shared by kernel writer and pusher reader. |
| **Pusher binary** | `pusher/src/main.rs` | Reads frames; speaks OTLP; the only place `opentelemetry-otlp` is imported in the workspace. |
| **CI lint** | `xtask/src/otel_attribute_check.rs` | Walks every `span.set_attribute()` call site at compile time and rejects unknown attribute names. |
| **Health check** | `cli/src/commands/doctor.rs` (additions) | `raxis doctor observability` — checks ring dir is writable, pusher process is running, last successful export `<` configured threshold. |

---

## §4 — Sidecar Protocol (Kernel → Pusher)

### §4.1 Filesystem layout

```text
<data_dir>/observability/
├── spans/
│   ├── 0001.jsonl         # active segment (kernel writes; pusher reads)
│   ├── 0002.jsonl         # rotated; pusher catches up
│   └── ...
├── metrics/
│   ├── 0001.jsonl
│   └── ...
├── cursor.toml            # pusher persists last-acked offsets here
└── lock                   # advisory flock; one pusher at a time
```

### §4.2 Frame format

Every line in a `*.jsonl` segment is one self-contained JSON object — no continuation, no streaming chunks, no partial frames. The kernel writes whole lines with `O_APPEND` semantics (single `write(2)` per frame on Linux; equivalent on macOS) so partial writes during an unclean shutdown leave a single trailing partial line that the pusher detects and ignores.

```jsonc
// span frame
{
  "kind":          "span",
  "schema":        1,
  "trace_id":      "01952c0fe0a07f3781e4f5e6a2a91c00",   // 32 hex
  "span_id":       "8e3a06b7d2c5fa11",                     // 16 hex
  "parent_span_id": null,                                  // or 16-hex string
  "name":          "raxis.intent.admission",
  "start_unix_nanos": 1715000000123456789,
  "end_unix_nanos":   1715000000234567890,
  "kind_otel":     "internal",                             // server | client | producer | consumer | internal
  "status":        "ok",                                   // ok | error
  "status_message": null,                                  // None or short string (≤256B)
  "attrs": {
    "intent_kind":   "CompleteTask",
    "session_id":    "01J...",                             // ULID (NOT secret)
    "task_id":       "01J...",
    "verdict":       "Accepted"
  },
  "events":        []                                      // optional span events; bounded length
}

// metric frame
{
  "kind":          "metric",
  "schema":        1,
  "name":          "raxis.intent.admission.duration",
  "metric_type":   "histogram",                            // counter | histogram | gauge
  "unit":          "ms",
  "labels": {
    "verdict":       "Accepted",
    "intent_kind":   "CompleteTask"
  },
  "datapoint": {
    "value":         42.7,                                 // for counters/gauges, the numeric value
    "buckets":       [1, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000],
    "counts":        [0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0],
    "sum":           42.7,
    "count":         1,
    "min":           42.7,
    "max":           42.7
  },
  "unix_nanos":    1715000000234567890
}
```

The schema field is mandatory and exists exclusively to support backward-compatible evolution. The pusher rejects frames with unknown `schema` values (forward-compat: a pusher built against schema 1 will not silently ship a schema-2 frame whose semantics it does not understand).

### §4.3 Segment rotation

| Trigger | Action |
|---|---|
| Active segment size ≥ `segment_max_bytes` (default 16 MiB) | Close the active fd, rename to `NNNN.jsonl` (next sequence), open a new active segment. Atomic rename — no torn files. |
| Total bytes across all closed segments + active segment ≥ `max_total_bytes` (default 512 MiB) | Drop-oldest GC: delete the lowest-numbered closed segment whose offset is `≤` pusher's persisted cursor. If no such segment exists (pusher is behind by more than the cap), the kernel **stops writing observability frames** and increments `raxis_observability_dropped_due_to_disk_pressure_total`. The kernel does NOT halt admission for disk pressure on the observability subsystem — that would weaken §2.3. |
| Pusher detects a segment with seq < cursor's segment | Pusher re-opens the next segment in order; never seeks backwards. |

### §4.4 Cursor file

The pusher persists its last-acked offset for each stream (spans, metrics) in `cursor.toml`. The kernel never reads or writes this file.

```toml
schema_version = 1

[spans]
last_segment       = 42
last_byte_offset   = 8123456
last_export_unix   = 1715000000

[metrics]
last_segment       = 17
last_byte_offset   = 4567890
last_export_unix   = 1715000000

[health]
last_export_attempt_unix = 1715000000
last_export_success_unix = 1715000000
consecutive_failures     = 0
```

The pusher MUST `fsync` the cursor file after every successful OTLP batch ack, so a pusher crash does not re-export already-shipped batches. (At-most-once is acceptable for the OTel layer; the audit chain is the at-least-once forensic record.)

### §4.5 Lock file

A pusher takes an advisory `flock(LOCK_EX | LOCK_NB)` on `<data_dir>/observability/lock`. Two pushers cannot run concurrently against the same data directory. The kernel does NOT take this lock; the kernel only writes to the segments.

---

## §5 — Configuration Schema (`policy.toml`)

### §5.1 Schema

```toml
[observability]
enabled = false                          # master switch; default off

[observability.ring]
# Local kernel-owned spool directory where SpanData / MetricData JSONL
# segments accumulate. The pusher reads these; the kernel writes them.
# Default: <data_dir>/observability.
dir                = ""                  # empty ⇒ default
segment_max_bytes  = 16777216            # 16 MiB; range [1 MiB, 256 MiB]
max_total_bytes    = 536870912           # 512 MiB; range [16 MiB, 16 GiB]
max_queue_depth    = 8192                # in-memory drop threshold; range [256, 1_048_576]

[observability.traces]
enabled       = true
sample_rate   = 0.1                      # head-based; range [0.0, 1.0]
max_attrs_per_span = 32                  # range [4, 128]
max_events_per_span = 16                 # range [0, 64]

[observability.metrics]
enabled            = true
# How often the kernel-side `spawn_periodic_flush` task drains the
# `ObservabilityHub`'s in-memory queue into the ring file exporter.
# This is the kernel-side queue-drain cadence, NOT the pusher-side
# OTLP batch cadence — see `[observability.pusher].otlp_flush_interval`
# for the latter. The two are independent: the kernel writes JSONL
# frames to disk every `export_interval`; the pusher reads those
# frames and ships them to OTLP every `otlp_flush_interval`.
#
# An enabled hub without this periodic-flush task fails closed
# silently — the queue fills to `[observability.ring].max_queue_depth`,
# every subsequent `record_*` call increments
# `DropReason::QueueFull`, and the JSONL ring file stays 0 bytes for
# the full kernel lifetime. The contract is enforced by the boot-side
# `kernel/src/observability_boot.rs::spawn_periodic_flush` and
# witness-tested by `kernel/src/observability_boot.rs::tests::\
# periodic_flush_drains_queue_to_ring_file_within_one_interval` plus
# the live-e2e Tier-3 assertion in
# `kernel/tests/extended_e2e_realistic_scenario.rs`.
export_interval    = "15s"               # range [1s, 300s]
histogram_buckets  = [1, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000]   # ms

[observability.resource]
# Resource attributes (OTel ResourceAttributes) attached to every span
# and metric. Operator-declared. The reserved namespace `raxis.*`
# (case-insensitive) is rejected at policy validation time.
service_name    = "raxis-kernel"
environment     = "production"

[observability.resource.extra]
team       = "platform"
cluster_id = "us-east-1a"

[observability.pusher]
# Configuration for the separate raxis-otel-pusher binary. The kernel
# does NOT read these fields; the pusher reads its own copy of
# policy.toml (or is launched with --config <path>) and validates them
# the same way. The fields live here so policy validation is one place.
otlp_endpoint     = "https://otlp.example.com:4317"
otlp_protocol     = "grpc"               # "grpc" | "http"
otlp_compression  = "gzip"               # "none" | "gzip" | "zstd"
otlp_export_timeout = "10s"              # per-batch deadline; range [1s, 60s]
otlp_batch_size   = 512                  # spans/metrics per batch; range [1, 8192]
otlp_flush_interval = "5s"               # batch boundary; range [100ms, 60s]
otlp_max_inflight = 4                    # concurrent in-flight batches; range [1, 64]
backoff_initial   = "500ms"
backoff_max       = "30s"
backoff_jitter    = 0.25                 # ±25%; range [0.0, 1.0]

[observability.pusher.tls]
# Optional client TLS to authenticate to the collector. Either both
# cert+key are set, or neither. CA file optional; absent means "use
# system CA roots".
cert_file = ""
key_file  = ""
ca_file   = ""

[observability.pusher.headers]
# Optional static HTTP/gRPC metadata headers (e.g. for vendor auth).
# Values reference credential names declared in
# [[permitted_credentials]] (environment-access-control.md §5.2);
# the pusher resolves them via the `CredentialBackend` at startup
# and never logs the resolved values.
authorization = "@cred:datadog-otel-token"
x-tenant-id   = "platform"
```

### §5.2 Validation rules

`PolicyBundle::validate` enforces:

| Rule | Failure code |
|---|---|
| `enabled = true` requires `[observability.pusher]` to be a fully-formed section. | `FAIL_OBS_PUSHER_REQUIRED` |
| `ring.segment_max_bytes ∈ [1 MiB, 256 MiB]`. | `FAIL_OBS_RING_SEGMENT_SIZE` |
| `ring.max_total_bytes ∈ [16 MiB, 16 GiB]` AND `ring.max_total_bytes ≥ 4 × ring.segment_max_bytes`. | `FAIL_OBS_RING_TOTAL_SIZE`, `FAIL_OBS_RING_TOTAL_TOO_SMALL` |
| `ring.max_queue_depth ∈ [256, 1_048_576]`. | `FAIL_OBS_RING_QUEUE_DEPTH` |
| `traces.sample_rate ∈ [0.0, 1.0]`. | `FAIL_OBS_TRACES_SAMPLE_RATE` |
| `traces.max_attrs_per_span ∈ [4, 128]`, `traces.max_events_per_span ∈ [0, 64]`. | `FAIL_OBS_TRACES_LIMITS` |
| `metrics.export_interval ∈ [1s, 300s]`. | `FAIL_OBS_METRICS_INTERVAL` |
| `metrics.histogram_buckets` is non-empty, strictly increasing, all positive, and length ≤ 64. | `FAIL_OBS_METRICS_BUCKETS` |
| `resource.service_name` non-empty. | `FAIL_OBS_RESOURCE_SERVICE_NAME` |
| No key in `resource.extra` starts with `raxis.` (case-insensitive); no key collides with reserved OTel resource attribute names (`service.*`, `host.*`, `os.*`, `process.*`). | `FAIL_OBS_RESOURCE_RESERVED` |
| `resource.extra` keys match `^[a-z][a-z0-9_-]{0,63}$`. | `FAIL_OBS_RESOURCE_KEY_FORMAT` |
| `resource.extra` values are non-empty UTF-8 strings ≤ 256 bytes. | `FAIL_OBS_RESOURCE_VALUE` |
| `pusher.otlp_endpoint` is a valid URL with scheme `http://` or `https://`; gRPC endpoints in URI form are accepted. | `FAIL_OBS_OTLP_ENDPOINT` |
| `pusher.otlp_protocol ∈ {"grpc", "http"}`. | `FAIL_OBS_OTLP_PROTOCOL` |
| `pusher.otlp_compression ∈ {"none", "gzip", "zstd"}`. | `FAIL_OBS_OTLP_COMPRESSION` |
| `pusher.otlp_batch_size ∈ [1, 8192]`. | `FAIL_OBS_OTLP_BATCH_SIZE` |
| `pusher.otlp_flush_interval ∈ [100ms, 60s]`. | `FAIL_OBS_OTLP_FLUSH_INTERVAL` |
| `pusher.otlp_export_timeout ∈ [1s, 60s]`. | `FAIL_OBS_OTLP_EXPORT_TIMEOUT` |
| `pusher.otlp_max_inflight ∈ [1, 64]`. | `FAIL_OBS_OTLP_INFLIGHT` |
| `pusher.backoff_initial ≤ pusher.backoff_max`; both within `[10ms, 5min]`. | `FAIL_OBS_BACKOFF` |
| `pusher.backoff_jitter ∈ [0.0, 1.0]`. | `FAIL_OBS_JITTER` |
| `pusher.tls.cert_file` and `pusher.tls.key_file` are either both empty or both non-empty. | `FAIL_OBS_TLS_PARTIAL` |
| `pusher.headers.*` values that start with `@cred:` resolve to a `[[permitted_credentials]]` entry; values that do NOT start with `@cred:` are length-checked (≤ 256 bytes) and pattern-checked (no `\r\n`). | `FAIL_OBS_HEADER_CRED_UNKNOWN`, `FAIL_OBS_HEADER_VALUE` |
| `pusher.headers` keys match `^[a-zA-Z0-9_-]+$` and are not in the reserved set `{user-agent, content-type, content-length, te, host, transfer-encoding}`. | `FAIL_OBS_HEADER_KEY` |

The validator runs at policy load and at every `advance_epoch` call; an invalid `[observability]` section refuses the rotation (`FAIL_POLICY_VALIDATION`).

### §5.3 Silent-failure mode (the queue-drain contract)

An enabled `[observability]` section without a kernel-side periodic queue-drain task fails closed silently. The structural truth (`v3/otel-observability.md §3.1`):

> An enabled `ObservabilityHub` MUST have its in-memory queue drained periodically. With no drain, the queue fills to `[observability.ring].max_queue_depth`, every subsequent `record_*` call increments `DropReason::QueueFull`, the JSONL ring file under `<data_dir>/observability/{spans,metrics}/` stays 0 bytes for the full kernel lifetime, the out-of-process `raxis-otel-pusher` tails empty files, and Prometheus / Grafana scrape nothing.

The drain runs on the kernel's main multi-threaded tokio runtime as a single task spawned by `kernel/src/observability_boot.rs::spawn_periodic_flush` immediately after the hub is constructed. Its cadence is `[observability.metrics].export_interval`. The task is suppressed when:

  * `enabled = false` (the hub holds a `NoopExporter`; nothing to drain).
  * `interval.is_zero()` (a defence-in-depth guard against a hand-constructed `HubConfig`; production policy validation forbids zero via `FAIL_OBS_METRICS_INTERVAL`).

The contract is enforced by:

  * **Unit witness**: `kernel/src/observability_boot.rs::tests::periodic_flush_drains_queue_to_ring_file_within_one_interval` — drives a record through `record_intent_admission` after `spawn_periodic_flush`, asserts the ring file is 0 bytes before one interval has elapsed, sleeps `2 × interval + 50 ms`, asserts the ring file is non-zero.
  * **Live-e2e Tier-3 assertion**: `kernel/tests/extended_e2e_realistic_scenario.rs` reads `<data_dir>/observability/metrics/000001.jsonl` after the full realism scenario completes (BEFORE graceful shutdown so a kernel-side `flush()` on shutdown can't mask a missing periodic-flush task) and panics if the file is 0 bytes.

This is `[observability.metrics].export_interval`'s load-bearing semantics; ignore it in code and the entire dashboard surface goes silent.

---

## §6 — Type System

### §6.1 SpanData

```rust
//! crates/observability/src/types.rs

use std::collections::BTreeMap;

/// One completed authority-side span. Pure data; no I/O; no time
/// retrieval. Constructed by `ObservabilityHub::start_span` →
/// `RecordingSpan::end()`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SpanData {
    /// 16-byte trace identifier; rendered hex on the wire.
    pub trace_id:        [u8; 16],
    /// 8-byte span identifier; rendered hex on the wire.
    pub span_id:         [u8; 8],
    /// Optional parent for nested spans (gateway fetch under intent
    /// admission, verifier execution under intent admission, etc.).
    pub parent_span_id:  Option<[u8; 8]>,
    /// Closed enumeration of span names; see §7.1.
    pub name:            SpanName,
    /// OTel SpanKind. RAXIS authority-side spans are mostly
    /// `Internal` (kernel work) and `Client` (gateway/notification
    /// outbound). `Server` is reserved for the `OperatorTransport`
    /// inbound. `Producer`/`Consumer` are unused in V3.
    pub kind:            SpanKind,
    /// Wallclock at span start; nanos since UNIX epoch.
    pub start_unix_nanos: u64,
    /// Wallclock at span end; nanos since UNIX epoch. ALWAYS ≥ start.
    pub end_unix_nanos:  u64,
    /// Pass / fail status. `error` is reserved for kernel-internal
    /// failures (verifier spawn fail, gateway TCP error, etc.) — NOT
    /// for "intent rejected" or "claim insufficient" outcomes, which
    /// are recorded as `ok` with a `verdict` attribute.
    pub status:          SpanStatus,
    /// One-line human-readable status message; ≤ 256 bytes; never
    /// contains credential or model-output bytes (redactor-checked).
    pub status_message:  Option<String>,
    /// Closed allow-list of attributes; see §10. The map is sorted by
    /// key so frame canonicalisation is byte-deterministic.
    pub attrs:           BTreeMap<String, AttrValue>,
    /// Optional span events; bounded by `max_events_per_span`.
    pub events:          Vec<SpanEvent>,
}

#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize)]
pub enum SpanKind { Internal, Server, Client, Producer, Consumer }

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum SpanStatus { Ok, Error }

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SpanEvent {
    pub name:        EventName,
    pub unix_nanos:  u64,
    pub attrs:       BTreeMap<String, AttrValue>,
}

/// Closed enumeration of span names. Adding a new variant is a spec
/// change; the CI lint walks emit sites to ensure they all use one of
/// these names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum SpanName {
    IntentAdmission,
    GatewayFetch,
    VerifierExecution,
    CredentialProxyRequest,
    NotificationDispatch,
    OperatorIpc,
    EscalationLifecycle,
    SessionSpawn,
    PolicyEpochAdvance,
    AuditEmit,
    BreakglassActivation,
    BreakglassAction,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum EventName {
    GateRequired,
    GateSatisfied,
    GateMissing,
    VerifierSpawned,
    BudgetReserved,
    BudgetReleased,
    InferenceTokensReported,
    CircuitOpened,
    CircuitClosed,
    HeartbeatTick,
}
```

### §6.2 AttrValue

```rust
/// Closed-shape attribute value. The redactor only accepts these
/// concrete shapes; anything else is a compile-time impossibility.
/// In particular there is NO `Bytes` variant (would invite raw blob
/// leakage) and NO `Json` variant (would invite open-ended payload
/// leakage). Each variant has bounded size.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum AttrValue {
    /// UTF-8 string ≤ 256 bytes after sanitisation. Newlines, NULs,
    /// and unprintable chars are replaced with `?` by the redactor.
    Str(String),
    /// 64-bit signed integer; covers durations in milliseconds, byte
    /// counts up to 8 EiB, sequence numbers, and similar.
    I64(i64),
    /// 64-bit float; covers histogram quantiles and ratio values.
    F64(f64),
    /// Boolean flag; e.g. `cached`, `circuit_open`.
    Bool(bool),
}
```

### §6.3 MetricData

```rust
/// One aggregated metric data point.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MetricData {
    pub name:         MetricName,
    pub metric_type:  MetricType,
    pub unit:         Unit,
    /// Stable label set; sorted by key on the wire.
    pub labels:       BTreeMap<String, AttrValue>,
    pub datapoint:    DataPoint,
    pub unix_nanos:   u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum MetricName {
    IntentAdmissionDuration,
    IntentAdmissionTotal,
    GatewayFetchDuration,
    GatewayFetchTotal,
    VerifierExecutionDuration,
    VerifierExecutionTotal,
    TokensConsumed,
    CircuitBreakerState,
    CredentialProxyRequestDuration,
    NotificationDeliveryDuration,
    NotificationDeliveryTotal,
    SessionsActive,
    AuditChainLength,
    EscalationsOpen,
    EscalationsClosedTotal,
    BudgetReserved,
    BudgetExceededTotal,
    ObservabilityDroppedTotal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum MetricType { Counter, Histogram, Gauge }

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Unit { Milliseconds, Bytes, Tokens, Connections, None }

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum DataPoint {
    /// Counter or gauge: a single number.
    Sum   { value: f64 },
    /// Histogram with explicit bucket boundaries.
    Histo {
        buckets: Vec<f64>,
        counts:  Vec<u64>,
        sum:     f64,
        count:   u64,
        min:     f64,
        max:     f64,
    },
}
```

---

## §7 — Span Catalog

Every authority-side span has a fixed name, a fixed parent rule, a fixed attribute set, and a single emit site (or a small enumerated set of emit sites). Emit sites that drift are caught by the §10 CI lint.

### §7.1 Span table

| `SpanName` | OTel name | Kind | Parent | Attributes (closed allow-list) | Emit site |
|---|---|---|---|---|---|
| `IntentAdmission` | `raxis.intent.admission` | Internal | root | `intent_kind`, `task_id`, `session_id`, `verdict`, `verdict_reason`, `policy_epoch`, `latency_ms` | `kernel/src/handlers/intent.rs::handle_intent` |
| `GatewayFetch` | `raxis.gateway.fetch` | Client | `IntentAdmission` (when called from inference) or root (egress) | `provider`, `model`, `status_code`, `latency_ms`, `bytes_in`, `bytes_out`, `cached`, `circuit_state` | `kernel/src/gateway/client.rs::fetch` |
| `VerifierExecution` | `raxis.verifier.execution` | Internal | `IntentAdmission` (synchronous spawn) or root (async) | `verifier_name`, `task_id`, `gate_type`, `final_status`, `duration_ms`, `exit_code` | `kernel/src/gates/verifier_runner.rs::run` |
| `CredentialProxyRequest` | `raxis.credential_proxy.request` | Client | `IntentAdmission` (mostly) | `proxy_type`, `proxy_name`, `method`, `url_prefix`, `status_code`, `latency_ms` | `crates/credential-proxy-*/src/lib.rs` |
| `NotificationDispatch` | `raxis.notification.dispatch` | Client | root | `channel_kind`, `channel_id`, `event_kind`, `delivery_ms`, `success` | `kernel/src/notifications/handler/*.rs` |
| `OperatorIpc` | `raxis.operator.ipc` | Server | root | `command_kind`, `latency_ms`, `accepted` | `kernel/src/ipc/operator.rs` |
| `EscalationLifecycle` | `raxis.escalation.lifecycle` | Internal | root | `escalation_id`, `task_id`, `from_state`, `to_state`, `class` | `kernel/src/handlers/escalation.rs` |
| `SessionSpawn` | `raxis.session.spawn` | Internal | root | `role`, `image_alias`, `duration_ms`, `outcome` | `crates/session-spawn/src/lib.rs` |
| `PolicyEpochAdvance` | `raxis.policy.epoch.advance` | Internal | root | `from_epoch`, `to_epoch`, `reason`, `duration_ms` | `kernel/src/policy_manager.rs::advance_epoch` |
| `AuditEmit` | `raxis.audit.emit` | Internal | (any) | `event_kind`, `seq`, `latency_ns` | `crates/audit/src/sink.rs::FileAuditSink::emit` (debug builds only by default; opt-in in release via `traces.audit_emit_enabled`) |
| `BreakglassActivation` | `raxis.breakglass.activation` | Internal | root | `activation_id`, `expires_at_unix`, `activated_by_count`, `success` | `kernel/src/breakglass.rs::activate` |
| `BreakglassAction` | `raxis.breakglass.action` | Internal | root | `activation_id`, `session_id`, `task_id`, `gate_type` | `kernel/src/breakglass.rs::log_breakglass_action` |

### §7.2 Verdict semantics

`IntentAdmission.verdict` is one of `Accepted` | `Rejected` | `Pending`. The detailed reason (claim insufficient, budget overrun, etc.) goes on `verdict_reason` as a coarse machine-friendly token (`MissingWitness`, `BudgetOverrun`, `RateLimitExceeded`, `Unauthorized`, `PolicyViolation`, `Pending`); the rich error string is NEVER attached to the span — it lives only in the audit chain. This preserves `INV-08` (`philosophy.md §1.2`): rejection codes do not leak policy structure. The OTel surface uses the same coarse tokens the audit chain exposes via `IntentResponse::Rejected.reason`.

### §7.3 Sampling

Head sampling is applied at `span.start` time. The decision is per-trace: if the parentless `IntentAdmission` is sampled, every child span emitted under it during that intent's evaluation is also sampled. The decision is computed as:

```rust
fn should_sample(trace_id: [u8; 16], rate: f64) -> bool {
    // Take the low 64 bits of the trace_id, normalise to [0, 1),
    // and compare to the rate. Deterministic per trace_id.
    let low = u64::from_le_bytes(trace_id[8..].try_into().unwrap());
    (low as f64) / (u64::MAX as f64) < rate
}
```

Sampling is monotone: a child span never emits if its trace's root was not sampled. Metric emission is unsampled; counters and histograms always update.

### §7.4 Span event catalog

Span events are within-span timeline annotations. The closed list is in `EventName`. New event names are spec changes.

---

## §8 — Metric Catalog

| `MetricName` | Type | Unit | Labels | Description |
|---|---|---|---|---|
| `IntentAdmissionDuration` | Histogram | ms | `intent_kind`, `verdict` | Wall-clock from request enqueue to response. |
| `IntentAdmissionTotal` | Counter | None | `intent_kind`, `verdict`, `verdict_reason` | Cumulative count of admission decisions. |
| `GatewayFetchDuration` | Histogram | ms | `provider`, `model`, `status_code` | Outbound provider round-trip. |
| `GatewayFetchTotal` | Counter | None | `provider`, `model`, `status_code`, `cached` | Cumulative gateway fetches. |
| `VerifierExecutionDuration` | Histogram | ms | `gate_type`, `final_status` | Verifier wall-clock, from spawn to reap. |
| `VerifierExecutionTotal` | Counter | None | `gate_type`, `final_status` | Cumulative verifier runs. |
| `TokensConsumed` | Counter | Tokens | `direction` (`input`/`output`), `provider`, `model` | Cumulative provider tokens. Cost in micro-dollars is **NOT** an OTel metric — pricing tables are operator-specific and live in the audit chain. |
| `CircuitBreakerState` | Gauge | None | `provider`, `state` (`closed`/`open`/`half_open`) | 1 when this circuit is in the labelled state, else 0. |
| `CredentialProxyRequestDuration` | Histogram | ms | `proxy_type`, `proxy_name`, `status_code` | Per-request latency. |
| `NotificationDeliveryDuration` | Histogram | ms | `channel_kind`, `channel_id`, `success` | Notification handler wall-clock. |
| `NotificationDeliveryTotal` | Counter | None | `channel_kind`, `channel_id`, `success` | Cumulative notification dispatches. |
| `SessionsActive` | Gauge | Connections | `role` (`planner`/`gateway`/`executor`/`reviewer`/`orchestrator`/`verifier`) | Current active sessions per role. |
| `AuditChainLength` | Gauge | None | (none) | Highest audit `seq` durably written. Sampled every export interval. |
| `EscalationsOpen` | Gauge | None | `class` | Currently open escalations per class. |
| `EscalationsClosedTotal` | Counter | None | `class`, `outcome` (`approved`/`rejected`/`expired`/`cancelled`) | Cumulative closed escalations. |
| `BudgetReserved` | Gauge | None | `lane_id` | Current reserved cost per lane. |
| `BudgetExceededTotal` | Counter | None | `lane_id` | Cumulative budget-exceeded admission rejections. |
| `ObservabilityDroppedTotal` | Counter | None | `reason` (`queue_full`/`disk_pressure`/`schema_mismatch`/`redaction_failure`) | Frames the kernel could not persist. **An operator dashboard MUST surface this metric — non-zero value means the dashboard is incomplete.** |
| `IsolationRespawnAttemptedTotal` | Counter | None | `backend`, `image_kind`, `attempt`, `respawn_kind` (`vm_crash`/`orchestrator_no_progress`/`reviewer_rejection`/`unknown`) | Cumulative respawn attempts. `respawn_kind` (iter44 / `INV-OBS-RESPAWN-KIND-LABEL-01`) disambiguates healthy transient-retry churn from logical-deadlock and reviewer-disagreement respawns; the closed lexicon is the load-bearing dashboard contract. |
| `IntentAdmitPredicateEvaluatedTotal` | Counter | None | `intent_kind`, `admissible` (`true`/`false`), `reason` (`ok`/`retry_inadmissible`/`budget_exhausted`/`unknown_lane`/`other`) | Cumulative intent-admit-predicate evaluations. iter44 leading-indicator metric: `admissible="false"` rate trends toward zero as the KSB-capabilities envelope teaches the planner not to submit known-inadmissible intents. The dashboard query `sum(rate(...{admissible="false"}[5m])) / sum(rate(...[5m]))` is the canonical "LLM blind-ask rate" panel. Emitted by the `RetrySubTask` handler on every server-side retry-eligibility decision; the `reason` lexeme is sourced from `raxis_types::intent_admit::RetryInadmissibleReason::observability_lexeme()` and pinned by `INV-KSB-CAPABILITIES-PARITY-01` (the lexeme set is closed; adding a rejection class requires registering a new lexeme + updating this row). The KSB capabilities envelope's `retry_inadmissible_reason` field carries the matching human-readable form so an operator inspecting the dashboard panel can correlate the counter spike against the LLM-visible reason without out-of-band lookup. |
| `KernelRespawnTotal` | Counter | None | `trigger` (`deadlock`/`sigsegv`/`sigabrt`/`exit_70`/`other`), `outcome` (`ok`/`refused_ceiling`/`refused_other`) | Cumulative supervisor-driven kernel respawns observed at boot. iter44 / `INV-OBS-KERNEL-RESPAWN-COVERAGE-01`. The kernel-boot codepath emits `outcome="ok"` when the supervisor sentinel says `Restarting`; the `refused_*` outcome lexemes are reserved for a future supervisor-side emission expansion (the supervisor crate is intentionally observability-isolated today, so kernel-side emission is the structural witness for now). `trigger` is mapped from the supervisor's `last_restart_reason` PascalCase classification + `prev_run_exit_code` per `kernel/src/observability.rs::classify_respawn_trigger`. Cross-ref: `v2/self-healing-supervisor.md §9`. |
| `KernelRespawnDuration` | Histogram | ms | `trigger` | Wall-clock from supervisor restart-decision (sentinel `last_restart_unix_ts`) to kernel-up-and-rehydrated. Wide bucket spread (`[10, 50, 100, 500, 1000, 5000, 30000, 60000, 300000]` ms) per `INV-OBS-KERNEL-RESPAWN-COVERAGE-01`: kernel respawn ranges from sub-second auto-restart through 5 minute crash-loop back-off; the global default `[1..10000]` ms loses all resolution past ten seconds. Per-metric bucket overrides are exposed via `ObservabilityHub::record_histogram_with_buckets`; spec `§8.1` continues to pin the global default for every other histogram. |
| `SupervisorRefusedRestartTotal` | Counter | None | `reason` (`circuit_open`/`operator_stop`/`operator_stop_forced`/`supervisor_gone`/`other`) | Cumulative supervisor refused-restart events observed at kernel boot. iter44 / `INV-OBS-KERNEL-RESPAWN-COVERAGE-01`. Bumped once per kernel boot when the boot path observes a `Halted` sentinel — the operationally meaningful event is "an operator manually bypassed a halted supervisor", which the supervisor crate cannot itself emit (it has already exited by the time the operator starts the kernel directly). `reason` is drawn from the supervisor sentinel's `sub_state` field for `Halted` rows. |
| `OperatorIpcDuration` | Histogram | ms | `command_kind` (closed allow-list — every `OperatorRequest` variant in `raxis_types::operator_wire`, snake_case, see `kernel/src/observability.rs::COMMAND_KIND_CLOSED_SET`), `accepted` (`true`/`false`) | Per-frame operator UDS dispatch latency (kernel-side). iter44 / `INV-OBS-OPERATOR-IPC-COVERAGE-01`. One observation per processed frame; the timer brackets handler dispatch (frame-received → response-built). Wider iter44 bucket override `[1, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000]` ms — operator commands are typically fast (FSM transitions on committed state) but escalation approval / plan-bundle admission can take several hundred milliseconds when signature verification is on the critical path. The 2.5s / 5s tail buckets cover crash-loop and fail-closed paths where the kernel is pathologically slow but still responding. Counterpart of the `OperatorIpc` span (§7.1). |
| `OperatorIpcTotal` | Counter | None | `command_kind`, `accepted` | Cumulative operator UDS dispatches. iter44 / `INV-OBS-OPERATOR-IPC-COVERAGE-01`. One increment per processed frame; rate-equal to `OperatorIpcDuration`'s observation rate. `accepted = false` iff the response is `OperatorResponse::Error` (the sole error envelope per `peripherals.md §3 "Operator socket"`). The dashboard's "accepted vs rejected" panel pivots on this label. |
| `KernelSubstrateIpcRoundtripDuration` | Histogram | ms | `role` (closed allow-list = `{ "planner", "verifier", "gateway", "unknown" }`, see `kernel/src/observability.rs::KERNEL_SUBSTRATE_IPC_ROLE_CLOSED_SET`), `message_kind` (closed allow-list = `{ "intent_request", "witness_submission", "escalation_request", "planner_fetch_request", "planner_exit_notice", "unexpected" }`, snake_case projection of every dispatched `IpcMessage` request variant in `kernel/src/ipc/server.rs::drive_planner_stream`, see `KERNEL_SUBSTRATE_IPC_MESSAGE_KIND_CLOSED_SET`) | Per-frame kernel↔substrate IPC round-trip latency (kernel-side). iter44 slice 4b / `INV-OBS-IPC-ROUNDTRIP-COVERAGE-01`. Wall-clock from frame-received to response-frame-written (or, for the `unexpected` arm, frame-received to drop). Same iter44 IPC bucket override `[1, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000]` ms as `OperatorIpcDuration` — substrate IPC round-trips span sub-millisecond ksb-update probes through multi-second `planner_fetch_request` tool calls (LLM provider invocations via the gateway). The RAII guard `KernelSubstrateIpcRoundtrip` emits the histogram in its `Drop` impl, so the observation lands regardless of handler outcome (`Ok` return, early `?` propagation from `write_frame`, panic unwind). |
| `KernelSubstrateIpcMessagesTotal` | Counter | None | `role`, `message_kind` | Cumulative kernel↔substrate IPC dispatches. iter44 slice 4b / `INV-OBS-IPC-ROUNDTRIP-COVERAGE-01`. One increment per processed frame; rate-equal to `KernelSubstrateIpcRoundtripDuration`'s observation rate. The `unexpected` arm increments too — proving the closed lexicon stays total over `raxis_ipc::IpcMessage`. A non-zero `message_kind="unexpected"` rate at steady state is the leading indicator of a wire-protocol mismatch between a substrate client and the kernel. |
| `KernelSubstrateIpcInflight` | Gauge | None | `role` | Per-`role` count of kernel↔substrate IPC frames the kernel is currently mid-handler on, summed across all live planner streams. iter44 slice 4b / `INV-OBS-IPC-ROUNDTRIP-COVERAGE-01`. Module-global atomic counter that increments before the per-variant handler runs and decrements after the response frame is written; re-emitted as a gauge sample on every increment / decrement so the dashboard sees actual concurrency in real time. A monotonically growing line is the operator's leading indicator of a stuck handler (or a session leak); the gauge MUST return to zero whenever every planner stream is idle (witnessed by the inline `raii_guard_round_trips_inflight_to_zero` test). |

### §8.1 Histogram bucket policy

Default buckets (ms) are `[1, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000]`. Operators MAY override via `[observability.metrics.histogram_buckets]`; the override applies to every metric that does not declare its own buckets in code.

iter44 introduces a small set of perf-metric outliers whose latency profile spans several decades wider than the global default — kernel respawn (10 ms cold-restart through 5 minute crash-loop back-off) is the canonical example. Operator IPC + kernel↔substrate IPC (slices 4a + 4b) share the iter44 IPC-bucket override `[1, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000]` ms — both span sub-millisecond FSM transitions through multi-second handler stalls (signature verification on `approve_plan` for operator IPC; LLM provider RTT on `planner_fetch_request` for substrate IPC). Those metrics use `ObservabilityHub::record_histogram_with_buckets` to declare per-call buckets at the emit site; the per-metric buckets are listed in the relevant `§8` row above. The hub-wide `[observability.metrics.histogram_buckets]` setting remains the single source of truth for every other histogram, so existing dashboards keep rendering against the same cumulative buckets they always have.

### §8.2 Cumulative semantics

Counters in V3 are **monotonic per-process**: they reset on kernel restart. The pusher reports them as monotonic counters in OTLP; collectors that compute deltas across restarts do so via the standard OTel `_total` semantic. Process restarts are visible in the audit chain (`KernelStarted` / `KernelStopped`); operators correlating dashboards with restarts use the audit chain timestamps.

---

## §9 — No Logs Surface (Explicit)

V3 does NOT export logs via OTel. The audit chain (JSONL + hash chain) is the canonical log surface; `R-7` requires it to be the authoritative forensic record. An OTel logs export would create a parallel weaker surface.

Operators who want OTel-shaped logs run an out-of-tree sidecar that tails the audit chain and converts events to `LogRecord` in their preferred shape. RAXIS does not ship that sidecar; the audit chain's structured-event surface is documented enough to write one in 200 lines of any high-level language.

---

## §10 — Redaction and Attribute Allow-list

### §10.1 Allow-list

The allow-list is a `phf::Map<&'static str, AttrSchema>` compiled into `crates/observability/src/redact.rs`. Every span attribute key the kernel ever attaches is in this map. Adding a key is a code change reviewed by the security reviewer.

```rust
//! crates/observability/src/redact.rs (excerpt)

pub static ATTR_ALLOW_LIST: phf::Map<&'static str, AttrSchema> = phf::phf_map! {
    "intent_kind"      => AttrSchema { ty: AttrTy::Str, max_bytes: 32  },
    "task_id"          => AttrSchema { ty: AttrTy::Str, max_bytes: 64  },  // ULID
    "session_id"       => AttrSchema { ty: AttrTy::Str, max_bytes: 64  },  // ULID
    "verdict"          => AttrSchema { ty: AttrTy::Str, max_bytes: 16  },
    "verdict_reason"   => AttrSchema { ty: AttrTy::Str, max_bytes: 32  },
    "policy_epoch"     => AttrSchema { ty: AttrTy::I64, max_bytes: 0   },
    "latency_ms"       => AttrSchema { ty: AttrTy::I64, max_bytes: 0   },
    "provider"         => AttrSchema { ty: AttrTy::Str, max_bytes: 32  },
    "model"            => AttrSchema { ty: AttrTy::Str, max_bytes: 64  },
    "status_code"      => AttrSchema { ty: AttrTy::I64, max_bytes: 0   },
    "bytes_in"         => AttrSchema { ty: AttrTy::I64, max_bytes: 0   },
    "bytes_out"        => AttrSchema { ty: AttrTy::I64, max_bytes: 0   },
    "cached"           => AttrSchema { ty: AttrTy::Bool, max_bytes: 0  },
    "circuit_state"    => AttrSchema { ty: AttrTy::Str, max_bytes: 16  },
    "verifier_name"    => AttrSchema { ty: AttrTy::Str, max_bytes: 64  },
    "gate_type"        => AttrSchema { ty: AttrTy::Str, max_bytes: 64  },
    "final_status"     => AttrSchema { ty: AttrTy::Str, max_bytes: 16  },
    "exit_code"        => AttrSchema { ty: AttrTy::I64, max_bytes: 0   },
    "proxy_type"       => AttrSchema { ty: AttrTy::Str, max_bytes: 16  },
    "proxy_name"       => AttrSchema { ty: AttrTy::Str, max_bytes: 64  },
    "method"           => AttrSchema { ty: AttrTy::Str, max_bytes: 8   },
    "url_prefix"       => AttrSchema { ty: AttrTy::Str, max_bytes: 128 }, // scheme://host[:port] only — never path/query
    "channel_kind"     => AttrSchema { ty: AttrTy::Str, max_bytes: 16  },
    "channel_id"       => AttrSchema { ty: AttrTy::Str, max_bytes: 64  },
    "event_kind"       => AttrSchema { ty: AttrTy::Str, max_bytes: 64  },
    "delivery_ms"      => AttrSchema { ty: AttrTy::I64, max_bytes: 0   },
    "success"          => AttrSchema { ty: AttrTy::Bool, max_bytes: 0  },
    "command_kind"     => AttrSchema { ty: AttrTy::Str, max_bytes: 32  },
    "accepted"         => AttrSchema { ty: AttrTy::Bool, max_bytes: 0  },
    "escalation_id"    => AttrSchema { ty: AttrTy::Str, max_bytes: 64  },
    "from_state"       => AttrSchema { ty: AttrTy::Str, max_bytes: 16  },
    "to_state"         => AttrSchema { ty: AttrTy::Str, max_bytes: 16  },
    "class"            => AttrSchema { ty: AttrTy::Str, max_bytes: 32  },
    "role"             => AttrSchema { ty: AttrTy::Str, max_bytes: 16  },
    "image_alias"      => AttrSchema { ty: AttrTy::Str, max_bytes: 64  },
    "duration_ms"      => AttrSchema { ty: AttrTy::I64, max_bytes: 0   },
    "outcome"          => AttrSchema { ty: AttrTy::Str, max_bytes: 16  },
    "from_epoch"       => AttrSchema { ty: AttrTy::I64, max_bytes: 0   },
    "to_epoch"         => AttrSchema { ty: AttrTy::I64, max_bytes: 0   },
    "reason"           => AttrSchema { ty: AttrTy::Str, max_bytes: 64  },
    "seq"              => AttrSchema { ty: AttrTy::I64, max_bytes: 0   },
    "latency_ns"       => AttrSchema { ty: AttrTy::I64, max_bytes: 0   },
    "lane_id"          => AttrSchema { ty: AttrTy::Str, max_bytes: 32  },
    "activation_id"    => AttrSchema { ty: AttrTy::Str, max_bytes: 64  },
    "expires_at_unix"  => AttrSchema { ty: AttrTy::I64, max_bytes: 0   },
    "activated_by_count" => AttrSchema { ty: AttrTy::I64, max_bytes: 0 },
    "circuit_open"     => AttrSchema { ty: AttrTy::Bool, max_bytes: 0  },
};
```

### §10.2 Forbidden attributes

The allow-list is closed; every other attribute is implicitly forbidden. The CI lint additionally maintains an **explicit denylist** so accidental near-matches are caught with a clear error:

```rust
pub static ATTR_DENYLIST: &[&str] = &[
    "session_token", "api_key", "credential_value", "password",
    "plan_bytes", "policy_sig", "operator_key", "operator_private_key",
    "prompt_text", "response_text", "model_input", "model_output",
    "diff_bytes", "file_content", "blob_bytes",
    "url",  // forbidden — only `url_prefix` (scheme://host[:port]) is allowed
];
```

### §10.3 Runtime fail-closed

`Redactor::sanitize(span)` is called inside `ObservabilityHub::record_span` before the frame is queued. If the redactor rejects an attribute (unknown key, denylisted key, type mismatch, oversized value), the **entire span is dropped**, an internal `ObservabilityDroppedTotal { reason: "redaction_failure" }` counter is incremented, and a one-line `eprintln!` warning fires (rate-limited via `log_throttle`). The span never reaches the ring file. This is fail-closed: a bug in an emit site can never leak; it can only blow a hole in the dashboard, which §8.2's `ObservabilityDroppedTotal` makes visible.

### §10.4 Compile-time CI lint

```text
xtask/src/otel_attribute_check.rs
```

- Walks every `set_attr(span, "<key>", ...)` call site (or the equivalent ergonomic `span.set("<key>", ...)`).
- Asserts every `"<key>"` literal is a key in `ATTR_ALLOW_LIST`.
- Asserts no `"<key>"` literal is in `ATTR_DENYLIST` (defense in depth).
- Asserts no `set_attr` call site reads from a runtime variable for the key (`set_attr(span, &dyn_key, …)`); keys MUST be string literals.
- Run as part of `cargo xtask ci`; failure blocks merge.

### §10.5 Resource attribute reservation

`policy.toml [observability.resource.extra]` keys are operator-controlled, but the validator (§5.2) rejects:

- Any key starting with `raxis.` (case-insensitive).
- Any of the OTel SDK reserved keys: `service.*`, `host.*`, `os.*`, `process.*`, `telemetry.*`, `sdk.*`.

The kernel sets the canonical ones itself (`service.name`, `host.name` if non-empty, `process.pid`, `telemetry.sdk.name = "raxis"`, `telemetry.sdk.version = <kernel version>`).

---

## §11 — Trait Boundary

```rust
//! crates/observability/src/exporter.rs

use std::sync::Arc;
use crate::types::{SpanData, MetricData};

/// Extensibility trait for observability export backends.
///
/// V3 ships exactly one production impl: `RingFileExporter`, which
/// writes JSONL to `<data_dir>/observability/{spans,metrics}/`. Tests
/// use `InMemoryExporter`. Future deployments may plug in
/// `TonicExporter` (in-process OTLP gRPC for trusted environments
/// where the §3.2 process separation is overkill) — that impl lives
/// out-of-tree.
///
/// # Safety contract
///
/// - `export_spans` and `export_metrics` MUST be non-blocking; any
///   I/O MUST go through a dedicated thread or async task. The
///   kernel calls these methods fire-and-forget on its commit path.
/// - Implementations MUST NOT propagate errors. Failure is logged
///   internally; the kernel never sees an `Err`.
/// - Implementations MUST NOT log credential values, model
///   prompt/response bytes, or any field that crosses the redactor.
/// - Implementations MUST be `Send + Sync + 'static` so they can be
///   held as `Arc<dyn ObservabilityExporter>` on `HandlerContext`.
pub trait ObservabilityExporter: Send + Sync + 'static {
    /// Export a batch of completed spans. The slice is owned by the
    /// caller; the impl MUST clone or serialise eagerly.
    fn export_spans(&self, spans: &[SpanData]);

    /// Export a batch of metric data points.
    fn export_metrics(&self, metrics: &[MetricData]);

    /// Graceful shutdown — flush pending batches and release any
    /// file descriptors. Called once during kernel shutdown after
    /// the IPC dispatch loop returns and before `KernelStopped` is
    /// emitted to the audit chain.
    fn shutdown(&self);
}

/// No-op exporter. Used when [observability] enabled = false. Avoids
/// every emit site having to check a boolean — the hub holds an
/// `Arc<dyn ObservabilityExporter>` either way.
pub struct NoopExporter;

impl ObservabilityExporter for NoopExporter {
    fn export_spans(&self, _: &[SpanData])  {}
    fn export_metrics(&self, _: &[MetricData]) {}
    fn shutdown(&self) {}
}
```

The `RingFileExporter` is the kernel's only production impl. It owns the file descriptors for the active span and metric segments under `<data_dir>/observability/`, handles rotation per §4.3, and writes one JSONL frame per export call (the `ObservabilityHub` already batches at the queue layer; the exporter writes whatever the hub hands it).

---

## §12 — `raxis-otel-pusher` Architecture

### §12.1 Process model

`raxis-otel-pusher` is a separate binary in the workspace (member `pusher/`). It runs as its own process under a dedicated UID (`raxis-otel`, conventional GID 992). It has:

- Read access to `<data_dir>/observability/spans/` and `<data_dir>/observability/metrics/`.
- Read+write access to `<data_dir>/observability/cursor.toml` and `<data_dir>/observability/lock`.
- Network egress to the operator-configured OTLP collector.
- **No** access to `kernel.db`, the audit chain, the credentials directory, or any worktree.

### §12.2 Configuration

The pusher reads `policy.toml` (read-only) and consumes ONLY the `[observability.*]` sections plus `[meta]` for diagnostic labels. Other sections are ignored. The pusher does not verify the policy signature — it trusts the kernel-resident `policy.toml` because the kernel's bootstrap already verified it. (A pusher pointing at a different `policy.toml` is the operator's fault and would only mis-tag dashboards; no R-invariant is at risk.)

### §12.3 Main loop

```rust
loop {
    // 1. Open cursor.toml; resume position.
    let cursor = Cursor::load_or_init(&data_dir)?;

    // 2. Open the next segment (spans first, then metrics).
    for stream in &[Stream::Spans, Stream::Metrics] {
        let segment = cursor.open_next_segment(stream)?;
        let mut batch = Batch::new(stream, batch_size);

        loop {
            select! {
                line = segment.read_line() => match line {
                    Some(line) => {
                        let frame = parse_frame(stream, &line)?;
                        batch.push(frame);
                        if batch.is_full() {
                            send_with_retry(&otlp_client, &mut batch).await;
                            cursor.persist(&data_dir)?;
                        }
                    },
                    None => {
                        // EOF on active segment, wait for new bytes.
                        if segment.is_rotated() {
                            cursor.advance_segment(stream);
                            break;
                        }
                        sleep(flush_interval).await;
                    }
                }
                _ = flush_timer.tick() => {
                    if !batch.is_empty() {
                        send_with_retry(&otlp_client, &mut batch).await;
                        cursor.persist(&data_dir)?;
                    }
                }
            }
        }
    }
}
```

Key properties:

- **At-most-once delivery.** Cursor advances after a successful OTLP `Export` ack. A pusher crash before ack re-exports the un-acked tail on restart — but OTel collectors are idempotent for span/metric IDs, so a duplicate is harmless.
- **In-order per stream.** Spans are exported in segment+offset order; metrics likewise. There is no cross-stream ordering guarantee — span `S` and metric `M` for the same intent may arrive in either order at the collector.
- **Bounded memory.** Active batch is bounded by `otlp_batch_size`; flush timer guarantees a stale batch ships within `otlp_flush_interval`.
- **No fan-out.** A pusher delivers to exactly one OTLP endpoint. Multi-collector fan-out is the collector's job (run a Grafana Agent locally that fans out to N upstreams).

### §12.4 Retry, backoff, jitter

- `send_with_retry` retries on `5xx`, gRPC `UNAVAILABLE` / `DEADLINE_EXCEEDED`, TCP connect failures.
- Initial delay = `pusher.backoff_initial`; doubles each attempt (capped at `pusher.backoff_max`); ±`pusher.backoff_jitter` random spread.
- Maximum 8 attempts per batch. After 8 attempts, the pusher logs `OtlpExportPermanentFailure { batch_size, last_error }` and **drops the batch**, advancing the cursor anyway. Dropping is observable via `ObservabilityDroppedTotal { reason: "export_permanent_failure" }` (the pusher emits this back to the kernel via a small write to `<data_dir>/observability/pusher-events.jsonl` which the kernel's heartbeat loop reads at every tick).
- 4xx responses (other than 408, 429) are treated as configuration errors and the batch is dropped immediately with a `OtlpExportClientError { status }` log line — retrying a malformed request will not help.

### §12.5 Health surface

The pusher exposes a tiny HTTP endpoint at `127.0.0.1:<port>/healthz` returning `200 OK` with a JSON body:

```json
{
  "status":                       "ok",
  "last_export_attempt_unix":     1715000000,
  "last_export_success_unix":     1714999990,
  "consecutive_failures":         0,
  "spans_exported_total":         123456,
  "metrics_exported_total":       7890,
  "spans_dropped_total":          0,
  "cursor_lag_segments":          0
}
```

`raxis doctor observability` calls this endpoint and surfaces the result. The port is configured via `[observability.pusher].health_port` (default `:9501`).

### §12.6 Boot ordering

The pusher tolerates any kernel boot ordering:

- **Pusher started before kernel**: ring directory may not exist yet; pusher polls every second until it does, then opens the first segment.
- **Pusher started after kernel**: cursor file initialised at segment 0 / offset 0; pusher catches up over time.
- **Pusher restarted while kernel is running**: cursor.toml is fsynced after every batch ack; resume is exact.

### §12.7 systemd unit (operator reference)

```ini
[Unit]
Description=RAXIS OTel Pusher
After=raxis-kernel.service
Requires=raxis-kernel.service

[Service]
Type=simple
User=raxis-otel
Group=raxis-otel
ExecStart=/usr/local/bin/raxis-otel-pusher --config /etc/raxis/policy.toml --data-dir /var/lib/raxis
Restart=on-failure
RestartSec=5s
NoNewPrivileges=true
ProtectSystem=strict
ReadOnlyPaths=/var/lib/raxis/observability/spans /var/lib/raxis/observability/metrics
ReadWritePaths=/var/lib/raxis/observability/cursor.toml /var/lib/raxis/observability/lock /var/lib/raxis/observability/pusher-events.jsonl
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

---

## §13 — OTLP Export Semantics

### §13.1 Trace export

- One OTel `ResourceSpans` per batch, with the kernel-pinned resource attributes plus the operator's `[observability.resource.extra]`.
- `InstrumentationScope.name = "raxis-kernel"`, `version` = the kernel binary version embedded in the frame metadata. (The pusher reads this from a per-segment header line; the kernel writes it on every segment-rotation.)
- Span `trace_id` and `span_id` are unchanged from the frame.
- Span attributes are converted from `AttrValue` to `KeyValue` 1:1.

### §13.2 Metric export

- Cumulative temporality (the OTLP default for sum/histogram).
- One `ResourceMetrics` per batch.
- Histograms use explicit boundaries (matching `[observability.metrics.histogram_buckets]`).
- Gauges are sampled once per export interval (the kernel updates the gauge value on each event; the pusher reads the most-recent line for a `(MetricName, labels)` tuple in the segment).

### §13.3 Wire compression

`pusher.otlp_compression = "gzip"` (default) is honoured; the pusher delegates to the `tonic`/`reqwest` HTTP client's compression layer. `"zstd"` is supported when the operator's collector advertises it.

---

## §14 — Failure Isolation Model

| Fault | Observable | Kernel impact | Operator action |
|---|---|---|---|
| Pusher process down | `cursor_lag_segments` grows; `last_export_success_unix` stale | None | Restart pusher; segments accumulate up to `max_total_bytes`. |
| OTLP collector down | Pusher retries; `consecutive_failures` rises | None | Fix collector; pusher drains backlog automatically. |
| Pusher disk full (cursor write) | Pusher logs `CursorPersistFailed`; retries | None | Free disk on pusher's volume. |
| Kernel ring dir disk full | Kernel increments `ObservabilityDroppedTotal { reason: "disk_pressure" }`, stops writing observability frames; admission unchanged | **No admission halt** (§3.3 C1) | Free disk; observability resumes automatically. |
| Operator misconfigures `[observability.resource.extra]` with a reserved key | Policy validation rejects | Policy reload fails (`FAIL_OBS_RESOURCE_RESERVED`) | Fix policy. |
| New emit site references undeclared attribute key | CI lint blocks merge | n/a | Add the key to the allow-list (security review). |
| Span emit site references denylisted key | CI lint blocks merge | n/a | Use a different key (security review). |
| Runtime span fails redaction | Span dropped silently; `ObservabilityDroppedTotal { reason: "redaction_failure" }` increments | None | File a bug; the lint should have caught it. |
| OTLP collector returns 4xx | Pusher drops batch; logs `OtlpExportClientError` | None | Inspect collector logs; fix endpoint config. |

---

## §15 — Invariants

### §15.1 R-invariant impact

OTel observability is additive. No `R-*` invariant is weakened. R-7 remains the authoritative forensic record.

### §15.2 New `INV-OTEL-*` invariants (proposed for `invariants.md` mirror)

| ID | Statement | Justification |
|---|---|---|
| `INV-OTEL-01` | Export failure NEVER blocks the kernel commit path. | C1 in §3.3; preserves R-3 / R-4 enforcement. |
| `INV-OTEL-02` | Span and metric attributes are drawn from a closed allow-list; the runtime redactor rejects any attribute outside the list and drops the span. | Prevents credential / prompt / response leakage to the OTel collector. |
| `INV-OTEL-03` | The kernel does NOT import any OTLP transport library. All OTLP wire-protocol code lives in `raxis-otel-pusher`. | Preserves `INV-CRED-KERNEL-01` egress surface. |
| `INV-OTEL-04` | Sampling is head-based and decided at span start; child spans inherit the parent's decision. | Deterministic per-trace; no tail-sampling buffer in the kernel. |
| `INV-OTEL-05` | The `policy.toml [observability.resource.extra]` namespace excludes `raxis.*` and the OTel SDK reserved roots. | Prevents operators from clobbering kernel-pinned resource attributes. |
| `INV-OTEL-06` | Metric counters are monotonic per-process and reset on kernel restart; cumulative cross-restart aggregation is the collector's responsibility. | Avoids in-kernel persistence of metric state, which would compete with the audit chain as a forensic surface. |
| `INV-OTEL-07` | The pusher cursor advances only after the matching OTLP `Export` ack; pusher crash re-exports the un-acked tail. | At-most-once with idempotent collector — no kernel-side bookkeeping required. |
| `INV-OTEL-08` | Disk pressure on the observability ring drops frames; it does NOT halt admission or the audit chain. | Audit chain has its own disk-full halt under `host-capacity.md §7`; observability is best-effort by definition. |
| `INV-OTEL-09` | Authority-side spans are root spans. The kernel never honours a planner-supplied `traceparent` header. | Prevents a compromised planner from forging trace topology. |

---

## §16 — Testing Contracts

V3 OTel test fixtures use **real runtime objects** — no `mock` dispatch indirections — to catch the runtime bugs an integration-level test must catch. The pattern matches `kernel/tests/mock_planner_end_to_end.rs` (real UDS, real frame codec, real handler dispatch, real `Store`, real `AuditWriter`).

### §16.1 Unit tests

- `crates/observability/src/types.rs` round-trip tests for `SpanData` / `MetricData` JSONL serde.
- `crates/observability/src/redact.rs` enforces the allow-list / denylist; exhaustive negative cases (every denylisted key, every type mismatch, oversize string).
- `crates/observability/src/hub.rs` queue overflow → `ObservabilityDroppedTotal` increments.
- `crates/observability/src/exporter.rs` `RingFileExporter` segment rotation at the byte boundary; drop-oldest GC cadence.
- `crates/policy/src/bundle.rs` validation of `[observability]` schema (every `FAIL_OBS_*` failure code has a unit test).
- CI lint test (`xtask/tests/otel_attribute_check.rs`) walks the workspace and asserts every `set_attr` literal is in the allow-list and not in the denylist.

### §16.2 Integration tests

Located in `crates/observability/tests/` and `kernel/tests/`. Each test bootstraps a real `Store`, real `FileAuditSink`, real `ObservabilityHub`, real `RingFileExporter`, and either a real or mock OTLP collector (using `tonic` test-server fixtures).

| File | Coverage |
|---|---|
| `crates/observability/tests/hub_real_emit.rs` | Drive `record_span` and `record_metric` against a real on-disk ring, assert frames land in `<data_dir>/observability/spans/0001.jsonl` byte-perfect. |
| `crates/observability/tests/redact_real_attrs.rs` | Construct spans with every allow-listed key, every denylisted key, and out-of-schema types; assert the allow-listed pass through untouched and the others are dropped with `ObservabilityDroppedTotal` incremented. |
| `crates/observability/tests/rotation_real_segments.rs` | Emit enough spans to force two rotations; assert `0001.jsonl` is closed atomically and `0002.jsonl` opens at the next boundary. |
| `crates/observability/tests/disk_pressure_dropping.rs` | Set `max_total_bytes` to 64 KiB; emit 200 KiB of spans; assert (a) no `Err` propagates, (b) `ObservabilityDroppedTotal { reason: "disk_pressure" }` increments, (c) admission still succeeds. |
| `pusher/tests/cursor_durability.rs` | Drive the pusher against a fixture ring; ack a batch; restart pusher; assert no duplicate export on the wire. |
| `pusher/tests/otlp_grpc_smoke.rs` | Use `tonic::transport::Server` to host a fake OTLP collector; pusher exports against it; assert the trace_id/span_id round-trip is byte-for-byte. |
| `pusher/tests/retry_backoff.rs` | Fake collector responds with `503` for 3 attempts then `200`; assert backoff schedule matches `[backoff_initial, *2, *2]` with jitter within bounds. |
| `kernel/tests/intent_admission_emits_span.rs` | Drive a real `IntentRequest` end-to-end through `mock_planner` → kernel; assert exactly one `IntentAdmission` span lands in the ring with the expected attributes. |
| `kernel/tests/gateway_fetch_under_intent.rs` | Drive an `InferenceRequest`; assert nested `GatewayFetch` span has the parent `IntentAdmission`'s `span_id`. |
| `kernel/tests/observability_failure_does_not_halt_admission.rs` | Mount the ring directory read-only mid-test; assert subsequent admissions still succeed; assert `ObservabilityDroppedTotal { reason: "io_error" }` increments. |
| `kernel/tests/sampling_is_deterministic_per_trace.rs` | Set `sample_rate = 0.5`; emit 1000 intents; assert ~500 spans land and that any given trace_id is either entirely present or entirely absent. |
| `kernel/tests/pusher_health_endpoint.rs` | Spawn a real pusher process against a test ring; curl `127.0.0.1:9501/healthz`; assert JSON shape. |

### §16.3 Conformance test fixture

Per `extensibility-traits.md §1.2`, every trait family ships a conformance fixture. `crates/observability/tests/exporter_conformance.rs` exercises any `Arc<dyn ObservabilityExporter>` against the same scripted span/metric stream and asserts:

- Every span is exported at most once.
- Every metric data point is exported at least once.
- `shutdown()` is idempotent.
- `export_*` never panics on empty input.
- `export_*` is `Send` and can be called from multiple tasks concurrently.

---

## §17 — Implementation Roadmap

The implementation is staged so each step is independently committable, testable, and reviewable. Each step lands as one PR.

| Step | Crate / file | Deliverable | Tests |
|---|---|---|---|
| 1 | `crates/observability/` (new) | Types (SpanData, MetricData, AttrValue, MetricName, SpanName), serde round-trips, redactor with allow-list/denylist. | `types::roundtrip`, `redact::*`. |
| 2 | `crates/observability/` (continued) | `ObservabilityHub` with bounded queue + drop counters; `NoopExporter`; `RingFileExporter` with rotation + drop-oldest GC. | `hub::*`, `exporter::*`. |
| 3 | `crates/policy/src/bundle.rs` | `[observability]` schema, validation, every `FAIL_OBS_*` code. | `validate_observability_*`. |
| 4 | `xtask/src/otel_attribute_check.rs` | CI lint walking emit sites. | `xtask::tests::otel_attribute_check`. |
| 5 | `kernel/src/main.rs` | Boot wiring: construct `ObservabilityHub`, inject `Arc<ObservabilityHub>` into `HandlerContext`, install `RingFileExporter` when `[observability]` enabled. | `kernel/tests/observability_boot.rs`. |
| 6 | `kernel/src/handlers/intent.rs` | `IntentAdmission` span + `IntentAdmissionDuration`/`IntentAdmissionTotal` metrics. | `kernel/tests/intent_admission_emits_span.rs`. |
| 7 | `kernel/src/gateway/client.rs` + `kernel/src/gateway/*.rs` | `GatewayFetch` span + metrics; `CircuitBreakerState` gauge. | `kernel/tests/gateway_fetch_under_intent.rs`. |
| 8 | `kernel/src/gates/verifier_runner.rs` | `VerifierExecution` span + metrics. | `kernel/tests/verifier_emits_span.rs`. |
| 9 | `crates/credential-proxy-*/src/lib.rs` (all) | `CredentialProxyRequest` span + metric (one PR per family is fine). | per-proxy unit tests. |
| 10 | `kernel/src/notifications/*.rs` | `NotificationDispatch` span + metrics. | `notifications_emit_span`. |
| 11 | `kernel/src/ipc/operator.rs` | `OperatorIpc` span + per-command labels. | `operator_ipc_emit_span`. |
| 12 | `kernel/src/handlers/escalation.rs` | `EscalationLifecycle` span; `EscalationsOpen` / `EscalationsClosedTotal` metrics. | `escalation_emit_span`. |
| 13 | `pusher/` (new workspace member) | `raxis-otel-pusher` binary: cursor, batch, OTLP gRPC/HTTP client, retry/backoff, health endpoint. | `pusher::tests::*`. |
| 14 | `cli/src/commands/doctor.rs` | `raxis doctor observability` health check. | `doctor_observability_smoke`. |
| 15 | `kernel/src/main.rs` (final) | Wire `RingFileExporter` into the OTel exporter slot; emit `OtelExporterStarted` audit event on boot. | `observability_boot_emits_audit`. |
| 16 | `release/` artifacts | `raxis-otel-pusher` packaged in installer; systemd unit; Homebrew formula. | release-engineering smoke. |
| 17 | `guides/` | Operator integration guides (Grafana, Datadog, Honeycomb, Jaeger). | n/a. |

The conformance fixture (§16.3) lands alongside Step 2 so any future exporter impl can plug in immediately.

---

## §18 — Dependencies

The kernel address space gains:

| Crate | Version | Justification |
|---|---|---|
| `phf` | `0.11+` | Compile-time perfect-hash maps for `ATTR_ALLOW_LIST` and `ATTR_DENYLIST`. Already in the workspace's transitive graph; we surface it directly. |

The pusher address space gains:

| Crate | Version | Justification |
|---|---|---|
| `opentelemetry` | `0.26+` | Core OTel API. |
| `opentelemetry-otlp` | `0.26+` | OTLP gRPC + HTTP exporter. |
| `opentelemetry_sdk` | `0.26+` | Batch processor + resource detector. |
| `tonic` | `0.12+` | gRPC transport (already in the workspace via gateway-substrate's transitive graph). |
| `prost` | `0.13+` | OTLP wire types (transitive through `opentelemetry-otlp`). |

The kernel does NOT depend on `opentelemetry`, `opentelemetry-otlp`, `tonic`, or `prost`. The CI lint `xtask::deps_check::kernel_excludes_otlp` enforces this — adding any of those names to the kernel's `Cargo.toml` fails the build.

---

## §19 — Operator Quick Start

For an operator with an existing OTLP collector at `https://otlp.example.com:4317`:

1. Set `[observability]` in `policy.toml`:

   ```toml
   [observability]
   enabled = true

   [observability.pusher]
   otlp_endpoint = "https://otlp.example.com:4317"
   otlp_protocol = "grpc"

   [observability.resource]
   service_name = "raxis-kernel"
   environment  = "production"
   ```

2. Re-sign and load the policy: `raxis policy sign && raxis policy push`.
3. Start the pusher: `systemctl start raxis-otel-pusher`.
4. Verify: `raxis doctor observability` → all checks pass.
5. Open the dashboard preset: `raxis dashboard preset import grafana-default.json` (V3 ships a baseline Grafana JSON dashboard at `release/dashboards/grafana-raxis-default.json`).

For an air-gapped deployment without an OTLP collector: leave `[observability].enabled = false` (default). Nothing runs; nothing exports; the audit chain remains the canonical observability surface.

---

## §20 — Future Work (V4+)

- **Tail sampling** with a kernel-local buffer (rejected for V3 to keep the kernel address space minimal).
- **Multi-tenant resource detection** for kernel deployments serving multiple operator orgs (out of scope for V3 — one kernel = one org).
- **Per-metric histogram bucket overrides** (out of scope for V3 — one global bucket policy is enough for the catalog).
- **Logs export via OTel** — a V4 decision once the audit chain export tooling matures and the parallel-surface concern can be revisited.
- **In-VM agent telemetry** — a V4 trust-boundary discussion (`R-1` interaction).
- **Sampling at the planner / executor egress** — out of scope; agent observability lives in its own trust boundary.

---



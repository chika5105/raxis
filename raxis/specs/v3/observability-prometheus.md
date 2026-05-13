# observability-prometheus.md

V3 perf-data spec. Companion to `specs/v3/otel-observability.md`.

This document describes how the kernel's OTel-shaped emit surface
flows into Prometheus + Grafana for operator-facing time-series
visibility, lists every metric the V3 surface exposes, and
documents the live-e2e + perf-harness wiring.

---

## 1. Pipeline

```
raxis-kernel              (in-process)
  |
  |  ObservabilityHub.record_*   (ring file JSONL frames)
  v
<data_dir>/observability/  (per-segment JSONL, drop-oldest GC)
  |
  |  raxis-otel-pusher           (host process; OTLP/HTTP)
  v
otel-collector:4318       (OTLP HTTP receiver)
  |
  |  prometheus exporter         (/metrics on :8889)
  v
prometheus:9090           (5s scrape, 14d retention)
  |
  |  Grafana datasource          (uid `prometheus`)
  v
grafana:3000              (anonymous Viewer; 10 raxis dashboards)
```

The collector is **Option A** from the V3 audit: kernel stays
OTLP-only per `INV-OTEL-03`; the collector swaps the downstream
sink (Prometheus today, Datadog / Honeycomb / managed Tempo
tomorrow) without touching the kernel binary.

## 2. Live-e2e integration

The Prometheus / Grafana / OTel stack is a first-class part of the
live-e2e setup, not a separate dev convenience. Operators bring
the entire surface up with a single command:

```bash
docker compose -f raxis/live-e2e/docker-compose.e2e.yml up -d --wait
```

Three observability services join the upstream service containers
(`postgres`, `mongodb`, `redis`, `smtp`, `mysql`, `mssql`):

| Service          | Image                                                 | Host port              | Purpose |
|---|---|---|---|
| `otel-collector` | `otel/opentelemetry-collector-contrib:0.110.0`       | 4318 (OTLP/HTTP), 8889 (Prometheus exposition), 8888 (collector internal), 13133 (health) | OTLP receiver + Prometheus exposition |
| `prometheus`     | `prom/prometheus:v2.55.1`                             | 9090                  | 14-day retention, scrapes the collector + itself |
| `grafana`        | `grafana/grafana:11.3.0`                              | 3000                  | Anonymous Viewer; auto-provisioned datasource + 10 dashboards |

### 2.1 Persistence

Two named docker volumes hold time-series and Grafana state:

| Volume                                   | Mounted as            | Survives `docker compose down`? |
|---|---|---|
| `raxis-live-e2e-test_prometheus_data`    | `prometheus:/prometheus`           | yes |
| `raxis-live-e2e-test_grafana_data`       | `grafana:/var/lib/grafana`         | yes |

The volumes are wiped only by `docker compose down -v` or
`docker volume rm raxis-live-e2e-test_prometheus_data raxis-live-e2e-test_grafana_data`.
Operators wanting a clean baseline before a regression bisect set
`RAXIS_E2E_OBS_FRESH=1` (see `live-e2e/README.md`).

Both compose files
(`live-e2e/docker-compose.e2e.yml` +
`live-e2e/docker-compose.extended.e2e.yml`) pin the project
namespace via the top-level `name: raxis-live-e2e-test` field so
the auto-generated network and volume prefix is stable regardless
of which directory `docker compose -f` is invoked from. Per-service
`container_name:` directives keep the short brand prefix
(`raxis-e2e-pg`, `raxis-e2e-mongo`, …) for the actual containers.

### 2.1a Prometheus external_labels (cluster tag)

`raxis/observability/prometheus/prometheus.yml` sets one global
`external_label` on every series Prometheus emits:

```yaml
global:
  external_labels:
    cluster: raxis-live-e2e-test
```

The `cluster=raxis-live-e2e-test` label MUST match the compose
project namespace exactly. Grafana dashboards and the live-e2e
validation matrix (`observability/measurements/`) both filter on
this label to scope every series to the live-e2e harness and
distinguish it from a future production-side Prometheus that may
scrape the same metric names against a different `cluster` value.
Operators forking the compose stack onto a non-test namespace MUST
update BOTH the compose `name:` field AND the
`prometheus.yml::external_labels.cluster` value in lockstep — they
are the canonical identifier of "this is the live-e2e namespace"
across the substrate.

### 2.2 Auto-open landing pages

When `RAXIS_E2E_OPEN_OBSERVABILITY=1` is set in the live-e2e run
environment, the Tier-3 artifact block prints (and `open(1)`s on
macOS / `xdg-open`s on Linux) the operator-friendly URLs:

- Grafana overview dashboard:
  `http://127.0.0.1:3000/d/raxis-00-overview`
- Prometheus query view (deep-linked to a sample query):
  `http://127.0.0.1:9090/graph?g0.expr=raxis_isolation_spawn_cold_boot_duration_milliseconds_count&g0.tab=0`
- OTel collector health:
  `http://127.0.0.1:13133/`

The default is OFF so headless / SSH runs do not try to open
browser windows; operators opt in for visual debugging the same
way they opt in to the dashboard browser via `RAXIS_E2E_OPEN_REPO`.

## 3. Metric inventory

Every metric below is defined in
`raxis/crates/observability/src/types.rs::MetricName` and
projected to its OTel-canonical name via
`MetricName::as_otel_name()`. The Prometheus naming convention
follows the OTel-to-Prometheus mapping (`.` -> `_`, durations get
the `_milliseconds_*` suffix family).

Attribute keys are validated against the closed allow-list in
`raxis/crates/observability/src/redact.rs::ALLOW_LIST`. Adding a
key that is not on the list drops the entire metric and bumps
`raxis.observability.dropped.total{drop_reason="attr_not_allowed"}`.

### 3.1 Isolation / VM lifecycle

| Metric (OTel) | Type | Attributes |
|---|---|---|
| `raxis.isolation.spawn.cold_boot.duration`     | Histogram (ms) | `backend`, `image_kind`, `outcome` |
| `raxis.isolation.spawn.host_init.duration`     | Histogram (ms) | `backend`, `image_kind`, `outcome` |
| `raxis.isolation.spawn.guest_init.duration`    | Histogram (ms) | `backend`, `image_kind`, `outcome` |
| `raxis.isolation.spawn.vsock_handshake.duration` | Histogram (ms) | `backend`, `image_kind`, `outcome` |
| `raxis.isolation.spawn.total`                  | Counter        | `backend`, `image_kind`, `outcome`, `failure_class?` |
| `raxis.isolation.respawn_attempted.total`      | Counter        | `backend`, `image_kind`, `attempt`, `respawn_kind` |
| `raxis.isolation.failed_final.total`           | Counter        | `backend`, `image_kind`, `failure_class` |
| `raxis.isolation.scale.event.total`            | Counter        | `direction`, `reason` |
| `raxis.isolation.scale.deferred.total`         | Counter        | `reason` |

### 3.2 Session / initiative lifecycle

| Metric (OTel) | Type | Attributes |
|---|---|---|
| `raxis.session.lifecycle.transition.total`     | Counter        | `from_state`, `to_state`, `agent_type`, `outcome` |
| `raxis.session.duration`                       | Histogram (ms) | `agent_type`, `outcome` |
| `raxis.session.active`                         | Gauge          | `role` |
| `raxis.initiative.duration`                    | Histogram (ms) | `initiative_class`, `outcome` |
| `raxis.initiative.task.in_flight`              | Gauge          | `initiative_class` |

### 3.3 Audit chain

| Metric (OTel) | Type | Attributes |
|---|---|---|
| `raxis.audit.event.append.duration`            | Histogram (ms) | `kind` |
| `raxis.audit.event.confirmed.duration`         | Histogram (ms) | `kind` |
| `raxis.audit.event.append.total`               | Counter        | `kind` |
| `raxis.audit.fsync.failure.total`              | Counter        | `reason` |
| `raxis.audit.chain.length`                     | Gauge          | (none) |
| `raxis.audit.chain.lag`                        | Gauge          | (none) |

### 3.4 Planner / inference

| Metric (OTel) | Type | Attributes |
|---|---|---|
| `raxis.planner.inference.duration`             | Histogram (ms) | `provider`, `model`, `outcome`, `streaming` |
| `raxis.planner.inference.tokens.total`         | Counter        | `provider`, `model`, `direction`, `streaming` |
| `raxis.planner.dispatch.turn.total`            | Counter        | `agent_type`, `outcome` |
| `raxis.planner.tool_call.duration`             | Histogram (ms) | `tool_name`, `outcome` |
| `raxis.planner.retry.total`                    | Counter        | `provider`, `attempt`, `final_outcome` |
| `raxis.intent.admit_predicate.evaluated.total` | Counter        | `intent_kind`, `admissible`, `reason` |

### 3.5 Credential proxies

| Metric (OTel) | Type | Attributes |
|---|---|---|
| `raxis.credential_proxy.connection.duration`   | Histogram (ms) | `service`, `outcome` |
| `raxis.credential_proxy.connection.total`      | Counter        | `service`, `outcome` |
| `raxis.credential_proxy.statement.duration`    | Histogram (ms) | `service`, `operation`, `outcome`, `blocked` |
| `raxis.credential_proxy.bytes.total`           | Counter        | `service`, `direction` |
| `raxis.credential_proxy.policy_block.total`    | Counter        | `service`, `reason` |

### 3.6 Egress / gateway

| Metric (OTel) | Type | Attributes |
|---|---|---|
| `raxis.egress.allowlist.check.duration`        | Histogram (ms) | `outcome` |
| `raxis.egress.allowlist.block.total`           | Counter        | `reason` |
| `raxis.gateway.upstream.duration`              | Histogram (ms) | `provider`, `outcome` |
| `raxis.gateway.fetch.total`                    | Counter        | `provider`, `model?`, `cached`, `status_code` |
| `raxis.tokens.consumed`                        | Counter (tokens) | `provider`, `model?`, `direction` |

### 3.7 Operator dashboard

| Metric (OTel) | Type | Attributes |
|---|---|---|
| `raxis.dashboard.http.request.duration`        | Histogram (ms) | `route`, `http_method`, `http_status` |
| `raxis.dashboard.sse.connection.active`        | Gauge          | `route` |
| `raxis.dashboard.sse.event.total`              | Counter        | `route` |
| `raxis.dashboard.sse.lag.duration`             | Histogram (ms) | `route` |

### 3.8 Reviewer / disagreement

| Metric (OTel) | Type | Attributes |
|---|---|---|
| `raxis.reviewer.review.duration`               | Histogram (ms) | `outcome` |
| `raxis.reviewer.outcome.total`                 | Counter        | `outcome` |
| `raxis.reviewer.disagreement.total`            | Counter        | `revision_round` |
| `raxis.review.revision_round`                  | Histogram (rounds) | (none) |

### 3.9 Git / worktree

| Metric (OTel) | Type | Attributes |
|---|---|---|
| `raxis.git.worktree.provision.duration`        | Histogram (ms) | `role`, `outcome` |
| `raxis.git.merge.duration`                     | Histogram (ms) | `outcome` |
| `raxis.git.commit.total`                       | Counter        | `author_role` |

### 3.10 Process / host + observability self-metrics

| Metric (OTel) | Type | Attributes |
|---|---|---|
| `raxis.kernel.uptime.seconds`                  | Gauge          | (none) |
| `raxis.observability.dropped.total`            | Counter        | `drop_reason` |

### 3.11 Self-healing supervisor (iter44)

| Metric (OTel) | Type | Attributes |
|---|---|---|
| `raxis.kernel.respawn.total`                   | Counter        | `trigger`, `outcome` |
| `raxis.kernel.respawn.duration`                | Histogram (ms) | `trigger` |
| `raxis.supervisor.refused_restart.total`       | Counter        | `reason` |

## 4. Grafana dashboards

Ten dashboards live under
`raxis/observability/grafana/dashboards/` and are auto-provisioned
into the Grafana container under the `raxis` folder:

| File | UID | Dashboard |
|---|---|---|
| `00-overview.json`           | `raxis-00-overview`        | Mission-control entry point |
| `10-isolation.json`          | `raxis-10-isolation`       | VM cold-boot four-tier histograms |
| `20-lifecycle.json`          | `raxis-20-lifecycle`       | Sessions / initiatives / lifecycle transitions |
| `30-audit.json`              | `raxis-30-audit`           | Append latency, chain length, lag, fsync failures |
| `40-planner.json`            | `raxis-40-planner`         | Inference latency / tokens / tool calls / retries |
| `50-credential-proxies.json` | `raxis-50-credproxies`     | Per-service connection / statement / bytes / blocks |
| `60-egress.json`             | `raxis-60-egress`          | Allowlist checks, blocks, gateway upstream RTT |
| `70-dashboard.json`          | `raxis-70-dashboard`       | Operator dashboard HTTP/SSE health |
| `80-budget-reviewer.json`    | `raxis-80-budget-reviewer` | Budget reservation / exceed + reviewer outcomes |
| `90-git.json`                | `raxis-90-git`             | Worktree provision / merge / commit |

The dashboard JSONs target the `prometheus` datasource UID
declared in
`raxis/observability/grafana/provisioning/datasources/prometheus.yaml`;
that uid is the contract every dashboard pins. Renaming the uid
is a coordinated change with every dashboard JSON.

## 5. Perf harness

The `cargo xtask perf` runner in
`raxis/xtask/src/perf.rs` is the canonical way to drive
reproducible measurements against the Prometheus stack:

```bash
cargo xtask perf vm-cold-boot      [--iterations N] [--backend subprocess|apple-vz]
cargo xtask perf audit-throughput  [--iterations N]
cargo xtask perf all               [--iterations N]
```

Stack reuse: the harness probes
`http://127.0.0.1:9090/-/healthy` first; if a live-e2e Prometheus
is already up, it attaches rather than spinning up its own. This
is mandatory — operators must never have two Prometheus
instances competing for port 9090, and the named-volume
persistence story (14-day retention) is owned by the live-e2e
compose file.

Each subcommand emits both:

- a focused per-subcommand markdown report
  (`vm-cold-boot-YYYY-MM-DD.md`,
  `audit-throughput-YYYY-MM-DD.md`, ...) under
  `raxis/observability/measurements/`,
- a consolidated `perf-report-YYYY-MM-DD.md` when invoked via
  `perf all`.

## 6. Dev-loop env vars

| Variable                       | Default | Effect |
|---|---|---|
| `RAXIS_E2E_OPEN_OBSERVABILITY` | OFF     | When set, prints + opens the Grafana / Prometheus / collector URLs at the end of a live-e2e run. |
| `RAXIS_E2E_OBS_FRESH`          | OFF     | When set, wipes `prometheus_data` + `grafana_data` BEFORE the live-e2e run. Use for a clean baseline before a bisect. |
| `RAXIS_E2E_OBS_KEEP_UP`        | ON for live-e2e, OFF for `cargo xtask perf` | When set, leaves the compose stack up after the test exits (operator can keep poking at Grafana). |

Volumes survive `docker compose down` by default; they are wiped
only by `docker compose down -v` or `docker volume rm
raxis-live-e2e-test_prometheus_data raxis-live-e2e-test_grafana_data`.

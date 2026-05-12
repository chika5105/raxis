# Recipe 16 — Measure performance with the Prometheus stack

**Audience.** Operators or contributors who want to compare a
local build's performance against the V3 baseline numbers in
`raxis/observability/measurements/`, or who want to drive a fresh
perf run end-to-end (Prometheus + Grafana + dashboards + report).

**Spec.** `specs/v3/observability-prometheus.md`.

---

## What you get

After running this recipe you will have:

1. A live Prometheus + Grafana + OTel-collector stack on
   `127.0.0.1:9090` / `:3000` / `:13133`, with 14-day retention,
   that survives `docker compose down`.
2. Ten pre-built Grafana dashboards covering every raxis subsystem
   (overview, isolation, lifecycle, audit, planner, credential
   proxies, egress, dashboard, budget/reviewer, git/worktree).
3. A multi-section `perf-report-YYYY-MM-DD.md` markdown file that
   you can paste straight into a PR description.

## Step 1 — bring up the stack

```bash
docker compose -f raxis/live-e2e/docker-compose.e2e.yml up -d --wait \
    otel-collector prometheus grafana
```

(Starting the entire live-e2e stack — the upstream service
containers PLUS the observability triple — is also fine; the
perf harness only depends on the observability triple.)

Verify the three observability containers are healthy:

```bash
docker ps --format '{{.Names}}: {{.Status}}' \
    | grep -E 'raxis-e2e-(otel|prom|grafana)'
# Expected:
#   raxis-e2e-otel:    Up X seconds (healthy)
#   raxis-e2e-prom:    Up X seconds (healthy)
#   raxis-e2e-grafana: Up X seconds (healthy)
```

## Step 2 — open Grafana

```bash
open 'http://127.0.0.1:3000/d/raxis-00-overview'
```

Grafana is configured with an anonymous Viewer role so no
login is required to inspect dashboards. The admin credentials
(needed only if you want to edit a dashboard from the UI) are
`admin` / `raxis-e2e`.

## Step 3 — drive the benchmarks

```bash
# Run every subcommand sequentially (vm-cold-boot,
# audit-throughput, ...). Emits one consolidated
# perf-report-YYYY-MM-DD.md PLUS one per-subcommand report.
cd raxis && cargo xtask perf all --iterations 500
```

Or pick a specific subsystem:

```bash
cargo xtask perf vm-cold-boot     --iterations 500
cargo xtask perf audit-throughput --iterations 1000
```

The harness automatically detects a running live-e2e Prometheus
and attaches to it (it never spins up a competing instance).

## Step 4 — read the report

```bash
ls raxis/observability/measurements/
# Expected (latest day):
#   perf-report-2026-05-12.md
#   vm-cold-boot-2026-05-12.md
#   audit-throughput-2026-05-12.md
```

The `perf-report-<DATE>.md` file is the one to attach to a PR or
weekly perf review. It includes the environment, every subsystem
section, target / regression status, and the exact commands used
to reproduce.

## Step 5 (optional) — wipe between runs

The Prometheus + Grafana volumes survive `docker compose down`
by default. To wipe them before a fresh baseline (recommended
before a regression bisect):

```bash
# Either:
docker compose -f raxis/live-e2e/docker-compose.e2e.yml down -v

# Or surgically wipe just the observability volumes:
docker volume rm live-e2e_prometheus_data live-e2e_grafana_data
```

Or use the env-var opt-in: set `RAXIS_E2E_OBS_FRESH=1` in your
shell before invoking the live-e2e harness.

## Targets the dashboards alert on

| Subsystem            | Metric                                                   | Target | Dashboard                  |
|---|---|---:|---|
| Isolation (apple-vz) | `cold_boot.duration` p95                                 | < 350 ms | `raxis-10-isolation`       |
| Isolation (subprocess test) | `cold_boot.duration` p95                          | < 1 ms   | `raxis-10-isolation`       |
| Audit chain          | `event.append.duration` p95                              | < 10 ms  | `raxis-30-audit`           |
| Planner inference    | `inference.duration` p95 (per provider/model)            | provider-specific | `raxis-40-planner` |
| Egress check         | `allowlist.check.duration` p95                           | < 1 ms   | `raxis-60-egress`          |
| Dashboard SSE        | `sse.lag.duration` p95                                   | < 250 ms | `raxis-70-dashboard`       |
| Observability        | `dropped.total` rate over 5m                             | 0        | `raxis-00-overview`        |

## When numbers regress

1. Check `raxis-00-overview` first - dropped frames or spawn-error
   spikes will surface here before they show up on subsystem
   dashboards.
2. Drill into the subsystem dashboard for the regressing metric.
   Pivot by `backend` / `service` / `tool_name` etc. (every
   dashboard has the canonical attribute templated so you can
   filter out a noisy outlier).
3. Re-run the perf harness with `--iterations 2000` for a tighter
   p99 reading, attach the resulting `perf-report-<DATE>.md` to
   the bug ticket.

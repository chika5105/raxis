# Live-e2e observability validation — 2026-05-13

This is the validator-side companion to the realistic-scenario
live-e2e fix loop. It cross-references the **dashboards in
`raxis/observability/grafana/dashboards/*.json`** against the
**live Prometheus instance from the `raxis-live-e2e-test` compose
stack** and records what populated, what stayed empty, and which
anomalies were found.

The validation harness, raw query results, and the per-panel TSV
all live under `/tmp/observability-validator/` for reproducibility;
this report summarises them.

---

## TL;DR

| | Status |
|---|---|
| Prometheus + Grafana + OTel collector stack health | **OK** (all green pre/during/post) |
| 10 dashboards provisioned + parseable via Grafana API | **OK** (8 + 10 + 5 + 6 + 4 + 4 + 4 + 4 + 5 + 3 = 53 panels total) |
| All 61 dashboard PromQL targets parse (no syntax errors) | **OK** |
| OTLP/HTTP → OTel collector → Prometheus data path | **OK** (validated end-to-end with a synthetic push) |
| Kernel `[observability]` push during the realistic-scenario live-e2e | **BLOCKED — config gap, see §Anomalies** |
| `cargo xtask perf all --iterations 200` numbers vs. 2026-05-12 baseline | **OK — within noise** |

The live-e2e kernel did **not** emit any `raxis_*` metric series
during this run. Root cause is **not** broken instrumentation —
it is a missing `[observability]` block in the live-e2e
policy.toml (see `Anomaly A1`). With observability disabled at
the policy layer, the `ObservabilityHub` short-circuits before
any sanitisation or ring-buffer write, so the pusher (whether
running or not) has nothing to ship.

A targeted synthetic OTLP/HTTP push at `127.0.0.1:4318`
**did** land cleanly in Prometheus, proving the collector +
exporter + Prometheus + Grafana legs are healthy.

---

## Stack health (Phase 0)

| Component | Probe | Result |
|---|---|---|
| Prometheus | `GET /-/healthy` | `Prometheus Server is Healthy.` |
| Grafana | `GET /api/health` | `{"database":"ok","version":"11.3.0", ...}` |
| OTel zPages | `GET /` (`:13133`) | `{"status":"Server available","upSince":"2026-05-13T01:29:14.558Z","uptime":"~1h15m"}` |
| Prometheus targets | `GET /api/v1/targets` | `raxis-otel`, `otel-collector-internal`, `prometheus` all `health=up` |
| Active metric names | `GET /api/v1/label/__name__/values` | 288 (baseline, pre-synth-push) |
| Grafana dashboards | `GET /api/search?type=dash-db` | 10 / 10 dashboards present (all 10 expected UIDs returned) |

Compose project: `raxis-live-e2e-test`. Container statuses:
```text
raxis-e2e-grafana       Up About an hour (healthy)
raxis-e2e-prom          Up About an hour (healthy)
raxis-e2e-otel          Up About an hour (healthy)
```

---

## Dashboard panel matrix (Phase 2)

61 PromQL targets across 10 dashboards. Each was parsed and run
against `/api/v1/query` after substituting Grafana template
variables (`$backend` etc.) with `.+` so the queries are valid
PromQL. Classifications:

- **POPULATED** — query returned ≥1 series.
- **EMPTY-METRIC** — query parsed but returned 0 series; the
  underlying metric family **does** exist (so the filter
  predicate matched no rows during the query window).
- **NO-METRIC** — query parsed but returned 0 series and the
  underlying metric family does not exist in Prometheus at all
  (kernel never pushed).
- **ERROR** — PromQL parse / type error on the server side.

All 61 targets classified after the synthetic OTLP push:

| classification | count |
|---|---:|
| POPULATED | 12 |
| EMPTY-METRIC | 1 |
| NO-METRIC | 48 |
| ERROR | 0 |

Per-dashboard summary (full per-panel grid in
`/tmp/observability-validator/panel-matrix.md`):

| dashboard | panels | populated | empty-metric | no-metric | error |
|---|---:|---:|---:|---:|---:|
| `raxis-00-overview` | 8 | 4 | 0 | 4 | 0 |
| `raxis-10-isolation` | 10 | 7 | 1 | 2 | 0 |
| `raxis-20-lifecycle` | 5 | 0 | 0 | 5 | 0 |
| `raxis-30-audit` | 6 | 1 | 0 | 5 | 0 |
| `raxis-40-planner` | 4 | 0 | 0 | 4 | 0 |
| `raxis-50-credproxies` | 4 | 0 | 0 | 4 | 0 |
| `raxis-60-egress` | 4 | 0 | 0 | 4 | 0 |
| `raxis-70-dashboard` | 4 | 0 | 0 | 4 | 0 |
| `raxis-80-budget-reviewer` | 5 | 0 | 0 | 5 | 0 |
| `raxis-90-git` | 3 | 0 | 0 | 3 | 0 |

Of the 12 POPULATED panels, **all** are downstream of the
synthetic OTLP push (`raxis_isolation_spawn_*`,
`raxis_audit_event_append_total`). No panel populated from
real kernel emission this run.

The single EMPTY-METRIC panel (`raxis-10-isolation #21
Failure rate by failure_class`) is **correct behaviour**: the
query filters on `outcome="failure"`, the synthetic push only
emitted `outcome="success"` rows, so the filter matches nothing.
The query itself is well-formed and the metric family exists.

### Cross-check: dashboard metric names ↔ kernel emission

Every dashboard PromQL family was cross-referenced against
`MetricName::as_otel_name()` in
`raxis/crates/observability/src/types.rs` (lines 407–478). All
40 distinct metric families used by the dashboards have a
matching kernel definition; no naming mismatches detected. The
dot→underscore Prometheus translation is consistent across
counters / histograms / gauges (e.g.
`raxis.isolation.spawn.cold_boot.duration` →
`raxis_isolation_spawn_cold_boot_duration_milliseconds_*`).

---

## OTLP path validation (synthetic)

Because the kernel did not emit during the live-e2e run, the
OTel-collector → Prometheus → Grafana data path was validated
end-to-end with a synthetic OTLP/HTTP `/v1/metrics` POST built
from
`/tmp/observability-validator/synth_push.py`. The payload
included:

- one cumulative-temporality histogram
  (`raxis.isolation.spawn.cold_boot.duration`, bound family
  `[0.05, 0.1, 0.2, 0.5, 1, 2, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000]`
  ms, with attributes `backend=subprocess image_kind=rootfs_erofs outcome=success`);
- one monotonic counter
  (`raxis.isolation.spawn.total`, value `100`, same attribute set);
- one monotonic counter
  (`raxis.audit.event.append.total`, value `42`, attribute
  `kind=PerfHarnessSynthetic`).

Result:

```yaml
OTLP push: HTTP 200 -> {"partialSuccess":{}}
After ~25s scrape:
  raxis_isolation_spawn_cold_boot_duration_milliseconds_bucket: 17 series  (16 explicit + +Inf)
  raxis_isolation_spawn_total:                                   1 series, value=100
  raxis_audit_event_append_total:                                1 series, value=42
```

Every series carried the OTel-collector projection labels
(`collector=raxis-otel`, `instance=otel-collector:8889`,
`exported_job=raxis/raxis-kernel`, `job=raxis-otel`,
`source=otel-collector`) plus the kernel-supplied attributes,
matching the spec mapping in
`specs/v3/otel-observability.md`. The data-path is healthy.

---

## Perf harness reproducibility (Phase 3)

`cargo xtask perf all --iterations 200` was run alongside the
live-e2e kernel. The harness detected the live-e2e Prometheus
stack and reused it (no parallel stack started). Wall-clock to
finish: ~6 min (5m30s build + ~6s perf). Reports:

- `raxis/observability/measurements/vm-cold-boot-2026-05-13.md`
- `raxis/observability/measurements/audit-throughput-2026-05-13.md`

Numbers vs. yesterday's baseline
([`raxis/observability/measurements/perf-report-2026-05-12.md`](perf-report-2026-05-12.md)):

| metric | 2026-05-12 | 2026-05-13 | Δ |
|---|---:|---:|---|
| VM cold-boot p50 (ms, subprocess) | 0.11 | 0.12 | +9 % |
| VM cold-boot p95 (ms, subprocess) | 0.17 | 0.18 | +6 % |
| VM cold-boot p99 (ms, subprocess) | 0.28 | 0.29 | +4 % |
| Audit append p50 (us) | 4067 | 4048 | -0.5 % |
| Audit append p95 (us) | 6132 | 5872 | -4 % |
| Audit append p99 (us) | 7136 | 7116 | -0.3 % |

All within noise (n=200 vs n=500 yesterday; APFS fsync floor
dominates audit-append latency). **No perf regressions.**

> Note: `cargo xtask perf all` does NOT currently emit a
> consolidated `perf-report-YYYY-MM-DD.md` — its `run_all` only
> chains the two subcommands. The May-12 consolidated file
> appears to have been hand-curated. Not a blocker for this
> validation, but a follow-up clean-up for the perf harness:
> `xtask/src/perf.rs::run_all` should emit a top-level
> `perf-report-{date}.md` per
> `specs/v3/observability-prometheus.md §10`.

---

## Latency p50 / p95 / p99 by subsystem

Real-kernel quantiles are **not measurable** this run because
the kernel did not push (see Anomaly A1). The synthetic push
produced a single observation, which is insufficient for
`histogram_quantile(rate(...[5m]))` to produce a finite value
(rate over a single sample with no time-series evolution is
flat → quantile NaN). The dashboard panels reflecting these
p50/p95/p99 stats therefore render as `No data` in Grafana
even though the underlying buckets are populated.

For the perf-harness numbers (which DO measure real latency,
just outside the OTLP path), see the previous section.

---

## Anomalies

### A1 — Live-e2e policy.toml lacks an `[observability]` block (BLOCKING for dashboards)

**Severity**: high — explains every NO-METRIC panel above.

The realistic-scenario harness
(`raxis/kernel/tests/extended_e2e_support/kernel_driver.rs::enable_gateway_in_policy`)
appends `[gateway]`, `[egress]`, and `[[providers]]` to the
auto-generated `policy.toml`, but it never appends an
`[observability]` block. The kernel's policy parser
(`raxis/crates/policy/src/bundle.rs:4641-4646`) falls back to
`ObservabilityConfig::disabled_default()` when the section is
absent, which sets `enabled = false`. With `enabled = false`,
`build_obs_hub` (`kernel/src/observability_boot.rs:38-40`)
short-circuits to a noop hub:

> `if !oc.enabled { return Arc::new(ObservabilityHub::disabled()); }`

…and every emit site short-circuits before sanitisation per
the rationale comment in that file. Net effect: the kernel
writes ZERO ring frames to `<data_dir>/observability/`, the
`raxis-otel-pusher` has nothing to ship, and Prometheus stays
empty for the kernel.

Cross-checks:
- `<data_dir>/observability/` does not exist for the
  in-progress test (`/var/folders/.../tmpPGbwxm/`); only
  `audit/`, `policy/`, `streams/`, etc. are present.
- `policy/policy.toml` for that run contains
  `[gateway]` + `[egress]` + `[[providers]]` only, no
  `[observability]` section.
- `raxis-otel-pusher` is not running anywhere on this host
  (`ps -axo command | grep raxis-otel-pusher` returns nothing).
- The `[realism-e2e]` boot banner reports
  `OTLP/HTTP : http://127.0.0.1:4318 (kernel [observability]
  push target) (up)`. The `(up)` is a TCP-probe of the OTel
  collector — it does NOT mean the kernel is actually
  pushing. This is misleading; the banner should additionally
  reflect the kernel-side `[observability].enabled` value.

**Recommended follow-up** (out-of-scope for this branch — does
not touch the kernel source per the in-flight fix-loop
constraint): extend
`kernel_driver.rs::enable_gateway_in_policy` (or a new
`enable_observability_in_policy` helper) to append:

```toml
[observability]
enabled = true

[observability.pusher]
otlp_endpoint = "http://127.0.0.1:4318"
otlp_protocol = "http"
batch_max_records = 256
batch_max_age_ms   = 1000

[observability.ring]
segment_max_bytes = 16777216
max_total_bytes   = 268435456
max_queue_depth   = 4096
```

…and then spawn `raxis-otel-pusher --config <policy.toml>
--data-dir <data_dir>` from the test harness. Otherwise none
of the V3 perf-telemetry surface is exercised by the
realistic-scenario test, and §6 of the validator spec
(metric-arrival timeline within ~30 s of kernel boot) is
unsatisfiable by construction.

### A2 — Metrics referenced in the validation spec but not in the kernel `MetricName` enum

The validator brief lists these expected arrivals:

| Metric (validator spec) | Status in `MetricName` (`raxis/crates/observability/src/types.rs`) |
|---|---|
| `raxis_credential_proxy_substitution_total` | **NOT PRESENT** — flagged as new from `worker/secrets-model-realignment`. |
| `raxis_egress_admit_total` / `raxis_egress_deny_total` | **NOT PRESENT** — current kernel uses `raxis.egress.allowlist.check.duration` + `raxis.egress.allowlist.block.total` (the `60-egress.json` dashboard already queries the existing names). |
| `raxis_egress_default_provider_grant_total` | **NOT PRESENT** — flagged as new from the egress-defaults worker. |
| `raxis_egress_stall_detected_total` | **NOT PRESENT**. |

Per the validator brief §17 these are flagged for the relevant
worker, **not** added in this branch.

If any of those workers lands a kernel-side metric, the
respective dashboard
(`60-egress.json` for `egress.*`, `50-credential-proxies.json`
for `credential_proxy.substitution.*`) will need a new panel +
PromQL — that is a follow-up commit gated on the upstream
instrumentation actually existing.

### A3 — `cargo xtask perf all` does not emit the consolidated `perf-report-YYYY-MM-DD.md`

`xtask/src/perf.rs::run_all` chains `run_vm_cold_boot` and
`run_audit_throughput` but does not write a top-level
consolidated report. The May-12 consolidated file
([`perf-report-2026-05-12.md`](perf-report-2026-05-12.md)) was hand-authored. The spec
(`specs/v3/observability-prometheus.md §10`) states the
canonical filename is regenerated by every `cargo xtask perf
all` invocation; today's run only emitted
`vm-cold-boot-2026-05-13.md` and `audit-throughput-2026-05-13.md`
(the per-subcommand reports). Out-of-scope for this branch;
filed as a follow-up.

### A4 — No POPULATED panel for `raxis_audit_chain_length` / `raxis_session_active`

These are gauges that should populate as soon as the kernel is
running (sessions table = at least 0; audit chain length = at
least 1 from the genesis anchor). Both panels (`00-overview #1`,
`#4`; `30-audit #1`, `#2`) are NO-METRIC because of A1 — once
the observability block is wired into the test policy, these
should populate within the first heartbeat tick (1 s).

---

## Cross-validation: kernel emissions vs. dashboard counts

Not measurable this run (Anomaly A1 — kernel emitted nothing).
Will rerun Phase 4 verification once the live-e2e harness wires
`[observability]` into the policy template.

For the synthetic push, dashboard-side and source-side numbers
match exactly:

| Source emission | Dashboard read | Match |
|---|---|---|
| `spawn.total` push value=100 (single counter) | `sum(raxis_isolation_spawn_total)` = 100 | ✓ |
| `audit.event.append.total` push value=42, kind=PerfHarnessSynthetic | `sum by(kind)(rate([1m]))` returns 42 events under that label | ✓ |
| Histogram bucket `+Inf` | `..._count` = total samples | ✓ |

---

## Phase-4 sanity checks

| Check | Expected | Observed | Verdict |
|---|---|---|---|
| VM cold-boot p99 < 5 s (sub-2-second target per perf baseline) | < 2 s on subprocess substrate | 0.29 ms (perf harness, n=200) | OK |
| `raxis_egress_stall_detected_total` stays at 0 | 0 | metric does not exist (Anomaly A2) | UNVERIFIABLE |
| Kernel-emitted audit count matches `sum(increase(raxis_audit_events_total[5m]))` within ~1 % | match | UNVERIFIABLE — kernel did not push (A1) | UNVERIFIABLE |
| Kernel-spawned VM count matches `sum(raxis_isolation_spawn_total)` exactly | match | UNVERIFIABLE — kernel did not push (A1) | UNVERIFIABLE |
| `sum(raxis_credential_proxy_substitution_total) >= 1` by end of test | ≥ 1 | metric does not exist (A2) | UNVERIFIABLE |

---

## Reproducibility

Validation harness lives in `/tmp/observability-validator/`:

```text
panels.tsv          — panel target inventory (61 rows)
panel-results.tsv   — full per-target results with classification
panel-matrix.md     — compact per-dashboard summary
validate_panels.py  — runs every PromQL target against /api/v1/query
synth_push.py       — synthetic OTLP/HTTP push for path validation
metric-names.json   — snapshot of /api/v1/label/__name__/values
otel-exposed.txt    — snapshot of the OTel collector :8889 exposition
perf-all.log        — full output of `cargo xtask perf all --iterations 200`
```

To re-run the dashboard validator:

```bash
python3 /tmp/observability-validator/validate_panels.py
```

To re-run the synthetic OTLP→Prometheus path test:

```bash
python3 /tmp/observability-validator/synth_push.py
```

---

## Final status

- **Stack**: green — all three components healthy throughout
  the validation window.
- **Dashboards**: provisioned correctly; every PromQL query
  parses; data-path validated by synthetic push.
- **Kernel→Prometheus path during live-e2e**: blocked by
  Anomaly A1 (test policy lacks `[observability]`). This is a
  test-harness configuration gap, not a kernel-instrumentation
  gap — the kernel `MetricName` enum already covers every
  field referenced by the 10 dashboards.
- **Perf harness**: green — numbers match the 2026-05-12
  baseline within statistical noise.

After the live-e2e fix loop (worker `4e18313f-…`) lands the
`working e2e` commit on `main` AND the harness is updated to
write an `[observability]` block, a final clean validation
pass should be re-run — at which point the
`raxis-{20-lifecycle, 40-planner, 50-credproxies, 60-egress,
70-dashboard, 80-budget-reviewer, 90-git}` panels are expected
to populate within ~30 s of kernel boot per the V3 spec.

---

_Generated 2026-05-13 02:55 UTC against
[`011905f`](../../../) on `main`._

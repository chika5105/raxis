# `raxis-live-e2e`

Live end-to-end test harness for the credential proxies and the
gateway. Every slice in this binary drives a **real** upstream
service (no in-process mocks, no hand-rolled wire fixtures) so a
regression in the proxy's wire-protocol handling cannot hide
behind a fixture that happens to mirror the proxy's own
assumptions.

This README is the operator-side runbook for the un-mocked stack.
The slices' docstrings carry the per-slice contract.

---

## What is and is NOT in scope

| Slice                                        | Real upstream                   | Status      | Notes                                                                                                            |
| -------------------------------------------- | ------------------------------- | ----------- | ---------------------------------------------------------------------------------------------------------------- |
| `postgres-proxy*`                            | `postgres:16-alpine`            | 🟢 active   | Real upstream by default against the compose container; cap-paths covered: `allow_only_select` (`postgres-proxy-restrictions`), `allowed_tables` / `forbidden_tables` / multi-statement ambiguity (`postgres-proxy-table-allowlists`), `max_result_rows` streaming cap (`postgres-proxy-max-result-rows`). `RAXIS_LIVE_POSTGRES_URL` overrides for non-CI debugging. |
| `mongodb-proxy`                              | `mongo:7`                       | 🟢 active   | `--noauth` mode by default; `RAXIS_LIVE_MONGODB_URL` overrides.                                                  |
| `mongodb-proxy-collection-allowlists`        | `mongo:7`                       | 🟢 active   | Auth (SCRAM-SHA-256) against `admin`. Seeds `live_e2e_cap.users` via `docker exec mongosh` and drops on cleanup. |
| `redis-proxy`                                | `redis:7-alpine`                | 🟢 active   | `--requirepass`-protected; the slice drives a real RESP `AUTH` + round-trip.                                     |
| `smtp-proxy`                                 | `mailserver/docker-mailserver`  | 🟢 active   | Postfix + Dovecot SASL. The slice verifies delivery by `docker exec`-ing into the container's Maildir.           |
| `mysql-proxy`                                | `mysql:8.0.36`                  | 🟢 active   | Real upstream by default against the compose container; `RAXIS_LIVE_MYSQL_URL` overrides for non-CI debugging.   |
| `mssql-proxy`                                | SQL Server 2022                 | 🟢 active   | Real upstream by default against the compose container; `RAXIS_LIVE_MSSQL_URL` overrides for non-CI debugging.   |
| `aws-proxy`, `gcp-proxy`, `azure-proxy`      | n/a (V2 IMDS emulator)          | 🟢 active   | V2 proxies SYNTHESISE IMDS responses from the credential backend; they do NOT forward to AWS / GCP / Azure. The slices exercise the synthesizer wire shape on a localhost TCP socket.                                              |
| `aws-proxy-real-endpoint`                    | `https://sts.amazonaws.com/`    | 🟡 V3 witness | Skip-by-default; opt in with `RAXIS_LIVE_CLOUD_NET=1`. Pins the AWS STS canonical `MissingAuthenticationToken` / `InvalidClientTokenId` envelope for the V3 forwarding work. NOT a V2 coverage path — see Phase B notes below.  |
| `gcp-proxy-real-endpoint`                    | `https://oauth2.googleapis.com/`| 🟡 V3 witness | Skip-by-default; opt in with `RAXIS_LIVE_CLOUD_NET=1`. Pins the Google OAuth2 RFC 6749 §5.2 `error` envelope for the V3 forwarding work. NOT a V2 coverage path — see Phase B notes below.                                       |
| `azure-proxy-real-endpoint`                  | `https://login.microsoftonline.com/` | 🟡 V3 witness | Skip-by-default; opt in with `RAXIS_LIVE_CLOUD_NET=1`. Pins the AAD OAuth2 RFC 6749 §5.2 `error` + AAD-specific `error_codes` envelope for the V3 forwarding work. NOT a V2 coverage path — see Phase B notes below.        |
| `http-proxy*`, `gateway-anthropic`           | real HTTPS endpoints            | 🟢 active   | Drive real `https://` upstreams; nothing to un-mock.                                                             |
| `egress-enforcement`, `session-spawn`        | n/a (kernel-internal)           | 🟢 active   | Exercise the kernel's own state machines, not external services.                                                 |

---

## Compose stack

The harness pins every image to a SPECIFIC minor tag (see the
header of `docker-compose.e2e.yml` for the full rationale). A
silent base-image bump is the same class of failure the un-mock
sweep itself was meant to catch.

```bash
# Bring the stack up (hermetic — every `up` is a clean tmpfs slate)
docker compose -f live-e2e/docker-compose.e2e.yml up -d --wait

# Confirm everything is healthy
docker compose -f live-e2e/docker-compose.e2e.yml ps

# Tear down (drops every tmpfs)
docker compose -f live-e2e/docker-compose.e2e.yml down -v
```

Two compose files live in this directory:

* `docker-compose.e2e.yml` — the minimum stack the live-e2e
  slices and `kernel/tests/full_e2e_session_lifecycle.rs` need.
* `docker-compose.extended.e2e.yml` — superset that pre-seeds
  `appdb.seeded_docs` and `raxis_e2e.seeded_rows` for
  `kernel/tests/extended_e2e_*.rs`. It publishes the same ports
  on the same loopback addresses so a slice configured for one
  works against the other unchanged.

Both compose files pin the project namespace to
`raxis-live-e2e-test` via the top-level `name:` field, which
means the auto-generated network and named volumes carry the
same prefix (`raxis-live-e2e-test_default`,
`raxis-live-e2e-test_prometheus_data`,
`raxis-live-e2e-test_grafana_data`) regardless of which directory
you invoke `docker compose -f <path>` from. Per-service
`container_name:` directives in the compose files keep the
short brand prefix (`raxis-e2e-pg`, `raxis-e2e-mongo`, ...) for
the actual containers.

> **Migration note (one-time).** The compose project was
> previously the implicit directory-derived `live-e2e` and is
> now `raxis-live-e2e-test` for namespace clarity on shared
> developer hosts. If you have leftover containers, networks,
> or named volumes from a pre-rename run, do a one-time cleanup
> against the OLD namespace before bringing the stack back up:
>
> ```bash
> docker compose -f live-e2e/docker-compose.e2e.yml -p live-e2e down -v
> ```
>
> Subsequent `up` / `down` invocations pick up the new
> `raxis-live-e2e-test` namespace from the compose file's
> `name:` field with no extra flags required.

Published loopback ports (offset from defaults to avoid colliding
with operator-side databases):

| Service            | Container port | Host port           |
| ------------------ | -------------- | ------------------- |
| `postgres`         | 5432           | `127.0.0.1:54399`   |
| `mongodb`          | 27017          | `127.0.0.1:27399`   |
| `redis`            | 6379           | `127.0.0.1:63799`   |
| `smtp`             | 25             | `127.0.0.1:25199`   |
| `mysql`            | 3306           | `127.0.0.1:33099`   |
| `mssql`            | 1433           | `127.0.0.1:14399`   |

---

## Run the slices

Selecting individual slices keeps the iteration loop tight:

```bash
# All slices (those that need a service will refuse to start if
# the service is not reachable)
RAXIS_LIVE_E2E=1 cargo run -p raxis-live-e2e

# A single slice
RAXIS_LIVE_E2E=1 cargo run -p raxis-live-e2e -- redis-proxy

# Several at once
RAXIS_LIVE_E2E=1 cargo run -p raxis-live-e2e -- redis-proxy smtp-proxy
```

Each slice prints `OK — all selected slices passed` on success
and exits non-zero with an actionable error (which compose
service to start, which env var to set) on failure.

### Postgres + MySQL + MSSQL — active by default

All three SQL-database proxy slices now exercise the real
upstream forwarding path by default against the compose stack
containers. Bring the stack up first and the slices Just Work;
no env-var dance required:

```bash
docker compose -f live-e2e/docker-compose.e2e.yml \
    up -d postgres mysql mssql --wait

RAXIS_LIVE_E2E=1 cargo run -p raxis-live-e2e -- postgres-proxy
RAXIS_LIVE_E2E=1 cargo run -p raxis-live-e2e -- postgres-proxy-restrictions
RAXIS_LIVE_E2E=1 cargo run -p raxis-live-e2e -- postgres-proxy-table-allowlists
RAXIS_LIVE_E2E=1 cargo run -p raxis-live-e2e -- postgres-proxy-max-result-rows
RAXIS_LIVE_E2E=1 cargo run -p raxis-live-e2e -- mysql-proxy
RAXIS_LIVE_E2E=1 cargo run -p raxis-live-e2e -- mssql-proxy
```

The slices TCP-preflight their respective host ports
(`127.0.0.1:54399` for Postgres, `127.0.0.1:33099` for MySQL,
`127.0.0.1:14399` for MSSQL) and fail fast with an actionable
error message if the container isn't reachable.

If you need to point at a non-compose upstream (e.g. an Aurora /
RDS / Azure SQL endpoint for non-CI debugging):

```bash
RAXIS_LIVE_POSTGRES_URL='postgresql://user:pass@host:5432/db' \
    cargo run -p raxis-live-e2e -- postgres-proxy
RAXIS_LIVE_MYSQL_URL='mysql://user:pass@host:3306/db' \
    cargo run -p raxis-live-e2e -- mysql-proxy
RAXIS_LIVE_MSSQL_URL='mssql://user:pass@host:1433/db?encrypt=false' \
    cargo run -p raxis-live-e2e -- mssql-proxy
```

Note: the proxy is plaintext-only on the upstream side (V2.1
MVP); `?encrypt=true` on the MSSQL URL fails fast at
`UpstreamSession::connect`, as does `?sslmode=require` on the
Postgres URL. TLS upstream lands in V3 alongside Windows /
Entra ID auth.

The slices no longer support a hermetic / no-container mode —
the upstream-failure audit path is covered by the unit tests in
`crates/credential-proxy-{postgres,mysql,mssql}/src/upstream.rs::tests`
(Postgres `tokio-postgres` SCRAM-SHA-256 + MD5 path + MySQL
fake-server fixtures + MSSQL `forward_sql_batch` rewrite
fuzzers).

#### Postgres cap-paths covered by real-upstream slices

| Capability                                         | Slice                              | Wire-shape assertion                                                                                                                       |
| -------------------------------------------------- | ---------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------ |
| `allow_only_select` (V2.1 verb-class)              | `postgres-proxy-restrictions`      | `INSERT` / `UPDATE` / `DELETE` ⇒ `ErrorResponse(42501)`; `SELECT` reaches `CommandComplete` against real upstream.                         |
| `allowed_tables` + `forbidden_tables`              | `postgres-proxy-table-allowlists`  | Walker resolves `public.users` → `42501` (`table_not_in_allowed_list`); `public.audit_log` → `42501` (`table_in_forbidden_list`).          |
| Ambiguous SQL (multi-statement) + `enforce=false`  | `postgres-proxy-table-allowlists`  | `SELECT ...; DROP ...` fail-closes with `ambiguous_sql_multi_statement`; audit-only mode admits and surfaces `restriction_reason`.         |
| `max_result_rows` (V2.2 streaming cap)             | `postgres-proxy-max-result-rows`   | `SELECT generate_series(1, 100)` capped at 5: wire shape `T + 5×D + E(54000) + Z`; `queries_capped_by_max_result_rows = 1`; audit carries `upstream_error = "max_result_rows_exceeded"`. |
| SCRAM-SHA-256 / MD5 password auth (Postgres 14+)   | all four slices                    | `tokio-postgres` performs the SASL exchange against the real `raxis_test` user (compose Postgres 16 default = SCRAM).                      |
| TLS upstream (`sslmode=require`)                   | unit test `upstream::tests`        | V2.1 MVP rejects `sslmode=require` at parse time with `FAIL_PROXY_TLS_NOT_SUPPORTED`; V3 lands TLS.                                        |

---

## Transparent-proxy validation tier

Beyond the per-protocol slices in `raxis-live-e2e`, the realism
e2e harness layers a second validation tier that proves the
credential proxy is **transparent to the agent** — a stock
Python program that knows nothing about RAXIS connects via the
proxy, pulls the seeded data, and writes byte-canonical outputs.
The contract, witness module, and assertion order are pinned in
[`raxis/specs/v2/transparent-proxy-validation.md`](../specs/v2/transparent-proxy-validation.md).

### Pieces

* Stock-Python scripts: `live-e2e/seed/scripts/transparent_proxy/`
  (`check_postgres.py`, `check_mongodb.py`, `check_redis.py`,
  `check_smtp.py`, `check_mysql.py`, `check_mssql.py`,
  `run_all_services.sh`, `requirements.txt`).
* Operator-realistic prompt:
  `live-e2e/seed/prompts/transparent_proxy_real_scripts.md`.
* Plan task: `transparent-proxy-realscripts` (a successor of
  `service-round-trip` in the realistic-scenario plan;
  `path_allowlist = ["out/services/", "scripts/last_run_summary.txt"]`).
* Witness module:
  `kernel/tests/extended_e2e_support/transparent_proxy_evidence.rs`.

### Run the scripts standalone (no kernel needed)

The scripts read `*_URL` env vars and have no RAXIS imports, so
an operator can run them directly against the un-mock compose
stack to confirm behaviour outside a kernel-driven flow:

```bash
docker compose -f live-e2e/docker-compose.extended.e2e.yml up -d --wait

cd live-e2e/seed/scripts/transparent_proxy
pip install -r requirements.txt   # or use a venv

DATABASE_URL='postgresql://raxis_test:raxis_test_pass@127.0.0.1:54399/raxis_e2e_pg' \
PG_DATABASE=raxis_e2e_pg \
python3 check_postgres.py --output /tmp/postgres-direct.txt

MONGO_URL='mongodb://127.0.0.1:27399/' \
MONGO_DATABASE=raxis_e2e_mongo \
python3 check_mongodb.py --output /tmp/mongodb-direct.txt

REDIS_URL='redis://:raxis_test_pass@127.0.0.1:63799/0' \
python3 check_redis.py --output /tmp/redis-direct.txt

SMTP_URL='smtp://127.0.0.1:25199/' \
python3 check_smtp.py --output /tmp/smtp-direct.txt

bash run_all_services.sh /tmp/run-all
```

Outputs are byte-canonical (pipe-delimited rows, sorted JSON
lines, etc.). The kernel-driven realism e2e uses the same scripts
through the credential proxies and asserts the resulting bytes
match seed-derived canonicals.

### Witness gating + smoke test

The realistic-scenario test (`cargo test -p raxis-kernel
--test extended_e2e_realistic_scenario`) exercises the
transparent-proxy witness in **two** modes:

1. **Wiring smoke test (default; both gates off).** Builds a
   tempdir fixture, writes the canonical output bytes from the
   `service_evidence` seed shapes, and asserts the witness
   accepts the fixture against a synthetic audit chain. Fast,
   no containers required.
2. **Live-driven (`RAXIS_LIVE_E2E=1 RAXIS_LIVE_E2E_REALISTIC=1`).**
   Stages the scripts into the executor's worktree, lets the
   real LLM-driven Executor task run them through the credential
   proxies, then asserts the chain + worktree against the witness.

---

## Cloud-proxy real-endpoint witnesses (Phase B)

The `*-proxy-real-endpoint` slices were authored as **V3
readiness witnesses**, not as V2 coverage. The V2 cloud proxies
(`AwsProxy`, `GcpProxy`, `AzureProxy`) are IMDS / metadata-server
emulators: they synthesise the wire shape AWS / GCP / Azure SDKs
expect, populated from a `CredentialBackend`-resolved long-lived
key. They do NOT call the real cloud control plane:

  * `AwsProxy` — does not call `sts.amazonaws.com`, does not
    perform SigV4 signing, does not mint scoped STS credentials.
    The deferral to V3 is documented at
    `crates/credential-proxy-aws/src/lib.rs` "What is deferred"
    (`Real sts:AssumeRole round-trip`).
  * `GcpProxy` — does not call `oauth2.googleapis.com`, does not
    perform JWT-bearer assertion exchange. Documented at
    `crates/credential-proxy-gcp/src/lib.rs` "What is deferred"
    (`Real oauth2.googleapis.com exchange`).
  * `AzureProxy` — does not call `login.microsoftonline.com`,
    does not perform OAuth2 client-credentials grant. Documented
    at `crates/credential-proxy-azure/src/lib.rs` "What is
    deferred" (`Real oauth2/v2.0/token exchange`).

The V3 work to land genuine forwarding requires SigV4 / JWT-
bearer / client-credentials grant code that the V2 spec
explicitly defers. Until V3 ships, the `*-real-endpoint` slices
exist to:

  1. Confirm the canonical authentication-failure response
     shapes from the real cloud control planes are stable —
     RFC 6749 §5.2 plus AAD-specific `error_codes` for Azure,
     `MissingAuthenticationToken` / `InvalidClientTokenId` for
     AWS STS.
  2. Provide a green-or-red signal an operator can use to
     answer "is this network egress path reachable?" without
     standing up a full agent VM.
  3. Serve as the wire-shape contract V3 implementers
     pattern-match against when the proxies start forwarding.

Run the witnesses opt-in:

```bash
RAXIS_LIVE_CLOUD_NET=1 cargo run -p raxis-live-e2e -- \
    aws-proxy-real-endpoint
RAXIS_LIVE_CLOUD_NET=1 cargo run -p raxis-live-e2e -- \
    gcp-proxy-real-endpoint
RAXIS_LIVE_CLOUD_NET=1 cargo run -p raxis-live-e2e -- \
    azure-proxy-real-endpoint
```

Without the env var the slices skip with an actionable hint
(matching the MySQL/MSSQL preflight pattern). They do NOT
require any cloud credentials — the assertion is on the
canonical _unauthenticated_ error shape.

### V3 forwarding witness (the V3 work has landed)

When **both** `RAXIS_LIVE_CLOUD_NET=1` and
`RAXIS_V3_CLOUD_FORWARDING=1` are set, each
`*-proxy-real-endpoint` slice replaces the no-proxy baseline
with an end-to-end V3 forwarding witness:

* `aws-proxy-real-endpoint` — binds an in-process
  `AwsProxy::bind_v3` with a deliberately invalid IAM key,
  dials the loopback IMDS endpoint, and asserts the proxy
  signed an `sts:AssumeRole` with the bad key, POSTed it to
  `sts.amazonaws.com`, and mirrored the 4xx `<ErrorResponse>`
  envelope back. Exercises the SigV4 sign-and-dispatch path.
* `gcp-proxy-real-endpoint` — generates a throwaway RSA-2048
  key at startup, builds a synthetic service-account JSON
  body, binds an in-process `GcpProxy::bind_v3`, and dials
  the metadata-server `/token` endpoint. Asserts the proxy
  minted a JWT, POSTed the JWT-bearer-grant to
  `oauth2.googleapis.com`, received an RFC 6749 §5.2 4xx
  envelope, and mirrored it back. The PEM and synthetic
  email are asserted absent from the in-VM response.
* `azure-proxy-real-endpoint` — binds an in-process
  `AzureProxy::bind_v3` with a synthetic service-principal
  env body, dials the IMDS `/metadata/identity/oauth2/token`
  endpoint, and asserts the proxy executed a
  `client_credentials`-grant against `login.microsoftonline.com`
  and mirrored the 4xx OAuth2 envelope back. The synthetic
  client_secret is asserted absent from the in-VM response.

```bash
RAXIS_LIVE_CLOUD_NET=1 RAXIS_V3_CLOUD_FORWARDING=1 \
    cargo run -p raxis-live-e2e -- aws-proxy-real-endpoint
RAXIS_LIVE_CLOUD_NET=1 RAXIS_V3_CLOUD_FORWARDING=1 \
    cargo run -p raxis-live-e2e -- gcp-proxy-real-endpoint
RAXIS_LIVE_CLOUD_NET=1 RAXIS_V3_CLOUD_FORWARDING=1 \
    cargo run -p raxis-live-e2e -- azure-proxy-real-endpoint
```

Operator recipe: see
`specs/v3/cloud-proxy-forwarding-recipe.md` for the plan
TOML / credential-backend / egress-allowlist contracts.

---

## Troubleshooting

### `<service> container not reachable at 127.0.0.1:<port>`

A slice's preflight `TcpStream::connect` to the host port timed
out. Either the container is not running or it is not yet
healthy. Bring it up with `--wait`:

```bash
docker compose -f live-e2e/docker-compose.e2e.yml up -d <service> --wait
```

### `failed to read env file ... .env`

`raxis-live-e2e` requires an env file containing
`ANTHROPIC-API-DEV-KEY` for the gateway slice. For local runs
that do not exercise the gateway you can pass any non-empty
value:

```bash
echo 'ANTHROPIC-API-DEV-KEY=local-dev-only' > /tmp/raxis-test.env
RAXIS_LIVE_E2E=1 cargo run -p raxis-live-e2e -- \
    --env-file /tmp/raxis-test.env redis-proxy
```

### Slice fails with `cap-path: real upstream returned ok=0.0`

The cap-rewrite slice could not authenticate against the real
mongo container. Check that the container is the one this
compose stack stood up (a stray `mongo:6` from a previous
project on the same loopback port would have a different SCRAM
salt) and that the credentials match `MONGO_INITDB_ROOT_*` in
`docker-compose.e2e.yml`.

```bash
docker exec raxis-e2e-mongo mongosh --quiet \
    -u raxis_test -p raxis_test_pass --authenticationDatabase admin \
    --eval 'db.adminCommand({ ping: 1 })'
```

A successful ping with `{ ok: 1 }` confirms the auth path is
healthy.

---

## Observability stack

Per `specs/v3/observability-prometheus.md`, every live-e2e run
brings up the full Prometheus + Grafana + OpenTelemetry-collector
stack alongside the upstream-service containers. One
`docker compose up -d --wait` produces the entire developer /
operator surface.

| Service          | Image                                                 | Host port | Purpose |
|---|---|---|---|
| `otel-collector` | `otel/opentelemetry-collector-contrib:0.110.0`       | 4318, 8889, 8888, 13133 | OTLP receiver + Prometheus exposition |
| `prometheus`     | `prom/prometheus:v2.55.1`                             | 9090      | 14-day retention, scrapes the collector + itself every 5 s |
| `grafana`        | `grafana/grafana:11.3.0`                              | 3000      | Anonymous Viewer access, 10 raxis dashboards auto-provisioned |

### Open the dashboards

The fastest path for an operator who just wants to *look* at the
dashboards (no live-e2e run, no perf harness) is the standalone
xtask wrapper that brings up only the observability triple, waits
for the healthchecks, and (on macOS / Linux) auto-opens Grafana
home + the `raxis-00-overview` dashboard in the default browser:

```bash
cd raxis && cargo xtask observability up
```

Companion subcommands:

| Subcommand                                                 | Effect                                                                        |
|---                                                         | ---                                                                            |
| `cargo xtask observability up [--full] [--no-open]`        | Bring up the obs triple (or `--full` for the entire compose stack).            |
| `cargo xtask observability status`                         | Probe each endpoint with a 1s TCP / HTTP check and print `UP` / `DOWN`.       |
| `cargo xtask observability urls [--open] [--dashboard ID]` | Print URL block + per-dashboard deep links; `--open` re-opens in the browser. |
| `cargo xtask observability down [-v]`                      | Tear down. `-v` also drops named volumes for a clean baseline.                |

Or hit the URLs directly:

```bash
open http://127.0.0.1:3000/d/raxis-00-overview
open http://127.0.0.1:9090/
open http://127.0.0.1:13133/
```

The Grafana admin login (`admin` / `raxis-e2e`) is needed only
to edit a dashboard; viewing is anonymous.

The xtask command honors `RAXIS_E2E_NO_OPEN=1`, `CI`, and
`SSH_CONNECTION` to suppress the auto-open step for CI / SSH
contexts.

### Cursor in-IDE browser vs system browser

The auto-open step detects whether you're running inside
Cursor's integrated terminal and routes accordingly:

| Host                                   | URL opens in                                                                          |
|---                                     | ---                                                                                    |
| Cursor integrated terminal             | Cursor's in-IDE Simple Browser pane (via the `cursor --open-url` CLI flag).            |
| Any other terminal (Terminal.app, iTerm, JetBrains, plain shell, ...) | OS default browser (`open` on macOS, `xdg-open` on Linux, `cmd /C start` on Windows). |
| Headless / CI / SSH-without-DISPLAY    | Suppressed — URLs still printed for copy-paste.                                       |

Detection signals (any one is sufficient):

  * `TERM_PROGRAM=cursor` (case-insensitive).
  * `CURSOR_TRACE_ID` set.
  * `CURSOR_LAYOUT` set (Cursor's Glass-layout marker).
  * `VSCODE_IPC_HOOK` contains `/Cursor/`.

Explicit override via `RAXIS_E2E_BROWSER`:

| Value                          | Effect                                                                          |
|---                             | ---                                                                              |
| `RAXIS_E2E_BROWSER=cursor`     | Force the Cursor CLI path (falls back to system default if the CLI is missing). |
| `RAXIS_E2E_BROWSER=system`     | Force the OS default browser; never invoke `cursor`.                            |
| `RAXIS_E2E_BROWSER=none`       | Suppress opening entirely; URLs are still printed.                              |
| (unset / any other value)      | Auto-detect from the signals above.                                              |

The Cursor CLI is located either on `$PATH` (after running
"Cursor → Shell Command: Install `cursor` command in PATH") or at
the canonical macOS bundle path
`/Applications/Cursor.app/Contents/Resources/app/bin/cursor`. If
neither is available, the auto-open falls back to the system
browser and prints a one-line hint pointing at the Shell-Command
install action.

### URL block at startup and end-of-run

When the `extended_e2e_realistic_scenario` or
`full_e2e_session_lifecycle` test drivers run, they print the
same observability URL block at kernel-ready time AND again as
part of the Tier-3 reporter's post-run artifact dump. Each URL
line is annotated with `(up)` / `(down — bring up via
`cargo xtask observability up`)` based on a 250 ms TCP probe, so
an operator skimming a live-e2e stderr capture sees the metric
dashboards in the same block they see the kernel-log path, the
audit dir, and the merged worktree.

### Persistence

Two named docker volumes hold the time-series and Grafana state:

| Volume                                    | Mounted at              | Survives `docker compose down`? |
|---|---|---|
| `raxis-live-e2e-test_prometheus_data`     | `prometheus:/prometheus`           | yes |
| `raxis-live-e2e-test_grafana_data`        | `grafana:/var/lib/grafana`         | yes |

To wipe them between runs:

```bash
docker compose -f live-e2e/docker-compose.e2e.yml down -v
docker volume rm raxis-live-e2e-test_prometheus_data raxis-live-e2e-test_grafana_data
```

### Dev-loop env vars

| Variable                       | Default | Effect |
|---|---|---|
| `RAXIS_E2E_OPEN_OBSERVABILITY` | OFF     | At end of run (`Tier3Reporter::with_observability_urls()` opted in), open Grafana home + `raxis-00-overview` in the best browser (Cursor in-IDE if detected, else system default). |
| `RAXIS_E2E_BROWSER`            | (auto)  | Override Cursor-vs-system detection: `cursor` / `system` / `none`. |
| `RAXIS_E2E_OBS_FRESH`          | OFF     | Wipe volumes BEFORE the live-e2e run for a clean baseline. |
| `RAXIS_E2E_OBS_KEEP_UP`        | ON      | Leave the compose stack running after the test exits. |

### Verifying data flow

After a kernel run, confirm the OTLP path:

```bash
curl -s 'http://127.0.0.1:9090/api/v1/query?query=raxis_intent_admission_total' \
    | python3 -c 'import sys,json; d=json.load(sys.stdin); print(len(d["data"]["result"]), "series")'
```

A non-zero series count proves the kernel `[observability]` block
is wired to the collector at `http://127.0.0.1:4318` and the
collector is pushing into Prometheus.

### Perf harness

`cargo xtask perf` reuses this stack automatically when present
(it never spins up a competing instance). See
`raxis/guides/recipes/ops/16-measure-perf.md` for the recipe.

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

| Slice                                        | Real upstream                   | Notes                                                                                                            |
| -------------------------------------------- | ------------------------------- | ---------------------------------------------------------------------------------------------------------------- |
| `postgres-proxy*`                            | `postgres:16-alpine`            | Original real-service slice — the pattern every other slice mirrors.                                             |
| `mongodb-proxy`                              | `mongo:7`                       | `--noauth` mode by default; `RAXIS_LIVE_MONGODB_URL` overrides.                                                  |
| `mongodb-proxy-collection-allowlists`        | `mongo:7`                       | Auth (SCRAM-SHA-256) against `admin`. Seeds `live_e2e_cap.users` via `docker exec mongosh` and drops on cleanup. |
| `redis-proxy`                                | `redis:7-alpine`                | `--requirepass`-protected; the slice drives a real RESP `AUTH` + round-trip.                                     |
| `smtp-proxy`                                 | `mailserver/docker-mailserver`  | Postfix + Dovecot SASL. The slice verifies delivery by `docker exec`-ing into the container's Maildir.           |
| `mysql-proxy`                                | `mysql:8.0.36` (opt-in)         | Hermetic by default; set `RAXIS_LIVE_MYSQL_URL` to drive the compose container.                                  |
| `mssql-proxy`                                | SQL Server 2022 (opt-in)        | Hermetic by default; set `RAXIS_LIVE_MSSQL_URL` to drive the compose container.                                  |
| `aws-proxy`, `gcp-proxy`, `azure-proxy`      | n/a                             | These proxies SYNTHESISE IMDS responses or proxy to public internet endpoints — there is no mock to replace.     |
| `http-proxy*`, `gateway-anthropic`           | real HTTPS endpoints            | Drive real `https://` upstreams; nothing to un-mock.                                                             |
| `egress-enforcement`, `session-spawn`        | n/a (kernel-internal)           | Exercise the kernel's own state machines, not external services.                                                 |

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

Published loopback ports (offset from defaults to avoid colliding
with operator-side databases):

| Service            | Container port | Host port           |
| ------------------ | -------------- | ------------------- |
| `postgres`         | 5432           | `127.0.0.1:54399`   |
| `mongodb`          | 27017          | `127.0.0.1:27399`   |
| `redis`            | 6379           | `127.0.0.1:63799`   |
| `smtp`             | 25             | `127.0.0.1:25199`   |
| `mysql` (opt-in)   | 3306           | `127.0.0.1:33099`   |
| `mssql` (opt-in)   | 1433           | `127.0.0.1:14399`   |

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

### Opt-in real-upstream mode for mysql / mssql

Both slices default to a hermetic mode that asserts the
`upstream_connects_failed ≥ 1` invariant against an unreachable
upstream. To exercise the real-upstream round-trip against the
compose containers:

```bash
docker compose -f live-e2e/docker-compose.e2e.yml \
    up -d mysql mssql --wait

RAXIS_LIVE_MYSQL_URL='mysql://raxis_test:raxis_test_pass@127.0.0.1:33099/raxis_e2e' \
RAXIS_LIVE_MSSQL_URL='mssql://sa:Raxis_e2e_pass!@127.0.0.1:14399/master?encrypt=false' \
RAXIS_LIVE_E2E=1 \
    cargo run -p raxis-live-e2e -- mysql-proxy mssql-proxy
```

(See the slices' module docstrings for the exact URL shape each
proxy understands.)

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

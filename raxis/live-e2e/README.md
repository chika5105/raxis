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

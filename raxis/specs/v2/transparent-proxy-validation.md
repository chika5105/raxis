# RAXIS V2 — Transparent-Proxy Validation Contract

> **Status:** V2 Specified
> **Companion specs:**
> - [`credential-proxy.md`](credential-proxy.md) — the proxy substrate this contract validates.
> - [`vm-network-isolation.md`](vm-network-isolation.md) — Tier 1 egress, which underpins the proxy-bypass denial signature.
> - [`e2e-extended-scenario.md`](e2e-extended-scenario.md) — the realism e2e harness that exercises this contract.
>
> **Test surface:**
> - Witness module: `raxis/kernel/tests/extended_e2e_support/transparent_proxy_evidence.rs`.
> - Driver call site: `raxis/kernel/tests/extended_e2e_realistic_scenario.rs` (after `service-evidence` passes).
> - Operator-realistic prompt: `raxis/live-e2e/seed/prompts/transparent_proxy_real_scripts.md`.
> - Stock-Python script set: `raxis/live-e2e/seed/scripts/transparent_proxy/`.

---

## 1. The transparency contract

The credential proxy's design promise is that **operators do not have to modify their existing code to use RAXIS**. A stock Python program written against an unmodified upstream — `psycopg2.connect(os.environ["DATABASE_URL"])`, `pymongo.MongoClient(os.environ["MONGO_URL"])`, `redis.from_url(os.environ["REDIS_URL"])`, `smtplib.SMTP(...)` — MUST work unchanged when it is run as a RAXIS Executor task with a credential proxy mounted. The script never imports a RAXIS shim, never reads a `RAXIS_*` environment variable, never branches on whether a proxy is in front of the upstream.

This contract has two halves; both must hold:

1. **Compatibility.** The `loopback_env()` URL the credential-proxy manager injects (`DATABASE_URL`, `MONGO_URL`, `REDIS_URL`, `SMTP_URL`, `MYSQL_URL`, `MSSQL_URL`) MUST be a valid scheme-prefixed URL the corresponding canonical Python client library accepts at face value. The proxy's substitution of the upstream credentials happens inside the proxy connection; the in-VM client only sees the loopback URL and the proxy's stand-in `AUTH`/`USER`/`PASSWORD` payloads.
2. **Exclusivity.** The proxy MUST be the only path from inside the VM to the upstream. If the executor could dial the real upstream `host:port` directly — bypassing the proxy entirely — a script that hardcoded the production address would silently succeed and the proxy would never be exercised. The kernel's Tier-1 egress policy denies any non-proxy upstream and emits `TransparentProxyDenied { reason: "proxy_target_bypass", … }` for every attempt; the validation witness fails closed when one of those events appears in the executor's session.

Together, (1) and (2) are the *transparency contract*. The validation tier described here mechanically certifies both halves on every realistic-scenario run.

## 2. Why service-evidence alone is not enough

`raxis/kernel/tests/extended_e2e_support/service_evidence.rs` already exercises the round-trip: it seeds canonical rows into every upstream, drives the `service-round-trip` Executor task with a directive prompt that names the canonical output shapes, and byte-compares the committed `out/services/<service>.txt` against the canonical seed. That witness pins **"the data round-tripped correctly"**.

It does NOT pin **"the executor was unaware of the proxy"**. The service-round-trip prompt enumerates exact column names, key prefixes, and SMTP envelope fields, and the Executor produces canonical bytes from that direct instruction. A regression that broke `loopback_env` to emit a malformed `MONGO_URL` would *also* succeed there: the agent has enough information in the prompt to write the canonical bytes from prose alone, and the per-service slice tests assert protocol-level correctness from the kernel side, not the agent side.

The transparent-proxy tier closes this gap by:

- Running scripts that have **no semantic knowledge** of the canonical output shapes — they only read the URL from the env var, query the upstream, and serialise the response in a deterministic form. The output bytes therefore originate from the upstream wire response, not the prompt.
- Asserting the kernel emitted **no proxy-bypass denial** for the executor's session. This is the structural lock that proves the proxy was actually in the data path.

`service_evidence` says "the round-trip happened." `transparent_proxy_evidence` says "AND the executor was unaware — it used stock client libraries against stock env vars, the proxy was invisible." Both passing means both contracts hold; failure in either points at a distinct root cause.

## 3. Mechanical witness — assertion order

For each service in scope, [`assert_transparent_proxy_round_trip`](../../kernel/tests/extended_e2e_support/transparent_proxy_evidence.rs) walks the following checks in order and returns the **first** failure as a structured `TransparentProxyEvidenceError`. The error's `Display` impl renders a grep-friendly per-service tag (`[transparent-proxy:<svc>]`) so a CI scraper can locate the failing service immediately.

1. **Credential proxy was started in the executor's session.** The audit chain must contain a `CredentialProxyStarted` event whose `proxy_type` matches the service AND whose envelope `(initiative_id, task_id)` resolves to the `transparent-proxy-realscripts` executor task — NOT a kernel preflight session. The scope filter is identical to `service_evidence`'s `WitnessScope`.
2. **No proxy-bypass egress.** The audit chain must NOT contain any `TransparentProxyDenied` event with `reason == "proxy_target_bypass"` scoped to the executor's session. If the executor tried to skip the proxy and dial the real upstream `host:port` directly, that's the kernel's emitted signature — the transparent-proxy contract is broken if we see one.
3. **Output file present at the worktree-canonical path.** The executor must have committed `out/services/<service>.txt` to its worktree, where `<service>` is one of `postgres`, `mongodb`, `redis`, `smtp`, `mysql`, `mssql`.
4. **Output bytes canonical.** The file's content must byte-equal the canonical bytes produced by [`service_evidence`](../../kernel/tests/extended_e2e_support/service_evidence.rs) for that service. The two witnesses share the same canonicalisers (`postgres_canonical_bytes`, `mongo_canonical_bytes`, …) so a single source of truth defines the expected wire shape.
5. **Wrapper transcript present and lists the service.** `scripts/last_run_summary.txt` must exist in the worktree and must mention the service name verbatim. The wrapper script (`scripts/run_all_services.sh`) is operator-orchestration glue: an operator must be able to grep its transcript for a service and see whether the per-service script ran, was skipped, or failed.

Opt-in services (MySQL, MSSQL) self-skip when `RAXIS_LIVE_MYSQL_URL` / `RAXIS_LIVE_MSSQL_URL` are unset — the helper bypasses the entire witness with an informational `eprintln!`, matching the existing `service_evidence` opt-in shape. The wrapper script's summary line for a skipped service reads `skipped`; the witness only requires that the service name appears, not the success/skip state.

## 4. Egress denial is load-bearing

Without it, this Python snippet:

```python
import os, psycopg2
conn = psycopg2.connect("postgresql://real_user:real_pass@prod-db.company.com:5432/mydb")
```

would succeed against the upstream and produce canonical output bytes — passing the *service-evidence* witness — while completely bypassing the credential proxy. The proxy would never be in the data path, the upstream credentials would round-trip into the in-VM environment, and the transparency contract would be silently violated.

The Tier-1 egress admission layer (`vm-network-isolation.md`) denies any non-proxy upstream from inside an Executor VM and emits `TransparentProxyDenied { reason: "proxy_target_bypass", host_or_sni, original_dst_ip, original_dst_port, protocol }`. The witness asserts:

- `CredentialProxyStarted` is present in the executor's session for the expected `proxy_type`.
- *No* `TransparentProxyDenied { reason: "proxy_target_bypass" }` is present for the same session.

If the executor's policy correctly forbids direct upstream reach, the second clause is trivially satisfied. If the policy is misconfigured to allow upstream egress, the executor's stock client library may still happen to dial the proxy's `127.0.0.1:<port>` (because the env var points there) — in which case nothing fails. The negative-path coverage relies on the kernel's egress admission emitting the deny event whenever any attempt is made; the witness's negative-test fixture (`synthetic_proxy_bypass_event`) confirms that one such event in the chain produces a `TransparentProxyEvidenceError::DirectEgressDetected` failure with the offending `(ip, port)` tuple surfaced.

## 5. Stock-Python script tier

The scripts live under `raxis/live-e2e/seed/scripts/transparent_proxy/`:

| Service  | Script               | Library         | URL env var      | Notes                                |
|----------|----------------------|-----------------|------------------|--------------------------------------|
| Postgres | `check_postgres.py`  | psycopg2-binary | `DATABASE_URL`   | SELECT all rows, sort by `id`        |
| MongoDB  | `check_mongodb.py`   | pymongo         | `MONGO_URL`      | find(), `OrderedDict` key stability  |
| Redis    | `check_redis.py`     | redis-py        | `REDIS_URL`      | SCAN under prefix, GET each          |
| SMTP     | `check_smtp.py`      | stdlib smtplib  | `SMTP_URL`       | One canonical envelope               |
| MySQL    | `check_mysql.py`     | PyMySQL         | `MYSQL_URL`      | Self-skips when env unset            |
| MSSQL    | `check_mssql.py`     | pymssql         | `MSSQL_URL`      | Self-skips when env unset            |

Each script:

- Imports only stdlib + its one upstream client. No raxis imports. No `RAXIS_*` env-var reads. No branching on whether a proxy is in front.
- Reads connection details from the standard URL env var.
- Pulls the canonical rows / documents / keys / envelope.
- Writes one canonical text record per upstream entity to a CLI-passed `--output` path.
- Raises on any connection / query / write failure so the executor's task log surfaces a real exception trace.

A pinned `requirements.txt` and a `run_all_services.sh` wrapper sit next to the per-service scripts. The wrapper invokes each `check_*.py` against `out/services/<service>.txt`, captures stdout/stderr, and prints a per-service summary line (`success`, `skipped`, or `failed`) which the executor commits as `scripts/last_run_summary.txt`.

## 6. Operator-realistic executor prompt

The prompt at `raxis/live-e2e/seed/prompts/transparent_proxy_real_scripts.md` reads like a normal task assignment a human would give a teammate:

> We have a small collection of Python scripts in `scripts/` that connect to our backing services and dump per-service data into text files for the daily integrity check…

It does NOT mention "credential proxy", "raxis", "loopback", "tproxy", or any infrastructure-aware concept. The executor figures out what to do by reading the scripts. The witness module asserts the prompt does not leak (see `plan_realistic::tests::transparent_proxy_prompt_is_operator_realistic`).

## 7. Plan wiring

The `transparent-proxy-realscripts` task in `raxis/kernel/tests/extended_e2e_support/plan_realistic.rs` is wired with:

- `predecessors = ["service-round-trip"]` — runs after the data round-trip task has committed.
- `path_allowlist = ["out/services/", "scripts/last_run_summary.txt"]` — same per-service output directory as `service-round-trip`, plus the wrapper transcript path.
- Credential mounts: `DATABASE_URL` (postgres), `MONGO_URL` (mongodb), `REDIS_URL` (redis), `SMTP_URL` (smtp). MySQL / MSSQL stay opt-in via the same env-var gates `service-evidence` uses.

The kernel's per-task egress allowlist defaults to deny-by-default for Executor tasks; the only egress targets the executor can reach are the credential-proxy `127.0.0.1:<port>` endpoints the manager bound for this task. Any other dial-out attempt fires `TransparentProxyDenied`, which is exactly what the witness's negative path keys on.

## 8. Executor VM Python availability

The `executor-starter` image (`raxis/images/executor-starter/Containerfile`) installs the same pinned Python client libraries the host-side `requirements.txt` lists:

```text
psycopg2-binary==2.9.10
pymongo==4.10.1
redis==5.2.1
PyMySQL==1.1.1
pymssql==2.3.2
```

Versions stay in lock-step via a comment in the Containerfile that explicitly references the requirements file. The executor prompt asks the agent NOT to `pip install` — the image ships the libraries pre-baked so the task is deterministic and so no egress to PyPI is required (which Tier-1 would deny anyway).

Operators running with a custom pinned Executor image MUST replicate this set if they want the transparent-proxy task to run; otherwise the per-service scripts fail on import and the witness reports `WrapperSummaryMissesService` for whichever services the failing script blocks.

## 9. Failure taxonomy

`TransparentProxyEvidenceError` variants (one per check, plus a self-skip helper for opt-in services):

- `OptInBypassed { service, env_var }` — opt-in env var was unset; helper bypassed. Not a failure.
- `ProxyStartMissing { service, proxy_type, scope }` — no `CredentialProxyStarted` event scoped to the executor's task.
- `DirectEgressDetected { service, scope, original_dst_ip, original_dst_port }` — a `TransparentProxyDenied { reason: "proxy_target_bypass" }` event fired; the executor tried to dial the upstream directly.
- `OutputFileMissing { service, path }` — `out/services/<service>.txt` not present in the worktree.
- `OutputFileReadFailed { service, path, reason }` — IO error reading the committed output.
- `OutputContentMismatch { service, path, expected_sha256, actual_sha256, diff_preview }` — bytes do not match the canonical seed; first divergent line surfaces in the preview.
- `WrapperSummaryMissing { service, path }` — `scripts/last_run_summary.txt` not present.
- `WrapperSummaryMissesService { service, summary_path, summary_preview }` — wrapper transcript exists but does not mention the service.

The harness aggregates failures (`collect_active_witness_failures`) and renders them grouped per service (`render_failures`) so one panic message lists every problem at once.

## 10. Cross-references

- The proxy-bypass denial signature and Tier-1 admission flow: `vm-network-isolation.md`.
- The credential-proxy manager and `loopback_env()`: `raxis/crates/credential-proxy-manager/src/lib.rs`, spec §2 in `credential-proxy.md`.
- The realism e2e driver and the rich-multilang seed: `extended_e2e_realistic_scenario.rs`, `rich-multilang-001/`.
- Per-service canonical bytes (the single source of truth used by both witnesses): `service_evidence.rs`.

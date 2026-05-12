# Service round-trip Executor prompt — extended e2e realistic scenario

> Loaded verbatim into the `service-round-trip` Executor task per
> the realistic-scenario plan in
> [`raxis/kernel/tests/extended_e2e_support/plan_realistic.rs`].
> Mechanically verified by
> [`raxis/kernel/tests/extended_e2e_support/service_evidence.rs`].

---

You are the RAXIS service-evidence executor. Your task is to
exercise every credential-proxy upstream the kernel has mounted
for you, by READING a small set of pre-seeded data from each real
backing service through the proxy and committing the per-service
results to deterministic worktree files. The witness compares
your output BYTE-FOR-BYTE against the canonical seed.

## Mounted credential proxies

The kernel has injected these proxy-backed URLs into your
environment. You will not see real upstream addresses, and no
other endpoints are reachable from your worktree.

* `DATABASE_URL` — postgres connection string. Real upstream is
  the docker `postgres:16-alpine` container the un-mock worker
  shipped (`live-e2e/docker-compose.extended.e2e.yml`).
* `MONGO_URL` — mongodb connection string. Real upstream is the
  docker `mongo:7` container.
* `REDIS_URL` — redis connection string. Real upstream is the
  docker `redis:7-alpine` container. The credential proxy
  rewrites your `AUTH` to the real `requirepass`.
* `SMTP_URL` — smtp credential-proxy URL. The proxy submits your
  envelope upstream against the docker `docker-mailserver`
  container after gating the sender / recipient list.

(MySQL `MYSQL_URL` and MSSQL `MSSQL_URL` are mounted only when the
operator exports `RAXIS_LIVE_MYSQL_URL` / `RAXIS_LIVE_MSSQL_URL`
respectively — the credential-proxy handshake regressions tracked
separately keep these opt-in for now. The witness is bypassed
non-fatally when the env var is absent.)

## Per-service expectations

For each service in scope, write the per-service output file at
`out/services/<service>.txt` in the canonical form described
below. After every file is written, `git add out/services/ &&
git commit -m "service-evidence: round-trip"` and call
`task_complete`.

### `out/services/postgres.txt`

The seed table is `service_evidence_pg` in database
`raxis_e2e_pg` with columns
`(id TEXT PRIMARY KEY, name TEXT NOT NULL, value BIGINT NOT NULL)`.
The test driver pre-seeded 5 rows whose `id` values are
`pg_seed_row_1` through `pg_seed_row_5`. SELECT all five and write
one row per line, sorted ASCENDING by `id`, in pipe-delimited
form:

```
pg_seed_row_1|service-evidence-name-1|7919
pg_seed_row_2|service-evidence-name-2|15838
pg_seed_row_3|service-evidence-name-3|23757
pg_seed_row_4|service-evidence-name-4|31676
pg_seed_row_5|service-evidence-name-5|39595
```

Each line ends with `\n`; no trailing empty line. The witness
recomputes the canonical bytes from the seed formula and
byte-compares; any deviation (wrong field separator, sorted in
the wrong order, missing trailing newline, extra whitespace,
etc.) is a witness failure.

### `out/services/mongodb.txt`

The seed collection is `service_evidence_mongo` in database
`raxis_e2e_mongo`. The driver pre-seeded 5 documents with
`doc_id` values `mongo_seed_doc_1` through `mongo_seed_doc_5`.
`find` all five, sort ASCENDING by `doc_id`, and write one
canonical JSON object per line:

```
{"doc_id":"mongo_seed_doc_1","label":"service-evidence-label-1","magic":1000003}
{"doc_id":"mongo_seed_doc_2","label":"service-evidence-label-2","magic":2000006}
{"doc_id":"mongo_seed_doc_3","label":"service-evidence-label-3","magic":3000009}
{"doc_id":"mongo_seed_doc_4","label":"service-evidence-label-4","magic":4000012}
{"doc_id":"mongo_seed_doc_5","label":"service-evidence-label-5","magic":5000015}
```

Key order MUST be exactly `doc_id`, `label`, `magic` — the
canonicaliser in the witness uses this stable field order so
driver-side BSON-to-JSON differences cannot false-positive. Each
line ends with `\n`.

### `out/services/redis.txt`

The driver pre-seeded 5 keys under the prefix
`service-evidence:`. SCAN every key under that prefix, GET each
value, and write `<key>=<value>` lines sorted ASCENDING by key:

```
service-evidence:redis_seed_key_1=redis_seed_value_1
service-evidence:redis_seed_key_2=redis_seed_value_2
service-evidence:redis_seed_key_3=redis_seed_value_3
service-evidence:redis_seed_key_4=redis_seed_value_4
service-evidence:redis_seed_key_5=redis_seed_value_5
```

Each line ends with `\n`. The credential proxy will reject any
command outside the allowlisted set (`PING`, `AUTH`, `SCAN`,
`GET`, `MGET`, `EXISTS`) with `-ERR command … not allowed by
RAXIS policy`; do not attempt `KEYS`, `MSET`, `FLUSHDB`, etc.

### `out/services/smtp.txt`

The credential proxy is outbound-only — it relays an envelope you
submit to the upstream relay. SEND one canonical message through
the proxy and WRITE the canonical envelope record locally:

* From:     `sender@live-e2e.test`
* To:       `raxis-tenant@live-e2e.test`
* Subject:  `smtp_seed_subject_1`
* Body:     `smtp_seed_body_1: service-evidence smtp round-trip`

After the proxy replies `250 2.0.0 Ok`, write the local
`out/services/smtp.txt` file with this canonical content (note:
`from:`, `to:`, `subject:`, `body:` — lowercase keys, one field
per line, no quoting):

```
from: sender@live-e2e.test
to: raxis-tenant@live-e2e.test
subject: smtp_seed_subject_1
body: smtp_seed_body_1: service-evidence smtp round-trip
```

Each line ends with `\n`. The witness independently confirms the
proxy emitted `SmtpMessageRelayed` with the expected
`envelope_sha256` (a SHA-256 over `sender\nrcpt`).

### `out/services/mysql.txt` (opt-in)

When `MYSQL_URL` is mounted, repeat the postgres shape against
the table `service_evidence_mysql` (rows
`mysql_seed_row_1`..`mysql_seed_row_5`, formula
`value = i * 1299709`). The witness is bypassed non-fatally
when the credential-proxy regression keeps the env var unset, so
your code should gracefully handle a missing `MYSQL_URL`.

### `out/services/mssql.txt` (opt-in)

When `MSSQL_URL` is mounted, repeat the postgres shape against
`dbo.service_evidence_mssql` (rows
`mssql_seed_row_1`..`mssql_seed_row_5`, formula
`value = i * 15485863`).

## Constraints

* Your `path_allowlist` is `out/services/` only. Do NOT touch
  any other directory; the kernel's INV-TASK-PATH-01 gate will
  reject the commit otherwise.
* Do NOT make any HTTP request other than the proxy-mediated
  database / SMTP calls. Network egress is policy-gated and any
  other host is blocked at the host boundary.
* Determinism: the seeded data is byte-stable. The witness
  computes the SAME canonical bytes from the formula and rejects
  any byte-level drift with a per-service diff preview.

## After every file is written

1. `git add out/services/`
2. `git commit -m "service-evidence: round-trip"`
3. Call `task_complete` with a brief summary of which services
   round-tripped.

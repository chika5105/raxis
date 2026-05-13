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
* **TWO distinct file locations.** Read this carefully — confusing
  these two is the #1 way the task fails:
  1. **Helper scripts go in `/tmp/`.** The Python / shell driver
     code itself MUST live at `/tmp/round_trip.py` (or similar
     `/tmp/*.py`). `/tmp/` is mounted ephemerally inside the
     executor VM and never appears in the diff. Any `.py` /
     `.sh` driver you write inside the worktree root will land
     in the commit and trip `FailPathPolicyViolation`.
  2. **OUTPUT data files go in `out/services/<service>.txt`
     INSIDE the worktree.** These are the files the witness
     reads. The Python script you put in `/tmp/` writes its
     output INTO the worktree's `out/services/` directory
     (relative paths work because your cwd IS the worktree
     root, but the explicit absolute form `f.write_text(...)`
     against an absolute path under `os.getcwd()` is safer
     against subprocess cwd quirks).
* Do NOT make any HTTP request other than the proxy-mediated
  database / SMTP calls. Network egress is policy-gated and any
  other host is blocked at the host boundary.
* Determinism: the seeded data is byte-stable. The witness
  computes the SAME canonical bytes from the formula and rejects
  any byte-level drift with a per-service diff preview.

## Copy-paste-ready helper

The following script is a working starting point. Save it AS-IS
to `/tmp/round_trip.py`, run it once, then `git add` + commit
+ `task_complete`. Adjust only the service-specific blocks if
the seed shape changes.

```bash
mkdir -p out/services
cat > /tmp/round_trip.py <<'PY'
# /tmp/round_trip.py — service-evidence round-trip writer.
#   Reads seeded rows / docs / keys / SMTP envelope through the
#   credential proxies mounted in the executor env, then writes
#   one canonical-form file per service into out/services/.
#   Idempotent: rerunning overwrites any prior partial output.
import json, os, smtplib, ssl, sys, time
from email.message import EmailMessage
from pathlib import Path

WORKTREE = Path(os.getcwd()).resolve()
OUT_DIR  = WORKTREE / "out" / "services"
OUT_DIR.mkdir(parents=True, exist_ok=True)

# ── postgres ────────────────────────────────────────────────
import psycopg2
pg = psycopg2.connect(os.environ["DATABASE_URL"])
pg.autocommit = True
with pg.cursor() as cur:
    cur.execute(
        "SELECT id, name, value FROM service_evidence_pg "
        "ORDER BY id ASC"
    )
    rows = cur.fetchall()
pg.close()
pg_lines = [f"{r[0]}|{r[1]}|{r[2]}\n" for r in rows]
(OUT_DIR / "postgres.txt").write_text("".join(pg_lines))

# ── mongodb ─────────────────────────────────────────────────
import pymongo
mongo = pymongo.MongoClient(
    os.environ["MONGO_URL"],
    serverSelectionTimeoutMS=60_000,
    directConnection=True,
)
# Force a server-selection round-trip so the connection error
# surfaces here, not inside the find() iterator below.
mongo.admin.command("ping")
mdb     = mongo["raxis_e2e_mongo"]
docs    = list(
    mdb["service_evidence_mongo"]
        .find({}, {"_id": 0, "doc_id": 1, "label": 1, "magic": 1})
        .sort("doc_id", 1)
)
mongo_lines = [
    # Canonical key order: doc_id, label, magic — match the
    # witness exactly.
    json.dumps(
        {"doc_id": d["doc_id"], "label": d["label"], "magic": d["magic"]},
        separators=(",", ":"),
    ) + "\n"
    for d in docs
]
(OUT_DIR / "mongodb.txt").write_text("".join(mongo_lines))
mongo.close()

# ── redis ───────────────────────────────────────────────────
import redis
r = redis.Redis.from_url(os.environ["REDIS_URL"])
r.ping()
keys = sorted(
    k.decode() for k in r.scan_iter(match="service-evidence:*")
)
redis_lines = []
for k in keys:
    v = r.get(k)
    redis_lines.append(f"{k}={v.decode()}\n")
(OUT_DIR / "redis.txt").write_text("".join(redis_lines))

# ── smtp ────────────────────────────────────────────────────
# SMTP_URL is `smtp://127.0.0.1:NNN` (no auth in the agent-side
# URL — the proxy injects upstream auth). Compose the canonical
# envelope and let the proxy relay it.
import urllib.parse as _u
smtp_url = _u.urlparse(os.environ["SMTP_URL"])
host = smtp_url.hostname
port = smtp_url.port

msg = EmailMessage()
msg["From"]    = "sender@live-e2e.test"
msg["To"]      = "raxis-tenant@live-e2e.test"
msg["Subject"] = "smtp_seed_subject_1"
msg.set_content("smtp_seed_body_1: service-evidence smtp round-trip")

with smtplib.SMTP(host, port, timeout=30) as s:
    # No EHLO/STARTTLS — the proxy speaks plain SMTP on
    # loopback and synthesises a `250 2.0.0 Ok` for the agent.
    s.send_message(msg)

# Canonical envelope record (lowercase keys, one field per line).
smtp_lines = [
    "from: sender@live-e2e.test\n",
    "to: raxis-tenant@live-e2e.test\n",
    "subject: smtp_seed_subject_1\n",
    "body: smtp_seed_body_1: service-evidence smtp round-trip\n",
]
(OUT_DIR / "smtp.txt").write_text("".join(smtp_lines))

# ── opt-in services (mysql / mssql) — silently skip when the env
#    var is not exported.
if "MYSQL_URL" in os.environ:
    import pymysql
    cn = pymysql.connect(**{
        # Parse from MYSQL_URL if provided; left as a stub.
    })
    # Stub: leave as a TODO once RAXIS_LIVE_MYSQL_URL is
    # routinely set — the witness short-circuits otherwise.
if "MSSQL_URL" in os.environ:
    # Same opt-in shape as mysql.
    pass

print("service-evidence round-trip wrote:", sorted(p.name for p in OUT_DIR.iterdir()))
PY

python3 /tmp/round_trip.py
```

## After every file is written

1. **Verify the files exist on disk** with
   `ls out/services/` — you should see at minimum `postgres.txt`,
   `mongodb.txt`, `redis.txt`, `smtp.txt`. If a file is missing
   the python script crashed; fix it and rerun before
   committing. **Do not call `task_complete` until every
   in-scope file is present** — the kernel's
   `compute_touched_paths` runs over the commit you submit and
   the witness re-reads the files from `out/services/`, so a
   missing file fails both gates.
2. `git add out/services/` (explicit path; do NOT run
   `git add .` / `git add -A` / `git commit -a` — those stage
   every untracked file in the worktree, including any helper
   scratch you forgot was there).
3. `git commit -m "service-evidence: round-trip"`
4. **Capture the new HEAD SHA** with `git rev-parse HEAD` and
   pass it as the `head_sha` argument to `task_complete`. If
   you submit a head_sha that doesn't match the actual commit
   the kernel returns `FailInvalidDiff` and the task burns a
   crash-retry slot (live-e2e iter35 root cause: agent called
   `task_complete` without ever running `git commit`, so the
   submitted head_sha referenced a SHA that didn't exist in
   the worktree's history).
5. Call `task_complete` with `head_sha = <the SHA above>` and
   a brief summary of which services round-tripped.

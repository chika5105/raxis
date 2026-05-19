# Materializer Executor prompt — extended e2e scenario

> Loaded verbatim into the `materialize-records` Executor task per
> [`raxis/specs/v2/e2e-extended-scenario.md`](../../../specs/v2/e2e-extended-scenario.md) §4.1.
> The prompt is committed to the repository so reviewers can audit
> exactly what the LLM saw.

---

You are the RAXIS materialization executor. Your task is to
serialise every record from two pre-seeded data sources into JSON
files inside this worktree, then commit the result.

## Data sources

Use these environment variables directly:

* `DATABASE_URL` — postgres connection string. The seeded table is
  `seeded_rows` with columns `(id TEXT, payload JSONB, created_at
  BIGINT)`. There are exactly **25** rows.
* `MONGO_URL` — mongo connection string. The seeded collection is
  `seeded_docs` in the `raxis_e2e_mongo` database. Each document
  has fields `_id` (`ObjectId`), `doc_id` (`string`), `payload`
  (`object`), `created_at` (`int64`). There are exactly **25**
  documents.

## Files to write

For each postgres row, create the file
`out/postgres/<id>.json` containing the JSON object:

```json
{ "id": "row-NNNN",
  "payload": { ... },
  "created_at": 1700000000 }
```

For each mongo document, create the file
`out/mongo/<doc_id>.json` containing the JSON object:

```json
{ "_id_hex": "<24 hex chars of the ObjectId>",
  "doc_id":  "doc-NNNN",
  "payload": { ... },
  "created_at": 1700000000 }
```

The `_id_hex` field MUST be the 24-character lowercase hex string
of the source `ObjectId` (i.e. the byte string converted to hex,
no `ObjectId(...)` wrapper). This normalisation is the only
transformation between the source records and the on-disk JSON.

Total expected files: 25 in `out/postgres/`, 25 in `out/mongo/`.

## Recommended one-shot helper (copy-paste-ready)

The fastest, lowest-tool-call path is to write a single Python
helper to `/tmp/materialize.py` and run it once. Both `pymongo`
and `psycopg2-binary` are pre-installed in the executor VM
(`live-e2e/src/slice_vm_capabilities.rs::CANONICAL_EXECUTOR_PYTHON_DB_CLIENTS`).
The helper below uses `find` on `seeded_docs` and `SELECT` on
`seeded_rows`.

> **Why `/tmp/` and not the worktree root?** `path_allowlist` is
> enforced against the full `base..head` git diff at
> `task_complete` time (see Constraints). `/tmp/` is mounted
> ephemerally inside the executor VM and never appears in the
> diff. Writing the helper to the worktree root is the most
> common cause of this task failing.

```bash
cat > /tmp/materialize.py <<'PY'
#!/usr/bin/env python3
# One-shot materializer. Idempotent: rerunning produces the same
# files. Designed to need at most one tool call from the planner:
# write + run + verify in a single bash invocation. (Triple-double-
# quoted module / function docstrings are intentionally avoided —
# this prompt is embedded into a TOML multi-line-string description
# block by `multi_initiative.rs`, so a sequence of three quote
# characters would terminate the enclosing string early.)
from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

import psycopg2
import psycopg2.extras
from pymongo import MongoClient
from pymongo.errors import PyMongoError

OUT_PG    = Path("/workspace/out/postgres")
OUT_MONGO = Path("/workspace/out/mongo")

def materialize_postgres() -> int:
    dsn = os.environ["DATABASE_URL"]
    OUT_PG.mkdir(parents=True, exist_ok=True)
    with psycopg2.connect(dsn) as conn, \
         conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(
            "SELECT id, payload, created_at "
            "FROM seeded_rows ORDER BY id;"
        )
        rows = cur.fetchall()
    for row in rows:
        body = {
            "id":         row["id"],
            "payload":    row["payload"],
            "created_at": int(row["created_at"]),
        }
        (OUT_PG / f"{row['id']}.json").write_text(
            json.dumps(body, separators=(",", ":"), sort_keys=True)
            + "\n"
        )
    return len(rows)

def materialize_mongo() -> int:
    # MONGO_URL does not carry a default-database segment — pass
    # the database name explicitly with `client["raxis_e2e_mongo"]`,
    # do NOT call `client.get_default_database()` (it would raise
    # `ConfigurationError: No default database name defined`).
    url = os.environ["MONGO_URL"]
    # serverSelectionTimeoutMS=60_000 rides out the few seconds the
    # docker-compose mongo container might still be in `starting`
    # health-check during a fresh stack `up`. `directConnection=True`
    # forces standalone topology so the driver does not speculate
    # about replica-set / mongos shapes.
    last_err: PyMongoError | None = None
    for attempt in range(12):
        try:
            client = MongoClient(
                url,
                serverSelectionTimeoutMS=60_000,
                directConnection=True,
            )
            # Force a round-trip so we discover unreachable proxies
            # at construction time, not on first `find()`.
            client.admin.command("ping")
            break
        except PyMongoError as e:
            last_err = e
            time.sleep(5)
    else:
        raise SystemExit(
            f"mongo: gave up after 12 attempts (60 s elapsed): "
            f"{last_err!r}"
        )
    coll = client["raxis_e2e_mongo"]["seeded_docs"]
    docs = list(coll.find({}).sort("doc_id", 1))
    OUT_MONGO.mkdir(parents=True, exist_ok=True)
    for d in docs:
        body = {
            "_id_hex":    bytes(d["_id"].binary).hex(),
            "doc_id":     d["doc_id"],
            "payload":    d["payload"],
            "created_at": int(d["created_at"]),
        }
        (OUT_MONGO / f"{d['doc_id']}.json").write_text(
            json.dumps(body, separators=(",", ":"), sort_keys=True)
            + "\n"
        )
    client.close()
    return len(docs)

def main() -> int:
    n_pg    = materialize_postgres()
    n_mongo = materialize_mongo()
    sys.stdout.write(f"postgres={n_pg} mongo={n_mongo}\n")
    if n_pg != 25 or n_mongo != 25:
        raise SystemExit(
            f"materialize: expected 25/25, got pg={n_pg} mongo={n_mongo}"
        )
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
PY
python3 /tmp/materialize.py
```

A single successful run of the helper above emits exactly the 50
expected files (25 + 25) and exits `0`. If pymongo raises
`ConfigurationError: No default database`, you forgot the
`client["raxis_e2e_mongo"]` indexing step — re-read the docstring
on `materialize_mongo()`. If the helper exits non-zero, capture
its stderr and decide whether to retry inline or report_failure;
do not silently swallow it.

## After every file is written

1. `git add out/postgres/ out/mongo/` (explicit paths only — do
   NOT run `git add .` or `git add -A`, see Constraints below).
2. `git commit -m "seed: materialize records"`
3. Call `task_complete` with a one-line summary of the count.

## Constraints

* Only commit files under `out/postgres/`, `out/mongo/`, or
  `out/manifest.json`. Any other committed path fails the
  path-scope check.
* In particular: if you need a helper script (e.g. a Python
  driver to iterate the postgres rows and mongo docs), write it
  to **`/tmp/`** (outside the worktree), not to the worktree
  root. `/tmp/` is mounted ephemerally inside the executor VM
  and never appears in the git diff. The "Recommended one-shot
  helper" block above already follows this convention.
* Use `git add out/postgres/ out/mongo/` with explicit paths;
  do **not** run `git add .` / `git add -A` / `git commit -a`
  (these stage every untracked or modified file, including any
  scratch you forgot was in the worktree).
* Do NOT make any HTTP request. This task only needs the database
  queries above.
* Determinism: the seeded data is byte-stable. If your output
  files do not match the canonical expected JSON in the test's
  witness oracle, the test will surface a per-row diff and fail.
* Budget guidance: the planner is configured with
  `max_turns = 100` (see `planner-env-vars.md`); aim to complete
  in **≤ 6 tool calls** by using the "Recommended one-shot
  helper" pattern (write file → run file → git add → git commit
  → task_complete). Exploratory tool calls (`ls`, `cat`,
  per-row `db.find`, `pip list`) burn turns without progress.

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

The kernel has injected two credential URLs into your environment:

* `DATABASE_URL` — postgres connection string. The seeded table is
  `seeded_rows` with columns `(id TEXT, payload JSONB, created_at
  BIGINT)`. There are exactly **25** rows.
* `MONGO_URL` — mongo connection string. The seeded collection is
  `seeded_docs` in the `raxis_e2e_mongo` database. Each document
  has fields `_id` (`ObjectId`), `doc_id` (`string`), `payload`
  (`object`), `created_at` (`int64`). There are exactly **25**
  documents.

Both URLs point at credential proxies — you will not see real
upstream addresses, and no other endpoints are reachable from your
worktree.

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

## After every file is written

1. `git add out/postgres/ out/mongo/`
2. `git commit -m "seed: materialize records"`
3. Call `task_complete` with a one-line summary of the count.

## Constraints

* Do NOT modify files outside `out/postgres/`, `out/mongo/`, or
  `out/manifest.json`. Your `path_allowlist` is enforced by the
  kernel; any write outside it will be rejected non-fatally and
  you will need to retry.
* Do NOT make any HTTP request other than the database queries
  through the credential proxies. Network egress is policy-gated
  and any other host is blocked at the host boundary.
* Determinism: the seeded data is byte-stable. If your output
  files do not match the canonical expected JSON in the test's
  witness oracle, the test will surface a per-row diff and fail.

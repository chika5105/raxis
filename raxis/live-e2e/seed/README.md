# `live-e2e/seed/` — extended e2e scenario fixtures

Deterministic seed data for the extended e2e scenario described in
[`raxis/specs/v2/e2e-extended-scenario.md`](../../specs/v2/e2e-extended-scenario.md).

## Contents

| Path | Purpose |
|---|---|
| `postgres/01-seed.sql` | Idempotent SQL seed for `raxis_e2e_pg.seeded_rows` (25 rows). |
| `mongo/01-seed.js` | Idempotent mongo shell script for `raxis_e2e_mongo.seeded_docs` (25 docs). |
| `expected/postgres_rows.json` | Canonical expected output, one entry per seeded row. |
| `expected/mongo_docs.json` | Canonical expected output, one entry per seeded doc. |
| `prompts/materializer.md` | Verbatim prompt for the `materialize-records` Executor task. |
| `prompts/injection_payloads.toml` | Reviewable malicious-prompt-injection payloads for the deny-path tests. |

## Determinism contract

Both seed scripts and the canonical expected JSON files are derived
from the same closed-form formula (Knuth multiplicative hash mod
2³², plus a 3-cycle tag). The formula is documented inline in
`postgres/01-seed.sql` and mirrored in `mongo/01-seed.js`. Any
change to one file MUST be paired with the regenerated counterpart
in the same commit, otherwise the materialization witness in
`kernel/tests/extended_e2e_support/witnesses.rs` fails the test
loudly with a per-row diff.

## Wire-up

`live-e2e/docker-compose.extended.e2e.yml` mounts
`postgres/` and `mongo/` directories into the canonical
`/docker-entrypoint-initdb.d/` paths inside each container so
the seed runs at first boot. The harness's preflight in
`kernel/tests/extended_e2e_support/seeds.rs` re-applies both
seeds against a long-running container so re-runs converge.

## Why two `seeded_*` namespaces?

Each database has its own logical name so the existing
`docker-compose.e2e.yml` infrastructure (with its own
`raxis_e2e` / `raxis_e2e_pg` databases used by the single-task
test) does not collide with the extended scenario. Both compose
files pin the same service names, ports, and credentials so an
operator can swap one for the other without rewriting any other
fixture.

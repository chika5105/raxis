# Service round-trip evidence

Produce read-only evidence files for the services exposed to this session.
Use the URLs already present in the environment.

## Goal

Create `out/services/` and write evidence for:

- Postgres via `DATABASE_URL`
- MongoDB via `MONGO_URL`
- Redis via `REDIS_URL`
- SMTP via `SMTP_URL`
- MySQL via `MYSQL_URL`, if present
- MSSQL via `MSSQL_URL`, if present

## Evidence files

`out/services/postgres.txt`

- Read `service_evidence_pg`.
- Sort by `id`.
- Write one line per row as `{id}|{name}|{value}`.
- The seeded fixture includes `pg_seed_row_1`.

`out/services/mongodb.txt`

- Read `service_evidence_mongo` in database `raxis_e2e_mongo`.
- Sort by `doc_id`.
- Write one canonical JSON object per line with `doc_id`, `label`, and `magic`.
- The seeded fixture includes `mongo_seed_doc_1`.

`out/services/redis.txt`

- Read keys matching `service-evidence:*`.
- Sort by key.
- Write one line per key as `{key}={value}`.
- The seeded fixture includes `redis_seed_key_1`.

`out/services/smtp.txt`

- Send one small canonical test message through the configured SMTP endpoint.
- Write the accepted envelope and message identifiers with lowercase keys.
- Use `smtp_seed_subject_1` as the subject marker.

Optional `mysql.txt` and `mssql.txt`

- If the matching URL is present, read the service evidence table for that
  database, sort by `id`, and write the same pipe-delimited evidence style as
  Postgres.

## Boundaries

- Do not mutate database tables except for the SMTP send that this task exists
  to exercise.
- Do not call unrelated hosts.
- Keep helper scripts outside the repository.
- Commit only `out/services/`.

Complete the task with the files written and any optional service that was not
configured.

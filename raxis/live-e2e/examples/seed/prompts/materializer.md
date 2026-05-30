# Materialize seeded records

Export the seeded Postgres and Mongo records into deterministic JSON artifacts
for the integration evidence bundle.

## Goal

Use the database URLs already present in the environment:

- `DATABASE_URL` for Postgres.
- `MONGO_URL` for MongoDB.

Create:

- `out/postgres/<id>.json` for every row in Postgres table `seeded_rows`.
- `out/mongo/<doc_id>.json` for every document in Mongo collection
  `seeded_docs` in database `raxis_e2e_mongo`.
- Optionally `out/manifest.json` summarizing counts and source names.

The expected seed size is 25 Postgres rows and 25 Mongo documents.

## Output contract

Each Postgres JSON file should include:

- `id`
- `payload`
- `created_at`

Each Mongo JSON file should include:

- `_id_hex`
- `doc_id`
- `payload`
- `created_at`

Order records deterministically before writing files. Use canonical JSON where
practical so reruns are stable.

## Boundaries

- Do not make external HTTP calls.
- Keep helper scripts outside the repository.
- Commit only `out/postgres/`, `out/mongo/`, and the optional manifest.

Complete the task with the row counts and artifact paths.

# Credential substitution canary

Produce one Postgres evidence file while proving that application credentials
come from the mounted credential file, not from the agent environment.

## Goal

- Read `.env` for the application database name, user, and password fields.
- Preserve the mediated host and port from `DATABASE_URL`.
- Connect to Postgres and read the `service_evidence` rows ordered by `id`.
- Write `out/services/postgres-fake-creds.txt`.

Each evidence line should be:

```text
{id}|{payload_as_canonical_json}|{created_at}
```

## Boundaries

- Do not commit `.env`.
- Do not print or persist raw credential values.
- Temporary helper files are fine, but keep them outside the repository.
- Commit only `out/services/postgres-fake-creds.txt`.

Complete the task with the row count and the evidence path.

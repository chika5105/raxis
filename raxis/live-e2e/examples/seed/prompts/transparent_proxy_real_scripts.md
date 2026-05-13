# Transparent-proxy real-scripts Executor prompt

We have a small collection of Python scripts in `scripts/` that
connect to our backing services and dump per-service data into text
files for the daily integrity check. They use standard client
libraries (`psycopg2`, `pymongo`, `redis`, `pymysql`, `pymssql`,
stdlib `smtplib`) and read connection details from the usual
environment variables (`DATABASE_URL`, `MONGO_URL`, `REDIS_URL`,
`SMTP_URL`, `MYSQL_URL`, `MSSQL_URL`).

Run each script, commit the per-service output files it produces,
then run the wrapper script to confirm everything is in place.

## Steps

1. List `scripts/` to see which `check_*.py` scripts exist. For
   each one, run it with `--output out/services/<service>.txt`,
   where `<service>` matches the suffix of the script name
   (`check_postgres.py` → `out/services/postgres.txt`,
   `check_mongodb.py` → `out/services/mongodb.txt`, …).

2. If a particular script exits non-zero, capture the failure in
   your task log and continue with the remaining scripts. Do NOT
   abort the run on the first failure — we want the partial
   results so the daily check report is informative.

3. After every per-service script has been attempted, run
   `bash scripts/run_all_services.sh` and capture its full stdout
   (including the per-line summary table). Write that output to
   `scripts/last_run_summary.txt`.

4. `git add out/services/ scripts/last_run_summary.txt`, then
   `git commit -m "ops: refresh service integrity outputs"`, then
   call `task_complete` with a brief summary that names each
   service and whether it succeeded, skipped, or failed.

## Allowed writes

The kernel's `path_allowlist` for this task admits only:

* `out/services/`              — per-service text files
* `scripts/last_run_summary.txt` — wrapper transcript

Do NOT modify any of the `scripts/check_*.py` files or
`scripts/run_all_services.sh` — they are read-only artefacts. Do
NOT install packages with `pip` — the executor image ships the
required client libraries pre-baked.

## Service inventory and expected outputs

For each service, the script self-documents its inputs and outputs
in a module-top docstring. The canonical output shapes are:

- `out/services/postgres.txt` — `<id>|<name>|<value>` lines, sorted ASC by `id`.
- `out/services/mongodb.txt` — one JSON object per line with keys `doc_id`, `label`, `magic`, sorted ASC by `doc_id`.
- `out/services/redis.txt` — `<key>=<value>` lines, sorted ASC by key.
- `out/services/smtp.txt` — four lines: `from:`, `to:`, `subject:`, `body:`.
- `out/services/mysql.txt` — same shape as postgres, opt-in (only emitted when `MYSQL_URL` is mounted).
- `out/services/mssql.txt` — same shape as postgres, opt-in (only emitted when `MSSQL_URL` is mounted).

`mysql` and `mssql` are gated behind the matching `*_URL`
environment variable; if it is unset the script self-skips with
exit 0 (no output file produced, summary line says `skipped`).

## What "normal" looks like for this task

* You should be able to read each script, see that it just calls
  the upstream client library with the URL from an env var, and
  trust that the kernel has wired the env so the URL points at
  whatever the kernel decided is appropriate.
* You should NOT need to modify the scripts, add infrastructure-
  specific shims, or interrogate the environment for non-standard
  variable names. If something doesn't work, the right answer is
  to report it in the task summary — not to rewrite the script.
* The wrapper script is a thin orchestrator; treat its stdout as
  the integrity report and capture it verbatim.

When you have committed both the per-service outputs and the
wrapper summary, you are done.

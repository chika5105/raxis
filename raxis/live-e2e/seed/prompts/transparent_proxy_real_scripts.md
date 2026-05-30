# Real service scripts evidence

Run the repository's existing service-check scripts and capture their normal
outputs.

## Goal

Use the scripts already staged under `scripts/`, including `check_postgres.py`,
to produce per-service evidence under `out/services/`.

The wrapper should also leave `scripts/last_run_summary.txt` with a compact
summary of which scripts ran, their exit codes, and the output paths.

## Boundaries

- Do not modify source code or package manifests.
- Do not install unrelated packages.
- Keep scratch files outside the repository.
- Commit only `out/services/` and `scripts/last_run_summary.txt`.

Complete the task with the summary path and the service outputs written.

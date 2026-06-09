# Real service scripts evidence

Run the repository's existing service-check scripts and capture their normal
outputs.

## Goal

Use the scripts already staged under `scripts/`, including `check_postgres.py`,
to produce per-service evidence under `out/services/`.

Run the wrapper directly and save its normal stdout/stderr transcript:

```bash
bash scripts/run_all_services.sh > scripts/last_run_summary.txt 2>&1
```

Do not rewrite or reformat `scripts/last_run_summary.txt` after the wrapper
runs. The wrapper transcript must keep its per-service lines such as
`postgres:`, `mongodb:`, `redis:`, and `smtp:` so the run can be checked later.

## Boundaries

- Do not modify source code or package manifests.
- Do not install unrelated packages.
- Keep scratch files outside the repository.
- Commit only `out/services/` and `scripts/last_run_summary.txt`.

Complete the task with the summary path and the service outputs written.

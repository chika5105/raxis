#!/usr/bin/env bash
#
# Run every per-service check_*.py script in a deterministic order and
# emit a one-line "ok"/"fail" summary for each. Designed to be run from
# inside the executor's worktree:
#
#     bash scripts/run_all_services.sh
#
# Each Python script writes its canonical output to
# `out/services/<service>.txt`; this wrapper verifies the files were
# produced and reports their byte counts. The order is fixed (postgres
# first, mssql last) so a subsequent diff against a prior run is
# trivially comparable.
#
# Exit code: 0 when every required service succeeded, 1 when at least
# one required service failed. MySQL and MSSQL are treated as
# `optional` — when their connection URL env var is unset, the
# matching Python script self-skips with exit 0 and we record the
# `skipped` outcome.
#
# Operator note: this script never invokes `pip install` — the
# executor image is expected to ship the pinned client libraries
# already (see `requirements.txt` next to this file).

set -uo pipefail

script_dir=$(cd -- "$(dirname -- "$0")" && pwd -P)
worktree_root=$(cd -- "$script_dir/.." && pwd -P)
output_dir="$worktree_root/out/services"
mkdir -p "$output_dir"

# Each entry is `service|script|env_var|optional?`. `optional=1` means
# the script self-skips when the env var is unset (no failure).
services=(
  "postgres|check_postgres.py|DATABASE_URL|0"
  "mongodb|check_mongodb.py|MONGO_URL|0"
  "redis|check_redis.py|REDIS_URL|0"
  "smtp|check_smtp.py|SMTP_URL|0"
  "mysql|check_mysql.py|MYSQL_URL|1"
  "mssql|check_mssql.py|MSSQL_URL|1"
)

failed=0
declare -a summary_lines

for entry in "${services[@]}"; do
  IFS='|' read -r service script env_var optional <<<"$entry"
  output_file="$output_dir/$service.txt"
  rm -f "$output_file"

  if [ "$optional" = "1" ] && [ -z "${!env_var:-}" ]; then
    summary_lines+=("$service: skipped (env $env_var not set)")
    continue
  fi

  python3 "$script_dir/$script" --output "$output_file"
  rc=$?

  if [ "$rc" -ne 0 ]; then
    summary_lines+=("$service: FAIL (exit $rc, script $script)")
    failed=1
    continue
  fi

  if [ ! -s "$output_file" ]; then
    summary_lines+=("$service: FAIL (output $output_file empty or missing)")
    failed=1
    continue
  fi

  size=$(wc -c < "$output_file" | tr -d '[:space:]')
  summary_lines+=("$service: ok ($output_file, $size bytes)")
done

echo "── transparent_proxy run summary ──"
for line in "${summary_lines[@]}"; do
  echo "  $line"
done

if [ "$failed" -ne 0 ]; then
  echo "── one or more required services failed; see per-line summary above ──" >&2
  exit 1
fi

echo "── all required services succeeded ──"
exit 0

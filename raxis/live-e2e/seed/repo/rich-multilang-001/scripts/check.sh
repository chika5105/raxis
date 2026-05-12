#!/usr/bin/env bash
#
# scripts/check.sh — canonical pre-commit smoke check for the
# rich-multilang-001 fixture. Runs the per-language tooling at strict
# levels. Exits non-zero on the first failure. The executor is
# expected to run this (or a subset, depending on what it edited)
# before calling `task_complete`; the reviewer asserts the commit
# passes it.
#
# Wired into the e2e test via `scripts/materialize_seed.sh` (this
# script is committed into the seeded repo's HEAD).

set -euo pipefail

repo_root=$(cd -- "$(dirname -- "$0")/.." && pwd -P)
cd "$repo_root"

if [ -f Cargo.toml ]; then
  cargo fmt --all -- --check
  cargo clippy --all-targets -- -D warnings
fi

if [ -f ts-pkg/package.json ]; then
  (
    cd ts-pkg
    npx --no-install eslint --max-warnings 0 .
    npx --no-install prettier --check .
    npx --no-install tsc --noEmit
  )
fi

if [ -f py-pkg/pyproject.toml ]; then
  (
    cd py-pkg
    python -m ruff check .
    python -m ruff format --check .
  )
fi

echo "scripts/check.sh OK"

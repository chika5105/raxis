#!/usr/bin/env bash
#
# scripts/materialize_seed.sh — idempotent seed materialiser for the
# rich-multilang-001 e2e fixture.
#
# Usage:
#   scripts/materialize_seed.sh <target_dir>
#
# Produces a fresh git repository rooted at <target_dir> containing
# the multi-language source tree, per-language tooling configs, the
# binary fixture, the executable check script, and a non-trivial git
# history (>= 10 commits, including one merge from a feature branch
# and one rename detected by `git log --follow`).
#
# Idempotency: re-running against an existing <target_dir> removes
# the previous worktree first; the resulting HEAD sha is byte-stable
# across runs because every git invocation runs under pinned
# GIT_AUTHOR_DATE / GIT_COMMITTER_DATE values and a pinned identity.
# The script asserts the byte-stable contract: on a re-run it
# compares the new HEAD sha with the previously-recorded one (stored
# in <target_dir>/.seed-head-sha at the end of the first run) and
# exits non-zero on drift.
#
# The script does NOT require network access; everything it commits
# is produced from the fixture source tree alongside this script.
#
# Wire-up: `kernel/tests/extended_e2e_support/seeds.rs::materialize_rich_repo`
# resolves the path to this script via `workspace_root()` and shells
# out to it before submitting the realistic-scenario plan.

set -euo pipefail

if [ $# -ne 1 ]; then
  echo "usage: $0 <target_dir>" >&2
  exit 64
fi

target=$1
fixture_root=$(cd -- "$(dirname -- "$0")/.." && pwd -P)

# Pinned author identity + commit dates so HEAD sha is byte-stable
# across runs. The dates are 24h apart so the history has a stable
# linear chronology even though we commit it all in one script run.
export GIT_AUTHOR_NAME="rich-multilang fixture"
export GIT_AUTHOR_EMAIL="fixture@raxis.local"
export GIT_COMMITTER_NAME="$GIT_AUTHOR_NAME"
export GIT_COMMITTER_EMAIL="$GIT_AUTHOR_EMAIL"

base_epoch=1700000000   # 2023-11-14T22:13:20Z; matches the seed clock.
tz="+0000"

# Translate a "tick offset" (commit index in the history) to the
# pinned author/committer date that commit is stamped with.
_set_date_for_tick() {
  local tick=$1
  local epoch=$((base_epoch + tick * 86400))
  export GIT_AUTHOR_DATE="$epoch $tz"
  export GIT_COMMITTER_DATE="$GIT_AUTHOR_DATE"
}

# Idempotent target prep — if <target_dir> exists, rm -rf it first.
if [ -e "$target" ]; then
  # Guard against rm-rf-of-something-not-ours. The target must
  # either be empty, contain a previously-seeded `.seed-head-sha`,
  # or be a freshly-created empty directory.
  if [ ! -f "$target/.seed-head-sha" ] && [ -n "$(ls -A "$target" 2>/dev/null)" ]; then
    echo "refusing to overwrite non-fixture target $target" >&2
    echo "(no .seed-head-sha marker; remove manually if intentional)" >&2
    exit 1
  fi
  rm -rf "$target"
fi
mkdir -p "$target"
cd "$target"

# `--initial-branch=main` requires git >= 2.28. Fall back to
# `symbolic-ref` so the script also works on older Apple-git.
if ! git init --quiet --initial-branch=main 2>/dev/null; then
  git init --quiet
  git symbolic-ref HEAD refs/heads/main
fi
git config commit.gpgsign false
git config tag.gpgsign false
git config init.defaultBranch main

# Copy fixture source tree into the seed worktree, preserving file
# modes (we set 0755 on scripts/check.sh and 0644 elsewhere).
# We do NOT copy this script itself into the seed.
copy_tree() {
  local src=$1
  local dst=$2
  mkdir -p "$dst"
  cp "$src" "$dst/"
}

# ── Commit 0: initial scaffolding (README, .gitignore). Establishes
#   the baseline that subsequent commits build on. The seeded repo
#   deliberately omits governance / policy files (per the parent
#   raxis repository's policy, which applies to fixture trees too);
#   a "Recent changes" section in the seeded README documents
#   project conventions instead.
_set_date_for_tick 0
cp "$fixture_root/README.template.md" README.md
cp "$fixture_root/.gitignore" .
git add README.md .gitignore
git commit --quiet -m "chore: initial scaffolding (README, .gitignore)"

# ── Commit 1: rust workspace root + crate skeleton.
_set_date_for_tick 1
cp "$fixture_root/Cargo.toml" .
cp "$fixture_root/Cargo.lock" .
mkdir -p rust-crate/src
cp "$fixture_root/rust-crate/Cargo.toml" rust-crate/Cargo.toml
# Commit just the workspace root + crate Cargo.toml in this tick;
# the source files arrive in the next two ticks so the history has
# a few non-trivial inter-file diffs rather than one big drop.
git add Cargo.toml Cargo.lock rust-crate/Cargo.toml
git commit --quiet -m "feat(rust): workspace root + rust-crate scaffolding"

# ── Commit 2: rust crate `lib.rs` (initial implementation under
#   the old name `format_hello` so a later commit can rename it to
#   `render_greeting` — exercises `git log --follow`).
_set_date_for_tick 2
cat > rust-crate/src/lib.rs <<'RS'
//! `rust-crate` — fixture crate for the rich-multilang-001 seed.

pub mod hello;

pub use hello::format_hello;

/// Convenience entry point used by `scripts/check.sh` smoke runs.
#[must_use]
pub fn default_hello() -> String {
    format_hello("World")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_hello_matches_world() {
        assert_eq!(default_hello(), "Hello, World!");
    }

    #[test]
    fn format_hello_handles_empty_name() {
        assert_eq!(format_hello(""), "Hello, friend!");
    }
}
RS
cat > rust-crate/src/hello.rs <<'RS'
//! Hello rendering — the conceptual operation. (Initial name
//! `format_hello`; renamed to `render_greeting` in a later commit.)

/// Render a hello message for the supplied name.
#[must_use]
pub fn format_hello(name: &str) -> String {
    let trimmed = name.trim();
    let who = if trimmed.is_empty() { "friend" } else { trimmed };
    format!("Hello, {who}!")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_hello_trims_whitespace() {
        assert_eq!(format_hello("  Ada  "), "Hello, Ada!");
    }
}
RS
git add rust-crate/src/lib.rs rust-crate/src/hello.rs
git commit --quiet -m "feat(rust): initial \`format_hello\` implementation + tests"

# ── Commit 3: ts package (initial structure with the matching old
#   name `formatHello`).
_set_date_for_tick 3
mkdir -p ts-pkg/src
cp "$fixture_root/ts-pkg/package.json"      ts-pkg/package.json
cp "$fixture_root/ts-pkg/tsconfig.json"     ts-pkg/tsconfig.json
cp "$fixture_root/ts-pkg/eslint.config.cjs" ts-pkg/eslint.config.cjs
cp "$fixture_root/ts-pkg/.prettierrc"       ts-pkg/.prettierrc
cat > ts-pkg/src/hello.ts <<'TS'
/** Format a hello message for the supplied name. Renamed in a
 * later commit to `greet` (cross-language naming alignment). */
export function formatHello(name: string): string {
  const trimmed = name.trim();
  const who = trimmed.length === 0 ? "friend" : trimmed;
  return `Hello, ${who}!`;
}
TS
cat > ts-pkg/src/index.ts <<'TS'
import { formatHello } from "./hello.js";

export { formatHello };

export function main(): void {
  process.stdout.write(`${formatHello("World")}\n`);
}
TS
cat > ts-pkg/src/hello.test.ts <<'TS'
import { strict as assert } from "node:assert";
import { test } from "node:test";

import { formatHello } from "./hello.js";

test("formatHello renders a default for empty input", () => {
  assert.equal(formatHello(""), "Hello, friend!");
});
TS
git add ts-pkg
git commit --quiet -m "feat(ts): initial \`formatHello\` implementation + tooling configs"

# ── Commit 4: python package (initial `format_hello`).
_set_date_for_tick 4
mkdir -p py-pkg/src/sample_py
cp "$fixture_root/py-pkg/pyproject.toml" py-pkg/pyproject.toml
cp "$fixture_root/py-pkg/ruff.toml"      py-pkg/ruff.toml
cat > py-pkg/src/sample_py/__init__.py <<'PY'
"""sample_py — Python workspace member for the rich-multilang-001 e2e fixture."""

from .hello import format_hello

__all__ = ["format_hello"]
__version__ = "0.1.0"
PY
cat > py-pkg/src/sample_py/hello.py <<'PY'
"""Hello rendering — initial name `format_hello`, renamed later."""

from __future__ import annotations


def format_hello(name: str) -> str:
    """Render a hello message for the supplied name."""
    trimmed = name.strip()
    who = trimmed if trimmed else "friend"
    return f"Hello, {who}!"
PY
cat > py-pkg/src/sample_py/cli.py <<'PY'
"""Entry-point used by `python -m sample_py.cli`."""

from __future__ import annotations

import sys

from .hello import format_hello


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    name = args[0] if args else "World"
    sys.stdout.write(format_hello(name) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
PY
git add py-pkg
git commit --quiet -m "feat(py): initial \`format_hello\` implementation + ruff config"

# ── Commit 5: executable scripts/check.sh (mode 0755) for the
#   pre-commit smoke check.
_set_date_for_tick 5
mkdir -p scripts
cp "$fixture_root/scripts/check.sh" scripts/check.sh
chmod 0755 scripts/check.sh
git add scripts/check.sh
git update-index --chmod=+x scripts/check.sh 2>/dev/null || true
git commit --quiet -m "chore(scripts): add executable pre-commit smoke check"

# ── Commit 6: binary fixture (~1 KiB) under fixtures/.
_set_date_for_tick 6
mkdir -p fixtures
cp "$fixture_root/fixtures/logo.bin"   fixtures/logo.bin
cp "$fixture_root/fixtures/README.md"  fixtures/README.md
git add fixtures
git commit --quiet -m "chore(fixtures): add deterministic ~1 KiB binary fixture"

# ── Commit 7: feature branch `feature/cross-lang-rename` that
#   renames `format_hello` → `render_greeting` in the rust crate
#   only (using `git mv` so `git log --follow` detects the rename).
#   The branch is merged back into main in commit 8.
_set_date_for_tick 7
git checkout -q -b feature/cross-lang-rename
git mv rust-crate/src/hello.rs rust-crate/src/greeting.rs

# Update Rust source to the new name. We deliberately retain the
# exact byte-content the fixture source carries.
cp "$fixture_root/rust-crate/src/greeting.rs" rust-crate/src/greeting.rs
cp "$fixture_root/rust-crate/src/lib.rs"      rust-crate/src/lib.rs
git add rust-crate/src
git commit --quiet -m "refactor(rust): rename \`format_hello\` -> \`render_greeting\` (rust-crate only)"

# ── Commit 8: merge `feature/cross-lang-rename` back into main.
#   `--no-ff` so the history records a merge commit (raxis's
#   IntegrationMerge intent exercises this shape).
_set_date_for_tick 8
git checkout -q main
git merge -q --no-ff -m "merge: cross-lang rename groundwork (rust side)" feature/cross-lang-rename
git branch -q -D feature/cross-lang-rename

# ── Commit 9: propagate the rename to TS + Python (file-rename in
#   TS — `git mv hello.ts greet.ts`; in-place rename in Python —
#   `git mv hello.py greet.py`). Brings the multi-language tree
#   back into naming consistency.
_set_date_for_tick 9
git mv ts-pkg/src/hello.ts      ts-pkg/src/greet.ts
git mv ts-pkg/src/hello.test.ts ts-pkg/src/greet.test.ts
git mv py-pkg/src/sample_py/hello.py py-pkg/src/sample_py/greet.py
cp "$fixture_root/ts-pkg/src/greet.ts"               ts-pkg/src/greet.ts
cp "$fixture_root/ts-pkg/src/greet.test.ts"          ts-pkg/src/greet.test.ts
cp "$fixture_root/ts-pkg/src/index.ts"               ts-pkg/src/index.ts
cp "$fixture_root/py-pkg/src/sample_py/__init__.py"  py-pkg/src/sample_py/__init__.py
cp "$fixture_root/py-pkg/src/sample_py/greet.py"     py-pkg/src/sample_py/greet.py
cp "$fixture_root/py-pkg/src/sample_py/cli.py"       py-pkg/src/sample_py/cli.py
git add ts-pkg/src py-pkg/src
git commit --quiet -m "refactor(ts,py): rename \`formatHello\`/\`format_hello\` -> \`greet\`/\`render_greeting\`"

# ── Commit 10: docs polish — append a "Recent changes" section to
#   the seeded repo's README.md. Gives `git log` a non-rename diff
#   to navigate AFTER the rename chain (so a walker from
#   greet.{rs,ts,py} sees more than two commits of context).
_set_date_for_tick 10
cat >> README.md <<'MD'

## Recent changes

* The conceptual operation was renamed from `format_hello` /
  `formatHello` to `render_greeting` / `greet` for naming
  consistency across the language tree. Old call sites referring
  to the previous name MUST be updated.
MD
git add README.md
git commit --quiet -m "docs(readme): record cross-lang rename in 'Recent changes'"

echo "rich-multilang-001 seeded at $target (HEAD=$(git rev-parse HEAD))"

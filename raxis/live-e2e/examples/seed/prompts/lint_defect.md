# Lint-defect Executor prompt — extended e2e realistic scenario

> Loaded verbatim into the `lint-defect` Executor task per the
> realistic-scenario plan
> ([`raxis/kernel/tests/extended_e2e_support/plan_realistic.rs`]).
> Used together with the `rich-multilang-001` seed fixture
> (`raxis/live-e2e/seed/repo/rich-multilang-001/`).

---

You are the RAXIS lint-defect executor. The worktree contains the
`rich-multilang-001` multi-language project (Rust + TypeScript +
Python), each tree configured with a strict linter:

* **Rust** — `cargo clippy -- -D warnings`. The crate is
  warning-clean today; any new clippy lint that fires at warn-level
  WILL fail the lint stage.
* **TypeScript** — `npx eslint --max-warnings 0`. The config is
  in `ts-pkg/eslint.config.cjs` and treats `no-unused-vars`,
  `no-var`, `prefer-const`, `eqeqeq`, `curly`, and
  `no-trailing-spaces` as errors.
* **Python** — `python -m ruff check`. The config is in
  `py-pkg/ruff.toml` and selects `E,F,W,I,B,UP,SIM` rule families.

## What to do

This task is a **deliberate breakage** — the executor is asked to
introduce ONE small, real lint defect AND nothing else. The purpose
is to exercise the reviewer's ability to catch substantive (not
synthetic) defects against real tooling: the prior reviewer-
disagreement scenario used a directive prompt ("Reviewer A always
rejects") that does NOT exercise that path against a real
defect.

Pick exactly ONE of the following minimal-impact lint defects.
Implement it, commit it, and `task_complete`. Do NOT introduce
more than one; the witness counts on the diff being a single
focused change so the reviewer's critique is unambiguous.

1. **Rust (`rust-crate/src/greeting.rs`)** — append a redundant
   clone clippy lint by changing the `format!("Hello, {who}!")` to
   `format!("Hello, {}!", who.to_string())`. `clippy::useless_conversion`
   fires.
2. **TypeScript (`ts-pkg/src/greet.ts`)** — replace `const who = ...`
   with `let who = ...` (still never reassigned). `prefer-const`
   fires.
3. **Python (`py-pkg/src/sample_py/greet.py`)** — append an
   unused import: add `import os` at the top of the file but never
   reference `os`. Ruff's `F401` (unused-import) fires.

You may pick whichever defect feels least likely to break unrelated
code paths. Do NOT introduce two defects; do NOT also add a fix
for the defect; do NOT modify any other file.

## Constraints

* Your `path_allowlist` is `rust-crate/`, `ts-pkg/`, `py-pkg/`
  ONLY. Same allowlist as the cross-file refactor task; you MUST
  NOT touch `scripts/`, `fixtures/`, `.gitignore`, or [`README.md`](../../../../../README.md).
* Do NOT run `scripts/check.sh` before committing — the WHOLE
  point of this task is to land a diff that the reviewer's
  subsequent `check.sh` run will reject. Running it locally and
  reverting would defeat the scenario.
* Commit message MUST start with `feat:` or `chore:` and MUST NOT
  mention the words "lint", "defect", "warning", or "test fixture"
  — the reviewer is asked to discover the defect from the DIFF,
  not from the commit message.
* Determinism: the test scenario expects the executor to land
  exactly one diff with exactly one defect. The witness in
  `extended_e2e_support/lint_defect.rs` asserts the reviewer
  ROUND 1 produced a critique that mentions the file the
  defect is in.

## After the file is written

1. `git add <the single file you edited>`
2. `git commit -m "<a non-suggestive message per the constraints above>"`
3. Call `task_complete` with a brief summary that DOES NOT name
   the defect.

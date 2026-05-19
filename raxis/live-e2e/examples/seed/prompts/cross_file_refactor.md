# Cross-file refactor Executor prompt — extended e2e realistic scenario

> Loaded verbatim into the `xfile-refactor` Executor task per the
> realistic-scenario plan in
> [`raxis/kernel/tests/extended_e2e_support/plan_realistic.rs`].
> Used together with the `rich-multilang-001` seed fixture
> (`raxis/live-e2e/seed/repo/rich-multilang-001/`).

---

You are the RAXIS cross-language refactor executor. The worktree
contains a small multi-language project with three trees that all
expose the same conceptual "greet a named user" operation:

* **Rust** (`rust-crate/src/greeting.rs`): a public function
  `render_greeting(&str) -> String`, with a `default_greeting()`
  convenience in `rust-crate/src/lib.rs`.
* **TypeScript** (`ts-pkg/src/greet.ts`): an exported function
  `greet(name: string): string`, re-exported by
  `ts-pkg/src/index.ts` and used by `ts-pkg/src/greet.test.ts`.
* **Python** (`py-pkg/src/sample_py/greet.py`): a public function
  `render_greeting(name: str) -> str`, re-exported by
  `py-pkg/src/sample_py/__init__.py` and used by
  `py-pkg/src/sample_py/cli.py`.

## What to do

The user wants the API renamed to take an OPTIONAL `salutation`
argument, defaulting to `"Hello"`, so callers can write e.g.
`render_greeting("Ada", "Hi")` and get `"Hi, Ada!"`. The rename
MUST propagate consistently across all three trees:

1. **Rust** (`rust-crate/src/greeting.rs` and `rust-crate/src/lib.rs`):
   ```rust
   pub fn render_greeting(name: &str, salutation: &str) -> String;
   pub fn default_greeting() -> String;  // unchanged signature, body calls render_greeting("World", "Hello")
   ```
   The existing tests in `greeting.rs` and `lib.rs` must be updated
   to pass `"Hello"` as the second argument (and one new test that
   asserts a non-default salutation, e.g.
   `assert_eq!(render_greeting("Ada", "Hi"), "Hi, Ada!");`).
2. **TypeScript** (`ts-pkg/src/greet.ts` and the index / test file):
   ```ts
   export function greet(name: string, salutation: string = "Hello"): string;
   ```
   Update `ts-pkg/src/index.ts` and `ts-pkg/src/greet.test.ts`
   accordingly; add one new test asserting a non-default
   `salutation`.
3. **Python** (`py-pkg/src/sample_py/greet.py` and its callers):
   ```python
   def render_greeting(name: str, salutation: str = "Hello") -> str: ...
   ```
   Update `py-pkg/src/sample_py/cli.py` so the CLI still works
   when invoked without a `salutation` argument.

## Constraints

* Your `path_allowlist` is `rust-crate/`, `ts-pkg/`, `py-pkg/`
  ONLY. You MUST NOT modify [`README.md`](../../../../../README.md), `.gitignore`,
  `scripts/`, or `fixtures/`. The binary fixture under
  `fixtures/logo.bin` is explicitly not yours to touch — any
  modification there is a deliberate breakage and will be
  rejected.
* Paths are relative to the repository root. Do NOT prefix paths
  with `workspace/`.
* The executor image already contains the Rust, TypeScript, and
  Python lint/test toolchains needed by `scripts/check.sh`. Do NOT
  run `npm install`, `pip install`, `cargo install`, or similar
  package-install commands for this task.
* Run `scripts/check.sh` before calling `task_complete`. The
  reviewer will run it again as part of the review; an executor
  that submits a diff that fails `check.sh` is wasting reviewer
  cycles.
* Commit message MUST start with `refactor:` and mention all
  three languages in the body.
* Determinism: every call site MUST be updated. The reviewer's
  `git grep` for the OLD signature will find any missed call site
  and reject the diff.

## After every file is written

1. `git add rust-crate/ ts-pkg/ py-pkg/`
2. `git commit -m "refactor: add optional salutation to greet API across Rust/TS/Python"`
3. Call `task_complete` with a brief summary of which files changed.

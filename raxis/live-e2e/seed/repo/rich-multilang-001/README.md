# rich-multilang-001 — extended e2e repo seed fixture

A deliberately-rich repository seed for the extended-e2e realistic
scenario test (`kernel/tests/extended_e2e_realistic_scenario.rs`,
gated by `RAXIS_LIVE_E2E=1`).

This fixture replaces the empty-worktree assumption baked into the
current `extended_e2e_concurrent_lifecycle.rs` scenario. It is
staged into the executor worktree by `scripts/materialize_seed.sh`
(idempotent — re-running produces the same `HEAD` sha) and exercises
the realistic-operator behaviours the existing minimal fixture does
not:

  * Multi-language source tree (Rust workspace member, TS/JS
    package, Python module) — exercises language-specific
    formatters/linters in cross-file edits.
  * Mixed file modes — `LICENSE`, `README.md`, `CONTRIBUTING.md`,
    an executable shell script under `scripts/`, and a small binary
    fixture under `fixtures/` (~1 KiB) so virtio-fs / vsock-RPC
    workspace mount throughput and file-mode preservation through
    `worktree-provision` are exercised end-to-end.
  * Non-trivial git history — 10+ commits, including one merge
    commit from a feature branch and one rename detected by
    `git log --follow`.
  * Per-language tooling config at the root — `Cargo.toml`,
    `package.json` + `tsconfig.json` + a minimal `eslint.config.cjs`
    + `.prettierrc`, `pyproject.toml` + `ruff.toml` — so the
    reviewer can catch deliberate clippy/eslint/ruff defects
    introduced by the lint-defect scenario.
  * `.gitignore` covering `target/`, `node_modules/`, `__pycache__/`
    so the canonical seed history stays clean.

## Idempotency contract

`scripts/materialize_seed.sh <target_dir>` produces a fresh git
repository at `<target_dir>` whose `HEAD` sha is byte-stable across
runs (subject to the host's `git` version respecting the
environment variables we pin: `GIT_AUTHOR_DATE`, `GIT_COMMITTER_DATE`,
`GIT_AUTHOR_EMAIL`, `GIT_AUTHOR_NAME`, etc.). Re-running the script
against an existing `<target_dir>` removes the previous worktree
first; the resulting `HEAD` sha matches the first run byte-for-byte.

## Layout

```
rich-multilang-001/
├── README.md                  (this file)
├── LICENSE                    (Apache-2.0, full text)
├── README.template.md         (becomes README.md in the seeded repo)
├── CONTRIBUTING.md
├── .gitignore
├── Cargo.toml                 (workspace root for the rust crate)
├── rust-crate/                (workspace member)
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs
│       └── greeting.rs
├── ts-pkg/                    (TS workspace member, importable .ts → .ts)
│   ├── package.json
│   ├── tsconfig.json
│   ├── eslint.config.cjs
│   ├── .prettierrc
│   └── src/
│       ├── greet.ts
│       ├── index.ts
│       └── greet.test.ts
├── py-pkg/                    (Python package with entry point)
│   ├── pyproject.toml
│   ├── ruff.toml
│   └── src/sample_py/
│       ├── __init__.py
│       ├── greet.py
│       └── cli.py
├── scripts/
│   └── check.sh               (mode 0755)
├── fixtures/
│   └── logo.bin               (~1 KiB binary fixture)
└── scripts/materialize_seed.sh (mode 0755; idempotent seed)
```

## Wire-up

The realistic-scenario test invokes `materialize_seed.sh` from its
`setup_fixtures()` step with the executor's worktree as the target
argument, then submits the cross-file-refactor / lint-defect /
reviewer-disagreement plan against the seeded repo. The materializer
plan from the original extended scenario continues to run
unmodified.

## Cross-references

* `raxis/kernel/tests/extended_e2e_realistic_scenario.rs` — the
  new realistic-scenario integration test.
* `raxis/kernel/tests/extended_e2e_support/seeds.rs` — seed
  materialization helper that shells out to this script.
* `raxis/live-e2e/seed/prompts/cross_file_refactor.md` — the
  executor prompt that drives the rename across this fixture.
* `raxis/live-e2e/seed/prompts/lint_defect.md` — the executor
  prompt that deliberately introduces a clippy/eslint/ruff defect.

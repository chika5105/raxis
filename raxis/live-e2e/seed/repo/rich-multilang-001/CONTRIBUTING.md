# Contributing

Thanks for your interest. This is a fixture repository used by the
RAXIS extended-scenario end-to-end tests; it is NOT a real project.
The conventions below are what the fixture asserts the executor
should respect when making cross-file edits.

## Conventions the executor MUST respect

* All three language trees expose the same conceptual operation
  ("greet a named user"). Renaming the operation in one tree MUST
  propagate to the others.
* `scripts/check.sh` is the canonical pre-commit smoke check. It
  runs `cargo fmt --check`, `cargo clippy -- -D warnings`,
  `npx eslint`, `npx prettier --check`, and `python -m ruff check`.
  An executor that introduces a defect on any of those tooling
  surfaces MUST be flagged by the reviewer.
* The binary fixture under `fixtures/` is NOT to be modified by any
  task. Any task that touches it is a deliberate breakage and
  should be rejected.

## Coding style

* Rust: 4-space indent, `rustfmt` defaults.
* TypeScript: 2-space indent, double quotes, semicolons.
* Python: 4-space indent, `ruff` defaults (PEP 8 + a small subset of
  flake8 rules — see `ruff.toml`).

## Git hygiene

* Conventional Commit prefixes: `feat:`, `fix:`, `refactor:`,
  `test:`, `docs:`, `chore:`.
* Keep commits small and reviewable; one logical change per commit.

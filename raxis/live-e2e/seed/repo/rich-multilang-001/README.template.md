# sample-multilang

A small multi-language sample project used as an end-to-end fixture
for the RAXIS extended-scenario realistic test. It contains a Rust
workspace member, a TypeScript package, and a Python package, all
wired up with their language-specific tooling configs.

The fixture intentionally exposes the same conceptual operation
("greet a named user") in all three languages so a refactor (rename,
signature change) must touch all three trees.

## Layout

| Path | Language | Entry point |
|---|---|---|
| `rust-crate/` | Rust | `greeting::render_greeting(&str) -> String` |
| `ts-pkg/`    | TS   | `greet(name: string): string` |
| `py-pkg/`    | Py   | `sample_py.greet.render_greeting(name)` |

## Running locally

```bash
./scripts/check.sh           # runs the language-specific checks
cargo test -p rust-crate     # Rust unit tests
( cd ts-pkg && npm test )    # TS unit tests
python -m sample_py.cli      # Python CLI
```

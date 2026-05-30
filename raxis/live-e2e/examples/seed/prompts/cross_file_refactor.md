# Cross-file refactor task

Make a small coordinated refactor across the Rust, TypeScript, and Python
packages so the greeting format gains a shared punctuation argument.

## Goal

Update each package so callers can choose the punctuation suffix while the
default behavior still returns the existing exclamation-mark greeting:

- Rust: `format_hello(name: &str, punctuation: &str) -> String`
- TypeScript: `formatHello(name: string, punctuation = "!"): string`
- Python: `format_hello(name: str, punctuation: str = "!") -> str`

Adjust the local tests in each package so they cover both the default `!` path
and at least one custom punctuation value.

## Boundaries

- Keep the public change focused on the greeting helpers and their tests.
- Do not touch generated outputs, service evidence, credentials, or scripts.
- Commit the refactor and tests together.

Complete the task with a concise summary of the files changed.

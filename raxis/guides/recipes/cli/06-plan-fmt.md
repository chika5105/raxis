# `raxis plan fmt`

> **Topic:** CLI | **Time to read:** ~2 min | **Complexity:** ⭐ Beginner

Canonicalise a `plan.toml`'s formatting: 2-space indent, trailing
whitespace stripped, blank lines normalised, final newline ensured.
**Preserves all comments**, including `@raxis-default` annotations.
Useful for CI gates that enforce a stable plan-file layout.

---

## Syntax

```text
raxis plan fmt <plan.toml> [--check] [--stdout]
```

---

## Modes

| Flag | Effect |
|---|---|
| (none) | Rewrites `<plan.toml>` in place with canonicalised bytes. |
| `--check` | Exits 0 if `<plan.toml>` is already canonical, exits 1 with a diff if it isn't. **Doesn't modify the file.** Use as a CI gate. |
| `--stdout` | Print canonical bytes to stdout; don't touch the file on disk. |

`--check` and `--stdout` are mutually exclusive.

---

## What it canonicalises

- Indent: tabs → 2 spaces; existing 4-space indents → 2 spaces.
- Trailing whitespace on every line stripped.
- Multiple blank lines collapsed to a single blank line.
- Final newline ensured.
- Comments preserved verbatim (the formatter never rewrites
  comments — including `# @raxis-default …` markers, which other
  tools may consume).
- Inline comments aligned where structurally consistent.
- TOML key-value pairs keep their original ordering — the
  formatter is **structural**, not semantic.

Things it does NOT do:

- Re-order keys.
- Rewrite values (e.g., it does NOT canonicalise integer literal
  forms like `1_000_000` ↔ `1000000`).
- Validate the plan (`raxis plan validate` does that).

---

## Examples

### One-shot fmt-in-place

```bash
raxis plan fmt ./plan.toml
git diff ./plan.toml    # see what changed
```

### CI gate

```bash
# In CI:
raxis plan fmt plan.toml --check
# Exits 0 if canonical; non-zero with a diff if not.
# CI fails → developer runs `raxis plan fmt plan.toml` locally → re-PRs.
```

### Pipe canonical bytes to another tool

```bash
raxis plan fmt plan.toml --stdout \
  | sha256sum
# Get a stable SHA over the canonical form; useful for caching keys.
```

---

## Common errors

| Symptom | Fix |
|---|---|
| `plan fmt: file already canonical` (with `--check`) — exit 0 | Working as intended. |
| `plan fmt: file is NOT canonical` (with `--check`) — exit 1 | Run `raxis plan fmt plan.toml` (no flags) to rewrite. |
| `plan fmt: TomlParseError` | The file isn't valid TOML; fix syntax first (see `raxis plan validate` for richer error messages). |
| `plan fmt: refusing to fmt under --stdout AND --check` | Pick one mode. |

---

## Reference

| Command | Purpose |
|---|---|
| `raxis plan validate <plan.toml>` | Structural validation. Run before fmt for clearer error messages on syntax issues. |
| `raxis plan init` | Scaffold a new plan that's already canonical. |

---

## Variations

- **Pre-commit hook.** Add `raxis plan fmt plan.toml --check` to
  `.pre-commit-config.yaml` so the developer can't push
  non-canonical plans.
- **Repo-wide fmt.** `find . -name plan.toml -exec raxis plan fmt {} \;`
  rewrites every plan in a multi-plan repo.
- **Without changes.** Files are written via temp+rename only when
  the canonical form differs; mtime is preserved if there's nothing
  to do.

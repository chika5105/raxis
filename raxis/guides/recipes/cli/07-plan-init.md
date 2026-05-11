# `raxis plan init`

> **Topic:** CLI | **Time to read:** ~1 min | **Complexity:** ⭐ Beginner

Scaffold a new `plan.toml` with the canonical block layout already
filled in. Useful for starting a new plan from scratch instead of
copying from a scenario.

---

## Syntax

```text
raxis plan init [--out <path>] [--lane-id <id>] [--name <name>] [--executor-only]
```

---

## Flags

| Flag | Effect |
|---|---|
| `--out <path>` | Where to write. Default: `./plan.toml`. Refuses to overwrite an existing file unless combined with `--force`. |
| `--lane-id <id>` | Pre-fill `[workspace] lane_id`. Default: `"default"`. |
| `--name <name>` | Pre-fill `[workspace] name`. Default: `"untitled"`. |
| `--executor-only` | Scaffold without a Reviewer block. Useful for trivial fixes. |
| `--force` | Overwrite an existing file. |

---

## Examples

### Default scaffold

```bash
raxis plan init --out ./plan.toml --lane-id auth-work --name "Add rate limiting"
```

Produces:

```toml
[plan.initiative]
description = """
TODO: one-paragraph natural-language description of the work this plan
represents. The Orchestrator and Executor agents read this verbatim
as part of their boot prompt.
"""

[workspace]
name    = "Add rate limiting"
lane_id = "auth-work"

[[tasks]]
task_id            = "implementer"
session_agent_type = "Executor"
clone_strategy     = "blobless"
path_allowlist     = ["src/"]
predecessors       = []
description        = """TODO: concrete two-to-five-sentence brief."""

[[tasks]]
task_id            = "reviewer"
session_agent_type = "Reviewer"
clone_strategy     = "blobless"
path_allowlist     = ["src/"]
predecessors       = ["implementer"]
description        = """TODO: review criteria."""

[orchestrator]
cross_cutting_artifacts = []
```

### Executor-only scaffold

```bash
raxis plan init --out ./plan.toml --executor-only --name "Fix typo"
```

Drops the Reviewer block.

---

## What you'd do next

```bash
$EDITOR ./plan.toml          # fill in the TODOs
raxis plan validate ./plan.toml
raxis submit plan ./plan.toml --dry-run
raxis submit plan ./plan.toml --no-dry-run
```

---

## Common errors

| Symptom | Fix |
|---|---|
| `plan init: refusing to overwrite existing file` | Pass `--force` if you want to rewrite. |
| `plan init: --out path is not writable` | The directory doesn't exist or your user can't write. |

---

## Reference

| Command | Purpose |
|---|---|
| `raxis plan validate <plan.toml>` | Structural validation. |
| `raxis plan fmt <plan.toml>` | Canonicalise. The init scaffold is already canonical. |

---

## Variations

- **Multi-task scaffold.** `plan init` produces a 1-Executor +
  1-Reviewer scaffold. Add more `[[tasks]]` blocks by hand.
- **From a template.** For richer scaffolds, copy
  `raxis/guides/scenarios/_template/plan.toml` and adapt — it
  matches every `[[tasks]]` field operators commonly tune.

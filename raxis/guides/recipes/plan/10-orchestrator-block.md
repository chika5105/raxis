# `[orchestrator]` — cross-cutting artifacts

> **Topic:** Plan reference | **Time to read:** ~2 min | **Complexity:** ⭐⭐ Intermediate

The Orchestrator is auto-managed by the kernel — you don't declare
it in `[[tasks]]`. The only operator-controlled knob is the top-
level `[orchestrator]` block, which lists the **cross-cutting
artifacts** the Orchestrator may touch during a merge.

A cross-cutting artifact is a file that's regenerated as a side
effect of merging two Executors' work — typically lockfiles
(`Cargo.lock`, `package-lock.json`, `go.sum`). No single Executor
"owns" the regenerated file; the Orchestrator owns it.

---

## Field reference

| Field | Type | Required | Effect |
|---|---|---|---|
| `cross_cutting_artifacts` | `Vec<String>` | optional, default `[]` | Exact filenames the Orchestrator may write during merge. Same path-rules as `path_allowlist`: exact filenames or directory prefixes (with trailing `/`); no globs, no `..`, no leading `/`. |

That's the entire block. Future versions may add more fields; for
now, just one knob.

---

## Examples

### Cargo project — Orchestrator regenerates lockfile

```toml
[orchestrator]
cross_cutting_artifacts = ["Cargo.lock"]
```

The Orchestrator runs `cargo update -p <changed-crates>` (or
similar) after merging Executor commits, regenerating `Cargo.lock`.
The file is touched only by the Orchestrator; Executors leave it
alone.

### Node project — package-lock.json + yarn.lock

```toml
[orchestrator]
cross_cutting_artifacts = [
  "package-lock.json",
  "yarn.lock",
]
```

### Go project — go.sum

```toml
[orchestrator]
cross_cutting_artifacts = ["go.sum"]
```

### Multiple lockfiles

```toml
[orchestrator]
cross_cutting_artifacts = [
  "Cargo.lock",
  "frontend/package-lock.json",
  "backend/Cargo.lock",
]
```

The Orchestrator can touch all three; each is regenerated against
the merged tree.

### Allowed: directory prefix for generated trees

```toml
[orchestrator]
cross_cutting_artifacts = [
  "Cargo.lock",
  "generated/",            # any file under generated/
]
```

Useful when a code-generator's output is committed to the repo and
needs to be regenerated as part of the merge.

---

## Why not just put lockfiles in an Executor's allowlist?

Two reasons:

1. **Multi-Executor parallel.** If two Executors both bumped a
   dependency, neither one alone has the right view of `Cargo.lock`.
   The Orchestrator merges both their commits, then regenerates the
   lockfile against the merged tree.
2. **Audit attribution.** A change to `Cargo.lock` attributable to
   the Orchestrator is structurally different from a change
   attributable to an Executor. Both are audited; the
   `cross_cutting_artifacts` list lets the kernel emit
   `OrchestratorTouched` events with a clear label.

---

## What the Orchestrator can't do

The cross_cutting_artifacts list is a **declared whitelist** —
anything not in it, the Orchestrator won't touch. Specifically:

- It cannot write outside the union of (sub-task path_allowlists +
  cross_cutting_artifacts).
- It cannot expand the list at runtime; everything is admission-
  determined.
- It still runs the merge through the same `WriteFile` IPC + audit
  chain as Executors; the difference is just *who* the audit row
  attributes to.

---

## Common failure modes

| Symptom | Fix |
|---|---|
| `FAIL_PATH_ALLOWLIST_INVALID_ENTRY` on cross_cutting_artifacts | Glob, leading `/`, or `..`. Use exact filenames or directory prefixes. |
| Orchestrator merges fail with "lockfile dirty" | The Orchestrator can't regenerate the file because it's not in `cross_cutting_artifacts`. Add it. |
| Lockfile changes attributed to "Executor:N" | The Executor wrote the lockfile (probably ran `cargo build` and committed the result). Either add `Cargo.lock` to `cross_cutting_artifacts` and remove it from the Executor's allowlist, OR have the Executor explicitly NOT commit lockfile changes. |
| Lockfile drift between Executors and Orchestrator | The Orchestrator regenerates after merge; the Executor's lockfile is overwritten. This is correct behaviour. |

---

## Reference

| Surface | Purpose |
|---|---|
| `[[tasks]] path_allowlist` | Per-task write scope. The Orchestrator's effective allowlist is the union of these PLUS `cross_cutting_artifacts`. |
| `raxis log --kind OrchestratorTouched --since 1h` | Audit Orchestrator-attributed writes. |
| `raxis initiative show <id> --bundle` | Lists every artifact the Orchestrator stamped during merge. |

---

## Variations

- **No cross-cutting artifacts.** Many plans don't have any; omit
  the block entirely or set `cross_cutting_artifacts = []`. The
  Orchestrator merges Executor commits straight, no regeneration.
- **Generated docs / OpenAPI.** Put `docs/openapi.yaml` in
  `cross_cutting_artifacts` and have the Orchestrator regenerate
  from source. Pair with a verifier that fails the merge if the
  generated file would have differed.
- **Full directory.** `generated/` covers any file beneath. Useful
  for codegen pipelines.

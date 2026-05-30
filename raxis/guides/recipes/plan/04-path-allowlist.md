# `path_allowlist` — file-write scope rules

> **Topic:** Plan reference | **Time to read:** ~3 min | **Complexity:** ⭐⭐ Intermediate

`path_allowlist` is the **only** mechanism that limits where an
agent can write files. The kernel enforces it at every
`write_file` IPC; agent attempts to write outside trigger
`FAIL_PATH_NOT_IN_ALLOWLIST`. This recipe is the precise rules
reference.

---

## The two legal entry shapes (V2 §19)

| Shape | Example | Matches |
|---|---|---|
| Exact filename | `Cargo.toml`, `src/api/handler.rs` | Exactly that file path. |
| Directory prefix | `src/api/` | Everything beneath `src/api/` (recursive). The trailing `/` is mandatory. |

`src/api/` and `src/api` are **different**:

- `src/api/` (with `/`) = directory prefix; matches `src/api/foo.rs`,
  `src/api/v1/bar.rs`, etc.
- `src/api` (no `/`) = exact filename; matches *only* a file literally
  named `src/api`.

---

## What's rejected at admission

| Pattern | Reason |
|---|---|
| `src/*.rs` | Globs are forbidden. |
| `src/?/foo.rs` | Single-char wildcards are forbidden. |
| `src/{a,b}.rs` | Brace expansion is forbidden. |
| `[abc]` | Character classes are forbidden. |
| `!sensitive.rs` | Negation is forbidden. |
| `/tmp/foo` | Leading `/` (absolute path) is forbidden. |
| `../sibling/` | `..` (path escape) is forbidden. |
| `` (empty) | Empty entries are forbidden. |

The parser rejects any of these with
`FAIL_PATH_ALLOWLIST_INVALID_ENTRY` at `raxis plan validate` time —
no kernel round-trip needed.

---

## Examples

### Allow Executor to write within `src/auth/`

```toml
path_allowlist = ["src/auth/"]
```

The Executor may write `src/auth/handler.rs`, `src/auth/v1/foo.rs`,
etc. It cannot write `src/billing/...` or `Cargo.toml`.

### Allow specific files only

```toml
path_allowlist = [
  "src/auth/rate_limit.rs",
  "src/auth/rate_limit_test.rs",
]
```

Only those two files. Anything else is rejected at write time.

### Mixed shape

```toml
path_allowlist = [
  "src/auth/",        # any file under src/auth/
  "Cargo.toml",       # plus this exact file
  "Cargo.lock",       # and this exact file
]
```

Useful for tasks that need to bump `Cargo.lock` after editing
source. (Better practice: put `Cargo.lock` in the orchestrator's
`cross_cutting_artifacts` instead.)

---

## The Orchestrator-superset rule

The Orchestrator's allowlist is automatically computed by the kernel
as the **union** of every sub-task's `path_allowlist`. There's no
explicit `[orchestrator] path_allowlist` field — the kernel ensures
the Orchestrator covers every sub-task by construction.

If you need the Orchestrator to touch a file no sub-task touches
(e.g. a generated `Cargo.lock`), use `[orchestrator]
cross_cutting_artifacts`:

```toml
[orchestrator]
cross_cutting_artifacts = ["Cargo.lock"]
```

The cross-cutting list is exact filenames only — same rules as
`path_allowlist` but globs are doubly forbidden because the
Orchestrator's role is narrow.

---

## Reviewer's allowlist is a READ scope, not a write scope

Reviewers have **no write authority** at all. Their VM mounts
`/workspace` read-only (`INV-PLANNER-HARNESS-01`); the planner
harness has no `edit_file` / `bash` tool; the dispatch matrix
denies every commit-pathway intent (`SingleCommit`,
`IntegrationMerge`) for `session_agent_type = "Reviewer"`. Setting
or omitting `path_allowlist` does not change any of that.

What a Reviewer's `path_allowlist` does today:

- Defines the **sparse-checkout read scope** for the Reviewer's
  worktree (the files the Reviewer can actually read for evidence).
- The kernel rejects entries that no predecessor Executor's
  allowlist covers — letting a Reviewer read code outside the
  initiative's effective scope would defeat scope discipline.

```toml
[[tasks]]
task_id            = "ex"
clone_strategy     = "blobless"
description        = "Ex"
prompt             = """Complete Ex according to this plan's acceptance criteria."""
session_agent_type = "Executor"
path_allowlist     = ["src/auth/"]

[[tasks]]
task_id            = "rev"
clone_strategy     = "blobless"
description        = "Rev"
prompt             = """Complete Rev according to this plan's acceptance criteria."""
session_agent_type = "Reviewer"
predecessors       = ["ex"]
path_allowlist     = ["src/auth/"]            # OK — read scope = Executor's write scope
# path_allowlist   = ["src/auth/v1/"]         # OK — subset
# path_allowlist   = ["src/billing/"]         # REJECTED — not in union of predecessors' allowlists
```

> **Spec direction (informational).** `INV-PLANNER-HARNESS-01`'s
> plan-side authoring corollary moves toward rejecting any
> `path_allowlist` declaration on a Reviewer task outright
> (`FAIL_REVIEWER_PATH_ALLOWLIST_NOT_ALLOWED`). The current runtime
> still accepts it as the read-scope above, and existing scenarios
> use it. Treat the field as a sparse-mount hint, never as a write
> grant.

---

## Common failure modes

| Symptom | Fix |
|---|---|
| `FAIL_PATH_ALLOWLIST_INVALID_ENTRY` at validate | An entry uses a glob, leading `/`, or `..`. Use exact path or directory prefix. |
| `FAIL_PATH_NOT_IN_ALLOWLIST` at write | Agent tried to write outside its allowlist. Either (a) the description told it to write somewhere it shouldn't, or (b) the allowlist is too narrow. Sharpen the description first; widen the allowlist only if genuinely needed. |
| `FAIL_REVIEWER_ALLOWLIST_NOT_SUBSET` at admission | Reviewer references paths no predecessor Executor covers. Tighten Reviewer scope. |
| Files exist on disk but the kernel reports "no diff" | Agent wrote outside the allowlist; the kernel's diff hashes only allowlisted entries. Check `raxis log --kind PathWriteRejected --since 5m`. |

---

## Reference: relevant CLI

| Command | Purpose |
|---|---|
| `raxis plan validate <plan.toml>` | Catches malformed entries before submission. |
| `raxis inspect <task_id> --reveal-paths` | Shows the resolved (path_allowlist, path_export_globs) for a task. Appends a `PathReadAccessed` audit event. |
| `raxis log --kind PathWriteRejected --since 1h` | Audit trail of rejected writes. |

---

## Variations

- **Tight scope.** List individual files only; the agent can't
  accidentally touch siblings. Best for surgical fixes.
- **Broad scope.** A directory prefix (`src/`); fine for
  feature-implementer Executors. Pair with a Reviewer whose
  allowlist is the same prefix.
- **Cross-cutting build files.** Put `Cargo.lock`, `package-lock.json`,
  `go.sum`, etc. in `[orchestrator] cross_cutting_artifacts` rather
  than per-Executor allowlists. The Orchestrator regenerates them
  during merge.

# Pattern: cross-cutting refactor (`cross_cutting_artifacts`)

> **Topic:** Plan patterns | **Time to read:** ~3 min | **Complexity:** ⭐⭐⭐ Advanced

Three Executors split a refactor across `src/auth/`, `src/api/`,
and `src/db/`. Each one has a clean `path_allowlist`. But the
merge introduces a fourth touched path — `Cargo.lock` — that no
single Executor "owns", because the lockfile entry only resolves
once all three modules' `Cargo.toml` edits are unioned.

This is the situation `[orchestrator].cross_cutting_artifacts` is
designed for. It declares the **set of paths the auto-spawned
Orchestrator is permitted to touch** during `IntegrationMerge`
admission — paths that are NOT in any sub-task's
`path_allowlist`, but legitimately appear in the merged tree.

---

## Why Raxis enforces this

The `IntegrationMerge` admission pipeline (Check 5 in
`specs/v2/integration-merge.md`) computes the union of paths
touched by the candidate merge tree, and demands that **every
touched path** is covered by:

- `union(plan.tasks[*].path_allowlist)` — the sub-tasks' declared
  scopes, **or**
- `[orchestrator].cross_cutting_artifacts` — the Orchestrator's
  explicit, plan-time-declared escape hatch.

Anything else fail-closes with
`FAIL_PATH_OUTSIDE_ALLOWLIST { paths }`. This is the plan-side
half of the kernel's sandbox: an Executor can only write paths
its `path_allowlist` covers; the Orchestrator's writes during
merge can only land in `cross_cutting_artifacts`.

The strictness is intentional. If the Orchestrator could touch
arbitrary paths during merge, every `IntegrationMerge` would
expand the trust boundary by an unbounded amount.

---

## When this fits

- Polyglot lockfile updates: `Cargo.lock`, `package-lock.json`,
  `poetry.lock`, `go.sum`.
- Generated-artifact regeneration: `*.proto` → `*.pb.go`,
  OpenAPI specs → typed clients, schema migrations index files.
- A single shared `CHANGELOG.md` that aggregates per-module
  entries.
- Vendored-dependency manifests touched by multiple Executors'
  `Cargo.toml` edits.

When this does NOT fit:

- A protected path (e.g., `policy.toml`, security-sensitive
  config). Those should require operator approval via
  `[orchestrator].all_merges_require_approval` plus an
  `[escalation]` rule, not just a cross-cutting allowance.
- A file one Executor genuinely owns. Put it in that
  Executor's `path_allowlist`; don't dump it into the
  cross-cutting set.

---

## Plan shape

```toml
[plan.initiative]
description = "Migrate to tokio 1.40 across auth/api/db modules"

[workspace]
name        = "tokio-bump"
lane_id     = "default"
target_ref  = "refs/heads/main"

# Three Executors, each owns its own module's source AND
# Cargo.toml. None of them owns Cargo.lock — that's the
# orchestrator-side concern at merge time.

[[tasks]]
task_id            = "bump-auth"
session_agent_type = "Executor"
clone_strategy     = "sparse"
path_allowlist     = ["src/auth/", "tests/auth/", "Cargo.toml", "auth/Cargo.toml"]
predecessors       = []
description        = """Bump tokio to 1.40 in auth/Cargo.toml. Update src/auth/ for any breaking-change adjustments."""

[[tasks]]
task_id            = "bump-api"
session_agent_type = "Executor"
clone_strategy     = "sparse"
path_allowlist     = ["src/api/", "tests/api/", "api/Cargo.toml"]
predecessors       = []
description        = """Bump tokio to 1.40 in api/Cargo.toml."""

[[tasks]]
task_id            = "bump-db"
session_agent_type = "Executor"
clone_strategy     = "sparse"
path_allowlist     = ["src/db/", "tests/db/", "db/Cargo.toml"]
predecessors       = []
description        = """Bump tokio to 1.40 in db/Cargo.toml."""

# One Reviewer per Executor (panel optional — see pattern 02).
[[tasks]]
task_id            = "review-auth"
session_agent_type = "Reviewer"
clone_strategy     = "blobless"
path_allowlist     = ["src/auth/", "auth/Cargo.toml"]
predecessors       = ["bump-auth"]

[[tasks]]
task_id            = "review-api"
session_agent_type = "Reviewer"
clone_strategy     = "blobless"
path_allowlist     = ["src/api/", "api/Cargo.toml"]
predecessors       = ["bump-api"]

[[tasks]]
task_id            = "review-db"
session_agent_type = "Reviewer"
clone_strategy     = "blobless"
path_allowlist     = ["src/db/", "db/Cargo.toml"]
predecessors       = ["bump-db"]

# THE escape-hatch surface. The auto-spawned Orchestrator may
# touch only these paths during IntegrationMerge.
[orchestrator]
cross_cutting_artifacts = ["Cargo.lock"]
```

---

## How it interacts with the merge admission pipeline

Per `specs/v2/integration-merge.md`, when the Orchestrator
submits `IntegrationMerge { commit_sha, merged_task_ids }`:

```text
Kernel admission:
  Check 5  hybrid path-allowlist:
    candidate_paths = git diff --name-only base..commit_sha
    permitted_set   = union(merged_task_ids[*].path_allowlist)
                    ∪ orchestrator.cross_cutting_artifacts
    require: candidate_paths ⊆ permitted_set
```

In our example, `candidate_paths` for the merged tokio-bump tree
contains paths from all three modules **plus** the regenerated
`Cargo.lock`. The first three are covered by their respective
Executors' allowlists; `Cargo.lock` is covered by
`cross_cutting_artifacts`. Admission passes.

If the Orchestrator's merge touched, say, `README.md`, admission
would reject with `FAIL_PATH_OUTSIDE_ALLOWLIST { paths:
["README.md"] }` — adding a path to `cross_cutting_artifacts` is
a plan-time decision; the Orchestrator cannot escalate at merge
time.

---

## What the Orchestrator's merge actually looks like

The auto-spawned Orchestrator builds the merge tree by:

1. Cherry-picking each sub-task's commit onto the workspace base
   in the order announced by `merged_task_ids`.
2. Running any deterministic post-merge steps the operator
   declared in `[orchestrator].post_merge_commands` (e.g.,
   `cargo update --workspace --offline` to refresh
   `Cargo.lock`).
3. Producing a single `commit_sha` representing the merged tree.
4. Submitting `IntegrationMerge { commit_sha, merged_task_ids }`.

The `Cargo.lock` change in step 2 only writes to a path in
`cross_cutting_artifacts` — the kernel verifies this on
admission and audits the touched path set in
`IntegrationMergeCompleted`.

---

## Cross-cutting paths and integration verifiers

`cross_cutting_artifacts` is independent of
`[[integration_merge_verifiers]]` (see
[`patterns/03-merge-with-integration-verifiers`](./03-merge-with-integration-verifiers.md)).
The two surfaces compose cleanly:

| Surface | Plane | Question it answers |
|---|---|---|
| `cross_cutting_artifacts` | Plan | Is the Orchestrator allowed to touch this path? |
| `[[integration_merge_verifiers]]` | Policy | Does the merged tree pass these mechanical checks? |

Both must pass for `IntegrationMerge` to succeed. A common
deployment uses `cross_cutting_artifacts = ["Cargo.lock"]`
**and** an `[[integration_merge_verifiers]]` running
`cargo build --workspace --locked` to guarantee the lockfile is
internally consistent.

---

## Common errors

| Symptom | Cause | Fix |
|---|---|---|
| `FAIL_PATH_OUTSIDE_ALLOWLIST { paths: ["Cargo.lock"] }` on `IntegrationMerge` | Lockfile not declared in any allowlist or in `cross_cutting_artifacts`. | Add `Cargo.lock` to `[orchestrator].cross_cutting_artifacts`. |
| `FAIL_PATH_OUTSIDE_ALLOWLIST` for paths an Executor "should" own | The Executor's `path_allowlist` was too narrow; it touched something outside its declared scope. | Widen the Executor's allowlist OR, if cross-cutting, add to `cross_cutting_artifacts`. |
| `cross_cutting_artifacts` contains a `[[tasks.path_allowlist]]` path | Redundant but not an error. The kernel takes the union; double-listing is fine. | Optional cleanup. |
| Orchestrator wrote to a path even though it's not in the merge | The Orchestrator's `post_merge_commands` produced an artifact you didn't expect. Inspect the `IntegrationMergeAttempted` audit row to see the exact `candidate_paths`. | Either constrain the post-merge command, or add the path to `cross_cutting_artifacts`. |
| Want to allow ANY path to be cross-cut | Not supported. `cross_cutting_artifacts` is an explicit allowlist; there is no wildcard syntax. | Refactor the plan; if you genuinely need it, your plan probably belongs in two initiatives. |

---

## Variations

- **Multi-language lockfiles.** A polyglot project may need
  `cross_cutting_artifacts = ["Cargo.lock",
  "package-lock.json", "poetry.lock"]`. The list is plain
  glob-free strings (no wildcards), so each lockfile is
  declared explicitly.
- **Generated index file.** `cross_cutting_artifacts =
  ["docs/api/index.md"]` plus an `[[integration_merge_verifiers]]`
  that regenerates the index from the merged tree gives you a
  predictable docs-index update at merge time.
- **Workspace `Cargo.toml`.** If your refactor edits the
  *workspace*-root `Cargo.toml` (e.g., adds a member crate),
  the workspace-root file is shared by all Executors. Either
  put it in every Executor's `path_allowlist` (each writes the
  same change) or — better — put it in
  `cross_cutting_artifacts` and have the Orchestrator emit it.
- **Combined with operator approval.** Set
  `[orchestrator].all_merges_require_approval = true` for a
  refactor that crosses high-trust boundaries. Cross-cutting
  artifacts plus operator approval is a defensible policy for
  any change that updates lockfiles **and** generated security
  artifacts.

---

## Reference

| Surface | Where |
|---|---|
| Plan-side declaration | `[orchestrator].cross_cutting_artifacts` |
| Plan parser | `kernel/src/initiatives/lifecycle.rs::parse_orchestrator_block` |
| Merge admission check | `kernel/src/handlers/intent.rs::handle_integration_merge` (Check 5: hybrid allowlist) |
| Spec | `specs/v2/integration-merge.md` (Check 5: hybrid path-allowlist) |
| Companion docs | [`plan/10-orchestrator-block`](../plan/10-orchestrator-block.md) |
| Companion verifiers | [`patterns/03-merge-with-integration-verifiers`](./03-merge-with-integration-verifiers.md) |

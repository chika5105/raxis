# `raxis plan validate`

> **Topic:** CLI | **Time to read:** ~2 min | **Complexity:** ⭐ Beginner

Local-only structural pre-flight for `plan.toml`. Catches every
operator mistake before the signed-bundle round-trip through
`submit plan`. Exits 0 on success, non-zero on the first violation.
Doesn't talk to the kernel.

---

## Syntax

```text
raxis plan validate <plan.toml>
```

---

## What it catches

- TOML syntax errors.
- Missing `[workspace] lane_id`.
- Per-task `lane_id` overrides (`single_lane_propagation` rule).
- `session_agent_type = "Orchestrator"` declarations.
- Invalid `clone_strategy` values.
- Sparse + Orchestrator combinations.
- Duplicate `task_name`s.
- Forbidden user-authored `task_id` fields.
- Self-loop, dangling, or cyclic predecessors.
- Globs / `..` / leading `/` in `path_allowlist` or
  `cross_cutting_artifacts`.
- Reviewer with `vm_image` set.
- Reviewer with empty predecessors or predecessor-not-Executor.
- Reviewer `path_allowlist` not a subset of predecessor Executors'.

The validator is **fast** — typical < 50ms on commodity hardware —
because it does no IO beyond reading the plan file.

---

## Example

```bash
raxis plan validate ./plan.toml
```

Sample success:

```text
[OK] [workspace] lane_id = auth-work declared in policy.
[OK] [[tasks]] task_name "implementer" — Executor, sparse clone, 1 path entry.
[OK] [[tasks]] task_name "reviewer" — Reviewer, blobless clone, predecessor satisfied.
[OK] [orchestrator] cross_cutting_artifacts = ["Cargo.lock"] — exact filenames.
[OK] DAG: 2 tasks, 1 edge, 0 cycles.
[OK] Plan validates structurally.
```

Sample failure:

```text
[OK] [workspace] lane_id = auth-work.
[FAIL] [[tasks]] task_name "reviewer" path_allowlist references "src/billing/" which is NOT in any predecessor Executor's allowlist.
```

The validator stops at the first failure and exits 1.

---

## When to use

- **Every edit.** Run after every plan change, before submitting.
- **CI.** `raxis plan validate plan.toml` as a pre-merge check on
  the repo that hosts your plans.
- **Pre-bundle preflight.** `raxis submit plan --dry-run` runs
  `validate` internally; a separate explicit `validate` is cheaper
  and skips the bundle-build step.

---

## Common errors and fixes

| Symptom | Fix |
|---|---|
| `FAIL_PATH_ALLOWLIST_INVALID_ENTRY` | Glob, `..`, or leading `/` in an entry. Use exact paths or directory prefixes (with trailing `/`). |
| `FAIL_DAG_CYCLE` | Cycle between two+ tasks. The validator names the offending edge. |
| `FAIL_REVIEWER_VM_IMAGE_NOT_ALLOWED` | Reviewer task declares `vm_image`. Remove the field. |
| `FAIL_UNKNOWN_LANE` | `[workspace] lane_id` doesn't match any `[[lanes]] lane_id` in the active policy. **Note:** the validator reads policy if the kernel is locally accessible; otherwise it skips the check. |
| `FAIL_PLAN_INITIATIVE_DESCRIPTION_REQUIRED` | `[plan.initiative].description` is empty. Add one. |
| `TomlParseError` | Generic TOML syntax issue. Look at the line/column the error names. |

---

## Reference

| Command | Purpose |
|---|---|
| `raxis plan fmt <plan.toml> [--check] [--stdout]` | Canonicalise formatting. `--check` is a CI gate. |
| `raxis plan init` | Scaffold a new plan with the canonical layout. |
| `raxis submit plan <plan.toml> [--dry-run \| --no-dry-run]` | Build + submit the bundle. `--dry-run` is the default. |

---

## Variations

- **CI gate.** Add `raxis plan validate plan.toml` to your repo's
  pre-merge checks. Plans go through the same review cycle as code.
- **Multi-plan repo.** Loop over every `plan.toml` under your
  repo: `find . -name plan.toml -exec raxis plan validate {} \;`.
- **Without policy.** The validator skips lane validation when no
  RAXIS install is locally available; it still catches every other
  structural issue.

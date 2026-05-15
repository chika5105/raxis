# Scenario 06 — Parallel Decomposition

> **Complexity:** ⭐⭐ Intermediate | **Wall clock:** ~10 min | **Provider:** Anthropic

Two Executors run in parallel against non-overlapping path
allowlists. After this scenario you understand how the kernel uses
`path_allowlist` UNION at IntegrationMerge time to compose
non-conflicting work, and how lane-budget reservations are split
across concurrent tasks.

---

## Prerequisites

Same as scenario 01.

---

## What this scenario demonstrates

- Two `[[tasks]]` blocks with no `predecessors` between them: the
  kernel admits both and runs them in parallel up to lane-budget.
- Disjoint `path_allowlist`s (`src/auth/` vs `src/billing/`) — the
  V2 hybrid allowlist UNION composes them at merge time.
- Per-task lane-budget reservations.

---

## Repository setup

```bash
export DEMO_ROOT="/tmp/raxis-scenario-06"
rm -rf "$DEMO_ROOT" && mkdir -p "$DEMO_ROOT"
cd "$DEMO_ROOT"

git init -q
mkdir -p src/auth src/billing
echo 'pub fn placeholder() {}' > src/auth/mod.rs
echo 'pub fn placeholder() {}' > src/billing/mod.rs
echo 'pub mod auth; pub mod billing;' > src/lib.rs
git -c user.email=demo@raxis.local -c user.name=Demo add . > /dev/null
git -c user.email=demo@raxis.local -c user.name=Demo commit -qm "init"
```

---

## Run it

```bash
raxis plan validate ./plan.toml
raxis submit plan   ./plan.toml --no-dry-run
INIT_ID="$(raxis initiative list --state Draft --json | jq -r '.[0].initiative_id')"
raxis plan approve "$INIT_ID"

# Both tasks should be Running concurrently for at least a few seconds.
watch -n 1 "raxis initiative show $INIT_ID --with-tasks"
```

---

## What "success" looks like

```yaml
auth_module:    Completed
billing_module: Completed
```

Final commit on main is a merge of both branches; `git log
--graph` shows two parents on the merge commit.

---

## Variations

- **Trigger a lane-budget contention.** Drop the lane's
  `token_budget` to a small number; one task waits for the other to
  finish before it activates.
- **Make them overlap.** Add `src/lib.rs` to BOTH allowlists. The
  Orchestrator's IntegrationMerge succeeds when both Executors
  produce non-conflicting diffs; demand the same line modified by
  both and watch the kernel emit `MergeConflict` and request operator
  assistance.

---

## Tear-down

```bash
raxis initiative abort "$INIT_ID" 2>/dev/null || true
rm -rf "$DEMO_ROOT"
```

---

## Cross-references

- Pattern: [`../../patterns/single-executor-reviewer.md`](../../patterns/single-executor-reviewer.md)
  (this is the parallel-decomposition variant).
- Spec: `specs/v2/v2-deep-spec.md §Step 11` for the hybrid allowlist;
  `integration-merge.md` for the merge algorithm.

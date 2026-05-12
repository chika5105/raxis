# Scenario 46 — Two Concurrent Initiatives

> **Complexity:** ⭐⭐⭐ Advanced | **Wall clock:** ~12 min | **Provider:** Anthropic

Submit two independent initiatives into the same running kernel and
watch them progress side-by-side. Each initiative declares its own
`workspace.lane_id`; the per-lane reservation accounting in
`lane_budget_reservations` keeps the two from starving each other.
Demonstrates lane-budget isolation and the absence of head-of-line
blocking across initiatives.

## When to use this

- You want to confirm two unrelated streams of work don't share a
  budget by accident.
- You're tuning lane caps in `policy.toml` and need a deterministic
  shape to validate.
- You're investigating "why did my second initiative sit in
  `Admitted` forever?" — this scenario is the negative control.

---

## Prerequisites

- **One-time setup complete.** See [`../../SETUP.md`](../../SETUP.md).
- **Kernel running.**
- **`RAXIS_DATA_DIR` and `RAXIS_OPERATOR_KEY` exported.**
- **Anthropic credentials** at
  `$RAXIS_DATA_DIR/providers/anthropic-prod.toml` (mode 0600).
- **Two lanes declared in policy.** Merge the `policy.toml` from this
  folder (or just confirm your policy already has at least two distinct
  `[[lanes]]` entries with `max_cost_per_epoch ≥ 200`).

---

## What this scenario demonstrates

- The kernel admits both initiatives concurrently — there is no
  global "one initiative at a time" lock.
- Each initiative's tasks run against their declared lane; budget
  accounting is per-lane, not per-initiative.
- The dashboard's **Initiatives** and **Sessions** views show two
  active rows; the **Audit** stream interleaves their events.

---

## Repository setup

Reuse the scratch repos from earlier scenarios (the file paths inside
each plan are disjoint, so they will not collide on `main`):

```bash
# Scratch repo A — borrowed from scenario 04.
export DEMO_ROOT_A="/tmp/raxis-scenario-46a"
rm -rf "$DEMO_ROOT_A" && mkdir -p "$DEMO_ROOT_A"
( cd "$DEMO_ROOT_A" \
  && git init -q \
  && echo "# A" > README.md \
  && git -c user.email=demo@raxis.local -c user.name=Demo add . > /dev/null \
  && git -c user.email=demo@raxis.local -c user.name=Demo commit -qm "init" )

# Scratch repo B — borrowed from scenario 05.
export DEMO_ROOT_B="/tmp/raxis-scenario-46b"
rm -rf "$DEMO_ROOT_B" && mkdir -p "$DEMO_ROOT_B"
( cd "$DEMO_ROOT_B" \
  && git init -q \
  && echo "# B" > README.md \
  && git -c user.email=demo@raxis.local -c user.name=Demo add . > /dev/null \
  && git -c user.email=demo@raxis.local -c user.name=Demo commit -qm "init" )
```

Copy the plans from scenarios 04 and 05 into the scratch directories,
or write any two single-task plans with **different `lane_id` values**.

---

## Run it

```bash
# 1. Validate both.
raxis plan validate "$DEMO_ROOT_A/plan.toml"
raxis plan validate "$DEMO_ROOT_B/plan.toml"

# 2. Submit + approve back-to-back. Order doesn't matter.
raxis submit plan "$DEMO_ROOT_A/plan.toml" --no-dry-run
raxis submit plan "$DEMO_ROOT_B/plan.toml" --no-dry-run

INIT_A="$(raxis initiative list --state Draft --json | jq -r '.[0].initiative_id')"
INIT_B="$(raxis initiative list --state Draft --json | jq -r '.[1].initiative_id')"
echo "A=$INIT_A  B=$INIT_B"

raxis plan approve "$INIT_A"
raxis plan approve "$INIT_B"

# 3. Watch both progress.
watch -n 2 'raxis initiative list --state Active'
```

---

## What "success" looks like

```bash
# Both initiatives reach Completed (order is non-deterministic).
raxis initiative show "$INIT_A" --with-tasks   # State: Completed
raxis initiative show "$INIT_B" --with-tasks   # State: Completed

# Per-lane reservation rows are independent.
raxis log --kind BudgetReserved --json --limit 20 \
  | jq 'group_by(.payload.lane_id) | map({lane: .[0].payload.lane_id, count: length})'
# A row per lane_id.

# The audit chain has two PlanApproved + two IntegrationMergeCompleted
# events with distinct initiative_ids, interleaved.
raxis log --kind PlanApproved              --limit 10
raxis log --kind IntegrationMergeCompleted --limit 10

# Chain still verifies.
raxis verify-chain
```

---

## Variations

- **Same lane on purpose.** Edit one plan to point at the lane the
  other is using. Now you should see them queue against each other
  once the lane budget fills — this scenario becomes the positive
  control for [`49-budget-exceeded-graceful-stop`](../49-budget-exceeded-graceful-stop/).
- **Different `target_ref` per initiative.** If both initiatives
  fast-forward `main`, the second wins the merge. Have one target
  `main` and the other a feature branch to avoid contention.

---

## Tear-down

```bash
raxis initiative abort "$INIT_A" 2>/dev/null || true
raxis initiative abort "$INIT_B" 2>/dev/null || true
rm -rf "$DEMO_ROOT_A" "$DEMO_ROOT_B"
```

---

## Cross-references

- Concepts: [`../../CONCEPTS.md#lane-budgets`](../../CONCEPTS.md#lane-budgets).
- Pattern: this is the **multi-initiative variant** of
  [`../../patterns/parallel-decomposition.md`](../../patterns/parallel-decomposition.md);
  parallel-decomposition is intra-initiative, this is inter-initiative.
- Spec: `specs/v2/v2-deep-spec.md §Step 28` (single lane per
  initiative); `specs/v1/kernel-store.md §2.5.1.1 Pattern A`
  (`reserve_budget_in_tx` semantics).
- Related scenarios:
  - [`49-budget-exceeded-graceful-stop`](../49-budget-exceeded-graceful-stop/)
    for the saturation case.
  - [`47-crash-recovery-mid-merge`](../47-crash-recovery-mid-merge/)
    for what happens if the kernel dies mid-flight here.

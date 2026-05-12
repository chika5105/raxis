# Scenario 22 — Reviewer Rejection Then Pass

> **Complexity:** ⭐⭐⭐⭐ Expert | **Wall clock:** ~12 min | **Provider:** Anthropic

A Reviewer rejects the Executor's first commit ("use bytes-safe
concatenation"), the Executor revises in light of the critique, and
the Reviewer accepts the second commit. End-to-end demonstration of
the V2 critique-prepended retry loop: `revision_round`
monotonically increments on each rejection, the Executor sees the
prior critique in its prompt's KSB block, and the merge only happens
on the final accepting Reviewer verdict.

## When to use this

- You want to see the full reject → revise → accept cycle play out
  with audit events and no skipped steps.
- You're debugging a runaway revise loop in your own initiative and
  need a known-good baseline to compare against.
- You're tuning Reviewer prompts — this scenario gives you a
  predictable test bed.

---

## Prerequisites

- **One-time setup complete.** See [`../../SETUP.md`](../../SETUP.md).
- **Kernel running.**
- **`RAXIS_DATA_DIR` and `RAXIS_OPERATOR_KEY` exported.**
- **Anthropic credentials** at
  `$RAXIS_DATA_DIR/providers/anthropic-prod.toml` (mode 0600).
- This scenario assumes the V2.5+ surface: see
  [V2_STATUS.md](../../../specs/v2/V2_STATUS.md) for the
  revision-cycle landed-status table.

---

## What this scenario demonstrates

- The kernel's enforcement of `revision_round` increments on every
  rejection — the planner cannot fake-increment to skip rounds.
- Reviewer rejection causes the Executor's task to re-enter
  `Admitted → Running` with a fresh `evaluation_sha` and the prior
  critique appended to the Executor's KSB.
- The merge is gated on the **final** Reviewer verdict; an
  intermediate rejection is never merged, even if the operator
  approves the plan.
- `subtask_activations.review_reject_count` increments correctly
  (V2.5+ wiring in `handle_submit_review`).

---

## Repository setup

```bash
export DEMO_ROOT="/tmp/raxis-scenario-22"
rm -rf "$DEMO_ROOT" && mkdir -p "$DEMO_ROOT/src"
cd "$DEMO_ROOT"

git init -q
echo 'fn main() { println!("hi"); }' > src/main.rs
git -c user.email=demo@raxis.local -c user.name=Demo add . > /dev/null
git -c user.email=demo@raxis.local -c user.name=Demo commit -qm "init"
```

Copy the plan into the scratch directory:

```bash
cp /path/to/raxis/guides/scenarios/22-reviewer-rejection-then-pass/plan.toml "$DEMO_ROOT/plan.toml"
```

---

## Files in this scenario

| File | Purpose |
|---|---|
| `plan.toml` | Two tasks: `implement` (Executor) → `review` (Reviewer). The Executor's prompt asks it to deliberately use `format!` first, then switch on retry. |
| `policy.toml` | Empty delta. |
| `credential.toml` | Standard Anthropic placeholder. |

> The plan deliberately omits `max_review_rejections` and
> `max_revision_rounds`. The V2.6 plan-toml parser will surface
> those ceilings; today the kernel silently ignores them — see
> `specs/v2/V2_GAPS.md §12.13`. Until that lands, rely on the
> Reviewer's wall-clock budget to bound the loop.

---

## Run it

```bash
raxis plan validate "$DEMO_ROOT/plan.toml"
raxis submit plan   "$DEMO_ROOT/plan.toml" --no-dry-run
INIT_ID="$(raxis initiative list --state Draft --json | jq -r '.[0].initiative_id')"
raxis plan approve "$INIT_ID"

# Follow live — there will be two ReviewSubmitted events.
raxis log "$INIT_ID" -f
```

---

## What "success" looks like

```bash
# 1. Both tasks Completed.
raxis initiative show "$INIT_ID" --with-tasks
# implement: Completed
# review:    Completed

# 2. Two ReviewSubmitted events — first Reject, then Accept.
raxis log "$INIT_ID" --kind ReviewSubmitted --json \
  | jq '.[] | {round: .payload.revision_round, verdict: .payload.verdict, reason: .payload.reason}'
# { round: 0, verdict: "Reject", reason: "use bytes-safe concatenation" }
# { round: 1, verdict: "Accept" }

# 3. The Executor produced two distinct commits — the second one
#    on a fresh evaluation_sha. The integration merge is bound to
#    the second.
raxis log "$INIT_ID" --kind IntentAccepted --json \
  | jq '[.[] | select(.payload.task_id == "implement")] | length'
# 2

# 4. `main` carries the second commit only — the first was
#    discarded with the rejected worktree.
git -C "$DEMO_ROOT" log --oneline -3 main

# 5. Chain still verifies.
raxis verify-chain
```

---

## Variations

- **Force a third rejection.** Edit the Reviewer prompt to reject
  *both* `format!` and manual concatenation. With no per-task
  ceiling (today) the loop is bounded only by wall-clock; abort
  with `raxis initiative abort` once you've observed enough rounds.
- **Strip the critique.** Comment out the kernel's KSB
  `review_history` injection in your local build and re-run; the
  Executor produces the same first commit again, confirming the
  critique propagation is load-bearing.
- **Two Reviewers.** Promote this into [scenario 07](../07-panel-review/)
  by adding a second Reviewer task with `predecessors =
  ["implement"]`. Demonstrate that the Executor sees both critiques
  on revision.

---

## Tear-down

```bash
raxis initiative abort "$INIT_ID" 2>/dev/null || true
rm -rf "$DEMO_ROOT"
```

---

## Cross-references

- Concepts: [`../../CONCEPTS.md#agent-types`](../../CONCEPTS.md#agent-types).
- Pattern: [`../../patterns/single-executor-reviewer.md`](../../patterns/single-executor-reviewer.md).
- Spec: `specs/v2/v2-deep-spec.md §Step 13` (revision-cycle
  protocol); `specs/v2/V2_STATUS.md` (V2.5 surface table).
- Related scenarios:
  - [`02-single-executor-reviewer`](../02-single-executor-reviewer/)
    — the happy path with no rejection.
  - [`24-circular-revision-detection`](../24-circular-revision-detection/)
    — what happens when the Executor refuses to converge.

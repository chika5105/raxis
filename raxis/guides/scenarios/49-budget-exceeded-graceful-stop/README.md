# Scenario 49 — Budget Exceeded: Graceful Stop

> **Complexity:** ⭐⭐⭐ Advanced | **Wall clock:** ~8 min | **Provider:** Anthropic

A plan declares a deliberately small `max_tokens` lane budget, then
asks the Executor for an essay so long it cannot possibly fit. The
kernel computes the admission cost for the next inference round,
sees that the lane's reserved units would exceed
`max_cost_per_epoch`, and rejects with `FAIL_BUDGET_EXCEEDED`. The
task transitions to `Failed` cleanly between rounds — no half-written
file, no truncated commit, no admin-required cleanup.

## When to use this

- You're sizing lane budgets and need to see the rejection shape
  before tuning numbers.
- You want a deterministic reproducer of a `BudgetExceeded` audit row
  for dashboards / alerting tests.
- You're rehearsing the "agent ran away on tokens" runbook.

---

## Prerequisites

- **One-time setup complete.** See [`../../SETUP.md`](../../SETUP.md).
- **Kernel running.**
- **`RAXIS_DATA_DIR` and `RAXIS_OPERATOR_KEY` exported.**
- **Anthropic credentials** at
  `$RAXIS_DATA_DIR/providers/anthropic-prod.toml` (mode 0600).
- **Policy declares `tiny-budget-lane` with a small cap.** The
  `policy.toml` in this folder declares
  `max_cost_per_epoch = 1` so the very first inference round can't
  fit. Merge that delta and re-sign before submitting the plan.

---

## What this scenario demonstrates

- Budget enforcement is **between rounds**, never mid-stream — the
  current inference completes, the kernel evaluates the next round's
  admission cost, and only rejects if accepting would breach the cap.
- The rejection is structural: it travels back to the planner as
  `IntentResponse::Rejected { reason: FAIL_BUDGET_EXCEEDED }`, not a
  silent timeout or a torn TCP connection.
- The task FSM transitions `Running → Failed` via the planner-issued
  `ReportFailure` intent; `lane_budget_reservations` rows are cleaned
  up by `release_budget`.
- `BudgetOverrun` audit rows fire if the **actual** cost (after
  inference completed) exceeded the reservation — a separate signal
  from "rejection on the next round".

---

## Files in this scenario

| File | Purpose |
|---|---|
| `plan.toml` | One task asking for a 5,000-word essay. The lane has 1 admission unit of headroom. |
| `policy.toml` | Declares `[[lanes]] id = "tiny-budget-lane" max_cost_per_epoch = 1`. |
| `credential.toml` | Standard Anthropic placeholder. |

---

## Run it

```bash
# 1. Merge the policy delta + re-sign.
cat ./policy.toml >> "$RAXIS_DATA_DIR/policy/policy.toml"
raxis policy sign "$RAXIS_DATA_DIR/policy/policy.toml" \
  --key "$RAXIS_OPERATOR_KEY"
raxis epoch advance \
  --policy "$RAXIS_DATA_DIR/policy/policy.toml" \
  --sig    "$RAXIS_DATA_DIR/policy/policy.sig"

# 2. Materialise a scratch repo.
export DEMO_ROOT="/tmp/raxis-scenario-49"
rm -rf "$DEMO_ROOT" && mkdir -p "$DEMO_ROOT"
( cd "$DEMO_ROOT" && git init -q \
  && echo "# essay" > README.md \
  && git -c user.email=demo@raxis.local -c user.name=Demo add . > /dev/null \
  && git -c user.email=demo@raxis.local -c user.name=Demo commit -qm "init" )

# 3. Validate + submit + approve.
cp ./plan.toml "$DEMO_ROOT/plan.toml"
raxis plan validate "$DEMO_ROOT/plan.toml"
raxis submit plan  "$DEMO_ROOT/plan.toml" --no-dry-run
INIT_ID="$(raxis initiative list --state Draft --json | jq -r '.[0].initiative_id')"
raxis plan approve "$INIT_ID"

# 4. Watch.
raxis initiative show "$INIT_ID" --with-tasks
raxis log "$INIT_ID" -f
```

---

## What "success" looks like

```bash
# 1. The task ends Failed (not Aborted, not Completed).
raxis initiative show "$INIT_ID" --with-tasks
# verbose-task: Failed   reason: FAIL_BUDGET_EXCEEDED

# 2. The audit chain has the rejection row.
raxis log "$INIT_ID" --kind IntentRejected --limit 1 --json \
  | jq '.[0].payload.reason'
# "FAIL_BUDGET_EXCEEDED"

# 3. No phantom reservation rows remain — release_budget cleaned up.
raxis log "$INIT_ID" --kind BudgetReleased --limit 1
# present

# 4. The initiative is Failed.
raxis initiative show "$INIT_ID" --json | jq '.state'
# "Failed"

# 5. Chain still verifies.
raxis verify-chain
```

---

## Variations

- **Higher cap, longer task.** Bump `max_cost_per_epoch` to a value
  that allows N rounds; the rejection fires on round N+1.
- **Operator escalation.** Configure a `[[escalations]]` rule that
  notifies you on `FAIL_BUDGET_EXCEEDED`; have the operator extend
  the budget via `policy.toml` + `epoch advance` and resume.
- **`BudgetOverrun` instead of `BudgetExceeded`.** Use a tasks plan
  where the reservation passes admission but the actual cost (after
  inference) exceeds the reservation; `release_budget` records the
  delta as `BudgetOverrun` instead.

---

## Tear-down

```bash
raxis initiative abort "$INIT_ID" 2>/dev/null || true
rm -rf "$DEMO_ROOT"

# Roll back the tiny-budget-lane policy if you don't want it active.
# Edit policy.toml to remove the [[lanes]] entry, re-sign, advance.
```

---

## Cross-references

- Concepts: [`../../CONCEPTS.md#lane-budgets`](../../CONCEPTS.md#lane-budgets).
- Spec: `specs/v1/kernel-core.md §handlers/intent.rs "Budget check
  and reservation"`; `specs/v1/kernel-store.md §2.5.1.1 Pattern A`
  (`reserve_budget_in_tx`).
- Related scenarios:
  - [`46-two-concurrent-initiatives`](../46-two-concurrent-initiatives/)
    for the negative control (two lanes, no contention).
  - [`25-wall-clock-limit`](../25-wall-clock-limit/) for the wall-
    clock equivalent of this token cap.

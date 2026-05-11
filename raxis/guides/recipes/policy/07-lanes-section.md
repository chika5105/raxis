# `[[lanes]]` — concurrency + epoch-budget per lane

> **Topic:** Policy reference | **Time to read:** ~3 min | **Complexity:** ⭐⭐ Intermediate

A **lane** is the kernel's primary work-isolation unit. Every
initiative pins to exactly one `lane_id`, and every session in that
initiative shares the lane's concurrency cap and epoch budget. Use
lanes to:

- Isolate critical lanes from experimental ones (`prod-merge` vs
  `experiment-junkdrawer`).
- Cap the LLM spend per logical workstream.
- Order work — a lane with `priority = 200` outruns one at `100`
  when the kernel has free VM slots but two lanes ready.

---

## Field reference

Each `[[lanes]]` block declares one lane.

| Field | Type | Required | Default | Effect |
|---|---|---|---|---|
| `lane_id` | `String` | yes | — | Stable identifier referenced by `[workspace] lane_id` in `plan.toml`. Plans whose lane_id isn't declared here fail admission with `FAIL_UNKNOWN_LANE`. |
| `max_concurrent_tasks` | `u32` | no | 4 | Maximum number of `Active` (non-terminal) sessions on this lane at any instant. Beyond this, new sessions stay `Admitted` until a slot frees. |
| `max_cost_per_epoch` | `u64` | no | 10000 | Cap on cumulative admission-unit cost summed across every reserved intent in the current policy epoch. The cost values come from `[budget.base_cost_per_intent_kind]`. |
| `priority` | `u8` | no | 100 | Higher = scheduled first when both lanes have ready work and one VM slot. Range 0–255; ties are broken FIFO. |

---

## Example — single shared lane (sandbox)

```toml
[[lanes]]
lane_id              = "default"
max_concurrent_tasks = 4
max_cost_per_epoch   = 10000
priority             = 100
```

## Example — production multi-lane

```toml
[[lanes]]
lane_id              = "prod-merge"
max_concurrent_tasks = 8
max_cost_per_epoch   = 100000
priority             = 200          # outruns experimental work

[[lanes]]
lane_id              = "experiment"
max_concurrent_tasks = 4
max_cost_per_epoch   = 50000
priority             = 50

[[lanes]]
lane_id              = "ci-bot"
max_concurrent_tasks = 16
max_cost_per_epoch   = 200000
priority             = 100
```

---

## Lifecycle of the budget counter

The epoch budget is the **kernel-tracked sum** of admission costs
reserved against the lane in the current policy epoch. Every:

- `submit plan` adds the planning intent's cost.
- `IntentAccepted` adds the per-intent cost.

When the policy epoch advances (any `policy sign` triggers a hot
reload + new epoch row), the counter resets. Inflight intents stay
attributed to the previous epoch's already-reserved budget; only
new intents reserve against the new epoch.

The result: a runaway lane gets paused by `FAIL_LANE_BUDGET_EXCEEDED`
**within the current epoch** until the operator either advances the
epoch (re-signing policy is enough) or raises the cap.

---

## Inspect lane pressure

```bash
# All lanes:
raxis budget

# Drill into one lane's reservations:
raxis budget prod-merge --json | jq '.reservations[]'
```

Output names the reserved intents and their costs, plus the running
total vs `max_cost_per_epoch`.

---

## Step-by-step — add a new lane to an existing install

```bash
$EDITOR "$RAXIS_DATA_DIR/policy/policy.toml"
# Append a new [[lanes]] block.

raxis policy sign \
  "$RAXIS_DATA_DIR/policy/policy.toml" \
  --key "$RAXIS_OPERATOR_KEY"

# Confirm the kernel sees the new lane:
raxis policy show \
  | sed -n '/^\[\[lanes\]\]$/,/^\[\[/p'

raxis budget --json | jq '.lanes[].lane_id'
```

Plans submitted **before** the new lane was declared still pin to
their original `lane_id`; only new submissions can target the new
lane.

---

## Common failure modes

| Symptom | Fix |
|---|---|
| `FAIL_UNKNOWN_LANE` on `submit plan` | The plan's `[workspace] lane_id` doesn't match any `[[lanes]] lane_id`. Add the lane (and re-sign), or change the plan. |
| `FAIL_LANE_BUDGET_EXCEEDED` mid-task | The lane's `max_cost_per_epoch` ran out. Either bump the cap (and re-sign — this advances the epoch and resets the counter), OR wait for the operator to advance the epoch manually with `raxis epoch advance`. |
| Lane never schedules | `max_concurrent_tasks = 0` is admissible; the lane admits but never activates. Set ≥ 1. |
| Plans on a high-priority lane don't outrun a lower-priority one | Both lanes have free slots? Priority only matters when scheduling is contested. Inspect with `raxis queue --lane prod-merge`. |

---

## Reference: relevant CLI

| Command | Purpose |
|---|---|
| `raxis budget [<lane_id>]` | Lane budget pressure overview. |
| `raxis queue --lane <id>` | Per-lane DAG scheduler view (READY + BLOCKED tasks). |
| `raxis log --kind LaneBudgetExceeded` | Audit hits against the cap. |
| `raxis epoch advance --policy <path> --sig <sig>` | Force-advance the policy epoch (hot reset on every lane budget). |

---

## Variations

- **One lane, simple deployments.** Most installs ship a single
  lane (`"default"`). Multi-lane is justified when you have
  distinct workstreams that need budget / priority isolation.
- **CI overrun control.** Give CI its own lane (`ci-bot`) with a
  large `max_concurrent_tasks` and a tight `max_cost_per_epoch`.
  Bursty CI traffic gets the parallelism it needs but can't
  starve operator workflows.
- **Pause a lane.** Set `max_concurrent_tasks = 0`, re-sign. The
  lane admits no new sessions; existing ones run to completion.
  Useful for graceful drains before deleting a lane outright.

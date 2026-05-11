# `[budget]` — admission-cost heuristic + token / sleep caps

> **Topic:** Policy reference | **Time to read:** ~4 min | **Complexity:** ⭐⭐ Intermediate

The budget block tells the kernel **how to compute the admission
cost** of an intent and **how big a single task may be** before the
lane budget enforcement kicks in. The cost is a heuristic measured
in admission units — it is **not** a token count or a dollar amount.
Treating it as money is a misuse.

---

## Field reference

### `[budget]` — top-level

| Field | Type | Required | Default | Effect |
|---|---|---|---|---|
| `cost_per_touched_path` | `u64` | optional | 1 | Multiplier applied to `len(touched_paths)` when computing per-intent cost. |
| `max_cost_per_task` | `u64` | optional | 10000 | Ceiling on a single task's accumulated cost. Beyond this the kernel rejects the next intent with `FAIL_TASK_COST_EXCEEDED`. |

### `[budget.base_cost_per_intent_kind]`

A required map: each `IntentKind` (`SingleCommit`,
`MultiBranchCommit`, `IntegrationMerge`, `PrGateEvaluation`,
`CompleteTask`, `ReportFailure`, `RaiseEscalation`, ...) gets a
base cost. The kernel adds this to
`cost_per_touched_path × len(touched_paths)` to compute the unit
cost for that intent.

| Intent | Typical base cost | Why |
|---|---|---|
| `SingleCommit` | 10 | A single-task commit; cost dominated by touched paths. |
| `MultiBranchCommit` | 25 | Cross-branch intent; higher fixed cost. |
| `IntegrationMerge` | 50 | Three-way merge across N branches. |
| `PrGateEvaluation` | 15 | Gate evaluation alone (no merge). |
| `CompleteTask` | 5 | Lifecycle marker; minimal work. |
| `ReportFailure` | 1 | Pure metadata write. |
| `RaiseEscalation` | 1 | Bookkeeping intent; rate-limited separately by `[escalation_policy]`. |

Tune per workload — these are policy values, not invariants.

### `[budget.token_caps]` — V2 LLM budgets

| Field | Type | Required | Effect |
|---|---|---|---|
| `max_input_tokens_per_session` | `u64` | optional | Hard cap on cumulative LLM input tokens stamped into the planner-VM env at spawn time. Absent ⇒ uncapped. |
| `max_output_tokens_per_session` | `u64` | optional | Same for output tokens. |
| `max_total_tokens_per_session` | `u64` | optional | Combined input+output cap. |

Stamped into `RAXIS_PLANNER_MAX_TOKENS_INPUT_TOTAL`,
`RAXIS_PLANNER_MAX_TOKENS_OUTPUT_TOTAL`,
`RAXIS_PLANNER_MAX_TOKENS_TOTAL`. Enforced **inside** the VM by the
dispatch loop (the kernel never sees individual token counts).

### `[budget.sleep_caps]` — V2 sleep tool budgets

| Field | Type | Required | Effect |
|---|---|---|---|
| `max_seconds_per_call` | `u32` | optional | Per-call ceiling on the in-VM `sleep` tool. 0 (or section omitted) ⇒ tool refuses every invocation with `FAIL_SLEEP_DISABLED`. |
| `max_cumulative_seconds` | `u32` | optional | Cumulative cap across the session. Once reached, every subsequent `sleep` invocation fails with `FAIL_SLEEP_BUDGET_EXCEEDED`. |

Both default to 0, which means **the sleep tool is disabled by
default**. Operators must opt in.

---

## Example — minimal but functional

```toml
[budget]
cost_per_touched_path = 1
max_cost_per_task     = 10000

[budget.base_cost_per_intent_kind]
SingleCommit       = 10
MultiBranchCommit  = 25
IntegrationMerge   = 50
PrGateEvaluation   = 15
CompleteTask       = 5
ReportFailure      = 1
```

## Example — with token + sleep caps

```toml
[budget]
cost_per_touched_path = 1
max_cost_per_task     = 50000

[budget.base_cost_per_intent_kind]
SingleCommit       = 10
IntegrationMerge   = 50
CompleteTask       = 5
ReportFailure      = 1

[budget.token_caps]
max_input_tokens_per_session  = 200000   # ~Claude Sonnet context
max_output_tokens_per_session = 100000
max_total_tokens_per_session  = 250000

[budget.sleep_caps]
max_seconds_per_call    = 60
max_cumulative_seconds  = 300
```

---

## How the kernel computes admission cost

```text
cost(intent) = base_cost_per_intent_kind[intent.kind]
             + cost_per_touched_path * len(intent.touched_paths)
```

That value is reserved against the lane's `max_cost_per_epoch`
budget at admission. If it pushes the lane over, the intent is
rejected with `FAIL_LANE_BUDGET_EXCEEDED`. If the per-task running
total exceeds `max_cost_per_task`, the intent is rejected with
`FAIL_TASK_COST_EXCEEDED`.

There is **no relationship** between admission units and LLM
tokens or dollars. They share neither units nor scale.

---

## Common failure modes

| Symptom | Fix |
|---|---|
| `FAIL_LANE_BUDGET_EXCEEDED` immediately | Lane cap is too low for your per-intent cost. Either lower the costs in `base_cost_per_intent_kind` or raise the lane's `max_cost_per_epoch`. |
| `FAIL_TASK_COST_EXCEEDED` on a long-running task | The task is hitting its per-task ceiling. Raise `max_cost_per_task`, OR lower `cost_per_touched_path` if it's path-count dominant, OR break the task in two. |
| `FAIL_SLEEP_DISABLED` on every `sleep` call | The `[budget.sleep_caps]` section is missing. Opt in. |
| `FAIL_SLEEP_BUDGET_EXCEEDED` mid-task | Cumulative cap reached. Either raise `max_cumulative_seconds` or shorten the agent's actual usage. |
| Token cap ignored | Token caps are stamped into env at spawn time; only NEW sessions see updated values. Existing sessions keep their original env block. |

---

## Reference: env vars + audit

| Surface | Purpose |
|---|---|
| `RAXIS_PLANNER_MAX_TOKENS_INPUT_TOTAL` | Stamped from `[budget.token_caps] max_input_tokens_per_session`. |
| `RAXIS_PLANNER_MAX_TOKENS_OUTPUT_TOTAL` | Stamped from `max_output_tokens_per_session`. |
| `RAXIS_PLANNER_MAX_TOKENS_TOTAL` | Stamped from `max_total_tokens_per_session`. |
| `raxis budget [<lane_id>]` | Per-lane budget pressure: reserved / max_cost_per_epoch. |
| `raxis log --kind LaneBudgetExceeded` | Surfaces every rejection. |
| `raxis log --kind TokenBudgetExceeded` | (V2.5+) Token-cap rejections from inside the VM. |

---

## Variations

- **Cost-blind.** Set `cost_per_touched_path = 0` and uniform low
  `base_cost_per_intent_kind` (e.g. all 1). Useful when you want
  the lane budget to track *count* of intents, not their shape.
- **Aggressive token policing.** Tight token_caps + low
  `max_cost_per_task` — agents that wander hit budgets fast.
- **Disabled sleep.** Omit `[budget.sleep_caps]` entirely; every
  `sleep` call inside an agent VM fails. This is the safest
  default; only enable when a specific scenario needs it (e.g.
  rate-limiting against an external service).

# `raxis budget` and `raxis top`

> **Topic:** CLI | **Time to read:** ~2 min | **Complexity:** ⭐ Beginner

`budget` is a static snapshot of lane / initiative cost
consumption. `top` is a live dashboard refreshing every second —
think `htop` for the kernel.

---

## budget — cost snapshot

```bash
raxis budget
# Output:
# LANE          ACTIVE/CAP   BUDGET_USED/CAP    UTILIZATION
# auth-work     1/3          $1.20/$10.00       12%
# api-work      0/2          $10.00/$10.00      100%  *
# ops           2/4          $0.40/$5.00        8%
#
# INITIATIVE     LANE        BUDGET_USED   ACTIVE_TASKS
# 1f3c8a4b       auth-work   $1.20         2
# 9e1f4b22       api-work    $10.00        0
```

Per-lane filter:

```bash
raxis budget --lane auth-work
```

Per-initiative filter:

```bash
raxis budget --initiative 1f3c8a4b
```

JSON form for monitoring:

```bash
raxis budget --json | jq '.lanes[] | select(.utilization > 0.9)'
```

How costs are computed:

- Each `IntentKind` has a base cost from `[budget.base_cost_per_intent_kind]`.
- LLM intents add token-based cost from provider-reported usage. RAXIS
  prices those tokens with operator policy overrides when configured,
  runtime/provider pricing when available, and an explicitly labelled
  bundled estimate as the final fallback.
- The lane's `[budget].max_cost_per_epoch` caps total spend per
  epoch; the policy epoch advances on operator-signed
  `raxis epoch advance` (or scheduled).

When a lane hits 100%, no more admissions land in that lane until
the epoch rolls.

---

## top — live dashboard

```bash
raxis top
# Output (refreshes every 1s):
# raxis-kernel  uptime: 6h 12m   data_dir: /var/raxis   epoch: 7
#
# LANES
#   auth-work    [###..]  active 1/3   budget 12%
#   api-work     [#####]  active 0/2   budget 100%  *
#
# ACTIVE INITIATIVES (3)
#   1f3c8a4b   auth-work   "Add rate limiting"             age 4m
#   2a7d9f0c   ops         "Bump cargo deps"               age 3h
#   9e1f4b22   api-work    "Generate OpenAPI"              age 2h  [Q]
#
# RUNNABLE (1) | WAITING (1) | BLOCKED (1) | ESCALATIONS (1) | ALERTS (2)
#
# RECENT AUDIT EVENTS (last 5)
#   17:31:14  WitnessRecorded   1f3c8a4b   implementer
#   17:31:01  TaskStarted       1f3c8a4b   code_reviewer
#   ...
```

`top` is the operator's "everything-at-once" view. Quit with `q`.

Useful keys (on supported terminals):

| Key | Effect |
|---|---|
| `i` | Toggle initiatives section. |
| `l` | Toggle lanes section. |
| `e` | Toggle escalations section. |
| `a` | Toggle audit events. |
| `q` | Quit. |

---

## Common errors

| Symptom | Fix |
|---|---|
| `budget: no lanes defined` | The active policy has no `[[lanes]]`; sign a policy with at least one lane. |
| `budget: kernel not running` | `raxis status` then start the kernel. |
| `top: terminal too small` | The dashboard expects ≥ 80 cols × 24 rows. |
| `top: no audit events` | Either fresh install or large clock skew. |

---

## Reference

| Command | Purpose |
|---|---|
| `raxis epoch advance` | Roll the policy epoch (resets per-epoch budgets). |
| `raxis policy show` | Inspect lane config and budget caps. |
| `raxis queue` | Scheduler queue snapshot. |
| `raxis inbox` | Aggregate operator alerts. |
| `raxis status` | Cheap liveness check. |

---

## Variations

- **CI cost report.** `raxis budget --json --initiative <id>` after
  the run to attribute spend per initiative.
- **Lane saturation alert.** Cron `raxis budget --json | jq '.lanes[] | .utilization' | max ≥ 0.9` to page on near-saturation.
- **Operator overview.** `raxis top` left running on a wall display
  for ops visibility.
- **Pre-flight cost check.** Sum the predicted token use of a
  plan's tasks before submission; compare against the lane's
  remaining `max_cost_per_epoch` via `raxis budget`.

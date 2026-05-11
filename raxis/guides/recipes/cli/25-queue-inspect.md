# `raxis queue` and `raxis inspect`

> **Topic:** CLI | **Time to read:** ~2 min | **Complexity:** ⭐⭐ Intermediate

`queue` shows the scheduler's runnable / waiting / blocked sets.
`inspect` is a deep-dive into a single subject (initiative, task,
session, lane, etc.). Both are read-only.

---

## Syntax

```text
raxis queue [--lane <lane_id>] [--state runnable|waiting|blocked|all] [--json]
raxis inspect <subject_kind>:<id> [--json]
```

---

## queue — scheduler view

```bash
raxis queue
# Output:
# RUNNABLE
#   TASK_ID                     INITIATIVE      LANE         AGENT_TYPE   PRED_OK
#   implementer-2025-05-10      1f3c8a4b        auth-work    Executor     yes
#
# WAITING (predecessors not satisfied)
#   code_reviewer-2025-05-10    1f3c8a4b        auth-work    Reviewer     [implementer]
#
# BLOCKED (lane budget / capacity)
#   migrator-2025-05-10         9e1f4b22        api-work     Executor     budget_exhausted
#
# Lane summary:
#   auth-work:  active=1/3, budget_used=1.20/10.00 (12%)
#   api-work:   active=0/2, budget_used=10.00/10.00 (100%)  *
```

Filter to a single lane:

```bash
raxis queue --lane auth-work
```

Filter to one state:

```bash
raxis queue --state blocked
```

What the columns mean:

- `PRED_OK` — `yes` if all `predecessors` are `Completed`. If `no`,
  the cell shows the missing predecessor IDs.
- The lane summary's `*` flags lanes at budget cap.
- A task in `BLOCKED` typically waits for either lane budget to
  free or `[host_capacity]` floor to recover.

---

## inspect — subject deep-dive

`inspect` accepts `<kind>:<id>` form. Supported kinds:

| Kind | Example |
|---|---|
| `initiative` | `inspect initiative:1f3c8a4b` |
| `task` | `inspect task:implementer-2025-05-10` |
| `session` | `inspect session:91a7c8…` |
| `lane` | `inspect lane:auth-work` |
| `verifier` | `inspect verifier:cargo-test` |
| `credential` | `inspect credential:github-deploy` |
| `delegation` | `inspect delegation:d8a93c1f…` |

Each kind unfolds the relevant pieces:

```bash
raxis inspect initiative:1f3c8a4b
# Output: initiative metadata + task list + lane budget snapshot +
#         pending escalations + recent audit lines.

raxis inspect task:implementer-2025-05-10
# Output: task FSM state + predecessors + assigned session +
#         witnesses + recent intents + retry counters.

raxis inspect lane:auth-work
# Output: lane config (max_concurrent_tasks, budget) + active
#         tasks + recent admissions + budget burn-down.

raxis inspect session:91a7c83f
# Output: session metadata (agent_type, ttl, initiative) +
#         delegations + recent intents + worktree path.
```

Many of these mirror the per-subject `show` commands; `inspect` is
the unified surface.

---

## Common errors

| Symptom | Fix |
|---|---|
| `queue: kernel not running` | `raxis status` — start the kernel. |
| `inspect: unknown subject kind` | Check the supported kinds above. |
| `inspect: subject not found` | Wrong id; use `raxis initiative list` / `raxis sessions` / etc. to find it. |
| Empty `RUNNABLE` despite expectations | Either no Draft initiative is approved yet, or every task is blocked. Check the BLOCKED section for budget / capacity stalls. |

---

## Reference

| Command | Purpose |
|---|---|
| `raxis initiative show <id>` | Initiative-only view. |
| `raxis explain <task_id>` | Decision tree for one task. |
| `raxis sessions` | Active sessions. |
| `raxis budget` | Lane / initiative budget summary. |
| `raxis top` | Live dashboard. |

---

## Variations

- **CI smoke test.** Submit a plan, approve it, then poll `queue --json`
  until `RUNNABLE` is empty for the initiative.
- **Capacity alerting.** `queue --json | jq '.lanes[] | select(.budget_used / .budget_cap > 0.9)'`
  to alert on near-cap lanes.
- **Task triage.** `inspect task:<id>` is the shortest path from
  "this task seems stuck" to "here's what's wrong".
- **Replay scratch session.** `inspect session:<id>` shows the
  worktree path; you can `cd` into it for manual inspection (the
  kernel is the source of truth for intents, but the worktree is
  visible read-only).

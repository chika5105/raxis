# Tune lane budget and concurrency

> **Topic:** Operations | **Time to read:** ~3 min | **Complexity:** ⭐⭐ Intermediate

How to size `[[lanes]]` for real workloads. Covers
`max_concurrent_tasks`, `max_cost_per_epoch`, `priority`, and
the right way to roll out a change without blowing up in-flight
work.

---

## Concepts recap

A lane is a concurrency + budget container. Every task in
`plan.toml` runs in exactly one lane (`workspace.lane_id = "..."`).

| Field | Effect |
|---|---|
| `id` | Stable name referenced from `plan.toml`. |
| `max_concurrent_tasks` | Hard cap on simultaneously-active tasks. |
| `max_cost_per_epoch` | Hard cap on USD cost per policy epoch. |
| `priority` | Higher value → admitted first when multiple lanes are runnable. |
| `description` | Operator-facing label. |

The kernel rejects new admissions in a lane when EITHER the
concurrency cap OR the budget cap is hit. Reset of budget cap
happens at every epoch advance (`raxis epoch advance` or scheduled).

---

## Decide what to tune

### Symptoms → likely fix

| Observation | Likely fix |
|---|---|
| Lane sits at `100% budget used` for hours | Raise `max_cost_per_epoch` or shorten `epoch_seconds`. |
| Frequent `BLOCKED: budget_exhausted` queue rows | Same as above. |
| Active count consistently at `max_concurrent_tasks` cap with backlog | Raise `max_concurrent_tasks` (watch host capacity). |
| Two lanes contend; one always wins | Use `priority` to set explicit ordering. |
| One lane starves another | Lower the dominant lane's `priority` or split into two policies. |

### Sizing heuristics

- `max_concurrent_tasks`: start at `host_cpu_count / 4` for LLM
  workloads (each session has high I/O, low CPU), `host_cpu_count`
  for compute-heavy verifiers.
- `max_cost_per_epoch`: pick the operator's daily LLM-spend cap;
  set `epoch_seconds` to 24 hours (`86400`) so the budget aligns
  with daily spend.
- `priority`: use coarse buckets (10 = low, 50 = normal, 100 = high).
  Don't overuse fine-grained values.

---

## Steps

### 1. Inspect current lane behavior

```bash
raxis budget                # snapshot per-lane
raxis budget --json --lane auth-work | jq '.utilization'
raxis log --kind LaneAdmissionRejected --since "24 hours ago" --json | jq '.[] | .reason' | sort | uniq -c
```

Build a picture of how often each lane is hitting its caps.

### 2. Edit `policy.toml`

Pull the current policy:

```bash
raxis policy show > /tmp/policy.toml
```

Edit the relevant `[[lanes]]` entry:

```toml
[[lanes]]
id                   = "auth-work"
max_concurrent_tasks = 5        # was 3
max_cost_per_epoch   = 25.00    # was 10.00; USD
priority             = 50
description          = "auth team feature work"
```

### 3. Re-sign and apply

```bash
raxis policy sign /tmp/policy.toml \
  --operator-key /tmp/op.key
# Output: signed_at, new_epoch.
```

The kernel hot-reloads. Check:

```bash
raxis policy show | grep -A 5 "id = \"auth-work\""
raxis log --kind PolicyReloaded --since "1 minute ago"
```

### 4. Verify the change took effect

```bash
raxis budget --lane auth-work
# Output: max_concurrent_tasks: 5, budget_cap: $25.00
```

If you raised the budget mid-epoch, the existing `budget_used`
counter is preserved; you'll only see effective change if it was
above the old cap.

### 5. Optional: advance the epoch

```bash
raxis epoch advance --reason "lane tuning: reset budget for new caps"
```

This zeros the lane's `budget_used` and lets fresh admissions
take advantage of the new cap immediately.

---

## Roll out without disruption

In-flight tasks are unaffected by lane-config changes — they run
to completion under whatever caps were in force at admission. Only
NEW admissions land on the new caps. Safe to apply during peak hours.

If you're **lowering** caps (less generous):

1. Monitor `raxis budget --lane <id>` to see the new cap is
   binding.
2. Watch `raxis log --kind LaneAdmissionRejected` for new
   rejections.
3. Be prepared to roll back if too many admissions get rejected.

If you're **raising** caps:

1. Confirm host capacity supports the new concurrency.
2. Watch `raxis log --kind ReconciliationGap` and
   `raxis doctor` for any drift the new pressure exposes.

---

## Common errors

| Symptom | Fix |
|---|---|
| `policy sign: lane id duplicated` | Check the policy for two `[[lanes]]` with the same `id`. |
| `policy sign: priority out of range` | `priority` must be 0–100. |
| `policy reloaded` but new admissions still hit old caps | The kernel cached the policy; check `raxis policy show` matches your new bundle. |
| Lane budget overspends after raise | The new admissions are honoring the new cap; the overspend is from in-flight tasks that started under the old cap. Wait or abort. |

---

## Reference

| Command | Purpose |
|---|---|
| `raxis budget [--lane <id>]` | Per-lane snapshot. |
| `raxis log --kind LaneAdmissionRejected` | Recent rejections. |
| `raxis epoch advance` | Zero per-epoch budgets immediately. |
| `raxis policy show` | Inspect active policy. |
| [policy/07-lanes-section](../policy/07-lanes-section.md) | Full schema. |

---

## Variations

- **Per-team lanes.** One lane per team (`auth-work`, `api-work`,
  `ops`); each team's spend visible separately in `budget`.
- **Burst lane.** A high-priority lane with small
  `max_concurrent_tasks` for emergency / break-glass plans;
  default plans land elsewhere.
- **Cost shaping.** Drop `max_cost_per_epoch` overnight via a cron
  that rewrites policy on-the-hour; signals tighter spend during
  off-hours.
- **Priority ladder.** Three-tier system: priority 10 / 50 / 100;
  only well-justified plans get 100.

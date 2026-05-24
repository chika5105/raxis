# `raxis plan approve` and `raxis plan reject`

> **Topic:** CLI | **Time to read:** ~2 min | **Complexity:** ⭐ Beginner

`approve` admits a `Draft` initiative's tasks to the scheduler.
`reject` denies the initiative without spawning anything. Both are
operator-signed actions and recorded in the audit chain.

---

## Syntax

```text
raxis plan approve <initiative_id>
raxis plan reject  <initiative_id> [--reason <text>]
```

---

## When approve fits

After a successful `raxis submit plan --no-dry-run` an initiative
is `Draft`: the bundle is admitted, the canonical plan.toml is
stored, but no Executor / Reviewer sessions exist yet. `approve`
mints those sessions and starts the work.

```bash
INIT_ID="$(raxis submit plan ./plan.toml --no-dry-run | awk '/^Initiative / {print $2} /^initiative_id:/ {print $2}')"
raxis plan approve "$INIT_ID"
# Output:
# initiative_id:   1f3c8a...
# tasks_admitted:  3
# state:           Active
```

`tasks_admitted` is the count of Executor + Reviewer tasks the
kernel just admitted (= length of `[[tasks]]`).

The Orchestrator session spawns automatically; the initiative is
now visible in:

```bash
raxis initiative show "$INIT_ID" --with-tasks
raxis log "$INIT_ID"
```

---

## When reject fits

Use `reject` when the bundle was admitted but you've decided not to
run it (e.g., the plan was a draft submitted for review, the
operator review finds an issue, etc.). After reject:

- The initiative state transitions to `Rejected`.
- No sessions are spawned.
- The plan-bundle artifacts remain in the database (forensic).

```bash
raxis plan reject "$INIT_ID" \
  --reason "policy review: too broad path_allowlist"
# Output:
# initiative_id:  1f3c8a...
# state:          Rejected
# reason:         policy review: too broad path_allowlist
```

The reason is capped at 512 bytes server-side and mirrored into the
audit chain (`InitiativeRejected` event).

---

## Common errors

| Symptom | Fix |
|---|---|
| `approve: initiative not found` | Wrong `<initiative_id>`. Look it up with `raxis initiative list`. |
| `approve: initiative not in Draft state` | Already approved (running/done) or rejected. `raxis initiative show <id>` for the current state. |
| `approve: OPERATOR_NOT_AUTHORIZED` | Your cert lacks `ApprovePlan` in `permitted_ops`. Re-issue a cert with the op, or have a different operator approve. |
| `approve: FAIL_LANE_BUDGET_EXCEEDED` | The plan's lane is at its `max_cost_per_epoch`. Wait for the lane budget to free, or raise the cap and re-sign policy. |
| `reject: --reason too long` | Trim to ≤ 512 bytes. |

---

## Reference

| Surface | Purpose |
|---|---|
| `raxis initiative list [--state active \| completed \| quarantined \| all]` | Find initiatives by bucket. |
| `raxis initiative show <id> [--with-tasks]` | Drill into the initiative's per-task state. |
| `raxis initiative abort <id>` | Stop a running initiative. |
| `raxis log <initiative_id>` | Stream the audit events for one initiative. |
| `raxis plan validate <path>` | Pre-flight before submission. |

---

## Variations

- **Auto-approve in CI.** A CI bot with `CreateInitiative` +
  `ApprovePlan` permitted_ops can `submit plan --no-dry-run` and
  immediately `plan approve`. Use carefully — it removes a human
  review step.
- **Two-stage operator review.** Operator A signs the plan
  (`submit plan`); operator B reviews and approves
  (`plan approve`). This requires both operators to have
  appropriate `permitted_ops`.
- **Reject with no reason.** Allowed but discouraged — the audit
  chain captures the rejection but loses the why. Always pass
  `--reason`.

# `raxis epoch advance`

> **Topic:** CLI | **Time to read:** ~2 min | **Complexity:** ⭐⭐ Intermediate

Roll the policy epoch. Resets per-epoch lane budgets, advances
delegations into `StaleOnNextUse` if they reference an old epoch,
and is recorded as `EpochAdvanced` in the audit chain.

---

## Syntax

```text
raxis epoch advance [--reason <text>]
```

---

## When to advance

The policy epoch is a monotonic counter. The default scheduler
runs `epoch advance` automatically based on `[budget].epoch_seconds`
in policy. You manually advance when:

- You want to reset lane budgets immediately (e.g., after a CI run
  exhausted them and you want to admit more work without waiting).
- You changed `policy.toml` and `raxis policy sign` produced a new
  bundle; the kernel hot-reloads on file change, but a manual
  advance documents the operator-driven boundary.
- A break-glass response: you've just rotated cert sets and want
  delegations on the old epoch to transition to `StaleOnNextUse`
  for safety.

---

## Example

```bash
raxis epoch advance \
  --reason "manual: budget reset after incident"
# Output:
# from_epoch:   7
# to_epoch:     8
# reset_lanes:  3
# stale_delegations: 5
# audit_event:  EpochAdvanced (line 7322)
```

What happens during advance:

1. `from_epoch → to_epoch` is recorded in `policy_epochs` and
   audited (`EpochAdvanced`).
2. Each lane's `[budget].max_cost_per_epoch` accumulator resets
   to zero for the new epoch.
3. Active delegations whose policy epoch is `< to_epoch`
   transition to `StaleOnNextUse` — the next intent that uses them
   re-validates against the new policy or fails-closed.
4. The kernel emits `KernelPush::EpochAdvanced` to active
   Orchestrator sessions so they can re-issue intents that were
   blocked on budget.

The kernel rejects a manual advance if no `policy.toml` change has
occurred AND no `epoch_seconds` boundary has been crossed; pass
`--force` to override (rare; document the reason).

---

## Common errors

| Symptom | Fix |
|---|---|
| `epoch advance: not enough time since last advance` | The kernel rate-limits manual advances; pass `--force --reason ...` if you intentionally want to override. |
| `OPERATOR_NOT_AUTHORIZED` | Cert lacks `AdvanceEpoch` in `permitted_ops`. |
| `epoch advance: reason required` | The kernel always wants a reason in the audit chain. |
| `epoch advance: in-flight admission detected; retry` | Another admission was mid-flight; retry. Idempotent. |

---

## Reference

| Command | Purpose |
|---|---|
| `raxis policy show` | Active epoch + history. |
| `raxis budget` | Lane budgets (resets on advance). |
| `raxis log --kind EpochAdvanced` | Past advance events. |
| `raxis policy sign` | Re-sign policy.toml (often paired with advance). |

---

## Variations

- **Daily reset.** Cron `raxis epoch advance --reason "scheduled daily reset"`
  every 24 hours, even if `[budget].epoch_seconds` is longer.
- **Post-incident reset.** After investigating a budget-blowup
  incident, advance the epoch with a detailed `--reason` so the
  audit chain captures the operator decision.
- **Cert-rotation pairing.** After installing new operator certs
  and revoking old ones, advance the epoch immediately so any
  delegations issued under the old certs land on `StaleOnNextUse`.
- **Pre-deploy.** Advance before a large deploy plan so the deploy
  has a fresh full epoch budget, eliminating partial-budget
  variability in test results.

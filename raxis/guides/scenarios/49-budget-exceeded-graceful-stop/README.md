# Scenario 49 — Budget Exceeded: Graceful Stop

> **Complexity:** ⭐⭐ Intermediate | **Wall clock:** ~5 min | **Provider:** Anthropic

A plan is given a token budget that's deliberately too small. The
kernel emits `FAIL_BUDGET_EXCEEDED` and stops the initiative cleanly
between rounds.

---

## Run it

```bash
raxis plan validate ./plan.toml
raxis submit plan ./plan.toml --no-dry-run
INIT_ID="$(raxis initiative list --state Draft --json | jq -r '.[0].initiative_id')"
raxis plan approve "$INIT_ID"

# Watch the audits to see the budget breach.
raxis audit list --initiative-id "$INIT_ID"
```

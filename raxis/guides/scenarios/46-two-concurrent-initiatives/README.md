# Scenario 46 — Two Concurrent Initiatives

> **Complexity:** ⭐⭐ Intermediate | **Wall clock:** ~10 min | **Provider:** Anthropic

Submit two independent initiatives at once. Demonstrates per-lane
isolation and how the scheduler avoids head-of-line blocking.

---

## Run it

```bash
# Reuse scenarios 04 and 05 plan files:
raxis submit plan /tmp/scenario-04/plan.toml --no-dry-run
raxis submit plan /tmp/scenario-05/plan.toml --no-dry-run

raxis initiative list --state Active
```

# Scenario 44 — Session Revocation

> **Complexity:** ⭐⭐ Intermediate | **Wall clock:** ~5 min | **Provider:** Anthropic

Revoke a single agent session while keeping the initiative running.
Demonstrates the targeted "kill switch" for a misbehaving agent
without aborting the whole plan.

---

## Run it

```bash
# Find a running session:
raxis session list --json | jq

# Revoke one:
raxis session revoke <session_id> --reason "manual operator stop"
```

# Scenario 43 — Policy Epoch Advance (Live)

> **Complexity:** ⭐⭐⭐ Advanced | **Wall clock:** ~10 min | **Provider:** Anthropic

Publish a tighter policy bundle while an initiative is mid-flight.
Demonstrates how live sessions migrate to the new epoch on next
heartbeat without disturbance.

---

## Prerequisites

Same as scenario 04. A long-running initiative (use scenario 26 to
launch one).

---

## What this scenario demonstrates

- `raxis policy publish` issues `AUDIT_POLICY_EPOCH_ADVANCED`.
- In-flight tasks fail-closed if the new policy denies them.

---

## Run it

```bash
# Start a long task (scenario 26's plan):
INIT_ID=$(... see scenario 26 ...)

# Tighten the policy:
raxis policy publish ./tighter-policy.toml.signed
```

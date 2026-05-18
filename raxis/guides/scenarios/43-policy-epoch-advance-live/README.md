# Scenario 43 — Policy Epoch Advance (Live)

> **Complexity:** ⭐⭐⭐ Advanced | **Wall clock:** ~10 min | **Provider:** Anthropic

Sign and advance a tighter policy bundle while an initiative is
mid-flight. Demonstrates how live sessions migrate to the new epoch on
next policy check without disturbance.

---

## Prerequisites

Same as scenario 04. A long-running initiative (use scenario 26 to
launch one).

---

## What this scenario demonstrates

- `raxis policy sign` writes a fresh `policy.sig`.
- `raxis epoch advance` issues the policy-epoch audit event.
- In-flight tasks fail-closed if the new policy denies them.

---

## Run it

```bash
# Start a long task (scenario 26's plan):
INIT_ID=$(... see scenario 26 ...)

# Tighten the policy:
cp ./tighter-policy.toml "$RAXIS_DATA_DIR/policy/policy.toml"
raxis policy sign "$RAXIS_DATA_DIR/policy/policy.toml" \
  --key "$RAXIS_OPERATOR_KEY"
raxis epoch advance \
  --policy "$RAXIS_DATA_DIR/policy/policy.toml" \
  --sig "$RAXIS_DATA_DIR/policy/policy.sig"
```

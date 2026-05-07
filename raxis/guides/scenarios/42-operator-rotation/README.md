# Scenario 42 — Operator Rotation

> **Complexity:** ⭐⭐⭐ Advanced | **Wall clock:** ~10 min | **Provider:** Anthropic

Add a second operator with `raxis operator add`, sign a policy
update with the new key, then revoke the old one. Demonstrates the
multi-operator policy quorum and key-rotation flow.

---

## Prerequisites

Genesis must be complete. See SETUP.md.

---

## What this scenario demonstrates

- `raxis operator add` issues an OperatorActivated audit.
- Policy bundles signed with multiple operator fingerprints.
- `raxis operator deactivate` for offboarding.

---

## Run it

```bash
# Generate a new operator key:
raxis operator add --label alice

# List operators (should show two now):
raxis operator list

# Sign a policy with both keys:
raxis policy sign ./policy.toml --operator alice
raxis policy publish ./policy.toml.signed

# Deactivate the old key (after the new one signs first):
raxis operator deactivate --operator-id <old_fp>
```

# Scenario 42 — Operator Rotation

> **Complexity:** ⭐⭐⭐ Advanced | **Wall clock:** ~10 min | **Provider:** Anthropic

Add a second cert-backed operator, sign the updated policy, then rotate
or revoke the old cert. Demonstrates the operator-cert flow without the
removed pre-cert `raxis operator add` surface.

---

## Prerequisites

Genesis must be complete. See SETUP.md.

---

## What this scenario demonstrates

- `raxis cert mint` creates the new self-signed operator cert.
- `raxis cert install --policy ...` embeds it in policy.
- `raxis policy sign ... --key ...` writes the new `policy.sig`.
- Old certs are rotated with `raxis cert install --replace-for ...`.

---

## Run it

```bash
# Mint alice's cert on the machine that holds alice's private key.
raxis cert mint \
  --key /tmp/alice.key \
  --display-name alice \
  --ops "CreateInitiative,ApprovePlan,RejectPlan" \
  --out /tmp/alice.cert.toml

# Install alice into the live policy.
raxis cert install /tmp/alice.cert.toml \
  --policy "$RAXIS_DATA_DIR/policy/policy.toml"

# Re-sign the policy with the existing operator key.
raxis policy sign "$RAXIS_DATA_DIR/policy/policy.toml" \
  --key "$RAXIS_OPERATOR_KEY"

# Later, rotate an existing cert without changing its public key:
raxis cert install --replace-for <old-fingerprint> \
  --new-cert /tmp/alice-renewed.cert.toml \
  --policy "$RAXIS_DATA_DIR/policy/policy.toml"
```

For the full runbook, use
[`../../recipes/setup/10-add-second-operator.md`](../../recipes/setup/10-add-second-operator.md)
and [`../../recipes/ops/01-rotate-operator-cert.md`](../../recipes/ops/01-rotate-operator-cert.md).

# `raxis epoch advance`

> **Topic:** CLI | **Time to read:** ~2 min | **Complexity:** ⭐⭐ Intermediate

Load a new signed policy artifact and roll the policy epoch. The
kernel verifies the policy bytes plus detached signature, rejects
epoch replay, swaps the active bundle atomically, advances stale
delegations, invalidates affected prompts, and records
`PolicyEpochAdvanced` in the audit chain.

---

## Syntax

```text
raxis epoch advance --policy <policy.toml> --sig <policy.sig>
```

---

## When to advance

The policy epoch is a monotonic counter. Advance it when:

- You changed `policy.toml` and produced a matching signature.
- A break-glass response: you've just rotated cert sets and want
  delegations on the old epoch to transition to `StaleOnNextUse`
  for safety.
- You want the new policy's per-epoch lane budgets to become the
  active budget boundaries immediately.

---

## Example

```bash
raxis policy sign "$RAXIS_DATA_DIR/policy/policy.toml" \
  --key "$RAXIS_DATA_DIR/keys/authority_keypair.pem"

raxis epoch advance \
  --policy "$RAXIS_DATA_DIR/policy/policy.toml" \
  --sig    "$RAXIS_DATA_DIR/policy/policy.sig"
# Output:
# Epoch advanced:
#   new_epoch_id:               8
#   policy_sha256:              9ab3...
#   signed_by_authority:        8f0c...
#   n_delegations_marked_stale: 5
#   n_sessions_invalidated:     2
#   advanced_at:                1779068884
```

What happens during advance:

1. The kernel verifies the detached signature and checks that
   `[meta].epoch` is greater than the current epoch. The signature
   must be a raw 64-byte Ed25519 signature over the exact policy
   bytes, created with the authority key.
2. The epoch row and audit pointer land in one store transaction
   with the delegation sweep and prompt invalidation.
3. Active delegations whose policy epoch is `< to_epoch`
   transition to `StaleOnNextUse` — the next intent that uses them
   re-validates against the new policy or fails-closed.
4. The in-memory policy and allowlist snapshots swap after the
   transaction commits.
5. The kernel sends a best-effort `EpochAdvanced` signal to the
   gateway so provider egress and credential views reload.

---

## Common errors

| Symptom | Fix |
|---|---|
| `epoch advance requires --policy <path>` | Pass the policy artifact path explicitly. |
| `epoch advance requires --sig <path>` | Pass the detached signature path explicitly. |
| `FAIL_POLICY_SIGNATURE_INVALID` | The signature does not verify against the authority key or is not the expected detached signature bytes. Re-sign the exact policy bytes. |
| `FAIL_POLICY_EPOCH_REPLAY` | `[meta].epoch` is not greater than the current kernel epoch. Start from `raxis policy show`, bump/sign a fresh artifact, and retry. |
| `FAIL_POLICY_PATH_OUTSIDE_DATA_DIR` | Stage the policy and signature under `<data-dir>/policy/`; the kernel refuses paths outside its controlled policy directory. |

---

## Reference

| Command | Purpose |
|---|---|
| `raxis policy show` | Active epoch + history. |
| `raxis budget` | Lane budgets (resets on advance). |
| `raxis log --kind PolicyEpochAdvanced` | Past advance events. |
| `raxis policy sign` | Re-sign policy.toml (often paired with advance). |

---

## Variations

- **Post-incident reset.** After investigating a budget-blowup
  incident, stage a fresh policy artifact and advance the epoch so
  the audit chain captures the new boundary.
- **Cert-rotation pairing.** After installing new operator certs
  and revoking old ones, advance the epoch immediately so any
  delegations issued under the old certs land on `StaleOnNextUse`.
- **Pre-deploy.** Advance before a large deploy plan so the deploy
  has a fresh full epoch budget, eliminating partial-budget
  variability in test results.

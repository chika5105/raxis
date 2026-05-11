# Rotate an operator certificate

> **Topic:** Operations | **Time to read:** ~5 min | **Complexity:** ⭐⭐⭐ Advanced

This recipe walks the end-to-end rotation: mint a fresh cert,
embed it in policy, revoke the old one, and verify nothing breaks.
Use when a cert is approaching its `not_after`, when you suspect
compromise, or as a routine hygiene step.

---

## Prerequisites

- `RAXIS_DATA_DIR` exported and pointing at the active install.
- An operator key with `RotateOperatorCert`, `IssueCert`,
  `InstallCert`, `RevokeCert`, `SignPolicy` in `permitted_ops`. The
  initial genesis key always has these.
- Kernel running (`raxis status` returns `running`).
- A backup of `policy.toml` (cheap insurance):
  `cp $RAXIS_DATA_DIR/policy.toml /tmp/policy.toml.bak`.

---

## Steps

### 1. Mint the new cert

```bash
# Generate a new keypair if rotating to a fresh key (recommended).
raxis auth keygen --out /tmp/alice-new
# Produces: /tmp/alice-new.key (private), /tmp/alice-new.pub (public).

raxis cert mint \
  --signer 8a4f...                    \
  --subject ops-alice                  \
  --pubkey /tmp/alice-new.pub          \
  --permitted-ops CreateInitiative,ApprovePlan,SubmitPlan,GrantDelegation,ApproveEscalation,DenyEscalation \
  --ttl-seconds 7776000                \
  --out /tmp/alice-new.cert
```

Expected: `cert mint` prints the new kid (e.g., `3b1d…`) and writes
`/tmp/alice-new.cert`.

### 2. Verify chain validity before installing

```bash
raxis cert verify /tmp/alice-new.cert \
  --against-policy "$RAXIS_DATA_DIR/policy.toml"
# Expected: verdict: VALID
```

If `INVALID`, the signer's chain is broken — fix that first.

### 3. Embed in policy and re-sign

```bash
raxis cert install /tmp/alice-new.cert \
  --operator-key /tmp/genesis.key
# Expected: kernel_reload: ok, new_epoch: <N+1>
```

The kernel hot-reloads. Confirm the new cert is in policy:

```bash
raxis cert list | grep ops-alice
# Should show TWO ops-alice rows: the old kid (8a4f...) and the new (3b1d...).
```

### 4. Smoke-test the new cert

Use the new cert for a no-op operator action to confirm it works:

```bash
RAXIS_OPERATOR_KEY=/tmp/alice-new.key raxis status
# This signs an internal probe with the new key; if rejected,
# the install didn't take.
```

For a more thorough check, submit a tiny no-op plan with the new
key and immediately abort it:

```bash
RAXIS_OPERATOR_KEY=/tmp/alice-new.key \
raxis submit plan guides/scenarios/00-hello-orchestrator/plan.toml --dry-run
# Expected: dry_run_ok
```

### 5. Revoke the old cert

```bash
raxis cert revoke 8a4f... \
  --reason "rotation: TTL nearing expiry" \
  --operator-key /tmp/genesis.key
# Expected: revoked_kid 8a4f..., new_epoch advanced.
```

After revoke:

- The old kid is in `[[operators.revocations]]`.
- Any session whose chain lands on the old kid has its delegations
  transition to `StaleOnNextUse`.
- New plans signed with the old key are rejected.

### 6. Verify the rotation

```bash
raxis cert list | grep ops-alice                # only the new kid remains active
raxis cert list-revocations | grep 8a4f         # old kid in revocation list
raxis log --kind OperatorAdded --since "10 minutes ago"
raxis log --kind OperatorRevoked --since "10 minutes ago"
raxis verify-chain                                # audit chain still ok
```

All four commands should report consistent state.

---

## Rollback

If something is wrong:

```bash
raxis cert revoke 3b1d... --reason "rollback rotation" \
  --operator-key /tmp/genesis.key
# The new cert is now invalid; the old one is still revoked.
# You'll need to mint a fresh cert (cert mint -> cert install) to
# restore service for ops-alice.
```

There's no operation that "un-revokes" — once revoked, mint a new
cert with a new kid.

---

## Common errors

| Symptom | Fix |
|---|---|
| `cert mint: --ttl-seconds exceeds [operators].max_cert_ttl_seconds` | Lower TTL or raise the policy cap. |
| `cert install: kernel_reload failed` | Check `journalctl -u raxis-kernel` for the underlying parse error. Restore from `/tmp/policy.toml.bak`. |
| `cert revoke: cannot revoke last operator with permitted_op X` | At least one operator must remain authorized for each op. Add another operator first. |
| New cert smoke test rejected | Confirm `RAXIS_OPERATOR_KEY` points at the new private key, not the old one. |

---

## Variations

- **Two-operator rotation.** Operator A mints + installs the new
  cert; operator B revokes the old. Use this when a single
  operator shouldn't have both `IssueCert` and `RevokeCert`.
- **Hardware-key rotation.** Generate the keypair on a hardware
  signer; pass `--pubkey` and have the signer perform the cert
  signing.
- **Bulk rotation.** Loop through every operator entry in policy
  and rotate; pair with `raxis epoch advance` after the last
  rotation to flush stale delegations.
- **Pre-rotation drill.** In a sandbox `RAXIS_DATA_DIR`, perform
  the full rotation and verify; only then run on production.

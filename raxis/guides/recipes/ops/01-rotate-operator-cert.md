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
openssl genpkey -algorithm ED25519 -out /tmp/alice-new.key
chmod 600 /tmp/alice-new.key

raxis cert mint \
  --key /tmp/alice-new.key \
  --display-name ops-alice \
  --ops "CreateInitiative,ApprovePlan,GrantDelegation,ApproveEscalation,DenyEscalation" \
  --validity-days 90 \
  --out /tmp/alice-new.cert.toml
```

Expected: `cert mint` writes `/tmp/alice-new.cert.toml`.

### 2. Verify the cert before installing

```bash
raxis cert verify /tmp/alice-new.cert.toml
# Expected: self-signature OK
```

If verification fails, re-mint the cert before editing policy.

### 3. Embed in policy and re-sign

```bash
raxis cert install /tmp/alice-new.cert.toml \
  --policy "$RAXIS_DATA_DIR/policy/policy.toml"
raxis policy sign "$RAXIS_DATA_DIR/policy/policy.toml" \
  --key /tmp/genesis.key
```

The edited policy is now signed; advance the epoch or restart the
kernel according to your rollout flow. Confirm the new cert is in
policy:

```bash
raxis cert list | grep ops-alice
# Should show TWO ops-alice rows: the old kid (8a4f...) and the new (3b1d...).
```

### 4. Smoke-test the new cert

Use the new key to submit a tiny plan. `--dry-run` proves the key can
sign a bundle locally; `--no-dry-run` proves the kernel accepted the
operator after the policy reload.

```bash
RAXIS_OPERATOR_KEY=/tmp/alice-new.key \
raxis submit plan guides/scenarios/01-hello-world/plan.toml --dry-run
# Expected: dry_run_ok
```

### 5. Revoke the old cert

```bash
raxis --operator-key /tmp/genesis.key cert revoke /tmp/alice-old.cert \
  --reason rotation \
  --reference change-1234
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
raxis log --kind OperatorCertInstalled --since 10m
raxis log --kind OperatorCertRevoked --since 10m
raxis verify-chain                                # audit chain still ok
```

All four commands should report consistent state.

---

## Rollback

If something is wrong:

```bash
raxis --operator-key /tmp/genesis.key cert revoke /tmp/alice-new.cert.toml \
  --reason rotation \
  --reference rollback-rotation
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
| `cert mint requires --ops <op,op,...>` | Standard certs require an explicit operation list. |
| `cert install requires --policy <policy.toml>` | Pass the policy file to edit, then re-sign with `raxis policy sign`. |
| `cert revoke requires --reference <id>` | Include a ticket or incident id for forensic attribution. |
| New cert smoke test rejected | Confirm `RAXIS_OPERATOR_KEY` points at the new private key, not the old one. |

---

## Variations

- **Two-operator rotation.** Operator A mints + installs the new cert;
  operator B reviews the policy diff and re-signs.
- **Hardware-key rotation.** Generate the keypair on a hardware
  signer and expose the signing operation through a local path or
  wrapper that `raxis cert mint --key` can read.
- **Bulk rotation.** Loop through every operator entry in policy
  and rotate; pair with `raxis epoch advance` after the last
  rotation to flush stale delegations.
- **Pre-rotation drill.** In a sandbox `RAXIS_DATA_DIR`, perform
  the full rotation and verify; only then run on production.

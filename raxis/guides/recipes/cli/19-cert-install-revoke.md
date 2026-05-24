# `raxis cert install`, `cert revoke`, `cert list`, `cert list-revocations`

> **Topic:** CLI | **Time to read:** ~2 min | **Complexity:** ⭐⭐ Intermediate

Manage the operator-cert population embedded in `policy.toml`.
`install` adds a cert; `revoke` puts a kid in the revocation list;
`list` and `list-revocations` are read-only inspection.

---

## Syntax

```text
raxis cert install <cert_path> --policy <policy.toml>
raxis cert install --replace-for <old_fp> --new-cert <cert_path> --policy <policy.toml>
raxis [--operator-key <key.priv>] cert revoke <cert_path> --reason <rotation|compromise> --reference <id>
raxis cert list                  [--json]
raxis cert list-revocations      [--json]
```

---

## install — embed a cert

`cert install` edits `policy.toml`: it reads the cert, appends or
rotates the matching `[[operators.entries]]` block, embeds the cert,
and prints the re-sign reminder. It does not sign or advance the
policy by itself.

```bash
raxis cert install /tmp/alice.cert \
  --policy "$RAXIS_DATA_DIR/policy/policy.toml"
raxis policy sign "$RAXIS_DATA_DIR/policy/policy.toml" \
  --key "$RAXIS_DATA_DIR/keys/authority_keypair.pem"
# Output:
# cert subject:    ops-alice
# reminder: re-sign the policy
```

If you are rotating an existing cert for the same operator key, use
`--replace-for <old_fp> --new-cert <path>`. The kernel records the
rotation on the next epoch advance.

The same path is how you widen an operator after genesis. For example,
to grant `OperatorCertInstall`, mint a replacement cert for the same
operator key with that op included, install it with `--replace-for`,
re-sign the policy, and advance the epoch. `cert install` mirrors the
new cert's `permitted_ops` into the policy entry so reviewers can see
the authority change in the diff before it becomes active.

Dashboard plaintext reveal requires the local `admin` role. RAXIS
derives that role from cert authority: `RotateEpoch` plus
`OperatorCertInstall` in the operator's `permitted_ops`. A typical
same-key widening ceremony is:

```bash
export OPS="CreateInitiative,ApprovePlan,RejectPlan,CreateSession,RevokeSession,GrantDelegation,RetryTask,ResumeTask,AbortTask,AbortInitiative,ApproveEscalation,DenyEscalation,RotateEpoch,QuarantineInitiative,QuarantinePlansBy,OperatorCertInstall"

OLD_FP="$(raxis policy show --json | jq -r '.operators[0].pubkey_fingerprint')"

raxis cert mint \
  --display-name "$USER" \
  --key "$RAXIS_OPERATOR_KEY" \
  --ops "$OPS" \
  --out "$RAXIS_DATA_DIR/policy/operator-admin.cert.toml"

raxis cert install \
  --replace-for "$OLD_FP" \
  --new-cert "$RAXIS_DATA_DIR/policy/operator-admin.cert.toml" \
  --policy "$RAXIS_DATA_DIR/policy/policy.toml"

# Set [meta].epoch to the next integer before signing.
$EDITOR "$RAXIS_DATA_DIR/policy/policy.toml"

raxis policy sign "$RAXIS_DATA_DIR/policy/policy.toml" \
  --key "$RAXIS_DATA_DIR/keys/authority_keypair.pem"

raxis --operator-key "$RAXIS_OPERATOR_KEY" epoch advance \
  --policy "$RAXIS_DATA_DIR/policy/policy.toml" \
  --sig "$RAXIS_DATA_DIR/policy/policy.sig"
```

After the advance, sign out and back into the dashboard. Existing
JWTs keep the roles they were minted with.

---

## revoke — invalidate a kid

```bash
raxis --operator-key /tmp/genesis.key cert revoke /tmp/alice.cert \
  --reason rotation \
  --reference change-1234
# Output:
# Revoked: alice (...)
# on-disk path: <data-dir>/revocations/<pubkey>.toml
```

Effects:

- A signed revocation record is written under
  `<data-dir>/revocations/`.
- All future cert-verify checks fail-closed against this kid (and
  any cert it signed).
- Sessions whose operator-cert chain now lands on this kid have
  their delegations transition to `StaleOnNextUse` — the next intent
  from those sessions is rejected.
- The local cert CLI audit trail records `OperatorCertRevoked`; restart
  the kernel for the revocation to take effect.

`revoke` does **not** retroactively undo prior actions — it's
strictly forward-looking. If you need to undo prior runs, use
`raxis operator quarantine-plans-by <signer_kid>` to mass-quarantine
initiatives signed by the kid.

---

## list / list-revocations — inspection

```bash
raxis cert list
# Output:
# KID            SUBJECT       TTL_REMAINING  PERMITTED_OPS                  EMERGENCY
# 8a4f...        genesis       365d           <full set>                     no
# 3b1d...        ops-alice     90d            CreateInitiative,ApprovePlan   no
# 7f88...        ops-bob       1d             <full set>                     yes  (reason: ...)

raxis cert list-revocations
# Output:
# KID            REASON                                AT
# 9c41...        Suspected leak; rotated 2026-04-12    2026-04-12T...
```

`--json` form is suitable for dashboards.

---

## Common errors

| Symptom | Fix |
|---|---|
| `install: cert verify failed` | The cert isn't valid against the current policy. Use `cert verify` to diagnose. |
| `install: cert already installed (kid: ...)` | Idempotent — already in policy. |
| `cert install requires --policy <policy.toml>` | Pass the policy file you intend to edit. |
| `cert revoke requires --reference <id>` | Add a short change ticket or incident id. |
| `cert revoke requires --operator-key <path>` | Pass it as a global flag before `cert` or set `RAXIS_OPERATOR_KEY`. |

---

## Reference

| Command | Purpose |
|---|---|
| `raxis cert mint` / `cert mint-emergency` | Issue a new cert. |
| `raxis cert show <path>` | Decode a cert. |
| `raxis cert verify <path>` | Chain check. |
| `raxis policy sign` | Re-sign policy after manual edits. |
| `raxis policy show` | Inspect active policy. |
| `raxis operator quarantine-plans-by <kid>` | Bulk quarantine initiatives by signer. |

---

## Variations

- **Rotation playbook.** `cert mint` new, `cert install --replace-for`
  new, `policy sign`, then `cert revoke` old if the old cert must be
  invalidated immediately.
- **Two-operator approval.** Run `cert install --policy`, have a second
  operator review the policy diff (`raxis policy diff`), then run
  `raxis policy sign` to bless the install.
- **Bulk audit.** Pipe `cert list --json | jq` into a script that
  alerts on any cert with `ttl_remaining < 7d` or
  `emergency == true`.

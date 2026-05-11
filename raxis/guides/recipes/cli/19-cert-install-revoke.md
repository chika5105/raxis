# `raxis cert install`, `cert revoke`, `cert list`, `cert list-revocations`

> **Topic:** CLI | **Time to read:** ~2 min | **Complexity:** ⭐⭐ Intermediate

Manage the operator-cert population embedded in `policy.toml`.
`install` adds a cert; `revoke` puts a kid in the revocation list;
`list` and `list-revocations` are read-only inspection.

---

## Syntax

```text
raxis cert install <cert_path> [--operator-key <key.priv>] [--no-resign]
raxis cert revoke  <signer_kid> --reason <text> [--operator-key <key.priv>] [--no-resign]
raxis cert list                  [--json]
raxis cert list-revocations      [--json]
```

---

## install — embed a cert

`cert install` does the round-trip: read the cert, append to
`[[operators.entries]]`, re-sign `policy.toml`, advance the policy
epoch, and trigger a hot reload. Without `--no-resign` the
operator key is required (`--operator-key` or `RAXIS_OPERATOR_KEY`).

```bash
raxis cert install /tmp/alice.cert \
  --operator-key /tmp/genesis.key
# Output:
# cert subject:    ops-alice
# new_epoch:       8
# policy_path:     /var/raxis/policy.toml
# kernel_reload:   ok
```

If you've cherry-picked a specific cert and want the kernel to
reload immediately, this one command does it. The audit chain
captures `OperatorAdded` for the new entry and `PolicyReloaded`
for the new epoch.

`--no-resign` skips the re-sign step — useful when scripting
multi-step changes (e.g., install three certs, then re-sign once
at the end). Don't forget to `raxis policy sign` afterwards.

---

## revoke — invalidate a kid

```bash
raxis cert revoke 8a4f... \
  --reason "key rotation: alice retired" \
  --operator-key /tmp/genesis.key
# Output:
# revoked_kid:     8a4f...
# new_epoch:       9
# kernel_reload:   ok
```

Effects:

- The kid is appended to `[[operators.revocations]]` with the
  supplied reason and operator signature.
- All future cert-verify checks fail-closed against this kid (and
  any cert it signed).
- Sessions whose operator-cert chain now lands on this kid have
  their delegations transition to `StaleOnNextUse` — the next intent
  from those sessions is rejected.
- The audit chain captures `OperatorRevoked { kid, reason }`.

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
# 3b1d...        ops-alice     90d            CreateInitiative,SubmitPlan    no
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
| `install: --operator-key required` | Either set `RAXIS_OPERATOR_KEY` or pass `--operator-key`. |
| `revoke: kid not found in policy` | Already revoked, or never installed. |
| `revoke: cannot revoke last operator with permitted_op X` | The system needs at least one operator authorized for each permitted_op; remove the constraint by adding another operator first. |

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

- **Rotation playbook.** `cert mint` new, `cert install` new,
  `cert revoke` old (in that order). The kernel hot-reloads after
  each step.
- **Two-operator approval.** Install a cert with `--no-resign`,
  have a second operator review the policy diff
  (`raxis policy diff`) and run `raxis policy sign` to actually
  bless the install.
- **Bulk audit.** Pipe `cert list --json | jq` into a script that
  alerts on any cert with `ttl_remaining < 7d` or
  `emergency == true`.

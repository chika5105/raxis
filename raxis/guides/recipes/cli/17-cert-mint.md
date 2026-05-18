# `raxis cert mint` and `raxis cert mint-emergency`

> **Topic:** CLI | **Time to read:** ~3 min | **Complexity:** ⭐⭐⭐ Advanced

Mint operator certificates from your operator key. `cert mint` is
the standard path used at install time and for routine rotation.
`cert mint-emergency` produces a narrowly-scoped recovery cert
intended for break-glass situations where the standard cert is
compromised or unavailable.

---

## Syntax

```text
raxis cert mint --key <operator_private.pem>
                --display-name <name>
                --ops <csv>
                [--validity-days <days>]
                [--warn-days <days>]
                [--grace-days <days>]
                [--contact <text>]
                [--out <path>]

raxis cert mint-emergency --key <operator_private.pem>
                          --display-name <name>
                          [--out <path>]
```

---

## Concepts

A Raxis operator cert is an Ed25519-signed document with:

- `display_name` — human-readable operator name.
- `pubkey_hex` — derived from the private key passed via `--key`.
- `permitted_ops` — the list of operations this cert authorizes
  (e.g., `CreateInitiative`, `ApprovePlan`, `RevokeSession`).
- `not_before` / `not_after` — TTL bounds.
- `self_sig_hex` — Ed25519 self-signature over the canonical bytes.

Every operator-signed action checks: the operator cert is valid
(not expired, not revoked, embedded in current `policy.toml`), and
the op is in `permitted_ops`. Fail-closed.

---

## mint — standard operator cert

Common use: rotating an operator's cert before TTL expires.

```bash
raxis cert mint \
  --key /tmp/alice.key \
  --display-name ops-alice \
  --ops "CreateInitiative,ApprovePlan,GrantDelegation" \
  --validity-days 90 \
  --out /tmp/alice.cert.toml
# Output:
# ✓ Wrote operator cert ...
# display_name:  ops-alice
# kind:          Standard
# permitted_ops: CreateInitiative,ApprovePlan,GrantDelegation
```

The output cert must then be embedded into `policy.toml` under
`[[operators.entries]]` and re-signed with `raxis policy sign`.

---

## mint-emergency — break-glass cert

Use when the normal operator path is broken and you need the narrow
recovery operation. Emergency certs:

- Are structurally pinned to `permitted_ops = ["RotateEpoch"]`.
- Have no normal validity window (`not_after = 0` sentinel).
- Still require policy install + policy signing before use.

```bash
raxis cert mint-emergency \
  --key /tmp/bob.key \
  --display-name ops-bob \
  --out /tmp/bob-emergency.cert.toml
# Output:
# kind:          EmergencyRecovery
# permitted_ops: RotateEpoch
```

After the emergency, the operator should mint a regular cert
(`cert mint`) and rotate policy away from the emergency cert. The
emergency cert is deliberately limited to `RotateEpoch`.

---

## Common errors

| Symptom | Fix |
|---|---|
| `cert mint requires --ops <op,op,...>` | Standard certs require an explicit operation list. |
| `unknown cert mint flag` | Run `raxis cert mint --help`; the current flag is `--ops`, not `--permitted-ops`. |
| `cert mint requires --key <path>` | Pass `--key` or the global `--operator-key` before `cert`. |
| `cert mint-emergency rejects --ops other than 'RotateEpoch'` | Emergency certs are structurally pinned to `RotateEpoch`. |

---

## Reference

| Command | Purpose |
|---|---|
| `raxis cert show <path>` | Decode a cert file. |
| `raxis cert verify <path>` | Confirm structure, time status, and self-signature. |
| `raxis cert install <path> --policy <policy.toml>` | Embed in `policy.toml`; re-sign afterwards. |
| `raxis [--operator-key <key>] cert revoke <cert> --reason <rotation\|compromise> --reference <id>` | Add a signed revocation record. |
| `raxis cert list` | Active certs in the current policy. |
| `raxis cert list-revocations` | Revoked certs. |

---

## Variations

- **CI bot cert with narrow permitted_ops.** `--ops CreateInitiative,CreateSession`
  for a CI bot that should only submit plans, not approve them.
- **Reviewer-only cert.** `--ops ApprovePlan,ApproveEscalation,DenyEscalation`
  for an operator who reviews but doesn't initiate.
- **Short-lived TTLs.** Set `--validity-days 1` for daily rotation
  of automated bots; pair with a refresh script.
- **Multi-region.** Mint per-region certs with distinct
  `--display-name` values to track which region performed which action
  in audit.

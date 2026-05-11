# `raxis cert mint` and `raxis cert mint-emergency`

> **Topic:** CLI | **Time to read:** ~3 min | **Complexity:** ⭐⭐⭐ Advanced

Mint operator certificates from your operator key. `cert mint` is
the standard path used at install time and for routine rotation.
`cert mint-emergency` produces a short-TTL one-shot cert intended
for break-glass situations where the standard cert is compromised
or unavailable.

---

## Syntax

```text
raxis cert mint --signer <signer_kid>
                --subject <operator_id>
                --pubkey <hex_or_path>
                --permitted-ops <csv>
                --ttl-seconds <seconds>
                [--out <path>]

raxis cert mint-emergency --signer <signer_kid>
                          --subject <operator_id>
                          --pubkey <hex_or_path>
                          --reason <text>
                          [--out <path>]
```

---

## Concepts

A Raxis operator cert is an Ed25519-signed document with:

- `subject` — operator id this cert grants authority to.
- `pubkey` — operator's public key (32-byte Ed25519).
- `signer_kid` — the key id of the signer (typically the genesis
  signer or a higher-privilege operator).
- `permitted_ops` — the list of operations this cert authorizes
  (e.g., `CreateInitiative`, `ApprovePlan`, `RevokeSession`).
- `not_before` / `not_after` — TTL bounds.
- `signature` — Ed25519 signature over the canonical bytes.

Every operator-signed action checks: signer's cert is valid (not
expired, not revoked, embedded in current `policy.toml`), and the
op is in `permitted_ops`. Fail-closed.

---

## mint — standard operator cert

Common use: rotating an operator's cert before TTL expires.

```bash
raxis cert mint \
  --signer 8a4f...                      \
  --subject ops-alice                    \
  --pubkey  /tmp/alice.pub               \
  --permitted-ops CreateInitiative,ApprovePlan,SubmitPlan,GrantDelegation \
  --ttl-seconds 7776000                  \
  --out /tmp/alice.cert
# Output:
# cert_path:     /tmp/alice.cert
# signer_kid:    8a4f...
# subject:       ops-alice
# not_before:    2026-05-10T17:30:00Z
# not_after:     2026-08-08T17:30:00Z
# permitted_ops: CreateInitiative,ApprovePlan,SubmitPlan,GrantDelegation
```

The output cert must then be embedded into `policy.toml` under
`[[operators.entries]]` and re-signed with `raxis policy sign`.

---

## mint-emergency — break-glass cert

Use when standard cert chain is broken: signer's key is lost, all
operator certs expired in CI, etc. Emergency certs:

- Always TTL ≤ 24 hours (server-side ceiling, can't be raised).
- Carry a mandatory `--reason` string in the cert payload.
- Fire an audit-chain event of kind `EmergencyCertMinted` so the
  break-glass action is auditable forever.

```bash
raxis cert mint-emergency \
  --signer 8a4f...                       \
  --subject ops-bob                       \
  --pubkey  /tmp/bob.pub                  \
  --reason  "rotate alice cert: CI auth lost" \
  --out /tmp/bob-emergency.cert
# Output:
# cert_path:     /tmp/bob-emergency.cert
# signer_kid:    8a4f...
# subject:       ops-bob
# not_before:    2026-05-10T17:30:00Z
# not_after:     2026-05-11T17:30:00Z   (24h max)
# permitted_ops: <full set>
# emergency:     true
# reason:        "rotate alice cert: CI auth lost"
```

After the emergency, the operator should mint a regular cert
(`cert mint`) and let the emergency cert expire naturally. The
audit event is permanent.

---

## Common errors

| Symptom | Fix |
|---|---|
| `mint: --signer cert not found in policy` | Embed the signer's cert in `policy.toml` and re-sign. |
| `mint: --pubkey not 32 bytes` | Verify the public key is raw 32-byte Ed25519, not PEM. Use `raxis auth show-pubkey <key.priv>` to extract. |
| `mint: --permitted-ops contains unknown op` | The op name doesn't match the kernel's enum. Run `raxis cert show --help-permitted-ops` for the supported list. |
| `mint: --ttl-seconds exceeds [operators].max_cert_ttl_seconds` | Lower TTL or raise the policy cap. |
| `mint-emergency: missing --reason` | Required for emergency certs (audit). |

---

## Reference

| Command | Purpose |
|---|---|
| `raxis cert show <path>` | Decode a cert file. |
| `raxis cert verify <path> --against-policy <policy.toml>` | Confirm chain validity. |
| `raxis cert install <path>` | Embed in `policy.toml` and re-sign. |
| `raxis cert revoke <kid> --reason ...` | Add to revocation list. |
| `raxis cert list` | Active certs in the current policy. |
| `raxis cert list-revocations` | Revoked certs. |

---

## Variations

- **CI bot cert with narrow permitted_ops.** `--permitted-ops CreateInitiative,SubmitPlan`
  for a CI bot that should only submit plans, not approve them.
- **Reviewer-only cert.** `--permitted-ops ApprovePlan,ApproveEscalation,DenyEscalation`
  for an operator who reviews but doesn't initiate.
- **Short-lived TTLs.** Set `--ttl-seconds 86400` for daily rotation
  of automated bots; pair with a refresh script.
- **Multi-region.** Mint per-region certs with distinct `subject`
  values to track which region performed which action in audit.

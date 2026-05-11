# `raxis cert show` and `raxis cert verify`

> **Topic:** CLI | **Time to read:** ~2 min | **Complexity:** ⭐⭐ Intermediate

Read-only inspection of operator certificates. `cert show` decodes
a cert file and prints its claims. `cert verify` checks chain
validity against a policy bundle.

---

## Syntax

```text
raxis cert show   <cert_path> [--json]
raxis cert verify <cert_path> --against-policy <policy.toml>
```

---

## show — decode a cert

```bash
raxis cert show /tmp/alice.cert
# Output:
# subject:        ops-alice
# pubkey:         3b1d... (32 bytes)
# signer_kid:     8a4f...
# not_before:     2026-05-10T17:30:00Z
# not_after:      2026-08-08T17:30:00Z
# permitted_ops:  CreateInitiative,ApprovePlan,SubmitPlan,GrantDelegation
# emergency:      false
# signature:      <hex>
# signature_ok:   yes (over canonical bytes)
```

JSON form for tooling:

```bash
raxis cert show /tmp/alice.cert --json | jq '.permitted_ops'
```

`signature_ok: yes` confirms the cert's bytes haven't been
tampered with — the kernel re-runs Ed25519 verification using the
signer's public key embedded in the cert. It does **not** confirm
the signer's cert is valid against the current policy; for that,
use `cert verify`.

---

## verify — full chain check

`cert verify` is what the kernel does at admission time. It checks:

1. The cert's signature is valid (Ed25519 over canonical bytes).
2. The signer is embedded in the supplied policy's
   `[[operators.entries]]`.
3. The signer's cert is itself within its `not_before` /
   `not_after` window.
4. Neither the signer nor the subject is on the revocation list
   (`[[operators.revocations]]`).
5. `now()` is within the cert's TTL.

```bash
raxis cert verify /tmp/alice.cert \
  --against-policy /var/raxis/policy.toml
# Output:
# subject:                   ops-alice
# signer_kid:                8a4f...
# signature_ok:              yes
# signer_in_policy:          yes
# signer_within_ttl:         yes
# subject_revoked:           no
# signer_revoked:            no
# subject_within_ttl:        yes
# verdict:                   VALID
```

If any check fails, `verdict` is `INVALID` and the line that failed
is marked `no`. Useful for diagnosing
`OPERATOR_NOT_AUTHORIZED` errors.

---

## Common errors

| Symptom | Fix |
|---|---|
| `show: file not found` | Wrong path. |
| `show: not a Raxis cert` | Wrong file format. Raxis certs are CBOR-encoded; check you're not pointing at a TOML or PEM file. |
| `verify: --against-policy not found` | Provide the path to the active policy bundle (`/var/raxis/policy.toml` typically). |
| `verify: signer not in policy` | The signer cert was rotated out of the policy; this cert is no longer chainable. Re-sign by a current signer. |
| `verify: subject revoked` | The cert is in `[[operators.revocations]]`. Mint a new cert. |
| `verify: subject TTL expired` | Re-mint with `cert mint`. |

---

## Reference

| Command | Purpose |
|---|---|
| `raxis cert mint` / `cert mint-emergency` | Issue a new cert. |
| `raxis cert install <path>` | Embed cert in policy and re-sign. |
| `raxis cert revoke <kid>` | Add to revocation list. |
| `raxis cert list` | Active certs in policy. |
| `raxis cert list-revocations` | Revoked certs. |
| `raxis policy show` | Display the active policy bundle. |

---

## Variations

- **Pre-flight cert install.** `cert verify` against the policy
  before running `cert install` to ensure the install will succeed.
- **CI sanity check.** A periodic cron that runs
  `cert verify` for every operator cert and pages on `INVALID`
  verdicts.
- **Cert audit.** Track the output of `cert show --json` over time;
  feed it into a compliance dashboard that flags certs nearing TTL.
- **Revocation drill.** `cert revoke` a test cert, then
  `cert verify` confirms the `subject_revoked: yes` line — useful
  to validate the revocation pipeline end-to-end.

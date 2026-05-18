# `raxis cert show` and `raxis cert verify`

> **Topic:** CLI | **Time to read:** ~2 min | **Complexity:** ⭐⭐ Intermediate

Read-only inspection of operator certificates. `cert show` decodes a
cert file and prints its claims. `cert verify` checks the cert's
structure, self-signature, and time status.

---

## Syntax

```text
raxis cert show   <cert_path> [--json]
raxis cert verify <cert_path> [--at-time <unix-seconds>]
```

---

## show — decode a cert

```bash
raxis cert show /tmp/alice.cert.toml
# Output:
# display_name:   ops-alice
# pubkey_hex:     3b1d...
# kind:           Standard
# not_before:     2026-05-10T17:30:00Z
# not_after:      2026-08-08T17:30:00Z
# permitted_ops:  CreateInitiative,ApprovePlan,GrantDelegation
# self_sig_ok:    yes
```

JSON form for tooling:

```bash
raxis cert show /tmp/alice.cert.toml --json | jq '.permitted_ops'
```

`self_sig_ok: yes` confirms the cert's bytes have not been
tampered with. It does **not** confirm the cert is installed in the
current policy; for that, use `raxis cert list` or `raxis doctor`.

---

## verify — structural check

`cert verify` checks:

1. The cert's signature is valid (Ed25519 over canonical bytes).
2. The cert has no structural violations.
3. `now()` (or `--at-time`) is within the cert's validity window.

```bash
raxis cert verify /tmp/alice.cert.toml
# Output:
# display_name:             ops-alice
# status:                   Active
# self-signature            OK
```

If structure or self-signature fails, the command exits non-zero and
prints the failing checks.

---

## Common errors

| Symptom | Fix |
|---|---|
| `show: file not found` | Wrong path. |
| `show: not a Raxis cert` | Wrong file format. RAXIS certs are TOML; check you are not pointing at a PEM key. |
| `unknown cert verify flag: "--against-policy"` | Current `cert verify` is local-only; use `raxis cert list` or `raxis doctor` to inspect installed policy state. |
| `cert verification failed` | Re-mint the cert; the file is structurally invalid or its self-signature does not match. |

---

## Reference

| Command | Purpose |
|---|---|
| `raxis cert mint` / `cert mint-emergency` | Issue a new cert. |
| `raxis cert install <path> --policy <policy.toml>` | Embed cert in policy; re-sign afterwards. |
| `raxis [--operator-key <key>] cert revoke <cert> --reason <rotation\|compromise> --reference <id>` | Add a signed revocation record. |
| `raxis cert list` | Active certs in policy. |
| `raxis cert list-revocations` | Revoked certs. |
| `raxis policy show` | Display the active policy bundle. |

---

## Variations

- **Pre-flight cert install.** Run `cert verify` before
  `cert install --policy` to catch structural mistakes early.
- **CI sanity check.** A periodic cron that runs
  `cert verify` for every operator cert and pages on `INVALID`
  verdicts.
- **Cert audit.** Track the output of `cert show --json` over time;
  feed it into a compliance dashboard that flags certs nearing TTL.
- **Revocation drill.** `cert revoke` a test cert, then
  `cert list-revocations` confirms the signed revocation record.

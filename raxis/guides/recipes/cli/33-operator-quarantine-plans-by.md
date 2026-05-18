# `raxis operator quarantine-plans-by`

> **Topic:** CLI | **Time to read:** ~2 min | **Complexity:** ⭐⭐⭐ Advanced

Bulk operator-signed action: quarantine **every** initiative whose
plan was signed by the given operator kid. Use as the immediate
response to a suspected operator-key compromise.

---

## Syntax

```text
raxis operator quarantine-plans-by <signer_kid>
                                   [--reason <text>]
                                   [--lift]
                                   [--dry-run]
```

---

## Why this exists

If an operator key is compromised, the attacker may have signed
plans submitted before you noticed. Revoking the cert
(`cert revoke <cert.toml>`) prevents NEW plans, but the old ones are
already running. `quarantine-plans-by` freezes them in bulk so you
can investigate without manually iterating.

The kernel scans `initiatives` for any whose
`plan_bundle.signer_kid == <kid>` and quarantines each
(equivalent to running `raxis initiative quarantine` on each).

---

## Example

```bash
# Dry run first - see what would be touched.
raxis operator quarantine-plans-by 8a4f... \
  --reason "key compromise: alice laptop stolen" \
  --dry-run
# Output:
# would_quarantine: 23 initiatives
# state distribution:
#   Active:    14
#   Draft:      6
#   Completed:  3   (already terminal; no-op for these)

# Apply.
raxis operator quarantine-plans-by 8a4f... \
  --reason "key compromise: alice laptop stolen"
# Output:
# quarantined: 20 initiatives  (3 already terminal, skipped)
# audit_event: 20x InitiativeQuarantined
```

---

## Lift

After investigation, you can lift in bulk:

```bash
raxis operator quarantine-plans-by 8a4f... \
  --reason "investigation complete: no compromise" \
  --lift
# Output:
# lifted: 20 initiatives
```

`--lift` only un-quarantines initiatives that were quarantined by
THIS bulk action (linked via the `--reason` field's audit
correlation). Initiatives quarantined by a separate
`raxis initiative quarantine` call are unaffected.

---

## Companion: revoke the cert

The bulk quarantine should be paired with revoking the cert:

```bash
raxis --operator-key /tmp/safe-genesis.key cert revoke /tmp/alice.cert.toml \
  --reason compromise \
  --reference incident-2026-05
raxis --operator-key /tmp/safe-genesis.key operator quarantine-plans-by 8a4f... \
  --reason "key compromise: alice laptop stolen"
```

In that order: revoke first, then quarantine. The revoke
prevents new admissions; the quarantine handles already-admitted
work.

---

## Common errors

| Symptom | Fix |
|---|---|
| `quarantine-plans-by: signer not in policy` | The kid isn't recognized. Check `raxis cert list` for the right kid. |
| `quarantine-plans-by: 0 initiatives matched` | The signer never signed any plan, or the kid is wrong. |
| `OPERATOR_NOT_AUTHORIZED` | Cert lacks `QuarantineInitiative` in `permitted_ops`. |
| `--lift: 0 lifted` | The supplied `--reason` doesn't match a prior bulk-quarantine action; lift will only undo the ones it created. |

---

## Reference

| Command | Purpose |
|---|---|
| `raxis cert revoke <cert.toml> --reason compromise --reference <id>` | Revoke the cert itself. |
| `raxis initiative quarantine <id>` | Single-initiative quarantine. |
| `raxis log --kind InitiativeQuarantined --since <when>` | Audit the bulk action. |
| `raxis initiative list --state quarantined` | List frozen initiatives. |

---

## Variations

- **Per-tenant compromise.** If you mint per-tenant operator certs
  (one cert per business unit), `quarantine-plans-by <tenant_kid>`
  freezes only that tenant's initiatives.
- **CI bot rotation.** When rotating a CI bot's cert, optionally
  bulk-quarantine its in-flight initiatives so the rotation is
  atomic from a forensic POV.
- **Drill.** Periodically practice the compromise response: revoke
  a test cert, run `quarantine-plans-by`, verify the audit chain
  captures everything, lift, restore.

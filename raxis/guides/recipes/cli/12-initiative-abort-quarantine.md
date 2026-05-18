# `raxis initiative abort` and `raxis initiative quarantine`

> **Topic:** CLI | **Time to read:** ~3 min | **Complexity:** ⭐⭐ Intermediate

Two operator-signed safety levers for a running initiative.
`abort` is a one-shot stop. `quarantine` freezes the initiative and
rejects future intents until lifted. Both record an
`InitiativeAborted` / `InitiativeQuarantined` audit event.

---

## Syntax

```text
raxis initiative abort      <initiative_id>
raxis initiative quarantine <initiative_id> [--reason <text>] [--lift]
```

---

## abort — irreversible stop

`abort` immediately terminates all sessions tied to the initiative,
marks the initiative `Aborted`, and refuses any further intents.

```bash
raxis initiative abort 1f3c8a4b
# Output:
# Initiative 1f3c8a4b aborted. All non-terminal tasks cancelled.
```

What aborts mean:

- All Executor / Reviewer / Verifier sessions on the initiative
  receive `SIGTERM` then `SIGKILL` after a 10s grace.
- In-flight intents from those sessions are dropped before any
  side effects fire (deny-by-default).
- The audit chain captures `InitiativeAborted { initiative_id, reason }`.
- `state == Aborted` is **terminal** — you cannot resume.

When to use abort:

- The initiative is stuck in a compute loop you don't want to wait
  out (e.g., escalation rate-limit eaten by junk).
- You changed your mind and want to free the lane budget.
- Forensic evidence is sufficient and you no longer need the
  workspace.

---

## quarantine — reversible freeze

`quarantine` is non-destructive. The initiative stays alive but
new intents from its sessions are **rejected** with
`SECURITY_QUARANTINED` until you lift it.

```bash
raxis initiative quarantine 1f3c8a4b \
  --reason "investigation: suspicious egress"
# Output:
# initiative_id:   1f3c8a4b...
# quarantined:     yes
# reason:          investigation: suspicious egress

# Lift later
raxis initiative quarantine 1f3c8a4b --lift
# Output:
# initiative_id:   1f3c8a4b...
# quarantined:     no
```

Differences from abort:

| | `abort` | `quarantine` |
|---|---|---|
| Sessions terminated? | Yes | No |
| FSM state changes? | Yes (`Aborted`) | No (orthogonal flag) |
| Reversible? | No | Yes (`--lift`) |
| Future intents? | Rejected (initiative is terminal) | Rejected with `SECURITY_QUARANTINED` |
| Visible in `initiative list`? | Default bucket excludes it | Default bucket excludes; `--state quarantined` shows |

When to use quarantine:

- Suspect compromise; preserve the run for forensics.
- Mid-investigation pause where you want to leave the workspace
  exactly as it is.
- Reactive policy: a CI bot triggers quarantine on a heuristic, an
  operator lifts after review.

---

## Combine — quarantine then abort

A common safety pattern is to **quarantine first, abort later**:

```bash
raxis initiative quarantine "$INIT_ID" --reason "incident: review pending"
# investigate, dump bundle, etc.
raxis initiative show "$INIT_ID" --bundle --to /tmp/incident-${INIT_ID}
# decision: cannot resume safely
raxis initiative abort "$INIT_ID"
```

---

## Common errors

| Symptom | Fix |
|---|---|
| `abort: initiative not found` | Wrong UUID. `raxis initiative list --state all`. |
| `abort: initiative already terminal` | Already `Aborted` / `Completed` / `Rejected`. |
| `quarantine: already quarantined` | Idempotent in normal flow; if you're scripting, swallow. |
| `quarantine --lift: not currently quarantined` | Same — idempotent. |
| `OPERATOR_NOT_AUTHORIZED` | Cert lacks `AbortInitiative` / `QuarantineInitiative` in `permitted_ops`. |

---

## Reference

| Command | Purpose |
|---|---|
| `raxis initiative list --state quarantined` | List frozen initiatives. |
| `raxis initiative show <id>` | Inspect quarantine reason and FSM state. |
| `raxis log <initiative_id>` | Audit events including the abort/quarantine entry. |
| `raxis operator quarantine-plans-by <signer_kid>` | Bulk quarantine: every initiative whose plan was signed by `<signer_kid>`. |

---

## Variations

- **Bulk quarantine by signer.** A leaked operator key is detected;
  freeze every initiative they signed:
  `raxis --operator-key <pem> operator quarantine-plans-by <signer_kid> --reason "key compromise"`.
- **Auto-quarantine on egress drift.** Cron parses the audit log for
  `EgressViolation` events and quarantines the offending initiative.
- **Lift after fix.** Once the suspicious change is addressed,
  `raxis initiative quarantine <id> --lift` resumes new intents.
- **Capacity recovery.** `abort` immediately frees the lane's
  active-task slot; useful when waiting out the natural completion
  is slow.

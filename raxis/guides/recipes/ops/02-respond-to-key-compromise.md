# Respond to a suspected operator-key compromise

> **Topic:** Operations | **Time to read:** ~5 min | **Complexity:** ⭐⭐⭐ Advanced

A break-glass runbook. Run when you suspect an operator's private
key has leaked. The order matters: every step is designed to stop
new damage and preserve forensic evidence without destroying it.

---

## Decision tree (read first)

1. **Is the kernel running?** If yes, you can use the CLI.
   If no, restart it first (`systemctl start raxis-kernel`).
2. **Do you have a separate operator key with full
   `permitted_ops`?** If yes, use that for the response. If no,
   use `cert mint-emergency` from the genesis key (or the most
   privileged key you still trust).
3. **Has the suspected-compromised key been used in the last hour?**
   `raxis log --kind OperatorAction --since 1h --json | jq -c 'select(.payload.signer_kid == "<suspect_kid>")'`.
   The output drives the urgency.

---

## Steps

### 1. Snapshot the audit chain (FIRST)

```bash
DATE=$(date -u +%Y%m%dT%H%M%SZ)
mkdir -p /tmp/incident-$DATE
cp -a "$RAXIS_DATA_DIR"/audit /tmp/incident-$DATE/audit
cp -a "$RAXIS_DATA_DIR"/policy /tmp/incident-$DATE/policy
cp -a "$RAXIS_DATA_DIR"/kernel.db   /tmp/incident-$DATE/kernel.db
```

This captures evidence before any further changes.

### 2. Revoke the suspected cert

Pick a trusted operator key (NOT the suspected one). Use
`cert mint-emergency` if you don't have a normal trusted key.

```bash
raxis --operator-key /tmp/safe-genesis.key cert revoke /path/to/suspect.cert.toml \
  --reason compromise \
  --reference incident-2026-05
# Expected: signed revocation written under <data-dir>/revocations/.
```

Effect:

- New plans signed with the suspected key are rejected.
- Sessions whose chain lands on the kid get `StaleOnNextUse`
  delegations.

### 3. Bulk-quarantine in-flight initiatives

```bash
raxis --operator-key /tmp/safe-genesis.key operator quarantine-plans-by <suspect_kid> \
  --reason "key compromise: investigation pending"
# Expected: N initiatives quarantined.
```

Effect:

- Every initiative whose plan was signed by the suspect kid is
  frozen (sessions left running, but new intents rejected).
- `raxis initiative list --state quarantined` shows the population.

### 4. Revoke active sessions linked to compromised work

```bash
raxis sessions --json \
  | jq -r '.active_sessions[] | select(.signer_kid == "<suspect_kid>") | .session_id' \
  | while read SID; do
      raxis session revoke "$SID"
    done
```

This kills the live planner sessions that the attacker could be
controlling.

### 5. Verify the audit chain is intact

```bash
raxis verify-chain
# Expected: Chain integrity: OK
```

If `FAIL`, the audit chain itself was tampered with. Stop, treat
the system as fully compromised, restore from offline backup.

### 6. Capture forensic bundle for the suspected initiatives

```bash
raxis initiative list --state quarantined --json \
  | jq -r '.[].initiative_id' \
  | while read INIT; do
      raxis initiative show "$INIT" --bundle --to /tmp/incident-$DATE/bundles/$INIT
      raxis log "$INIT" --json > /tmp/incident-$DATE/logs/$INIT.jsonl
    done
```

### 7. Rotate other potentially-compromised secrets

If the same attacker had the operator key, they may have had
access to other secrets:

```bash
# Rotate every credential.
raxis credential list --json | jq -r '.[].id' \
  | while read CID; do
      echo "Rotate $CID manually with raxis credential rotate ..."
    done

# Rotate sibling operator certs that share the same operator's
# physical access (e.g., same laptop).
```

### 8. Investigate

With the audit snapshot, walk:

```bash
raxis log --kind SessionMinted --since 24h --json | jq -c 'select(.payload.signer_kid == "<suspect_kid>")'
raxis log --kind CredentialUsed --since 24h --json | jq -c 'select(.session_id as $s | <suspect_session_ids> | index($s))'
raxis log --kind SecurityViolation --since 24h
```

Build a timeline. Identify:

- Earliest signed action by the suspect kid.
- Credentials accessed by suspect sessions.
- Egress requests by suspect sessions (`raxis log --kind EgressRequest`).
- Files written by suspect sessions
  (`raxis log --kind FileWrite --json`).

### 9. Decide: lift quarantine or abort

For each quarantined initiative:

- If the investigation shows the work is unaffected, lift
  quarantine: `raxis initiative quarantine <id> --lift`.
- If contaminated, abort: `raxis initiative abort <id>`. This frees
  lane budgets.

### 10. Post-mortem

- Archive `/tmp/incident-$DATE/` immutably (S3 Object Lock,
  off-site backup).
- Document the root cause and remediation in your incident-tracking
  system.
- Schedule a follow-up cert-rotation drill and update playbooks.

---

## What NOT to do

- **Do not** delete `audit/` segments. They are append-only forensic
  evidence; rotation is fine, deletion is not.
- **Do not** stop the kernel before revoking the cert. A running
  kernel rejects revoked-cert intents immediately; a stopped
  kernel buys you nothing and stops the audit chain from
  capturing the response actions.
- **Do not** rotate every cert simultaneously. Rotate the suspect
  first, then triage other certs. Bulk rotation amplifies the
  blast radius if your trusted key is also compromised.

---

## Reference

| Command | Purpose |
|---|---|
| `raxis cert revoke <cert.toml> --reason compromise --reference <id>` | Revoke the compromised cert. |
| `raxis cert mint-emergency` | Break-glass cert if no trusted key. |
| `raxis --operator-key <pem> operator quarantine-plans-by <kid>` | Bulk quarantine. |
| `raxis session revoke <id>` | Kill a live session. |
| `raxis verify-chain` | Audit-chain integrity. |
| `raxis initiative show --bundle --to <dir>` | Forensic export. |

---

## Variations

- **Compromise of genesis key.** Even worse: you need to mint a
  new genesis cert from a backup of the genesis key (you should
  have one offline). If no backup, the install is effectively
  burned and you must rebuild from scratch.
- **Tampered audit chain.** Stop the kernel, restore `audit/`
  from snapshot, rerun `verify-chain` to confirm. Treat
  any audit data after the tampering point as untrusted.
- **Key compromise in CI.** Disable the CI bot's runner, revoke
  its cert, mint a new one, redeploy with the new key. Don't
  share the runner across compromised workloads.

# Run a Raxis incident post-mortem

> **Topic:** Operations | **Time to read:** ~3 min | **Complexity:** ⭐⭐ Intermediate

A structured post-mortem template for any Raxis incident. Pulls
forensic evidence from the audit chain, reconstructs the timeline,
and lands on actionable follow-ups. Self-contained — no live
service required, only the audit-chain snapshot.

---

## When to run

- Any `SecurityViolation` event.
- Any `EscalationRaised` whose decision led to an aborted
  initiative.
- Any cluster of `ReconciliationGap` events.
- Any operator-triggered `cert revoke` or
  `operator quarantine-plans-by`.
- Any kernel crash (process terminated unexpectedly).
- Any user-visible outage (e.g., gateway down for > N minutes).

---

## Pre-work: capture forensic evidence

Within the first 30 minutes of the incident:

```bash
DATE=$(date -u +%Y%m%dT%H%M%SZ)
INCIDENT_DIR=/tmp/incident-$DATE
mkdir -p $INCIDENT_DIR

# 1. Audit chain snapshot.
sudo cp -a "$RAXIS_DATA_DIR/audit" $INCIDENT_DIR/

# 2. Kernel db snapshot.
sqlite3 "$RAXIS_DATA_DIR/kernel.db" ".backup '$INCIDENT_DIR/kernel.db'"

# 3. Active policy.
sudo cp -a "$RAXIS_DATA_DIR/policy" $INCIDENT_DIR/

# 4. Recent gateway and kernel logs.
sudo journalctl -u raxis-kernel  --since "2 hours ago" > $INCIDENT_DIR/kernel.log
sudo journalctl -u raxis-gateway --since "2 hours ago" > $INCIDENT_DIR/gateway.log

# 5. Status snapshots.
raxis status        --json > $INCIDENT_DIR/status.json
raxis doctor        --json > $INCIDENT_DIR/doctor.json
raxis providers status --json > $INCIDENT_DIR/providers.json
raxis budget        --json > $INCIDENT_DIR/budget.json
raxis sessions      --json > $INCIDENT_DIR/sessions.json
raxis escalations   --json > $INCIDENT_DIR/escalations.json
raxis initiative list --state all --json > $INCIDENT_DIR/initiatives.json

tar czf $INCIDENT_DIR.tar.gz $INCIDENT_DIR
```

This is non-destructive; the kernel keeps running.

---

## Reconstruct the timeline

### 1. Identify the incident window

```bash
# When did the SecurityViolation / first symptom appear?
raxis --data-dir "$INCIDENT_DIR" log --json --limit 0 \
  | jq -c 'select(.event_kind == "SecurityViolation") | {seq, emitted_at, payload}' \
  | head -5

# What was happening just before?
raxis --data-dir "$INCIDENT_DIR" log --json --limit 0 \
  | tail -200 > $INCIDENT_DIR/audit-tail.jsonl
```

Pin `SEQ_START` and `SEQ_END` from the event `seq` values.

### 2. Filter to the incident window

```bash
jq -c "select(.seq >= $SEQ_START and .seq <= $SEQ_END)" \
   $INCIDENT_DIR/audit-tail.jsonl > $INCIDENT_DIR/window.jsonl

# Audit-event histogram:
jq -r '.event_kind' $INCIDENT_DIR/window.jsonl | sort | uniq -c | sort -rn
```

A typical incident window has:

```text
   1421 IntentReceived
    873 IntentApplied
    512 WitnessRecorded
     45 SecurityViolation                <-- the cluster
     12 EscalationRaised
      4 InitiativeAborted
      2 ReconciliationGap
      1 OperatorRevoked
```

### 3. Identify affected initiatives

```bash
jq -r 'select(.event_kind == "SecurityViolation") | .initiative_id' \
   $INCIDENT_DIR/window.jsonl | sort -u
```

For each, pull a per-initiative narrative:

```bash
for INIT in $(jq -r 'select(.event_kind == "SecurityViolation") | .initiative_id' $INCIDENT_DIR/window.jsonl | sort -u); do
  echo "=== $INIT ==="
  jq -c "select(.initiative_id == \"$INIT\")" $INCIDENT_DIR/window.jsonl > $INCIDENT_DIR/init-$INIT.jsonl
  raxis explain $(jq -r '.task_id' $INCIDENT_DIR/init-$INIT.jsonl | head -1) > $INCIDENT_DIR/explain-$INIT.txt
done
```

### 4. Identify the trigger

Most incidents fall into one of:

| Pattern | Likely trigger |
|---|---|
| Cluster of `EgressDenied` for a single host | A planner's prompt referenced an unanticipated host. |
| `CredentialUsed` immediately followed by `OperatorRevoked` | Reactive cert revoke after suspected key leak. |
| `ReconciliationGap` cluster around a kernel restart | Kernel crash; partial-write recovery left orphans. |
| `EscalationRaised` rate spike | Lineage looping; rate limit kicked in. |
| `LaneAdmissionRejected` cluster | Lane budget overspend or capacity floor. |
| `PolicyEpochAdvanced` followed by `SECURITY_QUARANTINED` | A policy edit revoked an in-flight delegation. |

### 5. Verify chain integrity

```bash
raxis verify-chain --audit-dir "$INCIDENT_DIR/audit"
# Expected: Chain integrity: OK
```

If `FAIL`, the audit chain itself was tampered or corrupted; that
becomes a parallel investigation.

---

## The post-mortem document

Use this template:

```markdown
# Incident <YYYY-MM-DD>: <one-line summary>

## TL;DR
- What happened: <one paragraph>
- Impact: <one paragraph>
- Root cause: <one paragraph>
- Resolution: <one paragraph>

## Timeline (UTC)
- T_START - first event
- ...
- T_END   - incident resolved

## Detection
- How was it noticed? (alert, operator, complaint)

## Root cause
- Detailed walk through the events. Reference specific audit lines
  by `seq` so anyone can replay against the snapshot.

## Impact
- Initiatives aborted: list
- Initiatives quarantined: list
- Sessions revoked: count
- Cost: <USD>
- Customer-visible: yes/no

## What went well
- <bullets>

## What went poorly
- <bullets>

## Action items
- [ ] (owner) ... by <date>
- [ ] (owner) ... by <date>

## Forensic snapshot
- Path: $INCIDENT_DIR.tar.gz
- sha256: <sum>
- Archive uploaded: yes (s3://...)
```

---

## Action-item patterns

Common follow-ups:

- **Detection gaps** — add a missing alert (e.g., on
  `EgressDenied` rate > N/min).
- **Policy hardening** — tighten a lane's
  `[host_capacity].cpu_high_water_pct` so the watchdog reaps
  earlier.
- **Plan template changes** — every plan now must include
  `[[tasks.verifiers]]` for `pre_admit` linting.
- **Runbook update** — capture the new pattern into the relevant
  recipe (e.g., "for this gap_kind, run X").
- **Operator training** — walk the team through the timeline.

---

## Reference

| Command | Purpose |
|---|---|
| `raxis log <id> --json` | Audit slice. |
| `raxis explain <task_id>` | Per-task narrative. |
| `raxis verify-chain [--audit-dir <path>]` | Audit-chain integrity. |
| `raxis doctor` | Aggregate health check. |
| `jq` | Audit-chain analysis. |

---

## Variations

- **Live incident channel.** Stream `raxis log --follow --kind SecurityViolation`
  into Slack or pagerduty during the incident; freeze the channel
  for the post-mortem.
- **Pre-mortem drill.** Quarterly: simulate an incident, run the
  post-mortem template, identify gaps in the runbook.
- **Compliance-grade post-mortem.** Sign the post-mortem document
  with `raxis auth sign` and archive alongside the forensic
  snapshot for audit attestation.
- **Cross-team post-mortem.** When the trigger spans Raxis and
  other systems, capture the audit chain alongside the other
  systems' logs in a unified incident folder.

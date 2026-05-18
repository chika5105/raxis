# Handle a `ReconciliationGap` audit event

> **Topic:** Operations | **Time to read:** ~3 min | **Complexity:** ⭐⭐⭐ Advanced

A `ReconciliationGap` event means the kernel itself detected an
inconsistency between two derived views of the same state — e.g.,
`subtask_activations` says a task is Active but `tasks` shows it
Completed. This is a self-reported bug or a partial-write window;
either way it needs investigation.

---

## What it means

The kernel reconciles durable state during boot and selected recovery
paths. If a derived index disagrees with the audit chain or a
kernel-owned table, an `AuditEventKind::ReconciliationGap` is emitted
with the conflicting data and a `gap_kind` tag.

Common `gap_kind` values:

| `gap_kind` | Likely cause |
|---|---|
| `subtask_activation_orphan` | An activation row exists for a non-existent task. |
| `task_session_mismatch` | A task references a session that no longer exists. |
| `lane_budget_drift` | The cached lane spend doesn't equal the sum of admitted tasks. |
| `delegation_session_orphan` | A delegation references a missing session. |
| `verifier_witness_mismatch` | A witness blob's stored sha doesn't equal the recomputed sha. |
Reconciliation gaps are warning-level until they cluster or block a
plan, at which point they're a blocker. Treat repeated gaps as a
production bug until proven otherwise.

---

## Steps

### 1. Pull the gap event

```bash
raxis log --kind ReconciliationGap --since 24h --json
# Output: JSONL rows with payload.gap_kind, payload.detail.
```

For one specific gap:

```bash
raxis log --kind ReconciliationGap --since 24h --json \
  | jq -c 'select(.payload.gap_kind == "task_session_mismatch")'
# Output:
# {
#   "emitted_at": 1778432400,
#   "payload": {
#     "gap_kind": "task_session_mismatch",
#     "task_id": "implementer-2025-05-10",
#     "expected_session_id": "91a7c83f...",
#     "actual_session_id": null
#   }
# }
```

### 2. Reproduce locally

For most gaps, the kernel can be queried directly:

```bash
raxis inspect implementer-2025-05-10 --json
# Look at: task state, assigned_session_id, gate witnesses, recent events.
raxis explain implementer-2025-05-10
# Expected: the narrative matches the gap payload.
```

This confirms the gap reflects current state.

### 3. Investigate root cause

Walk the audit chain backwards from the gap event:

```bash
raxis log --json --since 1h \
  | jq -c 'select(.task_id == "implementer-2025-05-10") | {seq, emitted_at, event_kind}'
```

Look for:

- A `SessionEnded` for `91a7c83f` followed by no `SessionMinted`
  for the task.
- A `TaskStarted` event without a corresponding `SessionMinted`.
- A `WitnessRecorded` that didn't update the witness store.

Most root causes are one of:

- A previous kernel version had a bug; the upgrade left orphan
  state.
- A crash mid-write (kernel killed between an audit-segment append
  and `kernel.db` index update). Recovery is automatic on next
  start but may leave the gap.
- Operator manually edited `kernel.db`. Don't do this.

### 4. Decide: heal, abort, or escalate

#### Abort

If the gap is around an in-flight task and you can't determine
what's going on, abort:

```bash
raxis task abort implementer-2025-05-10
# OR
raxis initiative abort <init_id>
```

There is no general-purpose public reconcile-fix CLI today.
Recovery reconciliation runs at kernel boot, and operator
remediation should happen through audited task/initiative control
commands.

#### Escalate (file an upstream issue)

Capture forensic evidence:

```bash
DATE=$(date -u +%Y%m%dT%H%M%SZ)
mkdir -p /tmp/recon-$DATE
raxis log --kind ReconciliationGap --since 7d --json > /tmp/recon-$DATE/gaps.json
raxis log --kind PolicyEpochAdvanced --since 7d --json > /tmp/recon-$DATE/policy.json
raxis verify-chain > /tmp/recon-$DATE/verify.txt
raxis doctor --json > /tmp/recon-$DATE/doctor.json
sqlite3 "$RAXIS_DATA_DIR/kernel.db" "PRAGMA integrity_check;" > /tmp/recon-$DATE/integrity.txt

tar czf /tmp/recon-$DATE.tar.gz /tmp/recon-$DATE
# Attach to your upstream bug report.
```

### 5. Confirm resolution

```bash
# Wait at least 5 minutes (next reconciler cycle) and re-check.
raxis log --kind ReconciliationGap --since 5m --json | wc -l
# Expected: 0
```

---

## Common errors

| Symptom | Fix |
|---|---|
| Same gap repeats every cycle | The bug producing the gap is still active, or the affected task is still in a bad state. Capture evidence and abort the affected initiative. |
| `verify-chain FAIL` near a gap | The audit chain itself is corrupted; gaps are a downstream symptom. Restore from backup. |
| `doctor` returns clean but gaps persist | The gap may be in a derived index that `doctor` doesn't check yet. Capture evidence and file a production bug. |

---

## Reference

| Command | Purpose |
|---|---|
| `raxis log --kind ReconciliationGap` | List gap events. |
| `raxis verify-chain` | Audit-chain integrity. |
| `raxis doctor` | Aggregate health check. |
| `raxis inspect <task_id>` / `raxis explain <task_id>` | Probe specific subjects. |

---

## Variations

- **Scheduled clean state.** A weekly `raxis doctor`, paired with
  `raxis sessions --json` and a worktree audit, catches orphans
  before they manifest as gap events.
- **Forensic-first response.** For any gap on a high-trust system,
  always snapshot before aborting, quarantining, or cleaning up
  worktrees.
- **Aggregated dashboard.** `raxis log --kind ReconciliationGap`
  by `gap_kind` over time. Recurring gap_kinds indicate either a
  workload pattern or a real bug.

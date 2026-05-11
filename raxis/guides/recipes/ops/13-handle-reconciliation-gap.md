# Handle a `ReconciliationGap` audit event

> **Topic:** Operations | **Time to read:** ~3 min | **Complexity:** ⭐⭐⭐ Advanced

A `ReconciliationGap` event means the kernel itself detected an
inconsistency between two derived views of the same state — e.g.,
`subtask_activations` says a task is Active but `tasks` shows it
Completed. This is a self-reported bug or a partial-write window;
either way it needs investigation.

---

## What it means

The kernel periodically reconciles internal indexes against the
source-of-truth `audit.jsonl`. If a derived index disagrees with
the audit chain, an `AuditEventKind::ReconciliationGap` is emitted
with the conflicting data and a `gap_kind` tag.

Common `gap_kind` values:

| `gap_kind` | Likely cause |
|---|---|
| `subtask_activation_orphan` | An activation row exists for a non-existent task. |
| `task_session_mismatch` | A task references a session that no longer exists. |
| `lane_budget_drift` | The cached lane spend doesn't equal the sum of admitted tasks. |
| `delegation_session_orphan` | A delegation references a missing session. |
| `verifier_witness_mismatch` | A witness blob's stored sha doesn't equal the recomputed sha. |
| `audit_cursor_advance_skipped` | The audit-verify cursor advanced past a line that should have been verified. |

The kernel **does not** auto-correct; it logs the gap and continues
operating. Reconciliation gaps are warning-level until they cluster
or block a plan, at which point they're a blocker.

---

## Steps

### 1. Pull the gap event

```bash
raxis log --kind ReconciliationGap --since "24 hours ago" --json
# Output: array of gap events with payload.gap_kind, payload.detail.
```

For one specific gap:

```bash
raxis log --kind ReconciliationGap --since "24 hours ago" --json \
  | jq '.[] | select(.payload.gap_kind == "task_session_mismatch")'
# Output:
# {
#   "ts": "2026-05-10T17:00:00Z",
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
raxis inspect task:implementer-2025-05-10
# Look at: assigned_session_id field.
raxis inspect session:91a7c83f...
# Expected: not_found  (because expected_session_id != actual)
```

This confirms the gap reflects current state.

### 3. Investigate root cause

Walk the audit chain backwards from the gap event:

```bash
raxis log --json --since "1 hour ago" \
  | jq '.[] | select(.task_id == "implementer-2025-05-10") | {seq, ts, kind}'
```

Look for:

- A `SessionEnded` for `91a7c83f` followed by no `SessionMinted`
  for the task.
- A `TaskStarted` event without a corresponding `SessionMinted`.
- A `WitnessRecorded` that didn't update the witness store.

Most root causes are one of:

- A previous kernel version had a bug; the upgrade left orphan
  state.
- A crash mid-write (kernel killed between `audit.jsonl` append
  and `kernel.db` index update). Recovery is automatic on next
  start but may leave the gap.
- Operator manually edited `kernel.db`. Don't do this.

### 4. Decide: heal, abort, or escalate

#### Heal (reconciler subcommand, kernel-side)

For some gap_kinds, the kernel exposes a heal command:

```bash
raxis-kernel reconcile --gap-kind task_session_mismatch \
  --task-id implementer-2025-05-10 \
  --action mark_aborted \
  --reason "reconciler: session orphaned, marking task aborted"
# Output:
# action_taken: mark_aborted
# audit_event:  TaskMarkedAborted (line 7421)
```

Available actions vary by gap_kind. Run with `--help` for the
list. Each heal action writes its own audit line so the
remediation is traceable.

#### Abort

If the gap is around an in-flight task and you can't determine
what's going on, abort:

```bash
raxis task abort implementer-2025-05-10 --reason "reconciliation gap"
# OR
raxis initiative abort <init_id> --reason "reconciliation gap; resubmit"
```

#### Escalate (file an upstream issue)

Capture forensic evidence:

```bash
DATE=$(date -u +%Y%m%dT%H%M%SZ)
mkdir -p /tmp/recon-$DATE
raxis log --kind ReconciliationGap --since "7 days ago" --json > /tmp/recon-$DATE/gaps.json
raxis log --kind PolicyReloaded --since "7 days ago" --json > /tmp/recon-$DATE/policy.json
raxis verify-chain --full --json > /tmp/recon-$DATE/verify.json
raxis doctor --full-audit-verify --json > /tmp/recon-$DATE/doctor.json
sqlite3 "$RAXIS_DATA_DIR/kernel.db" "PRAGMA integrity_check;" > /tmp/recon-$DATE/integrity.txt

tar czf /tmp/recon-$DATE.tar.gz /tmp/recon-$DATE
# Attach to your upstream bug report.
```

### 5. Confirm resolution

```bash
# Wait at least 5 minutes (next reconciler cycle) and re-check.
raxis log --kind ReconciliationGap --since "5 minutes ago" --json | jq length
# Expected: 0 (or fewer than before, if pre-existing).
```

---

## Common errors

| Symptom | Fix |
|---|---|
| Same gap repeats every cycle | Heal didn't take, or the bug producing the gap is still active. Capture evidence and abort the affected initiative. |
| `reconcile: gap_kind not heal-able` | Some gap_kinds have no automatic heal; manual decision needed. |
| `verify-chain FAIL` near a gap | The audit chain itself is corrupted; gaps are a downstream symptom. Restore from backup. |
| `doctor` returns clean but gaps persist | The gap may be in a derived index that `doctor` doesn't check. Run the kernel's reconciler one-shot: `raxis-kernel reconcile --once`. |

---

## Reference

| Command | Purpose |
|---|---|
| `raxis log --kind ReconciliationGap` | List gap events. |
| `raxis-kernel reconcile [--gap-kind ...] [--action ...]` | Heal where possible. |
| `raxis verify-chain --full` | Audit-chain integrity. |
| `raxis doctor --full-audit-verify` | Aggregate health check. |
| `raxis inspect task:<id>` / `session:<id>` | Probe specific subjects. |

---

## Variations

- **Auto-heal pipeline.** A daily cron that runs the reconciler in
  a heal-able set of gap_kinds (`subtask_activation_orphan`,
  `delegation_session_orphan`); manual review for the rest.
- **Scheduled clean state.** A weekly `raxis doctor --fix-orphans`
  catches orphans before they manifest as gap events.
- **Forensic-first response.** For any gap on a high-trust system,
  always snapshot before healing. Once healed, the original
  evidence is hidden behind the heal action.
- **Aggregated dashboard.** `raxis log --kind ReconciliationGap`
  by `gap_kind` over time. Recurring gap_kinds indicate either a
  workload pattern or a real bug.

# `raxis explain`

> **Topic:** CLI | **Time to read:** ~2 min | **Complexity:** ⭐⭐ Intermediate

The "why is this task in its current state" command. `explain`
walks the audit chain for one task and produces a compact human
narrative: every state transition, every decision, the reason or
witness behind it, and the next blocker (if any).

---

## Syntax

```text
raxis explain <task_id> [--json] [--max-events N]
```

---

## What you get

```bash
raxis explain code_reviewer-2025-05-10
# Output:
# task: code_reviewer-2025-05-10
# initiative: 1f3c8a4b ("Add rate limiting")
# agent_type: Reviewer
#
# 2026-05-10T17:30:00Z  Created
#   reason: admitted from plan-bundle 1f3c8a4b at policy epoch 7
#
# 2026-05-10T17:30:01Z  PredecessorsSatisfied
#   predecessors: [implementer]  (last completed at 17:30:00Z)
#
# 2026-05-10T17:30:01Z  SessionMinted
#   session_id: 91a7c83f...
#   agent_type: Reviewer
#   worktree:   /var/raxis/worktrees/9c41.../tasks/code_reviewer
#
# 2026-05-10T17:30:02Z  Active
#   provisioning ok; awaiting first intent from session 91a7c8...
#
# 2026-05-10T17:31:14Z  WitnessRecorded
#   verifier:   review-checks
#   witness:    7f880c2e...
#   verdict:    pass
#
# 2026-05-10T17:31:15Z  ReviewSubmitted
#   verdict:    Approved
#
# 2026-05-10T17:31:15Z  Completed
#   reason:     all reviewers approved (panel of 1)
#
# Final state: Completed (no further action needed)
```

For a stuck or failed task you'll see the blocker called out:

```text
2026-05-10T17:33:00Z  ReviewSubmitted
  verdict:  Rejected
  critique: "missing test for empty input"
  review_reject_count: 1

2026-05-10T17:33:00Z  PausedForRevision
  reason: orchestrator must decide between RetrySubTask and Escalate

Final state: Paused (waiting on Orchestrator decision)
```

For an escalation:

```text
2026-05-10T17:33:00Z  EscalationRaised
  escalation_id: e8a5...
  reason: "Cannot decide: ambiguous spec line 42"

Final state: Paused (waiting on operator approve/deny)
Resolve with:  raxis escalation approve e8a5... --scope <capability_class> --max-uses 1 --valid-for 3600
              raxis escalation deny    e8a5... --reason "..."
```

---

## JSON form

For tooling, `--json` returns the structured event sequence:

```bash
raxis explain code_reviewer-2025-05-10 --json | jq '.events[] | .kind'
```

---

## Common errors

| Symptom | Fix |
|---|---|
| `explain: task not found` | Wrong id; `raxis initiative show <id> --with-tasks`. |
| `explain: task has no events` | The task was created but the kernel hasn't advanced beyond admission yet. Wait a moment. |
| Empty narrative for a known active task | The audit log might be ahead of the read cursor; rerun. |

---

## Reference

| Command | Purpose |
|---|---|
| `raxis log <initiative_id>` | Full audit chain (raw). |
| `raxis inspect <task_id>` | Task deep-dive (FSM + sessions + witnesses). |
| `raxis task outputs <id>` | Witness blobs the task produced. |
| `raxis escalations` | Pending escalations across all initiatives. |

---

## Variations

- **First triage step.** Whenever a task is stuck, `raxis explain`
  is the shortest path to "where do I look next". Most outputs end
  with a recommended next CLI invocation.
- **Pre-approval review.** Before `escalation approve`, run
  `explain <task_id>` to see the full lead-up and decide if
  approval makes sense.
- **CI artifact.** A failed CI deploy can attach `raxis explain`
  outputs for every failed task; useful in PR comments.
- **Diff two runs.** `explain` two task ids from different runs of
  the same plan to see where they diverged.

# Investigate a stuck task

> **Topic:** Operations | **Time to read:** ~4 min | **Complexity:** ⭐⭐ Intermediate

Step-by-step triage when a task seems wedged. Start broad, narrow
down, then act. Aimed at on-call operators who don't yet know the
codebase deeply.

---

## What "stuck" can mean

- The task FSM hasn't advanced for an unusually long time.
- The task is `Active` but no audit events for N minutes.
- The task is `Paused` and the operator doesn't know why.
- The task is `Created` but `SessionMinted` never fired.
- The task hit `BLOCKED` in the queue (lane budget / capacity).

Each has a different root cause; the steps below disambiguate.

---

## Steps

### 1. Get the bird's-eye view

```bash
raxis explain <task_id>
```

This is almost always the right first command. The output ends
with one of:

- `Final state: Completed` → not stuck, you're looking at the
  wrong task.
- `Final state: Active (provisioning ok; awaiting first intent ...)`
  → see step 2 (active session).
- `Final state: Paused (waiting on Orchestrator decision)` → see
  step 3 (paused).
- `Final state: Paused (waiting on operator approve/deny)` → see
  step 4 (escalation).
- `Final state: Created (predecessors not satisfied)` → see step 5
  (DAG).
- The narrative ends in `Active` but with no recent events for
  several minutes → see step 6 (silent session).

### 2. Active session, but quiet

The session is alive but not making intents.

```bash
raxis sessions show <session_id>
# Look at: ttl_remaining, last_intent_at, current_intent_in_flight.
raxis log <initiative_id> --kind ProviderError --since "1 hour ago"
raxis log <initiative_id> --kind CredentialUsed --since "1 hour ago"
raxis providers status
```

Common causes:

- Provider degraded → `raxis providers status` flags it; wait or
  reset the breaker.
- Credential proxy returning errors → `raxis credential audit <id>`
  shows recent failures.
- Session in a long compute (LLM call) → `last_intent_at` was
  recent; just wait.

### 3. Paused (revision pending)

The Reviewer rejected; the Orchestrator must decide whether to
`RetrySubTask` or escalate.

```bash
raxis log <initiative_id> --kind ReviewSubmitted --since "1 hour ago"
raxis log <initiative_id> --kind RetrySubTaskRequested --since "1 hour ago"
raxis log <initiative_id> --kind EscalationRaised --since "1 hour ago"
```

Possible states:

- Orchestrator hasn't responded yet → the Orchestrator session
  itself may be stuck; recurse: `raxis explain <orchestrator_task_id>`.
- Retry was requested but the kernel didn't action it (V2.6
  follow-up) → run `raxis task retry` manually.
- Escalation was raised → see step 4.

### 4. Pending escalation

```bash
raxis escalations
raxis escalation show <esc_id>
raxis witnesses show <context_witness_sha>
```

Decide: approve with guidance, or deny. See
[`cli/16-escalation-approve-deny`](../cli/16-escalation-approve-deny.md).

### 5. Created (DAG-blocked)

The task is waiting on predecessors.

```bash
raxis explain <task_id> | grep -A 1 "predecessors"
# Pull the predecessor IDs.

# Inspect each predecessor.
raxis explain <pred_task_id>
```

If the predecessor is also stuck, recurse into this same runbook
on it.

If the predecessor is `Aborted`, the dependent will never run; you
need to abort the dependent or resubmit the plan with a different
DAG.

### 6. Silent session (no events for N minutes)

The session is alive but produced no audit lines.

```bash
raxis sessions show <session_id> | grep ttl_remaining
ps -p <session_pid>     # confirm the OS process is alive
# If isolated in a microVM, look at the VM's metrics in your
# observability stack.
```

Common causes:

- LLM call in flight (long).
- Credential proxy hung (rare; the proxy has its own timeouts).
- The session is doing local computation that doesn't yet
  produce an intent (rare; sessions emit intents frequently).

If the session is truly hung:

```bash
raxis session revoke <session_id> --reason "investigation: hang"
# If the task should be retried:
raxis task retry <task_id>
```

### 7. BLOCKED in the queue

```bash
raxis queue --state blocked
# Look at the row's "block reason" column: budget_exhausted,
# host_capacity_floor, no_image_available, etc.
```

Causes:

- `budget_exhausted` → wait for epoch advance, or
  `raxis epoch advance --reason "manual: unblock test"`.
- `host_capacity_floor` → free capacity (kill rogue processes,
  raise `[host_capacity]` floor).
- `no_image_available` → the verifier or VM image isn't installed
  yet; check `raxis verifiers` and `[[vm_images]]` in policy.

---

## Decision: act, wait, or escalate

After the triage above, you typically choose:

| Situation | Action |
|---|---|
| Provider degraded | Wait (auto-retry) or `raxis providers reset`. |
| Pending escalation | `raxis escalation approve/deny`. |
| Hung session | `raxis session revoke`, then `raxis task retry`. |
| DAG blocked by aborted predecessor | `raxis task abort <task>` and resubmit a new plan. |
| Budget-exhausted lane | `raxis epoch advance` or wait for natural rollover. |
| Schema or kernel-state corruption | Stop kernel, restore from backup. |

When in doubt: take a forensic snapshot
(`raxis initiative show <id> --bundle --to /tmp/...`,
`raxis log <id> --json > /tmp/.../log.jsonl`) **before** any
remediation action.

---

## Common errors

| Symptom | Fix |
|---|---|
| `explain: task has no events` | Wait a few seconds; the kernel may be mid-write. |
| `sessions show: not found` | The session has already ended; `raxis log <init> --kind SessionEnded` for the closing event. |
| `task retry: parent initiative is terminal` | The initiative has already finished; resubmit a fresh plan. |
| `queue: no row for <task_id>` | The task is in a non-runnable state. Use `explain` instead. |

---

## Reference

| Command | Purpose |
|---|---|
| `raxis explain <task_id>` | Decision-tree narrative. |
| `raxis log <initiative_id>` | Raw audit chain. |
| `raxis sessions show <id>` / `inspect session:<id>` | Session detail. |
| `raxis escalations` | Pending human-in-loop. |
| `raxis queue` | Scheduler view. |
| `raxis providers status` | LLM gateway health. |
| `raxis credential audit <id>` | Credential-use history. |

---

## Variations

- **Self-service runbook.** A plan that, when stuck, exposes a
  pre-canned guidance string in the escalation; the operator can
  approve verbatim.
- **Auto-recovery.** A cron that finds tasks `Active` for > N
  minutes with no recent audit events and `task retry` them.
- **Triage-only readonly access.** Operators with a cert that has
  only `ReadAudit` and `ReadInitiative` can run all triage
  commands without write authority.
- **Post-mortem template.** For every stuck-task incident,
  capture the `explain` output + relevant log slice; build up a
  pattern library for recurring failure modes.

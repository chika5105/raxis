# `raxis task abort`, `task resume`, `task retry`, `task outputs`

> **Topic:** CLI | **Time to read:** ~3 min | **Complexity:** ⭐⭐ Intermediate

Per-task surgery commands. These let you act on a single task
inside a running initiative without disturbing the rest.

---

## Syntax

```text
raxis task abort   <task_id>
raxis task resume  <task_id>
raxis task retry   <task_id>
raxis task outputs <task_id> [--json]
```

---

## task abort — terminate one task

Stops the session running this task. The task FSM transitions to
`Aborted`. Successors stay blocked (DAG order is enforced; an
aborted predecessor never satisfies the predecessor list).

```bash
raxis task abort code_reviewer-2025-05-10
# Output:
# Task code_reviewer-2025-05-10 aborted. New state: Aborted
```

Differences vs `initiative abort`:

| | `task abort` | `initiative abort` |
|---|---|---|
| Scope | One task only | All tasks in the initiative |
| Successors | Blocked but not aborted | All terminated |
| Initiative state | Unchanged | `Aborted` |

If aborting the task makes the initiative un-progressable (e.g., it
has no Reviewer left to advance), the initiative typically lands in
the human-escalation surface; investigate via `raxis explain <task>`
and `raxis escalations`.

---

## task resume — un-pause a paused task

Some failure paths leave a task in `Paused` state (e.g., budget
exhausted while waiting for an epoch advance, manual operator
pause). `task resume` clears the pause flag and the scheduler picks
the task up again.

```bash
raxis task resume code_reviewer-2025-05-10
# Output:
# task_id:  code_reviewer-2025-05-10
# state:    Active
```

If the task is not currently paused, the command is a no-op and
returns `task not paused`.

---

## task retry — re-run a failed task

For tasks that terminated on a recoverable failure (e.g., a verifier
crashed mid-run, an LLM provider 5xx'd through the proxy retries),
`task retry` mints a fresh session and re-issues `Provisioned`.

```bash
raxis task retry implementer-2025-05-10
# Output:
# task_id:        implementer-2025-05-10
# new_session_id: 91a7c83f...
# state:          Active
```

Caveats:

- `task retry` does **not** reset the parent initiative's FSM. If
  the initiative has already transitioned to `Aborted` /
  `Completed`, retry is rejected.
- Retry consumes a slot from the lane's `max_concurrent_tasks`.
- The kernel charges the new session against the same plan budget
  (`max_cost_per_task`); a near-exhausted budget will immediately
  fail-closed.

---

## task outputs — show artifacts the task produced

Lists all witness blobs and patch artifacts a task emitted, along
with their content addresses (sha256). Read-only.

```bash
raxis task outputs implementer-2025-05-10
# Output:
# WITNESS                 SHA_PREFIX  KIND          BYTES
# rg-pre-commit-1         3a2c01ff    rg            812
# cargo-test-1            7f880c2e    cargo-test    11403
# cargo-test-2            7f880c2e    cargo-test    11403   (cached)
#
# PATCHES
# implementer.diff        41bf09cc    git-diff      2104

raxis task outputs implementer-2025-05-10 --json | jq '.witnesses'
```

Use this to:

- Verify a witness exists before promoting an initiative.
- Pull the sha into `raxis witnesses show <sha>` for replay.
- Re-fetch the patch bytes for forensic review.

---

## Common errors

| Symptom | Fix |
|---|---|
| `task abort: task already terminal` | Already `Completed` / `Aborted`. Check `raxis explain <task_id>`. |
| `task resume: task not paused` | The task is already running or terminal — no-op. |
| `task retry: parent initiative is terminal` | You can't retry a task whose initiative is `Aborted` / `Completed`. Submit a new plan if you need to redo the work. |
| `task outputs: no outputs yet` | Task hasn't emitted any witnesses or patches. Verify with `raxis explain <task_id>`. |

---

## Reference

| Command | Purpose |
|---|---|
| `raxis explain <task_id>` | Why this task is in its current state. |
| `raxis log <initiative_id>` | Audit events for the initiative. |
| `raxis witnesses show <sha>` | Inspect a single witness blob. |
| `raxis sessions [--task <id>]` | Live sessions linked to a task. |
| `raxis escalations` | Escalation surface if the task asked for human review. |

---

## Variations

- **Forensic outputs.** Pipe `task outputs --json` into a script
  that downloads each witness blob via
  `raxis witnesses show <sha> --raw > out/<witness>.bin`.
- **Selective rerun.** A reviewer rejected; you fixed the executor's
  patch in-place; `task retry implementer` and let the new
  reviewer panel decide.
- **Pause while debugging.** Operator pauses a task in CLI tooling
  (via a future `task pause` command in V2.6); `task resume` lifts.
- **Bulk abort.** A lane went rogue; iterate
  `raxis initiative list --state all --json | jq -r '.[].initiative_id'`
  and `task abort` each suspected task.

# `predecessors` — DAG dependencies

> **Topic:** Plan reference | **Time to read:** ~3 min | **Complexity:** ⭐⭐ Intermediate

`predecessors` declares the task-level DAG. A task with
`predecessors = []` activates immediately when the initiative
starts; a task with `predecessors = ["task_a"]` activates only
after `task_a` reaches `Completed`. The kernel enforces the order;
agents cannot bypass it via IPC.

---

## Field reference

| Field | Type | Required | Effect |
|---|---|---|---|
| `predecessors` | `Vec<String>` | yes (may be empty) | List of `task_id`s that MUST reach `Completed` (Executors) or `Approved` (Reviewers) before this task activates. |

The plan-side field is named **`predecessors`** (verified against
`kernel/src/initiatives/lifecycle.rs::parse_plan_tasks`). Some
spec prose uses `depends_on` as an informal synonym; the kernel
parser only reads `predecessors`.

---

## What the kernel rejects at admission

| Pattern | Reason |
|---|---|
| `predecessors = ["self"]` (where `task_id = "self"`) | Self-loop. |
| `predecessors = ["a"]` and `predecessors of a includes self` | Cycle. |
| `predecessors = ["nonexistent"]` | Dangling reference. |
| `predecessors = ["dup", "dup"]` | Duplicate entries inside the list. |
| Reviewer with `predecessors = []` | Reviewers must review someone. |
| Reviewer's predecessor is a Reviewer (not an Executor) | Reviewers don't review Reviewers. |

`raxis plan validate` catches every one of these locally.

---

## Examples

### Linear chain

```toml
[[tasks]]
task_id      = "design"
predecessors = []

[[tasks]]
task_id      = "implement"
predecessors = ["design"]

[[tasks]]
task_id      = "test"
predecessors = ["implement"]
```

`design` runs first; `implement` activates after `design.Completed`;
`test` activates after `implement.Completed`.

### Fan-out + fan-in

```toml
[[tasks]]
task_id      = "shared_setup"
predecessors = []

[[tasks]]
task_id      = "frontend"
predecessors = ["shared_setup"]

[[tasks]]
task_id      = "backend"
predecessors = ["shared_setup"]

[[tasks]]
task_id      = "integration_test"
predecessors = ["frontend", "backend"]   # waits for BOTH
```

`integration_test` activates only after BOTH `frontend` and
`backend` reach `Completed`. Multiple predecessors imply
logical-AND.

### Panel review

```toml
[[tasks]]
task_id      = "implementer"
predecessors = []

[[tasks]]
task_id      = "reviewer_correctness"
predecessors = ["implementer"]

[[tasks]]
task_id      = "reviewer_style"
predecessors = ["implementer"]

[[tasks]]
task_id      = "reviewer_security"
predecessors = ["implementer"]
```

All three Reviewers activate in parallel after the Executor
completes. The kernel waits for all three before deciding the merge
verdict (logical-AND across `verdict`).

---

## How activation propagates

```text
admission:
  └─ Find tasks with predecessors = [].
       └─ Mint an Activate intent for each.

executor completes (writes files, submits CompleteTask):
  └─ Kernel transitions task to Completed.
       └─ Find tasks where this task is a predecessor.
            └─ For each, check if ALL predecessors are Completed.
                 └─ If yes: mint an Activate intent for that task.
                 └─ If no:  task stays Admitted.
```

The same logic applies for Reviewer dependencies, except a Reviewer
"completes" only on `verdict = Approve`. A `Reject` keeps the
downstream tasks blocked; the kernel waits for the Executor to
re-submit (rejection retry loop) and the Reviewer to re-evaluate.

---

## Common failure modes

| Symptom | Fix |
|---|---|
| `FAIL_DAG_CYCLE` | Self-loops or cycles between two+ tasks. Inspect with `raxis plan validate`; the validator names the offending edge. |
| `FAIL_DAG_DANGLING_PREDECESSOR` | A predecessor `task_id` doesn't exist in the plan. Spelling check. |
| `FAIL_DAG_DUPLICATE_PREDECESSOR` | List contains the same `task_id` twice. Deduplicate. |
| Task never activates | Some predecessor is stuck (Failed, Aborted, BlockedRecoveryPending). `raxis explain <task>` shows which predecessor is unsatisfied. |
| Reviewer activates and immediately rejects "no commit" | The predecessor Executor's `CompleteTask` was for a no-op (no diff). The Reviewer has nothing to review. |

---

## Reference: relevant CLI

| Command | Purpose |
|---|---|
| `raxis plan validate <plan.toml>` | Catches every DAG constraint above. |
| `raxis explain <task_id>` | Decision tree explaining why a task is in its current state, including unsatisfied predecessors. |
| `raxis queue` | DAG scheduler view: READY (Admitted+GatesPending) and BLOCKED (BlockedRecoveryPending). |
| `raxis log --kind PredecessorCompleted --since 1h` | Audit trail of dependency satisfaction. |

---

## Variations

- **Implicit serialisation.** A single chain
  (`A → B → C → D`) — each step inherits the previous step's
  worktree state via the Orchestrator's bundle hand-off.
- **Maximum parallelism.** Many tasks with `predecessors = []`
  activate at once, bounded by the lane's
  `max_concurrent_tasks`.
- **Conditional fan-in (V3).** Today, multi-predecessor is logical-AND
  only. "OR-style" predecessors (any one satisfies) and conditional
  predecessors (run only if X passed) are out of scope for V2.

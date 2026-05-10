# RAXIS V2 Orchestration — End-to-End Explained

## What is V2 orchestration?

V2 introduces **hierarchical multi-agent coordination**. Instead of one agent doing everything, the operator defines a DAG of tasks:
- An **Orchestrator** coordinates the work
- **Executors** write the code
- **Reviewers** review the code

The kernel enforces the DAG ordering, the role boundaries, and the retry limits.

---

## Step 1: Operator Defines the Task DAG

```toml
[[tasks]]
task_id = "orchestrate"
agent_type = "Orchestrator"
lane_id = "feature-work"

[[tasks]]
task_id = "implement"
agent_type = "Executor"
lane_id = "feature-work"
depends_on = ["orchestrate"]

[[tasks]]
task_id = "review"
agent_type = "Reviewer"
lane_id = "feature-work"
depends_on = ["implement"]
```

**In plain English:** "The orchestrator decides what to do, the executor writes the code, and the reviewer checks it. Each step must wait for the previous one."

---

## Step 2: Kernel Enforces DAG Dependencies

When the Orchestrator submits `ActivateSubTask { task_id: "implement" }`:

1. The kernel checks: is `"orchestrate"` (the predecessor) in `Completed` state?
2. If not → `DEPENDENCY_NOT_MET` → the Orchestrator must wait
3. If yes → the kernel spawns a session for the Executor

```
orchestrate ──→ implement ──→ review
   (orch)         (exec)       (rev)
```

---

## Step 3: Static Dispatch Matrix

The kernel has a compile-time table:

| Intent Kind | Orchestrator | Executor | Reviewer |
|---|---|---|---|
| `SingleCommit` | ❌ | ✅ | ❌ |
| `IntegrationMerge` | ❌ | ✅ | ❌ |
| `CompleteTask` | ❌ | ✅ | ❌ |
| `ReportFailure` | ❌ | ✅ | ❌ |
| `ActivateSubTask` | ✅ | ❌ | ❌ |
| `RetrySubTask` | ✅ | ❌ | ❌ |
| `SubmitReview` | ❌ | ❌ | ✅ |
| `StructuredOutput` | ✅ | ✅ | ❌ |

Adding a new `IntentKind` variant **breaks compilation** until a row is added to this matrix. This guarantees exhaustive role checking.

---

## Step 4: Review Loop

After the Executor completes its code:

1. Orchestrator submits `ActivateSubTask { task_id: "review" }`
2. Kernel spawns a Reviewer session with the Executor's `evaluation_sha`
3. Reviewer inspects the code diff
4. Reviewer submits `SubmitReview { approved: true/false, critique: "..." }`

### On approval:
- Task transitions to `Completed`
- Orchestrator is notified via `KernelPush::SubTaskCompleted`

### On rejection:
- Executor's task transitions to `Failed`
- Orchestrator receives `KernelPush::SubTaskFailed`
- Orchestrator can issue `RetrySubTask` (subject to retry counters)

---

## Step 5: Retry Counters

Each sub-task has two retry counters:

| Counter | What it counts | Default max |
|---|---|---|
| `crash_retry_count` | VM crashes / process exits | 3 |
| `review_reject_count` | Reviewer rejections | 2 |

When either counter exceeds its ceiling → `FAIL_INVALID_REQUEST`. The Orchestrator must report the failure to the operator.

Each retry creates a **new** `subtask_activations` row with a fresh `PendingActivation` state and incremented counter.

---

## The Full V2 Flow (Visual)

```
Operator submits plan with DAG
        │
        ▼
    Kernel spawns Orchestrator
        │
        ▼
    Orchestrator: ActivateSubTask("implement")
        │
        ├── Dependency check: predecessors completed? ✅
        │
        ▼
    Kernel spawns Executor for "implement"
        │
        ▼
    Executor: SingleCommit → IntentAdmitted
    Executor: CompleteTask → task Completed
        │
        ▼
    Orchestrator: ActivateSubTask("review")
        │
        ▼
    Kernel spawns Reviewer for "review"
    Sets review_evaluation_sha = executor's head_sha
        │
        ▼
    Reviewer: SubmitReview { approved: true }
        │
        ▼
    All tasks Completed → Initiative Completed
```

---

## Edge Cases

### 1. Executor crashes mid-work

The kernel detects the VM exit. The task transitions to `Failed`. The Orchestrator sees `SubTaskFailed { reason: "VmCrash" }` and can issue `RetrySubTask`. `crash_retry_count` increments.

### 2. Reviewer rejects the code

The Executor's task goes back to `Failed`. The Reviewer's `critique` is stored. The Orchestrator can `RetrySubTask`, and the new Executor session has the Reviewer's critique injected into its system prompt so it can fix the specific issues.

### 3. DAG has a cycle

The plan validator detects cycles at load time → `PlanError::CyclicDependency`. The plan is rejected.

### 4. Orchestrator tries to spawn a task that doesn't exist in the plan

`ActivateSubTask { task_id: "nonexistent" }` → `FAIL_INVALID_REQUEST`. Task IDs are validated against the plan at admission time.

### 5. All retry counters exhausted

The Orchestrator's `RetrySubTask` is rejected with `FAIL_INVALID_REQUEST`. The Orchestrator must issue `ReportFailure` or escalate to the operator.

---

## Key Source Files

| File | Role |
|------|------|
| `crates/types/src/intent.rs` | `IntentKind` — all 8 variants including V2 |
| `kernel/src/scheduler/dag.rs` | DAG dependency resolution |
| `kernel/src/ipc/handlers/intent.rs` | Static dispatch matrix enforcement |
| `crates/planner-core/src/driver.rs` | Role-specific prompt assembly |
| `specs/v2/v2-deep-spec.md` | V2 formal specification |

# `session_agent_type` — Executor vs Reviewer

> **Topic:** Plan reference | **Time to read:** ~3 min | **Complexity:** ⭐ Beginner

`session_agent_type` declares whether a `[[tasks]]` block is an
Executor (writes code) or a Reviewer (evaluates code). The
**Orchestrator is kernel-managed** and never declared — every plan
gets exactly one Orchestrator session, auto-spawned at admission.

---

## The three agent types (V2 §6)

| Type | Writes code | Activates sub-tasks | Submits reviews | Network |
|---|---|---|---|---|
| `Orchestrator` | ❌ | ✅ | ❌ | mediated egress |
| `Executor` | ✅ | ❌ | ❌ | mediated egress (per `allowed_egress`) |
| `Reviewer` | ❌ | ❌ | ✅ | **none** (`INV-NETISO-01`) |

In `[[tasks]]`, only `Executor` and `Reviewer` are valid. Setting
`session_agent_type = "Orchestrator"` triggers
`FAIL_ORCHESTRATOR_TASK_NOT_PERMITTED` at admission.

---

## What an Executor can do (per `dispatch_matrix.rs`)

- Write files within `path_allowlist` (commits become git objects
  in its worktree).
- Read files according to `clone_strategy`.
- Make outbound network calls to hosts in `allowed_egress` (kernel
  egress proxy).
- Use credential proxies (per `[[tasks.credentials]]`).
- Submit `SingleCommit` (per individual commit), `CompleteTask`
  (close the task), or `ReportFailure` (self-fail).
- **Cannot** submit `IntegrationMerge` (Orchestrator-only). Cannot
  submit `SubmitReview` (Reviewer-only). Cannot delegate
  (`ActivateSubTask` / `RetrySubTask` are Orchestrator-only).

## What a Reviewer can do (per `dispatch_matrix.rs`)

- Read files within its sparse worktree mount (the `path_allowlist`
  field declares the read scope today).
- Submit exactly one intent: `SubmitReview { approved: bool,
  critique }`. That is the entire authorized surface.
- **Cannot** write files. Reviewer's `/workspace` is mounted RO
  (`INV-PLANNER-HARNESS-01`).
- **Cannot** make network calls. Reviewer VMs have no network
  device (`INV-NETISO-01`).
- **Cannot** `SingleCommit`, `IntegrationMerge`, `CompleteTask`,
  `ReportFailure`, or any delegation intent.
- **Cannot** declare `vm_image` (kernel-canonical
  `raxis-reviewer-core`) — admission rejects with
  `FAIL_REVIEWER_VM_IMAGE_NOT_ALLOWED`.

## What the Orchestrator does (auto-managed; never in `[[tasks]]`)

- Activates sub-tasks per the DAG (`ActivateSubTask`).
- On `KernelPush::SubTaskFailed` may re-spawn via `RetrySubTask`
  (subject to `crash_retry_count` / `review_reject_count`
  ceilings).
- Receives Executor commit bundles and Reviewer verdicts via
  `KernelPush` (`SubTaskCompleted`, `AllReviewersPassed`,
  `ReviewRejected`).
- After `AllReviewersPassed` for a sub-task, performs the
  per-sub-task git merge in its workspace and submits
  `IntegrationMerge { commit_sha, merged_task_ids, ... }` — the
  ONLY merger in the whole system. The kernel admission pipeline
  fast-forwards the initiative's target ref on accept.
- May touch files in `cross_cutting_artifacts` (declared in the
  plan's `[orchestrator]` block) during merge regeneration.

The Orchestrator session is created at `approve_plan` admission.
You cannot declare it; declaring `session_agent_type =
"Orchestrator"` in `[[tasks]]` triggers
`FAIL_ORCHESTRATOR_TASK_NOT_PERMITTED`.

---

## Example — Executor + Reviewer

```toml
[[tasks]]
task_id            = "implementer"
prompt             = """Complete Implementer according to this plan's acceptance criteria."""
session_agent_type = "Executor"
clone_strategy     = "sparse"
path_allowlist     = ["src/auth/"]
predecessors       = []
description        = """Implement rate limiting on /auth/login."""

[[tasks]]
task_id            = "code_reviewer"
prompt             = """Complete Code Reviewer according to this plan's acceptance criteria."""
session_agent_type = "Reviewer"
clone_strategy     = "blobless"
path_allowlist     = ["src/auth/"]
predecessors       = ["implementer"]
description        = """Review src/auth/rate_limit.rs for correctness + style."""
```

## Example — multi-Executor parallel

```toml
[[tasks]]
task_id            = "frontend"
description        = "Frontend"
prompt             = """Complete Frontend according to this plan's acceptance criteria."""
session_agent_type = "Executor"
clone_strategy     = "sparse"
path_allowlist     = ["frontend/"]
predecessors       = []

[[tasks]]
task_id            = "backend"
description        = "Backend"
prompt             = """Complete Backend according to this plan's acceptance criteria."""
session_agent_type = "Executor"
clone_strategy     = "sparse"
path_allowlist     = ["backend/"]
predecessors       = []
```

Both Executors activate immediately; the auto-spawned Orchestrator
merges their commits into the target branch.

## Example — panel review

```toml
[[tasks]]
task_id            = "implementer"
clone_strategy     = "blobless"
description        = "Implementer"
prompt             = """Complete Implementer according to this plan's acceptance criteria."""
session_agent_type = "Executor"
...

[[tasks]]
task_id            = "correctness_reviewer"
clone_strategy     = "blobless"
prompt             = """Complete Correctness Reviewer according to this plan's acceptance criteria."""
session_agent_type = "Reviewer"
predecessors       = ["implementer"]
description        = """Review for correctness."""

[[tasks]]
task_id            = "style_reviewer"
clone_strategy     = "blobless"
prompt             = """Complete Style Reviewer according to this plan's acceptance criteria."""
session_agent_type = "Reviewer"
predecessors       = ["implementer"]
description        = """Review for style + idioms."""

[[tasks]]
task_id            = "security_reviewer"
clone_strategy     = "blobless"
prompt             = """Complete Security Reviewer according to this plan's acceptance criteria."""
session_agent_type = "Reviewer"
predecessors       = ["implementer"]
description        = """Review for security."""
```

The kernel applies logical-AND across the three Reviewer verdicts:
all three must Approve for the merge to proceed. Any single
`Reject` discards the merge candidate and the kernel emits
`ReviewRejected`.

---

## Common failure modes

| Symptom | Fix |
|---|---|
| `FAIL_ORCHESTRATOR_TASK_NOT_PERMITTED` | A `[[tasks]]` declared `Orchestrator`. Remove it; the Orchestrator is kernel-managed. |
| `FAIL_REVIEWER_NO_PREDECESSOR` | A Reviewer with `predecessors = []`. Reviewers must depend on at least one Executor. |
| `FAIL_REVIEWER_PREDECESSOR_NOT_EXECUTOR` | A Reviewer's predecessor is another Reviewer. Reviewers review Executors. |
| Executor tries `SubmitReview` | Rejected with `FAIL_INTENT_FOR_WRONG_AGENT_TYPE`. Use `CompleteTask`. |
| Reviewer tries `WriteFile` | Rejected with `FAIL_INTENT_FOR_WRONG_AGENT_TYPE`. Reviewers don't write. |

---

## Reference

| Surface | Purpose |
|---|---|
| `kernel/src/initiatives/lifecycle.rs::parse_plan_tasks` | Parser; this is where invalid agent types are caught. |
| `[[tasks]] session_agent_type` | The declared field. |
| `raxis plan validate` | Catches every constraint above. |

---

## Variations

- **Pure Executor plan.** Drop all Reviewer blocks; the Orchestrator
  merges each Executor's commit directly on `CompleteTask`. Fast,
  useful for trivial fixes where review cost exceeds value.
- **Sequential refinement.** Three Executors in a chain
  (`E1 → E2 → E3`); each polishes the previous one's output. Each
  may optionally have its own Reviewer. The DAG enforces order.
- **Read-only audit on a snapshot.** A Reviewer cannot stand alone
  in `[[tasks]]` (`FAIL_REVIEWER_NO_PREDECESSOR`). For a pure-audit
  workflow, ship a no-op Executor (`predecessors = []`,
  `description = "no-op snapshot for audit"`, no commit produced
  → `CompleteTask` with empty diff) and pin the audit Reviewer's
  `predecessors` to that no-op task. The Reviewer's verdict
  surfaces as the audit's outcome; the Orchestrator's
  `IntegrationMerge` is a no-op fast-forward.
- **Multiple Reviewers per Executor (panel).** Each Reviewer's
  `predecessors = [<same Executor>]`. The kernel applies
  logical-AND across the panel. See
  [patterns/02-reviewer-panel](../patterns/02-reviewer-panel.md).

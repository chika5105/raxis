# Pattern: Single Executor + Reviewer

> **Complexity:** ⭐ Beginner | **Agents:** 3 (Orchestrator, 1 Executor, 1 Reviewer)
>
> The baseline RAXIS pattern. One agent implements a task; one agent reviews the output.
> Learn this pattern before any other — every more complex pattern is built on top of it.

> **Field-name note.** The plan-TOML field for "task A blocks task
> B until A completes" is **`predecessors`** (verified against
> `kernel/src/initiatives/lifecycle.rs::parse_plan_tasks`). Some
> spec prose uses `depends_on` as an informal synonym; the
> kernel parser only reads `predecessors`. All runnable plan
> snippets in this guide use the wire-correct name.

---

## When to Use

- A well-scoped task that fits in one context window
- You want a second set of eyes (automated code review, security check, style check)
- The review criteria are known upfront and can be encoded in the Reviewer's `context`

## When Not to Use

- The task is too large for a single Executor (use [Parallel Decomposition](parallel-decomposition.md))
- You need multiple independent review perspectives (use [Panel Review](panel-review.md))
- You need iterative design before implementation (use [Structured Debate](structured-debate.md))

---

## The Plan

```toml
[workspace]
name        = "Add rate limiting to the auth API"
lane_id     = "auth-work"
description = """
  Add IP-based rate limiting to POST /auth/login. Max 10 requests per minute per IP.
  Return 429 Too Many Requests with a Retry-After header when exceeded.
"""

# ── Orchestrator ──────────────────────────────────────────────────────────────
# Coordinates the initiative. Merges the Executor's commit after the Reviewer
# approves. Uses full clone because it must merge across the full tree.
[[tasks]]
task_id             = "orchestrator"
session_agent_type  = "Orchestrator"
clone_strategy      = "full"
path_allowlist      = ["src/auth/"]          # must be a superset of all sub-tasks
cross_cutting_artifacts = ["Cargo.lock"]     # files the Orchestrator may touch during merge

# ── Executor ──────────────────────────────────────────────────────────────────
# Implements the feature. Sparse clone: only downloads src/auth/ — fast for
# large monorepos. The Executor can only WRITE to src/auth/**; it can READ
# anything in the full sparse cone.
[[tasks]]
task_id             = "rate_limit_implementer"
session_agent_type  = "Executor"
clone_strategy      = "sparse"
path_allowlist      = ["src/auth/"]
predecessors        = []                     # starts immediately
max_crash_retries   = 2                      # VM crash budget (OOM, panic, etc.)
max_review_rejections = 2                    # quality rejection budget
context             = """
  Implement IP-based rate limiting on POST /auth/login.
  - 10 requests per minute per IP using a sliding window
  - Return 429 with Retry-After header when exceeded
  - Store rate limit state in Redis (the client is already initialised in src/auth/redis.rs)
  - Add unit tests in src/auth/rate_limit_test.rs
"""

# ── Reviewer ──────────────────────────────────────────────────────────────────
# Evaluates the Executor's output. Activates only AFTER the Executor submits
# CompleteTask — the kernel enforces this via the `predecessors` gate.
# The Reviewer receives the Executor's exact HEAD SHA in its system prompt.
[[tasks]]
task_id             = "security_reviewer"
session_agent_type  = "Reviewer"
clone_strategy      = "blobless"             # needs to read the full src/auth/ tree
path_allowlist      = ["src/auth/"]          # must match (or be subset of) the Executor's
predecessors        = ["rate_limit_implementer"]
context             = """
  Review the rate limiting implementation for:
  1. Correctness: does the sliding window logic match the spec?
  2. Security: could an attacker bypass the limit (X-Forwarded-For spoofing, etc.)?
  3. Test coverage: are the happy path and the 429 case both tested?
  Approve if all three criteria are met. Reject with a specific critique if not.
"""
```

---

## How It Executes

```
approve_plan
  └── Kernel validates: DAG acyclicity, path subset, single Orchestrator ✓

Kernel activates Orchestrator VM
Orchestrator receives: [rate_limit_implementer] in activatable list

Orchestrator → ActivateSubTask { task_id: "rate_limit_implementer" }
  └── Kernel boots Executor VM with sparse clone of src/auth/

Executor runs (N turns):
  - reads src/auth/redis.rs for context
  - implements src/auth/rate_limit.rs
  - adds tests in src/auth/rate_limit_test.rs
  - git commit → CompleteTask { head_sha: "abc123" }

Kernel:
  1. Writes abc123 to tasks.completed_sha
  2. Creates bundle: executor worktree → orchestrator staging
  3. Sends KernelPush::SubTaskCompleted {
       task_id: "rate_limit_implementer",
       newly_activatable: ["security_reviewer"]
     }
  4. Tears down Executor VM

Orchestrator receives push → git fetch bundle → git merge (no conflict expected)
Orchestrator → ActivateSubTask { task_id: "security_reviewer" }

Kernel boots Reviewer VM:
  - evaluation_sha = "abc123" injected into system_prompt.txt
  - Reviewer checks out exactly abc123

Reviewer runs (N turns):
  - reads src/auth/rate_limit.rs
  - reads src/auth/rate_limit_test.rs
  - approves or rejects

Case A — Reviewer approves:
  Reviewer → SubmitReview { approved: true }
  Kernel → KernelPush::AllReviewersPassed
  Orchestrator → IntegrationMerge { commit_sha: "abc123" }
  Kernel fast-forwards main branch ✓

Case B — Reviewer rejects:
  Reviewer → SubmitReview { approved: false, critique: "X-Forwarded-For not sanitised" }
  Kernel:
    - writes critique to tasks.last_critique on the Executor's row
    - increments review_reject_count (1 of 2 allowed)
    - sends KernelPush::ReviewFailed { executor_task_id: "rate_limit_implementer" }
  Orchestrator → RetrySubTask { task_id: "rate_limit_implementer" }
  Kernel boots new Executor VM:
    - system_prompt.txt now PREPENDS the critique from the previous attempt
    - Executor sees: "[Reviewer security_reviewer]: X-Forwarded-For not sanitised\n\n"
  Cycle repeats...
```

---

## Invariant Checklist

- [x] Path subset: `{"src/auth/"} ⊆ {"src/auth/"}` (Orchestrator allowlist covers all sub-tasks)
- [x] Orchestrator clone strategy: `full` (not `sparse`)
- [x] Single `lane_id` at `[workspace]` level; no sub-task overrides
- [x] Reviewer's `predecessors` lists the Executor (not the other way around)
- [x] No cycles in the DAG
- [x] `cross_cutting_artifacts` is an exact filename list (`Cargo.lock`), not a glob

---

## Tuning the Retry Budget

```toml
max_crash_retries     = 2   # environmental failures (OOM, VM panic, host eviction)
max_review_rejections = 2   # quality failures (Reviewer says "not good enough")
```

These are independent counters. An Executor can crash twice AND be rejected twice before the
task fails — giving it 4 activation attempts total across two different failure modes.

Set `max_review_rejections = 0` if you want a zero-tolerance quality gate: one rejection
fails the initiative immediately. Set it higher if you expect the LLM to need iterations.

---

## Common Mistakes

**Mistake:** Reviewer `predecessors = []` (forgets the dependency)
**Result:** `approve_plan` accepts it, but the Reviewer activates immediately with no
`evaluation_sha` — there is nothing to review. Always set `predecessors` to the Executor.

**Mistake:** Executor uses `sparse` clone, Reviewer uses `sparse` on its own path
**Result:** Reviewer's sparse cone only has its own allowlist path, not the Executor's
implementation files. Use `blobless` for Reviewers so they can read the full `src/auth/` tree.

**Mistake:** Setting `path_allowlist = ["src/"]` on the Executor (too broad)
**Result:** Works technically, but defeats the purpose of scoped isolation. Set the
allowlist to the minimum directory the Executor genuinely needs to write.

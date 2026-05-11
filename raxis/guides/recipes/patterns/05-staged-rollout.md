# Pattern: staged rollout (sequential predecessor chain)

> **Topic:** Plan patterns | **Time to read:** ~3 min | **Complexity:** ⭐⭐ Intermediate

Three things have to happen in order:

1. Land a feature-flagged stub (no behaviour change yet).
2. Implement the feature behind the flag.
3. Flip the flag in a config file.

Each step has a different blast radius and a different reviewer
profile, and step 3 must not happen if step 2 was rejected. The
Raxis primitive for "do these in order" is `predecessors`: a task
is `Pending` until **all** of its predecessors are `Completed`,
at which point the kernel transitions it to `Admitted` and a
later `ActivateSubTask` may spawn it.

This is **not** the same as fan-out + merge (no parallelism); it
is a true linear chain. `predecessors` enforce a strict happens-
before relationship at the task FSM level.

---

## When this fits

- Migrations whose stages must commit independently and review
  independently.
- Schema changes split into "expand" (write-side adds the new
  column) → "deploy code" → "contract" (drop the old column).
- Feature flags: stub → impl → flip.
- Anything where step N would be unsafe / unreviewable until
  step N-1 has merged.

When this does NOT fit:

- Concurrent independent slices — see
  [`01-fan-out-then-merge`](./01-fan-out-then-merge.md).
- A single Executor that just commits multiple times — that's
  one task; the chain pattern applies when each step has a
  distinct review scope and reviewer.

---

## Plan shape

```toml
[plan.initiative]
description = "Roll out percent-based pricing"

[workspace]
name        = "pricing-rollout"
lane_id     = "default"

# Stage 1: Land the gate (feature-flagged stub).
[[tasks]]
task_id            = "pricing-stub"
session_agent_type = "Executor"
clone_strategy     = "sparse"
path_allowlist     = ["src/pricing/", "tests/pricing/"]
predecessors       = []
description        = """Add a `flat_fee` vs `percent_fee` enum behind the off-by-default `RAXIS_PRICING_PERCENT` flag. No behaviour change at runtime."""

[[tasks]]
task_id            = "review-stub"
session_agent_type = "Reviewer"
clone_strategy     = "blobless"
path_allowlist     = ["src/pricing/", "tests/pricing/"]
predecessors       = ["pricing-stub"]
description        = """Verify the gate exists, defaults to off, and is exercised by tests in both states."""

# Stage 2: Real implementation. CANNOT START until Stage 1 is
# Completed (`predecessors = ["review-stub"]` is the contract).
[[tasks]]
task_id            = "pricing-impl"
session_agent_type = "Executor"
clone_strategy     = "sparse"
path_allowlist     = ["src/pricing/", "tests/pricing/"]
predecessors       = ["review-stub"]
description        = """Implement percent-based pricing in the new `percent_fee` arm of the enum from stage 1. Flag remains off in production."""

[[tasks]]
task_id            = "review-impl"
session_agent_type = "Reviewer"
clone_strategy     = "blobless"
path_allowlist     = ["src/pricing/", "tests/pricing/"]
predecessors       = ["pricing-impl"]
description        = """Verify the percent-fee arithmetic (boundary tests, overflow, zero-fee corner)."""

# Stage 3: The flag flip. Touches a different path, must wait
# for the impl to merge first.
[[tasks]]
task_id            = "pricing-flip"
session_agent_type = "Executor"
clone_strategy     = "sparse"
path_allowlist     = ["config/feature-flags.toml"]
predecessors       = ["review-impl"]
description        = """Set `pricing.percent_fee_enabled = true` in config/feature-flags.toml."""

[[tasks]]
task_id            = "review-flip"
session_agent_type = "Reviewer"
clone_strategy     = "blobless"
path_allowlist     = ["config/feature-flags.toml"]
predecessors       = ["pricing-flip"]
description        = """Verify the flip is the ONLY change in this commit."""

[orchestrator]
cross_cutting_artifacts = []
```

The DAG it produces:

```text
pricing-stub  →  review-stub  →  pricing-impl  →  review-impl  →  pricing-flip  →  review-flip
              (predecessors)   (predecessors)   (predecessors)   (predecessors)   (predecessors)
```

`pricing-impl` is held in `Pending` by the kernel until
`review-stub` reports `Completed` (which is a no-op state
transition for Reviewers — they `Complete` after a `SubmitReview`
that approves; the Orchestrator then issues `IntegrationMerge`
which fast-forwards the target ref).

---

## What the kernel actually enforces

The task FSM (`task_transitions.rs`) is the single source of
truth: tasks are inserted as `Pending`, with the predecessor
edge stored in `task_dag_edges`. On every `Completed` transition,
the FSM walks downstream edges and admits any task whose
predecessors are now all-Completed.

```text
Initial: pricing-stub Admitted; everything downstream Pending.

Activate pricing-stub → ... → Reviewer approves → Orchestrator merges
         pricing-stub: Completed
   ⇒ FSM admits review-stub: Pending → Admitted

Activate review-stub → SubmitReview approved → Reviewer Completes
         review-stub: Completed
   ⇒ FSM admits pricing-impl: Pending → Admitted
   (... loop continues ...)
```

Two safety properties fall out:

- A failed predecessor stops the chain dead. If `pricing-impl`'s
  Reviewer rejects beyond the rejection budget and the
  Orchestrator `ReportFailure`s, `pricing-flip` stays `Pending`
  forever (or until the operator aborts). The flag never gets
  flipped on a broken implementation.
- Predecessors compose with `IntegrationMerge` admission. The
  kernel will not admit `pricing-flip`'s `IntegrationMerge`
  until the `pricing-impl`'s merge is on the target ref —
  ancestry is checked against the *current* `target_ref`, not
  the workspace base from plan time.

---

## Cost & scheduling

Each stage is independent for budget purposes. If the lane has
`max_concurrent_tasks = 4`, all six tasks could in principle run
concurrently — but the predecessor edges keep it serialised.
Concretely:

| Wall clock | Concurrent tasks | Activations |
|---|---|---|
| t=0 | 1 | `pricing-stub` activates; everything else Pending |
| t=1 | 1 | `review-stub` (after stub Completes) |
| t=2 | 1 | `pricing-impl` (after stub merged + reviewed) |
| t=3 | 1 | `review-impl` |
| t=4 | 1 | `pricing-flip` |
| t=5 | 1 | `review-flip` |

You will not benefit from a wide lane here. If you want
concurrency, see the fan-out pattern.

---

## Common errors

| Symptom | Cause | Fix |
|---|---|---|
| `pricing-flip` never starts | Its predecessor (`review-impl`) didn't reach `Completed`. Reviewers `Complete` only after a `SubmitReview` whose `approved = true` chain merges. Inspect `raxis initiative show <id>` for the upstream task state. | Push the upstream task to completion, or abort. |
| `FAIL_TASK_NOT_ADMITTED` on `ActivateSubTask` for a downstream task | Operator (or orchestrator) tried to start a task before its predecessors completed. | The orchestrator should only `ActivateSubTask` after the kernel emits `KernelPush::TaskAdmitted`. |
| Plan parse error: cycle in predecessors | A → B → A. The parser detects this and rejects with `LifecycleError::PlanInvalid`. | Refactor — Raxis plans are strict DAGs (no cycles, no self-edges). |
| Predecessor declared but not present in `[[tasks]]` | Typo. The parser cross-validates that every entry in `predecessors` matches a `task_id`. | Fix the typo, re-submit. |
| Reviewer can run while stub is still in PR | You forgot `predecessors = ["pricing-stub"]` on `review-stub`. Without it, the kernel admits the Reviewer immediately and it has nothing to review. | Add the edge. The plan-validator (`raxis plan validate`) catches Reviewers without a single Executor predecessor. |

---

## Variations

- **Branching after a stage.** A single Executor predecessor can
  feed multiple downstream tasks. After Stage 2 reviews
  successfully, you might branch into "deploy to staging" + "run
  long-haul soak test" in parallel, both gated on
  `predecessors = ["review-impl"]`.
- **Multi-predecessor merge.** A late stage with
  `predecessors = ["a", "b", "c"]` is admitted only when all three
  upstream tasks Complete. Useful for an "integration smoke test"
  task that runs at the end of a fan-out.
- **Optional stage.** No such thing in a plan — every declared
  task must Complete or the initiative cannot Complete. If a
  step is genuinely optional, leave it out of the plan and let
  the operator add a follow-up plan.
- **Stage with broader path scope.** Stage 3 (the flag flip)
  uses a different `path_allowlist` than Stages 1 & 2. The
  per-stage scope keeps each commit auditable.
- **Operator-required stage.** Add an `escalation` rule keyed on
  `pricing-flip` so the operator must explicitly approve the
  final stage's `IntegrationMerge`. See
  [`policy/03-escalation-policy`](../policy/03-escalation-policy.md).

---

## Reference

| Surface | Where |
|---|---|
| `predecessors` parsing | `kernel/src/initiatives/lifecycle.rs::parse_plan_tasks` |
| DAG edge storage | `task_dag_edges` table (`crates/store/migrations/0001_initial_schema.sql`) |
| FSM admission walk | `kernel/src/initiatives/task_transitions.rs::transition_task` (admits downstream on Complete) |
| Validator rejection | `LifecycleError::PlanInvalid` (cycles, missing predecessors, self-edges) |
| Plan-side syntax | [`plan/07-predecessors`](../plan/07-predecessors.md) |
| Companion: parallel slices | [`patterns/01-fan-out-then-merge`](./01-fan-out-then-merge.md) |

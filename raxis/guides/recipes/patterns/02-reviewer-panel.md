# Pattern: reviewer panel (logical-AND quorum)

> **Topic:** Plan patterns | **Time to read:** ~3 min | **Complexity:** ⭐⭐ Intermediate

Multiple Reviewers vote on the same Executor's commit; the
Reviewer-aggregation step (`kernel/src/initiatives/review_aggregation.rs`)
applies logical-AND across their `SubmitReview` verdicts. The
Orchestrator only receives `KernelPush::AllReviewersPassed` —
and therefore can only submit `IntegrationMerge` for that
sub-task — when **every** Reviewer in the panel approved.

---

## Role recap

- **Executors write code** (`SingleCommit`, `CompleteTask`).
- **Reviewers only emit verdicts** (`SubmitReview { approved,
  critique }`). They never write code, never merge, never
  `CompleteTask`, never `ReportFailure`.
- **The Orchestrator merges** via `IntegrationMerge` after the
  panel's logical-AND fires `AllReviewersPassed`.
- **The Orchestrator is auto-spawned** by the kernel; never
  declared in `[[tasks]]`.

The dispatch matrix (`dispatch_matrix.rs`) is exhaustive and
compile-checked; an Executor that tries `IntegrationMerge`, a
Reviewer that tries `SingleCommit`, etc. all fail-closed at
`FAIL_POLICY_VIOLATION`.

---

## When this fits

- Security-sensitive code (auth, crypto, billing) where one
  Reviewer's perspective isn't enough.
- Cross-team review (one platform reviewer + one product
  reviewer, each evaluating a different concern).
- Compliance: a "two-person rule" mandates ≥ 2 approvals.

When this does NOT fit:

- Trivial work where the panel cost dwarfs the value.
- Tight latency budgets — Reviewers run in parallel after the
  Executor completes, but their wall-clock is dominated by the
  slowest single verdict.

---

## Plan shape

```toml
[plan.initiative]
description = "Implement the SAML auth flow"

[workspace]
name        = "saml-flow"
lane_id     = "default"
repository  = "main"
target_ref  = "refs/heads/main"

# Single Executor. Writes inside its path_allowlist; commits via
# SingleCommit; closes with CompleteTask.

[[tasks]]
task_id            = "implementer"
session_agent_type = "Executor"
clone_strategy     = "sparse"
path_allowlist     = ["src/auth/saml/", "tests/auth/saml/"]
predecessors       = []
description        = "Implementer"
prompt             = """Implement SAML SSO per spec/saml.md."""

# Three Reviewers, all reviewing `implementer`. Each has a narrow
# `description` (its remit) but its predecessors and path_allowlist
# point at the SAME Executor's work. Each emits exactly one
# SubmitReview verdict; the kernel aggregates them.

[[tasks]]
task_id            = "review-security"
session_agent_type = "Reviewer"
clone_strategy     = "blobless"
path_allowlist     = ["src/auth/saml/", "tests/auth/saml/"]
predecessors       = ["implementer"]
description        = "Review Security"
prompt             = """Security review: confirm the implementation matches the threat model in spec/saml-threat-model.md. Reject on any unmitigated finding."""

[[tasks]]
task_id            = "review-spec-conformance"
session_agent_type = "Reviewer"
clone_strategy     = "blobless"
path_allowlist     = ["src/auth/saml/", "tests/auth/saml/"]
predecessors       = ["implementer"]
description        = "Review Spec Conformance"
prompt             = """Confirm conformance with spec/saml.md sections 3-7. Reject on any deviation."""

[[tasks]]
task_id            = "review-tests"
session_agent_type = "Reviewer"
clone_strategy     = "blobless"
path_allowlist     = ["src/auth/saml/", "tests/auth/saml/"]
predecessors       = ["implementer"]
description        = "Review Tests"
prompt             = """Confirm tests cover happy path, malformed assertion, replay, and missing audience cases. Reject if any case missing."""

[orchestrator]
cross_cutting_artifacts = []
```

Key invariants the kernel enforces:

- All three Reviewers share `predecessors = ["implementer"]`.
  The kernel detects them as a panel for `implementer` because
  multiple Reviewer tasks have the same single Executor predecessor.
- A Reviewer's `path_allowlist` defines its sparse worktree read
  scope. Reviewers have **no write authority** regardless of the
  field's value. `vm_image` MUST be unset (the Reviewer image is
  kernel-canonical, `INV-PLANNER-HARNESS-02`); `allowed_egress`
  MUST be empty (`INV-NETISO-01`).
- Each Reviewer's `description` carries its specific remit. The
  planner harness composes the system prompt from this.

---

## How aggregation actually works

Aggregation lives in `compute_aggregate_review_outcome`. As each
Reviewer submits its `SubmitReview` intent, the kernel:

1. Records the verdict in `subtask_activations` (`approved` boolean
   + `critique` text).
2. Checks the panel set: every Reviewer task whose predecessor is
   `implementer` and whose `evaluation_sha` matches the Executor's
   completed sha.
3. If **all** approved → emits `KernelPush::AllReviewersPassed
   { task_id }` to the Orchestrator session.
4. If **any** rejected → emits `KernelPush::ReviewRejected
   { task_id, critique, reviewer_session_id }`. The kernel
   increments `subtask_activations.review_reject_count` for the
   Executor task **once per rejection round** (not once per
   rejecting Reviewer in the panel).
5. The Orchestrator decides next step on rejection:
   `RetrySubTask { task_id }` to re-spawn the Executor (subject
   to the retry ceiling), or `ReportFailure` to surface to the
   operator.

If the panel is mixed (some approved, some rejected), the kernel
treats it as `AtLeastOneRejected` — a single reject collapses the
round.

---

## Per-Reviewer mechanical verifiers

A Reviewer's verdict is a planner judgment. If you also need a
mechanical pre-condition (e.g., test coverage threshold), declare
it as a verifier on the **Executor** with `on_failure = "block_review"`:

```toml
[[tasks.verifiers]]
name       = "test_coverage_check"
image      = "raxis-verifier-starter"
command    = "raxis-verify-coverage --baseline-ref refs/heads/main"
timeout    = "10m"
on_failure = "block_review"
```

Per-task verifiers run between `CompleteTask` and Reviewer
activation. A failure prevents the Reviewers from spawning at all
(the Executor must fix its commit first).

Don't try to attach `[[tasks.verifiers]]` to a Reviewer — the
Reviewer's worktree is RO and the harness has no commit-pathway
intent; the verifier substrate doesn't apply there.

---

## Common errors

| Symptom | Fix |
|---|---|
| `FAIL_REVIEWER_NO_PREDECESSOR` | A Reviewer with `predecessors = []`. Pin to the Executor. |
| `FAIL_REVIEWER_PREDECESSOR_NOT_EXECUTOR` | Reviewer's predecessor is another Reviewer. |
| `FAIL_REVIEWER_VM_IMAGE_NOT_ALLOWED` | Remove `vm_image` from the Reviewer task. The Reviewer image is kernel-canonical. |
| Panel size > lane's `max_concurrent_tasks` | Reviewers queue; total wall-clock grows but correctness unaffected. |
| `review_reject_count` increments by N rather than 1 per round | Bug; should be exactly one. File upstream with the audit slice (`raxis log <init> --kind ReviewRejected --json`). |
| All three reviewers approve in seconds | Either the work was tiny or the planner is rubber-stamping (bad system prompt; tighten the Reviewer's `prompt`). |
| Reviewer tries to write a file | Rejected with `FAIL_POLICY_VIOLATION`. Reviewers have no write authority. |

---

## Reference

| Concept | Surface |
|---|---|
| Aggregation logic | `kernel/src/initiatives/review_aggregation.rs::compute_aggregate_review_outcome` |
| Dispatch matrix | `kernel/src/authority/dispatch_matrix.rs` |
| `session_agent_type` constraints | [plan/06-session-agent-type](../plan/06-session-agent-type.md) |
| `predecessors` (DAG) | [plan/07-predecessors](../plan/07-predecessors.md) |
| Existing scenario | `guides/scenarios/07-panel-review/` |

---

## Variations

- **Panel of 2.** Two Reviewers; cheaper than three but still
  enforces "two-person rule".
- **Tiered panel.** Two general Reviewers + one specialty
  Reviewer (e.g., DBA-only review for migration files); each
  Reviewer's `description` defines its narrow remit.
- **Per-language Reviewers.** A Rust Reviewer + a TypeScript
  Reviewer for a polyglot change; each reads only the relevant
  files (different `path_allowlist` sparse scopes; same Executor
  predecessor).
- **Conditional panel size.** A pre-submission tool decides at
  plan-creation time how many Reviewers to attach: small change →
  one Reviewer, multi-module → three. The plan is then signed
  with the chosen panel.
- **Veto-style architecture.** One Reviewer is the "veto" with
  broad scope and the others are narrow. Functionally identical
  to a logical-AND panel — the kernel doesn't weight verdicts —
  but it documents intent.

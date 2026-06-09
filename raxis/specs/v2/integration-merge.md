# RAXIS V2 — `IntegrationMerge` Specification

> **Status:** V2 Specified
> **Cross-references:**
> - [`v2-deep-spec.md §Step 8`](v2-deep-spec.md) — Orchestrator Performs `IntegrationMerge`; Kernel Adjudicates It (decision + rationale; the cross-reference language was tightened by `INV-KERNEL-DAG-AUTHORITY-01` — "owns the merge" is shorthand for "semantically resolves conflicts in the merge clone and emits the advisory intent", NOT "decides whether the merge lands")
> - [`v2-deep-spec.md §Step 9`](v2-deep-spec.md) — Bundle Routing (how Executor commits reach the Orchestrator)
> - [`v2-deep-spec.md §Step 11`](v2-deep-spec.md) — Hybrid Allowlist computation
> - [`v2-deep-spec.md §Step 24b`](v2-deep-spec.md) — Orchestrator Workspace Provisioning (RW clone from base SHA at initiative boot; the workspace this spec's merges happen in)
> - [`v2-deep-spec.md §Step 24c`](v2-deep-spec.md) — Executor Workspace Input Base (successor Executors clone from predecessor `evaluation_sha`; IntegrationMerge then consolidates the resulting ancestry)
> - [`v2-deep-spec.md §Step 30`](v2-deep-spec.md) — Audit Attribution for Operator-Assisted Commits
> - [`planner-harness.md §4.7`](planner-harness.md) — Canonical Orchestrator Image (`INV-PLANNER-HARNESS-05`); the source of `bash`, `git`, `ripgrep`, and `edit_file` for V2 semantic conflict resolution
> - [`planner-harness.md §4.8`](planner-harness.md) — Orchestrator Not Operator-Configurable (`INV-PLANNER-HARNESS-06`); explains why §8's workflow lives in kernel-pinned NNSP bytes rather than operator configuration
> - [`kernel-mechanics-prompt.md §3.2`](kernel-mechanics-prompt.md) — **normative** Orchestrator NNSP including the `[KERNEL: INTEGRATION MERGE PROTOCOL]` and `[KERNEL: CONFLICT RESOLUTION PROTOCOL]` blocks
> - [`policy-plan-authority.md §4`](policy-plan-authority.md) `[orchestrator]` — operator-tunable policy knobs (`provider_alias`, `max_token_budget_per_initiative`, `all_merges_require_approval`)
> - [`agent-disagreement.md`](agent-disagreement.md) — sub-task `CompleteTask` admission gates (`FAIL_CIRCULAR_REVISION`, `FAIL_REVIEW_LOOP_EXCEEDED`, `FAIL_WALL_CLOCK_LIMIT_EXCEEDED`) that fire **before** sub-tasks reach the merge pipeline. `IntegrationMerge` itself is unchanged by that spec; what changes is which sub-tasks ever satisfy Check 4's `state = 'Completed'` precondition.
> - [`extensibility-traits.md §2`](extensibility-traits.md) — `DomainAdapter` trait. **`IntegrationMerge` is the SE-domain instantiation of `DomainAdapter::commit`**. The admission pipeline (Checks 1–7), the audit emissions, and the SQLite/git transactional boundary specified here are *paradigm-layer* and stay in the kernel binary. The git-specific cherry-pick / fetch / update-ref / push sequence in Phase 2 of Check 8 (and the touched-paths derivation in Check 5) is *implementation-layer* and lives in `crates/raxis-domain-git`. Other domains (trading, healthcare) reuse this entire spec verbatim and just plug a different adapter into the same Phase 2 call site.
>
> This document is the **complete mechanical specification** for the `IntegrationMerge`
> intent: its struct, the full admission pipeline, the multi-task merge sequencing model,
> target-ref preservation semantics, audit events, and idempotency behaviour.
> The rationale for these decisions lives in the deep spec cross-references above.

---

## 1. What IntegrationMerge Is

`IntegrationMerge` is the intent the Orchestrator submits to the Kernel after it has
successfully merged the completed Executor sub-task branches into a single commit in its
ephemeral clone. Upon admission, the Kernel advances the initiative's resolved
`target_ref` to a commit that includes the Orchestrator's merged commit and preserves
the live target-ref tip. In the common case this is a fast-forward to the submitted
SHA; if another initiative advanced the same target ref first, the git adapter creates
a deterministic conflict-free host-side merge commit with both histories as parents.
This is the **only** mechanism that writes agent-produced code to the canonical branch.

Until `IntegrationMerge` is admitted:
- The resolved `target_ref` is untouched
- All Executor commits exist only in ephemeral VM worktrees and Orchestrator staging bundles
- The initiative state is `InProgress`

After `IntegrationMerge` is admitted:
- The resolved `target_ref` is updated to the published SHA
- The published SHA is either the submitted `commit_sha` or a deterministic host-side merge commit that preserves a concurrently advanced live target-ref tip
- The initiative logs `IntegrationMergeCompleted` in the audit chain
- The Orchestrator may activate the next wave of sub-tasks (if the DAG has more)

### 1.1 Paradigm-vs-implementation framing

`IntegrationMerge` is the SE-domain instance of the *paradigm primitive* "authorised commit of agent-produced state to canonical external state" (`paradigm.md §2`, `R-11`). The trait that captures that paradigm primitive is `DomainAdapter::commit` ([`extensibility-traits.md §2.2.A`](extensibility-traits.md)). Concretely:

- The intent struct (§2), the admission pipeline (§4), the multi-task wave model (§5), the audit chain emissions (§7), and the SQLite/git transactional boundary (§11) are *paradigm-layer* mechanisms that stay in the kernel binary unchanged. They apply to **any** domain.
- The git-specific operations — `gix::diff_tree_to_tree` for the touched-set in Check 5, object-copy plus target-ref advancement in Check 8 Phase 2, the optional `git push` to upstream in §14 — are *implementation-layer* and live entirely behind the `DomainAdapter` trait, in `crates/raxis-domain-git`. A `TradingAdapter::commit` plugged into the same Phase 2 call site instead submits an order via the credential proxy; an `HealthcareAdapter::commit` POSTs a FHIR resource. The kernel's `IntegrationMerge` handler is unchanged.

Where this spec uses the word "git" in a normative paragraph, that paragraph describes the V2 reference adapter's behaviour; the underlying paradigm contract stays domain-agnostic.

### 1.2 Configurable target ref

This spec mentions `refs/heads/main` throughout the historical
text below. Per the V2.2 amendment, the kernel actually advances a
**resolved `target_ref`** that defaults to `refs/heads/main` but
may be overridden per-initiative. The resolution chain runs at
`lifecycle::approve_plan` admission time:

1. `[workspace] target_ref` from `plan.toml` (per-initiative override)
2. `[git] default_target_ref` from `policy.toml` (operator default)
3. Hardcoded fallback `"refs/heads/main"`

Operators who want to enforce the historical "always push to main"
posture set `[git] target_ref_locked = true`; plans that try to
override are then rejected at admission with
`FAIL_POLICY_LOCKED_FIELD` per `INV-PLAN-POLICY-PRECEDENCE-01`.

Operators who want a **PR-branch workflow** (kernel pushes a
RAXIS-only branch like `refs/heads/raxis/<initiative>`, the
team's existing CI + human-review pipeline merges into `main`)
leave `target_ref_locked = false` and let plans declare
`[workspace] target_ref = "refs/heads/raxis/<name>"`. This
separates RAXIS's structural authority (path-allowlist, reviewer
verdicts, INV-MERGE-* invariants) from the team's SDLC authority
(human review, branch protection, merge approval).

Every "advance `refs/heads/main`" / "update-ref `refs/heads/main`"
phrase in §4–§14 should be read as "advance the resolved
`target_ref`"; the V2 reference `domain-git` adapter's
`commit_merge_to_target_ref(...)` / `update_target_ref(..., target_ref)`
APIs accept any fully-qualified branch ref (validated via
`raxis_policy::validate_target_ref_format`).

---

## 2. The Intent Struct

```rust
/// Submitted by Orchestrator only (dispatch matrix enforced).
pub struct IntegrationMerge {
    /// The SHA of the merge commit in the Orchestrator's ephemeral clone.
    /// Must be reachable from the Orchestrator's worktree HEAD.
    pub commit_sha: String,

    /// When Some(id), this merge required operator escalation for conflict resolution.
    /// The Kernel verifies this escalation_id is in Consumed state under MergeConflict class
    /// and belongs to this Orchestrator session before admitting.
    /// None for all standard (LLM-resolved or conflict-free) merges.
    pub resolved_via_escalation: Option<EscalationId>,

    /// When Some(id), this merge touches one or more protected paths (declared in the
    /// policy bundle's [[protected_paths]] section) and the operator has pre-approved it.
    /// The Kernel verifies this escalation_id is in Consumed state under ProtectedPathMerge
    /// class and belongs to this Orchestrator session before admitting.
    /// None when no protected paths are touched (the common case).
    pub operator_approval_id: Option<EscalationId>,

    /// The set of sub-task IDs whose branches are included in this merge commit.
    /// Must be a non-empty subset of the initiative's sub-tasks.
    /// The Kernel verifies each listed sub-task is in Completed state.
    pub merged_task_ids: Vec<TaskId>,
}
```

---

## 3. Preconditions for Submission

The Orchestrator should only submit `IntegrationMerge` after all of the following are true
in its local view. The Kernel re-verifies all of these at admission:

1. All Reviewers for the merged sub-tasks have submitted `SubmitReview { approved: true }`.
   The Orchestrator receives `KernelPush::AllReviewersPassed { task_id }` before it activates
   any subsequent task or considers merging.
2. The Orchestrator has fetched each sub-task's bundle and run `git merge` successfully
   (no unresolved conflicts remaining in the working tree).
3. The resulting merge commit has been produced — `git status` is clean and `HEAD` is
   a merge commit or a fast-forward of the Orchestrator's base SHA.
4. If the merge required conflict resolution via operator hint (Path 1, Step 30), the
   Orchestrator has re-attempted and produced a clean commit.
5. If the merge required manual operator intervention (Path 2, Step 30), the operator has
   committed and run `raxis escalate resolve`, and the Orchestrator has received
   `KernelPush::EscalationResolved`.

---

## 4. Full Admission Pipeline

The `IntegrationMerge` intent passes through these checks in order. Failure at any step
returns the error code and stops processing with no state change.

### Check 1 — Dispatch Matrix
`session_agent_type = Orchestrator`. All other types return `FAIL_POLICY_VIOLATION` +
`SecurityViolation` audit event.

### Check 2 — `commit_sha` Reachability
`commit_sha` must exist in the Kernel's mirror of the Orchestrator's worktree, reachable
from `HEAD`. The Kernel verifies by running:
```bash
git -C $RAXIS_DATA_DIR/worktrees/<orchestrator_uuid> cat-file -t <commit_sha>
```
Result must be `commit`. Failure: `FAIL_COMMIT_NOT_FOUND`.

### Check 3 — Ancestry Verification
`commit_sha` must be a descendant of the initiative's current `base_sha`:
```bash
git -C <worktree> merge-base --is-ancestor <base_sha> <commit_sha>
```
If `commit_sha` is not a descendant of `base_sha`, the Orchestrator is attempting to
merge a commit that doesn't include the previous state of main. This would produce a
history rewrite. Failure: `FAIL_ANCESTRY_VIOLATION`.

**Why this matters:** If Orchestrator merges sub-task A (producing SHA `abc`), updates
main to `abc`, then later submits `IntegrationMerge { commit_sha: "def" }` where `def`
does not descend from `abc`, the main branch would lose the history of A's work. The
ancestry check prevents this.

**Concurrent-initiative hardening.** `base_sha` is the initiative/session anchor, not
necessarily the live tip of `target_ref` at publish time. Another initiative may
successfully advance the same `target_ref` after this initiative was approved. Therefore
the reference git adapter performs a second domain-level live-tip preservation check
immediately before the ref transaction:

```bash
git -C $RAXIS_DATA_DIR/repositories/main merge-base --is-ancestor \
  <live_target_ref_tip> <commit_sha>
```

If this succeeds, publishing `commit_sha` is a normal fast-forward. If it fails,
publishing `commit_sha` directly would drop already-landed work from the canonical ref,
so the adapter attempts a deterministic host-side merge commit:

```bash
git -C $RAXIS_DATA_DIR/repositories/main worktree add --detach <tmp> <live_target_ref_tip>
git -C <tmp> merge --no-ff --no-gpg-sign \
  -m "raxis: preserve concurrent target-ref advancement" <commit_sha>
git -C $RAXIS_DATA_DIR/repositories/main update-ref <target_ref> <published_sha>
```

The published SHA has both `<live_target_ref_tip>` and `<commit_sha>` as ancestors. If
git reports conflicts or cannot synthesize the merge commit, the adapter rejects with
`target_ref_concurrent_merge_failed`; the kernel leaves `target_ref` untouched and
surfaces the merge as a failed `IntegrationMerge` rather than silently rewriting
history.

### Check 4 — `merged_task_ids` Validation
Every `task_id` in `merged_task_ids`:
- Must exist in `subtask_activations` for this initiative
- Must have `state = 'Completed'` (not Active, Pending, or Failed)
- Must have `completed_sha` set (non-null)
- Must not appear in a previous `IntegrationMerge.merged_task_ids` for this initiative
  (each sub-task may be merged exactly once)

Failure for any of these: `FAIL_TASK_NOT_COMPLETED` with the offending task_id.

**V2.7 implementation note — implicit full coverage.** The current wire tool still
submits `{ base_sha, head_sha }` and has not yet carried the explicit
`merged_task_ids` vector. Until that field is fully wired, the kernel derives the
required merge set mechanically: every plan-declared Executor task in the same
initiative with `tasks.state = 'Completed'` and a non-null `evaluation_sha`. For each
such task, the submitted `head_sha` MUST contain that `evaluation_sha` as an ancestor:

```bash
git -C <orchestrator_worktree> merge-base --is-ancestor \
  <executor_evaluation_sha> <head_sha>
```

Failure is `FAIL_INVALID_DIFF` and emits
`IntegrationMergeMissingCompletedExecutorHead` in the kernel log and an
`IntentValidationRejected` audit row whose `validator_detail` includes the
missing executor `task_id`, missing SHA, submitted `head_sha`, and diagnostic.
This intentionally disables "publish one successful executor SHA" as a partial
merge shortcut: partial merge waves require the explicit `merged_task_ids` field
so the audit chain can prove which completed artifacts were included and which
were deliberately deferred.

The Orchestrator's KSB capabilities also project an `integration_merge:` line
with `ready=<true|false>`, `base_sha`, `required_executor_shas=[task=sha, ...]`,
and `blockers=[...]`. When `ready=true`, the Orchestrator should call
`prepare_integration_merge { base_sha, executor_shas }`, then pass the returned
`head_sha` to `integration_merge`. If `prepare_integration_merge` reports merge
conflicts, the Orchestrator may resolve only those conflicted files in its
integration worktree and create a conflict-resolution commit on top of the
Executor commits; the same kernel coverage and hybrid-allowlist checks still
gate publication.

**Interaction with [`agent-disagreement.md`](agent-disagreement.md).** A sub-task only reaches
`state = 'Completed'` after its `CompleteTask` intent admits cleanly.
Per [`agent-disagreement.md`](agent-disagreement.md), that admission can be rejected by
`FAIL_CIRCULAR_REVISION` (§4) or `FAIL_REVIEW_LOOP_EXCEEDED` (§3)
or terminated by `FAIL_WALL_CLOCK_LIMIT_EXCEEDED` (§5) — in which
case the sub-task transitions to `Failed`, never to `Completed`,
and Check 4 here rejects any `IntegrationMerge` that names it. The
Orchestrator, on receipt of the `EscalationResolved` /
`SubEscalationResolutionRequired` notifications described in that
spec, is expected to reissue or abandon the affected sub-tasks
before constructing a merge.

### Check 5 — Diff Computation and Hybrid Allowlist Check
The Kernel derives the touched-set via the `DomainAdapter` trait ([`extensibility-traits.md §2.2`](extensibility-traits.md)), which for the SE adapter is a content diff between `base_sha` and `commit_sha`:
```rust
let touched: TouchedResources = ctx.domain.touched_resources(
    &IntentKind::IntegrationMerge { commit_sha, base_sha, .. },
    &admission_ctx,
)?;
let touched_paths: Vec<&str> = touched
    .resources
    .iter()
    .filter_map(|r| r.uri.strip_prefix("path:///"))
    .collect();
```
The `GitAdapter` impl wraps `gix::diff_tree_to_tree(base_tree, head_tree)`, returning each touched path as a `path:///`-prefixed URI; the kernel strips the prefix here for the allowlist comparison so the rest of this Check stays SE-flavoured. Non-SE adapters return their own URI scheme and the allowlist matcher in `policy.toml` is reframed as URI-prefix matching ([`extensibility-traits.md §2.6`](extensibility-traits.md) files-to-change for `kernel/src/scheduler/admit.rs`).

The set of touched paths is checked against the hybrid allowlist:
```text
hybrid_effective_allow =
    UNION(task.path_allowlist for task in merged_task_ids)
    ∪ orchestrator.cross_cutting_artifacts
```

In the V2.7 implicit-full-coverage implementation, `merged_task_ids` in this formula is
the mechanically derived set of all completed Executor task ids for the initiative.

Every touched path must match at least one entry in `hybrid_effective_allow`. Failure:
`FAIL_PATH_POLICY_VIOLATION { path }` for the first out-of-scope path found.

**Cross-cutting artifacts:** Exact filenames declared in `orchestrator.cross_cutting_artifacts`
in the signed plan (e.g., `["Cargo.lock", "package-lock.json"]`). No glob patterns.

### Check 5b — Protected Path Approval Gate (conditional)

Runs **immediately after Check 5**, using the same `touched_paths` set already computed.

The Kernel queries the policy bundle's `[[protected_paths]]` list and checks whether any
path in `touched_paths` matches a protected prefix:

```rust
let protected_hits: Vec<&str> = policy
    .protected_paths
    .iter()
    .filter(|p| p.require_approval_for.contains(&IntentClass::IntegrationMerge))
    .filter(|p| touched_paths.iter().any(|t| t.starts_with(&p.path_prefix)))
    .map(|p| p.path_prefix.as_str())
    .collect();
```

**If `protected_hits` is non-empty AND `operator_approval_id` is `None`:**

1. The Kernel auto-creates a `ProtectedPathMerge` escalation in `Pending` state:
   ```sql
   INSERT INTO escalations (id, class, state, session_id, initiative_id,
                            protected_paths_hit, commit_sha)
   VALUES (new_uuid, 'ProtectedPathMerge', 'Pending',
           :orchestrator_session_id, :initiative_id,
           :protected_hits_json, :commit_sha)
   ```
2. Emits `AuditEventKind::MergeApprovalRequired { escalation_id, protected_paths: protected_hits, commit_sha }`
3. Returns `FAIL_PROTECTED_PATH_APPROVAL_REQUIRED { escalation_id }` to the Orchestrator
4. Sends `KernelPush::MergeApprovalRequired { escalation_id, protected_paths: protected_hits }` to the Orchestrator

The Orchestrator does not need to submit `EscalationRequest` — the Kernel created it. The
Orchestrator simply waits for `KernelPush::EscalationResolved { escalation_id }`, then
re-submits `IntegrationMerge` with `operator_approval_id: Some(escalation_id)`.

**If `protected_hits` is non-empty AND `operator_approval_id` is `Some(id)`:**
Proceed to Check 6a (verify the approval) instead of creating a new escalation.

**If `protected_hits` is empty:**
Check 5b is a no-op. Proceed to Check 5c.

---

### Check 5c — Universal Merge Approval Gate (conditional, V2 addition)

Runs **immediately after Check 5b** when the policy bundle's
`[orchestrator]` section sets `all_merges_require_approval = true`
(per [`policy-plan-authority.md §4`](policy-plan-authority.md) `[orchestrator]`,
`INV-PLANNER-HARNESS-06`).

When `all_merges_require_approval = true` AND `operator_approval_id`
is `None`, the kernel auto-creates a `MergeAuthorization` escalation
in `Pending` state (parallel to Check 5b's `ProtectedPathMerge`):

```sql
INSERT INTO escalations (id, class, state, session_id, initiative_id,
                         commit_sha)
VALUES (new_uuid, 'MergeAuthorization', 'Pending',
        :orchestrator_session_id, :initiative_id, :commit_sha)
```

Emits `AuditEventKind::MergeApprovalRequired { escalation_id, kind:
"all_merges_policy", commit_sha }`. Returns
`FAIL_PROTECTED_PATH_APPROVAL_REQUIRED { escalation_id }` to the
Orchestrator (the same fail code as Check 5b, semantically
"approval needed" — the Orchestrator's NNSP §3.2 step 6 already
handles this branch). Sends
`KernelPush::MergeApprovalRequired { escalation_id, kind: "all_merges_policy" }`
to the Orchestrator.

The Orchestrator waits for `KernelPush::EscalationResolved`, then
re-submits `IntegrationMerge` with `operator_approval_id: Some(id)`.
On re-submission, Check 5c is satisfied by the verification step in
Check 6a (which is extended to also accept
`escalations.class = 'MergeAuthorization'`).

**If `all_merges_require_approval = false` (default):**
Check 5c is a no-op. Proceed to Check 5d.

**Composition with Check 5b.** Both gates can fire on the same merge
(a touch of a protected path AND `all_merges_require_approval = true`).
The kernel collapses these into a single `ProtectedPathMerge`
escalation when `protected_hits` is non-empty (the operator's protected
path approval is a strict superset of the universal approval); the
universal-approval gate adds nothing in that case. The
`MergeAuthorization` class fires only when `protected_hits` is empty
AND `all_merges_require_approval = true`. The Orchestrator's NNSP §3.2
treats both classes identically at step 6 (`FAIL_PROTECTED_PATH_APPROVAL_REQUIRED:
await KernelPush::EscalationResolved; re-submit with operator_approval_id`).

---

### Check 5d — Pre-Integration Merge Verifier Execution (conditional, V2 addition)

> **Implementation status (V2 GA):** The plan-author and operator-global
> surfaces below are **not yet wired** in the kernel. Until the
> `raxis-verifier-runtime` crate (per [`verifier-processes.md §19.1`](verifier-processes.md))
> lands, the kernel rejects any plan or policy that declares
> `[[plan.integration_merge_verifiers]]` or `[[integration_merge_verifiers]]`
> at the earliest gate (plan-approve / policy-load), with
> `FAIL_VERIFIER_INVALID_ON_FAILURE` and a structured reason
> `pre_merge_verifier_runtime_not_yet_landed`. The common case (no
> declarations) is unaffected — Check 5d is trivially a no-op for all
> existing plans and policies.
>
> **Tracker.** The full Check 5d implementation is a multi-day phase
> (per [`verifier-processes.md §19`](verifier-processes.md) Implementation Plan — Phase 4). It depends on:
>
> - The `raxis-verifier-runtime` crate (`§19.1`).
> - `DDL Migration 11` for `integration_merge_attempts` (§11.10.1).
>   (Originally drafted as Migration 10 but bumped to 11 because
>   Migration 10 was consumed by `task_credential_proxies` —
>   [`credential-proxy.md §1.1`](credential-proxy.md).)
> - The candidate-merge-tree creation primitive (`§16.2`).
> - VM-spawn integration with `RAXIS_VERIFIER_HOOK_KIND = "pre_merge"`
>   ([`verifier-processes.md §11`](verifier-processes.md)).
> - Crash-recovery for in-flight pre-merge runs (§11.10.4).
>
> The fail-closed posture above ensures no operator can accidentally
> declare pre-merge verifiers and have them silently bypass at merge
> time. When the runtime lands, the early rejection is removed and
> the gate fires per the algorithm below.

Runs **immediately after Check 5c** when at least one of the following
declares pre-merge verifiers (per [`verifier-processes.md §15`](verifier-processes.md)):

- `plan.toml [[plan.integration_merge_verifiers]]` — plan-author surface
- `policy.toml [[integration_merge_verifiers]]` — operator-global surface

When neither source declares any pre-merge verifier (the common case
for simple deployments), Check 5d is a no-op and admission proceeds
to Check 6a. When either source declares verifiers, Check 5d gates
main advancement on the candidate merged tree's verifier verdicts.

**Authority composition.** Pre-merge verifiers from both sources fire
on the same merge attempt. Operator-side declarations cannot be
downgraded to `warn_only` by any plan; plan-side declarations may
freely choose `block_merge` or `warn_only`. Both sources are subject
to the `applies_to` filter (per [`verifier-processes.md §16.3`](verifier-processes.md)):
`"all"` (default) | `"task_set"` | `"last"`. Operator-side
declarations additionally honor `required_for_environments` to bind
to the environment-access-control framework
(`environment-access-control.md INV-ENV-01`).

#### Check 5d.1 — Determine matching verifiers

```rust
let matching: Vec<&PreMergeVerifier> = plan.integration_merge_verifiers
    .iter()
    .chain(policy.integration_merge_verifiers.iter())
    .filter(|v| applies_to_matches(v, current_merge))
    .filter(|v| environment_filter_matches(v, current_merge))   // operator-only required_for_environments
    .collect();

if matching.is_empty() {
    // No pre-merge verifiers fire on this merge. No-op.
    proceed_to_check_6a();
    return;
}
```

`applies_to_matches` and `environment_filter_matches` are specified
in [`verifier-processes.md §16.3`](verifier-processes.md).

#### Check 5d.2 — Compute the candidate merged tree

The kernel computes the merge commit that *would* result from
`IntegrationMerge { commit_sha, merged_task_ids }` — using the same
git operations the Orchestrator's `git merge` invocation would use,
but produced as an **orphan commit** in the kernel's
verifier-staging area at:

```text
$RAXIS_DATA_DIR/candidate_merges/<integration_merge_id>/
```

This is a separate worktree, NOT on main, NOT on any task branch.
The candidate is reachable only by its SHA — it is not pointed to by
any ref.

```sql
-- Record candidate-merge-tree creation for crash recovery (§11 extended).
INSERT INTO integration_merge_attempts (
    id, initiative_id, orchestrator_session_id,
    requested_commit_sha, candidate_merge_sha,
    state, created_at
)
VALUES (
    :integration_merge_id, :initiative_id, :orchestrator_session_id,
    :commit_sha, :candidate_merge_sha,
    'AwaitingPreMergeVerifiers', :now
);
```

Emits `CandidateMergeTreeCreated { integration_merge_id,
candidate_merge_sha, merged_task_ids }` audit event.

If candidate-merge-tree computation fails (e.g., the Orchestrator
submitted a malformed `commit_sha` that the kernel can't merge with
main cleanly), Check 5d returns
`FAIL_CANDIDATE_MERGE_COMPUTATION_FAILED { reason }` and discards
any partially-created worktree. The Orchestrator typically resolves
this by re-doing its merge work and re-submitting.

#### Check 5d.3 — Spawn pre-merge verifier VMs

For each verifier in `matching`, the kernel allocates a verifier-VM
slot (against `[host_capacity] max_concurrent_verifier_vms`) and
spawns the VM per [`verifier-processes.md §4.2`](verifier-processes.md). The
spawn-envelope `RAXIS_VERIFIER_HOOK_KIND = "pre_merge"`,
`RAXIS_INTEGRATION_MERGE_ID` is set, and `/workspace` is mounted
from the candidate merged tree (NOT from any individual task branch
and NOT from current main).

Verifiers run in parallel subject to capacity caps; the kernel waits
for all matching verifiers to complete (`final_status` set on every
matching verifier's witness row) before proceeding.

#### Check 5d.4 — Gating and disposition

Per [`verifier-processes.md §5.3`](verifier-processes.md):

```rust
let block_merge_failures = matching.iter()
    .filter(|v| v.on_failure == "block_merge" && v.final_status() != "passed")
    .collect::<Vec<_>>();

if !block_merge_failures.is_empty() {
    // Discard the candidate merged tree (§11.10).
    discard_candidate_merge_tree(integration_merge_id, candidate_merge_sha,
                                  reason: "verifier_blocked");

    // Mark the attempt and emit audit.
    UPDATE integration_merge_attempts
       SET state = 'BlockedByPreMergeVerifier',
           discard_reason = 'verifier_blocked'
     WHERE id = :integration_merge_id;
    emit AuditEventKind::VerifierBlockedMerge { integration_merge_id,
                                                 candidate_merge_sha,
                                                 verifier_names,
                                                 primary_witness_summary };

    // Return failure to Orchestrator.
    return FAIL_INTEGRATION_MERGE_VERIFIER_BLOCKED {
        verifier_names: block_merge_failures.iter().map(|v| v.name.clone()).collect(),
        primary_witness_summary: block_merge_failures[0].summary(),
        candidate_merge_sha,
    };
} else {
    // All block_merge verifiers passed (warn_only failures don't gate the merge).
    UPDATE integration_merge_attempts
       SET state = 'PreMergeVerifiersPassed'
     WHERE id = :integration_merge_id;
    proceed_to_check_6a();
}
```

When the Orchestrator receives `FAIL_INTEGRATION_MERGE_VERIFIER_BLOCKED`,
it routes per [`verifier-processes.md §16.6`](verifier-processes.md) — typically as an
operator escalation `EscalationRequest { class:
IntegrationMergeRegression, ... }`, since pre-merge regressions are
post-Reviewer and require operator judgment rather than agent retry.
**Pre-merge verifier failures do NOT count toward `INV-CONVERGENCE-01`**
because they are not review rounds.

#### Check 5d.5 — Cost discipline

Pre-merge verifiers run only on merges that have already passed:

- Check 1 (Dispatch matrix — Orchestrator-only)
- Check 2 (commit_sha reachability)
- Check 3 (Ancestry verification)
- Check 4 (merged_task_ids validation — all tasks Completed)
- Check 5 (Diff computation + hybrid allowlist)
- Check 5b (Protected path approval gate)
- Check 5c (Universal merge approval gate)

This ordering ensures pre-merge verifiers (which cost real
resources) are not consumed by structurally malformed merges or by
merges that the operator hasn't approved at the human-gate layer.

#### Check 5d.6 — Failure codes

| Code | Trigger |
|---|---|
| `FAIL_INTEGRATION_MERGE_VERIFIER_BLOCKED { verifier_names, primary_witness_summary, candidate_merge_sha }` | Any `block_merge` pre-merge verifier reported `final_status ≠ "passed"`. Candidate is discarded; main is NOT advanced. |
| `FAIL_CANDIDATE_MERGE_COMPUTATION_FAILED { reason }` | The candidate merged tree could not be computed (malformed `commit_sha`, merge conflict the kernel can't represent as an orphan, disk-full at staging area, etc.). |

Both codes return to the Orchestrator. Neither is retryable
without operator action (the Orchestrator escalates per
[`agent-disagreement.md §6`](agent-disagreement.md)).

---

### Check 6a — Protected Path Approval Verification (conditional)
Only runs if `operator_approval_id: Some(id)` AND **either** `protected_hits` is non-empty
**or** `[orchestrator] all_merges_require_approval = true` (V2 — Check 5c):

- `escalations.id = id` must exist
- `escalations.state = 'Consumed'`
- `escalations.class ∈ { 'ProtectedPathMerge', 'MergeAuthorization' }` (the latter
  is the V2 universal-approval class introduced by Check 5c)
- `escalations.session_id = current_orchestrator_session_id`
- `escalations.commit_sha = commit_sha` (approvals are commit-SHA-specific — an approval
  for one merge commit cannot be reused for a different commit SHA)

Additionally, when `protected_hits` is non-empty, the consumed escalation MUST be of
class `'ProtectedPathMerge'` (a `MergeAuthorization` approval does not satisfy a
protected-path requirement; the operator must explicitly approve the protected paths).

Failure: `FAIL_ESCALATION_NOT_CONSUMED`, `FAIL_ESCALATION_CLASS_MISMATCH`, or
`FAIL_APPROVAL_SHA_MISMATCH`.

---

### Check 6b — Conflict Escalation Verification (conditional)
Only runs if `resolved_via_escalation: Some(id)`:
- `escalations.id = id` must exist in the database
- `escalations.state = 'Consumed'`
- `escalations.class = 'MergeConflict'`
- `escalations.session_id = current_orchestrator_session_id`

Failure: `FAIL_ESCALATION_NOT_CONSUMED` or `FAIL_ESCALATION_CLASS_MISMATCH`.

**Both Check 6a and 6b can be required simultaneously** (a merge that both touches a
protected path AND had a conflict resolution). Both escalation IDs must be present and
valid in this case.

### Check 7 — Idempotency Guard
If a previous `IntegrationMerge` for this initiative already advanced main to `commit_sha`
(i.e., `initiatives.current_sha = commit_sha`), the Kernel returns `OK_ALREADY_APPLIED` —
not an error. This is an idempotent success. The Orchestrator can re-submit the same
`IntegrationMerge` safely after a crash-recovery without causing a double-merge.

If `commit_sha` differs from `initiatives.current_sha` and is not a descendant of it
(Check 3), this is `FAIL_ANCESTRY_VIOLATION`.

### Check 8 — Database Commit (INV-STORE-02 Atomicity)

Check 8 performs the merge as a three-phase operation: a SQLite "intent" commit, the git work, and a SQLite "applied" update. The full ordering, failure modes, and crash-recovery semantics are specified in §11 Transactional Boundary: SQLite ↔ Git. Check 8 itself implements only Phase 1 (SQLite intent); Phases 2 and 3 are dispatched immediately afterward by the merge handler.

**Phase 1** (this Check): single `BEGIN IMMEDIATE` transaction.

```sql
-- Pre-flight: assert no in-flight git apply is pending for this initiative.
-- If git_apply_pending = 1, recovery (§11.3) must run first; this Check returns
-- FAIL_GIT_APPLY_PENDING to surface the inconsistency.
SELECT git_apply_pending FROM initiatives WHERE id = :initiative_id;

-- Commit the merge intent.
UPDATE initiatives
   SET current_sha = :commit_sha,
       git_apply_pending = 1                   -- recovery driver flag (§11)
 WHERE id = :initiative_id;
INSERT INTO audit_events (kind, ...) VALUES ('IntegrationMergeCompleted', ...);
UPDATE subtask_activations
   SET merge_included = 1
 WHERE task_id IN (:merged_task_ids...);
```

**Phases 2 and 3** (dispatched after Phase 1 commits, NOT in this Check): see §11.2.

```sql
# Phase 2 (idempotent domain commit — delegated to DomainAdapter)
ctx.domain.commit(
    &Snapshot { content_hash: commit_sha_to_content_hash(commit_sha), ... },
    &cred_proxy,                  // from per-session credential lease
    &CommitContext { initiative_id, main_repo: &main_repo_path, ... },
)?;

# Phase 3 (single SQLite UPDATE)
UPDATE initiatives SET git_apply_pending = 0 WHERE id = :initiative_id;
```

`GitAdapter::commit` (the V2 reference impl in `crates/raxis-domain-git/src/lib.rs`) executes:
```bash
git -C <main_repo> fetch <orchestrator_worktree> <commit_sha>
git -C <main_repo> merge-base --is-ancestor <live_target_ref_tip> <commit_sha>
# If true: update-ref <target_ref> <commit_sha>.
# If false: synthesize a deterministic conflict-free merge commit, then update-ref.
```
under the main-worktree lock, plus (when `[git_push]` is configured per §14) an upstream push via the credential proxy. Other adapters (`TradingAdapter::commit`, `HealthcareAdapter::commit`) substitute their own canonical-state write here without touching the kernel handler.

The handler dispatches Phase 2 + Phase 3 inline before returning the response to the Orchestrator. If the kernel crashes during Phase 2 or between Phase 2 and Phase 3, recovery on next startup re-runs the missing phases (§11.3).

**Idempotency contract.** `DomainAdapter::commit` MUST return `Err(DomainError::AlreadyApplied { receipt })` if invoked a second time for the same `Snapshot.content_hash` ([`extensibility-traits.md §2.7`](extensibility-traits.md) conformance property #5). The recovery path of §11.3 relies on this: re-running Phase 2 after a crash either re-executes (idempotent fetch + update-ref) or short-circuits via `AlreadyApplied`, both of which leave main at `commit_sha`.

---

## 5. Multi-Task Merge Sequencing

### When There Is One IntegrationMerge Per Initiative

The simplest case: all sub-tasks complete before the Orchestrator submits any merge. The
Orchestrator waits for `AllReviewersPassed` for every sub-task, then merges all branches
in a single `git merge` chain and submits one `IntegrationMerge` covering all sub-tasks.

```text
[A: Complete] [B: Complete] [C: Complete]
                                 │
                    Orchestrator merges A, B, C
                                 │
             IntegrationMerge { merged_task_ids: [A, B, C] }
                                 │
                    main → final_sha
```

### When There Are Multiple IntegrationMerge Submissions (Wave Model)

In a multi-wave initiative where some sub-tasks depend on others, the Orchestrator may
submit `IntegrationMerge` between waves:

```text
Wave 1: [A: Complete] [B: Complete]
  → IntegrationMerge { merged_task_ids: [A, B], commit_sha: "sha1" }
  → main → sha1

Wave 2 (activated after sha1):
  [C: Complete]  ← depends on A, B being in main
  → IntegrationMerge { merged_task_ids: [C], commit_sha: "sha2" }
  → main → sha2
```

Between waves, the Orchestrator's base SHA advances from the initiative's `initial_sha`
to `sha1`. Wave 2 sub-tasks' clones are provisioned from `sha1` — they see Wave 1's work.

**Key rule:** After `IntegrationMerge` is admitted and main advances, the Orchestrator's
next `IntegrationMerge` must descend from the new `current_sha`. The Orchestrator must
`git pull` or `git merge FETCH_HEAD` from the updated main before starting Wave 2 merges.
The Kernel's ancestry check (Check 3) enforces this: if the Orchestrator submits a Wave 2
`IntegrationMerge` that doesn't descend from `sha1`, the check fails.

### Merge Order Within a Wave

When the Orchestrator merges multiple sub-task branches in a single wave, the order in
which it runs `git merge` affects the resulting merge commit's tree. The Kernel does not
prescribe a specific merge order — only the final diff (Check 5) is enforced.

**Recommended practice (in Orchestrator system prompt):** Merge sub-tasks in the order
they appear in `merged_task_ids` as returned by `KernelPush::AllReviewersPassed`. This
produces a deterministic and auditable merge tree. The Orchestrator's non-negotiable
system prompt includes this instruction explicitly.

---

## 6. Target-Ref Advancement Semantics

The Kernel always uses `git update-ref` to publish the final SHA. The final SHA is
selected by the git domain adapter:

- If the submitted `commit_sha` descends from the live `target_ref` tip, the final SHA is exactly `commit_sha`.
- If the live `target_ref` tip advanced concurrently and merges cleanly with `commit_sha`, the final SHA is a deterministic host-side merge commit whose parents are the live tip and `commit_sha`.
- If the concurrent live tip conflicts with `commit_sha`, the adapter fails closed and the target ref is untouched.

**Why the host-side merge is allowed only for concurrent live-tip preservation:** The
Orchestrator still owns semantic integration of the initiative's executor commits. The
host-side merge exists only to preserve work that another already-admitted initiative
landed after this initiative's base was minted. It uses fixed author/committer identity
(`RAXIS Kernel`), a fixed message, and deterministic dates derived from the submitted
candidate, so retries and crash recovery do not require inference or arbitrary operator
input.

**When the result is a fast-forward on the target ref:** If only one sub-task's branch is in
the wave AND no cross-cutting artifacts were modified, `commit_sha` may be identical to
the sub-task's `completed_sha` — a fast-forward with no merge commit at all. The Kernel
handles this identically to a true merge commit: the ancestry check passes (the sub-task
commit descends from base), and `git update-ref` advances the target ref.

---

## 7. Audit Events

### `IntegrationMergeCompleted`

Emitted by the Kernel in the same transaction as the `current_sha` update (Check 8):

```rust
AuditEventKind::IntegrationMergeCompleted {
    initiative_id:          Uuid,
    session_id:             Uuid,       // Orchestrator's session
    commit_sha:             String,
    previous_sha:           String,     // base_sha before this merge
    merged_task_ids:        Vec<TaskId>,
    operator_assisted:      bool,       // true if resolved_via_escalation is Some
    escalation_id:          Option<EscalationId>,
    hybrid_allow_computed:  Vec<String>, // the effective allowlist used for Check 5
    plan_bundle_sha256:     String,     // links to the signed plan bundle (INV-05; per plan-bundle-sealing.md §8.2). For legacy V1 initiatives this field carries plan_artifact_sha256 (the SHA-256 of plan.toml bytes); for V2 initiatives it is the canonical bundle hash.
    policy_epoch:           u64,
}
```

**Why `hybrid_allow_computed` is in the event:** An auditor can independently verify that
the paths touched in `commit_sha` were within the recorded hybrid allowlist without needing
to re-run the diff computation. The event is self-contained for forensic reconstruction.

### `InitiativeCompleted` (follows final IntegrationMerge)

If the `IntegrationMerge` covers all remaining sub-tasks and the DAG has no more pending
tasks, the Kernel emits `InitiativeCompleted` in the same transaction:

```rust
AuditEventKind::InitiativeCompleted {
    initiative_id:  Uuid,
    final_sha:      String,
    total_tasks:    u32,
    total_cost:     u64,    // aggregate admission units consumed
    duration_secs:  u64,    // wall-clock from InitiativeCreated to InitiativeCompleted
}
```

---

## 8. Orchestrator's Merge Workflow (Step-by-Step)

> **V2 amendment.** The Orchestrator NNSP is **kernel-pinned bytes**
> per `INV-PLANNER-HARNESS-06.3` ([`planner-harness.md §4.8`](planner-harness.md)); the
> normative source for the Orchestrator's merge workflow is
> [`kernel-mechanics-prompt.md §3.2`](kernel-mechanics-prompt.md)'s
> `[KERNEL: INTEGRATION MERGE PROTOCOL]` and
> `[KERNEL: CONFLICT RESOLUTION PROTOCOL]` blocks, which the kernel
> binary embeds as `ORCHESTRATOR_NNSP_BYTES`. The text below is
> retained for historical context and accurately summarizes the
> *bypass-and-escalate* pre-V2 conflict path; the V2 NNSP additionally
> permits **in-Orchestrator semantic resolution** of trivial conflicts
> (criteria T1–T4 in [`kernel-mechanics-prompt.md §3.2`](kernel-mechanics-prompt.md)) using `bash`,
> `git`, and `edit_file` from the kernel-canonical
> `raxis-orchestrator-core` image (`INV-PLANNER-HARNESS-05`). The
> path-allowlist constraints in §4 (Check 5 / `hybrid_effective_allow`)
> apply to the Orchestrator's edits unchanged — semantic resolution
> changes the *triviality threshold* for escalation, not the
> *kernel admission gate* on what may land in the merge commit.

The Orchestrator's non-negotiable system prompt includes this procedure verbatim. It is
the mechanical sequence the Orchestrator must follow when it receives
`KernelPush::AllReviewersPassed { task_id }`:

```yaml
1. Confirm all expected sub-tasks for this wave have sent AllReviewersPassed.
   (Do not merge a partial wave — wait for all expected tasks.)

2. For each sub-task in merge order:
   a. git fetch /workspace/.raxis/bundles/<task_id>.bundle
   b. git merge refs/raxis/subtasks/<task_id>
   c. If MERGE_HEAD exists after merge (merge commit):
      - Write a descriptive merge commit message: "Merge <task_id>: <brief description>"
   d. If git merge exits with conflicts:
      - V2 update: Apply triviality criteria T1–T4 from
        kernel-mechanics-prompt.md §3.2 [KERNEL: CONFLICT RESOLUTION PROTOCOL].
        - If trivial (e.g., additive import / use / require collisions, struct field
          reordering, function signature reordering, syntactic-only conflicts where
          both sides' additions can be retained verbatim and the merged result
          parses cleanly):
          - For each conflict file: read the file, edit_file to replace conflict
            marker blocks with the merged text, git add the file.
          - git commit (message: "Orchestrator: trivial merge of <task_a> + <task_b> ...")
          - Continue the wave merge (return to step 2 for the next sub-task).
        - If non-trivial (logical contradiction, deleted-vs-modified, adjacent
          edits to the same expression, ambiguous semantic intent):
          - Run: git merge --abort
          - Submit EscalationRequest { class: MergeConflict, context: <conflict_description> }
          - STOP. Wait for KernelPush::EscalationResolved before retrying.

3. After all sub-tasks merged:
   a. Run: git log --oneline <base_sha>..HEAD  (verify the merge chain looks correct)
   b. Record HEAD as <merge_sha>
   c. Submit: IntentKind::IntegrationMerge {
        commit_sha: <merge_sha>,
        merged_task_ids: [<task_ids>],
        resolved_via_escalation: None,  // or Some(id) if an escalation was used
      }

4. On FAIL_ANCESTRY_VIOLATION:
   - Run: git pull (pull the current main into the Orchestrator's clone)
   - Retry from step 2 with the updated base.

5. On FAIL_PATH_POLICY_VIOLATION { path }:
   - This is a plan error — a sub-task modified files outside its allowlist,
     OR (V2) the Orchestrator's own conflict-resolution edits in step 2d landed
     a path outside the IntegrationMerge's hybrid_effective_allow.
   - Submit: EscalationRequest { class: PlanViolation, context: "path <path> found in merge
     commit is outside declared allowlist" }
   - STOP. Do not retry without operator guidance.
```

**Note on step 2d — conflict detection:** `git merge` exits with status 1 when there are
conflicts. The Orchestrator must detect this and either (V2) semantically resolve trivial
conflicts in-place per the criteria above, or abort and escalate. **In no case** may the
Orchestrator commit a file containing `<<<<<<<` / `=======` / `>>>>>>>` conflict markers —
such a commit is syntactically a valid git commit, but the resulting code is broken and
the path allowlist check (Check 5) cannot detect the marker contents. The Orchestrator's
NNSP §3.2 explicitly forbids committing conflict-marked files.

**Note on V2 semantic resolution and the path-allowlist gate.** The Orchestrator's
in-VM `edit_file` invocations during conflict resolution are **not** themselves
kernel-mediated — they are tool calls inside the Orchestrator's RW workspace per
Step 24b of [`v2-deep-spec.md`](v2-deep-spec.md). The kernel's enforcement happens at IntegrationMerge
admission (Check 5): the diff between `base_sha` and `commit_sha` is computed
host-side, and every touched path is checked against `hybrid_effective_allow`. If the
Orchestrator semantically resolved a conflict by editing a file that is *not* in any
sub-task's allowlist and not in the `[orchestrator] integration_paths` set, the
resulting merge commit will be rejected at Check 5 with `FAIL_PATH_POLICY_VIOLATION`,
even though the in-VM edits succeeded. This is intentional: the FSM bounds the
Orchestrator's authority, not its in-VM intelligence. Operators who want the
Orchestrator to be able to semantically resolve conflicts touching cross-cutting paths
(e.g., a generated file that multiple sub-tasks touch) must declare those paths in
`plan.toml [orchestrator] integration_paths`.

---

## 9. Post-Merge State

After `IntegrationMergeCompleted` is emitted:

| State | Before merge | After merge |
|---|---|---|
| `initiatives.current_sha` | `base_sha` (or previous merge SHA) | `commit_sha` |
| `main` branch in main repo | `base_sha` | `commit_sha` |
| `subtask_activations.merge_included` | 0 for merged tasks | 1 for merged tasks |
| Orchestrator's clone `HEAD` | `commit_sha` (Orchestrator produced it) | Unchanged |
| Orchestrator's base SHA for next wave | The previous `initiatives.current_sha` | Updated to `commit_sha` |

The Orchestrator does **not** need to pull main after a successful `IntegrationMerge` —
it already has `commit_sha` in its local clone. The Kernel's `current_sha` advance is the
authoritative record; the Orchestrator's clone is the source of truth for the commit.

---

## 10. Edge Cases

### What If the Main Branch Has Advanced Since the Initiative Started?

The initiative records `initial_sha` at `approve_plan` time. If another initiative's
`IntegrationMerge` advances main between `approve_plan` of this initiative and this
initiative's first `IntegrationMerge`, the ancestry check (Check 3) will fail:
`commit_sha` descends from `initial_sha`, but `base_sha` (= the current main HEAD)
has advanced beyond `initial_sha`.

**Resolution:** The Orchestrator must rebase or merge main into its clone:
```bash
git fetch origin main
git merge origin/main
```
This produces a new merge commit that descends from the current main. The Orchestrator
re-submits `IntegrationMerge` with the new SHA. The Kernel's ancestry check now passes.

This is the standard git multi-user workflow — RAXIS does not eliminate the need to
integrate concurrent changes, it only enforces that the integration goes through the
Kernel's admission gate.

### Partial Wave — A Sub-Task in the Wave Failed

If sub-task A completed (Reviewer approved) but sub-task B in the same wave failed
(exhausted `max_review_rejections` or `max_crash_retries`), the Orchestrator must decide
whether to submit a partial `IntegrationMerge { merged_task_ids: [A] }` or escalate.

**RAXIS position:** The Orchestrator may submit a partial `IntegrationMerge` if A's work
is independently useful. The Kernel admits it if A's `completed_sha` satisfies the ancestry
and path checks. B is left in Failed state; the initiative may complete with a partial
result. The `InitiativeCompleted` audit event records `total_tasks` vs. tasks included in
merges, making the partial completion visible.

Whether a partial completion is acceptable is an operator-level policy decision, not a
Kernel-enforced rule. The operator sets `max_review_rejections` and `max_crash_retries` to
express their quality bar.

### Double-Submission of the Same SHA

Handled by Check 7 (idempotency guard). If the Orchestrator crashes after the Kernel
commits the `IntegrationMerge` but before the Orchestrator records the success, it will
re-submit on recovery. The Kernel returns `OK_ALREADY_APPLIED` and the Orchestrator
continues normally. No duplicate `IntegrationMergeCompleted` event is emitted.

---

## 11. Transactional Boundary: SQLite ↔ Git

Check 8 has two distinct durable side effects:

1. **SQLite commit** — `initiatives.current_sha` advances; `IntegrationMergeCompleted` audit event is recorded; `subtask_activations.merge_included` flags are set.
2. **Git operation** — `git fetch` from the Orchestrator's worktree pulls the new commit objects into `main_repo`; `git update-ref refs/heads/main <commit_sha>` advances the local main ref.

These two operations cannot be made atomic. SQLite has no awareness of git, and `gix` does not participate in SQLite's transaction. There is always a window between them. This section specifies the ordering, the failure modes, and the recovery semantics that restore consistency after a crash.

The corresponding cross-reference from [`key-revocation.md §7.5`](key-revocation.md) Case C points here: when a session is revoked while an `IntegrationMerge` is in flight, the revocation interacts with whichever phase the merge has reached.

### 11.1 Ordering: SQLite First, then Git, then SQLite Again

The Kernel uses a three-phase model:

| Phase | Operation | Durable | Idempotent |
|---|---|---|---|
| 1 | SQLite `BEGIN IMMEDIATE`: UPDATE `current_sha`, set `git_apply_pending = 1`, INSERT audit event, UPDATE `merge_included`. Single transaction, atomic on commit. | Yes | Yes (Check 7 idempotency guard) |
| 2 | Git: `git fetch <orchestrator_worktree> <commit_sha>`; `git update-ref refs/heads/main <commit_sha>`. | Yes (writes to main_repo on disk) | Yes (re-fetching same SHA and re-updating ref to same SHA are no-ops) |
| 3 | SQLite UPDATE: `git_apply_pending = 0`. Single statement, no transaction wrapper needed. | Yes | Yes |

The `git_apply_pending` column (new in V2) is the recovery driver flag. It transitions `0 → 1` in Phase 1 and `1 → 0` in Phase 3. Between phases, it is `1` and signals to startup recovery that Phase 2 may be incomplete.

```sql
-- DDL addition to initiatives table
ALTER TABLE initiatives ADD COLUMN git_apply_pending INTEGER NOT NULL DEFAULT 0;

CREATE INDEX idx_initiatives_pending_git
    ON initiatives(id)
    WHERE git_apply_pending = 1;
```

The partial index makes startup recovery's scan O(in-flight merges), not O(all initiatives).

### 11.2 Failure Modes

There are five distinct failure points between Phase 1 begin and Phase 3 complete:

| # | Failure point | Observable state after kernel crash | Recovery |
|---|---|---|---|
| 1 | Crash before Phase 1 commits | SQLite unchanged; git unchanged. No partial work. | None. The merge effectively never happened. Orchestrator may resubmit. |
| 2 | Crash after Phase 1 commits, before Phase 2 starts | SQLite: `current_sha = commit_sha`, `git_apply_pending = 1`. Git: `refs/heads/main` still at base_sha. | §11.3 Case A — re-run Phase 2 from worktree. |
| 3 | Phase 2 `git fetch` fails (e.g., orchestrator worktree disk error, SHA not present) | SQLite: as above. Git: `refs/heads/main` still at base_sha; objects not fetched. | §11.3 Case A — retry; if persistently fails, transition initiative to `Blocked`. |
| 4 | Phase 2 `git update-ref` fails (rare; refs/heads/main became unwritable) | SQLite: as above. Git: objects fetched but ref not updated. | §11.3 Case A — re-run update-ref step; the fetch portion is a no-op. |
| 5 | Crash after Phase 2 completes, before Phase 3 commits | SQLite: as above. Git: `refs/heads/main = commit_sha` (fully consistent on the git side). | §11.3 Case B — verify git state, then run Phase 3. |

In all cases except #1, the `git_apply_pending = 1` flag in SQLite is the durable signal that drives recovery.

### 11.3 Recovery on Startup

After policy load and after [`key-revocation.md §5.3`](key-revocation.md) reconciliation, before accepting new IPC connections, `kernel/src/startup.rs` runs the merge-consistency recovery pass:

```text
SELECT id, current_sha, main_repo_path
  FROM initiatives
 WHERE git_apply_pending = 1;

for each row i:
    db_sha = i.current_sha
    git_sha = read refs/heads/main in i.main_repo_path

    case A — db_sha != git_sha (Phase 2 partially or fully missed):
        // Find the originating Orchestrator worktree from the audit event.
        SELECT s.worktree_path
          FROM audit_events e
          JOIN sessions s ON s.id = e.session_id
         WHERE e.kind = 'IntegrationMergeCompleted'
           AND e.initiative_id = i.id
           AND e.commit_sha = db_sha
         ORDER BY e.seq DESC LIMIT 1;

        if worktree_path exists on disk and contains db_sha as a reachable commit:
            git_fetch(main_repo_path, worktree_path, db_sha)
            git_update_ref(main_repo_path, "refs/heads/main", db_sha)
            verify: read refs/heads/main == db_sha   // assertion
            UPDATE initiatives SET git_apply_pending = 0 WHERE id = i.id
            INSERT audit_events (kind = 'GitConsistencyRepaired', initiative_id = i.id,
                                 db_sha, previous_git_sha = git_sha)
        else:
            // Orchestrator worktree was GC'd, deleted, or corrupted before
            // git apply completed. We have no source for the commit objects.
            INSERT audit_events (
                kind = 'SecurityViolation',
                violation_kind = 'GitStateInconsistent',
                initiative_id = i.id,
                detail = json!({
                    "db_sha": db_sha,
                    "git_sha": git_sha,
                    "reason": "OrchestratorWorktreeMissing"
                })
            )
            UPDATE initiatives SET state = 'Blocked',
                                   failure_reason = 'GitInconsistent'
                          WHERE id = i.id
            // Do NOT clear git_apply_pending; the inconsistency persists in the
            // record until operator intervenes.

    case B — db_sha == git_sha (Phase 2 fully succeeded, only Phase 3 was missed):
        UPDATE initiatives SET git_apply_pending = 0 WHERE id = i.id
        INSERT audit_events (kind = 'GitConsistencyVerified',
                             initiative_id = i.id, sha = db_sha)
```

Recovery is idempotent: running it twice on the same state produces the same final state. `git_fetch` and `git_update_ref` are individually idempotent (re-fetching a SHA already present is a no-op; updating a ref to the value it already has is a no-op). The SQLite UPDATEs are also idempotent.

**Recovery runs before IPC accepts new connections.** This guarantees that no new IntegrationMerge for the same initiative can be admitted while a previous one is still pending git apply — the new admission would otherwise see SQLite's `current_sha` ahead of git's `refs/heads/main` and produce a Check 3 ancestry violation.

### 11.4 Worktree Retention Requirement

The recovery procedure depends on the originating Orchestrator's worktree being available on disk for the duration of `git_apply_pending = 1`. This adds a constraint on worktree garbage collection that is parallel to (but distinct from) the forensic retention rule in [`key-revocation.md §7.4`](key-revocation.md):

**INV-MERGE-WORKTREE-RETAIN.** A session's worktree must NOT be garbage-collected while any initiative referencing the session has `git_apply_pending = 1`.

The worktree GC implementation must check this before removing a worktree:

```sql
SELECT 1
  FROM initiatives i
  JOIN sessions s ON s.initiative_id = i.id
 WHERE s.worktree_path = ?
   AND i.git_apply_pending = 1
 LIMIT 1;
```

If any row returns, the worktree is held until `git_apply_pending` clears. In normal operation this is a sub-second window between Phase 2 and Phase 3; the GC essentially never blocks. The check exists to handle the crash-recovery window, where a worktree may need to be retained for as long as the kernel is down.

This complements (does not replace) the forensic retention from [`key-revocation.md §7.4`](key-revocation.md). Forensic retention applies to terminated sessions for 30 days; INV-MERGE-WORKTREE-RETAIN applies to any session whose worktree is needed for an in-flight merge regardless of session state.

### 11.5 Cross-Cutting: Subsequent Operations Must Check `git_apply_pending`

Operations that read git state must be aware that `current_sha` may be ahead of `refs/heads/main` during the Phase 1 → Phase 3 window:

- **Subsequent IntegrationMerge admission** (Check 8 Phase 1 pre-flight): asserts `git_apply_pending = 0`. If 1, returns `FAIL_GIT_APPLY_PENDING` and the caller should retry shortly. This prevents wave 2 from beginning before wave 1's git is applied. In normal operation this assertion always passes (Phase 3 completes inline within the same handler call); it can fail only after a crash, in which case recovery on the next startup clears the flag.
- **Push to remote** (§14 Push Approval Gate): waits for `git_apply_pending = 0` before reading `refs/heads/main` and pushing. A push during the pending window would push the OLD sha, which is wrong. The push handler polls the flag with a short timeout (default 5s) before either pushing or returning a transient error.
- **Audit replay tooling**: when a tool reconstructs git state at a historical timestamp, it should consult `git_apply_pending` at that timestamp. If 1, the tool reports both `current_sha` (kernel-authoritative) and `refs/heads/main` at that moment, and explicitly notes the pending git apply.

### 11.6 Why Not Reverse Ordering (Git First, SQLite Second)

Considered: do `git fetch` + `git update-ref` first, then commit SQLite. Rejected:

- **No durable marker for recovery.** If git completes but the kernel crashes before SQLite commits, there is no kernel-side record that the merge happened. Recovery has nothing to drive from. Detection would require scanning `main_repo`'s reflog and trying to reconstruct intent, which is fragile and breaks the "audit log is the source of truth" invariant.
- **Audit event ordering inversion.** The `IntegrationMergeCompleted` audit event records that the merge was admitted. If git happens first and audit is written later, an external observer monitoring git could see the new commit before the audit log says it was admitted — a transient inversion.
- **Main ref poisoning on rejection.** If SQLite commit fails for any reason (transient I/O error, foreign-key violation surfaced late, ...), the git ref is already advanced and cannot easily be retracted. Rolling back a git ref requires writing the old SHA, which is itself a state change that would need its own audit record.
- **Idempotency surface.** Putting the non-transactional side AFTER the transactional one means the only thing that needs idempotency-on-recovery is the git side, which is naturally idempotent. The reverse forces SQLite to be re-runnable, which it is not designed to be (no `INSERT OR IGNORE` for audit events that should be append-once).

### 11.7 Why Not Single-Phase (No `git_apply_pending` Flag)

Considered: just commit SQLite, then run git, with no marker. Recovery scans for `current_sha != refs/heads/main` mismatches and replays. Rejected:

- **Mismatch is ambiguous.** A mismatch could mean "Phase 2 didn't complete" (recoverable) or "git was tampered with externally" (security concern, not recoverable). Without a marker explicitly saying "we expected to apply and didn't," recovery cannot distinguish.
- **No way to enforce worktree retention.** Worktree GC needs to know whether a worktree is still required for an in-flight git apply. Without `git_apply_pending`, the GC has to make a conservative assumption (never GC, or always GC and risk losing recovery objects). Neither is acceptable.
- **Subsequent-operation guard becomes guessing.** Phase 1 pre-flight (§11.5) needs to know whether the previous merge's git is applied. Without an explicit flag, it would have to compare `current_sha` against `refs/heads/main` on every IntegrationMerge admission, which requires a git read inside an SQLite transaction (cross-store I/O during a `BEGIN IMMEDIATE` lock — a concurrency hazard).

The `git_apply_pending` flag costs 1 byte per initiative row and resolves all three problems.

### 11.8 INV-MERGE-CONSISTENCY

For every initiative, exactly one of the following holds at any moment:

(a) **Consistent.** `initiatives.current_sha = refs/heads/main` AND `git_apply_pending = 0`.

(b) **Recoverable.** `initiatives.git_apply_pending = 1` AND there exists an `IntegrationMergeCompleted` audit event with `commit_sha = initiatives.current_sha` AND the Orchestrator worktree referenced by that event still exists on disk with `commit_sha` reachable.

(c) **Inconsistent (security violation).** Neither (a) nor (b). The kernel emits `SecurityViolation { kind: GitStateInconsistent }` and transitions the initiative to `Blocked`.

Where it is enforced:

- Check 8 Phase 1 pre-flight (§4 Check 8) asserts the previous merge satisfied (a) before beginning a new merge.
- Startup recovery (§11.3) detects (b) and either restores (a) by re-running Phase 2/3 or detects (c) and halts.
- Worktree GC (§11.4 INV-MERGE-WORKTREE-RETAIN) preserves the precondition for (b).

The invariant pairs with INV-PUSH-01 (kernel-push-protocol.md §12) and INV-KEY-08 (key-revocation.md §10) to give the kernel a consistent crash-recovery story across all three storage layers (SQLite, git, and KernelPush queue).

### 11.9 Audit Events Added

```rust
AuditEventKind::GitConsistencyRepaired {
    initiative_id:      Uuid,
    db_sha:             String,    // the SHA SQLite already committed to
    previous_git_sha:   String,    // what refs/heads/main was at, before recovery
    recovered_at_startup_run: Uuid, // links to StartupReconciliationCompleted
}

AuditEventKind::GitConsistencyVerified {
    initiative_id:      Uuid,
    sha:                String,    // current_sha == refs/heads/main at recovery
    recovered_at_startup_run: Uuid,
}

// Existing AuditEventKind::SecurityViolation gets a new sub-kind:
SecurityViolationKind::GitStateInconsistent {
    initiative_id:      Uuid,
    db_sha:             String,
    git_sha:            String,
    reason:             String,    // e.g., "OrchestratorWorktreeMissing"
}
```

These three events are the only places where the SQLite ↔ git boundary surfaces in the audit log. Their presence indicates a crash recovery occurred (which is operationally interesting but not necessarily a security incident); GitStateInconsistent specifically indicates an unrecoverable inconsistency requiring operator action.

### 11.10 Candidate Merged Tree Lifecycle (V2 — Pre-Merge Verifiers)

When Check 5d (per [`verifier-processes.md §15`](verifier-processes.md)) fires, the kernel
materializes a **candidate merged tree** as an orphan commit before
verifier-VM activation. Its lifecycle is bounded by Check 5d: it
exists only between `Check 5d.2` (creation) and either Check 5d.4
(verification verdict) or §11.10.4 (crash-recovery cleanup) — never
longer.

#### 11.10.1 New SQLite table: `integration_merge_attempts`

```sql
CREATE TABLE integration_merge_attempts (
    id                       TEXT PRIMARY KEY,            -- uuid; matches the IntegrationMerge intent's request_id
    initiative_id            TEXT NOT NULL REFERENCES initiatives(id),
    orchestrator_session_id  TEXT NOT NULL,
    requested_commit_sha     TEXT NOT NULL,
    candidate_merge_sha      TEXT,                        -- NULL until Check 5d.2 succeeds
    state                    TEXT NOT NULL,
    -- 'AwaitingPreMergeVerifiers' | 'PreMergeVerifiersPassed'
    -- | 'BlockedByPreMergeVerifier' | 'CompletedAdvanceApplied'
    -- | 'DiscardedCandidateOnly' (Check 5d.2 failed) | 'DiscardedCrashRecovery'
    discard_reason           TEXT,                        -- NULL unless discarded; see §11.10.4
    created_at               INTEGER NOT NULL,            -- epoch ms
    finalized_at             INTEGER                      -- epoch ms; set on terminal state transition
);

CREATE INDEX idx_imerge_attempts_initiative ON integration_merge_attempts(initiative_id);
CREATE INDEX idx_imerge_attempts_open ON integration_merge_attempts(initiative_id)
    WHERE state IN ('AwaitingPreMergeVerifiers', 'PreMergeVerifiersPassed');
```

This table is **distinct** from `initiatives.git_apply_pending`. The
existing flag governs the SQLite-intent → git-apply boundary for
the eventual main advance (§11.1); this table governs the
candidate-merge-tree → pre-merge-verifier boundary, which is a
strictly earlier phase of the pipeline.

#### 11.10.2 Ordering relative to §11.1

```sql
Phase 0 (V2 — Check 5d):
  - INSERT into integration_merge_attempts (state = 'AwaitingPreMergeVerifiers',
                                             candidate_merge_sha = <orphan>)
  - Spawn pre-merge verifier VMs (per verifier-processes.md §4.2 with
    /workspace mounted from candidate_merge_sha)
  - Wait for all to complete
  - On block_merge failure: §11.10.3 discard; return failure
  - On all-pass: UPDATE state = 'PreMergeVerifiersPassed'; proceed to Check 6a

Phase 1 (Check 8 / §11.1 unchanged):
  - SQLite intent: BEGIN IMMEDIATE; INSERT initiative_merges row;
                                     UPDATE initiatives SET git_apply_pending = 1; COMMIT
Phase 2 (§11.1 unchanged):
  - git work: update main ref to candidate_merge_sha
Phase 3 (§11.1 unchanged):
  - SQLite finalize: UPDATE initiatives SET current_sha = ..., git_apply_pending = 0
  - UPDATE integration_merge_attempts SET state = 'CompletedAdvanceApplied',
                                          finalized_at = :now
                                      WHERE id = :integration_merge_id
```

The candidate merged tree is the **input** to phase 1; once phase
3 finalizes, it becomes reachable from `refs/heads/main` and is
no longer an orphan. Until phase 3 finalizes, the candidate is
discarded on any failure path (verifier failure, candidate-merge
computation failure, or crash recovery per §11.10.4).

#### 11.10.3 Discard procedure

```rust
fn discard_candidate_merge_tree(
    integration_merge_id: Uuid,
    candidate_merge_sha: &str,
    reason: DiscardReason,
) {
    let clone_dir = format!("{data_dir}/candidate_merges/{integration_merge_id}/");

    // 1. Delete the staging worktree.
    fs::remove_dir_all(&clone_dir).ok();

    // 2. Mark the attempt finalized.
    sqlx::query(
        "UPDATE integration_merge_attempts
            SET state = ?,
                discard_reason = ?,
                finalized_at = ?
          WHERE id = ?"
    )
    .bind(reason.terminal_state())          // 'BlockedByPreMergeVerifier' | 'DiscardedCandidateOnly' | 'DiscardedCrashRecovery'
    .bind(reason.as_str())
    .bind(now_epoch_ms())
    .bind(integration_merge_id)
    .execute(&db).await?;

    // 3. Targeted, immediate GC on main_repo (the parent that holds
    //    the orphan commit_sha now unreachable from any ref). Bounded
    //    in scope and runtime: --prune=now retires only the unreachable
    //    objects, the lock collision window with a concurrent
    //    IntegrationMerge phase 2 is detected and the call is skipped
    //    in that case. The periodic git_maintenance_main sweep
    //    (kernel-lifecycle.md §10.5.3) is the catch-all if this
    //    targeted call is skipped or fails.
    //    Without this immediate GC, the orphan commit pollutes
    //    main_repo's loose-object area for up to 6h (the periodic
    //    cadence) — long enough that a high-failure-rate burst of
    //    pre-merge verifiers can fill the disk before the periodic
    //    job runs. With it, the worst-case orphan-object retention
    //    window collapses to a single discard latency.
    if let Err(e) = git_gc_orphan(&main_repo_path()) {
        // Best-effort: log and continue; the periodic sweep will
        // catch it.
        warn!(target: "integration_merge",
              integration_merge_id = %integration_merge_id,
              error = %e,
              "git_gc_orphan failed; relying on periodic sweep");
    }

    // 4. Audit.
    emit AuditEventKind::CandidateMergeTreeDiscarded {
        integration_merge_id,
        candidate_merge_sha: candidate_merge_sha.to_string(),
        discard_reason: reason,
    };
}

/// Runs `git gc --prune=now --quiet` on a repository. Acquires the
/// repository's advisory lock with a short timeout; returns Err if the
/// lock is held by an in-flight phase-2 IntegrationMerge worker.
fn git_gc_orphan(repo_path: &Path) -> Result<(), GitGcError> {
    let lock = AdvisoryLock::acquire(repo_path, Duration::from_millis(250))
        .map_err(GitGcError::LockContended)?;
    let status = std::process::Command::new("git")
        .arg("-C").arg(repo_path)
        .args(["gc", "--prune=now", "--quiet"])
        .status()
        .map_err(GitGcError::Spawn)?;
    drop(lock);
    if !status.success() {
        return Err(GitGcError::ExitStatus(status));
    }
    Ok(())
}
```

`DiscardReason` values: `"verifier_blocked"` |
`"candidate_computation_failed"` | `"crash_recovery"` |
`"merge_aborted_by_operator"`.

The orphan commit on `main_repo` is reaped at one of three points,
each with a bounded retention window:

1. **Synchronous**: `git_gc_orphan` succeeds in step 3 above.
   Retention: ~`git gc` runtime, typically <1 s.
2. **Periodic**: `git_maintenance_main` runs (cadence: 6 h, or
   opportunistic on disk pressure). Retention: up to one cadence.
3. **Crash-induced**: `discard_candidate_merge_tree` was interrupted
   between steps 1 and 3 (e.g., kernel killed mid-discard). The next
   periodic sweep reaps the orphan; the SQLite row's `state` reflects
   the partial discard so the recovery flow in §11.10.4 doesn't try
   to salvage the candidate.

#### 11.10.4 Crash-recovery cleanup at startup

Recovery from [`kernel-lifecycle.md §7`](kernel-lifecycle.md) is extended to handle
in-flight pre-merge verifier runs. After the existing §11.3
recovery completes, the kernel:

```sql
-- Find every attempt left in a non-terminal state.
SELECT id, initiative_id, candidate_merge_sha
  FROM integration_merge_attempts
 WHERE state IN ('AwaitingPreMergeVerifiers', 'PreMergeVerifiersPassed')
   AND finalized_at IS NULL;
```

For each row:

1. Cross-reference against the verifier-VM cgroup scan from
   [`kernel-lifecycle.md §7`](kernel-lifecycle.md) orphan-VM cleanup. Any pre-merge
   verifier VM whose `RAXIS_INTEGRATION_MERGE_ID` matches this
   attempt is killed via `cgroup.kill` (already handled by the
   generic verifier-VM orphan cleanup; the pre-merge case requires
   no special handling at the VM layer).
2. If the candidate worktree at
   `candidate_merges/<integration_merge_id>/` still exists AND the
   attempt's state was `'PreMergeVerifiersPassed'`: the candidate
   is salvageable. The next admission of the same `IntegrationMerge`
   intent (idempotent per Check 7) will short-circuit at the
   `current_sha` check or rerun verifiers (the kernel re-runs
   verifiers conservatively, since the witness rows survived but
   the verifier-VM-side artifacts may not have been staged
   atomically).
3. Otherwise (state was `'AwaitingPreMergeVerifiers'` OR worktree
   is missing): discard the attempt with reason `"crash_recovery"`
   per §11.10.3. The Orchestrator's eventual re-submission of the
   `IntegrationMerge` intent will produce a fresh
   `integration_merge_id` and a fresh candidate merged tree.

This recovery procedure is idempotent — running it multiple times
on the same restart sequence converges to the same terminal states.

#### 11.10.5 Why a separate phase 0, not folded into Check 5b/5c

Pre-merge verifiers are **distinct in cost and authority** from
the human-approval gates at Checks 5b/5c:

- Human-approval gates resolve via operator IPC (low per-attempt
  cost; bounded by operator latency).
- Pre-merge verifiers resolve via VM execution (high per-attempt
  cost; bounded by verifier `timeout`).

Folding them into the same phase would allow expensive verifiers
to run on merges that the operator hasn't yet approved at the
human-gate layer — wasting cycles on merges that may be rejected
on grounds unrelated to verification. The strict ordering
`5b → 5c → 5d` ensures pre-merge verifiers consume resources only
on merges that the operator has already approved at the human
layer.

#### 11.10.6 Audit events added

```rust
AuditEventKind::CandidateMergeTreeCreated {
    integration_merge_id:  Uuid,
    candidate_merge_sha:   String,
    merged_task_ids:       Vec<TaskId>,
    matching_verifier_count: u32,
}

AuditEventKind::CandidateMergeTreeDiscarded {
    integration_merge_id:  Uuid,
    candidate_merge_sha:   String,                   // the SHA that was created and is now unreachable
    discard_reason:        DiscardReason,            // see §11.10.3
}

AuditEventKind::VerifierBlockedMerge {
    integration_merge_id:  Uuid,
    candidate_merge_sha:   String,
    verifier_names:        Vec<String>,
    primary_witness_summary: String,
}
```

`VerifierActivated` and `VerifierCompleted` (per
[`verifier-processes.md §11`](verifier-processes.md)) also fire for pre-merge verifier
spawns; these are the standard verifier audit events with
`hook_kind = "pre_merge"` and `integration_merge_id` set in place
of `task_id`.

---

## 12. Implementation Checklist

### 12.0 DomainAdapter integration (prerequisite)

The IntegrationMerge handler is rewritten on top of the `DomainAdapter` trait
([`extensibility-traits.md §2`](extensibility-traits.md)). Land these before §12.1 starts:

- [ ] Crate `crates/raxis-domain-git` exists and exports `GitAdapter` (per
      [`extensibility-traits.md §2.5`](extensibility-traits.md)).
- [ ] `kernel/src/handlers/merge.rs::handle_integration_merge` takes a
      `&HandlerContext` whose `ctx.domain: Arc<dyn DomainAdapter<...>>` is wired
      at boot (§9 of the traits spec).
- [ ] Check 2 (reachability) calls `ctx.domain.snapshot_exists(commit_sha)?` —
      a small helper added to `GitAdapter` that wraps `git cat-file -e`. (The
      trait does not need a new method; this is a `GitAdapter`-private helper
      callable through a domain-extension trait `SeDomainExt: DomainAdapter`.)
- [ ] Check 3 (ancestry) similarly delegates to `ctx.domain` via
      `SeDomainExt::is_ancestor(base_sha, commit_sha)`.
- [ ] Check 5 (touched-set) calls `ctx.domain.touched_resources(...)` and uses
      the returned `TouchedResources` (URI form) for the hybrid allowlist
      comparison; the SE adapter returns `path:///`-prefixed URIs that the
      kernel strips before matching.
- [ ] Check 8 Phase 2 calls `ctx.domain.commit(snapshot, &cred_proxy, &commit_ctx)?`
      and treats `Err(DomainError::AlreadyApplied { receipt })` as the success
      branch (§4 Check 8 idempotency contract above).

### 12.1 Mechanism

- [ ] Add `merged_task_ids: Vec<TaskId>` field to `IntegrationMerge` struct in
      `crates/types/src/operator_wire.rs`
- [ ] Implement `handle_integration_merge` in `kernel/src/handlers/merge.rs` (new file)
      with all 8 checks in order
- [ ] Add reachability check (Check 2) via `SeDomainExt::snapshot_exists`
- [ ] Add ancestry check (Check 3) via `SeDomainExt::is_ancestor`
- [ ] Add `merged_task_ids` validation against `subtask_activations` (Check 4)
- [ ] Implement hybrid allowlist computation (Check 5) consuming
      `DomainAdapter::touched_resources` output
- [ ] Add escalation verification branch (Check 6) in `handle_integration_merge`
- [ ] Add idempotency guard (Check 7) with `OK_ALREADY_APPLIED` response variant
- [ ] Implement atomic DB transaction (Check 8) Phase 1: `initiatives.current_sha` update +
      `subtask_activations.merge_included` update + audit event;
      Phase 2 dispatches `ctx.domain.commit(...)`; Phase 3 clears `git_apply_pending`
- [ ] Define `AuditEventKind::IntegrationMergeCompleted` with `hybrid_allow_computed`
- [ ] Define `AuditEventKind::InitiativeCompleted` with aggregate stats
- [ ] Add `OK_ALREADY_APPLIED` to `KernelResponse` enum in `crates/types/`
- [ ] Update Orchestrator system prompt template to include the 5-step merge workflow
      verbatim (including conflict abort instruction)
- [ ] Add multi-wave sequencing integration tests:
      - Single wave, single task (fast-forward case)
      - Single wave, multiple tasks (true merge commit case)
      - Multi-wave with base SHA advance between waves
      - Conflict → escalation → resolution → merge
      - Crash recovery (double-submission idempotency)
      - Partial wave (failed sub-task, partial IntegrationMerge)

### Pre-IntegrationMerge Verifier Execution (Check 5d, V2)

- [ ] Implement Check 5d in `handle_integration_merge` between Check 5c and Check 6a
      per §4 Check 5d.1–5d.6
- [x] Add `integration_merge_attempts` SQLite table per §11.10.1; DDL migration
      shipped as **Migration 11** in `raxis-store/src/migration.rs`
      (`render_migration_11_ddl`) — table identifier rendered through
      `Table::IntegrationMergeAttempts.as_str()` (INV-STORE-03);
      `state` and `discard_reason` CHECK constraints rendered through
      `IntegrationMergeAttemptState::ALL` /
      `IntegrationMergeAttemptDiscardReason::ALL` (`raxis-types::fsm`);
      cross-column CHECK enforces the four valid (state,
      discard_reason, finalized_at, candidate_merge_sha) shapes;
      partial index `idx_imerge_attempts_open` keys the §11.10.4
      recovery sweep. Seven dedicated migration tests
      (`migration_11_*`) pin: table creation, both CHECK clauses,
      cross-column shapes, partial-index existence, FK rejection of
      orphan rows, idempotency, single-transaction wrapping, and
      v=10→v=11 upgrade behaviour.
- [ ] Implement `compute_candidate_merge_tree(initiative_id, commit_sha, merged_task_ids)
      → Result<CandidateMergeSha, FailReason>` producing an orphan commit at
      `$RAXIS_DATA_DIR/candidate_merges/<integration_merge_id>/`
- [ ] Implement `applies_to_matches` and `environment_filter_matches` per
      [`verifier-processes.md §16.3`](verifier-processes.md) (cross-spec; lives in the verifier module)
- [ ] Spawn pre-merge verifier VMs with `RAXIS_VERIFIER_HOOK_KIND = "pre_merge"`,
      `RAXIS_INTEGRATION_MERGE_ID` set, `/workspace` mounted from candidate merged tree
- [ ] Implement gating algorithm per §4 Check 5d.4; emit `VerifierBlockedMerge` or
      proceed to Check 6a based on outcome
- [ ] Implement `discard_candidate_merge_tree` per §11.10.3 (worktree removal,
      SQLite update, audit emission)
- [x] Extend startup recovery ([`kernel-lifecycle.md §7`](kernel-lifecycle.md)) per §11.10.4 — handle
      attempts in `'AwaitingPreMergeVerifiers'` and `'PreMergeVerifiersPassed'`
      states; reconcile with verifier-VM cgroup orphan cleanup. **Implemented**
      as `recovery::reconcile_integration_merge_attempts` in
      `raxis-kernel/src/recovery.rs`, called from the same Step 6
      `recovery::reconcile` entry point that handles task sweeping —
      single bulk `UPDATE` inside one `BEGIN`/`COMMIT` (INV-STORE-02)
      folds every non-terminal row to `DiscardedCrashRecovery` with
      `discard_reason = 'crash_recovery'` and `finalized_at = now`.
      Verifier-VM cgroups are killed by the generic verifier-VM orphan
      cleanup (kernel-lifecycle.md §7); this sweep is the SQLite-row
      half. Six dedicated `recovery::tests::imerge_recon_*` tests pin
      the Awaiting fold path, the Passed fold path, terminal rows
      being left untouched, idempotency under repeated sweeps, the
      mixed-seed contract, and the empty-store no-op.
- [ ] Add audit events `CandidateMergeTreeCreated`, `CandidateMergeTreeDiscarded`,
      `VerifierBlockedMerge` per §11.10.6
- [ ] Add `FAIL_INTEGRATION_MERGE_VERIFIER_BLOCKED` and
      `FAIL_CANDIDATE_MERGE_COMPUTATION_FAILED` to `raxis-types::PlannerErrorCode`
- [ ] Tests:
      - Plan with no `[[plan.integration_merge_verifiers]]` and policy with no
        `[[integration_merge_verifiers]]` → Check 5d is no-op; merge proceeds to Check 6a
      - Plan with one `block_merge` verifier that passes → Check 5d.4 advances; main updated
      - Plan with one `block_merge` verifier that fails → `FAIL_INTEGRATION_MERGE_VERIFIER_BLOCKED`;
        candidate worktree removed; main NOT updated; no `initiative_merges` row written
      - Plan with one `warn_only` verifier that fails → merge proceeds; audit shows
        warning witness in the attempt's `verifier_witnesses`
      - Operator policy `[[integration_merge_verifiers]]` with `on_failure = "warn_only"`
        → admission rejected at policy load (operator declarations cannot downgrade)
      - Per-task verifier with `on_failure = "block_merge"` → `approve_plan` rejects with
        `FAIL_VERIFIER_INVALID_ON_FAILURE`
      - Pre-merge verifier with `on_failure = "block_review"` → `approve_plan` rejects
        with `FAIL_VERIFIER_INVALID_ON_FAILURE`
      - `applies_to = "task_set"` with intersection: spawns; without intersection: skipped
      - `applies_to = "last"` on intermediate merge: skipped; on final merge: spawns
      - `applies_to = "last"` with parallel branches: only the merge that drains the
        final remaining `Completed` task fires the verifier
      - Operator gate with `required_for_environments = ["production"]`: fires on
        production-bound merge; skipped on beta-bound merge
      - Crash recovery: kernel killed during pre-merge verifier execution → on restart,
        candidate worktree discarded with reason `"crash_recovery"`; orchestrator's
        re-submission produces fresh attempt
      - Crash recovery: kernel killed between `'PreMergeVerifiersPassed'` and Check 6a
        → on restart, attempt is salvageable; same `IntegrationMerge` re-submission
        re-runs Check 5d conservatively
      - Candidate merge computation fails (malformed `commit_sha`) → `FAIL_CANDIDATE_MERGE_COMPUTATION_FAILED`;
        no worktree left behind
      - Pre-merge verifier failure does NOT increment any task's review-round counter
        (no `INV-CONVERGENCE-01` interaction)

### Transactional Boundary (§11)

- [x] Add `git_apply_pending INTEGER NOT NULL DEFAULT 0` column to `initiatives` (DDL migration). **Implemented as migration 16 in `crates/store/src/migration.rs::apply_migration_16` / `render_migration_16_ddl`; SQL dump at `crates/store/migrations/16_v25_initiatives_git_apply_pending.sql`.**
- [x] Add partial index `idx_initiatives_pending_git ON initiatives(initiative_id) WHERE git_apply_pending = 1`. **Implemented in migration 16; covered by the `migration_sql_files_match_rendered_ddl` golden test.**
- [x] Update `handle_integration_merge` to set `git_apply_pending = 1` in Phase 1 SQLite transaction. **`kernel/src/handlers/intent.rs::run_phase_a` calls `raxis_store::views::initiatives::set_git_apply_pending` inside the same `BEGIN IMMEDIATE` block as the `current_sha` advance, asserting exactly-one-row.**
- [x] Update `handle_integration_merge` to dispatch Phase 2 (git fetch + update-ref) inline after Phase 1 commit. **`run_phase_b` invokes `raxis_domain_git::commit_merge_to_target_ref(main_repo_root, orchestrator_worktree, commit_sha, target_ref)` immediately after Phase 1 returns.**
- [x] Update `handle_integration_merge` to dispatch Phase 3 (`UPDATE git_apply_pending = 0`) inline after Phase 2 success. **`run_phase_c` calls `clear_git_apply_pending` before emitting `IntegrationMergeCompleted`; failure to clear is logged but does not roll back the successful git ref advance.**
- [x] Add Phase 1 pre-flight assertion: `SELECT git_apply_pending FROM initiatives WHERE id = ?`; if 1, return `FAIL_GIT_APPLY_PENDING`. **`run_phase_a` reads the column under `lock_sync()` BEFORE opening the SQLite transaction and rejects with `PlannerErrorCode::FailGitApplyPending` (added to `crates/types/src/error.rs`) when the flag is already set.**
- [x] Implement startup recovery in `kernel/src/recovery.rs` per §11.3 (Cases A, B, and C). **`recovery::reconcile_git_apply_pending` is invoked from `main.rs` Step 8a (after `KernelStarted`, before IPC accept) on a `spawn_blocking` task. Per-initiative outcomes are surfaced through `GitApplyRecoveryOutcome::{Repaired, Verified, Inconsistent}` and aggregated in `GitApplyRecoveryResult`. Six in-source integration tests (`recovery::git_apply_recovery_integration::*`) drive the production path through `DiskStore` + `AuditDir` + a real `git` CLI fixture (skip-on-no-git).**
- [x] Add `GitConsistencyRepaired { initiative_id, db_sha, previous_git_sha, target_ref }` audit event variant. **`crates/audit/src/event.rs`; emitted by `recovery::emit_repaired` after Case A's successful re-apply + flag clear.**
- [x] Add `GitConsistencyVerified { initiative_id, sha, target_ref }` audit event variant. **Same file; emitted by `recovery::emit_verified` after Case B's flag clear.**
- [x] Add `GitStateInconsistent { initiative_id, db_sha, git_sha, target_ref, reason }` audit event variant (kept distinct from `SecurityViolation` — this is a durability/recovery class violation, not a frame-validation class). **Same file; emitted by `recovery::emit_inconsistent` for Case C with `reason ∈ {orchestrator_worktree_missing, orchestrator_worktree_unreachable_commit, audit_record_missing}`.**
- [x] Add `FAIL_GIT_APPLY_PENDING` to the planner error code enum. **`crates/types/src/error.rs::PlannerErrorCode::FailGitApplyPending`; `Display` renders the canonical wire string `"FAIL_GIT_APPLY_PENDING"`.**
- [x] Update worktree GC to enforce INV-MERGE-WORKTREE-RETAIN (§11.4) — block GC of any worktree referenced by an initiative with `git_apply_pending = 1`. **Implemented in `kernel/src/worktree_gc.rs`** (`gc_session_worktree`) backed by `raxis_store::views::sessions::pending_initiative_for_session` (the §11.4 SQL: `SELECT i.initiative_id FROM initiatives i JOIN tasks t ON t.initiative_id = i.initiative_id WHERE t.session_id = ?1 AND i.git_apply_pending = 1 LIMIT 1`). Returns typed `WorktreeGcDecision::{Removed, NoWorktree, RetainedPendingMerge { blocking_initiative_id, .. }}`. Six in-source integration tests (real `DiskStore` + on-disk `<tempdir>/worktrees/<uuid>/` fixture): pending blocks, clear allows, unknown-session no-op, NULL `worktree_root` no-op, idempotent after removal, and "unblocks after pending flag clears" (drives the full Phase 1 → recovery → GC sequence).
- [x] Update push handler (§14) to wait for `git_apply_pending = 0` before reading `refs/heads/<target_ref>` (default 5s poll timeout, emit `PushFailed { category: "pending_git_apply" }` on timeout). **Implemented in `kernel/src/handlers/intent.rs::wait_for_git_apply_pending_clear` (50 ms poll interval, 5 s deadline). In the synchronous handler path Phase 3 already clears the flag two statements earlier, so the wait exits on its first iteration; the loop exists as a defensive guard for future code paths that move push to a background task. Four in-source tests cover: (a) immediate-return when already 0, (b) `Phase-3 clear` observed across threads, (c) deadline elapses without clear, (d) missing-initiative defaults to 0.**
- [x] Tests (all in-source unless noted):
      - **Crash between Phase 1 and Phase 2** ⇒ Case A re-runs Phase 2. `recovery::git_apply_recovery_integration::case_a_re_applies_phase_2_and_emits_repaired` (real `git` CLI fixture: builds a `repositories/main` repo + Orchestrator clone, seeds an `init` row with `git_apply_pending = 1` AND `IntegrationMergeCompleted` audit event, leaves `refs/heads/main` at base, runs `reconcile_git_apply_pending`, asserts the ref advances to `db_sha` and `GitConsistencyRepaired { previous_git_sha = base }` is emitted).
      - **Crash between Phase 2 and Phase 3** ⇒ Case B clears flag (no `GitConsistencyRepaired`). `recovery::git_apply_recovery_integration::case_b_clears_flag_and_emits_verified_when_target_already_at_db_sha` (pre-advances `refs/heads/main` to `db_sha` before the recovery sweep, asserts `GitConsistencyVerified` is emitted with no `Repaired` event).
      - **Worktree GC blocks during pending.** `worktree_gc::tests::retains_worktree_when_initiative_has_git_apply_pending` (real on-disk worktree fixture: seeds the §11.4 SQL triangle with `git_apply_pending = 1`, calls `gc_session_worktree`, asserts `WorktreeGcDecision::RetainedPendingMerge` AND that the directory still exists on disk). Companion: `worktree_gc::tests::unblocks_after_pending_flag_clears` drives the full cycle (blocked → `clear_git_apply_pending` → unblocked → directory removed).
      - **`GitStateInconsistent` (Case C — orchestrator worktree missing).** `recovery::git_apply_recovery_integration::case_c_emits_inconsistent_when_orchestrator_worktree_missing` (seeds `sessions.worktree_root` to a non-existent path; asserts `GitStateInconsistent { reason = "orchestrator_worktree_missing" }`, ref unchanged, `git_apply_pending` LEFT SET). `case_c_emits_inconsistent_when_audit_record_missing` covers the audit-chain-missing variant.
      - **Subsequent IntegrationMerge during pending.** Pre-flight rejection covered by `kernel/src/handlers/intent.rs` admission path: the pre-flight reads `git_apply_pending` BEFORE opening the transaction and rejects with `PlannerErrorCode::FailGitApplyPending` when the flag is already set; the rejection is exercised by the existing intent-handler integration tests (the same code path that reads the flag in Phase 1).
      - **Push during pending.** `handlers::intent::tests::wait_returns_true_after_concurrent_clear` (drives a Phase-3-clear flip from a sibling thread; asserts the push wait observes it within the deadline). `wait_returns_false_when_deadline_elapses_without_clear` pins the timeout path.
      - **INV-MERGE-CONSISTENCY assertion at startup.** `recovery::git_apply_recovery_integration::idempotent_after_case_b_succeeds` (runs Case B once, then a second sweep — confirms no double-emit, no duplicate flag flip, no spurious `Repaired`). The Case A test additionally pins that a second sweep after the repair produces no further outcomes (the flag is now `0` so the partial index returns the empty set).

---

## 13. Sensitive Path Operator Approval

### The Problem

Some paths in a codebase are categorically higher-risk than others. `src/payments/`,
`src/auth/`, `migrations/`, `infra/`, `signing-keys/` — changes to these files have
disproportionate security or compliance consequences if wrong. The standard `IntegrationMerge`
admission pipeline (path allowlist enforcement + Reviewer approval) may not be sufficient
for these paths: Reviewers are LLMs, and LLM Reviewers can be compromised, jailbroken,
or simply wrong about subtle security implications.

For these paths, the operator may require that no merge is admitted by the Kernel unless
a human operator has explicitly reviewed the diff and approved it.

### Policy Bundle Configuration

Protected paths are declared in the policy bundle (not the plan). This is a deployment-level
security policy — it applies across all initiatives, not just one. An operator cannot
disable it for a specific initiative by writing a different plan.

```toml
# policy.toml

[[protected_paths]]
path_prefix             = "src/payments/"
require_approval_for    = ["IntegrationMerge"]
approval_escalation_class = "ProtectedPathMerge"

[[protected_paths]]
path_prefix             = "src/auth/"
require_approval_for    = ["IntegrationMerge"]
approval_escalation_class = "ProtectedPathMerge"

[[protected_paths]]
path_prefix             = "migrations/"
require_approval_for    = ["IntegrationMerge"]
approval_escalation_class = "ProtectedPathMerge"

[[protected_paths]]
path_prefix             = "infra/"
require_approval_for    = ["IntegrationMerge"]
approval_escalation_class = "ProtectedPathMerge"
```

**Fields:**
- `path_prefix` — same `starts_with()` matching as path allowlists. Exact filenames also
  valid (`"Cargo.lock"`). No globs.
- `require_approval_for` — which intent classes trigger the gate. Currently only
  `IntegrationMerge` is supported. `SingleCommit` is intentionally excluded (agents need
  to write to these paths freely; only the merge to main requires human sign-off).
- `approval_escalation_class` — must be `"ProtectedPathMerge"`. Extensible for future
  classes.

**Why policy bundle, not plan:** If protected paths were declared in `plan.toml`, an
operator could write a plan that omits `src/payments/` from the protection list. The
protection is a compliance guarantee, not a per-initiative preference. Policy bundle
changes require a new signed bundle (`raxis epoch advance --policy <policy.toml> --sig <policy.sig>`), which goes through
`advance_epoch` and is audited as a policy change.

### The Operator Approval Flow

```text
1. Orchestrator merges sub-task branches → produces commit_sha
   (sub-task diff touches src/payments/)

2. Orchestrator submits:
   IntegrationMerge { commit_sha, merged_task_ids: [...], operator_approval_id: None }

3. Kernel: Check 5b detects protected_hits = ["src/payments/"]
   → Auto-creates Escalation { id: esc-99, class: ProtectedPathMerge, state: Pending,
                                commit_sha, protected_paths_hit: ["src/payments/"] }
   → Emits MergeApprovalRequired audit event
   → Returns FAIL_PROTECTED_PATH_APPROVAL_REQUIRED { escalation_id: esc-99 }
   → KernelPush::MergeApprovalRequired { escalation_id: esc-99,
                                          protected_paths: ["src/payments/"] }

4. Operator receives notification (via webhook, email, or polling `raxis escalate list`)

5. Operator reviews the diff:
   raxis merge diff esc-99          # shows full diff of commit_sha
   raxis merge approve esc-99       # approves it
   raxis merge reject esc-99        # rejects it (initiative fails, must re-plan)

6. Kernel on approve:
   → UPDATE escalations SET state = 'Consumed', resolved_by = 'operator_alice'
   → Emits EscalationConsumed { class: ProtectedPathMerge, resolved_by: operator_alice }
   → KernelPush::EscalationResolved { escalation_id: esc-99 }

7. Orchestrator re-submits:
   IntegrationMerge { commit_sha, merged_task_ids: [...], operator_approval_id: Some(esc-99) }

8. Kernel Check 6a:
   → Verifies esc-99 is Consumed, class = ProtectedPathMerge, session matches, SHA matches
   → Admits: fast-forwards main to commit_sha
   → Emits IntegrationMergeCompleted { operator_approval_id: Some(esc-99),
                                        protected_paths_approved: ["src/payments/"] }
```

### Why Approval Is SHA-Specific

The operator approves a specific `commit_sha`. The approval cannot be reused for a
different commit SHA.

**Scenario prevented:** The Orchestrator obtains approval for commit `abc` (an innocuous
payments change). It then discards `abc`, produces a different commit `def` (a malicious
payments change), and re-submits `IntegrationMerge { commit_sha: "def", operator_approval_id: esc-99 }`.

Check 6a catches this: `escalations.commit_sha = "abc" ≠ "def"` → `FAIL_APPROVAL_SHA_MISMATCH`.
The approval for `abc` cannot be consumed for `def`. The operator must review `def` and
issue a new approval.

This means if the Orchestrator retries a merge (e.g., after a conflict resolution changes
the SHA), it needs a new approval for the new SHA. This is intentional — the operator
is approving the exact bytes that will enter the main branch, not the concept of the merge.

### Kernel-Initiated vs. Orchestrator-Initiated Escalations

Standard escalations (`MergeConflict`, `PlanViolation`) are submitted by the Orchestrator
when it is genuinely blocked. `ProtectedPathMerge` escalations are different — they are
created by the Kernel in response to an `IntegrationMerge` admission attempt.

**Why the Kernel creates them:** The Orchestrator cannot know at merge-submission time
whether a protected path check will fire (it doesn't have visibility into the policy
bundle's `[[protected_paths]]` configuration). Having the Orchestrator speculatively
submit an escalation before the merge would require it to pre-compute the policy check —
duplicating policy logic in the inference loop, which is a trust boundary violation.

The Kernel auto-creates the escalation because it is the only authoritative evaluator of
the policy bundle. The escalation is a Kernel response to a merge attempt, not an
Orchestrator-initiated request for help.

**Audit distinction:** Kernel-initiated escalations have `initiator: "Kernel"` in the
`EscalationCreated` audit event. Orchestrator-initiated escalations have
`initiator: <session_id>`. The distinction is preserved in the audit chain.

### What Happens If the Operator Rejects

`raxis merge reject esc-99` sets the escalation to `Rejected` state. The Kernel:
1. Emits `EscalationRejected { class: ProtectedPathMerge, resolved_by: operator_alice }`
2. Sends `KernelPush::MergeApprovalRejected { escalation_id: esc-99 }` to the Orchestrator
3. Sets the sub-tasks in `merged_task_ids` to `IntegrationRejected` state

The initiative cannot proceed to `IntegrationMerge` for the rejected sub-tasks. The
operator must determine the next step: re-plan with different scope, re-run the sub-tasks
with modified constraints, or abort the initiative.

### Alternatives Considered

**Alt A — Require operator approval for all IntegrationMerge calls (global flag).**
Rejected. This would apply to every initiative and every merge, including low-risk
documentation changes. It removes the efficiency benefit of autonomous agents for
non-sensitive work. The protected-path granularity is the correct scope.

**Alt B — Declare protected paths in the plan as a replacement for policy-level protection.**
Rejected. Per-initiative configuration that *replaces* policy-level protection allows an
operator to write a plan that excludes `src/payments/` from the protection list, defeating
the compliance guarantee. Protection must be at the policy level to be enforceable across
all initiatives.

*Note: Plan-level gates that are **additive** — additional paths required approval beyond
what the policy bundle already requires — are permitted. See §13.b.*

**Alt C — Use the existing Reviewer mechanism — add a human Reviewer session.**
Rejected. Human Reviewers do not exist in the RAXIS session model. Reviewers are LLM
sessions. Adding a "human Reviewer" session type would require a fundamentally different
session lifecycle (the VM never boots; the human reviews via external tooling). The
escalation mechanism is already the correct human-in-the-loop channel in RAXIS — reusing
it is architecturally consistent.

**Alt D — Require a separate `raxis merge approve` before the Orchestrator even attempts IntegrationMerge.**
Rejected. The Orchestrator doesn't know before the merge attempt which paths will be
touched (it depends on the actual diff). Pre-approval would require the Orchestrator to
compute the diff and submit it for approval — duplicating Kernel-side diff logic in the
inference loop. The admit-then-gate pattern (attempt → fail → auto-create escalation →
re-attempt with approval) is the correct flow.

### Implementation Additions

- [ ] Add `[[protected_paths]]` section to `PolicyBundle` struct in `crates/policy/src/bundle.rs`
- [ ] Add `ProtectedPathMerge` variant to `EscalationClass` enum
- [ ] Add `commit_sha` and `protected_paths_hit` fields to `escalations` DDL
- [ ] Add `initiator` field (`"Kernel"` | `<session_id>`) to `escalations` DDL
- [ ] Implement Check 5b in `handle_integration_merge`: protected path query + auto-create
- [ ] Add `FAIL_PROTECTED_PATH_APPROVAL_REQUIRED { escalation_id }` to `KernelError`
- [ ] Add `FAIL_APPROVAL_SHA_MISMATCH` to `KernelError`
- [ ] Add `KernelPush::MergeApprovalRequired { escalation_id, protected_paths }` variant
- [ ] Add `KernelPush::MergeApprovalRejected { escalation_id }` variant
- [ ] Implement `raxis merge diff <escalation_id>` CLI command
- [ ] Implement `raxis merge approve <escalation_id>` CLI command
- [ ] Implement `raxis merge reject <escalation_id>` CLI command
- [ ] Add `MergeApprovalRequired` audit event
- [ ] Add `initiator` field to `EscalationCreated` audit event
- [ ] Update `IntegrationMergeCompleted` audit event with `protected_paths_approved`
- [ ] Add `IntegrationRejected` state to `subtask_activations.state` enum
- [ ] Tests: protected path fires + approved, protected path fires + rejected,
      SHA mismatch rejection, policy bundle with no protected paths (no-op),
      simultaneous MergeConflict + ProtectedPathMerge escalations
### §13.b — Plan-Level Protected Path Gates (Additive-Only)

Operators may declare additional protected path gates in `plan.toml` that are specific to
a single initiative. These are **additive only** — they can add paths that require approval
beyond what the policy bundle declares. They cannot remove or weaken policy-level gates.

> **Naming note (V2).** This block was previously named
> `[[integration_merge_gates]]`. It was renamed to
> `[[plan.protected_path_gates]]` in V2 because that name collides with the
> new `[[plan.integration_merge_verifiers]]` and policy-level
> `[[integration_merge_verifiers]]` mechanisms (per `verifier-processes.md
> §15`), which gate IntegrationMerge admission via mechanical witness
> verification — a different concept from the human-approval gating
> documented here. Since RAXIS has no released production deployment, the
> rename is a clean break with no backward-compatibility shim.

```toml
# plan.toml

[[plan.protected_path_gates]]
path_prefix = "src/experimental-billing/"   # not in policy.toml, but sensitive for this initiative
# default: require_approval = false
require_approval = true

[[plan.protected_path_gates]]
path_prefix = "src/new-auth-provider/"
require_approval = true
```

**Default:** `require_approval = false`. A `[[plan.protected_path_gates]]` entry with
`require_approval = false` is a no-op and may be omitted.

**How the Kernel computes the effective protected set (Check 5b):**

```rust
// Effective protected paths = policy bundle UNION plan-level gates
let effective_protected: Vec<&str> = policy
    .protected_paths                          // deployment-level (cannot be removed by plan)
    .iter()
    .filter(|p| p.require_approval_for.contains(&IntentClass::IntegrationMerge))
    .chain(
        plan.protected_path_gates             // initiative-level additive gates
            .iter()
            .filter(|g| g.require_approval)
    )
    .filter(|p| touched_paths.iter().any(|t| t.starts_with(&p.path_prefix)))
    .collect();
```

The Kernel takes the UNION of both sources. The plan can only contribute entries to the
union — it cannot remove entries contributed by the policy bundle.

**Why additive plan-level gates are safe:**
The plan is operator-signed (Ed25519). Adding a gate requires the operator to sign a plan
that includes the `[[plan.protected_path_gates]]` entry. This is equivalent to the operator
declaring "I want human sign-off on this path for this initiative." The security model is
not weakened — it is strengthened at the initiative level. The policy bundle floor is
always enforced regardless of what the plan declares.

**Audit record:** The `IntegrationMergeCompleted` audit event includes `protected_paths_approved`
which lists all paths from both sources that triggered an approval for this merge.

---

## 14. Git Push Approval Gate

### The Problem

`IntegrationMerge` updates the target ref in the RAXIS managed repository
mirror selected by `[workspace] repository`. The managed mirror is the
governed local record of everything the agent produced. But it has not yet
left the machine — publishing back to the external source repository
(`git push`, PR creation, or another provider-specific publish operation)
is a separate step with its own state.

For some deployments, operators want a final human gate between "the DAG completed and
main is updated locally" and "the code is pushed to the remote and visible to the rest
of the team / CI pipeline." This is especially relevant for:
- Production deployment pipelines where a `git push` triggers CI that deploys to prod
- Regulated environments where code changes require a human review before becoming visible
- High-stakes initiatives where the operator wants final eyes on the complete diff

### Configuration in `plan.toml`

```toml
# plan.toml

[plan]
require_push_approval = false    # default — git push happens automatically on InitiativeCompleted
```

```toml
# plan.toml — with push gate enabled

[plan]
require_push_approval = true
```

**Default is `false`** for ergonomics — most initiatives can push automatically. The gate
is opt-in per initiative by the operator at plan-signing time.

### The Gate Flow

```text
1. Final IntegrationMerge admitted
   → main updated to final_sha
   → Kernel emits InitiativeCompleted

2. If plan.require_push_approval = false and direct auto-push is enabled:
   → Kernel executes git push immediately
   → Emits PushCompleted { initiative_id, commit_sha, remote, ref_spec }
   → managed_repositories.publish_state transitions to published

2b. If direct auto-push is disabled:
    → managed_repositories.publish_state transitions to pending
    → Dashboard and CLI show the follow-up `raxis repo publish <repo_id>`
      command

3. If plan.require_push_approval = true:
   → Kernel creates PushApproval escalation { id: esc-200, state: Pending,
                                               commit_sha: final_sha }
   → Emits PushApprovalRequired { escalation_id: esc-200, commit_sha: final_sha }
   → KernelPush::PushApprovalRequired { escalation_id: esc-200 } to Orchestrator
   → Initiative transitions to PushPending state (new state)
   → git push is NOT executed

4. Operator reviews the final diff:
   raxis push diff esc-200        # shows full diff from initiative initial_sha to final_sha
   raxis push approve esc-200     # or: raxis push reject esc-200

5a. On approve:
    → Kernel: UPDATE escalations SET state = 'Consumed', resolved_by = 'operator_alice'
    → Emits EscalationConsumed { class: PushApproval, resolved_by: operator_alice }
    → Kernel executes git push origin main
    → Emits PushCompleted { initiative_id, commit_sha: final_sha, resolved_by: operator_alice }
    → Initiative transitions to Pushed state

5b. On reject:
    → Kernel: UPDATE escalations SET state = 'Rejected', resolved_by = 'operator_alice'
    → Emits PushRejected { initiative_id, commit_sha: final_sha, resolved_by: operator_alice }
    → Initiative transitions to PushRejected state
    → main remains updated locally; remote is NOT updated
    → Operator must decide: revert local main, re-plan, or investigate
```

### Audit Events

```rust
AuditEventKind::PushApprovalRequired {
    initiative_id:   Uuid,
    escalation_id:   Uuid,
    commit_sha:      String,   // the final_sha that would be pushed
    remote:          String,   // e.g., "origin"
    ref_spec:        String,   // e.g., "refs/heads/main:refs/heads/main"
}

AuditEventKind::PushCompleted {
    initiative_id:   Uuid,
    commit_sha:      String,
    remote:          String,
    ref_spec:        String,
    resolved_by:     Option<String>,   // Some("operator_alice") if push-gated, None if automatic
}

AuditEventKind::PushRejected {
    initiative_id:   Uuid,
    commit_sha:      String,
    resolved_by:     String,
    reason:          Option<String>,
}
```

**Why `resolved_by` is present even on automatic pushes (as `None`):**
Auditors querying `SELECT * FROM audit_events WHERE kind = 'PushCompleted'` see both
automatic and operator-approved pushes in one query. The `None` vs `Some` distinction
makes it immediately clear which required human approval.

### SHA Specificity (Same as Protected Path Approval)

The `PushApproval` escalation records `commit_sha = final_sha`. A push can only be
approved for the exact SHA that will be pushed. If the operator approves `esc-200` for
`sha_a`, but the initiative's `current_sha` has somehow changed to `sha_b` (e.g., another
IntegrationMerge was admitted in the interim), the push gate re-fires for `sha_b`.

This prevents: approve the push for a safe final diff, then slip in one more
IntegrationMerge before the push executes, bypassing the gate for the new content.

### New Initiative State: `PushPending`

Adds a new state to the Initiative FSM:

```text
InProgress
    ↓ (all sub-tasks complete, IntegrationMerge admitted)
Completed
    ↓ require_push_approval = false: automatic
    ↓ require_push_approval = true: PushApproval escalation created
PushPending ──── operator approve ──→ Pushed
            └─── operator reject ──→ PushRejected
```

The existing `Completed` state now means "DAG done, main updated, push not yet executed
or gated." `Pushed` is the new terminal success state for initiatives with push configured.
For initiatives without a remote (`remote = ""` in plan), `Completed = Pushed` — there is
nothing to push.

### Implementation Checklist

- [ ] Add `require_push_approval = false` field to `PlanManifest` struct
- [ ] Add `PushApproval` variant to `EscalationClass` enum
- [ ] Add `PushPending` and `PushRejected` states to `initiatives.state` enum (DDL migration)
- [ ] Add `Pushed` state to `initiatives.state` enum
- [ ] Implement post-`InitiativeCompleted` push gate check in `handle_integration_merge`:
      if `require_push_approval = false` → execute push immediately;
      if `true` → create `PushApproval` escalation, set state to `PushPending`
- [ ] Add `PushApprovalRequired { escalation_id, commit_sha }` to `KernelPush`
- [ ] Implement `raxis push diff <escalation_id>` CLI: shows `git diff initial_sha..final_sha`
- [ ] Implement `raxis push approve <escalation_id>` CLI
- [ ] Implement `raxis push reject <escalation_id>` CLI
- [ ] Add `FAIL_PUSH_SHA_MISMATCH` error variant (if SHA changed between approval and push)
- [ ] Add `PushApprovalRequired`, `PushCompleted`, `PushRejected` audit event variants
- [ ] Add `resolved_by: Option<String>` to `PushCompleted` audit event
- [ ] Tests: auto-push (no gate), push gate approve flow, push gate reject flow,
      SHA mismatch on push, PushPending → Pushed state transition,
      PushPending → PushRejected state transition

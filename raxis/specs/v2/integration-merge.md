# RAXIS V2 — `IntegrationMerge` Specification

> **Status:** V2 Specified  
> **Cross-references:**  
> - `v2-deep-spec.md §Step 8` — Orchestrator Owns IntegrationMerge (decision + rationale)  
> - `v2-deep-spec.md §Step 9` — Bundle Routing (how Executor commits reach the Orchestrator)  
> - `v2-deep-spec.md §Step 11` — Hybrid Allowlist computation  
> - `v2-deep-spec.md §Step 30` — Audit Attribution for Operator-Assisted Commits  
>
> This document is the **complete mechanical specification** for the `IntegrationMerge`
> intent: its struct, the full admission pipeline, the multi-task merge sequencing model,
> fast-forward vs. merge commit semantics, audit events, and idempotency behaviour.
> The rationale for these decisions lives in the deep spec cross-references above.

---

## 1. What IntegrationMerge Is

`IntegrationMerge` is the intent the Orchestrator submits to the Kernel after it has
successfully merged one or more Executor sub-task branches into a single commit in its
ephemeral clone. Upon admission, the Kernel fast-forwards the initiative's master branch
to the merged commit SHA. This is the **only** mechanism that writes agent-produced code
to the master branch.

Until `IntegrationMerge` is admitted:
- The master branch is untouched
- All Executor commits exist only in ephemeral VM worktrees and Orchestrator staging bundles
- The initiative state is `InProgress`

After `IntegrationMerge` is admitted:
- The master branch is updated to `commit_sha`
- The Orchestrator's base SHA is advanced to `commit_sha`
- The initiative logs `IntegrationMergeCompleted` in the audit chain
- The Orchestrator may activate the next wave of sub-tasks (if the DAG has more)

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
```
git -C $RAXIS_DATA_DIR/worktrees/<orchestrator_uuid> cat-file -t <commit_sha>
```
Result must be `commit`. Failure: `FAIL_COMMIT_NOT_FOUND`.

### Check 3 — Ancestry Verification
`commit_sha` must be a descendant of the initiative's current `base_sha`:
```
git -C <worktree> merge-base --is-ancestor <base_sha> <commit_sha>
```
If `commit_sha` is not a descendant of `base_sha`, the Orchestrator is attempting to
merge a commit that doesn't include the previous state of master. This would produce a
history rewrite. Failure: `FAIL_ANCESTRY_VIOLATION`.

**Why this matters:** If Orchestrator merges sub-task A (producing SHA `abc`), updates
master to `abc`, then later submits `IntegrationMerge { commit_sha: "def" }` where `def`
does not descend from `abc`, the master branch would lose the history of A's work. The
ancestry check prevents this.

### Check 4 — `merged_task_ids` Validation
Every `task_id` in `merged_task_ids`:
- Must exist in `subtask_activations` for this initiative
- Must have `state = 'Completed'` (not Active, Pending, or Failed)
- Must have `completed_sha` set (non-null)
- Must not appear in a previous `IntegrationMerge.merged_task_ids` for this initiative
  (each sub-task may be merged exactly once)

Failure for any of these: `FAIL_TASK_NOT_COMPLETED` with the offending task_id.

### Check 5 — Diff Computation and Hybrid Allowlist Check
The Kernel computes the full diff between `base_sha` and `commit_sha`:
```
git -C <worktree> diff --name-only <base_sha> <commit_sha>
```

The set of touched paths is checked against the hybrid allowlist:
```
hybrid_effective_allow =
    UNION(task.path_allowlist for task in merged_task_ids)
    ∪ orchestrator.cross_cutting_artifacts
```

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
Check 5b is a no-op. Proceed to Check 6.

---

### Check 6a — Protected Path Approval Verification (conditional)
Only runs if `operator_approval_id: Some(id)` AND `protected_hits` is non-empty:
- `escalations.id = id` must exist
- `escalations.state = 'Consumed'`
- `escalations.class = 'ProtectedPathMerge'`
- `escalations.session_id = current_orchestrator_session_id`
- `escalations.commit_sha = commit_sha` (approvals are commit-SHA-specific — an approval
  for one merge commit cannot be reused for a different commit SHA)

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
If a previous `IntegrationMerge` for this initiative already advanced master to `commit_sha`
(i.e., `initiatives.current_sha = commit_sha`), the Kernel returns `OK_ALREADY_APPLIED` —
not an error. This is an idempotent success. The Orchestrator can re-submit the same
`IntegrationMerge` safely after a crash-recovery without causing a double-merge.

If `commit_sha` differs from `initiatives.current_sha` and is not a descendant of it
(Check 3), this is `FAIL_ANCESTRY_VIOLATION`.

### Check 8 — Database Commit (INV-STORE-02 Atomicity)
If all checks pass, the Kernel executes in a single `BEGIN IMMEDIATE` transaction:
```sql
UPDATE initiatives SET current_sha = :commit_sha WHERE id = :initiative_id;
INSERT INTO audit_events (kind, ...) VALUES ('IntegrationMergeCompleted', ...);
UPDATE subtask_activations
   SET merge_included = 1
 WHERE task_id IN (:merged_task_ids...);
```
The git fast-forward is executed immediately after the transaction commits:
```
git -C <master_repo> fetch <orchestrator_worktree> <commit_sha>
git -C <master_repo> update-ref refs/heads/master <commit_sha>
```

---

## 5. Multi-Task Merge Sequencing

### When There Is One IntegrationMerge Per Initiative

The simplest case: all sub-tasks complete before the Orchestrator submits any merge. The
Orchestrator waits for `AllReviewersPassed` for every sub-task, then merges all branches
in a single `git merge` chain and submits one `IntegrationMerge` covering all sub-tasks.

```
[A: Complete] [B: Complete] [C: Complete]
                                 │
                    Orchestrator merges A, B, C
                                 │
             IntegrationMerge { merged_task_ids: [A, B, C] }
                                 │
                    master → final_sha
```

### When There Are Multiple IntegrationMerge Submissions (Wave Model)

In a multi-wave initiative where some sub-tasks depend on others, the Orchestrator may
submit `IntegrationMerge` between waves:

```
Wave 1: [A: Complete] [B: Complete]
  → IntegrationMerge { merged_task_ids: [A, B], commit_sha: "sha1" }
  → master → sha1

Wave 2 (activated after sha1):
  [C: Complete]  ← depends on A, B being in master
  → IntegrationMerge { merged_task_ids: [C], commit_sha: "sha2" }
  → master → sha2
```

Between waves, the Orchestrator's base SHA advances from the initiative's `initial_sha`
to `sha1`. Wave 2 sub-tasks' clones are provisioned from `sha1` — they see Wave 1's work.

**Key rule:** After `IntegrationMerge` is admitted and master advances, the Orchestrator's
next `IntegrationMerge` must descend from the new `current_sha`. The Orchestrator must
`git pull` or `git merge FETCH_HEAD` from the updated master before starting Wave 2 merges.
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

## 6. Fast-Forward vs. True Merge Commit on Master

The Kernel always uses `git update-ref` (equivalent to `--ff-only`) to advance master.
It never produces a merge commit on master itself.

**Implication:** The Orchestrator must produce the merge commit in its ephemeral clone
before submitting `IntegrationMerge`. The Orchestrator runs `git merge` — which produces
a merge commit if the branches have diverged. The Orchestrator's merge commit becomes the
new master HEAD directly.

**Why not merge commit on master by the Kernel:** The Kernel runs as a deterministic
policy enforcer. Producing a merge commit requires author identity, committer identity,
and a commit message — all of which are either arbitrary (making the audit record
non-deterministic) or would require the Kernel to run inference (catastrophic). The
Orchestrator, as an LLM, can produce a contextually appropriate merge commit message
("Merge auth-executor and payments-executor: add rate limiting and refunds").

**When the result is a fast-forward on master:** If only one sub-task's branch is in
the wave AND no cross-cutting artifacts were modified, `commit_sha` may be identical to
the sub-task's `completed_sha` — a fast-forward with no merge commit at all. The Kernel
handles this identically to a true merge commit: the ancestry check passes (the sub-task
commit descends from base), and `git update-ref` fast-forwards master.

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
    plan_artifact_sha256:   String,     // links to signed plan (INV-05)
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

The Orchestrator's non-negotiable system prompt includes this procedure verbatim. It is
the mechanical sequence the Orchestrator must follow when it receives
`KernelPush::AllReviewersPassed { task_id }`:

```
1. Confirm all expected sub-tasks for this wave have sent AllReviewersPassed.
   (Do not merge a partial wave — wait for all expected tasks.)

2. For each sub-task in merge order:
   a. git fetch /workspace/.raxis/bundles/<task_id>.bundle
   b. git merge refs/raxis/subtasks/<task_id>
   c. If MERGE_HEAD exists after merge (merge commit):
      - Write a descriptive merge commit message: "Merge <task_id>: <brief description>"
   d. If git merge exits with conflicts:
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
   - Run: git pull (pull the current master into the Orchestrator's clone)
   - Retry from step 2 with the updated base.

5. On FAIL_PATH_POLICY_VIOLATION { path }:
   - This is a plan error — a sub-task modified files outside its allowlist.
   - The sub-task's SingleCommit was admitted but the aggregate merge contains unexpected paths.
   - Submit: EscalationRequest { class: PlanViolation, context: "path <path> found in merge
     commit is outside declared allowlist" }
   - STOP. Do not retry without operator guidance.
```

**Note on step 2d — conflict detection:** `git merge` exits with status 1 when there are
conflicts. The Orchestrator must detect this and abort rather than attempting to produce a
commit with conflict markers. A commit containing `<<<<<<<` conflict markers is a valid
git commit — but the path allowlist check at Kernel admission will pass it (the paths may
be within scope), and the resulting code will be broken. The Orchestrator must abort and
escalate before committing, not after.

---

## 9. Post-Merge State

After `IntegrationMergeCompleted` is emitted:

| State | Before merge | After merge |
|---|---|---|
| `initiatives.current_sha` | `base_sha` (or previous merge SHA) | `commit_sha` |
| `master` branch in master repo | `base_sha` | `commit_sha` |
| `subtask_activations.merge_included` | 0 for merged tasks | 1 for merged tasks |
| Orchestrator's clone `HEAD` | `commit_sha` (Orchestrator produced it) | Unchanged |
| Orchestrator's base SHA for next wave | The previous `initiatives.current_sha` | Updated to `commit_sha` |

The Orchestrator does **not** need to pull master after a successful `IntegrationMerge` —
it already has `commit_sha` in its local clone. The Kernel's `current_sha` advance is the
authoritative record; the Orchestrator's clone is the source of truth for the commit.

---

## 10. Edge Cases

### What If the Master Branch Has Advanced Since the Initiative Started?

The initiative records `initial_sha` at `approve_plan` time. If another initiative's
`IntegrationMerge` advances master between `approve_plan` of this initiative and this
initiative's first `IntegrationMerge`, the ancestry check (Check 3) will fail:
`commit_sha` descends from `initial_sha`, but `base_sha` (= the current master HEAD)
has advanced beyond `initial_sha`.

**Resolution:** The Orchestrator must rebase or merge master into its clone:
```
git fetch origin master
git merge origin/master
```
This produces a new merge commit that descends from the current master. The Orchestrator
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

## 11. Implementation Checklist

- [ ] Add `merged_task_ids: Vec<TaskId>` field to `IntegrationMerge` struct in
      `crates/types/src/operator_wire.rs`
- [ ] Implement `handle_integration_merge` in `kernel/src/handlers/merge.rs` (new file)
      with all 8 checks in order
- [ ] Add `git cat-file` reachability check (Check 2) using `gix` crate
- [ ] Add `git merge-base --is-ancestor` ancestry check (Check 3)
- [ ] Add `merged_task_ids` validation against `subtask_activations` (Check 4)
- [ ] Implement hybrid allowlist computation (Check 5) reusing `vcs::diff` primitives
- [ ] Add escalation verification branch (Check 6) in `handle_integration_merge`
- [ ] Add idempotency guard (Check 7) with `OK_ALREADY_APPLIED` response variant
- [ ] Implement atomic DB transaction (Check 8): `initiatives.current_sha` update +
      `subtask_activations.merge_included` update + audit event, then git `update-ref`
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

---

## 12. Sensitive Path Operator Approval

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
  to write to these paths freely; only the merge to master requires human sign-off).
- `approval_escalation_class` — must be `"ProtectedPathMerge"`. Extensible for future
  classes.

**Why policy bundle, not plan:** If protected paths were declared in `plan.toml`, an
operator could write a plan that omits `src/payments/` from the protection list. The
protection is a compliance guarantee, not a per-initiative preference. Policy bundle
changes require a new signed bundle (`raxis policy push`), which goes through
`advance_epoch` and is audited as a policy change.

### The Operator Approval Flow

```
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
   → Admits: fast-forwards master to commit_sha
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
is approving the exact bytes that will enter the master branch, not the concept of the merge.

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

**Alt B — Declare protected paths in the plan (per-initiative).**
Rejected. Per-initiative configuration allows an operator to write a plan that excludes
`src/payments/` from protection, defeating the compliance guarantee. Protection must be
at the policy level to be enforceable across all initiatives.

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

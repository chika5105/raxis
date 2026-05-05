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

```
# Phase 2 (idempotent git work)
git -C <master_repo> fetch <orchestrator_worktree> <commit_sha>
git -C <master_repo> update-ref refs/heads/master <commit_sha>

# Phase 3 (single SQLite UPDATE)
UPDATE initiatives SET git_apply_pending = 0 WHERE id = :initiative_id;
```

The handler dispatches Phase 2 + Phase 3 inline before returning the response to the Orchestrator. If the kernel crashes during Phase 2 or between Phase 2 and Phase 3, recovery on next startup re-runs the missing phases (§11.3).

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

## 11. Transactional Boundary: SQLite ↔ Git

Check 8 has two distinct durable side effects:

1. **SQLite commit** — `initiatives.current_sha` advances; `IntegrationMergeCompleted` audit event is recorded; `subtask_activations.merge_included` flags are set.
2. **Git operation** — `git fetch` from the Orchestrator's worktree pulls the new commit objects into `master_repo`; `git update-ref refs/heads/master <commit_sha>` advances the local master ref.

These two operations cannot be made atomic. SQLite has no awareness of git, and `gix` does not participate in SQLite's transaction. There is always a window between them. This section specifies the ordering, the failure modes, and the recovery semantics that restore consistency after a crash.

The corresponding cross-reference from `key-revocation.md §7.5` Case C points here: when a session is revoked while an `IntegrationMerge` is in flight, the revocation interacts with whichever phase the merge has reached.

### 11.1 Ordering: SQLite First, then Git, then SQLite Again

The Kernel uses a three-phase model:

| Phase | Operation | Durable | Idempotent |
|---|---|---|---|
| 1 | SQLite `BEGIN IMMEDIATE`: UPDATE `current_sha`, set `git_apply_pending = 1`, INSERT audit event, UPDATE `merge_included`. Single transaction, atomic on commit. | Yes | Yes (Check 7 idempotency guard) |
| 2 | Git: `git fetch <orchestrator_worktree> <commit_sha>`; `git update-ref refs/heads/master <commit_sha>`. | Yes (writes to master_repo on disk) | Yes (re-fetching same SHA and re-updating ref to same SHA are no-ops) |
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
| 2 | Crash after Phase 1 commits, before Phase 2 starts | SQLite: `current_sha = commit_sha`, `git_apply_pending = 1`. Git: `refs/heads/master` still at base_sha. | §11.3 Case A — re-run Phase 2 from worktree. |
| 3 | Phase 2 `git fetch` fails (e.g., orchestrator worktree disk error, SHA not present) | SQLite: as above. Git: `refs/heads/master` still at base_sha; objects not fetched. | §11.3 Case A — retry; if persistently fails, transition initiative to `Blocked`. |
| 4 | Phase 2 `git update-ref` fails (rare; refs/heads/master became unwritable) | SQLite: as above. Git: objects fetched but ref not updated. | §11.3 Case A — re-run update-ref step; the fetch portion is a no-op. |
| 5 | Crash after Phase 2 completes, before Phase 3 commits | SQLite: as above. Git: `refs/heads/master = commit_sha` (fully consistent on the git side). | §11.3 Case B — verify git state, then run Phase 3. |

In all cases except #1, the `git_apply_pending = 1` flag in SQLite is the durable signal that drives recovery.

### 11.3 Recovery on Startup

After policy load and after `key-revocation.md §5.3` reconciliation, before accepting new IPC connections, `kernel/src/startup.rs` runs the merge-consistency recovery pass:

```
SELECT id, current_sha, master_repo_path
  FROM initiatives
 WHERE git_apply_pending = 1;

for each row i:
    db_sha = i.current_sha
    git_sha = read refs/heads/master in i.master_repo_path

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
            git_fetch(master_repo_path, worktree_path, db_sha)
            git_update_ref(master_repo_path, "refs/heads/master", db_sha)
            verify: read refs/heads/master == db_sha   // assertion
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

**Recovery runs before IPC accepts new connections.** This guarantees that no new IntegrationMerge for the same initiative can be admitted while a previous one is still pending git apply — the new admission would otherwise see SQLite's `current_sha` ahead of git's `refs/heads/master` and produce a Check 3 ancestry violation.

### 11.4 Worktree Retention Requirement

The recovery procedure depends on the originating Orchestrator's worktree being available on disk for the duration of `git_apply_pending = 1`. This adds a constraint on worktree garbage collection that is parallel to (but distinct from) the forensic retention rule in `key-revocation.md §7.4`:

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

This complements (does not replace) the forensic retention from `key-revocation.md §7.4`. Forensic retention applies to terminated sessions for 30 days; INV-MERGE-WORKTREE-RETAIN applies to any session whose worktree is needed for an in-flight merge regardless of session state.

### 11.5 Cross-Cutting: Subsequent Operations Must Check `git_apply_pending`

Operations that read git state must be aware that `current_sha` may be ahead of `refs/heads/master` during the Phase 1 → Phase 3 window:

- **Subsequent IntegrationMerge admission** (Check 8 Phase 1 pre-flight): asserts `git_apply_pending = 0`. If 1, returns `FAIL_GIT_APPLY_PENDING` and the caller should retry shortly. This prevents wave 2 from beginning before wave 1's git is applied. In normal operation this assertion always passes (Phase 3 completes inline within the same handler call); it can fail only after a crash, in which case recovery on the next startup clears the flag.
- **Push to remote** (§14 Push Approval Gate): waits for `git_apply_pending = 0` before reading `refs/heads/master` and pushing. A push during the pending window would push the OLD sha, which is wrong. The push handler polls the flag with a short timeout (default 5s) before either pushing or returning a transient error.
- **Audit replay tooling**: when a tool reconstructs git state at a historical timestamp, it should consult `git_apply_pending` at that timestamp. If 1, the tool reports both `current_sha` (kernel-authoritative) and `refs/heads/master` at that moment, and explicitly notes the pending git apply.

### 11.6 Why Not Reverse Ordering (Git First, SQLite Second)

Considered: do `git fetch` + `git update-ref` first, then commit SQLite. Rejected:

- **No durable marker for recovery.** If git completes but the kernel crashes before SQLite commits, there is no kernel-side record that the merge happened. Recovery has nothing to drive from. Detection would require scanning `master_repo`'s reflog and trying to reconstruct intent, which is fragile and breaks the "audit log is the source of truth" invariant.
- **Audit event ordering inversion.** The `IntegrationMergeCompleted` audit event records that the merge was admitted. If git happens first and audit is written later, an external observer monitoring git could see the new commit before the audit log says it was admitted — a transient inversion.
- **Master ref poisoning on rejection.** If SQLite commit fails for any reason (transient I/O error, foreign-key violation surfaced late, ...), the git ref is already advanced and cannot easily be retracted. Rolling back a git ref requires writing the old SHA, which is itself a state change that would need its own audit record.
- **Idempotency surface.** Putting the non-transactional side AFTER the transactional one means the only thing that needs idempotency-on-recovery is the git side, which is naturally idempotent. The reverse forces SQLite to be re-runnable, which it is not designed to be (no `INSERT OR IGNORE` for audit events that should be append-once).

### 11.7 Why Not Single-Phase (No `git_apply_pending` Flag)

Considered: just commit SQLite, then run git, with no marker. Recovery scans for `current_sha != refs/heads/master` mismatches and replays. Rejected:

- **Mismatch is ambiguous.** A mismatch could mean "Phase 2 didn't complete" (recoverable) or "git was tampered with externally" (security concern, not recoverable). Without a marker explicitly saying "we expected to apply and didn't," recovery cannot distinguish.
- **No way to enforce worktree retention.** Worktree GC needs to know whether a worktree is still required for an in-flight git apply. Without `git_apply_pending`, the GC has to make a conservative assumption (never GC, or always GC and risk losing recovery objects). Neither is acceptable.
- **Subsequent-operation guard becomes guessing.** Phase 1 pre-flight (§11.5) needs to know whether the previous merge's git is applied. Without an explicit flag, it would have to compare `current_sha` against `refs/heads/master` on every IntegrationMerge admission, which requires a git read inside an SQLite transaction (cross-store I/O during a `BEGIN IMMEDIATE` lock — a concurrency hazard).

The `git_apply_pending` flag costs 1 byte per initiative row and resolves all three problems.

### 11.8 INV-MERGE-CONSISTENCY

For every initiative, exactly one of the following holds at any moment:

(a) **Consistent.** `initiatives.current_sha = refs/heads/master` AND `git_apply_pending = 0`.

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
    previous_git_sha:   String,    // what refs/heads/master was at, before recovery
    recovered_at_startup_run: Uuid, // links to StartupReconciliationCompleted
}

AuditEventKind::GitConsistencyVerified {
    initiative_id:      Uuid,
    sha:                String,    // current_sha == refs/heads/master at recovery
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

---

## 12. Implementation Checklist

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

### Transactional Boundary (§11)

- [ ] Add `git_apply_pending INTEGER NOT NULL DEFAULT 0` column to `initiatives` (DDL migration)
- [ ] Add partial index `idx_initiatives_pending_git ON initiatives(id) WHERE git_apply_pending = 1`
- [ ] Update `handle_integration_merge` to set `git_apply_pending = 1` in Phase 1 SQLite transaction
- [ ] Update `handle_integration_merge` to dispatch Phase 2 (git fetch + update-ref) inline after Phase 1 commit
- [ ] Update `handle_integration_merge` to dispatch Phase 3 (`UPDATE git_apply_pending = 0`) inline after Phase 2 success
- [ ] Add Phase 1 pre-flight assertion: `SELECT git_apply_pending FROM initiatives WHERE id = ?`; if 1, return `FAIL_GIT_APPLY_PENDING`
- [ ] Implement startup recovery in `kernel/src/startup.rs` per §11.3 (Cases A and B)
- [ ] Add `GitConsistencyRepaired { initiative_id, db_sha, previous_git_sha, recovered_at_startup_run }` audit event variant
- [ ] Add `GitConsistencyVerified { initiative_id, sha, recovered_at_startup_run }` audit event variant
- [ ] Add `SecurityViolationKind::GitStateInconsistent { initiative_id, db_sha, git_sha, reason }` variant
- [ ] Add `FAIL_GIT_APPLY_PENDING` to `KernelError` enum
- [ ] Update worktree GC to enforce INV-MERGE-WORKTREE-RETAIN (§11.4) — block GC of any worktree referenced by an initiative with `git_apply_pending = 1`
- [ ] Update push handler (§14) to wait for `git_apply_pending = 0` before reading `refs/heads/master` (default 5s poll timeout, return transient error on timeout)
- [ ] Tests:
      - Crash between Phase 1 and Phase 2: SIGKILL kernel after Phase 1 commit; restart; verify §11.3 Case A re-runs Phase 2; final state matches no-crash baseline.
      - Phase 2 git fetch failure: stub `gix::fetch` to fail once; verify error surfaced to Orchestrator; on retry, Phase 2 succeeds.
      - Crash between Phase 2 and Phase 3: SIGKILL after `update-ref` but before SQLite Phase 3 UPDATE; restart; verify §11.3 Case B clears flag; no `GitConsistencyRepaired` (it's a Verified, not Repaired).
      - Worktree GC blocks during pending: simulate long Phase 2 by stalling `gix::fetch`; concurrently invoke worktree GC; verify GC skips the worktree until flag clears.
      - GitStateInconsistent (case C of §11.3): manually delete the Orchestrator's worktree before restart; verify SecurityViolation emitted, initiative transitions to Blocked, kernel does NOT clear `git_apply_pending`.
      - Subsequent IntegrationMerge during pending: hold Phase 2 stalled; submit a second IntegrationMerge from the same Orchestrator; verify `FAIL_GIT_APPLY_PENDING`; release Phase 2; verify second merge succeeds on retry.
      - Push during pending: hold Phase 2 stalled; trigger push (auto-push initiative); verify push handler waits for flag; release Phase 2; verify push proceeds with the correct SHA.
      - INV-MERGE-CONSISTENCY assertion at startup: corrupt `refs/heads/master` to point at base_sha while leaving `current_sha = commit_sha` and `git_apply_pending = 1`; restart; verify §11.3 Case A re-applies and the invariant is restored to (a).

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
### §13.b — Plan-Level Integration Merge Gates (Additive-Only)

Operators may declare additional protected path gates in `plan.toml` that are specific to
a single initiative. These are **additive only** — they can add paths that require approval
beyond what the policy bundle declares. They cannot remove or weaken policy-level gates.

```toml
# plan.toml

[[integration_merge_gates]]
path_prefix = "src/experimental-billing/"   # not in policy.toml, but sensitive for this initiative
# default: require_approval = false
require_approval = true

[[integration_merge_gates]]
path_prefix = "src/new-auth-provider/"
require_approval = true
```

**Default:** `require_approval = false`. An `[[integration_merge_gates]]` entry with
`require_approval = false` is a no-op and may be omitted.

**How the Kernel computes the effective protected set (Check 5b):**

```rust
// Effective protected paths = policy bundle UNION plan-level gates
let effective_protected: Vec<&str> = policy
    .protected_paths                          // deployment-level (cannot be removed by plan)
    .iter()
    .filter(|p| p.require_approval_for.contains(&IntentClass::IntegrationMerge))
    .chain(
        plan.integration_merge_gates          // initiative-level additive gates
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
that includes the `[[integration_merge_gates]]` entry. This is equivalent to the operator
declaring "I want human sign-off on this path for this initiative." The security model is
not weakened — it is strengthened at the initiative level. The policy bundle floor is
always enforced regardless of what the plan declares.

**Audit record:** The `IntegrationMergeCompleted` audit event includes `protected_paths_approved`
which lists all paths from both sources that triggered an approval for this merge.

---

## 14. Git Push Approval Gate

### The Problem

`IntegrationMerge` updates the local master branch in the RAXIS host's git repository.
The local master is the record of everything the agent produced. But it has not yet left
the machine — `git push` to the remote (GitHub, GitLab, etc.) is a separate step.

For some deployments, operators want a final human gate between "the DAG completed and
master is updated locally" and "the code is pushed to the remote and visible to the rest
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

```
1. Final IntegrationMerge admitted
   → master updated to final_sha
   → Kernel emits InitiativeCompleted

2. If plan.require_push_approval = false:
   → Kernel executes git push immediately
   → Emits PushCompleted { initiative_id, commit_sha, remote, ref_spec }
   → Initiative transitions to Pushed state

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
    → Kernel executes git push origin master
    → Emits PushCompleted { initiative_id, commit_sha: final_sha, resolved_by: operator_alice }
    → Initiative transitions to Pushed state

5b. On reject:
    → Kernel: UPDATE escalations SET state = 'Rejected', resolved_by = 'operator_alice'
    → Emits PushRejected { initiative_id, commit_sha: final_sha, resolved_by: operator_alice }
    → Initiative transitions to PushRejected state
    → master remains updated locally; remote is NOT updated
    → Operator must decide: revert local master, re-plan, or investigate
```

### Audit Events

```rust
AuditEventKind::PushApprovalRequired {
    initiative_id:   Uuid,
    escalation_id:   Uuid,
    commit_sha:      String,   // the final_sha that would be pushed
    remote:          String,   // e.g., "origin"
    ref_spec:        String,   // e.g., "refs/heads/master:refs/heads/master"
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

```
InProgress
    ↓ (all sub-tasks complete, IntegrationMerge admitted)
Completed
    ↓ require_push_approval = false: automatic
    ↓ require_push_approval = true: PushApproval escalation created
PushPending ──── operator approve ──→ Pushed
            └─── operator reject ──→ PushRejected
```

The existing `Completed` state now means "DAG done, master updated, push not yet executed
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

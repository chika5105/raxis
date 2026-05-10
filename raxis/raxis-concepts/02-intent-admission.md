# RAXIS Intent Admission — End-to-End Explained

## What is an intent?

An intent is the **only way an AI agent can act**. Every agent action — committing code, completing a task, reporting failure — goes through the kernel as an `IntentRequest`. The kernel either admits or rejects it. There is no side channel.

---

## The 8 Intent Kinds

| Intent Kind | Who can use it | What it does |
|---|---|---|
| `SingleCommit` | Executor | One committed change on top of `base_sha` |
| `IntegrationMerge` | Executor | Merge commit integrating agent branches |
| `CompleteTask` | Executor | Assert task is done — triggers gate closure check |
| `ReportFailure` | Executor | Self-report inability to complete — requires justification |
| `ActivateSubTask` | Orchestrator only | Request kernel to spawn a sub-task |
| `RetrySubTask` | Orchestrator only | Re-activate a previously-failed sub-task |
| `SubmitReview` | Reviewer only | Report verdict on executor's code (approve/reject) |
| `StructuredOutput` | Executor/Orchestrator | Emit typed mid-session output (non-terminal) |

---

## The 13-Step Admission Pipeline

When an agent submits an `IntentRequest`, the kernel runs this pipeline:

```
IntentRequest arrives on planner UDS socket
        │
        ▼
    ┌── Step 1: Session Auth ──────────┐
    │  Verify session token            │
    │  Check sequence number (replay)  │
    │  Check session not revoked       │
    └──────────────────────────────────┘
        │
        ▼
    ┌── Step 2: Intent Validation ─────┐
    │  Check intent_kind is valid      │
    │  Verify required fields present  │
    │  Role-based dispatch matrix      │
    └──────────────────────────────────┘
        │
        ▼
    ┌── Step 3: Task State Check ──────┐
    │  Load task row from store        │
    │  Verify task.state is valid      │
    │  (Admitted or Running)           │
    └──────────────────────────────────┘
        │
        ▼
    ┌── Step 4: VCS Path Derivation ───┐
    │  git diff base_sha head_sha      │
    │  → touched_paths                 │
    │  Topology check (no merges in    │
    │  SingleCommit ranges)            │
    └──────────────────────────────────┘
        │
        ▼
    ┌── Step 5: Bind SHA Fields ───────┐
    │  UPDATE task SET evaluation_sha, │
    │  base_sha, session_id,           │
    │  submitted_claims_json           │
    └──────────────────────────────────┘
        │
        ▼
    ┌── Step 6: Gate Evaluation ───────┐
    │  (see 01-claims-and-gates.md)    │
    │  Claims + Witness check          │
    └──────────────────────────────────┘
        │
        ▼
    ┌── Step 7: Budget Check ──────────┐
    │  Lane concurrency limit          │
    │  Lane cost ceiling               │
    │  compute_admission_cost()        │
    └──────────────────────────────────┘
        │
        ▼
    ┌── Step 8: Budget Reservation ────┐
    │  INSERT lane_budget_reservations │
    │  (first pickup only)             │
    └──────────────────────────────────┘
        │
        ▼
    ┌── Step 9: State Transition ──────┐
    │  Admitted → Running              │
    │  (or Admitted → GatesPending)    │
    └──────────────────────────────────┘
        │
        ▼
    IntentResponse::Accepted
```

---

## Step-by-Step Detail

### Step 1: Session Authentication

Every `IntentRequest` carries a `session_id` and `session_token`. The kernel:

1. Looks up the session in the `sessions` table
2. Verifies the token (constant-time compare of HMAC)
3. Checks the sequence number (monotonically increasing — prevents replay)
4. Checks `revoked_at IS NULL` (session not revoked)

**Gap check:** ✅ Session auth is fully implemented. The nonce cache and sequence number enforcement prevent replay attacks. Sessions are kernel-issued at spawn time — the agent cannot create its own session.

### Step 2: Intent Validation

The kernel validates:
- `intent_kind` is one of the 8 known kinds
- Required fields are present (e.g., `SingleCommit` needs `base_sha` + `head_sha`)
- **V2 Role-based dispatch matrix:** Only Orchestrators can `ActivateSubTask`/`RetrySubTask`, only Reviewers can `SubmitReview`, Reviewers cannot use `StructuredOutput`

```rust
// From driver.rs — Reviewer tool restrictions
Role::Reviewer => {
    // Reviewer is explicitly denied structured_output and sleep
}
```

### Step 3: Task State Check

The kernel loads the task row and verifies the FSM allows this transition:
- First pickup: task must be in `Admitted` state
- Continuation: task must be in `Running` state
- `GatesPending` → rejected with `TaskNotSchedulable` (wait for witnesses)

### Step 4: VCS Path Derivation

For SHA-bearing intents (`SingleCommit`, `IntegrationMerge`, `CompleteTask`):

```bash
git diff <base_sha> <head_sha> --name-status --no-renames
```

The kernel also runs a topology check for `SingleCommit`:
```bash
git rev-list <base_sha>..<head_sha> --min-parents=2 --count
```
If count > 0 → merge commits in a `SingleCommit` range → rejected.

**Key invariant:** The agent reports SHAs, but the kernel independently verifies the VCS state. The agent cannot lie about which files changed.

### Steps 5–9: Binding, Gates, Budget, Transition

These steps are covered in:
- **01-claims-and-gates.md** — gate evaluation pipeline
- **03-lanes-and-budgets.md** — lane-based budget enforcement

---

## What the Agent Receives Back

### On acceptance:
```json
{
  "status": "Accepted",
  "task_state": "Running",
  "warn_delegation_stale": false,
  "budget_snapshot": {
    "reserved_cost": 42,
    "remaining_in_lane": 958
  }
}
```

### On rejection:
```json
{
  "status": "Rejected",
  "reason": "FAIL_POLICY_VIOLATION",
  "task_state": "Admitted"
}
```

Rejection codes always start with `FAIL_` (except `FETCH_DENIED` which is per-request recoverable).

---

## Edge Cases

### 1. Agent submits to a task it doesn't own

The kernel checks `task.session_id == request.session_id`. If they differ → rejected. One session = one task binding.

### 2. Agent submits with a stale sequence number

Replay protection: the kernel's `nonce_cache` INSERT fails → `SequenceMismatch` → rejected. The agent must increment its sequence counter monotonically.

### 3. Task's predecessor DAG dependencies aren't met

`next_ready_tasks()` filters tasks whose DAG predecessors are all `Completed`. If a dependency isn't met → `DEPENDENCY_NOT_MET` (for `ActivateSubTask`).

### 4. Policy epoch advances mid-intent

The kernel pins a single `PolicyBundle` snapshot for the duration of gate evaluation (Step 2.5 in the gate pipeline). A concurrent epoch advance does not tear an in-flight decision.

---

## Key Source Files

| File | Role |
|------|------|
| `kernel/src/ipc/handlers/intent.rs` | The 13-step admission pipeline |
| `kernel/src/ipc/auth.rs` | Session token validation + sequence check |
| `kernel/src/gates/mod.rs` | Gate evaluation entry point |
| `kernel/src/scheduler/budget.rs` | Lane budget check + reservation |
| `kernel/src/vcs/diff.rs` | VCS path derivation, topology check |
| `crates/types/src/intent.rs` | `IntentKind`, `IntentRequest`, `IntentResponse` |

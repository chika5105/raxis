# RAXIS Lanes & Budgets — End-to-End Explained

> **Audience.** Operators sizing `[[lanes]]` blocks in `policy.toml`,
> reviewers debugging `BudgetExceeded` admissions, and contributors
> changing `kernel/src/scheduler/budget.rs`.
>
> **Authority.** The runtime contract is
> `kernel/src/scheduler/budget.rs` (admission units) and
> `kernel/src/scheduler/budget.rs::evaluate_token_budget` (LLM
> token cost). The schema lives in `crates/store/src/migration.rs`
> Tables 14 (`lane_budget_reservations`) and 15. Policy fields are
> `crates/policy/src/bundle.rs::LaneEntry`.
>
> **Paradigm anchor.** Lanes implement **R-3 — Bounded resources**:
> every action against external compute, money, or wall-clock has
> a kernel-checked ceiling that the agent cannot raise.

---

## What is a lane?

A lane is a **concurrency and cost container**. The operator groups tasks into lanes and sets three limits per lane:
1. **`max_concurrent_tasks`** — how many tasks can run at the same time
2. **`max_cost_per_epoch`** — how much total admission-unit budget the lane can spend
3. **`priority`** (default `100`) — higher number = scheduler dequeues first when multiple lanes have headroom

---

## Step 1: Operator Configures Lanes

```toml
[[lanes]]
lane_id = "feature-work"
max_concurrent_tasks = 4
max_cost_per_epoch = 1000
priority = 10

[[lanes]]
lane_id = "hotfix"
max_concurrent_tasks = 2
max_cost_per_epoch = 500
priority = 20  # higher = runs first
```

**In plain English:** "Up to 4 feature tasks can run at once, spending at most 1000 cost units. Hotfix tasks get priority."

---

## Step 2: Tasks are Assigned to Lanes

Each task in the plan specifies its lane:

```toml
[[tasks]]
task_id = "build-auth-module"
lane_id = "feature-work"
```

In V2 multi-agent plans, all tasks in one initiative share the same lane (per Step 28). This means an Orchestrator + its Executors + Reviewers **share one budget**.

---

## Step 3: Budget Check at Admission

When an intent passes gate evaluation, the kernel checks the lane budget:

```rust
reserve_budget_in_tx(conn, lane_id, task_id, estimated_cost, policy)
```

This runs **atomically in one transaction** (fixing the TOCTOU bug from kernel-store.md §2.5.1.1 Pattern A):

1. **Read** current lane status: `SELECT SUM(reserved_cost) ... WHERE lane_id = ?`
2. **Check concurrency:** `active_tasks >= max_concurrent_tasks` → reject
3. **Check cost:** `reserved_cost + estimated_cost > max_cost_per_epoch` → reject
4. **Reserve:** `INSERT OR IGNORE INTO lane_budget_reservations` (idempotent on PK)

---

## Admission Cost Formula

The kernel computes the cost of each intent (the agent cannot influence this):

```text
base_cost = policy.base_cost_for_intent_kind("SingleCommit")
path_cost = touched_paths.len() × policy.cost_per_touched_path()
raw       = base_cost + path_cost
result    = min(raw, policy.max_cost_per_task())
```

Example: If `base_cost = 10`, `cost_per_touched_path = 2`, and the agent touched 5 files → cost = `10 + (5 × 2) = 20`.

---

## Token-Cost Budget (V2.5)

In addition to admission-unit budgets, V2.5 adds a **per-task LLM token-cost ceiling**:

```toml
[workspace]
max_cost_per_task = 100  # USD cents
```

The kernel tracks cumulative LLM spending per task:

1. Each `IntentRequest` carries a `TokensReport { input_tokens, output_tokens, ... }`
2. The kernel resolves the LLM provider's pricing from policy
3. Cost is computed in micro-dollars: `pricing.cost_micro_dollars(input, output, cache_read, cache_creation)`
4. If cumulative cost exceeds `max_cost_per_task × 10_000 µ$/¢` → **reject**

```rust
if new_micros > ceiling {
    TokenBudgetVerdict::Reject { cumulative_token_cost_micros, ceiling_micros }
}
```

**Example:** At Anthropic pricing ($5/MTok input, $20/MTok output), 100k input + 50k output = $1.50 = 1,500,000 µ$. If the ceiling is $1.00 (100¢ = 1,000,000 µ$) → rejected.

---

## The Budget Flow (Visual)

```text
Intent passes gate evaluation
        │
        ▼
    ┌── Compute Cost ──────────────────┐
    │  base_cost + (paths × per_path)  │
    │  = estimated_cost                │
    └──────────────────────────────────┘
        │
        ▼
    ┌── BEGIN TRANSACTION ─────────────┐
    │                                  │
    │  SELECT SUM(reserved_cost)       │
    │  FROM lane_budget_reservations   │
    │  WHERE lane_id = ?               │
    │                                  │
    │  Check: active_tasks < max?      │
    │  Check: sum + cost <= max?       │
    │                                  │
    │  INSERT OR IGNORE reservation    │
    │                                  │
    │  COMMIT                          │
    └──────────────────────────────────┘
        │
        ▼
    ┌── Token Budget Check ────────────┐
    │  cumulative_µ$ <= ceiling_µ$?    │
    └──────────────────────────────────┘
        │
    ┌───┴───┐
    ▼       ▼
  Pass    Reject
  │       │
  ▼       ▼
Admitted  BudgetExceeded
```

---

## Budget Release

When a task reaches a terminal state (`Completed`, `Failed`, `Cancelled`):

```rust
release_budget(lane_id, task_id, store)
// DELETE FROM lane_budget_reservations WHERE lane_id=? AND task_id=?
```

This frees the reserved cost for other tasks. Idempotent — calling twice is safe.

---

## Edge Cases

### 1. Two tasks race for the last budget slot

**Pre-fix (TOCTOU):** Both read `reserved_cost = 90`, both compute `90 + 15 = 105 < 110`, both succeed. Over-committed.

**Post-fix (INV-STORE-02):** `reserve_budget_in_tx` runs the read + write in one transaction. The second task sees the first's reservation and is rejected with `BudgetExceeded`.

### 2. Continuation intent on an already-running task

The PK is `(lane_id, task_id)`. `INSERT OR IGNORE` means the second reservation is a no-op. The task is not double-charged.

### 3. V2 shared lane — Orchestrator + Executors share budget

Per Step 28: all tasks in one initiative carry the same `lane_id`. The lane ceiling bounds the **sum across all sessions**:

```yaml
Orchestrator: 40 units  ✅ (sum = 40)
Executor 1:   30 units  ✅ (sum = 70)
Executor 2:   20 units  ✅ (sum = 90)
Reviewer:     15 units  ❌ (sum = 105 > 100)
```

### 4. Different initiatives on different lanes don't interfere

`lane-feature` and `lane-bugfix` have separate ceilings. Saturating `lane-feature` does not block `lane-bugfix`.

### 5. No LLM provider pricing configured

`cost_micros_for_tokens` returns `0` → token budget check always passes. This is the "degraded read-only" mode.

---

## Key Source Files

| File | Role |
|------|------|
| `kernel/src/scheduler/budget.rs` | `check_budget`, `reserve_budget_in_tx`, `release_budget`, `compute_admission_cost`, `evaluate_token_budget`, `cost_micros_for_tokens`, `TokenBudgetVerdict` |
| `kernel/src/scheduler/lane.rs` | Lane status queries, lane config lookup |
| `kernel/src/scheduler/admit.rs` | Admission-unit wrapper around `reserve_budget_in_tx` |
| `crates/policy/src/bundle.rs` | `LaneEntry { max_concurrent_tasks, max_cost_per_epoch, priority }`, LLM provider pricing tables |
| `kernel/src/handlers/intent.rs` | Phase C of admission: invokes `reserve_budget_in_tx` inside the post-gate transaction (see concept 02 §"Pipeline overview") |
| `crates/store/src/migration.rs` | Table 14: `lane_budget_reservations(PK = (lane_id, task_id), reserved_cost)`; idempotent under `INSERT OR IGNORE` |
| `specs/v1/kernel-store.md` §2.5.1.1 Pattern A | Normative description of the closed TOCTOU read-modify-write window (INV-STORE-02) |

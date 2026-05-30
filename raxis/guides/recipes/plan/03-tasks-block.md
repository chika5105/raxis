# `[[tasks]]` — task block field reference

> **Topic:** Plan reference | **Time to read:** ~5 min | **Complexity:** ⭐⭐ Intermediate

`[[tasks]]` is the central block in `plan.toml`. Each block declares
one Executor or Reviewer task; the Orchestrator is auto-created by
the kernel and you do not declare it. This recipe is the field
reference. Other recipes drill deeper into individual fields.

---

## Field reference

| Field | Type | Required | Effect |
|---|---|---|---|
| `task_id` | `String` | yes | Stable, plan-unique identifier. Must match `^[A-Za-z][A-Za-z0-9_-]{0,63}$`. Referenced by other tasks' `predecessors`. |
| `session_agent_type` | `String` | yes | One of `"Executor"` or `"Reviewer"`. `"Orchestrator"` is REJECTED — the Orchestrator is kernel-managed. |
| `clone_strategy` | `String` | yes | One of `"full"`, `"blobless"`, `"sparse"`. Reviewers can use `full` or `blobless`; Executors prefer `blobless` or `sparse`; sparse on Orchestrators is rejected. |
| `path_allowlist` | `Vec<String>` | yes | Which paths the agent may **write**. See *path_allowlist rules* recipe for the precise semantics. |
| `predecessors` | `Vec<String>` | yes (may be empty) | List of `task_id`s that MUST reach `Completed` before this task activates. Empty list = activates immediately. |
| `description` | `String` | yes | Short human-readable task summary for dashboards, logs, and audit pivots. Keep it brief. |
| `prompt` | `String` (multi-line OK) | yes | The precise task-scoped instruction body the agent executes. Do not put the main instructions in `description`. |
| `vm_image` | `String` | optional | `[[vm_images]] name` to use. Omit to use `[default_executor_image]` or the kernel-canonical starter. **Reviewers cannot declare this**; the Reviewer image is kernel-canonical. |
| `allowed_egress` | `Vec<String>` | optional | Per-task egress allowlist (host suffix list). Subset of any `[[vm_images]] egress_allowlist` and policy `[egress] domains`. |
| `path_export_globs` | `Vec<String>` | optional | Globs matching files this task expects to *read* outside its `path_allowlist`. Used by the Orchestrator's clone-shape decision. |
| `cross_cutting_artifacts` | `Vec<String>` | (orchestrator only) | NOT a `[[tasks]]` field — declared in the top-level `[orchestrator]` block. Listed here for cross-reference. |
| `[[tasks.credentials]]` | sub-block | optional | Per-task credential declarations; see *task credentials* recipe. |
| `[[tasks.verifiers]]` | sub-block | optional | Per-task verifiers; see *task verifiers* recipe. |
| `cumulative_max_seconds` | `u32` | optional | Wall-clock cap. Beyond this, the kernel emits `FAIL_WALL_CLOCK_LIMIT_EXCEEDED`. |
| `elastic` | `bool` | optional | Per-task override of `policy.[elastic].enabled`. **Plan can only NARROW** — `elastic = false` always wins (`INV-ELASTIC-01`); `elastic = true` is rejected if the policy disables elastic. Default: inherit `policy.[elastic].enabled` (V2 GA default = `true`). See *elastic VM scaling* recipe. |
| `min_vcpus` / `max_vcpus` | `u32` | optional | Per-task vCPU floor / ceiling for `[elastic]` scaling. The ceiling MUST be `≤ policy.[elastic].max_vcpus_per_session`; over-broad values are rejected with `FAIL_ELASTIC_PLAN_EXCEEDS_POLICY`. Reviewer tasks MUST NOT declare these (`FAIL_REVIEWER_ELASTIC_NOT_ALLOWED`). |
| `min_memory_mb` / `max_memory_mb` | `u32` | optional | Per-task memory floor / ceiling for `[elastic]` scaling. Same `≤ policy.[elastic].max_memory_mb_per_session` rule. Reviewer tasks MUST NOT declare these. |

> **Reserved (V2.6) — silently ignored today.** `max_crash_retries`,
> `max_review_rejections`, and `max_revision_rounds` parse without
> error but the kernel does NOT enforce them. The
> `subtask_activations.review_reject_count` substrate is wired
> (V2.5+), but the parser + ceiling enforcement are V2.6 follow-ups
> in . Don't rely on them; orchestrator
> heuristics still drive escalation.

---

## Example — single Executor + Reviewer

```toml
[plan.initiative]
description = """Add IP rate limiting to /auth/login."""

[workspace]
name    = "Rate limit /auth/login"
lane_id = "auth-work"
repository = "main"
target_ref = "refs/heads/main"

[[tasks]]
task_id            = "rate_limit_implementer"
session_agent_type = "Executor"
clone_strategy     = "sparse"
path_allowlist     = ["src/auth/"]
predecessors       = []
description        = "Implement rate limiting"
prompt             = """
  Implement IP-based rate limiting on POST /auth/login.
  - 10 req/min/IP, sliding window
  - Return 429 + Retry-After
  - Use src/auth/redis.rs (already present)
  - Add tests in src/auth/rate_limit_test.rs
"""

[[tasks]]
task_id            = "security_reviewer"
session_agent_type = "Reviewer"
clone_strategy     = "blobless"
path_allowlist     = ["src/auth/"]            # subset (or equal) to Executor's
predecessors       = ["rate_limit_implementer"]
description        = "Review rate limiting"
prompt             = """
  Review src/auth/rate_limit.rs for:
  - correct sliding-window math (off-by-one, race conditions)
  - resource exhaustion (Redis key TTLs, memory bound)
  - 429 response shape (Retry-After in seconds, integer-formatted)
"""

[orchestrator]
cross_cutting_artifacts = ["Cargo.lock"]
```

---

## Reviewer task constraints

A `session_agent_type = "Reviewer"` task has additional invariants:

| Constraint | Effect |
|---|---|
| `path_allowlist` | The Reviewer's allowlist MUST be a subset of (or equal to) the Executor's it depends on. The kernel rejects Reviewer allowlist entries that aren't covered by some predecessor Executor. |
| `vm_image` | MUST be unset; the Reviewer image is kernel-canonical. Setting it triggers `FAIL_REVIEWER_VM_IMAGE_NOT_ALLOWED`. |
| `allowed_egress` | MUST be empty; Reviewer VMs have no network device (`INV-NETISO-01`). |
| `predecessors` | MUST be non-empty — a Reviewer with no predecessor Executor has nothing to review. |
| `[[tasks.credentials]]` | Should be empty; Reviewers can't reach the credential proxy without egress. |
| `min_vcpus` / `max_vcpus` / `min_memory_mb` / `max_memory_mb` | MUST be unset; Reviewer resource ceilings are kernel-canonical (`FAIL_REVIEWER_ELASTIC_NOT_ALLOWED`). |

---

## Executor task constraints

| Constraint | Effect |
|---|---|
| `predecessors` | MAY be empty (activates at admission) or list other Executors. Cannot list a Reviewer (`predecessor_role_invalid`). |
| `clone_strategy` | `sparse` is the recommended choice for narrow-scope work in large monorepos. |
| `path_allowlist` | Defines write scope. Read access is governed by `clone_strategy` and `path_export_globs`. |

---

## Common errors

| Symptom | Fix |
|---|---|
| `task_id duplicate` | Two `[[tasks]]` share an id. Rename. |
| `task_id format invalid` | Must start with a letter, alphanumeric + `_-`, ≤ 64 chars. |
| `session_agent_type Orchestrator` | Forbidden — the Orchestrator is kernel-managed. |
| `predecessors cycle` / `self-loop` / `dangling` | The DAG check rejects cycles, self-references, and references to non-existent task_ids. |
| `Reviewer with empty predecessors` | A Reviewer must depend on the Executor it reviews. |
| `Reviewer path_allowlist superset of Executor` | The Reviewer can't read paths the Executor didn't write. Tighten. |
| `Reviewer with vm_image set` | Remove the field. |

---

## Reference: relevant CLI

| Command | Purpose |
|---|---|
| `raxis plan validate <plan.toml>` | Local pre-flight: catches every constraint above before submission. |
| `raxis plan fmt <plan.toml> --check` | CI gate: rejects non-canonical formatting. |
| `raxis plan init` | Scaffold a new plan with the canonical block layout. |

---

## Variations

- **Pure Executor plan (no Reviewer).** Drop the Reviewer block; the
  kernel admits the plan as a single-task DAG. Useful for trivial
  changes where the cost of a Reviewer outweighs its value.
- **Multi-Executor parallel.** Multiple `[[tasks]]` with disjoint
  `path_allowlist` and `predecessors = []` activate in parallel.
- **Panel review.** Three Reviewer tasks all depending on the same
  Executor; the kernel applies logical-AND across their verdicts.

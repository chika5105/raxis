# RAXIS Guides

> **Audience:** Developers writing `plan.toml` files and operators running RAXIS initiatives.
> This is the practical cookbook. For architectural rationale, see
> [`specs/design-decisions.md`](../specs/design-decisions.md) and
> [`specs/v2/v2-deep-spec.md`](../specs/v2/v2-deep-spec.md).

RAXIS is a general-purpose multi-agent orchestration kernel. Its invariants are strict, but
the plan topology is flexible. The guides below document common patterns for structuring
multi-agent work within those invariants — ready-to-adapt templates with annotated explanations.

---

## Task Patterns

These patterns cover how to decompose work into agent topologies. Each pattern is a
self-contained guide with an annotated `plan.toml`, an invariant checklist, and notes on
when to use it and when not to.

| Pattern | Summary | Guide |
|---|---|---|
| **Single Executor + Reviewer** | One agent implements, one reviews. The baseline. | [`patterns/single-executor-reviewer.md`](patterns/single-executor-reviewer.md) |
| **Parallel Decomposition** | Multiple Executors work on non-overlapping paths simultaneously. | [`patterns/parallel-decomposition.md`](patterns/parallel-decomposition.md) |
| **Structured Debate** | Two agents argue a design across N rounds before a third implements. | [`patterns/structured-debate.md`](patterns/structured-debate.md) |
| **Panel Review** | Multiple Reviewers with different criteria evaluate the same output concurrently. | [`patterns/panel-review.md`](patterns/panel-review.md) |
| **Sequential Refinement** | Multiple Executors in sequence, each improving the previous one's output. | [`patterns/sequential-refinement.md`](patterns/sequential-refinement.md) |

---

## Security Guides

| Guide | Summary |
|---|---|
| **Compromised Agent Threat Model** | What happens when one agent in an initiative is compromised. Covers LLM jailbreak, prompt injection, VM process compromise, and colluding agents. | [`security/compromised-agent-threat-model.md`](security/compromised-agent-threat-model.md) |
| **RAXIS Security Model** | Complete reference for every security mechanism in RAXIS — isolation, authentication, enforcement, audit, and credential protection with reasons and scenarios. | [`security/raxis-security-model.md`](security/raxis-security-model.md) |

---

## Reading Order for New Developers

1. Read [`single-executor-reviewer.md`](patterns/single-executor-reviewer.md) first — it
   establishes the core concepts (path allowlists, lane budgets, Reviewer activation) in
   their simplest form.
2. Read [`parallel-decomposition.md`](patterns/parallel-decomposition.md) to understand
   the path subset rule and how Orchestrators integrate multiple branches.
3. Pick the pattern that matches your task type.

---

## Core Concepts (Quick Reference)

### Path Allowlists
Every agent can only write files within its `path_allowlist`. Two legal formats:
- **Exact file:** `src/api/handler.rs`
- **Directory prefix:** `src/api/` (matches everything under that directory)

The Orchestrator's allowlist must be a superset of all sub-task allowlists — validated at
`approve_plan` time before any VM boots.

### Clone Strategies
| Strategy | Downloads | Use when |
|---|---|---|
| `full` | Everything | Small repos; Orchestrators always |
| `blobless` | Tree structure + blobs on access | Large repos; agents needing broad read access |
| `sparse` | Only declared `path_allowlist` paths | Narrow-scope Executors in large monorepos |

> **Rule:** Orchestrators must never use `sparse`. Git's 3-way merge requires the full
> tree object graph. Use `full` or `blobless` for Orchestrators.

### Lane Budget
All sessions in one initiative share a single lane. The budget is measured in
**admission units** — a kernel-computed heuristic based on intent type and paths touched.
It is not a token count or dollar amount. Set `lane_id` once at `[workspace]` level;
sub-tasks inherit it automatically.

### Agent Types
| Type | Can write code | Can activate sub-tasks | Can submit reviews |
|---|---|---|---|
| `Orchestrator` | ❌ | ✅ | ❌ |
| `Executor` | ✅ | ❌ | ❌ |
| `Reviewer` | ❌ | ❌ | ✅ |

### Dependency Rules
- `depends_on = []` — activates immediately when the initiative starts
- `depends_on = ["task_a"]` — activates only after `task_a` reaches `Completed`
- Cycles, dangling references, and listing the Orchestrator as a dependency are all
  rejected at `approve_plan` time

### How Agents Communicate
They don't — directly. The only communication channel is the git worktree:
- **Agent A writes** a file and submits `CompleteTask`
- **Orchestrator merges** Agent A's commit
- **Agent B boots** with a fresh clone that contains Agent A's file

Every signal between agents goes through the Kernel. No agent-to-agent IPC exists.

---

## Adding New Patterns

When you develop a new effective plan topology, document it:
1. Create `guides/patterns/<pattern-name>.md`
2. Follow the template in any existing pattern guide (Context, Plan, Annotated TOML,
   Invariant Checklist, When to Use, When Not to Use)
3. Add a row to the table above

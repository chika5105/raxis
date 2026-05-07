# RAXIS Concepts — A 10-Minute Introduction

> **Read this once, before your first scenario.** Every guide under
> `scenarios/` references the terms defined here.

RAXIS is a multi-agent orchestration kernel. It admits **plans** signed
by **operators**, runs each plan's tasks inside isolated **VMs**, and
fast-forwards a main git branch when (and only when) the kernel's
admission gates pass. Everything the kernel cares about is encoded
either in the operator's `policy.toml` (long-lived deployment shape)
or the operator's per-initiative `plan.toml` (the work to do).

## Path Allowlists

Every agent can only **write** files within its `path_allowlist`.
Two legal entry shapes (V2 §19):

- **Exact filename** — `Cargo.toml`, `src/api/handler.rs`
- **Directory prefix** — `src/api/` (matches everything beneath)

Glob characters (`*`, `?`, `[`, `]`, `{`, `}`), leading `!` (negation),
leading `/` (absolute path), and `..` (path escape) are all rejected
at admission. Entries are kernel-canonical: `src/api/` and `src/api`
are different (the trailing slash means "directory prefix"; the
no-slash form is an exact filename).

The Orchestrator's allowlist must be a **superset** of every sub-task's
allowlist. RAXIS validates this at `approve_plan` time, before any VM
boots.

## Clone Strategies (V2 §27)

| Strategy | Downloads | Use when |
|---|---|---|
| `full` | Everything | Small repos; **Orchestrators always**. |
| `blobless` | Tree structure + blobs on access | Large repos; agents needing broad read access. **V2 default.** |
| `sparse` | Only `path_allowlist` paths | Narrow-scope Executors in large monorepos. |

> **Rule:** Orchestrators must never use `sparse`. Git's 3-way merge
> requires the full tree object graph. `validate_sparse_orchestrator_exclusion`
> rejects any `sparse` + `Orchestrator` plan at admission.

## Lane Budget (V2 §28)

All sessions in one initiative share a **single lane**. The budget is
measured in **admission units** — a kernel-computed heuristic from the
intent type and `touched_paths`. It is **not** a token count or dollar
amount; treating it that way is a misuse.

The lane is declared exactly once at `[workspace] lane_id`. Per-task
overrides are rejected (`single_lane_propagation` rule). The kernel
propagates the workspace lane to every sub-task.

## Agent Types (V2 §6)

| Type | Writes code | Activates sub-tasks | Submits reviews |
|---|---|---|---|
| `Orchestrator` | ❌ | ✅ | ❌ |
| `Executor` | ✅ | ❌ | ❌ |
| `Reviewer` | ❌ | ❌ | ✅ |

The Orchestrator is **kernel-managed**: V2 auto-creates exactly one
Orchestrator session per initiative from the kernel-bundled
`raxis-orchestrator-core` image. Operators only declare Executor and
Reviewer tasks in `[[tasks]]`. A `session_agent_type = "Orchestrator"`
declaration is rejected at admission (`orchestrator_task_not_permitted`).

## Dependency Rules (the DAG)

- `predecessors = []` — activates immediately when the initiative starts.
- `predecessors = ["task_a"]` — activates only after `task_a` reaches
  `Completed`.
- Cycles, dangling references, self-loops, and duplicate `task_id`s are
  rejected at admission.

## How Agents Communicate

**They don't, directly.** The only channel is the git worktree:

1. Agent A writes a file and submits `CompleteTask`.
2. Kernel bundles the touched objects → Orchestrator's staging dir.
3. Orchestrator merges Agent A's commit into its worktree.
4. Agent B boots with a fresh clone that contains Agent A's file.

Every signal between agents goes through the kernel. There is no
agent-to-agent IPC.

## Verifiers and Witnesses

A **verifier** is a small image the kernel boots to evaluate the
Executor's output mechanically (e.g., `cargo test`). The verifier
emits a **witness** — a content-addressed blob the kernel keeps in
`witness/`. The merge can be gated on a witness's presence and shape.

V2 ships canonical verifier images (`raxis-verifier-symbol-index`)
plus tiered language starters (`raxis-verifier-{rust,node,python,go}-starter`).
Operators can also declare their own verifier images per task.

## Egress and the Network Surface (V2)

Every Executor / Orchestrator VM has its egress mediated by a
kernel-side proxy. Operators declare `allowed_egress` per task:

```toml
[[tasks]]
allowed_egress = ["api.anthropic.com", "registry.npmjs.org"]
```

Hosts not in the allowlist are denied at the proxy with
`TransparentProxyDenied` audit events. Reviewer VMs have **no
network device** at all (`INV-NETISO-01`). Credentials for
allowed providers are injected by the credential proxy without
ever transiting the agent's address space.

## The Audit Chain

Every kernel decision (boot, admission, FSM transition, merge,
session revoke, escalation, etc.) is appended to a hash-chained
JSONL log under `$RAXIS_DATA_DIR/audit/segment-NNN.jsonl`. The
chain is operator-verifiable end-to-end via `raxis verify-chain`.
Tampering anywhere in the chain breaks every record after it.

## Genesis Ceremony

A one-time setup that mints the kernel's authority keys, the
operator's signing certificate, the genesis policy.toml, and the
chain-anchor audit segment. After genesis the kernel is ready to
admit signed plans. See [`SETUP.md`](SETUP.md) for the full
walkthrough.

## Reading Order

If you are new to RAXIS, work through scenarios 01–05 in
`scenarios/` *in order*. Each one introduces exactly one new
concept on top of the previous. After scenario 05 you understand
enough to pick from the catalogue freely.

# RAXIS Concepts

A complete guide to every core concept in the RAXIS kernel. Each document explains one concept from operator configuration through kernel enforcement, with edge cases and implementation gap analysis.

---

## Concept Guides

| # | Concept | What it covers |
|---|---------|---------------|
| [01](01-claims-and-gates.md) | **Claims & Gates** | Proof requirements, verifier subprocesses, witness records, auto-derivation fix |
| [02](02-intent-admission.md) | **Intent Admission** | The 13-step pipeline from request to acceptance |
| [03](03-credential-proxies.md) | **Credential Proxies** | Protocol-aware proxies (Postgres, HTTP, SMTP, Redis, AWS, GCP, Azure, MySQL, MSSQL, MongoDB) |
| [04](04-delegations-and-authority.md) | **Delegations & Authority** | Operator-signed capability grants, TTL, epoch staleness |
| [05](05-lanes-and-budgets.md) | **Lanes & Budgets** | Per-lane concurrency/cost limits, token-cost budgets, TOCTOU fix |
| [06](06-audit-chain.md) | **Audit Chain** | Hash-linked tamper-evident logging, chain verification |
| [07](07-escalations.md) | **Escalations** | Human-in-the-loop: request → park → approve/reject → resume |
| [08](08-sessions-and-isolation.md) | **Sessions & Isolation** | Session lifecycle, microVM isolation, system prompt assembly |
| [09](09-policy-configuration.md) | **Policy Configuration** | Every section of policy.toml, signing, hot reload, epochs |
| [10](10-v2-orchestration.md) | **V2 Orchestration** | Multi-agent DAG, Orchestrator/Executor/Reviewer, review loops, retry counters |

---

## Glossary — every Raxis term in one place

A canonical, alphabetised-within-section reference for the
vocabulary the kernel, the planner, and the spec all share. Each
row points at the concept guide that owns the term in depth, plus
(where useful) the spec / source-of-truth path. If you read one
unfamiliar word in a concept doc and don't want to scroll, look
here first.

> **Reading note.** Where a term has a strict in-codebase
> identifier (`IntentKind::ActivateSubTask`,
> `subtask_activations.crash_retry_count`, etc.), the rendered
> form is in `monospace`. Where a term is a domain noun
> (Orchestrator, Initiative), it is rendered as a Capitalised
> Word.

### Top-level entities

| Term | Meaning | Defined in |
|---|---|---|
| **Raxis** | The project. A multi-agent orchestration kernel that runs operator-signed plans against operator-isolated microVMs and merges the results into operator-controlled git refs. The kernel is the only trusted code in the loop. | top-level `README.md`, [`specs/v2/v2-deep-spec.md`](../specs/v2/v2-deep-spec.md) |
| **Kernel** | The single trusted binary (`raxis-kernel`) that admits intents, spawns agent VMs, runs verifiers, persists the audit chain, and enforces every invariant. Everything else (planners, agents, CLI) is unprivileged client. | [`specs/v1/kernel-core.md`](../specs/v1/kernel-core.md) |
| **Operator** | A human (or fleet of humans) holding an Ed25519 keypair the kernel trusts to sign `policy.toml` and (optionally) to approve plans. Operators are the highest authority Raxis recognises. | [04](04-delegations-and-authority.md), [`specs/v1/policy.md`](../specs/v1/policy.md) |
| **Initiative** | One logical unit of work the kernel is driving end-to-end: a plan, its task DAG, its in-flight sessions, its audit subset, its merge target. Initiative state lives in the `initiatives` table. | [10](10-v2-orchestration.md) |
| **Plan** | The operator-authored TOML (`plan.toml`) declaring the workspace, the task DAG, and per-task scopes. Submitted as one Initiative; sealed (parsed + stored) into the kernel store at `approve_plan`. | [10](10-v2-orchestration.md), [recipes/plan/](../guides/recipes/plan/) |
| **Plan bundle** | The post-`approve_plan` form of the plan: `plan_artifact_sha256`, the `task_dag_edges` rows, and the `TaskPlanFields` registry entries. The bundle is the kernel's source of truth at runtime; the original `plan.toml` text is no longer consulted. | `kernel/src/initiatives/lifecycle.rs::approve_plan` |
| **Plan registry** | An in-memory, hot-readable cache of per-task plan fields keyed on `(initiative_id, task_id)`. Populated at `approve_plan` and rehydrated at kernel restart. | `kernel/src/initiatives/plan_registry.rs` |
| **Policy** | The operator-signed TOML (`policy.toml`) that declares lanes, budgets, providers, VM images, escalation rules, and the gateway. Hot-reloaded; every reload bumps the **policy epoch**. | [09](09-policy-configuration.md), [recipes/policy/](../guides/recipes/policy/) |
| **Policy epoch** | A monotonically-increasing integer the kernel stamps on every admission. Used to detect plans / delegations / budgets that were authored against a stale policy and need re-evaluation. | [09](09-policy-configuration.md) |
| **Substrate** | The kernel layer that spawns / monitors / tears down agent VMs. Implemented by `SessionSpawnService` over Firecracker / Apple-VZ / containerd backends; agents see only the bridge. | [08](08-sessions-and-isolation.md), `crates/session-spawn/`, `crates/isolation-*/` |

### Agents, sessions, and roles

| Term | Meaning | Defined in |
|---|---|---|
| **Agent** | An LLM-driven planner subprocess running inside an isolated VM, talking to the kernel over a vsock-mediated bridge. Three flavours: Orchestrator, Executor, Reviewer. | [08](08-sessions-and-isolation.md), [10](10-v2-orchestration.md) |
| **Orchestrator** | The DAG coordinator. Auto-spawned by the kernel at `approve_plan` (never declared in `[[tasks]]`). The only role authorised to submit `ActivateSubTask`, `RetrySubTask`, and `IntegrationMerge`. | [10](10-v2-orchestration.md) |
| **Executor** | The code-writing role. Submits `SingleCommit` and `CompleteTask`; never merges, never reviews, never delegates. | [10](10-v2-orchestration.md) |
| **Reviewer** | The verdict-only role. Submits `SubmitReview { approved, critique }`; never writes code, never merges, never `CompleteTask`s, never `ReportFailure`s. | [10](10-v2-orchestration.md), [`patterns/02-reviewer-panel`](../guides/recipes/patterns/02-reviewer-panel.md) |
| **Session** | A kernel-issued identity for one agent VM lifecycle. Carries `session_id` (UUID v4), `session_token` (64-char hex, CSPRNG), `session_agent_type`, and a `lineage_id`. Persisted in the `sessions` table. | [08](08-sessions-and-isolation.md) |
| **Session token** | The 64-char hex secret an agent presents on every IntentRequest. Verified against `sessions.session_token`; replay-protected via `nonce_cache` + `sequence_number`. | `kernel/src/authority/session.rs` |
| **`session_agent_type`** | One of `Orchestrator`, `Executor`, `Reviewer`, or NULL (V1 compat). The dispatch matrix's row index. | `crates/types/src/session.rs::SessionAgentType` |
| **`lineage_id`** | UUID grouping every retry of the same logical task. New activations from `RetrySubTask` mint a fresh `session_id` but **inherit** the lineage so forensic replay can trace the full retry chain. | [08](08-sessions-and-isolation.md) |
| **`can_delegate`** | A boolean field on the `sessions` row. Only Orchestrator sessions may have `can_delegate = 1`; the kernel rejects any other session asserting it. Second line of defence behind the dispatch matrix (INV-DELEGATE-01). | `kernel/src/authority/dispatch_matrix.rs` |
| **System-prompt assembly** | The kernel-side process of building each agent's per-session system prompt (role-block + plan-context-block + critique-block + provider-block). Operators never directly author the system prompt. | [08](08-sessions-and-isolation.md), `kernel-system-prompts.md` |

### Tasks, the DAG, and lifecycle FSMs

| Term | Meaning | Defined in |
|---|---|---|
| **Task** | One declared `[[tasks]]` entry in the plan. Lives in the `tasks` table. Has its own FSM, lane assignment, predecessors, path-allowlist, and (in V2) `session_agent_type`. | [10](10-v2-orchestration.md), [recipes/plan/03-tasks-block](../guides/recipes/plan/03-tasks-block.md) |
| **Sub-task** | At V2, every task that isn't the auto-spawned Orchestrator: i.e. every `[[tasks]]` entry. The terms "task" and "sub-task" are interchangeable except in dispatch-matrix prose where "sub-task" disambiguates from the Orchestrator. | [10](10-v2-orchestration.md) |
| **Task FSM** | `Pending → Admitted → Running → {Completed \| Failed \| GatesPending}`. Transitions go through `kernel/src/initiatives/task_transitions.rs::transition_task` (INV-INIT-04: never raw `UPDATE tasks SET state = …`). | `task-states.md`, `task_transitions.rs` |
| **Activation** | One run of a sub-task. A row in `subtask_activations`. Per Migration 5 (line 51-52), each retry **inserts** a new row; rows are append-only. Activation FSM: `PendingActivation → Active → {Completed \| Failed}`. | [08](08-sessions-and-isolation.md), [`patterns/04-retry-on-failure`](../guides/recipes/patterns/04-retry-on-failure.md) |
| **`predecessors`** | Per-task DAG edge list. The kernel-correct field name (`depends_on` is spec-prose only). A task admits only when every predecessor is `Completed`. | [recipes/plan/07-predecessors](../guides/recipes/plan/07-predecessors.md) |
| **`path_allowlist`** | The set of paths a task's session is allowed to read/write under its worktree. Enforced at `IntegrationMerge` admission (Check 5). | [recipes/plan/04-path-allowlist](../guides/recipes/plan/04-path-allowlist.md) |
| **`cross_cutting_artifacts`** | The orchestrator-level escape hatch in `[orchestrator]`: paths the auto-spawned Orchestrator may touch during merge that no Executor's `path_allowlist` covers (typically `Cargo.lock`). | [`patterns/06-cross-cutting-refactor`](../guides/recipes/patterns/06-cross-cutting-refactor.md) |
| **`crash_retry_count`** | Per-activation counter. Incremented when the VM exits non-zero / OOMs / panics / hits `cumulative_max_seconds`. Ceilinged by `max_crash_retries` (default 3). | [10](10-v2-orchestration.md), `kernel/src/handlers/intent.rs::handle_retry_sub_task` |
| **`review_reject_count`** | Per-activation counter. Incremented when an aggregated reviewer panel terminal-rejects (`SubmitReview { approved = false }` causes the aggregator to enter `AtLeastOneRejected`). Ceilinged by `max_review_rejections` (default 2). | [10](10-v2-orchestration.md), `kernel/src/handlers/intent.rs::handle_submit_review` |
| **Initiative FSM** | `Pending → Approved → Executing → {Completed \| Failed \| Aborted \| Quarantined}`. | `initiative-states.md` |
| **Lineage** | The chain of activations sharing a `lineage_id`. Captures every retry of a single logical task across crashes, review rejections, and operator interventions. | [08](08-sessions-and-isolation.md) |

### Intents (wire surface)

| Term | Meaning | Defined in |
|---|---|---|
| **Intent / `IntentRequest`** | The bincode-framed wire envelope a planner submits to the kernel. Carries `session_token`, `sequence_number`, `envelope_nonce`, `intent_kind`, and per-kind payload. | [02](02-intent-admission.md), `crates/types/src/intent.rs` |
| **`IntentKind`** | The discriminator. Eight variants total at V2.5: `SingleCommit`, `IntegrationMerge`, `CompleteTask`, `ReportFailure`, `ActivateSubTask`, `RetrySubTask`, `SubmitReview`, `StructuredOutput`. | `crates/types/src/intent.rs` |
| **`SingleCommit`** | Executor-only. Submits a commit SHA along with `submitted_claims` (kernel auto-derives from witnesses). | [01](01-claims-and-gates.md) |
| **`IntegrationMerge`** | Orchestrator-only. Fast-forwards the workspace `target_ref` onto the merged tree of approved sub-task commits. Subject to the hybrid path-allowlist + integration-merge-verifier admission pipeline. | [`patterns/03-merge-with-integration-verifiers`](../guides/recipes/patterns/03-merge-with-integration-verifiers.md), `specs/v2/integration-merge.md` |
| **`CompleteTask`** | Executor or Reviewer. Terminal state for a task. Reviewers `Complete` after a `SubmitReview`. | `crates/types/src/intent.rs` |
| **`ReportFailure`** | Surface a non-recoverable failure. Marks the task `Failed`. | `crates/types/src/intent.rs` |
| **`ActivateSubTask`** | Orchestrator-only. The single VM-spawn entrypoint: creates a new `subtask_activations` row in `Active` and asks the substrate to spawn the Executor or Reviewer VM. | [10](10-v2-orchestration.md) |
| **`RetrySubTask`** | Orchestrator-only. Cleanup-and-prepare for a retry: validates the prior activation is `Failed`, checks both retry ceilings, revokes the prior session, inserts a new `PendingActivation` row carrying counters forward, resets `tasks.state` to `Admitted`. **Does not spawn** — the Orchestrator follows up with `ActivateSubTask`. | [`patterns/04-retry-on-failure`](../guides/recipes/patterns/04-retry-on-failure.md), `kernel/src/handlers/intent.rs::handle_retry_sub_task` |
| **`SubmitReview`** | Reviewer-only. Carries `{ approved: bool, critique: Option<String> }`. Bumps `review_reject_count` on terminal-rejection at the aggregator. | [10](10-v2-orchestration.md) |
| **`StructuredOutput`** | Typed payload (V2.5). One of `TaskSummary`, `ProgressReport`, `DiagnosticFlag`. Persists structured agent reasoning to the audit chain without affecting task FSM. | `v2_extended_gaps.md §3.2` |
| **Dispatch matrix** | The compile-time `(IntentKind, SessionAgentType) → Authorized \| Unauthorized` lookup at `kernel/src/authority/dispatch_matrix.rs`. The first authorisation gate every IntentRequest passes through. | [10](10-v2-orchestration.md) |

### Claims, gates, witnesses, verifiers

| Term | Meaning | Defined in |
|---|---|---|
| **Claim** | A `SubmittedClaim { kind, sha, target }` assertion attached to a `SingleCommit`. Each claim resolves a specific gate. The kernel auto-derives the claim list from witnesses; agents do not author it. | [01](01-claims-and-gates.md) |
| **Gate** | A kernel-side condition a SHA must satisfy to advance (e.g. "cargo test passed", "SBOM emitted"). Gates are auto-generated from `[[tasks.verifiers]]`. | [01](01-claims-and-gates.md) |
| **Witness** | A content-addressed evidence blob emitted by a verifier subprocess. Carries the verifier image SHA, the input subset SHA, and the output. The audit-chain anchor for "did this verifier run, and what did it return?". | [01](01-claims-and-gates.md), [recipes/cli/28-witnesses-verifiers](../guides/recipes/cli/28-witnesses-verifiers.md) |
| **Verifier** | A kernel-isolated subprocess (run inside a verifier VM) that produces a witness. Two surfaces: per-task `[[tasks.verifiers]]` (plan-side) and `[[integration_merge_verifiers]]` (policy-side). | [`patterns/03-merge-with-integration-verifiers`](../guides/recipes/patterns/03-merge-with-integration-verifiers.md) |
| **Verifier image** | A signed VM rootfs image referenced by `image_alias` in `policy.toml`'s `[[vm_images]]`. The kernel pulls + verifies the image before running the verifier. | [recipes/ops/09-publish-verifier-image](../guides/recipes/ops/09-publish-verifier-image.md) |
| **Auto-derivation** | The kernel-side process of populating a `SingleCommit`'s `submitted_claims` from existing witness rows; pre-fix, planners hard-coded `submitted_claims: vec![]`. | [01](01-claims-and-gates.md) — "Gap Found" section |

### Authority, security, and isolation

| Term | Meaning | Defined in |
|---|---|---|
| **Authority graph** | The operator-signed `[authority]` block describing which operators can sign plans, mint certs, and grant delegations. | [04](04-delegations-and-authority.md), [recipes/policy/02-authority-section](../guides/recipes/policy/02-authority-section.md) |
| **Delegation** | An operator-signed, TTL-bounded capability grant: "operator A delegates X authority to operator B until time T". Subject to epoch-staleness checks. | [04](04-delegations-and-authority.md) |
| **Operator certificate** | The Ed25519 signing identity an operator presents on every signed artifact (`policy.toml`, signed plans, delegations). Minted via `raxis cert mint`. | [recipes/cli/17-cert-mint](../guides/recipes/cli/17-cert-mint.md) |
| **Nonce cache** | The kernel-side replay-protection structure: every `IntentRequest`'s `envelope_nonce` is checked against a per-session window before sequence-number advancement. | `kernel/src/authority/session.rs::accept_envelope_and_advance_sequence` |
| **Egress allowlist** | Per-task `egress_allowed = ["api.openai.com:443", …]` declaring outbound HTTPS destinations the agent may reach. Enforced by the kernel-side egress proxy; deny-by-default. | [recipes/plan/09-vm-image-and-egress](../guides/recipes/plan/09-vm-image-and-egress.md) |
| **Credential proxy** | Localhost TCP listeners (Postgres, MySQL, MSSQL, MongoDB, Redis, HTTP, SMTP, AWS, GCP, Azure) the agent talks to instead of the real backend; the proxy injects credentials, applies per-proxy restrictions (table allowlists, max result rows), logs every request, and forwards upstream. | [03](03-credential-proxies.md) |
| **Credential backend** | The pluggable trait (`CredentialBackend`) the proxy queries to resolve a per-task credential at request time. | [03](03-credential-proxies.md), `extensibility-traits.md §4` |
| **Quarantine** | An operator-driven hard halt of a single plan, a single operator's plans, or an initiative. Surfaces as `initiatives.state = Quarantined`; the kernel admits no further intents against it. | [recipes/cli/12-initiative-abort-quarantine](../guides/recipes/cli/12-initiative-abort-quarantine.md), [recipes/cli/33-operator-quarantine-plans-by](../guides/recipes/cli/33-operator-quarantine-plans-by.md) |

### Lanes, budgets, and scheduling

| Term | Meaning | Defined in |
|---|---|---|
| **Lane** | A named concurrency container declared in `[[lanes]]`. Carries `max_concurrent_tasks` (admission ceiling) and an `admission_strategy`. | [05](05-lanes-and-budgets.md), [recipes/policy/07-lanes-section](../guides/recipes/policy/07-lanes-section.md) |
| **Budget** | A `[[budget]]` row keyed on `scope = "lane" \| "operator"`. Carries `max_cost_per_epoch` + `epoch_seconds`. Cost is summed from `tasks.actual_cost` across the rolling window. | [05](05-lanes-and-budgets.md), [recipes/policy/06-budget-section](../guides/recipes/policy/06-budget-section.md) |
| **Admission strategy** | `fifo` or `priority`. Selects the next Pending task once a lane slot frees. | `kernel/src/scheduler/lane.rs` |
| **`actual_cost`** | The per-task cost stamp the kernel writes after admission. Sums into the lane / operator budget snapshot. | `tasks.actual_cost` |
| **`cumulative_max_seconds`** | Per-task wall-clock ceiling. The kernel kills the VM and bumps `crash_retry_count` on overrun. | [recipes/plan/12-cumulative-max-seconds](../guides/recipes/plan/12-cumulative-max-seconds.md) |

### Worktrees, git, and the merge surface

| Term | Meaning | Defined in |
|---|---|---|
| **Worktree** | The kernel-mounted local checkout of the workspace repository attached to a session. Constrained by the session's `worktree_root` allowlist. | [08](08-sessions-and-isolation.md), [recipes/setup/08-allowlist-worktree-roots](../guides/recipes/setup/08-allowlist-worktree-roots.md) |
| **`worktree_root`** | The directory prefix under which the kernel may instantiate a session's worktree. Per-session immutable. | [08](08-sessions-and-isolation.md) |
| **Clone strategy** | One of `full`, `sparse`, or `blobless`. Controls how the kernel populates a session's worktree. Sparse/blobless are RO scopes used for Reviewer sessions. | [recipes/plan/05-clone-strategy](../guides/recipes/plan/05-clone-strategy.md) |
| **Workspace** | The `[workspace]` block of `plan.toml`: repository name, `base_sha`, `target_ref`, optional `lane_id`. The plan-time pin of the merge target. | [recipes/plan/02-workspace-block](../guides/recipes/plan/02-workspace-block.md) |
| **`base_sha` / `target_ref`** | The commit the workspace clones at, and the ref the merge fast-forwards. The merge admission pipeline checks the candidate tree's ancestry against both. | `specs/v2/integration-merge.md` |
| **Candidate merge tree** | The kernel-computed orphan commit produced at `IntegrationMerge` Check 5d. Integration verifiers run against this tree before fast-forward. | `specs/v2/integration-merge.md` |

### Audit chain, escalations, and kernel pushes

| Term | Meaning | Defined in |
|---|---|---|
| **Audit chain** | The append-only, hash-linked JSONL log under `audit/`. Every kernel mutation emits one record; each record's `prev_sha256` chains to its predecessor's `raw_line_sha256`. Tamper-evident. | [06](06-audit-chain.md) |
| **`AuditEventKind`** | The typed enum of every audit record variant (`SessionCreated`, `SessionRevoked`, `IntentSubmitted`, `WitnessRecorded`, `IntegrationMergeCompleted`, …). | `crates/audit/src/event.rs` |
| **Audit segment** | A single audit file (`audit/0000000001.jsonl`). The chain rolls to a new segment on size threshold; `genesis_record` anchors each new segment back to the previous one. | [06](06-audit-chain.md) |
| **Genesis record** | The first record of every audit segment, carrying the previous segment's tail hash. Validated by `raxis log verify`. | [recipes/cli/24-log-verify-chain](../guides/recipes/cli/24-log-verify-chain.md) |
| **Escalation** | A human-in-the-loop pause. Created by an `[[escalations]]` rule firing or an explicit agent request; the kernel admits no further intents on the affected scope until the operator approves or denies. | [07](07-escalations.md), [recipes/policy/03-escalation-policy](../guides/recipes/policy/03-escalation-policy.md) |
| **Kernel push (`KernelPush`)** | An async kernel-to-planner notification (e.g. `AllReviewersPassed`, `ReviewRejected`, `ExecutorCrashed`, `SubscribeInitiativeAttached`). Delivered over the per-session bridge or the operator UDS stream. | [`specs/v2/kernel-push-protocol.md`](../specs/v2/kernel-push-protocol.md) |
| **Reconciliation** | The kernel-restart catch-up phase: walks the on-disk store + audit chain to detect activations that were `Active` at shutdown, drives them to `Failed`, and re-emits any pending pushes. | [recipes/ops/13-handle-reconciliation-gap](../guides/recipes/ops/13-handle-reconciliation-gap.md) |

### Common error codes (`PlannerErrorCode`)

| Code | Meaning |
|---|---|
| `Unauthorized` | Replay protection rejected the envelope (bad nonce / sequence) or the dispatch matrix said `Unauthorized`. |
| `FAIL_UNKNOWN_TASK` | Task row, plan-registry entry, or activation row missing. |
| `FAIL_INVALID_REQUEST` | Wire-shape / payload validation failed; or a retry ceiling was met / the prior activation is in a non-retryable state. |
| `FAIL_POLICY_VIOLATION` | Defence-in-depth catch for internal SQL / authority errors; also some delegation gate failures. |
| `FAIL_PATH_OUTSIDE_ALLOWLIST` | The candidate merge tree touched a path neither in any sub-task's `path_allowlist` nor in `cross_cutting_artifacts`. |
| `FAIL_INTEGRATION_MERGE_VERIFIER_BLOCKED` | A `[[integration_merge_verifiers]]` with `on_failure = "block_merge"` rejected. |
| `FAIL_TASK_VERIFIER_BLOCKED` | A `[[tasks.verifiers]]` with `on_failure = "block"` rejected at its declared gate. |
| `FAIL_LANE_AT_CAPACITY` | The lane is at `max_concurrent_tasks`. |
| `FAIL_BUDGET_EXHAUSTED` | The lane / operator budget hit `max_cost_per_epoch`. |
| `FAIL_TASK_ENVIRONMENT_INCONSISTENT` | A plan crosses environments illegally (e.g., a single initiative declares both staging + prod credentials). |
| `FAIL_PROTECTED_PATH_APPROVAL_REQUIRED` | The merge touched a protected path (Check 5b) — operator escalation is required. |

---

## Gaps Found During Documentation

Each concept guide includes a "Gap Found" section when an implementation gap was discovered during the analysis. Summary:

| Concept | Gap | Severity | Status |
|---------|-----|----------|--------|
| Claims & Gates | Planner hardcoded `submitted_claims: vec![]` | 🔴 Critical | **Fixed** — kernel auto-derives from witnesses |
| Credential Proxies | Per-request audit emit uses `warn!` not hard abort | 🟡 Low | Accepted deviation |
| Escalations | Cooldown timer not enforced after rejection | 🟡 Medium | Needs implementation |
| Sessions & Isolation | No proactive liveness monitoring (heartbeat) | 🟡 Medium | Needs implementation |

---

## How to Read

Each document follows the same structure:
1. **What is it?** — one-paragraph explanation
2. **Step by step** — operator configures → agent acts → kernel enforces
3. **Visual pipeline** — ASCII flow diagram
4. **Edge cases** — what happens when things go wrong
5. **Gap analysis** — implementation issues found during review
6. **Key source files** — where to look in the code

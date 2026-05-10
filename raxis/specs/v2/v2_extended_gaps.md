# RAXIS V2 — Extended Gaps & Forward Features

> **Last updated:** 2026-05-09
> **Scope:** Items discovered during the V2.5 code audit that are
> **not covered** by `V2_GAPS.md`. That document tracks spec-vs-code
> reconciliation for the 30 V2 specification documents. This document
> tracks **functional gaps**, **ergonomic features**, and **new
> subsystems** that the code audit surfaced as necessary for
> production-ready operator deployments.
>
> **Relationship to V2_GAPS.md:** V2_GAPS.md is closed — every V2
> BLOCKER is resolved through V2.5. This document captures the
> *next* layer: things that must work for operators to run real
> workloads end-to-end.

---

## §1 — 🔴 Category 1: Functional Gaps (blocks real end-to-end usage)

These are code-verified gaps that prevent the kernel from executing
real agent workloads. The planner binaries, the dispatch loop, the
tool registries, the intent pipeline — all of that is implemented.
But two wiring gaps mean that no real agent work actually runs today.

### §1.1 — Planner task-prompt plumbing (FORWARD-ONLY, IMPLEMENTED)

**Severity:** 🔴 P0 — blocks all agent execution.
**Status:** ✅ **Implemented in V2.5** (forward-only — no scaffold-mode fallback).

**The problem.** The three planner role binaries (executor, reviewer,
orchestrator) have a full working agent loop
(`crates/planner-core/src/driver.rs::run_role_session`) that:

1. Parses the kernel-stamped env contract
   (`RAXIS_KERNEL_PLANNER_SOCKET`, `RAXIS_PLANNER_TASK_PROMPT`, etc.)
2. Builds the role-specific tool registry (executor: write tools;
   reviewer: read-only; orchestrator: DAG tools)
3. Constructs a `DispatchLoop` with the configured `ModelClient`
4. Renders the role-specific system prompt
5. Drives the loop to a terminal outcome
6. Converts the terminal tool into the matching IPC intent
   (`task_complete`, `submit_review`, `integration_merge`, etc.)
7. Returns a structured `DriverOutcome`

In V1 / V2.4-and-earlier the kernel never stamped
`RAXIS_PLANNER_TASK_PROMPT` into the guest env at spawn time, so
every spawned planner binary entered `DriverOutcome::Scaffold` and
parked on SIGTERM — **no real agent work ran**.

**Forward-only mandate.** Raxis V2.5 retired scaffold mode as a
production code path. There is no end user yet, so we move
features forward instead of carrying optional V1 plumbing
indefinitely. The new contract is:

* **Admission rejects empty descriptions.** The plan validator
  (`raxis-cli plan validate`) and the kernel's
  `parse_plan_tasks` / `parse_plan_orchestrator` reject any plan
  whose `[plan.initiative]` block or any `[[tasks]]` stanza is
  missing / empty / non-string / oversized `description` with
  `LifecycleError::PlanInvalid` ("`FAIL_PLAN_PARSE_ERROR`"),
  exactly the same severity as a missing `task_id`.
* **Stamping is unconditional.** Both spawn sites
  (`session_spawn_orchestrator::spawn_for_initiative` and
  `handlers::intent::handle_activate_sub_task` →
  `spawn_executor_for_task`) unconditionally populate
  `RAXIS_PLANNER_TASK_PROMPT` from the `PlanRegistry`'s
  `TaskPlanFields::description` /
  `OrchestratorPlanFields::description`. A
  `debug_assert!(!task_prompt.is_empty(), …)` guards both
  sites so a future regression in the parser surfaces loudly in
  test builds rather than silently spawning an idle agent.
* **Source of truth.** Orchestrator prompt comes from
  `[plan.initiative] description`; per-task prompts come from
  `[[tasks]] description`. Plan templates and scenario fixtures
  ship with concrete prompts — the migration removed every
  `[workspace] description` and every `context = …` field that
  pre-dated the canonical schema.

**Implementation surface (v2.5 → main).**

1. `kernel/src/initiatives/plan_registry.rs` —
   `TaskPlanFields::description` and
   `OrchestratorPlanFields::description` now non-optional fields
   on the registry, populated at `approve_plan` time.
2. `kernel/src/initiatives/lifecycle.rs::parse_plan_tasks` /
   `parse_plan_orchestrator` — extract + validate
   (trim trailing whitespace, 64 KiB cap, reject empty / wrong
   type).
3. `kernel/src/session_spawn_orchestrator.rs` —
   `pub const PLANNER_TASK_PROMPT_ENV` declared once;
   `spawn_for_initiative` stamps it unconditionally; trait doc
   pins the "always non-empty by construction" contract.
4. `kernel/src/handlers/intent.rs::handle_activate_sub_task` —
   builds `extra_env` with `RAXIS_PLANNER_TASK_PROMPT` from the
   plan registry's task fields.
5. `cli/src/commands/plan_validate.rs` — mirrors the kernel-side
   validation so operators see the rejection at `plan validate`
   time, before signing.
6. CLI templates (`cli/templates/plan_*.toml`) and scenario
   plans (`guides/scenarios/*/plan.toml`) ship with concrete,
   non-trivial multi-line descriptions for both
   `[plan.initiative]` and every `[[tasks]]`.

**Invariant safety.** The change preserves every prior invariant
and tightens one (`INV §1.1`: every spawned agent has a non-empty
seed prompt). There is intentionally no escape hatch — production
must move forward; legacy "park in scaffold mode" plans are
rejected at admission, not silently degraded at spawn.

---

### §1.2 — Integration merge host-side fast-forward (V2.5 IMPLEMENTED — Phase 2 inline)

**Status:** 🟢 Phase 2 (host-side fast-forward) is wired; the Phase 3
durable-recovery flag (`git_apply_pending`) tracked separately under
the §11.1 spec migration TODO.

**Forward-only mandate.** Per the V2 cleanup, there is no longer a
"backwards-compatibility audit-only path." Every successful
`IntegrationMerge` intent now drives the kernel through the
two-phase commit defined by `integration-merge.md §11`:

* **Phase 1 (SQLite intent commit).** The kernel state machine is
  advanced and `IntegrationMergeCompleted` is emitted. (Same as
  before.)
* **Phase 2 (host-side fast-forward of the operator-configured
  `target_ref`).** Performed inline by the kernel, AFTER the SQLite
  commit and BEFORE the optional `auto_push`, by calling
  `raxis_domain_git::commit_merge_to_target_ref`. The function is
  idempotent on success; the operator-configured `target_ref` is
  resolved at admission time (`[workspace] target_ref` ⊕ `[git]
  default_target_ref` ⊕ `[git] target_ref_locked` ⊕ hardcoded
  `refs/heads/main`), stamped into `OrchestratorPlanFields`, and
  re-resolved against the *current* policy on kernel restart by
  `repopulate_plan_registry`.

**Implementation surface.**

* `kernel/src/handlers/intent.rs` — `run_phase_c` IntegrationMerge
  branch (after `tx.commit()`). Reads `target_ref` from
  `ctx.plan_registry.orchestrator(initiative_id).target_ref` and
  calls `commit_merge_to_target_ref` with the orchestrator
  `worktree_path` from `pre_state`.
* `kernel/src/initiatives/plan_registry.rs` — `OrchestratorPlanFields`
  carries `target_ref: String` (default `refs/heads/main`).
* `kernel/src/initiatives/lifecycle.rs` — `approve_plan` writes the
  resolved `target_ref` into the registry; `repopulate_plan_registry`
  re-resolves the plan's `target_ref` field against the current
  policy on kernel restart.
* `crates/audit/src/event.rs` — `MergeFastForwardFailed` audit
  variant (5 fields: `initiative_id`, `commit_sha`, `target_ref`,
  `category`, `reason`).
* `crates/domain-git/src/lib.rs` — `commit_merge_to_target_ref` is
  the existing host-side primitive (Phase 2a fetch + Phase 2b
  atomic ref update via `git update-ref`).

**Failure handling — `MergeFastForwardFailed`.** When Phase 2
fails, the kernel:

1. Logs the failure to stderr as a structured JSON line with
   `event = "IntegrationMergeFastForwardFailed"`.
2. Emits a typed `MergeFastForwardFailed` audit event carrying the
   `category` discriminator (`unopenable_main_repo`,
   `unopenable_source_repo`, `git_failed`, `missing_commit`,
   `target_ref_advanced_concurrently`, `invalid_sha`).
3. Suppresses the optional `auto_push` (pushing the un-advanced
   `target_ref` would race the operator's manual recovery).
4. Returns `IntentResponse::Accepted` for the Phase-1 intent — the
   merge commit IS recorded, the state machine IS advanced, and
   the audit chain has the durable signal an external auditor /
   operator dashboard / future recovery driver needs.

The full Phase-3 `git_apply_pending` durable-recovery flag is
tracked as a follow-up; the V2.5 cut performs Phase 2 inline and
relies on the audit-chain signal for operator recovery.

**Tests.**

* `kernel/tests/integration_merge_attribution_chain.rs::
  merge_fast_forward_failed_lands_on_audit_chain_with_category_discriminator`
  — pins the on-disk audit shape (real `FileAuditSink` +
  `AuditWriter`) and chain integrity.
* `crates/audit/src/event.rs` — `merge_fast_forward_failed_*`
  unit tests pin JSON round-trip + `as_str()` projection.
* `crates/domain-git/src/lib.rs` — full coverage of
  `commit_merge_to_target_ref` (idempotency, fetch, ref txn) is
  exercised by the existing `domain-git` integration test suite.

**Invariant safety.** The kernel never advances `current_sha`
past what the state machine committed; Phase 2 failure leaves the
initiative's `current_sha` at the orchestrator's claimed `head_sha`
in SQLite (the state machine already committed) but the
operator-configured `target_ref` lags. The `MergeFastForwardFailed`
audit row is the durable signal; the recovery driver re-runs
`commit_merge_to_target_ref` on next boot (the call is idempotent
on success).

---

## §2 — 🟡 Category 2: Operator-Facing Features (not blocking ship, high value)

### §2.1 — `SubscribeInitiative` (real-time initiative event stream)

**Current state:** Returns `FAIL_NOT_YET_IMPLEMENTED`
(`kernel/src/ipc/operator_ergonomics.rs:550-563`).

**What it does.** Lets an operator run `raxis initiative watch
init-123` and receive a live stream of events as they happen:

* Task activated / completed / failed
* Reviewer verdict delivered
* Escalation raised / resolved
* Integration merge completed
* Budget threshold crossed

**Why it was deferred.** The operator UDS is single-shot: one
request frame → one response frame → connection close. The
original design assumed this required a full `KernelPush`
bidirectional transport redesign.

**Revised assessment.** A simpler implementation is viable in V2:

1. On `SubscribeInitiative { initiative_id }`, hold the connection
   open.
2. Register a `tokio::sync::broadcast::Receiver` on the kernel's
   existing `NotificationRouter` for events matching the initiative.
3. Write each event as a length-prefixed JSON frame (same wire
   format as the existing response).
4. Close the connection on initiative terminal state or client
   disconnect.

The client reads frames in a loop. No protocol redesign needed —
just changing the handler from "write one frame, close" to "write
frames in a loop, close on terminal."

**Estimate:** ~80 lines (handler + broadcast tap + client-side
CLI `initiative watch` subcommand).

**Workaround today:** Operators poll `DescribeInitiativePause` or
read the audit chain via `raxis audit tail`.

---

### §2.2 — MongoDB SCRAM-SHA-256 (credential proxy auth)

**Current state:** `credential-proxy-mongo` supports `--noauth`
only. The proxy synthesizes empty `saslSupportedMechs` so MongoDB
drivers skip authentication entirely.

**What it does.** When an executor VM connects to a MongoDB
credential proxy, the proxy authenticates with the real upstream
MongoDB on the agent's behalf. SCRAM-SHA-256 is MongoDB's default
authentication mechanism since MongoDB 4.0.

**What works today.** The proxy handles the MongoDB wire protocol
(`OP_MSG`) and routes queries to the upstream, but only for
`--noauth` development deployments. Production MongoDB instances
that require authentication are not reachable through the proxy.

**What's needed.**

1. **SCRAM-SHA-256 handshake implementation.** Multi-round-trip
   challenge-response: `SASLStart` → server nonce + salt + iteration
   count → client proof (HMAC-SHA-256) → server signature
   verification. ~300 lines of crypto plumbing using the `hmac` and
   `sha2` crates (already in the workspace for `raxis-crypto`).

2. **Credential injection.** The proxy reads the upstream MongoDB
   username/password from the credential store (same path as the
   Postgres and MySQL proxies) and injects them into the SCRAM
   handshake transparently. The agent never sees the credential.

3. **`OP_MSG` real relay.** Today the proxy synthesizes responses
   for some operations. Full SCRAM requires real bidirectional
   `OP_MSG` relay with the frame header intact. ~100 lines.

**Estimate:** ~400 lines total.

**Invariant safety:** The credential proxy is outside the kernel's
trust boundary — it runs on the host side, mediating between the
in-VM tproxy and the upstream database. No kernel invariants are
affected. The only RAXIS-relevant constraint is that the credential
never enters the VM (enforced by the tproxy architecture, unchanged).

---

### §2.3 — MySQL `caching_sha2_password` (credential proxy auth)

**Current state:** `credential-proxy-mysql` supports
`mysql_native_password` only. Operators using MySQL 8.0+ must set
`default-authentication-plugin=mysql_native_password` on their
upstream.

**What it does.** `caching_sha2_password` is MySQL 8.0's default
authentication plugin. It uses SHA-256 with an RSA public key
exchange for the first connection (when the server's auth cache
is cold) and a cached fast-path for subsequent connections.

**What's needed.**

1. **RSA public key exchange.** On first connection (cache miss),
   the server sends its RSA public key; the client encrypts the
   password with it. ~80 lines using the `rsa` crate.
2. **SHA-256 hashing.** Replace the `mysql_native_password`
   double-SHA1 path with SHA-256. ~40 lines.
3. **Fast-path detection.** When the server indicates a cache hit
   (`0x03` response), skip the RSA exchange. ~20 lines.

**Estimate:** ~140 lines.

**Invariant safety:** Same as §2.2 — credential proxy is outside
the kernel trust boundary.

---

### §2.4 — In-VM KSB (Kernel State Block) renderer (V2.5 IMPLEMENTED)

**Status:** ✅ Implemented in V2.5 (`raxis-ksb` shared crate +
kernel-side assembly + driver-side fold).

**Implementation surface (v2.5 → main).**

1. `crates/ksb/` — new workspace crate that owns `KsbSnapshot`,
   `DagRow`, `ReviewerVerdict`, `PendingEscalation`, `CredentialPort`,
   the `KSB_DELIMITER_OPEN` / `KSB_DELIMITER_CLOSE` /
   `PLANNER_KSB_ENV` / `KSB_SCHEMA_VERSION` constants, the
   `render_ksb` deterministic renderer, and `assemble_system_prompt`.
   `crates/planner-core/src/ksb.rs` is now a thin re-export so older
   import paths keep working.
2. `kernel/src/initiatives/ksb_assembly.rs` — projects live state
   (initiative + task rows, `PlanRegistry`, escalations) into a
   `KsbSnapshot`. Provides `fallback_snapshot` so transient SQLite
   contention never blocks initiative activation.
3. `kernel/src/session_spawn_orchestrator.rs` — both
   `spawn_orchestrator_for_initiative` and `spawn_executor_for_task`
   call `assemble_ksb_snapshot` (off the tokio worker via
   `spawn_blocking`), serialize to JSON, and stamp into the guest env
   as `RAXIS_PLANNER_KSB`. `LiveOrchestratorSpawn::new` takes
   `Arc<PlanRegistry>` so the spawn path can read plan-side fields.
4. `crates/planner-core/src/driver.rs` —
   `run_role_session_with_env_fn` reads `RAXIS_PLANNER_KSB`,
   deserializes to `Option<KsbSnapshot>`, and feeds
   `run_role_session_with_model`. The system prompt is built via
   `raxis_ksb::assemble_system_prompt(NNSP, snap)` when present; the
   NNSP-only path remains for unit tests that pass `None`.

**Tests.** `raxis-ksb` ships 21 unit tests (deterministic render,
delimiter sanitization, JSON round-trip, field-order stability).
`planner-core::driver` adds two new tests pinning the KSB-fold
contract (`run_role_session_with_model_folds_ksb_snapshot_into_system_prompt`
and `run_role_session_with_model_uses_nnsp_only_when_no_ksb_supplied`).
Kernel binary tests (750) and integration tests stay green.

**Invariant safety.** Unchanged from §2.4 invariant note above:
KSB is read-only, stamped into the guest env at spawn time, and the
agent cannot modify it.

**Original problem statement (preserved for context).** The planner's
system prompt was previously a hardcoded string template in
`crates/planner-core/src/driver.rs:400-422`. It said "you are the
executor for task X of initiative Y" but contained no live kernel
state.

**What KSB is.** The Kernel State Block is a structured JSON
document the kernel assembles at session activation time, containing:

* Initiative metadata (id, state, target_ref, policy_epoch)
* Task DAG snapshot (which tasks are done, which are blocked,
  which are running, predecessor/successor relationships)
* Reviewer verdicts on prior attempts (approved/rejected + critique)
* Escalation state (any pending escalations the operator must
  resolve)
* Credential proxy port assignments (which ports map to which
  upstream services)
* Path scope (which files this task is allowed to touch)
* Budget state (tokens consumed so far, ceiling)

**Why it matters.** Without KSB, the agent has no context about the
broader initiative. The executor doesn't know what other tasks have
done, what the reviewer said about the last attempt, or what files
it's allowed to touch. It operates on the task prompt alone.

**What's needed.**

1. **KSB assembly in the kernel.** A function that reads the
   initiative state, task states, reviewer verdicts, escalation
   rows, and credential port assignments from the store and
   assembles a `KsbDocument` struct. ~200 lines.
2. **KSB serialization.** Render the `KsbDocument` to a
   structured text block suitable for inclusion in the system
   prompt. ~50 lines.
3. **KSB injection at spawn time.** Stamp the rendered KSB into
   `extra_env["RAXIS_PLANNER_KSB"]` alongside
   `RAXIS_PLANNER_TASK_PROMPT`. The driver reads it and prepends
   it to the system prompt. ~30 lines.
4. **Driver-side rendering.** `render_system_prompt_for_role`
   reads `RAXIS_PLANNER_KSB` from the env and inserts it after
   the role blurb. ~20 lines.

**Estimate:** ~300 lines.

**Invariant safety:** KSB is read-only kernel state rendered at
spawn time. It does not mutate any rows, does not bypass admission,
and does not introduce a new IPC surface. The agent cannot modify
the KSB — it is stamped into the guest env before the process
starts. `INV-OPERATOR-ERG-01` (read-only handlers) is satisfied
trivially because KSB assembly is not a handler.

---

### §2.5 — Token-limit enforcement (per-provider pricing)

**Current state:** The `EstimateCost` handler uses a flat heuristic
rate (`$0.01 / 1K tokens`). The kernel tracks `actual_cost` on
the task row but has no per-provider pricing tables. There is no
mid-session budget enforcement — the dispatch loop runs to
completion regardless of spend.

**What's needed.**

1. **Policy schema expansion.** Add `[providers.<id>.pricing]`
   tables to `policy.toml`:

   ```toml
   [providers.anthropic.pricing]
   input_tokens_per_dollar  = 200_000   # $5 / 1M input
   output_tokens_per_dollar = 50_000    # $20 / 1M output
   ```

   Parsed into `ProviderPricing` on `PolicyBundle`. ~60 lines.

2. **Real-time token counting.** The dispatch loop already tracks
   `Usage { input_tokens, output_tokens }` per response. Wire
   the cumulative counts into the `IntentSubmitter` so the kernel
   receives actual token usage with every intent. ~30 lines.

3. **Budget enforcer.** At intent admission, the kernel computes
   the dollar cost from the provider's pricing table and the
   reported token counts, compares against
   `policy.max_cost_per_task`, and rejects if exceeded. ~80 lines.

4. **Mid-session abort.** The dispatch loop checks cumulative
   tokens against a ceiling (from `DispatchConfig`) after each
   model response. `DispatchOutcome::TokensExceeded` is already
   implemented — just needs the ceiling wired from the kernel's
   budget response. ~40 lines.

**Estimate:** ~210 lines.

**Invariant safety:** Budget enforcement is fail-closed — exceeding
the ceiling rejects the intent. No new trust surface; the pricing
tables are operator-declared in policy (same trust model as
`max_cost_per_task`).

---

### §2.6 — Sidecar streaming + heartbeat

**Current state:** The gateway's SSE reader
(`gateway/src/http_backend.rs`) streams model responses end-to-end.
But there is no heartbeat to detect stalled streams and no
mid-stream abort for budget enforcement.

**What's needed.**

1. **Heartbeat detection.** The gateway sends a `heartbeat` SSE
   comment every 15 seconds during an active stream. If no data
   or heartbeat arrives for 30 seconds, the gateway closes the
   upstream connection and returns a structured error to the
   planner. ~60 lines.

2. **Reconnect logic.** On heartbeat timeout or upstream
   disconnect, the gateway retries the request once (with the
   same idempotency key if the provider supports it). If the
   retry also fails, the error propagates to the planner as a
   `DispatchError::Model`. ~40 lines.

3. **Mid-stream budget abort.** The sidecar (host-side process
   co-located with the gateway) monitors cumulative tokens from
   the SSE `usage` events. When the per-session ceiling is
   reached, the sidecar closes the upstream connection mid-stream,
   causing the gateway to return a `TokensExceeded` error. ~80
   lines.

**Estimate:** ~180 lines.

**Invariant safety:** The gateway is outside the kernel trust
boundary. Heartbeat and reconnect are transparent to the planner
— it sees either a complete response or a structured error. The
mid-stream abort is a defense-in-depth limb for the budget enforcer
(§2.5); the kernel-side enforcement remains the authoritative
check.

---

## §3 — 🟢 Category 3: New Planner Tools

### §3.1 — `Sleep` (token-budget-preserving wait)

**What it does.** Lets an agent wait for an external process (CI
build, database migration, deployment rollout) without burning
model turns on a polling loop.

```json
{
  "tool": "sleep",
  "input": { "seconds": 15, "reason": "waiting for CI to finish" }
}
```

The dispatch loop calls `tokio::time::sleep(duration)` and resumes
without consuming a model inference turn. One `Sleep(15)` costs
zero tokens vs. a `bash("while ! curl ...; do true; done")` loop
that costs thousands.

**Policy guardrails required.**

1. **`policy.max_sleep_seconds`** — hard ceiling per call (e.g.,
   60). The tool rejects any `seconds > max_sleep_seconds` with
   a structured error. Prevents an agent from stalling a VM for
   hours.
2. **Cumulative sleep budget.** The dispatch loop tracks total
   sleep time. When cumulative sleep exceeds
   `policy.max_cumulative_sleep_seconds` (e.g., 300), the next
   `Sleep` call fails with `FAIL_SLEEP_BUDGET_EXCEEDED`.
3. **Wall-clock accounting.** Sleep time counts against the
   session's wall-clock budget (if configured) so a sleeping agent
   still eventually times out.

**Implementation.**

1. **Tool definition.** Add `sleep` to the executor tool registry
   (`crates/planner-core/src/tools.rs`). Input schema:
   `{ seconds: u32, reason?: string }`. ~40 lines.
2. **Dispatch integration.** The `DispatchLoop` handles `sleep`
   as a non-model tool call: sleep the duration, return
   `{ "slept_seconds": N }` as the tool result, resume without
   incrementing the turn counter. ~30 lines.
3. **Policy wiring.** Read `max_sleep_seconds` and
   `max_cumulative_sleep_seconds` from `DispatchConfig` (populated
   from the kernel's session env). ~20 lines.

**Estimate:** ~90 lines.

**Invariant safety.**

* `INV-PLANNER-HARNESS-04` (turn ceiling) — Sleep does not
  increment the turn counter, which is correct because no model
  inference occurs. The wall-clock budget is the backstop.
* `INV-CAPACITY-01` (VM slot) — Sleep holds the VM slot. The
  cumulative sleep budget prevents indefinite slot hold.
* Reviewer tool registry — `Sleep` is **not** added to the
  reviewer registry. The Pure-Static Reviewer has no external
  process to wait for (`INV-PLANNER-HARNESS-02`).

---

### §3.2 — `StructuredOutput` (typed mid-session communication)

**What it does.** Lets an agent emit structured data mid-session
that the kernel can validate, store, and surface to operators or
downstream agents. Unlike terminal tools (which end the session),
`StructuredOutput` is a **non-terminal** tool — the session
continues after the output is emitted.

**Design: fixed enum, not open-ended JSON.**

The kernel defines a closed set of output kinds. This is consistent
with the RAXIS invariant model: the kernel is a reference monitor
that structurally validates every IPC payload. Open-ended JSON
would create an unvalidatable surface.

> [!IMPORTANT]
> **Invariant review checkpoint.** Before implementing
> `StructuredOutput`, the following invariants MUST be reviewed to
> ensure the new tool does not create a bypass:
>
> * `R-1` (Domain separation) — structured output must not leak
>   cross-initiative state. Each output is scoped to the emitting
>   session's `(initiative_id, task_id)`.
> * `R-2` (Mediated I/O) — the output is submitted through the
>   kernel UDS, not written to a shared filesystem. The kernel
>   validates the payload before storing it.
> * `R-5` (Bounded capabilities) — the output tool is a capability
>   the kernel grants. It must be revocable (omit from tool registry
>   → agent cannot emit).
> * `R-10` (Opaque rejection) — if the kernel rejects an output
>   (malformed, rate-limited, unknown kind), the error message must
>   not leak internal kernel state.
> * `INV-PLANNER-HARNESS-02` — Reviewer must NOT have the
>   `structured_output` tool. Reviewer verdicts go through
>   `submit_review` exclusively.
> * `INV-PLANNER-HARNESS-04` — StructuredOutput IS a model turn
>   (the model chose to call the tool). It MUST increment the turn
>   counter.
> * `INV-OPERATOR-ERG-01` — Reading stored outputs via the CLI is a
>   read-only operation. The handler must not mutate kernel state.

**Output kind enum (Rust):**

> [!IMPORTANT]
> **Wire shape (INV-IPC-BINCODE).** The enum uses the **default
> external-tag** serde representation (NOT
> `#[serde(tag = "kind")]` as an earlier draft suggested). The
> canonical IPC encoder is `bincode::serde` which does NOT
> support `serde::deserialize_any` and rejects internally-tagged
> enums with `Decode(Serde(AnyNotSupported))`. The
> snake-case `kind` discriminator the model and CLI speak is
> bridged to the external-tag wire shape by the
> `parse_structured_output_input` helper in
> `crates/planner-core/src/tools.rs` and surfaced for SQL
> projections via `StructuredOutputKind::variant_tag()`.

```rust
/// Typed mid-session output kinds. Each variant has a fixed schema
/// the kernel validates before accepting.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StructuredOutputKind {
    /// Mid-session progress snapshot. The kernel stores it as an
    /// audit event; the operator dashboard (§4) renders it as a
    /// progress bar / file list.
    ProgressReport {
        files_modified: Vec<String>,
        tests_passing:  u32,
        tests_failing:  u32,
        confidence:     f32,  // 0.0–1.0, clamped at validation
    },

    /// "I found something the operator should see." The kernel
    /// stores it and optionally routes it through the notification
    /// system (§notification-routing.md). Critical-severity flags
    /// can trigger an escalation.
    DiagnosticFlag {
        severity: DiagnosticSeverity,  // Info | Warning | Critical
        message:  String,              // ≤ 1024 chars, validated
        evidence: Option<String>,      // file path or line ref
    },

    /// Executor → Orchestrator handoff. Stored on the task row so
    /// the orchestrator's KSB (§2.4) includes it when activating
    /// the next task.
    TaskSummary {
        commit_sha:    String,
        changed_paths: Vec<String>,
        approach:      String,  // ≤ 2048 chars, one-paragraph rationale
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticSeverity {
    Info,
    Warning,
    Critical,
}
```

**Tool input schema (JSON, exposed to the model):**

```json
{
  "name": "structured_output",
  "description": "Emit a typed mid-session output. Use progress_report for status updates, diagnostic_flag for operator alerts, task_summary for handoff to the orchestrator.",
  "input_schema": {
    "type": "object",
    "required": ["kind"],
    "properties": {
      "kind": { "enum": ["progress_report", "diagnostic_flag", "task_summary"] },
      "files_modified": { "type": "array", "items": { "type": "string" } },
      "tests_passing":  { "type": "integer" },
      "tests_failing":  { "type": "integer" },
      "confidence":     { "type": "number", "minimum": 0, "maximum": 1 },
      "severity":       { "enum": ["info", "warning", "critical"] },
      "message":        { "type": "string", "maxLength": 1024 },
      "evidence":       { "type": "string" },
      "commit_sha":     { "type": "string" },
      "changed_paths":  { "type": "array", "items": { "type": "string" } },
      "approach":       { "type": "string", "maxLength": 2048 }
    }
  }
}
```

**Implementation status: ✅ shipped (V2.5).**

1. **Types.** `StructuredOutputKind` + `DiagnosticSeverity` in
   `crates/types/src/structured_output.rs`. External-tag serde
   enum (see Wire shape note above) with `validate_and_normalise`
   (clamp confidence, truncate over-cap strings, reject non-hex
   `commit_sha`) + size constants
   (`STRUCTURED_OUTPUT_MAX_DIAG_MESSAGE_BYTES`,
   `STRUCTURED_OUTPUT_MAX_APPROACH_BYTES`,
   `STRUCTURED_OUTPUT_MAX_PATH_LIST_LEN`,
   `STRUCTURED_OUTPUT_MAX_PATH_BYTES`,
   `STRUCTURED_OUTPUT_PER_SESSION_RATE_LIMIT`).
2. **Tool handler.** `StructuredOutputTool` in
   `crates/planner-core/src/tools.rs` registered into
   `build_executor_registry_full` /
   `build_orchestrator_registry_full` (NOT reviewer — pinned by
   `reviewer_registry_never_includes_structured_output` test).
   Parses snake-case input → bridges to external-tag wire enum →
   submits via `IntentSubmitter::submit_structured_output`.
3. **Kernel IPC handler.** `IntentKind::StructuredOutput` arm in
   `kernel/src/handlers/intent.rs::run_phase_a` dispatches to
   `handle_structured_output` (validate → rate-limit COUNT +
   INSERT in one BEGIN IMMEDIATE tx → `StructuredOutputEmitted`
   audit emit → NON-TERMINAL Accepted response). The handler
   does NOT auto-escalate `DiagnosticFlag { severity: Critical }`
   in V2.5 — operator dashboards are the routing surface; an
   auto-escalation would be a policy decision (the kernel is the
   reference monitor, not the policy engine).
4. **Store.** Migration 13 creates `structured_outputs`:
   `(output_id, initiative_id, task_id, session_id, kind,
   severity, payload_json, emitted_at)`. Indexes on
   `(task_id, emitted_at)`, `(initiative_id, emitted_at)`,
   `(session_id)` so the CLI / dashboard read paths and the
   per-session rate-limit COUNT all run as index probes.
5. **CLI.** `raxis task outputs <task-id>` exposed by
   `cli/src/commands/task_outputs.rs`. Read-only.

**Rate limiting.** The kernel enforces
`STRUCTURED_OUTPUT_PER_SESSION_RATE_LIMIT` (currently 10) outputs
per session. Exceeding the limit returns
`FAIL_STRUCTURED_OUTPUT_RATE_LIMITED`. The COUNT + INSERT run
inside one `BEGIN IMMEDIATE` so concurrent submissions on the
same session cannot race past the cap.

---

## §4 — 🔵 Category 4: Operator Dashboard (HTTP backend + React UI)

### §4.1 — Overview

The operator dashboard is a **read-only web UI** that gives
operators real-time visibility into the kernel's state. It replaces
the need to run multiple CLI commands to understand what the kernel
is doing.

**Design principles:**

1. **Read-only.** The dashboard never mutates kernel state. All
   data comes from read-only SQLite connections
   (`SQLITE_OPEN_READ_ONLY`) and in-memory bounded queues. This
   is consistent with `INV-OPERATOR-ERG-01`.
2. **Operator-scoped.** Every view is scoped by the authenticated
   operator's role. An operator with `read` permission sees state;
   an operator with `write` permission can additionally view and
   edit `policy.toml` in the browser.
3. **Kernel-launched.** The HTTP server starts when the kernel
   starts (configurable via `policy.toml`). No separate process
   to manage.
4. **Fast.** React frontend with client-side rendering. The
   backend serves a static bundle + JSON API endpoints. No SSR,
   no framework overhead.

### §4.2 — Authentication (challenge-response with signed keys)

**Authentication flow.** The dashboard uses the same operator
key infrastructure (`raxis-crypto`) that the CLI uses. No
passwords, no sessions cookies with secrets — cryptographic
identity only.

1. **Browser requests challenge.** `GET /api/auth/challenge`
   returns a JSON object:
   ```json
   {
     "challenge": "<random-32-byte-hex>",
     "expires_at": 1715300000
   }
   ```
   The challenge is valid for 60 seconds. The kernel stores it
   in a bounded in-memory map (max 100 pending challenges; oldest
   evicted on overflow).

2. **Operator signs the challenge.** The browser prompts the
   operator to paste their `raxis` private key (or uses a
   browser extension / local agent that holds the key). The
   challenge is signed with Ed25519:
   ```
   POST /api/auth/verify
   {
     "challenge": "<the-challenge>",
     "signature": "<ed25519-sig-hex>",
     "public_key": "<operator-pubkey-hex>"
   }
   ```

3. **Kernel verifies.** The kernel:
   * Checks the challenge exists and is not expired.
   * Verifies the Ed25519 signature.
   * Looks up the public key in the `operator_keys` table.
   * Checks the operator's certificate status via
     `CertEnforcer::enforce` (same path as CLI auth).
   * Returns a short-lived JWT (1 hour, HS256 with a kernel-
     generated ephemeral secret rotated at boot):
     ```json
     {
       "token": "<jwt>",
       "operator_id": "alice",
       "roles": ["read", "write_policy"],
       "expires_at": 1715303600
     }
     ```

4. **Browser stores the JWT** in `localStorage` and sends it as
   `Authorization: Bearer <jwt>` on every API request.

5. **Logout.** `POST /api/auth/logout` — the kernel adds the JWT
   to a bounded revocation set (max 1000 entries; entries expire
   naturally). The browser clears `localStorage`.

**Roles.**

| Role | Permissions |
|---|---|
| `read` | View all dashboard pages (initiatives, tasks, DAG, sessions, audit, escalations, git worktrees, diffs, structured outputs, agent streams) |
| `write_policy` | Additionally: view and edit `policy.toml` in the browser, trigger policy reload |
| `admin` | Additionally: view operator keys, view certificate status, trigger `raxis doctor` from dashboard |

Roles are derived from the operator's certificate attributes
(same source as CLI permission checks). No separate role table.

### §4.3 — HTTP backend (Rust, kernel-integrated)

**Architecture.** The dashboard backend is a new crate
`raxis-dashboard` that the kernel binary links. It is NOT a
separate process — it shares the kernel's `Store` (read-only
connections) and `HandlerContext` (for policy snapshot, plan
registry, notification router).

**Server stack:**

* `axum` (already in the workspace via `gateway`) for HTTP routing
* `tower-http` for CORS, static file serving, compression
* `tokio` for async (already the kernel's runtime)

**Startup.** Configured in `policy.toml`:

```toml
[dashboard]
enabled       = true
bind_address  = "127.0.0.1"
bind_port     = 9820
# Optional: serve over TLS with the kernel's certificate.
tls_cert_path = ""
tls_key_path  = ""
```

The kernel starts the dashboard server in `kernel/src/main.rs`
after the store is initialized and the policy is loaded. A
disabled dashboard (`enabled = false`) has zero runtime cost.

**API endpoints (JSON):**

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/auth/challenge` | Issue a challenge for login |
| `POST` | `/api/auth/verify` | Verify signed challenge, return JWT |
| `POST` | `/api/auth/logout` | Revoke JWT |
| `GET` | `/api/initiatives` | List all initiatives with state summary |
| `GET` | `/api/initiatives/:id` | Initiative detail (state, metadata, task count) |
| `GET` | `/api/initiatives/:id/dag` | Task DAG as adjacency list with state per node |
| `GET` | `/api/initiatives/:id/tasks` | All tasks for an initiative |
| `GET` | `/api/tasks/:id` | Task detail (state, session, reviewer verdicts, structured outputs) |
| `GET` | `/api/tasks/:id/outputs` | Structured outputs for a task |
| `GET` | `/api/sessions` | List active and recent sessions |
| `GET` | `/api/sessions/:id` | Session detail (agent type, state, token usage) |
| `GET` | `/api/sessions/:id/stream` | SSE stream of raw model output (bounded in-memory queue) |
| `GET` | `/api/escalations` | List pending escalations |
| `GET` | `/api/escalations/:id` | Escalation detail |
| `GET` | `/api/audit` | Paginated audit chain (newest first) |
| `GET` | `/api/audit?initiative_id=X` | Filtered audit events |
| `GET` | `/api/inbox` | Operator inbox (pending actions) |
| `GET` | `/api/health` | Kernel health state (doctor summary) |
| `GET` | `/api/policy` | Current policy snapshot (read role) |
| `GET` | `/api/policy/toml` | Raw `policy.toml` content (write_policy role) |
| `PUT` | `/api/policy/toml` | Update `policy.toml` + trigger reload (write_policy role) |
| `GET` | `/api/git/worktrees` | List worktrees (main + per-executor/orchestrator) |
| `GET` | `/api/git/worktrees/:name` | Worktree detail (HEAD, branch, status) |
| `GET` | `/api/git/worktrees/:name/log` | Git log (last N commits) |
| `GET` | `/api/git/worktrees/:name/diff` | Diff between worktree HEAD and main |
| `GET` | `/api/git/worktrees/:name/diff/:sha1..:sha2` | Diff between two commits |
| `GET` | `/api/plan/:initiative_id` | Rendered plan TOML for an initiative |
| `GET` | `/api/vm-images` | Operator-published `[[vm_images]]` registry |

**Agent stream capture.** Raw model streaming output (the SSE
chunks the gateway relays from the model provider) is not stored
in `kernel.db` (it would be too large and too transient). Instead:

1. **Bounded file ring.** Each active session's raw model output
   is appended to `<data_dir>/streams/<session_id>.jsonl`. Each
   line is a timestamped SSE event. Max file size: 10 MB per
   session (configurable). On overflow, the oldest lines are
   truncated (ring buffer semantics via `seek + truncate`).
2. **In-memory tail.** The dashboard backend holds the last 500
   events per active session in a `tokio::sync::broadcast` channel.
   The `/api/sessions/:id/stream` SSE endpoint taps this channel
   for real-time streaming to the browser.
3. **Persistence across restart.** On kernel restart, the
   `.jsonl` files survive. The dashboard loads the last N lines
   from disk for sessions that were active at shutdown. The
   in-memory broadcast is refilled from the file tail.

### §4.4 — React frontend

**Stack:**

* React 18+ with TypeScript
* Vite for build tooling (fast dev server, small production bundle)
* React Router for client-side routing
* `@tanstack/react-query` for data fetching and caching
* Recharts for DAG visualization and time-series charts
* `react-diff-viewer-continued` for git diff rendering
* Monaco Editor for `policy.toml` editing (write_policy role only)
* Tailwind CSS for styling (operator tooling, not end-user product
  — clean utility-first is appropriate)

**Pages.**

| Route | Page | Description |
|---|---|---|
| `/login` | Login | Challenge-response auth flow |
| `/` | Home / Overview | Kernel health, active initiative count, recent activity feed, resource utilization |
| `/initiatives` | Initiative List | Sortable/filterable table of all initiatives with state badges, task progress bars, created/updated timestamps |
| `/initiatives/:id` | Initiative Detail | Full initiative view with embedded DAG, task list, escalation summary, timeline |
| `/initiatives/:id/dag` | DAG View | Interactive directed acyclic graph visualization. Nodes = tasks, colored by state (green=completed, blue=running, gray=pending, red=failed, yellow=blocked). Click a node → task detail panel slides in. |
| `/initiatives/:id/plan` | Plan View | Rendered `plan.toml` with syntax highlighting. Shows `[workspace]`, `[[tasks]]`, `[orchestrator]` sections. |
| `/tasks/:id` | Task Detail | State machine history, session list, reviewer verdicts with critique text, structured outputs timeline, path scope visualization |
| `/sessions/:id` | Session Detail | Agent type, model id, token usage chart (input/output over turns), tool call log, terminal outcome |
| `/sessions/:id/stream` | Agent Stream | Real-time raw model output. SSE-connected, auto-scrolling terminal-style view. Shows tool calls inline with syntax-highlighted JSON. Paused sessions show the persisted `.jsonl` tail. |
| `/escalations` | Escalations | Pending escalation list with initiative context, severity, requested action |
| `/inbox` | Operator Inbox | Unified view of pending actions: escalations to resolve, reviews to acknowledge, initiatives awaiting operator input |
| `/audit` | Audit Chain | Paginated, filterable audit event log. Each event expandable to show full payload. Filter by initiative, task, event kind, time range. |
| `/git` | Git Worktrees | List of worktrees: `main`, each executor's branch, orchestrator's integration branch. Select any to see log + diff. |
| `/git/:worktree` | Worktree Detail | Git log (commit list), file tree at HEAD, unified diff vs. main. Side-by-side diff view option. |
| `/git/:worktree/diff/:sha1..:sha2` | Diff View | Full diff between two commits. Syntax-highlighted, file-by-file, with expand/collapse. |
| `/policy` | Policy View | Read-only rendered `policy.toml` (read role). Monaco editor with save button (write_policy role). Diff against previous epoch on save. |
| `/health` | Health | `raxis doctor` output rendered as a checklist. Green/yellow/red per category. Auto-refreshes every 30 seconds. |
| `/vm-images` | VM Images | Operator-published `[[vm_images]]` registry. Per-entry: alias, digest, role restriction, Linux kernel floor, cache status. |

**UI design principles:**

1. **Dark mode default.** Operator tooling runs in terminals and
   dark IDEs. The dashboard matches that context. Light mode toggle
   available.
2. **Information density.** Operators need to see a lot of state
   at once. Dense tables, compact cards, collapsible sections.
   No wasted whitespace.
3. **Real-time indicators.** Pulsing dots on running sessions,
   live token counters, auto-updating DAG colors. SSE connections
   for agent streams and initiative events.
4. **Keyboard navigation.** `j/k` for list navigation, `Enter`
   to drill in, `Escape` to go back. Vim-style for operators who
   live in the terminal.
5. **Fast.** Static bundle served by axum. API responses are JSON
   with `Cache-Control: no-cache` for live data. React Query
   handles background refetch (5-second stale time for list
   endpoints, 1-second for detail endpoints with active sessions).
6. **Responsive but desktop-first.** Operators use this on
   widescreen monitors. The layout is optimized for ≥ 1440px but
   degrades gracefully to 1024px. Mobile is not a target.

### §4.5 — Read/write role enforcement

**Read role (default).** Every API endpoint except
`PUT /api/policy/toml` is read-only. The JWT carries the
operator's roles; the middleware checks `roles.contains("read")`
for all `GET` endpoints.

**Write policy role.** `PUT /api/policy/toml` requires
`roles.contains("write_policy")`. The handler:

1. Validates the new TOML parses into a valid `PolicyBundle`.
2. Writes the file to the policy path.
3. Triggers the kernel's policy reload mechanism (same as
   `raxis policy reload` CLI).
4. Returns the new policy epoch.
5. Emits a `PolicyUpdatedViaDashboard` audit event with the
   operator's id, the old epoch, and the new epoch.

**Admin role.** `GET /api/health` (doctor output) requires
`roles.contains("admin")`. Operator key listing and certificate
status are admin-only because they contain security-sensitive
metadata.

### §4.6 — Implementation plan

| Phase | Scope | Estimate |
|---|---|---|
| 1 | `raxis-dashboard` crate skeleton + axum server + static serving + auth endpoints | ~400 lines |
| 2 | Core API endpoints (initiatives, tasks, sessions, audit, escalations, inbox) | ~600 lines |
| 3 | Git worktree API (log, diff, file tree) | ~300 lines |
| 4 | Agent stream capture (bounded file ring + broadcast channel + SSE endpoint) | ~250 lines |
| 5 | Policy view/edit API | ~150 lines |
| 6 | React frontend: scaffold + routing + auth flow + overview page | ~800 lines |
| 7 | React frontend: initiative detail + DAG visualization + task detail | ~1000 lines |
| 8 | React frontend: session detail + agent stream view | ~600 lines |
| 9 | React frontend: git worktree + diff view + audit log | ~800 lines |
| 10 | React frontend: policy editor + health page + inbox | ~500 lines |
| **Total** | | **~5400 lines** |

### §4.7 — Invariant safety

The dashboard introduces a new network-facing surface (HTTP server).
The following invariants must be reviewed:

* **`R-1` (Domain separation).** The dashboard runs in the kernel
  process, not inside a VM. It has read-only access to the store.
  It cannot inject intents, spawn sessions, or mutate task state.
  The only write path is `PUT /api/policy/toml`, which goes
  through the same validation as the CLI's `raxis policy reload`.

* **`R-2` (Mediated I/O).** The dashboard's HTTP listener is
  bound to a configurable address (default `127.0.0.1` — loopback
  only). Exposing it to a network requires explicit operator
  configuration in `policy.toml`.

* **`R-10` (Opaque rejection).** API errors must not leak internal
  kernel state. Error responses use the same `FAIL_*` code
  vocabulary as the operator UDS, with no stack traces or internal
  paths in production mode.

* **`INV-CERT-01` (certificate mandatory).** The JWT is derived
  from a certificate-verified operator key. Expired / revoked
  certificates cannot obtain a JWT. The JWT itself has a 1-hour
  TTL and is revocable via logout.

* **`INV-OPERATOR-ERG-01` (read-only handlers).** Every `GET`
  handler is a pure read from the store or in-memory state. The
  `PUT /api/policy/toml` handler is the only write, and it
  delegates to the kernel's existing policy reload path which is
  already audited.

---

## §5 — Priority Summary

| Priority | §  | Item | Est. lines |
|---|---|---|---|
| 🟢 DONE | §1.1 | Plan `description` REQUIRED + `RAXIS_PLANNER_TASK_PROMPT` unconditional stamp | ~50 |
| 🟢 DONE | §1.2 | Integration merge Phase 2 (host-side fast-forward) inline + `MergeFastForwardFailed` audit | ~140 |
| 🟢 DONE | §2.4 | In-VM KSB renderer (`raxis-ksb` + kernel assembly + driver fold) | ~300 |
| 🟡 P1 | §2.1 | `SubscribeInitiative` | ~80 |
| 🟡 P1 | §3.2 | `StructuredOutput` (fixed enum) | ~310 |
| 🟡 P1 | §2.5 | Token-limit enforcement | ~210 |
| 🟡 P2 | §3.1 | `Sleep` tool | ~90 |
| 🟡 P2 | §2.6 | Sidecar streaming + heartbeat | ~180 |
| 🟡 P2 | §2.2 | MongoDB SCRAM-SHA-256 | ~400 |
| 🟡 P2 | §2.3 | MySQL `caching_sha2_password` | ~140 |
| 🔵 P2 | §4   | Operator dashboard (full stack) | ~5400 |
| | | **Total** | **~7260** |

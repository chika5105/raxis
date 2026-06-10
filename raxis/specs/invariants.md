# RAXIS — Core Invariants

This file consolidates the **load-bearing** invariants of the RAXIS
kernel: the structural rules whose violation breaks the system's
correctness guarantees (authority, auditability, isolation,
reproducibility). Each entry uses the same shape:

1. **Statement** — the thing that must be true.
2. **Justification** — why we hold it; what breaks without it.
3. **Scenario** — a concrete adversarial or operational example.
4. **Canonical home** — the spec file that owns the normative wording;
   when the canonical home disagrees with this file, the canonical
   home wins.

Operational details, UI feature requirements, build-tool constraints,
and CI-style coverage assertions are documented in their canonical
homes, not here. This file is the kernel's structural promise to the
operator; everything in it is enforced in production code and
exercised by the test suite.

---

## §1 — Top-level invariants

These are the structural promises that distinguish RAXIS from an
LLM-with-a-shell. If any one of these fails, the paradigm fails.

### INV-01 — Planner actions are bound to a kernel session

**Statement.** The planner cannot perform any authorised action without
a valid kernel-issued session binding. For session-bound VM streams,
the guest sends no bearer material; the host dispatcher resolves the
session row and stamps the canonical session token onto legacy handler
requests before admission. Unbound/manual planner-socket requests must
still carry a valid token. In both cases the kernel rejects at
session-lookup if the session is missing, expired, or revoked.

**Justification.** Without this, authority is convention rather than
enforcement: any process that knows the IPC wire format could pose
as the planner. Pinning every IPC call to a `sessions` row gives
the kernel a single point at which to revoke planner authority and
a single object that captures `(role, worktree_root, delegations,
expiry)`.

**Scenario.** A second planner-shaped process connects to the kernel
and submits `IntentRequest`. On an unbound socket, no session token is
rejected at the dispatcher. On a VM-bound stream, the host binding
selects exactly one session row; revoked and expired sessions are
rejected at session-lookup. No authority leaks past these checks, and
the guest never needs to hold bearer material.

**Canonical home.** [`v1/philosophy.md`](v1/philosophy.md) §1.2.

---

### INV-02A — All inference goes planner → kernel → gateway, kernel-priced

**Statement.** The planner binary has no provider credential store
access and no IPC message type that routes to a provider inference
endpoint; the only inference path is `InferenceRequest → kernel →
gateway`. Admission cost is kernel-computed from VCS-derived inputs
and policy — no planner-supplied field reaches `reserve_budget_in_tx`.

**Justification.** Two failure modes are blocked by one invariant:
(a) a planner with provider credentials could call the model
directly and bypass the budget entirely; (b) a planner allowed to
declare its own admission cost could declare zero and bypass budget
enforcement on the kernel-routed path.

**Scenario.** A compromised planner attempts to route an inference
call directly to OpenAI to bypass the lane budget. It has no
credentials, no DNS exit, and no IPC discriminant for "raw provider
call" — structurally impossible to express. Even on the kernel
path, the `estimated_cost` it supplies is discarded by
`compute_admission_cost`.

**Canonical home.** [`v1/philosophy.md`](v1/philosophy.md) §1.2;
[`v1/kernel-core.md`](v1/kernel-core.md) §3 (`budget`).

---

### INV-02B — Planner has no direct network egress

**Statement.** The planner has no direct network egress; all external
data fetches go through `FetchRequest → kernel → gateway`. The
kernel logs `{fetch_request_id, url, fetched_at, response_sha256,
content_type, byte_len}` before content is returned.

**Justification.** Without this, INV-05 (reproducibility) breaks —
unlogged external inputs make the audit chain insufficient to
reconstruct kernel decisions. It also closes the prompt-injection
observability gap: every external byte the planner has seen is
named, hashed, and timestamped.

**Scenario.** A planner attempts to `curl` an attacker-controlled
config endpoint. The sandbox firewall rejects the egress; the only
allowed wire path is the IPC socket; every fetch is logged with
URL, hash, and byte length.

**Canonical home.** [`v1/philosophy.md`](v1/philosophy.md) §1.2;
[`v1/peripherals.md`](v1/peripherals.md) §3.

---

### INV-03 — Witness-to-commit binding

**Statement.** A witness bound to commit SHA `A` cannot satisfy a gate
check for commit SHA `B`. Every witness row in `witness_records`
carries the `head_sha` it was produced under.

**Justification.** Without this, stale or fabricated witnesses pass
gates: a verifier's "tests passed" claim from yesterday could let
today's regression through the same gate. Binding witnesses to a
specific commit SHA makes "this gate is satisfied" a statement
about a specific source state, not history.

**Scenario.** Planner submits `CompleteTask` with `head_sha = B`.
`evaluate_claims` looks up `witness_records` for `(task_id,
head_sha = B)`; the prior witness for `head_sha = A` does not
appear. The kernel re-spawns the verifier under `B`, the
regression fails, and the gate rejects.

**Canonical home.** [`v1/philosophy.md`](v1/philosophy.md) §1.2;
[`v1/kernel-store.md`](v1/kernel-store.md) §2.5.6 (`witness_records`).

---

### INV-04 — Audit log tamper-evidence

**Statement.** Any modification to the audit log (delete, update,
truncate) is detectable by hash chain verification. Every record
carries `seq`, `prev_sha256`, and a content hash forming an
append-only chain.

**Justification.** Without this the audit log is a convenience, not a
record. The chain must be unforgeable: if an entry can be silently
edited, the kernel's "all decisions are reproducible from stored
records" claim collapses.

**Scenario.** An attacker truncates `segment-007.jsonl` to remove an
`OperatorCertInstalled` event for a compromised key.
`verify_chain_full` re-walks the chain and detects the
discontinuity at the segment boundary. The kernel refuses to
advance the epoch when the chain is invalid.

**Canonical home.** [`v1/philosophy.md`](v1/philosophy.md) §1.2;
[`v1/kernel-store.md`](v1/kernel-store.md) §2.5.2 (audit log).

---

### INV-05 — Decisions are reproducible from stored records

**Statement.** Given the audit log and kernel state at any point,
kernel decisions are reproducible from durable records alone — no
reliance on in-memory state that may be lost on crash.

**Justification.** Without this, recovery is guesswork. The kernel
must be able to answer "why did this task transition to `Failed` at
timestamp T?" from disk alone. This is what makes
`recovery::reconcile` deterministic.

**Scenario.** The kernel crashes mid-execution. On restart,
`recovery::reconcile` sweeps non-terminal tasks to
`BlockedRecoveryPending` based on stored state alone; no in-memory
queue is consulted. An investigator can replay every decision
from the audit log six months later.

**Canonical home.** [`v1/philosophy.md`](v1/philosophy.md) §1.2;
[`v1/kernel-core.md`](v1/kernel-core.md) §recovery.

---

### INV-06 — Approval gates require a valid scoped token

**Statement.** An action requiring approval does not execute without a
valid, scoped, unexpired approval token whose `ApprovalProof` is
written to the kernel state store.

**Justification.** Without this, escalation is a delay mechanism
rather than a gate: the planner could claim "approved" and proceed.
The kernel must independently verify each token and persist the
resulting `ApprovalProof` so the audit chain records exactly which
token authorised which action.

**Scenario.** The planner crafts a fake `ApprovalToken`.
`validate_approval_token` performs token-hash lookup, policy-epoch
match, expiry, consumed-bit, nonce-replay, scope, and validity
checks and rejects the forgery at step 1 (`NotFound`). Even a
real-but-replayed token is rejected at the nonce-replay step.

**Canonical home.** [`v1/philosophy.md`](v1/philosophy.md) §1.2;
[`v1/kernel-core.md`](v1/kernel-core.md) §4 (escalation FSM); see also
INV-ESC-01..05.

---

### INV-07 — Required claims are kernel-derived from VCS state

**Statement.** A planner-submitted path manifest cannot influence
which claim types are required. The kernel derives required claims
from VCS state via `policy_lookup::required_claims` independently
of the planner's declared `touched_paths`.

**Justification.** Without this, the planner controls its own quality
obligations: a planner that declares "no test files touched" gets
to skip the test-pass gate. Kernel-derived path information ensures
the gate set is a function of what was *actually* committed, not
what was *claimed*.

**Scenario.** Planner submits an intent claiming `touched_paths = []`.
`required_claims` ignores the manifest and computes the path set
from `vcs::diff(base_sha, head_sha)`; the resulting required claims
include the test-pass gate.

**Canonical home.** [`v1/philosophy.md`](v1/philosophy.md) §1.2;
[`v1/kernel-core.md`](v1/kernel-core.md) §gates.

---

### INV-08 — Rejection codes do not leak policy structure

**Statement.** Rejection reason codes exposed to the planner do not
reveal which specific policy rule fired. The full diagnostic lives
in the audit chain (operator-visible) and the planner-feedback
table (operator-mediated).

**Justification.** Without this, the gate system can be reverse-
engineered by probing: a planner observing "rejected because rule
R7 fired" learns the policy structure rule by rule. Opaque
rejection codes keep the policy hidden behind a binary gate.

**Scenario.** An attacker probes the kernel with malformed intents
to map the policy. They observe `FAIL_POLICY_VIOLATION` for many
distinct underlying causes and cannot tell which rule fired.

**Canonical home.** [`v1/philosophy.md`](v1/philosophy.md) §1.2;
[`v1/peripherals.md`](v1/peripherals.md) §3.1.

---

## §2 — Initiative & task FSM

Canonical home: [`v1/kernel-core.md`](v1/kernel-core.md) §4.8.

### INV-INIT-01 — Planner cannot create or amend tasks

**Statement.** The planner cannot create or amend tasks. Tasks are
instantiated from the signed plan artifact at `approve_plan` time.
No planner IPC message results in a new task row. This applies to
direct plan tasks and to the kernel-synthesised IntegrationMerge
coordinator task.

**Justification.** The signed plan is the authoritative declaration of
what work was approved. If the planner could insert tasks
post-approval, the operator's signature on the plan no longer
covers the actual workload — the planner could expand its scope
indefinitely.

**Scenario.** A planner submits `IntentKind::CompleteTask { task_id:
T_new }` for a `task_id` that does not exist in any signed plan.
The intent handler rejects with `FAIL_UNKNOWN_TASK`.

---

### INV-INIT-02 — Planner-driven transitions are bounded to terminal task states

**Statement.** The planner cannot transition a task to any state other
than `Completed` or `Failed`. All other transitions are kernel- or
operator-initiated. `transition_task` enforces this via the
`TransitionActor` check.

**Justification.** Limiting planner-initiated transitions to the two
terminal states reduces the FSM surface the planner can manipulate.
The planner can declare "I'm done" or "I gave up," but cannot
move a task to `Blocked`, `Aborted`, `BlockedRecoveryPending`, or
any intermediate non-terminal state.

**Scenario.** A misbehaving planner attempts to move its task back to
`Admitted`. `transition_task` checks the actor against the
requested transition and rejects.

---

### INV-INIT-03 — Successors blocked until predecessor gates close

**Statement.** A successor task cannot become schedulable (returned by
`next_ready_tasks`) until all its predecessors are `Completed`. When
a completed Executor predecessor has Reviewer successors, non-Reviewer
downstream tasks remain blocked until those Reviewers have aggregated to
`AllReviewersPassed`. Reviewer successors are the gate-closing tasks, so
they may start as soon as the Executor predecessor is mechanically
complete. `release_successors` is the only mechanism that marks a
successor's predecessors as satisfied in the DAG edge table.

**Justification.** The DAG edges in the signed plan encode work
dependencies approved by the operator. If a successor could run
before its predecessors complete, the kernel would be executing
work in an order the operator did not approve — a structural
violation of the plan signature.

**Scenario.** Plan declares `review depends on implement` and
`publish depends on implement`. Task `implement` reaches `Completed`.
The reviewer can start, but `publish` remains unschedulable until
the review aggregate passes. The gate prevents publish from starting
and later needing cleanup.

**Reviewer predecessor rule.** A plan MUST NOT declare a Reviewer task
as a direct predecessor of any task. Reviewers emit verdicts, not
workspace artifacts or `evaluation_sha` values. Downstream work that
must wait for review depends on the reviewed Executor task; the kernel
then applies the Reviewer gate before admitting the downstream task.

---

### INV-INIT-04 — `evaluate_terminal_criteria` is synchronous after every transition

**Statement.** `evaluate_terminal_criteria` is called after **every**
`transition_task` write — terminal and non-terminal — inside the
same transaction. It is never called proactively or on a timer.
`transition_task` is the single authoritative call-site.

**Justification.** Initiative state (`Executing`, `Blocked`,
`Completed`, `Failed`) must always be consistent with the task
state snapshot after each state change. A timer-based evaluator
would introduce a window in which the initiative state and task
states disagree.

**Scenario.** The last running task transitions `Running → Completed`
under `AllTasksSucceeded`. `evaluate_terminal_criteria` runs
synchronously inside the same transaction and transitions the
initiative to `Completed`. The operator's next `raxis status`
call sees both states consistent.

**Corollary — generic crash recovery.** Outside the supervisor-aware
auto-resume codepath, a `BlockedRecoveryPending` task is exited
only by operator action (`task resume → Admitted`, `task abort →
Aborted`). The supervisor-aware exception lives entirely in
`recovery::reconcile_after_supervisor_restart` and is documented in
[`v2/supervisor-restart-classification.md`](v2/supervisor-restart-classification.md).

---

## §3 — Escalation

Canonical home: [`v1/kernel-core.md`](v1/kernel-core.md) §4 (escalation FSM).

### INV-ESC-01 — No self-approval

**Statement.** The operator who *requested* an escalation cannot
*approve* it. The kernel records `requesting_operator_fingerprint`
on the escalation row at creation; any `Approve` action whose
operator fingerprint matches is rejected with
`FAIL_SELF_APPROVAL_FORBIDDEN`.

**Justification.** Self-approval collapses the escalation gate to a
no-op — the planner could request an escalation, then the same
operator hits "approve" out of habit. Two-person integrity is a
structural property, not an honour system.

**Scenario.** Operator Alice requests an escalation for `DangerousIntent`.
Alice clicks "approve" five minutes later. The kernel reads the
escalation row, sees `requesting_operator = Alice's fingerprint`,
matches the approver's fingerprint, and rejects.

---

### INV-ESC-02 — Approval tokens are scoped to a policy epoch

**Statement.** Every `ApprovalToken` carries the `policy_epoch` it was
minted under. A token whose `policy_epoch` does not match the
current epoch is rejected.

**Justification.** Policy changes are how operators say "the rules
have changed." Letting tokens minted under the old rules satisfy
gates evaluated under the new rules silently retains pre-change
authority.

**Scenario.** Operator advances policy from epoch 5 to epoch 6,
tightening the path-allowlist. A planner presents a token minted
at epoch 5. `validate_approval_token` rejects with
`FAIL_TOKEN_EPOCH_MISMATCH`.

---

### INV-ESC-03 — Approval tokens are session-bound

**Statement.** An `ApprovalToken` is bound to the session that
requested the escalation. Presenting a token from a different
session is rejected with `FAIL_TOKEN_SESSION_MISMATCH`.

**Justification.** Tokens are not bearer credentials. Binding to the
requesting session prevents a compromised second session from
re-using a token approved for another session's specific intent.

**Scenario.** Session `S_a` requests an escalation; operator approves;
session `S_b` (compromised) intercepts the token and presents it.
The kernel reads the token's `session_id`, compares against the
presenting session, and rejects.

---

### INV-ESC-04 — Approval tokens are single-use (nonce-checked)

**Statement.** Every `ApprovalToken` carries a CSPRNG nonce. The
kernel records `consumed_at` in `approval_tokens` on first use.
A second presentation is rejected with `FAIL_TOKEN_REPLAY`.

**Justification.** Without nonce checking, an attacker who recovers a
token from disk or memory can replay it indefinitely. Single-use
makes "this token authorised this action" a one-shot fact, not a
recurring permission.

**Scenario.** Planner uses an approval token for `CompleteTask`. The
token is committed with `consumed_at = now`. Attacker recovers
the token bytes and replays for a second `CompleteTask`. The
kernel checks `consumed_at IS NOT NULL` and rejects.

---

### INV-ESC-05 — Action must fall within token scope

**Statement.** An `ApprovalToken` carries a `scope` field naming the
specific action(s) it authorises. Using a token for an action
outside its scope is rejected with `FAIL_TOKEN_SCOPE_MISMATCH`.

**Justification.** Without scoping, a token approved for one
sensitive action authorises any subsequent action. Scoping
collapses the blast radius of any compromised token to exactly
the operator-approved action.

**Scenario.** Operator approves a token scoped to "delete file
`/secrets/test-key.pem`". Planner attempts to use the same token
for "delete file `/secrets/prod-key.pem`". The kernel matches the
intent payload against the token scope and rejects.

---

## §4 — Kernel store

Canonical home: [`v1/kernel-store.md`](v1/kernel-store.md) §2.5.

### INV-STORE-01 — Single-acquire single-transaction discipline

**Statement.** Every kernel operation that issues `BEGIN`/`COMMIT` on
the connection must hold the `tokio::sync::Mutex` continuously from
`BEGIN` through `COMMIT` (or `ROLLBACK`). Releasing the mutex
mid-transaction is forbidden.

**Justification.** SQLite serialises writes across connections via
its WAL; the tokio mutex serialises tokio tasks across the **same**
connection. Releasing the mutex mid-transaction would let another
tokio task observe the partially-completed transaction state.

**Scenario.** A handler calls `transition_task` then
`evaluate_terminal_criteria`. Both writes happen under one
`Connection::transaction()` borrow held under one mutex
acquisition; another tokio task waiting on the mutex sees the
fully-committed snapshot, never the in-between state.

---

### INV-STORE-02 — Multi-table atomicity

**Statement.** Operations that mutate more than one table to maintain
a cross-table consistency relationship MUST execute every write in
a single SQL transaction held under one INV-STORE-01 mutex
acquisition.

**Justification.** A partial-write outcome would leave the store in
an inconsistent state — e.g. a budget reservation without a
matching task transition, or a `Draft` initiative with no
`signed_plan_artifacts` row that subsequent `approve_plan` calls
will fail to read. These are unrecoverable: the kernel has no way
to "undo" a half-applied multi-table change at startup.

**Scenario.** Intent admission writes to `tasks`,
`task_intent_ranges`, and `lane_budget_reservations` in one
transaction. If the transaction fails mid-way (operator concurrently
aborted, disk full, constraint violation), nothing is committed and
the lane is not stranded with a phantom reservation.

**Concurrency-bug catalogue.** Patterns A–D (split mutex acquisition,
multi-call composition outside tx, read-then-write across two tx,
multi-table writes with no explicit tx) are documented step-by-step
in [`v1/kernel-store.md`](v1/kernel-store.md) §2.5.1.1.

---

### INV-KERNEL-STORE-LOCK-SYNC-NEVER-FROM-ASYNC-01 — `lock_sync` is never reached from an async runtime thread

**Statement.** `Store::lock_sync` (the blocking variant of the
connection mutex) MUST be reached only from a `spawn_blocking`
worker, an OS thread, or a `#[test]` runtime. Calling it directly
from a `#[tokio::main]` or `#[tokio::test(flavor = "multi_thread")]`
context panics in debug builds and recovers via `block_in_place`
in release.

**Justification.** `lock_sync` ultimately calls
`tokio::runtime::Handle::block_on` to acquire the async-aware
mutex. Calling `block_on` from inside the runtime that owns the
caller's thread deadlocks the runtime. The `#[track_caller]` panic
in debug builds catches the violation at code-review time.

**Scenario.** A new handler in `handlers/intent.rs` calls
`ctx.store.lock_sync()` directly inside `async fn handle`. Under
`cargo test` the assertion fires with a `track_caller` panic
naming the file:line. The fix is to wrap the SQL operation in
`tokio::task::spawn_blocking`.

**Canonical home.** [`v1/kernel-store.md`](v1/kernel-store.md) §2.5.1.2.

---

## §5 — Policy epochs

Canonical home: [`v1/kernel-store.md`](v1/kernel-store.md) §2.5.1;
[`v1/kernel-core.md`](v1/kernel-core.md) §`policy_manager.rs`.

### INV-POLICY-01 — Epoch advance atomicity

**Statement.** `policy_manager::advance_epoch` Phase 1 (the SQL-write
phase) writes to `delegations`, `sessions`, `policy_epoch_history`,
and the audit-pointer table inside one transaction held under one
INV-STORE-01 mutex acquisition. Phase 2 (in-memory `ArcSwap` swaps
for `ctx.policy` and `ctx.allowlist_cache`) runs only after Phase 1
commits, and is infallible. Phase 3 (gateway `EpochAdvanced` signal)
is best-effort and does not affect the success of the advance.

**Justification.** A partially-applied epoch advance would leave some
kernel components running under the new policy and others under the
old — operators would see contradictory enforcement depending on
which subsystem they hit first.

**Scenario.** Mid-`advance_epoch`, the disk fills up. Phase 1's
transaction rolls back; Phase 2 never runs; the in-memory `ArcSwap`
still points at the old policy; the gateway never receives
`EpochAdvanced`. The kernel logs `PolicyAdvanceFailed` and
continues serving under the old epoch.

---

## §6 — Scheduler

Canonical home: [`v1/kernel-store.md`](v1/kernel-store.md) §2.5.7.

### INV-SCHED-01 — `scheduler::admit` runs only at plan approval

**Statement.** `scheduler::admit` is called exclusively from
`initiatives::lifecycle::approve_plan`. The intent handler
(`handlers/intent.rs`) never calls `admit`.

**Justification.** Tasks are sealed at approval (INV-INIT-01); calling
`admit` from the intent handler would re-introduce the planner's
ability to influence the task set post-approval.

**Scenario.** A future PR adds an `IntentKind` variant that needs to
insert a new task. The reviewer notices the new call to `admit`
from `handlers/intent.rs`, flags the violation, and the PR is
rejected before merge.

---

### INV-SCHED-02 — `release_budget` is called on every terminal-state transition

**Statement.** Every code path that transitions a task into a terminal
state (`Completed` / `Failed` / `Aborted` / `Cancelled`) MUST call
`scheduler::budget::release_budget_in_tx` inside the same
`Connection::transaction()` borrow that performs the FSM flip. The
exhaustive list:

* `handlers/intent::commit_task_completion`
* `handlers/intent::handle_report_failure`
* `initiatives::lifecycle::abort_task`
* `initiatives::lifecycle::abort_initiative`

**Justification.** Lane bookkeeping caps the total `estimated_cost`
reserved across all live tasks on a lane. Without a paired release,
the cap is charged monotonically; after enough completions the
IntegrationMerge synthetic task cannot reserve its merge-cost slice
and every IntegrationMerge intent is rejected with
`FAIL_BUDGET_EXCEEDED`. Pairing within the same transaction
preserves INV-STORE-02: a crash leaves either both writes durable
or both rolled back.

**Scenario.** Pre-fix iter 38: 8 sub-tasks completed
(8 × `TaskCompleted`, 0 × `release_budget`); IntegrationMerge was
admitted, `reserve_budget_in_tx` returned `BudgetExceeded`; the
orchestrator died without respawning. Post-fix every completion
decrements the lane charge and the merge admits cleanly.

---

## §7 — VCS path enforcement

Canonical home: [`v1/kernel-core.md`](v1/kernel-core.md) §gates;
[`v1/peripherals.md`](v1/peripherals.md) §3.

### INV-TASK-PATH-01 — Intent admission requires path coverage

**Statement.** Every write-intent (`SingleCommit`, `IntegrationMerge`,
`SubmitArtifact`, etc.) MUST declare a non-empty `touched_paths`
manifest. The kernel computes the VCS-derived effective path set
and admits the intent only if every committed path falls under at
least one entry in the plan task's `path_allowlist`.

**Justification.** The `path_allowlist` is the operator's declaration
of which files this task is allowed to touch. Without admission-time
coverage, a planner can edit `/etc/passwd` inside its worktree and
slip the diff past gate evaluation.

**Scenario.** Plan declares `path_allowlist = ["src/**"]`. Planner
commits both `src/foo.rs` and `etc/passwd`. The kernel's path
check rejects the intent with `FAIL_PATH_POLICY_VIOLATION` before
any commit-side work happens.

---

### INV-TASK-PATH-02 — Task completion requires full path closure

**Statement.** `CompleteTask` admission requires that every committed
path on the executor branch falls under the task's `path_allowlist`,
*including* paths the planner did not declare in earlier
`SingleCommit` intents.

**Justification.** Without this, a planner could declare a small
`touched_paths` manifest at admission, slip through the per-intent
gate, then commit additional files in the same task and complete.
The completion-time re-check closes the loop.

**Scenario.** Task allowlist is `["src/**"]`. Planner admits a
`SingleCommit { touched_paths: ["src/foo.rs"] }` then quietly adds
`Cargo.toml` to the next commit and calls `CompleteTask`. The
completion-time re-scan against the executor branch surfaces
`Cargo.toml`, the path check fails, and the task is held in
`Running` pending operator action.

---

## §8 — Operator certificates

Canonical home: [`v1/kernel-core.md`](v1/kernel-core.md) §operator-cert;
[`v1/cli-ceremony.md`](v1/cli-ceremony.md).

### INV-CERT-01 — Cert is mandatory for every operator entry

**Statement.** Every `[[operators]]` entry in `policy.toml` MUST carry
a certificate file (`operator_<fp>.cert.toml`) on disk. The kernel
refuses to boot if any operator listed in policy is missing its
cert.

**Justification.** The cert is the operator's signed self-declaration
of `(pubkey, display_name, permitted_ops, expires_at)`. Without
it the policy's operator entry is just a public key — the kernel
has no record of what operations that operator is allowed to
authorise.

**Scenario.** An operator hand-edits `policy.toml` to add an entry
without dropping the matching cert file. On kernel restart the
boot sequence fails with `BOOT_ERR_OPERATOR_CERT_MISSING`.

---

### INV-CERT-02 — Self-signature is unbypassable

**Statement.** Every operator cert MUST carry a valid Ed25519 signature
over its own contents, signed by the same pubkey the cert
declares. Loading a cert with an invalid self-signature fails
closed at boot.

**Justification.** The self-signature is what binds the cert's claims
(`display_name`, `permitted_ops`, `expires_at`) to the pubkey.
Without it, an attacker with filesystem write access could
replace the `permitted_ops` list to grant themselves new
operations.

**Scenario.** Attacker rewrites `operator_<fp>.cert.toml` to add
`RotateEpoch` to `permitted_ops`. On reload, the cert's
self-signature no longer matches the modified bytes; the kernel
rejects with `BOOT_ERR_OPERATOR_CERT_INVALID_SIGNATURE`.

---

### INV-CERT-03 — Operator private key is never persisted

**Statement.** The operator's Ed25519 private key MUST NEVER touch
disk in any file the kernel reads or writes. The operator-side
CLI generates the key in-memory, signs the cert, signs intent
payloads, and discards the key on process exit.

**Justification.** A private key on disk is a stolen private key.
Every threat model that includes filesystem access to the
operator host must assume the key is compromised. Generating
fresh per-session keys (or holding a long-lived key in hardware)
is the only structurally-safe approach.

**Scenario.** An attacker exfiltrates the operator host's filesystem.
There is no `operator_<fp>.priv.toml` to recover; the cert
public-key alone cannot sign anything; the attacker cannot
authorise any operation against the kernel.

---

### INV-CERT-04 — Cert rotation pubkey continuity

**Statement.** When an operator rotates their cert (`OperatorCertRotated`
audit event), the new cert MUST carry the same `pubkey` as the old.
Pubkey changes require a separate `OperatorCertInstalled` event
authorised by another operator at a higher trust tier.

**Justification.** Rotation is for extending `expires_at` or narrowing
`permitted_ops` — it preserves the identity. Allowing rotation to
change the pubkey would let a compromised operator quietly swap
their identity to an attacker key under cover of a routine
rotation.

**Scenario.** Operator Alice's cert nears expiry. She runs
`raxis-cli cert rotate` which mints a new cert with the same
pubkey, longer `expires_at`, and the existing `permitted_ops`.
The kernel accepts the rotation. Operator Bob (separately
authenticated) cannot quietly substitute his pubkey through
the same channel.

---

## §9 — Planner harness

Canonical home: [`v2/planner-harness.md`](v2/planner-harness.md).

### INV-PLANNER-HARNESS-01 — Reviewer code execution prohibition

**Statement.** A Reviewer-role planner session MUST NOT have access to
any code-execution primitive: no shell, no language runtime, no
compiler, no LSP server, no package manager, no git binary, no
network utility. Enforcement is three-layered:
(a) Reviewer image content (the kernel-bundled `raxis-reviewer-core`
contains none of these binaries); (b) harness build (the Reviewer
build target of `raxis-planner` excludes the `bash` claw-code
module at link time); (c) kernel dispatch matrix (intents that
would route to shell-execution paths are rejected when the
session role is `Reviewer`).

**Plan-side corollary.** Any plan field whose semantics presuppose a
capability the Reviewer lacks (`vm_image`, custom tools,
`path_allowlist`) is rejected at admission with the corresponding
`FAIL_REVIEWER_*_NOT_ALLOWED` code.

**Justification.** A Reviewer that can execute code can be
deterministically compromised by the code it is reviewing — a
malicious `build.rs` or LSP extension can poison symbol-resolution
responses so the Reviewer LLM approves genuinely malicious changes.
The defense is structural: remove the tools entirely.

**Scenario.** A malicious Executor commits a Cargo crate with a
`build.rs` that exfiltrates its arguments. Under V1 a Reviewer
with LSP access would invoke `rust-analyzer` and execute
`build.rs`. Under V2 the Reviewer's image lacks `rust-analyzer`
and lacks `cargo`; the malicious code never runs in the
Reviewer's VM. Code-running verification is delegated to verifier
VMs.

---

### INV-PLANNER-HARNESS-05 — Canonical Orchestrator image

**Statement.** The Orchestrator's VM image is the kernel-bundled
`raxis-orchestrator-core` image, shipped at
`$RAXIS_INSTALL_DIR/images/raxis-orchestrator-core-<kernel_version>.img`
with a kernel-binary-pinned SHA-256. Operators cannot specify the
image in `plan.toml`; any `vm_image` (or equivalent) field on an
Orchestrator task is rejected at `approve_plan` with
`FAIL_ORCHESTRATOR_VM_IMAGE_NOT_ALLOWED`. The Orchestrator binary
has no shell, no LSP, and no operator-customisable tool surface.

**Justification.** The Orchestrator drives the plan's DAG: every
sub-task activation, every retry decision, every IntegrationMerge
gate is routed through it. Letting operators substitute a
custom image opens the door to a tampered Orchestrator that
selectively skips activations, mis-reports retries, or fakes
verifier witnesses. Kernel-bundled + digest-verified keeps the
Orchestrator's trust base as small as the Reviewer's
(INV-PLANNER-HARNESS-01).

**Scenario.** An attacker with filesystem write replaces
`raxis-orchestrator-core-<v>.img` with a tampered build. On
the next Orchestrator activation, the kernel re-computes the
digest, compares against the kernel-binary's compiled-in value,
finds the mismatch, and aborts with
`FAIL_ORCHESTRATOR_IMAGE_DIGEST_MISMATCH` +
`SecurityViolationDetected`.

---

## §10 — Kernel DAG authority

Canonical home: [`v2/kernel-mechanics-prompt.md`](v2/kernel-mechanics-prompt.md).

### INV-KERNEL-DAG-AUTHORITY-01 — Kernel gates `ActivateSubTask` on predecessor gate closure

**Statement.** `handle_activate_sub_task` rejects an activation with
`FAIL_PREDECESSORS_NOT_COMPLETE` whenever any predecessor task on
the DAG is not in `Completed`, or whenever a non-Reviewer successor
would run past a completed Executor predecessor whose Reviewer gate has
not aggregated to `AllReviewersPassed`. The check is mechanical: the
kernel walks the `task_dag_edges` rows for the target sub-task and
queries each predecessor's state and reviewer verdict under the same
transaction.

**Justification.** The Orchestrator's prompt rules guide it toward
respecting the DAG, but prompts are advice, not enforcement. The
kernel must mechanically refuse out-of-order activations so a
malformed Orchestrator (jailbroken, compromised, hallucinating)
cannot reorder dependent tasks.

**Scenario.** Plan declares `B depends on A`. Orchestrator (under
prompt-injection or a model regression) calls
`activate_subtask(B)` while A is still `Running`. The kernel
rejects; the rejection is recorded in the audit chain;
review-aggregate cannot satisfy the upstream gate; the
initiative halts pending operator action rather than executing
out-of-order work.

**Reviewer-gate scenario.** Plan declares `review-A depends on A`
and `B depends on A`. Once A completes, `review-A` may start because it
is the gate. `B` remains blocked with `AwaitingReviewerVerdicts` until
`review-A` submits an approved verdict. RAXIS must prevent `B` from
starting early rather than starting it and revoking/retrying it after
the reviewer result arrives.

If a plan instead declares `B depends on review-A`, plan approval must
fail. `review-A` has no `evaluation_sha` to materialize into B's
executor worktree; the dependency edge belongs on A, with review-A
enforced as A's approval gate.

### INV-KERNEL-DAG-AUTHORITY-02 — Review-rejection retry supersedes prior integration candidates

**Statement.** When a Reviewer rejects an Executor output and the
Orchestrator admits `RetrySubTask`, the rejected Executor
`evaluation_sha` is superseded for final integration. The kernel clears
the task's per-attempt VCS state, deletes the stale per-task transfer
ref, and resets the per-initiative Orchestrator integration worktree to
the initiative anchor before the retry is driven forward. Root closeout
and `IntegrationMerge` consume only the current terminal approved
Executor head for each task lineage.

**Justification.** The Orchestrator worktree is mutable integration
scratch. A prior Orchestrator turn may have merged an Executor commit
before the Reviewer panel closed; if the Reviewer rejects that output
and the retry writes overlapping files, keeping both commits in the
integration workspace can strand Git in an add/add conflict and make the
root Orchestrator respawn indefinitely. Reviewer rejection means the
candidate is no longer authority-valid input for final merge.

**Scenario.** Executor `A` commits files `x` and `y`. Reviewer `R`
rejects because `y` is missing required content. The Orchestrator retries
`A`; the second attempt commits corrected `x` and `y` and passes review.
RAXIS must integrate only the approved retry head. It must not merge the
rejected round-1 head and the approved round-2 head together, and if an
unexpected Git conflict still occurs it must surface an integration
conflict instead of cycling root Orchestrator sessions.

---

## §11 — Verifier processes

Canonical home: [`v2/verifier-processes.md`](v2/verifier-processes.md).

### INV-VERIFIER-01 — Witness-only output channel

**Statement.** A verifier VM has exactly one output surface: a
single signed `VerifierWitness` (verdict + structured payload)
written into `witness_records` by the kernel at verifier exit.
Verifiers have no IPC channel, no stdout/stderr that influences
kernel decisions, and no filesystem write that survives VM
shutdown. The verdict is the only consequence.

**Justification.** A verifier with side-channels (e.g. ability to
emit logs that the kernel scans) re-opens the same trust surface
as planner code. The witness-only contract means the only thing
the kernel ever does with verifier output is read the signed
verdict and record it; the verifier's reasoning is opaque to
kernel decision-making.

**Scenario.** A malicious verifier image attempts to influence the
kernel by writing to a known-path inside its VM. The kernel
reaps the VM, ignores its filesystem changes, and reads only the
witness object the verifier returned. The witness is structurally
typed and limited to `(verdict, claim_payload)`; no side-channel
field is honoured.

**Operational constraints.** Verifier VMs MUST run under a kernel-
enforced timeout (`cgroup.kill` on Linux), have no network by
default, and emit a signed witness or a kernel-synthesized
`Timeout` verdict on exit. The full constraint set lives in the
canonical home.

---

## §12 — Environment binding

Canonical home: [`v2/environment-access-control.md`](v2/environment-access-control.md).

### INV-ENV-01 — Task environment consistency

**Statement.** Every task carries an `environment` field that pins
the operator-declared `[environments.<label>]` block. The kernel
validates at `approve_plan` that the declared environment exists,
exposes only operator-permitted credentials, and matches the
task's `[[permitted_credentials]]` declarations. At runtime,
credential-proxy substitution honours only the bound environment.

**Justification.** An operator who declares `environment = "staging"`
is signing for "this task is allowed to touch the staging Postgres,
nothing else." Letting a planner mix credentials across
environments at runtime breaks the operator's mental model of
what they approved.

**Scenario.** Plan declares `environment = "staging"` and
`permitted_credentials = ["staging-pg"]`. A planner attempts to
read `prod-pg` from inside the task. The credential proxy
resolves the lookup against the bound environment, finds no
match, and rejects with `FAIL_CREDENTIAL_NOT_PERMITTED`.

---

## §13 — Audit chain coverage

Canonical home: [`v1/kernel-store.md`](v1/kernel-store.md) §2.5.2;
[`v2/audit-paired-writes.md`](v2/audit-paired-writes.md) (when present).

### INV-AUDIT-PAIRED-01 — State-mutating events are paired with their precursor

**Statement.** Every kernel-emitted audit event whose payload describes
a state transition MUST be paired with the precursor event that
explains *why* the transition fired, written in the same
transaction.

Examples of paired pairs:

* `IntentReceived` → `IntentAdmitted | IntentRejected`
* `SessionVmSpawned` → `SessionVmExited`
* `EscalationCreated` → `EscalationResolved | EscalationExpired`
* `OrchestratorRespawnAttempt` →
  `OrchestratorRespawnCompleted | OrchestratorRespawnCeilingExceeded`

**Justification.** Operators reading the audit chain in postmortem
mode need both the cause and the effect to reconstruct kernel
decisions (INV-05). A `SessionVmExited` row with no matching
`SessionVmSpawned` is unreconstructable; an `IntentAdmitted` with
no matching `IntentReceived` is structurally suspicious. Pairing
in the same transaction guarantees that either both rows land or
neither does.

**Scenario.** Mid-`approve_plan` the disk fills. Pre-pairing, the
kernel had emitted `PlanApproved` to the audit file and the
transaction then rolled back — the operator sees an approval that
never took effect. Post-pairing, the `PlanApproved` row is
buffered with the SQL transaction; the rollback drops both
together; the audit chain shows no event for the failed approval.

---

## §14 — Canonical image trust

Canonical home: [`v3/canonical-image-trust-anchor.md`](v3/canonical-image-trust-anchor.md).

### INV-IMAGE-TRUST-ANCHOR-FAIL-LOUD-01 — Boot rejects an unpopulated trust anchor

**Statement.** At boot, the kernel asserts that the compiled-in
`EXPECTED_KERNEL_SIGNING_KEY_BYTES` is not all-zero. If it is, the
kernel exits with `BOOT_ERR_KERNEL_TRUST_ANCHOR_UNPOPULATED` and
prints the operator-actionable remediation (re-bake with a
populated signing key).

**Justification.** An all-zero trust anchor means the kernel will
"verify" any canonical image because the signature it's checking
against is zero. This is the worst possible failure mode: the
trust system reports success while accepting arbitrary images.
Failing loud at boot rather than silently honouring zero makes
the misconfiguration impossible to miss.

**Scenario.** A developer builds the kernel without setting the
`RAXIS_KERNEL_SIGNING_KEY` env var that the build script reads.
The build emits a warning and embeds zeros. On the next boot,
the trust-anchor assertion fires; the kernel exits before opening
any socket; the operator re-bakes with a populated key.

---

## §15 — Plan bundle freshness

Canonical home: [`v2/plan-bundle-sealing.md`](v2/plan-bundle-sealing.md).

### INV-PLAN-BUNDLE-FRESH — Plan bundles are admitted at most once, within their freshness window

**Statement.** Every signed plan bundle carries a `signed_at`
timestamp and a CSPRNG nonce. The kernel admits a bundle only if
(a) `now - signed_at` is within `policy.plan_bundle.max_skew`, and
(b) the nonce has not been seen before (recorded in
`plan_bundle_nonces_seen` with a unique constraint).

**Justification.** Without freshness, an attacker who recovers an
old signed plan can replay it at any future time. Without nonce
binding, the same attacker can re-submit the same plan multiple
times to escape rate-limits. The two checks together make a plan
bundle a one-shot artifact bound to a specific wall-clock window.

**Scenario.** Operator signs a plan in the morning. Attacker
recovers the bundle bytes and re-submits at midday. The kernel
checks `plan_bundle_nonces_seen` and finds the nonce already
recorded; the second submission is rejected with
`FAIL_PLAN_BUNDLE_REPLAY`.

---

## §16 — Self-healing supervisor

Canonical home: [`v2/self-healing-supervisor.md`](v2/self-healing-supervisor.md).

### INV-SUPERVISOR-EXIT-CODE-CLASSIFICATION-01 — Restartable exits are bounded

**Statement.** The supervisor restarts the kernel only on a closed,
documented set of exit codes that represent transient,
self-healing failure modes (panic-with-no-state-corruption,
short-lived OOM, transient IO). All other exit codes
(`BOOT_ERR_*`, security violations, deliberate operator
SIGTERM) leave the kernel down. The classification table lives
in `crates/supervisor/src/classify.rs`.

**Justification.** A supervisor that restarts unconditionally turns
every fail-loud guarantee into a fail-loop. The kernel deliberately
exits with `BOOT_ERR_*` codes on configuration problems
(trust anchor unpopulated, store schema mismatch) precisely so
that human attention is required; the supervisor MUST honour
those exit codes by NOT restarting.

**Scenario.** The kernel exits with
`BOOT_ERR_KERNEL_TRUST_ANCHOR_UNPOPULATED` (per
INV-IMAGE-TRUST-ANCHOR-FAIL-LOUD-01). The supervisor reads the
exit code, looks it up in `classify_exit_code`, finds
`Classification::NonRestartable`, emits
`SupervisorRefusedRestart`, and exits itself. The operator is
paged.

**Operator-continuity exception.** After a clean supervisor-driven
restart, `recovery::reconcile_after_supervisor_restart` re-admits
the rows that THIS boot's recovery sweep produced (per
INV-INIT-04 corollary). Operators who want strict V1 fail-safe
behaviour (every kernel exit halts work for human review)
disable the supervisor entirely (`RAXIS_SUPERVISOR_AUTO_RESTART=0`).

---

## §17 — Notification scope

Canonical home: [`v2/email-and-notification-channels.md`](v2/email-and-notification-channels.md).

### INV-NOTIF-SCOPE-01 — Notification routing honours operator scope

**Statement.** Notifications dispatched to operator-visible channels
(email, webhook, inbox.jsonl) MUST be filtered against the
recipient's `operator_visible_events` policy block. A notification
about another operator's escalation is silently dropped at the
route-selection step before any channel emit.

**Justification.** Operators must not learn about activity outside
their declared scope through notification side-channels — that
breaks the same scoping that the dashboard enforces. Operators
who *should* see another operator's activity declare it
explicitly in policy.

**Scenario.** Operator Alice and Operator Bob run on the same kernel.
Bob's escalation fires. The notification dispatcher reads Alice's
`operator_visible_events`, finds Bob's escalation outside scope,
and routes only to Bob's channels. Alice's inbox is unaffected.

---

## §18 — Failure reason discipline

Canonical home: [`v3/failure-reason-mandate.md`](v3/failure-reason-mandate.md)
(when present).

### INV-FAILURE-REASON-MANDATORY-01 — Every terminal-Failed transition records a concrete reason

**Statement.** Any FSM transition into `Failed` (task, initiative,
session) MUST record a concrete, operator-actionable
`failure_reason` in the transition row. Synthetic or placeholder
reasons (`Unknown`, empty string, `"see logs"`) are rejected at
the transition function.

**Justification.** A `Failed` state with no reason is unreconstructable
six months later; the audit chain becomes a record of *that*
something failed, not *why*. The kernel's recovery and operator
UX both depend on the reason being a typed enum the system can
reason about (retry classification, escalation surface).

**Scenario.** A new IPC handler attempts to call
`transition_task(.., Failed, reason: "")`. The transition function
panics in debug builds via a `track_caller` `debug_assert!` and
rejects in release builds with `INVARIANT_FAILURE_REASON_REQUIRED`.

---

### INV-PLANNER-IPC-IDLE-WATCHDOG-01 — Wedged planner VMs are detected and forcibly recovered

Canonical home: [`v2/planner-ipc-idle-watchdog.md`](v2/planner-ipc-idle-watchdog.md).

**Statement.** Every kernel-supervised planner-IPC dispatch loop
(`crate::ipc::server::drive_planner_stream`) MUST bound the
wall-clock time between consecutive IPC frames from the planner
side. When the bound is exceeded the kernel MUST:

1. Forcibly terminate the substrate session via
   `SessionSpawnService::terminate_session` (which routes through
   the substrate's `shutdown_grace_then_force` dance, releasing
   the host-side hypervisor handle + vsock CID + virtiofs daemon
   adoption).
2. Synthesise a CONCRETE Mode-B failure reason that names the
   watchdog firing AND the threshold. The synthesised reason MUST
   pre-empt every other source-of-truth tier (structured exit
   notice, dispatch-stream error, activity breadcrumb), because
   every other tier is by definition stale when the watchdog
   fires.
3. Drive the orchestrator-continuation respawn through the same
   path Mode-B uses for any other premature exit, so the
   orchestrator can decide retry_subtask vs. settle Blocked per
   policy.

**Justification.** Without the watchdog a wedged planner VM
(host substrate reports the VM as "running" but no progress is
being made — e.g. AVF orphan XPC adoption race, in-guest PID 1
hung, vsock fd starvation) sits indefinitely consuming an
admission slot and silently breaks every DAG that depends on it.
The reproducer in iter71/iter72 was the AVF orphan pathology on
macOS, where a `SIGKILL`'d kernel left
`com.apple.Virtualization.VirtualMachine.xpc` processes parented
to `launchd`, and the next fresh kernel's executors stalled
before their first IntentRequest.

**Scenario.** An executor VM logs `planner-boot` then never
emits another frame (substrate-level wedge). After the configured
threshold (default 900s; override via
`RAXIS_PLANNER_IPC_IDLE_TIMEOUT_SECS`), the kernel emits
`planner_ipc_idle_watchdog_fired`, terminates the substrate
session, transitions the task `Running → Failed` with a reason
quoting the threshold and (where available) the last-seen
intent, and respawns the orchestrator to pick a recovery action.

---

### INV-PLANNER-PID1-ONLY-EXEC-01 — Planner binaries refuse to start outside PID 1

Canonical home: [`v2/planner-pid1-only-exec.md`](v2/planner-pid1-only-exec.md).

**Statement.** Each planner binary (`raxis-executor`,
`raxis-orchestrator`, `raxis-reviewer`) MUST refuse to start on
Linux when `std::process::id() != 1`, except when explicitly
bypassed via `RAXIS_PLANNER_PID1_ENFORCEMENT_BYPASS=1`
(SubprocessIsolation test fixtures only). The refusal MUST:

1. Run as the very first step of `main()`, BEFORE any
   filesystem mount, env hydration, or socket binding.
2. Emit a structured stderr breadcrumb
   (`planner_pid1_enforcement_violation`) carrying `pid`,
   `ppid`, `argv0`, the cited invariant, and the exit code.
3. Exit with code `126`, distinct from every other documented
   planner exit code (0 / 1 / 2 / 64 / 78).

**Justification.** Inside a Raxis microVM the planner binary is
PID 1 (`/init` in the initramfs). After PID 1 boots, the binary
remains at `/usr/local/bin/raxis-{executor,orchestrator,reviewer}`
and is reachable from the agent's `bash` tool. A child
invocation of the binary inside its own VM is a jailbreak: the
child inherits the parent's transport hints, can read the parent's
`/proc/<ppid>/cmdline`, and collides on the parent's port-binding
setup. iter72 forensics observed this in the wild
(an executor's Claude agent ran `raxis-executor --help` while
diagnosing DNS).

**Scenario.** An LLM-driven `bash` invocation inside an executor
VM runs `/usr/local/bin/raxis-executor --help`. The child sees
PID > 1, emits the structured violation breadcrumb to its
stderr (visible in the VM console log), and exits 126 BEFORE
opening any file descriptor or socket. The parent session
continues unaffected; the kernel's audit chain captures the
breadcrumb via the console-log scraper.

---

### INV-PLANNER-GUEST-AGENT-JAILBREAK-DEFENSE-01 — Guest hardening sweep precedes every dispatch

Canonical home: [`v3/guest-agent-jailbreak-defense.md`](v3/guest-agent-jailbreak-defense.md).

**Statement.** Every planner binary (`raxis-executor`,
`raxis-orchestrator`, `raxis-reviewer`) MUST invoke
`raxis_planner_core::harden_guest_for_agent` between its
PID-1-only filesystem mounts (`init_pid1_filesystem`,
`init_pid1_a3_egress`, `mount_workspace_shares`) and the
construction of its tokio runtime. It MUST then invoke
`raxis_planner_core::scrub_sensitive_env_for_agent` inside its
`run()` async fn between `BootContext::from_process` and
`run_role_session`. Together these MUST:

1. Bind-mount `/dev/null` over `/proc/cmdline` so reads return
   EOF (vector V1 — kernel-cmdline env-token recovery).
2. Set `PR_SET_DUMPABLE = SUID_DUMP_DISABLE` so per-pid procfs
   entries deny same-uid reads of PID 1's environ / maps /
   cmdline / exe (vector V2 — `/proc/1/environ` recovery).
3. Bind-mount `/dev/null` over each canonical planner-binary
   path in `PLANNER_BINARY_PATHS_TO_MASK` (vector V3 — binary
   exfiltration / offline analysis).
4. Drop `CAP_SYS_BOOT` from the bounding set so the agent's
   bash children cannot `reboot(2)` the VM out-of-band
   (vector V4 — out-of-band VM kill).
5. Set `PR_SET_NO_NEW_PRIVS = 1` so future setuid binaries
   cannot grant privileges across `execve` (vector V5 — setuid
   drift).
6. Remove every entry in `SENSITIVE_ENV_VARS_TO_SCRUB` from
   the process environment AFTER the in-guest listeners have
   captured their token clones (vector V6 —
   `Command::spawn`-inheritance leak to the agent's bash).

Every step MUST emit one structured stderr JSON line keyed on
`step:"guest-harden"` with an `event` discriminant naming the
specific defense. A verifier reviewer is expected to flag any
session whose console log lacks the canonical six-line guard
sequence before the first `step:"planner-boot"` line.

**Justification.** `INV-PLANNER-PID1-ONLY-EXEC-01` closes only
the *re-exec* sub-vector — the planner binary refuses to start
if invoked outside PID 1. The wider surface (kernel cmdline
exposing `raxis.envb64=…`, PID 1 environ readable to any
root-uid child, planner binary world-readable on disk,
`reboot(2)` callable from any root child, sensitive env
inherited by `Command::spawn`) remained open until this
hardening sweep. Each vector independently lets an in-VM LLM
agent recover a kernel-stamped secret, exfiltrate code, or
shut down the VM out-of-band. The sweep closes all six in a
single PID-1 post-mount hook so the dispatch loop never runs
against an unhardened guest.

**Scenario.** An executor VM boots. Between
`init_pid1_a3_egress` and the tokio runtime construction the
planner's `main` calls `harden_guest_for_agent`; the substrate
console log records six structured lines (`proc_cmdline_masked`,
`pr_set_dumpable_disabled`, `planner_binaries_masked`,
`cap_sys_boot_dropped_from_bounding_set`,
`pr_set_no_new_privs_enabled`). Inside `run()` the binary
calls `scrub_sensitive_env_for_agent`; the console log records
a seventh structured line (`sensitive_env_scrubbed`). The
agent then dispatches a tool call; the `BashTool` spawns
`bash -lc 'env | grep RAXIS_'`, which returns no output because
transport hints, model-routing hints, sidecar paths, budget knobs,
and session identity metadata were scrubbed from child-process
inheritance — proving the hardening engaged before the first agent
dispatch.

---

## §19 — Gate rejection and agent-hint contract

Canonical home: [`v3/gate-rejection-orchestrator-fixup.md`](v3/gate-rejection-orchestrator-fixup.md).

### INV-WITNESS-AGENT-HINT-WIRE-VALID-01 — `agent_hint` wire validity is enforced before token consumption

**Statement.** A `WitnessSubmission` whose `body.agent_hint` is
present but not a JSON string, or whose string length exceeds
`WITNESS_AGENT_HINT_MAX_BYTES` (8192), MUST be rejected with
`WitnessRejectionReason::InvalidAgentHint { reason }` and the
verifier's single-use token MUST NOT be consumed. Absent /
empty-string `agent_hint` on non-`Pass` is NOT a wire violation —
it routes through the tier-fallback chain pinned by
`INV-WITNESS-AGENT-HINT-RESOLUTION-TIERS-01`. `Pass` submissions
are exempt from the validity check.

**Justification.** The reserved key carries a structured contract
that downstream code paths depend on (orchestrator push, fixup
KSB). Letting a wire-malformed value through corrupts every
downstream view. Refusing to consume the token preserves the
existing verifier-respawn semantics (`Inconclusive`-equivalent
treatment for a malformed payload).

**Scenario.** A verifier emits `body.agent_hint = 42`. The kernel
detects the non-string and rejects with `InvalidAgentHint`. The
verifier token is preserved. The kernel re-spawns the verifier
(via the existing retry path), which now emits a valid string
hint, and the witness commits.

---

### INV-WITNESS-AGENT-HINT-RESOLUTION-TIERS-01 — Non-`Pass` witnesses always end up with a persisted (gate_type, critique) pair

**Statement.** When the kernel commits a non-`Pass` witness, it
MUST persist `tasks.last_gate_critique` and `tasks.last_gate_type`
through the deterministic three-tier resolution chain: (1)
verifier-emitted `body.agent_hint`; if absent / empty, (2)
operator-supplied `[[gates]].agent_hint_default` from policy; if
absent (only possible after a regression bypasses policy
validation), (3) a defensive gate-name-only template. Tiers 2 and
the defensive fallback MUST emit a `WitnessMissingAgentHint
{ source }` audit event with `source ∈ {"operator_default",
"gate_name_only"}`.

**Justification.** Downstream code (orchestrator push, fixup KSB)
assumes a non-empty critique is always available. Falling back
silently makes weak verifier authoring invisible; refusing the
commit blocks the operator's ability to observe the failure at
all. The graceful-degradation + audit-emit pattern preserves
visibility without making the system brittle.

**Scenario.** A poorly-written verifier emits `Fail` with no
`agent_hint`. The kernel reads
`[[gates]].agent_hint_default = "Review the {gate_type} policy..."`
from policy, persists it as the critique, emits
`WitnessMissingAgentHint { source: "operator_default" }`, and the
dashboard surfaces the weak-verifier flag.

---

### INV-GATE-FIXUP-BUDGET-KERNEL-ENFORCED-01 — Gate-fixup retry budget is enforced on one kernel code path

**Statement.** The `[gate_fixup].max_attempts` budget MUST be
enforced on exactly one code path:
`kernel::gate_fixup::auto_admit_gate_fixup_task` (iter72; replaces
the pre-iter72 orchestrator-mediated `handle_add_sub_task`). The
helper reads `parent.gate_fixup_attempts`, compares to policy, and
either returns `AutoAdmitOutcome::BudgetExhausted` (paired by the
witness handler with `TaskStateChanged { GatesPending → Failed }`
and `GateRejectionTerminal { terminal_reason:
"gate_rejected_fixup_budget_exhausted" }`), or inserts a fixup
task and increments `parent.gate_fixup_attempts` in the same
SQLite transaction.

**Justification.** Multi-site budget enforcement (witness handler,
intent handler, completion hook) is the canonical "off-by-one"
trap. Iter72 collapsed the orchestrator-mediated round-trip down
to a single kernel-side admit so the orchestrator cannot
double-spend the budget by retrying the round-trip; only the
kernel gets to say "enough"; the parent's `Failed` transition
lives on the same paired write as the rejection.

**Scenario.** A fourth non-`Pass` witness arrives for the same
parent. `process_non_pass_witness` calls
`auto_admit_gate_fixup_task`; the helper sees
`parent.gate_fixup_attempts = 3` ≥ `max_attempts = 3`, returns
`BudgetExhausted`. The witness handler emits
`GateRejectionTerminal { terminal_reason:
"gate_rejected_fixup_budget_exhausted" }` and transitions the
parent to `Failed`.

---

### INV-GATE-FIXUP-ADMIT-ATOMIC-01 — Kernel-authoritative gate-fixup admit is a single transaction

**Statement.** The kernel's `gate_fixup::admit_fixup_task_in_tx`
helper (called from `auto_admit_gate_fixup_task`) MUST land its
three SQL writes in one transaction:

  1. `INSERT INTO tasks (..., is_gate_fixup = 1,
     parent_gate_failure_task_id, parent_gate_failure_type,
     evaluation_sha = parent.evaluation_sha)`.
  2. `INSERT INTO task_dag_edges (predecessor = parent,
     successor = new fixup task)`.
  3. `UPDATE tasks SET gate_fixup_attempts = gate_fixup_attempts
     + 1 WHERE task_id = parent`.

The `GateFixupSpawned` audit row is emitted only after the
transaction commits successfully and carries the post-bump
attempt counter as `attempt_index`.

**Justification.** A crash between (1) and (3) leaves the
parent's budget counter unchanged while a fixup row exists — the
next admit for the same parent succeeds and the budget
under-counts. A crash between (1) and (2) leaves a fixup row
with no DAG edge — the topology query (`SubscribeInitiative
DagPanel`) silently drops the row. Combining the three writes
into one tx eliminates both partial-failure modes, and pairing
the audit emit with the post-commit observation eliminates a
"ghost spawn" surface that would otherwise survive transaction
rollback.

**Scenario.** Witness handler receives a non-`Pass` witness for
parent-1; `process_non_pass_witness` calls
`auto_admit_gate_fixup_task("parent-1", ...)`. Kernel observes
parent state `GatesPending`, parent `gate_fixup_attempts = 1`,
`[gate_fixup].max_attempts = 3`. Inside one transaction the
kernel inserts `tasks(parent-1--gatefixup-2, ..., is_gate_fixup=1,
parent_gate_failure_task_id = "parent-1")`, inserts
`task_dag_edges(parent-1 → parent-1--gatefixup-2)`, and updates
`parent-1.gate_fixup_attempts = 2`. Post-commit, the audit chain
carries `GateFixupSpawned { fixup_task_id:
"parent-1--gatefixup-2", parent_task_id: "parent-1", gate_type:
"NoSecretStrings", parent_evaluation_sha: "<parent SHA>",
attempt_index: 2 }`.

---

### INV-GATE-FIXUP-COMPLETION-PROPAGATES-01 — `CompleteTask` on a fixup task always closes the fixup loop

**Statement.** When `handle_complete_task` flips a task with
`is_gate_fixup = 1` to `Completed`, the kernel MUST emit
`AuditEventKind::GateFixupCompleted` (carrying
`fixup_task_id`, `parent_task_id`, `gate_type`, `outcome`,
`new_evaluation_sha`). When the fixup produced a new commit
(`outcome == "completed_with_commit"`), the kernel MUST also
update the parent's `tasks.evaluation_sha` to the new SHA so the
next gate-evaluation pass runs against the repaired tip.

**Justification.** The fixup loop is observable only through this
audit row. Without it, the orchestrator sees a normal executor
`Completed` without knowing whether the gate it was meant to
repair is now satisfiable, and the parent's `evaluation_sha`
stays anchored to the original failing SHA — the next witness
pass would re-fail on the same gate. Pairing the audit emit with
the parent's SHA update inside the same handler turns "fixup
done" into a single observable transaction the dashboard can
render and the orchestrator can route on.

**Scenario.** A `Fail` witness on `NoSecretStrings` triggers a
fixup task that removes an AWS access key from the diff. The
fixup commits the repair on top of the parent's failing SHA. On
`CompleteTask`, the kernel emits `GateFixupCompleted
{ outcome: "completed_with_commit",
  new_evaluation_sha: <repaired SHA> }`, updates the parent's
`evaluation_sha`, and the orchestrator re-emits an admission
intent against the new SHA. The verifier re-runs against the
repaired tip and emits a `Pass` witness; the parent advances
out of `GatesPending`.

---

### INV-PHASE-C-RUNNING-GATES-PENDING-COVERED-01 — Phase C transitions Running into GatesPending whenever pending gates appear

**Statement.** When intent Phase C admits a new intent for a task
whose evaluation produces a non-empty `pending_gates` set, the
SQL `tasks.state` MUST be flipped to `GatesPending` regardless of
whether the entry state is `Admitted` or `Running`. The handler
records a `TaskTransitionRecord` so the paired
`AuditEventKind::TaskStateChanged` row reaches the dashboard's
`SubscribeInitiative` push stream.

**Justification.** Pre-fix, Phase C only flipped the SQL state on
the `Admitted → GatesPending` edge, even though the FSM
(`fsm.rs` line 116) explicitly admits `Running → GatesPending`.
Tasks that admitted a fresh intent while already `Running` (e.g.
re-spawned executor pushes a second commit, or the witness
handler re-spawns verifiers on a new HEAD) had their SQL state
silently left at `Running` while every downstream consumer
(`evaluate_claims` re-spawn, `tasks.is_blocked()`, recovery
sweep, dashboard timeline) treated them as `GatesPending` based
on the separately-maintained `pending_gates` set. The split
view was observable as the dashboard's per-task FSM appearing
stuck on `Running` for the duration of the witness wait.

**Scenario.** A `Running` task admits a `ReportProgress` intent
that touches files newly gated by `[[gates]] gate_type =
TestCoverage`. The pre-spawn evaluator returns `pending_gates =
["TestCoverage"]`. Phase C transitions the SQL row to
`GatesPending`, emits the paired `TaskStateChanged
{ Running → GatesPending }` audit, and the dashboard observes
the FSM flip in real time. When the witness arrives and the
gate clears, the witness handler's gate-recheck path
transitions `GatesPending → Admitted` and Phase C then
re-transitions `Admitted → Running` on the next intent.

---

## Removed / consolidated invariants

The following invariant IDs appeared in earlier drafts of this file
and in code comments. They have been folded into the core
invariants listed above; their old wordings are preserved in the
git history (`git log specs/invariants.md`) and their canonical
homes still contain the full normative discussion.

| Old ID | Consolidated into |
|---|---|
| INV-INIT-05..11 | INV-INIT-04 (corollary) |
| INV-ESC-06 | INV-ESC-04 (operational; not an invariant) |
| INV-STORE-03 | code-style lint, not a structural rule |
| INV-SCHED-03 | INV-INIT-01 (plan-time validation) |
| INV-CERT-05 | INV-04 (audit chain captures all events) |
| INV-CONVERGENCE-01..06 | review-round cap; see [`v2/agent-disagreement.md`](v2/agent-disagreement.md) |
| INV-PLANNER-HARNESS-02..04, 06 | INV-PLANNER-HARNESS-01, INV-PLANNER-HARNESS-05 |
| INV-PLANNER-ORCH-* | INV-KERNEL-DAG-AUTHORITY-01 (kernel enforces; prompt advises) |
| INV-VERIFIER-02..15 | INV-VERIFIER-01 (operational constraints) |
| INV-AUDIT-PAIRED-02..07 | INV-AUDIT-PAIRED-01 |
| INV-NETISO-A3-* | [`v2/vm-network-isolation.md`](v2/vm-network-isolation.md) |
| INV-DASHBOARD-* | UI feature requirements; see [`v2/dashboard-hardening.md`](v2/dashboard-hardening.md) |
| INV-OBSERVABILITY-* | CI assertions; see [`v3/observability-prometheus.md`](v3/observability-prometheus.md) |
| INV-LIVE-E2E-* | test-harness rules; see [`v2/e2e-extended-scenario.md`](v2/e2e-extended-scenario.md) |
| INV-IMAGE-BAKE-* | build-pipeline constraints; see [`images/README.md`](../images/README.md) |
| INV-SUPERVISOR-{RESTART-AUDIT,CIRCUIT-BREAKER,OPT-IN,SIGTERM,SIGINT,SHUTDOWN-GRACE,OPERATOR-CONTINUITY,AUTO-RESUME}-* | INV-SUPERVISOR-EXIT-CODE-CLASSIFICATION-01 |
| INV-EXECUTOR-IMAGE-* | build-pipeline constraints; see [`images/README.md`](../images/README.md) |
| INV-KSB-* | [`v2/kernel-mechanics-prompt.md`](v2/kernel-mechanics-prompt.md) |
| INV-RETRY-* | [`v2/agent-disagreement.md`](v2/agent-disagreement.md) |
| INV-CRED-PROXY-*, INV-PROVIDER-*, INV-ELASTIC-*, INV-PUSH-*, INV-VM-CAP-*, INV-CAPACITY-*, INV-MERGE-*, INV-CLOUD-FWD-*, INV-NETISO-*, INV-OPERATOR-CUSTOM-IMAGE-*, INV-PROXY-TABLE-*, INV-AUDIT-RETENTION-* | feature-area specs; see [`v2/`](v2/) and [`v3/`](v3/) directories |
| INV-PLANNER-DNS-STUB-SYNC-BIND-01 | code-design constraint inside `raxis::tproxy::dns_stub`; rationale stays in the function's rustdoc |
| INV-PLANNER-DNS-STUB-SERVFAIL-ON-UPSTREAM-ERROR-01 | code-design constraint inside `raxis::tproxy::dns_stub`; rationale stays in the function's rustdoc |
| INV-DASHBOARD-GATE-STATS-PER-GATE-ROLLUP-01 | UI feature requirement; see [`v2/dashboard-hardening.md`](v2/dashboard-hardening.md) (matches the existing `INV-DASHBOARD-*` removal row) |
| INV-KSB-GATE-FIXUP-CONTEXT-01 | KSB-shape detail; see [`v2/kernel-mechanics-prompt.md`](v2/kernel-mechanics-prompt.md) (matches the existing `INV-KSB-*` removal row) |

Code comments still referencing the old IDs are accurate
descriptions of behaviour — they just point at consolidated parents.
Future PRs that touch a comment with a removed ID may either drop
the label, rewrite to the consolidated parent, or leave it alone.
The doc system is the source of truth; the comments are
navigational aids.

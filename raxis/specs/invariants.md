# RAXIS — System Invariants

> Single-file consolidation of every `INV-*` invariant in the v1 spec
> system. Each entry has the same shape:
>
> 1. **Statement** — the thing that must be true.
> 2. **Justification** — why we hold this invariant; what breaks without it.
> 3. **Scenario** — a concrete adversarial or operational example.
> 4. **Canonical home** — the spec file that owns the normative wording;
>    when the canonical home and this file disagree, the canonical home
>    wins (this file is a navigational consolidation, not a
>    re-specification).
>
> The full normative discussion of each invariant — failure modes,
> implementation call-sites, audit-event coverage, edge cases — lives
> in its canonical home. This file is for operators, reviewers, and new
> contributors who want to see the whole guarantee surface in one
> screen rather than reconstruct it from a dozen specs.
>
> Numbering convention:
>
> - **INV-NN / INV-NN<letter>** — top-level v1 invariants from
>   `philosophy.md` §1.2 (the must-pass list).
> - **INV-`<DOMAIN>`-NN** — domain-scoped invariants. Domain prefixes:
>   `INIT` (initiative & task FSM), `ESC` (escalation), `STORE`
>   (kernel store / SQLite), `POLICY` (policy epochs), `SCHED`
>   (scheduler), `TASK-PATH` (VCS path enforcement), `CERT`
>   (operator certificates).

---

## Table of contents

| Domain | IDs | Count |
|---|---|---|
| Top-level (must-pass) | INV-01, INV-02A, INV-02B, INV-03, INV-04, INV-05, INV-06, INV-07, INV-08 | 9 |
| Initiative & task FSM | INV-INIT-01..11 | 11 |
| Escalation | INV-ESC-01..06 | 6 |
| Kernel store | INV-STORE-01..03 | 3 |
| Policy epochs | INV-POLICY-01 | 1 |
| Scheduler | INV-SCHED-01 | 1 |
| VCS path enforcement | INV-TASK-PATH-01, INV-TASK-PATH-02 | 2 |
| Operator certificates | INV-CERT-01..05 | 5 |
| **Total** | | **38** |

---

## §1 — Top-level invariants (must-pass list)

These are the v1 release gates. If any one of these fails, v1 is not
done — regardless of what else works. Canonical home: `v1/philosophy.md`
§1.2.

### INV-01 — Planner needs a kernel session token

**Statement.** The planner cannot perform any authorised action without
a valid kernel-issued session token.

**Justification.** Without this, the entire authority model is
convention rather than enforcement: any process that knows the IPC
wire format could pose as the planner. Pinning every IPC call to a
session row in the store gives the kernel a single point at which to
revoke planner authority (`session revoke`) and a single object that
captures `(role, worktree_root, delegations, expiry)`.

**Scenario.** A second planner-shaped process (perhaps the operator's
shell history reading from the wrong env) connects to the kernel and
submits `IntentRequest`. With no session token in the message it is
rejected at the dispatcher; with a session token whose row was
revoked it is rejected at session-lookup; with a session token whose
`expires_at` has passed it is rejected at the same gate. No
authority leaks past these checks.

**Canonical home.** `v1/philosophy.md` §1.2.

---

### INV-02A — All inference goes planner → kernel → gateway, kernel-priced

**Statement.** The planner binary has no provider credential store
access and no IPC message type that routes to a provider inference
endpoint; the only inference path is `InferenceRequest → kernel →
gateway`. Admission cost (`estimated_cost`) is kernel-computed from
`budget::compute_admission_cost` using VCS-derived inputs and policy —
no planner-supplied field reaches `consume_budget`.

**Justification.** Two failure modes are blocked by one invariant:
(a) a planner with provider credentials could call the model directly
and bypass the budget entirely; (b) a planner allowed to declare its
own admission cost could declare zero and bypass budget enforcement
even on the kernel-routed path. Pricing must be derived from VCS facts
the kernel already trusts.

**Scenario.** A compromised planner attempts to route an inference
call directly to OpenAI to avoid the lane budget. It has no
credentials, no DNS exit, and no IPC discriminant for "raw provider
call" — the request is structurally impossible to express. Even when
it routes through the kernel, the `estimated_cost` it provides is
discarded by `compute_admission_cost`, which derives the real cost
from `(touched_paths, intent_kind, policy.budget.base_cost_per_intent_kind)`.

**Canonical home.** `v1/philosophy.md` §1.2; `v1/kernel-core.md` §3 (`budget`).

---

### INV-02B — Planner has no direct network egress

**Statement.** The planner has no direct network egress of any kind;
all external data fetches go through `FetchRequest → kernel →
gateway`. The kernel logs `{fetch_request_id, url, fetched_at,
response_sha256, content_type, byte_len}` before content is returned
to the planner.

**Justification.** Without this, INV-05 (reproducibility) breaks —
a planner that can pull in unlogged external inputs makes the
audit chain insufficient to reconstruct kernel decisions. It also
closes the prompt-injection observability gap: every external byte
the planner has ever seen is named, hashed, and timestamped in the
audit log.

**Scenario.** A planner attempts to `curl` an attacker-controlled
config endpoint to fetch instructions. The container/sandbox
firewall rejects the egress; the only allowed wire path is the
IPC socket to the kernel; the kernel logs every fetch with its
URL, content hash, and byte length. After a postmortem the
operator can `grep` the audit chain for unexpected hosts.

**Canonical home.** `v1/philosophy.md` §1.2; `v1/peripherals.md` §3.

---

### INV-03 — Witness-to-commit binding

**Statement.** A witness bound to commit SHA `A` cannot satisfy a
gate check for commit SHA `B`.

**Justification.** Without this, stale or fabricated witnesses pass
gates: a verifier's "tests passed" claim from yesterday's commit
could let today's regression-introducing commit through the same
gate. Binding every witness to a specific commit SHA via the
`witness_records` row makes "this gate is satisfied" a statement
about a specific source state, not about history.

**Scenario.** The planner submits `CompleteTask` with `head_sha = B`.
`evaluate_claims` looks up `witness_records` rows for `(task_id,
head_sha = B)`; the previous successful witness for `head_sha = A`
does not appear. The kernel re-spawns the verifier under `head_sha
= B`, the regression fails, and the gate check rejects.

**Canonical home.** `v1/philosophy.md` §1.2; `v1/kernel-store.md`
§2.5.6 (`witness_records`).

---

### INV-04 — Audit log tamper-evidence

**Statement.** Any modification to the audit log (delete, update,
truncate) is detectable by hash chain verification.

**Justification.** Without this the audit log is a convenience, not
a record. Every operator and forensic investigator depends on the
chain being unforgeable: if an entry can be silently edited, the
chain stops being usable as evidence and the kernel's "all
decisions are reproducible from stored records" claim collapses.

**Scenario.** An attacker truncates `segment-007.jsonl` to remove
an `OperatorCertInstalled` event for a key they had compromised.
`raxis audit verify` re-walks the chain, computes the hash of
segment N+1's first record from segment N's last record, and
detects the discontinuity. The kernel itself refuses to advance
the epoch when the chain is invalid.

**Canonical home.** `v1/philosophy.md` §1.2; `v1/kernel-store.md`
§2.5.2 (audit log).

---

### INV-05 — Decisions are reproducible from stored records

**Statement.** Given the audit log and kernel state at crash time,
kernel decisions are reproducible from stored records.

**Justification.** Without this, recovery is guesswork. The kernel
must be able to answer "why did this task transition to `Failed`
at timestamp T?" by reading state alone, with no reliance on
in-memory state that may have been lost on crash. This is what
makes `recovery::reconcile_tasks` and the audit chain meaningful —
the recovery path is a deterministic function of the durable
inputs.

**Scenario.** The kernel crashes mid-execution. On restart,
`recovery::reconcile_tasks` sweeps non-terminal tasks to
`BlockedRecoveryPending` based on their stored state alone; no
in-memory queue or counter is consulted. An investigator pulls
the audit log six months later and replays every decision in
order — same inputs, same outputs.

**Canonical home.** `v1/philosophy.md` §1.2; `v1/kernel-core.md` §recovery.

---

### INV-06 — Approval gates require a valid scoped token

**Statement.** An action requiring approval does not execute without
a valid, scoped, unexpired approval token whose `ApprovalProof` is
written to the kernel state store.

**Justification.** Without this, escalation is a delay mechanism
rather than a gate: the planner could claim "approved" and proceed.
The kernel must independently verify each token (`validate_approval_token`)
and persist the resulting `ApprovalProof` so the audit chain
records exactly which token authorised which action.

**Scenario.** The planner crafts a fake `ApprovalToken` and presents
it. `validate_approval_token` performs eight checks (token-hash
lookup, policy-epoch match, expiry, consumed bit, nonce replay,
scope, escalation-status, validity) and rejects the forgery at
step 1 (`NotFound`). Even a real-but-replayed token is rejected at
the nonce-replay step.

**Canonical home.** `v1/philosophy.md` §1.2; `v1/kernel-core.md` §4
(escalation FSM); INV-ESC-01..06.

---

### INV-07 — Required claims are kernel-derived from VCS state

**Statement.** A planner-submitted path manifest cannot influence
which claim types are required; the kernel derives required claims
from VCS state independently.

**Justification.** Without this, the planner controls its own
quality obligations: a planner that declares "no test files
touched" gets to skip the test-pass gate. Kernel-derived path
information ensures the gate set is a function of what was
*actually* committed, not what was *claimed* committed.

**Scenario.** The planner submits an intent claiming
`touched_paths = []`. `policy_lookup::required_claims` ignores the
manifest and computes the path set from `vcs::diff(base_sha,
head_sha)`; the resulting required claims include the test-pass
gate; the planner cannot bypass the gate by lying about its scope.

**Canonical home.** `v1/philosophy.md` §1.2; `v1/kernel-core.md` §gates.

---

### INV-08 — Rejection codes do not leak policy structure

**Statement.** Rejection reason codes exposed to the planner do not
reveal which specific policy rule fired.

**Justification.** Without this, the gate system can be reverse-engineered
by probing: a planner that observes "rejected because rule R7 fired"
learns the policy structure rule by rule and can craft inputs that
satisfy each rule individually. Opaque rejection codes (`FAIL_POLICY_VIOLATION`,
`FAIL_PATH_POLICY_VIOLATION`, etc.) keep the policy structure
hidden behind a binary gate.

**Scenario.** An attacker probes the kernel with malformed intents
to map the policy. They observe `FAIL_POLICY_VIOLATION` for many
distinct underlying causes — path scope, unknown task, missing
gate witness — and cannot tell which rule fired. The richer
diagnostic lives only in the audit chain (operator-visible) and
the planner-feedback table (operator-mediated).

**Canonical home.** `v1/philosophy.md` §1.2; `v1/peripherals.md` §3.1.

---

## §2 — Initiative & task FSM (INV-INIT-*)

Canonical home: `v1/kernel-core.md` §4.8 (Trust Invariants — Gap 4).

### INV-INIT-01 — Planner cannot create or amend tasks

**Statement.** The planner cannot create or amend tasks. Tasks are
instantiated from the signed plan artifact at `approve_plan` time.
No planner IPC message results in a new task row.

**Justification.** The signed plan is the authoritative declaration
of what work was approved. If the planner could insert tasks
post-approval, the operator's signature on the plan no longer
covers the actual workload — the planner could expand its scope
indefinitely after approval.

**Scenario.** A planner submits `IntentKind::CompleteTask { task_id:
T_new }` for a `task_id` that does not exist in any signed plan.
The intent handler rejects with `FAIL_UNKNOWN_TASK` because no
task row was ever inserted for `T_new`; only `approve_plan` has
the privilege of inserting task rows.

---

### INV-INIT-02 — Planner-driven transitions are bounded to terminal task states

**Statement.** The planner cannot transition a task to any state
other than `Completed` or `Failed`. All other transitions are
kernel- or operator-initiated. `transition_task` enforces this via
the `TransitionActor` check.

**Justification.** Limiting planner-initiated transitions to the two
terminal states reduces the FSM surface the planner can manipulate:
the planner can declare "I'm done" or "I gave up," but cannot move
a task to `Blocked`, `Aborted`, `BlockedRecoveryPending`, or any
intermediate non-terminal state. Those transitions belong to the
kernel (gate evaluation, recovery) or to the operator (`task abort`).

**Scenario.** A misbehaving planner submits a synthetic `IntentRequest`
hoping to move its task back to `Admitted`. `transition_task`
checks the actor (planner) against the requested transition and
rejects: planner can only request `Running → Completed` or
`Running → Failed`.

---

### INV-INIT-03 — Successors blocked until predecessors complete

**Statement.** A successor task cannot become schedulable (returned
by `next_ready_tasks`) until all its predecessors are `Completed`.
`release_successors` is the only mechanism that marks a successor's
predecessors as satisfied in the DAG edge table.

**Justification.** The DAG edges in the signed plan encode work
dependencies that the operator has approved. If a successor could
run before its predecessors complete, the kernel would be
executing work the operator did not approve in the order they
approved it — a structural violation of the plan signature.

**Scenario.** Plan declares `B depends on A`. Task A is in
`Running`. Planner attempts to schedule B. `next_ready_tasks` does
not return B because the DAG edge `A → B` has not been satisfied
yet (`release_successors` only runs after `A` reaches `Completed`).

---

### INV-INIT-04 — `evaluate_terminal_criteria` is synchronous after every transition

**Statement.** `evaluate_terminal_criteria` is called after **every**
`transition_task` write — terminal and non-terminal. It is never
called proactively or on a timer. `transition_task` is the single
authoritative call-site.

**Justification.** Initiative state (`Executing`, `Blocked`,
`Completed`, `Failed`) must always be consistent with the task
state snapshot after each state change. A timer-based or
asynchronous evaluator would introduce a window in which the
initiative state and task states disagree — operators making
real-time decisions in that window would see contradictory state.

**Scenario.** The last running task in an initiative transitions
`Running → Completed` under an `AllTasksSucceeded` terminal
criterion. `evaluate_terminal_criteria` runs synchronously inside
the same transaction and transitions the initiative to
`Completed`. The operator's next `raxis status` call sees both
states consistent — no sliver of "all tasks done but initiative
still Executing."

---

### INV-INIT-05 — `BlockedRecoveryPending` requires operator action

**Statement.** A `BlockedRecoveryPending` task can only be resumed
(`raxis-cli task resume`) or terminated by operator `task abort`.
The planner cannot self-resume; the kernel cannot auto-resume.

**Justification.** A task lands in `BlockedRecoveryPending` only
after a kernel crash; the operator must inspect the situation and
decide whether to resume (state was salvageable) or abort (state
was lost). Auto-resume would replay potentially-stale work without
human review of the crash cause.

**Scenario.** Kernel crashes mid-task. On restart, `reconcile_tasks`
sweeps the task to `BlockedRecoveryPending`. Operator runs `raxis
log` to inspect crash cause, decides the task is safe to resume,
runs `raxis task resume <id>`. Only then does the task transition
back to `Running`.

---

### INV-INIT-06 — Plan artifact immutability

**Statement.** The signed plan artifact is immutable after
`approve_plan`. The `terminal_criteria`, task list, and DAG edges
cannot be modified. Any change requires a new plan submission and
a new `approve_plan` operation.

**Justification.** The operator's signature on the plan covers a
specific snapshot of work. If the plan could be edited
post-approval, the signature no longer authenticates the executing
plan — the operator's authority would be retroactively transferred
to whoever made the edit.

**Scenario.** A planner attempts to add a new task to an in-flight
initiative by re-submitting the plan. The store rejects because
`signed_plan_artifacts.plan_artifact_sha256` is set and never
updated; the only way forward is `create_initiative` with a new
`initiative_id`, then `approve_plan` against the new artifact.

---

### INV-INIT-07 — `RetryTask` accepts only `Failed`

**Statement.** `RetryTask` (`lifecycle::retry_task`) is the only v1
operator-initiated transition out of a terminal task state. It
accepts `Failed` only — never `Aborted`, `Cancelled`, or
`Completed`.

**Justification.** `Aborted` is non-retryable because the cause was
infrastructure failure or operator abort; re-attempt requires a
fresh initiative. `Cancelled` is non-retryable because the
initiative is itself terminal. `Completed` cannot be "un-completed"
without violating the terminal state's audit-chain semantics.

**Scenario.** Operator sees a task in `Aborted` and attempts to
retry. `retry_task` rejects with the explicit "non-retryable
terminal state" error and directs the operator to create a new
initiative for the work.

---

### INV-INIT-08 — Gate progress is recoverable from `witness_records`

**Statement.** Gate progress is always recoverable from
`witness_records` (Table 13) plus the policy artifact, without any
in-memory state surviving a crash.

**Justification.** The verifier subsystem's pending spawn queue and
running-verifier counter are explicitly best-effort: lost on crash,
rebuilt as the empty queue + zero counter at startup. The
persistent state of "which gates are satisfied for which `(task_id,
evaluation_sha)`" lives in `witness_records`; "which gates are
required" is computable from `policy_lookup::required_claims`
against `task.touched_paths`. After a crash, the kernel rebuilds
this view deterministically.

**Scenario.** Kernel crashes after gate G0 has been witnessed but
G1, G2, G3 are mid-flight. On restart, the in-memory queue is
empty and the running counter is zero — but `witness_records` still
shows G0 as satisfied. `evaluate_claims` re-spawns G1, G2, G3
verifiers; G0 is not re-spawned because its witness is durable.

---

### INV-INIT-09 — No automatic v1 deadline

**Statement.** v1 has no automatic task-level or initiative-level
wall-clock deadline. No `deadline_at` column, no sweep, no
`BlockReason::DeadlineExpired`, no `FAIL_TASK_DEADLINE_EXPIRED`.

**Justification.** Wall-clock deadlines without operator opt-in
would be a behaviour change that surprises operators (their
in-flight work suddenly aborts after N hours). v1 instead bounds
task lifetime by seven mechanisms documented in `kernel-core.md`
§4.5: lane budget exhaustion, verifier rlimits, operator levers
(`task abort`, `initiative abort`, `session revoke`), and
cooperative planner self-deadline via `IntentKind::ReportFailure`.

**Scenario.** A planner gets stuck on a task and consumes lane
budget endlessly. `max_cost_per_epoch` exhaustion fires
`FAIL_BUDGET_EXCEEDED` once the lane runs out, bounding the
infinite-loop case to one epoch's worth of cost — without
introducing a new failure mode that catches well-behaved long
tasks.

---

### INV-INIT-10 — Initiative quarantine

**Statement.** A row in `initiative_quarantines` (Table 21) freezes
its initiative against new `IntentRequest`s. The intent handler's
`run_phase_a` runs the quarantine guard at Step 3A. All four
`IntentKind` variants hit this gate; quarantine is total. In-flight
tasks are NOT aborted — quarantine is a curtain, not a guillotine.

**Justification.** When an operator key is suspected compromised,
the operator needs a fast, reversible-only-by-fresh-initiative way
to stop new work routing under that authority. Quarantine is
faster than `policy sign` + `epoch advance` (which is the slower
key-rotation path) and is the immediate containment primitive.

**Scenario.** Operator's signing key may be leaked. They run
`raxis operator quarantine-plans-by <fp> --reason "leaked"`. The
kernel inserts one quarantine row per matching initiative + emits
one `InitiativeQuarantined` per row + a single
`OperatorQuarantineSwept` rollup. Subsequent planner intents
under those initiatives reject with `FAIL_INITIATIVE_QUARANTINED`.

---

### INV-INIT-11 — Operator-cert four-zone gate

**Statement.** Every operator op is gated by
`kernel/authority/cert_check::CertEnforcer` against the cert's
four-zone status. `Active` and `AlwaysActiveEmergency` allow all
`permitted_ops`; `Expiring` allows all ops but emits a deduplicated
warning; `Grace` allows only recovery ops; `Expired` and
`NotYetValid` deny all ops. `EmergencyRecovery` certs are
structurally pinned to `permitted_ops = ["RotateEpoch"]` and
`not_after = 0`. Misconfigured certs are loadable only via
`--force-misconfig` at policy-sign time, which records a bypass
event; the bypass NEVER applies to pubkey/fingerprint or
self-signature mismatches. Per INV-CERT-01, there is no legacy
no-cert branch that bypasses this gate.

**Justification.** The four-zone model gives operators a graceful
expiry path: warn before expiry, allow recovery ops in grace,
fail closed past grace. Without zones, expiry would be a cliff
that strands operators mid-incident; without grace's recovery-op
allowlist, the operator could not even rotate the expired cert
because cert rotation requires their authority.

**Scenario.** Chika's cert hits the `Grace` zone the night before
an outage. She runs `raxis cert install --replace-for <fp>
--new-cert chika-renewed.cert.toml --policy …` — `cert install`
is in the recovery-op allowlist, so the rotation succeeds even in
grace. She re-signs the policy and advances the epoch. The
`OperatorCertInstalled.previous_fingerprint` event records the
rotation.

---

## §3 — Escalation (INV-ESC-*)

Canonical home: `v1/kernel-core.md` §4.

### INV-ESC-01 — No self-approval

**Statement.** No transition from `Pending` to `Approved` without an
operator-signed `ApprovalToken`. The kernel cannot self-approve an
escalation.

**Justification.** Escalation exists precisely to inject human
authority into otherwise-automated execution. If the kernel could
self-approve, there would be no human gate.

**Scenario.** Planner submits an escalation; the kernel inserts
`Pending`. Even if there is a bug elsewhere that calls
`approve_escalation`, that handler refuses without a valid
`ApprovalToken` — and `ApprovalToken` minting requires an
operator's IPC call.

---

### INV-ESC-02 — Approval tokens are scoped to a policy epoch

**Statement.** `validate_approval_token` always checks
`token.policy_epoch == ctx.policy.load().epoch()`. If they differ,
returns `EpochMismatch` and the escalation remains `Approved`.
The token is invalid; the operator must re-issue.

**Justification.** Policy epochs change the rules under which an
action is judged. A token issued under epoch N might authorise an
action that epoch N+1 would forbid; failing closed on
epoch-mismatch keeps the operator's intent ("approve under the
rules I just signed") legible.

**Scenario.** Operator approves an escalation for `WriteSecrets`
under epoch 5. While the planner is preparing to use the token,
the operator advances to epoch 6 (which removes the
`WriteSecrets` capability). Token presentation fires
`EpochMismatch`; the operator must re-approve under epoch 6 if
they still want to grant the capability.

---

### INV-ESC-03 — Approval tokens are session-bound

**Statement.** `token.session_id` must equal the session presenting
the token. A token issued for session A cannot be used by session B.

**Justification.** Sessions are the kernel's per-planner trust
unit; binding tokens to sessions ensures that if planner A's
approval leaks, planner B cannot use it. The cost of this binding
is one session column in the token; the benefit is per-planner
blast-radius isolation.

**Scenario.** Two planner sessions exist (perhaps a primary and a
fallback). An attacker compromises the primary's filesystem and
exfiltrates an approval token. Using it from any other session
fails — including from a freshly-minted session for the same
operator.

---

### INV-ESC-04 — Approval tokens are single-use (nonce-checked)

**Statement.** The nonce in each `ApprovalToken` is single-use.
Once consumed, the nonce is written to `approval_token_nonces`;
future presentations of the same token return `NonceConsumed`.

**Justification.** Without a single-use guarantee, an approval
token becomes a long-lived capability — an attacker who captures
it once can replay it indefinitely. Nonce single-use bounds the
window of compromise to "between issuance and first use."

**Scenario.** Operator approves an escalation; planner uses the
token successfully. An attacker captures the token from the
filesystem and replays it. `validate_approval_token` step 5
(nonce-replay check) finds the existing nonce row and returns
`NonceConsumed`; the dispatcher maps to `UNAUTHORIZED`.

---

### INV-ESC-05 — Action must fall within token scope

**Statement.** The proposed action must fall within
`token.scope` — `action ⊆ scope`. Enforced by `check_scope` at
step 6 of `validate_approval_token`.

**Justification.** The operator's scope choice is the granular
control surface for escalation: "I'm approving exactly this
narrower thing." Without scope-fidelity, a token approved for
`{ WriteCode }` could authorise `{ WriteSecrets }` — collapsing
all escalation to "all-or-nothing" and removing the operator's
ability to grant least privilege.

**Scenario.** Operator approves an escalation scoped to
`CapabilityUpgrade { WriteCode }`. The planner attempts to use
the token for `CapabilityUpgrade { WriteSecrets }`. `check_scope`
returns `false`; the kernel returns `ScopeMismatch`.

---

### INV-ESC-06 — Planner has no escalation-status query in v1

**Statement.** The planner cannot query escalation status by
`escalation_id` via IPC in v1 — no status-query endpoint exists in
`handlers/mod.rs`. Notification of approval is out-of-band (Shell
notification channel by default).

**Justification.** A status-query endpoint would invite the
planner to busy-poll for approval, which couples the planner to
operator latency in a way the v1 notification model deliberately
avoids. The out-of-band channel makes the operator the producer
of the "you may proceed" signal.

**Scenario.** A planner attempts to call a hypothetical
`EscalationStatusQuery` IPC variant. The dispatcher has no arm
for it; the call is rejected as an unknown discriminant. Spec
violation: any future PR that adds such an arm in v1 fails the
testable assertion against this invariant.

---

## §4 — Kernel store (INV-STORE-*)

Canonical home: `v1/kernel-store.md` §2.5.1 (DDL + mutex/transaction
contracts).

### INV-STORE-01 — Single-acquire single-transaction discipline

**Statement.** Every kernel operation that issues `BEGIN`/`COMMIT` on
the connection must hold the `tokio::sync::Mutex` continuously from
`BEGIN` through `COMMIT` (or `ROLLBACK`). The mutex is async-aware
and FIFO; using `std::sync::Mutex` would block the runtime,
`parking_lot::Mutex` would not be FIFO under contention. Releasing
the mutex mid-transaction is forbidden.

**Justification.** SQLite serialises writes across connections via
its WAL; the tokio mutex is what serialises tokio tasks across
the **same** connection. Releasing the mutex mid-transaction
would let another tokio task observe the partially-completed
transaction state — undefined at the SQLite level.

**Scenario.** A handler calls `transition_task` which writes to
`tasks`, then calls `evaluate_terminal_criteria` which writes to
`initiatives`. Both writes happen under one
`Connection::transaction()` borrow held under one mutex
acquisition; another tokio task waiting on the mutex sees the
fully-committed snapshot, never the in-between state.

---

### INV-STORE-02 — Multi-table atomicity

**Statement.** Operations that mutate more than one table to
maintain a cross-table consistency relationship must execute
every write in a single SQL transaction held under one
INV-STORE-01 mutex acquisition. The exhaustive v1 list:
`lifecycle::transition_task` + `evaluate_terminal_criteria`,
`lifecycle::approve_plan` + `scheduler::admit_in_tx`,
`lifecycle::create_initiative` (initiatives + signed_plan_artifacts),
`lifecycle::abort_initiative` (tasks bulk-cancel + initiatives),
`policy_manager::advance_epoch` Phase 1,
`handlers/intent::run_phase_c` (intent acceptance),
`scheduler::budget::reserve_budget_in_tx` (check + INSERT),
`handlers/witness::handle` SQL portion (validate + write +
consume), `recovery::reconcile_tasks` +
`expire_orphan_verifier_tokens`.

**Justification.** A partial-write outcome would leave the store
in an inconsistent state — e.g. a budget reservation without a
matching task transition, a swept policy without the
`policy_epoch_history` row, or a `Draft` initiative with no
`signed_plan_artifacts` row that subsequent `approve_plan` calls
will fail to read. These are unrecoverable: the kernel has no
way to "undo" a half-applied multi-table change at startup
(except for the tasks-sweep `recovery::reconcile_tasks` does for
the specific `BlockedRecoveryPending` case).

**Scenario.** An intent is accepted: handler writes to `tasks`
(state + intent fields), `task_intent_ranges` (range row), and
`lane_budget_reservations` (reservation row) — all in one
transaction. If the transaction fails mid-way (FSM rejection
because operator concurrently aborted, disk full, constraint
violation), nothing is committed; the intent is rejected
wholesale and the lane is not stranded with a phantom
reservation.

**Concurrency-bug catalogue.** The non-trivial enforcement
scenarios — patterns A (split mutex acquisition / TOCTOU), B
(multi-call composition outside tx), C (read in one tx then
write in another), D (multi-table writes with no explicit
transaction) — are documented step-by-step in
`v1/kernel-store.md` §2.5.1.1 with concrete adversarial
interleavings, the canonical fix for each, and the
regression-test home that pins it. New PRs that touch a
multi-write kernel path are required to read that section.

---

### INV-STORE-03 — No raw SQL string literals

**Statement.** No Rust source file across the workspace —
production or test code, in any crate that touches `kernel.db`
(`raxis-kernel`, `raxis-store`, `raxis-cli`, `raxis-test-support`,
and any future store consumer) — may contain a raw SQL
table-name or state-value string literal. Use the `Table` enum
plus `.as_str()` or the appropriate state enum.

**Justification.** Without this, a typo in a table name (`tasks`
vs `task`) or a state value (`Completed` vs `Complete`) silently
becomes a runtime SQL error in code paths that may not be hit
until production. The enum forces the typo to surface at compile
time.

**Scenario.** A new contributor writes
`conn.execute("DELETE FROM task_dag_edges WHERE …", …)` in test
code. CI catches the raw string literal via the workspace lint;
the contributor is forced to use `Table::TaskDagEdges.as_str()`
which (correctly) resolves to `task_dag_edges` regardless of
typo-sensitivity.

---

## §5 — Policy epochs (INV-POLICY-*)

Canonical home: `v1/kernel-store.md` §2.5.1 (multi-phase advance
contract); `v1/kernel-core.md` §`policy_manager.rs`.

### INV-POLICY-01 — Epoch advance atomicity

**Statement.** `policy_manager::advance_epoch` Phase 1 (the
SQL-write phase) writes to `delegations`, `sessions`,
`policy_epoch_history`, and the audit-pointer table inside one
transaction held under one INV-STORE-01 mutex acquisition. Phase
2 (in-memory `ArcSwap` swaps for `ctx.policy` and
`ctx.allowlist_cache`) runs only after Phase 1 commits, and is
infallible. Phase 3 (gateway `EpochAdvanced` signal) is
best-effort and does not affect the success of the advance.

**Justification.** A partially-applied epoch advance would leave
some kernel components running under the new policy and others
under the old — operators would see contradictory enforcement
depending on which subsystem they hit first. The
single-transaction Phase 1 + infallible Phase 2 + best-effort
Phase 3 ordering keeps the visible state machine binary
(old | new), never mixed.

**Scenario.** Mid-`advance_epoch`, the disk fills up. Phase 1's
transaction rolls back; Phase 2 never runs; the in-memory
`ArcSwap` still points at the old policy; the gateway never
receives `EpochAdvanced`. The kernel logs `PolicyAdvanceFailed`
and continues serving under the old epoch.

---

## §6 — Scheduler (INV-SCHED-*)

Canonical home: `v1/kernel-store.md` §2.5.7 (INV amendments).

### INV-SCHED-01 — `scheduler::admit` runs only at plan approval

**Statement.** `scheduler::admit` is called exclusively from
`initiatives::lifecycle::approve_plan`. The intent handler
(`handlers/intent.rs`) never calls `admit`. `admit`'s sole
responsibility is inserting the task row and DAG edges into the
store at plan approval time.

**Justification.** Tasks are sealed at approval (INV-INIT-01,
INV-INIT-06); calling `admit` from the intent handler would
re-introduce the planner's ability to influence the task set
post-approval. Pinning `admit` to one call-site makes the
"approval is the only insertion point" property a function of
where calls go, not a property of every individual handler.

**Scenario.** A future PR adds an `IntentKind` variant that
needs to insert a new task. The reviewer notices the new call
to `admit` from `handlers/intent.rs`, flags the spec violation,
and the PR is rejected before merge.

---

## §7 — VCS path enforcement (INV-TASK-PATH-*)

Canonical home: `v1/kernel-store.md` §2.5.8 (VCS Path Scope
Enforcement).

### INV-TASK-PATH-01 — Intent admission requires path coverage

**Statement.** The kernel admits an intent if and only if every
path in `touched_paths(intent)` — computed by the kernel from
`(base_sha, head_sha)` via `vcs::diff`, not from any
planner-declared manifest — is a member of `effective_allow(task_id)`
at the time of admission. Failing intents are rejected non-terminally;
the task remains in its current state. `effective_allow` is recomputed
on every intent call.

**Justification.** Planner-declared path lists are untrusted
(INV-07): the planner could lie. Computing the path set from
the diff binds the enforcement to what was actually committed.
Recomputing `effective_allow` on every call ensures policy
changes mid-task take effect immediately.

**Scenario.** Planner commits a fix that incidentally touches
`secrets/aws_creds.json`. They submit the intent claiming
`touched_paths = ["src/foo.rs"]`. `vcs::diff` returns the real
list including the secrets path; the path is not in
`effective_allow`; the intent is rejected with
`FAIL_PATH_POLICY_VIOLATION`. Task stays in `Running`; planner
must revert the out-of-scope commit.

---

### INV-TASK-PATH-02 — Task completion requires full path closure

**Statement.** The kernel does not transition a task to
`Completed` unless every path in the union of `touched_paths`
across all accepted intent ranges, **plus** the trailing segment
from `tasks.evaluation_sha` to the `CompleteTask` intent's
`head_sha` (when they differ) — with that trailing segment
passing `topology_check` (no integration carve-out) before
`vcs::diff` — is a member of `effective_allow(task_id)`
recomputed at completion time.

**Justification.** Without checking the trailing segment, a
planner could land out-of-scope commits in the gap between the
last accepted intent and the `CompleteTask` intent and complete
the task without path closure on that tip. Without the
topology check on the trailing segment, a planner could slip a
merge commit past the integration-merge carve-out at completion.

**Scenario.** Planner has accepted intent ranges covering
commits A..C, all in scope. Between submitting the last
intent and `CompleteTask`, they push commit D that touches
`secrets/`. `CompleteTask` triggers the trailing-segment check
on `(C, D)`; `vcs::diff` finds the secrets path; the
completion is rejected. Task stays `Running`; planner must
revert D and resubmit.

---

## §8 — Operator certificates (INV-CERT-*)

Canonical home: `v1/kernel-core.md` §4.8 (cross-cutting cert
invariants); `v1/kernel-store.md` §2.5.9 (operator certificates);
`v1/philosophy.md` §1.2 (must-pass list).

### INV-CERT-01 — Cert is mandatory for every operator entry

**Statement.** Every `[[operators.entries]]` block in any policy
bundle the kernel will accept carries a self-signed
`[operators.entries.cert]` sub-table. There is no legacy
bare-pubkey path. Enforced at: `raxis_policy::loader` (serde
rejects `missing field "cert"` before the bundle is
constructed); `raxis_genesis_tools::render_genesis_policy_toml`
(the canonical emitter unconditionally writes the cert sub-table);
`raxis_kernel::bootstrap` (the kernel-side `RAXIS_BOOTSTRAP=1`
path uses the same emitter); `raxis_store::operator_certificates::repopulate`
(one row per operator entry on every successful epoch advance);
`raxis_cli::commands::doctor::check_operator_certs` (an empty
`operator_certificates` table after a successful advance is a
structural impossibility and surfaces as `[FAIL]`).

**Justification.** Operator authority is the kernel's single
authoritative root-of-trust. A cert-less entry would have no
recoverable display name (audit chain can't say *who* approved a
plan), no expiry (a leaked key never auto-fails-closed), and no
declared `permitted_ops` (ambient authority defeats the
least-privilege model behind the four-zone gate). Pushing the
detection of a missing cert to the loader makes the absence
unforgeable: the bundle never reaches the rest of the kernel.

**Scenario.** An operator hand-edits `policy.toml` to remove
the `[operators.entries.cert]` sub-table and re-signs with their
key. `policy_load` fails with `serde: missing field "cert" for
operators.entries[0]`; the kernel refuses to advance the epoch;
`raxis doctor` (which reads `operator_certificates` directly via
WAL) prints `[FAIL] cert.list: no operator certificates installed
(INV-CERT-01)` and exits non-zero.

---

### INV-CERT-02 — Self-signature is unbypassable

**Statement.** Every cert the kernel accepts has been verified to
be self-signed by the Ed25519 key whose public hex equals
`cert.pubkey_hex`. Enforced at:
`raxis_crypto::cert::verify_cert_self_signature` (cryptographic
check); `raxis_policy::bundle::validate_operator_certs` (called
on every policy load — there is **no** `--force-misconfig` bypass
for this check); `raxis_cli::commands::cert::run` (every install
path verifies before splicing); `raxis_cli::commands::genesis::run`
(both `--operator-cert` and `--operator-key` paths verify before
embedding).

**Justification.** A cert is the operator's claim about their own
pubkey, validity window, and permitted ops. If the self-signature
could be forged or skipped, an attacker who controlled the policy
file could reissue an arbitrary cert bearing the victim
operator's pubkey and grant themselves any `permitted_ops` they
liked. Pinning self-signature verification as the **only**
unbypassable cert invariant (structural failures are bypassable
via `--force-misconfig`) keeps the cryptographic anchor solid
even when operators need to ship partially-misconfigured certs in
emergencies.

**Scenario.** An attacker with write access to `policy.toml`
copies a victim operator's cert, changes `permitted_ops` to add
`RotateEpoch`, and re-bumps the file. `validate_operator_certs`
recomputes the canonical cert bytes, runs `Verify` against the
edited cert's `self_sig_hex` field, and rejects the load with
`OperatorCertSelfSigInvalid`. No `--force-misconfig` flag relaxes
this check.

---

### INV-CERT-03 — Operator private key is never persisted

**Statement.** No CLI command ever writes operator private-key
bytes to `<data_dir>` or any other persistent location. Private
keys are read into process memory exclusively for in-process
`sign_cert` / `sign_policy` calls, then dropped. The kernel
itself never sees the operator private key on any path.

**Justification.** The operator key is the apex of the trust
chain — losing it means losing the ability to sign new policy
bundles and (worse) means an attacker who exfiltrates the data
directory could mint policy bundles indistinguishable from the
legitimate operator. Refusing to write private bytes anywhere
the kernel manages keeps the blast radius of a `<data_dir>`
compromise bounded to "attacker can read public keys, certs, and
audit log."

**Scenario.** A misconfigured backup tool snapshots `<data_dir>`
to an off-host destination. Even if the snapshot leaks publicly,
the operator's private key is not in it; the attacker cannot
sign a fresh policy bundle, cannot mint an `OperatorCert` bound
to the operator's pubkey (cert self-signature would not verify
against any key the attacker controls), and the kernel will
refuse any policy load whose `operator_signature_hex` was not
produced by the legitimate operator key. The CLI test
`run_genesis_with_operator_key_mints_cert_and_does_not_persist_private_bytes`
asserts this invariant by recursive seed-leakage scan over
`<data_dir>` after `genesis` completes.

---

### INV-CERT-04 — Cert rotation pubkey continuity

**Statement.** When `raxis cert install --replace-for <fp>
--new-cert <path>` rotates a cert, the new cert's `pubkey_hex`
MUST equal the old cert's `pubkey_hex`. A pubkey change is a
different operator entirely and goes through `policy sign` +
`epoch advance` instead. There is no `--force-misconfig` bypass
for this check.

**Justification.** "Cert rotation" semantically means *the same
operator extending their identity* — new validity window,
possibly trimmed `permitted_ops`, possibly a new display name.
Allowing the pubkey to change under a rotation would let an
attacker (or careless operator) silently swap one operator for
another while the audit chain reads "rotation, not new operator,"
obscuring the change of authority. Pinning pubkey continuity
makes the audit chain's rotation walk unambiguous.

**Scenario.** An operator wants to "rotate" Chika's cert to
Jinanwa's key. `cert install --replace-for <chika-fp> --new-cert
jinanwa.cert.toml` rejects with `OperatorCertPubkeyMismatch` before
splicing; the operator must instead remove Chika's entry, add
Jinanwa's entry, re-sign the policy, and advance the epoch — all of
which produce loud audit events (`OperatorCertInstalled` for Jinanwa
with no `previous_fingerprint`, not a rotation rollup).

---

### INV-CERT-05 — Audit chain captures every cert event

**Statement.** Every state transition involving an operator cert
produces an audit event on the chain — install, rotation,
structural bypass, expiry-window crossing, expired-op denial,
emergency use. Per-event granularity, not per-policy-load
rollups. Enforced at:
`raxis_kernel::ipc::operator::emit_cert_chain_mirror` (called from
epoch-advance dispatch; emits `OperatorCertInstalled` per cert
with `previous_fingerprint` populated when the prior bundle held
a cert for the same pubkey, plus `OperatorCertMisconfigBypassed`
per `force_misconfig_bypass = true` entry); `CertEnforcer` (emits
`OperatorCertExpiringSoon` deduplicated per `(fp, day)`,
`OperatorCertExpiredOpDenied` per denied op,
`EmergencyOperatorUsed` per emergency-cert op).

**Justification.** The audit chain is the kernel's single source
of forensic truth. If a cert event went unrecorded, an
investigator could not reconstruct who held authority at any
historical moment. Emitting per-event keeps the granularity
high enough to answer "did Chika's cert grant permission to
*this specific approval*?" rather than just "was Chika's cert
installed at any point?". The `previous_fingerprint` field on
`OperatorCertInstalled` makes rotations unambiguously traceable
end-to-end.

**Scenario.** An investigator pulls the audit chain six months
later and asks "who was the active Chika cert at timestamp T?"
They `grep OperatorCertInstalled` for Chika's pubkey, sort by
audit chain index, walk the `previous_fingerprint` chain forward
to T, and arrive at exactly one cert fingerprint — the one in
force at that moment. No combination of (no-op rotations,
structural bypass, expiry crossings, emergency uses) is
invisible to this walk.

---

## §9 — How invariants combine (composition map)

Most security properties at the system level are emergent from
**combinations** of invariants. The most consequential combinations:

| Combined property | Component invariants |
|---|---|
| **Operator authority is forensically traceable** | INV-04 (audit log integrity) + INV-CERT-05 (per-event cert chain) + INV-CERT-04 (rotation pubkey continuity) |
| **Operator authority is cryptographically anchored** | INV-CERT-01 (cert mandatory) + INV-CERT-02 (self-signature unbypassable) + INV-CERT-03 (private key not persisted) |
| **Planner cannot influence its own scope** | INV-INIT-01 (no task creation) + INV-INIT-06 (plan immutable) + INV-07 (kernel-derived claims) + INV-SCHED-01 (admit only at approval) |
| **Path scope is enforced at every step** | INV-TASK-PATH-01 (admission) + INV-TASK-PATH-02 (completion) + INV-07 (claim derivation) |
| **Recovery is deterministic from durable state** | INV-05 (reproducibility) + INV-INIT-08 (gate progress recoverable) + INV-INIT-05 (BlockedRecoveryPending requires operator) + INV-STORE-01/02 (atomic transactions) |
| **Budget enforcement cannot be bypassed** | INV-02A (kernel-priced inference) + INV-02B (no direct egress) + INV-INIT-09 (no auto-deadline; budget bounds runtime) |
| **Approval is real, scoped, single-use** | INV-06 (approval gate) + INV-ESC-01..05 (FSM, epoch, session, nonce, scope) |
| **Policy advance never partial** | INV-POLICY-01 (advance phasing) + INV-STORE-01/02 (single-transaction multi-table) |

When auditing a code path, look for which combination of invariants
governs it; a single invariant in isolation rarely tells the full
story.

---

## §10 — When this file is wrong

This file is a navigational consolidation. The canonical homes
(noted on each entry) are the normative authority. If this file
disagrees with the canonical home — wording, scope, exception
list — the canonical home wins, and the divergence is a doc bug
that should be fixed by editing this file.

The agreed protocol when adding a new `INV-*`:

1. Write the normative statement in the appropriate canonical home
   (`philosophy.md` for top-level, the relevant module spec for
   domain-prefixed).
2. Add an entry to this file with statement, justification,
   scenario, canonical-home crossref.
3. Add the invariant ID to §1's table-of-contents row count and to
   any relevant §9 composition row.
4. If the invariant is enforced by code, leave a `// INV-XXX` or
   spec crossref comment at the enforcement site.

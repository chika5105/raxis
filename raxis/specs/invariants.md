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
>   (operator certificates), `CONVERGENCE` (multi-agent
>   non-convergence bounds — V2).
>
> **V2 invariant consolidation status.** This file currently
> consolidates V1 invariants in full and is being incrementally
> expanded to include V2 invariants. Mirrored so far:
> `INV-CONVERGENCE-*` (§9), `INV-PLANNER-HARNESS-01..06` (§10),
> `INV-VERIFIER-*` (§11), `INV-ENV-01` (§11.5),
> `INV-AUDIT-PAIRED-01..07` (§11.6). V2 invariants in their canonical
> homes that have NOT yet been mirrored here include:
> `INV-VM-CAP-01..05`, `INV-PUSH-01..05`, `INV-KEY-01..08`,
> `INV-MERGE-WORKTREE-RETAIN`, `INV-MERGE-CONSISTENCY`,
> `INV-CAPACITY-01..06`, `INV-PROVIDER-01..10`,
> `INV-LIFECYCLE-01..07`, `INV-CRED-KERNEL-01`, `INV-SECRET-01..05`
> (canonical home: `v2/secrets-model.md`), `INV-DELEGATE-01`,
> `INV-DISPATCH`, `INV-RUNTIME-CLASSIFICATION` (§12 of this file per
> the V1 numbering, slated to become INV-09),
> `INV-ELASTIC-01..07` (canonical home: `v2/elastic-vm-scaling.md`).
>
> **DEPRECATED in V2 (do NOT mirror; will be removed entirely in V3):**
> `INV-EGRESS-01` (kernel-mediated egress allowlist; superseded by
> two-tier model in `vm-network-isolation.md` + `credential-proxy.md`),
> `INV-EGRESS-INTENT-01` (`require_intent` plan field; superseded by
> credential-proxy declarations per §3.5 of `credential-proxy.md`).
>
> New PRs adding any of these to their canonical home should also
> add an entry here following the pattern in §9–§11.

---

## Table of contents

| Domain | IDs | Count |
|---|---|---|
| Top-level (must-pass) — V1 | INV-01, INV-02A, INV-02B, INV-03, INV-04, INV-05, INV-06, INV-07, INV-08 | 9 |
| Initiative & task FSM — V1 | INV-INIT-01..11 | 11 |
| Escalation — V1 | INV-ESC-01..06 | 6 |
| Kernel store — V1 | INV-STORE-01..03 | 3 |
| Policy epochs — V1 | INV-POLICY-01 | 1 |
| Scheduler — V1 | INV-SCHED-01 | 1 |
| VCS path enforcement — V1 | INV-TASK-PATH-01, INV-TASK-PATH-02 | 2 |
| Operator certificates — V1 | INV-CERT-01..05 | 5 |
| Convergence — V2 | INV-CONVERGENCE-01..06 | 6 |
| Planner harness — V2 | INV-PLANNER-HARNESS-01..06 | 6 |
| Verifier processes — V2 | INV-VERIFIER-01..15 | 15 |
| Environment binding — V2 | INV-ENV-01 | 1 |
| Paired audit writes — V2 | INV-AUDIT-PAIRED-01..07 | 7 |
| **Total** | | **71** |

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
no planner-supplied field reaches `reserve_budget_in_tx`.

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
`raxis verify-chain` re-walks the chain, computes the hash of
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

**Post-admission read discipline (V2 strengthening).** Once an
initiative has been admitted, the kernel reads plan-derived data
**exclusively from its internal content-addressed store** (the
`plan_bundles` and `plan_bundle_artifacts` tables in V2; the V1
`signed_plan_artifacts` table for legacy initiatives). The host
filesystem is **NEVER** consulted for plan files after admission —
not by `approve_plan`, not by KSB rendering, not by crash recovery,
and not by audit-chain replay. Mutating, renaming, or deleting the
operator's on-disk plan working tree after submission has zero
effect on kernel behaviour for any initiative derived from it.

**Justification.** The operator's signature on the plan covers a
specific snapshot of work. If the plan could be edited
post-approval, the signature no longer authenticates the executing
plan — the operator's authority would be retroactively transferred
to whoever made the edit. The post-admission read discipline above
closes the residual TOCTOU window between admission and any later
read: in V2, "admission" is the last moment the host filesystem
matters for an initiative.

**Technical enforcement mechanism (V2).** The strengthened post-
admission read discipline is enforced by **Plan Bundle Sealing**
(`v2/plan-bundle-sealing.md`). The CLI bundles `plan.toml` plus all
transitively-referenced host-side artifacts into a canonical byte
array, signs the bundle hash atomically with submission, and the
kernel seals the bundle bytes into SQLite at admission time. The
sole API by which initiative-execution code accesses plan-derived
bytes is `raxis-kernel::store::plan_bundle::read_artifact`, which
reads exclusively from the sealed store. Code paths that construct
host paths from plan-derived data after admission are a spec
violation.

**Scenario.** A planner attempts to add a new task to an in-flight
initiative by re-submitting the plan. The store rejects because
the initiative's `plan_bundle_sha256` is set and never updated; the
only way forward is `create_initiative` with a new `initiative_id`,
then `approve_plan` against the new bundle. Separately, an attacker
who gains write access to the operator's plan directory after
submission cannot influence the executing initiative — the kernel
no longer reads from that directory and the bundle bytes in SQLite
are signature-protected.

**Canonical home.** `v2/plan-bundle-sealing.md`.

---

### INV-PLAN-BUNDLE-FRESH — Signed plan bundles are admitted at most once and only inside their freshness window

**Statement.** A plan bundle whose `bundle_nonce` already appears in
`plan_bundle_nonces_seen` with `outcome ∈ {Admitted,
TerminallyRejected}` MUST be rejected with `FAIL_PLAN_BUNDLE_REPLAY`
regardless of signature validity, key trust state, or policy
admissibility. A plan bundle whose `signed_at_unix_secs` falls
outside `[now() - max_plan_bundle_age_secs, now() +
max_clock_skew_secs]` MUST be rejected with `FAIL_PLAN_BUNDLE_EXPIRED`
or `FAIL_PLAN_BUNDLE_FROM_FUTURE` respectively, before the kernel
runs the policy admission chain. The freshness window and the nonce
fence operate as floors that compose with — but do not depend on —
key revocation. The replay/freshness check executes inside the same
`BEGIN IMMEDIATE` transaction as the admission decision and the
nonce-row INSERT, so concurrent re-submission of the same signed
bytes cannot race past the check.

**Justification.** Before V2.1, the only protection against an
adversary replaying a previously-signed plan bundle was the eventual
revocation of the operator's signing key. That window can be
arbitrarily long: an attacker who exfiltrates a signed bundle (from
`<data_dir>/plan_bundles/`, a CI cache, a forensic image, a
supply-chain compromise of the operator's local toolchain) can
re-submit it at any later moment under the still-valid signing key
and obtain a fresh `initiative_id` for replayed work. Compromise-class
key revocation (`key-revocation.md §6`) closes this once detected,
but until detection the attacker has unlimited admit attempts. A
signed-into-the-envelope timestamp + nonce closes the window before
detection: the operator's signature commits to both, so an adversary
cannot re-stamp the bundle forward without the private key. The
storage cost of nonce state is bounded by the freshness window plus
a sweep grace; nonces older than this are inert and can be reaped
because the freshness check rejects them on its own.

**Scenario.** Operator signs plan P at 09:00 with
`max_plan_bundle_age_secs = 86_400`. P is admitted, runs, completes
at 11:00. An attacker exfiltrates the signed bundle bytes that
afternoon and resubmits them at 09:30 the next morning (24h30m after
signing). Step 10a fires: `now() - signed_at_unix_secs = 88_200 >
86_400`; rejected with `FAIL_PLAN_BUNDLE_EXPIRED`. Even if the
attacker had submitted at 14:00 the same day (still within the
window), step 10b finds the nonce already in
`plan_bundle_nonces_seen` with `outcome = 'Admitted'` and rejects
with `FAIL_PLAN_BUNDLE_REPLAY`, attaching the prior `initiative_id`
to the failure detail so the operator can immediately distinguish
the replay from a benign re-submission after a lost CLI ack.

**Canonical home.** `v2/plan-bundle-sealing.md` §3.5, §8.1
step 10a/10b.

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

## §9 — Convergence (INV-CONVERGENCE-*)

Canonical home: `v2/agent-disagreement.md` §8. These invariants bound
multi-agent non-convergence — review-rejection loops, circular
revision attempts, wall-clock runaway, and the abandoned-worktree
lifecycle that follows a non-converging task. They were introduced
because V2's hierarchical orchestration (Orchestrator / Executor /
Reviewer) creates failure modes V1 did not have: agents that
disagree without ever converging, consuming budget and disk until
something coarse fires.

### INV-CONVERGENCE-01 — Review round cap enforcement

**Statement.** A task whose `review_rounds_consumed` equals or
exceeds its configured `max_review_rounds` MUST NOT admit further
`CompleteTask` intents from any Executor session for that task
until the resulting escalation is resolved (by extending rounds,
abandoning the task, or force-admitting the latest commit), the
task fails (per `on_max_rounds = "fail_task"`), or the operator
reopens the task with a fresh round count via `raxis task reopen`.

**Justification.** Without a round cap, a Reviewer-rejection loop
can run dozens of revisions before the per-task token budget
exhausts — operators pay for many rounds of unproductive work and
the audit log fills with repeated content. The round cap fires
earlier in the loop's lifetime regardless of per-round cost.
Token budgets bound "expected total work"; round caps bound
"expected iteration depth." Both are needed because per-round cost
varies wildly (a 50-token critique vs. a 20K-token full-rewrite are
both "one round").

**Scenario.** Plan declares `max_rounds = 3` and `on_max_rounds = "escalate"`
for task T. Executor submits commits A, B, C; Reviewer rejects all
three. On the Executor's attempt to submit commit D, the kernel
rejects with `FAIL_REVIEW_LOOP_EXCEEDED` and auto-creates a
`ReviewLoopExceeded` escalation. The Executor session blocks; the
operator (or Orchestrator if `orchestrator_first` routing is in
effect) decides whether to extend rounds, abandon, or force-admit.

**Canonical home.** `v2/agent-disagreement.md` §3.

---

### INV-CONVERGENCE-02 — Circular revision rejection

**Statement.** A `CompleteTask` whose computed `diff_hash =
sha256(diff_bytes)` matches a row in `task_completed_diffs` for
the same `task_id` with `outcome = 'Rejected'` MUST be rejected
with `FAIL_CIRCULAR_REVISION` regardless of remaining budget,
remaining review rounds, or other authority state. The rejection
is non-negotiable; even an Orchestrator's `ResolveSubEscalation`
cannot grant authority to bypass it. To bypass, the operator must
explicitly remove the rejected diff hash via `raxis task
clear-circular-history <task_id>`, which is itself audited.

**Justification.** A pathological self-loop — Executor produces
the same diff repeatedly expecting different acceptance — burns
budget without progress. Exact-hash detection is cheap (sha256 of
diff bytes is already computed for path-allowlist enforcement),
unambiguous (no false positives), and auditable (the matching
prior submission is identifiable). The non-bypassable nature is
load-bearing: if Orchestrators could grant "permission to retry
the same diff," circular detection would be defeated by the same
LLM that produced the loop in the first place.

**Scenario.** Executor submits `CompleteTask` with `head = X`;
Reviewer rejects. Executor "fixes" by rewriting unchanged code
and submits `CompleteTask` with `head = Y` whose diff against the
task base is byte-identical to the diff for `X`. The kernel
computes `diff_hash(Y) == diff_hash(X)`, finds the row marked
`Rejected`, and rejects with `FAIL_CIRCULAR_REVISION` before the
intent admits. Worktree is preserved for forensics; the configured
`on_circular` behavior fires.

**Canonical home.** `v2/agent-disagreement.md` §4.

---

### INV-CONVERGENCE-03 — Wall-clock enforcement

**Statement.** A task whose `unblocked_elapsed_ms` equals or
exceeds its configured `wall_clock_limit_ms` MUST trigger the
configured `wall_clock_behavior` on the next intent admission
attempt for that task. The kernel does NOT use real-time alarms;
enforcement is on the next admission attempt, with granularity
bounded by intent submission frequency. Time spent in `Blocked(*)`
states does not count toward `unblocked_elapsed_ms` (escalation
resolution latency is dominated by human response time and would
auto-fail every escalating task otherwise).

**Justification.** Wall-clock budgets are the operator's hedge
against tasks that consume real-world time (e.g., slow external
verifiers, accumulated 30-minute pauses) without advancing token
budgets. Real-time alarms would require a separate kernel event
loop interacting with task FSMs mid-flight, expanding the kernel's
concurrency surface; admission-time enforcement is sufficient
because tasks cannot make external state changes without admitted
intents anyway.

**Scenario.** Plan declares `wall_clock_limit = "2h"` for task T.
Executor works for 1h45m of active time, hits an escalation that
takes the operator 4h to respond to, then resumes. On the next
intent admission, the kernel checks: `unblocked_elapsed_ms` =
1h45m (escalation pause excluded) — still under limit. Executor
works for another 30m of active time; on the next intent attempt,
`unblocked_elapsed_ms` = 2h15m, exceeds limit; kernel rejects with
`FAIL_WALL_CLOCK_LIMIT_EXCEEDED` and fires `wall_clock_behavior`.

**Canonical home.** `v2/agent-disagreement.md` §5.

---

### INV-CONVERGENCE-04 — Orchestrator resolution bounded by authority

**Statement.** An Orchestrator's `ResolveSubEscalation` intent MUST
be admitted only if the proposed resolution falls within the
Orchestrator's own delegated authority at admission time. The
Orchestrator MUST NOT grant any authority it does not itself hold.
Specifically: budget extensions cannot exceed the Orchestrator's
remaining budget; wall-clock extensions cannot exceed the
Orchestrator's remaining wall-clock budget; agent replacements
require `can_replace_agents = true` in the Orchestrator's
plan-declared scope.

**Justification.** This preserves `R-4` (Authority Hierarchy):
sub-artifacts can only narrow parent authority. Routing
escalations to the Orchestrator first is an efficiency
optimization, not an authority expansion — the Orchestrator's
decisions remain bounded by the operator-signed plan. If an
Orchestrator could grant escalation extensions exceeding its own
budget, the operator's declared budgets become advisory rather
than enforced.

**Scenario.** Orchestrator O has a remaining token budget of
50K. Executor E hits a per-task token limit and escalates;
routing is `orchestrator_first`. Orchestrator submits
`ResolveSubEscalation { resolution: ExtendBudget { additional_tokens: 100_000 } }`.
Kernel rejects: 100K extension exceeds Orchestrator's own 50K
remaining. Orchestrator must either grant ≤ 50K (which the
kernel deducts from its own budget) or `EscalateUpward` for the
operator to grant a larger amount.

**Canonical home.** `v2/agent-disagreement.md` §6.3.

---

### INV-CONVERGENCE-05 — Abandoned worktree retention

**Statement.** A task's worktree, after the task transitions to
`Failed`, MUST be retained for at least `salvage_window` (allowing
operator salvage) and SHOULD be retained for
`abandoned_commits_retention` total (allowing forensic
inspection). The disk watchdog (`host-capacity.md` §7) MUST NOT
auto-purge abandoned worktrees during the salvage window; if disk
pressure requires reclaiming abandoned-worktree space inside the
window, the operator must explicitly force purge via `raxis
worktree purge --force <task_id>`. Forced purge is audited.

**Justification.** Abandoned commits are a forensic resource: they
record the agent's last work product before non-convergence, often
including partial fixes the operator can salvage. Auto-purging
under disk pressure would silently destroy this record at the
moment it is most likely to be needed (an active disagreement
loop is exactly when the operator wants to inspect what happened).
The interaction with `INV-CAPACITY-02` is intentional: the disk
watchdog's `halt_admit` default fails closed on new intents
rather than purging forensic data.

**Scenario.** Task T fails after a wall-clock-limit escalation;
worktree enters `AbandonedSalvageable` with a 7-day window. Disk
fills four days later; watchdog fires `halt_admit`. Operator runs
`raxis worktree abandoned`, sees T's worktree is 800MB of the
remaining pressure, decides the abandoned commits are not worth
preserving, runs `raxis worktree purge --force <T>`. The forced
purge audits as `WorktreeForciblyPurgedDuringSalvage` so the
forensic gap is explicit and attributable.

**Canonical home.** `v2/agent-disagreement.md` §7.

---

### INV-CONVERGENCE-06 — Routing authority preservation

**Statement.** An escalation's effective resolution authority MUST
trace through every routing level recorded in `routing_history`.
An Orchestrator that resolves an escalation cannot grant authority
that the operator's signed policy does not allow; an operator that
resolves an escalation cannot grant authority exceeding their own
role per `policy.toml`. The kernel re-validates the resolution
authority at the moment of resolution admission, not at routing
time.

**Justification.** Two-tier escalation routing introduces a window
between routing-time and resolution-time during which the
Orchestrator's or operator's authority may have changed (policy
epoch advance, cert rotation, key revocation). Re-validation at
resolution time guarantees the resolution reflects current
authority, not stale authority captured at routing. This is the
escalation-routing analogue of `INV-ESC-02` (epoch-mismatch
rejection of approval tokens).

**Scenario.** Orchestrator O is delegated 100K tokens at plan
approval. An Executor escalates a budget extension; the kernel
routes to O. Before O resolves, the operator advances the policy
epoch, narrowing O's plan-declared authority to 20K. O submits
`ResolveSubEscalation { ExtendBudget { 50_000 } }`. Kernel
re-validates O's current authority (20K), finds the resolution
exceeds it, and rejects. O must `EscalateUpward` for the operator
to grant a larger extension. The new policy epoch is honored, not
the stale routing-time snapshot.

**Canonical home.** `v2/agent-disagreement.md` §6.3, §8.

---

## §10 — Planner Harness (INV-PLANNER-HARNESS-*)

Canonical home: `v2/planner-harness.md` §4–§5, §13. These invariants
constrain the planner's tool surface (per role), the source and
integrity of the Reviewer's VM image, and the in-VM
backgrounded-process containment substrate. They were introduced
because V2 leverages claw-code-derived planner machinery (which
is generic across roles) inside a kernel-mediated multi-role
architecture (Orchestrator, Executor, Reviewer) that must
structurally prevent the Reviewer role from executing code or
running shells under any circumstances.

### INV-PLANNER-HARNESS-01 — Reviewer code execution prohibition

**Statement.** A Reviewer-role planner session MUST NOT have access to
any code-execution primitive: no shell (`bash`, `sh`, `dash`, `zsh`,
busybox sh), no language runtime (`node`, `python`, `ruby`, `perl`,
`lua`), no compiler (`rustc`, `gcc`, `clang`, `tsc`, `go`), no LSP
server (`rust-analyzer`, `pyright`, `tsserver`, etc.), no package
manager (`npm`, `cargo`, `pip`, `gem`), no git binary, no network
utility (`curl`, `wget`, `ssh`). Enforcement is three-layered:
(a) Reviewer image content (the kernel-bundled `raxis-reviewer-core`
contains none of these binaries — `raxis doctor` verifies absence
on every install per `system-requirements.md §11`); (b) harness
build (the Reviewer build target of `raxis-planner` excludes the
`bash` claw-code module at link time); (c) kernel dispatch matrix
(intents that would route to shell-execution paths are rejected
when the session role is `Reviewer`).

**Plan-side authoring corollary.** The Reviewer's tool-execution
prohibition extends to the plan-side authoring surface: any plan
field whose semantics presuppose a capability the Reviewer lacks is
structurally meaningless on a Reviewer task and MUST be rejected at
admission, never silently stripped. The V2 enumeration of forbidden
fields on Reviewer tasks:

- **`[plan.tasks.<id>] vm_image`** (and any image-specifying field) —
  rejected with `FAIL_REVIEWER_VM_IMAGE_NOT_ALLOWED` per
  `INV-PLANNER-HARNESS-02`.
- **`[[profiles.<name>.custom_tool]]` blocks** on a Reviewer-rooted
  profile-inheritance chain — rejected with
  `FAIL_REVIEWER_CUSTOM_TOOL_NOT_ALLOWED` per `INV-PLANNER-HARNESS-04`.
- **`[plan.tasks.<id>] path_allowlist`** (any value, including the
  empty array `[]`) — the Reviewer's `/workspace` is mounted
  read-only and the harness has no commit-pathway intent
  (`SingleCommit`, `IntegrationMerge`, `edit_file`, `bash`); the
  field is structurally meaningless. Rejected with
  `FAIL_REVIEWER_PATH_ALLOWLIST_NOT_ALLOWED` per
  `policy-plan-authority.md §3b`. `raxis-cli plan prepare` surfaces
  the same hard-refusal pre-signing per `operator-ergonomics.md
  §4.5.5`.

The kernel never silently mutates an operator-signed plan; the
operator owns every byte they sign, including bytes that turn out to
be structurally invalid. Future V2.x additions to this enumeration
MUST follow the same discipline (document why the field is
structurally meaningless on a Reviewer task; add the corresponding
`FAIL_REVIEWER_*` admission code in `policy-plan-authority.md §3b`;
extend `plan prepare`'s §4.5 surface in `operator-ergonomics.md` to
surface the rejection pre-signing; update this corollary).

**Justification.** A Reviewer that can execute code can be
deterministically compromised by the code it is reviewing — a
malicious `build.rs`, a malicious `setup.py`, a malicious LSP
extension. The blast radius is bounded by the VM (no host
escape), but the LLM-side impact is catastrophic: a compromised
LSP can poison symbol-resolution responses, omit malicious
caller references from `find_references`, etc., causing the
Reviewer LLM to approve genuinely malicious changes. The
defense is structural: remove the tools entirely so no tool
can be compromised. Code-running verification of the changes
under review is performed instead by Kernel-spawned verifier
VMs (`INV-VERIFIER-*`), whose outputs reach the Reviewer via
the audit-bound `verifier_witnesses` KSB block.

The plan-side authoring corollary closes a parallel category of
silent-failure modes: an operator who declares a `path_allowlist`
on a Reviewer task is reasoning about a Reviewer that can write —
which contradicts the runtime invariant. Failing admission loud is
the structural feedback that the operator's mental model is wrong;
silently stripping the field would let the operator continue
reasoning incorrectly. Same logic applies to `vm_image` and custom
tools.

**Scenario.** A malicious Executor commits a Cargo crate with a
`build.rs` that, when invoked by `rust-analyzer`, exfiltrates
its arguments to a remote endpoint. Under V1, a Reviewer with
LSP access would invoke `rust-analyzer` on the project as part
of opening it, executing `build.rs`. Under V2, the Reviewer's
image lacks `rust-analyzer`, lacks `cargo`, lacks any binary
that would invoke `build.rs`. The malicious code never executes
in the Reviewer's VM. Code-running verification is delegated to
a verifier VM (operator-published) where the same malicious
`build.rs` runs under cgroup containment with no access to
Reviewer or other planner state.

**Canonical home.** `v2/planner-harness.md` §4.4.

---

### INV-PLANNER-HARNESS-02 — Reviewer image is kernel-owned

**Statement.** The VM image used for any Reviewer-role task is the
kernel-bundled `raxis-reviewer-core` image. Operators MUST NOT
specify the image in `plan.toml`; any `vm_image` (or equivalent)
field on a Reviewer task is rejected at `approve_plan` with
`FAIL_REVIEWER_VM_IMAGE_NOT_ALLOWED`. The kernel-bundled image
is a single OCI image bundle shipped at
`$RAXIS_INSTALL_DIR/images/raxis-reviewer-core-<kernel_version>.img`;
the kernel binary contains a compiled-in SHA-256 of the image bytes.
At every Reviewer activation, the kernel re-computes the on-disk
digest and refuses to boot the VM with `FAIL_REVIEWER_IMAGE_DIGEST_MISMATCH`
on any mismatch (with `SecurityViolationDetected` audit emission).

**Justification.** Allowing operator-specified Reviewer images
introduces supply-chain risk (a tampered image with a
compromised `grep` or `libc` could selectively hide malicious
strings from the Reviewer LLM's `grep_search`) AND mental burden
(operators maintaining an image for a role that does not even
use user-space tools beyond the planner binary). Kernel-bundled
+ digest-verified is the smallest possible trusted computing
base for the ultimate security gate.

**Scenario.** An attacker with operator-host filesystem write
access (e.g., partial compromise of a CI runner that builds RAXIS
images) replaces `raxis-reviewer-core-2.0.0.img` with a tampered
build that includes a modified `ripgrep` whose output omits
matches against pattern `password`. On the next Reviewer
activation, the kernel re-computes SHA-256 of the on-disk file,
finds it does not match the kernel-binary's compiled-in expected
digest, and aborts activation with `FAIL_REVIEWER_IMAGE_DIGEST_MISMATCH`
+ `SecurityViolationDetected { kind: "ReviewerImageDigestMismatch" }`.
The compromised image never runs; the operator is paged to
investigate.

**Canonical home.** `v2/planner-harness.md` §4.5.

---

### INV-PLANNER-HARNESS-03 — In-VM process containment via cgroup v2

**Statement.** Every planner VM (Orchestrator, Executor) AND every
verifier VM (per `INV-VERIFIER-06`) MUST run a Linux 5.14+ guest
kernel with cgroup v2 mounted and `cpu`, `memory`, `pids`
controllers in `cgroup.subtree_control`. The harness's
backgrounded-shell substrate places each background process in a
named sub-cgroup (`/sys/fs/cgroup/raxis/bash-bg-<n>/`); termination
uses `cgroup.kill` (atomic, race-free, reliable against
double-forking daemons). VM stop is the universal reap point
regardless of in-VM cleanup state.

**Justification.** Without cgroup v2 + `cgroup.kill`, the in-VM
backgrounded-shell substrate degrades to walking `/proc` and
sending SIGKILL in a loop — racing against new forks, leaking
double-forked daemons, and generally being unreliable. cgroup v2
provides atomic, race-free termination guarantees that match the
harness's contract with the planner LLM ("when you call `bash
bg_kill`, the process tree IS dead by the time the call returns").
Linux 5.14 (August 2021) is the first kernel version with
`cgroup.kill`; earlier kernels are rejected as a baseline rather
than supporting a fallback path that produces subtly different
behavior.

**Scenario.** A planner LLM invokes `bash run --background "node
dev_server.js"`; node spawns 4 worker subprocesses via
`cluster.fork()`. Later the LLM invokes `bash bg_kill bg_3`. The
harness writes `1` to
`/sys/fs/cgroup/raxis/bash-bg-3/cgroup.kill`; in a single atomic
operation the parent and all 4 workers receive SIGKILL. The
harness verifies by reading `cgroup.events` `populated=0`, then
returns to the LLM. No worker survives, no race window, no
process tree fragmentation.

**Canonical home.** `v2/planner-harness.md` §5.3, §10.2.

---

### INV-PLANNER-HARNESS-04 — Reviewer Custom Tool Prohibition

**Statement.** A profile whose effective role is `Reviewer` MUST NOT
declare any `[[profiles.<name>.custom_tool]]` blocks (directly or via
`inherits_from`-chain ancestor profiles). At plan admission, the
admission stage walks the inheritance graph, computes the effective
custom-tool set for each profile, and rejects with
`FAIL_REVIEWER_CUSTOM_TOOL_NOT_ALLOWED { profile, declaring_profiles:
[...] }` if the effective role is `Reviewer` AND the effective
custom-tool set is non-empty. Custom tools may be declared on any
profile inheriting from `Executor` or `Orchestrator`; the structural
ban applies to Reviewer-rooted inheritance chains only.

**Justification.** A custom tool is, by definition, arbitrary code
execution: a forked subprocess running operator-defined argv with
operator-defined input. This is the exact attack surface that
`INV-PLANNER-HARNESS-01` was designed to eliminate. The kernel-bundled
`raxis-reviewer-core` image (`INV-PLANNER-HARNESS-02`) lacks the
runtimes (no `python3`, `node`, shell, or compilers) that most
operator scripts would require, so most violations would fail at
runtime regardless — but relying on "fails at runtime" produces
partial audit trails, leaks the misconfiguration into a live session,
and surfaces the failure to the LLM mid-loop. Catching the
declaration at admission, with a clear remediation message, is the
correct fail-closed posture.

**Scenario.** An operator authors a `Reviewer`-inheriting profile
`security_reviewer` and adds a `[[profiles.security_reviewer.custom_tool]]`
called `static_analyzer` that runs an internal SAST tool. Plan
admission walks the inheritance chain, sees the effective role is
`Reviewer` and the effective custom-tool set is non-empty, and
rejects with `FAIL_REVIEWER_CUSTOM_TOOL_NOT_ALLOWED`. The remediation
message points the operator to either: (a) declare the analyzer as a
verifier (`verifier-processes.md`), where its output reaches the
Reviewer via `verifier_witnesses` in the KSB and properly gates
review activation per `INV-VERIFIER-04`; or (b) move the tool to an
Executor-inheriting profile if the use case is execution-time, not
review-time.

**Canonical home.** `v2/custom-tools.md` §10.

---

### INV-PLANNER-HARNESS-05 — Canonical Orchestrator Image

**Statement.** A V2 Orchestrator session boots from a kernel-bundled,
kernel-digest-verified image — `raxis-orchestrator-core` — distributed
alongside the kernel binary at
`$RAXIS_INSTALL_DIR/images/raxis-orchestrator-core-<kernel_version>.img`.
The kernel binary contains a compiled-in
`EXPECTED_ORCHESTRATOR_IMAGE_DIGEST: [u8; 32]` (SHA-256). At every
Orchestrator activation, the kernel re-computes the on-disk SHA-256 and
refuses to boot the VM with `FAIL_ORCHESTRATOR_IMAGE_DIGEST_MISMATCH` on
mismatch, emitting `SecurityViolationDetected { kind:
"OrchestratorImageDigestMismatch" }`. Operator-supplied Orchestrator
images are categorically prohibited; `policy.toml`'s `[[vm_images]]`
table rejects any entry whose `role_restriction` contains
`"Orchestrator"` at policy load with
`FAIL_POLICY_INVALID_ROLE_RESTRICTION` (parallel to the Reviewer
treatment in `INV-PLANNER-HARNESS-02`).

**Justification.** The Orchestrator multiplexes the parallel branches
of an initiative — activating ready sub-tasks, semantically resolving
trivial git conflicts (so a forest of import collisions does not become
an operator-escalation flood), and coordinating final merges. To do
this safely, its image must be small, audited, and bound to the same
trust root as the kernel: a `git` binary whose merge output the
Orchestrator trusts, a `bash` whose semantics the harness understands,
a `libc` whose path-handling has not been silently subverted. Allowing
operator-supplied Orchestrator images reintroduces the entire
supply-chain risk class that `INV-PLANNER-HARNESS-02` eliminated for
the Reviewer.

The image is large enough to perform 3-way semantic git merges with
bash + git + edit_file, and nothing more (no language runtimes, no
compilers, no package managers, no curl, no editors, no LSPs). See
`v2/planner-harness.md §10.5` for the full image manifest.

**Scenario.** An attacker with operator-host filesystem write access
replaces `raxis-orchestrator-core-2.0.0.img` with a tampered build
whose `git` binary silently inserts an attacker-controlled commit
during `git merge`. On the next Orchestrator activation, the kernel
re-computes the on-disk SHA-256, finds it does not match
`EXPECTED_ORCHESTRATOR_IMAGE_DIGEST`, and aborts activation with
`FAIL_ORCHESTRATOR_IMAGE_DIGEST_MISMATCH` +
`SecurityViolationDetected { kind: "OrchestratorImageDigestMismatch" }`.
The compromised image never runs; the operator is paged.

**Canonical home.** `v2/planner-harness.md` §4.7.

---

### INV-PLANNER-HARNESS-06 — Orchestrator Is Not Operator-Configurable

**Statement.** The Orchestrator role's complete behavior surface is
kernel-owned and version-locked with the kernel binary. Specifically:

1. **No operator-declared Orchestrator profiles.** `plan.toml` MUST
   NOT contain a profile whose effective role is `Orchestrator` and
   MUST NOT contain a task whose `role` is `"Orchestrator"`. Plan
   admission rejects with `FAIL_ORCHESTRATOR_PROFILE_NOT_ALLOWED` or
   `FAIL_ORCHESTRATOR_TASK_NOT_ALLOWED`. The Orchestrator session is
   auto-created by the kernel at initiative admission.
2. **No `inherits_from = "Orchestrator"`.** Profile inheritance can
   only target operator-extensible role roots, which in V2 is
   exclusively `"Executor"`. Profiles attempting `inherits_from =
   "Reviewer"` or `inherits_from = "Orchestrator"` are rejected at
   admission with `FAIL_PROFILE_ROLE_NOT_CONFIGURABLE`.
3. **No operator-modifiable NNSP.** The Orchestrator's NNSP is
   compiled into the kernel binary as `ORCHESTRATOR_NNSP_BYTES` and is
   version-locked with the Orchestrator image per
   `INV-PLANNER-HARNESS-05`. Operators cannot edit it.
4. **No operator-declared custom tools.** Structural consequence of
   (1) — there is no operator-declared profile to attach custom tools
   to.
5. **No backgrounded `bash`.** The Orchestrator harness build excludes
   `bash run --background` and the `bash bg_*` family; the
   Orchestrator's `bash` is foreground-only.

Operator policy MAY tune three orthogonal knobs in
`policy.toml [orchestrator]`: `provider_alias`,
`max_token_budget_per_initiative`, and `all_merges_require_approval`.
There are no other Orchestrator-tunable controls in V2.

**Justification — the "Invisible Infrastructure" framing.** The
user-facing surface of RAXIS is Executors and tasks. The kernel runs an
Orchestrator underneath to multiplex the DAG, semantically resolve
trivial conflicts, and finalize merges. Operators do not think about
the Orchestrator the same way Kubernetes operators do not think about
the Kubelet — it is part of the runtime, not part of the workload
definition. This produces three concrete properties an
operator-configurable Orchestrator could not: configuration surface
area for the Orchestrator is zero (operators cannot misconfigure what
they cannot configure); behavior consistency across deployments
(every RAXIS deployment running kernel version `X` has byte-identical
Orchestrator behavior); upgrade atomicity (kernel upgrades ship a new
Orchestrator image AND NNSP atomically).

The trade-off operators accept is the loss of operator-specific
prompt instructions, custom Orchestrator images, custom tools, and
long-lived background processes in the Orchestrator session. In
exchange, they get an Orchestrator that just works, plus three
deployment-wide policy knobs for the genuine cases where
deployment-wide constraints need to bind Orchestrator behavior.

**Scenario.** An operator authoring their first plan declares
`[profiles.coordinator]` with `role = "Orchestrator"` and adds custom
fields, expecting V1-style operator-orchestrator tuning. Plan
admission rejects with `FAIL_ORCHESTRATOR_PROFILE_NOT_ALLOWED` and a
remediation message: "The Orchestrator is kernel-managed and not
operator-configurable in V2. Remove the orchestrator profile.
Per-initiative guidance can be added to the initiative description
field, which the Orchestrator reads via its KSB. Deployment-wide
controls are in `policy.toml [orchestrator]`. See
`planner-harness.md §4.8`."

**Canonical home.** `v2/planner-harness.md` §4.8.

---

## §11 — Verifier Processes (INV-VERIFIER-*)

Canonical home: `v2/verifier-processes.md` §13. These invariants
constrain the unified verifier subsystem (no V1/V2 split per
`verifier-processes.md §7` — single `WitnessSubmission` frame,
single `witness_records` schema, single `raxis-verifier` PID-1
binary). Three authoring sources fan into the unified runtime:
policy claim-based gates (`policy.toml [[gates]]`), per-task plan
verifiers (`[[plan.tasks.X.verifiers]]`), and pre-`IntegrationMerge`
plan verifiers (`[[plan.integration_merge_verifiers]]` and
`policy.toml [[integration_merge_verifiers]]`). All three produce
witnesses in the same `witness_records` table; the `hook_kind`
column distinguishes the lifecycle hook at which each witness was
produced.

These invariants exist because the Pure-Static Reviewer decision
(`INV-PLANNER-HARNESS-01`) requires code-running verification to
happen outside the Reviewer's VM in a separate trust domain that
produces structured witness data the Reviewer (or, for pre-merge
verifiers, the Orchestrator and operator) consumes.

### INV-VERIFIER-01 — Witness-only output channel

**Statement.** A verifier VM cannot invoke any commit-pathway
intent (`SingleCommit`, `CompleteTask`, `IntegrationMerge`,
`ActivateSubTask`, `ApprovePlan`, `EgressRequest`). Verifier VMs
have no planner harness, no LLM, no inference; their only
kernel-bound communication is the `WitnessSubmission` frame
(per `verifier-processes.md §7`). Verifier output enters the audit
chain via `witness_records` only.

**Canonical home.** `v2/verifier-processes.md` §13.

---

### INV-VERIFIER-02 — Verifier VM isolation from agent VMs

**Statement.** Verifier VMs share no state with agent VMs
(Orchestrator, Executor, Reviewer); no inter-VM IPC exists. The
only path from verifier output to a Reviewer is the kernel's
KSB injection at Reviewer activation time. The only path from
pre-`IntegrationMerge` verifier output to the Orchestrator is the
`FAIL_INTEGRATION_MERGE_VERIFIER_BLOCKED` admission-failure return
on the Orchestrator's `IntegrationMerge` request (per
`integration-merge.md §4 Check 5d.4`). Verifier VMs cannot be
observed by the Executor whose commit they evaluate, by sibling
Reviewers, or by the Orchestrator (who sees only the failure code,
not the verifier process state).

**Canonical home.** `v2/verifier-processes.md` §13.

---

### INV-VERIFIER-03 — Reviewer activation gated on all per-task verifiers

**Statement.** A Reviewer is activated for a given `evaluation_sha`
ONLY after every plan-declared per-task verifier (per
`verifier-processes.md §15.1` plan-author per-task source) AND every
policy claim-based gate (per `verifier-processes.md §15.2`) for that
task has written a witness with non-NULL `final_status` (`passed`,
`failed`, `timed_out`, `crashed`, or `artifact_missing`). A Reviewer
is NEVER activated with partial witness data. If any per-task
verifier or claim-based gate is still `Pending`, the Reviewer waits.
Pre-`IntegrationMerge` verifiers (per `INV-VERIFIER-13`) do NOT
participate in this gate — they fire at a strictly later lifecycle
hook and the Reviewer has no dependency on them.

**Canonical home.** `v2/verifier-processes.md` §13, §5.2.

---

### INV-VERIFIER-04 — `block_review` failures fail the Executor's task

**Statement.** A verifier with `on_failure = "block_review"`
producing `final_status ≠ "passed"` causes the originating
Executor's `CompleteTask` to be rolled into `Failed` per
`agent-disagreement.md §3`. The Reviewer is not activated. The
Executor receives `FAIL_VERIFIER_BLOCKED` on its next intent. The
failure counts as a review round toward `INV-CONVERGENCE-01`.
`block_review` is the only legal `on_failure` value for the
`CompleteTask`-hooked verifiers (per-task plan verifiers and
implicitly for policy claim-based gates); pre-`IntegrationMerge`
verifiers cannot use `block_review` (per `INV-VERIFIER-13`).

**Canonical home.** `v2/verifier-processes.md` §13, §5.2.

---

### INV-VERIFIER-05 — Declared artifact validation

**Statement.** A verifier's `artifact` declaration MUST be
validated post-success: file MUST exist, be non-empty, and not
exceed `artifact_max_bytes`. Missing, empty, or oversize artifacts
produce `final_status = "artifact_missing"` regardless of the
command's exit code. The kernel does NOT partial-stage or
truncate. This applies uniformly to all three authoring sources.

**Canonical home.** `v2/verifier-processes.md` §13, §6.3.

---

### INV-VERIFIER-06 — Verifier image substrate matches planner

**Statement.** Every verifier VM image MUST satisfy the same VM
guest kernel and cgroup substrate requirements as planner images:
Linux 5.14+ guest kernel; cgroup v2 mounted; `cpu`, `memory`,
`pids` controllers in `cgroup.subtree_control`. `raxis doctor`'s
`vm-images` category enforces this for every operator-published
verifier image referenced by an installed `policy.toml`. The
kernel-bundled verifier images (per `INV-VERIFIER-12` for the
canonical symbol-index image; per `verifier-processes.md §14.5`
for the four tiered language starters) are pre-validated at
release-build time.

**Canonical home.** `v2/verifier-processes.md` §13. Cross-references
`INV-PLANNER-HARNESS-03`.

---

### INV-VERIFIER-07 — Verifier images are operator-published (with one exception)

**Statement.** Verifier VM images are operator-published per
`INV-VM-CAP-03` and policy-pinned by OCI digest, with **one
exception**: the kernel-canonical `raxis-verifier-symbol-index`
image (per `INV-VERIFIER-12`), which is kernel-bundled and
kernel-digest-bound, mirroring the
`INV-PLANNER-HARNESS-02`/`INV-PLANNER-HARNESS-05` exception model
for canonical Reviewer/Orchestrator images. For all other verifier
images — including the four kernel-bundled tiered language starters
(`raxis-verifier-{rust,node,python,go}-starter`) — operators ship
the image, the kernel verifies the on-disk digest matches the
operator's policy-pinned `[[vm_images]] oci_digest`, and the trust
boundary is operator-signed policy. The `role_restriction` field on
`[[vm_images]]` MUST include `Verifier` for any image referenced by
any verifier-source surface (`[[plan.tasks.X.verifiers]].image`,
`[[plan.integration_merge_verifiers]].image`,
`[[integration_merge_verifiers]].image`,
`[default_verifier_images].<lang>`).

**Canonical home.** `v2/verifier-processes.md` §13, §14.

---

### INV-VERIFIER-08 — Verifier VM has no LLM and no harness

**Statement.** Verifier VMs run `raxis-verifier` (a small,
single-purpose command runner) as PID 1. They have NO LLM, NO
inference, NO planner harness, NO `IntentKind` dispatch. No
claw-code module is linked into `raxis-verifier`.

**Justification.** A verifier VM that crashes due to a
programming error in the verifier command cannot escalate the
failure mode — it just produces a `crashed` witness and the
kernel handles per `on_failure`. A planner-harness-equipped
"verifier" would invert this: a malicious or buggy verifier
command could trigger novel intent paths, escalate authority,
or otherwise increase the trust surface of code-running
verification.

**Canonical home.** `v2/verifier-processes.md` §13.

---

### INV-VERIFIER-09 — Verifier mutations do not persist

**Statement.** Verifier VMs have read-write access to `/workspace`
(mounted from a fresh clone of `evaluation_sha`) and `/raxis/`
(for artifact output). All `/workspace` and `/raxis/` mutations
are dropped at VM exit unless declared as `artifact` per §6 of
`verifier-processes.md`. Verifier VMs cannot persist mutations
to the `main_repo` or any session-shared storage.

**Canonical home.** `v2/verifier-processes.md` §13.

---

### INV-VERIFIER-10 — Kernel-enforced timeout via `cgroup.kill`

**Statement.** Verifier timeouts are kernel-enforced via
`cgroup.kill` on the verifier-process cgroup at the declared
`timeout` (or the per-verifier kernel hard cap, whichever is
smaller). Timeout produces `VerifierTimedOut` audit and treats
the verifier as failed per its `on_failure` rule. The kernel
does NOT rely on the verifier's internal timeout handling for
this guarantee.

**Canonical home.** `v2/verifier-processes.md` §13. Cross-references
`INV-PLANNER-HARNESS-03`.

---

### INV-VERIFIER-11 — No network by default

**Statement.** Verifier VMs have NO network interface by default.
Network egress requires explicit `allowed_egress` declaration on
the verifier source (`[[plan.tasks.X.verifiers.allowed_egress]]`,
`[[plan.integration_merge_verifiers.allowed_egress]]`, or
`[[integration_merge_verifiers.allowed_egress]]`), mirroring the
Executor / Orchestrator egress pattern. The default is air-gapped;
verifiers that don't need network do not get one.

**Justification.** Reduces blast radius of a supply-chain
compromise of a verifier image: a compromised image cannot
exfiltrate `evaluation_sha` contents (or, for pre-merge verifiers,
candidate-merge-tree contents) without explicit egress declared.

**Canonical home.** `v2/verifier-processes.md` §13.

---

### INV-VERIFIER-12 — Kernel-canonical symbol-index verifier image

**Statement.** When `policy.toml [prepare] auto_inject_symbol_index
= true` (V2 default per `policy-plan-authority.md §4 [prepare]`),
the symbol-index verifier image auto-injected by `raxis-cli plan
prepare` (per `operator-ergonomics.md §4.2`) MUST be the
kernel-canonical `raxis-verifier-symbol-index` image. The image is
kernel-built, distributed via the kernel release at
`$RAXIS_INSTALL_DIR/images/raxis-verifier-symbol-index-<kernel_version>.img`,
and digest-verified at every spawn against the kernel-binary's
compiled-in `EXPECTED_SYMBOL_INDEX_VERIFIER_IMAGE_DIGEST` (per
`verifier-processes.md §14.4`). The image alias
`"raxis-verifier-symbol-index"` is **reserved at policy load** —
any `[[vm_images]]` entry attempting to use the alias is rejected
with `FAIL_POLICY_RESERVED_VM_IMAGE_NAME` (per
`policy-plan-authority.md §3b`). The reserved alias guarantees
plan-side references resolve unambiguously to the kernel-bundled
image.

**Justification.** The Pure-Static Reviewer (per
`INV-PLANNER-HARNESS-01`) is structurally dependent on a
symbol-index witness for full symbol-resolution fidelity. Operators
forgetting to declare a symbol-index verifier silently degrade the
Reviewer; auto-injection inverts the default. Auto-injection has
authority — the operator's signed plan contains the injected entry
verbatim — but it must reach for a trusted, kernel-bound image
rather than an operator-published image (which would re-introduce
the supply-chain trust gap auto-injection is supposed to close).
The reserved alias prevents an operator from accidentally or
maliciously shadowing the canonical image.

**Operator override.** Operators who want a different
symbol-extraction tool MUST set `policy.toml [prepare]
auto_inject_symbol_index = false` AND declare their own verifier
in their plan with their own image. Per-task suppression is also
available via `[plan.tasks.<id>.review] symbol_index = "not_needed"`
(per `planner-harness.md §4.1`).

**Canonical home.** `v2/verifier-processes.md` §14.

---

### INV-VERIFIER-13 — Pre-IntegrationMerge verifier gating

**Statement.** When the union of `[[plan.integration_merge_verifiers]]`
(plan-side) and `policy.toml [[integration_merge_verifiers]]`
(operator-side) declares at least one verifier whose `applies_to`
filter matches an `IntegrationMerge` request, the kernel MUST
materialize the candidate merged tree (per
`integration-merge.md §11.10`), spawn all matching verifier VMs,
wait for all to complete, and gate `IntegrationMerge` admission on
the result per `integration-merge.md §4 Check 5d`. Main is
advanced ONLY if every matching verifier with `on_failure =
"block_merge"` reports `final_status = "passed"`. Pre-merge
verifier failures with `block_merge` produce
`FAIL_INTEGRATION_MERGE_VERIFIER_BLOCKED` and the candidate merged
tree is discarded.

**Authority asymmetry.** Operator-side declarations
(`[[integration_merge_verifiers]]` in `policy.toml`) MUST set
`on_failure = "block_merge"` — operator-side gates cannot be
downgraded to `warn_only` per `policy-plan-authority.md §4
[[integration_merge_verifiers]]`. Plan-side declarations
(`[[plan.integration_merge_verifiers]]`) MAY set `on_failure =
"block_merge"` or `on_failure = "warn_only"`. `block_review` is
NEVER legal for pre-merge verifiers (per
`policy-plan-authority.md §5 step 3.7`).

**Convergence accounting.** Pre-merge verifier failures do NOT
count toward `INV-CONVERGENCE-01` (review-round cap), because they
fire at `IntegrationMerge` admission — strictly after Reviewer
activation has already accepted the constituent tasks. Operator
escalation per `verifier-processes.md §16.6` is the resolution
path.

**Justification.** Per-task verifiers gate Reviewer activation but
do not see cross-task interactions; pre-merge verifiers gate
main advancement and run against the candidate merged tree, so
they see the integration boundary that per-task verifiers cannot.
This is the operator's mechanism for "regression gating" tests
that should hold at the main frontier, not just at individual
task boundaries. The strict `block_merge` discipline prevents
silent regressions: if a pre-merge gate fails, main does not
advance until either the gate passes or the operator explicitly
escalates.

**Canonical home.** `v2/verifier-processes.md` §15,
`v2/integration-merge.md §4 Check 5d`, §11.10.

---

### INV-VERIFIER-14 — Symbol-index witness provenance

**Statement.** Whenever the kernel-canonical
`raxis-verifier-symbol-index` verifier (per `INV-VERIFIER-12`)
runs, it MUST run against a kernel-provisioned clone of the
evaluation tree. The kernel performs `git clone --shared
--no-checkout main_repo.git` to a fresh path under the
verifier VM's VirtioFS mount and then `git checkout
<evaluation_sha>` inside the verifier VM. The Executor's
worktree is NEVER the substrate for symbol-index verification.

**Justification.** A symbol index that depended on
Executor-provided source bytes would let a malicious or buggy
Executor mis-represent the symbol topology of the changes the
Reviewer is reviewing — the `verifier_witnesses` block in the
Reviewer's KSB carries an authority bound by the audit chain
(`INV-04`); cracking the provenance lets the Executor mint
witnesses against bytes that never traversed `evaluation_sha`'s
content addressing. The kernel-side clone closes that
confused-deputy path: `evaluation_sha → symbol_index` is a pure
function of the commit object, so the symbol index inherits the
same trust budget as the audit chain itself.

**Operational evidence.** The kernel-spawned helper
`verifier_provision_workspace` (in `kernel/src/verifier/spawn.rs`)
emits the audit event
`VerifierWorkspaceProvisioned { evaluation_sha, clone_method:
"kernel_share_no_checkout" }` exactly once before the verifier
VM is started. The forensic auditor verifies provenance by
reading this event from the audit chain — no instrumentation of
the verifier VM is required.

**Canonical home.** `v2/verifier-processes.md` §13
(invariant statement), §16.5 (provisioning step), and the
`kernel/src/verifier/spawn.rs` helper `verifier_provision_workspace`.

---

### INV-VERIFIER-15 — Verifier authenticated egress requires explicit per-image policy opt-in

**Statement.** A verifier VM that declares `allowed_egress`
defaults to **audit-only** mode: outbound requests are logged
but unauthenticated, and credentials from
`[[providers.credentials]]` / `[[permitted_credentials]]` are
NOT injected by the egress proxy. Authenticated egress
requires:

1. A matching `[[verifier_credentials.images]]` entry in
   `policy.toml` whose `image` resolves to the verifier image's
   pinned OCI digest.
2. That entry's `permit_authenticated = true`.
3. The kill-switch `[verifier_credentials].emergency_audit_only
   = false`.

If any of those three conditions fails, every credential
injection attempt against the verifier returns the audit-only
proxy and the resolution is recorded as
`VerifierCredentialModeResolved { image, mode: AuditOnly,
reason }` in the audit chain.

**Justification.** Verifier images are the supply-chain weak
link: unlike Executor images (kernel-provisioned from a known
base), verifier images may be operator-authored,
third-party-authored, or community-maintained. A compromised
verifier image with authenticated egress to a private package
registry could exfiltrate the registry token to an
attacker-controlled package or publish a malicious package
back to the registry; every downstream consumer of that
registry is then compromised. The blast radius is wider than
the equivalent Executor compromise because the verifier sees
EVERY task's `evaluation_sha`. Audit-only-by-default forces
operators to make a deliberate per-image decision about which
verifier images they trust enough to receive real credentials,
and the global kill-switch lets them revert that decision in a
single line during incident response without rewriting per-image
rows.

**Canonical home.** `v2/verifier-processes.md §13` (invariant
statement), `§16.7` (full policy schema, resolution chain,
audit events, V2.0→V2.1 migration story).

---

## §11.5 — Environment Binding (INV-ENV-*)

Canonical home: `v2/environment-access-control.md` §11. These
invariants constrain V2's optional environment-binding compliance
layer. The whole subsystem is **opt-in**: a deployment whose
`policy.toml` declares zero `[environments.<label>]` sections runs
exactly as a V1 deployment does — none of the INV-ENV-* checks fire,
and the rest of the kernel's authority chain operates unchanged. The
invariants below activate the moment the operator's signed policy
declares one or more environments.

The motivation is structural: when a deployment manages multiple
compliance boundaries (beta vs. production, customer-A vs. customer-B,
tenant-X vs. tenant-Y), the kernel needs a mechanically-enforceable
guarantee that no single agent execution context simultaneously holds
credentials and reach across two boundaries. Without that guarantee,
an operator's careful per-task egress allowlists and per-task
credential bindings remain pure-convention — the agent inside the VM
*could* mix credentials and URLs at runtime, and the audit chain
would record the resulting cross-boundary activity as legitimate
("the plan said so"). INV-ENV-01 elevates this from convention to
admission-time invariant.

### INV-ENV-01 — Task Environment Consistency

**Statement.** When the loaded policy declares at least one
`[environments.<label>]` section, every admitted task in every plan
bundle binds to **at most one** environment. The set of environments
a task binds to is computed by walking the task's environment-bound
resources per the `environment-access-control.md §11.3` algorithm
(environment-bound `[[plan.tasks.X.credentials]]` entries plus
`allowed_egress` URLs that match `[[environment_gates]]` labels,
excluding URLs whose conflated environments all declare
`same_cluster_acknowledged = true`). Tasks whose computed set has
more than one element are rejected at `approve_plan` with
`FAIL_TASK_ENVIRONMENT_INCONSISTENT`. Tasks with cardinality 0 are
recorded as environment-neutral and pass trivially. The
`--no-strict` plan-submission flag does NOT downgrade this check;
it is structural, not warning-class.

**Justification.** Without this invariant, an operator could
declare a single Executor task that holds both `registry-beta-read`
(an env-bound credential) and `registry-prod-write` (a different
env-bound credential), with `allowed_egress` covering both
`api.beta.example.com` and `api.prod.example.com`. The kernel would
inject both credentials into the same VM at boot. A confused (or
compromised) agent process inside that VM could authenticate to
either environment from the same execution context. The audit chain
would record the resulting cross-environment activity as plan-sanctioned;
nothing in the runtime would distinguish "agent intentionally promoted
an artifact" from "agent leaked a beta credential into a prod-bound
HTTP request". INV-ENV-01 makes the admission-time invariant
structural — the kernel *cannot* be configured into a state where one
session holds two environments' worth of authority simultaneously.

**Scenario.** An operator wants to "promote a verified artifact from
beta to production" and writes a single `promote_artifact` Executor
task that lists both `registry-beta-read` and `registry-prod-write`
as `[[plan.tasks.credentials]]`. At `approve_plan`, the per-task
binding algorithm computes `task_envs = {"beta", "production"}` from
the credential bindings and returns `FAIL_TASK_ENVIRONMENT_INCONSISTENT
{ task: "promote_artifact", environments: ["beta", "production"],
sources: [(Credential("registry-beta-read"), "beta"),
(Credential("registry-prod-write"), "production")] }`. The CLI
surfaces this with a remediation hint pointing at
`environment-access-control.md §11.5` (the canonical DAG-split
pattern). The operator refactors the plan into two tasks — one
"beta"-bound `fetch_from_beta` and one "production"-bound
`publish_to_prod` connected by `depends_on` — passing the artifact
between them via the kernel's task-output store. Both new tasks pass
INV-ENV-01 trivially (each binds to exactly one env), and the kernel
mediates the artifact handoff with a SHA-256 record in the audit
chain.

**Role-implicit neutrality.** Reviewer and Orchestrator tasks have
**cardinality 0** for environment-bound resources by structural
prohibition rather than operator choice. Reviewer (per
`INV-PLANNER-HARNESS-01` / `INV-PLANNER-HARNESS-04`: pure-static, no
operator-egress, no operator-credentials) and Orchestrator (per
`INV-PLANNER-HARNESS-06`: not declarable in `plan.toml`, no
operator-controlled credentials, no operator-controlled egress) both
admit zero environment-bound resources by definition. INV-ENV-01 is
therefore a no-op for these roles — they always record as Neutral.
This is the architecturally-correct outcome: the Reviewer is a
pure-static analyzer acting on bytes (the environment binding has no
meaning for it), and the Orchestrator is a kernel-owned actor that
sequences the DAG without holding any environment's credentials.

**Activation gate.** The invariant fires only when the loaded policy
declares at least one `[environments.<label>]` (per
`environment-access-control.md §1.5.2`). A V1-style deployment, a
fresh V2 install, or any V2 deployment that has not opted into the
environment model bypasses the check entirely — the binding algorithm
computes an empty environment set for every task and INV-ENV-01 is
trivially satisfied. This is what makes the entire subsystem opt-in
without compromising existing deployments.

**Alternatives rejected.**

- **Per-session enforcement instead of per-task.** Would require
  recomputing the binding on every session activation; admits a race
  condition where a task could alternate between bindings across
  retries. Per-task enforcement at admission is one-shot, cheap, and
  durable for the initiative's lifetime.
- **Warning-class with `--no-strict` downgrade.** Mirrors the
  existing pattern for some warnings, but mixing environments is a
  structural failure mode (one VM holding two boundaries' worth of
  authority), not a hygiene issue. The operator's ergonomic remedy
  is the §11.5 DAG-split pattern, not bypass.
- **Implicit "shared" environment for tasks without bindings.**
  Re-introduces a kernel opinion the operator may not want. Tasks
  with cardinality 0 are explicitly Neutral; the audit chain records
  them as such; future per-environment knobs simply don't apply to
  them.
- **Credential-name conventions (e.g., `*-prod` auto-binds to
  "production").** Rejected: name-shape coupling makes rename
  refactors a security risk. Binding is exclusively the
  `environment` field on `[[permitted_credentials]]`.

**Canonical home.** `v2/environment-access-control.md` §11
(behavioral spec, including the §11.3 algorithm, §11.4 same-cluster
interaction, §11.5 DAG-split pattern, and §11.6 role-implicit
neutrality table).

---

## §11.6 — Paired audit writes (INV-AUDIT-PAIRED-*)

The seven invariants below are the canonical R-7-bearing properties of
the V2.1 paired-audit protocol. They make the V1 probabilistic R-7
gap (chain integrity conditional on `recovery::reconcile` running on
the next kernel start) into a structural guarantee: an offline
forensic verifier resolves every chain orphan from a frozen SQLite
snapshot alone, with no kernel runtime dependency.

**Canonical home.** `v2/audit-paired-writes.md` §14 (full statements,
verification tests, and rationale per invariant).

### INV-AUDIT-PAIRED-01 — Every state-mutating event is preceded by a pending

**Statement.** For every `AuditEventKind` variant in the paired class
(`v2/audit-paired-writes.md §4.1`), the kernel writes and durably
fsyncs a `StateChangePending` event before issuing `BEGIN IMMEDIATE`.
No path through the kernel mutates SQLite without a preceding
fsync'd pending.

**Justification.** Floor of strict R-7 satisfaction. Without it, a
crash mid-COMMIT leaves the chain silent on a state change.

**Scenario.** An attacker triggers a kernel panic between Phase B0 and
Phase B1; recovery never runs (host decommissioned). Without this
invariant the chain is silent on the attempted mutation; with it, a
`StateChangePending` survives the crash for the offline verifier to
resolve.

**Canonical home.** `v2/audit-paired-writes.md` §14.1.

---

### INV-AUDIT-PAIRED-02 — Every confirmed references a real pending with matching digests

**Statement.** For every paired-class confirmed event in the chain,
the cited `confirms_pending_seq` MUST refer to a `StateChangePending`
event earlier in the chain, AND the confirmed's
`actual_post_state_digest` MUST equal that pending's
`intended_post_state_digest`.

**Justification.** Closes the kernel-buggery / kernel-compromise
vector where the kernel announces one mutation and commits a
different one. The digest binding is the structural defence the
threat model in `v2/audit-paired-writes.md §9` enumerates.

**Scenario.** A buggy or compromised kernel announces `Admitted →
Active` in the pending and commits `Admitted → Failed`. The verifier
flags `Finding::DigestMismatch` as a critical finding.

**Canonical home.** `v2/audit-paired-writes.md` §14.2.

---

### INV-AUDIT-PAIRED-03 — Every rollback references a real pending

**Statement.** For every `StateChangeRolledBack` in the chain, the
cited `rolls_back_pending_seq` MUST refer to a `StateChangePending`
earlier in the chain. Pending and rollback together form a complete
pair; no SQLite mutation occurred under that pending's claim.

**Justification.** Symmetric to `INV-AUDIT-PAIRED-02`. A dangling
rollback (rollback referencing nothing) is a critical R-7 finding —
it implies chain truncation or fabrication.

**Scenario.** Operator notices an unexpected `StateChangeRolledBack
{ rolls_back_pending_seq: 9001 }` but the chain has no event at
seq 9001. Verifier flags `Finding::RolledBackWithoutPending` as
critical.

**Canonical home.** `v2/audit-paired-writes.md` §14.3.

---

### INV-AUDIT-PAIRED-04 — `last_committing_event_seq` reflects the most recent pending

**Statement.** For every state-bearing SQLite row, the
`last_committing_event_seq` column records the seq of the most
recent pending whose Phase B1 successfully committed a mutation to
that row. The kernel writes this column inside the same transaction
as the row mutation; no path exists by which a row mutates without
`last_committing_event_seq` being updated.

**Justification.** SQLite half of offline-verifier resolution
(`v2/audit-paired-writes.md §5.1` Phase 3). Without it, the verifier
cannot distinguish a committed orphan from a rolled-back orphan.

**Scenario.** Crash window §7.4 (COMMIT succeeded, confirmed fsync
never ran). Verifier sees orphan pending(X) and confirms it
committed by reading `last_committing_event_seq = X` on the affected
row.

**Canonical home.** `v2/audit-paired-writes.md` §14.4.

---

### INV-AUDIT-PAIRED-05 — Audit chain is offline-verifiable without the kernel

**Statement.** Given (a) the JSONL chain segments and (b) a SQLite
snapshot at any point-in-time after the chain, the verifier algorithm
in `v2/audit-paired-writes.md §5` MUST resolve every orphan to either
`OrphanResolvedByStateSnapshot` or `OrphanRolledBackInferred`. The
verifier MUST NOT require the kernel to be running, MUST NOT require
any kernel-side recovery process to have run, and MUST produce the
same set of findings on the same inputs regardless of whether the
host kernel is currently up.

**Justification.** This is the literal statement of R-7. Closes the
strict-reading gap in V1.

**Scenario.** A host is decommissioned years after the kernel last
ran. A compliance auditor receives the data directory and
reconstructs the full chain integrity story without the kernel
binary.

**Canonical home.** `v2/audit-paired-writes.md` §14.5.

---

### INV-AUDIT-PAIRED-06 — Recovery is advisory, not required for chain integrity

**Statement.** `kernel/src/recovery.rs::reconcile_advisory` MAY
synthesise missing `confirmed` and `StateChangeRolledBack` events on
kernel start, but the chain's R-7 verifiability MUST NOT depend on
this synthesis having run. A chain that has never been touched by
recovery MUST produce the same offline-verifier output (modulo
`Finding::OrphanResolvedByStateSnapshot` vs
"confirmed-event-present") as one that has.

**Justification.** Closes the V1 R-7 conditional-on-restart violation
explicitly. Recovery becomes a chain-readability optimisation, not a
correctness requirement.

**Scenario.** A V2.1 kernel crashes mid-write; the operator runs the
offline verifier from a snapshot before any kernel restart. Findings
include `OrphanResolvedByStateSnapshot` (or `OrphanRolledBackInferred`)
for each orphan, with no critical findings — full chain
verifiability without `reconcile_advisory` having run.

**Canonical home.** `v2/audit-paired-writes.md` §14.6.

---

### INV-AUDIT-PAIRED-07 — Pre-V2.1 rows fall back gracefully

**Statement.** For SQLite rows with `last_committing_event_seq = 0`
(rows the V2.1 migration could not backfill), the offline verifier
flags `Finding::PreV21Row` (non-critical) and applies V1
reconciliation semantics for those rows' history. The V1 fallback is
bounded: no V2.1+ paired event can resolve to a `PreV21Row` (the
kernel sets `last_committing_event_seq` on every mutation
post-migration).

**Justification.** Migration-cycle safety — the protocol must handle
deployments that have years of pre-V2.1 chain.

**Scenario.** A long-running V1 deployment migrates to V2.1. The
backfill cannot resolve a row that was deleted from the chain by
prior segment rotation. The verifier flags it as `PreV21Row`, falls
back to V1 reconciliation for that row's narrative, and continues
without raising a critical finding.

**Canonical home.** `v2/audit-paired-writes.md` §14.7.

---

## §11.7 — V3 cloud-proxy forwarding (INV-CLOUD-FWD-*)

These invariants apply only when a credential's
`[tasks.credentials.forwarding].enabled = true`. The V2
emulator path is unaffected.

### INV-CLOUD-FWD-01 — Construction-enforced egress allowlist

The shared `CloudHttpClient` is constructed against a
typed `CloudUpstreamHost` enum whose variants are
hard-coded to `{sts.amazonaws.com,
sts.{region}.amazonaws.com, oauth2.googleapis.com,
login.microsoftonline.com}`. Any attempt to dispatch to a
host not in this set fails at construction time
(`UpstreamError::EgressAllowlist`) before any TLS handshake
is initiated. The kernel surfaces the failure as
`ManagerError::CloudForwardingConfig` at session start so
malformed plans never spawn an unauthorized proxy.

**Justification.** A V3 proxy that could be redirected to an
attacker-controlled host by a misconfigured plan is strictly
worse than the V2 emulator. The allowlist is structural, not
configuration-driven.

**Canonical home.** `v3/cloud-proxy-forwarding.md §3.1`.

### INV-CLOUD-FWD-02 — Audit redaction discipline

The four V3 audit events (`CloudCredentialForwarded`,
`CloudCredentialForwardingDenied`, `CloudCredentialCacheHit`,
`CloudCredentialCacheRefreshed`) emit only
non-credential-bearing fields: provider, exchange-kind,
upstream-host FQDN, elapsed-ms, HTTP status code, response
size in bytes, denial-reason enum. The IAM access-key ID is
NEVER emitted; the GCP `client_email` and `private_key` are
NEVER emitted; the Azure `client_secret` is NEVER emitted.
The Azure cache key folds `sha256(client_id)[:8]` instead
of the raw client ID so the cache surface itself cannot leak
identifying bytes.

**Justification.** The V3 work increases the audit chain's
visibility into credential operations. Without strict
redaction the chain becomes a credential exfiltration vector.

**Canonical home.** `v3/cloud-proxy-forwarding.md §5` and
`raxis-credential-proxy-cloud-shared::audit`.

### INV-CLOUD-FWD-03 — Failed refresh does not poison cache

When the aging-window background refresh fails (network
error, upstream 4xx, malformed body, timeout), the existing
cache entry is NOT evicted. The proxy continues to serve
the old (still-valid) credential to in-VM clients until its
hard TTL expires, at which point the cache misses and a
fresh cold-path exchange is attempted. The refresh path
emits `CloudCredentialForwardingDenied` so operators see
the failure even though the in-VM SDK is unaffected.

**Justification.** A transient STS outage must not cascade
into agent-side credential starvation while the refresh
window is open. Operators need explicit signal of refresh
failures so they can act before the hard TTL expires.

**Canonical home.** `v3/cloud-proxy-forwarding.md §6.5`.

### INV-CLOUD-FWD-04 — Upstream 4xx envelope pass-through

When the upstream returns a 4xx (auth, permission,
malformed-request) the proxy mirrors the body bytes verbatim
to the in-VM SDK with the upstream status code unchanged,
modulo a synthetic 503 substitution on 5xx /
network-failure / timeout / malformed-success per spec
§6.4. The pass-through preserves the canonical wire shape
(`<ErrorResponse>` XML for AWS, RFC 6749 JSON for GCP /
AAD) the SDK expects so existing client-side error handlers
continue to work without V3-specific patches.

**Justification.** SDKs (boto3, google-auth-library,
azure-identity, terraform providers) hard-code wire-shape
expectations. A proxy that "helpfully" translates the error
into a non-canonical shape becomes a compatibility
liability.

**Canonical home.** `v3/cloud-proxy-forwarding.md §6.4`.

### INV-CLOUD-FWD-05 — Operator credentials never enter the VM

The long-lived issuance material (AWS IAM key bytes, GCP
service-account JSON private key, Azure service-principal
client secret) is resolved through `CredentialBackend` on
the kernel host and lives only in the proxy process memory
(zeroized on drop where the type wrapper supports it). The
in-VM SDK sees only the short-lived upstream-issued token
the proxy mints. INV-VM-CAP-04 already forbids
`credentials/` mounts inside the VM; this invariant
strengthens it for the V3 path by establishing that even the
proxy-side surface keeps the issuance material out of the
audit chain, the JSON response body, and the cache key.

**Justification.** The V3 forwarding work moves the proxy
from an emulator to a real cryptographic actor on behalf
of the operator. The risk surface for credential leakage
grows; this invariant pins the mitigations.

**Canonical home.** `v3/cloud-proxy-forwarding.md §5, §6.1,
§6.2, §6.3`.

---

### INV-EGRESS-DEFAULT-01 — Provider-FQDN egress is auto-granted by default

For every `[[providers]]` entry in the active policy bundle
the kernel SYNTHESISES one egress allowlist entry against
the provider's canonical inference FQDN
(`Anthropic ⇒ api.anthropic.com`,
`OpenAI ⇒ api.openai.com`,
`Gemini ⇒ generativelanguage.googleapis.com`,
`Bedrock ⇒ bedrock-runtime.us-east-1.amazonaws.com`,
`http_sidecar ⇒ host of sidecar_endpoint`). The synthesised
entries are unioned with operator-declared `[egress] domains`
and consumed by BOTH egress chokepoints — the gateway URL
allowlist (`raxis-gateway::policy_view`) and the Tier-1
transparent-proxy admission service
(`raxis-egress-admission`). Operator can opt out per-policy
with `[egress] implicit_provider_grants = false` (validator
rejects this combination when at least one provider is
declared and zero explicit egress is configured) or
per-provider with `[egress] deny_provider = ["…"]`.

**Justification.** Production bug class: operator declares
`[[providers]] anthropic-prod` but forgets the matching
`[egress] domains = ["api.anthropic.com"]` and EVERY agent
(Reviewer, Orchestrator, Executor) silently fails its first
inference call with `DomainNotAllowed` or
`HostNotInAllowlist`. The invariant eliminates the
configuration coupling — `[[providers]]` is now the single
source of truth for "agent X can reach provider Y".

**Canonical home.** `v2/reviewer-egress-defaults-decision.md §5`.

### INV-EGRESS-DEFAULT-02 — Implicit grants are auditable

Every implicit-provider grant the kernel applies emits one
`AuditEventKind::DefaultProviderEgressApplied` event
carrying `(policy_epoch, provider_id, provider_kind, fqdn)`.
Emit timing:
- ONE event per grant at kernel boot (so the active
  genesis bundle's grants are recorded on every startup, not
  just at the next `RotateEpoch`); and
- ONE event per grant after every successful
  `policy_manager::advance_epoch` post-commit (so a rotation
  that adds or changes a `[[providers]]` entry surfaces its
  derived grants in the audit chain).

**Justification.** Implicit grants WITHOUT an audit event
would be a silent security smell — operators couldn't tell
which FQDNs the kernel is enforcing beyond the
operator-declared `[egress] domains`. The audit trail closes
the gap; the operator-visible diff between
`bundle.egress_domains()` (what the operator typed) and
`bundle.effective_egress_domains()` (what the kernel
enforces) is reconstructible from the audit chain alone.

**Canonical home.** `v2/reviewer-egress-defaults-decision.md §5`.

### INV-EGRESS-DEFAULT-03 — Opt-out is validated at policy-load

`[egress] deny_provider` entries that don't resolve to a
declared `[[providers]] provider_id` are rejected at
`PolicyBundle::load` with
`FAIL_POLICY_EGRESS_DENY_PROVIDER_UNKNOWN`. A typo'd
`provider_id` in `deny_provider` would otherwise silently
fail to opt out and the operator would believe a provider
was disabled when it wasn't.

**Justification.** Closes the dual-failure mode where the
operator BELIEVES they have opted out but the policy still
auto-grants the FQDN.

**Canonical home.** `v2/reviewer-egress-defaults-decision.md §6`.

### INV-EGRESS-STALL-01 — Repeated egress denials emit one stall event

When the same `(session_id, host_or_sni, port, reason)`
tuple is denied at least 3 times within a 30-second sliding
window (the configured defaults of
`raxis_egress_admission::EgressStallTracker`), the kernel
emits exactly ONE
`AuditEventKind::SessionEgressStallDetected` event with
`source ∈ {"tproxy", "kernel_mediated_fetch"}` identifying
which chokepoint observed the stall. Subsequent denials
inside the same window are debounced; the bucket re-arms
once the window slides past the last emit.

The event is a structured signal — the kernel does NOT
auto-respawn the agent (that's the elastic-VM-scaling
worker's territory). Downstream tooling (operator
dashboards, alerting) consume the event to surface the
silent-spin failure mode.

**Justification.** Even with INV-EGRESS-DEFAULT-01 closing
the dominant config-time failure, runtime stalls remain
possible (post-admission policy reload, scoped
`deny_provider` opt-out, cred-proxy down). The detector
catches every stall regardless of root cause.

**Canonical home.** `v2/reviewer-egress-defaults-decision.md §7`.

---

## §11.X — Secrets model invariants

The five invariants below form the V2 secrets-model surface. The
canonical doctrinal text is `v2/secrets-model.md`; the formal
statements live here.

### INV-SECRET-01 — Operators never place raw secret material in worktrees

The worktree is, by construction, the agent's read/write surface.
Raw credential material (real passwords, real tokens, real signing
keys, real kubeconfigs) MUST NOT appear in any file under any
worktree the agent can mount. This rule is asserted on the
*operator*: RAXIS does not police worktree contents on the
operator's behalf — the operator's provisioning tooling owns this
discipline. The kernel's role is to make the discipline
*sufficient*.

**Justification.** Mounting credentials into the worktree makes
the kernel's protections vacuous: the secrets model presupposes
the agent never has the bytes, not that the agent politely
declines to read them.

**Canonical home.** `v2/secrets-model.md §2.1`.

### INV-SECRET-02 — Real credentials live in `CredentialBackend`, resolved host-side

Real credential material is held by a `CredentialBackend` impl
(`extensibility-traits.md §4`), resolved via `resolve(name,
consumer)` from kernel address space only, and never crosses the
VM boundary in any form (no VirtioFS mount, no env var, no
generated config blob carrying real bytes). The bytes that DO
cross the VM boundary are either non-sensitive (a loopback URL
pointing at the proxy, an `AWS_CONTAINER_CREDENTIALS_FULL_URI`
pointing at the in-VM AWS proxy, a placeholder string the
operator deliberately staged) or a short-lived proxy-minted
token whose lifetime is bounded by the upstream issuer.

**Justification.** Resolution outside the VM is the structural
boundary the threat model relies on. Anything inside the VM is
inside the agent's reach and is therefore treated as
exfiltratable.

**Canonical home.** `v2/secrets-model.md §2.2`,
`extensibility-traits.md §4`.

### INV-SECRET-03 — Agents reach external services only via credential proxies

The kernel-mediated egress allowlist (`vm-network-isolation.md`
Tier 1 SNI + `credential-proxy.md` Tier 2 loopback) means the
ONLY reachable network path from inside an agent VM to an
authenticated upstream is the per-session credential proxy bound
at `127.0.0.1:NNN`. Direct dials to the real upstream's IP / FQDN
are denied at the in-guest tproxy with
`TransparentProxyDenied { reason: "proxy_target_bypass" }`,
surfaced in the audit chain.

**Justification.** Without this invariant the proxy can be
bypassed and the substitution discipline is voluntary. With it,
the substitution discipline is the only path that *works*.

**Canonical home.** `v2/secrets-model.md §2.4`, `credential-
proxy.md`, `vm-network-isolation.md`.

### INV-SECRET-04 — Mechanical enforcement, not agent compliance

The kernel does not rely on agent compliance with policy text.
Every protection in the secrets model is *mechanical*: structural
enforcement at the proxy boundary, the egress-allowlist boundary,
and the path-allowlist boundary. The LLM is treated as
adversarial-by-design — a passing test based on "the agent
politely refrained from doing X" is a categorical failure of
test design, not evidence of safety.

**Justification.** This invariant is the doctrinal anchor that
keeps the threat model honest. The realistic-scenario e2e's
`credential-substitution-canary` task is its current concrete
witness; future tests that violate this invariant should be
rejected at review.

**Canonical home.** `v2/secrets-model.md §1, §4`.

### INV-SECRET-05 — Credential-proxy substitutes placeholder credentials before forwarding upstream

When an agent attempts authentication using operator-supplied
placeholder credentials (e.g., a `.env` staged by the operator
with deliberately fake user / password / token strings, or a
plan-level env mount carrying placeholders), the credential
proxy at the loopback target MUST substitute the real credential
material — resolved via `CredentialBackend::resolve(...)` on the
host — BEFORE forwarding to the real upstream. The placeholder
credentials MUST NOT reach the upstream. The real credential
material MUST NOT be visible to the agent in any form (env var,
worktree file, audit envelope reachable from inside the VM, or
wire byte the agent can observe).

The proxy's `CredentialProxySubstituted { service,
substitution_shape, real_resolved: true }` audit event pins this
fact on the chain at the moment substitution takes effect.

**Justification.** A jailbroken / hallucinating / prompt-injected
LLM that exfiltrates everything it can observe leaks only the
placeholder material — which the operator already treated as
non-sensitive. The real credentials never enter the LLM's
context. This invariant makes that property mechanically
testable, and pairs with the
`credential_substitution_evidence::assert_credential_
substitution_round_trip` witness in the realism extended e2e.

**Canonical home.** `v2/secrets-model.md §2.5`,
`credential-proxy.md`,
`kernel/tests/extended_e2e_support/credential_substitution_evidence.rs`.

---

## §12 — How invariants combine (composition map)

Most security properties at the system level are emergent from
**combinations** of invariants. The most consequential combinations:

| Combined property | Component invariants |
|---|---|
| **Operator authority is forensically traceable** | INV-04 (audit log integrity) + INV-CERT-05 (per-event cert chain) + INV-CERT-04 (rotation pubkey continuity) |
| **Operator authority is cryptographically anchored** | INV-CERT-01 (cert mandatory) + INV-CERT-02 (self-signature unbypassable) + INV-CERT-03 (private key not persisted) |
| **Planner cannot influence its own scope** | INV-INIT-01 (no task creation) + INV-INIT-06 (plan immutable) + INV-07 (kernel-derived claims) + INV-SCHED-01 (admit only at approval) |
| **Signed plan bytes cannot be replayed by an attacker** | INV-PLAN-BUNDLE-FRESH (per-bundle nonce + freshness window) + INV-INIT-06 (post-admission immutability) + INV-04 (audit-chain integrity records every admission) + INV-CERT-* (operator key custody) — the nonce closes same-window replay; the freshness window closes long-tail replay; key revocation closes detected-key-compromise; the three layers compose so an attacker who exfiltrates a signed bundle gets at most one admission attempt inside a bounded window |
| **Provider-credential compromise has bounded post-revocation exposure** | INV-PROVIDER-10 (synchronous re-check at dispatch + UDS half-close on in-flight) + INV-KEY-08 (immediate session termination on compromise) + INV-PROVIDER-08 (per-attempt audit immediacy) + INV-VM-CAP-04 (no credential value in VM) — the re-check eliminates the alias-resolution → dispatch TOCTOU; the half-close drops in-flight HTTPS within a worker-side EOF latency; session termination removes the parent context; per-attempt audit makes every aborted call forensically visible |
| **Path scope is enforced at every step** | INV-TASK-PATH-01 (admission) + INV-TASK-PATH-02 (completion) + INV-07 (claim derivation) |
| **Recovery is deterministic from durable state** | INV-05 (reproducibility) + INV-INIT-08 (gate progress recoverable) + INV-INIT-05 (BlockedRecoveryPending requires operator) + INV-STORE-01/02 (atomic transactions) |
| **Budget enforcement cannot be bypassed** | INV-02A (kernel-priced inference) + INV-02B (no direct egress) + INV-INIT-09 (no auto-deadline; budget bounds runtime) |
| **Provider egress is correct-by-default + auditable + stall-detected** | INV-EGRESS-DEFAULT-01 (kernel auto-grants provider FQDNs) + INV-EGRESS-DEFAULT-02 (`DefaultProviderEgressApplied` audit per grant) + INV-EGRESS-DEFAULT-03 (`deny_provider` typo rejected) + INV-EGRESS-STALL-01 (`SessionEgressStallDetected` after 3-in-30s denials) — `DEFAULT-01` eliminates the dominant config-time stall; `DEFAULT-02` keeps the implicit grant auditable; `DEFAULT-03` closes the silent-opt-out failure mode; `STALL-01` catches every runtime stall regardless of root cause |
| **Approval is real, scoped, single-use** | INV-06 (approval gate) + INV-ESC-01..05 (FSM, epoch, session, nonce, scope) |
| **Policy advance never partial** | INV-POLICY-01 (advance phasing) + INV-STORE-01/02 (single-transaction multi-table) |
| **Multi-agent loops bounded by structure, not budget alone** | INV-CONVERGENCE-01 (round caps) + INV-CONVERGENCE-02 (circular-revision rejection) + INV-CONVERGENCE-03 (wall-clock) + INV-04 (token budgets — backstop) |
| **Two-tier escalation routing preserves authority hierarchy** | INV-CONVERGENCE-04 (Orchestrator bounded by own authority) + INV-CONVERGENCE-06 (re-validation at resolution time) + INV-ESC-02 (epoch-mismatch on approval tokens) + R-4 (paradigm) |
| **Forensic record survives non-convergence** | INV-CONVERGENCE-05 (no auto-purge during salvage) + INV-04 (audit log integrity) + INV-CAPACITY-02 (halt-admit before purge) |
| **Reviewer cannot be deceived by code under review** | INV-PLANNER-HARNESS-01 (no Reviewer code execution) + INV-PLANNER-HARNESS-02 (kernel-bundled image, digest-verified) + INV-PLANNER-HARNESS-04 (no Reviewer custom tools) + INV-VERIFIER-02 (verifier VM isolation) + INV-VERIFIER-08 (verifier has no LLM) |
| **Reviewer pure-static guarantee survives operator extension surface** | INV-PLANNER-HARNESS-01 (harness build + plan-side authoring corollary covering vm_image, custom tools, path_allowlist) + INV-PLANNER-HARNESS-02 (image content) + INV-PLANNER-HARNESS-04 (admission gate against operator-declared tools) — admission rejects every plan field whose semantics presuppose a Reviewer capability that does not exist; the operator's mental model is corrected at the boundary, not patched into runtime quietly |
| **Operator authoring discipline survives kernel-side defaulting machinery** | INV-PLANNER-HARNESS-01 (plan-side authoring corollary, structural rejection of meaningless fields) + INV-INIT-06 (plan immutable post-admission, no kernel-side mutation of operator-signed bytes) — the kernel never silently strips, mutates, or defaults a Reviewer-only-meaningful field; `raxis-cli plan prepare` surfaces hard refusals pre-signing so the operator catches the issue before bundle sealing; the kernel's admission gate is the defense-in-depth backstop. Together these keep operator authority unambiguous: every byte in the signed plan is the operator's deliberate choice |
| **Only the Executor role has operator-controlled toolchain** | INV-PLANNER-HARNESS-02 (Reviewer image kernel-canonical) + INV-PLANNER-HARNESS-05 (Orchestrator image kernel-canonical) + INV-VM-CAP-03 (Executor image operator-published, OCI-pinned) |
| **Orchestrator is invisible at the configuration layer** | INV-PLANNER-HARNESS-05 (kernel-canonical image) + INV-PLANNER-HARNESS-06 (no operator profile, no NNSP override, no custom tools, no background processes) — operators cannot misconfigure what they cannot configure |
| **Trivial git conflicts do not flood operator escalations** | INV-PLANNER-HARNESS-05 (Orchestrator image includes git + bash + edit_file) + INV-PLANNER-HARNESS-06 (Orchestrator NNSP encodes semantic conflict resolution protocol) + INV-TASK-PATH-02 (hybrid_effective_allow bounds the Orchestrator's editing authority structurally) — the Orchestrator's semantic intelligence resolves routine conflicts; the FSM bounds its authority |
| **Code-running verification is structurally separated from review** | INV-VERIFIER-01 (witness-only output) + INV-VERIFIER-02 (verifier VM isolation) + INV-VERIFIER-03 (Reviewer waits for all per-task witnesses) + INV-VERIFIER-04 (block_review fails the task) + INV-VERIFIER-13 (pre-merge verifiers gate IntegrationMerge separately from Reviewer) |
| **In-VM background processes are reliably contained** | INV-PLANNER-HARNESS-03 (cgroup v2 + `cgroup.kill`) + INV-VERIFIER-10 (kernel-enforced verifier timeout) + INV-LIFECYCLE-* (VM stop is universal reap point) |
| **Verifier supply chain bounded** | INV-VERIFIER-07 (operator-published with kernel-canonical exception per INV-VERIFIER-12) + INV-VERIFIER-11 (no network by default) + INV-VERIFIER-09 (mutations don't persist) + INV-VERIFIER-12 (symbol-index image is kernel-canonical, digest-bound, alias-reserved) |
| **Symbol-index witness is structurally trustworthy under auto-injection** | INV-VERIFIER-12 (kernel-canonical image, kernel-bound digest, reserved alias) + INV-PLANNER-HARNESS-01 (Reviewer cannot bypass the witness with its own code execution) + INV-VERIFIER-01 (witness-only output channel) — the Pure-Static Reviewer's symbol-resolution gap is closed by an artifact whose producer is structurally trusted, structurally isolated, and structurally limited to a witness output |
| **Main frontier regressions are gated mechanically, not just reviewed** | INV-VERIFIER-13 (pre-merge verifier gating) + INV-MERGE-CONSISTENCY (atomic SQLite-then-git ordering) + INV-TASK-PATH-02 (per-task path closure) — per-task review establishes per-task correctness; pre-merge verifiers establish integration-frontier correctness; the SQLite-first ordering ensures verifier failures cannot half-advance main |
| **No single agent execution context spans two compliance boundaries** | INV-ENV-01 (per-task environment consistency) + INV-VM-CAP-04 (credentials/ never mounted) + INV-PLANNER-HARNESS-01/04/06 (Reviewer/Orchestrator structurally environment-neutral) — credentials are kernel-injected by name, the per-task binding constrains which set of names can be injected together, and the planner-harness invariants ensure only the Executor role even has the surface for binding to fail |
| **Cross-environment data flows are auditable** | INV-ENV-01 (forces DAG split for cross-env work) + INV-04 (audit log integrity) + INV-VERIFIER-* (artifact mechanism mediates the kernel-store handoff) — every cross-environment byte transfer becomes two task IDs and a SHA-256 in the audit chain rather than a single VM with multiple credentials |
| **Audit chain is verifiable without the kernel running** | INV-AUDIT-PAIRED-01 (every state change has a pending) + INV-AUDIT-PAIRED-02/03 (pairing integrity) + INV-AUDIT-PAIRED-04 (`last_committing_event_seq` disambiguates orphans) + INV-AUDIT-PAIRED-05 (offline verifier algorithm) + INV-AUDIT-PAIRED-06 (recovery is advisory) + INV-04 (chain hash linkage) — together these turn R-7 from a probabilistic "if recovery runs" guarantee into a structural "verifiable from frozen state alone" guarantee |
| **Kernel cannot announce one mutation and commit another** | INV-AUDIT-PAIRED-02 (digest equality between pending's `intended_post_state_digest` and confirmed's `actual_post_state_digest`) + INV-04 (chain hash linkage prevents post-hoc edit) + INV-CERT-* (event signing prevents forgery) — a buggy or compromised kernel that diverges intent from effect is flagged as `Finding::DigestMismatch` by the offline verifier, with no kernel cooperation required |
| **V3 cloud-credential exchange is structurally bounded** | INV-CLOUD-FWD-01 (construction-enforced egress allowlist) + INV-CLOUD-FWD-02 (audit redaction) + INV-CLOUD-FWD-05 (operator credentials never enter VM) + INV-VM-CAP-04 (no credential mounts in VM) — together these guarantee the V3 forwarding path can dial only the four known cloud control planes, cannot leak the operator's issuance material through audit / cache / response, and confines the long-lived secret to the kernel-host proxy process | |
| **Secrets model is structurally sound against an adversarial LLM** | INV-SECRET-01 (operators never place raw secrets in worktrees) + INV-SECRET-02 (resolution host-side) + INV-SECRET-03 (proxy is the only egress path) + INV-SECRET-04 (no LLM-compliance dependence) + INV-SECRET-05 (proxy substitutes placeholders before upstream) + INV-VM-CAP-04 (no credential mounts in VM) — together these guarantee a jailbroken / prompt-injected / hallucinating LLM that exfiltrates everything it can observe leaks only the operator-staged placeholders. The real credential material never enters the LLM's context; the substitution discipline at the proxy boundary is the load-bearing mechanical guarantee, with the witness in `credential_substitution_evidence` pinning all five sub-properties on every realism e2e run |

When auditing a code path, look for which combination of invariants
governs it; a single invariant in isolation rarely tells the full
story.

---

## §13 — When this file is wrong

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
3. Add the invariant ID to the table-of-contents row count and to
   any relevant §12 composition row.
4. If the invariant is enforced by code, leave a `// INV-XXX` or
   spec crossref comment at the enforcement site.

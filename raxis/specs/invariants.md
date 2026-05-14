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
> `INV-EXEC-DISCOVERY-01` (§10.4a),
> `INV-VERIFIER-*` (§11), `INV-ENV-01` (§11.5),
> `INV-AUDIT-PAIRED-01..07` (§11.6),
> `INV-SUPERVISOR-*` + `INV-DASHBOARD-KERNEL-LIFECYCLE-01` +
> `INV-DASHBOARD-JWT-SECRET-PERSISTENT-01` (§11.12). V2 invariants in their canonical
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
| Post-ceiling cascade & respawn — V2 | INV-FSM-POST-CEILING-RESPAWN-01 | 1 |
| Escalation — V1 | INV-ESC-01..06 | 6 |
| Kernel store — V1 | INV-STORE-01..03 | 3 |
| Policy epochs — V1 | INV-POLICY-01 | 1 |
| Scheduler — V1 | INV-SCHED-01, INV-SCHED-02, INV-SCHED-03 | 3 |
| Orchestrator respawn ceiling — V2 | INV-ORCH-RESPAWN-NO-PROGRESS-CEILING-01, INV-ORCH-STRANDED-INITIATIVE-RESPAWN-01 | 2 |
| Auto-escalation — V2.5b | INV-ESCALATION-AUTO-LOGICAL-DEADLOCK-01 | 1 |
| VCS path enforcement — V1 | INV-TASK-PATH-01, INV-TASK-PATH-02 | 2 |
| Operator certificates — V1 | INV-CERT-01..05 | 5 |
| Convergence — V2 | INV-CONVERGENCE-01..06 | 6 |
| Planner harness — V2 | INV-PLANNER-HARNESS-01..06 | 6 |
| Planner harness — orchestrator NNSP — V2 | INV-PLANNER-ORCH-RETRY-ON-REJECT-01, INV-PLANNER-ORCH-PREDS-READY-GATE-01, INV-PLANNER-ORCH-RETRY-PRIORITY-OVER-ACTIVATE-01 | 3 |
| KSB projection — V2 | INV-KSB-PREDS-READY-PROJECTION-01 | 1 |
| Retry preconditions — V2 | INV-RETRY-FROM-COMPLETED-REVIEW-REJECTED-01, INV-ORCH-RETRY-SUBTASK-PENDING-ACTIVATION-NOT-RETRYABLE-01 | 2 |
| Executor / role-session capability discovery — V2 | INV-EXEC-DISCOVERY-01 | 1 |
| Verifier processes — V2 | INV-VERIFIER-01..15 | 15 |
| Environment binding — V2 | INV-ENV-01 | 1 |
| Paired audit writes — V2 | INV-AUDIT-PAIRED-01..07 | 7 |
| Dashboard surface — V2   | INV-DASHBOARD-STREAM-ENVELOPE-01, INV-DASHBOARD-STREAM-PRODUCER-01, INV-AUDIT-DASHBOARD-01, INV-AUDIT-OPERATOR-ACTION-01, INV-NOTIF-SCOPE-01, INV-DASHBOARD-VALIDATE-01, INV-DASHBOARD-FAILURE-VISIBILITY-01, INV-DASHBOARD-INITIATIVE-PLAN-VISIBLE-01, INV-DASHBOARD-SESSION-DETAIL-FORENSIC-01, INV-DASHBOARD-AUTOLOGIN-VALID-AT-BOOT-01, INV-DASHBOARD-TASK-STATE-COMPLETENESS-01, INV-DASHBOARD-INTEGRATION-MERGE-VISIBLE-OR-EXCLUDED-01, INV-DASHBOARD-WIRE-UNITS-CONSISTENT-01 | 13 |
| Kernel-side failure-reason mandate — V3 (iter54) | INV-FAILURE-REASON-MANDATORY-01 | 1 |
| Live-e2e harness — V2     | INV-LIVE-E2E-HARNESS-NO-INDEFINITE-WAIT-01, INV-LIVE-E2E-EXAMPLES-NO-REAL-SECRETS-01, INV-LIVE-E2E-DASHBOARD-FE-BUNDLE-PRESENT-01, INV-LIVE-E2E-OTEL-PUSHER-PRESENT-01, INV-LIVE-E2E-OBSERVABILITY-LOG-NO-CONTRADICTION-01 | 5 |
| Host hygiene — V2.5 | INV-HOST-HYGIENE-01 | 1 |
| Universal airgap (Path A3) — V2 | INV-NETISO-A3-UNIVERSAL-NO-NIC-01, INV-NETISO-A3-VSOCK-CHOKEPOINT-01, INV-NETISO-A3-DNS-MEDIATED-01, INV-NETISO-A3-IPV6-DISABLED-01, INV-AUDIT-TPROXY-ADMIT-01, INV-AUDIT-DNS-RESOLVE-01 | 6 |
| Self-healing supervisor — V2.5 | INV-SUPERVISOR-RESTART-AUDIT-01, INV-SUPERVISOR-CIRCUIT-BREAKER-01, INV-SUPERVISOR-OPT-IN-01, INV-SUPERVISOR-SIGTERM-RESPECT-01, INV-SUPERVISOR-SIGINT-RESPECT-01, INV-SUPERVISOR-EXIT-CODE-CLASSIFICATION-01, INV-SUPERVISOR-SHUTDOWN-GRACE-01, INV-SUPERVISOR-OPERATOR-CONTINUITY-01, INV-SUPERVISOR-AUTO-RESUME-ON-CLEAN-RESTART-01 | 9 |
| Dashboard kernel-lifecycle — V2.5 | INV-DASHBOARD-KERNEL-LIFECYCLE-01, INV-DASHBOARD-JWT-SECRET-PERSISTENT-01 | 2 |
| Observability metric coverage — V3 (iter44) | INV-OBS-RESPAWN-KIND-LABEL-01, INV-OBS-KERNEL-RESPAWN-COVERAGE-01, INV-OBS-OPERATOR-IPC-COVERAGE-01, INV-OBS-IPC-ROUNDTRIP-COVERAGE-01 | 4 |
| KSB capabilities envelope — V2.6 | INV-KSB-CAPABILITIES-PARITY-01, INV-KSB-CAPABILITIES-ROLE-SCOPED-01, INV-KSB-CAPABILITIES-TURN-COHERENT-01 | 3 |
| Kernel DAG authority — V2 | INV-KERNEL-DAG-AUTHORITY-01 | 1 |
| Planner turn budget — V2.7 / V3 | INV-PLANNER-MAX-TURNS-PRECEDENCE-01, INV-KSB-MAX-TURNS-VISIBILITY-01, INV-PLANNER-MAX-TURNS-PROGRESSIVE-ON-RETRY-01 | 3 |
| Grafana provisioning lifecycle — V3 (iter52) | INV-GRAFANA-DATASOURCE-PROVISIONED-AT-STACK-UP-01 | 1 |
| Dashboard credential viewer completeness — V3 (iter53) | INV-DASHBOARD-CREDENTIAL-VIEWER-LISTS-ALL-OPERATOR-VISIBLE-SECRETS-01, INV-DASHBOARD-CREDENTIAL-REVEAL-PLAINTEXT-WORKS-OR-EXPLAINS-01 | 2 |
| Integration-merge completion cascade — V3 (iter54) | INV-INTEGRATION-MERGE-COMPLETES-SYNTHETIC-TASK-01, INV-INITIATIVE-COMPLETES-WHEN-INTEGRATION-MERGE-SUCCEEDS-01 | 2 |
| Executor image lint-toolchain pre-bake — V3 (iter56) | INV-EXECUTOR-IMAGE-LINT-TOOLCHAIN-PYTHON-01, INV-EXECUTOR-IMAGE-LINT-TOOLCHAIN-JS-01 | 2 |
| **Total** | | **129** |

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

### INV-INIT-05 — `BlockedRecoveryPending` requires operator action (generic crash recovery)

**Statement.** Outside the V2.5 supervisor-aware auto-resume codepath,
a `BlockedRecoveryPending` task can only be resumed
(`raxis-cli task resume`) or terminated by operator `task abort`.
The planner cannot self-resume; the kernel cannot auto-resume.

**Scope.** This invariant governs the **generic crash-recovery
fork** of `recovery::reconcile` — the operator-launched kernel boot
that follows an unmonitored crash, an operator-initiated SIGTERM,
or a non-supervised exit. In the generic fork, the boot-time
reconciliation sweep moves every non-terminal task to
`BlockedRecoveryPending` and the only legal exit edges from that
state are operator-initiated (`task resume → Admitted`,
`task abort → Aborted`).

**Supervisor-aware exception.** When the supervisor restarts the
kernel after an auto-restartable exit code (per
`INV-SUPERVISOR-EXIT-CODE-CLASSIFICATION-01`), the `recovery::
reconcile_after_supervisor_restart` codepath transparently re-admits
the rows that THIS boot's recovery sweep just produced. The
auto-resume is unconditional when the supervisor is enabled and
explicitly skips (a) operator-quarantined initiatives and (b) tasks
that were ALREADY `BlockedRecoveryPending` BEFORE the restart
(preserve operator pre-existing block). See
`INV-SUPERVISOR-AUTO-RESUME-ON-CLEAN-RESTART-01` for the full
contract. Operators who want strict V1 fail-safe behaviour (every
kernel exit halts work for human review, including supervisor-
triggered restarts) disable the supervisor entirely
(`RAXIS_SUPERVISOR_AUTO_RESTART=0`); the supervisor opt-in is the
sole operator surface for that choice.

**Justification.** A task lands in `BlockedRecoveryPending` after a
kernel exit; in the unmonitored case the operator must inspect the
situation and decide whether to resume (state was salvageable) or
abort (state was lost). Auto-resume in the generic fork would
replay potentially-stale work without human review of the crash
cause. The supervisor-aware fork is exempt because the previous
exit was already classified by an immortal external observer (the
supervisor binary) as a kernel-internal pathology — the agent work
itself is fine, only the kernel got stuck — and the audit chain
already records the restart context paired with each auto-resume.

**Scenario.** Operator-launched kernel crashes mid-task (no
supervisor in the picture). On restart, `reconcile_tasks` sweeps
the task to `BlockedRecoveryPending`. Operator runs `raxis log` to
inspect crash cause, decides the task is safe to resume, runs
`raxis task resume <id>`. Only then does the task transition back
to `Admitted` (and onward through normal scheduling). The contrast
with the supervisor-aware fork — where the same FSM edge fires
automatically with `actor = "kernel"` and a paired
`TaskAutoResumedAfterSupervisorRestart` audit event — is what the
9th supervisor invariant pins.

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

### INV-FSM-POST-CEILING-RESPAWN-01 — Post-ceiling cascade closes activation rows and triggers orchestrator respawn

**Statement.** When an Executor session reports
`IntentKind::ReportFailure` (or `CompleteTask` with a terminal
failure outcome) for its bound `task_id`, the kernel — inside a
**single SQLite transaction** — atomically performs all of the
following:

1.  Increments `subtask_activations.crash_retry_count` for the
    `Active` row matching `(task_id, executor_session_id)`
    (`bump_executor_crash_retry_count_in_tx`, commit `6237618`).
2.  Drives the parent `tasks.state` through `transition_task_in_tx`
    to `Failed` (or its terminal equivalent for `CompleteTask`).
3.  Cascades the row above by setting
    `subtask_activations.activation_state = 'Failed'` and stamping
    `terminated_at = unix_now_secs()` for every `Active` row whose
    `task_id` matches the failed task. This is the schema-required
    closure (`activation_state IN ('Completed','Failed') ⇒
    terminated_at IS NOT NULL`, migration 5) and the c986e6d fix
    that prevents `RetrySubTask` from being silently rejected
    against a stale `Active` row.
4.  After the transaction commits, the intent dispatcher's
    EarlyResponse hook (commit `d7ca482`) plus the per-session
    post-exit hook in `session_spawn_orchestrator` evaluates the
    parent initiative and, if the failure satisfies the
    storm-guard preflight (commit `aafd4f2`), triggers a respawn
    of the bound orchestrator session. The respawn outcome is
    logged to stderr as exactly one of
    `orchestrator_respawn_ok`, `orchestrator_respawn_skipped`, or
    `orchestrator_respawn_failed` — never silence.

The whole sequence is bounded: from the moment `ReportFailure` is
accepted, the kernel reaches a stable post-ceiling state (active
row closed, primary orchestrator either respawned or
storm-guarded) within **5 seconds** under no-VM/no-LLM test
conditions. No kernel-owned thread parks for >100 ms during this
window (the parking_lot deadlock watcher under
`runtime-deadlock-detection`, see `concurrency-and-locking.md`
INV-LOCK-07, panics within ~2 s if a cycle forms).

**Justification.** Iter15 / iter16 of the live-e2e
`realistic_session_lifecycle` reproduced a ~30-minute deadlock in
which an executor crash-ceiling left the activation row `Active`
forever, the orchestrator's subsequent `RetrySubTask` was rejected
as "InvalidRequest" (precondition: prior row must be `Failed`),
and `RetrySubTask` is not in the kernel's `respawn_kinds`
allowlist — so no orchestrator respawn fired and the DAG silently
stalled until the live-e2e harness wall-clock timed out. The
fixes landed across four commits (`6237618`, `c986e6d`,
`d7ca482`, `aafd4f2`); without an executable witness for the
combined behaviour, any future refactor of
`transition_task_in_tx`, `bump_executor_crash_retry_count_in_tx`,
or the EarlyResponse / post-exit respawn hooks could regress one
piece of the chain and re-introduce the deadlock — observable
only after the next 30-minute live-e2e iteration. This invariant
pins the chain as a single transactional contract and witnesses
it under <60 s.

**Scenario.** Two initiatives share a lane: `it-primary` (one
task, currently `Admitted`, orchestrator session running) and
`it-sibling` (one task `Running`, executor session bound, an
`Active` `subtask_activations` row with `crash_retry_count = 2`,
one short of the default ceiling). The sibling executor sends
`ReportFailure` for its task. Inside one transaction the kernel
bumps `crash_retry_count` to `3`, transitions
`tasks.task-sibling` to `Failed`, and updates
`subtask_activations.act-sibling` to
`activation_state='Failed', terminated_at=<now>`. After commit,
the EarlyResponse hook evaluates `respawn_kinds` against
`ReportFailure`, decides the sibling's parent orchestrator is
eligible for a respawn check (or skip-with-reason), and emits one
of `orchestrator_respawn_ok` / `orchestrator_respawn_skipped` /
`orchestrator_respawn_failed`. The `IntentResponse` returned to
the executor echoes the new `TaskState::Failed`. Total kernel
wall-time from `ReportFailure` reception to all three log lines
visible: ≤ 5 s.

**Witness.**
`raxis/kernel/tests/post_ceiling_orchestrator_respawn.rs::post_ceiling_deadlock_respawn`.
The test boots the real kernel binary via
`common::kernel_harness`, seeds the post-ceiling state directly
in `kernel.db` via `rusqlite` (no IPC ceremony required for the
sibling-already-near-ceiling precondition), opens a planner
session as the bound Executor, sends `ReportFailure`, and
asserts:

*   The `IntentResponse` carries the post-commit
    `TaskState::Failed` and `IntentOutcome::Accepted` and echoes
    the request `sequence`.
*   Post-commit `kernel.db` shows
    `tasks.task-sibling.state = 'Failed'`,
    `subtask_activations.act-sibling.activation_state = 'Failed'`,
    `terminated_at IS NOT NULL`,
    `crash_retry_count = 3`. (Direct read-back is the
    structural witness for the c986e6d cascade, which is a SQL
    `UPDATE` with no log line of its own.)
*   Kernel stderr contains one
    `event":"TaskTransitioned","task_id":"task-sibling","from":"Running","to":"Failed"`
    line and one of `orchestrator_respawn_ok` /
    `orchestrator_respawn_skipped` / `orchestrator_respawn_failed`.
*   Kernel stderr does NOT contain `event":"deadlock_detected"`
    (cross-witness for INV-LOCK-07: the watcher would fire within
    ~2 s if any of the cascade SQL or the EarlyResponse hook took
    a parking_lot lock that another thread held).

The test is wrapped in `tokio::time::timeout(Duration::from_secs(60))`
as a hard wall — if the kernel hangs anywhere along the chain,
the test fails fast (current wall-clock: ~1.5 s).

**Canonical home.** `v2/concurrency-and-locking.md` §7a
(INV-LOCK-07, the deadlock watcher that bounds detection
latency); `v1/kernel-store.md` §2 (INV-STORE-02, multi-table
atomicity that ties the four mutations into one transaction).

---

### INV-INTEGRATION-MERGE-COMPLETES-SYNTHETIC-TASK-01 — IntegrationMerge success drives the synthetic coordinator task to Completed

**Statement.** When `IntentKind::IntegrationMerge` is admitted
AND the host-side fast-forward (V2.5 §11.1 Phase 2,
`raxis_domain_git::commit_merge_to_target_ref`) returns `Ok`,
the kernel MUST transition the synthetic coordinator task
(`task_id == initiative_id`, inserted by
`kernel/src/initiatives/lifecycle.rs::auto_spawn_orchestrator_session_in_tx`)
from `Running` to `Completed` via `transition_task_in_tx` —
inside the **same transaction** that closes the matching
`subtask_activations` row (`INV-STORE-02`) and resets the
`orchestrator_no_progress_respawn_count`. The transition MUST
also be reflected in the `IntentResponse.task_state` returned
to the caller so the orchestrator's KSB and the dashboard's
projection see `Completed` immediately, not `Running`.

A push failure (`PushFailed` audit, V2_GAPS §C6) downstream of
the cascade MUST NOT regress the now-Completed synthetic task.
A second pass (boot-recovery sweep, idempotent re-dispatch)
MUST be a structural no-op: the FSM rejects
`Completed → Completed` and the helper returns `Ok(None)`
without modifying any row.

**Justification.** Iter54 of the live-e2e
`realistic_session_lifecycle` reproduced a UX defect in which
`IntegrationMergeCompleted` had been audited (Phase 2 succeeded,
`refs/heads/main` pointed at the merge commit on disk) but the
synthetic coordinator task remained in `Running` forever and the
parent initiative remained in `Executing` forever. Operators
read the dashboard as "stuck initiative" and started killing the
kernel mid-flight. Without this invariant, the orchestrator's
"I'm done" signal never advances either FSM and the only path to
a terminal state is operator-driven `abort_initiative` — which
loses the success/failure distinction in the audit chain and
prevents any downstream automation that triggers on
`InitiativeStateChanged → Completed`.

**Scenario.** A 2-task initiative (`exec` + `reviewer`) reaches
the merge phase. The orchestrator submits `IntegrationMerge`
referencing the orchestrator worktree `head_sha`. Phase 2
fast-forwards `refs/heads/main` from `base_sha → head_sha`.
Inside one transaction the kernel: (1) calls
`transition_task_in_tx` with `(synthetic_task_id, Completed,
None, Kernel)`, which closes the synthetic task's
`subtask_activations` row and resets the per-initiative
no-progress counter; (2) reads `initiatives.state` and confirms
`Executing`; (3) UPDATEs `initiatives.state = 'Completed',
completed_at = now`. After commit, the kernel emits
`InitiativeStateChanged { initiative_id, from_state:
"Executing", to_state: "Completed" }` and rebinds
`task_state = TaskState::Completed` so the
`IntentResponse.task_state` returned to the orchestrator is
`Completed`, not `Running`. Total cascade wall-time on a healthy
SQLite store: < 5 ms.

**Witness.**
* `raxis/kernel/src/handlers/intent.rs::tests::finalize_cascades_executing_initiative_and_running_synthetic_to_completed`
  seeds an `Executing` initiative + a `Running` synthetic task,
  invokes `finalize_integration_merge_completion`, asserts the
  return is `Ok(Some(("Executing", "Completed")))` AND that the
  on-disk `tasks.state` and `initiatives.state` rows both reflect
  `Completed`.
* `raxis/kernel/src/handlers/intent.rs::tests::finalize_is_idempotent_against_already_completed_synthetic_task`
  pre-seeds both rows in `Completed`, invokes the helper, asserts
  the return is `Ok(None)` and neither row changes — the
  recovery-sweep idempotency contract.

**Canonical home.** `v2/v2-deep-spec.md §IntegrationMerge`,
`v2/v2_extended_gaps.md §1.2` (host-side fast-forward),
`v1/kernel-store.md §2` (INV-STORE-02 single-transaction
atomicity).

---

### INV-INITIATIVE-COMPLETES-WHEN-INTEGRATION-MERGE-SUCCEEDS-01 — IntegrationMerge success drives the parent initiative to Completed

**Statement.** When the IntegrationMerge cascade above
(`INV-INTEGRATION-MERGE-COMPLETES-SYNTHETIC-TASK-01`) fires
successfully, the parent initiative MUST transition from
`Executing` to `Completed` in the **same SQL transaction** as
the synthetic-task FSM transition. The
`initiatives.completed_at` column MUST be stamped to the same
`unix_now_secs()` reading used for the task transition's
`transitioned_at` column, so audit-replay tooling sees the two
timestamps in lockstep.

The transition MUST emit a single
`AuditEventKind::InitiativeStateChanged { from_state:
"Executing", to_state: "Completed" }` paired-write
(post-commit, mirroring every other handler in `intent.rs`) so
operator dashboards and notification subscribers
(`crates/dashboard-kernel/src/notification_filter.rs`) see the
state change without polling.

The transition MUST be a **no-op** when the initiative is
already in any non-`Executing` state at cascade time —
specifically `Aborted`, `Failed`, `Blocked`, or `Completed`.
Operator-driven `abort_initiative` (`InitiativeAborted` audit,
`lifecycle.rs §abort_initiative`) and recovery-pass writebacks
must not be regressed by a late-arriving merge intent. The
helper returns `Ok(None)` in those cases and the synthetic-task
FSM transition (which IS independent of initiative state)
either commits or is itself rejected by the FSM, depending on
the synthetic task's prior state.

**Justification.** Without the cascade an initiative whose
merge has succeeded never reaches a terminal state in the
kernel store. Downstream consumers — dashboard "completed
today" widgets, notification subscribers, the `worktree_gc`
sweeper that retires merged worktrees, the operator's
"initiatives I no longer have to think about" mental model —
all break. The audit chain also lacks the
`InitiativeStateChanged → Completed` row that
`crates/dashboard/src/data.rs` and the V3 OTel collectors
expect to count toward "successful initiatives" metrics.

This invariant pairs with
`INV-INTEGRATION-MERGE-COMPLETES-SYNTHETIC-TASK-01` so the two
FSMs (initiative + synthetic task) advance atomically — partial
states (synthetic task `Completed`, initiative still
`Executing`) MUST NOT exist on disk for any operator-visible
duration.

**Witness.**
* `raxis/kernel/src/handlers/intent.rs::tests::finalize_cascades_executing_initiative_and_running_synthetic_to_completed`
  asserts the same atomic transition as above, with the
  initiative-side check explicit
  (`read_initiative_state(...) == "Completed"`).
* `raxis/kernel/src/handlers/intent.rs::tests::finalize_skips_initiative_update_when_initiative_is_aborted`
  seeds the initiative as `Aborted` + the synthetic task as
  `Running`, invokes the helper, asserts the return is `Ok(None)`
  and `initiatives.state` remains `"Aborted"` — the
  no-regress-out-of-terminal contract.
* `raxis/kernel/src/handlers/intent.rs::tests::finalize_handles_missing_initiative_row_gracefully`
  exercises the `QueryReturnedNoRows` path so a forensics-
  deleted initiative cannot crash the cascade.

**Canonical home.** `v2/v2-deep-spec.md §IntegrationMerge`,
`v1/kernel-core.md §2.4` (initiative FSM —
`Executing → Completed` is the canonical success edge),
`v1/kernel-store.md §2` (INV-STORE-02 multi-table atomicity).

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

### INV-SCHED-02 — `release_budget` is called on every terminal-state transition

**Statement.** Every code path that transitions a task into a
terminal state (`Completed` / `Failed` / `Aborted` / `Cancelled`)
MUST call `scheduler::budget::release_budget_in_tx` (or the
standalone `release_budget` for crash-recovery sweeps) inside the
SAME `Connection::transaction()` borrow that performs the FSM
flip. The exhaustive v2 list:

* `handlers/intent::commit_task_completion`
  (`Running → Completed` via `IntentKind::CompleteTask`),
* `handlers/intent::handle_report_failure`
  (`Admitted | Running → Failed` via `IntentKind::ReportFailure`),
* `initiatives::lifecycle::abort_task`
  (operator-driven `* → Aborted` for a single task),
* `initiatives::lifecycle::abort_initiative`
  (operator-driven bulk `* → Cancelled` for every non-terminal
  task on the initiative).

**Justification.** Lane bookkeeping (`lane_budget_reservations`)
caps the total `estimated_cost` reserved across all live tasks on
a lane (`v1/kernel-store.md` §2.5.1.1 Pattern A). The
`reserve_budget_in_tx` write at intent admission charges the cap;
without a paired `release_budget_in_tx` at terminal transition the
cap is charged monotonically. After enough sub-task completions on
a workspace lane, the IntegrationMerge synthetic coordinator-task
admitted by `auto_spawn_orchestrator_session_in_tx` cannot reserve
its merge-cost slice, every IntegrationMerge intent is rejected
with `FAIL_BUDGET_EXCEEDED`, and the orchestrator dies after
`planner_session_revoked_on_exit` without respawning — a hard
hang detectable only by the harness-side deadline. The "in the
same tx" qualifier preserves INV-STORE-02: a crash mid-handler
must leave either both writes durable (task is terminal AND its
reservation is freed) or both rolled back (task is pre-terminal
AND its reservation is still charged).

**Scenario.** Iter 38 of `realistic_session_lifecycle`
(`/private/tmp/raxis-fix-loop-respawn2-33043/raxis`, 2026-05-13).
Eight sub-tasks completed cleanly (8 × `TaskCompleted`,
0 × `release_budget`) on the workspace lane; the orchestrator
respawned for the IntegrationMerge step; the
`reserve_budget_in_tx` call on the synthetic coordinator-task
returned `BudgetExceeded`; the intent handler rejected with
`FailBudgetExceeded`; the orchestrator exited; no respawn fired;
the harness polled silently for 10+ minutes until killed.
Post-fix every TaskCompleted decrements the lane charge so the
coordinator task's reservation fits.

---

### INV-SCHED-03 — Every plan's `[workspace] lane_id` must be declared in the active policy's `[[lanes]]`

**Statement.** A plan submitted to `lifecycle::approve_plan` is
admitted if and only if its `[workspace] lane_id` matches the
`lane_id` of some `[[lanes]]` entry in the operator-signed policy
bundle that's authoritative at approval time. The check fires in
`lifecycle::validate_workspace_lane_in_policy`, called **before**
`BEGIN TRANSACTION`. Failure surfaces as
`LifecycleError::PlanLaneNotInPolicy { workspace_lane,
declared_lanes, suggestion }`. The validator runs in inert mode
when `policy_lanes` is empty (test-fixture path used by
`approve_plan_for_test`); production `handle_approve_plan` always
passes the bundle's full `lanes()` slice, which is non-empty
(genesis emits the `default` lane).

**Justification.** The scheduler resolves the per-task `lane_id`
against the policy on every Phase-C budget admission via
`scheduler::lane::lane_config_for_row`. If the lane is absent,
that call returns `SchedulerError::NoLaneAssigned`,
`scheduler::budget::reserve_budget_in_tx` propagates it, and
`handlers/intent.rs::run_phase_c` Step 10's
`map_err(|_| FailBudgetExceeded)` rewrites it to the wire-level
`PlannerErrorCode::FailBudgetExceeded`. Crucially, the
**early-dispatch** handlers (`ActivateSubTask`, `CompleteTask`,
`SubmitReview`, `RetrySubTask`, `StructuredOutput`,
`ReportFailure`) bypass the budget check entirely — sub-task
admission flows succeed silently against an unregistered lane,
masking the gap until the synthetic IntegrationMerge
coordinator-task admitted by
`auto_spawn_orchestrator_session_in_tx` reaches Phase C and
fails. That asymmetry surfaces as a deadline-only silent hang in
the live-e2e harness: every sub-task completes, the orchestrator
session for IntegrationMerge exits without emitting
`IntegrationMergeCompleted`, and the harness's
`poll_for_dual_lifecycle_completion` blocks until its
`RAXIS_E2E_REALISTIC_DEADLINE_SECS` deadline.

Pulling the check forward to `approve_plan` time gives the
operator an actionable
`LifecycleError::PlanLaneNotInPolicy` diagnostic at the moment
of submission. The error string enumerates every declared
`lane_id` and a remediation suggestion (either change the plan
to use a declared lane, or advance the policy epoch with a
new `[[lanes]]` entry that matches).

This is the structural-contract sister of INV-SCHED-02: that
invariant pins lane-bookkeeping atomicity at terminal-state
transitions; this one pins lane-existence at admission, so the
bookkeeping has a concrete `(max_concurrent_tasks,
max_cost_per_epoch)` ceiling to enforce against.

**Scenario.** Iter 39 of `realistic_session_lifecycle`
(`/private/tmp/raxis-fix-loop-respawn2-33043/raxis`, 2026-05-13).
The realistic-scenario plan declares
`[workspace] lane_id = "e2e-realistic-lane"` (primary) and
`"e2e-realistic-sibling-lane"` (sibling). The genesis-emitted
bootstrap `policy.toml` declared only the `default` lane; the
test harness's `enable_gateway_in_policy` appended `[gateway]` +
`[[providers]]` + `[egress]` but no `[[lanes]]`. Result: every
`ActivateSubTask` / `CompleteTask` succeeded silently against
the unregistered lanes; the sibling's first IntegrationMerge
intent was rejected with `FailBudgetExceeded` after a **single**
sibling-task completion (budget never accumulated near a cap —
the lane lookup itself failed); the orchestrator's
planner-session exited cleanly; no respawn fired; the harness
polled silently until the 3900 s deadline. Post-fix
`approve_plan` rejects the plan with
`PlanLaneNotInPolicy("e2e-realistic-sibling-lane", declared:
"default", ...)` and the harness registers the lanes in the
same fix commit so the live-e2e runs to completion.

## §6.5 — Orchestrator respawn ceiling (INV-ORCH-RESPAWN-*)

Canonical home: `v2/v2-deep-spec.md` §Step 12 (V2.5b extension —
Orchestrator no-progress respawn counter). The pre-existing
bounded-capability invariants (`INV-CONVERGENCE-01` review-round
cap, `crash_count` Executor-Failed cap, `max_orch_turns`
per-session fetch quota) do **not** cover the loop pattern where
the Orchestrator cleanly exits on a kernel-rejected intent
without any task FSM transition — none of those counters
advances on a clean exit, so the orchestrator-respawn loop runs
silently and unbounded until the harness-side wall-clock
deadline fires. This section closes that gap as a
structural backstop on top of the higher-fidelity NNSP fix
(`INV-PLANNER-ORCH-RETRY-ON-REJECT-01`,
`INV-KSB-AGGREGATE-VERDICT-PROJECTION-01`) and the kernel's
fail-closed admission gate
(`INV-RETRY-FROM-COMPLETED-REVIEW-REJECTED-01`).

### INV-ORCH-RESPAWN-NO-PROGRESS-CEILING-01 — Per-initiative respawn ceiling without task FSM progress

**Statement.** For any initiative `i`, the kernel MUST NOT spawn
more than `MAX_ORCH_NO_PROGRESS_RESPAWNS` (default 3)
orchestrator sessions for `i` without an intervening task FSM
transition on any task belonging to `i`. The counter
(`initiatives.orchestrator_no_progress_respawn_count`, INTEGER
NOT NULL DEFAULT 0, added by Migration 19) is maintained as
follows:

* **Increment.** Every `respawn_orchestrator_for_initiative`
  call (the post-exit respawn path in
  `kernel/src/session_spawn_orchestrator.rs`) calls
  `orch_respawn_ceiling::increment_no_progress_count_in_tx`
  **before** issuing the new orchestrator spawn. The increment
  is paired with a read of the post-increment value, returned as
  `CeilingOutcome::Permitted { new_count }` if
  `new_count <= MAX_ORCH_NO_PROGRESS_RESPAWNS` or
  `CeilingOutcome::Exceeded { new_count, attempts }` otherwise.
* **Reset.** Every legal task FSM transition in
  `transition_task_in_tx` (kernel/src/initiatives/
  task_transitions.rs) — `Admitted → Running`, `Running →
  Completed`, `Running → Failed`, `* → Aborted`, `* →
  Cancelled` — calls
  `orch_respawn_ceiling::reset_no_progress_count_in_tx` on the
  parent initiative inside the SAME transaction as the FSM flip.
  Any forward FSM progress restarts the budget from 0.
* **Ceiling enforcement.** When the increment returns
  `Exceeded`, the same transaction updates
  `initiatives.state = 'Failed'` and `initiatives.completed_at`
  to the current epoch second; the post-commit async task emits
  `AuditEventKind::OrchestratorRespawnCeilingExceeded
  { initiative_id, attempts }` to the audit chain
  (paired-write contract documented in
  `audit-paired-writes.md §4.1`/`§4.3`); the spawn returns
  early with `orchestrator_respawn_skipped reason=
  "no-progress respawn ceiling exceeded"`.

After ceiling-exceeded, `respawn_orchestrator_for_initiative`
short-circuits on subsequent invocations because the
`initiatives.state = 'Failed'` row no longer satisfies the
"orchestrator-eligible initiative" predicate at the call site.
The audit event is the operator-facing failure surface; the
dashboard's notification filter promotes
`OrchestratorRespawnCeilingExceeded` to `Critical` priority via
`raxis-dashboard-kernel::notification_filter::
notification_priority`.

**Justification.** The Orchestrator runs as a one-shot
planner-session per turn: it enters with a fresh KSB, the LLM
proposes a terminal tool call (`activate_subtask`,
`retry_subtask`, `integration_merge`, etc.), the kernel
admits or rejects, the session exits, and the post-exit hook
optionally respawns. None of the pre-existing
bounded-capability counters fires on the "kernel rejected the
intent" path:

* `INV-CONVERGENCE-01` review-round cap counts review rounds,
  not orchestrator decision-cycles. A Completed-with-aggregate-
  Pending KSB never crosses a review-round boundary, so the cap
  stays inert.
* `crash_count` increments only on Executor `Failed` task FSM
  transitions. A clean orchestrator exit on an admit-rejected
  intent never touches Executor state, so this counter stays
  at 0.
* `max_orch_turns` (`INV-PLANNER-HARNESS-01`) caps planner
  fetches **per session**. Every fresh respawn starts with a
  fresh quota, so a no-progress respawn loop charges 0 against
  this ceiling.

Iter42 reproduced the failure mode in production: 45
`SessionVmSpawned` in 18 minutes, zero
`ReviewAggregationCompleted`, zero
`ExecutorRespawnFromReviewRejection`, zero `TaskStateChanged`.
The orchestrator NNSP-aggregate fix
(`INV-PLANNER-ORCH-RETRY-ON-REJECT-01` /
`INV-KSB-AGGREGATE-VERDICT-PROJECTION-01`) closes the
**immediate** loop class for one specific upstream cause
(NNSP rule racing the kernel aggregator). This invariant adds
the **structural** backstop so any future regression with a
different upstream cause (new NNSP bug, projection drift, LLM
hallucination on a fresh aggregator surface) is still
guaranteed to bound worst-case observability + operator
recovery surface to four consecutive respawns, after which the
initiative is loudly Failed with an audited reason.

The reset-on-FSM-transition policy is deliberate: any forward
progress (a Reviewer voting, an Executor activation
admitting, an integration-merge completing) is taken as a
signal the orchestrator is making real decisions and the
counter resets. Only the pathological "respawn → reject →
respawn" treadmill — by construction unable to advance the
FSM — accumulates the counter.

**Scenario.** Iter42 second run (`/tmp/raxis-e2e-realistic-
iter42.log`, 2026-05-13). The orchestrator NNSP rule fires
`retry_subtask { subtask_task_id: "lint-defect" }`. The kernel
admits the intent against the activation row's
`activation_state=Completed, review_reject_count=0` and rejects
with `RetrySubTaskRejectedNotRetryable` (per
`INV-RETRY-FROM-COMPLETED-REVIEW-REJECTED-01`'s fail-closed
default). The session exits clean; the post-exit hook fires
`respawn_orchestrator_for_initiative`; Step 1b calls
`increment_no_progress_count_in_tx` → returns
`CeilingOutcome::Permitted { new_count: 1 }`; the new
orchestrator spawns and re-reads the same KSB and fires the
same `retry_subtask`. Three more iterations:
`Permitted { 2 }`, `Permitted { 3 }`,
`Permitted { 4 }` (= MAX). On the fifth call, the
increment returns `Exceeded { attempts: 5 }`; the same
transaction sets `initiatives.state = 'Failed'`,
`completed_at = <now>`; the post-commit task emits
`OrchestratorRespawnCeilingExceeded { initiative_id, attempts: 5
}` to the audit chain; the spawn returns early with
`orchestrator_respawn_skipped reason="no-progress respawn
ceiling exceeded"`. The dashboard renders a Critical-priority
notification; the operator opens the audit log, sees the
ceiling event, and either operator-aborts the initiative or
intervenes upstream. No silent harness-deadline hang.

A second scenario: the NNSP fix lands and the orchestrator
correctly waits on `aggregate=AtLeastOneRejected` before
firing `retry_subtask`. The reviewer pass aggregates,
`subtask_activations.review_reject_count` bumps to 1, the
`RetrySubTask` admits, and the Executor activation flips
back to `Running`. The FSM transition fires
`transition_task_in_tx`, which calls
`reset_no_progress_count_in_tx` in the same transaction,
dropping `orchestrator_no_progress_respawn_count` back to 0.
The ceiling never fires for the legitimate retry path; it
remains armed as a backstop for the next pathological loop.

**Pinned regression tests.**

* `kernel/src/orch_respawn_ceiling.rs`:
  - `fresh_initiative_increments_from_zero_to_one`
  - `ceiling_exceeded_after_max_plus_one_increments`
  - `reset_drops_count_back_to_zero`
  - `increment_against_missing_initiative_is_permitted_no_op`
  - `reset_against_zero_count_is_idempotent`
  - `lookup_initiative_id_for_task_resolves_existing_task`
  - `lookup_initiative_id_for_missing_task_returns_none`
  - `build_ceiling_event_returns_none_on_permitted`
  - `build_ceiling_event_returns_some_on_exceeded`
* `kernel/src/initiatives/task_transitions.rs`: the existing
  `transition_task_in_tx` test suite re-runs against the
  reset-on-transition hook (the reset is idempotent against a
  zero count per the pinned test above, so legacy tests pass
  unchanged).
* `crates/store/tests/migration_sql_dumps.rs`: Migration 19
  drift-detector — re-running with
  `RAXIS_DUMP_MIGRATION_SQL=1` regenerates the SQL file
  byte-for-byte, and the test panics on any drift.

**Canonical home.** `kernel/src/orch_respawn_ceiling.rs` (module
implementing the predicate + audit-event constructor);
`kernel/src/session_spawn_orchestrator.rs` Step 1b (increment +
ceiling check + state update); `kernel/src/initiatives/
task_transitions.rs` (reset on FSM transition);
`crates/audit/src/event.rs::AuditEventKind::
OrchestratorRespawnCeilingExceeded`;
`crates/dashboard-kernel/src/notification_filter.rs`
(`Critical` priority promotion);
`crates/store/src/migration.rs::apply_migration_19` +
`render_migration_19_ddl` (schema migration);
`specs/v2/v2-deep-spec.md §Step 12` V2.5b extension;
`specs/v2/audit-paired-writes.md §4.1`/`§4.3`
(`OrchestratorRespawnCeilingExceeded` paired-class registration).

---

---

## §6.6 — Auto-escalation (INV-ESCALATION-AUTO-*)

V2.5b extension. The orchestrator-respawn no-progress ceiling
(`INV-ORCH-RESPAWN-NO-PROGRESS-CEILING-01`, `§6.5`) is fail-loud
but fire-and-forget — operators get a notification but no tracked
approve/deny workflow. The orchestrator itself cannot escalate
(it's the agent that's structurally confused; it just exits
cleanly when its intent is rejected), so the kernel auto-creates
an `escalations` row when the ceiling exceeds. The new class
`EscalationClass::LogicalDeadlock` carries `initiator = 'Kernel'`
(Migration 20 added the `initiator` column to `escalations`) and
is the FIRST V2/V2.5 escalation class with kernel admission.

Invariant body covers:

  * Same-transaction insert (`escalations` row + `initiatives.state =
    'Failed'` flip in one BEGIN..COMMIT).
  * Operator-approve handler (counter reset + initiative back to
    `Executing` + post-commit
    `OperatorApprovedRespawnEscalation` audit + scheduled fresh
    orchestrator respawn).
  * Operator-deny handler (preserves `Failed` + post-commit
    `OperatorDeniedRespawnEscalation` audit; counter NOT reset).
  * Defense-in-depth admission rejection of any planner-submitted
    `EscalationRequest { class: LogicalDeadlock }` (the kernel-side
    approve handler additionally rejects rows whose `initiator !=
    'Kernel'`).

---

### INV-ORCH-STRANDED-INITIATIVE-RESPAWN-01 — Post-exit hook respawns the orchestrator on any non-terminal initiative with no in-flight work

**Statement.** The orchestrator-session post-exit hook in
`kernel/src/session_spawn_orchestrator.rs::after_session_revoked`
MUST return `PostExitAction::OrchestratorRespawn` whenever
ALL of the following hold for the exiting session's initiative
(`session.initiative_id`):

* `initiatives.state = 'Executing'` (non-terminal — terminal
  states `Completed` / `Failed` / `Aborted` and pre-execution
  states `Draft` / `ApprovedPlan` / `Blocked` MUST NOT trigger
  the respawn; `Blocked` is operator-owned, the others are
  by-construction inert);
* there is NO row in `subtask_activations` with
  `initiative_id = session.initiative_id` whose
  `activation_state = 'Active'` (no in-flight worker);
* there is NO row in `subtask_activations` with the same
  `initiative_id` whose `activation_state = 'PendingActivation'`
  (Mode A's narrow predicate is already covered separately;
  this clause activates ONLY when Mode A would have
  short-circuited).

When all three hold the kernel MUST log a single structured
trigger line keyed on the new event name
`orchestrator_stranded_initiative_respawn_trigger` carrying the
exiting `session_id`, the `initiative_id`, and the cite
`INV-ORCH-STRANDED-INITIATIVE-RESPAWN-01`, then proceed through
`respawn_orchestrator_for_initiative` exactly the same way
Mode A does — including the
`orch_respawn_ceiling::increment_no_progress_count_in_tx` call
that is the storm guard.

**Justification.** Mode A's
`pending_exists && !active_exists` predicate covers the common
mid-DAG case where an Executor / Reviewer just completed and
left a `PendingActivation` row for the orchestrator to chase.
It does NOT cover the **stranded-initiative** case: an
`Executing` initiative with NO `PendingActivation` row and
NO `Active` worker, where the only path forward is an
orchestrator-side terminal decision (`ReportFailure` for a
`Failed` task that has exhausted
`max_crash_retries`, `IntegrationMerge` for a DAG whose
executors all `Completed`, `AbortInitiative` for a catastrophic
preflight failure). In v2, the orchestrator is the ONLY agent
that can move an `Executing` initiative toward terminality;
without a respawn the kernel has no way to re-enter that
decision surface and the harness sees an indefinite hang.

Iter54-N reproduced the wedge end-to-end on the
`realistic_session_lifecycle` test:

1. The realistic-scenario plan's `lint-runner` Round-2 path
   (Reviewer-rejection → fresh executor must read the captured
   output, locate the defective file across three language
   trees, edit, re-run `scripts/check.sh`, commit) exhausted the
   per-task `max_turns=30` budget on every cold-start retry.
   The kernel paired each `TaskFailedOnWorkerPrematureExit` with
   `worker_post_exit_respawn_trigger`, the orchestrator
   correctly emitted `RetrySubTask` (per
   `INV-PLANNER-ORCH-RETRY-PRIORITY-OVER-ACTIVATE-01`), and the
   kernel admitted three retries (per
   `INV-RETRY-FROM-COMPLETED-REVIEW-REJECTED-01` shape with
   `crash_retry_count` advancing 1 → 2 → 3 against
   `max_crash_retries=3`).
2. After the fourth `Failed` activation (no admissible retry
   left — `crash_retry_count` would exceed the ceiling), the
   orchestrator's LLM emitted a non-terminal
   `StructuredOutput { kind: "diagnostic_flag", payload_bytes:
   377, actor: "orchestrator" }` then went idle. The planner
   guest exited with `dispatch loop terminated with Idle (no
   terminal tool fired)`, exit code 5.
3. The kernel observed `planner_session_revoked_on_exit`. With
   only Mode A in force the post-exit hook short-circuited:
   `pending_exists = false` (no fresh activation row was ever
   created — the orchestrator never emitted ActivateSubTask /
   RetrySubTask), `active_exists = false` (lint-runner is now
   `Failed`, not `Active`). No respawn fired, no
   `orch_respawn_ceiling` increment fired. The kernel went
   silent for the rest of the test wall-clock; the harness
   could not observe a terminal initiative state.

The fix is the **structural** counterpart to
`INV-ORCH-RESPAWN-NO-PROGRESS-CEILING-01`: the ceiling
guarantees the kernel cannot respawn forever without progress,
but it can only fire if `respawn_orchestrator_for_initiative`
is actually called. Mode A+ is the missing call site that
ensures the ceiling fires on the stranded-initiative path. With
Mode A+ in force, the wedge resolves in at most three
additional respawns: each respawn that re-emits
`diagnostic_flag` (or any other non-terminal) advances the
`orchestrator_no_progress_respawn_count` counter (no FSM
transition resets it because no FSM transition occurs); the
third increment trips
`orch_respawn_ceiling::CeilingOutcome::Exceeded`,
`initiatives.state = 'Failed'` lands in the same transaction,
and `OrchestratorRespawnCeilingExceeded` is committed to the
audit chain — the same operator-facing failure surface the
realistic-scenario harness's
`scan_audit_for_orchestrator_respawn_ceiling_exceeded`
fast-fail (per `INV-LIVE-E2E-HARNESS-NO-INDEFINITE-WAIT-01`
audit-poll extension) panics on within seconds.

**Scenario.** Iter54-N reproduction (`/tmp/raxis-e2e-realistic-
iter54.log` 2026-05-14, kernel stderr at
`<data_dir>/kernel.stderr.log`): primary-initiative
`019e25c8-89ef-7c73-9d1d-1c112a1df7ca` reaches the
stranded state (`initiatives.state = 'Executing'`,
`tasks.lint-runner = 'Failed'`, all other tasks `Completed`,
zero rows in `subtask_activations` with
`activation_state IN ('Active', 'PendingActivation')` for this
initiative). Without Mode A+ the kernel emits zero further
events for ~27 minutes until the test wrapper is SIGTERMed.
With Mode A+ the kernel emits an
`orchestrator_stranded_initiative_respawn_trigger` log line on
the first session-revoke, the orchestrator respawns, the LLM
re-emits a non-terminal intent (counter += 1), session revokes,
counter += 1 (still no FSM progress), respawn 3 trips the
ceiling, `OrchestratorRespawnCeilingExceeded` lands in audit,
the harness's audit-poll fast-fail panics with the upstream
hypothesis, and the operator sees the failure within ~90s
instead of after the full deadline ceiling.

**Witness.** Hand-verified against the iter54-N kernel.stderr
forensic capture cited above; mechanical regression coverage
follows in iter55+ via a focused unit test that builds a
`subtask_activations` snapshot matching the stranded shape
(no `Active`, no `PendingActivation`, parent initiative
`Executing`) and asserts `after_session_revoked` returns
`Some(PostExitAction::OrchestratorRespawn)`. The integration-
level witness is the realistic-scenario test itself: with this
invariant in force the test transitions from "indefinite hang"
to "loud `OrchestratorRespawnCeilingExceeded` failure within
the audit-poll fast-fail window" on any future regression of
the upstream `lint-runner` Round-2 budget exhaustion (or any
other stranded-initiative cause).

**Canonical home.**
`kernel/src/session_spawn_orchestrator.rs::after_session_revoked`
(Mode A+ branch carrying the
`INV-ORCH-STRANDED-INITIATIVE-RESPAWN-01` cite in its inline
comment + the structured trigger log line).

---

### INV-ESCALATION-AUTO-LOGICAL-DEADLOCK-01 — Kernel-initiated LogicalDeadlock escalation paired with orch-respawn ceiling

**Statement.** When `respawn_orchestrator_for_initiative` observes
`CeilingOutcome::Exceeded` from
`orch_respawn_ceiling::increment_no_progress_count_in_tx`, the
kernel MUST, in ONE SQLite transaction:

  1. INSERT a row into `escalations` with `class = 'LogicalDeadlock'`,
     `initiator = 'Kernel'`, `status = 'Pending'`, FK columns
     (`session_id`, `task_id`, `lineage_id`) populated from the
     most recently FSM-touched task on the failing initiative
     whose `session_id IS NOT NULL`. The
     `requested_scope_json` carries the
     `RequestedEscalationScope::LogicalDeadlock { initiative_id,
     attempts, window_secs, last_intent_kind, last_rejection_reason }`
     payload (text fields capped at
     `MAX_LOGICAL_DEADLOCK_REASON_LEN` = 1 KiB on a UTF-8
     boundary).
  2. UPDATE `initiatives` SET `state = 'Failed'`,
     `completed_at = now()` for the offending initiative.

After commit, the kernel emits
`AuditEventKind::OrchestratorRespawnCeilingExceeded`
post-commit per the §11.6 paired-write contract.

The operator-approval handler (`approve_logical_deadlock_escalation_in_tx`
in `kernel/src/orch_respawn_ceiling.rs`) MUST, in ONE SQLite
transaction, refuse any row that is not
`(class = 'LogicalDeadlock' AND initiator = 'Kernel' AND
status = 'Pending')`. On a valid row it:

  1. UPDATE `escalations` SET `status = 'Approved'`,
     `resolved_at = now()`.
  2. UPDATE `initiatives` SET `orchestrator_no_progress_respawn_count = 0`.
  3. UPDATE `initiatives` SET `state = 'Executing'`,
     `completed_at = NULL` (transitions back from `Failed`).

After commit, the kernel emits
`AuditEventKind::OperatorApprovedRespawnEscalation { initiative_id,
escalation_id, operator_id }` and schedules a fresh orchestrator
respawn so the "approve = retry" semantic observably fires (the
respawn driver's own ceiling check runs on entry, but starts at 0
because step 2 just reset it).

The operator-deny handler (`deny_logical_deadlock_escalation_in_tx`)
MUST, in ONE SQLite transaction, refuse non-matching rows by the
same `(class, initiator, status)` triple test. On a valid row it
ONLY UPDATEs `escalations.status = 'Denied'` (and `resolution_notes`
if a reason was carried) — the initiative stays `Failed`, the
counter stays at its post-ceiling value, no respawn is scheduled.
After commit the kernel emits
`AuditEventKind::OperatorDeniedRespawnEscalation { initiative_id,
escalation_id, operator_id }`.

The planner-side `handlers/escalation::handle` MUST reject any
`EscalationRequest { class: LogicalDeadlock }` at admission. This
is defense-in-depth — the operator-approval handler additionally
rejects rows whose `initiator` is not `'Kernel'`, but the planner-
side rejection prevents the row from being created in the first
place.

**Justification.** The pre-V2.5b ceiling event left the operator
with a notification but no tracked workflow: there was no canonical
"this initiative is structurally stuck; here's what to do about
it" surface. The auto-escalation pairs the structural failure
with an operator decision point so the recovery path is a single
approve / deny click rather than a manual retry pipeline. The
kernel-only initiator constraint matters because `LogicalDeadlock`
has no capability semantics — the approval IS the action, no
approval-token is minted, no scope is bound for downstream intent
consumption — so a planner-submitted row is unambiguously a
misuse.

The same-transaction pairing of escalation-INSERT + initiative-
Failed UPDATE is the load-bearing piece: an operator racing the
audit event MUST observe a non-empty escalation row, never
`Failed` without an actionable surface. A crash between either
write leaves both rolled back (transactional atomicity); a crash
after commit leaves both written (the audit emit is best-effort
post-commit per `INV-AUDIT-PAIRED-06`).

The text-field byte cap (`MAX_LOGICAL_DEADLOCK_REASON_LEN` = 1
KiB) bounds audit-row size against a hostile orchestrator that
loops on a pathologically long intent shape. UTF-8 boundary
truncation prevents storing invalid UTF-8 in the audit chain.

**Scenario.** An iter42-class regression re-introduces the
no-progress orchestrator loop (orchestrator submits a rejected
`RetrySubTask` intent, exits cleanly, post-exit hook respawns;
loop repeats). On the 4th respawn attempt, the kernel's
`increment_no_progress_count_in_tx` returns
`CeilingOutcome::Exceeded { count_after_increment: 4,
max_attempts: 3 }`. In one transaction, the kernel inserts an
`escalations` row (class `'LogicalDeadlock'`, initiator
`'Kernel'`, status `'Pending'`) keyed to the most-recently-FSM-
touched task on the initiative, then flips
`initiatives.state = 'Failed'`. After commit, the kernel emits
`OrchestratorRespawnCeilingExceeded`. The operator's dashboard
surfaces the new escalation under "Pending escalations" with
class `LogicalDeadlock` and the failure-classification
justification. The operator clicks "approve"; the kernel
transitions the initiative back to `Executing`, resets the
counter, emits `OperatorApprovedRespawnEscalation`, and schedules
a fresh respawn. The new orchestrator session boots with a
fresh counter (0 / 3) and the post-iter42 NNSP fix in
`9ecf2fa` re-routes the `RetrySubTask` decision into a different
intent shape that admits — the loop is broken.

If the operator instead clicks "deny", the escalation flips to
`'Denied'`, the initiative stays `Failed`, and the operator is
expected to investigate the upstream cause manually (e.g. the
plan asked for an impossible task; the orchestrator's NNSP has
a regression specific to this plan's `policy.toml`; etc.).

**Canonical home.** `v2/v2-deep-spec.md §Step 12 V2.5b extension`
+ `raxis-concepts/07-escalations.md §The six escalation classes`.

**Implementation references.**

  * `crates/types/src/escalation.rs` — `EscalationClass::LogicalDeadlock`,
    `RequestedEscalationScope::LogicalDeadlock`,
    `MAX_LOGICAL_DEADLOCK_REASON_LEN`.
  * `crates/store/src/migration.rs` — `apply_migration_20`,
    `render_migration_20_ddl`.
  * `crates/store/migrations/0020_v2_escalations_initiator.sql` —
    DDL artefact.
  * `kernel/src/orch_respawn_ceiling.rs` —
    `insert_logical_deadlock_escalation_in_tx`,
    `approve_logical_deadlock_escalation_in_tx`,
    `deny_logical_deadlock_escalation_in_tx`,
    `truncate_for_scope`.
  * `kernel/src/session_spawn_orchestrator.rs` — extension to the
    ceiling-exceeded branch wiring the auto-create + paired-write
    order.
  * `kernel/src/ipc/operator.rs` — `handle_approve_escalation`
    (pre-classifies + dispatches),
    `handle_approve_logical_deadlock`,
    `handle_deny_logical_deadlock`,
    `lookup_escalation_class_initiator`.
  * `crates/audit/src/event.rs` —
    `AuditEventKind::OperatorApprovedRespawnEscalation`,
    `AuditEventKind::OperatorDeniedRespawnEscalation`.
  * `crates/dashboard-kernel/src/notification_filter.rs` —
    promotes both new audit events to `Medium` priority.
  * `kernel/tests/orch_respawn_ceiling_escalation.rs` — witness
    test (7 cases) covering schema, class round-trip, audit
    priority, ceiling auto-create, approve, deny, FSM idempotency.

---

## §6.7 — KSB capabilities envelope (INV-KSB-CAPABILITIES-*)

V2.6 extension. The KSB historically surfaced raw kernel state
(DAG, reviewer verdicts, base SHA, …) but left the **admission
predicates** invisible to the LLM — the planner had to learn-by-
rejection that e.g. `RetrySubTask` against a `Completed` activation
with `review_reject_count = 0` is inadmissible. The iter44
leading-indicator metric `IntentAdmitPredicateEvaluatedTotal{
admissible="false"}` measures exactly this rate of LLM blind-asks.

The capabilities envelope (added to [`raxis_ksb::KsbSnapshot`] as
the `Option<Capabilities>` field) projects the admission predicate
verdicts into the system prompt so the LLM consults them BEFORE
issuing the intent. The envelope is role-scoped — the orchestrator
sees per-task admit verdicts (it's the only role authorised to
issue `RetrySubTask`); the executor sees its own task envelope
only; the reviewer sees identity-only artifact context. The shape
is enforced by the type system ([`raxis_ksb::Capabilities`] is an
enum with three disjoint variants).

Invariant body covers:

  * Predicate-parity: the KSB row's `retry_admissible` boolean is
    derived from the SAME pub fn the kernel handler calls
    (`raxis_types::intent_admit::admit_retry_subtask_check`).
  * Role-scope: each role's envelope variant carries ONLY the
    fields its decision surface needs; the type system enforces
    disjointness.
  * Turn-coherence: every capabilities field is read from the
    SAME `&Connection` the rest of `assemble_ksb_snapshot` uses,
    inheriting SQLite's per-connection read-consistency model.

---

### INV-KSB-CAPABILITIES-PARITY-01 — KSB admit-predicate verdicts mirror the IPC handler

**Statement.** The `retry_admissible` boolean stamped into every
[`raxis_ksb::TaskCapabilityView`] in the projected KSB snapshot
MUST equal the verdict
[`raxis_types::intent_admit::admit_retry_subtask_check`] returns
for the same inputs (`prior_activation_state`, `crash_retry_count`,
`review_reject_count`, `max_crash_retries`, `max_review_rejections`).
The kernel's `RetrySubTask` IPC handler MUST route its eligibility
cascade through the SAME `admit_retry_subtask_check` pub fn.

The `retry_inadmissible_reason` (when present) MUST carry the
output of [`raxis_types::intent_admit::RetryInadmissibleReason::
human()`] for the matching variant; the leading lexemes (`"no prior
activation"`, `"prior state {state}"`, `"crash_retry_count {n}"`,
`"review_reject_count {n}"`) are substring-stable across kernel
revisions because the orchestrator NNSP pattern-matches against
them.

**Justification.** Without parity, the LLM can (a) pre-evaluate
the KSB row to "admissible" and submit an intent the kernel
rejects (false-negative blind-ask), or (b) pre-evaluate the KSB
row to "inadmissible" and choose an alternative path
(`request_escalation`) when the kernel would actually have
admitted (false-positive escalation). Both classes of drift
silently degrade orchestrator throughput; parity makes them
unrepresentable.

The predicate is intentionally a pure function (takes primitives,
returns a structured outcome — no SQL, no I/O, no async) so both
call sites can run it inside their own transaction without
coupling on a shared `&Connection`. Side effects (the IPC
handler's eprintln + observability counter increment + audit
emit) belong to the call site; the predicate owns the BOOLEAN
decision only.

**Scenario.** A future revision tightens the retry-admission
gate (e.g. adds a "no retry within 30 s of the prior failure"
rule) and updates `handle_retry_sub_task` to enforce it but
forgets to update the KSB assembly. The orchestrator's KSB
shows `retry_admissible=true` for a task whose retry is now
blocked by the new gate; the orchestrator submits the intent;
the kernel rejects it with `FAIL_INVALID_REQUEST`. The parity
witness (`kernel/tests/ksb_capabilities_parity.rs`) catches this
class of regression before it lands by asserting both call sites
return the same verdict for the matrix of admit / reject
inputs.

**Canonical home.** `crates/types/src/intent_admit.rs` (the
predicate); `crates/ksb/src/lib.rs` `Capabilities` /
`TaskCapabilityView` (the wire shape).

**Implementation references.**

  * `crates/types/src/intent_admit.rs` — `admit_retry_subtask_check`,
    `AdmitOutcome`, `RetryInadmissibleReason`, `RetryAdmitInputs`.
  * `kernel/src/handlers/intent.rs` — `handle_retry_sub_task`
    eligibility cascade (uses `raxis_types::intent_admit::*`).
  * `kernel/src/initiatives/ksb_assembly.rs` — `assemble_capabilities`,
    `build_task_capability_view` (uses `raxis_types::intent_admit::*`
    via `admit_retry_subtask_check` to populate the KSB).
  * `kernel/tests/ksb_capabilities_parity.rs` — witness (3
    cases) covering matrix parity, leading-lexeme stability,
    observability-axis stability.

---

### INV-KSB-CAPABILITIES-ROLE-SCOPED-01 — Each role's envelope carries only its decision-surface fields

**Statement.** [`raxis_ksb::Capabilities`] has exactly three
variants (`Orchestrator`, `Executor`, `Reviewer`) whose field
sets are disjoint:

  * `Orchestrator` carries `session: SessionCapabilityView`,
    `initiative: InitiativeCapabilityView` (per-initiative respawn
    budget), `tasks: Vec<TaskCapabilityView>` (per-executor-task
    admit verdicts).
  * `Executor` carries `session: SessionCapabilityView`,
    `task: TaskCapabilityView` (the SINGLE task the executor was
    spawned for) — and nothing else.
  * `Reviewer` carries `session: SessionCapabilityView`,
    `artifact_task_id: String` (identity-only artifact pointer)
    — and nothing else. No counters; the reviewer's verdict MUST
    be on the artifact, not on the executor's prior trajectory.

The wire shape (serde-tagged JSON) MUST mirror this disjointness:
serialising a non-orchestrator envelope MUST NOT include
`initiative` or `tasks` keys; serialising a non-reviewer envelope
MUST NOT include `artifact_task_id`; serialising a non-executor
envelope MUST NOT include the executor's `task` key.

**Justification.** The role-scope contract is the kernel-side
mitigation against three classes of LLM error:

  * **Orchestrator over-reach** — surfacing per-task admit
    verdicts only to the orchestrator means the executor cannot
    "go behind the orchestrator's back" by attempting a sibling
    task's retry (the executor has no API for this, but the
    type-level disjointness means the executor's KSB doesn't
    even surface the field).
  * **Executor cross-DAG visibility** — withholding the
    orchestrator's per-initiative respawn counter from the
    executor means the executor cannot correlate its own
    activation against orchestrator structural failures (which
    would invite reasoning like "the orchestrator is unstable;
    I should rush my commit").
  * **Reviewer trajectory bias** — the reviewer's verdict
    contract (`v1/peripherals.md §reviewer`) is "verdict on the
    artifact, not on the executor". Surfacing
    `crash_retry_count` / `review_reject_count` to the reviewer
    would invite "approve, the executor has burned 2/2 budget;
    rejecting again now leaves the operator stuck" reasoning the
    contract explicitly forbids.

The disjointness is enforced at the **type system** level (Rust
enum variants with disjoint field sets), so a future field
addition that crosses the role boundary (e.g. adding
`crash_retry_count` to `ReviewerCapabilities`) is caught at
compile time by the structural contract. The wire-shape witness
(`kernel/tests/ksb_capabilities_role_scoped.rs`) additionally
pins the JSON serialisation so a serde-rename or
`#[serde(flatten)]` regression that smuggles a forbidden field
across roles is caught at the wire level.

**Scenario.** A planner-side dashboard PR adds a
`peer_task_states: Vec<DagRow>` field to `ExecutorCapabilities`
(intent: surface peer review state to the executor for
better self-coordination). The witness fires:
`executor_envelope_omits_orchestrator_and_peer_state` asserts
the executor's serialised JSON does NOT contain the field. The
PR author either justifies the change (and updates the
invariant's body to widen the contract), or scopes the field
to the orchestrator's envelope where it belongs.

**Canonical home.** `crates/ksb/src/lib.rs` `Capabilities`
docstring + `kernel-mechanics-prompt.md §"KSB schema"`.

**Implementation references.**

  * `crates/ksb/src/lib.rs` — `Capabilities`,
    `OrchestratorCapabilities`, `ExecutorCapabilities`,
    `ReviewerCapabilities`, `SessionCapabilityView`,
    `InitiativeCapabilityView`, `TaskCapabilityView`.
  * `kernel/src/initiatives/ksb_assembly.rs` —
    `assemble_capabilities` dispatches per `KsbRole` and
    constructs only the matching variant.
  * `kernel/tests/ksb_capabilities_role_scoped.rs` — witness (5
    cases) covering wire-shape disjointness and rendered-text
    role-keying.

---

### INV-KSB-CAPABILITIES-TURN-COHERENT-01 — Capabilities snapshot reads share the assembler's connection

**Statement.** The kernel-side
[`assemble_ksb_snapshot`] MUST read every capabilities-envelope
field from the SAME `&Connection` it uses for the rest of the
KSB projection (DAG rows, reviewer verdicts, pending escalations,
base SHA). The capabilities envelope assembly
(`assemble_capabilities`) takes the `&Connection` argument and
runs all SQL against it; no separate connection or transaction
is opened.

**Justification.** SQLite's read-consistency model on a single
connection guarantees a stable snapshot for the duration of a
read sequence (autocommit reads see a transaction-scoped
snapshot per
`https://www.sqlite.org/isolation.html`). The kernel-side
spawn paths assemble the KSB inside a `spawn_blocking` closure
that holds `Store::lock_sync()` (the per-store mutex around the
shared `Connection`) for the whole assembly, inheriting that
guarantee. Splitting the capabilities envelope read across a
SECOND connection would risk drift: an operator-side write
landing between connection-A's `dag_rows` read and
connection-B's `tasks.crash_retry_count` read would surface a
torn snapshot whose `retry_admissible` boolean was computed
from a different store revision than the DAG row the LLM is
reasoning against.

The same property makes the kernel's auto-escalation
paired-write (slice B,
`INV-ESCALATION-AUTO-LOGICAL-DEADLOCK-01`) safe under
concurrent KSB assembly: the assembler will see either the
BEFORE state (initiative `Executing`, no escalation row) or the
AFTER state (initiative `Failed`, escalation row present),
never a torn snapshot in between (the paired write is one
SQLite transaction).

**Scenario.** A future refactor moves the per-task counter
read into a separate `Store::lock_sync()` block "for
performance" (each call would acquire / release the per-store
mutex independently). Under concurrent operator load, an
intervening `subtask_activations` UPDATE between the
DAG-row read and the counter read produces a KSB snapshot whose
`dag_rows[i].state` and `tasks[i].crash_retry_count` come from
different store revisions. The orchestrator's NNSP scans
`aggregate=AtLeastOneRejected` rows against
`retry_admissible=true` — the divergence shows up as a transient
"the kernel says retry is admissible but the activation row was
already advanced" race the witness
(`kernel/tests/ksb_capabilities_turn_coherent.rs`) catches by
pinning the per-connection snapshot guarantees the assembler
relies on.

**Canonical home.** `kernel/src/initiatives/ksb_assembly.rs`
`assemble_capabilities` docstring +
`v2/v2-deep-spec.md §V2.6 KSB capabilities envelope`.

**Implementation references.**

  * `kernel/src/initiatives/ksb_assembly.rs` —
    `assemble_capabilities` (single `&Connection` arg);
    `assemble_ksb_snapshot` (caller threads the connection
    through).
  * `kernel/src/session_spawn_orchestrator.rs` — both spawn
    paths wrap the assembler in `spawn_blocking` with
    `Store::lock_sync()` for the whole call.
  * `kernel/tests/ksb_capabilities_turn_coherent.rs` — witness
    (3 cases) covering single-connection self-write
    observation, sibling-connection committed-write visibility,
    and uncommitted-write opacity to concurrent readers.

---

## §6.8 — Kernel DAG authority (INV-KERNEL-DAG-AUTHORITY-*)

Canonical home: `paradigm.md §3.4` (the orchestrator is an untrusted
LLM agent confined to its own VM); `paradigm.md` rules `R-2`
(mediated I/O), `R-5` (bounded capabilities), `R-11` (mediated
coordination); `v2/agent-disagreement.md §3.6` (Authority boundary
block); `v2/v2-deep-spec.md §Step 8` (`IntegrationMerge`
adjudication), `§Step 20` (static dispatch matrix), `§Step 21`
(`DEPENDENCY_NOT_MET`).

This section consolidates the structural fences that keep the kernel
— not the orchestrator — in authority over every DAG-release
decision (task activation, retry admission, integration merge). The
orchestrator's only DAG-driving primitive is to *emit advisory
intents*; the kernel mechanically adjudicates each intent against
the parsed plan-registry DAG, the per-task FSM admit predicates, and
the bounded-capability counters BEFORE any state transition or VM
spawn.

### INV-KERNEL-DAG-AUTHORITY-01 — Kernel mechanically gates `ActivateSubTask` on predecessor completion

**Statement.** The kernel admits an Orchestrator's `ActivateSubTask
{ task_id }` intent if and only if every row in `task_dag_edges
WHERE successor_task_id = task_id` resolves to a predecessor whose
`tasks.state = 'Completed'` at the moment of admission. The check
is performed inside the same SQLite transaction as the `subtask_
activations` row pivot (`PendingActivation → Active`); a
predecessor whose state is anything other than `Completed`
(`Admitted`, `Running`, `GatesPending`, `BlockedRecoveryPending`,
`Failed`, `Aborted`, `Cancelled`) causes the kernel to reject the
intent with `IntentResponse::Rejected { reason: DEPENDENCY_NOT_MET }`
BEFORE the substrate spawn step. The check uses kernel-owned tables
exclusively (`tasks`, `task_dag_edges`); the orchestrator's intent
payload contributes only the `task_id` lookup key.

**Justification.** The orchestrator is an untrusted LLM agent
running inside a confined VM (`paradigm.md §3.4`). If it owned DAG
release, it could (i) skip review gates by activating a downstream
Executor before its predecessor Reviewer finishes voting, (ii)
provision extra VMs out of plan order to race the kernel's
bounded-capability counters, or (iii) reorder tasks to circumvent
plan-author-declared dependency constraints. Every one of those
violates `R-2` (mediated I/O), `R-5` (bounded capabilities), and
`R-11` (mediated coordination). The Layer 2 prompt-hiding mechanism
(`v2-deep-spec.md §Step 21`) reduces the rate of premature
activation an *honest* orchestrator will produce, but is not a
structural defense against a hallucinating or compromised
orchestrator that ignores its prompt — only the kernel-side
admission gate is.

**Scope.** The gate fires on every `ActivateSubTask` admission,
covering both Executor-after-Executor and Executor-after-Reviewer
edges. The Reviewer-after-Executor edge is *additionally* gated by
the `evaluation_sha IS NOT NULL` lookup at worktree-provisioning
time (the Reviewer's predecessor Executor must have stamped
`tasks.evaluation_sha` via its own `CompleteTask` admission), but
that secondary gate is a defense-in-depth check, not a substitute
for `INV-KERNEL-DAG-AUTHORITY-01`'s primary predecessor-state
verification.

**Audit chain.** A `DEPENDENCY_NOT_MET` rejection emits
`IntentRejectedDependencyNotMet { task_id,
missing_predecessors: [(predecessor_task_id, observed_state), ...] }`
to the audit chain so forensic replay can reconstruct (a) which
DAG edges were unsatisfied at admission time and (b) what state
each unsatisfied predecessor was in. The audit emit happens
post-rejection, audit-after-rejection per
`audit-paired-writes.md §6` (no SQLite write occurred — the gate
rolled back its own transaction — so the audit emit is the only
event for the rejection).

**Witness.** `kernel/src/handlers/intent.rs::tests::
inv_kernel_dag_authority_01_activate_subtask_rejects_unsatisfied_predecessor`
— pins the kernel-side `missing_predecessors_for_activation` free
fn (the structural payload of this invariant) against a 2-task DAG
`task-A → task-B` seeded into a real `DiskStore`. Phase 1: both
rows in `Admitted`; the predicate MUST return
`[("task-A", "Admitted")]` (the non-empty list that triggers the
`ActivateRejection::DependencyNotMet` arm in
`handle_activate_sub_task`). Phase 2: flip A to `Completed`; the
predicate MUST return `[]`. A sibling test
`inv_kernel_dag_authority_01_reports_every_unmet_predecessor` pins
the multi-predecessor fan-in case (every non-Completed edge appears
in the rejection payload, no Completed edge leaks through) so the
`IntentRejected` audit row's `missing_predecessors` field carries
the full forensic record. The free-fn factoring is mandated by
`raxis-kernel`'s bin-only crate shape (`kernel/tests/*.rs` cannot
reach `handle_activate_sub_task` without standing up the kernel
binary + IPC harness); the rejection wiring (audit emit + return
shape) is exercised by the `extended_e2e_*` lifecycle harnesses
that drive the kernel binary directly.

**Composition with other authority gates.** This invariant slots
into the per-intent gate cascade BEFORE the substrate spawn and
AFTER the dispatch-matrix authorization (`§Step 20`):

1. `evaluate_dispatch((ActivateSubTask, Some(Orchestrator))) ⇒
   Authorized` — only orchestrator-typed sessions can submit at all.
2. Replay protection (envelope nonce + sequence advance, `INV-01`).
3. Disk-full watchdog (`INV-CAPACITY-02`).
4. VM concurrency cap (`INV-CAPACITY-01`).
5. Activation row state == `PendingActivation` (kernel-owned column).
6. Task state == `Admitted` (kernel-owned column).
7. **`INV-KERNEL-DAG-AUTHORITY-01` predecessor-completion gate**
   (this invariant).
8. Plan-registry lookup (Orchestrator-typed task rejection;
   `INV-PLANNER-HARNESS-06` defense-in-depth).
9. VM image override resolution (`INV-OPERATOR-CUSTOM-IMAGE-01`).
10. Worktree provisioning (Reviewer-side `evaluation_sha`
    secondary check).
11. Substrate spawn (`ctx.session_spawn.spawn_session()`).
12. Activation row pivot `PendingActivation → Active` + audit emit.

A failure at any of steps 1–10 short-circuits before the
irreversible substrate spawn.

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

### INV-PLANNER-ORCH-RETRY-ON-REJECT-01 — Orchestrator NNSP MUST direct `retry_subtask` on `approved=false`

**Statement.** The Orchestrator's NNSP — rendered by
`crates/planner-core/src/driver.rs::render_system_prompt_for_role(
Role::Orchestrator, …)` and version-locked with the kernel binary
per `INV-PLANNER-HARNESS-06` — MUST instruct the model to:

1. Inspect the `reviewer_verdicts=` block of the rendered KSB
   (`crates/ksb/src/lib.rs::render_ksb`) before deciding the next
   terminal tool to call.
2. Call `retry_subtask { subtask_task_id: "<executor_task_id>" }`
   — NOT `integration_merge` — whenever any row of
   `reviewer_verdicts=` reads `approved=false` against an
   executor whose task row is `complete` AND the executor's
   matching `capabilities.tasks[*]` row reads
   `retry_admissible=true`.
2a. When the executor's `capabilities.tasks[*]` row reads
   `retry_admissible=false` with `reason="prior state
   PendingActivation; …"`, a PRIOR `retry_subtask` already
   landed and the kernel minted a fresh activation row in
   `PendingActivation`. The Orchestrator MUST then call
   `activate_subtask { subtask_task_id: "<executor_task_id>" }`
   to spawn the executor VM for the fresh activation, per
   `kernel/src/handlers/intent.rs::handle_retry_sub_task` step 6
   ("the Orchestrator's next step is `ActivateSubTask` against
   the same task_id, which will spawn the fresh VM"). Re-issuing
   `retry_subtask` against the new row would be rejected with
   `RetrySubTaskRejectedNotRetryable` and would burn a slot of
   the per-initiative `orchestrator_no_progress_respawn_count`
   ceiling (`INV-ORCH-RESPAWN-NO-PROGRESS-CEILING-01`).
3. Defer to the kernel's `[plan.tasks.<exec>.review].max_rounds`
   ceiling (per `agent-disagreement.md §3`) for the retry-loop
   ceiling — the Orchestrator MUST NOT itself enforce a separate
   ceiling. When `capabilities.tasks[*]` reports
   `retry_admissible=false` with `reason="review_reject_count …
   >= max_review_rejections …"` (or `crash_retry_count …`), the
   ceiling has fired; the Orchestrator falls through to
   escalation per `agent-disagreement.md §3` rather than
   reissuing `retry_subtask`.
4. Only call `integration_merge` after every executor's
   `reviewer_verdicts=` row reads `approved=true`.

**Justification.** The kernel's cross-Reviewer aggregator
(`kernel/src/handlers/intent.rs::handle_submit_review` post-commit
loop) emits `ReviewAggregationCompleted { verdict:
"AtLeastOneRejected" }` and best-effort enqueues
`KernelPush::ReviewRejected` to the live Orchestrator session
when the rejection is current. Critically, the executor task's
own FSM stays at `Completed` regardless of the verdict (per
`kernel-store.md §2.5.1` the executor's task FSM is independent
of downstream review verdicts; the verdict is captured in
`subtask_activations.review_reject_count` and the audit row, not
the task `state`). The Orchestrator's `dag=` view therefore shows
the executor row as `complete` even when reviewers rejected it,
and the only Orchestrator-side signal for retry-vs-merge is the
`reviewer_verdicts=` block. Without this NNSP rule, the
Orchestrator defaults to `integration_merge` once every executor
row is `complete` regardless of verdict, silently merging
defective code despite the reviewer's objection — a
paradigm-`R-6` (Fail-Closed Default) violation.

The kernel-side alternatives (auto-issuing `RetrySubTask` on
`AtLeastOneRejected`, or coupling the `IntegrationMerge`
admission predicate to the cross-Reviewer aggregator) are
rejected per `agent-disagreement.md §3.6`: the kernel cannot
distinguish recoverable rejections from structurally
unrecoverable ones, so the decision belongs to the Orchestrator
agent reading the critique. This invariant is the NNSP-side
contract that completes the retry loop.

**Scenario (iter41 reproduction).** A two-reviewer Executor task
`lint-defect` is followed by reviewers `review-lint-defect-A`
(approves) and `review-lint-defect-B` (rejects with critique
"`greeting.rs` introduces clippy::useless_conversion"). The
kernel emits `ReviewAggregationCompleted { verdict:
"AtLeastOneRejected" }` and skips the `KernelPush::ReviewRejected`
push because no Orchestrator session is live at that instant.
The post-`SubmitReview` Orchestrator respawn fires, but the
Orchestrator NNSP under iter41 contains only "rule 3: if a row
is `failed`, call `retry_subtask`" — no rule for the
`approved=false`-but-`complete` case. The Orchestrator therefore
proceeds to `integration_merge` and the
`ReviewerSubstantiveDisagreementWitness` panics with
`saw_executor_respawn = false` + `saw_aggregation_pass = false`.
The fix adds rule 3a (scan `reviewer_verdicts=`; on
`approved=false`, call `retry_subtask`) and tightens rule 4
(merge only when all verdicts are `approved=true`).

**Canonical home.** `v2/agent-disagreement.md §3.6` (NNSP
responsibility) + `v2/planner-harness.md §4.8` (Orchestrator
NNSP is kernel-owned per `INV-PLANNER-HARNESS-06`).

**Kernel-side projection contract.** The NNSP rule is dead-letter
unless the kernel's KSB projection populates the
`reviewer_verdicts=` block from live store rows.
`kernel/src/initiatives/ksb_assembly.rs::read_reviewer_verdicts_for_initiative`
joins `tasks.review_verdict` (Reviewer's per-vote outcome) +
`tasks.last_critique` (executor's concatenated formatted
critiques per Step 22 of `v2-deep-spec.md`) +
`task_dag_edges` (reviewer → executor predecessor) so the
orchestrator's KSB carries one `ReviewerVerdict` per voted
Reviewer with the executor's `evaluation_sha`. Executor sessions
get an empty list (executor KSB has no DAG visibility per
`KsbRole::Executor`). `DagRow::reviewers` is sourced symmetrically
via `read_reviewer_counts_per_executor` — only `Reviewer`-typed
successors are counted (a downstream executor that depends on
this executor does NOT inflate the count). Iter42 reproduced
the gap — the orchestrator NNSP scanned correctly but the
projection was hard-coded to `Vec::new()`, so the rule never
fired.

**Pinned regression coverage.**
- `crates/planner-core/src/driver.rs::tests::render_system_prompt_for_orchestrator_includes_review_rejection_retry_rule`
  (NNSP unit test).
- `kernel/src/initiatives/ksb_assembly.rs::tests::assemble_orchestrator_snapshot_populates_reviewer_verdicts_from_store`
  (kernel-side projection unit test).
- `kernel/tests/extended_e2e_support/reviewer_substantive_disagreement.rs::ReviewerSubstantiveDisagreementWitness`
  (end-to-end audit-chain witness wired into
  `kernel/tests/extended_e2e_realistic_scenario.rs::realistic_session_lifecycle`).

---

### INV-KSB-PREDS-READY-PROJECTION-01 — Every `dag=` row carries a wire-stable `preds_ready` boolean

**Statement.** The orchestrator KSB renderer
(`crates/ksb/src/lib.rs::render_ksb`) MUST emit a
`preds_ready=<true|false>` token on every `dag=` row, between
the `reviewers=<N>` field and any optional `aggregate=` field.
The token's value MUST be the exact projection of:

> "every plan-declared predecessor of this task in
> `task_dag_edges` is in the `tasks.state = 'Completed'`
> terminal state".

Tasks with no predecessor edges are vacuously `preds_ready=true`.
The projection is computed by
`kernel/src/initiatives/ksb_assembly.rs::read_preds_ready_per_task`
inside the same `&Connection` snapshot the rest of the
`assemble_ksb_snapshot` projection reads from, so the rendered
row is a coherent witness of one SQLite read-snapshot.

**Why `tasks.state = 'Completed'` and NOT
`task_dag_edges.predecessor_satisfied = 1`.** The kernel never
UPDATEs the `predecessor_satisfied` column in v1 (despite the
schema comment); only INSERTs at admission set it from the
plan-validator side. `tasks.state = 'Completed'` is the only
ground-truth signal that an Executor has stamped
`evaluation_sha` (per `commit_task_completion` step 1 — the
Running → Completed flip and the SHA stamp happen in the same
SQLite tx). The kernel-side `ActivateSubTask` reviewer-branch
(`kernel/src/handlers/intent.rs::handle_activate_sub_task`)
gates reviewer activation on the *same* predicate (it joins
`task_dag_edges → tasks.evaluation_sha IS NOT NULL` to surface
`ActivateSubTaskReviewerNoEvalSha`); the wire field
`preds_ready` is therefore a sound lower bound on the kernel's
own admission predicate — a row with `preds_ready=true` is
guaranteed to pass the gate, and a row with `preds_ready=false`
is guaranteed to be rejected.

**Justification (iter49 reproduction).** The realistic plan's
`lint-defect → lint-runner → review-lint-defect-A/B` chain
requires the orchestrator LLM to activate `lint-runner`
(its sole predecessor `lint-defect` Completes first) BEFORE
`review-lint-defect-A`. With no wire-stable predecessor
indicator the LLM activated `review-lint-defect-A` directly
after `lint-defect` Completed, expecting `lint-defect`'s SHA
to satisfy the reviewer. The kernel rejected every attempt
with `ActivateSubTaskReviewerNoEvalSha` because the reviewer's
*immediate* DAG predecessor in the realistic plan is
`lint-runner`, not `lint-defect`. The respawn loop fired the
per-initiative `OrchestratorRespawnCeilingExceeded` ceiling
(`INV-ORCH-RESPAWN-NO-PROGRESS-CEILING-01`). With this
projection in place the LLM sees
`review-lint-defect-A admitted reviewers=0 preds_ready=false`
on the wire and the NNSP rule 2
(`INV-PLANNER-ORCH-PREDS-READY-GATE-01`) prevents the
activation in the first place.

**Wire shape stability.** The field is unconditionally emitted
(no compactness optimisation). The LLM relies on its presence
to tell apart "predecessors actually all complete" from "row
is from a pre-iter50 renderer that never emitted the field"
— a missing field would be ambiguous. The
`#[serde(default)]` on `DagRow::preds_ready` covers
backward-compat for any pre-iter50 dashboard / replay tool
decoding a stale snapshot from disk: the safe (over-blocking)
default is `false`.

**Pinned regression coverage.**
- `crates/ksb/src/lib.rs::tests::render_includes_required_fields`
  (renderer wire shape).
- `crates/ksb/src/lib.rs::tests::render_emits_aggregate_when_set`
  (positional placement: `preds_ready=` precedes `aggregate=`).
- `kernel/src/initiatives/ksb_assembly.rs::tests::dag_row_preds_ready_blocks_reviewer_when_immediate_executor_predecessor_not_completed`
  (kernel-side projection unit test, iter49 shape).

**Canonical home.**
`crates/ksb/src/lib.rs::DagRow::preds_ready`,
`kernel/src/initiatives/ksb_assembly.rs::read_preds_ready_per_task`.

---

### INV-PLANNER-ORCH-PREDS-READY-GATE-01 — Orchestrator NNSP rule 2 gates `activate_subtask` on `preds_ready=true`

**Statement.** The Orchestrator's NNSP — rendered by
`crates/planner-core/src/driver.rs::render_system_prompt_for_role(
Role::Orchestrator, …)` — MUST instruct the model to:

1. Parse the `preds_ready=` field from every `dag=` row (the
   wire-stable token defined by
   `INV-KSB-PREDS-READY-PROJECTION-01`).
2. Call `activate_subtask { subtask_task_id: "<task_id>" }`
   ONLY for rows whose `state` is `pending` (or `admitted`)
   AND `preds_ready=true`.
3. NEVER call `activate_subtask` against a row whose
   `preds_ready=false` — at least one plan-declared
   predecessor is short of `Completed` and the kernel will
   reject the activation
   (`ActivateSubTaskReviewerNoEvalSha` for reviewer rows;
   worktree-provision miss for executor rows whose predecessor
   ODB closure is not yet copied). Each rejection burns one
   slot of the per-initiative
   `orchestrator_no_progress_respawn_count` ceiling
   (`INV-ORCH-RESPAWN-NO-PROGRESS-CEILING-01`).

The NNSP MUST also cite the realistic-plan
`lint-defect → lint-runner → review-lint-defect-A/B` chain as
a worked example so the LLM grounds the rule on a concrete
shape (the iter49 reproduction).

**Justification.** Without this rule the planner LLM has to
reconstruct predecessor satisfaction from per-task description
text it was never handed (the executor / reviewer prompts ship
their own descriptions but no machine-readable predecessor
table). Iter49 demonstrated the failure mode: the orchestrator
activated `review-lint-defect-A` directly after `lint-defect`
Completed, the kernel rejected three attempts with
`ActivateSubTaskReviewerNoEvalSha`, and the respawn ceiling
fired. Pairing the rule with the wire-stable
`preds_ready=` projection
(`INV-KSB-PREDS-READY-PROJECTION-01`) makes the gate
mechanical: the LLM never has to recompute predecessor
satisfaction.

**Pinned regression coverage.**
- `crates/planner-core/src/driver.rs::tests::render_system_prompt_for_orchestrator_gates_activate_on_preds_ready`
  (NNSP unit test).
- `kernel/tests/extended_e2e_support/reviewer_substantive_disagreement.rs::ReviewerSubstantiveDisagreementWitness`
  (end-to-end audit-chain witness wired into
  `kernel/tests/extended_e2e_realistic_scenario.rs::realistic_session_lifecycle`).

**Canonical home.** `v2/agent-disagreement.md §3.6` (NNSP
responsibility) + `v2/planner-harness.md §4.8` (Orchestrator
NNSP is kernel-owned per `INV-PLANNER-HARNESS-06`).

---

### INV-PLANNER-ORCH-RETRY-PRIORITY-OVER-ACTIVATE-01 — Orchestrator NNSP gives review-rejection retry ABSOLUTE priority over fresh activation

**Statement.** The Orchestrator's NNSP — rendered by
`crates/planner-core/src/driver.rs::render_system_prompt_for_role(
Role::Orchestrator, …)` — MUST instruct the model to apply
its per-turn decision algorithm in this STRICT order, firing
the FIRST matching action and STOPPING:

1. **(highest priority)** Scan `dag=` for any Executor row
   reading `aggregate=AtLeastOneRejected`. If at least one
   such row exists AND its matching
   `capabilities.tasks[*].retry_admissible=true`, call
   `retry_subtask { subtask_task_id: "<executor_task_id>" }`
   THIS turn — DO NOT activate any pending task.
2. (failed-task retry) If a row's `state=failed` and a retry
   is warranted, call `retry_subtask`.
3. (fresh activation) Otherwise find the first task whose
   `state` is `pending` (or `admitted`) AND whose
   `preds_ready=true` and call `activate_subtask` (per
   `INV-PLANNER-ORCH-PREDS-READY-GATE-01`).
4. (terminal merge) When EVERY executor row is `complete`
   AND every reviewer row is `complete` AND every executor
   row reads `aggregate=AllPassed` (or `NoSuccessors`), call
   `integration_merge`.

The NNSP MUST flag the priority directive explicitly with the
literal token `PRIORITY` and state that retry-on-rejection
takes "ABSOLUTE precedence over fresh activation". It MUST
also cite the kernel-side audit tag
`IntegrationMergeBlockedByOutstandingReview` (the Step 3d gate
documented in `specs/v2/agent-disagreement.md §3.6`'s "Iter49
kernel-side fail-closed backstop") so the LLM understands that
thrashing on `integration_merge` is wasteful: every rejection
burns one slot of the per-initiative
`orch_no_progress_respawns=` budget
(`INV-ORCH-RESPAWN-NO-PROGRESS-CEILING-01`).

**Justification (iter49 → iter50 reproduction).** In the
realistic_session_lifecycle e2e the orchestrator successfully
drove `lint-defect → lint-runner` to Completed (with the
`scripts/check.sh` defect intact in `lint-runner`'s commit),
both reviewers `review-lint-defect-A`/`-B` rejected with
substantive critiques naming `greeting.rs`, the kernel emitted
`ReviewAggregationCompleted{verdict=AtLeastOneRejected}` and
bumped `subtask_activations.review_reject_count` per
`INV-RETRY-FROM-COMPLETED-REVIEW-REJECTED-01`. The orchestrator
NNSP at the time numbered the rules as `2. activate_subtask`,
`3. failed-retry`, `3a. retry on AtLeastOneRejected`,
`4. integration_merge`. The LLM scanned rules in order, found
pending tasks (`service-round-trip`, `transparent-proxy-realscripts`,
`xfile-refactor`, …) that satisfied rule 2's `preds_ready=true`
predicate, activated them in sequence, and never returned to
retry `lint-runner`. When all other tasks Completed, the LLM
proceeded directly to rule 4 and submitted `integration_merge
{ head_sha = …/xfile-refactor }`. Iter49 closed by adding the
kernel Step 3d hard-reject (commit `810fa63` — fast-forwards
no longer ship defective heads); iter50 closes the LLM-side
behaviour: the orchestrator now retries `lint-runner` BEFORE
activating any other pending task, so the kernel's structural
backstop never has to fire in the first place. The realistic
scenario's `ReviewerSubstantiveDisagreementWitness` then sees
`saw_executor_respawn=true` AND `saw_aggregation_pass=true`
on the round-2 review cycle.

**Pinned regression coverage.**
- `crates/planner-core/src/driver.rs::tests::render_system_prompt_for_orchestrator_prioritizes_retry_over_activate`
  (NNSP unit test).
- `kernel/tests/extended_e2e_support/reviewer_substantive_disagreement.rs::ReviewerSubstantiveDisagreementWitness`
  (end-to-end audit-chain witness wired into
  `kernel/tests/extended_e2e_realistic_scenario.rs::realistic_session_lifecycle`
  — the iter49 → iter50 reproduction's full chain).

**Canonical home.** `v2/agent-disagreement.md §3.6` (NNSP
responsibility) + `v2/planner-harness.md §4.8` (Orchestrator
NNSP is kernel-owned per `INV-PLANNER-HARNESS-06`).

---

### INV-RETRY-FROM-COMPLETED-REVIEW-REJECTED-01 — Kernel admits `RetrySubTask` from `Completed` IFF `review_reject_count > 0`

**Statement.**
`handle_retry_sub_task` (in `kernel/src/handlers/intent.rs`) MUST
admit a `RetrySubTask` intent against an executor sub-task whose
MOST-RECENT `subtask_activations` row is in one of the two
retry-eligibility classes below; everything else MUST reject with
`FAIL_INVALID_REQUEST`. The previously-admitted iter48 third class
(`PendingActivation` + `review_reject_count > 0`) was reversed in
iter54 — see `INV-ORCH-RETRY-SUBTASK-PENDING-ACTIVATION-NOT-RETRYABLE-01`
below.

| Class | Prior activation state | `review_reject_count` | Anchor audit event | Decision rationale |
|---|---|---|---|---|
| Crash-retry | `Failed` | (any) | none — the preceding `TaskStateChanged { state: Failed }` is the anchor | Classic `ReportFailure` → retry per `v2-deep-spec.md §Step 12` |
| Reviewer-rejection retry (Option A) | `Completed` | `> 0` | `ExecutorRespawnFromReviewRejection` (this invariant's anchor) | Executor task-FSM stays `Completed` (forward-only) per `kernel-store.md §2.5.1`; the counter is the canonical "this round was rejected" witness |
| (rejected) | `Completed` | `0` | n/a — the handler rejects with `FAIL_INVALID_REQUEST` | Clean completion; admitting would let the orchestrator force a re-run of a successful task (paradigm-`R-6` Fail-Closed Default violation) |
| (rejected) | `PendingActivation` | `0` | n/a — `FAIL_INVALID_REQUEST` | Brand-new round-1 admission; no Reviewer has voted yet, the orchestrator MUST issue `ActivateSubTask` (not `RetrySubTask`); admitting would race the pending spawn against the retry handler's revoke + insert |
| (rejected) | `PendingActivation` | `> 0` | n/a — `FAIL_INVALID_REQUEST` per `INV-ORCH-RETRY-SUBTASK-PENDING-ACTIVATION-NOT-RETRYABLE-01` | A prior `RetrySubTask` already minted this row. The orchestrator's correct next intent is `ActivateSubTask` (which spawns the executor for the existing pending row). Admitting another `RetrySubTask` here is iter54's reproduced no-progress loop: the LLM exits after one terminal call, the post-exit hook respawns a fresh orchestrator decision-cycle, the new session reads the still-pending row + the still-rejected aggregate verdict, re-issues `retry_subtask`, and the cycle repeats until `orchestrator_respawn_ceiling_exceeded`. |
| (rejected) | `Active` | (any, including `> 0`) | n/a — `FAIL_INVALID_REQUEST` | Executor VM is still running; admitting would race the executor's eventual `CompleteTask` cascade against this handler's revoke + insert. The orchestrator MUST wait for activation termination before retrying. |

The retry inserts a NEW `PendingActivation` row carrying both
counters forward from the prior row verbatim. The prior row's
`activation_state` is NOT mutated (the FSM is forward-only —
`Completed → Failed` is forbidden, this is the load-bearing
distinction from the rejected Option B). Both rows coexist for
the same `task_id`; the bump in
`increment_executor_review_reject_count` targets the LATEST row
by `created_at`, so per-round counter semantics are preserved.

**Justification.**
Two ground-truth constraints force Option A over Option B
(`Completed → Failed` backward transition):

1. `paradigm.md §3.6` — "the executor's task-FSM is
   independent of downstream review verdicts". The Executor's
   responsibility is "I produced the output you asked for"; the
   Reviewer's verdict on that output belongs to a separate axis.
   A backward transition would conflate the two.
2. `kernel-store.md §2.5.1` — the activation FSM is documented
   as forward-only. Every downstream consumer (dashboard
   counters, audit chain replay, recovery sweep) assumes
   monotonic transitions; reversing the assumption requires a
   refactor wave through every consumer.

The narrower precondition (`review_reject_count > 0`, not just
`Completed`) is the negative-case regression guard: without it
an accidental "retry this task" intent against a clean
completion would silently admit, and the operator's audit trail
would show two activations for the same `task_id` with no
preceding rejection round. The counter is the canonical witness
that "a Reviewer rejected this round" — bumped in
`increment_executor_review_reject_count` at the
post-`SubmitReview` aggregator's terminal-`AtLeastOneRejected`
branch, paired in the SQLite transaction with the
`ReviewAggregationCompleted` audit emission per
`audit-paired-writes.md §4`.

**iter41 reproduction trace.** Before this invariant landed,
three interlocking bugs masked the retry path:
1. The Orchestrator's NNSP had no rule for the
   `approved=false`-but-`Completed` case (fixed by
   `INV-PLANNER-ORCH-RETRY-ON-REJECT-01`), so no `RetrySubTask`
   was ever issued.
2. `increment_executor_review_reject_count` filtered on
   `terminated_at IS NULL`; the `CompleteTask` cascade had
   already populated `terminated_at` before the aggregator
   ran, so the UPDATE matched zero rows and the counter never
   advanced.
3. `handle_retry_sub_task` rejected `prior_state != "Failed"`
   unconditionally, so even a hand-issued `RetrySubTask`
   against the rejected Executor would have surfaced
   `INVALID_REQUEST`.

The fix lands all three halves in one PR:
- Orchestrator NNSP rule 3a (per `INV-PLANNER-ORCH-RETRY-ON-REJECT-01`).
- SQL fix targeting the LATEST activation row by `created_at`
  (`handlers/intent.rs::increment_executor_review_reject_count`).
- Precondition relaxation in `handle_retry_sub_task` admitting
  the `Completed + review_reject_count > 0` branch (this
  invariant).

**iter48 reproduction trace + extension.** The iter42 fix above
admitted the FIRST retry-from-rejection but left a follow-up loop
class uncovered. Iter48's `realistic_session_lifecycle` live-e2e
on `lint-defect` reproduced it:

1. Round-1 `Completed` activation `cba693a4-...` got two reviewer
   rejections (`AtLeastOneRejected`); the kernel bumped
   `review_reject_count = 1`.
2. Orchestrator session `88a256b1-...` submitted `RetrySubTask`;
   the kernel admitted via the iter42 `Completed +
   review_reject_count > 0` branch and inserted a round-2
   `PendingActivation` row `bcfdd7ce-...` carrying
   `review_reject_count = 1` forward.
3. Orchestrator session `88a256b1-...` exited cleanly BEFORE
   issuing the follow-up `ActivateSubTask` (decision-cycle
   sessions exit after each terminal tool call per V2.5b).
4. The post-exit hook respawned a fresh orchestrator
   `84d011c5-...`. The new session read the cumulative-trajectory
   witness (`review_reject_count = 1`, still
   `aggregate=AtLeastOneRejected`) and re-issued `RetrySubTask`
   against the `bcfdd7ce-...` PendingActivation row.
5. The kernel rejected with
   `RetrySubTaskRejectedNotRetryable`,
   `prior_state=PendingActivation`, `review_reject_count=1`.
6. The orchestrator exited; the post-exit hook respawned again;
   the same loop repeated. After three no-progress rounds the
   `INV-ORCH-RESPAWN-NO-PROGRESS-CEILING-01` ceiling fired and
   the kernel marked the initiative `Failed`.

Iter48 first attempted to fix the loop via the orchestrator NNSP
(commit `4d19026`: gate `retry_subtask` on
`capabilities.tasks[*].retry_admissible`, route the LLM to
`activate_subtask` when the retry is inadmissible). That fix is
correct AND necessary — the LLM should not blind-ask retry — but
is not load-bearing on its own: a future NNSP regression, KSB
projection bug, harness bug, or LLM hallucination could
re-introduce the loop class with a different cause. The kernel
admit predicate is the structural backstop.

This invariant therefore extends the admit-set with a third
class: `prior_state == 'PendingActivation'` AND
`review_reject_count > 0`. The same `> 0` witness gates both the
`Completed` and `PendingActivation` branches — a brand-new
round-1 PendingActivation row (no Reviewer ever voted) stays
non-retryable. `Active` is intentionally excluded regardless of
counter (admitting a retry against a still-running executor
would race the eventual `CompleteTask` cascade against the
retry handler's revoke + insert).

**Rejected alternative — Option B (`Completed → Failed`
backward transition).** The earlier proposal to transition the
activation row from `Completed` back to `Failed` on
terminal-`AtLeastOneRejected` was rejected for five interlocking
reasons:
1. Violates the forward-only FSM contract documented above.
2. Overloads `Failed` semantically ("executor reported failure"
   vs "reviewers rejected" — two different recovery surfaces
   that should not share a state).
3. Makes dashboard counters flap (Executor goes
   `Completed → Failed → Completed → Failed → …` on every
   rejection round, churning every dashboard subscriber).
4. Crash-recovery surface gains a transient inconsistent window
   between the cascade's terminate-row write and the rejection
   handler's reopen write.
5. Substantially larger kernel diff (~50 LOC + new audit variant
   + pairing logic) vs Option A (~5 LOC + counter column —
   which already existed in the schema since migration 0005).

**Canonical home.** `agent-disagreement.md §3.6` (decision
rationale) + `v2-deep-spec.md §Step 12` (`RetrySubTask`
admission contract) + `kernel-store.md §2.5.1`
(`subtask_activations.review_reject_count` semantics).

**Pinned regression coverage.**
- `kernel/src/handlers/intent.rs::tests::retry_from_completed_with_review_rejection_admits_and_emits_audit`
  — positive case: `Completed + review_reject_count = 1` admits
  the retry, inserts a `PendingActivation` row, leaves the
  prior `Completed` row immutable, emits
  `ExecutorRespawnFromReviewRejection` with the prior +
  new activation ids in the payload.
- `kernel/src/handlers/intent.rs::tests::retry_from_completed_without_review_rejection_is_rejected`
  — negative case: `Completed + review_reject_count = 0`
  rejects with `FAIL_INVALID_REQUEST` (regression guard against
  accidentally unlocking retry from clean Completed states).
- `kernel/src/handlers/intent.rs::tests::retry_from_pending_activation_with_review_rejection_is_rejected_per_iter54`
  — iter54 reversal of the iter48 admission: `PendingActivation +
  review_reject_count = 1` rejects with `FAIL_INVALID_REQUEST`,
  does NOT insert a new activation row, and emits NEITHER
  `ExecutorRespawnFromReviewRejection` (that anchor belongs to
  the admission flow) NOR `SessionRevoked` (no prior session was
  bound). See `INV-ORCH-RETRY-SUBTASK-PENDING-ACTIVATION-NOT-RETRYABLE-01`.
- `kernel/src/handlers/intent.rs::tests::retry_from_pending_activation_without_review_rejection_is_rejected`
  — negative case: `PendingActivation + review_reject_count = 0`
  (a brand-new round-1 admission, no Reviewer ever voted) rejects
  with `FAIL_INVALID_REQUEST` (regression guard against
  accidentally widening retry to in-flight rounds).
- `crates/types/src/intent_admit.rs::tests::rejects_when_pending_activation_with_review_rejection_so_orchestrator_steers_to_activate_subtask`
  + `rejects_when_pending_activation_without_review_rejection`
  + `rejects_active_even_with_review_rejection` — pure
  predicate unit tests covering the iter54 reversal and the
  `Active`-stays-non-retryable carve-out.
- `kernel/tests/ksb_capabilities_parity.rs::predicate_and_ksb_view_agree_across_admission_matrix`
  — extended with the `pending-activation-with-rejection-iter54-reversal`
  parity row (inadmissible per iter54) and the
  `active-with-rejection-still-not-retryable` parity row
  (inadmissible). A drift between the kernel admit predicate and
  the KSB `retry_admissible` projection on either row would fail
  this parity witness before any live-e2e dryrun has to wait
  for the harness deadline.
- `kernel/src/handlers/intent.rs::tests::increment_review_reject_count_bumps_most_recent_terminated_row`
  — counter-no-op fix: bump succeeds against a Completed
  activation with populated `terminated_at` (iter41 silent-bug
  fix; the pre-fix `terminated_at IS NULL` filter would have
  returned 0 rows).
- `kernel/src/handlers/intent.rs::tests::increment_review_reject_count_targets_latest_when_multiple_rows`
  — per-round counter semantic: when round-1 (`Completed`) +
  round-2 (`PendingActivation`) rows coexist, the bump
  targets round-2 only (the prior round's counter is
  historical and never re-bumped).
- `kernel/tests/extended_e2e_support/reviewer_substantive_disagreement.rs::ReviewerSubstantiveDisagreementWitness::evaluate_chain`
  — chain-side anchor: witness matches on
  `ExecutorRespawnFromReviewRejection`, NOT on the more-generic
  `SessionVmSpawned` (whose round-1 first-spawn payload is
  indistinguishable from the round-2 retry-spawn payload
  without a SQLite join — violating `INV-AUDIT-04`).
- `kernel/tests/extended_e2e_support/reviewer_substantive_disagreement.rs::tests::round_1_session_vm_spawn_does_not_mask_round_2_anchor`
  — regression guard: a chain with both round-1
  `SessionVmSpawned` AND round-2
  `ExecutorRespawnFromReviewRejection` is accepted; round-1
  alone is rejected.

---

### INV-ORCH-RETRY-SUBTASK-PENDING-ACTIVATION-NOT-RETRYABLE-01 — Kernel rejects `RetrySubTask` against a prior `PendingActivation` row (iter54 reversal of iter48)

**Statement.**
`handle_retry_sub_task` (in `kernel/src/handlers/intent.rs`) MUST
reject every `RetrySubTask` whose MOST-RECENT
`subtask_activations` row's `activation_state` is
`PendingActivation`, regardless of `review_reject_count`. The
kernel emits `RetrySubTaskRejectedNotRetryable` with
`prior_state=PendingActivation` and the
`admit_set="Failed | Completed+review_reject_count>0"` hint;
`admit_retry_subtask_check` returns
`Inadmissible(NotRetryable)` and the KSB capability projection
stamps `retry_admissible=false reason="prior state
PendingActivation; …"` so the orchestrator NNSP rule 3a steers
the LLM toward `ActivateSubTask` against the existing pending
row (which is the correct second half of the two-intent retry
contract — see
`INV-ORCH-RETRY-SUBTASK-TWO-INTENT-CONTRACT-01`).

**Justification (iter54 `realistic_session_lifecycle`
reproduction).** Iter48 originally extended the admit-set to
include `(PendingActivation + review_reject_count > 0)`. The
intent was a structural backstop for orchestrators that exited
between `RetrySubTask` and the follow-up `ActivateSubTask`: the
post-exit-hook respawned a fresh orchestrator, and the iter48
admission let that orchestrator re-issue `RetrySubTask` to
recover. In practice the admission contradicted the
co-introduced iter48 NNSP rule 3a (in
`crates/planner-core/src/driver.rs::render_system_prompt_for_role`),
which already told the orchestrator to call `activate_subtask`
on this state. Because the kernel was happy to accept the second
`retry_subtask`, the KSB stamped `retry_admissible=true`, the
NNSP's primary clause (admissible ⇒ MUST retry) won over its
diagnostic clause, and the LLM chained
`retry_subtask → exit → respawn → retry_subtask` indefinitely
without ever issuing `activate_subtask`. Iter54's run on
`lint-runner` reproduced the loop deterministically: 4
`RetrySubTask` admits in 30 s, zero `ActivateSubTask`s, zero
executor VMs spawned for the retried activation,
`orchestrator_respawn_ceiling_exceeded` fired at attempt 4
(max 3), and the initiative deadlocked to `Failed`.

The fix flips `admit_retry_subtask_check` to return
`Inadmissible(NotRetryable { prior_state="PendingActivation", … })`
on this branch. The structural recovery for the "orchestrator
exited between RetrySubTask and ActivateSubTask" case is now
the NNSP rule 3a + the kernel rejection feedback loop: the
respawned orchestrator reads the KSB
(`retry_admissible=false reason="prior state PendingActivation; …"`),
the NNSP rule 3a fires, the LLM calls `activate_subtask`, and
`handle_activate_sub_task` promotes the existing pending row to
`Active` and spawns the executor for the fresh activation. The
single-spawn-point invariant is preserved (the only caller of
`spawn_executor_for_task` is `handle_activate_sub_task`), and
the two-intent retry contract is the only legal path.

**Witness pins.**

- `crates/types/src/intent_admit.rs::tests::rejects_when_pending_activation_with_review_rejection_so_orchestrator_steers_to_activate_subtask`
  — pure-predicate unit test: `PendingActivation +
  review_reject_count = 1` returns
  `Inadmissible(NotRetryable { prior_state: "PendingActivation",
  review_reject_count: 1 })`.
- `crates/types/src/intent_admit.rs::tests::human_strings_carry_load_bearing_lexemes`
  — extended to assert the human-readable reason carries
  `prior state PendingActivation` AND `activate_subtask` so a
  future NNSP regression that drops rule 3a still leaves the
  KSB envelope with an LLM-actionable hint.
- `kernel/src/handlers/intent.rs::tests::retry_from_pending_activation_with_review_rejection_is_rejected_per_iter54`
  — IPC-handler witness: same inputs, kernel rejects with
  `FAIL_INVALID_REQUEST`, NO new activation row inserted, NO
  `ExecutorRespawnFromReviewRejection` audit event (that anchor
  belongs to the admission flow), NO `SessionRevoked`.
- `kernel/tests/ksb_capabilities_parity.rs::predicate_and_ksb_view_agree_across_admission_matrix`
  — parity row `pending-activation-with-rejection-iter54-reversal`
  pins `expected_admissible=false`; the KSB projection MUST flip
  in lockstep with the predicate (parity guarantee from
  `INV-KSB-CAPABILITIES-PARITY-01`).
- `kernel/tests/extended_e2e_realistic_scenario.rs::realistic_session_lifecycle`
  — live-e2e witness: the iter54 reproduction (which drove
  `orchestrator_respawn_ceiling_exceeded` at attempt 4 of 3 in
  ~14 min on `lint-runner`) MUST land a green `working e2e`
  commit; a regression that reintroduces the iter48 admission
  surfaces here as the same no-progress loop.

---

## §10.4a — Role-session VM capability discovery (INV-EXEC-DISCOVERY-*)

The Executor / Reviewer / Orchestrator LLM runs inside an airgapped
VM whose contents — pre-installed binaries, language runtimes,
package versions, credential-proxy URLs, workdir state — are
opaque to the model. The model cannot do trial-and-error
`pip install` / `npm install` / `cargo install` / `go get` because
egress is gated by the kernel's allowlist (per
`v2/vm-network-isolation.md`) and the credential proxies only
proxy DB / cloud traffic, not package mirrors. The capability-
discovery surface is the model's only legitimate way to learn
what's already baked in. It SHOULD short-circuit a wasted turn
on every session whose first action would otherwise have been a
blind `import` / `require` / `use` of a package that isn't there.

### INV-EXEC-DISCOVERY-01 — Every role session receives a capability manifest at session start

**Statement.** Every Executor, Reviewer, and Orchestrator session
MUST receive a VM-capability manifest at session start, surfaced
through BOTH:

1. A **system-prompt capability hint** — a short
   `## VM Environment` section appended to the role's NNSP before
   the KSB block, summarising the language runtimes (Python, Node,
   Rust, Go), the curated DB-client / CLI-tool subsets, the
   credential-proxy env-var **names** (NOT values), and the workdir
   snapshot (path + git head). The hint MUST also carry the
   "no outbound network — `pip install` / `npm install` /
   `cargo install` / `go get` will fail" reminder.
2. A **`vm_capabilities` LLM tool** — registered in the role
   registry alongside the standard tool surface, returning a
   structured JSON manifest filterable by `categories` (any subset
   of `binaries`, `python`, `node`, `rust`, `go`, `env`,
   `filesystem`) and `filter` (substring binary name, specific
   `python_package` / `node_package` import-test, specific
   `env_var`). The structured tool is the recourse for finer
   queries the system-prompt hint cannot economically enumerate
   (e.g., "is `numpy` available?", "is `socat` on PATH?").

The manifest MUST be derived from **in-guest introspection** —
the planner-core probe runs inside the VM (reading
`std::env::vars()`, walking `PATH`, parsing `*.dist-info/METADATA`,
shelling out to `rustc --version` / `go version` / `npm list -g`)
— NOT from a kernel-side static catalog. This guarantees the
manifest is faithful to the bytes actually booted, including
operator-published BYO images (per
`INV-OPERATOR-CUSTOM-IMAGE-01`) whose contents the kernel has no
prior knowledge of.

The manifest MUST exclude **kernel-private env vars**: the
`RAXIS_VSOCK_LOOPBACK_PLAN` payload, the kernel-stamped session
token (`RAXIS_PLANNER_SESSION_TOKEN`), the inline / sidecar task
prompt (`RAXIS_PLANNER_TASK_PROMPT*`), the inline KSB
(`RAXIS_PLANNER_KSB`), and any `*_TOKEN` / `*_SECRET` /
`*_PASSWORD` / `*_API_KEY` pattern match. Kernel-private vars
that legitimately stamp connection coordinates (the credential-
proxy `DATABASE_URL` / `MONGO_URL` / `REDIS_URL` / `SMTP_URL`
family) are surfaced verbatim because they are the model's only
legitimate handle on the proxy fleet.

The manifest MUST be **deterministic** for a given (image
digest, session env) pair: the same image booted with the same
proxy stamping MUST produce a byte-identical manifest. This is
load-bearing for prompt-cache stability — the system-prompt
capability hint is rendered from the same cached manifest, so
two sessions on the same image hit the same prompt prefix and
benefit from provider-side prompt caching. Determinism is
achieved by sorting every collection (binaries, package names,
env-var names) into `BTreeMap` / `BTreeSet` ordering and by
filtering `std::env::vars()` through the same allowlist /
redaction logic on every probe.

The manifest MUST be **cached per-process**: the planner-executor
is one-shot per session, so a process-wide `OnceLock` is the
correct cache scope. The system-prompt hint and the
`vm_capabilities` tool MUST read from the same cache so their
outputs are byte-coherent — a model that sees `pymongo 4.10.1`
in the hint and then calls `vm_capabilities { python_package:
"pymongo" }` MUST get the same version back.

**Justification.** Without this invariant, the model has no
in-band way to learn what the VM contains. The two failure
modes the invariant eliminates are: (a) the model writes a
script importing a missing module (`import numpy`), the script
fails at runtime, the model wastes a turn diagnosing a
missing-package error and then proposes `pip install numpy`
which also fails because egress is gated; (b) the model proposes
`pip install pymongo` BEFORE attempting the import, the install
silently fails (no egress) or gets blocked by tproxy, and the
model again wastes a turn. Both failure modes burn token
budget against `INV-PLANNER-HARNESS-01`'s ceiling on the wrong
problem. The capability hint pre-empts both: the model sees
`pymongo 4.10.1` in the system prompt and writes `import
pymongo` directly. The structured tool covers the long tail of
queries the curated hint omits.

The "in-guest, not kernel-side" constraint is what makes the
mechanism image-agnostic. A kernel-side static catalog would
need to be re-shipped every time `policy.toml [[vm_images]]`
admits a new BYO image — an unacceptable coupling between the
kernel binary and operator artifacts. In-guest introspection
shifts the cost to the per-session probe (sub-second on warm
VM) and removes the coupling entirely.

The kernel-private redaction is a defence-in-depth boundary on
top of the kernel-stamped env-var allowlist: even if a future
kernel revision accidentally stamps a sensitive var into the
guest env (a one-line bug in the executor-spawn code), the
manifest probe MUST NOT re-export it to the LLM transcript or
the system prompt.

The determinism + per-process caching constraints are what make
the mechanism **prompt-cache-safe**. Without determinism, two
sessions on the same image would produce different system-prompt
prefixes, defeating provider-side prompt caching and re-billing
the operator for the manifest tokens on every session. Without
per-process caching, every `vm_capabilities` invocation would
re-walk `PATH` and re-parse `*.dist-info/METADATA`, breaking
the sub-second budget in §3 above.

**Scenario.** An Executor session boots on the canonical
`raxis-executor-starter` image. The planner-core driver, in
`run_role_session_with_connected_transport`, calls
`vm_capabilities::cached_capabilities()` to populate the
process-wide `OnceLock` and renders
`vm_capabilities::build_capability_hint` into the role NNSP
before folding the KSB. The model's first turn sees a
`## VM Environment` block listing `Python 3.11.2 (site:
/usr/lib/python3.11/dist-packages)`, `Node 20.18.0`, `Rust
1.78.0`, `Go 1.22.0`, the curated DB-client subset
(`psycopg2-binary 2.9.10, pymongo 4.10.1, redis 5.2.1, PyMySQL
1.1.1, pymssql 2.3.2`), the curated CLI subset (`bash, git, gh,
jq, ripgrep, fd, curl, wget, make, gcc`), the credential-proxy
env-var names (`DATABASE_URL, MONGO_URL, REDIS_URL, SMTP_URL`),
the workdir (`/workspace/repo` + git head), and the egress
warning. The model, instead of guessing, writes a Python script
that does `import pymongo` and uses `os.environ["MONGO_URL"]`
on the first turn — no wasted turn diagnosing a missing
package, no wasted turn on a blocked `pip install`. Later, the
model wonders whether `numpy` is available; it calls
`vm_capabilities { categories: ["python"], filter: {
python_package: "numpy" } }` and gets back `{ name: "numpy",
version: null, importable: false }` instantly.

A negative scenario: the kernel stamps
`RAXIS_VSOCK_LOOPBACK_PLAN` into the guest env (it must, for
the loopback-transport plumbing). The capability probe sees
the var in `std::env::vars()`, recognises it via
`is_kernel_private_env`, and emits `RAXIS_VSOCK_LOOPBACK_PLAN:
"<redacted>"` in the manifest's `env` map — never the
base64 payload itself. The system-prompt hint's "Credential-
proxy env vars" line lists the `DATABASE_URL` / `MONGO_URL`
/ `REDIS_URL` / `SMTP_URL` names but never
`RAXIS_VSOCK_LOOPBACK_PLAN`. A model that asks
`vm_capabilities { categories: ["env"], filter: { env_var:
"RAXIS_VSOCK_LOOPBACK_PLAN" } }` gets back `"<redacted>"` for
the value (presence is acknowledged so the model knows the
var is set; the value never reaches the transcript).

**Canonical home.** `v2/canonical-images.md` §"VM capability
discovery" and `v2/planner-harness.md §10.6` (probe site +
cache scope + redaction allowlist + system-prompt hint
formatter). Implementation: `raxis/crates/planner-core/src/`
modules `vm_capabilities.rs` (probes + cache + manifest
projection + hint formatter) and `tools_vm_capabilities.rs`
(LLM-callable tool wrapper). Wired into all three role
registries by `tools::build_executor_registry`,
`build_reviewer_registry`, and `build_orchestrator_registry`
(plus the `_with_sleep` variants) so every role session
satisfies the "tool availability" leg of the invariant.

---

## §10.5 — Image resolution & operator-published images (INV-IMAGE-*, INV-OPERATOR-CUSTOM-IMAGE-*)

Canonical home: `v2/canonical-images.md` (BYO end-to-end flow) and
`v2/image-cache.md` (resolver trait + on-disk cache layout). These
invariants pin the trust contract that binds the kernel's
`policy.toml [[vm_images]]` admit-list to the bytes the substrate
actually boots from. They sit alongside the `INV-PLANNER-HARNESS-*`
canonical-image invariants (`INV-PLANNER-HARNESS-02` /
`INV-PLANNER-HARNESS-05`) which cover the kernel-bundled Reviewer
and Orchestrator images: the Operator-Custom-Image invariants below
say "if you DO let operators ship their own image, here's the trust
plumbing that survives the supply-chain hop", and the
Image-Resolution-Per-Role invariant says "no role's image gets
silently mis-bound to another role's image at activation".

### INV-IMAGE-RESOLUTION-PER-ROLE-01 — Per-role image binding is
non-substitutable

**Statement.** Every session-spawn admits exactly ONE image-
resolution path per agent role:

* **Orchestrator activations** resolve through the kernel-canonical
  `raxis-orchestrator-core` preflight in
  `kernel/src/canonical_images_preflight.rs` —
  `EXPECTED_ORCHESTRATOR_IMAGE_DIGEST` is compiled into the kernel
  binary and re-verified at each spawn; mismatch fires
  `SecurityViolationDetected { violation_kind:
  "OrchestratorImageDigestMismatch" }` and refuses activation
  (`INV-PLANNER-HARNESS-05`).
* **Reviewer activations** resolve through the kernel-canonical
  `raxis-reviewer-core` preflight, with the analogous compiled-in
  `EXPECTED_REVIEWER_IMAGE_DIGEST` and
  `SecurityViolationDetected { violation_kind:
  "ReviewerImageDigestMismatch" }` taxonomy
  (`INV-PLANNER-HARNESS-02`).
* **Executor activations** resolve through one of two paths,
  selected at admission and stamped on the activation row:
    1. The operator-published `[[vm_images]]` registry, via
       `kernel/src/handlers/intent.rs::resolve_vm_image_override`
       calling
       `raxis_image_cache::ImageResolver::resolve(oci_digest, …)`.
       The resolver verifies the on-disk SHA-256 against the
       policy-declared `oci_digest` and emits
       `VmImageResolved { agent_role: "Executor", … }` on success
       OR `SecurityViolationDetected { violation_kind:
       "OperatorImageDigestMismatch" }` on mismatch
       (`INV-OPERATOR-CUSTOM-IMAGE-01`,
       `INV-OPERATOR-CUSTOM-IMAGE-02`).
    2. The kernel-canonical `raxis-executor-starter` fallback when
       no `[[vm_images]]` alias is bound to the activation. Same
       preflight shape as Orchestrator / Reviewer.

Cross-wiring is structurally rejected at policy load:
`[[vm_images]]` entries declaring `role_restriction` containing
`"Reviewer"` or `"Orchestrator"` fail with
`FAIL_REVIEWER_VM_IMAGE_NOT_ALLOWED` /
`FAIL_ORCHESTRATOR_VM_IMAGE_NOT_ALLOWED` (per
`policy/src/bundle.rs::validate_vm_images` — the
`role_restriction` field is a `Vec<String>` admit-list, not a
single role token). At admission,
`validate_task_vm_images` rejects `[[tasks]] vm_image = "..."`
on Reviewer-typed tasks with `reviewer_image_not_allowed`. The
`VmImageResolved` audit event's `agent_role` field is normatively
constrained to `"Executor"` so an audit-replay reader observing
any other value is observing a kernel bug.

A stub-fallback path that silently substitutes the canonical
starter when the BYO resolution fails is structurally absent —
both admission (`validate_vm_images` /
`validate_default_executor_image`) and activation
(`resolve_vm_image_override` returning a structured
`VmImageResolveError` consumed by the activation handler) fail
closed with `FAIL_POLICY_VIOLATION`, leaving the activation row
in `PendingActivation` so the operator observes the failure and
can repair `policy.toml`.

**Justification.** The four roles (Orchestrator, Reviewer,
Executor, Verifier) carry distinct trust scopes and distinct
toolsets. An Executor image silently backing a Reviewer
activation would surface the entire Executor toolchain (build
toolchain, package managers, network egress) inside the
trust-anchor role that `INV-PLANNER-HARNESS-01` forbids from
running code at all. Conversely, a Reviewer image backing an
Executor activation would surface as "task fails to invoke
its language tooling" — a noisy correctness failure rather than
a silent security failure, but still a correctness regression no
operator should hit. Fail-closed at admission AND activation
closes both directions of cross-binding before the substrate
boots.

**Scenario.** An operator publishes
`[[vm_images]] name = "ops-shared-rust" oci_digest =
"sha256:abc..." role_restriction = ["Executor"]` and writes a
plan with `[[tasks]] task_id = "review-pass-1"
session_agent_type = "Reviewer" vm_image = "ops-shared-rust"`.
At `approve_plan`, `validate_task_vm_images` walks the plan,
hits the Reviewer task with a non-empty `vm_image` field, and
rejects with `reviewer_image_not_allowed` + remediation message.
The plan never admits; the kernel-canonical Reviewer image is
the only image any Reviewer activation can ever boot from
(`INV-PLANNER-HARNESS-02`).

**Canonical home.** `v2/canonical-images.md §2`.

---

### INV-OPERATOR-CUSTOM-IMAGE-01 — Operator images are digest-pinned, mismatches fail closed

**Statement.** Every operator-published `[[vm_images]]` entry MUST
declare an `oci_digest` of shape `sha256:<64 lower-hex>`
(`policy/src/bundle.rs::validate_vm_images`'s
`FAIL_POLICY_VM_IMAGE_DIGEST_INVALID` rejects any other shape at
policy load). At every Executor session-spawn that resolves to a
`[[vm_images]]` alias, the kernel
(`kernel/src/handlers/intent.rs::resolve_vm_image_override`) calls
`raxis_image_cache::ImageResolver::resolve(oci_digest, …)`. The
resolver implementation
(`raxis_image_cache::PrePopulatedResolver` for offline-staged
caches; `raxis_image_cache::ProductionResolver` for registry-
backed pulls) stream-hashes the on-disk rootfs bytes and returns
`ImageResolverError::DigestMismatch { expected, actual, path }`
on any divergence. The activation handler maps that error to
`SecurityViolationDetected { violation_kind:
"OperatorImageDigestMismatch", expected, actual, path }` AND
`FAIL_POLICY_VIOLATION` — the activation row stays in
`PendingActivation` so the operator can either rebuild the
on-disk artefact to match the declared digest or amend
`policy.toml` to the digest the bytes actually hash to.

The audit event's `expected` / `actual` carry the canonical
`sha256:<hex>` strings from
`raxis_image_cache::OciDigest::to_string()`; `path` carries the
on-disk path the resolver was hashing
(`<data_dir>/oci-cache/images/sha256/<aa>/<full>/rootfs.img` for
the offline-staged path). The dashboard's
`notification_priority` classifies every
`SecurityViolationDetected` variant as `Critical` — operators
are paged immediately.

The trust anchor is the operator's signature on `policy.toml`:
the kernel verifies (a) the policy bundle's signature chains to
an active operator certificate, then (b) the `oci_digest` in the
admitted bundle matches the resolved bytes. There is no
"unsigned image" path; an `oci_digest` typo at policy-sign time
surfaces as the same audit event the test asserts on, with the
operator-typo'd digest in `expected` and the on-disk SHA in
`actual`.

**Justification.** A signed-policy / unsigned-bytes split would
let any host-side write to `<data_dir>/oci-cache/` swap a
trusted image for a malicious one without re-signing the
operator policy — the kernel would happily boot whatever
rootfs.img it found at the layout-derived path. Pinning the
digest at policy-sign time AND re-verifying at every spawn
collapses that gap into a single trust boundary: tampering the
on-disk bytes requires also tampering the operator's signed
policy, which requires the operator's signing key.

**Scenario.** Operator publishes `[[vm_images]] name =
"executor-rust-v1" oci_digest = "sha256:9c41..."`. A host-side
attacker with filesystem write access (compromised CI runner
sharing the data dir) overwrites
`<data_dir>/oci-cache/images/sha256/9c/9c41…/rootfs.img` with
a tampered build whose `cargo` silently exfiltrates
`Cargo.toml` over the egress allowlist. On the next Executor
session-spawn against this alias, the kernel's resolver
stream-hashes the new bytes, finds the SHA-256 doesn't match
`sha256:9c41...`, returns `DigestMismatch { expected: 9c41…,
actual: <new-hash>, path: …/rootfs.img }`. The activation
handler emits `SecurityViolationDetected { violation_kind:
"OperatorImageDigestMismatch", expected: "sha256:9c41…",
actual: "sha256:<new-hash>", path: "…/rootfs.img" }` and
fails the activation with `FAIL_POLICY_VIOLATION`. The
attacker-staged image never boots; the operator is paged via
the Critical-priority notification.

**Canonical home.** `v2/canonical-images.md §3`.

---

### INV-OPERATOR-CUSTOM-IMAGE-02 — Operator-image plumbing is identical to canonical-image plumbing

**Statement.** The same kernel-side trust contract that pins the
canonical Orchestrator and Reviewer images
(`INV-PLANNER-HARNESS-05` / `INV-PLANNER-HARNESS-02`: declare a
SHA-256, re-verify at every spawn, fail-closed with
`SecurityViolationDetected` on mismatch) ALSO governs every
operator-published `[[vm_images]]` entry. There are NOT two
distinct plumbing paths — the difference between a canonical
image and a BYO image is WHERE the expected digest lives
(compiled into the kernel binary for canonical, declared in
signed `policy.toml` for BYO), not HOW the digest is verified
or what shape the audit event takes.

Concrete uniformity:

1. **Verification mechanism.** Both paths stream-hash the on-disk
   rootfs bytes with `sha2::Sha256` (the canonical preflight via
   `raxis_canonical_images::compute_image_digest`; the BYO path
   via `raxis_image_cache::PrePopulatedResolver::resolve` →
   `compute_image_sha256`). Both compare against the
   policy-declared / kernel-binary-pinned digest as a
   constant-time equality.
2. **Failure shape.** Both fail closed with
   `SecurityViolationDetected { kind / violation_kind: "<...>
   ImageDigestMismatch", expected, actual, path }`. The variant
   discriminant is the same (`SecurityViolationDetected`); the
   `violation_kind` taxonomy distinguishes the role
   (`ReviewerImageDigestMismatch`,
   `OrchestratorImageDigestMismatch`,
   `OperatorImageDigestMismatch`). All three classify as
   `Critical` at the dashboard layer.
3. **Success shape.** Canonical images log `canonical_image_ok`
   from the preflight. BYO images emit `VmImageResolved` from
   the activation handler. Both fire BEFORE the substrate spawn
   step proceeds, so the audit chain records the resolution
   independent of whether the spawn ultimately succeeds — a
   forensics reader walking the chain can always recover "which
   bytes booted this session" without re-running the resolver.
4. **Activation gating.** Both paths refuse the activation on
   mismatch; both leave the activation row in
   `PendingActivation` so operator-side recovery is observable.
5. **Forward compatibility.** A future production registry-pull
   resolver implementation
   (`raxis_image_cache::ProductionResolver` per
   `image-cache.md §6`) preserves the same byte-equality contract
   on the cached blob, so wiring it in does not change the
   audit-event surface or the trust anchor — the BYO trust
   contract is registry-implementation-agnostic.

**Justification.** Two divergent plumbing paths would create
two divergent failure modes operators have to learn: a
canonical-image tamper would surface as one taxonomy and one
remediation, a BYO-image tamper as another. The dashboard,
SOC playbooks, and `raxis doctor` would each need to handle
both. A uniform contract collapses the operator-facing surface
to a single mental model ("digest pinning, fail-closed on
mismatch, Critical notification, look in `<data_dir>/oci-cache/`
for BYO or `<install_dir>/images/` for canonical") and makes
the security guarantee composable: if one path's mechanical
witness passes, the corresponding witness for the other path
passes for free.

**Scenario.** A new role added in V3 (e.g. a dedicated
`Auditor` image) only needs to declare its expected digest in
the kernel binary (canonical) OR in `policy.toml` (operator-
published), declare its `[[vm_images]] role_restriction`
admit-list, and wire its activation handler to call the same
`ImageResolver::resolve` (or
`canonical_images_preflight::verify_canonical_image_via_manifest`).
No new audit-event variant, no new dashboard category, no new
trust contract surface — the existing
`SecurityViolationDetected` taxonomy plus the existing
`VmImageResolved` event extend by adding a new
`violation_kind` string and a new `agent_role` value
respectively. `INV-OPERATOR-CUSTOM-IMAGE-02` makes that
extensibility shape normative.

**Canonical home.** `v2/canonical-images.md §3`.

---

### INV-IMAGE-BAKE-NO-STALE-CACHE-01 — `build-all` MUST refuse (or auto-rebake) any role whose staged planner binary predates its source tree

**Statement.** When `cargo xtask images build-all` runs (the
final step of the macOS-hermetic dev-host image-build pipeline
defined in `planner-harness.md §14.4`), it MUST verify for each
role being packed that the staged planner binary at
`images/<role>-core/rootfs/usr/local/bin/<binary>` is at least as
new as every regular file under both
`crates/planner-<role>/src/**` and
`crates/planner-core/src/**`. If any source file's mtime
postdates the staged binary's mtime — i.e. the staging tree was
left stale by a `dev-stage` skipped after a later source edit —
`build-all` MUST take one of two actions:

1. **Default (auto-rebake).** Synthesise a `DevStageArgs` for the
   role and invoke `dev_stage(&DevStageArgs)` internally before
   packing the cpio. The cross-compile re-runs (incrementally,
   so the overhead is seconds when nothing else changed) and the
   freshly-built binary overwrites the stale staging-tree entry.
   The auto-rebake emits a structured `build_all_auto_stage_invoked`
   warn line carrying the role, staged-binary mtime, newest
   source-file path, and source-file mtime, so a build-log replay
   can answer "did the guard fire on this role" without trawling
   filesystems.
2. **`--no-auto-stage` (hermetic CI).** Refuse to pack the cpio
   and bail with an error whose message contains the literal
   token `INV-IMAGE-BAKE-NO-STALE-CACHE-01 VIOLATED`, the per-role
   `cargo xtask images dev-stage --role <role>-core` remediation,
   and the precise file pair (staged path, newest source path,
   both mtimes) that drove the verdict. Reserved for release-CI
   lanes that already ran `dev-stage` as a separate audit-tracked
   step and want `build-all` to fail closed rather than silently
   re-running the cross-compile.

A `Missing` staged binary (the staging path does not exist at all
because `dev-stage` was never run for this role) is treated
identically to a `Stale` verdict: auto-rebake under the default,
fail closed under `--no-auto-stage`. A `Fresh` verdict — every
source file's mtime ≤ staged-binary mtime — emits a
`build_all_freshness_check_fresh` info line and proceeds with no
filesystem mutation.

**Justification.** Iter53's reviewer-VM spawn failure
(`ActivateSubTaskSpawnFailed { agent_kind: "Reviewer", error:
"vsock CONNECT 1024: ... Connection reset by peer" }`, ~30 s into
the first reviewer activation) had a structural root cause: the
canonical reviewer image at
`/usr/local/lib/raxis/images/raxis-reviewer-core-0.1.0.img`
contained a planner binary built before
`crates/planner-core/src/driver.rs::read_task_prompt` learned to
read the `RAXIS_PLANNER_TASK_PROMPT_PATH` sidecar variable.
After the sidecar codepath landed the operator ran `dev-stage`
for orchestrator and executor-starter but not reviewer; the next
`build-all` invocation happily packed the May-12 stale reviewer
binary into a fresh May-13 cpio.gz, signed the manifest, and
shipped it. The kernel's session-spawn intentionally drops the
inline `RAXIS_PLANNER_TASK_PROMPT` env (see
`kernel/src/session_spawn_orchestrator.rs` lines 3697-3744 — the
inline prompt is cleared whenever the sidecar path is provided
to avoid AVF cmdline truncation), so the stale binary saw an
empty prompt, dropped into `DriverOutcome::Scaffold`, and called
`park_on_signal()` — never opening the vsock listener the host
was trying to connect to. The visible symptom 30 s later was
`vsock CONNECT 1024: ... Connection reset by peer`, indistinguishable
on the host side from a genuine VM boot failure.

The fix has TWO load-bearing parts:

1. The mtime-based freshness check itself, which mechanically
   detects the iter53 reproduction shape (an operator who runs
   `dev-stage` for some roles but not others, or who edits
   `planner-core` and forgets to re-stage downstream).
2. The auto-rebake default, which makes the fix invisible to
   operators in the common case — a routine `build-all`
   invocation simply does the right thing without needing to
   remember to chain `dev-stage` per role. Hermetic CI keeps
   the fail-closed behaviour via `--no-auto-stage`, so the
   release-track audit trail is unaffected.

The guard sits at the BUILD layer, not the BOOT layer:
`build-all` is the gate every canonical image must traverse
before reaching `<install_dir>/images/`, so a stale binary
cannot make it into the operator-visible artefact in the first
place. The orthogonal cpio-walk preflight described in
`planner-harness.md §14.4` ("Per-role required-binary cpio-walk
preflight") and `INV-PLANNER-HARNESS-02 / -05` (image digest
verification) operate at the trust layer (post-pack); this
invariant operates at the freshness layer (pre-pack). The two
layers compose: even an attacker who somehow re-signs a stale
manifest cannot evade the build-time freshness check, and
even an operator who somehow disables auto-rebake cannot evade
the boot-time digest check.

**Scenario.** An operator edits
`crates/planner-core/src/driver.rs` to add a new env-handling
codepath (the iter53 reproduction shape was adding sidecar
support to `read_task_prompt`). They run
`cargo xtask images dev-stage --role orchestrator-core` and
`cargo xtask images dev-stage --role executor-starter` then
forget reviewer. The next
`cargo xtask images build-all` invocation:

* Reads `images/orchestrator-core/rootfs/usr/local/bin/raxis-orchestrator`,
  observes `mtime ≥ driver.rs mtime` → emits
  `build_all_freshness_check_fresh { role: "raxis-planner-orchestrator" }`,
  packs.
* Reads `images/reviewer-core/rootfs/usr/local/bin/raxis-reviewer`,
  observes `mtime < driver.rs mtime` → emits
  `build_all_auto_stage_invoked { role: "raxis-planner-reviewer",
   reason: "stale_staged_binary", newest_source:
   "crates/planner-core/src/driver.rs", … }`, then runs
  `dev_stage(...)` for the reviewer role, then emits
  `build_all_auto_stage_ok { role: "raxis-planner-reviewer" }`,
  then packs the freshly-staged binary.
* Reads `images/executor-starter/rootfs/usr/local/bin/raxis-executor`,
  observes fresh → packs.

The operator sees `build_all_role_ok` for all three roles and
the canonical images at `/usr/local/lib/raxis/images/` are all
binary-current. No manual remediation step is needed; the iter53
silent-skew shape is structurally unreachable.

Under `--no-auto-stage` the same scenario produces a bail with
the literal `INV-IMAGE-BAKE-NO-STALE-CACHE-01 VIOLATED for role
Reviewer: staged planner binary
images/reviewer-core/rootfs/usr/local/bin/raxis-reviewer
(mtime <T1>) is older than source file
crates/planner-core/src/driver.rs (mtime <T2>) …` plus the
remediation command, so the CI lane operator can replay the
exact dev-stage invocation that would have unblocked the build.

**Witness.**
[`xtask::images::tests::inv_image_bake_no_stale_cache_01_verdict_stale_when_planner_core_newer`](../xtask/src/images.rs):
synthesises the iter53 reproduction shape (a staged reviewer
binary plus a newer `crates/planner-core/src/driver.rs`),
classifies the verdict via `check_staged_binary_freshness`, and
pins that the verdict is `Stale` with `newest_source` pointing
at the driver.rs path — the operator-visible fingerprint that
explains *why* the auto-rebake fires.
Pairs with
[`…::inv_image_bake_no_stale_cache_01_verdict_stale_when_role_src_newer`](../xtask/src/images.rs)
(symmetric for `crates/planner-<role>/src/main.rs`),
[`…::inv_image_bake_no_stale_cache_01_verdict_fresh_when_staged_newer_than_source`](../xtask/src/images.rs)
(no-op happy path),
[`…::inv_image_bake_no_stale_cache_01_verdict_missing_when_no_staged_binary`](../xtask/src/images.rs)
(dev-stage never ran for the role),
[`…::inv_image_bake_no_stale_cache_01_verdict_fresh_when_no_source_tree`](../xtask/src/images.rs)
(release-tarball worktree with no `crates/` — packing allowed),
[`…::inv_image_bake_no_stale_cache_01_planner_source_dirs_per_role`](../xtask/src/images.rs)
(pins the two-dir contract so a future role addition surfaces as
a compile-time TODO rather than a silent miss),
[`…::inv_image_bake_no_stale_cache_01_newest_mtime_walks_files_recursively`](../xtask/src/images.rs)
(depth-first walk, deepest mtime wins),
[`…::inv_image_bake_no_stale_cache_01_newest_mtime_returns_none_for_missing_root`](../xtask/src/images.rs)
(absent-tree case),
[`…::inv_image_bake_no_stale_cache_01_no_auto_stage_bails_on_stale_with_remediation`](../xtask/src/images.rs)
+
[`…::inv_image_bake_no_stale_cache_01_no_auto_stage_bails_on_missing_with_remediation`](../xtask/src/images.rs)
(fail-closed remediation contains the invariant token, the
`dev-stage --role <role>-core` command, and the `--no-auto-stage`
opt-out hint), and
[`…::inv_image_bake_no_stale_cache_01_fresh_returns_ok_without_subprocess`](../xtask/src/images.rs)
(fresh binary returns Ok without invoking the cargo subprocess).
The CLI surface itself is pinned by
[`…::build_all_args_default_no_auto_stage_is_false`](../xtask/src/images.rs)
+
[`…::build_all_args_no_auto_stage_flag_parses`](../xtask/src/images.rs)
— the auto-rebake default is the load-bearing UX bit; flipping
that default would silently re-introduce the iter53 failure
mode without any other test catching it.

**Canonical home.** `v2/planner-harness.md §14.4` (image-build
pipeline) — the freshness check is one of three guards listed
in the "Why the dev-stage guard, the cpio-walk preflight, and
the freshness check are all load-bearing" subsection. The
operator-facing recipe `guides/recipes/ops/...` notes the
auto-rebake behaviour so operators know they can simply run
`build-all` after editing planner-core without remembering to
chain `dev-stage` per role.

---

### INV-EXECUTOR-IMAGE-LINT-TOOLCHAIN-PYTHON-01 — Canonical executor-starter image MUST ship a working `ruff` without task-time egress

**Statement.** The kernel-built canonical executor-starter image
(`raxis-executor-starter-<kver>.img`, distributed under
`$RAXIS_INSTALL_DIR/images/`) MUST ship the Python lint
toolchain (`ruff`) at a pinned, declared version in the
rootfs's system Python site-packages, such that both
`/usr/local/bin/ruff --version` AND `python3 -m ruff --version`
succeed without any task-time network access. The pin is
declared in two places that the image-build verifier
cross-checks: the `RUN pip3 install --break-system-packages
"ruff==<X.Y.Z>"` line in `raxis/images/executor-starter/
Containerfile` and the `[lint_toolchain] ruff_version = "X.Y.Z"`
field in `raxis/images/executor-starter/manifest.toml`. The
post-bake verifier `raxis/images/executor-starter/verify.sh`
MUST refuse the bake if the matching `ruff-<X.Y.Z>.dist-info/`
directory is absent from any `usr/lib/python3*/dist-packages/`
or `usr/local/lib/python3*/dist-packages/` root in the rootfs.
Bumping the pin requires a synchronous edit of the Containerfile,
the manifest, AND the verifier's `RUFF_PINNED_VERSION` shell
constant; an asymmetric bump surfaces at bake time as
`INV-EXECUTOR-IMAGE-LINT-TOOLCHAIN-PYTHON-01 VIOLATED`.

**Justification.** Iter56's `lint-runner-python` task burned
the entirety of its 60-turn budget on the lit failure shape
`/usr/bin/python: No module named ruff / raxis_check_sh_exit_code=1`.
The task prompt
([`kernel/tests/extended_e2e_support/plan_realistic.rs::TASK_LINT_RUNNER_PYTHON`](../kernel/tests/extended_e2e_support/plan_realistic.rs))
invokes `python -m ruff check . && python -m ruff format
--check .` against the seed `py-pkg/`, whose `ruff.toml`
selects `E,F,W,I,B,UP,SIM` rule families. The executor VM
ships with **no preconfigured egress allowlist** by default
(`planner-harness.md §10.6` egress posture, `INV-VM-EGRESS-01`),
so the runner cannot `pip install ruff` at runtime — the
binary / module must already be importable from the rootfs's
own site-packages. Parallel `lint-runner-rust` works because
`cargo` + `rustfmt` + `clippy` are rustup-baked at image build
time AND the seed crate's `[dependencies]` is empty (cargo
makes no network call against an empty dep tree). The Python
side reaches identical structural shape via the
`pip3 --break-system-packages "ruff==..."` layer in the
Containerfile.

The verifier's pin-version cross-check is the load-bearing
guard against a silent bump on the next bake. Without it, an
operator who replaces `ruff==0.7.4` with `ruff` (no pin) in the
Containerfile would silently start shipping whatever PyPI's
HEAD ruff is, breaking the `lint_defect.md` reproduction shape
(the seed defect is `F401 unused-import` — a rule whose
fixture-stable wording the dual-Reviewer pair in
`ReviewerSubstantiveDisagreementWitness` keys on).

**Scenario.** An operator runs `cargo xtask images bake-rootfs
--role executor-starter` against a worktree whose Containerfile
pins `ruff==0.7.4`. The bake completes and the image-builder
invokes `images/executor-starter/verify.sh`:

* `usr/local/bin/ruff` exists → pass.
* `usr/lib/python3.11/dist-packages/ruff-0.7.4.dist-info/`
  exists → pin matches.
* (On a Linux-on-Linux bake host) `python3 -c "import ruff" &&
  python3 -m ruff --version` returns `ruff 0.7.4` → dynamic
  check passes.

The realistic-scenario test then submits `lint-runner-python`;
the task body runs `python -m ruff check .` inside the VM and
produces a non-zero exit code (the upstream `lint-defect`
introduced an `F401 unused-import` defect that ruff 0.7.4
diagnoses verbatim), commits the capture, and `task_complete`s
within ~5 turns. The downstream dual-Reviewer pair reads the
capture, names `greet.py` in the critique, and the witness
asserts `ReviewerSubstantiveDisagreementWitness::Verdict::
SubstantivelyDisagreed` per the canonical iter55 trajectory.

The fail-closed scenario: an operator hand-edits the
Containerfile from `ruff==0.7.4` to `ruff==0.8.0` but forgets
to bump `manifest.toml` `[lint_toolchain] ruff_version` and
`verify.sh` `RUFF_PINNED_VERSION`. The bake's `pip install`
succeeds (pip happily installs the newer version), but
`verify.sh` then looks for `ruff-0.7.4.dist-info/` in the
rootfs, finds `ruff-0.8.0.dist-info/` instead, and bails with
`verify: ruff-0.7.4.dist-info not found ... INV-EXECUTOR-IMAGE-
LINT-TOOLCHAIN-PYTHON-01 VIOLATED`. The bake is rejected before
the manifest is signed.

**Witness.**
[`xtask::tests::executor_starter_lint_toolchain::inv_executor_image_lint_toolchain_python_01_*`](../xtask/tests/executor_starter_lint_toolchain.rs)
— a set of synthetic-rootfs witnesses that build a tempdir
fixture mirroring the Containerfile's expected layout
(`usr/local/bin/ruff`, the matching dist-info dir, and a
stubbed `manifest.toml` + `verify.sh`) and run `verify.sh`
against it. The witnesses pin:

* Happy path — `verify.sh <fixture>` exits 0 when the pinned
  ruff dist-info is present and the CLI shim is in place.
* Missing dist-info — `verify.sh` exits non-zero with the
  literal `INV-EXECUTOR-IMAGE-LINT-TOOLCHAIN-PYTHON-01 VIOLATED`
  token AND the `bake-rootfs --role executor-starter`
  remediation command in the error body.
* Version drift — a fixture carrying `ruff-0.8.0.dist-info`
  (instead of the pin `0.7.4`) trips the same invariant token,
  so a silent transitive bump surfaces at bake time rather than
  at the next `lint-runner-python` task run.

**Canonical home.** `v2/planner-harness.md §10.6` (canonical
executor starter image manifest — "Pre-installed lint
toolchain" subsection) and `§14.4` (image-build pipeline,
normative-pins paragraph). The witness binds the Containerfile
pin, the manifest pin, and the verifier-script pin into one
auditable triple.

---

### INV-EXECUTOR-IMAGE-LINT-TOOLCHAIN-JS-01 — Canonical executor-starter image MUST ship working `eslint` + `prettier` + `tsc` + `tsx` without task-time egress

**Statement.** Sibling of
`INV-EXECUTOR-IMAGE-LINT-TOOLCHAIN-PYTHON-01` for the
JavaScript / TypeScript lane. The canonical executor-starter
image MUST ship `eslint`, `prettier`, `typescript` (which
provides the `tsc` shim), `tsx`, and `@types/node` at pinned
versions in the rootfs's global node_modules root
(`usr/lib/node_modules/<pkg>/` or
`usr/local/lib/node_modules/<pkg>/`), with executable shims
on `$PATH` at `/usr/bin/<bin>` or `/usr/local/bin/<bin>`.
`npx --no-install <bin>` from the realistic-scenario
`lint-runner-js` task body MUST succeed against the seed
`ts-pkg/` directory (which has NO local `node_modules/`)
because npx's resolution fallback order — local node_modules
→ parent walk → global node_modules → `$PATH` — terminates on
the global install before the `--no-install` clause errors out.
Pin declaration mirrors the Python invariant: the Containerfile,
the `manifest.toml` `[lint_toolchain]` table, and `verify.sh`
all carry the same version triple; an asymmetric bump surfaces
as `INV-EXECUTOR-IMAGE-LINT-TOOLCHAIN-JS-01 VIOLATED` at bake
time.

**Justification.** Iter56's `lint-runner-js` task captured the
failing shape
`npm error code EAI_AGAIN / npm error request to
https://registry.npmjs.org/eslint failed, reason: getaddrinfo
EAI_AGAIN registry.npmjs.org / raxis_check_sh_exit_code=1` —
exactly mirroring the Python failure mode, structurally
explained by the same root cause: the seed materializer ships
no `node_modules/`, the VM has no egress, and the task body's
`npx --no-install` correctly refuses to fetch from the
registry. The fix is parity: pre-bake the four linters
globally at image-build time so `npx --no-install`'s
resolution-fallback to `$PATH` finds them before the
`--no-install` branch fires. The fail-closed contract on
`verify.sh` is what prevents the asymmetric-bump regression
(e.g. an operator updating only the Containerfile to
`eslint@10.x` without updating the documented pin in
`manifest.toml`).

**Scenario.** Symmetric to the Python invariant's scenario.
Happy path: bake completes, verifier asserts
`usr/lib/node_modules/{eslint,prettier,typescript,tsx}/`
exists AND `/usr/bin/{eslint,prettier,tsc}` shims are in place;
realistic-scenario `lint-runner-js` task runs `npx --no-install
eslint --max-warnings 0 .`, npx resolves through `$PATH` to the
global eslint, and the capture lands with exit code 0 (or with
the Python-only seed defect's exit-code-zero clean shape on a
JS-not-targeted iter). Fail-closed: dropping `eslint` from the
`npm install -g` line in the Containerfile (or hand-editing the
rootfs to remove the dist tree) trips `verify.sh` with
`missing global node_modules/eslint under either
/usr/lib/node_modules/ or /usr/local/lib/node_modules/ ...
INV-EXECUTOR-IMAGE-LINT-TOOLCHAIN-JS-01 VIOLATED` plus the
`bake-rootfs --role executor-starter` remediation.

**Witness.**
[`xtask::tests::executor_starter_lint_toolchain::inv_executor_image_lint_toolchain_js_01_*`](../xtask/tests/executor_starter_lint_toolchain.rs)
— synthetic-rootfs witnesses covering happy path, each linter
removed individually (one witness per `eslint` / `prettier` /
`typescript` / `tsx` so a future regression that drops just
one surfaces with the correct package name in the violation
message), and CLI-shim-missing-but-module-present (`npm
install -g` succeeded but the symlink step failed — the verifier
must still reject because `$PATH` resolution is the load-bearing
mechanism, not the module presence alone).

**Canonical home.** `v2/planner-harness.md §10.6` (canonical
executor starter image manifest — "Pre-installed lint
toolchain" subsection) and `§14.4` (image-build pipeline). The
witness binds the Containerfile pin, the manifest pin, and the
verifier-script pin into one auditable triple, identical in
shape to the Python invariant.

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

## §11.8a — Universal airgap (Path A3) invariants

These six invariants form the contract for the **universal airgap**
egress model documented in `v2/airgap-architecture.md`. They are
**unconditional** in V2 after the Tier1Tproxy deletion (TODO
`tier1-deletion-fold-into-cleanup-sweep`): the legacy
`EgressTier::Tier1Tproxy` variant, the `runtime-airgap-a3` cargo
feature, and the `RAXIS_AIRGAP_A3` runtime env gate were all
removed in the same sweep. Path A3 is no longer opt-in. The A3
invariants universally supersede the historical role-asymmetric
`INV-NETISO-01` family — the Reviewer / Orchestrator are at
`EgressTier::None` (no NIC); the Executor is at
`EgressTier::Mediated` (also no NIC, with admission over vsock).

### INV-NETISO-A3-UNIVERSAL-NO-NIC-01 — No role's VM has a virtio-net device

The kernel session-spawn path selects `EgressTier::None` for the
Orchestrator and Reviewer roles and `EgressTier::Mediated` for the
Executor, unconditionally. Both V2 microVM substrates honour the
tier: `crates/isolation-apple-vz::translate_to_avf` emits no
network device for any tier, and
`crates/isolation-firecracker::drive_boot` omits the
`PUT /network-interfaces` call for any tier. The guest kernel boots
without an `eth0` (or any other virtio-net device) regardless of
role; the guest networking stack has loopback only.

**Justification.** The pre-deletion audit identified that the
legacy Executor / Orchestrator path under `Tier1Tproxy` shipped a
virtio-net NAT adapter *without* the matching in-guest iptables
enforcement and without the `raxis-tproxy` binary on the rootfs.
Removing the NIC entirely (and then removing the Tier1Tproxy
variant itself in the deletion sweep) makes the enforcement
contract structurally true: the agent has no path around the
kernel admission gate because there is no second path *and there
is no codepath that produces a NIC*.

**Witness.** `kernel/tests/airgap_a3_executor_no_nic.rs`.

**Canonical home.** `v2/airgap-architecture.md §5`.

### INV-NETISO-A3-VSOCK-CHOKEPOINT-01 — Kernel admission gate is the sole arbiter of guest egress

Under A3 every outbound byte the guest produces flows through the
in-guest `raxis-tproxy` binary, which sends a
`TproxyAdmissionRequest` over AF_VSOCK to the kernel-side handler
in `kernel/src/handlers/tproxy_admit.rs`. The handler validates the
session token, looks the (SNI, host_header, destination)
admission tuple up against the session's
`policy.tproxy_allowlist`, and emits the paired audit event
(`TproxyAdmissionGranted` or `TproxyAdmissionDenied`) **before**
sending the response back. Only on Admit does the kernel open the
upstream TCP socket and register a single-use tunnel handle the
guest re-dials over a second vsock connection.

**Justification.** With the NIC removed the agent has exactly one
egress path — the kernel arbitrates every flow, every admission
decision is a kernel-host decision against the active policy
bundle, and the audit chain captures every flow that ever opened
*and* every flow that was refused.

**Witness.** `kernel/tests/airgap_a3_admission_admit_path.rs` and
`kernel/tests/airgap_a3_admission_deny_path.rs`.

**Canonical home.** `v2/airgap-architecture.md §3.1 / §3.2`.

### INV-NETISO-A3-DNS-MEDIATED-01 — DNS queries flow through the kernel under A3

The guest's `/etc/resolv.conf` is rewritten at PID 1 boot to
`nameserver 127.0.0.1`; iptables redirects UDP/53 to a local stub
forwarder (`raxis-tproxy::dns_stub`) that wraps every query in a
`DnsResolveRequest` IPC frame to the kernel over AF_VSOCK. The
guest cannot reach `8.8.8.8:53` (or any other external resolver)
because there is no NIC; even the in-guest DNS stub fails closed if
the kernel admission channel is unavailable. DNS resolution
itself is not an egress grant — the subsequent
`TproxyAdmissionRequest` against the resolved IP is the gate.

**Justification.** A DNS-over-UDP covert channel would otherwise
let a malicious agent exfiltrate data via the query name even
when egress was admin-disabled. Routing every DNS query through
the kernel closes the channel and gives the audit chain the same
visibility into hostname lookup that it has into TCP admission.

**Witness.** `kernel/tests/airgap_a3_dns_resolve.rs`.

**Canonical home.** `v2/airgap-architecture.md §3.3 / §4`.

### INV-NETISO-A3-IPV6-DISABLED-01 — IPv6 is disabled at PID 1 under A3

When the guest boots under A3, PID 1 writes `1` to
`/proc/sys/net/ipv6/conf/{all,default,lo}/disable_ipv6`. The
in-guest tproxy is IPv4-only; the iptables REDIRECT rules are
IPv4-only; the admission handler's `SocketAddr` argument is IPv4.
Leaving IPv6 enabled would let an agent reach loopback-IPv6
(`::1`) services that bypass the iptables `! -d 127.0.0.1/32`
exception used to skip the credential-proxy loopback ports.

**Justification.** Defence in depth — even with no NIC the
in-guest network stack would still bind IPv6 sockets and accept
IPv6 connections on `::1`. Disabling IPv6 makes the loopback
attack surface IPv4-only so the iptables exceptions are
exhaustive.

**Witness.** `kernel/tests/airgap_a3_executor_no_nic.rs` asserts
the `disable_ipv6` sysctls read `1` inside the booted guest's
mount-namespace fixture.

**Canonical home.** `v2/airgap-architecture.md §4`.

### INV-AUDIT-TPROXY-ADMIT-01 — Every tproxy admission emits a paired audit event before the response

`handlers::tproxy_admit::handle` emits exactly one
`AuditEventKind::TproxyAdmissionGranted` (on Admit) or
`AuditEventKind::TproxyAdmissionDenied` (on Deny) **before** the
response frame is written back to the in-guest tproxy. The
ordering matches the paired-write contract used for SQL state
mutations: the guest must not observe an admission whose audit
emission failed. An audit emission failure causes the handler to
return Deny with `reason = "FAIL_AUDIT_EMIT"` so the agent cannot
discover an unobserved admission.

**Justification.** Without the audit-before-response ordering a
malicious guest could exploit a crash-window where the kernel
admitted a flow but the audit emission was lost; the flow would
appear in upstream logs but not in the local chain. The pairing
makes the chain authoritative.

**Witness.** `kernel/tests/airgap_a3_admission_admit_path.rs`
and `kernel/tests/airgap_a3_admission_deny_path.rs` both assert
the audit event is present in the chain by the time the response
arrives at the in-guest tproxy.

**Canonical home.** `v2/audit-paired-writes.md §3` (the
paired-write framework) and `v2/airgap-architecture.md §8`
(specific A3 contract).

### INV-AUDIT-DNS-RESOLVE-01 — Every DNS resolution emits an audit event

`handlers::dns_resolve::handle` emits one
`AuditEventKind::DnsResolveRequested
{ hostname, query_type, resolved_count, ttl_secs }` event before
returning the resolved-address list to the guest. The event is
single-class (low-severity, not paired with an allowlist check
— DNS resolution does not itself grant egress) so it is emitted
synchronously after the resolver call and before the response
frame is written. A resolver failure still emits the event with
`resolved_count = 0` so the audit chain records the hostname the
agent asked about even when the lookup returns NXDOMAIN.

**Justification.** Operators investigating an incident need to
know not only which destinations the agent reached, but which it
*asked about*. A hostname-only audit trail is enough to
reconstruct the agent's reconnaissance pattern even when no
admission was granted.

**Witness.** `kernel/tests/airgap_a3_dns_resolve.rs`.

**Canonical home.** `v2/airgap-architecture.md §3.3 / §8`.

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

### INV-CRED-PROXY-VM-REACHABILITY-01 — Substrate transparently bridges in-VM `127.0.0.1:N` to host loopback

Executor agents inside isolation VMs MUST be able to reach
host-side credential proxies via stock loopback URLs
(`127.0.0.1:<port>`); the kernel substrate (AVF bridge / vsock
forwarder / port-forward) MUST provide this transparently.
Credential material itself MUST NEVER traverse the VM boundary;
only the proxied protocol traffic.

**Mechanical enforcement.** `raxis-session-spawn::spawn_session`
allocates one vsock port per credential proxy, stamps a
`RAXIS_VSOCK_LOOPBACK_PLAN` env var the in-guest forwarder
(`raxis-tproxy::loopback_forwarder`) reads at boot, and registers
a host-side `VZVirtioSocketListener` on the VM's
`VZVirtioSocketDevice` whose delegate splices each accepted vsock
connection to host `127.0.0.1:<host_loopback_port>`. The vsock
port lives on the VM's own vsock device (per-VM isolation
boundary), the forwarder is transport-agnostic (no credential
material ever crosses the boundary), and the agent's stock
libpq / pymongo / redis-py / aws-sdk clients dial
`127.0.0.1:<port>` exactly as on a non-virtualised host. Substrates
that cannot satisfy this invariant MUST refuse
`Session::register_loopback_listener` fail-closed
(`IsolationError::BackendInternal`) so the kernel can tear down
the VM rather than ship a session whose agent silently cannot
reach its credentials.

**Justification.** Without this invariant the credential-proxy
contract breaks the moment the agent runs inside an AVF /
Firecracker VM: the kernel binds proxies on host
`127.0.0.1:NNN`, but `127.0.0.1` inside the VM resolves to the
**guest's** loopback — nothing listens there, every database /
storage / cloud-API task fails with `ECONNREFUSED`, and the
operator-visible failure mode is "the bash tool is completely
non-functional" rather than a clear isolation diagnostic. The
substrate-level fan-out preserves both the credential boundary
(`INV-SECRET-02`, `INV-VM-CAP-04`) and the stock-URL contract
the executor scripts depend on.

**Canonical home.** `v2/credential-proxy.md §12a`,
`raxis/crates/vsock-loopback/src/lib.rs` (wire format),
`raxis/crates/isolation-apple-vz/src/vsock_loopback_bridge.rs`
(host half), `raxis/tproxy/src/loopback_forwarder.rs`
(in-guest half).

### INV-CRED-PROXY-VM-REACHABILITY-02 — Every supported isolation backend implements the host loopback bridge fail-closed

The host loopback bridge MUST be implemented for every isolation
backend that ships in raxis (Apple-VZ on macOS workstations,
Firecracker on Linux production). Backends without a bridge MUST
fail-closed at session-spawn time when a non-empty `LoopbackPlan`
is requested, with a clear typed error from
`Session::register_loopback_listener` identifying the missing
capability. The substrate's `register_loopback_listener`
implementation is the contractual boundary: any in-tree backend
that does not implement it inherits the `Session` trait's default
which returns `IsolationError::BackendInternal("...register_
loopback_listener is not supported by this substrate...")`, and
the `session-spawn` composer turns that error into a teardown of
the partially built session (VM, admission listener, credential
proxies all reaped before the error is surfaced to the caller).

**Mechanical enforcement.**
`raxis-session-spawn::spawn_session` builds the `LoopbackPlan`
from `cred_handles.started_summaries()` (one entry per credential
proxy), stamps `RAXIS_VSOCK_LOOPBACK_PLAN` into the VM env block,
then iterates the plan and calls
`Session::register_loopback_listener(vsock_port,
host_loopback_port)` for every entry — fail-closed: any error
from any backend triggers `session.shutdown()` plus
`cred_handles.shutdown()` before the spawn returns. The
two in-tree backends BOTH implement the trait method (no default
inheritance):

* **Apple-VZ** (`raxis/crates/isolation-apple-vz/src/
  vsock_loopback_bridge.rs`) registers a `VZVirtioSocketListener`
  on the VM's `VZVirtioSocketDevice` whose delegate dups the
  accepted vsock fd and splices it to host
  `127.0.0.1:<host_loopback_port>`.
* **Firecracker** (`raxis/crates/isolation-firecracker/src/
  vsock_loopback_bridge.rs` + `lib.rs::
  Session::register_loopback_listener`) pre-binds a Unix-domain-
  socket listener at `<uds_path>_<vsock_port>` — the path
  Firecracker's vsock multiplexer routes reverse-direction
  `(VMADDR_CID_HOST, vsock_port)` guest-side dials onto — and
  runs a tokio accept loop that drives
  `tokio::io::copy_bidirectional` between each accepted UDS
  stream and a fresh
  `TcpStream::connect("127.0.0.1:<host_loopback_port>")`.

The in-guest half is symmetric across both backends: PID 1's
`mount_pid1_essentials` brings `lo` up via `bring_up_loopback`
(`raxis/crates/planner-core/src/guest_init.rs`), and the
`planner-executor` driver activates the forwarder at boot
(`raxis/crates/planner-executor/src/main.rs::
activate_vsock_loopback_forwarder` → `raxis_tproxy::
loopback_forwarder::spawn_forwarder`). The forwarder reads the
stamped `RAXIS_VSOCK_LOOPBACK_PLAN`, binds the guest-side
`127.0.0.1:<port>` listeners declared by the plan, and splices
each accepted TCP connection to `(VMADDR_CID_HOST, vsock_port)`
against the per-VM vsock device.

**Justification.** `-01` says the substrate MUST provide
transparent reachability. `-02` is the no-quiet-omission corollary:
adding a new in-tree isolation backend without wiring the bridge
would silently break credential reachability the first time a
task with credentials runs against that backend. By making the
default `Session::register_loopback_listener` return
`BackendInternal` and by making the composer fail-closed on any
non-`Ok` result, the type system forces every backend author to
either implement the bridge or be visibly absent from production
roll-out. There is no path where a session boots with credentials
declared but no working loopback bridge — the kernel either has a
working bridge for the chosen backend or it tears the session
down before the agent's first tool invocation.

**Canonical home.** `v2/credential-proxy.md §12a.4`,
`raxis/crates/isolation/src/lib.rs` (default `Session::
register_loopback_listener` returning `BackendInternal`),
`raxis/crates/session-spawn/src/lib.rs` (composer fail-closed
loop + `RAXIS_VSOCK_LOOPBACK_PLAN` env stamp),
`raxis/crates/isolation-apple-vz/src/vsock_loopback_bridge.rs`
(AVF impl), `raxis/crates/isolation-firecracker/src/
vsock_loopback_bridge.rs` + `raxis/crates/isolation-firecracker/
src/lib.rs` (Firecracker impl),
`raxis/crates/planner-core/src/guest_init.rs::bring_up_loopback`
(in-guest `lo` bring-up at PID 1),
`raxis/crates/planner-executor/src/main.rs::
activate_vsock_loopback_forwarder` and
`raxis/tproxy/src/loopback_forwarder.rs` (in-guest forwarder
activation).

---

## §11.9 — Dashboard surface (INV-DASHBOARD-* / INV-AUDIT-DASHBOARD-* / INV-AUDIT-OPERATOR-* / INV-NOTIF-SCOPE-*)

The dashboard is a privileged read surface over kernel state
plus a narrow mutating surface (policy advance, mark-read).
These invariants close the gap between "operator can see this"
and "the audit chain records who saw what".

### INV-DASHBOARD-STREAM-ENVELOPE-01 — Session SSE wire envelope is uniform

**Statement.** Every data frame emitted on
`GET /api/sessions/:id/stream` carries the full
`{at_ms, kind, payload}` envelope as the SSE `data:` field
with the default `message` event type. Control frames
(`tail-complete`, `lagged`, `kernel-shutdown`, `ping`) retain
explicit `event:` names. The frontend `EventSource` consumer
attaches a single `onmessage` listener and decodes the
envelope JSON — it does NOT subscribe per-kind.

**Justification.** Per-kind `addEventListener` is a closed
extensibility surface: every new audit kind the kernel
introduces would otherwise need a paired frontend listener
or the frame would silently disappear. The single-envelope
contract makes the wire forward-compatible by construction —
new kinds light up on the dashboard the moment the kernel
emits them.

**Canonical home.** `v2/dashboard-hardening.md §4.2`.

### INV-DASHBOARD-STREAM-PRODUCER-01 — Audit emits feed the SSE pump

**Statement.** The kernel's audit-sink chain MUST include a
`raxis_dashboard_kernel::StreamingAuditSink` decorator that
mirrors every emitted `AuditEvent` whose `session_id` is
`Some(_)` into the matching `SessionStreamCapture`. The
decorator wraps the `Arc<dyn AuditSink>` the rest of the
kernel uses, so audit-chain order and session-stream order
are identical for session-scoped events.

**Justification.** Without this producer the session SSE
surface is structurally dead: subscribers attach to capture
channels nobody writes to. The decorator path keeps a single
chain order between the canonical audit log and the live
dashboard stream — the dashboard never reorders or invents
events relative to the kernel-authoritative ordering.

**Canonical home.** `v2/dashboard-hardening.md §4.1`.

### INV-AUDIT-DASHBOARD-01 — Chain status comes from the kernel walker

**Statement.** The dashboard surfaces audit-chain integrity
exclusively via the kernel's own walker
(`raxis_audit_tools::verify_chain_from`). The
`GET /api/audit/chain-status` endpoint MUST return a verdict
derived from a walker call; the frontend MUST NOT re-implement
verification. Explicit `?reverify=true` requests bypass the
kernel cache and force a fresh walk; otherwise the data layer
honours a coarse TTL to keep idle page mounts from pinning a
worker thread on chain re-walks.

**Justification.** Two verifiers means two truths and two
bugs to keep in sync. The chain's integrity contract is
already proven by `verify_chain_full` (`INV-04`); reusing
it as the single source of truth for the dashboard banner is
strictly safer than a frontend re-implementation and trivially
correct.

**Canonical home.** `v2/dashboard-hardening.md §2.1`.

### INV-AUDIT-OPERATOR-ACTION-01 — Every operator action emits an audit row

**Statement.** Every operator-initiated dashboard handler —
mutating OR privileged-read — emits exactly one structured
`Operator*` audit event before returning success. The event
carries:

  * `operator_fingerprint` — the JWT-derived `fp-<8 hex>` of the
    caller;
  * resource correlation fields (`notification_id`,
    `worktree_id`, `path`, `verdict`, `count`, etc.) appropriate
    to the surface;
  * `outcome` — one of `Accepted` / `RejectedValidation` /
    `RejectedPermission` / `InternalError`.

Failure paths (auth-rejected, schema-rejected, NotFound,
internal-error) MUST also emit, with the rejection class on
the `outcome` field. The audit emit MUST NOT precede
mechanical validation (auth, role, schema, path-safety) on
the success path. A failed audit emit on the success path
MUST surface as `InternalError` to the operator — the
invariant cannot be silently violated.

**Justification.** Passive operator interactions — opening a
worktree, viewing a diff, fetching a file, re-verifying the
chain — are part of the same accountability surface as
mutating actions. Without operator-action audit, the audit
chain records the agent's behaviour with high fidelity and
the operator's behaviour with none. The `Operator*` event
family closes this gap.

The `outcome` field is the surface dashboards use to
distinguish "operator was rejected at the gate" from "operator
clicked, action ran". A single-class enum keeps the
discriminant small enough for dashboards to render directly.

**Canonical home.** `v2/dashboard-hardening.md §2.2`.

### INV-NOTIF-SCOPE-01 — Notifications are a strict subset of audit events

**Statement.** The operator-notifications inbox is a strict
projection of the audit chain — every notification corresponds
to exactly one audit event, but not every audit event creates a
notification. The mapping
`AuditEventKind → Option<NotificationPriority>` is defined by
`notification_priority` in
`crates/dashboard-kernel/src/notification_filter.rs` and is
EXHAUSTIVE over `raxis_audit_tools::AuditEventKind`. Operator-
initiated dashboard actions (`OperatorNotificationMarkedRead`,
`OperatorNotificationsMarkedAllRead`,
`OperatorNotificationViewed`, `OperatorWorktreeAccessed`,
`OperatorDiffViewed`, `OperatorFileContentFetched`,
`OperatorAuditChainReverified`, `OperatorHealthQueried`) are
recorded in the audit chain but MUST NOT create notifications.
The notification priority bucket is one of `Critical`, `High`,
`Medium`, `Low`, or `None` (the audit-only sentinel); rows with
`None` are dropped at notification dispatch and never reach the
inbox SQLite table or `inbox.jsonl`.

**Two-layer filter, one source of truth.** The filtering happens
at two sites for defence-in-depth, but both sites consult the
same exhaustive match (typed twin
`notification_priority(&AuditEventKind)` and string twin
`notification_priority_for_kind_str(&str)`, locked against
divergence by the `typed_and_string_apis_agree_on_all_constructed_variants`
unit test):

  1. `kernel/src/notifications/sink.rs::NotifyingAuditSink::emit`
     — primary gate. Skips ALL inbox-side I/O (SQLite insert,
     `inbox.jsonl` append, SSE fan-out) when priority is `None`.
  2. `kernel/src/notifications/mod.rs::dispatch` — defence-in-
     depth. Re-applies the str-keyed filter so any caller that
     bypasses `NotifyingAuditSink` still cannot poison the inbox.

The audit-sink upstream is unaffected by either filter: every
event still reaches the chain. This is what `notifications-as-
strict-subset` means in practice.

**Append-only enum discipline.** Adding a new
`AuditEventKind` variant requires extending both
`notification_priority` arms — Rust's exhaustive match enforces
this at compile time. Removing or reordering existing variants
is forbidden by the workspace-wide append-only enum convention.

**Justification.** Operators who see their own clicks reflected
back as inbox rows ("you marked notification X as read", "you
viewed diff Y", "you reverified the chain") drown in noise and
miss the genuinely-important signals — escalations awaiting
approval, session-VM final failures, audit-chain integrity
violations. The audit chain is the forensic surface; the
notifications inbox is the attention surface. Conflating them
trades a useful inbox for a redundant audit log.

The exhaustive `match` keeps the taxonomy a one-place-edit
contract: a new kernel event cannot land in production without a
deliberate decision about whether it deserves operator
attention. The two-layer filter prevents accidental rebleed if
a future contributor adds a side-channel into the dispatch path
that bypasses `NotifyingAuditSink`.

**Reset path (dev-mode).** `cargo xtask dev-reset notifications`
truncates the `notifications` SQLite table and removes
`<data_dir>/notifications/inbox.jsonl` so the operator can clear
pre-filter rows from earlier dev runs. The command NEVER
touches `<data_dir>/audit/`; an integration test asserts the
audit-segment file is byte-identical before/after.

**Canonical home.** `v2/dashboard-hardening.md §2.6`.

### INV-DASHBOARD-VALIDATE-01 — Validation precedes every side effect and privileged read

**Statement.** Every dashboard endpoint validates
auth + role + request schema + path safety BEFORE any side
effect, privileged read, or audit emit on the success path.
Validation failures return a structured `ApiError` envelope
with a stable error code (`FAIL_DASHBOARD_*`). Internal-error
messages MUST NOT leak to the wire — the `log_only` payload
on `ApiError::Internal` is only routed to `tracing::error!`;
the wire surface is a generic `internal error`.

**Justification.** The dashboard is the operator's TCB
boundary into the kernel. The route layer's validators —
JWT verification, role gates, `validate_name` /
`validate_relative_path`, query-parser typing — are the
load-bearing safety net. Validation BEFORE side effect
prevents path-traversal, auth-bypass-on-error-paths, and
audit-noise-from-rejected-requests; structured error codes
make every rejection mechanically classifiable so dashboards
never have to grep stack traces for failure modes.

**Canonical home.** `v2/dashboard-hardening.md §2.3`.

### INV-DASHBOARD-FAILURE-VISIBILITY-01 — Every failure surfaced by the dashboard MUST display its reason

**Statement.** Every failure-bearing or rejection-bearing entity
surfaced through the dashboard MUST display its REASON to the
operator, not merely a status colour. The set of failure-bearing
surfaces is enumerated in `v2/dashboard-hardening.md §5` and
includes (non-exhaustive):

  * Lifecycle terminals — `SessionView.failure`, `TaskView.failure`,
    `InitiativeView.failure` (terminal `Failed` / `Aborted` /
    `Cancelled` / `Revoked` / `VmFailedFinal` /
    `BlockedRecoveryPending` states).
  * Subsystem health — `SubsystemHealthCard.last_error` for every
    card whose `status` is `degraded` or `failing`.
  * Review rejections — `ReviewerRejected` /
    `ReviewerDisagreement` audit events.
  * Operator-action rejections — every `Operator*` audit event with
    `outcome != Accepted`.
  * Egress / proxy — `TransparentProxyDenied`,
    `SessionEgressDenied`, `SessionEgressStallDetected`,
    `CredentialProxyConnectionFailed`,
    `CredentialProxyUpstreamFailed`.
  * Approval / escalation — `EscalationDenied`,
    `OperatorApprovalDenied`.
  * Worktree / git — `WorktreeProvisionFailed`, `PushFailed`,
    `MergeFastForwardFailed`.
  * Runtime — `GatewayCrashed`, `GatewayQuarantined`,
    `GatewaySignalFailed`, `VerifierProcessFailed`.

A "reason" comprises (where the kernel supplies it):

  * **`kind`** — the PascalCase error class
    (`SessionVmFailedFinal`, `WorktreeProvisionFailed`, …).
  * **`message`** — the free-form human-readable reason
    (`final_reason`, `reason`, `detail`). NOT truncated. NOT
    sanitised.
  * **Structured fields** — `exit_code`, `failure_class`,
    `target_host`, `chokepoint`, `block_count_in_window`, etc.
    Rendered as a definition list.
  * **Artifact links** — `kernel.stderr.log`, worktree path,
    deep link to the originating audit-chain row, etc.

The frontend renders this through the shared
`<FailureReasonPanel>` component on detail pages and the
companion `<FailurePill>` on list / ribbon surfaces. Failure
pills MUST NOT show only a status colour — they MUST surface the
reason via inline text, expansion, tooltip, or modal.

**Operator-action rejections.** When a dashboard mutation
(approve, mark-read, re-verify, policy-advance, …) fails, the
frontend MUST render the API `code` + `detail` inline at the
click site rather than as a generic toast that hides the reason.
The dashboard surface that initiated the action is responsible
for rendering its own action-failure block.

**Empty-reason rule.** A failure-bearing entity whose
backend-shipped reason is `null` is an operator-actionable bug
(the originating kernel reporter SHOULD always include a reason).
The dashboard MUST render the string
`"No reason supplied — kernel bug"` on the affected surface, with
a tooltip directing the operator to file a bug, rather than
silently rendering an empty state that hides the gap.

**Justification.** The operator-experience bar for a privileged
operational dashboard is: the operator never has to grep
`kernel.stderr.log` (nor open devtools) to find out why something
in the dashboard failed. A bare red badge with no reason
forces exactly that — operators interpret it as either an
unrecoverable kernel error (panicked → restart) or as
"something's wrong but I don't know what" (paged → on-call).
Both outcomes are worse than the structural truth: every kernel
failure event in the audit chain carries enough detail for the
operator to either fix the issue (approve a path expansion,
re-issue an egress allowlist entry, restart a fluky proxy) or
correctly route to engineering (`exit_code=139 in worker
foo_session_abc.log` is a real bug report; "Failed" is not).

The empty-reason rule keeps the invariant from being a one-way
ratchet: a future kernel reporter that ships a `*Failed` event
without populating a `reason` field is observable AT THE
DASHBOARD — the operator sees `"No reason supplied — kernel bug"`
and files it. Without the rule the gap is invisible — both the
operator and the engineering team see the same red badge they'd
see for any other failure.

**Canonical home.** `v2/dashboard-hardening.md §5`.

### INV-FAILURE-REASON-MANDATORY-01 — Every kernel-emitted terminal-failure transition MUST carry a non-empty reason

**Statement.** Every transition into a terminal-failure or
operator-blocked state MUST carry a non-empty, human-readable
`reason` string. Concretely:

  * `TaskState::Failed`, `TaskState::Aborted`,
    `TaskState::Cancelled`, `TaskState::BlockedRecoveryPending`
    — the task FSM's per-task `block_reason` column
    (`tasks.block_reason`) MUST be non-NULL and MUST NOT be
    empty / whitespace-only.
  * `InitiativeState::Failed`, `InitiativeState::Aborted`,
    `InitiativeState::Blocked` — the kernel-emitted audit
    event that drives the FSM transition
    (`OrchestratorRespawnCeilingExceeded`,
    `IntegrationMergeFailed`, `InitiativeAborted`, etc.) MUST
    carry a non-empty reason in either a dedicated field or
    the structured-payload field set the
    `<FailureReasonPanel>` projection reads.
  * `SessionRevoked` — the audit event MUST carry a non-empty
    `revoked_by` (operator fingerprint) AND, when the operator
    is resolvable in the policy bundle at emit time, a
    non-empty `revoked_by_display_name`. A
    `revoked_by_display_name = None` against an operator that
    IS in the bundle is a kernel bug per this invariant (the
    dashboard cannot render a 64-char hex fingerprint as
    operator-actionable text).

The kernel MUST NEVER emit a failure transition (or its
corresponding audit event) with `reason = None`, `""`, or a
whitespace-only string.

**Justification.** Operators need actionable failure context to
diagnose incidents. `"No reason supplied"` surfaces in the
dashboard as opaque body text (`<FailureReasonPanel>` empty-state
fallback per `INV-DASHBOARD-FAILURE-VISIBILITY-01`) and forces
operators into kernel-log spelunking — which defeats the entire
purpose of having a dashboard. A failure without a reason is a
*kernel bug*, not legitimate user-visible data: the kernel knows
why it transitioned the FSM (it just made the decision); failing
to propagate that "why" to the operator is a defect in the emit
site, not a permissible state.

This invariant is the kernel-side counterpart of
`INV-DASHBOARD-FAILURE-VISIBILITY-01` (which mandates the FE
*surface* the reason): the FE can only render real reasons if
the kernel supplies them. Holding both halves makes the
operator-experience contract symmetric: every Failed entity
ships a reason; every reason ships to the dashboard.

**Scenario (iter54 reproduction).** A dashboard surface displays
a task in `Failed` state with body text `"No reason supplied —
kernel bug"`. Tracing back: the kernel's
`session_spawn_orchestrator` worker-post-exit hook drove a
synthetic `Running → Failed` transition for an executor whose VM
exited prematurely (`exit_code=4`, planner-boot-error from VM
console). Pre-fix, the synthesized `block_reason` was a generic
`"VM exited without submitting a terminal intent"` string, but
the underlying VM-console `planner-boot-error` (which carries
the *actual* root cause: `dispatch loop exceeded max_turns: 30`)
was logged to `guests/<sid>/console.log` and dropped on the
floor of the failure-reason payload. The operator then sees a
red badge with vague text, opens devtools / `kernel.stderr.log`
to find the real reason, and files an avoidable on-call ticket
asking "why did this fail?". With this invariant + the Option-A
type-level enforcement (`FailureReason` newtype) + the Option-B
debug_assert at the audit-emit site, every failure-emitting
code path is a regression target — adding a `Failed { reason:
None }` literal to the codebase fails witness tests at PR-time.

A second class of pre-fix bug: `recovery::reconcile_tasks`'s
bulk sweep into `BlockedRecoveryPending` at kernel boot wrote
only `state` + `transitioned_at`, leaving `block_reason` at its
prior value (often NULL). Every restart-recovery sweep then
surfaced `"No reason supplied — kernel bug"` for the swept
tasks, even though the structural cause was straightforward
("kernel restarted while task was non-terminal — operator must
resume or abort"). The fix populates `block_reason` with a
structural reason that names operator action and references
this invariant.

**Sub-cases of the Mode-B kernel-side synthesis path
(`session_spawn_orchestrator::spawn_planner_dispatcher`).** Three
priority-ordered sub-cases produce non-generic `block_reason`
text on a worker (Executor / Reviewer) premature exit; the
synthesis MUST NOT fall back to the pre-iter56 generic umbrella
`"MaxTurnsExceeded / TokensExceeded / DispatchIdle / process
death"` placeholder under any condition (its appearance in
`tasks.block_reason` is a regression alarm for this invariant):

  1. **`drive_planner_stream` returned `Err(_)`** — the
     dispatch error string is inlined verbatim. Template:
     `"session_spawn_orchestrator: <role> VM exited without
     submitting a terminal intent. planner_dispatch error:
     <err>"`.
  2. **`drive_planner_stream` returned `Ok(())` AND the kernel
     observed at least one `IntentRequest` for the session**
     (clean-EOF-with-activity sub-case, iter56). The
     per-session activity tracker
     ([`kernel/src/session_activity.rs::SessionActivityTracker`])
     surfaces the last `(intent_kind, sequence_number,
     outcome, timestamp)` tuple; the synthesised
     `block_reason` quotes it. Template:
     `"session_spawn_orchestrator: <role> VM exited cleanly
     after last intent <Kind> #<seq> (<outcome>) at
     unix=<ts>; no terminal intent submitted before EOF
     (likely MaxTurnsExceeded / TokensExceeded /
     DispatchIdle)."` — example:
     `"session_spawn_orchestrator: executor VM exited cleanly
     after last intent StructuredOutput #7 (Accepted) at
     unix=1715694342; no terminal intent submitted before EOF
     (likely MaxTurnsExceeded / TokensExceeded /
     DispatchIdle)."`.
  3. **`drive_planner_stream` returned `Ok(())` AND the kernel
     observed NO `IntentRequest` for the session** (clean-EOF-
     without-activity sub-case, iter56). Distinct from (2) by
     design — "no IntentRequest observed before EOF" is
     operationally a different incident class than "planner
     ran for N turns and then hit MaxTurnsExceeded". Template:
     `"session_spawn_orchestrator: <role> VM exited cleanly
     without ever submitting an IntentRequest before EOF;
     likely planner-boot-error / model-init failure /
     dispatch loop returned Idle on the very first turn (no
     terminal intent observed)."`.

The two iter56 sub-cases MUST surface operator-actionable text
that lets the dashboard's `<FailureReasonPanel>` distinguish
boot-failure exits from runaway-loop exits without operator log
spelunking. Per the anti-pattern catalogue below, a placeholder
that doesn't carry operator-actionable detail is structurally
equivalent to `None` from the dashboard's perspective.

**Witness:**
- `crates/types/src/error.rs::FailureReason` (newtype impl)
- `crates/types/src/error.rs::EmptyReasonError` (constructor
  failure type)
- `kernel/src/initiatives/task_transitions.rs::transition_task_in_tx`
  (debug_assert! defense-in-depth)
- `kernel/src/recovery.rs::reconcile_tasks` (bulk-sweep
  block_reason population)
- `kernel/src/session_spawn_orchestrator.rs::spawn_planner_dispatcher`
  (Mode-B premature-exit synthesis — captures the
  `drive_planner_stream` dispatch error as the operator-facing
  reason; on a clean `Ok(())` return reads
  `ctx.session_activity` for the last observed IntentRequest
  and emits one of the two iter56 sub-case templates listed
  above; the pre-iter56 umbrella `"MaxTurnsExceeded /
  TokensExceeded / DispatchIdle / process death"` placeholder
  is no longer reachable on any tier)
- `kernel/src/session_activity.rs::{SessionActivityTracker,
  render_clean_exit_with_activity, render_clean_exit_without_activity}`
  (kernel-side per-session activity tracker + the two iter56
  sub-case rendering helpers; the `Mutex<HashMap>` is keyed by
  session_id, written by
  `kernel/src/ipc/server.rs::drive_planner_stream` on every
  IntentRequest round-trip, and consumed by the post-exit
  hook before the synthesis arm fires)
- `kernel/src/session_spawn_orchestrator.rs` ceiling cascade
  (`OrchestratorRespawnCeilingExceeded` arm — non-terminal
  tasks under the ceiling-exceeded initiative get
  `block_reason = "parent initiative failed: orchestrator
  no-progress respawn ceiling exceeded
  (INV-ORCH-RESPAWN-NO-PROGRESS-CEILING-01)"`)
- `kernel/src/handlers/intent.rs::handle_inner` IntegrationMerge
  fast-forward failure cascade (`MergeFastForwardFailed` arm —
  synthetic coordinator task + parent initiative both flip to
  `Failed` with `block_reason = "IntegrationMerge fast-forward
  failed (<category>): <reason>"`)
- `kernel/src/handlers/intent.rs::activate_subtask_substrate_spawn`
  (`ActivateSubTaskSpawnFailed` arm — task `block_reason`
  captures the substrate `SpawnError` text so the dashboard's
  per-task FailureReasonPanel attributes the substrate-level
  cause; FSM state untouched so the orchestrator's
  transient-retry loop still owns terminality)
- `kernel/tests/failure_reason_invariant_witness.rs`
  (cross-crate witness — newtype contract + audit-event variant
  shapes + SQL projection;
  `tasks_block_reason_clean_exit_with_activity_is_non_generic`
  and `tasks_block_reason_clean_exit_without_activity_is_non_generic`
  pin the iter56 sub-case templates and assert the pre-fix
  umbrella substring is absent from both branches)
- `kernel/src/initiatives/task_transitions.rs::tests::failed_transition_persists_non_empty_block_reason`
- `kernel/src/initiatives/task_transitions.rs::tests::failed_transition_with_none_reason_trips_debug_assert`
- `kernel/src/recovery.rs::tests::reconcile_populates_block_reason_for_swept_tasks`

**Enforcement.** Two layers, defense-in-depth:

1. **Type-level (Option A).** `FailureReason::new()` rejects
   empty / whitespace-only input at construction time. Any new
   FSM-transition function that takes `FailureReason` instead
   of `Option<String>` gets the invariant for free at compile
   time — the compiler refuses to admit a `None` or `""`
   value through the type.

2. **Audit-emit gate (Option B).** Existing `Option<&str>`
   callers route through `transition_task_in_tx`, which carries
   a `debug_assert!` that fires on every Failed /
   BlockedRecoveryPending transition with a missing or empty
   reason. Test + dev builds panic loudly with the invariant
   name in the message; release builds keep the historical
   behaviour (write NULL) so production tasks never get stuck
   inside an `assert_failed` panic — the FE-side
   `<FailureReasonPanel>` empty-state then surfaces the gap as
   a kernel-bug badge per
   `INV-DASHBOARD-FAILURE-VISIBILITY-01`.

The two layers are intentionally redundant: the newtype catches
forward-going regressions in new code paths; the debug_assert
catches regressions in legacy `Option<&str>` callers that
haven't been migrated yet. Both reference this invariant by
name in their failure messages so a tripped check immediately
points the engineer at the spec.

**Anti-pattern catalogue.** The following are forbidden by this
invariant — DO NOT apply any of these at an emit site that
cannot determine a real reason:

  * `reason: None` / `reason: Some("")` / `reason: Some("   ")`
    — the literal failure modes the invariant exists to
    prevent. Fix the call site to determine and supply a real
    reason.
  * `reason: Some("Unknown")` / `Some("Failed")` /
    `Some("error occurred")` / `Some("see logs")` — the same
    bug spelled differently. A placeholder that doesn't carry
    operator-actionable detail is structurally equivalent to
    `None` from the dashboard's perspective.
  * Wrapping a real failure in a generic outer reason that
    discards the inner detail
    (`Some("internal kernel error: see kernel.stderr.log")`)
    — the inner detail (exit code, role, planner-boot-error
    string from VM console) is what the operator needs.
    Propagate the inner reason verbatim or include it in the
    outer one.

**Canonical home.** `specs/invariants.md` (this file) — the
invariant's normative wording lives here; the FE-side
empty-reason rule (operator-experience contract) is in
`v2/dashboard-hardening.md §5.5`; the audit-event
non-nullability declaration is in `v2/audit-paired-writes.md`.

### INV-DASHBOARD-INITIATIVE-PLAN-VISIBLE-01 — Approved plans surface their original sealed TOML

**Statement.** For every initiative the dashboard lists, an
operator with the `read` role MUST be able to retrieve the
**original submitted** `plan.toml` byte-for-byte through
`GET /api/initiatives/:initiative_id/plan`, with no
re-parse / re-serialize step between
`signed_plan_artifacts.plan_bytes` (V1) /
`plan_bundle_artifacts.artifact_bytes` (V2.1) and the wire
body. The endpoint MUST:

  * Return 200 with the bytes embedded as a UTF-8 string in
    the response's `submitted_toml` field within 60 s of
    initiative approval.
  * Return 404 `FAIL_DASHBOARD_NOT_FOUND` when the
    `initiative_id` is unknown, never a 5xx.
  * Return 410 `FAIL_DASHBOARD_GONE` when the initiative
    exists but its plan blob has been archived / purged,
    never a 5xx and never a 404 (the distinction lets the
    frontend render "Plan archived" rather than "Initiative
    not found").
  * Carry `Cache-Control: private, max-age=60` for plans
    whose `approval_status == "approved"` (immutable post-
    approval per `plan-bundle-sealing.md §8.2`) and
    `Cache-Control: private, no-store` otherwise (Draft
    bytes are still mutable; client caching them across
    refreshes leaks stale plans).

The frontend's `useInitiativePlan` hook MUST hold a 60-second
TanStack Query `staleTime` so the React cache and the HTTP
cache stay aligned (a plan re-fetch never out-paces the
server-side cache).

**Justification.** The original sealed `plan.toml` is the
single source of operator intent for an initiative — it
cryptographically binds the planner's permitted scope, the
elastic budget, the path allowlist, and the credential-proxy
shape. Dashboards that re-serialize the bytes via TOML
encoders silently lose ordering, spacing, and comments
(operators routinely embed `# why this lane` annotations in
the TOML to disambiguate later operator review); a re-encoded
view actively hides operator intent and breaks deep audit
forensics. The 404-vs-410 split keeps "wrong link" (operator
typo / stale URL) and "plan gone" (purge / archival) as
distinct operator actions: a 410 is an operational event the
dashboard surfaces with a "Plan archived" banner; a 404 is a
client-side mistake. Folding both into 5xx — or both into 404 —
collapses two operationally distinct paths the operator MUST
be able to tell apart.

**Scenario.** An operator clicks an `Executing` initiative,
opens the **Plan** panel, and sees the same `plan.toml` bytes
they signed and submitted (preserved comments, blank lines,
trailing whitespace). They click **Copy**, paste into a fresh
file, run the kernel's `raxis plan verify` against it, and the
plan signature verifies — because the dashboard surfaced the
literal sealed bytes, not a TOML round-trip. A second operator
opens the same panel for an archived (`Aborted`) initiative
whose plan bundle was purged; the panel renders "Plan archived
or purged" inline (410), not a generic 5xx toast.

**Canonical home.** `v2/dashboard-hardening.md §plan-view`.

---

### INV-DASHBOARD-SESSION-DETAIL-FORENSIC-01 — Session detail surfaces every catalogued row, including terminated ones

**Statement.** `GET /api/sessions/:id` MUST return a `SessionView`
for any `session_id` that exists in the kernel's `sessions`
catalog, regardless of the row's current state (active, revoked,
or expired). Concretely:

  1. The dashboard-kernel resolves the row through
     `raxis_store::views::sessions::by_id`, NOT through
     `active_list`. `by_id` ignores the active-window filter
     (`revoked = 0 AND expires_at > now`) and the 200-row cap
     `active_list` applies.
  2. The wire `state` field carries the terminal classification
     — one of `Active` / `Revoked` / `Expired`. `Revoked`
     takes precedence over `Expired` (a row that is BOTH
     revoked AND past `expires_at` reports `Revoked` because
     the deliberate kernel/operator action is the salient
     terminal cause; the passive timeout is incidental).
  3. The `failure` field stays `None` for V2.5; V3 walks the
     audit chain for the matching `SessionRevoked` /
     `SessionVmFailedFinal` row and surfaces a structured
     reason. The wire shape is stable across versions.
  4. `404 FAIL_DASHBOARD_NOT_FOUND` is reserved for session ids
     the catalog has never seen — typos, stale tokens, sessions
     from a different kernel run.

**Justification.** The Sessions list page (`/sessions`) renders
every active session as a clickable row. An operator clicks one,
the page navigates to `/sessions/<id>`, and the detail handler
runs against the kernel store. With the V2.5 `active_list`-backed
implementation, any session whose `expires_at` had elapsed
between the list fetch and the click — or that had been revoked
in the same window — silently 404'd. Operators reported this as
"the session was right there a second ago, why is it gone now?"
and were forced to grep the audit chain by hand to see what
happened to a session they'd just been looking at.

The fix is structural: detail is a *forensic* read surface, not
a dispatch surface. Once a session existed in the catalog it must
remain navigable for the rest of the kernel run. The list page
is allowed to show only active rows (that's its semantic — "which
sessions are live"), but the detail surface must answer "what
happened to this id" for any `id` in the catalog.

**Canonical home.** `v2/dashboard-hardening.md §session-detail`
(referenced; the full body lives in this invariants block).

**Witness.**
  * `crates/store/src/views/sessions.rs::tests::by_id_finds_active_session`
  * `crates/store/src/views/sessions.rs::tests::by_id_finds_revoked_session`
  * `crates/store/src/views/sessions.rs::tests::by_id_finds_expired_session`
  * `crates/store/src/views/sessions.rs::tests::by_id_returns_none_for_unknown`
  * `crates/dashboard-kernel/src/lib.rs::tests::session_row_state_active_when_not_revoked_and_in_window`
  * `crates/dashboard-kernel/src/lib.rs::tests::session_row_state_revoked_takes_precedence_over_expiry`
  * `crates/dashboard-kernel/src/lib.rs::tests::session_row_state_expired_when_past_window_and_not_revoked`
  * Frontend: `dashboard-fe/src/pages/SessionDetail.tsx`'s
    `<SessionNotFound>` affordance is the operator-facing
    fallback for the legacy 404 path; once this invariant is
    satisfied that affordance only fires for genuinely-unknown
    session ids.

---

### INV-DASHBOARD-AUTOLOGIN-VALID-AT-BOOT-01 — Autologin URL minted at boot stays valid for the kernel's process lifetime

**Statement.** The autologin URL printed by the kernel test
harness at boot (and best-effort opened in the operator's
default browser by `spawn_url_opener`) MUST carry a JWT whose
`expires_at` is at least **24 hours** in the future at mint
time. Concretely:

  1. `DashboardConfig::default().jwt_ttl_secs` ≥ 86 400 s
     (24 h). The default is pinned at exactly 86 400 in
     `crates/dashboard/src/config.rs::DEFAULT_JWT_TTL_SECS`.
  2. The genesis emitter (`crates/genesis-tools/src/policy_toml.rs`)
     writes `jwt_ttl_secs = 86400` into the genesis-bootstrapped
     `policy.toml`, so a kernel booted from genesis without
     an operator-supplied policy override inherits the same
     budget.
  3. A JWT minted via `POST /api/auth/verify` MUST authorise
     every read endpoint (`GET /api/initiatives`, `…/tasks`,
     `…/sessions`, etc.) for the full TTL window.

**Justification.** The realistic-scenario live-e2e harness
(`extended_e2e_realistic_scenario`) routinely runs 60+
minutes — its default deadline is 3 600 s and operators
override it via `RAXIS_E2E_REALISTIC_DEADLINE_SECS` for slow-
VM iterations. The original 1-hour TTL the spec pinned
regularly expired mid-run: by the time a QA worker noticed
"the dashboard is up, here is the URL", the JWT was already
30+ minutes into its 60-minute budget. `parseAutologinHash`
mirrors the URL's stale `expires_at` into `localStorage`
without checking freshness (separation of concerns — the
`RequireAuth` route guard is the single seam that judges
freshness), `RequireAuth::isTokenLive` then sees the expired
profile and redirects to `/login`, and the operator lands on
the manual challenge-response form even though the kernel is
still serving traffic.

The 24-hour floor outlives every realistic kernel lifetime
in production today while preserving the short-secret
contract: `JwtSigner::new` mints a fresh 32-byte HMAC secret
from `OsRng` at every kernel boot and discards it on
shutdown, so every JWT — autologin or otherwise — is
invalidated the instant the kernel exits. Widening the TTL
inside one boot does NOT survive a restart.

**Canonical home.** `v2/dashboard-hardening.md §2.8`.

**Witness.** `crates/dashboard/tests/autologin_witness.rs`
(three test cases pin the constant, the loader path, and the
end-to-end mint → authorise flow). The genesis emitter
witness (`crates/genesis-tools/src/policy_toml.rs::dashboard_section_is_emitted_with_enabled_true_and_loopback_defaults`)
asserts the on-disk artifact carries `jwt_ttl_secs = 86400`.

---

### INV-DASHBOARD-TASK-STATE-COMPLETENESS-01 — Every kernel TaskState renders as a distinct dashboard badge

**Statement.** Every variant of the kernel `TaskState` FSM
(`raxis_types::fsm::TaskState`, eight values pinned by the
`tasks.state` SQL CHECK constraint in
`kernel-store.md §2.5.1 Table 5`: `Admitted`, `Running`,
`GatesPending`, `Completed`, `Failed`, `Aborted`, `Cancelled`,
`BlockedRecoveryPending`) MUST have an explicit, non-fallback
entry in the dashboard state-color map
(`dashboard-fe/src/lib/state-color.ts::MAP`). The map MUST NOT
collapse two variants onto the same tone — `Running` and
`Admitted` in particular MUST resolve to distinct
[`StateBadgeTone`] values so an operator can tell a queued task
apart from an executing one at a glance. The wire string the
kernel-side projection emits on `TaskView.state`
(`crates/dashboard-kernel/src/lib.rs::task_row_to_view`) MUST
be the canonical SQL form (the `TaskState::as_sql_str` output)
for every variant, so the FE renderer never has to normalise.

The contract is two-sided: the kernel-side witness pins the
enum length (`TaskState::ALL.len() == 8`) AND round-trips every
variant through `task_row_to_view` to assert the projection
preserves the canonical SQL string; the FE-side witness imports
the canonical 8-tuple, walks it, and asserts every entry resolves
to an explicit `MAP[state]` hit (not the case-normalised fallback,
not the "unknown → muted" trap door). A new `TaskState` variant
landed in the Rust enum without a matching FE entry trips both
witnesses in the same commit.

**Justification.** iter53 saw the IntegrationMerge coordinator
task sit in `Running` for the full lifetime of an initiative
while the operator dashboard showed only `Admitted` and
`Completed` rows — the FE renderer's "unknown → muted" fallback
swallowed any kernel state that lacked an explicit entry, and a
visual collision between `Running` (`info`) and `Admitted`
(`muted`) would have made the intermediate state effectively
invisible even if the renderer had picked it up. Operators
inferred "nothing is running" from the dashboard while live-e2e
runs were silently mid-flight.

The completeness invariant forecloses the silent-degradation
shape: any future addition to the kernel enum either lands with
a paired FE update (both witnesses green) or fails admission
(both witnesses red) — there is no "renders as muted, pretend
it's Admitted" middle path. This is the same shape as
`INV-DASHBOARD-FAILURE-VISIBILITY-01` ("no failure goes
unsurfaced") but lifted one tier up: no FSM state goes
unsurfaced either.

**Canonical home.** `v2/dashboard-hardening.md §task-state-rendering`.

**Witness.**
  * Frontend: `dashboard-fe/src/test/state-color.test.ts`
    suite `INV-DASHBOARD-TASK-STATE-COMPLETENESS-01` walks
    `KERNEL_TASK_STATES` and asserts `hasExplicitStateEntry`
    holds for every variant; a separate case pins
    `stateTone("Running") !== stateTone("Admitted")` to catch
    a tone-collision regression. Companion checks cover
    `KERNEL_INITIATIVE_STATES` and `KERNEL_SESSION_STATES`.
  * Kernel: `crates/dashboard-kernel/src/lib.rs::tests::inv_dashboard_task_state_completeness_projection_round_trips_every_variant`
    builds a `TaskRow` for every `TaskState::ALL` variant,
    pushes it through the production `task_row_to_view`
    projection, and asserts `TaskView.state ==
    TaskState::as_sql_str()` for each. The same test pins
    `TaskState::ALL.len() == 8` as the cross-language
    drift trip-wire.

---

### INV-DASHBOARD-INTEGRATION-MERGE-VISIBLE-OR-EXCLUDED-01 — IntegrationMerge coordinator task is first-class in the dashboard

**Statement.** The synthetic IntegrationMerge coordinator-task
row (inserted by
`kernel/src/initiatives/lifecycle.rs::auto_spawn_orchestrator_session_in_tx`
with `task_id == initiative_id` in lockstep with the
Orchestrator session, per `v2-deep-spec.md §Step 11
IntegrationMerge`) MUST NOT render as an opaque UUID-titled row
in the dashboard's per-initiative task list. The chosen surface
is **option (A) — first-class visible task**:

  1. The kernel-side projection
     (`crates/dashboard-kernel/src/lib.rs::task_row_to_view`)
     detects the coordinator row by the
     `task_id == initiative_id` predicate and stamps a fixed
     human title (`Integration merge`) on the wire `TaskView`.
     The constant lives at
     `crates/dashboard-kernel/src/lib.rs::INTEGRATION_MERGE_TITLE`.
  2. The FE substitutes a stable display id
     (`«integration-merge»`, pinned at
     `dashboard-fe/src/lib/state-color.ts::INTEGRATION_MERGE_DISPLAY_ID`)
     wherever the task-id chip would otherwise render the same
     UUID as the parent initiative. Routing and copy-to-clipboard
     keep using the real `task_id` so `/tasks/<initiative_id>`
     deep-links remain valid and audit-chain joins against the
     wire id are stable.
  3. The coordinator task counts toward `task_count` /
     `completed_tasks` in the initiative summary (current
     behaviour preserved); the Overview progress widget
     therefore reads "N done / M total = M%" without any
     option-(B) bookkeeping carve-out.
  4. The coordinator's FSM state is rendered through the same
     `StateBadge` as every other task. Per
     `INV-DASHBOARD-TASK-STATE-COMPLETENESS-01`, all eight
     `TaskState` variants surface with distinct visual styling,
     so the merge-task's `Admitted → Running → Completed`
     trajectory is operator-legible.

The **current behaviour is forbidden**: counted in the
denominator AND either hidden from the list (option B without
the matching surface) OR rendered as an opaque UUID row that
looks like a duplicate of the parent initiative.

**Option (B)** ("exclude from `task_count`/`completed_tasks`,
render a separate `Merge: pending / running / done / failed`
pill beside the progress bar") is documented as a future
candidate but **NOT** wired today. Selecting it requires
touching every consumer of `task_count` / `completed_tasks` to
ensure they exclude the synthetic row; option (A) preserves the
existing arithmetic for minimum impedance, per the iter53
fix-loop decision.

**Justification.** Without the title carve-out, the
coordinator's task_id (which equals the initiative UUID by
construction) reads in the dashboard as a duplicate of the
initiative row. Operators see "1 done / 50%" with no second
declared task and conclude either "the dashboard is broken" or
"the merge will never run"; both readings are wrong — the
merge task IS in flight, but the dashboard offered no surface
to make that fact visible. iter53's live SQLite confirmed the
row was in `Running` state at the very moment operators reported
"nothing is happening on the dashboard".

The option-(A) surface is the minimum operator-visible
intervention that surfaces the merge phase: a human title, a
stable display id distinct from the initiative chip, and the
same `StateBadge` taxonomy every other task uses. It also
preserves the option-(B) escape hatch: the kernel-side title
constant + the FE display-id helper are both render-time
substitutions, so a future migration to option (B) only needs
to change the consumers of `task_count` / `completed_tasks` and
introduce the dedicated `<MergePhasePill>` component without
re-litigating the title contract.

**Canonical home.** `v2/v2-deep-spec.md §IntegrationMerge / Operator
surface` and `v2/dashboard-hardening.md §integration-merge-visibility`.

**Witness.**
  * Kernel: `crates/dashboard-kernel/src/lib.rs::tests::inv_integration_merge_visible_coordinator_renames_to_human_title`
    asserts `task_display_title(initiative_id, initiative_id)
    == "Integration merge"` and pins `INTEGRATION_MERGE_TITLE`
    to its spec-pinned literal. The companion
    `inv_integration_merge_visible_subtask_keeps_authored_id`
    asserts ordinary sub-task rows echo their operator-authored
    `task_id` (so the carve-out cannot accidentally rename a
    real sub-task).
  * Frontend: `dashboard-fe/src/test/state-color.test.ts` suite
    `INV-DASHBOARD-INTEGRATION-MERGE-VISIBLE-OR-EXCLUDED-01`
    pins `INTEGRATION_MERGE_DISPLAY_ID === "«integration-merge»"`,
    asserts `isIntegrationMergeTask` fires iff
    `task_id == initiative_id`, and verifies `taskDisplayId`
    substitutes the stable display id for the coordinator row
    while echoing the operator-authored id for sub-tasks.
  * Renderer wiring: the helper is consumed by
    `dashboard-fe/src/pages/InitiativeDetail.tsx` (task list +
    focused-task aside), `dashboard-fe/src/pages/InitiativeDag.tsx`
    (focused-node panel), and
    `dashboard-fe/src/pages/TaskDetail.tsx` (breadcrumb chip).

### INV-DASHBOARD-WIRE-UNITS-CONSISTENT-01 — Dashboard wire timestamps name and emit a single unit

**Statement.** Every timestamp / duration field on the dashboard
wire schema (`raxis/crates/dashboard/src/data.rs`) MUST either
(a) carry an explicit unit suffix in its name (`_ms`, `_s`,
`_us`, `_ns`, or the spelled-out `_unix_secs` /
`_at_unix`) AND be emitted in that unit by every kernel
producer, OR (b) carry a doc-comment that explicitly states the
unit AND be emitted in that unit by every kernel producer. The
FE consumer MUST read the field at the documented unit; no
silent unit conversions are permitted at consumption time, and
no producer may emit a value in a unit other than the field's
documented one.

**Justification.** A unit mismatch between the kernel producer
and the documented wire contract silently produces nonsense at
the rendering layer with no compile-time, no runtime, and no
test-time check. The dashboard Health page surfaced this
concretely in iter54: the kernel emitted milliseconds into
`SubsystemHealthCard.last_observed_at`, a field documented at
`crates/dashboard/src/data.rs:802-804` as **"Unix-seconds when
the kernel last reported on this subsystem"**. The FE's
`fmtRelative` (`dashboard-fe/src/lib/format.ts`) correctly
read the field as seconds per the documented contract, computed
the delta against `Math.floor(Date.now()/1000)`, and rendered
**"in 56,347 years"** on every one of the nine subsystem cards.

The math is unambiguous: `1.78×10¹² ms − 1.78×10⁹ s ≈ 1.78×10¹²
seconds delta ≈ 56,402 years`. The render path had no defence
because (a) JavaScript's `number` accepts both magnitudes
without complaint, (b) Rust's `u64` accepts both magnitudes
without complaint, and (c) neither side had a typed unit
wrapper to force the producer and consumer into structural
agreement. The invariant exists to make this class of bug
visible at code-review time, since at runtime it surfaces only
as a nonsense duration string to operators who may dismiss it
as a one-off display glitch rather than a producer bug.

**Scenario.** Iter54 live e2e: an operator opens the Health
page during a healthy run. Every subsystem card reads
`Booted at (unix-s): 1778750356 / kernel_main_loop ... in
56,347 years`. The 9-card consistency tells the operator the
bug is structural rather than per-subsystem; the explicit
"Unix-seconds when ..." doc comment in `data.rs` tells the
reviewer the producer is the violator (the FE was reading at
the documented unit). Fixed in iter54 by switching the
`subsystem_health` producer to `unix_now_s()` for the
seconds-typed field while keeping `unix_now_ms()` for the
correctly `_ms`-suffixed `generated_at_ms` and `verified_at_ms`
fields.

**Canonical home.**
`v2/dashboard-hardening.md §5.13 Wire-time units` (this file
mirrors); see also `v2_extended_gaps.md §4` for the broader
dashboard backend contract.

**Witness.**
  * Wire schema: `crates/dashboard/src/data.rs` — every
    timestamp field carries either a unit-suffixed name
    (`_ms`, `_unix_secs`, `_at_unix`) OR a doc-comment line
    that begins `Unix-seconds` / `Unix-milliseconds`. New
    fields without one of these markers MUST be rejected at
    code review.
  * Kernel producer: `crates/dashboard-kernel/src/lib.rs` —
    `fn unix_now_s() -> u64` is the canonical helper for
    seconds-typed fields; `fn unix_now_ms() -> u64` is the
    canonical helper for `_ms`-suffixed fields. The
    `subsystem_health` builder demonstrates the pattern: it
    holds both `now_s` and `now_ms` locals, and each per-arm
    tuple feeds the variable matching the destination field's
    unit.
  * FE consumer: `dashboard-fe/src/lib/format.ts::fmtRelative`
    and `fmtAbsolute` both expect unix-seconds and document so
    in their function signatures (`unixSeconds: number`).
    Consumer pages (`Health.tsx`, `Sessions.tsx`,
    `Initiatives.tsx`, …) MUST pass the wire field at the
    documented unit; the only sanctioned conversion is at the
    field-name boundary (e.g.
    `dashboard-fe/src/components/ChainStatusBanner.tsx`
    divides `verified_at_ms` by 1000 before passing to
    `fmtAbsolute`, with the field-name suffix making the
    conversion locally obvious).

**Enforcement.** Documentation contract, audited at every
dashboard wire schema change. A future stronger enforcement —
introducing newtype wrappers (`UnixSeconds(u64)`,
`UnixMillis(u64)`) in `crates/dashboard/src/data.rs` so the
compiler refuses to mix the two — is filed for the
post-validation cleanup sweep but is not wired today
(touching every wire field would balloon this fix beyond the
one-line correction the live bug needed).

---

## §11.10 — Live-e2e test harness (INV-LIVE-E2E-*)

The live-e2e harness drives real docker-compose-backed services
(postgres / mongo / redis / smtp / mysql / mssql) through real
database client subprocesses (`psql` / `mongosh` / `redis-cli`
/ `mysql` / `sqlcmd`). Every one of those subprocesses talks
TCP to a container that may not be up; the invariant below
forces every spawn to be bounded so a missing container fails
the test fast instead of hanging the test runner forever.

**Canonical home.** `kernel/tests/extended_e2e_support/harness_timeout.rs`,
`kernel/tests/extended_e2e_support/health_probe.rs`,
`kernel/tests/extended_e2e_support/docker_stack.rs`,
`live-e2e/README.md`.

### INV-LIVE-E2E-HARNESS-NO-INDEFINITE-WAIT-01 — Every external-process spawn is bounded

**Statement.** Every external-process spawn in the live-e2e
harness (`psql` / `mongosh` / `redis-cli` / `swaks` / `mysql` /
`sqlcmd` / `docker` / `pg_isready` / `mysqladmin` / etc.) MUST be
wrapped in a bounded timeout: 30 s default for seeding
([`SEED_TIMEOUT`]), 5 s default for health probes
([`HEALTH_PROBE_TIMEOUT`]), 30 s for `docker compose ps`
([`DOCKER_PROBE_TIMEOUT`]), 240 s for `docker compose up -d --wait`
([`DOCKER_BRINGUP_TIMEOUT`]). The harness MUST NOT contain any
unbounded `Child::wait()`, `Child::wait_with_output()`, or pipe
`read_to_end()` call in any `seed_*` / `verify_*` / `probe_*` /
`ensure_*` path. On timeout the wrapper SIGKILLs and reaps the
child before returning.

The realistic-scenario harness MUST verify the
`raxis-live-e2e-test` docker-compose project is up + healthy
BEFORE the first `seed_*` call. Auto-bring-up is the operator-
ergonomic default; opt out via
`RAXIS_LIVE_E2E_NO_AUTO_DOCKER=1`, in which case the harness
fail-fast surfaces the literal token
`RAXIS_LIVE_E2E_DOCKER_STACK_DOWN` so a CI log scraper can pin
the failure mode.

The lifecycle-completion poll (`poll_for_dual_lifecycle_completion`
in `extended_e2e_support::kernel_driver`) MUST also fail-fast
when the kernel emits a *terminal* `orchestrator_spawn_failed`
event for either watched initiative. The kernel logs this JSON
shape on stderr after exhausting its
`session_vm_transient_retry` budget for a session VM, and the
event's own `hint` field documents that "PlanApproved was
committed; recovery::reconcile or a follow-up operator command
is needed to drive the orchestrator boot once the substrate is
available" — neither of which the harness performs.
Polling further is therefore a guaranteed indefinite wait
until [`realistic_lifecycle_deadline`] (60 min default,
iter31). The
scanner is a pure substring-prefilter over `kernel.stderr.log`
(read at the existing 500 ms poll cadence) that surfaces the
kernel's own `error` + `hint` in the panic body so the operator
sees the substrate failure in seconds — typically the
"`apple-vz-14.x: block device rootfs: Invalid disk image`" path
on a host whose `EXPECTED_KERNEL_SIGNING_KEY_BYTES` is the
all-zero placeholder (see `release-and-distribution.md §8.2`).
The scanner intentionally filters out the mid-flight
`session_vm_transient_retry` lines so a substrate that
self-recovers after a transient stall is not falsely failed.

**Fast-fail on `OrchestratorRespawnCeilingExceeded`.** The
poll loop scans the audit chain on every iteration and panics
immediately when an `OrchestratorRespawnCeilingExceeded` audit
event lands for either watched initiative. The kernel commits
`initiatives.state = 'Failed'` in the same paired write that
emits the chain-side audit row
(`session_spawn_orchestrator.rs::orchestrator_post_exit_respawn_trigger`,
paired per `audit-paired-writes.md §4`). No further audit
events fire on that initiative's lane, so polling for
`IntegrationMergeCompleted` is a guaranteed indefinite wait —
the same indefinite-wait class the spawn-failure scanner above
covers. Iter48 reproduced the gap: the orchestrator's planner
LLM blind-asked `retry_subtask` against a task whose
`capabilities.tasks[*].retry_admissible=false reason="prior
state PendingActivation; …"`, the kernel correctly rejected
each retry with `RetrySubTaskRejectedNotRetryable` per
`INV-RETRY-FROM-COMPLETED-REVIEW-REJECTED-01`, and after three
no-progress respawn cycles the per-initiative ceiling
(`INV-ORCH-RESPAWN-NO-PROGRESS-CEILING-01`) fired and marked
the initiative `Failed`. Without the fast-fail the harness
deadlined out after the full 65 min wait; with the fast-fail
the operator sees the upstream blind-ask hypothesis (NNSP rule
3a + the matching invariant cite) in seconds.

[`SEED_TIMEOUT`]: ../kernel/tests/extended_e2e_support/harness_timeout.rs
[`HEALTH_PROBE_TIMEOUT`]: ../kernel/tests/extended_e2e_support/harness_timeout.rs
[`DOCKER_PROBE_TIMEOUT`]: ../kernel/tests/extended_e2e_support/harness_timeout.rs
[`DOCKER_BRINGUP_TIMEOUT`]: ../kernel/tests/extended_e2e_support/harness_timeout.rs
[`realistic_lifecycle_deadline`]: ../kernel/tests/extended_e2e_support/kernel_driver.rs

**Justification.** A single unbounded `Child::wait_with_output()`
is enough to hang the entire test runner indefinitely when its
target service is not reachable. Witnessed in iter 17 of the
`realistic_session_lifecycle` fix-loop: `seed_postgres` blocked
on `psql`'s pipe `read2 → poll` against a postgres container
that wasn't up. The single-thread, 0% CPU, no-progress, no-VM
failure mode wasted ~6 minutes per iteration before the operator
manually killed the runner — every silent hang is a forensic
black hole the harness's three-tier diagnostic block cannot
unwind. A bounded wait turns it into a typed `SeedTimedOut`
(or `PreSeedHealthCheckFailed`) carrying the seed name, the
wrapped subprocess label, and the target service URL, so an
operator finds the failure mode in seconds rather than blaming
the kernel.

**Scenario.** Operator runs `cargo test -p raxis-kernel --test
extended_e2e_realistic_scenario` without first bringing up the
docker-compose stack. With this invariant in force the harness
auto-brings-up the stack via `docker compose ... up -d --wait`
within 240 s and proceeds; in the opt-out mode it fail-fast
surfaces `RAXIS_LIVE_E2E_DOCKER_STACK_DOWN: docker-compose
project raxis-live-e2e-test is not up + healthy ...` within the
30 s probe timeout. Without it the runner blocks indefinitely on
the first `seed_postgres` call.

**Witness.**
[`extended_e2e_support::harness_timeout::tests::sleep_9999_killed_by_timeout_wrapper`](../kernel/tests/extended_e2e_support/harness_timeout.rs):
spawns `Command::new("sleep").arg("9999")` through the wrapper
with a 2 s timeout; asserts the typed
`BoundedWaitError::Timeout` variant is returned within
`timeout + 5 s`. Pairs with
[`extended_e2e_support::docker_stack::tests::opt_out_against_missing_project_surfaces_stack_down_token`](../kernel/tests/extended_e2e_support/docker_stack.rs)
which exercises the auto-bring-up opt-out path against a
synthetic non-existent project name and asserts the
`RAXIS_LIVE_E2E_DOCKER_STACK_DOWN` token surfaces in the panic
message. The audit-poll fast-fail extension is witnessed by
[`extended_e2e_support::kernel_driver::tests::scan_stderr_matches_terminal_spawn_failed_for_watched_initiative`](../kernel/tests/extended_e2e_support/kernel_driver.rs)
(positive: terminal `orchestrator_spawn_failed` surfaces the
kernel's own `error` + `hint`),
[`…::scan_stderr_ignores_transient_retry_lines`](../kernel/tests/extended_e2e_support/kernel_driver.rs)
(negative: mid-flight `session_vm_transient_retry` lines do
NOT trip the watchdog), and
[`…::scan_stderr_ignores_spawn_failed_for_unwatched_initiative`](../kernel/tests/extended_e2e_support/kernel_driver.rs)
(filter: spawn-failed for an initiative the current poll is
not watching is ignored, so leftovers from a prior boot of the
same data_dir don't false-fail a fresh test).

**Canonical home.**
`kernel/tests/extended_e2e_support/harness_timeout.rs` (wrapper
+ regression test);
`kernel/tests/extended_e2e_support/health_probe.rs` (probe
helpers);
`kernel/tests/extended_e2e_support/docker_stack.rs` (auto-bring-
up + opt-out gate);
`kernel/tests/extended_e2e_support/kernel_driver.rs`
(`poll_for_dual_lifecycle_completion` + the
`orchestrator_spawn_failed` scanner that satisfies the audit-
poll fast-fail half of this invariant);
`live-e2e/README.md` (operator-facing recipe + env-var
documentation).

---

### INV-LIVE-E2E-EXAMPLES-NO-REAL-SECRETS-01 — Example-bundle refresh hook refuses to land real Anthropic credentials

**Statement.** The realistic-scenario live-e2e harness's
example-bundle auto-refresh hook
([`extended_e2e_support::kernel_driver::maybe_refresh_examples`])
MUST refuse to land a refreshed
`raxis/live-e2e/examples/credentials/` directory if any file
under it contains a byte sequence matching the real-Anthropic-key
regex `sk-ant-api[0-9]{2}-[A-Za-z0-9_-]{20,}`. The witness
function
([`extended_e2e_support::kernel_driver::assert_no_real_anthropic_key`])
runs as the LAST step of every refresh — AFTER each file is
rewritten but BEFORE the harness returns control to the test
driver, so a refresh that would carry a real key fails the whole
iter BEFORE the kernel daemon spawns and no half-baked diff can
be `git add`-ed.

The witness's structural guarantee composes with two adjacent
disciplines:

1. **Hardcoded placeholder rewrite.** The refresh hook rewrites
   `examples/credentials/anthropic.env.placeholder` from a
   constant `ANTHROPIC_PLACEHOLDER_BODY` in
   `kernel_driver.rs`, NOT from a copy of whatever real
   `ANTHROPIC-API-DEV-KEY` value the harness loaded into
   `<data_dir>/providers/anthropic-realism-e2e.toml` at
   bootstrap. The real bytes never reach the refresh code path
   — the only way they could leak is via a non-`maybe_refresh_examples`
   call site that mistakenly writes them under
   `examples/credentials/`, and the witness catches that case.
2. **Commit-time guard.**
   `raxis/scripts/check-no-real-anthropic-key.sh` runs the same
   regex over `raxis/live-e2e/examples/` at the operator's
   pre-commit hook (and in CI). A real key that somehow
   bypassed the witness — e.g. via an operator hand-editing
   the placeholder file — still rejects at `git commit` time.

The example bundle's other credential files (`test-pg-dev.env`,
`test-mongo-dev.env`, `test-redis-dev.env`,
`test-smtp-dev.env`) are explicitly EXEMPT from this invariant
because they only authenticate against the local docker-compose
stack (loopback-only bindings) and the matching server-side
credentials already commit in
`raxis/live-e2e/docker-compose.extended.e2e.yml`. They have no
production value and their commit is documented in
`raxis/live-e2e/examples/README.md`.

**Justification.** The point of `raxis/live-e2e/examples/` is
to let an operator answer "what configuration produced the
latest live-e2e iter?" without re-running the test or
reconstructing it from Rust constants. The bundle is therefore a
checked-in mirror of the harness's per-run tmpdir; the
auto-refresh hook re-mirrors it on every green iter (gated on
`RAXIS_E2E_REFRESH_EXAMPLES=1`). Without this invariant the
refresh path is a credential-exfiltration footgun: a future
maintainer adding "convenience" code that copies the real
Anthropic credential from `<data_dir>/providers/` into
`examples/credentials/` would silently leak the operator's
production key into the repo on the next `git add`. The witness
makes that mistake mechanically impossible to commit — even if
the maintainer ALSO disables `ANTHROPIC_PLACEHOLDER_BODY`, the
real-key regex still fires at refresh time and panics the
harness before the kernel spawns, so the diff is never produced
in the first place.

**Scenario.** A future maintainer changes the hardcoded
`ANTHROPIC_PLACEHOLDER_BODY` constant to read
`std::fs::read_to_string(&data_dir.join("providers/anthropic-realism-e2e.toml"))`
"for convenience". On the next iter where someone sets
`RAXIS_E2E_REFRESH_EXAMPLES=1`, the refresh would normally write
the real `api_key` into
`examples/credentials/anthropic.env.placeholder`. With this
invariant in force, `assert_no_real_anthropic_key` matches the
regex against the rewritten file, panics with a copy-pastable
remediation hint (including "ROTATE THE KEY IN YOUR ANTHROPIC
CONSOLE IMMEDIATELY"), and the iter aborts before the kernel
daemon spawns. The worktree is left clean (no `examples/`
diff), and the maintainer's mistake is caught in seconds rather
than weeks.

**Witness.**
[`extended_e2e_support::kernel_driver::tests::assert_no_real_anthropic_key_rejects_real_looking_key`](../kernel/tests/extended_e2e_support/kernel_driver.rs):
synthesises a fixture credential file with a real-shape key
(`sk-ant-api03-` + 32 chars of `[A-Za-z0-9_-]`, none of which
came from any real Anthropic account) and asserts the witness
panics with the `INV-LIVE-E2E-EXAMPLES-NO-REAL-SECRETS-01
VIOLATED` token. Negative-direction pinned by
[`…::find_real_anthropic_key_negative_cases`](../kernel/tests/extended_e2e_support/kernel_driver.rs)
(single-digit version, body-too-short, unrelated `sk-ant-`
prefixes, and the literal `PLACEHOLDER_REPLACE_ME_WITH_REAL_KEY`
string all MUST NOT trip the witness). The end-to-end refresh
shape is pinned by
[`…::refresh_examples_writes_plan_and_credentials_under_env_gate`](../kernel/tests/extended_e2e_support/kernel_driver.rs)
which drives the full hook against a tmpdir fixture and asserts
every output file matches the expected source byte-for-byte; the
no-op default-off path is pinned by
[`…::maybe_refresh_examples_default_off_is_no_op`](../kernel/tests/extended_e2e_support/kernel_driver.rs);
the layout-drift fail-fast is pinned by
[`…::maybe_refresh_examples_panics_when_examples_dir_missing`](../kernel/tests/extended_e2e_support/kernel_driver.rs).

**Canonical home.**
`kernel/tests/extended_e2e_support/kernel_driver.rs`
(`maybe_refresh_examples` + `assert_no_real_anthropic_key` +
`find_real_anthropic_key` + the regression test block);
`raxis/scripts/check-no-real-anthropic-key.sh` (commit-time
guard with the same regex);
`raxis/live-e2e/examples/README.md` (operator-facing refresh
contract + the rules for which credentials are OK to commit);
`raxis/specs/v2/secrets-model.md §2.5` (operator-supplied-
placeholder discipline that this invariant operationalises for
the harness's own self-managed examples bundle).

---

### INV-LIVE-E2E-DASHBOARD-FE-BUNDLE-PRESENT-01 — Live-e2e harness MUST produce a working dashboard React bundle (or hard-fail), never silently degrade

**Statement.** When the live-e2e harness mounts the operator
dashboard during a `realistic_session_lifecycle` (or sibling
`full_e2e_session_lifecycle`) run, the React production bundle
([`dashboard-fe/dist/index.html`]) MUST be present on disk
before the kernel's `[dashboard]` block consumes it as
`static_dir`, UNLESS the operator has explicitly opted out by
setting `RAXIS_E2E_SKIP_DASHBOARD_BUILD=1`. The harness's
single source of truth for this contract is
[`tests::common::dashboard::locate_dashboard_dist`]; that
function MUST:

1. Return `Some(dist)` immediately when
   `dashboard-fe/dist/index.html` is already on disk (the fast
   path; no subprocess work).
2. Return `None` with a single explicit `[dashboard-bundle]
   <opt-out>` log line when `RAXIS_E2E_SKIP_DASHBOARD_BUILD=1`
   is set (the operator-explicit JSON-only path).
3. Run `npm ci` (bounded by `RAXIS_E2E_NPM_INSTALL_TIMEOUT_SECS`,
   default 600 s) when `dashboard-fe/node_modules/.bin/vite`
   is absent. This is the iter52 root-cause shape: a fresh
   `git worktree add` carries `package.json` but not
   `node_modules/`, so the previous behaviour of jumping
   straight to `npm run build` produced `tsc: command not
   found` — which the previous implementation swallowed.
4. Run `npm run build` (bounded by
   `RAXIS_E2E_NPM_BUILD_TIMEOUT_SECS`, default 300 s).
5. **Hard-panic** with a message containing the literal token
   `INV-LIVE-E2E-DASHBOARD-FE-BUNDLE-PRESENT-01 VIOLATED` on
   ANY of: missing `package.json`, `npm ci` failure (spawn /
   non-zero exit / timeout), `npm run build` failure, or
   post-build sanity check (the `dist/index.html` artefact
   missing after `npm run build` returned success).

The classifier
[`tests::common::dashboard::classify_bundle_state`] is the
pure-data half of this contract — the policy decision pivots
on `(dist_index_present, skip_env_set, package_json_present,
node_modules_vite_present)` and the classifier is exhaustively
witness-tested independent of the host's `npm` availability.
The actual subprocess steps in `locate_dashboard_dist` compose
the classifier's decision with `run_npm_bounded` invocations.

**Justification.** Operator visibility is a kernel-level
guarantee — every other dashboard invariant in §11.9 is
predicated on the dashboard rendering the React UI to a
browser, not just serving the JSON API. Without the bundle the
React app cannot mount and `/`, `/login`, every SPA route
return HTTP 404, while the JSON API at `/api/*` continues to
respond. A Dashboard QA worker attached during such a run
would correctly classify the surface as broken even though the
kernel itself is healthy — exactly the iter52 false-RED
verdict that consumed an entire QA worker iteration cycle.

**Iter52 reproduction.** The iter52 fix-loop ran in a fresh
sibling worktree (`/private/tmp/raxis-iter52-fixloop/`) where
`dashboard-fe/node_modules/` was absent. The previous
implementation logged the four lines below and returned
`None`, leaving the dashboard server in JSON-only mode for the
entire 65 min run:

```
[dashboard-bundle] dashboard-fe/dist/index.html missing — running `npm run build` in /private/tmp/raxis-iter52-fixloop/raxis/raxis/dashboard-fe (opt out via RAXIS_E2E_SKIP_DASHBOARD_BUILD=1)

> raxis-dashboard-fe@0.1.0 build
> tsc -b && vite build

sh: tsc: command not found
[dashboard-bundle] npm run build exited with ExitStatus(unix_wait_status(32512)); dashboard will serve JSON API only (no UI). Re-run `cd raxis/dashboard-fe && npm install && npm run build` manually to diagnose.
```

The `tsc: command not found` message is the iter52 fingerprint:
`tsc` lives at `node_modules/.bin/tsc`, so its absence
means `npm ci` was never run for this worktree. With this
invariant in force the harness:

1. Detects `node_modules/.bin/vite` (and `.bin/tsc`) absent.
2. Runs `npm ci` automatically (bounded 600 s).
3. Then runs `npm run build` (bounded 300 s).
4. Hands the resulting `dist/` to the kernel.
5. If ANY step fails (cold registry pull broken, network
   blocked, real `tsc` error, …) hard-panics so the operator
   sees the root cause in seconds rather than discovering 65
   min later that the dashboard QA worker can't see anything.

**Bounded-wait composition.** Both subprocess steps satisfy
`INV-LIVE-E2E-HARNESS-NO-INDEFINITE-WAIT-01` via
[`tests::common::dashboard::run_npm_bounded`], which polls
`Child::try_wait` and `SIGKILL`s the child when the bounded
deadline elapses. The bound defaults are deliberately generous
(`npm ci` 600 s for cold pulls; `npm run build` 300 s for a
real `tsc -b && vite build`) and clamp safely on
non-positive / unparseable env overrides — a regression that
flipped either default to `0` would silently disable the
bound, which the witness
[`inv_live_e2e_dashboard_fe_bundle_present_01_default_timeouts_are_generous_but_bounded`]
catches.

**Opt-out contract.** Setting
`RAXIS_E2E_SKIP_DASHBOARD_BUILD=1` skips both the install and
the build step and returns `None` (dashboard serves JSON-only),
with a single explicit `[dashboard-bundle]` log line. This is
the path for release-CI lanes that bake the React bundle
externally as a separate workflow step. The classifier proves
the opt-out wins over the missing-`package.json` and
missing-`node_modules` arms — a CI lane that pre-bakes the
bundle does not need a Node toolchain installed at all.

**Scenario.** Operator clones a fresh worktree of the repo
(typical for a fix-loop iteration or a PR review) and runs
`cargo test --release --test extended_e2e_realistic_scenario`.
With this invariant in force the harness auto-installs the
Node deps within the 600 s bound and proceeds — the operator
does NOT need to remember to `cd raxis/dashboard-fe && npm
ci && npm run build` first. In the opt-out mode the harness
fail-fast surfaces the literal opt-out log line and serves
JSON-only. Without this invariant the iter52 silent-degrade
ships: dashboard is broken, QA reports false-RED, the failure
mode is buried in the cargo log under several MB of unrelated
build output.

**Witness.**
[`tests::common::dashboard::tests::inv_live_e2e_dashboard_fe_bundle_present_01_classifier_dist_already_built_wins`](../kernel/tests/common/dashboard.rs):
exhaustively pins the fast-path arm — when `dist/index.html`
is already present the classifier returns
`BundleState::DistAlreadyBuilt` regardless of every other
input (`skip × 2 × pkg × 2 × nm × 2` = 8 cases). Pairs with
[`…::inv_live_e2e_dashboard_fe_bundle_present_01_classifier_skip_env_wins_over_failure_arms`](../kernel/tests/common/dashboard.rs)
(opt-out wins over package.json missing / node_modules
missing — the operator's "I'll handle it externally"
overrides workspace-shape arms),
[`…::inv_live_e2e_dashboard_fe_bundle_present_01_classifier_missing_package_json_hard_fails`](../kernel/tests/common/dashboard.rs)
(no dist + no opt-out + no package.json ⇒ hard-fail arm),
[`…::inv_live_e2e_dashboard_fe_bundle_present_01_classifier_missing_node_modules_needs_install`](../kernel/tests/common/dashboard.rs)
(no dist + no opt-out + package.json present + no
node_modules ⇒ install-then-build arm — the iter52 root cause
shape),
[`…::inv_live_e2e_dashboard_fe_bundle_present_01_classifier_node_modules_present_needs_build_only`](../kernel/tests/common/dashboard.rs)
(no dist + no opt-out + node_modules populated ⇒ skip
install, just build), and
[`…::inv_live_e2e_dashboard_fe_bundle_present_01_node_modules_probe_handles_missing_tree`](../kernel/tests/common/dashboard.rs)
(`node_modules_vite_present` returns `false` for missing
tree, present-but-empty-`.bin`, and the half-pruned shape that
bites in practice). Operator-surface stability is pinned by
[`…::inv_live_e2e_dashboard_fe_bundle_present_01_opt_out_env_var_name_pinned`](../kernel/tests/common/dashboard.rs)
(env var spellings),
[`…::inv_live_e2e_dashboard_fe_bundle_present_01_violation_token_shape`](../kernel/tests/common/dashboard.rs)
(panic-message scraper token), and
[`…::inv_live_e2e_dashboard_fe_bundle_present_01_default_timeouts_are_generous_but_bounded`](../kernel/tests/common/dashboard.rs)
(timeout defaults are bounded, with the iter52 lower-bound
floor + a 30 min ceiling so a future regression that flipped
either default to `0` would trip here).
[`…::inv_live_e2e_dashboard_fe_bundle_present_01_timeout_overrides_clamp_safely`](../kernel/tests/common/dashboard.rs)
exercises the env-override path: a missing var falls back to
the default, a positive value is honoured, and `0` /
unparseable values fall back to the default (the
"misconfigured CI lane" shape).

**Canonical home.**
`kernel/tests/common/dashboard.rs::locate_dashboard_dist` (the
mechanical enforcement site — every panic body carries the
`INV-LIVE-E2E-DASHBOARD-FE-BUNDLE-PRESENT-01 VIOLATED` token);
`kernel/tests/common/dashboard.rs::classify_bundle_state` (the
pure-data classifier the witness tests pin exhaustively);
`live-e2e/README.md §Dashboard FE bundle contract`
(operator-facing recipe + opt-out + bounded-wait env var
documentation).

[`dashboard-fe/dist/index.html`]: ../dashboard-fe/
[`tests::common::dashboard::locate_dashboard_dist`]: ../kernel/tests/common/dashboard.rs
[`tests::common::dashboard::classify_bundle_state`]: ../kernel/tests/common/dashboard.rs
[`tests::common::dashboard::run_npm_bounded`]: ../kernel/tests/common/dashboard.rs

---

### INV-LIVE-E2E-OTEL-PUSHER-PRESENT-01 — Live-e2e harness MUST guarantee a forwarding OTel pusher (or hard-fail), never silently degrade

**Statement.** Before the realism-e2e harness submits any plan,
it MUST guarantee that an OTel pusher process is actively
forwarding the kernel's metric ring to the OTLP collector at
`http://127.0.0.1:4318`, AND that Prometheus shows
`up{job=~"raxis.*"} = 1` for at least one raxis target. The
harness either spawns and supervises this pusher itself
(default) or asserts an external pusher is reachable (opt-out
via `RAXIS_E2E_SKIP_OTEL_PUSHER=1`). Silent degradation — the
run continuing while Grafana panels stay empty — is forbidden.

The harness's single source of truth for this contract is
[`extended_e2e_support::otel_pusher::ensure_otel_pusher_or_panic`];
that function MUST:

1. Resolve the pusher binary in this priority:
   a) `RAXIS_OTEL_PUSHER_BINARY` env var if set + present.
   b) Convention paths
      `<workspace>/target/{release,debug}/raxis-otel-pusher`
      and `$RAXIS_INSTALL_DIR/bin/raxis-otel-pusher`.
   c) If still missing AND `RAXIS_E2E_SKIP_OTEL_PUSHER` is unset,
      run `cargo build --release -p raxis-otel-pusher` with a
      bounded timeout
      ([`DEFAULT_OTEL_PUSHER_BUILD_TIMEOUT_SECS`], default 180 s,
      tunable via `RAXIS_E2E_OTEL_PUSHER_BUILD_TIMEOUT_SECS` and
      clamped to `[60s, 600s]`).
2. Spawn the pusher as a supervised child of the test process
   pointing at the kernel's `<data_dir>` and the kernel-signed
   `policy.toml`; capture its stderr to
   `<data_dir>/otel-pusher.stderr.log`; verify the child is
   alive after [`POST_SPAWN_LIVENESS_DELAY`] (3 s).
3. Smoke-probe Prometheus
   (`http://127.0.0.1:9090/api/v1/query?query=up`) for up to
   [`SMOKE_PROBE_BUDGET`] (30 s) at [`SMOKE_PROBE_INTERVAL`]
   (1 s) cadence; assert at least one `raxis*` job appears as
   `up=1`. The probe loop short-circuits on supervised-child
   death so a pusher that crashes mid-startup surfaces
   immediately instead of waiting out the full budget.
4. Return an [`OtelPusherSupervisor`] RAII guard whose `Drop`
   SIGTERM-then-SIGKILL's the child (500 ms grace window).
5. Emit exactly ONE operator-facing success log line of the
   form `[realism-e2e] observability: pusher spawned (pid=N,
   bin=…, log=…), smoke-probed, live metrics flowing to Grafana
   …`. The opt-out branch emits the parallel external-pusher
   form. Neither branch emits the contradictory pair this
   invariant exists to prevent (`INV-LIVE-E2E-OBSERVABILITY-LOG-NO-CONTRADICTION-01`).

Every panic body produced by the pipeline carries the literal
[`OTEL_PUSHER_VIOLATION_TOKEN`] (`INV-LIVE-E2E-OTEL-PUSHER-PRESENT-01
VIOLATED`) so a CI log scraper can pin the failure mode
without parsing the whole remediation block. The remediation
block names every escape hatch: pre-build the pusher, point
`RAXIS_OTEL_PUSHER_BINARY` at an existing binary, opt out via
`RAXIS_E2E_SKIP_OTEL_PUSHER=1`, or tune the build deadline.

**Opt-out (operator-supervised pusher).** Set
`RAXIS_E2E_SKIP_OTEL_PUSHER=1` to skip the auto-locate /
auto-build / spawn path. The harness logs an explicit opt-out
line and STILL runs the Prometheus smoke-probe — if no
external pusher is actually forwarding, the harness hard-fails
with the alternate remediation message
("Set `RAXIS_E2E_SKIP_OTEL_PUSHER=0` (or unset it) to let the
harness manage the pusher, OR ensure your external pusher is
running and pointing at `http://127.0.0.1:4318`"). Mirrors the
`RAXIS_LIVE_E2E_NO_AUTO_DOCKER` discipline for the docker
backing stack.

**Bounded-wait composition.** The auto-build subprocess is
bounded by [`otel_pusher_build_timeout`], which clamps any
out-of-range / unparseable / non-positive override to the
default — satisfying `INV-LIVE-E2E-HARNESS-NO-INDEFINITE-WAIT-01`
even on a misconfigured CI lane. The smoke-probe loop is
bounded by [`SMOKE_PROBE_BUDGET`].

**Justification.** The kernel emits per-frame metrics into an
in-process JSONL ring (`<data_dir>/observability/{spans,metrics}/`)
per `INV-OTEL-03`. Without the out-of-process pusher
forwarding those frames to OTLP, Prometheus has no data to
scrape and every Grafana panel stays empty for the duration
of the run. Iter53 reproduced the silent-degradation shape
exactly: the realism-e2e harness emitted both
`raxis-otel-pusher binary not located … Grafana panels will
stay empty` AND `kernel pushing OTLP to … live metrics flowing
to Grafana` in the same boot, the latter contradicting the
former — and the run continued for ~30 minutes without any
operator-visible signal that the dashboards were dark. The
parallel iter52 case for the dashboard FE bundle
(`INV-LIVE-E2E-DASHBOARD-FE-BUNDLE-PRESENT-01`) demonstrated
the same hard-fail policy works: the operator either pre-builds
the artifact, sets the explicit opt-out, or accepts the
auto-build cost — but never silently runs without the
artifact.

**Scenario.** Operator runs `cargo test -p raxis-kernel
--test extended_e2e_realistic_scenario --features
runtime-deadlock-detection` after `git worktree add` on a
fresh clone where `target/release/raxis-otel-pusher` has
never been built. With this invariant in force the harness
auto-builds the pusher (≤180 s on a healthy host), spawns it,
smoke-probes Prometheus, emits the single success log line,
and proceeds — the live test sees Grafana panels populating
within ~5 s of the kernel emitting its first metric. Without
the invariant the run would proceed silently with empty
dashboards (the iter53 root-cause shape) until the operator
manually notices the Grafana darkness ~30 minutes in.

**Witness.**
[`extended_e2e_support::otel_pusher::tests::inv_live_e2e_otel_pusher_present_01_classifier_opt_out_wins_over_locate`](../kernel/tests/extended_e2e_support/otel_pusher.rs)
(opt-out beats every locate-success arm),
[`…::inv_live_e2e_otel_pusher_present_01_classifier_envvar_beats_convention`](../kernel/tests/extended_e2e_support/otel_pusher.rs)
(env-var override beats convention paths),
[`…::inv_live_e2e_otel_pusher_present_01_classifier_convention_path_used`](../kernel/tests/extended_e2e_support/otel_pusher.rs)
(convention path arm dispatches when present),
[`…::inv_live_e2e_otel_pusher_present_01_default_path_auto_builds_when_missing`](../kernel/tests/extended_e2e_support/otel_pusher.rs)
(default path is `NeedsAutoBuild` — pins iter53 fix),
[`…::inv_live_e2e_otel_pusher_present_01_classifier_never_returns_hard_fail_directly`](../kernel/tests/extended_e2e_support/otel_pusher.rs)
(`HardFailMissingBinary` is reserved for the post-failed-build
dispatcher, not the classifier itself),
[`…::inv_live_e2e_otel_pusher_present_01_convention_path_precedence_release_first`](../kernel/tests/extended_e2e_support/otel_pusher.rs)
(release-before-debug precedence; pinned so a future maintainer
cannot silently flip onto a stale debug build).
Operator-surface stability is pinned by
[`…::inv_live_e2e_otel_pusher_present_01_opt_out_env_var_name_pinned`](../kernel/tests/extended_e2e_support/otel_pusher.rs)
(env var spellings),
[`…::inv_live_e2e_otel_pusher_present_01_violation_token_shape`](../kernel/tests/extended_e2e_support/otel_pusher.rs)
(panic-message scraper token + `cargo build --release -p
raxis-otel-pusher` remediation phrase),
[`…::inv_live_e2e_otel_pusher_present_01_default_build_timeout_generous_but_bounded`](../kernel/tests/extended_e2e_support/otel_pusher.rs)
(default sits in `[60s, 600s]` window), and
[`…::inv_live_e2e_otel_pusher_present_01_build_timeout_override_clamp_safely`](../kernel/tests/extended_e2e_support/otel_pusher.rs)
(env-override path: missing / `0` / unparseable / out-of-range
all clamp to default). Supervision discipline is pinned by
[`…::inv_live_e2e_otel_pusher_present_01_supervisor_kills_child_on_drop`](../kernel/tests/extended_e2e_support/otel_pusher.rs)
(spawns `sleep 9999` under the supervisor, drops the guard,
asserts the child dies within 5 s — the "no leaked processes"
contract). Smoke-probe shape is pinned by
[`…::inv_live_e2e_otel_pusher_present_01_smoke_probe_blocks_on_no_metrics`](../kernel/tests/extended_e2e_support/otel_pusher.rs)
(empty `up` series, only-non-raxis jobs, raxis-job-up=0 all
classify as `NoRaxisUpYet`; only raxis-job-up=1 short-circuits
the loop). Opt-out smoke-probe path is pinned by
[`…::inv_live_e2e_otel_pusher_present_01_opt_out_still_smoke_probes`](../kernel/tests/extended_e2e_support/otel_pusher.rs)
(opt-out branch dispatches into `SmokeProbeMode::ExternalPusher`
with the alternate remediation phrasing).

**Canonical home.**
`kernel/tests/extended_e2e_support/otel_pusher.rs::ensure_otel_pusher_or_panic`
(the mechanical enforcement site — every panic body carries
the `INV-LIVE-E2E-OTEL-PUSHER-PRESENT-01 VIOLATED` token);
`kernel/tests/extended_e2e_support/otel_pusher.rs::classify_otel_pusher_state`
(the pure-data classifier the witness tests pin exhaustively);
`kernel/tests/extended_e2e_support/otel_pusher.rs::OtelPusherSupervisor`
(the RAII guard that satisfies the no-leaked-processes half
of the invariant);
`live-e2e/README.md §OTel pusher auto-spawn contract`
(operator-facing recipe + opt-out + bounded-wait env var
documentation);
`specs/v3/observability-prometheus.md §4.2`
(cross-link to this invariant from the Prometheus side of the
contract).

[`extended_e2e_support::otel_pusher::ensure_otel_pusher_or_panic`]: ../kernel/tests/extended_e2e_support/otel_pusher.rs
[`OtelPusherSupervisor`]: ../kernel/tests/extended_e2e_support/otel_pusher.rs
[`OTEL_PUSHER_VIOLATION_TOKEN`]: ../kernel/tests/extended_e2e_support/otel_pusher.rs
[`POST_SPAWN_LIVENESS_DELAY`]: ../kernel/tests/extended_e2e_support/otel_pusher.rs
[`SMOKE_PROBE_BUDGET`]: ../kernel/tests/extended_e2e_support/otel_pusher.rs
[`SMOKE_PROBE_INTERVAL`]: ../kernel/tests/extended_e2e_support/otel_pusher.rs
[`DEFAULT_OTEL_PUSHER_BUILD_TIMEOUT_SECS`]: ../kernel/tests/extended_e2e_support/otel_pusher.rs
[`otel_pusher_build_timeout`]: ../kernel/tests/extended_e2e_support/otel_pusher.rs

---

### INV-LIVE-E2E-OBSERVABILITY-LOG-NO-CONTRADICTION-01 — Harness MUST NOT emit contradictory observability log lines in the same run

**Statement.** Within a single realism-e2e run the harness MUST
NOT emit BOTH a line containing `Grafana panels will stay
empty` AND a line containing `live metrics flowing to Grafana`.
Either the pusher is actively forwarding (success log fires
once) or the pusher is not (the harness hard-fails per
`INV-LIVE-E2E-OTEL-PUSHER-PRESENT-01`); there is no
intermediate state where both can coexist. The contradictory
pair would cause an operator scanning the log to trust the
"live metrics flowing" claim and stop debugging the dark
dashboard, so the absence of the contradictory pair is itself
a contract.

**Justification.** The iter53 root-cause sequence emitted both
lines back-to-back:

```text
[realism-e2e] observability: raxis-otel-pusher binary not located …
  kernel will emit to its in-process JSONL ring but Grafana panels will stay empty for this run
[realism-e2e] observability: kernel pushing OTLP to http://127.0.0.1:4318 —
  live metrics flowing to Grafana http://127.0.0.1:3000/d/raxis-00-overview
```

The second line was static, fired unconditionally after a
best-effort spawn that returned `None`. Operators scanning
the log saw "live metrics flowing" and assumed the dashboards
were live — the dark Grafana was attributed to a misconfigured
panel rather than to a missing pusher. The fix
(`INV-LIVE-E2E-OTEL-PUSHER-PRESENT-01`) makes the missing-
pusher path hard-fail, but the no-contradiction invariant
exists as a defence-in-depth witness so a future maintainer
who adds a new code path cannot reintroduce the contradictory
pair via a different code path (e.g. a "best-effort fallback
to a stub pusher that doesn't actually forward").

**Scenario.** Future maintainer adds a `RAXIS_E2E_OTEL_PUSHER_DRY_RUN=1`
env var that spawns the pusher with `--dry-run` (no OTLP
exports). They emit a "Grafana panels will stay empty" warning
in that branch but forget to suppress the pre-existing "live
metrics flowing" line. Without this invariant the
contradictory pair re-emerges silently. With it the witness
asserts neither shape coexists with the other — adding a new
"stay empty" surface is a deliberate spec-edit-required
choice rather than an accidental regression.

**Witness.**
[`extended_e2e_support::otel_pusher::tests::inv_live_e2e_observability_log_no_contradiction_01_pusher_absent_emits_only_failure_path`](../kernel/tests/extended_e2e_support/otel_pusher.rs)
asserts (a) the constructed success log line shape contains
`live metrics flowing to Grafana` and DOES NOT contain `stay
empty`; (b) the constructed hard-fail panic body carries the
`OTEL_PUSHER_VIOLATION_TOKEN` and DOES NOT contain `live
metrics flowing`. Together these pin the contract at both
the success-log and the failure-panic surfaces.

**Canonical home.**
`kernel/tests/extended_e2e_support/otel_pusher.rs::ensure_otel_pusher_or_panic`
(the mechanical enforcement site — both the success log and
the hard-fail panic bodies are constructed inline; a
maintainer adding a new code path with a "stay empty" warning
would have to also drop the "live metrics flowing" success
line, which the witness prevents). Pairs with
`INV-LIVE-E2E-OTEL-PUSHER-PRESENT-01` whose enforcement
mechanism makes the contradictory pair structurally
impossible in the default path.

---

## §11.11 — Host hygiene (INV-HOST-HYGIENE-*)

These invariants govern the parent-side worktree pool that
spawns Raxis worker agents. They are operational invariants:
the kernel does not enforce them at admission time, but the
live-e2e harness and the operator dashboard MUST refuse to
proceed when they are violated, because a saturated host
cannot satisfy the V2 disk-watchdog contract
(`INV-CAPACITY-02`, `host-capacity.md §7.1`).

### INV-HOST-HYGIENE-01 — Worktree pool MUST be swept; live-e2e MUST refuse over-pressure

**Statement.** Every developer host running parent-side Raxis
worker agents MUST have a worktree-hygiene mechanism that
prunes git worktrees whose branches have landed to the host
repo's resolved default-branch ref AND whose files are not
actively held open. The live-e2e harness MUST refuse to run
when host disk usage exceeds 90% on the repo volume,
`/private/tmp`, or `/var/folders/*`.

**Scope: dev/CI host, not production operator.** This
invariant governs the developer-host concern of keeping the
parent-side `git worktree` pool from filling the data volume
under concurrent worker activity. A `brew install raxis`
production operator has no cargo workspace and no
aegis-worktrees to sweep — the invariant simply does not
apply to that deployment. Accordingly, the enforcement chain
is workspace-/CI-scoped: `cargo xtask hygiene` + `cargo xtask
hygiene-check` (developer tools), the live-e2e harness
preflight (CI / developer pre-test gate), the structured
stderr envelope `OPERATOR_ATTENTION_REQUIRED
HostHygieneDiskPressure {json}` (harness / terminal / CI-log
consumer), and the operator recipe at
`guides/operator/18-host-hygiene.md`. The operator dashboard
is **deliberately not** part of the surface: the kernel does
not emit a `HostHygieneDiskPressure` audit event, and the
audit chain stays kernel-scoped for runtime invariants only
per `INV-DASHBOARD-FAILURE-VISIBILITY-01`'s kernel-emitted-only
scope (see `dashboard-hardening.md §5.7`).

The reference implementation is `cargo xtask hygiene` (sweep)
+ `cargo xtask hygiene-check --threshold-pct N` (read-only
preflight). The hygiene mechanism MAY be invoked manually or
on a periodic timer (the macOS launchd plist
`raxis/launchd/com.raxis.hygiene.plist` and the Linux
systemd unit `raxis/systemd/raxis-hygiene.{service,timer}`
are the supported defaults — see
`guides/operator/18-host-hygiene.md`).

The merge-base reference used by the classifier is
**operator-configurable / auto-detected, NOT hardcoded** so
the invariant holds for any Raxis-based repo regardless of
default-branch name (`main` / `master` / `trunk` /
`develop` / etc.):

1. If the operator passes `--main-ref REF`, that value is
   used verbatim.
2. Otherwise the resolver runs
   `git symbolic-ref --short refs/remotes/origin/HEAD` and
   uses whatever ref it returns (e.g. `origin/main` on a
   vanilla clone, `origin/develop` on a fork).
3. If auto-detect fails (no `origin/HEAD` configured,
   detached state, etc.), the resolver falls back to the
   literal `origin/main`.

The chosen ref + its provenance MUST be logged at sweep
start as `[hygiene] main_ref=<ref> (<source>)` where
`<source>` is one of `auto`, `--main-ref override`, or
`fallback`. The auto-detect parser is unit-tested
(`xtask/src/hygiene.rs::tests::parse_symbolic_ref_output_*`)
to ensure forks with renamed default branches produce a
clean ref value.

The classifier rule is mechanical:

* REMOVABLE only when ALL of: (a) the worktree is NOT the
  main checkout, (b) the worktree is NOT on the operator's
  `--keep` allowlist, (c) the worktree is NOT the current
  `cargo xtask` invocation's own dir, (d) the branch tip is
  reachable from the resolved main ref (`git merge-base
  --is-ancestor <tip> <main-ref>`), AND (e) no process
  holds files open under the worktree (lsof CWD evidence
  on macOS / Linux).
* KEEP otherwise. The classifier surfaces a typed
  `KeepReason` (`MainCheckout` / `OnKeepList` /
  `SelfInvocation` / `Locked` / `DetachedHead` /
  `BranchAhead` / `InUse` / `TooNew`) so the dry-run output
  is auditable.

The live-e2e preflight emits a structured stderr envelope
`OPERATOR_ATTENTION_REQUIRED HostHygieneDiskPressure {json}`
where `{json}` is a `raxis_types::host_preflight::HostPreflightError::DiskPressure`
payload (`pressure_kind`, `threshold_pct`, `observed_volumes`,
`remediation_cmd`, `docs_url`) *before* bailing the test.
The envelope is consumed by the harness itself, the
developer's terminal, and CI log scrapers — NOT by the
operator dashboard (see Scope above and
`dashboard-hardening.md §5.7`). The preflight ALSO panics
with the structured `Display` rendering so the offending
volume and the `cargo xtask hygiene` remediation command land
in the `cargo test` failure summary without parsing stderr.

**Justification.** A single saturating run of seven
concurrent parent-side workers (each carrying a multi-GiB
`cargo target/`) filled 902 GiB and tripped
`DiskFullHaltEntered` mid-iteration. The kernel's own
`min_free_disk_mb` floor caught the failure but only AFTER
1867 s of wasted live-e2e runtime — every activation in
iter 16 was rejected with `FailDiskFull`. The hygiene
sweep + preflight refuses to start a 31-min flow when the
host is already one `cargo build` away from
`DiskFullHaltEntered`, converting a mid-flight failure into
a sub-second skip with a clear, structured remediation
pointer.

**Scenario.** Six parent-side worker agents land their
branches over a 24-hour window; each leaves behind a
`/private/tmp/raxis-<task>-<pid>/` worktree carrying a
~3 GiB `target/`. The seventh worker spawns, the host disk
crosses 90%, the live-e2e preflight observes the
`/System/Volumes/Data` capacity, prints the
`OPERATOR_ATTENTION_REQUIRED HostHygieneDiskPressure {json}`
envelope to stderr, panics with the structured remediation
pointer, and fails the test before any kernel boot. The
developer reads the panic message (or the `cargo test`
failure summary), runs `cargo xtask hygiene`, watches the
six landed worktrees disappear, and re-runs the test — clean.

**Canonical home.** `xtask/src/hygiene.rs` header (sweep
mechanism + `resolve_main_ref` / `parse_symbolic_ref_output`
default-branch resolver), `guides/operator/18-host-hygiene.md`
"Default-branch resolution" section (operator recipe + the
`--main-ref` override example). The structured-error payload
is pinned in `crates/types/src/host_preflight.rs`. The
out-of-scope rationale for the operator dashboard is pinned
in `dashboard-hardening.md §5.7`.

**Witness / verification.**
  * Sweep + classifier: `xtask/src/hygiene.rs::tests` (unit
    tests for `resolve_main_ref` / `parse_symbolic_ref_output`
    + classifier rules).
  * Preflight + envelope shape:
    `kernel/tests/extended_e2e_support/kernel_driver.rs::hygiene_preflight_tests`
    (synthetic disk-pressure round-trip through the stderr
    envelope JSON + `Display`, `ATTENTION_KIND` constant pin,
    clear-host happy path).
  * Wire-shape: `crates/types/src/host_preflight.rs::tests`
    (JSON round-trip, `pressure_kind` discriminator,
    `Display` rendering, `ATTENTION_KIND` constant).

---

## §11.12 — Self-healing supervisor (INV-SUPERVISOR-*)

These invariants govern the optional `raxis-supervisor` binary
that wraps `raxis-kernel` so a deadlock / panic / OOM-kill /
crash becomes a sub-second auto-restart instead of a permanently
wedged kernel. Lands behind the
`RAXIS_SUPERVISOR_AUTO_RESTART=1` opt-in env var; default-off
preserves the existing operator-managed restart behaviour and
leaves live-e2e iter-by-iter behaviour bit-identical.

Canonical home: `v2/self-healing-supervisor.md`.

### INV-SUPERVISOR-RESTART-AUDIT-01 — Every restart emits a paired audit chain entry

**Statement.** Every kernel restart triggered by the supervisor
emits a paired (`KernelRestartInitiated` + matching
`KernelRestartCompleted` OR `KernelRestartHaltedCircuitOpen`)
audit-chain entry, and the chain stays hash-continuous across
the restart boundary. When the restart cause is a deadlock
detection on the prior run, a `KernelDeadlockDetected` event is
synthesised into the chain on the next boot from the on-disk
forensic dump (`<data_dir>/deadlock_dump_<unix_ts>.json`),
sequenced ahead of `KernelRestartCompleted` so the chain reads
left-to-right as
`KernelDeadlockDetected → KernelStarted → KernelRestartCompleted`.

**Justification.** The audit chain is the single
forensically-trustworthy record of kernel-process lifecycle
(`R-7`, `INV-04`). Without paired restart records the chain
would silently elide deadlock-driven exits — an offline
verifier looking at the JSONL would see a clean
`KernelStarted` after a `KernelStarted` with no signal that the
prior kernel died. Pairing the events explicitly preserves
forensic legibility AND keeps `verify-chain` hash-clean across
the restart.

**Scenario.** A deadlock cycle forms across two
`parking_lot::Mutex`es at `t=0`. The watcher detects it at
`t≈2 s`, writes
`<data_dir>/deadlock_dump_1714500002.json`, and exits 70. The
supervisor classifies the exit, writes the sentinel, and
spawns a new kernel. The new kernel boots, runs
`recovery::reconcile`, opens the audit writer, scans
`<data_dir>/` for unprocessed dumps, finds the file, emits
`KernelDeadlockDetected { dump_path: Some("...") }`, then
emits the canonical `KernelStarted`, then emits
`KernelRestartCompleted { prev_run_exit_code: 70,
recovery_sweep_ms: 47, dump_path: Some("...") }`. The dump
file is moved to `<data_dir>/deadlock_dumps_consumed/` so the
next boot doesn't double-emit. `verify-chain` reads the
segment end-to-end and validates every `prev_sha256` link.

**Witness.** `raxis/kernel/tests/deadlock_supervisor_handoff.rs`
seeds a synthetic dump file and a partial audit chain,
re-boots the kernel binary, and asserts:
*  `KernelDeadlockDetected { dump_path: Some(...) }` is
   appended;
*  `KernelStarted` is appended;
*  `KernelRestartCompleted { prev_run_exit_code: 70 }` is
   appended;
*  `raxis_audit_tools::verify_chain_from(audit_dir, 0)` returns
   `Ok` end-to-end across the seeded prior segment + the
   freshly-appended events.

**Canonical home.** `v2/self-healing-supervisor.md` §3.3 +
§3.4 (boot-time rehydration + new audit event variants);
`v2/audit-paired-writes.md` §6 (restart audit emission
contract addendum).

---

### INV-SUPERVISOR-CIRCUIT-BREAKER-01 — ≤3 restarts in 60s sliding window

**Statement.** The supervisor allows **at most 3** kernel
restarts inside any rolling **60-second** window. The 4th
restart attempt within the window MUST cause the supervisor
to:
1. Refuse the restart (no kernel child spawned);
2. Write the sentinel as `Halted (CircuitOpen)`;
3. On the next boot of the supervisor (manually or via
   `reset-circuit-breaker`), emit
   `KernelRestartHaltedCircuitOpen { attempts_in_window,
   window_secs, last_failure_reason }` into the audit chain;
4. Exit `0` (the supervisor is done; operator must intervene).

The window is a true sliding window (each restart's
`unix_ts` is recorded; entries older than `window_secs` fall
off). The state survives supervisor restarts via
`<data_dir>/supervisor_state.json` so a launchd / systemd
restart of the supervisor does not silently re-arm the
breaker.

**Justification.** Without this bound a persistent deadlock
(or a kernel that fails its boot recovery) would burn
indefinitely in a tight restart loop, hot-loading the disk +
audit chain. The 3/60 s limit converts a pathological loop
into an operator-paged halt within ~3 minutes wall-clock,
preserving forensic evidence (the dump files for each of the
3 attempts persist on disk).

**Scenario.** A kernel bug introduced in an upgrade
deadlocks immediately on the first session-spawn — every
restart hits the same bug at the same code path and exits 70
within ~5 s. The supervisor restarts at `t=5, t=10, t=15`,
then refuses at `t=20` with `Halted (CircuitOpen)`. The
operator opens the dashboard, sees the red banner, runs
`raxis-supervisor reset-circuit-breaker --yes` after rolling
back the kernel binary, and the cycle clears.

**Witness.**
`raxis/crates/supervisor/tests/circuit_breaker.rs::four_failures_in_window_open_circuit`
spawns a fake child binary that exits 70 on launch, runs the
supervisor's spawn-and-classify loop synthetically with a
fake clock, and asserts the 4th attempt is refused + sentinel
transitions to `Halted (CircuitOpen)`.

**Canonical home.** `v2/self-healing-supervisor.md` §4.3.

---

### INV-SUPERVISOR-OPT-IN-01 — Auto-restart is gated behind `RAXIS_SUPERVISOR_AUTO_RESTART=1`

**Statement.** The supervisor's spawn-and-watch loop runs ONLY
when `RAXIS_SUPERVISOR_AUTO_RESTART=1` is set in the
supervisor's process environment. Without the env var,
`raxis-supervisor start` logs a single
`{"event":"SupervisorOptInGateClosed"}` line on stderr and
exits `0` immediately without spawning a kernel child. The
operator's existing manual `raxis-kernel` invocation runs
exactly as it did before this surface landed.

**Justification.** Phase-1 rollout discipline. The kernel's
default deadlock behaviour today (`panic = "abort"` on
detection, operator restarts manually) is the
known-stable-on-iter-41 baseline. An always-on supervisor
would ship a behaviour change to the live-e2e harness
(`raxis/live-e2e/...`) the same day the supervisor lands,
mixing two variables in one regression-window. The env-var
gate keeps live-e2e bit-identical until phase 2.

**Scenario.** A developer runs `cargo test
-p raxis-kernel --test extended_e2e_realistic_scenario`. The
test harness does not set
`RAXIS_SUPERVISOR_AUTO_RESTART=1`. Even if the supervisor
binary is on PATH, no auto-restart fires; if a deadlock
forms, the kernel exits non-zero and the test fails fast as
before. The same test on a production deployment with
`RAXIS_SUPERVISOR_AUTO_RESTART=1` set in the launchd
environment would auto-restart up to the §INV-SUPERVISOR-
CIRCUIT-BREAKER-01 ceiling.

**Witness.**
`raxis/crates/supervisor/tests/opt_in_gate.rs::no_env_var_means_no_supervision`
invokes the supervisor's `lib::run` entrypoint with an
empty `RAXIS_SUPERVISOR_AUTO_RESTART` env var and asserts
no kernel child is spawned + the gate-closed log line is
emitted.

**Canonical home.** `v2/self-healing-supervisor.md` §4.9.

---

### INV-SUPERVISOR-SIGTERM-RESPECT-01 — SIGTERM never triggers a restart

**Statement.** The supervisor MUST NOT restart the kernel
after a SIGTERM-induced exit, regardless of who sent the
signal:
1. **Operator → supervisor → kernel** (the canonical
   `raxis-supervisor stop` path): the supervisor sets
   `intentional_shutdown = true`, forwards SIGTERM to the
   kernel child, waits for the child to exit, classifies as
   `Halted (OperatorTerminated)`, and exits 0 itself.
2. **External actor → kernel directly** (e.g. an init system
   or a manual `kill -TERM <kernel_pid>`): the supervisor
   observes the child exit with `WIFSIGNALED + SIGTERM` and
   `intentional_shutdown = false`, classifies as `Halted
   (ExternalSigterm)`, and exits 0 without spawning a
   replacement.

The bound on this is mechanical: the §4.4 classification
table makes both paths return `SupervisorAction::Halt`, and
the supervisor never spawns a replacement child after
classifying `Halt`.

**Justification.** SIGTERM is the universal "please stop"
signal. Auto-restarting after SIGTERM transforms `kill
-TERM` (and `launchctl stop`, `systemctl stop`, the operator's
own `raxis-supervisor stop`) into an infuriating "stop, then
auto-restart 200 ms later" loop — a UX bug serious enough
that it would single-handedly disqualify the supervisor for
production. The contract makes restart behaviour a strict
subset of the failure space: only crash recovery, never
operator override.

**Scenario.** Operator runs `systemctl stop raxis-supervisor`
on a Linux production host. systemd sends SIGTERM to the
supervisor PID. The supervisor handler sets
`intentional_shutdown = true`, forwards SIGTERM to the
kernel child, waits up to 30 s for the kernel's own
`signal::ctrl_c` handler to drain in-flight IPC, observes
the child exit, writes sentinel `Halted
(OperatorTerminated)`, and exits 0. systemd sees the supervisor
exit 0 and marks the unit `inactive (dead)`. No replacement
kernel is spawned. The dashboard renders the grey "Kernel
terminated by operator" banner with the `raxis-supervisor
start` restart command.

**Witness.**
`raxis/crates/supervisor/tests/sigterm_respect.rs::sigterm_to_supervisor_propagates_and_halts`
spawns the supervisor against a fake kernel child, sends
SIGTERM via `nix::sys::signal::kill`, and asserts (a) the
child receives the forwarded SIGTERM, (b) the supervisor
exits 0 within the grace window, (c) the sentinel is written
as `Halted (OperatorTerminated)`, (d) NO replacement child
process is spawned (verified by polling `/proc` or
equivalent under the supervisor's process group).

**Canonical home.** `v2/self-healing-supervisor.md` §4.5.

---

### INV-SUPERVISOR-SIGINT-RESPECT-01 — SIGINT never triggers a restart

**Statement.** The supervisor MUST NOT restart the kernel
after a SIGINT-induced exit. SIGINT is universally Ctrl+C
(the user pressed it on the controlling terminal); the
supervisor classifies as `Halted (OperatorInterrupt)` and
exits 0 without spawning a replacement, regardless of whether
the supervisor or an external actor sent the signal.

**Justification.** Same UX argument as
`INV-SUPERVISOR-SIGTERM-RESPECT-01`, with extra force: SIGINT
is what every developer types when they want a process to
stop right now. A supervisor that ignored SIGINT would be
worse than one that ignored SIGTERM, because terminal users
expect Ctrl+C to mean "stop everything, including the
supervisor's restart loop".

**Scenario.** Developer runs `raxis-supervisor start
--data-dir ~/.raxis` in a terminal, presses Ctrl+C. The
shell delivers SIGINT to the foreground process group (both
the supervisor AND the kernel child receive it). The
supervisor handler observes either delivery path (its own
SIGINT or the child's exit-on-SIGINT), classifies, writes
sentinel `Halted (OperatorInterrupt)`, exits 0. Terminal
returns to a prompt within the grace window.

**Witness.**
`raxis/crates/supervisor/tests/sigint_respect.rs::sigint_to_supervisor_propagates_and_halts`
mirrors the SIGTERM-respect test against SIGINT.

**Canonical home.** `v2/self-healing-supervisor.md` §4.5.

---

### INV-SUPERVISOR-EXIT-CODE-CLASSIFICATION-01 — Exit-code → action mapping is mechanical

**Statement.** The supervisor's `classify(outcome,
intentional_shutdown) → SupervisorAction` function MUST
return the action specified by the §4.4 exit-code table for
every input combination. The table is exhaustive (covers
`WEXITSTATUS = 0`, `WEXITSTATUS = 70`, other non-zero exits,
SIGTERM with both supervisor-sent and external origins,
SIGINT, SIGKILL with both origins, SIGABRT/SIGSEGV/SIGBUS,
SIGHUP, and a fall-through for any other signal). No code
path decides restart vs halt outside this function.

**Justification.** Centralising the decision in a single pure
function makes the operator-signal contract auditable: every
restart-or-not call has exactly one source of truth, every
row of the table has a witness sub-test, and the §4.4 table
itself is the documentation. Without this discipline,
restart logic would scatter across the spawn loop, signal
handlers, and the circuit breaker — and a future contributor
would re-introduce the "auto-restart after SIGTERM" UX bug
the moment they touched any one of those sites.

**Scenario.** A developer adds a new `SIGUSR1`-driven
observability dump path to the kernel (separate PR). The
supervisor's table has a fall-through "any other signal →
restart with circuit breaker" row; the new SIGUSR1 path
either causes the kernel to exit `0` (handled, no restart)
or to crash (SIGSEGV → restart). The classifier needs no
update; the §4.4 table covers the new case structurally.

**Witness.**
`raxis/crates/supervisor/tests/exit_classification.rs::*`
runs one sub-test per row of the §4.4 table, asserting
`classify(...)` returns the documented `SupervisorAction`
for each combination.

**Canonical home.** `v2/self-healing-supervisor.md` §4.4.

---

### INV-SUPERVISOR-SHUTDOWN-GRACE-01 — Supervisor honours the shutdown grace deadline

**Statement.** When the supervisor forwards SIGTERM (or
SIGINT) to the kernel child, it MUST wait at least
`RAXIS_SUPERVISOR_SHUTDOWN_GRACE_SECS` (default `30`) for
the kernel to exit naturally before escalating to SIGKILL.
The supervisor MUST NOT escalate inside the grace window
even if the operator sends a second SIGTERM (which is
recorded as already-shutting-down + ignored). The
escalation, when it fires, MUST emit a structured
`KernelGracefulShutdownTimedOut { grace_secs, child_pid }`
log line on supervisor stderr.

**Justification.** The kernel's own graceful shutdown path
runs `dashboard::serve_with_shutdown` (which drains SSE
clients, dashboard-hardening.md §1.5), the IPC graceful
drain seam (any in-flight `IntentRequest` completes), and
the audit-writer fsync. Cutting that short with a premature
SIGKILL would (a) drop in-flight operator-visible work, (b)
risk a partial audit-write on the way out, and (c) defeat
the point of having a graceful shutdown handler in the
kernel at all. The 30-second default is generous enough to
absorb a long-running planner or an integration-merge
fsync; operators who need a tighter bound use
`raxis-supervisor stop --force` (which uses a 5 s grace).

**Scenario.** A long-running planner-orchestrator session
is mid-evaluation when the operator runs `raxis-supervisor
stop`. SIGTERM reaches the supervisor, which forwards to the
kernel. The kernel's `signal::ctrl_c` handler drains SSE
clients (~1 s), waits for the in-flight intent to finish
(~8 s), and exits cleanly. Total wall-clock: ~9 s, well
under the 30 s grace; supervisor classifies as `Halted
(OperatorTerminated)` and exits 0. No SIGKILL was sent.

**Witness.**
`raxis/crates/supervisor/tests/shutdown_grace.rs::supervisor_waits_full_grace_before_sigkill`
spawns a fake kernel child that takes 5 s to handle SIGTERM.
Sets `RAXIS_SUPERVISOR_SHUTDOWN_GRACE_SECS=10`. Asserts the
child exited via SIGTERM (not SIGKILL — checked via the
exit-status discriminator), and that the elapsed wall-clock
between SIGTERM-send and child-exit is ≥ 5 s and
< 10 s (i.e. inside the grace window, not at the deadline).

**Canonical home.** `v2/self-healing-supervisor.md` §4.5.

---

### INV-DASHBOARD-KERNEL-LIFECYCLE-01 — Dashboard surfaces non-Healthy state within 5s

**Statement.** When `<data_dir>/kernel_lifecycle_status.json`
shows a non-`Healthy` status, the operator dashboard MUST
render the matching `KernelLifecycleBanner` within 5 seconds
of the sentinel transition. The banner copy + tone for each
sub-state is pinned by `v2/self-healing-supervisor.md §5.3`.

**Justification.** The kernel may be down during a restart
window (sentinel = `Restarting`) or permanently halted
(sentinel = `Halted (CircuitOpen)`). Without a prominent
banner, the operator's dashboard is silently empty / stale
and the operator has no way to distinguish "the dashboard
itself is broken" from "the kernel is down" from "the kernel
is recovering". The 5-second cadence is an upper bound on
how long an operator stares at stale data before learning
the kernel state changed.

**Scenario.** A deadlock fires on the kernel; supervisor
writes sentinel `Restarting (DeadlockDetected, attempt 1/3)`.
The operator's dashboard tab is open; within 5 s the yellow
banner replaces the (previously absent) banner area, telling
the operator the kernel is restarting and that this is
attempt 1 of 3. After the kernel boots, the supervisor
writes sentinel `Healthy`; within 5 s the banner clears.

**Witness.** Pair of mechanical test bundles:
*  `raxis/crates/dashboard/src/routes/health.rs::tests::*` —
   eight round-trip tests (`missing_sentinel_returns_healthy_fresh`,
   `missing_data_dir_returns_healthy_fresh`,
   `fresh_healthy_sentinel_passes_through`,
   `fresh_restarting_sentinel_passes_through`,
   `fresh_halted_circuit_open_sentinel_passes_through`,
   `stale_sentinel_with_dead_supervisor_pid_reports_supervisor_gone`,
   `corrupted_sentinel_returns_supervisor_gone_no_panic`,
   `unknown_future_field_silently_ignored`) drive
   `read_kernel_lifecycle_response` directly with hand-built
   sentinel files and assert every sub-state of the §4.6
   schema round-trips with the correct freshness verdict.
*  `raxis/dashboard-fe/src/test/kernel-lifecycle-banner.test.tsx` —
   fifteen tests covering `bannerTone`, `headlineFor`, and the
   pure-presentation `<KernelLifecycleBannerView>`. They assert
   (a) the banner is hidden whenever `supervisor_pid === 0` OR
   `status === "Healthy"` (the "no chrome leak" guard for
   operators who never opted in), (b) the rose / amber tone
   pair fires for every documented sub-state
   (`CircuitOpen`, `OperatorStop`, `OperatorStopForced`,
   `SupervisorGone`, `Restarting`), and (c) the stale-data
   note appears when `fresh === false`.

**Canonical home.** `v2/self-healing-supervisor.md` §5;
`v2/dashboard-hardening.md §6` (kernel-lifecycle banner
contract addendum).

---

### INV-SUPERVISOR-OPERATOR-CONTINUITY-01 — Operator JWTs survive supervisor-triggered restarts

**Statement.** When the supervisor auto-restarts the kernel
(deadlock, panic, OOM, signal-crash — any
`Outcome::restart_eligible() == true` per `INV-SUPERVISOR-EXIT-CODE-CLASSIFICATION-01`),
the new kernel boot MUST produce a `JwtSigner` that verifies
every JWT minted by the prior boot whose `exp > now` and
whose `gen` matches the persisted `secret_generation`. In
plain English: an operator with a valid open dashboard tab
MUST NOT be bounced to `/login` as a side effect of the
supervisor doing its job. The operator is bounced to `/login`
ONLY when (a) the JWT has expired, (b) the JWT has been
revoked, or (c) the operator explicitly ran
`raxis dashboard rotate-jwt-secret` between the two boots.

**Justification.** Pre-V2.5 the dashboard's HS256 secret was
ephemeral per kernel boot. The only way the kernel restarted
was operator-initiated (controlled, expected, infrequent), so
re-login on every restart was acceptable. The supervisor
changes the contract: the kernel can now restart
**autonomously** within ~3 seconds of a deadlock. Without
this invariant, every autonomous restart would silently log
out every operator currently using the dashboard — losing
unsaved React state (a partially-typed escalation response,
a partially-edited `policy.toml` draft, an unscrolled audit-
log filter) — with no causal explanation visible to the
operator. That is the worst possible UX failure for a self-
healing system: the kernel did the right thing
(restart promptly + cleanly) and the operator experiences it
as the system having **failed**. This invariant closes that
failure mode by persisting the secret across boots so the
new kernel reloads the same bytes the previous kernel was
using.

**Scenario.** Operator is reviewing an escalation in the
dashboard. The kernel deadlocks at `T+0`, watcher writes a
forensic dump and exits 70 at `T+50ms`. Supervisor sees
exit 70, classifies as `DeadlockDetected`, updates the
sentinel to `Restarting (1/3)`, forks a new kernel at
`T+100ms`. New kernel calls `JwtSigner::load_or_mint(&data_dir)`,
**reloads** the same secret bytes + same generation. Sentinel
flips back to `Healthy` at `T+2.5s`. Meanwhile the operator's
browser was polling `/api/health/kernel-lifecycle`; it showed
the yellow `Restarting (1/3)` banner for ~2.5 s; the banner
cleared once the new kernel was up. The operator's existing
JWT verifies cleanly under the new signer (same secret, same
gen). **They keep their unsaved escalation draft.** No
re-login.

**Witness.** Pair of mechanically-enforced tests:
* `raxis/crates/dashboard/src/jwt_secret.rs::tests::load_or_mint_reloads_existing_file_byte_identical`
  asserts the persisted file round-trips byte-identically.
* `raxis/crates/dashboard/src/auth.rs::tests::jwt_minted_pre_restart_verifies_post_restart_via_persisted_secret`
  models the restart by minting a JWT under one signer,
  dropping it, constructing a fresh signer from the same
  data dir, and asserting the JWT verifies — including
  asserting `claims.gen == 1` (the persisted generation).

**Canonical home.** `v2/self-healing-supervisor.md` §10
(Operator session continuity across supervisor-triggered
restarts).

---

### INV-SUPERVISOR-AUTO-RESUME-ON-CLEAN-RESTART-01 — Tasks auto-resume after a supervisor-triggered restart

**Statement.** When the supervisor restarts the kernel after an
auto-restartable exit code (per
`INV-SUPERVISOR-EXIT-CODE-CLASSIFICATION-01`), the kernel MUST
auto-resume every `BlockedRecoveryPending` task created by THAT
supervisor's recovery sweep, EXCEPT tasks under operator
quarantine (`initiative_quarantines` row exists for the
initiative) OR tasks that were already `BlockedRecoveryPending`
before the restart (preserve pre-existing operator block —
distinguishable via the per-task `prior_state` captured by the
boot-time `reconcile_tasks` SELECT-then-UPDATE pass).

Each auto-resume MUST emit
`TaskAutoResumedAfterSupervisorRestart` with `task_id`,
`initiative_id`, `prior_state`, `witness_count_preserved`, and a
`supervisor_restart_id` shared by every event from the same
restart episode. Skipped tasks (quarantined or pre-existing
block) MUST NOT emit the event — the existing
`InitiativeQuarantined` row + the prior `TaskBlockedForRecovery`
audit record (or the pre-restart operator-resume FSM history) is
the audit trail for the skip.

There is no operator opt-out at the per-restart, per-initiative,
or per-task granularity. Operators who want strict V1 fail-safe
behaviour (every kernel exit halts work for human review,
including supervisor-triggered restarts) MUST disable the
supervisor entirely (`RAXIS_SUPERVISOR_AUTO_RESTART=0`); the
supervisor opt-in is the SOLE operator surface for that choice.

**FSM contract.** The auto-resume codepath walks the same
`task_transitions::transition_task` API the operator
`task resume` IPC handler uses (`BlockedRecoveryPending →
Admitted`). The pre-sweep state is recorded on the audit event
for forensics, but the FSM transition itself always lands at
`Admitted`; the kernel re-derives the post-Admitted state via
normal scheduling. The auto-resume actor is `kernel`, not
`operator`, so audit-chain readers can mechanically distinguish
operator-initiated resumes from supervisor-initiated resumes by
the `actor` column on the `TaskStateChanged` row + the paired
`TaskAutoResumedAfterSupervisorRestart` event.

**Order rationale.** The auto-resume sweep MUST run AFTER
`restart_lifecycle::rehydrate_restart_context` has emitted the
paired `KernelRestart{Initiated,Completed}` events (so the chain
reads left-to-right
`KernelDeadlockDetected? → KernelStarted → KernelRestartInitiated →
KernelRestartCompleted → TaskAutoResumedAfterSupervisorRestart{N}`)
and BEFORE IPC accept (so the orchestrator never observes a
transient `BlockedRecoveryPending` window — by the time the first
IPC frame arrives, every auto-resumable task is already back in
`Admitted` and the scheduler picks up exactly where it left off).

**Justification.** The supervisor's whole purpose is to recover
transparently from kernel-internal pathology — deadlock, panic,
signal-crash. The agent work itself is fine; only the kernel got
stuck. Forcing operators to manually resume every task after
every supervisor restart converts self-healing into self-
pretending: the kernel did the right thing (restart promptly +
cleanly) and the operator experiences it as the system having
**failed**. There is no realistic operator decision to add at
the per-task granularity — the kernel already knows everything
an operator would know about whether to resume (the previous
exit was an auto-restartable code; the work itself is durable in
SQLite + the audit chain). The two skip clauses preserve
explicit operator intent (quarantine = "freeze this initiative",
pre-existing BRP = "I had this paused for a reason"); both are
recorded with their own audit row before the restart, so the
operator's intent is mechanically preserved across the restart
boundary.

**Why a single operator-resume event isn't enough.** Without an
auto-resume sweep, a supervisor-triggered restart leaves every
task in `BlockedRecoveryPending` and the operator has to walk
the inbox / dashboard and manually resume each one — even though
the kernel already knows the previous exit was auto-restartable
(the supervisor said so via the sentinel + the just-emitted
`KernelRestartCompleted`). The auto-resume sweep elides that
manual ceremony for the common case (steady-state work
in-flight at the moment of the deadlock) while preserving
operator intent for the explicit-block cases.

**Witness.** Three layered tests:

* `kernel/src/recovery.rs::supervisor_auto_resume_witness::auto_resume_partitions_six_task_fixture_per_invariant`
  — FSM-level witness on a 6-task fixture across 3 initiatives
  (3 Running + 1 GatesPending + 1 pre-existing BRP +
  1 Running-on-quarantined-init). Asserts the canonical 4-2
  partition (4 resumed → `Admitted`; 1 pre-existing block stays
  at BRP; 1 quarantined task stays at BRP), asserts each
  emitted event carries the correct `prior_state` +
  `task_id` + `initiative_id`, asserts skipped tasks emit
  ZERO `TaskAutoResumed*` events, asserts the
  `supervisor_restart_id` is shared across the 4 emitted events.
* `kernel/src/recovery.rs::supervisor_auto_resume_witness::auto_resume_is_a_noop_when_recovery_sweep_was_empty`
  — short-circuit: when reconcile sweeps nothing, the auto-resume
  sweep emits nothing and reports zero in every counter.
* `kernel/tests/supervisor_auto_resume.rs` — cross-crate
  contract: pins the `TaskAutoResumedAfterSupervisorRestart`
  serde envelope shape, asserts `notification_priority` and
  `notification_priority_for_kind_str` agree on `Medium`, and
  asserts the discriminant string is in
  `raxis-policy::KNOWN_AUDIT_EVENT_KINDS` (so operator
  `[notifications.routes]` referring to it parse cleanly per
  `cli-readonly.md §5.6.2`).

**Canonical home.** `v2/self-healing-supervisor.md` §3.5
(Operator session continuity — task auto-resume).

---

### INV-DASHBOARD-JWT-SECRET-PERSISTENT-01 — Dashboard JWT secret is persisted with rotation

**Statement.** The dashboard's HS256 signing secret MUST be
persisted to `<data_dir>/auth/dashboard_jwt.secret` whenever
the dashboard is constructed with a configured `data_dir`
(every production kernel boot). The on-disk file MUST:

1. Hold `{schema_version, generation, secret_hex,
   updated_at_unix_secs}` as JSON.
2. Be `0600` permissions on Unix; the parent `<data_dir>/auth/`
   dir MUST be `0700`.
3. Be written via `tempfile + rename` with the tempfile
   `chmod 0600` BEFORE the rename (so the canonical filename
   never transiently appears with looser perms).

The signer MUST bind `secret_generation` into every minted
JWT's `gen` claim, and `JwtSigner::verify` MUST reject any
token whose `gen` ≠ the live generation. Operators MUST be
able to invoke `raxis dashboard rotate-jwt-secret` to bump
the on-disk generation and mint a fresh secret, immediately
invalidating every pre-rotation token.

**Justification.** This invariant is the on-disk layer that
enables `INV-SUPERVISOR-OPERATOR-CONTINUITY-01`. Persistence
alone is insufficient — without a generation counter bound
into the claims, an operator who suspects a dashboard
compromise has no way to mechanically invalidate every
issued token short of waiting for the 1h TTL or deleting
the secret file by hand and restarting the kernel. The `gen`
binding gives the operator an explicit "kick everyone out"
lever (`raxis dashboard rotate-jwt-secret`) that does not
require kernel restart privilege, does not open
`operator.sock`, and does not require `--operator-key` —
because the rotation is a local file-system mutation under
the data dir, which the operator already owns. The
generation check on verify is also a defence-in-depth lane
against any future change that re-uses secret bytes (e.g. a
hypothetical KDF-from-root scheme).

**Scenario.** A forensic event reveals that a contractor
laptop with a copy of `<data_dir>` was lost. The on-call
operator runs `raxis dashboard rotate-jwt-secret` from
their workstation, sees `generation: 2` in the output. The
running kernel keeps using its in-memory secret until its
next restart (the operator schedules a `raxis-supervisor
stop`+`start` in the maintenance window 3 hours later).
During those 3 hours, every operator with a valid dashboard
session continues to work normally — their JWTs were minted
under generation 1 and the live signer is still on
generation 1. Once the kernel restarts and reloads the file
at generation 2, every pre-rotation operator's next request
fails with `InvalidJwt` and their browser bounces to
`/login`. They re-auth via challenge+sign and continue. The
JWT minted by the lost-laptop attacker (assuming they got
that far) likewise bounces.

**Witness.** Test matrix in §10.6 of
`v2/self-healing-supervisor.md`:
* `secret_file_is_0600_after_mint` (Unix) — perm contract.
* `auth_dir_is_0700_after_mint` (Unix) — perm contract.
* `rotate_bumps_generation_and_changes_secret_bytes` —
  rotation semantics.
* `jwt_rotation_invalidates_pre_rotation_tokens` — end-to-end
  rotation contract: pre-rotation token MUST fail verify
  post-rotation; post-rotation token MUST verify cleanly.
* `verify_rejects_mismatched_generation` — defence-in-depth:
  even if HMAC happens to match, mismatched `gen` is
  rejected.
* `unknown_future_field_is_silently_ignored` — forward-compat
  on the on-disk schema.

**Canonical home.** `v2/self-healing-supervisor.md` §10;
`v2/dashboard-hardening.md` §7 (persistent JWT secret
addendum).

---

## §11.13 — Observability metric coverage (INV-OBS-*)

iter44 perf-metrics expansion. Each invariant pairs a closed-set
or coverage statement with a deterministic unit-test witness so the
"what does a working live-e2e iter44 run look like in Grafana?"
reference can be programmatically asserted instead of eyeballed.

Canonical home: `v3/otel-observability.md §8` (metric catalog) +
`v3/observability-prometheus.md §3` (Prometheus naming).

### INV-OBS-RESPAWN-KIND-LABEL-01 — `IsolationRespawnAttemptedTotal` carries a closed `respawn_kind` label

**Statement.** Every emission of
`raxis.isolation.respawn_attempted.total` (the OTel-canonical name
of `MetricName::IsolationRespawnAttemptedTotal`) MUST carry a
non-empty `respawn_kind` label whose value is drawn from the closed
set `{ "vm_crash", "orchestrator_no_progress", "reviewer_rejection",
"unknown" }`. Adding a new value is a spec change to
`v3/otel-observability.md §8` AND a code change to
`kernel/src/observability.rs::RESPAWN_KIND_CLOSED_SET`.

**Justification.** The pre-iter44 metric counted every respawn under
one bucket, which made the operator dashboard unable to distinguish
"healthy retry on a transient VM spawn failure" (a sub-second
self-healing event) from "the orchestrator session keeps exiting
without making DAG progress" (a logical-deadlock pathology that
needs human attention). iter42's root-cause investigation needed
this disambiguation and had to reconstruct it after the fact from
audit-chain joins. With the closed lexicon, the dashboard panel
"Respawn rate by kind" (`grafana/dashboards/10-isolation.json`,
`id=32`) renders the three kinds as distinct stacked time-series;
zero work for the operator.

**Scenario.** Reviewer-disagreement causes the executor to be
respawned twice in quick succession. The audit chain shows
`ExecutorRespawnFromReviewRejection` (round 1) and
`ExecutorRespawnFromReviewRejection` (round 2). Without this
invariant, the dashboard shows `respawn_attempted_total` jumping by
+2 with no explanation; the operator opens the audit log to see why.
With this invariant, the dashboard's "Respawn rate by kind" panel
shows a +2 spike on the `reviewer_rejection` series, the operator
recognises it as the agent-disagreement code path, and moves on.

**Witness.** Two unit tests in
`kernel/src/observability.rs::respawn_kind_tests`:
* `every_closed_set_value_is_emitted_with_known_label` — drives
  `record_isolation_respawn_attempted` once per constant in
  `RESPAWN_KIND_CLOSED_SET`, asserts each metric carries the
  matching label.
* `closed_set_matches_spec_table` — pins the four constants
  enumerated in this invariant.

**Canonical home.** `v3/otel-observability.md §8` (Metric Catalog
row for `IsolationRespawnAttemptedTotal`).

### INV-OBS-KERNEL-RESPAWN-COVERAGE-01 — Every supervisor-driven kernel respawn has a paired metric emission

**Statement.** Every `KernelRespawnedBySupervisor` audit event the
supervisor writes (via the sentinel-file → kernel-boot rehydration
path documented in `v2/self-healing-supervisor.md §3.3`) MUST be
paired with one `KernelRespawnTotal` counter increment AND one
`KernelRespawnDuration` histogram observation, both emitted from
the kernel-boot codepath the next time the kernel boots and reads
the supervisor sentinel. Symmetrically, every kernel boot that
observes a `Halted` sentinel (the operator manually bypassed the
supervisor after a circuit-open / forced-stop episode) MUST emit
one `SupervisorRefusedRestartTotal` counter increment.

The label vocabularies are CLOSED:
* `KernelRespawnTotal.trigger` ∈ `{ "deadlock", "sigsegv",
  "sigabrt", "exit_70", "other" }`.
* `KernelRespawnTotal.outcome` ∈ `{ "ok", "refused_ceiling",
  "refused_other" }`. (Today the kernel-boot path only emits `ok`;
  `refused_*` are reserved for a future supervisor-side emission
  expansion — the supervisor crate is intentionally
  observability-isolated and would have to grow a hub binding to
  emit `refused_*` directly.)
* `KernelRespawnDuration.trigger` — same closed set as above.
* `SupervisorRefusedRestartTotal.reason` ∈ `{ "circuit_open",
  "operator_stop", "operator_stop_forced", "supervisor_gone",
  "other" }`.

Adding a new value to any of these lexicons is a spec change to
`v3/otel-observability.md §8` AND a code change to
`kernel/src/observability.rs::RESPAWN_*_CLOSED_SET` /
`REFUSED_REASON_CLOSED_SET`.

**Justification.** The supervisor crate (`crates/supervisor/`) is
deliberately process-isolated from the kernel and takes ZERO
`raxis-*` dependencies — its design contract (per
`crates/supervisor/src/lib.rs` module-doc) is "spawn child /
classify exit / decide restart-or-not, with the audit chain owned
by the kernel and the sentinel file owned by the supervisor".
That single-responsibility design is load-bearing for the
crash-loop story: even a kernel-side crate-graph regression must
not be able to break the supervisor's ability to spawn the kernel.
Keeping the supervisor observability-isolated mirrors that
constraint: the operator dashboard's "Self-healing supervisor"
panels are fed by the kernel-side rehydration path, which is the
structural witness for every supervisor-driven restart episode
(the kernel cannot boot WITHOUT reading the sentinel; reading the
sentinel is what produces the metric).

Pre-iter44 the audit chain was the only operator-visible record of
self-healing activity. Operators who wanted "what is the kernel
respawn rate over the last hour?" had to grep the audit chain or
write SQL against the supervisor's circuit-breaker file. The
dashboard panel "Self-healing supervisor" in
`grafana/dashboards/00-overview.json` (rows 31, 32, 33) renders
the rate-by-trigger, latency p50/p95/p99, and refused-restart rate
without operator-side joins.

**Scenario.** A canonical-images preflight regression sends the
kernel into a tight crash-loop on every boot. The supervisor
restarts it three times in 30 seconds, then trips its circuit
breaker and writes `Halted (CircuitOpen)`. The operator notices
their CLI commands hanging, logs in, sees the `Halted` sentinel,
and starts the kernel directly (`raxis-kernel` instead of
`raxis-supervisor`) to investigate. With this invariant:

  1. The first three boots each emit one `KernelRespawnTotal{
     trigger="deadlock", outcome="ok"}` increment and one
     `KernelRespawnDuration{trigger="deadlock"}` observation
     (the supervisor sentinel was `Restarting` each time).
  2. The fourth boot — operator-bypassed — emits one
     `SupervisorRefusedRestartTotal{reason="circuit_open"}`
     increment.

The dashboard's "Kernel respawn rate by trigger" panel shows a
+3 spike on the `deadlock` series; "Supervisor refused-restart
rate" shows a +1 on `circuit_open`. The operator immediately
recognises the pattern (deadlock → circuit-trip → manual bypass)
without opening the audit log or the supervisor's stderr file.

**Witness.** Five unit tests in
`kernel/src/observability.rs::kernel_respawn_tests`:
* `every_trigger_outcome_pair_emits_paired_metrics` — drives
  `record_kernel_respawn` once per (trigger, outcome) pair drawn
  from the closed lexicons and asserts both the counter and the
  histogram observation land with the matching labels and that
  the histogram uses the iter44 wide-bucket override (not the
  hub's global default).
* `missing_duration_emits_counter_only` — covers the older
  supervisor binary case (sentinel does not surface
  `last_restart_unix_ts`); only the counter fires.
* `closed_sets_match_spec_tables` — pins the trigger / outcome /
  reason lexemes against this invariant text.
* `classify_respawn_trigger_is_total_and_in_closed_set` — pins
  the supervisor `last_restart_reason` × `prev_run_exit_code` →
  `trigger` mapping table verbatim from this invariant.
* `supervisor_refused_reason_is_total_and_in_closed_set` — pins
  the supervisor sentinel `sub_state` → `reason` mapping.
* `refused_restart_emits_counter` — drives every
  `REFUSED_REASON_CLOSED_SET` value through
  `record_supervisor_refused_restart`, asserts the counter and
  the closed-set membership of the `reason` label.

**Canonical home.** `v3/otel-observability.md §8` (Metric Catalog
rows for `KernelRespawnTotal` / `KernelRespawnDuration` /
`SupervisorRefusedRestartTotal`) + cross-ref from
`v2/self-healing-supervisor.md §9`.

### INV-OBS-OPERATOR-IPC-COVERAGE-01 — Every operator IPC dispatch is paired with one counter increment + one duration sample

**Statement.** Every operator IPC frame the kernel dispatches in
`kernel/src/ipc/operator.rs::dispatch_loop` MUST emit exactly one
`OperatorIpcTotal` counter increment AND exactly one
`OperatorIpcDuration` histogram observation, both labelled with the
same `command_kind` and `accepted` values. Coverage is one-to-one:
`rate(OperatorIpcTotal[5m]) == rate(OperatorIpcDuration[5m])` per
`(command_kind, accepted)` series.

The label vocabularies are CLOSED:
* `command_kind` — every `OperatorRequest` variant in
  `raxis_types::operator_wire`, projected to `snake_case`. The
  closed set is pinned by
  `kernel/src/observability.rs::COMMAND_KIND_CLOSED_SET` and the
  total-mapping helper `operator_command_kind` whose match arm is
  exhaustive over the wire enum (the compiler enforces the
  invariant at every variant-addition refactor).
* `accepted` — `Bool`. `false` iff the response is
  `OperatorResponse::Error` (the sole error envelope per
  `peripherals.md §3 "Operator socket"`); `true` for every other
  response variant including `Ack`. The boolean projection is
  pinned by `operator_response_accepted`.

**Justification.** Operator UDS dispatch is the single entry point
for every operator-driven kernel mutation: `CreateInitiative`,
`ApprovePlan`, `RotateEpoch`, `QuarantineInitiative`,
`ApproveEscalation`, etc. Pre-iter44 the operator-visible signals
were the structured stderr log line emitted by
`dispatch_log::op_response` and the audit-chain entry — both
durable, neither pivot-able into a Grafana panel. The "accepted vs
rejected per command" panel on the new `15-ipc.json` dashboard
(slice 4b) is the operator's first dashboard view of "is the
operator socket healthy and what commands are getting rejected
right now". Pinning the rate equality between counter and histogram
also gives the dashboard PromQL surface a structural redundancy:
if either series silently drops sampling (sample-rate change, hub
disabled per-environment), the operator sees the divergence
immediately.

**Scenario.** A misconfigured CLI build retries `ApprovePlan` with
a wrong-epoch signature. The kernel's plan-approval handler
returns `OperatorResponse::Error { code: "FAIL_APPROVE_PLAN",
detail: "epoch mismatch" }`. With this invariant:

  1. `OperatorIpcTotal{command_kind="approve_plan",
     accepted="false"}` increments by 1.
  2. `OperatorIpcDuration{command_kind="approve_plan",
     accepted="false"}` observes the dispatch latency.
  3. The dashboard's "Operator IPC: rate by command_kind" panel
     shows the spike on the `approve_plan` series; the "accepted
     vs rejected" panel shows the rejection rate climbing.
  4. The operator pivots from the rejection rate to the structured
     stderr log (which already carries the same `command_kind` /
     `code` / `detail` fields) and resolves the bad CLI build.

Without the metric, the operator's only signal is the audit log —
which is durable but not real-time-pivot-able from a Grafana
dashboard.

**Witness.** Four unit tests in
`kernel/src/observability.rs::operator_ipc_tests`:

* `every_variant_emits_paired_metrics` — drives one fixture
  instance per `OperatorRequest` variant through
  `operator_command_kind` and asserts both the counter and the
  histogram observation land with the matching labels and the
  iter44 wide-bucket override (not the hub'''s global default).
* `rejected_response_emits_accepted_false` — pins the `accepted =
  false` polarity for `OperatorResponse::Error` so a future
  refactor cannot silently invert it.
* `closed_set_matches_op_name_table` — pins the closed lexicon
  against the `operator_command_kind` projection in both
  directions: every variant produces a closed-set value, and
  every closed-set value (except `unknown`) is reachable from at
  least one variant.
* `response_accepted_is_total` — pins
  `operator_response_accepted` over a representative slice of
  `OperatorResponse` variants (non-Error → true, Error → false).

The `operator_command_kind` match arm is itself a structural
witness — adding a new `OperatorRequest` variant produces a
compile error here until the variant is mapped, which forces the
closed-lexicon update to be a single PR.

**Canonical home.** `v3/otel-observability.md §8` (Metric Catalog
rows for `OperatorIpcTotal` and `OperatorIpcDuration`). Referenced
from `v3/observability-prometheus.md §3.12` (Prometheus inventory).

### INV-OBS-IPC-ROUNDTRIP-COVERAGE-01 — Every kernel↔substrate IPC frame has a paired counter + histogram + inflight emission

**Statement.** Every `IpcMessage` frame the kernel dispatcher
`kernel/src/ipc/server.rs::drive_planner_stream` consumes MUST
produce:

  1. Exactly one `KernelSubstrateIpcMessagesTotal` counter
     increment, labelled with the same closed-lexicon `(role,
     message_kind)` pair as item 2.
  2. Exactly one `KernelSubstrateIpcRoundtripDuration` histogram
     observation, with the iter44 IPC-bucket override `[1, 5, 10,
     25, 50, 100, 250, 500, 1000, 2500, 5000]` ms, recording the
     wall-clock from frame-received to response-frame-written (or,
     for the `unexpected` arm, frame-received to drop).
  3. One `KernelSubstrateIpcInflight` gauge sample with the
     post-increment count emitted BEFORE the handler runs, and
     one gauge sample with the post-decrement count emitted AFTER
     the response frame is written (or after the unexpected drop).
     The per-`role` inflight counter MUST return to its pre-frame
     baseline value once the handler completes — i.e. the
     increments and decrements pair up exactly, regardless of
     handler outcome (`Ok` return, early `?` propagation from
     `write_frame`, panic unwind).

Coverage is one-to-one across counter / histogram per
`(role, message_kind)` series: `rate(KernelSubstrateIpcMessagesTotal[5m])
== rate(KernelSubstrateIpcRoundtripDuration[5m])`. The inflight
gauge labelled by `role` is a defense-in-depth surface: at
steady state when no streams are mid-handler, every `role`
series MUST read zero.

The label vocabularies are CLOSED:
* `role` — `{ "planner", "verifier", "gateway", "unknown" }`. The
  closed set is pinned by
  `kernel/src/observability.rs::KERNEL_SUBSTRATE_IPC_ROLE_CLOSED_SET`
  and by the static-str constants the dispatcher passes to
  `KernelSubstrateIpcRoundtrip::start`. `gateway` is reserved for
  a future gateway-side dispatcher migration (slice 4c+); it is
  pinned in the closed set today so the dashboard PromQL stays
  stable when the gateway dispatcher starts emitting.
* `message_kind` — `{ "intent_request", "witness_submission",
  "escalation_request", "planner_fetch_request", "unexpected" }`.
  The lexeme is the snake_case projection of the dispatched
  `IpcMessage` request variant; every non-dispatched variant
  collapses to `unexpected` so the dashboard's "Messages by
  kind" panel can pivot on a stable set even as new wire variants
  are added. Pinned by
  `kernel/src/observability.rs::KERNEL_SUBSTRATE_IPC_MESSAGE_KIND_CLOSED_SET`
  and by the exhaustive match arm in
  `kernel_substrate_ipc_route` whose totality is enforced by the
  compiler over every `IpcMessage` variant.

**Justification.** The kernel↔substrate IPC dispatcher is the
single entry point for every planner / verifier subprocess
frame the kernel admits: intent submissions, witness submissions,
escalation requests, and the kernel-mediated gateway egress
fetches that LLM tool-calls travel over. Pre-iter44 the only
operator-visible IPC signals were the per-arm structured stderr
log lines emitted by `planner_dispatch_log::*` — durable, but not
pivot-able into a Grafana panel and impossible to alert on at the
rate / latency level.

The three metrics are the structural complement of slice 4a's
`OperatorIpcDuration` / `OperatorIpcTotal` on the operator-socket
side: together they cover every kernel UDS dispatcher the iter44
"is the kernel healthy and what is it doing right now?" view
depends on. The new `15-ipc.json` dashboard surfaces:

  * p50 / p95 / p99 round-trip latency overall and per
    `message_kind` (a tail-latency spike on `intent_request`
    indicates a kernel admission slow path; on
    `planner_fetch_request` it tracks LLM provider RTT).
  * Messages-per-second by `(role, message_kind)` — the
    dispatcher's traffic mix at a glance.
  * Inflight by `role` — a monotonically growing line is the
    leading indicator of a stuck handler (or a session leak); the
    inflight=0 baseline pinned by item 3 is the "kernel is
    quiescent" signal.
  * Unexpected-variant rate — non-zero steady-state indicates a
    wire-protocol mismatch between a substrate client and the
    kernel (e.g. a planner build that smuggles an
    `OperatorRequest` onto planner.sock).

The "regardless of handler outcome" guarantee on item 3 is
load-bearing: the RAII guard
`KernelSubstrateIpcRoundtrip` in `kernel/src/observability.rs`
emits the full metric tuple inside its `Drop` impl, so any
exit path — normal return, early `?` propagation from
`write_frame`, panic unwind — flushes the counter + histogram +
post-decrement gauge exactly once. A handler that hangs
mid-`.await` keeps the inflight counter elevated, which is
exactly the operator-visible signal the invariant promises.

**Scenario.** A planner subprocess deadlocks while awaiting a
`PlannerFetchResponse` from a misbehaving upstream LLM provider.
The provider response never arrives; the kernel's
`handlers::planner_fetch::handle` future never completes. With
this invariant:

  1. The dispatcher's `KernelSubstrateIpcRoundtrip` guard for
     this frame is still held — `Drop` has not run.
  2. `KernelSubstrateIpcInflight{role="planner"}` reads `1`
     (one frame mid-handler).
  3. The dashboard's "Inflight by role" panel shows the
     `planner` series stuck at 1 (or higher, if other planners
     also fan in).
  4. The operator pivots from the inflight gauge to the
     structured `planner_fetch_response` log (which carries
     `request_id`, `latency_ms`, `error`) to identify the
     wedged tool-call and either operator-abort the task or
     restart the gateway upstream.

Without the metric, the operator's only signal is the audit
log (which records the FetchRequest but not the timing of the
missing response) — durable but not real-time-pivot-able.

**Witness.** Four unit tests in
`kernel/src/observability.rs::substrate_ipc_tests`:

* `every_variant_maps_to_closed_lexicons` — drives one fixture
  instance per dispatched `IpcMessage` variant plus a
  representative `unexpected` variant through
  `kernel_substrate_ipc_route` and asserts each `(role,
  message_kind)` pair lies in the closed sets. The exhaustive
  match arm in `kernel_substrate_ipc_route` provides the
  compile-time totality witness over the full enum.
* `dispatched_variants_have_canonical_route` — pins the canonical
  `(role, message_kind)` pair for each of the four dispatched
  variants and the `(unknown, unexpected)` collapse for every
  other variant.
* `record_roundtrip_emits_paired_metrics` — iterates the full
  Cartesian product of the two closed sets, asserts each
  `record_kernel_substrate_ipc_roundtrip` call emits BOTH the
  counter and the histogram observation with matching labels
  and the iter44 IPC-bucket override (not the hub's global
  default).
* `raii_guard_round_trips_inflight_to_zero` — drives N (=5)
  `KernelSubstrateIpcRoundtrip::start` + `Drop` pairs and
  asserts (a) the per-role inflight counter returns to zero,
  (b) the metric tape carries exactly 2N gauge samples + N
  counters + N histograms, and (c) the final gauge sample is
  zero — pinning the RAII Drop contract end-to-end.

The `kernel_substrate_ipc_route` match arm is itself a structural
witness — adding a new `IpcMessage` variant produces a compile
error here until the variant is mapped, which forces the
closed-lexicon update to be a single PR.

**Canonical home.** `v3/otel-observability.md §8` (Metric Catalog
rows for `KernelSubstrateIpcRoundtripDuration`,
`KernelSubstrateIpcMessagesTotal`, `KernelSubstrateIpcInflight`).
Referenced from `v3/observability-prometheus.md §3.13`
(Prometheus inventory).

---

### INV-PLANNER-MAX-TURNS-PRECEDENCE-01 — Per-task `max_turns` precedence chain is mechanical

**Statement.**
The kernel MUST resolve the per-session planner hard turn ceiling
(`RAXIS_PLANNER_MAX_TURNS`) at session-spawn time via the following
precedence chain, evaluated in order, with the FIRST matching arm
winning:

1. **Per-task** — If the activating task's
   `[[tasks]].max_turns` (parsed into
   `kernel/src/initiatives/plan_registry.rs::TaskPlanFields::max_turns`)
   is `Some(c)`, the resolved value is `c` and the resolution
   `source` is `"task"`.
2. **Policy default** — Else, if
   `[gateway].planner_max_turns_default` (parsed into
   `crates/policy/src/bundle.rs::GatewaySection::planner_max_turns_default`)
   is `Some(d)`, the resolved value is `d` and the resolution
   `source` is `"policy"`.
3. **Compiled default** — Otherwise the resolved value is
   `kernel/src/initiatives/plan_registry.rs::DEFAULT_PLANNER_MAX_TURNS`
   (currently `100`) and the resolution `source` is
   `"compiled-default"`.

The kernel MUST then `insert` (orchestrator path:
`session_spawn_orchestrator::populate_planner_max_turns_env`) or
`entry().or_insert` (executor / reviewer path:
`session_spawn_orchestrator::populate_planner_max_turns_env_or_insert`)
the resolved integer into the spawned VM's env table under
[`raxis_types::planner_env::PLANNER_MAX_TURNS_ENV`]
(`RAXIS_PLANNER_MAX_TURNS`), and emit a structured `PlannerMaxTurnsResolved`
log line carrying `task_id`, `session_id`, `initiative_id`, the
resolution `source` label, and the resolved integer.

The orchestrator-spawn path passes `task_fields = None` to the
resolver (orchestrator is per-initiative, not per-task — the
per-task arm always short-circuits for orchestrator sessions),
so the orchestrator's effective ceiling is always either the
policy default or the compiled default.

The plan parser (`kernel/src/initiatives/lifecycle.rs::parse_plan_tasks`)
MUST reject `max_turns = 0` at admission with
`LifecycleError::PlanInvalid` (a 0-turn budget would terminate the
dispatch loop before the first model call and is never useful).
Negative values, non-integer values, and integer values exceeding
`u32::MAX` are also rejected by the existing
`parse_optional_u32_field` shape check.

**Justification.**
Three live-e2e iterations (iter25, iter31, iter50) reproduced the
same failure mode: a `DEFAULT_PLANNER_MAX_TURNS` calibrated for the
single hardest Executor task (`materialize-records`: 25 postgres rows
× per-row write × commit × verify) was simultaneously too tight for
that task at lower defaults AND wasteful for trivial Reviewer / single-
edit Executor tasks. Bumping the compiled default `20 → 50 → 100` to
fit the worst-case meant every Reviewer that hadn't decided in 5 turns
got a 100-turn budget, weakening the liveness backstop ("if you haven't
finished in N turns, you're stuck") for every other task. Per-task
`max_turns` lets the plan author express what they already know: this
Reviewer needs ≤ 5; this materializer Executor needs ≥ 150. The kernel
projects the resolved value into both the env stamp (in-VM dispatch
loop ceiling) and the KSB capabilities envelope (`SessionCapabilityView::planner_max_turns`,
per `INV-KSB-MAX-TURNS-VISIBILITY-01`) so the agent and the kernel
share one view of the budget.

> **Note (iter54 + iter55).** Per-task `max_turns` is the spec
> author's responsibility to size for the **worst-case**
> activation, including review-rejection retries that must
> REPAIR (not just introduce) the work. Under-sizing a task's
> `max_turns` deterministically exhausts the crash-retry budget
> on review rejection: every retry hits the same `dispatch loop
> exceeded max_turns: N` wall (exit code 4) with no progressive
> bump (per the v1 ceiling — see
> `INV-PLANNER-MAX-TURNS-PROGRESSIVE-ON-RETRY-01` for the
> kernel-side fix), the kernel logs
> `TaskFailedOnWorkerPrematureExit` → `RetrySubTask` increments
> `crash_retry_count`, and a fresh VM spawns into the same wall
> until `max_crash_retries` is hit and the task permanently
> fails.
>
> Iter54 surfaced this mode on the monolithic `lint-runner` task
> in `kernel/tests/extended_e2e_support/plan_realistic.rs`
> (mirrored at `live-e2e/examples/plan_primary.toml`): a single
> Executor session was asked to introduce-then-on-retry-repair
> lint defects across Rust + TypeScript + Python in a single
> 30-turn budget. The introduce path fit; the repair path
> deterministically did not. The iter54 one-shot fix bumped the
> monolithic ceiling `30 → 90` (3× headroom). Iter55 SUPERSEDES
> that bump with a structural split: the monolithic
> `lint-runner` is gone, replaced by three per-language children
> (`lint-runner-python`, `lint-runner-rust`, `lint-runner-js`)
> each scoped to ONE language tree and sized at `max_turns = 60`
> — 8× per-language headroom on introduce, 2-3× on repair,
> further elasticated on retry by the Fix 2 progressive bump
> (`INV-PLANNER-MAX-TURNS-PROGRESSIVE-ON-RETRY-01` —
> `base + (attempt-1) * step`, default `step = base/2`; retry #1
> on a 60-turn task yields 90, retry #2 yields 120). The dual-
> Reviewer disagreement pair is pinned to `lint-runner-python`
> (the upstream `lint-defect` prompt is correspondingly pinned
> to the Python F401 unused-import target — per-language
> children only see their own language's lint, so for the
> disagreement aggregation to fire deterministically the defect
> must live in the language whose child carries the pair); the
> Rust and JS children carry single rubber-stamp Reviewers each.
> Iter55 also bumped sibling tight budgets in the same plan as a
> defensive sweep: `lint-defect` 25 → 35,
> `allowlist-positive-codegen` 15 → 25,
> `credential-substitution-canary` 25 → 40, every Reviewer task
> 10 → 30.

**Witness tests:**
* `kernel/src/session_spawn_orchestrator.rs::tests::inv_planner_max_turns_precedence_01_per_task_wins_over_policy`
* `kernel/src/session_spawn_orchestrator.rs::tests::inv_planner_max_turns_precedence_01_policy_wins_over_compiled`
* `kernel/src/session_spawn_orchestrator.rs::tests::inv_planner_max_turns_precedence_01_compiled_default_when_both_absent`
* `kernel/src/session_spawn_orchestrator.rs::tests::inv_planner_max_turns_precedence_01_orchestrator_path_ignores_task_arm`
* `kernel/src/session_spawn_orchestrator.rs::tests::inv_planner_max_turns_compiled_default_matches_planner_core` (pins the kernel-side `DEFAULT_PLANNER_MAX_TURNS` constant against `raxis_planner_core::DEFAULT_PLANNER_MAX_TURNS`)
* `kernel/src/initiatives/lifecycle.rs::tests::inv_planner_max_turns_precedence_01_parser_rejects_zero`
* `kernel/tests/extended_e2e_support/multi_initiative.rs::tests::sibling_plan_toml_carries_max_turns_150` (iter52 parity guard: the Rust source-of-truth `sibling_plan_toml()` MUST declare `max_turns = 150` for the sibling materializer so the kernel resolves it via `source=task` rather than `source=compiled-default=100`, mirroring the primary plan's `materialize-records` budget)

**Enforcement sites:**
* `kernel/src/session_spawn_orchestrator.rs::resolve_planner_max_turns_for` — the resolver
* `kernel/src/session_spawn_orchestrator.rs::populate_planner_max_turns_env` — orchestrator env stamp + log
* `kernel/src/session_spawn_orchestrator.rs::populate_planner_max_turns_env_or_insert` — executor / reviewer env stamp + log
* `kernel/src/initiatives/lifecycle.rs::parse_plan_tasks` — `max_turns = 0` rejection
* `kernel/src/initiatives/plan_registry.rs::TaskPlanFields::effective_max_turns` — pure resolution helper called by the resolver

**Canonical home.** `v2/v2-deep-spec.md §Step 12` (planner-harness
ceiling resolution); `guides/recipes/env/11-planner-env-vars.md`
(operator-facing recipe); `guides/recipes/policy/06-budget-section.md`
(policy-side default).

---

### INV-KSB-MAX-TURNS-VISIBILITY-01 — KSB carries the resolved per-session `planner_max_turns`

**Statement.**
For every planner session the kernel spawns, the
`raxis_ksb::SessionCapabilityView::planner_max_turns` field on the
session's KSB capabilities envelope MUST equal the resolved
`RAXIS_PLANNER_MAX_TURNS` value the kernel stamped into the spawned
VM's env table (per `INV-PLANNER-MAX-TURNS-PRECEDENCE-01`). Both
fields MUST come from a SINGLE call to
`session_spawn_orchestrator::resolve_planner_max_turns_for(...)` so
they are bit-equal by construction; reading the resolution arm twice
(once for the env stamp, once for the KSB) is forbidden because the
underlying inputs (`TaskPlanFields::max_turns`,
`GatewaySection::planner_max_turns_default`) could in principle change
between reads on a hot policy-rotate.

The KSB renderer
(`crates/ksb/src/lib.rs::push_session_capability_line`) MUST emit
the `planner_max_turns=N` token on the `role=…` line of the rendered
capabilities block for ALL three role envelopes (orchestrator,
executor, reviewer) — the token's presence is a positive structural
signal the agent can rely on; absence indicates a renderer regression
or an old kernel version (which the agent is permitted to refuse).

**Justification.**
The agent's only authoritative source of state is the KSB the driver
deserialises at boot and folds into the system prompt. The agent does
not have direct visibility into its own process env; surfacing
`planner_max_turns` only via `RAXIS_PLANNER_MAX_TURNS` would mean the
agent could not see its own budget without a separate IPC round-trip.
Including the resolved value in the per-session capabilities block
gives the agent the BUDGET; the agent's own internal turn counter
(driver-tracked, see `crates/planner-core/src/dispatch.rs::Dispatcher::run`'s
`for turn in 0..self.config.max_turns`) gives the SPENT count.
Computing `remaining = planner_max_turns - turn_index` is then trivial
inside the dispatch loop, and the role NNSPs instruct the agent to
self-regulate against this remaining count (e.g. an Executor that has
spent >75% of its budget on a single coherent edit should prefer
`task_complete` over speculative further investigation).

**Witness tests:**
* `kernel/src/initiatives/ksb_assembly.rs::tests::inv_ksb_max_turns_visibility_01_session_view_carries_resolved_value`
* `kernel/tests/ksb_capabilities_role_scoped.rs::inv_ksb_max_turns_visibility_01_all_three_roles_carry_planner_max_turns`
* `crates/ksb/src/lib.rs::tests::inv_ksb_max_turns_visibility_01_renderer_emits_planner_max_turns_for_all_roles`

**Enforcement sites:**
* `crates/ksb/src/lib.rs::SessionCapabilityView::planner_max_turns` — the field
* `kernel/src/initiatives/ksb_assembly.rs::assemble_capabilities` — the assembler that populates the field from `KsbInputs::planner_max_turns`
* `kernel/src/session_spawn_orchestrator.rs` (orchestrator + executor spawn paths) — the spawn-site bridge that calls `resolve_planner_max_turns_for(...)` once and threads the result into BOTH the env stamp and `KsbInputs`
* `crates/ksb/src/lib.rs::push_session_capability_line` — the renderer that emits the `planner_max_turns=N` token

**Canonical home.** `v2/v2_extended_gaps.md §2.4` (KSB schema);
`v2/v2-deep-spec.md §Step 12` (planner-harness ceiling resolution).

---

### INV-PLANNER-MAX-TURNS-PROGRESSIVE-ON-RETRY-01 — Per-task `max_turns` scales by `step` on each crash retry

**Statement.**
On every per-task planner-VM spawn the kernel computes the
**effective** per-attempt `max_turns` budget as

    effective = min(base + (attempt - 1) * step, hard_ceiling)

where:

* `base` is the resolved per-task `max_turns` (per
  `INV-PLANNER-MAX-TURNS-PRECEDENCE-01`: per-task →
  `[gateway].planner_max_turns_default` → compiled default).
* `step` is the resolved per-task `max_turns_step` (precedence:
  per-task `[[tasks]].max_turns_step` →
  `[gateway].planner_max_turns_step_default` → derived default
  `max(round_up_to_5(base / 2), 10)`).
* `attempt` is `subtask_activations.crash_retry_count + 1` for the
  task being spawned, sourced from the most-recent activation row.
  `attempt = 1` is the first spawn (no prior crash) — the resolver
  is a no-op (`effective = base`) on attempt 1 by construction.
* `hard_ceiling` is the runtime ceiling clamp — default 240,
  overridable via the `RAXIS_PLANNER_MAX_TURNS_HARD_CEILING` env
  var read at kernel boot. Values `<= 0` or unparseable values
  silently degrade to the compiled default (operator typos do not
  fail-close the spawn).

Both the spawned VM's `RAXIS_PLANNER_MAX_TURNS` env stamp AND the
KSB capabilities envelope's `planner_max_turns` /
`max_turns_scaling` fields MUST come from a SINGLE call to
`session_spawn_orchestrator::resolve_planner_max_turns_for(task_fields,
gateway, attempt)`. The KSB scaling view is shipped only on the
orchestrator + executor envelopes; the reviewer envelope MUST omit
it (role-scoping rule per
`INV-KSB-CAPABILITIES-ROLE-SCOPED-01`).

`[[tasks]].max_turns_step = 0` MUST fail admission at the plan
parser (`parse_plan_tasks` in
`kernel/src/initiatives/lifecycle.rs`) — a zero step degenerates
the resolver back to a constant budget and masks the cold-start
retry tax this knob exists to absorb.

When `attempt > 1` the kernel MUST emit the
`PlannerMaxTurnsProgressivelyScaled` audit event with the
(`base`, `step`, `attempt`, `effective`, `hard_ceiling`) tuple so
the dashboard's "why-did-this-budget-change" timeline reflects the
spawn-site decision verbatim. The companion
`PlannerMaxTurnsResolved` structured-log line on stderr MUST carry
the same five numeric fields so operators grepping the kernel log
have parity with the audit chain.

**Justification.**
Production telemetry from iter54/iter55 shows the dominant
crash-retry failure mode is "executor ran out of turns mid-edit on
attempt 2 with the same budget that failed on attempt 1". A
fixed-budget retry asks the same agent to do the same work with
the same scratch, which is not what the operator wants — a retry
that doesn't add resources is just a re-run with a different
random seed. Progressive scaling gives the kernel a structural
defense-in-depth lever: when a crash retry fires the kernel knows
the prior attempt under-budgeted itself, and the new attempt gets
a larger turn budget without operator intervention.

The hard ceiling clamp exists so a misconfigured plan that
declares (say) `max_turns = 1000, max_turns_step = 1000` cannot
inflate the budget unboundedly — the kernel-side clamp keeps the
per-attempt cost bounded even when the operator's TOML is wrong.

**Witness tests:**
* `kernel/src/session_spawn_orchestrator.rs::tests::inv_progressive_max_turns_base_30_step_30_three_attempts`
* `kernel/src/session_spawn_orchestrator.rs::tests::inv_progressive_max_turns_clamps_at_hard_ceiling`
* `kernel/src/session_spawn_orchestrator.rs::tests::inv_progressive_max_turns_derived_step_default`
* `kernel/src/session_spawn_orchestrator.rs::tests::inv_progressive_max_turns_derived_step_min_10`
* `kernel/src/session_spawn_orchestrator.rs::tests::inv_progressive_max_turns_policy_step_default_wins_over_derived`
* `kernel/src/session_spawn_orchestrator.rs::tests::inv_progressive_max_turns_per_task_step_wins_over_policy`
* `kernel/src/initiatives/lifecycle.rs::tests::inv_planner_max_turns_progressive_on_retry_01_parser_rejects_zero_step`
* `kernel/src/initiatives/lifecycle.rs::tests::inv_planner_max_turns_progressive_on_retry_01_parser_admits_one_step`
* `kernel/src/initiatives/lifecycle.rs::tests::inv_planner_max_turns_progressive_on_retry_01_parser_admits_omitted_step`
* `kernel/tests/ksb_capabilities_role_scoped.rs::inv_planner_max_turns_progressive_on_retry_01_role_scoped`

**Enforcement sites:**
* `kernel/src/session_spawn_orchestrator.rs::resolve_planner_max_turns_for` — the resolver
* `kernel/src/session_spawn_orchestrator.rs::resolve_planner_max_turns_step_for` — step resolver + derived-default
* `kernel/src/session_spawn_orchestrator.rs::resolve_planner_max_turns_hard_ceiling` — env override + compiled default
* `kernel/src/session_spawn_orchestrator.rs::read_crash_retry_count_for_task` — attempt derivation
* `kernel/src/session_spawn_orchestrator.rs::maybe_emit_planner_max_turns_scaled_audit` — audit emit guard
* `kernel/src/session_spawn_orchestrator.rs::log_planner_max_turns_resolved` — stderr structured log
* `kernel/src/initiatives/plan_registry.rs::TaskPlanFields::max_turns_step` — schema
* `kernel/src/initiatives/lifecycle.rs::parse_plan_tasks` — `Some(0)` rejection at admission
* `crates/policy/src/bundle.rs::GatewaySection::planner_max_turns_step_default` — per-policy default
* `crates/audit/src/event.rs::AuditEventKind::PlannerMaxTurnsProgressivelyScaled` — audit variant
* `crates/ksb/src/lib.rs::MaxTurnsScalingView` — KSB wire shape
* `crates/ksb/src/lib.rs::push_max_turns_scaling_line` — KSB renderer
* `kernel/src/initiatives/ksb_assembly.rs::assemble_capabilities` — role-scoped projection

**Canonical home.** `v2/v2-deep-spec.md §Step 12` (planner-harness
progressive ceiling resolution); `v2/planner-harness.md`
(progressive scaling section); `guides/recipes/policy/06-budget-section.md`
(policy-side `planner_max_turns_step_default`);
`guides/recipes/env/11-planner-env-vars.md`
(`RAXIS_PLANNER_MAX_TURNS_HARD_CEILING` override).

---

## §11.14 — Grafana provisioning lifecycle (INV-GRAFANA-*)

The extended-e2e observability stack stands or falls on a single
container-runtime contract: when Grafana starts, the YAML files
under `raxis/observability/grafana/provisioning/` are picked up
and applied. There is no Grafana-side reload API for datasources
in 11.x — the only deterministic moment to assert provisioning
state is "after `docker compose up --wait` returns." iter52's
metrics validator flagged a regression in exactly this surface
(operator reported empty dashboards because the wrong admin
credentials returned a misleading view, attributing an auth
problem to a provisioning failure). This invariant pins the
contract mechanically so no future drift — in the YAML, in the
compose mount paths, or in the datasource URL — can slip into
main without breaking the witness.

### INV-GRAFANA-DATASOURCE-PROVISIONED-AT-STACK-UP-01 — Grafana auto-provisions the Prometheus datasource + every raxis dashboard at stack-up

**Statement.** After `docker compose -p raxis-live-e2e-test -f
raxis/live-e2e/docker-compose.extended.e2e.yml up -d --wait`
returns successfully, Grafana on `http://127.0.0.1:3000` MUST
satisfy all four sub-properties below. Each is independently
assertable from the Grafana HTTP API by an operator probe armed
with the canonical admin credentials (`admin` /
`GF_SECURITY_ADMIN_PASSWORD` — pinned in the compose env block
to `raxis-e2e` and to be rotated only in lock-step with the
witness):

  1. **Datasource registration.** `GET /api/datasources` MUST
     return a JSON array containing a single entry with
     `uid == "prometheus"`, `type == "prometheus"`,
     `access == "proxy"`, `url == "http://prometheus:9090"`,
     `isDefault == true`, `readOnly == true`. The URL host
     `prometheus` is the compose service name — the kernel of
     the gotcha: `127.0.0.1` and `localhost` inside the Grafana
     container resolve to Grafana itself and silently break every
     panel query without breaking datasource registration.
  2. **Dashboard provisioning.** `GET
     /api/search?type=dash-db&folderUIDs=raxis` MUST return
     exactly eleven entries, with the uid set
     `{raxis-00-overview, raxis-10-isolation, raxis-15-ipc,
     raxis-20-lifecycle, raxis-30-audit, raxis-40-planner,
     raxis-50-credproxies, raxis-60-egress, raxis-70-dashboard,
     raxis-80-budget-reviewer, raxis-90-git}`. The count and the
     uid set are both load-bearing: a drift in either signals a
     dashboard provider misconfiguration or a renamed
     dashboard JSON whose uid doesn't match its
     `provisioning/dashboards/raxis.yaml` path.
  3. **Overview fetchability.** `GET
     /api/dashboards/uid/raxis-00-overview` MUST return a
     dashboard envelope whose `dashboard.title` field contains
     `"00 Overview"`. This is the canonical "home" dashboard
     (`GF_DEFAULT_HOME_DASHBOARD_PATH: /var/lib/grafana/dashboards/00-overview.json`)
     — if it can't be fetched by uid, anonymous browser landing
     is broken too.
  4. **Proxy query.** `GET
     /api/datasources/proxy/uid/prometheus/api/v1/query?query=up`
     MUST return `{"status":"success", ...}` with at least one
     series in `data.result`. This is the end-to-end witness
     that the datasource URL actually resolves to a running
     Prometheus: registration without working query proxy is
     the failure mode §3.1 of `recipes/ops/19-grafana-datasource-provisioning.md`
     calls out specifically.

**Justification.** Eleven raxis dashboards (`00-overview` through
`90-git`) all pin `datasource.uid = "prometheus"` in their panel
queries — this uid is the single contract between the dashboard
JSONs and the datasource YAML. A drift in any of:

  * the datasource YAML (missing `apiVersion: 1`; key casing
    `isDefault` vs `is_default`; deprecated `access: direct`;
    URL host typo),
  * the bind mount in the compose file
    (`../observability/grafana/provisioning:/etc/grafana/provisioning:ro`
    — relative to the compose file's directory, not the caller's
    cwd; macOS Docker Desktop has been known to silently drop
    bind mounts when the host path carries a `com.apple.*`
    xattr), or
  * the dashboard provider YAML
    (`provisioning/dashboards/raxis.yaml` — `path:` typo,
    `orgId:` drift, removed `apiVersion: 1`),

manifests as "Grafana UI is up, but every panel says No data" —
a symptom that is impossible to distinguish from "Prometheus
has no metrics yet" without poking the four API endpoints
above. The validator that flagged iter52's P0 ALSO hit a
related-but-distinct gotcha: `GF_AUTH_ANONYMOUS_ENABLED: "true"`
+ `GF_AUTH_ANONYMOUS_ORG_ROLE: Viewer` means `GET
/api/datasources` succeeds without ANY credentials (returning
the Viewer's view, which is the same as the admin's view for
the datasource list), so an auth-misconfigured probe that
expected a 401 and got a 200 with what looked like an empty
list led the validator to attribute the symptom to provisioning
when no provisioning regression existed. The witness asserts
the strict positive shape so neither the auth path nor the
provisioning path can be the silent cause of a false report.

**Scenario.** A contributor edits
`raxis/observability/grafana/provisioning/datasources/prometheus.yaml`
to change `url: http://prometheus:9090` to `url:
http://localhost:9090` while debugging a Prometheus
configuration issue locally. They forget to revert before
pushing. The datasource still REGISTERS at stack-up (Grafana
does not probe the URL during provisioning); the operator opens
the overview dashboard and every panel reads `No data`.
Without this invariant, the operator's first hypothesis is
"Prometheus isn't scraping" — they spend twenty minutes
poking at the OTel collector and scrape configs before
finding the YAML drift. With this invariant + witness, the
sub-property §1.url check fails on the next CI run (or local
pre-commit) with `datasource.url mismatch want=http://prometheus:9090
got=http://localhost:9090` — root cause localized in seconds.
The §4 proxy query is the defense-in-depth: a future URL drift
to a syntactically-plausible-but-wrong host would still pass
the §1 string check if someone updated the witness's expected
URL without thinking, but the §4 proxy query catches it
because the resulting fetch fails.

**Witness.** The shell script
`raxis/live-e2e/witness/inv_grafana_datasource_provisioned_at_stack_up_01.sh`:

* `--bounce` mode runs `docker compose down -v` (wiping the
  named `grafana_data` volume so provisioning runs against a
  fresh Grafana DB), then `up -d --wait`, then verifies — this
  is the canonical CI-gate / pre-commit form of the witness.
* Default mode (no `--bounce`) probes whatever stack is
  currently up — useful when an operator wants a fast read-only
  check without disturbing in-flight state.
* Twenty-two checks across the four sub-properties (§1 — 7
  datasource fields, §2 — 12 dashboard checks (count + each
  uid), §3 — title substring, §4 — proxy status + non-empty
  result).
* Exit 0 ⇔ invariant HOLDS; exit 1 ⇔ at least one check failed
  (every failure line in stderr names the field, the expected
  value, and the observed value); exit 2 ⇔ prerequisites
  missing (`curl`/`jq`/`docker`) or stack not up.

**Canonical home.** `v3/observability-prometheus.md §4`
(Grafana dashboards) — the dashboards-and-datasource contract
description. Operator-facing recipe:
`guides/recipes/ops/19-grafana-datasource-provisioning.md`
(canonical YAML + the six known gotchas + the witness
invocation).

---

## §11.14 — Dashboard credential viewer completeness (INV-DASHBOARD-CREDENTIAL-VIEWER-*)

V3 (iter53) adds two invariants tightening the dashboard's
credential-viewer surface so an operator with at least the
`read` role can audit every credential the kernel uses, and
so the reveal action is never a silent no-op.

### INV-DASHBOARD-CREDENTIAL-VIEWER-LISTS-ALL-OPERATOR-VISIBLE-SECRETS-01 — Every credential the kernel uses appears in the dashboard list, scoped by role

**Statement.** Every credential the kernel resolves at runtime —
per-initiative proxies declared in plan TOML AND system-wide
provider credentials under `<data_dir>/providers/*.toml`
(Anthropic, OpenAI, …) — MUST appear in the dashboard
credential-viewer's listing wire (`GET
/api/initiatives/:id/credentials` or `GET
/api/system/credentials`) for any authenticated operator
carrying at least the `read` role. Plaintext is never on the
listing wire; the metadata MUST include the credential name,
proxy / kind, format hint, byte size, SHA-256 prefix,
on-disk path, `is_revealable`, and `reveal_required_role`
fields so an operator can audit the surface area without
reading the kernel host's disk.

**Justification.** A credential the kernel uses but the
dashboard hides is a forensic blind spot — the operator has
no way to confirm that the planner's LLM provider key is
the one the policy intended, that an old test fixture
hasn't been left in `<data_dir>/providers/`, or that a
gateway-bound credential isn't quietly being read on every
session spawn. The dashboard is the operator's single
window onto the kernel's credential surface; if a
credential is reachable from the kernel but not from the
dashboard, the operator is forced to ssh into the host and
`ls /var/raxis/providers/`, defeating the principle that
the operator workstation is the only privileged surface.

**Scenario.** A planner agent makes Anthropic API calls every
turn during iter53. The operator opens the dashboard
expecting to confirm WHICH key the kernel is using
(test-only, prod, recently rotated, …) but the credential
viewer hides system credentials from `read` operators
entirely; the planner key is invisible. The operator
escalates to `admin` and only then discovers
`providers/anthropic-realism-e2e.toml` — a delay that turns
a 30-second sanity check into a five-minute flow.
With this invariant + witness, the listing wire returns
the Anthropic credential's metadata to any `read` operator
and the operator confirms the source path on the first
page load.

**Witness.**
`raxis/crates/dashboard/tests/credentials_integration.rs::list_system_credentials_metadata_visible_to_read_role`
boots the dashboard server, registers a `read`-role operator,
seeds an `InMemoryDashboardData` with a `providers.anthropic`
fixture, and asserts that `GET /api/system/credentials` returns
200 + a body containing `providers.anthropic` + NO plaintext.
A second witness
(`crates/dashboard/src/routes/credentials.rs::tests::list_system_metadata_visible_to_read_role`)
exercises the same contract at the route handler level. The
in-tree `<CredentialsView>` test
(`raxis/dashboard-fe/src/test/credentials-view.test.tsx::"renders the system-credential listing as a read operator (Anthropic visible)"`)
pins the FE rendering side: a read operator on the System
Credentials page sees the Anthropic row + a `read-only`
header pill.

**Canonical home.**
`specs/v2/dashboard-hardening.md §2.7.1` (listing surfaces +
role gate) and `specs/v2/secrets-model.md §5.1` (operator-
visible inventory bullet).

### INV-DASHBOARD-CREDENTIAL-REVEAL-PLAINTEXT-WORKS-OR-EXPLAINS-01 — A reveal click either succeeds or denies cleanly with an audit row

**Statement.** When an operator clicks "Reveal plaintext" on
any credential row in the dashboard credential viewer, the
system MUST take exactly one of these two paths:

1. **Granted.** Return the decrypted value AND emit a paired
   `OperatorRevealedCredential` (per-initiative, severity
   `high`) or `OperatorRevealedSystemCredential` (system,
   severity `critical`) audit row with `outcome = "Accepted"`
   BEFORE the response leaves the kernel AND update the UI to
   display the plaintext inside an auto-hiding Monaco viewer
   (`INV-DASHBOARD-CREDENTIAL-AUTO-HIDE-01`).
2. **Denied.** Return a structured 4xx with a stable error
   code (`FAIL_DASHBOARD_FORBIDDEN`,
   `FAIL_DASHBOARD_RATE_LIMITED`,
   `FAIL_DASHBOARD_NOT_FOUND`,
   `FAIL_DASHBOARD_CREDENTIAL_NOT_REVEALABLE`, …) AND emit
   the same paired audit row with `outcome = "RejectedPermission"`
   / `RejectedValidation` / `RejectedPolicy` AND render the
   error inline in the FE (the row's state machine
   transitions to `error` and shows a dismissable banner).

**Silent failure is forbidden.** A click MUST NOT result in
any of: (a) the button doing nothing visible, (b) no audit
row being written, (c) a 5xx that the operator has no way
to attribute. The non-revealable-credential branch
(`is_revealable=false`) is the one path that does NOT
round-trip — the kernel cannot satisfy that request under
any role — and instead surfaces an inline local
explanation pointing at the on-disk path.

**Justification.** The reveal action is the highest-stakes
operator action the dashboard exposes (it materializes a
live secret in the operator's browser). A silent failure
mode — the iter53 bug where the button was HTML-`disabled`
for `read` operators, so clicks were swallowed by the
browser before the handler ran — leaves the operator with
no signal at all: no UI change, no audit row, no console
error. They cannot tell whether the kernel rejected the
request, the network dropped, the JWT expired, or the
button is broken. The contract here pins three properties:
every click produces UI feedback within ~1 s; every click
either grants or denies (no third "did nothing" outcome);
every denial appears in the audit chain so a forensic
walker reconstructs the attempt.

**Scenario.** A `read`-role operator clicks "Reveal
plaintext" on the Anthropic credential. Pre-fix: the
button is disabled; the click is swallowed by the browser;
the operator stares at an unchanging UI and cannot tell
whether the kernel rejected, the action is unsupported, or
the FE is broken. Post-fix: the click round-trips to
`POST /api/system/credentials/providers.anthropic/reveal`;
the kernel emits `OperatorRevealedSystemCredential
{ severity: "critical", outcome: "RejectedPermission" }`;
the response is 403 with code `FAIL_DASHBOARD_FORBIDDEN`
and message `this action requires the "admin" role`; the
FE renders the inline error banner; the audit chain
records the denied attempt against the operator's
fingerprint. A subsequent admin operator reviewing the
audit chain sees both the denied attempt and (if they
proceed) their own granted reveal.

**Witness.** Two integration tests in
`raxis/crates/dashboard/tests/credentials_integration.rs`
pin the contract:

* `reveal_initiative_credential_rejects_read_role_with_403_and_audits`
  — initiative-scope deny path (existing).
* `reveal_system_credential_read_role_returns_403_with_audited_denial`
  — system-scope deny path (new in iter53): asserts 403 + a
  paired `OperatorRevealedSystemCredential { severity:
  "critical", outcome: "RejectedPermission" }` audit row.

The FE side is pinned by
`raxis/dashboard-fe/src/test/credentials-view.test.tsx::"round-trips the reveal click as a read operator and renders the kernel-audited 403 inline"`,
which asserts the button is NOT HTML-disabled (so clicks
reach the handler), a click as a read operator fires the
POST exactly once, the modal does NOT open (it would gate
plaintext that's never coming), and the structured 403 is
rendered inline. A companion test
(`"surfaces the local explanation when the credential
itself is non-revealable"`) pins the
`is_revealable=false` branch — no round-trip, local
explanation only.

**Canonical home.**
`specs/v2/dashboard-hardening.md §2.7.5` (frontend contract +
round-trip-on-deny) and `specs/v2/secrets-model.md §5.1`
(explicit-reveal bullet).

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
| **Recovery is deterministic from durable state** | INV-05 (reproducibility) + INV-INIT-08 (gate progress recoverable) + INV-INIT-05 (BlockedRecoveryPending requires operator — generic crash-recovery fork) + INV-SUPERVISOR-AUTO-RESUME-ON-CLEAN-RESTART-01 (supervisor-aware fork auto-resumes with two explicit skip clauses) + INV-STORE-01/02 (atomic transactions) |
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
| **Secrets model is structurally sound against an adversarial LLM** | INV-SECRET-01 (operators never place raw secrets in worktrees) + INV-SECRET-02 (resolution host-side) + INV-SECRET-03 (proxy is the only egress path) + INV-SECRET-04 (no LLM-compliance dependence) + INV-SECRET-05 (proxy substitutes placeholders before upstream) + INV-VM-CAP-04 (no credential mounts in VM) + INV-CRED-PROXY-VM-REACHABILITY-01 (substrate-level vsock fan-out preserves stock-URL transparency without crossing the credential boundary) — together these guarantee a jailbroken / prompt-injected / hallucinating LLM that exfiltrates everything it can observe leaks only the operator-staged placeholders. The real credential material never enters the LLM's context; the substitution discipline at the proxy boundary is the load-bearing mechanical guarantee, with the witness in `credential_substitution_evidence` pinning all five sub-properties on every realism e2e run |

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

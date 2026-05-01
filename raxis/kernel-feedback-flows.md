# RAXIS — Kernel Feedback Flows

How the kernel communicates policy restrictions and verification state back to the agent (planner). This document covers two distinct feedback surfaces: policy enforcement responses and witness/gate lifecycle signals.

---

## Governing Principle: INV-08

The kernel never tells the planner which specific policy rule fired. If the planner could discover "rule 4 in the claim table denied you because `src/auth/**` requires `SecurityReview`," it could probe the policy by varying inputs until it maps the entire rule surface.

The analogy is a syscall returning `EPERM`. The kernel does not explain which DAC rule or capability check fired — it says "permission denied." The process knows which syscall it made and can infer from there. RAXIS works the same way.

**What the agent always has:** knowledge of its own output. It knows which request it sent, which URL it tried to fetch, which commit SHA it submitted. Coarse codes are sufficient because the agent has first-party context the kernel doesn't need to repeat back.

**What the operator always has:** the full audit log — which rule fired, which path was blocked, which domain was denied, the complete decision chain. The agent cannot access the audit log.

---

## Part 1 — Policy Enforcement Feedback

### Response channels

**Channel 1 — `IntentResponse::Rejected { reason: PlannerErrorCode }`**

When an `IntentRequest` is blocked by policy, the kernel returns an `Ok(IntentResponse::Rejected { reason })` — not a transport error. The planner receives this on its normal request path and branches in code on the typed enum.

| `PlannerErrorCode` | What fired | What the agent knows | What the agent can do |
|---|---|---|---|
| `FAIL_MISSING_WITNESS` | Required gate types not satisfied | Which intent it submitted; which SHA | Submit escalation or acquire missing claims |
| `FAIL_POLICY_VIOLATION` | Budget ceiling, unknown intent kind, structural policy block | Something about this request violated policy | Submit smaller-scope intent or escalate |
| `UNAUTHORIZED` | Session invalid, token revoked, or nonce consumed | The session or token is not acceptable | Re-authenticate or escalate |
| `FETCH_DENIED` | Egress allowlist miss or rate limit | The specific URL it tried (it composed the request) | Try different URL, back off, or escalate |
| `INVALID_REQUEST` | Malformed request | The request itself | Fix and resubmit |

**Wire vs Rust:** planner-visible JSON uses uppercase snake strings such as `INVALID_REQUEST`; the corresponding Rust enum is typically `PlannerErrorCode::InvalidRequest` — same semantic, different spelling convention.

**Channel 2 — `FetchDenied { deny_reason: FetchDenyReason }` on the fetch path**

For egress restrictions, the kernel provides a slightly more specific signal because the fetch is a discrete, named operation. `FetchDenyReason` has two variants:

- `DomainNotAllowed` — the domain is not in the signed allowlist. Retrying the same URL will not work. The agent needs a different approach or an escalation.
- `RateLimitExceeded` — the session has hit its fetch quota for the current window. The agent can back off and retry after a delay without operator intervention.

Both variants are still coarse — no URL pattern is revealed, no allowlist structure is exposed. The distinction exists because the recovery paths are meaningfully different.

**Channel 3 — Proactive warn signals in `IntentResponse`**

For non-blocking issues, the kernel adds warning fields to a *successful* `IntentResponse`. The primary one is `warn_delegation_stale: bool`. When the policy epoch has advanced since the session's delegation was issued, the kernel lets the current intent through but signals "your delegation may be stale — renew before the next gated action or you will hit a claim failure."

The agent can act on this proactively rather than discovering it as a rejection later.

---

### Egress restriction — step by step

```
Agent sends:   FetchRequest { fetch_request_id: X, url: "https://docs.example.com/api" }

Kernel:
  1. Validates URL format
  2. Checks domain against signed allowlist
  3. "docs.example.com" not found → DomainNotAllowed

Kernel sends:  FetchDenied { fetch_request_id: X, deny_reason: DomainNotAllowed }
               AuditEvent::FetchDenied { url, deny_reason, session_id }  ← audit only
```

The agent receives `DomainNotAllowed`. It knows which URL it tried. Its options:

**A) Find the information another way** — use already-fetched context, local files, or known documentation already in its context window.

**B) Submit an escalation:**
```
EscalationRequest {
    class:           EscalationClass::EgressException,
    requested_scope: EgressExceptionScope {
        url_pattern: "https://docs.example.com/**",
    },
    justification:   "Need access to docs.example.com to resolve the API
                      contract for the authentication module. No local copy
                      of this documentation exists in the workspace.",
    idempotency_key: Uuid::new_v4(),
}
```
Kernel returns `EscalationResponse::Submitted { escalation_id, timeout_at }`. Agent continues other work and presents an `ApprovalToken` on the next fetch attempt when the operator approves.

**C) Report it cannot complete this step** and surface the issue to the operator out-of-band.

What the agent does NOT know:
- Whether any other domain in `docs.example.com` is blocked or just this path
- Which allowlist entry governs the decision
- What domains are in the allowlist (probing would be required to discover this — a deliberate property of the design)

---

### Claim restriction — step by step

```
Agent pushes commit touching src/auth/session.rs, src/auth/token.rs
Agent sends:   IntentRequest { head_commit_sha: "a3f9...", intent_kind: CompleteWork, ... }

Kernel:
  1. Computes touched_paths from VCS diff independently
  2. Evaluates claim table:
       src/auth/** → requires SecurityReview claim
  3. Session has no SecurityReview claim
  4. Returns rejection

Kernel sends:  IntentResponse::Rejected { reason: FAIL_MISSING_WITNESS }
               AuditEvent::IntentRejected { task_id, reason: ClaimInsufficient,
                 failing_claims: [...] }   ← audit only; failing_claims not sent to planner
```

The agent receives `FAIL_MISSING_WITNESS`. It knows its diff touches auth files. Its options:

**A) Narrow the work** — split the commit so only non-gated paths are in scope for this intent. Submit a separate intent for the auth changes with appropriate claims.

**B) Submit an escalation** requesting the required capability for this session:
```
EscalationRequest {
    class:           EscalationClass::CapabilityUpgrade,
    requested_scope: CapabilityUpgradeScope { capability: SecurityReview },
    justification:   "The authentication session token reuse fix in src/auth/
                      session.rs is required to close the security regression
                      identified in the current initiative.",
}
```

**C) Request the operator provision the `SecurityReview` claim type** for this session through normal policy update and epoch advance.

---

### Budget ceiling — step by step

```
Agent sends:   IntentRequest (task that would exceed lane cost ceiling)

Kernel:
  1. Computes admission cost from touched_paths and intent_kind
  2. Checks lane_budget_reservations: reserved_cost + estimated_cost > lane ceiling
  3. Returns rejection

Kernel sends:  IntentResponse::Rejected { reason: FAIL_POLICY_VIOLATION }
```

The agent receives `FAIL_POLICY_VIOLATION`. This code also covers unknown intent kinds and other structural violations — the agent cannot distinguish which specific policy block fired. Its options:

**A) Submit a smaller-scope intent** — break the work into smaller pieces that individually fit within the remaining budget.

**B) Submit a `BudgetException` escalation** requesting a higher ceiling for this initiative.

**C) Wait** — if other tasks in the lane are completing and releasing their budget reservations, the lane may have capacity later.

---

## Part 2 — Witness / Gate Feedback

### Phase 1 — Agent submits "I'm done"

The agent pushes a commit and sends an `IntentRequest`. This is the agent's claim that work is complete at a specific SHA. The kernel does not accept this claim on faith — it evaluates the claim table and determines which gate types are required.

```
Agent sends:
IntentRequest {
    head_commit_sha: "a3f9c2b...",
    base_commit_sha: "e81d4a0...",
    intent_kind:     IntentKind::CompleteWork,
    lane_id:         "default",
    idempotency_key: Uuid::new_v4(),
}
```

Kernel processes synchronously before responding:
1. Validates both SHAs (40-char hex, ancestor check, single-commit parent check if applicable)
2. Computes `touched_paths` from VCS diff independently — planner-supplied path manifests are discarded
3. Evaluates claim table to determine required gate types
4. Admits task to the lane (budget reservation, DAG predecessor check)
5. Spawns verifier processes for each required gate type
6. Returns immediately

**Response the agent receives:**
```
IntentResponse::Admitted {
    task_id:       Uuid,
    gates_pending: vec![
        GateType::RustBuild_Linux,
        GateType::RustBuild_Windows,
    ],
}
```

The agent now knows:
- Its work was received and the task was admitted
- Exactly which gate types are blocking completion — not which rule fired, but which verifier categories are outstanding
- The task will not be promotable until all listed gates clear

The agent does NOT know:
- When the verifiers will finish
- Whether they will pass or fail
- Which specific claim rule triggered each gate type

---

### Phase 2 — Verifiers run concurrently

The kernel spawns all required verifiers before returning the `Admitted` response. The agent and verifiers run concurrently — the agent can continue doing other work: picking up another task, making fetch requests, working in a different lane.

Each verifier:
1. Receives its `verifier_run_token`, `task_id`, `verifier_run_id`, `head_commit_sha`, and `RAXIS_SOCKET` path from the kernel at spawn time via environment variables
2. Runs the project-specific verification work (build, test, lint — operator-configured)
3. Connects to the kernel IPC socket and authenticates with its token
4. Submits `WitnessSubmission { verifier_run_id, task_id, gate_type, head_commit_sha, result }`
5. Receives `WitnessAck::Accepted { verifier_run_id, remaining_gates }` — `remaining_gates` is informational, telling this verifier which other gates are still outstanding on the same task
6. Exits

The kernel validates the SHA binding on every `WitnessSubmission` (INV-03): a witness bound to SHA A cannot satisfy a gate check for SHA B. A verifier that ran against a different commit is rejected regardless of result.

---

### Phase 3 — The agent discovers gate state by re-submitting

There is no push channel from the kernel to the agent in v1. The agent discovers gate state by re-submitting the same intent with the **same `idempotency_key`**. The kernel recognises the key, finds the existing task row, and returns the current gate state without creating a duplicate task.

**If some gates have cleared but others are still running:**
```
IntentResponse::Admitted {
    task_id:       <same Uuid as before>,
    gates_pending: vec![GateType::RustBuild_Windows],  // Linux cleared; Windows still running
}
```

**Once all gates clear:**
```
IntentResponse::GatesCleared {
    task_id:       <same Uuid>,
    gates_pending: vec![],    // empty — all witnesses accepted
}
```

The agent sees an empty `gates_pending` and knows the task is fully verified. It can now submit a promotion intent or move to the next piece of work.

The agent controls its own polling cadence. Re-submission with the same `idempotency_key` is safe and cheap — the kernel does a row lookup and state read, no re-evaluation of SHAs or claim tables.

---

### Phase 4 — Witness failure

If a verifier submits `WitnessResult::Fail` (the build broke, the tests failed), the kernel:
1. Records the failure in the witness store
2. Transitions the task to `TaskState::Aborted { reason: BlockReason::WitnessFailure }`
3. Releases the lane budget reservation

When the agent re-submits with the same `idempotency_key`:
```
IntentResponse::Rejected { reason: PlannerErrorCode::FAIL_MISSING_WITNESS }
```

The coarse code is the same as "witness not yet submitted." The agent cannot distinguish "verifier hasn't run yet" from "verifier ran and failed" from this code alone. But it can infer from timing and context: if it already received `Admitted { gates_pending }` and has been polling, a rejection now likely means a verifier reported failure.

The failed task is terminal — it cannot be retried in place. The agent must:
1. Diagnose the failure from its own workspace (build output, test results — whatever the verifier script generates locally)
2. Fix the underlying problem
3. Push a new commit
4. Submit a new `IntentRequest` with a new `head_commit_sha` and a new `idempotency_key`
5. Start the cycle again from Phase 1

---

### Phase 5 — Witness timeout

If a verifier's `verifier_run_token` expires before a `WitnessSubmission` arrives (the build environment crashed, the process was killed, the script hung), the kernel's timeout sweep fires:
1. Transitions task to `TaskState::Aborted { reason: BlockReason::WitnessTimeout }`
2. Releases the lane budget reservation

The agent's re-submission produces the same `FAIL_MISSING_WITNESS` response. Same recovery: fix, new commit, new intent.

---

### Full timeline — cross-compilation example

```
Agent                          Kernel                         Verifiers
  |                              |                                |
  |-- IntentRequest { SHA } ---> |                                |
  |                              |-- spawn RustBuild_Linux -----> |
  |                              |-- spawn RustBuild_Windows ---> |
  |<-- Admitted {                |                                |
  |    gates_pending:            |                                |
  |    [Linux, Windows]          |                   [Linux: cargo build runs]
  |    } ----------------------- |                                |
  |                              |                                |
  |   (agent does other work)    |<-- WitnessSubmission Pass  --- | (Linux done)
  |                              |    Linux gate cleared          |
  |                              |                   [Windows: cross build runs]
  |-- IntentRequest              |                                |
  |   (re-poll, same key) -----> |                                |
  |<-- Admitted {                |                                |
  |    gates_pending: [Windows]  |                                |
  |    } ----------------------- |                                |
  |                              |                                |
  |   (agent does other work)    |<-- WitnessSubmission Pass  --- | (Windows done)
  |                              |    All gates cleared           |
  |-- IntentRequest              |                                |
  |   (re-poll, same key) -----> |                                |
  |<-- GatesCleared { } -------- |                                |
  |                              |                                |
  (agent proceeds to next work)
```

---

### Full timeline — witness failure example

```
Agent                          Kernel                         Verifiers
  |                              |                                |
  |-- IntentRequest { SHA } ---> |                                |
  |<-- Admitted {                |                                |
  |    gates_pending: [Linux]    |                   [Linux: cargo build fails]
  |    } ----------------------- |                                |
  |                              |<-- WitnessSubmission Fail  --- | (Linux done, result=Fail)
  |                              |    Task → Aborted              |
  |-- IntentRequest              |                                |
  |   (re-poll, same key) -----> |                                |
  |<-- Rejected {                |                                |
  |    reason: FAIL_MISSING_WITNESS                               |
  |    } ----------------------- |                                |
  |                              |                                |
  (agent inspects build output in workspace, fixes code, pushes new commit)
  |                              |                                |
  |-- IntentRequest { NEW SHA,   |                                |
  |   NEW idempotency_key } ---> |                                |
  |<-- Admitted { ... } -------- |                                |
  (cycle repeats with new task)
```

---

## Why these design choices

**Admitted-then-poll rather than synchronous wait.** Some verifiers take minutes (cross-compilation, E2E test suites). Blocking the agent's IPC connection for that duration creates a single point of failure — a dropped connection would lose the task. `Admitted { gates_pending }` decouples the agent session lifetime from the verifier lifetime.

**Coarse failure codes for witness failures.** If the agent got "RustBuild_Windows failed at linker step, exit 1, output: ..." it would have the verifier's internal reasoning in its context. That reasoning could be manipulated by a compromised verifier. The kernel's job is to say "this gate did not clear." The agent reads the build output from its own workspace — context it already has access to and that the kernel never needs to relay.

**Agent re-polls rather than kernel pushing.** Push requires the kernel to maintain a live channel per agent session for the duration of verification. If the agent crashes and restarts, push breaks. Re-poll with idempotency keys is stateless from the kernel's perspective — the agent can crash, restart, and re-poll from wherever it left off with no kernel-side recovery logic required.

**Same coarse code for "not yet" and "failed".** An agent that can distinguish "not yet" from "failed" will poll differently in each case and can infer verifier behavior over time. Collapsing them to the same coarse code prevents the agent from learning the verifier's internal timing or failure characteristics through observation.

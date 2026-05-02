# RAXIS — Kernel Feedback Flows

How the kernel communicates policy restrictions and verification state back to the agent (planner). This document covers policy enforcement responses and witness/gate lifecycle signals.

**Normative contracts:** Planner-visible codes and remediation match [`specs/v1/planner-api.md`](specs/v1/planner-api.md) and [`specs/v1/peripherals.md`](specs/v1/peripherals.md) §3.1. Escalation shapes match [`specs/v1/philosophy.md`](specs/v1/philosophy.md) (`raxis-types` escalation / approval types). This guide is auxiliary — if it conflicts with those specs, the specs win.

---

## Governing Principle: INV-08

The kernel never tells the planner which specific policy rule fired. If the planner could discover "rule 4 in the claim table denied you because `src/auth/**` requires `SecurityReview`," it could probe the policy by varying inputs until it maps the entire rule surface.

The analogy is a syscall returning `EPERM`. The kernel does not explain which DAC rule or capability check fired — it says "permission denied." The process knows which syscall it made and can infer from there. RAXIS works the same way.

**What the agent always has:** knowledge of its own output. It knows which request it sent, which URL it tried to fetch, which commit SHA it submitted. Coarse codes are sufficient because the agent has first-party context the kernel does not need to repeat back.

**What the operator always has:** the full audit log — which rule fired, which path was blocked, which domain was denied, the complete decision chain. The planner cannot access the audit log.

---

## Part 1 — Policy Enforcement Feedback

### Response channels

**Channel 1 — `IntentResponse`**

Every intent returns **`outcome`**: `"Accepted"` or `"Rejected"` ([`peripherals.md`](specs/v1/peripherals.md) §3.1). There is no partial outcome. On **`Rejected`**, the planner receives **`error_code`** (`PlannerErrorCode`). On **`Accepted`**, it receives **`remaining_budget`** and **`task_state`**.

|`PlannerErrorCode` (representative)| What fired | What the agent knows | What the agent can do |
|---|---|---|---|
| `FAIL_MISSING_WITNESS` | Required witnesses or submitted claims not satisfied (includes verifier not finished **and**, per v1 test matrix, empty / insufficient **submitted claim** manifest where mapped to this code — see [`philosophy.md`](specs/v1/philosophy.md) §1.3 INV-08 note) | Which intent it submitted; which SHAs | Wait/back off; fix claims; escalate per policy |
| `FAIL_INSUFFICIENT_WITNESS` | Witness present but evidence below threshold (`result_class: Fail` path) | Same | Improve tests/build; new commit; resubmit |
| `FAIL_PATH_POLICY_VIOLATION` | Committed paths outside `effective_allow` | Own diff vs task allowlist (kernel does not enumerate paths) | Revert / narrow scope; resubmit |
| `FAIL_INVALID_COMMIT_TOPOLOGY` | Merge in range (non‑`IntegrationMerge`) or bad merge shape | Own Git history | Rebase / fix merge tip per [`planner-api.md`](specs/v1/planner-api.md) |
| `FAIL_INVALID_DIFF` | Dirty / unmerged history | Working tree state | Resolve conflicts; clean commit |
| `FAIL_POLICY_VIOLATION` | Budget, unknown intent kind, other structural policy blocks | May read **`error_detail`** only when this code is used ([`peripherals.md`](specs/v1/peripherals.md) INV-08 rule) | Smaller scope, escalate, or fix shape |
| `FAIL_BUDGET_EXCEEDED` | Admission would exceed budget | Remaining budget from last accepted response | `CompleteTask`, `ReportFailure`, or wait for capacity |
| `FAIL_UNKNOWN_TASK` | `task_id` not in signed plan | — | **Stop** — not retryable |
| `FAIL_TASK_NOT_RUNNING` | Task not schedulable (`Admitted` waiting on DAG, `GatesPending`, `BlockedRecoveryPending`, etc.) | Task id | Wait / unblock / pick another task |
| `FAIL_STALE_BASE` | `IntegrationMerge` behind pinned main | Session pin vs current ref | Rebase integration branch; resubmit |
| `UNAUTHORIZED` | Token, sequence, nonce, or session failure | Session invalid | **Stop** — do not retry same token ([`planner-api.md`](specs/v1/planner-api.md)) |
| `FETCH_DENIED` | Allowlist miss or fetch quota | URL it requested | Allowed URL, backoff, or operator/policy change |
| `INVALID_REQUEST` | Malformed envelope / intent | Request payload | Fix shape; not a policy oracle |

**Wire vs Rust:** JSON projections use uppercase snake strings (e.g. `FAIL_MISSING_WITNESS`); Rust enums use `PascalCase` equivalents.

**Channel 2 — Fetch path: `FetchDenied`**

For `FetchRequest`, denials use **`FetchDenied`** with **`deny_reason`**: `DomainNotAllowed` | `RateLimitExceeded` ([`philosophy.md`](specs/v1/philosophy.md) audit types). Distinct recovery: wrong domain vs backoff.

**Channel 3 — Proactive warning on success**

On **`Accepted`**, **`warn_delegation_stale: bool`** may be true when the kernel consumed a stale delegation grace use — renew delegation before the next gated action ([`philosophy.md`](specs/v1/philosophy.md) §1.6 `IntentResponse`).

---

### Egress restriction — step by step

```
Agent sends:   FetchRequest { fetch_request_id: X, url: "https://docs.example.com/api" }

Kernel:
  1. Validates URL format
  2. Checks domain against signed allowlist ([egress.domain_allowlist] in policy.toml)
  3. "docs.example.com" not found → DomainNotAllowed

Kernel sends:  FetchDenied { fetch_request_id: X, deny_reason: DomainNotAllowed }
               AuditEventKind::FetchDenied { ... }  ← audit only
```

**v1 does not define a planner escalation class that widens egress.** [`philosophy.md`](specs/v1/philosophy.md) lists `EscalationClass`: `CapabilityUpgrade` | `DelegationRenewal` | `BudgetException` | `QualityGateException` — none of these replaces a domain allowlist edit.

The agent's options:

**A)** Use already-fetched context, local files, or an allowed URL.

**B)** Stop and surface the need for a **signed policy update** (`egress.domain_allowlist` / fetch quotas in `policy.toml`), authority re-signs, operator stages the new artifact under `<data_dir>/policy/`, then runs **`raxis-cli epoch advance --policy <path> --sig <path>`** (both arguments required; see `specs/v1/cli-ceremony.md`) — no fictional `EgressException` IPC.

**C)** **`ReportFailure`** or operator-directed pause if the task cannot proceed without that fetch.

What the agent does **not** learn from the kernel: allowlist membership beyond the coarse deny reason (INV-08).

---

### Claim restriction — step by step

```
Agent pushes commits touching src/auth/session.rs, src/auth/token.rs
Agent sends:   IntentRequest {
                 intent_kind: "SingleCommit",
                 base_sha:    "...",
                 head_sha:    "...",
                 task_id:     "...",
                 submitted_claims: [ ... ],  // may be empty → can map to FAIL_MISSING_WITNESS (see philosophy §1.3)
                 ...
               }

Kernel:
  1. Computes touched_paths from VCS diff independently (INV-07)
  2. Derives required claim types from signed policy claim_requirements
  3. Gate / claim evaluation fails pre-admission or pending witnesses
  4. Returns Rejected with coarse code (often FAIL_MISSING_WITNESS)

Kernel sends:  IntentResponse::Rejected { error_code: FAIL_MISSING_WITNESS, ... }
               Audit log holds precise subtype — not sent to planner
```

Escalation for missing **capability** (not a free-form egress URL pattern) uses the normative request shape:

```
EscalationRequest {
    class: EscalationClass::CapabilityUpgrade,
    requested_scope: RequestedEscalationScope::CapabilityUpgrade {
        capability: CapabilityClass::...,  // e.g. role-specific capability your policy defines
    },
    justification: "...",
    idempotency_key: Uuid::new_v4(),
    task_id: ...,
}
```

(`CapabilityUpgradeScope` / URL-pattern scopes are not v1 types — use [`philosophy.md`](specs/v1/philosophy.md) §1.6 `EscalationRequest`.)

---

### Budget ceiling — step by step

```
Agent sends:   IntentRequest (would exceed lane / session admission budget)

Kernel:
  1. Computes admission cost from VCS-derived touched_paths + intent_kind + policy (INV-02A)
  2. Budget check fails
  3. Returns Rejected { FAIL_BUDGET_EXCEEDED } or FAIL_POLICY_VIOLATION per dispatcher mapping
```

Options: complete with **`CompleteTask`** if done, **`ReportFailure`**, operator **`BudgetException`** escalation ([`philosophy.md`](specs/v1/philosophy.md)), or wait for reservations to clear.

---

## Part 2 — Witness / Gate Feedback (v1)

### No separate “Admitted / GatesCleared” response type

v1 returns **`IntentResponse`** with **`outcome`** and **`task_state`** only ([`peripherals.md`](specs/v1/peripherals.md) §3.1). Tasks may be **`GatesPending`** while verifiers run; the planner discovers progress by **submitting further intents** (e.g. another `SingleCommit` or **`CompleteTask`**) after backoff and observing **`Accepted`** vs **`Rejected`** and updated **`task_state`**. There is **no v1 kernel push** channel to the planner ([`README.md`](README.md) v2 roadmap).

### Typical flow

1. Planner submits **`SingleCommit`** (or empty-range bind) → **`Accepted`**, **`task_state`** often **`Running`**; kernel may spawn verifiers for required gates.
2. While witnesses are outstanding, **`task_state`** may be **`GatesPending`** (not returned by `next_ready_tasks` for new pickup — [`philosophy.md`](specs/v1/philosophy.md)).
3. **`CompleteTask`** with final **`head_sha`** succeeds only when path closure (INV-TASK-PATH-02) and gate closure succeed; otherwise **`Rejected`** with **`FAIL_MISSING_WITNESS`**, **`FAIL_INSUFFICIENT_WITNESS`**, or path/topology codes per [`planner-api.md`](specs/v1/planner-api.md).

### Witness IPC (verifier side)

Verifiers submit **`WitnessSubmission`** with **`evaluation_sha`** matching env **`RAXIS_EVALUATION_SHA`** ([`peripherals.md`](specs/v1/peripherals.md) §3.3). The field is **`evaluation_sha`** in the typed message — not a planner-only alias.

### Witness pass

When all required witnesses pass, gate recheck allows progression; the planner sees **`Accepted`** on a subsequent intent (e.g. **`CompleteTask`**) with **`task_state: Completed`** when all completion predicates hold.

### Witness `result_class: Fail`

Evidence recorded; gate does not clear. On a later **`CompleteTask`** (or relevant intent), the planner typically receives **`FAIL_INSUFFICIENT_WITNESS`** ([`planner-api.md`](specs/v1/planner-api.md)), not the same semantics as “verifier not run yet.”

### Witness timeout / process failure

Per v1 FSM, timeout may transition the task to **`Aborted`** with **`BlockReason::WitnessTimeout`**. Further intents for that task fail preconditions (e.g. **`FAIL_TASK_NOT_RUNNING`** / terminal state handling — exact code depends on dispatcher mapping; terminal tasks are not completable).

### Idempotency

Optional **`idempotency_key`** on **`IntentRequest`** duplicates the same **`IntentResponse`** within the session ([`peripherals.md`](specs/v1/peripherals.md)); it does not replace **`sequence_number`** / nonce rules (INV-01).

---

### Timeline sketch — multi-gate task (conceptual)

```
Planner                Kernel                         Verifiers
  |                       |                                |
  |-- SingleCommit -----> |                                |
  |                       |-- spawn gate A --------------> |
  |                       |-- spawn gate B --------------> |
  |<-- Accepted           |                                |
  |    task_state:        |                   [A: runs...] |
  |    GatesPending       |                   [B: runs...] |
  |                       |<-- WitnessSubmission Pass --- |
  |                       |<-- WitnessSubmission Pass --- |
  |                       |   (gate recheck → ready)      |
  |-- CompleteTask -----> |                                |
  |<-- Accepted           |                                |
  |    task_state:        |                                |
  |    Completed          |                                |
```

Exact states and ordering are defined in **`handlers/intent.rs`**, **`handlers/witness.rs`**, and Part 2.4 FSM tables in [`kernel-core.md`](specs/v1/kernel-core.md); this diagram is illustrative only.

---

## Why these design choices

**Coarse planner-facing codes.** Detailed reasons live in audit entries only — prevents policy probing (INV-08) and keeps the planner prompt stable ([`planner-api.md`](specs/v1/planner-api.md)).

**No LLM-as-oracle for approvals or egress.** Matches [`design-decisions.md`](specs/design-decisions.md) rejected alternatives (A.10–A.12).

**v1 polling.** Push notifications are a committed **v2** item ([`README.md`](README.md)); until then, backoff and resubmit.

---

## Related auxiliary doc

Operator setup for gates and verifier env vars: [`configuring-witnesses.md`](configuring-witnesses.md) (aligned with [`kernel-store.md`](specs/v1/kernel-store.md) §2.5.6).

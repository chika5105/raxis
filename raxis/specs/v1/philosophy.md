# RAXIS — Part 1: Philosophy, Invariants, and Workspace Layout

> **Scope:** Implementation philosophy, all v1 invariants (full table with rationale), test matrix, release gates, workspace layout, shared library crates, and the policy artifact on-disk format.
>
> **Navigation:** [README](../../README.md) | [Design Decisions](../design-decisions.md) | [Part 2 Core](kernel-core.md) | [Part 2 Store](kernel-store.md)

---

## Detailed Implementation

> **This section is written in parts, reviewed and approved incrementally.**
> Part 1 covers philosophy, invariants, and workspace layout.
> Subsequent parts cover each component in file-level detail.

---

### Part 1 — Philosophy, Invariants, and Workspace Layout

#### 1.1 — One Codebase, Three Release Phases, No Shared Blast Radius

The temptation when designing for v2 is to build v1 and v2 simultaneously, reasoning that it saves time to architect everything at once.
This is the highest-probability path to shipping neither safely.

**Why building v1 and v2 together is risky:**
- v2 features (multi-provider routing, smarter scheduling, finer-grained policy diffs) are exactly the surfaces where hidden authority bypasses appear.
- Adding v2 complexity before v1 invariants are proven makes regression detection unreliable — you cannot tell whether a new failure comes from v1 logic or v2 interaction.
- You lose the ability to establish a clean baseline for adversarial testing. You cannot chaos-test a system that is still being assembled.
- Trust boundaries blur during construction. A developer adding multi-provider routing "just for now" in the kernel binary blurs the gateway abstraction before it is proven.

**The correct model:** architect for v2, but gate each phase behind a formal release check.

```
Phase A  ─  v1 hard core
            Kernel/planner process split, provider gateway, verifier runner,
            signed structured plans, witness-based gates, audit chain,
            local signed approvals, fail-closed bootstrap.
            STOP. Run invariant suite. Run adversarial suite. Run chaos drills.

Phase B  ─  v2 features, flags OFF by default
            Multi-provider routing intelligence, multi-lane scheduling,
            per-capability epoch staleness, richer intake UX.
            All controlled by feature flags, disabled at compile time or runtime.
            STOP. Run v1 invariant suite again. Confirm no regression.

Phase C  ─  Enable v2 features one at a time
            Each feature enabled only after its own adversarial tests pass
            and failure drills confirm expected blocked/quarantine behavior.
```

Every feature flag starts as `cfg(feature = "v2-<name>")` in Rust.
No v2 feature is enabled in a release binary until it has its own pass in the test matrix.
This means the v1 release binary is compiled with all v2 features gated out — not just disabled at runtime, but absent from the binary's attack surface.

---

#### 1.2 — V1 Invariants (The Must-Pass List)

These are the properties that must be provably true before Phase A is complete.
If any of these fail, v1 is not done — regardless of what else works.

| ID | Invariant | Why it matters |
|---|---|---|
| INV-01 | Planner cannot perform any authorized action without a valid kernel-issued session token | Without this, the entire authority model is convention, not enforcement |
| INV-02A | Planner binary has no provider credential store access and no IPC message type that routes to a provider inference endpoint; the only inference path is `InferenceRequest → kernel → gateway`; admission cost (`estimated_cost`) is kernel-computed from `budget::compute_admission_cost` using VCS-derived inputs and policy — no planner-supplied field reaches `consume_budget` | Without this, budget enforcement is advisory: a provider call bypassing the kernel bypasses the budget, and a planner-priced admission charge is no enforcement at all |
| INV-02B | Planner has no direct network egress of any kind; all external data fetches go through `FetchRequest → kernel → gateway`; kernel logs `{fetch_request_id, url, fetched_at, response_sha256, content_type, byte_len}` before content is returned to planner | Without this, INV-05 breaks — decisions are not reproducible from stored records if planner can pull in unlogged external inputs; also closes the prompt-injection observability gap |
| INV-03 | A witness bound to commit SHA `A` cannot satisfy a gate check for commit SHA `B` | Without this, stale or fabricated witnesses pass gates |
| INV-04 | Any modification to the audit log (delete, update, truncate) is detectable by hash chain verification | Without this, the audit log is not an unforgeable record |
| INV-05 | Given the audit log and kernel state at crash time, kernel decisions are reproducible from stored records | Without this, recovery is guesswork |
| INV-06 | An action requiring approval does not execute without a valid, scoped, unexpired approval token whose `ApprovalProof` is written to the kernel state store | Without this, escalation is a delay, not a gate |
| INV-07 | A planner-submitted path manifest cannot influence which claim types are required; kernel derives required claims from VCS state independently | Without this, the planner controls its own quality obligations |
| INV-08 | Rejection reason codes exposed to the planner do not reveal which specific policy rule fired | Without this, the gate system can be reverse-engineered by probing |
| INV-TASK-PATH-01 | The kernel admits an intent if and only if every path in `touched_paths(intent)` — computed from `(base_sha, head_sha)` via `vcs::diff`, not from any planner-declared manifest — is a member of `effective_allow(task_id)` at the time of admission; failing intents are rejected non-terminally | Without this, a task can land out-of-scope files while the kernel accepts the intent |
| INV-TASK-PATH-02 | The kernel does not transition a task to `Completed` unless every path in the union of `touched_paths` across all accepted intent ranges **plus** the trailing segment from `tasks.evaluation_sha` to the `CompleteTask` intent's `head_sha` (when they differ) — with the trailing segment passing the same merge-topology check as §2.5.8 step 2A, then `vcs::diff` — is a member of `effective_allow(task_id)` recomputed at completion time; path coverage is a necessary condition, not a sufficient one; failing `CompleteTask` intents are rejected non-terminally | Without this, a planner can land commits after the last recorded range (or a bad final commit) and complete the task without path closure on that tip, or slip merge commits past topology enforcement |

---

#### 1.3 — V1 Test Matrix

Every invariant must have a corresponding test. Tests are grouped into suites with specific purposes.

> **Vocabulary note:** This matrix uses informal shorthand — "blocked," "blocked_capability," "blocked_provider" — for readability. The authoritative typed enums are `TaskState` (e.g. `GatesPending`, `BlockedRecoveryPending`) and `BlockReason` (e.g. `DelegationInsufficient`, `ProviderTimeout`) defined in `raxis-types/src/initiative.rs` and specified in Part 2.3. When implementing, map each informal term to the nearest typed variant; Part 2.3 wins on conflict.
>
> **INV-08 coarse codes:** `PlannerErrorCode::FAIL_MISSING_WITNESS` is the single planner-facing code for every internal failure mapped to `HandlerError::MissingWitness` — including insufficient or empty *submitted claim* manifests (gate pre-admission) as well as missing *verifier-produced* witness blobs where that maps to the same handler variant. The English string emphasizes witness gaps; the audit log records the precise subtype. The planner does not learn which internal branch fired.

**Unit tests — kernel policy engine**
- Envelope parsing rejects missing/mismatched session tokens
- Capability bitmap evaluation: each capability class grants and denies correctly
- Delegation TTL: expired delegation causes `blocked_capability`, not silent permit
- Escalation state machine: timeout transitions to `blocked`, not `approved`
- Epoch staleness: any epoch mismatch marks delegation stale-on-next-use
- Budget admission: pre-call check blocks over-ceiling requests
- Budget reconciliation: post-call overage creates audit event and applies to future ceiling

**Protocol tests — IPC contracts**
- Invalid token → `UNAUTHORIZED` (not a crash)
- Wrong sequence (`sequence != last_accepted + 1`) → `UNAUTHORIZED` — §2.5.1 Table 16 check (A)
- Replayed envelope nonce (duplicate `nonce_cache` insert for the same session) → `UNAUTHORIZED` — matches §2.5.1 Table 16 check (B); do **not** use `INVALID_REQUEST` here (that code is for malformed / semantically invalid envelopes, not auth-layer replay)
- Malformed envelope → `INVALID_REQUEST` (kernel does not crash on bad input)
- Stale session ID → `UNAUTHORIZED`
- Planner-supplied timestamp in any field → rejected, kernel timestamp used

**Integration tests — happy path and denial flows**
- Full initiative lifecycle: `draft → approved_plan → executing → completed`
- Task submitted with witnesses not yet collected → gate returns `GateEvalResult::PendingWitness`; task admitted as `TaskState::GatesPending`; `WitnessAck::Accepted { verifier_run_id, remaining_gates }` returned to planner (`WitnessAck` is an enum — see `crates/ipc/src/message.rs` in `raxis-ipc` and Part 2.3 `handlers/witness.rs`; not a rejection). Verify: task is in `GatesPending`, not schedulable until witnesses arrive.
- Verifier completes but witnesses never satisfy all gate types before TTL → task transitions from `GatesPending` to `TaskState::Aborted { reason: BlockReason::WitnessTimeout }` after verifier token TTL expires; planner task-status query returns `Aborted`; `AuditEventKind::VerifierTimeout` emitted. (Same invariant as chaos drill “Kill verifier mid-gate” — integration confirms correctness; chaos drill confirms behavior under stress.)
- Task with wrong-evaluation-sha witness (evaluation_sha mismatch) → `WitnessSubmission` rejected at `ipc/handlers/witness.rs`; `WitnessAck::Rejected { reason: EvaluationShaMismatch }`; task remains `GatesPending`.
- Intent submitted with required claim types present but planner sends zero submitted claims → `claim::evaluate` returns `Insufficient { failing_claims }`; `gates/mod.rs` step 3 maps that to `GateEvalResult::ClaimInsufficient { reason: ClaimInsufficient, failing_claims }` (same shape as Part 2.3); intent handler maps to `HandlerError::MissingWitness` → `IntentResponse::Rejected { reason: PlannerErrorCode::FAIL_MISSING_WITNESS }`. Task never admitted. (See INV-08 note above: `FAIL_MISSING_WITNESS` here means missing submitted claims, not absent verifier output.)
- Intent submitted with `IntentKind` not in policy cost table → `compute_admission_cost` returns `BudgetError::UnknownIntentKindCost`; handler returns `Ok(IntentResponse::Rejected { reason: FAIL_POLICY_VIOLATION })` directly (not through `map_error`); no task row binding `UPDATE`, no `lane_budget_reservations` insert, no `transition_task`. Verify: the task row (if it existed) is unchanged; no new reservation for that `task_id`.
- Session fetch quota exhausted mid-task → `check_rate_limit` returns internal `ProviderError::RateLimitExceeded`; `fetch.rs` handler maps to `HandlerError::FetchDenied`; dispatcher maps to `PlannerErrorCode::FETCH_DENIED`; planner observes `FETCH_DENIED` per denied request. Task state unchanged (`GatesPending` or `Running`); no `BlockReason` written; no FSM transition. Verify: task row state unchanged; no `BlockReason` field written; audit log contains `AuditEventKind::FetchDenied { deny_reason: RateLimitExceeded }` for each denied request (same variant as allowlist denial, distinguished by `deny_reason`).
- **Escalation — happy path:** Planner submits `EscalationRequest { class: CapabilityUpgrade, requested_scope: CapabilityUpgrade { WriteSecrets } }`. Kernel writes `Pending` row, emits `EscalationSubmitted`. Operator runs `raxis-cli escalation approve <escalation_id> --scope <capability_class> --max-uses <n> --valid-for <seconds>` (Part 4). Kernel writes `ApprovalToken`, moves escalation to `Approved`, emits `EscalationApproved`. Planner presents token on next intent. `validate_approval_token` runs all eight checks (steps 0–7), returns `Ok(ApprovalStatus::Valid)`. Kernel executes action, writes `ApprovalProof`, moves escalation to `Consumed`, writes nonce to consumed-nonce table. Verify: escalation row is `Consumed`; `ApprovalProof` row exists; nonce table entry present.
- **Escalation — expired token:** Same flow as happy path, but planner waits until after `token.scope.valid_until`. Kernel timeout sweep fires, moves escalation to `TokenExpired`, emits `ApprovalTokenExpired`. Planner presents the expired token; `validate_approval_token` check 3 returns `ApprovalStatus::Expired`. Action does not execute. Verify: escalation row is `TokenExpired`; no `ApprovalProof` row; no nonce table entry.
- **Escalation — denied:** Operator runs `raxis-cli escalation deny <escalation_id>`. Kernel moves escalation to `Denied`, emits `EscalationDenied`. Verify: escalation row is `Denied`; any subsequent attempt to transition the row is rejected by the kernel (terminal-state immutability rule).
- **Escalation — timeout without operator action:** Planner submits escalation. `timeout_at` elapses with no operator action. Kernel timeout sweep fires, moves escalation to `TimedOut`, emits `EscalationTimedOut`. Verify: escalation row is `TimedOut`; associated task remains in its pre-escalation state (no forced `BlockedRecoveryPending` transition).
- **Escalation — epoch mismatch:** Operator approves escalation, issues token at epoch N. Policy epoch advances to N+1 before planner presents token. `validate_approval_token` check 2 returns `ApprovalStatus::EpochMismatch`. Action does not execute. Escalation remains `Approved` (token is invalid; operator must re-issue). Verify: escalation stays `Approved`; no `ApprovalProof`; no nonce consumed; `EpochMismatch` audit entry.
- **Escalation — nonce replay:** Planner presents valid token, action executes (`Consumed`). Planner presents the same token a second time. `validate_approval_token` check 4 finds nonce in consumed-nonce table, returns `NonceConsumed`. Action does not execute. Verify: second presentation produces no `ApprovalProof`; no state change.
- **Escalation — scope mismatch:** Operator approves `CapabilityUpgrade { WriteCode }`. Planner presents token while requesting `CapabilityUpgrade { WriteSecrets }`. `check_scope` returns `false` (action exceeds scope); `validate_approval_token` step 6 maps that to `Ok(ApprovalStatus::ScopeMismatch)`. Action does not execute. Verify: escalation remains `Approved`; no `ApprovalProof`; scope-mismatch audit entry.
- **Escalation — cross-session rejection:** Token issued with `scope.session_id = A`. Planner session B presents the token. `validate_approval_token` check 5 returns `ScopeMismatch`. Action does not execute. Verify: session B's intent rejected; session A's escalation row unchanged.
- **Escalation — rate-limiter fires:** Planner submits `max_per_window + 1` escalations within `window_secs`. Final submission returns `EscalationResponse::Rejected { reason: RateLimitExceeded }`. Verify: escalation table has exactly `max_per_window` rows for this window; `EscalationRateLimitExceeded` audit entry present; no `(max_per_window + 1)`th escalation row.
- **Escalation — quarantine:** Planner triggers rate-limit `quarantine_threshold` times across multiple windows. On the `quarantine_threshold`th trigger, kernel sets quarantine flag, emits `LineageQuarantined`. Subsequent escalation submissions return `LineageQuarantined` immediately. Verify: quarantine row exists in store; only operator CLI can lift (`raxis-cli quarantine lift <lineage_id>`); no new escalation rows while quarantined.

**Adversarial tests (most important — must pass before Phase A is complete)**
- Planner submits branch ref instead of commit SHA → kernel rejects, no claim inference runs
- Planner submits false touched-path manifest → kernel ignores, derives from VCS independently
- Planner attempts to fabricate a witness: kernel ignores any blob that lacks a kernel-issued `verifier_run_id` in the witness index — the structural assertion is that **file existence in `~/.raxis/witness/` is not evidence**; only an index entry created by the kernel during a kernel-spawned verifier run is evidence
- Planner replays old witness from a previous commit → commit SHA binding check fails, `FAIL_INSUFFICIENT_WITNESS`
- Planner attempts direct provider access (INV-02A): structural proof is that `raxis-planner` has no provider credential store access and no `InferenceRequest`-equivalent IPC type it can forge — if a provider credential or inference-bypass message type ever appears in planner-reachable code, the build fails the trust boundary audit
- Planner attempts direct network fetch without kernel (INV-02B): structural proof is that `raxis-planner` has no HTTP client crate in its dependency closure — the compiler enforces this; any HTTP client dep in `raxis-planner`'s `Cargo.toml` or any transitive dep is a critical build violation; runtime test confirms kernel logs a `FetchExternalDataAudited` event for every external URL the planner successfully consumes
- Planner sends escalation spam → probe-rate limiter fires, lineage enters quarantine after threshold
- Planner sets role/session fields in intent packet → kernel strips fields, rejects if authority fields present in planner-writable position

**Failure-recovery tests**
- Kill kernel mid-initiative → restart → verify in-flight tasks enter `BlockedRecoveryPending`, audit log is intact and chain-verifiable
- Kill kernel mid-audit-write → restart → verify partial JSONL line is detected, segment integrity is recoverable

**Storage integrity tests**
- Manually corrupt a JSONL segment → chain verification detects it at the corrupted segment
- Delete a witness blob → index reconciliation detects orphaned index entry at startup
- Tamper with policy SQLite cache → kernel detects mismatch with signed artifact on load, rebuilds

**Chaos drills (before Phase B)**
- Kill verifier mid-gate → witness never arrives → task stays `TaskState::GatesPending`; after verifier token TTL expires, kernel records `BlockReason::WitnessTimeout` and transitions task to `TaskState::Aborted`. No phantom witness created.
- Expire delegation mid-task → gate recheck returns `ClaimCheckResult::DelegationInsufficient`; task stays `GatesPending` with `BlockReason::DelegationInsufficient`; planner must renew before resubmitting.
- Rotate policy epoch during execution → next delegation use triggers staleness check; renewal required before next gated action.
- Provider gateway timeout on every call → task transitions to `TaskState::Aborted { reason: BlockReason::ProviderTimeout }`; initiative does not complete silently.
- Leave escalation unresolved past timeout → initiative transitions to `InitiativeState::Blocked`, not self-resolved.
- Combined failure (delegation expiry + escalation timeout simultaneously): delegation expiry writes `BlockReason::DelegationInsufficient` on the task whose delegation expired (task-level state change); escalation timeout moves the escalation row to `TimedOut` (escalation-level state change, no `BlockReason` written to the task row — escalation is orthogonal to task state). Both failures are audited independently; unaffected lane tasks continue.

---

#### 1.4 — V1 Release Gates (Phase A → Phase B transition requires all of these)

| Gate | Criterion |
|---|---|
| Adversarial suite | 0 fail-open findings (includes path scope bypass attempts: out-of-scope commit, merge commit injection, rename-masking) |
| Invariant suite | 100% pass on all 11 invariants (INV-01, INV-02A, INV-02B, INV-03 through INV-08, INV-TASK-PATH-01, INV-TASK-PATH-02) |
| Audit replay | Deterministic replay of at least one full initiative from audit log + state |
| Recovery drill | Kernel restart + initiative resume with consistent state |
| Break-glass drill | Break-glass invocation succeeds, completes, is fully audited, and cooldown enforces re-entry block |
| Continuous load | System runs for **minimum 1 hour** under simulated stress (multiple concurrent initiatives, deliberate adversarial inputs) with no fail-open. Note: 1 hour is a smoke gate, not a confidence threshold for a long-running autonomous system; extended soak testing is recommended before production use. |

---

#### 1.5 — Workspace Layout

The RAXIS **repository root** is a Rust workspace when implementation crates land here. If this tree sits inside a larger monorepo (for example `parent/raxis/`), still treat **`raxis/`** as the workspace root for paths below—`cargo` commands, `Cargo.toml` members, and CI scoped to RAXIS all run from this directory.

Normative documentation (`README.md`, `specs/`, `fixtures/`) lives alongside the workspace in this repository; it is not part of the Rust dependency graph.

Every component is a separate crate. This is not organizational preference — it is a trust boundary enforcement mechanism.

**Why Rust crate boundaries matter here:**
The Rust compiler enforces the dependency graph. If `raxis-planner` does not declare a dependency on `raxis-policy`, it cannot call policy functions — at all, not just by convention. If `raxis-planner` does not depend on `raxis-store`, it cannot open the kernel state database. We use the compiler as a structural trust enforcer, not just a syntax checker.

The dependency graph must be designed so that the crates the planner depends on contain *only* what a proposer needs: type definitions, IPC client code, and its own working-cache logic. Nothing else.

```
raxis/                          # repository root (standalone clone or nested subtree)
│
├── Cargo.toml                    # workspace root; defines member crates and shared deps
├── README.md                     # project overview and doc index
├── specs/                        # normative specifications (this document lives under specs/v1/)
├── fixtures/                     # canonical integration fixtures
│
├── crates/                       # shared library crates (no binaries)
│   ├── types/                    # raxis-types
│   ├── crypto/                   # raxis-crypto
│   ├── ipc/                      # raxis-ipc
│   ├── policy/                   # raxis-policy
│   ├── audit/
│   │   ├── writer/               # raxis-audit-tools-writer  (planner-safe: types only)
│   │   └── tools/                # raxis-audit-tools   (kernel/cli: crypto + chain ops)
│   └── store/                    # raxis-store
│
├── kernel/                       # raxis-kernel binary
├── planner/                      # raxis-planner binary
├── gateway/                      # raxis-gateway binary
├── verifier/                     # raxis-verifier binary
├── cli/                          # raxis-cli binary
│
├── tests/
│   ├── adversarial/              # adversarial test suite
│   ├── integration/              # end-to-end integration tests
│   ├── chaos/                    # failure-drill tests
│   └── invariants/               # invariant property tests
│
├── policy-fixtures/              # TEST-ONLY: signed policy artifacts for test harness
│   │                             # !! NOT loaded by production kernel (see guardrail below)
│   ├── epoch-001.policy          # test epoch snapshot, signed with test-only key
│   └── claim-requirements.toml  # claim-requirement table source for test fixtures
│   # GUARDRAIL: production kernel loads policy exclusively from ~/.raxis/policy/.
│   # Test mode is enabled by RAXIS_TEST_POLICY_DIR env var, absent in release builds.
│   # Any code path that loads policy-fixtures/ in a non-test binary is a critical bug.
│
└── genesis/
    ├── README.md                 # human-readable genesis ceremony procedure
    └── bootstrap.sh              # bootstrap ceremony helper (non-privileged portions)
```

> **Checkout shape:** Until implementation crates are merged, this repository may ship as **documentation + fixtures only** (no `Cargo.toml` at the root). §1.5 still defines the **target** workspace layout for implementers.

> **CLI naming:** The binary is **`raxis-cli`**. Some narrative examples abbreviate `raxis …`; treat that as shorthand for `raxis-cli …` unless a different tool is explicitly named.

> **Host isolation vs IPC honesty:** v1 assumes processes voluntarily use typed IPC and crate boundaries; it does **not** prove resistance to a same-UID agent that bypasses UDS, opens `kernel.db` directly, or compromises the planner binary. For the threat model, planned hardening directions, and items that still need gap specs, see [`README.md`](../../README.md) → **Assumptions and Limits** → *Tightening isolation beyond “honest IPC clients”*.

---

#### 1.6 — Shared Library Crates (with rationale for each)

---

##### `crates/types/` — `raxis-types`

**Purpose:** Every structured data type shared across process boundaries lives here and nowhere else.

**Why it exists as a separate crate:** If types were defined in `raxis-kernel`, the planner would need to depend on the kernel crate to deserialize messages — and the kernel crate contains authority logic the planner must not call. Separating types eliminates this dependency entirely.

**What it contains:**
- `src/envelope.rs` — The typed IPC envelope: `session_id`, `lineage_id`, `role_id`, `capability_bitmap`, `request_type`, `target_resource`, `idempotency_key`, `nonce`, `sequence_number`. These are the immutable fields the kernel sets at spawn. The planner can read them (to know its own identity) but cannot produce new ones without going through kernel spawn.
- `src/intent.rs` — Intent packet types: `IntentRequest`, `IntentResponse`. `IntentResponse::Accepted { task_id: TaskId, warn_delegation_stale: bool }` — `warn_delegation_stale` is `true` when `evaluate_claims` detected stale delegation (SufficientStale path) and consumed the grace use; the planner must renew the delegation before the next gated action. `IntentResponse::Rejected { reason: PlannerErrorCode }`. Intent packets carry no authority-bearing fields (no capabilities or signing keys). Requests carry VCS pins (`base_commit_sha`, `head_commit_sha`), `intent_kind`, planner-supplied claim manifests, `request_type`, `target_resource`, `justification_blob` (opaque to kernel policy), and `idempotency_key`. **Task binding:** `IntentRequest` carries `task_id: TaskId` — the kernel uses this to bind the intent to the correct task row. For the initial pick-up of a task (`Admitted → Running`), the planner supplies the `task_id` returned by `next_ready_tasks`. For subsequent intents on the same in-flight task (`Running`), the planner repeats the same `task_id`; the kernel validates it against the session's in-flight task context without re-running `next_ready_tasks`. **Cost guardrail:** `IntentRequest` must not contain any field named `estimated_cost`, `cost`, `budget_units`, `cost_hint`, or any semantic equivalent, including serde-renamed fields (`#[serde(rename = "...")]`) that deserialize to a cost-adjacent value. If a future version adds a planner-supplied cost hint for observability, it must be named `planner_cost_hint: Option<u64>` and must be explicitly excluded from any code path reaching `compute_admission_cost` or `consume_budget` — it may appear only in audit records. Structural test: grep for any `IntentRequest` field (including serde aliases) appearing as an argument or binding in `compute_admission_cost` or `consume_budget`; any match is a critical trust violation.
- `src/witness.rs` — Witness record types: `WitnessRef`, `WitnessBundle`, `GateVerdict`. `WitnessRef` binds `evaluation_sha` (the `head_commit_sha` of the range intent the gate was evaluated against — renamed from `commit_sha` to match `WitnessRecord`, `WitnessSubmission`, and `AuditEventKind::WitnessAccepted`; no aliases, one canonical name), `task_id`, `gate_type`, `verifier_run_id`, `generated_at`, `result_class`. `GateVerdict` is the coarse verdict the planner receives: `Pass`, `FailMissingWitness`, `FailInsufficientWitness`, `FailPolicyViolation`.
- `src/initiative.rs` — Initiative and task FSM state types: `InitiativeState` enum (`Draft`, `ApprovedPlan`, `Executing`, `Blocked`, `Completed`, `Failed`, `Aborted`), `TaskState` enum (`Admitted`, `GatesPending`, `Running`, `Completed`, `Failed`, `Aborted`, `Cancelled`, `BlockedRecoveryPending`), `BlockReason` enum.
  - **`Admitted`**: the non-terminal stored state for tasks that are not `GatesPending`, `Running`, `BlockedRecoveryPending`, or terminal. Whether a specific `Admitted` task is returned by `next_ready_tasks` (and therefore schedulable) is determined at query time from the DAG edge table — no separate `Ready` state is needed because readiness is a derived query, not a stored flag.
  - **`GatesPending`**: task admitted to the scheduler but blocking on outstanding verifier witnesses. Not returned by `next_ready_tasks`. Transitions to `Admitted` when `handlers/witness.rs` gate-recheck returns `Pass` for all outstanding gates.
  - **`Running`**: planner has taken a work turn on this task.
  - **`Completed` / `Failed` / `Aborted`**: terminal states. `Aborted` always carries a `BlockReason` field (e.g. `BlockReason::WitnessTimeout`, `BlockReason::DelegationInsufficient`, `BlockReason::ProviderTimeout`) — it is never set without a typed reason. `Failed` and `Aborted` are distinct: `Failed` is a planner-reported task failure (the work was attempted and did not meet success criteria); `Aborted` is a kernel-recorded infrastructure failure (the task could not proceed due to a gate, delegation, or provider fault).
  - **`Cancelled`**: bulk-terminated task (initiative-level abort or criteria-driven mass-cancel); distinct from per-task **`Aborted`** with **`OperatorAbort`** via `raxis-cli task abort`. Recovery leaves `Cancelled` tasks in place — they do not transition to `BlockedRecoveryPending`.
  - **`BlockedRecoveryPending`**: set by `recovery::reconcile_tasks` for in-flight tasks that were interrupted mid-execution and require operator review before resuming.
- `src/delegation.rs` — Delegation types: `Delegation`, `CapabilityClass` enum, `DelegationStatus` enum (`Active`, `StaleOnNextUse`, `Expired`, `RenewalRequired`).
- `src/escalation.rs` — Escalation types:
  - `EscalationClass` enum: `CapabilityUpgrade` | `DelegationRenewal` | `BudgetException` | `QualityGateException`. Each class corresponds to a distinct authority gap the planner cannot resolve autonomously.
  - `RequestedEscalationScope` enum — what the planner is specifically requesting:
    - `CapabilityUpgrade { capability: CapabilityClass }` — capability not in current session delegation
    - `DelegationRenewal { delegation_id: DelegationId }` — renewing an `Expired` or `RenewalRequired` delegation
    - `BudgetException { additional_units: u64 }` — requesting headroom above `max_cost_per_task` or `max_cost_per_epoch`
    - `QualityGateException { gate_type: GateType, task_id: TaskId }` — requesting a quality gate bypass (ad-hoc; distinct from policy `override_rules` which are pre-authorized)
  - `EscalationRequest` — submitted by planner via IPC:
    - `task_id: TaskId` — which task requires this escalation (must exist and belong to `session_id`)
    - `class: EscalationClass`
    - `requested_scope: RequestedEscalationScope`
    - `justification: String` — opaque to kernel policy; logged verbatim in audit record; planner-supplied
    - `idempotency_key: Uuid` — planner-supplied; prevents duplicate escalation rows on IPC retry
    - Note: `escalation_id`, `session_id`, and `submitted_at` are **kernel-assigned** and are not present in the request; they are set by `handlers/escalation.rs`.
  - `EscalationStatus` enum: `Pending` | `Approved` | `Denied` | `TimedOut` | `TokenExpired` | `Consumed`
    - `Pending`: submitted, awaiting operator action. Non-terminal.
    - `Approved`: operator issued an `ApprovalToken`; token not yet consumed. Non-terminal.
    - `Denied`: operator explicitly denied via CLI. Terminal.
    - `TimedOut`: `timeout_at` passed without operator action. Terminal. The task the escalation was for remains in its current state; the planner may submit a new escalation.
    - `TokenExpired`: operator approved (`Approved` state) but the token's `valid_until` elapsed before the planner presented it. Terminal. The planner must submit a new escalation.
    - `Consumed`: approval token successfully presented and action executed. Terminal.
- `src/approval.rs` — Approval types:
  - `ApprovalScope` — the operator-declared predicate bounding what the token authorizes. The kernel enforces `ApprovalScope ⊆ EscalationRequest.requested_scope` when the operator runs `raxis-cli escalation approve` — the CLI cannot grant broader authority than the escalation requested; any attempt is rejected before the `Approved` state transition is written. **Defense in depth:** at consume time (when `validate_approval_token` returns `Valid` and the action is about to execute), the kernel additionally loads the escalation row and verifies `token.scope ⊆ escalation.requested_scope` before writing the `ApprovalProof`. This catches any client — scripted raw IPC or future non-CLI tooling — that bypasses the CLI validation step.
    - `class: EscalationClass`
    - `session_id: SessionId` — token is bound to this session; presented by any other session → invalid
    - `allowed_capability: Option<CapabilityClass>` — required (non-`None`) when `class = CapabilityUpgrade`; `None` for all other classes where the capability dimension is not applicable. A `CapabilityUpgrade` scope with `allowed_capability: None` is malformed and rejected at CLI issuance.
    - `allowed_path_glob: Option<String>` — optional path restriction. `None` = no path restriction within the approved class (broadest within class). Operators should prefer explicit globs for security-sensitive capabilities.
    - `allowed_intent_kinds: Option<Vec<IntentKind>>` — optional intent kind restriction. `None` = no intent kind restriction within the approved class.
    - `valid_until: DateTime<Utc>` — token expiry; operator sets this explicitly via `--expiry`
  - `ApprovalToken` — the operator-signed artifact:
    - `approval_id: Uuid`
    - `escalation_id: Uuid` — links back to the escalation record
    - `session_id: SessionId`
    - `scope: ApprovalScope`
    - `policy_epoch: u64` — epoch at time of issuance; token is invalidated if `current_epoch != policy_epoch`
    - `nonce: [u8; 32]` — prevents replay; kernel checks this nonce has not been consumed
    - `issued_at: DateTime<Utc>` — set by the CLI at signing time and included in the signed payload. The kernel trusts this value as part of signature verification (it is covered by the Ed25519 signature), not as an independently verified claim. The kernel does not use `issued_at` for any enforcement decision — enforcement uses `scope.valid_until` (step 3 of `validate_approval_token`).
    - `issued_by: OperatorId` — must appear in `policy.operators`
    - `signature: [u8; 64]` — Ed25519 over the canonical serialization of all fields above, signed with the operator's private key
  - `ApprovalProof` — the kernel-signed execution record created when a token is consumed:
    - `action_id: Uuid` — the specific kernel action (intent admission, delegation renewal, etc.)
    - `approval_id: Uuid`
    - `escalation_id: Uuid`
    - `session_id: SessionId`
    - `scope: ApprovalScope` — copied from the consumed token
    - `execution_timestamp: DateTime<Utc>` — kernel-set; when the escalated action actually executed
    - `policy_epoch: u64`
    - `nonce: [u8; 32]` — same nonce from the consumed `ApprovalToken`
    - `kernel_signature: [u8; 64]` — Ed25519 over proof fields, signed with `registry.authority_keypair`
  - `ApprovalStatus` enum: `Valid` | `Expired` | `EpochMismatch` | `NonceConsumed` | `ScopeMismatch`
- `src/audit.rs` — Audit event types: `AuditEvent`, `AuditEventKind` enum. Every kernel decision has a corresponding `AuditEventKind` variant. The planner can produce `ProposalEvent` variants only. Key variants: `FetchExternalDataAudited { fetch_request_id, url, fetched_at, response_sha256, content_type, byte_len, allowed_by_domain_allowlist }` — emitted by the kernel before any fetch response is returned to the planner; this is the record that makes planner context inputs reproducible for INV-05. `FetchDenied { fetch_request_id, url, deny_reason: FetchDenyReason, session_id }` — emitted for every denied fetch regardless of deny path; `FetchDenyReason` enum: `DomainNotAllowed` (allowlist check) | `RateLimitExceeded` (quota check). Both deny paths emit this single variant so operator audit queries need only filter on `FetchDenied` to see all denied fetches; `deny_reason` provides sub-classification. `BudgetOverrun { task_id, lane_id, estimated_cost: u64, actual_cost: u64, delta: u64, planner_reported: bool }` — emitted by `budget::reconcile_actual_cost` when `actual_cost > estimated_cost`; `planner_reported: true` when the source is `ActualCostSource::PlannerReported`; enforcement-grade analysis must filter on `planner_reported = false`. `SuccessorSchedulable { task_id: TaskId, unblocked_by: TaskId, initiative_id: InitiativeId, at: Timestamp }` — emitted by `store::dag::release_successors` when a predecessor reaches `Completed` and a successor's full predecessor set is now satisfied; the successor's task row state remains `Admitted` (no transition); this event signals that `next_ready_tasks` will now include the successor. `InitiativeBlocked { initiative_id: InitiativeId, at: Timestamp }` — emitted by `evaluate_terminal_criteria` when it detects that `next_ready_tasks` is empty and no task is `Running`, transitioning `Executing → Blocked`. `InitiativeResumed { initiative_id: InitiativeId, at: Timestamp, resumed_by: Option<OperatorId> }` — emitted by `evaluate_terminal_criteria` when it detects that `next_ready_tasks` is non-empty or a task is `Running`, transitioning `Blocked → Executing`. `resumed_by` is `Some(operator_id)` when the unblock was triggered by an operator `raxis task resume` command (the operator identity flows from `TransitionActor::Operator` into `evaluate_terminal_criteria`'s context); `None` when the unblock is kernel-automatic (witness clearance, DAG predecessor completion). Per-task attribution for automatic unblocks is available on the triggering `TaskTransitioned` event.
- `src/lane.rs` — Lane schema: `Lane`, `PriorityClass` enum, `LaneStatus`.
- `src/policy_epoch.rs` — `PolicyEpoch` type (monotonic counter, not a timestamp), `EpochRef`.

**Who depends on it:** Every crate. This is the only crate that all processes share.

**What it must NOT contain:** Any logic, any kernel state, any policy evaluation code. Types only. Serialization derives (`serde`) are fine.

---

##### `crates/crypto/` — `raxis-crypto`

**Purpose:** All cryptographic operations: signing, verification, token generation, nonce management, hash computation.

**Why it exists as a separate crate:** Cryptographic primitives are security-critical and must be centrally maintained. If each binary implements its own signing, subtle incompatibilities and vulnerabilities appear. Centralizing also means auditing one crate for all crypto behavior.

**What it contains:**
- `src/signing.rs` — Sign and verify policy artifacts. Wraps a signing backend (v1: `ring` or `ed25519-dalek`). The authority signing key and quality signing key have different key types registered in the key registry — this is enforced here, not by convention. **Note on approval tokens:** `ApprovalToken` signing is performed by the operator CLI using the operator's own private key (not the kernel's authority keypair) and is not part of this module's responsibility. Verification of approval tokens uses `policy.operator_entry(token.issued_by).public_key` loaded from the policy artifact — see `authority/approval.rs`.
- `src/token.rs` — Token generation and verification, split by token class:
  - *Session and process tokens* (`planner_session_token`, `gateway_process_token`): random 256-bit values bound to their respective identity (session ID or spawn UUID). Generated at spawn, verified on every IPC message via constant-time comparison. **Reusable within TTL** — the same token authenticates every message in that session or process lifetime.
  - *Approval tokens*: generated by the operator CLI and signed with the **operator's own private key** (from `[[operators.entries]]` in the policy artifact — a key the operator holds, not the kernel's authority keypair). The kernel verifies the signature using the public key from `policy.operator_entry(token.issued_by)`. **Strictly single-use** — the kernel marks the token consumed on first valid presentation; a second presentation returns `UNAUTHORIZED` regardless of expiry. The distinction matters: session tokens are authentication tokens (identity over time); approval tokens are authorization vouchers (one specific action, one time only). The kernel's `authority_keypair` is used only to sign `ApprovalProof` records after a token is consumed — never to sign the token itself.
- `src/nonce.rs` — Types/helpers for envelope nonces where needed outside `ipc/auth.rs`. **INV-01 replay prevention** for planner sessions is enforced by the `nonce_cache` store transaction in `ipc/auth.rs` (§2.5.1 Table 16): duplicate `(session_id, envelope_nonce)` → planner-facing `UNAUTHORIZED`, not `INVALID_REQUEST`.
- `src/hash.rs` — SHA-256 content hashing for witness blobs and audit chain links. Centralizing this ensures hash format consistency across audit segments and witness blobs.
- `src/keyring.rs` — Key registry: loads key entries from the policy store, provides a typed lookup (`AuthorityKey`, `QualityKey`, `VerifierTokenKey`). The authority key and quality key are different entries with different capability grants — the compiler enforces this by making them separate types.

**Who depends on it:** `raxis-kernel`, `raxis-cli`, `raxis-audit-tools`, `raxis-policy`. `raxis-audit-tools-writer` intentionally does NOT depend on this crate — keeping it crypto-free is what makes the planner's transitive closure safe.

**What must NOT depend on it:** `raxis-planner` (the planner never touches signing keys), `raxis-gateway`, `raxis-verifier`. If the planner could call `crypto::signing::sign()`, it could forge approval tokens.

---

##### `crates/ipc/` — `raxis-ipc`

**Purpose:** The Unix Domain Socket message protocol — framing, serialization, authentication, and client/server helpers.

**Why it exists as a separate crate:** The kernel and every process that talks to it (planner, gateway, verifier) need compatible framing and serialization. Defining this in one crate means a schema change is a compile error everywhere simultaneously — no silent protocol drift.

**What it contains:**
- `src/frame.rs` — Length-prefixed message framing over UDS. Every message is `[4-byte length][payload bytes]`. The kernel reads the length, allocates exactly that buffer, then deserializes. This bounds memory allocation per message and prevents partial-read ambiguity.
- `src/message.rs` — `IpcMessage` enum: `KernelRequest(IntentRequest)`, `KernelResponse(IntentResponse)`, `InferenceRequest(...)`, `InferenceResponse(...)`, `FetchRequest(FetchRequest)`, `FetchResponse(FetchResponse)`, `WitnessSubmission(...)`, `WitnessAck(...)`, `EscalationRequest(EscalationRequest)`, `EscalationResponse(EscalationResponse)`. Every variant is typed; the kernel pattern-matches on the variant, never on a string field. `EscalationRequest` and `EscalationResponse` are planner-facing only — verifier sessions may not send `EscalationRequest` (dispatcher rejects on session role check). `WitnessAck` is an enum: `Accepted { verifier_run_id, remaining_gates }` on success, or `Rejected { reason }` (e.g. `EvaluationShaMismatch` when `head_commit_sha` does not match the task row's `evaluation_sha` — see `handlers/witness.rs`). `FetchRequest` carries `{fetch_request_id, url, max_bytes, accepted_content_types}`; `FetchResponse` carries `{fetch_request_id, response_sha256, content_type, byte_len, body}`. The kernel validates the URL against the domain allowlist before forwarding to the gateway; a blocked URL returns `FetchDenied` without logging the content (only the attempt is audited).
- `src/auth.rs` — Session token attachment and validation helpers on the **client side** (used by planner, gateway, verifier processes). Every outbound message attaches its token via `auth::attach_token(msg, token_bytes)`. The exported `auth::validate_token()` in this crate is a client-side pre-send sanity check (format / length), not the authoritative kernel authentication. The kernel's authoritative auth is in `raxis-kernel/src/ipc/auth.rs` (`AuthValidator::validate`), which runs on the server side after the frame is received. The two layers are distinct: `raxis-ipc/auth.rs` is transport plumbing; `kernel/ipc/auth.rs` is trust enforcement.
- `src/client.rs` — A typed UDS client used by the planner, gateway, and verifier to open a connection to the kernel socket, attach their token, and send/receive typed messages.
- `src/server.rs` — A typed UDS server used by the kernel to accept connections, read tokens, and dispatch messages to registered handlers.
- `src/schema_version.rs` — A `SCHEMA_VERSION` constant. Both client and server must agree on schema version at handshake; version mismatch causes connection rejection with an error that tells the operator which binary is stale.

**Who depends on it:** `raxis-kernel`, `raxis-planner`, `raxis-gateway`, `raxis-verifier`.

**Who must NOT depend on it:** `raxis-types` (types have no IPC dependency — they must serialize cleanly without knowing how they are transported), `raxis-crypto` (crypto has no network dependency).

---

##### `crates/policy/` — `raxis-policy`

**Purpose:** Load, verify, and provide read access to the signed policy store. This crate is the only authorized reader of policy artifacts.

**Why it exists as a separate crate:** If policy loading were inlined in the kernel binary, the same logic might be copy-pasted into the planner "for convenience." As a separate crate with a type-safe API, the planner is physically prevented from linking it (its `Cargo.toml` simply does not list it as a dependency).

**What it contains:**
- `src/loader.rs` — Load and verify signed policy artifacts. Load sequence:
  1. Read raw bytes of `policy.toml` from the provided path.
  2. Read raw bytes of `policy.sig` (same directory, same stem, `.sig` extension).
  3. Call `raxis-crypto::ed25519_verify(authority_public_key, policy_toml_bytes, sig_bytes)`. On failure → `PolicyError::SignatureInvalid`; exit `BOOT_ERR_POLICY_INVALID` at boot, `PolicyError::SignatureInvalid` at `advance_epoch`.
  4. Parse TOML: `toml::from_slice::<RawPolicyArtifact>(policy_toml_bytes)`. On parse failure → `PolicyError::MalformedArtifact { detail }`.
  5. Check `raw.meta.schema_version`. If `> LOADER_SUPPORTED_MAX` → `PolicyError::PolicySchemaUnsupported { found, max_supported }` (fail-closed; kernel cannot honestly enforce fields it does not understand). If in `[LOADER_SUPPORTED_MIN, LOADER_SUPPORTED_MAX - 1]` → emit `AuditEventKind::PolicySchemaDeprecated { schema_version, current_max }` and continue loading. If missing required blocks for the parsed schema version → `PolicyError::MalformedArtifact`. `LOADER_SUPPORTED_MIN` and `LOADER_SUPPORTED_MAX` are compile-time constants; in v1 both equal `1`.
  6. Check `raw.meta.epoch > store.read_current_epoch()` where `store.read_current_epoch()` returns `0` if the store has never recorded an epoch (genesis boot). The comparison is strictly greater than — loading the same epoch twice is rejected as `PolicyError::EpochReplay`. This rule is identical at boot and at `advance_epoch`; the only difference at genesis is that `read_current_epoch()` returns `0`, which any valid first artifact (epoch ≥ 1) satisfies.
  7. Construct and return `PolicyBundle` (see `src/bundle.rs`).
  - No panic; all errors are typed `PolicyError` variants.
- `src/bundle.rs` — **[NEW]** `PolicyBundle` struct and accessor methods. Constructed by `loader::load_and_verify`. This is the in-memory, fully validated representation of a loaded policy artifact. Wrapped in `ArcSwap<PolicyBundle>` by `policy_manager.rs`.
  - `pub fn base_cost_for_intent_kind(&self, kind: IntentKind) -> Option<u64>` — returns `None` if kind absent from `budget.base_cost_per_intent_kind`; callers treat `None` as `UnknownIntentKindCost`.
  - `pub fn cost_per_touched_path(&self) -> u64`
  - `pub fn max_cost_per_task(&self) -> u64`
  - `pub fn required_claims(&self, touched_paths: &[PathBuf]) -> Vec<ClaimType>` — delegates to `claim_table::evaluate`. For each path individually, finds the first matching rule (or implicitly applies `StrictDefault` if no rule matches that path). Returns the **union** of all per-path claim types across the full `touched_paths` slice — not a single-path result, not an intersection. A planner must hold the complete union to pass gate evaluation; a single path requiring `SecurityReview` forces the requirement across the entire intent regardless of other paths.
  - `pub fn ceiling_for_role(&self, role: &RoleId) -> CapabilityBitmap` — if `role` is not present in `role_ceilings`, returns `CapabilityBitmap::EMPTY`. `authority::create_session` treats an `EMPTY` ceiling (from an unknown role) as `SessionError::UnknownRole` and rejects session creation — parallel to `UnknownIntentKindCost` rejecting at admission. Unknown roles fail closed at session creation, not at first intent.
  - `pub fn max_fetches_per_window(&self) -> u64`
  - `pub fn domain_allowlist(&self) -> &[Domain]`
  - `pub fn lane_config(&self, lane_id: &LaneId) -> Option<&LaneConfig>`
  - `pub fn all_lanes(&self) -> &[(LaneId, LaneConfig)]`
  - `pub fn override_rules(&self) -> &[QualityExceptionRule]`
  - `pub fn key_entry(&self, key_id: &KeyId) -> Option<&KeyEntry>`
  - `pub fn operator_entry(&self, operator_id: &OperatorId) -> Option<&OperatorEntry>`
  - `pub fn max_concurrent_verifiers(&self) -> u32`
  - `pub fn verifier_token_ttl(&self) -> Duration`
  - `pub fn schema_version(&self) -> u32`
  - `pub fn epoch(&self) -> u64`
  - `pub fn issued_at(&self) -> DateTime<Utc>`
  - `pub fn issued_by(&self) -> &OperatorId`
- `src/epoch.rs` — Track current `PolicyEpoch`. Increment on each successfully loaded and verified policy update. Emit an audit event on every epoch change.
- `src/claim_table.rs` — Path-pattern → claim-type evaluation. `fn evaluate(rules: &[ClaimRule], touched_paths: &[PathBuf]) -> Vec<ClaimType>`. Called once for the full `touched_paths` slice. For each path individually: normalize to POSIX form, then walk the ordered rule list and use the first matching rule (first-match-wins per path). If no rule matches a given path, `StrictDefault` is added for that path. The function returns the **union** of all per-path claim types with duplicates deduplicated. A path with no matching rule contributes `[StrictDefault]` to the union — it never contributes nothing.
- `src/role_ceilings.rs` — Role capability ceilings. `fn ceiling_for_role(role: &RoleId, ceilings: &RoleCeilingTable) -> CapabilityBitmap`.
- `src/key_registry.rs` — Key and operator entry loading from the parsed artifact. Returns `KeyEntry` and `OperatorEntry` structs.
- `src/override_rules.rs` — Quality exception rules: gate type, permitted signer roles, max expiry duration. Authority override rules are hardcoded in the kernel and not loaded from here (circular trust problem).

**Who depends on it:** `raxis-kernel`, `raxis-cli`.

**Who must NOT depend on it:** `raxis-planner`, `raxis-gateway`, `raxis-verifier`.

---

#### Policy Artifact On-Disk Format

**Two-file layout.** Every policy artifact consists of exactly two files residing in the same directory:

| File | Role |
|---|---|
| `policy.toml` | Human-readable policy content; the operator-reviewed document |
| `policy.sig` | Detached Ed25519 signature over the exact raw bytes of `policy.toml` |

The loader reads both files. It verifies the signature before parsing any TOML content. Operators may inspect `policy.toml` directly; `policy.sig` contains exactly 64 bytes — the raw Ed25519 signature output with no header, no key-id prefix, no algorithm identifier, and no length encoding. `raxis-crypto::ed25519_verify(authority_public_key, policy_toml_bytes, sig_bytes)` receives these 64 bytes directly as the `sig_bytes` parameter; CLI and loader must agree on this wire format — no framing layer is permitted between the 64 signature bytes and the file boundary.

**Signature contract.** The signature covers the exact bytes written to `policy.toml` as read from disk — no normalization, no canonicalization. Post-sign editing of `policy.toml` (including whitespace or comment changes) invalidates the signature. The ceremony tool (Part 3 / `raxis-cli`) is the canonical generator of both files; operators review the TOML before the tool signs, not after.

**Schema.** The canonical `policy.toml` schema for `schema_version = 1`:

```toml
[meta]
schema_version = 1                        # u32; loader fails-closed if > LOADER_SUPPORTED_MAX
epoch = 42                                # u64; strictly monotonic; loader rejects if <= current epoch
issued_at = "2026-04-29T19:00:00Z"       # RFC 3339 timestamp
issued_by = "operator-alice"             # OperatorId; must appear in [[operators.entries]]

[budget]
cost_per_touched_path = 1                # u64; global weight per touched path (admission formula)
max_cost_per_task = 1000                 # u64; absolute ceiling on compute_admission_cost output

[budget.base_cost_per_intent_kind]
# Every IntentKind variant in raxis-types MUST have a row here.
# Absent variant → UnknownIntentKindCost at admission (FAIL_POLICY_VIOLATION).
# See coordinated-release guardrail in intent.rs and budget.rs specs.
SingleCommit      = 10
MergeIntegration  = 50
RevertCommit      = 5
AmendCommit       = 10
PRGateEvaluation  = 20

[egress]
max_fetches_per_window = 100             # u64; stamped into session.fetch_quota at session creation

[egress.domain_allowlist]
# Exact domain matching. No glob expansion. Each entry is a bare hostname.
# Subdomain wildcard entries ("*.example.com") are not permitted in v1.
domains = [
  "api.example.com",
  "docs.example.com",
]

# Lane definitions — one [[lanes]] entry per lane_id.
# All enforcement parameters (concurrency ceiling, cost ceiling) are inside the signed artifact.
# Unsigned lane configuration does not exist — any lane parameter change requires a signed epoch advance.
[[lanes]]
lane_id           = "default"
priority_class    = "Normal"             # PriorityClass: Normal | High | Critical
max_concurrent_tasks = 4                # u32
max_cost_per_epoch   = 5000             # u64; resets on epoch advance
fairness_weight      = 1.0              # f64; relative scheduling weight
stall_threshold_secs = 300              # u32; seconds before lane stall audit event fires

[[lanes]]
lane_id           = "high_priority"
priority_class    = "High"
max_concurrent_tasks = 2
max_cost_per_epoch   = 10000
fairness_weight      = 2.0
stall_threshold_secs = 120
# Lane note: the [[lanes]] section is the single source of truth for lane configuration.
# At advance_epoch time, the kernel reconciles the store lanes table against
# PolicyBundle::all_lanes(): lanes absent from the new policy are removed, new lanes are
# upserted. The store lanes table is a runtime replica; implementers must not add lane
# fields to the store schema that are absent from LaneConfig. There is no second source.

# Claim requirements — ordered list; first matching rule wins per path.
# Paths are normalized to POSIX form before matching (see path normalization below).
# The catch-all "**" rule is optional — omitting it produces identical behavior because
# any unmatched path implicitly contributes StrictDefault to the union. Include it
# explicitly to make the policy self-documenting; its presence or absence does not
# change enforcement.
[[claim_requirements.rules]]
pattern = "src/authority/**"
claims  = ["AuthorityModification", "SecurityReview"]

[[claim_requirements.rules]]
pattern = "src/ipc/**"
claims  = ["IPCModification", "SecurityReview"]

[[claim_requirements.rules]]
pattern = "**"
claims  = ["StrictDefault"]

[role_ceilings]
# Role → permitted capability list. Capabilities outside this list cannot be delegated to the role.
[role_ceilings.planner]
capabilities = ["WriteCode", "ReadFiles", "FetchExternal"]

[role_ceilings.verifier]
capabilities = ["ReadFiles", "RunGate"]

# Quality exception rules — authority override rules are hardcoded in the kernel, not here.
[[quality_exceptions.rules]]
gate_type    = "LintGate"
signer_roles = ["tech-lead"]             # OperatorId roles permitted to sign an exception
max_expiry_secs = 86400

[[quality_exceptions.rules]]
gate_type    = "TestCoverageGate"
signer_roles = ["tech-lead", "eng-manager"]
max_expiry_secs = 3600

[verifier_limits]
max_concurrent_verifiers = 16           # u32; global cap; overrides kernel default
spawn_queue_max          = 64           # u32; pending spawn queue ceiling
verifier_token_ttl_secs  = 300         # u32; single-use verifier token TTL

# Non-authority keys: verifier output signing keys, quality-gate signing keys, etc.
# The authority keypair is NOT here (signing the artifact with a key embedded in the artifact is circular).
[[keys.entries]]
key_id           = "verifier-signing-key-001"
public_key_base64 = "..."               # base64-encoded Ed25519 public key
permitted_ops    = ["VerifierOutput"]
valid_until      = "2027-01-01T00:00:00Z"

# Operator entries — public keys for humans authorized to sign approvals, activate breakglass, etc.
[[operators.entries]]
operator_id      = "alice"
public_key_base64 = "..."
permitted_ops    = ["SignApproval", "ActivateBreakglass", "SignQualityException"]
```

**Path normalization rules** (applied in `claim_table::evaluate` before glob matching):

1. Normalize to POSIX separators (replace `\` with `/` on all platforms).
2. Strip any leading `/` or `./` prefix.
3. Resolve no `..` segments — any path containing `..` after VCS derivation is a kernel error (`VcsError::TraversalPath`), not a policy evaluation input.
4. Paths are case-sensitive. Pattern matching is case-sensitive on all platforms.
5. First-match-wins over the rule list in declaration order. Ties are not possible under first-match; order is total and determined by TOML array position.
6. **Operator ordering requirement:** rules must be listed from most specific to least specific in the artifact; the catch-all `**` must appear last. The loader does not sort or reorder rules. A rule higher in the list shadows any rule below it for paths that match both. This is a documentation convention enforced by operator discipline, not by the loader — consistent with `policy_lookup::required_claims` declaration-order semantics.

**Schema versioning rules:**

| Condition | Loader behavior |
|---|---|
| `schema_version > LOADER_SUPPORTED_MAX` | `PolicyError::PolicySchemaUnsupported` → fail-closed. Kernel cannot enforce fields it does not understand. |
| `schema_version == LOADER_SUPPORTED_MAX` | Normal load. |
| `schema_version in [LOADER_SUPPORTED_MIN, LOADER_SUPPORTED_MAX - 1]` | **In v1 this row is never triggered** — `LOADER_SUPPORTED_MIN == LOADER_SUPPORTED_MAX == 1`, so no deprecation band exists. When a future schema bump creates this band, the loader must enumerate explicitly which new fields have safe defaults vs. fail-closed behavior; blanket silent-default is not permitted. |
| `schema_version < LOADER_SUPPORTED_MIN` | `PolicyError::PolicySchemaUnsupported` → reject. |

> **v1 rule:** `LOADER_SUPPORTED_MIN = LOADER_SUPPORTED_MAX = 1`. Any artifact with `schema_version != 1` is rejected. No deprecation path, no migration code. When v2 introduces a new schema field, the schema bump and the field-level safe-default table must be documented together before the first artifact with the new version is shipped.

**New audit event:**
- `AuditEventKind::PolicySchemaDeprecated { schema_version: u32, current_max: u32, policy_path: PathBuf }` — emitted on successful load of a schema version below `LOADER_SUPPORTED_MAX`. Signals to operators that the policy artifact should be re-exported and re-signed to the current schema format.

---

##### `crates/audit/` — split into two sub-crates


The audit crate is split to prevent transitive coupling: if a single audit crate depends on `raxis-crypto` (for chain hashing) and `raxis-planner` depends on audit, the planner gains an indirect crypto dependency — which enables signing operations the planner must not have.

---

###### `crates/audit/writer/` — `raxis-audit-tools-writer`

**Purpose:** The minimal, policy-free, crypto-free audit append path. This is the only audit sub-crate the planner may link.

**Dependencies:** `raxis-types` only. No crypto, no policy, no store.

**Why no crypto dependency:** The writer does not compute chain hashes itself — it serializes the event payload and delegates to the kernel's audit IPC endpoint for chain linking. In-process callers (kernel itself) use `raxis-audit-tools` which has the crypto dependency. Out-of-process callers (planner) go through IPC. This eliminates the transitive crypto path entirely.

**What it contains:**
- `src/event.rs` — `fn append_proposal(event: ProposalEvent) -> Result<()>`. Accepts only `ProposalEvent` variants — enforced by the type signature, not a runtime check. Sends the event to the kernel's audit IPC endpoint. The planner never touches a file handle.
- `src/proposal_event.rs` — `ProposalEvent` type: a restricted subset of `AuditEventKind` containing only `PlanProposed`, `IntentSubmitted`, `AmendmentProposed`. No decision, grant, or denial variants.

**Who depends on it:** `raxis-planner` only.

**Who must NOT depend on it:** No other component needs this crate. The kernel uses `raxis-audit-tools` for all its audit writes.

---

###### `crates/audit/tools/` — `raxis-audit-tools`

**Purpose:** Full audit functionality: chain-linked writing, chain verification, segment management, retention logic. Used by kernel and CLI only.

**Dependencies:** `raxis-types`, `raxis-crypto`.

**Concurrency model — process-level, not just thread-level:** The kernel is the single authoritative writer for authority events. The planner sends proposal events to the kernel's IPC endpoint; the kernel serializes them into the chain. There is no multi-process concurrent write to the same segment file — the kernel owns the file handle for its duration. This is the single-writer service model: the kernel process is the audit service, other processes submit events through it.

**What it contains:**
- `src/writer.rs` — `fn append(event: AuditEvent) -> Result<()>`. Reads the previous event's hash, computes the chained hash (`sha256(prev_hash || event_bytes)`), serializes to JSONL, and `fsync`s. Internally mutex-guarded for concurrent kernel threads. This function is `pub(crate)` — external processes cannot call it directly.
- `src/segment.rs` — Segment file management: naming (`audit-000001.jsonl`), size-based rotation (50MB per segment in v1), cross-segment anchor in first record of each new segment.
- `src/verifier.rs` — `fn verify_chain(since: Option<SegmentId>) -> ChainVerificationResult`. Walks segments in order, re-hashes each record, verifies chain links. Used at kernel startup and by CLI tooling.
- `src/retention.rs` — Retention policy by data class. **Clarification:** retention affects archival decisions on closed segments (move to compressed archive, mark eligible for deletion after N days) — it never mutates, truncates, or rewrites chain history. The chain remains intact and verifiable even after a segment is archived. In-place mutation of chain history is structurally impossible; `retention.rs` only produces archival metadata, not write operations on existing records.

---

##### `crates/store/` — `raxis-store`

**Purpose:** SQLite-backed kernel state store: sessions, tasks, initiatives, delegations, escalations, lanes, budget positions.

**Why it exists as a separate crate:** If state access were inlined in the kernel binary, tests could not mock or inspect state without starting the full kernel. A separate crate lets unit tests construct a `Store` with an in-memory SQLite database and verify state transitions in isolation.

**What it contains:**
- `src/db.rs` — SQLite connection setup: WAL mode, `synchronous = FULL`, checkpoint policy (`PRAGMA wal_autocheckpoint = 1000`). Startup integrity check: verify schema version matches binary version.
- `src/migrations.rs` — Versioned SQL migrations. Every schema change is a numbered migration. The store refuses to open a database whose schema version is ahead of the binary's known migrations (fail-closed on schema mismatch).
- `src/sessions.rs` — CRUD for session records. `fn create_session(...)`, `fn revoke_session(...)`, `fn get_session(id: SessionId)`. Sessions are never deleted; they are marked `Revoked` with a timestamp.
- `src/tasks.rs` — Task records. `fn insert_task(...)`, `fn transition_task(id, new_state, validator, timestamp, policy_epoch)`. Every state transition records the validator identity, timestamp, and which policy epoch was active. This is what makes decisions reproducible from stored records (INV-05).
- `src/initiatives.rs` — Initiative records, including the signed plan artifact reference and terminal criteria fields.
- `src/delegations.rs` — Delegation records with TTL, epoch-at-issue, and `staleness_status`. `fn mark_stale_on_epoch_advance(old_epoch, new_epoch)` updates all active delegations on policy epoch increment.
- `src/escalations.rs` — Escalation records. Row shape matches the canonical `escalations` DDL (§2.5.1 Table 8): `escalation_id`, `session_id`, `task_id`, `lineage_id`, `initiative_id`, `class` (`EscalationClass`), `requested_scope_json`, `justification`, `idempotency_key`, `status` (`EscalationStatus`: `Pending | Approved | Denied | TimedOut | TokenExpired | Consumed`), `created_at`, `timeout_at`, `resolved_at`, `resolution_notes`. Authority tokens, proofs, nonces, and rate-limit state live in their own canonical tables (`approval_tokens` §2.5.1 Table 9, `approval_proofs` Table 10, `approval_token_nonces` Table 11, `lineage_rate_limits` Table 15) — **not** as embedded sub-tables within this module. See Escalation FSM section and §2.5.1 DDL Part 2 for all field definitions and state transition invariants.
- `src/lanes.rs` — Lane records: `lane_id`, `priority_class`, `concurrency_budget`, `cost_ceiling`, `fairness_weight`, `stall_threshold`.
- `src/budget.rs` — Budget tracking: pre-call reservation, post-call actual reconciliation, overage audit events.
- `src/dag.rs` — Task dependency graph: store predecessor/successor relationships, `fn release_successors(completed_task_id)` — evaluates which successors have all predecessors in terminal success state and marks them admission-ready.

**Who depends on it:** `raxis-kernel` only.

**Who must NOT depend on it:** `raxis-planner`, `raxis-gateway`, `raxis-verifier`, `raxis-cli`. The CLI operator tooling queries kernel state through an authenticated IPC endpoint, not by opening the SQLite database directly. This is enforced by the dependency graph.

---

#### 1.7 — Dependency Graph (Trust Enforcement Summary)

The following diagram shows which crates may depend on which.
An arrow means "may depend on." Absence of an arrow means the compiler prevents the dependency.

```
raxis-types        ←──────────── all crates depend on this

raxis-crypto       ←─── kernel, cli, audit-tools, policy
raxis-ipc          ←─── kernel, planner, gateway, verifier
raxis-policy       ←─── kernel, cli                [PLANNER CANNOT SEE POLICY INTERNALS]
raxis-audit-tools-writer ←─── planner only               [NO CRYPTO DEP — safe for planner]
raxis-audit-tools  ←─── kernel, cli                [HAS CRYPTO — kernel/operator only]
raxis-store        ←─── kernel only                [NO OTHER PROCESS TOUCHES STATE DB]

raxis-kernel    depends on: types, crypto, ipc, policy, audit-tools, store
raxis-planner   depends on: types, ipc, audit-writer   ← no crypto, no policy, no store
raxis-gateway   depends on: types, ipc                 ← no raxis-crypto (no authority-key ops); TLS for HTTPS handled by the HTTP client crate, not raxis-crypto
raxis-verifier  depends on: types, ipc                 ← no raxis-crypto (no authority-key ops); SHA-256 over witness blobs uses stdlib or bundled crates, not raxis-crypto
raxis-cli       depends on: types, crypto, ipc, policy, audit-tools
```

**Why the audit crate split is the correct fix for transitive coupling:**
If `raxis-planner` depended on a single `raxis-audit-tools` that also depended on `raxis-crypto`, the planner would gain signing capabilities through the transitive dependency chain — `planner → audit → crypto → sign()`. The split eliminates this: `raxis-audit-tools-writer` depends only on `raxis-types`, so the planner's transitive closure contains no crypto, no policy, and no state access. The compiler verifies this on every build.

**Why the gateway and verifier have even smaller surfaces:**
The gateway only needs to know how to receive an `InferenceRequest` or `FetchRequest` from the kernel, make an HTTP/HTTPS call (TLS handled by the HTTP client crate, not `raxis-crypto`), and return a response. It does not need `raxis-crypto`, policy, state, or audit access — "no crypto" here means no authority-key operations, not "no TLS." The verifier only needs to receive a gate-run specification, execute tools, and return structured results. Neither has any path to authority-bearing operations.

---

#### 1.8 — Token Taxonomy

Four distinct token classes exist in the system, each with different scope, TTL, and replay rules. They must not be confused or substituted.

| Token Class | Issued by | Presented by | Scope | TTL | Replay rule |
|---|---|---|---|---|---|
| `planner_session_token` | Kernel at session spawn | Planner on every IPC message | **256-bit CSPRNG random bytes** stored in the kernel session row. Verification is a DB lookup by `session_id` plus constant-time comparison of the presented bytes against the stored value — no HMAC recomputation. Authorizes planner to submit intent packets for that session only. **Validator rule:** token presented with a `session_id` that does not match the stored row is a hard `UNAUTHORIZED`. Token reuse across sessions is not permitted even if the token bytes are numerically valid. | Session lifetime (expires on session revocation or TTL) | Per-message nonce prevents replay within session; token itself is reusable within TTL |
| `gateway_process_token` | Kernel at gateway spawn | Gateway on every kernel→gateway IPC call | Bound to spawn UUID (a random value generated by kernel at spawn time and delivered to child via sealed pipe); PID is recorded as auxiliary metadata only and is not part of the cryptographic binding, since PIDs can be reused by the OS. | Process lifetime (single gateway spawn; token invalid after restart) | Monotonic sequence number per gateway process; replayed or out-of-order sequence → rejected |
| `verifier_run_token` | Kernel at verifier spawn (per gate-run) | Verifier on witness writeback IPC | Bound to `verifier_run_id` + `task_id` + `gate_type`; authorizes exactly one witness submission for that run | Single-use; expires after first accepted writeback or wall-clock timeout (whichever comes first) | Strictly one-time; second presentation of same token → `INVALID_REQUEST`, audit event emitted |
| `approval_token` | Human operator via local CLI, signed with the operator's own private key (from `[[operators.entries]]`) | Planner, presented on the intent retry that requires the escalated authority | Bound to `escalation_id`, `approval_id`, `session_id`, `ApprovalScope` (predicate over capability class / intent kinds / path glob), `policy_epoch`, single-use `nonce`; authorizes exactly one escalated action within scope. See `raxis-types/src/approval.rs` and the Escalation FSM section for normative field list. | `ApprovalScope.valid_until`; additionally invalidated if `policy_epoch` advances before the token is presented | Strictly one-time via nonce table; second presentation returns `Ok(ApprovalStatus::NonceConsumed)` internally, which the dispatcher maps to `IpcResponse::Error(PlannerErrorCode::UNAUTHORIZED)` (planner sees coarse code; internal `NonceConsumed` status is logged to audit only) |

---

#### 1.9 — IPC Replay Protection: Nonce vs Sequence Number

The types envelope contains both `nonce` and `sequence_number`. They serve different purposes and must both be present.

**`sequence_number` — strict next-expected enforcement for control messages**
Each session starts at sequence `0`. Every control-plane message must carry `sequence == last_accepted + 1`. The kernel rejects any message where `sequence != last_accepted + 1` with **`UNAUTHORIZED`** (§2.5.1 Table 16 check (A); logged as sequence gap / replay class — not `INVALID_REQUEST`).

This is strict next-expected, not tolerant monotonic: gaps are not accepted with a warning — they are rejected. A gap means either a message was lost (session is in an inconsistent state and must be inspected) or an attacker is probing with out-of-order submissions. In both cases, the correct action is rejection, not acceptance with alert. If the planner genuinely loses a message acknowledgment, it must resubmit using the idempotency key mechanism, not by advancing the sequence past the gap.

**`nonce` — per-message random value for parallel delivery races**
A 128-bit random value generated fresh for each message. Duplicate `(session_id, envelope_nonce)` pairs are rejected by the **`nonce_cache`** store insert (§2.5.1 Table 16 check (B)) with planner-facing **`UNAUTHORIZED`**. Rows are evicted by TTL in the dispatcher background task; the table survives restart (unlike a purely in-memory cache).

The nonce does not protect against sequence-check gaps — the sequence check handles ordering. The nonce protects against a different class of attack: parallel delivery races and multi-connection duplication. Specifically, if the planner holds two UDS connections simultaneously (e.g., a connection in teardown and a new connection in setup), both connections may present the same `session_id` with overlapping sequence state. The nonce ensures that even if two messages arrive with the same valid sequence position across two connections, they produce different nonces and only one can be accepted.

**Why both are required:**
Sequence numbers enforce ordering and provide the primary replay barrier. Nonces close the parallel-connection/pre-dispatch duplication window that sequence checks cannot cover when the same session is contacted from more than one connection simultaneously. Removing either creates a gap that is exploitable in a specific delivery race condition.

---

#### 1.10 — CLI Mode Separation

The CLI (`raxis-cli`) has broad local power — it depends on `policy`, `crypto`, and `audit-tools`. To prevent normal operation from accidentally exercising privileged paths, CLI commands are separated into modes.

**Normal mode (default):** Commands available without elevated authentication (exact subcommand set evolves — **Part 4 / `cli-ceremony.md`** is normative).
- `raxis-cli …` — examples: status queries, `audit verify` on segment files (read-only)

**Operator mode** (requires operator challenge-response / operator session):
- `raxis-cli escalation approve …` / `raxis-cli escalation deny …` — escalation lifecycle
- Plan and initiative commands per Part 4 (`plan approve`, `task abort`, etc.)

**Bootstrap/break-glass mode** (explicit ceremony — see Part 4):
- `raxis-cli genesis …`, epoch advance, break-glass flows as specified in `cli-ceremony.md`

All bootstrap/break-glass commands are rate-limited by the kernel — the kernel's break-glass state machine enforces the cooldown and rejects repeat invocations regardless of what the CLI sends. The CLI may enforce the same limits locally as a UX convenience to avoid a round-trip, but the kernel is the sole authority; CLI-side enforcement is advisory only and must not be relied upon for security.

---

> **End of Part 1.**

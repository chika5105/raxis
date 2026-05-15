# RAXIS V2 — Token Limit Enforcement

> **Status:** V2 Specified
> **Cross-references:**
> - [`v2-deep-spec.md §Part 6`](v2-deep-spec.md) — Budget lanes and admission units
> - [`immutable-artifact-store.md §2.4`](immutable-artifact-store.md) — Audit log immutability
> - [`integration-merge.md §12`](integration-merge.md) — Escalation-as-amendment pattern
> - `security/raxis-security-model.md §Part 16` — Always-recorded audit events

---

## 1. `InferenceCompleted` Audit Event (Definitive)

`prompt_sha256` and `response_sha256` are **always recorded** — not optional. The raw
bytes are the operator's responsibility to store externally (S3, GCS, etc.). The Kernel
only stores the hash. The hash allows an operator to verify that any externally stored
bytes have not been tampered with. External integration specs (V3) will define the
webhook/push mechanism for raw byte export.

<!-- spec-graph:cross-ref -->

```rust
AuditEventKind::InferenceCompleted {
    session_id:         Uuid,
    task_id:            String,
    initiative_id:      Uuid,

    // Attribution
    model:              String,    // e.g., "claude-opus-4-5"
    provider:           String,    // e.g., "anthropic"

    // Token usage (from provider response)
    tokens_input:       u32,
    tokens_output:      u32,
    tokens_cache_creation: u32,    // provider-specific; 0 if not applicable
    tokens_cache_read:     u32,    // provider-specific; 0 if not applicable

    // Budget
    admission_units:    u32,       // pre-allocated budget units at admission
    actual_units:       u32,       // reconciled after actual token count known

    // Latency
    latency_ms:         u64,

    // Content integrity — always recorded, never optional
    prompt_sha256:      String,    // SHA-256 of exact bytes sent to provider (KSB+NNSP+messages)
    response_sha256:    String,    // SHA-256 of exact bytes received from provider

    // KSB integrity — always recorded; deterministically verifiable from DB state
    ksb_sha256:         String,    // SHA-256 of the KSB string assembled for this specific call
                                   // Auditor can reconstruct KSB from DB snapshot at call
                                   // timestamp and verify hash matches without external storage
}
```

---

## 2. Token Limit Types

RAXIS enforces token limits at two granularities:

### Granular (per-request)

| Limit | Scope | Enforcement point |
|---|---|---|
| `max_tokens_input_per_request` | Single inference call | Pre-admission (char proxy) + post-completion |
| `max_tokens_output_per_request` | Single inference call | Post-completion only |
| `max_tokens_total_per_request` | `input + output` for one call | Post-completion only |

**Why post-completion for output:** The Kernel cannot know `tokens_output` until the
provider responds. Per-request output limits are checked after the response arrives.

**Why pre-admission for input:** The Kernel has the prompt bytes before sending. A
character-count proxy (`len(prompt_bytes) / 4`) is used as a rough upper bound at
admission. After the provider responds with the exact count, the actual check runs and
the `limit_behavior` is applied if violated.

### Coarse (per-session cumulative)

| Limit | Scope | Enforcement point |
|---|---|---|
| `max_tokens_input_total` | Session lifetime | Pre-admission (exact — uses running total) |
| `max_tokens_output_total` | Session lifetime | Post-completion |
| `max_tokens_total` | Session lifetime (input + output) | Pre-admission (estimated) |

Cumulative totals are tracked per session in the database and updated atomically after
each `InferenceCompleted` event.

---

## 3. Plan Configuration

```toml
# plan.toml

[[tasks]]
task_id            = "auth_implementer"
session_agent_type = "Executor"
vm_image           = "raxis/rust:1.87"

[tasks.token_policy]
# Granular per-request limits
max_tokens_input_per_request  = 80_000
max_tokens_output_per_request = 8_000
max_tokens_total_per_request  = 88_000

# Coarse per-session limits
max_tokens_input_total  = 2_000_000
max_tokens_output_total = 200_000
max_tokens_total        = 2_200_000

# Behavior when limits are hit (see §5)
[tasks.token_policy.limit_behavior]
on_request_limit_exceeded = "fail_request"   # this call fails; session continues
on_session_limit_exceeded = "escalate"       # request operator approval for extension
on_session_limit_denied   = "fail_session"   # if operator denies, session terminates
```

**All limits default to `"uncapped"` if omitted — but omitting a limit generates
`WARN_UNCAPPED_TOKEN_LIMIT` at `approve_plan`.** Strict-by-default means this warning
is treated as an error unless the operator runs with `--no-strict`. The operator must
consciouslly declare `"uncapped"` to suppress the warning, making the choice explicit.

```rust
/// Token limit value — either uncapped or a specific count.
///
/// Serialization:
///   "uncapped"         → TokenLimit::Uncapped (explicit: no limit, warning suppressed)
///   <positive integer> → TokenLimit::Count(NonZeroU32)
///   omitted / missing  → TokenLimit::Uncapped (implicit: generates WARN_UNCAPPED_TOKEN_LIMIT)
///   "forever"          → parse error (wrong type — use "forever" only for RetentionDays)
///   0 or negative      → parse error
///
/// The distinction between explicit "uncapped" and implicit omission matters at
/// approve_plan time: omission generates WARN_UNCAPPED_TOKEN_LIMIT; explicit "uncapped"
/// suppresses the warning (operator consciously chose no limit).
pub enum TokenLimit {
    /// No limit. Explicitly declared with "uncapped" string — warning suppressed.
    Uncapped,
    /// Specific count. N must be ≥ 1.
    Count(NonZeroU32),
}

impl Default for TokenLimit {
    /// Implicit default when field is omitted — generates WARN_UNCAPPED_TOKEN_LIMIT.
    /// Explicit "uncapped" string also produces Uncapped but suppresses the warning.
    fn default() -> Self { TokenLimit::Uncapped }
}
```

---

## 4. Schema — Per-Session Token Tracking

```sql
-- migration 3 addition: per-session token totals
ALTER TABLE sessions ADD COLUMN tokens_input_total   INTEGER NOT NULL DEFAULT 0;
ALTER TABLE sessions ADD COLUMN tokens_output_total  INTEGER NOT NULL DEFAULT 0;
ALTER TABLE sessions ADD COLUMN tokens_total         INTEGER NOT NULL DEFAULT 0;

-- token limit grants (escalation-based extensions)
CREATE TABLE token_limit_grants (
    id              TEXT    NOT NULL PRIMARY KEY,  -- UUID
    session_id      TEXT    NOT NULL REFERENCES sessions(id),
    escalation_id   TEXT    NOT NULL REFERENCES escalations(id),
    additional_tokens INTEGER NOT NULL,            -- granted extension
    limit_type      TEXT    NOT NULL,              -- 'input_total' | 'output_total' | 'total'
    granted_at      INTEGER NOT NULL,              -- Unix timestamp
    granted_by      TEXT    NOT NULL               -- operator identifier
);
```

Cumulative token totals are updated in the same `BEGIN IMMEDIATE` transaction as the
`InferenceCompleted` audit event — atomically with the record of the inference itself.

---

## 5. Limit Behavior Modes

Three modes, consistent with how budget lane ceilings work:

### `"fail_request"` (per-request limit exceeded)
The specific inference call is rejected. The session remains active. The agent receives
`FAIL_TOKEN_LIMIT_PER_REQUEST { limit_type, actual, limit }` and may retry with a
shorter prompt or a different strategy. Used for per-request limits — one oversized
call should not terminate a productive session.

### `"escalate"` (session cumulative limit exceeded)
The Kernel auto-creates a `TokenLimitExceeded` escalation in `Pending` state. The
session is paused — no new `InferenceRequest` is admitted until the escalation is
resolved. Operator uses `raxis token-limit approve <esc-id> --additional <N>` or
`raxis token-limit deny <esc-id>`.

**On approval:** The Kernel records a `token_limit_grants` row with `additional_tokens`.
The session's effective limit becomes `plan_limit + sum(grants)`. Session resumes.

**On denial:** Session terminates with `FAIL_TOKEN_LIMIT_DENIED`. Same outcome as
`"fail_session"` but reached via the escalation path. Orchestrator receives
`KernelPush::SessionFailed { reason: TokenLimitDenied }`.

### `"fail_session"` (no escalation wanted)
The session terminates immediately when the cumulative limit is hit. No escalation is
created. This is for operators who have pre-declared the answer in the limit value
and do not want to be interrupted mid-run. The limit IS the policy.

---

## 6. The Plan Immutability Tension — Resolved

**The tension:** `plan.toml` is signed and immutable. If the plan declares
`max_tokens_total = 1_000_000` and the session needs more, "granting more tokens"
sounds like mutating a signed document.

**The resolution:** The escalation-as-amendment pattern (same as `ProtectedPathMerge`).

The plan document is **never modified**. The `token_limit_grants` record is a
separate document — a session-scoped permission record that says:

> "For session `S` of initiative `I`, the operator granted +500,000 additional total
> tokens beyond the plan's declared limit of 1,000,000. Escalation `esc-42`. Granted by
> `operator_alice` at timestamp T."

Two documents:
1. `plan.toml` — `max_tokens_total = 1_000_000` (unchanged, still valid, still signed)
2. `token_limit_grants` row — `additional_tokens = 500_000` for session `S`

Effective limit = `plan_limit + SUM(grants for session S)`.

The plan's immutability is preserved. The grant is a separate operator decision,
audited independently. The audit chain shows the original limit, the escalation event,
the approval, and the effective limit at each inference.

**Why this does NOT invalidate `policy.toml`:** Token limits are declared in `plan.toml`,
not `policy.toml`. The policy bundle is unaffected by token limit grants. The INV-POLICY-01
floor (policy protections cannot be weakened by plan) still holds — token limit grants
are session-scoped exceptions to plan limits, not policy changes.

---

## 7. Audit Events for Token Limits

```rust
AuditEventKind::TokenLimitApproaching {
    session_id:       Uuid,
    limit_type:       String,    // "input_total" | "output_total" | "total"
    current:          u64,
    limit:            u64,
    pct_used:         u8,        // 80, 90, 95 — emitted at each threshold
}

AuditEventKind::TokenLimitExceeded {
    session_id:       Uuid,
    escalation_id:    Option<Uuid>,   // Some if behavior = "escalate", None if "fail_*"
    limit_type:       String,
    current:          u64,
    limit:            u64,
    behavior:         String,         // "fail_request" | "escalate" | "fail_session"
}

AuditEventKind::TokenLimitGranted {
    session_id:       Uuid,
    escalation_id:    Uuid,
    limit_type:       String,
    plan_limit:       u64,
    additional_tokens: u64,
    effective_limit:  u64,         // plan_limit + sum of all grants
    granted_by:       String,
}

AuditEventKind::TokenLimitDenied {
    session_id:       Uuid,
    escalation_id:    Uuid,
    limit_type:       String,
    denied_by:        String,
}
```

**Approaching thresholds** (80%, 90%, 95%) are emitted proactively so operators can
approve extensions before the session actually hits the limit — avoiding a mid-inference
pause.

---

## 8. Consistency with Budget Lanes

| Concept | Budget lanes | Token limits |
|---|---|---|
| Declaration | `[lanes.<name>].ceiling` in policy | `[tasks.token_policy]` in plan |
| Level | Deployment-wide lane | Per-task / per-session |
| Pre-admission check | `admission_units + cost <= ceiling` | `tokens_so_far + estimate <= max` |
| Post-completion reconciliation | `actual_units` recorded | `actual_tokens` recorded |
| Behavior at limit | Implied `fail_request` | Explicit `limit_behavior` field |
| Extension mechanism | Not currently specified | `token_limit_grants` via escalation |
| Audit events | Lane ceiling events | `TokenLimitApproaching/Exceeded/Granted/Denied` |

**Recommended:** Budget lanes should adopt the same `limit_behavior` field in V2.2,
making the two systems fully parallel. Noted as a future consistency improvement.

---

## 9. V3 External Integration Note

Raw prompt and response bytes are NOT stored by the Kernel. The `prompt_sha256` and
`response_sha256` in `InferenceCompleted` are integrity anchors for externally stored
bytes.

V3 will specify a webhook/event stream mechanism by which operators can receive raw
inference content for archival to S3, GCS, or any external store. The SHA-256 in the
audit chain is the verification key: if the external store returns bytes that hash to
the recorded SHA-256, the content is authentic and unmodified.

---

---

## 10. Budget Lanes vs. Token Limits — Relationship and Tensions

This section documents the full design analysis of the relationship between budget lanes
and token limits. The conclusion is in §11.7. The step-by-step reasoning is preserved
here because the tradeoffs are non-obvious and future contributors need to understand
why the two systems exist as separate rather than unified.

### 10.1 — The Two Systems Defined

RAXIS has two resource governance systems that both constrain inference.

**Budget lanes (`admission_units`)** — declared in `policy.toml`, deployment-level.
A weighted abstract unit covering ALL intent types: `InferenceRequest`, `SingleCommit`,
`EgressRequest`, `IntegrationMerge`, etc. Every intent that enters the Kernel admission
pipeline consumes some admission_units from the active lane.

In the current V2 spec, the weight for each intent type is a **fixed configured value**
— it does not vary with the actual content of the intent. An `InferenceRequest` for a
5-token prompt and one for a 100,000-token prompt consume the **same admission_units**
because the weight is tied to the intent class, not the call's actual payload.

This means budget lanes are currently **token-blind**: they approximate resource
consumption but do not track actual LLM token usage.

**Token limits** — declared in `plan.toml`, per-initiative, per-task.
Cover `InferenceRequest` **only**. Track **actual token counts** from the provider
response (the authoritative source). Operate at two granularities:
- Per-request: limits on a single inference call
- Per-session cumulative: limits on the session's total token consumption

Token limits are token-aware by definition — they are specified in the unit that LLM
providers use for billing and rate limiting.

**The critical observation:** The two systems currently measure different things.
Budget lanes measure a proxy; token limits measure the actual quantity. This creates
the tension analyzed below.

---

### 10.2 — Step-by-Step: Arguments for Keeping Them Separate

**Argument S1: Different measurement units, different scope.**

Admission_units cover all intent types. Creating a unified system means defining a
common unit that can express "a SingleCommit" and "a 50,000-token inference" on the
same scale. There is no natural conversion. Any rate chosen is arbitrary:
- If 1 unit = 1000 tokens, then SingleCommit = 1 unit = 1000 tokens, which is
  meaningless (commits don't have tokens)
- If units represent USD, then commits need a USD cost, which varies by git repo size
  and is rarely what operators want to express

The scope mismatch (all intents vs. inference only) means unification would either
force non-inference intents into a token-equivalent framework (wrong) or exclude them
from the unified system (then it's not unified).

**Argument S2: Different authority levels break INV-POLICY-01.**

Budget lanes are in `policy.toml` — the immutable security floor. Token limits are in
`plan.toml` — per-initiative configuration. Unifying them requires choosing one location:

- Move token limits to `policy.toml`: lose per-task granularity. Every initiative
  in the deployment gets the same token limits, regardless of task complexity.
- Move budget lanes to `plan.toml`: break INV-POLICY-01. The deployment-level
  financial ceiling is now operator-overridable per plan. A plan could simply omit
  the budget ceiling and consume unbounded resources.

Neither is acceptable. The authority level mismatch is structural.

**Argument S3: Different blast radius at limit.**

When a budget lane ceiling is hit, the **entire lane** is blocked. Every initiative in
that lane stops admitting new intents. This is intentional — the lane ceiling represents
a deployment-wide resource constraint.

When a per-request token limit fires with `"fail_request"` behavior, only **one
inference call** fails. The session continues. The agent retries with a shorter prompt.
This is a local, recoverable failure.

Conflating these would mean: when an agent sends one oversized inference request,
the entire lane stops for all other initiatives. That is catastrophically over-broad.

**Argument S4: Different operator audiences and remediation paths.**

Budget lane exhaustion: remediated by the infra/ops team who owns policy.toml —
they raise the ceiling, re-balance lanes, or wait for the next billing period.

Token limit exhaustion: remediated by the initiative operator who wrote plan.toml —
they approve a token extension via escalation, or re-plan the task with tighter scope.

In large organizations these are genuinely different people. Unifying the systems
would send the wrong escalation to the wrong person.

**Argument S5: Distinct audit semantics.**

"Initiative failed: token limit exhausted on session X" and "Initiative failed: lane
budget exhausted" are different root causes:
- Token limit: the task needed more reasoning than planned. Fix: re-plan with higher
  limit or break task into smaller pieces.
- Budget exhaustion: the initiative consumed more financial resources than the
  deployment allows. Fix: adjust deployment policy or reduce initiative scope.

Unified error codes would obscure which problem occurred.

---

### 10.3 — Step-by-Step: Arguments for Unifying Them

**Argument U1: Both govern the same underlying resource.**

At the end of the day, inference costs compute time, API fees, and energy. Having two
systems governing access to the same underlying resource creates double-counting:
an inference call is checked against budget lanes AND token limits. If both reject it,
two escalation paths fire, two operator decisions are needed for one call.

**Argument U2: Budget lanes for inference are already an implicit token proxy.**

If `InferenceRequest` has weight 10 and a typical call uses ~10k tokens, then the
operator is implicitly reasoning "1 unit ≈ 1k tokens" when setting the lane ceiling.
The relationship is there — it's just not explicit. Making it explicit and exact is
strictly better than the current approximation.

**Argument U3: Operator cognitive overhead.**

Operators currently must declare:
- Budget lane ceiling in policy.toml (financial/resource floor)
- Token limits in plan.toml per task (technical constraint)
- Understand how they interact
- Handle two separate escalation paths

One system with one set of limits is simpler to reason about, easier to configure,
and less likely to produce surprising interactions.

**Argument U4: One escalation path is architecturally cleaner.**

Token limit escalation (`TokenLimitExceeded`) and budget lane escalation (currently
not fully specified) are two paths for what the operator experiences as one question:
"should this agent be allowed to consume more resources?" A single escalation mechanism
with a `reason` field (token limit vs. financial limit) is more composable.

---

### 10.4 — The Decisive Question

The tension resolves entirely once this is answered:

> **Should admission_units for InferenceRequest be token-proportional or token-blind?**

**If token-blind (current state):** Admission_units are generic work-units. They don't
reflect actual inference cost. Token limits are the only accurate measure of LLM
resource consumption. Both systems must exist because they measure fundamentally
different things.

**If token-proportional (proposed):** Admission_units for InferenceRequest become:

```text
actual_units = (tokens_input × input_cost_per_k + tokens_output × output_cost_per_k)
               ÷ cost_per_unit
```

Where `input_cost_per_k` and `output_cost_per_k` are provider pricing rates, and
`cost_per_unit` is the operator-defined conversion factor (e.g., 1 unit = $0.001).

With this change, budget lanes for InferenceRequest become an **actual cost-based
financial ceiling**. The two systems now govern genuinely different dimensions:

- **Token limits** = technical constraint: "this call/session can only use X tokens"
  (regardless of what they cost)
- **Budget lanes** = financial constraint: "this lane can only spend $Y equivalent"
  (regardless of how the tokens were used)

This is the cloud quota vs. cloud budget model. Both can bind simultaneously for
genuinely different reasons:
- A session can be within financial budget but exceed a per-request token limit
  (one call is technically too large)
- A session can be within token limits but exhaust the lane budget
  (many smaller calls added up to exceed the financial ceiling)

These are orthogonal. Not redundant.

---

### 10.5 — The Interaction Model

With token-proportional budget lanes, the `admit_inference` path
performs **all three pre-admission resource checks (budget lane,
token limit, lane reservation) inside a single SQLite
`BEGIN IMMEDIATE` transaction**. The transaction commits the lane
reservation; if any check fails, the transaction rolls back and no
state is mutated. This eliminates a race condition where two
concurrent `admit_inference` calls in the same lane each see
`lane_used + estimate ≤ lane_ceiling` (because neither has
reserved yet), both pass, and the post-completion reconciliation
permanently puts the lane over its ceiling.

```text
admit_inference(InferenceRequest, session, plan, policy):
  estimated_units  = estimate_units(request, policy)
  estimated_input  = estimate_input_tokens(request)

  --- BEGIN IMMEDIATE on kernel.db ---
  // Step 1: Budget lane check (policy-level, financial).
  //         Reads provider_circuit_state's lane sibling and
  //         lane_reservations. Atomic vs. concurrent admit_inference
  //         in the same lane.
  if lane_used + lane_reserved + estimated_units > lane_ceiling:
      ROLLBACK; return FAIL_BUDGET_CEILING_EXCEEDED
      // No escalation (policy floor — operator set the ceiling
      // deliberately).

  // Step 2: Token limit check (plan-level, technical).
  //         Reads session_token_state. Atomic vs. concurrent
  //         requests in the same session.
  if session_tokens_total + estimated_input >= max_tokens_total:
      ROLLBACK; return apply_limit_behavior(...)
      // fail_request | escalate | fail_session per §5.

  // Step 3: Reserve the lane unit estimate. The reservation
  //         survives transaction commit and is reconciled at
  //         post-completion (see step 6).
  INSERT INTO lane_reservations (
      reservation_id, lane, session_id, request_id,
      reserved_units, created_at_ms
  ) VALUES (uuid_v7(), lane, session.id, request.id,
            estimated_units, now());
  COMMIT;
  --- END BEGIN IMMEDIATE ---

  // Step 4: Audit InferenceAttempt before dispatch
  // (provider-failure-handling.md §6.1 / INV-PROVIDER-08).
  audit InferenceAttempt { ... };

  // Step 5: Dispatch to gateway.
  result = gateway.invoke(...);

  // Step 6: Post-completion reconciliation
  //         (single BEGIN IMMEDIATE; commits before InferenceCompleted
  //         audit emission).
  --- BEGIN IMMEDIATE on kernel.db ---
  actual_units = compute_actual_units(result.tokens, policy);
  // Reconcile the reservation with actual_units (may be less than
  // estimated):
  DELETE FROM lane_reservations WHERE reservation_id = ?;
  UPDATE lane_state
     SET lane_used = lane_used + actual_units
   WHERE lane = ?;
  UPDATE session_token_state
     SET tokens_input_total  = tokens_input_total  + result.tokens.input,
         tokens_output_total = tokens_output_total + result.tokens.output
   WHERE session_id = ?;
  COMMIT;
  --- END BEGIN IMMEDIATE ---

  // Step 7: Emit InferenceCompleted, check post-completion per-request
  // token limits (output, total).
  audit InferenceCompleted { ... };
  apply_post_completion_token_checks(...);
```

The `lane_reservations` table is the gate: a reservation row is
held against `lane_used + lane_reserved` for the duration of the
in-flight request. If the kernel crashes between step 3 and step 6,
recovery ([`kernel-lifecycle.md §10.5`](kernel-lifecycle.md) maintenance loop's
companion `lane_reservation_orphan_sweep` job, registered alongside
the §10.5.2 built-ins) reclaims orphaned reservations whose
`session_id` is no longer in `Active` state, restoring lane capacity
without operator intervention.

The `session_token_state` row is updated **only** in step 6,
post-completion, with the actual provider-reported counts. No
estimate is ever durably committed to `session_tokens_total` —
estimates exist only as comparison values inside the BEGIN
IMMEDIATE transaction.

```sql
-- New table backing step 3.
CREATE TABLE lane_reservations (
    reservation_id   BLOB PRIMARY KEY,    -- uuid_v7
    lane             TEXT NOT NULL,
    session_id       TEXT NOT NULL,
    request_id       TEXT NOT NULL,
    reserved_units   INTEGER NOT NULL,
    created_at_ms    INTEGER NOT NULL
);

CREATE INDEX idx_lane_reservations_lane
    ON lane_reservations(lane);

CREATE INDEX idx_lane_reservations_session
    ON lane_reservations(session_id);

-- The lane "available capacity" is now lane_ceiling - lane_used
-- - SUM(reserved_units WHERE lane = ?). Computed inline in the
-- step 1 check.
```

**Error code distinction:**
- `FAIL_BUDGET_CEILING_EXCEEDED` — financial ceiling from policy; no plan override
- `FAIL_TOKEN_LIMIT_PER_REQUEST` — technical per-call limit from plan; retry with
  shorter prompt or different strategy; session continues
- `FAIL_TOKEN_LIMIT_SESSION` — cumulative technical limit from plan; apply limit_behavior

---

### 10.6 — Enhancement to Budget Lanes for Inference

Replace the fixed weight for `InferenceRequest` in the policy bundle with a
`TokenProportionalWeight`:

```toml
# policy.toml

[lanes.standard.intent_weights]
SingleCommit      = { fixed = 1 }
EgressRequest     = { fixed = 2 }
IntegrationMerge  = { fixed = 5 }
InferenceRequest  = { token_proportional = true,
                      input_cost_per_k   = 3,      # units per 1k input tokens
                      output_cost_per_k  = 15,     # units per 1k output tokens
                      cache_read_cost_per_k = 0.3  # provider cache read (cheaper)
                    }
```

Other intent types keep their fixed weights — this is a non-breaking addition.
Existing deployments that don't declare `token_proportional` for InferenceRequest
continue to use their fixed weight unchanged.

The `input_cost_per_k` values are set by the operator to reflect the provider's actual
pricing scaled to their admission_unit denomination. For example:
- Anthropic Claude: input ~$3/1M tokens = 3 units per 1k tokens (at 1 unit = $0.001)
- OpenAI GPT-4o: input ~$2.50/1M tokens = 2.5 units per 1k tokens

---

### 10.7 — Conclusion

**Keep budget lanes and token limits as separate systems.** They are orthogonal
dimensions — financial (policy-level) vs. technical (plan-level). Unifying them is
architecturally incorrect because the authority level mismatch (policy vs. plan)
is structural and cannot be resolved without breaking INV-POLICY-01.

**But make them coherent** by making `InferenceRequest` weights token-proportional in
the policy bundle. This makes budget lanes genuinely cost-aware for inference rather
than a fixed-weight approximation, without changing their scope (all intent types) or
authority level (policy.toml).

**Future consideration (V3):** If budget lanes become fully token-proportional for all
providers and operators use financial ceilings as their primary resource control, token
limits may become redundant for most deployments. At that point a unified system could
be reconsidered. For V2, both systems serve distinct governance needs.

---

### Arguments for Keeping Them Separate

**1. Different measurement units.** Admission units are weighted abstractions covering
all intent types. Unifying requires an arbitrary conversion between "a file commit" and
"a token" — meaningless and fragile.

**2. Different authority levels.** Budget lanes are in `policy.toml` (the immutable
floor). Token limits are in `plan.toml` (per-initiative). Unifying would break
INV-POLICY-01: either token limits move to policy (losing per-task granularity) or
budget lanes move to plan (breaking the deployment-level floor guarantee).

**3. Different blast radius.** A budget lane ceiling blocks the entire lane for all
initiatives in that lane. A per-request token limit failure retries one inference call.
Conflating these would make per-call retries cause lane-level disruption.

**4. Different operator audiences.** Budget lanes are for the infra/ops team. Token
limits are for the initiative operator. Different people, different remediation paths.

**5. Different root causes in the audit chain.** "Session failed: token limit exhausted"
and "Session failed: lane budget exhausted" require different remediation. Audit clarity
demands distinct events and error codes.

---

### Arguments for Unifying Them

**1. Double-counting.** An inference call currently hits both admission_units (budget
lane) AND token limits simultaneously. Two escalation paths, two operator decisions for
what is fundamentally one resource event.

**2. Admission_units for inference are already an implicit token proxy.** If
`InferenceRequest` has weight 10 and a typical call uses ~10k tokens, then 1 unit ≈
1k tokens. Budget lanes are already a coarse token limit — just not honest about it.

**3. Simpler operator mental model.** One resource limit is simpler than two. Operators
currently must reason about how both interact, when each fires, and which escalation
path applies.

**4. One escalation path.** Two separate escalation classes for what the operator
experiences as one question ("can this agent use more resources?") adds unnecessary
complexity.

---

### The Decisive Insight — What Should Admission_Units Represent?

The tension collapses once this is answered: should admission_units for
`InferenceRequest` be token-proportional or token-blind?

**If token-blind (current):** Admission_units are a generic work-unit budget. They
don't track actual inference cost. Token limits are the only accurate measure of LLM
resource consumption. The two systems govern different things and must both exist.

**If token-proportional (proposed enhancement):** Admission_units for `InferenceRequest`
become a financial proxy:

```text
actual_units = (tokens_input × input_cost_per_k + tokens_output × output_cost_per_k)
               ÷ cost_per_unit
```

Where `input_cost_per_k`, `output_cost_per_k` are provider pricing rates and
`cost_per_unit` is the operator-defined conversion (e.g., 1 unit = $0.001).
Admission_units now represent **actual USD cost** for inference calls.

---

### Conclusion — Keep Separate, Make Coherent, Enhance Budget Lanes

**Token limits** and **budget lanes** are **two orthogonal dimensions** — analogous
to cloud quotas (technical limit) vs. cloud budgets (financial limit). Both can bind
simultaneously for different reasons:

- A session can be **within financial budget but exceed a per-request token limit**
  (the call is too large technically)
- A session can be **within token limits but exhaust the lane budget**
  (the initiative consumed more USD-equivalent than the deployment allows)

These are not redundant. They answer different questions. **Keep them separate.**

**But make them coherent by enhancing budget lanes for inference:**

Replace the fixed weight for `InferenceRequest` with a `TokenProportionalWeight` in
the policy bundle:

```toml
# policy.toml

[lanes.standard.intent_weights]
SingleCommit      = { fixed = 1 }
EgressRequest     = { fixed = 2 }
IntegrationMerge  = { fixed = 5 }
InferenceRequest  = { token_proportional = true,
                      input_cost_per_k   = 0.003,    # $/1k input tokens (provider rate)
                      output_cost_per_k  = 0.015,    # $/1k output tokens
                      cost_per_unit      = 0.001 }   # 1 unit = $0.001
```

Other intent types keep their fixed weights. `InferenceRequest` becomes cost-aware.
This is a non-breaking addition — existing deployments with fixed weights still work.

**Admission flow with both systems active.** See §10.5 for the
canonical, race-free admission procedure: all three pre-admission
checks (budget lane, token limit, lane reservation) execute inside
**one** `BEGIN IMMEDIATE` transaction so concurrent
`admit_inference` calls in the same lane cannot collectively over-
admit past the lane ceiling. The post-completion update of
`lane_used` and `session_tokens_total` is a separate
`BEGIN IMMEDIATE` transaction that reconciles the reservation
against actual provider-reported usage.

```text
InferenceRequest arrives at Kernel

  → see §10.5 for the canonical atomic procedure (single
    BEGIN IMMEDIATE for budget lane check + token limit check + lane
    reservation; separate BEGIN IMMEDIATE post-completion for
    reconciliation).
```

**Error code distinction:**
- `FAIL_BUDGET_CEILING_EXCEEDED` — financial limit from policy; no plan-level override
- `FAIL_TOKEN_LIMIT_PER_REQUEST` — technical limit from plan; retry with shorter prompt
- `FAIL_TOKEN_LIMIT_SESSION` — cumulative technical limit; escalate or fail session

Auditors and operators see distinct causes. Remediation paths differ.

**One remaining simplification for future consideration (V3):** If budget lanes are made
fully token-proportional for all providers, and all operators use financial budget lanes
as their primary resource control, then token limits become redundant for most use cases.
At that point a unified system could be reconsidered. For V2, the two-system approach is
correct: budget lanes are established infrastructure at the policy level; token limits are
a new fine-grained addition at the plan level. They serve different governance needs.

---

---

## 11. CLI Commands for Token Limit Management

```bash
# --- Observation ---

# Show current token usage for a specific session
raxis token status <session-id>
# Output: tokens_input_total, tokens_output_total, tokens_total,
#         plan limits, effective limits (plan + grants), % used per limit

# Show all token limits and usage across all sessions of an initiative
raxis token status --initiative <initiative-id>

# Show per-inference token history for a session
raxis token history <session-id>
# Output: table of InferenceCompleted events with tokens_input, tokens_output,
#         model, latency_ms, prompt_sha256 (truncated), timestamp

# --- Escalation Management ---

# List all active TokenLimitExceeded escalations
raxis token escalations list
raxis token escalations list --initiative <initiative-id>

# Show detail for a specific token escalation
raxis token escalations show <escalation-id>
# Output: session context, limit type, current usage, plan limit,
#         model's explanation (from escalation.context field)

# Approve a token limit extension
raxis token escalations approve <escalation-id> --additional <N>
# --additional: number of additional tokens to grant beyond current effective limit
# Emits: TokenLimitGranted audit event

# Deny a token limit extension
raxis token escalations deny <escalation-id> [--reason "..."]
# Emits: TokenLimitDenied audit event; session terminates

# --- Audit ---

# Show all token limit events for an initiative (approaching, exceeded, granted, denied)
raxis token audit <initiative-id>

# Show effective token limits for a session (plan limit + all grants)
raxis token effective-limits <session-id>
```

---

## 12. Prompt Engineering — Token Limit Awareness

### 13.1 — Why the Model Must Know About Token Limits

The model is the only entity that can recover from recoverable token limit errors. The
Kernel returns a structured error code, but the model must understand:
- What the error means
- Whether recovery is possible
- What the correct recovery action is
- What to put in an escalation request when recovery requires operator intervention

Without explicit guidance in the non-negotiable system prompt, a model is likely to:
- Retry the same oversized request repeatedly (wastes budget)
- Escalate for a per-request limit that it could fix by trimming context (wastes operator attention)
- Send a tiny prompt to a cumulative limit exhaustion (doesn't help — adds to the total)
- Write vague escalation context ("I need more tokens") instead of actionable explanation

### 13.2 — Recoverability Classification

The system prompt must teach the model the following classification:

**Class R1 — Recoverable by the model without escalation:**
`FAIL_TOKEN_LIMIT_PER_REQUEST { limit_type: "input" }`

The input prompt for this specific call exceeded the per-request input limit. The session
continues. The model can fix this by sending a smaller prompt. Recovery strategies:
- Summarize earlier conversation history instead of including it verbatim
- Remove less relevant file context from the prompt
- Split a large file read into a targeted excerpt
- Use `grep_search` instead of `read_file` to extract only the relevant section

The model MUST attempt recovery before escalating. Escalating a per-request input limit
is a protocol violation — it signals the model did not attempt to trim the prompt.

**Class R2 — Recoverable by changing approach, not by smaller prompts:**
`FAIL_TOKEN_LIMIT_PER_REQUEST { limit_type: "output" | "total" }`

The response or combined tokens for this call exceeded the per-request limit. The model
cannot change the length of a response it already generated. Recovery strategies:
- Break the current task into smaller subtasks (one function at a time, not a whole file)
- Use more focused prompts that produce shorter targeted responses
- Write incrementally: produce part of the implementation, commit, then continue

The model MUST adjust its working strategy before escalating.

**Class R3 — NOT recoverable by sending smaller prompts — requires escalation or stopping:**
`FAIL_TOKEN_LIMIT_SESSION { limit_type: "input_total" | "output_total" | "total" }`

The session's cumulative token budget is exhausted. Sending a smaller prompt does NOT
fix this — it still adds tokens to the cumulative total. Even a 1-token prompt would
be rejected. The model has two options:
1. **If significant work remains and `limit_behavior = "escalate"`:** Submit a
   `TokenLimitExceeded` escalation request with a detailed explanation.
2. **If the work is substantially complete:** Commit what is done and submit
   `ReportFailure` explaining what was not completed due to token exhaustion.

The model MUST NOT attempt to send more inference requests after receiving this error.
Each attempt consumes budget on a refusal and moves the session no closer to completion.

### 13.3 — Non-Negotiable System Prompt Addition (Token Limit Protocol)

The following section is added to every Executor and Orchestrator non-negotiable system
prompt when any `[tasks.token_policy]` limits are declared in the plan:

```text
## Token Limit Protocol

Your inference calls are subject to token limits. You will receive structured error
responses if a limit is hit. You MUST follow this protocol exactly.

### Error codes and required actions:

FAIL_TOKEN_LIMIT_PER_REQUEST (input):
  MEANING: This single inference call's input was too large.
  RECOVERABLE: YES — by sending a smaller prompt.
  REQUIRED ACTION: Trim your next prompt. Do NOT escalate.
  Strategies: summarize history, use grep instead of full file read,
  excerpt only the relevant section of a large file.

FAIL_TOKEN_LIMIT_PER_REQUEST (output or total):
  MEANING: This call's response or combined tokens exceeded the per-call limit.
  RECOVERABLE: YES — by changing your working strategy.
  REQUIRED ACTION: Break your next task into smaller pieces. Write one
  function at a time, not a whole file. Commit partial work, then continue.
  Do NOT attempt the same scope in one call.

FAIL_TOKEN_LIMIT_SESSION (any cumulative limit):
  MEANING: Your session's lifetime token budget is exhausted.
  RECOVERABLE: NO — sending a smaller prompt will NOT help. Each attempt
  still consumes tokens from the exhausted budget.
  REQUIRED ACTION (if limit_behavior = escalate):
    Submit TokenLimitExceeded escalation with full explanation (see below).
    Do NOT send any more inference requests while waiting.
  REQUIRED ACTION (if limit_behavior = fail_session):
    Commit any completed work. Submit ReportFailure explaining what was
    completed and what remains. Do NOT attempt more inference.

### Escalation request requirements:

If you submit an escalation for a token limit, your context field MUST include:

1. CURRENT STATE: What have you completed so far in this session?
   (list files modified, tests passing, functions implemented)
2. REMAINING WORK: What specifically remains to be done?
   (be precise — list the functions/files still needed)
3. ESTIMATED TOKENS: Why do you need more tokens?
   (estimate: X input tokens for Y files to read, Z output tokens for W functions)
4. CANNOT COMPLETE WITH LESS: Explain why you cannot trim further.
   (e.g., "the remaining functions require the full existing codebase as context
   to maintain consistency — summarizing would produce incorrect implementations")

Vague context ("I need more tokens to finish") will be treated as an invalid
escalation. The operator needs a precise, actionable explanation to decide
whether to grant the extension.
```

### 13.4 — Escalation `context` Field — Required for ALL Escalation Types

This requirement extends beyond token limits. Every escalation request submitted by
any agent must include a structured `context` field that the operator can act on.

The `context` field in `EscalationRequest` is upgraded from a free-text string to a
structured type with a required `explanation` field:

```rust
pub struct EscalationContext {
    /// Required: human-readable explanation of why this escalation is needed.
    /// Must be specific and actionable. Vague explanations are a protocol violation.
    pub explanation: String,

    /// For MergeConflict: which files conflicted and what the LLM attempted
    pub conflict_detail: Option<ConflictDetail>,

    /// For TokenLimitExceeded: structured breakdown of current state and need
    pub token_detail: Option<TokenEscalationDetail>,

    /// For PlanViolation: which invariant was violated and what triggered it
    pub violation_detail: Option<ViolationDetail>,
}

pub struct TokenEscalationDetail {
    pub completed_work:    String,   // what was done
    pub remaining_work:    String,   // what is left
    pub estimated_tokens:  u32,      // operator-readable estimate
    pub cannot_trim_reason: String,  // why smaller prompts won't help
}
```

The Kernel validates at escalation admission that `explanation` is non-empty and
≥ 50 characters. A one-sentence explanation is insufficient for an operator to make
an informed approval decision. Escalations with invalid context are rejected with
`FAIL_ESCALATION_CONTEXT_INSUFFICIENT`.

The non-negotiable system prompt for every agent role includes the context requirements
for each escalation class the agent is permitted to submit.

---

## 14. Kernel State Block — Per-Request System Prompt Injection

### 14.1 — Rationale

The non-negotiable system prompt (injected once at session boot) teaches the model
the token limit protocol — error codes, recoverability classes, and escalation
requirements. But the model also needs **current state** on every inference call:
how many tokens it has used, how many remain, and whether it is approaching a limit.

Without per-request state injection, the model must:
- Guess how close it is to limits (it cannot)
- React to errors after they occur (wasteful — tokens spent on a rejected call)
- Escalate reactively rather than self-regulating proactively

The **Kernel State Block (KSB)** is a lightweight structured section the Kernel
prepends to the system prompt on every `InferenceRequest` before forwarding to the
gateway. It is Kernel-generated, tamper-proof from the agent's perspective, and kept
deliberately small (target: ≤ 200 tokens).

### 14.2 — KSB Format (Injected on Every Request)

The KSB is prepended as the first section of the system prompt. The model is
instructed in the non-negotiable prompt to read but never modify this section.

**Normal state (no limit approaching):**
```text
[RAXIS:KERNEL_STATE v=1]
session  = <session_uuid_short>     # first 8 chars of UUID
tokens   = in:12450 out:8230 tot:20680
limits   = in:uncapped out:uncapped tot:200000
remaining= tot:179320 (89.6%)
status   = OK
[/RAXIS:KERNEL_STATE]
```

**Approaching state (≥ 80% of any limit consumed):**
```text
[RAXIS:KERNEL_STATE v=1]
session  = <session_uuid_short>
tokens   = in:162000 out:18200 tot:180200
limits   = in:uncapped out:uncapped tot:200000
remaining= tot:19800 (9.9%)
status   = APPROACHING_LIMIT
warn     = total_tokens at 90.1% — begin wrapping up; commit completed work before exhaustion
[/RAXIS:KERNEL_STATE]
```

**Limit exhausted (session paused, escalation pending):**
```text
[RAXIS:KERNEL_STATE v=1]
session  = <session_uuid_short>
tokens   = in:198000 out:19500 tot:217500  # over limit — final state
limits   = in:uncapped out:uncapped tot:200000
status   = LIMIT_REACHED:total_tokens
action   = ESCALATION_PENDING:esc-42 — await operator approval before sending further requests
[/RAXIS:KERNEL_STATE]
```

### 14.3 — Why This Format

**Structured, not prose:** The format is machine-readable. Key=value pairs can be
parsed by the model reliably without ambiguity about where state ends and task content
begins.

**Versioned (`v=1`):** Adding `v=` allows the format to evolve. Models instructed for
v=1 will still parse v=1 blocks correctly even after a v=2 is introduced for new
deployments.

**Delimited (`[RAXIS:KERNEL_STATE]` ... `[/RAXIS:KERNEL_STATE]`):** The block has
unambiguous start and end markers. The non-negotiable prompt instructs the model to
locate and read this block first, before processing any task content.

**Abbreviated values:** `in:`, `out:`, `tot:` are short field prefixes. The full
words (`tokens_input`, `tokens_output`, `tokens_total`) are in the non-negotiable
prompt's legend — the per-request block uses abbreviations to minimize token cost.

**Target size:** ≤ 200 tokens (typically 100-150). This is the per-request overhead
of the KSB. Over a session with 100 inference calls, this adds ~15,000 tokens to the
input total — visible in the cumulative token count, so operators can account for it
when setting limits.

### 14.4 — What the Non-Negotiable Prompt Says About the KSB

Added to the non-negotiable system prompt for all agent roles:

```text
## Kernel State Block

At the start of every system prompt you will find a [RAXIS:KERNEL_STATE] block.
Read it first. It tells you your current resource status.

Fields:
  tokens = in:<input_used> out:<output_used> tot:<total_used>
  limits = in:<input_limit> out:<output_limit> tot:<total_limit>
           ("uncapped" = no limit set for that dimension)
  remaining = <dimension>:<amount> (<pct>% remaining)
  status = OK | APPROACHING_LIMIT | LIMIT_REACHED:<dimension>
  warn   = human-readable warning (present only when status = APPROACHING_LIMIT)
  action = required action (present only when status = LIMIT_REACHED)

Required behavior by status:

  OK:
    Continue working normally. No action required.

  APPROACHING_LIMIT:
    Read the warn field. Begin winding down your current work unit.
    Commit what is complete. Do not start new large tasks.
    Prefer shorter, focused responses until the work is committed.

  LIMIT_REACHED:<dimension>:
    Read the action field immediately.
    Do NOT send additional inference requests.
    Do NOT attempt to work around the limit by splitting prompts.
    Follow the action field exactly (escalation pending or session terminating).
```

### 14.5 — Kernel Assembly of the KSB

The KSB is assembled by the Kernel Prompt Assembler immediately before the
`InferenceRequest` is forwarded to `raxis-gateway`. The assembler:

1. Reads `sessions.tokens_input_total`, `tokens_output_total`, `tokens_total`
   from the database (the current running totals, updated after each completed call)
2. Reads the effective limits from `token_limit_grants` (plan_limit + granted extensions)
3. Computes `remaining` and `pct_used` per dimension
4. Determines `status`:
   - `OK` if all dimensions < 80% used
   - `APPROACHING_LIMIT` if any dimension ≥ 80%
   - `LIMIT_REACHED:<dim>` if the session is paused pending escalation
5. Serializes the KSB string
6. Prepends it to the system prompt string before the operator's task content

The KSB is assembled in the Kernel, not in the gateway or agent VM. The agent
receives it as part of the system prompt payload — it cannot modify the running
totals it reads from or the KSB it receives.

### 14.6 — Implementation Additions

- [ ] Implement `kernel/src/prompts/kernel_state_block.rs`:
      `fn build_ksb(session: &Session, effective_limits: &EffectiveLimits) -> String`
- [ ] Call `build_ksb` in `kernel/src/handlers/inference_request.rs` before forwarding
      to gateway — prepend KSB to `system_prompt` field
- [ ] Add KSB abbreviation legend to all non-negotiable system prompt templates
- [ ] Add `status = APPROACHING_LIMIT` logic at 80%, 90%, 95% thresholds
- [ ] Add `status = LIMIT_REACHED` logic when session is in token-paused state
- [ ] Test: KSB injected on every InferenceRequest (verified in gateway-received payload)
- [ ] Test: KSB reflects current token totals (not stale — reads from DB after each call)
- [ ] Test: KSB token overhead ≤ 200 tokens (tokenize the KSB string in test suite)

---

---

## 13. Implementation Checklist

- [ ] Make `prompt_sha256` and `response_sha256` non-optional in `InferenceCompleted`
- [ ] Add `tokens_cache_creation`, `tokens_cache_read`, `actual_units` to `InferenceCompleted`
- [ ] Implement `TokenLimit` enum with `Uncapped` default and `NonZeroU32` for counts
- [ ] Add `[tasks.token_policy]` section to `PlanTask` struct
- [ ] Add `[tasks.token_policy.limit_behavior]` with `LimitBehavior` enum
- [ ] DDL migration 3: `tokens_input_total`, `tokens_output_total`, `tokens_total` on sessions
- [ ] DDL migration 3: `token_limit_grants` table
- [ ] Implement cumulative token total update (atomic with `InferenceCompleted` transaction)
- [ ] Implement pre-admission char-proxy check for `max_tokens_input_per_request`
- [ ] Implement post-completion check for all per-request limits
- [ ] Implement pre-admission cumulative check against `max_tokens_total`
- [ ] Implement `TokenLimitApproaching` threshold events (80%, 90%, 95%)
- [ ] Add `TokenLimitExceeded` escalation class
- [ ] Implement `raxis token-limit approve <esc-id> --additional <N>` CLI
- [ ] Implement `raxis token-limit deny <esc-id>` CLI
- [ ] Compute `effective_limit = plan_limit + SUM(grants for session)` at pre-admission
- [ ] Tests:
      - Per-request limit exceeded → `fail_request`, session continues
      - Cumulative limit exceeded → escalation created, session paused
      - Token limit grant → effective limit updated, session resumes
      - Token limit denied → session fails with `FAIL_TOKEN_LIMIT_DENIED`
      - `fail_session` behavior → immediate termination, no escalation
      - Approaching threshold → events emitted at 80%, 90%, 95%
      - Plan with no token limits → `TokenLimit::Uncapped` default, no checks run

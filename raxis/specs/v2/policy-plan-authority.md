# RAXIS V2 — Policy-Plan Authority Hierarchy

> **Status:** V2 Specified
> **Cross-references:**
> - `integration-merge.md §12` — Protected path approval gate
> - `integration-merge.md §12.b` — Plan-level integration merge gates (additive)
> - `integration-merge.md §13` — Git push approval gate
> - `kernel-mediated-egress.md §2` — Two-level egress allowlist
> - `v2-deep-spec.md §INV-VM-CAP-03` — VM image policy bundle validation

---

## 1. The Core Invariant — INV-POLICY-01

> **INV-POLICY-01: The policy bundle is the immutable security floor. The plan operates
> within the policy envelope. Plans may only add protections; they may never remove or
> weaken protections established by the policy bundle.**

This invariant applies uniformly across all features. For each configurable dimension:

### Why Approach A Has the Strongest Security Model

Of the four approaches considered (see §8), Approach A provides the strongest security
posture for three reasons:

**1. The security floor is unconditional.** Policy protections cannot be removed,
weakened, or worked around by any plan — regardless of how the plan is constructed.
This is a structural property, not a runtime check. An attacker who gains the ability
to write arbitrary plan files still cannot disable deployment-level security controls
because the Kernel's enforcement of the policy floor is not predicated on the plan
being well-behaved.

**2. The failure mode is safe.** When policy and plan conflict, the more restrictive
interpretation always wins. There is no scenario where a conflict produces weaker
security than either policy or plan alone. This means the system degrades gracefully:
a misconfigured plan produces more security, not less.

**3. Strict-by-default closes the warning gap.** Approach A combined with `--strict`
as the default means policy-plan divergences never silently reach production. Every
divergence that reaches the Kernel has been explicitly acknowledged by the operator
(by running `--no-strict`), which is recorded in the `InitiativeCreated` audit event.
Auditors can query all initiatives approved with `approved_strict = false` and review
the specific warnings that were acknowledged.

Approaches B, C, and D all introduce mechanisms that complicate the enforcement model
(strict field separation, overridability flags, key hierarchy) without adding security
properties beyond what Approach A achieves through the simpler UNION/INTERSECTION rule
and strict-by-default approval.

| Dimension | Policy role | Plan role | Conflict resolution |
|---|---|---|---|
| VM images | Defines the permitted set + OCI digests | Selects one from the permitted set | Plan outside set → `FAIL_VM_IMAGE_NOT_PERMITTED` at `approve_plan` |
| Egress hosts | Defines permitted hostnames + methods | Declares per-task URL prefixes + methods | Plan methods beyond policy methods → Warning + runtime enforcement at policy ceiling |
| Protected merge paths | Always-required approval prefixes | Additive per-initiative extra gates | Plan `require_approval = false` for policy-protected path → Warning (policy enforced regardless) |
| Push approval | Minimum requirement (`require_push_approval_minimum`) | Per-initiative on/off | Plan `false` below policy minimum → Warning (policy enforced regardless) |
| Budget / lane ceiling | Hard ceiling values | `estimated_cost` estimate | Estimate exceeds ceiling → `FAIL_BUDGET_EXCEEDED` at admission |

**Permission dimensions** (egress, VM images, providers) follow INTERSECTION:
the effective permission is `policy ∩ plan`. The plan can only narrow, never expand.

**Protection dimensions** (protected paths, push approval) follow UNION:
the effective protection is `policy ∪ plan`. The plan can only add, never remove.

---

## 2. The `approve_plan` Warning System

### Philosophy

When a plan field conflicts with the policy bundle in a way that INV-POLICY-01 resolves
deterministically (the policy wins), the Kernel does not silently ignore the plan field
and it does not reject the plan. Instead it:

1. **Approves the plan** — the conflict is resolvable, the initiative can proceed
2. **Issues a warning** — explaining precisely what the plan field said and what the
   Kernel will actually do instead
3. **Lets the operator decide** — if the divergence is intentional (the operator knows),
   they proceed. If it was a mistake, they fix the plan.

This is the correct ergonomic trade-off: silent downgrade hides real mistakes; hard rejection
blocks legitimate workflows. The warning makes the Kernel's behavior fully transparent
without preventing the initiative from running.

### CLI Behavior

```bash
# Default: strict mode — any warning is a rejection
raxis plan approve plan.toml

# Lenient mode: approve with warnings displayed (opt-out from strict)
raxis plan approve --no-strict plan.toml

# Suppress warning output (strict mode still applies — only suppresses stdout display)
raxis plan approve --no-warnings plan.toml
```

**Why `--strict` is the default:**
Approach A is the strongest security model because the policy bundle is the immutable
floor. Approving a plan that silently diverges from policy — even with a warning — means
the initiative runs with operator expectations that don't match Kernel behavior. In a
production deployment this is a subtle but real risk: an operator believes they configured
X, the Kernel enforces Y, and the difference only becomes apparent at runtime. Strict
mode as default ensures every policy-plan divergence is a conscious, explicit operator
decision — not a mistake that was waved through.

**`--no-strict` use cases:**
- Deployments where the operator is aware of the divergence and accepts it
- Iterative plan development where the operator is prototyping and wants to run despite
  known policy gaps
- Plans that include intentionally redundant gate declarations for documentation clarity

**`--no-warnings` use cases:**
- Suppresses warning stdout output; strict mode behavior is unchanged
- Use when piping `raxis plan approve` output to a structured log collector that
  expects clean output; warnings are still recorded in the `InitiativeCreated` audit event

### Warning Output Format

```
raxis plan approve plan.toml

Validating plan against policy bundle (epoch 7)...

⚠ WARN [WARN_PROTECTION_OVERRIDDEN] plan.toml line 24
  [[integration_merge_gates]] declares require_approval = false for "src/payments/"
  This path is already protected by policy.toml [[protected_paths]].
  ─ Plan field value:   require_approval = false
  ─ Kernel behavior:   policy protection enforced; approval will be required regardless
  ─ Effect:            the plan field has no effect for this path prefix

⚠ WARN [WARN_PUSH_APPROVAL_DOWNGRADED] plan.toml line 8
  [plan] require_push_approval = false
  Policy bundle sets require_push_approval_minimum = true
  ─ Plan field value:   require_push_approval = false
  ─ Kernel behavior:   push approval will be required for this initiative
  ─ Effect:            plan field silently upgraded to true by policy floor

2 warning(s). Plan rejected (strict mode is default). Use --no-strict to approve with warnings.

Initiative ID: 3f7a9c2e
Plan SHA-256:  a4b8c1d3...
Policy epoch:  7
```

**With `--no-strict`:**
```
raxis plan approve --no-strict plan.toml

Validating plan against policy bundle (epoch 7)...

⚠ WARN [WARN_PROTECTION_OVERRIDDEN] plan.toml line 24
  ...

2 warning(s). Plan approved (--no-strict). Warnings recorded in audit chain.
Initiative ID: 3f7a9c2e
```

### Warning record in audit chain

Warnings are recorded in the `InitiativeCreated` audit event:

```rust
AuditEventKind::InitiativeCreated {
    initiative_id:    Uuid,
    plan_sha256:      String,
    policy_epoch:     u64,
    approve_warnings: Vec<ApproveWarning>,   // empty if no warnings
    approved_strict:  bool,                  // true if --strict was used and passed
}

pub struct ApproveWarning {
    pub code:          String,   // e.g., "WARN_PROTECTION_OVERRIDDEN"
    pub plan_location: String,   // e.g., "plan.toml line 24"
    pub description:   String,
    pub plan_value:    String,   // what the plan said
    pub kernel_value:  String,   // what the Kernel will actually do
}
```

Auditors can query initiatives that were approved with warnings — useful for compliance
review of any initiative that had a policy-plan mismatch.

---

## 3. Warning Catalog

### WARN_PROTECTION_OVERRIDDEN

**Trigger:** A `[[integration_merge_gates]]` entry in `plan.toml` declares
`require_approval = false` for a path prefix that is already covered by a
`[[protected_paths]]` entry in `policy.toml`.

**Kernel behavior:** The policy-level protection is enforced. The plan field has no
effect. The path will require operator approval on `IntegrationMerge`.

**Why a warning, not an error:** The operator may have included this entry by mistake
(copy-paste from a template that included the field), or may be aware that the policy
protects this path and explicitly wants to confirm no additional requirement — i.e., the
`false` was intentional as a "no further action needed." The warning surfaces the
discrepancy without blocking the initiative.

**Recommended fix:** Remove the `[[integration_merge_gates]]` entry for paths already
protected by policy. It is redundant and misleading.

---

### WARN_PUSH_APPROVAL_DOWNGRADED

**Trigger:** `plan.toml` sets `require_push_approval = false` (or omits the field,
defaulting to `false`), but `policy.toml` sets `require_push_approval_minimum = true`.

**Kernel behavior:** Push approval will be required for this initiative. The plan field
is silently upgraded to `true` by the policy floor.

**Why a warning, not an error:** `false` is the default. An operator who did not set
`require_push_approval` explicitly in their plan may not know the deployment policy
requires it. The warning informs them that push approval will apply even though they
didn't configure it.

**Recommended fix:** Explicitly set `require_push_approval = true` in `plan.toml` to
match the enforced behavior, eliminating the warning.

---

### WARN_EGRESS_METHOD_RESTRICTED

**Trigger:** A `[[tasks.allowed_egress]]` entry in `plan.toml` declares a method
(e.g., `"POST"`) that is not permitted by the corresponding `[[egress_hosts]]` entry in
`policy.toml` for that hostname.

**Kernel behavior:** At `EgressRequest` admission (Check E4), only policy-permitted
methods are accepted. The plan's declared method is effectively restricted to the
policy ceiling.

**Why a warning, not an error:** The plan declares *intent* for what methods a task
wants. The policy decides what is *permitted*. The warning surfaces that the task's
declared method capability will be narrower than planned — it may affect the agent's
ability to complete its work, which the operator should know about before running.

**Recommended fix:** Either (a) update `policy.toml` to permit the needed method for
the hostname, or (b) remove the method from `plan.toml` allowed_egress to match reality.

---

### WARN_INTEGRATION_MERGE_GATE_REDUNDANT

**Trigger:** A `[[integration_merge_gates]]` entry in `plan.toml` declares
`require_approval = true` for a path prefix that is already covered by a
`[[protected_paths]]` entry in `policy.toml`. This is a redundant (but harmless)
duplicate declaration.

**Kernel behavior:** The UNION operation deduplicates the entry. No change in
enforcement — the path already required approval via the policy.

**Why a warning, not an error:** Strictly harmless. The warning surfaces that the plan
entry is redundant and can be cleaned up.

**Recommended fix:** Remove the redundant `[[integration_merge_gates]]` entry. The
policy-level protection already covers it.

---

## 4. Policy Bundle — New Fields for INV-POLICY-01

### `require_push_approval_minimum`

```toml
# policy.toml

[push_policy]
require_push_approval_minimum = false   # default

# Set to true to mandate push approval for ALL initiatives in this deployment.
# Plans with require_push_approval = false will be warned and silently upgraded.
```

This field does not exist in V1. It is a V2 addition. Its absence (or `false`) means
no deployment-wide push approval mandate — plan-level `require_push_approval` is
honored as-is.

### `approve_plan_strict_by_default`

```toml
# policy.toml

[approve_policy]
approve_plan_strict_by_default = true   # default — strict mode is always on

# Set to false only for deployments where operators explicitly want lenient
# approval (warnings do not block). Not recommended for production deployments.
approve_plan_strict_by_default = false
```

`--strict` is the Kernel default. This policy field allows a deployment to explicitly
configure lenient mode as the default, removing the need for operators to pass
`--no-strict` on every invocation. Setting this to `false` is a conscious security
trade-off: it means plans with policy-plan divergences will be approved without explicit
operator acknowledgment. Not recommended for production.

---

## 5. `approve_plan` Shift-Left Check Order (Updated)

The `approve_plan` validation now runs in this order:

```
1. Verify Ed25519 plan signature against operator public key
2. Verify policy bundle epoch matches current Kernel epoch
3. For each task:
   a. Resolve vm_image → policy vm_images list
      → Not found: FAIL_VM_IMAGE_NOT_PERMITTED (hard error)
   b. For each allowed_egress entry:
      - hostname in policy egress_hosts?
        → Not found: FAIL_EGRESS_HOST_NOT_PERMITTED (hard error)
      - methods subset of policy egress_hosts methods?
        → Not subset: WARN_EGRESS_METHOD_RESTRICTED (warning)
4. For each integration_merge_gates entry:
   - require_approval = true AND path already in policy protected_paths?
     → WARN_INTEGRATION_MERGE_GATE_REDUNDANT (warning)
   - require_approval = false AND path already in policy protected_paths?
     → WARN_PROTECTION_OVERRIDDEN (warning)
5. Check plan.require_push_approval vs policy.push_policy.require_push_approval_minimum:
   - plan = false AND policy_min = true?
     → WARN_PUSH_APPROVAL_DOWNGRADED (warning)
6. Check plan.estimated_cost vs lane budget ceiling:
   - estimated_cost > ceiling? → FAIL_ESTIMATED_COST_EXCEEDS_CEILING (hard error)
7. Collect all warnings
8. If policy.approve_plan_strict_by_default = false AND --no-strict flag:
   - Approve plan, emit all warnings to stdout
   - Record warnings in InitiativeCreated audit event (approved_strict = false)
9. Else (default — strict mode):
   - Any warnings? → Reject plan, emit all warnings as errors
   - No warnings? → Approve plan (approved_strict = true)
```

**Hard errors** (`FAIL_*`) always reject the plan regardless of `--strict`.
**Warnings** (`WARN_*`) allow the plan to proceed unless `--strict` is active.

The distinction is: hard errors indicate a configuration that *cannot run correctly*
(plan references an unpermitted image — the VM will never boot). Warnings indicate
a configuration that *will run*, but not exactly as the plan declared — the Kernel's
behavior diverges from the plan's stated intent.

---

## 6. Implementation Checklist

- [ ] Add `ApproveWarning` struct to `crates/types/src/operator_wire.rs`
- [ ] Add `approve_warnings: Vec<ApproveWarning>` to `InitiativeCreated` audit event
- [ ] Add `approved_strict: bool` to `InitiativeCreated` audit event
- [ ] Implement warning collection in `kernel/src/handlers/approve_plan.rs`:
      - `WARN_PROTECTION_OVERRIDDEN`
      - `WARN_PUSH_APPROVAL_DOWNGRADED`
      - `WARN_EGRESS_METHOD_RESTRICTED`
      - `WARN_INTEGRATION_MERGE_GATE_REDUNDANT`
- [ ] Add `--strict` flag to `raxis plan approve` CLI command
- [ ] Add `--no-warnings` flag to `raxis plan approve` CLI command
- [ ] Add `[push_policy]` section to `PolicyBundle` struct with `require_push_approval_minimum`
- [ ] Add `[approve_policy]` section to `PolicyBundle` struct with `approve_plan_strict_by_default`
- [ ] Implement policy-floor enforcement for push approval in initiative activation:
      effective_require_push_approval = plan.require_push_approval || policy.require_push_approval_minimum
- [ ] Update `raxis plan approve` output format: warning blocks with plan_value / kernel_value
- [ ] Tests:
      - Plan with WARN_PROTECTION_OVERRIDDEN → approved with warning (default)
      - Plan with WARN_PROTECTION_OVERRIDDEN + --strict → rejected
      - Plan with WARN_PUSH_APPROVAL_DOWNGRADED → push approval enforced at runtime
      - Plan with WARN_EGRESS_METHOD_RESTRICTED → method blocked at EgressRequest admission
      - policy.approve_plan_strict_by_default = true → warnings become errors without --strict flag
      - Plan with no warnings → clean approval output, empty approve_warnings in audit

---

## 7. Tensions Identified During Design

Before arriving at INV-POLICY-01, the following specific conflict scenarios were analyzed.
Each reveals a case where `policy.toml` and `plan.toml` can disagree, and where the
resolution must be unambiguous.

### Tension 1 — Push Approval Mandate

**Scenario:** The deployment policy mandates push approval for all initiatives
(`require_push_approval_minimum = true`), but an operator writes a plan with
`require_push_approval = false` (or simply omits the field, accepting the default).

**What happens without a rule:** The plan's `false` silently overrides the policy
mandate. Push happens automatically. The compliance requirement is invisible — no error,
no warning.

**Resolution:** Protection dimension → UNION. Policy's `true` floor is always enforced.
Plan's `false` triggers `WARN_PUSH_APPROVAL_DOWNGRADED`. Operator is informed; initiative
still runs with push approval enforced.

---

### Tension 2 — Duplicate Protected Paths

**Scenario:** Policy protects `src/payments/`. An operator writes a plan with
`[[integration_merge_gates]] { path_prefix = "src/payments/", require_approval = true }`.
The plan is adding what the policy already requires.

**What happens without a rule:** UNION dedupes cleanly. No double escalation. The entry
is redundant but harmless.

**Resolution:** `WARN_INTEGRATION_MERGE_GATE_REDUNDANT`. The plan is approved; the
operator is told the entry is redundant and can be cleaned up. No behavioral change.

---

### Tension 3 — Plan Attempts to Remove a Policy Protection

**Scenario:** Policy protects `src/payments/`. An operator writes a plan with
`[[integration_merge_gates]] { path_prefix = "src/payments/", require_approval = false }`.
The intent (possibly accidental) is to declare "no gate needed for this path."

**What happens without a rule:** With a naive UNION, `false` entries are ignored —
the policy protection stands. But silently. The operator doesn't know their entry was
overridden.

**Resolution:** `WARN_PROTECTION_OVERRIDDEN`. The plan is approved; the operator is
explicitly told that the policy-level protection is enforced regardless of the plan field.
With `--strict`: plan rejected. This catches operators who genuinely believe they've
disabled the gate when they haven't.

---

### Tension 4 — Egress Method Expansion

**Scenario:** Policy permits `api.github.com GET` only. An operator writes a plan with
`allowed_egress = [{ url_prefix = "https://api.github.com/", methods = ["GET", "POST"] }]`.
The plan requests a method the policy does not permit.

**What happens without a rule:** At `EgressRequest` admission, the Kernel enforces
policy's `GET` ceiling. A `POST` request fails at runtime with `FAIL_EGRESS_METHOD_NOT_PERMITTED`.
The operator doesn't know the plan was over-specified until a task fails mid-run.

**Resolution:** Permission dimension → INTERSECTION. Detected at `approve_plan` shift-left
as `WARN_EGRESS_METHOD_RESTRICTED`. Operator is informed before any VM boots: "your task
declared POST but the Kernel will only permit GET." With `--strict`: plan rejected.

---

### Tension 5 — Two-Operator Model (Infra vs. Dev)

**Scenario:** In a larger organization, `policy.toml` is written and signed by the
infrastructure/security team (platform operator), while `plan.toml` is written and signed
by the engineer running the initiative (task operator). These are different people with
different keys and different intentions.

**Why this creates risk:** The task operator may write a plan that disagrees with
platform policy — not maliciously, but because they don't know the full policy
configuration. Or because the policy changed since they last looked.

**Resolution:** INV-POLICY-01 makes the platform operator (policy) always win on
protection dimensions. The task operator can only add gates; they cannot remove the
platform operator's gates. The warning system makes divergences visible — the task
operator sees exactly where their plan conflicts with platform policy before the initiative
runs.

This also means the `--strict` flag is useful as a platform-enforced default
(`policy.approve_policy.approve_plan_strict_by_default = true`) — the infra team can
require that all plan submissions in their deployment must resolve all policy-plan
conflicts before proceeding.

---

## 8. Approaches Considered and Rejected

### Approach B — Strict Separation (Policy and Plan Cover Distinct Fields)

**Description:** Policy and plan cover entirely different configuration fields. Any
field that appears in policy cannot appear in plan. No overlap, no ambiguity.

**Why rejected:** Eliminates per-initiative flexibility that is both legitimate and
necessary. Egress allowlists, protected path gates, and push approval requirements are
all things operators need to configure differently per initiative. Moving all of this to
the policy level means the ops/infra team must be involved in every initiative — which
destroys the operational model. Additionally, it makes the policy file enormous and hard
to reason about: it would need to enumerate every possible initiative's configuration.

---

### Approach C — Explicit Override Flags (`operator_overridable = true | false`)

**Description:** Each policy section declares whether it can be overridden by the plan.
If `operator_overridable = true`, the plan can set the field. If `false`, the plan cannot
touch it at all.

**Why rejected:** Introduces a new meta-concept (overridability) into the policy schema
that itself requires specification, tooling, and testing. The complexity of specifying
what "override" means for each section (full replacement? additive? UNION? INTERSECTION?)
replicates the same design problem one level up. Additionally, it requires the plan
parser to check the policy's overridability declarations before accepting plan fields —
a tight coupling between policy parsing and plan parsing that complicates both.

The implicit model of INV-POLICY-01 (protection = UNION, permission = INTERSECTION) is
simpler to implement and reason about than explicit overridability flags.

---

### Approach D — Signing Authority Hierarchy (Two Key Types)

**Description:** `policy.toml` is signed by a platform key (HSM-held, infra team).
`plan.toml` is signed by an initiative key (individual operator). When both keys are
valid but the documents conflict, the platform key (policy) wins.

**Why rejected:** Introduces real key management complexity. Two operator key types means
two key issuance procedures, two revocation procedures, two audit trails for key usage.
An operator who writes both `policy.toml` and `plan.toml` (common in small deployments)
must manage two separate keys — significant operational overhead for no additional
security benefit.

More fundamentally: the signing hierarchy doesn't resolve the _semantic_ conflict — it
only declares which document wins. INV-POLICY-01 already declares that policy wins.
The key hierarchy adds mechanism without adding clarity.

**Note:** A future version of RAXIS that supports multi-tenant deployments — where a
platform operator and tenant operators are genuinely different organizations — may need
to revisit this. In that context, key separation between platform and tenant is a
meaningful security property, not just operational overhead.

---

### The Silent Downgrade (Rejected in Favor of Warning System)

**Description:** When a plan field conflicts with policy (e.g., `require_push_approval = false`
against a policy that mandates push approval), silently upgrade the plan field to match
policy and proceed without any notification to the operator.

**Why rejected:** Silent downgrades hide real mistakes. An operator who set
`require_push_approval = false` believing it would take effect will be surprised when
their initiative requires push approval. Worse: they may believe the push gate was
working as they intended and not investigate when push approval fires. The warning system
makes the Kernel's actual behavior transparent: the operator knows what they configured,
what the Kernel will do instead, and why.

**Why the warning + strict-by-default is correct:**
A hard `FAIL_*` error and a warning-with-strict-default produce the same outcome in
practice: the plan is rejected unless the operator explicitly acknowledges the divergence.
The difference is in the error message: `FAIL_*` gives a binary "wrong or right" signal;
the warning system gives a precise "what you said vs. what the Kernel will do" explanation.
The warning form is more actionable — it tells the operator exactly how to fix the plan.
Strict mode as default means no plan silently diverges from policy in production.
`--no-strict` is an explicit, audited opt-out.

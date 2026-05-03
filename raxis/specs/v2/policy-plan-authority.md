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
# Default: approve with warnings displayed
raxis plan approve plan.toml

# Strict mode: any warning becomes a rejection
raxis plan approve --strict plan.toml

# Suppress warnings (for CI pipelines that have already reviewed)
raxis plan approve --no-warnings plan.toml
```

**`--strict` use cases:**
- CI pipelines where the plan is generated programmatically and any policy deviation
  indicates a generation error
- High-security deployments where operator-policy mismatches must always be caught before
  running
- Pre-commit hooks on plan files in version control

**`--no-warnings` use cases:**
- Automated re-runs of a previously reviewed plan in the same pipeline stage
- Scripted initiative batches where the operator has already reviewed all warnings
  in a prior dry-run step

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

2 warning(s). Plan approved. Use --strict to reject on warnings.

Initiative ID: 3f7a9c2e
Plan SHA-256:  a4b8c1d3...
Policy epoch:  7
```

**With `--strict`:**
```
raxis plan approve --strict plan.toml

Validating plan against policy bundle (epoch 7)...

⚠ WARN [WARN_PROTECTION_OVERRIDDEN] plan.toml line 24
  ...

✗ ERROR: --strict mode active. Plan rejected due to 2 warning(s).
  Fix the plan fields or remove --strict to approve with warnings.
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
approve_plan_strict_by_default = false   # default

# Set to true to make --strict the default behavior for all `raxis plan approve`
# invocations in this deployment, without requiring the operator to pass --strict
# on every command.
```

Useful for high-security deployments where policy-plan divergence should always be
treated as an error. Operators can still override per-invocation with
`raxis plan approve --no-strict` if needed.

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
8. If policy.approve_plan_strict_by_default = true OR --strict flag:
   - Any warnings? → Reject plan, emit all warnings as errors
9. Else:
   - Approve plan, emit all warnings to stdout
   - Record warnings in InitiativeCreated audit event
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

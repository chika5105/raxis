# RAXIS V2 — Per-Capability Policy Epoch Staleness Diffing

> **Status:** V2 Specified  
> **Promoted from:** `design-decisions.md §A.18` (deferred in V1)  
> **Scope:** Policy engine only. Does not interact with the orchestration architecture
> in `v2-deep-spec.md`. Can be implemented and shipped independently of the
> Orchestrator/Executor/Reviewer machinery.

---

## 1. Background: The V1 Model and Why It Was Blunt

### 1.1 V1 Blunt Invalidation

When an operator advances the policy epoch via `policy_manager::advance_epoch`, the V1
kernel runs:

```sql
UPDATE delegations
   SET epoch_stale = 1
 WHERE status = 'Active'
```

Every active delegation across every active session is immediately marked stale. On each
session's next intent submission, the kernel discovers `epoch_stale = 1` and requires a
renewal decision before the intent can be processed. The session stalls until the renewal
completes.

This is deliberately conservative: the kernel never makes the judgment "this epoch change
doesn't affect you." Every change is treated as potentially affecting every session.

### 1.2 Why V1 Chose This

The V1 rationale (documented in `design-decisions.md §A.18`) was correct for its context:

> *"Implementing this correctly requires the kernel to diff two policy epochs and determine
> per-capability impact, which is a complex and failure-prone piece of infrastructure to
> build before the basic system is proven."*

V1 also deliberately used the operational disruption as an incentive signal: epoch changes
are expensive (all sessions stall), so operators keep policy changes rare. This is the
correct incentive for a system in its first production deployment.

The `policy_epoch` field was established in the V1 `SessionCreated` audit event (4-field
attribution chain), making it a first-class audit citizen even in V1.

### 1.3 Why V2 Needs Something Better

V2 runs multiple concurrent sessions per initiative: one Orchestrator, multiple Executors,
multiple Reviewers. An epoch advance while a V2 initiative is mid-flight stalls **all of
them simultaneously**.

Example: operator rotates the auth signing key (`AuthPolicy` change). There are 8 active
Executor VMs. All 8 stall for renewal. The `PathPolicy`, `BudgetPolicy`, `WitnessPolicy`,
and `ProviderPolicy` delegations for those Executors are entirely unaffected by a key
rotation — but they stall anyway under the V1 model.

**However — the V2 mitigation argument:** V2 sessions are short-lived (one task per VM,
15–30 minutes typically). The disruption window is shorter than a V1 long-running session.
Additionally, an operator advancing the epoch has visibility into active initiatives and
should schedule epoch changes between initiatives, not mid-flight. The blunt invalidation
incentive remains correct.

**The conclusion:** V1 blunt invalidation works for V2 correctness. Per-capability
staleness diffing is a targeted operational improvement for cases where epoch advances
cannot be scheduled around active initiatives (e.g., emergency key rotation, security
incident response). It is not a correctness fix; it is an operational quality-of-life
improvement with a clear safety contract.

---

## 2. Design: Capability Classes

### 2.1 The Classification Model

The policy bundle is divided into logical **capability classes**. Each class maps to one
or more top-level sections in the signed `policy.toml`. A change to a class's sections
means all delegations of that class are affected; delegations of other classes are not.

```rust
/// Top-level classification of what a delegation grants authority over.
/// Each variant maps to one or more top-level sections in policy.toml.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CapabilityClass {
    /// path_allowlist rules, path tier assignments, claim_requirements.rules.
    /// Affects: which files sessions may write, which witness types are required.
    PathPolicy,

    /// Lane definitions, max_cost_per_epoch, admission unit weight table.
    /// Affects: how much budget sessions may consume per epoch.
    BudgetPolicy,

    /// Provider allowlist, model routing rules, gateway endpoints.
    /// Affects: which LLM providers sessions may use.
    ProviderPolicy,

    /// Escalation class definitions, operator approval thresholds.
    /// Affects: what escalation classes sessions may submit, who must approve.
    EscalationPolicy,

    /// Session token expiry, signing key material, session issuance rules.
    /// Affects: the auth properties of newly-issued session tokens.
    AuthPolicy,

    /// Gate definitions, required witness types, verifier subprocess configs.
    /// Affects: what evidence is required for task completion.
    WitnessPolicy,

    /// V2: VM image declarations and per-role default-image bindings.
    /// Top-level sections: `[[vm_images]]`, `[default_executor_image]`,
    /// `[default_verifier_images]`. Affects: which OCI digest a session
    /// boots against. Image changes do NOT affect any in-flight VM (a VM
    /// already boots from the digest pinned at session admission); they
    /// affect the *next* session a delegation issues. Sessions whose
    /// delegation includes image-pinning authority are marked stale so the
    /// renewal pass re-resolves the digest before the next boot. Sessions
    /// that hold no image-pinning capability (e.g., a Reviewer running on
    /// the kernel-canonical image per `INV-PLANNER-HARNESS-02`) are not
    /// affected.
    VmImagePolicy,

    /// V2: Environment-access-control gates and the credential→environment
    /// binding map. Top-level section: `[[environment_gates]]`. Affects:
    /// which URL prefixes count as "production" (and require approval),
    /// which `[[permitted_credentials]]` entry binds to which environment
    /// label, and the per-task environment-binding outcome enforced by
    /// `INV-ENV-01`. Changing a gate's `write_requires_approval` or its
    /// `url_prefixes` is functionally equivalent to changing the policy
    /// floor for every session that touches the affected URLs, so all
    /// such delegations are marked stale.
    EnvironmentPolicy,

    /// V2: Operator-ergonomics defaulting machinery.
    /// Top-level sections: `[prepare]` (e.g., `auto_inject_symbol_index`),
    /// `[orchestrator]` non-NNSP fields (e.g., default routing knobs).
    /// The Orchestrator's NNSP itself is NOT in this class — it is
    /// kernel-binary-pinned per `INV-PLANNER-HARNESS-06` and changes
    /// require a kernel re-deploy, not an epoch advance. This class
    /// captures the operator-authoring surface that affects how
    /// `raxis-cli plan prepare` writes defaults; in-flight sessions are
    /// not directly affected (the defaulted plan was bundle-sealed at
    /// admission), but pending plan-prepare invocations and any session
    /// holding a delegation that references the changed defaults
    /// (an `auto_inject_symbol_index` toggle, for example) are marked
    /// stale.
    ErgonomicsPolicy,

    /// V2: Custom-tool concurrency and resource caps.
    /// Top-level sections: `[custom_tool_limits]`. Affects: per-VM caps
    /// like `max_concurrent_custom_tool_invocations`,
    /// `max_queued_custom_tool_invocations`, and (V2.x) per-tool
    /// resource ceilings. Sessions whose delegations admit custom-tool
    /// invocations are marked stale; sessions without custom-tool
    /// authority (Reviewer per `INV-PLANNER-HARNESS-04`, Orchestrator
    /// per `INV-PLANNER-HARNESS-06`) are not.
    CustomToolPolicy,
}
```

### 2.2 Policy Bundle Section Map

The mapping from `policy.toml` top-level keys to `CapabilityClass` is **static and
compile-time defined** in the kernel's `policy_manager` module. This mapping is not
configurable by operators — it is part of the kernel binary.

| policy.toml top-level key | CapabilityClass |
|---|---|
| `[[claim_requirements.rules]]` | `PathPolicy` |
| `[path_tiers]` | `PathPolicy` |
| `[lanes]` | `BudgetPolicy` |
| `[admission_weights]` | `BudgetPolicy` |
| `[[providers]]` | `ProviderPolicy` |
| `[gateway]` | `ProviderPolicy` |
| `[escalation_classes]` | `EscalationPolicy` |
| `[auth]` | `AuthPolicy` |
| `[witness_gates]` | `WitnessPolicy` |
| `[verifiers]` | `WitnessPolicy` |
| `[[vm_images]]` | `VmImagePolicy` |
| `[default_executor_image]` | `VmImagePolicy` |
| `[default_verifier_images]` | `VmImagePolicy` |
| `[[environment_gates]]` | `EnvironmentPolicy` |
| `[[permitted_credentials]]` | `EnvironmentPolicy` |
| `[prepare]` | `ErgonomicsPolicy` |
| `[orchestrator]` (non-NNSP fields only) | `ErgonomicsPolicy` |
| `[custom_tool_limits]` | `CustomToolPolicy` |
| `[plan_bundle_limits]` | `AuthPolicy` |
| `[plan_signing]` | `AuthPolicy` |
| `[[plan_signing_keys]]` | `AuthPolicy` |
| `[verifier_credentials]` | `EnvironmentPolicy` |
| `[[verifier_credentials.images]]` | `EnvironmentPolicy` |

Any key not in this table is treated as `AuthPolicy` by default (the most conservative
class — affects the highest-impact security properties). Unknown keys default to the
strictest treatment, not the most lenient.

> **`[orchestrator]` is split between two classes.** The Orchestrator's
> NNSP is kernel-binary-pinned per `INV-PLANNER-HARNESS-06` and is NOT
> a policy.toml field — operators cannot change it. The non-NNSP
> Orchestrator knobs (default routing thresholds, conflict-resolution
> policy hints) are `ErgonomicsPolicy`. If a future spec re-introduces
> any operator-controlled NNSP-influencing fields under
> `[orchestrator]`, that addition MUST also update this table and the
> §2.3 lint (else the field falls through to `AuthPolicy`, which is
> safe but defeats per-capability diffing).

### 2.3 Section-Map Drift Lint

The mapping table above is the kernel binary's source of truth for
how a `policy.toml` top-level key maps to a `CapabilityClass`. As
V2.x and beyond grow the policy schema, every new top-level key MUST
be assigned a class explicitly. Falling through to the `AuthPolicy`
default is **safe** (over-marks rather than under-marks), but it
silently turns per-capability diffing back into V1-style blunt
invalidation for the new key — defeating the operational improvement
the spec was introduced for.

The kernel ships with a static lint that fails CI when the policy
schema introduces a top-level key that does not appear in the §2.2
table:

```rust
// crates/policy/tests/section_map_completeness.rs

#[test]
fn every_policy_toml_top_level_key_has_a_capability_class() {
    let schema_keys: HashSet<&'static str> =
        raxis_policy::schema::TOP_LEVEL_KEYS.iter().copied().collect();
    let mapped_keys: HashSet<&'static str> =
        raxis_policy::epoch::SECTION_TO_CLASS
            .iter()
            .map(|(k, _)| *k)
            .collect();

    let unmapped: Vec<&str> = schema_keys
        .difference(&mapped_keys)
        .copied()
        .collect();

    assert!(
        unmapped.is_empty(),
        "policy.toml schema introduces top-level keys without a \
         CapabilityClass mapping in policy-epoch-diffing.md §2.2: {:?}. \
         Add an explicit row to SECTION_TO_CLASS rather than relying on \
         the AuthPolicy default — silent fallthrough defeats per-capability \
         diffing for these keys.",
        unmapped
    );
}
```

`raxis_policy::schema::TOP_LEVEL_KEYS` is the canonical list of
top-level keys produced by parsing the policy.toml schema definition;
`SECTION_TO_CLASS` is the in-binary materialization of the §2.2
table. Any mismatch — schema introduces a new key, or the table is
out-of-date relative to the schema — fails the test with the offending
key list.

The reverse direction (a key in `SECTION_TO_CLASS` that is no longer
in the schema) is also checked, with a softer assertion: a stale
mapping costs nothing at runtime, but flagging it during cleanup is
useful when a policy section is removed in a future version.

---

## 3. The `PolicyDelta` Computation

### 3.1 Data Structures

```rust
/// Produced by advance_epoch() before any staleness updates are applied.
pub struct PolicyDelta {
    pub from_epoch:       u64,
    pub to_epoch:         u64,
    /// Which capability classes had at least one changed top-level section.
    /// Empty means no capability-relevant sections changed (unusual but possible
    /// if only metadata/comments changed in the bundle).
    pub affected_classes: HashSet<CapabilityClass>,
}
```

### 3.2 Diff Algorithm

The diff operates on the **deserialized policy bundle structs**, not the raw TOML bytes.
Byte-level diff is rejected because it would flag cosmetic changes (whitespace, comment
reordering, field reordering within a section) as substantive. Struct-level diff compares
semantic values.

```text
advance_epoch(new_bundle_bytes):
  1. Verify Ed25519 signature on new_bundle_bytes → reject if invalid
  2. Deserialize new_bundle_bytes → new_bundle: PolicyBundle
  3. Load current_bundle from ArcSwap<PolicyBundle>
  4. Compute delta = diff_bundles(current_bundle, new_bundle)
  5. If diff computation fails → delta = ALL_CLASSES (fallback to blunt)
  6. Run staleness update (§3.3) using delta.affected_classes
  7. Atomically swap ArcSwap<PolicyBundle> to new_bundle
  8. Emit PolicyEpochAdvanced audit event
  9. Return Ok(delta)
```

**Why the signature check comes first (step 1):** A malicious bundle that passes the diff
but fails the signature check would have already contaminated the diff result. Signature
verification is the precondition for any further processing.

**Why the ArcSwap happens after the staleness update (step 7):** Between steps 4 and 7,
new intents arriving from active sessions see the old policy (which is correct — they are
processed under the old epoch). Staleness is marked atomically in SQLite before the new
policy is visible. No session can observe the new policy without first being checked against
the stale flag.

### 3.3 Staleness Update Query

```sql
-- Only called after PolicyDelta is computed and contains specific classes.
-- If fallback to blunt: omit the AND capability_class IN (...) clause.
UPDATE delegations
   SET epoch_stale = 1
 WHERE epoch_at_creation < :new_epoch
   AND status = 'Active'
   AND capability_class IN (:class_1, :class_2, ...)   -- from delta.affected_classes
```

The query is executed inside a SQLite `BEGIN IMMEDIATE` transaction. The staleness update
and the audit event write (step 8) are committed together atomically (INV-STORE-02).

### 3.4 Fallback to Blunt Invalidation

If `diff_bundles` returns an error for any reason:
- Deserialization of the new bundle structure failed
- A section's semantic comparison panicked
- An unexpected type mismatch in the bundle schema

The kernel falls back to V1 blunt invalidation:
```sql
UPDATE delegations SET epoch_stale = 1 WHERE status = 'Active'
```

The `PolicyEpochAdvanced` audit event records `fallback_to_blunt: true` so this is visible
in the audit log. **Failure of the diff engine is never a permission grant.**

---

## 4. Interaction with Active V2 Sessions

### 4.1 What Happens When a Session Hits a Stale Delegation

When a session submits any intent and the kernel finds `epoch_stale = 1` on its delegation:

1. The intent is held (not rejected).
2. The kernel evaluates the session against the **new** policy bundle.
3. If the session's existing capabilities are still valid under the new epoch → kernel
   issues a renewed delegation (`epoch_at_creation = new_epoch`, `epoch_stale = 0`),
   applies it, and processes the held intent. No session interruption.
4. If the session's capabilities are **not** valid under the new epoch (e.g., a model
   it was using is no longer in the provider allowlist) → kernel returns
   `FAIL_EPOCH_RENEWAL_DENIED` for the held intent. The Orchestrator receives
   `KernelPush::SessionCapabilityRevoked { session_id, reason }` and must decide
   whether to abort the sub-task or escalate.

### 4.2 Renewal Is Silent When It Succeeds

Case 3 (auto-renewal) is transparent to the session. The session submits an intent, the
kernel detects staleness, renews internally, and returns the normal intent response. The
session does not observe the epoch check. This is the common case — most epoch advances
(provider additions, budget adjustments) do not affect an in-flight Executor working on
a path-scoped task.

### 4.3 The V2 Mid-Initiative Sequencing

Consider an initiative with:
- `orchestrator` session (active)
- `executor_a`, `executor_b` sessions (active, working on `src/api/` and `src/db/`)
- `reviewer_c` session (pending, waiting for `executor_a`)

An epoch advance changes `ProviderPolicy` only (new model added to the allowlist).

Under per-capability staleness diffing:
- `ProviderPolicy` delegations → marked stale
- All other delegations (`PathPolicy`, `BudgetPolicy`, etc.) → unchanged

On next intent from `executor_a` (a `SingleCommit`):
- `executor_a`'s `PathPolicy` delegation is not stale → intent processed normally
- `executor_a`'s `ProviderPolicy` delegation is stale → renewed silently (the new
  provider list still includes the model `executor_a` is using) → no disruption

The initiative continues without interruption. All 3 active sessions auto-renew silently.

Under V1 blunt invalidation, all 3 sessions would have stalled for renewal. The improvement
is real but the risk of correctness error is bounded by the fallback guarantee.

### 4.4 Epoch Advances During `approve_plan` — Still Blunt

If an epoch advances while `approve_plan` is executing (between the 7 validation checks and
the final `admit_in_tx` write), the entire `approve_plan` transaction is **aborted**. The
operator must resubmit the plan.

Per-capability staleness diffing applies only to **already-active sessions** — sessions that
have a row in the `sessions` table with `status = 'Active'`. A plan submission in progress
is not yet an active session. There is no partial staleness evaluation for pre-admission
sessions. This constraint preserves the atomicity of plan admission (INV-STORE-02).

---

## 5. Audit Event

The existing `AuditEventKind::PolicyEpochAdvanced` is extended for V2:

```rust
AuditEventKind::PolicyEpochAdvanced {
    from_epoch:         u64,
    to_epoch:           u64,
    // V2 additions:
    affected_classes:   Vec<CapabilityClass>,
    stale_count:        u32,    // sessions marked stale
    unaffected_count:   u32,    // sessions not marked stale (preserved)
    fallback_to_blunt:  bool,   // true if diff failed and blunt invalidation was used
}
```

An external auditor can reconstruct:
- Which capability classes changed in each epoch advance
- How many sessions were disrupted vs. preserved
- Whether the per-capability machinery worked correctly or fell back to blunt

---

## 6. What Does Not Change

The following V1 mechanisms are **unchanged** by this spec:

| Mechanism | Status |
|---|---|
| Ed25519 signing ceremony for `advance_epoch` | Unchanged |
| `policy_epoch` field in `SessionCreated` audit event | Unchanged |
| V1 blunt invalidation code path | Preserved as fallback, not removed |
| Stale delegation → renewal decision enforcement logic | Unchanged |
| `FAIL_EPOCH_RENEWAL_DENIED` error code | Unchanged |
| Per-session `epoch_at_creation` tracking | Unchanged |

---

## 7. Alternatives Considered

### Alt A — Field-Level Diff (Fine-Grained)

Compare every field in the policy bundle struct recursively. Mark only delegations whose
specific authorized values appear in a changed field.

**Rejected:** Field-level diff is semantically ambiguous for a policy bundle. A field that
appears unchanged may have had its meaning altered by a change to an enum variant it
references (e.g., a `TierName` that was `"standard"` is still `"standard"` but the
`[path_tiers]` section now defines `"standard"` differently). Field-level diff would
produce false negatives — concluding "no change" when there was a semantic change.
Conservative coarse-grained class-level diff is correct even if it over-marks.

### Alt B — Capability-Class-Level Diff (Adopted)

Compare top-level sections of the policy bundle. If any field within a section changed,
the entire class is affected. This is:
- Fast: O(num_top_level_sections) comparison
- Conservative: over-marks rather than under-marks (never a false negative)
- Unambiguous: section identity is a well-defined schema concept

### Alt C — Operator-Annotated Diff

Require operators to declare which capability classes their epoch advance affects at
signing time (e.g., a `[affected_classes]` field in the new bundle).

**Rejected:** Operator-declared scope creates a trust gap — an operator (or an attacker
who compromised the signing ceremony) could declare `affected_classes = []` to suppress
all staleness marking for a change that actually affects all classes. The diff must be
computed by the kernel from the bundle content, not declared by the submitter.

---

## 8. Implementation Checklist

- [ ] Add `CapabilityClass` enum (10 variants: the 6 V1.x classes plus
      V2 `VmImagePolicy`, `EnvironmentPolicy`, `ErgonomicsPolicy`,
      `CustomToolPolicy`) to `crates/policy/src/lib.rs`.
- [ ] Add `PolicyDelta` struct to `crates/policy/src/lib.rs`
- [ ] Implement `diff_bundles(old: &PolicyBundle, new: &PolicyBundle) -> PolicyDelta`
      in `crates/policy/src/epoch.rs` (new file)
- [ ] Materialize the §2.2 table as
      `crates/policy/src/epoch.rs::SECTION_TO_CLASS` —
      a static `&[(&'static str, CapabilityClass)]` array. The diff
      walker iterates this array; any top-level key not present
      defaults to `AuthPolicy` AND emits a `PolicySchemaUnmapped` warn
      log (operator-visible, not failure-class).
- [ ] Add `crates/policy/tests/section_map_completeness.rs` per §2.3.
      The test fails CI if the schema introduces a key not in
      `SECTION_TO_CLASS`. New v2.x policy fields MUST add a row to
      `SECTION_TO_CLASS` or explicitly opt into `AuthPolicy` fallthrough.
- [ ] Add `capability_class` column to `delegations` table in DDL migration 2
      (or migration 3 if migration 2 is already shipped). The new V2
      classes are stored as their `serde::Serialize` representation
      (string), forward-compatible with future class additions.
- [ ] Update `policy_manager::advance_epoch` in `kernel/src/policy/manager.rs` to call
      `diff_bundles` and use targeted SQL UPDATE
- [ ] Add fallback to blunt on `diff_bundles` error
- [ ] Extend `AuditEventKind::PolicyEpochAdvanced` with V2 fields
- [ ] Add `KernelPush::SessionCapabilityRevoked` variant to `crates/types/src/operator_wire.rs`
- [ ] Add `FAIL_EPOCH_RENEWAL_DENIED` to `kernel/src/errors.rs` if not present
- [ ] Update `advance_epoch` to abort in-progress `approve_plan` transactions
      (check `initiatives` table for `state = 'Admitting'` before diff; abort if found)
- [ ] Add tests:
      - Targeted staleness for each of the 10 classes
        (one test per class — change a single section, verify only
        that class is marked).
      - **VmImagePolicy**: change `[default_executor_image].alias`;
        a session with `capability_class = VmImagePolicy` is marked
        stale; an unrelated `BudgetPolicy` session is not.
      - **EnvironmentPolicy**: change
        `[[environment_gates]].write_requires_approval`; sessions
        whose delegations admit egress to the gate's URL prefixes
        are marked stale.
      - **ErgonomicsPolicy**: toggle
        `[prepare].auto_inject_symbol_index`; sessions are marked
        stale only if they hold a delegation that references
        prepare-time defaulting (e.g., a session whose plan was
        prepared against the old default and is still in-flight).
      - **CustomToolPolicy**: lower
        `[custom_tool_limits].max_concurrent_custom_tool_invocations`;
        Executor sessions are marked stale; Reviewer / Orchestrator
        sessions (no custom-tool authority) are not.
      - Section-map drift lint: schema-only test ensures every
        `policy.toml` top-level key is mapped.
      - Fallback test: malformed bundle → blunt invalidation,
        `fallback_to_blunt: true` audit field set.
      - Genesis-phase abort test, silent auto-renewal test
        (carried over from V1).

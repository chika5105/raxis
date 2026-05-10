# RAXIS Claims & Gates — End-to-End Explained

## What is a claim?

A claim is a **proof requirement**. The operator says: "Before any AI agent can modify files in `migrations/`, I need proof that tests passed." The claim system enforces this.

---

## Step 1: Operator Configures Policy

The operator writes this in `policy.toml`:

```toml
# "Which files need proof, and what kind of proof?"
[claim_requirements]
default_action = "deny"          # everything is locked down unless a rule says otherwise

[[claim_requirements.rules]]
path_glob = "migrations/**"      # files matching this pattern...
claim_types = ["TestSuite"]      # ...require this type of proof

[[claim_requirements.rules]]
path_glob = "src/**"
claim_types = ["WriteCode"]

# "Who runs the proof?"
[[gates]]
gate_type = "TestSuite"                              # matches the claim_type above
verifier_command = "/usr/local/bin/run-tests.sh"     # a real executable, not a model
max_wall_seconds = 120                                # kill it after 2 minutes
max_memory_bytes = 536870912                          # 512 MB max
network_allowed = false                               # no internet access
```

**In plain English:** "If an agent touches anything in `migrations/`, a test suite must pass before I'll accept the change."

---

## Step 2: Agent Makes a Change

The AI agent edits `migrations/0042_add_users.sql` and submits a `SingleCommit` intent to the kernel.

---

## Step 3: Kernel Derives What Happened

The kernel runs:
```
git diff <base_sha> <head_sha> --name-status --no-renames
```

This produces `touched_paths = ["migrations/0042_add_users.sql"]`.

**The agent cannot lie about which files it touched.** The kernel computes this from git, not from the agent's claim.

---

## Step 4: Kernel Looks Up Requirements

The kernel runs `policy_lookup::required_claims(touched_paths, policy)`:

```
"migrations/0042_add_users.sql" matches "migrations/**"
→ required claim types = ["TestSuite"]
```

---

## Step 5: Auto-Derive Claims from Witnesses (Gap Fix)

> **Implementation note:** The original spec designed the system so the planner
> would actively populate `submitted_claims`. The planner driver hardcoded
> `submitted_claims: vec![]`. This was fixed in `gates/mod.rs` Step 2.5:
> the kernel now auto-derives claims from passing witness records.

Before evaluating claims, the kernel checks `witness_records` for each required claim type:

```rust
// For each required claim type, check if a passing witness exists
let witness = witness::lookup(evaluation_sha, task_id, claim_type, None, store)?;
if witness.result_class == Pass {
    // Inject a synthetic SubmittedClaim with the witness blob hash
    effective_claims.push(SubmittedClaim {
        claim_type: claim_type.to_owned(),
        evidence_ref: Some(witness.blob_sha256.clone()),
    });
}
```

This is strictly more secure than planner-submitted claims — the kernel already has the evidence and the agent can't fabricate a passing witness.

---

## Step 6: Kernel Checks the Agent's Claims

The kernel evaluates the **effective claims** (auto-derived + planner-submitted):

### Check A: Does the agent have permission (delegation)?

```
authority::check_capability(session_id, "TestSuite", store)
```

A delegation is a **kernel-issued credential** that the operator granted via CLI:
```bash
raxis-cli escalation approve <escalation_id> --scope "migrations/**"
```

The operator signs this with their Ed25519 private key. The agent cannot create one.

- **No delegation** → `DelegationInsufficient` → intent rejected. Full stop.
- **Expired delegation** → same result.
- **Delegation exists** → proceed.

### Check B: Did a matching claim exist?

The kernel looks for `{ claim_type: "TestSuite" }` in the effective claims.

- **Not found** → `Insufficient` → intent rejected.
- **Found** (auto-derived or planner-submitted) → proceed.

### Check C: Does the claim's scope cover the actual files?

For auto-derived claims, the `evidence_ref` is the blob hash (passes all paths). For planner-submitted claims, scope is checked against the touched paths.

- **Scope too narrow** → `ScopeInsufficient` → rejected.
- **Scope matches** → proceed.

---

## Step 7: Kernel Verifies Witness Evidence

Even after A/B/C pass, the kernel checks:

```
witness::lookup(evaluation_sha, task_id, "TestSuite", witness_index)
```

A witness record is created when the kernel **spawns the verifier subprocess** and the verifier **reports back**:

1. Kernel spawns `/usr/local/bin/run-tests.sh` in the agent's worktree
2. The script runs the test suite against the agent's code
3. The script sends a `WitnessSubmission` back to the kernel via UDS socket
4. The kernel writes a `witness_record` row: `{ result_class: "Pass", blob_sha256: "..." }`

- **No witness record exists** → `PendingWitness` → task enters `GatesPending` state. The agent waits.
- **Witness exists but `result_class = Fail`** → task stays in `GatesPending`.
- **Witness exists and `result_class = Pass`** → gate satisfied → intent admitted.

---

## The Full Pipeline (Visual)

```
Agent modifies migrations/0042_add_users.sql
                    │
                    ▼
        ┌─── Kernel: git diff ───┐
        │  touched_paths = [...]  │
        └────────────────────────┘
                    │
                    ▼
        ┌─── Policy Lookup ──────┐
        │  "migrations/**"       │
        │  requires: TestSuite   │
        └────────────────────────┘
                    │
                    ▼
        ┌─── Auto-Derive Claims ─┐
        │  witness Pass exists?  │
        │  → inject claim        │
        └────────────────────────┘
                    │
            ┌───────┼───────┐
            ▼       ▼       ▼
         Check A  Check B  Check C
        Delegation Claim   Scope
         exists?  present? covers?
            │       │       │
            └───────┼───────┘
                    │ all pass
                    ▼
        ┌─── Witness Lookup ─────┐
        │  Has run-tests.sh      │
        │  returned Pass for     │
        │  this (task, sha)?     │
        └────────────────────────┘
                    │
              ┌─────┴─────┐
              ▼           ▼
           No Pass     Pass exists
              │           │
              ▼           ▼
        GatesPending   ADMITTED
        (wait for       (intent
         verifier)      accepted)
```

---

## Edge Cases

### 1. Agent submits a fake claim type

Agent sends `submitted_claims: [{ claim_type: "TestSuite" }]` without tests ever running.

**Result:** Check A passes (if delegation exists), Check B passes (string matches), Check C passes (scope okay). But **Step 7 fails** — no witness record exists because the kernel never spawned a verifier, or the verifier didn't return Pass. Task goes to `GatesPending`. The agent can't proceed.

**Why:** The agent can't write to `witness_records`. Only kernel-spawned verifier subprocesses can, using a single-use token the kernel generated.

### 2. Agent submits a claim type that doesn't exist in policy

Agent sends `submitted_claims: [{ claim_type: "FakeGate" }]`.

**Result:** `policy_lookup::required_claims` determines what's required based on the **touched paths**, not the agent's claims. If `migrations/**` requires `TestSuite`, then `FakeGate` is irrelevant — it's ignored (extra claims are accepted but don't satisfy requirements). The kernel still needs `TestSuite`, which is missing → `Insufficient`.

### 3. No `claim_requirements` rules at all

```toml
[claim_requirements]
default_action = "permit"
```

**Result:** `required_claims` returns an empty vec → no claims needed → no gates → intent goes straight through. This is the "no restrictions" mode.

### 4. `default_action = "deny"` with no rules

```toml
[claim_requirements]
default_action = "deny"
# no [[claim_requirements.rules]]
```

**Result:** Every path that doesn't match a rule falls through to `StrictDefault`. The `required_claims` function returns `Err(GateError::PolicyMisconfigured)` — the kernel rejects with a configuration error, not a planner error. The operator made a mistake.

### 5. Verifier binary crashes

The kernel's wall-clock timeout kills the subprocess. No witness is produced. Task stays `GatesPending`. On kernel crash + recovery, `witness_records` is durable — any witnesses that arrived pre-crash are preserved. Missing verifiers are re-spawned on the next intent.

### 6. Verifier binary returns Fail

Witness record is written with `result_class = Fail`. The gate is **not** satisfied. The agent must fix the code, submit a new `SingleCommit` (new `evaluation_sha`), and the kernel spawns a fresh verifier run against the new SHA.

### 7. Break-glass override

Two operators sign a break-glass activation:
```bash
raxis-cli breakglass activate --justification "production down"
```

**Result:** `gates/mod.rs` Step 1 detects `BreakglassStatus::Active` → skips all claim/gate checks → returns `GateEvalResult::BreakglassPass`. Every action is logged with `BreakglassAction` in the audit chain. TTL auto-expires (default 4 hours).

---

## Key Source Files

| File | Role |
|------|------|
| `kernel/src/gates/mod.rs` | Entry point: `evaluate_claims()` + auto-derivation (Step 2.5) |
| `kernel/src/gates/claim.rs` | Delegation + scope + submission checks |
| `kernel/src/gates/policy_lookup.rs` | Maps paths → required claim types via glob matching |
| `kernel/src/gates/witness.rs` | Read-side witness lookup (dumb — returns record as-is) |
| `kernel/src/gates/verifier_runner.rs` | Spawns verifier subprocesses with env scrub + resource limits |
| `kernel/src/witness_index.rs` | Write-side witness store (blob FS + SQL index) |
| `crates/policy/src/bundle.rs` | `PolicyBundle` — parsed policy.toml |
| `crates/types/src/intent.rs` | `SubmittedClaim`, `IntentRequest` wire types |

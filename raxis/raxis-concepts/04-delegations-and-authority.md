# RAXIS Delegations & Authority — End-to-End Explained

## What is a delegation?

A delegation is an **operator-signed permission slip**. It grants a specific agent session the right to perform a specific capability class (e.g., "WriteCode", "ReadSecrets") for a limited time. Without one, the agent's claims are rejected.

---

## Why are delegations needed?

Claims require evidence (witness records from verifiers). But claims also require **permission**. The operator must have explicitly said: "Yes, this session is allowed to assert WriteCode claims on these files."

Without delegations, any agent could claim any capability. The delegation is the **authorization** step; the witness is the **evidence** step.

---

## Step 1: Agent Hits a Claim Requirement

When the kernel runs `claim::evaluate` and a required claim type maps to a `CapabilityClass`, the kernel checks:

```rust
delegation::check_capability(session_id, &capability, store)
```

This returns one of:

| Status | Meaning | Effect |
|---|---|---|
| `Active` | Operator granted this, TTL hasn't expired | Proceed |
| `StaleOnNextUse` | Policy epoch advanced — this delegation needs renewal | Grace use: proceed, but mark for renewal |
| `Expired` | TTL expired | **Reject** — `DelegationInsufficient` |
| `RenewalRequired` | Already used under StaleOnNextUse grace | **Reject** |
| `NotGranted` | No delegation row exists | **Reject** |

---

## Step 2: Operator Grants a Delegation

The operator grants delegations via CLI:

```bash
raxis-cli delegation grant \
  --session-id "sess-abc" \
  --capability "WriteCode" \
  --scope '{"paths": ["src/**"]}' \
  --ttl 3600 \
  --max-uses 10
```

This triggers the kernel to:

1. **Verify TTL** — must not exceed `policy.max_delegation_ttl` (INV-DELEG-02)
2. **Verify capability ceiling** — must be within the role's allowed capabilities (INV-DELEG-03)
3. **Verify Ed25519 signature** — the CLI signs with the operator's private key (INV-DELEG-04)
4. **Check uniqueness** — at most one active delegation per `(session_id, capability_class)` (INV-DELEG-01)
5. **INSERT** into the `delegations` table

```sql
INSERT INTO delegations (
    delegation_id, session_id, capability_class, scope_json,
    granted_by, granted_at, expires_at, use_count, max_uses, status
) VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?, 'Active')
```

---

## Step 3: Delegation Lifecycle

```
Operator grants delegation
        │
        ▼
    ┌── Active ──────────────────┐
    │  TTL countdown running     │
    │  use_count increments      │
    │  on each gate pass         │
    └────────────────────────────┘
        │                    │
        │ TTL expires        │ Policy epoch advances
        ▼                    ▼
    ┌── Expired ──┐   ┌── StaleOnNextUse ────┐
    │  Permanent  │   │  One grace use left  │
    │  rejection  │   │  (soft transition)   │
    └─────────────┘   └──────────────────────┘
                             │ used once
                             ▼
                      ┌── RenewalRequired ─┐
                      │  Permanent reject  │
                      │  until re-granted  │
                      └────────────────────┘
```

---

## Policy Epoch Advances

When the operator updates `policy.toml` and the kernel detects a new epoch:

```rust
delegation::mark_stale_on_epoch_advance(store)
```

This runs:
```sql
UPDATE delegations SET status='StaleOnNextUse' WHERE status='Active'
```

**Why:** Policy changes might tighten restrictions. Existing delegations get one more use (grace period), then the operator must re-grant under the new policy.

---

## Edge Cases

### 1. Agent tries to use capability it was never delegated

`check_capability` returns `NotGranted` → `DelegationInsufficient` → intent rejected. No grace, no retry.

### 2. Two operators try to grant the same capability to the same session

UNIQUE constraint on `(session_id, capability_class)` → second grant fails with `DelegationAlreadyActive`. The existing delegation must expire or be revoked first.

### 3. Delegation expires mid-evaluation

`check_capability` reads `expires_at` from the row. If `expires_at <= now` → `Expired`. This is a pure read check — no timer needed. Even if the delegation expires between the check and the gate pass, the evaluation is atomic.

### 4. `max_uses` is exhausted

When `use_count >= max_uses`, the delegation transitions to `Expired` on the next `check_capability` call. The operator must grant a new delegation.

### 5. Agent forges an operator signature

The Ed25519 signature is verified against the operator's public key from the policy. The agent doesn't have the operator's private key. A forged signature fails verification → `DelegationSignatureInvalid` → grant rejected.

---

## Key Source Files

| File | Role |
|------|------|
| `kernel/src/authority/delegation.rs` | Grant, check, record use, epoch stale marking |
| `kernel/src/authority/keys.rs` | `AuthorityError` types, key resolution |
| `crates/types/src/lib.rs` | `DelegationStatus`, `CapabilityClass` enums |
| `crates/crypto/src/delegation.rs` | Ed25519 signature verification |

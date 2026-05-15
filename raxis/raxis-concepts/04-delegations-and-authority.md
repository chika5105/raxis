# RAXIS Delegations & Authority — End-to-End Explained

> **Audience.** Operators issuing `delegation grant` from the CLI,
> reviewers debugging "why was this gate rejected", and contributors
> touching `kernel/src/authority/delegation.rs` or the
> `delegations` migration.
>
> **Authority.** Spec is `specs/v1/kernel-store.md` §2.5.1 Table 7
> (DDL) and §2.5.5 (signing domain); the runtime is
> `kernel/src/authority/delegation.rs`; the CLI is
> `cli/src/commands/delegation.rs`. Where this guide and any of those
> files disagree, the source files win — fix one or the other and
> file a follow-up.

---

## What is a delegation?

A delegation is an **operator-signed permission slip**. It binds a single
agent **session** to a single **`CapabilityClass`** (e.g.
`WriteCode`, `ReadSecrets`) for a bounded TTL. Without an *Active*
delegation, every gate that maps to that capability class is rejected
with `DelegationInsufficient` — the witness alone is not enough.

The delegation answers the **authority question** ("does the operator
permit this session to make this kind of claim?"). The
witness/verifier path answers the **evidence question** ("did the
asserted change actually pass the mechanical check?"). Both must hold
before a gate clears.

**Paradigm anchor.** Delegations are the authority side of
**R-7 — Operator-bound authority**: every privileged decision is
chained back to an Ed25519 signature from a key that lives outside
the agent's blast radius. The kernel never grants a capability on
its own initiative.

---

## Why are delegations needed?

Claims require evidence (witness records from verifiers). But claims
also require **permission**. The operator must have explicitly said:
"Yes, this session is allowed to assert WriteCode claims." Without
delegations, any agent could claim any capability simply by producing
a passing witness.

The delegation is the **authorisation** step; the witness is the
**evidence** step. Both halves are required, and the kernel checks
them in that order — delegation first, then witness — so an
unauthorised session can never spend verifier compute it has no right
to use.

---

## At-rest schema (Table 7, `delegations`)

The DDL is rendered by `crates/store/src/migration.rs` at migration 1
and is **frozen** for v1 (no `ALTER TABLE delegations` exists in any
later migration). The columns and constraints are:

```sql
CREATE TABLE IF NOT EXISTS delegations (
    delegation_id        TEXT    NOT NULL PRIMARY KEY,
    session_id           TEXT    NOT NULL REFERENCES sessions(session_id),
    capability_class     TEXT    NOT NULL,
    delegating_role_id   TEXT    NOT NULL,   -- the operator role that signed
    delegate_role_id     TEXT    NOT NULL,   -- session.role at grant time
    effective_from       INTEGER NOT NULL,   -- unix seconds (lower bound)
    expires_at           INTEGER NOT NULL,   -- unix seconds (hard expiry)
    revoked_at           INTEGER,            -- soft revocation timestamp
    status               TEXT    NOT NULL DEFAULT 'Active'
        CHECK (status IN ('Active', 'StaleOnNextUse', 'RenewalRequired')),
    epoch_stale_set_at   INTEGER,            -- when policy_manager set status='StaleOnNextUse'
    operator_signature   BLOB    NOT NULL,   -- raw Ed25519 sig over signing domain
    UNIQUE (session_id, capability_class)    -- INV-DELEG-01
);
```

There is **no** `granted_by`, `granted_at`, `scope_json`,
`use_count`, or `max_uses` column. Earlier drafts of this doc claimed
those columns; they are not part of the schema.

`Revoked` and `Expired` are *runtime-derived* states, not stored
values. The kernel computes them from `revoked_at` and `expires_at`
during `check_capability`; only `Active`, `StaleOnNextUse`, and
`RenewalRequired` are valid stored values, enforced by the CHECK
clause.

> **⚠️ KNOWN GAP — runtime SQL drift.**
> `kernel/src/authority/delegation.rs` (HEAD) issues an
> `INSERT INTO delegations (..., scope_json, granted_by, granted_at,
> ..., use_count, max_uses, status)` — referencing **five columns
> that do not exist in the migration DDL**. The first
> `OperatorRequest::GrantDelegation` to reach a real kernel will fail
> with a SQLite "no such column" error. The spec
> (`kernel-store.md` §2.5.1 Table 7) and the migration agree; the
> runtime implementation needs to be rewritten to match. This is
> tracked in `specs/v2/V2_GAPS.md` ("Delegation runtime SQL drift");
> see the `record_capability_use` and `list_delegations` siblings
> for the same drift. Until that PR lands, the only path that works
> end-to-end is `mark_stale_on_epoch_advance` (which uses the
> spec-correct columns).

---

## Step 1: Operator grants a delegation

The CLI call (verified against `cli/src/commands/delegation.rs`):

```bash
raxis delegation grant \
  --session "sess-abc" \
  --capability "WriteCode" \
  --role "operator-prod" \
  --ttl 3600 \
  --scope-json '{"paths": ["src/**"]}' \
  --operator-key /path/to/operator.priv
```

| Flag | Required | Notes |
|------|----------|-------|
| `--session`     | yes | UUID of the target session row |
| `--capability`  | yes | Variant name from `CapabilityClass` (e.g. `WriteCode`) |
| `--role`        | yes | The operator role id that authorises this grant; signed into the canonical signing domain |
| `--ttl`         | yes | TTL in seconds. The kernel re-derives `expires_at = now() + ttl_secs`; the CLI does NOT send `expires_at` directly |
| `--scope-json`  | no  | Free-form JSON included in the signing input. Currently NOT persisted in the table — it survives only in the operator audit row |
| `--operator-key`| yes | Path to the operator Ed25519 private key (PEM or raw seed); used locally, never sent |

**Flags that do NOT exist (despite earlier drafts):**

- `--max-uses` — the wire `max_uses` field is plumbed through to the
  kernel handler but `cli/src/commands/delegation.rs` does not yet
  surface a flag (see the inline TODO at line 83).
- `--scope` (alias for `--scope-json`) — must be exactly `--scope-json`.
- `--session-id` — must be exactly `--session`.
- `--reject` / `--reason` — this is delegation grant, not escalation.

The CLI computes the canonical signing input
(`raxis_crypto::token::sha256_hex(delegation_grant_signing_domain(...))`)
and signs it locally. Only the resulting hex signature is sent on
the operator socket.

---

## Step 2: Kernel verification (`grant_delegation`)

`handlers/operator::handle_grant_delegation` then dispatches to
`authority::delegation::grant_delegation`, which performs:

1. **TTL bound check** — `ttl_secs ≤ policy.max_delegation_ttl`
   (INV-DELEG-02). Out-of-range → `DelegationTtlOutOfRange`.
2. **Ed25519 signature verification** — via
   `raxis_crypto::delegation::verify_delegation_grant` over the
   canonical domain. Failure → `DelegationSignatureInvalid` (INV-DELEG-04).
3. **Capability ceiling check** — performed by the operator-handler
   layer before dispatch (`role_ceilings[operator.role]` must include
   the requested `capability_class`, INV-DELEG-03). Failure →
   `FAIL_CAPABILITY_OUT_OF_CEILING`.
4. **Uniqueness** — UNIQUE(session_id, capability_class) constraint
   (INV-DELEG-01). Duplicate → `DelegationAlreadyActive { existing_delegation_id }`.
5. **Insert** — single statement under the
   `Store::lock_sync()` mutex (INV-STORE-01).

On success the operator handler returns
`OperatorResponse::DelegationGranted { delegation_id }`.

---

## Step 3: Delegation lifecycle FSM

```text
            ┌──────────── Active ──────────────┐
            │  TTL countdown running           │
            │  (revoked_at IS NULL)            │
            │  effective_from <= now <= expires_at
            └────────┬─────────────────┬───────┘
                     │                 │
       policy epoch  │                 │ TTL elapses
       advances      │                 │ (now() >= expires_at)
                     ▼                 ▼
            ┌─ StaleOnNextUse ─┐   ┌── Expired ──┐
            │ one grace use   │   │ runtime-     │
            │ left;           │   │ derived,     │
            │ planner gets    │   │ never stored │
            │ warn flag       │   └──────────────┘
            └───────┬─────────┘
       grace use   │
       consumed    │
                    ▼
            ┌── RenewalRequired ──┐
            │ permanent reject    │
            │ until re-grant      │
            └─────────────────────┘
```

There is also a soft-delete branch from any state to `Revoked`
(operator-initiated; sets `revoked_at` to the current time without
changing `status`, and the runtime treats any non-NULL `revoked_at`
as terminal).

`StaleOnNextUse` is **only** set by the policy-manager (one
SQL `UPDATE` covering every active row when an epoch advances —
see `mark_stale_on_epoch_advance` and INV-POLICY-01). The transition
`StaleOnNextUse → RenewalRequired` is set by `claim::evaluate` step 4
the first time the grace use is consumed, and is one-way until the
operator issues a new grant.

---

## Policy-epoch interaction

When `policy.toml` is rotated and the kernel detects a higher epoch:

1. Phase 1 (single transaction):
   - `UPDATE delegations SET status='StaleOnNextUse', epoch_stale_set_at=? WHERE status='Active' AND revoked_at IS NULL AND expires_at > ?`
   - Sessions are marked for prompt-cache invalidation.
   - `policy_epoch_history` row inserted.
   - `PolicyEpochAdvanced` audit event appended.
2. Phase 2 (in-memory): `ArcSwap<PolicyBundle>` and `ArcSwap<AllowlistCache>` swap atomically.
3. Phase 3 (best-effort): gateway notification.

The atomicity of Phase 1 is INV-POLICY-01 — see
`specs/v1/kernel-store.md` §"Policy epoch atomicity invariant".

---

## Step 4: Gate-time check (`check_capability`)

The check order is **pure read, no writes** — required so a single
intent admission cannot mutate delegation state until *every* gate has
been evaluated:

1. Row lookup by `(session_id, capability_class)`. No row →
   `DelegationStatus::NotGranted`.
2. `revoked_at IS NULL` (else `Revoked`).
3. `now() < expires_at` (else `Expired`).
4. `now() >= effective_from` (else `NotYetEffective`).
5. Return the stored `status` value (`Active`, `StaleOnNextUse`, or
   `RenewalRequired`).

Only `Active` and `StaleOnNextUse` clear the gate. `StaleOnNextUse`
clears it once and then `record_capability_use` flips the row to
`RenewalRequired`. Everything else is a hard rejection mapped to
the planner-visible `PlannerErrorCode::DelegationInsufficient`
(INV-08 lossy by design — the planner does not learn *which* failure
mode it hit).

---

## Edge cases

### 1. Agent tries to use a capability that was never delegated

`check_capability` returns `NotGranted`. The intent admitter rejects
with `DelegationInsufficient`. No grace, no retry. The operator must
issue a new grant.

### 2. Two operators try to grant the same `(session, capability_class)`

`UNIQUE(session_id, capability_class)` rejects the second insert at
SQLite level. The handler maps the constraint violation to
`DelegationAlreadyActive { existing_delegation_id: <id> }`. Operator
must `revoke` the existing row before re-granting.

### 3. Delegation expires between check and use

`check_capability` reads `expires_at` once and returns a snapshot.
Even if the row formally expires a millisecond later, the snapshot
already taken governs the in-flight admission. The next admission
will fail. (Real-world TTLs are minutes-to-hours, so this race is
nominal.)

### 4. Forged operator signature

The signing domain is `"RAXIS-V1-DELEGATION-GRANT" || 0x00 || …`
(see `specs/v1/kernel-store.md` §2.5.5). Verification uses the
operator's pubkey from the *current* policy bundle. A signature
that does not verify against any current operator pubkey returns
`DelegationSignatureInvalid` and the row is never inserted.

### 5. Operator was removed in a later policy epoch

`recovery::reconcile` runs at kernel start and re-verifies every
*Active* / *StaleOnNextUse* row against the **current** policy.
A row whose `delegating_role_id` is no longer in
`[[operators.entries]]` is forced to `Revoked` and an
`AuditEventKind::DelegationSignatureUnverifiable` event is emitted
(`expected_signer_unknown_in_current_policy: true`). The session
will see `NotGranted` on the next gate and must escalate for a
fresh grant.

---

## Key source files

| File | Role |
|---|---|
| `kernel/src/authority/delegation.rs` | `grant_delegation`, `check_capability`, `record_capability_use`, `list_delegations`, `mark_stale_on_epoch_advance`. ⚠️ See "KNOWN GAP" callout above. |
| `kernel/src/authority/keys.rs`       | `AuthorityError` taxonomy, key/pubkey resolution helpers |
| `kernel/src/ipc/operator.rs`         | `handle_grant_delegation` operator wire dispatcher |
| `kernel/src/gates/claim.rs`          | Step-4 enforcement: `record_capability_use` on `StaleOnNextUse` grace path |
| `kernel/src/policy_manager.rs`       | Phase-1 epoch advance; calls `mark_stale_on_epoch_advance` |
| `kernel/src/recovery.rs`             | Post-crash signature re-verification of stored rows |
| `crates/store/src/migration.rs`      | Migration 1 — Table 7 delegations DDL (the at-rest schema) |
| `crates/types/src/lib.rs`            | `DelegationStatus`, `CapabilityClass`, `SessionId` |
| `crates/crypto/src/delegation.rs`    | `verify_delegation_grant` Ed25519 verification |
| `cli/src/commands/delegation.rs`     | `raxis delegation grant` CLI surface |
| `cli/src/signing.rs`                 | `delegation_grant_signing_domain` byte layout |
| `specs/v1/kernel-store.md` §2.5.1 / §2.5.5 | Normative DDL + signing domain |
| `specs/v1/kernel-core.md` §2.3       | Authority subsystem function contracts |

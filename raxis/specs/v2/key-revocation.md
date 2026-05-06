# RAXIS V2 — Plan Signing Key Revocation

> **Status:** V2 Specified
> **Cross-references:**
> - `specs/v2/policy-plan-authority.md §3` — Policy is the security floor; plans cannot weaken it
> - `specs/v2/plan-bundle-sealing.md` — V2 admission ceremony: atomic in-memory bundle + sign + submit; the bundle hash (rather than the bare `plan.toml` hash) is what the operator key signs
> - `specs/v2/immutable-artifact-store.md §2` — Plans are content-addressed and immutable; signatures bind to the bundle hash
> - `specs/v2/policy-epoch-diffing.md §4` — Per-capability staleness diffing; this spec extends the diffing rules to key revocations
> - `specs/v2/kernel-push-protocol.md §9` — `KernelPush::SessionRevoked` envelope used here
> - `specs/invariants.md` — `INV-CRED-KERNEL-01` (closed set of kernel credential reads); `INV-VM-CAP-04` (no credential value in VM)
> - `kernel/src/handlers/intent.rs` — Existing approve_plan path; this spec extends it
>
> **V2 plan-hash field naming.** This spec was authored against the V1
> `plan_artifact_sha256` column (the SHA-256 of `plan.toml` bytes). V2 ships
> with **Plan Bundle Sealing**, which replaces that column with
> `plan_bundle_sha256` (the SHA-256 of the canonical bundle encoding per
> `plan-bundle-sealing.md §3.2`). Where this spec writes
> `plan_artifact_sha256`, V2 deployments use `plan_bundle_sha256`; the
> revocation logic, key-trust state machine, and audit attribution chain
> are otherwise unchanged. The legacy spelling is preserved in the V1
> column for forensic reproducibility of pre-V2 initiatives, and the kernel
> resolves both columns at lookup time depending on the initiative's
> generation.

---

## 1. The Problem

Plans (`plan.toml`) authorize agent sessions and declare what they may do — sub-task DAGs, allowed egress, credential bindings, escalation classes. Because plans are powerful, V2 requires every plan to be signed by an operator key declared in `policy.toml` under `[[plan_signing_keys]]`. The kernel verifies the signature before admitting the plan.

Two operational realities force this spec to exist:

1. **Keys get rotated.** Operators rotate plan-signing keys on a schedule (annual, post-personnel-change, post-laptop-loss). Plans signed by the previous key were perfectly legitimate at the time and the agents running under them must not be killed gratuitously.
2. **Keys get compromised.** Sometimes a key leaks. Once leaked, every plan ever signed by it must be treated as untrustworthy — including plans currently driving live agent sessions, because the attacker may have substituted plan content with the same signature.

These two cases require different kernel behavior:

- **Rotation** is forward-looking. New plans must use a new key; old in-flight sessions continue.
- **Compromise** is retroactive. Every in-flight session admitted under the compromised key is terminated immediately, the plans it signed are flagged for forensic review, and admission of any new plan signed by it is permanently rejected.

Without this distinction baked into the kernel, operators face a brutal trade-off: either every key rotation kills every running session (operationally untenable), or compromise events leave attackers in control of live VMs until session natural-completion (security failure). This spec separates the two with structural enforcement.

---

## 2. The Key Registry

### 2.1 Schema in `policy.toml`

```toml
[[plan_signing_keys]]
id                       = "ops-2025-q4"
algorithm                = "ed25519"
public_key_pem           = """-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAxxx...
-----END PUBLIC KEY-----"""
trust_window_starts_at   = "2025-10-01T00:00:00Z"

# OPTIONAL — populated only after revocation. Once populated, immutable.
revoked_at               = "2026-04-15T14:30:00Z"
revocation_reason        = "compromise"      # "compromise" | "rotation"
revocation_reference     = "INC-2026-04-15-laptop-theft"
```

`id` is operator-chosen; the kernel uses it as the lookup key from a plan's `signing_key_id` header. It MUST be unique within a policy bundle; collisions reject the policy push with `FAIL_DUPLICATE_KEY_ID`.

`trust_window_starts_at` is the earliest plan-creation timestamp the key may sign. Plans whose `created_at` predates this are rejected. This protects against backdated plans being signed by a future key.

### 2.2 Append-only invariant

**INV-KEY-01 — Append-only key registry.**

For policy epoch N+1 to be admissible, every `[[plan_signing_keys]]` entry present in epoch N must also be present in epoch N+1, identified by `id`, with `algorithm`, `public_key_pem`, and `trust_window_starts_at` byte-identical. The only fields that may change between epochs are the revocation fields, which transition from absent → populated exactly once and are immutable thereafter.

Operators can ADD new key entries between epochs. They CANNOT remove entries, mutate identity fields, or un-revoke.

**Why:** if the operator could delete a key entry, audit log replay against historical policies would see signed events whose signing key is "unknown" — indistinguishable from forgery. The append-only rule guarantees every signature ever produced by a key in the registry remains structurally verifiable (whether the verification *passes* depends on the rules in §5–§6).

**Enforcement.** `approve_policy` (in `kernel/src/handlers/policy.rs`, new in V2) computes the diff against current policy and rejects with `FAIL_KEY_REGISTRY_NOT_APPEND_ONLY` on any violation. The rejection is itself audit-emitted.

---

## 3. Revocation Reasons

### 3.1 `rotation`

The key is being retired in the normal course of operations. Plans signed by it before `revoked_at` remain valid; plans signed after `revoked_at` are rejected.

**Effect on in-flight sessions:** none. They continue running.
**Effect on new admissions:** plans must be signed by a non-revoked key whose trust window includes the plan's `created_at`.
**Effect on audit replay:** signature verification still succeeds for events whose plan was signed before `revoked_at`.

### 3.2 `compromise`

The key's private half has been or may have been exposed. We assume an attacker can produce signatures over arbitrary plan content.

**Effect on in-flight sessions:** every session whose `plan.signing_key_id` matches the compromised key is terminated. Reason: `KeyCompromised`. The session's VM receives SIGTERM, then SIGKILL after a 5-second grace period.
**Effect on new admissions:** plans signed by the compromised key are permanently rejected with `FAIL_KEY_COMPROMISED`. There is no time-window logic — even plans created before the leak are rejected, because we cannot know when the leak actually occurred.
**Effect on audit replay:** signatures still verify cryptographically, but a replay tool MUST surface a `RevokedKeyVerification { reason: compromise, key_id, replayed_event }` warning so a human can decide whether to trust the historical event.

The asymmetric treatment of rotation vs compromise is the entire reason this spec exists.

### 3.3 No third reason

V2 defines exactly two values for `revocation_reason`. A future version may add `superseded` (key replaced by a stronger algorithm), `expired` (TTL hit), etc., but V2 forbids them. `approve_policy` validates `revocation_reason ∈ {"rotation", "compromise"}` and rejects otherwise.

---

## 4. The `key_trust_state` Materialized View

After every successful policy push, the kernel computes a per-epoch trust-state map and persists it. This is what every other validation path reads.

### 4.1 Schema

```sql
-- Migration N: per-epoch key trust state
CREATE TABLE key_trust_state (
    policy_epoch           INTEGER NOT NULL,
    key_id                 TEXT    NOT NULL,
    fingerprint_sha256     TEXT    NOT NULL,           -- SHA-256 over canonical PEM bytes; canonical identifier
    state                  TEXT    NOT NULL,           -- 'Active' | 'Rotated' | 'Compromised'
    trust_window_starts_at INTEGER NOT NULL,           -- Unix timestamp
    revoked_at             INTEGER,                    -- NULL when state = 'Active'
    revocation_reference   TEXT,                       -- NULL when state = 'Active'
    PRIMARY KEY (policy_epoch, key_id)
);

CREATE INDEX idx_key_trust_state_by_key
    ON key_trust_state(key_id, policy_epoch);

CREATE INDEX idx_key_trust_state_by_fingerprint
    ON key_trust_state(fingerprint_sha256, policy_epoch);
```

One row per (epoch, key) pair. The view grows monotonically — when policy epoch N+1 is committed, all epoch-N rows are copied forward, with revocation fields populated for any key whose state changed. `fingerprint_sha256` is computed at policy ingestion and used by the emergency-revocation lookup (§6) to match by canonical key identity.

### 4.2 Population

Inside the same `BEGIN IMMEDIATE` transaction that commits a new policy epoch:

1. For each `[[plan_signing_keys]]` entry in the new policy:
   - Compute `state`:
     - `revoked_at IS NULL` → `Active`
     - `revoked_at IS NOT NULL AND revocation_reason = 'rotation'` → `Rotated`
     - `revoked_at IS NOT NULL AND revocation_reason = 'compromise'` → `Compromised`
   - INSERT into `key_trust_state` with the new `policy_epoch`.
2. Compare against epoch N's rows; identify any key that transitioned `Active` → `Rotated` or `Active` → `Compromised`.
3. Stash the transition list in a temp table for the reconciliation phase (see §5.2).
4. Commit.

This is part of the policy-push transaction, so INV-STORE-02 (atomic state changes) holds.

### 4.3 Why a materialized view, not "compute on demand"

Computing trust state on every admission requires re-parsing the entire policy TOML (already in memory, so cheap) and walking every key entry (also cheap). So why materialize?

Because the **historical** validation paths (§7 audit replay) must reconstruct trust state at arbitrary epochs in the past. Rather than walking back through every policy bundle in the immutable store, the materialized view gives O(1) lookup per (epoch, key_id). The disk cost is trivial: ≤ 100 keys × ≤ 1000 epochs × ~100 bytes = 10 MB even after years of operation.

---

## 5. Validation Sequences

This is the core of the spec. Four distinct kernel paths exercise key revocation logic; they must be consistent.

### 5.1 Admit-time validation (admitting a new plan)

Triggered by `IntentRequest::ApprovePlan { plan_artifact_sha256, ... }`.

Within a single `BEGIN IMMEDIATE` transaction:

1. Load plan content from immutable store via `plan_artifact_sha256`.
2. Parse plan header: extract `signing_key_id`, `signature`, `created_at`.
3. SELECT from `key_trust_state` WHERE `policy_epoch = current_policy_epoch AND key_id = signing_key_id`.
   - **Zero rows** → key is unknown to current policy. Reject with `FAIL_UNKNOWN_SIGNING_KEY`. Emit `SecurityViolation { kind: UnknownSigningKey, key_id, plan_sha }`.
4. Examine returned row:
   - `state = 'Compromised'` → reject with `FAIL_KEY_COMPROMISED`. Emit `SecurityViolation { kind: AdmissionUnderCompromisedKey, key_id, plan_sha }`. (The fact that an admission was even attempted under a compromised key is itself a security event, even if the request came from an otherwise-trusted operator workstation, because the attacker who has the key may also have access to the operator's workstation.)
   - `state = 'Rotated' AND created_at > revoked_at` → reject with `FAIL_PLAN_AFTER_ROTATION`. (Plan was created after the key was rotated; should have used a new key.) Emit standard `PlanRejected` audit event — this is operational, not adversarial.
   - `state = 'Rotated' AND created_at <= revoked_at` → continue. Plan was created during the key's valid window; rotation is forward-only.
   - `state = 'Active'` → continue.
5. `created_at >= trust_window_starts_at`? If not, reject with `FAIL_PLAN_BEFORE_TRUST_WINDOW`.
6. Verify `signature` over canonical bytes of plan content using `public_key_pem`. If verification fails, reject with `FAIL_BAD_SIGNATURE`. Emit `SecurityViolation { kind: BadPlanSignature, key_id, plan_sha }`.
7. Continue with the rest of the existing `approve_plan` admission pipeline (path-allowlist intersection check, declared-environment check, etc.).
8. On admission success, store `sessions.signing_key_id = signing_key_id` and `sessions.admission_policy_epoch = current_policy_epoch`. These two columns are the linchpins of the reconciliation paths (§5.2, §5.3).

### 5.2 Apply-time validation (policy push containing a revocation)

Triggered by an operator pushing `policy.toml` whose epoch advances from N to N+1 and contains at least one new revocation.

Within the same `BEGIN IMMEDIATE` transaction that commits the new policy:

1. Persist the new policy bundle to immutable store; bump `policy_current_epoch` to N+1.
2. Populate `key_trust_state` for epoch N+1 (per §4.2).
3. Identify the **transition set** — keys where state in epoch N+1 differs from epoch N:
   - `Active → Rotated` — call this `rotated_keys`.
   - `Active → Compromised` — call this `compromised_keys`.
4. For each key in `compromised_keys`:
   ```sql
   SELECT id, vsock_cid, current_pid
     FROM sessions
    WHERE state IN ('Active', 'Paused', 'AwaitingEscalation')
      AND signing_key_id = ?
   ```
   For each affected session:
   - UPDATE `sessions SET state = 'Failed', failure_reason = 'KeyCompromised'`.
   - INSERT `audit_events (kind = 'SessionTerminated', reason = 'KeyCompromised', session_id, signing_key_id, revocation_reference)`.
   - INSERT into `pending_pushes` a `KernelPush::SessionRevoked { reason: KeyCompromised, key_id, revocation_reference }` (per `kernel-push-protocol.md §10.3`). The push is mostly for audit completeness — for `KeyCompromised`, signal handling is **Immediate** per §7.1 and the planner will be killed by hypervisor stop before it can read the push. The enqueue is correct per INV-PUSH-01 atomicity regardless.
   - Stash the session row for post-commit teardown.
5. For each key in `rotated_keys`: do nothing. Rotation has no retroactive effect.
6. Commit.
7. Post-commit (outside transaction): for each stashed session, dispatch teardown per §7.3 step 3. For `KeyCompromised`, this is hypervisor stop with no SIGTERM grace (Immediate, INV-KEY-08). For other reasons (none in this path, but the helper is generic), the helper consults `reason.signal_handling()`.

The post-commit teardown is intentionally outside the transaction. We don't want signal delivery or hypervisor stops blocking the database write. The state transition already committed; the session is `Failed` regardless of teardown progress. Even if the kernel crashes between step 6 and step 7, restart reconciliation (§5.3) re-runs teardown on any session in `state = Failed` whose VM PID is still alive (using the same §7.3 dispatch on `failure_reason.signal_handling()`).

### 5.3 Restart-time reconciliation (kernel boot)

Triggered by `kernel/src/startup.rs` after policy and audit log are loaded.

This is the path the user specifically asked about — when the kernel boots and discovers it must apply a revocation that may have been pushed while it was down, OR that was pushed and the kernel crashed mid-apply.

Sequence:

1. Load current policy bundle; `current_policy_epoch = N`.
2. Verify `key_trust_state` is populated for epoch N. (If not, the policy push transaction was incomplete; abort startup with `FAIL_INCONSISTENT_POLICY_STATE` — operator must manually re-push.)
3. Read all in-flight sessions:
   ```sql
   SELECT id, signing_key_id, admission_policy_epoch, vsock_cid, plan_artifact_sha256, current_pid
     FROM sessions
    WHERE state IN ('Active', 'Paused', 'AwaitingEscalation')
   ```
4. For each session row, run the following decision tree against the **current** policy epoch:

   ```
   trust_now = SELECT state, revoked_at, revocation_reference
                 FROM key_trust_state
                WHERE policy_epoch = current_policy_epoch
                  AND key_id = session.signing_key_id;
   ```

   **Case 4a — `trust_now` is empty (zero rows).**
   This is impossible if INV-KEY-01 holds: a key that signed an admitted plan must exist in every subsequent policy epoch. Encountering it means either:
   - The append-only invariant was violated by a buggy `approve_policy` implementation.
   - The state database is corrupt.
   Either way, treat as `SecurityViolation { kind: KeyVanished, session_id, key_id }`, terminate the session with reason `KeyVanished`, halt acceptance of new policies until operator intervention. This is the most severe case and should never happen in a correct implementation.

   **Case 4b — `trust_now.state = 'Active'`.**
   Session continues. Re-bind VSock listener (per `kernel-push-protocol.md §6.2`). Done.

   **Case 4c — `trust_now.state = 'Rotated'`.**
   Compare `session.admission_policy_epoch` vs the epoch in which the key was rotated. Specifically, find the smallest `policy_epoch` where this key's state became `Rotated`:
   ```sql
   SELECT MIN(policy_epoch) AS rotation_epoch
     FROM key_trust_state
    WHERE key_id = session.signing_key_id
      AND state = 'Rotated';
   ```
   - `session.admission_policy_epoch < rotation_epoch` → session was admitted before the key was rotated. Continue (rotation is forward-only).
   - `session.admission_policy_epoch >= rotation_epoch` → impossible per the admit-time check (§5.1 step 4 would have rejected). Treat as `SecurityViolation { kind: SessionAdmittedAfterRotation }`, terminate with reason `SessionAdmittedAfterRotation`. Same severity as 4a.

   **Case 4d — `trust_now.state = 'Compromised'`.**
   Terminate regardless of admission epoch. This covers two sub-cases:
   - The compromise was pushed while the kernel was down; this is the expected reconciliation path.
   - The compromise was pushed before the crash; teardown was incomplete (case in §5.2 step 7); re-run teardown.
   Specifically:
   - If `session.state` is already `'Failed'` and `failure_reason = 'KeyCompromised'` (or `EmergencyKeyCompromised`), the database transition already happened; just re-run teardown per §7.3 step 3 (Immediate for both these reasons).
   - If `session.state` is `Active` / `Paused` / `AwaitingEscalation`, run the full §5.2 step 4 path: UPDATE → audit → enqueue push → teardown via §7.3 (Immediate for KeyCompromised).

5. Mark reconciliation complete: `INSERT INTO startup_runs (started_at, completed_at, sessions_reviewed, sessions_terminated_count)`.

**The crucial property:** §5.2 and §5.3 are equivalent. Whether a compromise revocation is processed live (operator pushes while kernel runs) or detected on restart (kernel was down when operator pushed), the same audit events, the same FSM transitions, and the same teardown actions occur. This is INV-KEY-05 (reconciliation idempotency).

### 5.4 Per-intent re-check?

**No.** Once §5.1 admits a session under an Active key, and §5.2/§5.3 leave it running because the key has not been compromised, individual intents do NOT re-verify the signature. The trust state is checked at admission and at every policy push and at every kernel restart. Per-intent re-verification would be wasted CPU.

The exception: any intent that re-references the plan content (e.g., a future `RefreshPlan` intent, not in V2) would re-verify. V2 has no such intent.

### 5.5 The lookup function `key_trust_now`

All four validation paths (§5.1, §5.2, §5.3, and §8 audit replay) call into a single helper that consults emergency revocations FIRST, then falls back to policy-derived state:

```
fn key_trust_now(key_id, fingerprint, current_epoch) -> KeyTrustState:
    // Emergency revocations always win because they are always more
    // restrictive than policy state (always reason=compromise, never rotation).
    if let Some(emergency) = SELECT * FROM emergency_key_revocations
                              WHERE fingerprint_sha256 = ?:
        return Compromised {
            since: emergency.revoked_at,
            source: EmergencyFile { authorized_by, revocation_reference }
        }

    // Fall back to policy-derived state.
    return SELECT state, ... FROM key_trust_state
            WHERE policy_epoch = current_epoch AND key_id = ?
```

The single lookup function ensures that emergency revocations and policy revocations cannot diverge across validation paths. See §6 for the emergency-revocation mechanism.

---

## 6. Emergency Out-of-Band Revocation

### 6.1 The chicken-and-egg problem

The normal revocation path (§5.2) requires the operator to push a `policy.toml` signed by an operator key. But the operator key in question may be the one that was compromised. If the operator has only one signing key and it was leaked, they have no signature the kernel will trust to push the revocation. Worse, if the attacker has the key, the attacker can push their own malicious policy that does not revoke it (or, more subtly, that revokes a different key as a distraction).

The kernel needs an authority path that does NOT depend on cryptographic signatures verifiable inside the kernel. The only authority RAXIS can rely on outside its key registry is the host operating system — specifically, root file ownership.

### 6.2 The break-glass file

The kernel reads a single file at startup and on `SIGHUP`:

`/var/lib/raxis/emergency_revocations.toml`

Authority comes from filesystem permissions:

- Owner: root, group: root.
- Mode: 0600 (only root can read or write).
- Located on a filesystem mounted at boot by the host (i.e., not user-mountable; not a removable USB).

The kernel itself runs as root (it must, to manage VMs, raw VSock listeners, and audit-log files). Anyone with root on the host has equivalent authority to the kernel itself — there is no separation to enforce. Filesystem permissions ARE the authority boundary; cryptographic signatures are not used and not accepted.

If the file does not exist, the kernel proceeds normally (no emergency revocations active). If the file exists but ownership/mode is wrong, the kernel refuses to start with `FAIL_EMERGENCY_FILE_PERMISSIONS_INVALID` and emits `SecurityViolation { kind: EmergencyFilePermissionsInvalid }`. This is fail-closed: a wrong-permissions file might be an attacker dropping their own revocation.

### 6.3 File schema

```toml
# /var/lib/raxis/emergency_revocations.toml
# Authority: root ownership and 0600 permissions.
# Recommended modification path: `raxis emergency-revoke <key_id>`
# (validates, atomically rewrites, fsyncs, signals SIGHUP to running kernel).

[[emergency_revocation]]
fingerprint_sha256    = "ab12cd34..."          # 64 hex chars; SHA-256 of public_key_pem; CANONICAL identifier
key_id_at_record_time = "ops-2025-q4"          # human-readable; kernel cross-checks against current policy
revoked_at            = "2026-04-15T14:30:00Z" # operator's claim of when compromise was detected
revocation_reference  = "INC-2026-04-15-laptop-theft"
authorized_by         = "alice@example.com"    # operator self-claim; forensic only, not authority
recorded_at           = "2026-04-15T14:35:22Z" # set by `raxis emergency-revoke` at file-write time

# Multiple entries permitted.
[[emergency_revocation]]
fingerprint_sha256    = "..."
# ...
```

`fingerprint_sha256` is the canonical identifier — it is an immutable property of the public key bytes. `key_id_at_record_time` is human-friendly but the kernel does not trust it as primary identity (the operator might mistype). The kernel matches emergency entries to known keys by fingerprint.

`authorized_by` is operator self-claim with no cryptographic verification. It is recorded for forensic purposes (audit log captures it verbatim) but does not grant authority. Filesystem permissions are the authority.

### 6.4 The `raxis emergency-revoke` CLI

```
$ raxis emergency-revoke --key-id ops-2025-q4 --reference INC-2026-04-15
```

The CLI:

1. Reads the current `policy.toml` (NOT verifying its signature — just parsing the key registry to look up keys).
2. Looks up `key_id` to find `public_key_pem`; computes `fingerprint_sha256`.
3. Prompts for confirmation, displaying:
   - Key ID, fingerprint, when it was issued, when last used.
   - List of currently-active sessions admitted under this key (count, initiative IDs, agent role).
   - Warning: "N sessions will be terminated immediately on SIGHUP. Worktrees will be retained for 30 days."
4. On confirmation: write to `<file>.tmp`, fsync, atomic rename to `emergency_revocations.toml`. The atomicity ensures the kernel never reads a half-written file.
5. Sends `SIGHUP` to the running `raxis-kernel` process (PID from `/var/run/raxis-kernel.pid`).
6. Tails the audit log for `EmergencyRevocationApplied` events confirming application.

The CLI is a convenience. The operator may also hand-edit the file as long as ownership and format are correct; the kernel validates on reload (§6.5). The CLI is not the authority boundary — root write access is.

### 6.5 Reload protocol

The kernel reads `emergency_revocations.toml`:

- At startup, after policy load, BEFORE in-flight session reconciliation (§5.3). This ordering matters: emergency revocations recorded while the kernel was down must be applied before reconciliation decides which sessions to keep alive.
- On `SIGHUP` at any time during operation.

On reload, the kernel:

1. `stat()` the file. If owner ≠ root, group ≠ root, or mode ≠ 0600, refuse the reload, keep previous in-memory state, emit `SecurityViolation { kind: EmergencyFilePermissionsInvalid }`. On startup, this also halts startup with `FAIL_EMERGENCY_FILE_PERMISSIONS_INVALID`.
2. Parse TOML. On parse error, refuse reload, keep previous state, emit `SecurityViolation { kind: EmergencyFileMalformed }`.
3. Validate each entry:
   - `fingerprint_sha256` is exactly 64 lowercase hex chars.
   - `revoked_at`, `recorded_at` are RFC 3339 timestamps; `recorded_at >= revoked_at`.
   - `revocation_reference` is non-empty.
   - `authorized_by` is non-empty.
4. For each entry, compute `entry_hash_sha256` (canonical TOML serialization → SHA-256). This is the durable identity of the entry; reload behavior is keyed on it.
5. Compare against existing rows in `emergency_key_revocations`:
   - Entry already applied (`entry_hash_sha256` matches a row): no-op; entry is already in effect.
   - Entry new (no matching row): proceed to apply (§6.6).
   - Existing row missing from file: leave the row in the database (revocations are append-only, INV-KEY-07); emit `EmergencyRevocationFileTampered { previous_count, new_count, missing_fingerprints }`. Operator should investigate (was the file restored from a backup? did someone hand-delete an entry?).

### 6.6 Application of a new emergency revocation

For each new entry, in a single `BEGIN IMMEDIATE` transaction:

1. INSERT into `emergency_key_revocations` with all entry fields and `applied_at = NOW()`.
2. Look up `fingerprint_sha256` against current `key_trust_state`:
   - **Match found** (a key with this fingerprint exists in current policy): proceed to step 3.
   - **No match** (orphan revocation — operator revoked a key not in current policy): record the revocation but no live sessions can be affected. Emit `EmergencyRevocationApplied { fingerprint, applied_to_sessions: 0, orphan: true }`. The revocation will activate immediately if any future policy push introduces a key with this fingerprint (the lookup function in §5.5 always consults emergency table first).
3. Find affected sessions:
   ```sql
   SELECT s.id, s.vsock_cid, s.current_pid, s.parent_session_id
     FROM sessions s
     JOIN key_trust_state k ON s.signing_key_id = k.key_id
    WHERE k.policy_epoch = current_policy_epoch
      AND k.fingerprint_sha256 = ?
      AND s.state IN ('Active', 'Paused', 'AwaitingEscalation')
   ```
4. For each affected session:
   - UPDATE `sessions SET state = 'Failed', failure_reason = 'EmergencyKeyCompromised'`.
   - INSERT `audit_events (kind = 'SessionTerminated', reason = 'EmergencyKeyCompromised', session_id, fingerprint, revocation_reference, authorized_by, ...)`.
   - Stash for post-commit teardown.
5. Emit `EmergencyRevocationApplied { fingerprint, key_id_at_record_time, applied_to_sessions: <count>, authorized_by, revocation_reference, entry_hash_sha256 }`.
6. Commit.
7. Post-commit (outside transaction): for each stashed session, **immediate hypervisor stop** (per §7.1 — NO SIGTERM grace). Cascade-terminate child sessions inheriting the Immediate signal class.

### 6.7 Schema additions

```sql
-- Migration N+1: emergency revocations
CREATE TABLE emergency_key_revocations (
    fingerprint_sha256        TEXT    NOT NULL PRIMARY KEY,
    key_id_at_record_time     TEXT,                           -- nullable; operator's claim, not authoritative
    revoked_at                INTEGER NOT NULL,               -- operator's claim
    revocation_reference      TEXT    NOT NULL,
    authorized_by             TEXT    NOT NULL,
    recorded_at               INTEGER NOT NULL,               -- set by raxis emergency-revoke
    applied_at                INTEGER NOT NULL,               -- set by kernel on application
    entry_hash_sha256         TEXT    NOT NULL UNIQUE         -- forensic linkage to file entry
);

-- INV-KEY-01 extension: emergency_key_revocations is also append-only.
-- No DELETE allowed except by manual operator intervention with full audit trail.
```

`fingerprint_sha256` is also added to `key_trust_state` (and to `[[plan_signing_keys]]` parsing in policy.toml) as a derived column computed at policy ingestion. This allows the JOIN in §6.6 step 3.

### 6.8 Auditability

Emergency revocations produce a distinct audit-event chain:

| Event | When |
|---|---|
| `EmergencyRevocationFileLoaded { entry_count, applied_count, new_count, orphan_count }` | Every successful reload |
| `EmergencyRevocationApplied { fingerprint, key_id_at_record_time, authorized_by, revocation_reference, entry_hash_sha256, applied_to_sessions }` | Per new entry |
| `SessionTerminated { reason: EmergencyKeyCompromised, fingerprint, authorized_by, revocation_reference, ... }` | Per terminated session |
| `EmergencyRevocationFileTampered { previous_count, new_count, missing_fingerprints }` | When file entries disappear between reloads |
| `SecurityViolation { kind: EmergencyFilePermissionsInvalid \| EmergencyFileMalformed }` | On reload validation failure |

Audit log replay (§8) treats `EmergencyKeyCompromised` events identically to `KeyCompromised` for retroactive-warning purposes (INV-KEY-06), but the `authorized_by` and `revocation_reference` fields make the operational chain visible: "this revocation was emergency-applied by alice@example.com on 2026-04-15 with reference INC-2026-04-15-laptop-theft."

### 6.9 What emergency revocation cannot do

- **Cannot un-revoke.** Once applied, an emergency revocation is permanent (INV-KEY-07). The operator who decides "actually, that key wasn't compromised" must rotate to a fresh key; the original key is dead forever.
- **Cannot revoke as Rotated.** All emergency revocations are reason=compromise. Rotation is non-urgent by definition; if you need to rotate, push a normal policy.
- **Cannot un-commit work.** A session terminated for `EmergencyKeyCompromised` may have produced commits that already merged into local master via `IntegrationMerge` — see §7.5 for race-outcome detail. Reverting those is operator incident-response, not kernel work.
- **Cannot defend against host root compromise.** If the attacker has root on the host, they can also write the emergency file or delete it before SIGHUP. The break-glass mechanism assumes the host root account is not compromised — only the plan-signing key was leaked. Host root compromise is outside RAXIS's defensible perimeter and warrants different incident response (image rebuild, key reissuance from a clean machine).

### 6.10 Recommended operational practice

After applying an emergency revocation, the operator SHOULD push a normal `policy.toml` that codifies the revocation through the standard path. This ensures:

- The next policy bundle in the immutable artifact store reflects the true trust state.
- Audit replay against the post-incident policy bundle correctly classifies the key without needing to consult the emergency table.
- Future operators reading the policy understand the key is dead even without inspecting `/var/lib/raxis/`.

The kernel does NOT enforce this — emergency revocations remain in effect indefinitely without a backing policy update. But operational hygiene strongly favors codification.

---

## 7. Termination Semantics

When a session is terminated, the kernel applies different signal-handling rules depending on the termination reason. The categorization is statically defined in code, not configurable in policy.toml — security termination must never be downgraded to graceful by configuration error.

### 7.1 Signal-handling categories

Every `TerminationReason` is statically classified into one of two categories:

| Category | Mechanism | Reasons |
|---|---|---|
| **Immediate** | Hypervisor primitive stop (Firecracker `InstanceStop`, AVF `VZVirtualMachine.stop`) — halts in-VM execution at instruction boundary. SIGKILL of VM process is fallback if hypervisor primitive fails. **No SIGTERM. No grace period. No in-VM handler runs.** | `KeyCompromised`, `EmergencyKeyCompromised`, `CidDriftDetected`, `BadPlanSignature`, `AdmissionUnderCompromisedKey`, `KeyVanished`, `SessionAdmittedAfterRotation`, `SecurityViolation(*)` (all variants) |
| **Graceful** | SIGTERM to VM process. Wait up to 5 seconds. If still alive, hypervisor stop (or SIGKILL of VM process). | `CompletedSuccessfully`, `OperatorAborted`, `PushQueueOverflow`, `PushAckTimeout`, `KeyRotated` (rare; only fires if a session somehow runs past rotation_epoch — should never happen given §5.1 enforcement), `ParentSessionRevoked` (where parent's reason was Graceful) |

**Cascade inheritance.** When a parent session is terminated and its children are cascade-terminated (`ParentSessionRevoked`), the children inherit the parent's signal-handling category. Parent killed Immediate → children killed Immediate. Parent killed Graceful → children killed Graceful.

The classification lives in `crates/types/src/termination.rs::TerminationReason::signal_handling()` as a `match` on the enum. Tests assert exhaustive coverage; a new `TerminationReason` variant added without a `signal_handling()` match arm fails compilation.

### 7.2 Why Immediate for security-driven termination

A session terminated for `KeyCompromised` (or any security-driven reason) is, by definition, suspected of being under attacker control — the entire point of the revocation is that we no longer trust whatever signed the plan. SIGTERM gives the attacker a final window to:

- `rm -rf /workspace` — destroying the forensic evidence the operator explicitly wants to preserve (per §7.4 retention policy).
- Final burst of network exfiltration via any open egress connection or credential proxy.
- Tampering with audit-log fragments cached in-VM (the canonical audit log lives on the host, but in-VM caches could mislead post-hoc analysis).
- Any other catch-and-cleanup logic the attacker installed in a SIGTERM handler.

Hypervisor-level stop (the equivalent of pulling the power plug) halts in-VM execution at the next instruction boundary, before any handler can run. Operating-system signal handlers cannot trap or delay it. This is the only correct response to suspected-compromise termination.

The 5-second SIGTERM grace is reserved for operational reasons where the VM is not suspected of being malicious — natural completion, queue overflow on a slow but well-intentioned consumer, etc.

### 7.3 Termination flow

For both Immediate and Graceful termination, in order:

1. Within the triggering transaction (whether §5.2 policy push, §5.3 restart reconciliation, or §6.6 emergency apply):
   - UPDATE `sessions.state = 'Failed'`, `sessions.failure_reason = <reason>`, `sessions.terminated_at = NOW()`.
   - INSERT `audit_events (kind = 'SessionTerminated', reason, session_id, ...)` with the full attribution chain (signing_key_id, fingerprint, revocation_reference, authorized_by where applicable, initiative_id, plan_artifact_sha256, policy_epoch).
   - Enqueue `KernelPush::SessionRevoked { reason, ... }` (per `kernel-push-protocol.md §10.3` atomicity rules; the push enqueue commits with the state change). For Immediate cases, the planner will be killed before reading the push; the enqueue is for audit completeness and for the rare reconnect-during-teardown case.
2. Commit the SQLite transaction.
3. Post-commit, apply signal handling per §7.1:
   - **Immediate**: invoke the hypervisor stop primitive (Firecracker `PUT /actions { action_type: "InstanceStop" }` or AVF `VZVirtualMachine.stop(completionHandler:)` with abrupt termination). If the primitive fails or returns an error, fall back to `kill -9 <vm_process_pid>` on the host.
   - **Graceful**: send `SIGTERM` to `<vm_process_pid>`. Wait up to 5 seconds. If still alive, hypervisor stop or SIGKILL.
4. After VM is confirmed stopped, INSERT `audit_events (kind = 'VmTerminated', session_id, signal_class, exit_latency_ms)`.
5. Cascade-terminate child sessions if any. Recursively: query `sessions WHERE parent_session_id = ?`; for each, repeat steps 1–5 with `reason = 'ParentSessionRevoked'` AND inheriting the parent's signal-handling category.

### 7.4 Worktree retention

For ALL termination reasons (Immediate and Graceful), the session's worktree is NOT garbage-collected immediately. It is retained for forensic review (configurable retention, default 30 days, settable per session role in `policy.toml`).

For Immediate terminations, the worktree's content is what an attacker may have caused the agent to write, and operators will want to inspect it. For Graceful terminations, the content is operationally interesting (debugging) but not security-critical.

Because Immediate termination halts the VM at an instruction boundary, in-flight writes to the worktree (via VirtioFS) may be partial. Forensic tools should diff against the last known commit to identify in-progress edits and treat partial files appropriately.

### 7.5 In-flight `IntegrationMerge` race outcomes

If an `IntegrationMerge` from the terminated session was in-flight at the moment the revocation was applied, the outcome depends on which transaction acquired the SQLite write lock first. SQLite `BEGIN IMMEDIATE` serializes write transactions; there is no actual race within the database, only a question of lock-acquisition ordering. The kernel does NOT auto-revert any merge that committed before revocation; reverting committed work is operator incident-response.

**Case A — `IntegrationMerge` transaction committed before the revocation transaction acquired the lock.**

- Local `master_repo` is already fast-forwarded to the merge commit.
- `initiatives.current_sha` is already updated.
- The git commit is permanent in local master.
- Audit log entry for the merge has `policy_epoch = <pre-revocation epoch>`. Audit replay (§8) will flag the merge with `RetroactivelyCompromisedKey` per INV-KEY-06; operators reading replay output will see "this merge was admitted under a key that has since been compromised."
- **The kernel does NOT auto-revert the merge.** Reverting commits requires choosing a strategy (revert commit on the same branch? force-push a clean history? operator-coordinated PR revert?) that depends on remote conventions and is outside RAXIS's authority. The kernel's responsibility ends at preventing future merges from this session.

Sub-cases of A based on remote-push state:

- **A1 — Push to remote not yet executed (`PushApprovalRequired` escalation pending).** The pending escalation is auto-canceled when the requesting Orchestrator session is killed (its `EscalationRequest` was scoped to the now-Failed session; cancellation is part of cascade cleanup). The local master commit remains; remote is untouched. Operator may choose to delete the local commit or investigate first.
- **A2 — Push to remote already executed.** The remote has the commit. The kernel cannot unpush. Operator coordinates with the remote (revert PR, force-push from a clean branch, etc.). Fully outside RAXIS authority.

**Case B — Revocation transaction committed before `IntegrationMerge` could acquire the lock.**

- `IntegrationMerge`'s `BEGIN IMMEDIATE` blocks waiting for the revocation transaction to release.
- When `IntegrationMerge` finally acquires the lock, the handler reads `sessions.state = 'Failed'` (set by the revocation) and aborts with `FAIL_SESSION_REVOKED`. No git operation occurs.
- The commit objects from the Orchestrator's clone are untouched in their worktree (preserved for forensics) but never reach local master.

**Case C — `IntegrationMerge` handler is between Phase 2 (git work) and Phase 3 (SQLite "applied" UPDATE) at the moment of revocation.**

This is the SQLite ↔ git boundary specified in `integration-merge.md §11`. The handler runs three phases: SQLite Phase 1 (commit `current_sha`, set `git_apply_pending = 1`, audit event), Phase 2 (`git fetch` + `git update-ref`, idempotent), Phase 3 (clear `git_apply_pending = 0`).

When a revocation racing an `IntegrationMerge` lands during the Phase 2/3 window:

- The revocation transaction commits independently of the merge's git work — SQLite serializes the two transactions, but the git work happens between them and is not under SQLite's lock.
- After both commits, SQLite has `current_sha = commit_sha` AND the session is `Failed` for `KeyCompromised`. The git side may or may not have been updated depending on which physical instant the crash occurred.
- Startup reconciliation runs both `key-revocation.md §5.3` (to enforce the revocation termination) AND `integration-merge.md §11.3` (to repair git/SQLite consistency). The order is: revocation reconciliation first (per §6.5 emergency reload before reconciliation; same ordering applies to policy-driven revocations), then merge consistency repair.
- If the Orchestrator's worktree is still on disk (per `INV-MERGE-WORKTREE-RETAIN` from `integration-merge.md §11.4`), Phase 2 is replayed idempotently from that worktree. The merge's commit lands in master under the audit-flagged provenance (replay later flags it `RetroactivelyCompromisedKey` per INV-KEY-06).
- If the worktree was lost (extremely unusual — INV-MERGE-WORKTREE-RETAIN forbids GC during pending), the initiative transitions to `Blocked` with `SecurityViolation { kind: GitStateInconsistent }` per `integration-merge.md §11.3` Case A else-branch. Operator intervention is required.

The key-revocation spec does not need to define recovery for this case beyond invoking the standard merge recovery; `integration-merge.md §11` is the source of truth.

---

## 8. Audit Log Replay (Historical Policy Validation)

This is a separate, read-only path used by auditors and operators reconstructing what happened.

The replay tool (in CLI: `raxis audit replay --until <ts>` or similar, V2-defined separately) does not modify state. It walks `audit_events` in order and, for each event, validates against the policy that was current AT THE EVENT'S TIMESTAMP.

For events that involve a plan signature (e.g., `SessionCreated`, `IntegrationMergeCommitted`):

1. From the event, extract `policy_epoch` and `plan_artifact_sha256`.
2. Load the policy bundle from the immutable store at that epoch.
3. Load the plan from the immutable store at that SHA.
4. Look up `key_trust_state WHERE policy_epoch = event.policy_epoch AND key_id = plan.signing_key_id`.
5. Verify the signature using the historical key.
6. Branch on the historical trust state:
   - `Active` → signature valid; event accepted as authentic.
   - `Rotated` (in epoch N where event happened) → also valid (the key was already rotated by the time of this event; admission shouldn't have happened — the audit reveals an inconsistency in the kernel's enforcement).
   - `Compromised` (in epoch N where event happened) → emit `RevokedKeyAtEventTime` warning; the event is forensically suspect.
7. ADDITIONALLY, look up `key_trust_state` at the **current** epoch:
   - If the key is currently `Compromised` but was `Active` at event time → emit `RetroactivelyCompromisedKey` warning. The event was authentic when emitted, but the operator has since determined the key was compromised. Each such event needs human review.

**INV-KEY-06 — Replay uses historical trust state for authenticity, current trust state for warnings.**

The auditor sees both: "this event was correctly accepted when it happened" AND "the key has since been compromised, so the event may need re-investigation." Conflating these two is the most common mistake in revocation tooling and we explicitly separate them.

---

## 9. Cross-cutting: Kernel-Initiated Master-Repo Pushes

Per `INV-CRED-KERNEL-01`, the kernel directly reads exactly one credential class: the master-repo push credential, used to fast-forward the master branch on remote after `IntegrationMerge` commits.

This credential is itself declared in `policy.toml` and is NOT a `plan_signing_key`. But it has a parallel revocation story:

- It MAY be revoked the same way (rotation vs compromise).
- On compromise revocation, kernel-pending pushes (master-branch updates not yet sent to remote) are aborted; their corresponding audit events are flagged.
- Reconciliation logic for master-repo push credentials is parallel to §5 and lives in `specs/v2/credential-proxy.md` Appendix B (out of scope here, just calling out that the patterns match).

---

## 10. Invariants

### INV-KEY-01 — Append-only key registry

Every `[[plan_signing_keys]]` entry, once committed in any policy epoch, must persist with byte-identical identity fields (`id`, `algorithm`, `public_key_pem`, `trust_window_starts_at`) in all subsequent policy epochs. The revocation fields may transition from absent → populated exactly once and are immutable thereafter.

**Where:** `kernel/src/handlers/policy.rs` (new) — `approve_policy` rejects with `FAIL_KEY_REGISTRY_NOT_APPEND_ONLY` on violation.

**Scenario it prevents:** Operator pushes a new policy with a key removed (perhaps thinking "we don't use that key anymore"). Sessions admitted under the removed key would later look "unsigned" to audit replay, indistinguishable from forgery. With INV-KEY-01, the policy push is rejected.

### INV-KEY-02 — Sticky historical trust

A signature produced during a key's trust window remains structurally verifiable for forensic purposes regardless of subsequent revocation. (Whether verification is treated as authoritative depends on `revocation_reason`.)

**Where:** `key_trust_state` is materialized per-epoch and never deleted. Historical policy bundles in the immutable store contain the historical key material.

**Scenario it prevents:** A key is compromised and revoked. The kernel can no longer verify any historical signature, including the audit log's chain over `SessionCreated` events from a year ago. Auditors are blind to the past. INV-KEY-02 keeps the historical material available; INV-KEY-06 governs how to interpret it.

### INV-KEY-03 — Compromise terminates retroactively

When a key transitions to `Compromised` in policy epoch N+1, every session whose `signing_key_id` matches and whose `state ∈ {Active, Paused, AwaitingEscalation}` is terminated within the same `BEGIN IMMEDIATE` transaction (state change) and within 5 seconds of commit (VM teardown).

**Where:** §5.2 (apply-time) and §5.3 case 4d (restart-time reconciliation).

**Scenario it prevents:** Attacker steals key K. Operator detects the leak, pushes revocation. Without INV-KEY-03, sessions admitted under K might continue running for hours/days under attacker influence (the attacker can't admit *new* sessions but the existing ones already have execution capability). With INV-KEY-03, the blast radius collapses to "what the agent did before the operator pushed the revocation."

### INV-KEY-04 — Rotation is forward-only

A `Rotated` revocation does not affect any session whose `admission_policy_epoch < rotation_epoch`. Such sessions continue running normally.

**Where:** §5.2 step 5; §5.3 case 4c.

**Scenario it prevents:** Operator rotates a key annually. Without INV-KEY-04, every annual rotation kills every running long-running session, causing operational pain that disincentivizes regular rotation (a security regression). With INV-KEY-04, rotation is operationally cheap and operators rotate freely.

### INV-KEY-05 — Reconciliation idempotency

Apply-time (§5.2) and restart-time (§5.3) reconciliation produce identical observable outcomes for any given (current policy, in-flight sessions) state. Whether a revocation was processed live or detected on restart, the audit log, FSM transitions, and teardown actions are equivalent.

**Where:** §5.2 and §5.3 share helper functions. Tested via crash-injection: kill the kernel between step 6 and step 7 of §5.2; restart; verify §5.3 produces identical final state.

**Scenario it prevents:** Operator pushes revocation; kernel crashes mid-teardown. On restart, the kernel's reconciliation logic differs from the live-apply logic, leaving some sessions in an inconsistent half-terminated state. With INV-KEY-05, the restart path is idempotent with the live-apply path; the final state is the same.

### INV-KEY-06 — Replay uses historical trust state for authenticity, current trust state for warnings

Audit log replay validates signatures using the trust state of the policy bundle in effect at the event's timestamp (authenticity check). Replay also surfaces warnings when a historically-Active key is currently revoked, especially when currently `Compromised`.

**Where:** §8. CLI replay tool implements both checks and renders distinct warning categories.

**Scenario it prevents:** An auditor uses current policy to verify all historical events; events signed by a now-revoked key fail signature verification and the audit log appears compromised. Or worse: the auditor uses historical trust state and never learns that the key was later compromised, accepting all events as authoritative. INV-KEY-06 surfaces both perspectives.

### INV-KEY-07 — Emergency revocations are append-only and authoritative by filesystem permission

Emergency revocations (§6) are append-only at the database level (`emergency_key_revocations` table) and authoritative at the file level by root ownership and 0600 mode. Once an emergency revocation entry is processed (a row exists in `emergency_key_revocations`), it is permanent — deleting the corresponding entry from `/var/lib/raxis/emergency_revocations.toml` does not un-revoke. No cryptographic signature is required or accepted on emergency revocations; authority comes solely from filesystem permissions.

**Where:** §6.5 (reload protocol; tampering detection without un-application); §6.6 step 1 (INSERT into `emergency_key_revocations`); §6.7 (schema with no DELETE); §6.9 ("cannot un-revoke").

**Scenario it prevents:** (a) An attacker who briefly gains write access to `emergency_revocations.toml` modifies an existing entry to weaken or remove a revocation; even after the operator restores the file, the original revocation remains in effect. (b) An operator regrets their emergency revocation and tries to undo it by editing the file; the kernel keeps the revocation applied and emits `EmergencyRevocationFileTampered`. (c) An attacker pushes a `policy.toml` (with their own valid-looking signature, perhaps after stealing a SECOND key) that doesn't include an emergency-applied revocation; the kernel still treats the key as Compromised because the lookup function consults emergency table first.

### INV-KEY-08 — Security-driven termination is Immediate (hypervisor stop, no SIGTERM grace)

When a session is terminated for a security-driven reason (`KeyCompromised`, `EmergencyKeyCompromised`, `CidDriftDetected`, `BadPlanSignature`, `AdmissionUnderCompromisedKey`, `KeyVanished`, `SessionAdmittedAfterRotation`, `SecurityViolation(*)`), the kernel uses hypervisor-level stop with no SIGTERM grace period. Cascade-terminated children of an Immediate-class parent inherit the Immediate signal class.

The classification of `TerminationReason` variants into Immediate vs Graceful is statically defined in code (`crates/types/src/termination.rs`), not configurable in policy.toml.

**Where:** §7.1 (signal-handling categories table); §7.2 (rationale); §7.3 step 3 (termination flow).

**Scenario it prevents:** A session terminated for `KeyCompromised` runs a SIGTERM handler that (a) `rm -rf /workspace` destroying forensic evidence, (b) executes a final burst of network exfiltration, or (c) tampers with cached state. With INV-KEY-08, the VM is stopped at the next instruction boundary; no in-VM handler runs. The 5-second SIGTERM grace is reserved for operationally-driven terminations where the VM is not suspected of being malicious.

---

## 11. Implementation Checklist

### Schema (migration N)

- [ ] Create `key_trust_state` table per §4.1, including `fingerprint_sha256 TEXT NOT NULL` column
- [ ] Create index `idx_key_trust_state_by_key`
- [ ] Create `emergency_key_revocations` table per §6.7
- [ ] Add `signing_key_id TEXT NOT NULL` column to `sessions`
- [ ] Add `admission_policy_epoch INTEGER NOT NULL` column to `sessions`
- [ ] Add `failure_reason TEXT` and `terminated_at INTEGER` to `sessions` (shared with `kernel-push-protocol.md`; declare once)
- [ ] Add `parent_session_id TEXT REFERENCES sessions(id)` for cascade termination

### `policy.toml` parser

- [ ] Add `[[plan_signing_keys]]` table parser in `crates/types/src/policy.rs`
- [ ] Validate `algorithm ∈ {"ed25519"}` (extensible; V2 ships ed25519 only)
- [ ] Validate `revocation_reason ∈ {"rotation", "compromise"}` if present
- [ ] Validate `id` uniqueness within bundle
- [ ] Compute `fingerprint_sha256` for each key during ingestion (SHA-256 over canonical PEM bytes)

### `crates/types/src/termination.rs` (new)

- [ ] Define `TerminationReason` enum exhaustively (KeyCompromised, EmergencyKeyCompromised, KeyRotated, KeyVanished, AdmissionUnderCompromisedKey, BadPlanSignature, CidDriftDetected, SessionAdmittedAfterRotation, SecurityViolation(SecurityViolationKind), CompletedSuccessfully, OperatorAborted, PushQueueOverflow, PushAckTimeout, ParentSessionRevoked { parent_reason: Box<TerminationReason> })
- [ ] Implement `signal_handling()` returning `SignalHandling::{Immediate, Graceful}` per §7.1 table
- [ ] Test: `signal_handling()` exhaustive match guarantees compile error if a new variant lacks classification
- [ ] Test: every Immediate-class reason is genuinely security-driven (review checklist; not strictly machine-checkable)

### `kernel/src/handlers/policy.rs` (new)

- [ ] Implement `approve_policy` handler
- [ ] Append-only diff check (INV-KEY-01)
- [ ] Populate `key_trust_state` for new epoch including `fingerprint_sha256`
- [ ] Identify transition set; classify rotated vs compromised
- [ ] For each compromised key, run §5.2 step 4 (terminate matching sessions; signal_handling = Immediate per INV-KEY-08)
- [ ] Post-commit teardown spawn (hypervisor stop for Immediate; SIGTERM grace for Graceful)
- [ ] Audit events: `PolicyPushed`, `KeyRotated`, `KeyCompromised`, `SessionTerminated { reason }`, `VmTerminated { signal_class, exit_latency_ms }`

### `kernel/src/handlers/emergency_revocation.rs` (new)

- [ ] Implement file reload triggered by SIGHUP and at startup-before-reconciliation
- [ ] Validate file ownership (root) and mode (0600); refuse on mismatch with `FAIL_EMERGENCY_FILE_PERMISSIONS_INVALID`
- [ ] Parse TOML; validate per §6.5 step 3
- [ ] Compute `entry_hash_sha256` per entry (canonical TOML serialization)
- [ ] Diff against `emergency_key_revocations`; classify as already-applied, new, or missing
- [ ] For each new entry, run §6.6 application transaction
- [ ] For missing entries, emit `EmergencyRevocationFileTampered`
- [ ] Audit events: `EmergencyRevocationFileLoaded`, `EmergencyRevocationApplied`, `EmergencyRevocationFileTampered`, `SecurityViolation { EmergencyFilePermissionsInvalid | EmergencyFileMalformed }`

### `kernel/src/lookup/key_trust.rs` (new)

- [ ] Implement `key_trust_now(key_id, fingerprint, current_epoch) -> KeyTrustState` per §5.5; consults emergency table FIRST
- [ ] Used by §5.1 (admit), §5.2 (apply), §5.3 (reconcile), §8 (audit replay)
- [ ] Test: emergency revocation always wins over policy state for the same fingerprint

### `kernel/src/handlers/intent.rs` (modified — `approve_plan`)

- [ ] Use `key_trust_now()` instead of direct `key_trust_state` query
- [ ] Implement six-case admit-time decision tree (§5.1) including emergency-Compromised branch
- [ ] Audit events: `SecurityViolation { UnknownSigningKey | AdmissionUnderCompromisedKey | BadPlanSignature }`, `PlanRejected { reason: PlanAfterRotation | PlanBeforeTrustWindow }`
- [ ] Persist `signing_key_id` and `admission_policy_epoch` on successful admission

### `kernel/src/startup.rs` (modified)

- [ ] Load policy, then read `emergency_revocations.toml` (§6.5), then run §5.3 reconciliation (in that order — emergency revocations may affect reconciliation outcomes)
- [ ] Implement four-case restart-time decision tree using `key_trust_now()`
- [ ] Cascade-terminate child sessions of any terminated parent (inheriting parent's signal class)
- [ ] Re-run incomplete teardowns (re-run signal handling for sessions already in `state = Failed` whose VM PID is still alive)
- [ ] Audit event: `StartupReconciliationCompleted { sessions_reviewed, sessions_terminated_count, emergency_revocations_loaded }`

### `kernel/src/teardown.rs` (new)

- [ ] Implement `teardown_session(session_id, reason)` that dispatches on `reason.signal_handling()`
- [ ] Immediate path: invoke hypervisor stop primitive; fall back to `kill -9 <vm_pid>`
- [ ] Graceful path: SIGTERM, wait 5s, then hypervisor stop or SIGKILL
- [ ] Both paths emit `VmTerminated` with `signal_class` and `exit_latency_ms`
- [ ] Recursive cascade with parent's signal class

### CLI

- [ ] `raxis policy push <bundle.toml>` — invokes `approve_policy`; surfaces revocation effects in pre-commit summary ("This push will terminate 3 active sessions due to key compromise. Continue? [y/N]")
- [ ] `raxis emergency-revoke --key-id <id> --reference <ref>` — implements §6.4 flow; computes fingerprint, lists affected sessions, atomically rewrites the file, sends SIGHUP, tails audit log for confirmation
- [ ] `raxis emergency-revoke --fingerprint <sha256> --reference <ref>` — variant for revoking by fingerprint (e.g., orphan revocation)
- [ ] `raxis audit replay [--until <ts>]` — implements §8 historical validation; renders `RevokedKeyAtEventTime` and `RetroactivelyCompromisedKey` warning categories distinctly; surfaces `EmergencyKeyCompromised` provenance with `authorized_by` field

### Audit events

- [ ] `KeyRotated { key_id, revoked_at, revocation_reference, policy_epoch }`
- [ ] `KeyCompromised { key_id, revoked_at, revocation_reference, policy_epoch, sessions_terminated_count }`
- [ ] `EmergencyRevocationFileLoaded { entry_count, applied_count, new_count, orphan_count }`
- [ ] `EmergencyRevocationApplied { fingerprint_sha256, key_id_at_record_time, authorized_by, revocation_reference, entry_hash_sha256, applied_to_sessions }`
- [ ] `EmergencyRevocationFileTampered { previous_count, new_count, missing_fingerprints }`
- [ ] `SessionTerminated` extended with `reason ∈ {KeyCompromised, EmergencyKeyCompromised, ParentSessionRevoked, KeyVanished, SessionAdmittedAfterRotation, ...}` and `signal_class ∈ {Immediate, Graceful}`
- [ ] `VmTerminated { session_id, signal_class, exit_latency_ms, exit_signal }`
- [ ] `SecurityViolation` sub-kinds: `UnknownSigningKey`, `AdmissionUnderCompromisedKey`, `BadPlanSignature`, `KeyVanished`, `SessionAdmittedAfterRotation`, `EmergencyFilePermissionsInvalid`, `EmergencyFileMalformed`
- [ ] `StartupReconciliationCompleted { sessions_reviewed, sessions_terminated_count, emergency_revocations_loaded, transition_set_summary }`

---

## 12. Tests

### Unit / property

- [ ] `approve_policy` rejects removal of any existing key entry → `FAIL_KEY_REGISTRY_NOT_APPEND_ONLY`
- [ ] `approve_policy` rejects mutation of `public_key_pem` for existing key → same
- [ ] `approve_policy` rejects un-revoke (revoked → active) → same
- [ ] `approve_policy` rejects `revocation_reason` outside the allowed set
- [ ] `approve_plan` rejects `created_at < trust_window_starts_at` → `FAIL_PLAN_BEFORE_TRUST_WINDOW`
- [ ] `approve_plan` rejects `created_at > revoked_at` for Rotated key → `FAIL_PLAN_AFTER_ROTATION`
- [ ] `approve_plan` rejects any plan signed by Compromised key → `FAIL_KEY_COMPROMISED`

### Integration: live revocation

- [ ] Admit 3 sessions under key K (state = Active). Push policy with K → Compromised. Verify all 3 sessions transition to `state = Failed, failure_reason = KeyCompromised` within the policy-push transaction. Verify SIGTERM sent to each VM PID. Verify `KernelPush::SessionRevoked` enqueued for each.
- [ ] Same scenario but K → Rotated. Verify all 3 sessions remain `state = Active`. Verify subsequent `approve_plan` for a NEW plan signed by K with `created_at > revoked_at` is rejected.
- [ ] Cascade: Orchestrator session O delegates to Executor sessions E1, E2. Compromise the key both were admitted under (same key for both). Verify O, E1, E2 all terminate. Verify cascade events emitted.

### Integration: restart reconciliation (the user's scenario)

- [ ] **Crash-mid-apply**: Push policy with K → Compromised. After the policy push transaction commits but BEFORE post-commit teardown runs, SIGKILL the kernel. Restart. Verify §5.3 case 4d sub-path runs SIGTERM on the still-alive VM PID; verify final audit log is byte-identical to the no-crash baseline (idempotency, INV-KEY-05).
- [ ] **Kernel-down-during-push**: Stop the kernel. Manually push a new policy bundle to the immutable store with K → Compromised and bump `policy_current_epoch`. Restart kernel. Verify §5.3 detects the unprocessed transition, terminates affected sessions, populates `key_trust_state`, and emits the same audit events as the live-apply path.
- [ ] **Cascade rotation**: Push K → Rotated. Restart kernel. Verify all sessions admitted under K continue running (case 4c, admission_epoch < rotation_epoch). Verify no SecurityViolation emitted.
- [ ] **The Case 4a horror path**: Manually corrupt the database to remove a `key_trust_state` row for an in-flight session's signing key. Restart kernel. Verify case 4a triggers: `SecurityViolation { kind: KeyVanished }`, session terminated, kernel halts acceptance of new policies.
- [ ] **Race between admit and revoke**: Operator pushes plan-admission intent for key K at T0; another operator pushes policy with K → Compromised at T0+ε. Verify SQLite serializes the two transactions; the later-committed one observes the earlier's state. If admission commits first, the new session is then terminated by the policy push's reconciliation. If policy push commits first, admission rejects with `FAIL_KEY_COMPROMISED`. Either ordering is acceptable; both are covered.

### Integration: audit replay (INV-KEY-06)

- [ ] Run scripted scenario: epoch 1 admits S1 under K (Active); epoch 2 admits S2 under K (Active); epoch 3 marks K Compromised; S3 attempted in epoch 3 is rejected.
- [ ] Run `raxis audit replay`. Verify:
  - `SessionCreated(S1)` and `SessionCreated(S2)` events: signature verifies (key was Active at event time); BOTH are flagged with `RetroactivelyCompromisedKey` warning.
  - `PlanRejected(S3)` event: verifies normally; no warning (key was already Compromised at event time, rejection was correct).
  - `SessionTerminated(S1, reason=KeyCompromised)` event: verifies normally.

### Integration: emergency revocation (INV-KEY-07)

- [ ] Admit 2 sessions under key K. Hand-write a valid `emergency_revocations.toml` revoking K. Send SIGHUP. Verify both sessions are terminated with `EmergencyKeyCompromised`, immediate hypervisor stop (no SIGTERM grace, verify by checking the VM had no opportunity to run a SIGTERM handler — e.g., write a sentinel file from the SIGTERM handler in the test agent and verify it does not exist).
- [ ] Permissions failure: write `emergency_revocations.toml` with mode 0644. Start kernel. Verify startup fails with `FAIL_EMERGENCY_FILE_PERMISSIONS_INVALID`. Fix permissions; restart succeeds.
- [ ] Permissions failure mid-run: kernel running normally, change file mode to 0644, send SIGHUP. Verify reload refuses, `SecurityViolation { EmergencyFilePermissionsInvalid }` emitted, previous in-memory state preserved (no spurious revocations or un-revocations).
- [ ] Tamper detection: apply 3 emergency revocations. Edit file to remove one. SIGHUP. Verify `EmergencyRevocationFileTampered { missing_fingerprints: [...] }` emitted; the removed revocation REMAINS APPLIED in `emergency_key_revocations`.
- [ ] Cannot un-revoke: emergency-revoke K. Try to push a normal `policy.toml` that omits the revocation. Verify the lookup function still returns Compromised for K (via `key_trust_now()` consulting emergency table); new admissions under K still rejected.
- [ ] Orphan revocation: emergency-revoke a fingerprint not in current policy. Verify entry is recorded with `applied_to_sessions: 0`. Push a new policy that introduces a key with that fingerprint. Verify the next admission attempt under that key fails with `FAIL_KEY_COMPROMISED` (because emergency entry pre-exists).
- [ ] Crash mid-emergency-apply: SIGKILL kernel after committing the `emergency_key_revocations` row but before VM teardown. Restart. Verify reconciliation completes the teardown.
- [ ] CLI confirmation: `raxis emergency-revoke --key-id K` with N active sessions; verify CLI surfaces "N sessions will be terminated immediately" before confirmation prompt.

### Integration: signal handling (INV-KEY-08)

- [ ] Plant a SIGTERM handler in a test agent that writes `/workspace/sigterm-ran` and exits cleanly. Trigger `KeyCompromised`. Verify `/workspace/sigterm-ran` does NOT exist (Immediate teardown, hypervisor stop, no in-VM handler ran).
- [ ] Same agent with same SIGTERM handler. Trigger `PushQueueOverflow` (Graceful). Verify `/workspace/sigterm-ran` DOES exist (Graceful teardown, SIGTERM ran successfully within 5s grace).
- [ ] Cascade signal class inheritance: Orchestrator session O (signing_key K) delegates to Executor E. Compromise K. Verify O is terminated Immediate; E is cascade-terminated Immediate (NOT Graceful — inheritance preserves Immediate class).
- [ ] Cascade with operational parent: O completes naturally. E is cascade-terminated as ParentSessionRevoked with parent_reason=CompletedSuccessfully → Graceful. Verify E's SIGTERM handler runs.
- [ ] Hypervisor stop fallback: simulate hypervisor stop primitive failure (mock returns error). Verify kernel falls back to `kill -9 <vm_pid>`. Verify VM exits regardless.

### Integration: race outcomes (§7.5)

- [ ] **Case A1** (merge committed before revocation, push pending): start IntegrationMerge; commit it; immediately push policy with K → Compromised; verify local master has the merge commit, PushApprovalRequired escalation is auto-canceled, remote is untouched, audit replay flags merge with `RetroactivelyCompromisedKey`.
- [ ] **Case A2** (merge committed AND pushed before revocation): same as A1 but the push escalation was already approved and executed; verify local master has commit, remote has commit, kernel does NOT attempt unpush, audit log clearly identifies the push as suspect.
- [ ] **Case B** (revocation committed before merge): hold the merge transaction at BEGIN IMMEDIATE; commit revocation; release merge; verify merge handler reads `sessions.state = Failed` and aborts with `FAIL_SESSION_REVOKED`; no git operation occurs; Orchestrator's clone is preserved.

---

## 13. Alternatives Considered and Rejected

### Alt A — Single-reason revocation (always retroactive)

Treat every revocation as compromise; rotation-without-killing-sessions is operator's problem. Rejected: makes regular key rotation operationally painful, which discourages rotation, which weakens security. The two-reason model costs one TOML field and removes a perverse incentive.

### Alt B — Kill on next intent rather than at policy push

When a key is compromised, leave in-flight sessions alone; reject their next intent with `FAIL_REVOKED`. Rejected: the agent can keep doing damage in the inference loop between operator pushing the revocation and the agent emitting its next intent. Inference can take 30+ seconds; that's 30 seconds of attacker-controlled execution. INV-KEY-03 requires SIGTERM at policy-push commit time.

### Alt C — Soft compromise (warn but don't terminate)

A `compromise` revocation could surface warnings without termination, deferring the decision to the operator. Rejected: turns a structural enforcement into a procedural one, violates fail-closed default (INV-01). The operator already chose to call it `compromise` in the TOML — that IS the decision.

### Alt D — Unified key registry with credential-proxy keys

Roll plan-signing keys, master-repo push credentials, gateway provider keys, all into one `[[keys]]` table. Rejected: each key class has different semantics (plan signing is verifying; provider keys are signing/encrypting; push credentials are HTTP authentication). A unified table forces a lowest-common-denominator schema and prevents class-specific validations. Separate tables, parallel revocation patterns, is cleaner.

### Alt E — Auto-bump policy epoch on revocation only

Operator pushes a "revocation patch" that only contains the revocation, kernel auto-bumps epoch. Rejected: deviates from the "policy is one signed bundle per epoch" model. Forces the kernel to support partial-policy semantics, which complicates diffing and audit replay. Operators who want to revoke quickly can push a one-line-changed policy bundle; that's the same number of operator actions for substantially less kernel complexity.

### Alt F — Make `revoked_at` a strict cutoff in compromise mode (only kill sessions admitted after `revoked_at`)

Compromise means the key was leaked AT `revoked_at`; sessions admitted earlier were under a clean key. Rejected: by the time the operator detects and reports a leak, the leak has typically been live for hours or days. Pretending `revoked_at` is the actual leak time is fiction. The honest behavior is: if you don't know when the leak started, treat all admissions under this key as suspect. This matches industry practice (PKI: a `revoked` cert is invalid for ALL signatures, not just post-revocation ones).

### Alt G — Persist `key_trust_state` only for current epoch; recompute historical state from policy bundles on demand

Simpler schema. Rejected: §8 audit replay would need to re-parse arbitrarily-old policy bundles for every event, scaling badly with audit log size. The 10MB-over-years materialization cost is trivial compared to the operational benefit of O(1) historical lookups.

### Alt H — Cryptographically signed emergency revocations (HSM-backed)

Require emergency revocations to be signed by an HSM-backed root key separate from plan-signing keys. Rejected: re-introduces the chicken-and-egg problem in a different form (what if the HSM is unavailable, the root key holder is unreachable, the HSM key is itself compromised?). HSM pre-provisioning is also operationally heavy and excludes operators who don't have HSMs. Filesystem-permission authority works on every UNIX host without additional infrastructure and is observably correct (the operator can verify with `ls -l`).

V3 may add OPTIONAL HSM-backed emergency revocations as a defense-in-depth layer for operators who want it, but V2 ships with filesystem-permission authority as the sole mechanism.

### Alt I — Allow emergency revocations to un-revoke (recovery from operator mistake)

Add a `restore` operation that un-revokes an emergency-revoked key. Rejected: violates INV-KEY-07 append-only. Once a key has been treated as compromised, even briefly, the only safe response is to assume any signature it produced during the un-revocation window is suspect. Restoring trust is fundamentally inconsistent with the threat model. The operator who emergency-revoked by mistake must rotate to a new key — operationally costly but the only honest answer.

### Alt J — Hand-write the emergency file with no validation

Skip the kernel-side validation step (§6.5 step 3) and trust the operator to write a valid file. Rejected: the operator may be using `raxis emergency-revoke` (validated CLI) OR hand-editing under stress (typo-prone). A hand-written entry with a wrong fingerprint would silently revoke the wrong key, or no key at all (orphan). Strict validation with clear error messages is mandatory; the cost is trivial.

### Alt K — Single signal-handling category (Immediate for all)

Always use hypervisor stop, even for natural completion. Rejected: graceful termination has legitimate use cases (a cleanly completing agent should be allowed to flush its in-VM caches, close file handles, write a `done` marker for orchestrator visibility). The two-category model with static classification correctly separates "this VM is suspect, kill it now" from "this VM finished its work, let it tidy up."

### Alt L — Configurable signal handling per termination reason

Allow `policy.toml` to override the signal class for any reason. Rejected: a misconfigured policy could downgrade `KeyCompromised` to Graceful, defeating INV-KEY-08. Static code-level classification with compiler-enforced exhaustiveness eliminates this footgun.

### Alt M — Auto-revert IntegrationMerge commits on revocation

When a session is killed for `KeyCompromised`, automatically revert any commits it produced via `IntegrationMerge`. Rejected: requires choosing a revert strategy (revert commit on master, force-push clean history, drop and recreate), which depends on remote conventions and team policy. Auto-reverting could destroy work that is actually fine (a buggy `compromise` decision by the operator). Conservative position: kernel preserves the commits and flags them via `RetroactivelyCompromisedKey` audit warning; operator decides whether and how to revert.

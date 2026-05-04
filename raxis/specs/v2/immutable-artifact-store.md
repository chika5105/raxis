# RAXIS V2 — Immutable Artifact Store

> **Status:** V2 Specified
> **Cross-references:**
> - `security/raxis-security-model.md §Part 16` — Store isolation and INV-STORE-02
> - `policy-plan-authority.md §INV-POLICY-01` — Policy as immutable floor
> - `v2-deep-spec.md §INV-VM-CAP-03` — VM image OCI digest pinning
> - `integration-merge.md §7` — Audit events (IntegrationMergeCompleted)

---

## 1. The Core Principle

Every artifact in RAXIS that represents state at a point in time is stored
**content-addressed and immutably**. Files in the artifact store are:

- Written exactly once
- Named by the SHA-256 hash of their content
- Never modified after being written
- Never deleted (or only deleted after a configurable retention window, never sooner)

This means any question of the form **"what was X at time T?"** is always answerable:

1. Query the audit chain for the event nearest T that references artifact X by SHA-256
2. Retrieve the artifact at `$RAXIS_DATA_DIR/artifacts/<sha256>`
3. Verify the retrieved file's SHA-256 matches — content-address is a built-in
   integrity check

This is the same model git uses for its object store: every commit, tree, and blob is
SHA-addressed and immutable. The audit chain is the git log; the artifact store is the
object database.

---

## 2. Artifact Categories

### 2.1 Policy Bundles

**Every policy bundle ever active is preserved.**

```
$RAXIS_DATA_DIR/artifacts/policy/
  <sha256-a>.toml          ← policy bundle active at epochs 1–5
  <sha256-b>.toml          ← policy bundle active at epochs 6–9
  <sha256-c>.toml          ← current active policy bundle (epoch 10)

$RAXIS_DATA_DIR/policy/
  policy.toml              ← symlink → ../artifacts/policy/<current-sha256>.toml
  current_epoch            ← plain text file: "10"
```

**Write path:** `raxis policy push new_policy.toml`
1. Kernel computes `sha256 = SHA-256(new_policy.toml bytes)`
2. Kernel verifies it does not already exist (idempotent push of same bytes is a no-op)
3. Kernel writes `$RAXIS_DATA_DIR/artifacts/policy/<sha256>.toml` with `O_CREAT | O_EXCL`
   (fails if file exists — guarantees no overwrite)
4. Kernel updates `policy.toml` symlink atomically (`rename()` after creating a temp symlink)
5. Kernel advances epoch, emits `PolicyEpochAdvanced` with both SHA-256 values

**Permissions:** `artifacts/policy/` owned by `raxis-kernel`, mode `0700`. No other
process has read access. The Kernel reads policy at startup and caches it in memory.
Direct filesystem reads by operators for auditing go through `raxis policy history` CLI.

---

### 2.2 Plan Bundles

**Every approved plan is preserved with its Ed25519 signature.**

```
$RAXIS_DATA_DIR/artifacts/plans/
  <sha256-of-plan>.toml    ← plan bytes (as submitted)
  <sha256-of-plan>.sig     ← Ed25519 signature over the plan bytes
```

**Write path:** `raxis plan approve plan.toml`
1. Kernel computes `sha256 = SHA-256(plan.toml bytes)`
2. Kernel writes `artifacts/plans/<sha256>.toml` with `O_CREAT | O_EXCL`
3. Kernel writes `artifacts/plans/<sha256>.sig` (the operator's signature bytes)
4. `InitiativeCreated` audit event records `plan_sha256` (already specified)

**Why preserve the signature alongside the plan:**
The plan artifact is only meaningful if you can verify it was legitimately approved.
The `.sig` file allows any auditor with `operator_public.pem` to verify:
- The plan was approved by an operator who held the private key at approval time
- The plan bytes haven't been modified since approval

**Re-approval:** If the same plan is re-approved (same bytes, new epoch), the artifact
files already exist — the `O_CREAT | O_EXCL` write is a no-op. The Kernel records the
new `InitiativeCreated` event with the same `plan_sha256` but the new `policy_epoch`.

---

### 2.3 Operator Public Keys

**Key rotation preserves all historical public keys.**

```
$RAXIS_DATA_DIR/artifacts/keys/
  <fingerprint-a>.pem      ← operator public key A (may be superseded)
  <fingerprint-b>.pem      ← operator public key B (current)

$RAXIS_DATA_DIR/
  operator_public.pem      ← symlink → artifacts/keys/<current-fingerprint>.pem
```

**Key fingerprint:** `SHA-256(DER-encoded public key bytes)`, hex-encoded.

**Why preserve historical keys:**
Audit events and plan signatures made under key A must remain verifiable after key B
is in use. Without the historical key file, a signature from before a key rotation
cannot be verified — the audit chain becomes partially unverifiable.

**`OperatorKeyRotated` audit event:**
```rust
AuditEventKind::OperatorKeyRotated {
    old_key_fingerprint: String,   // SHA-256 of the old DER-encoded public key
    new_key_fingerprint: String,   // SHA-256 of the new DER-encoded public key
    effective_at_epoch:  u64,      // policy epoch at which new key takes effect
}
```

Plans and policy bundles approved after `effective_at_epoch` must be signed with the
new key. Plans approved before remain valid under the old key.

---

### 2.4 Audit Log Segments (Already Immutable — INV-STORE-02)

The SQLite audit store is already append-only (INV-STORE-02): no `DELETE` or `UPDATE`
on `audit_events`. This is the existing guarantee from the security model. Documented
here for completeness.

The audit log is not content-addressed per event (events are rows, not files), but the
database file itself can be periodically snapshotted and SHA-256-hashed for archival
verification — not specified as a V2 requirement but a natural extension.

---

### 2.5 VM Images (Already Content-Addressed — OCI)

OCI images are content-addressed by design: the `oci_digest` in the policy bundle's
`[[vm_images]]` is the SHA-256 of the image manifest. The Kernel verifies the pulled
image matches the pinned digest before booting. This already satisfies the immutability
principle — VM images are never "updated in place," they are replaced by a new digest
and a new policy epoch.

---

## 3. Updated `PolicyEpochAdvanced` Audit Event

The existing event is extended to include full content attribution:

```rust
AuditEventKind::PolicyEpochAdvanced {
    from:                    u64,
    to:                      u64,

    // Content-addressed references to the exact policy bytes
    new_policy_sha256:       String,   // SHA-256 of the incoming policy bundle
    previous_policy_sha256:  String,   // SHA-256 of the policy bundle being replaced

    // Attribution
    operator_key_fingerprint: String,  // fingerprint of the key that signed the push

    // Semantic diff summary (for human-readable audit queries)
    sections_changed:        Vec<String>,  // e.g., ["protected_paths", "egress_hosts"]
    sections_added:          Vec<String>,
    sections_removed:        Vec<String>,
}
```

**`sections_changed/added/removed`:** The Kernel computes a high-level semantic diff
between the old and new policy bundles at push time. This is a summary for human-readable
audit queries — not a substitute for the full diff (which is always available by
retrieving the two artifacts by SHA-256 and running `diff`).

---

## 4. Storage Layout (Complete)

```
$RAXIS_DATA_DIR/
  artifacts/
    policy/
      <sha256>.toml        ← one file per unique policy bundle ever submitted
    plans/
      <sha256>.toml        ← one file per unique plan ever approved
      <sha256>.sig         ← Ed25519 signature over the plan bytes
    keys/
      <fingerprint>.pem    ← one file per unique operator public key ever registered

  policy/
    policy.toml            ← symlink → ../artifacts/policy/<current-sha256>.toml
    current_epoch          ← plain text: current epoch number

  operator_public.pem      ← symlink → artifacts/keys/<current-fingerprint>.pem

  audit/
    audit.db               ← append-only SQLite (INV-STORE-02)

  worktrees/               ← ephemeral (created per session, deleted on VM teardown)
  sessions/                ← ephemeral session config (created per session, deleted on teardown)
  credentials/             ← operator-managed; not mounted into VMs (INV-VM-CAP-04)
```

**Ownership and permissions:**

| Path | Owner | Mode | Rationale |
|---|---|---|---|
| `artifacts/` | `raxis-kernel` | `0700` | No other process reads artifacts directly |
| `artifacts/policy/` | `raxis-kernel` | `0700` | Policy is kernel-internal |
| `artifacts/plans/` | `raxis-kernel` | `0700` | Plans may contain sensitive task context |
| `artifacts/keys/` | `raxis-kernel` | `0700` | Public key material; reads via CLI only |
| `audit/audit.db` | `raxis-kernel` | `0600` | Append-only; only Kernel writes |

Operators read historical artifacts through the CLI (`raxis policy history`,
`raxis plan show <sha256>`, `raxis keys list`) — not by direct filesystem access.
The CLI commands read through the Kernel's query API.

---

## 5. Retention Policy

By default, artifacts are retained indefinitely — the immutability guarantee is
strongest when nothing is ever deleted. For deployments with storage constraints,
a retention window may be configured:

```toml
# policy.toml

[artifact_retention]
policy_bundles_days = 0    # 0 = retain forever (default)
plans_days          = 0    # 0 = retain forever (default)
keys_days           = 0    # 0 = retain forever (recommended — needed for signature verification)
```

`0` means indefinite retention. Non-zero values enable garbage collection of artifacts
older than the specified window. **Key artifacts should never be deleted** — a key
deleted before all signatures made under it have been verified breaks the audit chain.
The Kernel enforces: `keys_days` cannot be set to a non-zero value if any plan or policy
artifact references a key fingerprint and the artifact itself would be retained beyond
the key's deletion window.

---

## 6. Audit Queries Enabled by Immutable Artifacts

With content-addressed immutable storage, the following queries become fully answerable:

| Question | How to answer |
|---|---|
| What were the egress rules on March 3 at 14:22? | Find `PolicyEpochAdvanced` event ≤ 14:22 with highest epoch; retrieve `artifacts/policy/<new_sha256>.toml` |
| Who approved initiative X and under what policy? | Query `InitiativeCreated` for initiative X; retrieve `plan_sha256` and `policy_epoch`; retrieve both artifacts |
| Did the policy change between initiative A and initiative B? | Compare `policy_epoch` in their `InitiativeCreated` events; if different, diff the two policy artifacts |
| Was the plan for initiative X modified after approval? | Retrieve `artifacts/plans/<plan_sha256>.toml`; verify SHA-256 matches; verify Ed25519 signature |
| Which initiatives were running when policy changed from epoch 7 to 8? | Find `PolicyEpochAdvanced` event (epoch 7→8); find all `InitiativeCreated` events with epoch ≤ 7 and no `InitiativeCompleted` before the policy change |
| Which operator key signed policy epoch 8? | Read `PolicyEpochAdvanced.operator_key_fingerprint`; retrieve `artifacts/keys/<fingerprint>.pem` |

---

## 7. Implementation Checklist

- [ ] Create `artifacts/policy/`, `artifacts/plans/`, `artifacts/keys/` directories
      at Kernel first boot with correct ownership and permissions
- [ ] Implement content-addressed write in `raxis policy push`:
      SHA-256 computation → `O_CREAT | O_EXCL` write → symlink update (atomic `rename()`)
- [ ] Implement content-addressed write in `raxis plan approve`:
      SHA-256 computation → `O_CREAT | O_EXCL` for `.toml` and `.sig` files
- [ ] Implement `OperatorKeyRotated` audit event
- [ ] Update `PolicyEpochAdvanced` audit event struct:
      add `new_policy_sha256`, `previous_policy_sha256`, `operator_key_fingerprint`,
      `sections_changed`, `sections_added`, `sections_removed`
- [ ] Implement semantic diff computation between policy bundles at `raxis policy push`
- [ ] Add `[artifact_retention]` section to `PolicyBundle` struct
- [ ] Implement retention GC with key-retention safety check
- [ ] Implement CLI read commands:
      - `raxis policy history` — list all past epochs with SHA-256 and timestamp
      - `raxis policy show <sha256>` — display policy bundle at given SHA-256
      - `raxis policy diff <sha256-a> <sha256-b>` — diff two policy bundles
      - `raxis plan show <sha256>` — display plan bundle with signature verification
      - `raxis keys list` — list all registered operator key fingerprints with dates
- [ ] Tests:
      - Policy push: artifact written with correct SHA-256 name
      - Policy push: same bytes twice → second write is no-op, no new epoch
      - Symlink update is atomic (verify using concurrent reader)
      - Plan approve: artifact and sig written
      - PolicyEpochAdvanced contains both SHA-256 values and key fingerprint
      - Historical artifact retrieval returns correct bytes for past epoch
      - Retention GC: refuses to delete key if referenced plan is within retention window

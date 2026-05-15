# RAXIS V2 — Immutable Artifact Store

> **Status:** V2 Specified
> **Cross-references:**
> - `security/raxis-security-model.md §Part 16` — Store isolation and INV-STORE-02
> - [`policy-plan-authority.md §INV-POLICY-01`](policy-plan-authority.md) — Policy as immutable floor
> - [`v2-deep-spec.md §INV-VM-CAP-03`](v2-deep-spec.md) — VM image OCI digest pinning
> - [`integration-merge.md §7`](integration-merge.md) — Audit events (IntegrationMergeCompleted)

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

```text
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

```text
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

```text
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

<!-- spec-graph:cross-ref -->

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

```text
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

By default, artifacts are retained indefinitely. The default value for every retention
field is `"forever"` — an explicit, unambiguous declaration that the artifact lives
forever.

```toml
# policy.toml

[artifact_retention]
policy_bundles = "forever"   # default — retain all policy bundles forever
plans          = "forever"   # default — retain all approved plans forever
keys           = "forever"   # default — retain all operator keys forever (strongly recommended)
```

For deployments with storage constraints, a specific retention window may be configured
using a positive integer (number of days):

```toml
[artifact_retention]
policy_bundles = 3650    # retain for 10 years
plans          = 3650    # retain for 10 years
keys           = "forever"   # keys should never be deleted — see safety constraint below
```

### Rust Type — `RetentionDays`

The TOML value is parsed into a Rust enum that makes invalid states unrepresentable.
The value `0` is not a valid `RetentionDays` — it is rejected at the serde deserialization
layer before it reaches any Kernel logic. An operator who types `plans = 0` gets a parse
error at `raxis policy push` time, not a silent "retain zero days" behavior.

```rust
/// Retention window for a class of artifacts.
///
/// Serialization:
///   "forever"         → RetentionDays::Forever
///   <positive integer> → RetentionDays::Days(NonZeroU64)
///   0                  → parse error (serde rejects before reaching kernel logic)
///   negative integer   → parse error
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum RetentionDays {
    /// Retain indefinitely. No garbage collection runs for this artifact class.
    Forever,
    /// Retain for exactly N days. N must be ≥ 1.
    Days(NonZeroU64),
}

impl<'de> Deserialize<'de> for RetentionDays {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        use serde::de::Error;

        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Raw {
            Str(String),
            Int(i64),
        }

        match Raw::deserialize(d)? {
            Raw::Str(s) if s == "forever" => Ok(RetentionDays::Forever),
            Raw::Str(s) => Err(D::Error::custom(format!(
                "invalid retention value {:?}: expected "forever" or a positive integer",
                s
            ))),
            Raw::Int(n) if n <= 0 => Err(D::Error::custom(format!(
                "invalid retention value {}: must be a positive integer (≥ 1) or "forever".                  Use "forever" to retain forever.",
                n
            ))),
            Raw::Int(n) => Ok(RetentionDays::Days(
                NonZeroU64::new(n as u64).expect("checked above"),
            )),
        }
    }
}

impl Default for RetentionDays {
    fn default() -> Self {
        RetentionDays::Forever   // "forever" is the default for all retention fields
    }
}
```

```rust
// crates/policy/src/bundle.rs

#[derive(Debug, Deserialize, Default)]
pub struct ArtifactRetention {
    #[serde(default)]
    pub policy_bundles: RetentionDays,   // default: Forever

    #[serde(default)]
    pub plans: RetentionDays,            // default: Forever

    #[serde(default)]
    pub keys: RetentionDays,             // default: Forever
}
```

### Safety Constraint on Key Retention

**Key artifacts should never be deleted.** An operator key that is deleted before all
plan and policy artifacts signed by it are also deleted breaks the audit chain — historical
signatures become unverifiable.

The Kernel enforces this at `raxis policy push` time: if `keys` is set to `Days(N)`,
the Kernel checks that `policy_bundles` and `plans` are also set to `Days(M)` where
`M ≤ N`. If any plan or policy artifact would outlive the key used to sign it, the push
is rejected:

```text
ERROR: artifact_retention.keys = 365 (days) is shorter than artifact_retention.plans = "forever".
Plans retained longer than the key used to sign them cannot be re-verified.
Set keys = "forever" or reduce plans retention to ≤ 365 days.
```

The recommended posture is `keys = "forever"` always.

---

## 5b. Garbage Collection — Review and Deletion of Expiring Artifacts

### Overview

When a retention window is set to `Days(N)`, artifacts older than N days become
eligible for deletion. The Kernel does not delete eligible artifacts automatically —
deletion is operator-initiated. This is intentional: the retention window is a policy
decision, but the act of reclaiming storage is an operational one. The operator reviews
what will be deleted before any file is touched.

### GC Flow

```text
1. Operator: raxis gc --dry-run
   → Kernel computes expiry candidates (no files touched)
   → Kernel runs safety checks on the full candidate set
   → Prints report: what would be deleted, what is blocked, why
   → No audit event emitted (dry-run is read-only)

2. Operator reviews the report

3. Operator: raxis gc
   → Kernel re-computes expiry candidates (list may differ if time passed)
   → Kernel re-runs safety checks
   → Emits ArtifactGCStarted { candidates, blocked, dry_run: false }
   → For each candidate that passes safety checks:
       - Unlinks the file (atomic at OS level)
       - Emits ArtifactExpired { artifact_type, sha256, created_at, deleted_at }
   → Emits ArtifactGCCompleted { deleted_count, blocked_count, failed_count }
```

### Expiry Candidate Computation

An artifact is an expiry candidate when:

```text
now() - artifact.written_at > retention_window.days()
```

The `written_at` timestamp is recorded in the Kernel's artifact index (a table in
`audit.db`) at the moment the artifact is written with `O_CREAT | O_EXCL`. The index
is not the artifact file itself — it is a separate record that survives even after
the artifact file is deleted.

```sql
-- artifact index (in audit.db, separate from audit_events)
CREATE TABLE artifact_index (
    sha256        TEXT    NOT NULL PRIMARY KEY,
    artifact_type TEXT    NOT NULL CHECK (artifact_type IN ('policy', 'plan', 'key')),
    written_at    INTEGER NOT NULL,   -- Unix timestamp (seconds)
    deleted_at    INTEGER,            -- NULL if not yet deleted
    UNIQUE (sha256, artifact_type)
);
```

Expiry candidates:
```sql
SELECT sha256, artifact_type, written_at
FROM artifact_index
WHERE deleted_at IS NULL
  AND artifact_type IN (
      -- only include types whose retention window is Days(N), not Forever
      -- resolved from current policy bundle at GC time
  )
  AND (unixepoch('now') - written_at) > (retention_days * 86400);
```

### Safety Checks Before Any Deletion

The Kernel runs these checks on the **full candidate set** before unlinking any file.
A single blocked artifact does not prevent others from being deleted — blocked artifacts
are reported separately and skipped.

**Check S1 — Key-plan referential integrity:**
For each key artifact in the candidate set:
- Query `audit_events` for all `InitiativeCreated` events with
  `operator_key_fingerprint = <this_key_fingerprint>`
- For each such initiative, find its `plan_sha256`
- Check if that plan artifact is still present (`deleted_at IS NULL`) and NOT in the
  candidate set
- If yes: the key cannot be deleted (plan would outlive its signing key)
- Result: `BLOCKED_KEY_REFERENCED_BY_LIVE_PLAN { key_fingerprint, referencing_plan_sha256 }`

**Check S2 — Key-policy referential integrity:**
Same as S1 but for `PolicyEpochAdvanced` events:
- If a policy artifact is live and was signed by this key, the key cannot be deleted
- Result: `BLOCKED_KEY_REFERENCED_BY_LIVE_POLICY { key_fingerprint, referencing_policy_sha256 }`

**Check S3 — Policy-plan referential integrity:**
For each policy artifact in the candidate set:
- Query `audit_events` for `InitiativeCreated` events with `policy_sha256 = <this_sha256>`
- If the corresponding plan artifact is still live and NOT in the candidate set:
  the policy artifact can be deleted (policy and plan have independent retention)
  — note: losing the policy means you cannot reconstruct the exact policy the plan
  was approved against. This is acceptable if the operator has chosen a shorter
  retention for policy bundles than for plans. The audit event `InitiativeCreated`
  still records the `policy_sha256` — you know what the policy was, you just can't
  retrieve its full content.
  → No block. But a warning is printed:
  `WARN_GC_POLICY_ARTIFACT_UNRETRIEVABLE_AFTER_DELETION { policy_sha256, referencing_plan_sha256 }`

### Audit Events for GC

```rust
AuditEventKind::ArtifactGCStarted {
    candidates:    Vec<ArtifactRef>,   // full list considered for deletion
    blocked:       Vec<BlockedArtifact>, // blocked by safety checks with reason
    dry_run:       bool,
}

AuditEventKind::ArtifactExpired {
    artifact_type:  String,   // "policy" | "plan" | "key"
    sha256:         String,
    written_at:     u64,      // Unix timestamp when artifact was first written
    deleted_at:     u64,      // Unix timestamp of this deletion
    retention_days: u64,      // the Days(N) value that triggered eligibility
}

AuditEventKind::ArtifactGCCompleted {
    deleted_count:  u32,
    blocked_count:  u32,
    failed_count:   u32,   // OS-level unlink failures (permissions, IO errors)
    duration_ms:    u64,
}
```

**Why GC events are in the append-only audit log:**
Even after an artifact's bytes are gone, the audit chain permanently records:
- That the artifact existed (from the original write event)
- Its SHA-256 (so cross-references in `InitiativeCreated` remain meaningful)
- When it was deleted and why (retention policy)

An auditor can always answer: "did policy artifact `abc123` exist and when was it
deleted?" — even after the file is gone.

### What the `--dry-run` Report Looks Like

```text
raxis gc --dry-run

Retention policy (epoch 12):
  policy_bundles : 3650 days
  plans          : 3650 days
  keys           : infinity

Expiry candidates (as of 2026-05-03 16:05 UTC):
  policy  sha256=a1b2c3...  written=2015-12-01  age=3805d  → ELIGIBLE
  policy  sha256=d4e5f6...  written=2016-03-15  age=3701d  → ELIGIBLE
  plan    sha256=g7h8i9...  written=2016-01-10  age=3765d  → ELIGIBLE
  key     sha256=j0k1l2...  written=2014-08-20  age=4273d  → BLOCKED

Safety check results:
  BLOCKED  key j0k1l2... → referenced by live plan g7h8i9... (would outlive key)
           Fix: delete plan g7h8i9... first, or set keys = "forever"

Warnings:
  WARN  policy a1b2c3... is referenced by plan m3n4o5... (plan within retention).
        After deletion, policy a1b2c3... bytes will be unrecoverable.
        Audit event InitiativeCreated for initiative 9f8e7d will still record
        policy_sha256 = a1b2c3... for traceability.

Would delete: 3 artifacts (2 policy, 1 plan)
Blocked:      1 artifact (1 key)
Run 'raxis gc' to execute.
```

### Optional Scheduled GC

For deployments that want automatic GC, the policy can configure a schedule:

```toml
[artifact_retention]
policy_bundles = 3650
plans          = 3650
keys           = "forever"

[artifact_retention.gc_schedule]
enabled        = false        # default — GC is manual
cron           = "0 2 * * 0" # if enabled: run at 02:00 UTC every Sunday
dry_run_only   = false        # if true: scheduled runs are always dry-run (report only)
```

**`dry_run_only = true`** is recommended for scheduled GC: the Kernel runs the dry-run
report automatically and records it as `ArtifactGCStarted { dry_run: true }` in the
audit chain. The operator reviews the weekly report and runs `raxis gc` manually when
ready. This gives the time-awareness of scheduled GC without automatic deletion.

### Updated Implementation Checklist Additions

- [ ] Create `artifact_index` table in DDL (migration 3):
      `sha256`, `artifact_type`, `written_at`, `deleted_at`
- [ ] Populate `artifact_index` on every artifact write (`O_CREAT | O_EXCL` success)
- [ ] Implement `kernel/src/gc/expiry.rs`: expiry candidate query
- [ ] Implement `kernel/src/gc/safety.rs`: checks S1, S2, S3
- [ ] Implement `raxis gc --dry-run` CLI command
- [ ] Implement `raxis gc` CLI command (with confirmation prompt if terminal is interactive)
- [ ] Emit `ArtifactGCStarted`, `ArtifactExpired`, `ArtifactGCCompleted` audit events
- [ ] Update `artifact_index.deleted_at` on successful unlink
- [ ] Implement `[artifact_retention.gc_schedule]` section in `PolicyBundle`
- [ ] Implement scheduled GC via Kernel-internal timer (tokio interval)
- [ ] Tests:
      - Artifact past retention window appears in dry-run as ELIGIBLE
      - Key blocked by live plan → BLOCKED with reason
      - Policy deletion with live plan reference → warning (not block)
      - Scheduled dry-run emits ArtifactGCStarted { dry_run: true } in audit
      - artifact_index.deleted_at set after successful gc
      - artifact_index row survives artifact file deletion (index outlives artifact)


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

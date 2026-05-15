# RAXIS V3 — Audit Retention, Archiving, and Forensic Verification

> **Status:** V3 Specified (deferred from V2 GA per design discussion)
> **Cross-references:**
> - `specs/invariants.md` — INV-04 (audit log tamper-evidence; this spec specifies V3's enforcement mechanism), INV-05 (decisions reproducible from stored records), INV-CRED-KERNEL-01 (kernel egress strictly bounded; this spec preserves it)
> - `specs/v2/host-capacity.md §6.3, §7.5, §7.6` — audit segment rotation, audit reserve, `AuditWriteImpossible` halt behavior; this spec extends segment lifecycle past the host
> - `specs/v2/key-revocation.md §3` — `key_trust_state` table; the operating key used to sign witnesses is in the same registry
> - `specs/v2/integration-merge.md §11` — three-phase transactional pattern; the redaction tool reuses this pattern for its SQLite ↔ filesystem boundary
> - `specs/v2/provider-failure-handling.md §6.5` — `inference_attempts` indexed view; this spec specifies its retention separately from the raw audit log

---

## 1. The Problem

V2 ships with the simplest possible audit retention: segments accumulate on the kernel host indefinitely, and the disk-full watchdog (`host-capacity.md §7`) eventually halts admission when `min_free_disk_mb` is breached. This is correct fail-closed behavior — no audit data is lost, no untracked deletions occur — but it is operationally hostile for any production deployment that expects to run for more than a few months. The first audit log byte written never leaves the kernel host, the disk fills, the kernel halts, and recovery is "manually move segments off-host, then restart."

V3 specifies the full lifecycle: how segments leave the kernel host, how operators verify archived data months or years later, and how the system handles the legal reality that some data must occasionally be deleted (GDPR right-to-erasure). Four hard constraints shape the design:

- **The kernel must not perform WAN egress.** Per `INV-CRED-KERNEL-01` (drafted with `key-revocation.md`), the kernel's outbound network surface is strictly bounded to `git push` operations using a statically-enumerated credential. Putting an AWS S3 SDK, Azure Blob client, or any other archive backend's network library into the kernel address space would expand the most-privileged process's attack surface against memory-safety bugs in third-party network code. The archiving must happen in a separate process.
- **The audit log is a hash-chained Merkle structure that cannot be retroactively mutated.** Once Event N is written and Event N+1 commits with N's hash embedded, mutating N's bytes invalidates every hash that follows. This is a mathematical property, not a policy choice. Any redaction mechanism that pretends otherwise is broken on arrival.
- **Forensic verification of historical events must be tractable without downloading the entire archive.** A 50,000-segment archive cannot require a full restore to verify a single event. Resolution: the V3 audit log is a Merkle tree, not a linear hash chain, enabling O(log N) inclusion proofs.
- **GDPR right-to-erasure is a real legal obligation in many jurisdictions.** The system must support a deliberate, signed, attested redaction action that erases specific personal data while preserving forensic verifiability of everything else.

This spec answers four operator-facing questions: "what happens to my audit data after it's written?", "how do I prove a specific event happened in court?", "what if I get a GDPR request to erase a former employee's data?", and "what if my audit storage backend goes down?"

---

## 2. Architecture: Three Actors and One Filesystem Boundary

V3 introduces a separate `raxis-archiver` daemon process. The three-actor model:

| Actor | Owns | Network surface |
|---|---|---|
| **Kernel** | Audit segment writing, Merkle tree maintenance, witness signing, redaction tool execution, segment-lifecycle state machine, archiver IPC | Local filesystem; UDS to archiver and to gateway workers; `git push` per `INV-CRED-KERNEL-01` |
| **`raxis-archiver`** | Reading finalized segments from local filesystem; uploading to operator-configured backend (S3, Azure, NAS, custom); verifying upload integrity; ACKing back to kernel; supporting `RedactSegment` operations when GDPR redaction is enabled; optional witness publication to external anchors | Local UDS to kernel; WAN egress to operator-chosen backends |
| **External anchor service** (optional) | Receiving signed witness publications and providing tamper-evident external timestamping | Receives HTTP POSTs from `raxis-archiver` (Sigstore Rekor, internal Certificate Transparency log, custom HTTP endpoint) |

The single filesystem boundary the kernel never crosses: `disk_root/audit/` files are written by the kernel; the archiver reads them. The archiver runs under its own unprivileged UID (e.g., `raxis-archiver:raxis-archiver`) with read-only access to `disk_root/audit/` and write access to its own state directory. The archiver has zero ability to modify, replay, or fabricate audit content — it can only mirror what the kernel wrote.

### 2.1 Component diagram

```text
┌─────────────────────────────────┐
│            Kernel               │
│                                 │
│  - Writes events to active      │
│    segment (Merkle tree leaves) │
│  - Finalizes segments at        │
│    audit_segment_size_mb        │
│  - Computes per-segment Merkle  │
│    root; updates inter-segment  │
│    tree                         │
│  - Signs witnesses              │
│  - Notifies archiver            │
│  - Deletes locally only after   │
│    verified ACK                 │
└────────┬────────────────────────┘
         │
         │  /var/lib/raxis/audit/   (filesystem; archiver has read-only access)
         │  ├── 0001.log
         │  ├── 0001.merkle         (within-segment intermediate nodes)
         │  ├── 0002.log
         │  ├── 0002.merkle
         │  ├── ...
         │  ├── inter-segment.merkle (incremental tree of segment roots)
         │  └── witnesses.log       (signed Merkle root snapshots)
         │
         │  /var/run/raxis/archiver.sock  (UDS for control plane)
         │  ├── kernel sends:  AuditSegmentReady, RedactSegment, PublishWitness
         │  └── kernel receives: AuditSegmentArchived, RedactionPropagated, WitnessPublished
         │
         ▼
┌─────────────────────────────────┐
│      raxis-archiver             │
│ (separate process,              │
│  separate UID,                  │
│  unprivileged)                  │
│                                 │
│  - Reads finalized segments     │
│    from kernel's audit dir      │
│  - Uploads to backend           │
│  - Verifies roundtrip checksum  │
│  - ACKs to kernel               │
│  - Optional: publishes          │
│    witnesses to external anchor │
│  - Supports RedactSegment if    │
│    operator opted in to GDPR    │
└────────┬────────────────────────┘
         │ WAN egress to operator's backend
         │
         ▼
┌─────────────────────────────────┐    ┌────────────────────────────┐
│  Archive backend                 │    │  External anchor (opt-in)  │
│  - S3 / Glacier                  │    │  - Sigstore Rekor          │
│  - Azure Blob                    │    │  - Internal CT log         │
│  - On-prem object store          │    │  - Custom HTTP endpoint    │
│  - WORM filesystem               │    └────────────────────────────┘
│  - Custom (operator's choice)    │
└─────────────────────────────────┘
```

### 2.2 What changes vs V2

| Concern | V2 behavior | V3 behavior |
|---|---|---|
| Audit log structure | Linear hash chain | Two-level Merkle tree (within-segment + inter-segment) |
| INV-04 enforcement mechanism | Each event hashes the previous event | Each event is a leaf in the within-segment Merkle tree; segment roots are leaves of the inter-segment tree; root signed in witness |
| Local retention | Unbounded (until disk-full halt) | Configurable; segments deletable only after archiver ACK |
| Archive | Operator's responsibility (rsync / fluentd / restic) | Native via `raxis-archiver` UDS protocol |
| Forensic verification | Re-hash entire chain | Inclusion proof of any event in O(log N) hashes plus the containing segment |
| GDPR right-to-erasure | Not supported | Per-event redaction with signed `ChainTruncation` attestation |
| External tamper-evidence | None (operator trusts kernel's operating key) | Optional: witnesses publishable to Sigstore Rekor or other anchor |

The V2 audit-log format remains valid — V3 is opt-in via configuration, and operators may run V3-capable kernels in V2-compatible mode (`audit_format = "v2_linear"`) for as long as they choose. A one-time conversion tool (`raxis admin audit-migrate-to-v3`) re-builds the Merkle structure over existing V2 data when operators are ready to switch.

---

## 3. Configuration

### 3.1 `policy.toml`

```toml
[audit_retention]
# V3 audit format. "v2_linear" preserves the V2 hash-chain format;
# "v3_merkle" enables this spec's mechanisms. Migration via
# `raxis admin audit-migrate-to-v3`.
audit_format                = "v3_merkle"

# Local retention before segments become eligible for deletion (only after
# verified archiver ACK). Set to a sentinel value (e.g., 36500) for "never
# delete locally even after archive."
local_retention_days        = 90

# Path to the archiver sidecar's UDS. If empty, archiving is disabled and the
# kernel keeps everything locally indefinitely (V2-compatible behavior). The
# kernel checks SO_PEERCRED on connection and refuses any peer not running
# under the configured archiver_uid.
archiver_uds_path           = "/var/run/raxis/archiver.sock"
archiver_uid                = 991              # raxis-archiver dedicated UID

# How long the kernel tolerates accumulated archive lag before paging the
# operator. The kernel does NOT halt admission on archive lag (that's
# host-capacity.md's job when disk eventually fills); this only controls when
# OperatorAttentionRequired { kind: ArchiverLagging } fires.
archiver_lag_alert_days     = 7

[audit_retention.merkle]
# Per-segment branching factor (binary fixed in V3; reserved for future
# variants like SHA-256 Merkle Patricia trees).
within_segment_branching    = "binary"

# When a segment is finalized, the within-segment Merkle tree is computed and
# its root inserted as a leaf into the inter-segment tree. The inter-segment
# tree is updated incrementally; intermediate node hashes are persisted to
# disk as part of `inter-segment.merkle`.
inter_segment_persistence_mode = "incremental"

[audit_retention.witnesses]
# Local witness file; signed Merkle root snapshots, append-only.
local_witness_path          = "/var/lib/raxis/audit/witnesses.log"

# Sign a witness every Nth segment finalization, AND at least once every M
# seconds (whichever comes first). Witnesses are cheap; sign frequently.
sign_every_n_segments       = 10
sign_at_least_every_seconds = 3600

# Operating key used to sign witnesses. References a key in the immutable
# artifact store; rotates per `key-revocation.md` semantics.
operating_key_ref           = "raxis-operating-2026-q1"

[audit_retention.witnesses.external_anchor]
# OPTIONAL. When enabled, the archiver also publishes each witness to the
# operator's chosen anchor service. Provides tamper-evidence even against
# operating-key compromise (an attacker who controls the operating key cannot
# rewrite history because external-anchored witnesses survive elsewhere).
enabled                     = false
backend                     = "rekor"          # "rekor" | "ct_log" | "http_post"

[audit_retention.witnesses.external_anchor.rekor]
url                         = "https://rekor.sigstore.dev"
# Operator's signing identity for Rekor entries (Sigstore-compatible key/cert).
key_ref                     = "sigstore-prod-2026-q1"

[audit_retention.witnesses.external_anchor.http_post]
# Generic HTTP POST endpoint for operators with custom anchor services.
url                         = "https://anchor.internal.example.com/witness"
auth_token_ref              = "anchor-token-2026-q1"

[audit_retention.indexed_views]
# These are SQLite-side queryable indexes; distinct from the raw audit log
# (which is the forensic source of truth). Operators query indexes for
# operational use; raw log for forensic verification.
inference_attempts_days     = 90
admission_queue_days        = 30
breaker_state_history_days  = 90
operator_attention_days     = 365              # high-importance events kept longer

[audit_retention.gdpr]
# Configuration for GDPR right-to-erasure handling per §9 (Option B:
# chain truncation with signed attestation). DEFAULT: disabled. Operators
# must explicitly opt in.
redaction_enabled                 = false

# Required if redaction_enabled = true. References a separate signing key
# (NOT the operating key) used by the redaction tool to sign ChainTruncation
# attestations. This separation lets operators delegate redaction authority
# without delegating witness signing authority.
redaction_signing_key_ref         = ""

# When true, the kernel verifies (via the archiver) that the configured
# archive backend supports the RedactSegment operation BEFORE allowing
# any redaction to proceed. Set false ONLY if the operator has chosen
# immutable-archive compliance over GDPR right-to-erasure compatibility.
require_archive_compatibility     = true
```

### 3.2 SQLite schema additions

```sql
-- Per-segment archive lifecycle state. One row per segment.
CREATE TABLE audit_segment_archive_state (
    segment_id                  INTEGER PRIMARY KEY,
    finalized_at_ms             INTEGER NOT NULL,
    local_path                  TEXT    NOT NULL UNIQUE,
    local_sha256                BLOB    NOT NULL,             -- SHA-256 of the .log file bytes
    merkle_root                 BLOB    NOT NULL,             -- within-segment Merkle root
    event_count                 INTEGER NOT NULL,             -- number of leaves in this segment

    -- Archiver lifecycle
    archiver_notified_at_ms     INTEGER,
    archiver_acked_at_ms        INTEGER,
    archive_uri                 TEXT,                         -- backend-specific (s3://..., azure://..., etc.)
    archive_sha256              BLOB,                         -- SHA-256 verified by archiver post-upload
    archive_verification_at_ms  INTEGER,

    -- Local retention
    eligible_for_local_delete_at_ms INTEGER,                  -- = max(finalized_at_ms + local_retention_days,
                                                              --       archive_verification_at_ms)
    locally_deleted_at_ms       INTEGER,

    -- Redaction (rare; NULL for non-redacted segments)
    redacted_at_ms              INTEGER,
    redaction_event_id          BLOB                          -- reference to the ChainTruncation event
);

CREATE INDEX idx_audit_segment_archive_pending
    ON audit_segment_archive_state (archiver_notified_at_ms)
    WHERE archiver_acked_at_ms IS NULL;

CREATE INDEX idx_audit_segment_local_delete_eligible
    ON audit_segment_archive_state (eligible_for_local_delete_at_ms)
    WHERE locally_deleted_at_ms IS NULL
      AND archive_verification_at_ms IS NOT NULL;

-- Witnesses (signed Merkle root snapshots). Append-only.
CREATE TABLE audit_witnesses (
    witness_id                  INTEGER PRIMARY KEY,
    signed_at_ms                INTEGER NOT NULL,
    last_segment_id             INTEGER NOT NULL UNIQUE,      -- highest segment covered
    inter_segment_root          BLOB    NOT NULL,             -- Merkle root over segment roots [1..last_segment_id]
    operating_key_fingerprint   TEXT    NOT NULL,
    signature                   BLOB    NOT NULL,

    -- External anchor (NULL if local-only)
    external_anchor_backend     TEXT,                          -- "rekor" | "ct_log" | "http_post"
    external_anchor_ref         TEXT,                          -- backend-specific (Rekor entry UUID, etc.)
    external_anchor_at_ms       INTEGER,
    external_anchor_attempts    INTEGER NOT NULL DEFAULT 0
);

-- Chain truncations (rare). Append-only.
CREATE TABLE audit_chain_truncations (
    truncation_id                INTEGER PRIMARY KEY,
    truncated_at_ms              INTEGER NOT NULL,
    segment_id                   INTEGER NOT NULL,
    redacted_event_ids           BLOB    NOT NULL,             -- JSON array of redacted event UUIDs
    operator_id                  TEXT    NOT NULL,
    legal_basis                  TEXT    NOT NULL,             -- e.g., "GDPR Art. 17 request from data subject X dated Y"
    pre_truncation_segment_root  BLOB    NOT NULL,             -- the segment's Merkle root before redaction
    post_truncation_segment_root BLOB    NOT NULL,             -- the segment's new Merkle root after redaction
    chain_truncation_event_id    BLOB    NOT NULL,             -- reference to the ChainTruncation event in current chain
    archive_propagation_status   TEXT    NOT NULL CHECK (archive_propagation_status IN (
                                     'NotApplicable', 'Pending', 'Verified', 'Failed'
                                 )),
    archive_propagation_at_ms    INTEGER,
    operator_signature           BLOB    NOT NULL              -- signed under redaction_signing_key
);

CREATE INDEX idx_audit_chain_truncations_segment ON audit_chain_truncations (segment_id);
```

---

## 4. Audit Log Format: Linear Chain → Merkle Tree

### 4.1 The two-level Merkle structure

V3 organizes the audit log as a two-level Merkle tree:

```text
                            ┌──────────────────────────────┐
                            │  Inter-segment Merkle root   │
                            │  (signed in witnesses)        │
                            └──────────┬───────────────────┘
                                       │
                  ┌────────────────────┴────────────────────┐
                  │                                         │
          ┌───────┴────────┐                       ┌────────┴───────┐
          │  internal node │                       │  internal node │
          └───┬─────────┬──┘                       └───┬─────────┬──┘
              │         │                              │         │
       ┌──────┴──┐  ┌───┴───┐                   ┌──────┴──┐  ┌───┴───┐
       │  Seg 1  │  │ Seg 2 │  ...              │  Seg N-1│  │ Seg N │
       │  root   │  │ root  │                   │  root   │  │ root  │
       └────┬────┘  └───┬───┘                   └────┬────┘  └───┬───┘
            │           │                            │           │
        (within-segment Merkle trees, one per segment, leaves are events)
```

**Within-segment tree.** When a segment finalizes (rotation per `host-capacity.md §6.3`), the kernel computes a binary Merkle tree over the events in that segment. Each event is a leaf; pairs of leaves hash to internal nodes; the segment's Merkle root is the digest. The intermediate node hashes are persisted alongside the segment as `<segment_id>.merkle`. For a segment with K events, the within-segment tree has K-1 internal nodes (~32K extra bytes for SHA-256).

**Inter-segment tree.** Segment roots are leaves of a higher-level Merkle tree. Updated incrementally: when segment N+1's root is computed, it is inserted into the inter-segment tree, the affected internal nodes are recomputed, and the tree's root advances. The full inter-segment intermediate node set is persisted as `inter-segment.merkle`. For N segments, the inter-segment tree has N-1 internal nodes.

**Storage overhead is small.** For 1 million events averaging 1 KiB each (1 GB of raw audit data), the Merkle overhead is approximately:

- Within-segment trees: 1M events × 32 B/hash = 32 MiB
- Inter-segment tree: ~10K segments × 32 B/hash = 320 KiB

Total Merkle overhead is approximately 3% of raw audit data size. The benefit (O(log N) inclusion proofs without contiguous chain download) is structurally enormous for the cost.

### 4.2 Event format

Each event in V3 carries the within-segment leaf-position metadata needed to reconstruct its inclusion proof:

```rust
struct AuditEventV3 {
    // V2-compatible fields
    event_id:               Uuid,
    sequence_number:        u64,           // monotonic per segment
    timestamp_ms:           u64,
    event_kind:             AuditEventKind,
    payload:                Vec<u8>,       // bincode-encoded event-specific fields

    // V3 additions
    segment_id:             u64,
    leaf_index_in_segment:  u32,           // 0-based, monotonic within segment
    leaf_hash:              [u8; 32],      // SHA-256(event_id || sequence_number || timestamp_ms ||
                                           //          event_kind_tag || payload)
}
```

The leaf hash is computed deterministically and is the input to the within-segment Merkle tree. The previous-event hash from V2 is removed (the Merkle structure subsumes it). For backward compatibility, V3 readers can compute the V2-equivalent linear-chain hash on demand by traversing the in-order leaves; V2 readers cannot read V3 segments without the migration tool.

### 4.3 Segment finalization protocol (V3)

When the active segment reaches `audit_segment_size_mb` (per `host-capacity.md §6.3`), the kernel runs the V3 finalization protocol:

```text
state ActiveSegment(N):
    on event_appended(E):
        E.leaf_hash = compute_leaf_hash(E)
        write E to /var/lib/raxis/audit/{N:04}.log.active
        in-memory tree builder accumulates E
        if segment_size_mb >= audit_segment_size_mb:
            transition to FinalizingSegment(N)

state FinalizingSegment(N):
    1. Flush any in-memory event buffers to {N:04}.log.active.
    2. Compute within-segment Merkle root from accumulated leaves.
    3. Write within-segment intermediate hashes to {N:04}.merkle.tmp.
    4. fsync({N:04}.log.active), fsync({N:04}.merkle.tmp).
    5. SQLite Phase 1 (BEGIN IMMEDIATE):
         INSERT INTO audit_segment_archive_state (
             segment_id, finalized_at_ms, local_path,
             local_sha256, merkle_root, event_count
         ) VALUES (...);
       COMMIT.
    6. Atomic rename {N:04}.log.active → {N:04}.log; same for .merkle.tmp → .merkle.
    7. Insert segment root as leaf into inter-segment tree:
         a. Read current inter-segment.merkle.
         b. Append leaf for segment N's root.
         c. Recompute affected internal nodes (O(log N)).
         d. Write inter-segment.merkle.tmp; fsync; atomic rename.
    8. If sign_every_n_segments cadence reached OR sign_at_least_every_seconds
       elapsed since last witness: trigger witness signing per §7.
    9. Notify archiver:
         UDS send: AuditSegmentReady { segment_id: N, local_path, local_sha256, merkle_root }
         UPDATE audit_segment_archive_state SET archiver_notified_at_ms = now() WHERE segment_id = N.
    10. Open new active segment {(N+1):04}.log.active.
    11. transition to ActiveSegment(N+1).
```

The protocol is crash-safe: every disk-modifying step uses atomic rename, every SQLite-modifying step is transactional. On kernel restart, the recovery procedure (§4.4) reconstructs intermediate state.

### 4.4 Crash recovery during finalization

On kernel startup, the audit subsystem inspects the audit directory and SQLite state to reconcile any partial finalization:

| Observed state | Recovery action |
|---|---|
| `{N}.log.active` exists; no row in `audit_segment_archive_state` for N | Resume as ActiveSegment(N); appends continue. |
| `{N}.log.active` exists; row exists for N (Phase 5 committed but rename in step 6 didn't complete) | Re-run steps 6-11 of finalization; idempotent. |
| `{N}.log` exists; row exists; no `{N}.merkle` | Recompute Merkle tree from leaves; write `{N}.merkle`; verify root matches SQLite row's `merkle_root`; if mismatch, INV-AUDIT-RETENTION-03 violation: halt with `AuditChainCorrupted`. |
| `{N}.log` exists; row exists; `{N}.merkle` exists; no `archiver_notified_at_ms` | Re-notify archiver; idempotent (archiver dedupes by `segment_id`). |
| Inter-segment tree last update lags behind highest segment_id in `audit_segment_archive_state` | Replay inter-segment leaf insertions for missing segment roots in order. |

The recovery is designed to be idempotent: re-running the whole protocol produces the same on-disk state. Operators can `kill -9` the kernel during finalization without consequence beyond a brief recovery window on next startup.

### 4.5 V2 → V3 migration

The migration tool `raxis admin audit-migrate-to-v3` is run with the kernel offline:

```text
1. Validate the V2 linear chain end-to-end (full re-hash from segment 1 to current).
2. For each V2 segment {N}.log:
   a. Re-read events; compute V3 leaf hashes from event payloads.
   b. Compute the within-segment Merkle root.
   c. Write {N}.merkle; insert audit_segment_archive_state row.
3. Build the inter-segment tree by inserting segment roots in order.
4. Sign an initial V3 witness covering segments [1..highest_id].
5. Update policy.toml's audit_format from "v2_linear" to "v3_merkle"
   (validated; the kernel refuses to start in v3_merkle mode if the migration
   tool has not been run successfully).
6. The migration is recorded as a special audit event V3MigrationCompleted in
   the first V3 active segment.
```

Migration is one-way (V3 segments cannot be re-hashed back into V2 linear chain because the V3 leaf-hash format includes leaf_index_in_segment which V2 didn't compute). Operators run the tool once during a planned maintenance window.

---

## 5. Segment Lifecycle and Local Retention

### 5.1 Lifecycle states

A segment progresses through five states:

```text
   Active ──finalize──► Finalized ──archiver_notify──► PendingArchive
                                                            │
                                                            │ archiver ACKs
                                                            ▼
                                                       Archived
                                                            │
                                          local_retention_days expires
                                          AND archive verified
                                                            │
                                                            ▼
                                                    LocallyDeleted

  (RedactionPending state branches off Archived; see §9 for details.)
```

- **Active.** Open for appends. Exactly one active segment at any time.
- **Finalized.** Merkle root computed; SQLite row exists; on-disk files immutable; not yet pushed to archiver.
- **PendingArchive.** Archiver has been notified; awaiting `AuditSegmentArchived` ACK.
- **Archived.** Archiver has uploaded successfully and verified the roundtrip checksum; eligible for local deletion when retention expires.
- **LocallyDeleted.** Local files removed; row remains in `audit_segment_archive_state` with `locally_deleted_at_ms` set; segment is still retrievable via `raxis admin audit-restore` from the archive.

### 5.2 Eligibility for local deletion

A segment becomes eligible for local deletion only when both:

```text
finalized_at_ms + local_retention_days × 86_400_000 <= now_ms
AND
archive_verification_at_ms IS NOT NULL
```

The first condition enforces the retention window; the second ensures the archive copy is verified. Together they guarantee no audit data is lost even if the archiver is silently broken (it might ACK without actually uploading; the verification check catches that — see §6.4).

A periodic GC task (every 1 hour) scans `audit_segment_archive_state WHERE eligible_for_local_delete_at_ms <= now_ms AND locally_deleted_at_ms IS NULL`, deletes the local `.log` and `.merkle` files atomically (via rename-to-`.deleted`-then-unlink), and updates the row.

### 5.3 What if the archiver is silent?

If the archiver never ACKs (process down, misconfigured, network-isolated):

1. `archiver_notified_at_ms` is set; `archiver_acked_at_ms` remains NULL.
2. After `archiver_lag_alert_days` (default 7), the kernel emits `OperatorAttentionRequired { kind: ArchiverLagging, oldest_unacked_segment_id }`.
3. Segments accumulate locally; nothing is deleted.
4. Eventually `min_free_disk_mb` is breached; `host-capacity.md §7.6` halts admission per `INV-CAPACITY-04`.

This is the correct fail-closed behavior: a broken archiver does not silently lose audit data; it eventually halts the system, forcing operator intervention. The 7-day alert window gives operators significant lead time before disk pressure becomes critical.

### 5.4 What if `archiver_uds_path` is unset?

V2-compatible mode. The kernel does not notify any archiver; segments accumulate locally indefinitely; `local_retention_days` is ignored. The disk-full halt mechanism is the only retention bound. Useful for:

- V2 deployments upgraded to V3 binaries but not yet ready to deploy an archiver.
- Air-gapped deployments where there is no archive backend.
- Small deployments where unbounded local retention is acceptable.

The kernel emits a startup log line confirming "archiver disabled, V2-compatible retention behavior" so operators are not surprised.

---

## 6. The `raxis-archiver` Sidecar Protocol

### 6.1 IPC over UDS

The kernel and archiver communicate over a single Unix domain socket at `archiver_uds_path` (default `/var/run/raxis/archiver.sock`). The kernel is the client; the archiver is the server. Connection is established at kernel startup and re-established on disconnect with exponential backoff.

The wire format follows `peripherals.md §wire-format` (4-byte little-endian length prefix; bincode-encoded body). All messages are typed:

```rust
// Kernel → archiver
enum KernelToArchiver {
    AuditSegmentReady {
        segment_id:        u64,
        local_path:        PathBuf,         // archiver reads from this path
        local_sha256:      [u8; 32],
        merkle_root:       [u8; 32],
        event_count:       u32,
        finalized_at_ms:   u64,
    },
    RedactSegment {
        segment_id:           u64,
        new_local_path:       PathBuf,      // path to the redacted replacement segment
        new_local_sha256:     [u8; 32],
        new_merkle_root:      [u8; 32],
        chain_truncation_id:  u64,          // reference to the audit_chain_truncations row
    },
    PublishWitness {
        witness_id:        u64,
        local_witness_blob: Vec<u8>,        // signed witness, ready to publish
        external_anchor_backend: ExternalAnchorBackend,
    },
    Ping,                                    // heartbeat
}

// Archiver → kernel
enum ArchiverToKernel {
    AuditSegmentArchived {
        segment_id:                u64,
        archive_uri:               String,
        archive_sha256:            [u8; 32], // hash of the bytes uploaded; MUST equal local_sha256
        archive_verification_at_ms: u64,
    },
    AuditSegmentArchiveFailed {
        segment_id:        u64,
        error_kind:        ArchiveErrorKind, // BackendUnavailable, AuthFailure, ChecksumMismatch, ...
        error_message:     String,
        retry_after_ms:    Option<u64>,      // archiver hint to kernel (kernel doesn't drive retry; archiver does)
    },
    RedactionPropagated {
        segment_id:        u64,
        truncation_id:     u64,
        archive_uri:       String,           // new URI of redacted version
        archive_sha256:    [u8; 32],         // matches new_local_sha256
        propagated_at_ms:  u64,
    },
    RedactionPropagationFailed {
        segment_id:        u64,
        truncation_id:     u64,
        error_kind:        RedactionErrorKind, // BackendImmutable, BackendUnavailable, ...
        error_message:     String,
    },
    WitnessPublished {
        witness_id:                u64,
        external_anchor_ref:       String,   // backend-specific (Rekor entry UUID, etc.)
        external_anchor_at_ms:     u64,
    },
    WitnessPublicationFailed {
        witness_id:        u64,
        error_kind:        AnchorErrorKind,
        error_message:     String,
    },
    Pong,
}
```

### 6.2 Authentication via SO_PEERCRED

When the archiver connects, the kernel checks the peer's UID via `SO_PEERCRED` (Linux) or `LOCAL_PEERCRED` (BSD). The connection is accepted only if `peer_uid == archiver_uid` from `policy.toml`. There is no shared-secret or cryptographic authentication — the trust boundary is the local OS's process isolation. Any process running under `archiver_uid` is trusted to be the archiver; the operator is responsible for ensuring no other process runs under that UID.

If a connection arrives from any other UID, the kernel logs `SecurityViolation { kind: ArchiverAuthFailed, peer_uid }`, audits the rejection, and closes the socket. This is a hard fence — there is no fallback to "maybe it's a misconfiguration" interpretation.

### 6.3 At-least-once delivery and idempotency

`AuditSegmentReady`, `RedactSegment`, and `PublishWitness` are all idempotent on the archiver side. The archiver deduplicates by the `segment_id`, `truncation_id`, or `witness_id` in the message; receiving the same notification twice produces at most one upload (the second is a no-op or returns the cached ACK).

The kernel's queue of pending notifications is persisted in SQLite (the `audit_segment_archive_state` table itself acts as the durable queue: any row with `archiver_notified_at_ms IS NOT NULL AND archiver_acked_at_ms IS NULL` is a pending notification). On reconnect after archiver crash:

1. Kernel queries pending notifications.
2. Re-sends each as `AuditSegmentReady` over the new connection.
3. Archiver returns cached ACKs for already-completed uploads, performs uploads for the rest.

The kernel never blocks segment finalization on archiver throughput. Notifications are fire-and-forget; the kernel's segment-finalization step only enqueues the notification to the connection writer, then returns to ActiveSegment(N+1). Slow archiver = local disk fills = `host-capacity.md §7` halt.

### 6.4 Kernel-side ACK verification

When an `AuditSegmentArchived` ACK arrives, the kernel verifies:

```text
ack.archive_sha256 == row.local_sha256
```

If the hashes mismatch, the archiver's upload does not match the local segment bytes. The kernel:

1. Logs `SecurityViolation { kind: ArchiveCorruption, segment_id, expected_sha256, archiver_reported_sha256 }`.
2. Marks the row's `archiver_acked_at_ms` as NULL (rejects the ACK).
3. Re-notifies the archiver to retry.
4. After 3 consecutive checksum mismatches for the same segment, halts further notifications to the archiver and emits `OperatorAttentionRequired { kind: ArchiverChecksumMismatch }`.

Checksum mismatch is structurally distinct from the archiver self-reporting a failure (`AuditSegmentArchiveFailed`). The former indicates either silent backend corruption (very rare) or archiver malfunction (somewhat more common); the latter is a normal operational condition the archiver knows about (network outage, auth refresh needed, etc.).

### 6.5 Reference archiver implementation

RAXIS V3 ships a reference `raxis-archiver` daemon supporting:

- **S3-compatible backends** (AWS S3, Cloudflare R2, MinIO, etc.) via `aws-sdk-s3`.
- **Azure Blob Storage** via `azure_storage_blobs`.
- **Local filesystem mirroring** (write to a separate directory; useful for testing or for operators who NFS-mount their archive backend).
- **Rekor publication** for witnesses (when `external_anchor.backend = "rekor"`).

The reference archiver is documented as an example, not the canonical implementation. Operators with bespoke backends (institutional NAS, on-prem object stores, custom WORM filesystems) implement their own archiver against the documented UDS protocol. The protocol is stable (V3 commits to backward-compatible additions only), so custom archivers continue working across V3.x kernel releases.

### 6.6 Custom archiver requirements

A custom archiver MUST:

1. Authenticate as `archiver_uid` on UDS connection.
2. Handle every message kind in `KernelToArchiver`. Unknown messages MUST be ignored (forward compatibility); known messages MUST be processed.
3. Be idempotent: receiving the same `segment_id`/`truncation_id`/`witness_id` twice MUST produce at most one upload.
4. Verify roundtrip checksum after each upload and report it in the ACK.
5. If `redaction_enabled = true`, support `RedactSegment` operations. If the chosen archive backend physically cannot support redaction (immutable WORM tier), the archiver MUST report this in its startup handshake so the kernel can refuse `redaction_enabled = true` configurations.

A custom archiver MAY:

- Fan out to multiple backends (e.g., S3 + on-prem mirror). The kernel sees one ACK per segment regardless.
- Compress segments before upload (decompression must be transparent on `Restore`).
- Encrypt segments with a backend-side key (the kernel's audit data is plaintext within RAXIS's trust boundary; archive-side encryption is a separate concern).
- Implement custom retry policies, backoff strategies, and rate limiting against its backend.

---

## 7. Witnesses and External Anchoring

### 7.1 Witness format

A witness is a signed snapshot of the inter-segment Merkle root at a point in time:

```rust
struct Witness {
    witness_id:                 u64,
    signed_at_ms:               u64,
    last_segment_id:            u64,
    inter_segment_root:         [u8; 32],
    operating_key_fingerprint:  KeyFingerprint,
}

struct SignedWitness {
    witness:    Witness,
    signature:  Vec<u8>,                     // Ed25519 signature over bincode-encoded `Witness`
}
```

Witnesses are written to `local_witness_path` (default `/var/lib/raxis/audit/witnesses.log`) as length-prefixed `SignedWitness` records, append-only. Each witness is also inserted into the `audit_witnesses` SQLite table for fast lookup.

### 7.2 When witnesses are signed

- **Cadence-based:** every `sign_every_n_segments` (default 10) finalizations.
- **Time-based:** at least once every `sign_at_least_every_seconds` (default 3600) regardless of segment finalizations.
- **On kernel shutdown:** a final witness covers the last finalized segment, signed before the kernel exits cleanly (`SIGTERM`). This is best-effort; on `SIGKILL` no shutdown witness is written.
- **On operator request:** `raxis admin audit-witness-now` triggers an immediate witness signing.

The signing operation is fast (one Ed25519 signature, ~100 µs) and uses the kernel's `operating_key_ref` from `policy.toml`. If the operating key is compromised (`key-revocation.md §6`), all witnesses signed under that key are invalidated; the operator must rotate to a new operating key and re-sign a witness covering the affected range.

### 7.3 Local-only witnesses

By default, witnesses are written only to local disk. Verification trusts the kernel's operating key. This is sufficient for deployments where:

- The operator key is well-protected (HSM-backed, hardware token, etc.).
- The threat model does not include kernel-host compromise.
- The deployment is air-gapped (no external anchor available).

Local-only witnesses do NOT defend against an attacker who compromises the operating key; such an attacker can sign fraudulent witnesses to make rewritten history appear valid. For deployments needing defense against this threat, opt in to external anchoring.

### 7.4 External anchoring (opt-in)

When `external_anchor.enabled = true`, every signed witness is also published to the operator's chosen anchor service via the archiver:

1. Kernel signs the witness; writes to local file; INSERTs into `audit_witnesses`.
2. Kernel sends `PublishWitness` UDS message to archiver.
3. Archiver POSTs the signed witness to the anchor backend (Sigstore Rekor, internal CT log, custom HTTP endpoint).
4. Archiver receives a backend-specific acknowledgment (Rekor returns an entry UUID and Merkle inclusion proof; CT log returns an SCT; custom HTTP returns whatever the operator's endpoint provides).
5. Archiver reports `WitnessPublished { witness_id, external_anchor_ref, external_anchor_at_ms }` back to kernel.
6. Kernel updates `audit_witnesses` row with the anchor reference.

If publication fails (`WitnessPublicationFailed`), the archiver retries per its own backoff policy. The kernel does NOT block on publication; witnesses are valid locally as soon as signed, and external publication is an enhancement layered on top. Failed publications are tracked in `audit_witnesses.external_anchor_attempts`; after 10 failures, the kernel emits `OperatorAttentionRequired { kind: WitnessAnchorPublicationFailing }`.

### 7.5 Verification with external anchors

When `raxis admin audit-verify --witness <witness_id> --check-external-anchor` is run:

1. Kernel reads the local `SignedWitness`.
2. Verifies the signature under the (then-current) operating key.
3. Reads the `external_anchor_ref` from `audit_witnesses`.
4. Asks the archiver: "fetch this anchor entry from the backend."
5. Archiver retrieves the anchor record (Rekor entry, CT SCT, etc.).
6. Verifies the externally-anchored signed witness byte-for-byte matches the local copy.

A mismatch indicates either local tampering (an attacker modified the local witness file) or external-anchor tampering (Rekor was compromised, the CT log was forged). Both are catastrophic; the kernel emits `SecurityViolation { kind: WitnessAnchorMismatch }` and refuses to admit any new write-class intents until operator intervention.

### 7.6 Sigstore Rekor as the recommended default for opt-in

For operators choosing external anchoring, Sigstore Rekor is the recommended default backend because:

- Publicly-operated, Linux Foundation-hosted, free.
- Cryptographically auditable (Rekor is itself a transparency log with its own Merkle proofs).
- Standard Sigstore tooling (`cosign`, `rekor-cli`) for verification.
- Supports the same byte-blob → entry-UUID workflow we need.

Operators with regulatory concerns (data residency, government-only backends, etc.) may choose `ct_log` (their own Certificate Transparency-style log) or `http_post` (any backend they control). The archiver's backend module is replaceable; the kernel sees the same interface regardless.

---

## 8. Inclusion Proofs

### 8.1 What an inclusion proof is

An inclusion proof for Event X demonstrates, given:

- The event itself,
- A small set of intermediate hashes (the "Merkle path"),
- A signed witness covering the segment containing Event X,

...that Event X was logged exactly as shown, in the segment shown, at the position shown, and that the segment is part of the chain attested to by the witness.

The proof is `O(log N)` in size where N is the total number of events in the audit log: roughly `log₂(events_per_segment) + log₂(segments)` hashes.

### 8.2 Proof generation

```bash
$ raxis admin audit-prove --event-id <uuid> > proof.bin
```

The kernel:

1. Looks up the event via `inference_attempts` or other indexed views to find `(segment_id, leaf_index_in_segment)`.
2. Loads the event from `{segment_id}.log`.
3. Loads `{segment_id}.merkle` to construct the within-segment Merkle path from the leaf to the segment root.
4. Loads `inter-segment.merkle` to construct the inter-segment Merkle path from the segment root to the inter-segment root.
5. Loads the most recent witness covering `segment_id` from `audit_witnesses`.
6. Bundles into a self-contained proof:

```rust
struct InclusionProof {
    event:                          AuditEventV3,
    within_segment_path:            Vec<MerklePathElement>,
    segment_root:                   [u8; 32],
    inter_segment_path:             Vec<MerklePathElement>,
    inter_segment_root:             [u8; 32],
    witness:                        SignedWitness,
    witness_external_anchor:        Option<ExternalAnchorReference>,
}

struct MerklePathElement {
    sibling_hash:       [u8; 32],
    sibling_position:   Side,                // Left | Right
}
```

### 8.3 Proof verification

`raxis admin audit-verify-proof --proof proof.bin --operating-key <fingerprint>` (or any standalone tool implementing the V3 proof format) verifies:

1. Recompute Event's leaf hash from its content.
2. Walk `within_segment_path`: at each step, hash sibling appropriately to derive the parent. Final result must equal `segment_root`.
3. Walk `inter_segment_path`: similar, ending at `inter_segment_root`.
4. Verify `witness.signature` over `witness.witness` (the unsigned struct) using the operator's public key matching `operating_key_fingerprint`.
5. Verify `witness.witness.inter_segment_root == inter_segment_root`.
6. If `witness_external_anchor` is present, fetch the anchor record from the backend and verify it matches the local witness byte-for-byte.

A successful proof verification is mathematically conclusive: Event X was logged in segment S at position P, and the witness signed at time T covers it. No download of segments other than the proof itself is required.

### 8.4 Use cases

- **Legal evidence.** "Your honor, RAXIS event UUID `c4f7a8b2...` is the operator's approval of this commit; here is its inclusion proof signed under the operator's well-known public key, with external anchor in Sigstore Rekor entry `12340987...`. The operator cannot deny this event without invalidating either the operating key signature or the Rekor entry."
- **Regulatory review.** Auditors can verify specific events without being granted access to the full audit log (preserving privacy of unrelated audit data).
- **Supply-chain attestation.** A built artifact's inclusion proof in the audit log provides cryptographic evidence of its provenance through the RAXIS pipeline.
- **Selective forensic disclosure.** Investigators can verify a subset of events relevant to an incident without burdening the operator with full-log disclosure.

### 8.5 Proof of non-inclusion (intentionally not in V3)

V3 does NOT support proofs of non-inclusion (proofs that a specific event was NOT logged). Doing so requires either a sorted log (so neighbors of the absent slot can be shown) or a different data structure (e.g., sparse Merkle tree). Both add significant complexity and have unclear use cases for RAXIS — operators investigating "what didn't happen" typically iterate over what DID happen for a time range, not query specific absences. V4 may revisit if operational data warrants.

---

## 9. GDPR Right-to-Erasure: Chain Truncation with Signed Attestation

### 9.1 The principle

Per Critique #2, the audit log's hash-chain structure forbids retroactive mutation of events. A genuine erasure of personal data (as required by GDPR Art. 17, CCPA right-to-delete, etc.) therefore must:

1. Physically delete the bytes containing the personal data.
2. Re-compute the affected segment's Merkle root.
3. Acknowledge that the chain is broken at that segment.
4. Create a signed `ChainTruncation` event in the current active segment attesting to the redaction (legal basis, operator, timestamp, redacted event UUIDs, pre-/post-truncation roots).
5. Propagate the redaction to all archived copies.

The result: the chain is mathematically discontinuous at the truncation point, but the discontinuity is itself a signed, attested, audit-logged event — forensically far more valuable than a missing or fraudulent record.

### 9.2 Per-event redaction granularity (Tension #3)

The redaction tool operates per-event. The operator identifies specific event UUIDs to redact:

```bash
$ raxis admin redact \
    --event-ids c4f7a8b2-1234,7c9e3f1d-5678 \
    --legal-basis "GDPR Art. 17 request from data subject Jane Doe dated 2026-04-15, ticket DPO-2026-0047" \
    --signing-key redaction-2026-q1 \
    --confirm-i-understand-this-breaks-the-chain
```

Per-event redaction is the sweet spot identified in our design discussion:

- **Segment-level** (entire segment redacted): destroys too much innocent data; one PII reference erases potentially thousands of unrelated events in the same segment.
- **Field-level** (specific fields within events redacted): requires the kernel to parse arbitrary JSON schemas during redaction tool runs, introducing a new dependency surface and version-skew issues with the event schema.
- **Per-event** (entire events redacted): surgical enough to preserve most innocent data, simple enough to implement without parsing event payloads.

If a redaction would inadvertently expose the redacted PII through reference (e.g., another event references the redacted event by UUID), the operator must include the referencing events in the redaction set. The tool warns when a target event is referenced by other events but does not auto-include them — operator judgment is required.

### 9.3 The redaction protocol

```sql
1. Pre-flight checks:
   - redaction_enabled == true in policy.toml; else FAIL_REDACTION_DISABLED.
   - redaction_signing_key_ref valid in immutable artifact store; key trust state == Trusted.
   - Operator identity verified (CLI requires authenticated operator session).
   - If require_archive_compatibility == true: verify archiver supports RedactSegment
     for current backend; else FAIL_BACKEND_IMMUTABLE.
   - All event_ids resolve to existing events; all are in segments older than
     the active segment (cannot redact in-flight active segment).
   - Group event_ids by segment_id; one redaction operation may span multiple segments.

2. Per-segment redaction (one transactional unit per segment):

   2a. SQLite Phase 1 (BEGIN IMMEDIATE):
       INSERT INTO audit_chain_truncations (
           segment_id, redacted_event_ids, operator_id, legal_basis,
           pre_truncation_segment_root, archive_propagation_status, ...
       ) VALUES (..., 'NotApplicable' or 'Pending', ...);
       INSERT a ChainTruncation audit event into the current active segment with
           reference to the truncation_id.
       UPDATE audit_segment_archive_state SET redacted_at_ms = now()
           WHERE segment_id = <target>;
       COMMIT.

   2b. Filesystem work:
       Read {target}.log; write {target}.log.redacted with the specified events removed.
       Recompute within-segment Merkle tree over the remaining leaves.
       Write {target}.merkle.redacted.
       fsync both.
       Atomic rename: {target}.log → {target}.log.pre-redact-{truncation_id};
                      {target}.log.redacted → {target}.log;
                      same for .merkle files.

   2c. SQLite Phase 2 (BEGIN IMMEDIATE):
       UPDATE audit_segment_archive_state SET local_sha256 = <new>, merkle_root = <new>
           WHERE segment_id = <target>;
       UPDATE audit_chain_truncations SET post_truncation_segment_root = <new>
           WHERE truncation_id = <id>;
       COMMIT.

   2d. Inter-segment tree update:
       The {target} segment's leaf in the inter-segment tree changes hash.
       Recompute affected internal nodes; write inter-segment.merkle.tmp; rename.

   2e. If archive_propagation required (archiver_uds_path set, archive exists):
       Send RedactSegment { segment_id, new_local_path, new_local_sha256, new_merkle_root, truncation_id }
       to archiver.
       Archiver reports back via RedactionPropagated or RedactionPropagationFailed.
       Update archive_propagation_status accordingly.

3. Sign a fresh witness over the new inter-segment root (per §7).

4. Delete {target}.log.pre-redact-{truncation_id} files only after archive_propagation_status
   is 'Verified' or 'NotApplicable'. (Held until verified so the operator can roll back the
   redaction if archive propagation fails — see §9.5.)
```

### 9.4 The `ChainTruncation` event format

```rust
AuditEventKind::ChainTruncation {
    truncation_id:                 u64,
    segment_id:                    u64,
    redacted_event_ids:            Vec<Uuid>,
    operator_id:                   String,
    legal_basis:                   String,
    pre_truncation_segment_root:   [u8; 32],
    post_truncation_segment_root:  [u8; 32],
    operator_signature:            Vec<u8>,        // signed under redaction_signing_key
    truncated_at_ms:               u64,
}
```

The event lives in the current active segment (a forward-going part of the chain), so it is itself part of a continuous Merkle structure from the truncation point onward. Forensic reviewers traversing the audit log encounter this event when they reach segment `<current_active>` and learn:

- A redaction occurred;
- Which events were redacted (by UUID, not content);
- Why (legal basis);
- Who authorized it;
- What the segment's Merkle root was before and after.

The pre-truncation root cannot be used to verify pre-redaction events (those events are gone), but it CAN be used to verify other audit data: any inclusion proof issued before the redaction date that referenced `pre_truncation_segment_root` remains independently verifiable against this on-record value.

### 9.5 Archive propagation

When the operator's archive backend supports the operation, the redacted segment's bytes are re-uploaded to replace the original in the archive. The archiver's `RedactionPropagated` ACK carries the new archive checksum, which the kernel verifies matches the local redacted segment.

When the archive backend physically forbids the operation (S3 Object Lock in Compliance mode, write-once filesystems, etc.), the operator faces a binary choice at deployment time:

- **`require_archive_compatibility = true` (default):** the redaction tool refuses to run if the backend is immutable. The operator must either choose a writable backend or accept that GDPR right-to-erasure compliance is not possible for this deployment.
- **`require_archive_compatibility = false`:** the redaction tool runs locally but the archive copy is never updated. The redacted PII remains in the archive forever. This is a knowingly-noncompliant configuration; it is logged at startup as `OperatorAttentionRequired { kind: GdprRedactionWillNotPropagateToArchive }`.

This is a fundamental tension between two legitimate compliance regimes (data immutability and right-to-erasure), and there is no technical solution that makes both work simultaneously. RAXIS's role is to surface the tension explicitly at configuration time, not to pretend it doesn't exist.

### 9.6 Verification in the presence of truncations

Inclusion proofs for events in non-redacted segments work normally. For events in segments containing redactions:

- **Verifying a redacted event:** impossible; the event is gone. Attempting `raxis admin audit-prove --event-id <redacted>` returns `FAIL_EVENT_REDACTED { truncation_id }` with a pointer to the `ChainTruncation` event.
- **Verifying a non-redacted event in a redacted segment:** the proof works, but uses the post-truncation segment root. The witness used to anchor the proof must be one signed AFTER the redaction (witnesses signed before the redaction reference the pre-truncation root and fail verification).

The CLI explicitly surfaces this in proof output:

```text
Inclusion proof for event 7c9e3f1d-5678:
  Segment 4242 was redacted on 2026-04-15 (truncation_id 17).
  Pre-truncation root: a3f9b2c1...
  Post-truncation root: b4c8d9e2...
  This proof uses the post-truncation root, anchored in witness #189
    signed at 2026-04-15T10:32Z (post-redaction).
  ✓ Proof valid.
```

### 9.7 Cumulative redactions

Multiple redactions over time produce multiple `ChainTruncation` events, each with its own pre/post root for its specific segment. The audit log accumulates an honest record of every redaction.

The forensic story for a 2-year-old segment that was redacted twice (once for each of two GDPR requests): there are two `ChainTruncation` events in the audit log referencing that segment; the operator's redaction signing key authorized both; the segment's current Merkle root reflects both; non-redacted events in that segment can still be verified via post-second-redaction proofs.

---

## 10. Indexed View Retention

### 10.1 The distinction

The raw audit log (per `host-capacity.md §6.3`, this spec's §4) is the forensic source of truth: append-only, Merkle-chained, signed, archived. Some queries against it would be expensive (full segment scans for "all inference attempts in the last 30 days").

For operational use, RAXIS maintains SQLite-side indexed views: materialized projections of selected audit data into queryable tables. The most prominent in V2/V3:

- `inference_attempts` (per `provider-failure-handling.md §6.5`)
- `admission_queue` (per `host-capacity.md`)
- `provider_circuit_state` (per `provider-failure-handling.md §6.4`; though this is current-state, not history, so retention doesn't apply)
- `breaker_state_history` (per `provider-failure-handling.md`; the audit-event timeline projected to a queryable table)
- `operator_attention_log` (a projection of `OperatorAttentionRequired` events)

### 10.2 Independent retention

Indexed view retention is INDEPENDENT of audit log retention. Operators may keep 90 days of `inference_attempts` in SQLite for fast querying while retaining the underlying audit data for 7 years in the archive. When the operator queries "what were our inference attempts on 2024-03-15?", the workflow is:

- If 2024-03-15 is within `inference_attempts_days` retention: query SQLite directly. Fast.
- Otherwise: query the archive for the relevant segments; reconstruct via the per-event audit records. Slow but always available.

This makes the operator's choice operational, not data-availability: how much SQLite disk and query speed do they want to trade for older operational queries? The forensic record is unaffected.

### 10.3 GC mechanism

A periodic task (every 6 hours) runs:

```sql
DELETE FROM inference_attempts
 WHERE completed_at_ms < (now_ms - inference_attempts_days * 86_400_000);

DELETE FROM admission_queue
 WHERE queued_at_ms < (now_ms - admission_queue_days * 86_400_000)
   AND admitted_at_ms IS NOT NULL;     -- never delete unfinished queue entries

DELETE FROM breaker_state_history
 WHERE state_change_at_ms < (now_ms - breaker_state_history_days * 86_400_000);

DELETE FROM operator_attention_log
 WHERE created_at_ms < (now_ms - operator_attention_days * 86_400_000)
   AND resolved_at_ms IS NOT NULL;     -- never delete unresolved attention events
```

Each DELETE is wrapped in its own transaction with an audit event recording the count deleted and the cutoff timestamp. The audit event is itself in the audit log, so future readers can reconstruct what was once in the index.

---

## 11. Verification and Restoration CLI

### 11.1 Verification commands

```bash
# Verify a single segment's internal Merkle structure.
$ raxis admin audit-verify --segment 4242
Verifying segment 4242 (5,432 events)...
  ✓ Within-segment Merkle root matches stored value.
  ✓ All event leaf hashes match recomputed values.
  ✓ Segment file SHA-256 matches archive_state.local_sha256.
Segment 4242 OK.

# Verify a contiguous range.
$ raxis admin audit-verify --range 4000..4500
Verifying segments 4000-4500 (501 segments)...
  ✓ All within-segment roots verified.
  ✓ Inter-segment Merkle path 4000→4500 consistent.
Range OK.

# Verify against witnesses (fast — does not re-hash events; just witness signatures).
$ raxis admin audit-verify --witness-only
Loading witnesses.log (327 witnesses since deployment)...
  ✓ All witness signatures verified under known operating keys.
  ✓ Inter-segment root chain consistent across witness intervals.
Witness chain OK.

# Verify an inclusion proof generated by audit-prove.
$ raxis admin audit-verify-proof --proof proof.bin
Loading proof.bin...
  Event UUID:           c4f7a8b2-1234-...
  Segment:              4242, leaf 1738
  Witness:              #189 signed 2026-04-15T10:32Z
  External anchor:      Sigstore Rekor entry 0x12340987... (verified)
  ✓ Within-segment Merkle path valid.
  ✓ Inter-segment Merkle path valid.
  ✓ Witness signature verified.
  ✓ External anchor matches local witness.
Proof valid.
```

### 11.2 Restoration commands

```bash
# Restore segment(s) from archive to local disk for forensic review.
$ raxis admin audit-restore --segment 4242
Requesting segment 4242 from archiver...
  Archive backend: s3://raxis-audit-prod/host-1/0004242.log
  Downloading: 234 MB
  Verifying SHA-256: ✓
  Verifying Merkle root: ✓
Segment 4242 restored to /var/lib/raxis/audit-restored/0004242.log

$ raxis admin audit-restore --range 4000..4010
Requesting 11 segments from archiver...
  ...
All segments restored to /var/lib/raxis/audit-restored/.

# Restored segments are read-only; they don't re-enter the live audit chain.
# Operators inspect them with raxis admin audit-inspect --segment <N> --from-restored.
```

### 11.3 Redaction commands

```bash
$ raxis admin redact \
    --event-ids c4f7a8b2-1234,7c9e3f1d-5678 \
    --legal-basis "GDPR Art. 17 request from data subject Jane Doe dated 2026-04-15, ticket DPO-2026-0047" \
    --signing-key redaction-2026-q1
PRE-FLIGHT CHECKS
  ✓ redaction_enabled = true
  ✓ Signing key 'redaction-2026-q1' trust state: Trusted
  ✓ Archiver supports RedactSegment for backend: s3 (Object Lock disabled)
  ✓ All 2 event IDs resolved
    - c4f7a8b2-1234 in segment 4042
    - 7c9e3f1d-5678 in segment 4042
  ✓ Both events in same segment 4042 (one truncation_id will be created)
  ⚠ WARNING: event 7c9e3f1d-5678 is referenced by 3 other events:
      - 8ab12c34-... in segment 4045
      - 9bc23d45-... in segment 4047
      - acdef012-... in segment 4051
    These referencing events will remain after redaction; their references
    will point to a now-redacted event. Continue? [y/N]
  > y

EXECUTION
  Phase 1 (SQLite intent commit):
    - Created truncation_id 17
    - ChainTruncation event 9b8a7c6d... appended to active segment 4823
  Phase 2 (filesystem work):
    - Rewrote 0004042.log: 5432 → 5430 events
    - Recomputed within-segment Merkle root: a3f9b2... → b4c8d9...
    - Renamed 0004042.log.pre-redact-17 (kept until archive propagation verified)
  Phase 3 (SQLite finalize):
    - Updated audit_segment_archive_state.merkle_root for segment 4042
  Phase 4 (inter-segment tree update):
    - Recomputed inter-segment Merkle root: c5d6e7f8... → d6e7f8a9...
  Phase 5 (sign fresh witness #190 over new root)
  Phase 6 (notify archiver to propagate redaction to s3):
    - RedactSegment sent
    - Awaiting RedactionPropagated ACK...
    - ACK received; archive_propagation_status = Verified
  Phase 7 (delete 0004042.log.pre-redact-17): done.

REDACTION COMPLETE
  Truncation ID:           17
  ChainTruncation event:   9b8a7c6d-...-...
  Segments affected:       1 (segment 4042)
  Events redacted:         2
  Pre-truncation root:     a3f9b2c1...
  Post-truncation root:    b4c8d9e2...
  Operator signature:      verified under redaction-2026-q1
  Archive propagation:     verified
```

### 11.4 Witness commands

```bash
# Sign a witness immediately (e.g., before a backup snapshot).
$ raxis admin audit-witness-now
Signing witness #191 covering segments [1..4823]...
  inter_segment_root:        d6e7f8a9...
  operating_key_fingerprint: SHA256:abcd...
  ✓ Signature written to witnesses.log
  ✓ Inserted into audit_witnesses (witness_id 191)
  External anchor (rekor): publishing...
  ✓ Rekor entry: 0x67890abc... at 2026-05-04T16:22:13Z
Witness #191 signed and anchored.

# List witnesses.
$ raxis admin audit-witness list
ID    SIGNED_AT             COVERS SEGMENTS  ANCHOR
189   2026-04-15T10:32Z     1..4805          rekor:0x12340987...
190   2026-04-15T10:33Z     1..4805 (post-redact 17)  rekor:0x23451098...
191   2026-05-04T16:22Z     1..4823          rekor:0x67890abc...
```

### 11.5 Migration command

```bash
# One-time V2 → V3 migration (kernel offline).
$ raxis admin audit-migrate-to-v3 --confirm
Validating V2 linear chain...
  ✓ Chain valid: 4823 segments, 18,432,109 events.
Building V3 Merkle structures...
  Segment 1: building within-segment tree (5,201 events)... ✓
  Segment 2: building within-segment tree (4,892 events)... ✓
  ...
  Segment 4823: building within-segment tree (3,217 events)... ✓
  Building inter-segment tree (4,823 leaves)... ✓
  Inter-segment root: d6e7f8a9...
Signing initial V3 witness #1...
  ✓ Witness signed under operating key SHA256:abcd...
  ✓ Inserted into audit_witnesses
Updating policy.toml audit_format = "v3_merkle"... ✓
Recording V3MigrationCompleted event in next active segment... ✓
Migration complete. The kernel can now start in V3 mode.
```

---

## 12. Invariants

### INV-AUDIT-RETENTION-01 — Kernel does not perform WAN egress for audit purposes

The kernel's network egress is strictly bounded to `git push` per `INV-CRED-KERNEL-01`. All audit archive uploads, witness publications, and external anchor postings are performed by `raxis-archiver` over WAN; the kernel only communicates with the archiver via local UDS.

**Where:** §2 architecture; §6 archiver protocol; §7.4 external anchoring.

**Scenario it prevents:** A memory-safety vulnerability in the AWS S3 SDK or Azure Blob client would compromise the most-privileged process in the system. By keeping WAN egress out of the kernel address space, such vulnerabilities affect only the unprivileged archiver process, which can do far less damage (it can corrupt or fail to upload audit data, but it cannot mutate kernel state, forge audit events, or grant itself credentials).

### INV-AUDIT-RETENTION-02 — Local segment deletion requires verified archiver ACK

A segment row's `locally_deleted_at_ms` may be set ONLY after both `local_retention_days` has elapsed since `finalized_at_ms` AND `archive_verification_at_ms IS NOT NULL`. The verification check requires `archiver_reported_sha256 == local_sha256`.

**Where:** §5.2 eligibility; §6.4 ACK verification.

**Scenario it prevents:** A misbehaving or compromised archiver could ACK without uploading, or ACK with a different file's checksum. Without INV-AUDIT-RETENTION-02, the kernel would delete local segments believing they were safely archived; in fact the archive copy would be missing or corrupted. The checksum-equality requirement gates local deletion on cryptographic proof of correct archive.

### INV-AUDIT-RETENTION-03 — Two-level Merkle tree integrity

For every finalized segment, the within-segment Merkle root in `audit_segment_archive_state.merkle_root` MUST equal the root computed by hashing the segment's events in order. The inter-segment Merkle root MUST equal the root computed by aggregating segment roots in `segment_id` order.

**Where:** §4.1, §4.3 finalization; §4.4 crash recovery.

**Scenario it prevents:** A bug in the Merkle tree update logic could leave the inter-segment tree out of sync with the segment it covers. INV-AUDIT-RETENTION-03 makes the kernel detect this on next verification or startup recovery and halt with `AuditChainCorrupted` rather than silently issuing inclusion proofs that don't actually verify against the witness root.

### INV-AUDIT-RETENTION-04 — Witnesses are signed and durably recorded

Every witness MUST be signed under the operating key, written to `local_witness_path`, and INSERTed into `audit_witnesses` BEFORE being acknowledged as a valid anchor. External anchor publication (when enabled) is best-effort and asynchronous; failure to publish does not invalidate the local witness.

**Where:** §7.2 signing; §7.3 local-only; §7.4 external anchoring.

**Scenario it prevents:** A witness signed in memory but never written to disk could be lost on kernel crash, leaving a window of audit history unanchored. Conversely, a witness published externally before being signed locally could create a discrepancy between Rekor's record and what the kernel believes it signed. INV-AUDIT-RETENTION-04 enforces the order: sign locally, write locally, then publish externally.

### INV-AUDIT-RETENTION-05 — Inclusion proofs are O(log N) and self-contained

A valid inclusion proof for any event must verify using only: the proof's contained data, the operating key's public key matching the proof's witness, and (optionally) one fetch from the external anchor backend. Verification MUST NOT require downloading any audit segment beyond the one containing the proven event.

**Where:** §8.1, §8.2 proof generation; §8.3 verification.

**Scenario it prevents:** A regression in the proof format (e.g., omitting necessary intermediate hashes from the proof) would force verifiers to download additional segments to fill the gap. INV-AUDIT-RETENTION-05 makes O(log N) self-containment a structural property of the proof format; any verifier seeing a proof that requires additional fetches knows the proof is malformed.

### INV-AUDIT-RETENTION-06 — Redaction creates a signed `ChainTruncation` attestation

Every redaction operation MUST produce: (a) physical deletion of the redacted event bytes, (b) recomputation of the affected segment's Merkle root, (c) a `ChainTruncation` event in the current active segment signed under the `redaction_signing_key`, (d) a fresh witness signed over the new inter-segment root. The redaction is only complete when all four are committed.

**Where:** §9.3 protocol; §9.4 event format.

**Scenario it prevents:** A redaction that deletes bytes without producing a `ChainTruncation` event leaves the audit log in a state where a future verifier sees the chain break with no explanation; this is operationally indistinguishable from tampering. INV-AUDIT-RETENTION-06 makes the chain break itself a forensically valuable, signed, time-stamped event.

### INV-AUDIT-RETENTION-07 — Archive propagation is operator-acknowledged

When `redaction_enabled = true` AND `require_archive_compatibility = true`, redaction MAY proceed only if the archiver confirms the backend supports `RedactSegment`. When `require_archive_compatibility = false`, the kernel emits `OperatorAttentionRequired { kind: GdprRedactionWillNotPropagateToArchive }` at startup and on every redaction attempt, ensuring the operator is repeatedly reminded that local redactions do not propagate to the archive.

**Where:** §9.5 archive propagation; configuration §3.1 `require_archive_compatibility`.

**Scenario it prevents:** An operator unknowingly deploys with an immutable archive backend (S3 Object Lock Compliance mode) and runs a redaction; the local segment is redacted but the archive copy is not; the operator believes they are GDPR-compliant but the personal data persists in cold storage indefinitely. INV-AUDIT-RETENTION-07 forces the operator to confront the immutability/erasability tension explicitly at configuration time.

### INV-AUDIT-RETENTION-08 — Indexed view retention is independent of audit log retention

Deletions from indexed-view tables (`inference_attempts`, `admission_queue`, `breaker_state_history`, `operator_attention_log`) are SQLite operations that do NOT modify, redact, or otherwise affect the raw audit log. The audit log remains the forensic source of truth at all times; indexed views are operational projections.

**Where:** §10.1 distinction; §10.3 GC mechanism.

**Scenario it prevents:** An operator running `inference_attempts_days = 30` might believe they have "30-day retention" of inference data, then be surprised when a forensic investigation requires data from 90 days ago that was archived but not in the index. INV-AUDIT-RETENTION-08 makes the distinction unambiguous: indexed views are throwaway operational caches; the audit log is forever (or until explicitly redacted).

### INV-AUDIT-RETENTION-09 — Archiver authentication is filesystem-derived

The kernel accepts archiver UDS connections only from peers whose UID matches `archiver_uid` per `SO_PEERCRED`. There is no shared-secret, cryptographic, or key-based authentication. Trust is derived solely from the operating system's process-isolation guarantees.

**Where:** §6.2 authentication.

**Scenario it prevents:** An attacker compromising any process running as a different UID on the kernel host cannot impersonate the archiver. The single point of trust is "the OS correctly attributes UIDs to socket peers" — a property the operating system guarantees as a foundational primitive. Adding cryptographic authentication on top would be redundant complexity that doesn't strengthen the trust boundary.

---

## 13. Implementation Checklist

### Schema (V3 migration)

- [ ] Create `audit_segment_archive_state` table per §3.2 with appropriate indexes
- [ ] Create `audit_witnesses` table per §3.2
- [ ] Create `audit_chain_truncations` table per §3.2
- [ ] Add `audit_format` column to deployment metadata; default to `v2_linear` for V2-upgraded deployments

### `policy.toml` parser

- [ ] Parse `[audit_retention]`, `[audit_retention.merkle]`, `[audit_retention.witnesses]`, `[audit_retention.witnesses.external_anchor.*]`, `[audit_retention.indexed_views]`, `[audit_retention.gdpr]`
- [ ] Validate `audit_format ∈ {"v2_linear", "v3_merkle"}`
- [ ] Validate `local_retention_days >= 1` (zero would mean immediate deletion; nonsensical)
- [ ] Validate `sign_every_n_segments >= 1`, `sign_at_least_every_seconds >= 60`
- [ ] If `external_anchor.enabled`: validate `backend ∈ {"rekor", "ct_log", "http_post"}` and matching sub-section present
- [ ] If `redaction_enabled = true`: validate `redaction_signing_key_ref` non-empty and key present in artifact store; require `operating_key_ref != redaction_signing_key_ref` (separation of duties)
- [ ] Validate the kernel can locate `archiver_uds_path`'s parent directory (must exist; permissions must be 0700)

### `kernel/src/audit/`

- [ ] `kernel/src/audit/v3/leaf.rs`: V3 event format with `leaf_index_in_segment` and `leaf_hash` per §4.2
- [ ] `kernel/src/audit/v3/within_segment_tree.rs`: in-memory tree builder; finalization writes `<N>.merkle`
- [ ] `kernel/src/audit/v3/inter_segment_tree.rs`: incremental tree maintenance; persistence to `inter-segment.merkle`
- [ ] `kernel/src/audit/v3/finalization.rs`: 11-step finalization protocol per §4.3 with crash-safe atomic renames
- [ ] `kernel/src/audit/v3/recovery.rs`: startup reconciliation per §4.4
- [ ] `kernel/src/audit/v3/witness.rs`: witness signing per §7.2; integration with operating key from `key-revocation.md`
- [ ] `kernel/src/audit/v3/proof.rs`: inclusion proof generation per §8.2 and verification per §8.3
- [ ] `kernel/src/audit/v3/migration.rs`: one-time V2 → V3 conversion per §4.5

### `kernel/src/archiver/`

- [ ] `kernel/src/archiver/protocol.rs`: `KernelToArchiver` and `ArchiverToKernel` enums; bincode wire format per §6.1
- [ ] `kernel/src/archiver/connection.rs`: UDS client; `SO_PEERCRED` verification per §6.2; reconnect with backoff
- [ ] `kernel/src/archiver/dispatcher.rs`: persists pending notifications via `audit_segment_archive_state`; resends on reconnect
- [ ] `kernel/src/archiver/ack_handler.rs`: validates `archive_sha256 == local_sha256` per §6.4; SecurityViolation on mismatch
- [ ] `kernel/src/archiver/lag_monitor.rs`: emits `OperatorAttentionRequired { ArchiverLagging }` per §5.3 after `archiver_lag_alert_days`

### `kernel/src/segment_lifecycle/`

- [ ] `kernel/src/segment_lifecycle/gc.rs`: hourly task scanning eligibility; atomic local deletion; audit event for each deletion
- [ ] `kernel/src/segment_lifecycle/restore.rs`: `audit-restore` CLI handler; archiver restore protocol; verification before exposing restored files

### `kernel/src/redaction/`

- [ ] `kernel/src/redaction/preflight.rs`: pre-flight checks per §9.3 step 1
- [ ] `kernel/src/redaction/per_segment.rs`: 7-phase per-segment redaction per §9.3
- [ ] `kernel/src/redaction/chain_truncation_event.rs`: `ChainTruncation` event construction and signing per §9.4
- [ ] `kernel/src/redaction/archive_propagation.rs`: `RedactSegment` dispatch and ACK handling per §9.5

### `kernel/src/indexed_views/`

- [ ] `kernel/src/indexed_views/gc.rs`: 6-hour periodic task per §10.3; per-view DELETE with audit event recording counts and cutoffs

### Reference `raxis-archiver` daemon

- [ ] `crates/archiver/src/main.rs`: UDS server; protocol implementation; lifecycle (startup, signal handling, graceful shutdown)
- [ ] `crates/archiver/src/backends/s3.rs`: S3 / Glacier upload with multipart, roundtrip checksum verification, IAM credential refresh
- [ ] `crates/archiver/src/backends/azure.rs`: Azure Blob Storage equivalent
- [ ] `crates/archiver/src/backends/local_mirror.rs`: write segments to a configured local directory (testing / NFS mounts)
- [ ] `crates/archiver/src/anchor/rekor.rs`: Sigstore Rekor publication for witnesses
- [ ] `crates/archiver/src/anchor/ct_log.rs`: Certificate Transparency log publication
- [ ] `crates/archiver/src/anchor/http_post.rs`: generic HTTP POST anchor
- [ ] `crates/archiver/src/redact_segment.rs`: handle `RedactSegment` (re-upload replacement); emit immutability error for unsupported backends
- [ ] `crates/archiver/src/persistence.rs`: archiver-side bookkeeping (which segments uploaded, where, with what checksum)

### Audit events

- [ ] `AuditSegmentFinalized { segment_id, event_count, merkle_root, finalized_at_ms }`
- [ ] `AuditSegmentArchived { segment_id, archive_uri, archive_sha256, verified_at_ms }`
- [ ] `AuditSegmentLocallyDeleted { segment_id, deleted_at_ms }`
- [ ] `AuditSegmentArchiveFailed { segment_id, error_kind, error_message }`
- [ ] `WitnessSigned { witness_id, last_segment_id, inter_segment_root, operating_key_fingerprint }`
- [ ] `WitnessExternallyAnchored { witness_id, backend, external_anchor_ref, anchored_at_ms }`
- [ ] `WitnessAnchorPublicationFailed { witness_id, attempts, error_kind }`
- [ ] `ChainTruncation { truncation_id, segment_id, redacted_event_ids, operator_id, legal_basis, pre_truncation_segment_root, post_truncation_segment_root, operator_signature, truncated_at_ms }`
- [ ] `RedactionPropagated { truncation_id, segment_id, archive_uri, archive_sha256, propagated_at_ms }`
- [ ] `RedactionPropagationFailed { truncation_id, segment_id, error_kind }`
- [ ] `IndexedViewGarbageCollected { view_name, rows_deleted, cutoff_at_ms }`
- [ ] `OperatorAttentionRequired` extended with `kind ∈ {ArchiverLagging, ArchiverChecksumMismatch, WitnessAnchorPublicationFailing, GdprRedactionWillNotPropagateToArchive, AuditChainCorrupted}`
- [ ] `SecurityViolation` extended with `kind ∈ {ArchiverAuthFailed, ArchiveCorruption, WitnessAnchorMismatch}`
- [ ] `V3MigrationCompleted { v2_chain_terminal_segment_id, initial_v3_witness_id, migration_at_ms }`

### CLI

- [ ] `raxis admin audit-verify --segment <N>` per §11.1
- [ ] `raxis admin audit-verify --range <from>..<to>` per §11.1
- [ ] `raxis admin audit-verify --witness-only` per §11.1
- [ ] `raxis admin audit-verify-proof --proof <file>` per §11.1
- [ ] `raxis admin audit-prove --event-id <uuid>` per §11.1 / §8.2
- [ ] `raxis admin audit-restore --segment <N>` per §11.2
- [ ] `raxis admin audit-restore --range <from>..<to>` per §11.2
- [ ] `raxis admin audit-inspect --segment <N> --from-restored` per §11.2
- [ ] `raxis admin redact --event-ids <list> --legal-basis <text> --signing-key <ref>` per §11.3
- [ ] `raxis admin audit-witness-now` per §11.4
- [ ] `raxis admin audit-witness list` per §11.4
- [ ] `raxis admin audit-migrate-to-v3 --confirm` per §11.5

### Tests

- [ ] V2 → V3 migration: pre-load V2 audit data; run migration; verify Merkle structure; verify initial witness covers all migrated segments
- [ ] V3 segment finalization happy path: append events; force finalization; verify Merkle root computed; verify `<N>.log` and `<N>.merkle` written; verify SQLite row inserted; verify inter-segment tree updated
- [ ] Crash recovery during finalization: kill kernel mid-finalization at each of the 11 steps; restart; verify recovery completes the protocol idempotently
- [ ] Crash recovery: orphaned `<N>.log.active` with no SQLite row → resume as ActiveSegment(N)
- [ ] Crash recovery: SQLite row exists but `<N>.log` was renamed but `<N>.merkle` was not → recompute and write merkle
- [ ] Crash recovery: Merkle root mismatch between recomputed and SQLite → halt with `AuditChainCorrupted`
- [ ] Archiver happy path: finalize segment; verify `AuditSegmentReady` sent; archiver ACKs; verify `archiver_acked_at_ms` set; verify `archive_sha256 == local_sha256`
- [ ] Archiver checksum mismatch: stub archiver returning wrong SHA-256 in ACK; verify SecurityViolation; verify ACK rejected; verify retry triggered
- [ ] Archiver auth failure: connect from wrong UID; verify connection refused; verify SecurityViolation audit event
- [ ] Archiver disconnect mid-flight: archiver crashes mid-upload; kernel detects UDS disconnect; reconnect; verify pending notifications resent; verify idempotent processing
- [ ] Archiver lag alert: stub archiver silent for 8 days; verify `OperatorAttentionRequired { ArchiverLagging }` after `archiver_lag_alert_days`
- [ ] Local deletion eligibility: segment finalized 91 days ago, archived; verify GC deletes locally and updates row
- [ ] Local deletion gating: segment finalized 91 days ago but NOT archived; verify GC does NOT delete; verify segment remains on disk
- [ ] Disk-full while archiver lagging: fill disk to `min_free_disk_mb`; verify `host-capacity.md §7` halts admission; verify no audit data lost
- [ ] V2-compatible mode: `archiver_uds_path = ""`; finalize segments; verify no archiver notification; verify segments accumulate locally with no deletion eligibility
- [ ] Witness signing happy path: finalize 10 segments; verify witness signed; verify `audit_witnesses` row inserted; verify `local_witness_path` appended
- [ ] Witness time-based signing: idle for `sign_at_least_every_seconds + 1`; verify witness signed even without new segment
- [ ] Witness on shutdown: send SIGTERM to kernel mid-flight; verify shutdown witness written before exit
- [ ] External anchor publication: `external_anchor.enabled = true`, backend = rekor; sign witness; verify `PublishWitness` sent to archiver; stub archiver returning Rekor entry UUID; verify `WitnessExternallyAnchored` audit event
- [ ] External anchor publication failure: stub Rekor returning 503; verify `WitnessAnchorPublicationFailed`; verify retry; after 10 failures verify `OperatorAttentionRequired`
- [ ] Inclusion proof generation: pick a known event; generate proof; verify proof contains within-segment path, inter-segment path, witness, optional anchor ref
- [ ] Inclusion proof verification: run audit-verify-proof against generated proof; verify success; tamper with one byte of proof; verify failure
- [ ] Inclusion proof for redacted event: redact an event; attempt audit-prove for it; verify `FAIL_EVENT_REDACTED` with `truncation_id` reference
- [ ] Inclusion proof for non-redacted event in redacted segment: verify proof uses post-truncation root; verify post-redaction witness used as anchor
- [ ] Redaction preflight: `redaction_enabled = false`; attempt redact; verify `FAIL_REDACTION_DISABLED`
- [ ] Redaction preflight: archiver reports backend immutable; verify `FAIL_BACKEND_IMMUTABLE` if `require_archive_compatibility = true`
- [ ] Redaction preflight: `require_archive_compatibility = false`, immutable backend; verify warning emitted; verify redaction proceeds locally; verify archive copy unchanged
- [ ] Redaction execution: redact 2 events in 1 segment; verify segment's `local_sha256` and `merkle_root` updated; verify `ChainTruncation` event in active segment; verify `audit_chain_truncations` row; verify fresh witness signed; verify pre-redact files retained pending archive propagation
- [ ] Redaction execution multi-segment: redact 5 events across 3 segments; verify 3 separate `ChainTruncation` events with separate truncation_ids
- [ ] Redaction archive propagation success: stub archiver returning `RedactionPropagated`; verify pre-redact local file deleted
- [ ] Redaction archive propagation failure: stub archiver returning `RedactionPropagationFailed`; verify pre-redact files retained; verify operator can re-attempt propagation
- [ ] Indexed view GC: insert old `inference_attempts` rows; advance time past `inference_attempts_days`; run GC; verify rows deleted; verify audit event records count and cutoff
- [ ] Indexed view independence: GC `inference_attempts`; verify raw audit log unchanged; verify `audit-restore` of corresponding segment retrieves original event data

---

## 14. Foundational Design Decisions

This section records the seven foundational commitments the audit-retention architecture is built on. Each entry follows the host-capacity.md §15 structure: **the decision**, **the alternative considered**, **why we rejected it**, and **the scenario the rejection prevents**.

### §14.1 — Sidecar archiver over kernel-side WAN egress

**Decision.** All audit archive uploads, witness publications, and external anchor postings are performed by a separate `raxis-archiver` daemon running under its own unprivileged UID. The kernel's network surface remains bounded to `git push` per `INV-CRED-KERNEL-01`.

**Considered alternative.** Embed AWS S3 / Azure Blob / Sigstore Rekor SDKs directly in the kernel address space; the kernel performs all archive I/O.

**Rejected because.** The kernel is the most-privileged process in the RAXIS host (it manages cryptographic keys, mediates all write-class intents, owns all SQLite state). Adding a multi-megabyte SDK with TLS, HTTP, and protocol-specific logic to the kernel's address space adds an enormous memory-safety attack surface. A bug in `aws-sdk-s3`'s response parser becomes a kernel-level RCE; a bug in `rustls`'s certificate validation becomes a kernel-level credential exfiltration. The blast radius of a memory-safety vulnerability in any of these libraries is catastrophically larger when they run inside the kernel.

We just spent significant design discussion drafting `INV-CRED-KERNEL-01` to bound kernel egress to `git push` only. Pulling cloud SDKs into the kernel address space within hours of that decision would render the invariant meaningless.

The sidecar architecture mirrors how operating system kernels interact with userspace daemons (`auditd`, `journald`, `systemd-journal-remote`). The trust boundary is the OS process isolation primitive, which is the strongest isolation primitive available to a Linux process. The archiver can corrupt or fail to upload audit data, but it cannot mutate kernel state, forge audit events, sign witnesses, or grant itself credentials.

**Scenario it prevents.** A zero-day in `aws-sdk-s3`'s SigV4 signing module is disclosed. With kernel-side WAN egress, every RAXIS host worldwide is immediately at risk of kernel compromise; an emergency patch must be deployed everywhere. With the sidecar architecture, the archiver process is at risk; the kernel is unaffected; operators can update the archiver on a normal patch schedule without urgency.

### §14.2 — Two-level Merkle tree over linear hash chain

**Decision.** V3 organizes the audit log as a two-level Merkle tree: per-segment Merkle trees with segment roots aggregated into an inter-segment Merkle tree. INV-04 (audit log tamper-evidence) is preserved in semantic meaning; the underlying data structure migrates from V2's linear chain to V3's Merkle structure.

**Considered alternative.** Keep V2's linear hash chain. Operators wanting to verify an old event in cold storage download the contiguous range from that event to the most recent local witness.

**Rejected because.** A linear chain cannot support O(log N) inclusion proofs. Verifying that Event X in segment 5,000 chains forward to a witness at segment 50,000 requires computing the hash of every event between 5,000 and 50,000 — a contiguous-range download operation. For audit logs in cold storage with many segments, this is operationally hostile (downloading 45,000 segments from Glacier to verify one event), and it categorically cannot support legal-evidence use cases that need a 50-byte proof rather than a 50-GB segment dump.

The Merkle tree's storage overhead is approximately 3% of raw audit data (per the math correction in design review: a binary Merkle tree with N leaves has N-1 internal nodes; 32 bytes per SHA-256 hash; for 1M events at 1KB each = 1GB raw, the Merkle overhead is 32MB). This is trivial compared to the operational benefit.

The cost is a one-time V2 → V3 migration with a documented format conversion tool (`raxis admin audit-migrate-to-v3`), and a one-time complexity addition to the audit subsystem. Both are bounded; the benefit (legal-grade single-event proofs without contiguous chain download) compounds forever.

**Scenario it prevents.** Six months into a V3 deployment, a regulator requires the operator to prove that a specific approval intent was logged at a specific time as part of a compliance review. With a linear chain, the operator must restore the contiguous segments from cold storage (potentially gigabytes) and submit them all to the regulator with a re-hash demonstration. With a Merkle tree, the operator generates a 50-byte inclusion proof; the regulator verifies it offline using the kernel's well-known operating key (and optionally a Sigstore Rekor entry); the proof is mathematically conclusive and trivial to validate.

### §14.3 — Chain truncation with signed attestation (Option B) over PII commitment store (Option A)

**Decision.** GDPR right-to-erasure is implemented via Option B: physically delete the redacted event bytes, recompute the affected segment's Merkle root, create a signed `ChainTruncation` event in the current active segment attesting to the redaction. The audit chain is mathematically discontinuous at the truncation point, and the discontinuity is itself a signed audit-logged event.

**Considered alternative (Option A).** The audit log never contains raw PII; it stores cryptographic commitments `Hash(Salt || PII)`. Real PII lives in a mutable SQLite `pii_store` table. Redaction = `DELETE FROM pii_store`.

**Rejected because.** Three structural problems with Option A:

1. **Upfront PII classification is brittle.** Option A requires the audit logger, at the moment an event is written, to designate which fields contain PII. When V3.1 adds a new event kind with a new field that turns out to contain PII, we must remember to mark it as PII. If we forget, the data goes into the audit log raw, and Option A is useless for that field — we have to fall back to Option B anyway.
2. **GDPR's "personal data" definition is operationally fuzzy.** Operator names are PII. User-prompt content may be PII (depends on what the user typed). File paths may be PII (`/home/jdoe/...`). Hash references usually aren't, but `git commit --author "Real Name <email>"` produces commit SHAs that index back to author identity. We cannot reliably classify at log time.
3. **Forensic asymmetry breaks incident response.** With Option A, the forensic reviewer (often a separate team from the GDPR-compliance team per SOC 2 / ISO standards of separated duties) sees opaque commitments instead of actual values. Audit events become useless for the people who actually need them.

**The decisive argument is retroactive applicability.** Option B works for any audit data, including data logged under the V2 schema before V3 existed. Option A only works for data logged after the system was designed with commitments. We would need both Option A and Option B in production anyway, and once Option B exists, Option A is just complexity for an asymmetric-but-rare convenience.

**Option B turns the chain break into a forensic asset.** The `ChainTruncation` event itself is part of the post-truncation chain — signed under the operator's redaction key, recording who authorized the redaction, the legal basis, the redacted event UUIDs, and the pre/post Merkle roots. A future auditor encountering the chain break gets a complete record of what happened and why, attested under a key the operator cannot deniably-rotate.

**Scenario it prevents.** A small operator deploys V3 with `redaction_enabled = true` and configures Option A's PII commitment system. Two years later, they receive a GDPR request and discover the new `provider-failure-handling.md`'s `inference_attempts` events from V3.2 added a `request_body_excerpt` field that wasn't classified as PII at the schema level. Option A cannot redact what wasn't classified. The operator now needs Option B as a fallback — having paid for Option A's complexity for the entire deployment lifetime for nothing. With Option B as the only mechanism, this scenario doesn't exist.

### §14.4 — Per-event redaction granularity over segment-level or field-level

**Decision.** The redaction tool operates per-event. The operator identifies specific event UUIDs to redact; the tool deletes those events from the segment, recomputes the segment's Merkle root, and signs a `ChainTruncation` attestation.

**Considered alternative A (segment-level).** Redact entire segments. Simpler to implement (no in-segment surgery; just delete the segment file).

**Rejected because.** Segments contain potentially thousands of unrelated events. One PII reference in a 5,000-event segment would erase 4,999 innocent records, destroying forensic visibility for unrelated incidents. Segment-level granularity is too blunt for actual GDPR compliance.

**Considered alternative B (field-level).** Redact specific fields within events. Maximum granularity (preserves the most information).

**Rejected because.** Field-level redaction requires the kernel to parse arbitrary JSON schemas during redaction tool runs. The audit log schema evolves (every new event kind adds new fields); the redaction tool would need to be schema-version-aware, with explicit support for every event kind that has ever existed. This is a significant ongoing maintenance burden for a feature invoked rarely.

Field-level also produces ambiguous semantics: if the redacted field is referenced elsewhere in the event payload (e.g., a hash that was computed over the now-redacted field's value), is the hash invalidated? Does the rest of the event still verify? These are V4 questions at best.

**Per-event is the sweet spot.** Surgical enough to preserve unrelated events in the same segment (typically thousands), simple enough to implement without schema parsing (just identify and remove specific events by UUID). The kernel rewrites the segment without the targeted events and recomputes the Merkle root from the remaining leaves.

**Scenario it prevents.** An operator receives a GDPR request to erase all data about Jane Doe. With segment-level redaction, the tool would erase entire segments containing any reference to Jane, potentially deleting thousands of unrelated audit events from active investigations. With field-level redaction, the tool would need to know every schema version's "PII fields" and might miss a field added in V3.4 that wasn't tagged. With per-event, the operator identifies the specific events about Jane (queryable via `inference_attempts`, `operator_attention_log`, etc.) and redacts exactly those, leaving everything else untouched and forensically usable.

### §14.5 — Local-only witnesses with opt-in external anchoring

**Decision.** By default, witnesses are signed under the operating key and stored locally. External anchoring (Sigstore Rekor, Certificate Transparency log, custom HTTP endpoint) is opt-in via `external_anchor.enabled = true`.

**Considered alternative A.** Mandate external anchoring for all V3 deployments.

**Rejected because.** RAXIS is deployed in fully air-gapped environments (defense, regulated medical, classified research). External anchoring requires WAN egress for anchor publication, which violates these deployments' threat models. Mandating it would force air-gapped operators to either skip V3 entirely or run a private internal anchor service (which most don't have).

**Considered alternative B.** Make all V3 deployments local-only; external anchoring is a future addition.

**Rejected because.** External anchoring is the single best defense against operating-key compromise. An attacker who steals the operating key can sign fraudulent witnesses to make rewritten history look valid. With external anchoring to a public log (Sigstore Rekor), the attacker would also need to backdate Rekor entries — practically impossible in Sigstore's tamper-evident structure. This is genuinely valuable for high-stakes deployments (financial services, healthcare, government); making it inaccessible removes RAXIS's strongest forensic story.

**Opt-in by default gives both.** Air-gapped operators get a working V3 without modification. High-assurance operators opt in to external anchoring with a single configuration line. The choice is operator-driven, not architecture-imposed.

**Sigstore Rekor as the recommended default for opt-in.** Public, free, Linux Foundation-hosted, cryptographically auditable, with mature tooling (`cosign`, `rekor-cli`). Operators with regulatory concerns about Sigstore can choose `ct_log` or `http_post`. The archiver's backend module is replaceable; the kernel sees one interface.

**Scenario it prevents.** A nation-state actor compromises an operator's RAXIS host and steals the operating key. They rewrite a year's worth of audit history to remove evidence of their intrusion and sign new witnesses under the stolen key. With local-only witnesses, the rewritten log appears valid — every witness signature checks out under the stolen key. With external anchoring to Sigstore Rekor, the attacker cannot fabricate Rekor entries with the original timestamps; the discrepancy between local witnesses and externally-anchored witnesses immediately reveals the tampering. The opt-in default gives operators who care about this threat the tool to defend against it without burdening operators who don't.

### §14.6 — Single-archiver UDS with at-least-once delivery and queued backpressure

**Decision.** The kernel speaks to exactly one archiver process over a single UDS path. Multi-backend redundancy (e.g., S3 + on-prem mirror) is the archiver's internal concern, not the kernel's. Notifications are at-least-once with idempotent archiver-side processing. Backpressure is implicit: the kernel never blocks segment finalization on archiver throughput; segments accumulate locally; the disk-full halt mechanism eventually fires if the archiver cannot keep up.

**Considered alternative A.** Kernel speaks to multiple archiver UDSs concurrently and waits for ALL to ACK before allowing local deletion.

**Rejected because.** Adds significant complexity to the kernel's archive state machine: per-segment state becomes a matrix of (archiver, segment) ACK status; verification requires reasoning about partial ACK sets; archiver failure modes multiply (one archiver down means all archivers blocked from deletion eligibility). The same operational outcome (multi-backend redundancy) can be achieved by the operator's archiver process internally fanning out to multiple backends, with the kernel seeing one ACK per segment.

**Considered alternative B.** Synchronous notification: kernel blocks segment finalization until archiver ACKs.

**Rejected because.** Couples segment finalization (a kernel-internal hot path) to archive throughput (a network operation that may take seconds to minutes for large segments). A slow archiver would block all audit writes, eventually starving the kernel's write pipeline. The current design (notification is fire-and-forget, archiver ACKs asynchronously) decouples these correctly; segments finalize at full kernel speed regardless of archive backend latency.

**Considered alternative C.** Bounded queue with explicit backpressure to the kernel (kernel pauses event writes when queue is full).

**Rejected because.** Pausing event writes pauses the entire kernel — every intent processing path needs to write audit events. Backpressure on the audit subsystem becomes backpressure on everything. The implicit backpressure via disk-full halt is structurally simpler: the same mechanism that protects against any disk pressure (host-capacity.md §7) protects against archiver lag, with no additional code paths.

**Scenario it prevents.** Operators with bespoke multi-backend redundancy needs (some regulatory environments require dual-locality archives) can implement the fanout in their custom archiver without any kernel changes. The kernel's protocol stays simple. Operators without such needs run the reference archiver and never think about it. Both populations are well-served by the simple protocol.

### §14.7 — Indexed view retention independent of audit log retention

**Decision.** SQLite-side indexed views (`inference_attempts`, `admission_queue`, `breaker_state_history`, `operator_attention_log`) have their own per-view retention configured under `[audit_retention.indexed_views]`. Indexed view retention is INDEPENDENT of raw audit log retention; deletions from indexed views do not affect the audit log.

**Considered alternative.** Tie indexed view retention to audit log retention (delete indexed view rows whenever the corresponding audit log segment is locally deleted).

**Rejected because.** Conflates two distinct operational concerns:

- **Audit log retention** is a forensic concern. It governs how long the system keeps the cryptographically-verifiable record of what happened. Operators want this LONG (years, often).
- **Indexed view retention** is an operational query concern. It governs how long fast SQLite queries can return data. Operators want this SHORT (weeks to months) to keep SQLite queries fast and the database compact.

Conflating them forces operators into a bad tradeoff: either keep SQLite indexes for years (huge database, slow queries) or have audit logs accessible only via slow archive restore for anything older than the operational query window.

The independence model lets operators have both: 30 days of fast SQLite queries for `inference_attempts`, plus 7 years of forensic record in the archive. Older queries fall back to "restore from archive" workflow, which is slow but always available.

**Scenario it prevents.** An operator in financial services needs 7-year audit retention for regulatory compliance, but their SQLite database would balloon to terabytes if `inference_attempts` retention matched. With independent retention, they configure `inference_attempts_days = 90` (fast queries for last quarter; SQLite stays small) and `local_retention_days = 90` with archive lifecycle = 7 years (forensic record preserved). Historical queries use `audit-restore` for the older time range. Without independent retention, this is impossible.

---

## 15. Alternatives Considered and Rejected

### Alt A — Embed S3/Azure SDKs in the kernel

Kernel-side WAN egress for archiving. Rejected per §14.1: catastrophic increase to kernel attack surface; violates `INV-CRED-KERNEL-01`.

### Alt B — Option A (PII commitment store) as the redaction primary

Hash-commitment-with-mutable-pii-store approach to GDPR. Rejected per §14.3 in favor of Option B.

### Alt C — Linear hash chain for V3 (Resolution B from design discussion)

Keep V2's linear chain in V3; rely on `audit-restore` of contiguous ranges for forensic verification. Rejected per §14.2: cannot support O(log N) inclusion proofs; legal-evidence use cases impractical; operators with 50,000-segment archives would need to download everything for any single-event verification.

### Alt D — Segment-level redaction granularity

Redact entire segments rather than per-event. Rejected per §14.4: destroys too much innocent forensic data.

### Alt E — Field-level redaction granularity

Redact specific fields within events. Rejected per §14.4: requires kernel-side schema parsing; ongoing maintenance burden; ambiguous semantics for field references.

### Alt F — Mandatory external witness anchoring

Force all V3 deployments to publish witnesses to an external anchor. Rejected per §14.5: incompatible with air-gapped deployments; opt-in is the right default.

### Alt G — Multi-archiver fanout in the kernel

Kernel speaks to N archivers concurrently. Rejected per §14.6: complexity belongs in the archiver process, not the kernel.

### Alt H — Synchronous archiver notification

Kernel blocks segment finalization on archiver ACK. Rejected per §14.6: couples kernel write hot path to network latency; slow archiver starves everything.

### Alt I — Tie indexed view retention to audit log retention

Delete `inference_attempts` rows when corresponding audit segments are locally deleted. Rejected per §14.7: conflates forensic and operational concerns.

### Alt J — Cryptographic erasure (Option D from design discussion)

Per-event symmetric encryption of designated PII fields, with key destruction as the redaction operation. Rejected for V3 in favor of the simpler chain-truncation approach. Significantly more powerful than Option A (no upfront classification needed; encrypted bytes act as proof-of-existence) but adds key-management complexity (per-event keys, key rotation, key escrow during legal holds). Deferred to V4 for evaluation if operational data on chain-truncation frequency suggests it would be useful.

### Alt K — `raxis admin scrub` (DELETE FROM audit_segment without re-hashing)

A simpler "redaction" that just removes events from the segment file without re-computing the Merkle root. Rejected: produces an audit log where `segment.merkle_root` no longer matches the file contents — equivalent to corruption from any verifier's perspective. The whole point of recomputing the Merkle root is to maintain a coherent (if discontinuous) chain.

### Alt L — Per-segment archiver authentication via shared keys

Authenticate the archiver via a pre-shared key in `policy.toml` rather than `SO_PEERCRED`. Rejected: redundant complexity. The `SO_PEERCRED`-derived UID check is already strictly stronger than a shared-key check (an attacker who compromises any process running on the host could read the shared key from `policy.toml`; they cannot fake a UID at the OS level without already having root, in which case they can do far worse than impersonate the archiver). Shared keys add no security and increase configuration complexity.

### Alt M — Separate "archive-deletion" key

Require a second key (distinct from `redaction_signing_key`) to authorize local segment deletion after retention expires. Rejected: GC of locally-deleted-but-archived segments is a routine operational task; gating it on a key signature would make ordinary disk-space management require signing ceremony. The verification gate (archiver-acked checksum match) is the structural protection; key-signing for routine GC adds ceremony without security benefit.

### Alt N — Witness publication via the kernel directly

Kernel publishes witnesses to Sigstore Rekor itself, bypassing the archiver. Rejected: this puts WAN egress back in the kernel for a second purpose (after we just removed it for archive uploads). The same arguments in §14.1 apply. The archiver handles all WAN egress; the kernel handles all signing.

### Alt O — Per-event Merkle leaf using the V2 linear-hash format

Make each event's `leaf_hash` equal to the V2 linear-chain hash (i.e., embed prev_event_hash in the leaf computation). Rejected: this would allow V2 verifiers to read V3 segments by interpreting them as a linear chain. Tempting for backward compatibility, but it doubles the per-event hash computation cost and creates ambiguity about which mechanism is authoritative for INV-04 enforcement. Cleaner to make V3 a hard format break with a documented one-way migration tool.

### Alt P — Witnesses signed under the redaction key during redaction-active operations

When a redaction is in flight, sign the post-truncation witness under `redaction_signing_key` instead of `operating_key`. Rejected: separation of duties is enforced by having two keys; a witness signed under the redaction key would imply the redaction key has authority over the audit log itself, which is a privilege escalation path. Witnesses are always signed under the operating key; the `ChainTruncation` event is signed under the redaction key. Both signatures are independently verifiable.

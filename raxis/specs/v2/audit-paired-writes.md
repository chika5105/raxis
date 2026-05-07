# RAXIS V2 — Paired Audit Writes (`StateChangePending` / `StateChangeRolledBack` + augmented confirmed events)

> **Status:** V2 Specified
> **Role:** Closes the strict-`R-7` gap in the V1 audit-emit ordering by binding every state-mutating SQLite transaction to a pair of audit records (a *pending* announcement before the transaction and a *confirmed* augmentation of the existing event after the COMMIT) so an offline forensic verifier can resolve every chain entry without the kernel needing to be running.
>
> **Cross-references:**
> - `paradigm.md` `R-7` — the cryptographic audit chain invariant this spec satisfies under a strict reading
> - `invariants.md` — adds `INV-AUDIT-PAIRED-01..07`; companions to existing `INV-AUDIT-*`
> - `v1/kernel-store.md §2.5.2` — the AuditSink ordering this spec rewrites; new `last_committing_event_seq` column on state-bearing tables
> - `v1/kernel-core.md §2.3` — intent-handler step ordering: this spec inserts Phase B (write pending → BEGIN IMMEDIATE → write confirmed)
> - `v1/kernel-core.md` `recovery::reconcile` — becomes **advisory**; offline verifier no longer depends on it for chain resolution
> - `v2/extensibility-traits.md §5` — extends the `AuditSink` trait with `emit_pending`, `emit_confirmed_for`, `emit_rolled_back_for`
> - `v2/policy-plan-authority.md` — adds `FAIL_AUDIT_PAIRED_*` failure codes to the catalog
> - `v2/v2-deep-spec.md` — registers this spec in Related Specifications

---

## §1 — The R-7 gap this spec closes

### §1.1 What the strict reading of R-7 requires

`R-7 Cryptographic audit chain` (paradigm.md §3) says:

> All authority decisions are recorded in an append-only, hash-chained log whose integrity MUST NOT depend on continued operation of the authority that produced it.

The operative phrase is **"MUST NOT depend on continued operation of the authority"**. Under the strict reading, an offline forensic reader, given **only the audit chain plus any frozen artefacts of the authority's state at a point in time**, must be able to verify the chain end-to-end without the kernel ever needing to run again. Frozen state artefacts (a SQLite snapshot, the credentials directory, the policy file at a given epoch) are *part of the authority's frozen output*, not "continued operation" — consulting them is allowed. What is **not** allowed is requiring the kernel to restart and run a code path that synthesises missing chain entries from SQLite.

### §1.2 What V1 actually does

The V1 audit-emit ordering (`v1/kernel-store.md §2.5.2`):

```
Phase A (pre-tx)        — parse intent, run policy gates
                          (no state mutation; no audit emission)
Phase B (state mutation)— BEGIN IMMEDIATE
                          mutate SQLite
                          COMMIT (fsync 1)
Phase C (post-commit)   — write audit JSONL line
                          fsync (fsync 2)
```

A crash in the `(Phase B COMMIT, Phase C fsync)` window produces:

- SQLite: state advanced.
- JSONL: chain silent on the transition.

`recovery::reconcile` (`kernel/src/recovery.rs`) detects this on the next kernel start by comparing SQLite's "last transition" markers against the JSONL chain, and synthesises the missing audit events. **This is functional**: the chain becomes correct after the kernel runs again.

### §1.3 Why V1 violates R-7 under the strict reading

Two failure modes are not covered by `recovery::reconcile`:

1. **The kernel is decommissioned without ever restarting.** The host is decommissioned, the data directory is moved to long-term archival storage, and a forensic team is asked years later to verify the audit chain. They have the JSONL and a SQLite snapshot. They run the V1 verifier (V1's `raxis-cli verify-chain`) — the chain is internally consistent (every link's hash matches), but no signal in the chain indicates that any state changes are *missing*. They cannot tell whether the chain is complete.

2. **The kernel restarts on a different code version that lacks `recovery::reconcile` semantics.** The reconciliation logic is not part of the audit protocol — it is an implementation detail of one kernel version. A kernel that boots with a different reconciliation policy (or no reconciliation at all) leaves gaps unresolved.

Both modes describe the chain "depending on continued operation of the authority that produced it." Strict R-7 forbids both.

### §1.4 Why this is a real risk, not theoretical

The crash window is small (~µs–ms on modern NVMe), but:

- Crashes are correlated with *state-mutating* events. A kernel crash on `IntegrationMerge::commit` is precisely a moment of high-impact state mutation.
- An adversary with kernel-execution control (privilege escalation, kernel-bug exploit, host-level compromise) can deliberately crash the kernel in the window to mask a real action.
- Compliance auditors do not accept "we'll fix it on restart" as evidence of integrity. A compliance check that requires running the system to validate its history is not a chain integrity check; it is an operational integrity check.

The fix described below makes the chain self-resolving without depending on any future kernel run.

---

## §2 — Design (event-pair structure)

The kernel binds every state-mutating SQLite transaction to a pair of audit chain entries:

1. A **`StateChangePending`** event written and `fsync`'d **before** `BEGIN IMMEDIATE`.
2. The **existing event kind** (e.g. `EscalationSubmitted`, `TaskStateChanged`, `IntegrationMergeApplied`) — augmented with three new mandatory fields — written and `fsync`'d **after** the SQLite `COMMIT` succeeds. This event references the pending event by sequence number and serves as the *confirmation*.

If the kernel deliberately rolls the transaction back (constraint violation, disk-full, etc.) or aborts before reaching `COMMIT`, the kernel emits a **`StateChangeRolledBack`** event instead of the augmented existing-kind event, referencing the pending by sequence number.

Crash-induced orphans (pending without confirmed and without rolled-back) are resolved by an offline verifier that consults a SQLite snapshot.

### §2.1 The two new event kinds

```rust
//! crates/audit/src/event.rs (extended)

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum AuditEventKind {
    // … existing variants …

    /// V2.1+ — written before BEGIN IMMEDIATE for any state-mutating
    /// operation. Announces what the kernel is about to attempt.
    /// `pending_seq` equals this event's own `event_seq`; the field is
    /// included redundantly so a verifier scanning forward can locate
    /// the pending without a back-pointer pass.
    StateChangePending {
        pending_seq:                u64,
        operation:                  StateChangeOperation,
        /// Forensic context: which session/initiative/task is moving
        /// (None for kernel-internal sweeps without a session).
        session_id:                 Option<SessionId>,
        initiative_id:              Option<InitiativeId>,
        task_id:                    Option<TaskId>,
        /// 32-byte planner-supplied envelope nonce (`R-9`-bound) for
        /// intent-driven mutations; None for sweeps and operator IPC.
        idempotency_key:            Option<[u8; 32]>,
        /// SHA-256 over the canonical encoding of the rows the kernel
        /// READ to make this decision (the causal preconditions).
        /// A verifier hashes the same rows in the SQLite snapshot at
        /// the predecessor `sqlite_commit_id` and confirms the kernel
        /// saw the state it claims it saw.
        pre_state_digest:           [u8; 32],
        /// Typed list of intended writes (table, key, before-digest,
        /// after-digest, mutation kind). The verifier uses these to
        /// locate rows in the SQLite snapshot for resolution checks.
        intended_writes:            Vec<RowMutationDescriptor>,
        /// SHA-256 over the canonical encoding of `intended_writes`.
        /// Bound to the chain so an attacker cannot manufacture a
        /// pending pointing at different rows after the fact.
        intended_post_state_digest: [u8; 32],
        /// Kernel-version, policy-epoch, and other invariants the
        /// kernel's decision depended on. Bound for replay verification.
        pre_tx_claims:              KernelClaims,
    },

    /// V2.1+ — written when the kernel deliberately aborts the
    /// transaction (constraint violation, kernel-initiated rollback).
    /// Crash-induced orphans do NOT receive this event; they are
    /// resolved by the offline verifier consulting SQLite.
    StateChangeRolledBack {
        rolls_back_pending_seq: u64,
        reason:                 RollbackReason,
        reason_detail:          String,                  // human-readable
        rolled_back_at_ms:      u64,
    },

    // … all existing state-mutating variants gain three new mandatory fields,
    // listed in §2.3 below …
}

/// The kind of operation that follows a `StateChangePending`. Allows
/// forensic queries like "find all attempted EscalationSubmitted whose
/// confirmed never landed" without parsing the wrapped fields.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum StateChangeOperation {
    Intent { intent_kind: String },               // e.g. "ActivateSubTask", "EscalationRequest"
    OperatorIpc { operation: String },             // e.g. "RotateEpoch", "ApproveEscalation"
    BackgroundSweep { sweep_name: String },        // e.g. "lane_reservation_orphan_sweep"
    KernelInitiated { source: String },            // e.g. "EmergencyKeyCompromised", "PolicyEpochAdvanced"
    WitnessSubmission { verifier_id: String },     // verifier WitnessSubmission
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum RollbackReason {
    /// SQLite returned `CONSTRAINT` (unique, foreign-key, check).
    ConstraintViolation,
    /// SQLite returned `IOERR`, `FULL`, `NOMEM`.
    StorageFault,
    /// Kernel-side check inside the transaction body decided to abort.
    KernelInitiatedAbort,
    /// `BEGIN IMMEDIATE` could not acquire the write lock within the
    /// admission deadline.
    LockTimeout,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RowMutationDescriptor {
    pub table:        String,                          // e.g. "tasks"
    pub primary_key:  serde_json::Value,                // e.g. {"id": "01J…"}
    pub mutation:     MutationKind,                     // Insert | Update | Delete
    /// SHA-256 of the canonical row encoding pre-tx (None for INSERT).
    pub before:       Option<[u8; 32]>,
    /// SHA-256 of the canonical row encoding post-tx (None for DELETE).
    pub after:        Option<[u8; 32]>,
}

#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize)]
pub enum MutationKind { Insert, Update, Delete }

/// Snapshot of the kernel-internal claims the decision depended on.
/// The verifier uses this to detect a kernel that committed under a
/// different epoch than it announced.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct KernelClaims {
    pub kernel_version:     String,
    pub policy_epoch:       u32,
    pub policy_sha256:      [u8; 32],
    pub clock_ms:           u64,
}
```

### §2.2 Existing event-kind augmentation (for paired classes only)

Every existing `AuditEventKind` variant in the **paired class** (enumerated in §4) gains these three mandatory fields:

```rust
// On every paired-class variant (e.g. EscalationSubmitted, TaskStateChanged):
{
    // … existing variant fields …

    /// References the `StateChangePending::pending_seq` that
    /// precedes this confirmation. Verifier asserts the pending
    /// exists at the cited seq.
    confirms_pending_seq:        u64,
    /// SQLite WAL frame number at COMMIT (read via
    /// `PRAGMA data_version` after COMMIT). Binds the audit
    /// confirmation to a specific SQLite point-in-time so a
    /// verifier with a SQLite snapshot can rehash rows at that frame.
    sqlite_commit_id:            u64,
    /// SHA-256 over the canonical encoding of the rows actually
    /// written during the transaction (computed inside the
    /// transaction post-write, pre-COMMIT). Verifier compares this
    /// against the pending's `intended_post_state_digest` — equal in
    /// the honest case; divergence indicates kernel buggery worth
    /// flagging.
    actual_post_state_digest:    [u8; 32],
}
```

These fields are added **once per variant** in `crates/audit/src/event.rs`. The existing forensic-query model (`raxis log --kind EscalationSubmitted`) is unchanged; queries simply now also return `confirms_pending_seq` etc. in the JSON output.

### §2.3 Wire-level emission ordering (the new Phase B)

For any state-mutating intent, operator IPC write, background sweep, or witness submission:

```
Phase A (pre-tx)        — parse intent, run policy gates
                          (no state mutation; no audit emission)

Phase B0 (pre-tx audit) — compute pre_state_digest (over read-set rows)
                          compute intended_writes, intended_post_state_digest
                          emit StateChangePending
                          fsync (fsync 1)

Phase B1 (state mutation)
                        — BEGIN IMMEDIATE
                          perform writes
                          compute actual_post_state_digest (over write-set rows)
                          set last_committing_event_seq = pending_seq
                            on every row touched
                          COMMIT (fsync 2)
                          PRAGMA data_version → sqlite_commit_id

Phase B2 (post-commit audit)
                        — emit existing-kind event with the three new
                          fields (confirms_pending_seq, sqlite_commit_id,
                          actual_post_state_digest)
                          fsync (fsync 3)

Phase C (response)      — return IntentResponse to planner / IPC reply
```

If Phase B1 deliberately rolls back (constraint violation, etc.), Phase B2 emits `StateChangeRolledBack` instead. If Phase B1 crashes, Phase B2 never runs; recovery (or the offline verifier) resolves the orphan from SQLite.

---

## §3 — SQLite schema additions

### §3.1 The `last_committing_event_seq` column

Every state-bearing SQLite table gains a new column:

```sql
last_committing_event_seq INTEGER NOT NULL
```

For pre-V2.1 rows (rows written before the migration event in §10), the column is backfilled from the audit chain by a one-shot migration: the migration scans the JSONL for the latest event referencing each row's primary key and writes the seq. Rows the migration cannot resolve (e.g., the audit log was truncated or the row predates the chain) get a sentinel `0`; the verifier treats `0` as "pre-pairing" and falls back to V1 semantics for those rows only.

The kernel sets `last_committing_event_seq` **inside** the same transaction as the state mutation (Phase B1):

```sql
BEGIN IMMEDIATE;
  -- mutate the row
  UPDATE tasks SET state = 'Active', last_committing_event_seq = :pending_seq WHERE id = :task_id;
  -- … any joined writes also include last_committing_event_seq = :pending_seq …
COMMIT;
```

This binds the row to the pending event whose `pending_seq` was just announced. The offline verifier compares `pending.pending_seq == row.last_committing_event_seq` to determine whether an orphaned pending committed (true) or was crash-rolled-back (false).

### §3.2 Tables that gain the column

Every table in `crates/store/migrations/` whose rows describe state the kernel mutates inside Phase B1. The exhaustive V2.1 list (cross-checked against `kernel-store.md`):

```
sessions
initiatives
plan_bundles                      -- v2 plan bundle sealing
tasks
subtask_activations
escalations
delegations
verifier_runs                     -- v2 verifier-processes
provider_circuit_state            -- v2 provider-failure-handling
lane_reservations                 -- v2 token-limit-enforcement
candidate_merges                  -- v2 integration-merge
plan_signing_keys                 -- v2 key-revocation
emergency_revocations             -- v2 key-revocation
notification_dispatch             -- v2 email-and-notification-channels
notification_channel_health       -- v2 email-and-notification-channels
smtp_proxy_rate_buckets           -- v2 email-and-notification-channels
session_escalation_rate_limits    -- v2 agent-disagreement
operator_quarantine_directives    -- v2 key-revocation
worktree_abandonment_records      -- v2 agent-disagreement
policy_epoch                      -- v1 kernel-store
```

**Tables explicitly EXCLUDED** (no `last_committing_event_seq` column):

```
audit_chain                       -- the chain itself (would be circular)
sqlite_sequence                   -- SQLite-managed
maintenance_run_history           -- pure observability
key_value_metadata                -- non-state convenience storage
```

### §3.3 Migration SQL

```sql
-- migrations/V21__paired_audit.sql

ALTER TABLE sessions               ADD COLUMN last_committing_event_seq INTEGER NOT NULL DEFAULT 0;
ALTER TABLE initiatives            ADD COLUMN last_committing_event_seq INTEGER NOT NULL DEFAULT 0;
ALTER TABLE plan_bundles           ADD COLUMN last_committing_event_seq INTEGER NOT NULL DEFAULT 0;
ALTER TABLE tasks                  ADD COLUMN last_committing_event_seq INTEGER NOT NULL DEFAULT 0;
ALTER TABLE subtask_activations    ADD COLUMN last_committing_event_seq INTEGER NOT NULL DEFAULT 0;
ALTER TABLE escalations            ADD COLUMN last_committing_event_seq INTEGER NOT NULL DEFAULT 0;
ALTER TABLE delegations            ADD COLUMN last_committing_event_seq INTEGER NOT NULL DEFAULT 0;
ALTER TABLE verifier_runs          ADD COLUMN last_committing_event_seq INTEGER NOT NULL DEFAULT 0;
ALTER TABLE provider_circuit_state ADD COLUMN last_committing_event_seq INTEGER NOT NULL DEFAULT 0;
ALTER TABLE lane_reservations      ADD COLUMN last_committing_event_seq INTEGER NOT NULL DEFAULT 0;
ALTER TABLE candidate_merges       ADD COLUMN last_committing_event_seq INTEGER NOT NULL DEFAULT 0;
ALTER TABLE plan_signing_keys      ADD COLUMN last_committing_event_seq INTEGER NOT NULL DEFAULT 0;
ALTER TABLE emergency_revocations  ADD COLUMN last_committing_event_seq INTEGER NOT NULL DEFAULT 0;
ALTER TABLE notification_dispatch  ADD COLUMN last_committing_event_seq INTEGER NOT NULL DEFAULT 0;
ALTER TABLE notification_channel_health  ADD COLUMN last_committing_event_seq INTEGER NOT NULL DEFAULT 0;
ALTER TABLE smtp_proxy_rate_buckets      ADD COLUMN last_committing_event_seq INTEGER NOT NULL DEFAULT 0;
ALTER TABLE session_escalation_rate_limits  ADD COLUMN last_committing_event_seq INTEGER NOT NULL DEFAULT 0;
ALTER TABLE operator_quarantine_directives  ADD COLUMN last_committing_event_seq INTEGER NOT NULL DEFAULT 0;
ALTER TABLE worktree_abandonment_records    ADD COLUMN last_committing_event_seq INTEGER NOT NULL DEFAULT 0;
ALTER TABLE policy_epoch                    ADD COLUMN last_committing_event_seq INTEGER NOT NULL DEFAULT 0;

-- Backfill pass run by the migration host as part of the V2.1 first-boot ceremony.
-- The migration emits AuditSchemaMigration before the first paired event is written.
```

The `DEFAULT 0` lets the column be added without rewriting every row; the backfill runs as a separate phase in the V2.1 first-boot ceremony (`§10`). A row with `last_committing_event_seq = 0` after backfill failed means "this row predates the paired protocol and the verifier should fall back to V1 semantics for its history" — flagged as `Finding::PreV21Row` by the offline verifier (not a chain integrity failure, but signalled).

### §3.4 Why a column instead of a transition-history table

| Option | Pros | Cons | Verdict |
| --- | --- | --- | --- |
| **A. One column per state-bearing table** (chosen) | Trivial schema; one `UPDATE … SET last_committing_event_seq = ?` per row touched; verifier check is a single `SELECT`; no growth in row count | Only the *latest* committing seq is stored; verifier cannot replay row history without parsing the chain | Sufficient for R-7 — verifier replays history from the chain and uses the column only to disambiguate orphans |
| **B. Per-row transition history table** (`task_transitions`, `session_transitions`, …) | Full row-history queryable in SQLite | Doubles write amplification (every transition writes the state row AND a history row); N new tables; massive schema churn | Rejected: the chain *is* the transition history. SQLite duplicating it serves no purpose for R-7 |
| **C. JSON column listing all committing seqs** | Full history in one column | JSON parsing in the hot admission path; SQLite JSON1 functions are slow at scale | Rejected: hot-path cost not justified by the benefit (which `B` already shows is non-essential) |

**A** is the chosen design.

---

## §4 — Event-pair classification (paired vs single)

Not every audit event participates in the paired protocol. The full classification is below. The classification is **load-bearing** — implementers must never invent a third class — and is enforced by the spec-graph lint (`v2-deep-spec.md §Spec-Graph Lint`):

| Class | Variants | Pattern |
| --- | --- | --- |
| **Paired (V2.1+)** — every variant in this class participates in `StateChangePending` → `<existing kind>` (with the three new fields) → `StateChangeRolledBack` | See §4.1 below | 3-event protocol per mutation |
| **Single (Phase-A rejection)** — emitted before any SQLite mutation; never paired | `FAIL_*Rejected` variants | 1 event; no pending |
| **Single (pure observability)** — no SQLite mutation; pure derived/derived-data | `InferenceRequested`, `InferenceCompleted`, `Heartbeat`, `KSBSnapshot`, `MaintenanceTickStarted`, `MaintenanceJobCompleted`, `MaintenanceJobSkipped`, `RaxisDoctorChecksRan` | 1 event |
| **Single (chain self-events)** — events the chain emits about itself; no SQLite involvement | `GenesisRecord`, `AuditChainCheckpoint` (V2.2+; see §11.2 alternative G), `AuditSegmentRotated`, `AuditSchemaMigration` | 1 event |
| **Single (notification dispatch outcomes)** — the `notification_dispatch` table is paired-class for state changes; but the *delivery* outcomes (`NotificationDelivered`, `NotificationDeliveryFailed`) are observability events that follow the dispatcher's idempotency record (which is paired) | See note below | 1 event each |

**Notification dispatch dual emission.** The dispatcher writes to `notification_dispatch` (a paired-class state table) before calling `OperatorNotificationChannel::deliver`, then emits `NotificationDelivered` / `NotificationDeliveryFailed` as a single (post-commit observation) event. This is consistent: the *state change* (the dispatcher recorded it took responsibility for the event) is paired; the *delivery outcome* (what the upstream said) is single because no SQLite row mutates after the upstream call.

### §4.1 Paired-class enumeration (V2.1)

The exhaustive list of state-mutating event kinds that gain the three new mandatory fields and participate in the protocol:

```
Session lifecycle:
  SessionCreated, SessionStateChanged, SessionRevoked, SessionExpired,
  SessionTokenInvalidated

Initiative lifecycle:
  InitiativeCreated, InitiativeApproved, InitiativeRejected,
  InitiativeAborted, InitiativeQuarantined, InitiativeCancelPending,
  InitiativeCancelled, InitiativeCompleted

Plan lifecycle (v2):
  PlanBundleSealed, PlanBundleAdmitted, PlanBundleRejected

Task lifecycle:
  TaskAdmitted, TaskStateChanged, TaskCompleted, TaskFailed,
  TaskAborted, TaskCancelled, TaskRetried

Sub-task / activation:
  SubTaskActivated, SubTaskDeactivated, SubTaskCompleted

Escalation lifecycle:
  EscalationSubmitted, EscalationApproved, EscalationDenied,
  EscalationConsumed, EscalationExpired,
  ApprovalTokenIssued, ApprovalTokenConsumed

Delegation lifecycle:
  DelegationGranted, DelegationRevoked, DelegationStaleOnNextUse

IntegrationMerge:
  IntegrationMergeRequested, IntegrationMergeApproved,
  IntegrationMergeApplied, IntegrationMergeRolledBack,
  IntegrationMergeBlocked

Verifier (v2):
  VerifierRunStarted, VerifierRunCompleted, VerifierRunFailed,
  VerifierWitnessSubmitted, VerifierEvictedForCidDrift

Circuit breaker (v2):
  ProviderBreakerStateChanged, ProviderBreakerProbeRecorded

Lane reservation (v2):
  LaneReservationAdmitted, LaneReservationReleased,
  LaneReservationOrphanReclaimed

Operator IPC writes:
  PolicyEpochAdvanced, PolicyAdvanceRejected, PolicyAdvanceFailed,
  OperatorIdentityRotated, OperatorEmergencyKeyAdded,
  OperatorEmergencyKeyRevoked, OperatorEmergencyRevocationApplied

Notification subsystem (v2):
  NotificationDispatchClaimed,                       // paired
  NotificationChannelDegraded                        // paired (writes notification_channel_health)

SMTP proxy state:
  SmtpProxyConnected, SmtpProxyMessageSent,
  SmtpProxyMessageRejected, SmtpProxyRateLimited,
  SmtpProxyDisconnected

Worktree lifecycle (v2 agent-disagreement):
  WorktreeAbandonedSalvageWindowOpened,
  WorktreeAbandonedSalvageCommitted,
  WorktreeAbandonedArchived,
  WorktreePurged

Operator quarantine (v2 key-revocation):
  OperatorQuarantineDirectiveAdded,
  OperatorQuarantineDirectiveExpired,
  OperatorQuarantineDirectiveCleared

Path-scope override:
  PathScopeOverrideApplied, PathScopeOverrideRevoked

Custom-tools (v2):
  CustomToolInvoked,                                  // writes custom-tool concurrency rows
  CustomToolQueueTimeout                              // writes the timeout state row

Provider model selection (v2):
  AliasResolved                                       // writes session-affinity pin

VM lifecycle (V2 SessionSpawnService):
  // 1:1 paired with each other across the lifetime of a VM.
  // Spawn writes the live-session row in the SessionSpawnService
  // table (in-memory only; SQLite is not the source of truth for
  // running-VM presence — `extensibility-traits.md §3.5`). Exit
  // removes that row. The pair is what `audit-paired-writes` lints
  // enforce ("every spawn has an exit; every exit has a spawn").
  SessionVmSpawned, SessionVmExited
```

**Out-of-scope events** (single, not paired): `AuditEventKind::InferenceRequested`, `AuditEventKind::InferenceCompleted`, all `FAIL_*` Phase-A rejections, `AuditEventKind::Heartbeat`, `AuditEventKind::KSBSnapshot`, `AuditEventKind::RaxisDoctorChecksRan`, `AuditEventKind::MaintenanceTickStarted/Completed/Skipped`, `AuditEventKind::GenesisRecord`, `AuditEventKind::AuditSegmentRotated`, `AuditEventKind::AuditSchemaMigration`, `AuditEventKind::IsolationSubstrateSelected` (boot-time substrate identity record, no state row), `AuditEventKind::IsolationFallbackBypass` (warning at boot, no state row), `AuditEventKind::NotificationDelivered`, `AuditEventKind::NotificationDeliveryFailed`, `AuditEventKind::NotificationTestSent` (the *test sent* is paired via `NotificationDispatchClaimed`; the *outcome* is single), `AuditEventKind::CredentialAccessed`, `AuditEventKind::CredentialRotated` (resolution / rotation observability emitted by `CredentialBackend`; no SQLite row mutates), `AuditEventKind::TransparentProxyAdmitted`, `AuditEventKind::TransparentProxyDenied` (admission outcome observability per `vm-network-isolation.md §3.2`), `AuditEventKind::CredentialProxyStarted`, `AuditEventKind::CredentialProxyStopped` (proxy-lifecycle observability per `credential-proxy.md §5`; the proxy registry row state-change goes through its own paired event), `AuditEventKind::DatabaseQueryExecuted`, `AuditEventKind::HttpProxyRequestExecuted` (per-request observability emitted by the credential proxies; no SQLite row mutates per query).

### §4.2 Spec-graph lint enforcement

`xtask spec-graph` (per `v2-deep-spec.md`) gains a new check: every variant of `AuditEventKind` MUST appear in either the paired-class list above OR in the explicit single-class list. A variant in neither list is a compile-error from the lint. New audit event kinds added in future PRs MUST update one of the two lists.

### §4.3 Compliance index — `AuditEventKind::` prefixed roster

The §4.1 paired-class enumeration uses bare variant names so the table reads cleanly; the spec-graph lint regex (`\bAuditEventKind::([A-Z][A-Za-z0-9]+)\b`) matches only the prefixed form. This subsection re-states every variant the lint must recognise, with the prefix attached and a one-line classification, so the lint can statically verify that no variant defined elsewhere in the spec corpus is unclassified here. New variants added in future PRs MUST be added here AND in either §4.1 (paired) or §4 prose (single).

**Paired-class roster (§4.1 mirror with prefixes):**
`AuditEventKind::SessionCreated`, `AuditEventKind::SessionStateChanged`, `AuditEventKind::SessionRevoked`, `AuditEventKind::SessionExpired`, `AuditEventKind::SessionTokenInvalidated`, `AuditEventKind::InitiativeCreated`, `AuditEventKind::InitiativeApproved`, `AuditEventKind::InitiativeRejected`, `AuditEventKind::InitiativeAborted`, `AuditEventKind::InitiativeQuarantined`, `AuditEventKind::InitiativeCancelPending`, `AuditEventKind::InitiativeCancelled`, `AuditEventKind::InitiativeCompleted`, `AuditEventKind::PlanBundleSealed`, `AuditEventKind::PlanBundleAdmitted`, `AuditEventKind::PlanBundleRejected`, `AuditEventKind::TaskAdmitted`, `AuditEventKind::TaskStateChanged`, `AuditEventKind::TaskCompleted`, `AuditEventKind::TaskFailed`, `AuditEventKind::TaskAborted`, `AuditEventKind::TaskCancelled`, `AuditEventKind::TaskRetried`, `AuditEventKind::SubTaskActivated`, `AuditEventKind::SubTaskDeactivated`, `AuditEventKind::SubTaskCompleted`, `AuditEventKind::EscalationSubmitted`, `AuditEventKind::EscalationApproved`, `AuditEventKind::EscalationDenied`, `AuditEventKind::EscalationConsumed`, `AuditEventKind::EscalationExpired`, `AuditEventKind::ApprovalTokenIssued`, `AuditEventKind::ApprovalTokenConsumed`, `AuditEventKind::DelegationGranted`, `AuditEventKind::DelegationRevoked`, `AuditEventKind::DelegationStaleOnNextUse`, `AuditEventKind::IntegrationMergeRequested`, `AuditEventKind::IntegrationMergeApproved`, `AuditEventKind::IntegrationMergeApplied`, `AuditEventKind::IntegrationMergeCompleted`, `AuditEventKind::IntegrationMergeRolledBack`, `AuditEventKind::IntegrationMergeBlocked`, `AuditEventKind::VerifierRunStarted`, `AuditEventKind::VerifierRunCompleted`, `AuditEventKind::VerifierRunFailed`, `AuditEventKind::VerifierWitnessSubmitted`, `AuditEventKind::VerifierEvictedForCidDrift`, `AuditEventKind::VerifierBlockedMerge`, `AuditEventKind::ProviderBreakerStateChanged`, `AuditEventKind::ProviderBreakerProbeRecorded`, `AuditEventKind::CircuitBreakerStateChanged`, `AuditEventKind::LaneReservationAdmitted`, `AuditEventKind::LaneReservationReleased`, `AuditEventKind::LaneReservationOrphanReclaimed`, `AuditEventKind::PolicyEpochAdvanced`, `AuditEventKind::PolicyAdvanceRejected`, `AuditEventKind::PolicyAdvanceFailed`, `AuditEventKind::OperatorIdentityRotated`, `AuditEventKind::OperatorKeyRotated`, `AuditEventKind::OperatorEmergencyKeyAdded`, `AuditEventKind::OperatorEmergencyKeyRevoked`, `AuditEventKind::OperatorEmergencyRevocationApplied`, `AuditEventKind::NotificationDispatchClaimed`, `AuditEventKind::NotificationChannelDegraded`, `AuditEventKind::SmtpProxyConnected`, `AuditEventKind::SmtpProxyMessageSent`, `AuditEventKind::SmtpProxyMessageRejected`, `AuditEventKind::SmtpProxyRateLimited`, `AuditEventKind::SmtpProxyDisconnected`, `AuditEventKind::WorktreeAbandonedSalvageWindowOpened`, `AuditEventKind::WorktreeAbandonedSalvageCommitted`, `AuditEventKind::WorktreeAbandonedArchived`, `AuditEventKind::WorktreePurged`, `AuditEventKind::OperatorQuarantineDirectiveAdded`, `AuditEventKind::OperatorQuarantineDirectiveExpired`, `AuditEventKind::OperatorQuarantineDirectiveCleared`, `AuditEventKind::PathScopeOverrideApplied`, `AuditEventKind::PathScopeOverrideRevoked`, `AuditEventKind::CustomToolInvoked`, `AuditEventKind::CustomToolQueueTimeout`, `AuditEventKind::AliasResolved`, `AuditEventKind::ArtifactExpired`, `AuditEventKind::ArtifactGCStarted`, `AuditEventKind::ArtifactGCCompleted`, `AuditEventKind::CandidateMergeTreeCreated`, `AuditEventKind::CandidateMergeTreeDiscarded`, `AuditEventKind::ChainTruncation`, `AuditEventKind::CredentialInjected`, `AuditEventKind::CredentialRegistered`, `AuditEventKind::CredentialRemoved`, `AuditEventKind::CredentialVerified`, `AuditEventKind::GitConsistencyRepaired`, `AuditEventKind::GitConsistencyVerified`, `AuditEventKind::IntentAdmittedFromQueue`, `AuditEventKind::IntentQueued`, `AuditEventKind::PushApprovalRequired`, `AuditEventKind::PushCompleted`, `AuditEventKind::PushRejected`, `AuditEventKind::ServiceInstalled`, `AuditEventKind::ServiceUninstalled`, `AuditEventKind::AdmissionQueueFull`, `AuditEventKind::PerOperatorQueueLimitReached`, `AuditEventKind::SessionVmSpawned`, `AuditEventKind::SessionVmExited`.

**Single-class roster (§4 prose mirror with prefixes):**
`AuditEventKind::InferenceRequested`, `AuditEventKind::InferenceCompleted`, `AuditEventKind::InferenceAttemptAborted`, `AuditEventKind::Heartbeat`, `AuditEventKind::KSBSnapshot`, `AuditEventKind::RaxisDoctorChecksRan`, `AuditEventKind::MaintenanceTickStarted`, `AuditEventKind::MaintenanceTickCompleted`, `AuditEventKind::MaintenanceTickSkipped`, `AuditEventKind::MaintenanceJobCompleted`, `AuditEventKind::MaintenanceJobFailed`, `AuditEventKind::MaintenanceJobSkipped`, `AuditEventKind::GenesisRecord`, `AuditEventKind::AuditSegmentRotated`, `AuditEventKind::AuditSchemaMigration`, `AuditEventKind::IsolationSubstrateSelected`, `AuditEventKind::IsolationFallbackBypass`, `AuditEventKind::NotificationDelivered`, `AuditEventKind::NotificationDeliveryFailed`, `AuditEventKind::NotificationTestSent`, `AuditEventKind::CredentialAccessed`, `AuditEventKind::CredentialRotated`, `AuditEventKind::TransparentProxyAdmitted`, `AuditEventKind::TransparentProxyDenied`, `AuditEventKind::CredentialProxyStarted`, `AuditEventKind::CredentialProxyStopped`, `AuditEventKind::DatabaseQueryExecuted`, `AuditEventKind::DatabaseQueryBlocked`, `AuditEventKind::HttpProxyRequestExecuted`, `AuditEventKind::KernelStarted`, `AuditEventKind::KernelStopped`, `AuditEventKind::KernelStopping`, `AuditEventKind::KernelReloaded`, `AuditEventKind::KernelReloadFailed`, `AuditEventKind::KernelCrashRecovered`, `AuditEventKind::EgressRequestAdmitted`, `AuditEventKind::EgressRequestRejected`, `AuditEventKind::DefaultsProposed`, `AuditEventKind::DryRunAdmitted`, `AuditEventKind::SecurityViolation`, `AuditEventKind::TokenLimitApproaching`, `AuditEventKind::TokenLimitGranted`, `AuditEventKind::TokenLimitDenied`, `AuditEventKind::TokenLimitExceeded`, `AuditEventKind::VerifierCredentialModeResolved`, `AuditEventKind::VerifierEgressAttempted`, `AuditEventKind::IsolationSubstrateRefused`.

**Note on dual-class variants:** A small number of variants appear in both rosters (e.g. `AuditEventKind::InitiativeCompleted`, `AuditEventKind::PolicyEpochAdvanced`) — those are paired-class in §4.1 (the kernel emits a paired sequence) but are also listed in the single-class roster because some specs reference them as observability-only emissions. The deduplication is a forthcoming editorial pass; for now the lint accepts a variant being listed in either roster.

---

## §5 — Offline verifier (independence-bearing standalone binary)

The offline verifier is the canonical `R-7` satisfaction artefact: an
auditor, compliance reviewer, or post-incident forensic investigator
holding only the JSONL chain segments and the operator's public key
must be able to verify chain integrity without a running RAXIS kernel
and without linking any kernel-side crate. **`R-7` requires
*independence*, and independence is enforced as a dependency
boundary** — the verifier ships as a standalone binary
(`raxis-audit-verify`) built from a leaf crate (`crates/audit-verify/`)
whose Cargo.toml dependency graph contains **no** kernel crate
(`raxis-store`, `raxis-policy`, `raxis-ipc`, `raxis-audit-tools`,
`raxis-types`).

The binary is **one-shot, not a daemon.** A background verifier that
emits "chain OK every 60 seconds" creates false confidence: the green
light means nothing if the daemon itself is compromised, stale, or
absent. The `R-7` property is a *point-in-time assertion by an
independent party*, not continuous self-attestation. Continuous
verification by the same kernel that produces the chain conflates
producer and verifier.

### §5.1 What the binary proves (independence-bound)

Given only `--chain <path glob>` and `--pubkey <operator-public.pem>`
(no SQLite snapshot, no kernel crate, no IPC), the standalone binary
provably establishes:

1. **Chain hash linkage.** Every event's `prev_sha256` matches the
   SHA-256 of the prior event's canonical bytes. A break is a critical
   `R-7` violation.
2. **Signature validity.** Every event's signature verifies against
   the operator pubkey supplied via `--pubkey`. (Multi-key chains
   accept a `--keyring` directory containing all valid pubkeys for the
   chain's lifetime.)
3. **Pairing integrity.** Every paired-class confirmed event references
   a real preceding `StateChangePending`; every `StateChangeRolledBack`
   references a real preceding pending; no pending references a
   different `intended_post_state_digest` than its confirmed's
   `actual_post_state_digest` claim. (`INV-AUDIT-PAIRED-02/03`.)
4. **Sequence monotonicity.** `seq` is contiguous across the supplied
   segments (gaps at segment boundaries permitted only at known
   rotation points marked by `AuditSegmentRotated`).
5. **Genesis anchoring.** The first event in the earliest segment is
   either `GenesisRecord` (with `prev_sha256 = 64 × 0x00`) or
   continues from a prior segment whose last event's hash matches.

What the standalone binary **cannot** prove without an additional
input:

- **Crash-orphan resolution.** Pending events without confirmed/
  rolled-back companions are reported as
  `Finding::OrphanIndeterminate`. The standalone binary does not link
  SQLite (per the dep boundary). Resolving orphans into
  `OrphanResolvedByStateSnapshot` vs `OrphanRolledBackInferred`
  requires SQLite consultation, which is delegated to either:

  - the kernel-side `recovery::reconcile_advisory` (which has direct
    SQLite access and runs at boot), OR
  - a forensic auditor passing `--state-export <json>` containing the
    relevant rows' `last_committing_event_seq` values, exported by
    `raxis audit export-state-for-verifier` (see `v1/cli-readonly.md`).

  The standalone binary's exit semantics are identical with or
  without the export: the chain-integrity properties (1)–(5) above are
  the `R-7` artefact; orphan resolution is a forensic refinement.

### §5.2 The algorithm

```rust
//! crates/audit-verify/src/lib.rs — reference implementation
//! Dependencies: sha2, ed25519-dalek, serde_json, serde, hex.
//! NO raxis-store, NO raxis-policy, NO raxis-ipc, NO raxis-types.

/// Resolve orphans against a state snapshot. The snapshot trait is
/// abstract over the concrete source so the kernel-side
/// `reconcile_advisory` (live SQLite) and the standalone binary
/// (JSON state-export from `raxis audit export-state-for-verifier`)
/// implement it differently. Crucially, the trait lives in this leaf
/// crate, so the standalone binary's dep boundary stays clean.
pub trait StateSnapshot {
    fn lookup_last_committing_event_seq(
        &self,
        table: &str,
        primary_key: &serde_json::Value,
    ) -> Option<u64>;
}

pub fn verify(
    jsonl: &[AuditEvent],
    pubkeys: &Keyring,                       // Ed25519 pubkeys keyed by fingerprint
    state: Option<&dyn StateSnapshot>,       // None = chain-only mode (default)
) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Phase 1 — chain-link verification (always runs).
    let mut prev_hash = GENESIS_HASH;
    for ev in jsonl {
        if ev.prev_sha256 != prev_hash {
            findings.push(Finding::ChainBreak {
                seq: ev.seq,
                expected: prev_hash,
                got: ev.prev_sha256,
            });
        }
        prev_hash = sha256_of_line(ev);
    }

    // Phase 1b — signature verification (always runs).
    for ev in jsonl {
        match pubkeys.verify(&ev.signer_fingerprint, &ev.canonical_bytes(), &ev.signature) {
            Ok(()) => { /* signature valid */ }
            Err(e) => findings.push(Finding::SignatureInvalid {
                seq:                 ev.seq,
                signer_fingerprint:  ev.signer_fingerprint,
                reason:              e.to_string(),
            }),
        }
    }

    // Phase 2 — pending/confirmed pairing.
    let mut pending_by_seq: BTreeMap<u64, &AuditEvent> = BTreeMap::new();
    for ev in jsonl {
        match &ev.kind {
            AuditEventKind::StateChangePending { pending_seq, .. } => {
                pending_by_seq.insert(*pending_seq, ev);
            }

            // The confirmed event is the existing kind augmented with
            // confirms_pending_seq. Verifier extracts that field
            // generically via the `Confirmable` trait.
            kind if kind.is_paired_class() => {
                let confirms_seq = kind.confirms_pending_seq().expect("paired class");
                let actual_digest = kind.actual_post_state_digest().expect("paired class");
                let pending = pending_by_seq.remove(&confirms_seq);

                match pending {
                    None => {
                        findings.push(Finding::ConfirmedWithoutPending {
                            confirmed_seq: ev.seq,
                            references: confirms_seq,
                        });
                    }
                    Some(p) => {
                        let expected_digest = match &p.kind {
                            AuditEventKind::StateChangePending {
                                intended_post_state_digest, ..
                            } => intended_post_state_digest,
                            _ => unreachable!(),
                        };
                        if expected_digest != &actual_digest {
                            findings.push(Finding::DigestMismatch {
                                pending_seq: confirms_seq,
                                confirmed_seq: ev.seq,
                                intended: *expected_digest,
                                actual: actual_digest,
                            });
                        }
                    }
                }
            }

            AuditEventKind::StateChangeRolledBack {
                rolls_back_pending_seq, reason, reason_detail, ..
            } => {
                let pending = pending_by_seq.remove(rolls_back_pending_seq);
                if pending.is_none() {
                    findings.push(Finding::RolledBackWithoutPending {
                        rollback_seq: ev.seq,
                        references: *rolls_back_pending_seq,
                    });
                }
                // Otherwise: pending matched and was removed — clean rollback.
            }

            _ => { /* single-class events; ignore here */ }
        }
    }

    // Phase 3 — orphan resolution. Anything still in pending_by_seq is
    // an unresolved orphan. Without a state snapshot the verifier
    // reports OrphanIndeterminate (non-critical; the chain itself is
    // intact). With a snapshot the verifier disambiguates committed
    // vs crash-rolled-back. The standalone binary defaults to
    // chain-only (no snapshot); --state-export switches to resolution
    // mode using a JSON export from raxis audit export-state-for-verifier.
    for (pending_seq, pending) in pending_by_seq {
        let row_keys = match &pending.kind {
            AuditEventKind::StateChangePending { intended_writes, .. } => intended_writes,
            _ => unreachable!(),
        };

        match state {
            None => {
                findings.push(Finding::OrphanIndeterminate {
                    pending_seq,
                    note: "chain-only verification; pass --state-export for resolution",
                });
            }
            Some(snap) => {
                let mut all_committed = true;
                for desc in row_keys {
                    let observed = snap
                        .lookup_last_committing_event_seq(&desc.table, &desc.primary_key);
                    match observed {
                        Some(seq) if seq == pending_seq => { /* committed */ }
                        Some(_) => { all_committed = false; break; }   // committed by a different seq
                        None    => { all_committed = false; break; }   // row never appeared
                    }
                }
                if all_committed {
                    findings.push(Finding::OrphanResolvedByStateSnapshot { pending_seq });
                } else {
                    findings.push(Finding::OrphanRolledBackInferred { pending_seq });
                }
            }
        }
    }

    findings
}
```

### §5.3 Finding classification

```rust
pub enum Finding {
    /// Hash chain link broken. R-7 critical failure.
    ChainBreak { seq: u64, expected: [u8; 32], got: [u8; 32] },

    /// Event signature did not verify against the supplied keyring.
    /// R-7 critical: chain provenance is broken.
    SignatureInvalid {
        seq:                u64,
        signer_fingerprint: [u8; 32],
        reason:             String,
    },

    /// Confirmed event references a pending that doesn't exist.
    /// R-7 critical: the chain has a confirmed without pre-announcement.
    ConfirmedWithoutPending { confirmed_seq: u64, references: u64 },

    /// Rollback event references a pending that doesn't exist.
    /// R-7 critical: same shape as above.
    RolledBackWithoutPending { rollback_seq: u64, references: u64 },

    /// Confirmed's actual_post_state_digest differs from the
    /// pending's intended_post_state_digest. The kernel announced
    /// one state change and committed a different one. R-7 critical:
    /// indicates kernel buggery worth investigating.
    DigestMismatch {
        pending_seq:   u64,
        confirmed_seq: u64,
        intended:      [u8; 32],
        actual:        [u8; 32],
    },

    /// Pending committed (verified by state snapshot's
    /// last_committing_event_seq). The chain is missing the
    /// confirmed event, but the state change is real and recorded.
    /// Recovery (advisory) should write a synthetic confirmed event.
    OrphanResolvedByStateSnapshot { pending_seq: u64 },

    /// Pending did NOT commit (state snapshot shows the row was never
    /// updated to the pending's seq, OR was updated to a different
    /// seq, OR the row doesn't exist). The pending was crash-rolled-back.
    /// Operator UI should display this as "attempted, did not commit."
    OrphanRolledBackInferred { pending_seq: u64 },

    /// Orphan exists; no state snapshot was supplied. Chain integrity
    /// is intact (the orphan is a known, named pending in the chain),
    /// but the standalone binary cannot determine commit vs rollback
    /// without a state snapshot. Non-critical: report and continue.
    /// To resolve, run `raxis audit export-state-for-verifier` and
    /// pass the resulting JSON via --state-export.
    OrphanIndeterminate { pending_seq: u64, note: &'static str },

    /// Row in SQLite has last_committing_event_seq = 0 — predates
    /// the V2.1 paired protocol. Verifier falls back to V1 semantics
    /// for this row's history. NOT a chain integrity failure.
    PreV21Row { table: String, primary_key: serde_json::Value },
}

impl Finding {
    pub fn is_critical(&self) -> bool {
        matches!(self,
            Finding::ChainBreak { .. } |
            Finding::SignatureInvalid { .. } |
            Finding::ConfirmedWithoutPending { .. } |
            Finding::RolledBackWithoutPending { .. } |
            Finding::DigestMismatch { .. }
        )
    }
}
```

### §5.4 Standalone binary (`raxis-audit-verify`) — independence boundary

The standalone binary lives in a leaf crate with strict dep limits.
The dep boundary **is** the independence guarantee — any crate that
the verifier transitively links is part of the trust base for the
verification result. Linking the kernel's storage or IPC code would
make the verdict trivially compromisable by a tampered kernel.

#### §5.4.1 Crate manifest

```toml
# crates/audit-verify/Cargo.toml
[package]
name        = "raxis-audit-verify"
version     = "0.1.0"
edition     = "2021"
description = "Independent R-7 verifier for the RAXIS audit chain"
license     = "Apache-2.0"

[lib]
name = "raxis_audit_verify"
path = "src/lib.rs"

[[bin]]
name = "raxis-audit-verify"
path = "src/bin/raxis-audit-verify.rs"

[dependencies]
sha2          = { version = "0.10", default-features = false }
ed25519-dalek = { version = "2",    default-features = false, features = ["pem"] }
serde         = { version = "1",    default-features = false, features = ["derive"] }
serde_json    = { version = "1",    default-features = false, features = ["std"] }
hex           = { version = "0.4",  default-features = false, features = ["std"] }
clap          = { version = "4",    default-features = false, features = ["std", "derive"] }
glob          = "0.3"

# DELIBERATELY ABSENT (load-bearing for INV-AUDIT-PAIRED-05):
#   raxis-store, raxis-policy, raxis-ipc, raxis-types, raxis-audit-tools,
#   raxis-kernel, rusqlite, tokio, anyhow, thiserror.
```

A CI lint (`xtask audit-verify-deps`, see §13.3) parses `cargo metadata`
output for `raxis-audit-verify` and fails if any crate name in the
transitive dependency closure begins with `raxis-` other than
`raxis-audit-verify` itself, or matches `rusqlite`, `tokio`, or
`reqwest`. This is the dep boundary check that makes
`INV-AUDIT-PAIRED-05` operational at build time, not just contractual.

#### §5.4.2 CLI surface

```
raxis-audit-verify
    --chain   <PATH-OR-GLOB>...     One or more JSONL segment files.
                                    Glob patterns expanded; multiple
                                    --chain flags accumulate.
    --pubkey  <PEM-PATH>            Operator Ed25519 public key.
                                    For multi-key chains, see --keyring.
    --keyring <DIR-PATH>            Directory of operator pubkeys; one
                                    file per signer, named after the
                                    signer's fingerprint hex prefix.
                                    Required for chains spanning a
                                    key rotation.
    --state-export <JSON-PATH>      Optional state-snapshot JSON
                                    exported by `raxis audit
                                    export-state-for-verifier`.
                                    Enables orphan resolution; absent
                                    means chain-only mode.
    --json-output                   Emit machine-readable findings
                                    JSON in addition to the human
                                    summary.
    --quiet                         Suppress the verbose progress
                                    summary; print only verdict.
    --strict-monotonic              Treat any seq gap (including across
                                    segment boundaries without an
                                    AuditSegmentRotated marker) as a
                                    chain break.
```

Example invocation matching the user-facing example:

```text
$ raxis-audit-verify \
      --chain  /var/lib/raxis/audit/segment-*.jsonl \
      --pubkey /etc/raxis/operator-public.pem

raxis-audit-verify v0.1.0 — R-7 chain integrity check
Chain        : 12,847 records, segments 000-002 (1.4 MiB)
Sequence     : monotonic, no gaps
Linkage      : SHA-256 chain intact (12,846 links verified)
Signatures   : 12,847/12,847 verified against operator key fp:7d2c…
Pairing      : 4,219 paired (StateChangePending → confirmed)
               7 pending without confirmed (chain-only mode; see below)
               0 dangling confirmed
               0 dangling rolled-back
               0 digest mismatches
Orphans      : 7 indeterminate — pass --state-export to resolve

Verdict      : INTACT
```

#### §5.4.3 Exit codes

| Code | Meaning |
| --- | --- |
| `0`  | Verdict `INTACT`. No critical findings. Orphans may exist; chain integrity is provable from the JSONL alone. |
| `2`  | Operator/CLI error (missing files, malformed pubkey, glob expanded to zero files). |
| `3`  | Critical finding — chain break, signature invalid, dangling confirmed, dangling rollback, or digest mismatch. The chain itself is corrupted; forensic investigation required. |
| `4`  | Internal error (panic, OOM, JSON parse failure on supposedly valid event). Tooling bug; not a verdict. |

Exit code 3 is the strict-`R-7` signal: any external auditor invoking
the binary against the chain files alone can take a 3 as proof of
chain corruption. The binary never emits exit code 3 on
`OrphanIndeterminate` or `OrphanRolledBackInferred` —  those are
chain-intact outcomes by design.

#### §5.4.4 Why one-shot, not a daemon

Three reasons, formalised:

1. **`R-7` requires independence, not continuous attestation.** A
   running daemon is part of the system; an auditor running the binary
   against archived chain files is not. The whole point of the
   property is "any party with the files can verify" — a daemon
   centralises trust on the running daemon. (`v2/audit-paired-writes.md`
   §1.1 strict reading.)

2. **Continuous green lights are noise.** A daemon emitting "chain OK"
   every minute trains operators to ignore the signal. The verifier's
   value is its discreteness: it answers a specific question (`is the
   chain intact at this point in time`) at a specific moment chosen
   by an operator or auditor.

3. **Daemon attack surface adds nothing.** A continuous verifier has
   IPC, scheduling, and authentication concerns the one-shot doesn't.
   Operationally, periodic verification is `cron` or systemd timer
   pointing at `raxis-audit-verify`; if that's the operational pattern,
   a separate daemon adds zero value over the timer.

#### §5.4.5 Companion CLI command (kernel-linked)

The standalone binary's chain-only mode is sufficient for `R-7`. For
operators who want orphan resolution from a running deployment, a
companion `raxis audit export-state-for-verifier` command (defined in
`v1/cli-readonly.md §5.5.19`) exports the
`last_committing_event_seq` column for every state-bearing row into
a JSON file the standalone binary consumes via `--state-export`.

The export command is part of `raxis-cli` (it links `raxis-store` to
read SQLite). The export's output **is** consumable by the
dependency-bounded standalone binary, which keeps the trust boundary
intact:

```text
operator-host           forensic-host (independent)
+--------------+         +-------------------------+
| raxis-cli    |         | raxis-audit-verify      |
| └─ export-   |  JSON   | └─ reads JSON +         |
|    state     ├────────►|    JSONL chain +        |
|              |  files  |    operator pubkey      |
+--------------+         +-------------------------+
                                    │
                                    ▼
                          chain INTACT/CORRUPTED
                          (kernel not involved)
```

The forensic host trusts the JSON export only insofar as the operator
host trusts its own SQLite — the export itself is content-addressed
(SHA-256 of the canonical JSON is part of the verdict output) and
signed by the kernel at export time. A tampered export would
mis-resolve orphans into the wrong category but cannot fabricate
chain breaks or signature failures (those are computed from the
chain file alone).

### §5.6 Honesty about what offline verification can prove

The standalone binary in chain-only mode (default; no `--state-export`)
proves the following properties **without depending on the kernel**:

1. **Chain integrity.** Hash links are intact end-to-end.
2. **Signature integrity.** Every event was signed by a key in the
   supplied `--pubkey` / `--keyring`.
3. **Pairing integrity.** Every confirmed/rolled-back has a preceding
   pending; every pending has a confirmed, a rolled-back, or is
   reported as `OrphanIndeterminate`.
4. **Digest integrity.** Every confirmed event's `actual_post_state_digest` matches its pending's `intended_post_state_digest`.

These four are the canonical R-7 satisfaction set. The chain-only mode
exit code 0 is the strict-`R-7` evidence an external auditor needs.

The standalone binary in resolution mode (`--state-export <path>`)
additionally proves:

5. **Orphan resolution.** Every unresolved orphan is annotated as
   `OrphanResolvedByStateSnapshot` (committed) or
   `OrphanRolledBackInferred` (rolled back). The state-export file is
   produced by `raxis audit export-state-for-verifier` (kernel-linked
   tooling, but its output is consumable by the dep-bounded standalone
   binary).

What the verifier **cannot** prove:

- That the row content the kernel claims it wrote is what was actually committed. (To prove this, the verifier would need to hash the rows in the SQLite snapshot at the cited `sqlite_commit_id` and compare against `actual_post_state_digest` — this is **out-of-scope** for V2.1's offline verifier. V2.2's `AuditChainCheckpoint` (alternative G in §11) and a content-rehash pass would close this gap.)
- That no row mutated *outside* of a paired transaction. (A buggy kernel that wrote to SQLite without writing a pending event would leave audit-silent rows. The `last_committing_event_seq = 0` sentinel detects this for new rows; the migration's NOT-NULL DEFAULT 0 makes the silence visible. Existing rows touched without a pending fall back to `PreV21Row`.)

These limitations are explicit and intentional. V2.1 closes the strict R-7 gap for the *transition events*; V2.2 will close it for the *post-state content*.

### §5.7 Relationship to `raxis verify-chain` (subprocess wrapper)

The `raxis verify-chain` CLI subcommand
(`v1/cli-readonly.md §5.5.13`, part of `raxis-cli`) is a convenience
wrapper that **shells out to `raxis-audit-verify` as a subprocess**
rather than importing the verifier library directly. The
verification itself is performed by the dep-bounded binary, in its
own process, with its own restricted dependency closure. The CLI's
job is reduced to:

1. **Argument translation.** Resolve operator-facing conveniences
   (data-dir defaults, `--from <seq>`, `--quick`) to the standalone
   binary's `--chain` / `--pubkey` / `--state-export` arguments.
2. **State export, if requested.** When the operator passes
   `--with-live-state`, the CLI first invokes
   `raxis audit export-state-for-verifier` to a tempfile, then
   passes the path via `--state-export` to the spawned binary.
3. **Output formatting.** Render the binary's verdict in the same
   style as the rest of the CLI (colour, JSON, etc.). The CLI
   suffixes every verdict line with `[verified by
   raxis-audit-verify v<X.Y.Z>]` so the trust path is visible.
4. **Verdict propagation.** The CLI's own exit code is the
   subprocess's exit code, unchanged. A binary exit `3` is a CLI
   exit `3`. No kernel-side code can mask a critical finding.

**Why subprocess, not library import.** Even though the verifier
algorithm is "the same code" in either model, subprocess invocation
has structural advantages:

- **The trust path bottoms out at the dep-bounded binary, not the
  CLI's claim about it.** A compromised `raxis-cli` cannot lie about
  the verification result — the CLI's exit code is the binary's
  exit code, end-to-end.
- **Process isolation.** The standalone binary runs in its own
  process with no shared memory or state with the kernel-linked CLI.
  An exploit in `raxis-cli`'s argument parsing or output formatter
  has no path to influence the verification.
- **Operationally identical to manual invocation.** What the CLI does
  is what an operator could do manually. Reducing the CLI to a thin
  wrapper means there's no "CLI-only" verification path; every
  verdict is reproducible by the operator running the binary
  directly with the same arguments.
- **Versioning is decoupled.** Patch upgrades to `raxis-audit-verify`
  ship without recompiling `raxis-cli` (and vice-versa). A site that
  wants to pin a specific verifier version for compliance can do so
  without rebuilding the kernel side.

**The kernel-side `reconcile_advisory` is the one exception.** It
imports `raxis_audit_verify::verify` directly (in-process) because
it runs at kernel boot, before any subprocess machinery is up, and
the kernel must be self-contained at boot to avoid bootstrap
circularity. This is acceptable because `reconcile_advisory` is
explicitly NOT R-7-bearing — it is advisory recovery; the
chain-integrity verdict that ships to operators always comes through
the standalone binary (either directly or via the CLI subprocess
wrapper).

**Three call sites, one R-7 artefact.**

| Caller | How it invokes the verifier | Crate it transitively links | R-7-bearing verdict? |
| --- | --- | --- | --- |
| `raxis-audit-verify` (standalone bin) | direct (it IS the binary) | `crates/audit-verify` only | **Yes** |
| `raxis verify-chain` (raxis-cli) | **subprocess: spawns `raxis-audit-verify`** | full kernel stack (CLI side); leaf-crate-only (verifier side) | **Yes — the verdict comes from the subprocess** |
| `recovery::reconcile_advisory` (kernel boot) | library import (in-process) | full kernel stack | No (advisory only; output is recovery synthesis events, not a "verdict") |

This is the design principle: **one algorithm, one library, two
call sites that produce R-7 verdicts** (both bottoming out at the
dep-bounded binary), **plus one in-process advisory caller** at
kernel boot. The independence property is the dep boundary on the
binary; both R-7-bearing call sites flow through that boundary.

---

## §6 — Recovery becomes advisory

### §6.1 What recovery did in V1

V1's `kernel/src/recovery.rs::reconcile` ran on every kernel start. It walked the JSONL chain forward, walked SQLite's "last transition" markers, and synthesised audit events for any state change where SQLite was advanced but the chain was silent. The kernel could not be safely run without it: the chain would otherwise diverge from state.

### §6.2 What recovery does in V2.1

In V2.1, recovery is **advisory**. Its only job is to keep the chain self-resolving for *future* offline verifications: it scans unresolved pending events and writes the missing `confirmed` (or `StateChangeRolledBack`) so the next forensic verifier doesn't need to consult SQLite for these orphans.

```rust
//! kernel/src/recovery.rs (revised)
//!
//! Recovery imports the algorithm from the leaf crate
//! `crates/audit-verify` (no kernel deps). It supplies a live
//! SQLite-backed `StateSnapshot` impl since recovery runs inside
//! the kernel process and has direct store access. The standalone
//! binary uses a different `StateSnapshot` impl backed by a JSON
//! state-export — same algorithm, two snapshot sources.

use raxis_audit_verify::{verify, Finding, StateSnapshot};

struct LiveSqliteSnapshot<'a>(&'a Store);

impl<'a> StateSnapshot for LiveSqliteSnapshot<'a> {
    fn lookup_last_committing_event_seq(
        &self,
        table: &str,
        primary_key: &serde_json::Value,
    ) -> Option<u64> {
        self.0.lookup_last_committing_event_seq(table, primary_key)
    }
}

pub async fn reconcile_advisory(
    audit: Arc<dyn AuditSink>,
    store: Arc<Store>,
    keyring: &Keyring,
) -> Result<RecoveryReport, RecoveryError> {
    let chain = audit.read_range(0..u64::MAX).await?;
    let snap  = LiveSqliteSnapshot(&store);
    let findings = verify(&chain, keyring, Some(&snap));

    let mut report = RecoveryReport::default();
    for finding in findings {
        match finding {
            Finding::OrphanResolvedByStateSnapshot { pending_seq } => {
                let synthesised = synthesise_confirmed_for(pending_seq, &snap)?;
                audit.emit_recovered_confirmed(synthesised).await?;
                report.synthesised_confirmed += 1;
            }
            Finding::OrphanRolledBackInferred { pending_seq } => {
                let rb = AuditEventKind::StateChangeRolledBack {
                    rolls_back_pending_seq: pending_seq,
                    reason:                 RollbackReason::CrashInferred,
                    reason_detail:          "synthesised by recovery::reconcile_advisory".into(),
                    rolled_back_at_ms:      now_ms(),
                };
                audit.emit_recovered_rollback(rb).await?;
                report.synthesised_rollback += 1;
            }
            Finding::OrphanIndeterminate { .. } => unreachable!("live snapshot supplied"),
            Finding::PreV21Row { .. } => { /* expected; ignore */ }
            crit if crit.is_critical() => {
                report.critical.push(crit);
            }
            _ => {}
        }
    }

    if !report.critical.is_empty() {
        // Critical findings during recovery (chain break, signature
        // invalid, dangling confirmed/rollback, digest mismatch) are
        // operator-attention events, not auto-fixable. The kernel
        // refuses to start until the operator clears the boot block
        // via the chain-state-bound acknowledgement protocol below.
        if let Some(ack) = read_signed_acknowledgement(&data_dir)? {
            // Acknowledgement is bound to the SPECIFIC chain state
            // that was verified. If the chain head moved between
            // ack-time and now, the binding fails closed — the
            // operator must re-verify and re-sign.
            let now_chain_head_digest = sha256_of_line(chain.last().expect("non-empty"));
            if ack.chain_head_digest != now_chain_head_digest {
                return Err(RecoveryError::AcknowledgementStale {
                    ack_head:  ack.chain_head_digest,
                    now_head:  now_chain_head_digest,
                });
            }
            // Acknowledgement must have come from a recent run of
            // raxis-audit-verify; the verdict hash MUST match the
            // findings recovery just observed. This is the
            // "matches what reconcile_advisory itself observed"
            // check — if the binary said INTACT but recovery sees
            // critical findings, the operator's view is stale.
            let now_verdict_hash = hash_findings_canonical(&report.critical);
            if ack.verdict_hash != now_verdict_hash {
                return Err(RecoveryError::AcknowledgementVerdictMismatch {
                    ack_verdict:  ack.verdict_hash,
                    now_verdict:  now_verdict_hash,
                });
            }
            keyring.verify(&ack.signer_fingerprint, &ack.canonical_bytes(), &ack.signature)
                .map_err(|e| RecoveryError::AcknowledgementSignatureInvalid(e))?;
            // All checks passed: the operator has independently
            // verified, the chain hasn't moved, and the verdict
            // matches. Boot proceeds with the critical findings
            // recorded in the chain (NOT auto-resolved — the
            // operator's signed acknowledgement is the audit trail).
            audit.emit(AuditEventKind::CriticalFindingsAcknowledged { ack }).await?;
            return Ok(report);
        }
        return Err(RecoveryError::CriticalFindings(report));
    }

    Ok(report)
}
```

The `AcknowledgeCriticalPayload` schema is:

```rust
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AcknowledgeCriticalPayload {
    /// Hex SHA-256 of `raxis-audit-verify`'s canonical findings
    /// JSON output (machine-readable, --json-output).
    pub verdict_hash:        [u8; 32],

    /// SHA-256 of the last event in the chain at verify time.
    /// Binds the acknowledgement to a specific chain state; the
    /// kernel rejects the ack if the chain head has moved.
    pub chain_head_digest:   [u8; 32],

    /// Last seq covered by the verifier; redundant with
    /// chain_head_digest but useful for human display.
    pub chain_head_seq:      u64,

    /// Version of `raxis-audit-verify` that produced the verdict.
    /// Operator can be required to use a specific version per
    /// policy.toml.
    pub verifier_version:    String,

    /// Operator's reason for acknowledging (free-text; logged for
    /// audit). e.g. "chain break at seq 4217 was caused by failed
    /// disk in primary; offline-restored from off-site backup,
    /// see incident #2026-04-12-IO".
    pub reason_detail:       String,

    /// Operator's certificate fingerprint (for signature
    /// verification by the kernel).
    pub signer_fingerprint:  [u8; 32],

    /// UNIX timestamp at signature time. Kernel rejects acks
    /// older than `acknowledgement_max_age_secs` (policy default:
    /// 3600 s — operator must re-verify if they take longer than
    /// an hour to clear the boot block).
    pub signed_at_unix_secs: u64,

    /// Ed25519 signature over the canonical CBOR encoding of
    /// the above fields.
    pub signature:           [u8; 64],
}
```

The `verdict_hash` and `chain_head_digest` together close the
"verify clean, swap chain, present stale ack" attack: even if an
attacker controls the operator's host between verification and
kernel restart, the kernel re-verifies the chain via
`reconcile_advisory` and refuses any acknowledgement whose
`chain_head_digest` doesn't match what the kernel itself just
observed. The ack therefore proves "the operator verified THIS chain
(byte-identical), and consciously accepted these critical findings,"
not just "the operator ran the binary at some point."

A new `RollbackReason::CrashInferred` variant captures the case where the synthesis is recovery's inference rather than a deliberate kernel decision. An offline verifier can distinguish recovery-synthesised rollbacks from real ones by this reason value — useful for forensic timelines.

### §6.3 Why advisory is the right design for R-7

The strict R-7 reading requires that integrity **MUST NOT depend on continued operation of the authority**. With paired writes:

- If recovery never runs, the chain still has every `pending`. The forensic verifier with a SQLite snapshot still resolves every orphan. **R-7 is satisfied.**
- If recovery runs, the chain becomes self-resolving (no SQLite consultation needed for those orphans on subsequent verifications). **A strict improvement, not a requirement.**

This is exactly what "MUST NOT depend on" means: the chain works without the kernel; the kernel can optionally make it work *better*.

---

## §7 — Failure modes (every error path explicitly treated)

Each crash window and each error path produces a deterministic outcome. The verifier handles every case.

### §7.1 Crash before pending fsync

| State after crash | Resolution |
| --- | --- |
| JSONL: nothing new written. SQLite: unchanged. | Nothing happened. The intent is treated as never-admitted; the planner's retry succeeds normally. |

### §7.2 Crash after pending fsync, before BEGIN IMMEDIATE

| State after crash | Resolution |
| --- | --- |
| JSONL: `pending(X)`. SQLite: unchanged. | Verifier consults SQLite: `last_committing_event_seq` for the row keys does not match `pending_seq`. → `OrphanRolledBackInferred`. Recovery (advisory) writes `StateChangeRolledBack { reason: CrashInferred }` for chain self-resolution. |

### §7.3 Crash mid-BEGIN IMMEDIATE (before COMMIT)

| State after crash | Resolution |
| --- | --- |
| JSONL: `pending(X)`. SQLite: WAL frame written but COMMIT never returned; WAL recovery on SQLite open rolls back. | Same as §7.2. SQLite row's `last_committing_event_seq` is unchanged. → `OrphanRolledBackInferred`. |

### §7.4 Crash after COMMIT, before confirmed fsync

| State after crash | Resolution |
| --- | --- |
| JSONL: `pending(X)`. SQLite: row updated, `last_committing_event_seq = X`. | Verifier consults SQLite: match. → `OrphanResolvedByStateSnapshot`. Recovery (advisory) writes the synthetic confirmed event. |

### §7.5 SQLite returns CONSTRAINT (deliberate rollback)

| State after error | Action |
| --- | --- |
| JSONL: `pending(X)`. SQLite: unchanged (transaction rolled back). | Kernel writes `StateChangeRolledBack { rolls_back_pending_seq: X, reason: ConstraintViolation, reason_detail: "<sqlite_text>" }` and fsyncs. |

The kernel returns a structured error to the planner (per existing `IntentResponse::Rejected` shape) **after** the rollback event is fsync'd. Returning before fsync would let the planner observe a rejection that's unrecorded if the kernel crashes immediately after the response.

### §7.6 SQLite returns IOERR / FULL / NOMEM

| State after error | Action |
| --- | --- |
| JSONL: `pending(X)`. SQLite: unknown — could be partial. | Kernel writes `StateChangeRolledBack { reason: StorageFault }` and fsyncs. SQLite recovery on next start reconciles WAL. If the next-start SQLite shows the row at `last_committing_event_seq = X`, that overrides the rollback record — the verifier flags this as a `Finding::DigestMismatch`-class anomaly worth investigating, BUT it's resolvable without the kernel running again. |

This is the only failure mode where the chain and SQLite can disagree about whether a transaction committed; it's recorded as a finding for operator attention, not as silent data loss.

### §7.7 BEGIN IMMEDIATE lock timeout

| State | Action |
| --- | --- |
| JSONL: `pending(X)`. SQLite: lock unavailable, no transaction started. | Kernel writes `StateChangeRolledBack { reason: LockTimeout }` and fsyncs. The intent is rejected to the planner with `FAIL_BEGIN_IMMEDIATE_TIMEOUT`. |

### §7.8 Confirmed-event fsync fails (rare)

| State | Action |
| --- | --- |
| SQLite: committed. JSONL: confirmed write returned an OS-level error or fsync failed. | Kernel retries the confirmed write up to 3 times with 100ms backoff. If retry exhausts, kernel logs to stderr, emits a structured panic via `process::abort()` after one final fsync attempt (so any successful retry is durable), and exits with code `137`. The next kernel start runs `reconcile_advisory`, which observes `last_committing_event_seq = X` matches the orphan pending and synthesises the confirmed event. |

The kernel **never** silently returns success to the planner without confirming the audit chain has the confirmed event durably written. If the kernel cannot durably record the confirmation, it would rather crash than misrepresent its state.

### §7.9 Pending-event fsync fails

| State | Action |
| --- | --- |
| JSONL: write returned error. SQLite: unchanged (Phase B1 not started). | Kernel returns `FAIL_AUDIT_PENDING_FSYNC` to the planner. SQLite is untouched; no recovery work needed; the planner retries. |

### §7.10 Two intents in flight; one pending observed by other's transaction

A subtle case: pending(X) is fsync'd, BEGIN IMMEDIATE is held, then a different intent's pending(Y) is fsync'd before X's COMMIT. The two pendings are sequenced in the chain by their seq numbers; their COMMITs may interleave (Y's commit may land first if Y is a different table or different row). The chain order does not match the SQLite-commit order in this case.

This is **fine**. The chain order is the chain's authoritative ordering. The `sqlite_commit_id` field on each confirmed event reveals SQLite's actual ordering. A verifier reproducing SQLite state at a specific `sqlite_commit_id` uses that field; replaying the chain in seq order gives the chain's narrative; the two views are reconcilable.

What the kernel must NOT do is reorder pendings to match SQLite ordering — that would let an attacker induce reordering by manipulating BEGIN IMMEDIATE timing.

---

## §8 — Performance and the +1 fsync cost

### §8.1 The cost in steady state

V1: 2 fsyncs per state-mutating intent (SQLite COMMIT, JSONL append).

V2.1: 3 fsyncs per state-mutating intent (JSONL pending, SQLite COMMIT, JSONL confirmed).

On a typical NVMe with `synchronous=FULL`, each fsync costs ~1–10ms (median ~2ms). The +1 fsync adds ~2ms latency per intent; on a workload bottlenecked by intent-admission throughput, this is roughly a 50% steady-state cost.

### §8.2 Why this cost is acceptable

- **R-7 priority.** The trade is "+50% intent latency for structural R-7 satisfaction." Compliance-driven and security-critical deployments accept this; performance-driven deployments would not have chosen RAXIS.
- **Most workloads are not admission-bottlenecked.** Intent admission is typically gated by `BEGIN IMMEDIATE` lock contention, which is seconds-not-milliseconds in adversarial cases. The +1 fsync is in the noise of normal operation.
- **Non-state-mutating events are unaffected.** `InferenceRequested`, `Heartbeat`, etc. remain single-event with one fsync.

### §8.3 Group-commit option (deferred to V2.2)

A future optimisation: amortise the pending fsync over a small batch of pendings (e.g., up to 16 or 5ms timeout). This trades a small amount of first-in-batch latency for higher steady-state throughput. The pattern:

```
T0: collect intent A's pending (not yet fsync'd)
T0+1ms: collect intent B's pending (not yet fsync'd)
T0+2ms: collect intent C's pending
T0+5ms: batched fsync; all three pendings durable; release BEGIN IMMEDIATE for each
```

This optimisation is **explicitly deferred to V2.2** because it complicates the "pending immediately precedes its commit" invariant. V2.1 ships with one-fsync-per-pending for clarity. The conformance kit (`§13`) verifies this at the protocol level — V2.2 would loosen the conformance test before introducing the batching.

### §8.4 Skip-pending for low-stakes events (rejected)

An alternative optimisation: don't emit pending for "low-stakes" event kinds (e.g., breaker probes, heartbeats). **Rejected.** The whole point of the protocol is that *every* state-mutation has a pending; carving out exceptions reintroduces the V1 R-7 gap for the carved-out events. The classification is binary: state-mutating or not.

---

## §9 — Threat model — why pre/post state digests matter

The pending event's `pre_state_digest` and `intended_post_state_digest` are not decorative. They close two attack vectors that pure ordering does not.

### §9.1 Attack — phantom manufacture by induced crash

**Scenario.** An attacker who can crash the kernel (e.g., trigger a panic via a malformed but admittable intent, or stop the host via OS-level access) wants to mask a real action.

**Without pre/post digests.** The attacker submits intent A (real, harmful). The kernel writes pending(A). The attacker crashes the kernel before COMMIT. The chain has pending(A) without confirmed(A). Now the attacker walks the post-crash chain to a forensic team and says: "See — the kernel attempted A but didn't commit. This is a known false-positive; the system was crashed mid-write." The forensic team has no way to disprove this without access to the *actual* outcome.

**With pre/post digests.** The pending(A) carries `pre_state_digest` = H of (rows the kernel claimed to read pre-tx). The forensic team consults the SQLite snapshot: if the rows at `last_committing_event_seq < pending_seq` actually had the pre-state the kernel claimed, AND `last_committing_event_seq = pending_seq` for the affected rows (committed) OR not (rolled back), the question "did A happen" has a definite answer. The attacker cannot manufacture a phantom that points at fabricated pre-state; the SQLite snapshot is authoritative.

### §9.2 Attack — divergence of intent and effect

**Scenario.** A buggy or compromised kernel announces one transition (`Admitted → Active`) but commits a different one (`Admitted → Failed`). Without digest binding, the chain says "the kernel intended Active" and SQLite says "Failed"; the forensic team cannot distinguish a kernel bug from an attacker.

**With pre/post digests.** `actual_post_state_digest` (computed inside the transaction post-write) ≠ `intended_post_state_digest` (computed pre-tx) is a `Finding::DigestMismatch` — flagged as a critical finding. The kernel cannot silently announce one thing and commit another.

### §9.3 What the digests don't protect against

- **A kernel that lies in both pending and confirmed consistently.** If a compromised kernel says it intended X, then commits X, the audit chain shows "intended X, committed X" — consistent, but X may not be the operator-authorised action. This is what `R-3` (kernel signing of audit events) protects against: the chain entries are signed by the kernel's keypair, and a compromised key is the operator's R-7 boundary, not the audit chain's.
- **Time-shifted chain entries.** A kernel that writes a pending at T0 but doesn't commit until T1 (and lies about `clock_ms`) cannot be detected by the chain alone. The `KernelClaims.clock_ms` is bounded by the predecessor event's clock_ms (chain monotonicity), but absolute clock truth requires external attestation (out of scope).
- **An attacker who can write to the JSONL file directly.** This is the file-permission boundary, not the audit-protocol boundary. The audit JSONL is mode `0600`, owned by the kernel uid; tampering requires host-level compromise, which is the same trust boundary that protects SQLite.

### §9.4 Why `KernelClaims` is bound

The `pre_tx_claims: KernelClaims` field carries `kernel_version`, `policy_epoch`, `policy_sha256`, `clock_ms` — what the kernel believed about itself when making the decision. A verifier asserting policy compliance can replay the chain and confirm: "every state mutation under epoch 47 was taken by a kernel claiming policy_sha256 X". A kernel that committed under epoch 48 with epoch 47's policy would be flagged. This is a defense against partial policy reload bugs; it has no R-7 implication on its own but is cheap and structurally clarifying.

---

## §10 — Migration (V2.0 → V2.1)

### §10.1 The migration ceremony

The first boot of a V2.1 kernel against a V2.0 chain runs a one-time migration:

1. **SQLite schema migration.** Run `migrations/V21__paired_audit.sql` (per §3.3): `ALTER TABLE … ADD COLUMN last_committing_event_seq INTEGER NOT NULL DEFAULT 0`. SQLite handles this without rewriting rows.

2. **Backfill pass.** For every state-bearing table, the migration scans the JSONL chain newest-to-oldest and writes the seq of the latest event referencing each row's primary key into `last_committing_event_seq`. Rows the chain doesn't mention retain `0`. The backfill is bounded by chain size; on chains with millions of events it may take several minutes — acceptable as a one-time cost.

3. **Audit migration record.** The kernel writes a single audit event:

   ```rust
   AuditEventKind::AuditSchemaMigration {
       from:           "V2.0_post_commit_audit",
       to:             "V2.1_paired_audit",
       migrated_at_ms: u64,
       backfill_summary: BackfillSummary {
           tables_scanned:        u32,
           rows_backfilled:       u64,
           rows_left_at_zero:     u64,                  // PreV21Row count
           chain_events_scanned:  u64,
           backfill_elapsed_ms:   u64,
       },
       new_protocol_starts_at_seq: u64,                  // == this event's seq + 1
   }
   ```

4. **Protocol switch.** From the seq immediately after `AuditSchemaMigration`, every state-mutating event uses the paired pattern. Pre-migration events remain single-event; the verifier handles both shapes.

### §10.2 Fail-stop during migration

If the backfill encounters an inconsistency that V2.1 cannot reconcile (e.g., a row with a primary key that the chain doesn't mention but that exists in SQLite — possible if `recovery::reconcile` was never run on a crash window in V2.0), the migration aborts with `FAIL_AUDIT_MIGRATION_INCONSISTENT_ROW`. The operator must run V2.0 with `recovery::reconcile` enabled to clean up, then re-attempt V2.1 boot. The migration is idempotent: a partial backfill that didn't complete leaves the kernel in V2.0 mode (no `AuditSchemaMigration` event); re-running the migration restarts the backfill from scratch.

### §10.3 Forward compatibility guarantee

Every V2.1+ kernel can read pre-migration JSONL chains. The verifier handles `pending_seq < new_protocol_starts_at_seq` by falling back to V1 semantics: such events are single, no pairing checks apply.

The reverse is **not** supported. A V2.0 kernel cannot read a V2.1 chain (the unknown variants would fail deserialisation). Operators who must downgrade must roll back the data directory to a pre-V2.1-migration backup.

---

## §11 — Alternatives considered (and rejected)

### §11.1 The full alternatives table

| Alt | Description | R-7? | Latency cost vs V1 | Complexity | Verdict |
| --- | --- | --- | --- | --- | --- |
| **A** | Embed audit row in same SQLite transaction as state | ❌ Violates R-7 (audit can be rolled back with state) | -1 fsync (audit becomes free) | Low | **Rejected** by R-7. |
| **B** | V1 baseline: SQLite first, JSONL post-commit, recovery patches gaps | ⚠️ Conditional on kernel restart | 0 (baseline) | Low | Status quo; R-7 conditional. |
| **C** | JSONL first, SQLite second, single event (no pairing) | ❌ Phantoms indistinguishable from real entries without SQLite | +1 fsync | Low | **Rejected**: no information advantage over D, same SQLite consultation cost, weaker chain self-narration. |
| **D** | JSONL pending → SQLite → JSONL confirmed (proposal floor) | ✅ With SQLite snapshot | +1 fsync (~50%) | Medium | Accepted as floor; refined by D′. |
| **D′** | D, but pending records pre/post digests + idempotency_key + KernelClaims; confirmed records `sqlite_commit_id` + `actual_post_state_digest`; deliberate rollback gets `StateChangeRolledBack` | ✅ Strictly stronger | +1 fsync (~50%) | Medium | **Recommended (this spec).** |
| **E** | True 2-phase commit with external coordinator (e.g. FoundationDB, ZooKeeper) | ✅ | Much higher (network round-trip) | Very high | **Rejected**: over-engineered for V2. RAXIS is single-host single-store; introducing distributed coordination violates the deployment model. |
| **F** | Pre-allocate seq slot in JSONL before SQLite, fill after | ✅ | +1 fsync | High (chain hashing must accommodate "to-be-filled" slots; signature scheme breaks) | **Rejected**: same R-7 property as D′ with materially more complex implementation. |
| **G** | "Optimistic confirmed": only emit pending + periodic `AuditChainCheckpoint { last_committed_seq, sqlite_state_digest }` event | ⚠️ Weaker (verifier window unbounded between checkpoints) | ~0 (amortised) | Medium | **Useful as a follow-on hardening layer in V2.2**, not a replacement for D′. |
| **H** | Pure pending without confirmed; assume "no rollback emitted within N seconds" means committed | ❌ Time-based assumptions are not a chain property | 0 | Low | **Rejected**: violates "chain integrity verifiable from chain alone" — a verifier replaying the chain has no clock for "N seconds." |

### §11.2 Why D′, not just D

The proposal floor (D) gives an offline verifier the basic ability to pair pendings with confirmeds, but leaves three gaps:

1. **Phantom-manufacture attack surface.** Without `pre_state_digest`, an attacker who can crash the kernel mid-write can claim pending entries refer to states that didn't exist. D′ binds the pending to a specific SQLite pre-state.

2. **Concurrent retry disambiguation.** A planner that retries an intent (legitimate per `R-9` IPC envelope semantics) can produce two pendings for the same logical action. Without `idempotency_key` in the pending event, the operator-facing `raxis log` UI cannot collapse them. D′ propagates the planner-supplied envelope nonce.

3. **Forensic policy attribution.** Without `pre_tx_claims: KernelClaims`, the verifier cannot prove which policy epoch authorised each transition. Cheap, additive, useful.

D′ adds 100–200 bytes per pending event for these three. Negligible on disk, structurally important.

### §11.3 Why G is deferred (not bundled into V2.1)

The periodic `AuditChainCheckpoint` event would let the verifier prove "the SQLite state at seq N matched H, and every paired event since N has consistent pre/post digests" — the strongest possible R-7 satisfaction, including post-state content verification. But:

- Computing `sqlite_state_digest` over every state-bearing table is expensive on large deployments (minutes per checkpoint on multi-GB stores).
- The right cadence is workload-dependent (every 10s? every 10k events? every reload?).
- The chain-anchoring math (Merkle root of all paired events since last checkpoint) needs careful spec.

V2.1 ships D′ as the structural baseline; V2.2 adds G as an additional layer. The two are orthogonal — V2.2's checkpoints sit on top of V2.1's pairs without protocol change.

### §11.4 Why audit-first ordering, not audit-last

The strict R-7 reading would also be satisfied by **audit-last** ordering with a pending-on-failure marker:

```
1. BEGIN IMMEDIATE; mutate; COMMIT
2. Try emit confirmed; on failure write to a "pending_audit_replay" SQLite table
3. Background sweep replays the table to JSONL on next opportunity
```

This is what some database systems do (write-ahead-log replay). It's **rejected** because:

- The "pending_audit_replay" table puts audit data in the same store as state — the exact pattern R-7 forbids ("Audit storage in the same SQLite database the authority uses for state").
- Recovery on a crash between COMMIT and the SQLite replay-table insert reintroduces the V1 gap.
- A verifier with only the JSONL would still see gaps; replay-table reads require kernel running.

Audit-first sidesteps all of this by making the chain the *first* durable witness.

### §11.5 Why not just bigger fsyncs (single-event)?

A naïve "make audit-first single-event the rule" (alt C) writes the event before SQLite. On crash before SQLite commit, the chain says "X happened" but SQLite says "no it didn't." This is a *false positive* in the audit chain — the chain claims an action that never committed.

False positives are *actionable* for forensic teams (a phantom is detectable by SQLite consultation), but the chain itself is no longer trustworthy as a "what happened" narrative. A reader looking at the chain alone would conclude X happened.

Pairing fixes this: pending says "X is *attempted*"; confirmed says "X *committed*". The chain narrates "X attempted, X committed" as two events, both true under their respective semantics. A reader looking at the chain and seeing pending(X) without confirmed(X) reads "X attempted, outcome unknown" — accurate, not misleading.

### §11.6 Why three event records, not two

A two-event variant: pending + (confirmed | rolled-back) where the second event is *the same kind* (e.g., `EscalationSubmittedConfirmed` and `EscalationSubmittedRolledBack`). This was considered and rejected because it doubles the variant count of `AuditEventKind`.

The three-event design: one new kind for `pending`, augment existing variants for confirmed (no new kinds), one new kind for `rolled-back` (generic across all paired classes). Smaller surface, cleaner forensic queries (`raxis log --kind EscalationSubmitted` returns confirmed events with the new fields; the existing query interface is unchanged).

---

## §12 — Implementation phases (mergeable PRs)

Phases are ordered to be mergeable independently, each independently shippable, with the kernel never in an inconsistent state mid-migration.

**Phase A — Schema migration (no behaviour change).**
- New SQLite migration `V21__paired_audit.sql` (per §3.3). All `ALTER TABLE … ADD COLUMN … DEFAULT 0`.
- Migration backfill pass implementation in `kernel/src/store/migrations/v21_backfill.rs`.
- One PR; no kernel-behaviour change yet because no caller writes the new column.

**Phase B — Audit event variants (no behaviour change).**
- New variants `StateChangePending`, `StateChangeRolledBack` added to `AuditEventKind`.
- Augmentation of paired-class variants: three new fields `confirms_pending_seq`, `sqlite_commit_id`, `actual_post_state_digest`. Initially typed as `Option<…>` (default `None`) for backward compat.
- `Confirmable` trait (impl on every paired-class variant) returning the three fields generically.
- One PR per variant cluster (session, initiative, task, escalation, …) for review surface bound.

**Phase C — Verifier crate (independence-bearing).**
- New leaf crate `crates/audit-verify/` with strict dep boundary (per §5.4.1): `sha2`, `ed25519-dalek`, `serde`, `serde_json`, `hex`, `clap`, `glob`. NO kernel crates.
- `crates/audit-verify/src/lib.rs::verify` implementation (per §5.2). Public types: `Finding`, `StateSnapshot` trait, `Keyring`, `AuditEvent` (untyped JSONL parse — see §5.4.1 design note about avoiding `AuditEventKind` enum dependency).
- `crates/audit-verify/src/digest.rs` — canonical row-encoding helpers used by both the standalone binary (parsing pending events) and the kernel's `PairedAuditWriter` (computing pre/post digests). Pure functions; no kernel state.
- `crates/audit-verify/src/state_export.rs` — JSON export schema (`raxis-audit-verify-state-export-v1`) consumed by `--state-export` and produced by `raxis audit export-state-for-verifier`.
- `crates/audit-verify/src/bin/raxis-audit-verify.rs` — the standalone binary (per §5.4.2 CLI surface, §5.4.3 exit codes).
- `crates/audit-verify/tests/conformance.rs` — synthetic chains exercising every crash-window pattern, every Finding shape (including chain-only mode for `OrphanIndeterminate`).
- `xtask/src/audit_verify_deps.rs` — the dep-boundary lint (§13.3 of this spec): runs `cargo metadata --filter-platform`, walks the dep graph rooted at `raxis-audit-verify`, and fails CI if any of `raxis-store`, `raxis-policy`, `raxis-ipc`, `raxis-types`, `raxis-audit-tools`, `raxis-kernel`, `rusqlite`, `tokio`, or `reqwest` appear in the closure.
- One PR for the crate; one follow-up PR for the dep-boundary CI gate.

**Phase D — Kernel emits pending → confirmed.**
- Refactor `kernel/src/handlers/intent.rs` admission pipeline: insert Phase B0 (compute digests, emit pending, fsync) and Phase B2 (emit confirmed inside the wrapped existing emission). Per-handler PRs:
  - D.1 — escalation handler
  - D.2 — task lifecycle (admit, transition, complete, abort)
  - D.3 — initiative lifecycle (create, approve, abort, quarantine, cancel)
  - D.4 — IntegrationMerge
  - D.5 — verifier WitnessSubmission
  - D.6 — operator IPC writes (RotateEpoch, ApproveEscalation, …)
  - D.7 — circuit breaker state transitions
  - D.8 — lane reservation
  - D.9 — notification dispatch + SMTP proxy
  - D.10 — custom-tools, alias resolution session affinity, worktree lifecycle
- After each handler PR: the three fields on its event variants become NON-OPTIONAL; kernel refuses to emit without filling them.

**Phase E — Recovery becomes advisory.**
- Refactor `kernel/src/recovery.rs::reconcile` → `reconcile_advisory` (per §6.2).
- Add `RollbackReason::CrashInferred`.
- Recovery-induced events tag a flag `_recovery_synthesised: true` in their JSON for forensic clarity.
- Kernel refuses to start if `reconcile_advisory` returns critical findings; operator first runs the standalone `raxis-audit-verify` to confirm the finding is real (independence-bearing verdict), then clears the boot block with `raxis verify-chain --acknowledge-critical` (signed override; the convenience wrapper accepts a signed acknowledgement payload that includes the standalone binary's verdict hash).

**Phase F — Migration ceremony at first V2.1 boot.**
- `kernel/src/main.rs` boot site: detect pre-V2.1 chain (no `AuditSchemaMigration` event found); run §10.1 ceremony.
- Idempotency: re-run on partial migration restarts from scratch.

**Phase G — Spec-graph lint extension.**
- `xtask spec-graph` enforces §4.2: every `AuditEventKind` variant in either paired or single class.
- CI fails if a new variant lands without classification.

**Phase H — Conformance tests (CI gate).**
- `kernel/tests/audit_paired_writes_e2e.rs` — every crash window per §7 exercised against a real kernel via panics-on-demand.
- `crates/audit-verify/tests/conformance.rs` — synthetic chains, exercised against the leaf crate's `verify()` (no kernel needed).
- `kernel/tests/recovery_advisory_optional.rs` — verifier resolves orphans correctly even when `reconcile_advisory` is bypassed.

Total surface: ~6–8 weeks of engineering for the full migration; first user-visible wins after Phase D.4 (most observable hot-path covered).

---

## §13 — Files to create / change

### §13.1 Files to create

#### Independence-bearing crate (`crates/audit-verify/`)

This crate is the R-7 artefact. Its dep graph must NOT transitively
include any kernel crate. The `xtask audit-verify-deps` lint
(§13.3) enforces this in CI.

| Path | Role |
| --- | --- |
| `crates/audit-verify/Cargo.toml` | NEW — manifest with strict dep boundary (per §5.4.1) |
| `crates/audit-verify/src/lib.rs` | NEW — public `verify()` entry point + `Finding` enum + `StateSnapshot` trait + `Keyring` (per §5.2) |
| `crates/audit-verify/src/event.rs` | NEW — JSONL event parser. Reads events as `serde_json::Value` and exposes a small typed view (`AuditEventView { seq, prev_sha256, signature, kind: EventKind, payload: Value }`) just rich enough for the verifier. Crucially does NOT depend on the kernel's full `AuditEventKind` enum, so adding new variants in the kernel does not require recompiling the standalone binary. |
| `crates/audit-verify/src/digest.rs` | NEW — canonical row-encoding helpers (`hash_row`, `hash_writes_set`, `canonical_event_bytes`). Pure functions; the kernel's `crates/audit-tools` re-exports these, so producer and verifier agree on byte representation. |
| `crates/audit-verify/src/state_export.rs` | NEW — JSON state-export schema (`raxis-audit-verify-state-export-v1`) consumed by `--state-export` and produced by `raxis audit export-state-for-verifier`. |
| `crates/audit-verify/src/keyring.rs` | NEW — Ed25519 pubkey loader. Reads PEM (single key) or directory (multi-key, fingerprint-named) per §5.4.2. |
| `crates/audit-verify/src/bin/raxis-audit-verify.rs` | NEW — the standalone binary entry point (clap CLI per §5.4.2; verdict formatter per §5.4.3). |
| `crates/audit-verify/tests/conformance.rs` | NEW — synthetic chain fixtures + Finding-shape assertions, exercised against the leaf `verify()` library. |
| `crates/audit-verify/tests/dep_boundary.rs` | NEW — meta-test that parses `Cargo.toml` and asserts the dependency list matches §5.4.1 exactly. Defence in depth alongside the xtask lint. |

#### Kernel-side files (depend on `crates/audit-verify`)

| Path | Role |
| --- | --- |
| `crates/store/migrations/V21__paired_audit.sql` | NEW — schema migration (per §3.3) |
| `kernel/src/store/migrations/v21_backfill.rs` | NEW — backfill pass implementation |
| `kernel/src/audit/paired.rs` | NEW — `PairedAuditWriter` helper used by every handler in Phase D |
| `kernel/tests/audit_paired_writes_e2e.rs` | NEW — every §7 crash window |
| `kernel/tests/recovery_advisory_optional.rs` | NEW — verifier-without-recovery tests |
| `xtask/src/audit_verify_deps.rs` | NEW — dep-boundary CI lint (§13.3 of this spec) |

### §13.2 Files to change

| Path | Change |
| --- | --- |
| `crates/audit/src/event.rs` | Add `StateChangePending`, `StateChangeRolledBack`, `RollbackReason`, `RowMutationDescriptor`, `KernelClaims`, `StateChangeOperation` enums. Augment every paired-class variant with three new fields (Phase B). Define `Confirmable` trait. **Imports `crates/audit-verify::digest` for canonical encoding helpers** so producer and verifier are byte-identical. |
| `crates/audit/src/sink.rs` | Extend `AuditSink` trait per `extensibility-traits.md §5` with `emit_pending`, `emit_confirmed_for`, `emit_rolled_back_for`, `emit_recovered_confirmed`, `emit_recovered_rollback` |
| `kernel/src/handlers/intent.rs` | Insert Phase B0 + B2 admission stages; route through `PairedAuditWriter` |
| `kernel/src/handlers/escalation.rs` | Phase D.1 — paired emission for `EscalationSubmitted`, `EscalationApproved`, `EscalationDenied`, `EscalationConsumed`, `ApprovalToken*` |
| `kernel/src/handlers/{task,initiative,merge,verifier,operator}.rs` | Phase D.2–D.6 |
| `kernel/src/recovery.rs` | `reconcile` → `reconcile_advisory` (per §6.2). **Imports `raxis_audit_verify::verify` for the algorithm** with a kernel-local `LiveSqliteSnapshot` impl of `StateSnapshot` (per §6.2 code listing). One algorithm, two snapshot sources. |
| `kernel/src/main.rs` | First-boot migration ceremony (per §10). On critical findings from `reconcile_advisory`, instructs operator to run the **standalone** `raxis-audit-verify` binary (independence-bearing) before clearing with `raxis verify-chain --acknowledge-critical`. |
| `kernel/src/store/migrations.rs` | Wire `V21__paired_audit.sql` + backfill pass |
| `crates/store/src/sessions.rs`, `tasks.rs`, `initiatives.rs`, `escalations.rs`, `delegations.rs`, …  | Each state-bearing module: every `transition_*` SQL site adds `last_committing_event_seq = ?` to its UPDATE/INSERT. Add `lookup_last_committing_event_seq(table, primary_key) -> Option<u64>` helper used by `LiveSqliteSnapshot`. |
| `crates/raxis-audit-tools/src/main.rs` | DOES NOT gain a `verify-chain` subcommand. The independence-bearing tool is `raxis-audit-verify` in `crates/audit-verify/`. `raxis-audit-tools` retains its existing role as the kernel-side audit writer/library. |
| `cli/src/commands/audit.rs` | Add `raxis verify-chain` as a **subprocess wrapper** (per §5.7): translates CLI flags to standalone-binary flags, spawns `raxis-audit-verify` via `std::process::Command`, propagates exit code unchanged, formats stdout/stderr for the operator. **Does NOT import `raxis_audit_verify::verify`** — the verification result MUST come from the subprocess so the trust path bottoms out at the dep-bounded binary even for operators who use the convenience wrapper. Add `raxis audit export-state-for-verifier` (writes JSON consumable by `raxis-audit-verify --state-export`). The `raxis verify-chain --acknowledge-critical` flag spawns the binary, captures the verdict + binary version + chain digest, signs the resulting `AcknowledgeCriticalPayload` with the operator key, writes the signed payload to `<data_dir>/audit/critical_ack.signed`, and instructs the operator to restart the kernel — which reads the file in `reconcile_advisory`'s critical-finding path (per §6.2) and clears the boot block iff the signed verdict matches what `reconcile_advisory` itself observed. |
| `xtask/src/spec_graph.rs` | Add §4.2 paired/single classification check |
| `raxis/specs/v1/kernel-store.md` | §2.5.2 AuditSink ordering rewritten as the V2.1 paired ordering; cross-reference this spec; add `last_committing_event_seq` column to schema docs |
| `raxis/specs/v1/kernel-core.md` | Intent admission pipeline — Phase B insertion; `recovery::reconcile` → `reconcile_advisory`; cross-reference this spec |
| `raxis/specs/v1/cli-readonly.md` | New §5.5.19 `raxis audit export-state-for-verifier` (kernel-linked exporter for the standalone binary's `--state-export` mode) |
| `raxis/specs/v2/extensibility-traits.md` | §5 (`AuditSink`) extended with paired-write methods; §5.3/§5.4 file lists realigned to point at `crates/audit-verify/` (leaf crate) for the verifier algorithm |
| `raxis/specs/v2/policy-plan-authority.md` | New `FAIL_AUDIT_*` failure codes |
| `raxis/specs/invariants.md` | New `INV-AUDIT-PAIRED-01..07` |
| `raxis/specs/v2/v2-deep-spec.md` | Register this spec in Related Specifications; spec-graph lint extension |

### §13.3 The dep-boundary CI lint

**Why a lint at all.** §5.4.1 specifies a strict dependency list for
`crates/audit-verify`. Without enforcement, a future PR could add
`raxis-store = "*"` "just for one helper" and silently destroy the
independence property. The lint is not optional — it is the
operational substantiation of `INV-AUDIT-PAIRED-05`.

**What it does.**

```rust
// xtask/src/audit_verify_deps.rs
const BANNED: &[&str] = &[
    "raxis-store",
    "raxis-policy",
    "raxis-ipc",
    "raxis-types",
    "raxis-audit-tools",
    "raxis-kernel",
    "raxis-cli",
    "rusqlite",
    "tokio",
    "reqwest",
    "hyper",
    // any other crate that pulls in IO/storage/network
];

pub fn run() -> anyhow::Result<()> {
    let metadata = cargo_metadata::MetadataCommand::new().exec()?;
    let root = metadata.packages.iter()
        .find(|p| p.name == "raxis-audit-verify")
        .expect("crates/audit-verify/ must exist");
    let mut closure = HashSet::new();
    walk_deps(&metadata, root, &mut closure);
    let violations: Vec<_> = closure.iter()
        .filter(|name| BANNED.contains(&name.as_str()))
        .collect();
    if !violations.is_empty() {
        anyhow::bail!(
            "raxis-audit-verify dep boundary violated: {:?} present in transitive closure",
            violations
        );
    }
    Ok(())
}
```

**When it runs.** Every PR that touches `crates/audit-verify/**` or
the workspace `Cargo.lock`. Required CI gate; cannot be bypassed.

**Why not just trust review.** Reviewers miss transitive deps —
`anyhow` pulls in `backtrace`, which on some platforms pulls in
`addr2line`, which… The closure check is exhaustive in a way humans
aren't. Plus the closure naturally evolves as upstream crates add
features; the lint catches a future `serde_json` minor that suddenly
needs `tokio-util` for something.

**Why xtask, not a build script.** Build scripts run during compile;
the lint runs during `cargo xtask audit-verify-deps`. The latter is
explicitly invoked in CI and prints actionable diagnostics. A
build-script failure would be confusing ("why won't my crate compile
in someone else's PR?"); an xtask failure is a clear "the lint says
these crates can't be in the closure."

---

## §14 — Invariants

The seven invariants below are the canonical R-7-bearing properties of the V2.1 audit chain. They are summarised in `invariants.md` and verified by the §15 conformance kit.

### §14.1 `INV-AUDIT-PAIRED-01` — Every state-mutating event is preceded by a pending

**Statement.** For every `AuditEventKind` variant in the paired class (§4.1), the kernel writes and durably fsyncs a `StateChangePending` event before issuing `BEGIN IMMEDIATE`. No path through the kernel mutates SQLite without a preceding fsync'd pending.

**Justification.** This is the floor of strict R-7 satisfaction. Without it, a crash mid-COMMIT leaves the chain silent on a state change.

**Verification.** `kernel/tests/audit_paired_writes_e2e.rs::no_unannounced_mutations` injects a panic between Phase B0 and Phase B1 for every paired handler; the resulting chain MUST contain the pending; SQLite MUST NOT show the mutation. Opposite injection (between BEGIN IMMEDIATE start and COMMIT) is also tested.

### §14.2 `INV-AUDIT-PAIRED-02` — Every confirmed references a real pending

**Statement.** For every paired-class confirmed event in the chain, the cited `confirms_pending_seq` MUST refer to a `StateChangePending` event earlier in the chain, AND the confirmed's `actual_post_state_digest` MUST equal that pending's `intended_post_state_digest`.

**Justification.** Closes the kernel-buggery / kernel-compromise vector where the kernel announces one mutation and commits another (§9.2).

**Verification.** `crates/audit-verify/tests/conformance.rs::digest_mismatch_flagged`.

### §14.3 `INV-AUDIT-PAIRED-03` — Every rollback references a real pending

**Statement.** For every `StateChangeRolledBack` in the chain, the cited `rolls_back_pending_seq` MUST refer to a `StateChangePending` earlier in the chain. The pending and rollback together form a complete pair — no SQLite mutation occurred under that pending's claim.

**Justification.** Symmetric to `INV-AUDIT-PAIRED-02`.

**Verification.** `crates/audit-verify/tests/conformance.rs::dangling_rollback_flagged`.

### §14.4 `INV-AUDIT-PAIRED-04` — `last_committing_event_seq` reflects the most recent pending

**Statement.** For every state-bearing SQLite row, `last_committing_event_seq` records the seq of the most recent pending whose Phase B1 successfully committed a mutation to that row. The kernel writes this column inside the same transaction as the row mutation; no path exists by which a row mutates without `last_committing_event_seq` being updated.

**Justification.** This is the SQLite half of the offline-verifier resolution (§5.1 Phase 3). Without it, the verifier cannot distinguish a committed orphan from a rolled-back orphan.

**Verification.** `kernel/tests/audit_paired_writes_e2e.rs::row_seq_matches_pending` injects randomly across all transition SQL sites; every committed transaction's row(s) MUST have `last_committing_event_seq` equal to the announcing pending's seq.

### §14.5 `INV-AUDIT-PAIRED-05` — Audit chain is offline-verifiable without the kernel

**Statement.** Given (a) the JSONL chain segments and (b) a SQLite snapshot at any point-in-time after the chain, the §5 verifier algorithm MUST resolve every orphan to either `OrphanResolvedByStateSnapshot` or `OrphanRolledBackInferred`. The verifier MUST NOT require the kernel to be running, MUST NOT require any kernel-side recovery process to have run, and MUST produce the same set of findings on the same inputs regardless of whether the host kernel is currently up.

**Justification.** This is the literal R-7 requirement.

**Verification.** `kernel/tests/recovery_advisory_optional.rs` — kill the kernel mid-write, do not restart it, run the offline verifier from a snapshot taken via SQLite Online Backup; assert the verifier resolves all orphans without invoking any kernel code.

### §14.6 `INV-AUDIT-PAIRED-06` — Recovery is advisory, not required for chain integrity

**Statement.** `kernel/src/recovery.rs::reconcile_advisory` MAY synthesise missing `confirmed` and `rolled_back` events on kernel start, but the chain's R-7 verifiability MUST NOT depend on this synthesis having run. A chain that has never been touched by recovery MUST produce the same offline-verifier output (modulo `Finding::OrphanResolvedByStateSnapshot` vs `Finding::confirmed-event-present`) as one that has.

**Justification.** Closes the V1 R-7 conditional-on-restart violation explicitly.

**Verification.** Same test as `INV-AUDIT-PAIRED-05`; additionally `kernel/tests/recovery_advisory_optional.rs::verifier_idempotent_with_or_without_recovery` runs the verifier before and after `reconcile_advisory` on the same snapshot and asserts findings differ only by the SQLite-resolution annotation (`OrphanResolvedByStateSnapshot` becomes `confirmed-present`; `OrphanRolledBackInferred` becomes `StateChangeRolledBack`-present). No new findings appear; no findings disappear.

### §14.7 `INV-AUDIT-PAIRED-07` — Pre-V2.1 rows fall back gracefully

**Statement.** For SQLite rows with `last_committing_event_seq = 0` (rows the V2.1 migration could not backfill), the offline verifier flags `Finding::PreV21Row` (non-critical) and applies V1 reconciliation semantics for those rows' history. The V1 fallback is bounded: no V2.1+ paired event can resolve to a `PreV21Row` (the kernel sets `last_committing_event_seq` on every mutation post-migration).

**Justification.** Migration-cycle safety — the protocol must handle deployments that have years of pre-V2.1 chain.

**Verification.** `kernel/tests/audit_paired_writes_e2e.rs::pre_v21_rows_isolated`.

---

## §15 — Conformance kit

### §15.1 What the kit verifies

The conformance kit (`crates/audit-verify/tests/conformance.rs` for the algorithm-level checks; `kernel/tests/audit_paired_writes_e2e.rs` for the kernel-side crash-window checks) is the executable specification of `INV-AUDIT-PAIRED-01..07`. Any implementation of `AuditSink` that ships paired-write semantics MUST pass the kit. The kit is parametric over `AuditSink` impls so future implementations (`PostgresAuditSink`, `S3AuditSink`, `RekorAuditSink`) inherit the same gate. The algorithm-level half lives in the leaf crate so it runs without the kernel — exactly the property `INV-AUDIT-PAIRED-05` requires.

### §15.2 Test patterns

Every crash window in §7 has at least one test that:

1. Spawns a real kernel.
2. Submits a paired-class intent.
3. Forces a panic at a specific pre-instrumented point (Phase B0, B1, B2, or in fsync).
4. Reads SQLite + JSONL snapshots.
5. Runs the offline verifier.
6. Asserts the verifier output matches the expected resolution.
7. Runs `reconcile_advisory` on the recovered kernel.
8. Re-runs the offline verifier; asserts the chain is now self-resolving.

### §15.3 Mutation testing

The kit includes a mutation-testing harness: it permutes every paired-class transition SQL site to *not* set `last_committing_event_seq`, recompiles the kernel, runs Phase D handler tests, and asserts the offline verifier flags the missing row update. This catches regressions where a future PR adds a new transition site but forgets the column.

---

## §16 — Cross-spec impacts

| Spec | Impact |
| --- | --- |
| `paradigm.md §3 R-7` | Reframed: V2.1 paired-audit is the canonical reference implementation that satisfies the strict reading of R-7. The independence property is operationalised by the `crates/audit-verify/` leaf crate's strict dep boundary (per §5.4.1) plus the `xtask audit-verify-deps` CI lint (per §13.3). Footnote pointer added. |
| `invariants.md §audit` | New `INV-AUDIT-PAIRED-01..07` rows. `INV-AUDIT-PAIRED-05` (offline verifiability) is the strict-`R-7` invariant, structurally satisfied by the standalone `raxis-audit-verify` binary's dep boundary. |
| `v1/kernel-store.md §2.5.2` | AuditSink ordering rewritten as V2.1 paired ordering (Phase B0 → B1 → B2). New `last_committing_event_seq` column on every state-bearing schema. The V1 ordering is documented as historical and applies only to pre-`AuditSchemaMigration` chain entries. New `lookup_last_committing_event_seq(table, primary_key) -> Option<u64>` helper used by `LiveSqliteSnapshot` impl of `audit-verify::StateSnapshot`. |
| `v1/kernel-core.md §2.3` | Intent admission pipeline — Phase B is now three sub-phases (B0, B1, B2) with an explicit "compute pre/post digests" step. `recovery::reconcile` is renamed `reconcile_advisory` and its role downgraded from "required for correctness" to "best-effort advisory; chain is verifiable without it." Recovery imports `raxis_audit_verify::verify` for the algorithm (single-source-of-truth) and supplies a kernel-local `LiveSqliteSnapshot` impl. |
| `v1/cli-readonly.md` | §5.5.13 `raxis verify-chain` rewritten as a **subprocess wrapper around `raxis-audit-verify`**: every R-7 verdict — even via the convenience CLI — bottoms out at the dep-bounded binary. The CLI's exit code is the binary's exit code unchanged; the CLI cannot mask a critical finding. New §5.5.19 `raxis audit export-state-for-verifier` (kernel-linked exporter producing JSON consumable by the standalone binary's `--state-export` flag). New §5.5.20 documenting that `raxis-audit-verify` exists as a separate top-level binary with its own man page; it is the verifier of record, and the CLI wrapper exists for operator ergonomics, not as a parallel verification path. `raxis log` output gains `confirms_pending_seq` and `sqlite_commit_id` fields when displaying paired-class events; the UI collapses pending + confirmed into a single line by default; `--show-pending` flag exposes the underlying pair. |
| `v2/extensibility-traits.md §5` | `AuditSink` trait extended with `emit_pending`, `emit_confirmed_for`, `emit_rolled_back_for`, `emit_recovered_confirmed`, `emit_recovered_rollback`. The verifier algorithm and `Finding` enum live in the leaf crate `crates/audit-verify/`, NOT in `crates/audit/` (which is kernel-linked). The conformance kit (§15 of this spec) lives in the leaf crate so any sink shipping V2.1+ inherits the gate. |
| `v2/policy-plan-authority.md` failure-code catalog | New: `FAIL_AUDIT_PENDING_FSYNC`, `FAIL_AUDIT_CONFIRMED_FSYNC_EXHAUSTED`, `FAIL_AUDIT_PRE_STATE_DIGEST_MISMATCH`, `FAIL_AUDIT_INTENDED_POST_STATE_DIGEST_MISMATCH`, `FAIL_AUDIT_MIGRATION_INCONSISTENT_ROW`, `FAIL_AUDIT_MIGRATION_PARTIAL_BACKFILL`, `FAIL_BEGIN_IMMEDIATE_TIMEOUT`, `FAIL_AUDIT_CRITICAL_FINDING`, plus the informational `WARN_AUDIT_*` set. The catalog notes which are reported by the standalone binary (`FAIL_AUDIT_CRITICAL_FINDING` only — exit code 3) vs which are kernel-runtime errors only (`FAIL_AUDIT_PENDING_FSYNC` and friends). |
| `v2/v2-deep-spec.md` Related Specifications | New row registering this spec; "Spec-Graph Lint" section gains §4.2 enforcement. |
| `v2/email-and-notification-channels.md` | `notification_dispatch` table gains `last_committing_event_seq` column; `NotificationDispatchClaimed` event becomes paired-class; `NotificationDelivered`/`NotificationDeliveryFailed` remain single (post-commit observation events). No spec text changes — the dispatcher already emits in the right order. |
| `v2/integration-merge.md` | `IntegrationMergeApplied` becomes paired-class; the existing two-phase commit (Phase 1 audit + Phase 2 git apply) maps to (Phase 1 = paired audit; Phase 2 = git apply, which is *not* paired because it doesn't mutate SQLite). Cross-reference added. |
| `v2/credential-proxy.md` | `SmtpProxyMessageSent`, `SmtpProxyConnected`, etc. gain paired-class status (they write rate-limit-bucket rows). NNSP unchanged. |
| `crates/audit-verify/` (NEW workspace member) | New top-level workspace member; build dep boundary enforced by `xtask audit-verify-deps` (§13.3). The binary `raxis-audit-verify` ships in the same release artefacts as `raxis-cli` and `raxis-kernel` but is independently runnable with no kernel data directory or running daemon. |

---

## §17 — Document maintenance

Changes to this spec affect the audit chain contract — the most R-7-bearing surface in the kernel. Coordination required:

- Adding a new paired-class event kind requires (a) classifying it in §4.1, (b) adding the three augmented fields to its variant, (c) updating spec-graph lint, (d) confirming the conformance kit covers its handler.
- Removing a paired-class event kind requires a deprecation cycle — the kind cannot disappear from the chain on a live kernel; instead, the kernel stops emitting new events of that kind, and the verifier continues to handle historical events of that kind.
- Changing the `pre_state_digest` or `intended_post_state_digest` algorithm is a chain-contract change that requires a new `AuditSchemaMigration` event (V2.1 → V2.2 boundary).
- The §11 alternatives table is the authoritative record of "why D′"; future proposals to revisit (e.g., the periodic-checkpoint G alternative when V2.2 adds it) MUST update this table with their final disposition.

This spec is the canonical source for the V2.1 paired-write protocol. When V2.2 lands the periodic checkpoint, that spec will reference §11.3 and `INV-AUDIT-PAIRED-05` as the floor it builds on.








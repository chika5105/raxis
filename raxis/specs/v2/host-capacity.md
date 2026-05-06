# RAXIS V2 — Host Capacity Management

> **Status:** V2 Specified
> **Cross-references:**
> - `specs/invariants.md` — INV-01 (fail-closed default), INV-05 (audit chain integrity), INV-STORE-02 (atomic state changes)
> - `specs/v2/integration-merge.md §11` — SQLite ↔ git transactional boundary; this spec specifies disk-full behavior at each phase
> - `specs/v2/kernel-push-protocol.md §10` — per-session push queue cap (a complementary capacity boundary at the IPC layer)
> - `specs/v2/key-revocation.md §7.4` — worktree retention for forensic review (constrains GC)
> - `specs/v2/immutable-artifact-store.md` — artifact-store GC, retention policies (consumes disk this spec budgets)
> - `specs/v2/v2-deep-spec.md §VM-Lifecycle` — microVM provisioning (consumer of memory and slot capacity)

---

## 1. The Problem

A RAXIS host is a single physical or virtual machine running the kernel and (potentially many) microVMs. Every resource it manages — memory, CPU, disk, file descriptors, SQLite connections, audit-log throughput — is finite. Without explicit caps:

- The host overcommits memory; OOM-killer takes random VMs (including the kernel itself); audit chain breaks.
- The disk fills with worktrees, bundle stagings, audit segments, or artifact store; new writes silently fail; partial state accumulates.
- A single greedy initiative monopolizes VM slots; other initiatives starve indefinitely; operators see no progress for unrelated work.
- A burst of operators submitting initiatives produces an unbounded admission queue; the kernel's intent dispatcher backs up; all sessions become slow.

This spec defines the resource caps, the watchdogs that detect approach to caps, the behavior at caps (admit-halt / queue / reject), and — critically — the interaction between disk-full conditions and the multi-phase write protocols (`IntegrationMerge` §11, audit log append, SQLite WAL flush). It also specifies the fairness model that prevents one initiative from starving another.

The user-facing question this spec answers: "what happens when the host runs out of X, and how do I configure that behavior?"

---

## 2. Resource Categories

RAXIS budgets six distinct resource categories. Each has its own cap configuration in `policy.toml` and its own watchdog. The categories are independent — running out of one does not directly affect the others, except as detailed in cross-cutting interactions (§7, §8, §11).

| Category | Unit | Cap configured as | Primary failure mode |
|---|---|---|---|
| VM concurrency | count of running microVMs | `max_concurrent_vms` | Admission queue or admit-halt |
| Aggregate VM memory | MiB | `max_aggregate_vm_memory_mb` | Admission queue or admit-halt |
| Per-initiative VM slots | count | `max_per_initiative_concurrent_vms` | Sub-task activation deferred |
| Disk space | bytes free under `disk_root` | `min_free_disk_mb` watchdog | Per `disk_full_behavior` (§7) |
| File descriptors | per-process count | inherited from `ulimit -n` | Detected at startup; admit-halt if too low |
| Admission queue depth | queued intents | `admission_queue_depth` | Operator-facing reject |

---

## 3. Configuration in `policy.toml`

```toml
[host_capacity]
# VM concurrency
max_concurrent_vms                 = 16
max_aggregate_vm_memory_mb         = 49152      # 48 GiB across all VMs
max_per_initiative_concurrent_vms  = 4
default_vm_memory_mb               = 2048       # if plan doesn't specify; max enforced separately
max_vm_memory_mb                   = 8192       # ceiling for any single VM

# Disk
disk_root                          = "/var/lib/raxis"
min_free_disk_mb                   = 5120       # 5 GiB headroom; below this triggers disk_full_behavior
disk_full_behavior                 = "halt_admit"   # "halt_admit" | "gc_then_retry" | "halt_all"

# Per-component disk caps
worktree_quota_mb                  = 2048       # per session
master_repo_quota_mb               = 8192       # per initiative; soft cap, warns on exceed
audit_log_max_size_gb              = 50         # rotates segments above this; oldest segments archived per audit-retention.md
artifact_store_quota_gb            = 100        # immutable artifact store; GC-able per immutable-artifact-store.md

# Admission queue
admission_queue_depth                  = 64
admission_queue_per_operator_default   = 8          # default cap per operator credential

# Process / FD
required_min_fd_limit              = 4096       # kernel refuses to start if ulimit -n < this

# Fairness
fairness_policy                      = "round_robin_per_initiative"   # only value in V2; V3 adds "priority"
starvation_protection_window_seconds = 300       # if an initiative gets no VM slot for this long, escalate

# Per-operator overrides for admission_queue_per_operator_default.
# Opt-in only — declared explicitly so operators must reason about each elevation.
# Use for service accounts (CI/CD, automation) that legitimately burst many intents;
# human operators rarely need overrides. See §10.2 for the enforcement model and
# §15.5 for the design rationale. (TOML ordering: array-of-tables MUST come after
# all scalar [host_capacity] keys above; otherwise subsequent scalars would be
# parsed as keys of the last override entry.)
[[host_capacity.operator_quota_overrides]]
operator_id            = "ci-service-account"
admission_queue_limit  = 64
purpose                = "CI/CD pipeline; bursts of up to 64 parallel PR reviews"

[[host_capacity.operator_quota_overrides]]
operator_id            = "nightly-batch"
admission_queue_limit  = 32
purpose                = "Nightly batch job; admits up to 32 long-running initiatives"
```

Defaults are conservative (small) so a fresh install on modest hardware does not crash. Production deployments tune per host capability. All caps are policy-pushable per `policy-epoch-diffing.md`; changing capacity caps advances the policy epoch.

---

## 4. VM Concurrency Cap

### 4.1 Tracking

`sessions.state IN ('Active', 'Paused', 'AwaitingEscalation')` AND `sessions.vm_pid IS NOT NULL` defines a VM as "running." The kernel maintains an in-memory `running_vm_count` updated atomically on VM start (post-spawn) and VM stop (post-reap).

A separate column `sessions.requested_memory_mb` records what the plan declared. `running_vm_memory_mb_total = SUM(requested_memory_mb)` over running sessions.

### 4.2 Pre-admission check

The cap is strict: V2 does not support overcommit, even opt-in. See §15.4 for the design rationale (kernel survival under host OOM-killer pressure).

Before spawning a VM (`approve_plan` for the root Orchestrator session, or `ActivateSubTask` for sub-tasks), the kernel checks:

```
if running_vm_count >= max_concurrent_vms:
    return AdmissionDeferred { reason: VmCountAtCap }
if running_vm_memory_mb_total + plan.vm_memory_mb > max_aggregate_vm_memory_mb:
    return AdmissionDeferred { reason: VmMemoryAtCap }
if initiative.running_vm_count >= max_per_initiative_concurrent_vms:
    return AdmissionDeferred { reason: PerInitiativeVmAtCap }
```

`AdmissionDeferred` is NOT a failure. It places the request on the admission queue (§10). The session row is created in state `Queued`; no VM is spawned. When capacity frees, the queue is drained and the session transitions to `Active`.

### 4.3 Cap-changing: policy push

If `max_concurrent_vms` decreases via a policy push and the new cap is below `running_vm_count`, the kernel does NOT terminate any sessions. It simply admits no new ones until natural drain brings the running count under the new cap. This avoids accidentally killing live work via configuration changes. (To kill sessions in a planned reduction, the operator uses `raxis session abort` per session.)

If the cap increases, the queued-up intents drain immediately on the next admission scan.

---

## 5. Aggregate VM Memory Budget

VMs are budgeted by their declared memory, not their actual usage. Plans declare `[plan] vm_memory_mb = N`; the kernel pins this as the VM's memory allocation (`VZVirtualMachineConfiguration.memorySize` on AVF; `MemSize` in Firecracker). Over-declaration wastes budget but prevents OOM; under-declaration risks the agent crashing.

`max_aggregate_vm_memory_mb` is the total budget. The pre-admission check (§4.2) refuses to spawn a VM whose memory would push the total over budget. This is a hard cap — exceeding it risks host OOM-killer activity, and OOM-killing the kernel means the audit chain breaks at an unpredictable point (a catastrophic INV-05 violation).

The kernel reserves additional memory for itself: `kernel_reserved_memory_mb` (default 1024). The effective budget is `max_aggregate_vm_memory_mb` plus `kernel_reserved_memory_mb`; the operator must ensure the host has at least that much physical memory plus swap headroom. The kernel does NOT check host physical memory against this — that is the operator's responsibility, validated by the operator's deployment checklist.

---

## 6. Disk Quota Subsystems

`disk_root` (default `/var/lib/raxis`) contains:

```
/var/lib/raxis/
├── state.db              SQLite kernel state (sessions, escalations, key_trust_state, pending_pushes, etc.)
├── state.db-wal          WAL for state.db
├── state.db-shm          SHM for state.db
├── audit/                Append-only audit log segments
│   ├── 0001.log
│   ├── 0002.log
│   └── ...
├── artifacts/            Immutable artifact store
│   ├── policies/<sha>/
│   ├── plans/<sha>/
│   └── keys/<fingerprint>/
├── master_repos/         Bare git repos, one per initiative
│   └── <initiative_uuid>/
├── worktrees/            Per-session worktrees (mounted into VMs via VirtioFS)
│   └── <session_uuid>/
├── bundles/              Per-initiative bundle staging (Executor → Orchestrator routing)
│   └── <initiative_uuid>/
└── tmp/                  Scratch space for in-progress operations (gix tmp packs, fetch-temp dirs)
```

Each subsystem has its own quota and GC behavior. The aggregate is bounded by the underlying filesystem capacity; the watchdog (§7) acts on aggregate free space.

### 6.1 Per-worktree quota

Each session's worktree is capped at `worktree_quota_mb` (default 2 GiB). Enforced via:

- **Soft enforcement (always)**: a periodic scan (every 30s) computes `du -s` on each active session's worktree and updates `sessions.worktree_size_mb`. If size exceeds 90% of quota, the kernel emits `KernelPush::DiskQuotaWarning { current_mb, quota_mb }` to the planner. If size exceeds 100% of quota, the kernel emits `KernelPush::DiskQuotaExceeded` and the next write-class intent (CompleteTask, IntegrationMerge) returns `FAIL_DISK_QUOTA_EXCEEDED`. The session does NOT auto-terminate — the agent has a chance to clean up large files and retry.
- **Hard enforcement (when filesystem supports it)**: if the host filesystem supports per-directory quotas (XFS prjquota, ZFS dataset quotas), the kernel sets a hard quota at `worktree_quota_mb × 1.1` (10% slack for the soft enforcement to surface first). If the filesystem doesn't support quotas (ext4 without prjquota), only soft enforcement applies and the operator is warned at startup.

### 6.2 master_repo size

`master_repos/<initiative_uuid>/` grows monotonically with merge history. `master_repo_quota_mb` is a SOFT cap — exceeding it does NOT block merges (you can't refuse to admit valid history). It triggers `KernelPush::MasterRepoLargeWarning` to the Orchestrator and an `OperatorAttentionRequired { kind: MasterRepoOverQuota }` audit event so the operator can plan to archive or split the initiative.

### 6.3 Audit log

Audit segments are append-only. When the active segment exceeds `audit_segment_size_mb` (default 256), it is closed and a new segment is opened (`0002.log`). Aggregate audit storage is bounded by `audit_log_max_size_gb`; oldest segments are archived per `audit-retention.md` (a separate spec, not authored here). Audit writes are PRIORITIZED at the disk-full watchdog level — if there is any free space at all, audit writes succeed; non-audit writes fail first (§7.5).

### 6.4 Bundle staging

`bundles/<initiative_uuid>/<task_id>.bundle` files are written by Executors (via Kernel-mediated bundle creation in CompleteTask) and consumed by Orchestrators (via `git fetch` from the VM-side mount of the staging directory). Each bundle is ephemeral: deleted when the corresponding sub-task is included in an `IntegrationMerge` or when the initiative completes.

Bundle staging is uncapped per-initiative but contributes to the aggregate disk watchdog. A pathological initiative with many large bundles can trigger the watchdog; in that case the disk_full_behavior (§7) applies.

### 6.5 tmp directory

`tmp/` is for in-progress operations: gix's pack-receive temp files during `git fetch`, scratch space for `gix gc`, in-progress tarball generation for diff display. Cleaned on every kernel startup (anything left from a previous run is garbage). Cleaned per-operation when the operation completes. Capped at `tmp_quota_mb` (default 4 GiB); exceeding triggers cleanup of the oldest tmp files (LRU).

### 6.6 SQLite state.db

`state.db` itself grows with `pending_pushes`, `audit_events_index` (a queryability index, separate from the canonical audit-log files), `subtask_activations`, etc. SQLite VACUUM is run automatically when the WAL file exceeds `wal_checkpoint_threshold_mb` (default 64). VACUUM requires up to `state.db.size + state.db-wal.size` free space; the disk watchdog (§7) reserves headroom for this.

### 6.7 Abandoned-worktree retention

When a task transitions to `Failed` (per `agent-disagreement.md §7`), its worktree enters the abandoned-commits lifecycle and is retained on disk for forensic inspection and operator salvage. Sizing characteristics:

- An abandoned worktree's size on disk equals the active worktree's size at the moment of failure (file copy; checkpoint of the failed state, not a live mount).
- The `[worktree_lifecycle]` policy (`abandoned_commits_retention`, `salvage_window`) governs total retention duration. Defaults: 30 days total retention, 7 day salvage window.
- Abandoned worktrees do NOT count against `worktree_quota_mb` (which is per-active-session); they accumulate as a separate pool tracked by `sessions.worktree_state = 'AbandonedSalvageable' | 'AbandonedArchived'` rows.
- They DO count against the aggregate disk watchdog (§7) — abandoned worktrees consume `disk_root` space like any other on-disk artifact.

Operators with tight disk budgets should shorten the retention defaults rather than relying on the watchdog to reclaim. Per `INV-CONVERGENCE-05`, the watchdog is forbidden from auto-purging abandoned worktrees inside `salvage_window`; the only path to in-window reclamation is the explicit, audited `raxis worktree purge --force <task_id>` operator command (§7.8).

---

## 7. Disk Full: Detection and Response

### 7.1 The watchdog

A dedicated tokio task runs every 5 seconds:

```
free_mb = statvfs(disk_root).f_bavail * f_frsize / (1024 * 1024)
if free_mb < min_free_disk_mb:
    transition to DiskFullState
else:
    transition to DiskHealthyState
```

The state is held in a single atomic enum, read by every write-class intent handler before issuing the write.

### 7.2 `disk_full_behavior` options

The default is `halt_admit`, deliberately chosen over `gc_then_retry`. See §15.1 for the design rationale (predictability beats apparent self-healing; `gc_then_retry` as default produces a thrashing-loop pathology that operators cannot easily diagnose).

| Value | Behavior |
|---|---|
| `halt_admit` (default) | New write-class intents return `FAIL_DISK_FULL` immediately. In-flight operations continue (their writes are typically small and reserved within the 5 GiB headroom). Read-class intents (queries, audit reads, escalation views) continue normally. |
| `gc_then_retry` | Triggers an immediate GC pass on the immutable artifact store and SQLite VACUUM. After GC, re-checks free space. If still below threshold, falls through to `halt_admit` for the duration. Useful for managed environments where automatic recovery is preferable to operator intervention. |
| `halt_all` | All intents return `FAIL_DISK_FULL`, including reads. Strictest; only chosen for environments that prefer explicit halt over best-effort continuation. |

### 7.3 What "write-class" means

Write-class intents (subject to halt under `halt_admit`):
- `ApprovePlan`, `ApprovePolicy`
- `ActivateSubTask`, `CompleteTask`, `SubmitReview`
- `IntegrationMerge`
- `EscalationRequest`, `EscalationApprove`, `EscalationReject`
- `EgressRequest`
- `RetrySubTask`

Read-class intents (allowed under `halt_admit`):
- Operator-side queries (`raxis session list`, `raxis log`, etc. — these go through the read-only operator API)
- `KernelPush` deliveries (the planner reading pushes does not consume disk)
- Audit log reads

### 7.4 In-flight operations during halt

Halt applies at admission only — operations already past admission continue. This is crucial for `IntegrationMerge` because Phases 2 and 3 must complete before the kernel is fully consistent (per `integration-merge.md §11`). Reserved headroom is sized to allow any reasonable in-flight write to complete:

- The `min_free_disk_mb` headroom (default 5 GiB) is sized to absorb: typical pack-fetch (≤ 1 GiB), SQLite WAL flush (≤ 256 MiB), audit segment append (≤ 1 MiB per event), and a comfortable safety margin.
- Plans that produce unusually large merges (gigabyte-scale generated artifacts) can declare `[plan] expected_max_merge_mb = N` and the kernel adjusts the per-initiative reservation. If the operator declares more than the host supports, `approve_plan` returns `FAIL_INSUFFICIENT_HEADROOM`.

### 7.5 Audit writes are prioritized

Audit writes are reserved against a separate budget: `audit_reserved_mb` (default 1024, fenced inside the `min_free_disk_mb` headroom). Even when the rest of the system is in `DiskFullHalt`, audit writes succeed against this reserve. The kernel cannot continue without the ability to write audit events (INV-05); if even the audit reserve is exhausted, the kernel halts entirely (§7.6).

### 7.6 Audit reserve exhausted: total halt

The total-halt response is categorical: the kernel does not log-and-continue on audit failure. See §15.2 for the design rationale (an un-audited state change is indistinguishable from forgery to a future auditor; INV-05 cannot tolerate gaps in the chain).

If `free_mb < audit_reserved_mb`, the kernel transitions to `AuditWriteImpossible` state:
- All intents (including reads) return `FAIL_AUDIT_UNWRITABLE`.
- The kernel stops accepting new IPC connections.
- An out-of-band log line is written to stderr (no audit event possible): `RAXIS HALTED: free disk = N MiB, audit reserve required = M MiB`.
- The operator must free space and restart the kernel. There is no automatic recovery from `AuditWriteImpossible` because we cannot write the audit event that would record the recovery.

This is the most extreme failure mode in V2. INV-CAPACITY-04 makes it categorical: rather than allow even one un-audited state change, the kernel halts.

### 7.7 Recovery on freed disk

When the watchdog detects `free_mb >= min_free_disk_mb` again (via the 5-second poll), it transitions back to `DiskHealthyState`. Pending intents in the admission queue are re-evaluated. An audit event `DiskHealthyAfterFull { previous_free_mb, current_free_mb, halt_duration_seconds }` is emitted.

Recovery from `AuditWriteImpossible` requires kernel restart (operator must free space first); there is no auto-recovery from the within-process side because of §7.6.

### 7.8 Interaction with abandoned-worktree retention (`INV-CONVERGENCE-05`)

Per `agent-disagreement.md §7` and `INV-CONVERGENCE-05`, abandoned worktrees from `Failed` tasks consume `disk_root` space and may contribute to disk pressure. The disk watchdog and any `gc_then_retry` GC pass MUST NOT auto-purge abandoned worktrees that are still inside their `salvage_window` (default 7 days). This is a deliberate trade-off: the forensic record survives transient disk pressure; reclamation requires explicit operator action.

The exact interactions:

1. **`disk_full_behavior = "halt_admit"` (default).** The watchdog never deletes abandoned worktrees. `halt_admit` failed-closes admission instead of reclaiming forensic data. Operators inspecting the resulting halt receive `KernelPush::DiskFull { abandoned_worktree_pool_mb }` so they can decide whether to extend disk, purge in-window worktrees with `--force`, or wait for the salvage window to elapse and natural retention-window purge to run.

2. **`disk_full_behavior = "gc_then_retry"`.** The GC pass collects from the immutable artifact store and runs SQLite VACUUM only. It does NOT touch abandoned worktrees inside `salvage_window` even though they would yield the largest reclamation. Worktrees past `abandoned_commits_retention` (i.e., already eligible for natural purge) are reclaimed by GC; the GC pass for those is functionally a "perform overdue scheduled purge now" and is audited as `WorktreeRetentionExpiredPurge`.

3. **`disk_full_behavior = "halt_all"`.** Same as `halt_admit` for purge purposes — no abandoned-worktree purge under any disk-pressure condition.

4. **Forced operator purge inside `salvage_window`.** The operator runs `raxis worktree purge --force <task_id>`. The kernel reclaims the worktree, audits `WorktreeForciblyPurgedDuringSalvage { task_id, salvage_remaining_seconds, operator_id, justification }`, and the salvage opportunity is permanently lost. The forced-purge command requires `--justification "<text>"` so the audit trail records why the operator chose forensic data destruction over service degradation.

5. **Watchdog audit visibility.** When the watchdog declines to purge abandoned worktrees that would relieve pressure, it emits `DiskPressureWithAbandonedRetention { current_free_mb, abandoned_pool_mb, in_window_count, oldest_failure_age_hours }` so the operator dashboard surfaces the trade-off explicitly. This event is rate-limited to once per 5-minute window to avoid log flooding during sustained pressure.

`INV-CONVERGENCE-05` and `INV-CAPACITY-02` are designed to compose: `halt_admit` fails closed at admission rather than destroying forensic data, and `INV-CONVERGENCE-05` ensures no automated path can reclaim that data behind the operator's back. The combined guarantee is "abandoned worktrees inside their salvage window survive any disk-pressure event short of explicit operator-forced purge."

---

## 8. Disk Full and `IntegrationMerge` Staging

This section directly answers the question: can a disk-full condition during `IntegrationMerge` produce a partial transaction or unrecoverable state?

**Answer: no.** The three-phase model in `integration-merge.md §11` is structurally robust to disk-full at every phase, provided the audit reserve (§7.5) is preserved. Every phase either fully succeeds, fully fails (rolling back via SQLite atomicity), or fails at a recoverable boundary (handled by §11.3 startup recovery). This section enumerates each disk-full point and shows the resulting state.

### 8.1 Staging directories involved

`IntegrationMerge` touches five distinct disk surfaces:

1. **Orchestrator's worktree** (`worktrees/<orchestrator_uuid>/`): the source of `commit_sha`. Already on disk before `IntegrationMerge` is submitted; not written by the merge handler itself.
2. **Bundle staging** (`bundles/<initiative_uuid>/`): consumed by the Orchestrator during its merge work, BEFORE submitting `IntegrationMerge`. Not touched by the kernel handler.
3. **`master_repo`** (`master_repos/<initiative_uuid>/.git/`): target of the kernel's `git fetch` + `git update-ref` during Phase 2.
4. **`tmp/`**: gix's pack-receive temporary files written during `git fetch` before atomic rename into `master_repo/.git/objects/pack/`.
5. **SQLite state.db + WAL**: target of Phase 1 and Phase 3 commits, plus the audit event INSERT inside Phase 1.

### 8.2 Disk-full scenarios per phase

**Phase 1 (SQLite intent commit) under disk full.**

`BEGIN IMMEDIATE` requests the database write lock and performs UPDATE/INSERT writes. If the WAL append fails because the disk is full:
- SQLite returns `SQLITE_FULL` to the rusqlite caller.
- The transaction is implicitly rolled back; no rows are modified, no audit event is recorded.
- The handler returns `FAIL_DISK_FULL` to the Orchestrator.
- **State after failure: identical to state before submission.** No `git_apply_pending`, no audit event, no current_sha advance. Orchestrator may resubmit when disk frees.

The audit-reserve mechanism (§7.5) ensures the audit-event INSERT specifically does not exhaust headroom that subsequent writes would need. The `BEGIN IMMEDIATE` lock-and-fail completes within milliseconds; the kernel does not hold the write lock waiting for disk to free.

**Phase 2 (`git fetch`) under disk full.**

The kernel invokes `gix::Repository::fetch` to pull `commit_sha` and its ancestors from the Orchestrator's worktree into `master_repo`. gix writes pack files into `tmp/` first, then atomically renames into `master_repo/.git/objects/pack/`. If the disk fills mid-fetch:

| Sub-case | What's on disk | Recovery |
|---|---|---|
| 2a. Failed before any tmp file written | tmp/ unchanged; master_repo unchanged | Re-fetch on retry (idempotent). |
| 2b. Failed mid-write of a tmp pack | Partial `tmp/pack-<sha>.tmp` file | gix's startup GC removes orphan tmp files. Re-fetch on retry. |
| 2c. Failed after tmp file written, before atomic rename | Complete `tmp/pack-<sha>.tmp` not yet renamed | gix's startup GC removes orphan tmp files. Re-fetch on retry; same pack will be re-created. |
| 2d. Renamed into pack/ but not yet referenced by index | `pack-<sha>.pack` and `.idx` exist; objects unreferenced | Objects are reachable by SHA; subsequent operations find them. Re-fetch is a no-op for already-present objects. |
| 2e. Fetch fully succeeded; `update-ref` failed (disk full at .lock write) | All objects in master_repo; `refs/heads/master` still at old base_sha | §11.3 Case A recovery: re-runs both fetch (no-op) and update-ref (succeeds when disk frees). |

In all sub-cases, `git_apply_pending = 1` remains set in SQLite (Phase 1 already committed). The handler returns `FAIL_DISK_FULL_DURING_GIT_APPLY` to the Orchestrator. The Orchestrator does NOT retry — instead, the kernel-side recovery on next disk-healthy transition (or kernel restart) replays Phase 2.

**Phase 3 (clear `git_apply_pending`) under disk full.**

Phase 3 is a single small UPDATE statement. The audit-reserve protects this — Phase 3 is sized in tens of bytes, well within `audit_reserved_mb`. In practice, Phase 3 cannot fail for disk reasons unless the audit reserve itself is exhausted, which triggers `AuditWriteImpossible` (§7.6) and total halt.

If Phase 3 nonetheless fails: state is `git_apply_pending = 1` AND `current_sha == refs/heads/master`. §11.3 Case B recovery on next startup detects this and clears the flag.

### 8.3 Why this is structurally non-partial

A "partial transaction" would mean: SQLite says one thing AND git says a different thing AND the kernel cannot reconstruct what should be true. This cannot happen because:

- Phase 1 is atomic in SQLite (`BEGIN IMMEDIATE` either commits all rows or none).
- Phase 2 is idempotent in git (re-fetching a SHA already present is a no-op; updating a ref to its current value is a no-op).
- Phase 3 is atomic and idempotent in SQLite.
- The `git_apply_pending` flag is the durable indicator that Phase 2 may be incomplete; recovery uses it to disambiguate.
- The audit reserve guarantees the audit event for Phase 1 is durably recorded before any disk-related failure can prevent it.

The worst observable state under any disk-full failure is: `git_apply_pending = 1` for some duration with refs lagging, recoverable via §11.3 once disk frees. **No combination of disk-full timing produces an irrecoverable inconsistent state.**

### 8.4 INV-CAPACITY-03

**No partial `IntegrationMerge` transactions under disk-full conditions.**

For any disk-full event during `IntegrationMerge`, the resulting state is exactly one of:
- (a) Pre-merge state, unchanged (Phase 1 failure).
- (b) `git_apply_pending = 1` with kernel-recoverable git lag (Phase 2 failure at any sub-case).
- (c) `git_apply_pending = 1` with git fully consistent (Phase 3 failure; Case B recovery clears the flag).

State (c) is rare-to-impossible in practice given the audit reserve. States (a) and (b) are recovered automatically. There is no state in which the kernel's view of the merge is inconsistent with reality and not detectable via the `git_apply_pending` flag.

### 8.5 What about disk-full during the Orchestrator's pre-merge work?

The Orchestrator does its own git work (fetching bundles, running `git merge`) inside its VM, writing to its own worktree. If the worktree quota (§6.1) or aggregate disk fills during this:

- The agent's git command fails.
- The agent's planner detects the failure and SHOULD escalate (`EscalationRequest { class: PlannerError }`) with the error context.
- The Orchestrator's session is not auto-terminated; it remains `Active` and the operator can investigate.
- No `IntegrationMerge` is ever submitted because the Orchestrator never produced a `commit_sha` to submit.

This is the cleanest failure mode: the kernel is uninvolved, no kernel-side state is touched, the agent surfaces the error.

### 8.6 What about disk-full during bundle staging?

When an Executor's `CompleteTask` is admitted, the kernel creates a bundle (`git bundle create` from the Executor's worktree, stored in `bundles/<initiative_uuid>/<task_id>.bundle`). If this fails for disk reasons:

- The bundle write is part of Phase 2 of `CompleteTask` (analogous to `IntegrationMerge`'s Phase 2 — out-of-SQLite work after Phase 1 commit).
- `CompleteTask` uses the same three-phase pattern: Phase 1 marks `tasks.state = 'Completing'`, Phase 2 writes the bundle, Phase 3 marks `tasks.state = 'Completed'` and enqueues the `KernelPush::SubTaskCompleted` to the Orchestrator.
- Phase 2 disk-full leaves `tasks.state = 'Completing'`, no bundle on disk; recovery on next disk-healthy transition retries the bundle write. (This requires the Executor's worktree to still be on disk — INV-MERGE-WORKTREE-RETAIN extends to Executor worktrees with `tasks.state IN ('Completing', 'Completed-pending-bundle-routing')`.)

(`CompleteTask` is specified separately; this paragraph is a forward-reference noting that the same disk-full robustness applies.)

---

## 9. Initiative Fairness

### 9.1 The starvation problem

If initiative A has 50 sub-tasks and initiative B has 1, and `max_concurrent_vms = 8`, naive FIFO admission could give A all 8 slots indefinitely while B's single sub-task waits for hours. RAXIS prevents this with explicit round-robin allocation.

### 9.2 Round-robin per initiative

When a VM slot frees and the admission queue has multiple initiatives waiting, the kernel allocates to the initiative that has waited longest since its last activation. Concretely:

```
candidates = SELECT initiative_id, MAX(activation_time) AS last_activation
               FROM sessions
              WHERE state IN ('Active', 'Paused', 'AwaitingEscalation')
                 OR state = 'Queued' AND queued_at IS NOT NULL
              GROUP BY initiative_id
              HAVING <queued sub-task exists>;

next_initiative = candidates ORDER BY last_activation ASC LIMIT 1
next_session = sessions in next_initiative with state = 'Queued' ORDER BY queued_at ASC LIMIT 1
spawn next_session
```

This guarantees: no initiative waits more than `(N - 1) × avg_session_duration` for its next slot, where N is the number of initiatives competing.

### 9.3 Starvation protection

If an initiative has been waiting on a VM slot for longer than `starvation_protection_window_seconds` (default 300), the kernel emits `OperatorAttentionRequired { kind: InitiativeStarvation, initiative_id, queued_for_seconds }`. This is an alert, not an action — it tells the operator that capacity is undersized for the workload. The kernel does NOT dynamically increase caps; that's an operator decision.

### 9.4 Per-initiative VM cap

`max_per_initiative_concurrent_vms` (default 4) prevents a single initiative from monopolizing VM slots even under round-robin. An initiative with 50 parallelizable sub-tasks runs at most 4 concurrently; the remaining 46 wait in the queue. This bounds the impact of any one initiative on overall host capacity.

### 9.5 V3 deferral: priorities

V2 ships with strict equality. V3 may add `[plan] priority = "high" | "normal" | "low"` and corresponding admission policies. V2 does not include this because priority systems require careful operational thought (preemption? starvation guards on low-priority? operator workflow for re-prioritizing in-flight work?) that's better deferred than rushed. See §15.3 for the full rationale (priority inversion, starvation, preemption complexity, attractive-nuisance failure mode where every plan ends up declaring `high`).

---

## 10. Admission Queue

### 10.1 Queue depth

The admission queue holds intents that have been received and validated structurally but cannot be admitted because of a capacity cap (VM count, memory, per-initiative cap). It is bounded by `admission_queue_depth` (default 64).

When the queue is at depth, new intents that would queue return `FAIL_ADMISSION_QUEUE_FULL` to the operator/agent immediately. This is an operator-facing error: it tells the submitter that the host is overloaded and they should either retry later or scale the deployment.

### 10.2 Per-operator limit

`admission_queue_per_operator_default` (default 8) bounds how many intents from any one operator credential can be queued at once. This prevents a single misbehaving CLI client from filling the queue and starving other operators. When a single operator hits their effective cap, their additional intents return `FAIL_PER_OPERATOR_QUEUE_LIMIT` until some of their queued intents drain.

The default of 8 is sized for human operators submitting work interactively. Service accounts (CI/CD pipelines, batch automation) routinely burst many more intents than a human ever would: a CI run that auto-submits one initiative per pull request may have 20+ pending at once during peak hours. A flat default of 8 would force such workflows to retry repeatedly, eroding the fail-fast guarantee that `FAIL_PER_OPERATOR_QUEUE_LIMIT` is meant to provide (the operator can no longer treat the rejection as "I'm misbehaving" — it's just "I'm busy"). See §15.5 for the design rationale.

#### 10.2.1 Per-operator overrides

Operators may declare per-credential overrides in `policy.toml`:

```toml
[host_capacity]
admission_queue_per_operator_default = 8

[[host_capacity.operator_quota_overrides]]
operator_id            = "ci-service-account"
admission_queue_limit  = 64
purpose                = "CI/CD pipeline; bursts of up to 64 parallel PR reviews"
```

Resolution order at intent admission:

1. Identify the submitter (operator credential ID, derived from the IPC layer's authentication — typically a UID-bound socket peer, or the operator-token-derived ID; specified in `peripherals.md §operator-ipc`).
2. Look up the operator ID in `host_capacity.operator_quota_overrides`.
3. If a match exists, the effective per-operator cap is the override's `admission_queue_limit`.
4. Otherwise, the effective cap is `admission_queue_per_operator_default`.

The override is opt-in and explicit — there is no wildcard or pattern-matching mechanism in V2. Each elevated operator is named individually, forcing the operator deploying the policy to reason about each elevation. This is intentional: the per-operator cap is a defense against silent abuse, and a `*`-wildcard override would erode the defense to nothing.

#### 10.2.2 Bounds and validation

The override mechanism is bounded:

- `admission_queue_limit` MUST be ≤ `admission_queue_depth` (an individual operator cannot queue more than the global queue holds in total).
- `admission_queue_limit` MUST be ≥ 1 (zero would silently lock out an operator; that should be done via operator deauthorization, not via queue cap).
- `operator_id` MUST be a unique key within `operator_quota_overrides` (duplicate entries cause `approve_policy` to fail with `FAIL_DUPLICATE_OPERATOR_OVERRIDE`).
- `purpose` MUST be present and non-empty (a forensic-readable rationale; future auditors reviewing why an operator had elevated limits will expect to find it).

`approve_policy` rejects malformed override blocks. The validation runs at policy push time, not at admission time, so misconfiguration is caught early.

#### 10.2.3 Audit visibility

When an intent is queued or rejected, the audit event records both the operator's effective cap and whether it came from the default or an override:

```rust
AuditEventKind::IntentQueued {
    intent_kind:           String,
    initiative_id:         Option<Uuid>,
    operator:              Option<String>,
    queue_depth_after:     u32,
    cap_reason:            String,
    operator_queue_count:  u32,                   // current count for this operator
    operator_queue_cap:    u32,                   // effective cap (default or override value)
    operator_cap_source:   OperatorCapSource,     // Default | Override
}

AuditEventKind::PerOperatorQueueLimitReached {
    operator:              String,
    intent_kind:           String,
    operator_queue_cap:    u32,
    operator_cap_source:   OperatorCapSource,
}
```

This makes it trivial to audit: "show me every operator who hit their cap, and whether it was the default or an explicitly-elevated override." Operators tuning their caps can use this to identify which service accounts need higher elevations.

#### 10.2.4 Override changes mid-flight

Overrides are policy-pushable. When `approve_policy` is called with a changed override list:

- New override added: takes effect immediately for new intent admissions; in-flight queued intents from that operator are not re-evaluated (they were admitted under the old cap and continue to count against the new cap until they drain).
- Existing override's `admission_queue_limit` increased: takes effect immediately; queued intents continue to count, and the operator can submit up to the new cap.
- Existing override's `admission_queue_limit` decreased below current queue depth for that operator: the operator's currently-queued intents remain queued (they were admitted; the kernel does not retroactively reject them); new intents from that operator are rejected until natural drain brings the count under the new cap.
- Override removed: operator falls back to `admission_queue_per_operator_default`. Same drain semantics as a decrease.

The kernel never silently drops queued intents to enforce a cap change. This preserves the "intent admitted = intent will run" guarantee.

### 10.3 Queue drain on capacity free

Whenever a session terminates (any reason) or completes, the kernel runs the admission scan. The scan picks the next eligible session per §9.2 round-robin. If the picked session can be admitted (capacity now permits), it is spawned and the queue length decrements.

### 10.4 Audit events

The full schemas for `IntentQueued` and `PerOperatorQueueLimitReached` (which carry the per-operator-cap and `operator_cap_source` annotation) appear in §10.2.3. The remaining queue-related audit events:

```rust
AuditEventKind::IntentAdmittedFromQueue {
    intent_kind:        String,
    initiative_id:      Uuid,
    queued_for_seconds: u64,
}

AuditEventKind::AdmissionQueueFull {
    intent_kind:        String,
    operator:           Option<String>,
    rejected_at_depth:  u32,
}
```

`AdmissionQueueFull` is distinct from `PerOperatorQueueLimitReached`: the former fires when the global queue (`admission_queue_depth`) is exhausted; the latter fires when a specific operator's per-credential cap (default or override) is exhausted while the global queue still has room.

---

## 11. SQLite WAL and Size Caps

### 11.1 WAL pressure

SQLite's WAL grows with every uncheckpointed write. By default, WAL is checkpointed when it reaches 1000 pages (≈4 MiB). RAXIS sets `wal_autocheckpoint = 16384` (≈64 MiB) for better throughput but adds an active checkpoint trigger when WAL exceeds `wal_checkpoint_threshold_mb` (default 64).

The active trigger is necessary because under heavy load, autocheckpoint can lag (it only runs at commit time). The active trigger is a periodic task (every 30s) that runs `PRAGMA wal_checkpoint(PASSIVE)` and, if PASSIVE returns busy, escalates to `RESTART` after 5 minutes of WAL growth past threshold.

### 11.2 WAL size cap

`wal_max_size_mb` (default 512) is a hard cap on WAL size. When approached:
- At 75% (384 MiB): emit `KernelPush::WalPressure` to all sessions; trigger `RESTART` checkpoint.
- At 100% (512 MiB): refuse new write transactions with `FAIL_WAL_FULL`. This forces drain — readers complete their snapshots, the next checkpoint succeeds, WAL shrinks.

WAL full is functionally equivalent to disk full for write purposes, but it has its own error code so operators can distinguish the cause.

### 11.3 VACUUM and free pages

SQLite's `VACUUM` rebuilds the database file, reclaiming free pages. RAXIS runs `auto_vacuum = INCREMENTAL` (set at database creation) and triggers `PRAGMA incremental_vacuum(N)` periodically (every hour) to release free pages back to the filesystem. Full `VACUUM` is invoked manually only via `raxis admin vacuum`.

### 11.4 Connection pooling

The kernel uses a single writer connection and a small pool of reader connections (default 4 readers). This avoids SQLite's database-wide write-lock contention. The connection pool size is fixed at startup, not configurable per intent — see Alt G in §16 for why.



---

## 12. File Descriptor Limits

### 12.1 Required minimum

The kernel checks `getrlimit(RLIMIT_NOFILE)` at startup. If the limit is below `required_min_fd_limit` (default 4096), the kernel refuses to start with `FAIL_INSUFFICIENT_FD_LIMIT`. The operator must `ulimit -n 4096` (or equivalent in their service manager) before launching.

### 12.2 Per-VM FD usage

Each running VM consumes ~10 FDs in the kernel: VSock listener, hypervisor control sockets, log file, two VirtioFS shares (rw worktree + ro raxis-tooling), couple of misc. With `max_concurrent_vms = 16`, that's ≈160 FDs for VM management, plus SQLite (≤ 8 FDs), audit log (1 FD per active segment), egress proxy (~50 FDs for connection pool), and operator IPC (~20 FDs). 4096 is comfortable for V2's expected scale.

### 12.3 V3 deferral: dynamic FD scaling

V2 fixes the limits at startup. V3 may explore re-checking and warning if usage approaches the static limit during operation (e.g., if `max_concurrent_vms` was increased mid-run). V2 keeps it simple.

---

## 13. Invariants

### INV-CAPACITY-01 — Fail-closed VM concurrency cap

The kernel never spawns a VM that would exceed `max_concurrent_vms`, `max_aggregate_vm_memory_mb`, or `max_per_initiative_concurrent_vms`. Admission requests beyond the cap are queued (§10) or rejected (`FAIL_ADMISSION_QUEUE_FULL`). The kernel does not "best-effort" allocate beyond cap.

**Where:** §4.2 pre-admission check; §10.1 queue depth.

**Scenario it prevents:** A burst of `ApprovePlan` intents rapidly spawns 50 VMs on a host configured for 16, exhausting host memory, triggering OOM-killer activity, killing the kernel mid-write, breaking the audit chain (INV-05 cascading violation).

### INV-CAPACITY-02 — `disk_full_behavior = halt_admit` admits no write-class intents below `min_free_disk_mb`

When the disk-full watchdog (§7.1) detects `free_mb < min_free_disk_mb`, no write-class intent (§7.3) is admitted. In-flight operations continue to drain against the audit reserve.

**Where:** §7.1 watchdog; §7.2 behavior table; §7.3 write-class enumeration.

**Scenario it prevents:** Disk fills during heavy admission; kernel keeps accepting intents; subsequent SQLite or git writes fail unpredictably; partial state accumulates. INV-CAPACITY-02 stops admission early enough that in-flight operations have headroom to finish cleanly.

**Composition with `INV-CONVERGENCE-05`:** When the disk-pressure source is in-window abandoned worktrees, `INV-CAPACITY-02` halts new admission and `INV-CONVERGENCE-05` (canonical home: `agent-disagreement.md §7`) forbids the watchdog from auto-purging those worktrees. The operator must either provision more disk, wait for `salvage_window` to elapse, or explicitly run `raxis worktree purge --force` to reclaim forensic data. See §7.8 for the full interaction matrix.

### INV-CAPACITY-03 — No partial `IntegrationMerge` transactions under disk-full

For any disk-full event during `IntegrationMerge` (any phase, any sub-case), the resulting state is one of: (a) pre-merge unchanged, (b) `git_apply_pending = 1` with kernel-recoverable git lag, (c) `git_apply_pending = 1` with git fully consistent. Recovery per `integration-merge.md §11.3` restores consistency in cases (b) and (c). State (a) is observably equivalent to the merge having never been submitted.

**Where:** §8 (full enumeration); `integration-merge.md §11.3` (recovery).

**Scenario it prevents:** Operator suspects a disk-full event during a merge and worries that git is "stuck" in a half-merged state. INV-CAPACITY-03 guarantees that no such state exists; the worst case is auto-recoverable on next disk-healthy transition.

### INV-CAPACITY-04 — Audit writes reserved; no un-audited state changes

A reserve of `audit_reserved_mb` (default 1024) within `min_free_disk_mb` is held exclusively for audit-event writes. State-changing operations that would trigger an audit event check the audit reserve before committing; if the reserve is exhausted, the kernel transitions to `AuditWriteImpossible` (§7.6) and halts all intents, including reads, until restart.

**Where:** §7.5 (audit reserve); §7.6 (AuditWriteImpossible state).

**Scenario it prevents:** A long-running disk-fill consumes the audit reserve; subsequent state changes happen but their audit events fail to write; the audit chain has gaps; INV-05 violated. INV-CAPACITY-04 prevents any state change from outliving an unwritable audit, even if it means halting more aggressively.

### INV-CAPACITY-05 — Round-robin per-initiative VM allocation

When multiple initiatives have queued sub-tasks and a VM slot frees, the kernel allocates to the initiative with the longest gap since its last activation (§9.2). No initiative waits more than `(N - 1) × avg_session_duration` for its next slot, where N is the count of competing initiatives.

**Where:** §9.2 round-robin algorithm; §9.3 starvation alert.

**Scenario it prevents:** Initiative A submits 50 sub-tasks at T0; initiative B submits 1 sub-task at T1. Naive FIFO would activate A's 50 before B's 1, starving B for hours. INV-CAPACITY-05 interleaves them.

### INV-CAPACITY-06 — Bounded admission queue with per-operator limit (default + opt-in overrides)

The admission queue is bounded by `admission_queue_depth` (default 64) and a per-operator effective cap. The per-operator effective cap is `admission_queue_per_operator_default` (default 8), unless overridden in `policy.toml` via `[[host_capacity.operator_quota_overrides]]` for a specifically-named operator. Overflow returns `FAIL_ADMISSION_QUEUE_FULL` (global) or `FAIL_PER_OPERATOR_QUEUE_LIMIT` (per-operator) immediately, surfacing the back-pressure to the submitter. The kernel never silently drops queued intents.

Override entries MUST be explicit per `operator_id` (no wildcards), MUST satisfy `1 ≤ admission_queue_limit ≤ admission_queue_depth`, and MUST carry a non-empty `purpose`. `approve_policy` validates these constraints at policy push time and emits `FAIL_INVALID_OPERATOR_OVERRIDE` on violation. Audit events for queueing and rejection record the effective cap AND its source (`Default` or `Override`) so future auditors can reconstruct the policy state under which any decision was made.

**Where:** §10.1, §10.2 (default + override mechanism), §10.2.2 (validation), §10.2.3 (audit visibility).

**Scenario it prevents (default):** A misbehaving CLI client floods the kernel with intents. Without a per-operator limit, the global queue fills with one operator's work and other operators are blocked. With the default cap, the misbehaving operator hits their limit first; other operators continue submitting normally.

**Scenario it prevents (overrides):** A CI/CD service account legitimately submits 20 parallel PR reviews from a single credential. Without overrides, a flat default of 8 forces the CI pipeline to retry repeatedly and erodes the fail-fast meaning of `FAIL_PER_OPERATOR_QUEUE_LIMIT`. With overrides, the operator declares the service account's elevated limit explicitly, the CI pipeline runs at its natural pace, and the rejection still works as a fail-fast for any operator without an override.

**Scenario it prevents (no wildcards):** An operator deploys a `*`-style override "to be safe" and inadvertently elevates every submitter to 64 — eroding the per-operator cap defense to nothing. INV-CAPACITY-06 forbids this by requiring named entries; any override is a deliberate per-operator decision that appears in the policy diff and the audit trail.

---

## 14. Implementation Checklist

### Schema (migration N)

- [ ] Add `requested_memory_mb INTEGER NOT NULL` to `sessions` (declared at session creation from plan)
- [ ] Add `worktree_size_mb INTEGER NOT NULL DEFAULT 0` to `sessions` (updated by quota scan)
- [ ] Add `state = 'Queued'`, `queued_at INTEGER` to `sessions` (admission queue persistence)
- [ ] Add table `admission_queue` for queue-position tracking (per-operator counts; can be derived from sessions WHERE state = 'Queued', but a separate table makes per-operator queries fast)

### `policy.toml` parser

- [ ] Add `[host_capacity]` section parsing in `crates/types/src/policy.rs`
- [ ] Validate `disk_full_behavior ∈ {"halt_admit", "gc_then_retry", "halt_all"}`
- [ ] Validate `fairness_policy = "round_robin_per_initiative"` (only valid V2 value; reject others)
- [ ] Validate `min_free_disk_mb >= audit_reserved_mb + max_in_flight_reservation` (sanity)
- [ ] Validate `required_min_fd_limit >= 1024` (cannot run below this regardless)
- [ ] Parse `[[host_capacity.operator_quota_overrides]]` entries; reject duplicates by `operator_id`
- [ ] Validate `admission_queue_limit ≥ 1` and `≤ admission_queue_depth` per override
- [ ] Validate `purpose` is present and non-empty per override
- [ ] Emit `FAIL_INVALID_OPERATOR_OVERRIDE` / `FAIL_DUPLICATE_OPERATOR_OVERRIDE` from `approve_policy` on violation

### `kernel/src/capacity/`

- [ ] `kernel/src/capacity/disk_watchdog.rs`: 5-second poll on `statvfs(disk_root)`; transitions DiskHealthy ↔ DiskFullHalt ↔ AuditWriteImpossible
- [ ] `kernel/src/capacity/vm_admission.rs`: pre-admission check per §4.2; returns Allow / Defer / Reject
- [ ] `kernel/src/capacity/queue.rs`: admission queue with FIFO + round-robin drain
- [ ] `kernel/src/capacity/operator_caps.rs`: resolves effective per-operator cap via override-or-default lookup; exposes `OperatorCapSource` for audit annotation
- [ ] `kernel/src/capacity/fairness.rs`: round-robin allocation algorithm per §9.2
- [ ] `kernel/src/capacity/quota_scan.rs`: 30-second `du`-based per-worktree quota check
- [ ] `kernel/src/capacity/wal_monitor.rs`: WAL size monitoring + checkpoint trigger
- [ ] `kernel/src/startup.rs`: FD limit check; reject startup if too low

### Disk-full integration

- [ ] Update every write-class handler to consult disk-full state before issuing writes
- [ ] Update `kernel/src/handlers/merge.rs` to handle `FAIL_DISK_FULL_DURING_GIT_APPLY` per §8.2 (leaves `git_apply_pending = 1`; relies on §11.3 recovery)
- [ ] Update `kernel/src/handlers/complete_task.rs` to use the same three-phase pattern (analogous to merge §11)
- [ ] Audit-reserve enforcement in audit-write helper

### Audit events

- [ ] `IntentQueued { intent_kind, initiative_id, operator, queue_depth_after, cap_reason, operator_queue_count, operator_queue_cap, operator_cap_source }`
- [ ] `IntentAdmittedFromQueue { intent_kind, initiative_id, queued_for_seconds }`
- [ ] `AdmissionQueueFull { intent_kind, operator, rejected_at_depth }`
- [ ] `PerOperatorQueueLimitReached { operator, intent_kind, operator_queue_cap, operator_cap_source }`
- [ ] `DiskFullHaltEntered { free_mb, behavior }`
- [ ] `DiskHealthyAfterFull { previous_free_mb, current_free_mb, halt_duration_seconds }`
- [ ] `AuditWriteImpossible { free_mb, audit_reserved_mb }` (logged to stderr too, since audit can't be written)
- [ ] `MasterRepoLargeWarning { initiative_id, current_mb, soft_cap_mb }`
- [ ] `WorktreeQuotaWarning { session_id, current_mb, quota_mb }`
- [ ] `WorktreeQuotaExceeded { session_id, current_mb, quota_mb }`
- [ ] `OperatorAttentionRequired` extended with `kind ∈ {DiskFull, AuditWriteImpossible, InitiativeStarvation, MasterRepoOverQuota, FdLimitInsufficient}`
- [ ] `WalPressure { current_mb, cap_mb, severity ∈ {Warning, Critical} }`
- [ ] `WalCheckpointTriggered { mode, duration_ms }`

### CLI

- [ ] `raxis capacity status` — current VM count, memory used, disk free, queue depth
- [ ] `raxis capacity tail` — live stream of capacity events
- [ ] `raxis admin vacuum` — manual VACUUM trigger (operator-only)
- [ ] `raxis admin gc` — manual GC of immutable artifact store, tmp/, archived audit segments

### Tests

- [ ] VM cap enforcement: configure `max_concurrent_vms = 2`; submit 5 ApprovePlan; verify 2 admitted, 3 queued
- [ ] VM cap drain: terminate one of the running sessions; verify next queued admits within 5s
- [ ] Memory cap: configure `max_aggregate_vm_memory_mb = 4096`; submit plans with 2 GiB each; verify 2 admit, 3rd queues
- [ ] Per-initiative cap: configure `max_per_initiative_concurrent_vms = 2`; one initiative with 5 parallel sub-tasks; verify 2 active, 3 queued
- [ ] Round-robin fairness: 2 initiatives with 10 sub-tasks each, `max_concurrent_vms = 2`; verify activations alternate (initiative A, B, A, B, ...)
- [ ] Starvation alert: artificially block initiative B for 301s; verify `OperatorAttentionRequired { InitiativeStarvation }` emitted
- [ ] Disk full halt: fill disk to below `min_free_disk_mb`; submit ApprovePlan; verify `FAIL_DISK_FULL`; verify in-flight CompleteTask still completes
- [ ] Disk full during merge Phase 2: stub gix to fail with disk-full mid-fetch; verify `git_apply_pending = 1` persists; free disk; restart kernel; verify §11.3 Case A recovery completes the merge
- [ ] Disk full during merge Phase 1: fill disk; submit IntegrationMerge; verify `BEGIN IMMEDIATE` rolls back, no `git_apply_pending` set, no audit event written
- [ ] Disk full during merge Phase 3: stub the Phase 3 UPDATE to fail; verify state is `git_apply_pending = 1` with `current_sha == refs/heads/master`; restart; verify §11.3 Case B recovery clears flag
- [ ] Audit reserve protection: fill disk to `audit_reserved_mb` exactly; verify state-changing intents return `FAIL_DISK_FULL`; verify audit writes for in-flight ops still succeed
- [ ] Audit reserve exhausted: fill disk below `audit_reserved_mb`; verify `AuditWriteImpossible` state, all intents return `FAIL_AUDIT_UNWRITABLE`, stderr log emitted
- [ ] Recovery from disk full: fill disk; observe halt; free disk; verify `DiskHealthyAfterFull` audit event after next watchdog poll; verify queued intents drain
- [ ] Admission queue depth: configure `admission_queue_depth = 2`; submit 5 intents (none admittable due to VM cap); verify first 2 queue, last 3 return `FAIL_ADMISSION_QUEUE_FULL`
- [ ] Per-operator queue limit (default): single operator submits 10 intents from one credential; verify first 8 queue, last 2 return `FAIL_PER_OPERATOR_QUEUE_LIMIT`; other operator can still submit 8; verify `operator_cap_source = Default` in audit
- [ ] Per-operator override applies: configure override `ci-service-account = 32`; submit 30 intents from that operator; verify all 30 queue successfully (assuming `admission_queue_depth ≥ 30`); verify `operator_cap_source = Override` in audit
- [ ] Per-operator override does not leak to other operators: same scenario, simultaneously submit 10 intents from `human-operator` (no override); verify human-operator caps at 8 with `operator_cap_source = Default`
- [ ] Per-operator override absent: no overrides configured; verify all operators use the default; audit records `operator_cap_source = Default` for every queued intent
- [ ] Override validation — out of range: `policy.toml` declares `admission_queue_limit = 0`; verify `approve_policy` returns `FAIL_INVALID_OPERATOR_OVERRIDE`
- [ ] Override validation — exceeds global queue: `policy.toml` declares `admission_queue_limit = 100` while `admission_queue_depth = 64`; verify `approve_policy` returns `FAIL_INVALID_OPERATOR_OVERRIDE`
- [ ] Override validation — duplicate operator_id: `policy.toml` declares two override entries for the same `operator_id`; verify `approve_policy` returns `FAIL_DUPLICATE_OPERATOR_OVERRIDE`
- [ ] Override validation — missing purpose: `policy.toml` declares an override with empty `purpose`; verify `approve_policy` returns `FAIL_INVALID_OPERATOR_OVERRIDE`
- [ ] Override change — increase mid-flight: operator at default cap 8 has 8 queued; policy push raises override to 16; verify operator can immediately submit 8 more without rejection
- [ ] Override change — decrease mid-flight: operator at override 32 has 20 queued; policy push lowers override to 8; verify the 20 queued intents continue to drain normally; verify new submissions from that operator return `FAIL_PER_OPERATOR_QUEUE_LIMIT` until count drops below 8
- [ ] WAL size: induce 1000 write transactions in a tight loop; verify checkpoint runs at threshold; verify WAL doesn't exceed `wal_max_size_mb`
- [ ] WAL hard cap: stub checkpoint to fail; verify `FAIL_WAL_FULL` returned when WAL exceeds cap
- [ ] FD limit: launch kernel with `ulimit -n 1024`; verify startup fails with `FAIL_INSUFFICIENT_FD_LIMIT`
- [ ] Worktree quota soft warning: write 1.9 GiB into worktree (cap 2 GiB); verify `WorktreeQuotaWarning` push delivered
- [ ] Worktree quota exceeded: write 2.1 GiB into worktree; submit CompleteTask; verify `FAIL_DISK_QUOTA_EXCEEDED`
- [ ] Worktree quota with hard FS quota (XFS): same scenarios on a host with prjquota enabled; verify hard quota fires before write completes

---

## 15. Foundational Design Decisions

This section records the five foundational commitments the host-capacity model is built on. They are higher-level than invariants (which describe the enforcement mechanism) and higher-level than the alternatives in §16 (which catalog implementation choices). They are recorded explicitly so future contributors do not relitigate them without first understanding why each commitment was made.

Each entry follows the same structure: **the decision**, **the alternative we considered**, **why we rejected it**, and **the scenario the rejection prevents**.

### §15.1 — `halt_admit` over `gc_then_retry` as default disk-full behavior

**Decision.** When the disk-full watchdog (§7.1) detects `free_mb < min_free_disk_mb`, the default behavior is `halt_admit`: refuse new write-class intents, let in-flight operations drain, page the operator. Operators must take explicit action (expand disk, run `raxis admin gc`, or change `disk_full_behavior`) to recover.

**Considered alternative.** Default to `gc_then_retry`, which automatically GCs the immutable artifact store on disk pressure and admits intents again once space is freed.

**Rejected because.** A thrashing-loop is plausible. GC runs, frees 500 MiB, takes 45 seconds. An Orchestrator immediately allocates 500 MiB for bundle staging. Disk fills again. GC runs again. The system appears alive — the kernel responds to health probes, intents are accepted — but is completely stalled on I/O. Operators receive no clear signal that intervention is needed because nothing has "failed."

`halt_admit` fails cleanly: `FAIL_DISK_FULL` is returned to the submitter, `OperatorAttentionRequired { kind: DiskFull }` is emitted, and the operator must make an explicit decision. Predictability is more valuable than apparent self-healing.

**Scenario it prevents.** A long-lived deployment encounters disk pressure for the first time after months of stable operation. With `gc_then_retry` as default, the on-call engineer sees nothing in their dashboards (the kernel is "responsive"); user complaints about slow intents trickle in but do not page; the pathology is diagnosed only after hours of degraded service. With `halt_admit`, the very first rejection pages the operator.

**Operators who genuinely want auto-GC behavior.** Set `disk_full_behavior = "gc_then_retry"` explicitly. The setting is per-deployment, so it remains a deliberate operator choice and not a silent default.

### §15.2 — Total kernel halt on `AuditWriteImpossible`

**Decision.** When the audit reserve (§7.5) is exhausted, the kernel transitions to `AuditWriteImpossible` (§7.6) and halts all intents — including reads — refuses new IPC connections, and requires operator restart with no automatic recovery.

**Considered alternative.** Log the audit-write failure to stderr and continue executing state changes, accepting a gap in the audit chain.

**Rejected because.** RAXIS's primary product is the audit chain (INV-05). An un-audited state change is indistinguishable from forgery to a future auditor: the auditor cannot determine whether a gap is benign (legitimate state change with audit failure) or malicious (forged state with no audit trail). One un-audited state change breaks the chain irreparably; subsequent audit events still chain backward to the last logged event, but the gap remains a forever-suspicious zone in any forensic review.

The decision is so categorical that there is no automatic recovery path. The kernel cannot write the audit event that would record "we recovered from `AuditWriteImpossible`" — recovery itself would be un-audited. Recovery requires explicit operator action (free disk, then `raxis admin restart`), which IS audit-recordable when the operator's restart command runs and writes its first event with the previous halt as a reachable predecessor.

**Scenario it prevents.** A long disk-fill consumes the audit reserve. Without INV-CAPACITY-04, subsequent state changes continue but their audit events fail to write. Days later, an operator runs `raxis log verify` and finds a multi-hour gap during which dozens of merges, sub-task completions, and key trust state changes occurred without any audit trail. There is no way to know which of those changes were legitimate and which (if any) were the work of a compromised operator account. The investigation requires reverse-engineering state from git, SQLite snapshots, and external logs — a multi-day forensic exercise. Halting the kernel on the first un-writable audit prevents this entire failure mode.

**The brutality is a feature.** The hard fence forces operators to size disk correctly and to set `audit_reserved_mb` conservatively. Operators who treat audit storage as "free overhead" learn quickly to budget it as first-class capacity.

### §15.3 — Round-robin fairness with no priorities in V2

**Decision.** V2 ships with strictly equal initiative scheduling via round-robin (§9.2). No `[plan] priority` field exists. All initiatives compete on equal terms, modulated only by `max_per_initiative_concurrent_vms`.

**Considered alternative.** Priority queuing with `[plan] priority = "high" | "normal" | "low"` and corresponding admission policies (e.g., always admit a "high" before any "normal" if both are queued).

**Rejected because.** Priority queuing introduces cascading complexity:

- **Priority inversion.** A High-Priority Orchestrator can be blocked waiting for a Low-Priority Reviewer (which the Orchestrator delegated to) to finish. The Orchestrator's "high priority" doesn't propagate naturally through delegated sub-tasks. Solving this requires priority-inheritance rules that themselves have edge cases (what if two High-Priority Orchestrators are blocked on the same Low-Priority Reviewer? what if a Low-Priority Reviewer is upgraded mid-execution?).
- **Starvation.** Low-Priority work may never run if High-Priority work continuously arrives. Mitigation requires an aging policy ("after N seconds at Low, promote to Normal"), which is its own design rabbit hole (what's the right N? does aging cross priority classes? how does this interact with `starvation_protection_window_seconds`?).
- **Preemption.** A Low-Priority VM is running. A High-Priority intent arrives but no slot is free. Do we kill the Low-Priority VM mid-execution? If yes, cascading sub-task termination per `key-revocation.md §7.3` applies — every preemption costs in-flight work. If no, "priority" is meaningless beyond admission-time tiebreaking.

V2 already ships hierarchical orchestration, the kernel push protocol, the immutable artifact store, the credential proxy architecture, and host capacity management. Adding a well-designed priority system on top would be a significant additional design and operational cost.

**Scenario it prevents.** Operators deploy V2 with a default `priority = "normal"` for all plans, believing they will rarely use the high tier. Under load, one team begins using `priority = "high"` "just to be safe." Other teams notice their work waiting and follow suit. Within weeks, every plan declares `high`, the priority field is meaningless, and the system has paid all the complexity cost for none of the benefit. Without priorities, this attractive-nuisance failure mode does not exist.

**Operators with a legitimate need for dedicated capacity.** Deploy a separate RAXIS host for the high-stakes workload. Cross-host capacity isolation is structurally simpler than within-host priority enforcement: each host has its own `max_concurrent_vms`, its own audit chain, its own policy, and zero risk of priority-inversion deadlocks. V3 may revisit this with a dedicated design pass once V2 has accumulated operational experience.

### §15.4 — Strict VM concurrency caps; no host OS OOM-killer dependency

**Decision.** The kernel never spawns a VM that would push aggregate VM memory past `max_aggregate_vm_memory_mb`. Strict cap, no overcommit, no opt-in best-effort mode. The kernel additionally reserves `kernel_reserved_memory_mb` (default 1 GiB) for itself, and operators are expected to size host physical memory at `max_aggregate_vm_memory_mb + kernel_reserved_memory_mb + os_overhead`.

**Considered alternative.** Best-effort overcommit (e.g., admit up to 110% of cap on the theory that not all VMs use peak memory simultaneously), relying on the Linux OOM-killer if memory pressure rises.

**Rejected because.** The OOM-killer is non-deterministic. When host memory is exhausted, the OOM-killer's heuristic (`oom_score_adj`-weighted RSS, allocation rate, process maturity) considers all running processes. The kernel itself — running for hours, with significant RSS from SQLite caches, audit buffers, and connection pools — is a credible OOM-killer target. We cannot guarantee with `oom_score_adj` tuning alone that the kernel will always be exempt; the kernel competes with other long-running host services (`systemd`, `sshd`, monitoring daemons) for the "do not kill" tier, and operators cannot universally set `oom_score_adj = -1000` for the kernel without significant deployment friction.

If the kernel is SIGKILL'd:

- SQLite WAL may be in an inconsistent state. SQLite's WAL crash recovery handles process death cleanly in the common case, but a SIGKILL during WAL header rewrite (a rare-but-real timing window) can leave the database requiring `.recover` to read.
- Pending audit events queued in the kernel's in-memory ring buffer (between durable-write boundaries) are lost.
- VSock connections to all VMs die simultaneously; planners detect EOF and reconnect (per `kernel-push-protocol.md §6.2`), but the in-memory loss means some pushes may be re-emitted on reconnect (idempotent, but observable).
- In-flight `IntegrationMerge` operations in Phase 2 (per `integration-merge.md §11`) leave `git_apply_pending = 1`, requiring §11.3 startup recovery.

Each of these is recoverable, but each is observable and each costs operator confidence. The control plane (kernel) must survive at all costs. Strict admission caps ensure host memory always has headroom for the kernel itself.

**Scenario it prevents.** Operator runs a deployment with `max_aggregate_vm_memory_mb = 60 GiB` on a 64 GiB host, expecting overcommit-free operation. Without INV-CAPACITY-01 strictness, an operational mistake (typo'ing `max_aggregate_vm_memory_mb = 600 GiB` in `policy.toml`) silently admits VMs until host memory is exhausted, the OOM-killer takes the kernel, the audit chain breaks at a random point, and a multi-day forensic recovery follows. With strict caps, the typo is caught at policy push (validation against operator-declared `max_host_memory_mb`) or at admission (the kernel refuses to spawn the 17th VM), and the failure is contained.

**Operators wanting overcommit.** Not supported in V2. Operators may declare smaller-than-actual `[plan] vm_memory_mb` if they trust their workload to use less, but this is a per-plan opt-in, not a kernel-wide policy.

### §15.5 — Per-operator queue limits: global default with explicit per-operator overrides

**Decision.** `admission_queue_per_operator_default = 8` is the default cap, with explicit per-operator overrides via `[[host_capacity.operator_quota_overrides]]` (§10.2.1). Overrides are opt-in, named per `operator_id` (no wildcards), bounded by `1 ≤ admission_queue_limit ≤ admission_queue_depth`, and require a non-empty `purpose`.

**Considered alternative A.** A single global `admission_queue_per_operator_limit = 8` with no overrides (the original design).

**Rejected because.** Artificially bottlenecks legitimate service accounts. A CI/CD pipeline using a service-account credential to auto-submit 20 parallel PR reviews would queue 8 and reject 12 with `FAIL_PER_OPERATOR_QUEUE_LIMIT`, breaking the pipeline. The default exists to prevent noisy-neighbor starvation between human operators (where 8 is plenty), not to constrain legitimate automation. Forcing service accounts to retry-loop against the cap erodes the fail-fast meaning of the rejection: the operator can no longer treat it as "I'm misbehaving" — it becomes "I'm busy and must retry," which is exactly the silent-degradation failure mode §15.1 rejects for disk full.

**Considered alternative B.** No per-operator limit at all (only the global `admission_queue_depth`).

**Rejected because.** A single misbehaving operator can fill the entire queue and starve other operators. The per-operator cap is necessary defense-in-depth: even if one operator's CLI client is buggy or compromised, other operators continue to make progress.

**Considered alternative C.** Allow wildcard-style overrides (e.g., `operator_id = "ci-*"` to match all CI service accounts).

**Rejected because.** Wildcards make the override mechanism effectively unbounded. An operator declaring `operator_id = "*"` to "fix CI for everyone" silently elevates every submitter and erodes the per-operator cap defense to nothing. By requiring named entries, every elevation appears explicitly in the policy diff and the audit trail; future auditors reviewing "why did this operator have a 64-cap?" find a specific override entry with a `purpose` field documenting the rationale.

The chosen approach (global default + opt-in per-operator named overrides) gives both protections: noisy-neighbor defense by default, and explicit elevation for known-good service accounts. Each elevation is a deliberate per-operator policy decision, surfacing in policy diffs, audit events (`operator_cap_source = Override`), and operator-facing tooling.

**Scenario it prevents.** A CI pipeline at a customer runs nightly batch jobs that submit 20 parallel initiatives. With Alt A, the pipeline silently rejects 12 of every 20 submissions, the customer's jobs run hours late, and the operator spends a week diagnosing "why is RAXIS slow on Tuesdays." With the chosen design, the operator declares the override at deployment time, the pipeline runs at its natural pace, and other operators (who submit one initiative at a time) remain protected from a hypothetical misbehaving credential.

---

## 16. Alternatives Considered and Rejected

### Alt A — Cgroup-based hard memory caps per VM

Use Linux cgroups v2 to set hard `memory.max` per VM, letting the host OOM-killer enforce caps. Rejected for V2 because the hypervisor primitives (Firecracker, AVF) already pin VM memory at allocation; cgroups would be a redundant second enforcement that complicates the configuration. V3 may add cgroup-based caps for non-VM kernel components (egress proxy, gateway) where the hypervisor enforcement doesn't apply.

### Alt B — Best-effort admission past cap

Allow admission to exceed cap by some percentage (e.g., 110%) under the theory that not all sessions use their declared memory at peak. Rejected: this is the "overcommit" pattern that produces unpredictable OOM-killer activity. The kernel's audit chain integrity (INV-05) cannot tolerate the kernel itself being OOM-killed mid-write. Strict caps are the only safe choice.

### Alt C — Dynamic worktree quota based on initiative size

Compute worktree quota as a function of master_repo size + expected diff scale. Rejected: complicates configuration significantly, and operators rarely have good estimates. Static `worktree_quota_mb` per session with `[plan] override_worktree_quota_mb = N` for special cases is simpler and adequately flexible.

### Alt D — Block kernel writes during disk full instead of halting admission

Hold every SQLite `BEGIN IMMEDIATE` indefinitely until disk frees. Rejected: SQLite's database-wide write lock would stall every other session's intent processing. One slow operator could effectively freeze the entire kernel by failing to free disk. Fail-fast with `FAIL_DISK_FULL` lets operators take action.

### Alt E — Allow audit writes to fail and continue

If audit reserve is exhausted, log the failure to stderr and continue with state changes. Rejected: violates INV-05 categorically. An un-audited state change is indistinguishable from forgery to a future auditor. The kernel must halt rather than allow this.

### Alt F — Priority-based admission in V2

Add `[plan] priority = "high" | "normal" | "low"` and let high-priority initiatives bypass round-robin. Rejected for V2 because priority systems require careful operational design (preemption rules? fairness within a priority class? operator workflow for re-prioritizing in-flight work?). Better to ship V2 with strict equality and add priorities in V3 with dedicated thought.

### Alt G — Per-intent SQLite connection (no pool)

Open a fresh SQLite connection for each intent, close it on completion. Rejected: SQLite connection setup is non-trivial (PRAGMA journal_mode=WAL, attaching auxiliary databases, etc.) — doing it per-intent adds latency. A small fixed pool with one writer + N readers is the standard pattern and is sufficient for V2's expected concurrency. Operators with very high intent rates can tune the reader pool size in `policy.toml`.

### Alt H — `disk_full_behavior = silently_drop_oldest`

When disk approaches full, drop the oldest sessions' worktrees to free space. Rejected: violates `INV-MERGE-WORKTREE-RETAIN` (`integration-merge.md §11.4`) and forensic retention (`key-revocation.md §7.4`). Also: silent data destruction is fundamentally hostile to operator trust. `gc_then_retry` GCs only the immutable artifact store (whose garbage-collectable items are explicitly safe to remove); it does not touch worktrees.

### Alt I — Allow per-initiative VM caps to be lifted by operator approval at admission time

When an initiative hits `max_per_initiative_concurrent_vms`, surface an escalation that the operator can approve to raise the cap for that initiative. Rejected for V2: adds operator workload to a routine capacity-management decision; the per-initiative cap is meant to enforce the host-wide allocation, not to be dynamically negotiated per-initiative. V3 may add this if operators report it as useful; V2 ships with the static cap and `OperatorAttentionRequired { InitiativeStarvation }` as the operator-visible signal.

### Alt J — Audit log on a separate filesystem from `disk_root`

Mount `audit/` on its own dedicated filesystem so audit writes are insulated from worktree/master_repo growth. Rejected as a default — most operators run RAXIS on a single filesystem and dual-mount adds operational complexity. However, the spec explicitly permits this layout: operators may mount `disk_root/audit/` on a separate device, and the audit reserve mechanism (§7.5) applies to whichever filesystem `audit/` lives on. The watchdog statvfs's `audit/` separately from `disk_root` if they are on different filesystems.

# Worktree Snapshots — `kernel-store.md §iter68`

**Status:** Active (iter68 lands the kernel + GC plumbing; the dashboard
surface lands in PR 2.)

**Companion code:**

- `raxis-kernel::worktree_snapshot` — single canonical write / read API.
- `raxis-store` migration 24 — `worktree_snapshots` SQL index table.
- `kernel::worktree_gc::gc_session_worktree` — pre-GC snapshot trigger.
- `kernel::handlers::intent::handle_complete_task` — commit-copy trigger.
- `kernel::handlers::witness::handle_inner` — witness-verdict trigger.

## 1. Why we keep snapshots

The agent's worktree is the physical artefact of every executor /
reviewer / orchestrator run. Today the worktree is destroyed when the
session is GC'd; the operator can no longer answer

  "*what did the agent actually write before that gate failed?*"
  "*what state was the integration-merge made against?*"
  "*why did the reviewer reject this run?*"

… without re-running the executor from scratch. Raxis already
persists LLM turns (`task-llm-capture.md`) and witness records
(`witness/`); worktree snapshots close the loop by persisting the
**code** the LLM produced alongside the **prompts that produced it**.

The snapshot store is also a substrate for higher-level dashboards
that PR 2–5 build on:

- "Show every diff this task ever touched" — list_for_task by
  `taken_at DESC`.
- "Compare two reviewer rounds" — two snapshot ids, two
  `diff_blob_sha256` blobs, FS diff.
- "Why did this initiative fail at IntegrationMerge?" — list_for_session
  of the merge session, look at the last snapshot's `head_sha`.

## 2. Storage model

Mirrors `witness_index` (the production reference for
content-addressed kernel storage):

```
<data_dir>/worktree-snapshots/
  blobs/
    <sha256>             # immutable content-addressed body
    <sha256>             # …
```

```sql
CREATE TABLE worktree_snapshots (
    snapshot_id           TEXT PRIMARY KEY,
    task_id               TEXT NOT NULL REFERENCES tasks(task_id),
    session_id            TEXT,
    initiative_id         TEXT,
    trigger               TEXT NOT NULL CHECK (trigger IN
        ('ExecutorActivate','ExecutorIdle','ExecutorCommitCopy',
         'WitnessPass','WitnessFail','WitnessInconclusive',
         'IntegrationMerge','PreGc')),
    taken_at              INTEGER NOT NULL,
    base_sha              TEXT NOT NULL,
    head_sha              TEXT NOT NULL,
    commit_count          INTEGER NOT NULL DEFAULT 0,
    diff_blob_sha256      TEXT,
    log_blob_sha256       TEXT,
    tree_blob_sha256      TEXT,
    porcelain_blob_sha256 TEXT,
    diff_bytes_total      INTEGER NOT NULL DEFAULT 0,
    diff_truncated        INTEGER NOT NULL DEFAULT 0
        CHECK (diff_truncated IN (0,1))
);
```

`*_blob_sha256` columns are nullable so the empty-body case
(`base == HEAD`, executor sitting idle) does not waste an FS write.
Indexed on `(task_id, taken_at DESC)`, `(session_id, taken_at DESC)`,
`(initiative_id, taken_at DESC)`, and `(diff_blob_sha256)` — the last
index powers content-address dedupe lookups.

Each body buffer is `git`-captured:

- `diff_blob_sha256`      ← `git diff <base>..HEAD`
- `log_blob_sha256`       ← `git log <base>..HEAD --format=%H\t%an\t%at\t%s`
- `tree_blob_sha256`      ← `git ls-tree -r HEAD --name-only`
- `porcelain_blob_sha256` ← `git status --porcelain`

## 3. Trigger sites

Every snapshot is recorded by `kernel::worktree_snapshot::snapshot_worktree`.
Production callers in iter68:

| Trigger              | Site                                                            | Hard-required? |
|----------------------|-----------------------------------------------------------------|----------------|
| `ExecutorCommitCopy` | `handlers::intent::handle_complete_task` (post `copy_executor_commit_to_orchestrator_odb`) | best-effort   |
| `WitnessPass`        | `handlers::witness::handle_inner` (post `WitnessAccepted`)      | best-effort   |
| `WitnessFail`        | `handlers::witness::handle_inner` (post `WitnessAccepted`)      | best-effort   |
| `WitnessInconclusive`| `handlers::witness::handle_inner` (post `WitnessAccepted`)      | best-effort   |
| `PreGc`              | `worktree_gc::gc_session_worktree` (before destroy)             | **YES**       |

Future iters extend the trigger set with `ExecutorActivate`,
`ExecutorIdle`, and `IntegrationMerge`; the SQL CHECK clause + the
`SnapshotTrigger` enum already cover those variants so the
later wiring is purely a call-site change.

## 4. Invariants

### `INV-WORKTREE-SNAPSHOT-PRE-GC-01`

`gc_session_worktree` MUST write a `PreGc` snapshot for every task
bound to the session BEFORE calling `worktree_staging::destroy`.
A snapshot-write failure surfaces as `WorktreeGcError::PreGcSnapshot`
and aborts the destroy; the next sweep retries. Tasks with a NULL
`base_sha` (pre-iter68 legacy) skip the snapshot with a structured
warn log — the invariant binds only iter68+ tasks.

Pinned by `kernel::worktree_gc::tests::
inv_worktree_snapshot_pre_gc_writes_snapshot_before_destroy`.

### `INV-WORKTREE-SNAPSHOT-CONTENT-ADDR-01`

`write_blob(bytes)` MUST be content-addressed: two calls with
identical `bytes` MUST land on the same on-disk filename and MUST NOT
write a second blob copy. Pinned by `kernel::worktree_snapshot::tests::
inv_worktree_snapshot_content_addr_01_identical_bytes_dedupe`.

### `INV-WORKTREE-SNAPSHOT-DURABLE-WRITE-01`

`write_blob` MUST `sync_all` the file handle before returning, so a
crash between FS write and SQL insert cannot leave a row pointing at
unflushed bytes. The kernel daemon's at-boot orphan walker
(`startup_check`) reconciles any orphans the crash window did create.

### `INV-WORKTREE-SNAPSHOT-BOUNDED-DIFF-01`

Diff bodies > `MAX_DIFF_BYTES` (1 MiB) MUST be truncated and
suffixed with the literal marker `\n<<< RAXIS-DIFF-TRUNCATED >>>\n`.
The row's `diff_truncated` column MUST be set to `1` and
`diff_bytes_total` MUST carry the pre-truncation byte count. Pinned
by `kernel::worktree_snapshot::tests::
inv_worktree_snapshot_diff_truncation_marker_pinned`.

## 5. Audit + dashboard

Every `snapshot_worktree` call (post-commit) emits an
`AuditEventKind::WorktreeSnapshotted { snapshot_id, task_id,
session_id, initiative_id, trigger, head_sha, base_sha }` row so the
audit-chain replay surface can render the snapshot timeline without
joining `worktree_snapshots`. The notification-priority classifier
maps the event to `None` — these are structural audit-trail rows,
not operator-attention events; the dashboard surfaces them in the
per-task timeline + the worktree-detail page directly.

The dashboard surface (PR 2):

- `GET /api/tasks/:id/worktree-snapshots` — list for a task.
- `GET /api/worktree-snapshots/:snapshot_id` — single row + 4 sha256s.
- `GET /api/worktree-snapshots/:snapshot_id/blob/:kind` — stream a
  body blob (`kind ∈ {diff, log, tree, porcelain}`).

## 6. Garbage-collection policy

Snapshots survive worktree GC by design — they are the post-mortem
trail. A future iter may add a retention policy (e.g., "keep last
N snapshots per task"), but iter68 keeps **every** snapshot row +
blob indefinitely. Operators with disk-pressure concerns can
manually prune via direct SQL DELETE on `worktree_snapshots`
followed by `raxis doctor worktree-snapshots gc-orphans` (which
removes blob files no row references); a tracked follow-up issue
captures the design for an automatic retention sweep.

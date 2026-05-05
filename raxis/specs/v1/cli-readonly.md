# RAXIS — Part 5: Read-Only Operator CLI

> **Status:** v1 normative. This document spec'd in 2026-Q2 and supersedes the
> ad-hoc references to `raxis-cli status` scattered throughout
> `kernel-core.md` and `peripherals.md`.

---

## §5.1 — Architectural primitive: the file-system bypass

### §5.1.1 — Why read-only commands MUST NOT go through IPC

RAXIS is local-first. The CLI binary runs on the same host as the kernel and
has Unix-level access to `<data_dir>/`. Routing read queries through the
kernel's IPC socket would:

1. **Couple the kernel surface to operator UX.** Every new operator dashboard
   would require a new IPC handler, IPC schema bump, and audit-event emit —
   exactly the brittle, ever-growing kernel surface v1 is designed to avoid.
2. **Force the kernel to serialise large reads.** A `raxis top` redraw at 1Hz
   over IPC would force the kernel to materialise and ship the same 50-row
   payload every second through `bincode + UDS`, on the same socket that
   carries authority-critical mutations.
3. **Lose snapshot semantics.** SQLite's WAL gives every reader a stable
   point-in-time snapshot; an IPC RPC would have to either lock the kernel's
   active transaction or return inconsistent rows.

The v1 design is therefore: **all read-only operator commands open `kernel.db`
directly with `OpenFlags::SQLITE_OPEN_READ_ONLY` and parse
`<data_dir>/audit/segment-*.jsonl` directly.** They do not connect to any
kernel socket.

### §5.1.2 — Why this is safe (the WAL contract)

`crates/store/src/db.rs` unconditionally executes
`PRAGMA journal_mode = WAL` at every connection open
(`kernel-store.md` §2.5.1, "WAL + synchronous=FULL: mandatory; non-negotiable").
WAL mode guarantees that read transactions never block writers and writers
never block readers; only `wal_checkpoint(TRUNCATE)` and DDL acquire the
exclusive lock — and the kernel's own writer never holds either while the IPC
loop is responsive.

The CLI's READ_ONLY handle therefore cannot:
- Block the kernel's commit path.
- Corrupt the database (READ_ONLY at the SQLite layer, plus Unix file
  permissions on `kernel.db` are `0644` so the CLI process inherits the same
  uid as the kernel — there is no cross-uid privilege escalation surface here).
- Observe a half-committed write (snapshot isolation).

### §5.1.3 — The four primitives

Every read-only command is built from at most these four primitives:

1. **`raxis_store::ro::open(data_dir) -> Result<RoConn>`** — opens
   `kernel.db` with `SQLITE_OPEN_READ_ONLY | SQLITE_OPEN_NO_MUTEX`,
   immediately verifies `schema_version` against the CLI's compiled-in
   `EXPECTED_SCHEMA_VERSION`, and returns a typed read-only connection.
2. **`raxis_store::views::*`** — a typed query catalog. Every function takes
   `&RoConn` and returns owned `Vec<T>` (no streaming iterators that would
   hold the WAL snapshot open). See §5.4.
3. **`raxis_audit_tools::reader::open_chain(audit_dir) -> ChainReader`** —
   opens every `segment-NNN.jsonl` in seq order, returns a streaming iterator
   over `AuditEvent`. Forward-compatible with v2 segment rollover.
4. **`raxis_runtime::heartbeat::read(data_dir) -> Option<Heartbeat>`** —
   reads `<data_dir>/runtime/heartbeat.json` (an atomic-rename JSON blob the
   kernel overwrites every 5s — see §5.2). Used for liveness, uptime, and
   the in-memory-only counters that `kernel.db` cannot expose.

These four primitives are **shared with the kernel's own production code**
(`raxis-store::ro`, `raxis-audit-tools::reader`, and `raxis-runtime` are
workspace crates) so a schema migration that changes a column rolls forward
in one place and both the kernel and the CLI pick it up.

### §5.1.4 — What the CLI cannot see, by design

| State | Lives in | CLI workaround |
|---|---|---|
| `PlanRegistry` (path_allowlist, path_export_globs, path_scope_override) | `RwLock<FxHashMap>` in `HandlerContext` | Re-parse `signed_plan_artifacts.plan_bytes` per task — same code path the kernel itself runs at boot via `lifecycle::repopulate_plan_registry`. Implemented as `views::task_plan_fields(&conn, task_id)`. |
| Pending verifier spawn queue | In-memory `VecDeque` in `gates::verifier_runner` (INV-INIT-08: never persisted) | **Best-effort:** kernel publishes a count + the head of the queue into `heartbeat.json::queued_spawns`. Documented in `raxis queue` output as "approximate; queue is in-memory". |
| Active verifier subprocess count | `static AtomicU32 ACTIVE_VERIFIERS` | Same as above — `heartbeat.json::active_verifiers`. |
| Live `tokio` task list | Tokio runtime internals | Not visible. **Accept.** |
| Open IPC connection list | `tokio::net::UnixListener` accept loop | Not visible. **Accept.** |

Anything in this table that an operator needs visibility on must be added to
the heartbeat schema (§5.2) — it MUST NOT motivate a new IPC handler.

---

## §5.2 — The kernel-side heartbeat file

### §5.2.1 — Path and lifetime

Path: `<data_dir>/runtime/heartbeat.json`
Mode: `0644`
Owner: same uid as the kernel process.

The kernel writes this file:
- **Once at startup**, immediately after `KernelStarted` is committed.
- **Every 5 seconds** thereafter from a dedicated `tokio::spawn`-ed task
  (`runtime::heartbeat_loop`).
- **Once at shutdown**, with `state = "Stopping"` set, before the
  `KernelStopped` audit event. Best-effort: the loop exits cleanly even if
  this final write fails.

Writes use **atomic rename** (`write_to_tempfile + rename`) so a CLI reader
never sees a torn JSON. If the rename fails, the previous heartbeat remains
in place — the CLI's freshness check (§5.2.3) catches this.

### §5.2.2 — Schema

```json
{
  "schema_version": 1,
  "kernel_pid": 47291,
  "started_at": 1714500000,
  "last_heartbeat_at": 1714500305,
  "state": "Running",
  "policy_epoch": 4,
  "store_schema_version": 1,
  "active_verifiers": 2,
  "max_concurrent_verifiers": 8,
  "queued_spawns": 0,
  "active_planner_sessions": 3,
  "active_gateway_sessions": 1,
  "active_verifier_sessions": 0
}
```

**`state`** is one of `"Starting" | "Running" | "Stopping"`.

The schema is forward-compatible: the CLI's deserializer ignores unknown
fields, and unknown `state` values are treated as `"Running"` for liveness
purposes (the audit chain is the source of truth for state transitions; the
heartbeat is a hint).

### §5.2.3 — Liveness check

A kernel is **live** iff all three conditions hold:

1. `heartbeat.json` exists and parses cleanly.
2. `now - last_heartbeat_at < 30 seconds` (six heartbeat intervals).
3. `kill -0 heartbeat.kernel_pid` succeeds (process exists and is owned by
   our uid).

Any condition failing means **stale**: the CLI reports
`kernel: STOPPED (last heartbeat <duration> ago, pid <N> <reason>)`. This is
the source of truth for `raxis status` liveness, NOT the audit log alone —
because a `KernelStopped` event is best-effort and may be missing on `kill -9`.

### §5.2.4 — Heartbeat is NOT part of the audit chain

The heartbeat file is a hint, not a record. It carries no `prev_sha256`,
no signature, and is overwritten every 5s. Any decision the kernel makes
that requires durability still goes through `kernel.db` + the audit chain.

The heartbeat exists solely to give the CLI visibility into the in-memory
counters and process uptime that `kernel.db` cannot capture. A corrupted
heartbeat must NEVER affect kernel behaviour — the kernel never reads its
own heartbeat file.

---

## §5.3 — Schema-version pinning

Every read-only command's first action, **before any business query**, is:

```rust
raxis_store::ro::assert_compatible_schema(
    &conn,
    EXPECTED_SCHEMA_VERSION  // compiled-in constant per CLI build
)?;
```

The kernel writes the canonical schema_version into a `meta` row at the end
of `migration::apply` (`kernel-store.md` §2.5.1 migration framework). The
CLI compares it against its own compiled-in constant; on mismatch it exits
with `ERR_SCHEMA_MISMATCH (exit 7)` and a message that names both versions
plus the upgrade path. Fail-closed: a schema-mismatched CLI never displays
data. This prevents the silent wrong-shape-row class of bug entirely.

`EXPECTED_SCHEMA_VERSION` lives in `raxis-store::SCHEMA_VERSION` (the same
constant the kernel's migration writes), so a schema bump in
`migration.rs` is mechanically a CLI version bump too — the build will fail
if the CLI was compiled against an older `SCHEMA_VERSION`. Cargo's
workspace dep resolution makes this a hard error, not a silent drift.

---

## §5.4 — `raxis-store::views` — the typed query catalog

`crates/store/src/views/` is a new submodule. Every read-only function the
CLI calls lives here. **No raw SQL ever escapes this module.** The kernel's
own production code is welcome to use these functions too (`recovery.rs`
already does similar reads; new reads should land here).

### §5.4.1 — Module structure

```
crates/store/src/views/
├── mod.rs            // re-exports + RoConn type
├── kernel_meta.rs    // schema_version, policy_epoch, KernelStarted lookup
├── tasks.rs          // task lists, gate state, blocking edges
├── initiatives.rs    // initiative state, plan artifacts, task counts
├── sessions.rs       // session list, lineage, TTL
├── budget.rs         // lane budget pressure, reservations
├── witnesses.rs      // witness_records joins
├── verifier_tokens.rs// outstanding tokens, consumed tokens
├── escalations.rs    // pending / approved / denied escalations
└── delegations.rs    // delegation status by session × capability
```

### §5.4.2 — The redaction layer

Every `views::*` function that returns a struct containing a path-list field
(`Vec<PathBuf>` or `Vec<String>` typed as a path) returns it wrapped in
`Redactable<Vec<String>>`:

```rust
pub enum Redactable<T> {
    Redacted { len: usize },
    Revealed(T),
}
```

Default at the call site is `Redacted { len }`. The CLI must explicitly call
`reveal_path_field(&conn, "task_plan_fields.path_allowlist", task_id, actor)`
to obtain the unredacted value, **AND** that call writes a
`PathReadAccessed { actor, table, column, task_id, command }` audit event
through `FileAuditSink` before returning the data. Audit-event-on-read is the
INV-08 enforcement mechanism at the file-system boundary — see §5.7.2.

This means:
- `raxis inspect <task_id>` **without** `--reveal-paths`:
  `path_allowlist: <12 entries; pass --reveal-paths to show>`.
- `raxis inspect <task_id> --reveal-paths`: full list, plus a fresh
  `PathReadAccessed` row in the audit log.

### §5.4.3 — Read transaction discipline

Every `views::*` function:
1. Opens its own `conn.transaction_with_behavior(Deferred)`.
2. Executes its query.
3. Materialises every row into an owned `Vec<T>`.
4. Commits (no-op for read txns) and returns.

Functions never return iterators or borrowed rows. This bounds every read
transaction to milliseconds and prevents the WAL-checkpoint-blocked-by-CLI
pathology described in §5.1.2. `raxis top` opens a fresh `RoConn` per
refresh tick (1Hz default); the cost is two `open()` calls per second
against an already-warm SQLite — negligible.

---

## §5.5 — Subcommand catalog

All commands listed below are READ-ONLY: they never connect to the kernel
IPC socket, never write to `kernel.db`, and (with the single exception of
`--reveal-paths`-driven `PathReadAccessed` audit events from
`raxis inspect`) never write to the audit chain.

Global flags (apply to every subcommand):

- `--data-dir <path>` — defaults to `$RAXIS_DATA_DIR` then `~/.raxis`. Same
  resolution rule the kernel uses.
- `--json` — emit machine-readable JSON to stdout, one record per line.
  When `--json` is set, `--no-color` is implied and human-readable headers
  are suppressed.
- `--no-color` — strip ANSI escapes (auto-applied when stdout is not a TTY).
- `--quiet` — suppress informational output; print only the body.
- `-h, --help` — context-sensitive help.

**Unknown subcommand suggestions.** Read-only commands share the
top-level dispatcher with `cli-ceremony.md` §4.1, so the
`Did you mean …?` behaviour described there applies equally here:
typos like `raxis stauts` surface `status`, and typos under a parent
(e.g. `raxis policy diffr`) surface `diff` / `show`. Ranking,
length-aware threshold, exact-prefix priority, the 5-suggestion cap,
and the dispatcher↔catalog drift test all live in
`cli/src/closeness.rs` + `cli/src/main.rs` and are spec'd once in
`cli-ceremony.md` §4.1 to avoid drift between this file and that one.

### §5.5.1 — `raxis status`

**Purpose:** one-screen kernel health snapshot. The "is anything on fire"
command.

**Exit code:** `0` if kernel live and audit chain intact; `1` if kernel
stopped; `2` if liveness ambiguous (heartbeat fresh but pid file missing);
`3` if audit chain shows a break.

**Output (human):**

```
RAXIS Kernel: RUNNING
  pid:                  47291
  uptime:               3h 17m 22s
  data_dir:             /home/op/.raxis
  policy_epoch:         4
  store_schema_version: 1
  binary version:       0.2.1

Workload:
  active sessions:    4 (planner=3, gateway=1, verifier=0)
  active verifiers:   2 / 8 cap
  queued spawns:      0
  initiatives running: 5
  tasks running:       7
  tasks queued:        12
  tasks blocked:       3
  pending escalations: 1

Audit chain:           OK (segment-000.jsonl, 4,217 records)
```

**Output (--json):** single JSON object with the same fields, plus
`heartbeat_age_ms` and the raw `KernelStarted.payload`.

**Data sources:** heartbeat.json (liveness, in-memory counters), `views::tasks::counts_by_state`, `views::sessions::active_counts`, `views::initiatives::running_count`, `views::escalations::pending_count`, `audit_tools::verifier::quick_chain_check` (last-line-only verification — does NOT walk the whole chain).

### §5.5.2 — `raxis top`

**Purpose:** live-refreshing dashboard. `htop` for RAXIS.

**Flags:**
- `--interval <duration>` — refresh interval; default `1s`, min `250ms`.
- `--once` — print one snapshot and exit. Useful for `watch raxis top --once`.
- `--by lane|session|initiative` — primary grouping; default `lane`.

**Behaviour:** Renders a `ratatui` full-screen TUI showing:
- Top bar: same content as `raxis status` first block, single-line.
- Main panel: per-lane table (active tasks, queued tasks, blocked tasks,
  budget utilization%, with red highlight at >80%).
- Bottom panel: scrolling per-event audit feed (`tail -f`-style on the
  audit log, filtered to `event_kind != TaskStateChanged` to keep noise down).
- `q` quits cleanly. `r` forces a refresh. `f` opens a filter prompt for
  the bottom panel.

**Exit code:** `0` on `q`; `130` on Ctrl-C.

**Note on TUI dep:** `ratatui` and `crossterm` are gated behind
`raxis-cli`'s `tui` feature (default-on for the standalone binary,
default-off when consumed as a library). `--once` works without the `tui`
feature — it falls back to the same human-readable output as `raxis status`
extended with the per-lane table.

**Data sources:** repeated `views::tasks::by_lane`, `views::budget::lane_pressure`, `audit::tail_since(last_seq)`. Each refresh opens a fresh `RoConn` and `ChainReader`.

### §5.5.3 — `raxis queue`

**Purpose:** show the DAG scheduler state.

**Flags:**
- `--lane <id>` — filter to one lane.
- `--blocked-only` — only show tasks in `Blocked*` states.

**Output:** two tables.

```
READY (5):
  task_id              initiative_id        lane     intent_kind
  01J7…task-01         01J7…init-x          default  SingleCommit
  …

BLOCKED (3):
  task_id              waiting_on              reason
  01J7…task-09         01J7…task-04            BlockedRecoveryPending
  01J7…task-09         01J7…task-05            BlockedRecoveryPending
  01J7…task-12         <gate: tests>           BlockedGate
  …
```

**Pending verifier spawn queue:** appended as a third (approximate) section
sourced from `heartbeat.json::queued_spawns`, clearly marked as
"approximate; queue is in-memory and may have changed since the last
heartbeat".

**Data sources:** `views::tasks::ready_set`, `views::tasks::blocking_edges`,
`heartbeat.json`.

### §5.5.4 — `raxis log`

**Purpose:** structured access to the audit chain.

**Forms:**

| Invocation | Behaviour |
|---|---|
| `raxis log` | Last 50 records, newest first. |
| `raxis log <initiative_id>` | All records with `initiative_id` matching. Reconstructs a per-initiative timeline. |
| `raxis log --task <task_id>` | All records with `task_id` matching. |
| `raxis log --session <session_id>` | All records with `session_id` matching. |
| `raxis log --kind <event_kind>` | Filter by `event_kind` (substring match, case-insensitive). |
| `raxis log --since <duration>` | Only records emitted in the last `<duration>` (e.g. `1h`, `30m`, `7d`). |
| `raxis log --limit <N>` | Cap output at N records (default 50; `--limit 0` = unlimited). |
| `raxis log -f` / `raxis log --follow` | Stream new records as they're appended. Honors all other filter flags. Uses 100ms `metadata().len()` poll — no platform-specific deps. Exits cleanly on Ctrl-C with all buffered records flushed. |

Filters compose: `raxis log --task t-1 --kind WitnessAccepted --since 1h`
returns the witnesses for task `t-1` accepted in the last hour.

**Output (human):** one event per line with relative timestamp:

```
3h17m ago [InitiativeCreated]   init=01J7…init-x  signed_by=fp-7d2c…
3h17m ago [PlanApproved]        init=01J7…init-x  task_count=4
3h17m ago [TaskAdmitted]        task=01J7…task-01 lane=default
3h16m ago [IntentAccepted]      task=01J7…task-01 kind=SingleCommit
…
```

**Output (--json):** raw `AuditEvent` per line, identical to the on-disk
JSONL.

**Data source:** `audit_tools::reader::open_chain(audit_dir)` + filter
combinators.

### §5.5.5 — `raxis budget`

**Purpose:** per-lane intent-cost utilization. **NOT LLM-token tracking** —
RAXIS does not meter LLM tokens in v1.

**Flags:**
- `--by-session` — drill into `lane_budget_reservations` joined to
  `tasks` → `sessions`.
- `--lane <id>` — filter to one lane.
- `--threshold <pct>` — only show lanes above the given utilization%
  (default 0).

**Output (human, default):**

```
lane_id     reservations  reserved_cost  budget_ceiling  utilization
default     7             83             1000            8.3%
ci-fast     12            340            500             68.0%
ci-slow     2             420            500             84.0%  ⚠
```

The `⚠` marker fires at >80%; the row is rendered red on a TTY.

**Output (--json):** array of `{lane_id, reservations, reserved_cost, budget_ceiling, utilization_pct, exceeds_threshold}`.

**Data source:** `views::budget::lane_pressure`, optional join to
`views::sessions::owners_by_reservation` for `--by-session`.

### §5.5.6 — `raxis inspect <task_id>`

**Purpose:** forensic deep-dive into a single task. Joins
`tasks` × `task_dag_edges` × `task_intent_ranges` × `witness_records` ×
`verifier_run_tokens` × the in-memory plan-fields.

**Flags:**
- `--reveal-paths` — show `path_allowlist` and `path_export_globs` in full.
  WRITES a `PathReadAccessed` audit event before returning. Default omits
  these fields.
- `--gates-only` — only show the witness and gate evaluation section.
- `--with-deps` — include the dependency closure (recursive parents).

**Output (human):**

```
Task 01J7…task-01
  initiative:        01J7…init-x
  state:             Running
  lane:              default
  intent_kind:       SingleCommit
  evaluation_sha:    abc123…
  base_sha:          def456…
  head_sha:          ghi789…
  worktree_root:     /home/op/worktrees/init-x

Plan fields:
  path_allowlist:           <12 entries; pass --reveal-paths to show>
  path_export_to_successors: true
  path_export_globs:        <3 entries; pass --reveal-paths to show>
  path_scope_override:      false

Dependencies:
  upstream:   [01J7…task-00 (Completed)]
  downstream: [01J7…task-02 (Blocked), 01J7…task-03 (GatesPending)]

Witnesses (3):
  verifier_run_id      gate_type     result_class  recorded_at
  01J7…run-a           tests         Pass          3h12m ago
  01J7…run-b           lints         Pass          3h11m ago
  01J7…run-c           coverage      Inconclusive  3h08m ago

Outstanding verifier tokens: 0
Consumed verifier tokens:    3
```

**Output (--json):** single JSON object with the same fields; redacted
fields are emitted as `{"redacted": true, "len": 12}`.

**Data sources:** `views::tasks::row_with_joins`,
`views::tasks::dependency_closure`, `views::witnesses::for_task`,
`views::verifier_tokens::for_task`, optional `views::tasks::reveal_path_field`.

### §5.5.7 — `raxis escalations`

**Purpose:** the operator's inbox.

**Flags:**
- `--state <Pending|Approved|Denied>` — filter by escalation state;
  default `Pending`.
- `--lineage <lineage_id>` — filter to one lineage.

**Output (human):**

```
PENDING (1):
  escalation_id        task          requested_capability  justification
  01J7…esc-a           01J7…task-04  WriteSecrets          "Need to rotate the auth bug fix"
  → use `raxis escalation approve 01J7…esc-a`

APPROVED (2): use --state Approved to view
DENIED (0):   use --state Denied to view
```

**Data source:** `views::escalations::list_by_state`.

### §5.5.8 — `raxis sessions`

**Purpose:** list active sessions with TTL countdown.

**Flags:**
- `--role <Planner|Gateway|Verifier>` — filter by role.
- `--include-revoked` — include revoked sessions.

**Output (human):**

```
ACTIVE (4):
  session_id        role      lineage             worktree_root           ttl_remaining
  01J7…sess-1       Planner   01J7…lineage-x      /home/op/worktrees/x    23h 17m
  01J7…sess-2       Planner   01J7…lineage-y      /home/op/worktrees/y    1h 02m  ⚠
  01J7…sess-3       Planner   01J7…lineage-z      /home/op/worktrees/z    18h 44m
  01J7…sess-4       Gateway   01J7…lineage-w      <none>                  6d 03h
```

`⚠` highlights sessions within 1 hour of expiry.

**Data source:** `views::sessions::active_with_ttl`.

### §5.5.9 — `raxis verifiers`

**Purpose:** live verifier subprocess visibility. Reads
`heartbeat.json` for the current count, then joins
`views::verifier_tokens::outstanding` to surface which `(task_id, gate_type)`
pairs each running verifier is associated with.

**Output (human):**

```
RUNNING (2 / 8 cap):
  verifier_run_id      task          gate_type   issued_at      ttl_remaining
  01J7…run-x           01J7…task-12  tests       1h 12m ago     17m
  01J7…run-y           01J7…task-13  coverage    47m ago        45m

QUEUED (0): in-memory; approximate; from heartbeat at 03s ago.

CONFIG:
  max_concurrent_verifiers: 8 (from policy.toml [verifier])
  verifier_token_ttl_secs:  3600
```

**Data sources:** `heartbeat.json`, `views::verifier_tokens::outstanding`.

### §5.5.10 — `raxis witnesses <task_id>`

**Purpose:** list `witness_records` for a task. Convenience subset of
`raxis inspect <task_id> --gates-only`.

**Output:** the "Witnesses" section from §5.5.6.

### §5.5.11 — `raxis policy show`

**Purpose:** pretty-print the loaded policy.

**Flags:**
- `--epoch <N>` — show a historical epoch from
  `<data_dir>/policy/archive/epoch-<N>.toml` (the kernel archives every
  superseded `policy.toml` on epoch advance — `epoch advance` already
  does this in `cli/src/commands/epoch.rs`).
- `--section <name>` — only show one TOML section
  (`authority|sessions|operators|gates|lanes|budget|notifications|…`).
- `--raw` — pass through the raw TOML bytes (no re-rendering).

**Data source:** filesystem read of
`<data_dir>/policy/policy.toml` (current) or
`<data_dir>/policy/archive/epoch-<N>.toml` (historical), parsed via
`raxis_policy::load_policy` then re-rendered. Validates the signature
against `<data_dir>/policy/policy.toml.sig` and prints
`signature: VALID | INVALID` at the top — fail-closed: if the signature
is invalid, the command exits `4` and prints nothing else.

### §5.5.12 — `raxis policy diff <epoch_a> <epoch_b>`

**Purpose:** structured diff between two policy epochs.

**Output:** unified-diff-style output, but **field-aware** — re-keys both
artifacts by `(section, entry_id)` before diffing so a `[[gates]]` reorder
doesn't appear as 12 changes. Critical at epoch advance review.

**Data source:** filesystem reads of the two
`<data_dir>/policy/archive/epoch-<N>.toml` files, parsed into
`PolicyBundle`s, then diffed with the `similar` crate.

### §5.5.13 — `raxis verify-chain`

**Purpose:** re-run `recovery::verify_audit_chain` from the CLI process.
Walks every record, verifies `prev_sha256` linkage and seq monotonicity.

**Flags:**
- `--from <seq>` — start from the given seq (default 0).
- `--quick` — only check the first and last record (used by `raxis status`).

**Exit code:** `0` if intact, `3` if any break or gap is found.

**Data source:** `audit_tools::verifier::verify_chain` — the same function
the kernel's boot path calls. Already exists; this command just exposes it
to the CLI surface.

### §5.5.14 — `raxis explain <task_id>`

**Purpose:** answer "why is this task not making progress?". Walks the
gate matrix + dependency graph and produces a human reason.

Decision tree:
1. Task state is terminal (`Completed`/`Aborted`/`Quarantined`) → print
   "task is in terminal state X; nothing more will happen".
2. Task state is `Running` → show what intent it last accepted, last
   `IntentAccepted` audit timestamp, and "no further action expected
   from kernel; the planner agent is responsible for continuing".
3. Task state is `Blocked*` → trace the immediate cause:
   - `BlockedDependency` → show which upstream task(s) are still
     non-Completed, with their states.
   - `BlockedGate` → show which gates have witnesses, which gates do not,
     and which verifier_run_tokens are outstanding for the missing ones.
   - `BlockedRecoveryPending` → show the `recovery_reason` from
     `recovery::reconcile_tasks` audit emit.
   - `BlockedEscalation` → show the pending escalation_id with its
     justification.
4. Task state is `GatesPending` → show the gate witness matrix:

```
Gates required: [tests, lints, coverage, security]
  tests     → witness recorded 12m ago (Pass)
  lints     → witness recorded 12m ago (Pass)
  coverage  → witness recorded  3m ago (Inconclusive) ⚠ requires retry
  security  → no witness; no outstanding verifier_run_token; gate has not been spawned
```

**This is the highest-value forensic command in the catalog** — "why isn't
this moving" is the single most common operator question.

**Data sources:** `views::tasks::row`, `views::tasks::blocking_edges`,
`views::witnesses::for_task`, `views::verifier_tokens::outstanding_for_task`,
`views::escalations::for_task`, `audit_tools::reader::events_for_task`.

### §5.5.15 — `raxis doctor`

**Purpose:** one-shot health diagnostic. Pre-flight before filing a bug.

**Checks (each emits a row):**

```
[OK]   schema_version: kernel.db=3, raxis-cli expects 3
[OK]   audit chain: 4,217 records, no breaks, no gaps
[OK]   policy.sig: signature VALID against [meta].signed_by
[OK]   heartbeat: fresh (3s ago), pid 47291 alive
[OK]   no orphaned task_id rows pointing at non-existent initiatives
[WARN] 12 verifier_run_tokens older than 24h (still valid, but unusually long-lived)
[OK]   no GatesPending tasks older than 1h
[OK]   <data_dir>/notifications/inbox.jsonl exists and is writable
[OK]   <data_dir>/runtime/heartbeat.json exists and is fresh
[OK]   cert.list: 1 operator certificate(s) installed
[OK]   cert.<fp>.status: Active (expires 2027-03-01T00:00:00Z, alice)
[WARN] cert.<fp>.status: Expiring (alice — 12d remaining; rotate before grace)
[FAIL] cert.<fp>.status: Expired (bob — 4d past grace; ops gated unless EmergencyRecovery)
[WARN] cert.<fp>.misconfig_bypass: --force-misconfig was used at install time
```

**Exit code:** `0` if no `[FAIL]` rows; `1` if any `[FAIL]` row; `[WARN]`
rows do not affect exit code.

**Data sources:** every `views::*` consistency check + the audit chain
verifier + heartbeat freshness + filesystem stat of expected paths +
the `operator_certificates` view (kernel-store.md §2.5.9).

**Cert checks** (added in step 11 of the operator-cert work):

| Outcome | Conditions |
|---|---|
| `[OK]`   | `Active` (Standard or Emergency) |
| `[WARN]` | `Expiring` (within `warn_window_secs`), `Grace` (past `not_after` but within `grace_window_secs`), `force_misconfig_bypass=true` |
| `[FAIL]` | `Expired` (past grace), `NotYetValid` (clock skew or future `not_before`) |

The `EmergencyRecovery` kind never expires (always `Active`) and is
listed separately as `AlwaysActiveEmergency`. `doctor` reads
`operator_certificates` directly via the SQLite WAL — it does **not**
require a running kernel.

### §5.5.16 — `raxis inbox`

**Purpose:** tail the local-shell notification channel introduced by §5.6.

`raxis inbox` is `tail -f <data_dir>/notifications/inbox.jsonl`, with
the same human-readable formatting as `raxis log`. `raxis inbox --since 1h`
shows the last hour. The notification channel system (§5.6) writes
JSONL records here; this command is the operator's view into them.

---

## §5.6 — Notification channels (replaces email-only)

This section supersedes the four hardcoded email references in
`kernel-core.md` §2.3 escalation_handler step 5,
`kernel-core.md` INV-ESC-06,
`peripherals.md` §3 escalation flow, and
`planner-api.md` §approval.

### §5.6.1 — Why this changes

The v1 spec previously hardcoded `notification::send_escalation_alert(...)`
as the operator-notification mechanism, with email or local alert as the
two implied channel kinds. The implementation does not yet exist
(`grep -r 'notification::' kernel/src` returns nothing as of this writing),
so the old text was forward-looking. The new model is:

- **Shell channel** (always available, zero-config) is the v1 default.
  Local-first means the operator runs `raxis inbox` to see notifications;
  no SMTP, no webhook, no daemon-sidecar ever needed.
- **Email** and **Webhook** are spec'd here for forward-compat with v2 but
  v1 ships handlers ONLY for **Shell** and **File** kinds.
- Routing is per-event-kind; an event with no matching route uses
  `default_channels`; an empty `channels` list silences that event entirely.

### §5.6.2 — Policy schema additions

`policy.toml` gains a top-level `[notifications]` block plus repeating
`[[notifications.channels]]` and `[[notifications.routes]]` tables:

```toml
[notifications]
default_channels = ["shell"]

[[notifications.channels]]
id     = "shell"                 # always present implicitly; explicit entry overrides target
kind   = "Shell"                 # Shell | File | Email | Webhook
target = "<data_dir>/notifications/inbox.jsonl"

[[notifications.channels]]
id     = "audit-mirror"
kind   = "File"
target = "/var/log/raxis-notifications.jsonl"

# v1 SCHEMA ONLY — handlers ship in v2.
# [[notifications.channels]]
# id           = "ops-email"
# kind         = "Email"
# target       = "ops@example.com"
# smtp_relay   = "smtp://localhost:25"
# auth_env_var = "RAXIS_SMTP_PASSWORD"

# [[notifications.channels]]
# id     = "ops-webhook"
# kind   = "Webhook"
# target = "https://hooks.example.com/raxis"
# auth_env_var = "RAXIS_WEBHOOK_TOKEN"

[[notifications.routes]]
event_kind = "EscalationSubmitted"
channels   = ["shell", "audit-mirror"]

[[notifications.routes]]
event_kind = "EscalationApproved"
channels   = ["shell"]

[[notifications.routes]]
event_kind = "TaskStateChanged"
channels   = []                      # silenced — too noisy by default

[[notifications.routes]]
event_kind = "PathScopeOverrideApplied"
channels   = ["shell", "audit-mirror"]   # security-relevant; force visibility
```

`PolicyBundle::validate` enforces:

- `default_channels` references only declared `[[notifications.channels]]`
  ids (the implicit `shell` channel counts).
- Every `[[notifications.routes]]` entry's `channels` list references only
  declared ids.
- Every `event_kind` is a real `AuditEventKind` variant name (validated
  against the same string the audit emit writes).
- For `Email`/`Webhook` channels in v1, `PolicyBundle::validate` MUST emit
  a warning to the kernel log at boot ("notification channel `<id>` of
  kind `<Email|Webhook>` is declared but its handler is not implemented in
  v1; events routed to this channel will be silently dropped"). This is a
  warning, not an error — it lets operators stage their v2 channel config
  in v1 without blocking the boot.

### §5.6.3 — Kernel emit path

`kernel-core.md` §2.3 escalation_handler step 5 changes from:

> Triggers `notification::send_escalation_alert(escalation_id, ...)` —
> operator notification (email or local alert). Non-fatal: …

to:

> Triggers `notifications::dispatch(event_kind, payload)` — looks up the
> route for `event_kind` in the loaded `PolicyBundle.notifications`, picks
> the channel set (route-specific OR `default_channels`), and dispatches a
> per-channel `notify` call. Each channel handler runs in its own
> `tokio::spawn` so a slow handler cannot block the kernel commit path.
> **Non-fatal:** any handler that fails emits a `NotificationDeliveryFailed
> { channel_id, event_kind, reason }` audit event; the originating mutation
> still commits. Handler failure NEVER aborts the parent transaction.

This applies uniformly to every event kind that has a route, not just
`EscalationSubmitted`. The dispatcher lives in
`kernel/src/notifications/` (new module).

### §5.6.4 — The Shell channel handler

The Shell channel handler is the simplest possible:

1. Opens `<data_dir>/notifications/inbox.jsonl` with `O_APPEND | O_CREAT`,
   mode `0644`.
2. Writes one JSON line per dispatched event:

   ```json
   {
     "notified_at": 1714500305,
     "event_kind": "EscalationSubmitted",
     "event_seq": 4218,
     "payload": { ... },
     "human_summary": "Escalation 01J7…esc-a from task 01J7…task-04 requesting WriteSecrets capability"
   }
   ```

3. Calls `fsync` (best-effort; failure → `NotificationDeliveryFailed`).

`human_summary` is rendered by a per-event-kind formatter in the
notifications module — the same formatter `raxis log` uses. The Shell
channel intentionally writes a different file from the audit chain so
operators can `rm` it without touching audit integrity.

### §5.6.5 — The File channel handler

Identical to Shell, but `target` is operator-supplied. Used for piping
notifications into a sidecar (`tail -f /var/log/raxis-notifications.jsonl
| journalctl --identifier=raxis -p notice`).

### §5.6.6 — Forward compatibility

A v2 patch landing the Email handler will:
1. Drop the boot warning for `Email` channels.
2. Add `notifications::handlers::email::dispatch(channel, event)`.
3. Add an integration test under `kernel/tests/notifications_smtp.rs`
   that runs against a local Maildrop fixture.

No policy.toml schema changes will be needed — the schema is the contract.

---

## §5.7 — Security and confidentiality

### §5.7.1 — File-system permissions

The CLI inherits the same Unix uid as the kernel. v1 operates under the
single-tenant assumption: one Unix user owns one `<data_dir>/`. There is
no cross-uid privilege model — anyone with read access to the data_dir
can run every read-only command. This is the same trust boundary the
kernel relies on; the read-only CLI does not weaken it.

Multi-tenant deployments (a single host running multiple kernels for
different operators) are **out of scope for v1** and require either
(a) one data_dir + one uid per kernel, or (b) v2 cross-uid IPC auth.
This is documented as a constraint, not a bug.

### §5.7.2 — INV-08 and the redaction layer

INV-08 says "path lists never cross the IPC boundary." That invariant is
about the *IPC* surface — to keep an untrusted planner from learning
about other planners' worktrees. The read-only CLI does NOT cross the
IPC boundary, so INV-08 does not apply directly. But the *spirit* of
INV-08 — that path lists are sensitive — applies to the CLI too,
because operator scripts that pipe `raxis inspect --json` into a chat or
a bug tracker can leak path information about adjacent initiatives.

The §5.4.2 redaction layer is the enforcement:

- Path-list fields are returned as `Redactable<Vec<String>>` with the
  default `Redacted { len: N }` shape.
- Showing the unredacted value requires explicit `--reveal-paths` AND
  emits a `PathReadAccessed { actor, table, column, task_id, command }`
  audit event before returning the data. The audit event is signed and
  chained, just like every other kernel audit event — the CLI uses the
  same `FileAuditSink` as the kernel's own writer.

This makes path-list access **observable** without making it
**impossible** — operators can still debug, but they leave a trace.

### §5.7.3 — No write surface

This entire CLI is READ-ONLY by contract. The single exception is the
`PathReadAccessed` audit event, which is itself a record of the read.
No `views::*` function executes any DML, no command opens `kernel.db`
without `OpenFlags::SQLITE_OPEN_READ_ONLY`, and the only file the CLI
ever writes is `<data_dir>/audit/segment-NNN.jsonl` (append-only, chain
contract). A code-search assertion in CI MUST verify that no
`views::*` function constructs a SQL string containing `INSERT`,
`UPDATE`, `DELETE`, `CREATE`, `ALTER`, or `DROP` (case-insensitive,
ignoring SQL comments).

---

## §5.8 — Implementation contracts (v1 normative)

The following are normative requirements on the implementation, in the
order an implementor would land them:

1. **`raxis-store::ro` and `raxis-store::views` modules** MUST be
   added in their own commit, with `views::*` returning owned Vec<T>
   and the `Redactable<T>` wrapper. No `cli/` code may execute raw
   SQL — a CI grep MUST enforce this.
2. **`raxis-runtime::heartbeat`** MUST be added as a new workspace
   crate (or sub-module of `raxis-kernel`) before any read-only command
   that depends on the heartbeat lands. The kernel's `main.rs` MUST
   spawn the heartbeat loop at boot step 8a (immediately after
   `KernelStarted`).
3. **`raxis-audit-tools::reader::open_chain`** MUST be implemented as
   a forward-compatible iterator over all `segment-NNN.jsonl` files in
   seq order, even though v1 only ever has `segment-000.jsonl`.
4. **`PolicyBundle.notifications`** MUST be added to
   `crates/policy/src/bundle.rs` per §5.6.2, with full
   `PolicyBundle::validate` enforcement of channel-id references and
   event_kind validity.
5. **`raxis-cli` subcommand catalog** MUST be implemented in the order
   `status` → `log` (with `-f`) → `queue` → `inspect` → `top` →
   `escalations` → `sessions` → `verifiers` → `witnesses` → `budget` →
   `policy show` → `policy diff` → `verify-chain` → `explain` →
   `doctor` → `inbox`. Each in its own commit; each with golden
   tests in `cli/tests/readonly/<command>.rs`.
6. **CI MUST run a `--json` schema check** for every command — a
   golden file under `cli/tests/golden/<command>.json` that the
   command's `--json` output must match (with timestamps redacted).
   This is the regression net for output-shape drift.
7. **`raxis status` MUST be the first command landed**, because every
   other read-only command's tests assume `status` works as the
   "did the harness boot" check.

The CLI version pin (`EXPECTED_SCHEMA_VERSION` in `raxis-store`) is
the cross-binary contract; bumping `migration::SCHEMA_VERSION` is a
cargo-resolution-level break for the CLI build, by design.

---

## §5.9 — Testing contracts

Each command MUST have:

1. **Golden test** for human output (with timestamps redacted) and
   `--json` output (full schema check).
2. **Permission test** asserting `kernel.db` is opened with
   `SQLITE_OPEN_READ_ONLY` (verified by trying to write through the
   handle and asserting it fails).
3. **Schema-mismatch test** asserting the command exits `7` with the
   expected message when `EXPECTED_SCHEMA_VERSION` and the on-disk
   `meta.schema_version` differ.
4. **Stale-heartbeat test** asserting commands that depend on
   heartbeat data correctly report "stale" rather than fabricating
   counts.

For the `views::*` layer:

5. **Round-trip test** per view function: kernel writes a known
   fixture, view reads it, output matches the fixture exactly.
6. **Redaction test** per view function that returns a path field:
   default call returns `Redacted { len: N }`; `reveal_path_field`
   returns `Revealed(...)` AND emits a `PathReadAccessed` audit event
   that can be read back.

For the audit reader:

7. **Multi-segment forward-compat test**: synthesize
   `segment-000.jsonl` and `segment-001.jsonl` (the latter manually
   crafted), assert `open_chain` iterates both in seq order, and
   assert filter combinators behave identically across the segment
   boundary.

---

## §5.10 — Out of scope for v1

- **`raxis-cli` mutating commands.** Those continue to go through the
  existing IPC operator socket (`peripherals.md` §3 + `cli/src/commands/`)
  and are governed by `cli-ceremony.md` §4.1.
- **LLM-token accounting.** RAXIS does not track LLM token consumption in
  v1. `raxis budget` is per-lane intent-cost utilization, NOT per-session
  LLM tokens. A future `raxis llm-tokens` subcommand is a v2 design item.
- **Cross-uid / multi-tenant access control.** v1 assumes one Unix uid per
  kernel (`raxis status` is callable by anyone with read access to
  `<data_dir>/`).
- **Email and Webhook notification handlers.** Spec'd in §5.6 for forward
  compatibility; implementation is v2.
- **Audit segment rollover.** `raxis-audit-tools::reader::open_chain` is
  forward-compatible with multi-segment chains, but v1 only ever produces
  `segment-000.jsonl`.
- **Push-style audit subscription.** `raxis log -f` is poll-based (100ms
  `metadata().len()` check). A push-based subscription would require an
  IPC handler and is explicitly not in v1.

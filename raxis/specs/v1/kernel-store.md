# RAXIS — Part 2 (Store): Closing Gaps — Schema, Signing, Keys, and Operator Auth

> **Scope:** Part 2.5 — store DDL (all 18 `kernel.db` tables, §2.5.1), VCS path scope enforcement (§2.5.8, **normative**), audit log transaction boundary (§2.5.2), plan artifact signing contract (§2.5.3), key inventory (§2.5.4), operator authentication protocol (§2.5.5), `[[gates]]` normative schema (§2.5.6), INV amendments (§2.5.7).
>
> **Authority:** When table name, column name, or column type in Part 2 Core prose conflicts with the canonical DDL here, this file wins for representation details. When this file is silent on FSM semantics, Part 2 Core wins.
>
> **Navigation:** [README](../../README.md) | [Part 2 Core](kernel-core.md) | [Part 3](peripherals.md) | [Part 4](cli-ceremony.md)

---

## Part 2.5 — Closing Gaps: Store Schema, Signing Contracts, Key Inventory, and Operator Authentication

Part 2.5 provides the normative specifications that are referenced throughout Parts 2.1–2.4 but were not yet formally written in one place. It also resolves conflicts surfaced by writing the DDL (primarily the task lifecycle story between Part 2.3 and Part 2.4) and establishes the conventions — table names, column types, directory paths, environment variables — that implementers use as ground truth when the spec prose and DDL diverge.

**Resolution rule:** When a table name, column name, or column type in Parts 2.3–2.4 prose conflicts with the canonical DDL in §2.5.1, the DDL wins for representation details. When the DDL is silent on FSM semantics (state transitions, actor rules, evaluation order), Parts 2.3–2.4 win.

> Part 2.5 is structured as seven sections, written incrementally with review between each.
> §2.5.1 — Store DDL and isolation model: database file layout, runtime pragmas, canonical schema for all 18 kernel tables (Tables 1–16 core + Tables 17–18 VCS path scope), indexes, and migration inventory.
> §2.5.2 — Audit log transaction boundary: write ordering between SQLite commits and `raxis-audit-tools` JSONL appends, crash-window characterisation, and what `recovery::reconcile` assumes as ground truth when the two diverge **(complete)**.
> §2.5.3 — Plan artifact signing contract: byte-exact signing domain, canonical serialisation, `plan.sig` format, plan-signing key (operator), IPC path, and `create_initiative` call path **(complete)**.
> §2.5.4 — Key inventory and custody model: all four key families, who holds what at runtime vs at ceremony time, blast-radius characterisation for each **(complete)**.
> §2.5.5 — Operator authentication protocol: three-socket model, operator challenge-response wire format, session establishment, nonce and clock-skew rules, `permitted_ops` schema **(complete)**.
> §2.5.6 — `[[gates]]` normative schema and env-var alignment: gate-type → verifier-command mapping, `VerifierSpawnEnvelope` env var names unified with `configuring-witnesses.md` **(complete)**.
> §2.5.7 — INV amendments and adversarial assertion matrix: INV-INIT-06 amendment, INV-SCHED-01 (new), adversarial assertion matrix for Gaps 1–4 **(complete)**.
> §2.5.8 — VCS Path Scope Enforcement: `vcs::diff` normative spec, `effective_allow` algorithm, `task_intent_ranges` and `task_exported_path_snapshots` DDL (Tables 17–18), intent handler amendments in `handlers/intent.rs` (steps 2A/3A/7A), integration merge carve-out, CompleteTask path check, INV-TASK-PATH-01 and INV-TASK-PATH-02 **(complete)**.

---

### §2.5.1 — Store DDL and Isolation Model

#### Runtime data directory

The kernel owns a single data directory: **`$RAXIS_DATA_DIR`**, which defaults to `~/.raxis/` on the kernel host if the environment variable is not set. This directory is created at first startup by `bootstrap.rs` with permissions `0700` (owner read/write/execute only). Its layout is:

```
~/.raxis/
├── kernel.db             # single SQLite database (all persistent kernel state)
├── policy/               # signed policy artifacts, loaded at startup and on epoch advance
│   ├── policy.toml       # human-readable policy (lanes, claims, operators, budgets, gates)
│   ├── policy.sig        # detached Ed25519 signature over policy.toml bytes
│   └── authority.key     # authority Ed25519 keypair (used only during ceremony; 0400 perms)
├── audit/                # JSONL audit segments, managed by raxis-audit-tools
│   ├── segment-000.jsonl
│   ├── segment-000.index
│   └── ...               # new segment per rotation threshold (size or time)
├── witness/              # filesystem witness blob store, managed by witness_index.rs
│   └── <blob_sha256>     # one file per witness blob, named by hex SHA-256 of contents
├── sockets/              # runtime UDS endpoints (created at bind, removed on clean shutdown);
│                         # directory mode 0700, owned by the kernel OS user (§2.5.5)
│   ├── planner.sock      # planner session IPC endpoint; also accepts WitnessSubmission from
│   │                     # verifier subprocesses (the WitnessSubmission variant is dispatched
│   │                     # on verifier_run_token auth, not session-token auth — see §2.5.5
│   │                     # three-socket model and §2.5.6 verifier token contract). This is the
│   │                     # path that RAXIS_KERNEL_SOCKET points to (see §2.5.6 env var table).
│   ├── gateway.sock      # provider gateway process IPC endpoint (gateway_process_token auth);
│   │                     # carries FetchRequest / FetchResponse and InferenceRequest /
│   │                     # InferenceResponse (§2.5.5).
│   └── operator.sock     # operator CLI: challenge-response handshake then operator session
│                         # token; carries the operator IPC discriminant set listed in §2.5.5.
└── emergency.log         # written only when audit chain cannot accept a KernelStarted
                          # or KernelStopped record; append-only; never part of the chain
```

`kernel.db`, `audit/`, `witness/`, and `sockets/` are four logically separate subsystems. They are **not** unified under a single transaction boundary — the relationship between the SQLite store and the JSONL audit store is defined in §2.5.2; the relationship between the store and the witness filesystem store is defined in the `witness_index.rs` spec in Part 2.3.

**Note on plan artifacts:** signed plan artifacts (`plan.toml` + `plan.sig`) are not stored under `policy/`. They are sealed into `kernel.db` (the `signed_plan_artifacts` table) at `create_initiative` time. `policy/` contains only the kernel policy artifact (system-wide configuration). This is intentional: a plan artifact is initiative-scoped, not system-scoped, and must survive epoch advances without being re-signed.

RAXIS has no runtime dependency on paths outside **`$RAXIS_DATA_DIR`** (default `~/.raxis/`) except the Git worktrees and repositories operators configure for initiatives. If RAXIS sources are checked out beside other projects, kernel state, policy, audit, and witness stores remain in the RAXIS data directory only—never mixed with another product's dot-directory layout. Any stray reference to a non-RAXIS system path in this specification is an error.

**DDL incremental note:** Canonical SQL for all `kernel.db` tables is delivered in parts in §2.5.1 (Parts 2–3 continue tables 7–16 including `witness_records`, escalation tables, and `verifier_run_tokens`). Until a subsection is merged, Parts 2.3–2.4 prose remains authoritative for behaviour; merged DDL wins on names and column types. The DAG edge table **`task_dag_edges`** is canonical (legacy prose may say `task_dependencies` — treat as the same edge relation).

---

#### Isolation model

The kernel uses **one SQLite database file**: `$RAXIS_DATA_DIR/kernel.db`. There are no secondary kernel SQLite databases, no in-memory databases, and no shared-cache connections. Every piece of persistent kernel state that is not an audit JSONL record or a witness blob lives in this one file.

**Runtime pragmas** — applied by `raxis-store::db::open()` immediately after opening the connection, before any query or migration:

```sql
PRAGMA journal_mode = WAL;
-- WAL (Write-Ahead Log) mode allows concurrent readers while a single writer
-- holds the write lock. The kernel's single-connection model means there is
-- never more than one writer, but WAL also improves crash safety: the database
-- file itself is never modified mid-transaction; changes are first written to
-- the WAL file and then checkpointed to the main file. A crash during a
-- transaction leaves the WAL file with uncommitted data that SQLite discards
-- on next open, leaving kernel.db in a consistent pre-crash state.

PRAGMA synchronous = FULL;
-- Every transaction commit is synced to disk (fdatasync) before the write
-- call returns. This is mandatory: the recovery procedure in Parts 2.2 and 2.4
-- assumes every committed transition_task write is durable before the caller
-- receives Ok(()). Lowering this to NORMAL or OFF is a correctness violation,
-- not a performance trade-off.

PRAGMA foreign_keys = ON;
-- Referential integrity is enforced at runtime. SQLite disables this by
-- default; enabling it here means INSERT/UPDATE/DELETE operations that would
-- violate a REFERENCES constraint are rejected with a constraint error.
-- This is a safety net — the application layer is responsible for correctness,
-- but FK enforcement catches implementation bugs.

PRAGMA temp_store = MEMORY;
-- Temporary tables and indices created during query execution live in memory
-- rather than in temp files. The kernel's queries are simple enough that
-- temp storage is small; this avoids unnecessary disk I/O for scratch space.
```

`WAL` mode and `synchronous = FULL` are mandatory and non-negotiable. Any deployment that lowers either setting voids the recovery correctness guarantees documented in Parts 2.2 and 2.4.

**Single connection per kernel process.** The kernel holds one `rusqlite::Connection` wrapped in `Arc<Mutex<Connection>>` inside `raxis-store::Store`. There is no connection pool. Multiple tokio tasks acquire the mutex, perform their query or transaction, and release. This is intentional for several reasons:

- SQLite WAL mode handles concurrent *readers* across separate connections, but the kernel's write rate is low (task state transitions, not high-frequency OLTP) and the mutex overhead is negligible at that rate.
- A single connection eliminates the entire class of bugs arising from connection-level state (e.g., `last_insert_rowid`, transaction isolation state, pragma settings applying only to one connection). Every caller sees the same view of the database.
- `PRAGMA foreign_keys = ON` is a per-connection setting. With a pool, any connection that skips this pragma silently bypasses FK enforcement. With one connection, the pragma is set once at open time and never needs to be re-applied.

Future versions may introduce a separate read-only connection pool if profiling shows mutex contention on high-load workloads. Any such addition must maintain the invariant that all writes go through the single write connection.

**WAL checkpoint policy.** The kernel uses SQLite's default automatic checkpointing (triggered at 1000 WAL pages). No custom checkpoint logic is added in v1. The checkpoint runs in the background as part of SQLite's normal WAL maintenance; it does not block reads or writes. Operators should not manually run `PRAGMA wal_checkpoint` unless advised during incident response.

**Mutex scope invariant (INV-STORE-01).** The `Mutex` wrapping the connection is **`tokio::sync::Mutex`** (FIFO, async-aware) — not `std::sync::Mutex` and not `parking_lot::Mutex`. The async-aware mutex is mandatory because handler tasks run inside a tokio runtime; using `std::sync::Mutex` would block the worker thread for the duration of the SQL transaction, starving the runtime. The FIFO property prevents writer starvation when many handlers contend for the connection.

Every kernel operation that issues `BEGIN`/`COMMIT` on the connection MUST hold the mutex continuously from `BEGIN` through `COMMIT` (or `ROLLBACK`). Releasing the mutex mid-transaction is undefined behaviour at the SQLite level (the next acquirer would see the partially-completed transaction state and could corrupt commit ordering) and is forbidden by INV-STORE-01. The implementation rule is mechanical: handlers hold a `tokio::sync::MutexGuard<Connection>`, call `Connection::transaction()` to obtain a `rusqlite::Transaction<'_>` that borrows the connection, perform their work via the `Transaction` handle, and `commit()` or drop-for-rollback before letting the `MutexGuard` go out of scope.

Functions that compose multiple writes — most importantly `lifecycle::transition_task` + the `lifecycle::evaluate_terminal_criteria` it calls (`kernel-core.md` §4.6) — MUST execute the entire composition under one mutex acquisition + one transaction. Calling `evaluate_terminal_criteria` from outside an open transition transaction is a spec violation; `transition_task` is the only authorised caller per INV-INIT-04, so this is enforced at the call-site. Any future kernel-side operation that needs to compose multiple table writes atomically MUST follow the same single-acquire / single-`BEGIN` / single-`COMMIT` pattern; never split a logical operation across two mutex acquisitions because another tokio task can interleave between them and observe inconsistent state.

When a separate read-only connection pool is introduced in a future version (per the "Future versions" note above), it MUST NOT be allowed to bypass this invariant: read-only pool connections may serve queries that don't `BEGIN IMMEDIATE`, but **every write path continues to go through the single mutex-protected write connection**, and the read pool's snapshot isolation must be derived from SQLite's WAL semantics (each pool connection sees a snapshot at its `BEGIN` time, isolated from concurrent writes via WAL frames). The single-writer model is permanent.

**Multi-table atomicity invariant (INV-STORE-02).** Operations that mutate **more than one table** to maintain a cross-table consistency relationship MUST execute every write in a single SQL transaction held under one INV-STORE-01 mutex acquisition. The exhaustive list of such operations in v1 is:

| Operation | Tables written in one transaction | Source-of-truth contract |
|---|---|---|
| `lifecycle::transition_task` (+ `evaluate_terminal_criteria` it calls) | `tasks`, `initiatives`, `task_dag_edges` (via `release_successors`), audit-pointer | `kernel-core.md` §4.6, INV-INIT-04 |
| `lifecycle::approve_plan` (+ `scheduler::admit` it calls per task) | `initiatives`, `tasks`, `task_dag_edges`, `signed_plan_artifacts`, audit-pointer | `kernel-core.md` §4.6 + Part 2.3 admit |
| `policy_manager::advance_epoch` Phase 1 | `delegations` (sweep), `sessions` (prompt-cache invalidation), `policy_epoch_history` (Table 19 insert), audit-pointer | `kernel-core.md` §`policy_manager.rs`, INV-POLICY-01 below |
| `handlers/intent` accepting an intent | `tasks` (intent fields + state), `task_intent_ranges`, `lane_budget_reservations`, audit-pointer | `kernel-core.md` Part 2.3 §`handlers/intent.rs` "Budget check and reservation" + `transition_task` call (which is itself bound by INV-INIT-04) |
| `gates/witness_index::write` | `witness_records`, `verifier_run_tokens` (consumed), audit-pointer | Part 2.3 §witness_index.rs |
| `recovery::reconcile_tasks` (+ `expire_orphan_verifier_tokens` it calls) | `tasks` (sweep to BlockedRecoveryPending), `verifier_run_tokens` (orphan expiry), audit-pointer | `kernel-core.md` §recovery.rs, INV-INIT-08 |

For each operation in this table, splitting writes across two transactions or two mutex acquisitions is a spec violation: another tokio task could interleave between them and observe an inconsistent intermediate state (e.g. for `advance_epoch`, see new delegations marked stale but old `policy_epoch_history` MAX still in place, allowing a stale-policy escalation to slip through). Any future kernel operation that needs to compose multiple table writes atomically MUST be added to this table as part of its spec PR.

**Policy epoch atomicity invariant (INV-POLICY-01).** `policy_manager::advance_epoch` Phase 1 (the SQL-write phase) writes to `delegations`, `sessions`, `policy_epoch_history`, and the audit-pointer table inside one transaction held under one INV-STORE-01 mutex acquisition. Phase 2 (in-memory `ArcSwap` swaps for `ctx.policy` and `ctx.allowlist_cache`) runs only after Phase 1 commits, and is infallible. Phase 3 (gateway `EpochAdvanced` signal) is best-effort and does not affect the success of the advance. The full phase contract — including failure modes for each phase, audit events for both rejection (`PolicyAdvanceRejected`) and post-`BEGIN` failure (`PolicyAdvanceFailed`), and crash semantics (which reduce to single-transaction commit/no-commit) — is normative in `kernel-core.md` §`policy_manager.rs`. A partially-applied epoch advance is structurally impossible: either all four SQL writes commit and the in-memory caches are then swapped, or the transaction rolls back and the kernel observably remains at the old epoch with no audit `PolicyEpochAdvanced` row.

---

#### SQL Type-Safety and Codebase Representation

**Type-safety invariant (INV-STORE-03):** To prevent runtime SQL errors from typos or schema drift, **no Rust source file in `raxis/kernel/src` may contain a raw SQL table-name or state-value string literal**. 
- **Table names** must be dynamically interpolated using the `raxis-store::Table` enum. A module interacting with the database must define a module-level constant (e.g., `const TASKS: &str = Table::Tasks.as_str();`) and use `format!()` to inject it into the query string.
- **State values** (e.g., TaskState, InitiativeState) must use the relevant enum's `.as_sql_str()` method as bound parameters.

---

> **§2.5.1 — isolation model complete.**
> DDL tables 1–6 follow immediately below.

---

#### Canonical DDL — Part 1 of 4: Core lifecycle tables

All tables are created by migration 1 (the v1 baseline migration, applied atomically on first startup). Table names below are canonical — any conflicting name in Parts 2.1–2.4 prose is superseded by these names. **`task_dag_edges`** is the canonical DAG table name (legacy alias in prose: `task_dependencies`).

**Creation order matters** because of foreign key constraints. `sessions` must precede `tasks` (tasks hold a nullable `session_id` FK). `initiatives` must precede `tasks`, `signed_plan_artifacts`, `task_dag_edges`, and `escalations`. The migration DDL below is ordered accordingly.

---

##### Table 1 — `schema_version`

```sql
-- ── schema_version ─────────────────────────────────────────────────────────────
-- Records each applied migration. PRIMARY KEY on version prevents duplicate
-- application. apply_pending() runs each migration in a single BEGIN EXCLUSIVE
-- ... COMMIT transaction so a crash during migration leaves the DB in the state
-- it was in before the migration started — never in a partial-apply state.
-- MAX(version) is the authoritative current schema level at startup.
CREATE TABLE IF NOT EXISTS schema_version (
    version     INTEGER NOT NULL PRIMARY KEY,   -- monotonic migration number
    applied_at  INTEGER NOT NULL                -- Unix seconds (UTC)
);
```

**Design note:** `PRIMARY KEY` on `version` prevents the duplicate-version bug where a bug in `apply_pending` could insert the same version twice and confuse `MAX(version)`. A `UNIQUE` constraint would also work; `PRIMARY KEY` is simpler and also creates the covering index SQLite uses for `MAX(version)`.

---

##### Table 2 — `initiatives`

```sql
-- ── initiatives ─────────────────────────────────────────────────────────────────
-- One row per initiative. created by create_initiative; mutated by approve_plan,
-- evaluate_terminal_criteria, and abort_initiative.
-- completed_at is NULL until the initiative reaches a terminal state
-- (Completed, Failed, or Aborted); it is set by evaluate_terminal_criteria.
-- INV-INIT-06: once stored, plan_artifact_sha256 is never updated.
CREATE TABLE IF NOT EXISTS initiatives (
    initiative_id          TEXT    NOT NULL PRIMARY KEY,
    state                  TEXT    NOT NULL
        CHECK (state IN (
            'Draft',
            'ApprovedPlan',
            'Executing',
            'Blocked',
            'Completed',
            'Failed',
            'Aborted'
        )),
    terminal_criteria_json TEXT    NOT NULL,   -- JSON-serialised TerminalCriteria enum variant
    plan_artifact_sha256   TEXT    NOT NULL,   -- hex SHA-256 of plan_bytes in signed_plan_artifacts
    created_at             INTEGER NOT NULL,   -- Unix seconds; set at create_initiative time
    approved_at            INTEGER,            -- NULL until approve_plan succeeds
    completed_at           INTEGER            -- NULL until terminal state is reached
);
```

**`terminal_criteria_json` format:** stores the JSON-serialised form of the `TerminalCriteria` Rust enum. The v1 enum has exactly three variants — `AllTasksSucceeded` (default, applied when the plan omits `terminal_criteria`), `AllTasksTerminal`, and `MinSuccessCount(u32)` — with serde representations `"AllTasksSucceeded"`, `"AllTasksTerminal"`, and `{"MinSuccessCount": <n>}` respectively. **Per-variant semantics, default-selection rules, and failure-detection logic are normatively defined in `kernel-core.md` §4.2 (Terminal criteria and initiative state evaluation); this column merely persists the operator's serialised choice so `evaluate_terminal_criteria` can deserialise and apply it on every call (no in-memory cache).** Variants explicitly *not* in the v1 enum (`RequiredSetSucceeded`, `AnyCompleted`, `AllTasksCompleted`, `CustomScript`) and the rationale for their exclusion are documented in `kernel-core.md` §4.2 — `create_initiative` rejects any plan whose `terminal_criteria_json` deserialises to one of those names with `InitiativeError::UnknownTerminalCriteriaVariant`.

---

##### Table 3 — `signed_plan_artifacts`

```sql
-- ── signed_plan_artifacts ───────────────────────────────────────────────────────
-- Stores the raw canonical plan TOML bytes and the detached Ed25519 signature
-- over their SHA-256 digest (see §2.5.3 "Byte-exact signing domain" for the
-- two-step sign model), sealed at create_initiative time. This row is immutable
-- after insertion (INV-INIT-06). approve_plan reads plan_bytes to instantiate
-- tasks; it never writes back to this table.
--
-- Normalisation note: plan_artifact_sha256 in initiatives is derived from
-- plan_bytes in this table. The kernel recomputes SHA-256(plan_bytes) at
-- create_initiative time and inserts both rows in the same transaction,
-- cross-checking that the computed hash matches. If they diverge (implementation
-- bug), the entire transaction is aborted and create_initiative fails.
CREATE TABLE IF NOT EXISTS signed_plan_artifacts (
    initiative_id  TEXT    NOT NULL PRIMARY KEY
        REFERENCES initiatives(initiative_id),
    plan_bytes     BLOB    NOT NULL,  -- raw canonical plan TOML bytes; signed by the operator key (see §2.5.3 "Plan-signing key (operator)")
    plan_sig       BLOB    NOT NULL,  -- 64-byte detached Ed25519 signature over SHA-256(plan_bytes); see §2.5.3 "Byte-exact signing domain"
    stored_at      INTEGER NOT NULL   -- Unix seconds; for audit cross-referencing
);
```

**Why store the full `plan_bytes` and not just the hash?** The kernel must be able to re-read and re-parse the plan definition after a crash, during recovery, and when `approve_plan` is called. If only the hash were stored, the kernel would need the original file (held by the CLI) to be re-provided. Storing the full blob makes the kernel self-contained: the plan is sealed into `kernel.db` at submission time and the CLI is no longer needed for the lifecycle of that initiative.

---

##### Table 4 — `sessions`

```sql
-- ── sessions ────────────────────────────────────────────────────────────────────
-- One row per planner or gateway process session. Sessions are never deleted —
-- only revoked (soft delete). revoked_at records when revocation happened for
-- audit and retention purposes. Expired sessions are revoked lazily (on next
-- auth validation attempt) rather than by a background sweep.
--
-- session_token is stored in plaintext (not hashed) because the auth path
-- performs constant-time comparison — the kernel never derives a hash from it.
-- If the token were stored hashed, every auth check would require a full hash
-- computation on the inbound token before comparing, adding latency with no
-- security benefit given that the token is not a password (it is a kernel-issued
-- random value that cannot be guessed; if the DB is compromised, the attacker
-- already has access to the system).
--
-- sequence_number enforces monotonic message ordering per session (INV-01):
-- every inbound IPC message must carry a sequence_number strictly greater than
-- the stored value. Updated atomically with the auth validation path.
CREATE TABLE IF NOT EXISTS sessions (
    session_id       TEXT    NOT NULL PRIMARY KEY,
    role_id          TEXT    NOT NULL,
    session_token    TEXT    NOT NULL UNIQUE,    -- random 256-bit, hex-encoded
    lineage_id       TEXT    NOT NULL,
    worktree_root    TEXT,                       -- NULL for Gateway / Verifier (no VCS on this row).
                                                 -- NOT NULL for Planner: absolute git worktree path;
                                                 -- validated at create_session (git rev-parse --git-dir).
    base_sha              TEXT,                  -- policy-pinned VCS base for this session.
                                                 -- For Role::Planner: set at create_session to the
                                                 -- resolved OID of base_tracking_ref at worktree creation
                                                 -- (locked; never updated). Used by IntegrationMerge as
                                                 -- the stale-base check anchor (locked tip vs current tip).
                                                 -- For Role::Gateway / Role::Verifier: NULL.
    base_tracking_ref     TEXT,                  -- NULL iff base_sha IS NULL. Symbolic ref string whose
                                                 -- tip was resolved into base_sha at create_session
                                                 -- (e.g. refs/heads/main). Kernel re-resolves this ref
                                                 -- at IntegrationMerge admission to obtain current_main_HEAD.
                                                 -- CHECK (below): planner rows with base_sha MUST carry both.
    fetch_quota      INTEGER NOT NULL,           -- remaining fetch budget for this session
    sequence_number  INTEGER NOT NULL DEFAULT 0, -- last accepted sequence number (INV-01)
    created_at       INTEGER NOT NULL,
    expires_at       INTEGER NOT NULL,
    revoked          INTEGER NOT NULL DEFAULT 0
        CHECK (revoked IN (0, 1)),
    revoked_at       INTEGER,                    -- NULL until revoked
    CHECK (
        (base_sha IS NULL AND base_tracking_ref IS NULL)
        OR (base_sha IS NOT NULL AND base_tracking_ref IS NOT NULL)
    ),
    -- If integration-style pins exist, Git resolution requires a real worktree path.
    CHECK (base_sha IS NULL OR worktree_root IS NOT NULL)
);
```

**`worktree_root` binding:** **Planner** sessions store a **non-NULL** absolute git worktree path; **Gateway** and **Verifier** sessions store **SQL NULL** (see `authority::create_session` — no sentinel strings). Range intents and planner-side VCS use this column via `authority::get_session`. Witness recheck and verifier spawn pass **`worktree_root` from the planner session** bound to `task.session_id`, not from the verifier's own session row. Not denormalised onto the task row.

**`base_sha` / `base_tracking_ref` binding:** When both are non-NULL (planner sessions that pin integration semantics), `base_sha` is the commit OID that Git resolves from `base_tracking_ref` in **`worktree_root`** at `create_session` — **`worktree_root` must be non-NULL** whenever these fields are resolved or re-resolved. Peel symbolic ref to commit (`git rev-parse` with commit peel semantics, same as used later for stale-base). Stale-base checks **must** re-resolve that **stored ref string** in that worktree, not a hard-coded branch name.

---

##### Table 5 — `tasks`

```sql
-- ── tasks ───────────────────────────────────────────────────────────────────────
-- One row per task. All rows for an initiative are inserted by approve_plan in a
-- single transaction — the intent handler never inserts task rows (INV-INIT-01).
--
-- NULL contract for intent-bound fields:
--   Before the first intent on a task: session_id, evaluation_sha, base_sha,
--   submitted_claims_json, admission_reserved_units are NULL. actual_cost is 0.
--   After the intent handler runs: all five fields are non-NULL. The first four
--   (session_id, evaluation_sha, base_sha, submitted_claims_json) are written by
--   the binding UPDATE (step 4). admission_reserved_units is written by the
--   consume_budget UPDATE that immediately follows — both updates are in the same
--   handler transaction, so from an observer's perspective they are atomic.
--   On continuation intents (task already Running), only evaluation_sha, base_sha,
--   and submitted_claims_json are refreshed; session_id and admission_reserved_units
--   are unchanged.
--   If the task goes to BlockedRecoveryPending via crash recovery, these fields
--   retain their last known values (used by reconcile_tasks to resume the verifier).
--   After a terminal transition: fields are retained (not NULLed) for auditability.
--
-- block_reason is non-NULL only when state is 'Aborted' or 'BlockedRecoveryPending'.
--
-- actor records the TransitionActor that caused the most recent state change,
-- JSON-serialised: {"Kernel":null}, {"Operator":"op-id-abc"}, {"Planner":null}.
--
-- admitted_at records when approve_plan inserted this row. transitioned_at records
-- the most recent transition_task call. These are separate fields because the gap
-- between admission and first intent is operationally significant (measures how long
-- the task sat in the ready queue before the planner picked it up).
CREATE TABLE IF NOT EXISTS tasks (
    task_id                TEXT    NOT NULL PRIMARY KEY,
    initiative_id          TEXT    NOT NULL
        REFERENCES initiatives(initiative_id),
    lane_id                TEXT    NOT NULL,     -- logical lane name from the plan; no FK (lane is policy-derived, not a DB table)
    state                  TEXT    NOT NULL
        CHECK (state IN (
            'Admitted',
            'GatesPending',
            'Running',
            'Completed',
            'Failed',
            'Aborted',
            'Cancelled',
            'BlockedRecoveryPending'
        )),
    block_reason           TEXT,                 -- NULL unless state IN ('Aborted','BlockedRecoveryPending'); JSON-serialised BlockReason
    actor                  TEXT    NOT NULL,     -- JSON-serialised TransitionActor; last transition author
    policy_epoch           INTEGER NOT NULL,     -- policy epoch at time of last transition
    admitted_at            INTEGER NOT NULL,     -- Unix seconds; set once by approve_plan, never updated
    transitioned_at        INTEGER NOT NULL,     -- Unix seconds; updated on every transition_task call
    session_id             TEXT                  -- NULL until intent handler binds the task; FK nullable
        REFERENCES sessions(session_id),
    evaluation_sha         TEXT,                 -- head_commit_sha from the binding intent; NULL when Admitted
    base_sha               TEXT,                 -- base_commit_sha from the binding intent; NULL when Admitted
    submitted_claims_json  TEXT,                 -- JSON array of planner-submitted claims; NULL when Admitted
    admission_reserved_units INTEGER,             -- admission units from first consume_budget; NULL until then; used after release_budget for BudgetOverrun
    actual_cost            INTEGER NOT NULL DEFAULT 0  -- accumulated by budget::reconcile_actual_cost on terminal transition
);
```

**`lane_id` — no FK:** lane configuration is read from the loaded signed policy artifact at runtime; there is no `lanes` table in `kernel.db`. The `lane_id` value is validated against the policy at `approve_plan` time (if the lane does not exist in the policy, task insertion fails). After that, `lane_id` is trusted — it passed policy validation when the task was created.

**`tasks` before `sessions` in FK order:** `tasks.session_id` is a nullable FK to `sessions`. SQLite enforces nullable FKs: `NULL` is always allowed (no FK violation), and a non-NULL value must match an existing `sessions.session_id`. Because `session_id` starts as NULL (tasks are inserted by `approve_plan` before any planner session interacts with them), the FK is only enforced at the time the intent handler writes `session_id` — at which point the session row must already exist. There is no circular dependency.

---

##### Table 6 — `task_dag_edges`

```sql
-- ── task_dag_edges ──────────────────────────────────────────────────────────────
-- One row per directed dependency edge: predecessor must complete (Completed)
-- before successor becomes schedulable.
--
-- All edges for an initiative are inserted by approve_plan alongside the task rows,
-- in the same transaction. No edges are added or removed after that (INV-INIT-06).
--
-- predecessor_satisfied is monotonically set: once set to 1 by
-- store::dag::release_successors (called from transition_task when predecessor
-- reaches Completed), it is never reset to 0. next_ready_tasks relies on this
-- monotonic guarantee: it queries for Admitted tasks where ALL predecessor edges
-- have predecessor_satisfied = 1.
--
-- The PRIMARY KEY (predecessor_task_id, successor_task_id) provides a covering
-- index for release_successors queries (WHERE predecessor_task_id = ?).
-- A separate index on successor_task_id supports next_ready_tasks's
-- "count unsatisfied predecessors" sub-query.
CREATE TABLE IF NOT EXISTS task_dag_edges (
    initiative_id           TEXT    NOT NULL
        REFERENCES initiatives(initiative_id),
    predecessor_task_id     TEXT    NOT NULL
        REFERENCES tasks(task_id),
    successor_task_id       TEXT    NOT NULL
        REFERENCES tasks(task_id),
    predecessor_satisfied   INTEGER NOT NULL DEFAULT 0
        CHECK (predecessor_satisfied IN (0, 1)),   -- BOOLEAN; monotonically set
    PRIMARY KEY (predecessor_task_id, successor_task_id)
);
```

**`next_ready_tasks` query pattern** (for implementer reference):

```sql
-- Find all Admitted tasks for initiative X whose every predecessor is satisfied.
-- A task with no predecessors (no rows in task_dag_edges where successor_task_id = task_id)
-- is immediately schedulable once in Admitted state.
SELECT t.task_id
FROM tasks t
WHERE t.initiative_id = ?           -- bind: initiative_id
  AND t.state = 'Admitted'
  AND NOT EXISTS (
      SELECT 1 FROM task_dag_edges e
      WHERE e.successor_task_id = t.task_id
        AND e.predecessor_satisfied = 0
  )
ORDER BY t.admitted_at ASC;         -- FIFO within the ready set; stable ordering
```

---

> **§2.5.1 — DDL Part 1 of 4 complete (tables 1–6: schema_version, initiatives, signed_plan_artifacts, sessions, tasks, task_dag_edges).**

---

#### Canonical DDL — Part 2 of 4: Authority, escalation, and token tables

**Creation order within this section:** `delegations` → `escalations` → `approval_tokens` → `approval_proofs` → `approval_token_nonces` → `verifier_run_tokens`. All reference tables from Part 1 (`sessions`, `tasks`, `initiatives`) or earlier tables in this section. No forward references.

---

##### Table 7 — `delegations`

```sql
-- ── delegations ──────────────────────────────────────────────────────────────────
-- One row per (session, capability_class) delegation. A delegation grants a
-- session the right to assert claims whose gate requirement maps to that
-- CapabilityClass. `authority::check_capability(session_id, capability)` does a
-- single index lookup on this table; it must be O(1).
--
-- capability_class: the CapabilityClass enum variant this delegation covers
-- (e.g. WriteSecrets, ReadExternalData). UNIQUE with session_id ensures at
-- most one active delegation per (session, capability); a second grant from the
-- same operator updates the existing row (upsert) rather than inserting a new one.
--
-- status encodes the three-state delegation lifecycle:
--   Active          — delegation is valid; check_capability returns Active.
--   StaleOnNextUse  — set by mark_stale_on_epoch_advance when the policy epoch
--                     advances. The delegation is still valid for one more gate
--                     evaluation (the "grace use"), after which record_capability_use
--                     transitions it to RenewalRequired. The planner receives
--                     warn_delegation_stale in IntentResponse on the grace use.
--   RenewalRequired — set by record_capability_use after the grace use is consumed.
--                     check_capability returns RenewalRequired; the planner must
--                     obtain a renewed delegation before the next intent.
-- Terminal override: revoked_at IS NOT NULL overrides status (Revoked).
-- Expiry override:   now() >= expires_at overrides status (Expired).
-- Both overrides run before the status field is examined.
--
-- epoch_stale_set_at: NULL until the first mark_stale_on_epoch_advance call
-- transitions this row Active → StaleOnNextUse. Retained for operator tooling.
--
-- revoked_at: soft-delete; never physically removed. Revocation takes effect
-- immediately at the next check_capability call.
CREATE TABLE IF NOT EXISTS delegations (
    delegation_id         TEXT    NOT NULL PRIMARY KEY,
    session_id            TEXT    NOT NULL
        REFERENCES sessions(session_id),
    capability_class      TEXT    NOT NULL,    -- CapabilityClass enum value; indexed for O(1) check_capability
    delegating_role_id    TEXT    NOT NULL,    -- role granting the delegation (operator-attested)
    delegate_role_id      TEXT    NOT NULL,    -- session.role_id at grant time; audit traceability
    effective_from        INTEGER NOT NULL,    -- Unix seconds; delegation invalid before this timestamp
    expires_at            INTEGER NOT NULL,    -- Unix seconds; hard expiry
    revoked_at            INTEGER,             -- NULL until explicitly revoked; overrides status when set
    status                TEXT    NOT NULL DEFAULT 'Active'
        CHECK (status IN ('Active', 'StaleOnNextUse', 'RenewalRequired')),
    epoch_stale_set_at    INTEGER,             -- NULL until mark_stale_on_epoch_advance fires (Active → StaleOnNextUse)
    UNIQUE (session_id, capability_class)      -- one delegation per (session, capability); O(1) lookup key
);
```

**`check_capability` check order (normative; maps to `authority::delegation::check_capability` in Part 2.3):**
1. Row lookup: `SELECT ... FROM delegations WHERE session_id = ? AND capability_class = ?`. If no row → `DelegationStatus::NotGranted`.
2. `revoked_at IS NULL` — if revoked, return `DelegationStatus::Revoked`.
3. `now() < expires_at` — if expired, return `DelegationStatus::Expired`.
4. `now() >= effective_from` — if not yet effective, return `DelegationStatus::NotYetEffective`.
5. Return `DelegationStatus::{Active | StaleOnNextUse | RenewalRequired}` matching `status`. `RenewalRequired` is the only status that blocks gate passage in `claim::evaluate`.

**`mark_stale_on_epoch_advance` (called from `policy_manager.rs` on epoch advance):**
```sql
UPDATE delegations
   SET status = 'StaleOnNextUse',
       epoch_stale_set_at = ?   -- now()
 WHERE status = 'Active'
   AND revoked_at IS NULL
   AND expires_at > ?;          -- now(); skip already-expired rows
```
Returns row count updated (`usize`). Applies system-wide to all active delegations when the policy epoch advances.

**`record_capability_use` (called from `claim::evaluate` step 4, on `SufficientStale` path only):**
```sql
UPDATE delegations
   SET status = 'RenewalRequired'
 WHERE delegation_id = ?
   AND status = 'StaleOnNextUse';   -- guard: returns DelegationNotStale if not in grace state
```
This transition is one-way. The planner must obtain a new delegation grant to restore `Active` status.

---

##### Table 8 — `escalations`

```sql
-- ── escalations ──────────────────────────────────────────────────────────────────
-- One row per escalation request. Created by handlers/escalation.rs when the
-- planner submits EscalationRequest. The status field is the Escalation FSM state.
--
-- Escalation FSM — canonical transitions (all non-terminal transitions are kernel):
--   Pending → Approved:      operator `raxis-cli escalation approve <escalation_id> ...`
--   Pending → Denied:        operator `raxis-cli escalation deny <escalation_id> [--reason ...]`
--   Pending → TimedOut:      kernel timeout sweep: now() > timeout_at
--   Approved → TokenExpired: kernel timeout sweep: now() > approval_tokens.expires_at
--   Approved → Consumed:     planner presents valid token; action executes; proof written
-- Terminal states: Denied, TimedOut, TokenExpired, Consumed.
-- A terminal escalation can never transition again (CHECK enforced procedurally).
--
-- lineage_id is denormalised from session.lineage_id at submission time.
-- The escalation rate-limiter query reads lineage_rate_limits by lineage_id
-- and must not require a join through sessions at query time.
-- lineage_id is immutable for a given session after creation, so denormalisation
-- is safe and will never diverge from session.lineage_id.
--
-- idempotency_key is planner-supplied. The kernel rejects a second
-- EscalationRequest from the same session with the same idempotency_key by
-- returning the existing escalation_id (not an error). This prevents duplicate
-- escalations from network retries. The UNIQUE (session_id, idempotency_key)
-- constraint makes the duplicate-detection check a single index lookup.
--
-- timeout_at: set at EscalationRequest submission time as
--   created_at + policy.escalation_timeout(class).
-- The timeout sweep is a best-effort kernel background task; it may fire slightly
-- after timeout_at. Downstream effects (TimedOut status) are idempotent.
CREATE TABLE IF NOT EXISTS escalations (
    escalation_id         TEXT    NOT NULL PRIMARY KEY,
    session_id            TEXT    NOT NULL
        REFERENCES sessions(session_id),
    task_id               TEXT    NOT NULL
        REFERENCES tasks(task_id),
    lineage_id            TEXT    NOT NULL,    -- denormalised from session.lineage_id; never updated
    initiative_id         TEXT    NOT NULL
        REFERENCES initiatives(initiative_id),
    class                 TEXT    NOT NULL,    -- JSON-serialised EscalationClass enum variant
    requested_scope_json  TEXT    NOT NULL,    -- JSON-serialised RequestedEscalationScope (planner-proposed)
    justification         TEXT    NOT NULL,    -- free-text planner rationale; included in operator notification
    idempotency_key       TEXT    NOT NULL,    -- planner-supplied; UNIQUE per session for dedup
    status                TEXT    NOT NULL DEFAULT 'Pending'
        CHECK (status IN (
            'Pending',
            'Approved',
            'Denied',
            'TimedOut',
            'TokenExpired',
            'Consumed'
        )),
    created_at            INTEGER NOT NULL,    -- Unix seconds; set when EscalationRequest is accepted
    timeout_at            INTEGER NOT NULL,    -- Unix seconds; Pending → TimedOut after this
    resolved_at           INTEGER,             -- NULL until status leaves Pending; set by all resolution paths
    resolution_notes      TEXT,                -- operator-supplied text for Denied; NULL for all other statuses
    UNIQUE (session_id, idempotency_key)
);
```

**`lineage_rate_limits` relationship:** the `escalations` table records individual escalation requests; the rate-limit state for a lineage is tracked separately in `lineage_rate_limits` (table 15, DDL Part 3). The escalation handler reads `lineage_rate_limits` before inserting into `escalations` — the two tables are coordinated by `handlers/escalation.rs` but are independent SQL structures.

**Escalation FSM invariant (INV-ESC-01):** the kernel never writes a new escalation row while another row for the same `(session_id, task_id)` is in `Pending` or `Approved` state. This check runs before INSERT and is enforced procedurally in `handlers/escalation.rs` (not as a SQL constraint, because concurrent callers could race; the check is inside a store transaction).

---

> **§2.5.1 — DDL Part 2a complete (tables 7–8: delegations, escalations).**

---

##### Table 9 — `approval_tokens`

```sql
-- ── approval_tokens ──────────────────────────────────────────────────────────────
-- One row per operator-issued approval token. Exactly one token per escalation
-- (UNIQUE on escalation_id) — the operator cannot issue a second token for an
-- escalation that already has one; if the first token expires, the escalation
-- transitions to TokenExpired and the operator must re-approve (creating a new
-- escalation row, which can then receive a new token).
--
-- policy_epoch: token is invalid if the kernel's current epoch differs from
-- this field (INV-ESC-02, validate_approval_token check 2). This prevents
-- stale-policy approvals: if policy changes between approve and present, the
-- operator must re-approve under the new policy epoch.
--
-- token_hash: hex SHA-256 of the raw token bytes. The raw bytes are NEVER
-- stored — only the hash. The planner presents raw bytes; the kernel recomputes
-- SHA-256 and compares constant-time. This prevents kernel.db from being a direct
-- token oracle (same design as verifier_run_tokens).
--
-- nonce: a random 128-bit value embedded in the token and also stored here.
-- On first presentation, the nonce is written to approval_token_nonces (PK
-- constraint prevents replay). The UNIQUE (nonce) constraint here ensures two
-- approval_tokens can never share a nonce, which simplifies the nonce-table
-- lookup: a match in approval_token_nonces unambiguously identifies one token.
--
-- scope_json may be narrower than escalations.requested_scope_json — the
-- operator may grant a subset of what the planner requested. validate_approval_
-- token check 6 verifies the presented action falls within scope_json.
CREATE TABLE IF NOT EXISTS approval_tokens (
    approval_token_id     TEXT    NOT NULL PRIMARY KEY,
    escalation_id         TEXT    NOT NULL UNIQUE     -- one token per escalation
        REFERENCES escalations(escalation_id),
    scope_json            TEXT    NOT NULL,    -- JSON-serialised ApprovalScope; may narrow requested_scope_json
    issued_by_operator_id TEXT    NOT NULL,    -- operator ID from authenticated operator CLI session
    policy_epoch          INTEGER NOT NULL,    -- epoch at issuance; token invalid if current epoch differs (INV-ESC-02)
    token_hash            TEXT    NOT NULL,    -- hex SHA-256 of raw token bytes; raw bytes never stored
    nonce                 TEXT    NOT NULL UNIQUE,  -- hex random 128-bit nonce embedded in the token
    issued_at             INTEGER NOT NULL,
    expires_at            INTEGER NOT NULL,    -- hard expiry; validate_approval_token check 3
    consumed              INTEGER NOT NULL DEFAULT 0   -- set to 1 atomically with approval_proofs insert
        CHECK (consumed IN (0, 1))
);
```

**`validate_approval_token` check order (normative; maps to INV-ESC-02):**
1. `token_hash` lookup — if no row found, return `ApprovalStatus::NotFound`.
2. `policy_epoch == ctx.policy.load().epoch()` — if mismatch, return `ApprovalStatus::EpochMismatch`. Escalation remains `Approved`; operator must re-issue.
3. `now() < expires_at` — if expired, return `ApprovalStatus::Expired`. Kernel timeout sweep will transition escalation to `TokenExpired`.
4. `consumed == 0` — if already consumed, return `ApprovalStatus::AlreadyConsumed`.
5. Nonce replay check — `NOT EXISTS (SELECT 1 FROM approval_token_nonces WHERE nonce = ?)`. If a row exists, return `ApprovalStatus::NonceConsumed` (internal; dispatcher maps to `UNAUTHORIZED`).
6. Scope check — verify the presented action falls within `scope_json`. If not, return `ApprovalStatus::OutOfScope`.
7. `escalation.status == 'Approved'` — if not Approved (e.g. race with timeout sweep), return `ApprovalStatus::EscalationNotApproved`.
8. If all checks pass, return `ApprovalStatus::Valid`.

---

##### Table 10 — `approval_proofs`

```sql
-- ── approval_proofs ──────────────────────────────────────────────────────────────
-- One row per successfully executed escalated action. Provides a non-repudiable
-- kernel attestation that a specific action was executed under a specific token.
--
-- Written atomically with three other writes (all in one store transaction):
--   1. approval_proofs INSERT (this row)
--   2. approval_tokens SET consumed = 1 WHERE approval_token_id = ?
--   3. approval_token_nonces INSERT (nonce row)
--   4. escalations SET status = 'Consumed', resolved_at = now()
-- If any step fails, all four roll back. This preserves the invariant that
-- escalation.status = Consumed ↔ approval_proofs row exists ↔ nonce consumed.
--
-- kernel_signature covers: escalation_id ‖ approval_token_id ‖ action_hash
--   ‖ policy_epoch ‖ action_taken_at (all as UTF-8 bytes, pipe-separated).
-- Signed with the kernel's authority_keypair (Ed25519) — see §2.5.4 four-key
-- custody model. The authority_keypair is the kernel's own runtime signing key
-- and is reserved for ApprovalProof receipts and policy artifact verification;
-- it is distinct from the operator key (held by the human operator, never by
-- the kernel) which signs plan artifacts per §2.5.3. This row provides a
-- kernel-signed receipt that survives audit log rotation and can be verified
-- without the JSONL chain by anyone holding the kernel authority_pubkey.
--
-- The audit log's AuditEventKind::EscalationConsumed carries the same fields
-- and is the operational record; approval_proofs is the cryptographic receipt.
CREATE TABLE IF NOT EXISTS approval_proofs (
    proof_id              TEXT    NOT NULL PRIMARY KEY,
    escalation_id         TEXT    NOT NULL UNIQUE     -- one proof per escalation
        REFERENCES escalations(escalation_id),
    approval_token_id     TEXT    NOT NULL UNIQUE     -- one proof per token (invariant from both directions)
        REFERENCES approval_tokens(approval_token_id),
    action_hash           TEXT    NOT NULL,    -- hex SHA-256 of action_description_json bytes
    action_description_json TEXT  NOT NULL,    -- JSON: action kind, parameters, outcome
    action_taken_at       INTEGER NOT NULL,    -- Unix seconds; when the escalated action executed
    policy_epoch          INTEGER NOT NULL,    -- epoch at execution time; included in kernel_signature
    kernel_signature      TEXT    NOT NULL     -- hex Ed25519 sig over (escalation_id ‖ approval_token_id ‖ action_hash ‖ policy_epoch ‖ action_taken_at)
);
```

**Why `UNIQUE` on both `escalation_id` and `approval_token_id`?** They are equivalent here (one token per escalation, one proof per token), but expressing both FKs as UNIQUE independently means a schema-level bug that breaks the one-to-one assumption is caught by whichever constraint fires first, rather than requiring a JOIN to detect the violation.

---

##### Table 11 — `approval_token_nonces`

```sql
-- ── approval_token_nonces ─────────────────────────────────────────────────────────
-- Tracks consumed approval token nonces to prevent replay.
--
-- The PRIMARY KEY on nonce is the replay-prevention mechanism: inserting the
-- same nonce a second time fails with a PRIMARY KEY constraint violation.
-- This makes the nonce-consumption step in the approval transaction idempotent-
-- safe: a duplicate presentation (network retry, adversarial replay) fails at
-- the SQL level, not just at the application level. The constraint fires
-- BEFORE the escalation status or proof row are written, so no partial state
-- is possible on replay.
--
-- Note: this table is distinct from the IPC-layer nonce_cache (table 16,
-- DDL Part 3), which stores (session_id, sequence_num, envelope_nonce) per
-- accepted IPC message for INV-01 replay prevention. The two nonce systems
-- use different types: nonce_cache rows carry a monotonic sequence_num plus
-- a random 128-bit envelope_nonce (one row per IPC message, TTL-evicted);
-- approval_token_nonces carry a random 128-bit token nonce with no ordering
-- guarantee (one row per consumed token, never evicted).
CREATE TABLE IF NOT EXISTS approval_token_nonces (
    nonce                 TEXT    NOT NULL PRIMARY KEY,  -- from approval_tokens.nonce; first use succeeds, replay fails
    approval_token_id     TEXT    NOT NULL
        REFERENCES approval_tokens(approval_token_id),
    consumed_at           INTEGER NOT NULL               -- Unix seconds; when the nonce was first consumed
);
```

---

##### Table 12 — `verifier_run_tokens`

```sql
-- ── verifier_run_tokens ──────────────────────────────────────────────────────────
-- Single-use credentials issued to verifier subprocesses. One row per verifier
-- run. The token authorises exactly one WitnessSubmission at ipc/handlers/witness.rs.
--
-- token_hash: hex SHA-256 of the raw token bytes (same pattern as approval_tokens).
-- The raw token bytes are NEVER stored. The verifier subprocess presents raw bytes;
-- the kernel computes SHA-256 and compares constant-time to token_hash.
--
-- gate_type: which gate this run evaluates. Not used for gate-recheck routing
-- (the full claim set is re-evaluated after witness acceptance); included for
-- audit traceability in WitnessAccepted events and for operator tooling.
--
-- Write-then-consume ordering (enforced by handlers/witness.rs):
--   1. Witness filesystem write (blob → witness/)
--   2. witness_records SQL insert
--   3. consume_verifier_token: SET consumed = 1 WHERE verifier_run_id = ?
-- If step 1 or 2 fails, step 3 is not reached; token remains unconsumed and
-- the verifier may resubmit within TTL. If step 3 fails after 1+2 succeed,
-- the witness is in the index but the token is not consumed — the verifier
-- receives an error and may retry; the retry will be a duplicate witness write
-- (content-addressed, idempotent on filesystem) and a duplicate SQL insert on
-- witness_records — same verifier_run_id hits PRIMARY KEY; witness_index::write
-- treats that as already recorded. Step 3 is then retried; if it succeeds, state is
-- consistent. If it fails permanently, startup_check detects the orphan.
--
-- consumed is never reset to 0 (monotonically set). A consumed token that
-- is presented again fails validate_verifier_token check 3.
CREATE TABLE IF NOT EXISTS verifier_run_tokens (
    verifier_run_id       TEXT    NOT NULL PRIMARY KEY,
    task_id               TEXT    NOT NULL
        REFERENCES tasks(task_id),
    gate_type             TEXT    NOT NULL,    -- JSON-serialised GateType enum value
    evaluation_sha        TEXT    NOT NULL,    -- head_commit_sha from the binding intent; gates this run to one SHA
    token_hash            TEXT    NOT NULL,    -- hex SHA-256 of raw token bytes; raw bytes never stored
    issued_at             INTEGER NOT NULL,
    expires_at            INTEGER NOT NULL,    -- hard TTL; validate_verifier_token check 2
    consumed              INTEGER NOT NULL DEFAULT 0   -- set to 1 by consume_verifier_token after witness write
        CHECK (consumed IN (0, 1)),
    consumed_at           INTEGER              -- Unix seconds; set when consumed transitions 0 → 1; NULL until consumed
);
```

**`validate_verifier_token` check order (normative):**
1. `token_hash` lookup by `verifier_run_id` — if no row, return `AuthorityError::TokenNotFound`.
2. `now() < expires_at` — if expired, return `AuthorityError::TokenExpired`.
3. `consumed == 0` — if already consumed, return `AuthorityError::TokenConsumed`.
4. `evaluation_sha` binding check — the witness handler compares `sub.head_commit_sha` to `task.evaluation_sha` (a separate application-level check, not a token-level check; included here for completeness). Token validates independently of this SHA comparison.
5. Return `Ok(VerifierTokenRow { verifier_run_id, task_id, gate_type, evaluation_sha })`.

---

> **§2.5.1 — DDL Part 2 of 4 complete (tables 7–12: delegations, escalations, approval_tokens, approval_proofs, approval_token_nonces, verifier_run_tokens).**

---

#### Canonical DDL — Part 3 of 4: Witness index, budget reservations, rate limits, nonce cache

**Creation order within this section:** `witness_records` → `lane_budget_reservations` → `lineage_rate_limits` → `nonce_cache`. All reference tables from Part 1 (`sessions`, `tasks`) or have no FK dependencies (standalone tracking tables).

---

##### Table 13 — `witness_records`

```sql
-- ── witness_records ───────────────────────────────────────────────────────────────
-- SQL index for the content-addressed witness blob store.
-- Blobs live on the filesystem at $RAXIS_DATA_DIR/witness/<blob_sha256>.
-- This table stores only index metadata; blob bytes are never in kernel.db.
-- All reads and writes go through witness_index.rs — no other module may
-- query or INSERT/UPDATE this table.
--
-- verifier_run_id is the PRIMARY KEY: one index row per verifier run.
-- Multiple rows for the same (evaluation_sha, task_id, gate_type) may exist
-- if a verifier was re-run (e.g. TTL retry after witness timeout). The lookup
-- function witness_index::lookup returns the most recent row when
-- verifier_run_id is None, ordered by recorded_at DESC.
--
-- result_class: normalised outcome of the verifier run. Set by handlers/witness.rs
-- from the verifier subprocess exit status (Pass / Fail / Inconclusive).
-- Interpretation: gates/witness.rs checks result_class == 'Pass' to decide
-- whether a gate is satisfied. Fail and Inconclusive are stored but cause
-- the gate to remain unsatisfied (triggering a re-run if within TTL, or
-- WitnessTimeout if TTL is exceeded).
--
-- blob_path: relative path within $RAXIS_DATA_DIR/witness/. In v1 this is
-- always equal to blob_sha256 (content-addressed naming). The field is stored
-- separately to allow future layout changes (e.g. sharding by prefix) without
-- a schema migration.
--
-- retry-idempotency: if consume_verifier_token fails after the witness write
-- (filesystem + witness_records insert), the verifier retries the same
-- WitnessSubmission (same verifier_run_id). The retry hits the PRIMARY KEY
-- constraint on this table — witness_index::write treats SQLITE_CONSTRAINT_PRIMARYKEY
-- as "already recorded" and returns Ok. There is no additional composite
-- UNIQUE needed for this case; the PK alone provides the guarantee.
CREATE TABLE IF NOT EXISTS witness_records (
    verifier_run_id       TEXT    NOT NULL PRIMARY KEY
        REFERENCES verifier_run_tokens(verifier_run_id),
    evaluation_sha        TEXT    NOT NULL,    -- head_commit_sha; must match verifier_run_tokens.evaluation_sha
    task_id               TEXT    NOT NULL
        REFERENCES tasks(task_id),
    gate_type             TEXT    NOT NULL,    -- JSON-serialised GateType; must match verifier_run_tokens.gate_type
    result_class          TEXT    NOT NULL
        CHECK (result_class IN ('Pass', 'Fail', 'Inconclusive')),
    blob_sha256           TEXT    NOT NULL,    -- hex SHA-256 of blob bytes; filename in witness/ dir
    blob_path             TEXT    NOT NULL,    -- relative path within witness_dir; = blob_sha256 in v1
    recorded_at           INTEGER NOT NULL     -- Unix seconds; set by witness_index::write
);
```

**Indexes for `witness_records`:**

```sql
-- Supports witness_index::lookup when verifier_run_id is None:
-- "most recent record for (evaluation_sha, task_id, gate_type)"
CREATE INDEX IF NOT EXISTS idx_witness_records_lookup
    ON witness_records (evaluation_sha, task_id, gate_type, recorded_at DESC);

-- Supports startup_check orphan-row scan:
-- "all blob_sha256 values in the index" without a full scan
CREATE INDEX IF NOT EXISTS idx_witness_records_blob_sha256
    ON witness_records (blob_sha256);
```

**Consistency invariant with `verifier_run_tokens`:** `witness_records.verifier_run_id` REFERENCES `verifier_run_tokens(verifier_run_id)`. This FK guarantees that a witness record can only exist for a token that was issued by the kernel. A record with no corresponding token row is impossible under FK enforcement — it would mean the verifier forged a run ID.

---

##### Table 14 — `lane_budget_reservations`

```sql
-- ── lane_budget_reservations ──────────────────────────────────────────────────────
-- Per-lane, per-task budget reservations. One row per task for the task's entire
-- non-terminal life (Admitted → Running or GatesPending → ... → terminal).
--
-- PRIMARY KEY (lane_id, task_id) enforces the single-reservation invariant:
-- at most one active reservation per task per lane. The intent handler checks
-- for row existence before calling consume_budget; if a row exists (continuation
-- intent or GatesPending → Admitted cycle), it skips check_budget and
-- consume_budget to avoid double-charging. The PK constraint is a schema-level
-- backstop against bugs in that application-level check.
--
-- reserved_cost: the estimated_cost computed by compute_admission_cost at first
-- intent pickup. This value is also written to tasks.admission_reserved_units
-- so it is available after release_budget deletes this row (needed by
-- reconcile_actual_cost for BudgetOverrun delta calculation).
--
-- reserved_at: set when consume_budget runs (inside the intent handler
-- transaction, after gate evaluation). Not the same as tasks.admitted_at
-- (set at approve_plan time). The gap between admitted_at and reserved_at
-- is the "plan-to-pickup latency" — observable from audit records.
--
-- release_budget: DELETE FROM lane_budget_reservations WHERE lane_id = ?
--   AND task_id = ?. rows_affected() == 0 → idempotent (already released,
--   safe in crash recovery); == 1 → released; > 1 → impossible under PK
--   (SchedulerError::CorruptReservationState). Every terminal-state handler
--   calls release_budget BEFORE reconcile_actual_cost — this ordering is
--   required because reconcile_actual_cost reads tasks.admission_reserved_units
--   (not this table) for the overrun delta; release_budget must clear the
--   row so the lane ceiling is updated before the next task's check_budget.
CREATE TABLE IF NOT EXISTS lane_budget_reservations (
    lane_id               TEXT    NOT NULL,    -- from tasks.lane_id; not a FK (lane config lives in policy, not DB)
    task_id               TEXT    NOT NULL
        REFERENCES tasks(task_id),
    reserved_cost         INTEGER NOT NULL,    -- admission units; = tasks.admission_reserved_units for this task
    reserved_at           INTEGER NOT NULL,    -- Unix seconds; when consume_budget ran (intent pickup time)
    PRIMARY KEY (lane_id, task_id)
);
```

**`check_budget` query pattern (for implementer reference):**

```sql
-- Active tasks = rows in this table for the lane (each row = one non-terminal task).
-- Reserved cost = sum of reserved_cost for the lane.
-- Both checks are pure reads; no write occurs.
SELECT
    COUNT(*)            AS active_tasks,
    COALESCE(SUM(reserved_cost), 0) AS reserved_cost
FROM lane_budget_reservations
WHERE lane_id = ?;          -- bind: lane_id
-- Caller compares:
--   active_tasks >= lane.max_concurrent_tasks → BudgetExceeded::ConcurrencyLimit
--   reserved_cost + estimated_cost > lane.max_cost_per_epoch → BudgetExceeded::CostLimit
```

**Why `lane_id` is not a FK:** lane configuration lives in the signed policy artifact (loaded into memory as `PolicyBundle`), not in a kernel.db table. There is no `lanes` SQL table — lanes are not mutable kernel state. Referential integrity between `lane_budget_reservations.lane_id` and the policy bundle is enforced at `scheduler::admit` time (lane existence check against `PolicyBundle`) and at `check_budget` time (lane ceiling lookup from `PolicyBundle`). A lane_id in `lane_budget_reservations` that no longer appears in a newly loaded policy is a runtime warning (`LaneRemovedFromPolicy`), not a DB constraint violation.

---

> **§2.5.1 — DDL Part 3a complete (tables 13–14: witness_records, lane_budget_reservations).**

---

##### Table 15 — `lineage_rate_limits`

```sql
-- ── lineage_rate_limits ───────────────────────────────────────────────────────────
-- Per-lineage escalation rate-limit state. One row per lineage_id, created on
-- first escalation submission from that lineage and updated on each subsequent
-- submission. Read by handlers/escalation.rs before accepting an EscalationRequest.
--
-- A "lineage" is the trust chain identifier stored on sessions: all sessions
-- from the same agent instance share a lineage_id. Rate-limiting by lineage
-- prevents a single compromised or misbehaving agent from overwhelming the
-- operator review queue by cycling through many short-lived sessions.
--
-- window_start: the start of the current sliding window (Unix seconds).
-- escalation_count: number of escalations accepted in [window_start, window_start + window_size).
-- window_size is read from policy.escalation_rate_limit.window_seconds at check
-- time — it is not stored here, so policy changes take effect at the next window.
-- If now() >= window_start + window_size, the handler resets (window_start = now(),
-- escalation_count = 1) before inserting the new escalation.
--
-- quarantined: set to 1 when escalation_count reaches
-- policy.escalation_rate_limit.quarantine_threshold within a window.
-- A quarantined lineage cannot submit new escalations; subsequent EscalationRequests
-- return HandlerError::LineageQuarantined immediately. Quarantine is lifted by
-- operator CLI: `raxis-cli quarantine lift <lineage_id>`.
--
-- quarantine_trigger_count: the escalation_count value that triggered quarantine.
-- Retained for audit inspection; not used in any runtime check.
--
-- quarantined_at: set when quarantined transitions 0 → 1. NULL before quarantine.
-- Used by operator tooling to show how long a lineage has been quarantined.
CREATE TABLE IF NOT EXISTS lineage_rate_limits (
    lineage_id              TEXT    NOT NULL PRIMARY KEY,
    window_start            INTEGER NOT NULL,    -- Unix seconds; start of current rate window
    escalation_count        INTEGER NOT NULL DEFAULT 0,  -- escalations accepted in this window
    quarantined             INTEGER NOT NULL DEFAULT 0
        CHECK (quarantined IN (0, 1)),
    quarantine_trigger_count INTEGER NOT NULL DEFAULT 0, -- escalation_count at quarantine time
    quarantined_at          INTEGER              -- NULL until quarantined; set when quarantined → 1
);
```

**Escalation rate-limit check flow (inside `handlers/escalation.rs`, before INSERT into `escalations`):**

```sql
-- Step 1: Load or initialise the lineage row (INSERT OR IGNORE first).
INSERT OR IGNORE INTO lineage_rate_limits (lineage_id, window_start, escalation_count)
    VALUES (?, ?, 0);   -- bind: lineage_id, now()

-- Step 2: Load current state.
SELECT window_start, escalation_count, quarantined
FROM lineage_rate_limits
WHERE lineage_id = ?;

-- Step 3 (application logic, not SQL):
--   If quarantined == 1 → return HandlerError::LineageQuarantined.
--   If now() >= window_start + policy_window_seconds:
--     → reset: UPDATE ... SET window_start = now(), escalation_count = 0.
--   If escalation_count + 1 >= policy_max_per_window:
--     → rate-limit: UPDATE ... SET escalation_count = count + 1.
--       Return HandlerError::RateLimitExceeded for THIS submission.
--       If, after the increment, escalation_count >= policy_quarantine_threshold:
--         additionally UPDATE ... SET quarantined = 1, quarantine_trigger_count = count + 1,
--                                     quarantined_at = now().
--         Emit AuditEventKind::LineageQuarantined. SUBSEQUENT submissions see LineageQuarantined;
--         THIS submission still returns RateLimitExceeded (quarantine is set before return
--         but the threshold-triggering request is rejected as RateLimitExceeded, not LineageQuarantined).
--   Otherwise: UPDATE ... SET escalation_count = escalation_count + 1.
--   Proceed to INSERT into escalations.
```

**Window-reset race:** the load and update run inside the enclosing handler store transaction (same connection, serialised writes). No concurrent modification is possible — the kernel's single-writer SQLite model means this check-then-update sequence is atomic within the transaction.

---

##### Table 16 — `nonce_cache`

```sql
-- ── nonce_cache ───────────────────────────────────────────────────────────────────
-- Per-session IPC message deduplication. Enforces both halves of INV-01:
--   (A) Strict sequence monotonicity: sequence_num == sessions.sequence_number + 1
--       (fast path — checked against the session row, NOT against this table)
--   (B) Random envelope nonce dedup: envelope_nonce not seen before within TTL
--       (checked via UNIQUE(session_id, envelope_nonce) insert constraint)
--
-- Role of sessions.sequence_number vs nonce_cache:
--   sessions.sequence_number  = last accepted sequence_num for this session.
--                               Updated atomically with the nonce_cache INSERT
--                               inside the auth transaction. Source of truth for
--                               check (A); no MAX() scan against this table needed.
--   nonce_cache               = per-message dedup window for check (B).
--                               Rows are TTL-evicted; sequence monotonicity makes
--                               eviction safe (evicted nonces cannot be replayed
--                               because their sequence_num <= sessions.sequence_number).
--
-- envelope_nonce: a random 128-bit value included in every IpcRequest envelope
-- (per §1.9). Must be unique within the session for the TTL window. Catches
-- duplicate delivery where the same packet arrives twice with the same sequence_num
-- AND the same envelope_nonce. UNIQUE(session_id, envelope_nonce): an INSERT that
-- fails this constraint → duplicate delivery detected → UNAUTHORIZED.
--
-- Distinct from approval_token_nonces (table 11):
--   approval_token_nonces: escalation-token nonces (random, per approval token,
--     permanent — no TTL eviction; no monotonic ordering guarantee).
--   nonce_cache: per-message envelope nonces (random 128-bit, scoped to session,
--     TTL-evicted; eviction is safe because sequence check (A) prevents replay).
--
-- Fast-path DELETE on session close:
--   DELETE FROM nonce_cache WHERE session_id = ?
-- Called by handlers/session.rs::close_session. No wait for background eviction.
CREATE TABLE IF NOT EXISTS nonce_cache (
    session_id            TEXT    NOT NULL
        REFERENCES sessions(session_id),
    sequence_num          INTEGER NOT NULL,    -- monotonic u64 from IpcRequest envelope
    envelope_nonce        TEXT    NOT NULL,    -- hex random 128-bit nonce from IpcRequest envelope
    observed_at           INTEGER NOT NULL,    -- Unix seconds; when this message was first accepted
    PRIMARY KEY (session_id, sequence_num),
    UNIQUE (session_id, envelope_nonce)        -- check (B): insert fails on duplicate envelope_nonce
);
```

**Indexes for `nonce_cache`:**

```sql
-- Supports background eviction sweep: find rows older than TTL.
CREATE INDEX IF NOT EXISTS idx_nonce_cache_observed_at
    ON nonce_cache (observed_at);
```

**INV-01 enforcement at the dispatcher (both checks run in one store transaction before dispatch):**
1. Extract `session_id`, `sequence_num`, and `envelope_nonce` from the incoming `IpcRequest` envelope.
2. Load session row: `SELECT sequence_number FROM sessions WHERE session_id = ?`. If no row or session is not `Active` → `UNAUTHORIZED`.
3. **Check (A) — strict sequence:** verify `sequence_num == sessions.sequence_number + 1`. If not, return `UNAUTHORIZED`. Log `AuditEventKind::ReplayRejected { session_id, sequence_num, reason: SequenceGap }`. No insert.
4. **Check (B) — envelope nonce:** `INSERT INTO nonce_cache (session_id, sequence_num, envelope_nonce, observed_at) VALUES (?, ?, ?, now())`. If this fails with `SQLITE_CONSTRAINT_UNIQUE` on `(session_id, envelope_nonce)` → duplicate delivery; return `UNAUTHORIZED`, log `reason: DuplicateNonce`. If it fails with `SQLITE_CONSTRAINT_PRIMARYKEY` → sequence already accepted (check A is the primary gate but PK is the schema backstop); return `UNAUTHORIZED`.
5. **Atomically:** `UPDATE sessions SET sequence_number = sequence_num WHERE session_id = ?`. Both the INSERT and UPDATE commit together or both roll back. This preserves the invariant `sessions.sequence_number == MAX(nonce_cache.sequence_num)` for this session.
6. Dispatch to handler. No handler logic executes before steps 2–5 complete.

---

> **§2.5.1 — DDL Part 3 of 4 complete.**
>
> **All 18 canonical `kernel.db` tables are now specified** (tables 17–18 added by §2.5.8 VCS Path Scope Enforcement):
>
> | Part | Tables |
> |------|--------|
> | Part 1 | `schema_version` (1), `initiatives` (2), `signed_plan_artifacts` (3), `sessions` (4), `tasks` (5), `task_dag_edges` (6) |
> | Part 2 | `delegations` (7), `escalations` (8), `approval_tokens` (9), `approval_proofs` (10), `approval_token_nonces` (11), `verifier_run_tokens` (12) |
> | Part 3 | `witness_records` (13), `lane_budget_reservations` (14), `lineage_rate_limits` (15), `nonce_cache` (16) |
> | Part 4 | `task_intent_ranges` (17), `task_exported_path_snapshots` (18) |
>
> The v1 baseline migration (migration 1) creates all 18 tables atomically. All table names in this DDL are canonical and supersede any conflicting names in Parts 2.1–2.4.

**DDL Part 4 of 4 — VCS Path Scope Enforcement tables (Tables 17–18)**

```sql
-- ============================================================
-- Table 17: task_intent_ranges
-- ============================================================
-- Accumulates per-intent VCS diff ranges for a task. Purposes:
--   1. Primary input for CompleteTask path check (union of all recorded intent
--      diffs), plus §2.5.8 trailing segment from tasks.evaluation_sha to
--      CompleteTask.head_sha when they differ.
--   2. Input for computing exported_paths snapshot at task completion.
--   3. Audit/replay: reconstruct the full path-touch history for any task.
--
-- Written atomically inside the same store transaction as intent acceptance.
-- Append-only. Never updated or deleted in normal operation.
-- One row per accepted intent per task.
--
-- PRIMARY KEY (task_id, head_sha): head_sha must advance monotonically per
-- task. Submitting the same head_sha twice returns SQLITE_CONSTRAINT_PRIMARYKEY;
-- the kernel treats this as an idempotent retry and returns the prior accepted
-- response without re-processing.
CREATE TABLE IF NOT EXISTS task_intent_ranges (
    task_id     TEXT    NOT NULL REFERENCES tasks(task_id),
    base_sha    TEXT    NOT NULL,    -- base_sha from the accepted IntentRequest
    head_sha    TEXT    NOT NULL,    -- head_sha from the accepted IntentRequest
    accepted_at INTEGER NOT NULL,   -- Unix seconds; intent acceptance timestamp
    PRIMARY KEY (task_id, head_sha)
);

CREATE INDEX IF NOT EXISTS idx_task_intent_ranges_task_id
    ON task_intent_ranges (task_id);

-- ============================================================
-- Table 18: task_exported_path_snapshots
-- ============================================================
-- Pre-computed export snapshot for tasks with path_export_to_successors = true.
-- Populated atomically during the task Completed transition (same transaction
-- as the tasks.status update). Never populated for tasks where
-- path_export_to_successors = false (default).
--
-- Contents: union of all touched paths across the task's accepted intents
-- (from task_intent_ranges via vcs::diff), intersected with the task's
-- path_export_globs if defined. If path_export_globs is absent, the full
-- union is stored (coarse export; operator's responsibility).
--
-- Queried by effective_allow() for successor tasks. Read-only after insert.
-- One row per exported path per task.
CREATE TABLE IF NOT EXISTS task_exported_path_snapshots (
    task_id TEXT NOT NULL REFERENCES tasks(task_id),
    path    TEXT NOT NULL,  -- POSIX-normalized path relative to worktree_root
    PRIMARY KEY (task_id, path)
);

CREATE INDEX IF NOT EXISTS idx_task_exported_path_snapshots_task_id
    ON task_exported_path_snapshots (task_id);

-- ============================================================
-- Table 19: policy_epoch_history
-- ============================================================
-- Append-only ledger of every successful policy epoch advance, plus the
-- genesis epoch installed at first boot. The MAX(epoch_id) row is the
-- kernel's current policy epoch — `read_current_epoch()` is implemented as
-- `SELECT COALESCE(MAX(epoch_id), 0) FROM policy_epoch_history` (returns 0
-- on a fresh, never-genesised store, which any valid first artifact with
-- epoch ≥ 1 satisfies — see philosophy.md §src/loader.rs step 6).
--
-- This table is the durable backing for `policy_manager::current_epoch` /
-- `read_current_epoch` and the source of truth for replay protection in
-- `load_and_verify` (an artifact whose epoch_id is not strictly greater than
-- MAX(epoch_id) is rejected as PolicyError::EpochReplay).
--
-- Written by exactly two paths:
--   1. genesis (`raxis-cli genesis` -> first `bootstrap::load_policy`):
--      inserts the row for epoch 1 (or whatever epoch the operator's
--      first signed artifact carries) under the same transaction that
--      finalises the schema.
--   2. `policy_manager::advance_epoch` Phase 1 step 6 (kernel-core.md
--      §policy_manager.rs): inserts one new row per successful advance,
--      under the same transaction as the delegations sweep, the session
--      prompt invalidation, and the PolicyEpochAdvanced audit append.
--
-- Never updated. Never deleted (the row count is naturally small — one row
-- per signed policy revision in the kernel's lifetime, typically tens to
-- low hundreds). The full history is needed for forensic replay: an audit
-- record that references policy_epoch = N must be interpretable against
-- the policy artifact identity (policy_sha256) that was active at epoch N.
--
-- policy_sha256 is hex-encoded SHA-256 of the canonical policy.toml bytes
-- (the same bytes verified by Ed25519Verify(authority_pubkey, ...) in
-- load_and_verify). signed_by_authority is the 8-byte truncated SHA-256
-- fingerprint of the authority public key (DER) that verified this
-- artifact; recording the fingerprint (not the full key) keeps the row
-- compact while still distinguishing across authority key rotations.
CREATE TABLE IF NOT EXISTS policy_epoch_history (
    epoch_id              INTEGER NOT NULL PRIMARY KEY,   -- monotonically increasing; matches PolicyBundle.epoch_id
    policy_sha256         TEXT    NOT NULL UNIQUE,        -- hex SHA-256 of canonical policy.toml bytes; UNIQUE prevents accidental re-insert of the same artifact under a different epoch_id
    signed_by_authority   TEXT    NOT NULL,               -- hex 8-byte truncated SHA-256 fingerprint of the authority pubkey that verified this artifact
    triggered_by_operator TEXT    NOT NULL,               -- OperatorId of the operator who invoked `raxis-cli epoch advance` (genesis row uses the literal string "genesis")
    advanced_at           INTEGER NOT NULL                -- Unix seconds (UTC); commit timestamp of this row
);

CREATE INDEX IF NOT EXISTS idx_policy_epoch_history_advanced_at
    ON policy_epoch_history (advanced_at);
```

> **§2.5.1 — DDL Part 4 of 4 complete. All 19 kernel.db tables specified.**

---

### §2.5.2 — Audit Log Transaction Boundary

#### Write ordering invariant

Every kernel state mutation follows a strict two-phase write order:

1. **SQLite commit first.** The store transaction is committed and `fsync`-equivalent durability is guaranteed before any audit record is attempted.
2. **JSONL append second.** `AuditTools::append` writes the serialised audit record to the JSONL file and flushes after the store commit returns `Ok`.

The JSONL audit log is the human-readable, tamper-evident ledger. SQLite is the ground truth for all FSM state. These roles never invert.

#### Audit record format

Audit records are append-only **JSONL**: one JSON object per line. **Physical layout:** under `<data_dir>/audit/`, the active segment file is conventionally named `segment-NNN.jsonl` (e.g. `segment-000.jsonl` on a fresh install). `raxis-audit-tools` may introduce additional segments when rotation policy triggers; the **per-line schema** is identical across segments. V1 deployments typically append to **`segment-000.jsonl`** until rotation is configured — there is no separate canonical `kernel.jsonl` path unless an operator symlink or migration supplies one.

Each line in the segment file being verified is a single JSON object:

```json
{
  "seq":          42,
  "event_id":     "<uuid-v4>",
  "event_kind":   "IntentAccepted",
  "session_id":   "<uuid>",
  "task_id":      "<task-id or null>",
  "initiative_id":"<initiative-id or null>",
  "payload":      { ... },
  "emitted_at":   1714500000,
  "prev_sha256":  "<hex of sha256 of previous line bytes>"
}
```

- `seq` — monotonically increasing counter, kernel-local, reset only on `genesis`. Gaps in `seq` indicate a reconciliation gap (see below).
- `prev_sha256` — SHA-256 of the **raw bytes** of the previous JSONL line (including the trailing newline). The first record uses `"0000...0000"` (64 zeroes). `raxis-audit-tools verify` walks the chain and fails on any hash mismatch.
- `payload` — event-kind-specific structured data. Schema for each `AuditEventKind` variant is defined in `raxis-types/src/audit.rs`.

#### Crash-window characterisation

Two failure modes are possible:

| Mode | Description | Recovery |
|---|---|---|
| **SQLite committed, JSONL not appended** | Process crashed between commit and JSONL write. State is correct; audit chain has a gap at that `seq`. | `recovery::reconcile` detects the gap: SQLite row exists with no corresponding JSONL line. Emits `AuditEventKind::ReconciliationGap { missing_seq, reconstructed_event }` to repair the chain. The reconstructed event is marked `reconstructed: true` in its payload. |
| **JSONL appended, SQLite rolled back** | Cannot happen under the write ordering invariant — JSONL is only written after `Ok` from the store commit. If the process crashes mid-commit (before `Ok`), SQLite WAL rolls back; no JSONL line is written. |

The second mode is structurally impossible given the write ordering invariant. Implementers **must not** attempt JSONL writes before store commit confirmation.

#### What `recovery::reconcile` treats as ground truth

- **SQLite is ground truth for FSM state.** On divergence, the task/initiative state in SQLite stands; JSONL is repaired to match.
- **JSONL is ground truth for ordering and chain integrity.** `seq` values from JSONL take precedence for chain repair; the kernel does not re-sequence existing records.
- `reconcile` never rewrites existing JSONL lines — it only appends gap records.

#### Kernel never reads JSONL

The kernel write path is append-only to JSONL. No kernel handler reads JSONL. Chain verification, gap analysis, and audit queries are exclusively `raxis-audit-tools` responsibilities. This is enforced by module boundaries: `src/audit.rs` exposes only `append` — no read interface.

---

### §2.5.3 — Plan Artifact Signing Contract

#### On-disk layout

```
<data_dir>/plans/<initiative_id>/
    plan.toml        # the human-readable plan artifact
    plan.sig         # the detached signature file
```

Both files are written by `raxis-cli plan sign`. The kernel reads both **once**, at `create_initiative` time, and seals their content into `signed_plan_artifacts` (Table 3). Every subsequent operation — `approve_plan`, crash recovery, audit reconstruction — reads `plan_bytes` and `plan_sig` from the sealed DB row, never from disk. The on-disk `plan.toml` and `plan.sig` files remain at `<data_dir>/plans/<initiative_id>/` for human inspection and external tooling, but they are **non-authoritative** once the seal succeeds: deleting, modifying, or replacing them does not affect kernel behaviour for that initiative, and the kernel does not re-open them at any point in the initiative lifecycle.

#### Byte-exact signing domain

The signature covers the **exact bytes of `plan.toml` as read from disk** — no normalization, no canonicalization, no whitespace stripping, no BOM handling. The SHA-256 of those exact bytes is computed first; the Ed25519 signature is over that SHA-256 digest (not over the raw bytes directly, for auditability).

```
plan_sha256   = SHA-256(file_bytes(plan.toml))
signature_hex = Ed25519Sign(operator_private_key, plan_sha256)
```

Post-sign editing of `plan.toml` — including whitespace or comment changes — **invalidates the signature**. The ceremony tool is the canonical generator; operators review the TOML before signing, not after.

#### `plan.sig` format

```toml
signed_by    = "<operator_pubkey_fingerprint>"   # SHA-256[:16] of the operator's raw Ed25519 public key, hex
signature    = "<hex-encoded Ed25519 signature>" # 64 bytes = 128 hex chars
plan_sha256  = "<hex SHA-256 of plan.toml>"      # 32 bytes = 64 hex chars
signed_at    = 1714500000                        # Unix timestamp (seconds)
```

`signed_by` is a fingerprint, not the full key. The kernel resolves the full public key from `policy.operators` by matching `fingerprint(operator.pubkey) == plan.sig.signed_by`. If no operator entry matches, `create_initiative` returns `FAIL_UNKNOWN_SIGNER`.

#### Plan-signing key (operator)

The **operator's Ed25519 private key** (registered in the policy artifact under `[[operators.entries]]`) signs plan artifacts — **not** the kernel's `authority_keypair`. The kernel verifies the signature using the operator's public key looked up via `policy.operator_entry(plan.sig.signed_by).public_key`. The kernel's `authority_keypair` is reserved for `ApprovalProof` records (escalation responses) and policy-artifact verification — it never signs or verifies plan artifacts. See §2.5.4 (four-key custody model) for the full key inventory and `philosophy.md` `src/signing.rs` for the three-way operator-vs-authority key-domain split. Older drafts of this section were titled "Authority key used"; that name is non-canonical and has been corrected to reflect the actual signing key.

#### IPC path — `create_initiative`

```
Operator → raxis-cli plan submit <initiative_id> <plan_dir>
    → kernel IPC: CreateInitiative { initiative_id, plan_toml_path, plan_sig_path }
    → kernel reads plan.toml bytes, plan.sig
    → verifies: SHA-256(plan.toml bytes) == plan.sig.plan_sha256
    → verifies: Ed25519Verify(operator_pubkey, plan.sig.plan_sha256, plan.sig.signature) == Ok
    → if ok: INSERT INTO initiatives + INSERT INTO signed_plan_artifacts (Table 3)
    → returns: InitiativeCreated { initiative_id } or error
```

`create_initiative` seals the plan into `signed_plan_artifacts` (§2.5.1 Table 3) by inserting a single row with exactly four columns:

- `initiative_id` — FK to `initiatives.initiative_id`.
- `plan_bytes` — the **full byte-image** of `plan.toml` exactly as read from disk and verified against `plan.sig.plan_sha256` above. The plan TOML content **is** stored in SQLite — this is intentional (see Table 3 rationale "Why store the full `plan_bytes` and not just the hash?"): it makes the kernel self-contained for `approve_plan`, recovery replay, and audit reconstruction, with no dependency on the on-disk file after sealing.
- `plan_sig` — the raw 64-byte Ed25519 signature decoded from `plan.sig.signature` (the hex-encoded form on disk is decoded to bytes for storage).
- `stored_at` — Unix seconds at insertion, for audit cross-referencing.

The other fields of `plan.sig` — `signed_by` (operator pubkey fingerprint), `signed_at`, and `plan_sha256` — are **verified** at this call but **not** duplicated as columns of `signed_plan_artifacts`:

- `plan_sha256` is recomputable from `plan_bytes` on demand and is also indexed at `initiatives.plan_artifact_sha256` for join lookups (Table 2).
- `signed_by` and `signed_at` are preserved in the audit log via `AuditEventKind::InitiativeCreated { initiative_id, plan_hash, signed_by, signed_at }` (see `kernel-core.md` `src/initiatives/lifecycle.rs::create_initiative`). The audit log is the durable signer-of-record; this avoids storing the same value redundantly in the row table while keeping forensic recoverability of "which operator authorised this initiative, and when did they sign it" intact even if the on-disk `plan.sig` file is later removed.

#### `approve_plan` call path

`approve_plan` does not re-verify the signature — it trusts the record in `signed_plan_artifacts` written at `create_initiative` time. It only checks that the `signed_plan_artifacts` row exists and `initiatives.status == Draft`. Signature verification happens exactly once, at `create_initiative`.

#### Immutability

Once `approve_plan` is called, the plan is locked (INV-INIT-06). The `signed_plan_artifacts` row is never updated. Any request to `create_initiative` with the same `initiative_id` returns `FAIL_INITIATIVE_EXISTS`.

---

### §2.5.4 — Key Inventory and Custody Model

#### Four key families

| Key | Algorithm | Who holds at runtime | Who holds at ceremony | Location on disk |
|---|---|---|---|---|
| `authority_keypair` | Ed25519 | Kernel only (loaded into memory at boot; file remains on disk) | Operator generates at genesis | `<data_dir>/keys/authority_keypair.pem` |
| `operator_key` | Ed25519 (per operator) | Operator workstation only — kernel never holds the private key | Operator (self-generated; public key registered at genesis) | Private key: operator's own keystore. Public key: `<data_dir>/keys/operator_<fingerprint>.pub` |
| `quality_keypair` | Ed25519 | **Reserved for v2 — not consumed by any v1 code path.** Loaded into `KeyRegistry` at startup and the public key is recorded in the policy artifact (`quality_pubkey`) so that v2 deployments can adopt witness-record signing without a new genesis ceremony or epoch advance. v1 writes `WitnessRecord` rows unsigned (see `kernel-core.md` `handlers/witness.rs` L349 and `gates/witness_index::write`); the integrity story for v1 witnesses rests on (a) FK enforcement that `witness_records.verifier_run_id` references a kernel-issued `verifier_run_tokens` row, (b) `evaluation_sha` binding so a witness submitted against the wrong commit is rejected at the handler, and (c) OS-level filesystem permissions on `kernel.db` (`0600`, kernel UID only). | Operator generates at genesis | `<data_dir>/keys/quality_keypair.pem` |
| `verifier_token_key` | HMAC-SHA256 (256-bit random) | Kernel only | Operator generates at genesis | `<data_dir>/keys/verifier_token_key.bin` |

#### Key loading at boot

`src/keyring.rs` loads all four families during `bootstrap::run`. Loading order:

1. `authority_keypair.pem` — Ed25519 keypair PEM (PKCS#8). Failure → `BOOT_ERR_KEY_LOAD { key: "authority_keypair" }`.
2. `operator_<fingerprint>.pub` files — all files matching that glob are loaded as trusted operator public keys. Zero files → `BOOT_ERR_NO_OPERATORS`.
3. `quality_keypair.pem` — Ed25519 keypair PEM. Failure → `BOOT_ERR_KEY_LOAD { key: "quality_keypair" }`.
4. `verifier_token_key.bin` — 32 raw bytes. Failure → `BOOT_ERR_KEY_LOAD { key: "verifier_token_key" }`.

All four must load successfully or the kernel exits before binding any socket.

#### Blast-radius characterisation

| Key compromised | Attacker capability | Recovery |
|---|---|---|
| `authority_keypair` | Forge `ApprovalProof` records — bypass escalation approval | Stop kernel · run genesis to generate new keypair · re-sign policy with new authority pubkey · verify all historical `ApprovalProof` records against old key · epoch advance |
| `operator_key` (private) | Sign fraudulent plan artifacts and approval tokens | Remove `operator_<fingerprint>.pub` from `keys/` · epoch advance · re-sign all active plans with a new operator key · audit all plans signed by the compromised key |
| `quality_keypair` | **In v1: no compromise impact.** The key is loaded but never used to sign or verify anything; an attacker who steals it gains no capability they did not already have. **In v2 (when witness signing is wired up):** forge `WitnessRecord` blobs — pass gate checks with fabricated evidence; mitigation will then be epoch advance + invalidate all cached witnesses + re-run all gates for active tasks + stop kernel + generate new keypair at next maintenance window. **Witness forgery threat in v1 is mitigated differently** — see the `quality_keypair` "Used by" cell above for the current integrity story (FK enforcement on `verifier_run_tokens` + `evaluation_sha` binding + OS filesystem permissions on `kernel.db`). |
| `verifier_token_key` | Forge `verifier_run_token` values — submit witness blobs without being spawned by the kernel | Rotate key (stop kernel · generate new `verifier_token_key.bin` · restart) · all in-flight verifier tokens are immediately invalid · active verifier runs must be re-spawned |

#### Key files format

```
authority_keypair.pem    — PKCS#8 PEM, Ed25519 private key (includes public key)
operator_<fp>.pub        — raw 32-byte Ed25519 public key, hex-encoded, one file per operator
quality_keypair.pem      — PKCS#8 PEM, Ed25519 private key (includes public key)
verifier_token_key.bin   — 32 bytes, raw binary (CSPRNG)
```

`<fp>` is the fingerprint: lowercase hex of SHA-256[:16] of the raw 32-byte Ed25519 public key.

#### Key rotation (v1)

Manual ceremony only. No in-place hot-swap. Rotation procedure:
1. Stop the kernel.
2. Run `raxis-cli genesis --rotate <key-family>` — generates new key material, writes new files.
3. For `operator_key`: operator generates new keypair externally; registers new `.pub` file and removes old one; re-signs all active plan artifacts with the new key.
4. Advance the policy epoch to invalidate all epoch-bound sessions and cached witnesses.
5. Restart the kernel.

---

### §2.5.5 — Operator Authentication Protocol

#### Three-socket model

The kernel binds three Unix domain sockets at startup:

| Socket | Path | Principals | Permitted operations |
|---|---|---|---|
| Planner UDS | `<data_dir>/sockets/planner.sock` | Planner sessions (session token auth) | All `IntentKind` variants, `WitnessSubmission` |
| Gateway UDS | `<data_dir>/sockets/gateway.sock` | Gateway process (gateway process token auth) | `FetchRequest`, `FetchResponse` |
| Operator UDS | `<data_dir>/sockets/operator.sock` | Operator CLI (challenge-response + operator session token) | `CreateInitiative`, `ApprovePlan`, `RejectPlan`, `CreateSession`, `RevokeSession`, `GrantDelegation`, `RetryTask`, `ResumeTask`, `AbortTask`, `AbortInitiative`, `ApproveEscalation`, `DenyEscalation`, `RotateEpoch` |

**Operator IPC discriminant reference:**

| IPC message | Precondition | State transition | Handler | `permitted_ops` name |
|---|---|---|---|---|
| `CreateInitiative { plan_toml_path, plan_sig_path }` | None | Inserts row in `initiatives` (`state: Draft`) + row in `signed_plan_artifacts` after Ed25519 verification | `initiatives::lifecycle::create_initiative` | `CreateInitiative` |
| `ApprovePlan { initiative_id }` | Initiative `Draft` | Initiative `→ ApprovedPlan`; instantiates task rows + DAG edges | `initiatives::lifecycle::approve_plan` | `ApprovePlan` |
| `RejectPlan { initiative_id }` | Initiative `Draft` | Initiative `→ Aborted` (draft discarded) | `initiatives::lifecycle::reject_plan` | `RejectPlan` |
| `CreateSession { role, worktree_root, base_tracking_ref, task_id?, lineage_id }` | `role == Planner` (gateway/verifier sessions are kernel-spawned, not operator-created in v1); `worktree_root` is an absolute path under operator-allowed roots; `lineage_id` is operator-supplied (see §2.5.5 "Lineage ownership and supply" below — operator-namespace UUID); `task_id` (optional) must be `Admitted` and unbound | Inserts row in `sessions` (`lineage_id` populates the NOT NULL Table 4 column); returns `(session_id, session_token)` | `authority::session::create_session` (called by `handlers/operator::create_session`) | `CreateSession` |
| `RevokeSession { session_id }` | Session row exists and `revoked_at IS NULL` | `UPDATE sessions SET revoked_at = now() WHERE session_id = ?` | `authority::session::revoke_session` | `RevokeSession` |
| `GrantDelegation { session_id, capability_class, delegating_role_id, expires_at, scope_json?, operator_sig }` | Session `Active` (not revoked, not expired); `capability_class ∈ policy.allowed_capabilities`; `delegating_role_id ∈ policy.role_ceilings` and the requested `capability_class` is within that role's ceiling; **at most one** active delegation per `(session_id, capability_class)` (UNIQUE in Table 7 — a duplicate grant returns `FAIL_DELEGATION_ALREADY_ACTIVE`; revoke first if you want to re-grant); `operator_sig` MUST verify against the operator's public key over the canonical signing domain defined in §2.5.5 "Delegation grant signing domain on the operator socket" below | Inserts row in `delegations` with `status = 'Active'`, `effective_from = now()`, `operator_signature` blob (Table 7 column), `epoch_stale_set_at = NULL` | `authority::delegation::grant_delegation` | `GrantDelegation` |
| `RetryTask { task_id }` | `Failed` | `→ Admitted` | `initiatives::lifecycle::retry_task` | `RetryTask` |
| `ResumeTask { task_id }` | `BlockedRecoveryPending` | `→ Running` | `recovery::resume_task` | `ResumeTask` |
| `AbortTask { task_id }` | Task non-terminal | `→ Aborted` (`OperatorAbort`) | `initiatives::lifecycle::abort_task` | `AbortTask` |
| `AbortInitiative { initiative_id }` | Initiative non-terminal | Initiative `→ Aborted`; bulk task cancellation per `lifecycle::abort_initiative` | `initiatives::lifecycle::abort_initiative` | `AbortInitiative` |
| `ApproveEscalation { op_token, escalation_id, approval_scope, operator_sig }` | Escalation `Pending` | Escalation `→ Approved`; writes `approval_tokens` + `approval_proofs` rows | `authority::approve_escalation` | `ApproveEscalation` |
| `DenyEscalation { op_token, escalation_id, reason }` | Escalation `Pending` | Escalation `→ Denied`; no token issued; audit-only record | `authority::deny_escalation` | `DenyEscalation` |
| `RotateEpoch { policy_path, sig_path }` | Phase 0 verification of new artifact passes (signature, epoch monotonicity, TOML shape, path under `<data_dir>/policy/`) | Phase 1 SQL transaction: sweeps `delegations` to `StaleOnNextUse`, invalidates session prompts, inserts `policy_epoch_history` row, appends `PolicyEpochAdvanced` audit. Phase 2 swaps `ArcSwap<PolicyBundle>` and `ArcSwap<AllowlistCache>`. Phase 3 best-effort gateway signal. | `policy_manager::advance_epoch` (called by `handlers/operator::handle_rotate_epoch`) | `RotateEpoch` |

`DenyEscalation` does not require `operator_sig` (no approval artifact is created; the audit event is the only record). `ApproveEscalation` requires `operator_sig` because the resulting `ApprovalProof` must be independently verifiable after a crash (INV-ESC-01). `AbortTask` and `AbortInitiative` are distinct variants — per-task abort (`OperatorAbort`) vs initiative-wide abort. `ResumeTask` and `RetryTask` are distinct message types dispatched on IPC discriminant, not on probed task state. `CreateSession` and `RevokeSession` are the v1 mechanism by which planner sessions are minted and torn down (gateway and verifier sessions are kernel-spawned via separate code paths and are not minted via this IPC — see `kernel-core.md` Part 2.3 §`session.rs` for the role-specific spawn paths). `GrantDelegation` is the operator's per-session capability-grant operation; the session must already exist (operator workflow is typically `CreateSession` → `GrantDelegation` × N capabilities → operator hands the session token to the planner spawn → planner submits its first intent). **This table is the single source of truth for operator IPC names and `permitted_ops` strings; `cli-ceremony.md` references it.**

The operator socket is bound with `mode 0600` and owned by the kernel OS user — readable only by the same user. v1 is single-operator, single-machine; this is the only access control at the socket layer.

#### Operator challenge-response handshake

On every new connection to the operator socket:

```
Kernel → Operator:  ChallengeEnvelope { challenge_bytes: [u8; 32], issued_at: u64 }
Operator → Kernel:  ChallengeResponse { signed_by: <fingerprint>, signature: <64-byte hex> }
```

- `challenge_bytes` — 32 CSPRNG random bytes, freshly generated per connection. Never reused.
- `issued_at` — Unix timestamp. The kernel rejects a `ChallengeResponse` if `now - issued_at > 60s` (clock-skew window). This prevents a captured challenge from being replayed later.
- `signature` — Ed25519 signature of the raw `challenge_bytes` (not a digest of them) using the operator's private key.
- Kernel verifies: `Ed25519Verify(operator_pubkey[signed_by], challenge_bytes, signature) == Ok`.
- On success: kernel issues an **operator session token** (32 CSPRNG bytes, hex) and returns `AuthOk { operator_session_token }`. Token is stored in memory only (not in SQLite `sessions` table — operator sessions are not tracked in the planner session DDL).
- On failure: kernel closes the connection. No retry on the same connection.

#### Operator session token

- Presented in the header of every subsequent operator IPC message on the same connection: `{ op_token: "<hex>", ... }`.
- Valid only for the lifetime of the TCP/UDS connection — the kernel discards the token on disconnect.
- Not stored in SQLite. Lost on kernel restart (operator must re-authenticate).
- Scope: limited to operations in `permitted_ops` for that operator's policy entry.

#### `permitted_ops` schema

Each operator entry in `policy.toml` carries a `permitted_ops` list. The snippet below is a **minimal illustration only** — production entries must include **every** IPC operation that operator is allowed to invoke (see the operator IPC discriminant table above for the canonical 13-operation v1 set: `CreateInitiative`, `ApprovePlan`, `RejectPlan`, `CreateSession`, `RevokeSession`, `GrantDelegation`, `RetryTask`, `ResumeTask`, `AbortTask`, `AbortInitiative`, `ApproveEscalation`, `DenyEscalation`, `RotateEpoch`).

```toml
[[operators.entries]]
pubkey_fingerprint = "abcd1234..."
display_name       = "Alice"
permitted_ops      = [
  "CreateInitiative", "ApprovePlan", "RejectPlan",
  "CreateSession", "RevokeSession", "GrantDelegation",
  "RetryTask", "ResumeTask",
  "AbortTask", "AbortInitiative",
  "ApproveEscalation", "DenyEscalation",
  "RotateEpoch",
]
```

The kernel enforces this at every operator IPC call: if the requested operation is not in `permitted_ops` for the authenticated operator → `UNAUTHORIZED { reason: OperationNotPermitted }`. This is evaluated after token validation, not before.

#### Lineage ownership and supply

`sessions.lineage_id` (Table 4 column, `NOT NULL`) is the **operator's namespace** for grouping related sessions. Every session has exactly one `lineage_id` and the value is **operator-supplied at `CreateSession` time** — the kernel does not synthesise it, does not derive it from any session field, and does not allow it to be `NULL`. The kernel's only constraints on the value are:

1. Non-empty UTF-8.
2. Parsable as a UUID v4 hyphenated form (36 ASCII bytes — same shape as `session_id`). The kernel validates with the standard `Uuid::parse_str` and rejects with `OperatorErrorCode::FAIL_INVALID_LINEAGE_ID` on parse failure.

Beyond those two checks the kernel is namespace-blind: any UUID v4 the operator supplies is accepted. The semantics are operator-side:

- **One agent instance, one lineage.** When an operator spawns a planner subprocess for a fresh agent (a fresh "instance" in their orchestration model — typically per-task, per-initiative, or per-developer-session), the operator generates a fresh `LineageId` (`Uuid::new_v4()` in the CLI). All sessions belonging to that agent instance share the lineage_id.
- **Reuse across sessions of the same agent.** If the operator revokes a session and creates a new one for the *same* logical agent (e.g. the agent crashed and the operator is restarting it under the same task), the operator MUST reuse the same `lineage_id`. This is what makes per-lineage rate-limiting (`escalation_max_per_window`) and quarantine (`escalation_quarantine_threshold`) effective — a misbehaving agent that hammers escalations cannot evade rate-limiting by getting its session revoked and recreated under a fresh lineage.
- **Distinct lineages per logical agent.** Two genuinely independent agents (different tasks, different initiatives, different developer sessions) MUST get different lineage_ids. Sharing a lineage across independent agents pools their rate-limit budgets, which is almost always a mistake.

**Why the operator owns lineage assignment, not the kernel.** The kernel cannot infer agent identity — it only sees session connections. "These two sessions are the same agent" is an orchestration-layer fact (same process tree, same task assignment, same operator-managed agent record). Asking the kernel to derive a lineage from session metadata would either be a tautology (lineage = session_id, which defeats the rate-limiting purpose) or wrong (lineage = task_id, which fails when one agent works on multiple tasks). The clean answer is: operator generates and supplies the lineage; kernel honours it.

**Why no `initiative_id` field on `CreateSession`.** Sessions in v1 are not bound to initiatives at the session-row level (`sessions` Table 4 has no `initiative_id` column). The session-to-initiative relationship is **derived through tasks**: a session that picks up `task_id = T` is operating on `T`'s containing initiative; a session bound to a single task at `CreateSession` time (`task_id: Some(T)`) is implicitly scoped to that initiative for its lifetime. Multi-initiative sessions (one session, intents on tasks across two initiatives) are accepted by the kernel but discouraged — operators SHOULD prefer one session per initiative for clarity, and v2 may add a normative `initiative_id` field to enforce it. v1 keeps the surface minimal.

**CLI behaviour.** `raxis-cli session create` accepts `--lineage-id <uuid>` for explicit reuse and **defaults to `--lineage-id $(uuidgen --random)`** when omitted (a fresh random UUID v4 per invocation). The CLI prints the chosen `lineage_id` in its stdout summary so operator scripts can capture it for later reuse. Operators implementing custom orchestration (Python, Go, etc. spawning the CLI) are responsible for tracking lineage_ids per agent instance — the kernel will not help them.

#### Escalation approval on the operator socket

`ApproveEscalation` is the most security-sensitive operator operation. Wire format:

```
Operator → Kernel: ApproveEscalation {
  op_token:          "<operator session token>",
  escalation_id:     "<uuid>",
  approval_scope:    { capability_class, max_uses, valid_for_seconds },
  operator_sig:      "<Ed25519 sig over (escalation_id || approval_scope bytes)>"
}
```

The kernel:
1. Validates `op_token`.
2. Checks `ApproveEscalation ∈ permitted_ops`.
3. Verifies `operator_sig` over `(escalation_id || approval_scope_canonical_bytes)`.
4. Writes `approval_tokens` row (Table 9) and `approval_proofs` row (Table 10).
5. Returns `EscalationApproved { approval_token }` to the operator CLI, which passes the token to the planner out-of-band.

The `operator_sig` is required even though the connection is already authenticated — it creates a durable `ApprovalProof` tied to the specific scope, independent of the session. This is what `recovery::reconcile` can verify after a crash.

#### Delegation grant signing domain on the operator socket

`GrantDelegation` requires `operator_sig` for the same reason `ApproveEscalation` does: a delegation is a long-lived authority artifact that may outlive the operator's session and is consumed across many gated actions until expiry. The kernel persists the operator's signature in `delegations.operator_signature` (Table 7 normative addition — see below) so that `recovery::reconcile` and any future audit-log replay can verify, post-crash, that the delegation row was authorised by the named operator and was not forged by a compromised kernel.

**Wire format:**

```
Operator → Kernel: GrantDelegation {
  op_token:            "<operator session token>",
  session_id:          "<uuid>",
  capability_class:    "<CapabilityClass enum variant name>",
  delegating_role_id:  "<RoleId>",
  expires_at:          <UnixSeconds u64>,
  scope_json:          "<inline JSON or null>",
  operator_sig:        "<64-byte hex Ed25519 sig over canonical signing domain — see below>"
}
```

**Signing domain (normative, byte-exact):**

The operator signs the SHA-256 digest of the canonical concatenation of all six functional fields, in the exact order below, with `0x00` as the field separator and length prefixes as noted. The `op_token` is **not** part of the signing domain (it authenticates the connection, not the artifact). This mirrors the §2.5.3 plan-signing pattern (Ed25519 over the SHA-256 digest, not the raw bytes — for auditability and constant-size signing input).

```
canonical_bytes = "RAXIS-V1-DELEGATION-GRANT" || 0x00
               || session_id (UTF-8 bytes of UUID hyphenated form, 36 bytes) || 0x00
               || capability_class (UTF-8 bytes of enum variant name, no quoting) || 0x00
               || delegating_role_id (UTF-8 bytes of role id) || 0x00
               || expires_at (8-byte little-endian u64 of absolute Unix seconds) || 0x00
               || scope_json_present (1 byte: 0x01 if scope_json is Some, 0x00 if None)
               || (if scope_json_present == 0x01:
                       u32_le(scope_json_byte_length) || scope_json_utf8_bytes
                   else: <empty>)

signing_input  = SHA-256(canonical_bytes)             // 32 bytes
operator_sig   = Ed25519Sign(operator_private_key, signing_input)   // 64 bytes
```

**Field-by-field rationale:**

- `"RAXIS-V1-DELEGATION-GRANT"` domain-separation prefix prevents a signature produced for one purpose (e.g. plan signing, escalation approval) from being replayed as a valid delegation grant. This is the standard cross-protocol replay defence; mirror prefixes exist for `"RAXIS-V1-PLAN"` (§2.5.3) and `"RAXIS-V1-ESCALATION-APPROVE"` (§2.5.5 above — to be added in a parallel cleanup; the pattern is the same).
- `session_id` in **UUID hyphenated form** (e.g. `550e8400-e29b-41d4-a716-446655440000`) — exactly 36 ASCII bytes. Not raw 16-byte UUID bytes, not the unhyphenated form. This matches the at-rest representation in `sessions.session_id TEXT`.
- `capability_class` as the **enum variant name** UTF-8 bytes (e.g. `"WriteSecrets"`), no JSON quoting, no surrounding whitespace. Matches the at-rest representation in `delegations.capability_class TEXT`.
- `delegating_role_id` as raw UTF-8 bytes of the operator-defined role id. No quoting. Matches `delegations.delegating_role_id TEXT`.
- `expires_at` as an **8-byte little-endian unsigned integer** — fixed width, byte-exact. The kernel reconstructs the same byte sequence by encoding `delegations.expires_at` (`INTEGER NOT NULL`) the same way before recomputing the signing input during `recovery::reconcile`.
- `scope_json_present` is a single discriminant byte that distinguishes "no scope" from "empty-string scope" — both must be unforgeable. When present, the JSON body's byte length is encoded as a 4-byte little-endian `u32` followed by the raw UTF-8 bytes of the JSON document **as the operator typed it** (no canonicalisation, no JSON re-serialisation). The operator CLI is the only canonical signer; the kernel signs nothing here. The kernel verifies what it received against what the operator's public key endorsed.

**Kernel verification (in `authority::delegation::grant_delegation` step 2.5 — between policy ceiling check and TTL bounds check):**

1. Reconstruct `canonical_bytes` from the request fields exactly as above.
2. Compute `signing_input = SHA-256(canonical_bytes)`.
3. Look up the operator's Ed25519 public key from `policy.operator_entry(authenticated_operator.fingerprint).public_key`.
4. `Ed25519Verify(pubkey, signing_input, req.operator_sig)`. Failure → `AuthorityError::DelegationSignatureInvalid` → `OperatorErrorCode::FAIL_DELEGATION_SIGNATURE_INVALID` (new code; see operator-error envelope addition in `peripherals.md` §3 below).
5. On success, the handler proceeds to step 3 (TTL bounds check), step 4 (uniqueness), and step 5 (insert + audit). The Phase-5 insert MUST persist `req.operator_sig` into the new `delegations.operator_signature` column added below.

**`delegations` table addendum (Table 7) — `operator_signature` column:**

The existing Table 7 DDL must add one column (or, equivalently, the next spec amendment that revises Table 7 must include it):

```sql
operator_signature  BLOB    NOT NULL,    -- 64-byte detached Ed25519 signature over
                                         -- the canonical GrantDelegation signing domain
                                         -- defined in §2.5.5 "Delegation grant signing
                                         -- domain". Persisted so recovery::reconcile and
                                         -- post-crash audit can re-verify the grant
                                         -- was operator-authorised. Distinct from the
                                         -- ApprovalProof signing path (§2.5.5
                                         -- "Escalation approval"); this signature is
                                         -- operator-produced, not kernel-produced.
```

**Post-crash verification (`recovery::reconcile`):** for every row in `delegations` whose `status IN ('Active', 'StaleOnNextUse')`, the recovery routine reconstructs `canonical_bytes` from the row's column values, recomputes the SHA-256, looks up the operator pubkey from the **current** policy bundle (a delegation whose granting operator was removed from `[[operators.entries]]` in a later epoch is treated as orphaned — see operator runbook), and runs `Ed25519Verify`. A row whose signature does not verify against any current operator pubkey is logged as `AuditEventKind::DelegationSignatureUnverifiable { delegation_id, expected_signer_unknown_in_current_policy: bool }` and the row's `status` is forced to `Revoked` (defensive — a kernel that cannot prove operator authorisation must not honour the delegation). This is the asymmetric mirror of how `ApprovalProof` records are verified.

---

### §2.5.6 — `[[gates]]` Normative Schema and `VerifierSpawnEnvelope`

#### `[[gates]]` in `policy.toml`

```toml
[[gates]]
gate_type        = "TestCoverage"          # matches GateType enum variant name (string)
verifier_command = "/usr/local/bin/raxis-verify-coverage"
max_wall_seconds = 120
max_memory_bytes = 536870912              # 512 MiB
network_allowed  = false                  # advisory in v1 (recorded for forward compat with v2 seccomp/namespace enforcement); see field rules below for v1 mitigations and limits

[[gates]]
gate_type        = "LintClean"
verifier_command = "/usr/local/bin/raxis-verify-lint"
max_wall_seconds = 60
max_memory_bytes = 268435456
network_allowed  = false
```

- `gate_type` — must match a `GateType` variant string as defined in `raxis-types/src/gate.rs`. Unknown values → `BOOT_ERR_UNKNOWN_GATE_TYPE` at startup.
- `verifier_command` — absolute path to the verifier executable. Must be readable and executable by the kernel OS user at startup; failure → `BOOT_ERR_VERIFIER_NOT_FOUND`.
- `max_wall_seconds` — kernel SIGKILL after this wall-clock duration. Minimum 1, maximum 600 (v1).
- `max_memory_bytes` — `setrlimit(RLIMIT_AS)` applied to the verifier subprocess. Minimum 64 MiB.
- `network_allowed` — **advisory only in v1**: the policy field is recorded in the `[[gates]]` stanza for forward compatibility and operator intent capture, but the v1 kernel does **not** enforce network isolation. The verifier subprocess runs under the same OS user as the kernel and can in principle issue `connect(2)` / `socket(2)` syscalls. v1 mitigations are limited to (a) `RLIMIT_NOFILE = 64` to cap the verifier's subsequent fd allocation (does **not** retroactively close inherited fds — for that see the FD-hygiene step in `kernel-core.md` `gates::verifier_runner::spawn_verifier` step 4), (b) `Command::env_clear()` so the verifier inherits no proxy / DNS / `HTTP_PROXY` / certificate-bundle env vars from the kernel, and (c) inability to inherit listening sockets via the FD_CLOEXEC + `closefrom` belt-and-suspenders. **None of this prevents an outbound connection** if the verifier issues raw socket syscalls and supplies its own DNS resolution. Full enforcement (Linux seccomp-bpf network filters, network namespace isolation, macOS sandbox profiles) is v2. Operators who need a hard guarantee in v1 should run the kernel under an OS-level network policy (firewall rules denying egress for the kernel's UID, or running on a host with no egress route) — there is no in-kernel substitute. **`network_allowed = true` is currently equivalent to `false` from an enforcement standpoint;** the field exists so v1 operator policies do not need to be rewritten when v2 enforcement lands.

#### `VerifierSpawnEnvelope` — normative env var set

These are the **only** env vars the kernel injects when forking a verifier subprocess. The verifier subprocess inherits no other env vars from the kernel process (environment is cleared before exec).

| Env var | Type | Content |
|---|---|---|
| `RAXIS_VERIFIER_TOKEN` | hex string | Short-lived `verifier_run_token` (32 bytes, hex). Verifier presents this when submitting a witness. Single-use; consumed on first valid `WitnessSubmission`. |
| `RAXIS_TASK_ID` | string | `task_id` of the task being evaluated. |
| `RAXIS_EVALUATION_SHA` | hex string | `head_commit_sha` the verifier must evaluate against. The submitted `WitnessRecord` must carry this SHA or be rejected with `EvaluationShaMismatch`. |
| `RAXIS_WORKTREE_ROOT` | absolute path | Planner session's `worktree_root` (from `task.session_id`). Verifier uses this as its working directory. |
| `RAXIS_KERNEL_SOCKET` | absolute path | Path of the kernel's planner UDS socket (witness intake endpoint). |
| `RAXIS_GATE_TYPE` | string | `GateType` variant name (e.g. `"TestCoverage"`). Verifier uses this to select its evaluation strategy. |
| `RAXIS_INITIATIVE_ID` | string | `initiative_id` for context; verifier may include in logs but must not use for auth decisions. |

No other env vars are injected. Verifier processes that require additional configuration must embed it in the `verifier_command` binary or read it from a config file at a predetermined path — they may not rely on env vars inherited from the kernel.

#### Verifier exit codes

| Exit code | Meaning | Kernel action |
|---|---|---|
| `0` | Witness submission was attempted (success or gate-fail — kernel checks `result_class` in the submitted `WitnessRecord`) | Consume `verifier_run_token`; record outcome |
| Non-zero | Verifier process failure (crash, OOM, exec failure) — not a gate failure | Log `AuditEventKind::VerifierProcessFailed { task_id, exit_code }`; do not consume token; re-queue for retry (up to `max_verifier_retries` from policy, default 2) |
| Timeout (SIGKILL) | Wall-clock limit exceeded | Treated as non-zero exit — same as verifier process failure |

A non-zero exit is **not** a gate failure. The gate outcome is determined only by the `result_class` field of a successfully submitted `WitnessRecord`. A verifier that cannot run does not fail the gate — it retries.

#### Alignment with `configuring-witnesses.md`

`configuring-witnesses.md` is the operator-facing tutorial — it shows worked examples of how to wire `[[gates]]` entries, write verifier scripts in shell/Rust/etc., and stage cross-platform witnesses. It is **not** a normative spec source; this `kernel-store.md` §2.5.6 (env vars + exit codes) and `peripherals.md` §3.3 (witness wire shape) together are the normative contract for the verifier surface. Where the two disagree on any of the four surfaces below, the normative spec wins and `configuring-witnesses.md` must be patched to match.

**The four surfaces `configuring-witnesses.md` covers, with their normative source:**

| Surface | What `configuring-witnesses.md` shows | Normative source | Precedence on conflict |
|---|---|---|---|
| Env-var inventory injected by `spawn_verifier` | Tutorial table at "Step 3" reproducing the seven `RAXIS_*` env vars | This section's env-var table (above) | This section wins |
| Verifier exit-code semantics | "Always `exit 0` after submission" pattern in every script example | This section's exit-code table (above) — `0` = submission attempted, non-zero = process failure (re-queued, not gate-fail) | This section wins |
| `WitnessSubmission` wire shape and `result_class` enum values | "Submit a `WitnessSubmission`" prose; result-class strings appear in the failure-modes table | `peripherals.md` §3.3 "Output: WitnessSubmission" + "result_class — canonical enum" | `peripherals.md` wins |
| IPC framing (length-prefixed bincode, not JSON) | One-line note "length-prefixed bincode framing per `peripherals.md` §3.3 — not JSON on the wire" | `peripherals.md` §3 opening normative note (bincode 2.x with `bincode::config::standard()`) | `peripherals.md` wins |

**As of v1, no known conflicts exist.** The tutorial has been swept against both normative sources after every iteration that touched §2.5.6 or §3.3 (most recently the `Error` → `Inconclusive` rename for `result_class`, which the tutorial does not reference, and the bincode-version pin to 2.x with `config::standard()`, which the tutorial cites by reference rather than restating). Engineers implementing the spec do **not** need to read `configuring-witnesses.md` to build a conformant kernel or verifier-host runtime — every behavioural contract is in the spec corpus (`kernel-store.md`, `peripherals.md`, `kernel-core.md`, `philosophy.md`, `cli-ceremony.md`, `planner-api.md`). Read `configuring-witnesses.md` only to learn the *operator workflow* (how to design gates for a real project, where to put scripts in the repo, how to layer per-OS gates).

**Authority on the precedence rule:** if a future patch introduces wording in `configuring-witnesses.md` that contradicts either normative source, the patch reviewer MUST treat the contradiction as a tutorial bug and fix `configuring-witnesses.md` — never the other way around.

---

### §2.5.7 — INV Amendments and Adversarial Assertion Matrix

#### INV-INIT-06 amendment

Original: *"The signed plan artifact is immutable after `approve_plan`. The `terminal_criteria`, task list, and DAG edges cannot be modified in v1."*

**Amendment (addendum, not replacement):** The kernel rejects any `IntentRequest` whose `task_id` is not present in the signed plan's task list with `FAIL_UNKNOWN_TASK { task_id }`, regardless of session state. This check runs at intent admission before path checks or gate evaluation. It closes the gap where a planner session could submit work against a task that was never part of the approved plan.

#### INV-SCHED-01 (new)

> **INV-SCHED-01:** `scheduler::admit` is called exclusively from `initiatives::lifecycle::approve_plan`. The intent handler (`handlers/intent.rs`) never calls `admit`. `admit`'s sole responsibility is inserting the task row and DAG edges into the store at plan approval time.

This formalises the Part 2.3 `admit.rs` amendment as a named invariant. Any code path that calls `admit` outside of `approve_plan` violates this invariant.

#### Adversarial assertion matrix

For each integration gap (Gaps 1–4), the following table shows what a malicious or buggy planner could attempt and which invariant blocks it.

| Gap | Adversarial attempt | Blocking invariant |
|---|---|---|
| **Gap 1 — Auth** | Replay a captured intent envelope with a prior sequence number | INV-01 (session token required) + sequence monotonicity check (`sequence_number` must be `prev + 1`) |
| **Gap 1 — Auth** | Forge a session token for a different planner session | INV-01: token is 256-bit CSPRNG; no derivation from `session_id`; brute-force infeasible |
| **Gap 1 — Auth** | Reuse a nonce across envelopes within the same session | `nonce_cache` uniqueness constraint (§2.5.1 Table 16); duplicate nonce → `UNAUTHORIZED` |
| **Gap 2 — Gates** | Submit a witness blob with a forged `evaluation_sha` (claiming a different commit) | INV-03: `verifier_run_token` binds to `(task_id, evaluation_sha)` at spawn time; mismatch → `EvaluationShaMismatch` |
| **Gap 2 — Gates** | Submit a planner-authored path manifest to influence claim requirements | INV-07: kernel derives required claims from VCS state (`vcs::diff`) independently; planner manifest is not read |
| **Gap 2 — Gates** | Probe rejection codes to reverse-engineer policy rules | INV-08: rejection codes are opaque to the planner (`FAIL_PATH_POLICY_VIOLATION`, not the specific rule that fired) |
| **Gap 3 — Budget** | Submit intents faster than budget allows to exhaust the lane | INV-02A: `budget::check_admission_cost` runs before any state mutation; rejection is non-terminal but the budget is not consumed |
| **Gap 3 — Budget** | Supply a low `estimated_cost` in the intent to pass the budget check cheaply | INV-02A: `estimated_cost` is kernel-computed from VCS-derived inputs and policy; no planner-supplied field reaches `consume_budget` |
| **Gap 4 — FSM** | Submit `CompleteTask` for a task owned by a different session | `task.session_id` FK check in the intent handler: the submitting session must match the bound session |
| **Gap 4 — FSM** | Submit `CompleteTask` for a task whose `task_id` is not in the signed plan | INV-INIT-06 amendment + INV-SCHED-01: unknown task → `FAIL_UNKNOWN_TASK`; task row never existed |
| **Gap 4 — FSM** | Land commits in the gap between the last accepted intent and `CompleteTask` to bypass path checks | INV-TASK-PATH-02: trailing segment `(evaluation_sha, CompleteTask.head_sha)` is topology-checked and path-checked at completion time |
| **Gap 4 — FSM** | Slip a merge commit into the trailing segment to amplify touched paths | INV-TASK-PATH-02 step 4a: `topology_check` runs on the trailing segment with no `IntegrationMerge` carve-out |



### §2.5.8 — VCS Path Scope Enforcement

#### Overview and enforcement model

Path scope enforcement constrains which filesystem paths a task may touch during execution. The kernel derives the set of touched paths from VCS history — the planner's self-declared path manifest is advisory only and is never the enforcement substrate (INV-07 already establishes this for claims; path scope enforcement applies the same principle to file access).

**Commit-then-enforce:** The kernel checks committed VCS history, not uncommitted edits. The planner's first intent on a task passes path enforcement trivially when `base_sha == head_sha` (nothing committed yet). This is a deliberate property of the model, not a bug. **INV-TASK-PATH-01 and INV-TASK-PATH-02 do not guarantee that uncommitted work is in-scope** — they guarantee that any committed and admitted range is in-scope, and that the final state at task completion is in-scope. Implementers must not read these invariants as "the kernel blocks edits before commit."

**Files changed by this section:**
- `specs/v1/kernel-store.md` (this file) — sole normative source for VCS path enforcement; §2.5.8 amendment and INV table additions.
- `specs/v1/kernel-core.md` — `src/vcs/diff.rs` module entry (Part 2.1) and `handlers/intent.rs` steps 2A/3A/7A (Part 2.3) are superseded by this section; implementers follow §2.5.8.
- No source code files are created by this spec. The spec is the normative contract; implementation maps 1:1 to these definitions.

---

#### Plan artifact fields (per `[[tasks]]` stanza)

These fields are part of the signed plan artifact. They are parsed at `approve_plan` time and stored in the kernel's in-memory `PolicyBundle`-equivalent plan representation. They are never re-read from disk after approval — the signed artifact is the authority.

```toml
[[tasks]]
task_id = "task-a"
# ... existing fields (depends_on, description, etc.) ...

# Glob patterns for paths this task is permitted to touch.
# Default: empty list — task may touch no paths (all intent path checks fail).
# Semantics: OR over all globs; a path is allowed if it matches any entry.
# Glob rules: * does not cross /; ** crosses directory boundaries.
# No other wildcard operators (no ?, no character classes, no negation).
# All paths are POSIX-normalized relative to worktree_root before matching.
path_allowlist = [
    "src/ipc/**",
    "src/ipc/handlers/new.rs",
]

# Whether to export this task's touched paths to direct DAG successors.
# Default: false. Opt-in required. See §effective_allow for semantics.
# When false: successors inherit nothing from this task automatically.
# When true: successors may touch the exported path set (filtered by
# path_export_globs if defined; full touched set otherwise).
path_export_to_successors = false

# Optional filter on what gets exported when path_export_to_successors = true.
# exported_paths(task) = accumulated_touched(task) ∩ match(path_export_globs)
# If omitted and path_export_to_successors = true: export = full touched set.
# If path_export_to_successors = false: this field is ignored.
path_export_globs = [
    "src/ipc/handlers/**",
]

# Bypass flag for path_allowlist enforcement. Default: false.
# When true: effective_allow(task_id) = universal set; all path checks pass.
# REQUIRES: the kernel emits PathScopeOverrideApplied audit event at
# approve_plan time. The signing tool (`raxis-cli policy sign`) must reject any
# plan containing path_scope_override = true without an explicit operator
# acknowledgement at sign time (Part 4 normative rule).
# See §path_scope_override for full semantics.
path_scope_override = false
```

**Blast-radius table for export settings:**

| `path_export_to_successors` | `path_export_globs` | Export to successors |
|---|---|---|
| `false` (default) | any | Nothing — zero export blast radius |
| `true` | absent | Full accumulated touched set (coarse; use with narrow `path_allowlist`) |
| `true` | defined | `accumulated_touched ∩ path_export_globs` (recommended) |

---

#### `vcs::diff` — normative specification

**Module:** `src/vcs/diff.rs`

**Purpose:** Compute `touched_paths` for a given `(base_sha, head_sha, worktree_root)` triple. This is the sole enforcement substrate for INV-07 (claims) and INV-TASK-PATH-01/02 (path scope). No other module may invoke git diff for enforcement purposes.

**Topology check — runs before diff computation:**

```
git -C <worktree_root> rev-list <base_sha>..<head_sha> --min-parents=2 --count
```

- **Commit set definition:** `base_sha..head_sha` (two-dot) — all commits reachable from `head_sha` but NOT reachable from `base_sha`. Base is excluded; head is included.
- **Predicate:** if result > 0 (any commit in the range has ≥ 2 parents), reject with `VcsDiffError::MergeCommitInRange { base_sha, head_sha, merge_count: u32 }`. Non-terminal at the intent handler — the planner must linearize (rebase or squash) and resubmit.
- This check runs before the diff. No diff is computed for a range that fails the topology check.

**Diff command (normative):**

```
git -C <worktree_root> diff <base_sha> <head_sha> --name-status --no-renames
```

- **`--name-status`:** outputs one line per changed path: `<status>\t<path>`.
- **`--no-renames`:** disables rename detection at the git level, regardless of `diff.renames` or `diff.renameLimit` git config. Renames always appear as `D <old_path>` + `A <new_path>`. The `-M`/`--find-renames` flag must never be passed in any codepath. `R` rows must never appear in the output (if they do, this is a kernel bug — fail with `VcsDiffError::UnexpectedRenameRow`).
- **Two-dot tree diff:** `git diff base_sha head_sha` compares the tree state at `base_sha` to the tree state at `head_sha`. This is graph-agnostic — no DAG traversal. The topology check (above) is a separate validation step.

**`touched_paths` construction from diff output:**

| Status code | Action |
|---|---|
| `A` (added) | Include path (column 2) |
| `M` (modified) | Include path (column 2) |
| `D` (deleted) | Include path (column 2) |
| `T` (type change) | Include path (column 2) — treated as modified |
| `C<score>` (copy) | Include **both** the source path (column 2) and destination path (column 3) in `touched_paths`. Conservative enforcement: both must be covered by `effective_allow`. If the source is not covered, the fact that the copy was sourced from it counts as access of that path. |
| `U` (unmerged) | Reject intent: `VcsDiffError::UnmergedPaths` |
| `X` / `B` (unknown/broken) | Reject intent: `VcsDiffError::InvalidDiffOutput` |
| `R` (rename) | Reject intent: `VcsDiffError::UnexpectedRenameRow` (invariant violation — `--no-renames` must have been omitted) |

**Post-processing:**
- Strip leading `./` from all paths.
- Assert no `..` components (reject: `VcsDiffError::PathTraversalDetected`).
- Assert all paths are relative (no leading `/`).
- Result: `Vec<PathBuf>` sorted lexicographically (deterministic; appears verbatim in audit records).

**`worktree_root` is per-session, set at `create_session` time.** For **planner** sessions it is supplied by the operator or orchestration layer — not by the planner at intent time and not from a global kernel config file. The intent handler reads **`session.worktree_root`** from the session row via `authority::get_session(session_id)` (**non-NULL** for planners). A planner-supplied path in an `IntentRequest` is ignored; the handler always uses the session-locked value. **Gateway/verifier** session rows store **NULL** here; they do not run `git -C` on their own session's `worktree_root`. **Planner** `worktree_root` is validated at `create_session` by running `git -C <worktree_root> rev-parse --git-dir`; failure returns `BOOT_ERR_VCS_ROOT`. Concurrent **planner** agent sessions operate on distinct non-NULL `worktree_root` paths (distinct `git worktree` directories backed by the same `.git` object store).

---

#### Merge ban — v1 constraint

**v1 rule:** The commit range `(base_sha, head_sha)` for any accepted intent must contain no merge commits. The kernel enforces this via the topology check above.

**Rationale:** `git diff base_sha head_sha` (two-dot tree diff) is content-complete — it correctly reflects what changed between two states, including content brought in by a merge. However, without the merge ban, a planner could incorporate a large merge from main that touches hundreds of paths outside the task's `path_allowlist`, making path enforcement unpredictable. The merge ban ensures that every path in `touched_paths` was explicitly committed by the planner's working branch.

**v1 planner requirement (non-integration intents):** Planner branches must use rebase or squash workflows. Merge commits are not permitted within an intent range for any intent kind other than `IntentKind::IntegrationMerge`. See §Integration merge carve-out for the approved merge shape. The operator must configure planner environments to enforce rebase workflows.

**v2 path:** When v2 adds kernel-managed worktree lifecycle, merge semantics can be revisited with explicit per-merge path attribution.

---

#### `effective_allow(task_id)` — normative algorithm

Computed at every intent admission and at `CompleteTask`. **Never cached between intents.** Predecessor completion between intents can widen the set — recomputation is required on every enforcement call.

```
fn effective_allow(task_id, store) -> GlobSet:
    task = store.get_task(task_id)

    // Layer 1: task's own path_allowlist (from signed plan)
    if task.path_scope_override:
        return UNIVERSAL_SET  // all path checks pass; audit event already emitted at approve_plan

    E = GlobSet::from(task.path_allowlist)

    // Layer 2: exports from completed direct DAG predecessors
    // "Direct" = direct depends_on edges only; no transitive lookup.
    // NOTE: path sets propagate transitively through exports by construction
    // (if A exports to B, and B exports to C, C sees A's paths via B's export).
    // "Direct deps only" controls which predecessor ROWS are queried —
    // not what those rows CONTAIN. Document this to prevent misreading.
    for pred_id in store.get_direct_predecessors(task_id):
        pred = store.get_task(pred_id)

        if pred.status != Completed:
            continue  // grant activates on Completed only.
                      // Aborted/Failed predecessors: grant never activates.

        if not pred.path_export_to_successors:
            continue  // default false; explicit opt-in required

        // exported_paths is pre-computed at pred's Completed transition
        // and stored in task_exported_path_snapshots. Query it directly.
        exported = store.get_exported_paths(pred_id)  // SELECT path FROM task_exported_path_snapshots WHERE task_id = pred_id
        E.exact_paths.extend(exported)  // stored as exact literal paths, NOT as globs

    return E

// E is a compound allow-set: glob_patterns ∪ exact_paths.
// Both must be checked together in a single function:
fn matches_allow(path, E: AllowSet) -> bool:
    // First: check glob patterns from task.path_allowlist
    if E.glob_patterns.any(|g| glob_match(g, path)):
        return true
    // Second: check exact literal paths from task_exported_path_snapshots
    if E.exact_paths.contains(path):
        return true
    return false
```

**Why the compound type matters:** `path_allowlist` entries are glob patterns (operators write `src/**`). Exported paths from `task_exported_path_snapshots` are concrete literal paths recorded from actual diffs (e.g. `src/ipc/handlers/new.rs`). Applying `glob_match` to a literal path string from the snapshot would only match if the path happened to look like a glob — which is not guaranteed and causes type confusion. `matches_allow` resolves both cleanly in one predicate.

**v1 has no non-predecessor path grants.** The earlier three-layer design discussed explicit `[[path_grants]]` (cross-task grants not tied to predecessor completion). These are **deferred to v3** — the `cross_initiative_path_grants` table in §v3.1. In v1, `effective_allow` has exactly two layers: the task's own `path_allowlist` and completed-predecessor exports. Any implementation adding a third grant layer in v1 is out of scope.

**Plan fields are loaded from the signed plan artifact, not from the `tasks` table.** The `tasks` DDL does not have `path_allowlist`, `path_export_to_successors`, `path_export_globs`, or `path_scope_override` columns. These fields are parsed from the approved plan artifact at `approve_plan` time and held in the kernel's in-memory plan representation (keyed by `initiative_id + task_id`). `effective_allow` reads from this in-memory structure, not from arbitrary task row mutation.

**Path coverage enforcement:**
```
fn check_paths(touched_paths, task_id, store) -> Result<(), PathPolicyViolation>:
    allow = effective_allow(task_id, store)
    violations = touched_paths.filter(|p| !matches_allow(p, allow))
    if violations.is_empty(): Ok(())
    else: Err(PathPolicyViolation { paths: violations })
```

---

#### Intent handler integration (`handlers/intent.rs` amendment)

**Supersession note:** §2.5.8 supersedes the existing `vcs/diff.rs` description in Part 2.3 (which specifies `git diff --name-only base..head` with no topology check and no `--no-renames`). The normative command is now `git diff base head --name-status --no-renames` (space-separated SHAs, not `..` syntax) with the topology check preceding it. **`git diff A B` (space) is the tree-comparison form — it compares tree states at A and B without graph traversal. This is intentional and must not be "fixed" to `A..B` range syntax, which has the same output for non-merge ranges but is conceptually different.** Part 2.3's `diff.rs` entry is superseded by §2.5.8 wherever it conflicts; implementers must follow §2.5.8.

The following steps are added to the intent admission flow in `handlers/intent.rs`, **after the ancestor check and before `touched_paths` computation.** Topology runs before diff — no diff is computed for a range that fails the topology check. No state mutation occurs before all checks complete.

**Revised step ordering (full flow):**
```
1. Auth (INV-01)
2. Ancestor check: is_ancestor(base_sha, head_sha) → HandlerError::InvalidShaRange
   2A. [NEW] Topology check: rev-list base..head --min-parents=2 --count
       → FAIL_INVALID_COMMIT_TOPOLOGY (non-terminal; no diff computed)
3. VCS diff: git diff base head --name-status --no-renames → touched_paths
   3A. [NEW] Path scope check: check_paths(touched_paths, task_id, store)
       → FAIL_PATH_POLICY_VIOLATION (non-terminal)
4. Task binding
5. Gate evaluation (INV-07)
6. Budget reservation
7. State transition
   7A. [NEW] INSERT INTO task_intent_ranges (same store transaction as step 4 task binding; see Step 7A below)
8. Audit record
```

**Step 2A — topology check (new):**
Run `vcs::diff::topology_check(base_sha, head_sha, session.worktree_root)`. On `VcsDiffError::MergeCommitInRange { merge_count }` → return `IntentResponse::Rejected { reason: FAIL_INVALID_COMMIT_TOPOLOGY }`. Log `AuditEventKind::IntentRejected { task_id, reason: TopologyViolation { merge_count } }`. Task remains in current state. **Exception: integration merge intents** — see §Integration merge carve-out below.

**Step 3A — path scope check (new):**
Run `check_paths(touched_paths, task_id, store)`. On `PathPolicyViolation` → return `IntentResponse::Rejected { reason: FAIL_PATH_POLICY_VIOLATION }`. Task remains in current state. Non-terminal.

**Step 7A — record accepted range (new):**
On successful admission, inside the **same store transaction** as **step 4 — Task binding** (Part 2.4 `handlers/intent.rs`, bullet **Bind or refresh SHA fields**): the handler already issued `UPDATE tasks SET session_id = ..., evaluation_sha = req.head_commit_sha, base_sha = req.base_commit_sha, submitted_claims_json = ...` for this intent. **Step 7A does not issue a second `UPDATE` to `evaluation_sha`.** In that same transaction, append:
```sql
INSERT INTO task_intent_ranges (task_id, base_sha, head_sha, accepted_at)
VALUES (?, ?, ?, unixepoch())
```
**Normative:** After commit, `tasks.evaluation_sha` for this `task_id` **must equal** the `head_sha` column in the new `task_intent_ranges` row (both come from the accepted `IntentRequest`).

If `SQLITE_CONSTRAINT_PRIMARYKEY` (same `head_sha` already accepted for this task): treat as idempotent retry, return prior accepted response, do not re-execute.

**When no row is inserted because `touched_paths` is empty** (the diff for `(base_sha, head_sha)` on that intent has nothing to record — same rule as the edge-case table: no `task_intent_ranges` row written): if the handler still performed the step-4 binding `UPDATE`, `evaluation_sha` reflects that intent’s `head_commit_sha`; if the handler rolls back before binding, `evaluation_sha` is unchanged — §2.5.8 CompleteTask trailing-segment rules use whatever `evaluation_sha` is visible after the last committed binding.

---

#### CompleteTask path check (`handlers/intent.rs` — `IntentKind::CompleteTask` branch)

**Alignment note:** `CompleteTask` is submitted as `IntentRequest { intent_kind: IntentKind::CompleteTask, base_sha, head_sha, ... }` via the same IPC path as regular intents. It is handled in `handlers/intent.rs` as a special branch on `intent_kind`, not a separate IPC message. `head_sha` on the `CompleteTask` intent is the final committed state the planner is asserting as its work product. The path check unions diffs from **`task_intent_ranges`** with an optional **trailing segment** from **`tasks.evaluation_sha`** to this `head_sha` when they differ — there is no separate `final_head_sha` field.

**`base_sha` disposition on a `CompleteTask` request:** The handler **ignores** `req.base_sha` entirely. The kernel does not validate it, compare it against `tasks.evaluation_sha`, or use it as a diff anchor. The authoritative trailing-segment base is always `tasks.evaluation_sha` read from the store (step 1 below) — not any planner-supplied field. This is intentional: if the kernel accepted a planner-supplied `base_sha` as the diff anchor, the planner could narrow the trailing segment to exclude commits it had already landed. Implementers **must not** add a `base_sha == tasks.evaluation_sha` consistency check; the planner may legitimately supply any value (or the IPC schema default) in that field for `CompleteTask` intents.

**Topology scope (stored ranges vs completion-time checks):** Each `(base_sha, head_sha)` pair in **`task_intent_ranges`** was already subject to **`topology_check`** at **intent admission** (§2.5.8 step **2A**), except **`IntentKind::IntegrationMerge`** per the carve-out. The CompleteTask path check **does not** re-run **`topology_check`** on those stored pairs. At completion, **`topology_check` runs only** on the **trailing** segment (**step 4a**, `H_bind` → `req.head_sha`). The **`CompleteTask` request's** `base_sha` field is **ignored** (see above); `head_sha` is used only as the trailing segment endpoint — neither field receives a topology pass as a standalone range.

**Path check at completion:**
1. Load `tasks.evaluation_sha` as `H_bind` for this `task_id` **before** any mutation that would advance the task toward `Completed` — same row read as used elsewhere for witness binding (may be SQL `NULL` only before the first intent binding on this task).
2. `SELECT base_sha, head_sha FROM task_intent_ranges WHERE task_id = ?` — load all accepted intent ranges for this task.
3. Initialize `full_touched_paths = {}`. For each range from step 2: run `vcs::diff::compute(base_sha, head_sha, session.worktree_root)` and union the resulting path sets into `full_touched_paths`. (`session.worktree_root` is loaded from the session row as in all intent processing.)
4. **Trailing segment (closes the gap after the last recorded range):** Let `req.head_sha` be the `CompleteTask` request's `head_sha`. If `H_bind` is NULL or `req.head_sha = H_bind` (commit OID equality), skip the rest of this step (empty trailing diff). Otherwise:
   - **4a. Topology (same rule as step 2A):** Run `vcs::diff::topology_check(H_bind, req.head_sha, session.worktree_root)`. On `MergeCommitInRange` → return `IntentResponse::Rejected { reason: FAIL_INVALID_COMMIT_TOPOLOGY }` (non-terminal; task stays `Running`). **No `IntegrationMerge` carve-out** — the trailing gap is never an integration-merge intent.
   - **4b. Diff:** Union into `full_touched_paths` the `touched_paths` from `vcs::diff::compute(H_bind, req.head_sha, session.worktree_root)`.
   - **If step 2 returned no rows** and `H_bind` is NULL: `full_touched_paths` remains `{}` — path check passes vacuously (no kernel-bound tip yet; commit-then-enforce still means uncommitted work is not checked). If there are no rows but `H_bind` is not NULL, steps 4a–4b still run when `req.head_sha ≠ H_bind`.
   - **Invariant:** `tasks.evaluation_sha` is set in **step 4 — Task binding** on every accepted range intent (Part 2.4); **step 7A** only adds the `task_intent_ranges` row in the **same transaction**, matching that `head_sha`. **`IntentKind::CompleteTask`** uses the separate branch below and does not substitute for the trailing segment unless an explicit future amendment records CompleteTask ranges in `task_intent_ranges`. The trailing segment covers extra commits landed **without** a new accepted intent that committed step 4+7A before `CompleteTask`.
5. Recompute `effective_allow(task_id, store)` at completion time (same algorithm as intent admission; predecessor completion between last intent and CompleteTask may have widened the set).
6. Run `check_paths(full_touched_paths, task_id, store)`.
7. On `PathPolicyViolation` → return `IntentResponse::Rejected { reason: FAIL_PATH_POLICY_VIOLATION }`. Log `AuditEventKind::IntentRejected { task_id, reason: PathPolicyViolation }`. Task remains in `Running`. **Non-terminal:** planner reverts the out-of-scope commits, pushes a new `head_sha`, resubmits the `CompleteTask` intent with the corrected `head_sha`. If the planner never satisfies the path check, the task remains `Running` until **normal termination elsewhere**: e.g. operator **`task abort`** (`OperatorAbort`), planner submits **`IntentKind::ReportFailure`** → **`Running` → `Failed`** (Part 2.4 §4.3 task transition table), or a successful retry of **`CompleteTask`** → **`Completed`**. There is **no automatic task-level deadline** in v1 — this is the design (`kernel-core.md` Part 2.4 INV-INIT-09 + §4.5 "Task lifetime bounds (no v1 task-level deadline)"); `deadline_at` is not a field on `initiatives` or `tasks` in the current DDL by intent. Lane budget exhaustion (`max_cost_per_epoch` → `FAIL_BUDGET_EXCEEDED`) is the practical bound on how long a planner stuck in this loop can keep submitting; see the §4.5 "Task lifetime bounds" table for the full enumeration of v1 lifetime bounds.
8. On success: proceed with normal `CompleteTask` branch flow (gate check, `Running → Completed` transition).

**Export snapshot — computed inside the `Running → Completed` transaction:**
```
if task.path_export_to_successors:
    exported = full_touched_paths  // already computed in steps 3–4
    if task.path_export_globs is not empty:
        exported = exported.filter(|p| task.path_export_globs.any(|g| glob_match(g, p)))
    INSERT INTO task_exported_path_snapshots (task_id, path)
    VALUES (task_id, ?) for each path in exported
    -- On SQLITE_CONSTRAINT_PRIMARYKEY: ignore (idempotent; task already completed)
```

The snapshot insert is part of the same store transaction as the `tasks.status = Completed` update. Both commit together or both roll back. A crash between the status update and the snapshot insert is impossible under SQLite's single-writer atomic transaction model.

---

#### `path_scope_override` semantics

**Definition:** When `path_scope_override = true` on a task in the signed plan, `effective_allow(task_id)` returns the universal set. All intent path checks and the CompleteTask path check pass unconditionally for that task. The `path_allowlist` field is ignored for enforcement (it may still be present for documentation purposes).

**Audit event at `approve_plan`:** The kernel emits `AuditEventKind::PathScopeOverrideApplied { initiative_id, task_id, operator_id }` for every task with `path_scope_override = true`, inside the `approve_plan` transaction. This resolves the offline-signing ambiguity: the audit event is emitted by the kernel when it processes the plan (always online), not at signing time. Offline signing workflows are permitted — the audit event is always created by the kernel, not the signing tool.

**Signing tool rule (Part 4 normative):** `raxis-cli policy sign` must require explicit operator acknowledgement (interactive prompt or `--allow-path-override` flag) before signing any plan containing `path_scope_override = true`. This is a signing-pipeline gate, not a kernel-runtime gate. The kernel honors the signed plan and emits the audit event regardless.

---

#### Planner feedback model — IPC rejection codes and remediation

**INV-08 is fully preserved for path policy rejections.** The IPC response for a path policy violation is:

```
IntentResponse::Rejected { reason: PlannerErrorCode::FAIL_PATH_POLICY_VIOLATION }
-- (for both regular intent admission and CompleteTask branch)
```

Both are opaque coarse codes. The kernel does not expose which specific paths failed `effective_allow`, which globs are in the allowlist, or any other policy internals. This matches the INV-08 contract exactly.

**How the planner learns to remediate without policy exposure:**

The planner does not need the kernel to reveal which paths are out of scope. The planner already has complete knowledge of what it committed — its own VCS working state is not hidden from it. Remediation is a function of what the planner knows about itself, not what the kernel tells it about policy.

The remediation strategy is delivered as a **machine-readable API spec included in the planner's system prompt** at session initialization. This spec teaches the planner how to interpret each rejection code and what corrective action to take, without referencing any specific policy value:

```
FAIL_PATH_POLICY_VIOLATION (intent admission):
  The kernel's VCS-derived diff of your last committed range contained
  one or more paths not covered by your task's effective path scope.
  Remediation: inspect your most recent commits (git log base_sha..head_sha
  --name-only), identify which paths you should not have touched for this
  task, revert those changes, commit the revert, and resubmit the intent
  with the new head_sha.

FAIL_PATH_POLICY_VIOLATION (CompleteTask):
  The union of all paths touched across this task's accepted intent ranges,
  plus any commits from the kernel-bound tip (evaluation_sha) to your
  CompleteTask head_sha, contains one or more paths not in scope at completion time.
  Remediation: inspect git log across those ranges and the trailing segment,
  identify and revert out-of-scope changes, and resubmit CompleteTask.

FAIL_INVALID_COMMIT_TOPOLOGY:
  Your intent range contains one or more merge commits (for non-integration intents).
  Remediation: rebase or squash your working branch to a linear history
  and resubmit the intent with the rebased head_sha.
  Note: this code does not apply to IntentKind::IntegrationMerge —
  integration merge intents use an approved merge shape (see kernel
  documentation for the five required predicates).
```

**Why this is the right design:**
- INV-08 stays fully intact — the kernel never exposes policy structure through its protocol.
- The planner's diagnostic capability comes from its own VCS access, not from kernel leakage.
- The API spec is a Part 3 contract (Planner binary specification) — it defines the machine-readable rejection code taxonomy that operators embed in planner system prompts. It is version-controlled alongside the kernel spec and must stay synchronized with the `PlannerErrorCode` enum.
- The system prompt API spec is a forward reference to Part 3 (not yet written). **Part 3 must define the full `PlannerErrorCode` taxonomy, remediation guidance for each code, and the canonical format operators use to include this spec in planner session initialization.**

---

#### INV-TASK-PATH-01 — Intent admission

> **INV-TASK-PATH-01:** The kernel admits an intent if and only if every path in `touched_paths(intent)` — computed by the kernel from `(base_sha, head_sha)` via `vcs::diff`, not from any planner-declared manifest — is a member of `effective_allow(task_id)` at the time of admission. An intent failing this check is rejected non-terminally; the task remains in its current state. `effective_allow` is recomputed on every intent call and is not cached between calls.

---

#### INV-TASK-PATH-02 — Task completion

> **INV-TASK-PATH-02 — Task completion:** The kernel does not transition a task to `Completed` unless every path in the union of `touched_paths` across all accepted intent ranges for the task **and** the trailing segment from `tasks.evaluation_sha` to the `CompleteTask` intent's `head_sha` (when they differ) — with that trailing segment passing **`topology_check`** (same rule as §2.5.8 step 2A, no integration carve-out) before **`vcs::diff`** — is a member of `effective_allow(task_id)` recomputed at completion time. Path coverage is a necessary condition for completion; all other completion predicates (gate checks, valid `CompleteTask` intent shape, initiative-level rules) remain independently required. A `CompleteTask` intent failing the path check is rejected non-terminally; the task remains in `Running`.

---

#### Edge case reference table

| Case | Enforcement behaviour |
|---|---|
| First intent, `base_sha == head_sha` | `touched_paths = {}` (empty diff). Path check passes vacuously at admission. No `task_intent_ranges` row written — empty diff has nothing to record. If `tasks.evaluation_sha` was still advanced to that commit on binding, a later `CompleteTask` with a **strictly newer** `head_sha` applies the **trailing segment** (step 4 above); if `evaluation_sha` stays NULL until a non-empty range exists, `CompleteTask` with no recorded ranges and NULL `H_bind` still yields `full_touched_paths = {}` (vacuous). Gates remain the mechanism for requiring substantive committed work when path closure is empty. |
| Rename `src/old.rs → src/new.rs` | `vcs::diff` with `--no-renames` emits `D src/old.rs` + `A src/new.rs`. Both paths are checked via `matches_allow`. If only `src/new.rs` is covered, `src/old.rs` is a violation. Operators renaming files must ensure both source and destination paths are in the allowlist. |
| Copy (`C<score>`) row | Both the source path (column 2) and the destination path (column 3) are included in `touched_paths`. Conservative enforcement: both must be in `effective_allow`. If only the destination is allowed, the source's inclusion is a violation. |
| Merge commit in range (non-integration) | Topology check fires before diff. `FAIL_INVALID_COMMIT_TOPOLOGY`. Planner must rebase and resubmit. |
| Merge commit only in the CompleteTask trailing segment (`evaluation_sha`..`CompleteTask.head_sha`) | §2.5.8 CompleteTask step **4a** runs `topology_check` on that segment (no `IntegrationMerge` carve-out). `FAIL_INVALID_COMMIT_TOPOLOGY`; task stays `Running`. |
| Integration merge (approved shape) | Topology check is bypassed for `IntentKind::IntegrationMerge`. See §Integration merge carve-out. |
| Predecessor `Aborted` (not `Completed`) | Grant never activates. `effective_allow` does not include aborted predecessor's exports. |
| Concurrent successors with shared predecessor exports | Both successors see the same `task_exported_path_snapshots` rows. Both may touch those paths. No mutual exclusion — concurrent write conflicts are git conflicts the planner must resolve. Path scope enforcement does not imply write exclusion (see §v3.1 for future cross-session write exclusion). |
| `path_scope_override = true` | `effective_allow` = universal set. Both INV-TASK-PATH-01 and INV-TASK-PATH-02 pass unconditionally. `PathScopeOverrideApplied` audit event written at `approve_plan`. Signing tool must require `--allow-path-override` acknowledgement; bare `**` without this flag must be rejected at signing time (Part 4 normative rule). |
| `CompleteTask` path check fails | Task stays `Running`. Planner reverts out-of-scope commits, resubmits `CompleteTask` with corrected `head_sha`. Otherwise the task can still leave `Running` via operator **`task abort`**, planner **`IntentKind::ReportFailure`** (Part 2.4 §4.3 task transition table: `Running` → `Failed`), or successful **`CompleteTask`** after remediation; there is no `deadline_at` on tasks/initiatives in v1 DDL by design (`kernel-core.md` Part 2.4 **INV-INIT-09** + §4.5 "Task lifetime bounds"). The seven practical lifetime bounds — most notably lane budget exhaustion via `max_cost_per_epoch` — are enumerated in `kernel-core.md` §4.5; v2 will add `deadline_at` columns and the corresponding sweep. |
| `path_export_to_successors = false` (default) | No rows written to `task_exported_path_snapshots` at completion. Successors' `effective_allow` is unaffected. Zero export blast radius. |
| Unmerged paths (`U` status in diff) | `VcsDiffError::UnmergedPaths` → `FAIL_INVALID_DIFF`. Non-terminal. Planner must resolve conflicts and resubmit. |

---

> **§2.5.8 complete.** Supersession summary (normative):
>
> - **`kernel-core.md` Part 2.3 `vcs/diff.rs`:** §2.5.8 normative command (`git diff base head --name-status --no-renames`) supersedes the earlier `--name-only` invocation. Implementers follow §2.5.8.
> - **`kernel-core.md` Part 2.3 `handlers/intent.rs`:** Steps 2A (topology check), 3A (path scope check), and 7A (`task_intent_ranges` insert) are added by §2.5.8 and supersede any conflicting Part 2.3 text. Implementers follow §2.5.8.
> - **Invariants:** INV-TASK-PATH-01 and INV-TASK-PATH-02 are normative here in §2.5.8. `philosophy.md` INV table references §2.5.8 as the authoritative source for these two invariants.
> - **Integration merge carve-out:** Defined immediately below in §Integration merge carve-out.

---

#### Integration merge carve-out — approved merge shape

**Problem:** The general merge ban (`FAIL_INVALID_COMMIT_TOPOLOGY` for any range containing a merge commit) conflicts with the existing Multi-Agent VCS Design Note (Part 2.3), which explicitly supports `IntentKind::IntegrationMerge` where `head_sha` IS a merge commit. Both cannot be v1 truth; the carve-out resolves this by defining the approved merge shape and its topology/diff semantics precisely.

**Approved merge shape (v1):** A merge commit is permitted in an intent range if and only if:
1. The intent has `intent_kind = IntentKind::IntegrationMerge`.
2. `head_sha` is the merge commit itself (not a descendant).
3. `base_sha` is the policy-pinned main tip from session creation (locked in `sessions.base_sha` at `create_session` time for integration sessions), with paired **`sessions.base_tracking_ref`** per §2.5.1 Table 4 for stale-base re-resolution.
4. `base_sha` is a true ancestor of `head_sha` (`is_ancestor(base_sha, head_sha)` = true).
5. `head_sha` has exactly 2 parents (binary merge; octopus merges are not permitted in v1).

**Topology check bypass:** The topology check (`rev-list base..head --min-parents=2 --count > 0`) is **not applied** for `IntentKind::IntegrationMerge`. The integration merge is the one permitted merge shape. The handler checks the 5 predicates above directly instead.

**Stale-base check (preserved from Part 2.3):** Before accepting an integration merge intent, the handler additionally checks `locked_base == current_main_HEAD`. **`locked_base`** is `sessions.base_sha`. **`current_main_HEAD`** is the commit OID obtained by **re-resolving `sessions.base_tracking_ref` in `session.worktree_root` at admission time** (same peel-to-commit semantics as at `create_session` — §2.5.1 Table 4 **sessions** binding paragraph). **Normative:** `sessions.base_sha` and `sessions.base_tracking_ref` must both be non-NULL for any session that may submit `IntegrationMerge`; otherwise stale-base is undefined and the handler must reject. If main has advanced since session creation (equality fails), return `HandlerError::StaleIntegrationBase`. The planner must rebase the integration branch onto the new main HEAD and resubmit. This check is independent of the topology check and runs before it.

**Diff semantics for integration merge:**

```
git -C <session.worktree_root> diff <base_sha> <head_sha> --name-status --no-renames
```

Same normative command as all other intent types. `base_sha` is the policy-pinned main tip; `head_sha` is the merge commit. This two-dot tree diff gives the full union of all changes from all contributing agent branches relative to the locked base — which is the intended enforcement domain for integration intents. The merge commit's graph structure is irrelevant to the path enforcement check; only the tree diff matters.

**Why two-dot is correct for integration merge:** `git diff base merge_commit` (two-dot, tree comparison) correctly captures the full union of all agent-branch changes. Three-dot (`base...merge_commit`) would compute the symmetric difference from the merge-base between base and merge_commit, which is the same as two-dot when `base` is a direct ancestor — but the two-dot intent is clearer and consistent with all other intent types. The ancestor check (predicate 4 above) ensures base is always a true ancestor, so two-dot and three-dot are equivalent — but two-dot is used for consistency.

**Path enforcement for integration merge:** Once `touched_paths` is computed from the two-dot diff, `check_paths(touched_paths, task_id, store)` runs with exactly the same `effective_allow` algorithm as all other intent types. The integration task's `path_allowlist` in the signed plan should cover the union of all contributing agent branches' allowlists, or use a broader scope appropriate for integration.

**task_intent_ranges for integration intents:** The `(base_sha, head_sha)` pair is recorded in `task_intent_ranges` on acceptance, same as all other intent types. The merge commit's `head_sha` serves as the unique key. At CompleteTask, `full_touched_paths` includes the integration merge range alongside all prior intents for the task and any §2.5.8 trailing segment.

**Part 2.3 alignment:** The "Integration merge commit rule" in the Multi-Agent VCS Design Note (Part 2.3, lines 1712–1720) describes the same semantics. §2.5.8 is the normative authority; Part 2.3 is the design context. Where they conflict (e.g. the old `--name-only` diff command vs `--name-status --no-renames`), §2.5.8 wins.

---

#### `worktree_root` — per-session model

See §`vcs::diff` normative specification above — specifically the `worktree_root` paragraph immediately following the diff command. **Planner** sessions: non-NULL path, set at `create_session`, read by the intent handler via `authority::get_session`. **Gateway / Verifier** sessions: **SQL NULL** on their own row (§2.5.1 Table 4); verifier spawn and witness recheck still use the **planner** session’s `worktree_root` from `task.session_id`.


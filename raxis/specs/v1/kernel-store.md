# RAXIS — Part 2 (Store): Closing Gaps — Schema, Signing, Keys, and Operator Auth

> **Scope:** Part 2.5 — store DDL (all 19 `kernel.db` tables: 16 core + Tables 17–18 VCS path scope + Table 19 policy_epoch_history, §2.5.1), VCS path scope enforcement (§2.5.8, **normative**), audit log transaction boundary (§2.5.2), plan artifact signing contract (§2.5.3), key inventory (§2.5.4), operator authentication protocol (§2.5.5), `[[gates]]` normative schema (§2.5.6), INV amendments (§2.5.7).
>
> **Authority:** When table name, column name, or column type in Part 2 Core prose conflicts with the canonical DDL here, this file wins for representation details. When this file is silent on FSM semantics, Part 2 Core wins.
>
> **Navigation:** [README](../../README.md) | [Part 2 Core](kernel-core.md) | [Part 3](peripherals.md) | [Part 4](cli-ceremony.md)

---

## Part 2.5 — Closing Gaps: Store Schema, Signing Contracts, Key Inventory, and Operator Authentication

Part 2.5 provides the normative specifications that are referenced throughout Parts 2.1–2.4 but were not yet formally written in one place. It also resolves conflicts surfaced by writing the DDL (primarily the task lifecycle story between Part 2.3 and Part 2.4) and establishes the conventions — table names, column types, directory paths, environment variables — that implementers use as ground truth when the spec prose and DDL diverge.

**Resolution rule:** When a table name, column name, or column type in Parts 2.3–2.4 prose conflicts with the canonical DDL in §2.5.1, the DDL wins for representation details. When the DDL is silent on FSM semantics (state transitions, actor rules, evaluation order), Parts 2.3–2.4 win.

> Part 2.5 is structured as seven sections, written incrementally with review between each.
> §2.5.1 — Store DDL and isolation model: database file layout, runtime pragmas, canonical schema for all 19 kernel tables (Tables 1–16 core + Tables 17–18 VCS path scope + Table 19 policy_epoch_history), indexes, and migration inventory.
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
| `lifecycle::approve_plan` (+ `scheduler::admit_in_tx` it calls per task) | `initiatives`, `tasks`, `task_dag_edges`, `signed_plan_artifacts`, audit-pointer | `kernel-core.md` §4.6 + Part 2.3 admit |
| `policy_manager::advance_epoch` Phase 1 | `delegations` (sweep), `sessions` (prompt-cache invalidation), `policy_epoch_history` (Table 19 insert), audit-pointer | `kernel-core.md` §`policy_manager.rs`, INV-POLICY-01 below |
| `handlers/intent` accepting an intent | `tasks` (intent fields + state), `task_intent_ranges`, `lane_budget_reservations`, audit-pointer | `kernel-core.md` Part 2.3 §`handlers/intent.rs` "Budget check and reservation" + `transition_task` call (which is itself bound by INV-INIT-04) |
| `gates/witness_index::write` | `witness_records`, `verifier_run_tokens` (consumed), audit-pointer | Part 2.3 §witness_index.rs |
| `recovery::reconcile_tasks` (+ `expire_orphan_verifier_tokens` it calls) | `tasks` (sweep to BlockedRecoveryPending), `verifier_run_tokens` (orphan expiry), audit-pointer | `kernel-core.md` §recovery.rs, INV-INIT-08 |

For each operation in this table, splitting writes across two transactions or two mutex acquisitions is a spec violation: another tokio task could interleave between them and observe an inconsistent intermediate state (e.g. for `advance_epoch`, see new delegations marked stale but old `policy_epoch_history` MAX still in place, allowing a stale-policy escalation to slip through). Any future kernel operation that needs to compose multiple table writes atomically MUST be added to this table as part of its spec PR.

**Deferred-FK pattern for intra-plan references.** `lifecycle::approve_plan` issues `PRAGMA defer_foreign_keys = 1;` immediately after `BEGIN`. This is required because plans frequently declare dependent tasks (`t2.predecessors = ["t1"]`) and the per-task admit pass inserts task rows + edge rows interleaved — at the moment the edge `(t1, t2)` is inserted while admitting `t2`, both `t1` and `t2` already exist as task rows but the FK on `task_dag_edges.predecessor_task_id → tasks(task_id)` would fail under default (immediate) FK mode if predecessors were inserted later in the same statement batch. Deferred-FK is per-transaction and reverts on COMMIT/ROLLBACK; cross-table integrity is still validated at COMMIT, so a plan that references a non-existent task ID still causes the entire `approve_plan` to roll back.

**Implementation pointer.** The `approve_plan` flow is:
1. Acquire the `Store` mutex (one acquisition for the entire operation).
2. Pre-tx reads (initiative state, plan bytes, plan signature) — these may legitimately fail before any write happens.
3. `BEGIN` → `PRAGMA defer_foreign_keys = 1` → conditional UPDATE on `initiatives` (re-checks Draft inside the tx to close the TOCTOU window).
4. For each `PlanTask` parsed from the plan TOML: call `scheduler::admit_in_tx(&tx, task, policy_epoch)` which (a) runs `dag::detect_cycle_in` against the in-progress edge set, (b) inserts the task row, (c) inserts that task's edges via `dag::insert_edges_in`.
5. `COMMIT` → drop the mutex → emit the `PlanApproved` audit record (per §2.5.2 audit-after-commit ordering).

Audit emission **after** commit is mandatory under V1 single-event ordering: an audit record for an operation that did not commit would corrupt the chain. The kernel routes every audit emission through the `raxis-audit-tools::AuditSink` trait held on `HandlerContext` (production wiring is `FileAuditSink` over `<data_dir>/audit/segment-000.jsonl`; tests inject `FakeAuditSink`). Direct `eprintln!`-based audit emission is forbidden — the only acceptable use of `eprintln!` in handler code is fallback logging when an `AuditSink::emit` call itself fails (a §2.5.2 "SQLite committed, JSONL not appended" gap that `recovery::reconcile` repairs under V1; under V2.1, `recovery::reconcile_advisory` resolves it without being mandatory — see `v2/audit-paired-writes.md §6`).

> **V2.1 paired-class handlers** route through the extended `AuditSink`
> trait (`emit_pending`, `emit_confirmed_for`, `emit_rolled_back_for`)
> per `v2/extensibility-traits.md §5`. The "after commit" rule is
> replaced by a three-phase ordering for paired-class events:
> `emit_pending` (fsync) → `BEGIN IMMEDIATE` … `COMMIT` → augmented
> existing-kind emission via `emit_confirmed_for` (fsync). The ordering
> details and crash-window resolutions live in
> `v2/audit-paired-writes.md §2.3` and §7.

**Policy epoch atomicity invariant (INV-POLICY-01).** `policy_manager::advance_epoch` Phase 1 (the SQL-write phase) writes to `delegations`, `sessions`, `policy_epoch_history`, and the audit-pointer table inside one transaction held under one INV-STORE-01 mutex acquisition. Phase 2 (in-memory `ArcSwap` swaps for `ctx.policy` and `ctx.allowlist_cache`) runs only after Phase 1 commits, and is infallible. Phase 3 (gateway `EpochAdvanced` signal) is best-effort and does not affect the success of the advance. The full phase contract — including failure modes for each phase, audit events for both rejection (`PolicyAdvanceRejected`) and post-`BEGIN` failure (`PolicyAdvanceFailed`), and crash semantics (which reduce to single-transaction commit/no-commit) — is normative in `kernel-core.md` §`policy_manager.rs`. A partially-applied epoch advance is structurally impossible: either all four SQL writes commit and the in-memory caches are then swapped, or the transaction rolls back and the kernel observably remains at the old epoch with no audit `PolicyEpochAdvanced` row.

---

#### §2.5.1.1 — Concurrency-bug catalogue (INV-STORE-02 enforcement scenarios)

The two atomicity invariants above (INV-STORE-01, INV-STORE-02) are
not self-enforcing — code can violate them silently. This sub-section
enumerates every concurrency-bug **class** the kernel has had to
defend against, with the canonical adversarial scenario for each so
future PRs can be reviewed against a concrete failure mode rather
than just an abstract rule. Each class is listed with: (a) the
pattern, (b) the step-by-step interleaving that breaks an invariant,
(c) the canonical fix, (d) the regression-test home.

These scenarios are **mandatory reading** for any PR that touches a
multi-write kernel path. Each enforcement-site listed below carries
an `// INV-STORE-02 (§2.5.1.1)` crossref comment so a reviewer can
trace from code back to this catalogue.

##### Pattern A — Split mutex acquisition for a single logical write

**Failure shape:** A function performs check (read) and mutate (write)
under two separate `Store::lock_sync()` calls, releasing the mutex
between them. A second tokio task can interleave between the two
acquisitions.

**Canonical scenario — budget TOCTOU (`scheduler::budget`):**

1. **t=0:** Task A's intent handler runs `check_budget(lane=L,
   cost=80, …)`. Inside, `get_lane_status` acquires the mutex,
   computes `reserved_cost = 20` (under the lane cap of 100),
   returns `Ok(())`. Mutex is **released**.
2. **t=1:** Task B's intent handler — running in a different tokio
   task on the same kernel — runs `check_budget(lane=L, cost=80,
   …)`. It also sees `reserved_cost = 20` (A has not yet consumed),
   passes the check, then runs `consume_budget` which inserts a
   row of cost 80 → `reserved_cost = 100`. Mutex is released.
3. **t=2:** Task A's handler resumes and calls `consume_budget(lane=L,
   task=A, cost=80, …)`. The PK is `(lane_id, task_id)` so A's
   `INSERT OR IGNORE` succeeds (different `task_id`) → `reserved_cost
    = 180`, **80 units over the lane cap of 100**.
4. **Result:** the lane is overcommitted in `lane_budget_reservations`.
   Subsequent `check_budget` calls correctly reject new work, but the
   damage is done — both A and B are accepted under a budget that
   should only have admitted one. The kernel has executed work
   beyond the operator-signed cap.

**Invariant broken:** INV-STORE-02 (the `lane_budget_reservations`
write must be inside the same transaction as the check that gates
it); operator's `max_cost_per_epoch` policy guarantee.

**Fix:** Replace the two-call pattern with a single transactional
helper `reserve_budget_in_tx(tx, lane_id, task_id, cost, policy)`
that runs the SELECT-aggregate (over `lane_budget_reservations` and
`tasks`) and the `INSERT OR IGNORE` inside one `BEGIN`/`COMMIT`,
both under one mutex acquisition. The intent handler's Phase C
opens that transaction once and passes `&tx` to the helper.

**Regression test home:** `scheduler::budget::tests::reserve_in_tx_serialises_concurrent_lane_writes`.

##### Pattern B — Multi-call composition outside a transaction

**Failure shape:** A high-level function calls multiple lower-level
helpers, each of which acquires the mutex and runs its own
auto-committed statement. A crash, or a concurrent operator IPC,
between any two helper calls leaves the store in a state where
some writes are visible and others are not.

**Canonical scenario — intent acceptance (`handlers::intent::run_phase_c`):**

The pre-fix code called five helpers in sequence, each opening its
own mutex acquisition:

1. `fsm_transition(task, GatesPending)` — auto-commits.
2. `check_budget(lane, cost, policy)` — read-only, mutex acquired and released.
3. `consume_budget(lane, task, cost)` — auto-commits the `INSERT`.
4. `fsm_transition(task, Running)` — auto-commits.
5. `update_task_intent_fields(task, head_sha, base_sha, …)` — auto-commits.
6. `insert_task_intent_range(task, base, head)` — auto-commits.

**Step-by-step interleaving:**

1. **t=0:** Phase C runs steps 1–3 successfully. `tasks.state` is
   now `Running` (oh wait — that's step 4; after step 3 the task
   is still `Admitted` but `lane_budget_reservations` has an entry).
2. **t=1:** Operator runs `task abort <task_id>`. The abort handler
   transitions `Admitted → Aborted` via `transition_task` (which
   succeeds because `Admitted → Aborted` is a legal edge per
   `is_legal_transition`). The lane reservation row is **not**
   released (release happens via `release_budget` only on the
   normal terminal-state path, not on operator-driven abort).
3. **t=2:** Phase C resumes step 4: `fsm_transition(task, Running)`.
   `transition_task` re-reads `tasks.state`, sees `Aborted`, and
   `is_legal_transition(Aborted, Running)` returns `false` →
   returns `LifecycleError::TaskNotAbortable`. The intent handler
   propagates this as `PlannerErrorCode::FailPolicyViolation`.
4. **Result:** the lane carries a stranded reservation for an
   `Aborted` task. The operator's `task abort` succeeded but did
   not release the budget; over time the lane drifts toward
   apparent capacity exhaustion even though no real work is
   running.

**Invariant broken:** INV-STORE-02 (intent acceptance is listed as
a multi-table operation that must be one transaction); spec
guarantee that "either the intent is fully accepted (FSM, budget,
intent fields, intent range all written) or none of it is".

**Fix:** Acquire the mutex once at the top of `run_phase_c`, open
a single `conn.transaction()`, and run all five helpers as `_in_tx`
variants that take `&Transaction` instead of `&Store`. If
`fsm_transition_in_tx(task, Running)` returns an error, the entire
transaction rolls back — the lane reservation row is never
committed, and the task is left in whatever state the abort wrote.
The operator's abort wins cleanly.

**Regression test homes:**
- `scheduler::budget::tests::reserve_in_tx_serialises_concurrent_lane_writes` (lane TOCTOU pin: pre-fix bug is exactly this scenario, post-fix the helper rejects the second over-cap reservation).
- `scheduler::budget::tests::reserve_in_tx_is_idempotent_on_same_task_pk` (continuation-intent idempotency — `INSERT OR IGNORE` on the PK collapses retries).
- `scheduler::budget::tests::reserve_in_tx_enforces_concurrency_cap` (concurrency cap is also enforced inside the same transaction).
- The Phase B composition fix in `handlers::intent::run_phase_c` is end-to-end-covered by the existing `kernel/tests/mock_planner_end_to_end.rs` integration suite (which exercises the full Admitted→Running intent acceptance path against a real Store).

##### Pattern C — Read in one tx, decide, write in another

**Failure shape:** A function reads a state value to decide what to
write, but the decision and the write are in different mutex
acquisitions. Between the two, a concurrent task can change the
state the decision was based on.

**Canonical scenario — verifier-token consume race (`handlers::witness::handle`):**

The pre-fix code had three `spawn_blocking` blocks, each acquiring
the mutex:

1. `validate_verifier_token(raw_token)` — SELECT row, check
   `consumed=0` and `expires_at > now`, return `run_id`.
2. `witness_index::write(record, blob, dir)` — write blob to FS,
   then `INSERT OR IGNORE` into `witness_records`.
3. `consume_verifier_token(raw_token)` — `UPDATE … SET consumed=1
   WHERE token_hash=? AND consumed=0`.

**Step-by-step interleaving (concurrent reconcile):**

1. **t=0:** Verifier callback A presents its token. Step 1 runs,
   sees `consumed=0`, returns `run_id_A`. Mutex released.
2. **t=1:** A separate code path triggers `recovery::reconcile_tasks`
   (e.g. via a manual reconcile RPC, or the kernel restart-after-crash
   path running concurrently with a still-in-flight verifier). The
   sweep transitions A's task to `BlockedRecoveryPending` and
   `expire_orphan_verifier_tokens` UPDATEs A's token row to
   `consumed=1`.
3. **t=2:** Verifier A's step 2 runs. Witness blob is written to
   FS; `INSERT OR IGNORE` into `witness_records` succeeds (no
   unique conflict on `verifier_run_id`). Audit `WitnessAccepted`
   is emitted to stderr. Mutex released.
4. **t=3:** Verifier A's step 3 runs `consume_verifier_token`. The
   UPDATE finds 0 rows (`consumed` is already 1) and returns
   `AuthorityError::TokenConsumed`. The handler propagates
   `HandlerError::Unauthorized`. The verifier subprocess receives
   "your callback was rejected" — but the witness row is already in
   the index, **and the gate evaluator will see it on the next
   recompute even though the kernel told the verifier its work was
   not accepted**.

**Invariant broken:** INV-INIT-08 (witness records are the source
of truth for "which gates are satisfied"; a witness that the kernel
told its producer it rejected MUST NOT be visible to the gate
evaluator); INV-STORE-02 (`witness_index::write` is listed as a
multi-table operation: `witness_records` + `verifier_run_tokens`
both written in one transaction).

**Fix:** Move validate + write + consume into a single transaction.
After the FS blob write (which is naturally outside SQL but is
content-addressed and idempotent), the SQL portion runs as one
`BEGIN`/`COMMIT`:

1. `SELECT verifier_run_id, evaluation_sha, expires_at, consumed
   FROM verifier_run_tokens WHERE token_hash=?` — returns the
   `run_id` and validates `consumed=0`, `expires_at > now`.
2. `INSERT OR IGNORE INTO witness_records (...)` — idempotent on
   `verifier_run_id` PK.
3. `UPDATE verifier_run_tokens SET consumed=1, consumed_at=?
   WHERE token_hash=? AND consumed=0` — must report 1 row, else
   the witness was concurrently expired and we must roll back.

If step 3 reports 0 rows, the entire transaction rolls back: the
witness INSERT is undone (atomic with the UPDATE) and the verifier
gets the same `Unauthorized` reply it would have gotten under the
pre-fix code, but **now the witness row is also rolled back** so
the gate evaluator never sees the inconsistent record.

**Regression test homes:**
- `handlers::witness::tests::commit_witness_in_tx_happy_path_commits_all_three` (success-path atomicity).
- `handlers::witness::tests::commit_witness_in_tx_rolls_back_when_token_concurrently_expired` (validate fails inside tx → no witness row leaks).
- `handlers::witness::tests::commit_witness_in_tx_rolls_back_witness_when_consume_races` (consume race → witness INSERT rolled back).

##### Pattern D — Multi-table writes with no explicit transaction

**Failure shape:** A function performs two writes to different tables
under one mutex hold, but does not open an explicit
`conn.transaction()`. SQLite auto-commits each statement, so a
process crash between them leaves the writes split.

**Canonical scenarios:**

- **`lifecycle::abort_initiative`** — UPDATE `tasks` (cancel all
  non-terminal), UPDATE `initiatives` (set Aborted). Crash between
  the two: tasks cancelled, initiative still in `Executing`. Next
  startup runs `recovery::reconcile_tasks` which sweeps the
  already-cancelled tasks to `BlockedRecoveryPending` (idempotent),
  but the initiative remains stuck `Executing` forever — there is
  no recovery sweep that re-derives initiative state from task
  state at startup. The operator's `initiative abort` would have to
  be re-run, except `abort_initiative` rejects already-aborted
  initiatives — it would *not* reject one stuck in `Executing`,
  so the second invocation succeeds and writes the `Aborted` state
  the first time around should have written.
- **`lifecycle::create_initiative`** — INSERT `initiatives`, INSERT
  `signed_plan_artifacts`. Crash between: the initiative row exists
  in `Draft` state but no plan artifact row. A subsequent
  `approve_plan` call would fail at the `SELECT plan_bytes FROM
  signed_plan_artifacts` step with `QueryReturnedNoRows` — leaving
  the operator with an undeletable `Draft` initiative they can
  never approve.

**Invariant broken:** INV-STORE-02 (general principle: multi-table
mutations for one logical operation must be one transaction).

**Fix:** Wrap both writes in `let tx = conn.transaction()?;` …
`tx.commit()?;` so the writes commit atomically. The audit event
is still emitted **after** `tx.commit()` per §2.5.2 audit ordering.

**Regression test homes:**
- `initiatives::lifecycle::tests::abort_initiative_commits_tasks_and_initiative_atomically` (`tasks` + `initiatives` updates land together).
- `initiatives::lifecycle::tests::create_initiative_rolls_back_initiative_row_on_signature_failure` (validation failure leaves zero rows).
- `initiatives::lifecycle::tests::create_initiative_commits_both_rows_atomically_on_success` (success path commits BOTH `initiatives` and `signed_plan_artifacts`).

##### Non-bugs (documented for completeness)

The following patterns are **safe** under the current single-process
single-connection-mutex architecture, but a reviewer who reads the
code in isolation might worry about them:

- **`transition_task`'s SELECT-then-UPDATE under one mutex hold,
  no explicit `BEGIN`/`COMMIT`.** Safe because the mutex is held
  across both statements (no other tokio task can interleave),
  and a crash between SELECT and UPDATE has no consequence (the
  SELECT is read-only). Will become a real bug if a future change
  introduces a second writer connection — at that point an explicit
  transaction with `BEGIN IMMEDIATE` should be added. Current code
  is annotated `// INV-STORE-01: single-connection mutex hold;
  upgrade to BEGIN IMMEDIATE if a second writer is added`.
- **`retry_task`'s pattern of read-then-drop-mutex-then-call-`transition_task`.**
  Safe because `transition_task` re-reads the state inside its own
  mutex acquisition; if the task was concurrently moved out of
  `Failed`, the inner re-read catches it and `transition_task`
  returns `TaskNotAbortable` via `is_legal_transition`.
- **Phase A of intent handler reading session-then-task-then-quarantine
  across multiple mutex acquisitions.** The intermediate-state
  reads are validated for staleness in Phase C's transaction by
  re-reading the task row inside the tx. Quarantine is double-checked
  there too. Phase A's reads exist only to compute the gate
  evaluation argument set; the authoritative checks all live in
  Phase C.

Adding any of these to the buggy list (because the architecture
has changed, or because new write paths render the assumptions
invalid) requires updating both the code annotation and this
catalogue.

---

#### SQL Type-Safety and Codebase Representation

**Type-safety invariant (INV-STORE-03):** To prevent runtime SQL errors from typos or schema drift, **no Rust source file across the workspace — production *or* test code, in any crate that touches `kernel.db` (`raxis-kernel`, `raxis-store`, `raxis-cli`, `raxis-test-support`, and any future store consumer) — may contain a raw SQL table-name or state-value string literal**.
- **Table names** must be dynamically interpolated using the `raxis-store::Table` enum. A module interacting with the database must define a module-level constant (e.g., `const TASKS: &str = Table::Tasks.as_str();`) and use `format!()` to inject it into the query string. The same rule applies inside `#[cfg(test)]` modules and integration-test fixtures: tests that hand-roll seed data via `INSERT`/`UPDATE`/`DELETE` MUST resolve their table names through `Table::*.as_str()` (typically by importing `raxis_store::Table` and re-binding it as a `const`). This ensures that renaming a table in `crates/store/src/table.rs` propagates through every `INSERT INTO …` / `SELECT … FROM …` site at compile time, including the test harness.
- **State values** (e.g., TaskState, InitiativeState) must use the relevant enum's `.as_sql_str()` method as bound parameters.

A workspace-wide `rg` over `INSERT INTO <ident>|UPDATE <ident> SET|DELETE FROM <ident>|FROM <ident>` with `<ident>` matching any name in `Table::ALL` MUST return zero hits in `*.rs`; the only legitimate occurrences of those bare identifiers are inside `crates/store/src/table.rs` (the enum definition itself) and in the migration DDL strings under `crates/store/src/migration.rs`. CI may codify this as a grep gate.

---

#### Hash table strategy (kernel-internal maps)

The kernel uses two hash families for in-memory maps and sets, picked by the **trust origin of the key**:

| Key origin | Default type | Rationale |
|---|---|---|
| Untrusted IPC frame, planner-supplied content, anything that can be chosen by an adversary to provoke worst-case collisions | `std::collections::HashMap` (SipHash-1-3) | HashDoS-resistant; the per-process random key prevents a remote attacker from constructing a colliding key set. |
| Operator-controlled or kernel-internal: lane IDs, gate types, capability classes, `task_id` after admission, `session_id` after creation, file paths derived by the kernel from `vcs::diff` | `rustc_hash::FxHashMap` / `FxHashSet` | Faster (~2× lookup, ~3× insert on small string keys); the FxHash function is intentionally non-DoS-resistant, but every key in this category is a value the kernel either generated itself or read from an artifact the operator signed — none are user-attacker-influenced at runtime. |

**Migration policy.** Modules adopting `FxHashMap` MUST justify the choice in a code comment that names the trust origin (e.g. "lane_id is read from the signed PolicyBundle; operator-controlled"). A code review that finds an `FxHashMap` keyed by a planner-supplied `String` is a P0 review block: the module must either revert to `HashMap` or prove (via a wrapped newtype with a length cap and character-set restriction) that the key cannot be adversarially shaped.

**Wire serialization.** Both map types serialize identically over `serde`/`bincode` — the choice is a memory-representation decision and never appears on the wire.

---

> **§2.5.1 — isolation model complete.**
> DDL tables 1–6 follow immediately below.

---

#### Canonical DDL — Part 1 of 4: Core lifecycle tables

All tables are created by migration 1 (the v1 baseline migration, applied atomically on first startup). Table names below are canonical — any conflicting name in Parts 2.1–2.4 prose is superseded by these names. **`task_dag_edges`** is the canonical DAG table name (legacy alias in prose: `task_dependencies`).

**Creation order matters** because of foreign key constraints. `sessions` must precede `tasks` (tasks hold a nullable `session_id` FK). `initiatives` must precede `tasks`, `signed_plan_artifacts`, `task_dag_edges`, and `escalations`. The migration DDL below is ordered accordingly.

---

> **V2.1 schema-extension notice — `last_committing_event_seq` column.**
>
> Every state-bearing table below (i.e. every table the kernel mutates
> inside an admission or operator-IPC transaction — `sessions`,
> `tasks`, `initiatives`, `escalations`, `delegations`,
> `signed_plan_artifacts`, `lane_budget_reservations`,
> `lineage_rate_limits`, `policy_epoch_history`, `operator_certificates`,
> `initiative_quarantines`, plus the V2-introduced state tables
> `plan_bundles`, `subtask_activations`, `verifier_runs`,
> `provider_circuit_state`, `candidate_merges`, `plan_signing_keys`,
> `emergency_revocations`, `notification_dispatch`,
> `notification_channel_health`, `smtp_proxy_rate_buckets`,
> `session_escalation_rate_limits`,
> `operator_quarantine_directives`, `worktree_abandonment_records`)
> gains a single new column under V2.1:
>
> ```sql
> last_committing_event_seq INTEGER NOT NULL DEFAULT 0
> ```
>
> The column is populated inside the same transaction as every state
> mutation, holding the `pending_seq` of the `StateChangePending` event
> that announced the mutation. The offline forensic verifier defined
> in `v2/audit-paired-writes.md §5` uses this column to disambiguate
> chain orphans (pending-without-confirmed) into "committed" or
> "rolled-back" outcomes without needing the kernel to be running.
>
> A column value of `0` is a sentinel meaning "row predates the V2.1
> migration" and triggers `Finding::PreV21Row` from the verifier (a
> non-critical finding; the verifier falls back to V1 reconciliation
> semantics for that row's history). The migration backfill walks the
> chain newest-to-oldest to populate the column for as many rows as
> the chain references.
>
> Tables NOT in the paired class (`audit_chain`, `sqlite_sequence`,
> `nonce_cache`, `task_intent_ranges`, `task_exported_path_snapshots`,
> `witness_records`, `approval_token_nonces`, `verifier_run_tokens`,
> `task_dag_edges`, `approval_proofs`, `approval_tokens`) are
> explicitly excluded — they are append-only or transition-derivative
> and do not represent state mutations the kernel takes responsibility
> for via the audit chain. The exhaustive paired/non-paired
> classification lives in `v2/audit-paired-writes.md §3.2` and §4.
>
> The Table-by-Table DDL below documents the V1 column set.
> Implementers building against V2.1+ MUST apply
> `migrations/V21__paired_audit.sql` (per
> `v2/audit-paired-writes.md §3.3`) on top of the V1 DDL; the migration
> is non-destructive (`ALTER TABLE … ADD COLUMN … DEFAULT 0`) and
> idempotent.

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

-- The PK above is a covering index for `release_successors` lookups
-- (`WHERE predecessor_task_id = ?`). The complementary direction —
-- "find every predecessor edge for task T" — is what `next_ready_tasks`
-- and `dag::predecessors_of` need; without an explicit index on
-- `successor_task_id` SQLite falls back to a full table scan plus a
-- temp-btree, which is fine for ~hundreds of edges and pathological
-- for the thousands an initiative may eventually carry.
CREATE INDEX IF NOT EXISTS idx_task_dag_edges_successor
    ON task_dag_edges (successor_task_id);
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

-- NOTE (spec/migration parity audit): this index is REDUNDANT with
-- the implicit `sqlite_autoindex_delegations_*` that SQLite creates
-- for the `UNIQUE (session_id, capability_class)` constraint above
-- (per https://sqlite.org/lang_createtable.html). It is preserved in
-- the migration heredoc only because v1 deployed databases already
-- carry it; new tables MUST NOT add a duplicate explicit index when
-- a UNIQUE constraint already covers the same column tuple. The
-- `check_capability` lookup at step 1 below uses the implicit index.
CREATE INDEX IF NOT EXISTS idx_delegations_session_capability
    ON delegations (session_id, capability_class);
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

> **Implementation pointer:** Steps 2–5 are implemented by
> `kernel::authority::session::accept_envelope_and_advance_sequence`,
> which is the single entry point called from
> `kernel::handlers::intent::handle_inner` before any business logic
> runs. Its `EnvelopeReplayReason` enum (`DuplicateNonce`,
> `SequenceAlreadyAccepted`, `SequenceGap`, `MalformedNonce`) is what
> populates the `reason` field in the `ReplayRejected` audit event.
> Direct callers of `update_sequence_number` are forbidden in the
> message ingress path; that helper is retained only for
> bootstrap/recovery flows that do not carry an envelope nonce.

---

> **§2.5.1 — DDL Part 4 of 4 complete.**
>
> **All 19 canonical `kernel.db` tables are now specified** (tables 17–18 added by §2.5.8 VCS Path Scope Enforcement; Table 19 added by `policy_manager.rs::advance_epoch` Phase 1 in `kernel-core.md`):
>
> | Part | Tables |
> |------|--------|
> | Part 1 | `schema_version` (1), `initiatives` (2), `signed_plan_artifacts` (3), `sessions` (4), `tasks` (5), `task_dag_edges` (6) |
> | Part 2 | `delegations` (7), `escalations` (8), `approval_tokens` (9), `approval_proofs` (10), `approval_token_nonces` (11), `verifier_run_tokens` (12) |
> | Part 3 | `witness_records` (13), `lane_budget_reservations` (14), `lineage_rate_limits` (15), `nonce_cache` (16) |
> | Part 4 | `task_intent_ranges` (17), `task_exported_path_snapshots` (18), `policy_epoch_history` (19) |
>
> The v1 baseline migration (migration 1) creates all 19 tables atomically. All table names in this DDL are canonical and supersede any conflicting names in Parts 2.1–2.4. The Rust implementation enforces this via the `raxis_store::Table` enum and the `INV-STORE-03` rule "no raw SQL table-name literals in any workspace crate that touches `kernel.db` (production *and* test code); use `Table` enum + `.as_str()`" — see §2.5.1 above for the full normative statement.

**DDL Part 4 of 4 — VCS Path Scope Enforcement tables (Tables 17–18) and policy epoch ledger (Table 19)**

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

> **V2.1 supersession notice.** The two-phase write ordering described
> below (SQLite commit first, JSONL append second, `recovery::reconcile`
> patching gaps on the next kernel start) is the **V1 / V2.0** mechanism.
> Under the strict reading of `R-7` ("audit chain integrity MUST NOT
> depend on continued operation of the authority that produced it"), the
> V1 ordering has a real but probabilistic R-7 gap: chains crashed in
> the (SQLite COMMIT, JSONL fsync) window are silent unless `reconcile`
> runs before the kernel is decommissioned.
>
> V2.1 closes the gap with a **paired-audit protocol** —
> `StateChangePending` → `<existing kind>` (with `confirms_pending_seq`,
> `sqlite_commit_id`, `actual_post_state_digest`) →
> `StateChangeRolledBack` — defined in `v2/audit-paired-writes.md`.
> Under the V2.1 protocol an offline forensic verifier can resolve every
> chain orphan against a SQLite snapshot without the kernel ever needing
> to run again, and `recovery::reconcile_advisory` becomes optional.
>
> The V1 ordering documented here remains authoritative for:
> 1. Audit chain entries written before the `AuditSchemaMigration` event
>    (which marks the V2.0 → V2.1 cutover; see `v2/audit-paired-writes.md
>    §10`).
> 2. Single-class events (Phase-A rejections, pure observability,
>    chain self-events) which the V2.1 protocol explicitly does NOT
>    pair (see `v2/audit-paired-writes.md §4`).
>
> For paired-class state mutations on a V2.1+ kernel, the §2.5.2 ordering
> is replaced by the three-phase ordering in `v2/audit-paired-writes.md
> §2.3`. Readers should treat this section as describing the historical
> baseline plus the residual single-event protocol that V2.1 still uses.

#### Write ordering invariant (V1 / V2.0 single-event ordering)

Every kernel state mutation follows a strict two-phase write order:

1. **SQLite commit first.** The store transaction is committed and `fsync`-equivalent durability is guaranteed before any audit record is attempted.
2. **JSONL append second.** `AuditSink::emit` (production impl: `FileAuditSink` wrapping `AuditWriter::append`) writes the serialised audit record to the JSONL file and flushes after the store commit returns `Ok`. The kernel exposes the sink through `HandlerContext::audit: Arc<dyn AuditSink>`; tests inject `FakeAuditSink` for in-memory capture without touching disk.

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

#### Crash-window characterisation (V1 / V2.0)

Two failure modes are possible under the V1 ordering:

| Mode | Description | Recovery |
|---|---|---|
| **SQLite committed, JSONL not appended** | Process crashed between commit and JSONL write. State is correct; audit chain has a gap at that `seq`. | `recovery::reconcile` detects the gap: SQLite row exists with no corresponding JSONL line. Emits `AuditEventKind::ReconciliationGap { missing_seq, reconstructed_event }` to repair the chain. The reconstructed event is marked `reconstructed: true` in its payload. |
| **JSONL appended, SQLite rolled back** | Cannot happen under the write ordering invariant — JSONL is only written after `Ok` from the store commit. If the process crashes mid-commit (before `Ok`), SQLite WAL rolls back; no JSONL line is written. |

The second mode is structurally impossible given the write ordering invariant. Implementers **must not** attempt JSONL writes before store commit confirmation.

> **V2.1 paired-class crash-window characterisation.** For paired-class
> events (state mutations under V2.1+), four crash windows are possible
> instead of two; each has a deterministic offline-verifier resolution
> that does NOT depend on `recovery::reconcile` running. See
> `v2/audit-paired-writes.md §7` (Failure modes — every error path
> explicitly treated). The paired protocol turns the V1 "SQLite
> committed, JSONL not appended" probabilistic R-7 gap into a structural
> guarantee resolvable from a frozen SQLite snapshot alone.

#### What `recovery::reconcile` treats as ground truth (V1 / V2.0)

- **SQLite is ground truth for FSM state.** On divergence, the task/initiative state in SQLite stands; JSONL is repaired to match.
- **JSONL is ground truth for ordering and chain integrity.** `seq` values from JSONL take precedence for chain repair; the kernel does not re-sequence existing records.
- `reconcile` never rewrites existing JSONL lines — it only appends gap records.

> **V2.1 supersession.** `reconcile` is renamed `reconcile_advisory` in
> V2.1 (see `v2/audit-paired-writes.md §6`). Its role is downgraded
> from "required for chain integrity" to "best-effort advisory":
> the chain is verifiable end-to-end from a SQLite snapshot without
> `reconcile_advisory` ever having run. When it does run, it
> synthesises the missing `confirmed` (or `StateChangeRolledBack`)
> events into the chain so future verifications don't need to consult
> SQLite for the same orphans. The "JSONL is ground truth for ordering"
> property is preserved exactly; what changes is that the V1
> `ReconciliationGap` event becomes a synthesised V2.1
> `StateChangeRolledBack { reason: CrashInferred }` (for inferred
> rollbacks) or a synthesised paired-class confirmed event (for
> committed orphans).

#### Kernel never reads JSONL

The kernel write path is append-only to JSONL. No kernel handler reads JSONL. Chain verification, gap analysis, and audit queries are exclusively `raxis-audit-tools` responsibilities. This is enforced by module boundaries: `src/audit.rs` exposes only `append` — no read interface.

#### Operator display-name fields

Audit-event variants that name an operator carry **two** fields, never one:

| Variant | Fingerprint field (always present) | Display-name field (optional snapshot) |
|---|---|---|
| `InitiativeAborted` | `triggered_by_operator: Option<String>` | `triggered_by_operator_display_name: Option<String>` |
| `PathScopeOverrideApplied` | `approving_operator: String` | `approving_operator_display_name: Option<String>` |
| `SessionRevoked` | `revoked_by: String` | `revoked_by_display_name: Option<String>` |
| `DelegationGranted` | `granted_by: String` | `granted_by_display_name: Option<String>` |
| `EscalationApproved` | `approved_by: String` | `approved_by_display_name: Option<String>` |
| `EscalationDenied` | `denied_by: String` | `denied_by_display_name: Option<String>` |
| `PolicyEpochAdvanced` | `triggered_by: String` | `triggered_by_display_name: Option<String>` |
| `InitiativeQuarantined` | `quarantined_by: String` | `quarantined_by_display_name: Option<String>` |
| `OperatorQuarantineSwept` | `quarantined_by: String`, `target_fingerprint: String` | `quarantined_by_display_name: Option<String>`, `target_display_name: Option<String>` |

**Wire-format invariants.**

- The fingerprint is the canonical, unforgeable identifier — it is derived from the operator's pubkey and never changes for a given key. It is the field downstream tools key against.
- The display name is a **snapshot** taken from the operator's policy entry at the moment the audit event is emitted. It is best-effort: present whenever the kernel can resolve the fingerprint against the live `PolicyBundle` at emit time, absent otherwise.
- Both display-name fields are serialised with `#[serde(default, skip_serializing_if = "Option::is_none")]`. Audit-chain segments written by older kernel binaries (no display-name plumbing) deserialise cleanly into the new shape with the field defaulting to `None` — adding the field is a strictly forward-compat change to the JSONL wire format.

**When the display name is `None`.**

1. **Legacy segment.** The event was written before the display-name plumbing shipped. CLI render layers MUST fall back to a live lookup against the `operator_certificates` view (see §2.5.7) and annotate the rendered name as historical so the operator knows the event itself does not vouch for the name (cert may have rotated since).
2. **Operator removed in flight.** The kernel could not resolve the fingerprint at emit time — extremely rare, would require the operator to have been removed from the bundle between authentication and the post-commit audit emit. Same render-layer fallback applies.
3. **PolicyEpochAdvanced lookup against the *new* bundle.** `triggered_by_display_name` is resolved against the **incoming** bundle (the one being installed by the advance), not the previous one. An operator who removes themselves as part of the rotation legitimately yields `None` here; the previous name lives in the prior `PolicyEpochAdvanced` chain entry.

**Render-layer fallback (CLI side, normative).**

When a CLI consumer (`raxis log`, `raxis inbox`, `raxis status`, `raxis verify-chain`, etc.) renders an operator-bearing audit event:

1. If the embedded display name is `Some(name)`, render `"name (fp_prefix)"` — this is the snapshot the kernel pinned at emit time. The name shown is the name the operator had **at the time of the event**, even if their cert has since rotated to a different display name.
2. If the embedded display name is `None`, look up the fingerprint in the current `operator_certificates` view (§2.5.7).
   1. If found, render `"name (fp_prefix) [historical cert; current name shown — event predates display-name plumbing]"`. The annotation is mandatory: the renderer cannot prove the current name was the name at emit time, so the operator MUST see the caveat.
   2. If not found, render `"<unknown> (fp_prefix) [operator no longer in policy]"`. This indicates a removed operator (e.g. revoked cert) — the audit event is still authoritative for the action, but the human-readable identity is irrecoverable in the live deployment.

**Why both fields, not just the snapshot.**

The fingerprint stays canonical so `raxis verify-chain` and any forensic tool can join across the chain by a stable, unforgeable key. The display name is a humane affordance — it is what the operator sees when they read their own logs, and it survives the case where the policy bundle shrinks (e.g. the operator who triggered the event was later removed, but the audit chain still tells you who they were). The two fields together let the audit chain be both machine-correct and human-readable without conflating identity with label.

**Kernel-stderr dispatch logs (third surface).**

In addition to the audit chain (the persistent record) and CLI render layers (the human-facing reader), the kernel emits per-request JSON log lines to its own `stderr` from the operator IPC dispatcher (`kernel/src/ipc/operator.rs::dispatch_log`). Every line that names an operator-fingerprint actor — `op_request`, `op_response`, `frame_decode_failed`, `unauthorized`, `cert_denied` — carries the same `operator_display` snapshot as an optional top-level JSON field, resolved per-request from the live `PolicyBundle` snapshot via `PolicyBundle::operator_display_name(&fingerprint)`. The dispatcher does the lookup at the **start of each request iteration** rather than once at connection time so a policy rotation mid-loop is reflected in subsequent log lines without restarting the per-operator connection. The field is omitted (not emitted as `null`) when the lookup yields `None`, so existing log-grep recipes that key off `operator_fp` continue to work unchanged. This third surface uses the same snapshot semantics as the audit chain — `operator_display` is what the name was *at the moment the request was logged*, not necessarily the current name — but unlike the audit chain it is not part of any tamper-evident record and is intended purely for operator-side log triage.

---

### §2.5.3 — Plan Artifact Signing Contract

> **V2 supersession notice.** The on-disk `<data_dir>/plans/<initiative_id>/`
> layout, the `raxis-cli plan sign` command, and the `signed_plan_artifacts`
> SQL table described below are the **V1** mechanism. V2 admissions go
> through **Plan Bundle Sealing** (`v2/plan-bundle-sealing.md`): the CLI
> performs an atomic in-memory parse + bundle + hash + sign + submit in a
> single `raxis-cli submit plan <plan.toml>` invocation, sending the bundle
> bytes directly to the kernel via IPC; the kernel seals into the V2
> `plan_bundles` / `plan_bundle_artifacts` tables and never reads from
> `<data_dir>/plans/`. This V1 section is retained for read-only audit
> compatibility with pre-V2 initiatives and for forensic recovery of
> historical state. New initiatives in V2 use the V2 path exclusively.

#### On-disk layout

```
<data_dir>/plans/<initiative_id>/
    plan.toml        # the human-readable plan artifact
    plan.sig         # the detached signature file
```

Both files are written by `raxis-cli plan sign`. The kernel reads both **once**, at `create_initiative` time, and seals their content into `signed_plan_artifacts` (Table 3). Every subsequent operation — `approve_plan`, crash recovery, audit reconstruction — reads `plan_bytes` and `plan_sig` from the sealed DB row, never from disk. The on-disk `plan.toml` and `plan.sig` files remain at `<data_dir>/plans/<initiative_id>/` for human inspection and external tooling, but they are **non-authoritative** once the seal succeeds: deleting, modifying, or replacing them does not affect kernel behaviour for that initiative, and the kernel does not re-open them at any point in the initiative lifecycle.

#### Byte-exact signing domain

The signature covers the **exact bytes of `plan.toml` as read from disk** — no normalization, no canonicalization, no whitespace stripping, no BOM handling. The signing input is a **domain-prefixed** SHA-256 digest, and the Ed25519 signature is over that digest (not over the raw bytes directly, for auditability and cross-protocol replay defence).

```
canonical_input = "RAXIS-V1-PLAN" || 0x00 || file_bytes(plan.toml)
signing_input   = SHA-256(canonical_input)            -- 32 bytes
signature_hex   = Ed25519Sign(operator_private_key, signing_input)

plan_sha256     = SHA-256(file_bytes(plan.toml))      -- without the prefix;
                                                      -- recorded separately
                                                      -- in plan.sig and in
                                                      -- initiatives.plan_artifact_sha256
```

The `"RAXIS-V1-PLAN"` 13-byte ASCII prefix and the `0x00` terminator are mandatory. They are the same domain-separation pattern used by `"RAXIS-V1-DELEGATION-GRANT"` (§2.5.5 below) and `"RAXIS-V1-ESCALATION-APPROVE"`. Without the prefix, an Ed25519 signature minted for one purpose could be replayed as a valid signature for another — see §2.5.5 "Why a domain-separation prefix" for the worked example.

`plan_sha256` (the **un**-prefixed SHA-256) is NOT what is signed. It is recorded as a separate field in `plan.sig` for human inspection and as `initiatives.plan_artifact_sha256` for join lookups. The kernel does not verify against `plan_sha256`; verification recomputes `signing_input` from `plan_bytes` on each call.

Canonical implementation: `raxis-crypto::plan::plan_signing_input` (signer side, called by `raxis-cli plan sign` / `policy sign`) and `raxis-crypto::plan::verify_plan_signature` (verifier side, called by `kernel::initiatives::lifecycle::approve_plan`). Both routes MUST go through these two functions; signing or verifying directly via `Ed25519::sign`/`Ed25519::verify` over any other byte string is a spec violation. The `cli/tests/plan_sign_roundtrip.rs` integration test pins this contract: it signs via the canonical helper and verifies via the kernel's verifier, and it asserts that signatures over the raw plan bytes OR over the hex string of `plan_sha256` are rejected.

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
    → verifies: raxis_crypto::plan::verify_plan_signature(
                    operator_pubkey,         -- looked up via plan.sig.signed_by
                    plan_bytes,              -- raw file bytes
                    plan.sig.signature,      -- 64 raw bytes (decoded from hex)
                ) == Ok
    → if ok: INSERT INTO initiatives + INSERT INTO signed_plan_artifacts (Table 3)
    → returns: InitiativeCreated { initiative_id } or error
```

The verifier function reconstructs `signing_input = SHA-256("RAXIS-V1-PLAN\0" || plan_bytes)` and calls `Ed25519::verify(pubkey, signing_input, signature)`. Calling `Ed25519::verify` with `plan.sig.plan_sha256` (the bare digest, no domain prefix) or with `plan_bytes` directly would NOT produce a valid verification under the canonical scheme and is a spec violation.

`create_initiative` seals the plan into `signed_plan_artifacts` (§2.5.1 Table 3) by inserting a single row with exactly four columns:

- `initiative_id` — FK to `initiatives.initiative_id`.
- `plan_bytes` — the **full byte-image** of `plan.toml` exactly as read from disk and verified against `plan.sig.plan_sha256` above. The plan TOML content **is** stored in SQLite — this is intentional (see Table 3 rationale "Why store the full `plan_bytes` and not just the hash?"): it makes the kernel self-contained for `approve_plan`, recovery replay, and audit reconstruction, with no dependency on the on-disk file after sealing.
- `plan_sig` — the raw 64-byte Ed25519 signature decoded from `plan.sig.signature` (the hex-encoded form on disk is decoded to bytes for storage).
- `stored_at` — Unix seconds at insertion, for audit cross-referencing.

The other fields of `plan.sig` — `signed_by` (operator pubkey fingerprint), `signed_at`, and `plan_sha256` — are **verified** at this call but **not** duplicated as columns of `signed_plan_artifacts`:

- `plan_sha256` is recomputable from `plan_bytes` on demand and is also indexed at `initiatives.plan_artifact_sha256` for join lookups (Table 2).
- `signed_by` and `signed_at` are preserved in the audit log via `AuditEventKind::InitiativeCreated { initiative_id, plan_hash, signed_by, signed_at }` (see `kernel-core.md` `src/initiatives/lifecycle.rs::create_initiative`). The audit log is the durable signer-of-record; this avoids storing the same value redundantly in the row table while keeping forensic recoverability of "which operator authorised this initiative, and when did they sign it" intact even if the on-disk `plan.sig` file is later removed.

#### `approve_plan` call path

`approve_plan` re-verifies the signature against the operator pubkey resolved from current policy (NOT against a key cached at `create_initiative` time). The cost is one Ed25519 verification per approval — negligible. The benefit: if an operator key is rotated or removed between submission and approval, the approval fails closed instead of executing under a key that policy no longer accepts. The kernel reads `plan_bytes` and `plan_sig` from `signed_plan_artifacts` (sealed at submission, never mutated thereafter — INV-INIT-06) and routes them through `raxis_crypto::plan::verify_plan_signature` exactly as `create_initiative` did. Only on success does it transition the initiative to `Executing` and admit tasks (see `kernel-core.md` §2.4 task FSM).

The operator public key MUST be looked up via `policy.operator_entry(approving_operator).pubkey_hex` — it is **never** taken from the wire. The `OperatorRequest::ApprovePlan { operator_pubkey_hex }` field exists only for back-compat with already-deployed CLI builds; the kernel **ignores** its value (it is not even decoded). New clients SHOULD send an empty string.

Two checks gate `approve_plan` before any signature verification:

1. **Identity binding (no impersonation).** The connected operator's challenge-response handshake established `AuthenticatedOperator { fingerprint, .. }` at the start of the connection. The handler enforces `request.approving_operator == authenticated.fingerprint`; mismatch → `FAIL_OPERATOR_IDENTITY_MISMATCH`. Without this, operator A holding a valid socket connection could submit a request claiming to be operator B and forge a "B-approved" plan.
2. **Trusted-operator lookup.** `approving_operator` MUST resolve to an entry in the loaded `policy.operators`. Absence → `FAIL_OPERATOR_UNKNOWN`. The pubkey used for Ed25519 verification is read from this entry's `pubkey_hex` and decoded inside the handler.

Reference implementation: `raxis-kernel::ipc::operator::handle_approve_plan`.

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
| `CancelInitiative { initiative_id, reason, grace_seconds, force_after_grace }` (V2) | Initiative in `Executing` (rejects from `Draft`, `ApprovedPlan`, or any terminal state with the appropriate FAIL code) | Initiative `→ CancelPending` (intermediate state added in V2 migration). Grace timer fires `cancel_finalizer` after `grace_seconds`: either transitions `→ Cancelled` naturally, or (if `force_after_grace`) bulk-cancels remaining non-terminal tasks via the same `lifecycle::abort_initiative` machinery (with `cancellation_class = OperatorCancel` distinguishing audit) and then `→ Cancelled`. | `initiatives::lifecycle::cancel_initiative` (handler enqueues the grace-deadline timer in `pending_lifecycle_timers`; `cancel_finalizer` consumes it) | `CancelInitiative` |
| `ApproveEscalation { op_token, escalation_id, approval_scope, operator_sig }` | Escalation `Pending` | Escalation `→ Approved`; writes `approval_tokens` + `approval_proofs` rows | `authority::approve_escalation` | `ApproveEscalation` |
| `DenyEscalation { op_token, escalation_id, reason }` | Escalation `Pending` | Escalation `→ Denied`; no token issued; audit-only record | `authority::deny_escalation` | `DenyEscalation` |
| `RotateEpoch { policy_path, sig_path }` | Phase 0 verification of new artifact passes (signature, epoch monotonicity, TOML shape, path under `<data_dir>/policy/`) | Phase 1 SQL transaction: sweeps `delegations` to `StaleOnNextUse`, invalidates session prompts, inserts `policy_epoch_history` row, appends `PolicyEpochAdvanced` audit. Phase 2 swaps `ArcSwap<PolicyBundle>` and `ArcSwap<AllowlistCache>`. Phase 3 best-effort gateway signal. | `policy_manager::advance_epoch` (called by `handlers/operator::handle_rotate_epoch`) | `RotateEpoch` |

`DenyEscalation` does not require `operator_sig` (no approval artifact is created; the audit event is the only record). `ApproveEscalation` requires `operator_sig` because the resulting `ApprovalProof` must be independently verifiable after a crash (INV-ESC-01). `AbortTask` and `AbortInitiative` are distinct variants — per-task abort (`OperatorAbort`) vs initiative-wide abort. `ResumeTask` and `RetryTask` are distinct message types dispatched on IPC discriminant, not on probed task state. `CreateSession` and `RevokeSession` are the v1 mechanism by which planner sessions are minted and torn down (gateway and verifier sessions are kernel-spawned via separate code paths and are not minted via this IPC — see `kernel-core.md` Part 2.3 §`session.rs` for the role-specific spawn paths). `GrantDelegation` is the operator's per-session capability-grant operation; the session must already exist (operator workflow is typically `CreateSession` → `GrantDelegation` × N capabilities → operator hands the session token to the planner spawn → planner submits its first intent). **This table is the single source of truth for operator IPC names and `permitted_ops` strings; `cli-ceremony.md` references it.**

The operator socket is bound with `mode 0600` and owned by the kernel OS user — readable only by the same user. v1 is single-operator, single-machine; this is the only access control at the socket layer.

> **INV-PLANNER-SPAWN (normative — cross-referenced from `peripherals.md` §3.1):** The kernel never autonomously decides to start a planner or create a planner session. `approve_plan` admits tasks and waits; no planner spawn logic fires. The canonical v1 operator workflow for starting an agent is:
>
> ```
> Step 1 — Plan approval:   raxis-cli plan approve <initiative_id>
>                           (kernel admits tasks, nothing else happens)
>
> Step 2 — Session creation: raxis-cli session create \
>                               --worktree <absolute_path> \
>                               --lineage <lineage_id>
>                            (kernel returns session_token)
>
> Step 3 — Planner start:   <operator starts planner subprocess or API call>
>                           passes session_token via env / config / API param
>                           planner connects to planner.sock, submits IntentRequests
> ```
>
> Steps 2 and 3 are explicitly the operator's responsibility. The kernel has no knowledge of how the planner process is started, what model it uses, or where it runs. This separation is intentional: it keeps orchestration logic (model selection, API keys, retry-on-crash) outside the kernel's audit surface. The kernel's role is to validate every intent frame, enforce policy, and record the audit trail — not to manage agent lifecycle.
>
> **Consequence for implementors:** Any kernel code path that calls `create_session(Role::Planner, ...)` without a corresponding `CreateSession` operator IPC message as the trigger is a spec violation. Session creation for planners MUST originate from an operator action, never from a timer, task state transition, or internal scheduler event.


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
display_name       = "Chika"
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

### §2.5.6a — `[notifications]` Normative Schema

> **Normative reference:** the full notification model — channel kinds,
> routing, fail-open semantics, the Shell channel handler, and the V2
> Email/Sidecar handlers — lives in `cli-readonly.md` §5.6. This
> section is the authoritative TOML schema and `PolicyBundle::validate`
> contract that section refers to.  The V1-draft `Webhook` kind was
> folded into `Sidecar` in V2.5 (forward-only — see V2_GAPS.md §C4).

#### `[notifications]` in `policy.toml`

```toml
[notifications]
default_channels = ["shell"]

[[notifications.channels]]
id     = "shell"                 # implicit; explicit entry overrides target
kind   = "Shell"                 # Shell | File | Email | Sidecar
target = "<data_dir>/notifications/inbox.jsonl"

[[notifications.channels]]
id     = "audit-mirror"
kind   = "File"
target = "/var/log/raxis-notifications.jsonl"

[[notifications.routes]]
event_kind = "EscalationSubmitted"
channels   = ["shell", "audit-mirror"]
```

**`PolicyBundle::validate` enforcement (normative):**

1. `default_channels` MUST reference only declared channel ids (the
   implicit `"shell"` channel always counts, even without an explicit
   `[[notifications.channels]]` entry — it defaults to
   `target = "<data_dir>/notifications/inbox.jsonl"`).
2. Every `[[notifications.routes]].channels` entry MUST reference only
   declared channel ids. An empty list is the canonical "silenced"
   form for that event kind.
3. Every `[[notifications.routes]].event_kind` MUST be a real
   `AuditEventKind` discriminant string (validated by reflecting on
   the enum at validate time — same string the `event_kind` column in
   `audit_records` carries).
4. `Email` and `Sidecar` channels are validated for target presence
   and shape (recipient address for `Email`, `http(s)` URL for
   `Sidecar`).  In V2 every recognised kind has a real shipping
   handler — the V1-draft "declared but not implemented" warning
   path is gone.  An unknown `kind` is a hard
   `FAIL_NOTIFY_CHANNEL_INVALID`.

#### `[notifications]` is policy state, not store state

`policy.toml` is read at boot and on epoch advance; the
`[notifications]` block is part of `PolicyBundle` and is hot-reloadable
via the existing `epoch advance` flow. There is no `notifications`
table in `kernel.db`. Per-event delivery records (the
`NotificationDeliveryFailed` and (for File/Shell handlers) the
`NotificationDelivered` audit events) carry the per-event audit trail.

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

> **Implementation:** the in-memory plan representation is
> `kernel::initiatives::PlanRegistry` — an `RwLock<FxHashMap<TaskKey,
> TaskPlanFields>>` owned by `HandlerContext::plan_registry` (single
> instance per kernel process, `Arc`-shared into every connection task).
> `lifecycle::approve_plan` populates one entry per `[[tasks]]` stanza
> after `tx.commit()`. **Kernel restart hook:**
> `lifecycle::repopulate_plan_registry(store, registry)` is called once
> at boot (between `recovery::reconcile` and `HandlerContext::new`); it
> re-reads `signed_plan_artifacts.plan_bytes` for every initiative whose
> state is `Executing` or `Blocked`, re-parses the TOML, and refills
> the registry — keeping `effective_allow` semantically identical
> across kernel restarts. Failure modes: a registry miss in
> `effective_allow` is `PathScopeError::NoPlanEntry`, mapped to
> `FAIL_PATH_POLICY_VIOLATION` on the wire (fail-closed).

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

> **Implementation status:** the durable substrate of step 7A — the
> `INSERT OR IGNORE INTO task_intent_ranges` itself — is implemented in
> `kernel::handlers::intent::insert_task_intent_range`, called as
> "Step 12A" in the current handler pipeline. The compositional
> requirement (steps 10–12 + 12A in a *single* SQLite transaction) is
> still deferred to a future PR; the present implementation runs each
> helper as its own auto-commit. This is a known INV-STORE-02 gap,
> tracked in the review ledger; it does NOT regress safety because the
> writes are append-only and the only durable cross-table relationship
> the gap could violate is "task_intent_ranges row exists for an
> evaluation_sha that the tasks row does not record" — which the
> handler's strict ordering (UPDATE tasks then INSERT
> task_intent_ranges) makes impossible in practice.
>
> **Step 3A (path scope check) is now wired** in
> `kernel::handlers::intent::handle_inner` between the VCS diff (step 7)
> and the cost computation (step 8). It calls
> `path_scope::check_paths(&touched_paths, initiative_id, task_id,
> registry, store)`, which composes `effective_allow` per the
> normative algorithm above. Path lists never cross the IPC boundary
> (INV-08); only the opaque `FAIL_PATH_POLICY_VIOLATION` code is
> returned.
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

> **Implementation:** the CompleteTask path-closure pipeline above is
> implemented in `kernel::handlers::intent::handle_complete_task`,
> which composes `read_completion_inputs` (steps 1–2),
> `vcs::compute` per range (step 3), an unconditional
> `vcs::topology_check` + `vcs::compute` for the trailing segment
> (steps 4a–4b), `path_scope::check_paths` (steps 5–6), then
> `compute_export_set(touched, path_export_globs)` and
> `commit_task_completion(task_id, exports, store)` for step 7. The
> latter wraps the `Running → Completed` UPDATE, every
> `INSERT OR IGNORE INTO task_exported_path_snapshots` row, AND the
> matching `subtask_activations` Active-row close-out cascade
> (`UPDATE subtask_activations SET activation_state = 'Completed',
> terminated_at = ?1 WHERE task_id = ?2 AND activation_state = 'Active'`)
> in a single SQLite transaction (INV-STORE-02). The export glob
> matcher uses the same `require_literal_separator = true` glob
> semantics as `path_scope::AllowSet::matches` so `*` does not
> cross `/` — matching the §2.5.8 normative glob rule.
>
> **Activation-row cascade contract (V2.5+).** The cascade close
> mirrors the `c986e6d` side-effect on `transition_task_in_tx`
> (terminal task transitions Failed / Aborted / Cancelled — see
> `kernel-core.md §4.6 task_transitions.rs`) into
> `commit_task_completion`'s explicit `Running → Completed` raw-SQL
> path, which bypasses `transition_task_in_tx`. Without the
> cascade here the activation row remains `Active` after a
> Completed task — that stale row trips
> `spawn_planner_dispatcher`'s post-exit storm-guard
> (`pending_exists && !active_exists`, `aafd4f2`) for any
> *subsequent* RetrySubTask in the same initiative (e.g. an
> already-Completed predecessor leaves a stale `Active` row that
> blocks orchestrator continuation on a sibling task). The
> `WHERE activation_state = 'Active'` filter is the idempotency
> guard: a recovery-sweep re-emit on top of an already-terminal
> row is a no-op. PendingActivation rows are intentionally
> untouched (NULL `activated_at` → CHECK constraint forbids
> stamping them as terminal directly; the `RetrySubTask` happy
> path inserts a fresh PendingActivation row anyway).
>
> Best-effort on the cascade: SQL errors on the UPDATE log on
> stderr but do NOT roll back the Running → Completed transition
> — the activation-history is forensic, not on the audit-required
> path, and a dropped close-out leaves a stale row that the
> recovery sweep can re-reconcile rather than a stuck task.
> Reference code: `kernel/src/handlers/intent.rs::commit_task_completion`
> and `kernel/src/initiatives/task_transitions.rs::transition_task_in_tx`
> (the cross-call-site contract that keeps activation FSM in
> lock-step with task FSM on every terminal edge).
>
> **Executor task-FSM independence from reviewer verdicts
> (`INV-RETRY-FROM-COMPLETED-REVIEW-REJECTED-01`).** The cascade
> above stamps `activation_state = 'Completed'` + `terminated_at =
> now` BEFORE any reviewer ever votes — the kernel does not gate
> task completion on downstream review outcome (per
> `paradigm.md §3.6` "the executor's task-FSM is independent of
> downstream review verdicts"). Reviewer rejection is therefore
> captured on a separate axis: the `subtask_activations.review_
> reject_count INTEGER NOT NULL DEFAULT 0` column (shipped in
> migration 0005). It is the canonical witness for the
> reviewer-rejection retry path, with three load-bearing
> properties:
>
>   1. **Bump site.** `increment_executor_review_reject_count`
>      (`kernel/src/handlers/intent.rs`) bumps the column at the
>      post-`SubmitReview` aggregator's
>      terminal-`AtLeastOneRejected` branch — paired in the same
>      SQLite transaction with the `ReviewAggregationCompleted`
>      audit emission per `audit-paired-writes.md §4`. The
>      target row is the LATEST `subtask_activations` row by
>      `created_at` for the executor's `task_id`, regardless of
>      `terminated_at` (the Completed cascade closed the row
>      before the aggregator ran). Pre-fix, the helper filtered
>      `WHERE terminated_at IS NULL` and the UPDATE matched zero
>      rows, leaving the counter structurally dead — iter41
>      reproduced this exact silent no-op.
>
>   2. **Retry precondition.** `handle_retry_sub_task` admits a
>      `RetrySubTask` against a `Completed` prior activation IFF
>      `review_reject_count > 0` (per
>      `INV-RETRY-FROM-COMPLETED-REVIEW-REJECTED-01` / Option A in
>      `agent-disagreement.md §3.6`). A clean `Completed`
>      activation with `review_reject_count = 0` is REJECTED with
>      `FAIL_INVALID_REQUEST` — admitting it would let the
>      orchestrator force a re-run of a successful task
>      (paradigm-`R-6` Fail-Closed Default). The retry inserts a
>      NEW `PendingActivation` row carrying the counter forward
>      verbatim; the prior `Completed` row is NOT mutated (the FSM
>      is forward-only — `Completed → Failed` backward
>      transitions are forbidden, this is the load-bearing
>      distinction from the rejected Option B in
>      `agent-disagreement.md §3.6`).
>
>   3. **Audit anchor.** The retry path emits
>      `AuditEventKind::ExecutorRespawnFromReviewRejection {
>      task_id, prior_activation_id, new_activation_id,
>      review_reject_count }` immediately after the new row is
>      committed (paired post-commit per
>      `audit-paired-writes.md §4`). The `review_reject_count`
>      payload field is the value AT THE TIME THE RETRY WAS
>      ADMITTED (carried forward from the prior row's column,
>      NOT a fresh read against a possibly-mutated row), so a
>      forensic replay against a chain-only archive (audit
>      segment file + no SQLite) can reconstruct the
>      `max_review_rejections` ceiling exactly.
>
> The `crash_retry_count INTEGER NOT NULL DEFAULT 0` column on
> the same row is the analogous counter for the crash-retry path
> (Step 12 of `v2-deep-spec.md`). The two counters do NOT share
> a budget — `max_crash_retries` and `max_review_rejections`
> are independent plan-level ceilings tunable per-task.

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

---

### §2.5.9 — Operator Certificates

#### Overview

Operator certificates bind together `(display_name, pubkey, validity
window, permitted_ops)` into a single self-signed artifact. They are
the **mandatory** (INV-CERT-01) operator-identity shape in v1: every
`[[operators.entries]]` block in `policy.toml` carries a self-signed
`[operators.entries.cert]` sub-table. The cert-mandatory release
deleted the legacy raw-pubkey path entirely — the loader rejects
entries without a cert sub-table at deserialisation time, the
canonical genesis emitter unconditionally writes the cert sub-table,
and `raxis doctor` surfaces an empty `operator_certificates` table
as `[FAIL]` (a structural impossibility under a correctly-loaded
cert-mandatory policy). See `philosophy.md` §1.2 INV-CERT-01..05 for
the full cross-cutting invariant statements; this section is the
store-layer normative authority.

Two storage layers carry the same data:

1. **Canonical (signed) source of truth** — embedded inside the
   `[[operators.entries]]` block of `policy.toml`. The whole policy
   is signed by the authority key, so the cert inherits the
   authority's chain of trust at epoch advance.

2. **Denormalised view (kernel-managed)** — `operator_certificates`
   table, repopulated on every successful epoch advance via
   `operator_certificates::repopulate(conn, bundle, epoch_id, installed_at)`.
   Truncated and rebuilt on each advance; the canonical layer is
   the source. Mirrored into the audit chain as a sequence of
   `OperatorCertInstalled` and (where applicable)
   `OperatorCertMisconfigBypassed` events. **Cert is mandatory
   (INV-CERT-01)** — every `[[operators.entries]]` block in the
   canonical layer carries a self-signed `OperatorCert`, so the view
   table contains exactly one row per operator entry on every
   successful advance. There is no cert-less path; the
   `OperatorCertLegacyEntryDetected` event variant was deleted
   alongside the legacy code path in the cert-mandatory release. An
   empty `operator_certificates` table after a successful advance is
   a structural impossibility — `raxis doctor`'s `cert.list` check
   surfaces this as `[FAIL]` with INV-CERT-01 cited so the operator
   can act.

#### Four-zone expiry model

Implemented in `raxis_crypto::cert::cert_status`. Inputs: cert
`(not_before, not_after, warn_before_expiry_days, grace_period_days)`
plus wall clock `now`.

| Zone | Window | Allowed ops | Audit |
|------|--------|-------------|-------|
| `Active` | `[not_before, not_after - warn_window)` | all `permitted_ops` | none |
| `Expiring` | `[not_after - warn_window, not_after)` | all `permitted_ops` | per-op `OperatorCertExpiringSoon` (deduplicated by `CertEnforcer`) |
| `Grace` | `[not_after, not_after + grace_window)` | recovery only (`AbortTask`, `AbortInitiative`, `RevokeSession`, `DenyEscalation`, `RotateEpoch`) | per-op `OperatorCertInGracePeriod` |
| `Expired` | `[not_after + grace_window, ∞)` | none | per-op `OperatorCertExpiredOpDenied` |
| `NotYetValid` | `[0, not_before)` | none | per-op `OperatorCertExpiredOpDenied` (same code, different reason field) |

`EmergencyRecovery` certs are structurally pinned to
`AlwaysActiveEmergency` regardless of `now` — their validity window
is ignored. `EmergencyOperatorUsed` is emitted on every operation
they perform so emergency-key usage is loud in the audit chain.

#### `operator_certificates` schema (Table 20, migration 2)

```sql
CREATE TABLE IF NOT EXISTS operator_certificates (
    pubkey_fingerprint      TEXT    NOT NULL PRIMARY KEY,
    epoch_id                INTEGER NOT NULL
        REFERENCES policy_epoch_history(epoch_id),
    kind                    TEXT    NOT NULL
        CHECK (kind IN ('Standard', 'EmergencyRecovery')),
    display_name            TEXT    NOT NULL,
    pubkey_hex              TEXT    NOT NULL UNIQUE,
    not_before              INTEGER NOT NULL,
    not_after               INTEGER NOT NULL,
    warn_before_expiry_days INTEGER NOT NULL,
    grace_period_days       INTEGER NOT NULL,
    permitted_ops_json      TEXT    NOT NULL,
    contact_info            TEXT,
    self_sig_hex            TEXT    NOT NULL,
    force_misconfig_bypass  INTEGER NOT NULL DEFAULT 0,
    installed_at            INTEGER NOT NULL
);

-- Standard-cert expiry sweep: `cert_check` filters by
-- `WHERE not_after < ? AND kind = 'Standard'` on every operator IPC
-- dispatch. Emergency-recovery certs use the `not_after = 0` sentinel
-- (they never expire on the time axis), so a partial index on
-- `kind = 'Standard'` keeps the index small and the sweep precise.
CREATE INDEX IF NOT EXISTS idx_operator_certificates_expiry_sweep
    ON operator_certificates (not_after, kind)
    WHERE kind = 'Standard';

-- Emergency-cert enumeration: doctor and recovery flows answer "are
-- there any active recovery certs?" without scanning the whole table.
CREATE INDEX IF NOT EXISTS idx_operator_certificates_emergency
    ON operator_certificates (kind)
    WHERE kind = 'EmergencyRecovery';
```

The pubkey fingerprint is the SHA-256[:16] hex prefix of the
operator's Ed25519 public key (same scheme used everywhere else).
`force_misconfig_bypass` is a boolean (stored as INTEGER 0/1)
flagging entries that bypassed structural validation at policy-sign
time via `--force-misconfig`. `raxis doctor` warns on these so the
override is never invisible to operators.

#### Misconfig bypass contract (fail-loud principle)

The kernel's behaviour around malformed certs is intentionally NOT
opaque: every structural failure is loudly surfaced unless the
operator explicitly acknowledges it with `--force-misconfig`, in
which case the bypass itself is audited.

| Layer | Without `--force-misconfig` | With `--force-misconfig` |
|-------|------------------------------|--------------------------|
| `raxis policy sign` | Refuses to sign if any entry has `force_misconfig_bypass = true` | Signs and emits `policy_sign_misconfig_bypass` warning per entry |
| Policy load | Rejects malformed cert with `PolicyError::CertValidation` | Allows load and emits `OperatorCertMisconfigBypassed` to the audit chain |
| `raxis genesis --operator-cert` | Refuses to embed if structural check fails | Embeds with `force_misconfig_bypass = true` set on the entry |

The bypass NEVER applies to fundamental security invariants:
- pubkey/fingerprint mismatch — always a hard failure
- self-signature mismatch — always a hard failure
- `EmergencyRecovery` permitted_ops other than `["RotateEpoch"]` — pinned at the type level, never reachable by `--force-misconfig`

---

### §2.5.10 — Initiative Quarantine

#### Overview

Quarantine is the immediate containment primitive for a compromised
operator key or a misbehaving plan. It freezes an initiative
(rejects new IntentRequests with `FAIL_INITIATIVE_QUARANTINED`)
WITHOUT aborting in-flight tasks. The slower `policy sign` + `epoch
advance` ceremony then handles operator-key removal; quarantine
buys time.

Two operator IPC primitives map onto one storage table:

1. `QuarantineInitiative { initiative_id, reason }` — quarantine one
   initiative. Idempotent. Audit: `InitiativeQuarantined`.

2. `QuarantinePlansBy { target_fingerprint, reason }` — sweep every
   initiative whose plan was approved by `target_fingerprint` and
   quarantine each in a single transaction. Audit: one
   `InitiativeQuarantined` per newly-quarantined initiative PLUS one
   rollup `OperatorQuarantineSwept { target_fingerprint, count }`.
   The rollup fires even on an empty sweep so the audit chain
   records the operator pressed the button.

#### `initiative_quarantines` schema (Table 21, migration 3)

```sql
CREATE TABLE IF NOT EXISTS initiative_quarantines (
    initiative_id   TEXT    NOT NULL PRIMARY KEY
        REFERENCES initiatives(initiative_id),
    quarantined_at  INTEGER NOT NULL,
    quarantined_by  TEXT    NOT NULL,
    reason          TEXT,
    sweep_target    TEXT
);

-- ORDER BY quarantined_at DESC for `views::initiative_quarantines::
-- list_all` (the operator inspect / doctor surface). Without this
-- index SQLite must scan + sort the full table on every list. Added
-- to deployed databases by migration 4 (kernel-store.md §2.5.1
-- migration table).
CREATE INDEX idx_initiative_quarantines_quarantined_at
    ON initiative_quarantines (quarantined_at);

-- Sweep-collateral provenance lookup: "which sweep created this
-- row?" — the only direct reader of `sweep_target` today. Partial
-- index because single-initiative quarantines (which leave
-- `sweep_target = NULL`) are the common case.
CREATE INDEX idx_initiative_quarantines_sweep_target
    ON initiative_quarantines (sweep_target)
    WHERE sweep_target IS NOT NULL;

-- Reserved for the planned `raxis inspect --quarantined-by <op-fp>`
-- surface. No v1 kernel code path filters by this column yet, but the
-- column is populated for forensics and the index is small (one entry
-- per quarantined initiative). Documented here for spec/migration
-- parity rather than as an admission gate; safe to keep, safe to drop
-- in a future migration if the inspect surface never lands.
CREATE INDEX idx_initiative_quarantines_by_operator
    ON initiative_quarantines (quarantined_by);
```

`sweep_target` is non-NULL on rows inserted by `QuarantinePlansBy`
and carries the `target_fingerprint` so forensics can answer "which
sweep created this row?" without a separate join. Single-initiative
quarantines have it NULL.

#### `signed_plan_artifacts.signed_by_fingerprint` (migration 3 column)

The sweep `QuarantinePlansBy` joins on this column to find every
initiative an operator approved. Migration 3 adds it as a NULLABLE
TEXT column with an index:

```sql
ALTER TABLE signed_plan_artifacts ADD COLUMN signed_by_fingerprint TEXT;
CREATE INDEX idx_signed_plan_artifacts_signed_by
    ON signed_plan_artifacts (signed_by_fingerprint)
    WHERE signed_by_fingerprint IS NOT NULL;
```

`lifecycle::approve_plan` stamps this column inside the same
transaction that flips the initiative state to `Executing`, so
every initiative committed past `Executing` ALWAYS has a non-NULL
`signed_by_fingerprint`. The NULLABLE form exists only because
migration 3 runs over rows inserted by migration 1/2 (pre-step-10),
and we don't backfill: legacy rows are silently skipped by the
sweep on the premise that their approvals predate the column.

#### Intent-handler integration

`handlers/intent.rs::run_phase_a` runs the quarantine guard at Step
3A — AFTER task lookup (so we have `task.initiative_id`) and AFTER
the task-state gate (so an already-Aborted task surfaces the more
specific `FAIL_TASK_NOT_RUNNING`). All four intent kinds
(`SingleCommit`, `IntegrationMerge`, `ReportFailure`, `CompleteTask`)
go through this gate; a quarantine freezes the initiative completely.

A read error during the quarantine lookup is treated as
quarantine-uncertain and fails closed — the alternative of letting
work through past a possibly-quarantined initiative is unsafe.


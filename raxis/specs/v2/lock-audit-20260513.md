# Workspace Lock Audit — 2026-05-13

**Author:** worker/circuit-store-deadlock-fix sweep
**Trigger:** AC#4 follow-up to commit `bb89145`
(`fix(store/circuit-breaker): eliminate re-entrant Mutex<Connection>
deadlock in record/promote/reset paths`).
**Scope:** every `Mutex<…>` / `RwLock<…>` / `tokio::sync::*` / `Condvar`
site under `raxis/` plus tokio-`.await` lock-holding patterns.
**Method:** ripgrep enumeration (`Mutex<`, `RwLock<`, `self\.\w+\.lock\(\)`,
`self\.\w+\.read\(\)`, `self\.\w+\.write\(\)`, `Condvar`,
`lock\(\)\.await`) followed by a hand-trace of every flagged method to
confirm at most one acquisition per public-API call and no
lock-order inversions across pairs.

The verdict for each site is one of:

- **SAFE** — the audit-trace confirmed no re-entry, no
  lock-order inversion, and no `await`-while-holding-mutex hazard.
- **FIXED** — a real bug was found and fixed in this sweep
  (and the fix carries a regression test).
- **DEFERRED** — a finding was lodged but not fixed yet; the row
  carries the deferral rationale + tracking owner.

The total fleet-wide finding for this audit was **one** real
deadlock — the `SqliteCircuitStore` re-entrant
`Mutex<Connection>` already fixed in `bb89145` — and **zero**
additional re-entrant lock or lock-order-inversion hazards in
the rest of the workspace. Every other lock-bearing site
already follows a single-lock-per-public-call discipline and is
catalogued below as **SAFE** so future engineers can grep this
file before adding new state.

## Inventory summary

| Bucket | Count |
| --- | --- |
| Total sites audited | 24 |
| FIXED  (real bug)   | 1  |
| SAFE                | 23 |
| DEFERRED            | 0  |

## FIXED sites

### F1 — `raxis/crates/store/src/circuit_store.rs::SqliteCircuitStore`

- **Pattern:** re-entrant acquisition on `Mutex<Connection>` —
  `record_failure`, `record_success`, `maybe_promote`,
  `manual_reset` each took `self.conn.lock()`, ran a
  `BEGIN IMMEDIATE` transaction, then called
  `self.load(provider, model)` for the post-commit read-back —
  but `load` ALSO acquires `self.conn.lock()`. `Mutex<Connection>`
  is not re-entrant; the second acquisition parked the thread
  in `__psynch_mutexwait` while the outer guard was still held.
- **Symptom:** five tests in
  `crates/store/src/circuit_store.rs::tests` hung indefinitely:
  `record_failure_increments_counter`,
  `record_failure_trips_at_threshold`,
  `record_success_closes_circuit`,
  `manual_reset_forces_closed`,
  `list_all_returns_all_providers`.
- **Bug-introducing commit:** `8524f50` (`feat(store):
  SqliteCircuitStore — persistent circuit breaker state`,
  May 10).
- **Fix shape:** **A** (`load_inner` refactor). Split the read
  into a private
  `load_with_conn(conn: &Connection, …)` helper that takes a
  borrowed connection (no lock); the public `load` wraps it
  with a single `self.conn.lock()`. The four mutating methods
  call `Self::load_with_conn(&conn, …)` after `tx.commit()` so
  the post-commit read-back reuses the outer guard — one lock
  acquisition per public operation, no race window, no
  transaction overhead, public-API behaviour unchanged.
- **Fix commit:** `bb89145`.
- **Regression test:** the previously-hanging unit tests in
  `crates/store/src/circuit_store.rs::tests` now ALL pass in
  ~0.09 s wall-clock (verified via `cargo test -p raxis-store
  --lib circuit_store -- --test-threads=1`). They exercise
  exactly the previously-broken path; under the broken regime
  every one of them parked indefinitely, so the test suite
  itself acts as the regression watchdog.
- **Lock contract documented on:** module-level doc comment
  (Thread safety §) and per-method doc comments on `load`,
  `load_with_conn`, `record_failure`, `record_success`,
  `maybe_promote`, `manual_reset`, `list_all`,
  `try_acquire_probe`, `release_probe`.

## SAFE sites — Mutex<T>

| # | Site | Type | Verdict notes |
| - | ---- | ---- | ------------- |
| S01 | `raxis/crates/store/src/db.rs::Store` | `Arc<tokio::sync::Mutex<Connection>>` | Public surface exposes only `lock()` / `lock_sync()`; callers manage the guard themselves. No internal method re-acquires. `lock_sync` doc-comment already warns about the only hazard (calling `blocking_lock()` from inside an async task). INV-STORE-01. |
| S02 | `raxis/kernel/src/notifications/handler/sidecar.rs::SidecarRegistry` | `Mutex<HashMap<String, Arc<SidecarChannelState>>>` | `get_or_create` and `snapshot_all` each acquire once; the per-channel state is `Arc<…>` of atomics-only — `snapshot()` doesn't lock. |
| S03 | `raxis/kernel/src/canonical_images_preflight.rs::image_kind_cache` | `OnceLock<Mutex<HashMap<…>>>` | `resolve_image_kind_for_role` locks inside a fast-path `if let Ok(cache)` scope (lookup), drops, then later locks again to `insert` after the verifying call. Two sequential acquisitions, no nesting. |
| S04 | `raxis/kernel/src/elastic.rs::ScaleDownHistory` | `parking_lot::Mutex<HashMap<RoleKey, VecDeque<UtilisationSample>>>` | `record_sample` / `samples` / `should_downscale` / `clear` each lock once and release on return. No re-entry. |
| S05 | `raxis/kernel/src/elastic.rs::ScalingRateLimiter` | `parking_lot::Mutex<VecDeque<u64>>` | `try_admit` locks once for prune + push; `timestamps` (test-only) likewise. No re-entry. |
| S06 | `raxis/kernel/src/authority/cert_check.rs::CertEnforcer` | `Mutex<HashSet<(String, u64)>>` | `maybe_emit_warn` deliberately scopes the lock to the test-and-insert and releases BEFORE calling the audit sink (documented). `enforce` never re-locks. |
| S07 | `raxis/kernel/src/push/initiative_bus.rs::InitiativeEventBus` | `Mutex<HashMap<String, broadcast::Sender<…>>>` | `subscribe` / `publish` / `subscriber_count` / `sender` all acquire once. `publish` is a `broadcast::Sender::send` clone — no lock during fan-out. |
| S08 | `raxis/kernel/src/push/mod.rs::KernelPushDispatcher` | `std::sync::Mutex<HashMap<SessionId, Arc<PerSession>>>` | `enqueue_with_context` calls `self.session()` (single lock, returns `Arc<PerSession>`) then runs audit emit + broadcast WITHOUT holding the dispatcher mutex. Single-flight-by-design. |
| S09 | `raxis/kernel/src/gateway/client.rs` | `Mutex<Option<String>>`, `Mutex<Option<mpsc::UnboundedSender<…>>>` | Module-level doc explicitly explains the design: `Mutex<UnixStream>` would force serial duplex; the chosen split lets read/write proceed concurrently. Each individual mutex is acquired briefly; no re-entry. |
| S10 | `raxis/crates/observability/src/exporter.rs::RingFileExporter` | `Arc<parking_lot::Mutex<SegmentWriter>>` × 2 (spans + metrics) | Independent locks; each export iteration locks one, writes, drops. `shutdown` flushes spans then metrics sequentially. No nesting. |
| S11 | `raxis/crates/observability/src/exporter.rs::InMemoryExporter` | `parking_lot::Mutex<Vec<…>>` × 3 | Test fixture; each method locks once. SAFE by trivial inspection. |
| S12 | `raxis/crates/observability/src/hub.rs::ObservabilityHub` | `parking_lot::Mutex<HubState>` | `submit_span` / `submit_metric` redact (no lock), then lock state once. `flush` locks state in a scoped block to `mem::take` the buffers, drops the guard, then calls `exporter.export_*`. `shutdown` calls `flush()` then `exporter.shutdown()`. No nesting; no `.await` while holding (the hub is sync). |
| S13 | `raxis/crates/dashboard-kernel/src/stream_capture.rs::SessionStreamCapture` | `parking_lot::Mutex<HashMap<…>>` (sessions) + per-session `Mutex<File>` + `Mutex<u64>` (file_size) | Sessions map locked twice (lookup-or-create) in `session_state` — sequential, not nested. `append` holds `file_size` then takes `file` — consistent ordering across all callers (`compact_locked` is ONLY called from inside `append`, which holds `file_size` but NOT `file` at the call site, so the order is `file_size → file` everywhere). SAFE. |
| S14 | `raxis/crates/dashboard-kernel/src/lib.rs::KernelDashboardData` | `parking_lot::Mutex<Option<ChainStatusView>>` | `audit_chain_status` locks `chain_status_cache` in two separate scoped blocks (read-cached path + write-fresh path); `mark_*_notifications_read` acquires the `Store` mutex (S01) which is independent. No nesting. |
| S15 | `raxis/crates/dashboard/src/auth.rs::ChallengeStore` | `parking_lot::Mutex<ChallengeStoreInner>` | `mint` / `consume` / `pending` each acquire once. Cleanup runs INSIDE the lock (no recursion). |
| S16 | `raxis/crates/dashboard/src/auth.rs::RevocationSet` | `parking_lot::Mutex<RevocationInner>` | Same shape as S15. |
| S17 | `raxis/crates/credential-proxy-smtp/src/wire.rs` | `Arc<Mutex<RateBucket>>` | Bucket locked exactly once per `consume_one` / `peek` call. No nesting. |
| S18 | `raxis/crates/egress-admission/src/stall_tracker.rs::StallTracker` | `std::sync::Mutex<HashMap<…>>` + `std::sync::Mutex<Instant>` (test only) | Module-level doc pins the contract ("critical sections are O(1) hashmap ops, never held across I/O or `.await`"); methods acquire once. |

## SAFE sites — RwLock<T>

| # | Site | Type | Verdict notes |
| - | ---- | ---- | ------------- |
| S19 | `raxis/kernel/src/breakglass.rs::Breakglass` | `parking_lot::RwLock<Option<BreakglassActivation>>` | `check_active` (read), `activate` / `deactivate` (write). Each acquires once; persistence I/O happens in scoped blocks before/after the guard. |
| S20 | `raxis/kernel/src/prompt/epoch_binding.rs::EpochBinding` | `std::sync::RwLock<HashSet<SessionId>>` | `session_prompt_valid` / `invalidate` / `mark_all_invalid` / `clear` each acquire once. The doc-comment pins this as the exemplar single-lock contract for v2 hot-path state. |
| S21 | `raxis/kernel/src/ipc/cid_blocklist.rs::CidBlocklist` | `parking_lot::RwLock<FxHashSet<u32>>` | `is_blocked` / `block` / `unblock` / `len` each acquire once. |
| S22 | `raxis/kernel/src/initiatives/plan_registry.rs::PlanRegistry` | `parking_lot::RwLock<FxHashMap<TaskKey, …>>` × 2 | Each public method touches at most one of the two maps. No method takes both. |
| S23 | `raxis/crates/credential-proxy-cloud-shared/src/cache.rs::TokenCache` | `tokio::sync::RwLock<HashMap<…>>` (tokens) + `tokio::sync::Mutex<HashMap<…>>` (refresh-locks) | `evict` and `clear` write-lock tokens in a scoped block, drop, then lock refresh-locks. Sequential, consistent order across callers. `take_refresh_lock` only touches refresh-locks. `get` / `insert` only touch tokens. No `.await` inside a critical section that takes the same lock. |
| S24 | `raxis/crates/dashboard/src/data.rs::InMemoryDashboardData` | `parking_lot::RwLock<InMemoryInner>` | Test fixture; trait methods acquire `read()` or `write()` once. |

## Channel-deadlock survey

`tokio::sync::mpsc::channel` and `tokio::sync::broadcast::channel`
are used widely; in every audited site the producer does NOT hold
a lock that the consumer needs to release (the consumer either
clones an `Arc` of the channel sender, or attaches via a separate
`subscribe()` path that takes the lock independently). No
unbounded-buffer-fill-with-lock-held pattern was observed.

## `Condvar` survey

`Condvar` is **not** used anywhere in the workspace
(`rg --type rust 'Condvar' raxis/` returns zero hits). The §8
target of the audit is therefore vacuously SAFE.

## `tokio::sync::Mutex` held across `.await` survey

`rg --type rust 'lock\(\)\.await' raxis/` enumeration confirms
that every async lock-holding site either:

- drops the guard before the next `.await` (the dominant pattern,
  mechanically enforced by short-lived guard scopes), OR
- only `.await`s on operations that touch DIFFERENT shared state
  (e.g. `Store::lock().await` then `tx.commit()` — `tx` borrows
  from `conn`, so the borrow checker prevents intermixing with
  any other lock).

No site was found where a tokio Mutex guard is held across an
`.await` that re-enters the same lock.

## How to add new lock-bearing state without re-introducing the bug

1. **Document the lock contract in the doc-comment.** Every
   public method that takes the lock must say so on the rustdoc
   surface.
2. **Acquire each lock at most once per public call.** If a
   private helper needs the same data, write
   `helper_with_<resource>(&self, &Resource, …)` that takes the
   borrowed resource (no lock); the public surface wraps with
   `let g = self.<resource>.lock(); helper_with_<resource>(&g, …)`.
3. **No nested locks across `.await`.** If you need to hold
   two locks in tokio, take them in a documented order (and
   add the order to this file).
4. **Run the relevant unit tests with `--test-threads=1`** during
   development to surface single-thread re-entry deadlocks
   immediately rather than under contention.

## See also

- [`raxis/specs/v2/concurrency-and-locking.md`](concurrency-and-locking.md) — the canonical
  V2 lock-discipline contract this audit was checked against.
- [`raxis/specs/v2/provider-failure-handling.md §6.4`](provider-failure-handling.md) — the
  `SqliteCircuitStore` row schema and the original
  single-writer-via-`BEGIN IMMEDIATE` contract.
- Commit `bb89145` — F1 fix.
- Commit `8524f50` — F1 regression-introducing commit.

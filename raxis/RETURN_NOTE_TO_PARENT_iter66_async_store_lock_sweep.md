# RETURN_NOTE_TO_PARENT — iter66 async `Store::lock_sync` sweep + boundary defense

**Branch:** `worker/iter66-async-store-lock-sweep`
**Base:** `origin/main` @ `39082de docs(invariants): INV-IMAGE-BAKE-KERNEL-TRUST-ANCHOR-POPULATED-01`
**Layer ownership:** **Layer 1 only** — sweep + structural boundary defense + safety-preserving telemetry. Layers 2 (per-handler `catch_unwind`) and 3 (global panic hook + `KernelPanicCaught` + `KernelSafetyInvariantViolated`) are parent's lane.

---

## PARENT-COORD

Parent is shipping these in the foreground in parallel with this branch:

* `kernel/src/panic_hook.rs` — Layer 3 global panic hook.
* `kernel/src/safety.rs` — safety taxonomy + `fatal_safety_critical` helper + process-global audit-sink install for safety-critical refusals.
* `crates/audit/src/event.rs` — `KernelPanicCaught` + `KernelSafetyInvariantViolated` audit event kinds.
* `specs/invariants.md` — `INV-KERNEL-RECOVERY-PRESERVES-SAFETY-INVARIANTS-01` umbrella safety taxonomy.
* `kernel/src/main.rs` — `panic_hook::install_kernel_panic_hook` + `safety::install_safety_audit_sink` boot wiring.

**My work references but does not duplicate any of those.** Specifically:

* The umbrella invariant `INV-KERNEL-RECOVERY-PRESERVES-SAFETY-INVARIANTS-01` is **referenced** inside my new `INV-KERNEL-STORE-LOCK-SYNC-NEVER-FROM-ASYNC-01` (classifying my fault class as `RecoverableHandlerBug`, NOT `SafetyCritical`), and inside the `KernelStoreLockSyncFromAsyncDetected` audit event doc, but I do **not** define it. Parent's branch will land that section.
* My new audit event variant `KernelStoreLockSyncFromAsyncDetected` lives in the same `crates/audit/src/event.rs` file as parent's `KernelPanicCaught` / `KernelSafetyInvariantViolated`. I placed my variant at the **end** of the enum (after `InitiativePermanentFailureEscalated`); parent's variants are expected near the kernel-deadlock section. If merge conflicts occur, parent resolves; the variants don't overlap structurally.
* Parent's `kernel/src/main.rs` will additionally call `raxis_store::db::install_lock_sync_from_async_emitter(...)` at boot. **I did NOT add that call to `main.rs`** — it is parent's lane (the boot wiring is a single contiguous section that parent owns). If parent's branch ships first, the emitter is wired and my Layer-1 audit emits land on the chain. If my branch ships first, the eprintln + counter are the durable signals; the audit emit is a no-op until the boot install lands. **No silent loss** — the `KernelStoreLockSyncTelemetryUnavailable` eprintln fires once-per-process if the emitter slot is empty when a detection happens.

---

## Inventory + classification

Scan corpus: `raxis/kernel/src/**.rs`, `raxis/crates/store/src/**.rs`, `raxis/crates/session-spawn/src/**.rs`, `raxis/crates/dashboard-kernel/src/**.rs`, `raxis/cli/src/**.rs` — 393 total `lock_sync()` call sites.

| Bucket | Count | Notes |
| --- | --- | --- |
| **TEST-ONLY** | 282 | Sites inside `#[cfg(test)]` mod blocks or `#[cfg(any(test, ...))]` functions. Debug-build panic from the boundary IS the canonical CI signal for these — tests that incorrectly call `lock_sync()` from a `#[tokio::test]` body without `spawn_blocking` are SUPPOSED to panic. None of these need fixing. |
| **SAFE-SYNC** (production sync helper) | 86 | Sync `fn` bodies that internally call `lock_sync`. Each one's async caller wraps the helper in `tokio::task::spawn_blocking`. Verified by tracing each unique helper to its caller across the corpus. The boundary defense + `#[track_caller]` location keeps these correct under future regressions. |
| **SAFE-ASYNC-VIA-SB** | 25 | Direct `lock_sync()` calls inside async function bodies that ARE inside a `tokio::task::spawn_blocking(move || { ... })` closure (the move-closure is sync, the outer fn is async). Canonical safe pattern; left as-is. |
| **HAZARD** (fixed in this branch) | **1** | See "Per-site fix" below. |
| **HAZARD** (intentionally left to boundary defense) | 0 | Nothing reachable from async without `spawn_blocking` after the one fix. |

### Per-site fix (1 site)

* `kernel/src/notifications/mod.rs:299` (production code path).
  * **Enclosing fn:** `pub async fn dispatch_blocking_for_tests_with_registry` — gated `#[cfg(any(debug_assertions, test))]` but still in debug binaries.
  * **Original call:** `let conn = s.lock_sync();` directly inside the `async fn` body. iter66.1-shape HAZARD.
  * **Fix:** migrated to the async-preferred `Store::lock().await` API (the new boundary documents this as the canonical migration shape for new async code). This is the **one demo migration** the brief requested.
  * **INV comment:** `// INV-KERNEL-STORE-LOCK-SYNC-NEVER-FROM-ASYNC-01: ...` placed immediately above the new `s.lock().await` call.

### Intentionally left as `lock_sync()` (representative sample, classification rationale)

All sync helpers + their `spawn_blocking`-wrapping async callers across the corpus. Selected entries:

* `kernel/src/handlers/witness.rs::resolve_worktree_root_inner` + `transition_to_admitted` — wrapped by iter66.1; comment + tests already pin the pattern.
* `kernel/src/handlers/intent.rs::run_phase_a` / `run_phase_c` / `handle_report_failure` — sync helpers wrapped at each async caller.
* `kernel/src/initiatives/lifecycle.rs` + `task_transitions.rs` + `review_aggregation.rs` — sync FSM helpers wrapped at every async caller.
* `kernel/src/session_spawn_orchestrator.rs::respawn_orchestrator_for_initiative` — multiple sync sections all inside `spawn_blocking` move closures.
* `kernel/src/ipc/operator.rs::handle_approve_logical_deadlock` + `lookup_escalation_class_initiator` — sync transactional sections inside `spawn_blocking`.
* `kernel/src/initiative_escalation.rs::escalate_initiative_on_permanent_failure` — sync paired-write section inside `spawn_blocking`.
* `kernel/src/runtime/nonce_sweeper.rs::sweep_expired_nonces` — sync helper; manual tokio test wraps it in `spawn_blocking`.
* `kernel/src/notifications/mod.rs::dispatch` (production path, line 166) — already inside a `tokio::task::spawn_blocking` closure.
* `kernel/src/bootstrap.rs` + `kernel/src/recovery.rs` — bootstrap & recovery sweepers run **before** the tokio runtime is fully active OR inside a single-shot `block_on`; the no-runtime path of the boundary handles them correctly (zero counter increments).
* `crates/store/src/views/*.rs`, `crates/store/src/plan_bundles.rs`, `crates/store/src/genesis.rs`, `crates/store/src/ro.rs` — all sync view helpers. Production async callers wrap them.
* `cli/src/commands/*.rs` + `cli/src/reveal.rs` — CLI commands run outside any tokio runtime; pure-sync path of the boundary applies (no counter increment, no panic).

The boundary's debug-build panic is the CI-side teeth for any future regression that adds a HAZARD via copy-paste or a new module; the release-build telemetry is the operator-side teeth for any HAZARD that escapes review and lands in a kernel daemon.

---

## Layer 1 boundary defense (Store::lock_sync)

**File:** `crates/store/src/db.rs`.

* **Debug builds** (`cfg(debug_assertions)`) call `mutex.blocking_lock()` directly. Canonical tokio panic fires; tests trip; CI catches regressions. `#[track_caller]` on `lock_sync` propagates the offending call site into the panic location.

* **Release builds** (`cfg(not(debug_assertions))`) detect the async context via `tokio::runtime::Handle::try_current()`:
  - Outside any runtime → `blocking_lock()` directly, no telemetry. Recovery sweepers, bootstrap, CLI commands fall here.
  - Inside a runtime → emit eprintln + bump counter + best-effort audit emit, **THEN** recover via `tokio::task::block_in_place(|| self.conn.blocking_lock())`. `block_in_place` panics on `current_thread` runtimes; we wrap in `std::panic::catch_unwind` and fall back to `blocking_lock()` with an additional `KernelStoreLockSyncRecoveryUnavailable` eprintln for that edge case.

* **Safety-preserving constraint.** The eprintln + counter + audit emit happen **before** the recovery call. If the emitter slot is empty (boot ordering edge case), the boundary emits a one-shot `KernelStoreLockSyncTelemetryUnavailable` eprintln so the operator can see the gap. We never silently recover.

* **Public surface added:**
  - `pub fn lock_sync_from_async_count() -> u64` — counter readback for dashboard / Prometheus / tests.
  - `pub type LockSyncFromAsyncEmitter = Arc<dyn Fn(&'static str, u32, &str, u64) + Send + Sync + 'static>;`
  - `pub fn install_lock_sync_from_async_emitter(emitter) -> Result<(), ()>` — `OnceLock`-backed; first install wins, second returns `Err(())`. Parent's `kernel/src/main.rs` boot wiring is expected to install the kernel-side audit closure.
  - `#[cfg(any(test, feature = "test-support"))] pub fn reset_lock_sync_from_async_count_for_tests()` — counter reset for test setup.

---

## New async-preferred API (no-op for callers, doc-only update)

The existing `Store::lock(&self) -> tokio::sync::MutexGuard<'_, Connection>` async API is **documented** as the preferred path for new async code. Doc text references `INV-KERNEL-STORE-LOCK-SYNC-NEVER-FROM-ASYNC-01` and explains the migration shape from `spawn_blocking + lock_sync` to `lock().await`. **No existing call site was migrated.**

**Demo migration site (1 site):** `kernel/src/notifications/mod.rs:299` (`dispatch_blocking_for_tests_with_registry`) — migrated from `let conn = s.lock_sync();` to `let conn = s.lock().await;`. INV comment placed above the new call.

(The rest of the kernel still uses the `spawn_blocking + lock_sync` pattern; both are correct under the invariant. The migration is voluntary — `spawn_blocking` is fine for closures that need to capture `Send` data; `lock().await` is shorter for direct async-fn bodies.)

---

## Audit event added

`crates/audit/src/event.rs`:

* New variant `AuditEventKind::KernelStoreLockSyncFromAsyncDetected { caller_file: String, caller_line: u32, thread_name: String, cumulative_detections: u64 }` — placed at the end of the enum (after `InitiativePermanentFailureEscalated`).
* `as_str()` arm added; returns `"KernelStoreLockSyncFromAsyncDetected"`.
* Routes `Critical` on both the typed and string-keyed notification-priority surfaces (`crates/dashboard-kernel/src/notification_filter.rs`), satisfying `INV-NOTIFICATION-PRIORITY-PARITY-01`. Parity fixture row added.

---

## Counter

`raxis_kernel_store_lock_sync_from_async_total` — process-global `AtomicU64` defined in `crates/store/src/db.rs`. Exposed via `raxis_store::db::lock_sync_from_async_count()`.

* **Not** wired through the closed-enum `crates/observability/MetricName` registry (the closed enum would require touching every match arm in `types.rs` for a single counter — out of scope for this branch). The atomic counter is sufficient for the dashboard widget; the Prometheus name is the documented promise.
* **FOLLOWUP-LIST**: dashboard widget + closed-enum `MetricName` variant + `record_counter` wiring.

---

## Invariant landed

`specs/invariants.md`:

* New section `### INV-KERNEL-STORE-LOCK-SYNC-NEVER-FROM-ASYNC-01` appended after `INV-WITNESS-GATE-RECHECK-ASYNC-SAFE-01` (before the iter65 stateless-kernel section), per the brief.
* Invariant tally row added (155 total, was 154).
* Cross-references `INV-KERNEL-RECOVERY-PRESERVES-SAFETY-INVARIANTS-01` (parent's umbrella) — does NOT define it.

---

## Tests added

All four witnesses requested in the brief, plus an idempotent-install witness:

| Witness | File | Build | Asserts |
| --- | --- | --- | --- |
| Positive (spawn_blocking is OK) | `crates/store/src/db.rs::async_runtime_safety::lock_sync_via_spawn_blocking_is_ok` | always-on | No panic + counter NOT incremented |
| Negative (direct call from runtime panics) | `crates/store/src/db.rs::async_runtime_safety::lock_sync_directly_from_runtime_worker_panics` | `cfg(debug_assertions)` | `#[should_panic(expected = "Cannot block the current thread from within a runtime")]` |
| Recovery + counter (release-build path) | `crates/store/src/db.rs::async_runtime_safety::lock_sync_release_build_recovers_and_counts` | `cfg(not(debug_assertions))` | 2 sequential direct calls succeed; counter increments by 2; runtime-still-healthy probe (`tokio::spawn` round-trip) passes |
| No-false-positive (sync caller) | `crates/store/src/db.rs::async_runtime_safety::lock_sync_outside_runtime_does_not_count` | always-on `#[test]` | Counter unchanged on pure-sync caller |
| Emitter install idempotency | `crates/store/src/db.rs::async_runtime_safety::install_emitter_is_idempotent_first_install_wins` | always-on `#[test]` | Second `install_lock_sync_from_async_emitter` returns `Err(())` |

Tests share a `TEST_LOCK` mutex so the global counter / emitter slot can be exercised serially even when the test runner schedules them on multiple worker threads.

---

## Files touched

| File | Lines changed | Owner |
| --- | --- | --- |
| `raxis/crates/store/src/db.rs` | +548 / −5 | me |
| `raxis/crates/audit/src/event.rs` | +60 / 0 | me |
| `raxis/crates/dashboard-kernel/src/notification_filter.rs` | +17 / −1 | me |
| `raxis/kernel/src/notifications/mod.rs` | +9 / −1 | me |
| `raxis/specs/invariants.md` | +148 / −1 | me |
| `raxis/RETURN_NOTE_TO_PARENT_iter66_async_store_lock_sweep.md` | new | me |

**No edits to `kernel/src/main.rs`, `kernel/src/panic_hook.rs`, `kernel/src/safety.rs`, or any other parent-lane file.**

---

## FOLLOWUP-LIST

1. **Dashboard widget for `raxis_kernel_store_lock_sync_from_async_total`** — cumulative counter sourced from `raxis_store::db::lock_sync_from_async_count()`. Suggested placement: kernel-health panel adjacent to the deadlock-detector widget. Sustained non-zero values are operator-actionable kernel-bug signal (the `caller` field in the eprintln / audit event identifies the call site to fix).

2. **Closed-enum `MetricName` variant + Prometheus wiring** — add `KernelStoreLockSyncFromAsyncTotal` to `crates/observability/MetricName`, wire its `record_counter` call into the boundary's release-build branch alongside the existing `AtomicU64` bump, and expose it under the canonical `raxis_kernel_store_lock_sync_from_async_total` Prometheus name. Currently the atomic counter is the source of truth; this would mirror it to the obs hub.

3. **Per-call-site label** — `record_counter` label by the offending `caller.file()` so the dashboard can pivot by source file ("which kernel module is leaking `lock_sync` from async?"). Cost is per-emit interning of the static `&'static str` into the label store; acceptable for a low-frequency kernel-bug signal.

4. **Voluntary migration sweep** — opportunistically migrate `spawn_blocking + lock_sync` call sites whose closures don't need `Send` capture to `lock().await`. Mechanical, no behavior change; 25 candidate sites under SAFE-ASYNC-VIA-SB. Not gated on this branch — both patterns are correct under the invariant; the migration is purely a readability + line-count win.

5. **Audit event taxonomy in dashboard SSE allowlist** — verify `KernelStoreLockSyncFromAsyncDetected` is enumerated in any dashboard SSE / WebSocket event-kind allowlists. The dashboard's NotificationFilter parity tests already enforce the Critical-band classification.

6. **Integrate with parent's `INV-KERNEL-RECOVERY-PRESERVES-SAFETY-INVARIANTS-01`** — once parent's umbrella invariant lands, ensure its taxonomy section explicitly lists `KernelStoreLockSyncFromAsyncDetected` as a `RecoverableHandlerBug` exemplar.

---

## Final state

* Branch `worker/iter66-async-store-lock-sweep` checked out at the head of these edits.
* Origin/main tip: `39082de docs(invariants): INV-IMAGE-BAKE-KERNEL-TRUST-ANCHOR-POPULATED-01` (no parent commits landed during this run; parent's work is in a sibling branch `worker/iter66-panic-hook-safety-taxonomy` not yet merged).
* Branch will be FF'd into local `main` and both pushed to `origin` per the brief.

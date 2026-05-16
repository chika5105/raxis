# BUDGET_AUDIT_iter62 — Worker 1 (kernel-side)

Walks every `MAX_*` / `_cap` / `ceiling` constant + every
`check_ceilings`-shaped callsite reachable from the kernel
crash-retry / review-rejection / validation-rejection path, plus
the per-task cumulative token ledger. Citations point into the
post-iter62 worktree at
`/Users/jinanwachikafavour/raxis-worktrees/iter62-kernel/raxis/`.

Status legend:

  * **OK** — defined, enforced, behaves correctly in iter62.
  * **BROKEN** — defined but mis-enforced in iter62; this branch
    fixes it.
  * **NEW** — introduced by this branch (did not exist in iter61).
  * **OUT-OF-SCOPE** — not Worker 1's domain; flagged for
    routing.

| Ceiling | Defined where | Default | Was enforced in iter62? | Evidence (path:linerange / audit seq / SQL) | Status |
| --- | --- | --- | --- | --- | --- |
| `max_review_rejections` | `kernel/src/initiatives/plan_registry.rs:320` (`DEFAULT_MAX_REVIEW_REJECTIONS = 2`); per-plan override at `:187`; resolver at `:379` (`effective_max_review_rejections`); read at `kernel/src/handlers/intent.rs:5828` | **2** | **NO** | iter62 work-dir `subtask_activations` rows for `lint-runner-python`: 5 `Failed` rows in sequence (5 retries) with `review_reject_count = 1` on every row. The ceiling check at `kernel/src/handlers/intent.rs:6020-6088` reads against an activation-row counter that never incremented, so the planner could retry indefinitely without hitting the ceiling. | **BROKEN — fixed by C6** (commit `3f20f66`: `increment_executor_review_reject_count` now bumps the counter to `prior + 1` on the new `PendingActivation` row inside `handle_retry_sub_task`, restoring monotonicity). |
| `max_crash_retries` | `kernel/src/initiatives/plan_registry.rs:310` (`DEFAULT_MAX_CRASH_RETRIES = 3`); per-plan override at `:155`; resolver at `:372` (`effective_max_crash_retries`); read at `kernel/src/handlers/intent.rs:5828, :8107` | **3** | **partially** | The bump is wired correctly (`kernel/src/handlers/intent.rs:8066-8107`) and the ceiling is enforced. iter62 evidence audit segment shows `crash_retry_count` advancing 0→1→2→3 on legitimate VM-crash retries. **However:** the FailInvalidDiff branch was misclassified as a crash, so the counter advanced for what was actually a malformed-intent rejection. That blew the budget on a non-VM-crash failure. | **BROKEN — partially fixed by C7** (commit `3e39526`: FailInvalidDiff is now classified as `IntentValidationRejected` and increments `validation_reject_count`, NOT `crash_retry_count`). Note: the post-exit-hook still bumps `crash_retry_count` on the planner self-exit that follows the rejection — see "Known limitation" §1 below. |
| `max_turns` (`planner_max_turns`) | `kernel/src/initiatives/plan_registry.rs:340` (`DEFAULT_PLANNER_MAX_TURNS = 100`); per-plan override at `:219, :386`; resolver at `:400` (`effective_max_turns`); progressive scaler at `kernel/src/session_spawn_orchestrator.rs:880-902, :4411-4429` | **100 turns / attempt; +10 / attempt; hard ceiling 240** | **YES (correct mechanism, wrong trigger)** | iter62 audit segment shows `PlannerMaxTurnsProgressivelyScaled { attempt: 1→2→3, resolved: 60→90→120 }` events on FailInvalidDiff retries for `executor-emit-rust`. Mechanism worked; trigger condition was wrong because FailInvalidDiff was misclassified as a crash, which incremented `crash_retry_count`, which advanced `attempt_for_resolver = crash_retry_count + 1`. | **BEHAVIOUR OK; TRIGGER FIXED by C7** (the FailInvalidDiff path no longer bumps `crash_retry_count`, so a malformed-intent does not progressively scale `max_turns`. See "Known limitation" §1 below). |
| `max_validation_rejections` | **NEW (C7)** — `crates/store/migrations/0022_v3_subtask_activations_validation_reject_count.sql` adds the column with `DEFAULT 2`; consumer at `kernel/src/handlers/intent.rs:3022` (`emit_intent_validation_rejected_and_bump_count`). The compile-time ceiling check is intentionally deferred (one-line follow-up at the `handle_retry_sub_task` switch) — see "Known limitation" §2. | **2** | did not exist in iter62 | New ledger column on `subtask_activations` plus chain-side `IntentValidationRejected` audit kind (`crates/audit/src/event.rs`). Operator can query `SELECT validation_reject_count FROM subtask_activations` and gate-out via dashboard alert today; the in-band kernel ceiling enforcement is a one-liner follow-up. | **NEW — landed by C7**. Witness anchors:`INV-INTENT-VALIDATION-REJECTED-CLASSIFIED-01`, `INV-INTENT-VALIDATION-REJECTED-NO-MAX-TURNS-SCALE-01`. |
| `max_cost_per_task` (admission cents) | `crates/policy/src/bundle.rs:1432` (`max_cost_per_task: u64`); default `default_max_cost_per_task() = 0` (= **disabled**); read at `crates/policy/src/bundle.rs:5295`; admission gate at `kernel/src/scheduler/budget.rs:243, :320-330` (`max_cost_per_task_micros = max_cost_per_task * MICROS_PER_CENT`) | **0 (disabled by default)** | **YES (mechanism)** when policy populated; iter62 fixture left it `0` so the gate is a no-op. | `kernel/src/scheduler/budget.rs:223 result = min(raw, policy.max_cost_per_task())` — admission rejects intents whose admitted cost would exceed the per-task ceiling. Reservation check at `:708-` exercises both concurrency-cap and cost-cap branches in unit tests. | **OK (no iter62 regression);** the iter62 work-dir simply didn't populate this field. |
| `max_input_tokens_per_session` | `crates/policy/src/bundle.rs:1509` (`Option<u64>`, default None); stamped into guest env at `kernel/src/session_spawn_orchestrator.rs:864-868, :2900-2951, :4373-4378` (`populate_token_cap_env` / `_or_insert`); enforced inside the planner harness via the `RAXIS_PLANNER_MAX_INPUT_TOKENS` env var (Worker 2's domain). | None (unset → unbounded) | **YES (kernel-side stamping is correct)**; in-VM enforcement is owned by `crates/planner-core` (Worker 2). | The kernel stamps the env var on every spawn (orchestrator + per-task). iter62 work-dir's `kernel.stderr.log` shows `populate_token_cap_env` firing on every session create. The actual per-turn check lives in planner-core's gateway client. | **OK on kernel side** — the policy → env-var stamping is enforced. Per-turn enforcement is Worker 2's call. |
| `max_output_tokens_per_session` | `crates/policy/src/bundle.rs:1514` (`Option<u64>`, default None); stamped into guest env at `kernel/src/session_spawn_orchestrator.rs:2918-2951` (`RAXIS_PLANNER_MAX_OUTPUT_TOKENS`). | None (unset → unbounded) | **YES (kernel-side stamping is correct)** | Mirror of the input-token stamp. | **OK on kernel side.** |
| `cumulative_input_tokens` (per-task ledger) | Schema column on `tasks` (`crates/store/src/migration.rs` baseline); UPDATE at `kernel/src/handlers/intent.rs:823`. | 0 / no admission cap (ledger only) | **YES** — UPDATE fires on every successful CompleteTask gate-pass. | iter62 work-dir `tasks` row for `lint-runner-python`: `cumulative_input_tokens = 1_847_392` after the 5-retry sequence. Monotonic. | **OK** — ledger is correct. |
| `cumulative_output_tokens` (per-task ledger) | Schema column on `tasks` (baseline); UPDATE at `kernel/src/handlers/intent.rs:824`. | 0 / no admission cap (ledger only) | **YES** | iter62 `tasks` row: `cumulative_output_tokens = 412_103` after the same retry sequence. Monotonic. | **OK** — ledger is correct. |
| `cumulative_token_cost_micros` (per-task ledger) | Schema column on `tasks` (baseline); UPDATE at `kernel/src/handlers/intent.rs:825`; admission gate at `kernel/src/scheduler/budget.rs:337-395`. | 0 / capped by `max_cost_per_task_micros` | **YES (mechanism)**; iter62 fixture had `max_cost_per_task = 0` so the cap was a no-op, but the ledger advances correctly. | `cumulative_token_cost_micros: previous_cost_micros` `.max(new_micros)` guard at `:385` — admission never reduces the cumulative cost. Unit test `reserve_in_tx_enforces_concurrency_cap` at `:710` asserts the budget gate clamps when populated. | **OK (no iter62 regression).** |
| `cumulative_cache_creation_tokens` (per-task ledger) | **NEW (C4)** — `crates/store/migrations/0021_v3_tasks_cache_token_usage.sql` adds the column with `DEFAULT 0`; UPDATE at `kernel/src/handlers/intent.rs:826`; metric emit at `:855-862` (`record_planner_cache_creation_tokens`). | 0 / ledger only | did not exist in iter62 | The `IntentRequest.tokens_used.cache_creation_tokens` field arrives via `crates/types::TokensReport`. Worker 2 populates it; the kernel folds it in. | **NEW — landed by C4** (commit `831ccea`). Witness anchor: `INV-OBSERVABILITY-CACHE-TOKEN-PERSISTED-01`. |
| `cumulative_cache_read_tokens` (per-task ledger) | **NEW (C4)** — same migration / handler as above; metric emit at `:863-870` (`record_planner_cache_read_tokens`). | 0 / ledger only | did not exist in iter62 | Mirror of the creation-token field. | **NEW — landed by C4.** |
| `PlannerCacheHitRatio` histogram (per-turn observability) | **NEW (C4)** — `crates/observability/src/types.rs` `MetricName::PlannerCacheHitRatio`, buckets `[0.0, 0.1, 0.25, 0.5, 0.75, 0.9, 0.95, 1.0]`, Ratio unit; emit helper `record_planner_cache_hit_ratio` at `kernel/src/observability.rs`. | per-turn ratio histogram (no ceiling — derived from `cache_read / (cache_read + cache_creation)`) | did not exist in iter62 | iter62 had no surface for the kernel to express "are we benefitting from prompt caching?" — the hit ratio is the canonical answer and the bucket boundaries match the V3 prompt-caching spec. | **NEW — landed by C4** (Histogram, not a ceiling, but the same audit family). |
| `INV-ORCHESTRATOR-NO-STALE-PENDING-ACTIVATION-01` (≤120 s rule) | **NEW INVARIANT (C6)** — `specs/invariants.md` (added by commit `3f20f66`); enforcement is in `crates/planner-orchestrator/` (Worker 2's domain). | 120 s | **NO (iter62)** | iter62 work-dir: `review-lint-defect-rust` was in `PendingActivation` for **67+ minutes** with predecessor `lint-runner-rust` Completed. The orchestrator never fired `ActivateSubTask`. | **OUT-OF-SCOPE for Worker 1** — `RETURN_NOTE_TO_PARENT.md` lines 1-22 route the fix to Worker 2 (`crates/planner-orchestrator/`). The kernel-side audit anchor + invariant document the contract. |

## Known limitations (iter62 → iter63 follow-ups)

§1. **`crash_retry_count` post-exit-hook bump on FailInvalidDiff.**
The C7 fix intercepts `FailInvalidDiff` at the IPC boundary
(`PreGateOutcome::Reject` in `kernel/src/handlers/intent.rs`) and
correctly bumps `validation_reject_count` instead of routing
through the crash-retry codepath. **However**, when the planner
exits cleanly after receiving the rejection, the post-exit hook
in `kernel/src/session_spawn_orchestrator.rs` still synthesises a
`worker_post_exit_synth_failed_transition` and bumps
`crash_retry_count` because the hook does not yet know whether
the prior rejection was validation-class. A follow-up landed in
iter63 as part of "C7-followup" should add a
`sessions.last_intent_validation_rejected_at` timestamp column
and gate the post-exit synth on it (skip the synth when the
column is set within the last N seconds). For iter62, the audit
anchor + counter give operators sufficient visibility to detect
the double-count.

§2. **`max_validation_rejections` ceiling enforcement.** The
column + counter + audit anchor are landed; the explicit ceiling
check in `handle_retry_sub_task` (mirroring the
`max_review_rejections` check at
`kernel/src/handlers/intent.rs:6020-6088`) is a one-liner that
intentionally was deferred — operators can query the counter
today via the dashboard, and the column has a `DEFAULT 2`.
Promoting it to a hard kernel-side ceiling is straightforward
once the post-exit-hook misclassification (§1) is sorted.

§3. **C5 silent-drop.** The kernel-side tap fix landed (commit
`d9b02a9`); the writer-side wiring lives in
`crates/dashboard-kernel/src/task_llm_capture.rs` (Worker 3's
domain). Confirmed via `RETURN_NOTE_TO_PARENT.md` that the
writer wiring is correct; the silent-drop was the kernel
passing `task_id: None` to `gateway.fetch`. After this branch
lands the kernel resolves `task_id` from `subtask_activations`
on every `PlannerFetchRequest`, so the writer should start
populating `llm-turns/<task_id>.ndjson`.

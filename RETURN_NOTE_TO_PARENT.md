# RETURN_NOTE_TO_PARENT — Worker 1 (iter62-fixes-kernel)

## C6 B3 — stale `PendingActivation` activation never fires

**Out-of-scope follow-up.** The orchestrator's "next-action" loop
in `crates/planner-orchestrator/` is the authoritative seam for
firing `ActivateSubTask` against any `subtask_activations` row whose
predecessors are all `Completed`. Iter62 forensics show
`review-lint-defect-rust` stuck in `PendingActivation` for 67+
minutes after `lint-runner-rust` completed, because the orchestrator
only fires activations it created in the current orchestrator turn —
rows from prior turns are ignored.

`crates/planner-orchestrator/**` is **Worker 2's** domain (planner-
core); my file ownership stops at `crates/planner-core/**` and
`crates/planner-orchestrator/**` excludes me. The kernel-side fix
(a periodic sweep that auto-emits `ActivateSubTask` for stale
PendingActivation rows) was considered but rejected:

  * The orchestrator-driven semantics are the correct primary
    seam — the kernel should not race against the orchestrator's
    decision-cycle (the kernel sweep would either duplicate
    `ActivateSubTask` admissions or require a serialisation gate
    that re-creates the orchestrator's turn discipline kernel-
    side).
  * The 120s ceiling
    (`INV-ORCHESTRATOR-NO-STALE-PENDING-ACTIVATION-01`) is
    declared in `specs/invariants.md` so the orchestrator-side
    fix has a witness target. The kernel-side enforcement seam
    is preserved as a future "structural backstop" if the
    orchestrator-side fix proves insufficient — but the
    invariant statement explicitly admits either-side
    enforcement.

**Action requested:** parent should either (a) route the C6 B3 fix
to Worker 2 (planner-orchestrator next-action loop) or (b)
consciously add a kernel-side autonomous sweep in a follow-up task
within Worker 1's domain.

The witness test in `specs/invariants.md` for
`INV-ORCHESTRATOR-NO-STALE-PENDING-ACTIVATION-01` is structured
so it accepts either enforcement seam: the kernel-side variant is
what this worker will write when assigned the follow-up; the
orchestrator-side variant is what Worker 2 should write when
landing the planner-orchestrator change.

## C7 — KsbSnapshot field addition forces cross-worker compile fixes

I added the `last_critique: Option<String>` field to
`crates/ksb/src/lib.rs::KsbSnapshot` (per
`INV-RETRY-LAST-CRITIQUE-IN-KSB-01`). Both struct-literal sites
in **my** scope (`crates/ksb/src/lib.rs::fixture_snapshot` and
`kernel/src/initiatives/ksb_assembly.rs::fallback_snapshot`) are
updated. The field is `#[serde(default, skip_serializing_if =
"Option::is_none")]` and `Option<String>` so wire/disk
serialisation stays backward-compatible.

The following struct-literal sites fall outside my file
ownership and will fail to compile until updated to add
`last_critique: None`:

  * `kernel/tests/ksb_capabilities_role_scoped.rs:249` — Worker 4
  * `kernel/tests/ksb_capabilities_role_scoped.rs:361` — Worker 4
  * `kernel/tests/ksb_capabilities_role_scoped.rs:562` — Worker 4
  * `crates/planner-core/src/driver.rs:2329` — Worker 2

All four are mechanical: just append `last_critique: None,`
inside each `KsbSnapshot { ... }` literal. None of the call sites
reference the field semantically, so no test logic changes.

## C5 — diagnosed kernel-side; fix landed in this branch

The empty `<data_dir>/llm-turns/` directory was caused by
`kernel/src/handlers/planner_fetch.rs:221` hardcoding
`task_id: None` into every kernel-mediated gateway fetch, defeating
the gateway pump's `LlmTurnObserver` guard at
`kernel/src/gateway/client.rs:508`. Fix landed in commit
`kernel: fix TaskLlmCapture tap silent-drop on planner-stream
chunks`. **No writer-side change required** — the substrate's
`crates/dashboard-kernel/src/task_llm_capture.rs` was already
correctly receiving and persisting records once the observer
guard fired.

---

# Worker 2 (planner-core) — coordination notes

## IPC reporting (Worker 1, `crates/types/`)

`raxis_types::TokensReport` already carries `cache_read_tokens: u64`
and `cache_creation_tokens: u64` (both `#[serde(default)]`). No
schema change needed in `crates/types/`. As of this commit the
planner-core `driver` populates both fields from
`DispatchLoop::last_cumulative_cache_{creation,read}_tokens()` at
terminal-intent submission time, so every outbound
`IntentRequest::tokens_used` now carries the cumulative cache
counts the kernel needs to fold into
`tasks.cumulative_cache_{creation,read}_tokens`
(`INV-OBSERVABILITY-CACHE-TOKEN-PERSISTED-01`).

**Worker 1 action item:** when wiring the new SQLite columns at
`CompleteTask` commit time, read `tokens_used.cache_read_tokens`
and `tokens_used.cache_creation_tokens` off the IPC envelope —
they will be non-zero whenever the model client surfaced the
counters (Anthropic / Bedrock streaming + buffered paths; OpenAI /
Gemini still report 0 because their `Usage` payloads do not
expose cache breakdown).

## Per-turn structured stderr (kernel-side scraper)

The new `planner_turn_usage` lines emit one JSON line per turn to
the planner binary's stderr (which the kernel pipes into
`kernel.stderr.log` via the session-spawn substrate). Wire shape:

```json
{"event":"planner_turn_usage","task_id":"...","session_id":"...",
 "role":"executor","model":"claude-sonnet-4-5-20250929","turn":0,
 "input_tokens":10,"output_tokens":20,
 "cache_creation_input_tokens":300,"cache_read_input_tokens":4000,
 "cache_hit_ratio":0.928,"cumulative_input_tokens":4310,
 "cumulative_output_tokens":20}
```

Kernel-side scrapers / dashboard panels can `serde_json::from_str`
each line directly. The shape is pinned by the
`planner_turn_usage_log_shape` witness test in
`crates/planner-core/src/dispatch.rs#tests`.

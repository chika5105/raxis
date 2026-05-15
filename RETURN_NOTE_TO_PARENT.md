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

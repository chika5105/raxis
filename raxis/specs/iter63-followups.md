# iter63 follow-ups (deferred from iter62)

This file tracks work explicitly deferred from the iter62 integration
pass. Each entry names the originating worker / RETURN_NOTE and the
expected file-ownership boundary for the iter63 fix.

## Deferred from iter62

* **stale-PendingActivation sweep** (deferred from iter62 — see
  C6 B3 in `worker/iter62-fixes-kernel`'s RETURN_NOTE_TO_PARENT.md).
  Forensics show `review-lint-defect-rust` stuck in
  `PendingActivation` for 67+ minutes after `lint-runner-rust`
  completed; the planner-orchestrator's "next-action" loop in
  `crates/planner-orchestrator/` is the authoritative seam for
  firing `ActivateSubTask` against any `subtask_activations` row
  whose predecessors are all `Completed`. The fix is non-trivial
  (touches the orchestrator's main loop), so it is queued here
  rather than landed in the iter62 integration window.

* **Audit-on-Drop or SIGTERM live-e2e harness path** (deferred from
  iter62 — see D4 in `worker/iter62-deep-sweep-2`'s
  RETURN_NOTE_TO_PARENT.md). 13 `CredentialProxyStarted` audit
  events with 0 `CredentialProxyStopped` because the kernel was
  SIGKILL'd by the test harness before any session reached its
  graceful-teardown branch. Cheapest fix: live-e2e harness change
  to SIGTERM (Worker 4 territory).

* **TaskRowData -> emit_witness_received initiative_id plumbing**
  (FOLLOWUP-E nicety). The witness handler currently passes `None`
  for `initiative_id` to `emit_witness_received` because
  `TaskRowData` does not denormalise the column today. iter63 can
  extend the SELECT in `load_task_row_in_tx` and pass the value
  through without touching the audit-emit call site.

* **VerifierArtifactRejected emit on artefact admission gate**
  (FOLLOWUP-E gap). The kernel-side WitnessRejectionReason today
  covers TokenRejected / TaskNotGatesPending / ShaMismatch -- none
  of which are size-cap / path-escape / sha-mismatch on the
  artefact payload. When iter63 adds the artefact-admission gate,
  call `verifier_audit::emit_artifact_rejected` from the matching
  reject arms.

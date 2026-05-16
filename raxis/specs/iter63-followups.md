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

* **Operator-authored hints into witnesses** (queued during iter63
  launch — surfaced during iter62 witness/verifier review at
  `3834db75`).

  **Problem.** There is no first-class operator-facing "hint" channel
  into a verifier or onto the witness body today.
  `WitnessSubmission.body` is verifier-produced JSON evidence —
  operators cannot attach structured metadata that the verifier echoes
  (or that the kernel propagates) into the witness for reviewer
  context. The closest workaround today is the optional
  `env: HashMap<String, String>` map on `IntegrationMergeVerifierEntry`
  and the `[env]` table on per-task verifier blocks
  (`crates/policy/src/bundle.rs::IntegrationMergeVerifierEntry`,
  `crates/plan/src/...`), but `RAXIS_*` keys are scrubbed and there is
  no schema on what an operator can pass.

  **Goal.** Add an operator-authored, schema-validated
  `hints: HashMap<String, serde_json::Value>` (or
  `BTreeMap<String, String>` if we want strict-typed) field on:
  - `[[gates]]` (claim-based)
  - `[[integration_merge_verifiers]]` and
    `[[plan.integration_merge_verifiers]]`
  - `[[plan.tasks.<id>.verifiers]]`

  The kernel must:
  1. Validate the hints against a per-gate-type schema (extend the
     policy bundle validator in `crates/policy/src/bundle.rs`).
  2. Inject the hints into the verifier spawn envelope (e.g., a single
     `RAXIS_VERIFIER_HINTS_JSON` env var with a size cap, OR individual
     `RAXIS_HINT_<KEY>=<VALUE>` envs).
  3. Echo the operator-supplied hints into the resulting
     `WitnessSubmission` body under a `operator_hints` field, so
     reviewers see exactly what the operator declared without trusting
     the verifier to echo them.
  4. Cap hint count + total payload size (suggest 32 keys max, 4 KiB
     total) and reject at policy validation time.

  **Open questions.**
  - Do hints participate in the `verifier_evaluation_sha` (i.e., do
    they invalidate caching when changed)?
  - Should there be a separate `secret_hints` channel that's redacted
    in the dashboard/audit chain?
  - Wire format: env var vs file mount vs IPC frame?

  **Suggested invariants** (draft):
  - `INV-VERIFIER-HINTS-SCHEMA-VALIDATED-01`: every operator-authored
    hint key/value must validate against the gate-type's hint schema
    at policy load.
  - `INV-VERIFIER-HINTS-PAYLOAD-CAP-01`: hint payload total size
    ≤ 4 KiB, count ≤ 32; rejected at validation.
  - `INV-WITNESS-OPERATOR-HINTS-ECHOED-01`: the kernel must populate
    `WitnessSubmission.body.operator_hints` from the policy-declared
    hints, not from the verifier's claimed payload.

  **Touch surface**: `crates/policy/src/bundle.rs`, `crates/plan/src/`,
  `crates/types/src/witness.rs` (add `operator_hints` field — additive,
  must not break existing serde), `kernel/src/gates/verifier_runner.rs`
  (env injection), `kernel/src/handlers/witness.rs` (echo into body
  before persistence), `crates/store/migrations/` (witness_records
  schema bump), `specs/v2/verifier-processes.md`.

* **Bounded-runtime guard for verifier execution (no kernel stall)**
  (queued during iter63 launch — iter62 architecture review).

  **Source.** Current spawn paths trust the verifier `timeout`
  declared in `IntegrationMergeVerifierEntry.timeout` and
  `[[gates]].max_wall_seconds`, but enforcement is partial:
  - Subprocess timeout is mostly host-side
    (`kernel/src/gates/verifier_runner.rs`).
  - VM-based verifiers (the new `Role::Verifier` from iter62) inherit
    microvm guest watchdog, but no second-line kernel-side wall-clock
    kill if the guest's watchdog also stalls.
  - No idle-timeout (verifier alive but not making progress on its
    UDS).
  - No per-VerifierFamily cumulative-time ceiling across retries — a
    misconfigured verifier could be re-spawned forever if
    `on_failure = "warn_only"` paired with an upstream retry budget.

  **Problem.** A misbehaving or hostile verifier (host subprocess OR
  microVM) could in principle stall the kernel's gate-evaluation flow,
  hold a verifier slot indefinitely, or burn CPU/IO well past its
  declared budget without the kernel forcefully reaping it.

  **Goal.** Bound verifier execution so witness code is **always**
  killed within a strict wall-clock + idle window, and the kernel
  emits a clean failure witness instead of stalling.

  **Specific guards to implement**:
  1. **Hard wall-clock kill** — kernel-side `tokio::time::timeout`
     wrapping the entire verifier run (subprocess OR VM lifetime).
     Default cap: `min(declared_timeout, 5 minutes)`. Configurable
     per-policy ceiling.
  2. **Idle-stream timeout** — if the verifier's UDS
     (`RAXIS_KERNEL_SOCKET`) sees no I/O for `idle_timeout` (default
     60s), the kernel kills it and emits `VerifierIdleTimeout` audit
     event.
  3. **Per-task cumulative-time ceiling** — sum of all verifier runs
     (across retries) on a single task must not exceed
     `task_verifier_total_budget` (default 15 minutes). When exceeded,
     the gate fails with `WitnessRejected { reason:
     TimeBudgetExhausted }`.
  4. **VM-side watchdog independence** — confirm the kernel's
     wall-clock kill works even if the guest watchdog is wedged. If
     the VM doesn't respond to graceful kill within 10s, force
     `vmm.shutdown()` (or equivalent isolation-apple-vz API).
  5. **Audit emission on every kill path** — emit one of
     `VerifierWallClockTimeout`, `VerifierIdleTimeout`,
     `VerifierBudgetExhausted` so the dashboard/operator can see
     exactly why a verifier was reaped.
  6. **Witness-handler timeout** —
     `kernel/src/handlers/witness.rs::handle` must itself complete in
     bounded time (e.g., 5s); a slow witness blob write must not stall
     other gate evaluations.

  **Suggested invariants** (draft):
  - `INV-VERIFIER-WALL-CLOCK-KILL-01`: every verifier execution
    (subprocess + VM) is reaped within
    `min(declared_timeout, policy_max_verifier_wall_seconds)`. Witness
    arm via a `should_panic` test that spawns a sleep-forever verifier
    and asserts kill within budget.
  - `INV-VERIFIER-IDLE-TIMEOUT-01`: a verifier with no UDS I/O for
    `idle_timeout` is killed and `VerifierIdleTimeout` is emitted.
  - `INV-VERIFIER-CUMULATIVE-BUDGET-01`: across retries, total
    verifier time per task ≤ `task_verifier_total_budget`; gate fails
    with `TimeBudgetExhausted` when exceeded.
  - `INV-WITNESS-HANDLER-BOUNDED-01`: `handlers::witness::handle`
    returns within 5s for any well-formed submission (witness arm via
    injected slow blob writer).
  - `INV-VERIFIER-VM-FORCE-SHUTDOWN-01`: when graceful kill exceeds
    `force_shutdown_grace`, the VM is force-terminated via
    `vmm.shutdown()`; witness arm via a wedged-watchdog test fixture.

  **Touch surface**: `kernel/src/gates/verifier_runner.rs` (subprocess
  wall-clock + idle), `crates/isolation-apple-vz/src/` (VM
  force-shutdown path), `kernel/src/handlers/witness.rs` (handler
  bounded-time), `crates/policy/src/bundle.rs` (new policy fields
  `max_verifier_wall_seconds`, `task_verifier_total_budget`,
  `verifier_idle_timeout_seconds`,
  `verifier_force_shutdown_grace_seconds`),
  `crates/audit/src/event.rs` (3 new audit variants:
  `VerifierWallClockTimeout`, `VerifierIdleTimeout`,
  `VerifierBudgetExhausted`), `kernel/src/notifications/sink.rs` (SSE
  bridge for new variants), `specs/invariants.md` (5 new INVs above).

  **Why now**: with the iter62 verifier runtime shipped
  (`raxis-verifier`, `raxis-verifier-no-secrets`, `Role::Verifier`),
  we now have multiple production verifier paths whose runtime safety
  is only as strong as the weakest enforcement. This must close
  before BYO operator-supplied verifier images are GA.

  **Priority**: HIGH — this is a kernel-stability invariant, not an
  enhancement.

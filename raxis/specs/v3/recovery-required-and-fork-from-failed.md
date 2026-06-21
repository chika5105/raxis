# RecoveryRequired and Fork From Failed

Status: Active/implemented for the core initiative lifecycle. Companion
coverage: `kernel/tests/operator_approve_recovery_semantics.rs`,
`kernel/tests/orch_respawn_ceiling_escalation.rs`, and
`raxis-live-e2e recovery-required-lifecycle`.

## Principle

RAXIS does not resume terminal failed initiatives in place.

Recoverable initiative-level stops transition to `RecoveryRequired`.
Terminal `Failed` is closed forensic history. If an operator needs to
continue from failed history, they create a new signed initiative that
references the failed initiative as its parent. That operation is
called `fork-from-failed`, not resume.

Recovery is an escalation, not an implicit retry. Task-local retries
inside the signed plan budget may happen automatically because the
operator already authorized that retry envelope. Once RAXIS needs a
human to re-authorize initiative progress, the kernel must create an
auditable recovery/escalation surface and wait for signed operator
approval.

This preserves two invariants at once:

* Plan immutability: the frozen plan that ran remains the frozen plan
  that ran.
* Operational recovery: transient infrastructure, merge, push, or
  orchestration stalls can be retried by signed operator approval
  without re-running completed DAG work from scratch.

## State Model

Recoverable stop:

```text
Executing | Blocked -> RecoveryRequired
RecoveryRequired -> Executing   # operator approves recovery
RecoveryRequired -> Failed      # operator denies recovery
```

Terminal close:

```text
Executing | Blocked -> Failed   # non-recoverable cause only
Failed -> Failed                # closed history
```

There is no normal `Failed -> Executing` transition.

## Scenarios

### 1. Orchestrator No-Progress Ceiling

The orchestrator respawns repeatedly without any task FSM progress.
The kernel increments `orchestrator_no_progress_respawn_count` and
eventually trips the ceiling.

Expected behavior:

* Insert a kernel-initiated `LogicalDeadlock` escalation.
* Set initiative state to `RecoveryRequired`.
* Stop respawning orchestrators for that initiative.
* On approval: reset the counter, set state to `Executing`, and spawn
  the orchestrator again.
* On denial: set state to terminal `Failed`.

### 2. Review-Rejection Ceiling

A reviewer keeps rejecting an executor output and the executor exhausts
the configured retry budget.

Expected behavior:

* Mark the relevant task/activation as failed with the reviewer
  critique preserved.
* Set the initiative to `RecoveryRequired`.
* Surface the reviewer critique and retry ceiling as the recovery
  reason.
* On approval: retry the same immutable DAG from the bounded recovery
  point.
* On denial: close the initiative as `Failed`.

### 3. Merge Or Push Failure

Integration merge or external publish fails because the target ref
advanced, the remote rejected the push, or credentials/networking were
temporarily unavailable.

Expected behavior:

* Preserve the candidate merge state and failure reason.
* Set the initiative to `RecoveryRequired`.
* Let the operator fix external conditions and approve recovery.
* Do not mutate the signed plan to work around the failure.

### 4. Reviewer Runtime Failure

A reviewer VM exits before submitting `SubmitReview` because the
planner hit a turn/token/tool-error limit, disconnected, or the IPC
stream failed.

Expected behavior:

* Mark the reviewer task and latest activation `Failed` with a
  concrete `ReviewerExitedWithoutVerdict`,
  `ReviewerTurnBudgetExhausted`, `ReviewerNoTerminalIntent`, or
  `ReviewInfrastructureFailed` reason.
* Surface the failed reviewer in the orchestrator KSB
  `capabilities.tasks` block with the same `retry_admissible`
  predicate used by `RetrySubTask`.
* On admissible retry: the orchestrator issues `RetrySubTask`, then
  `ActivateSubTask`, and the same reviewer task runs again against the
  same reviewed artifact.
* If repeated no-progress respawns exhaust the initiative ceiling, move
  the initiative to `RecoveryRequired` and require operator approval or
  denial.

### 5. Prompt, Allowlist, or Plan Shape Was Wrong

If recovery requires changing user-authored instructions, widening a
path allowlist, adding a task, changing a verifier, or changing model
routing, the current immutable plan cannot be resumed by approval.

Expected behavior:

* Close or leave the old initiative as forensic history.
* Submit a new signed plan or, when implemented, a signed add-only plan
  amendment linked to the original plan artifact.
* Reuse completed artifacts only through explicit, auditable lineage.

### 6. Terminal Failed Forensics

An administrator wants to continue from a failed initiative for
forensic or operational reasons.

Expected behavior:

* `raxis initiative fork-from-failed <initiative_id>` refuses non-Failed
  initiatives.
* For Failed initiatives, it prints parent lineage and bundle metadata.
* It does not mutate the old row.
* Stale pending recovery escalations attached to terminal `Failed`
  initiatives cannot be approved or denied through the normal recovery
  path.
* The operator authors and signs a new initiative that references the
  failed run as parent history.

## Audit Requirements

Every recovery path must leave a replayable record:

* the cause event that forced recovery
* the state transition into `RecoveryRequired`
* the pending escalation or recovery approval surface
* the operator approval or denial
* the resulting `RecoveryRequired -> Executing` or
  `RecoveryRequired -> Failed` transition

Audit readers must not infer recovery from terminal `Failed`. A failed
initiative may be used as parent history, but it is not resumed in
place.

## Amendment Rules

The normal recovery approval path does not amend the plan. It
re-authorizes another bounded attempt under the same frozen authority
artifact.

When the actual fix requires changing user-authored authority, RAXIS
needs a signed amendment or a new signed initiative. Examples include:

* widening a path allowlist
* adding a verifier or changing verifier failure behavior
* changing prompts or success criteria
* adding a new fixup task
* changing model routing, tool profiles, credentials, or egress

Amendments are allowed at any time, subject to policy. They are
add-only, parent-linked artifacts: the amendment records the previous
effective plan artifact digest, the operator signature, the reason, and
the exact delta. Applying an amendment creates a new effective plan
version; it does not mutate prior plan artifacts or prior task
evidence.

The kernel applies amendments by task state:

* Pending or not-yet-spawned task: update the future attempt before it
  runs.
* Running task: abort/revoke the current session, mark that attempt
  superseded, and start a new attempt under the amended authority.
* Failed or blocked task: create a new attempt under the amended
  authority.
* Completed task: supersede the completed attempt and reset every
  downstream task that depended on the superseded output.

Completed task evidence is never amended in place. The old commits,
evaluation SHA, witnesses, reviewer verdicts, and audit rows remain
forensic evidence.

If an operator amends a completed task, RAXIS treats that as a signed
supersession, not mutation: the completed attempt is marked superseded,
the task gets a new attempt under the amended authority, and every
downstream task that depended on the superseded output is reset and
rerun. This keeps the DAG honest: no task may continue to claim it was
built on evidence that has been replaced.

## Live E2E Coverage

`raxis-live-e2e recovery-required-lifecycle` applies real store
migrations and drives the persisted recovery contract:

* approval resumes `RecoveryRequired -> Executing`
* denial closes `RecoveryRequired -> Failed`
* stale recovery approval does not mutate or resurrect terminal
  `Failed`

The slice is also included in `raxis-live-e2e all`.

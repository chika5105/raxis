# Scenario 44 — Session Revocation

> **Complexity:** ⭐⭐ Intermediate | **Wall clock:** ~6 min | **Provider:** Anthropic

Revoke a single in-flight agent session — Orchestrator, Executor, or
Reviewer — without aborting the rest of the initiative. Demonstrates
the targeted "kill switch": the kernel marks the session
`Revoked` in `sessions`, deletes the verifier-token rows belonging to
that session, and forensically retains the session's worktree under
`<data_dir>/sessions/<id>-revoked/` so the operator can postmortem
without losing evidence. The initiative continues with whatever tasks
were not bound to the revoked session.

## When to use this

- An agent is clearly off the rails (looping, exfiltrating, stuck
  re-asking) but the rest of the plan is healthy and you don't want
  to abort the whole initiative.
- You are investigating a suspected compromise and want the
  worktree preserved for a forensic dump.
- You're rehearsing your incident-response runbook.

---

## Prerequisites

- **One-time setup complete.** See
  [`../../getting-started/README.md`](../../getting-started/README.md)
  for Homebrew, or [`../../SETUP.md`](../../SETUP.md) for source
  builds.
- **Kernel running.**
- **`RAXIS_DATA_DIR` and `RAXIS_OPERATOR_KEY` exported.**
- **An initiative with at least one task active.** The simplest way
  is to start [scenario 02](../02-single-executor-reviewer/) and pause
  the Reviewer for a moment by lengthening its prompt — that gives
  you a session sitting in `Running` long enough to revoke.

---

## What this scenario demonstrates

- `raxis session revoke` is a typed CLI surface, not a SIGKILL on
  the agent VM — the kernel transitions the session through an
  audit-logged `SessionRevoked` event before tearing down the VM.
- The session's verifier tokens are atomically expired in the same
  transaction (no orphan witness rows can land after revocation).
- The Orchestrator picks up the revocation via its IPC subscription
  and rebalances the task graph: pending tasks for the revoked
  session are re-admitted; in-flight task state is preserved as
  `BlockedRecoveryPending`.
- The session's worktree is moved under `<data_dir>/sessions/` with
  a `-revoked` suffix and a `manifest.json` describing the cause.

---

## Files in this scenario

| File | Purpose |
|---|---|
| `policy.toml` | Empty delta (revocation is a built-in CLI surface, no policy required). |
| `credential.toml` | Empty template. |
| (no `plan.toml`) | This scenario operates on an initiative *already created* by another scenario. |

---

## Run it

```bash
# 1. Pick a running initiative + session. The list is JSON; filter
#    for state Running.
raxis sessions --json | jq '.active_sessions[] | select(.state == "Running")'

# 2. Pick one session_id. Substitute below.
TARGET_SESSION="<session_id>"

# 3. Revoke.
raxis session revoke "$TARGET_SESSION"

# 4. Observe.
raxis log --session "$TARGET_SESSION" --kind SessionRevoked --limit 1 --json
```

---

## What "success" looks like

```bash
# 1. The session row is Revoked.
raxis log --session "$TARGET_SESSION" --kind SessionRevoked --limit 1 --json | wc -l
# 1

# 2. Session capture / worktree evidence remains available for forensics.
ls "$RAXIS_DATA_DIR/session-capture/" | grep "$TARGET_SESSION" || true
find "$RAXIS_DATA_DIR/worktrees" -maxdepth 2 -name "*$TARGET_SESSION*" -print

# 3. The revoked session's verifier tokens are consumed.
raxis log --kind VerifierTokenExpired \
  --limit 20 --json \
  | jq -c 'select(.payload.session_id == "'"$TARGET_SESSION"'")'

# 4. The initiative did *not* abort; pending tasks were re-admitted.
INIT_ID="$(raxis log --session "$TARGET_SESSION" --limit 1 --json | jq -r '.initiative_id')"
raxis initiative show "$INIT_ID" --with-tasks
# State: Active (or Completed if the remaining task graph finished)

# 5. Chain still verifies.
raxis verify-chain
```

The audit chain and session-capture files preserve the revocation
timeline for post-mortem work.

---

## Variations

- **Revoke a single Executor.** The kernel records `SessionRevoked`
  and downstream recovery decides whether the task can be retried.
- **Revoke an Orchestrator.** Orchestrator revocation cascades:
  every Executor/Reviewer spawned by it transitions to
  `BlockedRecoveryPending` and the operator must either retry or
  abort the initiative. Use this to rehearse the "rogue
  orchestrator" runbook.
- **Forensic mode.** Pass `--keep-vm` to leave the underlying VM
  running for a few extra seconds while the operator captures
  in-memory state with a sidecar tool. The default tears the VM
  down immediately.

---

## Tear-down

```bash
# Optional — the revoked-worktree directory accumulates under
# $RAXIS_DATA_DIR/sessions/<id>-revoked. The kernel retains it
# indefinitely; the operator decides when to delete.
rm -rf "$RAXIS_DATA_DIR/sessions/<id>-revoked"
```

---

## Cross-references

- Concepts: [`../../CONCEPTS.md#agent-types`](../../CONCEPTS.md#agent-types).
- Recipe: [`../../recipes/cli/16-session-management.md`](../../recipes/cli/16-session-management.md)
  walks every `raxis session` subcommand.
- Spec: `specs/v1/kernel-core.md §recovery.rs` (the
  re-admission logic invoked when the orchestrator notices a revoked
  child); `specs/v1/kernel-store.md §verifier_run_tokens` for the
  atomic-expiry contract.
- Related scenarios:
  - [`26-abort-mid-flight`](../26-abort-mid-flight/) for the
    whole-initiative kill switch.
  - [`47-crash-recovery-mid-merge`](../47-crash-recovery-mid-merge/)
    for what `BlockedRecoveryPending` looks like at restart.

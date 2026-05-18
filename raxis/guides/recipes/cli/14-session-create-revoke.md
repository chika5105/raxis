# `raxis session create` and `raxis session revoke`

> **Topic:** CLI | **Time to read:** ~2 min | **Complexity:** ⭐⭐ Intermediate

Two operator-facing commands for session lifecycle. `create` mints
a new session bound to an existing initiative or for ad-hoc
operator use; `revoke` terminates an active session before its
natural end.

---

## Syntax

```text
raxis session create --initiative <id> --agent-type <Executor|Reviewer|Orchestrator>
                     [--ttl <seconds>] [--lane <lane_id>]
raxis session revoke <session_id>
```

---

## create — mint an ad-hoc session

In normal flow the kernel mints sessions automatically when a plan
is approved. `session create` is the override for operator-driven
runs (debugging, manual replay, custom tooling).

```bash
raxis session create \
  --initiative 1f3c8a4b \
  --agent-type Executor \
  --ttl 3600
# Output:
# session_id:  91a7c83f...
# token:       <256-bit random hex; STORE THIS>
# expires_at:  2026-05-10T18:30:00Z
```

Caveats:

- The session token is a 256-bit CSPRNG random — it's only printed
  once; copy it now.
- TTL caps at the policy's `[sessions].max_ttl_seconds`.
- An ad-hoc session does not bypass DAG order; if you `Start` a
  task whose predecessors haven't completed, the kernel rejects.
- The kernel still charges the session against the lane's
  `max_concurrent_tasks` and the initiative's
  `max_cost_per_epoch`.

---

## revoke — terminate before TTL

`session revoke` ends the session immediately. The kernel sends
`SIGTERM` then `SIGKILL` after a 10s grace; in-flight intents from
the session are dropped before any side effects fire (the kernel
checks the session is alive on every IPC step).

```bash
raxis session revoke 91a7c83f
# Output:
# Session 91a7c83f revoked at 1779068884
```

Use revoke when:

- Suspected compromise of the session's token.
- Operator wants to free the lane slot without aborting the parent
  initiative.
- You spawned an ad-hoc session for debugging and forgot to set a
  TTL.

---

## Common errors

| Symptom | Fix |
|---|---|
| `session create: --ttl exceeds [sessions].max_ttl_seconds` | Lower the TTL or raise the policy cap. |
| `session create: agent type not allowed in this lane` | The lane only permits certain agent types; check `[[lanes]]`. |
| `session revoke: session not found` | UUID typo or already terminated. |
| `session revoke: session already terminal` | Idempotent — swallow if scripting. |
| `OPERATOR_NOT_AUTHORIZED` | Cert lacks `CreateSession` / `RevokeSession` in `permitted_ops`. |

---

## Reference

| Command | Purpose |
|---|---|
| `raxis sessions [--initiative <id>] [--agent-type ...]` | List active sessions. |
| `raxis sessions --json` + `raxis log --session <id>` | Detailed view of one session. |
| `raxis log <initiative_id>` | Audit events including SessionMinted / SessionRevoked. |
| `raxis initiative show <id>` | Initiative-level overview. |

---

## Variations

- **Manual replay session.** Mint an Executor session against a
  completed initiative to re-run the planner with a different
  prompt. The session has access to the original worktree; you can
  use `raxis explain <task_id>` to compare runs.
- **Short-lived diagnostic session.** `--ttl 600` for a 10-minute
  scratch session; the kernel auto-revokes at expiry.
- **Bulk revoke.** A leaked operator key — iterate
  `raxis sessions --json | jq -r '.active_sessions[].session_id'` and revoke each.
- **Pre-flight a token.** Before handing a token to a tool, do
  `raxis sessions --json | jq -e '.active_sessions[] | select(.session_id == "$SID")'`
  to confirm the session is still alive.

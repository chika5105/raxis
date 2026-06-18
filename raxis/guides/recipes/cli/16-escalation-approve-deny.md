# `raxis escalation approve` and `raxis escalation deny`

> **Topic:** CLI | **Time to read:** ~2 min | **Complexity:** ⭐⭐ Intermediate

Human-in-the-loop decision points. When an Orchestrator decides a
task can't make progress without operator input (R-12, INV-06), it
emits an escalation and pauses the dependent tasks. Operators
review and either `approve` with a bounded approval scope, or `deny`
(terminating or failing the affected recovery path).

---

## Syntax

```text
raxis escalation approve <escalation_id> --scope <capability_class> --max-uses <n> --valid-for <secs>
raxis escalation deny    <escalation_id> [--reason <text>]
```

---

## Discovery

```bash
raxis escalations
# Output (table):
# ESC_ID         INITIATIVE   TASK              REASON                                  AGE
# e8a5...        1f3c8a...    code_reviewer     Cannot decide: ambiguous spec line 42   5m
# 3b1d...        9e1f4b...    implementer       Verifier passed but I distrust output   1h

raxis escalations --json | jq '.[] | {escalation_id, initiative_id, task_id, reason}'
```

For a single one:

```bash
raxis escalation show e8a5...
# Output:
# escalation_id:    e8a5...
# initiative_id:    1f3c8a...
# task_id:          code_reviewer
# raised_by:        91a7c83f (Reviewer session)
# reason:           Cannot decide: ambiguous spec line 42
# context_witness:  41bf09cc (relevant evidence; pull via raxis witnesses show)
# created_at:       2026-05-10T17:25:00Z
# state:            Pending
```

---

## approve — mint a bounded approval

```bash
raxis escalation approve e8a5... \
  --scope NetworkEgress \
  --max-uses 1 \
  --valid-for 3600
# Output:
# Escalation e8a5... approved.
# approval_token_id:  7b4c...
# approval_token_raw: <redacted; sha256_fp=...> (re-run with --reveal-token to print the raw token to stdout)
# expires_at:         1770638892
```

What happens:

- The CLI signs `approval|<escalation_id>|<capability_class>|<max_uses>|<valid_for_seconds>`
  with the operator key.
- The kernel verifies the signature, marks the escalation `Approved`,
  and inserts an `approval_tokens` row.
- The returned token is a bearer secret. By default the CLI redacts it;
  pass `--reveal-token` only when you need to hand the raw token to a
  planner out-of-band.
- The token can be consumed only for the approved capability class, only
  until `--valid-for` expires, and only up to `--max-uses`.

Approval is an authority act, not a prompt-edit mechanism. If the agent
needs new instructions, encode those in the next signed plan or in the
human-controlled operating notes it is allowed to read.

---

## approve — recover a kernel logical deadlock

Some escalations are created by the kernel itself when an initiative
enters `RecoveryRequired`, for example an orchestrator no-progress /
logical-deadlock stop. These rows have class `LogicalDeadlock` and
initiator `Kernel`.

Use the same CLI shape:

```bash
raxis escalation approve 7edb... \
  --scope LogicalDeadlock \
  --max-uses 1 \
  --valid-for 3600
```

For this special class, the kernel does not mint a downstream approval
token. The operator approval is the action: it resets the recovery
counter, transitions the initiative from `RecoveryRequired` back to
`Executing`, and schedules the orchestrator to be respawned. The scope
flags remain required by the CLI because approval requests share one
typed wire shape.

---

## deny — terminate the initiative

```bash
raxis escalation deny e8a5... \
  --reason "reviewer distrust signals genuine ambiguity; reject"
# Output:
# escalation_id:    e8a5...
# state:            Denied
# initiative_state: Failed
```

A denied escalation is terminal for that recovery path. For
kernel-initiated `LogicalDeadlock` recovery, denial transitions
`RecoveryRequired -> Failed`. For ordinary planner capability
escalations, the denied capability remains unavailable and dependent
work fails closed.

---

## Lineage rate-limiting

If the same agent lineage produces escalations faster than
`[escalation_policy].max_per_window`, the kernel auto-quarantines
the lineage. Useful safety net when an agent enters a
"please-help-me" loop.

You'll see this in `raxis escalations`:

```text
ESC_ID  INITIATIVE  TASK  REASON                            AGE  FLAGS
...     ...         ...   Cannot decide: ambiguous spec...  5m   [QUARANTINED]
```

The escalation can still be acted on, but new escalations from
that lineage are dropped until you explicitly clear the quarantine
or the rate-limit window expires.

---

## Common errors

| Symptom | Fix |
|---|---|
| `approve: escalation not found` | Wrong UUID or already resolved. |
| `approve: escalation already resolved` | Idempotent — swallow if scripting. |
| `escalation approve requires --scope <capability_class>` | Add the capability class, for example `--scope LogicalDeadlock` for kernel recovery. |
| `escalation approve requires --max-uses <n>` | Add a positive use count such as `--max-uses 1`. |
| `escalation approve requires --valid-for <secs>` | Add a positive TTL such as `--valid-for 3600`. |
| `deny: initiative already terminal` | The initiative is already `Failed` / `Aborted` / `Completed`. The escalation auto-closed; nothing to do. |
| `OPERATOR_NOT_AUTHORIZED` | Cert lacks `ApproveEscalation` / `DenyEscalation` in `permitted_ops`. |

---

## Reference

| Command | Purpose |
|---|---|
| `raxis escalations [--json]` | List pending escalations. |
| `raxis escalation show <id>` | Detailed view with context witness. |
| `raxis witnesses show <sha>` | Pull the evidence blob. |
| `raxis explain <task_id>` | Why the task escalated. |
| `raxis inbox` | Operator-friendly aggregate of escalations + alerts. |

---

## Variations

- **Approve one bounded capability.** Give the planner exactly one
  short-lived token for the class it requested.
- **Approve recovery.** A kernel-created `LogicalDeadlock` escalation
  resumes a `RecoveryRequired` initiative without minting a planner
  token.
- **Deny on policy grounds.** A reviewer escalates because they
  found a bug in policy interpretation; deny so the initiative
  doesn't sneak through, and start a separate plan to fix the
  policy.
- **Auto-deny stale escalations.** Cron that denies any escalation
  pending > N hours, with `--reason "auto-deny: stale"`.

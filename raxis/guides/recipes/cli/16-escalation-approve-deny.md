# `raxis escalation approve` and `raxis escalation deny`

> **Topic:** CLI | **Time to read:** ~2 min | **Complexity:** ⭐⭐ Intermediate

Human-in-the-loop decision points. When an Orchestrator decides a
task can't make progress without operator input (R-12, INV-06), it
emits an escalation and pauses the dependent tasks. Operators
review and either `approve` (with optional guidance) or `deny`
(terminating the initiative).

---

## Syntax

```text
raxis escalation approve <escalation_id> [--guidance <text>]
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

## approve — let the work continue

```bash
raxis escalation approve e8a5... \
  --guidance "spec line 42 means 'reject expired tokens'; proceed with strict mode"
# Output:
# escalation_id:  e8a5...
# state:          Approved
# resumed_tasks:  [code_reviewer]
```

What happens:

- The kernel marks the escalation `Approved` in the audit chain
  (`EscalationResolved { decision: Approved, guidance }`).
- The Orchestrator's session receives a `KernelPush::EscalationResolved`
  containing the guidance. The Orchestrator decides how to proceed
  (typically: re-issue the task with augmented system prompt).
- Lineage rate-limit counters are reset (the operator's
  decision counts as fresh signal).

The guidance string is delivered verbatim to the Orchestrator via
the kernel push channel. Keep it precise and actionable.

---

## deny — terminate the initiative

```bash
raxis escalation deny e8a5... \
  --reason "reviewer distrust signals genuine ambiguity; reject"
# Output:
# escalation_id:    e8a5...
# state:            Denied
# initiative_state: Aborted
```

A denied escalation is **terminal for the initiative** — the kernel
aborts all sessions for it (just like `initiative abort`), records
`InitiativeAborted` linked to the escalation, and the lane budget
recovers.

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
| `approve: --guidance too long` | Trim to ≤ 4 KB (server-side cap). |
| `deny: initiative already terminal` | The initiative is already `Aborted` / `Completed`. The escalation auto-closed; nothing to do. |
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

- **Approve with broad guidance.** "Re-run with the strict-mode
  flag" → Orchestrator augments the system prompt and re-issues
  the Reviewer.
- **Deny on policy grounds.** A reviewer escalates because they
  found a bug in policy interpretation; deny so the initiative
  doesn't sneak through, and start a separate plan to fix the
  policy.
- **Operator playbook.** Map common escalation reason patterns to
  pre-canned guidance strings; review docs `R-12` for the
  invariant.
- **Auto-deny stale escalations.** Cron that denies any escalation
  pending > N hours, with `--reason "auto-deny: stale"`.

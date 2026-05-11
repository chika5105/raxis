# `raxis sessions`, `raxis escalations`, `raxis inbox`

> **Topic:** CLI | **Time to read:** ~2 min | **Complexity:** ⭐ Beginner

Three operator-facing listings. `sessions` and `escalations` are
the per-axis listings; `inbox` is the unified operator dashboard
that aggregates pending escalations, near-expiry certs, drift
warnings, and other "you should look at this" items.

---

## sessions — active session listing

```bash
raxis sessions
# Output:
# SESSION_ID    INITIATIVE    TASK             AGENT_TYPE    AGE    TTL_REMAINING
# 91a7c83f      1f3c8a4b      code_reviewer    Reviewer      4m     56m
# 3b1d4f00      9e1f4b22      implementer      Executor      2h     1h
```

Filters:

```bash
raxis sessions --initiative 1f3c8a4b
raxis sessions --agent-type Reviewer
raxis sessions --json | jq '.[] | select(.ttl_remaining_seconds < 300)'
```

`raxis sessions show <id>` (or `inspect session:<id>`) drills
into one session's metadata, delegations, and recent intents.

---

## escalations — pending human-in-loop decisions

```bash
raxis escalations
# Output:
# ESC_ID    INITIATIVE   TASK            REASON                                    AGE
# e8a5...   1f3c8a4b     code_reviewer   "Cannot decide: ambiguous spec line 42"   5m
# 3b1d...   9e1f4b22     implementer     "Verifier passed but I distrust output"   1h
```

Filters:

```bash
raxis escalations --initiative 1f3c8a4b
raxis escalations --json | jq '.[] | select(.age_seconds > 3600)'
```

Resolve via `raxis escalation approve` / `raxis escalation deny`.
See the dedicated escalation recipe.

---

## inbox — unified operator dashboard

```bash
raxis inbox
# Output:
# == ESCALATIONS (1 pending) ==
#   e8a5...    1f3c8a4b   code_reviewer   "Cannot decide..."   5m
#
# == DRIFT (1 warn) ==
#   InitiativeAdmitted at 17:30 has no matching SessionMinted within 30s
#     (initiative 9e1f4b22, lane api-work)
#
# == CERT EXPIRY (2 warn) ==
#   ops-bob:    1d remaining  (signer 8a4f...)
#   ci-bot:     6h remaining  (signer 8a4f...)
#
# == HOST CAPACITY (1 warn) ==
#   lane api-work: 100% budget used; 0 admissions in last 5min
#
# == AUDIT CHAIN ==
#   ok (last verified line 7321)
```

`inbox` is the "morning report" — the single command an operator
runs to see anything that wants attention. It pulls from:

- Pending escalations (`raxis escalations`).
- `ReconciliationGap` and `SecurityViolation` audit events (recent).
- Cert expiry windows (`raxis cert list`).
- Lane budget/capacity exhaustion (`raxis budget`, `queue`).
- `raxis verify-chain` cursor.

Each section is empty if there's nothing to report. A clean inbox
prints `Inbox empty (all clear).`

---

## Common errors

| Symptom | Fix |
|---|---|
| `sessions: kernel not running` | `raxis status` to verify, then `systemctl start raxis-kernel`. |
| `inbox: stale cert expiry warnings` | `raxis cert list --json` to get exact values; rotate certs as needed. |
| `inbox: drift warning persists after fix` | Drift entries are based on audit-chain events; a transient drift may already be resolved but the line stays in the historical record. Investigate via `raxis log --kind ReconciliationGap`. |

---

## Reference

| Command | Purpose |
|---|---|
| `raxis session show <id>` / `inspect session:<id>` | Per-session deep dive. |
| `raxis escalation show <id>` | Per-escalation deep dive. |
| `raxis explain <task_id>` | Why a task is in its state. |
| `raxis budget [--lane <id>]` | Lane-level budget view. |
| `raxis status` | Cheap liveness check. |
| `raxis verify-chain` | Audit integrity. |

---

## Variations

- **Operator login screen.** A shell `.zshrc` snippet that runs
  `raxis inbox` on every login; if non-empty, the operator
  immediately knows there's something to triage.
- **Slack bot.** Cron `raxis inbox --json` and post non-empty
  sections to a Slack channel.
- **Cert-only view.** Most `inbox` runs only need the cert section;
  `raxis cert list --json | jq '.[] | select(.ttl_remaining_seconds < 86400)'`
  is faster.
- **Per-lane operator.** A lane owner runs
  `raxis sessions --json | jq '.[] | select(.lane_id == "auth-work")'`
  to see their lane's sessions.

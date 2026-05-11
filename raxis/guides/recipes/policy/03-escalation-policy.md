# `[escalation_policy]` — escalation rate limits + quarantine

> **Topic:** Policy reference | **Time to read:** ~3 min | **Complexity:** ⭐⭐ Intermediate

The kernel uses lineage-based rate-limiting and quarantine to keep a
runaway agent from drowning the operator inbox in escalations. This
block tells the kernel **how aggressive** that throttling is.

---

## Field reference

All four fields are mandatory; a missing field triggers
`PolicyError::MalformedArtifact` at policy load.

| Field | Type | Required | Default-ish | Effect |
|---|---|---|---|---|
| `timeout_secs` | `u64` | yes | 3600 (1h) | An escalation that's been "Pending" for more than this many seconds is auto-expired. The originating session is then in the lineage's "expired escalations" bucket. |
| `window_secs` | `u64` | yes | 300 (5min) | The sliding window over which `max_per_window` is enforced. |
| `max_per_window` | `u32` | yes | 5 | Inside one rolling `window_secs`, a single lineage may emit at most this many `RaiseEscalation` intents. The (N+1)th is rejected with `FAIL_ESCALATION_RATE_LIMIT`. |
| `quarantine_threshold` | `u32` | yes | 3 | Once a lineage has accumulated this many *expired* escalations (timeout reached without operator action), the kernel quarantines the lineage. New sessions in the lineage are denied at admit time with `FAIL_LINEAGE_QUARANTINED` until the operator clears it. |

Lineage = a chain of sessions all spawned from the same root planner
session. The rate-limit is per-lineage, not per-session, so an
agent can't reset its quota by spawning a child.

---

## Example

```toml
[escalation_policy]
timeout_secs         = 3600    # 1 hour to act before auto-expire
window_secs          = 300     # 5 min rolling window
max_per_window       = 5       # 5 escalations / 5 min / lineage
quarantine_threshold = 3       # 3 expired → lineage quarantined
```

These are reasonable defaults. Tighten for high-trust environments:

```toml
[escalation_policy]
timeout_secs         = 600     # 10 min — operator on-call expected
window_secs          = 60
max_per_window       = 2
quarantine_threshold = 1       # one expired escalation → quarantine
```

Or loosen for batch / overnight processing:

```toml
[escalation_policy]
timeout_secs         = 86400   # 24h — overnight on-call
window_secs          = 3600    # 1h rolling
max_per_window       = 20
quarantine_threshold = 10
```

---

## What the rate limit looks like in practice

```bash
# A misbehaving lineage hits its 5/5min cap.
raxis log --kind RaiseEscalation --since 5m | wc -l   # → 5
raxis log --kind EscalationRateLimited --since 5m | wc -l   # → 1+

# Inspect the lineage:
raxis escalations --status pending --json \
  | jq '.[] | {lineage_id, count_in_window}'
```

Past the limit the kernel emits `EscalationRateLimited` events
(audit) and rejects the IPC frame with `FAIL_ESCALATION_RATE_LIMIT`.
The agent receives a typed error and may either retry later (after
the window slides) or report failure.

---

## What quarantine looks like

```bash
# Lineage has 3+ expired escalations.
raxis log --kind LineageQuarantined --limit 5

# New session create in that lineage:
raxis session create --role planner --lineage-id <quarantined> ...
# → FAIL_LINEAGE_QUARANTINED
```

The operator clears with:

```bash
raxis escalation approve <id> --scope <cap> --max-uses 1 --valid-for 600
# OR — to clear the quarantine without granting capability —
# revoke the quarantine row with the (V3) `raxis lineage clear` command
```

In the V2 MVP, lineage clear is performed by issuing **any**
`escalation approve` for the lineage; the kernel treats that as
operator acknowledgement and clears the expired-count.

---

## Common failure modes

| Symptom | Fix |
|---|---|
| Agents fail with `FAIL_ESCALATION_RATE_LIMIT` immediately | `max_per_window` is too tight for your workload. Raise it, re-sign. |
| Lineage quarantines on first failure | `quarantine_threshold = 1` — fine for high-trust posture, but probably too tight for development. Raise to ≥ 3. |
| Escalations sit "Pending" forever, never expire | `timeout_secs` is too long; the operator inbox piles up. Lower it. |
| `Validation: timeout_secs must be > window_secs` | The two fields are independent in V2; if you see this it's likely a stale fixture from a pre-release; remove it. |

---

## Reference: related CLI

| Command | Purpose |
|---|---|
| `raxis escalation list [--status pending\|approved\|denied\|all]` | Inspect outstanding escalations. |
| `raxis escalation approve <id> --scope <cap> --max-uses <N> --valid-for <secs>` | Grant a bounded capability in response to an escalation. |
| `raxis escalation deny <id> [--reason <text>]` | Refuse the escalation; the agent receives `FAIL_ESCALATION_DENIED`. |
| `raxis log --kind LineageQuarantined` | Find lineages currently quarantined. |
| `raxis log --kind EscalationRateLimited --since 1h` | Identify lineages hitting the rate limit. |

---

## Variations

- **Solo developer.** Bump `timeout_secs` to a multi-hour window
  so you don't lose escalations while you're at lunch:
  `timeout_secs = 14400` (4h).
- **CI-driven plans.** Set `max_per_window = 1` —
  CI plans should escalate at most once per failure; anything else
  is a bug in the plan. Pair with `quarantine_threshold = 1` so
  repeated misbehaviour halts the lineage immediately.
- **Disable rate limit (NOT recommended).** There is no `0` /
  `disable` value; the lowest meaningful setting is
  `max_per_window = 1`. The kernel always enforces *some* cap.

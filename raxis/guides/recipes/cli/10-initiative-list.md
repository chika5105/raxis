# `raxis initiative list`

> **Topic:** CLI | **Time to read:** ~1 min | **Complexity:** ⭐ Beginner

Read-only bucketed listing of initiatives. Default bucket is
`active` (non-terminal states only). The `quarantined` bucket is
**orthogonal** to the FSM — it returns ANY initiative with a row
in `initiative_quarantines`, regardless of state. Reads `kernel.db`
read-only; no kernel IPC.

---

## Syntax

```text
raxis initiative list [--state active|completed|quarantined|all]
                      [--limit N]
                      [--json]
```

---

## Flags

| Flag | Effect |
|---|---|
| `--state <bucket>` | Default `active`. `completed` shows finished. `quarantined` shows any initiative in `initiative_quarantines`. `all` shows everything regardless. |
| `--limit N` | Cap the number of rows. Default 50. |
| `--json` | JSON output for tooling. |

---

## Examples

```bash
# Default: active initiatives.
raxis initiative list

# Filter by state.
raxis initiative list --state active
raxis initiative list --state completed --limit 100
raxis initiative list --state quarantined

# JSON for tooling.
raxis initiative list --state all --json | jq '.rows[] | {initiative_id, state}'
```

Sample table output:

```text
INITIATIVE_ID  NAME                               STATE     LANE        AGE   FLAGS
1f3c8a4b      Add rate limiting                  Active    auth-work   12s
2a7d9f0c      Bump cargo deps                    Completed default     3h
9e1f4b22      Generate OpenAPI                   Quarantd  api-work    2h    [Q]
```

The `[Q]` marker (or `quarantined: true` in JSON) appears for any
quarantined initiative.

---

## Common errors

| Symptom | Fix |
|---|---|
| `initiative list: kernel.db locked` | Kernel mid-startup; retry in a second. |
| `initiative list: --state unknown` | The bucket name doesn't match. Use one of `active`, `completed`, `quarantined`, `all`. |
| Output empty when initiatives exist | The default bucket is `active`. Try `--state all` to confirm. |

---

## Reference

| Command | Purpose |
|---|---|
| `raxis initiative show <id> [--with-tasks]` | Drill into one initiative. |
| `raxis initiative abort <id>` | Stop a running initiative. |
| `raxis initiative quarantine <id> [--reason …]` | Freeze; subsequent intents rejected. |
| `raxis log <initiative_id>` | Audit events for one initiative. |
| `raxis explain <task_id>` | Decision-tree explanation for one task. |

---

## Variations

- **Operator dashboard.** Pipe `--json` through `jq` to feed any
  dashboard you build.
- **Drift alerts.** A cron that runs
  `raxis initiative list --state quarantined --json | jq length`
  and pages on non-zero output.
- **CI smoke check.** Confirm an expected initiative completed:
  `raxis initiative list --state completed --json | jq -e '.rows[] | select(.initiative_id == "$INIT_ID")'`.

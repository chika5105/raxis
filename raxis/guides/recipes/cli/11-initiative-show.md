# `raxis initiative show`

> **Topic:** CLI | **Time to read:** ~3 min | **Complexity:** ⭐⭐ Intermediate

Canonical forensic surface for one initiative. Always prints:
the base header (initiative id / state / created-at), the plan
bundle envelope summary, and the quarantine block. Pass
`--with-tasks` for per-task details, `--bundle` for artifact
listing, `--bundle --to <dir>` for full extraction.

---

## Syntax

```text
raxis initiative show <initiative_id>
                      [--bundle] [--to <dir>]
                      [--json]
                      [--with-tasks] [--task-limit N]
```

---

## Flags

| Flag | Effect |
|---|---|
| `--with-tasks` | Append per-task table (state, agent_type, predecessors, last_intent_kind). |
| `--task-limit N` | Cap rows in the per-task table. Default 100. |
| `--bundle` | Append per-artifact `(seq, name, bytes)` listing. |
| `--bundle --to <dir>` | Extract every artifact under `<dir>`, preserving artifact_name as the relative path. Refuses to write into a non-empty directory. |
| `--json` | JSON output. Supported in every mode except `--to` (where the side-effect IS the output). |

---

## Examples

### Live status

```bash
raxis initiative show 1f3c8a4b
# Output:
# initiative_id:    1f3c8a4b...
# name:             Add rate limiting
# state:            Active
# lane_id:          auth-work
# created_at:       2026-05-10T17:30:00Z
# bundle:
#   schema:           raxis-plan-bundle/v2.1
#   sha_prefix:       ab12cd34
#   epoch:            7
#   signed_by:        alice (8a4f...)
#   signed_at:        2026-05-10T17:29:55Z
#   artifact_count:   1
#   total_bytes:      4321
# quarantined:      no
# tasks:            3
```

### With per-task table

```bash
raxis initiative show 1f3c8a4b --with-tasks
# Appends:
# TASK_ID         AGENT_TYPE   STATE       PREDECESSORS         LAST_INTENT
# implementer     Executor     Completed   []                   CompleteTask
# code_reviewer   Reviewer     Active      [implementer]        (none)
```

### Extract the bundle artifacts

```bash
raxis initiative show 1f3c8a4b --bundle --to /tmp/forensic
ls /tmp/forensic
# plan.toml          # canonical bytes the kernel admitted
```

The extracted `plan.toml` is the **kernel-canonical** form — bytes
the kernel actually saw, not what's on disk in your scenario folder.

### JSON for dashboards

```bash
raxis initiative show 1f3c8a4b --with-tasks --json \
  | jq '{state, tasks: [.tasks[] | {task_id, state}]}'
```

---

## Common errors

| Symptom | Fix |
|---|---|
| `initiative show: not found` | Wrong UUID. `raxis initiative list` to find the right one. |
| `initiative show: --to <dir> not empty` | Pick a fresh directory. The CLI refuses to overwrite. |
| `initiative show: --json with --to` | Mutually exclusive. Drop one. |

---

## Reference

| Command | Purpose |
|---|---|
| `raxis initiative list [--state ...]` | Find initiatives. |
| `raxis log <initiative_id>` | Audit events for the initiative. |
| `raxis explain <task_id>` | Decision tree for a single task within the initiative. |
| `raxis initiative abort <id>` | Stop a running initiative. |

---

## Variations

- **Forensic snapshot.** `raxis initiative show <id> --bundle --to /tmp/incident-$(date +%Y%m%d)`
  + `raxis log <id> --json > /tmp/incident-$(date +%Y%m%d)/log.jsonl`
  produces a self-contained forensic bundle.
- **Re-validation.** Extract the bundle, run
  `raxis plan validate /tmp/forensic/plan.toml` against it. Useful
  to confirm the bundle the kernel admitted is still valid against
  the current policy.
- **Compare two runs.** `--bundle --to` two different initiatives,
  `diff -r` the extracted dirs to see what changed.

# `raxis policy diff`

> **Topic:** CLI | **Time to read:** ~2 min | **Complexity:** ⭐ Beginner

Semantic diff between two validated policy bundles. Reports
per-section deltas (lanes, operators, gates, egress, gateway,
providers, notifications, host_capacity, …) — **not** a textual
diff. Useful for code review of policy changes, comparing two
hosts' active bundles, or auditing what an `epoch advance` would
change.

---

## Syntax

```text
raxis policy diff <left.toml> <right.toml> [--json]
```

---

## Flags

| Flag | Effect |
|---|---|
| `--json` | JSON output. Each section gets `{"added": [...], "removed": [...], "changed": [...]}`. |

---

## Example — review a pending policy change

```bash
# Capture the current policy.
cp "$RAXIS_DATA_DIR/policy/policy.toml" /tmp/policy.before.toml

# Make edits + sign.
$EDITOR "$RAXIS_DATA_DIR/policy/policy.toml"
raxis policy sign "$RAXIS_DATA_DIR/policy/policy.toml" \
  --key "$RAXIS_OPERATOR_KEY"

# Diff against the snapshot.
raxis policy diff /tmp/policy.before.toml \
                  "$RAXIS_DATA_DIR/policy/policy.toml"
```

Sample output:

```text
=== [sessions] ===
  default_ttl_secs:      86400 → 21600
  allowed_worktree_roots:
    - "/tmp"
    + "/var/lib/raxis/worktrees"

=== [[lanes]] ===
  added: ci-bot
  changed: prod-merge.max_cost_per_epoch (50000 → 100000)

=== [[providers.entries]] ===
  no changes
```

The output is grouped by section. Within each section, additions
(`+`), removals (`-`), and per-field updates (`old → new`) are
listed.

---

## Example — compare two hosts

```bash
ssh prod-host "cat /var/lib/raxis/policy/policy.toml" > /tmp/prod-policy.toml
ssh dev-host  "cat /home/dev/.raxis/policy/policy.toml" > /tmp/dev-policy.toml

raxis policy diff /tmp/prod-policy.toml /tmp/dev-policy.toml
```

Confirm that the two installs share the operator entries you expect
(but probably differ on `[host_capacity]`, lanes, etc.).

---

## Example — JSON for tooling

```bash
raxis policy diff before.toml after.toml --json \
  | jq -r '.sessions.changed[]'

# Output:
# default_ttl_secs: 86400 → 21600
```

---

## What's diffed semantically

- **Per-section presence.** A section that exists on one side and
  not the other is reported as added / removed.
- **Per-field equality.** Within a section, each field is compared
  using its validated form (so `1_000_000` and `1000000` are equal,
  trailing whitespace is normalised, etc.).
- **Per-entry diffs in array sections.** `[[lanes]]`, `[[operators]]`,
  `[[gates]]`, `[[providers]]`, `[[vm_images]]`,
  `[[notifications.channels]]`, `[[integration_merge_verifiers]]`,
  `[[permitted_credentials]]`. Entry identity is the entry's
  primary key (e.g., `lane_id`, `pubkey_fingerprint`, `name`).
- **Per-section ordering.** Independent of declaration order.

What's NOT diffed:

- Whitespace, comment, and key ordering inside the file.
- Synthesised defaults (the diff operates on the **declared**
  values, not the resolved-with-defaults ones).

---

## Common errors

| Symptom | Fix |
|---|---|
| `policy diff: file <path> failed to validate as a policy bundle` | One of the inputs isn't a well-formed policy. Validate first with `raxis policy show <path>` (works on a path arg). |
| `policy diff: signature mismatch` | The `<file>.sig` sidecar doesn't match. The diff still runs, but with a warning. |
| Output empty when you expected changes | The change was inside a synthesised default (e.g., adding a value that equals the default). Diff reports declared deltas only. |

---

## Reference

| Command | Purpose |
|---|---|
| `raxis policy show [--history]` | Inspect either side standalone. |
| `raxis policy sign <path>` | Re-sign after edits. |
| `raxis epoch advance --policy <path> --sig <sig>` | Atomic hand-off; useful when you want to apply an externally-prepared bundle. |

---

## Variations

- **PR review.** Diff the proposed `policy.toml` against the
  current; paste the diff into the PR description.
- **Drift detection.** Cron job that runs
  `raxis policy diff /baseline/policy.toml $RAXIS_DATA_DIR/policy/policy.toml`
  against a baseline and pages on non-empty output.
- **Migration validation.** Before `epoch advance`, diff the new
  bundle against the active one to confirm only the intended
  sections changed.

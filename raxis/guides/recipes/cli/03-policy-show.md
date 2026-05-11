# `raxis policy show`

> **Topic:** CLI | **Time to read:** ~1 min | **Complexity:** ⭐ Beginner

Print the active policy bundle, with optional epoch history.
Read-only; opens `kernel.db` read-only and never connects to the
operator socket. Works whether or not the kernel is running.

---

## Syntax

```text
raxis policy show [--json] [--history]
```

---

## Flags

| Flag | Effect |
|---|---|
| `--json` | Output the bundle as JSON instead of pretty-printed TOML. |
| `--history` | Append the `policy_epoch_history` table — every (epoch, signed_by, signed_at, sha256) row the kernel has admitted. |

---

## Examples

```bash
# Pretty-print the active bundle.
raxis policy show

# Inspect just the [sessions] section.
raxis policy show \
  | sed -n '/^\[sessions\]$/,/^\[/p'

# JSON for tooling.
raxis policy show --json | jq '.lanes[] | {lane_id, max_concurrent_tasks}'

# Epoch history.
raxis policy show --history --json | jq '.history[]'
```

Sample output (`--history`):

```text
epoch  signed_by         signed_at             sha256_prefix
1      alice (8a4f...)   2026-05-10T17:30:00Z  ab12cd34...
2      alice (8a4f...)   2026-05-10T19:14:55Z  cd34ef56...
3      bob   (b1c2...)   2026-05-11T09:02:11Z  ef56ab12...
```

---

## What it shows

The output corresponds 1:1 with the validated `PolicyBundle` —
sections are normalised:

- `[meta]` (epoch, signed_by, signed_at).
- `[authority]` (kernel pubkey hex).
- `[escalation_policy]`, `[sessions]`, `[delegations]`, `[budget]`,
  `[budget.base_cost_per_intent_kind]`, `[budget.token_caps]`,
  `[budget.sleep_caps]`.
- `[[lanes]]`, `[[operators.entries]]` + embedded
  `[operators.entries.cert]`, `[[gates]]`,
  `[[integration_merge_verifiers]]`.
- `[gateway]`, `[[providers.entries]]`.
- `[plan_signing]`, `[plan_bundle_limits]`.
- `[notifications]`, `[host_capacity]`, `[git]`.
- `[[vm_images]]`, `[default_executor_image]`.
- `[observability]`.

---

## Common errors

| Symptom | Fix |
|---|---|
| `policy show: kernel.db locked` | Kernel is mid-startup; wait a second and retry. |
| `policy show: policy.toml malformed` | The signed bundle is corrupt; restore from backup or re-genesis. |
| Output is missing fields you expect | Defaults are not printed; only declared values appear. To see effective values, use `raxis doctor` (which surfaces resolved-with-defaults). |

---

## Reference

| Command | Purpose |
|---|---|
| `raxis policy diff <left> <right>` | Semantic diff. |
| `raxis policy sign <path>` | Re-sign after edits. |
| `raxis policy generate-sidecar-secret` | Mint a sidecar HMAC. |
| `raxis doctor` | Resolved-with-defaults view; useful for "why isn't [foo] applied?". |

---

## Variations

- **CI invariants.** Use `raxis policy show --json | jq` in CI to
  assert specific values (e.g., `host_capacity.max_concurrent_vms
  >= 32`).
- **Compare across hosts.** Pipe `policy show` from two hosts
  through `diff` to confirm they're aligned.
- **Forensic export.** `raxis policy show --history --json >
  policy-history-$(date +%Y%m%d).json` for archival snapshots.

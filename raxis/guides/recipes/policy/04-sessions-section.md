# `[sessions]` — TTLs and worktree-root allowlist

> **Topic:** Policy reference | **Time to read:** ~2 min | **Complexity:** ⭐ Beginner

The `[sessions]` block governs session minting: how long sessions
live, the maximum operator-extendable TTL, and which absolute path
prefixes the kernel will agree to provision worktrees beneath.
Without this block your kernel can boot but cannot create sessions.

---

## Field reference

| Field | Type | Required | Default-ish | Effect |
|---|---|---|---|---|
| `default_ttl_secs` | `u64` | yes | `86400` (1d) | TTL stamped on a fresh planner / verifier session when the operator doesn't pass `--ttl` to `session create`. After expiry the session is `Expired`; subsequent IPC frames are rejected with `FAIL_SESSION_EXPIRED`. |
| `max_ttl_secs` | `u64` | yes | `604800` (7d) | Hard ceiling on any session TTL. The operator may pass `--ttl` to `session create` up to this value; longer is rejected. |
| `allowed_worktree_roots` | `Vec<String>` | yes (≥ 1 entry) | (none) | Each entry is an absolute path prefix. A session's `worktree_root` is allowed iff some entry is a strict prefix of the request. No globs. |

`max_ttl_secs >= default_ttl_secs`. The kernel rejects an inverted pair
at policy load time.

`allowed_worktree_roots` MUST be non-empty. An empty list rejects
every session create call — the kernel treats this as a configuration
error and refuses to load.

---

## Example — production

```toml
[sessions]
default_ttl_secs       = 21600          # 6h
max_ttl_secs           = 86400          # 1d ceiling
allowed_worktree_roots = ["/var/lib/raxis/worktrees"]
```

A single owned-by-`_raxis` scratch tree, GC-managed by the kernel,
no demo paths permitted.

## Example — sandbox / demo

```toml
[sessions]
default_ttl_secs       = 86400          # 1d default
max_ttl_secs           = 604800         # 7d ceiling
allowed_worktree_roots = [
  "/tmp",
  "/var/folders",     # macOS TMPDIR base
  "/var/lib/raxis/worktrees",
]
```

---

## Step-by-step — adding a new prefix

```bash
$EDITOR "$RAXIS_DATA_DIR/policy/policy.toml"
# Edit allowed_worktree_roots to add the new prefix.

raxis policy sign \
  "$RAXIS_DATA_DIR/policy/policy.toml" \
  --key "$RAXIS_OPERATOR_KEY"
raxis epoch advance \
  --policy "$RAXIS_DATA_DIR/policy/policy.toml" \
  --sig    "$RAXIS_DATA_DIR/policy/policy.sig"

# Confirm the kernel advanced:
raxis log --kind PolicyEpochAdvanced --limit 1
```

---

## Common failure modes

| Symptom | Fix |
|---|---|
| `FAIL_WORKTREE_OUTSIDE_ALLOWED_ROOTS` on `session create` | The requested `worktree_root` does not start with any entry. Add the prefix; re-sign. |
| `Validation: allowed_worktree_roots must be non-empty` | You shipped an empty list. Add at least one prefix. |
| `Validation: max_ttl_secs < default_ttl_secs` | The two fields are inverted. Fix; re-sign. |
| Sessions silently expire mid-task | `default_ttl_secs` is too short for your workload. Raise it OR pass `--ttl` to `session create`. |
| `FAIL_SESSION_TTL_ABOVE_CEILING` | The operator passed `--ttl <N>` larger than `max_ttl_secs`. Raise `max_ttl_secs` (re-sign), OR lower the request. |

---

## Reference: related CLI

| Command | Purpose |
|---|---|
| `raxis session create --role planner --worktree-root <path> [--ttl <secs>]` | Create a planner session. |
| `raxis session revoke <id>` | Revoke an active session immediately; subsequent IPC is rejected with `FAIL_SESSION_REVOKED`. |
| `raxis sessions [--limit N]` | List active / expired / revoked sessions. |

---

## Variations

- **Per-host different prefixes.** Genesis writes a uniform policy,
  but the allowlist usually differs per host. Use a config-management
  tool to template the right prefixes before signing.
- **Tight TTLs for ephemeral CI.** `default_ttl_secs = 1800`
  (30 min) and `max_ttl_secs = 3600` (1h). Catches stuck sessions
  faster.
- **Long-running batch.** `default_ttl_secs = 86400` (1d) and
  `max_ttl_secs = 604800` (7d). Useful for overnight monorepo
  scans.

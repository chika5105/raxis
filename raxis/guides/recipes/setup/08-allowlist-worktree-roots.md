# Allowlist worktree roots in policy

> **Topic:** Setup | **Time to read:** ~2 min | **Complexity:** ⭐ Beginner

Every Executor / Reviewer / Orchestrator session writes its files
into a worktree. The kernel refuses to provision a worktree whose
absolute path doesn't sit beneath one of the prefixes listed in
`[sessions] allowed_worktree_roots`. This recipe shows how to
configure that list correctly.

---

## Prerequisites

- Existing genesis-completed install. `RAXIS_DATA_DIR` exported.
- `RAXIS_OPERATOR_KEY` set to your signing key.

---

## Step 1 — Inspect the current allowlist

```bash
raxis policy show \
  | sed -n '/^\[sessions\]$/,/^\[/p'
```

Sample output:

```toml
[sessions]
default_ttl_secs       = 86400
max_ttl_secs           = 604800
allowed_worktree_roots = ["/var/lib/raxis/worktrees"]
```

If the `allowed_worktree_roots` line is missing or empty, every
session create call fails with `FAIL_WORKTREE_OUTSIDE_ALLOWED_ROOTS`.

---

## Step 2 — Add the prefix(es) you need

Edit `policy.toml`:

```toml
[sessions]
default_ttl_secs       = 86400
max_ttl_secs           = 604800
allowed_worktree_roots = [
  "/var/lib/raxis/worktrees",   # production install
  "/tmp",                        # demo / scratch
  "/var/folders",                # macOS scratch (TMPDIR base)
]
```

Each entry is a **prefix**, not a glob. `/tmp` allows
`/tmp/raxis-scenario-01/`, `/tmp/raxis-test-foo/`, `/tmp/anything`.
There is no glob support; `*` and `?` are literal characters.

---

## Step 3 — Re-sign the policy

```bash
raxis policy sign \
  "$RAXIS_DATA_DIR/policy/policy.toml" \
  --key "$RAXIS_OPERATOR_KEY"
```

The kernel hot-reloads policy on file change; no restart needed. The
signature is rejected if any part of the file changed since the
prior signing — including comments and whitespace — so always
re-sign after edits.

---

## Step 4 — Confirm the kernel observed the new policy

```bash
# The kernel logs PolicyReloaded with the new epoch on hot-reload.
raxis log --kind PolicyReloaded --limit 5
```

Sample event:

```text
{"event":"PolicyReloaded","epoch_id":7,"new_epoch_id":8,"changed_sections":["sessions"]}
```

The `changed_sections` list confirms the kernel sees the diff and
only the `[sessions]` block changed.

---

## Step 5 — Try a session create and see it succeed

```bash
mkdir -p /tmp/scratch-demo
raxis session create \
  --role planner \
  --worktree-root /tmp/scratch-demo
```

Output (success):

```text
session_id:   c4f1...
session_token: redacted (stderr) — pass --reveal-token to print
worktree_root: /tmp/scratch-demo
expires_at:   ...
```

Failure (when the prefix isn't allowlisted):

```text
session create: FAIL_WORKTREE_OUTSIDE_ALLOWED_ROOTS
hint: /tmp/scratch-demo is not under any [sessions] allowed_worktree_roots prefix
```

---

## Common failure modes

| Symptom | Fix |
|---|---|
| `FAIL_WORKTREE_OUTSIDE_ALLOWED_ROOTS` | Add the prefix and re-sign; the canonical fix is to *broaden* the policy, not to *bypass* it. |
| `policy: signature mismatch` after edit | The file changed but wasn't re-signed. `raxis policy sign …`. |
| Hot reload didn't fire | The kernel watches policy.toml but only when its mtime changes. Some editors write to a temp + rename, breaking the watch — try `touch` after edit. |
| Allowlist worked yesterday, fails today | The host `TMPDIR` may have rotated (macOS `/var/folders/abc/T/` paths are user-specific). Allowlist the parent prefix `/var/folders` instead of the leaf. |

---

## Reference: policy block

| Field | Type | Default | Effect |
|---|---|---|---|
| `[sessions] allowed_worktree_roots` | `Vec<String>` | `[]` (deny everything) | Each entry is an absolute path prefix; a worktree path is allowed iff it begins with at least one entry. |
| `[sessions] default_ttl_secs` | `u64` | `86400` (1d) | New planner / verifier sessions expire after this many seconds. |
| `[sessions] max_ttl_secs` | `u64` | `604800` (7d) | Hard ceiling on session TTL; renewal beyond this is rejected. |

---

## Variations

- **Production-tight.** Keep `allowed_worktree_roots = ["/var/lib/raxis/worktrees"]`
  only. Every session is forced into a single, owned-by-_raxis,
  GC-managed scratch tree. No demo paths permitted.
- **CI-friendly.** Add `/tmp` plus the runner-specific scratch
  (`/runner/_work` on GitHub Actions, `/builds` on GitLab CI).
- **Per-host different roots.** The genesis policy is the same on
  every host, but the allowlist will differ — use a config-management
  tool (Ansible / Chef / NixOS) to template per-host overrides
  before signing.

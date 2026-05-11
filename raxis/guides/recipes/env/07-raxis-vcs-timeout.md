# `RAXIS_VCS_TIMEOUT_SECS` — git command timeout

> **Topic:** Environment variables | **Time to read:** ~2 min | **Complexity:** ⭐⭐ Intermediate

`RAXIS_VCS_TIMEOUT_SECS` caps how long the kernel will wait for any
single git command to complete. The kernel shells out to `git` for
clones, fetches, diffs, merge-bases, and the final fast-forward;
without a cap, a stuck `git fetch` against a hung remote could
deadlock the kernel's worktree provisioning loop.

---

## Read by

- `raxis-kernel` (`crates/dashboard-kernel/src/git.rs`,
  `crates/domain-git/src/git_cli.rs`, `kernel/src/vcs/diff.rs`).
- Both the kernel daemon and any in-process git invocation use the
  same value.

---

## Default

```text
60   (seconds)
```

When unset OR the value isn't a parseable integer, the kernel
falls back to 60 seconds.

---

## Set

```bash
# Foreground kernel:
RAXIS_VCS_TIMEOUT_SECS=120 raxis-kernel

# systemd unit:
[Service]
Environment=RAXIS_VCS_TIMEOUT_SECS=120

# launchd plist:
<key>EnvironmentVariables</key>
<dict>
    <key>RAXIS_VCS_TIMEOUT_SECS</key>
    <string>120</string>
</dict>
```

---

## What gets timed out

| Operation | Affected |
|---|---|
| `git clone` for a session worktree | yes |
| `git fetch` during integration merge | yes |
| `git diff` for path derivation | yes |
| `git merge-base` and `git rev-list` | yes |
| `git push` (when `[git] auto_push = true`) | yes |
| `git symbolic-ref`, `git rev-parse` | yes |
| Verifier-internal git invocations | NO — verifiers run their own git, this env var doesn't propagate. |

---

## When to raise

- **Large repos.** A 5 GB monorepo's initial clone over a slow
  network can exceed 60s. Bump to 300s+.
- **Slow remote git server.** Internal Gerrit / Gitea instances
  with weak hardware sometimes need 2–5 minutes for a `clone
  --filter=blob:none`.
- **Heavy `git fetch`.** First-fetch on a worktree that hasn't
  fetched in a while pulls a lot of objects.

## When to lower

- **Local-only repos** (no remote, file:// or `git daemon` on the
  same host). 30s is plenty.
- **CI runners with strict timeouts.** Match the runner's
  per-step cap so failure is fast and clear.

```bash
RAXIS_VCS_TIMEOUT_SECS=30 raxis-kernel    # tight CI mode
```

---

## What happens on timeout

The kernel kills the git subprocess (SIGTERM, then SIGKILL after
10s if still alive) and returns a typed error:

```text
{"event":"GitCommandTimedOut","cmd":"git clone …","elapsed_secs":60,"timeout_secs":60}
```

Depending on the calling path:

- **Worktree provisioning timeout.** The session's `Activate`
  intent fails with `FAIL_WORKTREE_PROVISION`. The agent never
  starts.
- **Integration merge timeout.** The merge transaction rolls back;
  the target ref is NOT advanced. The Orchestrator receives
  `FAIL_INTEGRATION_MERGE_TIMEOUT`.
- **Diff / merge-base timeout.** The intent the kernel was trying
  to evaluate fails with the typed error; the agent retries.

---

## Common failure modes

| Symptom | Fix |
|---|---|
| Repeated `GitCommandTimedOut` for the same op | Either the remote is genuinely slow / down, OR the timeout is too tight. Investigate first; raise as a last resort. |
| Kernel hangs even with this set | Some git path doesn't honour the timeout (rare; file an issue). The cap applies to subprocess wait, not to in-process git2 calls. |
| Inconsistent timing across two installs | Different env values; `echo $RAXIS_VCS_TIMEOUT_SECS` on each kernel host. |

---

## Reference: related env vars + state

| Surface | Purpose |
|---|---|
| `raxis log --kind GitCommandTimedOut --since 1h` | Audit trail. |
| `<data-dir>/runtime/git-{clone,fetch,push,...}.log` | Per-command logs the kernel writes for forensics. |
| `[git] default_target_ref` (policy) | Used by integration merge — independent of this var. |

---

## Variations

- **Per-environment.** Different value on slow-network hosts vs
  fast-LAN ones. The env var is read at every git invocation, so
  changes take effect immediately without kernel restart.
- **Unbounded.** No "disable" value — the lowest meaningful is 1.
  If you need genuinely-unbounded git operations, you have a
  remote-server problem and should fix that first.
- **Per-CI-step.** Set in each CI step's env block to match the
  step's overall timeout. Keeps RAXIS-side failures fast and
  aligned with the runner.

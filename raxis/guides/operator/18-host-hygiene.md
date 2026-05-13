# Host worktree hygiene — preventing parent-side disk fill

> **Topic:** Operations | **Time to read:** ~5 min | **Complexity:** ⭐⭐ Intermediate

Each parent-side parallel agent that runs against this repo
creates its own `git worktree add` checkout (typically under
`/private/tmp/raxis-<task>-<pid>/`). Every worktree carries a
multi-GiB `cargo target/`. A handful of concurrent workers can
fill the data volume in hours and trip the kernel's
`DiskFullHaltEntered` safety circuit mid-run — which fails every
in-flight activation with `FAIL_DISK_FULL` ([INV-CAPACITY-02],
[`host-capacity.md §7.1`]).

The `cargo xtask hygiene` family is the operator-side mechanism
that prevents that recurrence. It is the canonical implementation
of [`INV-HOST-HYGIENE-01`].

---

## What gets pruned

`cargo xtask hygiene` enumerates `git worktree list --porcelain`
and classifies each entry. A worktree is REMOVABLE only when ALL
of the following hold:

1. It is NOT the main checkout.
2. It is NOT on the operator's `--keep BRANCH ...` allowlist.
3. It is NOT the directory the running `cargo xtask` was
   invoked from.
4. It is NOT `git worktree lock`-ed.
5. Its branch tip IS reachable from `origin/main`
   (`git merge-base --is-ancestor <tip> origin/main`).
6. NO live process holds files open under the worktree
   (`lsof -d cwd` evidence).

Anything else is KEPT, with a typed `KeepReason` printed to
`stderr` so the dry-run output is auditable.

---

## Manual sweep

```bash
# 1) Always start with a dry-run. Reads only.
cargo xtask hygiene --dry-run

# 2) Apply the sweep when the dry-run output looks right.
cargo xtask hygiene

# 3) Optional: protect specific branches even if they have landed
#    (e.g. a worker you want to keep around for follow-up review).
cargo xtask hygiene --keep worker/some-feature --keep worker/other

# 4) Optional: only sweep worktrees whose head commit is older
#    than N days. Useful on shared hosts.
cargo xtask hygiene --max-age-days 1
```

The sweep prints a `[hygiene] removed=X kept=Y disk_free_before=...
disk_free_after=...` summary line to `stderr` so the operator can
confirm the reclamation.

---

## Disk-pressure preflight

```bash
# Read-only `df -P` probe. Exit non-zero when the repo volume,
# /private/tmp, or /var/folders/* exceeds --threshold-pct.
cargo xtask hygiene-check --threshold-pct 90
```

This is the same probe the live-e2e harness runs at preflight.
Embedding it in your own dev loop (e.g. in a `pre-commit` hook
or in your shell prompt) catches saturation before a long-running
build trips it.

---

## Periodic timer (recommended)

The repo ships ready-made unit files for both macOS and Linux.

### macOS (launchd)

```bash
# 1) Install the per-user LaunchAgent. Reads only with --dry-run.
cargo xtask hygiene-install-timer --dry-run
cargo xtask hygiene-install-timer

# 2) Verify it loaded.
launchctl list | grep com.raxis.hygiene

# 3) Logs land at ~/Library/Logs/raxis-hygiene.{out,err}.log
tail -f ~/Library/Logs/raxis-hygiene.err.log
```

The plist runs `cargo xtask hygiene --max-age-days 1` every six
hours (00:00, 06:00, 12:00, 18:00 local) and never sweeps at
load time — the operator must run a manual `--dry-run` first.

### Linux (systemd-user)

```bash
# 1) Install the user-scope timer.
cargo xtask hygiene-install-timer --dry-run
cargo xtask hygiene-install-timer

# 2) Verify the timer is enabled and the next scheduled run.
systemctl --user list-timers raxis-hygiene.timer

# 3) Tail the journal for sweep output.
journalctl --user -u raxis-hygiene.service -f
```

For a system-wide install (sweep runs as root, useful for shared
build hosts) pass `--system`:

```bash
sudo cargo xtask hygiene-install-timer --system
```

---

## Uninstall

```bash
cargo xtask hygiene-install-timer --uninstall
# add --system if you installed system-wide on Linux
```

---

## Opt-out

If you're happy doing the sweep by hand, just don't install the
timer. The live-e2e preflight ([INV-HOST-HYGIENE-01]) still fires
when the volume goes above 90% — you'll see the
`OperatorAttentionRequired { attention_kind:
"HostHygieneDiskPressure" }` event in the dashboard banner, and
the test will fail-fast with the remediation command embedded in
the structured payload.

---

## Related

- [INV-HOST-HYGIENE-01] — `raxis/specs/invariants.md §11.10`
- [INV-CAPACITY-02] — disk-full halt-admit, the watchdog this sweep is preventing from tripping
- [`host-capacity.md`] — the kernel's own disk-pressure watchdog (data-dir scope, distinct from the host-wide hygiene scope here)

[INV-HOST-HYGIENE-01]: ../../specs/invariants.md
[INV-CAPACITY-02]: ../../specs/v2/host-capacity.md
[`host-capacity.md`]: ../../specs/v2/host-capacity.md
[`host-capacity.md §7.1`]: ../../specs/v2/host-capacity.md
[`INV-HOST-HYGIENE-01`]: ../../specs/invariants.md

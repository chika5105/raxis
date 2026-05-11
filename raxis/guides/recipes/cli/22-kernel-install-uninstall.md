# `raxis kernel install` and `raxis kernel uninstall`

> **Topic:** CLI | **Time to read:** ~3 min | **Complexity:** ⭐⭐ Intermediate

Install or uninstall the kernel as a system service. On Linux this
writes systemd units; on macOS launchd plists. Both commands
respect `RAXIS_INSTALL_DIR` to override the default install path.

---

## Syntax

```text
raxis kernel install   [--user] [--data-dir <path>] [--no-enable] [--binary <path>]
raxis kernel uninstall [--user] [--purge]
```

---

## install — system service

Default Linux install (root):

```bash
sudo RAXIS_DATA_DIR=/var/raxis \
     RAXIS_OPERATOR_KEY=/etc/raxis/operator.key \
     raxis kernel install
# Output:
# unit_path:    /etc/systemd/system/raxis-kernel.service
# enabled:      yes
# active:       active (running)
# data_dir:     /var/raxis
```

User-mode (no root needed):

```bash
RAXIS_DATA_DIR="$HOME/.raxis" \
RAXIS_OPERATOR_KEY="$HOME/.raxis/operator.key" \
raxis kernel install --user
# Output:
# unit_path:  ~/.config/systemd/user/raxis-kernel.service
# enabled:    yes
# active:     active (running)
```

What the install does:

1. Generates a systemd unit (or launchd plist on macOS) pointing at
   the `raxis-kernel` binary (defaults to the binary on `$PATH`;
   override with `--binary` or `RAXIS_KERNEL_BINARY`).
2. Sets `Environment=RAXIS_DATA_DIR=…` and `RAXIS_OPERATOR_KEY=…`
   in the unit so the service can find them.
3. `daemon-reload`, `enable`, and `start` (skipped with
   `--no-enable`).

Override the install dir with `RAXIS_INSTALL_DIR`:

```bash
RAXIS_INSTALL_DIR=/opt/myorg/raxis raxis kernel install
# Writes /opt/myorg/raxis/raxis-kernel.service and registers it
# under that path's systemd file-set. Useful for non-root packaging.
```

---

## uninstall — remove the service

```bash
sudo raxis kernel uninstall
# Output:
# stopped:      yes
# unit_removed: /etc/systemd/system/raxis-kernel.service
# data_dir:     /var/raxis  (preserved)
```

`--purge` also wipes `RAXIS_DATA_DIR`:

```bash
sudo raxis kernel uninstall --purge
# Output:
# stopped:      yes
# unit_removed: /etc/systemd/system/raxis-kernel.service
# data_dir:     /var/raxis  (PURGED — all kernel state deleted)
```

Purging is destructive and removes:

- The audit chain (`audit.jsonl`).
- The kernel database (`kernel.db`).
- All worktrees and verifier images.
- Embedded operator certs and signed policy.

For a forensic backup before purge:

```bash
tar czf /tmp/raxis-backup-$(date +%Y%m%d).tgz "$RAXIS_DATA_DIR"
sudo raxis kernel uninstall --purge
```

---

## Service control after install

| Linux | macOS |
|---|---|
| `systemctl status raxis-kernel` | `launchctl list \| grep raxis` |
| `journalctl -u raxis-kernel -f` | `tail -f ~/Library/Logs/raxis/kernel.out` |
| `systemctl restart raxis-kernel` | `launchctl bootout … && launchctl bootstrap …` |
| `systemctl stop raxis-kernel` | `launchctl unload …` |

---

## Common errors

| Symptom | Fix |
|---|---|
| `install: must be root for system unit` | Re-run with `sudo`, or pass `--user` for user-mode service. |
| `install: RAXIS_DATA_DIR not set` | Export it (or pass `--data-dir <path>`). |
| `install: RAXIS_OPERATOR_KEY not set` | Same as above. The kernel refuses to start without an operator key. |
| `install: kernel already running on this data-dir` | Stop the existing service first or choose a different `RAXIS_DATA_DIR`. |
| `uninstall --purge: data dir not empty after purge` | Some files were locked; investigate `lsof` and retry. |

---

## Reference

| Command | Purpose |
|---|---|
| `raxis genesis` | First-time data-dir bootstrap. |
| `raxis status` | Confirm the kernel is responsive after install. |
| `raxis doctor` | Diagnostic suite (file paths, perms, key chain, etc.). |

---

## Variations

- **CI install.** `raxis kernel install --user --no-enable` then
  manually `systemctl --user start raxis-kernel` from the test
  setup; unit lifecycle scoped to the CI runner.
- **Docker / container install.** Don't use systemd; run
  `raxis-kernel` directly as PID 1 in a container with proper
  volume mounts for `RAXIS_DATA_DIR`.
- **Multi-instance host.** Use distinct `RAXIS_DATA_DIR` and
  `RAXIS_INSTALL_DIR` per instance; each gets its own
  `raxis-kernel-<inst>.service` unit.
- **Re-install after upgrade.** `kernel uninstall` (without
  `--purge`), update the binary on `$PATH`, `kernel install` —
  unit picks up the new binary.

# Uninstall RAXIS cleanly

> **Topic:** Setup | **Time to read:** ~2 min | **Complexity:** ⭐ Beginner

A complete teardown that removes the daemon, the binaries, the data
directory, and the operator keys. After this recipe nothing on the
machine remembers RAXIS ever existed (modulo audit chain *exports*
you may have copied elsewhere).

---

## Prerequisites

- Confirm `RAXIS_DATA_DIR` matches the install you want to remove
  (`echo $RAXIS_DATA_DIR`). The teardown is irreversible.

---

## Step-by-step

```bash
# 1. Stop the kernel.
#    User-level systemd:
systemctl --user stop raxis-kernel 2>/dev/null || true
systemctl --user disable raxis-kernel 2>/dev/null || true
#    System-level systemd:
sudo systemctl stop raxis-kernel 2>/dev/null || true
sudo systemctl disable raxis-kernel 2>/dev/null || true
#    macOS user-level launchd:
launchctl bootout gui/$(id -u)/com.raxis.kernel 2>/dev/null || true
#    macOS system-level launchd:
sudo launchctl bootout system/com.raxis.kernel 2>/dev/null || true
#    Or — if you ran the kernel manually in a terminal — just Ctrl-C it.

# 2. Remove the unit file the CLI installed.
raxis kernel uninstall 2>/dev/null || true
sudo raxis kernel uninstall --system 2>/dev/null || true

# 3. Wipe the data dir. IRREVERSIBLE — exports first if needed.
rm -rf "$RAXIS_DATA_DIR"

# 4. Remove the binaries (cargo install put them under ~/.cargo/bin).
rm -f ~/.cargo/bin/raxis ~/.cargo/bin/raxis-kernel ~/.cargo/bin/raxis-gateway

# 5. Remove the operator keys (only if you don't reuse them).
rm -rf "$HOME/raxis-keys"

# 6. Unset the env vars in your shell rc file.
$EDITOR ~/.zshrc ~/.bashrc   # remove any RAXIS_DATA_DIR / RAXIS_OPERATOR_KEY exports
```

---

## Pre-uninstall: export anything you want to keep

The audit chain is tamper-evident *only* while the host that wrote
it is honest. If you want to retain proof of past kernel decisions,
copy the chain off-host **before** step 3:

```bash
mkdir -p ~/raxis-archive/$(date +%Y%m%d)
cp -r "$RAXIS_DATA_DIR/audit"        ~/raxis-archive/$(date +%Y%m%d)/
cp -r "$RAXIS_DATA_DIR/policy"       ~/raxis-archive/$(date +%Y%m%d)/
cp     "$RAXIS_DATA_DIR/kernel.db"   ~/raxis-archive/$(date +%Y%m%d)/

# Verify the archived chain is still intact.
raxis verify-chain --audit-dir ~/raxis-archive/$(date +%Y%m%d)/audit
```

The exported `audit/` + `policy/` pair is enough to reconstruct
every kernel decision the install ever made.

---

## What success looks like

```bash
which raxis raxis-kernel raxis-gateway   # all three should print nothing (rc 1)
ls "$RAXIS_DATA_DIR" 2>/dev/null         # should print "No such file or directory"
systemctl --user status raxis-kernel 2>/dev/null   # "Unit raxis-kernel.service could not be found"
```

---

## Common failure modes

| Symptom | Fix |
|---|---|
| `rm: Permission denied` on the data dir | The system-level install runs as `_raxis`. Use `sudo rm -rf "$RAXIS_DATA_DIR"`. |
| `kernel uninstall` reports "no unit file found" | Either it was never installed via `raxis kernel install` (you ran the kernel by hand) or it was installed at the other scope — try with/without `--system`. |
| Kernel still running after `systemctl stop` | Some other supervisor (tmux, screen, foreground shell) is keeping it up. `pkill raxis-kernel` as a last resort. |
| Audit chain rejects re-import after archive | The `audit/` directory was archived inconsistently mid-write. Always stop the kernel **before** archiving (step 1). |

---

## Reference

| Command | Purpose |
|---|---|
| `raxis kernel uninstall` / `--system` | Remove the templated unit file. Does NOT stop the kernel; you must do that yourself. |
| `raxis verify-chain --audit-dir <path>` | Verify a chain that lives outside `RAXIS_DATA_DIR/audit/`, useful for archives. |

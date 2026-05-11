# Install RAXIS as a system daemon (Linux + macOS)

> **Topic:** Setup | **Time to read:** ~5 min | **Complexity:** ⭐⭐ Intermediate

`raxis kernel install` writes a platform-native unit file (systemd
on Linux, launchd on macOS) populated with this binary's resolved
`raxis-kernel` path and your `--data-dir`. After enabling the
service, the kernel survives reboots, restarts on crash, and
captures stdout/stderr into the standard logging surface (`journald`
or unified log).

---

## Prerequisites

- A working sandbox install (genesis run, policy signed, providers
  configured). See the *Bring up a sandbox RAXIS install on a clean
  machine* recipe.
- `RAXIS_DATA_DIR` set in the shell where you run `raxis kernel install`.
  The CLI templates this value into the unit file verbatim — the
  installed service uses **whatever value the env had at install
  time**.

---

## User-level install (recommended for sandboxes)

```bash
export RAXIS_DATA_DIR="$HOME/.raxis-demo"
raxis kernel install
```

What this does on each platform:

### Linux (systemd)

- Writes `~/.config/systemd/user/raxis-kernel.service`.
- Templates `ExecStart=` with the resolved `which raxis-kernel` path.
- Templates `Environment=RAXIS_DATA_DIR=…` from the current env.
- Prints the next-step command:

  ```bash
  systemctl --user daemon-reload
  systemctl --user enable --now raxis-kernel
  systemctl --user status raxis-kernel
  ```

  Logs flow to `journalctl --user -u raxis-kernel -f`.

### macOS (launchd)

- Writes `~/Library/LaunchAgents/com.raxis.kernel.plist`.
- Stamps `ProgramArguments` with the absolute `raxis-kernel` path.
- Stamps the `EnvironmentVariables` dict with `RAXIS_DATA_DIR`.
- Prints the next-step command:

  ```bash
  launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/com.raxis.kernel.plist
  launchctl print gui/$(id -u)/com.raxis.kernel
  ```

  Logs flow to `~/Library/Logs/raxis-kernel.{out,err}.log` (paths
  pinned in the templated plist).

---

## System-level install (production)

```bash
sudo RAXIS_DATA_DIR=/var/lib/raxis raxis kernel install --system
```

What this does:

- Linux: writes `/etc/systemd/system/raxis-kernel.service`. Runs as
  the dedicated `_raxis` user, expecting `/var/lib/raxis` to be
  owned by that user. Enable with
  `sudo systemctl enable --now raxis-kernel`.
- macOS: writes `/Library/LaunchDaemons/com.raxis.kernel.plist`,
  enabled with `sudo launchctl bootstrap system /Library/LaunchDaemons/com.raxis.kernel.plist`.

You must **separately** create the `_raxis` user and chown the data
dir:

```bash
# Linux
sudo useradd --system --home-dir /var/lib/raxis --shell /usr/sbin/nologin _raxis
sudo chown -R _raxis:_raxis /var/lib/raxis

# macOS — use dscl to create the role account; out of scope for this recipe.
```

---

## Inspect the templated unit file

```bash
# Linux
cat ~/.config/systemd/user/raxis-kernel.service        # user-level
sudo cat /etc/systemd/system/raxis-kernel.service       # system-level

# macOS
cat ~/Library/LaunchAgents/com.raxis.kernel.plist
sudo cat /Library/LaunchDaemons/com.raxis.kernel.plist
```

Verify the `ExecStart` (Linux) or `ProgramArguments` (macOS) points
at the absolute binary path. Verify the `RAXIS_DATA_DIR` env value
matches your install. If either is wrong, run
`raxis kernel uninstall` and re-install with the correct env.

---

## Override the binary path

```bash
RAXIS_DATA_DIR=/var/lib/raxis raxis kernel install \
  --binary /opt/raxis/bin/raxis-kernel
```

Use this when the kernel binary lives somewhere `which raxis-kernel`
can't find — e.g., a packaged install at `/opt/raxis/bin/`. The
templated unit file uses the path you pass verbatim.

The resolution precedence is:

1. `--binary <path>` (explicit flag).
2. `$RAXIS_KERNEL_BINARY` env var (if set).
3. `which raxis-kernel` on `$PATH`.

---

## Override the install dir

```bash
RAXIS_INSTALL_DIR=/etc/raxis raxis kernel install --system
```

By default the installer writes under `~/.config/systemd/user/` (Linux
user), `/etc/systemd/system/` (Linux system), or the matching
LaunchAgents/LaunchDaemons paths on macOS. Set `RAXIS_INSTALL_DIR` to
override the directory while keeping the platform-native filename.

This is mostly useful for dry-runs that template the unit file into
a sandbox path you can inspect before installing for real.

---

## Force overwrite an existing unit

```bash
raxis kernel install --force
```

Without `--force`, the installer refuses to overwrite an existing
unit file. With `--force`, the file is replaced atomically (write to
`<unit>.tmp`, `mv` over). The previous unit's contents end up in the
trash; if you customised it, **back it up first**.

---

## Uninstall

```bash
raxis kernel uninstall          # user-level
sudo raxis kernel uninstall --system   # system-level
```

This removes the templated unit file. It does NOT stop a running
kernel; the printed follow-up commands tell you to run
`systemctl disable` (Linux) or `launchctl bootout` (macOS) yourself,
because the CLI cannot interact with the service manager without
sudo elevation that the operator might not want.

After uninstall, the data dir at `RAXIS_DATA_DIR` is untouched — the
installer manages only the unit file. Tear down the data dir
separately when you're done.

---

## Common failure modes

| Symptom | Fix |
|---|---|
| `kernel install: refusing to overwrite existing unit file` | Pass `--force` (after backing up your customisations). |
| `raxis-kernel: command not found` after enable | The installer templated a path that no longer exists. `raxis kernel install --binary $(which raxis-kernel) --force` to re-template. |
| systemd `Failed to start raxis-kernel.service` | `journalctl --user -u raxis-kernel` for the actual stderr. Most often this is a missing `RAXIS_DATA_DIR` (the env block in the unit was empty). Re-install with the env set. |
| launchd `Bootstrap failed: 5: Input/output error` | The plist is malformed. Inspect with `plutil -lint ~/Library/LaunchAgents/com.raxis.kernel.plist`. Re-install with `--force`. |
| Service starts but `raxis status` reports `stopped` | The kernel is running under a different `RAXIS_DATA_DIR` than the shell where you ran `status`. `systemctl --user show raxis-kernel -p Environment` (Linux) or `launchctl print` (macOS) to confirm. |

---

## Reference: env vars + flags

| Variable / flag | Purpose |
|---|---|
| `RAXIS_DATA_DIR` (env) | Templated into the unit file's env block. Pin it in the shell where you run `kernel install`; it does NOT update if you later change the shell value. |
| `RAXIS_KERNEL_BINARY` (env) | Path to the `raxis-kernel` binary; used when `--binary` isn't passed and `which` fails. |
| `RAXIS_INSTALL_DIR` (env) | Override the directory the installer writes the unit file to. Default: platform-canonical (`~/.config/systemd/user/`, `/etc/systemd/system/`, LaunchAgents/LaunchDaemons). |
| `--system` | Install at the system level (sudo required) instead of the user level. |
| `--binary <path>` | Override the resolved `raxis-kernel` path templated into the unit. |
| `--force` | Overwrite an existing unit file. |

---

## Variations

- **Both user-level and system-level on the same machine.** Allowed —
  the unit names differ in scope. The user-level service runs in
  your session; the system-level one runs at boot. Don't run both
  against the same `RAXIS_DATA_DIR` simultaneously: SQLite WAL on
  `kernel.db` is exclusive-locked and the second kernel will
  fail-loop on boot.
- **Hand-roll the unit file.** The reference templates ship under
  `raxis/installer/{systemd,launchd}/`. Copy one, edit the
  ExecStart/ProgramArguments + Environment lines, install with
  `cp` instead of `raxis kernel install`. The CLI installer is
  optional — there's nothing magical inside the unit file.
- **Custom log rotation (Linux).** journald handles rotation by
  default. To rotate manually, ship `/etc/logrotate.d/raxis-kernel`
  pointing at journald's persistent path
  (`/var/log/journal/`).
- **Custom log rotation (macOS).** Use the bundled
  `installer/newsyslog/raxis.conf` template — it rotates the
  `~/Library/Logs/raxis-kernel.{out,err}.log` files via newsyslog.

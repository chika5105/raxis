# `RAXIS_INSTALL_DIR` — override systemd / launchd unit directory

> **Topic:** Environment variables | **Time to read:** ~2 min | **Complexity:** ⭐⭐ Intermediate

`RAXIS_INSTALL_DIR` overrides the directory `raxis kernel install`
writes the systemd / launchd unit file to. By default the
installer uses platform-canonical paths; this var is mostly useful
for sandbox / dry-run installs where you want to inspect the
templated unit before installing for real.

---

## Read by

- `raxis kernel install` — when the env var is set, the unit file
  is written under that path instead of the platform default.
- `raxis kernel uninstall` — uses the same path to find and remove
  the unit.
- `raxis doctor` — uses this to verify the install path matches
  the running kernel's unit file.

---

## Default (when unset)

| Platform + scope | Default install dir |
|---|---|
| Linux user-level | `~/.config/systemd/user/` |
| Linux system-level (`--system`) | `/etc/systemd/system/` |
| macOS user-level | `~/Library/LaunchAgents/` |
| macOS system-level (`--system`) | `/Library/LaunchDaemons/` |

The CLI writes a single file (`raxis-kernel.service` on Linux,
`com.raxis.kernel.plist` on macOS) under the chosen directory.

---

## Set

```bash
export RAXIS_INSTALL_DIR=/tmp/raxis-installer-dryrun
mkdir -p "$RAXIS_INSTALL_DIR"

raxis kernel install
# Writes /tmp/raxis-installer-dryrun/raxis-kernel.service (Linux)
# or       /tmp/raxis-installer-dryrun/com.raxis.kernel.plist (macOS).

# Inspect the templated unit:
cat /tmp/raxis-installer-dryrun/raxis-kernel.service
```

The CLI prints the next-step `systemctl --user enable --now …`
or `launchctl bootstrap …` command, but you can choose not to run
it and just keep the file as documentation.

---

## When this is useful

- **Dry-run / preview.** Template the unit into a sandbox path,
  inspect it, decide whether to commit to the canonical install.
- **Custom packaging.** A vendor's package (`.deb`, `.rpm`)
  templates the unit during build into a staging dir, then ships
  the file. Use `RAXIS_INSTALL_DIR` to point the installer at the
  staging dir instead of the live system.
- **Multi-tenant.** Multiple kernel installs on one host (each
  with its own `RAXIS_DATA_DIR`) need separate unit files. Set
  `RAXIS_INSTALL_DIR` to a tenant-specific dir to avoid stomping.

---

## Common failure modes

| Symptom | Fix |
|---|---|
| `kernel install: install dir does not exist` | Create the dir first: `mkdir -p "$RAXIS_INSTALL_DIR"`. The installer doesn't create parent directories. |
| `kernel install: refusing to overwrite existing unit file` | Pass `--force` (after backing up the old unit). |
| Unit installed but systemd / launchd doesn't see it | Override path → systemd / launchd doesn't auto-discover. You'd have to manually `systemctl link <path>` or `launchctl load <path>`. The override path is for inspection / staging, not direct enable. |
| `kernel uninstall` says "no unit found" | The CLI uninstaller looks at the same `RAXIS_INSTALL_DIR` that was set at install time. Match the env, then re-run uninstall. |

---

## Reference: related env vars + commands

| Variable / command | Relationship |
|---|---|
| `RAXIS_KERNEL_BINARY` | Path to the `raxis-kernel` binary; templated into the unit's ExecStart / ProgramArguments. |
| `RAXIS_DATA_DIR` | Templated into the unit's environment block. |
| `--system` (kernel install) | Switches to system-level paths even with the env var set. |
| `--binary <path>` | Override the resolved kernel binary path. |
| `--force` | Overwrite an existing unit. |

---

## Variations

- **Don't set in production.** Production hosts almost always want
  the platform-canonical path so systemd / launchd discovers the
  unit automatically.
- **CI staging.** Use this in CI to template + diff the unit
  against an expected fixture without polluting the runner's
  systemd state.
- **Container builds.** During Docker / OCI image builds, set this
  to the staging path that gets COPYed into the final image at
  the canonical location.

# `RAXIS_KERNEL_BINARY` — kernel binary path override

> **Topic:** Environment variables | **Time to read:** ~1 min | **Complexity:** ⭐ Beginner

`RAXIS_KERNEL_BINARY` overrides the `raxis-kernel` binary path the
installer (`raxis kernel install`) templates into the systemd /
launchd unit file. Useful when the binary lives somewhere
`which raxis-kernel` can't find — packaged installs at
`/opt/raxis/bin/`, custom build artefacts under `target/`, etc.

---

## Read by

- `raxis kernel install` — when no `--binary` flag is passed, the
  installer reads this var. If both are unset, it falls back to
  `which raxis-kernel`.

The kernel daemon itself does NOT read this var; it only matters at
install / uninstall time.

---

## Default

Unset. The installer falls back to `which raxis-kernel` on
`$PATH`.

---

## Set

```bash
# One-shot during install:
RAXIS_KERNEL_BINARY=/opt/raxis/bin/raxis-kernel raxis kernel install

# Or persistently:
export RAXIS_KERNEL_BINARY=/opt/raxis/bin/raxis-kernel
raxis kernel install
```

The installer then templates `ExecStart=/opt/raxis/bin/raxis-kernel`
(Linux) or the equivalent `ProgramArguments` array (macOS) into the
unit file.

---

## Resolution precedence

```text
--binary <path>                 ← always wins
   ├── if NOT passed:
   │      RAXIS_KERNEL_BINARY   ← fall back here
   │      └── if unset: which raxis-kernel
```

---

## When to use

- **Vendor packages** that ship under non-standard paths
  (`/opt/raxis/bin/`, `/usr/lib/raxis/bin/`).
- **Multiple kernel versions** side-by-side: pin the unit at a
  specific binary version while `which` returns whatever's at the
  top of `$PATH`.
- **Development.** `RAXIS_KERNEL_BINARY="$(cargo build -p raxis-kernel
  --message-format=json | jq -r 'select(.executable!=null).executable')"`
  templates the unit at your latest debug build.

---

## Common failure modes

| Symptom | Fix |
|---|---|
| `kernel install: binary not found at <path>` | The path doesn't exist or isn't executable. `ls -l "$RAXIS_KERNEL_BINARY"`. |
| Service starts but crashes immediately | The binary is the wrong shape (e.g., `raxis` instead of `raxis-kernel`). Templated path must point at `raxis-kernel`. |
| `which raxis-kernel` differs from the unit's `ExecStart` | The unit was templated with a different value than the current `which` output. Re-run `raxis kernel install --force`. |

---

## Reference: related env vars + flags

| Variable / flag | Relationship |
|---|---|
| `--binary <path>` | Always wins over `RAXIS_KERNEL_BINARY`. |
| `RAXIS_INSTALL_DIR` | Controls *where* the unit file lives, not what it points at. |
| `RAXIS_DATA_DIR` | Templated into the unit's environment block. |

---

## Variations

- **Symlink.** Some installs symlink `/usr/local/bin/raxis-kernel`
  → `/opt/raxis/<version>/bin/raxis-kernel`. The installer
  templates the resolved real path; reinstall after rotating the
  symlink target.
- **Containers.** Inside a container the binary is typically at a
  fixed path (`/usr/local/bin/raxis-kernel`); `which` works fine
  and you don't need this env.

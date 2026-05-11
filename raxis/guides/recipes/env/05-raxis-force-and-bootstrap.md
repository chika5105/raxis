# `RAXIS_FORCE` and `RAXIS_BOOTSTRAP` — kernel boot flags

> **Topic:** Environment variables | **Time to read:** ~2 min | **Complexity:** ⭐⭐ Intermediate

These two boot-time toggles change how the kernel handles edge
cases that would normally exit the process. Both are intended for
**operator-supervised one-off ceremonies**, not steady-state running.

---

## `RAXIS_FORCE` — overwrite-existing-data-dir at genesis

### Read by

- `raxis genesis` — when the data dir is already populated (has
  `policy/` or `audit/segment-000.jsonl`), genesis exits with
  `genesis: refusing to overwrite existing data dir`. Setting
  `RAXIS_FORCE=1` (any non-empty value) overrides this.

### Effect when set

The genesis ceremony **wipes the existing data dir contents** before
re-running. **This is irreversible**: every audit segment, every
admitted plan bundle, every operator entry — gone.

### When to use

- Resetting a sandbox install to factory state. (`rm -rf` is
  cleaner; `RAXIS_FORCE` exists for the case where you can't easily
  rm because the dir is mounted.)
- Recovering from a half-genesis (genesis crashed mid-write,
  leaving a partial layout).

### When NOT to use

- Production. Never. Use `rm -rf` after explicitly archiving the
  audit chain.
- "Just to make the error go away." Read what the kernel says first.

### Set

```bash
RAXIS_FORCE=1 raxis genesis --operator-key "$RAXIS_OPERATOR_KEY" --operator-name "$USER"
```

---

## `RAXIS_BOOTSTRAP` — bootstrap mode

### Read by

- `raxis-kernel` at boot. Setting any non-empty value enables
  bootstrap mode for this run only.

### Effect when set

Bootstrap mode lets the kernel boot **without a fully-loaded policy
bundle**. This is used during the genesis ceremony itself, where:

1. The kernel needs to boot to write `policy/policy.toml`.
2. But policy.toml doesn't exist yet.

In bootstrap mode the kernel:

- Skips the `[[operators.entries]]` cert-validation step (no
  operators are declared yet).
- Skips the `[gateway]` / `[[providers]]` validation (no inference
  needed for genesis).
- Skips the `verify-chain` startup check (no segments yet).
- Refuses to admit any IPC frames; only the genesis ceremony's
  internal bootstrap path runs.

This mode is **automatically toggled** by `raxis genesis`. Operators
should NOT set this manually — doing so on a steady-state kernel
puts the process in a degraded state where it cannot serve requests.

### When you might see this

- During genesis: `raxis genesis` spawns a kernel subprocess with
  `RAXIS_BOOTSTRAP=1` set; you'll see the env var briefly via
  `ps eww` while the ceremony runs.
- In `raxis log --kind KernelBootstrapMode` after a manual
  override (rare; only for kernel maintainers debugging the
  genesis path).

### Set (advanced; not recommended)

```bash
# Manually boot the kernel in bootstrap mode — not for normal use.
RAXIS_BOOTSTRAP=1 raxis-kernel
```

The kernel logs `KernelBootstrapMode` and refuses to admit any
IPC. `raxis status` reports `bootstrap`.

---

## Common failure modes

| Symptom | Cause / Fix |
|---|---|
| `genesis: refusing to overwrite existing data dir` | The dir already has state. Either `rm -rf` it (preferred) or `RAXIS_FORCE=1 raxis genesis` (if you can't rm). |
| Audit chain segment count drops after `RAXIS_FORCE=1` genesis | Expected — the old segments are gone. **Verify you archived the chain before forcing.** |
| Kernel reports `BootstrapMode` indefinitely | `RAXIS_BOOTSTRAP` is set in the kernel's env. Unset it (`unset RAXIS_BOOTSTRAP`); restart. |
| CLI commands fail with `BootstrapMode: kernel not yet ready` | Same as above, plus: wait for genesis to finish. |

---

## Reference: related env vars

| Variable | Relationship |
|---|---|
| `RAXIS_DATA_DIR` | Both `RAXIS_FORCE` and `RAXIS_BOOTSTRAP` operate on the dir at this path. |
| `RAXIS_OPERATOR_KEY` / `RAXIS_OPERATOR_CERT` | Used by `raxis genesis` regardless of `RAXIS_FORCE`. |

---

## Variations

- **`RAXIS_FORCE` for testing.** A test harness that resets a
  shared dir between runs uses this rather than fighting `rm`.
- **Combine with `RAXIS_BOOTSTRAP`.** Don't. `RAXIS_BOOTSTRAP` is
  internal to genesis; setting both manually is a footgun. Trust
  `raxis genesis` to set the right flags.
- **Production.** Neither variable should ever be set on a
  production kernel host. Audit-chain integrity is the kernel's
  most important property; both of these can compromise it if
  misused.

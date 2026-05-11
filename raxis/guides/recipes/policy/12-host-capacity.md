# `[host_capacity]` — admission caps + watchdog floors

> **Topic:** Policy reference | **Time to read:** ~3 min | **Complexity:** ⭐⭐ Intermediate

The `[host_capacity]` block is the kernel's **hard backstop** against
over-subscribing the host. It enforces a strict cap on concurrent
VMs (`INV-CAPACITY-01`), a free-disk floor (`INV-CAPACITY-02`), a
boot-time FD limit floor, and an admission queue depth. Defaults are
sized for a beefy developer laptop; production hosts should tune.

The block is **always populated**: omitting it from `policy.toml`
falls through to spec defaults (also documented below).

---

## Field reference

| Field | Type | Default | Effect |
|---|---|---|---|
| `max_concurrent_vms` | `u32` | 16 | Strict admission cap on simultaneous Executor / Reviewer / Orchestrator VMs. The (N+1)th admission is rejected with `FAIL_HOST_VM_CAP_EXCEEDED`. (`INV-CAPACITY-01`) |
| `min_free_disk_mb` | `u64` | 5120 (5 GiB) | If the watchdog observes free disk below this floor on `disk_root`, the kernel halts admission with `FAIL_HOST_DISK_LOW`. (`INV-CAPACITY-02`) |
| `disk_full_behavior` | `String` | `"halt_admit"` | Always `"halt_admit"` in V2 — the kernel rejects new admissions but keeps inflight tasks running. Other values fail policy load. |
| `required_min_fd_limit` | `u32` | 4096 | Floor for the kernel process's `RLIMIT_NOFILE`. If `getrlimit(NOFILE)` reports below this at boot, the kernel exits with `BOOT_ERR_FD_LIMIT`. |
| `admission_queue_depth` | `u32` | 64 | V2 MVP cap — the kernel does not actually queue beyond this; admissions over the cap are rejected with `FAIL_ADMISSION_QUEUE_FULL`. V3 will introduce a real backpressure queue. |
| `disk_root` | `String` (optional) | `<data_dir>` | Absolute path the watchdog `statvfs`'s for the `min_free_disk_mb` check. When unset, the kernel uses its own `data_dir`. |

---

## Example — sandbox laptop

```toml
[host_capacity]
max_concurrent_vms     = 4              # 4 cores → 4 VMs
min_free_disk_mb       = 2048           # 2 GiB
disk_full_behavior     = "halt_admit"
required_min_fd_limit  = 4096
admission_queue_depth  = 32
```

## Example — production server

```toml
[host_capacity]
max_concurrent_vms     = 64
min_free_disk_mb       = 51200          # 50 GiB
disk_full_behavior     = "halt_admit"
required_min_fd_limit  = 65536
admission_queue_depth  = 256
disk_root              = "/var/lib/raxis"   # explicit
```

## Example — verifier-only host

```toml
[host_capacity]
max_concurrent_vms     = 32           # all verifier VMs, short-lived
min_free_disk_mb       = 10240
required_min_fd_limit  = 8192
admission_queue_depth  = 128
```

---

## Inspect current pressure

```bash
raxis status --json | jq '.host_capacity'
# {
#   "active_vms":            7,
#   "max_concurrent_vms":   16,
#   "free_disk_mb":      32145,
#   "min_free_disk_mb":   5120,
#   ...
# }

# Or the auto-refreshing top:
raxis top
```

`raxis top` shows live counts of admitted / running / queued tasks
plus the disk + FD-limit headroom.

---

## What happens when caps are hit

### `FAIL_HOST_VM_CAP_EXCEEDED`

Activation of an Admitted task is deferred until a slot frees.
There's no rejection at admission for this — admission accepts the
intent; the activation queue holds it.

### `FAIL_HOST_DISK_LOW`

Admission is **rejected** at the IPC frame. The intent is not
queued. The agent receives the typed error and may retry later.
The kernel emits `HostDiskLow` and `AdmissionPaused` audit events.
The check unpauses automatically once free disk recovers.

### `BOOT_ERR_FD_LIMIT`

Kernel refuses to boot. Raise the FD limit:

```bash
# Linux — temporary in current shell
ulimit -n 65536

# Linux — persistent, systemd
sudo systemctl edit raxis-kernel
#   [Service]
#   LimitNOFILE=65536

# macOS launchd — edit the plist
<key>SoftResourceLimits</key>
<dict>
  <key>NumberOfFiles</key>
  <integer>65536</integer>
</dict>
```

---

## Common failure modes

| Symptom | Fix |
|---|---|
| `BOOT_ERR_FD_LIMIT` | Raise the host FD limit (above) and restart the kernel. |
| Admissions fail with `FAIL_HOST_VM_CAP_EXCEEDED` immediately | Cap is too low for your workload. Raise carefully — over-subscription causes thrashing. |
| `FAIL_HOST_DISK_LOW` triggers when there's plenty of free disk | The watchdog points at the wrong filesystem. Set `disk_root` to the partition that actually holds `<data-dir>/worktrees`. |
| `disk_full_behavior` validation fail | Only `"halt_admit"` is supported in V2. Don't set anything else. |

---

## Reference: relevant CLI

| Command | Purpose |
|---|---|
| `raxis status` | Headline numbers including capacity. |
| `raxis top` | Live capacity dashboard. |
| `raxis log --kind HostDiskLow --since 1h` | Audit trail of disk-low events. |
| `raxis log --kind AdmissionPaused` | Times the kernel paused/unpaused admission. |

---

## Variations

- **Verifier-host policy.** Aggressively low `min_free_disk_mb`
  (verifier worktrees are short-lived) but high `max_concurrent_vms`.
- **Quota tightness.** Pin `max_concurrent_vms` to your CI runner
  pool size — anything beyond it is just queued.
- **Multi-tenant.** Run separate kernel installs (separate
  `RAXIS_DATA_DIR` values) per tenant; each gets its own
  `[host_capacity]`.

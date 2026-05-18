# Tune host capacity floors and watchdog

> **Topic:** Operations | **Time to read:** ~3 min | **Complexity:** ⭐⭐ Intermediate

The `[host_capacity]` block in `policy.toml` defines the minimum
host resources the kernel demands before admitting new work, plus
how aggressively the watchdog reclaims runaway sessions. This
recipe explains the knobs and how to size them.

---

## Concepts

| Field | Effect |
|---|---|
| `min_free_disk_bytes` | Refuse new admissions if the data-dir filesystem has less free disk than this. |
| `min_free_ram_bytes` | Refuse new admissions below this free RAM. |
| `min_free_inodes` | Refuse new admissions below this many free inodes. |
| `cpu_high_water_pct` | Watchdog target: if 1-min load avg / cpu_count > this, the kernel pauses new admissions and starts terminating idle sessions. |
| `cpu_low_water_pct` | Watchdog resume threshold (must be < high water). |
| `watchdog_grace_seconds` | How long a session can stay idle (no intent) before the watchdog terminates it under pressure. |

A healthy install runs comfortably below all the high-water marks;
the watchdog is for surge protection.

---

## Steps

### 1. Inspect current behavior

```bash
raxis policy show | grep -A 20 "\[host_capacity\]"
raxis status --json | jq '{liveness, workload, audit_chain}'
df -h "$RAXIS_DATA_DIR"
raxis log --kind HostCapacityFloorTripped --since 24h --json | wc -l
raxis log --kind WatchdogSessionTerminated --since 24h --json | wc -l
```

If you see frequent `HostCapacityFloorTripped` events, the kernel
is throttling admissions; either raise capacity or lower the
floors. If you see frequent `WatchdogSessionTerminated`, the
watchdog is reaping idle sessions under pressure.

### 2. Pick floors

Reasonable starting values for a dedicated host:

| Resource | Suggested floor |
|---|---|
| `min_free_disk_bytes` | `10 GiB` (10737418240) |
| `min_free_ram_bytes` | `1 GiB` (1073741824) |
| `min_free_inodes` | `100000` |

For a shared host, increase the disk floor to `50 GiB` to leave
room for other tenants.

### 3. Pick watchdog thresholds

| Knob | Suggested |
|---|---|
| `cpu_high_water_pct` | `85` |
| `cpu_low_water_pct` | `60` |
| `watchdog_grace_seconds` | `300` (5 min idle before reaped under pressure) |

Watchdog only fires when CPU is above `cpu_high_water_pct`. It does
not fire on healthy days.

### 4. Edit and apply

```bash
raxis policy show > /tmp/policy.toml
```

Edit `[host_capacity]`:

```toml
[host_capacity]
min_free_disk_bytes      = 10737418240
min_free_ram_bytes       = 1073741824
min_free_inodes          = 100000
cpu_high_water_pct       = 85
cpu_low_water_pct        = 60
watchdog_grace_seconds   = 300
```

Re-sign:

```bash
raxis policy sign /tmp/policy.toml --key /tmp/op.key
raxis --operator-key /tmp/op.key epoch advance \
  --policy /tmp/policy.toml \
  --sig /tmp/policy.sig
```

Check the committed epoch with `raxis policy show` and the audit
chain:

```bash
raxis log --kind PolicyEpochAdvanced --since 1m
```

### 5. Monitor

```bash
# Daily check.
raxis log --kind HostCapacityFloorTripped --since 24h --json | wc -l
raxis log --kind WatchdogSessionTerminated --since 24h --json | wc -l
raxis status --json | jq '{liveness, workload, audit_chain}'
```

If the trip count is non-zero, the host is undersized for the
workload — either upgrade hardware, lower lane caps, or relax the
floors (with the trade-off that the kernel may run with less head-
room).

---

## Common errors

| Symptom | Fix |
|---|---|
| Kernel refuses every admission with `HOST_CAPACITY_FLOOR` | Free up disk/RAM/inodes, or temporarily lower the floors. |
| `policy sign: cpu_low_water_pct >= cpu_high_water_pct` | Low water must be strictly less than high water. |
| Watchdog reaps useful sessions | Raise `watchdog_grace_seconds` (sessions get more idle time before reaping under pressure). |
| `min_free_inodes` floor trips on a healthy disk | The filesystem (e.g., ext4) has a fixed inode count; small files (worktrees) can exhaust inodes before disk space. Upgrade FS or set lower floor. |

---

## Reference

| Command | Purpose |
|---|---|
| `raxis status --json` | Kernel liveness, workload counts, and audit-chain quick check. |
| `raxis log --kind HostCapacityFloorTripped` | Recent floor trips. |
| `raxis log --kind WatchdogSessionTerminated` | Recent watchdog reaps. |
| [policy/12-host-capacity](../policy/12-host-capacity.md) | Full schema. |

---

## Variations

- **Cluster mode.** When you run multiple kernels behind a load
  balancer, set the floors per-host based on its hardware; rely on
  the load balancer to skip a kernel reporting capacity-tripped.
- **Dev box.** Lower floors aggressively (e.g., `min_free_disk_bytes
  = 1 GiB`) so a small machine can run scenarios. Pair with
  `raxis sessions --json` and a worktree audit to recover space from
  dead worktrees.
- **Multi-tenant host.** Set floors high enough that Raxis won't
  starve other tenants — typically `min_free_disk_bytes = 50 GiB`
  and tighter CPU water marks.
- **Watchdog tuning for long LLM calls.** Reviewer sessions making
  long LLM calls may go silent for minutes; ensure
  `watchdog_grace_seconds` is at least double your typical longest
  LLM call so they're not reaped.

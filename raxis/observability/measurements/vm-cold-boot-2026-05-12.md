# VM cold-boot perf report

- **backend**: `subprocess`
- **iterations**: 500
- **wall-clock**: 0.08s (6634.2 spawns/s)
- **harness**: `cargo xtask perf vm-cold-boot --backend subprocess --iterations 500`
- **timestamp**: 2026-05-12 21:10:12 UTC

| metric (ms) | p50 | p95 | p99 |
|---|---:|---:|---:|
| `raxis.isolation.spawn.cold_boot.duration`     | 0.11 | 0.17 | 0.28 |
| `raxis.isolation.spawn.host_init.duration`     | 0.00 | 0.00 | 0.00 |
| `raxis.isolation.spawn.guest_init.duration`    | 0.11 | 0.17 | 0.28 |

> Numbers are observed inside `cargo xtask perf` against the
> `subprocess` test substrate; AVF / Firecracker numbers will
> land in a follow-up patch once the AVF demo prereqs are
> staged (see `cargo xtask dev-prereqs`).

# Audit-append throughput report

- **iterations**: 1000
- **wall-clock**: 4.35s (229.7 appends/s)
- **harness**: `cargo xtask perf audit-throughput --iterations 1000`
- **timestamp**: 2026-05-12 21:09:37 UTC

| metric (us) | p50 | p95 | p99 |
|---|---:|---:|---:|
| append latency | 4067 | 6132 | 7136 |

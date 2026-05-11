# `raxis status` and `raxis doctor`

> **Topic:** CLI | **Time to read:** ~2 min | **Complexity:** ⭐ Beginner

`status` is a one-line liveness probe; `doctor` runs a full
diagnostic suite. Both are read-only and safe to schedule.

---

## status — liveness in one shot

```bash
raxis status
# Output:
# kernel:                running (pid 17234, 6h12m uptime)
# data_dir:              /var/raxis
# audit_chain:           ok (last hash 91a7c8...)
# active_initiatives:    3
# active_sessions:       7
# pending_escalations:   1
# policy_epoch:          12
```

`raxis status --json` is the machine-readable form for monitoring
(scrape it from a cron, alert on `kernel != running` or
`audit_chain != ok`).

What `status` checks:

- The kernel process is alive (heartbeat via `heartbeat.json` in
  `RAXIS_DATA_DIR`).
- The audit chain's last line hash-links correctly to the
  previous (cheap walk; full verify is `verify-chain`).
- The active counts (initiatives, sessions, escalations) by reading
  `kernel.db` read-only.

If the kernel is **down**, `status` reports
`kernel: not running` and exits non-zero — useful exit-code for
shell scripting.

---

## doctor — full suite

`doctor` is a much heavier inspection that runs every health check
the kernel knows about and reports any anomaly. Run after upgrades
or when something feels off.

```bash
raxis doctor
# Output (abbreviated):
# [ok]   data_dir exists and is writable: /var/raxis
# [ok]   operator key file present and parseable: /etc/raxis/operator.key
# [ok]   audit_chain integrity (full verify):    7321 events, prev_sha matches all
# [ok]   policy bundle valid (epoch 12):         signature ok, no expired operators
# [warn] cert ttl_remaining < 30d for ops-bob (signer 8a4f...)
# [ok]   kernel.db integrity check:              passed
# [warn] orphan worktree found: /var/raxis/worktrees/9c41... (no matching session)
# [ok]   credential proxy ports reachable:       3 of 3
# [ok]   gateway sidecar running:                yes (last heartbeat 4s ago)
#
# 8 ok, 2 warn, 0 error
```

Exit codes:

- `0` — all checks ok or only `warn`.
- `1` — at least one `error` finding.

Warnings (`warn`) flag soft drift you should address but don't
block the kernel — e.g. cert nearing expiry, orphan worktree,
audit-log file size approaching `[observability].max_audit_size_bytes`.

Errors (`error`) are blocking: corrupted audit hash chain, kernel
db inconsistency, missing operator key, etc.

---

## Useful flags

```text
raxis status   [--json]
raxis doctor   [--json] [--fix-orphans] [--full-audit-verify]
```

| Flag | Effect |
|---|---|
| `--json` | Machine-readable output. |
| `doctor --fix-orphans` | Remove orphan worktrees the diagnostic finds. Idempotent and audited. |
| `doctor --full-audit-verify` | Verify every audit-chain hash from genesis (slow on large chains). Default is incremental. |

---

## Common errors

| Symptom | Fix |
|---|---|
| `status: kernel not running` | Start it: `systemctl start raxis-kernel` or run the binary. Check `journalctl -u raxis-kernel`. |
| `status: audit chain hash mismatch` | Tampering or disk corruption. Stop the kernel, run `raxis verify-chain --full`, restore from backup if needed. |
| `doctor [error] kernel.db integrity check failed` | The SQLite file is corrupted. Stop kernel, copy `kernel.db` aside, run `sqlite3 kernel.db "PRAGMA integrity_check;"`, restore from snapshot. |
| `doctor [warn] cert ttl_remaining < 30d` | Rotate the cert: `cert mint`, `cert install`, `cert revoke <old>`. |
| `doctor [warn] orphan worktree` | `doctor --fix-orphans` to clean up. |

---

## Reference

| Command | Purpose |
|---|---|
| `raxis verify-chain` | Cheap incremental audit-chain verify. |
| `raxis verify-chain --full` | Full verification from genesis. |
| `raxis policy show` | Inspect policy state. |
| `raxis cert list` | Check cert expiry windows. |
| `raxis sessions` | Active sessions. |

---

## Variations

- **Liveness probe.** `raxis status --json | jq -e '.kernel == "running"'`
  in your monitoring loop.
- **Pre-deploy gate.** A CI deploy step that runs
  `raxis doctor` and fails the deploy on any warn or error.
- **Periodic deep verify.** Cron `raxis doctor --full-audit-verify`
  weekly; `verify-chain` is the cheap/frequent counterpart.
- **Self-heal.** `doctor --fix-orphans` cleans worktrees the
  scheduler couldn't reach (e.g., crashed mid-provision); safe to
  schedule daily.

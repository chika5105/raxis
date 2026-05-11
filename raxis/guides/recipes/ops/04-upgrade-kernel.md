# Upgrade the kernel binary

> **Topic:** Operations | **Time to read:** ~4 min | **Complexity:** ⭐⭐ Intermediate

A safe upgrade flow: backup, swap binary, restart, verify. The
audit chain and kernel database are forward-compatible across
minor versions; major versions may require a migration step.

---

## Pre-flight

```bash
# Confirm what version is running.
raxis --version
# Output: raxis 1.4.0 (...)
raxis status   # confirm it's healthy before the upgrade

# Pick the new binary you want to install.
NEW_BIN=/tmp/raxis-1.5.0
chmod +x $NEW_BIN
$NEW_BIN --version
# Output: raxis 1.5.0 (...)

# Sanity-check the new binary against the current data dir
# without starting it (read-only).
$NEW_BIN doctor --dry-run-upgrade
# Expected: "compatible with current schema vX, no migrations required"
# OR:       "migration required: schema vX -> vY (run upgrade-schema)"
```

If `doctor --dry-run-upgrade` reports a migration is required, see
the migration variation below before proceeding.

---

## Steps

### 1. Backup before upgrade

```bash
DATE=$(date -u +%Y%m%dT%H%M%SZ)
mkdir -p /tmp/pre-upgrade-$DATE
sudo cp -a "$RAXIS_DATA_DIR"/{audit.jsonl,kernel.db,policy.toml} \
     /tmp/pre-upgrade-$DATE/
```

(See [`03-backup-and-restore.md`](./03-backup-and-restore.md) for
the full backup workflow.)

### 2. Quiesce admissions

Optionally pause new admissions while the upgrade runs. There's no
single CLI for this, so the standard approach is to quarantine new
plans pre-emptively or simply rely on the upgrade window being
short:

```bash
# Drain: wait for active tasks to finish.
while [ "$(raxis queue --state runnable --json | jq length)" -gt 0 ]; do
  sleep 5
  echo "Waiting for runnable to clear..."
done
```

For true draining, an operator-friendly approach is:

```bash
# Reject new submits during the upgrade window.
raxis policy show > /tmp/policy-pre.toml
# Manually edit /tmp/policy-pre.toml to set every lane's
# max_concurrent_tasks = 0, then:
raxis policy sign /tmp/policy-pre.toml --operator-key /tmp/op.key
```

Restore the original policy after the upgrade.

### 3. Stop the kernel

```bash
sudo systemctl stop raxis-kernel
raxis status      # expects: kernel: not running
```

### 4. Swap the binary

```bash
# Standard: replace the binary on $PATH.
sudo cp $NEW_BIN /usr/local/bin/raxis
sudo cp $NEW_BIN /usr/local/bin/raxis-kernel
raxis --version
# Output: raxis 1.5.0 (...)
```

If you used `RAXIS_KERNEL_BINARY` for the install, update its
target path instead:

```bash
sudo cp $NEW_BIN $(systemctl show raxis-kernel --property=ExecStart --value | awk '{print $1}')
```

### 5. Run schema migrations (if required)

```bash
raxis-kernel upgrade-schema
# Output:
# from_schema: 8
# to_schema:   10
# migrations_applied: 0008_v2_plan_bundle_sealing, 0009_..., 0010_v2_integration_merge
# verdict: OK
```

This is a kernel subcommand, not a CLI command — runs synchronously
without starting the full daemon.

### 6. Start the kernel

```bash
sudo systemctl start raxis-kernel
raxis status
# Expected: kernel: running, audit chain: ok
raxis --version
# Expected: 1.5.0
```

### 7. Post-upgrade verification

```bash
raxis doctor                          # expect 0 errors
raxis verify-chain                    # expect verdict OK
raxis policy show | grep epoch        # epoch unchanged unless migration bumped it
raxis initiative list --state Active  # confirm initiatives are still Active
raxis sessions                        # confirm sessions are still alive
```

Sessions that were active across the upgrade should resume from
where they left off — the kernel rebuilds in-memory state from
`kernel.db` and the audit chain on startup.

### 8. Lift the admission pause (if applied)

```bash
raxis policy sign /tmp/policy-pre-upgrade-original.toml \
  --operator-key /tmp/op.key
# Or revert via your usual policy-management process.
```

---

## Rollback

If the new kernel misbehaves:

```bash
sudo systemctl stop raxis-kernel

# Restore the previous binary.
sudo cp /tmp/raxis-1.4.0 /usr/local/bin/raxis-kernel

# If a schema migration ran, restore the database from backup.
sudo cp /tmp/pre-upgrade-$DATE/kernel.db "$RAXIS_DATA_DIR/kernel.db"

sudo systemctl start raxis-kernel
raxis status
```

Rollback after a schema migration is **destructive of forward
work**: any audit lines / db state created on the new schema are
lost. Treat it as the last resort.

---

## Common errors

| Symptom | Fix |
|---|---|
| `upgrade-schema: from > to` | You're trying to "upgrade" to an older binary; that's not supported. |
| `kernel start: schema mismatch` | Run `upgrade-schema` first. |
| `doctor: kernel.db integrity check failed` | The migration may have been interrupted. Restore from backup, retry. |
| `kernel start: policy parse error` | The new binary added required policy fields. Check the new release notes; add the missing keys to `policy.toml`. |

---

## Reference

| Command | Purpose |
|---|---|
| `raxis --version` | Current binary version. |
| `raxis-kernel doctor --dry-run-upgrade` | Pre-flight compatibility check. |
| `raxis-kernel upgrade-schema` | Apply pending schema migrations. |
| `raxis verify-chain` | Post-upgrade audit-chain integrity. |
| `raxis doctor` | Post-upgrade diagnostic suite. |

---

## Variations

- **Major-version upgrade with migration.** Allow extra time;
  schema migrations on a large `kernel.db` can take minutes.
  Verify `pragma integrity_check` after.
- **Blue/green upgrade.** Stand up a second kernel on a different
  `RAXIS_DATA_DIR` running the new version; copy state from the
  primary; run smoke tests; flip systemd unit pointers; demote
  the old data dir.
- **Canary upgrade.** Upgrade one host in a multi-host setup, run
  for a day, observe `raxis doctor` and `raxis log --kind ReconciliationGap`,
  then upgrade the rest.
- **Container upgrade.** Replace the container image; the
  `RAXIS_DATA_DIR` volume persists. Run `upgrade-schema` as part
  of the container's entrypoint if needed.

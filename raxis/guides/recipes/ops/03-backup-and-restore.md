# Backup and restore the kernel data directory

> **Topic:** Operations | **Time to read:** ~4 min | **Complexity:** ⭐⭐ Intermediate

A self-contained backup/restore workflow. Captures the audit
chain, kernel database, signed policy, embedded operator certs,
and any worktrees in a state recoverable to "kernel running on a
new host with the same state". Restore is rehearsed periodically.

---

## What's in the data directory

```
$RAXIS_DATA_DIR/
├── audit.jsonl                  # tamper-evident audit chain
├── kernel.db                    # SQLite: initiatives, tasks, sessions, etc.
├── kernel.db-wal                # SQLite WAL (transient if kernel running)
├── kernel.db-shm                # SQLite shared-memory (transient)
├── policy.toml                  # signed policy
├── audit-verify-cursor.txt      # incremental verify cursor
├── heartbeat.json               # kernel liveness file
├── credentials/                 # encrypted credential blobs
├── verifier-images/             # signed verifier images
├── witnesses/                   # content-addressed witness blobs
└── worktrees/                   # per-session worktrees (large; large blast radius)
```

The **critical** files are `audit.jsonl`, `kernel.db`, `policy.toml`,
and `credentials/`. Worktrees and witnesses can be regenerated or
re-fetched.

---

## Backup procedure

### 1. Quiesce the kernel briefly

Two options:

```bash
# Option A: Stop the kernel (a few seconds of downtime).
sudo systemctl stop raxis-kernel

# Option B: Use SQLite's online backup (no downtime).
sqlite3 "$RAXIS_DATA_DIR/kernel.db" \
  ".backup '/tmp/raxis-backup/kernel.db'"
# Then copy the rest with the kernel running; audit.jsonl is
# append-only so a hot copy is consistent.
```

Option B is preferred for production; Option A is simpler for
sandbox.

### 2. Snapshot the data dir

```bash
DATE=$(date -u +%Y%m%dT%H%M%SZ)
mkdir -p /tmp/raxis-backup-$DATE
sudo cp -a "$RAXIS_DATA_DIR/audit.jsonl"  /tmp/raxis-backup-$DATE/
sudo cp -a "$RAXIS_DATA_DIR/kernel.db"    /tmp/raxis-backup-$DATE/    # if Option A
sudo cp -a "$RAXIS_DATA_DIR/policy.toml"  /tmp/raxis-backup-$DATE/
sudo cp -a "$RAXIS_DATA_DIR/credentials"  /tmp/raxis-backup-$DATE/
sudo cp -a "$RAXIS_DATA_DIR/verifier-images" /tmp/raxis-backup-$DATE/
sudo cp -a "$RAXIS_DATA_DIR/witnesses"    /tmp/raxis-backup-$DATE/
# Optional, large:
sudo cp -a "$RAXIS_DATA_DIR/worktrees"    /tmp/raxis-backup-$DATE/
```

### 3. Verify the backup

Before relying on it:

```bash
# Verify the audit chain in the backup.
RAXIS_DATA_DIR=/tmp/raxis-backup-$DATE raxis verify-chain --full
# Expected: verdict OK

# Verify the SQLite db is consistent.
sqlite3 /tmp/raxis-backup-$DATE/kernel.db "PRAGMA integrity_check;"
# Expected: ok
```

### 4. Restart the kernel (if Option A)

```bash
sudo systemctl start raxis-kernel
raxis status
# Expected: kernel running, audit chain ok
```

### 5. Archive immutably

```bash
tar czf /tmp/raxis-backup-$DATE.tar.gz -C /tmp raxis-backup-$DATE
sha256sum /tmp/raxis-backup-$DATE.tar.gz > /tmp/raxis-backup-$DATE.tar.gz.sha256

# Upload to your immutable store; e.g.:
aws s3 cp /tmp/raxis-backup-$DATE.tar.gz \
  s3://my-raxis-backups/$DATE/ \
  --object-lock-mode COMPLIANCE \
  --object-lock-retain-until-date $(date -u -d '+1 year' --iso-8601=seconds)
```

---

## Restore procedure

### 1. Stop the kernel on the target host

```bash
sudo systemctl stop raxis-kernel
sudo rm -rf "$RAXIS_DATA_DIR"
sudo mkdir -p "$RAXIS_DATA_DIR"
sudo chown -R "$(id -un):$(id -gn)" "$RAXIS_DATA_DIR"
```

### 2. Extract the backup

```bash
tar xzf /tmp/raxis-backup-$DATE.tar.gz -C /tmp
sudo cp -a /tmp/raxis-backup-$DATE/. "$RAXIS_DATA_DIR/"
sudo chown -R "$(id -un):$(id -gn)" "$RAXIS_DATA_DIR"
```

### 3. Verify before starting

```bash
RAXIS_DATA_DIR="$RAXIS_DATA_DIR" raxis verify-chain --full
sqlite3 "$RAXIS_DATA_DIR/kernel.db" "PRAGMA integrity_check;"
```

### 4. Start the kernel

```bash
sudo systemctl start raxis-kernel
raxis status
raxis doctor
```

`raxis doctor` should report `0 ok / 0 warn / 0 error` (or only
`warn` items unrelated to restoration).

### 5. Replay any in-flight work

The restore captures the kernel's last consistent state. Tasks
that were in `Active` at backup time may need a manual decision:

```bash
raxis initiative list --state Active
# For each: decide whether to abort and resubmit, or resume.
# If resume: raxis task resume <task_id> (only works for paused).
# If abort:  raxis initiative abort <id> --reason "post-restore: rerun"
```

---

## Common errors

| Symptom | Fix |
|---|---|
| `verify-chain: FAIL after restore` | Backup was corrupted in transit. Verify the sha256 against the backup file before extraction. |
| `kernel.db: malformed` | SQLite WAL was not flushed cleanly at backup. Use `.backup` (Option B) instead of raw cp on a running kernel. |
| `policy: signer cert not chain-resolvable` | The policy in the backup references a cert that's been revoked since. Restore the policy plus revocation list together. |
| Worktrees missing after restore | Worktrees are optional; sessions for those will fail and you'll need to abort + resubmit those initiatives. |

---

## Reference

| Command | Purpose |
|---|---|
| `sqlite3 ... .backup` | Online SQLite backup (no kernel downtime). |
| `raxis verify-chain --full` | Audit-chain integrity check. |
| `raxis doctor` | Diagnostic suite. |
| `raxis initiative show --bundle --to` | Per-initiative forensic export (alternative for selective restore). |

---

## Variations

- **Hourly snapshots.** Use SQLite `.backup` mode + `cp -a audit.jsonl`
  + `cp -a policy.toml`; cheap and frequent.
- **Off-host backup.** Pipe the tarball directly to S3 / `rsync`
  to a remote host without writing locally.
- **Selective restore.** Use `raxis initiative show --bundle --to`
  to extract one initiative; replay it on the target by manual
  resubmission. Useful when only one initiative needs recovery.
- **DR drill.** Quarterly: take a backup, restore to a sandbox,
  verify `raxis doctor` is clean, run a smoke-test plan.

# Continuously monitor the audit chain

> **Topic:** Operations | **Time to read:** ~3 min | **Complexity:** ⭐⭐ Intermediate

The audit chain (`audit.jsonl`) is the source of truth for every
kernel-side decision. Tampering or corruption is a security
incident. This recipe sets up periodic verification, alerting on
failure, and forensic preservation.

---

## Overview

Three layers of monitoring:

1. **Cheap, frequent** — `raxis status` checks the last line's
   hash chain. Run every minute.
2. **Incremental, hourly** — `raxis verify-chain` advances the
   verify cursor from where it last left off.
3. **Deep, daily** — `raxis verify-chain --full` re-verifies the
   chain from genesis. Pair with `raxis doctor` to also check
   kernel.db integrity.

Plus: long-term archival to immutable storage for compliance.

---

## Steps

### 1. Add a frequent liveness check

A 1-minute cron:

```bash
* * * * * /usr/local/bin/raxis-monitor-status.sh
```

Where `raxis-monitor-status.sh`:

```bash
#!/usr/bin/env bash
set -euo pipefail
export RAXIS_DATA_DIR=/var/raxis

if ! raxis status --json | jq -e '.kernel == "running" and .audit_chain == "ok"' > /dev/null; then
  raxis status > /tmp/raxis-status.last
  /usr/local/bin/page-oncall "raxis status not OK"
  exit 1
fi
```

What this catches: kernel down, last-hash mismatch (cheap check
only, not a full verify).

### 2. Hourly incremental verify

```bash
0 * * * * /usr/local/bin/raxis-monitor-verify.sh
```

Where `raxis-monitor-verify.sh`:

```bash
#!/usr/bin/env bash
set -euo pipefail
export RAXIS_DATA_DIR=/var/raxis

OUT=$(raxis verify-chain --json 2>&1) || true
if echo "$OUT" | jq -e '.verdict == "OK"' > /dev/null; then
  echo "$(date -u): verify-chain OK ($(echo "$OUT" | jq -r '.verified'))"
  exit 0
fi

echo "$OUT" > /tmp/raxis-verify-chain.fail
/usr/local/bin/page-oncall "raxis verify-chain FAIL"
exit 1
```

What this catches: any tampering or partial-write that broke a
hash link.

### 3. Daily full verify + doctor

```bash
30 3 * * * /usr/local/bin/raxis-monitor-deep.sh
```

```bash
#!/usr/bin/env bash
set -euo pipefail
export RAXIS_DATA_DIR=/var/raxis

raxis verify-chain --full --json > /tmp/raxis-verify-deep.json
raxis doctor --full-audit-verify --json > /tmp/raxis-doctor.json

if ! jq -e '.verdict == "OK"' < /tmp/raxis-verify-deep.json > /dev/null; then
  /usr/local/bin/page-oncall "raxis deep verify FAIL"
  exit 1
fi

ERR=$(jq '[.findings[] | select(.severity == "error")] | length' < /tmp/raxis-doctor.json)
if [ "$ERR" -gt 0 ]; then
  /usr/local/bin/page-oncall "raxis doctor reported $ERR errors"
  exit 1
fi
```

What this catches: invariant drift, schema issues, cert expiry
windows, orphan worktrees.

### 4. Stream audit events to your SIEM

```bash
# Tail the file (works because audit.jsonl is append-only newline-
# delimited JSON).
tail -F /var/raxis/audit.jsonl | <your-shipper>

# Or use raxis log --follow --json:
raxis log --follow --json | <your-shipper>
```

Set up alerts on `kind`:

| Kind | Alert |
|---|---|
| `SecurityViolation` | Pager. |
| `ReconciliationGap` | Pager (kernel detected its own invariant drift). |
| `EmergencyCertMinted` | Pager + audit (break-glass cert was used). |
| `OperatorRevoked` (especially genesis) | Pager. |
| `EscalationRaised` (rate > N/hour) | Page (lineage may be looping). |
| `CredentialRotated` | Email/Slack (informational, but track). |
| `PolicyReloaded` (epoch jump > 1) | Email/Slack. |

### 5. Archive immutably

The audit chain grows unboundedly. Periodically archive past
windows:

```bash
# Snapshot up to a watermark.
NOW=$(date -u +%Y%m%dT%H%M%SZ)
WM=/var/raxis/audit-watermark.txt
LAST=$(cat $WM 2>/dev/null || echo 0)
HEAD=$(wc -l < /var/raxis/audit.jsonl)

awk -v lo="$((LAST+1))" -v hi="$HEAD" 'NR>=lo && NR<=hi' /var/raxis/audit.jsonl > /tmp/audit-$NOW.jsonl
sha256sum /tmp/audit-$NOW.jsonl > /tmp/audit-$NOW.jsonl.sha256

aws s3 cp /tmp/audit-$NOW.jsonl    s3://my-raxis-audit-archive/$NOW/ \
  --object-lock-mode COMPLIANCE \
  --object-lock-retain-until-date $(date -u -d '+7 years' --iso-8601=seconds)
aws s3 cp /tmp/audit-$NOW.jsonl.sha256 s3://my-raxis-audit-archive/$NOW/

echo "$HEAD" > $WM
```

The audit file itself is not pruned in-place — the kernel rotates
audit.jsonl when it exceeds `[observability].max_audit_size_bytes`,
producing `audit.jsonl.<seq>`. The above script captures windows
within the live file; you can also archive the rotated files
directly.

---

## Common errors

| Symptom | Fix |
|---|---|
| `verify-chain: cursor file mismatch` | The cursor file `audit-verify-cursor.txt` is out of sync (file was truncated). Re-run with `--full` to reset. |
| `verify-chain --full` slow | Expected on multi-million-line chains. Pair with periodic archival to keep the live file shorter. |
| `tail -F` misses events under rotation | Use `tail -F` (capital `F` follows file rotation), or use `raxis log --follow --json`. |
| Cron prints `kernel not running` daily | The cron job ran during a kernel restart; add a retry loop. |

---

## Reference

| Command | Purpose |
|---|---|
| `raxis status` | Cheap last-line check. |
| `raxis verify-chain` | Incremental verify. |
| `raxis verify-chain --full` | Full verify from genesis. |
| `raxis log --follow --json` | Stream audit events. |
| `raxis doctor --full-audit-verify` | Deep verify + other checks. |

---

## Variations

- **Streaming verify.** Instead of cron, run a long-lived process
  that watches `audit.jsonl` for appends and verifies each new
  line as it lands; alert on first failure.
- **Two-host replication.** Mirror `audit.jsonl` to a second host
  via `rsync -a --append`; verify on both. Splits the trust boundary.
- **Compliance attestation.** Daily `verify-chain --full` outputs
  signed by an operator (`raxis auth sign`); archived as
  attestations.
- **Incident replay.** When investigating, pull the relevant
  archive window, run `raxis verify-chain --from <line> --to <line>`
  to confirm the slice is intact, then replay events into a
  forensic tool.

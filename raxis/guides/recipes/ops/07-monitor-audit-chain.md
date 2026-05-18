# Continuously monitor the audit chain

> **Topic:** Operations | **Time to read:** ~3 min | **Complexity:** ⭐⭐ Intermediate

The audit chain (`<data-dir>/audit/segment-NNN.jsonl`) is the source
of truth for every kernel-side decision. Tampering or corruption is a
security incident. This recipe sets up periodic verification,
alerting on failure, and forensic preservation.

---

## Overview

Three layers of monitoring:

1. **Cheap, frequent** — `raxis status` checks the last line's
   hash chain. Run every minute.
2. **Full, hourly** — `raxis verify-chain` walks every audit segment
   and exits 3 on a chain break.
3. **Deep, daily** — `raxis doctor` checks kernel.db, cert, policy,
   filesystem, and image state. Pair it with `raxis verify-chain`.

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

if ! raxis status --json | jq -e '.liveness == "Running" and .audit_chain.status == "Ok"' > /dev/null; then
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

OUT=$(raxis verify-chain 2>&1)
RC=$?
if [ "$RC" -eq 0 ]; then
  echo "$(date -u): verify-chain OK"
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

raxis verify-chain > /tmp/raxis-verify-deep.txt
raxis doctor --json > /tmp/raxis-doctor.json

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
# Prefer the ChainReader-backed CLI; it follows audit segments and
# keeps filter semantics aligned with the dashboard.
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
| `PolicyEpochAdvanced` (epoch jump > 1) | Email/Slack. |

### 5. Archive immutably

The audit chain is segmented. Periodically verify it and then archive
the segment directory immutably:

```bash
NOW=$(date -u +%Y%m%dT%H%M%SZ)
ARCHIVE=/tmp/raxis-audit-$NOW.tar.gz

raxis verify-chain
tar czf "$ARCHIVE" -C /var/raxis audit
sha256sum "$ARCHIVE" > "$ARCHIVE.sha256"

aws s3 cp "$ARCHIVE" s3://my-raxis-audit-archive/$NOW/ \
  --object-lock-mode COMPLIANCE \
  --object-lock-retain-until-date $(date -u -d '+7 years' --iso-8601=seconds)
aws s3 cp "$ARCHIVE.sha256" s3://my-raxis-audit-archive/$NOW/
```

Do not prune segment files in place while the kernel is using the
data dir. Treat archived segments as forensic copies, not as a live
retention mechanism.

---

## Common errors

| Symptom | Fix |
|---|---|
| `unknown verify-chain flag: "--full"` | Current `raxis verify-chain` is a full walk by default. Use `--quick` only for the cheap first/last check. |
| `verify-chain` slow | Expected on multi-million-line chains. Pair with periodic archival and keep `--quick` for frequent health checks only. |
| `tail -F` misses events under rotation | Use `raxis log --follow --json`; it reads through `ChainReader`. |
| Cron prints `kernel not running` daily | The cron job ran during a kernel restart; add a retry loop. |

---

## Reference

| Command | Purpose |
|---|---|
| `raxis status` | Cheap last-line check. |
| `raxis verify-chain` | Full segment walk. |
| `raxis verify-chain --quick` | First/last-record check, same class as `raxis status`. |
| `raxis log --follow --json` | Stream audit events. |
| `raxis doctor` | Deep health checks beyond the audit chain. |

---

## Variations

- **Streaming verify.** Instead of cron, run a long-lived process
  that watches `audit/segment-NNN.jsonl` for appends and verifies each new
  line as it lands; alert on first failure.
- **Two-host replication.** Mirror `audit/` to a second host
  via `rsync -a --append`; verify on both. Splits the trust boundary.
- **Compliance attestation.** Daily `raxis verify-chain` outputs
  signed by an operator (`raxis auth sign`); archived as
  attestations.
- **Incident replay.** When investigating, pull the relevant archive,
  run `raxis verify-chain --audit-dir <archive>/audit --from <seq>`
  to confirm the chain is intact, then replay events into a forensic
  tool.

# `raxis log` and `raxis verify-chain`

> **Topic:** CLI | **Time to read:** ~3 min | **Complexity:** ⭐⭐ Intermediate

The audit chain is a tamper-evident, hash-linked JSONL log
(`audit.jsonl`) under `RAXIS_DATA_DIR`. `log` is the readable
viewer; `verify-chain` confirms every line's `prev_sha256`
matches the previous line's raw bytes.

---

## Syntax

```text
raxis log [<initiative_id>]
          [--since <timestamp>]
          [--kind <AuditEventKind>]
          [--limit N]
          [--json] [--follow]

raxis verify-chain [--full] [--from <line_no>] [--to <line_no>]
```

---

## log — readable audit stream

Without filters, `log` prints the entire chain (most recent last):

```bash
raxis log --limit 20
# AT                     KIND                  INITIATIVE   TASK            ACTOR
# 2026-05-10T17:30:00Z   InitiativeAdmitted    1f3c8a4b     —               operator:alice
# 2026-05-10T17:30:01Z   SessionMinted         1f3c8a4b     implementer     kernel
# 2026-05-10T17:30:02Z   TaskStarted           1f3c8a4b     implementer     session:91a7c8
# 2026-05-10T17:31:14Z   WitnessRecorded       1f3c8a4b     implementer     verifier:cargo-test
# ...
```

Filter to one initiative (the most useful default):

```bash
raxis log 1f3c8a4b
```

By kind (any `AuditEventKind` variant):

```bash
raxis log --kind WitnessRecorded
raxis log --kind SecurityViolation        # inspect every fail-closed event
raxis log --kind ReconciliationGap        # invariant-drift events
raxis log --kind EscalationRaised
```

Tail live:

```bash
raxis log 1f3c8a4b --follow
# blocks; prints new events as they're appended
```

JSON form:

```bash
raxis log 1f3c8a4b --json | jq '.[] | {ts, kind, payload}'
```

---

## verify-chain — tamper detection

Every audit line's `prev_sha256` is the sha256 of the previous
line's raw bytes. `verify-chain` walks the file and confirms:

```bash
raxis verify-chain
# Output:
# from: line 1
# to:   line 7321 (HEAD)
# verified: 7321 lines
# verdict:  OK
```

`--full` re-verifies from line 1 (default is incremental — start
where the last successful run ended, tracked in
`audit-verify-cursor.txt`). Use `--full` after suspected
tampering or to bootstrap fresh:

```bash
raxis verify-chain --full
# verified: 7321 lines
# verdict:  OK
```

Range form:

```bash
raxis verify-chain --from 100 --to 200
```

If a line's `prev_sha256` doesn't match the previous line:

```bash
# verdict: FAIL
# first failure at line 4521:
#   computed prev_sha256: ab12cd34...
#   recorded prev_sha256: 99999999...
#   diff: events between 4520 and 4521 may have been altered or removed
```

A failed `verify-chain` is a **security incident**. Stop the
kernel and treat the audit file as forensic evidence; restore from
a known-good snapshot.

---

## What's in each line

```json
{
  "seq": 7321,
  "ts": "2026-05-10T17:31:14.123Z",
  "kind": "WitnessRecorded",
  "initiative_id": "1f3c8a4b...",
  "task_id": "implementer-2025-05-10",
  "actor": "verifier:cargo-test",
  "payload": { "witness_sha": "7f880c2e...", "verifier": "cargo-test" },
  "prev_sha256": "9c41..."
}
```

The line's own raw bytes (UTF-8, including the trailing newline)
are what get hashed into the next line's `prev_sha256`.

---

## Useful kind filters

| Kind | When useful |
|---|---|
| `InitiativeAdmitted` | Audit which plans entered the system. |
| `SessionMinted` / `SessionRevoked` | Session lifecycle. |
| `WitnessRecorded` | Verifier outputs (mechanical evidence). |
| `EscalationRaised` / `EscalationResolved` | Human-in-loop decisions. |
| `SecurityViolation` | Any deny-by-default fire (egress denied, path-allowlist breach, etc.). |
| `ReconciliationGap` | The kernel detected an invariant drift; investigate. |
| `CredentialUsed` | Per-credential proxy traffic. |
| `OperatorAdded` / `OperatorRevoked` / `EmergencyCertMinted` | Operator-cert lifecycle. |
| `PolicyReloaded` | Policy epoch change. |
| `DelegationStateChanged` | Delegation lifecycle. |

---

## Common errors

| Symptom | Fix |
|---|---|
| `log: audit file not found` | Wrong `RAXIS_DATA_DIR`? `raxis status` to check. |
| `log: kind unknown` | The kind name doesn't match any `AuditEventKind`. Check the audit-chain doc for the supported list. |
| `verify-chain: FAIL` | Tampering or disk corruption. Stop kernel; treat as incident. |
| `verify-chain: cursor file mismatch` | The incremental cursor is ahead of the actual file (file truncated). Run with `--full`. |

---

## Reference

| Command | Purpose |
|---|---|
| `raxis status` | Cheap last-line hash check. |
| `raxis doctor --full-audit-verify` | Wraps `verify-chain --full` plus other checks. |
| `raxis explain <task_id>` | Pulls the relevant audit lines for one task. |
| `raxis witnesses show <sha>` | Pulls a witness blob referenced by an audit event. |

---

## Variations

- **Streaming SIEM.** `raxis log --follow --json` piped to your
  log shipper of choice. Each line is self-contained JSON.
- **Compliance export.** `raxis log --json --since 2026-01-01 > audit-q1.jsonl`,
  archive immutably (S3 Object Lock, etc.).
- **Forensic investigation.** Combine `raxis log --kind SecurityViolation`
  with `raxis log --kind ReconciliationGap` to scope an incident,
  then `verify-chain --from <line> --to <line>` to confirm the
  evidence range hasn't been tampered.
- **Hourly verify.** Cron `raxis verify-chain` with `--json` output;
  alert on any non-`OK` verdict.

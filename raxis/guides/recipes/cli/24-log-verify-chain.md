# `raxis log` and `raxis verify-chain`

> **Topic:** CLI | **Time to read:** ~3 min | **Complexity:** ⭐⭐ Intermediate

The audit chain is a tamper-evident, hash-linked set of JSONL
segments under `<data-dir>/audit/segment-NNN.jsonl`. `log` is the
readable viewer; `verify-chain` walks the same segments and confirms
every line's `prev_sha256` matches the previous line's raw bytes.

---

## Syntax

```text
raxis log [<initiative_id>]
          [--task <task_id>]
          [--session <session_id>]
          [--since <duration>]
          [--kind <substring>]
          [--limit N]
          [--json] [-f|--follow]

raxis verify-chain [--quick] [--from <seq>] [--audit-dir <path>]
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

By kind (case-insensitive substring match on `event_kind`):

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
raxis log 1f3c8a4b --json | jq -c '{seq, event_kind, payload}'
```

---

## verify-chain — tamper detection

Every audit line's `prev_sha256` is the sha256 of the previous
line's raw bytes. `verify-chain` walks every segment in numeric
order and confirms:

```bash
raxis verify-chain
# Output:
# Audit chain verification complete:
#   Audit dir:     /var/lib/raxis/audit
#   Segments:      1
#   Total records: 7321
#   Last seq:      7320
# Chain integrity: OK
```

`--quick` runs the same first/last-record check used by
`raxis status`. It is useful for cheap health checks, but production
integrity jobs should run the full command without `--quick`:

```bash
raxis verify-chain --quick
# Audit chain: OK (quick) — segments=1, last_seq=7320
```

Slice reporting:

```bash
raxis verify-chain --from 100
```

`--from` narrows the reported stats to records with `seq >= 100`.
The command still walks the whole chain end-to-end, so corruption
before the slice still fails the verdict.

If a line's `prev_sha256` doesn't match the previous line:

```bash
# AUDIT CHAIN COMPROMISED
#   Audit dir: /var/lib/raxis/audit
#   Error:     chain break in audit/segment-000.jsonl at seq=4521: ...
#   Segment:   audit/segment-000.jsonl
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
| `PolicyEpochAdvanced` | Policy epoch change. |
| `DelegationStateChanged` | Delegation lifecycle. |

---

## Common errors

| Symptom | Fix |
|---|---|
| `log: audit file not found` | Wrong `RAXIS_DATA_DIR` or no segment files yet. Run `raxis status` and inspect `<data-dir>/audit/`. |
| `log: kind unknown` | `--kind` is a substring filter. Check [the audit-chain concept doc](../../../raxis-concepts/06-audit-chain.md) for common event families. |
| `verify-chain: FAIL` | Tampering or disk corruption. Stop kernel; treat as incident. |
| `unknown verify-chain flag: "--full"` | Current verification is full by default; use `--quick` only for the cheap health check. |

---

## Reference

| Command | Purpose |
|---|---|
| `raxis status` | Cheap last-line hash check. |
| `raxis doctor` | Health checks beyond the audit chain. |
| `raxis explain <task_id>` | Pulls the relevant audit lines for one task. |
| `raxis witnesses <task_id> [--gate <name>]` | Lists witness records indexed for a task. |

---

## Variations

- **Streaming SIEM.** `raxis log --follow --json` piped to your
  log shipper of choice. Each line is self-contained JSON.
- **Compliance export.** `raxis log --json --since 90d > audit-window.jsonl`,
  archive immutably (S3 Object Lock, etc.).
- **Forensic investigation.** Combine `raxis log --kind SecurityViolation`
  with `raxis log --kind ReconciliationGap` to scope an incident,
  then `raxis verify-chain --from <seq>` to confirm the chain has not
  been tampered.
- **Hourly verify.** Cron `raxis verify-chain`; page on exit code 3.

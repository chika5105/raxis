# Scenario 41 — Audit Chain Replay

> **Complexity:** ⭐⭐⭐ Advanced | **Wall clock:** ~6 min | **Provider:** none (read-only)

Take any completed initiative and prove that every kernel decision
(admission, intent acceptance, gate evaluation, merge, abort) is
fully reconstructible from the hash-chained audit log plus the
operator's public keys. This is the canonical "trust nothing"
walk: at the end you have a script that re-derives the chain from
genesis, verifies every per-segment HMAC, and reports the count of
each event kind seen.

## When to use this

- You're convincing a security-conscious stakeholder that the audit
  story holds — no exotic infrastructure, just a CLI command.
- You're rehearsing an external-auditor procedure.
- You're investigating an incident and want to know exactly what
  the kernel decided, when, and on what evidence.
- You're verifying that a backup of `<data_dir>/audit/` is still
  cryptographically intact.

---

## Prerequisites

- **One-time setup complete.** See [`../../SETUP.md`](../../SETUP.md).
- **At least one completed initiative.** Any of
  [scenarios 01–40](../) will do. The walk works on aborted /
  failed initiatives too — they just produce different event
  histograms.
- **`RAXIS_DATA_DIR` exported** in this shell.

The kernel does **not** need to be running for this scenario —
`raxis verify-chain` and `raxis log` both read directly from
`<data_dir>/audit/`.

---

## What this scenario demonstrates

- The audit chain is **append-only** and **content-addressed**:
  every record carries the hash of the record before it, and
  segment boundaries seal with an HMAC keyed on the kernel's
  authority key.
- Any single-byte tamper (a flipped bit anywhere in any segment,
  an inserted record, a deleted record) is detected by
  `verify-chain` with the exact offset.
- `raxis log <initiative_id>` is a **complete** projection — every
  decision the kernel made for that initiative is in there. No
  log lives outside this surface; no telemetry pipe needs to be
  trusted.

---

## Files in this scenario

| File | Purpose |
|---|---|
| `policy.toml` | Empty delta (read-only walk). |
| `credential.toml` | Empty template. |

(There is no `plan.toml` — this scenario reads pre-existing audit
state.)

---

## Run it

```bash
# 1. Pick a completed initiative.
COMPLETED_INIT="$(raxis initiative list --state Completed --json \
  | jq -r '.[0].initiative_id')"
echo "Walking initiative $COMPLETED_INIT"

# 2. Replay the per-initiative projection — human-readable.
raxis log "$COMPLETED_INIT" | head -40

# 3. Histogram the events. A healthy single-Executor / single-
#    Reviewer initiative produces ~10 distinct event kinds.
raxis log "$COMPLETED_INIT" --json \
  | jq -r '.[] | .kind' \
  | sort | uniq -c | sort -rn

# 4. Walk the whole chain (every initiative, every segment) and
#    verify it.
raxis verify-chain
# expected: "chain ok — N records across M segments"

# 5. (Optional) Walk the chain offline. Copy <data_dir>/audit/
#    and <data_dir>/keys/*.pub to another machine and re-run
#    `raxis verify-chain --data-dir <copy>` there.
```

---

## What "success" looks like

The full success picture is six concrete checks:

```bash
# 1. verify-chain exits 0 and reports non-zero records.
raxis verify-chain
# chain ok — 142 records across 1 segment

# 2. Genesis event present.
raxis log --kind AuditChainGenesis --limit 1

# 3. The initiative's lifecycle is there in order.
raxis log "$COMPLETED_INIT" --json \
  | jq '[.[] | .kind] | .[0:5]'
# ["InitiativeCreated", "PlanBundleSealed", "PlanApproved",
#  "TaskAdmitted", "SessionCreated"]

# 4. Each TaskCompleted has a corresponding IntegrationMergeCompleted
#    (or InitiativeAborted / InitiativeFailed).
raxis log "$COMPLETED_INIT" --kind TaskCompleted --json | jq length
raxis log "$COMPLETED_INIT" --kind IntegrationMergeCompleted \
  --json | jq length

# 5. Tamper detection: flip a byte and re-run (DESTRUCTIVE — do this
#    on a copy of the audit dir, never on production).
cp -R "$RAXIS_DATA_DIR/audit" /tmp/audit-tamper-test/
# corrupt a single byte at offset 200 of segment-000.jsonl
printf 'X' | dd of=/tmp/audit-tamper-test/segment-000.jsonl bs=1 \
  count=1 seek=200 conv=notrunc
raxis verify-chain --data-dir /tmp/audit-tamper-test
# expected: FAIL_AUDIT_CHAIN_BROKEN at offset 200 of segment-000.jsonl
rm -rf /tmp/audit-tamper-test/

# 6. Reset — verify-chain on the real data dir still passes.
raxis verify-chain
```

---

## Variations

- **Walk a failed initiative.** Pick an initiative with state
  `Failed`. The event histogram will include `TaskFailed`,
  `IntentRejected`, and (if applicable) `BudgetExceeded` rows.
- **Offline witness audit.** Copy only `<data_dir>/audit/` and
  `<data_dir>/keys/*.pub` to an air-gapped machine. Run
  `raxis verify-chain --data-dir <copy>` there. The
  pub-key-only verification path makes no kernel-private-key
  assumption — anyone holding the kernel's public keys can audit.
- **Partial replay.** Filter by `--kind <Event>` to walk only
  high-value events (e.g. `PolicyAdvanceCompleted`,
  `BreakglassAction`, `OperatorActivated`) across a year of
  history.

---

## Tear-down

Nothing to tear down — this is a read-only walk.

---

## Cross-references

- Concepts: [`../../CONCEPTS.md#audit-chain`](../../CONCEPTS.md#audit-chain).
- Spec: `specs/v1/kernel-core.md §audit.rs`; `specs/v1/audit-chain.md`
  for the cryptographic shape (segment HMAC, record format,
  rotation rules).
- Recipe: [`../../recipes/cli/22-verify-chain.md`](../../recipes/cli/22-verify-chain.md),
  [`../../recipes/cli/14-log.md`](../../recipes/cli/14-log.md).
- Security model: [`../../security/raxis-security-model.md`](../../security/raxis-security-model.md)
  and [`../../security/compromised-agent-threat-model.md`](../../security/compromised-agent-threat-model.md)
  — the audit chain is the substrate both rely on.
- Related scenarios:
  - [`42-operator-rotation`](../42-operator-rotation/) — the
    public-key surface this scenario relies on for offline replay.
  - [`44-session-revocation`](../44-session-revocation/) — produces
    `SessionRevoked` rows that are visible in this walk.

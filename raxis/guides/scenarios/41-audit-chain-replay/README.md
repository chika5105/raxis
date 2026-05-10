# Scenario 41 — Audit Chain Replay

> **Complexity:** ⭐⭐ Intermediate | **Wall clock:** ~5 min | **Provider:** Anthropic

After running scenario 04, replay its audit chain and verify the
hash-chain integrity from genesis.

---

## Prerequisites

A completed initiative (any of scenarios 01–40 will do).

---

## What this scenario demonstrates

- `raxis verify-chain` walks the chain.
- Detection of any tampering would manifest as
  `FAIL_AUDIT_CHAIN_BROKEN`.

---

## Run it

```bash
raxis log "$INIT_ID"           # human-readable audit replay for one initiative
raxis verify-chain             # full chain integrity walk (every segment)
```

---

## What "success" looks like

`raxis verify-chain` exits 0 and prints `chain ok`.

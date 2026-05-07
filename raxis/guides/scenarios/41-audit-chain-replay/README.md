# Scenario 41 — Audit Chain Replay

> **Complexity:** ⭐⭐ Intermediate | **Wall clock:** ~5 min | **Provider:** Anthropic

After running scenario 04, replay its audit chain and verify the
hash-chain integrity from genesis.

---

## Prerequisites

A completed initiative (any of scenarios 01–40 will do).

---

## What this scenario demonstrates

- `raxis audit verify` walks the chain.
- Detection of any tampering would manifest as
  `FAIL_AUDIT_CHAIN_BROKEN`.

---

## Run it

```bash
raxis audit list --initiative-id "$INIT_ID"
raxis audit verify --initiative-id "$INIT_ID"
```

---

## What "success" looks like

`raxis audit verify` exits 0 and prints `chain ok`.

# Scenario 11 — Generate Docs From Source

> **Complexity:** ⭐⭐ Intermediate | **Wall clock:** ~8 min | **Provider:** Anthropic

A read-only Executor reads `src/` and writes a curated docs page,
without ever modifying source files. Demonstrates the composability
of `path_allowlist` for read vs write protection.

---

## Prerequisites

Same as scenario 04.

---

## What this scenario demonstrates

- Single-Executor task that reads source but only writes to `docs/`.
- The kernel rejects any commit touching files outside the allowlist.

---

## Repository setup

```bash
export DEMO_ROOT="/tmp/raxis-scenario-11"
rm -rf "$DEMO_ROOT" && mkdir -p "$DEMO_ROOT"
cd "$DEMO_ROOT"

cargo init --lib --name demo11 -q
cat > src/lib.rs <<'RS'
//! Tiny math util.
pub fn add(a: i64, b: i64) -> i64 { a + b }
pub fn mul(a: i64, b: i64) -> i64 { a * b }
RS
mkdir -p docs
git -c user.email=demo@raxis.local -c user.name=Demo add . > /dev/null
git -c user.email=demo@raxis.local -c user.name=Demo commit -qm "init"
```

---

## Run it

```bash
raxis plan validate ./plan.toml
raxis submit plan ./plan.toml --no-dry-run
INIT_ID="$(raxis initiative list --state Draft --json | jq -r '.[0].initiative_id')"
raxis plan approve "$INIT_ID"
```

---

## Tear-down

```bash
raxis initiative abort "$INIT_ID" 2>/dev/null || true
rm -rf "$DEMO_ROOT"
```

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
export RAXIS_MAIN_REPO="$RAXIS_DATA_DIR/repositories/main"
rm -rf "$RAXIS_MAIN_REPO" && mkdir -p "$RAXIS_MAIN_REPO"
cd "$RAXIS_MAIN_REPO"

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

Copy this scenario's plan into the canonical repo so the run commands below can execute from the seeded repo:

```bash
cp /path/to/raxis/guides/scenarios/11-generate-docs-from-source/plan.toml "$RAXIS_MAIN_REPO/plan.toml"
```

---

## Run it

```bash
raxis plan validate ./plan.toml
INIT_ID="$(raxis submit plan ./plan.toml --no-dry-run | awk '/^Initiative / {print $2} /^initiative_id:/ {print $2}')"
raxis plan approve "$INIT_ID"
```

---

## Tear-down

```bash
raxis initiative abort "$INIT_ID" 2>/dev/null || true
rm -rf "$RAXIS_MAIN_REPO"
```

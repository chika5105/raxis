# Scenario 24 — Circular Revision Detection

> **Complexity:** ⭐⭐ Intermediate | **Wall clock:** ~10 min | **Provider:** Anthropic

The kernel detects when an Executor "ping-pongs" between identical
fixes round over round and aborts with `FAIL_REVISION_LOOP_DETECTED`.

---

## Prerequisites

Same as scenario 04.

---

## What this scenario demonstrates

- The kernel's tree-hash-based loop detector.
- The `FAIL_REVISION_LOOP_DETECTED` audit kind.

---

## Repository setup

```bash
export DEMO_ROOT="/tmp/raxis-scenario-24"
rm -rf "$DEMO_ROOT" && mkdir -p "$DEMO_ROOT/src"
cd "$DEMO_ROOT"

git init -q
echo "fn main() { let x = 1; }" > src/main.rs
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

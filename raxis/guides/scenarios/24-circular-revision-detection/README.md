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
export RAXIS_MAIN_REPO="$RAXIS_DATA_DIR/repositories/main"
rm -rf "$RAXIS_MAIN_REPO" && mkdir -p "$RAXIS_MAIN_REPO/src"
cd "$RAXIS_MAIN_REPO"

git init -q
echo "fn main() { let x = 1; }" > src/main.rs
git -c user.email=demo@raxis.local -c user.name=Demo add . > /dev/null
git -c user.email=demo@raxis.local -c user.name=Demo commit -qm "init"
```

Copy this scenario's plan into the canonical repo so the run commands below can execute from the seeded repo:

```bash
cp /path/to/raxis/guides/scenarios/24-circular-revision-detection/plan.toml "$RAXIS_MAIN_REPO/plan.toml"
```

---

## Run it

```bash
raxis plan validate ./plan.toml
INIT_ID="$(raxis submit plan ./plan.toml --no-dry-run | awk '/^Initiative / {print $2} /^initiative_id:/ {print $2}')"
raxis plan approve "$INIT_ID"
```

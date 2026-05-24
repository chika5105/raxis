# Scenario 25 — Wall-Clock Limit

> **Complexity:** ⭐⭐ Intermediate | **Wall clock:** ~5 min | **Provider:** Anthropic

A task with a tight wall-clock ceiling is killed and audited as
`WARN_WALL_CLOCK_EXCEEDED`. Demonstrates how the kernel's deadline
enforcement preserves end-to-end progress (other tasks continue).

---

## Prerequisites

Same as scenario 04.

---

## What this scenario demonstrates

- Per-task `wall_clock_seconds` field in `[[tasks]]`.
- Audit emission and graceful task termination.

---

## Repository setup

```bash
export RAXIS_MAIN_REPO="$RAXIS_DATA_DIR/repositories/main"
rm -rf "$RAXIS_MAIN_REPO" && mkdir -p "$RAXIS_MAIN_REPO/src"
cd "$RAXIS_MAIN_REPO"

git init -q
echo "fn main() {}" > src/main.rs
git -c user.email=demo@raxis.local -c user.name=Demo add . > /dev/null
git -c user.email=demo@raxis.local -c user.name=Demo commit -qm "init"
```

Copy this scenario's plan into the canonical repo so the run commands below can execute from the seeded repo:

```bash
cp /path/to/raxis/guides/scenarios/25-wall-clock-limit/plan.toml "$RAXIS_MAIN_REPO/plan.toml"
```

---

## Run it

```bash
raxis plan validate ./plan.toml
INIT_ID="$(raxis submit plan ./plan.toml --no-dry-run | awk '/^Initiative / {print $2} /^initiative_id:/ {print $2}')"
raxis plan approve "$INIT_ID"
```

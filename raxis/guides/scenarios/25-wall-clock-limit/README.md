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
export DEMO_ROOT="/tmp/raxis-scenario-25"
rm -rf "$DEMO_ROOT" && mkdir -p "$DEMO_ROOT/src"
cd "$DEMO_ROOT"

git init -q
echo "fn main() {}" > src/main.rs
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

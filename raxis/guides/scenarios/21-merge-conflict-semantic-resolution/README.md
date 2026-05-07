# Scenario 21 — Semantic Merge Conflict Resolution

> **Complexity:** ⭐⭐⭐ Advanced | **Wall clock:** ~12 min | **Provider:** Anthropic

Two parallel Executors edit non-overlapping symbols in the *same*
file. Demonstrates how the Orchestrator's IntegrationMerge resolves
non-textual conflicts.

---

## Prerequisites

Same as scenario 04.

---

## What this scenario demonstrates

- Two Executors with overlapping `path_allowlist` (`src/lib.rs`).
- The kernel admits both because their content edits are in disjoint
  regions; the Orchestrator merges them.
- A `cargo build` mechanical witness on each task.

---

## Repository setup

```bash
export DEMO_ROOT="/tmp/raxis-scenario-21"
rm -rf "$DEMO_ROOT" && mkdir -p "$DEMO_ROOT"
cd "$DEMO_ROOT"

cargo init --lib --name demo21 -q
cat > src/lib.rs <<'RS'
pub fn add(a: i64, b: i64) -> i64 { a + b }
pub fn mul(a: i64, b: i64) -> i64 { a * b }
RS
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

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
export RAXIS_MAIN_REPO="$RAXIS_DATA_DIR/repositories/main"
rm -rf "$RAXIS_MAIN_REPO" && mkdir -p "$RAXIS_MAIN_REPO"
cd "$RAXIS_MAIN_REPO"

cargo init --lib --name demo21 -q
cat > src/lib.rs <<'RS'
pub fn add(a: i64, b: i64) -> i64 { a + b }
pub fn mul(a: i64, b: i64) -> i64 { a * b }
RS
git -c user.email=demo@raxis.local -c user.name=Demo add . > /dev/null
git -c user.email=demo@raxis.local -c user.name=Demo commit -qm "init"
```

Copy this scenario's plan into the canonical repo so the run commands below can execute from the seeded repo:

```bash
cp /path/to/raxis/guides/scenarios/21-merge-conflict-semantic-resolution/plan.toml "$RAXIS_MAIN_REPO/plan.toml"
```

---

## Run it

```bash
raxis plan validate ./plan.toml
INIT_ID="$(raxis submit plan ./plan.toml --no-dry-run | awk '/^Initiative / {print $2} /^initiative_id:/ {print $2}')"
raxis plan approve "$INIT_ID"
```

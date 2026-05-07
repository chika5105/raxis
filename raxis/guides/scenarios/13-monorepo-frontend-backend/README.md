# Scenario 13 — Monorepo Frontend + Backend

> **Complexity:** ⭐⭐⭐ Advanced | **Wall clock:** ~15 min | **Provider:** Anthropic

Two parallel Executors operate on disjoint subtrees in a monorepo.
After this scenario you understand how `path_allowlist` scopes
parallel work cleanly without locking.

---

## Prerequisites

Same as scenario 04.

---

## What this scenario demonstrates

- A monorepo with `frontend/` and `backend/` directories.
- Two parallel Executors with disjoint allowlists, no shared lock.
- The Orchestrator's IntegrationMerge stitches the two together.

---

## Repository setup

```bash
export DEMO_ROOT="/tmp/raxis-scenario-13"
rm -rf "$DEMO_ROOT" && mkdir -p "$DEMO_ROOT/frontend/src" "$DEMO_ROOT/backend/src"
cd "$DEMO_ROOT"

git init -q
echo "console.log('hello');" > frontend/src/index.js
echo "fn main() {}" > backend/src/main.rs
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

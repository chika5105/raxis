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
export RAXIS_MAIN_REPO="$RAXIS_DATA_DIR/repositories/main"
rm -rf "$RAXIS_MAIN_REPO" && mkdir -p "$RAXIS_MAIN_REPO/frontend/src" "$RAXIS_MAIN_REPO/backend/src"
cd "$RAXIS_MAIN_REPO"

git init -q
echo "console.log('hello');" > frontend/src/index.js
echo "fn main() {}" > backend/src/main.rs
git -c user.email=demo@raxis.local -c user.name=Demo add . > /dev/null
git -c user.email=demo@raxis.local -c user.name=Demo commit -qm "init"
```

Copy this scenario's plan into the canonical repo so the run commands below can execute from the seeded repo:

```bash
cp /path/to/raxis/guides/scenarios/13-monorepo-frontend-backend/plan.toml "$RAXIS_MAIN_REPO/plan.toml"
```

---

## Run it

```bash
raxis plan validate ./plan.toml
INIT_ID="$(raxis submit plan ./plan.toml --no-dry-run | awk '/^Initiative / {print $2} /^initiative_id:/ {print $2}')"
raxis plan approve "$INIT_ID"
```

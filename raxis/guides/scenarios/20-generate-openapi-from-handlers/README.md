# Scenario 20 — Generate OpenAPI from Handlers

> **Complexity:** ⭐⭐⭐ Advanced | **Wall clock:** ~12 min | **Provider:** Anthropic

A read-only Executor reads HTTP handler signatures and emits a
matching `openapi.yaml`. Demonstrates a "documentation as code"
workflow without touching source.

---

## Prerequisites

Same as scenario 04.

---

## What this scenario demonstrates

- A docs-only mutation with read access to source code.
- An audit-friendly Reviewer pass that compares the generated YAML
  against the same handlers (deterministic, no LLM judgement).

---

## Repository setup

```bash
export RAXIS_MAIN_REPO="$RAXIS_DATA_DIR/repositories/main"
rm -rf "$RAXIS_MAIN_REPO" && mkdir -p "$RAXIS_MAIN_REPO/src" "$RAXIS_MAIN_REPO/docs"
cd "$RAXIS_MAIN_REPO"

git init -q
cat > src/handlers.py <<'PY'
def get_users(): return []  # GET /users
def create_user(payload): pass  # POST /users
def get_user(user_id: int): return {}  # GET /users/{id}
PY
git -c user.email=demo@raxis.local -c user.name=Demo add . > /dev/null
git -c user.email=demo@raxis.local -c user.name=Demo commit -qm "init"
```

Copy this scenario's plan into the canonical repo so the run commands below can execute from the seeded repo:

```bash
cp /path/to/raxis/guides/scenarios/20-generate-openapi-from-handlers/plan.toml "$RAXIS_MAIN_REPO/plan.toml"
```

---

## Run it

```bash
raxis plan validate ./plan.toml
INIT_ID="$(raxis submit plan ./plan.toml --no-dry-run | awk '/^Initiative / {print $2} /^initiative_id:/ {print $2}')"
raxis plan approve "$INIT_ID"
```

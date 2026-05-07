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
export DEMO_ROOT="/tmp/raxis-scenario-20"
rm -rf "$DEMO_ROOT" && mkdir -p "$DEMO_ROOT/src" "$DEMO_ROOT/docs"
cd "$DEMO_ROOT"

git init -q
cat > src/handlers.py <<'PY'
def get_users(): return []  # GET /users
def create_user(payload): pass  # POST /users
def get_user(user_id: int): return {}  # GET /users/{id}
PY
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

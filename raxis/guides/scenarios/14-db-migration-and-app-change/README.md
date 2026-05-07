# Scenario 14 — DB Migration + Application Change

> **Complexity:** ⭐⭐⭐ Advanced | **Wall clock:** ~15 min | **Provider:** Anthropic

A migration writer adds a new column, then an app-code editor
references the new column. Demonstrates how the kernel orders
strict-predecessor tasks against shared schema changes.

---

## Prerequisites

Same as scenario 04. PostgreSQL is *not* required for this scenario;
the migration is just a `.sql` file we don't apply here.

---

## What this scenario demonstrates

- Strict serial ordering via `predecessors`.
- The reviewer-gate model where evaluation_sha drives the chain.

---

## Repository setup

```bash
export DEMO_ROOT="/tmp/raxis-scenario-14"
rm -rf "$DEMO_ROOT" && mkdir -p "$DEMO_ROOT/migrations" "$DEMO_ROOT/src"
cd "$DEMO_ROOT"

git init -q
cat > migrations/001_init.sql <<'SQL'
CREATE TABLE users (id INT PRIMARY KEY, email TEXT NOT NULL);
SQL
cat > src/users.py <<'PY'
def get_email(user): return user["email"]
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

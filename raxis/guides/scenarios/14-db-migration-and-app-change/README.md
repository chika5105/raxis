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
export RAXIS_MAIN_REPO="$RAXIS_DATA_DIR/repositories/main"
rm -rf "$RAXIS_MAIN_REPO" && mkdir -p "$RAXIS_MAIN_REPO/migrations" "$RAXIS_MAIN_REPO/src"
cd "$RAXIS_MAIN_REPO"

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

Copy this scenario's plan into the canonical repo so the run commands below can execute from the seeded repo:

```bash
cp /path/to/raxis/guides/scenarios/14-db-migration-and-app-change/plan.toml "$RAXIS_MAIN_REPO/plan.toml"
```

---

## Run it

```bash
raxis plan validate ./plan.toml
INIT_ID="$(raxis submit plan ./plan.toml --no-dry-run | awk '/^Initiative / {print $2} /^initiative_id:/ {print $2}')"
raxis plan approve "$INIT_ID"
```

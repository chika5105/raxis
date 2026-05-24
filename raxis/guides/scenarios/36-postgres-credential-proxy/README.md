# Scenario 36 — Postgres Credential Proxy

> **Complexity:** ⭐⭐⭐⭐ Expert | **Wall clock:** ~20 min | **Provider:** Anthropic

The Executor connects to a PostgreSQL server through the credential
proxy without ever seeing the actual password. Demonstrates the full
credential proxy pipeline: declaration → wire-protocol → audit.

> **Note (V2 status):** The Postgres proxy is implemented as a
> handshake-tier MVP. The agent sees a real Postgres
> handshake reach `ReadyForQuery`, simple-query `SELECT`
> statements return `CommandComplete`, and `INSERT` /
> `UPDATE` / `DELETE` are blocked with sqlstate `42501`
> when `allow_only_select = true`. Real upstream forwarding
> (so the agent can actually round-trip rows from a live
> `postgres:16` instance) is the V3 patch; until it lands,
> the proxy synthesises `CommandComplete` for every allowed
> statement so the wire path is observable end-to-end.

---

## Prerequisites

Same as scenario 04. A running PostgreSQL on the host (port 5432
exposed). For local dev:

```bash
docker run --rm -d --name pg-demo -e POSTGRES_PASSWORD=secret \
  -p 5432:5432 postgres:16
```

You also need to seed the credential file. From the host:

```bash
install -d -m 700 "$RAXIS_DATA_DIR/credentials"
cat > "$RAXIS_DATA_DIR/credentials/db_main.env" <<'EOF'
postgresql://postgres:secret@host.docker.internal:5432/postgres
EOF
chmod 600 "$RAXIS_DATA_DIR/credentials/db_main.env"
```

---

## What this scenario demonstrates

- `[[tasks.credentials]]` declaration.
- Audit emission `AUDIT_CREDENTIAL_RESOLVED`.
- The proxy enforcing connection-string-only access.

Copy this scenario's plan into the canonical repo so the run commands below can execute from the seeded repo:

```bash
cp /path/to/raxis/guides/scenarios/36-postgres-credential-proxy/plan.toml "$RAXIS_MAIN_REPO/plan.toml"
```

---

## Run it

```bash
export RAXIS_MAIN_REPO="$RAXIS_DATA_DIR/repositories/main"
rm -rf "$RAXIS_MAIN_REPO" && mkdir -p "$RAXIS_MAIN_REPO/src"
cd "$RAXIS_MAIN_REPO"

git init -q
echo "fn main() {}" > src/main.rs
git -c user.email=demo@raxis.local -c user.name=Demo add . > /dev/null
git -c user.email=demo@raxis.local -c user.name=Demo commit -qm "init"

raxis plan validate ./plan.toml
INIT_ID="$(raxis submit plan ./plan.toml --no-dry-run | awk '/^Initiative / {print $2} /^initiative_id:/ {print $2}')"
raxis plan approve "$INIT_ID"
```

# Scenario 36 — Postgres Credential Proxy

> **Complexity:** ⭐⭐⭐⭐ Expert | **Wall clock:** ~20 min | **Provider:** Anthropic

The Executor connects to a PostgreSQL server through the credential
proxy without ever seeing the actual password. Demonstrates the full
credential proxy pipeline: declaration → wire-protocol → audit.

> **Note (current state):** The Postgres proxy wire-protocol is in
> progress. Until it lands, plans declaring
> `kind = "postgres"` credentials are admitted but the proxy
> rejects connections with `FAIL_PROXY_NOT_IMPLEMENTED`. The
> declaration surface is complete.

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
mkdir -p ~/.raxis/credentials
cat > ~/.raxis/credentials/db_main.env <<'EOF'
postgresql://postgres:secret@host.docker.internal:5432/postgres
EOF
chmod 600 ~/.raxis/credentials/db_main.env
```

---

## What this scenario demonstrates

- `[[tasks.credentials]]` declaration.
- Audit emission `AUDIT_CREDENTIAL_RESOLVED`.
- The proxy enforcing connection-string-only access.

---

## Run it

```bash
export DEMO_ROOT="/tmp/raxis-scenario-36"
rm -rf "$DEMO_ROOT" && mkdir -p "$DEMO_ROOT/src"
cd "$DEMO_ROOT"

git init -q
echo "fn main() {}" > src/main.rs
git -c user.email=demo@raxis.local -c user.name=Demo add . > /dev/null
git -c user.email=demo@raxis.local -c user.name=Demo commit -qm "init"

raxis plan validate ./plan.toml
raxis submit plan ./plan.toml --no-dry-run
INIT_ID="$(raxis initiative list --state Draft --json | jq -r '.[0].initiative_id')"
raxis plan approve "$INIT_ID"
```

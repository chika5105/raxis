# `[[tasks.credentials]]` — per-task credential declarations

> **Topic:** Plan reference | **Time to read:** ~3 min | **Complexity:** ⭐⭐⭐ Advanced

`[[tasks.credentials]]` declares the credential proxies a task
needs at runtime. Each declaration tells the kernel to spawn a
localhost TCP listener inside the task's VM, intercept the agent's
requests, log them, apply restrictions, and inject the credential
without the agent ever holding the secret bytes.

The block is **optional**; tasks that don't need credentials omit it
entirely.

---

## Field reference

Each `[[tasks.credentials]]` block declares one proxy.

| Field | Type | Required | Effect |
|---|---|---|---|
| `name` | `String` | yes | The credential identifier — must match a name registered via `raxis credential add <name>`. |
| `kind` | `String` | yes | One of `"http"`, `"postgres"`, `"mysql"`, `"mssql"`, `"mongodb"`. Determines the proxy protocol. |
| `bind_port` | `u16` | optional | The localhost port to bind. Defaults to a kernel-allocated free port; the agent reads it via `RAXIS_CREDENTIAL_<NAME>_PORT` env. |
| `restriction` | `String` | optional, kind-specific | Per-kind restriction rules. See examples below. |
| `description` | `String` | optional | Free-text; surfaces in `raxis log --kind CredentialProxyStarted`. |

---

## Example — Postgres credential proxy

```toml
[[tasks]]
task_id            = "db_migrator"
session_agent_type = "Executor"
clone_strategy     = "blobless"
path_allowlist     = ["migrations/"]
allowed_egress     = ["localhost"]    # the proxy upstreams from inside the VM

[[tasks.credentials]]
name        = "prod-postgres"
kind        = "postgres"
restriction = """
allowed_databases = ["app_main"]
allowed_schemas   = ["public", "migrations"]
read_only         = false
max_query_seconds = 30
"""
description = "Apply pending migrations against prod-postgres."
```

The kernel:

1. Reads the credential bytes from
   `<data-dir>/credentials/prod-postgres.env` (mode 0600).
2. Boots a credential proxy bound to `127.0.0.1:<bind_port>` inside
   the VM. The proxy parses Postgres wire frames.
3. Stamps `RAXIS_CREDENTIAL_PROD_POSTGRES_PORT` (and family) into
   the agent's env block.
4. The agent runs `psql -h 127.0.0.1 -p $RAXIS_CREDENTIAL_PROD_POSTGRES_PORT
   -U app -d app_main` — the proxy sees the connection, replaces
   the auth bytes with the real credential, and connects upstream.
5. Per-statement restrictions (`allowed_schemas`, etc.) gate the
   query at the proxy.

The agent never reads `prod-postgres.env`; the bytes never enter the
VM's address space.

## Example — HTTP credential proxy (Stripe)

```toml
[[tasks.credentials]]
name        = "stripe-restricted"
kind        = "http"
restriction = """
allowed_methods = ["GET", "POST"]
allowed_paths   = ["/v1/charges", "/v1/customers"]
allowed_hosts   = ["api.stripe.com"]
"""
```

The proxy intercepts HTTP traffic to `api.stripe.com`, injects the
`Authorization: Bearer <key>` header, and rejects requests outside
the allowlist with `407 Proxy Authentication Required`.

## Example — MySQL with read-only

```toml
[[tasks.credentials]]
name        = "analytics-mysql"
kind        = "mysql"
restriction = """
allowed_databases = ["analytics"]
read_only         = true
"""
```

The proxy parses MySQL packets and rejects any non-SELECT statement
with `1142 access denied`.

---

## How the kernel lifecycle looks

```text
admission:
  └─ For each [[tasks.credentials]]:
       ├── Verify <name> is registered (raxis credential add ran).
       ├── Verify <kind> matches the credential file's declared kind.
       ├── Validate the restriction body (per-kind parser).
       └── Reserve a bind_port on the VM (kernel-allocated unless explicit).

session_spawn:
  └─ Boot the proxy listeners on the reserved ports.
  └─ Stamp env vars into the agent's process:
       RAXIS_CREDENTIAL_<NAME>_PORT = <bind_port>
       RAXIS_CREDENTIAL_<NAME>_HOST = "127.0.0.1"
       RAXIS_CREDENTIAL_<NAME>_USER = "<proxy-user>"   # for SQL kinds
  └─ Agent connects to localhost:port; proxy upstreams.

audit:
  └─ Every proxy intercept produces a CredentialProxyRequest event.
  └─ Every restriction violation is CredentialProxyDenied.
  └─ Session teardown emits CredentialProxyClosed with traffic stats.
```

---

## Per-kind restrictions

### `postgres` / `mysql` / `mssql`

| Field | Effect |
|---|---|
| `allowed_databases` | List of database names. Connections to other databases rejected. |
| `allowed_schemas` (postgres only) | Schemas the proxy permits. Statements touching others rejected. |
| `read_only` | If `true`, only read-style statements are permitted. |
| `max_query_seconds` | Per-query time cap; the proxy disconnects the session if exceeded. |
| `denied_keywords` | Optional list of substring matches; statements containing these are rejected. |

### `mongodb`

| Field | Effect |
|---|---|
| `allowed_databases` | List of MongoDB databases. |
| `read_only` | If `true`, only `find` / `aggregate` / `count` are allowed. |
| `allowed_collections` | List of `<db>.<col>` references. |

### `http`

| Field | Effect |
|---|---|
| `allowed_methods` | Allowed HTTP methods. |
| `allowed_paths` | Allowed URL path prefixes. |
| `allowed_hosts` | Allowed upstream hostnames. |
| `header_injections` | Map of headers to inject (e.g., `{"Authorization": "Bearer ${secret}"}`). The kernel substitutes `${secret}` at proxy time. |

---

## Common failure modes

| Symptom | Fix |
|---|---|
| `FAIL_CREDENTIAL_NOT_REGISTERED` at admission | The `name` doesn't have a matching `raxis credential add` ceremony. Run it; re-submit the plan. |
| `FAIL_CREDENTIAL_KIND_MISMATCH` | The credential file's declared `kind` differs from the plan's. Inspect with `raxis credential show <name>`. |
| Agent can connect but queries fail with `407` / `1142` / `EACCES` | Restriction in effect; the agent is doing something the policy doesn't allow. Check `raxis log --kind CredentialProxyDenied --since 5m`. |
| Proxy never starts (env var unset inside VM) | `[[tasks.credentials]]` block is malformed; the kernel skipped it. Check `raxis log --kind CredentialProxyStartFailed`. |
| `ECONNREFUSED` at the agent | Proxy crashed mid-task. Check `<data-dir>/runtime/credential-proxy-<name>.log`. |

---

## Reference: relevant CLI + env

| Surface | Purpose |
|---|---|
| `raxis credential add <name> --type <kind> [--env <label>]` | Register a credential before referencing it from a plan. |
| `raxis credential show <name>` | Inspect metadata (size, mode, kind) — never the bytes. |
| `raxis credential audit <name>` | Audit history of every change. |
| `RAXIS_CREDENTIAL_<NAME>_PORT` (env, per agent) | Localhost port the proxy is bound to. |
| `RAXIS_CREDENTIAL_<NAME>_HOST` (env, per agent) | Always `"127.0.0.1"`. |
| `RAXIS_CREDENTIAL_<NAME>_USER` (env, per agent) | Stand-in username for SQL kinds. |

---

## Variations

- **Multiple credentials per task.** List multiple
  `[[tasks.credentials]]` blocks; each gets its own port and env
  triple. Common shape for full-stack tasks (Postgres + Stripe +
  internal HTTP).
- **Read-only Reviewer.** Reviewers can't actually use credential
  proxies (no egress); declaring them on a Reviewer task is a
  no-op. Some operators omit them deliberately as documentation.
- **No restriction.** Omit the `restriction` field; the proxy still
  injects credentials but applies no policy beyond the kind's
  defaults. Don't do this in production — restrictions are
  defence-in-depth.

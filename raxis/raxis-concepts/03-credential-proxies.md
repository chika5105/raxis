# RAXIS Credential Proxies — End-to-End Explained

> **Audience.** Operators wiring `[[tasks.credentials]]` blocks in
> `plan.toml`, contributors building or modifying a `credential-proxy-*`
> crate, and reviewers auditing why an agent's request to a backend
> service was allowed or blocked.
>
> **Authority.** Wire shapes, restriction names, and crate paths
> below are pinned to the current source tree. Where this doc
> disagrees with the code, the code wins. The canonical specs are
> `specs/v2/credential-proxy.md` (architecture) and
> `specs/v2/proxy-table-allowlists.md` (the SQL allowlist semantics
> for `postgres` / `mysql` / `mssql`).

---

## What is a credential proxy?

A credential proxy is a **localhost TCP listener** that the kernel runs on behalf of an agent. The agent connects to `localhost:PORT` and talks a normal protocol (Postgres wire protocol, HTTP, SMTP, Redis, etc.). The proxy intercepts every request, logs it to the audit chain, applies restrictions, and forwards it to the real upstream service with the real credentials injected.

**The agent never sees the actual credentials.** It only sees `localhost:PORT`.

**Paradigm anchor.** Credential proxies are the reference
implementation's enforcement of **R-2 — Mediated I/O**. An agent
without a proxy has no path to the upstream system; with a proxy,
every request traverses an authority-controlled chokepoint that
audits, restricts, and reauthenticates.

---

## Step 1: Operator Declares Credentials in plan.toml

```toml
[[tasks.credentials]]
credential_name = "prod_db"
proxy_type = "postgres"
mount_as = "DATABASE_URL"

[tasks.credentials.restrictions]
allowed_operations = ["SELECT"]
allowed_tables = ["users", "orders"]
max_rows_per_query = 1000
```

**In plain English:** "The agent can query `users` and `orders` with SELECT only. No INSERT, UPDATE, DELETE. Max 1000 rows per query."

---

## Step 2: Operator Stores the Actual Credential

The operator stores the real Postgres connection string (with password) in the credential backend using the CLI:

```bash
raxis credential add prod_db \
  --type postgres \
  --value "postgresql://real_user:S3cret@prod-db.internal:5432/mydb"
```

The credential is stored encrypted at rest by the `CredentialBackend` (see `crates/raxis-credentials/`). The kernel resolves it at session start (lazily, only when a session that references it is admitted).

CLI surface (verified against `cli/src/main.rs:319-333` and `cli/src/commands/credential.rs`):

| Subcommand | Purpose |
|---|---|
| `raxis credential add`    | Insert / overwrite an entry in the encrypted backend |
| `raxis credential rotate` | Replace the stored value, bumping the credential version |
| `raxis credential list`   | Enumerate names + types (no secret material) |
| `raxis credential show`   | Reveal a value (operator-only, audited) |
| `raxis credential remove` | Delete a credential entry |
| `raxis credential verify` | Connect once and validate the upstream is reachable |
| `raxis credential audit`  | Replay the audit chain rows for a credential name |

There is **no** `raxis credential set` subcommand; earlier drafts of
this guide used it. Use `add` for a new entry and `rotate` to update
an existing one.

---

## Step 3: Kernel Spawns the Proxy at Session Start

When the kernel creates a session for a task, `CredentialProxyManager::start_for_session` runs:

1. Resolves the credential from the backend
2. Binds a TCP listener on `127.0.0.1:0` (OS-assigned port)
3. Starts the protocol-specific proxy task (Postgres, HTTP, SMTP, Redis, etc.)
4. Emits a `CredentialProxyStarted` audit event
5. Returns the bound port number

The kernel then injects the port into the agent's environment:
```bash
DATABASE_URL=postgresql://localhost:54321/mydb
```

The `mount_as` field from the plan determines the env var name.

---

## Step 4: Agent Uses the Proxy Transparently

The agent's code does:
```python
import psycopg2
conn = psycopg2.connect(os.environ["DATABASE_URL"])
cursor = conn.execute("SELECT * FROM users WHERE id = 42")
```

The agent thinks it's talking to a normal Postgres database.

---

## Step 5: Proxy Intercepts, Audits, Restricts

For every query the agent sends:

1. **Parse** the SQL statement (extract operation type: SELECT, INSERT, UPDATE, DELETE)
2. **Check restrictions:**
   - Is the operation in `allowed_operations`? → If not, **block** (return error to agent)
   - Is the table in `allowed_tables`? → If not, **block**
   - Did the result set exceed `max_rows_per_query`? → If so, **truncate**
3. **Audit:** Write a `DatabaseQueryExecuted` event to the audit chain:
   ```json
   {
     "event": "DatabaseQueryExecuted",
     "session_id": "sess-abc",
     "credential_name": "prod_db",
     "operation": "SELECT",
     "sql_sha256": "e3b0c44298...",
     "blocked": false
   }
   ```
4. **Forward** the query to the real upstream with the real credentials injected
5. **Return** the response to the agent

---

## Supported Proxy Types

| Proxy Type | Protocol | Key Restrictions |
|---|---|---|
| `postgres` | PostgreSQL wire protocol | `allow_only_select`, `allowed_tables`, `forbidden_tables`, `max_result_rows`, `enforce` |
| `mysql`    | MySQL wire protocol      | `allow_only_select`, `allowed_tables`, `forbidden_tables`, `max_result_rows`, `enforce` |
| `mssql`    | TDS (SQL Server)         | `allow_only_select`, `allowed_tables`, `forbidden_tables`, `max_result_rows` (audit-only, no streaming cap yet), `enforce` |
| `mongodb`  | MongoDB wire protocol    | `allow_read_only`, `allowed_collections`, `forbidden_collections`, `max_documents`, `enforce` |
| `redis` | RESP (Redis) | `allowed_commands`, `blocked_commands` |
| `http` | HTTP/1.1 reverse proxy | `allowed_methods`, `allowed_paths`, path globs |
| `k8s` | HTTP (rides the http proxy) | bearer auth, `allowed_verbs`, `allowed_resources` |
| `smtp` | SMTP | `allowed_recipients`, `max_recipients`, `max_message_size` |
| `aws` | AWS IMDS-compatible | `allowed_services`, `allowed_regions`, role ARN |
| `gcp` | GCP metadata-compatible | `allowed_scopes`, project ID |
| `azure` | Azure IMDS-compatible | `allowed_scopes`, subscription restrictions |

---

## The Full Flow (Visual)

```mermaid
flowchart TD
    Agent["Agent (in microVM)"]
    
    Proxy["<b>Credential Proxy (Postgres)</b><br/>1. Parse SQL → SELECT<br/>2. Check: SELECT ∈ allowed?<br/>&nbsp;&nbsp;&nbsp;✅ allowed<br/>3. Check: users ∈ allowed?<br/>&nbsp;&nbsp;&nbsp;✅ allowed<br/>4. Audit → audit chain<br/>5. Inject real credentials<br/>6. Forward to prod-db:5432"]
    
    RealDb["Real Postgres (prod-db.internal:5432)"]

    Agent -- "\"SELECT * FROM users\"<br/>→ localhost:54321" --> Proxy
    Proxy --> RealDb
    RealDb -- "response flows back through proxy" --> Agent
```

---

## Edge Cases

### 1. Agent tries to INSERT (but only SELECT is allowed)

Proxy parses the statement, sees `INSERT`, checks against `allowed_operations = ["SELECT"]` → **blocked**. Agent receives an error message. A `DatabaseQueryExecuted` event with `blocked: true` is written to the audit chain. The query never reaches the upstream database.

### 2. Agent sends a SQL injection attack

The proxy parses statements, not string-matches. Even so, the agent can only hit allowed tables with allowed operations. A SQL injection in the query text doesn't help because:
- The operation must be in the allowlist
- The table must be in the allowlist
- The upstream connection uses separate credentials the agent never sees

### 3. Two credentials have the same `mount_as`

```toml
[[tasks.credentials]]
credential_name = "prod_db"
mount_as = "DATABASE_URL"

[[tasks.credentials]]
credential_name = "staging_db"
mount_as = "DATABASE_URL"   # COLLISION
```

**Result:** `CredentialProxyManager` detects the collision at session start and returns `ManagerError::DuplicateMountAs`. The session fails to start. This is a plan configuration error.

### 4. Credential backend is unreachable

Credential resolution fails → proxy bind fails → `ManagerError::PostgresBind` (or appropriate variant) → session fails to start. Fail-closed: no proxy = no credential access.

### 5. Agent tries to connect to a port not assigned to it

The agent only knows `localhost:PORT`. Other ports are either:
- Not bound (connection refused)
- Bound to other sessions (but the microVM network namespace isolates them)

The isolation backend (microVM or container) ensures each agent only sees its own loopback interfaces.

### 6. Proxy process crashes

The proxy runs as a tokio task under the kernel. If it panics, the kernel detects the abort, emits `CredentialProxyStopped` with the crash reason, and the agent gets connection-refused on next attempt. No credential is leaked.

---

## Gap Found: Audit Failure Handling

> [!WARNING]
> **Per-request audit emissions use `tracing::warn!` on failure, not hard abort.**
>
> The audit adapters (`PostgresKernelAuditAdapter`, `HttpKernelAuditAdapter`, etc.)
> log a warning if a per-query/per-request audit emission fails, but continue
> processing the query. This means a wedged audit pipe does not block the agent's
> database queries.
>
> The spec says (kernel-store.md §2.5.2) that audit failure should be fatal.
> However, the lifecycle events (`CredentialProxyStarted`/`Stopped`) DO fail
> closed via `ManagerError::Audit`. The per-request path is intentionally softer
> to avoid tearing down a session mid-query due to a transient audit pipe hiccup.
>
> **Decision:** This is an acceptable deviation. The lifecycle events are the
> hard boundary; per-request audit is best-effort. If strict per-request audit
> is needed, the adapter should queue events and fail the session only if the
> queue exceeds a depth limit.

---

## Key Source Files

| File | Role |
|------|------|
| `crates/credential-proxy-manager/src/lib.rs` | Kernel-side lifecycle: start, stop, audit adapters |
| `crates/credential-proxy-postgres/` | Postgres wire protocol proxy |
| `crates/credential-proxy-http/` | HTTP reverse proxy |
| `crates/credential-proxy-smtp/` | SMTP relay proxy |
| `crates/credential-proxy-redis/` | Redis RESP proxy |
| `crates/credential-proxy-aws/` | AWS IMDS credential provider |
| `crates/credential-proxy-gcp/` | GCP metadata credential provider |
| `crates/credential-proxy-azure/` | Azure IMDS credential provider |
| `crates/credential-proxy-mysql/` | MySQL proxy |
| `crates/credential-proxy-mssql/` | MSSQL/TDS proxy |
| `crates/credential-proxy-mongodb/` | MongoDB wire proxy |
| `crates/plan-credentials/` | `TaskCredentialDecl` — parsed credential declarations |
| `crates/raxis-credentials/` | `CredentialBackend` trait — encrypted storage at rest |
| `cli/src/commands/credential.rs` | `raxis credential …` operator surface |
| `specs/v2/credential-proxy.md` | Architecture spec (authoritative) |
| `specs/v2/proxy-table-allowlists.md` | SQL `allowed_tables` semantics + result caps |

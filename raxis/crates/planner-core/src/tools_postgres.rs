//! `postgres_query` — structured Postgres tool for the executor.
//!
//! Closes the executor tool-registry gap pinned by
//! `INV-EXEC-TOOL-REGISTRY-01`: every credential-proxied service the
//! kernel binds a listener for MUST be reachable via a structured
//! tool from inside the executor VM. The proxy on the host
//! (`raxis-credential-proxy-postgres`) terminates the agent's
//! `postgres://` connection on the loopback `127.0.0.1:<port>`
//! listener and performs the real upstream auth + mTLS; the in-VM
//! client only speaks plaintext Postgres wire to the proxy.
//!
//! ## Wire contract
//!
//! * URL: `DATABASE_URL` env (or alternative `mount_as` if the
//!   operator declared one — the tool reads the env literally; the
//!   kernel session-spawn path is the source of truth for the
//!   `mount_as → URL` mapping).
//! * Driver: `tokio_postgres::connect(&url, NoTls)`. Plaintext on
//!   loopback because the proxy handles upstream TLS.
//! * Params: positional, bound via the Postgres extended protocol.
//!   Argument values are `serde_json::Value`s; the tool maps each
//!   to the canonical Postgres type (`bool` / `int8` / `float8` /
//!   `text` / NULL). Objects, arrays, and out-of-range numerics are
//!   rejected at parse time with `QuerySyntax`.
//! * Result: `{ "rows": [...], "row_count": N, "command_tag": "..." }`
//!   for queries that return rows; `{ "rows_affected": N,
//!   "command_tag": "..." }` for non-SELECT statements.
//! * Cap: `RAXIS_TOOL_POSTGRES_MAX_ROWS` (default 1000). When the
//!   upstream returns more rows than the cap, the result body is
//!   truncated AND `truncated: true` is set in the response so the
//!   LLM can detect cap-hit without re-running.
//! * Error shape: structured `{ "error_class": "...", "message": "..." }`
//!   with `error_class ∈ {ProxyUnreachable, AuthFailed, QuerySyntax,
//!   QueryRuntime, ResultTooLarge, Timeout, MissingEnv}`.
//!
//! ## Audit
//!
//! On every invocation the tool emits one `ToolAuditEvent` carrying
//! `tool="postgres_query"`, `sha256(query)`, `duration_ms`, and the
//! outcome shape. Parameter values are NEVER recorded — only the
//! query text's hash. The host-side proxy emits the canonical
//! `AuditEventKind::DatabaseQueryExecuted` (with the same `sql_sha256`)
//! when the wire frame reaches it; the two events pair on inspection
//! per `credential-proxy.md §14.5.1`.
//!
//! ## Invariants upheld
//!
//! * **INV-CRED-PROXY-VM-REACHABILITY-01** — the tool dials the
//!   loopback URL from the env literally; it never accepts a host /
//!   port argument, never reads `~/.pgpass` or `PGHOST` /
//!   `PGUSER` / `PGPASSWORD` (the proxy IS the only ingress).
//! * **INV-SECRET-02** — no credential bytes ever touch the planner
//!   (the proxy substitutes real credentials on the wire to the
//!   upstream).

use std::env;
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::Serialize;
use tokio_postgres::types::{ToSql, Type};
use tokio_postgres::{Error as PgError, NoTls, Row};

use crate::tool_audit::{
    sha256_hex, ToolAuditEvent, ToolAuditSink, ToolErrorClass,
};
use crate::tools::{Tool, ToolContext, ToolError, ToolOutput};

/// Env var the kernel session-spawn path stamps with the loopback
/// `postgresql://raxis@127.0.0.1:<port>/` URL from the credential-
/// proxy manager. Standard PostgreSQL convention; matches
/// `credential-proxy.md §2` and the `loopback_env()` injection in
/// `raxis-credential-proxy-manager`.
pub const DATABASE_URL_ENV: &str = "DATABASE_URL";

/// Cap-override env var. Operators MAY raise this for large
/// read-only analytics tasks; the default 1000 matches the row-cap
/// pinned in `credential-proxy.md §14.5.1` so a single tool call
/// never blows the per-turn token budget.
pub const POSTGRES_MAX_ROWS_ENV: &str = "RAXIS_TOOL_POSTGRES_MAX_ROWS";

/// Default per-tool row cap when `RAXIS_TOOL_POSTGRES_MAX_ROWS` is
/// unset or malformed.
pub const DEFAULT_POSTGRES_MAX_ROWS: u64 = 1000;

/// Default wall-clock timeout for one `postgres_query` invocation.
pub const DEFAULT_POSTGRES_TIMEOUT: Duration = Duration::from_secs(30);

/// `postgres_query` tool. Stateless; one instance is shared across
/// every executor session.
pub struct PostgresQueryTool;

#[async_trait::async_trait]
impl Tool for PostgresQueryTool {
    fn name(&self) -> &'static str { "postgres_query" }

    fn description(&self) -> &'static str {
        "Execute a SQL query against the credential-proxied Postgres \
         upstream bound to the `DATABASE_URL` environment variable. \
         Supports positional `$1`/`$2`/... parameter binding via the \
         optional `params` array (each value must be a JSON null, \
         boolean, integer, float, or string — objects and arrays are \
         rejected). SELECTs return `{rows, row_count, command_tag, \
         truncated?}`; non-SELECT statements return `{rows_affected, \
         command_tag}`. Result row count is capped at \
         RAXIS_TOOL_POSTGRES_MAX_ROWS (default 1000); a `truncated: \
         true` flag is set when the cap is hit. Errors surface as \
         `{error_class, message}` with classes ProxyUnreachable / \
         AuthFailed / QuerySyntax / QueryRuntime / ResultTooLarge / \
         Timeout / MissingEnv. Per-call timeout defaults to 30s; \
         override via `timeout_secs`. The tool dials the loopback \
         credential-proxy URL — DO NOT pass a host or port; the \
         proxy is the only ingress to the upstream database."
    }

    fn input_schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type":     "object",
            "required": ["query"],
            "properties": {
                "query": {
                    "type":        "string",
                    "minLength":   1,
                    "description": "SQL statement to execute. Use \
                                   `$1`, `$2`, ... placeholders for \
                                   positional parameters; bind values \
                                   via the `params` array."
                },
                "params": {
                    "type":  "array",
                    "items": {
                        "type": ["null", "boolean", "integer", "number", "string"]
                    },
                    "description": "Positional parameter bindings. \
                                   Each value must be a JSON null, \
                                   boolean, integer, float, or string \
                                   — objects/arrays are rejected."
                },
                "database": {
                    "type":        "string",
                    "description": "Optional database name override. \
                                   When supplied, replaces the \
                                   default-database path component of \
                                   the loopback `DATABASE_URL`. The \
                                   proxy enforces operator policy on \
                                   which databases are reachable."
                },
                "timeout_secs": {
                    "type":        "integer",
                    "minimum":     1,
                    "maximum":     600,
                    "description": "Per-call wall-clock timeout, in \
                                   whole seconds. Defaults to 30s; \
                                   max 600s."
                }
            }
        })
    }

    async fn execute(
        &self,
        input: &serde_json::Value,
        ctx:   &ToolContext,
    ) -> Result<ToolOutput, ToolError> {
        let start = Instant::now();
        let parsed = match parse_input(input) {
            Ok(p)  => p,
            Err(e) => {
                emit_err(ctx, sha256_hex(""), start, ToolErrorClass::QuerySyntax);
                return Ok(structured_err(ToolErrorClass::QuerySyntax, e));
            }
        };
        let query_sha = sha256_hex(&parsed.query);

        let url = match env::var(DATABASE_URL_ENV) {
            Ok(v) if !v.is_empty() => v,
            _ => {
                emit_err(ctx, query_sha, start, ToolErrorClass::MissingEnv);
                return Ok(structured_err(
                    ToolErrorClass::MissingEnv,
                    format!("env var `{DATABASE_URL_ENV}` is unset or empty; the kernel \
                             session-spawn path stamps this from the credential-proxy \
                             manager — check the kernel logs for `CredentialProxyStarted`"),
                ));
            }
        };
        let url = match maybe_override_database(&url, parsed.database.as_deref()) {
            Ok(u)  => u,
            Err(e) => {
                emit_err(ctx, query_sha, start, ToolErrorClass::QuerySyntax);
                return Ok(structured_err(ToolErrorClass::QuerySyntax, e));
            }
        };

        let max_rows = read_max_rows_env();
        let timeout  = parsed.timeout.unwrap_or(DEFAULT_POSTGRES_TIMEOUT);

        // Race the full operation against the wall-clock budget so a
        // wedged proxy can't pin the dispatch loop forever. The
        // budget covers connect + handshake + query + result decode;
        // a per-phase carve-up is future hardening once we have an
        // observability signal that any single phase is the offender.
        let op = run_query(url, parsed.query.clone(), parsed.params, max_rows);
        let result = match tokio::time::timeout(timeout, op).await {
            Ok(r)  => r,
            Err(_) => {
                emit_err(ctx, query_sha.clone(), start, ToolErrorClass::Timeout);
                return Ok(structured_err(
                    ToolErrorClass::Timeout,
                    format!("postgres_query exceeded {}s wall-clock timeout", timeout.as_secs()),
                ));
            }
        };
        match result {
            Ok(QueryOk::Rows { rows, command_tag, truncated, row_count }) => {
                emit_ok(ctx, query_sha, start, row_count, truncated);
                let body = serde_json::json!({
                    "rows":        rows,
                    "row_count":   row_count,
                    "command_tag": command_tag,
                    "truncated":   truncated,
                });
                Ok(ToolOutput::ok(body.to_string()))
            }
            Ok(QueryOk::Affected { rows_affected, command_tag }) => {
                emit_ok(ctx, query_sha, start, rows_affected, false);
                let body = serde_json::json!({
                    "rows_affected": rows_affected,
                    "command_tag":   command_tag,
                });
                Ok(ToolOutput::ok(body.to_string()))
            }
            Err(PgQueryError { class, message }) => {
                emit_err(ctx, query_sha, start, class.clone());
                Ok(structured_err(class, message))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Input parsing
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct ParsedInput {
    query:    String,
    params:   Vec<PgBoundParam>,
    database: Option<String>,
    timeout:  Option<Duration>,
}

fn parse_input(v: &serde_json::Value) -> Result<ParsedInput, String> {
    let query = v
        .get("query")
        .and_then(|q| q.as_str())
        .ok_or_else(|| "missing or non-string `query`".to_owned())?
        .to_owned();
    if query.trim().is_empty() {
        return Err("`query` MUST be a non-empty SQL statement".to_owned());
    }
    let params = match v.get("params") {
        Some(serde_json::Value::Array(arr)) => arr
            .iter()
            .map(json_value_to_pg_param)
            .collect::<Result<Vec<_>, _>>()?,
        Some(serde_json::Value::Null) | None => Vec::new(),
        Some(other) => {
            return Err(format!(
                "`params` MUST be a JSON array (got {:?})",
                other_kind(other),
            ));
        }
    };
    let database = v
        .get("database")
        .and_then(|d| d.as_str())
        .map(str::to_owned);
    let timeout = match v.get("timeout_secs") {
        Some(s) => {
            let n = s.as_u64().ok_or_else(|| {
                "`timeout_secs` MUST be a positive integer".to_owned()
            })?;
            if n == 0 || n > 600 {
                return Err("`timeout_secs` MUST be in [1, 600]".to_owned());
            }
            Some(Duration::from_secs(n))
        }
        None => None,
    };
    Ok(ParsedInput { query, params, database, timeout })
}

fn other_kind(v: &serde_json::Value) -> &'static str {
    match v {
        serde_json::Value::Null    => "null",
        serde_json::Value::Bool(_) => "boolean",
        serde_json::Value::Number(_) => "number",
        serde_json::Value::String(_) => "string",
        serde_json::Value::Array(_)  => "array",
        serde_json::Value::Object(_) => "object",
    }
}

fn json_value_to_pg_param(v: &serde_json::Value) -> Result<PgBoundParam, String> {
    match v {
        serde_json::Value::Null    => Ok(PgBoundParam::Null),
        serde_json::Value::Bool(b) => Ok(PgBoundParam::Bool(*b)),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Ok(PgBoundParam::Int(i))
            } else if let Some(f) = n.as_f64() {
                Ok(PgBoundParam::Float(f))
            } else {
                Err(format!(
                    "params: numeric value {n:?} is outside the i64/f64 range supported by postgres_query"
                ))
            }
        }
        serde_json::Value::String(s) => Ok(PgBoundParam::Str(s.clone())),
        serde_json::Value::Array(_) | serde_json::Value::Object(_) => Err(format!(
            "params: object/array values are not supported — pass JSONB \
             payloads as strings and CAST inside the SQL (got {:?})",
            other_kind(v),
        )),
    }
}

/// Compact `ToSql`-implementing param wrapper covering the JSON
/// primitive types `postgres_query` accepts. We deliberately do NOT
/// derive a generic `ToSql` here — Postgres needs the target column
/// type at serialization time, so each variant delegates to the
/// matching upstream `ToSql` impl which already speaks the wire
/// shape per target.
#[derive(Debug)]
enum PgBoundParam {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    Str(String),
}

impl ToSql for PgBoundParam {
    fn to_sql(
        &self,
        ty: &Type,
        out: &mut bytes::BytesMut,
    ) -> Result<tokio_postgres::types::IsNull, Box<dyn std::error::Error + Sync + Send>>
    {
        match self {
            Self::Null     => Ok(tokio_postgres::types::IsNull::Yes),
            Self::Bool(b)  => b.to_sql(ty, out),
            Self::Int(i)   => i.to_sql(ty, out),
            Self::Float(f) => f.to_sql(ty, out),
            Self::Str(s)   => s.to_sql(ty, out),
        }
    }

    fn accepts(ty: &Type) -> bool {
        matches!(
            *ty,
            Type::BOOL
                | Type::INT2 | Type::INT4 | Type::INT8
                | Type::FLOAT4 | Type::FLOAT8
                | Type::NUMERIC
                | Type::TEXT | Type::VARCHAR | Type::BPCHAR | Type::NAME
                | Type::UNKNOWN
                | Type::JSON | Type::JSONB
        )
    }

    tokio_postgres::types::to_sql_checked!();
}

// ---------------------------------------------------------------------------
// Query execution
// ---------------------------------------------------------------------------

enum QueryOk {
    Rows {
        rows:        Vec<serde_json::Value>,
        row_count:   u64,
        command_tag: String,
        truncated:   bool,
    },
    Affected {
        rows_affected: u64,
        command_tag:   String,
    },
}

#[derive(Debug)]
struct PgQueryError {
    class:   ToolErrorClass,
    message: String,
}

async fn run_query(
    url:      String,
    query:    String,
    params:   Vec<PgBoundParam>,
    max_rows: u64,
) -> Result<QueryOk, PgQueryError> {
    // Connect. NoTls because the loopback proxy speaks plaintext;
    // the proxy itself handles upstream TLS per `credential-proxy.md §14.3`.
    let (client, connection) = match tokio_postgres::connect(&url, NoTls).await {
        Ok(t)  => t,
        Err(e) => return Err(classify_connect_err(e)),
    };
    // Drive the connection task. Errors flow through `client`'s
    // operations, so we don't need to surface them separately.
    let conn_join = tokio::spawn(async move {
        let _ = connection.await;
    });

    let result = run_query_inner(&client, &query, &params, max_rows).await;

    drop(client);
    let _ = conn_join.await;
    result
}

async fn run_query_inner(
    client:   &tokio_postgres::Client,
    query:    &str,
    params:   &[PgBoundParam],
    max_rows: u64,
) -> Result<QueryOk, PgQueryError> {
    let stmt = client.prepare(query).await.map_err(classify_query_err)?;
    let columns = stmt.columns();

    // Re-bind params as `&dyn ToSql`. tokio-postgres expects a slice
    // of trait-object references.
    let bound_refs: Vec<&(dyn ToSql + Sync)> = params
        .iter()
        .map(|p| p as &(dyn ToSql + Sync))
        .collect();

    if columns.is_empty() {
        // Non-SELECT statement.
        let n = client
            .execute(&stmt, &bound_refs)
            .await
            .map_err(classify_query_err)?;
        return Ok(QueryOk::Affected {
            rows_affected: n,
            command_tag:   non_select_command_tag(query, n),
        });
    }

    let rows = client
        .query(&stmt, &bound_refs)
        .await
        .map_err(classify_query_err)?;
    let total = rows.len() as u64;
    let (kept, truncated) = if total > max_rows {
        (max_rows, true)
    } else {
        (total, false)
    };
    let mut out_rows = Vec::with_capacity(kept as usize);
    for row in rows.iter().take(kept as usize) {
        out_rows.push(row_to_json(row, columns));
    }
    if truncated {
        return Err(PgQueryError {
            class: ToolErrorClass::ResultTooLarge,
            message: format!(
                "postgres_query returned {total} rows, exceeding the per-call cap \
                 of {max_rows} (set via `{POSTGRES_MAX_ROWS_ENV}`); truncate the \
                 query with `LIMIT`/`OFFSET` or raise the cap"
            ),
        });
    }
    Ok(QueryOk::Rows {
        rows:        out_rows,
        row_count:   kept,
        command_tag: format!("SELECT {kept}"),
        truncated:   false,
    })
}

fn row_to_json(row: &Row, columns: &[tokio_postgres::Column]) -> serde_json::Value {
    let mut map = serde_json::Map::with_capacity(columns.len());
    for (i, col) in columns.iter().enumerate() {
        let value = pg_column_to_json(row, i, col.type_());
        map.insert(col.name().to_owned(), value);
    }
    serde_json::Value::Object(map)
}

fn pg_column_to_json(row: &Row, idx: usize, ty: &Type) -> serde_json::Value {
    macro_rules! try_typed {
        ($t:ty, $to:expr) => {{
            match row.try_get::<_, Option<$t>>(idx) {
                Ok(Some(v)) => return $to(v),
                Ok(None)    => return serde_json::Value::Null,
                Err(_)      => {}
            }
        }};
    }
    match *ty {
        Type::BOOL => try_typed!(bool, |b: bool| serde_json::Value::Bool(b)),
        Type::INT2 => try_typed!(i16, |i: i16| serde_json::Value::Number((i as i64).into())),
        Type::INT4 => try_typed!(i32, |i: i32| serde_json::Value::Number((i as i64).into())),
        Type::INT8 => try_typed!(i64, |i: i64| serde_json::Value::Number(i.into())),
        Type::FLOAT4 => try_typed!(f32, |f: f32| {
            serde_json::Number::from_f64(f as f64)
                .map(serde_json::Value::Number)
                .unwrap_or(serde_json::Value::Null)
        }),
        Type::FLOAT8 => try_typed!(f64, |f: f64| {
            serde_json::Number::from_f64(f)
                .map(serde_json::Value::Number)
                .unwrap_or(serde_json::Value::Null)
        }),
        Type::TEXT | Type::VARCHAR | Type::BPCHAR | Type::NAME | Type::UNKNOWN => {
            try_typed!(String, |s: String| serde_json::Value::String(s))
        }
        Type::BYTEA => {
            if let Ok(Some(bytes)) = row.try_get::<_, Option<Vec<u8>>>(idx) {
                use base64::Engine;
                let b64 = base64::engine::general_purpose::STANDARD.encode(&bytes);
                return serde_json::Value::String(format!("base64:{b64}"));
            }
            if let Ok(None) = row.try_get::<_, Option<Vec<u8>>>(idx) {
                return serde_json::Value::Null;
            }
        }
        _ => {
            // Fallback for types we don't enumerate (timestamps, dates, uuids,
            // jsonb, ...): try as String first so columns CAST to text by the
            // operator's SQL still surface readably; otherwise emit the type
            // tag so the agent has actionable context.
            if let Ok(Some(s)) = row.try_get::<_, Option<String>>(idx) {
                return serde_json::Value::String(s);
            }
            if let Ok(None) = row.try_get::<_, Option<String>>(idx) {
                return serde_json::Value::Null;
            }
        }
    }
    // Fallback: column couldn't be coerced into ANY of the supported
    // shapes. Surface the type's canonical name so the model has
    // actionable context rather than a silent `null`.
    serde_json::Value::String(format!("<unsupported pg type: {}>", ty.name()))
}

/// Build a Postgres-ish command tag for non-SELECT statements based
/// on the leading verb. Matches the shape Postgres' own `CommandComplete`
/// frame emits (`INSERT 0 N`, `UPDATE N`, `DELETE N`).
fn non_select_command_tag(query: &str, rows_affected: u64) -> String {
    let leading = query
        .trim_start()
        .split_whitespace()
        .next()
        .unwrap_or("")
        .to_ascii_uppercase();
    match leading.as_str() {
        "INSERT" => format!("INSERT 0 {rows_affected}"),
        "UPDATE" => format!("UPDATE {rows_affected}"),
        "DELETE" => format!("DELETE {rows_affected}"),
        // Fallback: tools may issue DDL / utility statements
        // (CREATE / DROP / ALTER / TRUNCATE / SET / BEGIN / COMMIT
        // / ROLLBACK / ...). Mirror the Postgres convention of
        // surfacing the verb with no row count.
        other if !other.is_empty() => other.to_owned(),
        _ => "OK".to_owned(),
    }
}

// ---------------------------------------------------------------------------
// Error classification
// ---------------------------------------------------------------------------

fn classify_connect_err(err: PgError) -> PgQueryError {
    // Strategy: stringify, then bucket on canonical substrings the
    // tokio-postgres / native I/O error chain surfaces. We do NOT
    // match on the upstream error's `SqlState` here because the
    // connect-phase error path rarely carries one; the database-
    // returned errors during query execution DO carry a SqlState
    // and are classified by `classify_query_err`.
    let msg = err.to_string();
    let lower = msg.to_ascii_lowercase();
    let class = if lower.contains("connection refused")
        || lower.contains("no such file or directory")
        || lower.contains("network is unreachable")
        || lower.contains("connection reset by peer")
    {
        ToolErrorClass::ProxyUnreachable
    } else if lower.contains("password authentication failed")
        || lower.contains("authentication failed")
        || lower.contains("scram authentication")
        || lower.contains("md5 authentication")
        || lower.contains("sasl authentication")
    {
        ToolErrorClass::AuthFailed
    } else if lower.contains("timed out") || lower.contains("timeout") {
        ToolErrorClass::Timeout
    } else {
        // Anything else: bucket as ProxyUnreachable. The proxy is
        // the only ingress; if the connection or handshake failed
        // outside the recognized buckets, the proxy itself is the
        // most actionable thing to inspect.
        ToolErrorClass::ProxyUnreachable
    };
    PgQueryError { class, message: format!("postgres connect failed: {msg}") }
}

fn classify_query_err(err: PgError) -> PgQueryError {
    let msg = err.to_string();
    if let Some(db_err) = err.as_db_error() {
        let code = db_err.code().code();
        // Postgres SqlState class `42` is "Syntax Error or Access Rule
        // Violation"; class `28` is "Invalid Authorization Specification"
        // (only at connect time, but we double-cover here for proxies
        // that surface auth as a query-time error). `08` is "Connection
        // Exception". Everything else surfacing here is runtime.
        let class = if code.starts_with("42") {
            ToolErrorClass::QuerySyntax
        } else if code.starts_with("28") {
            ToolErrorClass::AuthFailed
        } else if code.starts_with("08") {
            ToolErrorClass::ProxyUnreachable
        } else {
            ToolErrorClass::QueryRuntime
        };
        return PgQueryError {
            class,
            message: format!(
                "{}: {} (SQLSTATE {})",
                db_err.severity(),
                db_err.message(),
                code,
            ),
        };
    }
    // Not a server-returned error → bucket via the connect-style
    // classifier (covers io::Error wraps like ECONNRESET mid-query).
    let connect_style = classify_connect_err(err);
    PgQueryError {
        class:   connect_style.class,
        message: msg,
    }
}

// ---------------------------------------------------------------------------
// URL helpers
// ---------------------------------------------------------------------------

/// If `override_db` is `Some`, rewrite the URL's database-name path
/// component. The `DATABASE_URL` shape per `loopback_env()` is
/// `postgresql://raxis@127.0.0.1:<port>/` (empty path); the override
/// replaces the trailing `/<db>`. We do NOT touch host / port — the
/// proxy IS the only ingress, and a model that supplied a host
/// override would be silently bypassing INV-CRED-PROXY-VM-REACHABILITY-01.
fn maybe_override_database(
    url:         &str,
    override_db: Option<&str>,
) -> Result<String, String> {
    let Some(db) = override_db else { return Ok(url.to_owned()); };
    if db.is_empty() {
        return Err("`database` override MUST be a non-empty database name".to_owned());
    }
    if db.contains('/') || db.contains('?') || db.contains('#') {
        return Err(format!(
            "`database` override {db:?} contains forbidden character \
             (`/`, `?`, `#`); pass a bare database name"
        ));
    }
    // Find the scheme end and the host[:port] end.
    let scheme_end = url.find("://").ok_or_else(|| {
        format!("DATABASE_URL is missing scheme separator `://`: {url}")
    })?;
    let rest = &url[scheme_end + 3..];
    // The path starts at the first `/` after the host. If no `/`
    // present (the canonical loopback shape), append the override.
    if let Some(path_start) = rest.find('/') {
        // Preserve `?query` if present.
        let abs_path_start = scheme_end + 3 + path_start;
        let path_segment = &url[abs_path_start..];
        let q_start = path_segment.find('?');
        let query_suffix = match q_start {
            Some(i) => &path_segment[i..],
            None    => "",
        };
        Ok(format!("{}/{}{}", &url[..abs_path_start], db, query_suffix))
    } else {
        Ok(format!("{url}/{db}"))
    }
}

// ---------------------------------------------------------------------------
// Misc helpers
// ---------------------------------------------------------------------------

fn read_max_rows_env() -> u64 {
    env::var(POSTGRES_MAX_ROWS_ENV)
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .filter(|n| *n > 0)
        .unwrap_or(DEFAULT_POSTGRES_MAX_ROWS)
}

fn structured_err(class: ToolErrorClass, message: impl Into<String>) -> ToolOutput {
    #[derive(Serialize)]
    struct Body<'a> {
        error_class: &'a str,
        message:     String,
    }
    let body = Body { error_class: class.as_str(), message: message.into() };
    ToolOutput::err(serde_json::to_string(&body).unwrap_or_else(|_| {
        format!("{}: <serialization failed>", class.as_str())
    }))
}

fn emit_ok(
    ctx:        &ToolContext,
    query_sha:  String,
    start:      Instant,
    row_count:  u64,
    truncated:  bool,
) {
    if let Some(sink) = ctx.tool_audit_sink.as_ref() {
        emit_event(sink, ToolAuditEvent::ok(
            "postgres_query",
            query_sha,
            start.elapsed(),
            row_count,
            truncated,
        ));
    }
}

fn emit_err(
    ctx:       &ToolContext,
    query_sha: String,
    start:     Instant,
    class:     ToolErrorClass,
) {
    if let Some(sink) = ctx.tool_audit_sink.as_ref() {
        emit_event(sink, ToolAuditEvent::err(
            "postgres_query",
            query_sha,
            start.elapsed(),
            class,
        ));
    }
}

#[inline]
fn emit_event(sink: &Arc<dyn ToolAuditSink>, event: ToolAuditEvent) {
    sink.emit(event);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tool_audit::{RecordingAuditSink, ToolAuditOutcome};
    use std::sync::{Mutex, MutexGuard, OnceLock};

    /// Process-wide mutex serializing every test that touches
    /// `DATABASE_URL` / `RAXIS_TOOL_POSTGRES_MAX_ROWS`. `cargo test`
    /// runs tests in parallel on a multi-threaded runtime so two
    /// tests racing on `set_var` / `remove_var` would otherwise
    /// flake. This is the standard env-var-test pattern.
    fn env_guard() -> MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        // Recover from a poisoned mutex — a previous test panic
        // doesn't invalidate the env-var contract for subsequent
        // tests, so we deliberately consume the poison.
        LOCK.get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|p| p.into_inner())
    }

    fn ctx_with_sink(sink: Arc<dyn ToolAuditSink>) -> ToolContext {
        ToolContext::for_workspace("/tmp")
            .with_audit_sink(sink)
    }

    /// Schema-shape regression — the tool MUST advertise itself to
    /// the model with the canonical name and a JSON-object schema.
    #[test]
    fn schema_has_required_query_field() {
        let t = PostgresQueryTool;
        assert_eq!(t.name(), "postgres_query");
        let schema = t.input_schema();
        assert_eq!(schema["type"], "object");
        assert_eq!(schema["required"][0], "query");
        assert!(schema["properties"]["params"].is_object());
        assert!(schema["properties"]["timeout_secs"].is_object());
    }

    /// Param objects/arrays MUST be rejected at parse time with
    /// `QuerySyntax` (mirrors the per-element validation in
    /// `json_value_to_pg_param`).
    #[tokio::test]
    async fn rejects_object_params_with_query_syntax_class() {
        let _g   = env_guard();
        let sink = Arc::new(RecordingAuditSink::new());
        let ctx  = ctx_with_sink(sink.clone());
        // Stamp a DATABASE_URL so we don't trip the MissingEnv path.
        std::env::set_var(DATABASE_URL_ENV, "postgresql://r@127.0.0.1:1/db");
        let out = PostgresQueryTool.execute(
            &serde_json::json!({
                "query": "SELECT $1",
                "params": [{"forbidden": 1}],
            }),
            &ctx,
        ).await.unwrap();
        assert_eq!(out.is_error, Some(true));
        let body: serde_json::Value = serde_json::from_str(&out.content).unwrap();
        assert_eq!(body["error_class"], "QuerySyntax");
        assert!(body["message"].as_str().unwrap().contains("object/array"));
        // Audit event MUST be emitted with the same error_class.
        let events = sink.events();
        assert_eq!(events.len(), 1);
        match &events[0].outcome {
            ToolAuditOutcome::Err { error_class } => {
                assert_eq!(error_class, &ToolErrorClass::QuerySyntax);
            }
            other => panic!("expected Err audit outcome, got {other:?}"),
        }
    }

    /// Missing `DATABASE_URL` env surfaces `MissingEnv` — the kernel
    /// session-spawn path is the source of truth for this var.
    #[tokio::test]
    async fn missing_database_url_surfaces_missing_env_class() {
        let _g   = env_guard();
        let sink = Arc::new(RecordingAuditSink::new());
        let ctx  = ctx_with_sink(sink.clone());
        std::env::remove_var(DATABASE_URL_ENV);
        let out = PostgresQueryTool.execute(
            &serde_json::json!({ "query": "SELECT 1" }),
            &ctx,
        ).await.unwrap();
        assert_eq!(out.is_error, Some(true));
        let body: serde_json::Value = serde_json::from_str(&out.content).unwrap();
        assert_eq!(body["error_class"], "MissingEnv");
        let events = sink.events();
        assert_eq!(events.len(), 1);
        match &events[0].outcome {
            ToolAuditOutcome::Err { error_class } => {
                assert_eq!(error_class, &ToolErrorClass::MissingEnv);
            }
            other => panic!("expected Err audit outcome, got {other:?}"),
        }
    }

    /// Empty `DATABASE_URL` MUST also surface `MissingEnv` — the
    /// kernel session-spawn path stamps a non-empty URL or the
    /// proxy did not bind.
    #[tokio::test]
    async fn empty_database_url_surfaces_missing_env_class() {
        let _g   = env_guard();
        let sink = Arc::new(RecordingAuditSink::new());
        let ctx  = ctx_with_sink(sink.clone());
        std::env::set_var(DATABASE_URL_ENV, "");
        let out = PostgresQueryTool.execute(
            &serde_json::json!({ "query": "SELECT 1" }),
            &ctx,
        ).await.unwrap();
        assert_eq!(out.is_error, Some(true));
        let body: serde_json::Value = serde_json::from_str(&out.content).unwrap();
        assert_eq!(body["error_class"], "MissingEnv");
        std::env::remove_var(DATABASE_URL_ENV);
    }

    /// Dialing an unused 127.0.0.1:port returns `ProxyUnreachable`.
    /// We bind a listener to pick a free port then drop it so the
    /// port is guaranteed unused for the test.
    #[tokio::test]
    async fn proxy_unreachable_surfaces_when_no_listener() {
        let _g = env_guard();
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let url = format!("postgresql://r@127.0.0.1:{}/db", addr.port());
        std::env::set_var(DATABASE_URL_ENV, &url);

        let sink = Arc::new(RecordingAuditSink::new());
        let ctx  = ctx_with_sink(sink.clone());
        let out  = PostgresQueryTool.execute(
            &serde_json::json!({ "query": "SELECT 1", "timeout_secs": 2 }),
            &ctx,
        ).await.unwrap();
        std::env::remove_var(DATABASE_URL_ENV);

        assert_eq!(out.is_error, Some(true));
        let body: serde_json::Value = serde_json::from_str(&out.content).unwrap();
        assert_eq!(body["error_class"], "ProxyUnreachable",
            "expected ProxyUnreachable; got body: {}", out.content);
        let events = sink.events();
        match &events[0].outcome {
            ToolAuditOutcome::Err { error_class } => {
                assert_eq!(error_class, &ToolErrorClass::ProxyUnreachable);
            }
            other => panic!("expected Err audit outcome, got {other:?}"),
        }
    }

    /// A listener that accepts but never speaks → wall-clock timeout
    /// fires within `timeout_secs + small slack`.
    #[tokio::test]
    async fn timeout_surfaces_when_proxy_is_silent() {
        let _g = env_guard();
        use tokio::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        // Spawn a task that accepts connections but never writes.
        // The accepted streams sit idle until the test drops the
        // listener at the end.
        let _accept = tokio::spawn(async move {
            loop {
                if let Ok((stream, _)) = listener.accept().await {
                    // Keep the stream alive for the test's lifetime.
                    std::mem::forget(stream);
                }
            }
        });
        let url = format!("postgresql://r@127.0.0.1:{}/db", addr.port());
        std::env::set_var(DATABASE_URL_ENV, &url);

        let sink  = Arc::new(RecordingAuditSink::new());
        let ctx   = ctx_with_sink(sink.clone());
        let start = std::time::Instant::now();
        let out   = PostgresQueryTool.execute(
            &serde_json::json!({ "query": "SELECT 1", "timeout_secs": 1 }),
            &ctx,
        ).await.unwrap();
        let elapsed = start.elapsed();
        std::env::remove_var(DATABASE_URL_ENV);

        assert_eq!(out.is_error, Some(true));
        let body: serde_json::Value = serde_json::from_str(&out.content).unwrap();
        assert_eq!(body["error_class"], "Timeout",
            "expected Timeout error_class; got: {}", out.content);
        // Allow up to 3s of slack for slow CI workers.
        assert!(elapsed < Duration::from_secs(4),
            "timeout took too long: {elapsed:?}");
        let events = sink.events();
        match &events[0].outcome {
            ToolAuditOutcome::Err { error_class } => {
                assert_eq!(error_class, &ToolErrorClass::Timeout);
            }
            other => panic!("expected Err audit outcome, got {other:?}"),
        }
    }

    /// `timeout_secs = 0` is rejected as `QuerySyntax`.
    #[tokio::test]
    async fn rejects_zero_timeout_secs() {
        let _g = env_guard();
        std::env::set_var(DATABASE_URL_ENV, "postgresql://r@127.0.0.1:1/db");
        let ctx = ToolContext::for_workspace("/tmp");
        let out = PostgresQueryTool.execute(
            &serde_json::json!({ "query": "SELECT 1", "timeout_secs": 0 }),
            &ctx,
        ).await.unwrap();
        std::env::remove_var(DATABASE_URL_ENV);
        assert_eq!(out.is_error, Some(true));
        let body: serde_json::Value = serde_json::from_str(&out.content).unwrap();
        assert_eq!(body["error_class"], "QuerySyntax");
    }

    /// `timeout_secs > 600` is rejected.
    #[tokio::test]
    async fn rejects_oversize_timeout_secs() {
        let _g = env_guard();
        std::env::set_var(DATABASE_URL_ENV, "postgresql://r@127.0.0.1:1/db");
        let ctx = ToolContext::for_workspace("/tmp");
        let out = PostgresQueryTool.execute(
            &serde_json::json!({ "query": "SELECT 1", "timeout_secs": 9999 }),
            &ctx,
        ).await.unwrap();
        std::env::remove_var(DATABASE_URL_ENV);
        assert_eq!(out.is_error, Some(true));
    }

    /// `database` override containing `/` is rejected before any
    /// network I/O — `INV-CRED-PROXY-VM-REACHABILITY-01` requires we
    /// never let an LLM-supplied string smuggle a host change in.
    #[tokio::test]
    async fn rejects_database_override_with_slash() {
        let _g = env_guard();
        std::env::set_var(DATABASE_URL_ENV, "postgresql://r@127.0.0.1:1/db");
        let ctx = ToolContext::for_workspace("/tmp");
        let out = PostgresQueryTool.execute(
            &serde_json::json!({
                "query":    "SELECT 1",
                "database": "../other-host/db",
            }),
            &ctx,
        ).await.unwrap();
        std::env::remove_var(DATABASE_URL_ENV);
        assert_eq!(out.is_error, Some(true));
        let body: serde_json::Value = serde_json::from_str(&out.content).unwrap();
        assert_eq!(body["error_class"], "QuerySyntax",
            "rejecting host-smuggling MUST not be silent");
    }

    /// Cap-override env var is read lazily on every call. Default
    /// is 1000; non-positive / non-numeric values fall back to the
    /// default.
    #[test]
    fn read_max_rows_env_falls_back_to_default() {
        let _g = env_guard();
        std::env::remove_var(POSTGRES_MAX_ROWS_ENV);
        assert_eq!(read_max_rows_env(), 1000);
        std::env::set_var(POSTGRES_MAX_ROWS_ENV, "0");
        assert_eq!(read_max_rows_env(), 1000,
            "zero MUST fall back to the default cap");
        std::env::set_var(POSTGRES_MAX_ROWS_ENV, "not-a-number");
        assert_eq!(read_max_rows_env(), 1000);
        std::env::set_var(POSTGRES_MAX_ROWS_ENV, "5");
        assert_eq!(read_max_rows_env(), 5);
        std::env::remove_var(POSTGRES_MAX_ROWS_ENV);
    }

    /// Database-name override path-rewriting preserves the host /
    /// port verbatim. The proxy is the only ingress; smuggling a
    /// new host would defeat `INV-CRED-PROXY-VM-REACHABILITY-01`.
    #[test]
    fn maybe_override_database_only_changes_path() {
        let url = "postgresql://raxis@127.0.0.1:54321/";
        let new = maybe_override_database(url, Some("analytics")).unwrap();
        assert_eq!(new, "postgresql://raxis@127.0.0.1:54321/analytics");
    }

    /// Existing `/db` path component is replaced.
    #[test]
    fn maybe_override_database_replaces_existing_path() {
        let url = "postgresql://raxis@127.0.0.1:54321/old";
        let new = maybe_override_database(url, Some("new")).unwrap();
        assert_eq!(new, "postgresql://raxis@127.0.0.1:54321/new");
    }

    /// Query-string suffix is preserved when overriding the database.
    #[test]
    fn maybe_override_database_preserves_query_suffix() {
        let url = "postgresql://raxis@127.0.0.1:54321/old?sslmode=disable";
        let new = maybe_override_database(url, Some("new")).unwrap();
        assert_eq!(new, "postgresql://raxis@127.0.0.1:54321/new?sslmode=disable");
    }

    /// `None` override → URL unchanged.
    #[test]
    fn maybe_override_database_no_change_when_none() {
        let url = "postgresql://raxis@127.0.0.1:54321/db";
        let new = maybe_override_database(url, None).unwrap();
        assert_eq!(new, url);
    }

    /// Command tag synthesis mirrors the Postgres convention.
    #[test]
    fn non_select_command_tag_is_postgres_shaped() {
        assert_eq!(non_select_command_tag("INSERT INTO t VALUES (1)", 1),
            "INSERT 0 1");
        assert_eq!(non_select_command_tag("UPDATE t SET x=1", 3),
            "UPDATE 3");
        assert_eq!(non_select_command_tag("DELETE FROM t", 5),
            "DELETE 5");
        assert_eq!(non_select_command_tag("CREATE TABLE t (x int)", 0),
            "CREATE");
    }
}

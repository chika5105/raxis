//! `redis_query` — structured Redis tool for the executor.
//!
//! Closes the executor tool-registry gap pinned by
//! `INV-EXEC-TOOL-REGISTRY-01`: every credential-proxied service the
//! kernel binds a listener for MUST be reachable via a structured
//! tool from inside the executor VM. The proxy on the host
//! (`raxis-credential-proxy-redis`) terminates the agent's
//! `redis://` connection on the loopback `127.0.0.1:<port>`
//! listener and performs the real upstream auth + TLS; the in-VM
//! client only speaks plaintext RESP to the proxy.
//!
//! ## Wire contract
//!
//! * URL: `REDIS_URL` env (the kernel session-spawn path stamps
//!   `redis://raxis@127.0.0.1:<port>/` from the credential-proxy
//!   manager).
//! * Driver: `redis::Client::open(url)` + an async multiplexed
//!   connection.
//! * Args: `command: String` (e.g. `"GET"`, `"SET"`, `"HGET"`),
//!   `args: Vec<String>` (positional). Each arg is sent as a bulk
//!   string; binary payloads SHOULD be base64-encoded by the LLM
//!   before being passed in.
//! * Result: `{ "value": <json>, "kind": "..." }` where `kind ∈
//!   {nil, int, bulk_string, simple_string, array, ok, status,
//!   double, big_number, boolean, map, set}`. Bytes-shaped responses
//!   are returned as UTF-8 strings when valid; otherwise as
//!   `"base64:<payload>"`.
//! * Error shape: structured `{ "error_class": "...", "message": "..." }`
//!   with `error_class ∈ {ProxyUnreachable, AuthFailed, QuerySyntax,
//!   QueryRuntime, Timeout, MissingEnv}`. Redis doesn't carry a
//!   `ResultTooLarge` arm since each call is bounded by the cmd
//!   (`LRANGE 0 -1` is the operator's choice, not a tool default).
//!
//! ## Audit
//!
//! On every invocation the tool emits one `ToolAuditEvent` carrying
//! `tool="redis_query"`, `sha256(command_envelope)`, `duration_ms`,
//! and the outcome shape. The canonical envelope is
//! `"<UPPERCASE_CMD>|<argc>"` — argv values are never recorded in
//! the planner-side audit. The host-side proxy emits
//! `RedisCommandExecuted` with the canonical command-hash when the
//! wire frame reaches it; the two events pair on inspection.
//!
//! ## Invariants upheld
//!
//! * **INV-CRED-PROXY-VM-REACHABILITY-01** — the tool dials the
//!   loopback URL from the env literally; it never accepts a host /
//!   port argument.
//! * **INV-SECRET-02** — no credential bytes ever touch the planner.

use std::env;
use std::sync::Arc;
use std::time::{Duration, Instant};

use redis::{Client, RedisError, Value as RedisValue};
use serde::Serialize;
use serde_json::Value;

use crate::tool_audit::{sha256_hex, ToolAuditEvent, ToolAuditSink, ToolErrorClass};
use crate::tools::{Tool, ToolContext, ToolError, ToolOutput};

/// Env var the kernel session-spawn path stamps with the loopback
/// `redis://raxis@127.0.0.1:<port>/` URL.
pub const REDIS_URL_ENV: &str = "REDIS_URL";

/// Default wall-clock timeout for one `redis_query` invocation.
pub const DEFAULT_REDIS_TIMEOUT: Duration = Duration::from_secs(10);

/// Maximum argv length per call. Pinned defensively so a runaway
/// LLM can't pin the dispatch loop building a million-arg `MSET`.
pub const REDIS_MAX_ARGV: usize = 1024;

/// `redis_query` tool. Stateless; one instance is shared across
/// every executor session.
pub struct RedisQueryTool;

#[async_trait::async_trait]
impl Tool for RedisQueryTool {
    fn name(&self) -> &'static str { "redis_query" }

    fn description(&self) -> &'static str {
        "Execute a single Redis command against the credential-proxied \
         Redis upstream bound to the `REDIS_URL` environment variable. \
         The `command` argument is the command verb (e.g. `GET`, `SET`, \
         `HGETALL`, `LRANGE`); `args` is a JSON array of string \
         positional arguments (binary payloads SHOULD be base64-encoded \
         before being passed in). Returns `{value, kind}` where `value` \
         is the JSON-shaped response (nil → null; integer → number; \
         bulk-string → string or `\"base64:...\"`; arrays → nested \
         arrays). Errors surface as `{error_class, message}` with \
         classes ProxyUnreachable / AuthFailed / QuerySyntax / \
         QueryRuntime / Timeout / MissingEnv. Per-call timeout defaults \
         to 10s; override via `timeout_secs`. DO NOT pass a host or \
         port; the loopback proxy is the only ingress."
    }

    fn input_schema(&self) -> Value {
        serde_json::json!({
            "type":     "object",
            "required": ["command"],
            "properties": {
                "command": {
                    "type":        "string",
                    "minLength":   1,
                    "description": "Redis command verb (e.g. `GET`, \
                                   `SET`, `HGET`). Matched \
                                   case-insensitively."
                },
                "args": {
                    "type":  "array",
                    "items": {"type": "string"},
                    "description": "Positional command arguments. \
                                   Each value is sent as a bulk \
                                   string; binary payloads MUST be \
                                   base64-encoded."
                },
                "timeout_secs": {
                    "type":    "integer",
                    "minimum": 1,
                    "maximum": 600
                }
            }
        })
    }

    async fn execute(
        &self,
        input: &Value,
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
        let sha = sha256_hex(canonical_envelope(&parsed));

        let url = match env::var(REDIS_URL_ENV) {
            Ok(v) if !v.is_empty() => v,
            _ => {
                emit_err(ctx, sha, start, ToolErrorClass::MissingEnv);
                return Ok(structured_err(
                    ToolErrorClass::MissingEnv,
                    format!("env var `{REDIS_URL_ENV}` is unset or empty; the kernel \
                             session-spawn path stamps this from the credential-proxy \
                             manager — check the kernel logs for `CredentialProxyStarted`"),
                ));
            }
        };
        let timeout = parsed.timeout.unwrap_or(DEFAULT_REDIS_TIMEOUT);
        let op = run_command(url, parsed);
        let result = match tokio::time::timeout(timeout, op).await {
            Ok(r)  => r,
            Err(_) => {
                emit_err(ctx, sha.clone(), start, ToolErrorClass::Timeout);
                return Ok(structured_err(
                    ToolErrorClass::Timeout,
                    format!("redis_query exceeded {}s wall-clock timeout", timeout.as_secs()),
                ));
            }
        };
        match result {
            Ok(RedisOk { value, kind }) => {
                emit_ok(ctx, sha, start, 1, false);
                let body = serde_json::json!({ "value": value, "kind": kind });
                Ok(ToolOutput::ok(body.to_string()))
            }
            Err(RedisQueryError { class, message }) => {
                emit_err(ctx, sha, start, class.clone());
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
    command: String,
    args:    Vec<String>,
    timeout: Option<Duration>,
}

fn parse_input(v: &Value) -> Result<ParsedInput, String> {
    let command = v
        .get("command")
        .and_then(|c| c.as_str())
        .ok_or_else(|| "missing or non-string `command`".to_owned())?
        .trim()
        .to_owned();
    if command.is_empty() {
        return Err("`command` MUST be a non-empty Redis verb".to_owned());
    }
    if !command.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return Err(format!(
            "`command` {command:?} contains non-alphanumeric chars; Redis verbs \
             are ASCII alphanumerics + `_`"
        ));
    }
    let args = match v.get("args") {
        Some(Value::Array(arr)) => arr
            .iter()
            .enumerate()
            .map(|(i, a)| {
                a.as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| format!("args[{i}] MUST be a string"))
            })
            .collect::<Result<Vec<_>, _>>()?,
        Some(Value::Null) | None => Vec::new(),
        Some(_) => return Err("`args` MUST be a JSON array of strings".to_owned()),
    };
    if args.len() > REDIS_MAX_ARGV {
        return Err(format!(
            "`args` length {} exceeds the per-call cap of {REDIS_MAX_ARGV}; \
             batch the work into multiple redis_query calls",
            args.len()
        ));
    }
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
    Ok(ParsedInput { command, args, timeout })
}

fn canonical_envelope(p: &ParsedInput) -> String {
    format!("{}|{}", p.command.to_ascii_uppercase(), p.args.len())
}

// ---------------------------------------------------------------------------
// Command execution
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct RedisOk {
    value: Value,
    kind:  &'static str,
}

#[derive(Debug)]
struct RedisQueryError {
    class:   ToolErrorClass,
    message: String,
}

async fn run_command(url: String, parsed: ParsedInput) -> Result<RedisOk, RedisQueryError> {
    let client = match Client::open(url) {
        Ok(c)  => c,
        Err(e) => return Err(classify_connect_err(e)),
    };
    let mut conn = match client.get_multiplexed_async_connection().await {
        Ok(c)  => c,
        Err(e) => return Err(classify_connect_err(e)),
    };
    let mut cmd = redis::cmd(&parsed.command.to_ascii_uppercase());
    for a in &parsed.args {
        cmd.arg(a.as_str());
    }
    let v: RedisValue = cmd
        .query_async(&mut conn)
        .await
        .map_err(classify_query_err)?;
    Ok(redis_value_to_json(&v))
}

fn redis_value_to_json(v: &RedisValue) -> RedisOk {
    match v {
        RedisValue::Nil => RedisOk { value: Value::Null,                                 kind: "nil" },
        RedisValue::Int(i) => RedisOk { value: Value::Number((*i).into()),                kind: "int" },
        RedisValue::BulkString(bytes) => RedisOk {
            value: bytes_to_json(bytes),
            kind:  "bulk_string",
        },
        RedisValue::SimpleString(s) => RedisOk {
            value: Value::String(s.clone()),
            kind:  "simple_string",
        },
        RedisValue::Okay => RedisOk { value: Value::String("OK".to_owned()),              kind: "ok" },
        RedisValue::Array(arr) => {
            let mapped: Vec<Value> = arr.iter().map(|x| redis_value_to_json(x).value).collect();
            RedisOk { value: Value::Array(mapped),                                         kind: "array" }
        }
        RedisValue::Map(pairs) => {
            // Redis 6+ MAP type — pairs of `(key, value)`. Emit as a
            // JSON object when every key is a UTF-8 bulk-string,
            // otherwise fall back to a list of [k, v] arrays so we
            // don't lose data.
            if pairs.iter().all(|(k, _)| matches!(k, RedisValue::BulkString(b) if std::str::from_utf8(b).is_ok())) {
                let mut map = serde_json::Map::with_capacity(pairs.len());
                for (k, vv) in pairs {
                    let key = match k {
                        RedisValue::BulkString(b) => String::from_utf8_lossy(b).into_owned(),
                        other => format!("{other:?}"),
                    };
                    map.insert(key, redis_value_to_json(vv).value);
                }
                RedisOk { value: Value::Object(map), kind: "map" }
            } else {
                let mut out = Vec::with_capacity(pairs.len());
                for (k, vv) in pairs {
                    out.push(Value::Array(vec![
                        redis_value_to_json(k).value,
                        redis_value_to_json(vv).value,
                    ]));
                }
                RedisOk { value: Value::Array(out), kind: "map" }
            }
        }
        RedisValue::Set(items) => {
            let mapped: Vec<Value> = items.iter().map(|x| redis_value_to_json(x).value).collect();
            RedisOk { value: Value::Array(mapped),                                         kind: "set" }
        }
        RedisValue::Double(f) => RedisOk {
            value: serde_json::Number::from_f64(*f).map(Value::Number).unwrap_or(Value::Null),
            kind:  "double",
        },
        RedisValue::Boolean(b) => RedisOk { value: Value::Bool(*b),                       kind: "boolean" },
        RedisValue::VerbatimString { text, .. } => RedisOk {
            value: Value::String(text.clone()),
            kind:  "verbatim_string",
        },
        RedisValue::BigNumber(b) => RedisOk {
            value: Value::String(b.to_string()),
            kind:  "big_number",
        },
        RedisValue::Attribute { data, .. } => redis_value_to_json(data),
        RedisValue::Push { kind: pkind, data } => {
            let mapped: Vec<Value> = data.iter().map(|x| redis_value_to_json(x).value).collect();
            let mut wrapped = serde_json::Map::new();
            wrapped.insert("push_kind".to_owned(), Value::String(format!("{pkind:?}")));
            wrapped.insert("data".to_owned(),       Value::Array(mapped));
            RedisOk { value: Value::Object(wrapped), kind: "push" }
        }
        RedisValue::ServerError(e) => {
            // Server-returned RESP3 server-error frame — surface the
            // textual category + message inside the OK shape rather
            // than the Err shape; the caller asked Redis for this
            // payload deliberately (e.g. `XPENDING` against a missing
            // stream). The structured `error_class` shape is reserved
            // for protocol-level / connection-level errors.
            let mut o = serde_json::Map::new();
            o.insert("category".to_owned(), Value::String(format!("{e:?}")));
            RedisOk { value: Value::Object(o), kind: "server_error" }
        }
    }
}

fn bytes_to_json(bytes: &[u8]) -> Value {
    match std::str::from_utf8(bytes) {
        Ok(s) => Value::String(s.to_owned()),
        Err(_) => {
            use base64::Engine;
            let b64 = base64::engine::general_purpose::STANDARD.encode(bytes);
            Value::String(format!("base64:{b64}"))
        }
    }
}

// ---------------------------------------------------------------------------
// Error classification
// ---------------------------------------------------------------------------

fn classify_connect_err(err: RedisError) -> RedisQueryError {
    let msg   = err.to_string();
    let lower = msg.to_ascii_lowercase();
    let class = if lower.contains("connection refused")
        || lower.contains("no such file or directory")
        || lower.contains("network is unreachable")
        || lower.contains("connection reset")
        || err.is_connection_refusal()
    {
        ToolErrorClass::ProxyUnreachable
    } else if lower.contains("authentication") || lower.contains("auth ") {
        ToolErrorClass::AuthFailed
    } else if lower.contains("invalid") || lower.contains("malformed") {
        ToolErrorClass::QuerySyntax
    } else if lower.contains("timed out") || lower.contains("timeout") {
        ToolErrorClass::Timeout
    } else {
        ToolErrorClass::ProxyUnreachable
    };
    RedisQueryError { class, message: format!("redis connect failed: {msg}") }
}

fn classify_query_err(err: RedisError) -> RedisQueryError {
    let msg   = err.to_string();
    let lower = msg.to_ascii_lowercase();
    if err.is_connection_refusal()
        || lower.contains("connection refused")
        || lower.contains("broken pipe")
        || lower.contains("connection reset")
    {
        return RedisQueryError {
            class:   ToolErrorClass::ProxyUnreachable,
            message: format!("redis connection broken: {msg}"),
        };
    }
    if lower.contains("authentication") || lower.contains("wrongpass") || lower.contains("noauth") {
        return RedisQueryError {
            class:   ToolErrorClass::AuthFailed,
            message: format!("redis auth failed: {msg}"),
        };
    }
    if lower.contains("timed out") || lower.contains("timeout") || err.is_timeout() {
        return RedisQueryError {
            class:   ToolErrorClass::Timeout,
            message: format!("redis operation timed out: {msg}"),
        };
    }
    if lower.contains("unknown command")
        || lower.contains("wrong number of arguments")
        || lower.contains("err syntax error")
        || lower.contains("err value is not")
    {
        return RedisQueryError {
            class:   ToolErrorClass::QuerySyntax,
            message: format!("redis rejected the command: {msg}"),
        };
    }
    RedisQueryError {
        class:   ToolErrorClass::QueryRuntime,
        message: format!("redis runtime error: {msg}"),
    }
}

// ---------------------------------------------------------------------------
// Misc helpers
// ---------------------------------------------------------------------------

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
    sha:        String,
    start:      Instant,
    row_count:  u64,
    truncated:  bool,
) {
    if let Some(sink) = ctx.tool_audit_sink.as_ref() {
        emit_event(sink, ToolAuditEvent::ok(
            "redis_query",
            sha,
            start.elapsed(),
            row_count,
            truncated,
        ));
    }
}

fn emit_err(
    ctx:   &ToolContext,
    sha:   String,
    start: Instant,
    class: ToolErrorClass,
) {
    if let Some(sink) = ctx.tool_audit_sink.as_ref() {
        emit_event(sink, ToolAuditEvent::err(
            "redis_query",
            sha,
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

    fn env_guard() -> MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|p| p.into_inner())
    }

    fn ctx_with_sink(sink: Arc<dyn ToolAuditSink>) -> ToolContext {
        ToolContext::for_workspace("/tmp").with_audit_sink(sink)
    }

    #[test]
    fn schema_has_required_command_field() {
        let t = RedisQueryTool;
        assert_eq!(t.name(), "redis_query");
        let schema = t.input_schema();
        assert_eq!(schema["type"], "object");
        assert_eq!(schema["required"][0], "command");
    }

    #[test]
    fn canonical_envelope_uppercases_command_and_counts_args() {
        let p = ParsedInput {
            command: "get".into(),
            args:    vec!["a".into(), "b".into()],
            timeout: None,
        };
        assert_eq!(canonical_envelope(&p), "GET|2");
    }

    #[tokio::test]
    async fn missing_redis_url_surfaces_missing_env_class() {
        let _g   = env_guard();
        let sink = Arc::new(RecordingAuditSink::new());
        let ctx  = ctx_with_sink(sink.clone());
        std::env::remove_var(REDIS_URL_ENV);
        let out = RedisQueryTool.execute(
            &serde_json::json!({ "command": "PING" }),
            &ctx,
        ).await.unwrap();
        assert_eq!(out.is_error, Some(true));
        let body: Value = serde_json::from_str(&out.content).unwrap();
        assert_eq!(body["error_class"], "MissingEnv");
        let events = sink.events();
        match &events[0].outcome {
            ToolAuditOutcome::Err { error_class } => {
                assert_eq!(error_class, &ToolErrorClass::MissingEnv);
            }
            other => panic!("expected Err audit outcome, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn empty_redis_url_surfaces_missing_env_class() {
        let _g   = env_guard();
        let sink = Arc::new(RecordingAuditSink::new());
        let ctx  = ctx_with_sink(sink.clone());
        std::env::set_var(REDIS_URL_ENV, "");
        let out = RedisQueryTool.execute(
            &serde_json::json!({ "command": "PING" }),
            &ctx,
        ).await.unwrap();
        std::env::remove_var(REDIS_URL_ENV);
        assert_eq!(out.is_error, Some(true));
        let body: Value = serde_json::from_str(&out.content).unwrap();
        assert_eq!(body["error_class"], "MissingEnv");
    }

    #[tokio::test]
    async fn rejects_non_alphanumeric_command() {
        let _g = env_guard();
        std::env::set_var(REDIS_URL_ENV, "redis://127.0.0.1:1/");
        let ctx = ToolContext::for_workspace("/tmp");
        let out = RedisQueryTool.execute(
            &serde_json::json!({ "command": "GET; DROP" }),
            &ctx,
        ).await.unwrap();
        std::env::remove_var(REDIS_URL_ENV);
        assert_eq!(out.is_error, Some(true));
        let body: Value = serde_json::from_str(&out.content).unwrap();
        assert_eq!(body["error_class"], "QuerySyntax");
    }

    #[tokio::test]
    async fn rejects_non_string_args() {
        let _g = env_guard();
        std::env::set_var(REDIS_URL_ENV, "redis://127.0.0.1:1/");
        let ctx = ToolContext::for_workspace("/tmp");
        let out = RedisQueryTool.execute(
            &serde_json::json!({ "command": "SET", "args": ["k", 5] }),
            &ctx,
        ).await.unwrap();
        std::env::remove_var(REDIS_URL_ENV);
        assert_eq!(out.is_error, Some(true));
        let body: Value = serde_json::from_str(&out.content).unwrap();
        assert_eq!(body["error_class"], "QuerySyntax");
    }

    #[tokio::test]
    async fn rejects_oversize_argv() {
        let _g = env_guard();
        std::env::set_var(REDIS_URL_ENV, "redis://127.0.0.1:1/");
        let ctx = ToolContext::for_workspace("/tmp");
        let args: Vec<Value> = (0..=REDIS_MAX_ARGV).map(|i| Value::String(format!("{i}"))).collect();
        let out = RedisQueryTool.execute(
            &serde_json::json!({ "command": "MSET", "args": args }),
            &ctx,
        ).await.unwrap();
        std::env::remove_var(REDIS_URL_ENV);
        assert_eq!(out.is_error, Some(true));
        let body: Value = serde_json::from_str(&out.content).unwrap();
        assert_eq!(body["error_class"], "QuerySyntax");
        assert!(body["message"].as_str().unwrap().contains("cap"));
    }

    #[tokio::test]
    async fn proxy_unreachable_surfaces_when_no_listener() {
        let _g = env_guard();
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let url = format!("redis://127.0.0.1:{}/", addr.port());
        std::env::set_var(REDIS_URL_ENV, &url);

        let sink = Arc::new(RecordingAuditSink::new());
        let ctx  = ctx_with_sink(sink.clone());
        let out  = RedisQueryTool.execute(
            &serde_json::json!({ "command": "PING", "timeout_secs": 2 }),
            &ctx,
        ).await.unwrap();
        std::env::remove_var(REDIS_URL_ENV);

        assert_eq!(out.is_error, Some(true));
        let body: Value = serde_json::from_str(&out.content).unwrap();
        let class = body["error_class"].as_str().unwrap();
        assert!(
            class == "ProxyUnreachable" || class == "Timeout",
            "expected ProxyUnreachable or Timeout; got body: {}", out.content,
        );
        let events = sink.events();
        match &events[0].outcome {
            ToolAuditOutcome::Err { .. } => {}
            other => panic!("expected Err audit outcome, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn timeout_surfaces_when_proxy_is_silent() {
        let _g = env_guard();
        use tokio::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let _accept = tokio::spawn(async move {
            loop {
                if let Ok((stream, _)) = listener.accept().await {
                    std::mem::forget(stream);
                }
            }
        });
        let url = format!("redis://127.0.0.1:{}/", addr.port());
        std::env::set_var(REDIS_URL_ENV, &url);

        let sink  = Arc::new(RecordingAuditSink::new());
        let ctx   = ctx_with_sink(sink.clone());
        let start = std::time::Instant::now();
        let out   = RedisQueryTool.execute(
            &serde_json::json!({ "command": "PING", "timeout_secs": 1 }),
            &ctx,
        ).await.unwrap();
        let elapsed = start.elapsed();
        std::env::remove_var(REDIS_URL_ENV);

        assert_eq!(out.is_error, Some(true));
        let body: Value = serde_json::from_str(&out.content).unwrap();
        assert_eq!(body["error_class"], "Timeout",
            "expected Timeout; got body: {}", out.content);
        assert!(elapsed < Duration::from_secs(4),
            "timeout took too long: {elapsed:?}");
    }
}

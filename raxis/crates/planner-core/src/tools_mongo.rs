//! `mongo_query` — structured MongoDB tool for the executor.
//!
//! Closes the executor tool-registry gap pinned by
//! `INV-EXEC-TOOL-REGISTRY-01`: every credential-proxied service the
//! kernel binds a listener for MUST be reachable via a structured
//! tool from inside the executor VM. The proxy on the host
//! (`raxis-credential-proxy-mongodb`) terminates the agent's
//! `mongodb://` connection on the loopback `127.0.0.1:<port>`
//! listener and performs the real upstream auth + TLS; the in-VM
//! client only speaks plaintext MongoDB wire to the proxy.
//!
//! ## Wire contract
//!
//! * URL: `MONGO_URL` env (the kernel session-spawn path stamps
//!   `mongodb://raxis@127.0.0.1:<port>/` from the credential-proxy
//!   manager).
//! * Driver: `mongodb::Client::with_uri_str(url)`. The proxy speaks
//!   plaintext on loopback; upstream TLS / mTLS is between proxy and
//!   real upstream.
//! * Operations: `find`, `insert_one`, `insert_many`, `update_one`,
//!   `update_many`, `delete_one`, `delete_many`, `count`, `aggregate`.
//! * Inputs are `serde_json::Value`s the tool transcodes to BSON
//!   `Document`s via `bson::to_document` / `bson::to_bson`. Top-level
//!   filters / updates / documents MUST be JSON objects (`Document`-
//!   shaped); arrays of documents only appear as
//!   `documents` / `pipeline`.
//! * Result: shape varies per operation (see [`MongoOpResult`] below).
//! * Cap: `RAXIS_TOOL_MONGO_MAX_DOCS` (default 1000). `find` and
//!   `aggregate` results are truncated AND `truncated: true` is set
//!   in the body when the cap is hit.
//! * Error shape: structured `{ "error_class": "...", "message": "..." }`
//!   with `error_class ∈ {ProxyUnreachable, AuthFailed, QuerySyntax,
//!   QueryRuntime, ResultTooLarge, Timeout, MissingEnv}`.
//!
//! ## Audit
//!
//! On every invocation the tool emits one `ToolAuditEvent` carrying
//! `tool="mongo_query"`, `sha256(canonical_envelope)`, `duration_ms`,
//! and the outcome shape. The canonical envelope is
//! `"<op>|<db>|<collection>"` with no payload bytes — the host-side
//! proxy emits the canonical command-shaped audit event with the
//! full command BSON hash when the wire frame reaches it; the two
//! events pair on inspection.
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

use bson::{Bson, Document};
use futures_util::stream::TryStreamExt;
use mongodb::error::{Error as MongoError, ErrorKind as MongoErrorKind};
use mongodb::Client;
use serde::Serialize;
use serde_json::Value;

use crate::tool_audit::{sha256_hex, ToolAuditEvent, ToolAuditSink, ToolErrorClass};
use crate::tools::{Tool, ToolContext, ToolError, ToolOutput};

/// Env var the kernel session-spawn path stamps with the loopback
/// `mongodb://raxis@127.0.0.1:<port>/` URL.
pub const MONGO_URL_ENV: &str = "MONGO_URL";

/// Cap-override env var for `find` / `aggregate` document counts.
pub const MONGO_MAX_DOCS_ENV: &str = "RAXIS_TOOL_MONGO_MAX_DOCS";

/// Default per-tool document cap when `RAXIS_TOOL_MONGO_MAX_DOCS`
/// is unset or malformed.
pub const DEFAULT_MONGO_MAX_DOCS: u64 = 1000;

/// Default wall-clock timeout for one `mongo_query` invocation.
pub const DEFAULT_MONGO_TIMEOUT: Duration = Duration::from_secs(30);

/// `mongo_query` tool. Stateless; one instance is shared across
/// every executor session.
pub struct MongoQueryTool;

#[async_trait::async_trait]
impl Tool for MongoQueryTool {
    fn name(&self) -> &'static str { "mongo_query" }

    fn description(&self) -> &'static str {
        "Execute a structured MongoDB operation against the credential-\
         proxied Mongo upstream bound to the `MONGO_URL` environment \
         variable. The `operation` argument selects the verb: `find`, \
         `insert_one`, `insert_many`, `update_one`, `update_many`, \
         `delete_one`, `delete_many`, `count`, `aggregate`. Filters / \
         updates / documents are passed as JSON objects (transcoded \
         to BSON inside the tool). `find` and `aggregate` return \
         `{documents, count, truncated}`; mutating ops return their \
         per-op result shape. Result document count is capped at \
         RAXIS_TOOL_MONGO_MAX_DOCS (default 1000). Errors surface as \
         `{error_class, message}` with classes ProxyUnreachable / \
         AuthFailed / QuerySyntax / QueryRuntime / ResultTooLarge / \
         Timeout / MissingEnv. Per-call timeout defaults to 30s; \
         override via `timeout_secs`. DO NOT pass a host or port; \
         the loopback proxy is the only ingress."
    }

    fn input_schema(&self) -> Value {
        serde_json::json!({
            "type":     "object",
            "required": ["database", "collection", "operation"],
            "properties": {
                "database":   {"type": "string", "minLength": 1},
                "collection": {"type": "string", "minLength": 1},
                "operation":  {
                    "type": "string",
                    "enum": [
                        "find", "insert_one", "insert_many",
                        "update_one", "update_many",
                        "delete_one", "delete_many",
                        "count", "aggregate"
                    ]
                },
                "filter":    {"type": "object"},
                "update":    {"type": "object"},
                "documents": {"type": "array", "items": {"type": "object"}},
                "pipeline":  {"type": "array", "items": {"type": "object"}},
                "limit":     {"type": "integer", "minimum": 1, "maximum": 10000},
                "timeout_secs": {"type": "integer", "minimum": 1, "maximum": 600}
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
        let envelope = canonical_envelope(&parsed);
        let sha      = sha256_hex(&envelope);

        let url = match env::var(MONGO_URL_ENV) {
            Ok(v) if !v.is_empty() => v,
            _ => {
                emit_err(ctx, sha, start, ToolErrorClass::MissingEnv);
                return Ok(structured_err(
                    ToolErrorClass::MissingEnv,
                    format!("env var `{MONGO_URL_ENV}` is unset or empty; the kernel \
                             session-spawn path stamps this from the credential-proxy \
                             manager — check the kernel logs for `CredentialProxyStarted`"),
                ));
            }
        };
        let max_docs = read_max_docs_env();
        let timeout  = parsed.timeout.unwrap_or(DEFAULT_MONGO_TIMEOUT);

        let op = run_op(url, parsed, max_docs);
        let result = match tokio::time::timeout(timeout, op).await {
            Ok(r)  => r,
            Err(_) => {
                emit_err(ctx, sha.clone(), start, ToolErrorClass::Timeout);
                return Ok(structured_err(
                    ToolErrorClass::Timeout,
                    format!("mongo_query exceeded {}s wall-clock timeout", timeout.as_secs()),
                ));
            }
        };
        match result {
            Ok(MongoOpResult { body, rows_returned, truncated }) => {
                emit_ok(ctx, sha, start, rows_returned, truncated);
                Ok(ToolOutput::ok(body.to_string()))
            }
            Err(MongoQueryError { class, message }) => {
                emit_err(ctx, sha, start, class.clone());
                Ok(structured_err(class, message))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Input parsing
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Op {
    Find,
    InsertOne,
    InsertMany,
    UpdateOne,
    UpdateMany,
    DeleteOne,
    DeleteMany,
    Count,
    Aggregate,
}

impl Op {
    fn parse(s: &str) -> Result<Self, String> {
        Ok(match s {
            "find"        => Self::Find,
            "insert_one"  => Self::InsertOne,
            "insert_many" => Self::InsertMany,
            "update_one"  => Self::UpdateOne,
            "update_many" => Self::UpdateMany,
            "delete_one"  => Self::DeleteOne,
            "delete_many" => Self::DeleteMany,
            "count"       => Self::Count,
            "aggregate"   => Self::Aggregate,
            other => return Err(format!(
                "unsupported `operation` {other:?}; allowed: find / insert_one / \
                 insert_many / update_one / update_many / delete_one / \
                 delete_many / count / aggregate"
            )),
        })
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Find        => "find",
            Self::InsertOne   => "insert_one",
            Self::InsertMany  => "insert_many",
            Self::UpdateOne   => "update_one",
            Self::UpdateMany  => "update_many",
            Self::DeleteOne   => "delete_one",
            Self::DeleteMany  => "delete_many",
            Self::Count       => "count",
            Self::Aggregate   => "aggregate",
        }
    }
}

#[derive(Debug)]
struct ParsedInput {
    database:   String,
    collection: String,
    op:         Op,
    filter:     Option<Document>,
    update:     Option<Document>,
    documents:  Vec<Document>,
    pipeline:   Vec<Document>,
    limit:      Option<u64>,
    timeout:    Option<Duration>,
}

fn parse_input(v: &Value) -> Result<ParsedInput, String> {
    let database = required_str(v, "database")?;
    let collection = required_str(v, "collection")?;
    if database.contains('/') || database.contains('\\') {
        return Err("`database` MUST NOT contain `/` or `\\` — pass a bare name".to_owned());
    }
    if collection.contains('/') || collection.contains('\\') {
        return Err("`collection` MUST NOT contain `/` or `\\` — pass a bare name".to_owned());
    }
    let op_str = required_str(v, "operation")?;
    let op     = Op::parse(&op_str)?;

    let filter   = optional_document(v, "filter")?;
    let update   = optional_document(v, "update")?;
    let documents = match v.get("documents") {
        Some(Value::Array(arr)) => arr
            .iter()
            .map(value_to_document)
            .collect::<Result<Vec<_>, _>>()?,
        Some(Value::Null) | None => Vec::new(),
        Some(_) => return Err("`documents` MUST be a JSON array of objects".to_owned()),
    };
    let pipeline = match v.get("pipeline") {
        Some(Value::Array(arr)) => arr
            .iter()
            .map(value_to_document)
            .collect::<Result<Vec<_>, _>>()?,
        Some(Value::Null) | None => Vec::new(),
        Some(_) => return Err("`pipeline` MUST be a JSON array of objects".to_owned()),
    };
    let limit = match v.get("limit") {
        Some(s) => {
            let n = s.as_u64().ok_or_else(|| {
                "`limit` MUST be a positive integer".to_owned()
            })?;
            if n == 0 || n > 10_000 {
                return Err("`limit` MUST be in [1, 10000]".to_owned());
            }
            Some(n)
        }
        None => None,
    };
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

    validate_op_args(op, filter.as_ref(), update.as_ref(), &documents, &pipeline)?;

    Ok(ParsedInput {
        database, collection, op, filter, update, documents, pipeline, limit, timeout,
    })
}

fn required_str(v: &Value, field: &str) -> Result<String, String> {
    let s = v
        .get(field)
        .and_then(|x| x.as_str())
        .ok_or_else(|| format!("missing or non-string `{field}`"))?;
    if s.is_empty() {
        return Err(format!("`{field}` MUST be a non-empty string"));
    }
    Ok(s.to_owned())
}

fn optional_document(v: &Value, field: &str) -> Result<Option<Document>, String> {
    match v.get(field) {
        Some(Value::Object(_)) => Ok(Some(value_to_document(v.get(field).unwrap())?)),
        Some(Value::Null) | None => Ok(None),
        Some(_) => Err(format!("`{field}` MUST be a JSON object")),
    }
}

fn value_to_document(v: &Value) -> Result<Document, String> {
    if !v.is_object() {
        return Err("expected JSON object".to_owned());
    }
    bson::serialize_to_document(v).map_err(|e| {
        format!("could not transcode JSON to BSON document: {e}")
    })
}

fn validate_op_args(
    op:        Op,
    filter:    Option<&Document>,
    update:    Option<&Document>,
    documents: &[Document],
    pipeline:  &[Document],
) -> Result<(), String> {
    match op {
        Op::Find | Op::Count | Op::DeleteOne | Op::DeleteMany => {
            // filter optional (default = empty doc); update / documents
            // / pipeline forbidden.
            if update.is_some() {
                return Err(format!("`update` is not valid for {}", op.as_str()));
            }
            if !documents.is_empty() {
                return Err(format!("`documents` is not valid for {}", op.as_str()));
            }
            if !pipeline.is_empty() {
                return Err(format!("`pipeline` is not valid for {}", op.as_str()));
            }
        }
        Op::InsertOne => {
            if documents.len() != 1 {
                return Err("`insert_one` requires exactly 1 entry in `documents`".to_owned());
            }
            if filter.is_some() || update.is_some() || !pipeline.is_empty() {
                return Err("`insert_one` accepts only `documents`".to_owned());
            }
        }
        Op::InsertMany => {
            if documents.is_empty() {
                return Err("`insert_many` requires at least 1 entry in `documents`".to_owned());
            }
            if filter.is_some() || update.is_some() || !pipeline.is_empty() {
                return Err("`insert_many` accepts only `documents`".to_owned());
            }
        }
        Op::UpdateOne | Op::UpdateMany => {
            if filter.is_none() {
                return Err(format!("`{}` requires `filter`", op.as_str()));
            }
            if update.is_none() {
                return Err(format!("`{}` requires `update`", op.as_str()));
            }
            if !documents.is_empty() || !pipeline.is_empty() {
                return Err(format!("`{}` accepts only `filter` + `update`", op.as_str()));
            }
        }
        Op::Aggregate => {
            if pipeline.is_empty() {
                return Err("`aggregate` requires a non-empty `pipeline`".to_owned());
            }
            if filter.is_some() || update.is_some() || !documents.is_empty() {
                return Err("`aggregate` accepts only `pipeline`".to_owned());
            }
        }
    }
    Ok(())
}

fn canonical_envelope(p: &ParsedInput) -> String {
    format!("{}|{}|{}", p.op.as_str(), p.database, p.collection)
}

// ---------------------------------------------------------------------------
// Op execution
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct MongoOpResult {
    body:          Value,
    rows_returned: u64,
    truncated:     bool,
}

#[derive(Debug)]
struct MongoQueryError {
    class:   ToolErrorClass,
    message: String,
}

async fn run_op(
    url:      String,
    parsed:   ParsedInput,
    max_docs: u64,
) -> Result<MongoOpResult, MongoQueryError> {
    let client = Client::with_uri_str(&url)
        .await
        .map_err(classify_connect_err)?;
    let db   = client.database(&parsed.database);
    let coll = db.collection::<Document>(&parsed.collection);

    match parsed.op {
        Op::Find => {
            let filter = parsed.filter.unwrap_or_default();
            let cap = parsed.limit.unwrap_or(max_docs).min(max_docs);
            // Ask the upstream for `cap + 1` so we can detect cap-hit
            // without enumerating the entire result set.
            let req_limit = cap.saturating_add(1) as i64;
            let mut cursor = coll
                .find(filter)
                .limit(req_limit)
                .await
                .map_err(classify_query_err)?;

            let mut docs = Vec::with_capacity(cap as usize);
            let mut truncated = false;
            while let Some(d) = cursor.try_next().await.map_err(classify_query_err)? {
                if docs.len() as u64 >= cap {
                    truncated = true;
                    break;
                }
                docs.push(bson_doc_to_json(d));
            }
            let count = docs.len() as u64;
            Ok(MongoOpResult {
                body: serde_json::json!({
                    "documents": docs,
                    "count":     count,
                    "truncated": truncated,
                }),
                rows_returned: count,
                truncated,
            })
        }
        Op::Count => {
            let filter = parsed.filter.unwrap_or_default();
            let n = coll
                .count_documents(filter)
                .await
                .map_err(classify_query_err)?;
            Ok(MongoOpResult {
                body: serde_json::json!({ "count": n }),
                rows_returned: n,
                truncated: false,
            })
        }
        Op::InsertOne => {
            let d = parsed.documents.into_iter().next().expect("validated");
            let res = coll.insert_one(d).await.map_err(classify_query_err)?;
            Ok(MongoOpResult {
                body: serde_json::json!({
                    "inserted_id": bson_to_json(&res.inserted_id),
                }),
                rows_returned: 1,
                truncated: false,
            })
        }
        Op::InsertMany => {
            let count = parsed.documents.len() as u64;
            let res = coll.insert_many(parsed.documents).await.map_err(classify_query_err)?;
            let mut ids = Vec::with_capacity(res.inserted_ids.len());
            // `inserted_ids` is HashMap<usize, Bson>; we emit in the
            // input order so the LLM can match each ID back to the
            // request slot.
            let mut sorted: Vec<_> = res.inserted_ids.iter().collect();
            sorted.sort_by_key(|(k, _)| *k);
            for (_, b) in sorted {
                ids.push(bson_to_json(b));
            }
            Ok(MongoOpResult {
                body: serde_json::json!({
                    "inserted_ids":   ids,
                    "inserted_count": count,
                }),
                rows_returned: count,
                truncated: false,
            })
        }
        Op::UpdateOne => {
            let filter = parsed.filter.expect("validated");
            let update = parsed.update.expect("validated");
            let res = coll.update_one(filter, update).await.map_err(classify_query_err)?;
            Ok(MongoOpResult {
                body: serde_json::json!({
                    "matched_count":  res.matched_count,
                    "modified_count": res.modified_count,
                    "upserted_id":    res.upserted_id.as_ref().map(bson_to_json),
                }),
                rows_returned: res.modified_count,
                truncated: false,
            })
        }
        Op::UpdateMany => {
            let filter = parsed.filter.expect("validated");
            let update = parsed.update.expect("validated");
            let res = coll.update_many(filter, update).await.map_err(classify_query_err)?;
            Ok(MongoOpResult {
                body: serde_json::json!({
                    "matched_count":  res.matched_count,
                    "modified_count": res.modified_count,
                    "upserted_id":    res.upserted_id.as_ref().map(bson_to_json),
                }),
                rows_returned: res.modified_count,
                truncated: false,
            })
        }
        Op::DeleteOne => {
            let filter = parsed.filter.unwrap_or_default();
            let res = coll.delete_one(filter).await.map_err(classify_query_err)?;
            Ok(MongoOpResult {
                body: serde_json::json!({ "deleted_count": res.deleted_count }),
                rows_returned: res.deleted_count,
                truncated: false,
            })
        }
        Op::DeleteMany => {
            let filter = parsed.filter.unwrap_or_default();
            let res = coll.delete_many(filter).await.map_err(classify_query_err)?;
            Ok(MongoOpResult {
                body: serde_json::json!({ "deleted_count": res.deleted_count }),
                rows_returned: res.deleted_count,
                truncated: false,
            })
        }
        Op::Aggregate => {
            let cap = parsed.limit.unwrap_or(max_docs).min(max_docs);
            let mut cursor = coll
                .aggregate(parsed.pipeline)
                .await
                .map_err(classify_query_err)?;
            let mut docs = Vec::with_capacity(cap as usize);
            let mut truncated = false;
            while let Some(d) = cursor.try_next().await.map_err(classify_query_err)? {
                if docs.len() as u64 >= cap {
                    truncated = true;
                    break;
                }
                docs.push(bson_doc_to_json(d));
            }
            let count = docs.len() as u64;
            Ok(MongoOpResult {
                body: serde_json::json!({
                    "documents": docs,
                    "count":     count,
                    "truncated": truncated,
                }),
                rows_returned: count,
                truncated,
            })
        }
    }
}

fn bson_doc_to_json(d: Document) -> Value {
    // Round-trip through serde_json::to_value via Bson::Document so
    // ObjectId / DateTime etc. surface as readable strings.
    bson_to_json(&Bson::Document(d))
}

fn bson_to_json(b: &Bson) -> Value {
    // `Bson`'s upstream `Into<serde_json::Value>` impl is the
    // canonical extended-JSON shape; we re-export it as `Value`.
    b.clone().into_relaxed_extjson()
}

// ---------------------------------------------------------------------------
// Error classification
// ---------------------------------------------------------------------------

fn classify_connect_err(err: MongoError) -> MongoQueryError {
    let msg   = err.to_string();
    let lower = msg.to_ascii_lowercase();
    let class = if is_proxy_unreachable(&lower) {
        ToolErrorClass::ProxyUnreachable
    } else if is_auth_failed(&err, &lower) {
        ToolErrorClass::AuthFailed
    } else if lower.contains("invalid uri") || lower.contains("invalid argument") {
        ToolErrorClass::QuerySyntax
    } else if lower.contains("timed out") || lower.contains("timeout") {
        ToolErrorClass::Timeout
    } else {
        ToolErrorClass::ProxyUnreachable
    };
    MongoQueryError { class, message: format!("mongo connect failed: {msg}") }
}

fn classify_query_err(err: MongoError) -> MongoQueryError {
    let msg   = err.to_string();
    let lower = msg.to_ascii_lowercase();
    // Surface explicit auth-failed regardless of where in the
    // lifecycle the failure surfaced.
    if is_auth_failed(&err, &lower) {
        return MongoQueryError {
            class:   ToolErrorClass::AuthFailed,
            message: format!("mongo auth failed: {msg}"),
        };
    }
    if is_proxy_unreachable(&lower) {
        return MongoQueryError {
            class:   ToolErrorClass::ProxyUnreachable,
            message: format!("mongo proxy unreachable: {msg}"),
        };
    }
    if lower.contains("timed out") || lower.contains("timeout") {
        return MongoQueryError {
            class:   ToolErrorClass::Timeout,
            message: format!("mongo operation timed out: {msg}"),
        };
    }
    // Best-effort syntax-vs-runtime discrimination based on the
    // upstream `ErrorKind`. Server-returned `Command` errors with
    // codes in the well-known "bad request" / "syntax" buckets are
    // surfaced as `QuerySyntax`; everything else server-side is
    // `QueryRuntime`. Connection / I/O kinds were handled above.
    if let MongoErrorKind::Command(ce) = err.kind.as_ref() {
        // Mongo command codes: 9 (FailedToParse), 14 (TypeMismatch),
        // 40415 (UnknownField), 51091 (BSONObjectTooLarge), 121
        // (DocumentValidationFailure), 16410 (BadValue), ...
        let syntax_codes = [9, 14, 16410, 40415, 51091, 121];
        if syntax_codes.contains(&ce.code) {
            return MongoQueryError {
                class:   ToolErrorClass::QuerySyntax,
                message: format!("mongo command rejected (code {}): {}", ce.code, msg),
            };
        }
        return MongoQueryError {
            class:   ToolErrorClass::QueryRuntime,
            message: format!("mongo command error (code {}): {}", ce.code, msg),
        };
    }
    MongoQueryError {
        class:   ToolErrorClass::QueryRuntime,
        message: format!("mongo operation failed: {msg}"),
    }
}

fn is_proxy_unreachable(lower: &str) -> bool {
    lower.contains("connection refused")
        || lower.contains("no such file or directory")
        || lower.contains("network is unreachable")
        || lower.contains("connection reset")
        || lower.contains("server selection error")
        || lower.contains("no available servers")
        || lower.contains("kind: connectionerror")
        || lower.contains("io error: connection")
}

fn is_auth_failed(err: &MongoError, lower: &str) -> bool {
    if lower.contains("authentication failed")
        || lower.contains("auth failed")
        || lower.contains("scram")
        || lower.contains("sasl")
    {
        return true;
    }
    // Auth-shaped command errors carry codes 18 (AuthenticationFailed)
    // and 13 (Unauthorized).
    if let MongoErrorKind::Command(ce) = err.kind.as_ref() {
        if matches!(ce.code, 18 | 13) {
            return true;
        }
    }
    false
}

// ---------------------------------------------------------------------------
// Misc helpers
// ---------------------------------------------------------------------------

fn read_max_docs_env() -> u64 {
    env::var(MONGO_MAX_DOCS_ENV)
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .filter(|n| *n > 0)
        .unwrap_or(DEFAULT_MONGO_MAX_DOCS)
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
    sha:        String,
    start:      Instant,
    row_count:  u64,
    truncated:  bool,
) {
    if let Some(sink) = ctx.tool_audit_sink.as_ref() {
        emit_event(sink, ToolAuditEvent::ok(
            "mongo_query",
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
            "mongo_query",
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
    fn schema_advertises_canonical_operations() {
        let t = MongoQueryTool;
        assert_eq!(t.name(), "mongo_query");
        let schema = t.input_schema();
        let ops    = &schema["properties"]["operation"]["enum"];
        let ops_v: Vec<&str> = ops
            .as_array().unwrap()
            .iter().map(|x| x.as_str().unwrap()).collect();
        for required in [
            "find", "insert_one", "insert_many",
            "update_one", "update_many",
            "delete_one", "delete_many",
            "count", "aggregate",
        ] {
            assert!(ops_v.contains(&required),
                "schema MUST advertise `{required}` op, got: {ops_v:?}");
        }
    }

    #[tokio::test]
    async fn missing_mongo_url_surfaces_missing_env_class() {
        let _g   = env_guard();
        let sink = Arc::new(RecordingAuditSink::new());
        let ctx  = ctx_with_sink(sink.clone());
        std::env::remove_var(MONGO_URL_ENV);
        let out = MongoQueryTool.execute(
            &serde_json::json!({
                "database": "d", "collection": "c", "operation": "count",
            }),
            &ctx,
        ).await.unwrap();
        assert_eq!(out.is_error, Some(true));
        let body: Value = serde_json::from_str(&out.content).unwrap();
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

    #[tokio::test]
    async fn empty_mongo_url_surfaces_missing_env_class() {
        let _g   = env_guard();
        let sink = Arc::new(RecordingAuditSink::new());
        let ctx  = ctx_with_sink(sink.clone());
        std::env::set_var(MONGO_URL_ENV, "");
        let out = MongoQueryTool.execute(
            &serde_json::json!({
                "database": "d", "collection": "c", "operation": "count",
            }),
            &ctx,
        ).await.unwrap();
        std::env::remove_var(MONGO_URL_ENV);
        assert_eq!(out.is_error, Some(true));
        let body: Value = serde_json::from_str(&out.content).unwrap();
        assert_eq!(body["error_class"], "MissingEnv");
    }

    #[tokio::test]
    async fn unsupported_operation_rejected_with_query_syntax() {
        let _g = env_guard();
        std::env::set_var(MONGO_URL_ENV, "mongodb://127.0.0.1:1/");
        let sink = Arc::new(RecordingAuditSink::new());
        let ctx  = ctx_with_sink(sink.clone());
        let out  = MongoQueryTool.execute(
            &serde_json::json!({
                "database":  "d",
                "collection": "c",
                "operation":  "drop_database",
            }),
            &ctx,
        ).await.unwrap();
        std::env::remove_var(MONGO_URL_ENV);
        assert_eq!(out.is_error, Some(true));
        let body: Value = serde_json::from_str(&out.content).unwrap();
        assert_eq!(body["error_class"], "QuerySyntax");
    }

    #[tokio::test]
    async fn insert_one_missing_documents_rejected_with_query_syntax() {
        let _g = env_guard();
        std::env::set_var(MONGO_URL_ENV, "mongodb://127.0.0.1:1/");
        let ctx = ToolContext::for_workspace("/tmp");
        let out = MongoQueryTool.execute(
            &serde_json::json!({
                "database":  "d",
                "collection": "c",
                "operation":  "insert_one",
            }),
            &ctx,
        ).await.unwrap();
        std::env::remove_var(MONGO_URL_ENV);
        assert_eq!(out.is_error, Some(true));
        let body: Value = serde_json::from_str(&out.content).unwrap();
        assert_eq!(body["error_class"], "QuerySyntax");
    }

    #[tokio::test]
    async fn update_one_requires_filter_and_update() {
        let _g = env_guard();
        std::env::set_var(MONGO_URL_ENV, "mongodb://127.0.0.1:1/");
        let ctx = ToolContext::for_workspace("/tmp");
        let out = MongoQueryTool.execute(
            &serde_json::json!({
                "database":  "d",
                "collection": "c",
                "operation":  "update_one",
                "filter":     {"_id": 1},
            }),
            &ctx,
        ).await.unwrap();
        std::env::remove_var(MONGO_URL_ENV);
        assert_eq!(out.is_error, Some(true));
        let body: Value = serde_json::from_str(&out.content).unwrap();
        assert_eq!(body["error_class"], "QuerySyntax");
        assert!(body["message"].as_str().unwrap().contains("update"));
    }

    #[tokio::test]
    async fn database_with_slash_rejected() {
        let _g = env_guard();
        std::env::set_var(MONGO_URL_ENV, "mongodb://127.0.0.1:1/");
        let ctx = ToolContext::for_workspace("/tmp");
        let out = MongoQueryTool.execute(
            &serde_json::json!({
                "database":  "../etc",
                "collection": "c",
                "operation":  "count",
            }),
            &ctx,
        ).await.unwrap();
        std::env::remove_var(MONGO_URL_ENV);
        assert_eq!(out.is_error, Some(true));
        let body: Value = serde_json::from_str(&out.content).unwrap();
        assert_eq!(body["error_class"], "QuerySyntax");
    }

    #[tokio::test]
    async fn aggregate_requires_pipeline() {
        let _g = env_guard();
        std::env::set_var(MONGO_URL_ENV, "mongodb://127.0.0.1:1/");
        let ctx = ToolContext::for_workspace("/tmp");
        let out = MongoQueryTool.execute(
            &serde_json::json!({
                "database":  "d",
                "collection": "c",
                "operation":  "aggregate",
            }),
            &ctx,
        ).await.unwrap();
        std::env::remove_var(MONGO_URL_ENV);
        assert_eq!(out.is_error, Some(true));
        let body: Value = serde_json::from_str(&out.content).unwrap();
        assert_eq!(body["error_class"], "QuerySyntax");
        assert!(body["message"].as_str().unwrap().contains("pipeline"));
    }

    #[tokio::test]
    async fn proxy_unreachable_surfaces_when_no_listener() {
        let _g = env_guard();
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let url = format!("mongodb://127.0.0.1:{}/?serverSelectionTimeoutMS=500&connectTimeoutMS=500", addr.port());
        std::env::set_var(MONGO_URL_ENV, &url);

        let sink = Arc::new(RecordingAuditSink::new());
        let ctx  = ctx_with_sink(sink.clone());
        let out  = MongoQueryTool.execute(
            &serde_json::json!({
                "database":  "d",
                "collection": "c",
                "operation":  "count",
                "timeout_secs": 5,
            }),
            &ctx,
        ).await.unwrap();
        std::env::remove_var(MONGO_URL_ENV);

        assert_eq!(out.is_error, Some(true));
        let body: Value = serde_json::from_str(&out.content).unwrap();
        let class = body["error_class"].as_str().unwrap();
        // Either ProxyUnreachable or Timeout is acceptable depending
        // on driver internals — the contract is "not a successful
        // op"; the LLM-visible discrimination is enough.
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

    #[test]
    fn read_max_docs_env_falls_back_to_default() {
        let _g = env_guard();
        std::env::remove_var(MONGO_MAX_DOCS_ENV);
        assert_eq!(read_max_docs_env(), 1000);
        std::env::set_var(MONGO_MAX_DOCS_ENV, "0");
        assert_eq!(read_max_docs_env(), 1000);
        std::env::set_var(MONGO_MAX_DOCS_ENV, "junk");
        assert_eq!(read_max_docs_env(), 1000);
        std::env::set_var(MONGO_MAX_DOCS_ENV, "42");
        assert_eq!(read_max_docs_env(), 42);
        std::env::remove_var(MONGO_MAX_DOCS_ENV);
    }

    #[test]
    fn canonical_envelope_is_op_db_collection() {
        let p = ParsedInput {
            database:   "store".into(),
            collection: "orders".into(),
            op:         Op::Find,
            filter:     None,
            update:     None,
            documents:  vec![],
            pipeline:   vec![],
            limit:      None,
            timeout:    None,
        };
        assert_eq!(canonical_envelope(&p), "find|store|orders");
    }
}

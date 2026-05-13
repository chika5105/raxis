//! `smtp_send` — structured SMTP-relay tool for the executor.
//!
//! Closes the executor tool-registry gap pinned by
//! `INV-EXEC-TOOL-REGISTRY-01`: every credential-proxied service the
//! kernel binds a listener for MUST be reachable via a structured
//! tool from inside the executor VM. The proxy on the host
//! (`raxis-credential-proxy-smtp`) terminates the agent's SMTP
//! connection on the loopback `127.0.0.1:<port>` listener and
//! handles upstream auth + STARTTLS / implicit TLS; the in-VM
//! client speaks plaintext SMTP to the proxy.
//!
//! ## Wire contract
//!
//! * URL: `SMTP_URL` env (the kernel session-spawn path stamps
//!   `smtp://127.0.0.1:<port>/` from the credential-proxy manager).
//! * Driver: `lettre::AsyncSmtpTransport::<Tokio1Executor>` built via
//!   `from_url` (plaintext) — the proxy speaks plaintext on loopback.
//! * Args: `from`, `to` (Vec), optional `cc` / `bcc`, `subject`,
//!   `body_text`, optional `body_html`, optional `attachments`
//!   (`{name, content_base64, mime_type}`).
//! * Result: `{ "message_id": "...", "accepted_recipients": [...] }`.
//! * Error shape: structured `{ "error_class": "...", "message": "..." }`
//!   with `error_class ∈ {ProxyUnreachable, AuthFailed, QuerySyntax,
//!   QueryRuntime, Timeout, MissingEnv}`.
//!
//! ## Audit
//!
//! On every invocation the tool emits one `ToolAuditEvent` carrying
//! `tool="smtp_send"`, `sha256(canonical_envelope)`, `duration_ms`,
//! and the outcome shape. The envelope is the canonical
//! `<from>|<to_count>|<subject>` triple — no recipient names, no
//! body bytes; the host-side proxy emits `SmtpMessageRelayed` with
//! the full recipient + subject + body-sha when the wire frame
//! reaches it; the two events pair on inspection.
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

use lettre::address::Address;
use lettre::message::header::ContentType;
use lettre::message::{Mailbox, MessageBuilder, MultiPart, SinglePart, Attachment};
use lettre::transport::smtp::AsyncSmtpTransport;
use lettre::{AsyncTransport, Tokio1Executor};
use serde::Serialize;
use serde_json::Value;

use crate::tool_audit::{sha256_hex, ToolAuditEvent, ToolAuditSink, ToolErrorClass};
use crate::tools::{Tool, ToolContext, ToolError, ToolOutput};

/// Env var the kernel session-spawn path stamps with the loopback
/// `smtp://127.0.0.1:<port>/` URL.
pub const SMTP_URL_ENV: &str = "SMTP_URL";

/// Default wall-clock timeout for one `smtp_send` invocation.
pub const DEFAULT_SMTP_TIMEOUT: Duration = Duration::from_secs(30);

/// Max recipients per call (envelope `RCPT TO:` count). Pinned
/// defensively so a runaway LLM cannot send a million-recipient
/// blast in one tool call.
pub const SMTP_MAX_RECIPIENTS: usize = 100;

/// Max attachments per call.
pub const SMTP_MAX_ATTACHMENTS: usize = 16;

/// `smtp_send` tool. Stateless; one instance is shared across every
/// executor session.
pub struct SmtpSendTool;

#[async_trait::async_trait]
impl Tool for SmtpSendTool {
    fn name(&self) -> &'static str { "smtp_send" }

    fn description(&self) -> &'static str {
        "Send one email via the credential-proxied SMTP upstream bound \
         to the `SMTP_URL` environment variable. The proxy on the host \
         handles upstream auth + STARTTLS. Required args: `from`, `to` \
         (array), `subject`, `body_text`. Optional: `cc` / `bcc` (each \
         arrays of addresses), `body_html` (multipart alternative will \
         be sent when both bodies are present), `attachments` (array \
         of `{name, content_base64, mime_type}` objects). Returns \
         `{message_id, accepted_recipients}`. Errors surface as \
         `{error_class, message}` with classes ProxyUnreachable / \
         AuthFailed / QuerySyntax / QueryRuntime / Timeout / MissingEnv. \
         Per-call timeout defaults to 30s; override via `timeout_secs`. \
         DO NOT pass a host or port; the loopback proxy is the only \
         ingress."
    }

    fn input_schema(&self) -> Value {
        serde_json::json!({
            "type":     "object",
            "required": ["from", "to", "subject", "body_text"],
            "properties": {
                "from":      {"type": "string", "minLength": 1},
                "to":        {"type": "array",  "items": {"type": "string"}, "minItems": 1},
                "cc":        {"type": "array",  "items": {"type": "string"}},
                "bcc":       {"type": "array",  "items": {"type": "string"}},
                "subject":   {"type": "string"},
                "body_text": {"type": "string"},
                "body_html": {"type": "string"},
                "attachments": {
                    "type":  "array",
                    "items": {
                        "type": "object",
                        "required": ["name", "content_base64", "mime_type"],
                        "properties": {
                            "name":           {"type": "string", "minLength": 1},
                            "content_base64": {"type": "string"},
                            "mime_type":      {"type": "string", "minLength": 1}
                        }
                    }
                },
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
        let sha = sha256_hex(canonical_envelope(&parsed));

        let url = match env::var(SMTP_URL_ENV) {
            Ok(v) if !v.is_empty() => v,
            _ => {
                emit_err(ctx, sha, start, ToolErrorClass::MissingEnv);
                return Ok(structured_err(
                    ToolErrorClass::MissingEnv,
                    format!("env var `{SMTP_URL_ENV}` is unset or empty; the kernel \
                             session-spawn path stamps this from the credential-proxy \
                             manager — check the kernel logs for `CredentialProxyStarted`"),
                ));
            }
        };
        let timeout = parsed.timeout.unwrap_or(DEFAULT_SMTP_TIMEOUT);
        let op = run_send(url, parsed);
        let result = match tokio::time::timeout(timeout, op).await {
            Ok(r)  => r,
            Err(_) => {
                emit_err(ctx, sha.clone(), start, ToolErrorClass::Timeout);
                return Ok(structured_err(
                    ToolErrorClass::Timeout,
                    format!("smtp_send exceeded {}s wall-clock timeout", timeout.as_secs()),
                ));
            }
        };
        match result {
            Ok(SmtpOk { message_id, accepted_recipients }) => {
                emit_ok(ctx, sha, start, accepted_recipients.len() as u64, false);
                let body = serde_json::json!({
                    "message_id":          message_id,
                    "accepted_recipients": accepted_recipients,
                });
                Ok(ToolOutput::ok(body.to_string()))
            }
            Err(SmtpQueryError { class, message }) => {
                emit_err(ctx, sha, start, class.clone());
                Ok(structured_err(class, message))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Input parsing
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct ParsedAttachment {
    name:      String,
    mime_type: String,
    body:      Vec<u8>,
}

#[derive(Debug)]
struct ParsedInput {
    from:        Mailbox,
    to:          Vec<Mailbox>,
    cc:          Vec<Mailbox>,
    bcc:         Vec<Mailbox>,
    subject:     String,
    body_text:   String,
    body_html:   Option<String>,
    attachments: Vec<ParsedAttachment>,
    timeout:     Option<Duration>,
}

fn parse_input(v: &Value) -> Result<ParsedInput, String> {
    let from_str = required_str(v, "from")?;
    let from     = parse_mailbox(&from_str).map_err(|e| format!("`from`: {e}"))?;

    let to_strs = required_str_array(v, "to")?;
    if to_strs.is_empty() {
        return Err("`to` MUST contain at least one address".to_owned());
    }
    let to = parse_mailbox_list(&to_strs, "to")?;

    let cc  = parse_optional_mailbox_list(v, "cc")?;
    let bcc = parse_optional_mailbox_list(v, "bcc")?;

    let total = to.len() + cc.len() + bcc.len();
    if total > SMTP_MAX_RECIPIENTS {
        return Err(format!(
            "{total} recipients exceeds the per-call cap of {SMTP_MAX_RECIPIENTS}; \
             split the send into multiple smtp_send calls"
        ));
    }

    let subject = v
        .get("subject")
        .and_then(|s| s.as_str())
        .ok_or_else(|| "missing or non-string `subject`".to_owned())?
        .to_owned();

    let body_text = v
        .get("body_text")
        .and_then(|s| s.as_str())
        .ok_or_else(|| "missing or non-string `body_text`".to_owned())?
        .to_owned();

    let body_html = v.get("body_html").and_then(|s| s.as_str()).map(str::to_owned);

    let attachments = parse_attachments(v)?;

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

    Ok(ParsedInput {
        from, to, cc, bcc, subject, body_text, body_html, attachments, timeout,
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

fn required_str_array(v: &Value, field: &str) -> Result<Vec<String>, String> {
    let arr = v
        .get(field)
        .and_then(|x| x.as_array())
        .ok_or_else(|| format!("missing or non-array `{field}`"))?;
    arr.iter()
        .enumerate()
        .map(|(i, x)| {
            x.as_str()
                .map(str::to_owned)
                .ok_or_else(|| format!("`{field}`[{i}] MUST be a string"))
        })
        .collect()
}

fn parse_optional_mailbox_list(v: &Value, field: &str) -> Result<Vec<Mailbox>, String> {
    match v.get(field) {
        Some(Value::Array(arr)) => {
            let strs: Vec<String> = arr
                .iter()
                .enumerate()
                .map(|(i, x)| {
                    x.as_str()
                        .map(str::to_owned)
                        .ok_or_else(|| format!("`{field}`[{i}] MUST be a string"))
                })
                .collect::<Result<Vec<_>, _>>()?;
            parse_mailbox_list(&strs, field)
        }
        Some(Value::Null) | None => Ok(Vec::new()),
        Some(_) => Err(format!("`{field}` MUST be a JSON array of strings")),
    }
}

fn parse_mailbox_list(strs: &[String], field: &str) -> Result<Vec<Mailbox>, String> {
    strs.iter()
        .enumerate()
        .map(|(i, s)| {
            parse_mailbox(s).map_err(|e| format!("`{field}`[{i}]: {e}"))
        })
        .collect()
}

fn parse_mailbox(raw: &str) -> Result<Mailbox, String> {
    // Two acceptable shapes:
    //   - bare `user@host`
    //   - display-name form `"Alice" <alice@host>` (lettre parses both)
    raw.parse::<Mailbox>()
        .or_else(|_| {
            raw.parse::<Address>()
                .map(|a| Mailbox::new(None, a))
        })
        .map_err(|e| format!("{raw:?} is not a valid mailbox: {e}"))
}

fn parse_attachments(v: &Value) -> Result<Vec<ParsedAttachment>, String> {
    let arr = match v.get("attachments") {
        Some(Value::Array(a)) => a,
        Some(Value::Null) | None => return Ok(Vec::new()),
        Some(_) => return Err("`attachments` MUST be a JSON array of objects".to_owned()),
    };
    if arr.len() > SMTP_MAX_ATTACHMENTS {
        return Err(format!(
            "{} attachments exceeds the per-call cap of {SMTP_MAX_ATTACHMENTS}",
            arr.len()
        ));
    }
    let mut out = Vec::with_capacity(arr.len());
    for (i, a) in arr.iter().enumerate() {
        let obj = a.as_object().ok_or_else(|| {
            format!("`attachments`[{i}] MUST be a JSON object")
        })?;
        let name = obj
            .get("name")
            .and_then(|x| x.as_str())
            .ok_or_else(|| format!("`attachments`[{i}].name MUST be a non-empty string"))?
            .to_owned();
        if name.is_empty() {
            return Err(format!("`attachments`[{i}].name MUST be a non-empty string"));
        }
        let mime_type = obj
            .get("mime_type")
            .and_then(|x| x.as_str())
            .ok_or_else(|| format!("`attachments`[{i}].mime_type MUST be a non-empty string"))?
            .to_owned();
        if mime_type.is_empty() {
            return Err(format!("`attachments`[{i}].mime_type MUST be a non-empty string"));
        }
        let b64 = obj
            .get("content_base64")
            .and_then(|x| x.as_str())
            .ok_or_else(|| format!("`attachments`[{i}].content_base64 MUST be a string"))?;
        use base64::Engine;
        let body = base64::engine::general_purpose::STANDARD
            .decode(b64)
            .map_err(|e| format!("`attachments`[{i}].content_base64 is not valid base64: {e}"))?;
        out.push(ParsedAttachment { name, mime_type, body });
    }
    Ok(out)
}

fn canonical_envelope(p: &ParsedInput) -> String {
    format!("{}|{}|{}", p.from, p.to.len() + p.cc.len() + p.bcc.len(), p.subject)
}

/// Parse a `smtp://[user[:pass]@]host[:port][/[?query]]` URL into a
/// `(host, port)` pair. Custom-built because lettre's `from_url` is
/// gated on TLS features we deliberately do NOT enable (the proxy
/// IS the TLS termination boundary; the in-VM client speaks
/// plaintext on loopback).
fn parse_smtp_url(url: &str) -> Result<(String, u16), String> {
    let rest = url
        .strip_prefix("smtp://")
        .ok_or_else(|| "SMTP_URL MUST start with `smtp://`".to_owned())?;
    // Strip optional `user[:pass]@`. We do NOT honor the password —
    // the proxy reads its credential from the host-side stash; the
    // userinfo arm is accepted only because the substrate may stamp
    // a `raxis@` literal for symmetry with the other URL envs.
    let host_and_rest = match rest.rfind('@') {
        Some(i) => &rest[i + 1..],
        None    => rest,
    };
    // Strip optional `/path` and `?query`.
    let host_port_end = host_and_rest
        .find(|c: char| c == '/' || c == '?')
        .unwrap_or(host_and_rest.len());
    let host_port = &host_and_rest[..host_port_end];
    if host_port.is_empty() {
        return Err("SMTP_URL host is empty".to_owned());
    }
    let (host, port) = match host_port.rsplit_once(':') {
        Some((h, p)) => {
            let p_num: u16 = p
                .parse()
                .map_err(|_| format!("SMTP_URL port {p:?} is not a u16"))?;
            (h.to_owned(), p_num)
        }
        None => (host_port.to_owned(), 25),
    };
    if host.is_empty() {
        return Err("SMTP_URL host is empty".to_owned());
    }
    Ok((host, port))
}

// ---------------------------------------------------------------------------
// Send execution
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct SmtpOk {
    message_id:          Option<String>,
    accepted_recipients: Vec<String>,
}

#[derive(Debug)]
struct SmtpQueryError {
    class:   ToolErrorClass,
    message: String,
}

async fn run_send(url: String, parsed: ParsedInput) -> Result<SmtpOk, SmtpQueryError> {
    let (host, port) = parse_smtp_url(&url).map_err(|e| SmtpQueryError {
        class:   ToolErrorClass::QuerySyntax,
        message: format!("SMTP_URL `{url}` is not a valid SMTP URL: {e}"),
    })?;
    // `builder_dangerous` is the lettre idiom for plaintext SMTP —
    // intentional here: the loopback proxy speaks plaintext and
    // handles upstream STARTTLS / implicit TLS itself per
    // `credential-proxy.md §14.3`. We are NOT bypassing operator
    // TLS policy; the proxy IS the TLS termination boundary.
    let transport: AsyncSmtpTransport<Tokio1Executor> =
        AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(host)
            .port(port)
            .build();

    let to_strs: Vec<String> = parsed.to.iter().map(|m| m.email.to_string()).collect();
    let cc_strs: Vec<String> = parsed.cc.iter().map(|m| m.email.to_string()).collect();

    let mut builder: MessageBuilder = MessageBuilder::new()
        .from(parsed.from)
        .subject(parsed.subject.clone());
    for m in parsed.to {
        builder = builder.to(m);
    }
    for m in parsed.cc {
        builder = builder.cc(m);
    }
    for m in parsed.bcc {
        builder = builder.bcc(m);
    }

    let message = build_message_body(builder, &parsed.body_text, parsed.body_html.as_deref(), &parsed.attachments)
        .map_err(|e| SmtpQueryError {
            class:   ToolErrorClass::QuerySyntax,
            message: format!("could not build message body: {e}"),
        })?;
    let message_id_hdr = message
        .headers()
        .get_raw("Message-ID")
        .map(|s| s.to_string());

    let _resp = transport
        .send(message)
        .await
        .map_err(classify_send_err)?;

    // lettre's smtp response doesn't expose the per-RCPT accept list
    // explicitly; the proxy will have surfaced any partial-failure
    // response as an `Err` here. If we got Ok the entire To+Cc list
    // was accepted.
    let mut accepted = to_strs;
    accepted.extend(cc_strs);
    Ok(SmtpOk {
        message_id:          message_id_hdr,
        accepted_recipients: accepted,
    })
}

fn build_message_body(
    builder:     MessageBuilder,
    body_text:   &str,
    body_html:   Option<&str>,
    attachments: &[ParsedAttachment],
) -> Result<lettre::Message, String> {
    let text_part = SinglePart::builder()
        .header(ContentType::TEXT_PLAIN)
        .body(body_text.to_owned());

    let body_part: MultiPart = match (body_html, attachments.is_empty()) {
        (Some(html), true) => {
            // text + html alternative, no attachments
            MultiPart::alternative()
                .singlepart(text_part)
                .singlepart(
                    SinglePart::builder()
                        .header(ContentType::TEXT_HTML)
                        .body(html.to_owned()),
                )
        }
        (Some(html), false) => {
            // mixed: alternative(text,html) + attachments
            let alt = MultiPart::alternative()
                .singlepart(text_part)
                .singlepart(
                    SinglePart::builder()
                        .header(ContentType::TEXT_HTML)
                        .body(html.to_owned()),
                );
            let mut mixed = MultiPart::mixed().multipart(alt);
            for a in attachments {
                mixed = mixed.singlepart(attachment_part(a)?);
            }
            mixed
        }
        (None, true) => {
            // text only, no attachments → still wrap as a degenerate
            // mixed multipart for shape consistency with the html /
            // attachments branches. (lettre's `singlepart` builder
            // would also work; the mixed envelope is benign.)
            MultiPart::mixed().singlepart(text_part)
        }
        (None, false) => {
            // mixed: text + attachments
            let mut mixed = MultiPart::mixed().singlepart(text_part);
            for a in attachments {
                mixed = mixed.singlepart(attachment_part(a)?);
            }
            mixed
        }
    };

    builder
        .multipart(body_part)
        .map_err(|e| format!("lettre rejected message body: {e}"))
}

fn attachment_part(a: &ParsedAttachment) -> Result<SinglePart, String> {
    let ct = a.mime_type.parse::<ContentType>().map_err(|e| {
        format!("attachment `{}`: mime_type {:?} rejected: {e}", a.name, a.mime_type)
    })?;
    Ok(Attachment::new(a.name.clone()).body(a.body.clone(), ct))
}

// ---------------------------------------------------------------------------
// Error classification
// ---------------------------------------------------------------------------

fn classify_send_err(err: lettre::transport::smtp::Error) -> SmtpQueryError {
    let msg   = err.to_string();
    let lower = msg.to_ascii_lowercase();

    if err.is_permanent() && (
        lower.contains("auth")
            || lower.contains("login")
            || lower.contains("credential")
    ) {
        return SmtpQueryError {
            class:   ToolErrorClass::AuthFailed,
            message: format!("smtp auth failed: {msg}"),
        };
    }
    if lower.contains("connection refused")
        || lower.contains("no such file or directory")
        || lower.contains("network is unreachable")
        || lower.contains("connection reset")
        || (err.is_response() && lower.contains("421"))
    {
        return SmtpQueryError {
            class:   ToolErrorClass::ProxyUnreachable,
            message: format!("smtp proxy unreachable: {msg}"),
        };
    }
    if lower.contains("timed out") || lower.contains("timeout") || err.is_timeout() {
        return SmtpQueryError {
            class:   ToolErrorClass::Timeout,
            message: format!("smtp operation timed out: {msg}"),
        };
    }
    // 5xx permanent → caller-fixable problem (bad address, body too
    // large, content rejected). 4xx transient → runtime.
    if err.is_permanent() {
        return SmtpQueryError {
            class:   ToolErrorClass::QuerySyntax,
            message: format!("smtp rejected the message: {msg}"),
        };
    }
    SmtpQueryError {
        class:   ToolErrorClass::QueryRuntime,
        message: format!("smtp runtime error: {msg}"),
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
            "smtp_send",
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
            "smtp_send",
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

    fn happy_input() -> Value {
        serde_json::json!({
            "from":      "alice@example.com",
            "to":        ["bob@example.com"],
            "subject":   "hi",
            "body_text": "hello bob",
        })
    }

    #[test]
    fn schema_has_required_fields() {
        let t = SmtpSendTool;
        assert_eq!(t.name(), "smtp_send");
        let schema = t.input_schema();
        let req: Vec<&str> = schema["required"]
            .as_array().unwrap()
            .iter().map(|x| x.as_str().unwrap()).collect();
        for r in ["from", "to", "subject", "body_text"] {
            assert!(req.contains(&r), "schema MUST require `{r}`, got {req:?}");
        }
    }

    #[tokio::test]
    async fn missing_smtp_url_surfaces_missing_env_class() {
        let _g   = env_guard();
        let sink = Arc::new(RecordingAuditSink::new());
        let ctx  = ctx_with_sink(sink.clone());
        std::env::remove_var(SMTP_URL_ENV);
        let out = SmtpSendTool.execute(&happy_input(), &ctx).await.unwrap();
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
    async fn empty_smtp_url_surfaces_missing_env_class() {
        let _g   = env_guard();
        let sink = Arc::new(RecordingAuditSink::new());
        let ctx  = ctx_with_sink(sink.clone());
        std::env::set_var(SMTP_URL_ENV, "");
        let out = SmtpSendTool.execute(&happy_input(), &ctx).await.unwrap();
        std::env::remove_var(SMTP_URL_ENV);
        assert_eq!(out.is_error, Some(true));
        let body: Value = serde_json::from_str(&out.content).unwrap();
        assert_eq!(body["error_class"], "MissingEnv");
    }

    #[tokio::test]
    async fn rejects_empty_to_list() {
        let _g = env_guard();
        std::env::set_var(SMTP_URL_ENV, "smtp://127.0.0.1:1/");
        let ctx = ToolContext::for_workspace("/tmp");
        let out = SmtpSendTool.execute(
            &serde_json::json!({
                "from":      "alice@example.com",
                "to":        [],
                "subject":   "hi",
                "body_text": "hello",
            }),
            &ctx,
        ).await.unwrap();
        std::env::remove_var(SMTP_URL_ENV);
        assert_eq!(out.is_error, Some(true));
        let body: Value = serde_json::from_str(&out.content).unwrap();
        assert_eq!(body["error_class"], "QuerySyntax");
    }

    #[tokio::test]
    async fn rejects_invalid_from_address() {
        let _g = env_guard();
        std::env::set_var(SMTP_URL_ENV, "smtp://127.0.0.1:1/");
        let ctx = ToolContext::for_workspace("/tmp");
        let out = SmtpSendTool.execute(
            &serde_json::json!({
                "from":      "not-an-email",
                "to":        ["bob@example.com"],
                "subject":   "hi",
                "body_text": "hello",
            }),
            &ctx,
        ).await.unwrap();
        std::env::remove_var(SMTP_URL_ENV);
        assert_eq!(out.is_error, Some(true));
        let body: Value = serde_json::from_str(&out.content).unwrap();
        assert_eq!(body["error_class"], "QuerySyntax");
    }

    #[tokio::test]
    async fn rejects_oversize_recipient_count() {
        let _g = env_guard();
        std::env::set_var(SMTP_URL_ENV, "smtp://127.0.0.1:1/");
        let ctx = ToolContext::for_workspace("/tmp");
        let to: Vec<Value> = (0..=SMTP_MAX_RECIPIENTS)
            .map(|i| Value::String(format!("user{i}@example.com")))
            .collect();
        let out = SmtpSendTool.execute(
            &serde_json::json!({
                "from":      "alice@example.com",
                "to":        to,
                "subject":   "hi",
                "body_text": "hello",
            }),
            &ctx,
        ).await.unwrap();
        std::env::remove_var(SMTP_URL_ENV);
        assert_eq!(out.is_error, Some(true));
        let body: Value = serde_json::from_str(&out.content).unwrap();
        assert_eq!(body["error_class"], "QuerySyntax");
        assert!(body["message"].as_str().unwrap().contains("cap"));
    }

    #[tokio::test]
    async fn rejects_malformed_attachment_base64() {
        let _g = env_guard();
        std::env::set_var(SMTP_URL_ENV, "smtp://127.0.0.1:1/");
        let ctx = ToolContext::for_workspace("/tmp");
        let out = SmtpSendTool.execute(
            &serde_json::json!({
                "from":      "alice@example.com",
                "to":        ["bob@example.com"],
                "subject":   "hi",
                "body_text": "hello",
                "attachments": [{
                    "name":           "x.txt",
                    "content_base64": "not!base64!",
                    "mime_type":      "text/plain",
                }],
            }),
            &ctx,
        ).await.unwrap();
        std::env::remove_var(SMTP_URL_ENV);
        assert_eq!(out.is_error, Some(true));
        let body: Value = serde_json::from_str(&out.content).unwrap();
        assert_eq!(body["error_class"], "QuerySyntax");
    }

    #[tokio::test]
    async fn proxy_unreachable_surfaces_when_no_listener() {
        let _g = env_guard();
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let url = format!("smtp://127.0.0.1:{}/", addr.port());
        std::env::set_var(SMTP_URL_ENV, &url);

        let sink = Arc::new(RecordingAuditSink::new());
        let ctx  = ctx_with_sink(sink.clone());
        let out  = SmtpSendTool.execute(
            &serde_json::json!({
                "from":         "alice@example.com",
                "to":           ["bob@example.com"],
                "subject":      "hi",
                "body_text":    "hello",
                "timeout_secs": 3,
            }),
            &ctx,
        ).await.unwrap();
        std::env::remove_var(SMTP_URL_ENV);

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

    #[test]
    fn canonical_envelope_omits_recipients_and_body() {
        let p = ParsedInput {
            from:        "alice@example.com".parse().unwrap(),
            to:          vec!["bob@example.com".parse().unwrap()],
            cc:          vec![],
            bcc:         vec![],
            subject:     "hi".into(),
            body_text:   "secret-payload".into(),
            body_html:   None,
            attachments: vec![],
            timeout:     None,
        };
        let env = canonical_envelope(&p);
        // Envelope MUST NOT carry the body. Subject is operator-
        // visible by V2 audit contract so it stays.
        assert!(!env.contains("secret-payload"),
            "canonical envelope MUST NOT carry body bytes, got: {env}");
        assert!(env.contains("alice@example.com"),
            "envelope MUST identify the sender, got: {env}");
        assert!(env.contains("hi"),
            "envelope MUST carry the subject, got: {env}");
    }
}

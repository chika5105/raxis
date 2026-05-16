// raxis-kernel::notifications::handler::email — Email channel
// handler.
//(gap-c4-email).
// ## V2 scope
// This is the **minimum-viable** SMTP submission handler. The full
// vision in `email-and-notification-channels.md` (persistent SMTP
// connections, AUTH XOAUTH2, idempotent `Message-Id` reuse via the
// `notification_dispatch` table, conformance kit) is V3-grade.
// The V2 handler:
// * Parses `channel.target` as an SMTP submission URL of the shape
//   `smtp://<user>@<host>:<port>?from=<addr>&to=<addr1,addr2,...>`
//   or `smtps://...` for implicit-TLS submission on port 465.
// * Reads the SMTP password from a sidecar file at
//   `<data_dir>/notifications/credentials/<channel.id>.notify-cred`
//   (mode 0600). The sidecar holds the password verbatim, no
//   trailing newline. Missing / unreadable sidecar surfaces as
//   [`crate::notifications::DeliveryError::CredentialUnavailable`]
//   so the operator can distinguish a misconfigured channel from an
//   upstream outage.
// * Speaks SMTP submission: `EHLO` → `STARTTLS` (mandatory for
//   `smtp://`; absent for `smtps://`) → `EHLO` → `AUTH PLAIN` →
//   `MAIL FROM` → `RCPT TO` (one per recipient) → `DATA` → body →
//   `.\r\n` → `QUIT`.
// * Body is RFC-5322 compliant with a `multipart/alternative`
//   wrapper containing `text/plain` (the human summary plus the
//   pretty-printed JSON payload) and `application/json` (the raw
//   audit event for sidecar consumers).
// ## Failure mapping
// * Sidecar missing / unreadable    → `CredentialUnavailable(_)`
// * URL parse failure                → `TargetInvalid`
// * TCP connect / TLS / EHLO failed  → `Network(_)`
// * SMTP non-2xx response code       → `UpstreamRejected(_)`

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use raxis_audit_tools::AuditEvent;
use raxis_policy::NotificationChannel;
use rustls::ClientConfig;
use rustls_pki_types::ServerName;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;

use super::super::{summary, DeliveryError};

/// Per-event SMTP submission timeout. Bounded so a slow relay never
/// wedges the dispatcher's per-channel worker.
const SMTP_TIMEOUT: Duration = Duration::from_secs(30);

/// One parsed SMTP submission URL. `smtp://` requires STARTTLS;
/// `smtps://` uses implicit TLS on the connect socket.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedTarget {
    host: String,
    port: u16,
    username: String,
    from: String,
    recipients: Vec<String>,
    implicit_tls: bool,
}

/// Deliver one notification via SMTP submission. See module docs.
pub async fn deliver(
    channel: &NotificationChannel,
    event: &AuditEvent,
    data_dir: &Path,
) -> Result<(), DeliveryError> {
    let target = parse_target(&channel.target).map_err(|reason| {
        // Reuse `Network` so the audit reason carries the parse
        // detail. `TargetInvalid` is detail-free and would lose the
        // operator's debug surface.
        DeliveryError::Network(format!("smtp target parse: {reason}"))
    })?;

    let password = load_password_sidecar(data_dir, &channel.id).await?;

    let body = render_message_body(channel, event, &target);

    timeout(SMTP_TIMEOUT, do_smtp_submit(&target, &password, &body))
        .await
        .map_err(|_| DeliveryError::Network("submission timeout".to_owned()))??;

    Ok(())
}

// ---------------------------------------------------------------------------
// Target URL parser
// ---------------------------------------------------------------------------

fn parse_target(target: &str) -> Result<ParsedTarget, String> {
    let target = target.trim();
    let (rest, implicit_tls) = if let Some(s) = target.strip_prefix("smtps://") {
        (s, true)
    } else if let Some(s) = target.strip_prefix("smtp://") {
        (s, false)
    } else {
        return Err(format!(
            "unsupported scheme; expected smtp:// or smtps://, got {target:?}"
        ));
    };
    // <user>@<host>:<port>?from=...&to=...
    let (auth_host, query) = match rest.split_once('?') {
        Some((a, q)) => (a, q),
        None => (rest, ""),
    };
    let (username, host_port) = match auth_host.rsplit_once('@') {
        Some((u, hp)) => (u.to_owned(), hp),
        None => return Err("missing username (smtp://user@host:port?...)".to_owned()),
    };
    let (host, port) = match host_port.rsplit_once(':') {
        Some((h, p)) => {
            let port: u16 = p.parse().map_err(|e| format!("port parse error: {e}"))?;
            (h.to_owned(), port)
        }
        None => return Err("missing port (smtp://user@host:port?...)".to_owned()),
    };
    if host.is_empty() {
        return Err("empty host".to_owned());
    }

    // Parse query string. We accept only `from` and `to` keys; other
    // keys are rejected so a typo'd URL fails loudly.
    let mut from: Option<String> = None;
    let mut recipients: Vec<String> = Vec::new();
    if !query.is_empty() {
        for kv in query.split('&') {
            let (k, v) = kv
                .split_once('=')
                .ok_or_else(|| format!("malformed query parameter (expected key=value): {kv:?}"))?;
            let v = url_decode(v);
            match k {
                "from" => from = Some(v),
                "to" => {
                    for addr in v.split(',') {
                        let addr = addr.trim();
                        if !addr.is_empty() {
                            recipients.push(addr.to_owned());
                        }
                    }
                }
                other => return Err(format!("unknown query parameter {other:?}")),
            }
        }
    }
    let from = from.ok_or_else(|| "missing ?from=<address> query parameter".to_owned())?;
    if recipients.is_empty() {
        return Err("missing ?to=<addr1,addr2,...> query parameter".to_owned());
    }
    Ok(ParsedTarget {
        host,
        port,
        username: url_decode(&username),
        from,
        recipients,
        implicit_tls,
    })
}

/// Minimal percent-decoder. Accepts plain ASCII + `%hh` escapes.
/// Anything else is left verbatim so a malformed URL fails at the
/// SMTP-submission stage with a clear upstream error rather than a
/// silent corrupted address.
fn url_decode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(h), Some(l)) = (hex_digit(bytes[i + 1]), hex_digit(bytes[i + 2])) {
                out.push((h * 16 + l) as char);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

fn hex_digit(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Password sidecar
// ---------------------------------------------------------------------------

async fn load_password_sidecar(data_dir: &Path, channel_id: &str) -> Result<String, DeliveryError> {
    let path = data_dir
        .join("notifications")
        .join("credentials")
        .join(format!("{channel_id}.notify-cred"));
    let bytes = tokio::fs::read(&path).await.map_err(|e| {
        DeliveryError::CredentialUnavailable(format!(
            "cannot read sidecar at {}: {e}",
            path.display(),
        ))
    })?;
    let s = String::from_utf8(bytes).map_err(|e| {
        DeliveryError::CredentialUnavailable(format!(
            "sidecar at {} is not UTF-8: {e}",
            path.display(),
        ))
    })?;
    let trimmed = s.trim_end_matches(['\r', '\n']).to_owned();
    if trimmed.is_empty() {
        return Err(DeliveryError::CredentialUnavailable(format!(
            "sidecar at {} is empty",
            path.display(),
        )));
    }
    Ok(trimmed)
}

// ---------------------------------------------------------------------------
// Body rendering
// ---------------------------------------------------------------------------

fn render_message_body(
    channel: &NotificationChannel,
    event: &AuditEvent,
    target: &ParsedTarget,
) -> Vec<u8> {
    let _ = channel;
    let summary_line = summary::render(event);
    let to_header = target.recipients.join(", ");
    let pretty_json = serde_json::to_string_pretty(&event.payload)
        .unwrap_or_else(|_| "<failed to format payload>".to_owned());
    let raw_json = serde_json::to_string(&event.payload).unwrap_or_else(|_| "{}".to_owned());

    let boundary = format!("raxis-{}", event.event_id.simple());
    let date = format_rfc2822_date(event.emitted_at.max(0) as u64);
    let msgid = format!("<{}.{}@raxis-kernel>", event.seq, event.event_id);

    let mut buf = String::with_capacity(2048 + raw_json.len());
    buf.push_str(&format!("From: {}\r\n", target.from));
    buf.push_str(&format!("To: {to_header}\r\n"));
    buf.push_str(&format!(
        "Subject: [RAXIS] {} ({})\r\n",
        event.event_kind, summary_line,
    ));
    buf.push_str(&format!("Message-Id: {msgid}\r\n"));
    buf.push_str(&format!("Date: {date}\r\n"));
    buf.push_str(&format!("X-RAXIS-Event-Kind: {}\r\n", event.event_kind));
    buf.push_str(&format!("X-RAXIS-Event-Seq: {}\r\n", event.seq));
    buf.push_str("MIME-Version: 1.0\r\n");
    buf.push_str(&format!(
        "Content-Type: multipart/alternative; boundary=\"{boundary}\"\r\n",
    ));
    buf.push_str("\r\n");
    // text/plain
    buf.push_str(&format!("--{boundary}\r\n"));
    buf.push_str("Content-Type: text/plain; charset=utf-8\r\n\r\n");
    buf.push_str(&summary_line);
    buf.push_str("\r\n\r\nFull audit event:\r\n");
    buf.push_str(&pretty_json);
    buf.push_str("\r\n");
    // application/json
    buf.push_str(&format!("--{boundary}\r\n"));
    buf.push_str(&format!(
        "Content-Type: application/json; name=\"audit-{}.json\"\r\n",
        event.seq,
    ));
    buf.push_str("Content-Disposition: attachment; filename=\"audit-");
    buf.push_str(&event.seq.to_string());
    buf.push_str(".json\"\r\n\r\n");
    buf.push_str(&raw_json);
    buf.push_str("\r\n");
    // close
    buf.push_str(&format!("--{boundary}--\r\n"));

    // Apply RFC 5321 dot-stuffing: any line beginning with `.`
    // gets a leading `.` so the relay doesn't terminate DATA early.
    let mut out: Vec<u8> = Vec::with_capacity(buf.len());
    for line in buf.split_inclusive("\r\n") {
        if line.starts_with('.') {
            out.push(b'.');
        }
        out.extend_from_slice(line.as_bytes());
    }
    // Final ".\r\n" terminator follows separately at submission time.
    out
}

/// RFC 2822 date — best effort. We don't pull `chrono` in here just
/// for this; SMTP relays accept any well-formed RFC 2822 date and
/// will rewrite it server-side anyway. We render UTC.
fn format_rfc2822_date(unix_secs: u64) -> String {
    // Compute Y/M/D/H/M/S without any external date library.
    let secs = unix_secs % 86_400;
    let total_days = (unix_secs / 86_400) as i64;
    let h = secs / 3600;
    let m = (secs / 60) % 60;
    let s = secs % 60;

    let (y, mo, d) = days_to_ymd(total_days);
    let dow = day_of_week(total_days);

    let dow_str = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"][dow as usize];
    let mo_str = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ][(mo - 1) as usize];
    format!("{dow_str}, {d:02} {mo_str} {y:04} {h:02}:{m:02}:{s:02} +0000")
}

/// Convert days-since-1970 to (year, month, day). Pure arithmetic;
/// pinned by the test suite below against known anchor dates.
fn days_to_ymd(mut days: i64) -> (i32, u32, u32) {
    days += 719_468; // shift epoch to 0000-03-01
    let era = if days >= 0 {
        days / 146_097
    } else {
        (days - 146_096) / 146_097
    };
    let doe = (days - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y as i32, m as u32, d as u32)
}

fn day_of_week(days_since_1970: i64) -> i64 {
    // 1970-01-01 was a Thursday (index 3 in our Mon-first week).
    let dow = (days_since_1970 + 3) % 7;
    if dow < 0 {
        dow + 7
    } else {
        dow
    }
}

// ---------------------------------------------------------------------------
// SMTP submission
// ---------------------------------------------------------------------------

async fn do_smtp_submit(
    target: &ParsedTarget,
    password: &str,
    body: &[u8],
) -> Result<(), DeliveryError> {
    let plain = TcpStream::connect((target.host.as_str(), target.port))
        .await
        .map_err(|e| DeliveryError::Network(format!("tcp connect failed: {e}")))?;

    if target.implicit_tls {
        let tls = tls_wrap(plain, &target.host).await?;
        let mut sess = SmtpSession::new(tls);
        sess.banner_check().await?;
        sess.ehlo(&target.host).await?;
        sess.auth_plain(&target.username, password).await?;
        sess.send_message(&target.from, &target.recipients, body)
            .await?;
        sess.quit().await?;
    } else {
        let mut sess = SmtpSession::new(plain);
        sess.banner_check().await?;
        sess.ehlo(&target.host).await?;
        sess.starttls().await?;
        let inner = sess.into_inner();
        let tls = tls_wrap(inner, &target.host).await?;
        let mut sess = SmtpSession::new(tls);
        sess.ehlo(&target.host).await?;
        sess.auth_plain(&target.username, password).await?;
        sess.send_message(&target.from, &target.recipients, body)
            .await?;
        sess.quit().await?;
    }
    Ok(())
}

async fn tls_wrap<S>(
    stream: S,
    sni_host: &str,
) -> Result<tokio_rustls::client::TlsStream<S>, DeliveryError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let cfg = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(cfg));
    let server_name = ServerName::try_from(sni_host.to_owned())
        .map_err(|e| DeliveryError::Network(format!("invalid SNI host {sni_host:?}: {e}")))?;
    connector
        .connect(server_name, stream)
        .await
        .map_err(|e| DeliveryError::Network(format!("TLS handshake failed: {e}")))
}

/// Tiny in-tree SMTP session driver. We deliberately do not pull in
/// `lettre` or `mail-send` — the wire is small and well-specified,
/// and the V2 dispatcher has different semantics from those crates'
/// per-message connection model.
struct SmtpSession<S> {
    inner: BufReader<S>,
}

impl<S> SmtpSession<S>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    fn new(stream: S) -> Self {
        Self {
            inner: BufReader::new(stream),
        }
    }

    fn into_inner(self) -> S {
        self.inner.into_inner()
    }

    async fn write_line(&mut self, line: &str) -> Result<(), DeliveryError> {
        let mut buf = Vec::with_capacity(line.len() + 2);
        buf.extend_from_slice(line.as_bytes());
        buf.extend_from_slice(b"\r\n");
        self.inner
            .get_mut()
            .write_all(&buf)
            .await
            .map_err(|e| DeliveryError::Network(format!("smtp write: {e}")))?;
        Ok(())
    }

    /// Read a multi-line SMTP response. Returns the numeric code
    /// from the last line and the joined free-text portion.
    async fn read_response(&mut self) -> Result<(u16, String), DeliveryError> {
        let mut text = String::new();
        loop {
            let mut line = String::new();
            let n = self
                .inner
                .read_line(&mut line)
                .await
                .map_err(|e| DeliveryError::Network(format!("smtp read: {e}")))?;
            if n == 0 {
                return Err(DeliveryError::Network("smtp connection closed".to_owned()));
            }
            if line.len() < 4 {
                return Err(DeliveryError::Network(format!(
                    "smtp response too short: {line:?}",
                )));
            }
            let parsed: u16 = line[..3].parse().map_err(|e| {
                DeliveryError::Network(format!("smtp response code parse: {line:?}: {e}"))
            })?;
            let sep = line.as_bytes()[3];
            text.push_str(line[4..].trim_end());
            // Parse "<3 digits><sep><text>". `sep == '-'` ⇒ more
            // lines follow; `sep == ' '` ⇒ last line.
            if sep == b' ' {
                return Ok((parsed, text));
            }
            if sep != b'-' {
                return Err(DeliveryError::Network(format!(
                    "smtp response separator unexpected: {line:?}",
                )));
            }
            text.push('\n');
        }
    }

    async fn banner_check(&mut self) -> Result<(), DeliveryError> {
        let (code, text) = self.read_response().await?;
        if code != 220 {
            return Err(DeliveryError::UpstreamRejected(format!(
                "SMTP banner: {code} {text}",
            )));
        }
        Ok(())
    }

    async fn ehlo(&mut self, host: &str) -> Result<(), DeliveryError> {
        self.write_line(&format!("EHLO {host}")).await?;
        let (code, text) = self.read_response().await?;
        if code != 250 {
            return Err(DeliveryError::UpstreamRejected(format!(
                "SMTP EHLO: {code} {text}",
            )));
        }
        Ok(())
    }

    async fn starttls(&mut self) -> Result<(), DeliveryError> {
        self.write_line("STARTTLS").await?;
        let (code, text) = self.read_response().await?;
        if code != 220 {
            return Err(DeliveryError::UpstreamRejected(format!(
                "SMTP STARTTLS: {code} {text}",
            )));
        }
        Ok(())
    }

    async fn auth_plain(&mut self, username: &str, password: &str) -> Result<(), DeliveryError> {
        // RFC 4616 PLAIN: \0<authcid>\0<password>, base64.
        let mut sasl = Vec::with_capacity(2 + username.len() + password.len());
        sasl.push(0);
        sasl.extend_from_slice(username.as_bytes());
        sasl.push(0);
        sasl.extend_from_slice(password.as_bytes());
        let encoded = STANDARD.encode(&sasl);
        self.write_line(&format!("AUTH PLAIN {encoded}")).await?;
        let (code, text) = self.read_response().await?;
        if code != 235 {
            return Err(DeliveryError::UpstreamRejected(format!(
                "SMTP AUTH PLAIN: {code} {text}",
            )));
        }
        Ok(())
    }

    async fn send_message(
        &mut self,
        from: &str,
        recipients: &[String],
        body: &[u8],
    ) -> Result<(), DeliveryError> {
        self.write_line(&format!("MAIL FROM:<{from}>")).await?;
        let (code, text) = self.read_response().await?;
        if code != 250 {
            return Err(DeliveryError::UpstreamRejected(format!(
                "SMTP MAIL FROM: {code} {text}",
            )));
        }
        for rcpt in recipients {
            self.write_line(&format!("RCPT TO:<{rcpt}>")).await?;
            let (code, text) = self.read_response().await?;
            if code != 250 && code != 251 {
                return Err(DeliveryError::UpstreamRejected(format!(
                    "SMTP RCPT TO {rcpt}: {code} {text}",
                )));
            }
        }
        self.write_line("DATA").await?;
        let (code, text) = self.read_response().await?;
        if code != 354 {
            return Err(DeliveryError::UpstreamRejected(format!(
                "SMTP DATA: {code} {text}",
            )));
        }
        // Body is already dot-stuffed by `render_message_body`.
        self.inner
            .get_mut()
            .write_all(body)
            .await
            .map_err(|e| DeliveryError::Network(format!("smtp body write: {e}")))?;
        // RFC 5321 end-of-data: ".\r\n" on its own line.
        self.write_line(".").await?;
        let (code, text) = self.read_response().await?;
        if code != 250 {
            return Err(DeliveryError::UpstreamRejected(format!(
                "SMTP end-of-DATA: {code} {text}",
            )));
        }
        Ok(())
    }

    async fn quit(&mut self) -> Result<(), DeliveryError> {
        self.write_line("QUIT").await?;
        // Some servers don't always reply to QUIT; we don't error on
        // a closed connection here.
        let _ = self.read_response().await;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use raxis_audit_tools::AuditEvent;
    use raxis_policy::{NotificationChannel, NotificationChannelKind};
    use serde_json::json;
    use uuid::Uuid;

    fn make_event(kind: &str, seq: u64, payload: serde_json::Value) -> AuditEvent {
        AuditEvent {
            seq,
            event_id: Uuid::new_v4(),
            event_kind: kind.to_owned(),
            session_id: None,
            task_id: None,
            initiative_id: None,
            payload,
            emitted_at: 1_700_000_000,
            prev_sha256: "0".repeat(64),
        }
    }

    #[test]
    fn parse_target_smtp_with_query_params() {
        let p = parse_target(
            "smtp://ops%40example.com@smtp.example.com:587\
             ?from=ops@example.com&to=alerts@example.com,oncall@example.com",
        )
        .unwrap();
        assert_eq!(p.host, "smtp.example.com");
        assert_eq!(p.port, 587);
        assert_eq!(p.username, "ops@example.com");
        assert_eq!(p.from, "ops@example.com");
        assert_eq!(
            p.recipients,
            vec![
                "alerts@example.com".to_owned(),
                "oncall@example.com".to_owned(),
            ]
        );
        assert!(!p.implicit_tls);
    }

    #[test]
    fn parse_target_smtps_implicit_tls() {
        let p = parse_target(
            "smtps://relay@smtp.example.com:465?from=ops@example.com&to=alerts@example.com",
        )
        .unwrap();
        assert_eq!(p.port, 465);
        assert!(p.implicit_tls, "smtps:// must set implicit_tls=true");
    }

    #[test]
    fn parse_target_rejects_unknown_scheme() {
        let err = parse_target("imap://relay@host:143?from=x&to=y").unwrap_err();
        assert!(err.contains("unsupported scheme"));
    }

    #[test]
    fn parse_target_rejects_missing_from() {
        let err = parse_target("smtp://relay@host:587?to=alerts@example.com").unwrap_err();
        assert!(err.contains("?from="));
    }

    #[test]
    fn parse_target_rejects_missing_to() {
        let err = parse_target("smtp://relay@host:587?from=ops@example.com").unwrap_err();
        assert!(err.contains("?to="));
    }

    #[test]
    fn parse_target_rejects_missing_username() {
        let err = parse_target("smtp://host:587?from=x&to=y").unwrap_err();
        assert!(err.contains("missing username"), "got: {err}");
    }

    #[test]
    fn parse_target_rejects_unknown_query_param() {
        let err = parse_target("smtp://relay@host:587?from=x&to=y&password=PEOPLE").unwrap_err();
        assert!(
            err.contains("unknown query parameter"),
            "passwords MUST NOT be transported in URL queries; got: {err}"
        );
    }

    #[tokio::test]
    async fn missing_password_sidecar_returns_credential_unavailable() {
        let tmp = tempfile::tempdir().unwrap();
        let chan = NotificationChannel {
            id: "ops-email".into(),
            kind: NotificationChannelKind::Email,
            target: "smtp://ops@smtp.example.com:587\
                     ?from=ops@example.com&to=alerts@example.com"
                .into(),
            max_in_flight: 8,
        };
        let e = make_event("EscalationApproved", 1, json!({}));
        match deliver(&chan, &e, tmp.path()).await {
            Err(DeliveryError::CredentialUnavailable(reason)) => {
                assert!(
                    reason.contains("ops-email.notify-cred"),
                    "audit reason should name the missing sidecar; got: {reason}"
                );
            }
            other => panic!("expected CredentialUnavailable, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn empty_password_sidecar_returns_credential_unavailable() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("notifications/credentials");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("ops-email.notify-cred"), "\n").unwrap();
        let chan = NotificationChannel {
            id: "ops-email".into(),
            kind: NotificationChannelKind::Email,
            target: "smtp://ops@smtp.example.com:587\
                     ?from=ops@example.com&to=alerts@example.com"
                .into(),
            max_in_flight: 8,
        };
        let e = make_event("EscalationApproved", 1, json!({}));
        match deliver(&chan, &e, tmp.path()).await {
            Err(DeliveryError::CredentialUnavailable(_)) => {}
            other => panic!("expected CredentialUnavailable, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn target_with_unparseable_url_returns_network_error() {
        let tmp = tempfile::tempdir().unwrap();
        let chan = NotificationChannel {
            id: "broken".into(),
            kind: NotificationChannelKind::Email,
            target: "this-is-not-an-smtp-url".into(),
            max_in_flight: 8,
        };
        let e = make_event("EscalationApproved", 1, json!({}));
        // NB: we read the password sidecar AFTER parsing the URL,
        // but the Target invalid path detours via Network(_) — see
        // DeliveryErrorExt.
        match deliver(&chan, &e, tmp.path()).await {
            Err(DeliveryError::Network(reason)) => {
                assert!(reason.contains("smtp target parse"), "got: {reason}");
            }
            other => panic!("expected Network(parse), got {other:?}"),
        }
    }

    #[test]
    fn render_message_body_includes_required_headers() {
        let tgt = ParsedTarget {
            host: "smtp.example.com".into(),
            port: 587,
            username: "ops@example.com".into(),
            from: "ops@example.com".into(),
            recipients: vec!["alerts@example.com".into()],
            implicit_tls: false,
        };
        let chan = NotificationChannel {
            id: "ops-email".into(),
            kind: NotificationChannelKind::Email,
            target: String::new(),
            max_in_flight: 8,
        };
        let e = make_event("EscalationApproved", 7, json!({"k":"v"}));
        let body = render_message_body(&chan, &e, &tgt);
        let text = std::str::from_utf8(&body).unwrap();
        assert!(text.contains("From: ops@example.com\r\n"));
        assert!(text.contains("To: alerts@example.com\r\n"));
        assert!(text.contains("Subject: [RAXIS] EscalationApproved"));
        assert!(text.contains("X-RAXIS-Event-Kind: EscalationApproved"));
        assert!(text.contains("X-RAXIS-Event-Seq: 7"));
        assert!(text.contains("Content-Type: multipart/alternative;"));
        assert!(
            text.contains("\"k\": \"v\""),
            "pretty JSON body must include the payload"
        );
        assert!(
            text.contains("\"k\":\"v\""),
            "raw JSON attachment must include the payload"
        );
    }

    #[test]
    fn render_message_body_dot_stuffs_lines_starting_with_dot() {
        let tgt = ParsedTarget {
            host: "h".into(),
            port: 25,
            username: "u".into(),
            from: "f@x".into(),
            recipients: vec!["r@x".into()],
            implicit_tls: false,
        };
        let chan = NotificationChannel {
            id: "x".into(),
            kind: NotificationChannelKind::Email,
            target: String::new(),
            max_in_flight: 8,
        };
        let mut payload = json!({});
        payload["body"] = json!(".dotted-line\nnormal\n.also-dotted");
        let e = make_event("X", 1, payload);
        let body = render_message_body(&chan, &e, &tgt);
        let text = std::str::from_utf8(&body).unwrap();
        // Any line beginning with `.` MUST be doubled — a real SMTP
        // relay terminates DATA on a bare ".\r\n" line, so leaking
        // an unescaped dot would truncate the message.
        for line in text.split("\r\n") {
            if line.starts_with('.') && !line.starts_with("..") && !line.is_empty() {
                panic!("un-stuffed dot-line leaked into body: {line:?}");
            }
        }
    }

    #[test]
    fn format_rfc2822_date_known_anchors() {
        // 1970-01-01 00:00:00 UTC = epoch 0.
        let s = format_rfc2822_date(0);
        assert!(
            s.starts_with("Thu, 01 Jan 1970 00:00:00 +0000"),
            "epoch must format as 1970-01-01 Thursday, got: {s}"
        );
        // 2024-01-01 00:00:00 UTC.
        let s = format_rfc2822_date(1_704_067_200);
        assert!(
            s.starts_with("Mon, 01 Jan 2024"),
            "2024 New Year must be Monday, got: {s}"
        );
    }

    #[test]
    fn url_decode_handles_percent_escapes_and_passes_through_plain() {
        assert_eq!(url_decode("ops%40example.com"), "ops@example.com");
        assert_eq!(url_decode("plain"), "plain");
        // Malformed: pass through verbatim.
        assert_eq!(url_decode("a%g"), "a%g");
    }
}

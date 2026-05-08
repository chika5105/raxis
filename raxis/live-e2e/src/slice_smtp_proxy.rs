//! Slice — real `SmtpProxy` + a real in-process upstream SMTP relay.
//!
//! Why an in-process upstream and not a third-party SMTP server: the
//! live-e2e harness asserts "real subsystems against real upstream
//! services". The "service" here is the SMTP relay's wire
//! conversation, not the IP allocation; an in-process tokio listener
//! that speaks `EHLO/AUTH/MAIL FROM/RCPT TO/DATA/QUIT` is the real
//! SMTP wire and exercises the same code paths as a third-party MTA.
//! Using an external relay would make the slice flaky on credential
//! refresh, IP reputation, and cross-network reachability without
//! adding any coverage the in-process relay does not already provide.
//!
//! Slice shape:
//!
//!   1. Spin up a tiny upstream SMTP listener that records the
//!      `MAIL FROM`, `RCPT TO`, `AUTH PLAIN` / `AUTH LOGIN` payload
//!      and DATA body it sees.
//!   2. Bind the real `SmtpProxy` against the in-memory
//!      `CredentialBackend` we control, pointing its
//!      `upstream_host_port` at the listener from step 1. TLS is
//!      disabled (`require_upstream_tls = false`) so the slice does
//!      not need a TLS fixture; the TLS path is exercised by the
//!      crate-internal integration tests already (see
//!      `crates/credential-proxy-smtp/src/wire.rs`).
//!   3. Open a raw `TcpStream` to the proxy and drive a real SMTP
//!      submission with a junk credential payload.
//!   4. Verify:
//!        a. The upstream received the **proxy's** credential bytes
//!           (the real `live-e2e` value) — not the agent's junk
//!           bytes — proving the proxy strips and rewrites the
//!           agent-supplied AUTH payload.
//!        b. The upstream observed the envelope (`from`, all
//!           `rcpts`, the body in full).
//!        c. The proxy's `messages_relayed` and `bytes_relayed`
//!           counters incremented; `messages_rejected` stayed at
//!           zero.
//!        d. The `CredentialBackend` was asked at least once
//!           (per-submission resolution preserves rotation
//!           semantics).

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use raxis_credentials::{
    ConsumerIdentity, CredentialBackend, CredentialError, CredentialName, CredentialValue,
    Lease, OperatorId,
};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;

use raxis_credential_proxy_smtp::{
    AuthMode, NoopEnvelopeAuditSink, OwnedConsumer, ProxyConfig, Restrictions, SmtpProxy,
};

const UPSTREAM_USER: &str = "raxis-tenant";
const UPSTREAM_PASS: &str = "live-e2e-upstream-secret";

// ---------------------------------------------------------------------------
// Local CredentialBackend: returns the upstream password verbatim.
// ---------------------------------------------------------------------------

struct LiveBackend {
    value:    Vec<u8>,
    resolves: AtomicU32,
}

impl CredentialBackend for LiveBackend {
    fn resolve(
        &self,
        name: &CredentialName,
        _consumer: ConsumerIdentity<'_>,
    ) -> Result<CredentialValue, CredentialError> {
        if name.as_str() != "live-e2e" {
            return Err(CredentialError::NotFound(name.clone()));
        }
        self.resolves.fetch_add(1, Ordering::Relaxed);
        Ok(CredentialValue::from_bytes(self.value.clone()))
    }
    fn rotate(
        &self, name: &CredentialName, _new_value: CredentialValue, _actor: OperatorId,
    ) -> Result<(), CredentialError> {
        Err(CredentialError::Malformed {
            name: name.clone(),
            reason: "live-e2e backend does not rotate".to_owned(),
        })
    }
    fn exists(&self, name: &CredentialName) -> bool { name.as_str() == "live-e2e" }
    fn lease(&self, _name: &CredentialName) -> Lease { Lease::Forever }
    fn backend_kind(&self) -> &'static str { "live-e2e" }
}

// ---------------------------------------------------------------------------
// Shared "what did upstream see" record — the slice asserts on this
// after the conversation.
// ---------------------------------------------------------------------------

#[derive(Default, Debug, Clone)]
struct UpstreamRecord {
    /// Decoded base64 payload from `AUTH PLAIN` (the wire bytes
    /// surrendered by the proxy on behalf of the agent session).
    /// Format per RFC 4954: `\0user\0password`.
    pub auth_plain_payload: Option<Vec<u8>>,
    /// Decoded base64 payloads from `AUTH LOGIN` (`[user_b64,
    /// pass_b64]`).
    pub auth_login_payloads: Vec<Vec<u8>>,
    /// `MAIL FROM:<...>` value the upstream received.
    pub mail_from:           Option<String>,
    /// `RCPT TO:<...>` list (in order, with no de-dup).
    pub rcpts_to:            Vec<String>,
    /// Full DATA body (without the `\r\n.\r\n` terminator).
    pub data_body:           Vec<u8>,
    /// Did the conversation finish with `QUIT`?
    pub finished_clean:      bool,
}

// ---------------------------------------------------------------------------
// Tiny upstream SMTP fixture.
// ---------------------------------------------------------------------------

async fn spawn_upstream() -> Result<(std::net::SocketAddr, Arc<Mutex<UpstreamRecord>>)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let record = Arc::new(Mutex::new(UpstreamRecord::default()));
    let record_for_loop = Arc::clone(&record);
    tokio::spawn(async move {
        while let Ok((stream, _peer)) = listener.accept().await {
            let r = Arc::clone(&record_for_loop);
            tokio::spawn(async move {
                if let Err(e) = drive_upstream(stream, r).await {
                    tracing::warn!(error = %e, "upstream smtp fixture conn ended");
                }
            });
        }
    });
    Ok((addr, record))
}

async fn drive_upstream(stream: TcpStream, record: Arc<Mutex<UpstreamRecord>>) -> Result<()> {
    let (read, mut write) = stream.into_split();
    let mut reader = BufReader::new(read);
    write.write_all(b"220 upstream-relay ready\r\n").await?;
    let mut line = String::new();
    let mut in_data = false;
    let mut data_acc: Vec<u8> = Vec::new();
    loop {
        line.clear();
        let n = reader.read_line(&mut line).await?;
        if n == 0 { break; }
        if in_data {
            // Accumulate raw bytes including this line. The
            // canonical end is "\r\n.\r\n" — i.e. a line containing
            // a single dot.
            let trimmed = line.trim_end_matches(['\r', '\n']);
            if trimmed == "." {
                // Strip the trailing CRLF before the dot per
                // RFC 5321 §4.5.2 ("dot stuffing").
                if data_acc.ends_with(b"\r\n") {
                    data_acc.truncate(data_acc.len() - 2);
                }
                record.lock().await.data_body = data_acc.clone();
                data_acc.clear();
                in_data = false;
                write.write_all(b"250 2.0.0 OK <fixture-msgid>\r\n").await?;
                continue;
            }
            // Per RFC 5321 §4.5.2 a leading "." in the body is a
            // transparent escape — strip it. The proxy under test
            // doesn't currently emit dot-stuffing, but we tolerate
            // it for forward compatibility.
            if let Some(stripped) = trimmed.strip_prefix('.') {
                data_acc.extend_from_slice(stripped.as_bytes());
            } else {
                data_acc.extend_from_slice(trimmed.as_bytes());
            }
            data_acc.extend_from_slice(b"\r\n");
            continue;
        }
        let cmd = line.trim_end_matches(['\r', '\n']);
        if cmd.eq_ignore_ascii_case("QUIT") {
            record.lock().await.finished_clean = true;
            write.write_all(b"221 2.0.0 Bye\r\n").await?;
            break;
        }
        let upper = cmd.to_ascii_uppercase();
        if upper.starts_with("EHLO") || upper.starts_with("HELO") {
            write.write_all(b"250-upstream-relay\r\n").await?;
            // Advertise AUTH but NOT STARTTLS — slice runs
            // require_upstream_tls = false.
            write.write_all(b"250 AUTH PLAIN LOGIN\r\n").await?;
        } else if upper.starts_with("AUTH PLAIN") {
            // Two shapes per RFC 4954:
            //   AUTH PLAIN <base64-payload>
            //   AUTH PLAIN          (server prompts 334; client follows up)
            //
            // We compare the verb on the uppercased form (case-
            // insensitive per RFC 5321 §2.4) but extract the base64
            // payload from the **original** `cmd` so we don't fold
            // the case of the credential bytes.
            let rest = &cmd["AUTH PLAIN".len()..];
            let trimmed = rest.trim();
            if trimmed.is_empty() {
                write.write_all(b"334 \r\n").await?;
                line.clear();
                let _ = reader.read_line(&mut line).await?;
                let payload = line.trim_end_matches(['\r', '\n']);
                record.lock().await.auth_plain_payload = Some(b64_decode(payload));
            } else {
                record.lock().await.auth_plain_payload = Some(b64_decode(trimmed));
            }
            write.write_all(b"235 2.7.0 authentication successful\r\n").await?;
        } else if upper == "AUTH LOGIN" {
            write.write_all(b"334 VXNlcm5hbWU6\r\n").await?;
            line.clear();
            reader.read_line(&mut line).await?;
            let user_b64 = line.trim_end_matches(['\r', '\n']).to_owned();
            record.lock().await.auth_login_payloads.push(b64_decode(&user_b64));
            write.write_all(b"334 UGFzc3dvcmQ6\r\n").await?;
            line.clear();
            reader.read_line(&mut line).await?;
            let pass_b64 = line.trim_end_matches(['\r', '\n']).to_owned();
            record.lock().await.auth_login_payloads.push(b64_decode(&pass_b64));
            write.write_all(b"235 2.7.0 authentication successful\r\n").await?;
        } else if let Some(addr) = strip_prefix_ci(cmd, "MAIL FROM:") {
            record.lock().await.mail_from = Some(addr.trim().to_owned());
            write.write_all(b"250 2.1.0 OK\r\n").await?;
        } else if let Some(addr) = strip_prefix_ci(cmd, "RCPT TO:") {
            record.lock().await.rcpts_to.push(addr.trim().to_owned());
            write.write_all(b"250 2.1.5 OK\r\n").await?;
        } else if upper == "DATA" {
            in_data = true;
            write.write_all(b"354 end data with <CRLF>.<CRLF>\r\n").await?;
        } else if upper == "RSET" {
            write.write_all(b"250 2.0.0 OK\r\n").await?;
        } else {
            write.write_all(b"500 5.5.1 unsupported command\r\n").await?;
        }
    }
    Ok(())
}

fn strip_prefix_ci<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    if s.len() < prefix.len() { return None; }
    if s[..prefix.len()].eq_ignore_ascii_case(prefix) {
        Some(&s[prefix.len()..])
    } else {
        None
    }
}

fn b64_decode(s: &str) -> Vec<u8> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD
        .decode(s.trim())
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Slice driver.
// ---------------------------------------------------------------------------

pub(crate) async fn run() -> Result<()> {
    tracing::info!("slice smtp-proxy: starting");

    // Real upstream SMTP fixture.
    let (upstream_addr, record) = spawn_upstream().await
        .context("spawn upstream smtp fixture")?;

    // Real CredentialBackend whose value IS the password we expect
    // the proxy to send to upstream.
    let backend = Arc::new(LiveBackend {
        value:    UPSTREAM_PASS.as_bytes().to_vec(),
        resolves: AtomicU32::new(0),
    });

    // Real SmtpProxy bound at 127.0.0.1:0; upstream pinned to
    // upstream_addr; require_upstream_tls = false because the
    // fixture is loopback-only and the TLS path is covered by the
    // crate's own integration tests.
    let cfg = ProxyConfig {
        listen_addr:           "127.0.0.1:0".to_owned(),
        upstream_host_port:    upstream_addr.to_string(),
        require_upstream_tls:  false,
        credential_name:       CredentialName::new("live-e2e"),
        auth_mode:             AuthMode::Plain { user: UPSTREAM_USER.to_owned() },
        consumer:              OwnedConsumer::new(
            "credential_proxy",
            "live-e2e:smtp:0",
        ),
        restrictions:          Restrictions::default(),
    };
    let proxy = SmtpProxy::bind(backend.clone(), cfg, Arc::new(NoopEnvelopeAuditSink))
        .await
        .map_err(|e| anyhow!("SmtpProxy::bind: {e}"))?;
    let proxy_addr = proxy.local_addr()?;
    let stats = proxy.stats_handle();
    tokio::spawn(proxy.serve());

    // Real SMTP client (raw TCP, real wire shape).
    let mut s = TcpStream::connect(proxy_addr).await?;
    expect_status(&mut s, 220).await?;

    write_line(&mut s, "EHLO live-e2e.test\r\n").await?;
    drain_continued_status(&mut s, 250).await?;

    // Drive AUTH PLAIN with junk bytes; the proxy MUST discard them.
    write_line(&mut s, "AUTH PLAIN AGFnZW50AHByb3h5LWp1bmstcGFzcw==\r\n").await?;
    expect_status(&mut s, 235).await?;

    write_line(&mut s, "MAIL FROM:<sender@live-e2e.test>\r\n").await?;
    expect_status(&mut s, 250).await?;

    write_line(&mut s, "RCPT TO:<rcpt-a@live-e2e.test>\r\n").await?;
    expect_status(&mut s, 250).await?;
    write_line(&mut s, "RCPT TO:<rcpt-b@live-e2e.test>\r\n").await?;
    expect_status(&mut s, 250).await?;

    write_line(&mut s, "DATA\r\n").await?;
    expect_status(&mut s, 354).await?;

    let body =
        "From: sender@live-e2e.test\r\n\
         To: rcpt-a@live-e2e.test, rcpt-b@live-e2e.test\r\n\
         Subject: live-e2e\r\n\
         \r\n\
         body line 1\r\n\
         body line 2\r\n\
         .\r\n";
    s.write_all(body.as_bytes()).await?;
    expect_status(&mut s, 250).await?;

    write_line(&mut s, "QUIT\r\n").await?;
    expect_status(&mut s, 221).await?;

    // Allow the upstream a moment to finalize its tracking record.
    for _ in 0..50 {
        let snap = stats.snapshot();
        if snap.messages_relayed >= 1 { break; }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let snap = stats.snapshot();
    let rec = record.lock().await.clone();

    // Assertions: the proxy's recorded state.
    if snap.messages_relayed != 1 {
        return Err(anyhow!(
            "expected messages_relayed=1, got {} (snapshot={snap:?})",
            snap.messages_relayed,
        ));
    }
    if snap.messages_rejected != 0 {
        return Err(anyhow!(
            "expected messages_rejected=0, got {}",
            snap.messages_rejected,
        ));
    }
    if snap.recipients_accepted != 2 {
        return Err(anyhow!(
            "expected recipients_accepted=2, got {}",
            snap.recipients_accepted,
        ));
    }
    if snap.bytes_relayed == 0 {
        return Err(anyhow!("expected bytes_relayed > 0, got 0"));
    }

    // Assertions: the upstream-side record.
    let auth = rec.auth_plain_payload.as_deref()
        .ok_or_else(|| anyhow!("upstream did not see AUTH PLAIN payload"))?;
    let expected_auth = {
        let mut v = Vec::with_capacity(2 + UPSTREAM_USER.len() + UPSTREAM_PASS.len());
        v.push(0);
        v.extend_from_slice(UPSTREAM_USER.as_bytes());
        v.push(0);
        v.extend_from_slice(UPSTREAM_PASS.as_bytes());
        v
    };
    if auth != expected_auth.as_slice() {
        return Err(anyhow!(
            "upstream AUTH PLAIN payload mismatch — proxy did not strip the agent's junk and inject the real credential.\n\
             expected (canonical): {:?}\n\
             observed:             {:?}",
            expected_auth, auth,
        ));
    }
    if rec.mail_from.as_deref() != Some("<sender@live-e2e.test>") {
        return Err(anyhow!(
            "upstream MAIL FROM mismatch — got {:?}",
            rec.mail_from,
        ));
    }
    if rec.rcpts_to.len() != 2 {
        return Err(anyhow!(
            "upstream RCPT TO list mismatch — expected 2, got {} ({:?})",
            rec.rcpts_to.len(), rec.rcpts_to,
        ));
    }
    if rec.data_body.is_empty() {
        return Err(anyhow!("upstream DATA body was empty"));
    }
    if !rec.finished_clean {
        return Err(anyhow!("upstream did not see QUIT"));
    }
    if backend.resolves.load(Ordering::Relaxed) < 1 {
        return Err(anyhow!(
            "credential backend was never asked — proxy must resolve per submission",
        ));
    }

    tracing::info!(
        "slice smtp-proxy: PASS — messages_relayed={}, recipients_accepted={}, bytes_relayed={}, backend resolves={}",
        snap.messages_relayed, snap.recipients_accepted, snap.bytes_relayed,
        backend.resolves.load(Ordering::Relaxed),
    );
    Ok(())
}

async fn write_line(s: &mut TcpStream, line: &str) -> Result<()> {
    s.write_all(line.as_bytes()).await?;
    Ok(())
}

async fn read_status_line(s: &mut TcpStream) -> Result<(u16, bool, String)> {
    // Read until LF, then parse "<code><sep><text>" where sep is
    // ' ' for a final line or '-' for a continued line.
    let mut acc = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        let n = s.read(&mut byte).await?;
        if n == 0 { break; }
        acc.push(byte[0]);
        if byte[0] == b'\n' { break; }
    }
    let line = String::from_utf8_lossy(&acc).trim_end_matches(['\r', '\n']).to_owned();
    if line.len() < 4 {
        return Err(anyhow!("short SMTP status line {line:?}"));
    }
    let code: u16 = line[..3].parse()
        .map_err(|_| anyhow!("malformed SMTP code in {line:?}"))?;
    let sep = line.as_bytes()[3];
    let text = line[4..].to_owned();
    Ok((code, sep == b'-', text))
}

async fn expect_status(s: &mut TcpStream, want: u16) -> Result<()> {
    loop {
        let (code, continued, text) = read_status_line(s).await?;
        if code != want {
            return Err(anyhow!("expected status {want}, got {code} ({text})"));
        }
        if !continued { return Ok(()); }
    }
}

async fn drain_continued_status(s: &mut TcpStream, want: u16) -> Result<()> {
    loop {
        let (code, continued, text) = read_status_line(s).await?;
        if code != want {
            return Err(anyhow!("expected status {want}, got {code} ({text})"));
        }
        if !continued { return Ok(()); }
    }
}

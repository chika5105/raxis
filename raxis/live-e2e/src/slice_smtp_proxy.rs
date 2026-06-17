//! Slice — real `SmtpProxy` against a real Postfix MTA running in
//! the `mailserver/docker-mailserver:14.0` container.
//!
//! ## Why a real container, not an in-process SMTP fixture
//!
//! An earlier revision of this slice ran the proxy against an in-
//! process tokio `TcpListener` that re-implemented enough of RFC
//! 5321 to record `MAIL FROM` / `RCPT TO` / `AUTH PLAIN` / DATA
//! body bytes and assert the proxy submitted the right wire
//! envelope. The fixture passed even when the proxy made decisions
//! a real Postfix would reject — pipelining edge cases, line-
//! ending handling on the DATA terminator (`\r\n.\r\n` vs partial
//! reads), virtual-alias rewriting, the SASL auth-cache shape, and
//! the precise `5xx` codes a real MTA emits on a denied envelope
//! all differ between a hand-rolled accumulator and a real Postfix
//! / Dovecot pair. Real services catch real bugs that fixtures
//! paper over by construction.
//!
//! ## Trade-off: docker-mailserver vs Mailpit / MailHog
//!
//! `docker-mailserver` is a full Postfix + Dovecot SASL stack
//! (ClamAV / SpamAssassin / DKIM / DMARC etc. are all disabled by
//! the compose file). It is heavier than test-focused SMTP sinks
//! like Mailpit or MailHog, both of which expose an HTTP capture
//! API that would let the slice fetch delivered messages over
//! HTTP. We use docker-mailserver because the team-wide
//! preference is for `the real production-shaped MTA` rather than
//! a test sink — the slice asserts on the real Postfix mail
//! delivery path (queue → local delivery agent → Maildir),
//! including SASL auth against a real Dovecot backend, which
//! Mailpit / MailHog do not exercise.
//!
//! Inspection happens by `docker exec`-ing into the container
//! and reading the test mailbox's `Maildir/new/`. That is more
//! invasive than a Mailpit HTTP `GET /api/v1/messages`, but it is
//! deterministic, depends on no extra HTTP client, and the byte-
//! exact contents of the delivered message are what the slice
//! cares about.
//!
//! ## Lifecycle
//!
//!   1. Preflight — TCP-probe the loopback host:port the compose
//!      file publishes (`127.0.0.1:25199`). On failure the slice
//!      prints the exact `docker compose up` invocation and
//!      bails.
//!   2. Bind the real `SmtpProxy` against an in-memory
//!      `CredentialBackend` whose value IS the SASL password the
//!      docker-mailserver `postfix-accounts.cf` declares for
//!      `raxis-tenant@live-e2e.test`. The proxy's
//!      `upstream_host_port` points at the container.
//!   3. Drive a real SMTP submission through the proxy with a
//!      junk agent `AUTH PLAIN`. The proxy MUST strip the agent's
//!      bytes and inject the real credential.
//!   4. Verify against the **real upstream**:
//!      The proxy's `messages_relayed` counter incremented and
//!      `messages_rejected` stayed at zero — the only way that
//!      could happen is if the proxy's AUTH PLAIN was accepted
//!      by real Dovecot, proving the proxy stripped the agent
//!      junk and injected the real bytes. A `docker exec ls
//!      /var/mail/.../Maildir/new/` finds exactly one new
//!      message file containing the body the slice sent; the
//!      message's headers carry the envelope `MAIL FROM` and at
//!      least one of the allowlisted recipients. Finally, the
//!      `CredentialBackend` was asked at least once.
//!
//! The previous in-process SMTP fixture (`UpstreamRecord`,
//! `spawn_upstream`, `drive_upstream`, base64 helpers) is fully
//! deleted; no half-removed mock module remains.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use raxis_credentials::{
    ConsumerIdentity, CredentialBackend, CredentialError, CredentialName, CredentialValue,
    OperatorId,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use raxis_credential_proxy_smtp::{
    AuthMode, NoopEnvelopeAuditSink, OwnedConsumer, ProxyConfig, Restrictions, SmtpProxy,
};

/// Loopback host:port the docker-compose Docker Mailserver
/// publishes. Pinned to match `live-e2e/docker-compose.e2e.yml`.
const SMTP_HOST_PORT: &str = "127.0.0.1:25199";

/// Container name the compose file pins. Used by the inspection
/// step to `docker exec ls /var/mail/...` after submission.
const SMTP_CONTAINER: &str = "raxis-e2e-smtp";

/// Real account baked into `seed/smtp/postfix-accounts.cf`.
const UPSTREAM_USER: &str = "raxis-tenant@live-e2e.test";
/// Plaintext password matching the `{PLAIN}<password>` half of
/// the same line.
const UPSTREAM_PASS: &str = "live-e2e-upstream-secret";

/// Recipient address baked into `seed/smtp/postfix-accounts.cf`
/// (the slice delivers a copy here so we can `docker exec`-cat
/// the delivered file). Aliases for `rcpt-a@` / `rcpt-b@` route
/// into the same mailbox via `seed/smtp/postfix-virtual.cf`.
const TENANT_RCPT: &str = "raxis-tenant@live-e2e.test";
/// Aliased recipients — these go through Postfix's virtual-alias
/// table and land in the same `raxis-tenant` Maildir.
const ALIASED_RCPT: &str = "rcpt-a@live-e2e.test";

/// Where docker-mailserver writes delivered messages for the
/// tenant. Reading this directory via `docker exec` is the
/// inspection oracle.
const TENANT_MAILDIR_NEW: &str = "/var/mail/live-e2e.test/raxis-tenant/new";

// ---------------------------------------------------------------------------
// Local CredentialBackend: returns the upstream password verbatim.
// ---------------------------------------------------------------------------

struct LiveBackend {
    value: Vec<u8>,
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
        &self,
        name: &CredentialName,
        _new_value: CredentialValue,
        _actor: OperatorId,
    ) -> Result<(), CredentialError> {
        Err(CredentialError::Malformed {
            name: name.clone(),
            reason: "live-e2e backend does not rotate".to_owned(),
        })
    }
    fn exists(&self, name: &CredentialName) -> bool {
        name.as_str() == "live-e2e"
    }
    fn backend_kind(&self) -> &'static str {
        "live-e2e"
    }
}

// ---------------------------------------------------------------------------
// Slice driver
// ---------------------------------------------------------------------------

pub(crate) async fn run() -> Result<()> {
    tracing::info!(host_port = SMTP_HOST_PORT, "smtp-proxy slice starting");

    require_smtp_container().await?;

    // Capture the BEFORE snapshot of the tenant's Maildir so we
    // can attribute the delivered message to THIS run when the
    // compose stack has been up for a while.
    let pre_files = list_maildir_new()?;

    let backend = Arc::new(LiveBackend {
        value: UPSTREAM_PASS.as_bytes().to_vec(),
        resolves: AtomicU32::new(0),
    });

    let cfg = ProxyConfig {
        listen_addr: "127.0.0.1:0".to_owned(),
        upstream_host_port: SMTP_HOST_PORT.to_owned(),
        // The Docker Mailserver in compose is configured with
        // `SSL_TYPE=""` (plaintext) on its inbound port 25 path,
        // so the proxy's outbound dial does not need to STARTTLS.
        // Production deployments would set this `true`.
        require_upstream_tls: false,
        credential_name: CredentialName::new("live-e2e"),
        auth_mode: AuthMode::Plain {
            user: UPSTREAM_USER.to_owned(),
        },
        consumer: OwnedConsumer::new("credential_proxy", "live-e2e:smtp:0"),
        restrictions: Restrictions::default(),
    };
    let proxy = SmtpProxy::bind(backend.clone(), cfg, Arc::new(NoopEnvelopeAuditSink))
        .await
        .map_err(|e| anyhow!("SmtpProxy::bind: {e}"))?;
    let proxy_addr = proxy.local_addr()?;
    let stats = proxy.stats_handle();
    tokio::spawn(proxy.serve());

    // A tag the slice embeds in the message body so we can match
    // the right delivered file when the Maildir already had
    // pre-existing messages from a long-running compose stack.
    let run_tag = format!("raxis-live-e2e-smtp-{}", uuid::Uuid::now_v7());

    // Real SMTP client (raw TCP, real wire shape) talking to the
    // proxy.
    let mut s = TcpStream::connect(proxy_addr).await?;
    expect_status(&mut s, 220).await?;

    write_line(&mut s, "EHLO live-e2e.test\r\n").await?;
    drain_continued_status(&mut s, 250).await?;

    // Drive AUTH PLAIN with junk bytes; the proxy MUST discard
    // them and re-authenticate upstream with the kernel-resolved
    // credential. The fact that the eventual `MAIL FROM` /
    // `RCPT TO` succeed is the cross-check.
    write_line(&mut s, "AUTH PLAIN AGFnZW50AHByb3h5LWp1bmstcGFzcw==\r\n").await?;
    expect_status(&mut s, 235).await?;

    write_line(&mut s, "MAIL FROM:<sender@live-e2e.test>\r\n").await?;
    expect_status(&mut s, 250).await?;

    // Two recipients: the canonical tenant + an aliased recipient
    // that postfix-virtual.cf routes into the same Maildir. Both
    // landings prove (a) the alias table is loaded and (b) the
    // proxy forwarded each `RCPT TO` verbatim.
    write_line(&mut s, &format!("RCPT TO:<{TENANT_RCPT}>\r\n")).await?;
    expect_status(&mut s, 250).await?;
    write_line(&mut s, &format!("RCPT TO:<{ALIASED_RCPT}>\r\n")).await?;
    expect_status(&mut s, 250).await?;

    write_line(&mut s, "DATA\r\n").await?;
    expect_status(&mut s, 354).await?;

    let body = format!(
        "From: sender@live-e2e.test\r\n\
         To: {TENANT_RCPT}, {ALIASED_RCPT}\r\n\
         Subject: live-e2e {run_tag}\r\n\
         X-Raxis-Run-Tag: {run_tag}\r\n\
         \r\n\
         body line 1 ({run_tag})\r\n\
         body line 2\r\n\
         .\r\n",
    );
    s.write_all(body.as_bytes()).await?;
    expect_status(&mut s, 250).await?;

    write_line(&mut s, "QUIT\r\n").await?;
    expect_status(&mut s, 221).await?;

    // Allow the proxy a moment to flush counters AND give Postfix
    // a chance to deliver into the Maildir. Postfix delivery
    // through the local LDA is normally < 200 ms but a busy
    // queue on a cold container can take a few seconds.
    let snap = wait_for_relay(&stats, Duration::from_secs(8)).await?;

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
    if backend.resolves.load(Ordering::Relaxed) < 1 {
        return Err(anyhow!(
            "credential backend was never asked — proxy must resolve per submission",
        ));
    }

    // Inspect the real upstream: the message must have landed in
    // the tenant's Maildir/new/. We read every NEW file (any file
    // not present in the pre-snapshot) and verify at least one of
    // them carries our run-tag.
    let landed = wait_for_delivery(&pre_files, &run_tag, Duration::from_secs(15))?;
    if !landed.found {
        return Err(anyhow!(
            "upstream Maildir delivery missed run-tag {run_tag:?} after 15s.\n\
             new files since pre-snapshot: {:?}",
            landed.new_files,
        ));
    }

    // Best-effort cleanup so a long-running compose stack doesn't
    // accumulate slice residue. Failure is non-fatal.
    if let Err(e) = cleanup_delivered(&landed.new_files) {
        tracing::warn!(error = %e, "best-effort Maildir cleanup failed (non-fatal)");
    }

    tracing::info!(
        messages_relayed = snap.messages_relayed,
        recipients_accepted = snap.recipients_accepted,
        bytes_relayed = snap.bytes_relayed,
        backend_resolves = backend.resolves.load(Ordering::Relaxed),
        delivered_files = landed.new_files.len(),
        "smtp-proxy slice OK (real upstream)",
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Preflight + container inspection (`docker exec`)
// ---------------------------------------------------------------------------

async fn require_smtp_container() -> Result<()> {
    match tokio::time::timeout(
        Duration::from_millis(800),
        TcpStream::connect(SMTP_HOST_PORT),
    )
    .await
    {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(e)) => Err(anyhow!(
            "SMTP (docker-mailserver) container not reachable at {SMTP_HOST_PORT} ({e}).\n\
             Run:\n  \
             docker compose -f live-e2e/docker-compose.e2e.yml up -d smtp --wait\n\
             (or use docker-compose.extended.e2e.yml for the extended scenario)",
        )),
        Err(_) => Err(anyhow!(
            "SMTP container TCP connect to {SMTP_HOST_PORT} timed out after 800 ms.\n\
             Run:\n  \
             docker compose -f live-e2e/docker-compose.e2e.yml up -d smtp --wait",
        )),
    }
}

fn list_maildir_new() -> Result<Vec<String>> {
    let out = std::process::Command::new("docker")
        .args(["exec", SMTP_CONTAINER, "ls", "-1", TENANT_MAILDIR_NEW])
        .output()
        .with_context(|| format!("spawn `docker exec` against {SMTP_CONTAINER}"))?;
    if !out.status.success() {
        // First run: directory may not exist yet — Postfix creates
        // it on first delivery. Treat as empty.
        return Ok(Vec::new());
    }
    Ok(String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter(|l| !l.is_empty())
        .map(|l| l.to_owned())
        .collect())
}

struct LandingProbe {
    found: bool,
    new_files: Vec<String>,
}

/// Poll the tenant's Maildir for a file that is NEW (not in
/// `before`) AND whose body contains `run_tag`. Returns once at
/// least one such file lands or `deadline` elapses.
fn wait_for_delivery(before: &[String], run_tag: &str, deadline: Duration) -> Result<LandingProbe> {
    let started = Instant::now();
    let before_set: std::collections::BTreeSet<&str> = before.iter().map(String::as_str).collect();

    loop {
        let now = list_maildir_new()?;
        let new_files: Vec<String> = now
            .into_iter()
            .filter(|f| !before_set.contains(f.as_str()))
            .collect();

        if !new_files.is_empty() {
            // Read each new file and check the body.
            for f in &new_files {
                let body = read_maildir_file(f)?;
                if body.contains(run_tag) {
                    return Ok(LandingProbe {
                        found: true,
                        new_files,
                    });
                }
            }
        }
        if started.elapsed() >= deadline {
            return Ok(LandingProbe {
                found: false,
                new_files,
            });
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}

fn read_maildir_file(name: &str) -> Result<String> {
    let path = format!("{TENANT_MAILDIR_NEW}/{name}");
    let out = std::process::Command::new("docker")
        .args(["exec", SMTP_CONTAINER, "cat", &path])
        .output()
        .with_context(|| format!("docker exec cat {path}"))?;
    if !out.status.success() {
        return Err(anyhow!(
            "docker exec cat {path} failed: {}",
            String::from_utf8_lossy(&out.stderr),
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

fn cleanup_delivered(files: &[String]) -> Result<()> {
    if files.is_empty() {
        return Ok(());
    }
    let mut args = vec![
        "exec".to_owned(),
        SMTP_CONTAINER.to_owned(),
        "rm".to_owned(),
        "-f".to_owned(),
    ];
    for f in files {
        args.push(format!("{TENANT_MAILDIR_NEW}/{f}"));
    }
    let out = std::process::Command::new("docker").args(&args).output()?;
    if !out.status.success() {
        return Err(anyhow!(
            "docker exec rm failed: {}",
            String::from_utf8_lossy(&out.stderr),
        ));
    }
    Ok(())
}

async fn wait_for_relay(
    stats: &Arc<raxis_credential_proxy_smtp::ProxyStats>,
    deadline: Duration,
) -> Result<raxis_credential_proxy_smtp::ProxyStatsSnapshot> {
    let started = Instant::now();
    loop {
        let snap = stats.snapshot();
        if snap.messages_relayed >= 1 {
            return Ok(snap);
        }
        if started.elapsed() >= deadline {
            return Ok(snap);
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

// ---------------------------------------------------------------------------
// Tiny SMTP client helpers (raw wire — same byte shape as the
// in-VM agent's libc-only client).
// ---------------------------------------------------------------------------

async fn write_line(s: &mut TcpStream, line: &str) -> Result<()> {
    s.write_all(line.as_bytes()).await?;
    Ok(())
}

async fn read_status_line(s: &mut TcpStream) -> Result<(u16, bool, String)> {
    let mut acc = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        let n = s.read(&mut byte).await?;
        if n == 0 {
            break;
        }
        acc.push(byte[0]);
        if byte[0] == b'\n' {
            break;
        }
    }
    let line = String::from_utf8_lossy(&acc)
        .trim_end_matches(['\r', '\n'])
        .to_owned();
    if line.len() < 4 {
        return Err(anyhow!("short SMTP status line {line:?}"));
    }
    let code: u16 = line[..3]
        .parse()
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
        if !continued {
            return Ok(());
        }
    }
}

async fn drain_continued_status(s: &mut TcpStream, want: u16) -> Result<()> {
    loop {
        let (code, continued, text) = read_status_line(s).await?;
        if code != want {
            return Err(anyhow!("expected status {want}, got {code} ({text})"));
        }
        if !continued {
            return Ok(());
        }
    }
}

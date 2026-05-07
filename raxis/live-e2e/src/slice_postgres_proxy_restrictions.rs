//! Slice — `PostgresProxy` enforces `allow_only_select` denials.
//!
//! Goal: prove that a postgres proxy bound with
//! `Restrictions { allow_only_select: true }` rejects every
//! statement-class except `SELECT` and that the rejection is
//! observed:
//!
//!   1. Wire-side, as a real Postgres `ErrorResponse` with sqlstate
//!      `42501` (insufficient_privilege), followed by a
//!      `ReadyForQuery` so the simple-query path stays connected.
//!   2. Counter-side, as a `queries_blocked` increment on the
//!      proxy's stats handle.
//!
//! This is the deny-path twin of `postgres-proxy`. The allow path
//! (a clean `SELECT 1` reaching `CommandComplete`) is also exercised
//! to keep the slice self-contained — a positive-only twin in
//! isolation could not distinguish "the proxy correctly rejects DML"
//! from "the proxy is broken and rejects everything."
//!
//! Wire shape (frontend protocol — same harness as
//! `slice_postgres_proxy.rs`):
//!
//!   1. StartupMessage → AuthenticationOk → … → ReadyForQuery.
//!   2. `SELECT 1`     → `CommandComplete` ('C') + `ReadyForQuery`.
//!   3. `INSERT INTO`  → `ErrorResponse` ('E') with sqlstate `42501`
//!                       + `ReadyForQuery`.
//!   4. `UPDATE … SET` → `ErrorResponse` ('E') + `ReadyForQuery`.
//!   5. `DELETE FROM`  → `ErrorResponse` ('E') + `ReadyForQuery`.
//!   6. Terminate ('X').

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use anyhow::{anyhow, Result};
use raxis_credential_proxy_postgres::{
    OwnedConsumer, PostgresProxy, ProxyConfig, restriction::Restrictions,
};
use raxis_credentials::{
    CredentialBackend, CredentialError, CredentialName, CredentialValue,
    ConsumerIdentity, Lease, OperatorId,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

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

pub(crate) async fn run() -> Result<()> {
    tracing::info!("slice postgres-proxy-restrictions: starting");
    let backend = Arc::new(LiveBackend {
        value:    b"postgresql://demo:demo@127.0.0.1:5432/demo".to_vec(),
        resolves: AtomicU32::new(0),
    });
    let cfg = ProxyConfig {
        listen_addr:     "127.0.0.1:0".to_owned(),
        credential_name: CredentialName::new("live-e2e"),
        consumer:        OwnedConsumer::new("credential_proxy", "live-e2e:postgres:r"),
        restrictions:    Restrictions { allow_only_select: true },
    };
    let proxy = PostgresProxy::bind(backend.clone(), cfg).await
        .map_err(|e| anyhow!("PostgresProxy::bind: {e}"))?;
    let addr = proxy.local_addr()?;
    let stats = proxy.stats_handle();
    tokio::spawn(proxy.serve());

    let mut s = TcpStream::connect(addr).await?;

    // ── Handshake ──
    write_startup(&mut s).await?;
    let msgs = drain_until_ready(&mut s).await?;
    if msgs.last().map(|(t, _)| *t) != Some(b'Z') {
        return Err(anyhow!("handshake did not end at ReadyForQuery"));
    }

    // ── Allow path: SELECT 1 — must reach CommandComplete ──
    write_query(&mut s, "SELECT 1").await?;
    let msgs = drain_until_ready(&mut s).await?;
    if !msgs.iter().any(|(t, _)| *t == b'C') {
        return Err(anyhow!(
            "allow path: SELECT did not reach CommandComplete; tags={:?}",
            msgs.iter().map(|(t, _)| *t).collect::<Vec<_>>(),
        ));
    }

    // ── Deny class 1: INSERT — must surface ErrorResponse 42501 ──
    let blocks_before_insert = stats.snapshot().queries_blocked;
    write_query(&mut s, "INSERT INTO t VALUES (1)").await?;
    let msgs = drain_until_ready(&mut s).await?;
    assert_error_with_sqlstate(&msgs, "42501", "INSERT")?;
    let blocks_after_insert = stats.snapshot().queries_blocked;
    if blocks_after_insert <= blocks_before_insert {
        return Err(anyhow!(
            "queries_blocked did not increment after INSERT rejection: \
             {blocks_before_insert} → {blocks_after_insert}",
        ));
    }

    // ── Deny class 2: UPDATE ──
    let blocks_before_update = stats.snapshot().queries_blocked;
    write_query(&mut s, "UPDATE t SET x = 1 WHERE id = 1").await?;
    let msgs = drain_until_ready(&mut s).await?;
    assert_error_with_sqlstate(&msgs, "42501", "UPDATE")?;
    if stats.snapshot().queries_blocked <= blocks_before_update {
        return Err(anyhow!("queries_blocked did not increment after UPDATE rejection"));
    }

    // ── Deny class 3: DELETE ──
    let blocks_before_delete = stats.snapshot().queries_blocked;
    write_query(&mut s, "DELETE FROM t WHERE id = 1").await?;
    let msgs = drain_until_ready(&mut s).await?;
    assert_error_with_sqlstate(&msgs, "42501", "DELETE")?;
    if stats.snapshot().queries_blocked <= blocks_before_delete {
        return Err(anyhow!("queries_blocked did not increment after DELETE rejection"));
    }

    // ── Persistence: another SELECT after rejections must still succeed ──
    write_query(&mut s, "SELECT 2").await?;
    let msgs = drain_until_ready(&mut s).await?;
    if !msgs.iter().any(|(t, _)| *t == b'C') {
        return Err(anyhow!(
            "post-rejection SELECT failed; the proxy must keep the session alive after a denied DML",
        ));
    }

    write_terminate(&mut s).await?;

    let snap = stats.snapshot();
    tracing::info!(
        "slice postgres-proxy-restrictions: PASS — queries_audited={}, queries_blocked={} (≥3 expected)",
        snap.queries_audited, snap.queries_blocked,
    );
    if snap.queries_blocked < 3 {
        return Err(anyhow!(
            "expected at least 3 blocked queries (INSERT/UPDATE/DELETE); got {}",
            snap.queries_blocked,
        ));
    }
    Ok(())
}

/// Verify that `msgs` contains an `ErrorResponse` ('E') frame whose
/// body carries the expected sqlstate, that no `CommandComplete`
/// ('C') sneaks past, and that the conversation ended at
/// `ReadyForQuery` ('Z').
fn assert_error_with_sqlstate(
    msgs:     &[(u8, Vec<u8>)],
    sqlstate: &str,
    label:    &str,
) -> Result<()> {
    let tags: Vec<u8> = msgs.iter().map(|(t, _)| *t).collect();
    if msgs.iter().any(|(t, _)| *t == b'C') {
        return Err(anyhow!(
            "deny path {label}: unexpected CommandComplete in response (proxy let it through?); tags={tags:?}",
        ));
    }
    let err_frame = msgs.iter().find(|(t, _)| *t == b'E')
        .ok_or_else(|| anyhow!(
            "deny path {label}: no ErrorResponse frame; tags={tags:?}",
        ))?;
    if tags.last() != Some(&b'Z') {
        return Err(anyhow!(
            "deny path {label}: response did not end at ReadyForQuery; tags={tags:?}",
        ));
    }
    // ErrorResponse body is a sequence of (field-tag-byte, NUL-terminated string)
    // pairs ending with a zero byte. Field 'C' is the SQLSTATE per
    // postgres protocol §47.5.
    let body = &err_frame.1;
    let mut found_state: Option<String> = None;
    let mut i = 0;
    while i < body.len() && body[i] != 0 {
        let field_tag = body[i];
        i += 1;
        let mut end = i;
        while end < body.len() && body[end] != 0 {
            end += 1;
        }
        let value = std::str::from_utf8(&body[i..end]).unwrap_or("").to_owned();
        if field_tag == b'C' { found_state = Some(value); }
        i = end + 1;
    }
    let got = found_state
        .ok_or_else(|| anyhow!(
            "deny path {label}: ErrorResponse had no sqlstate (C) field; body bytes={body:?}",
        ))?;
    if got != sqlstate {
        return Err(anyhow!(
            "deny path {label}: expected sqlstate {sqlstate}, got {got}",
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Frontend protocol helpers — same shape as slice_postgres_proxy.rs
// ---------------------------------------------------------------------------

async fn write_startup(s: &mut TcpStream) -> Result<()> {
    let mut body = Vec::new();
    body.extend_from_slice(&196608i32.to_be_bytes());
    body.extend_from_slice(b"user\0raxis\0\0");
    let len = (body.len() as i32) + 4;
    s.write_all(&len.to_be_bytes()).await?;
    s.write_all(&body).await?;
    Ok(())
}

async fn read_tagged_message(s: &mut TcpStream) -> Result<(u8, Vec<u8>)> {
    let mut tag = [0u8; 1];
    s.read_exact(&mut tag).await?;
    let mut len = [0u8; 4];
    s.read_exact(&mut len).await?;
    let len = i32::from_be_bytes(len);
    let body_len = (len as usize)
        .checked_sub(4)
        .ok_or_else(|| anyhow!("frame length {len} < 4"))?;
    let mut body = vec![0u8; body_len];
    s.read_exact(&mut body).await?;
    Ok((tag[0], body))
}

async fn drain_until_ready(s: &mut TcpStream) -> Result<Vec<(u8, Vec<u8>)>> {
    let mut acc = Vec::new();
    loop {
        let (t, b) = read_tagged_message(s).await?;
        let is_z = t == b'Z';
        acc.push((t, b));
        if is_z { return Ok(acc); }
    }
}

async fn write_query(s: &mut TcpStream, sql: &str) -> Result<()> {
    s.write_all(b"Q").await?;
    let mut body = Vec::new();
    body.extend_from_slice(sql.as_bytes());
    body.push(0);
    let len = (body.len() as i32) + 4;
    s.write_all(&len.to_be_bytes()).await?;
    s.write_all(&body).await?;
    Ok(())
}

async fn write_terminate(s: &mut TcpStream) -> Result<()> {
    s.write_all(b"X").await?;
    let len = 4i32;
    s.write_all(&len.to_be_bytes()).await?;
    Ok(())
}

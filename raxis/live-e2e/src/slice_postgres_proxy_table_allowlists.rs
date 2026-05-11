//! Slice — `PostgresProxy` enforces V2 `allowed_tables` /
//! `forbidden_tables` end-to-end against real Postgres wire bytes.
//!
//! Reference: `specs/v2/proxy-table-allowlists.md §5` (Postgres
//! walker + admit/deny path) and §8 (audit envelope additions).
//!
//! Wire bytes (frontend protocol — same harness shape as
//! `slice_postgres_proxy_restrictions.rs`):
//!
//!   1. StartupMessage → … → ReadyForQuery.
//!   2. `SELECT * FROM public.orders` — admitted by walker; in
//!      hermetic mode the upstream is unreachable so the SELECT
//!      surfaces sqlstate `08*` (connection_exception) instead of
//!      CommandComplete. The assertion is that the proxy did NOT
//!      reject this with `42501` — that would mean the walker
//!      misclassified an allowlisted table.
//!   3. `SELECT * FROM public.users` — NOT in `allowed_tables`;
//!      the proxy MUST reject with sqlstate `42501` and the audit
//!      `restriction_reason` MUST be `"table_not_in_allowed_list"`.
//!   4. `SELECT * FROM public.audit_log` — in `forbidden_tables`;
//!      the proxy MUST reject with sqlstate `42501` and
//!      `restriction_reason = "table_in_forbidden_list"`.
//!   5. `SELECT 1; DROP TABLE public.orders` — multi-statement
//!      batch, walker fail-closes per §5.2 (`D4`) with
//!      `restriction_reason = "ambiguous_sql_multi_statement"`.
//!   6. Terminate.
//!
//! The slice also drives a second proxy bound with `enforce =
//! false` to verify that audit-only mode admits the query but
//! still records `restriction_reason` in the audit channel.

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Mutex;

use anyhow::{anyhow, Result};
use raxis_credential_proxy_postgres::{
    AuditChannel, AuditEvent, OwnedConsumer, PostgresProxy, ProxyConfig,
    restriction::Restrictions,
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

/// Audit sink that buffers every `DatabaseQueryExecuted` so the
/// slice can assert `restriction_reason` was populated.
#[derive(Default)]
struct CapturingAudit {
    events: Mutex<Vec<AuditEvent>>,
}

impl AuditChannel for CapturingAudit {
    fn emit(&self, event: AuditEvent) {
        if let Ok(mut guard) = self.events.lock() {
            guard.push(event);
        }
    }
}

impl CapturingAudit {
    fn snapshot(&self) -> Vec<AuditEvent> {
        self.events.lock().map(|g| g.clone()).unwrap_or_default()
    }
}

pub(crate) async fn run() -> Result<()> {
    // No real upstream needed — the wire-side assertions only
    // require the proxy to enforce restrictions at its boundary.
    let upstream_url = b"postgresql://demo:demo@127.0.0.1:1/demo".to_vec();
    let backend = Arc::new(LiveBackend {
        value:    upstream_url,
        resolves: AtomicU32::new(0),
    });

    tracing::info!("slice postgres-proxy-table-allowlists: starting");

    // ── Phase 1: enforce = true (default) ─────────────────────────
    let audit = Arc::new(CapturingAudit::default());
    let cfg = ProxyConfig {
        listen_addr:     "127.0.0.1:0".to_owned(),
        credential_name: CredentialName::new("live-e2e"),
        consumer:        OwnedConsumer::new("credential_proxy", "live-e2e:postgres:t"),
        restrictions:    Restrictions {
            allowed_tables:   vec!["public.orders".into()],
            forbidden_tables: vec!["public.audit_log".into()],
            ..Default::default()
        },
    };
    let proxy = PostgresProxy::bind(backend.clone(), cfg, Arc::clone(&audit) as Arc<dyn AuditChannel>)
        .await
        .map_err(|e| anyhow!("PostgresProxy::bind: {e}"))?;
    let addr = proxy.local_addr()?;
    let stats = proxy.stats_handle();
    tokio::spawn(proxy.serve());

    let mut s = TcpStream::connect(addr).await?;
    write_startup(&mut s).await?;
    let msgs = drain_until_ready(&mut s).await?;
    if msgs.last().map(|(t, _)| *t) != Some(b'Z') {
        return Err(anyhow!("handshake did not end at ReadyForQuery"));
    }

    // ── Case A: allowlisted table — walker resolves cleanly. ──
    write_query(&mut s, "SELECT * FROM public.orders WHERE id = 1").await?;
    let msgs = drain_until_ready(&mut s).await?;
    let err_state = first_error_sqlstate(&msgs);
    if err_state.as_deref() == Some("42501") {
        return Err(anyhow!(
            "case A: SELECT from public.orders was wrongly rejected with 42501 \
             — walker failed to resolve an allowlisted table",
        ));
    }
    // Either CommandComplete or sqlstate 08* (upstream unreachable)
    // is acceptable.
    let tags: Vec<u8> = msgs.iter().map(|(t, _)| *t).collect();
    let connection_exc = err_state
        .as_deref()
        .map(|s| s.starts_with("08"))
        .unwrap_or(false);
    if !tags.contains(&b'C') && !connection_exc {
        return Err(anyhow!(
            "case A: expected CommandComplete or sqlstate 08*; tags={tags:?}, sqlstate={err_state:?}",
        ));
    }

    // ── Case B: not-in-allowlist — must reject with 42501. ──
    let blocks_before_b = stats.snapshot().queries_blocked;
    write_query(&mut s, "SELECT * FROM public.users").await?;
    let msgs = drain_until_ready(&mut s).await?;
    assert_error_with_sqlstate(&msgs, "42501", "case B: not-in-allowlist")?;
    if stats.snapshot().queries_blocked <= blocks_before_b {
        return Err(anyhow!("case B: queries_blocked did not increment"));
    }
    if stats.snapshot().queries_blocked_by_table_allowlist == 0 {
        return Err(anyhow!(
            "case B: queries_blocked_by_table_allowlist sub-counter did not increment",
        ));
    }

    // ── Case C: in forbidden list — must reject with 42501. ──
    let blocks_before_c = stats.snapshot().queries_blocked;
    write_query(&mut s, "SELECT * FROM public.audit_log").await?;
    let msgs = drain_until_ready(&mut s).await?;
    assert_error_with_sqlstate(&msgs, "42501", "case C: forbidden")?;
    if stats.snapshot().queries_blocked <= blocks_before_c {
        return Err(anyhow!("case C: queries_blocked did not increment"));
    }

    // ── Case D: multi-statement batch is ambiguous → fail-closed. ──
    let blocks_before_d = stats.snapshot().queries_blocked;
    write_query(&mut s, "SELECT * FROM public.orders; DROP TABLE public.orders").await?;
    let msgs = drain_until_ready(&mut s).await?;
    assert_error_with_sqlstate(&msgs, "42501", "case D: ambiguous")?;
    if stats.snapshot().queries_blocked <= blocks_before_d {
        return Err(anyhow!("case D: queries_blocked did not increment"));
    }
    if stats.snapshot().queries_blocked_by_ambiguous_sql == 0 {
        return Err(anyhow!(
            "case D: queries_blocked_by_ambiguous_sql sub-counter did not increment",
        ));
    }

    write_terminate(&mut s).await?;
    drop(s);

    // ── Audit assertions: restriction_reason was populated on the
    //    blocked events.
    let events = audit.snapshot();
    let reasons: Vec<Option<String>> = events.iter().filter_map(|e| match e {
        AuditEvent::DatabaseQueryExecuted { restriction_reason, blocked: true, .. } =>
            Some(restriction_reason.clone()),
        _ => None,
    }).collect();
    let expected: &[&str] = &[
        "table_not_in_allowed_list",
        "table_in_forbidden_list",
        "ambiguous_sql_multi_statement",
    ];
    for want in expected {
        if !reasons.iter().any(|r| r.as_deref().map(|s| s == *want).unwrap_or(false)) {
            return Err(anyhow!(
                "missing restriction_reason {want:?} in audit; got {reasons:?}",
            ));
        }
    }

    // ── Audit assertions: tables_referenced populated on blocked
    //    events that resolved their relations (cases B and C).
    let tables_seen: Vec<Vec<String>> = events.iter().filter_map(|e| match e {
        AuditEvent::DatabaseQueryExecuted { tables_referenced, blocked: true, .. } =>
            Some(tables_referenced.clone()),
        _ => None,
    }).collect();
    let saw_users     = tables_seen.iter().any(|t| t.iter().any(|s| s.contains("users")));
    let saw_audit_log = tables_seen.iter().any(|t| t.iter().any(|s| s.contains("audit_log")));
    if !saw_users {
        return Err(anyhow!(
            "audit did not record public.users in tables_referenced; got {tables_seen:?}",
        ));
    }
    if !saw_audit_log {
        return Err(anyhow!(
            "audit did not record public.audit_log in tables_referenced; got {tables_seen:?}",
        ));
    }

    // ── Phase 2: enforce = false (audit-only) ──────────────────────
    let audit2 = Arc::new(CapturingAudit::default());
    let cfg2 = ProxyConfig {
        listen_addr:     "127.0.0.1:0".to_owned(),
        credential_name: CredentialName::new("live-e2e"),
        consumer:        OwnedConsumer::new("credential_proxy", "live-e2e:postgres:t-audit"),
        restrictions:    Restrictions {
            allowed_tables: vec!["public.orders".into()],
            enforce:        false,
            ..Default::default()
        },
    };
    let proxy2 = PostgresProxy::bind(backend.clone(), cfg2, Arc::clone(&audit2) as Arc<dyn AuditChannel>)
        .await
        .map_err(|e| anyhow!("PostgresProxy::bind: {e}"))?;
    let addr2 = proxy2.local_addr()?;
    let stats2 = proxy2.stats_handle();
    tokio::spawn(proxy2.serve());

    let mut s2 = TcpStream::connect(addr2).await?;
    write_startup(&mut s2).await?;
    let _ = drain_until_ready(&mut s2).await?;

    // Audit-only: this query is NOT in the allowlist. Under
    // `enforce = false` the proxy MUST admit it (forward to
    // upstream) and surface `restriction_reason` in audit. In
    // hermetic mode the upstream connect fails with `08*` —
    // but the key assertion is that the proxy did NOT reject
    // with `42501`.
    write_query(&mut s2, "SELECT * FROM public.users").await?;
    let msgs2 = drain_until_ready(&mut s2).await?;
    let state2 = first_error_sqlstate(&msgs2);
    if state2.as_deref() == Some("42501") {
        return Err(anyhow!(
            "audit-only mode: proxy rejected with 42501 instead of admitting upstream",
        ));
    }
    if stats2.snapshot().queries_blocked != 0 {
        return Err(anyhow!(
            "audit-only mode: queries_blocked = {} (must be 0)",
            stats2.snapshot().queries_blocked,
        ));
    }
    let events2 = audit2.snapshot();
    let saw_audit_only = events2.iter().any(|e| matches!(e,
        AuditEvent::DatabaseQueryExecuted {
            restriction_reason: Some(s),
            blocked: false,
            ..
        } if s == "table_not_in_allowed_list"));
    if !saw_audit_only {
        return Err(anyhow!(
            "audit-only mode: expected DatabaseQueryExecuted with blocked=false and \
             restriction_reason=Some(\"table_not_in_allowed_list\") in audit; got {events2:?}",
        ));
    }

    write_terminate(&mut s2).await?;

    let snap = stats.snapshot();
    tracing::info!(
        "slice postgres-proxy-table-allowlists: PASS — \
         queries_audited={}, queries_blocked={} (≥3 expected), \
         queries_blocked_by_table_allowlist={}, queries_blocked_by_ambiguous_sql={}",
        snap.queries_audited, snap.queries_blocked,
        snap.queries_blocked_by_table_allowlist,
        snap.queries_blocked_by_ambiguous_sql,
    );
    Ok(())
}

fn first_error_sqlstate(msgs: &[(u8, Vec<u8>)]) -> Option<String> {
    let body = msgs.iter().find(|(t, _)| *t == b'E').map(|(_, b)| b)?;
    let mut i = 0;
    while i < body.len() && body[i] != 0 {
        let field_tag = body[i];
        i += 1;
        let mut end = i;
        while end < body.len() && body[end] != 0 { end += 1; }
        if field_tag == b'C' {
            return Some(std::str::from_utf8(&body[i..end]).unwrap_or("").to_owned());
        }
        i = end + 1;
    }
    None
}

fn assert_error_with_sqlstate(
    msgs:     &[(u8, Vec<u8>)],
    sqlstate: &str,
    label:    &str,
) -> Result<()> {
    let tags: Vec<u8> = msgs.iter().map(|(t, _)| *t).collect();
    if msgs.iter().any(|(t, _)| *t == b'C') {
        return Err(anyhow!(
            "{label}: unexpected CommandComplete (proxy let it through?); tags={tags:?}",
        ));
    }
    if tags.last() != Some(&b'Z') {
        return Err(anyhow!(
            "{label}: response did not end at ReadyForQuery; tags={tags:?}",
        ));
    }
    let got = first_error_sqlstate(msgs)
        .ok_or_else(|| anyhow!("{label}: ErrorResponse had no sqlstate; tags={tags:?}"))?;
    if got != sqlstate {
        return Err(anyhow!(
            "{label}: expected sqlstate {sqlstate}, got {got}",
        ));
    }
    Ok(())
}

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

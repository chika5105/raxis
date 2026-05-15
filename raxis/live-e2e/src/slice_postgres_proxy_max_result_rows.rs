//! Slice — `PostgresProxy` enforces `max_result_rows` against a
//! real `postgres:16-alpine` upstream end-to-end.
//!
//! Reference: `specs/v2/credential-proxy.md §4.2` (V2.2 streaming
//! row-cap) and `crates/credential-proxy-postgres/src/lib.rs::
//! apply_max_result_rows_cap` for the implementation contract:
//!
//!   * The cap is applied **after** the upstream's
//!     `RowDescription` and the first N `DataRow` messages have
//!     been forwarded to the agent.
//!   * Upon hitting row N+1 the proxy stops relaying, emits an
//!     `ErrorResponse` with sqlstate `54000`
//!     (`program_limit_exceeded`) carrying the
//!     `max_result_rows_exceeded` message, then `ReadyForQuery`.
//!   * `queries_capped_by_max_result_rows` increments by exactly 1.
//!   * `DatabaseQueryCompleted.upstream_error =
//!     Some("max_result_rows_exceeded")`.
//!
//! Why a separate slice: the existing `postgres-proxy*` slices
//! cover the verb-class filter and the table-allowlists, but
//! V2.2's streaming row cap was the third leg of the cap-paths
//! audit and had no real-upstream coverage. This slice closes
//! that gap by issuing `SELECT generate_series(1, 100)` against
//! a proxy bound with `max_result_rows = 5`, then asserting both
//! the wire-side truncation AND the counter.
//!
//! ## Active by default
//!
//! Mirrors the redis-proxy / mongodb-proxy-collection-allowlists
//! pattern: TCP-preflights `127.0.0.1:54399` (compose-stack
//! Postgres 16) and fails fast with an actionable error if the
//! container isn't running.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use raxis_credential_proxy_postgres::{
    restriction::Restrictions, AuditChannel, AuditEvent, OwnedConsumer, PostgresProxy, ProxyConfig,
};
use raxis_credentials::{
    ConsumerIdentity, CredentialBackend, CredentialError, CredentialName, CredentialValue, Lease,
    OperatorId,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Loopback host:port the docker-compose Postgres publishes.
/// Pinned to match `live-e2e/docker-compose.e2e.yml`.
const POSTGRES_HOST_PORT: &str = "127.0.0.1:54399";

/// Default upstream URL — the loopback published by
/// `live-e2e/docker-compose.e2e.yml` for the Postgres 16 container.
/// Operators can override via `RAXIS_LIVE_POSTGRES_URL`.
const DEFAULT_UPSTREAM_URL: &str =
    "postgresql://raxis_test:raxis_test_pass@127.0.0.1:54399/raxis_e2e";

/// Hard cap configured on the proxy under test. Picked small
/// enough that a `generate_series(1, 100)` blows past it on the
/// first response wave AND large enough that the cap-triggering
/// row doesn't land before any rows are sent (which would change
/// the wire-shape assertion to "ErrorResponse with no DataRows").
const MAX_RESULT_ROWS: u64 = 5;
const TOTAL_ROWS_GENERATED: u64 = 100;

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
    fn lease(&self, _name: &CredentialName) -> Lease {
        Lease::Forever
    }
    fn backend_kind(&self) -> &'static str {
        "live-e2e"
    }
}

/// Audit sink that buffers `DatabaseQueryCompleted` so the slice
/// can assert the `upstream_error` field carries the proxy's
/// canonical `max_result_rows_exceeded` marker.
#[derive(Default)]
struct CapturingAudit {
    events: Mutex<Vec<AuditEvent>>,
}

impl AuditChannel for CapturingAudit {
    fn emit(&self, event: AuditEvent) {
        if let Ok(mut g) = self.events.lock() {
            g.push(event);
        }
    }
}

impl CapturingAudit {
    fn snapshot(&self) -> Vec<AuditEvent> {
        self.events.lock().map(|g| g.clone()).unwrap_or_default()
    }
}

pub(crate) async fn run() -> Result<()> {
    require_postgres_container().await?;
    let env_override = std::env::var("RAXIS_LIVE_POSTGRES_URL").ok();
    let upstream_url = match env_override.as_deref() {
        Some(u) if !u.is_empty() => u.as_bytes().to_vec(),
        _ => DEFAULT_UPSTREAM_URL.as_bytes().to_vec(),
    };
    tracing::info!(
        host_port = POSTGRES_HOST_PORT,
        max_result_rows = MAX_RESULT_ROWS,
        total_rows_generated = TOTAL_ROWS_GENERATED,
        "slice postgres-proxy-max-result-rows: starting",
    );

    let backend = Arc::new(LiveBackend {
        value: upstream_url,
        resolves: AtomicU32::new(0),
    });
    let audit = Arc::new(CapturingAudit::default());
    let cfg = ProxyConfig {
        listen_addr: "127.0.0.1:0".to_owned(),
        credential_name: CredentialName::new("live-e2e"),
        consumer: OwnedConsumer::new("credential_proxy", "live-e2e:postgres:m"),
        restrictions: Restrictions {
            max_result_rows: MAX_RESULT_ROWS,
            ..Default::default()
        },
    };
    let proxy = PostgresProxy::bind(
        backend.clone(),
        cfg,
        Arc::clone(&audit) as Arc<dyn AuditChannel>,
    )
    .await
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

    // ── Cap-triggering query — `SELECT generate_series(1, 100)` returns
    //    100 DataRows; the proxy admits the first MAX_RESULT_ROWS of
    //    them, then truncates with ErrorResponse 54000. ──
    let sql = format!("SELECT n FROM generate_series(1, {TOTAL_ROWS_GENERATED}) AS t(n)",);
    write_query(&mut s, &sql).await?;
    let msgs = drain_until_ready(&mut s).await?;

    let tags: Vec<u8> = msgs.iter().map(|(t, _)| *t).collect();
    // The wire MUST contain:
    //   * RowDescription ('T') exactly once.
    //   * exactly MAX_RESULT_ROWS DataRow ('D') frames.
    //   * an ErrorResponse ('E') with sqlstate 54000.
    //   * NO CommandComplete ('C') for this query (the cap interrupts
    //     the stream before the upstream's CommandComplete arrives).
    //   * a terminal ReadyForQuery ('Z').
    let n_t: usize = tags.iter().filter(|&&t| t == b'T').count();
    let n_d: usize = tags.iter().filter(|&&t| t == b'D').count();
    let n_c: usize = tags.iter().filter(|&&t| t == b'C').count();
    let n_e: usize = tags.iter().filter(|&&t| t == b'E').count();
    if n_t != 1 {
        return Err(anyhow!(
            "expected exactly 1 RowDescription frame, got {n_t}; tags={tags:?}",
        ));
    }
    if n_d as u64 != MAX_RESULT_ROWS {
        return Err(anyhow!(
            "expected exactly {MAX_RESULT_ROWS} DataRow frames, got {n_d}; tags={tags:?}",
        ));
    }
    if n_e != 1 {
        return Err(anyhow!(
            "expected exactly 1 ErrorResponse frame, got {n_e}; tags={tags:?}",
        ));
    }
    if n_c != 0 {
        return Err(anyhow!(
            "expected NO CommandComplete (cap interrupted the stream), got {n_c}; tags={tags:?}",
        ));
    }
    if tags.last() != Some(&b'Z') {
        return Err(anyhow!(
            "expected terminal ReadyForQuery, got tags={tags:?}",
        ));
    }

    let sqlstate = first_error_sqlstate(&msgs)
        .ok_or_else(|| anyhow!("ErrorResponse missing sqlstate field"))?;
    if sqlstate != "54000" {
        return Err(anyhow!(
            "expected sqlstate 54000 (program_limit_exceeded), got {sqlstate}",
        ));
    }
    let err_message = first_error_message(&msgs);
    if !err_message
        .as_deref()
        .unwrap_or("")
        .contains("max_result_rows_exceeded")
    {
        return Err(anyhow!(
            "ErrorResponse message did not contain `max_result_rows_exceeded`; got {err_message:?}",
        ));
    }

    // ── Counter assertion. ──
    let snap = stats.snapshot();
    if snap.queries_capped_by_max_result_rows != 1 {
        return Err(anyhow!(
            "queries_capped_by_max_result_rows must be exactly 1, got {}",
            snap.queries_capped_by_max_result_rows,
        ));
    }
    // The cap is NOT a blocked-query (the query was admitted upstream,
    // it just truncated mid-stream). `queries_blocked` therefore
    // stays at 0.
    if snap.queries_blocked != 0 {
        return Err(anyhow!(
            "queries_blocked must stay 0 for a max-rows cap event, got {}",
            snap.queries_blocked,
        ));
    }
    // Both queries got audited (one DatabaseQueryCompleted with the
    // cap message + the surrounding handshake's ReadyForQuery).
    if snap.queries_audited != 1 {
        return Err(anyhow!(
            "queries_audited must be exactly 1, got {}",
            snap.queries_audited,
        ));
    }

    // ── Audit-channel assertion: the `DatabaseQueryCompleted`
    //    event MUST carry `upstream_error =
    //    Some("max_result_rows_exceeded")`. ──
    let events = audit.snapshot();
    let saw_cap_audit = events.iter().any(|e| {
        matches!(e,
            AuditEvent::DatabaseQueryCompleted {
                upstream_error: Some(s), ..
            } if s == "max_result_rows_exceeded"
        )
    });
    if !saw_cap_audit {
        let kinds: Vec<_> = events
            .iter()
            .map(|e| match e {
                AuditEvent::DatabaseQueryCompleted { upstream_error, .. } => {
                    format!("DatabaseQueryCompleted({upstream_error:?})")
                }
                other => format!("{other:?}"),
            })
            .collect();
        return Err(anyhow!(
            "audit channel did not see DatabaseQueryCompleted with \
             upstream_error=\"max_result_rows_exceeded\"; got: {kinds:?}",
        ));
    }

    write_terminate(&mut s).await?;

    tracing::info!(
        queries_audited = snap.queries_audited,
        queries_capped_by_max_result_rows = snap.queries_capped_by_max_result_rows,
        rowdesc = n_t,
        datarows = n_d,
        backend_resolves = backend.resolves.load(Ordering::Relaxed),
        "postgres-proxy-max-result-rows slice OK",
    );
    Ok(())
}

async fn require_postgres_container() -> Result<()> {
    match tokio::time::timeout(
        Duration::from_secs(2),
        TcpStream::connect(POSTGRES_HOST_PORT),
    )
    .await
    {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(e)) => Err(anyhow!(
            "postgres container not reachable at {POSTGRES_HOST_PORT}: {e}\n\
             hint: docker compose -f live-e2e/docker-compose.e2e.yml up -d postgres --wait",
        )),
        Err(_) => Err(anyhow!(
            "postgres container not reachable at {POSTGRES_HOST_PORT}: timed out after 2s\n\
             hint: docker compose -f live-e2e/docker-compose.e2e.yml up -d postgres --wait",
        )),
    }
}

// ---------------------------------------------------------------------------
// Postgres v3 frontend wire helpers (mirror those in
// `slice_postgres_proxy_table_allowlists.rs`).
// ---------------------------------------------------------------------------

fn first_error_sqlstate(msgs: &[(u8, Vec<u8>)]) -> Option<String> {
    let body = msgs.iter().find(|(t, _)| *t == b'E').map(|(_, b)| b)?;
    let mut i = 0;
    while i < body.len() && body[i] != 0 {
        let field_tag = body[i];
        i += 1;
        let mut end = i;
        while end < body.len() && body[end] != 0 {
            end += 1;
        }
        if field_tag == b'C' {
            return Some(std::str::from_utf8(&body[i..end]).unwrap_or("").to_owned());
        }
        i = end + 1;
    }
    None
}

fn first_error_message(msgs: &[(u8, Vec<u8>)]) -> Option<String> {
    let body = msgs.iter().find(|(t, _)| *t == b'E').map(|(_, b)| b)?;
    let mut i = 0;
    while i < body.len() && body[i] != 0 {
        let field_tag = body[i];
        i += 1;
        let mut end = i;
        while end < body.len() && body[end] != 0 {
            end += 1;
        }
        if field_tag == b'M' {
            return Some(std::str::from_utf8(&body[i..end]).unwrap_or("").to_owned());
        }
        i = end + 1;
    }
    None
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
    if len < 4 || len > 64 * 1024 * 1024 {
        return Err(anyhow!("backend frame length out of range: {len}"));
    }
    let body_len = (len as usize) - 4;
    let mut body = vec![0u8; body_len];
    s.read_exact(&mut body).await.context("read backend body")?;
    Ok((tag[0], body))
}

async fn drain_until_ready(s: &mut TcpStream) -> Result<Vec<(u8, Vec<u8>)>> {
    let mut acc = Vec::new();
    loop {
        let (t, b) = read_tagged_message(s).await?;
        let is_z = t == b'Z';
        acc.push((t, b));
        if is_z {
            return Ok(acc);
        }
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

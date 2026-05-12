//! Slice — real `MssqlProxy` driving the V2.1 real-upstream-forwarding
//! contract against a real SQL Server 2022 container.
//!
//! ## Active by default — no env-var gate
//!
//! As of the credproxy-gap-closer worker (post the
//! `rewrite_sql_batch_for_upstream` ALL_HEADERS rebuild in
//! `crates/credential-proxy-mssql/src/upstream.rs`), the slice
//! exercises the **real upstream forwarding path** by default
//! against the compose stack's `127.0.0.1:14399` SQL Server 2022
//! container. Bring the stack up first:
//!
//! ```sh
//! docker compose -f live-e2e/docker-compose.e2e.yml up -d mssql --wait
//! cargo run -p raxis-live-e2e -- mssql-proxy
//! ```
//!
//! Plaintext TDS only — `?encrypt=true` is rejected at the proxy's
//! `connect()`. The slice TCP-preflights the container and refuses
//! to start with an actionable error message if it isn't reachable.
//!
//! Operators that need a different upstream (e.g. an Azure SQL
//! endpoint for non-CI debugging) can set
//! `RAXIS_LIVE_MSSQL_URL=mssql://user:pass@host:port/db?encrypt=false`
//! to override the default compose URL. The slice does NOT support
//! a hermetic / no-container mode anymore; the upstream-failure
//! audit path is covered by the unit tests in
//! `crates/credential-proxy-mssql/src/upstream.rs::tests`.
//!
//! ## What the slice asserts
//!
//! 1. PRELOGIN ↔ LOGIN7 ↔ LOGINACK + DONE succeeds (proxy-local).
//! 2. `SQLBatch "SELECT 1"` round-trips real `COLMETADATA + ROW
//!    + DONE` tokens — assertion: `upstream_connects_succeeded ≥ 1`,
//!    no ERROR token in the reply.
//! 3. `SQLBatch "INSERT INTO t VALUES (1)"` is rejected at the
//!    restriction layer BEFORE upstream — assertion: ERROR + DONE.
//! 4. Counters: `connections_served ≥ 1`, `queries_audited == 2`,
//!    `queries_blocked == 1`.

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use raxis_credentials::{
    ConsumerIdentity, CredentialBackend, CredentialError, CredentialName, CredentialValue,
    Lease, OperatorId,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use raxis_credential_proxy_mssql::{
    NoopAuditChannel, OwnedConsumer, ProxyConfig, MssqlProxy, Restrictions,
    wire::{frame_packet, PacketHeader, pkt as tds_pkt, HEADER_LEN},
};

/// Default upstream URL — the loopback published by
/// `live-e2e/docker-compose.e2e.yml` for the SQL Server 2022
/// container. Operators can override via `RAXIS_LIVE_MSSQL_URL`.
const DEFAULT_UPSTREAM_URL: &str =
    "mssql://sa:raxis_Test_Pass1!@127.0.0.1:14399/master?encrypt=false";

/// Loopback host:port the docker-compose SQL Server publishes;
/// used for the slice's TCP preflight.
const MSSQL_HOST_PORT: &str = "127.0.0.1:14399";

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

pub async fn run() -> Result<()> {
    let env_override = std::env::var("RAXIS_LIVE_MSSQL_URL").ok();
    let (upstream_url, source) = match env_override.as_deref() {
        Some(u) if !u.is_empty() => (u.to_owned(), "RAXIS_LIVE_MSSQL_URL override"),
        _ => (DEFAULT_UPSTREAM_URL.to_owned(), "compose-stack default"),
    };
    tracing::info!(
        host_port = MSSQL_HOST_PORT,
        url_source = source,
        "slice mssql-proxy: starting (real-upstream, active by default)",
    );

    require_mssql_container().await?;
    // Hermetic flag retained as a `false` constant so the rest of
    // the slice's audit-counter assertions do not need to branch.
    let hermetic = false;

    let backend = Arc::new(LiveBackend {
        value:    upstream_url.as_bytes().to_vec(),
        resolves: AtomicU32::new(0),
    });

    let credential_name = CredentialName::try_from("live-e2e".to_owned())
        .map_err(|e| anyhow!("CredentialName: {e}"))?;
    let cfg = ProxyConfig {
        listen_addr:     "127.0.0.1:0".to_owned(),
        credential_name: credential_name.clone(),
        consumer:        OwnedConsumer::new("live-e2e", "mssql-slice"),
        server_version:  "raxis-mssql-handshake".to_owned(),
        restrictions:    Restrictions::select_only(),
        log_content:     false,
    };

    let proxy = MssqlProxy::bind(
        Arc::clone(&backend) as Arc<dyn CredentialBackend>,
        cfg,
        Arc::new(NoopAuditChannel::default()),
    )
    .await
    .context("MssqlProxy::bind")?;
    let proxy_addr = proxy.local_addr().context("local_addr")?;
    let stats = proxy.stats_handle();
    let proxy_handle = tokio::spawn(async move { proxy.serve().await });

    tokio::time::sleep(Duration::from_millis(50)).await;

    let mut sock = TcpStream::connect(proxy_addr).await
        .context("connect to MssqlProxy")?;

    // 1. PRELOGIN — send a minimal stub. The proxy doesn't validate
    //    options; it just needs to see the packet type.
    let prelogin_body = build_minimal_prelogin();
    sock.write_all(&frame_packet(tds_pkt::PRELOGIN, &prelogin_body)).await
        .context("write PRELOGIN")?;
    sock.flush().await?;

    let prelogin_reply = read_packet(&mut sock).await
        .context("read PRELOGIN reply")?
        .ok_or_else(|| anyhow!("EOF before PRELOGIN reply"))?;
    if prelogin_reply.0.packet_type != tds_pkt::TABULAR_RESULT {
        return Err(anyhow!(
            "PRELOGIN reply packet_type {:#04x} != TABULAR_RESULT",
            prelogin_reply.0.packet_type,
        ));
    }
    // Body sanity-check: VERSION (0x00) + ENCRYPTION (0x01) + terminator (0xff).
    if prelogin_reply.1.first().copied() != Some(0x00) {
        return Err(anyhow!("PRELOGIN reply body did not start with VERSION option"));
    }
    if !prelogin_reply.1.contains(&0xff) {
        return Err(anyhow!("PRELOGIN reply body missing terminator byte 0xff"));
    }

    // 2. LOGIN7 — minimal payload. The proxy discards the contents,
    //    but the framing must parse.
    let login7_body = build_minimal_login7();
    sock.write_all(&frame_packet(tds_pkt::LOGIN7, &login7_body)).await
        .context("write LOGIN7")?;
    sock.flush().await?;

    let login_reply = read_packet(&mut sock).await
        .context("read LOGINACK reply")?
        .ok_or_else(|| anyhow!("EOF before LOGINACK"))?;
    if login_reply.0.packet_type != tds_pkt::TABULAR_RESULT {
        return Err(anyhow!(
            "LOGIN7 reply packet_type {:#04x} != TABULAR_RESULT",
            login_reply.0.packet_type,
        ));
    }
    if login_reply.1.first().copied() != Some(0xAD) {
        return Err(anyhow!(
            "LOGIN7 reply did not start with LOGINACK token (0xAD), got {:#04x}",
            login_reply.1.first().copied().unwrap_or(0),
        ));
    }

    // 3. SQLBatch "SELECT 1" — exercises upstream-forwarding path.
    //    Hermetic mode: upstream is unreachable, so the proxy
    //    surfaces an ERROR (0xAA) + DONE_ERROR token sequence to
    //    the agent. Real-upstream mode: COLMETADATA + ROW + DONE
    //    flow through verbatim.
    let select_body = build_sql_batch_body("SELECT 1");
    sock.write_all(&frame_packet(tds_pkt::SQL_BATCH, &select_body)).await
        .context("write SQLBatch SELECT")?;
    sock.flush().await?;
    let sel_reply = read_packet(&mut sock).await
        .context("read SELECT reply")?
        .ok_or_else(|| anyhow!("EOF after SELECT"))?;
    let has_error = sel_reply.1.iter().any(|&b| b == 0xAA);
    let has_done  = sel_reply.1.iter().any(|&b| b == 0xFD);
    let _ = hermetic;
    if has_error {
        return Err(anyhow!(
            "SELECT reply contained ERROR token (0xAA) — upstream may have rejected the query"
        ));
    }
    if !has_done {
        return Err(anyhow!(
            "SELECT reply missing DONE token (0xFD)"
        ));
    }

    // 4. SQLBatch "INSERT INTO t VALUES (1)" — must yield ERROR + DONE.
    let insert_body = build_sql_batch_body("INSERT INTO t VALUES (1)");
    sock.write_all(&frame_packet(tds_pkt::SQL_BATCH, &insert_body)).await
        .context("write SQLBatch INSERT")?;
    sock.flush().await?;
    let ins_reply = read_packet(&mut sock).await
        .context("read INSERT reply")?
        .ok_or_else(|| anyhow!("EOF after INSERT"))?;
    if ins_reply.1.first().copied() != Some(0xAA) {
        return Err(anyhow!(
            "INSERT reply did not start with ERROR token (0xAA), got {:#04x}",
            ins_reply.1.first().copied().unwrap_or(0),
        ));
    }
    if !ins_reply.1.iter().any(|&b| b == 0xFD) {
        return Err(anyhow!("INSERT reply missing DONE token"));
    }

    drop(sock);

    // 5. Verify counters.
    let snap = stats.snapshot();
    if snap.connections_served < 1 {
        return Err(anyhow!(
            "expected ≥1 connection_served, got {}", snap.connections_served,
        ));
    }
    if snap.queries_audited != 2 {
        return Err(anyhow!(
            "expected queries_audited=2, got {}", snap.queries_audited,
        ));
    }
    if snap.queries_blocked != 1 {
        return Err(anyhow!(
            "expected queries_blocked=1, got {}", snap.queries_blocked,
        ));
    }
    if backend.resolves.load(Ordering::Relaxed) < 1 {
        return Err(anyhow!(
            "expected ≥1 CredentialBackend::resolve call, got 0",
        ));
    }
    if snap.upstream_connects_succeeded < 1 {
        return Err(anyhow!(
            "expected upstream_connects_succeeded≥1, got {}",
            snap.upstream_connects_succeeded,
        ));
    }

    proxy_handle.abort();
    let _ = proxy_handle.await;

    tracing::info!(
        connections_served = snap.connections_served,
        queries_audited    = snap.queries_audited,
        queries_blocked    = snap.queries_blocked,
        upstream_succeeded = snap.upstream_connects_succeeded,
        upstream_failed    = snap.upstream_connects_failed,
        backend_resolves   = backend.resolves.load(Ordering::Relaxed),
        "mssql-proxy slice OK",
    );
    Ok(())
}

/// Build a minimal PRELOGIN body. We send a single VERSION option
/// followed by the terminator. The proxy's PRELOGIN reader only
/// requires that the packet type is `0x12` and that the body parses.
fn build_minimal_prelogin() -> Vec<u8> {
    // Two options + terminator, mirroring the proxy's reply shape so
    // the wire is symmetric.
    let mut body = Vec::with_capacity(18);
    // VERSION option header: type=0x00, offset=11 BE, length=6 BE.
    body.push(0x00);
    body.extend_from_slice(&11u16.to_be_bytes());
    body.extend_from_slice(&6u16.to_be_bytes());
    // ENCRYPTION option header: type=0x01, offset=17 BE, length=1 BE.
    body.push(0x01);
    body.extend_from_slice(&17u16.to_be_bytes());
    body.extend_from_slice(&1u16.to_be_bytes());
    // Terminator.
    body.push(0xff);
    // VERSION data: 15.0.4153.1.
    body.push(15);
    body.push(0);
    body.extend_from_slice(&4153u16.to_le_bytes());
    body.extend_from_slice(&1u16.to_le_bytes());
    // ENCRYPTION data: 0 = encryption off.
    body.push(0);
    body
}

/// Build a minimal LOGIN7 body. The proxy discards the contents;
/// we only need the framing to parse cleanly, which means the
/// 36-byte header (length + version + several offsets) must be
/// present. We zero-fill everything that isn't `length`.
fn build_minimal_login7() -> Vec<u8> {
    // The TDS spec defines a fixed 36-byte LOGIN7 prelude that the
    // proxy drains; the rest is a variable-length section the V2
    // proxy ignores. We send exactly the 36-byte prelude.
    let mut body = Vec::with_capacity(36);
    let total_len: u32 = 36;
    body.extend_from_slice(&total_len.to_le_bytes());
    // tds_version = 7.4 (0x74000004 BE per spec).
    body.extend_from_slice(&0x74000004u32.to_be_bytes());
    // packet_size, client_prog_ver, client_pid, conn_id, opt_flags1..4,
    // type_flags, client_time_zone, client_lcid — 28 bytes of zeros.
    body.extend_from_slice(&[0u8; 28]);
    body
}

/// Build a SQLBatch body: ALL_HEADERS preamble (4 bytes — length
/// only) followed by UTF-16 LE SQL text.
fn build_sql_batch_body(sql: &str) -> Vec<u8> {
    let mut body = Vec::with_capacity(4 + sql.len() * 2);
    body.extend_from_slice(&4u32.to_le_bytes());
    for u in sql.encode_utf16() {
        body.extend_from_slice(&u.to_le_bytes());
    }
    body
}

/// TCP-preflight the SQL Server container.
async fn require_mssql_container() -> Result<()> {
    match tokio::time::timeout(
        Duration::from_secs(2),
        TcpStream::connect(MSSQL_HOST_PORT),
    ).await {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(e)) => Err(anyhow!(
            "mssql container not reachable at {MSSQL_HOST_PORT}: {e}\n\
             hint: docker compose -f live-e2e/docker-compose.e2e.yml up -d mssql --wait",
        )),
        Err(_) => Err(anyhow!(
            "mssql container not reachable at {MSSQL_HOST_PORT}: timed out after 2s\n\
             hint: docker compose -f live-e2e/docker-compose.e2e.yml up -d mssql --wait",
        )),
    }
}

async fn read_packet(sock: &mut TcpStream) -> Result<Option<(PacketHeader, Vec<u8>)>> {
    let mut header_buf = [0u8; HEADER_LEN];
    if let Err(e) = sock.read_exact(&mut header_buf).await {
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            return Ok(None);
        }
        return Err(e.into());
    }
    let h = PacketHeader::parse(header_buf);
    if (h.length as usize) < HEADER_LEN {
        return Err(anyhow!(
            "TDS packet length {} smaller than header", h.length,
        ));
    }
    let body_len = (h.length as usize) - HEADER_LEN;
    let mut body = vec![0u8; body_len];
    sock.read_exact(&mut body).await
        .context("read TDS body")?;
    Ok(Some((h, body)))
}


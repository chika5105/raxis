//! Slice — real `MssqlProxy` driving the V2 handshake-tier MVP.
//!
//! Why no in-process upstream MSSQL: per `credential-proxy.md §4.3`,
//! the V2 MVP for MSSQL is a handshake-tier integration. The proxy
//! drives `PRELOGIN → LOGIN7 → LOGINACK + DONE` on its own bytes
//! (no `sqlservr` is contacted). What the live-e2e slice asserts is
//! the proxy's *visible* behaviour to a real TDS client:
//!
//!   1. PRELOGIN reaches the synthetic VERSION + ENCRYPTION reply.
//!   2. LOGIN7 yields a Tabular Result with a LOGINACK + DONE.
//!   3. SQLBatch "SELECT 1" yields a DONE token (allow path).
//!   4. SQLBatch "INSERT INTO t VALUES (1)" yields an ERROR token
//!      followed by DONE (deny path under `allow_only_select`).
//!   5. Counters reflect 1 connection_served, 2 queries_audited,
//!      1 queries_blocked.
//!   6. The `CredentialBackend` is asked at least once per
//!      connection.

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

const UPSTREAM_PASS: &str = "live-e2e-mssql-creds-bytes";

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
    let backend = Arc::new(LiveBackend {
        value:    UPSTREAM_PASS.as_bytes().to_vec(),
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

    // 3. SQLBatch "SELECT 1" — should yield DONE (no ERROR).
    let select_body = build_sql_batch_body("SELECT 1");
    sock.write_all(&frame_packet(tds_pkt::SQL_BATCH, &select_body)).await
        .context("write SQLBatch SELECT")?;
    sock.flush().await?;
    let sel_reply = read_packet(&mut sock).await
        .context("read SELECT reply")?
        .ok_or_else(|| anyhow!("EOF after SELECT"))?;
    if sel_reply.1.iter().any(|&b| b == 0xAA) {
        return Err(anyhow!("SELECT reply contained ERROR token"));
    }
    if !sel_reply.1.iter().any(|&b| b == 0xFD) {
        return Err(anyhow!("SELECT reply missing DONE token"));
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

    proxy_handle.abort();
    let _ = proxy_handle.await;

    tracing::info!(
        connections_served = snap.connections_served,
        queries_audited    = snap.queries_audited,
        queries_blocked    = snap.queries_blocked,
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

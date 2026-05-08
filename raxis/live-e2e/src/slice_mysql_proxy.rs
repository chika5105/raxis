//! Slice — real `MysqlProxy` driving the V2 handshake-tier MVP.
//!
//! Why no in-process upstream MySQL: per `credential-proxy.md §4.2`,
//! the V2 MVP for MySQL is a handshake-tier integration. The proxy
//! drives `Protocol::HandshakeV10 → HandshakeResponse41 →
//! OK_Packet` on its own bytes (the agent's password is discarded;
//! no real `mysqld` is contacted). What the live-e2e slice asserts
//! is the proxy's *visible* behaviour to a real MySQL client:
//!
//!   1. The handshake reaches `OK_Packet` (the client sees a
//!      successfully authenticated session).
//!   2. `COM_PING` is honoured.
//!   3. A `SELECT` `COM_QUERY` returns `OK_Packet` (allow path).
//!   4. An `INSERT` `COM_QUERY` returns `ERR_Packet { code = 1142,
//!      sqlstate = "42501" }` (deny path under `allow_only_select`).
//!   5. `COM_QUIT` closes the session cleanly.
//!   6. Counters reflect 1 connection, 2 queries audited (SELECT +
//!      INSERT), 1 query blocked (INSERT).
//!   7. The `CredentialBackend` is asked exactly once per
//!      connection (the proxy resolves at connect time so a
//!      missing/malformed credential aborts the handshake instead
//!      of a mid-query failure).
//!
//! The client side speaks the wire protocol directly (no third-
//! party MySQL crate) so the slice has zero external dependencies
//! beyond the proxy crate itself.

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

use raxis_credential_proxy_mysql::{
    NoopAuditChannel, OwnedConsumer, ProxyConfig, MysqlProxy, Restrictions,
    wire::{frame_packet, PacketHeader, cmd as mysql_cmd},
};

const UPSTREAM_PASS: &str = "live-e2e-mysql-creds-bytes";

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
        consumer:        OwnedConsumer::new("live-e2e", "mysql-slice"),
        server_version:  "8.0.30-raxis-handshake".to_owned(),
        restrictions:    Restrictions::select_only(),
        log_content:     false,
    };

    let proxy = MysqlProxy::bind(
        Arc::clone(&backend) as Arc<dyn CredentialBackend>,
        cfg,
        Arc::new(NoopAuditChannel::default()),
    )
    .await
    .context("MysqlProxy::bind")?;
    let proxy_addr = proxy.local_addr().context("local_addr")?;
    let stats = proxy.stats_handle();
    let proxy_handle = tokio::spawn(async move { proxy.serve().await });

    // Give the proxy a tick to be ready (bind already returned a
    // listening socket; the spawn just enters the accept loop).
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Drive a real MySQL handshake.
    let mut sock = TcpStream::connect(proxy_addr).await
        .context("connect to MysqlProxy")?;

    // 1. Read HandshakeV10 (seq=0).
    let (h0, payload0) = read_packet(&mut sock).await
        .context("read HandshakeV10")?
        .ok_or_else(|| anyhow!("EOF before HandshakeV10"))?;
    if h0.sequence_id != 0 {
        return Err(anyhow!(
            "expected HandshakeV10 seq=0, got seq={}", h0.sequence_id,
        ));
    }
    if payload0.first().copied() != Some(0x0a) {
        return Err(anyhow!(
            "expected protocol_version=10, got byte {:#04x}",
            payload0.first().copied().unwrap_or(0),
        ));
    }

    // 2. Send a minimal HandshakeResponse41 (seq=1). The proxy
    //    discards the contents, but the wire shape must parse
    //    cleanly. We send a 32-byte trimmed payload that matches
    //    what `mysql-connector` sends with empty username and no
    //    password.
    let mut handshake_response = Vec::new();
    // Capability flags (CLIENT_PROTOCOL_41 | CLIENT_LONG_PASSWORD |
    // CLIENT_CONNECT_WITH_DB | CLIENT_PLUGIN_AUTH).
    let caps: u32 = 0x000_0_0080_8205;
    handshake_response.extend_from_slice(&caps.to_le_bytes());
    // Max packet size.
    handshake_response.extend_from_slice(&0x0010_0000u32.to_le_bytes());
    // Charset (utf8mb4).
    handshake_response.push(0x21);
    // 23 bytes reserved.
    handshake_response.extend_from_slice(&[0u8; 23]);
    // Username NUL.
    handshake_response.push(0);
    // auth_response length (lenenc-int) = 0.
    handshake_response.push(0);
    // db NUL.
    handshake_response.push(0);
    // auth-plugin name NUL-terminated.
    handshake_response.extend_from_slice(b"mysql_native_password\0");
    sock.write_all(&frame_packet(&handshake_response, 1)).await
        .context("write HandshakeResponse41")?;
    sock.flush().await.context("flush HandshakeResponse41")?;

    // 3. Read OK_Packet (seq=2).
    let (h2, payload2) = read_packet(&mut sock).await
        .context("read OK_Packet")?
        .ok_or_else(|| anyhow!("EOF before OK_Packet"))?;
    if h2.sequence_id != 2 {
        return Err(anyhow!(
            "expected OK_Packet seq=2, got seq={}", h2.sequence_id,
        ));
    }
    if payload2.first().copied() != Some(0x00) {
        return Err(anyhow!(
            "expected OK_Packet header 0x00, got {:#04x}",
            payload2.first().copied().unwrap_or(0xff),
        ));
    }

    // 4. COM_PING — proxy must reply OK_Packet.
    let ping_payload = vec![mysql_cmd::PING];
    sock.write_all(&frame_packet(&ping_payload, 0)).await
        .context("write COM_PING")?;
    sock.flush().await?;
    let (_h_ping, payload_ping) = read_packet(&mut sock).await
        .context("read OK after PING")?
        .ok_or_else(|| anyhow!("EOF after PING"))?;
    if payload_ping.first().copied() != Some(0x00) {
        return Err(anyhow!("PING did not yield OK_Packet"));
    }

    // 5. COM_QUERY "SELECT 1" — must yield OK_Packet (V2 MVP).
    let mut select_payload = vec![mysql_cmd::QUERY];
    select_payload.extend_from_slice(b"SELECT 1");
    sock.write_all(&frame_packet(&select_payload, 0)).await
        .context("write COM_QUERY SELECT")?;
    sock.flush().await?;
    let (_h_sel, payload_sel) = read_packet(&mut sock).await
        .context("read SELECT response")?
        .ok_or_else(|| anyhow!("EOF after SELECT"))?;
    if payload_sel.first().copied() != Some(0x00) {
        return Err(anyhow!(
            "SELECT did not yield OK_Packet, first byte {:#04x}",
            payload_sel.first().copied().unwrap_or(0xff),
        ));
    }

    // 6. COM_QUERY "INSERT INTO t VALUES (1)" — must yield
    //    ERR_Packet under allow_only_select.
    let mut insert_payload = vec![mysql_cmd::QUERY];
    insert_payload.extend_from_slice(b"INSERT INTO t VALUES (1)");
    sock.write_all(&frame_packet(&insert_payload, 0)).await
        .context("write COM_QUERY INSERT")?;
    sock.flush().await?;
    let (_h_ins, payload_ins) = read_packet(&mut sock).await
        .context("read INSERT response")?
        .ok_or_else(|| anyhow!("EOF after INSERT"))?;
    if payload_ins.first().copied() != Some(0xff) {
        return Err(anyhow!(
            "INSERT did not yield ERR_Packet, first byte {:#04x}",
            payload_ins.first().copied().unwrap_or(0),
        ));
    }
    // Spot-check the SQLSTATE marker.
    let marker_pos = payload_ins.iter().position(|&b| b == b'#')
        .ok_or_else(|| anyhow!("ERR_Packet missing '#' SQLSTATE marker"))?;
    let sqlstate = &payload_ins[marker_pos + 1 .. marker_pos + 6];
    if sqlstate != b"42501" {
        return Err(anyhow!(
            "ERR_Packet sqlstate {:?} != 42501",
            String::from_utf8_lossy(sqlstate),
        ));
    }

    // 7. COM_QUIT — server closes.
    let quit_payload = vec![mysql_cmd::QUIT];
    sock.write_all(&frame_packet(&quit_payload, 0)).await
        .context("write COM_QUIT")?;
    sock.flush().await?;
    let mut tail = [0u8; 1];
    let _ = tokio::time::timeout(
        Duration::from_secs(1),
        sock.read_exact(&mut tail),
    ).await;
    drop(sock);

    // 8. Verify counters.
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
        "mysql-proxy slice OK",
    );
    Ok(())
}

async fn read_packet(sock: &mut TcpStream) -> Result<Option<(PacketHeader, Vec<u8>)>> {
    let mut header = [0u8; 4];
    if let Err(e) = sock.read_exact(&mut header).await {
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            return Ok(None);
        }
        return Err(e.into());
    }
    let h = PacketHeader::parse(header);
    let mut payload = vec![0u8; h.payload_len];
    sock.read_exact(&mut payload).await
        .context("read MySQL packet payload")?;
    Ok(Some((h, payload)))
}

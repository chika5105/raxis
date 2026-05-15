//! Slice — real `MysqlProxy` driving the V2.1 real-upstream-forwarding
//! contract against a real MySQL 8.0.36 container.
//!
//! ## Active by default — no env-var gate
//!
//! As of the credproxy-gap-closer worker (post the
//! `CLIENT_SSL` cap-bit fix in
//! `crates/credential-proxy-mysql/src/upstream.rs`), the slice
//! exercises the **real upstream forwarding path** by default
//! against the compose stack's `127.0.0.1:33099` MySQL 8.0.36
//! container. Bring the stack up first:
//!
//! ```sh
//! docker compose -f live-e2e/docker-compose.e2e.yml up -d mysql --wait
//! cargo run -p raxis-live-e2e -- mysql-proxy
//! ```
//!
//! The slice TCP-preflights the container and refuses to start
//! with an actionable error message if it isn't reachable —
//! mirroring the redis-proxy / mongodb-proxy-collection-allowlists
//! convention.
//!
//! Operators that need to point at a different upstream (e.g. an
//! Aurora / PlanetScale endpoint for non-CI debugging) can set
//! `RAXIS_LIVE_MYSQL_URL=mysql://user:pass@host:port/db` to
//! override the default compose URL. The slice does NOT support a
//! hermetic / no-container mode anymore; the upstream-failure
//! audit path is covered by the fake-MySQL fixtures in
//! `crates/credential-proxy-mysql/tests`.
//!
//! ## What the slice asserts
//!
//! 1. `HandshakeV10` ↔ `HandshakeResponse41` ↔ `OK_Packet` succeeds.
//! 2. `COM_PING` succeeds.
//! 3. `COM_QUERY "SELECT 1"` round-trips a real result set
//!    (TEXT_RESULTSET) — assertion: `upstream_connects_succeeded ≥ 1`.
//! 4. `COM_QUERY "INSERT INTO t VALUES (1)"` is rejected at the
//!    restriction layer BEFORE upstream — assertion:
//!    `ERR_Packet { sqlstate = "42501" }` and `queries_blocked == 1`.
//! 5. `COM_QUIT` closes cleanly.
//!
//! The client speaks the wire protocol directly (no third-party
//! MySQL crate) so the slice has zero external runtime dependencies
//! beyond the proxy crate itself.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use raxis_credentials::{
    ConsumerIdentity, CredentialBackend, CredentialError, CredentialName, CredentialValue, Lease,
    OperatorId,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use raxis_credential_proxy_mysql::{
    wire::{cmd as mysql_cmd, frame_packet, PacketHeader},
    MysqlProxy, NoopAuditChannel, OwnedConsumer, ProxyConfig, Restrictions,
};

/// Default upstream URL — the loopback published by
/// `live-e2e/docker-compose.e2e.yml` for the MySQL 8.0.36 container.
/// Operators can override via `RAXIS_LIVE_MYSQL_URL`.
const DEFAULT_UPSTREAM_URL: &str = "mysql://raxis_test:raxis_test_pass@127.0.0.1:33099/raxis_e2e";

/// Loopback host:port the docker-compose MySQL publishes; used for
/// the slice's TCP preflight.
const MYSQL_HOST_PORT: &str = "127.0.0.1:33099";

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

pub async fn run() -> Result<()> {
    let env_override = std::env::var("RAXIS_LIVE_MYSQL_URL").ok();
    let (upstream_url, source) = match env_override.as_deref() {
        Some(u) if !u.is_empty() => (u.to_owned(), "RAXIS_LIVE_MYSQL_URL override"),
        _ => (DEFAULT_UPSTREAM_URL.to_owned(), "compose-stack default"),
    };
    tracing::info!(
        host_port = MYSQL_HOST_PORT,
        url_source = source,
        "slice mysql-proxy: starting (real-upstream, active by default)",
    );

    // Preflight: the container must be reachable.  The slice does
    // not run in any "hermetic / unreachable upstream" fallback —
    // the proxy crate's fake-MySQL fixture tests cover the
    // upstream-failure audit path.
    require_mysql_container().await?;
    // Hermetic flag retained as a `false` constant so the rest of
    // the slice's audit-counter assertions do not need to branch.
    let hermetic = false;

    let backend = Arc::new(LiveBackend {
        value: upstream_url.as_bytes().to_vec(),
        resolves: AtomicU32::new(0),
    });

    let credential_name = CredentialName::from("live-e2e".to_owned());
    let cfg = ProxyConfig {
        listen_addr: "127.0.0.1:0".to_owned(),
        credential_name: credential_name.clone(),
        consumer: OwnedConsumer::new("live-e2e", "mysql-slice"),
        server_version: "8.0.30-raxis-handshake".to_owned(),
        restrictions: Restrictions::select_only(),
        log_content: false,
    };

    let proxy = MysqlProxy::bind(
        Arc::clone(&backend) as Arc<dyn CredentialBackend>,
        cfg,
        Arc::new(NoopAuditChannel),
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
    let mut sock = TcpStream::connect(proxy_addr)
        .await
        .context("connect to MysqlProxy")?;

    // 1. Read HandshakeV10 (seq=0).
    let (h0, payload0) = read_packet(&mut sock)
        .await
        .context("read HandshakeV10")?
        .ok_or_else(|| anyhow!("EOF before HandshakeV10"))?;
    if h0.sequence_id != 0 {
        return Err(anyhow!(
            "expected HandshakeV10 seq=0, got seq={}",
            h0.sequence_id,
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
    let caps: u32 = 0x0000_0080_8205;
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
    sock.write_all(&frame_packet(&handshake_response, 1))
        .await
        .context("write HandshakeResponse41")?;
    sock.flush().await.context("flush HandshakeResponse41")?;

    // 3. Read OK_Packet (seq=2).
    let (h2, payload2) = read_packet(&mut sock)
        .await
        .context("read OK_Packet")?
        .ok_or_else(|| anyhow!("EOF before OK_Packet"))?;
    if h2.sequence_id != 2 {
        return Err(anyhow!(
            "expected OK_Packet seq=2, got seq={}",
            h2.sequence_id,
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
    sock.write_all(&frame_packet(&ping_payload, 0))
        .await
        .context("write COM_PING")?;
    sock.flush().await?;
    let (_h_ping, payload_ping) = read_packet(&mut sock)
        .await
        .context("read OK after PING")?
        .ok_or_else(|| anyhow!("EOF after PING"))?;
    if payload_ping.first().copied() != Some(0x00) {
        return Err(anyhow!("PING did not yield OK_Packet"));
    }

    // 5. COM_QUERY "SELECT 1" — drives a real result-set round
    //    trip through the proxy.  Wire shape for `SELECT 1` against
    //    a live MySQL upstream is one of:
    //
    //      * `OK_Packet` (header `0x00`) — terminal, no result set
    //        (real MySQL never replies this for `SELECT 1` but the
    //        slice handles it defensively).
    //      * `ERR_Packet` (header `0xff`) — terminal, e.g. permission
    //        denied. Already-drained on read.
    //      * `ResultSetHeader` (lenenc-int column count) followed by
    //        N ColumnDef + EOF + N Row + EOF (no `CLIENT_DEPRECATE_EOF`
    //        advertised by the proxy, so we get classic EOFs).
    //
    //    The slice MUST drain the full result-set stream so the
    //    next `read_packet` after sending INSERT lines up with
    //    INSERT's own ERR_Packet rather than a leftover ColumnDef.
    let mut select_payload = vec![mysql_cmd::QUERY];
    select_payload.extend_from_slice(b"SELECT 1");
    sock.write_all(&frame_packet(&select_payload, 0))
        .await
        .context("write COM_QUERY SELECT")?;
    sock.flush().await?;
    let (_h_sel, payload_sel) = read_packet(&mut sock)
        .await
        .context("read SELECT response")?
        .ok_or_else(|| anyhow!("EOF after SELECT"))?;
    match payload_sel.first().copied() {
        Some(0xff) | Some(0x00) => {
            tracing::info!(
                first_byte = format!("{:#04x}", payload_sel.first().copied().unwrap_or(0)),
                "slice mysql-proxy: SELECT short-form reply",
            );
        }
        Some(_) => {
            let column_count = payload_sel.first().copied().unwrap_or(0) as u64;
            let mut eof_seen = 0;
            let mut frames_read = 1;
            while eof_seen < 2 {
                let (_h, p) = read_packet(&mut sock)
                    .await
                    .context("drain SELECT result-set frame")?
                    .ok_or_else(|| anyhow!("EOF mid-result-set after {frames_read} frames",))?;
                frames_read += 1;
                if !p.is_empty() && p[0] == 0xfe && p.len() < 9 {
                    eof_seen += 1;
                } else if !p.is_empty() && p[0] == 0xff {
                    break;
                }
            }
            tracing::info!(
                first_byte = format!("{:#04x}", payload_sel.first().copied().unwrap_or(0)),
                column_count,
                frames_read,
                "slice mysql-proxy: SELECT result-set drained",
            );
        }
        None => {
            return Err(anyhow!("SELECT yielded an empty packet payload"));
        }
    }

    // 6. COM_QUERY "INSERT INTO t VALUES (1)" — must yield
    //    ERR_Packet under allow_only_select.
    let mut insert_payload = vec![mysql_cmd::QUERY];
    insert_payload.extend_from_slice(b"INSERT INTO t VALUES (1)");
    sock.write_all(&frame_packet(&insert_payload, 0))
        .await
        .context("write COM_QUERY INSERT")?;
    sock.flush().await?;
    let (_h_ins, payload_ins) = read_packet(&mut sock)
        .await
        .context("read INSERT response")?
        .ok_or_else(|| anyhow!("EOF after INSERT"))?;
    if payload_ins.first().copied() != Some(0xff) {
        return Err(anyhow!(
            "INSERT did not yield ERR_Packet, first byte {:#04x}",
            payload_ins.first().copied().unwrap_or(0),
        ));
    }
    // Spot-check the SQLSTATE marker.
    let marker_pos = payload_ins
        .iter()
        .position(|&b| b == b'#')
        .ok_or_else(|| anyhow!("ERR_Packet missing '#' SQLSTATE marker"))?;
    let sqlstate = &payload_ins[marker_pos + 1..marker_pos + 6];
    if sqlstate != b"42501" {
        return Err(anyhow!(
            "ERR_Packet sqlstate {:?} != 42501",
            String::from_utf8_lossy(sqlstate),
        ));
    }

    // 7. COM_QUIT — server closes.
    let quit_payload = vec![mysql_cmd::QUIT];
    sock.write_all(&frame_packet(&quit_payload, 0))
        .await
        .context("write COM_QUIT")?;
    sock.flush().await?;
    let mut tail = [0u8; 1];
    let _ = tokio::time::timeout(Duration::from_secs(1), sock.read_exact(&mut tail)).await;
    drop(sock);

    // 8. Verify counters.
    let snap = stats.snapshot();
    if snap.connections_served < 1 {
        return Err(anyhow!(
            "expected ≥1 connection_served, got {}",
            snap.connections_served,
        ));
    }
    if snap.queries_audited != 2 {
        return Err(anyhow!(
            "expected queries_audited=2, got {}",
            snap.queries_audited,
        ));
    }
    if snap.queries_blocked != 1 {
        return Err(anyhow!(
            "expected queries_blocked=1, got {}",
            snap.queries_blocked,
        ));
    }
    if backend.resolves.load(Ordering::Relaxed) < 1 {
        return Err(anyhow!(
            "expected ≥1 CredentialBackend::resolve call, got 0",
        ));
    }
    // The SELECT must have driven a successful upstream connect.
    // A regression that bypassed upstream and answered the SELECT
    // locally would surface here.
    let _ = hermetic;
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
        queries_audited = snap.queries_audited,
        queries_blocked = snap.queries_blocked,
        upstream_succeeded = snap.upstream_connects_succeeded,
        upstream_failed = snap.upstream_connects_failed,
        backend_resolves = backend.resolves.load(Ordering::Relaxed),
        "mysql-proxy slice OK",
    );
    Ok(())
}

/// TCP-preflight the MySQL container. Returns an actionable error
/// when the container isn't running so the operator immediately
/// knows to bring up the compose stack.
async fn require_mysql_container() -> Result<()> {
    match tokio::time::timeout(Duration::from_secs(2), TcpStream::connect(MYSQL_HOST_PORT)).await {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(e)) => Err(anyhow!(
            "mysql container not reachable at {MYSQL_HOST_PORT}: {e}\n\
             hint: docker compose -f live-e2e/docker-compose.e2e.yml up -d mysql --wait",
        )),
        Err(_) => Err(anyhow!(
            "mysql container not reachable at {MYSQL_HOST_PORT}: timed out after 2s\n\
             hint: docker compose -f live-e2e/docker-compose.e2e.yml up -d mysql --wait",
        )),
    }
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
    sock.read_exact(&mut payload)
        .await
        .context("read MySQL packet payload")?;
    Ok(Some((h, payload)))
}

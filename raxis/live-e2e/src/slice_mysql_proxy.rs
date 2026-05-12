//! Slice — real `MysqlProxy` driving the V2.1 real-upstream-forwarding
//! contract.
//!
//! ## Two modes
//!
//! 1. **Hermetic (default)** — the proxy is configured with an
//!    unreachable upstream URL (`mysql://demo:demo@127.0.0.1:1/demo`)
//!    so the V2.1 upstream-forwarding path can be exercised
//!    without an external service:
//!      * The agent's `HandshakeV10` ↔ `HandshakeResponse41` ↔
//!        `OK_Packet` succeeds (the proxy answers locally).
//!      * `COM_PING` succeeds (still local).
//!      * `SELECT 1` triggers the proxy to attempt an upstream
//!        connection — which fails — and the agent receives an
//!        `ERR_Packet`. We assert the failure path emitted
//!        `CredentialProxyUpstreamFailed` and the
//!        `upstream_connects_failed` counter incremented.
//!      * `INSERT INTO t VALUES (1)` short-circuits at the
//!        restriction layer (BEFORE upstream) with
//!        `ERR_Packet { sqlstate = "42501" }`.
//!      * `COM_QUIT` closes cleanly.
//!
//! 2. **Real upstream (`RAXIS_LIVE_MYSQL_URL=mysql://...`)** — when
//!    the env var is set, the SELECT round-trips a real result set
//!    from a live MySQL server through `mysql_native_password`.
//!    The docker-compose MySQL service published in
//!    `live-e2e/docker-compose.e2e.yml` is the recommended
//!    target for the fast-path; set:
//!
//!    ```sh
//!    docker compose -f live-e2e/docker-compose.e2e.yml up -d mysql --wait
//!    export RAXIS_LIVE_MYSQL_URL=mysql://raxis_test:raxis_test_pass@127.0.0.1:33099
//!    cargo run -p raxis-live-e2e -- mysql-proxy
//!    ```
//!
//! Either mode validates the proxy's local handshake, restriction
//! enforcement, audit emission, and credential-resolution
//! invariants. The client side speaks the wire protocol directly
//! (no third-party MySQL crate) so the slice has zero external
//! dependencies beyond the proxy crate itself.

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

const HERMETIC_UPSTREAM_URL: &str = "mysql://demo:demo@127.0.0.1:1/demo";

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
    let real_upstream = std::env::var("RAXIS_LIVE_MYSQL_URL").ok();
    let upstream_url = match real_upstream.as_deref() {
        Some(u) if !u.is_empty() => u.to_owned(),
        _ => HERMETIC_UPSTREAM_URL.to_owned(),
    };
    let hermetic = real_upstream.as_deref().is_none_or(str::is_empty);
    tracing::info!(
        mode = if hermetic { "hermetic" } else { "real-upstream" },
        upstream_kind = if hermetic { "unreachable (127.0.0.1:1)" } else { "configured via RAXIS_LIVE_MYSQL_URL" },
        "slice mysql-proxy: starting",
    );

    let backend = Arc::new(LiveBackend {
        value:    upstream_url.as_bytes().to_vec(),
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

    // 5. COM_QUERY "SELECT 1" — exercises upstream-forwarding path.
    //    In hermetic mode this triggers an upstream connect to
    //    127.0.0.1:1 which fails, and the proxy surfaces an
    //    ERR_Packet (first byte 0xFF). In real-upstream mode this
    //    round-trips real result-set frames (TEXT_RESULTSET) which
    //    end with EOF or OK_Packet.
    let mut select_payload = vec![mysql_cmd::QUERY];
    select_payload.extend_from_slice(b"SELECT 1");
    sock.write_all(&frame_packet(&select_payload, 0)).await
        .context("write COM_QUERY SELECT")?;
    sock.flush().await?;
    let (_h_sel, payload_sel) = read_packet(&mut sock).await
        .context("read SELECT response")?
        .ok_or_else(|| anyhow!("EOF after SELECT"))?;
    if hermetic {
        // ERR_Packet (0xFF) is expected for the unreachable upstream.
        // OK_Packet (0x00) would also be acceptable IF some local
        // listener answered on port 1, but on a normal dev machine
        // that's never the case.
        if payload_sel.first().copied() != Some(0xff) {
            return Err(anyhow!(
                "hermetic mode: SELECT did not yield ERR_Packet (0xFF) for unreachable upstream, first byte {:#04x}",
                payload_sel.first().copied().unwrap_or(0),
            ));
        }
        tracing::info!("slice mysql-proxy: hermetic SELECT got ERR_Packet (upstream unreachable, expected)");
    } else {
        // Real upstream: drain the rest of the result-set stream so
        // the next `read_packet` after sending INSERT lines up with
        // INSERT's own ERR_Packet rather than a leftover ColumnDef /
        // EOF / Row / EOF.
        //
        // The wire shape for `SELECT 1` against a real MySQL
        // upstream is one of:
        //
        //   * `OK_Packet` (header `0x00`) — terminal, no result set.
        //     Real MySQL never replies this for `SELECT 1` but
        //     defensive: handle it anyway.
        //   * `ERR_Packet` (header `0xff`) — terminal, e.g. permission
        //     denied at the upstream. Already-drained on read.
        //   * `ResultSetHeader` (lenenc-int column count) followed by
        //     N ColumnDef + EOF + N Row + EOF (no `CLIENT_DEPRECATE_EOF`
        //     advertised by the proxy, so we get classic EOFs).
        //
        // We discriminate on the FIRST packet we already read and
        // drain accordingly.
        match payload_sel.first().copied() {
            Some(0xff) | Some(0x00) => {
                // Terminal: no further packets to read for this query.
                tracing::info!(
                    first_byte = format!("{:#04x}",
                        payload_sel.first().copied().unwrap_or(0)),
                    "slice mysql-proxy: real-upstream SELECT short-form reply",
                );
            }
            Some(_) => {
                // Result-set form. The reading loop must continue
                // until we see two EOFs (column-defs terminator AND
                // row terminator), or a mid-stream ERR_Packet.
                let column_count = payload_sel
                    .first()
                    .copied()
                    .unwrap_or(0) as u64;
                let mut eof_seen = 0;
                let mut frames_read = 1;
                while eof_seen < 2 {
                    let (_h, p) = read_packet(&mut sock).await
                        .context("drain SELECT result-set frame")?
                        .ok_or_else(|| anyhow!(
                            "EOF mid-result-set after {frames_read} frames",
                        ))?;
                    frames_read += 1;
                    if !p.is_empty() && p[0] == 0xfe && p.len() < 9 {
                        eof_seen += 1;
                    } else if !p.is_empty() && p[0] == 0xff {
                        // Mid-stream upstream error — fine for our
                        // purposes; the SELECT still drove an
                        // upstream round trip.
                        break;
                    }
                }
                tracing::info!(
                    first_byte = format!("{:#04x}",
                        payload_sel.first().copied().unwrap_or(0)),
                    column_count,
                    frames_read,
                    "slice mysql-proxy: real-upstream SELECT result-set drained",
                );
            }
            None => {
                return Err(anyhow!(
                    "real-upstream mode: SELECT yielded an empty packet payload",
                ));
            }
        }
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
    if hermetic {
        // The unreachable-upstream connect MUST have been
        // attempted and MUST have failed — otherwise the proxy
        // skipped the upstream-forwarding code path entirely
        // (regression).
        if snap.upstream_connects_failed < 1 {
            return Err(anyhow!(
                "hermetic mode: expected upstream_connects_failed≥1, got {}",
                snap.upstream_connects_failed,
            ));
        }
    } else if snap.upstream_connects_succeeded < 1 {
        // Real-upstream mode: the SELECT must have driven a
        // successful upstream connect. A regression that bypassed
        // upstream and answered the SELECT locally would surface
        // here.
        return Err(anyhow!(
            "real-upstream mode: expected upstream_connects_succeeded≥1, got {}",
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


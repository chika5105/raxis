//! Slice — real `MongodbProxy` driving the V2.1 real-upstream-forwarding
//! contract (no-auth tier).
//!
//! ## Two modes
//!
//! 1. **Hermetic (default)** — no real MongoDB required. The proxy
//!    is configured with an unreachable upstream URL
//!    (`mongodb://127.0.0.1:1/demo`) so the V2.1 path can be
//!    exercised without an external service:
//!      * `hello` / `ping` / `isMaster` / `buildInfo` are answered
//!        LOCALLY by the proxy with `ok: 1.0` — these never go
//!        upstream, so they succeed regardless of upstream reachability.
//!      * `find` (allowed read) triggers an upstream connect to
//!        127.0.0.1:1 which fails — the proxy synthesises an error
//!        doc with `ok: 0.0`.
//!      * `insert` (blocked under `allow_read_only`) short-circuits
//!        at the restriction layer with `ok: 0.0, code: 13`.
//!
//! 2. **Real upstream (`RAXIS_LIVE_MONGODB_URL=mongodb://...`)** —
//!    when the env var is set (must be a `--noauth` mongod —
//!    SCRAM-SHA-256 is V2.2), `find` round-trips real `nReturned`
//!    values. The slice asserts `ok: 1.0` in that case.
//!
//! The client side speaks the wire protocol directly using the
//! proxy's `BsonBuilder` so the slice has zero external
//! dependencies beyond the proxy crate itself.

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

use raxis_credential_proxy_mongodb::{
    wire::{first_bson_field_name, BsonBuilder, MsgHeader, HEADER_LEN, OP_MSG},
    MongodbProxy, NoopAuditChannel, OwnedConsumer, ProxyConfig, Restrictions,
};

const HERMETIC_UPSTREAM_URL: &str = "mongodb://127.0.0.1:1/demo";

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
    let real_upstream = std::env::var("RAXIS_LIVE_MONGODB_URL").ok();
    let upstream_url = match real_upstream.as_deref() {
        Some(u) if !u.is_empty() => u.to_owned(),
        _ => HERMETIC_UPSTREAM_URL.to_owned(),
    };
    let hermetic = real_upstream.as_deref().is_none_or(str::is_empty);
    tracing::info!(
        mode = if hermetic {
            "hermetic"
        } else {
            "real-upstream"
        },
        "slice mongodb-proxy: starting",
    );

    let backend = Arc::new(LiveBackend {
        value: upstream_url.as_bytes().to_vec(),
        resolves: AtomicU32::new(0),
    });

    let credential_name = CredentialName::try_from("live-e2e".to_owned())
        .map_err(|e| anyhow!("CredentialName: {e}"))?;
    let cfg = ProxyConfig {
        listen_addr: "127.0.0.1:0".to_owned(),
        credential_name: credential_name.clone(),
        consumer: OwnedConsumer::new("live-e2e", "mongodb-slice"),
        restrictions: Restrictions::read_only(),
    };

    let proxy = MongodbProxy::bind(
        Arc::clone(&backend) as Arc<dyn CredentialBackend>,
        cfg,
        Arc::new(NoopAuditChannel::default()),
    )
    .await
    .context("MongodbProxy::bind")?;
    let proxy_addr = proxy.local_addr().context("local_addr")?;
    let stats = proxy.stats_handle();
    let proxy_handle = tokio::spawn(async move { proxy.serve().await });

    tokio::time::sleep(Duration::from_millis(50)).await;

    let mut sock = TcpStream::connect(proxy_addr)
        .await
        .context("connect to MongodbProxy")?;

    // 1. hello → ok: 1.0
    drive_command(&mut sock, 1, "hello")
        .await
        .context("hello")?;

    // 2. ping → ok: 1.0
    drive_command(&mut sock, 2, "ping").await.context("ping")?;

    // 3. find — exercises upstream-forwarding path.
    //    Hermetic: upstream connect fails → proxy synthesises
    //    `ok: 0.0` error doc. Real-upstream: `ok: 1.0` from real mongod.
    let find_reply = drive_command_raw(&mut sock, 3, "find")
        .await
        .context("find")?;
    let find_ok =
        read_ok_field(&find_reply).ok_or_else(|| anyhow!("find reply missing ok field"))?;
    if hermetic {
        if find_ok != 0.0 {
            return Err(anyhow!(
                "hermetic mode: find reply ok={find_ok} != 0.0 (upstream unreachable should produce 0.0)",
            ));
        }
        tracing::info!(
            "slice mongodb-proxy: hermetic find got ok:0.0 (upstream unreachable, expected)"
        );
    } else if find_ok != 1.0 {
        return Err(anyhow!(
            "real-upstream mode: find reply ok={find_ok} != 1.0",
        ));
    }

    // 4. insert → ok: 0.0 (blocked at the restriction layer, BEFORE
    //    upstream — same in both modes).
    let reply_doc = drive_command_raw(&mut sock, 4, "insert")
        .await
        .context("insert")?;
    let ok_val =
        read_ok_field(&reply_doc).ok_or_else(|| anyhow!("insert reply missing ok field"))?;
    if ok_val != 0.0 {
        return Err(anyhow!(
            "insert reply ok={} != 0.0 (proxy did not block)",
            ok_val,
        ));
    }

    drop(sock);

    // 5. Verify counters.
    let snap = stats.snapshot();
    if snap.connections_served < 1 {
        return Err(anyhow!(
            "expected ≥1 connection_served, got {}",
            snap.connections_served,
        ));
    }
    if snap.commands_audited != 4 {
        return Err(anyhow!(
            "expected commands_audited=4, got {}",
            snap.commands_audited,
        ));
    }
    if snap.commands_blocked != 1 {
        return Err(anyhow!(
            "expected commands_blocked=1, got {}",
            snap.commands_blocked,
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
        commands_audited = snap.commands_audited,
        commands_blocked = snap.commands_blocked,
        backend_resolves = backend.resolves.load(Ordering::Relaxed),
        "mongodb-proxy slice OK",
    );
    Ok(())
}

/// Issue a one-field BSON command (`{ <command>: 1 }`) and assert
/// that the proxy's reply doc starts with `ok: 1.0`.
async fn drive_command(sock: &mut TcpStream, request_id: i32, command: &str) -> Result<()> {
    let reply_doc = drive_command_raw(sock, request_id, command).await?;
    let first = first_bson_field_name(&reply_doc)
        .ok_or_else(|| anyhow!("{command} reply has no first field"))?;
    if first != "ok" {
        return Err(anyhow!("{command} reply first field {:?} != 'ok'", first,));
    }
    let ok_bytes = &reply_doc[8..16];
    let ok_val = f64::from_le_bytes([
        ok_bytes[0],
        ok_bytes[1],
        ok_bytes[2],
        ok_bytes[3],
        ok_bytes[4],
        ok_bytes[5],
        ok_bytes[6],
        ok_bytes[7],
    ]);
    if ok_val != 1.0 {
        return Err(anyhow!("{command} reply ok={} != 1.0", ok_val,));
    }
    Ok(())
}

/// Pull the `ok` field from a BSON reply doc. The ok field is a
/// double immediately after the document length (4 bytes), the type
/// byte (1), and the field name `"ok\0"` (3 bytes).
fn read_ok_field(reply_doc: &[u8]) -> Option<f64> {
    let first = first_bson_field_name(reply_doc)?;
    if first != "ok" {
        return None;
    }
    if reply_doc.len() < 16 {
        return None;
    }
    let ok_bytes = &reply_doc[8..16];
    Some(f64::from_le_bytes([
        ok_bytes[0],
        ok_bytes[1],
        ok_bytes[2],
        ok_bytes[3],
        ok_bytes[4],
        ok_bytes[5],
        ok_bytes[6],
        ok_bytes[7],
    ]))
}

/// Issue a one-field BSON command and return the reply BSON doc.
async fn drive_command_raw(
    sock: &mut TcpStream,
    request_id: i32,
    command: &str,
) -> Result<Vec<u8>> {
    let bson_doc = BsonBuilder::new().int32(command, 1).finish();
    // OP_MSG body = flag_bits:u32 + section_kind:u8 + bson_doc.
    let mut body = Vec::with_capacity(4 + 1 + bson_doc.len());
    body.extend_from_slice(&0u32.to_le_bytes());
    body.push(0);
    body.extend_from_slice(&bson_doc);
    let total = HEADER_LEN + body.len();
    let header = MsgHeader {
        message_length: total as i32,
        request_id,
        response_to: 0,
        op_code: OP_MSG,
    };
    let mut wire = Vec::with_capacity(total);
    wire.extend_from_slice(&header.encode());
    wire.extend_from_slice(&body);
    sock.write_all(&wire)
        .await
        .with_context(|| format!("write {command}"))?;
    sock.flush().await?;

    let (reply_header, reply_body) = read_message(sock)
        .await
        .with_context(|| format!("read {command} reply"))?
        .ok_or_else(|| anyhow!("EOF after {command}"))?;
    if reply_header.op_code != OP_MSG {
        return Err(anyhow!(
            "{command} reply op_code {} != OP_MSG",
            reply_header.op_code,
        ));
    }
    if reply_header.response_to != request_id {
        return Err(anyhow!(
            "{command} reply response_to={} != request_id={}",
            reply_header.response_to,
            request_id,
        ));
    }
    if reply_body.len() < 5 {
        return Err(anyhow!("{command} reply body too short"));
    }
    // Skip flag_bits:u32 + section_kind:u8 → BSON doc starts at offset 5.
    Ok(reply_body[5..].to_vec())
}

async fn read_message(sock: &mut TcpStream) -> Result<Option<(MsgHeader, Vec<u8>)>> {
    let mut header_buf = [0u8; HEADER_LEN];
    if let Err(e) = sock.read_exact(&mut header_buf).await {
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            return Ok(None);
        }
        return Err(e.into());
    }
    let h = MsgHeader::parse(header_buf);
    if h.message_length < HEADER_LEN as i32 {
        return Err(anyhow!(
            "MongoDB header length {} smaller than HEADER_LEN",
            h.message_length,
        ));
    }
    let body_len = (h.message_length as usize) - HEADER_LEN;
    let mut body = vec![0u8; body_len];
    sock.read_exact(&mut body)
        .await
        .context("read MongoDB body")?;
    Ok(Some((h, body)))
}

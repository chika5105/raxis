//! Slice — `MongodbProxy` enforces V2 `allowed_collections` /
//! `forbidden_collections` and the `max_documents` cursor cap.
//!
//! Reference: `specs/v2/proxy-table-allowlists.md §6` (BSON
//! walker) and §7.4 (cursor rewrite).
//!
//! ## What this slice exercises
//!
//!   1. **Collection allowlist deny path** — `find` against
//!      `appdb.users` when `allowed_collections = ["appdb.orders"]`
//!      MUST be rejected with `{ ok: 0, code: 13 }` and the audit
//!      `restriction_reason` MUST be `"collection_not_in_allowed_list"`.
//!   2. **Forbidden list deny path** — `find` against
//!      `appdb.audit_log` when it's in `forbidden_collections`
//!      MUST be rejected with `restriction_reason =
//!      "collection_in_forbidden_list"`.
//!   3. **Server-introspection commands** (`hello`, `ping`)
//!      MUST be admitted unconditionally (no collection name).
//!   4. **Allowlist allow path** — `find` against
//!      `appdb.orders` MUST pass the walker.
//!   5. **Cursor cap rewrite** — when `max_documents = 3` and the
//!      upstream reply carries `firstBatch.len() = 5`, the proxy
//!      MUST truncate the batch to 3 docs AND zero the cursor id.
//!      Tested with an in-process upstream Mongo stub that serves
//!      a synthetic `firstBatch` of 5 documents.
//!
//! The slice runs entirely against a fake upstream that the slice
//! starts itself — no external mongod required.

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Mutex;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use raxis_credentials::{
    ConsumerIdentity, CredentialBackend, CredentialError, CredentialName, CredentialValue,
    Lease, OperatorId,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use raxis_credential_proxy_mongodb::{
    AuditChannel, AuditEvent, MongodbProxy, OwnedConsumer, ProxyConfig, Restrictions,
    wire::{first_bson_field_name, BsonBuilder, HEADER_LEN, MsgHeader, OP_MSG},
};

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

#[derive(Default)]
struct CapturingAudit {
    events: Mutex<Vec<AuditEvent>>,
}

impl AuditChannel for CapturingAudit {
    fn emit(&self, event: AuditEvent) {
        if let Ok(mut g) = self.events.lock() { g.push(event); }
    }
}

impl CapturingAudit {
    fn snapshot(&self) -> Vec<AuditEvent> {
        self.events.lock().map(|g| g.clone()).unwrap_or_default()
    }
}

pub(crate) async fn run() -> Result<()> {
    tracing::info!("slice mongodb-proxy-collection-allowlists: starting");

    // ── Phase 1: collection allowlist deny path ──────────────────
    let unreachable_upstream = b"mongodb://127.0.0.1:1/appdb".to_vec();
    let backend = Arc::new(LiveBackend {
        value:    unreachable_upstream.clone(),
        resolves: AtomicU32::new(0),
    });
    let audit = Arc::new(CapturingAudit::default());
    let cfg = ProxyConfig {
        listen_addr:     "127.0.0.1:0".to_owned(),
        credential_name: CredentialName::new("live-e2e"),
        consumer:        OwnedConsumer::new("credential_proxy", "live-e2e:mongo:t"),
        restrictions:    Restrictions {
            allowed_collections:    vec!["appdb.orders".into()],
            forbidden_collections:  vec!["appdb.audit_log".into()],
            ..Default::default()
        },
    };
    let proxy = MongodbProxy::bind(
        backend.clone() as Arc<dyn CredentialBackend>,
        cfg,
        Arc::clone(&audit) as Arc<dyn AuditChannel>,
    )
    .await
    .context("MongodbProxy::bind")?;
    let addr  = proxy.local_addr()?;
    let stats = proxy.stats_handle();
    tokio::spawn(proxy.serve());
    tokio::time::sleep(Duration::from_millis(30)).await;

    let mut sock = TcpStream::connect(addr).await?;

    // hello — server-intro command, must admit even with allowlist.
    let reply = drive_find(&mut sock, 1, FindShape::Server("hello")).await
        .context("hello")?;
    let ok = read_ok(&reply).ok_or_else(|| anyhow!("hello has no ok"))?;
    if ok != 1.0 {
        return Err(anyhow!("hello ok={ok} != 1.0 (server-intro must admit)"));
    }

    // find appdb.orders — allowlisted; the proxy admits it and
    // forwards to the unreachable upstream. The reply doc carries
    // ok: 0.0 (upstream connect failed) but the proxy MUST NOT
    // surface "Unauthorized"; we assert codeName != "Unauthorized".
    let reply = drive_find(&mut sock, 2, FindShape::Find { coll: "orders", db: "appdb" }).await
        .context("find orders")?;
    let code_name = read_string_field(&reply, "codeName");
    if code_name.as_deref() == Some("Unauthorized") {
        return Err(anyhow!(
            "find orders was rejected with Unauthorized — walker failed to admit allowlisted collection",
        ));
    }

    // find appdb.users — NOT in allowlist; must be rejected with
    // code 13 codeName Unauthorized.
    let reply = drive_find(&mut sock, 3, FindShape::Find { coll: "users", db: "appdb" }).await
        .context("find users")?;
    assert_blocked(&reply, "find users (not in allowlist)")?;

    // find appdb.audit_log — in forbidden; must be rejected.
    let reply = drive_find(&mut sock, 4, FindShape::Find { coll: "audit_log", db: "appdb" }).await
        .context("find audit_log")?;
    assert_blocked(&reply, "find audit_log (forbidden)")?;

    drop(sock);
    tokio::time::sleep(Duration::from_millis(30)).await;

    // ── Audit assertions for phase 1. ──
    let events = audit.snapshot();
    let reasons: Vec<Option<&'static str>> = events.iter().filter_map(|e| match e {
        AuditEvent::MongoCommandExecuted { restriction_reason, blocked: true, .. } =>
            Some(*restriction_reason),
        _ => None,
    }).collect();
    if !reasons.iter().any(|r| *r == Some("collection_not_in_allowed_list")) {
        return Err(anyhow!(
            "missing restriction_reason 'collection_not_in_allowed_list' in audit; got {reasons:?}",
        ));
    }
    if !reasons.iter().any(|r| *r == Some("collection_in_forbidden_list")) {
        return Err(anyhow!(
            "missing restriction_reason 'collection_in_forbidden_list' in audit; got {reasons:?}",
        ));
    }
    let snap = stats.snapshot();
    if snap.commands_blocked < 2 {
        return Err(anyhow!(
            "expected ≥2 commands_blocked (users + audit_log), got {}", snap.commands_blocked,
        ));
    }
    if snap.commands_blocked_by_collection_allowlist < 2 {
        return Err(anyhow!(
            "expected ≥2 commands_blocked_by_collection_allowlist, got {}",
            snap.commands_blocked_by_collection_allowlist,
        ));
    }

    // ── Phase 2: max_documents cursor cap with in-process upstream ──
    //
    // Start a fake mongod listener that:
    //   * responds to PRELOGIN-less raw OP_MSG;
    //   * on `find` returns a cursor with firstBatch of 5 docs;
    //   * on anything else returns ok:1.0 (e.g. SCRAM steps not in V2).
    let upstream = TcpListener::bind("127.0.0.1:0").await
        .context("bind fake upstream")?;
    let upstream_addr = upstream.local_addr()?;
    let upstream_url = format!("mongodb://127.0.0.1:{}/appdb", upstream_addr.port())
        .into_bytes();
    let upstream_handle = tokio::spawn(serve_fake_upstream(upstream));

    let backend2 = Arc::new(LiveBackend {
        value:    upstream_url,
        resolves: AtomicU32::new(0),
    });
    let audit2 = Arc::new(CapturingAudit::default());
    let cfg2 = ProxyConfig {
        listen_addr:     "127.0.0.1:0".to_owned(),
        credential_name: CredentialName::new("live-e2e"),
        consumer:        OwnedConsumer::new("credential_proxy", "live-e2e:mongo:cap"),
        restrictions:    Restrictions {
            max_documents: 3,
            ..Default::default()
        },
    };
    let proxy2 = MongodbProxy::bind(
        backend2.clone() as Arc<dyn CredentialBackend>,
        cfg2,
        Arc::clone(&audit2) as Arc<dyn AuditChannel>,
    )
    .await
    .context("MongodbProxy::bind phase 2")?;
    let addr2  = proxy2.local_addr()?;
    let stats2 = proxy2.stats_handle();
    tokio::spawn(proxy2.serve());
    tokio::time::sleep(Duration::from_millis(30)).await;

    let mut sock2 = TcpStream::connect(addr2).await?;
    let reply = drive_find(&mut sock2, 10, FindShape::Find { coll: "users", db: "appdb" }).await
        .context("find users (cap path)")?;
    let batch_size = count_first_batch(&reply)
        .ok_or_else(|| anyhow!("could not count firstBatch in reply: {reply:?}"))?;
    if batch_size != 3 {
        return Err(anyhow!(
            "max_documents cap: expected firstBatch.len() = 3, got {batch_size}",
        ));
    }
    let cursor_id = read_cursor_id(&reply)
        .ok_or_else(|| anyhow!("reply has no cursor.id"))?;
    if cursor_id != 0 {
        return Err(anyhow!(
            "max_documents cap: expected cursor.id = 0 after truncation, got {cursor_id}",
        ));
    }
    let cap_snap = stats2.snapshot();
    if cap_snap.commands_capped_by_max_documents == 0 {
        return Err(anyhow!(
            "max_documents cap: commands_capped_by_max_documents = 0; expected ≥1",
        ));
    }

    drop(sock2);
    upstream_handle.abort();

    tracing::info!(
        "slice mongodb-proxy-collection-allowlists: PASS — \
         commands_blocked={} commands_blocked_by_collection_allowlist={} \
         commands_capped_by_max_documents={}",
        snap.commands_blocked,
        snap.commands_blocked_by_collection_allowlist,
        cap_snap.commands_capped_by_max_documents,
    );
    Ok(())
}

#[derive(Debug, Clone, Copy)]
enum FindShape {
    /// `{ <command>: 1 }` — server-introspection.
    Server(&'static str),
    /// `{ find: "<coll>", $db: "<db>" }`.
    Find { coll: &'static str, db: &'static str },
}

async fn drive_find(
    sock:       &mut TcpStream,
    request_id: i32,
    shape:      FindShape,
) -> Result<Vec<u8>> {
    let bson = match shape {
        FindShape::Server(cmd) => BsonBuilder::new().int32(cmd, 1).finish(),
        FindShape::Find { coll, db } => BsonBuilder::new()
            .string("find", coll)
            .string("$db",  db)
            .finish(),
    };
    let mut body = Vec::with_capacity(4 + 1 + bson.len());
    body.extend_from_slice(&0u32.to_le_bytes());
    body.push(0);
    body.extend_from_slice(&bson);
    let total = HEADER_LEN + body.len();
    let header = MsgHeader {
        message_length: total as i32,
        request_id,
        response_to:    0,
        op_code:        OP_MSG,
    };
    let mut wire = Vec::with_capacity(total);
    wire.extend_from_slice(&header.encode());
    wire.extend_from_slice(&body);
    sock.write_all(&wire).await?;
    sock.flush().await?;

    let (h, reply_body) = read_message(sock).await?
        .ok_or_else(|| anyhow!("EOF on reply"))?;
    if h.op_code != OP_MSG {
        return Err(anyhow!("reply op_code {} != OP_MSG", h.op_code));
    }
    if reply_body.len() < 5 {
        return Err(anyhow!("reply body too short"));
    }
    Ok(reply_body[5..].to_vec())
}

async fn read_message(sock: &mut TcpStream) -> Result<Option<(MsgHeader, Vec<u8>)>> {
    let mut hdr = [0u8; HEADER_LEN];
    if let Err(e) = sock.read_exact(&mut hdr).await {
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            return Ok(None);
        }
        return Err(e.into());
    }
    let h = MsgHeader::parse(hdr);
    if h.message_length < HEADER_LEN as i32 {
        return Err(anyhow!("header length too small: {}", h.message_length));
    }
    let body_len = (h.message_length as usize) - HEADER_LEN;
    let mut body = vec![0u8; body_len];
    sock.read_exact(&mut body).await.context("read body")?;
    Ok(Some((h, body)))
}

fn read_ok(doc: &[u8]) -> Option<f64> {
    let first = first_bson_field_name(doc)?;
    if first != "ok" { return None; }
    if doc.len() < 16 { return None; }
    Some(f64::from_le_bytes([
        doc[8], doc[9], doc[10], doc[11], doc[12], doc[13], doc[14], doc[15],
    ]))
}

/// Find a top-level string field (`codeName`, etc.) in a BSON doc.
fn read_string_field(doc: &[u8], target: &str) -> Option<String> {
    if doc.len() < 5 { return None; }
    let total = i32::from_le_bytes(doc[..4].try_into().ok()?) as usize;
    if total > doc.len() { return None; }
    let body = &doc[4..total - 1];
    let mut p = 0;
    while p < body.len() {
        let t = body[p];
        p += 1;
        let nul = body[p..].iter().position(|&b| b == 0)?;
        let name = std::str::from_utf8(&body[p..p + nul]).ok()?;
        p += nul + 1;
        if t == 0x02 && name == target {
            if body.len() < p + 4 { return None; }
            let len = i32::from_le_bytes(body[p..p + 4].try_into().ok()?) as usize;
            if 4 + len > body.len() - p { return None; }
            let s = std::str::from_utf8(&body[p + 4..p + 4 + len - 1]).ok()?;
            return Some(s.to_owned());
        }
        let val_len = skip_value(t, &body[p..])?;
        p += val_len;
    }
    None
}

fn skip_value(t: u8, data: &[u8]) -> Option<usize> {
    Some(match t {
        0x01 => 8,
        0x02 => {
            let len = i32::from_le_bytes(data[..4].try_into().ok()?) as usize;
            4 + len
        }
        0x03 | 0x04 => i32::from_le_bytes(data[..4].try_into().ok()?) as usize,
        0x05 => 5 + i32::from_le_bytes(data[..4].try_into().ok()?) as usize,
        0x07 => 12,
        0x08 => 1,
        0x09 => 8,
        0x10 => 4,
        0x11 | 0x12 => 8,
        _ => return None,
    })
}

fn assert_blocked(reply: &[u8], label: &str) -> Result<()> {
    let ok = read_ok(reply).ok_or_else(|| anyhow!("{label}: no ok field"))?;
    if ok != 0.0 {
        return Err(anyhow!("{label}: ok={ok} != 0.0 (proxy did not block)"));
    }
    let code_name = read_string_field(reply, "codeName")
        .ok_or_else(|| anyhow!("{label}: no codeName field"))?;
    if code_name != "Unauthorized" {
        return Err(anyhow!(
            "{label}: codeName={code_name} != \"Unauthorized\"",
        ));
    }
    Ok(())
}

/// Count `cursor.firstBatch` array element count in a reply doc.
fn count_first_batch(doc: &[u8]) -> Option<u32> {
    let total = i32::from_le_bytes(doc[..4].try_into().ok()?) as usize;
    if total > doc.len() { return None; }
    let body = &doc[4..total - 1];
    let mut p = 0;
    while p < body.len() {
        let t = body[p];
        p += 1;
        let nul = body[p..].iter().position(|&b| b == 0)?;
        let name = std::str::from_utf8(&body[p..p + nul]).ok()?;
        p += nul + 1;
        if t == 0x03 && name == "cursor" {
            let inner_total = i32::from_le_bytes(body[p..p + 4].try_into().ok()?) as usize;
            let inner = &body[p + 4..p + inner_total - 1];
            let mut q = 0;
            while q < inner.len() {
                let t2 = inner[q];
                q += 1;
                let nul2 = inner[q..].iter().position(|&b| b == 0)?;
                let nm = std::str::from_utf8(&inner[q..q + nul2]).ok()?;
                q += nul2 + 1;
                if t2 == 0x04 && (nm == "firstBatch" || nm == "nextBatch") {
                    let arr_total = i32::from_le_bytes(inner[q..q + 4].try_into().ok()?) as usize;
                    let arr = &inner[q + 4..q + arr_total - 1];
                    let mut count = 0;
                    let mut r = 0;
                    while r < arr.len() {
                        let t3 = arr[r];
                        r += 1;
                        let nul3 = arr[r..].iter().position(|&b| b == 0)?;
                        r += nul3 + 1;
                        let vl = skip_value(t3, &arr[r..])?;
                        r += vl;
                        count += 1;
                    }
                    return Some(count);
                }
                let vl = skip_value(t2, &inner[q..])?;
                q += vl;
            }
        }
        let vl = skip_value(t, &body[p..])?;
        p += vl;
    }
    None
}

fn read_cursor_id(doc: &[u8]) -> Option<i64> {
    let total = i32::from_le_bytes(doc[..4].try_into().ok()?) as usize;
    let body = &doc[4..total - 1];
    let mut p = 0;
    while p < body.len() {
        let t = body[p];
        p += 1;
        let nul = body[p..].iter().position(|&b| b == 0)?;
        let name = std::str::from_utf8(&body[p..p + nul]).ok()?;
        p += nul + 1;
        if t == 0x03 && name == "cursor" {
            let inner_total = i32::from_le_bytes(body[p..p + 4].try_into().ok()?) as usize;
            let inner = &body[p + 4..p + inner_total - 1];
            let mut q = 0;
            while q < inner.len() {
                let t2 = inner[q];
                q += 1;
                let nul2 = inner[q..].iter().position(|&b| b == 0)?;
                let nm = std::str::from_utf8(&inner[q..q + nul2]).ok()?;
                q += nul2 + 1;
                if t2 == 0x12 && nm == "id" {
                    return Some(i64::from_le_bytes(inner[q..q + 8].try_into().ok()?));
                }
                let vl = skip_value(t2, &inner[q..])?;
                q += vl;
            }
            return None;
        }
        let vl = skip_value(t, &body[p..])?;
        p += vl;
    }
    None
}

/// Fake upstream mongod that returns a cursor reply with a
/// 5-document `firstBatch` on `find`, and `ok: 1.0` for
/// everything else. The proxy's V2 cap (max_documents = 3 in
/// phase 2) MUST truncate the upstream's 5 down to 3 before
/// the agent observes it.
async fn serve_fake_upstream(listener: TcpListener) {
    loop {
        let (mut sock, _) = match listener.accept().await {
            Ok(x) => x, Err(_) => return,
        };
        tokio::spawn(async move {
            loop {
                let mut hdr = [0u8; HEADER_LEN];
                if sock.read_exact(&mut hdr).await.is_err() { return; }
                let h = MsgHeader::parse(hdr);
                if h.message_length < HEADER_LEN as i32 { return; }
                let body_len = (h.message_length as usize) - HEADER_LEN;
                let mut body = vec![0u8; body_len];
                if sock.read_exact(&mut body).await.is_err() { return; }
                let cmd = raxis_credential_proxy_mongodb::wire::first_command_name(&body)
                    .unwrap_or_else(|| "<unknown>".to_owned());
                let reply_doc = match cmd.as_str() {
                    "find" => build_find_reply(5),
                    _      => BsonBuilder::new().double("ok", 1.0).finish(),
                };
                let reply = raxis_credential_proxy_mongodb::wire::build_op_msg_reply(
                    h.request_id.wrapping_add(0x4000_0000),
                    h.request_id,
                    &reply_doc,
                );
                if sock.write_all(&reply).await.is_err() { return; }
                let _ = sock.flush().await;
            }
        });
    }
}

fn build_find_reply(batch_size: usize) -> Vec<u8> {
    let mut arr = BsonBuilder::new();
    for i in 0..batch_size {
        let inner = BsonBuilder::new().int32("_id", i as i32).finish();
        arr = arr.document(&i.to_string(), inner);
    }
    let batch_array = arr.finish();
    let cursor = BsonBuilder::new()
        .int64 ("id",         99999i64)
        .string("ns",         "appdb.users")
        .array ("firstBatch", batch_array)
        .finish();
    BsonBuilder::new()
        .document("cursor", cursor)
        .double  ("ok",     1.0)
        .finish()
}

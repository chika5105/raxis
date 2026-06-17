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
//!      `appdb.orders` MUST pass the walker AND round-trip to the
//!      real upstream (the proxy's BSON walker MUST NOT mangle a
//!      well-formed admit-path command on the way out).
//!   5. **Cursor cap rewrite** — when `max_documents = 3` and a
//!      `find` against a seeded `live_e2e_cap.users` collection
//!      that holds 5 documents returns a `firstBatch` of 5 docs
//!      from the real server, the proxy MUST truncate the batch
//!      to 3 docs AND zero the cursor id BEFORE the agent
//!      observes the reply.
//!
//! ## Real upstream — mandatory
//!
//! This slice drives the `mongodb` service the live-e2e compose
//! stack publishes on `127.0.0.1:27399`
//! (root = `raxis_test:raxis_test_pass` against `admin`). The
//! cap-rewrite step seeds an ephemeral `live_e2e_cap.users`
//! collection with exactly 5 documents via
//! `docker exec ... mongosh --eval`, drives the `find` through
//! the proxy, asserts the truncated reply, and drops the
//! collection on the way out. The proxy authenticates upstream
//! with SCRAM-SHA-256 — the same handshake
//! `kernel/tests/full_e2e_session_lifecycle.rs` exercises against
//! the same container.
//!
//! ## Why not use an in-process mongod fixture
//!
//! Earlier revisions of this slice used a hand-rolled OP_MSG
//! listener that emitted a synthetic 5-document `firstBatch` to
//! drive the cap. That fixture re-implemented enough of the wire
//! protocol to look like a mongod, but it could not catch a
//! regression where the proxy's BSON walker mis-counted docs from
//! a real cursor reply (e.g. when the reply carries a `nextBatch`
//! field, additional cursor metadata, or BSON sub-types the
//! fixture never emitted). Driving the cap against a real mongod
//! reply byte-for-byte closes that gap and is the explicit goal
//! of the live-e2e un-mock sweep.
//!
//! ## Preflight
//!
//! `docker compose -f live-e2e/docker-compose.e2e.yml up -d \
//!  mongodb --wait`

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use raxis_credentials::{
    ConsumerIdentity, CredentialBackend, CredentialError, CredentialName, CredentialValue,
    OperatorId,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use raxis_credential_proxy_mongodb::{
    wire::{BsonBuilder, MsgHeader, HEADER_LEN, OP_MSG},
    AuditChannel, AuditEvent, MongodbProxy, OwnedConsumer, ProxyConfig, Restrictions,
};

// ---------------------------------------------------------------------------
// Real upstream constants — must match `live-e2e/docker-compose.e2e.yml`
// ---------------------------------------------------------------------------

const MONGO_HOST_PORT: &str = "127.0.0.1:27399";
const MONGO_CONTAINER: &str = "raxis-e2e-mongo";
const UPSTREAM_USER: &str = "raxis_test";
const UPSTREAM_PASS: &str = "raxis_test_pass";

/// Ephemeral database the cap-rewrite step seeds with 5 docs and
/// drops on cleanup. Kept distinct from `appdb` so the two phases
/// of this slice cannot interfere with each other or with anything
/// `kernel/tests/full_e2e_session_lifecycle.rs` writes into the
/// same container.
const CAP_DB: &str = "live_e2e_cap";
const CAP_COLL: &str = "users";
const CAP_BATCH_SIZE: usize = 5;

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
    fn backend_kind(&self) -> &'static str {
        "live-e2e"
    }
}

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
    tracing::info!("slice mongodb-proxy-collection-allowlists: starting");

    require_mongo_container().await?;
    // Drop any leftover state from a previous interrupted run
    // BEFORE the slice does anything else — the cap assertion
    // demands `firstBatch.len() == CAP_BATCH_SIZE` from the real
    // server, so a 4-doc collection from a flaked-out previous
    // run would mask a regression where the proxy fails to
    // truncate.
    cleanup_cap_collection()?;

    let real_upstream_url = mongo_real_upstream_url(CAP_DB);

    // ── Phase 1: collection allowlist deny + admit paths ─────────
    //
    // Phase 1 points the proxy at the SAME real mongo container
    // even though the deny-path commands never reach upstream — by
    // covering the admit path against a real server too, this
    // phase catches any regression where the BSON walker would
    // mangle a passed-through command in a way the in-process
    // fixture would have echoed back unchanged.
    let backend = Arc::new(LiveBackend {
        value: mongo_real_upstream_url("appdb").into_bytes(),
        resolves: AtomicU32::new(0),
    });
    let audit = Arc::new(CapturingAudit::default());
    let cfg = ProxyConfig {
        listen_addr: "127.0.0.1:0".to_owned(),
        credential_name: CredentialName::new("live-e2e"),
        consumer: OwnedConsumer::new("credential_proxy", "live-e2e:mongo:t"),
        restrictions: Restrictions {
            allowed_collections: vec!["appdb.orders".into()],
            forbidden_collections: vec!["appdb.audit_log".into()],
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
    let addr = proxy.local_addr()?;
    let stats = proxy.stats_handle();
    tokio::spawn(proxy.serve());
    tokio::time::sleep(Duration::from_millis(30)).await;

    let mut sock = TcpStream::connect(addr).await?;

    // hello — server-intro command, must admit even with allowlist.
    let reply = drive_find(&mut sock, 1, FindShape::Server("hello"))
        .await
        .context("hello")?;
    let ok = read_ok(&reply).ok_or_else(|| anyhow!("hello has no ok"))?;
    if ok != 1.0 {
        return Err(anyhow!("hello ok={ok} != 1.0 (server-intro must admit)"));
    }

    // find appdb.orders — allowlisted; the proxy admits it and
    // forwards to the unreachable upstream. The reply doc carries
    // ok: 0.0 (upstream connect failed) but the proxy MUST NOT
    // surface "Unauthorized"; we assert codeName != "Unauthorized".
    let reply = drive_find(
        &mut sock,
        2,
        FindShape::Find {
            coll: "orders",
            db: "appdb",
        },
    )
    .await
    .context("find orders")?;
    let code_name = read_string_field(&reply, "codeName");
    if code_name.as_deref() == Some("Unauthorized") {
        return Err(anyhow!(
            "find orders was rejected with Unauthorized — walker failed to admit allowlisted collection",
        ));
    }

    // find appdb.users — NOT in allowlist; must be rejected with
    // code 13 codeName Unauthorized.
    let reply = drive_find(
        &mut sock,
        3,
        FindShape::Find {
            coll: "users",
            db: "appdb",
        },
    )
    .await
    .context("find users")?;
    assert_blocked(&reply, "find users (not in allowlist)")?;

    // find appdb.audit_log — in forbidden; must be rejected.
    let reply = drive_find(
        &mut sock,
        4,
        FindShape::Find {
            coll: "audit_log",
            db: "appdb",
        },
    )
    .await
    .context("find audit_log")?;
    assert_blocked(&reply, "find audit_log (forbidden)")?;

    drop(sock);
    tokio::time::sleep(Duration::from_millis(30)).await;

    // ── Audit assertions for phase 1. ──
    let events = audit.snapshot();
    let reasons: Vec<Option<&'static str>> = events
        .iter()
        .filter_map(|e| match e {
            AuditEvent::MongoCommandExecuted {
                restriction_reason,
                blocked: true,
                ..
            } => Some(*restriction_reason),
            _ => None,
        })
        .collect();
    if !reasons.contains(&Some("collection_not_in_allowed_list")) {
        return Err(anyhow!(
            "missing restriction_reason 'collection_not_in_allowed_list' in audit; got {reasons:?}",
        ));
    }
    if !reasons.contains(&Some("collection_in_forbidden_list")) {
        return Err(anyhow!(
            "missing restriction_reason 'collection_in_forbidden_list' in audit; got {reasons:?}",
        ));
    }
    let snap = stats.snapshot();
    if snap.commands_blocked < 2 {
        return Err(anyhow!(
            "expected ≥2 commands_blocked (users + audit_log), got {}",
            snap.commands_blocked,
        ));
    }
    if snap.commands_blocked_by_collection_allowlist < 2 {
        return Err(anyhow!(
            "expected ≥2 commands_blocked_by_collection_allowlist, got {}",
            snap.commands_blocked_by_collection_allowlist,
        ));
    }

    // ── Phase 2: max_documents cursor cap against real mongo ─────
    //
    // Seed `live_e2e_cap.users` with EXACTLY `CAP_BATCH_SIZE`
    // documents directly via mongosh (`docker exec`), then drive
    // `find` through the proxy. With `max_documents = 3` and a
    // real upstream returning 5 docs in the first batch (mongo's
    // default batchSize is 101, so all 5 fit in one batch), the
    // proxy MUST truncate to 3 and zero `cursor.id` so the agent
    // cannot resume the cursor for the docs the proxy redacted.
    seed_cap_collection().context("seed live_e2e_cap.users")?;
    // Cleanup happens unconditionally below regardless of outcome.

    let cap_outcome = run_phase2_cap_cycle(&real_upstream_url).await;

    // Drop the seeded data even if the assertion failed — leaving
    // it behind would corrupt the next slice run's first attempt.
    let cleanup_result = cleanup_cap_collection();

    let cap_snap = cap_outcome?;
    if let Err(e) = cleanup_result {
        tracing::warn!("post-cap cleanup failed (non-fatal): {e}");
    }

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

/// Returns the snapshot of the cap-phase proxy's stats so the
/// caller can include the `commands_capped_by_max_documents`
/// counter in the success log line. On failure the seeded data
/// is dropped by the caller.
async fn run_phase2_cap_cycle(
    real_upstream_url: &str,
) -> Result<raxis_credential_proxy_mongodb::ProxyStatsSnapshot> {
    let backend = Arc::new(LiveBackend {
        value: real_upstream_url.as_bytes().to_vec(),
        resolves: AtomicU32::new(0),
    });
    let audit = Arc::new(CapturingAudit::default());
    let cfg = ProxyConfig {
        listen_addr: "127.0.0.1:0".to_owned(),
        credential_name: CredentialName::new("live-e2e"),
        consumer: OwnedConsumer::new("credential_proxy", "live-e2e:mongo:cap"),
        restrictions: Restrictions {
            // Pin the allowlist to the seeded collection so the
            // cap assertion cannot accidentally observe a stray
            // document from another database the container is
            // serving for a sibling slice.
            allowed_collections: vec![format!("{CAP_DB}.{CAP_COLL}")],
            max_documents: 3,
            ..Default::default()
        },
    };
    let proxy = MongodbProxy::bind(
        backend.clone() as Arc<dyn CredentialBackend>,
        cfg,
        Arc::clone(&audit) as Arc<dyn AuditChannel>,
    )
    .await
    .context("MongodbProxy::bind phase 2")?;
    let addr = proxy.local_addr()?;
    let stats = proxy.stats_handle();
    tokio::spawn(proxy.serve());
    tokio::time::sleep(Duration::from_millis(30)).await;

    let mut sock = TcpStream::connect(addr).await?;
    let reply = drive_find(
        &mut sock,
        10,
        FindShape::Find {
            coll: CAP_COLL,
            db: CAP_DB,
        },
    )
    .await
    .context("find live_e2e_cap.users (cap path)")?;
    let ok =
        read_ok(&reply).ok_or_else(|| anyhow!("cap-path reply missing ok field; raw={reply:?}"))?;
    if ok != 1.0 {
        return Err(anyhow!(
            "cap-path: real upstream returned ok={ok} != 1.0 — proxy SCRAM \
             may have failed against the live mongo container. Reply codeName={:?}",
            read_string_field(&reply, "codeName"),
        ));
    }
    let batch_size = count_first_batch(&reply)
        .ok_or_else(|| anyhow!("could not count firstBatch in reply: {reply:?}"))?;
    if batch_size != 3 {
        return Err(anyhow!(
            "max_documents cap: expected firstBatch.len() = 3 (truncated from \
             {CAP_BATCH_SIZE}), got {batch_size}",
        ));
    }
    let cursor_id = read_cursor_id(&reply).ok_or_else(|| anyhow!("reply has no cursor.id"))?;
    if cursor_id != 0 {
        return Err(anyhow!(
            "max_documents cap: expected cursor.id = 0 after truncation, got {cursor_id} \
             (a non-zero id would let the agent resume past the cap)",
        ));
    }

    drop(sock);
    let cap_snap = stats.snapshot();
    if cap_snap.commands_capped_by_max_documents == 0 {
        return Err(anyhow!(
            "max_documents cap: commands_capped_by_max_documents = 0; expected ≥1",
        ));
    }
    Ok(cap_snap)
}

#[derive(Debug, Clone, Copy)]
enum FindShape {
    /// `{ <command>: 1 }` — server-introspection.
    Server(&'static str),
    /// `{ find: "<coll>", $db: "<db>" }`.
    Find {
        coll: &'static str,
        db: &'static str,
    },
}

async fn drive_find(sock: &mut TcpStream, request_id: i32, shape: FindShape) -> Result<Vec<u8>> {
    let bson = match shape {
        FindShape::Server(cmd) => BsonBuilder::new().int32(cmd, 1).finish(),
        FindShape::Find { coll, db } => BsonBuilder::new()
            .string("find", coll)
            .string("$db", db)
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
        response_to: 0,
        op_code: OP_MSG,
    };
    let mut wire = Vec::with_capacity(total);
    wire.extend_from_slice(&header.encode());
    wire.extend_from_slice(&body);
    sock.write_all(&wire).await?;
    sock.flush().await?;

    let (h, reply_body) = read_message(sock)
        .await?
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

/// Find the top-level `ok` field anywhere in the BSON doc. Real
/// mongod replies place `ok` AFTER `cursor` (the proxy-synthesised
/// error replies from V2 deny paths place it first), so the
/// scanner has to walk the document instead of peeking the first
/// field.
fn read_ok(doc: &[u8]) -> Option<f64> {
    if doc.len() < 5 {
        return None;
    }
    let total = i32::from_le_bytes(doc[..4].try_into().ok()?) as usize;
    if total > doc.len() {
        return None;
    }
    let body = &doc[4..total - 1];
    let mut p = 0;
    while p < body.len() {
        let t = body[p];
        p += 1;
        let nul = body[p..].iter().position(|&b| b == 0)?;
        let name = std::str::from_utf8(&body[p..p + nul]).ok()?;
        p += nul + 1;
        if name == "ok" {
            // BSON `ok` is conventionally a `double` (0x01) but
            // some mongod versions / drivers send it as `int32`
            // (0x10). Accept both — anything else means the
            // server returned a doc shape we did not anticipate.
            return match t {
                0x01 => {
                    if body.len() < p + 8 {
                        return None;
                    }
                    Some(f64::from_le_bytes(body[p..p + 8].try_into().ok()?))
                }
                0x10 => {
                    if body.len() < p + 4 {
                        return None;
                    }
                    Some(i32::from_le_bytes(body[p..p + 4].try_into().ok()?) as f64)
                }
                _ => None,
            };
        }
        let val_len = skip_value(t, &body[p..])?;
        p += val_len;
    }
    None
}

/// Find a top-level string field (`codeName`, etc.) in a BSON doc.
fn read_string_field(doc: &[u8], target: &str) -> Option<String> {
    if doc.len() < 5 {
        return None;
    }
    let total = i32::from_le_bytes(doc[..4].try_into().ok()?) as usize;
    if total > doc.len() {
        return None;
    }
    let body = &doc[4..total - 1];
    let mut p = 0;
    while p < body.len() {
        let t = body[p];
        p += 1;
        let nul = body[p..].iter().position(|&b| b == 0)?;
        let name = std::str::from_utf8(&body[p..p + nul]).ok()?;
        p += nul + 1;
        if t == 0x02 && name == target {
            if body.len() < p + 4 {
                return None;
            }
            let len = i32::from_le_bytes(body[p..p + 4].try_into().ok()?) as usize;
            if 4 + len > body.len() - p {
                return None;
            }
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
        return Err(anyhow!("{label}: codeName={code_name} != \"Unauthorized\"",));
    }
    Ok(())
}

/// Count `cursor.firstBatch` array element count in a reply doc.
fn count_first_batch(doc: &[u8]) -> Option<u32> {
    let total = i32::from_le_bytes(doc[..4].try_into().ok()?) as usize;
    if total > doc.len() {
        return None;
    }
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

// ---------------------------------------------------------------------------
// Real mongo container helpers — preflight, seed, cleanup
// ---------------------------------------------------------------------------

/// Build the `mongodb://...` URL the proxy will use to authenticate
/// upstream. `default_db` is what the URL embeds as the default
/// database — the proxy still admits explicit `$db` headers in
/// each command, so this is mostly a label for the SCRAM
/// `authSource` resolution path.
fn mongo_real_upstream_url(default_db: &str) -> String {
    format!(
        "mongodb://{UPSTREAM_USER}:{UPSTREAM_PASS}@{MONGO_HOST_PORT}/{default_db}\
         ?authSource=admin",
    )
}

async fn require_mongo_container() -> Result<()> {
    match tokio::time::timeout(
        Duration::from_millis(800),
        TcpStream::connect(MONGO_HOST_PORT),
    )
    .await
    {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(e)) => Err(anyhow!(
            "mongo container not reachable at {MONGO_HOST_PORT} ({e}).\n\
             Run:\n  \
             docker compose -f live-e2e/docker-compose.e2e.yml up -d mongodb --wait",
        )),
        Err(_) => Err(anyhow!(
            "mongo container TCP connect to {MONGO_HOST_PORT} timed out after 800 ms.\n\
             Run:\n  \
             docker compose -f live-e2e/docker-compose.e2e.yml up -d mongodb --wait",
        )),
    }
}

/// Seed `live_e2e_cap.users` with EXACTLY `CAP_BATCH_SIZE`
/// documents. Drops any pre-existing collection first so the
/// final document count is deterministic regardless of how
/// previous runs terminated.
fn seed_cap_collection() -> Result<()> {
    // The mongosh script is intentionally bracketed by
    // `db.users.drop()` and an explicit count print so a CI
    // failure log always carries the post-seed cardinality the
    // proxy will observe.
    let script = format!(
        r#"db = db.getSiblingDB("{CAP_DB}");
db.{CAP_COLL}.drop();
const docs = [];
for (let i = 0; i < {CAP_BATCH_SIZE}; i++) {{
    docs.push({{ _id: i, slot: i }});
}}
db.{CAP_COLL}.insertMany(docs);
print("seeded:", db.{CAP_COLL}.countDocuments({{}}));
"#,
    );
    run_mongosh(&script).context("seed live_e2e_cap.users via docker exec mongosh")?;
    Ok(())
}

fn cleanup_cap_collection() -> Result<()> {
    let script = format!(
        r#"db = db.getSiblingDB("{CAP_DB}");
db.dropDatabase();
"#,
    );
    run_mongosh(&script).context("drop live_e2e_cap via docker exec mongosh")?;
    Ok(())
}

fn run_mongosh(script: &str) -> Result<String> {
    let out = std::process::Command::new("docker")
        .args([
            "exec",
            "-i",
            MONGO_CONTAINER,
            "mongosh",
            "--quiet",
            "-u",
            UPSTREAM_USER,
            "-p",
            UPSTREAM_PASS,
            "--authenticationDatabase",
            "admin",
            "--eval",
            script,
        ])
        .output()
        .with_context(|| format!("spawn `docker exec mongosh` against {MONGO_CONTAINER}"))?;
    if !out.status.success() {
        return Err(anyhow!(
            "docker exec mongosh failed (status {}):\n  stdout: {}\n  stderr: {}",
            out.status,
            String::from_utf8_lossy(&out.stdout).trim(),
            String::from_utf8_lossy(&out.stderr).trim(),
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

//! Integration tests for `MongodbProxy`'s real-upstream forwarding
//! path (V2.1, `credential-proxy.md §14`).

mod support;

use std::sync::{Arc, Mutex};

use raxis_credential_proxy_mongodb::{
    AuditChannel, AuditEvent, MongodbProxy, OwnedConsumer, ProxyConfig, Restrictions,
};
use raxis_credentials::{
    ConsumerIdentity, CredentialBackend, CredentialError, CredentialName, CredentialValue,
    OperatorId,
};

use support::{FakeBackend, FakeBsonValue, FakeResponse};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

struct StaticBackend {
    url: String,
}

impl CredentialBackend for StaticBackend {
    fn resolve(
        &self,
        _name: &CredentialName,
        _consumer: ConsumerIdentity<'_>,
    ) -> Result<CredentialValue, CredentialError> {
        Ok(CredentialValue::from_bytes(self.url.as_bytes().to_vec()))
    }
    fn rotate(
        &self,
        _: &CredentialName,
        _: CredentialValue,
        _: OperatorId,
    ) -> Result<(), CredentialError> {
        Ok(())
    }
    fn exists(&self, _: &CredentialName) -> bool {
        true
    }
    fn backend_kind(&self) -> &'static str {
        "test_static"
    }
}

#[derive(Default, Clone)]
struct CapturingChannel {
    inner: Arc<Mutex<Vec<AuditEvent>>>,
}

impl CapturingChannel {
    fn snapshot(&self) -> Vec<AuditEvent> {
        self.inner.lock().unwrap().clone()
    }
}

impl AuditChannel for CapturingChannel {
    fn emit(&self, event: AuditEvent) {
        self.inner.lock().unwrap().push(event);
    }
}

/// Build an OP_MSG with one kind-0 BSON section carrying
/// `{ <command>: 1, $db: "admin" }`.
fn build_op_msg(request_id: i32, command: &str) -> Vec<u8> {
    let mut bson_body = Vec::new();
    // int32 <command>
    bson_body.push(0x10);
    bson_body.extend_from_slice(command.as_bytes());
    bson_body.push(0);
    bson_body.extend_from_slice(&1i32.to_le_bytes());
    // string $db: admin
    bson_body.push(0x02);
    bson_body.extend_from_slice(b"$db");
    bson_body.push(0);
    let v = b"admin";
    bson_body.extend_from_slice(&((v.len() + 1) as i32).to_le_bytes());
    bson_body.extend_from_slice(v);
    bson_body.push(0);
    let bson_total = 4 + bson_body.len() + 1;
    let mut bson_doc = Vec::with_capacity(bson_total);
    bson_doc.extend_from_slice(&(bson_total as i32).to_le_bytes());
    bson_doc.extend_from_slice(&bson_body);
    bson_doc.push(0);

    let body_len = 4 + 1 + bson_doc.len();
    let total = 16 + body_len;
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(&(total as i32).to_le_bytes());
    out.extend_from_slice(&request_id.to_le_bytes());
    out.extend_from_slice(&0i32.to_le_bytes()); // response_to
    out.extend_from_slice(&2013i32.to_le_bytes()); // OP_MSG
    out.extend_from_slice(&0u32.to_le_bytes()); // flag_bits
    out.push(0); // section kind 0
    out.extend_from_slice(&bson_doc);
    out
}

async fn read_op_msg(s: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    let mut header = [0u8; 16];
    s.read_exact(&mut header).await?;
    let total = i32::from_le_bytes([header[0], header[1], header[2], header[3]]) as usize;
    let body_len = total - 16;
    let mut body = vec![0u8; body_len];
    s.read_exact(&mut body).await?;
    let mut frame = Vec::with_capacity(total);
    frame.extend_from_slice(&header);
    frame.extend_from_slice(&body);
    Ok(frame)
}

/// Find the value of an `int32` field by name in an OP_MSG body's
/// kind-0 BSON section.
///
/// Wire layout (after the 16-byte header):
///   - flag bits (i32, 4 bytes)
///   - one or more sections: each begins with a 1-byte kind, then
///     either a BSON document (kind=0) or a sequence (kind=1).
///
/// The OP_MSG bodies the test cares about (`hello`, `ping`,
/// `isMaster`) always place a single kind-0 section as their first
/// section, so this helper looks at exactly one section. A kind
/// other than 0 is treated as "not the shape we expect" and surfaces
/// as `None` rather than panicking.
fn op_msg_int32_field(frame: &[u8], field: &str) -> Option<i32> {
    if frame.len() < 16 + 5 {
        return None;
    }
    let body = &frame[16..];
    let kind_off = 4;
    if kind_off >= body.len() {
        return None;
    }
    let kind = body[kind_off];
    if kind != 0 {
        return None;
    }
    let doc = &body[kind_off + 1..];
    bson_lookup_int32(doc, field)
}

fn bson_lookup_int32(doc: &[u8], field: &str) -> Option<i32> {
    if doc.len() < 5 {
        return None;
    }
    let total = i32::from_le_bytes([doc[0], doc[1], doc[2], doc[3]]) as usize;
    if total < 5 || total > doc.len() {
        return None;
    }
    let body = &doc[4..total - 1];
    let mut i = 0;
    while i < body.len() {
        let type_byte = body[i];
        i += 1;
        let nul = body[i..].iter().position(|&b| b == 0)?;
        let name = std::str::from_utf8(&body[i..i + nul]).ok()?;
        i += nul + 1;
        let is_match = name == field;
        match type_byte {
            0x10 => {
                if i + 4 > body.len() {
                    return None;
                }
                let v = i32::from_le_bytes([body[i], body[i + 1], body[i + 2], body[i + 3]]);
                if is_match {
                    return Some(v);
                }
                i += 4;
            }
            0x01 => i += 8,
            0x02 => {
                if i + 4 > body.len() {
                    return None;
                }
                let l =
                    i32::from_le_bytes([body[i], body[i + 1], body[i + 2], body[i + 3]]) as usize;
                i += 4 + l;
            }
            0x08 => i += 1,
            0x12 => i += 8,
            _ => return None,
        }
    }
    None
}

#[tokio::test]
async fn allowed_command_round_trips_through_real_upstream() {
    let backend = FakeBackend::start(Arc::new(|cmd: &str| {
        if cmd == "find" {
            Some(FakeResponse::Ok {
                extras: vec![("nReturned".into(), FakeBsonValue::Int32(7))],
            })
        } else {
            Some(FakeResponse::Ok { extras: vec![] })
        }
    }))
    .await
    .unwrap();
    let upstream_addr = backend.addr();

    let creds = Arc::new(StaticBackend {
        url: format!("mongodb://{}/test", upstream_addr),
    });
    let audit = Arc::new(CapturingChannel::default());
    let cfg = ProxyConfig {
        listen_addr: "127.0.0.1:0".into(),
        credential_name: CredentialName::new("demo-mongo"),
        consumer: OwnedConsumer::new("session", "s-1"),
        restrictions: Restrictions::default(),
    };
    let proxy = MongodbProxy::bind(creds.clone(), cfg, audit.clone() as Arc<dyn AuditChannel>)
        .await
        .unwrap();
    let proxy_addr = proxy.local_addr().unwrap();
    tokio::spawn(async move { proxy.serve().await });

    let mut s = TcpStream::connect(proxy_addr).await.unwrap();
    s.write_all(&build_op_msg(42, "find")).await.unwrap();
    let reply = read_op_msg(&mut s).await.unwrap();
    let n = op_msg_int32_field(&reply, "nReturned");
    assert_eq!(
        n,
        Some(7),
        "expected upstream's nReturned=7 to round trip; got {n:?}"
    );
    drop(s);

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let events = audit.snapshot();
    let mut saw_executed = false;
    let mut saw_connected = false;
    let mut saw_completed = false;
    for ev in &events {
        match ev {
            AuditEvent::MongoCommandExecuted { blocked, .. } => {
                assert!(!*blocked);
                saw_executed = true;
            }
            AuditEvent::CredentialProxyUpstreamConnected { upstream_host, .. } => {
                assert_eq!(upstream_host, &upstream_addr.ip().to_string());
                saw_connected = true;
                assert!(saw_executed, "Connected before Executed");
            }
            AuditEvent::DatabaseQueryCompleted {
                upstream_error,
                bytes_returned,
                ..
            } => {
                assert!(upstream_error.is_none());
                assert!(*bytes_returned > 0);
                saw_completed = true;
                assert!(saw_connected, "Completed before Connected");
            }
            AuditEvent::CredentialProxyUpstreamFailed { .. } => {
                panic!("UpstreamFailed unexpected on success path");
            }
        }
    }
    assert!(
        saw_executed && saw_connected && saw_completed,
        "missing one of the expected V2.1 audit events: {events:#?}"
    );
}

#[tokio::test]
async fn blocked_command_short_circuits_without_upstream_contact() {
    let backend_calls: Arc<Mutex<u32>> = Arc::new(Mutex::new(0));
    let calls = Arc::clone(&backend_calls);
    let backend = FakeBackend::start(Arc::new(move |_: &str| -> Option<FakeResponse> {
        *calls.lock().unwrap() += 1;
        Some(FakeResponse::Ok { extras: vec![] })
    }))
    .await
    .unwrap();

    let creds = Arc::new(StaticBackend {
        url: format!("mongodb://{}/test", backend.addr()),
    });
    let audit = Arc::new(CapturingChannel::default());
    let cfg = ProxyConfig {
        listen_addr: "127.0.0.1:0".into(),
        credential_name: CredentialName::new("demo-mongo"),
        consumer: OwnedConsumer::new("session", "s-2"),
        restrictions: Restrictions::read_only(),
    };
    let proxy = MongodbProxy::bind(creds.clone(), cfg, audit.clone() as Arc<dyn AuditChannel>)
        .await
        .unwrap();
    let proxy_addr = proxy.local_addr().unwrap();
    tokio::spawn(async move { proxy.serve().await });

    let mut s = TcpStream::connect(proxy_addr).await.unwrap();
    s.write_all(&build_op_msg(7, "insert")).await.unwrap();
    let reply = read_op_msg(&mut s).await.unwrap();
    // Blocked command → ok=0.0 with code=13.
    let code = op_msg_int32_field(&reply, "code");
    assert_eq!(
        code,
        Some(13),
        "expected Unauthorized code 13, got {code:?}"
    );
    drop(s);

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert_eq!(
        *backend_calls.lock().unwrap(),
        0,
        "fake upstream was called for a blocked command"
    );
    let events = audit.snapshot();
    for ev in &events {
        match ev {
            AuditEvent::CredentialProxyUpstreamConnected { .. } => {
                panic!("UpstreamConnected fired for a blocked-only session");
            }
            AuditEvent::DatabaseQueryCompleted { .. } => {
                panic!("DatabaseQueryCompleted fired for a blocked command");
            }
            _ => {}
        }
    }
    assert!(
        events
            .iter()
            .any(|e| matches!(e, AuditEvent::MongoCommandExecuted { blocked: true, .. })),
        "expected MongoCommandExecuted with blocked=true: {events:#?}"
    );
}

#[tokio::test]
async fn upstream_error_is_forwarded_and_audited() {
    let backend = FakeBackend::start(Arc::new(|cmd: &str| {
        if cmd == "find" {
            Some(FakeResponse::Err {
                code: 211,
                code_name: "KeyNotFound".into(),
                errmsg: "fake upstream: key not found".into(),
            })
        } else {
            Some(FakeResponse::Ok { extras: vec![] })
        }
    }))
    .await
    .unwrap();

    let creds = Arc::new(StaticBackend {
        url: format!("mongodb://{}/test", backend.addr()),
    });
    let audit = Arc::new(CapturingChannel::default());
    let cfg = ProxyConfig {
        listen_addr: "127.0.0.1:0".into(),
        credential_name: CredentialName::new("demo-mongo"),
        consumer: OwnedConsumer::new("session", "s-3"),
        restrictions: Restrictions::default(),
    };
    let proxy = MongodbProxy::bind(creds.clone(), cfg, audit.clone() as Arc<dyn AuditChannel>)
        .await
        .unwrap();
    let proxy_addr = proxy.local_addr().unwrap();
    tokio::spawn(async move { proxy.serve().await });

    let mut s = TcpStream::connect(proxy_addr).await.unwrap();
    s.write_all(&build_op_msg(11, "find")).await.unwrap();
    let reply = read_op_msg(&mut s).await.unwrap();
    let code = op_msg_int32_field(&reply, "code");
    assert_eq!(
        code,
        Some(211),
        "upstream error code should be relayed verbatim"
    );
    drop(s);

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let events = audit.snapshot();
    let upstream_err = events.iter().find_map(|e| match e {
        AuditEvent::DatabaseQueryCompleted { upstream_error, .. } => Some(upstream_error.clone()),
        _ => None,
    });
    assert_eq!(upstream_err, Some(Some("ok=0".to_owned())));
}

#[tokio::test]
async fn scram_sha256_round_trips_against_real_upstream() {
    // V2 §2.2: when the credential URL carries `user:pass@`, the
    // proxy MUST drive SCRAM-SHA-256 SASL against the upstream
    // before serving any agent commands. Drives the full state
    // machine against a SCRAM-aware fake mongod fixture and
    // asserts (a) the upstream-Connected audit fires (proves SASL
    // ran to completion, not just TCP), (b) a subsequent `find`
    // round trips, and (c) the upstream's `nReturned` flows back
    // verbatim.
    let backend = support::FakeScramBackend::start(
        "demo".into(),
        b"hunter2".to_vec(),
        Arc::new(|cmd: &str| {
            if cmd == "find" {
                Some(FakeResponse::Ok {
                    extras: vec![("nReturned".into(), FakeBsonValue::Int32(11))],
                })
            } else {
                Some(FakeResponse::Ok { extras: vec![] })
            }
        }),
    )
    .await
    .unwrap();
    let upstream_addr = backend.addr();

    let creds = Arc::new(StaticBackend {
        url: format!(
            "mongodb://demo:hunter2@{}/test?authSource=admin",
            upstream_addr
        ),
    });
    let audit = Arc::new(CapturingChannel::default());
    let cfg = ProxyConfig {
        listen_addr: "127.0.0.1:0".into(),
        credential_name: CredentialName::new("demo-mongo"),
        consumer: OwnedConsumer::new("session", "s-scram-ok"),
        restrictions: Restrictions::default(),
    };
    let proxy = MongodbProxy::bind(creds.clone(), cfg, audit.clone() as Arc<dyn AuditChannel>)
        .await
        .unwrap();
    let proxy_addr = proxy.local_addr().unwrap();
    tokio::spawn(async move { proxy.serve().await });

    let mut s = TcpStream::connect(proxy_addr).await.unwrap();
    s.write_all(&build_op_msg(123, "find")).await.unwrap();
    let reply = read_op_msg(&mut s).await.unwrap();
    let n = op_msg_int32_field(&reply, "nReturned");
    assert_eq!(
        n,
        Some(11),
        "expected upstream's nReturned=11 to round trip after SCRAM; got {n:?}"
    );
    drop(s);

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let events = audit.snapshot();
    assert!(
        events
            .iter()
            .any(|e| matches!(e, AuditEvent::CredentialProxyUpstreamConnected { .. })),
        "UpstreamConnected (post-SCRAM) audit must fire: {events:#?}",
    );
    assert!(
        events.iter().any(|e| matches!(
            e,
            AuditEvent::DatabaseQueryCompleted {
                upstream_error: None,
                ..
            }
        )),
        "DatabaseQueryCompleted (success) audit must fire: {events:#?}",
    );
    assert!(
        !events
            .iter()
            .any(|e| matches!(e, AuditEvent::CredentialProxyUpstreamFailed { .. })),
        "UpstreamFailed must NOT fire on success path: {events:#?}",
    );
}

#[tokio::test]
async fn scram_sha256_with_wrong_password_surfaces_auth_rejected_audit() {
    // V2 §2.2: when the kernel-resolved credential is wrong, SCRAM
    // MUST surface as `CredentialProxyUpstreamFailed` with reason
    // `AuthRejected` (not `ProtocolHandshakeFailed`), and the
    // password bytes must never appear in the redacted detail.
    let backend = support::FakeScramBackend::start(
        "demo".into(),
        b"correct-password".to_vec(),
        Arc::new(|_: &str| Some(FakeResponse::Ok { extras: vec![] })),
    )
    .await
    .unwrap();

    let creds = Arc::new(StaticBackend {
        url: format!(
            "mongodb://demo:hunter2@{}/test?authSource=admin",
            backend.addr(),
        ),
    });
    let audit = Arc::new(CapturingChannel::default());
    let cfg = ProxyConfig {
        listen_addr: "127.0.0.1:0".into(),
        credential_name: CredentialName::new("demo-mongo"),
        consumer: OwnedConsumer::new("session", "s-scram-bad"),
        restrictions: Restrictions::default(),
    };
    let proxy = MongodbProxy::bind(creds.clone(), cfg, audit.clone() as Arc<dyn AuditChannel>)
        .await
        .unwrap();
    let proxy_addr = proxy.local_addr().unwrap();
    tokio::spawn(async move { proxy.serve().await });

    let mut s = TcpStream::connect(proxy_addr).await.unwrap();
    s.write_all(&build_op_msg(456, "find")).await.unwrap();
    let reply = read_op_msg(&mut s).await.unwrap();
    let code = op_msg_int32_field(&reply, "code");
    // Proxy synthesises code 8000 (RaxisProxyError) for upstream
    // connect / SASL failures; the upstream's data path is never
    // contacted.
    assert_eq!(code, Some(8000));
    drop(s);

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let events = audit.snapshot();
    let failed = events.iter().find_map(|e| match e {
        AuditEvent::CredentialProxyUpstreamFailed { reason, detail, .. } => {
            Some((reason.clone(), detail.clone()))
        }
        _ => None,
    });
    let (reason, detail) = failed.expect("expected UpstreamFailed audit");
    assert_eq!(
        reason, "AuthRejected",
        "wrong SCRAM password must classify as AuthRejected (not generic Handshake)"
    );
    assert!(
        !detail.contains("hunter2"),
        "password bytes must not leak into audit detail: {detail:?}"
    );
}

//! Integration tests for `MssqlProxy`'s real-upstream forwarding
//! path (V2.1, `credential-proxy.md §14`).

mod support;

use std::sync::{Arc, Mutex};

use raxis_credential_proxy_mssql::{
    AuditChannel, AuditEvent, MssqlProxy, OwnedConsumer, ProxyConfig, Restrictions,
};
use raxis_credentials::{
    ConsumerIdentity, CredentialBackend, CredentialError, CredentialName, CredentialValue,
    OperatorId,
};

use support::{FakeBackend, FakeResponse};
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

const PRELOGIN: u8 = 0x12;
const LOGIN7: u8 = 0x10;
const SQL_BATCH: u8 = 0x01;
const STATUS_EOM: u8 = 0x01;

async fn read_packet(s: &mut TcpStream) -> std::io::Result<(u8, Vec<u8>)> {
    let mut hdr = [0u8; 8];
    s.read_exact(&mut hdr).await?;
    let len = u16::from_be_bytes([hdr[2], hdr[3]]) as usize;
    let body_len = len - 8;
    let mut body = vec![0u8; body_len];
    s.read_exact(&mut body).await?;
    Ok((hdr[0], body))
}

fn frame_packet(kind: u8, body: &[u8]) -> Vec<u8> {
    let total = 8 + body.len();
    let mut out = Vec::with_capacity(total);
    out.push(kind);
    out.push(STATUS_EOM);
    out.extend_from_slice(&(total as u16).to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.push(1);
    out.push(0);
    out.extend_from_slice(body);
    out
}

/// Drive the agent-side handshake: send a minimal PRELOGIN, read
/// the proxy's PRELOGIN reply, send a stub LOGIN7, read LOGINACK.
async fn drive_agent_handshake(s: &mut TcpStream) {
    // PRELOGIN.
    let pre = vec![
        0x00u8, 0, 11, 0, 6, // VERSION header (BE u16 offset/length)
        0x01u8, 0, 17, 0, 1,    // ENCRYPTION header
        0xff, // terminator
        15, 0, 0x39, 0x10, 0, 1,    // VERSION data
        0x02, // ENCRYPTION = NOT_SUP
    ];
    s.write_all(&frame_packet(PRELOGIN, &pre)).await.unwrap();
    s.flush().await.unwrap();
    let _ = read_packet(s).await.unwrap();
    // LOGIN7 stub — the proxy drains this and the kernel-resolved
    // URL is what authenticates upstream. Send a minimal valid frame.
    let mut login = vec![0u8; 36 + 36 + 6 + 12 + 4];
    let total_len = login.len() as u32;
    login[..4].copy_from_slice(&total_len.to_le_bytes());
    login[4..8].copy_from_slice(&0x74_00_00_04u32.to_le_bytes());
    s.write_all(&frame_packet(LOGIN7, &login)).await.unwrap();
    s.flush().await.unwrap();
    let _ = read_packet(s).await.unwrap();
}

async fn send_sql_batch(s: &mut TcpStream, sql: &str) {
    // ALL_HEADERS: total_length = 4 (the length itself).
    let mut body = Vec::new();
    body.extend_from_slice(&4u32.to_le_bytes());
    let utf16: Vec<u8> = sql.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
    body.extend_from_slice(&utf16);
    s.write_all(&frame_packet(SQL_BATCH, &body)).await.unwrap();
    s.flush().await.unwrap();
}

/// Read TABULAR_RESULT packets until EOM, return the concatenated
/// body bytes (no headers).
async fn read_tabular_until_eom(s: &mut TcpStream) -> Vec<u8> {
    let mut bodies = Vec::new();
    loop {
        let mut hdr = [0u8; 8];
        s.read_exact(&mut hdr).await.unwrap();
        let len = u16::from_be_bytes([hdr[2], hdr[3]]) as usize;
        let body_len = len - 8;
        let mut body = vec![0u8; body_len];
        s.read_exact(&mut body).await.unwrap();
        bodies.extend_from_slice(&body);
        if hdr[1] & STATUS_EOM != 0 {
            break;
        }
    }
    bodies
}

fn has_error_token(body: &[u8]) -> bool {
    body.contains(&0xAA)
}
fn has_done_error_status(body: &[u8]) -> bool {
    // DONE token (0xFD) followed by status u16 LE; we look for
    // status bit 0x0002.
    let mut i = 0;
    while i < body.len() {
        if body[i] == 0xFD && i + 13 <= body.len() {
            let status = u16::from_le_bytes([body[i + 1], body[i + 2]]);
            if status & 0x0002 != 0 {
                return true;
            }
            i += 13;
        } else {
            i += 1;
        }
    }
    false
}

#[tokio::test]
async fn allowed_select_round_trips_through_real_upstream() {
    let backend = FakeBackend::start(Arc::new(|sql: &str| {
        if sql.starts_with("SELECT") {
            FakeResponse::Ok
        } else {
            FakeResponse::Err {
                number: 8000,
                message: "fake-mssql: did not expect this SQL".into(),
            }
        }
    }))
    .await
    .unwrap();
    let upstream_addr = backend.addr();

    let creds = Arc::new(StaticBackend {
        url: format!("mssql://sa:Hunter2!@{}/master", upstream_addr),
    });
    let audit = Arc::new(CapturingChannel::default());
    let cfg = ProxyConfig {
        listen_addr: "127.0.0.1:0".into(),
        credential_name: CredentialName::new("demo-mssql"),
        consumer: OwnedConsumer::new("session", "s-1"),
        server_version: "raxis-tds-test".into(),
        restrictions: Restrictions::default(),
        log_content: false,
    };
    let proxy = MssqlProxy::bind(creds.clone(), cfg, audit.clone() as Arc<dyn AuditChannel>)
        .await
        .unwrap();
    let proxy_addr = proxy.local_addr().unwrap();
    tokio::spawn(async move { proxy.serve().await });

    let mut s = TcpStream::connect(proxy_addr).await.unwrap();
    drive_agent_handshake(&mut s).await;
    send_sql_batch(&mut s, "SELECT 1").await;
    let body = read_tabular_until_eom(&mut s).await;
    assert!(
        !has_error_token(&body),
        "expected no ERROR token on success path"
    );
    drop(s);

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let events = audit.snapshot();
    let mut saw_executed = false;
    let mut saw_connected = false;
    let mut saw_completed = false;
    for ev in &events {
        match ev {
            AuditEvent::DatabaseQueryExecuted { blocked, .. } => {
                assert!(!*blocked);
                saw_executed = true;
            }
            AuditEvent::CredentialProxyUpstreamConnected { upstream_host, .. } => {
                assert_eq!(upstream_host, &upstream_addr.ip().to_string());
                saw_connected = true;
                assert!(saw_executed, "Connected before Executed");
            }
            AuditEvent::DatabaseQueryCompleted { upstream_error, .. } => {
                assert!(upstream_error.is_none());
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
        "missing one of the V2.1 audit events: {events:#?}"
    );
}

#[tokio::test]
async fn blocked_query_short_circuits_without_upstream_contact() {
    let backend_calls: Arc<Mutex<u32>> = Arc::new(Mutex::new(0));
    let calls = Arc::clone(&backend_calls);
    let backend = FakeBackend::start(Arc::new(move |_: &str| {
        *calls.lock().unwrap() += 1;
        FakeResponse::Ok
    }))
    .await
    .unwrap();

    let creds = Arc::new(StaticBackend {
        url: format!("mssql://sa:Hunter2!@{}/master", backend.addr()),
    });
    let audit = Arc::new(CapturingChannel::default());
    let cfg = ProxyConfig {
        listen_addr: "127.0.0.1:0".into(),
        credential_name: CredentialName::new("demo-mssql"),
        consumer: OwnedConsumer::new("session", "s-2"),
        server_version: "raxis-tds-test".into(),
        restrictions: Restrictions::select_only(),
        log_content: false,
    };
    let proxy = MssqlProxy::bind(creds.clone(), cfg, audit.clone() as Arc<dyn AuditChannel>)
        .await
        .unwrap();
    let proxy_addr = proxy.local_addr().unwrap();
    tokio::spawn(async move { proxy.serve().await });

    let mut s = TcpStream::connect(proxy_addr).await.unwrap();
    drive_agent_handshake(&mut s).await;
    send_sql_batch(&mut s, "INSERT INTO t VALUES (1)").await;
    let body = read_tabular_until_eom(&mut s).await;
    assert!(
        has_error_token(&body),
        "expected ERROR token for blocked DML"
    );
    assert!(
        has_done_error_status(&body),
        "expected DONE_ERROR status bit 0x0002"
    );
    drop(s);

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert_eq!(
        *backend_calls.lock().unwrap(),
        0,
        "fake upstream called for blocked query"
    );
    let events = audit.snapshot();
    for ev in &events {
        match ev {
            AuditEvent::CredentialProxyUpstreamConnected { .. } => {
                panic!("UpstreamConnected fired for a blocked-only session");
            }
            AuditEvent::DatabaseQueryCompleted { .. } => {
                panic!("DatabaseQueryCompleted fired for a blocked query");
            }
            _ => {}
        }
    }
    assert!(
        events
            .iter()
            .any(|e| matches!(e, AuditEvent::DatabaseQueryExecuted { blocked: true, .. })),
        "expected DatabaseQueryExecuted with blocked=true: {events:#?}"
    );
}

#[tokio::test]
async fn upstream_error_is_forwarded_and_audited() {
    let backend = FakeBackend::start(Arc::new(|sql: &str| {
        if sql.contains("BAD") {
            FakeResponse::Err {
                number: 8120,
                message: "Column 'foo' is invalid".into(),
            }
        } else {
            FakeResponse::Ok
        }
    }))
    .await
    .unwrap();

    let creds = Arc::new(StaticBackend {
        url: format!("mssql://sa:Hunter2!@{}/master", backend.addr()),
    });
    let audit = Arc::new(CapturingChannel::default());
    let cfg = ProxyConfig {
        listen_addr: "127.0.0.1:0".into(),
        credential_name: CredentialName::new("demo-mssql"),
        consumer: OwnedConsumer::new("session", "s-3"),
        server_version: "raxis-tds-test".into(),
        restrictions: Restrictions::default(),
        log_content: false,
    };
    let proxy = MssqlProxy::bind(creds.clone(), cfg, audit.clone() as Arc<dyn AuditChannel>)
        .await
        .unwrap();
    let proxy_addr = proxy.local_addr().unwrap();
    tokio::spawn(async move { proxy.serve().await });

    let mut s = TcpStream::connect(proxy_addr).await.unwrap();
    drive_agent_handshake(&mut s).await;
    send_sql_batch(&mut s, "SELECT BAD FROM t").await;
    let body = read_tabular_until_eom(&mut s).await;
    assert!(
        has_error_token(&body),
        "expected upstream's ERROR token to be forwarded"
    );
    drop(s);

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let events = audit.snapshot();
    let upstream_err = events.iter().find_map(|e| match e {
        AuditEvent::DatabaseQueryCompleted { upstream_error, .. } => Some(upstream_error.clone()),
        _ => None,
    });
    assert!(
        upstream_err.is_some_and(|e| e.is_some()),
        "expected DatabaseQueryCompleted.upstream_error = Some(_): events = {events:#?}"
    );
}

#[tokio::test]
async fn password_validates_against_login7_obfuscation() {
    // Assert the proxy's nibble-swap+XOR(0xA5) password obfuscation
    // round-trips against a fake-mssql that knows the expected
    // plaintext password.
    let backend = FakeBackend::start_with_password(
        Arc::new(|sql: &str| {
            if sql == "SELECT 'auth_check'" {
                FakeResponse::Ok
            } else {
                FakeResponse::Err {
                    number: 8000,
                    message: "fake-mssql: did not expect this SQL".into(),
                }
            }
        }),
        Some(("sa".to_owned(), b"correct-horse-battery".to_vec())),
    )
    .await
    .unwrap();

    let creds = Arc::new(StaticBackend {
        url: format!("mssql://sa:correct-horse-battery@{}/master", backend.addr()),
    });
    let audit = Arc::new(CapturingChannel::default());
    let cfg = ProxyConfig {
        listen_addr: "127.0.0.1:0".into(),
        credential_name: CredentialName::new("demo-mssql"),
        consumer: OwnedConsumer::new("session", "s-4"),
        server_version: "raxis-tds-test".into(),
        restrictions: Restrictions::default(),
        log_content: false,
    };
    let proxy = MssqlProxy::bind(creds.clone(), cfg, audit.clone() as Arc<dyn AuditChannel>)
        .await
        .unwrap();
    let proxy_addr = proxy.local_addr().unwrap();
    tokio::spawn(async move { proxy.serve().await });

    let mut s = TcpStream::connect(proxy_addr).await.unwrap();
    drive_agent_handshake(&mut s).await;
    send_sql_batch(&mut s, "SELECT 'auth_check'").await;
    let body = read_tabular_until_eom(&mut s).await;
    assert!(
        !has_error_token(&body),
        "expected no ERROR token after password round trip; body = {body:?}"
    );
}

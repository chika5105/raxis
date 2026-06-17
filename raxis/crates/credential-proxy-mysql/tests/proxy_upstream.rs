//! Integration tests for `MysqlProxy`'s real-upstream forwarding
//! path (V2.1, `credential-proxy.md §14`).
//!
//! Each test composes:
//!
//!   * `support::FakeBackend` — the in-process fake mysqld that
//!     answers HandshakeV10 + COM_QUERY with test-supplied frames.
//!   * `MysqlProxy` — the real proxy under test, configured to
//!     resolve a `mysql://...` credential pointing at the fake
//!     backend.
//!   * A raw MySQL agent connection — a hand-rolled client that
//!     drives `Protocol::HandshakeV10 → HandshakeResponse41 →
//!     COM_QUERY` against the proxy's loopback port.
//!
//! What the tests assert:
//!
//!   * Allowed queries reach the upstream and the result-set
//!     frames round-trip back to the agent verbatim (with row
//!     count + column names matching the fake's response).
//!   * Blocked queries short-circuit before any upstream contact
//!     (the fake's response callback never fires for the blocked
//!     SQL).
//!   * The full V2.1 audit-event sequence is emitted in the
//!     correct order:
//!     `DatabaseQueryExecuted (allowed) → CredentialProxyUpstreamConnected
//!      → DatabaseQueryCompleted (success)`.
//!   * Upstream errors (an `ERR_Packet` from fake-mysql) are
//!     forwarded to the agent verbatim AND surfaced as a
//!     `DatabaseQueryCompleted { upstream_error: Some(_) }` audit
//!     event.

mod support;

use std::sync::{Arc, Mutex};

use raxis_credential_proxy_mysql::{
    AuditChannel, AuditEvent, MysqlProxy, OwnedConsumer, ProxyConfig, Restrictions,
};
use raxis_credentials::{
    ConsumerIdentity, CredentialBackend, CredentialError, CredentialName, CredentialValue,
    OperatorId,
};

use support::{FakeBackend, FakeResponse};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Minimal `CredentialBackend` impl that always returns the same
/// resolved URL bytes regardless of the requested name. Used so the
/// proxy thinks it's resolving a real credential while the test
/// controls what URL the proxy sees.
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
        _name: &CredentialName,
        _new: CredentialValue,
        _actor: OperatorId,
    ) -> Result<(), CredentialError> {
        Ok(())
    }

    fn exists(&self, _name: &CredentialName) -> bool {
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

async fn read_packet(s: &mut TcpStream) -> std::io::Result<(u8, Vec<u8>)> {
    let mut hdr = [0u8; 4];
    s.read_exact(&mut hdr).await?;
    let len = (hdr[0] as usize) | ((hdr[1] as usize) << 8) | ((hdr[2] as usize) << 16);
    let mut payload = vec![0u8; len];
    if len > 0 {
        s.read_exact(&mut payload).await?;
    }
    Ok((hdr[3], payload))
}

fn frame_packet(payload: &[u8], seq: u8) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + payload.len());
    out.push((payload.len() & 0xff) as u8);
    out.push(((payload.len() >> 8) & 0xff) as u8);
    out.push(((payload.len() >> 16) & 0xff) as u8);
    out.push(seq);
    out.extend_from_slice(payload);
    out
}

/// Drive the agent-side handshake (HandshakeV10 → HandshakeResponse41 →
/// OK_Packet). The proxy ignores the contents of the response, so
/// we just send a minimal one with empty user / no password.
async fn drive_agent_handshake(s: &mut TcpStream) {
    // Read greeting.
    let (_, _greet) = read_packet(s).await.unwrap();
    // Send a minimal HandshakeResponse41.
    let mut p = Vec::new();
    p.extend_from_slice(&0u32.to_le_bytes()); // capabilities
    p.extend_from_slice(&(16u32 * 1024 * 1024).to_le_bytes()); // max_packet
    p.push(0x2d); // charset utf8mb4
    p.extend_from_slice(&[0u8; 23]); // reserved
    p.push(0); // empty username NUL
    p.push(0); // auth length = 0
    s.write_all(&frame_packet(&p, 1)).await.unwrap();
    s.flush().await.unwrap();
    // Read OK_Packet (seq=2).
    let (_, ok) = read_packet(s).await.unwrap();
    assert!(
        !ok.is_empty() && ok[0] == 0x00,
        "expected OK_Packet from proxy"
    );
}

/// Send a COM_QUERY with the given SQL.
async fn send_query(s: &mut TcpStream, sql: &str) {
    let mut p = Vec::with_capacity(1 + sql.len());
    p.push(0x03); // COM_QUERY
    p.extend_from_slice(sql.as_bytes());
    s.write_all(&frame_packet(&p, 0)).await.unwrap();
    s.flush().await.unwrap();
}

/// Read the full text-resultset response (header + cols + EOF +
/// rows + EOF), returning the row count and column names. Returns
/// `Err((code, sqlstate, message))` if the upstream sent an ERR.
async fn read_query_response(
    s: &mut TcpStream,
) -> Result<(Vec<String>, Vec<Vec<Option<Vec<u8>>>>), (u16, String, String)> {
    let (_, p0) = read_packet(s).await.unwrap();
    if !p0.is_empty() && p0[0] == 0xff {
        let code = u16::from_le_bytes([p0[1], p0[2]]);
        let mut i = 3;
        let mut sqlstate = String::new();
        if i < p0.len() && p0[i] == b'#' {
            i += 1;
            sqlstate = String::from_utf8_lossy(&p0[i..i + 5]).into_owned();
            i += 5;
        }
        let msg = String::from_utf8_lossy(&p0[i..]).into_owned();
        return Err((code, sqlstate, msg));
    }
    if !p0.is_empty() && p0[0] == 0x00 {
        // OK_Packet — empty result set.
        return Ok((vec![], vec![]));
    }
    // ResultSetHeader: lenenc int = column count.
    let column_count = decode_lenenc(&p0).unwrap();
    let mut columns = Vec::with_capacity(column_count as usize);
    for _ in 0..column_count {
        let (_, p) = read_packet(s).await.unwrap();
        // Column def: catalog, schema, table, org_table, name, org_name.
        let mut i = 0;
        for _ in 0..5 {
            let (_, consumed) = decode_lenenc_with_len(&p[i..]).unwrap();
            i += consumed;
            // Skip the body bytes too.
            let (_, body_len) = decode_lenenc_with_len(&p[(i - consumed)..]).unwrap();
            let _ = body_len;
        }
        // Hack: just look for the 5th lenenc string (the `name`).
        let (col, _) = read_5th_lenenc_string(&p);
        columns.push(col);
    }
    // EOF.
    let (_, eof) = read_packet(s).await.unwrap();
    assert_eq!(eof[0], 0xfe, "expected EOF after column defs");
    // Rows.
    let mut rows: Vec<Vec<Option<Vec<u8>>>> = Vec::new();
    loop {
        let (_, p) = read_packet(s).await.unwrap();
        if !p.is_empty() && p[0] == 0xfe && p.len() < 9 {
            break;
        }
        // Decode columns_count text-encoded fields.
        let mut row = Vec::with_capacity(column_count as usize);
        let mut i = 0;
        for _ in 0..column_count {
            if i < p.len() && p[i] == 0xfb {
                row.push(None);
                i += 1;
            } else {
                let (val, consumed) = decode_lenenc_with_len(&p[i..]).unwrap();
                let body_start = i + consumed;
                let body_end = body_start + val as usize;
                row.push(Some(p[body_start..body_end].to_vec()));
                i = body_end;
            }
        }
        rows.push(row);
    }
    Ok((columns, rows))
}

fn decode_lenenc(buf: &[u8]) -> Option<u64> {
    decode_lenenc_with_len(buf).map(|(v, _)| v)
}

fn decode_lenenc_with_len(buf: &[u8]) -> Option<(u64, usize)> {
    if buf.is_empty() {
        return None;
    }
    match buf[0] {
        0..=250 => Some((buf[0] as u64, 1)),
        0xfc if buf.len() >= 3 => Some((u16::from_le_bytes([buf[1], buf[2]]) as u64, 3)),
        0xfd if buf.len() >= 4 => Some((
            (buf[1] as u64) | ((buf[2] as u64) << 8) | ((buf[3] as u64) << 16),
            4,
        )),
        0xfe if buf.len() >= 9 => Some((
            u64::from_le_bytes([
                buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7], buf[8],
            ]),
            9,
        )),
        _ => None,
    }
}

fn read_5th_lenenc_string(p: &[u8]) -> (String, usize) {
    let mut i = 0;
    let mut last = String::new();
    for _ in 0..5 {
        let (len, consumed) = decode_lenenc_with_len(&p[i..]).unwrap();
        i += consumed;
        let body_start = i;
        let body_end = i + len as usize;
        last = String::from_utf8_lossy(&p[body_start..body_end]).into_owned();
        i = body_end;
    }
    (last, i)
}

#[tokio::test]
async fn allowed_select_round_trips_through_real_upstream() {
    // Fake upstream: SELECT 1 → one row with one column.
    let backend = FakeBackend::start(Arc::new(|sql: &str| {
        if sql == "SELECT 1" {
            Some(FakeResponse::Rows {
                columns: vec!["one".into()],
                rows: vec![vec![Some(b"1".to_vec())]],
            })
        } else {
            None
        }
    }))
    .await
    .unwrap();
    let upstream_addr = backend.addr();

    let creds = Arc::new(StaticBackend {
        url: format!("mysql://demo@{}/", upstream_addr),
    });
    let audit = Arc::new(CapturingChannel::default());
    let cfg = ProxyConfig {
        listen_addr: "127.0.0.1:0".into(),
        credential_name: CredentialName::new("demo-mysql"),
        consumer: OwnedConsumer::new("session", "s-1"),
        server_version: "8.0.0-raxis-test".into(),
        restrictions: Restrictions::default(),
        log_content: false,
    };
    let proxy = MysqlProxy::bind(creds.clone(), cfg, audit.clone() as Arc<dyn AuditChannel>)
        .await
        .unwrap();
    let proxy_addr = proxy.local_addr().unwrap();
    tokio::spawn(async move { proxy.serve().await });

    let mut s = TcpStream::connect(proxy_addr).await.unwrap();
    drive_agent_handshake(&mut s).await;
    send_query(&mut s, "SELECT 1").await;
    let (cols, rows) = read_query_response(&mut s).await.unwrap();
    assert_eq!(cols, vec!["one"]);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0][0].as_deref(), Some(&b"1"[..]));

    // Quit cleanly.
    let _ = s.write_all(&frame_packet(&[0x01], 0)).await;
    drop(s);

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let events = audit.snapshot();
    // Required ordering: Executed → UpstreamConnected → Completed.
    let mut saw_executed = false;
    let mut saw_connected = false;
    let mut saw_completed = false;
    for ev in &events {
        match ev {
            AuditEvent::DatabaseQueryExecuted { blocked, .. } => {
                assert!(!*blocked, "first query was blocked unexpectedly");
                saw_executed = true;
            }
            AuditEvent::CredentialProxyUpstreamConnected { upstream_host, .. } => {
                assert_eq!(upstream_host, &upstream_addr.ip().to_string());
                saw_connected = true;
                assert!(saw_executed, "Connected before Executed");
            }
            AuditEvent::CredentialProxyUpstreamFailed { .. } => {
                panic!("UpstreamFailed unexpected on success path");
            }
            AuditEvent::DatabaseQueryCompleted {
                rows_returned,
                upstream_error,
                ..
            } => {
                assert_eq!(*rows_returned, 1);
                assert!(upstream_error.is_none());
                saw_completed = true;
                assert!(saw_connected, "Completed before Connected");
            }
        }
    }
    assert!(
        saw_executed && saw_connected && saw_completed,
        "missing one of the expected V2.1 audit events: events = {events:#?}"
    );
}

#[tokio::test]
async fn blocked_query_short_circuits_without_upstream_contact() {
    let backend_calls: Arc<Mutex<u32>> = Arc::new(Mutex::new(0));
    let calls_clone = Arc::clone(&backend_calls);
    let backend = FakeBackend::start(Arc::new(move |_sql: &str| -> Option<FakeResponse> {
        *calls_clone.lock().unwrap() += 1;
        Some(FakeResponse::Ok { affected_rows: 0 })
    }))
    .await
    .unwrap();
    let upstream_addr = backend.addr();

    let creds = Arc::new(StaticBackend {
        url: format!("mysql://demo@{}/", upstream_addr),
    });
    let audit = Arc::new(CapturingChannel::default());
    let cfg = ProxyConfig {
        listen_addr: "127.0.0.1:0".into(),
        credential_name: CredentialName::new("demo-mysql"),
        consumer: OwnedConsumer::new("session", "s-2"),
        server_version: "8.0.0-raxis-test".into(),
        restrictions: Restrictions::select_only(),
        log_content: false,
    };
    let proxy = MysqlProxy::bind(creds.clone(), cfg, audit.clone() as Arc<dyn AuditChannel>)
        .await
        .unwrap();
    let proxy_addr = proxy.local_addr().unwrap();
    tokio::spawn(async move { proxy.serve().await });

    let mut s = TcpStream::connect(proxy_addr).await.unwrap();
    drive_agent_handshake(&mut s).await;
    send_query(&mut s, "INSERT INTO t VALUES (1)").await;
    // Expect ERR_Packet for blocked DML.
    let (_, p) = read_packet(&mut s).await.unwrap();
    assert_eq!(
        p[0], 0xff,
        "expected ERR_Packet for blocked INSERT, got 0x{:02x}",
        p[0]
    );
    let code = u16::from_le_bytes([p[1], p[2]]);
    assert_eq!(code, 1142, "expected ER_TABLEACCESS_DENIED_ERROR");

    let _ = s.write_all(&frame_packet(&[0x01], 0)).await;
    drop(s);

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert_eq!(
        *backend_calls.lock().unwrap(),
        0,
        "fake upstream was called for a blocked query"
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
        "expected DatabaseQueryExecuted with blocked=true: events = {events:#?}"
    );
}

#[tokio::test]
async fn upstream_error_response_is_forwarded_and_audited() {
    let backend = FakeBackend::start(Arc::new(|sql: &str| {
        if sql == "SELECT FROM bad_syntax" {
            Some(FakeResponse::Err {
                code: 1064,
                sqlstate: "42000".into(),
                message: "fake-mysql: syntax error".into(),
            })
        } else {
            None
        }
    }))
    .await
    .unwrap();

    let creds = Arc::new(StaticBackend {
        url: format!("mysql://demo@{}/", backend.addr()),
    });
    let audit = Arc::new(CapturingChannel::default());
    let cfg = ProxyConfig {
        listen_addr: "127.0.0.1:0".into(),
        credential_name: CredentialName::new("demo-mysql"),
        consumer: OwnedConsumer::new("session", "s-3"),
        server_version: "8.0.0-raxis-test".into(),
        restrictions: Restrictions::default(),
        log_content: false,
    };
    let proxy = MysqlProxy::bind(creds.clone(), cfg, audit.clone() as Arc<dyn AuditChannel>)
        .await
        .unwrap();
    let proxy_addr = proxy.local_addr().unwrap();
    tokio::spawn(async move { proxy.serve().await });

    let mut s = TcpStream::connect(proxy_addr).await.unwrap();
    drive_agent_handshake(&mut s).await;
    send_query(&mut s, "SELECT FROM bad_syntax").await;
    let result = read_query_response(&mut s).await;
    let (code, sqlstate, _msg) = result.unwrap_err();
    assert_eq!(code, 1064);
    assert_eq!(sqlstate, "42000");

    drop(s);
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let events = audit.snapshot();
    let completed = events.iter().find_map(|e| match e {
        AuditEvent::DatabaseQueryCompleted { upstream_error, .. } => Some(upstream_error.clone()),
        _ => None,
    });
    assert_eq!(completed, Some(Some("42000".to_owned())));
}

#[tokio::test]
async fn password_validates_against_native_password_challenge() {
    // This test asserts the proxy's `mysql_native_password` scramble
    // matches what the upstream computes against a known password.
    let backend = FakeBackend::start_with_password(
        Arc::new(|sql: &str| {
            if sql == "SELECT auth_check" {
                Some(FakeResponse::Rows {
                    columns: vec!["status".into()],
                    rows: vec![vec![Some(b"ok".to_vec())]],
                })
            } else {
                Some(FakeResponse::Ok { affected_rows: 0 })
            }
        }),
        Some(b"correct-horse-battery".to_vec()),
    )
    .await
    .unwrap();

    let creds = Arc::new(StaticBackend {
        url: format!("mysql://demo:correct-horse-battery@{}/", backend.addr()),
    });
    let audit = Arc::new(CapturingChannel::default());
    let cfg = ProxyConfig {
        listen_addr: "127.0.0.1:0".into(),
        credential_name: CredentialName::new("demo-mysql"),
        consumer: OwnedConsumer::new("session", "s-4"),
        server_version: "8.0.0-raxis-test".into(),
        restrictions: Restrictions::default(),
        log_content: false,
    };
    let proxy = MysqlProxy::bind(creds.clone(), cfg, audit.clone() as Arc<dyn AuditChannel>)
        .await
        .unwrap();
    let proxy_addr = proxy.local_addr().unwrap();
    tokio::spawn(async move { proxy.serve().await });

    let mut s = TcpStream::connect(proxy_addr).await.unwrap();
    drive_agent_handshake(&mut s).await;
    send_query(&mut s, "SELECT auth_check").await;
    let (cols, rows) = read_query_response(&mut s).await.unwrap();
    assert_eq!(cols, vec!["status"]);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0][0].as_deref(), Some(&b"ok"[..]));
}

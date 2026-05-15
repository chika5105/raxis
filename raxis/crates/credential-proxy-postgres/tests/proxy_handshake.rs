//! End-to-end tests for the Postgres proxy.
//!
//! Spins up a real proxy against a fake `CredentialBackend`, an
//! in-process fake-Postgres upstream (per V2.1's real-upstream-
//! forwarding contract), opens a TCP connection from the test
//! (acting as the agent), drives the Postgres frontend protocol
//! against it, and asserts:
//!
//!   * the handshake completes (StartupMessage → AuthenticationOk →
//!     ParameterStatus → BackendKeyData → ReadyForQuery);
//!   * a `SELECT 1` simple query returns `RowDescription` +
//!     `DataRow` + `CommandComplete` + `ReadyForQuery` (the
//!     fake-pg backend returns a known row, so the test asserts on
//!     real bytes flowing through the proxy);
//!   * an `INSERT` under `allow_only_select` is rejected with an
//!     `ErrorResponse` (sqlstate 42501) **before any upstream
//!     contact** (the fake-pg backend records 0 calls);
//!   * `Terminate` ('X') closes the connection cleanly;
//!   * the per-proxy stats counters reflect the queries served
//!     and blocked **and the new V2.1 `upstream_*` counters**;
//!   * the audit channel receives one
//!     `DatabaseQueryExecuted` plus one `DatabaseQueryCompleted`
//!     for each forwarded query, and one
//!     `CredentialProxyUpstreamConnected` per agent connection.
//!
//! No real Postgres server is required — the fake-pg fixture in
//! `support/` implements just enough of the wire protocol for
//! `tokio-postgres`'s `Config::connect(NoTls)` to reach a usable
//! session.

mod support;

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use raxis_credential_proxy_postgres::{
    restriction::Restrictions, AuditChannel, AuditEvent, NoopAuditChannel, OwnedConsumer,
    PostgresProxy, ProxyConfig,
};
use raxis_credentials::{
    ConsumerIdentity, CredentialBackend, CredentialError, CredentialName, CredentialValue, Lease,
    OperatorId,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use support::{FakeBackend as FakePg, FakeResponse, FakeRow, ResponderFn};

// ---------------------------------------------------------------------------
// Fake credential backend
// ---------------------------------------------------------------------------

struct FakeBackend {
    value: std::sync::Mutex<Vec<u8>>,
    resolves: AtomicU32,
}

impl FakeBackend {
    fn new(value: Vec<u8>) -> Self {
        Self {
            value: std::sync::Mutex::new(value),
            resolves: AtomicU32::new(0),
        }
    }
}

impl CredentialBackend for FakeBackend {
    fn resolve(
        &self,
        name: &CredentialName,
        _consumer: ConsumerIdentity<'_>,
    ) -> Result<CredentialValue, CredentialError> {
        if name.as_str() != "demo" {
            return Err(CredentialError::NotFound(name.clone()));
        }
        self.resolves.fetch_add(1, Ordering::Relaxed);
        Ok(CredentialValue::from_bytes(
            self.value.lock().unwrap().clone(),
        ))
    }

    fn rotate(
        &self,
        name: &CredentialName,
        _new_value: CredentialValue,
        _actor: OperatorId,
    ) -> Result<(), CredentialError> {
        Err(CredentialError::Malformed {
            name: name.clone(),
            reason: "fake backend does not support rotation".to_owned(),
        })
    }

    fn exists(&self, name: &CredentialName) -> bool {
        name.as_str() == "demo"
    }

    fn lease(&self, _name: &CredentialName) -> Lease {
        Lease::Forever
    }

    fn backend_kind(&self) -> &'static str {
        "fake"
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async fn write_startup(s: &mut TcpStream) {
    let mut body = Vec::new();
    body.extend_from_slice(&196608i32.to_be_bytes());
    body.extend_from_slice(b"user\0raxis\0\0");
    let len = (body.len() as i32) + 4;
    s.write_all(&len.to_be_bytes()).await.unwrap();
    s.write_all(&body).await.unwrap();
}

async fn read_tagged_message(s: &mut TcpStream) -> (u8, Vec<u8>) {
    let mut tag = [0u8; 1];
    s.read_exact(&mut tag).await.unwrap();
    let mut len_bytes = [0u8; 4];
    s.read_exact(&mut len_bytes).await.unwrap();
    let len = i32::from_be_bytes(len_bytes);
    let mut body = vec![0u8; (len as usize) - 4];
    s.read_exact(&mut body).await.unwrap();
    (tag[0], body)
}

async fn write_query(s: &mut TcpStream, sql: &str) {
    s.write_all(b"Q").await.unwrap();
    let mut body = Vec::new();
    body.extend_from_slice(sql.as_bytes());
    body.push(0);
    let len = (body.len() as i32) + 4;
    s.write_all(&len.to_be_bytes()).await.unwrap();
    s.write_all(&body).await.unwrap();
}

async fn write_terminate(s: &mut TcpStream) {
    s.write_all(b"X").await.unwrap();
    let len = 4i32;
    s.write_all(&len.to_be_bytes()).await.unwrap();
}

async fn drain_until_ready(s: &mut TcpStream) -> Vec<(u8, Vec<u8>)> {
    let mut acc = Vec::new();
    loop {
        let (tag, body) = read_tagged_message(s).await;
        let is_z = tag == b'Z';
        acc.push((tag, body));
        if is_z {
            return acc;
        }
    }
}

/// Boot a fake-pg upstream and return its `host:port` so the proxy's
/// credential URL can point at it.
async fn boot_fake_pg(handler: ResponderFn) -> std::net::SocketAddr {
    let backend = FakePg::start(handler).await.expect("fake-pg bind");
    backend.addr()
}

fn pg_url(addr: std::net::SocketAddr) -> Vec<u8> {
    format!("postgresql://demo:demo@{}:{}/demo", addr.ip(), addr.port()).into_bytes()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn handshake_completes_to_ready_for_query() {
    // Handshake-only: no upstream contact required (lazy connect on
    // first allowed Q). Use a deliberately-unreachable URL so the
    // test fails loudly if any code path tries to dial out.
    let backend = Arc::new(FakeBackend::new(
        b"postgresql://demo:demo@127.0.0.1:1/demo".to_vec(),
    ));
    let cfg = ProxyConfig {
        listen_addr: "127.0.0.1:0".to_owned(),
        credential_name: CredentialName::new("demo"),
        consumer: OwnedConsumer::new("credential_proxy", "test:postgres:0"),
        restrictions: Restrictions::default(),
    };

    let proxy = PostgresProxy::bind(backend, cfg, Arc::new(NoopAuditChannel))
        .await
        .unwrap();
    let addr = proxy.local_addr().unwrap();
    tokio::spawn(proxy.serve());

    let mut s = TcpStream::connect(addr).await.unwrap();
    write_startup(&mut s).await;
    let msgs = drain_until_ready(&mut s).await;
    let tags: Vec<u8> = msgs.iter().map(|(t, _)| *t).collect();
    assert!(
        tags.contains(&b'R'),
        "expected AuthenticationOk; tags = {tags:?}"
    );
    assert!(tags.contains(&b'Z'), "expected ReadyForQuery");

    write_terminate(&mut s).await;
}

#[tokio::test]
async fn select_query_returns_real_rows_through_upstream() {
    // The fake-pg upstream returns a real RowDescription + DataRow
    // for "SELECT 1". The proxy MUST relay those frames to the
    // agent, demonstrating the V2.1 real-upstream-forwarding path.
    let pg_addr = boot_fake_pg(Arc::new(|sql: &str| {
        if sql.trim().starts_with("SELECT") {
            Some(FakeResponse {
                columns: vec!["?column?".into()],
                rows: vec![FakeRow {
                    values: vec![Some(b"1".to_vec())],
                }],
                command_tag: "SELECT 1".into(),
            })
        } else {
            None
        }
    }))
    .await;
    let backend = Arc::new(FakeBackend::new(pg_url(pg_addr)));

    let cfg = ProxyConfig {
        listen_addr: "127.0.0.1:0".to_owned(),
        credential_name: CredentialName::new("demo"),
        consumer: OwnedConsumer::new("credential_proxy", "test:postgres:1"),
        restrictions: Restrictions::default(),
    };

    let proxy = PostgresProxy::bind(backend, cfg, Arc::new(NoopAuditChannel))
        .await
        .unwrap();
    let proxy_stats = proxy.stats_handle();
    let addr = proxy.local_addr().unwrap();
    tokio::spawn(proxy.serve());

    let mut s = TcpStream::connect(addr).await.unwrap();
    write_startup(&mut s).await;
    let _ = drain_until_ready(&mut s).await;

    write_query(&mut s, "SELECT 1").await;
    let msgs = drain_until_ready(&mut s).await;

    let tags: Vec<u8> = msgs.iter().map(|(t, _)| *t).collect();
    assert!(
        tags.contains(&b'T'),
        "expected RowDescription; tags = {tags:?}"
    );
    assert!(
        tags.contains(&b'D'),
        "expected at least one DataRow; tags = {tags:?}"
    );
    assert!(tags.contains(&b'C'), "expected CommandComplete");
    assert_eq!(tags.last(), Some(&b'Z'));

    // Stats sanity.
    let stats = proxy_stats.snapshot();
    assert_eq!(stats.queries_audited, 1);
    assert_eq!(stats.queries_blocked, 0);
    assert_eq!(stats.upstream_connects_attempted, 1);
    assert_eq!(stats.upstream_connects_succeeded, 1);
    assert_eq!(stats.upstream_connects_failed, 0);
    assert!(
        stats.upstream_bytes_forwarded > 0,
        "expected non-zero upstream bytes; got {stats:?}",
    );

    write_terminate(&mut s).await;
}

#[tokio::test]
async fn insert_blocked_under_select_only_short_circuits_before_upstream() {
    // The fake-pg should never be contacted under select-only
    // restriction — the proxy short-circuits with ErrorResponse
    // before any upstream connect.
    let upstream_calls = Arc::new(AtomicU32::new(0));
    let calls = Arc::clone(&upstream_calls);
    let pg_addr = boot_fake_pg(Arc::new(move |_sql: &str| {
        calls.fetch_add(1, Ordering::Relaxed);
        Some(FakeResponse::empty())
    }))
    .await;

    let backend = Arc::new(FakeBackend::new(pg_url(pg_addr)));
    let cfg = ProxyConfig {
        listen_addr: "127.0.0.1:0".to_owned(),
        credential_name: CredentialName::new("demo"),
        consumer: OwnedConsumer::new("credential_proxy", "test:postgres:2"),
        restrictions: Restrictions::select_only(),
    };

    let proxy = PostgresProxy::bind(backend, cfg, Arc::new(NoopAuditChannel))
        .await
        .unwrap();
    let proxy_stats = proxy.stats_handle();
    let addr = proxy.local_addr().unwrap();
    tokio::spawn(proxy.serve());

    let mut s = TcpStream::connect(addr).await.unwrap();
    write_startup(&mut s).await;
    let _ = drain_until_ready(&mut s).await;

    write_query(&mut s, "INSERT INTO t VALUES (1)").await;
    let msgs = drain_until_ready(&mut s).await;

    let tags: Vec<u8> = msgs.iter().map(|(t, _)| *t).collect();
    assert!(
        tags.contains(&b'E'),
        "expected ErrorResponse; tags = {tags:?}"
    );
    assert_eq!(tags.last(), Some(&b'Z'));

    let err_body = msgs
        .iter()
        .find(|(t, _)| *t == b'E')
        .map(|(_, b)| b)
        .unwrap();
    let body_str = String::from_utf8_lossy(err_body);
    assert!(
        body_str.contains("blocked by RAXIS policy"),
        "body = {body_str:?}",
    );

    // Critical: the upstream MUST NOT have been contacted.
    assert_eq!(
        upstream_calls.load(Ordering::Relaxed),
        0,
        "select-only block must short-circuit before upstream",
    );

    let stats = proxy_stats.snapshot();
    assert_eq!(stats.queries_audited, 1);
    assert_eq!(stats.queries_blocked, 1);
    assert_eq!(
        stats.upstream_connects_attempted, 0,
        "blocked queries must not trigger upstream connect"
    );

    write_terminate(&mut s).await;
}

#[tokio::test]
async fn unreachable_upstream_surfaces_clean_error_response() {
    // Point the proxy at a closed port and verify the agent gets a
    // single, well-formed ErrorResponse rather than a hang or a
    // protocol-violation byte sequence.
    let backend = Arc::new(FakeBackend::new(
        // 127.0.0.1:1 is the canonical "nothing is listening" port
        // on most kernels.
        b"postgresql://demo:demo@127.0.0.1:1/demo".to_vec(),
    ));
    let cfg = ProxyConfig {
        listen_addr: "127.0.0.1:0".to_owned(),
        credential_name: CredentialName::new("demo"),
        consumer: OwnedConsumer::new("credential_proxy", "test:postgres:unreach"),
        restrictions: Restrictions::default(),
    };

    let proxy = PostgresProxy::bind(backend, cfg, Arc::new(NoopAuditChannel))
        .await
        .unwrap();
    let proxy_stats = proxy.stats_handle();
    let addr = proxy.local_addr().unwrap();
    tokio::spawn(proxy.serve());

    let mut s = TcpStream::connect(addr).await.unwrap();
    write_startup(&mut s).await;
    let _ = drain_until_ready(&mut s).await;

    write_query(&mut s, "SELECT 1").await;
    let msgs = drain_until_ready(&mut s).await;

    let tags: Vec<u8> = msgs.iter().map(|(t, _)| *t).collect();
    assert!(
        tags.contains(&b'E'),
        "expected ErrorResponse; tags = {tags:?}"
    );
    assert_eq!(tags.last(), Some(&b'Z'));

    let stats = proxy_stats.snapshot();
    assert_eq!(stats.upstream_connects_attempted, 1);
    assert_eq!(stats.upstream_connects_succeeded, 0);
    assert_eq!(stats.upstream_connects_failed, 1);

    write_terminate(&mut s).await;
}

#[tokio::test]
async fn missing_credential_returns_clean_error_on_first_query() {
    // Credential lookup fails but the handshake completes (so the
    // agent gets a clean ErrorResponse on the first allowed query).
    let backend = Arc::new(FakeBackend::new(
        b"postgresql://demo:demo@127.0.0.1:5432/demo".to_vec(),
    ));
    let cfg = ProxyConfig {
        listen_addr: "127.0.0.1:0".to_owned(),
        credential_name: CredentialName::new("does-not-exist"),
        consumer: OwnedConsumer::new("credential_proxy", "test:postgres:miss"),
        restrictions: Restrictions::default(),
    };

    let proxy = PostgresProxy::bind(backend, cfg, Arc::new(NoopAuditChannel))
        .await
        .unwrap();
    let addr = proxy.local_addr().unwrap();
    tokio::spawn(proxy.serve());

    let mut s = TcpStream::connect(addr).await.unwrap();
    write_startup(&mut s).await;
    let _ = drain_until_ready(&mut s).await;

    write_query(&mut s, "SELECT 1").await;
    let msgs = drain_until_ready(&mut s).await;

    let tags: Vec<u8> = msgs.iter().map(|(t, _)| *t).collect();
    assert!(
        tags.contains(&b'E'),
        "expected ErrorResponse; tags = {tags:?}"
    );
    assert_eq!(tags.last(), Some(&b'Z'));

    write_terminate(&mut s).await;
}

// ---------------------------------------------------------------------------
// AuditChannel emission test — verifies the proxy emits the right
// V2.1 audit events (DatabaseQueryExecuted, DatabaseQueryCompleted,
// CredentialProxyUpstreamConnected) when forwarding queries.
// ---------------------------------------------------------------------------

#[derive(Default)]
struct CapturingAudit {
    events: std::sync::Mutex<Vec<AuditEvent>>,
}

impl AuditChannel for CapturingAudit {
    fn emit(&self, event: AuditEvent) {
        self.events.lock().unwrap().push(event);
    }
}

#[tokio::test]
async fn audit_channel_receives_full_v2_1_event_sequence() {
    let pg_addr = boot_fake_pg(Arc::new(|sql: &str| {
        if sql.trim().starts_with("SELECT") {
            Some(FakeResponse {
                columns: vec!["x".into()],
                rows: vec![FakeRow {
                    values: vec![Some(b"42".to_vec())],
                }],
                command_tag: "SELECT 1".into(),
            })
        } else {
            None
        }
    }))
    .await;

    let backend = Arc::new(FakeBackend::new(pg_url(pg_addr)));
    let cfg = ProxyConfig {
        listen_addr: "127.0.0.1:0".to_owned(),
        credential_name: CredentialName::new("demo"),
        consumer: OwnedConsumer::new("credential_proxy", "test:postgres:audit"),
        restrictions: Restrictions::select_only(),
    };
    let audit = Arc::new(CapturingAudit::default());

    let proxy = PostgresProxy::bind(backend, cfg, audit.clone())
        .await
        .unwrap();
    let addr = proxy.local_addr().unwrap();
    tokio::spawn(proxy.serve());

    let mut s = TcpStream::connect(addr).await.unwrap();
    write_startup(&mut s).await;
    let _ = drain_until_ready(&mut s).await;

    write_query(&mut s, "SELECT 1").await;
    let _ = drain_until_ready(&mut s).await;
    write_query(&mut s, "INSERT INTO t VALUES (1)").await;
    let _ = drain_until_ready(&mut s).await;

    write_terminate(&mut s).await;

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let events = audit.events.lock().unwrap();
    // Expected sequence (forwarded SELECT then blocked INSERT):
    //   1. CredentialProxySubstituted (per `INV-SECRET-05` /
    //      `secrets-model.md §2.5`: emitted once per agent
    //      connection right after the proxy resolves real
    //      credential material via `CredentialBackend::resolve`,
    //      BEFORE the simple-query loop runs)
    //   2. DatabaseQueryExecuted   (SELECT, blocked=false)
    //   3. CredentialProxyUpstreamConnected
    //   4. DatabaseQueryCompleted   (rows_returned=1)
    //   5. DatabaseQueryExecuted    (INSERT, blocked=true)
    // The blocked statement does NOT trigger an upstream connect or
    // a Completed event.
    assert!(
        events.len() >= 5,
        "expected at least 5 audit events; got {}: {:#?}",
        events.len(),
        events,
    );

    // First event: CredentialProxySubstituted, fired once per
    // connection at the moment the proxy commits to forwarding the
    // backend-resolved credential. Pins `INV-SECRET-05` on the chain
    // structurally; downstream tests
    // (`credential_substitution_evidence.rs`) filter on this event.
    // Audit-safety: `substitution_shape` is a fixed short string
    // describing the SHAPE of the substitution and MUST NOT carry
    // credential bytes; we assert the canonical postgres-proxy
    // wording and assert it does NOT contain the credential URL's
    // user/password material that the fake backend serves.
    match &events[0] {
        AuditEvent::CredentialProxySubstituted {
            consumer,
            credential,
            substitution_shape,
            ..
        } => {
            assert_eq!(credential.as_str(), "demo");
            assert_eq!(consumer.kind, "credential_proxy");
            assert_eq!(consumer.id, "test:postgres:audit");
            assert_eq!(
                substitution_shape,
                "postgres-url: agent-supplied user/password discarded; \
                 backend-resolved url applied to upstream",
            );
            // INV-SECRET-05 audit-safety: substitution_shape is a
            // fixed descriptor and must never leak the upstream
            // credential bytes (user, password, host, port, dbname).
            for forbidden in [
                "demo:demo",
                &pg_addr.ip().to_string(),
                &pg_addr.port().to_string(),
            ] {
                assert!(
                    !substitution_shape.contains(forbidden),
                    "substitution_shape must not contain credential material `{forbidden}`; \
                     got {substitution_shape:?}",
                );
            }
        }
        other => panic!("event[0] must be CredentialProxySubstituted, got {other:?}"),
    }

    // Second event: DatabaseQueryExecuted for SELECT.
    match &events[1] {
        AuditEvent::DatabaseQueryExecuted {
            operation,
            blocked,
            sql_sha256,
            credential,
            ..
        } => {
            assert_eq!(operation, "SELECT");
            assert!(!blocked);
            assert_eq!(credential.as_str(), "demo");
            assert_eq!(sql_sha256.len(), 64);
        }
        other => panic!("event[1] must be DatabaseQueryExecuted, got {other:?}"),
    }

    // Third event: CredentialProxyUpstreamConnected.
    match &events[2] {
        AuditEvent::CredentialProxyUpstreamConnected {
            upstream_host,
            upstream_port,
            tls,
            ..
        } => {
            assert_eq!(upstream_host, &pg_addr.ip().to_string());
            assert_eq!(*upstream_port, pg_addr.port());
            assert!(!tls, "fake-pg fixture is plaintext");
        }
        other => panic!("event[2] must be CredentialProxyUpstreamConnected, got {other:?}"),
    }

    // Fourth event: DatabaseQueryCompleted for SELECT.
    match &events[3] {
        AuditEvent::DatabaseQueryCompleted {
            rows_returned,
            bytes_returned,
            upstream_error,
            ..
        } => {
            assert_eq!(*rows_returned, 1, "expected 1 row from SELECT 1 fixture");
            assert!(*bytes_returned > 0);
            assert!(upstream_error.is_none());
        }
        other => panic!("event[3] must be DatabaseQueryCompleted, got {other:?}"),
    }

    // Fifth event: DatabaseQueryExecuted for blocked INSERT.
    match &events[4] {
        AuditEvent::DatabaseQueryExecuted {
            operation, blocked, ..
        } => {
            assert_eq!(operation, "INSERT");
            assert!(*blocked, "select-only restriction must block INSERT");
        }
        other => panic!("event[4] must be DatabaseQueryExecuted (blocked), got {other:?}"),
    }
}

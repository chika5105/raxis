//! End-to-end test for the HTTP credential proxy MVP.
//!
//! This test stands up two real services in-process:
//!
//!   1. A tiny `tokio` HTTP/1.1 echo server bound to a loopback port
//!      that captures the inbound `Authorization`, `Host`, and other
//!      request headers and replies with a small JSON body so the
//!      assertions can introspect what the proxy actually forwarded.
//!   2. The `HttpProxy` from this crate, configured to forward to
//!      that echo server.
//!
//! The test then opens a `TcpStream` from the test process (acting as
//! the agent) and drives raw HTTP/1.1 against the proxy. This means
//! every byte path the spec promises — restriction enforcement, header
//! rewriting, credential injection, response forwarding — is exercised
//! against real sockets and a real upstream, with no fakes.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use raxis_credential_proxy_http::{
    AuthMode, HttpProxy, OwnedConsumer, ProxyConfig, restriction::Restrictions,
};
use raxis_credentials::{
    CredentialBackend, CredentialError, CredentialName, CredentialValue,
    ConsumerIdentity, Lease, OperatorId,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

// ---------------------------------------------------------------------------
// Fake credential backend — emits a fixed bearer token on demand.
// ---------------------------------------------------------------------------

struct FakeBackend {
    value:    Vec<u8>,
    resolves: AtomicU32,
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
        Ok(CredentialValue::from_bytes(self.value.clone()))
    }

    fn rotate(
        &self,
        name: &CredentialName,
        _new_value: CredentialValue,
        _actor: OperatorId,
    ) -> Result<(), CredentialError> {
        Err(CredentialError::Malformed {
            name:   name.clone(),
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
// Tiny upstream echo server.
// ---------------------------------------------------------------------------

/// What the upstream observed from the proxy on a single request.
#[derive(Debug, Clone)]
struct Captured {
    method:    String,
    path:      String,
    headers:   BTreeMap<String, String>,
    body:      Vec<u8>,
}

/// Spawn an in-process HTTP/1.1 echo server. Returns its `SocketAddr`
/// and a channel receiving the captured request shape.
async fn spawn_echo(
    response_status: u16,
    response_body:   &'static [u8],
) -> (SocketAddr, tokio::sync::mpsc::UnboundedReceiver<Captured>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr     = listener.local_addr().unwrap();
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = match listener.accept().await {
                Ok(p)  => p,
                Err(_) => return,
            };
            let tx = tx.clone();
            tokio::spawn(async move {
                let mut buf = Vec::with_capacity(4096);
                let mut tmp = [0u8; 1024];
                let header_end = loop {
                    let n = match s.read(&mut tmp).await { Ok(n) => n, Err(_) => return };
                    if n == 0 { return; }
                    buf.extend_from_slice(&tmp[..n]);
                    if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        break p + 4;
                    }
                };
                // Parse request line + headers.
                let head = std::str::from_utf8(&buf[..header_end]).unwrap_or("").to_owned();
                let mut lines = head.split("\r\n");
                let request_line = lines.next().unwrap_or("");
                let mut parts = request_line.split_whitespace();
                let method = parts.next().unwrap_or("").to_owned();
                let path   = parts.next().unwrap_or("").to_owned();
                let mut headers = BTreeMap::new();
                let mut content_length: usize = 0;
                for line in lines {
                    if line.is_empty() { break; }
                    if let Some((name, value)) = line.split_once(":") {
                        let n = name.trim().to_ascii_lowercase();
                        let v = value.trim().to_owned();
                        if n == "content-length" {
                            content_length = v.parse().unwrap_or(0);
                        }
                        headers.insert(n, v);
                    }
                }
                // Read body.
                let mut body = Vec::with_capacity(content_length);
                let body_already = buf.len().saturating_sub(header_end);
                body.extend_from_slice(&buf[header_end..header_end + body_already]);
                while body.len() < content_length {
                    let n = match s.read(&mut tmp).await { Ok(n) => n, Err(_) => break };
                    if n == 0 { break; }
                    body.extend_from_slice(&tmp[..n]);
                }
                body.truncate(content_length);
                let _ = tx.send(Captured {
                    method:  method.clone(),
                    path:    path.clone(),
                    headers: headers.clone(),
                    body:    body.clone(),
                });
                // Write response.
                let resp = format!(
                    "HTTP/1.1 {status} OK\r\n\
                     Content-Type: application/json\r\n\
                     Content-Length: {clen}\r\n\
                     Connection: close\r\n\
                     X-Echo-Method: {method}\r\n\
                     \r\n",
                    status = response_status,
                    clen   = response_body.len(),
                );
                let _ = s.write_all(resp.as_bytes()).await;
                let _ = s.write_all(response_body).await;
                let _ = s.shutdown().await;
            });
        }
    });
    (addr, rx)
}

// ---------------------------------------------------------------------------
// Helpers for driving the proxy as the agent.
// ---------------------------------------------------------------------------

async fn drive_request(
    proxy_addr: SocketAddr,
    request_bytes: &[u8],
) -> (Vec<u8>, Vec<u8>) {
    let mut s = TcpStream::connect(proxy_addr).await.unwrap();
    s.write_all(request_bytes).await.unwrap();
    let mut all = Vec::new();
    s.read_to_end(&mut all).await.unwrap();
    let header_end = all.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
    (all[..header_end].to_vec(), all[header_end + 4..].to_vec())
}

fn http_status_line(headers: &[u8]) -> String {
    let s = std::str::from_utf8(headers).unwrap_or("");
    s.split("\r\n").next().unwrap_or("").to_owned()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn bearer_injected_and_host_rewritten() {
    let (upstream_addr, mut captured_rx) = spawn_echo(200, b"{\"ok\":true}").await;
    let backend = Arc::new(FakeBackend {
        value:    b"sek-r3t-token".to_vec(),
        resolves: AtomicU32::new(0),
    });
    let cfg = ProxyConfig {
        listen_addr:     "127.0.0.1:0".to_owned(),
        upstream_url:    format!("http://{upstream_addr}/"),
        credential_name: CredentialName::new("demo"),
        auth_mode:       AuthMode::Bearer,
        consumer:        OwnedConsumer::new("credential_proxy", "test:http:0"),
        restrictions:    Restrictions::default(),
    };
    let proxy = HttpProxy::bind(backend.clone(), cfg).await.unwrap();
    let proxy_addr = proxy.local_addr().unwrap();
    tokio::spawn(proxy.serve());

    let req = b"GET /widgets?count=10 HTTP/1.1\r\n\
                Host: agent-injected\r\n\
                User-Agent: raxis-test/1.0\r\n\
                Connection: close\r\n\
                \r\n";
    let (head, _body) = drive_request(proxy_addr, req).await;

    assert!(http_status_line(&head).starts_with("HTTP/1.1 200"),
        "expected 200; got {:?}", http_status_line(&head));

    let cap = captured_rx.recv().await.expect("upstream observed nothing");
    assert_eq!(cap.method, "GET");
    assert_eq!(cap.path,   "/widgets?count=10");
    assert_eq!(cap.headers.get("authorization").map(String::as_str),
        Some("Bearer sek-r3t-token"),
        "auth header was not injected; saw {:?}", cap.headers);
    assert_eq!(cap.headers.get("host").map(String::as_str),
        Some(format!("{}", upstream_addr).as_str()),
        "host header was not rewritten; saw {:?}", cap.headers.get("host"));
    assert_eq!(cap.headers.get("user-agent").map(String::as_str),
        Some("raxis-test/1.0"),
        "agent header was not forwarded; saw {:?}", cap.headers.get("user-agent"));

    assert_eq!(backend.resolves.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn method_allowlist_blocks_post() {
    let (upstream_addr, mut captured_rx) = spawn_echo(200, b"{}").await;
    let backend = Arc::new(FakeBackend {
        value:    b"tk".to_vec(),
        resolves: AtomicU32::new(0),
    });
    let cfg = ProxyConfig {
        listen_addr:     "127.0.0.1:0".to_owned(),
        upstream_url:    format!("http://{upstream_addr}/"),
        credential_name: CredentialName::new("demo"),
        auth_mode:       AuthMode::Bearer,
        consumer:        OwnedConsumer::new("credential_proxy", "test:http:1"),
        restrictions:    Restrictions::read_only(),
    };
    let proxy = HttpProxy::bind(backend, cfg).await.unwrap();
    let proxy_addr = proxy.local_addr().unwrap();
    tokio::spawn(proxy.serve());

    let req = b"POST /create HTTP/1.1\r\n\
                Host: ignored\r\n\
                Content-Length: 0\r\n\
                Connection: close\r\n\
                \r\n";
    let (head, _body) = drive_request(proxy_addr, req).await;

    assert!(http_status_line(&head).starts_with("HTTP/1.1 405"),
        "expected 405; got {:?}", http_status_line(&head));
    // The upstream MUST NOT have observed this request.
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_millis(50),
            captured_rx.recv(),
        )
        .await
        .is_err(),
        "upstream observed a request that should have been blocked",
    );
}

#[tokio::test]
async fn path_prefix_blocks_unscoped() {
    let (upstream_addr, mut captured_rx) = spawn_echo(200, b"{}").await;
    let backend = Arc::new(FakeBackend {
        value:    b"tk".to_vec(),
        resolves: AtomicU32::new(0),
    });
    let cfg = ProxyConfig {
        listen_addr:     "127.0.0.1:0".to_owned(),
        upstream_url:    format!("http://{upstream_addr}/"),
        credential_name: CredentialName::new("demo"),
        auth_mode:       AuthMode::Bearer,
        consumer:        OwnedConsumer::new("credential_proxy", "test:http:2"),
        restrictions:    Restrictions {
            allowed_methods:        vec![],
            allowed_path_prefixes:  vec!["/api/v1/widgets".to_owned()],
        },
    };
    let proxy = HttpProxy::bind(backend, cfg).await.unwrap();
    let proxy_addr = proxy.local_addr().unwrap();
    tokio::spawn(proxy.serve());

    // In-prefix path: forwarded.
    let req_in = b"GET /api/v1/widgets/42 HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n";
    let (head, _body) = drive_request(proxy_addr, req_in).await;
    assert!(http_status_line(&head).starts_with("HTTP/1.1 200"));
    let _ = captured_rx.recv().await.expect("upstream should have seen in-prefix request");

    // Out-of-prefix path: blocked with 403.
    let req_out = b"GET /api/v1/users HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n";
    let (head, _body) = drive_request(proxy_addr, req_out).await;
    assert!(http_status_line(&head).starts_with("HTTP/1.1 403"));
}

#[tokio::test]
async fn basic_auth_mode_emits_base64_header() {
    let (upstream_addr, mut captured_rx) = spawn_echo(204, b"").await;
    let backend = Arc::new(FakeBackend {
        value:    b"hunter2".to_vec(),
        resolves: AtomicU32::new(0),
    });
    let cfg = ProxyConfig {
        listen_addr:     "127.0.0.1:0".to_owned(),
        upstream_url:    format!("http://{upstream_addr}/"),
        credential_name: CredentialName::new("demo"),
        auth_mode:       AuthMode::Basic { user: "alice".to_owned() },
        consumer:        OwnedConsumer::new("credential_proxy", "test:http:3"),
        restrictions:    Restrictions::default(),
    };
    let proxy = HttpProxy::bind(backend, cfg).await.unwrap();
    let proxy_addr = proxy.local_addr().unwrap();
    tokio::spawn(proxy.serve());

    let req = b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n";
    let _ = drive_request(proxy_addr, req).await;

    let cap = captured_rx.recv().await.unwrap();
    // base64("alice:hunter2") = "YWxpY2U6aHVudGVyMg=="
    assert_eq!(
        cap.headers.get("authorization").map(String::as_str),
        Some("Basic YWxpY2U6aHVudGVyMg=="),
    );
}

#[tokio::test]
async fn websocket_upgrade_rejected() {
    let (upstream_addr, mut captured_rx) = spawn_echo(200, b"{}").await;
    let backend = Arc::new(FakeBackend {
        value:    b"tk".to_vec(),
        resolves: AtomicU32::new(0),
    });
    let cfg = ProxyConfig {
        listen_addr:     "127.0.0.1:0".to_owned(),
        upstream_url:    format!("http://{upstream_addr}/"),
        credential_name: CredentialName::new("demo"),
        auth_mode:       AuthMode::Bearer,
        consumer:        OwnedConsumer::new("credential_proxy", "test:http:4"),
        restrictions:    Restrictions::default(),
    };
    let proxy = HttpProxy::bind(backend, cfg).await.unwrap();
    let proxy_addr = proxy.local_addr().unwrap();
    tokio::spawn(proxy.serve());

    let req = b"GET /ws HTTP/1.1\r\n\
                Host: x\r\n\
                Connection: Upgrade\r\n\
                Upgrade: websocket\r\n\
                \r\n";
    let (head, _body) = drive_request(proxy_addr, req).await;
    assert!(http_status_line(&head).starts_with("HTTP/1.1 400"),
        "got {:?}", http_status_line(&head));
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_millis(50),
            captured_rx.recv(),
        )
        .await
        .is_err(),
    );
}

#[tokio::test]
async fn missing_credential_returns_502() {
    let (upstream_addr, mut captured_rx) = spawn_echo(200, b"{}").await;
    let backend = Arc::new(FakeBackend {
        value:    b"tk".to_vec(),
        resolves: AtomicU32::new(0),
    });
    let cfg = ProxyConfig {
        listen_addr:     "127.0.0.1:0".to_owned(),
        upstream_url:    format!("http://{upstream_addr}/"),
        credential_name: CredentialName::new("nope"),
        auth_mode:       AuthMode::Bearer,
        consumer:        OwnedConsumer::new("credential_proxy", "test:http:5"),
        restrictions:    Restrictions::default(),
    };
    let proxy = HttpProxy::bind(backend, cfg).await.unwrap();
    let proxy_addr = proxy.local_addr().unwrap();
    tokio::spawn(proxy.serve());

    let req = b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n";
    let (head, _body) = drive_request(proxy_addr, req).await;
    assert!(http_status_line(&head).starts_with("HTTP/1.1 502"),
        "got {:?}", http_status_line(&head));
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_millis(50),
            captured_rx.recv(),
        )
        .await
        .is_err(),
    );
}

#[tokio::test]
async fn post_body_forwarded_to_upstream() {
    let (upstream_addr, mut captured_rx) = spawn_echo(201, b"{\"id\":42}").await;
    let backend = Arc::new(FakeBackend {
        value:    b"tk".to_vec(),
        resolves: AtomicU32::new(0),
    });
    let cfg = ProxyConfig {
        listen_addr:     "127.0.0.1:0".to_owned(),
        upstream_url:    format!("http://{upstream_addr}/"),
        credential_name: CredentialName::new("demo"),
        auth_mode:       AuthMode::Bearer,
        consumer:        OwnedConsumer::new("credential_proxy", "test:http:6"),
        restrictions:    Restrictions::default(),
    };
    let proxy = HttpProxy::bind(backend, cfg).await.unwrap();
    let proxy_addr = proxy.local_addr().unwrap();
    tokio::spawn(proxy.serve());

    let body = b"{\"name\":\"widget\"}";
    let req = format!(
        "POST /widgets HTTP/1.1\r\n\
         Host: x\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n",
        body.len(),
    );
    let mut buf = Vec::new();
    buf.extend_from_slice(req.as_bytes());
    buf.extend_from_slice(body);
    let (head, _body) = drive_request(proxy_addr, &buf).await;
    assert!(http_status_line(&head).starts_with("HTTP/1.1 201"),
        "got {:?}", http_status_line(&head));

    let cap = captured_rx.recv().await.unwrap();
    assert_eq!(cap.method, "POST");
    assert_eq!(cap.body, body);
    assert_eq!(cap.headers.get("content-type").map(String::as_str),
        Some("application/json"));
}

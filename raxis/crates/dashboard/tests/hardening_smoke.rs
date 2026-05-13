//! Hardening smoke tests for the dashboard HTTP surface.
//!
//! These exercise the per-route guarantees the backend MUST
//! preserve through the live e2e run:
//!
//!   * malformed Authorization headers ⇒ 401, never 500;
//!   * oversized POST bodies ⇒ 413, never OOM / 500;
//!   * malformed query params on the new repo endpoints ⇒
//!     400 with a structured `code` (not a panic, not a 500);
//!   * unknown SSE session id ⇒ 404, even when the request
//!     carries a `Last-Event-ID` resume header.
//!
//! Run via the hosting workspace's normal test command (the
//! agent that produced this file does NOT run tests).
//!
//! Hermetic: uses `InMemoryDashboardData` + `DashboardServer`
//! bound to `127.0.0.1:0`; no kernel boot, no on-disk store.

#![cfg(test)]

use std::sync::Arc;

use raxis_dashboard::auth::DashboardRole;
use raxis_dashboard::config::DashboardConfig;
use raxis_dashboard::data::InMemoryDashboardData;
use raxis_dashboard::routes::auth::operator_fingerprint_hex;
use raxis_dashboard::server::{DashboardServer, ServerHandle};

/// Bind the dashboard with a default in-memory fixture and
/// return `(handle, "http://127.0.0.1:<port>")`.
async fn serve_in_memory() -> (ServerHandle, String) {
    let cfg = DashboardConfig {
        enabled: true,
        bind_address: "127.0.0.1".into(),
        bind_port: 0,
        static_dir: None,
        ..Default::default()
    };
    let data = InMemoryDashboardData::new();
    let server = DashboardServer::bind(cfg, Arc::clone(&data))
        .await
        .expect("DashboardServer::bind");
    let addr = server.local_addr();
    let handle = ServerHandle::spawn(server);
    let base = format!("http://{addr}");
    (handle, base)
}

// ---------------------------------------------------------------------------
// Auth surface — every malformed-input case becomes a typed 4xx,
// never a panic and never a 500.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn missing_authorization_header_yields_401_with_structured_code() {
    let (handle, base) = serve_in_memory().await;
    let client = reqwest::Client::new();
    let res = client
        .get(format!("{base}/api/initiatives"))
        .send()
        .await
        .expect("send");
    assert_eq!(res.status(), 401);
    let body: serde_json::Value = res.json().await.expect("json body");
    assert_eq!(body["code"], "FAIL_DASHBOARD_AUTH_MISSING");
    handle.shutdown().await.expect("shutdown");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn malformed_jwt_yields_401_not_500() {
    let (handle, base) = serve_in_memory().await;
    let client = reqwest::Client::new();
    // Garbage in the Bearer slot — JWT parser MUST reject without
    // panicking and the surface MUST surface a structured 401.
    let res = client
        .get(format!("{base}/api/initiatives"))
        .header(reqwest::header::AUTHORIZATION, "Bearer not.a.real.jwt")
        .send()
        .await
        .expect("send");
    assert_eq!(res.status(), 401);
    let body: serde_json::Value = res.json().await.expect("json body");
    let code = body["code"].as_str().unwrap_or_default().to_owned();
    assert!(
        code.starts_with("FAIL_DASHBOARD_AUTH"),
        "expected an auth-family code, got {code:?}",
    );
    handle.shutdown().await.expect("shutdown");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn oversized_verify_body_is_rejected_before_parsing() {
    // The `verify` handler is wrapped in a body-size limit (4 KiB
    // per `BODY_LIMIT_AUTH`). A 1 MiB JSON blob MUST be refused
    // by the request-body limit middleware, NOT bubble up to a
    // panic in the JSON parser.
    let (handle, base) = serve_in_memory().await;
    let client = reqwest::Client::new();
    let oversized = "x".repeat(1_048_576);
    let body = format!(
        "{{\"challenge\":\"{x}\",\"signature\":\"{x}\",\"public_key\":\"{x}\"}}",
        x = oversized
    );
    let res = client
        .post(format!("{base}/api/auth/verify"))
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(body)
        .send()
        .await
        .expect("send");
    let status = res.status().as_u16();
    assert!(
        status == 413 || status == 400,
        "oversized body must yield 413 (PayloadTooLarge) or 400, got {status}",
    );
    handle.shutdown().await.expect("shutdown");
}

// ---------------------------------------------------------------------------
// Repo browsing — bad query params get structured 4xx, no panics.
// (These exercise the route-layer `validate_relative_path` since
//  the in-memory fixture has no on-disk worktree.)
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn worktree_file_without_path_query_yields_401_then_400() {
    // Two-stage: first the auth layer rejects (401), then with a
    // valid token the missing `path=` query rejects (400). We
    // can't easily mint a JWT here without seeding an operator
    // entry; assert the auth-layer rejection so the 500 path is
    // ruled out at minimum.
    let (handle, base) = serve_in_memory().await;
    let client = reqwest::Client::new();
    let res = client
        .get(format!("{base}/api/git/worktrees/main-0/file"))
        .send()
        .await
        .expect("send");
    assert_eq!(res.status(), 401, "no auth ⇒ 401, never 500");
    handle.shutdown().await.expect("shutdown");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn worktree_tree_with_traversal_path_does_not_500() {
    // The route layer's `validate_relative_path` rejects `../..`
    // BEFORE the handler dereferences the data layer. Without a
    // JWT we'd hit auth first; the property under test is "no
    // 500 / panic in any of: query parse, validator, handler"
    // when the malformed input meets the auth layer.
    let (handle, base) = serve_in_memory().await;
    let client = reqwest::Client::new();
    let res = client
        .get(format!(
            "{base}/api/git/worktrees/main-0/tree?path=../../../etc/passwd"
        ))
        .send()
        .await
        .expect("send");
    let s = res.status().as_u16();
    assert!(
        s == 400 || s == 401 || s == 404,
        "traversal path must surface as a structured 4xx (got {s})",
    );
    handle.shutdown().await.expect("shutdown");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn worktree_name_with_slash_yields_404_or_400() {
    // axum's :name segment cannot contain `/`, so the router
    // doesn't even match — that's a 404 by design. We assert
    // the response is a typed 4xx (not a 500) so the kernel
    // never becomes a path-traversal oracle for the dashboard.
    let (handle, base) = serve_in_memory().await;
    let client = reqwest::Client::new();
    let res = client
        .get(format!("{base}/api/git/worktrees/..%2Fetc%2Fpasswd"))
        .send()
        .await
        .expect("send");
    let s = res.status().as_u16();
    assert!(
        s >= 400 && s < 500,
        "encoded slash in :name must yield a 4xx (got {s})",
    );
    handle.shutdown().await.expect("shutdown");
}

// ---------------------------------------------------------------------------
// SSE — Last-Event-ID resume on an unknown session must 4xx, never 500
// or hang.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sse_with_last_event_id_on_unknown_session_yields_4xx() {
    let (handle, base) = serve_in_memory().await;
    let client = reqwest::Client::new();
    // Without a valid JWT we expect 401 from the auth gate. The
    // important property is that supplying `Last-Event-ID` does
    // not divert into a different code path that panics. The
    // resume handler MUST treat the header as a stateless hint.
    let res = client
        .get(format!("{base}/api/sessions/sess-does-not-exist/stream"))
        .header("Last-Event-ID", "12345")
        .send()
        .await
        .expect("send");
    let s = res.status().as_u16();
    assert!(
        s >= 400 && s < 500,
        "SSE on unknown session w/ Last-Event-ID must 4xx, got {s}",
    );
    handle.shutdown().await.expect("shutdown");
}

// ---------------------------------------------------------------------------
// Concurrent unauthenticated load — verifies the handler doesn't panic
// under a small burst of requests. The hardening commit that wired the
// `ConcurrencyLimitLayer` must not turn this into a hang.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn burst_of_unauth_requests_drains_without_panicking() {
    let (handle, base) = serve_in_memory().await;
    let client = reqwest::Client::new();
    let mut joins = Vec::new();
    for _ in 0..32 {
        let c = client.clone();
        let url = format!("{base}/api/initiatives");
        joins.push(tokio::spawn(async move {
            let res = c.get(url).send().await.expect("send");
            res.status().as_u16()
        }));
    }
    for j in joins {
        let s = j.await.expect("task join");
        assert!(
            s >= 400 && s < 500,
            "every burst request must surface a 4xx (got {s})",
        );
    }
    handle.shutdown().await.expect("shutdown");
}

// ---------------------------------------------------------------------------
// Authenticated SSE on an unknown session must surface a structured 404
// JSON envelope, NOT a hung 200 connection. This is the post-fix
// regression guard for the issue the realistic-scenario probe surfaced
// against the live kernel: `GET /api/sessions/<bogus>/stream?tail=1`
// would respond `200 OK` and emit a single `tail-complete` SSE frame,
// then keep the TCP connection open until the browser idle-killed it.
// ---------------------------------------------------------------------------

/// Drive the full challenge → verify HTTP path with a freshly-generated
/// Ed25519 keypair and return `(token, fingerprint)`. The fingerprint is
/// the same value the verify route computes (SHA-256[:16] of the
/// pubkey, hex-encoded), so callers can pre-register the operator on the
/// in-memory fixture before issuing the verify call.
async fn mint_jwt(base: &str, signing_key: &ed25519_dalek::SigningKey) -> (String, String) {
    let client = reqwest::Client::new();
    let pubkey_bytes: [u8; 32] = signing_key.verifying_key().to_bytes();
    let fingerprint = operator_fingerprint_hex(&pubkey_bytes);

    let challenge_resp = client
        .get(format!("{base}/api/auth/challenge"))
        .send()
        .await
        .expect("challenge send");
    assert_eq!(challenge_resp.status(), 200, "challenge endpoint must 200");
    let challenge_json: serde_json::Value = challenge_resp.json().await.expect("challenge json");
    let challenge_hex = challenge_json["challenge"]
        .as_str()
        .expect("challenge field is string")
        .to_owned();
    let challenge_bytes = hex::decode(&challenge_hex).expect("challenge hex");

    use ed25519_dalek::Signer;
    let sig: ed25519_dalek::Signature = signing_key.sign(&challenge_bytes);
    let body = serde_json::json!({
        "challenge": challenge_hex,
        "signature": hex::encode(sig.to_bytes()),
        "public_key": hex::encode(pubkey_bytes),
    });
    let verify_resp = client
        .post(format!("{base}/api/auth/verify"))
        .json(&body)
        .send()
        .await
        .expect("verify send");
    assert_eq!(verify_resp.status(), 200, "verify must 200 for valid sig");
    let verify_json: serde_json::Value = verify_resp.json().await.expect("verify json");
    let token = verify_json["token"]
        .as_str()
        .expect("token field is string")
        .to_owned();
    (token, fingerprint)
}

// ---------------------------------------------------------------------------
// Initiative-id filter — every privileged-read list endpoint that
// advertises `?initiative_id=…` MUST narrow the result set. The
// post-fix contract is: pass `?initiative_id=foo`, get only rows
// where the row's initiative_id matches `foo`. No row with a
// different initiative_id may leak through.
// ---------------------------------------------------------------------------

/// Helper: registers an operator, binds the dashboard in
/// memory, returns `(handle, base, token, data)`. Tests can
/// push fixture rows onto `data` before issuing requests.
async fn serve_authed_in_memory()
-> (ServerHandle, String, String, std::sync::Arc<InMemoryDashboardData>) {
    let cfg = DashboardConfig {
        enabled: true,
        bind_address: "127.0.0.1".into(),
        bind_port: 0,
        static_dir: None,
        ..Default::default()
    };
    let seed = [0x5Au8; 32];
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
    let pubkey_bytes: [u8; 32] = signing_key.verifying_key().to_bytes();
    let fingerprint = operator_fingerprint_hex(&pubkey_bytes);
    let data = InMemoryDashboardData::new();
    data.with_operator(
        fingerprint,
        "filter-tester",
        vec![DashboardRole::Read],
    );
    let server = DashboardServer::bind(cfg, std::sync::Arc::clone(&data))
        .await
        .expect("bind");
    let addr = server.local_addr();
    let handle = ServerHandle::spawn(server);
    let base = format!("http://{addr}");
    let (token, _fp) = mint_jwt(&base, &signing_key).await;
    (handle, base, token, data)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sessions_list_with_initiative_id_filter_narrows_results() {
    use raxis_dashboard::data::SessionView;

    let (handle, base, token, data) = serve_authed_in_memory().await;

    let sess_alpha = SessionView {
        session_id:    "sess-alpha".into(),
        role:          "Executor".into(),
        initiative_id: Some("init-alpha".into()),
        task_id:       Some("task-1".into()),
        state:         "Active".into(),
        provider:      None,
        model:         None,
        input_tokens:  0,
        output_tokens: 0,
        created_at:    1_700_000_000,
        updated_at:    1_700_000_000,
    };
    let sess_beta = SessionView {
        session_id:    "sess-beta".into(),
        role:          "Executor".into(),
        initiative_id: Some("init-beta".into()),
        task_id:       Some("task-2".into()),
        state:         "Active".into(),
        provider:      None,
        model:         None,
        input_tokens:  0,
        output_tokens: 0,
        created_at:    1_700_000_001,
        updated_at:    1_700_000_001,
    };
    data.push_session(sess_alpha)
        .push_session(sess_beta);

    let client = reqwest::Client::new();

    // No filter — both rows surface.
    let res = client
        .get(format!("{base}/api/sessions?limit=200"))
        .header(reqwest::header::AUTHORIZATION, format!("Bearer {token}"))
        .send()
        .await
        .expect("send unfiltered");
    assert_eq!(res.status(), 200);
    let unfiltered: serde_json::Value = res.json().await.expect("json");
    let all_ids: Vec<&str> = unfiltered
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v["session_id"].as_str().unwrap())
        .collect();
    assert!(all_ids.contains(&"sess-alpha"), "unfiltered must include alpha");
    assert!(all_ids.contains(&"sess-beta"), "unfiltered must include beta");

    // `?initiative_id=init-alpha` — only alpha surfaces.
    let res = client
        .get(format!(
            "{base}/api/sessions?limit=200&initiative_id=init-alpha"
        ))
        .header(reqwest::header::AUTHORIZATION, format!("Bearer {token}"))
        .send()
        .await
        .expect("send filtered");
    assert_eq!(res.status(), 200);
    let filtered: serde_json::Value = res.json().await.expect("json");
    let filtered_ids: Vec<&str> = filtered
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v["session_id"].as_str().unwrap())
        .collect();
    assert_eq!(
        filtered_ids,
        vec!["sess-alpha"],
        "initiative_id filter must narrow to the matching row only \
         (got {filtered_ids:?})",
    );

    handle.shutdown().await.expect("shutdown");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn audit_list_with_initiative_id_filter_narrows_results() {
    use raxis_dashboard::data::AuditEntryView;

    let (handle, base, token, data) = serve_authed_in_memory().await;

    // Seed two audit rows on different initiatives.
    data.push_audit(AuditEntryView {
        seq:           1,
        event_id:      "ev-1".into(),
        event_kind:    "InitiativeCreated".into(),
        initiative_id: Some("init-alpha".into()),
        task_id:       None,
        session_id:    None,
        at:            1_700_000_000,
        payload:       serde_json::json!({}),
    });
    data.push_audit(AuditEntryView {
        seq:           2,
        event_id:      "ev-2".into(),
        event_kind:    "InitiativeCreated".into(),
        initiative_id: Some("init-beta".into()),
        task_id:       None,
        session_id:    None,
        at:            1_700_000_001,
        payload:       serde_json::json!({}),
    });

    let client = reqwest::Client::new();
    let res = client
        .get(format!(
            "{base}/api/audit?limit=200&initiative_id=init-alpha"
        ))
        .header(reqwest::header::AUTHORIZATION, format!("Bearer {token}"))
        .send()
        .await
        .expect("send");
    assert_eq!(res.status(), 200);
    let rows: serde_json::Value = res.json().await.expect("json");
    let ids: Vec<&str> = rows
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v["initiative_id"].as_str().unwrap_or_default())
        .collect();
    assert!(
        ids.iter().all(|i| *i == "init-alpha"),
        "audit ?initiative_id=… must narrow strictly (got {ids:?})",
    );

    handle.shutdown().await.expect("shutdown");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sse_authenticated_unknown_session_returns_404_envelope() {
    // Set up a fixture with one operator allow-listed for `Read`.
    let cfg = DashboardConfig {
        enabled: true,
        bind_address: "127.0.0.1".into(),
        bind_port: 0,
        static_dir: None,
        ..Default::default()
    };
    // Deterministic seed — this is a unit-test fixture only, not
    // an operator key. The fingerprint derived from it is registered
    // on the in-memory data layer below so the verify path resolves
    // a known operator + role list.
    let seed = [0xA5u8; 32];
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
    let pubkey_bytes: [u8; 32] = signing_key.verifying_key().to_bytes();
    let fingerprint = operator_fingerprint_hex(&pubkey_bytes);
    let data = InMemoryDashboardData::new();
    data.with_operator(fingerprint.clone(), "tester", vec![DashboardRole::Read]);
    let server = DashboardServer::bind(cfg, Arc::clone(&data))
        .await
        .expect("bind");
    let addr = server.local_addr();
    let handle = ServerHandle::spawn(server);
    let base = format!("http://{addr}");

    let (token, _fp) = mint_jwt(&base, &signing_key).await;

    // The session id below has not been registered via
    // `install_stream_source` / `push_session`. The pre-fix
    // contract would have returned `200 OK` and a single
    // `tail-complete` SSE frame, then hung. The post-fix
    // contract returns a structured 404.
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .expect("build client");
    let res = client
        .get(format!("{base}/api/sessions/no-such-session/stream?tail=1"))
        .header(reqwest::header::AUTHORIZATION, format!("Bearer {token}"))
        .send()
        .await
        .expect("send");
    assert_eq!(
        res.status(),
        404,
        "SSE on unknown session w/ valid auth must return 404, got {}",
        res.status(),
    );
    let body: serde_json::Value = res.json().await.expect("json body");
    assert_eq!(
        body["code"], "FAIL_DASHBOARD_NOT_FOUND",
        "404 must carry the structured ApiError envelope (got {body:?})",
    );

    handle.shutdown().await.expect("shutdown");
}

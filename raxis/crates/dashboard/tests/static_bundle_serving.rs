//! End-to-end test for the SPA bundle serving path.
//! when
//! `[dashboard].static_dir` is set, the dashboard's axum
//! router mounts the directory as the fallback service so:
//!   1. `GET /` returns `index.html` (entry point for the
//!      Vite-built React app),
//!   2. `GET /assets/<file>` returns the static asset
//!      verbatim with the right content-type,
//!   3. `GET /<deep/spa/route>` returns `index.html` so
//!      React Router can resolve the route in the browser
//!      (deep-link reload doesn't 404),
//!   4. `GET /api/*` continues to hit the JSON API and never
//!      falls through to the static service.
//! Uses the REAL [`raxis_dashboard::DashboardServer`] bound to
//! `127.0.0.1:0` and a real `reqwest::Client`. The "bundle" is
//! a tempdir with a stand-in `index.html` + asset so the test
//! is hermetic — it does not depend on `dashboard-fe/dist/`
//! existing on the build host.

#![cfg(test)]

use std::sync::Arc;

use raxis_dashboard::config::DashboardConfig;
use raxis_dashboard::data::InMemoryDashboardData;
use raxis_dashboard::server::{DashboardServer, ServerHandle};

/// Spin up the server with `static_dir` pointing at a tempdir
/// containing a known-good `index.html` and one asset.
async fn serve_with_bundle() -> (ServerHandle, String, tempfile::TempDir) {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path();
    std::fs::create_dir_all(dir.join("assets")).expect("mkdir assets");
    std::fs::write(
        dir.join("index.html"),
        b"<!doctype html><html><body><div id=\"root\"></div></body></html>",
    )
    .expect("write index");
    std::fs::write(dir.join("assets/app.js"), b"console.log('raxis');\n").expect("write asset");

    let cfg = DashboardConfig {
        enabled: true,
        bind_address: "127.0.0.1".into(),
        bind_port: 0,
        static_dir: Some(dir.to_string_lossy().into_owned()),
        ..Default::default()
    };
    let data = InMemoryDashboardData::new();
    let server = DashboardServer::bind(cfg, Arc::clone(&data))
        .await
        .expect("bind");
    let addr = server.local_addr();
    let handle = ServerHandle::spawn(server);
    let base = format!("http://{addr}");
    (handle, base, tmp)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn root_serves_index_html() {
    let (handle, base, _tmp) = serve_with_bundle().await;
    let client = reqwest::Client::new();
    let res = client.get(format!("{base}/")).send().await.expect("send");
    assert_eq!(res.status(), 200, "GET / should succeed");
    let body = res.text().await.expect("body");
    assert!(body.contains("<div id=\"root\">"), "body was {body:?}");
    handle.shutdown().await.expect("shutdown");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn deep_spa_link_falls_back_to_index_html() {
    let (handle, base, _tmp) = serve_with_bundle().await;
    let client = reqwest::Client::new();
    let res = client
        .get(format!("{base}/initiatives/init-abc/dag"))
        .send()
        .await
        .expect("send");
    assert_eq!(res.status(), 200, "deep SPA link must serve index.html");
    let body = res.text().await.expect("body");
    assert!(
        body.contains("<div id=\"root\">"),
        "deep link body should be index.html, got {body:?}"
    );
    handle.shutdown().await.expect("shutdown");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn assets_are_served_with_correct_content_type() {
    let (handle, base, _tmp) = serve_with_bundle().await;
    let client = reqwest::Client::new();
    let res = client
        .get(format!("{base}/assets/app.js"))
        .send()
        .await
        .expect("send");
    assert_eq!(res.status(), 200);
    let ct = res
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .map(|h| h.to_str().unwrap_or("").to_owned())
        .unwrap_or_default();
    assert!(
        ct.starts_with("application/javascript") || ct.starts_with("text/javascript"),
        "expected JS content-type, got {ct:?}",
    );
    let body = res.text().await.expect("body");
    assert!(body.contains("console.log"));
    handle.shutdown().await.expect("shutdown");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn api_requests_do_not_fall_through_to_static_service() {
    // `/api/health` is unauthenticated-allowed for the simple
    // case used here. We just need to assert the response is
    // JSON-shaped (NOT the index.html stand-in) — this proves
    // the API router fires before the ServeDir fallback.
    // The dashboard wires `/api/health` behind the JWT
    // extractor, so an unauth'd request returns the JSON
    // `FAIL_DASHBOARD_AUTH_MISSING` envelope. Either way the
    // body is JSON (not HTML), which is the property that
    // matters for routing precedence.
    let (handle, base, _tmp) = serve_with_bundle().await;
    let client = reqwest::Client::new();
    let res = client
        .get(format!("{base}/api/health"))
        .send()
        .await
        .expect("send");
    let ct = res
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .map(|h| h.to_str().unwrap_or("").to_owned())
        .unwrap_or_default();
    assert!(
        ct.starts_with("application/json"),
        "API endpoint must return JSON even on auth failure (got {ct:?})",
    );
    let body = res.text().await.expect("body");
    assert!(
        !body.contains("<div id=\"root\">"),
        "API request must not fall through to index.html — got {body:?}",
    );
    handle.shutdown().await.expect("shutdown");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn server_without_static_dir_serves_404_for_unknown_routes() {
    // No `static_dir` ⇒ no fallback service ⇒ axum returns 404.
    let cfg = DashboardConfig {
        enabled: true,
        bind_address: "127.0.0.1".into(),
        bind_port: 0,
        static_dir: None,
        ..Default::default()
    };
    let data = InMemoryDashboardData::new();
    let server = DashboardServer::bind(cfg, data).await.expect("bind");
    let addr = server.local_addr();
    let handle = ServerHandle::spawn(server);
    let client = reqwest::Client::new();
    let res = client
        .get(format!("http://{addr}/initiatives/init-abc"))
        .send()
        .await
        .expect("send");
    assert_eq!(
        res.status(),
        404,
        "without static_dir, unknown routes must 404",
    );
    handle.shutdown().await.expect("shutdown");
}

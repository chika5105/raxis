//! End-to-end test against the **real** built React bundle.
//!
//! Spec: `v2_extended_gaps.md §4.4` — when the operator runs
//! `npm run build` under `dashboard-fe/`, the resulting
//! `dist/` directory MUST be servable verbatim by the dashboard
//! backend with `[dashboard].static_dir` pointed at it.
//!
//! Where this differs from `static_bundle_serving.rs`:
//!   * `static_bundle_serving.rs` uses a hand-written tempdir
//!     bundle so the test is hermetic and runs everywhere.
//!   * This test points at `dashboard-fe/dist/` and asserts the
//!     real chunked production bundle (Vite-emitted asset
//!     hashes, `<link rel="modulepreload">` chains, etc.) is
//!     served correctly.
//!
//! The test SKIPS gracefully if the bundle is not present
//! (e.g. on a CI worker that hasn't run `npm run build` yet).
//! The skip message is loud enough to catch the regression
//! "we shipped an installer that wires `static_dir` at a
//! directory that doesn't exist".
//!
//! Uses the REAL [`raxis_dashboard::DashboardServer`] bound to
//! `127.0.0.1:0` and a real `reqwest::Client` — no mocks.

#![cfg(test)]

use std::path::PathBuf;
use std::sync::Arc;

use raxis_dashboard::config::DashboardConfig;
use raxis_dashboard::data::InMemoryDashboardData;
use raxis_dashboard::server::{DashboardServer, ServerHandle};

/// Locate the `dashboard-fe/dist/` directory relative to the
/// crate root. Returns `None` if the bundle hasn't been built
/// yet — the test prints a clear skip notice and exits 0.
fn locate_built_bundle() -> Option<PathBuf> {
    // CARGO_MANIFEST_DIR points at `raxis/crates/dashboard/`.
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let dist = manifest
        .parent() // crates
        .and_then(|p| p.parent()) // raxis
        .map(|p| p.join("dashboard-fe").join("dist"))?;
    if dist.join("index.html").is_file() {
        Some(dist)
    } else {
        None
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_built_bundle_is_served_verbatim() {
    let Some(dist) = locate_built_bundle() else {
        eprintln!(
            "SKIPPED: dashboard-fe/dist/ not built. Run `cd raxis/dashboard-fe && npm run build` to enable this test."
        );
        return;
    };
    let cfg = DashboardConfig {
        enabled: true,
        bind_address: "127.0.0.1".into(),
        bind_port: 0,
        static_dir: Some(dist.to_string_lossy().into_owned()),
        ..Default::default()
    };
    let data = InMemoryDashboardData::new();
    let server = DashboardServer::bind(cfg, Arc::clone(&data))
        .await
        .expect("bind real bundle");
    let addr = server.local_addr();
    let handle = ServerHandle::spawn(server);
    let base = format!("http://{addr}");
    let client = reqwest::Client::new();

    // 1) `GET /` returns the real index.html with the React
    //    root div and at least one Vite-injected module
    //    preload (sanity check that the production bundle
    //    is indeed a code-split build).
    let res = client.get(format!("{base}/")).send().await.expect("send /");
    assert_eq!(res.status(), 200);
    let body = res.text().await.expect("body");
    assert!(body.contains("<div id=\"root\">"), "body: {body:?}");
    assert!(
        body.contains("rel=\"modulepreload\"") || body.contains("rel='modulepreload'"),
        "production bundle should include modulepreload links — body: {body:?}",
    );

    // 2) Pick the JS asset Vite emitted and assert it loads
    //    with the right content-type. We extract the first
    //    `<script type="module" ... src="/assets/...js">`
    //    from index.html so the test self-discovers the
    //    Vite hash without hard-coding it.
    let script_url = body
        .split("src=\"")
        .nth(1)
        .and_then(|chunk| chunk.split('"').next())
        .map(str::to_owned)
        .expect("script src in index.html");
    assert!(
        script_url.starts_with("/assets/") && script_url.ends_with(".js"),
        "expected /assets/<hash>.js, got {script_url:?}",
    );
    let res = client
        .get(format!("{base}{script_url}"))
        .send()
        .await
        .expect("send asset");
    assert_eq!(res.status(), 200, "asset {script_url} must serve");
    let ct = res
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .map(|h| h.to_str().unwrap_or("").to_owned())
        .unwrap_or_default();
    assert!(
        ct.starts_with("application/javascript") || ct.starts_with("text/javascript"),
        "expected JS content-type for {script_url}, got {ct:?}",
    );

    // 3) A deep SPA route must fall through to index.html so
    //    React Router can resolve it on a fresh page load.
    let res = client
        .get(format!("{base}/initiatives/init-abc/dag"))
        .send()
        .await
        .expect("send deep");
    assert_eq!(res.status(), 200);
    let body = res.text().await.expect("body");
    assert!(
        body.contains("<div id=\"root\">"),
        "deep link must serve index.html, got: {body:?}",
    );

    // 4) `/api/*` must NOT fall through to the static
    //    service even when a bundle is mounted.
    let res = client
        .get(format!("{base}/api/health"))
        .send()
        .await
        .expect("send api");
    let ct = res
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .map(|h| h.to_str().unwrap_or("").to_owned())
        .unwrap_or_default();
    assert!(
        ct.starts_with("application/json"),
        "API endpoint must remain JSON even with a real bundle mounted (got {ct:?})",
    );

    handle.shutdown().await.expect("shutdown");
}

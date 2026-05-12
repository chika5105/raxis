//! Slice — V3-readiness witness: real `oauth2.googleapis.com`
//! authentication-failure shape.
//!
//! ## Architectural gap (P0 finding from the credproxy gap-closer audit)
//!
//! The V2 `GcpProxy` is an **IMDS / metadata-server emulator** —
//! it SYNTHESIZES the GCE metadata-server JSON envelope from the
//! operator's `CredentialBackend`-resolved bytes and serves it on
//! a localhost port. The agent's GCP SDK / `gcloud auth
//! application-default print-access-token` /
//! `google-auth-library` reaches for
//! `metadata.google.internal` (which `/etc/hosts` redirects to
//! `127.0.0.1`) and dials the proxy; the proxy returns the cached
//! access token directly. There is NO upstream forwarding code
//! path: the proxy does not call `oauth2.googleapis.com`, does
//! not perform JWT-bearer assertion exchange, and does not mint
//! short-lived OAuth2 tokens from a long-lived service-account
//! JSON key. Per `crates/credential-proxy-gcp/src/lib.rs` "What
//! is deferred":
//!
//!   > **Real `oauth2.googleapis.com` exchange** so the proxy
//!   > mints a fresh OAuth2 access token from a service-account
//!   > JSON key using the JWT-bearer grant. V3 lands this; V2
//!   > mirrors a long-lived token the operator stored in the
//!   > credential backend.
//!
//! Because there is no V2 forwarding path, this slice cannot
//! drive a request through the proxy to the real upstream — there
//! is nothing to drive. Instead this slice exists as a **V3
//! baseline witness**: it pins the canonical authentication-
//! failure response shape from `https://oauth2.googleapis.com/`
//! so the V3 proxy implementation has a stable wire-shape
//! contract to pattern-match against when forwarding the agent's
//! JWT-bearer grant exchange.
//!
//! ## What this slice asserts
//!
//! Gated behind `RAXIS_LIVE_CLOUD_NET=1` (default off).
//!
//! When set:
//!
//!   1. Issue an HTTPS `POST https://oauth2.googleapis.com/token`
//!      with a deliberately-invalid `grant_type` form body. The
//!      Google OAuth2 endpoint rejects malformed grant requests
//!      with a canonical OAuth2 error JSON. (We can't send an
//!      empty body — Google's frontend gives `411 Length
//!      Required` instead of routing to the OAuth2 layer.)
//!   2. Assert the response is `400 Bad Request`.
//!   3. Assert the body parses as JSON and contains an `error`
//!      field. Per RFC 6749 §5.2, OAuth2 errors are pinned to a
//!      closed enum: `invalid_request`, `invalid_client`,
//!      `invalid_grant`, `unauthorized_client`,
//!      `unsupported_grant_type`, `invalid_scope`. The slice
//!      asserts the value is in that set so a Google rotation
//!      to a different RFC-compliant code does not break the
//!      witness.
//!   4. Assert NO credential material from RAXIS appears in the
//!      response — the slice never resolved a credential, never
//!      injected one.
//!
//! No proxy is bound. No `CredentialBackend` is involved. The
//! slice deliberately bypasses the V2 emulator because the V2
//! emulator does not have a forwarding path to test. When V3
//! lands JWT-bearer-grant forwarding the slice should be flipped
//! to drive the request through the proxy.

use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use serde_json::Value as JsonValue;

const REAL_ENDPOINT: &str = "https://oauth2.googleapis.com/token";

/// RFC 6749 §5.2 closed enum of OAuth2 error codes. The slice
/// asserts the response body's `error` field is in this set.
const RFC6749_ERROR_CODES: &[&str] = &[
    "invalid_request",
    "invalid_client",
    "invalid_grant",
    "unauthorized_client",
    "unsupported_grant_type",
    "invalid_scope",
];

pub(crate) async fn run() -> Result<()> {
    if std::env::var("RAXIS_LIVE_CLOUD_NET").ok().as_deref() != Some("1") {
        tracing::info!(
            "slice gcp-proxy-real-endpoint: SKIP — RAXIS_LIVE_CLOUD_NET=1 not set\n\
             hint: set RAXIS_LIVE_CLOUD_NET=1 to exercise the V3 baseline witness against \
             {REAL_ENDPOINT}",
        );
        return Ok(());
    }
    tracing::info!(
        endpoint = REAL_ENDPOINT,
        "slice gcp-proxy-real-endpoint: starting"
    );

    let client = reqwest::Client::builder()
        .user_agent("raxis-live-e2e/gcp-proxy-real-endpoint")
        .timeout(Duration::from_secs(20))
        .no_proxy()
        .build()
        .context("build reqwest client")?;

    // Deliberate malformed `grant_type` to trigger the
    // canonical RFC 6749 §5.2 error path. `reqwest::form` sets
    // both `Content-Type: application/x-www-form-urlencoded` and
    // a precise `Content-Length` (Google's frontend rejects
    // `Transfer-Encoding: chunked` requests with `411 Length
    // Required` before routing to the OAuth2 layer).
    let resp = client
        .post(REAL_ENDPOINT)
        .form(&[("grant_type", "raxis-live-e2e-not-a-real-grant-type")])
        .send()
        .await
        .with_context(|| format!("POST {REAL_ENDPOINT}"))?;

    let status = resp.status();
    let body = resp.text().await.context("read response body")?;

    if status.as_u16() != 400 {
        return Err(anyhow!(
            "expected status 400 from oauth2.googleapis.com empty-body POST, got {status}; body={body:.300}",
        ));
    }
    let parsed: JsonValue =
        serde_json::from_str(&body).with_context(|| format!("parse JSON body: {body:.300}"))?;
    let obj = parsed
        .as_object()
        .ok_or_else(|| anyhow!("response body is not a JSON object: {body:.300}"))?;
    let error_field = obj.get("error").and_then(|v| v.as_str()).ok_or_else(|| {
        anyhow!(
            "response body has no `error` field; got keys {:?}",
            obj.keys().collect::<Vec<_>>(),
        )
    })?;
    if !RFC6749_ERROR_CODES.contains(&error_field) {
        return Err(anyhow!(
            "response body `error` = {error_field:?} is not in the RFC 6749 §5.2 closed enum {RFC6749_ERROR_CODES:?}",
        ));
    }
    if !obj.contains_key("error_description") {
        // Google always emits `error_description` per their docs;
        // pin it as a regression catch.
        return Err(anyhow!(
            "response body has no `error_description` field; Google OAuth2 errors must include one",
        ));
    }

    // Hygiene: a legit oauth2 error never echoes the credentials
    // we did not send, but a future regression upstream of us
    // (e.g. an HTTP intermediary that helpfully echoes request
    // bodies) MUST be caught.
    for forbidden in &["AKIA", "ASIA", "ya29.", "service_account", "private_key"] {
        if body.contains(forbidden) {
            return Err(anyhow!(
                "response body unexpectedly contained credential-shaped substring {forbidden:?}; body={body:.500}",
            ));
        }
    }

    tracing::info!(
        status   = %status,
        error    = error_field,
        body_len = body.len(),
        "slice gcp-proxy-real-endpoint: PASS — V3 baseline witness pinned",
    );
    Ok(())
}

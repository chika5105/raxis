//! Slice — V3-readiness witness: real `login.microsoftonline.com`
//! authentication-failure shape.
//!
//! ## Architectural gap (P0 finding from the credproxy gap-closer audit)
//!
//! The V2 `AzureProxy` is an **IMDS emulator** — it SYNTHESIZES
//! the Azure managed-identity IMDS JSON envelope from the
//! operator's `CredentialBackend`-resolved bytes and serves it on
//! a localhost port. The agent's `azure-identity` /
//! `Azure.Identity` / `@azure/identity` / `az` CLI reaches for
//! `169.254.169.254/metadata/identity/oauth2/token` (which
//! `/etc/hosts` redirects to `127.0.0.1`) and dials the proxy;
//! the proxy returns the cached access token directly. There is
//! NO upstream forwarding code path: the proxy does not call
//! `login.microsoftonline.com`, does not perform OAuth2 client-
//! credentials grant, and does not mint short-lived access tokens
//! from a long-lived service-principal client secret. Per
//! `crates/credential-proxy-azure/src/lib.rs` "What is deferred":
//!
//!   > **Real `oauth2/v2.0/token` exchange** so the proxy mints a
//!   > fresh OAuth2 access token from a service-principal client
//!   > secret using the `client_credentials` grant. V3 lands
//!   > this; V2 mirrors a token the operator stored in the
//!   > credential backend.
//!
//! Because there is no V2 forwarding path, this slice cannot
//! drive a request through the proxy to the real upstream — there
//! is nothing to drive. Instead this slice exists as a **V3
//! baseline witness**: it pins the canonical authentication-
//! failure response shape from
//! `https://login.microsoftonline.com/common/oauth2/v2.0/token`
//! so the V3 proxy implementation has a stable wire-shape
//! contract to pattern-match against when forwarding the agent's
//! client-credentials grant exchange.
//!
//! ## What this slice asserts
//!
//! Gated behind `RAXIS_LIVE_CLOUD_NET=1` (default off).
//!
//! When set:
//!
//!   1. Issue an HTTPS `POST
//!      https://login.microsoftonline.com/common/oauth2/v2.0/token`
//!      with a deliberately-invalid `grant_type` form body.
//!      Microsoft Identity Platform rejects malformed grant
//!      requests with a canonical OAuth2-compatible JSON error
//!      envelope plus AAD-specific `error_codes` and
//!      `correlation_id`. (We can't send an empty body — AAD's
//!      frontend gives `411 Length Required` instead of routing
//!      to the OAuth2 layer.)
//!   2. Assert the response is `400 Bad Request`.
//!   3. Assert the body parses as JSON and contains the canonical
//!      `error` field whose value is in the RFC 6749 §5.2 closed
//!      enum.
//!   4. Assert the body contains the AAD-specific `error_codes`
//!      array — a stable Microsoft extension to RFC 6749. This is
//!      the V3 wire-shape contract.
//!   5. Assert NO credential material from RAXIS appears in the
//!      response — the slice never resolved a credential, never
//!      injected one.
//!
//! No proxy is bound. No `CredentialBackend` is involved. The
//! slice deliberately bypasses the V2 emulator because the V2
//! emulator does not have a forwarding path to test. When V3
//! lands client-credentials-grant forwarding the slice should be
//! flipped to drive the request through the proxy.

use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use serde_json::Value as JsonValue;

const REAL_ENDPOINT: &str = "https://login.microsoftonline.com/common/oauth2/v2.0/token";

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
            "slice azure-proxy-real-endpoint: SKIP — RAXIS_LIVE_CLOUD_NET=1 not set\n\
             hint: set RAXIS_LIVE_CLOUD_NET=1 to exercise the V3 baseline witness against \
             {REAL_ENDPOINT}",
        );
        return Ok(());
    }
    tracing::info!(
        endpoint = REAL_ENDPOINT,
        "slice azure-proxy-real-endpoint: starting"
    );

    let client = reqwest::Client::builder()
        .user_agent("raxis-live-e2e/azure-proxy-real-endpoint")
        .timeout(Duration::from_secs(20))
        .no_proxy()
        .build()
        .context("build reqwest client")?;

    // Deliberate malformed `grant_type` to trigger the AAD
    // OAuth2 error path. `reqwest::form` sets both
    // `Content-Type: application/x-www-form-urlencoded` and a
    // precise `Content-Length` (AAD's frontend rejects
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
            "expected status 400 from login.microsoftonline.com empty-body POST, got {status}; body={body:.300}",
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
        return Err(anyhow!(
            "response body has no `error_description` field; AAD always emits one",
        ));
    }
    // AAD-specific extension: `error_codes` is a numeric array
    // that the V3 proxy will surface to operators (the AAD docs
    // pin this shape).
    let error_codes = obj
        .get("error_codes")
        .ok_or_else(|| {
            anyhow!(
                "response body has no AAD-specific `error_codes` field; got keys {:?}",
                obj.keys().collect::<Vec<_>>(),
            )
        })?
        .as_array()
        .ok_or_else(|| {
            anyhow!(
                "`error_codes` must be a JSON array; got {:?}",
                obj.get("error_codes")
            )
        })?;
    if error_codes.is_empty() {
        return Err(anyhow!(
            "`error_codes` array was empty; AAD always emits at least one"
        ));
    }

    for forbidden in &["AKIA", "ASIA", "ya29.", "service_account", "private_key"] {
        if body.contains(forbidden) {
            return Err(anyhow!(
                "response body unexpectedly contained credential-shaped substring {forbidden:?}; body={body:.500}",
            ));
        }
    }

    tracing::info!(
        status      = %status,
        error       = error_field,
        error_codes = ?error_codes,
        body_len    = body.len(),
        "slice azure-proxy-real-endpoint: PASS — V3 baseline witness pinned",
    );
    Ok(())
}

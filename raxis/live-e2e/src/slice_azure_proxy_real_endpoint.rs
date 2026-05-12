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

//! ## V3 forwarding pivot (`RAXIS_V3_CLOUD_FORWARDING=1`)
//!
//! When both `RAXIS_LIVE_CLOUD_NET=1` and
//! `RAXIS_V3_CLOUD_FORWARDING=1` are set, the slice replaces
//! the malformed-grant baseline with an end-to-end V3
//! forwarding witness:
//!
//!   1. Synthesise a service-principal credential body with
//!      a non-existent `tenant_id` / `client_id` /
//!      `client_secret`.
//!   2. Bind `AzureProxy::bind_v3` against the closed-
//!      allowlist `login.microsoftonline.com` upstream.
//!   3. Dial the proxy's loopback `/metadata/identity/oauth2/token?resource=...`
//!      endpoint. The proxy executes the
//!      `client_credentials`-grant POST upstream; AAD rejects
//!      it (`invalid_request` for the synthetic tenant); the
//!      proxy mirrors the 4xx envelope back.
//!   4. Assert: status is 4xx, body parses as JSON with an
//!      `error` field in the RFC 6749 §5.2 closed enum.

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use raxis_audit_tools::AuditSink;
use raxis_credential_proxy_azure::{
    AzureCacheValue, AzureProxy, ForwardingConfig as AzureForwardingConfig, NoopAuditChannel,
    OwnedConsumer, ProxyConfig, Restrictions,
};
use raxis_credential_proxy_cloud_shared::{CloudHttpClient, CloudUpstreamHost, TokenCache};
use raxis_credentials::{
    ConsumerIdentity, CredentialBackend, CredentialError, CredentialName, CredentialValue, Lease,
    OperatorId,
};
use raxis_test_support::audit_sink::FakeAuditSink;
use serde_json::Value as JsonValue;

const REAL_ENDPOINT: &str = "https://login.microsoftonline.com/common/oauth2/v2.0/token";

/// Local `CredentialBackend` for the V3 forwarding witness.
/// Returns a synthetic service-principal env body whose
/// tenant / client / secret are not real — AAD rejects the
/// client_credentials exchange.
struct SyntheticSpBackend {
    body:     Vec<u8>,
    resolves: AtomicU32,
}

impl CredentialBackend for SyntheticSpBackend {
    fn resolve(
        &self,
        _name:     &CredentialName,
        _consumer: ConsumerIdentity<'_>,
    ) -> std::result::Result<CredentialValue, CredentialError> {
        self.resolves.fetch_add(1, Ordering::SeqCst);
        Ok(CredentialValue::from_bytes(self.body.clone()))
    }
    fn rotate(
        &self, name: &CredentialName, _v: CredentialValue, _a: OperatorId,
    ) -> std::result::Result<(), CredentialError> {
        Err(CredentialError::Malformed {
            name:   name.clone(),
            reason: "live-e2e V3 Azure witness does not rotate".to_owned(),
        })
    }
    fn exists(&self, _name: &CredentialName) -> bool { true }
    fn lease(&self, _: &CredentialName) -> Lease { Lease::Forever }
    fn backend_kind(&self) -> &'static str { "live-e2e-v3-azure-witness" }
}

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
    if std::env::var("RAXIS_V3_CLOUD_FORWARDING").ok().as_deref() == Some("1") {
        return run_v3_forwarding_witness().await;
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

/// V3 forwarding witness. Bind an `AzureProxy::bind_v3` with a
/// synthetic service-principal credential. The proxy executes
/// the real `client_credentials`-grant exchange upstream
/// against `login.microsoftonline.com`; AAD rejects (the tenant
/// is synthetic); the proxy passes through the 4xx OAuth2
/// envelope.
async fn run_v3_forwarding_witness() -> Result<()> {
    tracing::info!(
        endpoint = REAL_ENDPOINT,
        "slice azure-proxy-real-endpoint: V3-forwarding witness starting",
    );

    // GUID-shaped but non-existent tenant + client + secret —
    // AAD rejects with `invalid_request` /
    // `unauthorized_client`.
    let sp_env =
        "AZURE_TENANT_ID=00000000-0000-0000-0000-000000000001\n\
         AZURE_CLIENT_ID=00000000-0000-0000-0000-000000000002\n\
         AZURE_CLIENT_SECRET=raxis-v3-witness-opaque-secret-not-real\n";
    let backend: Arc<dyn CredentialBackend> = Arc::new(SyntheticSpBackend {
        body:     sp_env.as_bytes().to_vec(),
        resolves: AtomicU32::new(0),
    });

    let upstream = CloudUpstreamHost::azure_login();
    let http_client = Arc::new(
        CloudHttpClient::new(upstream.clone())
            .context("construct CloudHttpClient for login.microsoftonline.com")?,
    );
    let token_cache = Arc::new(TokenCache::<AzureCacheValue>::new(Duration::from_secs(300)));
    let audit_sink: Arc<dyn AuditSink> = Arc::new(FakeAuditSink::new());

    let fwd = AzureForwardingConfig {
        upstream,
        cache_safety_window: Duration::from_secs(300),
    };

    let cfg = ProxyConfig {
        listen_addr:     "127.0.0.1:0".to_owned(),
        credential_name: CredentialName::new("live-e2e-v3-azure"),
        consumer:        OwnedConsumer::new("live-e2e-azure-slice", "v3-witness"),
        lease_seconds:   3600,
        tenant_id:       "live-e2e-v3-tenant".to_owned(),
        client_id:       None,
        forwarding:      Some(fwd),
        restrictions: Restrictions {
            allowed_resources: vec!["https://management.azure.com/".to_owned()],
            allowed_actions:   Vec::new(),
        },
    };

    let proxy = AzureProxy::bind_v3(
        backend,
        cfg,
        Arc::new(NoopAuditChannel::default()),
        Arc::clone(&audit_sink),
        http_client,
        token_cache,
    )
    .await
    .context("bind AzureProxy V3")?;
    let addr = proxy.local_addr().context("AzureProxy local_addr")?;
    tokio::spawn(async move { proxy.serve().await; });

    let url = format!(
        "http://{addr}/metadata/identity/oauth2/token\
         ?api-version=2018-02-01\
         &resource=https%3A%2F%2Fmanagement.azure.com%2F",
    );
    let client = reqwest::Client::builder()
        .user_agent("raxis-live-e2e/azure-proxy-real-endpoint-v3")
        .timeout(Duration::from_secs(20))
        .no_proxy()
        .build()
        .context("build reqwest client")?;
    let resp = client.get(&url)
        .header("Metadata", "true")
        .send().await
        .with_context(|| format!("GET {url}"))?;
    let status = resp.status();
    let body   = resp.text().await.context("read response body")?;

    if status.is_success() {
        return Err(anyhow!(
            "expected 4xx pass-through from login.microsoftonline.com for synthetic \
             service principal, got 200; body={body:.500}",
        ));
    }
    if !(status.as_u16() >= 400 && status.as_u16() < 600) {
        return Err(anyhow!(
            "expected 4xx/5xx status from V3 forwarding witness, got {status}; \
             body={body:.500}",
        ));
    }
    let parsed: JsonValue = serde_json::from_str(&body)
        .with_context(|| format!("parse V3 envelope JSON: {body:.500}"))?;
    let error_field = parsed.get("error").and_then(|v| v.as_str()).ok_or_else(|| {
        anyhow!(
            "V3-forwarding response body has no `error` field; body={body:.500}",
        )
    })?;
    if !RFC6749_ERROR_CODES.contains(&error_field) {
        return Err(anyhow!(
            "V3-forwarding response `error` = {error_field:?} not in RFC 6749 §5.2 \
             closed enum {RFC6749_ERROR_CODES:?}",
        ));
    }
    if body.contains("raxis-v3-witness-opaque-secret-not-real") {
        return Err(anyhow!(
            "V3-forwarding response body unexpectedly contained the client_secret bytes; \
             body={body:.500}",
        ));
    }

    tracing::info!(
        status   = %status,
        error    = error_field,
        body_len = body.len(),
        "slice azure-proxy-real-endpoint: PASS — V3 upstream-forwarding witness pinned",
    );
    Ok(())
}

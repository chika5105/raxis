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

//! ## V3 forwarding pivot (`RAXIS_V3_CLOUD_FORWARDING=1`)
//!
//! When BOTH `RAXIS_LIVE_CLOUD_NET=1` AND
//! `RAXIS_V3_CLOUD_FORWARDING=1` are set, the slice replaces
//! the unsigned-baseline witness with an end-to-end V3
//! forwarding witness:
//!
//!   1. Generate a throwaway RSA-2048 key at startup and
//!      assemble a service-account-JSON-shaped credential body
//!      (`client_email`, `private_key`, `private_key_id`,
//!      `token_uri`). The `client_email` deliberately points
//!      at a non-existent service account so Google rejects
//!      the JWT-bearer exchange.
//!   2. Bind `GcpProxy::bind_v3` with `ForwardingConfig` pinned
//!      to `oauth2.googleapis.com` and scope
//!      `https://www.googleapis.com/auth/cloud-platform`.
//!   3. Dial the proxy's loopback `/computeMetadata/v1/...token`
//!      endpoint. The proxy mints + signs the JWT, POSTs to
//!      real `oauth2.googleapis.com`, receives a 4xx RFC 6749
//!      envelope, and mirrors it back verbatim.
//!   4. Assert: status is 4xx, body parses as JSON with an
//!      `error` field in the RFC 6749 §5.2 closed enum.

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use raxis_audit_tools::AuditSink;
use raxis_credential_proxy_cloud_shared::{CloudHttpClient, CloudUpstreamHost, TokenCache};
use raxis_credential_proxy_gcp::{
    ForwardingConfig as GcpForwardingConfig, GcpCacheValue, GcpProxy, NoopAuditChannel,
    OwnedConsumer, ProxyConfig, Restrictions,
};
use raxis_credentials::{
    ConsumerIdentity, CredentialBackend, CredentialError, CredentialName, CredentialValue, Lease,
    OperatorId,
};
use raxis_test_support::audit_sink::FakeAuditSink;
use rsa::pkcs8::{EncodePrivateKey, LineEnding};
use rsa::RsaPrivateKey;
use serde_json::Value as JsonValue;

const REAL_ENDPOINT: &str = "https://oauth2.googleapis.com/token";

/// Local `CredentialBackend` that serves a synthetic service-
/// account JSON for the V3 forwarding witness. The PEM is a
/// valid throwaway RSA-2048 key so the proxy's JWT signer
/// succeeds; the `client_email` points at a non-existent
/// service account so the upstream rejects the exchange.
struct SyntheticSaBackend {
    body:     Vec<u8>,
    resolves: AtomicU32,
}

impl CredentialBackend for SyntheticSaBackend {
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
            reason: "live-e2e V3 GCP witness does not rotate".to_owned(),
        })
    }
    fn exists(&self, _name: &CredentialName) -> bool { true }
    fn lease(&self, _: &CredentialName) -> Lease { Lease::Forever }
    fn backend_kind(&self) -> &'static str { "live-e2e-v3-gcp-witness" }
}

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
    if std::env::var("RAXIS_V3_CLOUD_FORWARDING").ok().as_deref() == Some("1") {
        return run_v3_forwarding_witness().await;
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

/// V3 forwarding witness. Generates a throwaway RSA-2048 key,
/// builds a service-account-JSON-shaped credential body,
/// binds a `GcpProxy::bind_v3` against it, and dials the
/// proxy's metadata-server `/token` endpoint. The upstream
/// rejects the JWT (the issuer email is synthetic); the
/// proxy mirrors the 4xx OAuth2 envelope back.
async fn run_v3_forwarding_witness() -> Result<()> {
    tracing::info!(
        endpoint = REAL_ENDPOINT,
        "slice gcp-proxy-real-endpoint: V3-forwarding witness starting",
    );

    let mut rng = rand_core::OsRng;
    let private_key = RsaPrivateKey::new(&mut rng, 2048)
        .context("generate throwaway RSA-2048 key for V3 witness")?;
    let pem = private_key
        .to_pkcs8_pem(LineEnding::LF)
        .context("encode RSA private key to PKCS#8 PEM")?
        .to_string();

    // Synthetic service-account email — does not correspond
    // to any real Google service account, so the upstream
    // rejects the JWT-bearer exchange with `invalid_grant`.
    let synthetic_email = "raxis-v3-witness@nonexistent.iam.gserviceaccount.com";
    let sa_json = serde_json::json!({
        "type":             "service_account",
        "client_email":     synthetic_email,
        "private_key_id":   "raxis-v3-witness-kid",
        "private_key":      pem,
        "token_uri":        REAL_ENDPOINT,
        "project_id":       "raxis-v3-witness-project",
    });
    let body = serde_json::to_vec(&sa_json).context("serialise synthetic SA JSON")?;

    let backend: Arc<dyn CredentialBackend> = Arc::new(SyntheticSaBackend {
        body,
        resolves: AtomicU32::new(0),
    });

    let upstream = CloudUpstreamHost::gcp_oauth2();
    let http_client = Arc::new(
        CloudHttpClient::new(upstream.clone())
            .context("construct CloudHttpClient for oauth2.googleapis.com")?,
    );
    let token_cache = Arc::new(TokenCache::<GcpCacheValue>::new(Duration::from_secs(300)));
    let audit_sink: Arc<dyn AuditSink> = Arc::new(FakeAuditSink::new());

    let fwd = GcpForwardingConfig {
        upstream,
        scopes:              vec!["https://www.googleapis.com/auth/cloud-platform".to_owned()],
        jwt_lifetime:        Duration::from_secs(3600),
        cache_safety_window: Duration::from_secs(300),
    };

    let cfg = ProxyConfig {
        listen_addr:        "127.0.0.1:0".to_owned(),
        credential_name:    CredentialName::new("live-e2e-v3-gcp"),
        consumer:           OwnedConsumer::new("live-e2e-gcp-slice", "v3-witness"),
        lease_seconds:      3600,
        project_id:         "raxis-v3-witness-project".to_owned(),
        numeric_project_id: Some(123_456_789),
        forwarding:         Some(fwd),
        restrictions:       Restrictions::default(),
    };

    let proxy = GcpProxy::bind_v3(
        backend,
        cfg,
        Arc::new(NoopAuditChannel::default()),
        Arc::clone(&audit_sink),
        http_client,
        token_cache,
    )
    .await
    .context("bind GcpProxy V3")?;
    let addr = proxy.local_addr().context("GcpProxy local_addr")?;
    tokio::spawn(async move { proxy.serve().await; });

    let url = format!(
        "http://{addr}/computeMetadata/v1/instance/service-accounts/default/token",
    );
    let client = reqwest::Client::builder()
        .user_agent("raxis-live-e2e/gcp-proxy-real-endpoint-v3")
        .timeout(Duration::from_secs(20))
        .no_proxy()
        .build()
        .context("build reqwest client")?;
    let resp = client.get(&url)
        .header("Metadata-Flavor", "Google")
        .send().await
        .with_context(|| format!("GET {url}"))?;
    let status = resp.status();
    let body   = resp.text().await.context("read response body")?;

    if status.is_success() {
        return Err(anyhow!(
            "expected 4xx pass-through from oauth2.googleapis.com for synthetic SA \
             email, got 200; body={body:.500}",
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
    // Hygiene: the PEM and synthetic email are operator-side
    // bytes; they MUST NOT leak through the proxy to the
    // in-VM client. Assert their absence.
    if body.contains("BEGIN PRIVATE KEY")
        || body.contains("BEGIN RSA PRIVATE KEY")
        || body.contains(synthetic_email)
    {
        return Err(anyhow!(
            "V3-forwarding response body leaked credential-shaped substring; \
             body={body:.500}",
        ));
    }

    tracing::info!(
        status   = %status,
        error    = error_field,
        body_len = body.len(),
        "slice gcp-proxy-real-endpoint: PASS — V3 upstream-forwarding witness pinned",
    );
    Ok(())
}

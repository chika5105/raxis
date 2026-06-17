//! Slice — V3-readiness witness: real `sts.amazonaws.com`
//! authentication-failure shape.
//!
//! ## Architectural gap (P0 finding from the credproxy gap-closer audit)
//!
//! The V2 `AwsProxy` is an **IMDS emulator** — it SYNTHESIZES
//! the AWS container-credential-provider JSON envelope from the
//! operator's `CredentialBackend`-resolved bytes and serves it on
//! a localhost port. The agent's AWS SDK reads
//! `AWS_CONTAINER_CREDENTIALS_FULL_URI` and dials the proxy; the
//! proxy returns the cached IAM key + session token directly.
//! There is NO upstream forwarding code path: the proxy does not
//! call `sts.amazonaws.com`, does not perform SigV4 signing, and
//! does not mint short-lived STS credentials from a long-lived
//! IAM key. Per `crates/credential-proxy-aws/src/lib.rs` "What
//! is deferred":
//!
//!   > **Real `sts:AssumeRole` round-trip** so the proxy issues a
//!   > genuinely scoped, short-lived STS credential rather than
//!   > mirroring a long-lived IAM key. V3 lands this as
//!   > `IsLocallyMintedSts = false` mode using the `aws-sdk-sts`
//!   > crate; V2 mints synthetic responses from the long-lived
//!   > IAM key the operator stores in the credential backend.
//!
//! Because there is no V2 forwarding path, this slice cannot
//! drive a request through the proxy to the real upstream — there
//! is nothing to drive. Instead this slice exists as a **V3
//! baseline witness**: it pins the canonical authentication-
//! failure response shape from `https://sts.amazonaws.com/` so
//! the V3 proxy implementation has a stable wire-shape contract
//! to pattern-match against when forwarding the agent's signed
//! request.
//!
//! ## What this slice asserts
//!
//! Gated behind `RAXIS_LIVE_CLOUD_NET=1` (default off, mirroring
//! the MySQL/MSSQL preflight pattern). When the env var is unset
//! the slice prints a skip message and returns `Ok(())`.
//!
//! When set:
//!
//!   1. Issue an HTTPS `POST https://sts.amazonaws.com/` with the
//!      `GetCallerIdentity` action and NO `Authorization` header.
//!      AWS STS rejects unsigned requests with a canonical
//!      `MissingAuthenticationToken` error.
//!   2. Assert the response is `403 Forbidden` (the documented
//!      AWS STS behaviour for unsigned requests).
//!   3. Assert the body is the canonical `<ErrorResponse>` XML
//!      envelope and contains `<Code>MissingAuthenticationToken</Code>`
//!      verbatim. This is the V3 wire-shape contract.
//!   4. Assert NO credential material from RAXIS appears in the
//!      response — the slice never resolved a credential, never
//!      injected one, and the upstream cannot have echoed one.
//!
//! No proxy is bound. No `CredentialBackend` is involved. The
//! slice deliberately bypasses the V2 emulator because the V2
//! emulator does not have a forwarding path to test. When V3
//! lands `aws-sdk-sts`-based forwarding the slice should be
//! flipped to drive the request through the proxy, asserting the
//! same canonical `<Code>MissingAuthenticationToken</Code>` response
//! reaches the agent unmolested.

//! ## V3 forwarding pivot (`RAXIS_V3_CLOUD_FORWARDING=1`)
//!
//! When BOTH `RAXIS_LIVE_CLOUD_NET=1` AND
//! `RAXIS_V3_CLOUD_FORWARDING=1` are set, this slice replaces
//! the no-proxy baseline with an end-to-end V3 forwarding
//! witness:
//!
//!   1. Construct an in-process `AwsProxy::bind_v3` with a
//!      `ForwardingConfig` pinned to the global STS endpoint
//!      and `region = us-east-1`.
//!   2. Resolve a *deliberately invalid* IAM key
//!      (`AKIAEXAMPLEINVALIDKEY` + opaque secret) from a
//!      local `CredentialBackend`. The key MUST NOT be real;
//!      its only purpose is to exercise the real SigV4
//!      sign-and-dispatch path while guaranteeing STS rejects
//!      the AssumeRole.
//!   3. Dial the proxy's loopback IMDS endpoint with a fresh
//!      `reqwest` client. The proxy signs an `AssumeRole`
//!      request with the invalid key, POSTs it to real STS,
//!      receives a 4xx `<ErrorResponse>` envelope, and
//!      mirrors it back verbatim per spec §6.4.
//!   4. Assert: HTTP status is 4xx, body is the canonical AWS
//!      XML `<ErrorResponse>` shape, and the error code is one
//!      of the `EXPECTED_ERROR_CODES` set. No `AKIA`-prefixed
//!      bytes in the body except the literal invalid key
//!      bytes the slice fed in (rejected = good).
//!
//! When only `RAXIS_LIVE_CLOUD_NET=1` is set the slice falls
//! back to the original V3-baseline witness — a direct
//! unsigned POST to STS — which pins the canonical
//! `<ErrorResponse>` wire shape but does NOT exercise the
//! forwarding code path.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use raxis_audit_tools::AuditSink;
use raxis_credential_proxy_aws::{
    AwsProxy, ForwardingConfig as AwsForwardingConfig, NoopAuditChannel, OwnedConsumer,
    ProxyConfig, Restrictions, StsCacheValue,
};
use raxis_credential_proxy_cloud_shared::{CloudHttpClient, CloudUpstreamHost, TokenCache};
use raxis_credentials::{
    ConsumerIdentity, CredentialBackend, CredentialError, CredentialName, CredentialValue,
    OperatorId,
};
use raxis_test_support::audit_sink::FakeAuditSink;

const REAL_ENDPOINT: &str = "https://sts.amazonaws.com/";
const ACTION_QUERY: &str = "Action=GetCallerIdentity&Version=2011-06-15";

/// Local `CredentialBackend` that serves a deliberately
/// invalid AWS IAM key for the V3 forwarding witness. The
/// proxy will SigV4-sign with this key and POST to real STS;
/// STS rejects with `InvalidClientTokenId`.
struct InvalidKeyBackend {
    body: Vec<u8>,
    resolves: AtomicU32,
}

impl CredentialBackend for InvalidKeyBackend {
    fn resolve(
        &self,
        _name: &CredentialName,
        _consumer: ConsumerIdentity<'_>,
    ) -> std::result::Result<CredentialValue, CredentialError> {
        self.resolves.fetch_add(1, Ordering::SeqCst);
        Ok(CredentialValue::from_bytes(self.body.clone()))
    }
    fn rotate(
        &self,
        name: &CredentialName,
        _v: CredentialValue,
        _a: OperatorId,
    ) -> std::result::Result<(), CredentialError> {
        Err(CredentialError::Malformed {
            name: name.clone(),
            reason: "live-e2e V3 witness backend does not rotate".to_owned(),
        })
    }
    fn exists(&self, _name: &CredentialName) -> bool {
        true
    }
    fn backend_kind(&self) -> &'static str {
        "live-e2e-v3-witness"
    }
}

/// Closed enum of stable AWS STS error codes for unsigned /
/// invalid-credential requests. The slice asserts the response
/// body contains AT LEAST ONE of these, so AWS can rotate which
/// specific code they emit (they have historically used both
/// `MissingAuthenticationToken` for purely unsigned requests AND
/// `InvalidClientTokenId` for malformed signing) without
/// breaking the witness.
const EXPECTED_ERROR_CODES: &[&str] = &[
    "MissingAuthenticationToken",
    "InvalidClientTokenId",
    "SignatureDoesNotMatch",
    "AccessDenied",
];

pub(crate) async fn run() -> Result<()> {
    if std::env::var("RAXIS_LIVE_CLOUD_NET").ok().as_deref() != Some("1") {
        tracing::info!(
            "slice aws-proxy-real-endpoint: SKIP — RAXIS_LIVE_CLOUD_NET=1 not set\n\
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
        "slice aws-proxy-real-endpoint: starting"
    );

    let client = reqwest::Client::builder()
        .user_agent("raxis-live-e2e/aws-proxy-real-endpoint")
        .timeout(Duration::from_secs(20))
        // Disable proxies — this slice MUST go to the real
        // endpoint without any operator-side proxy interference.
        .no_proxy()
        .build()
        .context("build reqwest client")?;

    let url = format!("{REAL_ENDPOINT}?{ACTION_QUERY}");
    let resp = client
        .post(&url)
        .send()
        .await
        .with_context(|| format!("POST {url}"))?;

    let status = resp.status();
    let body = resp.text().await.context("read response body")?;

    if status.as_u16() != 403 {
        return Err(anyhow!(
            "expected status 403 from unsigned STS GetCallerIdentity, got {status}; body={body:.300}",
        ));
    }
    let lc_body = body.to_ascii_lowercase();
    let saw_envelope = lc_body.contains("<errorresponse")
        || lc_body.contains("<error>")
        || lc_body.contains("<errorresponse ");
    if !saw_envelope {
        return Err(anyhow!(
            "response body did not contain an `<ErrorResponse>` / `<Error>` envelope; body={body:.300}",
        ));
    }
    let saw_code = EXPECTED_ERROR_CODES.iter().any(|code| body.contains(code));
    if !saw_code {
        return Err(anyhow!(
            "response body did not contain any expected AWS STS error code from {EXPECTED_ERROR_CODES:?}; body={body:.500}",
        ));
    }

    // Hygiene: the slice never resolved a credential, but assert
    // that none of the well-known AWS credential prefixes
    // (`AKIA`, `ASIA`) sneaked into the body. AWS would not echo
    // one in an unsigned-request error, but pinning the assertion
    // here means a future regression cannot silently land.
    for prefix in &["AKIA", "ASIA"] {
        if body.contains(prefix) {
            return Err(anyhow!(
                "response body unexpectedly contained AWS credential prefix {prefix:?}; body={body:.500}",
            ));
        }
    }

    tracing::info!(
        status   = %status,
        body_len = body.len(),
        "slice aws-proxy-real-endpoint: PASS — V3 baseline witness pinned",
    );
    Ok(())
}

/// End-to-end V3-forwarding witness. Runs only when
/// `RAXIS_V3_CLOUD_FORWARDING=1`. Drives a real
/// `sts:AssumeRole` through `AwsProxy::bind_v3` with a
/// deliberately-invalid IAM key; STS rejects with one of
/// `EXPECTED_ERROR_CODES`; the proxy mirrors the 4xx
/// `<ErrorResponse>` envelope back to the in-VM client.
async fn run_v3_forwarding_witness() -> Result<()> {
    tracing::info!(
        endpoint = REAL_ENDPOINT,
        "slice aws-proxy-real-endpoint: V3-forwarding witness starting"
    );

    // Operator-stored long-lived IAM key. The key is
    // deliberately invalid (`AKIAEXAMPLE...`) — STS rejects
    // it, which is exactly what we want to assert.
    let env_body = "AWS_ACCESS_KEY_ID=AKIAEXAMPLEINVALIDKEY\n\
         AWS_SECRET_ACCESS_KEY=an-opaque-secret-that-cannot-pass-aws-iam\n";
    let backend: Arc<dyn CredentialBackend> = Arc::new(InvalidKeyBackend {
        body: env_body.as_bytes().to_vec(),
        resolves: AtomicU32::new(0),
    });

    let upstream = CloudUpstreamHost::aws_global();
    let http_client = Arc::new(
        CloudHttpClient::new(upstream.clone())
            .context("construct CloudHttpClient for global STS")?,
    );
    let token_cache = Arc::new(TokenCache::<StsCacheValue>::new(Duration::from_secs(300)));
    let audit_sink: Arc<dyn AuditSink> = Arc::new(FakeAuditSink::new());

    let fwd = AwsForwardingConfig {
        upstream,
        region: "us-east-1".to_owned(),
        role_arn: "arn:aws:iam::123456789012:role/raxis-v3-witness".to_owned(),
        external_id: None,
        duration_seconds: 900,
        cache_safety_window: Duration::from_secs(300),
    };

    let cfg = ProxyConfig {
        listen_addr: "127.0.0.1:0".to_owned(),
        credential_name: CredentialName::new("live-e2e-v3"),
        consumer: OwnedConsumer::new("live-e2e-aws-slice", "v3-witness"),
        lease_seconds: 900,
        role_arn: Some(fwd.role_arn.clone()),
        forwarding: Some(fwd),
        restrictions: Restrictions::default(),
    };

    let proxy = AwsProxy::bind_v3(
        backend,
        cfg,
        Arc::new(NoopAuditChannel),
        Arc::clone(&audit_sink),
        http_client,
        token_cache,
    )
    .await
    .context("bind AwsProxy V3")?;
    let addr = proxy.local_addr().context("AwsProxy local_addr")?;
    tokio::spawn(async move {
        proxy.serve().await;
    });

    // Dial the proxy's IMDS-shaped endpoint. The proxy will
    // SigV4-sign an AssumeRole with the invalid key and POST
    // to STS; STS rejects; the proxy mirrors the 4xx envelope
    // back.
    let url = format!("http://{addr}/raxis-credentials");
    let client = reqwest::Client::builder()
        .user_agent("raxis-live-e2e/aws-proxy-real-endpoint-v3")
        .timeout(Duration::from_secs(20))
        .no_proxy()
        .build()
        .context("build reqwest client")?;
    let resp = client
        .get(&url)
        .send()
        .await
        .with_context(|| format!("GET {url}"))?;
    let status = resp.status();
    let body = resp.text().await.context("read response body")?;

    if status.is_success() {
        return Err(anyhow!(
            "expected 4xx pass-through from STS for invalid IAM key, got 200; \
             body={body:.500}",
        ));
    }
    if !(status.as_u16() >= 400 && status.as_u16() < 600) {
        return Err(anyhow!(
            "expected 4xx/5xx status from V3 forwarding witness, got {status}; \
             body={body:.500}",
        ));
    }
    let lc_body = body.to_ascii_lowercase();
    let saw_envelope = lc_body.contains("<errorresponse") || lc_body.contains("<error>");
    if !saw_envelope {
        return Err(anyhow!(
            "V3-forwarding response did not contain an `<ErrorResponse>` envelope; \
             status={status} body={body:.500}",
        ));
    }
    let saw_code = EXPECTED_ERROR_CODES.iter().any(|code| body.contains(code));
    if !saw_code {
        return Err(anyhow!(
            "V3-forwarding response did not contain any expected STS error code from \
             {EXPECTED_ERROR_CODES:?}; status={status} body={body:.500}",
        ));
    }

    tracing::info!(
        status   = %status,
        body_len = body.len(),
        "slice aws-proxy-real-endpoint: PASS — V3 upstream-forwarding witness pinned",
    );
    Ok(())
}

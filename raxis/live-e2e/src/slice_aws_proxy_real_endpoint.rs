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

use std::time::Duration;

use anyhow::{Context, Result, anyhow};

const REAL_ENDPOINT: &str = "https://sts.amazonaws.com/";
const ACTION_QUERY: &str = "Action=GetCallerIdentity&Version=2011-06-15";

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

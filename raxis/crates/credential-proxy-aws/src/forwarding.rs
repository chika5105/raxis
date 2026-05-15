//! V3 AWS STS `AssumeRole` forwarding path.
//!
//! Normative reference: `specs/v3/cloud-proxy-forwarding.md §2.1`,
//! `§5`, `§6.1`.
//!
//! When [`ForwardingConfig`] is wired on the AWS proxy
//! ([`crate::ProxyConfig::forwarding`]), the per-request serve
//! path drives a real `sts:AssumeRole` POST against the global
//! or regional STS endpoint instead of mirroring the long-lived
//! IAM key. The exchange flow:
//!
//! 1. Parse the resolved IAM key (env-style or JSON) from
//!    `CredentialBackend::resolve`.
//! 2. Build the AssumeRole form body (`Action=AssumeRole&...`).
//! 3. SigV4-sign the POST via the shared `sigv4` module.
//! 4. Dispatch via the shared `CloudHttpClient` (closed
//!    allowlist + rustls).
//! 5. Parse the upstream XML response — extract the
//!    `<Credentials>` block on 2xx, surface the upstream's
//!    `<ErrorResponse>` envelope verbatim on 4xx, synthesise a
//!    503 envelope on 5xx / network / malformed-success.
//! 6. Render the in-VM IMDS JSON body, cache it, return bytes
//!    for the proxy's per-connection write. The next request
//!    inside the safety window re-serves the cached bytes
//!    without re-dispatching upstream.
//!
//! The XML parsing is a tiny hand-rolled tag extractor — the
//! shape is fixed (two known wire envelopes) so a full XML
//! dependency is overkill and shipping a parser surface
//! reduces auditability.

use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use raxis_audit_tools::AuditSink;
use raxis_credential_proxy_cloud_shared::{
    audit::{
        emit_cloud_credential_cache_hit, emit_cloud_credential_cache_refreshed,
        emit_cloud_credential_forwarded, emit_cloud_credential_forwarding_denied,
    },
    sigv4::{sign_v4, SigV4Inputs},
    time::unix_now_seconds,
    CacheKey, CloudExchangeKind, CloudHttpClient, CloudProvider, CloudUpstreamHost, TokenCache,
    UpstreamError,
};
use serde::Serialize;

/// Per-listener V3 forwarding configuration. When this is set
/// on [`crate::ProxyConfig::forwarding`], the proxy switches
/// from the V2 emulator path to the V3 STS-forwarding path.
#[derive(Debug, Clone)]
pub struct ForwardingConfig {
    /// Upstream STS host (closed-allowlist `CloudUpstreamHost`).
    pub upstream: CloudUpstreamHost,
    /// AWS region for SigV4 credential scope. For the global
    /// `sts.amazonaws.com` endpoint use `"us-east-1"`.
    pub region: String,
    /// Operator-declared IAM role ARN to assume. REQUIRED.
    pub role_arn: String,
    /// Optional ExternalId mirrored to `AssumeRole`.
    pub external_id: Option<String>,
    /// STS `DurationSeconds` (clamped 900..=43_200).
    pub duration_seconds: u64,
    /// Token cache safety-window. The cache module clamps to
    /// 60 s minimum.
    pub cache_safety_window: Duration,
}

/// Canonical content-type of an `<ErrorResponse>` envelope.
pub const AWS_XML_CONTENT_TYPE: &str = "text/xml";

/// In-VM IMDS JSON body shape. Same wire format the V2 emulator
/// served — preserves SDK compatibility.
#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct InVmResponse {
    /// Short-lived `AccessKeyId` (the upstream returns `ASIA...`).
    pub access_key_id: String,
    /// Short-lived secret access key.
    pub secret_access_key: String,
    /// Required session token.
    pub token: String,
    /// ISO-8601 / RFC 3339 expiration timestamp.
    pub expiration: String,
    /// IAM role ARN echoed for SDKs / audit consumers.
    pub role_arn: String,
}

/// What the proxy connection handler writes to the in-VM
/// client.
#[derive(Debug, Clone)]
pub enum ForwardOutcome {
    /// 200 OK with the rendered JSON body.
    Ok(Vec<u8>),
    /// Pass-through canonical AWS XML error envelope (status +
    /// body).
    UpstreamEnvelope {
        /// HTTP status code mirrored from the upstream
        /// (200..600). 5xx / synthetic paths surface as 503.
        status: u16,
        /// Body bytes — written verbatim to the in-VM client.
        body: Vec<u8>,
    },
}

/// Cache value: the rendered IMDS JSON body. The actual
/// credential bytes also live inside the JSON for the in-VM
/// SDK to consume — caching the rendered bytes once means
/// repeated in-VM dials inside the safety window do NOT
/// re-serialise.
#[derive(Debug, Clone)]
pub struct StsCacheValue {
    /// Pre-rendered IMDS JSON the proxy re-serves verbatim.
    pub rendered_in_vm_body: Vec<u8>,
}

/// Build the form-urlencoded AssumeRole body. Param order is
/// pinned so the SigV4 canonical-request hash is reproducible
/// from the same inputs.
pub fn build_assume_role_body(
    role_arn: &str,
    role_session_name: &str,
    external_id: Option<&str>,
    duration_seconds: u64,
) -> Vec<u8> {
    let mut parts = Vec::with_capacity(6);
    parts.push("Action=AssumeRole".to_owned());
    parts.push("Version=2011-06-15".to_owned());
    parts.push(format!("RoleArn={}", urlencode(role_arn)));
    parts.push(format!("RoleSessionName={}", urlencode(role_session_name)));
    parts.push(format!("DurationSeconds={duration_seconds}"));
    if let Some(eid) = external_id {
        parts.push(format!("ExternalId={}", urlencode(eid)));
    }
    parts.join("&").into_bytes()
}

/// URL-encode per `application/x-www-form-urlencoded`. Hand-
/// rolled to avoid a dep; AWS only cares about a small
/// reserved-char set.
fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.' || b == b'~' {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{:02X}", b));
        }
    }
    out
}

/// Extract the text between `<Tag>...</Tag>` (first occurrence,
/// non-nested). Returns `None` when the tag is absent or its
/// closing tag missing. The shapes we care about are flat and
/// unambiguous; a full XML dep would widen the audit surface.
pub fn extract_xml_tag<'a>(body: &'a [u8], tag: &str) -> Option<&'a [u8]> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let s = std::str::from_utf8(body).ok()?;
    let open_idx = s.find(&open)? + open.len();
    let close_idx = s[open_idx..].find(&close)? + open_idx;
    Some(&body[open_idx..close_idx])
}

/// Parsed credentials from an AssumeRoleResponse.
#[derive(Debug, Clone)]
pub struct AssumedCredentials {
    /// Short-lived access key id.
    pub access_key_id: String,
    /// Short-lived secret access key.
    pub secret_access_key: String,
    /// Required session token.
    pub session_token: String,
    /// Wall-clock unix-seconds upstream-claimed expiry.
    pub expiration_unix: u64,
}

/// Parse the canonical `<AssumeRoleResponse>` success body.
pub fn parse_assume_role_success(body: &[u8]) -> Result<AssumedCredentials, UpstreamError> {
    let creds_block = extract_xml_tag(body, "Credentials")
        .ok_or_else(|| UpstreamError::UpstreamMalformed("missing <Credentials>".to_owned()))?;
    let access_key_id = extract_xml_tag(creds_block, "AccessKeyId")
        .and_then(|b| std::str::from_utf8(b).ok())
        .ok_or_else(|| {
            UpstreamError::UpstreamMalformed("<Credentials> missing AccessKeyId".to_owned())
        })?
        .trim()
        .to_owned();
    let secret_access_key = extract_xml_tag(creds_block, "SecretAccessKey")
        .and_then(|b| std::str::from_utf8(b).ok())
        .ok_or_else(|| {
            UpstreamError::UpstreamMalformed("<Credentials> missing SecretAccessKey".to_owned())
        })?
        .trim()
        .to_owned();
    let session_token = extract_xml_tag(creds_block, "SessionToken")
        .and_then(|b| std::str::from_utf8(b).ok())
        .ok_or_else(|| {
            UpstreamError::UpstreamMalformed("<Credentials> missing SessionToken".to_owned())
        })?
        .trim()
        .to_owned();
    let expiration_str = extract_xml_tag(creds_block, "Expiration")
        .and_then(|b| std::str::from_utf8(b).ok())
        .ok_or_else(|| {
            UpstreamError::UpstreamMalformed("<Credentials> missing Expiration".to_owned())
        })?
        .trim();
    let expiration_unix = parse_iso8601_to_unix(expiration_str).ok_or_else(|| {
        UpstreamError::UpstreamMalformed(
            format!("<Expiration> not ISO-8601 Z: {expiration_str:?}",),
        )
    })?;
    Ok(AssumedCredentials {
        access_key_id,
        secret_access_key,
        session_token,
        expiration_unix,
    })
}

/// Tiny ISO-8601 (`YYYY-MM-DDTHH:MM:SSZ`) → unix seconds. UTC
/// only; tolerant of a trailing fractional-second component
/// (STS does emit `.000Z`).
fn parse_iso8601_to_unix(s: &str) -> Option<u64> {
    let s = s.strip_suffix('Z')?;
    let (date, time) = s.split_once('T')?;
    let mut date_parts = date.split('-');
    let y: i64 = date_parts.next()?.parse().ok()?;
    let mo: u32 = date_parts.next()?.parse().ok()?;
    let d: u32 = date_parts.next()?.parse().ok()?;
    let time_clean = time.split('.').next()?;
    let mut t_parts = time_clean.split(':');
    let h: u32 = t_parts.next()?.parse().ok()?;
    let mi: u32 = t_parts.next()?.parse().ok()?;
    let se: u32 = t_parts.next()?.parse().ok()?;
    Some(civil_to_unix(y, mo, d, h, mi, se))
}

/// Howard-Hinnant `days_from_civil` → unix seconds.
fn civil_to_unix(y: i64, m: u32, d: u32, h: u32, mi: u32, s: u32) -> u64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y / 400 } else { (y - 399) / 400 };
    let yoe = (y - era * 400) as u64;
    let mu = m as u64;
    let du = d as u64;
    let doy = (153 * (if mu > 2 { mu - 3 } else { mu + 9 }) + 2) / 5 + du - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + (doe as i64) - 719_468;
    (days as u64) * 86_400 + (h as u64) * 3600 + (mi as u64) * 60 + (s as u64)
}

/// Wall-clock unix → ISO-8601 Z (`YYYY-MM-DDTHH:MM:SSZ`).
fn format_iso8601_z_unix(secs: u64) -> String {
    let (y, mo, d, h, mi, s) = unix_to_civil(secs);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z")
}

fn unix_to_civil(secs: u64) -> (i64, u32, u32, u32, u32, u32) {
    let days = (secs / 86_400) as i64;
    let secs_of_day = (secs % 86_400) as u32;
    let hour = secs_of_day / 3600;
    let min = (secs_of_day / 60) % 60;
    let sec = secs_of_day % 60;
    let z = days + 719_468;
    let era = if z >= 0 {
        z / 146_097
    } else {
        (z - 146_096) / 146_097
    };
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let year = if m <= 2 { y + 1 } else { y };
    (year, m, d, hour, min, sec)
}

/// Sanitise a session id for the AWS-imposed `RoleSessionName`
/// charset (`[\w+=,.@-]{2,64}`). Replaces every disallowed byte
/// with `_`, truncates to 40 chars to leave room for the
/// `raxis-` prefix and `-<unix>` suffix.
fn sanitize_session_name(session_id: &str) -> String {
    let mut out = String::with_capacity(session_id.len());
    for b in session_id.bytes().take(40) {
        if b.is_ascii_alphanumeric() || matches!(b, b'+' | b'=' | b',' | b'.' | b'@' | b'-') {
            out.push(b as char);
        } else {
            out.push('_');
        }
    }
    out
}

/// Synthesise a canonical AWS XML error envelope. Used for the
/// 5xx / malformed-success / network synthetic-503 path.
pub fn synthesise_xml_error_envelope(code: &str, message: &str) -> Vec<u8> {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <ErrorResponse xmlns=\"https://sts.amazonaws.com/doc/2011-06-15/\">\n  \
           <Error>\n    \
             <Type>Sender</Type>\n    \
             <Code>{code}</Code>\n    \
             <Message>{message}</Message>\n  \
           </Error>\n  \
           <RequestId>raxis-v3-cloud-forwarding</RequestId>\n\
         </ErrorResponse>\n",
    )
    .into_bytes()
}

/// Render the in-VM IMDS JSON body for the agent's SDK.
pub fn render_in_vm_response(creds: &AssumedCredentials, role_arn: &str) -> InVmResponse {
    InVmResponse {
        access_key_id: creds.access_key_id.clone(),
        secret_access_key: creds.secret_access_key.clone(),
        token: creds.session_token.clone(),
        expiration: format_iso8601_z_unix(creds.expiration_unix),
        role_arn: role_arn.to_owned(),
    }
}

/// Cache key for an AssumeRole result. Folds `role_arn`,
/// hashed `external_id`, and `region` into a stable string.
/// NEVER includes credential bytes.
pub fn build_cache_key(fwd: &ForwardingConfig) -> CacheKey {
    let mut s = String::with_capacity(128);
    s.push_str(&fwd.role_arn);
    s.push('|');
    if let Some(ext) = fwd.external_id.as_deref() {
        use sha2::{Digest, Sha256};
        let h = Sha256::digest(ext.as_bytes());
        s.push_str(&hex::encode(&h[..8]));
    } else {
        s.push_str("noext");
    }
    s.push('|');
    s.push_str(&fwd.region);
    CacheKey::new(s)
}

/// Drive one synchronous AssumeRole upstream exchange. Returns
/// the parsed credentials + the rendered in-VM JSON body bytes.
/// All upstream-facing failure modes flow through `UpstreamError`.
pub async fn drive_assume_role_exchange(
    fwd: &ForwardingConfig,
    http: &CloudHttpClient,
    long_lived_access_key_id: &str,
    long_lived_secret_access_key: &str,
    session_id: &str,
) -> Result<(AssumedCredentials, Vec<u8>), UpstreamError> {
    let role_session_name = format!(
        "raxis-{}-{}",
        sanitize_session_name(session_id),
        unix_now_seconds(),
    );
    let body = build_assume_role_body(
        &fwd.role_arn,
        &role_session_name,
        fwd.external_id.as_deref(),
        fwd.duration_seconds,
    );

    let signed = sign_v4(SigV4Inputs {
        access_key_id: long_lived_access_key_id,
        secret_access_key: long_lived_secret_access_key,
        region: &fwd.region,
        service: "sts",
        method: "POST",
        canonical_uri: "/",
        canonical_query: "",
        host: fwd.upstream.host(),
        body: &body,
    });

    let url = format!("{}/", fwd.upstream.https_base());
    let (status, body_bytes) = http
        .post_form_urlencoded(
            &url,
            Bytes::from(body),
            &[
                ("authorization", signed.authorization.as_str()),
                ("x-amz-date", signed.amz_date.as_str()),
            ],
        )
        .await?;

    if status == 200 {
        let parsed = parse_assume_role_success(&body_bytes)?;
        let in_vm = render_in_vm_response(&parsed, &fwd.role_arn);
        let rendered = serde_json::to_vec(&in_vm)
            .map_err(|e| UpstreamError::UpstreamMalformed(format!("JSON serialise: {e}")))?;
        Ok((parsed, rendered))
    } else if (200..300).contains(&status) {
        Err(UpstreamError::UpstreamMalformed(format!(
            "non-200 2xx upstream status {status}",
        )))
    } else if (400..500).contains(&status) {
        Err(UpstreamError::Upstream4xx(status))
    } else if (500..600).contains(&status) {
        Err(UpstreamError::Upstream5xx(status))
    } else {
        Err(UpstreamError::UpstreamMalformed(format!(
            "unexpected upstream status {status}",
        )))
    }
}

/// Drive one upstream exchange and additionally return the
/// raw upstream body so the per-connection driver can pass
/// through 4xx envelopes verbatim. Distinct from
/// [`drive_assume_role_exchange`] so the cold-path code does
/// not pay for the 4xx-body buffer on success.
async fn drive_with_4xx_body(
    fwd: &ForwardingConfig,
    http: &CloudHttpClient,
    long_lived_access_key_id: &str,
    long_lived_secret_access_key: &str,
    session_id: &str,
) -> Result<(AssumedCredentials, Vec<u8>), (UpstreamError, Option<Vec<u8>>)> {
    let role_session_name = format!(
        "raxis-{}-{}",
        sanitize_session_name(session_id),
        unix_now_seconds(),
    );
    let body = build_assume_role_body(
        &fwd.role_arn,
        &role_session_name,
        fwd.external_id.as_deref(),
        fwd.duration_seconds,
    );
    let signed = sign_v4(SigV4Inputs {
        access_key_id: long_lived_access_key_id,
        secret_access_key: long_lived_secret_access_key,
        region: &fwd.region,
        service: "sts",
        method: "POST",
        canonical_uri: "/",
        canonical_query: "",
        host: fwd.upstream.host(),
        body: &body,
    });
    let url = format!("{}/", fwd.upstream.https_base());
    let (status, body_bytes) = http
        .post_form_urlencoded(
            &url,
            Bytes::from(body),
            &[
                ("authorization", signed.authorization.as_str()),
                ("x-amz-date", signed.amz_date.as_str()),
            ],
        )
        .await
        .map_err(|e| (e, None))?;

    if status == 200 {
        let parsed = parse_assume_role_success(&body_bytes).map_err(|e| (e, None))?;
        let in_vm = render_in_vm_response(&parsed, &fwd.role_arn);
        let rendered = serde_json::to_vec(&in_vm).map_err(|e| {
            (
                UpstreamError::UpstreamMalformed(format!("JSON serialise: {e}")),
                None,
            )
        })?;
        Ok((parsed, rendered))
    } else if (400..500).contains(&status) {
        Err((
            UpstreamError::Upstream4xx(status),
            Some(body_bytes.to_vec()),
        ))
    } else if (500..600).contains(&status) {
        Err((UpstreamError::Upstream5xx(status), None))
    } else {
        Err((
            UpstreamError::UpstreamMalformed(format!("unexpected upstream status {status}",)),
            None,
        ))
    }
}

/// End-to-end forwarder. Pulls from cache when fresh; otherwise
/// drives an upstream exchange. Emits all four V3 audit events
/// at the appropriate point in the flow.
///
/// Returns a [`ForwardOutcome`] the caller writes to the in-VM
/// socket: `Ok` on 200, `UpstreamEnvelope` on any upstream error
/// (including the synthetic 503 for 5xx / malformed / network).
#[allow(clippy::too_many_arguments)]
pub async fn forward_or_serve_from_cache(
    fwd: &ForwardingConfig,
    http: &Arc<CloudHttpClient>,
    cache: &Arc<TokenCache<StsCacheValue>>,
    audit: &Arc<dyn AuditSink>,
    session_id: &str,
    credential_name: &str,
    long_lived_access_key_id: &str,
    long_lived_secret_access_key: &str,
) -> ForwardOutcome {
    let key = build_cache_key(fwd);
    let safety_window = fwd.cache_safety_window;

    // Cache lookup.
    if let Some(entry) = cache.get(&key).await {
        let age_ms = entry.age().as_millis() as u32;
        let ttl_ms = entry.ttl_remaining().as_millis() as u32;
        emit_cloud_credential_cache_hit(
            audit,
            session_id,
            credential_name,
            CloudProvider::Aws,
            CloudExchangeKind::AssumeRole,
            age_ms,
            ttl_ms,
        )
        .ok();
        let body = entry.payload.rendered_in_vm_body.clone();
        if entry.is_stale(safety_window) {
            if let Some(_guard) = cache.take_refresh_lock(&key).await {
                let fwd2 = fwd.clone();
                let http2 = Arc::clone(http);
                let cache2 = Arc::clone(cache);
                let audit2 = Arc::clone(audit);
                let session2 = session_id.to_owned();
                let cred2 = credential_name.to_owned();
                let ak2 = long_lived_access_key_id.to_owned();
                let sk2 = long_lived_secret_access_key.to_owned();
                let prior_age = age_ms;
                tokio::spawn(async move {
                    let _g = _guard;
                    let started = Instant::now();
                    let res =
                        drive_assume_role_exchange(&fwd2, &http2, &ak2, &sk2, &session2).await;
                    let elapsed_ms = started.elapsed().as_millis() as u32;
                    let key2 = build_cache_key(&fwd2);
                    match res {
                        Ok((creds, rendered)) => {
                            let new_ttl = Duration::from_secs(
                                creds.expiration_unix.saturating_sub(unix_now_seconds()),
                            );
                            let new_ttl_ms = new_ttl.as_millis() as u32;
                            cache2
                                .insert(
                                    key2,
                                    StsCacheValue {
                                        rendered_in_vm_body: rendered.clone(),
                                    },
                                    new_ttl,
                                )
                                .await;
                            emit_cloud_credential_cache_refreshed(
                                &audit2,
                                &session2,
                                &cred2,
                                CloudProvider::Aws,
                                CloudExchangeKind::AssumeRole,
                                prior_age,
                                new_ttl_ms,
                            )
                            .ok();
                            emit_cloud_credential_forwarded(
                                &audit2,
                                &session2,
                                &cred2,
                                CloudProvider::Aws,
                                CloudExchangeKind::AssumeRole,
                                &fwd2.upstream,
                                elapsed_ms,
                                200,
                                rendered.len() as u32,
                                true,
                            )
                            .ok();
                        }
                        Err(e) => {
                            emit_cloud_credential_forwarding_denied(
                                &audit2,
                                &session2,
                                &cred2,
                                CloudProvider::Aws,
                                CloudExchangeKind::AssumeRole,
                                fwd2.upstream.host(),
                                e.denial_reason(),
                                e.status_code().unwrap_or(0),
                                elapsed_ms,
                            )
                            .ok();
                            // INV-CLOUD-FWD-08: failed refresh
                            // does NOT poison the cache.
                        }
                    }
                });
            }
        }
        return ForwardOutcome::Ok(body);
    }

    // Miss: synchronous exchange.
    let started = Instant::now();
    let result = drive_with_4xx_body(
        fwd,
        http,
        long_lived_access_key_id,
        long_lived_secret_access_key,
        session_id,
    )
    .await;
    let elapsed_ms = started.elapsed().as_millis() as u32;
    match result {
        Ok((creds, rendered)) => {
            let ttl = Duration::from_secs(creds.expiration_unix.saturating_sub(unix_now_seconds()));
            cache
                .insert(
                    key,
                    StsCacheValue {
                        rendered_in_vm_body: rendered.clone(),
                    },
                    ttl,
                )
                .await;
            emit_cloud_credential_forwarded(
                audit,
                session_id,
                credential_name,
                CloudProvider::Aws,
                CloudExchangeKind::AssumeRole,
                &fwd.upstream,
                elapsed_ms,
                200,
                rendered.len() as u32,
                true,
            )
            .ok();
            ForwardOutcome::Ok(rendered)
        }
        Err((e, maybe_body)) => {
            emit_cloud_credential_forwarding_denied(
                audit,
                session_id,
                credential_name,
                CloudProvider::Aws,
                CloudExchangeKind::AssumeRole,
                fwd.upstream.host(),
                e.denial_reason(),
                e.status_code().unwrap_or(0),
                elapsed_ms,
            )
            .ok();
            upstream_error_to_envelope(e, maybe_body)
        }
    }
}

/// Translate an `UpstreamError` to the wire envelope the proxy
/// writes to the in-VM client. 4xx passes through unchanged
/// (when the upstream body was captured); 5xx / network /
/// timeout / malformed-success collapse to a synthetic 503 +
/// canonical XML.
fn upstream_error_to_envelope(e: UpstreamError, body_4xx: Option<Vec<u8>>) -> ForwardOutcome {
    match e {
        UpstreamError::Upstream4xx(status) => ForwardOutcome::UpstreamEnvelope {
            status,
            body: body_4xx.unwrap_or_else(|| {
                synthesise_xml_error_envelope("UpstreamError", "upstream returned 4xx")
            }),
        },
        UpstreamError::Upstream5xx(_) => ForwardOutcome::UpstreamEnvelope {
            status: 503,
            body: synthesise_xml_error_envelope(
                "RaxisUpstreamUnavailable",
                "Upstream STS endpoint returned an unrecoverable error",
            ),
        },
        UpstreamError::Network(_) => ForwardOutcome::UpstreamEnvelope {
            status: 503,
            body: synthesise_xml_error_envelope(
                "RaxisUpstreamUnreachable",
                "Network error talking to upstream STS endpoint",
            ),
        },
        UpstreamError::Timeout => ForwardOutcome::UpstreamEnvelope {
            status: 503,
            body: synthesise_xml_error_envelope(
                "RaxisUpstreamTimeout",
                "Upstream STS endpoint did not respond within the deadline",
            ),
        },
        UpstreamError::UpstreamMalformed(_) => ForwardOutcome::UpstreamEnvelope {
            status: 503,
            body: synthesise_xml_error_envelope(
                "RaxisUpstreamMalformed",
                "Upstream STS endpoint returned a body that did not parse",
            ),
        },
        UpstreamError::EgressAllowlist(_) => ForwardOutcome::UpstreamEnvelope {
            status: 503,
            body: synthesise_xml_error_envelope(
                "RaxisEgressBlocked",
                "Upstream URL fell off the cloud-forwarding allowlist",
            ),
        },
        UpstreamError::MissingCredential(_) => ForwardOutcome::UpstreamEnvelope {
            status: 503,
            body: synthesise_xml_error_envelope(
                "RaxisMissingCredential",
                "Operator credential required for forwarding was missing or malformed",
            ),
        },
        UpstreamError::Misconfigured(_) => ForwardOutcome::UpstreamEnvelope {
            status: 503,
            body: synthesise_xml_error_envelope(
                "RaxisMisconfigured",
                "V3 cloud forwarding misconfigured at proxy construction",
            ),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fwd() -> ForwardingConfig {
        ForwardingConfig {
            upstream: CloudUpstreamHost::aws_global(),
            region: "us-east-1".to_owned(),
            role_arn: "arn:aws:iam::123456789012:role/demo".to_owned(),
            external_id: None,
            duration_seconds: 900,
            cache_safety_window: Duration::from_secs(60),
        }
    }

    #[test]
    fn assume_role_body_pins_canonical_param_order() {
        let body = build_assume_role_body(
            "arn:aws:iam::123456789:role/demo",
            "raxis-session-1740000000",
            None,
            900,
        );
        let s = std::str::from_utf8(&body).unwrap();
        assert!(s.starts_with("Action=AssumeRole&Version=2011-06-15&"));
        assert!(s.contains("RoleArn=arn%3Aaws%3Aiam%3A%3A123456789%3Arole%2Fdemo"));
        assert!(s.contains("RoleSessionName=raxis-session-1740000000"));
        assert!(s.contains("DurationSeconds=900"));
        assert!(!s.contains("ExternalId="));
    }

    #[test]
    fn assume_role_body_includes_external_id_when_supplied() {
        let body = build_assume_role_body(
            "arn:aws:iam::123456789:role/demo",
            "raxis-session",
            Some("operator-shared-secret-id"),
            3600,
        );
        let s = std::str::from_utf8(&body).unwrap();
        assert!(s.contains("ExternalId=operator-shared-secret-id"));
    }

    #[test]
    fn extract_xml_tag_round_trip() {
        let body = b"<wrap><AccessKeyId>ASIAX</AccessKeyId><other>x</other></wrap>";
        let v = extract_xml_tag(body, "AccessKeyId").unwrap();
        assert_eq!(v, b"ASIAX");
        assert!(extract_xml_tag(body, "Missing").is_none());
    }

    #[test]
    fn parse_assume_role_success_extracts_credentials() {
        let body = br#"
<AssumeRoleResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <AssumeRoleResult>
    <Credentials>
      <AccessKeyId>ASIAEXAMPLE</AccessKeyId>
      <SecretAccessKey>secretBytes</SecretAccessKey>
      <SessionToken>sessionTokenBytes</SessionToken>
      <Expiration>2026-05-12T18:00:00Z</Expiration>
    </Credentials>
  </AssumeRoleResult>
</AssumeRoleResponse>"#;
        let parsed = parse_assume_role_success(body).unwrap();
        assert_eq!(parsed.access_key_id, "ASIAEXAMPLE");
        assert_eq!(parsed.secret_access_key, "secretBytes");
        assert_eq!(parsed.session_token, "sessionTokenBytes");
        assert_eq!(parsed.expiration_unix, 1_778_608_800);
    }

    #[test]
    fn parse_assume_role_success_rejects_missing_fields() {
        let body = br#"
<AssumeRoleResponse>
  <AssumeRoleResult>
    <Credentials>
      <AccessKeyId>ASIA</AccessKeyId>
    </Credentials>
  </AssumeRoleResult>
</AssumeRoleResponse>"#;
        let err = parse_assume_role_success(body).unwrap_err();
        assert!(matches!(err, UpstreamError::UpstreamMalformed(_)));
    }

    #[test]
    fn parse_iso8601_to_unix_pins_a_known_value() {
        assert_eq!(
            parse_iso8601_to_unix("2026-05-12T18:00:00Z"),
            Some(1_778_608_800)
        );
    }

    #[test]
    fn parse_iso8601_to_unix_handles_fractional_seconds() {
        assert_eq!(
            parse_iso8601_to_unix("2026-05-12T18:00:00.123Z"),
            Some(1_778_608_800)
        );
    }

    #[test]
    fn sanitize_session_name_replaces_bad_chars() {
        assert_eq!(sanitize_session_name("abc/def 123*"), "abc_def_123_");
    }

    #[test]
    fn urlencode_pins_form_encoding() {
        assert_eq!(
            urlencode("arn:aws:iam::123:role/x"),
            "arn%3Aaws%3Aiam%3A%3A123%3Arole%2Fx"
        );
        assert_eq!(urlencode("plain"), "plain");
    }

    #[test]
    fn cache_key_changes_with_role_external_region() {
        let mk = |role: &str, ext: Option<&str>, region: &str| {
            let mut c = fwd();
            c.role_arn = role.to_owned();
            c.external_id = ext.map(str::to_owned);
            c.region = region.to_owned();
            build_cache_key(&c)
        };
        let a = mk("arn:x", None, "us-east-1");
        let b = mk("arn:y", None, "us-east-1");
        let c = mk("arn:x", Some("e"), "us-east-1");
        let d = mk("arn:x", None, "us-west-2");
        assert_ne!(a, b);
        assert_ne!(a, c);
        assert_ne!(a, d);
    }

    #[test]
    fn synthesised_envelope_is_well_formed_aws_xml() {
        let v = synthesise_xml_error_envelope("X", "msg");
        let s = std::str::from_utf8(&v).unwrap();
        assert!(s.contains("<ErrorResponse"));
        assert!(s.contains("<Code>X</Code>"));
        assert!(s.contains("<Message>msg</Message>"));
        assert!(s.contains("<RequestId>raxis-v3-cloud-forwarding</RequestId>"));
    }

    #[test]
    fn render_in_vm_response_pins_pascal_case_json() {
        let creds = AssumedCredentials {
            access_key_id: "ASIA".to_owned(),
            secret_access_key: "secret".to_owned(),
            session_token: "tok".to_owned(),
            expiration_unix: 1_778_608_800,
        };
        let r = render_in_vm_response(&creds, "arn:aws:iam::123:role/demo");
        let j = serde_json::to_string(&r).unwrap();
        assert!(j.contains("\"AccessKeyId\":\"ASIA\""));
        assert!(j.contains("\"SecretAccessKey\":\"secret\""));
        assert!(j.contains("\"Token\":\"tok\""));
        assert!(j.contains("\"Expiration\":\"2026-05-12T18:00:00Z\""));
        assert!(j.contains("\"RoleArn\":\"arn:aws:iam::123:role/demo\""));
    }
}

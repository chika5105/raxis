//! V3 Azure `client_credentials`-grant forwarding path.
//!
//! Normative reference: `specs/v3/cloud-proxy-forwarding.md §2.3`,
//! `§5`, `§6.3`.
//!
//! When [`ForwardingConfig`] is wired on the Azure proxy
//! ([`crate::ProxyConfig::forwarding`]), the per-request IMDS
//! `/metadata/identity/oauth2/token` endpoint drives a real
//! `client_credentials`-grant OAuth2 exchange against
//! `https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token`
//! instead of mirroring the long-lived `access_token` from the
//! operator credential body.
//!
//! Flow:
//!
//! 1. Parse the operator service-principal credential
//!    (`tenant_id`, `client_id`, `client_secret`) from the
//!    resolved credential body. The body is env-style or JSON.
//! 2. Derive the scope from the inbound IMDS request's
//!    `resource` query parameter as `<resource>/.default` (the
//!    Azure v2.0 endpoint requires `.default` semantics for
//!    daemon-style `client_credentials` flows).
//! 3. POST `grant_type=client_credentials&client_id=...&client_secret=...&scope=...`
//!    to `https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token`.
//! 4. Parse the JSON response (`access_token`, `expires_in`,
//!    `token_type`) and render the IMDS-shape response the
//!    in-VM SDK expects (with the additional numeric-string
//!    fields IMDS emits).
//! 5. Cache by `(tenant_id, client_id_hash, scope)` for the
//!    upstream-claimed TTL minus the safety window.
//!
//! On failure, the proxy preserves the upstream's AAD-flavored
//! RFC 6749 JSON envelope verbatim on 4xx, and synthesises a
//! canonical `error_description` / `503` envelope on 5xx /
//! network / timeout / malformed-success per spec §6.4.

use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use raxis_audit_tools::AuditSink;
use raxis_credential_proxy_cloud_shared::{
    CacheKey, CloudExchangeKind, CloudHttpClient, CloudProvider, CloudUpstreamHost,
    TokenCache, UpstreamError,
    audit::{
        emit_cloud_credential_cache_hit, emit_cloud_credential_cache_refreshed,
        emit_cloud_credential_forwarded, emit_cloud_credential_forwarding_denied,
    },
    time::unix_now_seconds,
};
use serde::{Deserialize, Serialize};

/// Per-listener V3 forwarding configuration.
#[derive(Debug, Clone)]
pub struct ForwardingConfig {
    /// Upstream AAD endpoint (`login.microsoftonline.com`).
    /// Construction-allowlisted via [`CloudUpstreamHost::azure_login`].
    pub upstream:            CloudUpstreamHost,
    /// Token cache safety-window.
    pub cache_safety_window: Duration,
}

/// Canonical content-type of an AAD OAuth2 envelope.
pub const AZURE_JSON_CONTENT_TYPE: &str = "application/json";

/// Parsed service-principal credential the operator stores in
/// the credential backend body for V3 forwarding.
#[derive(Debug, Clone)]
pub struct ServicePrincipal {
    /// Azure AD tenant ID (GUID). Routed into the URL path.
    pub tenant_id:     String,
    /// Service-principal application (client) id.
    pub client_id:     String,
    /// Service-principal client secret. NEVER logged.
    pub client_secret: String,
}

/// IMDS-shape response body the in-VM SDK expects. Numeric
/// fields are wire-stringified per real Azure IMDS.
#[derive(Debug, Serialize, Clone)]
pub struct ImdsTokenResponse {
    /// Short-lived bearer access token.
    pub access_token:   String,
    /// Service-principal client id (echoed).
    pub client_id:      String,
    /// Seconds until expiry (string-encoded per IMDS wire).
    pub expires_in:     String,
    /// Absolute unix-seconds expiry timestamp (string).
    pub expires_on:     String,
    /// AAD's `ext_expires_in` field (string).
    pub ext_expires_in: String,
    /// Unix-seconds `not_before` (string).
    pub not_before:     String,
    /// Resource the token was scoped to.
    pub resource:       String,
    /// Always `"Bearer"`.
    pub token_type:     String,
}

/// Upstream AAD OAuth2 response.
#[derive(Debug, Deserialize)]
struct UpstreamTokenResponse {
    access_token:   String,
    expires_in:     u64,
    #[serde(default)]
    ext_expires_in: Option<u64>,
    token_type:     String,
}

/// Cache value: the rendered in-VM JSON body.
#[derive(Debug, Clone)]
pub struct AzureCacheValue {
    /// Pre-rendered IMDS JSON the proxy re-serves verbatim.
    pub rendered_in_vm_body: Vec<u8>,
}

/// What the proxy connection handler writes to the in-VM
/// client.
#[derive(Debug, Clone)]
pub enum ForwardOutcome {
    /// 200 OK with the rendered IMDS JSON.
    Ok(Vec<u8>),
    /// Pass-through AAD RFC 6749 JSON envelope.
    UpstreamEnvelope {
        /// HTTP status mirrored from upstream (or 503 synthetic).
        status: u16,
        /// JSON body written verbatim.
        body:   Vec<u8>,
    },
}

/// Parse the service-principal credential body. Supports both
/// env-style and JSON.
pub fn parse_service_principal(body: &str) -> Result<ServicePrincipal, UpstreamError> {
    let trimmed = body.trim_start();
    if trimmed.starts_with('{') {
        let v: serde_json::Value = serde_json::from_str(trimmed).map_err(|e| {
            UpstreamError::MissingCredential(format!("service-principal JSON parse: {e}"))
        })?;
        let obj = v.as_object().ok_or_else(|| {
            UpstreamError::MissingCredential(
                "service-principal JSON is not an object".to_owned(),
            )
        })?;
        let tenant_id = pick_str(obj, &["tenant_id", "AZURE_TENANT_ID", "tenantId"])
            .ok_or_else(|| UpstreamError::MissingCredential(
                "missing tenant_id / AZURE_TENANT_ID".to_owned(),
            ))?.to_owned();
        let client_id = pick_str(obj, &["client_id", "AZURE_CLIENT_ID", "appId"])
            .ok_or_else(|| UpstreamError::MissingCredential(
                "missing client_id / AZURE_CLIENT_ID".to_owned(),
            ))?.to_owned();
        let client_secret = pick_str(obj, &["client_secret", "AZURE_CLIENT_SECRET", "password"])
            .ok_or_else(|| UpstreamError::MissingCredential(
                "missing client_secret / AZURE_CLIENT_SECRET".to_owned(),
            ))?.to_owned();
        Ok(ServicePrincipal { tenant_id, client_id, client_secret })
    } else {
        let mut tenant_id     = None;
        let mut client_id     = None;
        let mut client_secret = None;
        for line in body.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') { continue; }
            if let Some((k, v)) = line.split_once('=') {
                let k = k.trim();
                let v = v.trim().trim_matches(['"', '\''].as_ref()).to_owned();
                match k {
                    "AZURE_TENANT_ID"     => tenant_id     = Some(v),
                    "AZURE_CLIENT_ID"     => client_id     = Some(v),
                    "AZURE_CLIENT_SECRET" => client_secret = Some(v),
                    _ => {}
                }
            }
        }
        let tenant_id = tenant_id.ok_or_else(|| UpstreamError::MissingCredential(
            "missing AZURE_TENANT_ID".to_owned(),
        ))?;
        let client_id = client_id.ok_or_else(|| UpstreamError::MissingCredential(
            "missing AZURE_CLIENT_ID".to_owned(),
        ))?;
        let client_secret = client_secret.ok_or_else(|| UpstreamError::MissingCredential(
            "missing AZURE_CLIENT_SECRET".to_owned(),
        ))?;
        Ok(ServicePrincipal { tenant_id, client_id, client_secret })
    }
}

fn pick_str<'a>(
    obj:  &'a serde_json::Map<String, serde_json::Value>,
    keys: &[&str],
) -> Option<&'a str> {
    for k in keys {
        if let Some(v) = obj.get(*k).and_then(|v| v.as_str()) {
            return Some(v);
        }
    }
    None
}

/// Map an IMDS `resource` to the v2.0 OAuth2 `scope`. Real
/// Azure clients append `/.default` to the resource URI to
/// signal "the app-registration-declared default scope set".
/// Idempotent — when `resource` already ends in `/.default`
/// the function returns it unchanged.
pub fn resource_to_scope(resource: &str) -> String {
    let trimmed = resource.trim_end_matches('/');
    if trimmed.ends_with("/.default") {
        resource.to_owned()
    } else {
        format!("{trimmed}/.default")
    }
}

/// URL-encode per `application/x-www-form-urlencoded`.
fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric()
            || b == b'-' || b == b'_' || b == b'.' || b == b'~'
        {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{:02X}", b));
        }
    }
    out
}

/// Build the form-urlencoded `client_credentials`-grant body.
fn build_grant_body(sp: &ServicePrincipal, scope: &str) -> Vec<u8> {
    format!(
        "grant_type=client_credentials&\
         client_id={cid}&\
         client_secret={secret}&\
         scope={scope}",
        cid    = urlencode(&sp.client_id),
        secret = urlencode(&sp.client_secret),
        scope  = urlencode(scope),
    ).into_bytes()
}

/// Build the upstream URL: `https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token`.
fn build_token_url(upstream: &CloudUpstreamHost, tenant_id: &str) -> String {
    format!("{}/{}/oauth2/v2.0/token", upstream.https_base(), tenant_id)
}

/// Cache key for a `client_credentials`-grant result. Folds
/// `tenant_id`, hashed `client_id`, and `scope` into a stable
/// string. NEVER includes the secret.
pub fn build_cache_key(tenant_id: &str, client_id: &str, scope: &str) -> CacheKey {
    let mut s = String::with_capacity(128);
    s.push_str(tenant_id);
    s.push('|');
    use sha2::{Digest, Sha256};
    let h = Sha256::digest(client_id.as_bytes());
    s.push_str(&hex::encode(&h[..8]));
    s.push('|');
    s.push_str(scope);
    CacheKey::new(s)
}

/// Drive one upstream `client_credentials`-grant exchange.
pub async fn drive_client_credentials_exchange(
    fwd:      &ForwardingConfig,
    http:     &CloudHttpClient,
    sp:       &ServicePrincipal,
    resource: &str,
) -> Result<(ImdsTokenResponse, Vec<u8>), (UpstreamError, Option<Vec<u8>>)> {
    let scope = resource_to_scope(resource);
    let body  = build_grant_body(sp, &scope);
    let url   = build_token_url(&fwd.upstream, &sp.tenant_id);
    let (status, body_bytes) = http
        .post_form_urlencoded(&url, Bytes::from(body), &[])
        .await
        .map_err(|e| (e, None))?;

    if (200..300).contains(&status) {
        let parsed: UpstreamTokenResponse = serde_json::from_slice(&body_bytes).map_err(|e| {
            (UpstreamError::UpstreamMalformed(format!("AAD JSON parse: {e}")), None)
        })?;
        let now = unix_now_seconds();
        let expires_on  = now + parsed.expires_in;
        let imds = ImdsTokenResponse {
            access_token:   parsed.access_token,
            client_id:      sp.client_id.clone(),
            expires_in:     parsed.expires_in.to_string(),
            expires_on:     expires_on.to_string(),
            ext_expires_in: parsed.ext_expires_in
                .unwrap_or(parsed.expires_in).to_string(),
            not_before:     now.to_string(),
            resource:       resource.to_owned(),
            token_type:     parsed.token_type,
        };
        let rendered = serde_json::to_vec(&imds).map_err(|e| {
            (UpstreamError::UpstreamMalformed(format!("JSON serialise: {e}")), None)
        })?;
        Ok((imds, rendered))
    } else if (400..500).contains(&status) {
        Err((UpstreamError::Upstream4xx(status), Some(body_bytes.to_vec())))
    } else if (500..600).contains(&status) {
        Err((UpstreamError::Upstream5xx(status), None))
    } else {
        Err((UpstreamError::UpstreamMalformed(format!(
            "unexpected upstream status {status}",
        )), None))
    }
}

/// Synthesise an AAD-flavored OAuth2 RFC 6749 error envelope.
pub fn synthesise_aad_error_envelope(error: &str, description: &str) -> Vec<u8> {
    format!(
        "{{\"error\":\"{error}\",\"error_description\":\"{description}\"}}",
    ).into_bytes()
}

/// Translate an `UpstreamError` to the wire envelope.
fn upstream_error_to_envelope(
    e:           UpstreamError,
    body_4xx:    Option<Vec<u8>>,
) -> ForwardOutcome {
    match e {
        UpstreamError::Upstream4xx(status) => ForwardOutcome::UpstreamEnvelope {
            status,
            body: body_4xx.unwrap_or_else(||
                synthesise_aad_error_envelope("invalid_grant", "upstream returned 4xx")
            ),
        },
        UpstreamError::Upstream5xx(_) => ForwardOutcome::UpstreamEnvelope {
            status: 503,
            body:   synthesise_aad_error_envelope(
                "temporarily_unavailable",
                "Upstream AAD endpoint returned an unrecoverable error",
            ),
        },
        UpstreamError::Network(_) => ForwardOutcome::UpstreamEnvelope {
            status: 503,
            body:   synthesise_aad_error_envelope(
                "temporarily_unavailable",
                "Network error talking to upstream AAD endpoint",
            ),
        },
        UpstreamError::Timeout => ForwardOutcome::UpstreamEnvelope {
            status: 503,
            body:   synthesise_aad_error_envelope(
                "temporarily_unavailable",
                "Upstream AAD endpoint did not respond within the deadline",
            ),
        },
        UpstreamError::UpstreamMalformed(_) => ForwardOutcome::UpstreamEnvelope {
            status: 503,
            body:   synthesise_aad_error_envelope(
                "server_error",
                "Upstream AAD endpoint returned a body that did not parse",
            ),
        },
        UpstreamError::EgressAllowlist(_) => ForwardOutcome::UpstreamEnvelope {
            status: 503,
            body:   synthesise_aad_error_envelope(
                "server_error",
                "Upstream URL fell off the cloud-forwarding allowlist",
            ),
        },
        UpstreamError::MissingCredential(_) => ForwardOutcome::UpstreamEnvelope {
            status: 503,
            body:   synthesise_aad_error_envelope(
                "invalid_client",
                "Operator service-principal credential required for forwarding was missing or malformed",
            ),
        },
        UpstreamError::Misconfigured(_) => ForwardOutcome::UpstreamEnvelope {
            status: 503,
            body:   synthesise_aad_error_envelope(
                "server_error",
                "V3 cloud forwarding misconfigured at proxy construction",
            ),
        },
    }
}

/// End-to-end forwarder.
#[allow(clippy::too_many_arguments)]
pub async fn forward_or_serve_from_cache(
    fwd:             &ForwardingConfig,
    http:            &Arc<CloudHttpClient>,
    cache:           &Arc<TokenCache<AzureCacheValue>>,
    audit:           &Arc<dyn AuditSink>,
    session_id:      &str,
    credential_name: &str,
    sp:              &ServicePrincipal,
    resource:        &str,
) -> ForwardOutcome {
    let scope         = resource_to_scope(resource);
    let key           = build_cache_key(&sp.tenant_id, &sp.client_id, &scope);
    let safety_window = fwd.cache_safety_window;

    if let Some(entry) = cache.get(&key).await {
        let age_ms = entry.age().as_millis() as u32;
        let ttl_ms = entry.ttl_remaining().as_millis() as u32;
        emit_cloud_credential_cache_hit(
            audit, session_id, credential_name,
            CloudProvider::Azure, CloudExchangeKind::ClientCredentials,
            age_ms, ttl_ms,
        ).ok();
        let body = entry.payload.rendered_in_vm_body.clone();
        if entry.is_stale(safety_window) {
            if let Some(guard) = cache.take_refresh_lock(&key).await {
                let fwd2      = fwd.clone();
                let http2     = Arc::clone(http);
                let cache2    = Arc::clone(cache);
                let audit2    = Arc::clone(audit);
                let session2  = session_id.to_owned();
                let cred2     = credential_name.to_owned();
                let sp2       = sp.clone();
                let res2      = resource.to_owned();
                let prior_age = age_ms;
                tokio::spawn(async move {
                    let _g = guard;
                    let started = Instant::now();
                    let res = drive_client_credentials_exchange(
                        &fwd2, &http2, &sp2, &res2,
                    ).await;
                    let elapsed_ms = started.elapsed().as_millis() as u32;
                    let scope2 = resource_to_scope(&res2);
                    let key2 = build_cache_key(&sp2.tenant_id, &sp2.client_id, &scope2);
                    match res {
                        Ok((imds, rendered)) => {
                            let expires_in: u64 = imds.expires_in.parse().unwrap_or(3600);
                            let new_ttl    = Duration::from_secs(expires_in);
                            let new_ttl_ms = new_ttl.as_millis() as u32;
                            cache2.insert(
                                key2,
                                AzureCacheValue { rendered_in_vm_body: rendered.clone() },
                                new_ttl,
                            ).await;
                            emit_cloud_credential_cache_refreshed(
                                &audit2, &session2, &cred2,
                                CloudProvider::Azure, CloudExchangeKind::ClientCredentials,
                                prior_age, new_ttl_ms,
                            ).ok();
                            emit_cloud_credential_forwarded(
                                &audit2, &session2, &cred2,
                                CloudProvider::Azure, CloudExchangeKind::ClientCredentials,
                                &fwd2.upstream, elapsed_ms, 200,
                                rendered.len() as u32, true,
                            ).ok();
                        }
                        Err((e, _)) => {
                            emit_cloud_credential_forwarding_denied(
                                &audit2, &session2, &cred2,
                                CloudProvider::Azure, CloudExchangeKind::ClientCredentials,
                                fwd2.upstream.host(),
                                e.denial_reason(),
                                e.status_code().unwrap_or(0),
                                elapsed_ms,
                            ).ok();
                        }
                    }
                });
            }
        }
        return ForwardOutcome::Ok(body);
    }

    let started = Instant::now();
    let result = drive_client_credentials_exchange(fwd, http, sp, resource).await;
    let elapsed_ms = started.elapsed().as_millis() as u32;
    match result {
        Ok((imds, rendered)) => {
            let expires_in: u64 = imds.expires_in.parse().unwrap_or(3600);
            let ttl = Duration::from_secs(expires_in);
            cache.insert(
                key,
                AzureCacheValue { rendered_in_vm_body: rendered.clone() },
                ttl,
            ).await;
            emit_cloud_credential_forwarded(
                audit, session_id, credential_name,
                CloudProvider::Azure, CloudExchangeKind::ClientCredentials,
                &fwd.upstream, elapsed_ms, 200,
                rendered.len() as u32, true,
            ).ok();
            ForwardOutcome::Ok(rendered)
        }
        Err((e, maybe_body)) => {
            emit_cloud_credential_forwarding_denied(
                audit, session_id, credential_name,
                CloudProvider::Azure, CloudExchangeKind::ClientCredentials,
                fwd.upstream.host(),
                e.denial_reason(),
                e.status_code().unwrap_or(0),
                elapsed_ms,
            ).ok();
            upstream_error_to_envelope(e, maybe_body)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_env_style_service_principal() {
        let body = "\
            AZURE_TENANT_ID=tttt-tttt\n\
            AZURE_CLIENT_ID=cccc-cccc\n\
            AZURE_CLIENT_SECRET=secret-bytes\n";
        let sp = parse_service_principal(body).unwrap();
        assert_eq!(sp.tenant_id,     "tttt-tttt");
        assert_eq!(sp.client_id,     "cccc-cccc");
        assert_eq!(sp.client_secret, "secret-bytes");
    }

    #[test]
    fn parses_json_service_principal() {
        let body = r#"{
            "tenant_id":     "tttt-tttt",
            "client_id":     "cccc-cccc",
            "client_secret": "secret-bytes"
        }"#;
        let sp = parse_service_principal(body).unwrap();
        assert_eq!(sp.tenant_id, "tttt-tttt");
    }

    #[test]
    fn parses_az_ad_sp_create_json_aliases() {
        // `az ad sp create-for-rbac` emits this shape.
        let body = r#"{
            "appId":    "cccc-cccc",
            "password": "secret-bytes",
            "tenant":   "ignored",
            "tenantId": "tttt-tttt"
        }"#;
        let sp = parse_service_principal(body).unwrap();
        assert_eq!(sp.tenant_id,     "tttt-tttt");
        assert_eq!(sp.client_id,     "cccc-cccc");
        assert_eq!(sp.client_secret, "secret-bytes");
    }

    #[test]
    fn missing_field_is_rejected() {
        let body = "AZURE_TENANT_ID=tttt\nAZURE_CLIENT_ID=cccc\n";
        let err = parse_service_principal(body).unwrap_err();
        assert!(matches!(err, UpstreamError::MissingCredential(_)));
    }

    #[test]
    fn resource_to_scope_appends_default() {
        assert_eq!(
            resource_to_scope("https://management.azure.com/"),
            "https://management.azure.com/.default",
        );
    }

    #[test]
    fn resource_to_scope_is_idempotent() {
        let s = "https://graph.microsoft.com/.default";
        assert_eq!(resource_to_scope(s), s);
    }

    #[test]
    fn grant_body_pins_client_credentials_grant_type() {
        let sp = ServicePrincipal {
            tenant_id:     "tttt-tttt".to_owned(),
            client_id:     "cccc-cccc".to_owned(),
            client_secret: "shhh".to_owned(),
        };
        let b = build_grant_body(&sp, "https://management.azure.com/.default");
        let s = std::str::from_utf8(&b).unwrap();
        assert!(s.starts_with("grant_type=client_credentials&"));
        assert!(s.contains("client_id=cccc-cccc"));
        assert!(s.contains("client_secret=shhh"));
        assert!(s.contains("scope=https%3A%2F%2Fmanagement.azure.com%2F.default"));
    }

    #[test]
    fn token_url_includes_tenant_path() {
        let host = CloudUpstreamHost::azure_login();
        let url  = build_token_url(&host, "tttt-tttt");
        assert_eq!(
            url,
            "https://login.microsoftonline.com/tttt-tttt/oauth2/v2.0/token",
        );
    }

    #[test]
    fn cache_key_changes_with_tenant_client_or_scope() {
        let a = build_cache_key("t1", "c1", "s1");
        let b = build_cache_key("t2", "c1", "s1");
        let c = build_cache_key("t1", "c2", "s1");
        let d = build_cache_key("t1", "c1", "s2");
        assert_ne!(a, b);
        assert_ne!(a, c);
        assert_ne!(a, d);
    }

    #[test]
    fn cache_key_hides_client_id_bytes() {
        let k = build_cache_key("t1", "super-secret-client-id", "s1");
        assert!(!k.as_str().contains("super-secret-client-id"));
    }

    #[test]
    fn synthesised_envelope_is_well_formed_oauth2_json() {
        let v = synthesise_aad_error_envelope("invalid_grant", "no");
        let parsed: serde_json::Value = serde_json::from_slice(&v).unwrap();
        assert_eq!(parsed["error"],             "invalid_grant");
        assert_eq!(parsed["error_description"], "no");
    }
}

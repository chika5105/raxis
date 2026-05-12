//! V3 GCP JWT-bearer-grant forwarding path.
//!
//! Normative reference: `specs/v3/cloud-proxy-forwarding.md §2.2`,
//! `§5`, `§6.2`.
//!
//! When [`ForwardingConfig`] is wired on the GCP proxy
//! ([`crate::ProxyConfig::forwarding`]), the per-request serve
//! path for `/computeMetadata/v1/instance/service-accounts/default/token`
//! drives a real JWT-bearer-grant POST against
//! `oauth2.googleapis.com/token` instead of mirroring the
//! long-lived `access_token` from the operator credential body.
//!
//! Flow:
//!
//! 1. Parse the service-account JSON key from
//!    `CredentialBackend::resolve`. The body MUST contain
//!    `client_email`, `private_key` (PKCS#8 PEM), `token_uri`
//!    (which we ignore — the upstream is allowlist-pinned),
//!    and optionally `private_key_id` (mirrored to the JWT
//!    header's `kid` field).
//! 2. Build the JWT claims:
//!    `{ "iss": client_email, "scope": "<space-joined>",
//!       "aud": "https://oauth2.googleapis.com/token",
//!       "exp": now+3600, "iat": now }`.
//! 3. RS256-sign the JWT with the parsed RSA private key.
//! 4. POST `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=<jwt>`
//!    to the shared `CloudHttpClient` (closed allowlist).
//! 5. Parse the JSON response: `{ "access_token": "...",
//!    "expires_in": N, "token_type": "Bearer", "scope": "..." }`.
//! 6. Render the in-VM metadata-server token response
//!    (same fields, GCP-flavored) and cache it.
//!
//! On failure, the proxy preserves the upstream's RFC 6749
//! JSON error envelope verbatim on 4xx, and synthesises a
//! canonical `error_description` / `503` envelope on 5xx /
//! network / timeout / malformed-success per spec §6.4.

use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
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
use rsa::{RsaPrivateKey, pkcs8::DecodePrivateKey, signature::{RandomizedSigner, SignatureEncoding}, pkcs1v15::SigningKey};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

/// Per-listener V3 forwarding configuration.
#[derive(Debug, Clone)]
pub struct ForwardingConfig {
    /// Upstream OAuth2 endpoint (`oauth2.googleapis.com`).
    /// Construction-allowlisted via [`CloudUpstreamHost::gcp_oauth2`].
    pub upstream:            CloudUpstreamHost,
    /// OAuth scopes to request — space-joined into the JWT's
    /// `scope` claim. Comes from
    /// `Restrictions::allowed_scopes`. MUST be non-empty in
    /// V3.
    pub scopes:              Vec<String>,
    /// JWT lifetime. Spec-clamped to 60 s..3600 s.
    pub jwt_lifetime:        Duration,
    /// Token cache safety-window.
    pub cache_safety_window: Duration,
}

/// Canonical content-type of an OAuth2 RFC 6749 envelope.
pub const GCP_JSON_CONTENT_TYPE: &str = "application/json";

/// Parsed service-account JSON key — the operator credential
/// body shape for V3 GCP forwarding.
#[derive(Debug, Clone, Deserialize)]
pub struct ServiceAccountKey {
    /// Service-account email (the `iss` claim in the JWT).
    pub client_email:    String,
    /// PEM-encoded PKCS#8 RSA private key.
    pub private_key:     String,
    /// Optional fingerprint of the private key; goes into the
    /// JWT's `kid` header so the upstream can rotate.
    #[serde(default)]
    pub private_key_id:  Option<String>,
    /// Service-account token URI. Ignored — the upstream is
    /// allowlist-pinned. Parsed only so the JSON shape
    /// matches the GCP-canonical service-account.json layout.
    #[serde(default)]
    pub token_uri:       Option<String>,
}

/// In-VM metadata-server JSON body for the `/token` endpoint.
#[derive(Debug, Serialize, Clone)]
pub struct InVmTokenResponse {
    /// Short-lived access token (the upstream-issued value).
    pub access_token: String,
    /// Seconds until expiry (mirrored from upstream).
    pub expires_in:   u64,
    /// Always `"Bearer"`.
    pub token_type:   String,
    /// Space-joined scope set the upstream actually granted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope:        Option<String>,
}

/// Upstream OAuth2 success response.
#[derive(Debug, Deserialize)]
struct UpstreamTokenResponse {
    access_token: String,
    expires_in:   u64,
    token_type:   String,
    #[serde(default)]
    scope:        Option<String>,
}

/// Cache value: the rendered in-VM JSON body.
#[derive(Debug, Clone)]
pub struct GcpCacheValue {
    /// Pre-rendered metadata-server JSON the proxy re-serves
    /// verbatim.
    pub rendered_in_vm_body: Vec<u8>,
}

/// What the proxy connection handler writes to the in-VM
/// client.
#[derive(Debug, Clone)]
pub enum ForwardOutcome {
    /// 200 OK with the rendered metadata-server JSON.
    Ok(Vec<u8>),
    /// Pass-through OAuth2 RFC 6749 JSON envelope.
    UpstreamEnvelope {
        /// HTTP status mirrored from upstream (or 503 synthetic).
        status: u16,
        /// JSON body written verbatim.
        body:   Vec<u8>,
    },
}

/// Parse the service-account JSON key. Returns a structured
/// `UpstreamError::MissingCredential` when required fields are
/// absent.
pub fn parse_service_account_key(body: &str) -> Result<ServiceAccountKey, UpstreamError> {
    let key: ServiceAccountKey = serde_json::from_str(body.trim_start()).map_err(|e| {
        UpstreamError::MissingCredential(format!("service-account JSON parse: {e}"))
    })?;
    if key.client_email.is_empty() {
        return Err(UpstreamError::MissingCredential(
            "service-account JSON missing client_email".to_owned(),
        ));
    }
    if !key.private_key.contains("BEGIN") || !key.private_key.contains("PRIVATE KEY") {
        return Err(UpstreamError::MissingCredential(
            "service-account JSON missing or malformed private_key PEM".to_owned(),
        ));
    }
    Ok(key)
}

/// JWT header rendered into base64url-encoded bytes.
fn jwt_header(kid: Option<&str>) -> String {
    let json = match kid {
        Some(k) => format!(r#"{{"alg":"RS256","typ":"JWT","kid":"{}"}}"#, k),
        None    =>                  r#"{"alg":"RS256","typ":"JWT"}"#.to_owned(),
    };
    B64URL.encode(json.as_bytes())
}

/// JWT claims rendered into base64url-encoded bytes.
fn jwt_claims(
    iss:    &str,
    scope:  &str,
    aud:    &str,
    iat:    u64,
    exp:    u64,
) -> String {
    let json = format!(
        r#"{{"iss":"{iss}","scope":"{scope}","aud":"{aud}","exp":{exp},"iat":{iat}}}"#,
    );
    B64URL.encode(json.as_bytes())
}

/// Build and RS256-sign the JWT. Returns the full `header.claims.signature`
/// JWS-compact string.
pub fn build_signed_jwt(
    key:        &ServiceAccountKey,
    scopes:     &[String],
    audience:   &str,
    now_unix:   u64,
    lifetime:   Duration,
) -> Result<String, UpstreamError> {
    let header_b64 = jwt_header(key.private_key_id.as_deref());
    let scope_joined = scopes.join(" ");
    let claims_b64 = jwt_claims(
        &key.client_email,
        &scope_joined,
        audience,
        now_unix,
        now_unix + lifetime.as_secs(),
    );
    let signing_input = format!("{header_b64}.{claims_b64}");

    let private_key = RsaPrivateKey::from_pkcs8_pem(&key.private_key).map_err(|e| {
        UpstreamError::MissingCredential(format!("RSA private_key parse failed: {e}"))
    })?;
    let signing_key = SigningKey::<Sha256>::new(private_key);
    let mut rng = rsa::rand_core::OsRng;
    let sig = signing_key.sign_with_rng(&mut rng, signing_input.as_bytes());
    let signature_b64 = B64URL.encode(sig.to_bytes());

    Ok(format!("{signing_input}.{signature_b64}"))
}

/// Cache key for a JWT-bearer-grant result. Folds
/// `client_email` + sorted scopes into a stable string.
/// NEVER includes credential bytes.
pub fn build_cache_key(client_email: &str, scopes: &[String]) -> CacheKey {
    let mut sorted: Vec<&str> = scopes.iter().map(String::as_str).collect();
    sorted.sort_unstable();
    let mut s = String::with_capacity(128);
    s.push_str(client_email);
    s.push('|');
    s.push_str(&sorted.join(","));
    CacheKey::new(s)
}

/// Build the form-urlencoded JWT-bearer-grant body.
fn build_grant_body(assertion: &str) -> Vec<u8> {
    format!(
        "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion={assertion}",
    ).into_bytes()
}

/// Drive one upstream JWT-bearer-grant exchange. Returns the
/// rendered in-VM JSON body bytes on success.
pub async fn drive_jwt_bearer_exchange(
    fwd:    &ForwardingConfig,
    http:   &CloudHttpClient,
    sa:     &ServiceAccountKey,
) -> Result<(InVmTokenResponse, Vec<u8>), (UpstreamError, Option<Vec<u8>>)> {
    let now = unix_now_seconds();
    let audience = format!("{}/token", fwd.upstream.https_base());
    let jwt = build_signed_jwt(sa, &fwd.scopes, &audience, now, fwd.jwt_lifetime)
        .map_err(|e| (e, None))?;
    let body = build_grant_body(&jwt);
    let url  = format!("{}/token", fwd.upstream.https_base());
    let (status, body_bytes) = http
        .post_form_urlencoded(&url, Bytes::from(body), &[])
        .await
        .map_err(|e| (e, None))?;

    if (200..300).contains(&status) {
        let parsed: UpstreamTokenResponse = serde_json::from_slice(&body_bytes).map_err(|e| {
            (UpstreamError::UpstreamMalformed(format!("OAuth2 JSON parse: {e}")), None)
        })?;
        let in_vm = InVmTokenResponse {
            access_token: parsed.access_token,
            expires_in:   parsed.expires_in,
            token_type:   parsed.token_type,
            scope:        parsed.scope,
        };
        let rendered = serde_json::to_vec(&in_vm).map_err(|e| {
            (UpstreamError::UpstreamMalformed(format!("JSON serialise: {e}")), None)
        })?;
        Ok((in_vm, rendered))
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

/// Synthesise an OAuth2 RFC 6749 error envelope.
pub fn synthesise_oauth2_error_envelope(error: &str, description: &str) -> Vec<u8> {
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
                synthesise_oauth2_error_envelope("invalid_grant", "upstream returned 4xx")
            ),
        },
        UpstreamError::Upstream5xx(_) => ForwardOutcome::UpstreamEnvelope {
            status: 503,
            body:   synthesise_oauth2_error_envelope(
                "temporarily_unavailable",
                "Upstream OAuth2 endpoint returned an unrecoverable error",
            ),
        },
        UpstreamError::Network(_) => ForwardOutcome::UpstreamEnvelope {
            status: 503,
            body:   synthesise_oauth2_error_envelope(
                "temporarily_unavailable",
                "Network error talking to upstream OAuth2 endpoint",
            ),
        },
        UpstreamError::Timeout => ForwardOutcome::UpstreamEnvelope {
            status: 503,
            body:   synthesise_oauth2_error_envelope(
                "temporarily_unavailable",
                "Upstream OAuth2 endpoint did not respond within the deadline",
            ),
        },
        UpstreamError::UpstreamMalformed(_) => ForwardOutcome::UpstreamEnvelope {
            status: 503,
            body:   synthesise_oauth2_error_envelope(
                "server_error",
                "Upstream OAuth2 endpoint returned a body that did not parse",
            ),
        },
        UpstreamError::EgressAllowlist(_) => ForwardOutcome::UpstreamEnvelope {
            status: 503,
            body:   synthesise_oauth2_error_envelope(
                "server_error",
                "Upstream URL fell off the cloud-forwarding allowlist",
            ),
        },
        UpstreamError::MissingCredential(_) => ForwardOutcome::UpstreamEnvelope {
            status: 503,
            body:   synthesise_oauth2_error_envelope(
                "invalid_client",
                "Operator service-account key required for forwarding was missing or malformed",
            ),
        },
        UpstreamError::Misconfigured(_) => ForwardOutcome::UpstreamEnvelope {
            status: 503,
            body:   synthesise_oauth2_error_envelope(
                "server_error",
                "V3 cloud forwarding misconfigured at proxy construction",
            ),
        },
    }
}

/// End-to-end forwarder. Mirrors the AWS path: cache-hit fast-
/// path, aging-window single-flight background refresh,
/// cold-path synchronous exchange. All four V3 audit events
/// emitted at the right boundaries.
#[allow(clippy::too_many_arguments)]
pub async fn forward_or_serve_from_cache(
    fwd:             &ForwardingConfig,
    http:            &Arc<CloudHttpClient>,
    cache:           &Arc<TokenCache<GcpCacheValue>>,
    audit:           &Arc<dyn AuditSink>,
    session_id:      &str,
    credential_name: &str,
    service_account: &ServiceAccountKey,
) -> ForwardOutcome {
    let key           = build_cache_key(&service_account.client_email, &fwd.scopes);
    let safety_window = fwd.cache_safety_window;

    if let Some(entry) = cache.get(&key).await {
        let age_ms = entry.age().as_millis() as u32;
        let ttl_ms = entry.ttl_remaining().as_millis() as u32;
        emit_cloud_credential_cache_hit(
            audit, session_id, credential_name,
            CloudProvider::Gcp, CloudExchangeKind::JwtBearer,
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
                let sa2       = service_account.clone();
                let prior_age = age_ms;
                tokio::spawn(async move {
                    let _g = guard;
                    let started = Instant::now();
                    let res = drive_jwt_bearer_exchange(&fwd2, &http2, &sa2).await;
                    let elapsed_ms = started.elapsed().as_millis() as u32;
                    let key2 = build_cache_key(&sa2.client_email, &fwd2.scopes);
                    match res {
                        Ok((parsed, rendered)) => {
                            let new_ttl = Duration::from_secs(parsed.expires_in);
                            let new_ttl_ms = new_ttl.as_millis() as u32;
                            cache2.insert(
                                key2,
                                GcpCacheValue { rendered_in_vm_body: rendered.clone() },
                                new_ttl,
                            ).await;
                            emit_cloud_credential_cache_refreshed(
                                &audit2, &session2, &cred2,
                                CloudProvider::Gcp, CloudExchangeKind::JwtBearer,
                                prior_age, new_ttl_ms,
                            ).ok();
                            emit_cloud_credential_forwarded(
                                &audit2, &session2, &cred2,
                                CloudProvider::Gcp, CloudExchangeKind::JwtBearer,
                                &fwd2.upstream, elapsed_ms, 200,
                                rendered.len() as u32, true,
                            ).ok();
                        }
                        Err((e, _)) => {
                            emit_cloud_credential_forwarding_denied(
                                &audit2, &session2, &cred2,
                                CloudProvider::Gcp, CloudExchangeKind::JwtBearer,
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
    let result = drive_jwt_bearer_exchange(fwd, http, service_account).await;
    let elapsed_ms = started.elapsed().as_millis() as u32;
    match result {
        Ok((parsed, rendered)) => {
            let ttl = Duration::from_secs(parsed.expires_in);
            cache.insert(
                key,
                GcpCacheValue { rendered_in_vm_body: rendered.clone() },
                ttl,
            ).await;
            emit_cloud_credential_forwarded(
                audit, session_id, credential_name,
                CloudProvider::Gcp, CloudExchangeKind::JwtBearer,
                &fwd.upstream, elapsed_ms, 200,
                rendered.len() as u32, true,
            ).ok();
            ForwardOutcome::Ok(rendered)
        }
        Err((e, maybe_body)) => {
            emit_cloud_credential_forwarding_denied(
                audit, session_id, credential_name,
                CloudProvider::Gcp, CloudExchangeKind::JwtBearer,
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

    const TEST_PRIVATE_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKj\nMzEfYyjiWA4R4/M2bS1GB4t7NXp98C3SC6dVMvDuictGeurT8jNbvJZHtCSuYEvu\nNMoSfm76oqFvAp8Gy0iz5sxjZmSnXyCdPEovGhLa0VzMaQ8s+CLOyS56YyCFGeJZ\nqgtzJ6GR3eqoYSW9b9UMvkBpZODSctWSNGj3P7jRFDO5VoTwCQAWbFnOjDfH5Ulg\np2PKSQnSJP3AJLQNFNe7br1XbrhV//eO+t51mIpGSDCUv3E0DDFcWDTH9cXDTTlR\nZVEiR2BwpZOOkE/Z0/BVnhZYL71oZV34bKfWjQIt6V/isSMahdsAASACp4ZTGtwi\nVuNd9tybAgMBAAECggEAVc6bu7VAnP6v0frZ4nLF5h0rsAcKxlGoZRiOY/aD6CGl\n0qRD8KZNk+Fk8KZNk+aFk8KZNkbA4dG3l8VqM2nfXJjyl0vqGCpfBmKvgmGu1m1k\nNgK0pwYKZqYE8WyDpC5y3Y1z+oQJGZGqdMFGT8E8L6IUUYWQ6bWqOQ5w6Wzj0BBu\nl1Jt/qphkKqp17lUkBvk7E7E2lEZHezC5dE+8MgFa2k0kqYHkLcyy4VfFn/u1xkN\nhSDihu1lUKK4j7gzPksZBghHU7XBu2Z+9eOmZQwWtaQ6QV9SgGu/8x2lzCH4VPgo\nUm6bA0g+OAg6XnTYQONwGRq2cy3CYV1J5SCxewKBgQDr7tnHV5+pYNAB+ozzgwzm\n3FQOuh5kCcAJ8jWXqx3hKqWUO6m4lLF7AFhHaPHd3MMlmRwG7n2hrx96oa4Yy0g+\nWyykJZNyKlcpsdRzNxbpjwAA9LeImQwlw7ouxx9aHpFhdfFwhcb4OGgnMs5n7yWl\nDoqVH7lwSpu9k2bGfTC4VwKBgQDLn0pTMSZ6tdaJ2lZsv7QYxBaR3JJF0vfRdNB1\nQqj3KqxRl1HRb88PiGKQjB5+B5tLMo6dXn7+Pxc6JlYUvHHIxL3KAcr1nFLb3++8\nLh8tvDQNuRGZWxbF1Vp5TYsdK4eMU0SUNQqUq3xytAjvFRZECPXkprAW6dCEZ97W\nQOzlPQKBgQCFcZTOMfltLkAvIhKHwTrUlpDLZbXgJ1Tw8WqJpOoxqIKfALzhZ5x4\nF4mGRP3FCo5jPjZxBcdQyq+gh/3xz2bnnsl2sZIKGgPYBJj6kFM1pn8VEbY4MAFt\nF7XQ1jVHjvKvvHcXP8AfqaY0BB2P2OrWoBP/EHs2BlSktXJlsLfPdQKBgFCFNHLb\nVlPUjqHhRT8YQQ+yMOLBnQA40CcSyzwlV4QyrJG1zSdMYJoVQqg4tNQvtuC/sBHQ\nGRZL3LpFvLiX2YN9D3+JwAA5Y5o4hknXLfBzWzn5jvUL3a3/3uCJVZuJqGmEz5G7\nQjlEKLPxJrqDQXKWeOyTM5+J/2RUcGT0bLrZAoGAfFa3sNyy3DJBgUMtKL3w3p2g\nGD+f5cVKqWZeUlR2Hg7t8Q3pPzuS2vTfAA72ub3LM2sJYQwL2pgZkdC2Vwn5g8h4\nfO+y0YjlSj8mFGiI2eHvCZbqW0w8/sxANrAkPNHl8DcImTI3wRJDGoP8jq2NRBy/\nv3ZdiM9NLnQbR82wjQU=\n-----END PRIVATE KEY-----\n";

    #[test]
    fn parse_service_account_key_round_trip() {
        let body = format!(
            r#"{{
                "type": "service_account",
                "client_email": "svc@example.iam.gserviceaccount.com",
                "private_key_id": "kid-1",
                "private_key": {:?},
                "token_uri": "https://oauth2.googleapis.com/token"
            }}"#,
            TEST_PRIVATE_KEY_PEM,
        );
        let sa = parse_service_account_key(&body).unwrap();
        assert_eq!(sa.client_email, "svc@example.iam.gserviceaccount.com");
        assert_eq!(sa.private_key_id.as_deref(), Some("kid-1"));
        assert!(sa.private_key.contains("BEGIN PRIVATE KEY"));
    }

    #[test]
    fn parse_service_account_rejects_missing_client_email() {
        let body = r#"{"private_key": "-----BEGIN PRIVATE KEY-----\nfoo\n-----END PRIVATE KEY-----\n"}"#;
        let err = parse_service_account_key(body).unwrap_err();
        assert!(matches!(err, UpstreamError::MissingCredential(_)));
    }

    #[test]
    fn parse_service_account_rejects_missing_private_key() {
        let body = r#"{"client_email": "svc@example.iam.gserviceaccount.com"}"#;
        let err = parse_service_account_key(body).unwrap_err();
        assert!(matches!(err, UpstreamError::MissingCredential(_)));
    }

    #[test]
    fn jwt_header_pins_alg_typ_kid() {
        let h = jwt_header(Some("kid-1"));
        let raw = B64URL.decode(h).unwrap();
        let s = std::str::from_utf8(&raw).unwrap();
        assert!(s.contains(r#""alg":"RS256""#));
        assert!(s.contains(r#""typ":"JWT""#));
        assert!(s.contains(r#""kid":"kid-1""#));
    }

    #[test]
    fn jwt_claims_includes_all_required_fields() {
        let c = jwt_claims(
            "svc@example.iam.gserviceaccount.com",
            "https://www.googleapis.com/auth/devstorage.read_only",
            "https://oauth2.googleapis.com/token",
            1_778_608_800,
            1_778_612_400,
        );
        let raw = B64URL.decode(c).unwrap();
        let s = std::str::from_utf8(&raw).unwrap();
        assert!(s.contains(r#""iss":"svc@example.iam.gserviceaccount.com""#));
        assert!(s.contains(r#""scope":"https://www.googleapis.com/auth/devstorage.read_only""#));
        assert!(s.contains(r#""aud":"https://oauth2.googleapis.com/token""#));
        assert!(s.contains(r#""iat":1778608800"#));
        assert!(s.contains(r#""exp":1778612400"#));
    }

    #[test]
    fn cache_key_normalises_scope_order() {
        let a = build_cache_key("svc@e.example", &["scope2".into(), "scope1".into()]);
        let b = build_cache_key("svc@e.example", &["scope1".into(), "scope2".into()]);
        assert_eq!(a, b);
    }

    #[test]
    fn cache_key_changes_with_email_or_scope_set() {
        let a = build_cache_key("svc1@e.example", &["s".into()]);
        let b = build_cache_key("svc2@e.example", &["s".into()]);
        let c = build_cache_key("svc1@e.example", &["s2".into()]);
        assert_ne!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn grant_body_pins_jwt_bearer_grant_type() {
        let b = build_grant_body("HEADER.CLAIMS.SIG");
        let s = std::str::from_utf8(&b).unwrap();
        assert!(s.starts_with("grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&"));
        assert!(s.ends_with("assertion=HEADER.CLAIMS.SIG"));
    }

    #[test]
    fn synthesised_envelope_is_well_formed_oauth2_json() {
        let v = synthesise_oauth2_error_envelope("invalid_grant", "no");
        let parsed: serde_json::Value = serde_json::from_slice(&v).unwrap();
        assert_eq!(parsed["error"],             "invalid_grant");
        assert_eq!(parsed["error_description"], "no");
    }
}

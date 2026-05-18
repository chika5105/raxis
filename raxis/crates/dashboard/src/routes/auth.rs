//! Auth endpoints: challenge, verify, logout.

use std::sync::Arc;

use axum::extract::{Json as AxumJson, State};
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::auth::{now_secs, JwtSigner, MintedJwt};
use crate::error::{ApiError, ApiResult};
use crate::server::AppState;

/// Response body for `GET /api/auth/challenge`.
#[derive(Debug, Serialize)]
pub struct ChallengeResponse {
    /// Challenge bytes hex-encoded (32 bytes ⇒ 64 hex chars).
    pub challenge: String,
    /// Unix-seconds expiration timestamp.
    pub expires_at: u64,
}

/// `GET /api/auth/challenge` — mint a fresh challenge.
pub async fn challenge<D>(State(state): State<AppState<D>>) -> ApiResult<Json<ChallengeResponse>>
where
    D: crate::data::DashboardData,
{
    let (challenge, expires_at) = state.auth.challenges.mint()?;
    Ok(Json(ChallengeResponse {
        challenge,
        expires_at,
    }))
}

/// Request body for `POST /api/auth/verify`.
#[derive(Debug, Deserialize)]
pub struct VerifyRequest {
    /// The challenge bytes (hex) the operator signed.
    pub challenge: String,
    /// Ed25519 signature (hex; 64 bytes ⇒ 128 hex chars).
    pub signature: String,
    /// Operator public key (hex; 32 bytes ⇒ 64 hex chars).
    pub public_key: String,
}

/// Response body for `POST /api/auth/verify`.
#[derive(Debug, Serialize)]
pub struct VerifyResponse {
    /// Compact-form HS256 JWT.
    pub token: String,
    /// Operator's pubkey fingerprint.
    pub operator_id: String,
    /// Display name from the operator entry.
    pub display_name: String,
    /// Roles granted to the operator.
    pub roles: Vec<String>,
    /// Unix-seconds expiration of the JWT.
    pub expires_at: u64,
}

/// `POST /api/auth/verify` — consume the challenge, verify the
/// operator signature, look up roles, mint a JWT.
pub async fn verify<D>(
    State(state): State<AppState<D>>,
    AxumJson(req): AxumJson<VerifyRequest>,
) -> ApiResult<Json<VerifyResponse>>
where
    D: crate::data::DashboardData,
{
    // 1. Validate hex shapes up front to avoid a slow path that
    //    runs Ed25519 verify on garbage.
    let challenge_bytes = hex::decode(&req.challenge).map_err(|_| ApiError::BadRequest {
        detail: "challenge: not hex".into(),
    })?;
    let pubkey_bytes = hex::decode(&req.public_key).map_err(|_| ApiError::BadRequest {
        detail: "public_key: not hex".into(),
    })?;
    let sig_bytes = hex::decode(&req.signature).map_err(|_| ApiError::BadRequest {
        detail: "signature: not hex".into(),
    })?;
    if pubkey_bytes.len() != 32 {
        return Err(ApiError::BadRequest {
            detail: "public_key: not 32 bytes".into(),
        });
    }
    if sig_bytes.len() != 64 {
        return Err(ApiError::BadRequest {
            detail: "signature: not 64 bytes".into(),
        });
    }

    // 2. Consume the challenge (replay-protected) BEFORE the
    //    expensive sig verify. A wrong sig still consumes the
    //    challenge so an attacker cannot use the verify endpoint
    //    as a sig-verify oracle on a fixed challenge.
    state.auth.challenges.consume(&req.challenge)?;

    // 3. Verify the Ed25519 signature.
    raxis_crypto::verify_ed25519(&pubkey_bytes, &challenge_bytes, &sig_bytes)
        .map_err(|_| ApiError::SignatureInvalid)?;

    // 4. Compute the operator fingerprint (SHA-256[:16] of pubkey).
    let fingerprint = operator_fingerprint(&pubkey_bytes);

    // 5. Resolve roles via the data layer.
    let resolution = state
        .data
        .lookup_operator_roles(&fingerprint)
        .ok_or(ApiError::UnknownOperator)?;
    let role_strings: Vec<String> = resolution
        .roles
        .iter()
        .map(|r| r.as_str().to_owned())
        .collect();

    // 6. Mint the JWT.
    let MintedJwt {
        token,
        jti: _,
        expires_at,
        claims: _,
    } = state
        .auth
        .jwt
        .mint(&fingerprint, &resolution.display_name, role_strings.clone())?;

    Ok(Json(VerifyResponse {
        token,
        operator_id: fingerprint,
        display_name: resolution.display_name,
        roles: role_strings,
        expires_at,
    }))
}

/// Request body for `POST /api/auth/logout`.
#[derive(Debug, Deserialize)]
pub struct LogoutRequest {
    /// The JWT to revoke. Required so logout cannot be triggered
    /// by simply landing on the endpoint without a token (the
    /// shared revocation set is bounded; bound consumption MUST
    /// require the operator to actually present the token).
    pub token: String,
}

/// `POST /api/auth/logout` — verify-then-revoke the supplied JWT.
pub async fn logout<D>(
    State(state): State<AppState<D>>,
    AxumJson(req): AxumJson<LogoutRequest>,
) -> ApiResult<Json<serde_json::Value>>
where
    D: crate::data::DashboardData,
{
    // Verify so we know the JWT is one we minted (and not yet
    // expired). Otherwise a malicious client could fill the
    // revocation set with random strings.
    let claims = state.auth.jwt.verify(&req.token)?;
    state
        .auth
        .revocations
        .revoke(JwtSigner::digest(&req.token), claims.exp);
    Ok(Json(serde_json::json!({
        "revoked_at": now_secs(),
        "operator_id": claims.fingerprint,
    })))
}

/// Compute the SHA-256[:16] fingerprint that
/// `OperatorEntry::pubkey_fingerprint` carries.
fn operator_fingerprint(pubkey_bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(pubkey_bytes);
    let digest = h.finalize();
    hex::encode(&digest[..16])
}

/// Helper used by tests + integration crates to compute the same
/// fingerprint the verify path computes.
pub fn operator_fingerprint_hex(pubkey_bytes: &[u8]) -> String {
    operator_fingerprint(pubkey_bytes)
}

/// Build the auth router.
pub fn router<D>() -> axum::Router<Arc<AppStateInner<D>>>
where
    D: crate::data::DashboardData,
{
    use axum::routing::{get, post};
    axum::Router::new()
        .route("/api/auth/challenge", get(challenge::<D>))
        .route("/api/auth/verify", post(verify::<D>))
        .route("/api/auth/logout", post(logout::<D>))
}

// re-export for the router glue
pub use crate::server::AppStateInner;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operator_fingerprint_pins_first_16_bytes() {
        let pk = [0x42u8; 32];
        let fp = operator_fingerprint(&pk);
        // SHA-256(0x42 * 32) = ... pin truncation length only.
        assert_eq!(fp.len(), 32, "fingerprint is hex of 16 bytes");
    }
}

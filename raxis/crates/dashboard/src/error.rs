//! Uniform JSON error envelope for the dashboard HTTP surface.
//!
//! Spec: `v2_extended_gaps.md §4.7` — `R-10 (Opaque rejection)`.
//! API errors do NOT leak internal kernel state (no stack traces,
//! no internal paths). Each error carries a stable `code` string
//! (e.g. `FAIL_DASHBOARD_AUTH`) plus a short human-readable
//! `message`. The HTTP status code is derived from the variant.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Serialize;

/// JSON-shaped error returned to the browser.
#[derive(Debug, Clone, Serialize)]
pub struct ApiErrorBody {
    /// Stable machine-readable code (e.g. `FAIL_DASHBOARD_AUTH`).
    pub code: String,
    /// Short human-readable message. MUST NOT carry internal
    /// state (no paths, no stack traces, no opaque pointers).
    pub message: String,
}

/// Result alias the route handlers return.
pub type ApiResult<T> = Result<T, ApiError>;

/// All dashboard error variants.
#[derive(Debug, Clone, thiserror::Error)]
pub enum ApiError {
    /// Authorization header is missing or malformed.
    #[error("missing or malformed Authorization header")]
    MissingAuth,
    /// Bearer token rejected by JWT verification.
    #[error("invalid or expired JWT")]
    InvalidJwt,
    /// JWT was added to the revocation set via `POST /api/auth/logout`.
    #[error("token revoked")]
    JwtRevoked,
    /// Operator is authenticated but lacks the required role.
    #[error("operator lacks role: {required}")]
    Forbidden {
        /// Role name that was required.
        required: String,
    },
    /// Operator's certificate failed enforcement (expired,
    /// revoked, etc.). `detail` is a short SAFE message — no
    /// stack traces.
    #[error("operator certificate rejected: {detail}")]
    CertRejected {
        /// Short reason (e.g. "expired", "revoked", "unknown_fingerprint").
        detail: String,
    },
    /// Login challenge missing, expired, or already-consumed.
    #[error("challenge expired or unknown")]
    ChallengeExpired,
    /// Ed25519 signature verification failed.
    #[error("signature verification failed")]
    SignatureInvalid,
    /// Operator pubkey not present in the active policy bundle.
    #[error("unknown operator pubkey")]
    UnknownOperator,
    /// Caller asked for an entity (initiative, task, session, …)
    /// that does not exist.
    #[error("not found: {kind}")]
    NotFound {
        /// Entity kind name (e.g. `"initiative"`, `"task"`).
        kind: String,
    },
    /// Caller asked for an entity that **did** exist but has been
    /// archived / purged on disk and can no longer be served. Maps
    /// to HTTP 410 Gone — distinct from 404 because the absence is
    /// an intentional retention outcome rather than a bad path. The
    /// canonical instance is the dashboard plan-view endpoint when
    /// an initiative's `plan_bundle_artifacts` row was sweep-purged
    /// (see `INV-DASHBOARD-INITIATIVE-PLAN-VISIBLE-01`).
    #[error("gone: {kind}")]
    Gone {
        /// Entity kind name (e.g. `"plan"`).
        kind: String,
    },
    /// Caller-supplied input failed validation. `detail` is safe
    /// to surface to the browser.
    #[error("bad request: {detail}")]
    BadRequest {
        /// Short human-readable message.
        detail: String,
    },
    /// The dashboard policy-update endpoint refused the new TOML
    /// before it was installed. `detail` is the validator's own
    /// short message.
    #[error("policy validation failed: {detail}")]
    PolicyInvalid {
        /// Short validator-message (already operator-safe).
        detail: String,
    },
    /// An infrastructure error (DB, audit, IO) occurred. The
    /// inner detail is logged via `tracing::error!` and replaced
    /// with a generic `internal error` on the wire so internal
    /// state cannot leak.
    #[error("internal error")]
    Internal {
        /// Logged to tracing only; never sent to the browser.
        log_only: String,
    },
}

impl ApiError {
    fn status_and_code(&self) -> (StatusCode, &'static str) {
        match self {
            Self::MissingAuth => (StatusCode::UNAUTHORIZED, "FAIL_DASHBOARD_AUTH_MISSING"),
            Self::InvalidJwt => (StatusCode::UNAUTHORIZED, "FAIL_DASHBOARD_AUTH_JWT"),
            Self::JwtRevoked => (StatusCode::UNAUTHORIZED, "FAIL_DASHBOARD_AUTH_JWT_REVOKED"),
            Self::Forbidden { .. } => (StatusCode::FORBIDDEN, "FAIL_DASHBOARD_FORBIDDEN"),
            Self::CertRejected { .. } => (StatusCode::FORBIDDEN, "FAIL_DASHBOARD_CERT_REJECTED"),
            Self::ChallengeExpired => (StatusCode::UNAUTHORIZED, "FAIL_DASHBOARD_CHALLENGE_EXPIRED"),
            Self::SignatureInvalid => (StatusCode::UNAUTHORIZED, "FAIL_DASHBOARD_SIGNATURE"),
            Self::UnknownOperator => (StatusCode::UNAUTHORIZED, "FAIL_DASHBOARD_OPERATOR"),
            Self::NotFound { .. } => (StatusCode::NOT_FOUND, "FAIL_DASHBOARD_NOT_FOUND"),
            Self::Gone { .. } => (StatusCode::GONE, "FAIL_DASHBOARD_GONE"),
            Self::BadRequest { .. } => (StatusCode::BAD_REQUEST, "FAIL_DASHBOARD_BAD_REQUEST"),
            Self::PolicyInvalid { .. } => (StatusCode::BAD_REQUEST, "FAIL_DASHBOARD_POLICY_INVALID"),
            Self::Internal { log_only } => {
                tracing::error!(error = %log_only, "raxis-dashboard internal error");
                (StatusCode::INTERNAL_SERVER_ERROR, "FAIL_DASHBOARD_INTERNAL")
            }
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, code) = self.status_and_code();
        let body = ApiErrorBody {
            code: code.to_owned(),
            message: self.to_string(),
        };
        (status, Json(body)).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_auth_yields_401() {
        let r = ApiError::MissingAuth.into_response();
        assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn forbidden_yields_403() {
        let r = ApiError::Forbidden { required: "admin".into() }.into_response();
        assert_eq!(r.status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn internal_does_not_leak_log_only_into_message() {
        // The Display impl for ApiError::Internal collapses to a
        // generic "internal error" string. The log_only field is
        // captured by tracing; the wire message is safe.
        let e = ApiError::Internal {
            log_only: "secret /etc/raxis/internal.db corrupt".into(),
        };
        assert_eq!(e.to_string(), "internal error");
    }

    #[test]
    fn not_found_yields_404() {
        let r = ApiError::NotFound { kind: "initiative".into() }.into_response();
        assert_eq!(r.status(), StatusCode::NOT_FOUND);
    }

    /// `Gone` is structurally distinct from `NotFound` so the FE
    /// can render an "archived" copy instead of "not found". The
    /// dashboard plan-view endpoint surfaces this when the
    /// `plan_bundle_artifacts` row for an initiative was sweep-
    /// purged (`INV-DASHBOARD-INITIATIVE-PLAN-VISIBLE-01`).
    #[test]
    fn gone_yields_410_with_distinct_code() {
        let r = ApiError::Gone { kind: "plan".into() }.into_response();
        assert_eq!(r.status(), StatusCode::GONE);
    }

    #[test]
    fn gone_carries_distinct_code_string() {
        let (status, code) = ApiError::Gone { kind: "plan".into() }.status_and_code();
        assert_eq!(status, StatusCode::GONE);
        assert_eq!(code, "FAIL_DASHBOARD_GONE");
    }
}

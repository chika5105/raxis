//! Dashboard HTTP server lifecycle.
//!
//! The server is generic over `D: DashboardData` so production
//! (kernel-wired) and test (in-memory) deployments share the
//! same router code. State is held in [`AppState`] which is
//! `Clone` (cheap `Arc` clone) so axum's per-request state
//! cloning has zero allocation cost.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::async_trait;
use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::http::{header, StatusCode};
use axum::response::IntoResponse;
use axum::Router;
use tokio::net::TcpListener;
use tower_http::compression::CompressionLayer;
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;

use crate::auth::{build_auth_state, AuthState, DashboardRole, OperatorClaims};
use crate::config::DashboardConfig;
use crate::data::DashboardData;
use crate::error::ApiError;

/// Shared application state. Cheap `Arc` clone per request.
pub type AppState<D> = Arc<AppStateInner<D>>;

/// Inner state composed of `Arc`'d dependencies.
pub struct AppStateInner<D: DashboardData> {
    /// Operator data layer.
    pub data: Arc<D>,
    /// Auth (challenges + JWT signer + revocation set).
    pub auth: AuthState,
    /// Policy snapshot for the cert-enforcement re-check on
    /// every privileged request. Held as `Arc<dyn DashboardData>`
    /// already; the dashboard re-resolves operator entries through
    /// `data.lookup_operator_roles` rather than touching the
    /// policy bundle directly.
    pub config: DashboardConfig,
}

/// Dashboard server.
pub struct DashboardServer<D: DashboardData> {
    router: Router,
    listener: TcpListener,
    addr: SocketAddr,
    _state: AppState<D>,
}

impl<D: DashboardData> DashboardServer<D> {
    /// Bind a fresh dashboard server. `config.bind_address` and
    /// `config.bind_port` MUST be writable on the host.
    pub async fn bind(
        config: DashboardConfig,
        data: Arc<D>,
    ) -> Result<Self, BindError> {
        let auth = build_auth_state(&config)
            .map_err(|e| BindError::Auth(e.to_string()))?;
        let state: AppState<D> = Arc::new(AppStateInner {
            data: Arc::clone(&data),
            auth,
            config: config.clone(),
        });
        let router = build_router(Arc::clone(&state));
        let addr_str = format!("{}:{}", config.bind_address, config.bind_port);
        let listener = TcpListener::bind(&addr_str).await
            .map_err(|e| BindError::Bind {
                addr: addr_str.clone(),
                source: e,
            })?;
        let addr = listener.local_addr()
            .map_err(|e| BindError::Bind {
                addr: addr_str,
                source: e,
            })?;
        Ok(Self { router, listener, addr, _state: state })
    }

    /// Address the listener is bound to (useful for tests).
    pub fn local_addr(&self) -> SocketAddr { self.addr }

    /// Run the server until the supplied shutdown future
    /// completes. On graceful shutdown, in-flight requests are
    /// allowed to complete.
    pub async fn serve_with_shutdown(
        self,
        shutdown: impl std::future::Future<Output = ()> + Send + 'static,
    ) -> Result<(), std::io::Error> {
        axum::serve(self.listener, self.router)
            .with_graceful_shutdown(shutdown)
            .await
    }

    /// Run the server forever (until process exit).
    pub async fn serve(self) -> Result<(), std::io::Error> {
        axum::serve(self.listener, self.router).await
    }
}

/// Build the full router for the supplied state.
fn build_router<D: DashboardData>(state: AppState<D>) -> Router {
    use axum::routing::{get, post};
    use crate::routes::*;

    Router::new()
        // Auth (no JWT required).
        .route("/api/auth/challenge", get(auth::challenge::<D>))
        .route("/api/auth/verify",    post(auth::verify::<D>))
        .route("/api/auth/logout",    post(auth::logout::<D>))
        // Health (admin sees full, read sees sanitized).
        .route("/api/health",         get(health::health::<D>))
        // Initiatives.
        .route("/api/initiatives",                 get(initiatives::list::<D>))
        .route("/api/initiatives/:id",             get(initiatives::detail::<D>))
        .route("/api/initiatives/:id/dag",         get(initiatives::dag::<D>))
        .route("/api/initiatives/:id/tasks",       get(initiatives::tasks::<D>))
        // Tasks.
        .route("/api/tasks/:id",                   get(tasks::detail::<D>))
        .route("/api/tasks/:id/outputs",           get(tasks::outputs::<D>))
        // Sessions.
        .route("/api/sessions",                    get(sessions::list::<D>))
        .route("/api/sessions/:id",                get(sessions::detail::<D>))
        // Escalations.
        .route("/api/escalations",                 get(escalations::list::<D>))
        .route("/api/escalations/:id",             get(escalations::detail::<D>))
        // Audit + Inbox.
        .route("/api/audit",                       get(audit::list::<D>))
        .route("/api/inbox",                       get(inbox::list::<D>))
        // Policy.
        .route("/api/policy",                      get(policy::snapshot::<D>))
        .route("/api/policy/toml",                 get(policy::raw_toml::<D>))
        // Git worktrees.
        .route("/api/git/worktrees",                       get(git::list::<D>))
        .route("/api/git/worktrees/:name",                 get(git::detail::<D>))
        .route("/api/git/worktrees/:name/log",             get(git::log::<D>))
        .route("/api/git/worktrees/:name/diff",            get(git::diff_default::<D>))
        .route("/api/git/worktrees/:name/diff/:range",     get(git::diff_range::<D>))
        // Cross-cutting layers.
        .layer(TraceLayer::new_for_http())
        .layer(CorsLayer::permissive())
        .layer(CompressionLayer::new())
        .with_state(state)
}

/// Server bind / startup errors.
#[derive(Debug, thiserror::Error)]
pub enum BindError {
    /// TCP bind failed.
    #[error("dashboard bind failed at {addr}: {source}")]
    Bind {
        /// Address the bind was attempted on.
        addr: String,
        /// Underlying I/O error.
        source: std::io::Error,
    },
    /// Auth-state initialization failed (RNG failure, etc.).
    #[error("dashboard auth init failed: {0}")]
    Auth(String),
}

/// Handle returned by background-spawned dashboard tasks. Calling
/// [`ServerHandle::shutdown`] (consumed) signals the server's
/// `serve_with_shutdown` future to exit.
pub struct ServerHandle {
    shutdown_tx: tokio::sync::oneshot::Sender<()>,
    join: tokio::task::JoinHandle<Result<(), std::io::Error>>,
    addr: SocketAddr,
}

impl ServerHandle {
    /// Address the listener is bound to.
    pub fn local_addr(&self) -> SocketAddr { self.addr }

    /// Spawn the supplied server in the background. Returns a
    /// handle whose [`shutdown`](Self::shutdown) method drains
    /// the server gracefully.
    pub fn spawn<D: DashboardData>(server: DashboardServer<D>) -> Self {
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let addr = server.local_addr();
        let join = tokio::spawn(async move {
            server.serve_with_shutdown(async move {
                let _ = shutdown_rx.await;
            }).await
        });
        Self { shutdown_tx, join, addr }
    }

    /// Signal shutdown and await the serve task.
    pub async fn shutdown(self) -> Result<(), std::io::Error> {
        let _ = self.shutdown_tx.send(());
        match self.join.await {
            Ok(res) => res,
            Err(e) => Err(std::io::Error::other(format!("dashboard task panicked: {e}"))),
        }
    }
}

// ---------------------------------------------------------------------------
// JWT-bearer extractor: parses `Authorization: Bearer <jwt>`,
// verifies the JWT, checks revocation, and re-resolves the
// operator against the live data layer so role changes (or
// removed operators) take effect on the next request.
// ---------------------------------------------------------------------------

/// Authenticated operator extractor. Use as a parameter on any
/// route handler that requires a JWT. On failure produces an
/// `ApiError` (401/403) directly.
#[derive(Debug, Clone)]
pub struct AuthorizedOperator {
    /// Operator pubkey fingerprint (matches
    /// `OperatorEntry::pubkey_fingerprint`).
    pub fingerprint: String,
    /// Display name from the operator entry.
    pub display_name: String,
    /// Roles granted to the operator (re-resolved each request).
    pub roles: Vec<DashboardRole>,
    /// Underlying claims (for handlers that want `iat` / `exp`).
    pub claims: OperatorClaims,
}

impl AuthorizedOperator {
    /// `true` iff the operator currently holds the supplied role.
    pub fn has_role(&self, role: DashboardRole) -> bool {
        self.roles.iter().any(|r| *r == role)
    }
}

#[async_trait]
impl<D: DashboardData> FromRequestParts<AppState<D>> for AuthorizedOperator {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState<D>,
    ) -> Result<Self, Self::Rejection> {
        let header_val = parts
            .headers
            .get(header::AUTHORIZATION)
            .ok_or(ApiError::MissingAuth)?;
        let s = header_val
            .to_str()
            .map_err(|_| ApiError::MissingAuth)?
            .trim();
        let token = match s.strip_prefix("Bearer ") {
            Some(rest) => rest.trim(),
            None => return Err(ApiError::MissingAuth),
        };
        let claims = state.auth.jwt.verify(token)?;
        // Revocation check.
        let digest = crate::auth::JwtSigner::digest(token);
        if state.auth.revocations.is_revoked(&digest) {
            return Err(ApiError::JwtRevoked);
        }
        // Re-resolve through the data layer so an operator who
        // was removed since the JWT was minted gets bounced
        // immediately.
        let resolution = state.data.lookup_operator_roles(&claims.fingerprint)
            .ok_or(ApiError::UnknownOperator)?;
        Ok(AuthorizedOperator {
            fingerprint: claims.fingerprint.clone(),
            display_name: resolution.display_name,
            roles: resolution.roles,
            claims,
        })
    }
}

/// 404 handler used by axum for unknown routes — surfaces the
/// uniform error body.
#[allow(dead_code)]
async fn not_found() -> impl IntoResponse {
    ApiError::NotFound { kind: "endpoint".into() }
        .into_response()
        .into_response()
}

#[allow(dead_code)]
fn _status_assert() {
    // Compile-time assertion that we're using axum's
    // re-exported StatusCode (catches future type renames).
    let _ = StatusCode::OK;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data::InMemoryDashboardData;

    #[tokio::test]
    async fn server_binds_and_local_addr_works() {
        let cfg = DashboardConfig {
            enabled: true,
            bind_address: "127.0.0.1".into(),
            bind_port: 0,
            ..Default::default()
        };
        let data = InMemoryDashboardData::new();
        let server = DashboardServer::bind(cfg, Arc::clone(&data)).await.unwrap();
        let addr = server.local_addr();
        assert_eq!(addr.ip().to_string(), "127.0.0.1");
        assert!(addr.port() > 0);
        let handle = ServerHandle::spawn(server);
        handle.shutdown().await.unwrap();
    }
}

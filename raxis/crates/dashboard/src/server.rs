//! Dashboard HTTP server lifecycle.
//!
//! The server is generic over `D: DashboardData` so production
//! (kernel-wired) and test (in-memory) deployments share the
//! same router code. State is held in [`AppState`] which is
//! `Clone` (cheap `Arc` clone) so axum's per-request state
//! cloning has zero allocation cost.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::async_trait;
use axum::extract::{DefaultBodyLimit, FromRequestParts};
use axum::http::request::Parts;
use axum::http::{header, StatusCode};
use axum::response::IntoResponse;
use axum::Router;
use tokio::net::TcpListener;
use tower::limit::ConcurrencyLimitLayer;
use tower_http::compression::predicate::{NotForContentType, Predicate, SizeAbove};
use tower_http::compression::CompressionLayer;
use tower_http::cors::CorsLayer;
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;

// ---------------------------------------------------------------------------
// Phase 1 hardening — per-process bounds (see
// `crates/dashboard/src/server.rs::build_router`)
// ---------------------------------------------------------------------------

/// Per-handler wall-clock timeout for every JSON API endpoint.
/// The dashboard is meant to be operator-clicky, not long-poll —
/// any handler that does not finish in this window is buggy
/// (slow-loris client, runaway DB query, deadlocked git
/// subprocess, …) and we surface a 408 instead of holding
/// the connection forever. SSE handlers are exempt — see
/// [`build_router`].
const HANDLER_TIMEOUT: Duration = Duration::from_secs(30);

/// Maximum number of in-flight handler invocations (across all
/// routes, including SSE). Operator dashboards see at most a
/// handful of concurrent tabs per operator and ~5 outstanding
/// SSE streams; 256 leaves substantial headroom while keeping
/// the worst-case memory footprint bounded under e2e churn.
const MAX_INFLIGHT_REQUESTS: usize = 256;

/// Body size cap for tiny JSON requests (auth verify / logout —
/// payloads are <1 KiB in practice). Above this we 413 before
/// the handler runs to make the auth path immune to body-bomb
/// abuse.
const BODY_LIMIT_AUTH: usize = 4 * 1024;

/// Body size cap for the policy editor PUT
/// (`PUT /api/policy/toml`). 1 MiB is well above the largest
/// `policy.toml` we expect operators to author and well below
/// the kernel's working-set budget.
const BODY_LIMIT_POLICY: usize = 1024 * 1024;

/// Body size cap for everything else (GET endpoints in
/// practice, but defence-in-depth in case a future endpoint
/// adds a body without thinking about the limit).
const BODY_LIMIT_DEFAULT: usize = 16 * 1024;

use crate::auth::{build_auth_state, AuthState, DashboardRole, OperatorClaims};
use crate::config::DashboardConfig;
use crate::data::DashboardData;
use crate::error::ApiError;

#[cfg(test)]
pub(crate) const fn body_limit_auth_for_tests() -> usize { BODY_LIMIT_AUTH }
#[cfg(test)]
pub(crate) const fn body_limit_policy_for_tests() -> usize { BODY_LIMIT_POLICY }
#[cfg(test)]
pub(crate) const fn handler_timeout_for_tests() -> Duration { HANDLER_TIMEOUT }
#[cfg(test)]
pub(crate) const fn max_inflight_for_tests() -> usize { MAX_INFLIGHT_REQUESTS }

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
    /// Process-wide shutdown signal. Fires exactly once when the
    /// server's `serve_with_shutdown` future is signalled (or the
    /// server task is otherwise winding down). Long-poll handlers
    /// (SSE) `select!` on `shutdown.notified()` so they emit a
    /// final `kernel-shutdown` event and complete cleanly instead
    /// of leaving the browser hung waiting for a response.
    ///
    /// `Notify::notify_waiters` is fan-out-safe: every active
    /// SSE handler wakes exactly once. New subscribers that
    /// arrive AFTER the notify see the "closed" path through
    /// `is_shutdown_triggered`.
    pub shutdown: Arc<ShutdownSignal>,
}

/// One-shot, fan-out-safe shutdown signal handed to long-poll
/// handlers via `AppStateInner::shutdown`.
///
/// Wraps a `tokio::sync::Notify` plus a sticky `AtomicBool`:
/// `notify_waiters()` only wakes currently-waiting tasks, so a
/// handler that subscribes after shutdown was triggered would
/// otherwise miss the signal entirely. The sticky bit lets
/// `is_triggered` see the post-signal state without racing.
pub struct ShutdownSignal {
    notify: tokio::sync::Notify,
    triggered: std::sync::atomic::AtomicBool,
}

impl ShutdownSignal {
    /// Build a fresh, unsignalled shutdown.
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            notify: tokio::sync::Notify::new(),
            triggered: std::sync::atomic::AtomicBool::new(false),
        })
    }

    /// Trigger the shutdown. Idempotent — additional triggers
    /// are no-ops. Wakes every currently-waiting handler.
    pub fn trigger(&self) {
        self.triggered
            .store(true, std::sync::atomic::Ordering::SeqCst);
        self.notify.notify_waiters();
    }

    /// Wait for the shutdown to fire. Returns immediately when
    /// it has already fired (sticky bit).
    pub async fn notified(&self) {
        if self.triggered.load(std::sync::atomic::Ordering::SeqCst) {
            return;
        }
        self.notify.notified().await;
    }

    /// Synchronous probe used by handlers that need to know
    /// whether to emit a `kernel-shutdown` frame on attach.
    pub fn is_triggered(&self) -> bool {
        self.triggered.load(std::sync::atomic::Ordering::SeqCst)
    }
}

impl Default for ShutdownSignal {
    fn default() -> Self {
        Self {
            notify: tokio::sync::Notify::new(),
            triggered: std::sync::atomic::AtomicBool::new(false),
        }
    }
}

/// Dashboard server.
pub struct DashboardServer<D: DashboardData> {
    router: Router,
    listener: TcpListener,
    addr: SocketAddr,
    _state: AppState<D>,
    shutdown: Arc<ShutdownSignal>,
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
        let shutdown = ShutdownSignal::new();
        let state: AppState<D> = Arc::new(AppStateInner {
            data: Arc::clone(&data),
            auth,
            config: config.clone(),
            shutdown: Arc::clone(&shutdown),
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
        Ok(Self { router, listener, addr, _state: state, shutdown })
    }

    /// Address the listener is bound to (useful for tests).
    pub fn local_addr(&self) -> SocketAddr { self.addr }

    /// Shutdown signal handle (cloneable). Triggering this
    /// directly is equivalent to triggering the future passed to
    /// [`Self::serve_with_shutdown`]; long-poll handlers wake on
    /// either path.
    pub fn shutdown_signal(&self) -> Arc<ShutdownSignal> {
        Arc::clone(&self.shutdown)
    }

    /// Run the server until the supplied shutdown future
    /// completes. On graceful shutdown, in-flight requests are
    /// allowed to complete; long-poll SSE handlers receive a
    /// `kernel-shutdown` sentinel event and close cleanly
    /// instead of being held open against a hyper drain that
    /// will never finish.
    pub async fn serve_with_shutdown(
        self,
        shutdown: impl std::future::Future<Output = ()> + Send + 'static,
    ) -> Result<(), std::io::Error> {
        let signal = Arc::clone(&self.shutdown);
        let combined_shutdown = async move {
            shutdown.await;
            signal.trigger();
        };
        axum::serve(self.listener, self.router)
            .with_graceful_shutdown(combined_shutdown)
            .await
    }

    /// Run the server forever (until process exit).
    pub async fn serve(self) -> Result<(), std::io::Error> {
        axum::serve(self.listener, self.router).await
    }
}

/// Build the full router for the supplied state. When
/// `state.config.static_dir` is `Some(_)` the bundle is mounted
/// as the fallback service so SPA client-side routes (e.g.
/// `/initiatives/init-abc`) load `index.html` and resolve in
/// the browser.
///
/// # Hardening (Phase 1)
///
/// Every JSON API endpoint is bounded by:
///
/// 1. A per-route **body size limit** ([`BODY_LIMIT_AUTH`],
///    [`BODY_LIMIT_POLICY`], [`BODY_LIMIT_DEFAULT`]). Oversize
///    requests get a 413 before the handler runs.
/// 2. A **request timeout** ([`HANDLER_TIMEOUT`]) applied via
///    `tower_http::timeout::TimeoutLayer`. A handler that runs
///    longer surfaces an HTTP 408 to the operator instead of
///    pinning a tokio task. **SSE endpoints are intentionally
///    exempt** — they are long-poll by design and rely on
///    `axum::response::sse::KeepAlive` for liveness.
/// 3. A **process-wide concurrency cap**
///    ([`MAX_INFLIGHT_REQUESTS`]) applied via
///    `tower::limit::ConcurrencyLimitLayer`. Once the cap is hit
///    new requests queue (or get 503 with the right inner
///    layer); we accept queueing to keep the kernel below its
///    file-descriptor / memory budget under e2e churn.
///
/// The SSE route is mounted in a sibling sub-router that
/// inherits the concurrency cap but skips the timeout layer.
/// SPA fallback (when `static_dir` is set) is added last so
/// `/api/*` routes never fall through to `ServeDir`.
fn build_router<D: DashboardData>(state: AppState<D>) -> Router {
    use axum::routing::{get, patch, post};
    use crate::routes::*;

    let static_dir = state.config.static_dir.clone();

    // ── Auth + write surface: tighter body limits ────────────────────────
    //
    // `auth/verify` and `auth/logout` carry tiny JSON payloads
    // (≤ ~1 KiB in practice — challenge hex + Ed25519 sig hex +
    // pubkey hex). Capping at `BODY_LIMIT_AUTH` makes the
    // unauthenticated surface immune to body-bomb abuse without
    // ever entering the JWT verifier.
    //
    // `policy/toml` PUT carries the full policy.toml; cap at
    // `BODY_LIMIT_POLICY` (1 MiB) — far above any realistic
    // operator policy and far below the kernel's working set.
    let api_router: Router<AppState<D>> = Router::new()
        // Auth (no JWT required).
        .route(
            "/api/auth/challenge",
            get(auth::challenge::<D>)
                // `MethodRouter::layer<L, NewError>` needs `NewError` to be
                // disambiguated since `http 1.4` added a new
                // `From<Infallible> for http::Error` impl. Pin to
                // `Infallible` so the router's error type is preserved.
                .layer::<_, Infallible>(DefaultBodyLimit::max(BODY_LIMIT_DEFAULT))
                .layer::<_, Infallible>(RequestBodyLimitLayer::new(BODY_LIMIT_DEFAULT)),
        )
        .route(
            "/api/auth/verify",
            post(auth::verify::<D>)
                .layer::<_, Infallible>(DefaultBodyLimit::max(BODY_LIMIT_AUTH))
                .layer::<_, Infallible>(RequestBodyLimitLayer::new(BODY_LIMIT_AUTH)),
        )
        .route(
            "/api/auth/logout",
            post(auth::logout::<D>)
                .layer::<_, Infallible>(DefaultBodyLimit::max(BODY_LIMIT_AUTH))
                .layer::<_, Infallible>(RequestBodyLimitLayer::new(BODY_LIMIT_AUTH)),
        )
        // Health (admin sees full, read sees sanitized).
        .route("/api/health",             get(health::health::<D>))
        .route("/api/health/subsystems",  get(health::subsystems::<D>))
        // Initiatives.
        .route("/api/initiatives",                 get(initiatives::list::<D>))
        .route("/api/initiatives/:id",             get(initiatives::detail::<D>))
        .route("/api/initiatives/:id/dag",         get(initiatives::dag::<D>))
        .route("/api/initiatives/:id/tasks",       get(initiatives::tasks::<D>))
        // Original submitted plan TOML — INV-DASHBOARD-
        // INITIATIVE-PLAN-VISIBLE-01. Read-role suffices; the
        // handler emits a 60s `Cache-Control: private` header
        // for approved plans and `no-store` for pending ones.
        .route("/api/initiatives/:id/plan",        get(initiatives::plan::<D>))
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
        .route("/api/audit/chain-status",          get(audit::chain_status::<D>))
        .route("/api/inbox",                       get(inbox::list::<D>))
        // Notifications.
        .route("/api/notifications",               get(notifications::list::<D>))
        .route("/api/notifications/unread-count",  get(notifications::unread_count::<D>))
        .route("/api/notifications/mark-all-read", post(notifications::mark_all_read::<D>))
        .route("/api/notifications/:id/read",      patch(notifications::mark_read::<D>))
        // Policy.
        .route("/api/policy",                      get(policy::snapshot::<D>))
        .route(
            "/api/policy/toml",
            get(policy::raw_toml::<D>).put(
                policy::update_toml::<D>
            )
            .layer::<_, Infallible>(DefaultBodyLimit::max(BODY_LIMIT_POLICY))
            .layer::<_, Infallible>(RequestBodyLimitLayer::new(BODY_LIMIT_POLICY)),
        )
        // Git worktrees.
        .route("/api/git/worktrees",                       get(git::list::<D>))
        .route("/api/git/worktrees/:name",                 get(git::detail::<D>))
        .route("/api/git/worktrees/:name/log",             get(git::log::<D>))
        .route("/api/git/worktrees/:name/diff",            get(git::diff_default::<D>))
        .route("/api/git/worktrees/:name/diff/:range",     get(git::diff_range::<D>))
        // Repo browsing — directory tree + file content under
        // the worktree root, both subject to the
        // path-allowlist + symlink-escape sandbox in
        // `KernelDashboardData::worktree_{tree,file}`.
        .route("/api/git/worktrees/:name/tree",            get(git::tree::<D>))
        .route("/api/git/worktrees/:name/file",            get(git::file::<D>))
        // Per-handler wall-clock timeout. Applies to the
        // sub-router only so the SSE long-poll handler is
        // exempt (see the sibling sub-router below).
        .layer(TimeoutLayer::new(HANDLER_TIMEOUT));

    // ── SSE sub-router (no timeout layer — see HANDLER_TIMEOUT) ──────────
    //
    // Long-poll endpoints rely on
    // `axum::response::sse::KeepAlive` for liveness; wrapping
    // them in TimeoutLayer would force-close every SSE
    // connection after `HANDLER_TIMEOUT` seconds, which is
    // exactly the wrong behaviour for a stream the browser is
    // meant to hold open across the lifetime of a session.
    let sse_router: Router<AppState<D>> = Router::new()
        .route("/api/sessions/:id/stream",         get(sessions::stream::<D>));

    let mut router = api_router.merge(sse_router);

    // SPA fallback: any non-API route serves index.html so
    // React Router can resolve client-side routes. ServeDir's
    // fallback wires `not_found_service` to a handler that
    // serves `index.html` (so a deep link like
    // `/initiatives/init-abc` works on a fresh page load).
    if let Some(dir) = static_dir {
        use tower_http::services::ServeDir;
        let index = std::path::PathBuf::from(&dir).join("index.html");
        let serve = ServeDir::new(&dir).fallback(
            tower_http::services::ServeFile::new(index),
        );
        router = router.fallback_service(serve);
    }

    router
        // Cross-cutting layers.
        //
        // The compression predicate exempts text/event-stream so
        // the SSE handler in routes::sessions::stream is not
        // buffered for gzip — a buffered SSE stream looks like a
        // hung connection from the browser's point of view.
        //
        // The concurrency cap is the outermost meaningful layer
        // (TraceLayer wraps it for free) so it backpressures
        // BEFORE we allocate per-request handler state.
        .layer(ConcurrencyLimitLayer::new(MAX_INFLIGHT_REQUESTS))
        .layer(TraceLayer::new_for_http())
        .layer(CorsLayer::permissive())
        .layer(
            CompressionLayer::new().compress_when(
                SizeAbove::new(512)
                    .and(NotForContentType::const_new("text/event-stream")),
            ),
        )
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
        // Primary auth path: `Authorization: Bearer <jwt>` header.
        // Fallback (browser SSE only): `?token=<jwt>` query param,
        // because the EventSource API does not let JS attach
        // headers. The SSE handler is the only consumer in
        // practice; other endpoints continue to require the
        // header (the dashboard frontend always sets it).
        let token_owned: String = if let Some(h) = parts.headers.get(header::AUTHORIZATION) {
            let s = h
                .to_str()
                .map_err(|_| ApiError::MissingAuth)?
                .trim();
            match s.strip_prefix("Bearer ") {
                Some(rest) => rest.trim().to_owned(),
                None => return Err(ApiError::MissingAuth),
            }
        } else if let Some(qs) = parts.uri.query() {
            extract_query_token(qs).ok_or(ApiError::MissingAuth)?
        } else {
            return Err(ApiError::MissingAuth);
        };
        let token = token_owned.as_str();
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

/// Extract `token=<value>` from a URL query string. Used by the
/// SSE auth fallback (the browser EventSource API cannot attach
/// an `Authorization` header, so the JWT is passed via the
/// query string instead). Performs minimal percent-decoding so
/// JWTs with `=` padding round-trip.
fn extract_query_token(qs: &str) -> Option<String> {
    for pair in qs.split('&') {
        let mut it = pair.splitn(2, '=');
        let k = it.next()?;
        if k == "token" {
            let raw = it.next().unwrap_or("");
            // Manual percent-decode: only `%xx` escapes matter;
            // `+` is NOT decoded as space (JWTs are URL-safe
            // base64 + alphabet which doesn't include `+`, but
            // we keep verbatim for forward-compat).
            return Some(percent_decode(raw));
        }
    }
    None
}

fn percent_decode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or("");
            if let Ok(b) = u8::from_str_radix(hex, 16) {
                out.push(b as char);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
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

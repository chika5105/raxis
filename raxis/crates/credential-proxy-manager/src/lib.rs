//! `raxis-credential-proxy-manager` — kernel-side per-session
//! credential-proxy lifecycle.
//!
//! Normative reference: `specs/v2/credential-proxy.md §2`
//! ("How the Proxy Architecture Works") and §10 ("Lifecycle").
//!
//! ## Surface
//!
//! - [`CredentialProxyManager`] is constructed once at kernel boot
//!   alongside the credential backend and audit sink, and lives on
//!   `HandlerContext`.
//! - At session creation time the kernel calls
//!   [`CredentialProxyManager::start_for_session`] with the parsed
//!   [`raxis_plan_credentials::TaskCredentialDecl`] vector for the
//!   session's task. Each declaration is materialised into a real
//!   bound proxy listener (Postgres or HTTP — k8s rides the HTTP
//!   path with a fixed `bearer` `auth_mode`). The returned
//!   [`SessionProxyHandles`] carries the handles back to the caller.
//!   Per spec the kernel emits a `CredentialProxyStarted` audit event
//!   per bound proxy from inside `start_for_session`.
//! - At session teardown the kernel calls
//!   [`SessionProxyHandles::shutdown`]. The manager aborts the
//!   listeners, snapshots their stat counters, and emits one
//!   `CredentialProxyStopped` audit event per proxy carrying the
//!   counter snapshot.
//!
//! ## Why a kernel-side wrapper instead of inlining
//!
//! - Each proxy crate (`raxis-credential-proxy-postgres` and
//!   `raxis-credential-proxy-http`) is intentionally domain-agnostic
//!   — they have no dependency on `raxis-audit-tools` and no
//!   knowledge of `AuditEventKind::CredentialProxyStarted`. Owning
//!   the kernel-shaped audit semantics (event kinds + stat-snapshot
//!   translation) at this layer keeps that abstraction crisp.
//! - The kernel needs a single typed handle (`SessionProxyHandles`)
//!   that aborts every listener for a session in a single place. We
//!   want this to live behind a trait-shaped seam so future
//!   substrates (e.g. a remote credential-proxy gateway running on
//!   a separate host) plug in without rewriting the call sites.
//!
//! ## What this crate does NOT do
//!
//! - It does NOT own the in-VM transport plumbing (VirtioFS-mounted
//!   socket vs. loopback-mapped port). The bound proxy's
//!   `local_addr` is returned alongside the audit emission so the
//!   caller — which knows the substrate — can wire the address
//!   into the VM's kernel command line / kubeconfig generator /
//!   `DATABASE_URL` env-var injection.
//! - It does NOT spin up the credential backend. The kernel
//!   constructs that at boot and threads an `Arc<dyn CredentialBackend>`
//!   into the manager.
//! - It does NOT translate proxy-local `AuditEvent`s into kernel
//!   `AuditEventKind::DatabaseQueryExecuted` / `HttpProxyRequestExecuted`
//!   yet. That translation is a thin wrapper that lands when the
//!   proxy crates expose an `AuditChannel` callback parameter (a
//!   followup); for now the kernel only emits the lifecycle pair
//!   (`Started` + `Stopped`).

#![deny(unsafe_code)]
#![warn(missing_docs)]

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;

use raxis_audit_tools::{AuditEventKind, AuditSink};
use raxis_credentials::CredentialBackend;
use raxis_plan_credentials::{
    HttpAuthMode, HttpRestrictions, PostgresRestrictions, ProxyDecl, TaskCredentialDecl,
};

use raxis_credential_proxy_http::{
    AuthMode as HttpAuthModeImpl, HttpProxy, OwnedConsumer as HttpOwnedConsumer,
    ProxyConfig as HttpProxyConfig, ProxyError as HttpProxyError, ProxyStats as HttpProxyStats,
    Restrictions as HttpProxyRestrictions,
};
use raxis_credential_proxy_postgres::{
    OwnedConsumer as PgOwnedConsumer, PostgresProxy, ProxyConfig as PgProxyConfig,
    ProxyError as PgProxyError, ProxyStats as PgProxyStats,
    Restrictions as PgProxyRestrictions,
};

/// Errors surfaced by the manager.
#[derive(Debug, thiserror::Error)]
pub enum ManagerError {
    /// The plan declared a `proxy_type` the manager does not yet
    /// implement. Carries the literal proxy_type string from
    /// `raxis_plan_credentials::ProxyDecl::Unknown`.
    #[error("unknown or not-yet-implemented proxy type for credential `{credential_name}`")]
    UnknownProxyType {
        /// Policy-declared credential name from the plan.
        credential_name: String,
    },

    /// Postgres proxy failed to bind / start.
    #[error("postgres proxy bind failed for `{credential_name}`: {source}")]
    PostgresBind {
        /// Credential name whose proxy bind failed.
        credential_name: String,
        /// Source error from the postgres-proxy crate.
        #[source]
        source: PgProxyError,
    },

    /// HTTP proxy failed to bind / start.
    #[error("http proxy bind failed for `{credential_name}`: {source}")]
    HttpBind {
        /// Credential name whose proxy bind failed.
        credential_name: String,
        /// Source error from the http-proxy crate.
        #[source]
        source: HttpProxyError,
    },

    /// `local_addr()` on a freshly-bound listener failed (very rare;
    /// signals a race against listener shutdown, or that the OS lost
    /// our binding mid-construction).
    #[error("failed to read local_addr for `{credential_name}`: {source}")]
    LocalAddr {
        /// Credential name whose proxy bind failed.
        credential_name: String,
        /// Source IO error.
        #[source]
        source: std::io::Error,
    },

    /// Audit emission failed. The manager treats audit failure as
    /// fatal per `kernel-store.md §2.5.2` — the caller (kernel
    /// session-spawn path) MUST surface this and abort the session
    /// rather than continue with an unaudited proxy.
    #[error("audit emission failed: {0}")]
    Audit(String),
}

/// String name of the proxy type — embedded into the audit events.
fn proxy_type_str(decl: &ProxyDecl) -> &'static str {
    match decl {
        ProxyDecl::Postgres { .. } => "postgres",
        ProxyDecl::Http { .. } => "http",
        ProxyDecl::K8s { .. } => "k8s",
        ProxyDecl::Unknown => "unknown",
    }
}

/// One bound proxy listener belonging to a session. Carries the
/// `JoinHandle` of the accept loop so [`SessionProxyHandles::shutdown`]
/// can abort the listener cleanly. The address is the loopback
/// address the agent VM will dial.
struct ActiveProxy {
    /// Free-form proxy_type label ("postgres" / "http" / "k8s") —
    /// reused in the matching `CredentialProxyStopped` event.
    proxy_type: &'static str,
    /// Policy-declared credential name (never the value).
    credential_name: String,
    /// Env-var name the agent VM gets injected with (e.g.
    /// `DATABASE_URL`, `KUBECONFIG`). Reused by
    /// [`SessionProxyHandles::loopback_env`].
    mount_as: String,
    /// Loopback addr the listener is bound to.
    addr: SocketAddr,
    /// Counters snapshot handle; outlives the listener task.
    stats: ProxyStatsHandle,
    /// Aborts the accept loop.
    join: tokio::task::JoinHandle<()>,
}

/// Per-proxy counter snapshot view. Held by [`ActiveProxy`] so we
/// can serialise the final counters into `CredentialProxyStopped`
/// after the listener task has been aborted.
enum ProxyStatsHandle {
    Postgres(Arc<PgProxyStats>),
    Http(Arc<HttpProxyStats>),
}

impl ProxyStatsHandle {
    fn snapshot_counters(&self) -> StoppedCounters {
        match self {
            ProxyStatsHandle::Postgres(s) => {
                let snap = s.snapshot();
                StoppedCounters {
                    connections_served: snap.connections_served,
                    forwards_completed: snap.queries_audited.saturating_sub(snap.queries_blocked),
                    forwards_blocked:   snap.queries_blocked,
                }
            }
            ProxyStatsHandle::Http(s) => {
                let snap = s.snapshot();
                StoppedCounters {
                    connections_served: snap.connections_served,
                    forwards_completed: snap.requests_forwarded,
                    forwards_blocked:   snap.requests_blocked,
                }
            }
        }
    }
}

/// Plain-data view of the counter columns that get serialised into
/// `CredentialProxyStopped`. Public so tests can read a
/// post-shutdown snapshot via [`ShutdownReport`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StoppedCounters {
    /// Total accepted connections.
    pub connections_served: u32,
    /// Successfully forwarded queries / requests.
    pub forwards_completed: u32,
    /// Forwards rejected by `Restrictions`.
    pub forwards_blocked:   u32,
}

/// Per-proxy summary from a successful bind. Returned to the caller
/// so the kernel session-spawn path can wire the loopback addresses
/// into the VM's environment.
#[derive(Debug, Clone)]
pub struct StartedProxy {
    /// `proxy_type` string — `postgres` / `http` / `k8s`.
    pub proxy_type: &'static str,
    /// Policy-declared credential name (never the value).
    pub credential_name: String,
    /// `mount_as` env-var name from the plan TOML
    /// (e.g. `DATABASE_URL`, `KUBECONFIG`).
    pub mount_as: String,
    /// Loopback address the listener is bound to.
    pub addr: SocketAddr,
}

/// Per-proxy summary from a successful shutdown. Returned to the
/// caller (and to tests) so the kernel session-teardown path can
/// log/observe the final counters.
#[derive(Debug, Clone)]
pub struct StoppedProxy {
    /// `proxy_type` string — `postgres` / `http` / `k8s`.
    pub proxy_type: &'static str,
    /// Policy-declared credential name (never the value).
    pub credential_name: String,
    /// Final counter snapshot.
    pub counters: StoppedCounters,
}

/// Per-session bundle of bound proxy listeners.
///
/// The owning kernel handler holds this for the lifetime of the
/// session and calls [`Self::shutdown`] from the teardown path.
/// `Drop` aborts every listener task even if `shutdown` is not
/// called — this is the failsafe for unexpected handler panics. In
/// the `Drop` path the manager cannot emit audit events synchronously
/// (it has no async runtime context guaranteed), so the spec-required
/// `CredentialProxyStopped` event is emitted only via `shutdown`.
/// Tests assert that callers always use `shutdown`.
pub struct SessionProxyHandles {
    session_id: String,
    proxies:    Vec<ActiveProxy>,
    audit:      Arc<dyn AuditSink>,
    /// Once `shutdown` has run, the destructor must NOT emit a
    /// duplicate stop event.
    drained:    bool,
}

impl SessionProxyHandles {
    /// Number of bound proxies in this session.
    pub fn len(&self) -> usize { self.proxies.len() }

    /// Whether the session has zero declared proxies.
    pub fn is_empty(&self) -> bool { self.proxies.is_empty() }

    /// The session id this bundle belongs to. Useful for tests and
    /// for correlation in the kernel's session map.
    pub fn session_id(&self) -> &str { &self.session_id }

    /// Per-proxy summary of every successful bind, in declaration
    /// order. Useful for the kernel session-spawn path which needs
    /// to log each addr or build a per-substrate kubeconfig.
    pub fn started_summaries(&self) -> Vec<StartedProxy> {
        self.proxies
            .iter()
            .map(|p| StartedProxy {
                proxy_type:      p.proxy_type,
                credential_name: p.credential_name.clone(),
                mount_as:        p.mount_as.clone(),
                addr:            p.addr,
            })
            .collect()
    }

    /// Mapping from `mount_as` env-var name → loopback URL string
    /// the agent's environment should bind to. The kernel
    /// session-spawn path consumes this to fill `env: {
    /// DATABASE_URL: ..., ... }` in the VM spec.
    ///
    /// The URL shape is per-proxy: postgres proxies emit
    /// `postgresql://raxis@<host>:<port>/`, HTTP/k8s proxies emit
    /// `http://<host>:<port>`. The URL is the surface the agent
    /// dials; the credential VALUE is never embedded — the proxy
    /// injects auth on the wire.
    pub fn loopback_env(&self) -> BTreeMap<String, String> {
        let mut out = BTreeMap::new();
        for p in &self.proxies {
            let url = match p.proxy_type {
                "postgres" => format!(
                    "postgresql://raxis@{}/",
                    p.addr,
                ),
                _ => format!("http://{}", p.addr),
            };
            out.insert(p.mount_as.clone(), url);
        }
        out
    }

    /// Shut down every listener and emit one
    /// `CredentialProxyStopped` audit event per proxy. Returns the
    /// final counter snapshot per proxy for the caller to log /
    /// retain.
    pub fn shutdown(mut self) -> Result<ShutdownReport, ManagerError> {
        let mut stopped = Vec::with_capacity(self.proxies.len());
        for p in self.proxies.drain(..) {
            // Abort first so the listener stops accepting before we
            // snapshot. The accept loop returns Ok(stream) and then
            // hands off to the per-connection task; aborting the
            // accept loop drops the listener but leaves in-flight
            // per-connection tasks running. The kernel session
            // teardown code is responsible for waiting for those
            // (or letting tokio shut them down on runtime drop).
            p.join.abort();
            let counters = p.stats.snapshot_counters();
            self.audit.emit(
                AuditEventKind::CredentialProxyStopped {
                    session_id:         self.session_id.clone(),
                    proxy_type:         p.proxy_type.to_owned(),
                    credential_name:    p.credential_name.clone(),
                    connections_served: counters.connections_served,
                    forwards_completed: counters.forwards_completed,
                    forwards_blocked:   counters.forwards_blocked,
                },
                Some(&self.session_id),
                None,
                None,
            )
            .map_err(|e| ManagerError::Audit(e.to_string()))?;
            stopped.push(StoppedProxy {
                proxy_type:      p.proxy_type,
                credential_name: p.credential_name,
                counters,
            });
        }
        self.drained = true;
        Ok(ShutdownReport { stopped })
    }
}

impl Drop for SessionProxyHandles {
    fn drop(&mut self) {
        if !self.drained {
            // Abort the listeners as a failsafe so a forgotten
            // shutdown can't leave a hanging accept loop.
            for p in &self.proxies {
                p.join.abort();
            }
            tracing::warn!(
                session_id = %self.session_id,
                proxy_count = self.proxies.len(),
                "SessionProxyHandles dropped without explicit shutdown(); \
                 listeners aborted but CredentialProxyStopped audit events \
                 were NOT emitted — fix the call site to use shutdown()",
            );
        }
    }
}

/// Bundle returned from [`SessionProxyHandles::shutdown`].
#[derive(Debug, Clone)]
pub struct ShutdownReport {
    /// One [`StoppedProxy`] per proxy that was active at shutdown.
    pub stopped: Vec<StoppedProxy>,
}

/// Kernel-side per-session credential-proxy lifecycle owner.
///
/// Construct one of these at boot and clone its `Arc` into
/// `HandlerContext`. The manager itself is `Send + Sync` and stateless
/// across sessions — it just holds shared handles to the credential
/// backend and audit sink.
pub struct CredentialProxyManager {
    backend: Arc<dyn CredentialBackend>,
    audit:   Arc<dyn AuditSink>,
}

impl CredentialProxyManager {
    /// Construct a manager bound to a credential backend and audit
    /// sink. Both are typically the kernel's production wiring.
    pub fn new(
        backend: Arc<dyn CredentialBackend>,
        audit:   Arc<dyn AuditSink>,
    ) -> Self {
        Self { backend, audit }
    }

    /// Bind every credential proxy declared for a task and emit one
    /// `CredentialProxyStarted` audit event per proxy.
    ///
    /// `session_id` must be the session id of the agent VM the
    /// proxy is provisioned for. `task_id` is included only for
    /// audit linkage (the spec-mandated `task_id` field on the audit
    /// record).
    pub async fn start_for_session(
        &self,
        session_id: &str,
        task_id:    &str,
        decls:      &[TaskCredentialDecl],
    ) -> Result<SessionProxyHandles, ManagerError> {
        let mut proxies = Vec::with_capacity(decls.len());

        for decl in decls {
            let proxy_type = proxy_type_str(&decl.proxy);
            let credential_name = decl.name.as_str().to_owned();

            let active = match &decl.proxy {
                ProxyDecl::Postgres { restrictions } => {
                    self.bind_postgres(
                        session_id,
                        task_id,
                        &decl.name,
                        &decl.mount_as,
                        restrictions,
                    )
                    .await?
                }
                ProxyDecl::Http { auth_mode, upstream_url, restrictions } => {
                    self.bind_http(
                        session_id,
                        task_id,
                        &decl.name,
                        &decl.mount_as,
                        auth_mode,
                        upstream_url,
                        restrictions,
                    )
                    .await?
                }
                ProxyDecl::K8s { restrictions } => {
                    // k8s rides the HTTP proxy with a fixed Bearer
                    // mode. The upstream URL is taken from the
                    // resolved kubeconfig at proxy-bind time. The
                    // MVP defers the kubeconfig.server lookup
                    // (which would require shelling out to read
                    // the credential body and YAML-parse it); for
                    // now the manager refuses K8s proxies with a
                    // clear error so the kernel session-spawn path
                    // can fail fast and the operator can switch the
                    // declaration to `proxy_type = "http"`.
                    let _ = restrictions;
                    return Err(ManagerError::UnknownProxyType {
                        credential_name,
                    });
                }
                ProxyDecl::Unknown => {
                    return Err(ManagerError::UnknownProxyType {
                        credential_name,
                    });
                }
            };

            self.audit.emit(
                AuditEventKind::CredentialProxyStarted {
                    session_id:      session_id.to_owned(),
                    proxy_type:      proxy_type.to_owned(),
                    credential_name: credential_name.clone(),
                    addr:            active.addr.to_string(),
                },
                Some(session_id),
                Some(task_id),
                None,
            )
            .map_err(|e| ManagerError::Audit(e.to_string()))?;

            proxies.push(active);
        }

        Ok(SessionProxyHandles {
            session_id: session_id.to_owned(),
            proxies,
            audit:      Arc::clone(&self.audit),
            drained:    false,
        })
    }

    async fn bind_postgres(
        &self,
        session_id: &str,
        _task_id:   &str,
        name:       &raxis_credentials::CredentialName,
        mount_as:   &str,
        restrictions: &PostgresRestrictions,
    ) -> Result<ActiveProxy, ManagerError> {
        let cfg = PgProxyConfig {
            listen_addr:     "127.0.0.1:0".to_owned(),
            credential_name: name.clone(),
            consumer:        PgOwnedConsumer::new(
                "session",
                session_id.to_owned(),
            ),
            restrictions: PgProxyRestrictions {
                allow_only_select: restrictions.allow_only_select,
            },
        };
        let proxy = PostgresProxy::bind(Arc::clone(&self.backend), cfg)
            .await
            .map_err(|source| ManagerError::PostgresBind {
                credential_name: name.as_str().to_owned(),
                source,
            })?;
        let addr = proxy.local_addr().map_err(|source| ManagerError::LocalAddr {
            credential_name: name.as_str().to_owned(),
            source,
        })?;
        let stats_handle = proxy.stats_handle();
        let join = tokio::spawn(async move {
            proxy.serve().await;
        });
        Ok(ActiveProxy {
            proxy_type:      "postgres",
            credential_name: name.as_str().to_owned(),
            mount_as:        mount_as.to_owned(),
            addr,
            stats:           ProxyStatsHandle::Postgres(stats_handle),
            join,
        })
    }

    #[allow(clippy::too_many_arguments)]
    async fn bind_http(
        &self,
        session_id: &str,
        _task_id:   &str,
        name:       &raxis_credentials::CredentialName,
        mount_as:   &str,
        auth_mode:  &HttpAuthMode,
        upstream_url: &str,
        restrictions: &HttpRestrictions,
    ) -> Result<ActiveProxy, ManagerError> {
        let cfg = HttpProxyConfig {
            listen_addr:     "127.0.0.1:0".to_owned(),
            upstream_url:    upstream_url.to_owned(),
            credential_name: name.clone(),
            auth_mode: match auth_mode {
                HttpAuthMode::Bearer => HttpAuthModeImpl::Bearer,
                HttpAuthMode::Basic { user } => HttpAuthModeImpl::Basic {
                    user: user.clone(),
                },
            },
            consumer:     HttpOwnedConsumer::new(
                "session",
                session_id.to_owned(),
            ),
            restrictions: HttpProxyRestrictions {
                allowed_methods:       restrictions.allowed_methods.clone(),
                allowed_path_prefixes: restrictions.allowed_path_prefixes.clone(),
            },
        };
        let proxy = HttpProxy::bind(Arc::clone(&self.backend), cfg)
            .await
            .map_err(|source| ManagerError::HttpBind {
                credential_name: name.as_str().to_owned(),
                source,
            })?;
        let addr = proxy.local_addr().map_err(|source| ManagerError::LocalAddr {
            credential_name: name.as_str().to_owned(),
            source,
        })?;
        let stats_handle = proxy.stats_handle();
        let join = tokio::spawn(async move {
            proxy.serve().await;
        });
        Ok(ActiveProxy {
            proxy_type:      "http",
            credential_name: name.as_str().to_owned(),
            mount_as:        mount_as.to_owned(),
            addr,
            stats:           ProxyStatsHandle::Http(stats_handle),
            join,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use raxis_credentials::CredentialName;
    use raxis_credentials_file::FileCredentialBackend;
    use raxis_test_support::FakeAuditSink;

    fn build_manager() -> (CredentialProxyManager, Arc<FakeAuditSink>, tempfile::TempDir) {
        let tmp = tempfile::tempdir().expect("tmpdir");
        // Provision a single credential the postgres bind path can
        // resolve. The body shape doesn't matter for `start_for_session`
        // — we only resolve credentials lazily on the first
        // connection — but `FileCredentialBackend` requires the file
        // to exist for `exists` checks down the road.
        let creds_dir = tmp.path().join("credentials");
        std::fs::create_dir_all(&creds_dir).unwrap();
        std::fs::write(
            creds_dir.join("pg-staging.url"),
            b"postgresql://raxis@127.0.0.1:5432/test",
        )
        .unwrap();
        std::fs::write(
            creds_dir.join("api-key.token"),
            b"sk-test-token-123",
        )
        .unwrap();
        let backend: Arc<dyn CredentialBackend> =
            Arc::new(FileCredentialBackend::open_without_uid_check(tmp.path()));
        let audit = Arc::new(FakeAuditSink::new());
        let mgr = CredentialProxyManager::new(
            Arc::clone(&backend),
            Arc::clone(&audit) as Arc<dyn AuditSink>,
        );
        (mgr, audit, tmp)
    }

    #[tokio::test]
    async fn start_then_shutdown_emits_paired_audit_events_for_postgres() {
        let (mgr, audit, _tmp) = build_manager();

        let decls = vec![TaskCredentialDecl {
            name:     CredentialName::new("pg-staging"),
            mount_as: "DATABASE_URL".to_owned(),
            proxy:    ProxyDecl::Postgres {
                restrictions: PostgresRestrictions { allow_only_select: false },
            },
        }];

        let handles = mgr
            .start_for_session("sess-1", "task-1", &decls)
            .await
            .expect("start");
        assert_eq!(handles.len(), 1);
        assert_eq!(handles.session_id(), "sess-1");

        let summaries = handles.started_summaries();
        assert_eq!(summaries.len(), 1);
        assert_eq!(summaries[0].proxy_type, "postgres");
        assert_eq!(summaries[0].credential_name, "pg-staging");
        assert_eq!(summaries[0].mount_as, "DATABASE_URL");

        let env = handles.loopback_env();
        assert_eq!(env.len(), 1);
        let database_url = env.get("DATABASE_URL").expect("env var present");
        assert!(
            database_url.starts_with("postgresql://raxis@127.0.0.1:"),
            "expected loopback postgres URL, got {database_url}",
        );

        let started_events: Vec<_> = audit.events()
            .into_iter()
            .filter(|e| e.kind.as_str() == "CredentialProxyStarted")
            .collect();
        assert_eq!(started_events.len(), 1, "exactly one Started event");
        assert_eq!(started_events[0].session_id.as_deref(), Some("sess-1"));
        assert_eq!(started_events[0].task_id.as_deref(),    Some("task-1"));

        let report = handles.shutdown().expect("shutdown");
        assert_eq!(report.stopped.len(), 1);
        assert_eq!(report.stopped[0].proxy_type, "postgres");

        let stopped_events: Vec<_> = audit.events()
            .into_iter()
            .filter(|e| e.kind.as_str() == "CredentialProxyStopped")
            .collect();
        assert_eq!(stopped_events.len(), 1, "exactly one Stopped event");
        assert_eq!(stopped_events[0].session_id.as_deref(), Some("sess-1"));
    }

    #[tokio::test]
    async fn start_then_shutdown_emits_paired_audit_events_for_http() {
        let (mgr, audit, _tmp) = build_manager();

        let decls = vec![TaskCredentialDecl {
            name:     CredentialName::new("api-key"),
            mount_as: "API_BASE_URL".to_owned(),
            proxy:    ProxyDecl::Http {
                auth_mode:    HttpAuthMode::Bearer,
                upstream_url: "https://api.example.com/v1".to_owned(),
                restrictions: HttpRestrictions::default(),
            },
        }];

        let handles = mgr
            .start_for_session("sess-2", "task-2", &decls)
            .await
            .expect("start");
        assert_eq!(handles.len(), 1);

        let started_events: Vec<_> = audit.events()
            .into_iter()
            .filter(|e| e.kind.as_str() == "CredentialProxyStarted")
            .collect();
        assert_eq!(started_events.len(), 1);

        let report = handles.shutdown().expect("shutdown");
        assert_eq!(report.stopped.len(), 1);
        assert_eq!(report.stopped[0].proxy_type, "http");
    }

    #[tokio::test]
    async fn unknown_proxy_type_is_rejected_before_audit_emission() {
        let (mgr, audit, _tmp) = build_manager();

        let decls = vec![TaskCredentialDecl {
            name:     CredentialName::new("smtp-creds"),
            mount_as: "SMTP_URL".to_owned(),
            proxy:    ProxyDecl::Unknown,
        }];

        let result = mgr.start_for_session("sess-3", "task-3", &decls).await;
        let err = result.err().expect("start should fail for unknown proxy");
        match err {
            ManagerError::UnknownProxyType { credential_name } => {
                assert_eq!(credential_name, "smtp-creds");
            }
            other => panic!("unexpected error: {other:?}"),
        }
        // No partial audit emission when the very first decl is
        // unknown — we error out before the audit call.
        let started_events: Vec<_> = audit.events()
            .into_iter()
            .filter(|e| e.kind.as_str() == "CredentialProxyStarted")
            .collect();
        assert!(started_events.is_empty());
    }

    #[tokio::test]
    async fn k8s_proxy_decl_is_rejected_pending_kubeconfig_resolution() {
        let (mgr, _audit, _tmp) = build_manager();

        let decls = vec![TaskCredentialDecl {
            name:     CredentialName::new("k8s-staging"),
            mount_as: "KUBECONFIG".to_owned(),
            proxy:    ProxyDecl::K8s {
                restrictions: HttpRestrictions::default(),
            },
        }];

        let err = mgr
            .start_for_session("sess-4", "task-4", &decls)
            .await
            .err()
            .expect("k8s should be rejected at MVP");
        assert!(matches!(err, ManagerError::UnknownProxyType { .. }));
    }

    #[tokio::test]
    async fn empty_decls_yields_empty_handles_and_no_audit_events() {
        let (mgr, audit, _tmp) = build_manager();

        let handles = mgr
            .start_for_session("sess-5", "task-5", &[])
            .await
            .expect("start with no decls");
        assert!(handles.is_empty());

        let report = handles.shutdown().expect("shutdown empty");
        assert!(report.stopped.is_empty());

        // No started/stopped events for an empty plan declaration.
        let cred_events: Vec<_> = audit.events()
            .into_iter()
            .filter(|e| e.kind.as_str().starts_with("CredentialProxy"))
            .collect();
        assert!(cred_events.is_empty());
    }

    #[tokio::test]
    async fn multiple_decls_bind_independently_in_declaration_order() {
        let (mgr, audit, _tmp) = build_manager();

        let decls = vec![
            TaskCredentialDecl {
                name:     CredentialName::new("pg-staging"),
                mount_as: "DATABASE_URL".to_owned(),
                proxy:    ProxyDecl::Postgres {
                    restrictions: PostgresRestrictions { allow_only_select: true },
                },
            },
            TaskCredentialDecl {
                name:     CredentialName::new("api-key"),
                mount_as: "API_BASE_URL".to_owned(),
                proxy:    ProxyDecl::Http {
                    auth_mode:    HttpAuthMode::Bearer,
                    upstream_url: "https://api.example.com/v1".to_owned(),
                    restrictions: HttpRestrictions::default(),
                },
            },
        ];

        let handles = mgr
            .start_for_session("sess-6", "task-6", &decls)
            .await
            .expect("multi-decl start");
        assert_eq!(handles.len(), 2);

        let started: Vec<&'static str> = audit.events()
            .into_iter()
            .filter(|e| e.kind.as_str() == "CredentialProxyStarted")
            .map(|e| e.kind.as_str())
            .collect();
        assert_eq!(started.len(), 2);

        let report = handles.shutdown().expect("multi-shutdown");
        assert_eq!(report.stopped.len(), 2);
        assert_eq!(report.stopped[0].proxy_type, "postgres");
        assert_eq!(report.stopped[1].proxy_type, "http");
    }
}

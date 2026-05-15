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
//!   bound proxy listener (Postgres, HTTP, k8s — which rides the
//!   HTTP path with a fixed `bearer` `auth_mode` — or SMTP). The
//!   returned [`SessionProxyHandles`] carries the handles back to
//!   the caller. Per spec the kernel emits a
//!   `CredentialProxyStarted` audit event per bound proxy from
//!   inside `start_for_session`.
//! - At session teardown the kernel calls
//!   [`SessionProxyHandles::shutdown`]. The manager aborts the
//!   listeners, snapshots their stat counters, and emits one
//!   `CredentialProxyStopped` audit event per proxy carrying the
//!   counter snapshot.
//!
//! ## Why a kernel-side wrapper instead of inlining
//!
//! - Each proxy crate (`raxis-credential-proxy-postgres`,
//!   `raxis-credential-proxy-http`, and
//!   `raxis-credential-proxy-smtp`) is intentionally
//!   domain-agnostic — they have no dependency on
//!   `raxis-audit-tools` and no knowledge of
//!   `AuditEventKind::CredentialProxyStarted`. Owning the
//!   kernel-shaped audit semantics (event kinds + stat-snapshot
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
//!
//! ## Per-event audit translation
//!
//! Each `bind_*` helper constructs a kernel-side adapter
//! (`PostgresKernelAuditAdapter`, `HttpKernelAuditAdapter`,
//! `SmtpKernelAuditAdapter`) that implements the matching proxy
//! crate's audit-channel trait (`PgAuditChannel`,
//! `HttpAuditChannel`, `EnvelopeAuditSink`). The adapter translates
//! every proxy-local `AuditEvent` / `EnvelopeAudit` into the kernel
//! `AuditEventKind::{DatabaseQueryExecuted, HttpProxyRequestExecuted,
//! SmtpMessageRelayed, SmtpMessageRejected}` and writes it through
//! the same `Arc<dyn AuditSink>` as every other audit event. This
//! is in addition to the lifecycle pair (`CredentialProxyStarted` /
//! `CredentialProxyStopped`) emitted by the manager itself, giving
//! the audit chain one entry per query / request / envelope on top
//! of the bracketing lifecycle events.
//!
//! ## K8s proxy (`proxy_type = "k8s"`)
//!
//! K8s rides the HTTP credential proxy with a fixed `auth_mode =
//! "bearer"`; the upstream URL is the `cluster.server` field from
//! the kubeconfig YAML the credential body holds. Per
//! `credential-proxy.md §3.1`, a kubeconfig declares the upstream
//! cluster and the bearer token (or other auth) the proxy injects.
//! The MVP implementation here parses the `server:` line from the
//! first `cluster:` block in the kubeconfig with a tiny
//! line-based extractor; full YAML compliance (anchors, multi-doc,
//! list-of-clusters by `current-context` selector) is a forthcoming
//! refinement that lands when the kubeconfig surface grows beyond
//! the V2 MVP one-cluster shape. The credential body MUST be
//! valid UTF-8 — opaque-byte kubeconfigs are rejected at bind
//! time.

#![deny(unsafe_code)]
#![warn(missing_docs)]

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;

use raxis_audit_tools::{AuditEventKind, AuditSink};
use raxis_credentials::CredentialBackend;
use raxis_plan_credentials::{
    AwsForwardingDecl, AwsRestrictions, AzureForwardingDecl, AzureRestrictions, GcpForwardingDecl,
    GcpRestrictions, HttpAuthMode, HttpRestrictions, MongodbRestrictions, MssqlRestrictions,
    MysqlRestrictions, PostgresRestrictions, ProxyDecl, RedisRestrictions, SmtpAuthMode,
    SmtpRestrictions, TaskCredentialDecl,
};

use raxis_credential_proxy_aws::{
    AuditChannel as AwsAuditChannel, AuditEvent as AwsAuditEvent, AwsProxy,
    ForwardingConfig as AwsForwardingConfig, OwnedConsumer as AwsOwnedConsumer,
    ProxyConfig as AwsProxyConfig, ProxyError as AwsProxyError, ProxyStats as AwsProxyStats,
    Restrictions as AwsProxyRestrictions, StsCacheValue as AwsStsCacheValue,
};
use raxis_credential_proxy_azure::{
    AuditChannel as AzureAuditChannel, AuditEvent as AzureAuditEvent, AzureCacheValue, AzureProxy,
    ForwardingConfig as AzureForwardingConfig, OwnedConsumer as AzureOwnedConsumer,
    ProxyConfig as AzureProxyConfig, ProxyError as AzureProxyError, ProxyStats as AzureProxyStats,
    Restrictions as AzureProxyRestrictions,
};
use raxis_credential_proxy_cloud_shared::{CloudHttpClient, CloudUpstreamHost, TokenCache};
use raxis_credential_proxy_gcp::{
    AuditChannel as GcpAuditChannel, AuditEvent as GcpAuditEvent,
    ForwardingConfig as GcpForwardingConfig, GcpCacheValue, GcpProxy,
    OwnedConsumer as GcpOwnedConsumer, ProxyConfig as GcpProxyConfig, ProxyError as GcpProxyError,
    ProxyStats as GcpProxyStats, Restrictions as GcpProxyRestrictions,
};
use raxis_credential_proxy_http::{
    AuditChannel as HttpAuditChannel, AuditEvent as HttpAuditEvent, AuthMode as HttpAuthModeImpl,
    HttpProxy, OwnedConsumer as HttpOwnedConsumer, ProxyConfig as HttpProxyConfig,
    ProxyError as HttpProxyError, ProxyStats as HttpProxyStats,
    Restrictions as HttpProxyRestrictions,
};
use raxis_credential_proxy_mongodb::{
    AuditChannel as MongodbAuditChannel, AuditEvent as MongodbAuditEvent, MongodbProxy,
    OwnedConsumer as MongodbOwnedConsumer, ProxyConfig as MongodbProxyConfig,
    ProxyError as MongodbProxyError, ProxyStats as MongodbProxyStats,
    Restrictions as MongodbProxyRestrictions,
};
use raxis_credential_proxy_mssql::{
    AuditChannel as MssqlAuditChannel, AuditEvent as MssqlAuditEvent, MssqlProxy,
    OwnedConsumer as MssqlOwnedConsumer, ProxyConfig as MssqlProxyConfig,
    ProxyError as MssqlProxyError, ProxyStats as MssqlProxyStats,
    Restrictions as MssqlProxyRestrictions,
};
use raxis_credential_proxy_mysql::{
    AuditChannel as MysqlAuditChannel, AuditEvent as MysqlAuditEvent, MysqlProxy,
    OwnedConsumer as MysqlOwnedConsumer, ProxyConfig as MysqlProxyConfig,
    ProxyError as MysqlProxyError, ProxyStats as MysqlProxyStats,
    Restrictions as MysqlProxyRestrictions,
};
use raxis_credential_proxy_postgres::{
    AuditChannel as PgAuditChannel, AuditEvent as PgAuditEvent, OwnedConsumer as PgOwnedConsumer,
    PostgresProxy, ProxyConfig as PgProxyConfig, ProxyError as PgProxyError,
    ProxyStats as PgProxyStats, Restrictions as PgProxyRestrictions,
};
use raxis_credential_proxy_redis::{
    AuditChannel as RedisAuditChannel, AuditEvent as RedisAuditEvent,
    OwnedConsumer as RedisOwnedConsumer, ProxyConfig as RedisProxyConfig,
    ProxyError as RedisProxyError, ProxyStats as RedisProxyStats, RedisProxy,
    Restrictions as RedisProxyRestrictions,
};
use raxis_credential_proxy_smtp::{
    AuthMode as SmtpAuthModeImpl, EnvelopeAudit, EnvelopeAuditSink, EnvelopeOutcome,
    OwnedConsumer as SmtpOwnedConsumer, ProxyConfig as SmtpProxyConfig,
    ProxyError as SmtpProxyError, ProxyStats as SmtpProxyStats,
    Restrictions as SmtpProxyRestrictions, SmtpProxy,
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

    /// Two credentials in the same task declared the same `mount_as`
    /// env-var name. The second would silently overwrite the first
    /// in `loopback_env()`, leaving one proxy unreachable. Fail
    /// closed at session start instead.
    #[error("duplicate mount_as `{mount_as}`: credentials `{first}` and `{second}` collide")]
    DuplicateMountAs {
        /// The colliding env-var name.
        mount_as: String,
        /// Credential name of the first declaration.
        first: String,
        /// Credential name of the second declaration.
        second: String,
    },

    /// A `K8s` declaration named a credential whose body could not
    /// be resolved into a kubeconfig with a `cluster.server` URL.
    /// Either the credential resolution failed, the body was not
    /// UTF-8, or the kubeconfig had no parseable `server:` line.
    #[error("k8s kubeconfig resolution failed for `{credential_name}`: {detail}")]
    KubeconfigResolution {
        /// Policy-declared credential name from the plan.
        credential_name: String,
        /// Free-form diagnostic. NEVER includes the credential
        /// value (the kubeconfig body is treated as secret).
        detail: String,
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

    /// SMTP proxy failed to bind / start.
    #[error("smtp proxy bind failed for `{credential_name}`: {source}")]
    SmtpBind {
        /// Credential name whose proxy bind failed.
        credential_name: String,
        /// Source error from the smtp-proxy crate.
        #[source]
        source: SmtpProxyError,
    },

    /// Redis proxy failed to bind / start.
    #[error("redis proxy bind failed for `{credential_name}`: {source}")]
    RedisBind {
        /// Credential name whose proxy bind failed.
        credential_name: String,
        /// Source error from the redis-proxy crate.
        #[source]
        source: RedisProxyError,
    },

    /// AWS proxy failed to bind / start.
    #[error("aws proxy bind failed for `{credential_name}`: {source}")]
    AwsBind {
        /// Credential name whose proxy bind failed.
        credential_name: String,
        /// Source error from the aws-proxy crate.
        #[source]
        source: AwsProxyError,
    },

    /// GCP proxy failed to bind / start.
    #[error("gcp proxy bind failed for `{credential_name}`: {source}")]
    GcpBind {
        /// Credential name whose proxy bind failed.
        credential_name: String,
        /// Source error from the gcp-proxy crate.
        #[source]
        source: GcpProxyError,
    },

    /// Azure proxy failed to bind / start.
    #[error("azure proxy bind failed for `{credential_name}`: {source}")]
    AzureBind {
        /// Credential name whose proxy bind failed.
        credential_name: String,
        /// Source error from the azure-proxy crate.
        #[source]
        source: AzureProxyError,
    },

    /// MySQL proxy failed to bind / start.
    #[error("mysql proxy bind failed for `{credential_name}`: {source}")]
    MysqlBind {
        /// Credential name whose proxy bind failed.
        credential_name: String,
        /// Source error from the mysql-proxy crate.
        #[source]
        source: MysqlProxyError,
    },

    /// MSSQL proxy failed to bind / start.
    #[error("mssql proxy bind failed for `{credential_name}`: {source}")]
    MssqlBind {
        /// Credential name whose proxy bind failed.
        credential_name: String,
        /// Source error from the mssql-proxy crate.
        #[source]
        source: MssqlProxyError,
    },

    /// MongoDB proxy failed to bind / start.
    #[error("mongodb proxy bind failed for `{credential_name}`: {source}")]
    MongodbBind {
        /// Credential name whose proxy bind failed.
        credential_name: String,
        /// Source error from the mongodb-proxy crate.
        #[source]
        source: MongodbProxyError,
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

    /// V3 cloud-forwarding declaration is malformed (e.g. AWS
    /// region missing, GCP scope set empty, Azure
    /// `cache_safety_window_seconds` below 60). Surfaced at
    /// bind time so misconfigured plans fail closed before any
    /// upstream credential is minted.
    #[error("cloud-forwarding misconfigured for `{credential_name}`: {detail}")]
    CloudForwardingConfig {
        /// Credential name whose forwarding decl is malformed.
        credential_name: String,
        /// Free-form diagnostic. NEVER includes credential
        /// bytes.
        detail: String,
    },
}

/// String name of the proxy type — embedded into the audit events.
fn proxy_type_str(decl: &ProxyDecl) -> &'static str {
    match decl {
        ProxyDecl::Postgres { .. } => "postgres",
        ProxyDecl::Http { .. } => "http",
        ProxyDecl::K8s { .. } => "k8s",
        ProxyDecl::Smtp { .. } => "smtp",
        ProxyDecl::Redis { .. } => "redis",
        ProxyDecl::Aws { .. } => "aws",
        ProxyDecl::Gcp { .. } => "gcp",
        ProxyDecl::Azure { .. } => "azure",
        ProxyDecl::Mysql { .. } => "mysql",
        ProxyDecl::Mssql { .. } => "mssql",
        ProxyDecl::Mongodb { .. } => "mongodb",
        ProxyDecl::Unknown => "unknown",
    }
}

// ---------------------------------------------------------------------------
// Per-proxy → kernel `AuditSink` adapters
//
// Each proxy crate exposes a small typed audit-event surface
// (`AuditEvent::DatabaseQueryExecuted`,
// `AuditEvent::HttpProxyRequestExecuted`, `EnvelopeAudit`) that
// stays dependency-free of `raxis-audit-tools`. The manager is the
// single seam where those proxy-local events become kernel
// `AuditEventKind` rows on the audit chain — emission is
// fire-and-forget on the per-connection task, and the adapter
// `tracing::warn!`s on a transient `AuditWriterError` rather than
// panicking so a wedged audit pipe doesn't tear down the agent
// session mid-query.
//
// All adapters carry the `session_id` and `task_id` for the bound
// session so each translated event lands with the correct
// correlation columns on the audit chain. They are constructed
// inside `bind_postgres` / `bind_http` / `bind_smtp` and dropped
// when the matching `ActiveProxy` is dropped.
// ---------------------------------------------------------------------------

struct PostgresKernelAuditAdapter {
    audit_sink: Arc<dyn AuditSink>,
    session_id: String,
    task_id: String,
}

impl PgAuditChannel for PostgresKernelAuditAdapter {
    fn emit(&self, event: PgAuditEvent) {
        match event {
            // V2.1 upstream-forwarding events. See
            // `credential-proxy.md §14.5`.
            PgAuditEvent::DatabaseQueryCompleted {
                credential,
                sql_sha256,
                rows_returned,
                bytes_returned,
                duration_ms,
                upstream_error,
                ..
            } => {
                let kind = AuditEventKind::DatabaseQueryCompleted {
                    session_id: self.session_id.clone(),
                    credential_name: credential.as_str().to_owned(),
                    proxy_type: "postgres".to_owned(),
                    sql_sha256,
                    rows_returned,
                    bytes_returned,
                    duration_ms,
                    upstream_error,
                };
                if let Err(e) =
                    self.audit_sink
                        .emit(kind, Some(&self.session_id), Some(&self.task_id), None)
                {
                    tracing::warn!(
                        target:     "raxis::credential_proxy::manager",
                        session_id = %self.session_id,
                        error      = %e,
                        "DatabaseQueryCompleted (postgres) audit emit failed",
                    );
                }
            }
            PgAuditEvent::CredentialProxyUpstreamConnected {
                credential,
                upstream_host,
                upstream_port,
                tls,
                handshake_ms,
                ..
            } => {
                let kind = AuditEventKind::CredentialProxyUpstreamConnected {
                    session_id: self.session_id.clone(),
                    credential_name: credential.as_str().to_owned(),
                    proxy_type: "postgres".to_owned(),
                    upstream_host,
                    upstream_port,
                    tls,
                    handshake_ms,
                };
                if let Err(e) =
                    self.audit_sink
                        .emit(kind, Some(&self.session_id), Some(&self.task_id), None)
                {
                    tracing::warn!(
                        target:     "raxis::credential_proxy::manager",
                        session_id = %self.session_id,
                        error      = %e,
                        "CredentialProxyUpstreamConnected (postgres) audit emit failed",
                    );
                }
            }
            PgAuditEvent::CredentialProxyUpstreamFailed {
                credential,
                upstream_host,
                upstream_port,
                reason,
                detail,
                ..
            } => {
                let kind = AuditEventKind::CredentialProxyUpstreamFailed {
                    session_id: self.session_id.clone(),
                    credential_name: credential.as_str().to_owned(),
                    proxy_type: "postgres".to_owned(),
                    upstream_host,
                    upstream_port,
                    reason,
                    detail,
                };
                if let Err(e) =
                    self.audit_sink
                        .emit(kind, Some(&self.session_id), Some(&self.task_id), None)
                {
                    tracing::warn!(
                        target:     "raxis::credential_proxy::manager",
                        session_id = %self.session_id,
                        error      = %e,
                        "CredentialProxyUpstreamFailed (postgres) audit emit failed",
                    );
                }
            }
            PgAuditEvent::DatabaseQueryExecuted {
                credential,
                sql_sha256,
                sql_text,
                operation,
                blocked,
                ..
            } => {
                let kind = AuditEventKind::DatabaseQueryExecuted {
                    session_id: self.session_id.clone(),
                    credential_name: credential.as_str().to_owned(),
                    operation,
                    sql_sha256,
                    sql_plaintext: sql_text,
                    blocked,
                };
                if let Err(e) =
                    self.audit_sink
                        .emit(kind, Some(&self.session_id), Some(&self.task_id), None)
                {
                    tracing::warn!(
                        target:     "raxis::credential_proxy::manager",
                        session_id = %self.session_id,
                        error      = %e,
                        "DatabaseQueryExecuted audit emit failed; per-query audit chain entry skipped",
                    );
                }
            }
            PgAuditEvent::CredentialProxySubstituted {
                credential,
                substitution_shape,
                ..
            } => {
                let kind = AuditEventKind::CredentialProxySubstituted {
                    session_id: self.session_id.clone(),
                    credential_name: credential.as_str().to_owned(),
                    proxy_type: "postgres".to_owned(),
                    real_resolved: true,
                    substitution_shape,
                };
                if let Err(e) =
                    self.audit_sink
                        .emit(kind, Some(&self.session_id), Some(&self.task_id), None)
                {
                    tracing::warn!(
                        target:     "raxis::credential_proxy::manager",
                        session_id = %self.session_id,
                        error      = %e,
                        "CredentialProxySubstituted (postgres) audit emit failed",
                    );
                }
            }
        }
    }
}

struct HttpKernelAuditAdapter {
    audit_sink: Arc<dyn AuditSink>,
    session_id: String,
    task_id: String,
}

impl HttpAuditChannel for HttpKernelAuditAdapter {
    fn emit(&self, event: HttpAuditEvent) {
        match event {
            HttpAuditEvent::HttpProxyRequestExecuted {
                credential,
                method,
                path,
                path_sha256,
                status_code,
                blocked,
                ..
            } => {
                let kind = AuditEventKind::HttpProxyRequestExecuted {
                    session_id: self.session_id.clone(),
                    credential_name: credential.as_str().to_owned(),
                    method,
                    path,
                    path_sha256,
                    status_code,
                    blocked,
                };
                if let Err(e) =
                    self.audit_sink
                        .emit(kind, Some(&self.session_id), Some(&self.task_id), None)
                {
                    tracing::warn!(
                        target:     "raxis::credential_proxy::manager",
                        session_id = %self.session_id,
                        error      = %e,
                        "HttpProxyRequestExecuted audit emit failed; per-request audit chain entry skipped",
                    );
                }
            }
        }
    }
}

struct SmtpKernelAuditAdapter {
    audit_sink: Arc<dyn AuditSink>,
    session_id: String,
    task_id: String,
    credential_name: String,
}

impl EnvelopeAuditSink for SmtpKernelAuditAdapter {
    fn emit(&self, event: EnvelopeAudit) {
        let envelope_sha256 = hex::encode(event.envelope_sha256);
        let kind = match event.outcome {
            EnvelopeOutcome::Relayed => AuditEventKind::SmtpMessageRelayed {
                session_id: self.session_id.clone(),
                credential_name: self.credential_name.clone(),
                envelope_sha256,
                recipient_count: event.recipient_count,
                bytes_relayed: event.bytes_submitted,
            },
            EnvelopeOutcome::Rejected => {
                let reason = event
                    .rejection_reason
                    .unwrap_or_else(|| "unknown".to_owned());
                let short_reason = short_reject_reason(&reason);
                AuditEventKind::SmtpMessageRejected {
                    session_id: self.session_id.clone(),
                    credential_name: self.credential_name.clone(),
                    envelope_sha256,
                    recipient_count: event.recipient_count,
                    bytes_submitted: event.bytes_submitted,
                    reason: short_reason.to_owned(),
                }
            }
        };
        if let Err(e) =
            self.audit_sink
                .emit(kind, Some(&self.session_id), Some(&self.task_id), None)
        {
            tracing::warn!(
                target:     "raxis::credential_proxy::manager",
                session_id = %self.session_id,
                error      = %e,
                "SmtpMessageRelayed/Rejected audit emit failed; per-envelope audit chain entry skipped",
            );
        }
    }
}

struct AwsKernelAuditAdapter {
    audit_sink: Arc<dyn AuditSink>,
    session_id: String,
    task_id: String,
}

impl AwsAuditChannel for AwsKernelAuditAdapter {
    fn emit(&self, event: AwsAuditEvent) {
        match event {
            AwsAuditEvent::AwsCredentialServed {
                credential,
                path,
                path_sha256,
                role_arn,
                allowed_services,
                allowed_regions,
                blocked,
                ..
            } => {
                let kind = AuditEventKind::AwsCredentialServed {
                    session_id: self.session_id.clone(),
                    credential_name: credential.as_str().to_owned(),
                    path,
                    path_sha256,
                    role_arn,
                    allowed_services,
                    allowed_regions,
                    blocked,
                };
                if let Err(e) =
                    self.audit_sink
                        .emit(kind, Some(&self.session_id), Some(&self.task_id), None)
                {
                    tracing::warn!(
                        target:     "raxis::credential_proxy::manager",
                        session_id = %self.session_id,
                        error      = %e,
                        "AwsCredentialServed audit emit failed; per-request audit chain entry skipped",
                    );
                }
            }
        }
    }
}

struct RedisKernelAuditAdapter {
    audit_sink: Arc<dyn AuditSink>,
    session_id: String,
    task_id: String,
}

impl RedisAuditChannel for RedisKernelAuditAdapter {
    fn emit(&self, event: RedisAuditEvent) {
        match event {
            // V2.1 upstream-forwarding events. See
            // `credential-proxy.md §14.5`.
            RedisAuditEvent::CredentialProxyUpstreamConnected {
                credential,
                upstream_host,
                upstream_port,
                tls,
                handshake_ms,
                ..
            } => {
                let kind = AuditEventKind::CredentialProxyUpstreamConnected {
                    session_id: self.session_id.clone(),
                    credential_name: credential.as_str().to_owned(),
                    proxy_type: "redis".to_owned(),
                    upstream_host,
                    upstream_port,
                    tls,
                    handshake_ms,
                };
                if let Err(e) =
                    self.audit_sink
                        .emit(kind, Some(&self.session_id), Some(&self.task_id), None)
                {
                    tracing::warn!(
                        target:     "raxis::credential_proxy::manager",
                        session_id = %self.session_id,
                        error      = %e,
                        "CredentialProxyUpstreamConnected (redis) audit emit failed",
                    );
                }
            }
            RedisAuditEvent::CredentialProxyUpstreamFailed {
                credential,
                upstream_host,
                upstream_port,
                reason,
                detail,
                ..
            } => {
                let kind = AuditEventKind::CredentialProxyUpstreamFailed {
                    session_id: self.session_id.clone(),
                    credential_name: credential.as_str().to_owned(),
                    proxy_type: "redis".to_owned(),
                    upstream_host,
                    upstream_port,
                    reason,
                    detail,
                };
                if let Err(e) =
                    self.audit_sink
                        .emit(kind, Some(&self.session_id), Some(&self.task_id), None)
                {
                    tracing::warn!(
                        target:     "raxis::credential_proxy::manager",
                        session_id = %self.session_id,
                        error      = %e,
                        "CredentialProxyUpstreamFailed (redis) audit emit failed",
                    );
                }
            }
            RedisAuditEvent::RedisCommandExecuted {
                consumer: _,
                credential,
                command,
                frame_sha256,
                blocked,
                ..
            } => {
                let kind = AuditEventKind::RedisCommandExecuted {
                    session_id: self.session_id.clone(),
                    credential_name: credential.as_str().to_owned(),
                    command,
                    frame_sha256,
                    blocked,
                };
                if let Err(e) =
                    self.audit_sink
                        .emit(kind, Some(&self.session_id), Some(&self.task_id), None)
                {
                    tracing::warn!(
                        target:     "raxis::credential_proxy::manager",
                        session_id = %self.session_id,
                        error      = %e,
                        "RedisCommandExecuted audit emit failed; per-command audit chain entry skipped",
                    );
                }
            }
        }
    }
}

struct GcpKernelAuditAdapter {
    audit_sink: Arc<dyn AuditSink>,
    session_id: String,
    task_id: String,
}

impl GcpAuditChannel for GcpKernelAuditAdapter {
    fn emit(&self, event: GcpAuditEvent) {
        match event {
            GcpAuditEvent::GcpMetadataServed {
                credential,
                path,
                path_sha256,
                project_id,
                allowed_scopes,
                blocked,
                ..
            } => {
                let kind = AuditEventKind::GcpMetadataServed {
                    session_id: self.session_id.clone(),
                    credential_name: credential.as_str().to_owned(),
                    path,
                    path_sha256,
                    project_id,
                    allowed_scopes,
                    blocked,
                };
                if let Err(e) =
                    self.audit_sink
                        .emit(kind, Some(&self.session_id), Some(&self.task_id), None)
                {
                    tracing::warn!(
                        target:     "raxis::credential_proxy::manager",
                        session_id = %self.session_id,
                        error      = %e,
                        "GcpMetadataServed audit emit failed; per-request audit chain entry skipped",
                    );
                }
            }
        }
    }
}

struct AzureKernelAuditAdapter {
    audit_sink: Arc<dyn AuditSink>,
    session_id: String,
    task_id: String,
}

impl AzureAuditChannel for AzureKernelAuditAdapter {
    fn emit(&self, event: AzureAuditEvent) {
        match event {
            AzureAuditEvent::AzureTokenServed {
                credential,
                path,
                resource,
                request_sha256,
                tenant_id,
                allowed_actions,
                blocked,
                ..
            } => {
                let kind = AuditEventKind::AzureTokenServed {
                    session_id: self.session_id.clone(),
                    credential_name: credential.as_str().to_owned(),
                    path,
                    resource,
                    request_sha256,
                    tenant_id,
                    allowed_actions,
                    blocked,
                };
                if let Err(e) =
                    self.audit_sink
                        .emit(kind, Some(&self.session_id), Some(&self.task_id), None)
                {
                    tracing::warn!(
                        target:     "raxis::credential_proxy::manager",
                        session_id = %self.session_id,
                        error      = %e,
                        "AzureTokenServed audit emit failed; per-request audit chain entry skipped",
                    );
                }
            }
        }
    }
}

struct MysqlKernelAuditAdapter {
    audit_sink: Arc<dyn AuditSink>,
    session_id: String,
    task_id: String,
}

impl MysqlAuditChannel for MysqlKernelAuditAdapter {
    fn emit(&self, event: MysqlAuditEvent) {
        match event {
            MysqlAuditEvent::DatabaseQueryExecuted {
                credential,
                sql_sha256,
                sql_text,
                operation,
                blocked,
                ..
            } => {
                let kind = AuditEventKind::DatabaseQueryExecuted {
                    session_id: self.session_id.clone(),
                    credential_name: credential.as_str().to_owned(),
                    operation: mysql_operation_label(&operation).to_owned(),
                    sql_sha256,
                    sql_plaintext: sql_text,
                    blocked,
                };
                if let Err(e) =
                    self.audit_sink
                        .emit(kind, Some(&self.session_id), Some(&self.task_id), None)
                {
                    tracing::warn!(
                        target:     "raxis::credential_proxy::manager",
                        session_id = %self.session_id,
                        error      = %e,
                        "DatabaseQueryExecuted (mysql) audit emit failed",
                    );
                }
            }
            // V2.1 upstream-forwarding events. See
            // `credential-proxy.md §14.5`.
            MysqlAuditEvent::DatabaseQueryCompleted {
                credential,
                sql_sha256,
                rows_returned,
                bytes_returned,
                duration_ms,
                upstream_error,
                ..
            } => {
                let kind = AuditEventKind::DatabaseQueryCompleted {
                    session_id: self.session_id.clone(),
                    credential_name: credential.as_str().to_owned(),
                    proxy_type: "mysql".to_owned(),
                    sql_sha256,
                    rows_returned,
                    bytes_returned,
                    duration_ms,
                    upstream_error,
                };
                if let Err(e) =
                    self.audit_sink
                        .emit(kind, Some(&self.session_id), Some(&self.task_id), None)
                {
                    tracing::warn!(
                        target:     "raxis::credential_proxy::manager",
                        session_id = %self.session_id,
                        error      = %e,
                        "DatabaseQueryCompleted (mysql) audit emit failed",
                    );
                }
            }
            MysqlAuditEvent::CredentialProxyUpstreamConnected {
                credential,
                upstream_host,
                upstream_port,
                tls,
                handshake_ms,
                ..
            } => {
                let kind = AuditEventKind::CredentialProxyUpstreamConnected {
                    session_id: self.session_id.clone(),
                    credential_name: credential.as_str().to_owned(),
                    proxy_type: "mysql".to_owned(),
                    upstream_host,
                    upstream_port,
                    tls,
                    handshake_ms,
                };
                if let Err(e) =
                    self.audit_sink
                        .emit(kind, Some(&self.session_id), Some(&self.task_id), None)
                {
                    tracing::warn!(
                        target:     "raxis::credential_proxy::manager",
                        session_id = %self.session_id,
                        error      = %e,
                        "CredentialProxyUpstreamConnected (mysql) audit emit failed",
                    );
                }
            }
            MysqlAuditEvent::CredentialProxyUpstreamFailed {
                credential,
                upstream_host,
                upstream_port,
                reason,
                detail,
                ..
            } => {
                let kind = AuditEventKind::CredentialProxyUpstreamFailed {
                    session_id: self.session_id.clone(),
                    credential_name: credential.as_str().to_owned(),
                    proxy_type: "mysql".to_owned(),
                    upstream_host,
                    upstream_port,
                    reason,
                    detail,
                };
                if let Err(e) =
                    self.audit_sink
                        .emit(kind, Some(&self.session_id), Some(&self.task_id), None)
                {
                    tracing::warn!(
                        target:     "raxis::credential_proxy::manager",
                        session_id = %self.session_id,
                        error      = %e,
                        "CredentialProxyUpstreamFailed (mysql) audit emit failed",
                    );
                }
            }
        }
    }
}

fn mysql_operation_label(op: &raxis_credential_proxy_mysql::OperationKind) -> &'static str {
    use raxis_credential_proxy_mysql::OperationKind as K;
    match op {
        K::Select => "SELECT",
        K::Insert => "INSERT",
        K::Update => "UPDATE",
        K::Delete => "DELETE",
        K::Other(_) => "OTHER",
    }
}

struct MssqlKernelAuditAdapter {
    audit_sink: Arc<dyn AuditSink>,
    session_id: String,
    task_id: String,
}

impl MssqlAuditChannel for MssqlKernelAuditAdapter {
    fn emit(&self, event: MssqlAuditEvent) {
        match event {
            MssqlAuditEvent::DatabaseQueryExecuted {
                credential,
                sql_sha256,
                sql_text,
                operation,
                blocked,
                ..
            } => {
                let kind = AuditEventKind::DatabaseQueryExecuted {
                    session_id: self.session_id.clone(),
                    credential_name: credential.as_str().to_owned(),
                    operation: mssql_operation_label(&operation).to_owned(),
                    sql_sha256,
                    sql_plaintext: sql_text,
                    blocked,
                };
                if let Err(e) =
                    self.audit_sink
                        .emit(kind, Some(&self.session_id), Some(&self.task_id), None)
                {
                    tracing::warn!(
                        target:     "raxis::credential_proxy::manager",
                        session_id = %self.session_id,
                        error      = %e,
                        "DatabaseQueryExecuted (mssql) audit emit failed",
                    );
                }
            }
            // V2.1 upstream-forwarding events. See
            // `credential-proxy.md §14.5`.
            MssqlAuditEvent::DatabaseQueryCompleted {
                credential,
                sql_sha256,
                rows_returned,
                bytes_returned,
                duration_ms,
                upstream_error,
                ..
            } => {
                let kind = AuditEventKind::DatabaseQueryCompleted {
                    session_id: self.session_id.clone(),
                    credential_name: credential.as_str().to_owned(),
                    proxy_type: "mssql".to_owned(),
                    sql_sha256,
                    rows_returned,
                    bytes_returned,
                    duration_ms,
                    upstream_error,
                };
                if let Err(e) =
                    self.audit_sink
                        .emit(kind, Some(&self.session_id), Some(&self.task_id), None)
                {
                    tracing::warn!(
                        target:     "raxis::credential_proxy::manager",
                        session_id = %self.session_id,
                        error      = %e,
                        "DatabaseQueryCompleted (mssql) audit emit failed",
                    );
                }
            }
            MssqlAuditEvent::CredentialProxyUpstreamConnected {
                credential,
                upstream_host,
                upstream_port,
                tls,
                handshake_ms,
                ..
            } => {
                let kind = AuditEventKind::CredentialProxyUpstreamConnected {
                    session_id: self.session_id.clone(),
                    credential_name: credential.as_str().to_owned(),
                    proxy_type: "mssql".to_owned(),
                    upstream_host,
                    upstream_port,
                    tls,
                    handshake_ms,
                };
                if let Err(e) =
                    self.audit_sink
                        .emit(kind, Some(&self.session_id), Some(&self.task_id), None)
                {
                    tracing::warn!(
                        target:     "raxis::credential_proxy::manager",
                        session_id = %self.session_id,
                        error      = %e,
                        "CredentialProxyUpstreamConnected (mssql) audit emit failed",
                    );
                }
            }
            MssqlAuditEvent::CredentialProxyUpstreamFailed {
                credential,
                upstream_host,
                upstream_port,
                reason,
                detail,
                ..
            } => {
                let kind = AuditEventKind::CredentialProxyUpstreamFailed {
                    session_id: self.session_id.clone(),
                    credential_name: credential.as_str().to_owned(),
                    proxy_type: "mssql".to_owned(),
                    upstream_host,
                    upstream_port,
                    reason,
                    detail,
                };
                if let Err(e) =
                    self.audit_sink
                        .emit(kind, Some(&self.session_id), Some(&self.task_id), None)
                {
                    tracing::warn!(
                        target:     "raxis::credential_proxy::manager",
                        session_id = %self.session_id,
                        error      = %e,
                        "CredentialProxyUpstreamFailed (mssql) audit emit failed",
                    );
                }
            }
        }
    }
}

fn mssql_operation_label(op: &raxis_credential_proxy_mssql::OperationKind) -> &'static str {
    use raxis_credential_proxy_mssql::OperationKind as K;
    match op {
        K::Select => "SELECT",
        K::Insert => "INSERT",
        K::Update => "UPDATE",
        K::Delete => "DELETE",
        K::Other(_) => "OTHER",
    }
}

struct MongodbKernelAuditAdapter {
    audit_sink: Arc<dyn AuditSink>,
    session_id: String,
    task_id: String,
}

impl MongodbAuditChannel for MongodbKernelAuditAdapter {
    fn emit(&self, event: MongodbAuditEvent) {
        match event {
            MongodbAuditEvent::MongoCommandExecuted {
                credential,
                command,
                body_sha256,
                blocked,
                ..
            } => {
                let kind = AuditEventKind::MongoCommandExecuted {
                    session_id: self.session_id.clone(),
                    credential_name: credential.as_str().to_owned(),
                    command,
                    body_sha256,
                    blocked,
                };
                if let Err(e) =
                    self.audit_sink
                        .emit(kind, Some(&self.session_id), Some(&self.task_id), None)
                {
                    tracing::warn!(
                        target:     "raxis::credential_proxy::manager",
                        session_id = %self.session_id,
                        error      = %e,
                        "MongoCommandExecuted audit emit failed",
                    );
                }
            }
            // V2.1 upstream-forwarding events. See
            // `credential-proxy.md §14.5`.
            MongodbAuditEvent::DatabaseQueryCompleted {
                credential,
                body_sha256,
                rows_returned,
                bytes_returned,
                duration_ms,
                upstream_error,
                ..
            } => {
                let kind = AuditEventKind::DatabaseQueryCompleted {
                    session_id: self.session_id.clone(),
                    credential_name: credential.as_str().to_owned(),
                    proxy_type: "mongodb".to_owned(),
                    sql_sha256: body_sha256,
                    rows_returned,
                    bytes_returned,
                    duration_ms,
                    upstream_error,
                };
                if let Err(e) =
                    self.audit_sink
                        .emit(kind, Some(&self.session_id), Some(&self.task_id), None)
                {
                    tracing::warn!(
                        target:     "raxis::credential_proxy::manager",
                        session_id = %self.session_id,
                        error      = %e,
                        "DatabaseQueryCompleted (mongodb) audit emit failed",
                    );
                }
            }
            MongodbAuditEvent::CredentialProxyUpstreamConnected {
                credential,
                upstream_host,
                upstream_port,
                tls,
                handshake_ms,
                ..
            } => {
                let kind = AuditEventKind::CredentialProxyUpstreamConnected {
                    session_id: self.session_id.clone(),
                    credential_name: credential.as_str().to_owned(),
                    proxy_type: "mongodb".to_owned(),
                    upstream_host,
                    upstream_port,
                    tls,
                    handshake_ms,
                };
                if let Err(e) =
                    self.audit_sink
                        .emit(kind, Some(&self.session_id), Some(&self.task_id), None)
                {
                    tracing::warn!(
                        target:     "raxis::credential_proxy::manager",
                        session_id = %self.session_id,
                        error      = %e,
                        "CredentialProxyUpstreamConnected (mongodb) audit emit failed",
                    );
                }
            }
            MongodbAuditEvent::CredentialProxyUpstreamFailed {
                credential,
                upstream_host,
                upstream_port,
                reason,
                detail,
                ..
            } => {
                let kind = AuditEventKind::CredentialProxyUpstreamFailed {
                    session_id: self.session_id.clone(),
                    credential_name: credential.as_str().to_owned(),
                    proxy_type: "mongodb".to_owned(),
                    upstream_host,
                    upstream_port,
                    reason,
                    detail,
                };
                if let Err(e) =
                    self.audit_sink
                        .emit(kind, Some(&self.session_id), Some(&self.task_id), None)
                {
                    tracing::warn!(
                        target:     "raxis::credential_proxy::manager",
                        session_id = %self.session_id,
                        error      = %e,
                        "CredentialProxyUpstreamFailed (mongodb) audit emit failed",
                    );
                }
            }
        }
    }
}

/// Map the proxy-side `EnvelopeAudit::rejection_reason` (which
/// typically embeds the SMTP refusal reply text after a stable
/// `audit_summary` prefix) into the short stable reason string the
/// `SmtpMessageRejected` audit event documents (`sender_not_allowed`,
/// `recipient_not_allowed`, `too_many_recipients`,
/// `message_too_large`, `rate_limit_exceeded`). When the proxy emits
/// a reason we don't recognise, the raw string is forwarded so the
/// audit chain still carries diagnostic context.
fn short_reject_reason(raw: &str) -> &str {
    const KNOWN: &[&str] = &[
        "sender_not_allowed",
        "recipient_not_allowed",
        "too_many_recipients",
        "message_too_large",
        "rate_limit_exceeded",
    ];
    for prefix in KNOWN {
        if raw.starts_with(prefix) {
            return prefix;
        }
    }
    raw
}

/// One bound proxy listener belonging to a session. Carries the
/// `JoinHandle` of the accept loop so [`SessionProxyHandles::shutdown`]
/// can abort the listener cleanly. The address is the loopback
/// address the agent VM will dial.
struct ActiveProxy {
    /// Free-form proxy_type label ("postgres" / "http" / "k8s" /
    /// "smtp") — reused in the matching `CredentialProxyStopped`
    /// event.
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
    Smtp(Arc<SmtpProxyStats>),
    Redis(Arc<RedisProxyStats>),
    Aws(Arc<AwsProxyStats>),
    Gcp(Arc<GcpProxyStats>),
    Azure(Arc<AzureProxyStats>),
    Mysql(Arc<MysqlProxyStats>),
    Mssql(Arc<MssqlProxyStats>),
    Mongodb(Arc<MongodbProxyStats>),
}

impl ProxyStatsHandle {
    fn snapshot_counters(&self) -> StoppedCounters {
        match self {
            ProxyStatsHandle::Postgres(s) => {
                let snap = s.snapshot();
                StoppedCounters {
                    connections_served: snap.connections_served,
                    forwards_completed: snap.queries_audited.saturating_sub(snap.queries_blocked),
                    forwards_blocked: snap.queries_blocked,
                }
            }
            ProxyStatsHandle::Http(s) => {
                let snap = s.snapshot();
                StoppedCounters {
                    connections_served: snap.connections_served,
                    forwards_completed: snap.requests_forwarded,
                    forwards_blocked: snap.requests_blocked,
                }
            }
            ProxyStatsHandle::Smtp(s) => {
                let snap = s.snapshot();
                StoppedCounters {
                    connections_served: snap.connections_served,
                    forwards_completed: snap.messages_relayed,
                    forwards_blocked: snap.messages_rejected,
                }
            }
            ProxyStatsHandle::Redis(s) => {
                let snap = s.snapshot();
                StoppedCounters {
                    connections_served: snap.connections_served,
                    forwards_completed: snap.commands_forwarded,
                    forwards_blocked: snap.commands_blocked,
                }
            }
            ProxyStatsHandle::Aws(s) => {
                let snap = s.snapshot();
                StoppedCounters {
                    connections_served: snap.connections_served,
                    forwards_completed: snap.credentials_served,
                    forwards_blocked: snap.requests_blocked,
                }
            }
            ProxyStatsHandle::Gcp(s) => {
                let snap = s.snapshot();
                StoppedCounters {
                    connections_served: snap.connections_served,
                    forwards_completed: snap.credentials_served,
                    forwards_blocked: snap.requests_blocked,
                }
            }
            ProxyStatsHandle::Azure(s) => {
                let snap = s.snapshot();
                StoppedCounters {
                    connections_served: snap.connections_served,
                    forwards_completed: snap.tokens_served,
                    forwards_blocked: snap.requests_blocked,
                }
            }
            ProxyStatsHandle::Mysql(s) => {
                let snap = s.snapshot();
                StoppedCounters {
                    connections_served: snap.connections_served,
                    forwards_completed: snap.queries_audited.saturating_sub(snap.queries_blocked),
                    forwards_blocked: snap.queries_blocked,
                }
            }
            ProxyStatsHandle::Mssql(s) => {
                let snap = s.snapshot();
                StoppedCounters {
                    connections_served: snap.connections_served,
                    forwards_completed: snap.queries_audited.saturating_sub(snap.queries_blocked),
                    forwards_blocked: snap.queries_blocked,
                }
            }
            ProxyStatsHandle::Mongodb(s) => {
                let snap = s.snapshot();
                StoppedCounters {
                    connections_served: snap.connections_served,
                    forwards_completed: snap.commands_audited.saturating_sub(snap.commands_blocked),
                    forwards_blocked: snap.commands_blocked,
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
    pub forwards_blocked: u32,
}

/// Per-proxy summary from a successful bind. Returned to the caller
/// so the kernel session-spawn path can wire the loopback addresses
/// into the VM's environment.
#[derive(Debug, Clone)]
pub struct StartedProxy {
    /// `proxy_type` string — `postgres` / `http` / `k8s` / `smtp`.
    pub proxy_type: &'static str,
    /// Policy-declared credential name (never the value).
    pub credential_name: String,
    /// `mount_as` env-var name from the plan TOML
    /// (e.g. `DATABASE_URL`, `KUBECONFIG`). When a task declares
    /// multiple credentials of the same proxy type (e.g. two
    /// Postgres databases), each MUST have a distinct `mount_as`
    /// value — use explicit names like `USERS_DATABASE_URL` and
    /// `ANALYTICS_DATABASE_URL` rather than a generic `DATABASE_URL`.
    pub mount_as: String,
    /// Loopback address the listener is bound to.
    pub addr: SocketAddr,
}

/// Per-proxy summary from a successful shutdown. Returned to the
/// caller (and to tests) so the kernel session-teardown path can
/// log/observe the final counters.
#[derive(Debug, Clone)]
pub struct StoppedProxy {
    /// `proxy_type` string — `postgres` / `http` / `k8s` / `smtp`.
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
    proxies: Vec<ActiveProxy>,
    audit: Arc<dyn AuditSink>,
    /// Once `shutdown` has run, the destructor must NOT emit a
    /// duplicate stop event.
    drained: bool,
}

impl SessionProxyHandles {
    /// Number of bound proxies in this session.
    pub fn len(&self) -> usize {
        self.proxies.len()
    }

    /// Whether the session has zero declared proxies.
    pub fn is_empty(&self) -> bool {
        self.proxies.is_empty()
    }

    /// The session id this bundle belongs to. Useful for tests and
    /// for correlation in the kernel's session map.
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    /// Per-proxy summary of every successful bind, in declaration
    /// order. Useful for the kernel session-spawn path which needs
    /// to log each addr or build a per-substrate kubeconfig.
    pub fn started_summaries(&self) -> Vec<StartedProxy> {
        self.proxies
            .iter()
            .map(|p| StartedProxy {
                proxy_type: p.proxy_type,
                credential_name: p.credential_name.clone(),
                mount_as: p.mount_as.clone(),
                addr: p.addr,
            })
            .collect()
    }

    /// Mapping from `mount_as` env-var name → loopback URL string
    /// the agent's environment should bind to. The kernel
    /// session-spawn path consumes this to fill `env: {
    /// USERS_DATABASE_URL: ..., ANALYTICS_DATABASE_URL: ..., ... }`
    /// in the VM spec.
    ///
    /// Each credential's `mount_as` field is the map key. When a
    /// task has multiple credentials of the same proxy type, the
    /// operator MUST choose distinct `mount_as` names — a generic
    /// `DATABASE_URL` is ambiguous and should only be used when
    /// exactly one database credential is declared.
    ///
    /// The URL shape is per-proxy and MUST match the wire-protocol
    /// scheme the agent's standard client expects (see
    /// `credential-proxy.md §3` and the `§11.x` per-proxy_type
    /// examples — e.g. mongodb→`mongodb://`, mysql→`mysql://`,
    /// mssql→`mssql://`, redis→`redis://`). HTTP/k8s/aws/gcp/azure
    /// proxies stay on `http://` because their canonical clients
    /// (kubectl, aws CLI, …) dial an HTTP endpoint. The credential
    /// VALUE is never embedded — the proxy injects auth on the wire.
    ///
    /// **Bug history.** Until iter28 of the realistic-scenario live-e2e
    /// the catch-all arm emitted `http://` for every non-postgres /
    /// non-smtp proxy. mongodb agents (pymongo) reject `http://`
    /// URLs with `InvalidURI`, and even after a client-side rewrite
    /// to `mongodb://` they reach the proxy with no
    /// `mongodb`-protocol handshake context, which the proxy's
    /// `serve_one()` discards as a malformed greeting — surfacing
    /// to the agent as "connection closed". Adding explicit
    /// per-proxy_type arms here is the structural fix.
    pub fn loopback_env(&self) -> BTreeMap<String, String> {
        let mut out = BTreeMap::new();
        for p in &self.proxies {
            let url = match p.proxy_type {
                "postgres" => format!("postgresql://raxis@{}/", p.addr),
                "mysql" => format!("mysql://raxis@{}/", p.addr),
                "mssql" => format!("mssql://raxis@{}/", p.addr),
                // MongoDB clients (pymongo, mongo-rust-driver,
                // mongoose) reject userinfo-without-password URIs:
                // pymongo's `auth.parse_userinfo` raises
                // `InvalidURI` when `username` is present but
                // `password` is `None`, and the official Node and
                // Java drivers behave the same way. The proxy's
                // own contract is that the agent-side connection
                // is no-auth (`lib.rs` §"`mount_as` URI =
                // `mongodb://127.0.0.1:PORT/db` with no
                // credentials, hello response advertises an empty
                // `saslSupportedMechs`"), so the URL we hand the
                // agent must omit userinfo entirely. Live-e2e
                // iter29 reproduced this: with `mongodb://raxis@…`
                // pymongo bailed with `InvalidURI` before opening
                // a TCP socket, surfacing to the executor as
                // "connection closed" (the absence of any TCP
                // accept on the proxy is indistinguishable from a
                // local-loopback-RST from the agent's perspective).
                "mongodb" => format!("mongodb://{}/", p.addr),
                "redis" => format!("redis://{}", p.addr),
                // SMTP proxies are dialed as a host:port pair (no
                // scheme). Common SMTP client libraries expect a
                // bare `host:port`; surface that exactly so the
                // injected env var (e.g. `SMTP_URL` or `SMTP_HOST`)
                // is plug-compatible.
                "smtp" => p.addr.to_string(),
                // `http` / `k8s` / `aws` / `gcp` / `azure` and any
                // future REST-shaped proxy: agent dials an HTTP
                // endpoint on loopback.
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
            self.audit
                .emit(
                    AuditEventKind::CredentialProxyStopped {
                        session_id: self.session_id.clone(),
                        proxy_type: p.proxy_type.to_owned(),
                        credential_name: p.credential_name.clone(),
                        connections_served: counters.connections_served,
                        forwards_completed: counters.forwards_completed,
                        forwards_blocked: counters.forwards_blocked,
                    },
                    Some(&self.session_id),
                    None,
                    None,
                )
                .map_err(|e| ManagerError::Audit(e.to_string()))?;
            stopped.push(StoppedProxy {
                proxy_type: p.proxy_type,
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
    audit: Arc<dyn AuditSink>,
}

impl CredentialProxyManager {
    /// Construct a manager bound to a credential backend and audit
    /// sink. Both are typically the kernel's production wiring.
    pub fn new(backend: Arc<dyn CredentialBackend>, audit: Arc<dyn AuditSink>) -> Self {
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
        task_id: &str,
        decls: &[TaskCredentialDecl],
    ) -> Result<SessionProxyHandles, ManagerError> {
        // ── Defense-in-depth: mount_as uniqueness ────────────────────
        // The primary check is in `parse_for_task()` at plan
        // admission (shift-left). This backstop should never fire
        // in practice — if it does, the admission pipeline has a
        // bug. Kept as a fail-closed guard because silently
        // overwriting env vars is a correctness violation.
        {
            let mut seen: BTreeMap<&str, &str> = BTreeMap::new();
            for decl in decls {
                if let Some(first_cred) = seen.get(decl.mount_as.as_str()) {
                    return Err(ManagerError::DuplicateMountAs {
                        mount_as: decl.mount_as.clone(),
                        first: first_cred.to_string(),
                        second: decl.name.as_str().to_owned(),
                    });
                }
                seen.insert(&decl.mount_as, decl.name.as_str());
            }
        }

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
                ProxyDecl::Http {
                    auth_mode,
                    upstream_url,
                    restrictions,
                } => {
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
                    // k8s rides the HTTP credential proxy with a
                    // fixed Bearer mode. The upstream URL is the
                    // `cluster.server` field from the resolved
                    // kubeconfig YAML. We resolve the credential
                    // body once at bind time (the same way the
                    // HTTP proxy resolves its bearer token), parse
                    // the `server:` line, and then drive the rest
                    // of the bind through `bind_http`. The
                    // `proxy_type` label on the resulting
                    // `ActiveProxy` is overridden to `"k8s"` so
                    // audit events carry the operator-declared type.
                    let upstream_url =
                        self.resolve_kubeconfig_server_url(&decl.name, session_id)?;
                    let mut active = self
                        .bind_http(
                            session_id,
                            task_id,
                            &decl.name,
                            &decl.mount_as,
                            &HttpAuthMode::Bearer,
                            &upstream_url,
                            restrictions,
                        )
                        .await?;
                    active.proxy_type = "k8s";
                    active
                }
                ProxyDecl::Smtp {
                    auth_mode,
                    upstream_host_port,
                    require_upstream_tls,
                    restrictions,
                } => {
                    self.bind_smtp(
                        session_id,
                        task_id,
                        &decl.name,
                        &decl.mount_as,
                        auth_mode,
                        upstream_host_port,
                        *require_upstream_tls,
                        restrictions,
                    )
                    .await?
                }
                ProxyDecl::Redis {
                    upstream_host_port,
                    require_upstream_tls,
                    restrictions,
                } => {
                    self.bind_redis(
                        session_id,
                        task_id,
                        &decl.name,
                        &decl.mount_as,
                        upstream_host_port,
                        *require_upstream_tls,
                        restrictions,
                    )
                    .await?
                }
                ProxyDecl::Aws {
                    role_arn,
                    lease_seconds,
                    forwarding,
                    restrictions,
                } => {
                    self.bind_aws(
                        session_id,
                        task_id,
                        &decl.name,
                        &decl.mount_as,
                        role_arn.as_deref(),
                        *lease_seconds,
                        forwarding.as_ref(),
                        restrictions,
                    )
                    .await?
                }
                ProxyDecl::Gcp {
                    project,
                    numeric_project,
                    lease_seconds,
                    forwarding,
                    restrictions,
                } => {
                    self.bind_gcp(
                        session_id,
                        task_id,
                        &decl.name,
                        &decl.mount_as,
                        project,
                        *numeric_project,
                        *lease_seconds,
                        forwarding.as_ref(),
                        restrictions,
                    )
                    .await?
                }
                ProxyDecl::Azure {
                    tenant_id,
                    client_id,
                    lease_seconds,
                    forwarding,
                    restrictions,
                } => {
                    self.bind_azure(
                        session_id,
                        task_id,
                        &decl.name,
                        &decl.mount_as,
                        tenant_id,
                        client_id.as_deref(),
                        *lease_seconds,
                        forwarding.as_ref(),
                        restrictions,
                    )
                    .await?
                }
                ProxyDecl::Mysql { restrictions } => {
                    self.bind_mysql(
                        session_id,
                        task_id,
                        &decl.name,
                        &decl.mount_as,
                        restrictions,
                    )
                    .await?
                }
                ProxyDecl::Mssql { restrictions } => {
                    self.bind_mssql(
                        session_id,
                        task_id,
                        &decl.name,
                        &decl.mount_as,
                        restrictions,
                    )
                    .await?
                }
                ProxyDecl::Mongodb { restrictions } => {
                    self.bind_mongodb(
                        session_id,
                        task_id,
                        &decl.name,
                        &decl.mount_as,
                        restrictions,
                    )
                    .await?
                }
                ProxyDecl::Unknown => {
                    return Err(ManagerError::UnknownProxyType { credential_name });
                }
            };

            self.audit
                .emit(
                    AuditEventKind::CredentialProxyStarted {
                        session_id: session_id.to_owned(),
                        proxy_type: proxy_type.to_owned(),
                        credential_name: credential_name.clone(),
                        addr: active.addr.to_string(),
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
            audit: Arc::clone(&self.audit),
            drained: false,
        })
    }

    async fn bind_postgres(
        &self,
        session_id: &str,
        task_id: &str,
        name: &raxis_credentials::CredentialName,
        mount_as: &str,
        restrictions: &PostgresRestrictions,
    ) -> Result<ActiveProxy, ManagerError> {
        let cfg = PgProxyConfig {
            listen_addr: "127.0.0.1:0".to_owned(),
            credential_name: name.clone(),
            consumer: PgOwnedConsumer::new("session", session_id.to_owned()),
            restrictions: PgProxyRestrictions {
                allow_only_select: restrictions.allow_only_select,
                allowed_tables: restrictions.allowed_tables.clone(),
                forbidden_tables: restrictions.forbidden_tables.clone(),
                max_result_rows: restrictions.max_result_rows,
                enforce: restrictions.enforce,
            },
        };
        let audit_channel: Arc<dyn PgAuditChannel> = Arc::new(PostgresKernelAuditAdapter {
            audit_sink: Arc::clone(&self.audit),
            session_id: session_id.to_owned(),
            task_id: task_id.to_owned(),
        });
        let proxy = PostgresProxy::bind(Arc::clone(&self.backend), cfg, audit_channel)
            .await
            .map_err(|source| ManagerError::PostgresBind {
                credential_name: name.as_str().to_owned(),
                source,
            })?;
        let addr = proxy
            .local_addr()
            .map_err(|source| ManagerError::LocalAddr {
                credential_name: name.as_str().to_owned(),
                source,
            })?;
        let stats_handle = proxy.stats_handle();
        let join = tokio::spawn(async move {
            proxy.serve().await;
        });
        Ok(ActiveProxy {
            proxy_type: "postgres",
            credential_name: name.as_str().to_owned(),
            mount_as: mount_as.to_owned(),
            addr,
            stats: ProxyStatsHandle::Postgres(stats_handle),
            join,
        })
    }

    /// Resolve a kubeconfig credential and extract the
    /// `cluster.server` URL. The credential body is treated as
    /// secret — the helper does NOT log the body, only the
    /// derived URL (which is operator-known by definition since
    /// it points at the cluster API server). The credential is
    /// dropped before returning.
    fn resolve_kubeconfig_server_url(
        &self,
        name: &raxis_credentials::CredentialName,
        session_id: &str,
    ) -> Result<String, ManagerError> {
        let consumer = raxis_credentials::ConsumerIdentity::new("session", session_id);
        let value = self.backend.resolve(name, consumer).map_err(|e| {
            ManagerError::KubeconfigResolution {
                credential_name: name.as_str().to_owned(),
                detail: format!("backend resolve failed: {e}"),
            }
        })?;
        let url = value
            .as_utf8()
            .ok_or_else(|| ManagerError::KubeconfigResolution {
                credential_name: name.as_str().to_owned(),
                detail: "kubeconfig body is not UTF-8".to_owned(),
            })
            .and_then(|body| {
                kubeconfig::extract_first_cluster_server(&body).ok_or_else(|| {
                    ManagerError::KubeconfigResolution {
                        credential_name: name.as_str().to_owned(),
                        detail: "no `cluster.server` line found in kubeconfig".to_owned(),
                    }
                })
            });
        // `value` drops here regardless of success — its zeroize
        // discipline cleans the body bytes.
        url
    }

    #[allow(clippy::too_many_arguments)]
    async fn bind_http(
        &self,
        session_id: &str,
        task_id: &str,
        name: &raxis_credentials::CredentialName,
        mount_as: &str,
        auth_mode: &HttpAuthMode,
        upstream_url: &str,
        restrictions: &HttpRestrictions,
    ) -> Result<ActiveProxy, ManagerError> {
        let cfg = HttpProxyConfig {
            listen_addr: "127.0.0.1:0".to_owned(),
            upstream_url: upstream_url.to_owned(),
            credential_name: name.clone(),
            auth_mode: match auth_mode {
                HttpAuthMode::Bearer => HttpAuthModeImpl::Bearer,
                HttpAuthMode::Basic { user } => HttpAuthModeImpl::Basic { user: user.clone() },
            },
            consumer: HttpOwnedConsumer::new("session", session_id.to_owned()),
            restrictions: HttpProxyRestrictions {
                allowed_methods: restrictions.allowed_methods.clone(),
                allowed_path_prefixes: restrictions.allowed_path_prefixes.clone(),
            },
        };
        let audit_channel: Arc<dyn HttpAuditChannel> = Arc::new(HttpKernelAuditAdapter {
            audit_sink: Arc::clone(&self.audit),
            session_id: session_id.to_owned(),
            task_id: task_id.to_owned(),
        });
        let proxy = HttpProxy::bind(Arc::clone(&self.backend), cfg, audit_channel)
            .await
            .map_err(|source| ManagerError::HttpBind {
                credential_name: name.as_str().to_owned(),
                source,
            })?;
        let addr = proxy
            .local_addr()
            .map_err(|source| ManagerError::LocalAddr {
                credential_name: name.as_str().to_owned(),
                source,
            })?;
        let stats_handle = proxy.stats_handle();
        let join = tokio::spawn(async move {
            proxy.serve().await;
        });
        Ok(ActiveProxy {
            proxy_type: "http",
            credential_name: name.as_str().to_owned(),
            mount_as: mount_as.to_owned(),
            addr,
            stats: ProxyStatsHandle::Http(stats_handle),
            join,
        })
    }

    #[allow(clippy::too_many_arguments)]
    async fn bind_smtp(
        &self,
        session_id: &str,
        task_id: &str,
        name: &raxis_credentials::CredentialName,
        mount_as: &str,
        auth_mode: &SmtpAuthMode,
        upstream_host_port: &str,
        require_upstream_tls: bool,
        restrictions: &SmtpRestrictions,
    ) -> Result<ActiveProxy, ManagerError> {
        if require_upstream_tls && !raxis_credential_proxy_smtp::wire::Outbound::IS_TLS_WIRED {
            // Defence-in-depth: if a future build ever ships with the
            // TLS-wiring disabled, refuse to bind a proxy whose
            // policy demands TLS rather than silently dropping back
            // to cleartext. The current build always has IS_TLS_WIRED
            // = true (tokio-rustls is wired), so this is a tripwire.
            return Err(ManagerError::SmtpBind {
                credential_name: name.as_str().to_owned(),
                source: SmtpProxyError::BadUpstream(
                    "this kernel build does not have tokio-rustls upstream wired, but the proxy declaration requires TLS".to_owned(),
                ),
            });
        }
        let cfg = SmtpProxyConfig {
            listen_addr: "127.0.0.1:0".to_owned(),
            upstream_host_port: upstream_host_port.to_owned(),
            require_upstream_tls,
            credential_name: name.clone(),
            auth_mode: match auth_mode {
                SmtpAuthMode::Plain { user } => SmtpAuthModeImpl::Plain { user: user.clone() },
                SmtpAuthMode::Login { user } => SmtpAuthModeImpl::Login { user: user.clone() },
            },
            consumer: SmtpOwnedConsumer::new("session", session_id.to_owned()),
            restrictions: SmtpProxyRestrictions {
                allowed_sender_address: restrictions.allowed_sender_address.clone(),
                allowed_recipient_domains: restrictions.allowed_recipient_domains.clone(),
                max_recipients_per_message: restrictions.max_recipients_per_message,
                max_message_bytes: restrictions.max_message_bytes,
                max_messages_per_minute: restrictions.max_messages_per_minute,
            },
        };
        let envelope_sink: Arc<dyn EnvelopeAuditSink> = Arc::new(SmtpKernelAuditAdapter {
            audit_sink: Arc::clone(&self.audit),
            session_id: session_id.to_owned(),
            task_id: task_id.to_owned(),
            credential_name: name.as_str().to_owned(),
        });
        let proxy = SmtpProxy::bind(Arc::clone(&self.backend), cfg, envelope_sink)
            .await
            .map_err(|source| ManagerError::SmtpBind {
                credential_name: name.as_str().to_owned(),
                source,
            })?;
        let addr = proxy
            .local_addr()
            .map_err(|source| ManagerError::LocalAddr {
                credential_name: name.as_str().to_owned(),
                source,
            })?;
        let stats_handle = proxy.stats_handle();
        let join = tokio::spawn(async move {
            proxy.serve().await;
        });
        Ok(ActiveProxy {
            proxy_type: "smtp",
            credential_name: name.as_str().to_owned(),
            mount_as: mount_as.to_owned(),
            addr,
            stats: ProxyStatsHandle::Smtp(stats_handle),
            join,
        })
    }

    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::too_many_arguments)]
    async fn bind_redis(
        &self,
        session_id: &str,
        task_id: &str,
        name: &raxis_credentials::CredentialName,
        mount_as: &str,
        upstream_host_port: &str,
        require_upstream_tls: bool,
        restrictions: &RedisRestrictions,
    ) -> Result<ActiveProxy, ManagerError> {
        let cfg = RedisProxyConfig {
            listen_addr: "127.0.0.1:0".to_owned(),
            upstream_host_port: upstream_host_port.to_owned(),
            credential_name: name.clone(),
            consumer: RedisOwnedConsumer::new("session", session_id.to_owned()),
            restrictions: RedisProxyRestrictions {
                allowed_commands: restrictions.allowed_commands.clone(),
            },
            upstream_tls: require_upstream_tls,
        };
        let audit_channel: Arc<dyn RedisAuditChannel> = Arc::new(RedisKernelAuditAdapter {
            audit_sink: Arc::clone(&self.audit),
            session_id: session_id.to_owned(),
            task_id: task_id.to_owned(),
        });
        let proxy = RedisProxy::bind(Arc::clone(&self.backend), cfg, audit_channel)
            .await
            .map_err(|source| ManagerError::RedisBind {
                credential_name: name.as_str().to_owned(),
                source,
            })?;
        let addr = proxy
            .local_addr()
            .map_err(|source| ManagerError::LocalAddr {
                credential_name: name.as_str().to_owned(),
                source,
            })?;
        let stats_handle = proxy.stats_handle();
        let join = tokio::spawn(async move {
            proxy.serve().await;
        });
        Ok(ActiveProxy {
            proxy_type: "redis",
            credential_name: name.as_str().to_owned(),
            mount_as: mount_as.to_owned(),
            addr,
            stats: ProxyStatsHandle::Redis(stats_handle),
            join,
        })
    }

    #[allow(clippy::too_many_arguments)]
    async fn bind_aws(
        &self,
        session_id: &str,
        task_id: &str,
        name: &raxis_credentials::CredentialName,
        mount_as: &str,
        role_arn: Option<&str>,
        lease_seconds: u64,
        forwarding: Option<&AwsForwardingDecl>,
        restrictions: &AwsRestrictions,
    ) -> Result<ActiveProxy, ManagerError> {
        // V3 forwarding plumbing — only constructed when the plan
        // declares `[forwarding] enabled = true`. The shared
        // CloudHttpClient is bound to the allowlisted STS upstream
        // at construction so a misconfigured `region` /
        // `endpoint_kind` fails closed before any token is minted.
        let v3 = match forwarding {
            Some(f) if f.enabled => Some(build_aws_forwarding(name.as_str(), f, role_arn)?),
            _ => None,
        };
        let cfg = AwsProxyConfig {
            listen_addr: "127.0.0.1:0".to_owned(),
            credential_name: name.clone(),
            consumer: AwsOwnedConsumer::new("session", session_id.to_owned()),
            lease_seconds,
            role_arn: role_arn.map(|s| s.to_owned()),
            forwarding: v3.as_ref().map(|x| x.fwd.clone()),
            restrictions: AwsProxyRestrictions {
                allowed_paths: restrictions.allowed_paths.clone(),
                allowed_services: restrictions.allowed_services.clone(),
                allowed_regions: restrictions.allowed_regions.clone(),
            },
        };
        let audit_channel: Arc<dyn AwsAuditChannel> = Arc::new(AwsKernelAuditAdapter {
            audit_sink: Arc::clone(&self.audit),
            session_id: session_id.to_owned(),
            task_id: task_id.to_owned(),
        });
        let proxy = match v3 {
            Some(v3) => {
                AwsProxy::bind_v3(
                    Arc::clone(&self.backend),
                    cfg,
                    audit_channel,
                    Arc::clone(&self.audit),
                    Arc::new(v3.http),
                    Arc::new(v3.cache),
                )
                .await
            }
            None => AwsProxy::bind(Arc::clone(&self.backend), cfg, audit_channel).await,
        }
        .map_err(|source| ManagerError::AwsBind {
            credential_name: name.as_str().to_owned(),
            source,
        })?;
        let addr = proxy
            .local_addr()
            .map_err(|source| ManagerError::LocalAddr {
                credential_name: name.as_str().to_owned(),
                source,
            })?;
        let stats_handle = proxy.stats_handle();
        let join = tokio::spawn(async move {
            proxy.serve().await;
        });
        Ok(ActiveProxy {
            proxy_type: "aws",
            credential_name: name.as_str().to_owned(),
            mount_as: mount_as.to_owned(),
            addr,
            stats: ProxyStatsHandle::Aws(stats_handle),
            join,
        })
    }

    #[allow(clippy::too_many_arguments)]
    async fn bind_gcp(
        &self,
        session_id: &str,
        task_id: &str,
        name: &raxis_credentials::CredentialName,
        mount_as: &str,
        project: &str,
        numeric_project: Option<u64>,
        lease_seconds: u64,
        forwarding: Option<&GcpForwardingDecl>,
        restrictions: &GcpRestrictions,
    ) -> Result<ActiveProxy, ManagerError> {
        let v3 = match forwarding {
            Some(f) if f.enabled => Some(build_gcp_forwarding(
                name.as_str(),
                f,
                &restrictions.allowed_scopes,
            )?),
            _ => None,
        };
        let cfg = GcpProxyConfig {
            listen_addr: "127.0.0.1:0".to_owned(),
            credential_name: name.clone(),
            consumer: GcpOwnedConsumer::new("session", session_id.to_owned()),
            lease_seconds,
            project_id: project.to_owned(),
            numeric_project_id: numeric_project,
            forwarding: v3.as_ref().map(|x| x.fwd.clone()),
            restrictions: GcpProxyRestrictions {
                allowed_paths: restrictions.allowed_paths.clone(),
                allowed_scopes: restrictions.allowed_scopes.clone(),
                project: restrictions.project.clone(),
            },
        };
        let audit_channel: Arc<dyn GcpAuditChannel> = Arc::new(GcpKernelAuditAdapter {
            audit_sink: Arc::clone(&self.audit),
            session_id: session_id.to_owned(),
            task_id: task_id.to_owned(),
        });
        let proxy = match v3 {
            Some(v3) => {
                GcpProxy::bind_v3(
                    Arc::clone(&self.backend),
                    cfg,
                    audit_channel,
                    Arc::clone(&self.audit),
                    Arc::new(v3.http),
                    Arc::new(v3.cache),
                )
                .await
            }
            None => GcpProxy::bind(Arc::clone(&self.backend), cfg, audit_channel).await,
        }
        .map_err(|source| ManagerError::GcpBind {
            credential_name: name.as_str().to_owned(),
            source,
        })?;
        let addr = proxy
            .local_addr()
            .map_err(|source| ManagerError::LocalAddr {
                credential_name: name.as_str().to_owned(),
                source,
            })?;
        let stats_handle = proxy.stats_handle();
        let join = tokio::spawn(async move {
            proxy.serve().await;
        });
        Ok(ActiveProxy {
            proxy_type: "gcp",
            credential_name: name.as_str().to_owned(),
            mount_as: mount_as.to_owned(),
            addr,
            stats: ProxyStatsHandle::Gcp(stats_handle),
            join,
        })
    }

    #[allow(clippy::too_many_arguments)]
    async fn bind_azure(
        &self,
        session_id: &str,
        task_id: &str,
        name: &raxis_credentials::CredentialName,
        mount_as: &str,
        tenant_id: &str,
        client_id: Option<&str>,
        lease_seconds: u64,
        forwarding: Option<&AzureForwardingDecl>,
        restrictions: &AzureRestrictions,
    ) -> Result<ActiveProxy, ManagerError> {
        let v3 = match forwarding {
            Some(f) if f.enabled => Some(build_azure_forwarding(name.as_str(), f)?),
            _ => None,
        };
        let cfg = AzureProxyConfig {
            listen_addr: "127.0.0.1:0".to_owned(),
            credential_name: name.clone(),
            consumer: AzureOwnedConsumer::new("session", session_id.to_owned()),
            lease_seconds,
            tenant_id: tenant_id.to_owned(),
            client_id: client_id.map(|s| s.to_owned()),
            forwarding: v3.as_ref().map(|x| x.fwd.clone()),
            restrictions: AzureProxyRestrictions {
                allowed_resources: restrictions.allowed_resources.clone(),
                allowed_actions: restrictions
                    .allowed_actions
                    .iter()
                    .map(
                        |ra| raxis_credential_proxy_azure::restriction::ResourceActions {
                            resource: ra.resource.clone(),
                            actions: ra.actions.clone(),
                        },
                    )
                    .collect(),
            },
        };
        let audit_channel: Arc<dyn AzureAuditChannel> = Arc::new(AzureKernelAuditAdapter {
            audit_sink: Arc::clone(&self.audit),
            session_id: session_id.to_owned(),
            task_id: task_id.to_owned(),
        });
        let proxy = match v3 {
            Some(v3) => {
                AzureProxy::bind_v3(
                    Arc::clone(&self.backend),
                    cfg,
                    audit_channel,
                    Arc::clone(&self.audit),
                    Arc::new(v3.http),
                    Arc::new(v3.cache),
                )
                .await
            }
            None => AzureProxy::bind(Arc::clone(&self.backend), cfg, audit_channel).await,
        }
        .map_err(|source| ManagerError::AzureBind {
            credential_name: name.as_str().to_owned(),
            source,
        })?;
        let addr = proxy
            .local_addr()
            .map_err(|source| ManagerError::LocalAddr {
                credential_name: name.as_str().to_owned(),
                source,
            })?;
        let stats_handle = proxy.stats_handle();
        let join = tokio::spawn(async move {
            proxy.serve().await;
        });
        Ok(ActiveProxy {
            proxy_type: "azure",
            credential_name: name.as_str().to_owned(),
            mount_as: mount_as.to_owned(),
            addr,
            stats: ProxyStatsHandle::Azure(stats_handle),
            join,
        })
    }

    async fn bind_mysql(
        &self,
        session_id: &str,
        task_id: &str,
        name: &raxis_credentials::CredentialName,
        mount_as: &str,
        restrictions: &MysqlRestrictions,
    ) -> Result<ActiveProxy, ManagerError> {
        let cfg = MysqlProxyConfig {
            listen_addr: "127.0.0.1:0".to_owned(),
            credential_name: name.clone(),
            consumer: MysqlOwnedConsumer::new("session", session_id.to_owned()),
            server_version: "8.0.0-raxis-handshake".to_owned(),
            restrictions: MysqlProxyRestrictions {
                allow_only_select: restrictions.allow_only_select,
                allowed_tables: restrictions.allowed_tables.clone(),
                forbidden_tables: restrictions.forbidden_tables.clone(),
                max_result_rows: restrictions.max_result_rows,
                enforce: restrictions.enforce,
            },
            log_content: false,
        };
        let audit_channel: Arc<dyn MysqlAuditChannel> = Arc::new(MysqlKernelAuditAdapter {
            audit_sink: Arc::clone(&self.audit),
            session_id: session_id.to_owned(),
            task_id: task_id.to_owned(),
        });
        let proxy = MysqlProxy::bind(Arc::clone(&self.backend), cfg, audit_channel)
            .await
            .map_err(|source| ManagerError::MysqlBind {
                credential_name: name.as_str().to_owned(),
                source,
            })?;
        let addr = proxy
            .local_addr()
            .map_err(|source| ManagerError::LocalAddr {
                credential_name: name.as_str().to_owned(),
                source,
            })?;
        let stats_handle = proxy.stats_handle();
        let join = tokio::spawn(async move {
            proxy.serve().await;
        });
        Ok(ActiveProxy {
            proxy_type: "mysql",
            credential_name: name.as_str().to_owned(),
            mount_as: mount_as.to_owned(),
            addr,
            stats: ProxyStatsHandle::Mysql(stats_handle),
            join,
        })
    }

    async fn bind_mssql(
        &self,
        session_id: &str,
        task_id: &str,
        name: &raxis_credentials::CredentialName,
        mount_as: &str,
        restrictions: &MssqlRestrictions,
    ) -> Result<ActiveProxy, ManagerError> {
        let cfg = MssqlProxyConfig {
            listen_addr: "127.0.0.1:0".to_owned(),
            credential_name: name.clone(),
            consumer: MssqlOwnedConsumer::new("session", session_id.to_owned()),
            server_version: "16.0.1000.6-raxis-handshake".to_owned(),
            restrictions: MssqlProxyRestrictions {
                allow_only_select: restrictions.allow_only_select,
                allowed_tables: restrictions.allowed_tables.clone(),
                forbidden_tables: restrictions.forbidden_tables.clone(),
                max_result_rows: restrictions.max_result_rows,
                enforce: restrictions.enforce,
            },
            log_content: false,
        };
        let audit_channel: Arc<dyn MssqlAuditChannel> = Arc::new(MssqlKernelAuditAdapter {
            audit_sink: Arc::clone(&self.audit),
            session_id: session_id.to_owned(),
            task_id: task_id.to_owned(),
        });
        let proxy = MssqlProxy::bind(Arc::clone(&self.backend), cfg, audit_channel)
            .await
            .map_err(|source| ManagerError::MssqlBind {
                credential_name: name.as_str().to_owned(),
                source,
            })?;
        let addr = proxy
            .local_addr()
            .map_err(|source| ManagerError::LocalAddr {
                credential_name: name.as_str().to_owned(),
                source,
            })?;
        let stats_handle = proxy.stats_handle();
        let join = tokio::spawn(async move {
            proxy.serve().await;
        });
        Ok(ActiveProxy {
            proxy_type: "mssql",
            credential_name: name.as_str().to_owned(),
            mount_as: mount_as.to_owned(),
            addr,
            stats: ProxyStatsHandle::Mssql(stats_handle),
            join,
        })
    }

    async fn bind_mongodb(
        &self,
        session_id: &str,
        task_id: &str,
        name: &raxis_credentials::CredentialName,
        mount_as: &str,
        restrictions: &MongodbRestrictions,
    ) -> Result<ActiveProxy, ManagerError> {
        let cfg = MongodbProxyConfig {
            listen_addr: "127.0.0.1:0".to_owned(),
            credential_name: name.clone(),
            consumer: MongodbOwnedConsumer::new("session", session_id.to_owned()),
            restrictions: MongodbProxyRestrictions {
                allow_read_only: restrictions.allow_read_only,
                allowed_collections: restrictions.allowed_collections.clone(),
                forbidden_collections: restrictions.forbidden_collections.clone(),
                max_documents: restrictions.max_documents,
                enforce: restrictions.enforce,
            },
        };
        let audit_channel: Arc<dyn MongodbAuditChannel> = Arc::new(MongodbKernelAuditAdapter {
            audit_sink: Arc::clone(&self.audit),
            session_id: session_id.to_owned(),
            task_id: task_id.to_owned(),
        });
        let proxy = MongodbProxy::bind(Arc::clone(&self.backend), cfg, audit_channel)
            .await
            .map_err(|source| ManagerError::MongodbBind {
                credential_name: name.as_str().to_owned(),
                source,
            })?;
        let addr = proxy
            .local_addr()
            .map_err(|source| ManagerError::LocalAddr {
                credential_name: name.as_str().to_owned(),
                source,
            })?;
        let stats_handle = proxy.stats_handle();
        let join = tokio::spawn(async move {
            proxy.serve().await;
        });
        Ok(ActiveProxy {
            proxy_type: "mongodb",
            credential_name: name.as_str().to_owned(),
            mount_as: mount_as.to_owned(),
            addr,
            stats: ProxyStatsHandle::Mongodb(stats_handle),
            join,
        })
    }
}

// ---------------------------------------------------------------------------
// V3 cloud-forwarding plumbing.
//
// Each `build_*_forwarding` helper turns the plan-credentials
// decl into the proxy-crate-shaped `ForwardingConfig` plus the
// matching `CloudHttpClient` + `TokenCache<T>` instances. The
// CloudHttpClient is bound to the upstream allowlist at
// construction so any future call that hits a different host
// fails closed.
// ---------------------------------------------------------------------------

struct AwsV3 {
    fwd: AwsForwardingConfig,
    http: CloudHttpClient,
    cache: TokenCache<AwsStsCacheValue>,
}

fn build_aws_forwarding(
    credential_name: &str,
    decl: &AwsForwardingDecl,
    role_arn: Option<&str>,
) -> Result<AwsV3, ManagerError> {
    let role_arn = role_arn
        .ok_or_else(|| ManagerError::CloudForwardingConfig {
            credential_name: credential_name.to_owned(),
            detail: "aws forwarding requires `role_arn` on the ProxyDecl".to_owned(),
        })?
        .to_owned();
    if decl.region.is_empty() {
        return Err(ManagerError::CloudForwardingConfig {
            credential_name: credential_name.to_owned(),
            detail: "aws forwarding requires `region`".to_owned(),
        });
    }
    // Spec §7.1 clamp.
    if !(900..=43_200).contains(&decl.duration_seconds) {
        return Err(ManagerError::CloudForwardingConfig {
            credential_name: credential_name.to_owned(),
            detail: format!(
                "aws forwarding duration_seconds={} out of range 900..=43200",
                decl.duration_seconds,
            ),
        });
    }
    let upstream = match decl.endpoint_kind.as_str() {
        "global" => CloudUpstreamHost::aws_global(),
        "regional" => CloudUpstreamHost::aws_regional(&decl.region).map_err(|e| {
            ManagerError::CloudForwardingConfig {
                credential_name: credential_name.to_owned(),
                detail: format!("aws regional STS endpoint failed: {e}"),
            }
        })?,
        other => {
            return Err(ManagerError::CloudForwardingConfig {
                credential_name: credential_name.to_owned(),
                detail: format!("aws endpoint_kind={other:?} not in {{global, regional}}"),
            })
        }
    };
    let http = CloudHttpClient::new(upstream.clone()).map_err(|e| {
        ManagerError::CloudForwardingConfig {
            credential_name: credential_name.to_owned(),
            detail: format!("aws CloudHttpClient construction failed: {e}"),
        }
    })?;
    let safety_window = std::time::Duration::from_secs(decl.cache_safety_window_seconds.max(60));
    let cache = TokenCache::<AwsStsCacheValue>::new(safety_window);
    let fwd = AwsForwardingConfig {
        upstream,
        region: decl.region.clone(),
        role_arn,
        external_id: decl.external_id.clone(),
        duration_seconds: decl.duration_seconds,
        cache_safety_window: safety_window,
    };
    Ok(AwsV3 { fwd, http, cache })
}

struct GcpV3 {
    fwd: GcpForwardingConfig,
    http: CloudHttpClient,
    cache: TokenCache<GcpCacheValue>,
}

fn build_gcp_forwarding(
    credential_name: &str,
    decl: &GcpForwardingDecl,
    fallback_scopes: &[String],
) -> Result<GcpV3, ManagerError> {
    let scopes: Vec<String> = match decl.scopes.as_ref() {
        Some(v) if !v.is_empty() => v.clone(),
        _ => {
            if fallback_scopes.is_empty() {
                return Err(ManagerError::CloudForwardingConfig {
                    credential_name: credential_name.to_owned(),
                    detail: "gcp forwarding requires `scopes` \
                             or `restrictions.allowed_scopes` to be non-empty"
                        .to_owned(),
                });
            }
            fallback_scopes.to_vec()
        }
    };
    let lifetime = decl.jwt_lifetime_seconds.clamp(60, 3_600);
    let upstream = CloudUpstreamHost::gcp_oauth2();
    let http = CloudHttpClient::new(upstream.clone()).map_err(|e| {
        ManagerError::CloudForwardingConfig {
            credential_name: credential_name.to_owned(),
            detail: format!("gcp CloudHttpClient construction failed: {e}"),
        }
    })?;
    let safety_window = std::time::Duration::from_secs(decl.cache_safety_window_seconds.max(60));
    let cache = TokenCache::<GcpCacheValue>::new(safety_window);
    let fwd = GcpForwardingConfig {
        upstream,
        scopes,
        jwt_lifetime: std::time::Duration::from_secs(lifetime),
        cache_safety_window: safety_window,
    };
    Ok(GcpV3 { fwd, http, cache })
}

struct AzureV3 {
    fwd: AzureForwardingConfig,
    http: CloudHttpClient,
    cache: TokenCache<AzureCacheValue>,
}

fn build_azure_forwarding(
    credential_name: &str,
    decl: &AzureForwardingDecl,
) -> Result<AzureV3, ManagerError> {
    let upstream = CloudUpstreamHost::azure_login();
    let http = CloudHttpClient::new(upstream.clone()).map_err(|e| {
        ManagerError::CloudForwardingConfig {
            credential_name: credential_name.to_owned(),
            detail: format!("azure CloudHttpClient construction failed: {e}"),
        }
    })?;
    let safety_window = std::time::Duration::from_secs(decl.cache_safety_window_seconds.max(60));
    let cache = TokenCache::<AzureCacheValue>::new(safety_window);
    let fwd = AzureForwardingConfig {
        upstream,
        cache_safety_window: safety_window,
    };
    Ok(AzureV3 { fwd, http, cache })
}

// ---------------------------------------------------------------------------
// kubeconfig — minimal `cluster.server` extractor.
// ---------------------------------------------------------------------------

mod kubeconfig {
    /// Extract the first `cluster.server` URL from a kubeconfig
    /// YAML body. Returns `None` if no parseable `server:` line
    /// is found inside the first `cluster:` block.
    ///
    /// **Why a tiny line-based parser** (vs. a full YAML
    /// dependency): the V2 kubeconfig surface — generated by
    /// `kubectl config view --minify --raw` and the cluster
    /// fixtures the CredentialProxy tests exercise — has a
    /// well-shaped `clusters: -> cluster: -> server: <url>`
    /// pattern with consistent indentation. A line-based
    /// extractor handles every kubeconfig the V2 tests pass
    /// through it without taking on a YAML parser
    /// (`serde_yaml` is unmaintained; `serde_yaml_ng` is a
    /// fork). When we hit a real-world kubeconfig that breaks
    /// this extractor (anchors, multi-doc, list-of-clusters
    /// selected by `current-context`), the extractor fails
    /// with a structured `ManagerError::KubeconfigResolution`
    /// the operator can act on; at that point we replace it
    /// with a real YAML parser. The extractor is conservative:
    /// only `https?://` schemes are accepted to keep operator
    /// typos from binding the proxy to a non-HTTP upstream.
    pub fn extract_first_cluster_server(body: &str) -> Option<String> {
        // Walk lines top-down. Once we see the *singular* `cluster:`
        // keyword (typically as `- cluster:` inside the
        // `clusters:` list), the next non-comment `server: <url>`
        // line is taken as the upstream URL. We deliberately do
        // NOT accept `clusters:` (the plural list keyword) as the
        // gate — that would match the parent list header.
        let mut after_cluster_keyword = false;
        for raw in body.lines() {
            let line = raw.trim_end();
            let trimmed = line.trim_start();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            // Strip leading `- ` so YAML-list items match the same
            // way as plain mapping entries.
            let key_part = trimmed.strip_prefix("- ").unwrap_or(trimmed);
            if key_part == "cluster:" || key_part.starts_with("cluster:\n") {
                after_cluster_keyword = true;
                continue;
            }
            if after_cluster_keyword {
                if let Some(rest) = trimmed.strip_prefix("server:") {
                    let url = rest.trim().trim_matches('"').trim_matches('\'').to_owned();
                    if url.starts_with("http://") || url.starts_with("https://") {
                        return Some(url);
                    }
                }
            }
        }
        None
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        const KUBECONFIG_BASIC: &str = r#"apiVersion: v1
clusters:
- cluster:
    server: https://cluster.example.com:6443
    insecure-skip-tls-verify: true
  name: prod
contexts:
- context:
    cluster: prod
    user: agent
  name: default
current-context: default
users:
- name: agent
  user:
    token: REDACTED
"#;

        #[test]
        fn extracts_https_server_from_basic_kubeconfig() {
            assert_eq!(
                extract_first_cluster_server(KUBECONFIG_BASIC).as_deref(),
                Some("https://cluster.example.com:6443"),
            );
        }

        #[test]
        fn extracts_quoted_server_url() {
            let body = r#"clusters:
- cluster:
    server: "https://cluster.example.com:443"
"#;
            assert_eq!(
                extract_first_cluster_server(body).as_deref(),
                Some("https://cluster.example.com:443"),
            );
        }

        #[test]
        fn returns_none_when_server_is_missing() {
            let body = r#"clusters:
- cluster:
    name: prod
"#;
            assert_eq!(extract_first_cluster_server(body), None);
        }

        #[test]
        fn returns_none_for_non_http_scheme() {
            let body = r#"clusters:
- cluster:
    server: ssh://cluster.example.com
"#;
            assert_eq!(extract_first_cluster_server(body), None);
        }

        #[test]
        fn returns_none_for_empty_body() {
            assert_eq!(extract_first_cluster_server(""), None);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use raxis_credentials::CredentialName;
    use raxis_credentials_file::FileCredentialBackend;
    use raxis_test_support::FakeAuditSink;

    /// Write a credential body and chmod it to `0600` so
    /// `FileCredentialBackend::validate_path_security` accepts the
    /// file.
    fn write_cred_file(dir: &std::path::Path, name: &str, body: &[u8]) {
        let p = dir.join(name);
        std::fs::write(&p, body).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o600);
            std::fs::set_permissions(&p, perms).unwrap();
        }
    }

    fn build_manager() -> (
        CredentialProxyManager,
        Arc<FakeAuditSink>,
        tempfile::TempDir,
    ) {
        let tmp = tempfile::tempdir().expect("tmpdir");
        // Provision a single credential the postgres bind path can
        // resolve. The body shape doesn't matter for `start_for_session`
        // — we only resolve credentials lazily on the first
        // connection — but `FileCredentialBackend` requires the file
        // to exist for `exists` checks down the road.
        let creds_dir = tmp.path().join("credentials");
        std::fs::create_dir_all(&creds_dir).unwrap();
        // FileCredentialBackend resolves `<name>` → `credentials/<name>.env`.
        write_cred_file(
            &creds_dir,
            "pg-staging.env",
            b"postgresql://raxis@127.0.0.1:5432/test",
        );
        write_cred_file(&creds_dir, "api-key.env", b"sk-test-token-123");
        write_cred_file(
            &creds_dir,
            "k8s-staging.env",
            br#"apiVersion: v1
clusters:
- cluster:
    server: https://cluster.example.com:6443
    insecure-skip-tls-verify: true
  name: prod
contexts:
- context:
    cluster: prod
    user: agent
  name: default
current-context: default
users:
- name: agent
  user:
    token: REDACTED
"#,
        );
        write_cred_file(
            &creds_dir,
            "k8s-broken.env",
            b"# missing clusters block\nfoo: bar\n",
        );
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
            name: CredentialName::new("pg-staging"),
            mount_as: "DATABASE_URL".to_owned(),
            proxy: ProxyDecl::Postgres {
                restrictions: PostgresRestrictions {
                    allow_only_select: false,
                    ..Default::default()
                },
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

        let started_events: Vec<_> = audit
            .events()
            .into_iter()
            .filter(|e| e.kind.as_str() == "CredentialProxyStarted")
            .collect();
        assert_eq!(started_events.len(), 1, "exactly one Started event");
        assert_eq!(started_events[0].session_id.as_deref(), Some("sess-1"));
        assert_eq!(started_events[0].task_id.as_deref(), Some("task-1"));

        let report = handles.shutdown().expect("shutdown");
        assert_eq!(report.stopped.len(), 1);
        assert_eq!(report.stopped[0].proxy_type, "postgres");

        let stopped_events: Vec<_> = audit
            .events()
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
            name: CredentialName::new("api-key"),
            mount_as: "API_BASE_URL".to_owned(),
            proxy: ProxyDecl::Http {
                auth_mode: HttpAuthMode::Bearer,
                upstream_url: "https://api.example.com/v1".to_owned(),
                restrictions: HttpRestrictions::default(),
            },
        }];

        let handles = mgr
            .start_for_session("sess-2", "task-2", &decls)
            .await
            .expect("start");
        assert_eq!(handles.len(), 1);

        let started_events: Vec<_> = audit
            .events()
            .into_iter()
            .filter(|e| e.kind.as_str() == "CredentialProxyStarted")
            .collect();
        assert_eq!(started_events.len(), 1);

        let report = handles.shutdown().expect("shutdown");
        assert_eq!(report.stopped.len(), 1);
        assert_eq!(report.stopped[0].proxy_type, "http");
    }

    #[tokio::test]
    async fn start_then_shutdown_emits_paired_audit_events_for_smtp() {
        let (mgr, audit, tmp) = build_manager();
        // Provision an SMTP credential body. The wire driver only
        // resolves it lazily when a real envelope is forwarded; the
        // bind itself does not need the credential present, but
        // `FileCredentialBackend::exists` is invoked elsewhere so we
        // give it a real file.
        write_cred_file(
            &tmp.path().join("credentials"),
            "smtp-staging.env",
            b"plaintext-smtp-password",
        );

        let decls = vec![TaskCredentialDecl {
            name: CredentialName::new("smtp-staging"),
            mount_as: "SMTP_URL".to_owned(),
            proxy: ProxyDecl::Smtp {
                auth_mode: SmtpAuthMode::Plain {
                    user: "smtp-user".to_owned(),
                },
                upstream_host_port: "127.0.0.1:1".to_owned(),
                require_upstream_tls: false,
                restrictions: SmtpRestrictions {
                    allowed_sender_address: Some("noreply@example.com".to_owned()),
                    allowed_recipient_domains: vec!["customers.example.com".to_owned()],
                    max_recipients_per_message: Some(10),
                    max_message_bytes: Some(64 * 1024),
                    max_messages_per_minute: Some(60),
                },
            },
        }];

        let handles = mgr
            .start_for_session("sess-smtp", "task-smtp", &decls)
            .await
            .expect("smtp bind should succeed");
        assert_eq!(handles.len(), 1);
        let summaries = handles.started_summaries();
        assert_eq!(summaries[0].proxy_type, "smtp");
        assert_eq!(summaries[0].mount_as, "SMTP_URL");

        // SMTP loopback URL is a bare `host:port` (no scheme).
        let env = handles.loopback_env();
        let smtp_url = env.get("SMTP_URL").expect("env var present");
        assert!(
            smtp_url.starts_with("127.0.0.1:"),
            "expected loopback host:port for smtp, got {smtp_url:?}",
        );
        assert!(
            !smtp_url.contains("://"),
            "smtp loopback must not embed a scheme, got {smtp_url:?}",
        );

        let started_events: Vec<_> = audit
            .events()
            .into_iter()
            .filter(|e| e.kind.as_str() == "CredentialProxyStarted")
            .collect();
        assert_eq!(started_events.len(), 1);
        assert_eq!(started_events[0].session_id.as_deref(), Some("sess-smtp"));

        let report = handles.shutdown().expect("smtp shutdown");
        assert_eq!(report.stopped.len(), 1);
        assert_eq!(report.stopped[0].proxy_type, "smtp");

        let stopped_events: Vec<_> = audit
            .events()
            .into_iter()
            .filter(|e| e.kind.as_str() == "CredentialProxyStopped")
            .collect();
        assert_eq!(stopped_events.len(), 1);
    }

    #[tokio::test]
    async fn unknown_proxy_type_is_rejected_before_audit_emission() {
        let (mgr, audit, _tmp) = build_manager();

        let decls = vec![TaskCredentialDecl {
            name: CredentialName::new("smtp-creds"),
            mount_as: "SMTP_URL".to_owned(),
            proxy: ProxyDecl::Unknown,
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
        let started_events: Vec<_> = audit
            .events()
            .into_iter()
            .filter(|e| e.kind.as_str() == "CredentialProxyStarted")
            .collect();
        assert!(started_events.is_empty());
    }

    #[tokio::test]
    async fn k8s_proxy_decl_binds_using_kubeconfig_server_url() {
        let (mgr, audit, _tmp) = build_manager();

        let decls = vec![TaskCredentialDecl {
            name: CredentialName::new("k8s-staging"),
            mount_as: "KUBECONFIG".to_owned(),
            proxy: ProxyDecl::K8s {
                restrictions: HttpRestrictions::default(),
            },
        }];

        let handles = mgr
            .start_for_session("sess-4", "task-4", &decls)
            .await
            .expect("k8s bind should succeed when kubeconfig has a server URL");
        let summaries = handles.started_summaries();
        assert_eq!(summaries.len(), 1);
        assert_eq!(summaries[0].proxy_type, "k8s");
        assert_eq!(summaries[0].mount_as, "KUBECONFIG");

        let env = handles.loopback_env();
        let kubeconfig_url = env.get("KUBECONFIG").expect("env var present");
        assert!(
            kubeconfig_url.starts_with("http://127.0.0.1:"),
            "expected loopback http URL, got {kubeconfig_url}",
        );

        let started_events: Vec<_> = audit
            .events()
            .into_iter()
            .filter(|e| e.kind.as_str() == "CredentialProxyStarted")
            .collect();
        assert_eq!(started_events.len(), 1);

        let report = handles.shutdown().expect("shutdown");
        assert_eq!(report.stopped[0].proxy_type, "k8s");
    }

    #[tokio::test]
    async fn k8s_proxy_decl_with_broken_kubeconfig_surfaces_resolution_error() {
        let (mgr, audit, _tmp) = build_manager();

        let decls = vec![TaskCredentialDecl {
            name: CredentialName::new("k8s-broken"),
            mount_as: "KUBECONFIG".to_owned(),
            proxy: ProxyDecl::K8s {
                restrictions: HttpRestrictions::default(),
            },
        }];

        let err = mgr
            .start_for_session("sess-4b", "task-4b", &decls)
            .await
            .err()
            .expect("broken kubeconfig should be rejected");
        match err {
            ManagerError::KubeconfigResolution {
                credential_name,
                detail,
            } => {
                assert_eq!(credential_name, "k8s-broken");
                assert!(
                    detail.contains("server"),
                    "diagnostic should mention server URL: {detail}",
                );
            }
            other => panic!("expected KubeconfigResolution, got {other:?}"),
        }
        // No audit emission for a failed bind.
        let started_events: Vec<_> = audit
            .events()
            .into_iter()
            .filter(|e| e.kind.as_str() == "CredentialProxyStarted")
            .collect();
        assert!(started_events.is_empty());
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
        let cred_events: Vec<_> = audit
            .events()
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
                name: CredentialName::new("pg-staging"),
                mount_as: "DATABASE_URL".to_owned(),
                proxy: ProxyDecl::Postgres {
                    restrictions: PostgresRestrictions {
                        allow_only_select: true,
                        ..Default::default()
                    },
                },
            },
            TaskCredentialDecl {
                name: CredentialName::new("api-key"),
                mount_as: "API_BASE_URL".to_owned(),
                proxy: ProxyDecl::Http {
                    auth_mode: HttpAuthMode::Bearer,
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

        let started: Vec<&'static str> = audit
            .events()
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

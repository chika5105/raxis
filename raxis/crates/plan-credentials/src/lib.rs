//! `raxis-plan-credentials` — strict parser for the
//! `[[tasks.credentials]]` sub-table declared in operator-signed
//! plan TOML.
//!
//! Normative reference: `specs/v2/credential-proxy.md §3` (per-proxy
//! TOML schemas) and `§11` (operator config guide).
//!
//! ## What this crate does
//!
//! Given a parsed `toml::Value` for a single `[[tasks]]` block, it
//! extracts a `Vec<TaskCredentialDecl>`, mapping each
//! `[[tasks.credentials]]` entry to one of the typed proxy variants.
//! Failure modes are structured: the caller can surface a precise
//! diagnostic to the operator without re-walking the TOML.
//!
//! ## What this crate does NOT do
//!
//! - It does NOT touch the credential backend (no `Arc<dyn
//!   CredentialBackend>` parameter; resolution happens at proxy-bind
//!   time, not at parse time).
//! - It does NOT spin up listeners. That is the job of the kernel-side
//!   `CredentialProxyManager` (forthcoming) once the V2 VM-spawn
//!   callsites land.
//! - It does NOT validate that the policy actually permits the
//!   declared credential. That gate runs in `approve_plan`'s
//!   structural validators alongside the existing path-allowlist
//!   check.
//!
//! ## Why a separate crate
//!
//! `kernel/src/initiatives/lifecycle.rs` is already 4000+ lines. The
//! plan parser owns its own complexity envelope; pushing the
//! credential-decl parser into a focused crate keeps the surface
//! reviewable and unit-testable in isolation. The kernel will pull
//! in `raxis-plan-credentials` and call `parse_for_task(&task_value)
//! -> Result<Vec<TaskCredentialDecl>, _>` from `parse_plan_tasks`
//! when the wiring lands.

#![deny(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use raxis_credentials::CredentialName;

/// One `[[tasks.credentials]]` entry from a `[[tasks]]` block in plan
/// TOML.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskCredentialDecl {
    /// Policy-declared credential name. The kernel resolves the
    /// VALUE through `CredentialBackend::resolve` at proxy-bind
    /// time. NEVER the value.
    pub name:       CredentialName,
    /// Environment variable name the agent VM gets injected with;
    /// the value is the proxy's loopback URL (e.g.
    /// `postgresql://raxis@127.0.0.1:54321/` for Postgres,
    /// `http://127.0.0.1:54322` for HTTP proxies). The actual
    /// credential value is never exposed — only the proxy address.
    ///
    /// When a task declares multiple credentials of the same proxy
    /// type (e.g. two Postgres databases), each MUST have a distinct
    /// `mount_as` name. Use explicit, descriptive names:
    ///   - `USERS_DATABASE_URL` / `ANALYTICS_DATABASE_URL` (not `DATABASE_URL`)
    ///   - `CACHE_REDIS_URL` / `QUEUE_REDIS_URL` (not `REDIS_URL`)
    /// A generic name like `DATABASE_URL` is only appropriate when
    /// exactly one credential of that type is declared.
    pub mount_as:   String,
    /// Concrete proxy shape — determines which proxy implementation
    /// the kernel binds for this credential.
    pub proxy:      ProxyDecl,
}

/// Concrete proxy shape declared in `[[tasks.credentials]]`. Each
/// variant carries the proxy-specific options — every option that
/// ships in V2's `credential-proxy.md §3` lives here as a typed
/// field, not as a free-form TOML hashmap.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "proxy_type", rename_all = "lowercase")]
pub enum ProxyDecl {
    /// `proxy_type = "postgres"` — see `credential-proxy.md §4`.
    Postgres {
        /// Restrictions clause (`[tasks.credentials.restrictions]`).
        #[serde(default)]
        restrictions: PostgresRestrictions,
    },
    /// `proxy_type = "http"` — see `credential-proxy.md §3.5`. The
    /// MVP supports `Bearer` and `Basic` auth modes against a
    /// single pinned upstream URL.
    Http {
        /// Authentication mode for upstream injection.
        #[serde(default = "default_http_auth_mode")]
        auth_mode: HttpAuthMode,
        /// Single pinned upstream URL the agent's traffic is
        /// forwarded to.
        upstream_url: String,
        /// Restrictions clause (`[tasks.credentials.restrictions]`).
        #[serde(default)]
        restrictions: HttpRestrictions,
    },
    /// `proxy_type = "k8s"` — convenience over `Http` with a
    /// fixed `auth_mode = "bearer"` and the upstream URL inferred
    /// from `kubeconfig.server` at proxy-bind time.
    K8s {
        /// Restrictions clause.
        #[serde(default)]
        restrictions: HttpRestrictions,
    },
    /// `proxy_type = "smtp"` — see `credential-proxy.md §3` ("SMTP
    /// relay"). The proxy injects the relay's username + password
    /// (resolved through `CredentialBackend`) and forwards the
    /// envelope to a single pinned upstream `host:port`. The agent
    /// inside the VM dials a localhost SMTP-shaped socket; envelope
    /// sender, recipient domains, and message size / rate are gated
    /// by `[tasks.credentials.restrictions]`.
    Smtp {
        /// Authentication mode for upstream injection (`AUTH PLAIN`
        /// or `AUTH LOGIN`).
        #[serde(default = "default_smtp_auth_mode")]
        auth_mode: SmtpAuthMode,
        /// Single pinned upstream relay `host:port` (no scheme).
        upstream_host_port: String,
        /// Whether the proxy MUST establish an outbound TLS session
        /// (via STARTTLS upgrade) to the upstream relay before
        /// issuing AUTH. When `true` the wire driver drives
        /// `EHLO → STARTTLS → tokio-rustls handshake → re-EHLO over
        /// TLS → AUTH`, fails closed on any STARTTLS rejection or
        /// handshake error, and rejects builds whose proxy crate has
        /// `IS_TLS_WIRED = false` at bind time. When `false` the
        /// upstream hop is plain TCP.
        #[serde(default)]
        require_upstream_tls: bool,
        /// Restrictions clause (`[tasks.credentials.restrictions]`).
        #[serde(default)]
        restrictions: SmtpRestrictions,
    },
    /// `proxy_type = "redis"` — see `credential-proxy.md §4.5`.
    /// The Redis proxy intercepts the agent-issued `AUTH` /
    /// `HELLO` commands, authenticates upstream with the real
    /// credential resolved through `CredentialBackend`, and
    /// forwards every other command verbatim subject to the
    /// allowlist in `[tasks.credentials.restrictions]`.
    Redis {
        /// Single pinned upstream Redis `host:port` (no scheme).
        upstream_host_port: String,
        /// Wrap the upstream TCP socket in TLS before AUTH.
        /// Required by managed Redis offerings (AWS Elasticache,
        /// GCP Memorystore, Azure Cache for Redis). Defaults to
        /// `false` so self-hosted deployments where the upstream
        /// is a sibling on a private bridge network keep the
        /// historical plaintext path.
        #[serde(default)]
        require_upstream_tls: bool,
        /// Restrictions clause (`[tasks.credentials.restrictions]`).
        #[serde(default)]
        restrictions: RedisRestrictions,
    },
    /// `proxy_type = "aws"` — see `credential-proxy.md §3.2`. The
    /// AWS proxy implements the
    /// `AWS_CONTAINER_CREDENTIALS_FULL_URI` provider shape so AWS
    /// SDKs (boto3, aws-sdk-rust, terraform-aws) authenticate
    /// against the kernel's `CredentialBackend` without the IAM
    /// access key bytes ever crossing the VM boundary.
    Aws {
        /// Optional IAM role ARN echoed in the SDK response body.
        /// V2 does NOT call `sts:AssumeRole`; this field is
        /// audit/observability only.
        #[serde(default)]
        role_arn: Option<String>,
        /// Lease length the proxy advertises in the SDK response's
        /// `Expiration` field. SDKs will refresh shortly before
        /// this window closes. Defaults to 900 seconds (15 min)
        /// matching the AWS SDK default.
        #[serde(default = "default_aws_lease_seconds")]
        lease_seconds: u64,
        /// Restrictions clause (`[tasks.credentials.restrictions]`).
        #[serde(default)]
        restrictions: AwsRestrictions,
    },
    /// `proxy_type = "gcp"` — see `credential-proxy.md §3.3`. The
    /// GCP proxy emulates the Compute Engine metadata server.
    /// `google-auth-library`, `google-cloud-storage`, the `gcloud`
    /// CLI's application-default flow, and the Terraform `google`
    /// provider all reach for `metadata.google.internal`; the
    /// agent's VM `/etc/hosts` redirects that name to the proxy.
    Gcp {
        /// GCP project ID, returned by
        /// `/computeMetadata/v1/project/project-id`.
        project: String,
        /// Optional numeric project ID, returned by
        /// `/computeMetadata/v1/project/numeric-project-id`. When
        /// `None`, the proxy returns `"0"` so SDKs that demand the
        /// field do not panic.
        #[serde(default)]
        numeric_project: Option<u64>,
        /// Lease length advertised in `expires_in`. Defaults to
        /// 3600 seconds (1 hour) matching the GCP metadata-server
        /// default.
        #[serde(default = "default_gcp_lease_seconds")]
        lease_seconds: u64,
        /// Restrictions clause (`[tasks.credentials.restrictions]`).
        #[serde(default)]
        restrictions: GcpRestrictions,
    },
    /// `proxy_type = "azure"` — see `credential-proxy.md §3.4`. The
    /// Azure proxy emulates the Azure Instance Metadata Service
    /// (IMDS). `azure-identity`, `Azure.Identity` (.NET),
    /// `@azure/identity` (Node), and `az` CLI's
    /// `ManagedIdentityCredential` reach for `169.254.169.254`; the
    /// agent's VM iptables NAT redirects that IP to the proxy.
    Azure {
        /// Azure tenant ID. Audit-only at proxy-bind time; not echoed
        /// in the IMDS body.
        tenant_id: String,
        /// Optional managed-identity client ID echoed back in the
        /// IMDS response body. Useful for SDKs that record the
        /// identity that minted the token.
        #[serde(default)]
        client_id: Option<String>,
        /// Lease length advertised in `expires_in`. Defaults to
        /// 3600 seconds (1 hour) matching the Azure IMDS default.
        #[serde(default = "default_azure_lease_seconds")]
        lease_seconds: u64,
        /// Resource URI allowlist
        /// (`[tasks.credentials.restrictions].allowed_resources`).
        /// REQUIRED — empty allowlist blocks every request.
        #[serde(default)]
        restrictions: AzureRestrictions,
    },
    /// `proxy_type = "mysql"` — see `credential-proxy.md §4.2`.
    /// MySQL wire-protocol handshake-tier proxy.
    Mysql {
        /// Restrictions clause.
        #[serde(default)]
        restrictions: MysqlRestrictions,
    },
    /// `proxy_type = "mssql"` — see `credential-proxy.md §4.3`.
    /// Microsoft SQL Server TDS handshake-tier proxy.
    Mssql {
        /// Restrictions clause.
        #[serde(default)]
        restrictions: MssqlRestrictions,
    },
    /// `proxy_type = "mongodb"` — see `credential-proxy.md §4.4`.
    /// MongoDB OP_MSG handshake-tier proxy.
    Mongodb {
        /// Restrictions clause.
        #[serde(default)]
        restrictions: MongodbRestrictions,
    },
    /// Catch-all for proxy types declared in policy but not yet
    /// implemented. The parser preserves the literal `proxy_type`
    /// string so the validator can map it to a clear "not
    /// implemented in V2" diagnostic without losing information.
    #[serde(other)]
    Unknown,
}

fn default_http_auth_mode() -> HttpAuthMode { HttpAuthMode::Bearer }

fn default_smtp_auth_mode() -> SmtpAuthMode {
    SmtpAuthMode::Plain { user: String::new() }
}

fn default_aws_lease_seconds() -> u64 { 900 }

fn default_gcp_lease_seconds() -> u64 { 3600 }

fn default_azure_lease_seconds() -> u64 { 3600 }

/// HTTP-proxy authentication mode (mirrors
/// `raxis_credential_proxy_http::AuthMode`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HttpAuthMode {
    /// `Authorization: Bearer <value>`.
    Bearer,
    /// `Authorization: Basic base64(<user>:<value>)`.
    Basic {
        /// Username placed before the colon.
        user: String,
    },
}

/// SMTP-proxy authentication mode (mirrors
/// `raxis_credential_proxy_smtp::AuthMode`).
///
/// `Plain` is the default operator choice — RFC 4954 `AUTH PLAIN`
/// accepts the username and password in a single base64-encoded
/// `\\0user\\0password` payload, which is the simplest shape for
/// well-behaved relays. `Login` is provided for relays whose ACL
/// rejects `AUTH PLAIN` outright; behaviourally equivalent on the
/// kernel side.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum SmtpAuthMode {
    /// `AUTH PLAIN` — single-shot base64 user/password payload.
    Plain {
        /// Username placed before the credential value.
        #[serde(default)]
        user: String,
    },
    /// `AUTH LOGIN` — base64 username followed by a separate
    /// base64 password line.
    Login {
        /// Username placed in the first AUTH LOGIN line.
        #[serde(default)]
        user: String,
    },
}

/// Postgres restrictions
/// (`[tasks.credentials.restrictions]` for `proxy_type = "postgres"`).
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PostgresRestrictions {
    /// When `true`, DML/DDL statements are rejected at the proxy
    /// with sqlstate `42501`.
    #[serde(default)]
    pub allow_only_select: bool,
}

/// HTTP/k8s restrictions
/// (`[tasks.credentials.restrictions]` for `proxy_type = "http"`
/// or `"k8s"`).
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpRestrictions {
    /// Methods the proxy will forward (case-insensitive). Empty =
    /// unrestricted.
    #[serde(default)]
    pub allowed_methods: Vec<String>,
    /// Path prefixes the proxy will forward. Empty = unrestricted.
    #[serde(default)]
    pub allowed_path_prefixes: Vec<String>,
}

/// SMTP restrictions
/// (`[tasks.credentials.restrictions]` for `proxy_type = "smtp"`).
///
/// Mirrors `raxis_credential_proxy_smtp::Restrictions`. Empty values
/// (or `None` on the optional fields) mean unrestricted on that
/// axis; production deployments SHOULD pin every field that makes
/// sense for the upstream relay.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SmtpRestrictions {
    /// Single allowed `MAIL FROM:` envelope sender address. When
    /// `None`, the sender address is unrestricted.
    #[serde(default)]
    pub allowed_sender_address: Option<String>,
    /// Allowlisted recipient domains (compared case-insensitively
    /// against the part after `@`). Empty = unrestricted.
    #[serde(default)]
    pub allowed_recipient_domains: Vec<String>,
    /// Cap on `RCPT TO` count per envelope. `None` = uncapped.
    #[serde(default)]
    pub max_recipients_per_message: Option<u32>,
    /// Cap on the DATA-stage message body in bytes. `None` =
    /// uncapped.
    #[serde(default)]
    pub max_message_bytes: Option<u64>,
    /// Rolling rate cap (messages successfully forwarded per
    /// 60-second window). `None` = unrestricted.
    #[serde(default)]
    pub max_messages_per_minute: Option<u32>,
}

/// Redis restrictions
/// (`[tasks.credentials.restrictions]` for `proxy_type = "redis"`).
///
/// Mirrors `raxis_credential_proxy_redis::Restrictions`. The proxy
/// always intercepts `AUTH` and `HELLO`; `allowed_commands` gates
/// every other verb. Empty allowlist = unrestricted.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RedisRestrictions {
    /// Case-insensitive command allowlist. Empty = unrestricted.
    #[serde(default)]
    pub allowed_commands: Vec<String>,
}

/// AWS restrictions
/// (`[tasks.credentials.restrictions]` for `proxy_type = "aws"`).
///
/// Mirrors `raxis_credential_proxy_aws::Restrictions`. The proxy
/// only ever serves the path allowlist; everything else gets a
/// `403 Forbidden`. Default permits the canonical `/creds`
/// endpoint that AWS SDKs use when
/// `AWS_CONTAINER_CREDENTIALS_FULL_URI` is set.
///
/// `allowed_services` / `allowed_regions` carry operator-declared
/// scope intent (e.g. `["s3", "sqs"]` / `["us-east-1"]`). V2.3
/// enforces these declaratively (audit echo + `raxis doctor`
/// cross-check against the egress allowlist); the V3 SigV4-aware
/// egress proxy adds runtime enforcement. See
/// `credential-proxy-aws::restriction` module doc for the V2.3 →
/// V3 transition contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AwsRestrictions {
    /// Paths the proxy will serve. Defaults to `["/creds"]`.
    #[serde(default = "default_aws_allowed_paths")]
    pub allowed_paths: Vec<String>,

    /// AWS service names (lowercase, e.g. `"s3"`, `"sqs"`,
    /// `"dynamodb"`) the agent's tasks are intended to call.
    /// Empty (the default) means "no service-level intent
    /// declared".
    #[serde(default)]
    pub allowed_services: Vec<String>,

    /// AWS region IDs (e.g. `"us-east-1"`, `"eu-west-2"`) the
    /// agent's tasks are intended to use. Empty means "no
    /// region scoping declared".
    #[serde(default)]
    pub allowed_regions: Vec<String>,
}

impl Default for AwsRestrictions {
    fn default() -> Self {
        Self {
            allowed_paths:    default_aws_allowed_paths(),
            allowed_services: Vec::new(),
            allowed_regions:  Vec::new(),
        }
    }
}

fn default_aws_allowed_paths() -> Vec<String> {
    vec!["/creds".to_owned()]
}

/// GCP restrictions
/// (`[tasks.credentials.restrictions]` for `proxy_type = "gcp"`).
///
/// Mirrors `raxis_credential_proxy_gcp::Restrictions`. The proxy
/// only ever serves the path allowlist; everything else gets a
/// `404 Not Found`. Default permits the four canonical GCP
/// metadata-server endpoints (`/computeMetadata/v1/...`) that
/// `google-auth-library` and `gcloud` walk through.
///
/// `allowed_scopes` and `project` carry V2.3 declarative scope
/// intent. See `credential-proxy-gcp::restriction` module doc for
/// the V2.3 enforcement contract (audit echo + token-response
/// scope narrowing) and the V3 deferral story (token-exchange
/// API for genuinely scope-narrowed credentials).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GcpRestrictions {
    /// Paths the proxy will serve. Defaults to the four canonical
    /// metadata-server endpoints.
    #[serde(default = "default_gcp_allowed_paths")]
    pub allowed_paths: Vec<String>,

    /// OAuth scopes the operator declares the agent will use
    /// (e.g.
    /// `["https://www.googleapis.com/auth/devstorage.read_only"]`).
    /// Empty (the default) means "no scope-level intent declared".
    #[serde(default)]
    pub allowed_scopes: Vec<String>,

    /// GCP project ID the agent's tasks are intended to operate
    /// on. When non-empty the proxy bind step asserts equality
    /// with the proxy's configured `project_id`. Empty means "no
    /// project pinning declared".
    #[serde(default)]
    pub project: String,
}

impl Default for GcpRestrictions {
    fn default() -> Self {
        Self {
            allowed_paths:  default_gcp_allowed_paths(),
            allowed_scopes: Vec::new(),
            project:        String::new(),
        }
    }
}

fn default_gcp_allowed_paths() -> Vec<String> {
    vec![
        "/computeMetadata/v1/instance/service-accounts/default/token".to_owned(),
        "/computeMetadata/v1/instance/service-accounts/default/email".to_owned(),
        "/computeMetadata/v1/project/project-id".to_owned(),
        "/computeMetadata/v1/project/numeric-project-id".to_owned(),
    ]
}

/// MySQL restrictions
/// (`[tasks.credentials.restrictions]` for `proxy_type = "mysql"`).
///
/// Mirrors `raxis_credential_proxy_mysql::Restrictions`. The
/// `allow_only_select` flag is the only V2 MVP knob — when set,
/// every COM_QUERY whose first statement is not a `SELECT` /
/// `WITH … SELECT` / `SHOW` / `EXPLAIN … SELECT` is rejected with
/// an `ERR_Packet { code = 1142, sqlstate = "42501" }`.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MysqlRestrictions {
    /// If `true`, only `SELECT`-shaped statements pass; everything
    /// else is rejected at the proxy.
    #[serde(default)]
    pub allow_only_select: bool,
}

/// MSSQL restrictions
/// (`[tasks.credentials.restrictions]` for `proxy_type = "mssql"`).
///
/// Mirrors `raxis_credential_proxy_mssql::Restrictions`. Behaves
/// identically to `MysqlRestrictions` — the V2 wire surface for
/// both is "classify the first SQL token; reject DML/DDL when
/// `allow_only_select` is true".
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MssqlRestrictions {
    /// If `true`, only `SELECT`-shaped statements pass; everything
    /// else is rejected at the proxy with an `ERROR` token.
    #[serde(default)]
    pub allow_only_select: bool,
}

/// MongoDB restrictions
/// (`[tasks.credentials.restrictions]` for `proxy_type = "mongodb"`).
///
/// Mirrors `raxis_credential_proxy_mongodb::Restrictions`. The
/// `allow_read_only` flag is the only V2 MVP knob — when set,
/// every command document whose first field name is not a known
/// MongoDB read command is rejected with
/// `{ ok: 0, code: 13, codeName: "Unauthorized" }`.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MongodbRestrictions {
    /// If `true`, only read-only command names pass; everything
    /// else (insert / update / delete / findAndModify / etc.) is
    /// rejected at the proxy.
    #[serde(default)]
    pub allow_read_only: bool,
}

/// Azure restrictions
/// (`[tasks.credentials.restrictions]` for `proxy_type = "azure"`).
///
/// Mirrors `raxis_credential_proxy_azure::Restrictions`. Azure IMDS
/// uses a single path (`/metadata/identity/oauth2/token`) for every
/// resource; scoping happens through the `?resource=...` query
/// parameter. The proxy refuses to mint tokens for resources outside
/// `allowed_resources`, even if the agent passes an arbitrary URI.
///
/// `allowed_actions` carries V2.3 declarative per-resource ARM
/// action filtering. The proxy surfaces the matching action set in
/// the token response's `x-ms-allowed-actions` header and the audit
/// envelope; runtime ARM-URL gating is V3 work. See
/// `credential-proxy-azure::restriction` module doc for the full
/// V2.3 → V3 transition contract.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AzureRestrictions {
    /// Azure resource URIs (e.g. `"https://management.azure.com/"`,
    /// `"https://database.windows.net/"`) the proxy will mint tokens
    /// for. Empty list means "block everything".
    #[serde(default)]
    pub allowed_resources: Vec<String>,

    /// Per-resource ARM action vocabulary. Each entry pairs a
    /// resource URI (which MUST appear in `allowed_resources`)
    /// with the ARM verbs the agent's task is intended to perform
    /// (e.g. `Microsoft.Storage/storageAccounts/read`). Empty
    /// (the default) means "no action-level intent declared".
    #[serde(default)]
    pub allowed_actions: Vec<AzureResourceActions>,
}

/// One `(resource, [action, action, ...])` association declared
/// in `AzureRestrictions::allowed_actions`. Mirrors
/// `raxis_credential_proxy_azure::restriction::ResourceActions`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AzureResourceActions {
    /// Azure resource URI this action set applies to.
    pub resource: String,
    /// ARM action verbs.
    #[serde(default)]
    pub actions: Vec<String>,
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Failure modes surfaced by `parse_for_task`.
#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    /// The `[[tasks.credentials]]` array is structurally malformed
    /// (e.g. a non-table element, or missing required field).
    #[error("[[tasks.credentials]] entry {index} of task {task_id:?}: {detail}")]
    Malformed {
        /// Index within the tasks.credentials array.
        index:   usize,
        /// Owning task id from the plan TOML.
        task_id: String,
        /// Free-form diagnostic.
        detail:  String,
    },
    /// Two `[[tasks.credentials]]` entries in the same task declare
    /// the same `mount_as` env-var name. The second would overwrite
    /// the first in the agent's environment, silently making one
    /// proxy unreachable. Caught at plan admission (shift-left) so
    /// the operator gets an immediate, actionable diagnostic.
    #[error("task {task_id:?}: duplicate mount_as `{mount_as}` on credentials `{first}` and `{second}`")]
    DuplicateMountAs {
        /// Owning task id.
        task_id:  String,
        /// The colliding env-var name.
        mount_as: String,
        /// Credential name of the first declaration.
        first:    String,
        /// Credential name of the second declaration.
        second:   String,
    },
    /// The TOML value carrying the task block is not actually a table.
    #[error("[[tasks]] entry is not a table")]
    TaskNotTable,
}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

/// Parse the `[[tasks.credentials]]` sub-array from a single
/// `[[tasks]]` block. Returns an empty vector when the sub-array is
/// absent.
pub fn parse_for_task(task_value: &toml::Value) -> Result<Vec<TaskCredentialDecl>, ParseError> {
    let task_table = task_value
        .as_table()
        .ok_or(ParseError::TaskNotTable)?;
    let task_id = task_table
        .get("task_id")
        .and_then(|v| v.as_str())
        .unwrap_or("<unknown>")
        .to_owned();

    let arr = match task_table.get("credentials") {
        Some(toml::Value::Array(a)) => a,
        Some(other) => {
            return Err(ParseError::Malformed {
                index:   0,
                task_id,
                detail:  format!(
                    "credentials must be a TOML array of tables, got {}",
                    other.type_str(),
                ),
            });
        }
        None => return Ok(Vec::new()),
    };

    let mut out = Vec::with_capacity(arr.len());
    for (i, entry) in arr.iter().enumerate() {
        let parsed = parse_one_decl(entry).map_err(|detail| ParseError::Malformed {
            index:   i,
            task_id: task_id.clone(),
            detail,
        })?;
        out.push(parsed);
    }

    // ── Shift-left: validate mount_as uniqueness at parse time ────
    // Duplicate mount_as values would silently overwrite each other
    // in the agent's env. Catch it here at plan admission so the
    // operator gets an immediate diagnostic, not a mysterious
    // "proxy unreachable" at session runtime.
    {
        let mut seen = std::collections::BTreeMap::<&str, &str>::new();
        for decl in &out {
            if let Some(&first_name) = seen.get(decl.mount_as.as_str()) {
                return Err(ParseError::DuplicateMountAs {
                    task_id:  task_id.clone(),
                    mount_as: decl.mount_as.clone(),
                    first:    first_name.to_owned(),
                    second:   decl.name.as_str().to_owned(),
                });
            }
            seen.insert(&decl.mount_as, decl.name.as_str());
        }
    }

    Ok(out)
}

fn parse_one_decl(value: &toml::Value) -> Result<TaskCredentialDecl, String> {
    let table = value.as_table()
        .ok_or_else(|| "entry must be a TOML table".to_owned())?;

    let name_str = table.get("name")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "missing required `name`".to_owned())?;
    let name = CredentialName::new(name_str);
    let mount_as = table.get("mount_as")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "missing required `mount_as`".to_owned())?
        .to_owned();
    let proxy_type = table.get("proxy_type")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "missing required `proxy_type`".to_owned())?;

    // Decode the variant. We re-serialize the table without the
    // `name` / `mount_as` fields and let serde do the heavy lifting.
    let mut variant_table = table.clone();
    variant_table.remove("name");
    variant_table.remove("mount_as");
    let proxy: ProxyDecl = toml::Value::Table(variant_table)
        .try_into()
        .map_err(|e| format!("failed to decode proxy variant {proxy_type:?}: {e}"))?;

    Ok(TaskCredentialDecl { name, mount_as, proxy })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(input: &str) -> Result<Vec<TaskCredentialDecl>, ParseError> {
        let doc: toml::Value = toml::from_str(input).expect("valid toml");
        let task = doc.get("tasks")
            .and_then(|v| v.as_array())
            .and_then(|a| a.first())
            .expect("tasks[0]");
        parse_for_task(task)
    }

    #[test]
    fn no_credentials_yields_empty_vec() {
        let toml = r#"
            [[tasks]]
            task_id = "demo"
        "#;
        assert!(parse(toml).unwrap().is_empty());
    }

    #[test]
    fn parses_postgres_decl_with_default_restrictions() {
        let toml = r#"
            [[tasks]]
            task_id = "demo"

              [[tasks.credentials]]
              name       = "db-staging"
              proxy_type = "postgres"
              mount_as   = "DATABASE_URL"
        "#;
        let decls = parse(toml).unwrap();
        assert_eq!(decls.len(), 1);
        assert_eq!(decls[0].name.as_str(), "db-staging");
        assert_eq!(decls[0].mount_as, "DATABASE_URL");
        match &decls[0].proxy {
            ProxyDecl::Postgres { restrictions } => {
                assert!(!restrictions.allow_only_select);
            }
            other => panic!("expected Postgres, got {other:?}"),
        }
    }

    #[test]
    fn parses_postgres_decl_with_allow_only_select() {
        let toml = r#"
            [[tasks]]
            task_id = "demo"

              [[tasks.credentials]]
              name       = "db-prod-readonly"
              proxy_type = "postgres"
              mount_as   = "DATABASE_URL"

                [tasks.credentials.restrictions]
                allow_only_select = true
        "#;
        let decls = parse(toml).unwrap();
        assert_eq!(decls.len(), 1);
        match &decls[0].proxy {
            ProxyDecl::Postgres { restrictions } => {
                assert!(restrictions.allow_only_select);
            }
            other => panic!("expected Postgres, got {other:?}"),
        }
    }

    #[test]
    fn parses_http_bearer() {
        let toml = r#"
            [[tasks]]
            task_id = "demo"

              [[tasks.credentials]]
              name         = "kube-prod"
              proxy_type   = "http"
              mount_as     = "KUBECONFIG"
              auth_mode    = "bearer"
              upstream_url = "https://k8s.example.com/"
        "#;
        let decls = parse(toml).unwrap();
        match &decls[0].proxy {
            ProxyDecl::Http { auth_mode, upstream_url, .. } => {
                assert!(matches!(auth_mode, HttpAuthMode::Bearer));
                assert_eq!(upstream_url, "https://k8s.example.com/");
            }
            other => panic!("expected Http, got {other:?}"),
        }
    }

    #[test]
    fn parses_http_basic_with_user() {
        let toml = r#"
            [[tasks]]
            task_id = "demo"

              [[tasks.credentials]]
              name         = "saas-prod"
              proxy_type   = "http"
              mount_as     = "API_TOKEN"
              upstream_url = "https://api.saas.com/"

                [tasks.credentials.auth_mode]
                basic = { user = "alice" }
        "#;
        let decls = parse(toml).unwrap();
        match &decls[0].proxy {
            ProxyDecl::Http { auth_mode, .. } => {
                match auth_mode {
                    HttpAuthMode::Basic { user } => assert_eq!(user, "alice"),
                    other => panic!("expected Basic, got {other:?}"),
                }
            }
            other => panic!("expected Http, got {other:?}"),
        }
    }

    #[test]
    fn parses_http_with_method_and_path_prefix_restrictions() {
        let toml = r#"
            [[tasks]]
            task_id = "demo"

              [[tasks.credentials]]
              name         = "api-readonly"
              proxy_type   = "http"
              mount_as     = "API_URL"
              upstream_url = "https://api.example.com/"

                [tasks.credentials.restrictions]
                allowed_methods       = ["GET", "HEAD"]
                allowed_path_prefixes = ["/v1/widgets"]
        "#;
        let decls = parse(toml).unwrap();
        match &decls[0].proxy {
            ProxyDecl::Http { restrictions, .. } => {
                assert_eq!(restrictions.allowed_methods,
                    vec!["GET".to_owned(), "HEAD".to_owned()]);
                assert_eq!(restrictions.allowed_path_prefixes,
                    vec!["/v1/widgets".to_owned()]);
            }
            other => panic!("expected Http, got {other:?}"),
        }
    }

    #[test]
    fn parses_k8s_proxy_type() {
        let toml = r#"
            [[tasks]]
            task_id = "demo"

              [[tasks.credentials]]
              name       = "kube-staging"
              proxy_type = "k8s"
              mount_as   = "KUBECONFIG"

                [tasks.credentials.restrictions]
                allowed_methods = ["GET"]
        "#;
        let decls = parse(toml).unwrap();
        match &decls[0].proxy {
            ProxyDecl::K8s { restrictions } => {
                assert_eq!(restrictions.allowed_methods, vec!["GET".to_owned()]);
            }
            other => panic!("expected K8s, got {other:?}"),
        }
    }

    #[test]
    fn parses_aws_decl_with_default_restrictions() {
        let toml = r#"
            [[tasks]]
            task_id = "demo"

              [[tasks.credentials]]
              name       = "aws-staging"
              proxy_type = "aws"
              mount_as   = "AWS_CONTAINER_CREDENTIALS_FULL_URI"
              role_arn   = "arn:aws:iam::123456789:role/raxis-staging-agent"
        "#;
        let decls = parse(toml).unwrap();
        match &decls[0].proxy {
            ProxyDecl::Aws { role_arn, lease_seconds, restrictions } => {
                assert_eq!(role_arn.as_deref(),
                    Some("arn:aws:iam::123456789:role/raxis-staging-agent"));
                assert_eq!(*lease_seconds, 900);
                assert_eq!(restrictions, &AwsRestrictions::default());
            }
            other => panic!("expected Aws, got {other:?}"),
        }
    }

    #[test]
    fn parses_aws_decl_with_custom_lease_and_path_allowlist() {
        let toml = r#"
            [[tasks]]
            task_id = "demo"

              [[tasks.credentials]]
              name           = "aws-prod"
              proxy_type     = "aws"
              mount_as       = "AWS_CONTAINER_CREDENTIALS_FULL_URI"
              lease_seconds  = 1800

                [tasks.credentials.restrictions]
                allowed_paths = ["/creds", "/creds/v2"]
        "#;
        let decls = parse(toml).unwrap();
        match &decls[0].proxy {
            ProxyDecl::Aws { lease_seconds, restrictions, .. } => {
                assert_eq!(*lease_seconds, 1800);
                assert_eq!(
                    restrictions.allowed_paths,
                    vec!["/creds".to_owned(), "/creds/v2".to_owned()],
                );
            }
            other => panic!("expected Aws, got {other:?}"),
        }
    }

    #[test]
    fn parses_redis_decl_with_default_restrictions() {
        let toml = r#"
            [[tasks]]
            task_id = "demo"

              [[tasks.credentials]]
              name               = "redis-staging"
              proxy_type         = "redis"
              mount_as           = "REDIS_URL"
              upstream_host_port = "redis.example.com:6379"
        "#;
        let decls = parse(toml).unwrap();
        match &decls[0].proxy {
            ProxyDecl::Redis { upstream_host_port, require_upstream_tls, restrictions } => {
                assert_eq!(upstream_host_port, "redis.example.com:6379");
                assert!(!*require_upstream_tls);
                assert_eq!(restrictions, &RedisRestrictions::default());
            }
            other => panic!("expected Redis, got {other:?}"),
        }
    }

    #[test]
    fn parses_redis_decl_with_command_allowlist() {
        let toml = r#"
            [[tasks]]
            task_id = "demo"

              [[tasks.credentials]]
              name               = "redis-prod"
              proxy_type         = "redis"
              mount_as           = "REDIS_URL"
              upstream_host_port = "cache.internal:6379"

                [tasks.credentials.restrictions]
                allowed_commands = ["GET", "MGET", "EXISTS"]
        "#;
        let decls = parse(toml).unwrap();
        match &decls[0].proxy {
            ProxyDecl::Redis { restrictions, .. } => {
                assert_eq!(
                    restrictions.allowed_commands,
                    vec!["GET".to_owned(), "MGET".to_owned(), "EXISTS".to_owned()],
                );
            }
            other => panic!("expected Redis, got {other:?}"),
        }
    }

    #[test]
    fn parses_gcp_decl_with_default_restrictions() {
        let toml = r#"
            [[tasks]]
            task_id = "demo"

              [[tasks.credentials]]
              name       = "gcp-staging"
              proxy_type = "gcp"
              mount_as   = "GOOGLE_APPLICATION_CREDENTIALS"
              project    = "my-staging-project"
        "#;
        let decls = parse(toml).unwrap();
        match &decls[0].proxy {
            ProxyDecl::Gcp { project, numeric_project, lease_seconds, restrictions } => {
                assert_eq!(project, "my-staging-project");
                assert_eq!(*numeric_project, None);
                assert_eq!(*lease_seconds, 3600);
                assert_eq!(restrictions, &GcpRestrictions::default());
            }
            other => panic!("expected Gcp, got {other:?}"),
        }
    }

    #[test]
    fn parses_gcp_decl_with_numeric_project_and_path_allowlist() {
        let toml = r#"
            [[tasks]]
            task_id = "demo"

              [[tasks.credentials]]
              name             = "gcp-prod"
              proxy_type       = "gcp"
              mount_as         = "GOOGLE_APPLICATION_CREDENTIALS"
              project          = "my-prod-project"
              numeric_project  = 1234567890
              lease_seconds    = 1800

                [tasks.credentials.restrictions]
                allowed_paths = [
                  "/computeMetadata/v1/instance/service-accounts/default/token",
                ]
        "#;
        let decls = parse(toml).unwrap();
        match &decls[0].proxy {
            ProxyDecl::Gcp { project, numeric_project, lease_seconds, restrictions } => {
                assert_eq!(project, "my-prod-project");
                assert_eq!(*numeric_project, Some(1234567890));
                assert_eq!(*lease_seconds, 1800);
                assert_eq!(
                    restrictions.allowed_paths,
                    vec!["/computeMetadata/v1/instance/service-accounts/default/token".to_owned()],
                );
            }
            other => panic!("expected Gcp, got {other:?}"),
        }
    }

    #[test]
    fn parses_azure_decl_with_resource_allowlist() {
        let toml = r#"
            [[tasks]]
            task_id = "demo"

              [[tasks.credentials]]
              name      = "azure-staging"
              proxy_type = "azure"
              mount_as  = "AZURE_TOKEN_URL"
              tenant_id = "aaaa-bbbb-cccc-dddd"

                [tasks.credentials.restrictions]
                allowed_resources = [
                  "https://management.azure.com/",
                  "https://database.windows.net/",
                ]
        "#;
        let decls = parse(toml).unwrap();
        match &decls[0].proxy {
            ProxyDecl::Azure { tenant_id, client_id, lease_seconds, restrictions } => {
                assert_eq!(tenant_id, "aaaa-bbbb-cccc-dddd");
                assert_eq!(*client_id, None);
                assert_eq!(*lease_seconds, 3600);
                assert_eq!(
                    restrictions.allowed_resources,
                    vec![
                        "https://management.azure.com/".to_owned(),
                        "https://database.windows.net/".to_owned(),
                    ],
                );
            }
            other => panic!("expected Azure, got {other:?}"),
        }
    }

    #[test]
    fn parses_azure_decl_with_client_id_and_custom_lease() {
        let toml = r#"
            [[tasks]]
            task_id = "demo"

              [[tasks.credentials]]
              name          = "azure-mi"
              proxy_type    = "azure"
              mount_as      = "AZURE_TOKEN_URL"
              tenant_id     = "tenant-1"
              client_id     = "client-1"
              lease_seconds = 1800

                [tasks.credentials.restrictions]
                allowed_resources = ["https://management.azure.com/"]
        "#;
        let decls = parse(toml).unwrap();
        match &decls[0].proxy {
            ProxyDecl::Azure { client_id, lease_seconds, .. } => {
                assert_eq!(client_id.as_deref(), Some("client-1"));
                assert_eq!(*lease_seconds, 1800);
            }
            other => panic!("expected Azure, got {other:?}"),
        }
    }

    #[test]
    fn parses_mysql_decl_with_allow_only_select() {
        let toml = r#"
            [[tasks]]
            task_id = "demo"

              [[tasks.credentials]]
              name       = "mysql-staging"
              proxy_type = "mysql"
              mount_as   = "MYSQL_DSN"

                [tasks.credentials.restrictions]
                allow_only_select = true
        "#;
        let decls = parse(toml).unwrap();
        match &decls[0].proxy {
            ProxyDecl::Mysql { restrictions } => {
                assert!(restrictions.allow_only_select);
            }
            other => panic!("expected Mysql, got {other:?}"),
        }
    }

    #[test]
    fn parses_mssql_decl_with_allow_only_select() {
        let toml = r#"
            [[tasks]]
            task_id = "demo"

              [[tasks.credentials]]
              name       = "mssql-staging"
              proxy_type = "mssql"
              mount_as   = "MSSQL_DSN"

                [tasks.credentials.restrictions]
                allow_only_select = true
        "#;
        let decls = parse(toml).unwrap();
        match &decls[0].proxy {
            ProxyDecl::Mssql { restrictions } => {
                assert!(restrictions.allow_only_select);
            }
            other => panic!("expected Mssql, got {other:?}"),
        }
    }

    #[test]
    fn parses_mongodb_decl_with_allow_read_only() {
        let toml = r#"
            [[tasks]]
            task_id = "demo"

              [[tasks.credentials]]
              name       = "mongo-staging"
              proxy_type = "mongodb"
              mount_as   = "MONGO_URI"

                [tasks.credentials.restrictions]
                allow_read_only = true
        "#;
        let decls = parse(toml).unwrap();
        match &decls[0].proxy {
            ProxyDecl::Mongodb { restrictions } => {
                assert!(restrictions.allow_read_only);
            }
            other => panic!("expected Mongodb, got {other:?}"),
        }
    }

    #[test]
    fn parses_smtp_decl_with_default_auth_mode_and_no_restrictions() {
        let toml = r#"
            [[tasks]]
            task_id = "demo"

              [[tasks.credentials]]
              name               = "smtp-relay-staging"
              proxy_type         = "smtp"
              mount_as           = "SMTP_URL"
              upstream_host_port = "smtp.example.com:587"
        "#;
        let decls = parse(toml).unwrap();
        match &decls[0].proxy {
            ProxyDecl::Smtp {
                auth_mode,
                upstream_host_port,
                require_upstream_tls,
                restrictions,
            } => {
                match auth_mode {
                    SmtpAuthMode::Plain { user } => assert_eq!(user, ""),
                    other => panic!("expected default Plain auth, got {other:?}"),
                }
                assert_eq!(upstream_host_port, "smtp.example.com:587");
                assert!(!require_upstream_tls);
                assert_eq!(restrictions, &SmtpRestrictions::default());
            }
            other => panic!("expected Smtp, got {other:?}"),
        }
    }

    #[test]
    fn parses_smtp_decl_with_full_restrictions_and_login_auth() {
        let toml = r#"
            [[tasks]]
            task_id = "demo"

              [[tasks.credentials]]
              name                 = "smtp-prod"
              proxy_type           = "smtp"
              mount_as             = "SMTP_URL"
              upstream_host_port   = "mail.example.com:25"
              require_upstream_tls = true

                [tasks.credentials.auth_mode]
                kind = "login"
                user = "smtp-user"

                [tasks.credentials.restrictions]
                allowed_sender_address     = "noreply@example.com"
                allowed_recipient_domains  = ["customers.example.com", "ops.example.com"]
                max_recipients_per_message = 50
                max_message_bytes          = 1048576
                max_messages_per_minute    = 30
        "#;
        let decls = parse(toml).unwrap();
        match &decls[0].proxy {
            ProxyDecl::Smtp {
                auth_mode,
                upstream_host_port,
                require_upstream_tls,
                restrictions,
            } => {
                match auth_mode {
                    SmtpAuthMode::Login { user } => assert_eq!(user, "smtp-user"),
                    other => panic!("expected Login auth, got {other:?}"),
                }
                assert_eq!(upstream_host_port, "mail.example.com:25");
                assert!(*require_upstream_tls);
                assert_eq!(restrictions.allowed_sender_address.as_deref(),
                    Some("noreply@example.com"));
                assert_eq!(
                    restrictions.allowed_recipient_domains,
                    vec![
                        "customers.example.com".to_owned(),
                        "ops.example.com".to_owned(),
                    ],
                );
                assert_eq!(restrictions.max_recipients_per_message, Some(50));
                assert_eq!(restrictions.max_message_bytes, Some(1_048_576));
                assert_eq!(restrictions.max_messages_per_minute, Some(30));
            }
            other => panic!("expected Smtp, got {other:?}"),
        }
    }

    #[test]
    fn unknown_proxy_type_is_preserved_as_unknown_variant() {
        let toml = r#"
            [[tasks]]
            task_id = "demo"

              [[tasks.credentials]]
              name       = "future"
              proxy_type = "mongodb-future-spec"
              mount_as   = "MONGODB_URI"
        "#;
        let decls = parse(toml).unwrap();
        assert!(matches!(decls[0].proxy, ProxyDecl::Unknown));
    }

    #[test]
    fn missing_name_is_structured_error() {
        let toml = r#"
            [[tasks]]
            task_id = "demo"

              [[tasks.credentials]]
              proxy_type = "postgres"
              mount_as   = "DATABASE_URL"
        "#;
        let err = parse(toml).unwrap_err();
        match err {
            ParseError::Malformed { task_id, index, detail } => {
                assert_eq!(task_id, "demo");
                assert_eq!(index, 0);
                assert!(detail.contains("name"), "got {detail:?}");
            }
            other => panic!("expected Malformed; got {other:?}"),
        }
    }

    #[test]
    fn missing_mount_as_is_structured_error() {
        let toml = r#"
            [[tasks]]
            task_id = "demo"

              [[tasks.credentials]]
              name       = "x"
              proxy_type = "postgres"
        "#;
        let err = parse(toml).unwrap_err();
        match err {
            ParseError::Malformed { detail, .. } => {
                assert!(detail.contains("mount_as"), "got {detail:?}");
            }
            other => panic!("expected Malformed; got {other:?}"),
        }
    }

    #[test]
    fn missing_proxy_type_is_structured_error() {
        let toml = r#"
            [[tasks]]
            task_id = "demo"

              [[tasks.credentials]]
              name     = "x"
              mount_as = "X"
        "#;
        let err = parse(toml).unwrap_err();
        match err {
            ParseError::Malformed { detail, .. } => {
                assert!(detail.contains("proxy_type"), "got {detail:?}");
            }
            other => panic!("expected Malformed; got {other:?}"),
        }
    }

    #[test]
    fn multiple_credentials_in_one_task() {
        let toml = r#"
            [[tasks]]
            task_id = "demo"

              [[tasks.credentials]]
              name       = "db"
              proxy_type = "postgres"
              mount_as   = "DATABASE_URL"

              [[tasks.credentials]]
              name         = "kube"
              proxy_type   = "k8s"
              mount_as     = "KUBECONFIG"
        "#;
        let decls = parse(toml).unwrap();
        assert_eq!(decls.len(), 2);
        assert!(matches!(decls[0].proxy, ProxyDecl::Postgres { .. }));
        assert!(matches!(decls[1].proxy, ProxyDecl::K8s     { .. }));
    }

    // ── mount_as uniqueness tests ────────────────────────────────────

    #[test]
    fn duplicate_mount_as_rejected_at_parse_time() {
        let toml = r#"
            [[tasks]]
            task_id = "demo"

              [[tasks.credentials]]
              name       = "users-db"
              proxy_type = "postgres"
              mount_as   = "DATABASE_URL"

              [[tasks.credentials]]
              name       = "analytics-db"
              proxy_type = "postgres"
              mount_as   = "DATABASE_URL"
        "#;
        let err = parse(toml).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("duplicate mount_as"),
            "expected DuplicateMountAs error, got: {msg}"
        );
        assert!(msg.contains("DATABASE_URL"), "error should name the colliding env var: {msg}");
        assert!(msg.contains("users-db"), "error should name the first credential: {msg}");
        assert!(msg.contains("analytics-db"), "error should name the second credential: {msg}");
    }

    #[test]
    fn distinct_mount_as_across_same_proxy_type_is_valid() {
        let toml = r#"
            [[tasks]]
            task_id = "demo"

              [[tasks.credentials]]
              name       = "users-db"
              proxy_type = "postgres"
              mount_as   = "USERS_DATABASE_URL"

              [[tasks.credentials]]
              name       = "analytics-db"
              proxy_type = "postgres"
              mount_as   = "ANALYTICS_DATABASE_URL"
        "#;
        let decls = parse(toml).unwrap();
        assert_eq!(decls.len(), 2);
        assert_eq!(decls[0].mount_as, "USERS_DATABASE_URL");
        assert_eq!(decls[1].mount_as, "ANALYTICS_DATABASE_URL");
    }

    #[test]
    fn duplicate_mount_as_across_different_proxy_types_rejected() {
        // Even if proxy types differ, the env-var collision is the
        // same problem — the agent's environment can only hold one
        // value per key.
        let toml = r#"
            [[tasks]]
            task_id = "demo"

              [[tasks.credentials]]
              name       = "prod-db"
              proxy_type = "postgres"
              mount_as   = "SERVICE_URL"

              [[tasks.credentials]]
              name       = "cache"
              proxy_type = "redis"
              upstream_host_port = "redis:6379"
              mount_as   = "SERVICE_URL"
        "#;
        let err = parse(toml).unwrap_err();
        assert!(
            err.to_string().contains("duplicate mount_as"),
            "cross-type collision should still be caught: {err}"
        );
    }
}

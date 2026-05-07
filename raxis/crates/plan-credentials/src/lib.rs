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
    /// the value is the loopback URL the kernel-bound proxy listens
    /// on (e.g. `DATABASE_URL`, `KUBECONFIG`, `STRIPE_API_KEY`).
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
    /// Catch-all for proxy types declared in policy but not yet
    /// implemented. The parser preserves the literal `proxy_type`
    /// string so the validator can map it to a clear "not
    /// implemented in V2" diagnostic without losing information.
    #[serde(other)]
    Unknown,
}

fn default_http_auth_mode() -> HttpAuthMode { HttpAuthMode::Bearer }

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
}

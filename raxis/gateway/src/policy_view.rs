//! `PolicyView` — the gateway's read-only projection of policy.toml +
//! provider credentials.
//!
//! Normative reference: `peripherals.md` §3.2 — the gateway loads
//! policy.toml directly (not over IPC) so it can re-validate the domain
//! allowlist and resolve provider credentials. On `EpochAdvanced` the
//! gateway calls `load_policy_view` again and atomically swaps the new
//! view in.
//!
//! Why a separate "view" instead of using `PolicyBundle` directly: the
//! gateway only needs three slices of policy state (allowlist, providers,
//! and per-provider credentials). A purpose-built struct keeps the API
//! surface small AND lets the credentials live in the view (the
//! `PolicyBundle` cannot — credentials are NOT in policy.toml; they live
//! under `<data_dir>/providers/`).
//!
//! Failure model: `load_policy_view` is fail-closed. If policy.toml is
//! missing, malformed, or any declared `[[providers]]` is missing its
//! credentials file, this function returns an `Err`. The runtime loop
//! then either refuses to start (boot path) or marks the view as
//! "stale" and returns `error: "PolicyReloadFailed"` on every subsequent
//! `FetchRequest` until the next successful reload (epoch-advance path).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use raxis_credentials::{ConsumerIdentity, CredentialBackend, CredentialError, CredentialName};
use raxis_credentials_file::FileCredentialBackend;
use thiserror::Error;

// `ProviderEntryView` and `ProviderCredentials` live in the trait
// crate (`raxis-gateway-substrate`) so the in-memory test fake
// `raxis-test-support::MockBackend` can take a `&ProviderEntryView`
// without circular-deps through `raxis-gateway` itself. Re-export
// both so the gateway's existing
// `raxis_gateway::policy_view::ProviderEntryView` call sites keep
// working.
pub use raxis_gateway_substrate::{ProviderCredentials, ProviderEntryView};

/// All policy state the gateway needs to validate one `FetchRequest`.
/// Held behind an `Arc<RwLock<PolicyView>>` in the runtime loop so an
/// `EpochAdvanced` reload can swap it without blocking in-flight tasks.
#[derive(Debug, Clone)]
pub struct PolicyView {
    /// Current policy epoch — recorded for log diagnostics; the
    /// gateway does not gate on this value but the `FetchResponse`
    /// includes it so the kernel can detect skew between its view and
    /// ours.
    pub epoch: u64,

    /// Domain allowlist (exact-match hostnames). Populated from
    /// `[egress] domains` in policy.toml.
    pub egress_domains: Vec<String>,

    /// Domain allowlist (glob-match patterns). Populated from
    /// `[egress] patterns` in policy.toml.
    pub egress_patterns: Vec<String>,

    /// Provider catalogue keyed by `provider_id`. The gateway looks
    /// up the kind + credentials when dispatching a `FetchRequest`.
    pub providers: HashMap<String, ProviderEntryView>,
}

/// Fail-closed reasons `load_policy_view` can return.
#[derive(Debug, Error)]
pub enum PolicyViewError {
    #[error("policy.toml load failed at {path}: {source}")]
    PolicyLoad {
        path: PathBuf,
        source: raxis_policy::PolicyError,
    },
    #[error("provider {provider_id:?}: credentials file {path} not readable: {source}")]
    CredentialsRead {
        provider_id: String,
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("provider {provider_id:?}: credentials backend rejected resolution: {source}")]
    CredentialsBackend {
        provider_id: String,
        source: CredentialError,
    },
    #[error("provider {provider_id:?}: credentials file {path} malformed: {source}")]
    CredentialsParse {
        provider_id: String,
        path: PathBuf,
        source: toml::de::Error,
    },
    #[error("provider {provider_id:?}: credentials file {path} api_key is empty")]
    CredentialsEmpty { provider_id: String, path: PathBuf },
}

/// Read the full policy view from disk using the **default**
/// `FileCredentialBackend` rooted at `data_dir`. This is the convenience
/// boot-path used by the production gateway subprocess (see
/// `runtime.rs`); deployments that opt into Vault, AWS Secrets Manager,
/// Azure Key Vault, or PKCS#11 wire their own
/// `Arc<dyn CredentialBackend>` and call
/// [`load_policy_view_with_credential_backend`] directly.
///
/// Behaviourally identical to the prior direct `std::fs::read` path —
/// the file backend's mode/uid validation matches the on-disk
/// invariants `policy.toml` already assumed (chmod 0600, kernel-OS-user).
pub fn load_policy_view(data_dir: &Path) -> Result<PolicyView, PolicyViewError> {
    let backend: Arc<dyn CredentialBackend> = Arc::new(FileCredentialBackend::open(data_dir));
    load_policy_view_with_credential_backend(data_dir, &backend)
}

/// Load policy view using a caller-supplied `CredentialBackend`. The
/// kernel-driven boot path uses this directly so a single
/// `Arc<dyn CredentialBackend>` (already wrapped in `AuditingBackend`)
/// is shared across the gateway and every credential proxy.
///
/// Provider credentials are resolved by the policy-declared
/// `[[providers]].credentials_file` (e.g. `"anthropic-prod.toml"`),
/// translated to the canonical credential name `"providers.<stem>"`
/// (e.g. `"providers.anthropic-prod"`). The file backend re-derives
/// the original on-disk path from that name; alternate backends look
/// up the same name in their own store. `extensibility-traits.md §4.4`.
pub fn load_policy_view_with_credential_backend(
    data_dir: &Path,
    backend: &Arc<dyn CredentialBackend>,
) -> Result<PolicyView, PolicyViewError> {
    let policy_path = data_dir.join("policy/policy.toml");
    let (bundle, _bytes, _sha) =
        raxis_policy::load_policy(&policy_path).map_err(|e| PolicyViewError::PolicyLoad {
            path: policy_path.clone(),
            source: e,
        })?;

    let providers_dir = data_dir.join("providers");
    let mut providers = HashMap::with_capacity(bundle.providers().len());
    for entry in bundle.providers() {
        let path = providers_dir.join(&entry.credentials_file);
        let cred_name = credentials_filename_to_name(&entry.credentials_file);
        let creds =
            resolve_provider_credentials_via_backend(backend, &cred_name, &entry.provider_id)
                .map_err(|e| match e {
                    ProviderResolveError::Backend(src) => PolicyViewError::CredentialsBackend {
                        provider_id: entry.provider_id.clone(),
                        source: src,
                    },
                    ProviderResolveError::Parse(parse) => PolicyViewError::CredentialsParse {
                        provider_id: entry.provider_id.clone(),
                        path: path.clone(),
                        source: parse,
                    },
                    ProviderResolveError::EmptyApiKey => PolicyViewError::CredentialsEmpty {
                        provider_id: entry.provider_id.clone(),
                        path: path.clone(),
                    },
                    ProviderResolveError::NotUtf8(io) => PolicyViewError::CredentialsRead {
                        provider_id: entry.provider_id.clone(),
                        path: path.clone(),
                        source: io,
                    },
                })?;
        providers.insert(
            entry.provider_id.clone(),
            ProviderEntryView {
                provider_id: entry.provider_id.clone(),
                kind: entry.kind.clone(),
                inference_timeout_ms: entry.inference_timeout_ms,
                data_fetch_timeout_ms: entry.data_fetch_timeout_ms,
                max_response_bytes: entry.max_response_bytes,
                stream_idle_timeout_ms: entry.stream_idle_timeout_ms,
                credentials: creds,
            },
        );
    }

    // V2 reviewer-egress-defaults-decision.md §5: the gateway URL
    // allowlist consumes the EFFECTIVE egress domains (operator-
    // declared ∪ implicit-provider-FQDN grants). Without this,
    // every operator who declares `[[providers]]` but forgets to
    // mirror the provider FQDN under `[egress] domains` gets a
    // `DomainNotAllowed` rejection on the first inference call.
    Ok(PolicyView {
        epoch: bundle.epoch(),
        egress_domains: bundle.effective_egress_domains(),
        egress_patterns: bundle.effective_egress_patterns(),
        providers,
    })
}

/// Translate the policy's `[[providers]].credentials_file` (e.g.
/// `"anthropic-prod.toml"`) into the canonical credential name the
/// `FileCredentialBackend` understands (`"providers.anthropic-prod"`).
/// The mapping strips the `.toml` suffix when present; `policy.toml`
/// validation pinned that suffix at admission time so the strip is
/// safe.
fn credentials_filename_to_name(credentials_file: &str) -> CredentialName {
    let stem = credentials_file
        .strip_suffix(".toml")
        .unwrap_or(credentials_file);
    CredentialName::from(format!("providers.{stem}"))
}

/// Errors from `resolve_provider_credentials_via_backend`. Internal —
/// callers see them mapped onto `PolicyViewError` variants.
#[derive(Debug)]
enum ProviderResolveError {
    Backend(CredentialError),
    NotUtf8(std::io::Error),
    Parse(toml::de::Error),
    EmptyApiKey,
}

fn resolve_provider_credentials_via_backend(
    backend: &Arc<dyn CredentialBackend>,
    name: &CredentialName,
    provider_id: &str,
) -> Result<ProviderCredentials, ProviderResolveError> {
    let value = backend
        .resolve(name, ConsumerIdentity::new("gateway", provider_id))
        .map_err(ProviderResolveError::Backend)?;
    let text = value.as_utf8().ok_or_else(|| {
        ProviderResolveError::NotUtf8(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "credentials file is not valid UTF-8",
        ))
    })?;
    let creds: ProviderCredentials = toml::from_str(&text).map_err(ProviderResolveError::Parse)?;
    if creds.api_key.is_empty() {
        return Err(ProviderResolveError::EmptyApiKey);
    }
    Ok(creds)
}

/// Internal credentials-load error. Public callers see the richer
/// `PolicyViewError` variants instead, which carry the provider_id and
/// resolved path so operator log messages are actionable.
#[derive(Debug, Error)]
enum CredentialsLoadError {
    #[error(transparent)]
    Read(std::io::Error),
    #[error(transparent)]
    Parse(toml::de::Error),
    #[error("api_key is empty")]
    Empty,
}

/// Inner credentials loader. Returns the structured error so callers
/// can route Read / Parse / Empty separately.
fn load_provider_credentials_inner(
    path: &Path,
) -> Result<ProviderCredentials, CredentialsLoadError> {
    let bytes = std::fs::read(path).map_err(CredentialsLoadError::Read)?;
    let s = std::str::from_utf8(&bytes).map_err(|e| {
        // UTF-8 violation surfaces as a Read-class problem with a
        // descriptive io::Error so the operator gets one error string.
        CredentialsLoadError::Read(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("credentials file is not valid UTF-8: {e}"),
        ))
    })?;
    let creds: ProviderCredentials = toml::from_str(s).map_err(CredentialsLoadError::Parse)?;
    if creds.api_key.is_empty() {
        return Err(CredentialsLoadError::Empty);
    }
    Ok(creds)
}

/// Public, friendly wrapper used by tests + future callers that just
/// want a single `io::Error` flavour rather than the structured enum.
pub fn load_provider_credentials(
    providers_dir: &Path,
    filename: &str,
) -> Result<ProviderCredentials, std::io::Error> {
    let path = providers_dir.join(filename);
    load_provider_credentials_inner(&path).map_err(|e| match e {
        CredentialsLoadError::Read(io) => io,
        CredentialsLoadError::Parse(parse) => std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("toml parse: {parse}"),
        ),
        CredentialsLoadError::Empty => {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "api_key is empty")
        }
    })
}

// ─────────────────────────────────────────────────────────────────────────
// URL allowlist check
// ─────────────────────────────────────────────────────────────────────────

impl PolicyView {
    /// True iff the URL's hostname is allowed by either the exact-match
    /// `egress_domains` list or any glob in `egress_patterns`.
    ///
    /// Returns `false` for any URL that does not parse, has no host
    /// component, or whose host matches no entry. Fail-closed by design
    /// (peripherals.md §3.2 "Domain allowlist re-validation").
    pub fn is_url_allowed(&self, url: &str) -> bool {
        let host = match extract_host(url) {
            Some(h) => h,
            None => return false,
        };

        if self.egress_domains.iter().any(|d| d == &host) {
            return true;
        }

        for pat in &self.egress_patterns {
            if glob_match(pat, &host) {
                return true;
            }
        }
        false
    }
}

/// Extract the hostname from a URL string. We do NOT pull `url`-crate
/// here because the surface area we need is tiny and v1 only deals with
/// `http://` / `https://` URLs from the planner.
fn extract_host(url: &str) -> Option<String> {
    let after_scheme = url.split_once("://")?.1;
    let host_with_path = after_scheme.split('/').next()?;
    // Strip optional `:port`.
    let host = host_with_path.split(':').next()?;
    if host.is_empty() {
        None
    } else {
        Some(host.to_owned())
    }
}

/// Single-`*`-glob matcher. `*` matches any sequence of characters
/// (including empty). Exact matches and `*.example.com` style suffix
/// patterns are the only forms operators use in practice.
fn glob_match(pattern: &str, value: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if let Some(suffix) = pattern.strip_prefix("*.") {
        return value == suffix || value.ends_with(&format!(".{suffix}"));
    }
    if let Some(prefix) = pattern.strip_suffix(".*") {
        return value == prefix || value.starts_with(&format!("{prefix}."));
    }
    pattern == value
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_creds(dir: &Path, name: &str, body: &str) {
        std::fs::write(dir.join(name), body).unwrap();
    }

    #[test]
    fn load_credentials_with_only_api_key_uses_defaults() {
        let tmp = tempfile::tempdir().unwrap();
        write_creds(tmp.path(), "p1.toml", "api_key = \"sk-test\"\n");
        let creds = load_provider_credentials(tmp.path(), "p1.toml").unwrap();
        assert_eq!(creds.api_key, "sk-test");
        assert_eq!(creds.auth_header, "Authorization");
        assert_eq!(creds.auth_prefix, "Bearer ");
    }

    #[test]
    fn load_credentials_with_anthropic_style_overrides() {
        let tmp = tempfile::tempdir().unwrap();
        write_creds(
            tmp.path(),
            "anthropic.toml",
            r#"api_key = "sk-ant-..."
auth_header = "x-api-key"
auth_prefix = ""
"#,
        );
        let creds = load_provider_credentials(tmp.path(), "anthropic.toml").unwrap();
        assert_eq!(creds.auth_header, "x-api-key");
        assert_eq!(creds.auth_prefix, "");
    }

    #[test]
    fn load_credentials_rejects_empty_api_key() {
        let tmp = tempfile::tempdir().unwrap();
        write_creds(tmp.path(), "p1.toml", "api_key = \"\"\n");
        let err = load_provider_credentials(tmp.path(), "p1.toml").unwrap_err();
        assert!(format!("{err}").contains("empty"));
    }

    #[test]
    fn load_credentials_rejects_missing_file() {
        let tmp = tempfile::tempdir().unwrap();
        let err = load_provider_credentials(tmp.path(), "missing.toml").unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
    }

    #[test]
    fn load_credentials_rejects_malformed_toml() {
        let tmp = tempfile::tempdir().unwrap();
        write_creds(tmp.path(), "p1.toml", "this is not toml = = =");
        let err = load_provider_credentials(tmp.path(), "p1.toml").unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    // ── extract_host ────────────────────────────────────────────────────

    #[test]
    fn extract_host_basic_https() {
        assert_eq!(
            extract_host("https://api.anthropic.com/v1/messages"),
            Some("api.anthropic.com".to_owned())
        );
    }
    #[test]
    fn extract_host_with_port() {
        assert_eq!(
            extract_host("http://localhost:8080/foo"),
            Some("localhost".to_owned())
        );
    }
    #[test]
    fn extract_host_no_path() {
        assert_eq!(
            extract_host("https://api.example.com"),
            Some("api.example.com".to_owned())
        );
    }
    #[test]
    fn extract_host_rejects_no_scheme() {
        assert_eq!(extract_host("api.example.com"), None);
    }
    #[test]
    fn extract_host_rejects_empty_host() {
        assert_eq!(extract_host("https:///foo"), None);
    }

    // ── glob_match ───────────────────────────────────────────────────────

    #[test]
    fn glob_match_star_matches_everything() {
        assert!(glob_match("*", "anything.example.com"));
    }
    #[test]
    fn glob_match_star_dot_suffix() {
        assert!(glob_match("*.example.com", "api.example.com"));
        assert!(glob_match("*.example.com", "deep.api.example.com"));
        assert!(
            glob_match("*.example.com", "example.com"),
            "*.example.com must also match the bare suffix per common convention"
        );
        assert!(
            !glob_match("*.example.com", "evil-example.com"),
            "byte-prefix must not match"
        );
    }
    #[test]
    fn glob_match_exact_pattern() {
        assert!(glob_match("api.example.com", "api.example.com"));
        assert!(!glob_match("api.example.com", "other.example.com"));
    }

    // ── PolicyView::is_url_allowed ──────────────────────────────────────

    fn view_with(domains: &[&str], patterns: &[&str]) -> PolicyView {
        PolicyView {
            epoch: 1,
            egress_domains: domains.iter().map(|s| s.to_string()).collect(),
            egress_patterns: patterns.iter().map(|s| s.to_string()).collect(),
            providers: HashMap::new(),
        }
    }

    #[test]
    fn allowlist_exact_match_allows() {
        let v = view_with(&["api.openai.com"], &[]);
        assert!(v.is_url_allowed("https://api.openai.com/v1/chat"));
    }

    #[test]
    fn allowlist_pattern_match_allows() {
        let v = view_with(&[], &["*.anthropic.com"]);
        assert!(v.is_url_allowed("https://api.anthropic.com/v1/messages"));
    }

    #[test]
    fn allowlist_no_match_rejects() {
        let v = view_with(&["api.openai.com"], &["*.anthropic.com"]);
        assert!(!v.is_url_allowed("https://evil.example.com/exfiltrate"));
    }

    #[test]
    fn allowlist_rejects_unparseable_url() {
        let v = view_with(&["api.openai.com"], &["*"]);
        // Even with `*` allow-all, an URL we can't extract a host from
        // is rejected — fail-closed.
        assert!(!v.is_url_allowed("not a url"));
        assert!(!v.is_url_allowed("https:///empty-host"));
    }
}

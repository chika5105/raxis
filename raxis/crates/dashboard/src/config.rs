//! `[dashboard]` policy section parsing.
//!
//! Spec: `v2_extended_gaps.md §4.3` — kernel-launched HTTP server
//! configurable via `policy.toml`:
//!
//! ```toml
//! [dashboard]
//! enabled       = true
//! bind_address  = "127.0.0.1"
//! bind_port     = 9820
//! tls_cert_path = ""           # optional PEM
//! tls_key_path  = ""
//! jwt_ttl_secs  = 3600
//! max_pending_challenges = 100
//! max_revoked_jwts = 1000
//! ```

use serde::Deserialize;

/// Default loopback bind address for the dashboard listener
/// (operator-only; binding non-loopback requires explicit policy
/// configuration).
pub const DEFAULT_DASHBOARD_ADDR: &str = "127.0.0.1";

/// Default TCP port for the dashboard listener (per spec §4.3).
pub const DEFAULT_DASHBOARD_PORT: u16 = 9820;

/// Default JWT TTL (1 hour, per spec §4.2).
pub const DEFAULT_JWT_TTL_SECS: u64 = 3600;

/// Default maximum number of in-flight challenges retained in
/// memory before LRU eviction (per spec §4.2).
pub const DEFAULT_MAX_PENDING_CHALLENGES: usize = 100;

/// Default maximum number of revoked-JWT digests retained in
/// memory (per spec §4.2). Entries are aged out when their
/// underlying JWT exceeds its `expires_at`.
pub const DEFAULT_MAX_REVOKED_JWTS: usize = 1000;

/// Operator dashboard configuration parsed from `[dashboard]`.
#[derive(Debug, Clone, Deserialize)]
pub struct DashboardConfig {
    /// `true` ⇒ kernel boot starts the dashboard listener.
    /// `false` ⇒ kernel boot skips the dashboard entirely (zero
    /// runtime cost). Default: `false`. Operators MUST opt-in.
    #[serde(default)]
    pub enabled: bool,

    /// IPv4 / IPv6 string the listener binds to. Defaults to
    /// `127.0.0.1` (loopback only). Binding non-loopback exposes
    /// the dashboard to the network — operators MUST review the
    /// network ACL before changing.
    #[serde(default = "default_addr")]
    pub bind_address: String,

    /// TCP port. Default 9820.
    #[serde(default = "default_port")]
    pub bind_port: u16,

    /// Optional PEM-encoded TLS certificate path. Empty ⇒ HTTP
    /// only. The TLS termination is wired in `server.rs`.
    #[serde(default)]
    pub tls_cert_path: String,

    /// Optional PEM-encoded TLS private key path. Empty ⇒ HTTP
    /// only.
    #[serde(default)]
    pub tls_key_path: String,

    /// JWT TTL in seconds. Default 3600 (1 hour).
    #[serde(default = "default_jwt_ttl_secs")]
    pub jwt_ttl_secs: u64,

    /// Bounded in-memory map of pending challenges. LRU eviction
    /// when the bound is exceeded. Default 100.
    #[serde(default = "default_max_pending_challenges")]
    pub max_pending_challenges: usize,

    /// Bounded in-memory revocation set. Entries auto-expire
    /// when the underlying JWT's `expires_at` passes. Default 1000.
    #[serde(default = "default_max_revoked_jwts")]
    pub max_revoked_jwts: usize,

    /// Filesystem path of the React frontend bundle (the
    /// `dist/` directory produced by `npm run build` under
    /// `dashboard-fe/`). When `Some(_)` the dashboard mounts
    /// a `tower_http::services::ServeDir` fallback so any
    /// non-`/api/*` route serves the bundle (with SPA-style
    /// `index.html` fallback for client-side routes). When
    /// `None` (the default) the dashboard exposes only the
    /// JSON API and returns 404 for unknown routes.
    #[serde(default)]
    pub static_dir: Option<String>,

    /// Kernel data directory (the same path the kernel writes
    /// to via `--data-dir` / `RAXIS_DATA_DIR`). Used by the
    /// `GET /api/health/kernel-lifecycle` handler per
    /// `self-healing-supervisor.md §5.2` to read the
    /// `kernel_lifecycle_status.json` sentinel file the
    /// `raxis-supervisor` writes. When `None` (the default,
    /// supervisor not in play) the handler returns
    /// `status: "Healthy"` + `fresh: true` so the dashboard
    /// banner stays clean.
    #[serde(default)]
    pub data_dir: Option<String>,
}

impl Default for DashboardConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            bind_address: default_addr(),
            bind_port: default_port(),
            tls_cert_path: String::new(),
            tls_key_path: String::new(),
            jwt_ttl_secs: default_jwt_ttl_secs(),
            max_pending_challenges: default_max_pending_challenges(),
            max_revoked_jwts: default_max_revoked_jwts(),
            static_dir: None,
            data_dir: None,
        }
    }
}

fn default_addr() -> String { DEFAULT_DASHBOARD_ADDR.into() }
fn default_port() -> u16 { DEFAULT_DASHBOARD_PORT }
fn default_jwt_ttl_secs() -> u64 { DEFAULT_JWT_TTL_SECS }
fn default_max_pending_challenges() -> usize { DEFAULT_MAX_PENDING_CHALLENGES }
fn default_max_revoked_jwts() -> usize { DEFAULT_MAX_REVOKED_JWTS }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_spec() {
        let d = DashboardConfig::default();
        assert!(!d.enabled, "dashboard disabled by default");
        assert_eq!(d.bind_address, "127.0.0.1");
        assert_eq!(d.bind_port, 9820);
        assert_eq!(d.jwt_ttl_secs, 3600);
        assert_eq!(d.max_pending_challenges, 100);
        assert_eq!(d.max_revoked_jwts, 1000);
    }

    #[test]
    fn parses_minimal_toml_block() {
        let raw = "enabled = true\nbind_port = 18000\n";
        let cfg: DashboardConfig = toml::from_str(raw).unwrap();
        assert!(cfg.enabled);
        assert_eq!(cfg.bind_port, 18000);
        assert_eq!(cfg.bind_address, "127.0.0.1"); // default kept
    }

    #[test]
    fn parses_full_toml_block() {
        let raw = r#"
enabled = true
bind_address = "0.0.0.0"
bind_port = 8443
tls_cert_path = "/etc/raxis/tls.crt"
tls_key_path  = "/etc/raxis/tls.key"
jwt_ttl_secs  = 1800
max_pending_challenges = 25
max_revoked_jwts = 500
"#;
        let cfg: DashboardConfig = toml::from_str(raw).unwrap();
        assert!(cfg.enabled);
        assert_eq!(cfg.bind_address, "0.0.0.0");
        assert_eq!(cfg.bind_port, 8443);
        assert_eq!(cfg.tls_cert_path, "/etc/raxis/tls.crt");
        assert_eq!(cfg.tls_key_path, "/etc/raxis/tls.key");
        assert_eq!(cfg.jwt_ttl_secs, 1800);
        assert_eq!(cfg.max_pending_challenges, 25);
        assert_eq!(cfg.max_revoked_jwts, 500);
    }
}

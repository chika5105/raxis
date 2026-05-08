//! `raxis-live-e2e` — out-of-band end-to-end harness that exercises
//! real RAXIS subsystems against real upstream services (real
//! Anthropic API, real Postgres, real loopback HTTP servers, real
//! kernel binaries).
//!
//! ## Why a binary, not a `cargo test` integration test
//!
//! The user asked for a flag-driven entry point: "Normal cargo test
//! should not run the e2e, there should be a flag to run e2e." A
//! dedicated binary crate satisfies that — `cargo test --workspace`
//! only compiles this crate (a fast no-op since the binary has no
//! integration tests of its own); `cargo run -p raxis-live-e2e` is
//! how an operator (or CI on a labeled job) runs the live slices.
//!
//! ## Slices
//!
//!   * `gateway-anthropic` — spawn a real `raxis-gateway` process
//!     against a real `policy.toml` + `providers/anthropic-prod.toml`,
//!     drive a real `messages` API call to `https://api.anthropic.com/`
//!     using the dev key from `raxis/.env`, and verify the response
//!     body parses as JSON with a non-empty `content` field.
//!
//!   * `postgres-proxy` — start the real `PostgresProxy` from
//!     `crates/credential-proxy-postgres/`, drive a real
//!     Postgres-protocol client through it, and verify the handshake
//!     reaches `ReadyForQuery`. (Upstream forwarding is deferred per
//!     spec; the handshake-tier integration is what the MVP guarantees.)
//!
//!   * `postgres-proxy-restrictions` — same proxy as above bound with
//!     `allow_only_select = true`, asserting that INSERT / UPDATE /
//!     DELETE are rejected with sqlstate `42501` and that
//!     `queries_blocked` increments while the session stays alive.
//!     The deny-path twin of `postgres-proxy`.
//!
//!   * `http-proxy-bearer` — start the real `HttpProxy` from
//!     `crates/credential-proxy-http/`, target `https://httpbin.org/`,
//!     and verify a `GET /anything` round-trip carries the injected
//!     Bearer token to the real upstream.
//!
//!   * `http-proxy-restrictions` — same proxy as above bound with
//!     per-task `allowed_methods` + `allowed_path_prefixes` clauses,
//!     asserting that requests outside the policy are rejected at the
//!     proxy with a 4xx, *never* reach upstream, and *never* trigger
//!     a `CredentialBackend::resolve` call. The deny-path twin of
//!     `http-proxy-bearer`.
//!
//!   * `session-spawn` — drive `SessionSpawnService` end-to-end against
//!     a real `CredentialProxyManager`, a real `PolicyAdmissionService`,
//!     and the real `SubprocessIsolation` substrate. Verifies the
//!     full spawn → admission round-trip → terminate audit chain
//!     (`CredentialProxyStarted → SessionVmSpawned → ... →
//!     SessionVmExited → CredentialProxyStopped`) and that an
//!     allow-listed SNI receives `Admit` while a non-allow-listed
//!     SNI receives `Deny`, both with byte-exact bincode wire frames
//!     identical to what the in-guest `raxis-tproxy` writes.
//!
//!   * `smtp-proxy` — start the real `SmtpProxy` from
//!     `crates/credential-proxy-smtp/`, point its `upstream_host_port`
//!     at an in-process SMTP listener, drive a raw SMTP submission
//!     through the proxy, and assert that the upstream observed the
//!     *proxy's* AUTH-PLAIN payload (real credential bytes from the
//!     `CredentialBackend`) — never the agent's submitted junk
//!     bytes — plus the envelope and DATA body verbatim.
//!
//!   * `redis-proxy` — start the real `RedisProxy` from
//!     `crates/credential-proxy-redis/`, point its
//!     `upstream_host_port` at an in-process RESP listener, drive a
//!     raw RESP2 conversation through the proxy with a junk agent
//!     `AUTH`, and assert that the upstream observed the proxy's
//!     real AUTH password (never the agent's junk), allow-listed
//!     verbs (PING/SET/GET) reached upstream in order, and a
//!     denied verb (FLUSHDB) was rejected at the proxy boundary.
//!
//!   * `aws-proxy` — start the real `AwsProxy` from
//!     `crates/credential-proxy-aws/` and drive raw HTTP/1.1
//!     `GET /creds` requests through it. Asserts the canonical
//!     IMDS JSON envelope is emitted, the path allowlist denies
//!     non-`/creds` requests with `403`, and that querystrings
//!     are stripped before allowlist comparison.
//!
//!   * `gcp-proxy` — start the real `GcpProxy` from
//!     `crates/credential-proxy-gcp/` and drive raw HTTP/1.1
//!     requests through it. Asserts the canonical metadata-server
//!     JSON envelope is emitted, the `Metadata-Flavor: Google`
//!     header is enforced (403 when missing), and non-allowlisted
//!     paths get `404`.
//!
//!   * `azure-proxy` — start the real `AzureProxy` from
//!     `crates/credential-proxy-azure/` and drive raw HTTP/1.1
//!     requests through it. Asserts the canonical IMDS body is
//!     emitted with stringified numeric fields, the `Metadata: true`
//!     header is enforced (400 when missing), and resources outside
//!     `allowed_resources` get `400` even when the header is
//!     present.
//!
//!   * `mysql-proxy` — start the real `MysqlProxy` from
//!     `crates/credential-proxy-mysql/` and drive a raw MySQL
//!     wire conversation through it. Asserts that the V2
//!     handshake-tier MVP reaches `OK_Packet`, that `SELECT`
//!     yields a synthetic `OK_Packet` (allow path), and that
//!     `INSERT` yields the canonical
//!     `ERR_Packet { code = 1142, sqlstate = "42501" }` (deny
//!     path under `allow_only_select`).
//!
//!   * `mssql-proxy` — start the real `MssqlProxy` from
//!     `crates/credential-proxy-mssql/` and drive a raw TDS
//!     conversation through it. Asserts that PRELOGIN +
//!     LOGIN7 reach a synthetic `LOGINACK + DONE`, that
//!     `SELECT` yields a clean `DONE` (allow path), and that
//!     `INSERT` yields an `ERROR` token followed by `DONE`
//!     (deny path under `allow_only_select`).
//!
//!   * `mongodb-proxy` — start the real `MongodbProxy` from
//!     `crates/credential-proxy-mongodb/` and drive a raw
//!     `OP_MSG` conversation through it. Asserts that
//!     `hello` / `ping` / `find` return `ok: 1.0` (read
//!     path under `allow_read_only`), and that `insert`
//!     returns `ok: 0.0` with `code: 13` (deny path).
//!
//!   * `all` — run every slice in order; any slice failure aborts
//!     with non-zero exit.
//!
//! ## Reading the API key
//!
//! `raxis/.env` is read with a tiny built-in parser (no `dotenvy`
//! dependency — this binary is dev-only and pulling another crate
//! into the workspace is not justified). The expected line is
//! `ANTHROPIC-API-DEV-KEY=...`.
//!
//! ## Exit codes
//!
//!   * `0`  — every requested slice passed.
//!   * `64` — usage / configuration error (missing `.env`, malformed
//!     args).
//!   * `70` — at least one slice failed; details on stderr.

use std::path::PathBuf;

use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};

mod env_file;
mod slice_aws_proxy;
mod slice_azure_proxy;
mod slice_egress_enforcement;
mod slice_gateway_anthropic;
mod slice_gcp_proxy;
mod slice_http_proxy_bearer;
mod slice_http_proxy_restrictions;
mod slice_mongodb_proxy;
mod slice_mssql_proxy;
mod slice_mysql_proxy;
mod slice_postgres_proxy;
mod slice_postgres_proxy_restrictions;
mod slice_redis_proxy;
mod slice_session_spawn;
mod slice_smtp_proxy;

#[derive(Parser, Debug)]
#[command(
    name    = "raxis-live-e2e",
    about   = "Real-object end-to-end suite for RAXIS",
    long_about = "Runs RAXIS subsystems against REAL upstream services.\n\
                  Never run by `cargo test`. Call a slice subcommand\n\
                  to drive a specific surface.",
)]
struct Cli {
    #[command(subcommand)]
    slice: Slice,

    /// Path to the `.env` file that supplies real API keys. Defaults
    /// to `raxis/.env` (resolved from CARGO_MANIFEST_DIR).
    #[arg(long)]
    env_file: Option<PathBuf>,
}

#[derive(Subcommand, Debug)]
enum Slice {
    /// Real `raxis-gateway` subprocess + real Anthropic API.
    GatewayAnthropic,
    /// Egress allowlist enforcement: real Anthropic call permitted,
    /// real `httpbin.org` call denied with `DomainNotAllowed`.
    EgressEnforcement,
    /// Real `PostgresProxy` + real Postgres-protocol client (allow-path
    /// handshake + simple query).
    PostgresProxy,
    /// Real `PostgresProxy` with `allow_only_select = true` enforcing
    /// DML denial (sqlstate `42501`) for INSERT / UPDATE / DELETE while
    /// keeping SELECT and the session alive.
    PostgresProxyRestrictions,
    /// Real `HttpProxy` + real `https://httpbin.org/` — bearer
    /// injection on the allow path.
    HttpProxyBearer,
    /// Real `HttpProxy` with `allowed_methods` + `allowed_path_prefixes`
    /// enforcing per-restriction denials against `https://httpbin.org/`,
    /// asserting that denied requests never reach upstream and never
    /// resolve the credential.
    HttpProxyRestrictions,
    /// Real `SessionSpawnService` driving real `CredentialProxyManager`
    /// + real `PolicyAdmissionService` + real `SubprocessIsolation`.
    /// Asserts the full spawn → admission → terminate audit chain in
    /// the spec's fixed order, plus byte-shape verdicts on the
    /// admission wire (Admit + Deny).
    SessionSpawn,
    /// Real `SmtpProxy` + an in-process upstream SMTP relay. Asserts
    /// that the proxy strips the agent's AUTH PLAIN payload and
    /// injects the real `CredentialBackend`-resolved credentials
    /// into the upstream conversation, and that the envelope (MAIL
    /// FROM, RCPT TO, DATA body) reaches upstream verbatim.
    SmtpProxy,
    /// Real `RedisProxy` + an in-process upstream RESP relay. Asserts
    /// that the proxy strips the agent's AUTH payload, injects the
    /// real `CredentialBackend`-resolved password, forwards
    /// allow-listed verbs verbatim (PING/SET/GET), and rejects
    /// disallowed verbs (FLUSHDB) at the proxy boundary.
    RedisProxy,
    /// Real `AwsProxy` + a raw HTTP/1.1 client. Asserts that the
    /// canonical `/creds` endpoint returns the IMDS-shaped JSON body
    /// with the `CredentialBackend`-resolved keys, that
    /// non-allowlisted paths get `403 Forbidden`, and that the
    /// counters reflect the served / blocked decisions.
    AwsProxy,
    /// Real `GcpProxy` + a raw HTTP/1.1 client. Asserts that the
    /// canonical `/computeMetadata/v1/...` endpoints return the
    /// metadata-server JSON body, that requests missing
    /// `Metadata-Flavor: Google` get `403`, and that
    /// non-allowlisted paths get `404`.
    GcpProxy,
    /// Real `AzureProxy` + a raw HTTP/1.1 client. Asserts that
    /// `/metadata/identity/oauth2/token?resource=...` for an allowed
    /// resource returns the IMDS body with stringified numeric
    /// fields, and that requests missing `Metadata: true` or naming
    /// a disallowed resource get `400`.
    AzureProxy,
    /// Real `MysqlProxy` + a raw MySQL client. Asserts the
    /// handshake-tier MVP reaches `OK_Packet`, that `SELECT` is
    /// allowed and `INSERT` is blocked under `allow_only_select`
    /// with a canonical `ERR_Packet { code = 1142, sqlstate =
    /// "42501" }`, and that counters reflect the audit decisions.
    MysqlProxy,
    /// Real `MssqlProxy` + a raw TDS client. Asserts the
    /// handshake-tier MVP reaches `LOGINACK + DONE`, that `SELECT`
    /// yields a clean `DONE` and `INSERT` yields an `ERROR` token
    /// under `allow_only_select`, and that counters reflect the
    /// audit decisions.
    MssqlProxy,
    /// Real `MongodbProxy` + a raw OP_MSG client. Asserts the
    /// handshake-tier MVP returns `ok: 1.0` for `hello`, `ping`,
    /// and `find` (read path) under `allow_read_only`, and
    /// `ok: 0.0` with `code: 13` for `insert` (deny path).
    MongodbProxy,
    /// Run every slice in order.
    All,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_target(false)
        .compact()
        .init();

    let cli = Cli::parse();

    // Resolve the env file. Default: `<workspace>/raxis/.env`.
    let env_path = cli.env_file.unwrap_or_else(default_env_file_path);
    let env_map = match env_file::load(&env_path) {
        Ok(m) => m,
        Err(e) => {
            eprintln!(
                "raxis-live-e2e: failed to read env file {} — {e}\n\
                 hint: pass --env-file=<path> with a file that defines\n\
                 ANTHROPIC-API-DEV-KEY.",
                env_path.display(),
            );
            std::process::exit(64);
        }
    };

    let result = run(&cli.slice, &env_map).await;
    match result {
        Ok(()) => {
            tracing::info!("OK — all selected slices passed");
            std::process::exit(0);
        }
        Err(e) => {
            tracing::error!(error = %e, "FAIL — slice failed");
            std::process::exit(70);
        }
    }
}

fn default_env_file_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(|p| p.join(".env"))
        .unwrap_or_else(|| PathBuf::from("raxis/.env"))
}

async fn run(slice: &Slice, env: &env_file::EnvMap) -> Result<()> {
    match slice {
        Slice::GatewayAnthropic           => slice_gateway_anthropic::run(env).await,
        Slice::EgressEnforcement          => slice_egress_enforcement::run(env).await,
        Slice::PostgresProxy              => slice_postgres_proxy::run().await,
        Slice::PostgresProxyRestrictions  => slice_postgres_proxy_restrictions::run().await,
        Slice::HttpProxyBearer            => slice_http_proxy_bearer::run(env).await,
        Slice::HttpProxyRestrictions      => slice_http_proxy_restrictions::run(env).await,
        Slice::SessionSpawn               => slice_session_spawn::run().await,
        Slice::SmtpProxy                  => slice_smtp_proxy::run().await,
        Slice::RedisProxy                 => slice_redis_proxy::run().await,
        Slice::AwsProxy                   => slice_aws_proxy::run().await,
        Slice::GcpProxy                   => slice_gcp_proxy::run().await,
        Slice::AzureProxy                 => slice_azure_proxy::run().await,
        Slice::MysqlProxy                 => slice_mysql_proxy::run().await,
        Slice::MssqlProxy                 => slice_mssql_proxy::run().await,
        Slice::MongodbProxy               => slice_mongodb_proxy::run().await,
        Slice::All => {
            slice_gateway_anthropic::run(env).await
                .context("slice gateway-anthropic")?;
            slice_egress_enforcement::run(env).await
                .context("slice egress-enforcement")?;
            slice_postgres_proxy::run().await
                .context("slice postgres-proxy")?;
            slice_postgres_proxy_restrictions::run().await
                .context("slice postgres-proxy-restrictions")?;
            slice_http_proxy_bearer::run(env).await
                .context("slice http-proxy-bearer")?;
            slice_http_proxy_restrictions::run(env).await
                .context("slice http-proxy-restrictions")?;
            slice_session_spawn::run().await
                .context("slice session-spawn")?;
            slice_smtp_proxy::run().await
                .context("slice smtp-proxy")?;
            slice_redis_proxy::run().await
                .context("slice redis-proxy")?;
            slice_aws_proxy::run().await
                .context("slice aws-proxy")?;
            slice_gcp_proxy::run().await
                .context("slice gcp-proxy")?;
            slice_azure_proxy::run().await
                .context("slice azure-proxy")?;
            slice_mysql_proxy::run().await
                .context("slice mysql-proxy")?;
            slice_mssql_proxy::run().await
                .context("slice mssql-proxy")?;
            slice_mongodb_proxy::run().await
                .context("slice mongodb-proxy")?;
            Ok(())
        }
    }
}

// ---------------------------------------------------------------------------
// Shared helpers used by multiple slices.
// ---------------------------------------------------------------------------

pub(crate) fn require_env<'a>(env: &'a env_file::EnvMap, key: &str) -> Result<&'a str> {
    env.get(key)
        .map(|s| s.as_str())
        .ok_or_else(|| anyhow!("env file is missing key {key:?}"))
}

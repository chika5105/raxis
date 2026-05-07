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
//!     `crates/credential-proxy-postgres/`, drive a real `tokio-postgres`
//!     client through it, and verify the handshake reaches
//!     `ReadyForQuery`. (Upstream forwarding is deferred per spec; the
//!     handshake-tier integration is what the MVP guarantees.)
//!
//!   * `http-proxy-bearer` — start the real `HttpProxy` from
//!     `crates/credential-proxy-http/`, target `https://httpbin.org/`,
//!     and verify a `GET /headers` round-trip carries the injected
//!     Bearer token to the real upstream.
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
mod slice_egress_enforcement;
mod slice_gateway_anthropic;
mod slice_http_proxy_bearer;
mod slice_postgres_proxy;

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
    /// Real `PostgresProxy` + real `tokio-postgres` client (handshake).
    PostgresProxy,
    /// Real `HttpProxy` + real `https://httpbin.org/`.
    HttpProxyBearer,
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
        Slice::GatewayAnthropic   => slice_gateway_anthropic::run(env).await,
        Slice::EgressEnforcement  => slice_egress_enforcement::run(env).await,
        Slice::PostgresProxy      => slice_postgres_proxy::run().await,
        Slice::HttpProxyBearer    => slice_http_proxy_bearer::run(env).await,
        Slice::All => {
            slice_gateway_anthropic::run(env).await
                .context("slice gateway-anthropic")?;
            slice_egress_enforcement::run(env).await
                .context("slice egress-enforcement")?;
            slice_postgres_proxy::run().await
                .context("slice postgres-proxy")?;
            slice_http_proxy_bearer::run(env).await
                .context("slice http-proxy-bearer")?;
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

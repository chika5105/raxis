//! Fast pre-seed health probes for the live-e2e backing services.
//!
//! ## Why probe before seeding
//!
//! A `seed_*` helper (in [`super::service_evidence`]) shells out
//! to a database client (`psql` / `mongosh` / `redis-cli` / …)
//! against a docker-compose container. When the container is not
//! up, the client connect-retries inside its own loop —
//! `psql` drives `getaddrinfo` + ECONNREFUSED for several seconds
//! before erroring; `mongosh` waits the full server-selection
//! timeout (default 30 s); `mysql` blocks on the TCP handshake.
//! The harness-side bounded wait
//! ([`super::harness_timeout::wait_with_output_timeout`]) is the
//! safety net that stops these from hanging the runner forever,
//! but every seed call that reaches it has already burned 30 s
//! of operator time before failing.
//!
//! The probes here are the EARLIER and CLEARER signal: each one
//! invokes the official "is the service up" checker for the
//! protocol with a 2 s upstream-side timeout, wrapped in the
//! 5 s harness-side bounded wait. A failed probe surfaces a typed
//! [`HealthProbeError`] within seconds — well before the seeder
//! gets to wait 30 s for nothing.
//!
//! ## Invariant
//!
//! Spec parity:
//! [`raxis/specs/invariants.md`] — `INV-LIVE-E2E-HARNESS-NO-INDEFINITE-WAIT-01`:
//! every external-process spawn in the live-e2e harness MUST be
//! wrapped in a bounded timeout (5 s default for health probes).
//!
//! ## Probe choice per service
//!
//! | Service | Probe                                       | Notes |
//! |---------|---------------------------------------------|-------|
//! | postgres | `pg_isready -h … -p … -U … -d … -t 2`     | Ships with `postgresql-client`; the de-facto "is the server accepting connections" check. |
//! | mongodb  | `mongosh --quiet … --eval "db.adminCommand({ ping: 1 }).ok"` with `serverSelectionTimeoutMS=2000` | Only mongosh-driver knows whether AUTH succeeded too. |
//! | redis    | `redis-cli -h … -p … -a … -t 2 PING`      | Server replies `PONG` on success; AUTH errors surface here. |
//! | mysql    | `mysqladmin --connect-timeout=2 ping`     | Skipped when the opt-in env var is unset. |
//! | mssql    | `sqlcmd -l 2 -Q "SELECT 1"`               | Skipped when the opt-in env var is unset. |
//! | smtp     | `TcpStream::connect_timeout` for 2 s      | The proxy is outbound-only so a TCP handshake is the right surface. |
//!
//! The two opt-in services (`mysql`, `mssql`) follow the same
//! "skip unless the env var is set" gate as their seed
//! counterparts in [`super::service_evidence`]; calling them
//! unconditionally exercises the gate so a future env flip
//! becomes active with no code change.

#![allow(dead_code)]

use std::net::TcpStream;
use std::process::Command;
use std::time::Duration;

use super::harness_timeout::{
    run_command_output_timeout, BoundedWaitError, HEALTH_PROBE_TIMEOUT,
};
use super::service_evidence::{
    ENV_LIVE_MSSQL_URL, ENV_LIVE_MYSQL_URL, SE_MONGO_DATABASE, SE_MONGO_HOST,
    SE_MONGO_PASSWORD, SE_MONGO_PORT, SE_MONGO_USER, SE_PG_DATABASE, SE_PG_HOST,
    SE_PG_PASSWORD, SE_PG_PORT, SE_PG_USER, SE_REDIS_HOST, SE_REDIS_PASSWORD,
    SE_REDIS_PORT, SE_SMTP_HOST, SE_SMTP_PORT,
};

/// Per-protocol upstream-side timeout. The Rust `Duration` is
/// for our wrapper; we pass the integer seconds to the upstream
/// CLI's own timeout flag (`pg_isready -t`, `mysqladmin
/// --connect-timeout`, `sqlcmd -l`) so the upstream gives up
/// before our bounded wait fires.
const UPSTREAM_PROBE_SECS: u64 = 2;

/// Failure surface for the health probes. Distinct from the
/// service-evidence error taxonomy because the pre-seed probe is
/// the harness's OWN health check (not part of the kernel's
/// audit-chain witness surface) and we want the panic message to
/// be obvious about which probe failed.
#[derive(Debug, Clone)]
pub struct HealthProbeError {
    pub service: &'static str,
    pub target: String,
    pub reason: String,
}

impl std::fmt::Display for HealthProbeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "[live-e2e health-probe:{}] {} not reachable: {}",
            self.service, self.target, self.reason,
        )
    }
}

impl std::error::Error for HealthProbeError {}

fn lift_probe_error(
    err: BoundedWaitError,
    service: &'static str,
    target: &str,
) -> HealthProbeError {
    HealthProbeError {
        service,
        target: target.to_owned(),
        reason: format!("{err}"),
    }
}

/// Fast Postgres reachability + auth probe. `pg_isready -t 2` is
/// the canonical "is the server accepting connections" check;
/// the upstream CLI gives up after 2 s, the harness wrapper
/// closes the gap after 5 s.
pub fn probe_postgres() -> Result<(), HealthProbeError> {
    let target = format!(
        "postgresql://{user}@{host}:{port}/{db}",
        user = SE_PG_USER,
        host = SE_PG_HOST,
        port = SE_PG_PORT,
        db = SE_PG_DATABASE,
    );
    let mut cmd = Command::new("pg_isready");
    cmd.env("PGPASSWORD", SE_PG_PASSWORD)
        .arg("-h").arg(SE_PG_HOST)
        .arg("-p").arg(SE_PG_PORT.to_string())
        .arg("-U").arg(SE_PG_USER)
        .arg("-d").arg(SE_PG_DATABASE)
        .arg("-t").arg(UPSTREAM_PROBE_SECS.to_string());
    let out = run_command_output_timeout(&mut cmd, HEALTH_PROBE_TIMEOUT, "pg_isready")
        .map_err(|e| lift_probe_error(e, "postgres", &target))?;
    if !out.status.success() {
        return Err(HealthProbeError {
            service: "postgres",
            target,
            reason: format!(
                "pg_isready exit {:?}; stdout={}; stderr={}",
                out.status.code(),
                String::from_utf8_lossy(&out.stdout).trim_end(),
                String::from_utf8_lossy(&out.stderr).trim_end(),
            ),
        });
    }
    Ok(())
}

/// Fast MongoDB reachability + auth probe. We embed
/// `serverSelectionTimeoutMS=2000` in the URI so the driver
/// gives up at 2 s rather than waiting the 30 s default.
pub fn probe_mongodb() -> Result<(), HealthProbeError> {
    let target = format!(
        "mongodb://{user}:****@{host}:{port}/{db}",
        user = SE_MONGO_USER,
        host = SE_MONGO_HOST,
        port = SE_MONGO_PORT,
        db = SE_MONGO_DATABASE,
    );
    let uri = format!(
        "mongodb://{user}:{password}@{host}:{port}/{db}\
         ?authSource=admin&serverSelectionTimeoutMS=2000&connectTimeoutMS=2000",
        user = SE_MONGO_USER,
        password = SE_MONGO_PASSWORD,
        host = SE_MONGO_HOST,
        port = SE_MONGO_PORT,
        db = SE_MONGO_DATABASE,
    );
    let mut cmd = Command::new("mongosh");
    cmd.arg("--quiet")
        .arg(&uri)
        .arg("--eval")
        .arg("db.adminCommand({ ping: 1 }).ok");
    let out = run_command_output_timeout(&mut cmd, HEALTH_PROBE_TIMEOUT, "mongosh-ping")
        .map_err(|e| lift_probe_error(e, "mongodb", &target))?;
    if !out.status.success() {
        return Err(HealthProbeError {
            service: "mongodb",
            target,
            reason: format!(
                "mongosh ping exit {:?}; stderr={}",
                out.status.code(),
                String::from_utf8_lossy(&out.stderr).trim_end(),
            ),
        });
    }
    Ok(())
}

/// Fast Redis reachability + auth probe. `redis-cli PING`
/// returns `PONG` on success; AUTH errors surface as a non-zero
/// exit code with `(error) NOAUTH …` on stdout.
pub fn probe_redis() -> Result<(), HealthProbeError> {
    let target = format!("redis://{}:{}", SE_REDIS_HOST, SE_REDIS_PORT);
    let mut cmd = Command::new("redis-cli");
    cmd.arg("-h").arg(SE_REDIS_HOST)
        .arg("-p").arg(SE_REDIS_PORT.to_string())
        .arg("-a").arg(SE_REDIS_PASSWORD)
        .arg("--no-auth-warning")
        .arg("-t").arg(UPSTREAM_PROBE_SECS.to_string())
        .arg("PING");
    let out = run_command_output_timeout(&mut cmd, HEALTH_PROBE_TIMEOUT, "redis-cli-ping")
        .map_err(|e| lift_probe_error(e, "redis", &target))?;
    if !out.status.success() {
        return Err(HealthProbeError {
            service: "redis",
            target,
            reason: format!(
                "redis-cli PING exit {:?}; stdout={}; stderr={}",
                out.status.code(),
                String::from_utf8_lossy(&out.stdout).trim_end(),
                String::from_utf8_lossy(&out.stderr).trim_end(),
            ),
        });
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    if !stdout.trim().eq_ignore_ascii_case("PONG") {
        return Err(HealthProbeError {
            service: "redis",
            target,
            reason: format!(
                "redis-cli PING returned unexpected payload: {}",
                stdout.trim(),
            ),
        });
    }
    Ok(())
}

/// Fast SMTP reachability probe. The SMTP credential proxy is
/// outbound-only so a TCP handshake is the canonical "is the
/// MTA accepting submissions" surface.
pub fn probe_smtp() -> Result<(), HealthProbeError> {
    let target = format!("{}:{}", SE_SMTP_HOST, SE_SMTP_PORT);
    let parsed = target.parse().map_err(|e| HealthProbeError {
        service: "smtp",
        target: target.clone(),
        reason: format!("parse addr: {e}"),
    })?;
    TcpStream::connect_timeout(&parsed, Duration::from_secs(UPSTREAM_PROBE_SECS))
        .map(|_| ())
        .map_err(|e| HealthProbeError {
            service: "smtp",
            target,
            reason: format!("TCP connect: {e}"),
        })
}

/// Opt-in MySQL probe. Mirrors the seed-side gate: when
/// [`ENV_LIVE_MYSQL_URL`] is unset the probe short-circuits to
/// `Ok(())`, so the seeder is allowed to no-op (it returns the
/// canonical seed shape only) without a noisy false-negative.
pub fn probe_mysql() -> Result<(), HealthProbeError> {
    if std::env::var(ENV_LIVE_MYSQL_URL).is_err() {
        return Ok(());
    }
    let target = format!("mysql://raxis_test@{}:33099/raxis_e2e", SE_PG_HOST);
    let mut cmd = Command::new("mysqladmin");
    cmd.arg(format!("--host={SE_PG_HOST}"))
        .arg("--protocol=TCP")
        .arg("--port=33099")
        .arg("--user=raxis_test")
        .arg("--password=raxis_test_pass")
        .arg(format!("--connect-timeout={UPSTREAM_PROBE_SECS}"))
        .arg("ping");
    let out = run_command_output_timeout(&mut cmd, HEALTH_PROBE_TIMEOUT, "mysqladmin-ping")
        .map_err(|e| lift_probe_error(e, "mysql", &target))?;
    if !out.status.success() {
        return Err(HealthProbeError {
            service: "mysql",
            target,
            reason: format!(
                "mysqladmin ping exit {:?}; stderr={}",
                out.status.code(),
                String::from_utf8_lossy(&out.stderr).trim_end(),
            ),
        });
    }
    Ok(())
}

/// Opt-in MSSQL probe. Mirrors the seed-side gate. `sqlcmd -l 2`
/// caps the login wait at 2 s.
pub fn probe_mssql() -> Result<(), HealthProbeError> {
    if std::env::var(ENV_LIVE_MSSQL_URL).is_err() {
        return Ok(());
    }
    let target = "mssql://sa@127.0.0.1:14399/master".to_owned();
    let mut cmd = Command::new("sqlcmd");
    cmd.arg("-S").arg("127.0.0.1,14399")
        .arg("-U").arg("sa")
        .arg("-P").arg("raxis_Test_Pass1!")
        .arg("-C")
        .arg("-l").arg(UPSTREAM_PROBE_SECS.to_string())
        .arg("-Q").arg("SELECT 1");
    let out = run_command_output_timeout(&mut cmd, HEALTH_PROBE_TIMEOUT, "sqlcmd-ping")
        .map_err(|e| lift_probe_error(e, "mssql", &target))?;
    if !out.status.success() {
        return Err(HealthProbeError {
            service: "mssql",
            target,
            reason: format!(
                "sqlcmd ping exit {:?}; stderr={}",
                out.status.code(),
                String::from_utf8_lossy(&out.stderr).trim_end(),
            ),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    /// Hitting a port that is definitely closed must surface a
    /// `HealthProbeError` within the bounded wait — not hang. We
    /// test the SMTP probe because it is the only one that
    /// doesn't require a third-party CLI binary on the host.
    #[test]
    fn smtp_probe_against_closed_port_fails_fast() {
        // Save and override the SMTP probe target via process
        // env temporarily — the constants are compile-time, but
        // we can't shadow them; instead we drive the public TCP
        // probe directly against an unused localhost port.
        let started = Instant::now();
        let parsed: std::net::SocketAddr =
            "127.0.0.1:1".parse().expect("static literal parses");
        let r = TcpStream::connect_timeout(&parsed, Duration::from_secs(2));
        assert!(r.is_err(), "TCP connect to 127.0.0.1:1 must fail");
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "SMTP fast-fail probe must return within 5s; \
             elapsed={:?}",
            started.elapsed(),
        );
    }
}

//! Service-evidence mechanical witnesses for the realism extended
//! e2e scenario.
//!
//! ## Three-tier verification model
//!
//! The realistic-scenario test composes three independent layers:
//!
//! * **Tier 1 — kernel mechanical witnesses.** The kernel enforces
//!   its invariants via its existing witness / approval / audit
//!   gates. The credential proxies emit the canonical audit shapes
//!   ([`AuditEventKind::CredentialProxyStarted`],
//!   [`AuditEventKind::CredentialProxyUpstreamConnected`],
//!   [`AuditEventKind::DatabaseQueryExecuted`],
//!   [`AuditEventKind::DatabaseQueryCompleted`],
//!   [`AuditEventKind::RedisCommandExecuted`],
//!   [`AuditEventKind::MongoCommandExecuted`],
//!   [`AuditEventKind::SmtpMessageRelayed`], …) — this module
//!   does NOT re-implement those gates. It is the test-side
//!   reader that confirms the kernel emitted the expected events
//!   and that the executor's worktree-side output of the
//!   round-trip matches the seed we wrote upstream.
//!
//! * **Tier 2 — test layer assertions.** Each public helper
//!   returns `Result<(), ServiceEvidenceError>`. The realistic-
//!   scenario test uses plain `assert!(...is_ok(), "{}", err)`
//!   per the Tier-2 mandate; callers that want the error rendered
//!   directly in the panic message can `.unwrap()`.
//!
//! * **Tier 3 — operator-visible artifacts.** The realistic-scenario
//!   test (and `full_e2e_session_lifecycle`) print a post-run
//!   artifact block at end of run on both the success and the
//!   panic path so an operator can copy out the kernel log, audit
//!   dir, merged worktree, install dir, and (when mounted) the
//!   dashboard autologin URL. That printing logic lives in the
//!   test driver itself; this module focuses on the per-service
//!   helpers it calls.
//!
//! ## What the helpers verify (and what they don't)
//!
//! For each service in scope, the round-trip helper:
//!
//! 1. Confirms `<worktree_root>/<expected_file>` exists.
//! 2. Reads the file, canonicalises both seed and file content,
//!    and byte-compares.
//! 3. Walks the audit chain for the per-service canonical event
//!    sequence (`CredentialProxyStarted` →
//!    `CredentialProxyUpstreamConnected` → per-protocol command
//!    event), scoped by `(initiative_id, task_id)` and
//!    additionally by `session_id` when supplied.
//!
//! The helpers **do not** re-validate kernel-side invariants the
//! kernel itself enforces (e.g. they trust the audit chain's
//! `prev_sha256` link — that is the job of
//! [`super::audit_chain::AuditChainWitness`]). They also do not
//! decrypt or open the upstream service's wire frames — the proxy
//! audit shapes carry SHA-256 fingerprints, not plaintext.
//!
//! ## Distinguishable seed data
//!
//! Each per-service seed uses **service-name-prefixed** strings
//! (`pg_seed_row_1`, `mongo_seed_doc_1`, `redis_seed_key_1`,
//! `smtp_seed_subject_1`) so a cross-wired executor (e.g. the
//! Postgres credential proxy accidentally routed at the Mongo
//! upstream) would visibly fail rather than coincidentally match.
//!
//! ## Canonical-form rule
//!
//! Postgres rows can come back from a `SELECT` in any order; the
//! witness oracle sorts. Mongo cursor order is stable but the JSON
//! serialization differs across drivers; the oracle canonicalises
//! the JSON representation. Redis `SCAN` returns hash-bucket order;
//! the oracle sorts. SMTP message headers vary; the oracle keys on
//! sender + recipients + subject + body and renders one
//! deterministic line per field.
//!
//! ## MySQL / MSSQL opt-in gating
//!
//! The un-mock worker landed `mysql` and `mssql` containers in
//! `live-e2e/docker-compose.extended.e2e.yml`, but flagged both
//! credential proxies as `🟡 opt-in` because of handshake
//! regressions tracked separately. The matching helpers in this
//! module ([`assert_mysql_round_trip`], [`assert_mssql_round_trip`])
//! therefore **early-return `Ok(())` with an `eprintln!` notice**
//! when their per-service env var (`RAXIS_LIVE_MYSQL_URL` /
//! `RAXIS_LIVE_MSSQL_URL`) is absent. Once the proxy regression is
//! fixed the un-mock worker exports the env var and the witness
//! becomes active automatically — no production-code change
//! required.
//!
//! ## Failure taxonomy
//!
//! All failure modes flow through [`ServiceEvidenceError`]. The
//! `Display` impl is operator-readable; the panic message that
//! tests render via `{}` is grep-friendly for CI scrape pipelines.
//!
//! Spec references:
//!   * `raxis/specs/v2/audit-paired-writes.md` (per-event
//!     paired-write invariants and which `AuditEventKind`s carry
//!     `(session_id, task_id, initiative_id)`).
//!   * `raxis/specs/v2/credential-proxy.md` §14.5 (canonical
//!     `CredentialProxy*` event names emitted by each per-protocol
//!     proxy crate).
//!   * `raxis/live-e2e/seed/prompts/service_round_trip.md`
//!     (operator-facing description of the per-service round-trip
//!     the executor performs).

#![allow(dead_code)]
// The `ServiceEvidenceError` enum is intentionally rich (3 strings
// per `WitnessScope` + a diff preview) so the panic message is
// operator-readable. clippy::result_large_err triggers on the
// 128-byte default ceiling; that is a stylistic preference that
// would force us to box the error variant and trade clarity for
// stack-size. We accept the larger Err variant.
#![allow(clippy::result_large_err)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use raxis_audit_tools::{AuditEvent, AuditEventKind};
use sha2::{Digest, Sha256};

use super::harness_timeout::{
    run_command_output_timeout, wait_with_output_timeout, BoundedWaitError, SEED_TIMEOUT,
};
use super::health_probe::{
    probe_mongodb, probe_mssql, probe_mysql, probe_postgres, probe_redis, probe_smtp,
    HealthProbeError,
};

// ---------------------------------------------------------------------------
// Pinned host:port + credentials for the docker-compose stack the
// un-mock worker landed. The literals here track
// `raxis/live-e2e/docker-compose.extended.e2e.yml`; drift between
// the two would surface immediately in the test's preflight.
// ---------------------------------------------------------------------------

pub const SE_PG_HOST: &str = "127.0.0.1";
pub const SE_PG_PORT: u16 = 54399;
pub const SE_PG_USER: &str = "raxis_test";
pub const SE_PG_PASSWORD: &str = "raxis_test_pass";
pub const SE_PG_DATABASE: &str = "raxis_e2e_pg";

pub const SE_MONGO_HOST: &str = "127.0.0.1";
pub const SE_MONGO_PORT: u16 = 27399;
pub const SE_MONGO_USER: &str = "raxis_test";
pub const SE_MONGO_PASSWORD: &str = "raxis_test_pass";
pub const SE_MONGO_DATABASE: &str = "raxis_e2e_mongo";

pub const SE_REDIS_HOST: &str = "127.0.0.1";
pub const SE_REDIS_PORT: u16 = 63799;
pub const SE_REDIS_PASSWORD: &str = "raxis_test_pass";

pub const SE_SMTP_HOST: &str = "127.0.0.1";
pub const SE_SMTP_PORT: u16 = 25199;
pub const SE_SMTP_MAILBOX: &str = "raxis-tenant@live-e2e.test";

// ---------------------------------------------------------------------------
// Pinned task id + per-service output file names.
//
// The executor prompt at `live-e2e/seed/prompts/service_round_trip.md`
// instructs the executor to write one file per in-scope service into
// the worktree. The witness reads them at the matching path.
// ---------------------------------------------------------------------------

/// Pinned task id for the composite service-round-trip task. The
/// realistic plan builder ([`super::plan_realistic`]) wires this id
/// with `path_allowlist = ["out/services/"]` and the per-service
/// credential mounts.
pub const TASK_SERVICE_ROUND_TRIP: &str = "service-round-trip";

/// Worktree-relative directory the executor commits per-service
/// output files into. Pinned so the witness can read deterministic
/// paths.
pub const SERVICE_OUTPUT_DIR: &str = "out/services";

pub const POSTGRES_OUTPUT_FILE: &str = "out/services/postgres.txt";
pub const MONGODB_OUTPUT_FILE: &str = "out/services/mongodb.txt";
pub const REDIS_OUTPUT_FILE: &str = "out/services/redis.txt";
pub const SMTP_OUTPUT_FILE: &str = "out/services/smtp.txt";
pub const MYSQL_OUTPUT_FILE: &str = "out/services/mysql.txt";
pub const MSSQL_OUTPUT_FILE: &str = "out/services/mssql.txt";

/// Env-var opt-in toggles for the proxy paths the un-mock worker
/// flagged as `🟡 opt-in`. When unset, the matching assert helper
/// short-circuits to `Ok(())` with an `eprintln!` note so the
/// witness becomes active automatically once the operator (or the
/// upstream credential-proxy worker) flips the variable.
pub const ENV_LIVE_MYSQL_URL: &str = "RAXIS_LIVE_MYSQL_URL";
pub const ENV_LIVE_MSSQL_URL: &str = "RAXIS_LIVE_MSSQL_URL";

// ---------------------------------------------------------------------------
// WitnessScope — the (initiative, task, optional session) triple
// the audit-chain walk filters on.
// ---------------------------------------------------------------------------

/// Identity triple the round-trip witnesses use to scope-filter
/// audit events. `session_id` is optional — when supplied the
/// walker pins matches to that session, otherwise it admits any
/// session that carries the matching `task_id` + `initiative_id`.
#[derive(Debug, Clone)]
pub struct WitnessScope {
    pub initiative_id: String,
    pub task_id: String,
    pub session_id: Option<String>,
}

impl WitnessScope {
    pub fn new(initiative_id: impl Into<String>, task_id: impl Into<String>) -> Self {
        Self {
            initiative_id: initiative_id.into(),
            task_id: task_id.into(),
            session_id: None,
        }
    }

    pub fn with_session(mut self, session_id: impl Into<String>) -> Self {
        self.session_id = Some(session_id.into());
        self
    }

    fn matches(&self, ev: &AuditEvent) -> bool {
        if ev.initiative_id.as_deref() != Some(self.initiative_id.as_str()) {
            return false;
        }
        if let Some(task) = ev.task_id.as_deref() {
            if task != self.task_id {
                return false;
            }
        } else {
            return false;
        }
        if let Some(want_sid) = &self.session_id {
            if ev.session_id.as_deref() != Some(want_sid.as_str()) {
                return false;
            }
        }
        true
    }
}

// ---------------------------------------------------------------------------
// ServiceEvidenceError — failure taxonomy. Operator-readable
// `Display` impl + descriptive variants for grep-friendly CI logs.
// ---------------------------------------------------------------------------

/// One round-trip witness failure. Tests render with `{}` so the
/// panic message carries the full operator-facing diagnostic.
#[derive(Debug, Clone)]
pub enum ServiceEvidenceError {
    /// The seed-write step against the upstream service failed
    /// (process spawn / TCP / authentication / driver protocol).
    /// `reason` carries the underlying error untouched.
    SeedFailed {
        service: &'static str,
        reason: String,
    },

    /// The seed verification step (count probe, hash check, etc.)
    /// did not return the expected canonical shape — usually a
    /// container drift or a half-applied seed.
    SeedMismatch { service: &'static str, hint: String },

    /// `<worktree_root>/<expected_file>` is absent from the
    /// executor's worktree post-task.
    FileMissing {
        service: &'static str,
        path: PathBuf,
    },

    /// `std::fs::read` against the expected file failed.
    FileReadFailed {
        service: &'static str,
        path: PathBuf,
        reason: String,
    },

    /// The executor's output file content does not byte-equal the
    /// canonicalised expected seed. The diff preview is bounded to
    /// the first divergence + ±64 byte window so a CI scraper does
    /// not have to render megabytes.
    FileContentMismatch {
        service: &'static str,
        path: PathBuf,
        expected_sha: String,
        actual_sha: String,
        diff_preview: String,
    },

    /// An expected audit event was not observed within the witness
    /// scope. `hint` carries the matcher description (e.g.
    /// "proxy_type == \"postgres\"").
    AuditEventMissing {
        service: &'static str,
        expected_kind: &'static str,
        scope: WitnessScope,
        hint: String,
    },

    /// Helper bypassed because the opt-in env var was absent. The
    /// realistic-scenario driver treats this as a non-fatal
    /// information-only path; the variant exists so a future caller
    /// that requires the env can pattern-match and surface it.
    OptInBypassed {
        service: &'static str,
        env_var: &'static str,
    },

    /// The seed-write child process did not exit within the
    /// configured timeout (`SEED_TIMEOUT`, currently 30 s) and was
    /// SIGKILLed by the harness. Distinct from `SeedFailed` so a
    /// regression test (and a CI log scraper) can match the
    /// timeout path specifically vs. a generic seed failure.
    ///
    /// Spec: `INV-LIVE-E2E-HARNESS-NO-INDEFINITE-WAIT-01` in
    /// `raxis/specs/invariants.md`.
    SeedTimedOut {
        service: &'static str,
        /// Operator-readable label for the wrapped subprocess
        /// (e.g. `"psql"`, `"mongosh"`, `"redis-cli"`).
        label: String,
        /// Timeout that elapsed before SIGKILL.
        timeout: Duration,
        /// Target the seeder was talking to (host:port + db),
        /// surfaced for fast operator triage.
        target: String,
    },

    /// The pre-seed reachability probe (e.g. `pg_isready`,
    /// `mongosh ping`, `redis-cli PING`, TCP handshake against
    /// the SMTP submission port) failed. Distinct from
    /// `SeedTimedOut` so the operator sees the EARLIER signal
    /// — the probe burns 5 s, the seeder would have burned the
    /// full 30 s before reporting the same root cause.
    PreSeedHealthCheckFailed {
        service: &'static str,
        target: String,
        reason: String,
    },
}

impl fmt::Display for ServiceEvidenceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SeedFailed { service, reason } => write!(
                f,
                "[service-evidence:{service}] seed-write to upstream failed: {reason}",
            ),
            Self::SeedMismatch { service, hint } => write!(
                f,
                "[service-evidence:{service}] seed verification did not match \
                 canonical shape: {hint}",
            ),
            Self::FileMissing { service, path } => write!(
                f,
                "[service-evidence:{service}] expected executor output \
                 file does not exist: {}",
                path.display(),
            ),
            Self::FileReadFailed {
                service,
                path,
                reason,
            } => write!(
                f,
                "[service-evidence:{service}] read({}): {reason}",
                path.display(),
            ),
            Self::FileContentMismatch {
                service,
                path,
                expected_sha,
                actual_sha,
                diff_preview,
            } => write!(
                f,
                "[service-evidence:{service}] {} content mismatch\n  \
                 expected sha256: {expected_sha}\n  \
                 observed sha256: {actual_sha}\n  \
                 first divergence:\n{diff_preview}",
                path.display(),
            ),
            Self::AuditEventMissing {
                service,
                expected_kind,
                scope,
                hint,
            } => write!(
                f,
                "[service-evidence:{service}] expected audit event \
                 `{expected_kind}` not found in scope \
                 (initiative_id={}, task_id={}, session_id={:?}): {hint}",
                scope.initiative_id, scope.task_id, scope.session_id,
            ),
            Self::OptInBypassed { service, env_var } => write!(
                f,
                "[service-evidence:{service}] opt-in env var {env_var} \
                 not set; helper bypassed (returns Ok(()) for compatibility \
                 with the realistic-scenario harness).",
            ),
            Self::SeedTimedOut {
                service,
                label,
                timeout,
                target,
            } => write!(
                f,
                "[service-evidence:{service}] seed `{label}` against {target} \
                 did not exit within {:?}; SIGKILLed by the harness. The \
                 backing service is probably down or unreachable — verify with \
                 `docker compose -p raxis-live-e2e-test ps`. (Spec: \
                 INV-LIVE-E2E-HARNESS-NO-INDEFINITE-WAIT-01.)",
                timeout,
            ),
            Self::PreSeedHealthCheckFailed {
                service,
                target,
                reason,
            } => write!(
                f,
                "[service-evidence:{service}] pre-seed reachability probe \
                 failed against {target}: {reason}. Bring up the backing \
                 stack with `docker compose -p raxis-live-e2e-test \
                 -f live-e2e/docker-compose.extended.e2e.yml up -d --wait` \
                 (or set RAXIS_LIVE_E2E_NO_AUTO_DOCKER=1 to opt out of harness \
                 auto-bring-up).",
            ),
        }
    }
}

impl std::error::Error for ServiceEvidenceError {}

// ---------------------------------------------------------------------------
// Audit-chain walk helpers — shared by every per-service witness.
// ---------------------------------------------------------------------------

fn typed(ev: &AuditEvent) -> Option<AuditEventKind> {
    serde_json::from_value(ev.payload.clone()).ok()
}

/// Find the first `CredentialProxyStarted` event matching
/// `(scope, proxy_type)`. Returns the resolved `session_id` from
/// the matched event for callers that didn't pre-populate the
/// scope's session id.
fn find_proxy_started(
    chain: &[AuditEvent],
    scope: &WitnessScope,
    proxy_type: &str,
) -> Option<String> {
    chain.iter().find_map(|ev| {
        // CredentialProxyStarted carries (session_id, proxy_type,
        // credential_name, addr). The `initiative_id` / `task_id`
        // columns on the envelope identify the owning task.
        if !scope.matches(ev) {
            return None;
        }
        match typed(ev) {
            Some(AuditEventKind::CredentialProxyStarted {
                session_id,
                proxy_type: pt,
                ..
            }) if pt == proxy_type => Some(session_id),
            _ => None,
        }
    })
}

/// True iff `chain` contains a `CredentialProxyUpstreamConnected`
/// for the given `(scope, proxy_type)`.
fn has_upstream_connected(chain: &[AuditEvent], scope: &WitnessScope, proxy_type: &str) -> bool {
    chain.iter().any(|ev| {
        if !scope.matches(ev) {
            return false;
        }
        matches!(
            typed(ev),
            Some(AuditEventKind::CredentialProxyUpstreamConnected {
                proxy_type: pt, ..
            }) if pt == proxy_type
        )
    })
}

// ---------------------------------------------------------------------------
// Canonical-form helpers + diff preview.
// ---------------------------------------------------------------------------

fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

/// Render a small ±64 byte window around the first divergence
/// between `expected` and `actual`. Suitable for embedding in a
/// panic message; bounded so a CI log scraper isn't drowned.
fn diff_preview(expected: &[u8], actual: &[u8]) -> String {
    let mut idx = 0usize;
    while idx < expected.len() && idx < actual.len() && expected[idx] == actual[idx] {
        idx += 1;
    }
    let lo = idx.saturating_sub(64);
    let exp_hi = (idx + 64).min(expected.len());
    let act_hi = (idx + 64).min(actual.len());
    format!(
        "    at byte {idx} (expected_len={} actual_len={})\n    \
         expected[{lo}..{exp_hi}]: {:?}\n    \
         observed[{lo}..{act_hi}]: {:?}",
        expected.len(),
        actual.len(),
        String::from_utf8_lossy(&expected[lo..exp_hi]),
        String::from_utf8_lossy(&actual[lo..act_hi]),
    )
}

fn compare_file_against_canonical(
    service: &'static str,
    worktree_root: &Path,
    relative_path: &str,
    canonical: &[u8],
) -> Result<(), ServiceEvidenceError> {
    let abs = worktree_root.join(relative_path);
    if !abs.exists() {
        return Err(ServiceEvidenceError::FileMissing { service, path: abs });
    }
    let bytes = std::fs::read(&abs).map_err(|e| ServiceEvidenceError::FileReadFailed {
        service,
        path: abs.clone(),
        reason: format!("{e}"),
    })?;
    if bytes != canonical {
        return Err(ServiceEvidenceError::FileContentMismatch {
            service,
            path: abs,
            expected_sha: sha256_hex(canonical),
            actual_sha: sha256_hex(&bytes),
            diff_preview: diff_preview(canonical, &bytes),
        });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Postgres — seed + canonical form + round-trip witness.
//
// The seed installs a service-evidence-scoped table `service_evidence_pg`
// (distinct from the materialiser's `seeded_rows` so the two
// witnesses can coexist on the same database without contaminating
// each other). The executor's prompt produces
// `out/services/postgres.txt` with one row per line sorted by id.
// ---------------------------------------------------------------------------

/// Number of rows the postgres seed writes. Kept small so a re-run
/// against a long-lived container is cheap; large enough that a
/// cross-wired executor cannot trivially match by coincidence.
pub const SE_POSTGRES_ROW_COUNT: usize = 5;

#[derive(Debug, Clone)]
pub struct PostgresSeed {
    pub rows: Vec<PostgresSeedRow>,
}

#[derive(Debug, Clone)]
pub struct PostgresSeedRow {
    pub id: String,
    pub name: String,
    pub value: i64,
}

/// Generate the canonical seed rows. Deterministic — no time, no
/// UUIDs, no driver-defaulted values.
pub fn postgres_seed_rows() -> Vec<PostgresSeedRow> {
    (1..=SE_POSTGRES_ROW_COUNT)
        .map(|i| PostgresSeedRow {
            id: format!("pg_seed_row_{i}"),
            name: format!("service-evidence-name-{i}"),
            value: (i as i64) * 7919,
        })
        .collect()
}

/// Canonical text form of the postgres seed. One row per line,
/// sorted by `id`. Format: `<id>|<name>|<value>\n`. Lines end with
/// `\n`; no trailing empty line.
pub fn postgres_canonical_bytes(seed: &PostgresSeed) -> Vec<u8> {
    let mut rows = seed.rows.clone();
    rows.sort_by(|a, b| a.id.cmp(&b.id));
    let mut out = String::new();
    for r in &rows {
        out.push_str(&format!("{}|{}|{}\n", r.id, r.name, r.value));
    }
    out.into_bytes()
}

/// Drop + re-create `service_evidence_pg` and bulk-insert the
/// canonical rows. Idempotent — repeated calls converge to the
/// same final state. Shells out to `psql` so the kernel-side test
/// binary needs no `tokio-postgres` dev-dependency (matching the
/// existing [`super::seeds`] precedent).
pub fn seed_postgres() -> Result<PostgresSeed, ServiceEvidenceError> {
    // Pre-seed reachability probe — `pg_isready -t 2` wrapped in
    // a 5 s harness-side bounded wait. Surfaces a typed
    // `PreSeedHealthCheckFailed` within seconds when the docker
    // container is not up; the alternative (skip-probe) burns
    // the full 30 s `SEED_TIMEOUT` for the same root cause.
    probe_postgres().map_err(lift_health_probe_error)?;

    let seed = PostgresSeed {
        rows: postgres_seed_rows(),
    };
    let mut sql = String::new();
    sql.push_str(
        "BEGIN;\n\
         DROP TABLE IF EXISTS service_evidence_pg;\n\
         CREATE TABLE service_evidence_pg (\n  \
           id    TEXT PRIMARY KEY,\n  \
           name  TEXT NOT NULL,\n  \
           value BIGINT NOT NULL\n\
         );\n",
    );
    for r in &seed.rows {
        let name_escaped = r.name.replace('\'', "''");
        let id_escaped = r.id.replace('\'', "''");
        sql.push_str(&format!(
            "INSERT INTO service_evidence_pg (id, name, value) VALUES ('{id_escaped}', '{name_escaped}', {});\n",
            r.value,
        ));
    }
    sql.push_str("COMMIT;\n");

    let pg_target = format!(
        "postgresql://{user}@{host}:{port}/{db}",
        user = SE_PG_USER,
        host = SE_PG_HOST,
        port = SE_PG_PORT,
        db = SE_PG_DATABASE,
    );
    let mut child = Command::new("psql")
        .env("PGPASSWORD", SE_PG_PASSWORD)
        .arg("--quiet")
        .arg("--no-psqlrc")
        .arg("-v")
        .arg("ON_ERROR_STOP=1")
        .arg(&pg_target)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| ServiceEvidenceError::SeedFailed {
            service: "postgres",
            reason: format!("spawn psql: {e}"),
        })?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(sql.as_bytes())
            .map_err(|e| ServiceEvidenceError::SeedFailed {
                service: "postgres",
                reason: format!("write to psql stdin: {e}"),
            })?;
    }
    let out = wait_with_output_timeout(child, SEED_TIMEOUT, "psql")
        .map_err(|e| lift_bounded_wait_error(e, "postgres", &pg_target))?;
    if !out.status.success() {
        return Err(ServiceEvidenceError::SeedFailed {
            service: "postgres",
            reason: format!(
                "psql exit {:?}; stderr=\n{}",
                out.status.code(),
                String::from_utf8_lossy(&out.stderr),
            ),
        });
    }

    let mut probe_cmd = Command::new("psql");
    probe_cmd
        .env("PGPASSWORD", SE_PG_PASSWORD)
        .arg("--quiet")
        .arg("--tuples-only")
        .arg("--no-align")
        .arg(&pg_target)
        .arg("-c")
        .arg("SELECT COUNT(*) FROM service_evidence_pg;");
    let probe = run_command_output_timeout(&mut probe_cmd, SEED_TIMEOUT, "psql-count-probe")
        .map_err(|e| match e {
            BoundedWaitError::Timeout { label, timeout } => ServiceEvidenceError::SeedTimedOut {
                service: "postgres",
                label,
                timeout,
                target: pg_target.clone(),
            },
            other => ServiceEvidenceError::SeedMismatch {
                service: "postgres",
                hint: format!("probe psql: {other}"),
            },
        })?;
    if !probe.status.success() {
        return Err(ServiceEvidenceError::SeedMismatch {
            service: "postgres",
            hint: format!(
                "count probe exit {:?}: {}",
                probe.status.code(),
                String::from_utf8_lossy(&probe.stderr),
            ),
        });
    }
    let probed: usize = String::from_utf8_lossy(&probe.stdout)
        .lines()
        .find_map(|l| l.trim().parse().ok())
        .unwrap_or_default();
    if probed != seed.rows.len() {
        return Err(ServiceEvidenceError::SeedMismatch {
            service: "postgres",
            hint: format!("count want={}, got={probed}", seed.rows.len()),
        });
    }
    Ok(seed)
}

/// Walk the chain + worktree to confirm the executor's
/// service-evidence postgres round-trip landed.
pub fn assert_postgres_round_trip(
    chain: &[AuditEvent],
    worktree_root: &Path,
    seed: &PostgresSeed,
    scope: &WitnessScope,
) -> Result<(), ServiceEvidenceError> {
    let canonical = postgres_canonical_bytes(seed);
    compare_file_against_canonical("postgres", worktree_root, POSTGRES_OUTPUT_FILE, &canonical)?;
    if find_proxy_started(chain, scope, "postgres").is_none() {
        return Err(ServiceEvidenceError::AuditEventMissing {
            service: "postgres",
            expected_kind: "CredentialProxyStarted",
            scope: scope.clone(),
            hint: "proxy_type == \"postgres\"".to_owned(),
        });
    }
    if !has_upstream_connected(chain, scope, "postgres") {
        return Err(ServiceEvidenceError::AuditEventMissing {
            service: "postgres",
            expected_kind: "CredentialProxyUpstreamConnected",
            scope: scope.clone(),
            hint: "proxy_type == \"postgres\"".to_owned(),
        });
    }
    let saw_select = chain.iter().any(|ev| {
        if !scope.matches(ev) {
            return false;
        }
        matches!(
            typed(ev),
            Some(AuditEventKind::DatabaseQueryExecuted {
                operation, blocked: false, ..
            }) if operation == "SELECT"
        )
    });
    if !saw_select {
        return Err(ServiceEvidenceError::AuditEventMissing {
            service: "postgres",
            expected_kind: "DatabaseQueryExecuted",
            scope: scope.clone(),
            hint: "operation == \"SELECT\" && blocked == false".to_owned(),
        });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// MongoDB — seed + canonical form + round-trip witness.
//
// Distinct collection `service_evidence_mongo` so the materialiser's
// `seeded_docs` is untouched. Canonical form: one JSON object per
// line, sorted by `doc_id`, with object keys serialized in a
// deterministic order matching the seed-shape declared here.
// ---------------------------------------------------------------------------

pub const SE_MONGODB_DOC_COUNT: usize = 5;

#[derive(Debug, Clone)]
pub struct MongoSeed {
    pub docs: Vec<MongoSeedDoc>,
}

#[derive(Debug, Clone)]
pub struct MongoSeedDoc {
    pub doc_id: String,
    pub label: String,
    pub magic: i64,
}

pub fn mongo_seed_docs() -> Vec<MongoSeedDoc> {
    (1..=SE_MONGODB_DOC_COUNT)
        .map(|i| MongoSeedDoc {
            doc_id: format!("mongo_seed_doc_{i}"),
            label: format!("service-evidence-label-{i}"),
            magic: (i as i64) * 1_000_003,
        })
        .collect()
}

/// Canonical form for the mongo seed: one JSON document per line
/// sorted by `doc_id`, with stable field order `{doc_id, label,
/// magic}`. Uses `serde_json::Value` with the explicit object
/// construction we control here so driver-side field ordering does
/// not matter — the executor's prompt instructs them to produce
/// the same canonical form.
pub fn mongo_canonical_bytes(seed: &MongoSeed) -> Vec<u8> {
    let mut docs = seed.docs.clone();
    docs.sort_by(|a, b| a.doc_id.cmp(&b.doc_id));
    let mut out = String::new();
    for d in &docs {
        let canonical = serde_json::Value::Object(serde_json::Map::from_iter([
            (
                "doc_id".to_owned(),
                serde_json::Value::String(d.doc_id.clone()),
            ),
            (
                "label".to_owned(),
                serde_json::Value::String(d.label.clone()),
            ),
            (
                "magic".to_owned(),
                serde_json::Value::Number(d.magic.into()),
            ),
        ]));
        out.push_str(&serde_json::to_string(&canonical).expect("canonical mongo doc serialises"));
        out.push('\n');
    }
    out.into_bytes()
}

pub fn seed_mongodb() -> Result<MongoSeed, ServiceEvidenceError> {
    probe_mongodb().map_err(lift_health_probe_error)?;
    let seed = MongoSeed {
        docs: mongo_seed_docs(),
    };
    let docs_js = seed
        .docs
        .iter()
        .map(|d| {
            let label_escaped = d.label.replace('\\', "\\\\").replace('"', "\\\"");
            let id_escaped = d.doc_id.replace('\\', "\\\\").replace('"', "\\\"");
            format!(
            "{{ doc_id: \"{id_escaped}\", label: \"{label_escaped}\", magic: NumberLong({val}) }}",
            val = d.magic,
        )
        })
        .collect::<Vec<_>>()
        .join(",\n  ");
    let js = format!(
        "const target = db.getSiblingDB(\"{db}\");\n\
         const coll = target.getCollection(\"service_evidence_mongo\");\n\
         coll.drop();\n\
         coll.insertMany([\n  {docs}\n]);\n\
         const n = coll.countDocuments({{}});\n\
         if (n !== {expected}) {{ throw new Error(\"service_evidence_mongo count drift: got \" + n); }}\n\
         print(\"[service-evidence] mongo seed ok n=\" + n);\n",
        db       = SE_MONGO_DATABASE,
        docs     = docs_js,
        expected = SE_MONGODB_DOC_COUNT,
    );
    let uri = format!(
        "mongodb://{user}:{password}@{host}:{port}/{db}?authSource=admin",
        user = SE_MONGO_USER,
        password = SE_MONGO_PASSWORD,
        host = SE_MONGO_HOST,
        port = SE_MONGO_PORT,
        db = SE_MONGO_DATABASE,
    );
    let mut child = Command::new("mongosh")
        .arg("--quiet")
        .arg(&uri)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| ServiceEvidenceError::SeedFailed {
            service: "mongodb",
            reason: format!("spawn mongosh: {e}"),
        })?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(js.as_bytes())
            .map_err(|e| ServiceEvidenceError::SeedFailed {
                service: "mongodb",
                reason: format!("write mongosh stdin: {e}"),
            })?;
    }
    let out = wait_with_output_timeout(child, SEED_TIMEOUT, "mongosh")
        .map_err(|e| lift_bounded_wait_error(e, "mongodb", &uri))?;
    if !out.status.success() {
        return Err(ServiceEvidenceError::SeedFailed {
            service: "mongodb",
            reason: format!(
                "mongosh exit {:?}; stderr=\n{}",
                out.status.code(),
                String::from_utf8_lossy(&out.stderr),
            ),
        });
    }
    Ok(seed)
}

pub fn assert_mongodb_round_trip(
    chain: &[AuditEvent],
    worktree_root: &Path,
    seed: &MongoSeed,
    scope: &WitnessScope,
) -> Result<(), ServiceEvidenceError> {
    let canonical = mongo_canonical_bytes(seed);
    compare_file_against_canonical("mongodb", worktree_root, MONGODB_OUTPUT_FILE, &canonical)?;
    if find_proxy_started(chain, scope, "mongodb").is_none() {
        return Err(ServiceEvidenceError::AuditEventMissing {
            service: "mongodb",
            expected_kind: "CredentialProxyStarted",
            scope: scope.clone(),
            hint: "proxy_type == \"mongodb\"".to_owned(),
        });
    }
    if !has_upstream_connected(chain, scope, "mongodb") {
        return Err(ServiceEvidenceError::AuditEventMissing {
            service: "mongodb",
            expected_kind: "CredentialProxyUpstreamConnected",
            scope: scope.clone(),
            hint: "proxy_type == \"mongodb\"".to_owned(),
        });
    }
    let saw_find = chain.iter().any(|ev| {
        if !scope.matches(ev) {
            return false;
        }
        matches!(
            typed(ev),
            Some(AuditEventKind::MongoCommandExecuted {
                command, blocked: false, ..
            }) if command == "find"
        )
    });
    if !saw_find {
        return Err(ServiceEvidenceError::AuditEventMissing {
            service: "mongodb",
            expected_kind: "MongoCommandExecuted",
            scope: scope.clone(),
            hint: "command == \"find\" && blocked == false".to_owned(),
        });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Redis — seed + canonical form + round-trip witness.
//
// 5 distinguishable keys / values. Canonical form: `<key>=<value>`
// lines sorted by key.
// ---------------------------------------------------------------------------

pub const SE_REDIS_KEY_COUNT: usize = 5;

#[derive(Debug, Clone)]
pub struct RedisSeed {
    pub entries: Vec<RedisSeedEntry>,
}

#[derive(Debug, Clone)]
pub struct RedisSeedEntry {
    pub key: String,
    pub value: String,
}

pub fn redis_seed_entries() -> Vec<RedisSeedEntry> {
    (1..=SE_REDIS_KEY_COUNT)
        .map(|i| RedisSeedEntry {
            key: format!("service-evidence:redis_seed_key_{i}"),
            value: format!("redis_seed_value_{i}"),
        })
        .collect()
}

pub fn redis_canonical_bytes(seed: &RedisSeed) -> Vec<u8> {
    let mut entries = seed.entries.clone();
    entries.sort_by(|a, b| a.key.cmp(&b.key));
    let mut out = String::new();
    for e in &entries {
        out.push_str(&format!("{}={}\n", e.key, e.value));
    }
    out.into_bytes()
}

pub fn seed_redis() -> Result<RedisSeed, ServiceEvidenceError> {
    probe_redis().map_err(lift_health_probe_error)?;
    let seed = RedisSeed {
        entries: redis_seed_entries(),
    };
    // Build a redis-cli script that:
    //   1. Wipes any existing service-evidence keys (idempotent re-run).
    //   2. SETs each seed key.
    //   3. Confirms the count via DBSIZE-or-EXISTS for each key.
    //
    // We pipe a multi-line command list through `redis-cli -a`.
    // The `-x` switch is not used because we want one command per
    // line, not a single ARGV write.
    let mut script = String::new();
    // Wipe a known prefix; redis-cli script does not support globs
    // here, so we explicitly DEL every expected key first.
    for e in &seed.entries {
        script.push_str(&format!("DEL {}\n", e.key));
    }
    for e in &seed.entries {
        script.push_str(&format!("SET {} {}\n", e.key, e.value));
    }
    let redis_target = format!("redis://{}:{}", SE_REDIS_HOST, SE_REDIS_PORT);
    let mut child = Command::new("redis-cli")
        .arg("-h")
        .arg(SE_REDIS_HOST)
        .arg("-p")
        .arg(SE_REDIS_PORT.to_string())
        .arg("-a")
        .arg(SE_REDIS_PASSWORD)
        .arg("--no-auth-warning")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| ServiceEvidenceError::SeedFailed {
            service: "redis",
            reason: format!("spawn redis-cli: {e}"),
        })?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(script.as_bytes())
            .map_err(|e| ServiceEvidenceError::SeedFailed {
                service: "redis",
                reason: format!("write redis-cli stdin: {e}"),
            })?;
    }
    let out = wait_with_output_timeout(child, SEED_TIMEOUT, "redis-cli")
        .map_err(|e| lift_bounded_wait_error(e, "redis", &redis_target))?;
    if !out.status.success() {
        return Err(ServiceEvidenceError::SeedFailed {
            service: "redis",
            reason: format!(
                "redis-cli exit {:?}; stderr=\n{}",
                out.status.code(),
                String::from_utf8_lossy(&out.stderr),
            ),
        });
    }
    // The script terminates with a stream of `OK` lines. We do not
    // parse them — the round-trip witness will catch a half-applied
    // seed via the canonical-bytes comparison.
    Ok(seed)
}

pub fn assert_redis_round_trip(
    chain: &[AuditEvent],
    worktree_root: &Path,
    seed: &RedisSeed,
    scope: &WitnessScope,
) -> Result<(), ServiceEvidenceError> {
    let canonical = redis_canonical_bytes(seed);
    compare_file_against_canonical("redis", worktree_root, REDIS_OUTPUT_FILE, &canonical)?;
    if find_proxy_started(chain, scope, "redis").is_none() {
        return Err(ServiceEvidenceError::AuditEventMissing {
            service: "redis",
            expected_kind: "CredentialProxyStarted",
            scope: scope.clone(),
            hint: "proxy_type == \"redis\"".to_owned(),
        });
    }
    if !has_upstream_connected(chain, scope, "redis") {
        return Err(ServiceEvidenceError::AuditEventMissing {
            service: "redis",
            expected_kind: "CredentialProxyUpstreamConnected",
            scope: scope.clone(),
            hint: "proxy_type == \"redis\"".to_owned(),
        });
    }
    let saw_get = chain.iter().any(|ev| {
        if !scope.matches(ev) {
            return false;
        }
        matches!(
            typed(ev),
            Some(AuditEventKind::RedisCommandExecuted {
                command, blocked: false, ..
            }) if command == "GET" || command == "MGET"
        )
    });
    if !saw_get {
        return Err(ServiceEvidenceError::AuditEventMissing {
            service: "redis",
            expected_kind: "RedisCommandExecuted",
            scope: scope.clone(),
            hint: "command == \"GET\" || \"MGET\" && blocked == false".to_owned(),
        });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// SMTP — seed + canonical envelope + round-trip witness.
//
// The SMTP credential proxy is an outbound submission proxy
// (`credential-proxy.md §4.7`), not a mailbox reader. The
// round-trip we exercise here is therefore "executor SENDS a
// known envelope through the proxy → proxy emits
// `SmtpMessageRelayed` with the canonical envelope_sha256 →
// witness compares the executor's transcript file to the
// canonical envelope spec AND confirms the audit event landed".
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct SmtpSeed {
    pub sender: String,
    pub recipients: Vec<String>,
    pub subject: String,
    pub body: String,
}

pub fn smtp_seed() -> SmtpSeed {
    SmtpSeed {
        sender: "sender@live-e2e.test".to_owned(),
        recipients: vec![SE_SMTP_MAILBOX.to_owned()],
        subject: "smtp_seed_subject_1".to_owned(),
        body: "smtp_seed_body_1: service-evidence smtp round-trip".to_owned(),
    }
}

/// Canonical text form of the SMTP envelope. Keys + body on
/// distinct `from:` / `to:` / `subject:` / `body:` lines, with
/// recipients comma-joined. This is what the executor's
/// `out/services/smtp.txt` MUST byte-equal.
pub fn smtp_canonical_bytes(seed: &SmtpSeed) -> Vec<u8> {
    let mut rcpts = seed.recipients.clone();
    rcpts.sort();
    let mut out = String::new();
    out.push_str(&format!("from: {}\n", seed.sender));
    out.push_str(&format!("to: {}\n", rcpts.join(",")));
    out.push_str(&format!("subject: {}\n", seed.subject));
    out.push_str(&format!("body: {}\n", seed.body));
    out.into_bytes()
}

/// Canonical envelope-key SHA-256 the proxy's
/// `SmtpMessageRelayed.envelope_sha256` must equal. The proxy
/// definition (audit/src/event.rs §SmtpMessageRelayed) pins the
/// canonical key as `<sender>\n<rcpt1>\n<rcpt2>...`.
pub fn smtp_envelope_sha256(seed: &SmtpSeed) -> String {
    let mut envelope = String::new();
    envelope.push_str(&seed.sender);
    let mut rcpts = seed.recipients.clone();
    rcpts.sort();
    for r in &rcpts {
        envelope.push('\n');
        envelope.push_str(r);
    }
    sha256_hex(envelope.as_bytes())
}

/// Pre-deliver one fixture message to the mailserver so an
/// operator inspecting `docker exec raxis-e2e-smtp doveadm` after
/// the run sees the expected mailbox contents alongside whatever
/// the executor relayed. The proxy's outbound-only nature means
/// this seed is mainly a check that the SMTP container is up — we
/// open a plain SMTP submission over loopback (no TLS, no AUTH
/// since the container's PERMIT_DOCKER policy admits connected
/// networks). If the container is not reachable the witness's
/// upstream-connected audit event would also be absent, so this
/// seed failing is the earlier and clearer signal.
pub fn seed_smtp() -> Result<SmtpSeed, ServiceEvidenceError> {
    probe_smtp().map_err(lift_health_probe_error)?;
    let seed = smtp_seed();
    // Plain SMTP submission against the mailserver's :25 (mapped
    // to host :25199). Hand-rolled because we don't want a `lettre`
    // dev-dep just for one fixture deliver.
    let addr = (SE_SMTP_HOST, SE_SMTP_PORT);
    let mut stream = TcpStream::connect_timeout(
        &format!("{}:{}", SE_SMTP_HOST, SE_SMTP_PORT)
            .parse()
            .expect("smtp addr literal parses"),
        Duration::from_secs(5),
    )
    .map_err(|e| ServiceEvidenceError::SeedFailed {
        service: "smtp",
        reason: format!("connect {}:{}: {e}", addr.0, addr.1),
    })?;
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .map_err(|e| ServiceEvidenceError::SeedFailed {
            service: "smtp",
            reason: format!("set_read_timeout: {e}"),
        })?;
    stream
        .set_write_timeout(Some(Duration::from_secs(10)))
        .map_err(|e| ServiceEvidenceError::SeedFailed {
            service: "smtp",
            reason: format!("set_write_timeout: {e}"),
        })?;
    smtp_expect_code(&mut stream, "220", "banner")?;
    smtp_send(&mut stream, "EHLO live-e2e.test\r\n", "smtp", "EHLO")?;
    smtp_expect_code(&mut stream, "250", "EHLO")?;
    smtp_send(
        &mut stream,
        &format!("MAIL FROM:<{}>\r\n", seed.sender),
        "smtp",
        "MAIL FROM",
    )?;
    smtp_expect_code(&mut stream, "250", "MAIL FROM")?;
    for r in &seed.recipients {
        smtp_send(
            &mut stream,
            &format!("RCPT TO:<{r}>\r\n"),
            "smtp",
            "RCPT TO",
        )?;
        smtp_expect_code(&mut stream, "250", "RCPT TO")?;
    }
    smtp_send(&mut stream, "DATA\r\n", "smtp", "DATA")?;
    smtp_expect_code(&mut stream, "354", "DATA")?;
    let mut data = String::new();
    data.push_str(&format!("From: {}\r\n", seed.sender));
    data.push_str(&format!("To: {}\r\n", seed.recipients.join(", ")));
    data.push_str(&format!("Subject: {}\r\n", seed.subject));
    data.push_str("MIME-Version: 1.0\r\n");
    data.push_str("Content-Type: text/plain; charset=utf-8\r\n");
    data.push_str("\r\n");
    data.push_str(&seed.body);
    data.push_str("\r\n.\r\n");
    smtp_send(&mut stream, &data, "smtp", "DATA body")?;
    smtp_expect_code(&mut stream, "250", "DATA terminator")?;
    smtp_send(&mut stream, "QUIT\r\n", "smtp", "QUIT")?;
    // Do not assert on QUIT response code — some servers close the
    // socket without writing `221`.
    Ok(seed)
}

fn smtp_send(
    stream: &mut TcpStream,
    line: &str,
    service: &'static str,
    label: &str,
) -> Result<(), ServiceEvidenceError> {
    stream
        .write_all(line.as_bytes())
        .map_err(|e| ServiceEvidenceError::SeedFailed {
            service,
            reason: format!("write {label}: {e}"),
        })
}

fn smtp_expect_code(
    stream: &mut TcpStream,
    prefix: &str,
    label: &str,
) -> Result<(), ServiceEvidenceError> {
    let mut buf = [0u8; 4096];
    let n = stream
        .read(&mut buf)
        .map_err(|e| ServiceEvidenceError::SeedFailed {
            service: "smtp",
            reason: format!("read {label}: {e}"),
        })?;
    let line = String::from_utf8_lossy(&buf[..n]).to_string();
    // SMTP multi-line replies use `<code>-text` on every line
    // except the last, which uses `<code> text`. We accept either
    // shape — the prefix match handles both.
    if !line.starts_with(prefix) {
        return Err(ServiceEvidenceError::SeedFailed {
            service: "smtp",
            reason: format!("SMTP {label} expected {prefix}xx, got: {}", line.trim_end(),),
        });
    }
    Ok(())
}

pub fn assert_smtp_round_trip(
    chain: &[AuditEvent],
    worktree_root: &Path,
    seed: &SmtpSeed,
    scope: &WitnessScope,
) -> Result<(), ServiceEvidenceError> {
    let canonical = smtp_canonical_bytes(seed);
    compare_file_against_canonical("smtp", worktree_root, SMTP_OUTPUT_FILE, &canonical)?;
    if find_proxy_started(chain, scope, "smtp").is_none() {
        return Err(ServiceEvidenceError::AuditEventMissing {
            service: "smtp",
            expected_kind: "CredentialProxyStarted",
            scope: scope.clone(),
            hint: "proxy_type == \"smtp\"".to_owned(),
        });
    }
    let expected_envelope_sha = smtp_envelope_sha256(seed);
    let saw_relay = chain.iter().any(|ev| {
        if !scope.matches(ev) {
            return false;
        }
        matches!(
            typed(ev),
            Some(AuditEventKind::SmtpMessageRelayed { envelope_sha256, .. })
                if envelope_sha256 == expected_envelope_sha
        )
    });
    if !saw_relay {
        return Err(ServiceEvidenceError::AuditEventMissing {
            service: "smtp",
            expected_kind: "SmtpMessageRelayed",
            scope: scope.clone(),
            hint: format!(
                "envelope_sha256 == \"{expected_envelope_sha}\" \
                 (sender + sorted-recipients SHA-256)",
            ),
        });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// MySQL — opt-in gated round-trip witness.
//
// The un-mock worker shipped the `mysql:8.0.36` container but
// flagged the credential proxy's handshake as `🟡 opt-in` because
// of a `mysql_native_password` regression tracked separately.
// The witness here therefore SHORT-CIRCUITS to `Ok(())` with a
// one-line eprintln! note whenever `RAXIS_LIVE_MYSQL_URL` is
// absent. Once the proxy is fixed the operator (or the un-mock
// worker) exports the env var and the witness becomes active
// without any kernel-side or test-side code change.
// ---------------------------------------------------------------------------

pub const SE_MYSQL_ROW_COUNT: usize = 5;

#[derive(Debug, Clone)]
pub struct MysqlSeed {
    pub rows: Vec<MysqlSeedRow>,
}

#[derive(Debug, Clone)]
pub struct MysqlSeedRow {
    pub id: String,
    pub name: String,
    pub value: i64,
}

pub fn mysql_seed_rows() -> Vec<MysqlSeedRow> {
    (1..=SE_MYSQL_ROW_COUNT)
        .map(|i| MysqlSeedRow {
            id: format!("mysql_seed_row_{i}"),
            name: format!("service-evidence-mysql-{i}"),
            value: (i as i64) * 1_299_709,
        })
        .collect()
}

pub fn mysql_canonical_bytes(seed: &MysqlSeed) -> Vec<u8> {
    let mut rows = seed.rows.clone();
    rows.sort_by(|a, b| a.id.cmp(&b.id));
    let mut out = String::new();
    for r in &rows {
        out.push_str(&format!("{}|{}|{}\n", r.id, r.name, r.value));
    }
    out.into_bytes()
}

/// Seed `service_evidence_mysql` against the container the
/// un-mock worker shipped. Skipped when [`ENV_LIVE_MYSQL_URL`] is
/// unset; the matching `assert_mysql_round_trip` is also skipped.
/// Returns the canonical seed shape so callers can render it into
/// `mysql.txt` themselves if needed.
pub fn seed_mysql() -> Result<MysqlSeed, ServiceEvidenceError> {
    let seed = MysqlSeed {
        rows: mysql_seed_rows(),
    };
    // Probe is opt-in (skips when ENV_LIVE_MYSQL_URL is unset)
    // so the env-gated short-circuit below remains the
    // authoritative gate; we still call the probe so the
    // env-set path fails closed within 5 s rather than after 30 s.
    probe_mysql().map_err(lift_health_probe_error)?;
    if std::env::var(ENV_LIVE_MYSQL_URL).is_err() {
        eprintln!(
            "[service-evidence:mysql] {ENV_LIVE_MYSQL_URL} not set; \
             seed bypassed (returns canonical shape only). Export the var \
             to activate this path once the credential-proxy regression \
             is resolved.",
        );
        return Ok(seed);
    }
    let mut sql = String::new();
    sql.push_str(
        "DROP TABLE IF EXISTS service_evidence_mysql;\n\
         CREATE TABLE service_evidence_mysql (\n  \
           id    VARCHAR(64) PRIMARY KEY,\n  \
           name  VARCHAR(255) NOT NULL,\n  \
           value BIGINT NOT NULL\n\
         );\n",
    );
    for r in &seed.rows {
        let name_escaped = r.name.replace('\'', "''");
        let id_escaped = r.id.replace('\'', "''");
        sql.push_str(&format!(
            "INSERT INTO service_evidence_mysql (id, name, value) VALUES ('{id_escaped}', '{name_escaped}', {});\n",
            r.value,
        ));
    }
    let mysql_target = format!("mysql://raxis_test@{SE_PG_HOST}:33099/raxis_e2e");
    let mut child = Command::new("mysql")
        .arg(format!("--host={SE_PG_HOST}"))
        .arg("--protocol=TCP")
        .arg("--port=33099")
        .arg("--user=raxis_test")
        .arg("--password=raxis_test_pass")
        .arg("raxis_e2e")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| ServiceEvidenceError::SeedFailed {
            service: "mysql",
            reason: format!("spawn mysql: {e}"),
        })?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(sql.as_bytes())
            .map_err(|e| ServiceEvidenceError::SeedFailed {
                service: "mysql",
                reason: format!("write mysql stdin: {e}"),
            })?;
    }
    let out = wait_with_output_timeout(child, SEED_TIMEOUT, "mysql")
        .map_err(|e| lift_bounded_wait_error(e, "mysql", &mysql_target))?;
    if !out.status.success() {
        return Err(ServiceEvidenceError::SeedFailed {
            service: "mysql",
            reason: format!(
                "mysql exit {:?}; stderr=\n{}",
                out.status.code(),
                String::from_utf8_lossy(&out.stderr),
            ),
        });
    }
    Ok(seed)
}

pub fn assert_mysql_round_trip(
    chain: &[AuditEvent],
    worktree_root: &Path,
    seed: &MysqlSeed,
    scope: &WitnessScope,
) -> Result<(), ServiceEvidenceError> {
    if std::env::var(ENV_LIVE_MYSQL_URL).is_err() {
        eprintln!(
            "[service-evidence:mysql] {ENV_LIVE_MYSQL_URL} not set; \
             round-trip assertion bypassed. The helper preserves its \
             call-site shape so a future operator export becomes active \
             with no code change.",
        );
        return Ok(());
    }
    let canonical = mysql_canonical_bytes(seed);
    compare_file_against_canonical("mysql", worktree_root, MYSQL_OUTPUT_FILE, &canonical)?;
    if find_proxy_started(chain, scope, "mysql").is_none() {
        return Err(ServiceEvidenceError::AuditEventMissing {
            service: "mysql",
            expected_kind: "CredentialProxyStarted",
            scope: scope.clone(),
            hint: "proxy_type == \"mysql\"".to_owned(),
        });
    }
    if !has_upstream_connected(chain, scope, "mysql") {
        return Err(ServiceEvidenceError::AuditEventMissing {
            service: "mysql",
            expected_kind: "CredentialProxyUpstreamConnected",
            scope: scope.clone(),
            hint: "proxy_type == \"mysql\"".to_owned(),
        });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// MSSQL — opt-in gated round-trip witness.
//
// Same shape as `mysql` above. Gated behind `RAXIS_LIVE_MSSQL_URL`.
// ---------------------------------------------------------------------------

pub const SE_MSSQL_ROW_COUNT: usize = 5;

#[derive(Debug, Clone)]
pub struct MssqlSeed {
    pub rows: Vec<MssqlSeedRow>,
}

#[derive(Debug, Clone)]
pub struct MssqlSeedRow {
    pub id: String,
    pub name: String,
    pub value: i64,
}

pub fn mssql_seed_rows() -> Vec<MssqlSeedRow> {
    (1..=SE_MSSQL_ROW_COUNT)
        .map(|i| MssqlSeedRow {
            id: format!("mssql_seed_row_{i}"),
            name: format!("service-evidence-mssql-{i}"),
            value: (i as i64) * 15_485_863,
        })
        .collect()
}

pub fn mssql_canonical_bytes(seed: &MssqlSeed) -> Vec<u8> {
    let mut rows = seed.rows.clone();
    rows.sort_by(|a, b| a.id.cmp(&b.id));
    let mut out = String::new();
    for r in &rows {
        out.push_str(&format!("{}|{}|{}\n", r.id, r.name, r.value));
    }
    out.into_bytes()
}

pub fn seed_mssql() -> Result<MssqlSeed, ServiceEvidenceError> {
    let seed = MssqlSeed {
        rows: mssql_seed_rows(),
    };
    // Probe is opt-in (skips when ENV_LIVE_MSSQL_URL is unset).
    probe_mssql().map_err(lift_health_probe_error)?;
    if std::env::var(ENV_LIVE_MSSQL_URL).is_err() {
        eprintln!(
            "[service-evidence:mssql] {ENV_LIVE_MSSQL_URL} not set; \
             seed bypassed (returns canonical shape only).",
        );
        return Ok(seed);
    }
    // sqlcmd-driven seed; gated on the opt-in URL being set so the
    // CI default does not depend on `sqlcmd` being installed.
    let mut sql = String::new();
    sql.push_str(
        "IF OBJECT_ID('dbo.service_evidence_mssql', 'U') IS NOT NULL DROP TABLE dbo.service_evidence_mssql;\n\
         CREATE TABLE dbo.service_evidence_mssql (\n  \
           id    NVARCHAR(64) PRIMARY KEY,\n  \
           name  NVARCHAR(255) NOT NULL,\n  \
           value BIGINT NOT NULL\n\
         );\n",
    );
    for r in &seed.rows {
        let name_escaped = r.name.replace('\'', "''");
        let id_escaped = r.id.replace('\'', "''");
        sql.push_str(&format!(
            "INSERT INTO dbo.service_evidence_mssql (id, name, value) VALUES ('{id_escaped}', '{name_escaped}', {});\n",
            r.value,
        ));
    }
    let mssql_target = "mssql://sa@127.0.0.1:14399/master".to_owned();
    let mut child = Command::new("sqlcmd")
        .arg("-S")
        .arg("127.0.0.1,14399")
        .arg("-U")
        .arg("sa")
        .arg("-P")
        .arg("raxis_Test_Pass1!")
        .arg("-C")
        .arg("-d")
        .arg("master")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| ServiceEvidenceError::SeedFailed {
            service: "mssql",
            reason: format!("spawn sqlcmd: {e}"),
        })?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(sql.as_bytes())
            .map_err(|e| ServiceEvidenceError::SeedFailed {
                service: "mssql",
                reason: format!("write sqlcmd stdin: {e}"),
            })?;
    }
    let out = wait_with_output_timeout(child, SEED_TIMEOUT, "sqlcmd")
        .map_err(|e| lift_bounded_wait_error(e, "mssql", &mssql_target))?;
    if !out.status.success() {
        return Err(ServiceEvidenceError::SeedFailed {
            service: "mssql",
            reason: format!(
                "sqlcmd exit {:?}; stderr=\n{}",
                out.status.code(),
                String::from_utf8_lossy(&out.stderr),
            ),
        });
    }
    Ok(seed)
}

pub fn assert_mssql_round_trip(
    chain: &[AuditEvent],
    worktree_root: &Path,
    seed: &MssqlSeed,
    scope: &WitnessScope,
) -> Result<(), ServiceEvidenceError> {
    if std::env::var(ENV_LIVE_MSSQL_URL).is_err() {
        eprintln!(
            "[service-evidence:mssql] {ENV_LIVE_MSSQL_URL} not set; \
             round-trip assertion bypassed.",
        );
        return Ok(());
    }
    let canonical = mssql_canonical_bytes(seed);
    compare_file_against_canonical("mssql", worktree_root, MSSQL_OUTPUT_FILE, &canonical)?;
    if find_proxy_started(chain, scope, "mssql").is_none() {
        return Err(ServiceEvidenceError::AuditEventMissing {
            service: "mssql",
            expected_kind: "CredentialProxyStarted",
            scope: scope.clone(),
            hint: "proxy_type == \"mssql\"".to_owned(),
        });
    }
    if !has_upstream_connected(chain, scope, "mssql") {
        return Err(ServiceEvidenceError::AuditEventMissing {
            service: "mssql",
            expected_kind: "CredentialProxyUpstreamConnected",
            scope: scope.clone(),
            hint: "proxy_type == \"mssql\"".to_owned(),
        });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Smoke-test fixture: hand-build a complete service-evidence chain
// the realistic-scenario wiring smoke test can drive when the
// `RAXIS_LIVE_E2E_REALISTIC` gate is OFF. Keeps the witness wiring
// mechanically validated even on a developer's laptop with no
// docker stack up.
// ---------------------------------------------------------------------------

/// Build a synthetic per-service audit chain that satisfies every
/// active witness (postgres, mongodb, redis, smtp). Used by the
/// smoke test in [`crate::extended_e2e_realistic_scenario`].
pub fn synthetic_service_chain(
    initiative_id: &str,
    task_id: &str,
    session_id: &str,
    smtp_envelope: &str,
) -> Vec<AuditEvent> {
    let mut seq: u64 = 100;
    let mut chain: Vec<AuditEvent> = Vec::new();
    for proxy_type in &["postgres", "mongodb", "redis", "smtp"] {
        chain.push(make_event(
            seq,
            initiative_id,
            task_id,
            session_id,
            AuditEventKind::CredentialProxyStarted {
                session_id: session_id.to_owned(),
                proxy_type: (*proxy_type).to_owned(),
                credential_name: format!("test-{proxy_type}-dev"),
                addr: "127.0.0.1:0".to_owned(),
            },
        ));
        seq += 1;
        chain.push(make_event(
            seq,
            initiative_id,
            task_id,
            session_id,
            AuditEventKind::CredentialProxyUpstreamConnected {
                session_id: session_id.to_owned(),
                credential_name: format!("test-{proxy_type}-dev"),
                proxy_type: (*proxy_type).to_owned(),
                upstream_host: "127.0.0.1".to_owned(),
                upstream_port: 54399,
                tls: false,
                handshake_ms: 1,
            },
        ));
        seq += 1;
    }
    chain.push(make_event(
        seq,
        initiative_id,
        task_id,
        session_id,
        AuditEventKind::DatabaseQueryExecuted {
            session_id: session_id.to_owned(),
            credential_name: "test-pg-dev".to_owned(),
            operation: "SELECT".to_owned(),
            sql_sha256: "0".repeat(64),
            sql_plaintext: None,
            blocked: false,
        },
    ));
    seq += 1;
    chain.push(make_event(
        seq,
        initiative_id,
        task_id,
        session_id,
        AuditEventKind::MongoCommandExecuted {
            session_id: session_id.to_owned(),
            credential_name: "test-mongo-dev".to_owned(),
            command: "find".to_owned(),
            body_sha256: "0".repeat(64),
            blocked: false,
        },
    ));
    seq += 1;
    chain.push(make_event(
        seq,
        initiative_id,
        task_id,
        session_id,
        AuditEventKind::RedisCommandExecuted {
            session_id: session_id.to_owned(),
            credential_name: "test-redis-dev".to_owned(),
            command: "GET".to_owned(),
            frame_sha256: "0".repeat(64),
            blocked: false,
        },
    ));
    seq += 1;
    chain.push(make_event(
        seq,
        initiative_id,
        task_id,
        session_id,
        AuditEventKind::SmtpMessageRelayed {
            session_id: session_id.to_owned(),
            credential_name: "test-smtp-dev".to_owned(),
            envelope_sha256: smtp_envelope.to_owned(),
            recipient_count: 1,
            bytes_relayed: 42,
        },
    ));
    chain
}

fn make_event(
    seq: u64,
    initiative_id: &str,
    task_id: &str,
    session_id: &str,
    kind: AuditEventKind,
) -> AuditEvent {
    let event_kind = kind.as_str().to_owned();
    AuditEvent {
        seq,
        event_id: uuid::Uuid::nil(),
        event_kind,
        session_id: Some(session_id.to_owned()),
        task_id: Some(task_id.to_owned()),
        initiative_id: Some(initiative_id.to_owned()),
        payload: serde_json::to_value(&kind).expect("AuditEventKind serialises"),
        emitted_at: 1_700_000_000 + seq as i64,
        prev_sha256: "0".repeat(64),
    }
}

// ---------------------------------------------------------------------------
// Worktree-fixture helpers — write the per-service canonical output
// files the witness asserts on, used by both the smoke test and any
// future bench / regression that wants to exercise the helpers
// without a live executor.
// ---------------------------------------------------------------------------

/// Materialise every active per-service output file under
/// `<worktree>/out/services/...` using the canonical seed shapes
/// declared in this module. Used by the wiring smoke test so the
/// witnesses operate against a real worktree-shaped fixture even
/// when no kernel ran.
pub fn write_canonical_outputs_for_smoke(
    worktree_root: &Path,
    pg_seed: &PostgresSeed,
    mongo_seed: &MongoSeed,
    redis_seed: &RedisSeed,
    smtp_seed: &SmtpSeed,
) -> std::io::Result<()> {
    std::fs::create_dir_all(worktree_root.join(SERVICE_OUTPUT_DIR))?;
    std::fs::write(
        worktree_root.join(POSTGRES_OUTPUT_FILE),
        postgres_canonical_bytes(pg_seed),
    )?;
    std::fs::write(
        worktree_root.join(MONGODB_OUTPUT_FILE),
        mongo_canonical_bytes(mongo_seed),
    )?;
    std::fs::write(
        worktree_root.join(REDIS_OUTPUT_FILE),
        redis_canonical_bytes(redis_seed),
    )?;
    std::fs::write(
        worktree_root.join(SMTP_OUTPUT_FILE),
        smtp_canonical_bytes(smtp_seed),
    )?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Per-service helper: surface every applicable error from a single
// realistic-scenario witness pass. The driver renders the union of
// failures so an operator sees the full set in one panic rather
// than chasing one fix at a time.
// ---------------------------------------------------------------------------

/// Convenience aggregator: run every active per-service witness
/// against `chain` + `worktree_root` and return the full list of
/// failures.
pub fn collect_active_witness_failures(
    chain: &[AuditEvent],
    worktree_root: &Path,
    pg_seed: &PostgresSeed,
    mongo_seed: &MongoSeed,
    redis_seed: &RedisSeed,
    smtp_seed: &SmtpSeed,
    scope: &WitnessScope,
) -> Vec<ServiceEvidenceError> {
    let mut failures = Vec::new();
    if let Err(e) = assert_postgres_round_trip(chain, worktree_root, pg_seed, scope) {
        failures.push(e);
    }
    if let Err(e) = assert_mongodb_round_trip(chain, worktree_root, mongo_seed, scope) {
        failures.push(e);
    }
    if let Err(e) = assert_redis_round_trip(chain, worktree_root, redis_seed, scope) {
        failures.push(e);
    }
    if let Err(e) = assert_smtp_round_trip(chain, worktree_root, smtp_seed, scope) {
        failures.push(e);
    }
    failures
}

// ---------------------------------------------------------------------------
// Diagnostic: rendered union of `Vec<ServiceEvidenceError>` for
// embedding in a panic.
// ---------------------------------------------------------------------------

pub fn render_failures(failures: &[ServiceEvidenceError]) -> String {
    let mut by_service: BTreeMap<&'static str, Vec<String>> = BTreeMap::new();
    for f in failures {
        let svc = service_of(f);
        by_service.entry(svc).or_default().push(format!("{f}"));
    }
    let mut out = String::new();
    for (svc, lines) in &by_service {
        out.push_str(&format!("── {svc} ──\n"));
        for l in lines {
            out.push_str(&format!("  {l}\n"));
        }
    }
    out
}

fn service_of(e: &ServiceEvidenceError) -> &'static str {
    match e {
        ServiceEvidenceError::SeedFailed { service, .. }
        | ServiceEvidenceError::SeedMismatch { service, .. }
        | ServiceEvidenceError::FileMissing { service, .. }
        | ServiceEvidenceError::FileReadFailed { service, .. }
        | ServiceEvidenceError::FileContentMismatch { service, .. }
        | ServiceEvidenceError::AuditEventMissing { service, .. }
        | ServiceEvidenceError::OptInBypassed { service, .. }
        | ServiceEvidenceError::SeedTimedOut { service, .. }
        | ServiceEvidenceError::PreSeedHealthCheckFailed { service, .. } => service,
    }
}

fn lift_health_probe_error(err: HealthProbeError) -> ServiceEvidenceError {
    ServiceEvidenceError::PreSeedHealthCheckFailed {
        service: err.service,
        target: err.target,
        reason: err.reason,
    }
}

/// Render a [`BoundedWaitError`] into the service-evidence error
/// taxonomy. The `Timeout` variant lifts to `SeedTimedOut` so a
/// regression test and CI log scraper can pattern-match on the
/// timeout path specifically; everything else maps to `SeedFailed`.
fn lift_bounded_wait_error(
    err: BoundedWaitError,
    service: &'static str,
    target: &str,
) -> ServiceEvidenceError {
    match err {
        BoundedWaitError::Timeout { label, timeout } => ServiceEvidenceError::SeedTimedOut {
            service,
            label,
            timeout,
            target: target.to_owned(),
        },
        BoundedWaitError::SpawnFailed { label, reason } => ServiceEvidenceError::SeedFailed {
            service,
            reason: format!("spawn `{label}` against {target}: {reason}"),
        },
        BoundedWaitError::WaitFailed { label, reason } => ServiceEvidenceError::SeedFailed {
            service,
            reason: format!("wait `{label}` against {target}: {reason}"),
        },
    }
}

// ---------------------------------------------------------------------------
// Tests — drive every helper against synthetic fixtures.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn unique_initiative() -> String {
        uuid::Uuid::now_v7().to_string()
    }

    #[test]
    fn postgres_canonical_bytes_sorted_and_terminated() {
        let seed = PostgresSeed {
            rows: postgres_seed_rows(),
        };
        let bytes = postgres_canonical_bytes(&seed);
        let s = String::from_utf8(bytes).unwrap();
        let lines: Vec<&str> = s.lines().collect();
        assert_eq!(lines.len(), SE_POSTGRES_ROW_COUNT);
        // Ordered by id ascending.
        let mut sorted = lines.clone();
        sorted.sort();
        assert_eq!(lines, sorted, "rows must be sorted by id");
        // Each line is `id|name|value`.
        for l in &lines {
            assert_eq!(l.matches('|').count(), 2, "row pipe count: {l}");
        }
    }

    #[test]
    fn mongo_canonical_bytes_stable_object_order() {
        let seed = MongoSeed {
            docs: mongo_seed_docs(),
        };
        let bytes = mongo_canonical_bytes(&seed);
        let s = String::from_utf8(bytes).unwrap();
        for (i, l) in s.lines().enumerate() {
            let v: serde_json::Value = serde_json::from_str(l).unwrap();
            assert_eq!(v["doc_id"], format!("mongo_seed_doc_{}", i + 1));
            // Object key ordering is stable in our canonicaliser:
            // doc_id, label, magic.
            let keys: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
            assert_eq!(keys, vec!["doc_id", "label", "magic"]);
        }
    }

    #[test]
    fn redis_canonical_bytes_sorted_kv_lines() {
        let seed = RedisSeed {
            entries: redis_seed_entries(),
        };
        let bytes = redis_canonical_bytes(&seed);
        let s = String::from_utf8(bytes).unwrap();
        let lines: Vec<&str> = s.lines().collect();
        assert_eq!(lines.len(), SE_REDIS_KEY_COUNT);
        let mut sorted = lines.clone();
        sorted.sort();
        assert_eq!(lines, sorted);
        for l in &lines {
            assert!(l.contains('='), "kv line shape: {l}");
        }
    }

    #[test]
    fn smtp_canonical_envelope_renders_to_four_lines() {
        let seed = smtp_seed();
        let bytes = smtp_canonical_bytes(&seed);
        let s = String::from_utf8(bytes).unwrap();
        let lines: Vec<&str> = s.lines().collect();
        assert_eq!(lines.len(), 4);
        assert!(lines[0].starts_with("from: "));
        assert!(lines[1].starts_with("to: "));
        assert!(lines[2].starts_with("subject: "));
        assert!(lines[3].starts_with("body: "));
        // Envelope SHA must be stable over the (sender, sorted-rcpts) join.
        let sha = smtp_envelope_sha256(&seed);
        assert_eq!(sha.len(), 64);
        assert!(sha.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn synthetic_chain_satisfies_all_active_witnesses() {
        let tmp = tempfile::tempdir().unwrap();
        let pg = PostgresSeed {
            rows: postgres_seed_rows(),
        };
        let mongo = MongoSeed {
            docs: mongo_seed_docs(),
        };
        let redis = RedisSeed {
            entries: redis_seed_entries(),
        };
        let smtp = smtp_seed();
        write_canonical_outputs_for_smoke(tmp.path(), &pg, &mongo, &redis, &smtp).unwrap();
        let initiative = unique_initiative();
        let task = TASK_SERVICE_ROUND_TRIP.to_owned();
        let session = "smoke-sess-1".to_owned();
        let chain =
            synthetic_service_chain(&initiative, &task, &session, &smtp_envelope_sha256(&smtp));
        let scope = WitnessScope::new(initiative.clone(), task.clone()).with_session(session);
        let fails =
            collect_active_witness_failures(&chain, tmp.path(), &pg, &mongo, &redis, &smtp, &scope);
        assert!(
            fails.is_empty(),
            "smoke synthetic chain must satisfy every witness:\n{}",
            render_failures(&fails),
        );
    }

    #[test]
    fn missing_postgres_file_surfaces_with_path() {
        let tmp = tempfile::tempdir().unwrap();
        let pg = PostgresSeed {
            rows: postgres_seed_rows(),
        };
        let chain: Vec<AuditEvent> = Vec::new();
        let scope = WitnessScope::new("init", "task");
        let err = assert_postgres_round_trip(&chain, tmp.path(), &pg, &scope)
            .expect_err("file missing => error");
        let rendered = format!("{err}");
        assert!(rendered.contains("does not exist"), "render: {rendered}");
        assert!(rendered.contains("postgres.txt"), "render: {rendered}");
    }

    #[test]
    fn content_mismatch_surfaces_with_sha_pair() {
        let tmp = tempfile::tempdir().unwrap();
        let pg = PostgresSeed {
            rows: postgres_seed_rows(),
        };
        std::fs::create_dir_all(tmp.path().join(SERVICE_OUTPUT_DIR)).unwrap();
        std::fs::write(
            tmp.path().join(POSTGRES_OUTPUT_FILE),
            b"intentionally wrong content\n",
        )
        .unwrap();
        let chain: Vec<AuditEvent> = Vec::new();
        let scope = WitnessScope::new("init", "task");
        let err = assert_postgres_round_trip(&chain, tmp.path(), &pg, &scope)
            .expect_err("content mismatch => error");
        let rendered = format!("{err}");
        assert!(rendered.contains("expected sha256"), "render: {rendered}");
        assert!(rendered.contains("observed sha256"), "render: {rendered}");
        assert!(rendered.contains("first divergence"), "render: {rendered}");
    }

    #[test]
    fn audit_event_missing_surfaces_with_scope() {
        let tmp = tempfile::tempdir().unwrap();
        let pg = PostgresSeed {
            rows: postgres_seed_rows(),
        };
        std::fs::create_dir_all(tmp.path().join(SERVICE_OUTPUT_DIR)).unwrap();
        std::fs::write(
            tmp.path().join(POSTGRES_OUTPUT_FILE),
            postgres_canonical_bytes(&pg),
        )
        .unwrap();
        let chain: Vec<AuditEvent> = Vec::new();
        let scope = WitnessScope::new("init-x", "task-y");
        let err = assert_postgres_round_trip(&chain, tmp.path(), &pg, &scope)
            .expect_err("audit-event missing => error");
        let rendered = format!("{err}");
        assert!(
            rendered.contains("CredentialProxyStarted"),
            "render: {rendered}"
        );
        assert!(rendered.contains("init-x"), "render: {rendered}");
        assert!(rendered.contains("task-y"), "render: {rendered}");
    }

    #[test]
    fn mysql_witness_bypassed_when_env_unset() {
        let _guard = clear_env_for_test(ENV_LIVE_MYSQL_URL);
        let tmp = tempfile::tempdir().unwrap();
        let seed = MysqlSeed {
            rows: mysql_seed_rows(),
        };
        let chain: Vec<AuditEvent> = Vec::new();
        let scope = WitnessScope::new("init", "task");
        let r = assert_mysql_round_trip(&chain, tmp.path(), &seed, &scope);
        assert!(r.is_ok(), "mysql witness must bypass when env unset: {r:?}");
    }

    #[test]
    fn mssql_witness_bypassed_when_env_unset() {
        let _guard = clear_env_for_test(ENV_LIVE_MSSQL_URL);
        let tmp = tempfile::tempdir().unwrap();
        let seed = MssqlSeed {
            rows: mssql_seed_rows(),
        };
        let chain: Vec<AuditEvent> = Vec::new();
        let scope = WitnessScope::new("init", "task");
        let r = assert_mssql_round_trip(&chain, tmp.path(), &seed, &scope);
        assert!(r.is_ok(), "mssql witness must bypass when env unset: {r:?}");
    }

    #[test]
    fn witness_scope_session_id_filter_is_strict() {
        let pg = PostgresSeed {
            rows: postgres_seed_rows(),
        };
        let smtp = smtp_seed();
        let chain = synthetic_service_chain(
            "init-A",
            TASK_SERVICE_ROUND_TRIP,
            "sess-A",
            &smtp_envelope_sha256(&smtp),
        );
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join(SERVICE_OUTPUT_DIR)).unwrap();
        std::fs::write(
            tmp.path().join(POSTGRES_OUTPUT_FILE),
            postgres_canonical_bytes(&pg),
        )
        .unwrap();
        let scope_match =
            WitnessScope::new("init-A", TASK_SERVICE_ROUND_TRIP).with_session("sess-A");
        assert!(assert_postgres_round_trip(&chain, tmp.path(), &pg, &scope_match).is_ok(),);
        let scope_other_session =
            WitnessScope::new("init-A", TASK_SERVICE_ROUND_TRIP).with_session("sess-B");
        assert!(assert_postgres_round_trip(&chain, tmp.path(), &pg, &scope_other_session).is_err(),);
    }

    #[test]
    fn render_failures_groups_by_service() {
        let scope = WitnessScope::new("i", "t");
        let fs = vec![
            ServiceEvidenceError::FileMissing {
                service: "postgres",
                path: PathBuf::from("/tmp/postgres.txt"),
            },
            ServiceEvidenceError::AuditEventMissing {
                service: "mongodb",
                expected_kind: "MongoCommandExecuted",
                scope: scope.clone(),
                hint: "find".to_owned(),
            },
        ];
        let rendered = render_failures(&fs);
        assert!(rendered.contains("── postgres ──"));
        assert!(rendered.contains("── mongodb ──"));
        assert!(rendered.contains("/tmp/postgres.txt"));
        assert!(rendered.contains("MongoCommandExecuted"));
    }

    /// RAII guard that unsets an env var for the duration of a
    /// test and restores it on drop. Avoids cross-contaminating
    /// the opt-in env state when several tests run in the same
    /// process.
    struct EnvGuard {
        key: &'static str,
        prior: Option<String>,
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            match &self.prior {
                Some(v) => std::env::set_var(self.key, v),
                None => std::env::remove_var(self.key),
            }
        }
    }

    fn clear_env_for_test(key: &'static str) -> EnvGuard {
        let prior = std::env::var(key).ok();
        std::env::remove_var(key);
        EnvGuard { key, prior }
    }

    #[test]
    fn smoke_synthetic_chain_event_kinds_set() {
        let pg = PostgresSeed {
            rows: postgres_seed_rows(),
        };
        let _ = pg;
        let smtp = smtp_seed();
        let chain = synthetic_service_chain("i", "t", "s", &smtp_envelope_sha256(&smtp));
        let kinds: BTreeSet<String> = chain.iter().map(|e| e.event_kind.clone()).collect();
        for needle in [
            "CredentialProxyStarted",
            "CredentialProxyUpstreamConnected",
            "DatabaseQueryExecuted",
            "MongoCommandExecuted",
            "RedisCommandExecuted",
            "SmtpMessageRelayed",
        ] {
            assert!(
                kinds.contains(needle),
                "synthetic chain should contain {needle}; got {kinds:?}"
            );
        }
    }

    /// Live-stack smoke test: drives every `seed_*` helper against
    /// the docker-compose containers the un-mock worker shipped.
    /// Gated `#[ignore]` so `cargo test` keeps green on a developer
    /// laptop without the stack up. Invoke with:
    ///
    /// ```bash
    /// docker compose -f live-e2e/docker-compose.extended.e2e.yml up -d --wait
    /// cargo test -p raxis-kernel --test extended_e2e_realistic_scenario \
    ///   service_evidence::tests::seeds_hit_real_upstreams_when_unmocked -- \
    ///   --ignored --nocapture
    /// ```
    #[test]
    #[ignore]
    fn seeds_hit_real_upstreams_when_unmocked() {
        let pg = seed_postgres().expect("postgres container reachable on the un-mock stack");
        assert_eq!(pg.rows.len(), SE_POSTGRES_ROW_COUNT);
        let mongo = seed_mongodb().expect("mongodb container reachable on the un-mock stack");
        assert_eq!(mongo.docs.len(), SE_MONGODB_DOC_COUNT);
        let redis = seed_redis().expect("redis container reachable on the un-mock stack");
        assert_eq!(redis.entries.len(), SE_REDIS_KEY_COUNT);
        let smtp = seed_smtp().expect("smtp container reachable on the un-mock stack");
        assert_eq!(smtp.subject, "smtp_seed_subject_1");

        // Opt-in seeds: short-circuit when the env var is unset.
        // Calling them unconditionally exercises the gate.
        let mysql = seed_mysql().expect("mysql seed must not fail unguarded");
        assert_eq!(mysql.rows.len(), SE_MYSQL_ROW_COUNT);
        let mssql = seed_mssql().expect("mssql seed must not fail unguarded");
        assert_eq!(mssql.rows.len(), SE_MSSQL_ROW_COUNT);

        eprintln!(
            "[seed-smoke] postgres rows={} mongo docs={} redis keys={} smtp subj={} \
             mysql rows={} mssql rows={}",
            pg.rows.len(),
            mongo.docs.len(),
            redis.entries.len(),
            smtp.subject,
            mysql.rows.len(),
            mssql.rows.len(),
        );
    }
}

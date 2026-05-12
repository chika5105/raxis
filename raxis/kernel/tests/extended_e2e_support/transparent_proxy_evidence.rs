//! Transparent-proxy mechanical witness for the realism e2e.
//!
//! This module is the test-side companion of the
//! [`super::service_evidence`] witness; the two assert
//! **complementary** properties of the executor's run against the
//! credential-proxy substrate:
//!
//! * `service_evidence` says **the round-trip happened**:
//!   the executor opened a credential-proxy connection, the
//!   upstream returned the seeded data, and the data flowed back
//!   to the executor's worktree in a canonical shape.
//!
//! * `transparent_proxy_evidence` (this module) says **the
//!   executor was unaware**: it ran stock Python scripts that
//!   speak `psycopg2` / `pymongo` / `redis-py` / `pymysql` /
//!   `pymssql` / stdlib `smtplib` against stock environment-
//!   variable conventions (`DATABASE_URL`, `MONGO_URL`,
//!   `REDIS_URL`, `SMTP_URL`, `MYSQL_URL`, `MSSQL_URL`), with no
//!   raxis-specific shims. The proxy was the *only* reachable
//!   path because the executor's egress policy denied direct
//!   access to the upstreams.
//!
//! ## Per-service assertion order
//!
//! For each service in scope, [`assert_transparent_proxy_round_trip`]
//! walks the following in order, returning the first failure as a
//! structured [`TransparentProxyEvidenceError`]:
//!
//! 1. **Credential proxy was started in the executor's session.**
//!    The audit chain must contain a `CredentialProxyStarted` event
//!    whose `proxy_type` matches the service AND whose envelope
//!    `(initiative_id, task_id)` resolves to the executor task
//!    (not a kernel preflight session).
//! 2. **No proxy-bypass egress.** The audit chain must NOT contain
//!    any `TransparentProxyDenied` event with
//!    `reason == "proxy_target_bypass"` scoped to the executor's
//!    session. If the executor tried to skip the proxy and dial
//!    the real upstream host:port directly, that's the signature
//!    the kernel emits — the transparent-proxy contract is broken
//!    if we see one.
//! 3. **Output file present at the worktree-canonical path.**
//!    The executor must have committed
//!    `out/services/<service>.txt` to its worktree.
//! 4. **Output bytes canonical.** The file's content must
//!    byte-equal the canonical bytes produced by
//!    [`super::service_evidence`] for that service.
//! 5. **Wrapper transcript present and lists the service.**
//!    `scripts/last_run_summary.txt` must exist in the worktree
//!    and must mention the service name verbatim.
//!
//! ## Why the egress check is load-bearing
//!
//! Without it, a Python script that ran `psycopg2.connect(
//! 'postgresql://real_user:real_pass@prod-db.company.com:5432/mydb')`
//! would succeed against the upstream and produce the canonical
//! output bytes — passing the service-evidence witness — while
//! completely bypassing the credential proxy. The egress
//! assertion fails closed on that case: if the executor's policy
//! correctly forbids direct upstream reach, the kernel emits
//! `TransparentProxyDenied{reason: "proxy_target_bypass"}`, and
//! this witness asserts that no such event ever fires.
//!
//! ## Failure taxonomy
//!
//! All failure modes flow through
//! [`TransparentProxyEvidenceError`]; the `Display` impl renders
//! a grep-friendly per-service tag (`[transparent-proxy:<svc>]`)
//! so a CI scraper can locate the failing service immediately.

#![allow(dead_code)]
// Identical justification to `service_evidence.rs`: the error
// enum is intentionally rich so the panic message is
// operator-readable. We accept the larger Err variant rather
// than boxing.
#![allow(clippy::result_large_err)]

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};

use raxis_audit_tools::{AuditEvent, AuditEventKind};

use super::service_evidence::{
    mongo_canonical_bytes, mssql_canonical_bytes, mysql_canonical_bytes, postgres_canonical_bytes,
    redis_canonical_bytes, smtp_canonical_bytes, MongoSeed, MssqlSeed, MysqlSeed, PostgresSeed,
    RedisSeed, ServiceEvidenceError, SmtpSeed, WitnessScope, ENV_LIVE_MSSQL_URL,
    ENV_LIVE_MYSQL_URL,
};

// ---------------------------------------------------------------------------
// Pinned task id + worktree paths.
// ---------------------------------------------------------------------------

/// Pinned task id for the transparent-proxy real-scripts task.
/// The plan builder ([`super::plan_realistic`]) wires this id
/// with the same credential mounts as the service-round-trip
/// task plus `path_allowlist = ["out/services/", "scripts/last_run_summary.txt"]`.
pub const TASK_TRANSPARENT_PROXY_REALSCRIPTS: &str = "transparent-proxy-realscripts";

/// Worktree-relative path for the wrapper-script transcript the
/// executor commits after running `scripts/run_all_services.sh`.
pub const WRAPPER_SUMMARY_PATH: &str = "scripts/last_run_summary.txt";

/// Source directory under the workspace root containing the
/// pre-staged Python scripts the test driver overlays into the
/// transparent-proxy executor's worktree before the executor
/// wakes up.
pub const SCRIPT_SOURCE_DIR: &str = "live-e2e/seed/scripts/transparent_proxy";

/// File names the test driver copies into `<worktree>/scripts/`.
/// Pinned so the staging step is mechanically auditable.
pub const STAGED_SCRIPT_NAMES: &[&str] = &[
    "check_postgres.py",
    "check_mongodb.py",
    "check_redis.py",
    "check_smtp.py",
    "check_mysql.py",
    "check_mssql.py",
    "run_all_services.sh",
    "requirements.txt",
];

// ---------------------------------------------------------------------------
// ServiceKind — typed dispatch over the in-scope protocols.
// ---------------------------------------------------------------------------

/// Tag for the per-service witness dispatcher. Each variant maps
/// to one canonical-bytes generator from [`super::service_evidence`]
/// and one `proxy_type` string the audit walker filters on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceKind {
    Postgres,
    Mongodb,
    Redis,
    Smtp,
    /// Opt-in via [`ENV_LIVE_MYSQL_URL`]; the helper short-circuits
    /// to `Ok(())` when unset.
    Mysql,
    /// Opt-in via [`ENV_LIVE_MSSQL_URL`]; the helper short-circuits
    /// to `Ok(())` when unset.
    Mssql,
}

impl ServiceKind {
    /// Stable per-service label used in error rendering and the
    /// wrapper transcript grep. Also the basename of the executor's
    /// committed output file (e.g. `mongodb` -> `out/services/mongodb.txt`).
    pub fn as_str(self) -> &'static str {
        match self {
            ServiceKind::Postgres => "postgres",
            ServiceKind::Mongodb => "mongodb",
            ServiceKind::Redis => "redis",
            ServiceKind::Smtp => "smtp",
            ServiceKind::Mysql => "mysql",
            ServiceKind::Mssql => "mssql",
        }
    }

    /// `proxy_type` value the audit-chain walker matches against
    /// `AuditEventKind::CredentialProxyStarted.proxy_type`. The
    /// strings track the canonical names pinned in
    /// `raxis_credential_proxy_manager::proxy_type_str`.
    pub fn proxy_type(self) -> &'static str {
        match self {
            ServiceKind::Postgres => "postgres",
            ServiceKind::Mongodb => "mongodb",
            ServiceKind::Redis => "redis",
            ServiceKind::Smtp => "smtp",
            ServiceKind::Mysql => "mysql",
            ServiceKind::Mssql => "mssql",
        }
    }

    /// Worktree-relative output file the executor commits per
    /// service. Pinned so the witness can read deterministic
    /// paths and so a CI scraper can grep `out/services/`.
    pub fn output_path(self) -> &'static str {
        match self {
            ServiceKind::Postgres => "out/services/postgres.txt",
            ServiceKind::Mongodb => "out/services/mongodb.txt",
            ServiceKind::Redis => "out/services/redis.txt",
            ServiceKind::Smtp => "out/services/smtp.txt",
            ServiceKind::Mysql => "out/services/mysql.txt",
            ServiceKind::Mssql => "out/services/mssql.txt",
        }
    }

    /// Opt-in env-var name that gates the service. `None` for the
    /// always-on services (postgres / mongodb / redis / smtp);
    /// `Some(env_var)` for `mysql` / `mssql` (gated behind the
    /// credential-proxy gap closer's regression fixes).
    pub fn opt_in_env(self) -> Option<&'static str> {
        match self {
            ServiceKind::Mysql => Some(ENV_LIVE_MYSQL_URL),
            ServiceKind::Mssql => Some(ENV_LIVE_MSSQL_URL),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Failure taxonomy.
// ---------------------------------------------------------------------------

/// One transparent-proxy witness failure. Tests render with `{}`
/// so the panic message carries the full operator-facing
/// diagnostic. The variants intentionally do NOT collapse into
/// a generic `Other(String)` — each one is grep-able by tag in CI
/// log scrapers.
#[derive(Debug, Clone)]
pub enum TransparentProxyEvidenceError {
    /// Helper bypassed because the opt-in env var was absent.
    /// Returned as `Ok(())` from the helper; this variant exists
    /// so a future caller that requires the env can pattern-match.
    OptInBypassed {
        service: &'static str,
        env_var: &'static str,
    },

    /// The audit chain has no `CredentialProxyStarted` event
    /// scoped to `(initiative_id, task_id)` with the expected
    /// `proxy_type`. Either the kernel never bound the proxy, the
    /// scope is wrong, or the executor used a different task id.
    ProxyStartMissing {
        service: &'static str,
        proxy_type: &'static str,
        scope: WitnessScope,
    },

    /// The audit chain contains a `TransparentProxyDenied` event
    /// with `reason == "proxy_target_bypass"` (or a
    /// `SecurityViolation` pair) in the executor's session: the
    /// executor reached for the real upstream directly. The
    /// transparent-proxy contract is broken.
    DirectEgressDetected {
        service: &'static str,
        scope: WitnessScope,
        original_dst_ip: String,
        original_dst_port: u16,
    },

    /// `<worktree_root>/out/services/<service>.txt` is absent.
    OutputFileMissing {
        service: &'static str,
        path: PathBuf,
    },

    /// `std::fs::read` against the expected output file failed.
    OutputFileReadFailed {
        service: &'static str,
        path: PathBuf,
        reason: String,
    },

    /// The executor's output file does not byte-equal the canonical
    /// bytes the service-evidence module generates. We forward to
    /// the same `diff_preview` engine as [`ServiceEvidenceError`]
    /// for consistency in CI panic messages.
    OutputContentMismatch {
        service: &'static str,
        path: PathBuf,
        forwarded: Box<ServiceEvidenceError>,
    },

    /// `scripts/last_run_summary.txt` is absent from the worktree.
    WrapperSummaryMissing {
        service: &'static str,
        path: PathBuf,
    },

    /// `scripts/last_run_summary.txt` exists but does not contain
    /// the service name verbatim. The wrapper prints one line per
    /// service; the absence of the matching line implies the
    /// service was not exercised through the scripts substrate.
    WrapperSummaryMissesService {
        service: &'static str,
        path: PathBuf,
    },
}

impl fmt::Display for TransparentProxyEvidenceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OptInBypassed { service, env_var } => write!(
                f,
                "[transparent-proxy:{service}] opt-in env var {env_var} \
                 not set; helper bypassed (returns Ok(())).",
            ),
            Self::ProxyStartMissing {
                service,
                proxy_type,
                scope,
            } => write!(
                f,
                "[transparent-proxy:{service}] no `CredentialProxyStarted` \
                 event with proxy_type == `{proxy_type}` in scope \
                 (initiative_id={}, task_id={}, session_id={:?})",
                scope.initiative_id, scope.task_id, scope.session_id,
            ),
            Self::DirectEgressDetected {
                service,
                scope,
                original_dst_ip,
                original_dst_port,
            } => write!(
                f,
                "[transparent-proxy:{service}] executor reached upstream \
                 {original_dst_ip}:{original_dst_port} directly (TransparentProxyDenied \
                 reason=`proxy_target_bypass`); the credential proxy is no \
                 longer the only reachable path. Scope: (initiative_id={}, \
                 task_id={}, session_id={:?})",
                scope.initiative_id, scope.task_id, scope.session_id,
            ),
            Self::OutputFileMissing { service, path } => write!(
                f,
                "[transparent-proxy:{service}] expected executor output \
                 file missing: {}",
                path.display(),
            ),
            Self::OutputFileReadFailed {
                service,
                path,
                reason,
            } => write!(
                f,
                "[transparent-proxy:{service}] read({}): {reason}",
                path.display(),
            ),
            Self::OutputContentMismatch {
                service,
                path,
                forwarded,
            } => write!(
                f,
                "[transparent-proxy:{service}] {} byte-mismatch \
                 vs. canonical seed bytes:\n  {}",
                path.display(),
                forwarded,
            ),
            Self::WrapperSummaryMissing { service, path } => write!(
                f,
                "[transparent-proxy:{service}] `{}` is absent — the \
                 executor never committed the wrapper-script transcript",
                path.display(),
            ),
            Self::WrapperSummaryMissesService { service, path } => write!(
                f,
                "[transparent-proxy:{service}] `{}` exists but does not \
                 mention the service `{service}` verbatim — the wrapper \
                 either did not run or did not exercise this service",
                path.display(),
            ),
        }
    }
}

impl std::error::Error for TransparentProxyEvidenceError {}

// ---------------------------------------------------------------------------
// Per-service expectation bundle — feeds the round-trip helper.
//
// We share the `service_evidence` seed structs verbatim so the
// canonical bytes the two witnesses compare against are identical.
// A drift between the two would be a category error: the same
// seed produces the same canonical bytes regardless of which
// witness is reading them.
// ---------------------------------------------------------------------------

/// Bundle of every per-service seed the transparent-proxy witness
/// needs. Built by the realistic-scenario driver after the seed
/// helpers (`seed_postgres` etc.) succeed.
#[derive(Debug, Clone)]
pub struct TransparentProxyExpectations {
    pub postgres: PostgresSeed,
    pub mongodb: MongoSeed,
    pub redis: RedisSeed,
    pub smtp: SmtpSeed,
    pub mysql: MysqlSeed,
    pub mssql: MssqlSeed,
}

impl TransparentProxyExpectations {
    /// Pull the canonical bytes for one service. Returns a 0-byte
    /// vec for opt-in services that didn't run (so the comparison
    /// against a missing file yields `OutputFileMissing` rather
    /// than a length mismatch — both are correctly handled
    /// upstream).
    pub fn canonical_bytes(&self, service: ServiceKind) -> Vec<u8> {
        match service {
            ServiceKind::Postgres => postgres_canonical_bytes(&self.postgres),
            ServiceKind::Mongodb => mongo_canonical_bytes(&self.mongodb),
            ServiceKind::Redis => redis_canonical_bytes(&self.redis),
            ServiceKind::Smtp => smtp_canonical_bytes(&self.smtp),
            ServiceKind::Mysql => mysql_canonical_bytes(&self.mysql),
            ServiceKind::Mssql => mssql_canonical_bytes(&self.mssql),
        }
    }
}

// ---------------------------------------------------------------------------
// Audit-chain walk helpers.
// ---------------------------------------------------------------------------

fn typed(ev: &AuditEvent) -> Option<AuditEventKind> {
    serde_json::from_value(ev.payload.clone()).ok()
}

fn scope_matches(scope: &WitnessScope, ev: &AuditEvent) -> bool {
    if ev.initiative_id.as_deref() != Some(scope.initiative_id.as_str()) {
        return false;
    }
    match ev.task_id.as_deref() {
        Some(t) if t == scope.task_id => {}
        _ => return false,
    }
    if let Some(want_sid) = &scope.session_id {
        if ev.session_id.as_deref() != Some(want_sid.as_str()) {
            return false;
        }
    }
    true
}

fn has_proxy_started(chain: &[AuditEvent], scope: &WitnessScope, proxy_type: &str) -> bool {
    chain.iter().any(|ev| {
        if !scope_matches(scope, ev) {
            return false;
        }
        matches!(
            typed(ev),
            Some(AuditEventKind::CredentialProxyStarted { proxy_type: pt, .. }) if pt == proxy_type
        )
    })
}

/// Look for a `TransparentProxyDenied{ reason: "proxy_target_bypass" }`
/// scoped to the executor's session. Returns `Some((ip, port))`
/// on the first match. The proxy-bypass reason is the
/// kernel-emitted signature of "agent tried to dial the upstream
/// directly"; any other denial reason (host_not_in_allowlist,
/// etc.) is a separate concern and not a transparency violation.
fn find_proxy_bypass_denial(chain: &[AuditEvent], scope: &WitnessScope) -> Option<(String, u16)> {
    chain.iter().find_map(|ev| {
        if !scope_matches(scope, ev) {
            return None;
        }
        match typed(ev) {
            Some(AuditEventKind::TransparentProxyDenied {
                reason,
                original_dst_ip,
                original_dst_port,
                ..
            }) if reason == "proxy_target_bypass" => Some((original_dst_ip, original_dst_port)),
            _ => None,
        }
    })
}

// ---------------------------------------------------------------------------
// File comparison helpers — forward the byte-diff to
// `service_evidence` so the panic message format is consistent
// between the two witnesses.
// ---------------------------------------------------------------------------

fn compare_canonical(
    service: ServiceKind,
    worktree_root: &Path,
    canonical: &[u8],
) -> Result<(), TransparentProxyEvidenceError> {
    let svc = service.as_str();
    let abs = worktree_root.join(service.output_path());
    if !abs.exists() {
        return Err(TransparentProxyEvidenceError::OutputFileMissing {
            service: svc,
            path: abs,
        });
    }
    let bytes =
        std::fs::read(&abs).map_err(|e| TransparentProxyEvidenceError::OutputFileReadFailed {
            service: svc,
            path: abs.clone(),
            reason: format!("{e}"),
        })?;
    if bytes == canonical {
        return Ok(());
    }
    // Re-use `ServiceEvidenceError::FileContentMismatch` so the
    // SHA-pair + ±64-byte diff window is rendered consistently
    // with the sibling witness.
    let forwarded = ServiceEvidenceError::FileContentMismatch {
        service: svc,
        path: abs.clone(),
        expected_sha: sha256_hex(canonical),
        actual_sha: sha256_hex(&bytes),
        diff_preview: diff_preview(canonical, &bytes),
    };
    Err(TransparentProxyEvidenceError::OutputContentMismatch {
        service: svc,
        path: abs,
        forwarded: Box::new(forwarded),
    })
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

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

// ---------------------------------------------------------------------------
// Wrapper-summary check.
// ---------------------------------------------------------------------------

fn assert_wrapper_summary_mentions(
    service: ServiceKind,
    worktree_root: &Path,
) -> Result<(), TransparentProxyEvidenceError> {
    let svc = service.as_str();
    let abs = worktree_root.join(WRAPPER_SUMMARY_PATH);
    if !abs.exists() {
        return Err(TransparentProxyEvidenceError::WrapperSummaryMissing {
            service: svc,
            path: abs,
        });
    }
    let text = std::fs::read_to_string(&abs).map_err(|e| {
        TransparentProxyEvidenceError::OutputFileReadFailed {
            service: svc,
            path: abs.clone(),
            reason: format!("{e}"),
        }
    })?;
    // The wrapper emits one line per service of the form
    //   `  <svc>: ok (...)` / `  <svc>: skipped (...)` / `  <svc>: FAIL (...)`
    // — a verbatim `<svc>:` match is sufficient and resilient to
    // trailing-format drift.
    let needle = format!("{svc}:");
    if !text.contains(&needle) {
        return Err(TransparentProxyEvidenceError::WrapperSummaryMissesService {
            service: svc,
            path: abs,
        });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Top-level assertion — the entry point the realistic-scenario
// driver calls per service.
// ---------------------------------------------------------------------------

/// Assert the transparent-proxy round-trip property held for one
/// service in the executor's run. See the module-level
/// documentation for the assertion order.
pub fn assert_transparent_proxy_round_trip(
    chain: &[AuditEvent],
    worktree_root: &Path,
    service: ServiceKind,
    expectations: &TransparentProxyExpectations,
    scope: &WitnessScope,
) -> Result<(), TransparentProxyEvidenceError> {
    // Opt-in gate — same behaviour as `service_evidence` so the
    // two witnesses become active together when the operator
    // exports the env var.
    if let Some(env_var) = service.opt_in_env() {
        if std::env::var(env_var).is_err() {
            eprintln!(
                "[transparent-proxy:{svc}] {env_var} not set; \
                 helper bypassed. The witness will become active \
                 once the operator exports the var (matching the \
                 sibling service_evidence helper's opt-in gate).",
                svc = service.as_str(),
            );
            return Ok(());
        }
    }

    let svc = service.as_str();

    // 1. Credential proxy was started in the executor's scope.
    if !has_proxy_started(chain, scope, service.proxy_type()) {
        return Err(TransparentProxyEvidenceError::ProxyStartMissing {
            service: svc,
            proxy_type: service.proxy_type(),
            scope: scope.clone(),
        });
    }

    // 2. No direct-egress to the upstream's real address. The
    // kernel's egress admission denies any non-proxy host:port in
    // the executor's policy; the matching audit event is
    // `TransparentProxyDenied { reason: "proxy_target_bypass" }`.
    // Presence of any such event scoped to the executor's session
    // is a hard fail.
    if let Some((ip, port)) = find_proxy_bypass_denial(chain, scope) {
        return Err(TransparentProxyEvidenceError::DirectEgressDetected {
            service: svc,
            scope: scope.clone(),
            original_dst_ip: ip,
            original_dst_port: port,
        });
    }

    // 3 + 4. Output file present and content byte-matches.
    let canonical = expectations.canonical_bytes(service);
    compare_canonical(service, worktree_root, &canonical)?;

    // 5. Wrapper transcript mentions the service.
    assert_wrapper_summary_mentions(service, worktree_root)?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Aggregate helper — exercises every in-scope service and returns
// the union of failures so the harness can render them in one
// panic message rather than chasing them one-at-a-time.
// ---------------------------------------------------------------------------

/// Run every active transparent-proxy witness and collect every
/// failure. Mirrors
/// [`super::service_evidence::collect_active_witness_failures`].
pub fn collect_active_witness_failures(
    chain: &[AuditEvent],
    worktree_root: &Path,
    expectations: &TransparentProxyExpectations,
    scope: &WitnessScope,
) -> Vec<TransparentProxyEvidenceError> {
    let mut failures = Vec::new();
    for service in [
        ServiceKind::Postgres,
        ServiceKind::Mongodb,
        ServiceKind::Redis,
        ServiceKind::Smtp,
        ServiceKind::Mysql,
        ServiceKind::Mssql,
    ] {
        if let Err(e) =
            assert_transparent_proxy_round_trip(chain, worktree_root, service, expectations, scope)
        {
            failures.push(e);
        }
    }
    failures
}

/// Render a `Vec<TransparentProxyEvidenceError>` for embedding in
/// a panic message — grouped per service so the operator can read
/// the union at a glance.
pub fn render_failures(failures: &[TransparentProxyEvidenceError]) -> String {
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

fn service_of(e: &TransparentProxyEvidenceError) -> &'static str {
    match e {
        TransparentProxyEvidenceError::OptInBypassed { service, .. }
        | TransparentProxyEvidenceError::ProxyStartMissing { service, .. }
        | TransparentProxyEvidenceError::DirectEgressDetected { service, .. }
        | TransparentProxyEvidenceError::OutputFileMissing { service, .. }
        | TransparentProxyEvidenceError::OutputFileReadFailed { service, .. }
        | TransparentProxyEvidenceError::OutputContentMismatch { service, .. }
        | TransparentProxyEvidenceError::WrapperSummaryMissing { service, .. }
        | TransparentProxyEvidenceError::WrapperSummaryMissesService { service, .. } => service,
    }
}

// ---------------------------------------------------------------------------
// Staging helper — used by the realistic-scenario test driver to
// overlay the Python scripts into the executor's worktree before
// the executor wakes up. The kernel creates the worktree lazily
// after PlanApproved; the test driver polls for its existence,
// then copies every file from `live-e2e/seed/scripts/transparent_proxy/`
// into `<worktree>/scripts/`. This is the same hacky-overlay
// shape `materialise_realistic_seed` uses for the rich-multilang
// seed; a future commit replaces both with a kernel-side
// pre-task hook.
// ---------------------------------------------------------------------------

/// Copy the pre-staged Python scripts into the executor's
/// worktree at `<worktree>/scripts/`. Sets executable permissions
/// on the `.py` files and the `.sh` wrapper so they can be run
/// directly. Idempotent — calling twice converges to the same
/// on-disk state.
pub fn stage_scripts_into_worktree(
    worktree_root: &Path,
    workspace_root: &Path,
) -> std::io::Result<Vec<PathBuf>> {
    let source_dir = workspace_root.join(SCRIPT_SOURCE_DIR);
    let target_dir = worktree_root.join("scripts");
    std::fs::create_dir_all(&target_dir)?;

    let mut staged = Vec::with_capacity(STAGED_SCRIPT_NAMES.len());
    for name in STAGED_SCRIPT_NAMES {
        let src = source_dir.join(name);
        let dst = target_dir.join(name);
        std::fs::copy(&src, &dst)?;
        // Restore executable bits for runnable artefacts (the
        // `std::fs::copy` documentation explicitly notes that
        // permission preservation is best-effort across
        // platforms; we set it explicitly here for determinism).
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if name.ends_with(".py") || name.ends_with(".sh") {
                std::fs::set_permissions(&dst, std::fs::Permissions::from_mode(0o755))?;
            } else {
                std::fs::set_permissions(&dst, std::fs::Permissions::from_mode(0o644))?;
            }
        }
        staged.push(dst);
    }
    Ok(staged)
}

// ---------------------------------------------------------------------------
// Worktree-fixture helper — used by the wiring smoke test to
// build a hand-shaped worktree that satisfies every active
// witness so the call surface is mechanically exercised even
// with no kernel up.
// ---------------------------------------------------------------------------

/// Write the canonical bytes for every active service AND the
/// wrapper summary into `worktree_root` so a smoke test can
/// invoke [`assert_transparent_proxy_round_trip`] against the
/// fixture. Mirrors
/// [`super::service_evidence::write_canonical_outputs_for_smoke`].
pub fn write_canonical_outputs_for_smoke(
    worktree_root: &Path,
    expectations: &TransparentProxyExpectations,
) -> std::io::Result<()> {
    // Always-on services.
    std::fs::create_dir_all(worktree_root.join("out/services"))?;
    std::fs::create_dir_all(worktree_root.join("scripts"))?;
    for service in [
        ServiceKind::Postgres,
        ServiceKind::Mongodb,
        ServiceKind::Redis,
        ServiceKind::Smtp,
    ] {
        std::fs::write(
            worktree_root.join(service.output_path()),
            expectations.canonical_bytes(service),
        )?;
    }
    // Opt-in services: only emit the file when the env var is
    // set (matching the runtime contract).
    for service in [ServiceKind::Mysql, ServiceKind::Mssql] {
        if let Some(env_var) = service.opt_in_env() {
            if std::env::var(env_var).is_ok() {
                std::fs::write(
                    worktree_root.join(service.output_path()),
                    expectations.canonical_bytes(service),
                )?;
            }
        }
    }
    // Wrapper summary — list every always-on service plus
    // the opt-in ones with their gated state. The witness only
    // checks for the verbatim presence of `<svc>:`, so a single
    // line per service is sufficient.
    let mut transcript = String::new();
    transcript.push_str("── transparent_proxy run summary ──\n");
    for service in [
        ServiceKind::Postgres,
        ServiceKind::Mongodb,
        ServiceKind::Redis,
        ServiceKind::Smtp,
    ] {
        transcript.push_str(&format!("  {}: ok (smoke fixture)\n", service.as_str()));
    }
    for service in [ServiceKind::Mysql, ServiceKind::Mssql] {
        let state = if service
            .opt_in_env()
            .map(|v| std::env::var(v).is_ok())
            .unwrap_or(false)
        {
            "ok (smoke fixture)"
        } else {
            "skipped (opt-in env unset)"
        };
        transcript.push_str(&format!("  {}: {}\n", service.as_str(), state));
    }
    transcript.push_str("── smoke fixture wrapper transcript ──\n");
    std::fs::write(worktree_root.join(WRAPPER_SUMMARY_PATH), transcript)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Synthetic-chain helper for smoke testing.
// ---------------------------------------------------------------------------

/// Build a synthetic audit chain that satisfies every active
/// transparent-proxy witness. Used by the wiring smoke test.
pub fn synthetic_transparent_chain(
    initiative_id: &str,
    task_id: &str,
    session_id: &str,
) -> Vec<AuditEvent> {
    let mut seq: u64 = 500;
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
    }
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

/// Build a synthetic `TransparentProxyDenied{reason: "proxy_target_bypass"}`
/// event scoped to the given identity triple. Used by the
/// negative smoke test that asserts the witness fails closed when
/// the executor bypasses the proxy.
pub fn synthetic_proxy_bypass_event(
    initiative_id: &str,
    task_id: &str,
    session_id: &str,
    upstream_ip: &str,
    upstream_port: u16,
) -> AuditEvent {
    make_event(
        999,
        initiative_id,
        task_id,
        session_id,
        AuditEventKind::TransparentProxyDenied {
            session_id: session_id.to_owned(),
            host_or_sni: Some(upstream_ip.to_owned()),
            original_dst_ip: upstream_ip.to_owned(),
            original_dst_port: upstream_port,
            protocol: "tcp".to_owned(),
            reason: "proxy_target_bypass".to_owned(),
        },
    )
}

// ---------------------------------------------------------------------------
// Build a default `TransparentProxyExpectations` from the
// canonical per-service seed shapes the `service_evidence`
// module pins. Used by both the realistic-scenario driver and
// the smoke test so the two paths share one source of truth.
// ---------------------------------------------------------------------------

/// Build a default expectations bundle from the canonical
/// per-service seed shapes. The seed-row count + magic formulas
/// are pinned in `service_evidence`; the bundle here only
/// re-uses them for the byte-compare step. We do NOT call
/// `seed_*()` here — those open real network connections.
pub fn default_expectations() -> TransparentProxyExpectations {
    use super::service_evidence::{
        mongo_seed_docs, mssql_seed_rows, mysql_seed_rows, postgres_seed_rows, redis_seed_entries,
        smtp_seed,
    };
    TransparentProxyExpectations {
        postgres: PostgresSeed {
            rows: postgres_seed_rows(),
        },
        mongodb: MongoSeed {
            docs: mongo_seed_docs(),
        },
        redis: RedisSeed {
            entries: redis_seed_entries(),
        },
        smtp: smtp_seed(),
        mysql: MysqlSeed {
            rows: mysql_seed_rows(),
        },
        mssql: MssqlSeed {
            rows: mssql_seed_rows(),
        },
    }
}

// ---------------------------------------------------------------------------
// Tests — drive the witness against synthetic fixtures.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn unique_initiative() -> String {
        uuid::Uuid::now_v7().to_string()
    }

    #[test]
    fn service_kind_round_trips_via_string_form() {
        for svc in [
            ServiceKind::Postgres,
            ServiceKind::Mongodb,
            ServiceKind::Redis,
            ServiceKind::Smtp,
            ServiceKind::Mysql,
            ServiceKind::Mssql,
        ] {
            assert_eq!(svc.as_str(), svc.proxy_type());
            assert!(svc.output_path().starts_with("out/services/"));
            assert!(svc.output_path().ends_with(".txt"));
        }
    }

    #[test]
    fn synthetic_chain_satisfies_active_witness() {
        let tmp = tempfile::tempdir().unwrap();
        let expectations = default_expectations();
        write_canonical_outputs_for_smoke(tmp.path(), &expectations).unwrap();

        let initiative = unique_initiative();
        let task = TASK_TRANSPARENT_PROXY_REALSCRIPTS.to_owned();
        let session = "smoke-transparent-1".to_owned();
        let chain = synthetic_transparent_chain(&initiative, &task, &session);
        let scope = WitnessScope::new(initiative.clone(), task.clone()).with_session(session);

        let failures = collect_active_witness_failures(&chain, tmp.path(), &expectations, &scope);
        assert!(
            failures.is_empty(),
            "synthetic transparent chain must satisfy every active witness:\n{}",
            render_failures(&failures),
        );
    }

    #[test]
    fn missing_proxy_start_surfaces_with_scope() {
        let tmp = tempfile::tempdir().unwrap();
        let expectations = default_expectations();
        write_canonical_outputs_for_smoke(tmp.path(), &expectations).unwrap();
        let scope =
            WitnessScope::new("init-x", TASK_TRANSPARENT_PROXY_REALSCRIPTS).with_session("sess-x");
        let chain: Vec<AuditEvent> = Vec::new();
        let err = assert_transparent_proxy_round_trip(
            &chain,
            tmp.path(),
            ServiceKind::Postgres,
            &expectations,
            &scope,
        )
        .expect_err("no proxy-started event => ProxyStartMissing");
        let rendered = format!("{err}");
        assert!(
            rendered.contains("CredentialProxyStarted"),
            "render: {rendered}"
        );
        assert!(rendered.contains("postgres"), "render: {rendered}");
        assert!(rendered.contains("init-x"), "render: {rendered}");
    }

    #[test]
    fn proxy_bypass_event_surfaces_as_direct_egress_detected() {
        let tmp = tempfile::tempdir().unwrap();
        let expectations = default_expectations();
        write_canonical_outputs_for_smoke(tmp.path(), &expectations).unwrap();

        let initiative = unique_initiative();
        let task = TASK_TRANSPARENT_PROXY_REALSCRIPTS.to_owned();
        let session = "smoke-bypass-1".to_owned();
        let mut chain = synthetic_transparent_chain(&initiative, &task, &session);
        chain.push(synthetic_proxy_bypass_event(
            &initiative,
            &task,
            &session,
            "203.0.113.7",
            5432,
        ));
        let scope = WitnessScope::new(initiative, task).with_session(session);

        let err = assert_transparent_proxy_round_trip(
            &chain,
            tmp.path(),
            ServiceKind::Postgres,
            &expectations,
            &scope,
        )
        .expect_err("proxy_target_bypass event must surface");
        let rendered = format!("{err}");
        assert!(rendered.contains("reached upstream"), "render: {rendered}");
        assert!(rendered.contains("203.0.113.7"), "render: {rendered}");
        assert!(rendered.contains("5432"), "render: {rendered}");
    }

    #[test]
    fn missing_output_file_surfaces_with_path() {
        let tmp = tempfile::tempdir().unwrap();
        // No fixture writes — every output file is missing.
        let expectations = default_expectations();
        let initiative = unique_initiative();
        let task = TASK_TRANSPARENT_PROXY_REALSCRIPTS.to_owned();
        let session = "smoke-missing-1".to_owned();
        let chain = synthetic_transparent_chain(&initiative, &task, &session);
        let scope = WitnessScope::new(initiative, task).with_session(session);

        let err = assert_transparent_proxy_round_trip(
            &chain,
            tmp.path(),
            ServiceKind::Postgres,
            &expectations,
            &scope,
        )
        .expect_err("missing file => OutputFileMissing");
        let rendered = format!("{err}");
        assert!(
            rendered.contains("output file missing"),
            "render: {rendered}"
        );
        assert!(rendered.contains("postgres.txt"), "render: {rendered}");
    }

    #[test]
    fn content_mismatch_surfaces_with_sha_pair() {
        let tmp = tempfile::tempdir().unwrap();
        let expectations = default_expectations();
        write_canonical_outputs_for_smoke(tmp.path(), &expectations).unwrap();
        // Clobber the postgres output with bogus content.
        std::fs::write(
            tmp.path().join(ServiceKind::Postgres.output_path()),
            b"deliberately wrong\n",
        )
        .unwrap();

        let initiative = unique_initiative();
        let task = TASK_TRANSPARENT_PROXY_REALSCRIPTS.to_owned();
        let session = "smoke-mismatch-1".to_owned();
        let chain = synthetic_transparent_chain(&initiative, &task, &session);
        let scope = WitnessScope::new(initiative, task).with_session(session);

        let err = assert_transparent_proxy_round_trip(
            &chain,
            tmp.path(),
            ServiceKind::Postgres,
            &expectations,
            &scope,
        )
        .expect_err("wrong bytes => OutputContentMismatch");
        let rendered = format!("{err}");
        assert!(rendered.contains("byte-mismatch"), "render: {rendered}");
        assert!(rendered.contains("expected sha256"), "render: {rendered}");
        assert!(rendered.contains("observed sha256"), "render: {rendered}");
    }

    #[test]
    fn missing_wrapper_summary_surfaces() {
        let tmp = tempfile::tempdir().unwrap();
        // Write the per-service outputs but skip the wrapper summary.
        let expectations = default_expectations();
        std::fs::create_dir_all(tmp.path().join("out/services")).unwrap();
        std::fs::write(
            tmp.path().join(ServiceKind::Postgres.output_path()),
            expectations.canonical_bytes(ServiceKind::Postgres),
        )
        .unwrap();

        let initiative = unique_initiative();
        let task = TASK_TRANSPARENT_PROXY_REALSCRIPTS.to_owned();
        let session = "smoke-no-summary-1".to_owned();
        let chain = synthetic_transparent_chain(&initiative, &task, &session);
        let scope = WitnessScope::new(initiative, task).with_session(session);

        let err = assert_transparent_proxy_round_trip(
            &chain,
            tmp.path(),
            ServiceKind::Postgres,
            &expectations,
            &scope,
        )
        .expect_err("missing wrapper summary => WrapperSummaryMissing");
        let rendered = format!("{err}");
        assert!(
            rendered.contains("scripts/last_run_summary.txt"),
            "render: {rendered}",
        );
    }

    #[test]
    fn wrapper_summary_must_mention_service() {
        let tmp = tempfile::tempdir().unwrap();
        let expectations = default_expectations();
        write_canonical_outputs_for_smoke(tmp.path(), &expectations).unwrap();
        // Overwrite the wrapper summary with one that omits postgres.
        std::fs::write(
            tmp.path().join(WRAPPER_SUMMARY_PATH),
            "── transparent_proxy run summary ──\n  mongodb: ok\n",
        )
        .unwrap();

        let initiative = unique_initiative();
        let task = TASK_TRANSPARENT_PROXY_REALSCRIPTS.to_owned();
        let session = "smoke-missing-service-line".to_owned();
        let chain = synthetic_transparent_chain(&initiative, &task, &session);
        let scope = WitnessScope::new(initiative, task).with_session(session);

        let err = assert_transparent_proxy_round_trip(
            &chain,
            tmp.path(),
            ServiceKind::Postgres,
            &expectations,
            &scope,
        )
        .expect_err("wrapper without service line => WrapperSummaryMissesService");
        let rendered = format!("{err}");
        assert!(rendered.contains("does not mention"), "render: {rendered}");
        assert!(rendered.contains("postgres"), "render: {rendered}");
    }

    #[test]
    fn opt_in_services_self_skip_when_env_unset() {
        // Force-clear both opt-in env vars so the helper takes the
        // bypass path.
        let _g_mysql = clear_env_for_test(ENV_LIVE_MYSQL_URL);
        let _g_mssql = clear_env_for_test(ENV_LIVE_MSSQL_URL);
        let tmp = tempfile::tempdir().unwrap();
        let expectations = default_expectations();
        let initiative = unique_initiative();
        let task = TASK_TRANSPARENT_PROXY_REALSCRIPTS.to_owned();
        let scope = WitnessScope::new(initiative, task);
        let chain: Vec<AuditEvent> = Vec::new();
        for svc in [ServiceKind::Mysql, ServiceKind::Mssql] {
            let r =
                assert_transparent_proxy_round_trip(&chain, tmp.path(), svc, &expectations, &scope);
            assert!(
                r.is_ok(),
                "opt-in service {:?} must bypass when env var is unset: {r:?}",
                svc,
            );
        }
    }

    #[test]
    fn render_failures_groups_by_service() {
        let scope = WitnessScope::new("i", "t");
        let fs = vec![
            TransparentProxyEvidenceError::ProxyStartMissing {
                service: "postgres",
                proxy_type: "postgres",
                scope: scope.clone(),
            },
            TransparentProxyEvidenceError::DirectEgressDetected {
                service: "mongodb",
                scope,
                original_dst_ip: "203.0.113.9".to_owned(),
                original_dst_port: 27017,
            },
        ];
        let rendered = render_failures(&fs);
        assert!(rendered.contains("── postgres ──"));
        assert!(rendered.contains("── mongodb ──"));
        assert!(rendered.contains("CredentialProxyStarted"));
        assert!(rendered.contains("203.0.113.9"));
    }

    #[test]
    fn staging_helper_lays_down_every_pinned_script() {
        let tmp = tempfile::tempdir().unwrap();
        let workspace_root = workspace_root_for_tests();
        let worktree = tmp.path();
        let staged = stage_scripts_into_worktree(worktree, &workspace_root)
            .expect("stage should succeed against the in-repo source dir");
        for name in STAGED_SCRIPT_NAMES {
            let p = worktree.join("scripts").join(name);
            assert!(p.exists(), "missing staged script: {}", p.display());
        }
        assert_eq!(staged.len(), STAGED_SCRIPT_NAMES.len());

        // Idempotency: re-running converges to the same set of files
        // without panicking.
        let staged_again =
            stage_scripts_into_worktree(worktree, &workspace_root).expect("re-stage is idempotent");
        assert_eq!(staged_again.len(), STAGED_SCRIPT_NAMES.len());
    }

    /// The Cargo manifest dir for `raxis-kernel` is
    /// `<repo>/raxis/kernel`. The script source lives at
    /// `<repo>/raxis/live-e2e/seed/scripts/transparent_proxy`, so
    /// the workspace-root resolver walks up two dirs.
    fn workspace_root_for_tests() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("raxis/ parent")
            .to_path_buf()
    }

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
}

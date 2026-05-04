//! `raxis doctor` — preflight diagnostic for the operator's
//! `<data_dir>` and the kernel's on-disk surfaces.
//!
//! Normative reference: cli-readonly.md §5.5.15.
//!
//! # What this command does
//!
//! Walks every invariant the kernel asserts at boot and reports the
//! result as a typed list of `Check` records. Each check has an
//! outcome (`Ok` | `Warn` | `Fail`); the command's exit code is the
//! worst-of:
//!
//!   * 0 — every check is `Ok`.
//!   * 1 — at least one `Warn`, no `Fail`.
//!   * 2 — at least one `Fail`. The kernel is unlikely to boot
//!         (or has booted into a broken state).
//!
//! # What this command does NOT do
//!
//! * It does NOT mutate anything. There is no "fix-it" mode — the
//!   operator is responsible for editing files / setting permissions
//!   based on the report.
//! * It does NOT touch the kernel over IPC. Doctor must work even
//!   when the kernel cannot start.
//! * It does NOT walk the full audit chain. Use `raxis verify-chain`
//!   for the cryptographic walk; doctor uses the same quick-check
//!   `raxis status` does so the report stays under one screen.
//!
//! # Checks performed (in order)
//!
//! 1. `<data_dir>/` exists and is a directory.
//! 2. `<data_dir>/{keys,policy,audit,providers,runtime,sockets,notifications}/`
//!    each exist with sensible mode bits.
//! 3. `policy/policy.toml` is loadable through `raxis_policy::load_policy`.
//! 4. `kernel.db` is openable read-only AND its `SCHEMA_VERSION`
//!    matches the CLI's compiled-in expectation
//!    (`raxis_store::open_ro` does the assertion).
//! 5. `runtime/heartbeat.json` is parseable via `raxis_runtime::read`
//!    (`Warn` if missing — kernel may not have started yet).
//! 6. `audit/` has at least one `segment-NNN.jsonl` and the
//!    quick-check passes.
//! 7. Cross-check: bundle.epoch() == policy_epoch_history.MAX(epoch).
//! 8. Operator-cert status (step-11): for every row in the
//!    `operator_certificates` view table, classify against the
//!    four-zone state machine (`raxis_crypto::cert::cert_status`)
//!    and surface:
//!    * `WARN` for `Expiring` (within `warn_before_expiry_days`),
//!    * `WARN` for `Grace` (within `grace_period_days` past expiry),
//!    * `FAIL` for `Expired` (recovery ops also denied),
//!    * `FAIL` for `NotYetValid` (cert is dead-on-arrival),
//!    * `OK`   for `Active` and `AlwaysActiveEmergency`.
//!
//!    Plus `WARN` for any operator entry with
//!    `force_misconfig_bypass = true` so the operator is reminded
//!    they have an audited structural override active.

use std::io::Write;
use std::path::{Path, PathBuf};

use raxis_audit_tools::{quick_chain_check, ChainQuickCheck};
use raxis_crypto::cert::{cert_status, CertStatus};
use raxis_policy::load_policy;
use raxis_runtime::{read as read_heartbeat, ReadError as HeartbeatReadError};
use raxis_store::views::operator_certificates;
use raxis_store::views::policy_history;
use raxis_store::{open_ro, RoError};
use raxis_types::unix_now_secs;

use crate::errors::CliError;
use crate::GlobalFlags;

const POLICY_FILE_NAME: &str = "policy.toml";
const AUDIT_DIR_NAME:   &str = "audit";

// Spec'd mode bits per kernel-store.md §2.5.1 ("permissions") and
// peripherals.md §3.2 (providers/). These match what bootstrap.rs sets.
const EXPECTED_MODES: &[(&str, u32)] = &[
    ("keys",          0o700),
    ("policy",        0o755),
    ("audit",         0o755),
    ("providers",     0o700),
    ("runtime",       0o755),
    ("sockets",       0o755),
    ("notifications", 0o755),
];

// ────────────────────────────────────────────────────────────────────
// Outcome model
// ────────────────────────────────────────────────────────────────────

/// One row in the doctor report.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Check {
    /// Short stable identifier, e.g. "data_dir.exists". Stable across
    /// versions so JSON consumers can pin against it.
    id:      &'static str,
    outcome: Outcome,
    detail:  String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Outcome { Ok, Warn, Fail }

impl Outcome {
    fn label(self) -> &'static str {
        match self {
            Self::Ok   => "OK",
            Self::Warn => "WARN",
            Self::Fail => "FAIL",
        }
    }
}

#[derive(Debug, Clone, Default)]
struct Report {
    checks: Vec<Check>,
}

impl Report {
    fn push(&mut self, id: &'static str, outcome: Outcome, detail: impl Into<String>) {
        self.checks.push(Check { id, outcome, detail: detail.into() });
    }

    /// Worst-of outcome. Drives the process exit code.
    fn worst(&self) -> Outcome {
        let mut worst = Outcome::Ok;
        for c in &self.checks {
            worst = match (worst, c.outcome) {
                (_, Outcome::Fail)              => Outcome::Fail,
                (Outcome::Ok, Outcome::Warn)    => Outcome::Warn,
                (other, _)                      => other,
            };
        }
        worst
    }

    fn exit_code(&self) -> i32 {
        match self.worst() {
            Outcome::Ok   => 0,
            Outcome::Warn => 1,
            Outcome::Fail => 2,
        }
    }
}

// ────────────────────────────────────────────────────────────────────
// Entry point
// ────────────────────────────────────────────────────────────────────

pub fn run(flags: &GlobalFlags, args: &[String]) -> Result<(), CliError> {
    let opts = parse_args(args)?;
    let data_dir = flags.data_dir().clone();

    let report = collect(&data_dir);

    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    if opts.json {
        render_json(&mut out, &data_dir, &report);
    } else {
        render_human(&mut out, &data_dir, &report);
    }
    let _ = out.flush();
    std::process::exit(report.exit_code());
}

// ────────────────────────────────────────────────────────────────────
// Argument parsing
// ────────────────────────────────────────────────────────────────────

#[derive(Debug, Default, Clone, Copy)]
struct DoctorOpts {
    json: bool,
}

fn parse_args(args: &[String]) -> Result<DoctorOpts, CliError> {
    let mut opts = DoctorOpts::default();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--json" => opts.json = true,
            "-h" | "--help" => {
                print_help();
                std::process::exit(0);
            }
            other => {
                return Err(CliError::Usage(format!(
                    "unknown doctor flag: {other:?} (try --json or --help)"
                )));
            }
        }
        i += 1;
    }
    Ok(opts)
}

fn print_help() {
    println!(
        "raxis doctor — preflight checks against <data_dir>\n\
         \n\
         USAGE:\n\
         \traxis doctor [--json]\n\
         \n\
         FLAGS:\n\
         \t--json    Emit one JSON object instead of a human report.\n\
         \n\
         EXIT CODES:\n\
         \t0   every check OK\n\
         \t1   at least one WARN, no FAIL\n\
         \t2   at least one FAIL (kernel likely won't boot cleanly)\n\
         "
    );
}

// ────────────────────────────────────────────────────────────────────
// Collection — independent of rendering
// ────────────────────────────────────────────────────────────────────

fn collect(data_dir: &Path) -> Report {
    let mut r = Report::default();

    // 1. data_dir exists.
    match std::fs::metadata(data_dir) {
        Ok(m) if m.is_dir() => {
            r.push("data_dir.exists", Outcome::Ok, format!("{}", data_dir.display()));
        }
        Ok(_) => {
            r.push(
                "data_dir.exists",
                Outcome::Fail,
                format!("{} exists but is not a directory", data_dir.display()),
            );
            // No point continuing — every other check assumes a dir.
            return r;
        }
        Err(e) => {
            r.push(
                "data_dir.exists",
                Outcome::Fail,
                format!("cannot stat {}: {}", data_dir.display(), e),
            );
            return r;
        }
    }

    // 2. Subdir presence + mode bits.
    for (name, expected_mode) in EXPECTED_MODES {
        check_subdir(&mut r, data_dir, name, *expected_mode);
    }

    // 3. policy/policy.toml loadable.
    let policy_path = data_dir.join("policy").join(POLICY_FILE_NAME);
    let bundle_epoch_opt = match load_policy(&policy_path) {
        Ok((bundle, _bytes, sha)) => {
            r.push(
                "policy.loadable",
                Outcome::Ok,
                format!("epoch={} sha={}", bundle.epoch(), &sha[..16.min(sha.len())]),
            );
            Some(bundle.epoch())
        }
        Err(e) => {
            r.push("policy.loadable", Outcome::Fail, format!("{e}"));
            None
        }
    };

    // 4. kernel.db schema-version pin.
    let conn = match open_ro(data_dir) {
        Ok(c) => {
            r.push("store.open_ro", Outcome::Ok, "schema version pin satisfied");
            Some(c)
        }
        Err(RoError::SchemaMismatch { actual, expected, .. }) => {
            r.push(
                "store.open_ro",
                Outcome::Fail,
                format!("schema mismatch: db=v{actual}, CLI expected v{expected}"),
            );
            None
        }
        Err(e) => {
            r.push("store.open_ro", Outcome::Fail, format!("{e}"));
            None
        }
    };

    // 5. runtime/heartbeat.json reachable. Missing = WARN, not FAIL.
    match read_heartbeat(data_dir) {
        Ok(snap) => {
            r.push(
                "runtime.heartbeat",
                Outcome::Ok,
                format!(
                    "pid={} state={} policy_epoch={}",
                    snap.kernel_pid, snap.state, snap.policy_epoch,
                ),
            );
        }
        Err(HeartbeatReadError::Missing(_)) => {
            r.push(
                "runtime.heartbeat",
                Outcome::Warn,
                "no heartbeat.json (kernel not running, or first boot still in progress)",
            );
        }
        Err(e) => {
            r.push("runtime.heartbeat", Outcome::Fail, format!("{e}"));
        }
    }

    // 6. Audit chain quick check.
    let audit_dir = data_dir.join(AUDIT_DIR_NAME);
    match quick_chain_check(&audit_dir) {
        ChainQuickCheck::Ok { last_seq, segment_count } => {
            r.push(
                "audit.quick_check",
                Outcome::Ok,
                format!("segments={segment_count} last_seq={last_seq}"),
            );
        }
        ChainQuickCheck::NoSegments => {
            r.push(
                "audit.quick_check",
                Outcome::Warn,
                "no segment-NNN.jsonl (kernel never emitted an audit event)",
            );
        }
        ChainQuickCheck::Broken { error } => {
            r.push("audit.quick_check", Outcome::Fail, format!("{error}"));
        }
    }

    // 7. Cross-check bundle epoch against MAX(epoch_id).
    if let (Some(conn), Some(bundle_epoch)) = (conn.as_ref(), bundle_epoch_opt) {
        match policy_history::current_epoch(conn) {
            Ok(Some(kernel_epoch)) => {
                if kernel_epoch == bundle_epoch {
                    r.push(
                        "policy.epoch_aligned",
                        Outcome::Ok,
                        format!("bundle_epoch={bundle_epoch} == kernel_epoch={kernel_epoch}"),
                    );
                } else {
                    r.push(
                        "policy.epoch_aligned",
                        Outcome::Warn,
                        format!(
                            "bundle_epoch={bundle_epoch}, kernel_epoch={kernel_epoch} \
                             — policy.toml has not been rotated yet"
                        ),
                    );
                }
            }
            Ok(None) => {
                r.push(
                    "policy.epoch_aligned",
                    Outcome::Warn,
                    "no policy_epoch_history rows (genesis row not installed?)",
                );
            }
            Err(e) => {
                r.push(
                    "policy.epoch_aligned",
                    Outcome::Fail,
                    format!("policy_history::current_epoch failed: {e}"),
                );
            }
        }
    }

    // 8. Operator-cert status sweep (step-11). Only runs if the store
    // opened cleanly above.
    if let Some(conn) = conn.as_ref() {
        check_operator_certs(&mut r, conn, unix_now_secs() as i64);
    }

    r
}

/// Walk every row in the `operator_certificates` view and classify it
/// against the four-zone model. See module docstring for the exact
/// outcomes per zone.
///
/// Reading the kernel-managed view (rather than re-parsing
/// `policy.toml`) keeps doctor honest: if `repopulate` skipped a
/// cert (for instance due to migration drift), doctor will not see
/// it either, which is the right behaviour — the kernel's view of
/// the world is what matters at boot.
fn check_operator_certs(
    r:    &mut Report,
    conn: &raxis_store::RoConn,
    now:  i64,
) {
    let rows = match operator_certificates::list_all(conn) {
        Ok(rows) => rows,
        Err(e) => {
            r.push("cert.list", Outcome::Fail, format!("{e}"));
            return;
        }
    };

    if rows.is_empty() {
        // A fresh install with no operator certs is fine — emit a
        // single OK so JSON consumers see a stable id.
        r.push(
            "cert.list",
            Outcome::Ok,
            "no operator certificates installed (legacy operator-key flow)",
        );
        return;
    }

    r.push(
        "cert.list",
        Outcome::Ok,
        format!("found {n} operator certificate(s)", n = rows.len()),
    );

    for row in rows {
        // Surface bypass-misconfig regardless of expiry zone — the
        // operator deliberately overrode a structural validation
        // check at policy-sign time and should be reminded.
        if row.force_misconfig_bypass {
            r.push(
                Box::leak(format!("cert.{}.misconfig_bypass", &row.pubkey_fingerprint)
                    .into_boxed_str()),
                Outcome::Warn,
                format!(
                    "{display} ({fp}) was installed with --force-misconfig — \
                     a structural validation check was bypassed at policy-sign time. \
                     See `OperatorCertMisconfigBypassed` audit event for the reason.",
                    display = row.display_name,
                    fp      = row.pubkey_fingerprint,
                ),
            );
        }

        let cert   = row.clone().into_operator_cert();
        let status = cert_status(&cert, now);
        let id     = Box::leak(
            format!("cert.{}.status", &row.pubkey_fingerprint).into_boxed_str(),
        );

        match status {
            CertStatus::Active | CertStatus::AlwaysActiveEmergency => {
                r.push(
                    id,
                    Outcome::Ok,
                    format!(
                        "{display} ({fp}) status={tag}",
                        display = row.display_name,
                        fp      = row.pubkey_fingerprint,
                        tag     = status.tag(),
                    ),
                );
            }
            CertStatus::Expiring { secs_until_expiry } => {
                let days = secs_until_expiry / 86_400;
                r.push(
                    id,
                    Outcome::Warn,
                    format!(
                        "{display} ({fp}) expiring in ~{days}d \
                         (warn_window={warn_d}d, not_after={not_after}); \
                         rotate via `raxis cert mint` + `raxis cert install` \
                         + `raxis epoch advance`",
                        display   = row.display_name,
                        fp        = row.pubkey_fingerprint,
                        warn_d    = row.warn_before_expiry_days,
                        not_after = row.not_after,
                    ),
                );
            }
            CertStatus::Grace { secs_until_grace_end } => {
                let days = secs_until_grace_end / 86_400;
                r.push(
                    id,
                    Outcome::Warn,
                    format!(
                        "{display} ({fp}) IN GRACE PERIOD — only recovery ops \
                         allowed. {days}d remaining before all ops are denied. \
                         Rotate immediately.",
                        display = row.display_name,
                        fp      = row.pubkey_fingerprint,
                    ),
                );
            }
            CertStatus::Expired { secs_since_expiry } => {
                let days = secs_since_expiry / 86_400;
                r.push(
                    id,
                    Outcome::Fail,
                    format!(
                        "{display} ({fp}) EXPIRED ~{days}d ago — all ops denied. \
                         Operator key is unusable until rotated.",
                        display = row.display_name,
                        fp      = row.pubkey_fingerprint,
                    ),
                );
            }
            CertStatus::NotYetValid { secs_until_active } => {
                let days = secs_until_active / 86_400;
                r.push(
                    id,
                    Outcome::Fail,
                    format!(
                        "{display} ({fp}) NOT YET VALID — activates in ~{days}d \
                         (not_before={not_before}). All ops denied until then.",
                        display    = row.display_name,
                        fp         = row.pubkey_fingerprint,
                        not_before = row.not_before,
                    ),
                );
            }
        }
    }
}

// ────────────────────────────────────────────────────────────────────
// Subdir + mode check
// ────────────────────────────────────────────────────────────────────

fn check_subdir(r: &mut Report, data_dir: &Path, name: &'static str, expected_mode: u32) {
    let path = data_dir.join(name);
    let id_exists = leak_subdir_id(name, "exists");
    let id_mode   = leak_subdir_id(name, "mode");

    let meta = match std::fs::metadata(&path) {
        Ok(m) => m,
        Err(_) => {
            // notifications/ is created lazily by the kernel's first
            // delivery; surface as WARN, not FAIL, when it is missing.
            let outcome = if name == "notifications" {
                Outcome::Warn
            } else {
                Outcome::Fail
            };
            r.push(
                id_exists,
                outcome,
                format!("missing: {}", path.display()),
            );
            return;
        }
    };

    if !meta.is_dir() {
        r.push(
            id_exists,
            Outcome::Fail,
            format!("{} exists but is not a directory", path.display()),
        );
        return;
    }
    r.push(id_exists, Outcome::Ok, format!("{}", path.display()));

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let actual = meta.permissions().mode() & 0o777;
        if actual == expected_mode {
            r.push(id_mode, Outcome::Ok, format!("0{:o}", actual));
        } else {
            // Mode drift is a WARN, not FAIL: the kernel will refuse
            // to boot for keys/ and providers/ specifically (those
            // are policed by the kernel itself), but operator
            // workflows on macOS sometimes flip group-readable bits;
            // we report rather than fail-close from the CLI.
            let severity = if matches!(name, "keys" | "providers") {
                Outcome::Fail
            } else {
                Outcome::Warn
            };
            r.push(
                id_mode,
                severity,
                format!("mode is 0{:o}, expected 0{:o}", actual, expected_mode),
            );
        }
    }

    #[cfg(not(unix))]
    {
        // Mode bits are not meaningful on non-unix; report as OK so
        // the JSON consumers see a stable id regardless of platform.
        let _ = expected_mode;
        r.push(id_mode, Outcome::Ok, "mode check skipped (non-unix)");
    }
}

/// Build a static-ish id like `"providers.exists"` from a subdir
/// name + suffix. We Box::leak the formatted String so it satisfies
/// the `&'static str` field on `Check` without burdening every caller
/// with a lifetime parameter; total leakage is bounded by the number
/// of EXPECTED_MODES entries (well under a kilobyte).
fn leak_subdir_id(name: &'static str, suffix: &'static str) -> &'static str {
    let s = format!("{name}.{suffix}");
    Box::leak(s.into_boxed_str())
}

// ────────────────────────────────────────────────────────────────────
// Rendering — human
// ────────────────────────────────────────────────────────────────────

fn render_human<W: Write>(out: &mut W, data_dir: &Path, report: &Report) {
    let _ = writeln!(out, "raxis doctor — preflight report");
    let _ = writeln!(out, "  data_dir: {}", data_dir.display());
    let _ = writeln!(out, "  worst:    {}", report.worst().label());
    let _ = writeln!(out);
    for c in &report.checks {
        let _ = writeln!(
            out,
            "  [{lvl:<4}] {id:<28} {detail}",
            lvl    = c.outcome.label(),
            id     = c.id,
            detail = c.detail,
        );
    }
}

// ────────────────────────────────────────────────────────────────────
// Rendering — JSON
// ────────────────────────────────────────────────────────────────────

fn render_json<W: Write>(out: &mut W, data_dir: &Path, report: &Report) {
    let v = serde_json::json!({
        "data_dir": data_dir.display().to_string(),
        "worst":    report.worst().label(),
        "checks":   report.checks.iter().map(|c| serde_json::json!({
            "id":      c.id,
            "outcome": c.outcome.label(),
            "detail":  c.detail,
        })).collect::<Vec<_>>(),
    });
    let _ = serde_json::to_writer(&mut *out, &v);
    let _ = writeln!(out);
}

// ────────────────────────────────────────────────────────────────────
// Tests
// ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn worst_of_ok_warn_fail_is_fail() {
        let mut r = Report::default();
        r.push("a", Outcome::Ok,   "ok");
        r.push("b", Outcome::Warn, "warn");
        r.push("c", Outcome::Fail, "fail");
        assert_eq!(r.worst(), Outcome::Fail);
        assert_eq!(r.exit_code(), 2);
    }

    #[test]
    fn worst_of_ok_warn_is_warn() {
        let mut r = Report::default();
        r.push("a", Outcome::Ok,   "ok");
        r.push("b", Outcome::Warn, "warn");
        assert_eq!(r.worst(), Outcome::Warn);
        assert_eq!(r.exit_code(), 1);
    }

    #[test]
    fn worst_of_all_ok_is_ok() {
        let mut r = Report::default();
        r.push("a", Outcome::Ok, "ok");
        assert_eq!(r.worst(), Outcome::Ok);
        assert_eq!(r.exit_code(), 0);
    }

    #[test]
    fn collect_fails_when_data_dir_missing() {
        let r = collect(Path::new("/definitely/does/not/exist/raxis"));
        assert_eq!(r.checks.len(), 1);
        assert_eq!(r.checks[0].id, "data_dir.exists");
        assert_eq!(r.checks[0].outcome, Outcome::Fail);
    }

    #[test]
    fn collect_runs_full_pipeline_against_empty_dir_and_reports_each_failure() {
        let tmp = TempDir::new().unwrap();
        let r = collect(tmp.path());
        // data_dir.exists must succeed.
        let mut ids: Vec<&str> = r.checks.iter().map(|c| c.id).collect();
        ids.sort();
        assert!(ids.contains(&"data_dir.exists"), "ids: {ids:?}");
        // Every required subdir is missing → keys/providers fail,
        // notifications warns, audit warn-or-fail through to the
        // chain check.
        assert_eq!(r.worst(), Outcome::Fail);
    }

    #[test]
    fn parse_args_rejects_unknown_flag() {
        let err = parse_args(&["--bogus".to_owned()]).unwrap_err();
        assert!(matches!(err, CliError::Usage(_)));
    }

    #[test]
    fn parse_args_accepts_json() {
        let o = parse_args(&["--json".to_owned()]).unwrap();
        assert!(o.json);
    }

    #[test]
    fn render_json_emits_object_with_per_check_array() {
        let mut buf: Vec<u8> = Vec::new();
        let mut report = Report::default();
        report.push("a.b", Outcome::Ok,   "ok detail");
        report.push("c.d", Outcome::Warn, "warning detail");
        render_json(&mut buf, Path::new("/tmp/d"), &report);
        let v: serde_json::Value = serde_json::from_slice(&buf).unwrap();
        assert_eq!(v["data_dir"], "/tmp/d");
        assert_eq!(v["worst"], "WARN");
        let checks = v["checks"].as_array().unwrap();
        assert_eq!(checks.len(), 2);
        assert_eq!(checks[0]["id"], "a.b");
        assert_eq!(checks[1]["id"], "c.d");
        assert_eq!(checks[1]["outcome"], "WARN");
    }

    // ── Step-11: cert.* check coverage ────────────────────────────────
    //
    // These tests build a real on-disk SQLite via `Store::open`,
    // insert one or more `operator_certificates` rows directly with
    // raw SQL (the kernel-side `repopulate` helper drives off a full
    // PolicyBundle which is heavy to construct in a unit test), then
    // re-open read-only and exercise `check_operator_certs`.
    //
    // The `cert_status` classification is already tested in
    // `raxis-crypto::cert::tests`; here we only assert the
    // doctor-side mapping (status → Outcome + id format).

    fn setup_db_with_cert(
        tmp:                    &TempDir,
        fp:                     &str,
        display_name:           &str,
        not_before:             i64,
        not_after:              i64,
        warn_days:              u32,
        grace_days:             u32,
        kind:                   &str,
        force_misconfig_bypass: bool,
    ) {
        const POLICY_EPOCH_HISTORY:  &str =
            raxis_store::Table::PolicyEpochHistory.as_str();
        const OPERATOR_CERTIFICATES: &str =
            raxis_store::Table::OperatorCertificates.as_str();

        // Open RW once to apply migrations + insert the row, then
        // drop the handle so the RO open downstream sees a complete
        // schema (migrations run on `Store::open`).
        let store = raxis_store::Store::open(&tmp.path().join("kernel.db")).unwrap();
        let conn = store.lock_sync();
        // policy_epoch_history must have a row first — `operator_certificates.epoch_id`
        // FK-references it. We use `INSERT OR IGNORE` so multiple cert
        // inserts in one test (future-proofing for that case) don't trip
        // the PRIMARY KEY UNIQUE on (epoch_id) and pubkey UNIQUE on
        // policy_sha256.
        conn.execute(
            &format!(
                "INSERT OR IGNORE INTO {POLICY_EPOCH_HISTORY} (\
                    epoch_id, policy_sha256, signed_by_authority, \
                    triggered_by_operator, advanced_at\
                 ) VALUES (1, 'sha-test', 'auth-test', 'op-test', 0)"
            ),
            [],
        ).unwrap();
        // Each cert needs a unique pubkey_hex (UNIQUE constraint on the
        // column), so we derive one from the test-supplied fingerprint
        // padded to 64 hex chars.
        let pubkey_hex = format!("{fp}{}", "0".repeat(64usize.saturating_sub(fp.len())));
        let self_sig   = "11".repeat(32);
        conn.execute(
            &format!(
                "INSERT INTO {OPERATOR_CERTIFICATES} (\
                    pubkey_fingerprint, epoch_id, kind, display_name, pubkey_hex, \
                    not_before, not_after, warn_before_expiry_days, grace_period_days, \
                    permitted_ops_json, contact_info, self_sig_hex, \
                    force_misconfig_bypass, installed_at\
                 ) VALUES (?1, 1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, '[]', NULL, ?9, ?10, 0)"
            ),
            rusqlite::params![
                fp,
                kind,
                display_name,
                pubkey_hex,
                not_before,
                not_after,
                warn_days as i64,
                grace_days as i64,
                self_sig,
                force_misconfig_bypass as i64,
            ],
        ).unwrap();
        drop(conn);
        drop(store);
    }

    #[test]
    fn cert_check_lists_no_certs_emits_single_ok_row() {
        let tmp = TempDir::new().unwrap();
        let _ = raxis_store::Store::open(&tmp.path().join("kernel.db")).unwrap();
        // Re-open read-only.
        let conn = raxis_store::open_ro(tmp.path()).unwrap();
        let mut r = Report::default();
        check_operator_certs(&mut r, &conn, 1_700_000_000);

        let ids: Vec<&str> = r.checks.iter().map(|c| c.id).collect();
        assert!(ids.contains(&"cert.list"),
            "must emit cert.list when zero certs are installed; got {ids:?}");
        let cert_list = r.checks.iter().find(|c| c.id == "cert.list").unwrap();
        assert_eq!(cert_list.outcome, Outcome::Ok);
        assert!(cert_list.detail.contains("no operator certificates"),
            "detail must explain the legacy flow: {:?}", cert_list.detail);
    }

    #[test]
    fn cert_check_classifies_active_cert_as_ok() {
        let tmp = TempDir::new().unwrap();
        let now: i64 = 1_700_000_000;
        let one_year = 365 * 86_400;
        setup_db_with_cert(
            &tmp, "abcd1234deadbeef", "Alice",
            now - 86_400, now + one_year, // valid through next year
            30, 7, "Standard", false,
        );

        let conn = raxis_store::open_ro(tmp.path()).unwrap();
        let mut r = Report::default();
        check_operator_certs(&mut r, &conn, now);

        let status_check = r.checks.iter()
            .find(|c| c.id.starts_with("cert.abcd1234deadbeef.status"))
            .expect("must emit per-cert status check");
        assert_eq!(status_check.outcome, Outcome::Ok);
        assert!(status_check.detail.contains("status=active"),
            "detail must carry the active tag: {:?}", status_check.detail);
    }

    #[test]
    fn cert_check_warns_on_expiring_cert() {
        let tmp = TempDir::new().unwrap();
        let now: i64 = 1_700_000_000;
        // Cert expires in 5 days, warn window is 30 days → Expiring.
        setup_db_with_cert(
            &tmp, "expiring00000001", "Bob",
            now - 86_400 * 60, now + 86_400 * 5,
            30, 7, "Standard", false,
        );

        let conn = raxis_store::open_ro(tmp.path()).unwrap();
        let mut r = Report::default();
        check_operator_certs(&mut r, &conn, now);

        let status = r.checks.iter()
            .find(|c| c.id.starts_with("cert.expiring00000001.status"))
            .expect("must emit per-cert status check");
        assert_eq!(status.outcome, Outcome::Warn);
        assert!(status.detail.contains("expiring in"),
            "detail must mention expiry runway: {:?}", status.detail);
    }

    #[test]
    fn cert_check_fails_on_expired_cert() {
        let tmp = TempDir::new().unwrap();
        let now: i64 = 1_700_000_000;
        // Cert expired 30 days ago and grace (7d) elapsed → Expired.
        setup_db_with_cert(
            &tmp, "expired000000001", "Charlie",
            now - 86_400 * 365, now - 86_400 * 30,
            30, 7, "Standard", false,
        );

        let conn = raxis_store::open_ro(tmp.path()).unwrap();
        let mut r = Report::default();
        check_operator_certs(&mut r, &conn, now);

        let status = r.checks.iter()
            .find(|c| c.id.starts_with("cert.expired000000001.status"))
            .expect("must emit per-cert status check");
        assert_eq!(status.outcome, Outcome::Fail);
        assert!(status.detail.contains("EXPIRED"),
            "detail must carry the loud EXPIRED marker: {:?}", status.detail);
    }

    #[test]
    fn cert_check_warns_when_force_misconfig_bypass_is_set() {
        let tmp = TempDir::new().unwrap();
        let now: i64 = 1_700_000_000;
        let one_year = 365 * 86_400;
        setup_db_with_cert(
            &tmp, "bypassedcert0001", "Dana",
            now - 86_400, now + one_year,
            30, 7, "Standard", true, // ← bypass on
        );

        let conn = raxis_store::open_ro(tmp.path()).unwrap();
        let mut r = Report::default();
        check_operator_certs(&mut r, &conn, now);

        let bypass = r.checks.iter()
            .find(|c| c.id.starts_with("cert.bypassedcert0001.misconfig_bypass"))
            .expect("must emit a cert.<fp>.misconfig_bypass row");
        assert_eq!(bypass.outcome, Outcome::Warn);
        assert!(bypass.detail.contains("--force-misconfig"),
            "bypass detail must reference the CLI flag for grep-traceability: {:?}",
            bypass.detail);

        // Status itself is Active (the bypass is orthogonal).
        let status = r.checks.iter()
            .find(|c| c.id.starts_with("cert.bypassedcert0001.status"))
            .expect("status row must still appear alongside bypass row");
        assert_eq!(status.outcome, Outcome::Ok);
    }

    #[test]
    fn cert_check_treats_emergency_kind_as_always_active() {
        let tmp = TempDir::new().unwrap();
        let now: i64 = 1_700_000_000;
        // EmergencyRecovery: the not_before / not_after / warn / grace
        // values are STRUCTURALLY IGNORED by `cert_status` — we still
        // pass realistic values so the row passes any future row-level
        // CHECK constraints. The expected outcome is OK regardless.
        setup_db_with_cert(
            &tmp, "emergency00000001", "Break-Glass",
            0, 0, 0, 0, "EmergencyRecovery", false,
        );

        let conn = raxis_store::open_ro(tmp.path()).unwrap();
        let mut r = Report::default();
        check_operator_certs(&mut r, &conn, now);

        let status = r.checks.iter()
            .find(|c| c.id.starts_with("cert.emergency00000001.status"))
            .expect("must emit per-cert status check for emergency cert");
        assert_eq!(status.outcome, Outcome::Ok);
        assert!(status.detail.contains("always_active_emergency"),
            "emergency cert detail must use the canonical zone tag: {:?}",
            status.detail);
    }
}

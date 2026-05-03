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

use std::io::Write;
use std::path::{Path, PathBuf};

use raxis_audit_tools::{quick_chain_check, ChainQuickCheck};
use raxis_policy::load_policy;
use raxis_runtime::{read as read_heartbeat, ReadError as HeartbeatReadError};
use raxis_store::{open_ro, RoError};
use raxis_store::views::policy_history;

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

    r
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
}

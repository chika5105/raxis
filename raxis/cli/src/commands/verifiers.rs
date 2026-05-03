//! `raxis verifiers` — list outstanding + recent verifier subprocesses.
//!
//! Normative reference: cli-readonly.md §5.5.8.
//!
//! # Data sources (all read-only, no kernel IPC)
//!
//! * `<data_dir>/runtime/heartbeat.json` — `active_verifiers` and
//!   `max_concurrent_verifiers` published by the kernel's
//!   verifier-runner module. Best-effort: missing heartbeat is a
//!   warning row, not a hard failure.
//! * `<data_dir>/kernel.db` opened READ-ONLY via `raxis_store::open_ro`:
//!   - `views::verifier_tokens::outstanding` → tokens issued, not
//!     yet consumed, not yet expired (these correspond to
//!     verifier subprocesses currently in flight).
//!   - `views::verifier_tokens::recent_runs` → last N regardless of
//!     state when `--recent` is requested.
//!
//! # Why two surfaces
//!
//! "What's running right now?" and "what ran in the last hour?" are
//! different operator questions. The default render answers the
//! first; `--recent` answers the second. Folding them into one
//! gigantic table would bury whichever question the operator
//! actually had.
//!
//! # Exit code
//!
//! Always 0 on success. Heartbeat / view failures are surfaced
//! inline as a warning line; only a missing kernel.db hard-fails
//! through `CliError::Policy`.

use std::io::Write;

use raxis_runtime::read as read_heartbeat;
use raxis_store::open_ro;
use raxis_store::views::verifier_tokens::{
    outstanding, recent_runs, VerifierTokenRow,
};

use crate::errors::CliError;
use crate::GlobalFlags;

const DEFAULT_LIMIT: usize = 50;

// ────────────────────────────────────────────────────────────────────
// Entry point
// ────────────────────────────────────────────────────────────────────

pub fn run(flags: &GlobalFlags, args: &[String]) -> Result<(), CliError> {
    let opts = parse_args(args)?;

    let conn = open_ro(flags.data_dir())
        .map_err(|e| CliError::Policy(format!("kernel.db open failed: {e}")))?;

    let active = if opts.recent {
        recent_runs(&conn, opts.limit)
            .map_err(|e| CliError::Policy(format!("verifier_tokens::recent_runs failed: {e}")))?
    } else {
        outstanding(&conn, opts.limit)
            .map_err(|e| CliError::Policy(format!("verifier_tokens::outstanding failed: {e}")))?
    };

    let heartbeat = read_heartbeat(flags.data_dir()).ok();

    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    if opts.json {
        render_json(&mut out, &active, opts.recent, heartbeat.as_ref());
    } else {
        render_human(&mut out, &active, opts.recent, heartbeat.as_ref());
    }
    let _ = out.flush();
    Ok(())
}

// ────────────────────────────────────────────────────────────────────
// Argument parsing
// ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy)]
struct VerifiersOpts {
    recent: bool,
    limit:  usize,
    json:   bool,
}

impl Default for VerifiersOpts {
    fn default() -> Self {
        Self { recent: false, limit: DEFAULT_LIMIT, json: false }
    }
}

fn parse_args(args: &[String]) -> Result<VerifiersOpts, CliError> {
    let mut opts = VerifiersOpts::default();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--json"   => opts.json   = true,
            "--recent" => opts.recent = true,
            "--limit"  => {
                i += 1;
                let raw = args
                    .get(i)
                    .ok_or_else(|| CliError::Usage("--limit requires a value".to_owned()))?;
                opts.limit = raw.parse::<usize>().map_err(|_| {
                    CliError::Usage(format!("--limit must be a positive integer, got {raw:?}"))
                })?;
                if opts.limit == 0 {
                    return Err(CliError::Usage("--limit must be greater than 0".to_owned()));
                }
            }
            "-h" | "--help" => {
                print_help();
                std::process::exit(0);
            }
            other => {
                return Err(CliError::Usage(format!(
                    "unknown verifiers flag: {other:?} \
                     (try --recent, --limit N, --json, --help)"
                )));
            }
        }
        i += 1;
    }
    Ok(opts)
}

fn print_help() {
    println!(
        "raxis verifiers — list verifier subprocess tokens\n\
         \n\
         USAGE:\n\
         \traxis verifiers [--recent] [--limit N] [--json]\n\
         \n\
         FLAGS:\n\
         \t--recent   Show the last N issued tokens regardless of state\n\
         \t           (default: only outstanding — not consumed, not expired).\n\
         \t--limit N  Cap the number of rows shown (default: {DEFAULT_LIMIT}).\n\
         \t--json     Emit one JSON object instead of a human table.\n\
         "
    );
}

// ────────────────────────────────────────────────────────────────────
// Rendering — human
// ────────────────────────────────────────────────────────────────────

fn render_human<W: Write>(
    out:        &mut W,
    rows:       &[VerifierTokenRow],
    recent:     bool,
    heartbeat:  Option<&raxis_runtime::Snapshot>,
) {
    let label = if recent { "recent" } else { "outstanding" };
    let _ = writeln!(
        out,
        "Verifiers ({label}, {n} row{plural}):",
        n      = rows.len(),
        plural = if rows.len() == 1 { "" } else { "s" },
    );
    if let Some(s) = heartbeat {
        let _ = writeln!(
            out,
            "  heartbeat: active={active} max_concurrent={max} (kernel_pid={pid})",
            active = s.active_verifiers,
            max    = s.max_concurrent_verifiers,
            pid    = s.kernel_pid,
        );
    } else {
        let _ = writeln!(out, "  heartbeat: <unavailable>");
    }
    if rows.is_empty() {
        let _ = writeln!(out, "  (no rows)");
        return;
    }
    let _ = writeln!(
        out,
        "  {run:<24} {task:<20} {gate:<16} {state:<10} {ttl:>10}",
        run    = "verifier_run_id",
        task   = "task_id",
        gate   = "gate_type",
        state  = "state",
        ttl    = "ttl",
    );
    let now = unix_now_secs();
    for r in rows {
        let state = if r.consumed {
            "consumed"
        } else if r.expires_at <= now {
            "expired"
        } else {
            "in-flight"
        };
        let ttl = if state == "in-flight" {
            format_secs_relative(r.expires_at.saturating_sub(now))
        } else {
            "-".to_owned()
        };
        let _ = writeln!(
            out,
            "  {run:<24} {task:<20} {gate:<16} {state:<10} {ttl:>10}",
            run   = truncate(&r.verifier_run_id, 24),
            task  = truncate(&r.task_id, 20),
            gate  = truncate(&r.gate_type, 16),
            state = state,
            ttl   = ttl,
        );
    }
}

// ────────────────────────────────────────────────────────────────────
// Rendering — JSON
// ────────────────────────────────────────────────────────────────────

fn render_json<W: Write>(
    out:       &mut W,
    rows:      &[VerifierTokenRow],
    recent:    bool,
    heartbeat: Option<&raxis_runtime::Snapshot>,
) {
    let v = serde_json::json!({
        "view":  if recent { "recent" } else { "outstanding" },
        "count": rows.len(),
        "heartbeat": heartbeat.map(|s| serde_json::json!({
            "active_verifiers":         s.active_verifiers,
            "max_concurrent_verifiers": s.max_concurrent_verifiers,
            "kernel_pid":               s.kernel_pid,
        })),
        "rows": rows.iter().map(|r| serde_json::json!({
            "verifier_run_id": r.verifier_run_id,
            "task_id":         r.task_id,
            "gate_type":       r.gate_type,
            "evaluation_sha":  r.evaluation_sha,
            "issued_at":       r.issued_at,
            "expires_at":      r.expires_at,
            "consumed":        r.consumed,
            "consumed_at":     r.consumed_at,
        })).collect::<Vec<_>>(),
    });
    let _ = serde_json::to_writer(&mut *out, &v);
    let _ = writeln!(out);
}

// ────────────────────────────────────────────────────────────────────
// Helpers
// ────────────────────────────────────────────────────────────────────

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_owned()
    } else {
        let mut out: String = s.chars().take(max.saturating_sub(1)).collect();
        out.push('…');
        out
    }
}

fn unix_now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn format_secs_relative(secs: u64) -> String {
    if secs == 0                 { return "0s".to_owned(); }
    if secs < 60                 { return format!("{secs}s"); }
    if secs < 60 * 60            { return format!("{}m", secs / 60); }
    if secs < 24 * 60 * 60       { return format!("{}h", secs / 3600); }
    format!("{}d", secs / 86_400)
}

// ────────────────────────────────────────────────────────────────────
// Tests
// ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn row(id: &str, consumed: bool, expires_at: u64) -> VerifierTokenRow {
        VerifierTokenRow {
            verifier_run_id: id.to_owned(),
            task_id:         "t-1".to_owned(),
            gate_type:       "tests".to_owned(),
            evaluation_sha:  "eval".to_owned(),
            issued_at:       100,
            expires_at,
            consumed,
            consumed_at:     consumed.then_some(150),
        }
    }

    #[test]
    fn parse_args_defaults() {
        let o = parse_args(&[]).unwrap();
        assert!(!o.recent);
        assert_eq!(o.limit, DEFAULT_LIMIT);
        assert!(!o.json);
    }

    #[test]
    fn parse_args_accepts_recent_and_limit() {
        let o = parse_args(&[
            "--recent".to_owned(),
            "--limit".to_owned(),
            "5".to_owned(),
        ]).unwrap();
        assert!(o.recent);
        assert_eq!(o.limit, 5);
    }

    #[test]
    fn parse_args_rejects_zero_limit() {
        let err = parse_args(&[
            "--limit".to_owned(),
            "0".to_owned(),
        ]).unwrap_err();
        assert!(matches!(err, CliError::Usage(_)));
    }

    #[test]
    fn render_human_classifies_each_state() {
        let now = unix_now_secs();
        let rows = vec![
            row("v-active",   false, now + 10_000), // in-flight
            row("v-consumed", true,  now + 10_000), // consumed
            row("v-expired",  false, now.saturating_sub(1)),  // expired
        ];
        let mut buf: Vec<u8> = Vec::new();
        render_human(&mut buf, &rows, false, None);
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("in-flight"), "got: {s}");
        assert!(s.contains("consumed"), "got: {s}");
        assert!(s.contains("expired"), "got: {s}");
    }

    #[test]
    fn render_human_with_no_rows_says_so() {
        let mut buf: Vec<u8> = Vec::new();
        render_human(&mut buf, &[], false, None);
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("Verifiers (outstanding"), "got: {s}");
        assert!(s.contains("(no rows)"), "got: {s}");
    }

    #[test]
    fn render_json_emits_view_count_and_array() {
        let mut buf: Vec<u8> = Vec::new();
        let rows = vec![row("v-1", false, unix_now_secs() + 100)];
        render_json(&mut buf, &rows, true, None);
        let v: serde_json::Value = serde_json::from_slice(&buf).unwrap();
        assert_eq!(v["view"], "recent");
        assert_eq!(v["count"], 1);
        assert_eq!(v["rows"][0]["verifier_run_id"], "v-1");
    }
}

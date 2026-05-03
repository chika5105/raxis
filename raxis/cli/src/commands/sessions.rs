//! `raxis sessions` — list currently-active planner / gateway / verifier
//! sessions and global session-state counts.
//!
//! Normative reference: cli-readonly.md §5.5.7.
//!
//! # Data sources (all read-only, no kernel IPC)
//!
//! * `<data_dir>/kernel.db` opened READ-ONLY via `raxis_store::open_ro`.
//!   - `views::sessions::active_counts` → 3-bucket projection
//!     (active / expired / revoked).
//!   - `views::sessions::active_list`   → row-by-row table.
//!
//! # Why no `--all` flag in v1
//!
//! The v1 spec deliberately limits `raxis sessions` to *active* rows
//! because the operator's day-to-day question is "what is currently
//! talking to my kernel?" — not "what once did?". Expired / revoked
//! rows still surface in the COUNTS row at the top of the table so a
//! healthy 3-bucket history is visible at a glance, but the row-level
//! detail intentionally hides clutter that `raxis log` already covers
//! via the `SessionRevoked` / `SessionExpired` audit events.
//!
//! # Exit code
//!
//! `0` on every success; the only failure path is an `RoError`
//! (which `CliError::Policy` wraps for the operator).

use std::io::Write;

use raxis_store::open_ro;
use raxis_store::views::sessions::{active_counts, active_list, SessionRow, SessionStateCounts};

use crate::errors::CliError;
use crate::GlobalFlags;

// ────────────────────────────────────────────────────────────────────
// Defaults
// ────────────────────────────────────────────────────────────────────

/// How many active sessions we dump by default. Generous for v1 — a
/// single host should never see more than a handful of concurrent
/// planner / gateway / verifier sessions, but we cap to keep accidental
/// `raxis sessions` invocations on a stuck kernel from flooding the TTY.
const DEFAULT_LIMIT: usize = 50;

// ────────────────────────────────────────────────────────────────────
// Entry point
// ────────────────────────────────────────────────────────────────────

pub fn run(flags: &GlobalFlags, args: &[String]) -> Result<(), CliError> {
    let opts = parse_args(args)?;

    let conn = open_ro(flags.data_dir())
        .map_err(|e| CliError::Policy(format!("kernel.db open failed: {e}")))?;

    let counts = active_counts(&conn)
        .map_err(|e| CliError::Policy(format!("sessions::active_counts failed: {e}")))?;
    let rows = active_list(&conn, opts.limit)
        .map_err(|e| CliError::Policy(format!("sessions::active_list failed: {e}")))?;

    let stdout = std::io::stdout();
    let mut out = stdout.lock();

    if opts.json {
        render_json(&mut out, &counts, &rows);
    } else {
        render_human(&mut out, &counts, &rows);
    }
    let _ = out.flush();
    Ok(())
}

// ────────────────────────────────────────────────────────────────────
// Argument parsing
// ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy)]
struct SessionsOpts {
    limit: usize,
    json:  bool,
}

impl Default for SessionsOpts {
    fn default() -> Self {
        Self { limit: DEFAULT_LIMIT, json: false }
    }
}

fn parse_args(args: &[String]) -> Result<SessionsOpts, CliError> {
    let mut opts = SessionsOpts::default();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--json" => opts.json = true,
            "--limit" => {
                i += 1;
                let raw = args
                    .get(i)
                    .ok_or_else(|| CliError::Usage("--limit requires a value".to_owned()))?;
                opts.limit = raw.parse::<usize>().map_err(|_| {
                    CliError::Usage(format!("--limit must be a positive integer, got {raw:?}"))
                })?;
                if opts.limit == 0 {
                    return Err(CliError::Usage(
                        "--limit must be greater than 0".to_owned(),
                    ));
                }
            }
            "-h" | "--help" => {
                print_help();
                std::process::exit(0);
            }
            other => {
                return Err(CliError::Usage(format!(
                    "unknown sessions flag: {other:?} (try --json, --limit N, --help)"
                )));
            }
        }
        i += 1;
    }
    Ok(opts)
}

fn print_help() {
    println!(
        "raxis sessions — list active planner / gateway / verifier sessions\n\
         \n\
         USAGE:\n\
         \traxis sessions [--limit N] [--json]\n\
         \n\
         FLAGS:\n\
         \t--limit N   Cap the number of rows shown (default: {DEFAULT_LIMIT}).\n\
         \t--json      Emit one JSON object instead of a human table.\n\
         "
    );
}

// ────────────────────────────────────────────────────────────────────
// Rendering — human
// ────────────────────────────────────────────────────────────────────

fn render_human<W: Write>(out: &mut W, counts: &SessionStateCounts, rows: &[SessionRow]) {
    let _ = writeln!(
        out,
        "Sessions ({active} active, {expired} expired, {revoked} revoked, {total} total):",
        active  = counts.active,
        expired = counts.expired,
        revoked = counts.revoked,
        total   = counts.total,
    );
    if rows.is_empty() {
        let _ = writeln!(out, "  (no active sessions)");
        return;
    }
    let _ = writeln!(
        out,
        "  {sid:<26} {role:<10} {lineage:<20} {seq:>4} {expires_in:>10}",
        sid        = "session_id",
        role       = "role",
        lineage    = "lineage_id",
        seq        = "seq",
        expires_in = "expires",
    );
    let now = unix_now_secs();
    for r in rows {
        let expires_in = r.expires_at.saturating_sub(now);
        let _ = writeln!(
            out,
            "  {sid:<26} {role:<10} {lineage:<20} {seq:>4} {expires:>10}",
            sid     = truncate(&r.session_id, 26),
            role    = truncate(&r.role_id,    10),
            lineage = truncate(&r.lineage_id, 20),
            seq     = r.sequence_number,
            expires = format_secs_relative(expires_in),
        );
    }
}

// ────────────────────────────────────────────────────────────────────
// Rendering — JSON
// ────────────────────────────────────────────────────────────────────

fn render_json<W: Write>(out: &mut W, counts: &SessionStateCounts, rows: &[SessionRow]) {
    let v = serde_json::json!({
        "counts": {
            "active":  counts.active,
            "expired": counts.expired,
            "revoked": counts.revoked,
            "total":   counts.total,
        },
        "active_sessions": rows.iter().map(|r| serde_json::json!({
            "session_id":      r.session_id,
            "role_id":         r.role_id,
            "lineage_id":      r.lineage_id,
            "worktree_root":   r.worktree_root,
            "sequence_number": r.sequence_number,
            "created_at":      r.created_at,
            "expires_at":      r.expires_at,
            "revoked":         r.revoked,
            "revoked_at":      r.revoked_at,
        })).collect::<Vec<_>>(),
    });
    let _ = serde_json::to_writer(&mut *out, &v);
    let _ = writeln!(out);
}

// ────────────────────────────────────────────────────────────────────
// Small helpers
// ────────────────────────────────────────────────────────────────────

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_owned()
    } else {
        // Keep the first (max-1) chars + an ellipsis so the column
        // width is preserved exactly.
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

/// Render a duration-in-seconds as a compact relative label
/// (`12s`, `5m`, `3h`, `2d`). Caps at days; weeks roll up to "+Nd".
fn format_secs_relative(secs: u64) -> String {
    if secs == 0                 { return "expired".to_owned(); }
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

    fn sample_counts() -> SessionStateCounts {
        SessionStateCounts { active: 2, expired: 1, revoked: 0, total: 3 }
    }

    fn sample_row(id: &str, role: &str, expires_at: u64) -> SessionRow {
        SessionRow {
            session_id:      id.to_owned(),
            role_id:         role.to_owned(),
            lineage_id:      "lin-1".to_owned(),
            worktree_root:   None,
            sequence_number: 1,
            created_at:      0,
            expires_at,
            revoked:         false,
            revoked_at:      None,
        }
    }

    #[test]
    fn parse_args_defaults_when_empty() {
        let o = parse_args(&[]).unwrap();
        assert_eq!(o.limit, DEFAULT_LIMIT);
        assert!(!o.json);
    }

    #[test]
    fn parse_args_accepts_limit_and_json() {
        let o = parse_args(&[
            "--limit".to_owned(),
            "10".to_owned(),
            "--json".to_owned(),
        ])
        .unwrap();
        assert_eq!(o.limit, 10);
        assert!(o.json);
    }

    #[test]
    fn parse_args_rejects_zero_limit() {
        let err = parse_args(&["--limit".to_owned(), "0".to_owned()]).unwrap_err();
        assert!(matches!(err, CliError::Usage(_)));
    }

    #[test]
    fn parse_args_rejects_unknown_flag() {
        let err = parse_args(&["--bogus".to_owned()]).unwrap_err();
        assert!(matches!(err, CliError::Usage(_)));
    }

    #[test]
    fn render_human_with_no_rows_says_so() {
        let mut buf: Vec<u8> = Vec::new();
        render_human(
            &mut buf,
            &SessionStateCounts::default(),
            &[],
        );
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("(no active sessions)"), "got: {s}");
    }

    #[test]
    fn render_human_renders_counts_and_rows() {
        let mut buf: Vec<u8> = Vec::new();
        render_human(
            &mut buf,
            &sample_counts(),
            &[
                sample_row("s-a", "planner", unix_now_secs() + 90),
                sample_row("s-b", "gateway", unix_now_secs() + 5_000),
            ],
        );
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("Sessions (2 active"), "got: {s}");
        assert!(s.contains("s-a"), "got: {s}");
        assert!(s.contains("s-b"), "got: {s}");
        assert!(s.contains("planner"), "got: {s}");
        assert!(s.contains("gateway"), "got: {s}");
    }

    #[test]
    fn render_json_emits_object_with_counts_and_array() {
        let mut buf: Vec<u8> = Vec::new();
        render_json(&mut buf, &sample_counts(), &[sample_row("s-a", "planner", 9999)]);
        let v: serde_json::Value = serde_json::from_slice(&buf).unwrap();
        assert_eq!(v["counts"]["active"], 2);
        assert_eq!(v["counts"]["total"], 3);
        let arr = v["active_sessions"].as_array().unwrap();
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["session_id"], "s-a");
        assert_eq!(arr[0]["role_id"], "planner");
    }

    #[test]
    fn truncate_passes_short_strings_unchanged_and_ellipses_long_ones() {
        assert_eq!(truncate("abc", 5), "abc");
        assert_eq!(truncate("abcdefghij", 5), "abcd…");
    }

    #[test]
    fn format_secs_relative_uses_correct_unit_steps() {
        assert_eq!(format_secs_relative(0), "expired");
        assert_eq!(format_secs_relative(45), "45s");
        assert_eq!(format_secs_relative(120), "2m");
        assert_eq!(format_secs_relative(7_200), "2h");
        assert_eq!(format_secs_relative(2 * 86_400 + 3_600), "2d");
    }
}

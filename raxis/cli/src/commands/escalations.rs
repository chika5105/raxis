//! `raxis escalations` — list pending / approved / denied escalations.
//!
//! Normative reference: cli-readonly.md §5.5.6.
//!
//! # Why this command exists separately from `raxis escalation
//! approve|deny`
//!
//! `escalation approve` / `escalation deny` are *mutating* operator
//! commands (live in `commands/escalation.rs`). This file is the
//! plural, **read-only** companion that operators reach for when they
//! need to know what they're being asked to decide on. Keeping the
//! two surfaces in separate files makes the "no kernel IPC needed"
//! contract obvious — `raxis escalations` only ever opens
//! `kernel.db` read-only and never auths.
//!
//! # Data sources (all read-only, no kernel IPC)
//!
//! * `<data_dir>/kernel.db` opened READ-ONLY via `raxis_store::open_ro`.
//!   - `views::escalations::list` paged + filtered.
//!
//! # Filter
//!
//! `--status pending|approved|denied|all`. Default is `pending`
//! because the operator's recurring question is "what needs my
//! attention right now?" — listing every historical resolution by
//! default would bury the actionable rows.
//!
//! # Exit code
//!
//! Always `0` on success; the only failure path is a `Policy(...)`
//! error from the underlying view (e.g. corrupted `kernel.db`).

use std::io::Write;

use raxis_store::open_ro;
use raxis_store::views::escalations::{list, EscalationRow, EscalationStatusFilter};

use crate::errors::CliError;
use crate::GlobalFlags;

const DEFAULT_LIMIT: usize = 50;

// Per cli-readonly.md §5.5.6: the human table truncates the
// justification to keep one row per line. JSON output preserves the
// full string so audit consumers don't lose information.
const JUSTIFICATION_TRUNC: usize = 48;

// ────────────────────────────────────────────────────────────────────
// Entry point
// ────────────────────────────────────────────────────────────────────

pub fn run(flags: &GlobalFlags, args: &[String]) -> Result<(), CliError> {
    let opts = parse_args(args)?;

    let conn = open_ro(flags.data_dir())
        .map_err(|e| CliError::Policy(format!("kernel.db open failed: {e}")))?;
    let rows = list(&conn, opts.filter, opts.limit)
        .map_err(|e| CliError::Policy(format!("escalations::list failed: {e}")))?;

    let stdout = std::io::stdout();
    let mut out = stdout.lock();

    if opts.json {
        render_json(&mut out, opts.filter, &rows);
    } else {
        render_human(&mut out, opts.filter, &rows);
    }
    let _ = out.flush();
    Ok(())
}

// ────────────────────────────────────────────────────────────────────
// Argument parsing
// ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy)]
struct EscalationsOpts {
    filter: EscalationStatusFilter,
    limit: usize,
    json: bool,
}

impl Default for EscalationsOpts {
    fn default() -> Self {
        Self {
            filter: EscalationStatusFilter::Pending,
            limit: DEFAULT_LIMIT,
            json: false,
        }
    }
}

fn parse_args(args: &[String]) -> Result<EscalationsOpts, CliError> {
    let mut opts = EscalationsOpts::default();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--json" => opts.json = true,
            "--status" => {
                i += 1;
                let raw = args.get(i).ok_or_else(|| {
                    CliError::Usage(
                        "--status requires one of pending|approved|denied|all".to_owned(),
                    )
                })?;
                opts.filter = parse_status(raw)?;
            }
            "--limit" => {
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
                    "unknown escalations flag: {other:?} \
                     (try --status pending|approved|denied|all, --limit N, --json, --help)"
                )));
            }
        }
        i += 1;
    }
    Ok(opts)
}

fn parse_status(raw: &str) -> Result<EscalationStatusFilter, CliError> {
    // Case-insensitive: planners and CI tend to lowercase.
    match raw.to_ascii_lowercase().as_str() {
        "pending" => Ok(EscalationStatusFilter::Pending),
        "approved" => Ok(EscalationStatusFilter::Approved),
        "denied" => Ok(EscalationStatusFilter::Denied),
        "all" => Ok(EscalationStatusFilter::All),
        other => Err(CliError::Usage(format!(
            "unknown --status value {other:?} (expected pending|approved|denied|all)"
        ))),
    }
}

fn print_help() {
    println!(
        "raxis escalations — list escalations by status\n\
         \n\
         USAGE:\n\
         \traxis escalations [--status pending|approved|denied|all] [--limit N] [--json]\n\
         \n\
         FLAGS:\n\
         \t--status FILTER   Status to filter on (default: pending).\n\
         \t--limit  N        Cap the number of rows shown (default: {DEFAULT_LIMIT}).\n\
         \t--json            Emit one JSON object instead of a human table.\n\
         "
    );
}

// ────────────────────────────────────────────────────────────────────
// Rendering — human
// ────────────────────────────────────────────────────────────────────

fn render_human<W: Write>(out: &mut W, filter: EscalationStatusFilter, rows: &[EscalationRow]) {
    let _ = writeln!(
        out,
        "Escalations (status={status}, {n} row{plural}):",
        status = filter_label(filter),
        n = rows.len(),
        plural = if rows.len() == 1 { "" } else { "s" },
    );
    if rows.is_empty() {
        let _ = writeln!(out, "  (no escalations)");
        return;
    }

    // Header: spec'd column order is escalation_id, status, class,
    // task_id, justification (truncated). created_at is rendered as a
    // relative age.
    let _ = writeln!(
        out,
        "  {esc:<26} {status:<10} {class:<22} {task:<24} {age:>6}  justification",
        esc = "escalation_id",
        status = "status",
        class = "class",
        task = "task_id",
        age = "age",
    );
    let now = unix_now_secs();
    for r in rows {
        let age = now.saturating_sub(r.created_at);
        let _ = writeln!(
            out,
            "  {esc:<26} {status:<10} {class:<22} {task:<24} {age:>6}  {just}",
            esc = truncate(&r.escalation_id, 26),
            status = truncate(&r.status, 10),
            class = truncate(&r.class, 22),
            task = truncate(&r.task_id, 24),
            age = format_secs_relative(age),
            just = truncate(&r.justification, JUSTIFICATION_TRUNC),
        );
    }
}

// ────────────────────────────────────────────────────────────────────
// Rendering — JSON
// ────────────────────────────────────────────────────────────────────

fn render_json<W: Write>(out: &mut W, filter: EscalationStatusFilter, rows: &[EscalationRow]) {
    let v = serde_json::json!({
        "filter": filter_label(filter),
        "count":  rows.len(),
        "rows":   rows.iter().map(|r| serde_json::json!({
            "escalation_id":    r.escalation_id,
            "session_id":       r.session_id,
            "task_id":          r.task_id,
            "lineage_id":       r.lineage_id,
            "initiative_id":    r.initiative_id,
            "class":            r.class,
            "justification":    r.justification,
            "idempotency_key":  r.idempotency_key,
            "status":           r.status,
            "created_at":       r.created_at,
            "timeout_at":       r.timeout_at,
            "resolved_at":      r.resolved_at,
            "resolution_notes": r.resolution_notes,
        })).collect::<Vec<_>>(),
    });
    let _ = serde_json::to_writer(&mut *out, &v);
    let _ = writeln!(out);
}

// ────────────────────────────────────────────────────────────────────
// Helpers
// ────────────────────────────────────────────────────────────────────

fn filter_label(f: EscalationStatusFilter) -> &'static str {
    match f {
        EscalationStatusFilter::All => "all",
        EscalationStatusFilter::Pending => "pending",
        EscalationStatusFilter::Approved => "approved",
        EscalationStatusFilter::Denied => "denied",
    }
}

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
    if secs == 0 {
        return "0s".to_owned();
    }
    if secs < 60 {
        return format!("{secs}s");
    }
    if secs < 60 * 60 {
        return format!("{}m", secs / 60);
    }
    if secs < 24 * 60 * 60 {
        return format!("{}h", secs / 3600);
    }
    format!("{}d", secs / 86_400)
}

// ────────────────────────────────────────────────────────────────────
// Tests
// ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_row(id: &str, status: &str) -> EscalationRow {
        EscalationRow {
            escalation_id: id.to_owned(),
            session_id: "sess-1".to_owned(),
            task_id: "task-1".to_owned(),
            lineage_id: "lin-1".to_owned(),
            initiative_id: "init-1".to_owned(),
            class: "CapabilityUpgrade".to_owned(),
            justification: "needs WriteFiles for migration".to_owned(),
            idempotency_key: "idem-1".to_owned(),
            status: status.to_owned(),
            created_at: unix_now_secs().saturating_sub(45),
            timeout_at: unix_now_secs() + 3_600,
            resolved_at: None,
            resolution_notes: None,
        }
    }

    #[test]
    fn parse_args_defaults_to_pending_filter() {
        let o = parse_args(&[]).unwrap();
        assert_eq!(o.filter, EscalationStatusFilter::Pending);
        assert_eq!(o.limit, DEFAULT_LIMIT);
        assert!(!o.json);
    }

    #[test]
    fn parse_args_accepts_each_status_value_case_insensitively() {
        for (raw, want) in [
            ("pending", EscalationStatusFilter::Pending),
            ("PENDING", EscalationStatusFilter::Pending),
            ("approved", EscalationStatusFilter::Approved),
            ("denied", EscalationStatusFilter::Denied),
            ("all", EscalationStatusFilter::All),
        ] {
            let o = parse_args(&["--status".to_owned(), raw.to_owned()]).unwrap();
            assert_eq!(o.filter, want, "raw={raw:?}");
        }
    }

    #[test]
    fn parse_args_rejects_unknown_status() {
        let err = parse_args(&["--status".to_owned(), "bogus".to_owned()]).unwrap_err();
        assert!(matches!(err, CliError::Usage(_)));
    }

    #[test]
    fn parse_args_rejects_zero_limit() {
        let err = parse_args(&["--limit".to_owned(), "0".to_owned()]).unwrap_err();
        assert!(matches!(err, CliError::Usage(_)));
    }

    #[test]
    fn render_human_with_no_rows_says_so() {
        let mut buf: Vec<u8> = Vec::new();
        render_human(&mut buf, EscalationStatusFilter::Pending, &[]);
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("(no escalations)"), "got: {s}");
        assert!(s.contains("status=pending"), "got: {s}");
    }

    #[test]
    fn render_human_renders_columns_and_truncates_justification() {
        let mut buf: Vec<u8> = Vec::new();
        let mut row = sample_row("esc-1", "Pending");
        row.justification = "x".repeat(200);
        render_human(&mut buf, EscalationStatusFilter::Pending, &[row]);
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("esc-1"), "got: {s}");
        assert!(s.contains("Pending"), "got: {s}");
        assert!(
            s.contains('…'),
            "long justification must be ellipsised: {s}"
        );
        // The truncation must keep the line ≤ ~140 chars worst-case.
        for line in s.lines() {
            assert!(line.len() <= 200, "line too wide: {line:?}");
        }
    }

    #[test]
    fn render_json_full_justification_is_preserved() {
        let mut buf: Vec<u8> = Vec::new();
        let mut row = sample_row("esc-1", "Pending");
        row.justification = "preserve_me_in_json_".repeat(50);
        let want = row.justification.clone();
        render_json(&mut buf, EscalationStatusFilter::Pending, &[row]);
        let v: serde_json::Value = serde_json::from_slice(&buf).unwrap();
        assert_eq!(v["filter"], "pending");
        assert_eq!(v["count"], 1);
        assert_eq!(v["rows"][0]["justification"], want);
    }
}

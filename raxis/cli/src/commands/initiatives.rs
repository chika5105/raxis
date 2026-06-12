//! `raxis initiative list` — bucketed, read-only listing of
//! initiatives.
//!
//! Normative reference: `cli-readonly.md` §5.5.6b.
//!
//! # Why this lives in a *plural* module file
//!
//! The mutating `initiative abort` and `initiative quarantine`
//! commands live in `commands/initiative.rs` (singular). They open
//! `operator.sock`, perform the Ed25519 challenge-response handshake
//! and send a typed `OperatorRequest`. This file is the **read-only**
//! sibling — same naming convention as `commands/escalation.rs`
//! (mutating) vs. `commands/escalations.rs` (read-only). Keeping the
//! two in separate files makes the "no kernel IPC needed" contract
//! obvious — `raxis initiative list` only ever opens `kernel.db`
//! READ-ONLY via `raxis_store::open_ro` and never auths.
//!
//! # Data sources (all read-only, no kernel IPC)
//!
//! * `<data_dir>/kernel.db` opened READ-ONLY via
//!   `raxis_store::open_ro`.
//!   - `views::initiatives::list_filtered` — bucketed list with the
//!     joined `quarantined` flag.
//!
//! # Filter
//!
//! `--state active|recovery|completed|quarantined|all`. Default is `active`
//! because the operator's recurring at-a-glance question is "what is
//! currently being worked on?" — listing every historical initiative
//! by default would bury the actionable rows. Spec §5.5.6b.
//!
//! # Exit code
//!
//! Always `0` on success; the only failure path is a `Policy(...)`
//! error from the underlying view (e.g. corrupted `kernel.db`).

use std::io::Write;

use raxis_store::open_ro;
use raxis_store::views::initiatives::{list_filtered, InitiativeListFilter, InitiativeListRow};

use crate::errors::CliError;
use crate::GlobalFlags;

/// How many rows the human and JSON renderers cap to by default.
/// Generous for v1 — most operator deployments will see far fewer
/// concurrent initiatives, but the cap keeps an accidental
/// `raxis initiative list --state all` on a long-running host from
/// flooding the TTY.
const DEFAULT_LIMIT: usize = 50;

// ────────────────────────────────────────────────────────────────────
// Entry point
// ────────────────────────────────────────────────────────────────────

pub fn run(flags: &GlobalFlags, args: &[String]) -> Result<(), CliError> {
    let opts = parse_args(args)?;

    let conn = open_ro(flags.data_dir())
        .map_err(|e| CliError::Policy(format!("kernel.db open failed: {e}")))?;
    let rows = list_filtered(&conn, opts.filter, opts.limit)
        .map_err(|e| CliError::Policy(format!("initiatives::list_filtered failed: {e}")))?;

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
struct InitiativeListOpts {
    filter: InitiativeListFilter,
    limit: usize,
    json: bool,
}

impl Default for InitiativeListOpts {
    fn default() -> Self {
        Self {
            filter: InitiativeListFilter::Active,
            limit: DEFAULT_LIMIT,
            json: false,
        }
    }
}

fn parse_args(args: &[String]) -> Result<InitiativeListOpts, CliError> {
    let mut opts = InitiativeListOpts::default();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--json" => opts.json = true,
            "--state" => {
                i += 1;
                let raw = args.get(i).ok_or_else(|| {
                    CliError::Usage(
                        "--state requires one of active|recovery|completed|quarantined|all"
                            .to_owned(),
                    )
                })?;
                opts.filter = parse_state(raw)?;
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
                    "unknown initiative list flag: {other:?} \
                     (try --state active|recovery|completed|quarantined|all, --limit N, --json, --help)"
                )));
            }
        }
        i += 1;
    }
    Ok(opts)
}

fn parse_state(raw: &str) -> Result<InitiativeListFilter, CliError> {
    // Case-insensitive: scripted callers tend to lowercase, but
    // keeping `Quarantined` capitalised is also accepted to match
    // the canonical FSM-state spelling in `kernel-store.md`.
    match raw.to_ascii_lowercase().as_str() {
        "active" => Ok(InitiativeListFilter::Active),
        "recovery" | "recoveryrequired" | "recovery-required" => Ok(InitiativeListFilter::Recovery),
        "completed" => Ok(InitiativeListFilter::Completed),
        "quarantined" => Ok(InitiativeListFilter::Quarantined),
        "all" => Ok(InitiativeListFilter::All),
        other => Err(CliError::Usage(format!(
            "unknown --state value {other:?} \
             (expected active|recovery|completed|quarantined|all)"
        ))),
    }
}

fn print_help() {
    println!(
        "raxis initiative list — list initiatives by bucket\n\
         \n\
         USAGE:\n\
         \traxis initiative list [--state active|recovery|completed|quarantined|all] [--limit N] [--json]\n\
         \n\
         FLAGS:\n\
         \t--state FILTER   Bucket to filter on (default: active).\n\
         \t                 - active      = in-flight FSM states (ApprovedPlan,\n\
         \t                                 Executing, Blocked). Draft is not in flight.\n\
         \t                 - recovery    = RecoveryRequired only; paused until an\n\
         \t                                 operator approves recovery or closes it.\n\
         \t                 - completed   = the Completed terminal only. Failed and\n\
         \t                                 Aborted are reachable via `--state all` or\n\
         \t                                 `raxis initiative show <id>`.\n\
         \t                 - quarantined = any initiative with a row in\n\
         \t                                 `initiative_quarantines`, regardless of\n\
         \t                                 FSM state.\n\
         \t                 - all         = no filter.\n\
         \t--limit N        Cap the number of rows shown (default: {DEFAULT_LIMIT}).\n\
         \t--json           Emit one JSON object instead of a human table.\n\
         "
    );
}

// ────────────────────────────────────────────────────────────────────
// Rendering — human
// ────────────────────────────────────────────────────────────────────

fn render_human<W: Write>(out: &mut W, filter: InitiativeListFilter, rows: &[InitiativeListRow]) {
    let _ = writeln!(
        out,
        "Initiatives (state={state}, {n} row{plural}):",
        state = filter_label(filter),
        n = rows.len(),
        plural = if rows.len() == 1 { "" } else { "s" },
    );
    if rows.is_empty() {
        let _ = writeln!(out, "  (no initiatives)");
        return;
    }

    let _ = writeln!(
        out,
        "  {iid:<26} {state:<14} {flag:<3} {created:>12} {plan:<12}",
        iid = "initiative_id",
        state = "state",
        flag = " Q ",
        created = "created (rel)",
        plan = "plan_sha256",
    );
    let now = unix_now_secs();
    for r in rows {
        let age = now.saturating_sub(r.initiative.created_at);
        let _ = writeln!(
            out,
            "  {iid:<26} {state:<14} {flag:<3} {created:>12} {plan:<12}",
            iid = truncate(&r.initiative.initiative_id, 26),
            state = truncate(&r.initiative.state, 14),
            flag = if r.quarantined { "[Q]" } else { "   " },
            created = format_secs_relative(age),
            plan = truncate(&r.initiative.plan_artifact_sha256, 12),
        );
    }
    if rows.iter().any(|r| r.quarantined) {
        let _ = writeln!(
            out,
            "  ([Q] = quarantined; \
             see `raxis initiative show <id>` for details.)",
        );
    }
}

// ────────────────────────────────────────────────────────────────────
// Rendering — JSON
// ────────────────────────────────────────────────────────────────────

fn render_json<W: Write>(out: &mut W, filter: InitiativeListFilter, rows: &[InitiativeListRow]) {
    let v = serde_json::json!({
        "filter": filter_label(filter),
        "count":  rows.len(),
        "rows":   rows.iter().map(|r| serde_json::json!({
            "initiative_id":        r.initiative.initiative_id,
            "state":                r.initiative.state,
            "plan_artifact_sha256": r.initiative.plan_artifact_sha256,
            "created_at":           r.initiative.created_at,
            "approved_at":          r.initiative.approved_at,
            "completed_at":         r.initiative.completed_at,
            "quarantined":          r.quarantined,
        })).collect::<Vec<_>>(),
    });
    let _ = serde_json::to_writer(&mut *out, &v);
    let _ = writeln!(out);
}

// ────────────────────────────────────────────────────────────────────
// Helpers
// ────────────────────────────────────────────────────────────────────

fn filter_label(f: InitiativeListFilter) -> &'static str {
    match f {
        InitiativeListFilter::All => "all",
        InitiativeListFilter::Active => "active",
        InitiativeListFilter::Recovery => "recovery",
        InitiativeListFilter::Completed => "completed",
        InitiativeListFilter::Quarantined => "quarantined",
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

/// Render a duration-in-seconds as a compact relative label
/// (`12s`, `5m`, `3h`, `2d`). Mirrors `commands::sessions::
/// format_secs_relative` so cross-command output reads the same.
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
    use raxis_store::views::initiatives::InitiativeRow;

    fn sample_row(id: &str, state: &str, quarantined: bool) -> InitiativeListRow {
        InitiativeListRow {
            initiative: InitiativeRow {
                initiative_id: id.to_owned(),
                state: state.to_owned(),
                plan_artifact_sha256: "deadbeefcafe".to_owned(),
                created_at: unix_now_secs().saturating_sub(45),
                approved_at: None,
                completed_at: None,
            },
            quarantined,
        }
    }

    // ── argument parsing ─────────────────────────────────────────

    #[test]
    fn parse_args_defaults_to_active_filter() {
        let o = parse_args(&[]).unwrap();
        assert_eq!(o.filter, InitiativeListFilter::Active);
        assert_eq!(o.limit, DEFAULT_LIMIT);
        assert!(!o.json);
    }

    #[test]
    fn parse_args_accepts_each_state_value_case_insensitively() {
        for (raw, want) in [
            ("active", InitiativeListFilter::Active),
            ("Active", InitiativeListFilter::Active),
            ("ACTIVE", InitiativeListFilter::Active),
            ("recovery", InitiativeListFilter::Recovery),
            ("RecoveryRequired", InitiativeListFilter::Recovery),
            ("recovery-required", InitiativeListFilter::Recovery),
            ("completed", InitiativeListFilter::Completed),
            ("quarantined", InitiativeListFilter::Quarantined),
            ("Quarantined", InitiativeListFilter::Quarantined),
            ("all", InitiativeListFilter::All),
        ] {
            let o = parse_args(&["--state".to_owned(), raw.to_owned()]).unwrap();
            assert_eq!(o.filter, want, "raw={raw:?}");
        }
    }

    #[test]
    fn parse_args_rejects_unknown_state() {
        let err = parse_args(&["--state".to_owned(), "bogus".to_owned()]).unwrap_err();
        assert!(matches!(err, CliError::Usage(_)));
        if let CliError::Usage(m) = err {
            assert!(
                m.contains("active|recovery|completed|quarantined|all"),
                "got: {m}"
            );
        }
    }

    #[test]
    fn parse_args_rejects_state_without_value() {
        let err = parse_args(&["--state".to_owned()]).unwrap_err();
        assert!(matches!(err, CliError::Usage(_)));
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
        if let CliError::Usage(m) = err {
            assert!(m.contains("unknown initiative list flag"), "got: {m}");
        }
    }

    #[test]
    fn parse_args_accepts_limit_and_json() {
        let o = parse_args(&["--limit".to_owned(), "10".to_owned(), "--json".to_owned()]).unwrap();
        assert_eq!(o.limit, 10);
        assert!(o.json);
    }

    // ── human render ─────────────────────────────────────────────

    #[test]
    fn render_human_with_no_rows_says_so() {
        let mut buf: Vec<u8> = Vec::new();
        render_human(&mut buf, InitiativeListFilter::Active, &[]);
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("(no initiatives)"), "got: {s}");
        assert!(s.contains("state=active"), "got: {s}");
    }

    #[test]
    fn render_human_renders_columns_and_quarantine_marker() {
        let mut buf: Vec<u8> = Vec::new();
        render_human(
            &mut buf,
            InitiativeListFilter::All,
            &[
                sample_row("init-1", "Executing", false),
                sample_row("init-2", "Blocked", true),
            ],
        );
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("init-1"), "got: {s}");
        assert!(s.contains("Executing"), "got: {s}");
        assert!(s.contains("init-2"), "got: {s}");
        assert!(s.contains("Blocked"), "got: {s}");
        assert!(s.contains("[Q]"), "quarantine marker MUST surface: {s}");
        assert!(
            s.contains("[Q] = quarantined"),
            "footer legend MUST surface when at least one row is quarantined: {s}",
        );
    }

    #[test]
    fn render_human_omits_quarantine_legend_when_no_q_rows() {
        let mut buf: Vec<u8> = Vec::new();
        render_human(
            &mut buf,
            InitiativeListFilter::Active,
            &[sample_row("init-1", "Executing", false)],
        );
        let s = String::from_utf8(buf).unwrap();
        assert!(
            !s.contains("[Q] = quarantined"),
            "legend MUST NOT surface when no row is quarantined: {s}",
        );
        assert!(!s.contains("[Q]"), "Q marker MUST NOT surface: {s}");
    }

    #[test]
    fn render_human_singular_plural_agreement() {
        let mut one_buf: Vec<u8> = Vec::new();
        render_human(
            &mut one_buf,
            InitiativeListFilter::Active,
            &[sample_row("init-1", "Executing", false)],
        );
        let one_s = String::from_utf8(one_buf).unwrap();
        assert!(
            one_s.contains("1 row)") && !one_s.contains("1 rows)"),
            "singular `row` (no `s`) for n==1: {one_s}",
        );
        let mut many_buf: Vec<u8> = Vec::new();
        render_human(
            &mut many_buf,
            InitiativeListFilter::Active,
            &[
                sample_row("init-1", "Executing", false),
                sample_row("init-2", "Blocked", false),
            ],
        );
        let many_s = String::from_utf8(many_buf).unwrap();
        assert!(
            many_s.contains("2 rows)"),
            "plural `rows` for n==2: {many_s}"
        );
    }

    // ── JSON render ──────────────────────────────────────────────

    #[test]
    fn render_json_emits_filter_count_and_rows() {
        let mut buf: Vec<u8> = Vec::new();
        render_json(
            &mut buf,
            InitiativeListFilter::Quarantined,
            &[sample_row("init-x", "Executing", true)],
        );
        let v: serde_json::Value = serde_json::from_slice(&buf).unwrap();
        assert_eq!(v["filter"], "quarantined");
        assert_eq!(v["count"], 1);
        let rows = v["rows"].as_array().unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["initiative_id"], "init-x");
        assert_eq!(rows[0]["state"], "Executing");
        assert_eq!(rows[0]["quarantined"], true);
        // Ensure every documented field is surfaced (the §5.5.6b spec
        // pins the JSON shape).
        for k in [
            "initiative_id",
            "state",
            "plan_artifact_sha256",
            "created_at",
            "approved_at",
            "completed_at",
            "quarantined",
        ] {
            assert!(rows[0].get(k).is_some(), "missing JSON key {k}");
        }
    }

    #[test]
    fn render_json_empty_rows_array_is_an_empty_list() {
        let mut buf: Vec<u8> = Vec::new();
        render_json(&mut buf, InitiativeListFilter::Active, &[]);
        let v: serde_json::Value = serde_json::from_slice(&buf).unwrap();
        assert_eq!(v["filter"], "active");
        assert_eq!(v["count"], 0);
        assert_eq!(v["rows"], serde_json::json!([]));
    }

    // ── helpers ──────────────────────────────────────────────────

    #[test]
    fn truncate_passes_short_strings_unchanged_and_ellipses_long_ones() {
        assert_eq!(truncate("abc", 5), "abc");
        assert_eq!(truncate("abcdefghij", 5), "abcd…");
    }

    #[test]
    fn format_secs_relative_uses_correct_unit_steps() {
        assert_eq!(format_secs_relative(0), "0s");
        assert_eq!(format_secs_relative(45), "45s");
        assert_eq!(format_secs_relative(120), "2m");
        assert_eq!(format_secs_relative(7_200), "2h");
        assert_eq!(format_secs_relative(2 * 86_400 + 3_600), "2d");
    }

    #[test]
    fn filter_label_is_lowercase_for_every_variant() {
        for v in [
            InitiativeListFilter::All,
            InitiativeListFilter::Active,
            InitiativeListFilter::Recovery,
            InitiativeListFilter::Completed,
            InitiativeListFilter::Quarantined,
        ] {
            let l = filter_label(v);
            assert_eq!(
                l,
                l.to_ascii_lowercase(),
                "filter_label MUST be lowercase: {l:?}"
            );
        }
    }
}

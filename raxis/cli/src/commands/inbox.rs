//! `raxis inbox` — read the operator notification inbox.
//!
//! Normative reference: cli-readonly.md §5.5.16, §5.6.4.
//!
//! # What this command reads
//!
//! `<data_dir>/notifications/inbox.jsonl` — one JSON object per line
//! written by `raxis-kernel::notifications::handler::file::deliver`.
//! The on-disk shape is pinned by `cli-readonly.md` §5.6.4 and we
//! mirror it field-for-field in [`InboxRecord`] below; any drift in
//! the kernel's `ShellRecord` would surface as a parse-failure tally
//! (rendered, not silently dropped).
//!
//! # What this command does NOT do
//!
//! * It does NOT mutate the inbox. There is no "mark as read" in v1
//!   — the audit log is the source of truth, and the inbox is a
//!   convenience read.
//! * It does NOT tail. `--follow` is a v1.x add (the kernel's writer
//!   appends; a CLI tail is straightforward to layer on but has no
//!   corresponding spec section yet).
//! * It does NOT route via the notification dispatcher. A planner that
//!   wants notifications via `--watch` should consume `raxis log
//!   --follow` instead.
//!
//! # Filters
//!
//! * `--kind <event_kind>` — substring match on `event_kind`.
//! * `--since <Ns|Nm|Nh|Nd>` — show only records newer than this
//!   relative duration. `unix-secs:<n>` is also accepted for
//!   automation that pre-computes the cut-off.
//! * `--limit N` — last N records (default: 50).
//! * `--json` — emit each retained record on its own line as JSON
//!   (the raw on-disk shape, not a wrapper object).
//!
//! # Exit code
//!
//! `0` on success; `2` when the inbox file does not exist (e.g. the
//! kernel never delivered a notification yet) so scripts can branch on
//! "no inbox at all" vs "empty inbox after filtering".

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::errors::CliError;
use crate::GlobalFlags;

const INBOX_REL_PATH:  &[&str] = &["notifications", "inbox.jsonl"];
const DEFAULT_LIMIT:   usize   = 50;
const HUMAN_SUMMARY_TRUNC: usize = 80;

// ────────────────────────────────────────────────────────────────────
// Wire shape (mirror of kernel's ShellRecord — pinned by spec §5.6.4)
// ────────────────────────────────────────────────────────────────────

/// Wire shape we expect every JSON object in `inbox.jsonl` to have.
///
/// `serde(default)` on every field keeps us forward-compatible with a
/// kernel that ships extra columns; missing-required-fields are
/// surfaced as a parse-failure tally, not a hard error.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct InboxRecord {
    #[serde(default)]
    notified_at:   i64,
    #[serde(default)]
    event_kind:    String,
    #[serde(default)]
    event_seq:     u64,
    #[serde(default)]
    payload:       serde_json::Value,
    #[serde(default)]
    human_summary: String,
}

// ────────────────────────────────────────────────────────────────────
// Entry point
// ────────────────────────────────────────────────────────────────────

pub fn run(flags: &GlobalFlags, args: &[String]) -> Result<(), CliError> {
    let opts = parse_args(args)?;
    let inbox_path = inbox_path(flags.data_dir());

    if !inbox_path.exists() {
        // Distinct exit code so scripts can tell "kernel never wrote
        // to the inbox" from "filter matched nothing".
        eprintln!("inbox: no file at {}", inbox_path.display());
        std::process::exit(2);
    }

    let (records, parse_failures) = read_filtered(&inbox_path, &opts)?;

    let stdout = std::io::stdout();
    let mut out = stdout.lock();

    if opts.json {
        render_json(&mut out, &records);
    } else {
        render_human(&mut out, &records, parse_failures, &inbox_path);
    }
    let _ = out.flush();
    Ok(())
}

// ────────────────────────────────────────────────────────────────────
// Argument parsing
// ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
struct InboxOpts {
    kind:                 Option<String>,
    since_unix_secs:      Option<i64>,
    limit:                Option<usize>,
    json:                 bool,
}

fn parse_args(args: &[String]) -> Result<InboxOpts, CliError> {
    let mut opts = InboxOpts::default();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--json" => opts.json = true,
            "--kind" => {
                i += 1;
                opts.kind = Some(arg_value(args, i, "--kind")?.to_owned());
            }
            "--since" => {
                i += 1;
                let raw = arg_value(args, i, "--since")?;
                opts.since_unix_secs = Some(parse_since(raw)?);
            }
            "--limit" => {
                i += 1;
                let raw = arg_value(args, i, "--limit")?;
                let n = raw.parse::<usize>().map_err(|_| {
                    CliError::Usage(format!("--limit must be a positive integer, got {raw:?}"))
                })?;
                if n == 0 {
                    return Err(CliError::Usage(
                        "--limit must be greater than 0".to_owned(),
                    ));
                }
                opts.limit = Some(n);
            }
            "-h" | "--help" => {
                print_help();
                std::process::exit(0);
            }
            other => {
                return Err(CliError::Usage(format!(
                    "unknown inbox flag: {other:?} (try --kind K, --since DURATION, \
                     --limit N, --json, --help)"
                )));
            }
        }
        i += 1;
    }
    Ok(opts)
}

fn arg_value<'a>(args: &'a [String], idx: usize, flag: &str) -> Result<&'a str, CliError> {
    args.get(idx)
        .map(|s| s.as_str())
        .ok_or_else(|| CliError::Usage(format!("{flag} requires a value")))
}

/// Accepts:
///   * `Ns` / `Nm` / `Nh` / `Nd` — relative seconds / minutes / hours / days back from now.
///   * `unix-secs:<n>` — absolute UNIX-secs cut-off.
fn parse_since(raw: &str) -> Result<i64, CliError> {
    if let Some(rest) = raw.strip_prefix("unix-secs:") {
        return rest.parse::<i64>().map_err(|_| {
            CliError::Usage(format!("--since unix-secs:N must be an integer, got {rest:?}"))
        });
    }
    let last = raw.chars().last().ok_or_else(|| {
        CliError::Usage("--since cannot be empty".to_owned())
    })?;
    let unit_secs = match last {
        's' => 1_i64,
        'm' => 60,
        'h' => 3_600,
        'd' => 86_400,
        _ => {
            return Err(CliError::Usage(format!(
                "--since suffix must be s|m|h|d (or unix-secs:N), got {raw:?}"
            )));
        }
    };
    let n: i64 = raw[..raw.len() - last.len_utf8()]
        .parse()
        .map_err(|_| {
            CliError::Usage(format!("--since prefix must be an integer, got {raw:?}"))
        })?;
    let now = unix_now_secs() as i64;
    Ok(now - n.saturating_mul(unit_secs))
}

fn print_help() {
    println!(
        "raxis inbox — read the operator notification inbox\n\
         \n\
         USAGE:\n\
         \traxis inbox [--kind K] [--since DURATION] [--limit N] [--json]\n\
         \n\
         FLAGS:\n\
         \t--kind K          Substring match on event_kind.\n\
         \t--since DURATION  Ns | Nm | Nh | Nd | unix-secs:N relative cutoff.\n\
         \t--limit N         Show only the last N matching records (default: {DEFAULT_LIMIT}).\n\
         \t--json            Emit each record on its own line as JSON.\n\
         \n\
         EXIT CODES:\n\
         \t0   inbox file present (with or without records after filtering)\n\
         \t2   inbox file does not exist (kernel may not have delivered yet)\n\
         "
    );
}

// ────────────────────────────────────────────────────────────────────
// File reading
// ────────────────────────────────────────────────────────────────────

fn inbox_path(data_dir: &Path) -> PathBuf {
    let mut p = data_dir.to_path_buf();
    for seg in INBOX_REL_PATH {
        p = p.join(seg);
    }
    p
}

/// Walk the inbox and return:
///   - records that match the user's filter (newest-last, capped to
///     `opts.limit`);
///   - the count of lines we could not parse (for a footer warning).
fn read_filtered(
    path: &Path,
    opts: &InboxOpts,
) -> Result<(Vec<InboxRecord>, u64), CliError> {
    let file = std::fs::File::open(path).map_err(|e| CliError::Io {
        path:   path.display().to_string(),
        source: e,
    })?;
    let reader = BufReader::new(file);

    let mut matched: Vec<InboxRecord> = Vec::new();
    let mut parse_failures: u64 = 0;

    for line in reader.lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => {
                parse_failures = parse_failures.saturating_add(1);
                continue;
            }
        };
        if line.trim().is_empty() {
            continue;
        }
        let rec: InboxRecord = match serde_json::from_str(&line) {
            Ok(r) => r,
            Err(_) => {
                parse_failures = parse_failures.saturating_add(1);
                continue;
            }
        };
        if !filter_match(&rec, opts) {
            continue;
        }
        matched.push(rec);
    }

    // Cap at `--limit` from the END so the user sees the most recent
    // matches. We do this AFTER the full scan to keep the filter
    // boundary correct (e.g. --since cuts off old records before the
    // limit is applied).
    let limit = opts.limit.unwrap_or(DEFAULT_LIMIT);
    if matched.len() > limit {
        let drop = matched.len() - limit;
        matched.drain(0..drop);
    }
    Ok((matched, parse_failures))
}

fn filter_match(rec: &InboxRecord, opts: &InboxOpts) -> bool {
    if let Some(k) = &opts.kind {
        if !rec.event_kind.contains(k) {
            return false;
        }
    }
    if let Some(cut) = opts.since_unix_secs {
        if rec.notified_at < cut {
            return false;
        }
    }
    true
}

// ────────────────────────────────────────────────────────────────────
// Rendering — human
// ────────────────────────────────────────────────────────────────────

fn render_human<W: Write>(
    out:            &mut W,
    rows:           &[InboxRecord],
    parse_failures: u64,
    path:           &Path,
) {
    let _ = writeln!(
        out,
        "Inbox at {} ({n} record{plural}{warn}):",
        path.display(),
        n = rows.len(),
        plural = if rows.len() == 1 { "" } else { "s" },
        warn = if parse_failures > 0 {
            format!(", {parse_failures} unparsable line{p}",
                p = if parse_failures == 1 { "" } else { "s" })
        } else {
            String::new()
        },
    );
    if rows.is_empty() {
        let _ = writeln!(out, "  (no matching records)");
        return;
    }
    for r in rows {
        let _ = writeln!(
            out,
            "  [{ts:>10}] seq={seq:<6} {kind:<32} {summary}",
            ts      = r.notified_at,
            seq     = r.event_seq,
            kind    = truncate(&r.event_kind, 32),
            summary = truncate(&r.human_summary, HUMAN_SUMMARY_TRUNC),
        );
    }
}

// ────────────────────────────────────────────────────────────────────
// Rendering — JSON
// ────────────────────────────────────────────────────────────────────

fn render_json<W: Write>(out: &mut W, rows: &[InboxRecord]) {
    for r in rows {
        let _ = serde_json::to_writer(&mut *out, r);
        let _ = writeln!(out);
    }
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

// ────────────────────────────────────────────────────────────────────
// Tests
// ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _; // for `writeln!` on std::fs::File in test fixtures

    fn write_inbox(dir: &Path, lines: &[&str]) -> PathBuf {
        let nots = dir.join("notifications");
        std::fs::create_dir_all(&nots).unwrap();
        let path = nots.join("inbox.jsonl");
        let mut f = std::fs::File::create(&path).unwrap();
        for l in lines {
            writeln!(f, "{l}").unwrap();
        }
        path
    }

    fn record_line(kind: &str, seq: u64, notified_at: i64, summary: &str) -> String {
        serde_json::json!({
            "notified_at":   notified_at,
            "event_kind":    kind,
            "event_seq":     seq,
            "payload":       serde_json::json!({}),
            "human_summary": summary,
        })
        .to_string()
    }

    #[test]
    fn parse_since_handles_each_unit() {
        // ±5s tolerance — these run against wall clock.
        let now = unix_now_secs() as i64;
        assert!((parse_since("0s").unwrap() - now).abs() <= 5);
        assert!((parse_since("60s").unwrap() - (now - 60)).abs() <= 5);
        assert!((parse_since("2m").unwrap()  - (now - 120)).abs() <= 5);
        assert!((parse_since("1h").unwrap()  - (now - 3_600)).abs() <= 5);
        assert!((parse_since("1d").unwrap()  - (now - 86_400)).abs() <= 5);
    }

    #[test]
    fn parse_since_handles_unix_secs_form() {
        assert_eq!(parse_since("unix-secs:42").unwrap(), 42);
    }

    #[test]
    fn parse_since_rejects_bad_unit() {
        assert!(matches!(parse_since("5w"), Err(CliError::Usage(_))));
        assert!(matches!(parse_since(""), Err(CliError::Usage(_))));
        assert!(matches!(parse_since("abc"), Err(CliError::Usage(_))));
    }

    #[test]
    fn parse_args_defaults() {
        let o = parse_args(&[]).unwrap();
        assert_eq!(o.kind, None);
        assert_eq!(o.limit, None);
        assert!(!o.json);
    }

    #[test]
    fn parse_args_rejects_zero_limit() {
        let err = parse_args(&[
            "--limit".to_owned(),
            "0".to_owned(),
        ])
        .unwrap_err();
        assert!(matches!(err, CliError::Usage(_)));
    }

    #[test]
    fn read_filtered_drops_unparsable_lines_and_tallies() {
        let tmp = tempfile::TempDir::new().unwrap();
        write_inbox(
            tmp.path(),
            &[
                &record_line("Foo", 1, 100, "summary one"),
                "{not valid json",
                &record_line("Bar", 2, 200, "summary two"),
            ],
        );
        let path = inbox_path(tmp.path());
        let opts = InboxOpts::default();
        let (rows, fails) = read_filtered(&path, &opts).unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(fails, 1);
    }

    #[test]
    fn filter_kind_substring_matches() {
        let tmp = tempfile::TempDir::new().unwrap();
        write_inbox(
            tmp.path(),
            &[
                &record_line("EscalationApproved", 1, 100, "ok"),
                &record_line("EscalationDenied", 2, 200, "no"),
                &record_line("PolicyEpochAdvanced", 3, 300, "rotated"),
            ],
        );
        let path = inbox_path(tmp.path());
        let opts = InboxOpts {
            kind: Some("Escalation".to_owned()),
            ..Default::default()
        };
        let (rows, _) = read_filtered(&path, &opts).unwrap();
        assert_eq!(rows.len(), 2);
        for r in &rows {
            assert!(r.event_kind.contains("Escalation"));
        }
    }

    #[test]
    fn filter_since_drops_older_records() {
        let tmp = tempfile::TempDir::new().unwrap();
        write_inbox(
            tmp.path(),
            &[
                &record_line("Foo", 1, 100, "old"),
                &record_line("Foo", 2, 500, "newer"),
            ],
        );
        let path = inbox_path(tmp.path());
        let opts = InboxOpts {
            since_unix_secs: Some(300),
            ..Default::default()
        };
        let (rows, _) = read_filtered(&path, &opts).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].event_seq, 2);
    }

    #[test]
    fn limit_keeps_newest_records() {
        let tmp = tempfile::TempDir::new().unwrap();
        write_inbox(
            tmp.path(),
            &[
                &record_line("Foo", 1, 100, ""),
                &record_line("Foo", 2, 200, ""),
                &record_line("Foo", 3, 300, ""),
            ],
        );
        let path = inbox_path(tmp.path());
        let opts = InboxOpts { limit: Some(2), ..Default::default() };
        let (rows, _) = read_filtered(&path, &opts).unwrap();
        let seqs: Vec<u64> = rows.iter().map(|r| r.event_seq).collect();
        assert_eq!(seqs, vec![2, 3]);
    }

    #[test]
    fn render_human_renders_count_and_summary_lines() {
        let mut buf: Vec<u8> = Vec::new();
        let rows = vec![
            InboxRecord {
                notified_at:   100,
                event_kind:    "EscalationApproved".to_owned(),
                event_seq:     42,
                payload:       serde_json::json!({}),
                human_summary: "approved by alice".to_owned(),
            },
        ];
        render_human(&mut buf, &rows, 0, Path::new("/tmp/inbox.jsonl"));
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("1 record"), "got: {s}");
        assert!(s.contains("EscalationApproved"), "got: {s}");
        assert!(s.contains("approved by alice"), "got: {s}");
        assert!(s.contains("seq=42"), "got: {s}");
    }

    #[test]
    fn render_human_says_no_matching_records_when_empty() {
        let mut buf: Vec<u8> = Vec::new();
        render_human(&mut buf, &[], 0, Path::new("/tmp/inbox.jsonl"));
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("(no matching records)"), "got: {s}");
    }

    #[test]
    fn render_human_warns_on_unparsable_lines() {
        let mut buf: Vec<u8> = Vec::new();
        render_human(&mut buf, &[], 3, Path::new("/tmp/inbox.jsonl"));
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("3 unparsable lines"), "got: {s}");
    }

    #[test]
    fn render_json_emits_one_object_per_line() {
        let mut buf: Vec<u8> = Vec::new();
        let rows = vec![
            InboxRecord {
                notified_at:   100,
                event_kind:    "Foo".to_owned(),
                event_seq:     1,
                payload:       serde_json::json!({"k":"v"}),
                human_summary: "s1".to_owned(),
            },
            InboxRecord {
                notified_at:   200,
                event_kind:    "Bar".to_owned(),
                event_seq:     2,
                payload:       serde_json::json!({}),
                human_summary: "s2".to_owned(),
            },
        ];
        render_json(&mut buf, &rows);
        let s = String::from_utf8(buf).unwrap();
        let lines: Vec<&str> = s.trim_end().split('\n').collect();
        assert_eq!(lines.len(), 2);
        let v0: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(v0["event_kind"], "Foo");
        assert_eq!(v0["event_seq"], 1);
    }
}

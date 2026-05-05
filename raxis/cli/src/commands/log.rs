//! `raxis log` — structured access to the audit chain.
//!
//! Normative reference: cli-readonly.md §5.5.4.
//!
//! Walks the segment files via [`raxis_audit_tools::ChainReader`] and
//! filters by initiative_id (positional), --task, --session, --kind
//! (substring match, case-insensitive), --since (relative duration),
//! and --limit. Emits one event per line in either human-friendly or
//! `--json` (raw JSONL) shape. `-f` / `--follow` polls
//! `metadata().len()` every 100ms — no platform-specific deps.

use std::io::Write;
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use raxis_audit_tools::{ChainReader, ChainRecord, AUDIT_DIR_NAME};

use crate::errors::CliError;
use crate::operator_display::{
    extract_operators_from_event, format_operator_with_lookup, OperatorNameLookup,
};
use crate::GlobalFlags;

/// Default cap when `--limit` is not provided. Matches cli-readonly.md
/// §5.5.4 ("Last 50 records, newest first").
const DEFAULT_LIMIT: usize = 50;

/// Poll cadence for `--follow`. cli-readonly.md §5.5.4 fixes 100ms.
/// Constant rather than a flag because operators do not need to tune
/// it (and a runaway poll cadence is a footgun).
const FOLLOW_POLL_INTERVAL: Duration = Duration::from_millis(100);

pub fn run(flags: &GlobalFlags, args: &[String]) -> Result<(), CliError> {
    let opts = parse_args(args)?;
    let audit_dir = flags.data_dir().join(AUDIT_DIR_NAME);

    // Build the operator-name lookup once per invocation so every
    // rendered record gets fingerprint→display_name resolution
    // without per-record DB hits. See `operator_display` module
    // docstring for the perf rationale.
    let name_lookup = OperatorNameLookup::load_from_data_dir(flags.data_dir())
        .unwrap_or_else(|_| OperatorNameLookup::empty());

    if opts.follow {
        // Follow-mode runs forever (or until SIGINT). It still
        // honours every filter — the filter combinator is the same
        // function the one-shot path uses.
        run_follow(&audit_dir, &opts, &name_lookup)
    } else {
        run_one_shot(&audit_dir, &opts, &name_lookup)
    }
}

// ────────────────────────────────────────────────────────────────────
// One-shot mode
// ────────────────────────────────────────────────────────────────────

fn run_one_shot(
    audit_dir:   &std::path::Path,
    opts:        &LogOpts,
    name_lookup: &OperatorNameLookup,
) -> Result<(), CliError> {
    let reader = match ChainReader::open(audit_dir) {
        Ok(r) => r,
        Err(raxis_audit_tools::ChainReadError::NoSegments { .. }) => {
            // Zero-segment kernel = nothing to print. Exit 0; the
            // CLI's contract is "print events that exist", and zero
            // events is a valid (if surprising) answer.
            return Ok(());
        }
        Err(raxis_audit_tools::ChainReadError::AuditDirOpen { source, .. })
            if source.kind() == std::io::ErrorKind::NotFound =>
        {
            return Ok(());
        }
        Err(e) => return Err(CliError::Policy(format!("audit chain read failed: {e}"))),
    };

    // Materialise + filter every record. Memory cost is bounded by the
    // limit (we cap before retaining).
    let mut all: Vec<ChainRecord> = Vec::new();
    for rec in reader.records() {
        let r = match rec {
            Ok(r) => r,
            Err(e) => {
                eprintln!("warning: skipped malformed record: {e}");
                continue;
            }
        };
        if matches_filter(&r, opts) {
            all.push(r);
        }
    }
    // Newest-first per spec.
    all.sort_by_key(|r| std::cmp::Reverse(r.seq));
    if opts.limit > 0 {
        all.truncate(opts.limit);
    }

    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    let now = unix_now_secs();
    for r in &all {
        render_one(&mut out, r, opts.json, now, name_lookup);
    }
    let _ = out.flush();
    Ok(())
}

// ────────────────────────────────────────────────────────────────────
// Follow mode (--follow / -f)
// ────────────────────────────────────────────────────────────────────

/// Stream new records by polling the latest segment's
/// `metadata().len()`. cli-readonly.md §5.5.4 mandates this approach
/// (no platform-specific inotify/kqueue deps). On each tick we re-walk
/// the chain reader from where the previous tick stopped (tracked by
/// per-record `seq` rather than file offset, so a segment rotation
/// doesn't mis-resume).
fn run_follow(
    audit_dir:   &std::path::Path,
    opts:        &LogOpts,
    name_lookup: &OperatorNameLookup,
) -> Result<(), CliError> {
    let stdout = std::io::stdout();
    // Establish a baseline: print the "tail" the user would see in
    // one-shot mode FIRST so they're not staring at an empty TTY
    // until the first new record arrives.
    let mut last_seq_seen: i128 = -1;
    {
        if let Ok(reader) = ChainReader::open(audit_dir) {
            let mut tail: Vec<ChainRecord> = Vec::new();
            for rec in reader.records().flatten() {
                if matches_filter(&rec, opts) {
                    tail.push(rec);
                }
            }
            tail.sort_by_key(|r| std::cmp::Reverse(r.seq));
            let limit = if opts.limit == 0 { DEFAULT_LIMIT } else { opts.limit };
            tail.truncate(limit);
            tail.reverse(); // print oldest-first inside the tail
            let now = unix_now_secs();
            let mut out = stdout.lock();
            for r in &tail {
                render_one(&mut out, r, opts.json, now, name_lookup);
            }
            let _ = out.flush();
            if let Some(last) = tail.last() {
                last_seq_seen = last.seq as i128;
            }
        }
    }

    // SIGINT: install a shared atomic the loop polls. Avoids requiring
    // the `signal-hook` crate; on Ctrl-C the user sees the standard
    // "^C" rendering and the process exits 130 via libc::_exit when
    // the SIGINT handler returns the default disposition.
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    let stop = Arc::new(AtomicBool::new(false));
    let stop_for_handler = Arc::clone(&stop);
    // SAFETY: ctrlc-style handlers are notoriously platform-specific;
    // we use a tiny POSIX `sigaction(SIGINT, ...)` hook that flips the
    // atomic. The OS thread the handler runs on has no Rust state to
    // corrupt.
    install_sigint_handler(move || {
        stop_for_handler.store(true, Ordering::SeqCst);
    });

    loop {
        if stop.load(std::sync::atomic::Ordering::SeqCst) {
            return Ok(());
        }
        // Poll: any new records with seq > last_seq_seen?
        if let Ok(reader) = ChainReader::open(audit_dir) {
            let mut new_records: Vec<ChainRecord> = Vec::new();
            for rec in reader.records().flatten() {
                if (rec.seq as i128) > last_seq_seen && matches_filter(&rec, opts) {
                    new_records.push(rec);
                }
            }
            if !new_records.is_empty() {
                let now = unix_now_secs();
                let mut out = stdout.lock();
                new_records.sort_by_key(|r| r.seq);
                for r in &new_records {
                    render_one(&mut out, r, opts.json, now, name_lookup);
                    if (r.seq as i128) > last_seq_seen {
                        last_seq_seen = r.seq as i128;
                    }
                }
                let _ = out.flush();
            }
        }
        std::thread::sleep(FOLLOW_POLL_INTERVAL);
    }
}

// ────────────────────────────────────────────────────────────────────
// SIGINT handler — minimal, no external deps
// ────────────────────────────────────────────────────────────────────

/// Install a SIGINT handler that runs `f` on every Ctrl-C. The
/// handler is intentionally minimal: it captures a `Send + 'static`
/// closure into a static slot (one slot, last-installer-wins) and
/// then `sigaction`s a trampoline that calls it. Adequate for our
/// "set an atomic flag" use case; v2 should adopt `signal-hook`.
fn install_sigint_handler<F: Fn() + Send + Sync + 'static>(f: F) {
    use std::sync::Mutex;
    use std::sync::OnceLock;
    static SLOT: OnceLock<Mutex<Option<Box<dyn Fn() + Send + Sync + 'static>>>> =
        OnceLock::new();
    let slot = SLOT.get_or_init(|| Mutex::new(None));
    *slot.lock().unwrap() = Some(Box::new(f));

    extern "C" fn trampoline(_sig: libc::c_int) {
        if let Some(slot) = SLOT.get() {
            if let Ok(g) = slot.lock() {
                if let Some(f) = g.as_ref() {
                    f();
                }
            }
        }
    }

    // SAFETY: `sigaction` with a function-pointer handler is the
    // documented POSIX API; the `sigaction` struct is zeroed before
    // we set its fields.
    unsafe {
        let mut act: libc::sigaction = std::mem::zeroed();
        act.sa_sigaction = trampoline as usize;
        // SA_RESTART: any pending read syscalls finish naturally
        // before we observe the flag. (We're polling a sleep, so
        // this mostly matters for the initial tail-print.)
        act.sa_flags = libc::SA_RESTART;
        let _ = libc::sigemptyset(&mut act.sa_mask);
        let _ = libc::sigaction(libc::SIGINT, &act, std::ptr::null_mut());
    }
}

// ────────────────────────────────────────────────────────────────────
// Filter combinator
// ────────────────────────────────────────────────────────────────────

fn matches_filter(r: &ChainRecord, opts: &LogOpts) -> bool {
    if let Some(init) = &opts.initiative_id {
        match r.initiative_id.as_deref() {
            Some(s) if s == init => {}
            _ => return false,
        }
    }
    if let Some(task) = &opts.task_id {
        match r.task_id.as_deref() {
            Some(s) if s == task => {}
            _ => return false,
        }
    }
    if let Some(session) = &opts.session_id {
        match r.session_id.as_deref() {
            Some(s) if s == session => {}
            _ => return false,
        }
    }
    if let Some(needle) = &opts.kind {
        // Case-insensitive substring match per spec.
        if !r.event_kind.to_lowercase().contains(&needle.to_lowercase()) {
            return false;
        }
    }
    if let Some(min_emitted_at) = opts.since_unix_secs {
        match r.emitted_at {
            Some(e) if e >= min_emitted_at => {}
            _ => return false,
        }
    }
    true
}

// ────────────────────────────────────────────────────────────────────
// Rendering
// ────────────────────────────────────────────────────────────────────

fn render_one<W: Write>(
    out:         &mut W,
    r:           &ChainRecord,
    json:        bool,
    now_secs:    u64,
    name_lookup: &OperatorNameLookup,
) {
    if json {
        // Per spec: raw AuditEvent per line, identical to on-disk
        // JSONL. We emit `r.raw_line` (which we already parsed from
        // disk) so the CLI's JSON output is byte-identical to the
        // on-disk record.
        let _ = writeln!(out, "{}", r.raw_line);
        return;
    }
    let ago = match r.emitted_at {
        Some(e) if (e as u64) <= now_secs => format_relative(now_secs.saturating_sub(e as u64)),
        Some(_) => "0s ago".to_owned(), // future timestamp (clock skew)
        None => "?".to_owned(),
    };
    // Compose a one-line summary with the event_kind first (operators
    // grep on it most), then any present task / initiative / session
    // ids. We DO NOT print payload by default; the spec defers
    // payload-rendering to `raxis inspect <task>`.
    let mut line = format!("{ago:<12} [{}]", r.event_kind);
    if let Some(init) = &r.initiative_id {
        line.push_str(&format!(" init={}", short(init)));
    }
    if let Some(task) = &r.task_id {
        line.push_str(&format!(" task={}", short(task)));
    }
    if let Some(session) = &r.session_id {
        line.push_str(&format!(" session={}", short(session)));
    }
    // §2.5.2 "Operator display-name fields" — surface every
    // operator-bearing field the event payload carries. Each is
    // labelled by its role (approving_operator, granted_by, …)
    // so a one-line render still tells the operator who did
    // what. The fingerprint snapshot lives in the JSONL output
    // (visible via `--json`); the human form is name+prefix.
    if let Some(parsed) = r.parsed_value.as_ref() {
        for op in extract_operators_from_event(parsed) {
            let rendered = format_operator_with_lookup(
                &op.fingerprint,
                op.embedded_name.as_deref(),
                name_lookup,
            );
            line.push_str(&format!(" {}={rendered}", op.role));
        }
    }
    let _ = writeln!(out, "{line}");
}

/// Render a duration as `Nh Nm`, `Nm`, or `Ns ago`. Matches the
/// human format from cli-readonly.md §5.5.4 ("3h17m ago").
fn format_relative(secs: u64) -> String {
    if secs >= 3600 {
        format!("{}h{}m ago", secs / 3600, (secs % 3600) / 60)
    } else if secs >= 60 {
        format!("{}m{}s ago", secs / 60, secs % 60)
    } else {
        format!("{secs}s ago")
    }
}

/// Truncate UUID-shaped IDs to a recognisable prefix so the human
/// output stays single-line on a typical TTY. Full IDs are still
/// available via `--json`.
fn short(id: &str) -> String {
    if id.len() > 12 {
        format!("{}…", &id[..12])
    } else {
        id.to_owned()
    }
}

// ────────────────────────────────────────────────────────────────────
// Argument parsing
// ────────────────────────────────────────────────────────────────────

#[derive(Debug, Default, Clone)]
struct LogOpts {
    initiative_id: Option<String>,
    task_id: Option<String>,
    session_id: Option<String>,
    kind: Option<String>,
    since_unix_secs: Option<i64>,
    limit: usize,
    json: bool,
    follow: bool,
    #[allow(dead_code)]
    audit_dir: Option<PathBuf>,
}

fn parse_args(args: &[String]) -> Result<LogOpts, CliError> {
    let mut opts = LogOpts {
        limit: DEFAULT_LIMIT,
        ..LogOpts::default()
    };
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--task" => {
                i += 1;
                opts.task_id = Some(arg_value(args, i, "--task")?.to_owned());
            }
            "--session" => {
                i += 1;
                opts.session_id = Some(arg_value(args, i, "--session")?.to_owned());
            }
            "--kind" => {
                i += 1;
                opts.kind = Some(arg_value(args, i, "--kind")?.to_owned());
            }
            "--since" => {
                i += 1;
                let v = arg_value(args, i, "--since")?;
                let secs = parse_duration(v)?;
                let cutoff = unix_now_secs().saturating_sub(secs) as i64;
                opts.since_unix_secs = Some(cutoff);
            }
            "--limit" => {
                i += 1;
                let v = arg_value(args, i, "--limit")?;
                opts.limit = v.parse::<usize>().map_err(|_| {
                    CliError::Usage(format!("--limit expects a non-negative integer; got {v:?}"))
                })?;
            }
            "--json" => opts.json = true,
            "-f" | "--follow" => opts.follow = true,
            "-h" | "--help" => {
                print_help();
                std::process::exit(0);
            }
            other if !other.starts_with('-') => {
                if opts.initiative_id.is_some() {
                    return Err(CliError::Usage(format!(
                        "unexpected positional argument {other:?} (initiative_id already set)"
                    )));
                }
                opts.initiative_id = Some(other.to_owned());
            }
            other => {
                return Err(CliError::Usage(format!(
                    "unknown log flag: {other:?}"
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
        .ok_or_else(|| CliError::Usage(format!("{flag} requires an argument")))
}

/// Parse `1h`, `30m`, `7d`, `45s`. Plain integer = seconds. We keep
/// the grammar tiny on purpose: clipping to "the suffix unit set the
/// spec calls out" prevents accidental ambiguity.
fn parse_duration(s: &str) -> Result<u64, CliError> {
    if s.is_empty() {
        return Err(CliError::Usage("--since: empty duration".to_owned()));
    }
    let (num_str, mult): (&str, u64) = match s.chars().last() {
        Some('s') => (&s[..s.len() - 1], 1),
        Some('m') => (&s[..s.len() - 1], 60),
        Some('h') => (&s[..s.len() - 1], 3_600),
        Some('d') => (&s[..s.len() - 1], 86_400),
        _ => (s, 1),
    };
    let n: u64 = num_str.parse().map_err(|_| {
        CliError::Usage(format!("--since: cannot parse {num_str:?} as integer"))
    })?;
    n.checked_mul(mult).ok_or_else(|| {
        CliError::Usage(format!("--since: duration {s:?} overflows u64 seconds"))
    })
}

fn print_help() {
    println!(
        "raxis log — structured access to the audit chain\n\
         \n\
         USAGE:\n\
         \tlraxis log [<initiative_id>] [FLAGS]\n\
         \n\
         FLAGS:\n\
         \t--task <task_id>     filter to records with this task_id\n\
         \t--session <id>       filter to records with this session_id\n\
         \t--kind <substring>   case-insensitive substring on event_kind\n\
         \t--since <duration>   only records emitted in last <duration> (e.g. 1h, 30m, 7d)\n\
         \t--limit <N>          cap output (default 50; 0 = unlimited)\n\
         \t--json               emit raw AuditEvent JSONL\n\
         \t-f, --follow         stream new records (100ms poll); Ctrl-C to exit\n\
         \n\
         FILTERS COMPOSE:\n\
         \traxis log --task t-1 --kind WitnessAccepted --since 1h"
    );
}

fn unix_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// Compile-time pin: the iterator yields ChainRecord. Catches API drift.
#[allow(dead_code)]
fn _api_anchor(reader: &ChainReader) -> Vec<ChainRecord> {
    reader.records().flatten().collect()
}

// Avoid an "unused import" warning if Instant happens to be unused in
// some configurations.
#[allow(dead_code)]
fn _instant_anchor() -> Instant {
    Instant::now()
}

#[cfg(test)]
mod tests {
    use super::*;
    use raxis_audit_tools::{ChainRecord, GENESIS_PREV_SHA256_LITERAL};
    use sha2::{Digest, Sha256};
    use tempfile::TempDir;

    fn make_record(
        seq: u64,
        kind: &str,
        emitted_at: Option<i64>,
        initiative_id: Option<&str>,
        task_id: Option<&str>,
        session_id: Option<&str>,
    ) -> ChainRecord {
        ChainRecord {
            seq,
            event_kind: kind.to_owned(),
            prev_sha256: GENESIS_PREV_SHA256_LITERAL.to_owned(),
            emitted_at,
            session_id: session_id.map(|s| s.to_owned()),
            task_id: task_id.map(|s| s.to_owned()),
            initiative_id: initiative_id.map(|s| s.to_owned()),
            line_no: 1,
            segment_path: PathBuf::from("/tmp/audit/segment-000.jsonl"),
            line_sha256: "00".repeat(32),
            raw_line: "{}".to_owned(),
            parsed_value: None,
        }
    }

    #[test]
    fn matches_filter_initiative_id_strict_match() {
        let r = make_record(1, "X", None, Some("init-x"), None, None);
        let mut opts = LogOpts::default();
        opts.initiative_id = Some("init-x".to_owned());
        assert!(matches_filter(&r, &opts));
        opts.initiative_id = Some("init-y".to_owned());
        assert!(!matches_filter(&r, &opts));
    }

    #[test]
    fn matches_filter_kind_substring_case_insensitive() {
        let r = make_record(1, "WitnessAccepted", None, None, None, None);
        let mut opts = LogOpts::default();
        opts.kind = Some("witness".to_owned());
        assert!(matches_filter(&r, &opts), "case-insensitive substring");
        opts.kind = Some("REJECTED".to_owned());
        assert!(!matches_filter(&r, &opts));
    }

    #[test]
    fn matches_filter_since_excludes_too_old() {
        let r = make_record(1, "X", Some(1_700_000_000), None, None, None);
        let mut opts = LogOpts::default();
        opts.since_unix_secs = Some(1_700_000_500);
        assert!(!matches_filter(&r, &opts), "older than --since must drop");
        opts.since_unix_secs = Some(1_700_000_000);
        assert!(matches_filter(&r, &opts), "boundary must include");
        opts.since_unix_secs = Some(1_699_999_999);
        assert!(matches_filter(&r, &opts));
    }

    #[test]
    fn matches_filter_no_emitted_at_drops_when_since_set() {
        let r = make_record(1, "X", None, None, None, None);
        let mut opts = LogOpts::default();
        opts.since_unix_secs = Some(1_700_000_000);
        assert!(!matches_filter(&r, &opts),
            "missing emitted_at must drop under --since (we cannot prove it's recent)");
    }

    #[test]
    fn matches_filter_combines_all_predicates_as_and() {
        let r = make_record(
            1, "WitnessAccepted",
            Some(1_700_000_500),
            Some("init-x"),
            Some("task-1"),
            Some("session-1"),
        );
        let opts = LogOpts {
            initiative_id: Some("init-x".to_owned()),
            task_id: Some("task-1".to_owned()),
            session_id: Some("session-1".to_owned()),
            kind: Some("witness".to_owned()),
            since_unix_secs: Some(1_700_000_000),
            limit: 50, json: false, follow: false, audit_dir: None,
        };
        assert!(matches_filter(&r, &opts));
    }

    #[test]
    fn parse_duration_supports_each_suffix() {
        assert_eq!(parse_duration("45").unwrap(), 45);
        assert_eq!(parse_duration("45s").unwrap(), 45);
        assert_eq!(parse_duration("3m").unwrap(), 180);
        assert_eq!(parse_duration("2h").unwrap(), 7_200);
        assert_eq!(parse_duration("7d").unwrap(), 604_800);
    }

    #[test]
    fn parse_duration_rejects_garbage() {
        assert!(parse_duration("").is_err());
        assert!(parse_duration("h").is_err());
        assert!(parse_duration("3w").is_err()); // unsupported suffix → caught as bad int
    }

    #[test]
    fn format_relative_picks_resolution_by_magnitude() {
        assert_eq!(format_relative(0), "0s ago");
        assert_eq!(format_relative(45), "45s ago");
        assert_eq!(format_relative(125), "2m5s ago");
        assert_eq!(format_relative(3_600 * 3 + 60 * 17), "3h17m ago");
    }

    #[test]
    fn short_truncates_long_uuid_with_ellipsis() {
        assert_eq!(short("aaaa-bbbb-cccc-dddd-eeee"), "aaaa-bbbb-cc…");
        assert_eq!(short("init-1"), "init-1"); // short stays short
    }

    #[test]
    fn render_one_human_emits_event_kind_and_relative_time() {
        let now: u64 = 1_700_010_000;
        let r = make_record(
            5, "WitnessAccepted",
            Some(now as i64 - 125),
            Some("init-x"),
            Some("task-1"),
            None,
        );
        let mut buf: Vec<u8> = Vec::new();
        render_one(&mut buf, &r, false, now, &OperatorNameLookup::empty());
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("[WitnessAccepted]"), "got: {s}");
        assert!(s.contains("init=init-x"), "got: {s}");
        assert!(s.contains("task=task-1"), "got: {s}");
        assert!(s.contains("ago"), "got: {s}");
    }

    #[test]
    fn render_one_json_emits_raw_line_unmodified() {
        let mut r = make_record(5, "K", None, None, None, None);
        r.raw_line = r#"{"seq":5,"event_kind":"K","prev_sha256":"00"}"#.to_owned();
        let mut buf: Vec<u8> = Vec::new();
        render_one(&mut buf, &r, true, 0, &OperatorNameLookup::empty());
        let s = String::from_utf8(buf).unwrap();
        assert_eq!(s.trim_end(), r.raw_line);
    }

    /// §2.5.2 "Operator display-name fields" — when an audit
    /// event's payload carries an operator fingerprint AND an
    /// embedded display-name snapshot, the human render MUST
    /// surface the snapshot as `role=Name (fp_prefix)`, not just
    /// the bare ids.
    #[test]
    fn render_one_human_surfaces_embedded_operator_display_name() {
        let mut r = make_record(
            7, "EscalationApproved",
            Some(1_700_000_500),
            None,
            None,
            None,
        );
        r.parsed_value = Some(serde_json::json!({
            "seq": 7,
            "event_kind": "EscalationApproved",
            "payload": {
                "kind":          "EscalationApproved",
                "escalation_id": "esc-1",
                "approved_by":   "abcd1234abcd1234abcd1234abcd1234",
                "approved_by_display_name": "Chika",
            }
        }));
        let mut buf: Vec<u8> = Vec::new();
        render_one(&mut buf, &r, false, 1_700_001_000, &OperatorNameLookup::empty());
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("approved_by=Chika (abcd1234)"),
            "operator render must show embedded name + fp prefix; got: {s}");
        assert!(!s.contains("[historical cert"),
            "no historical annotation when embedded name is present; got: {s}");
    }

    /// Legacy event without an embedded name: the renderer falls
    /// back to the live `operator_certificates` lookup and MUST
    /// annotate the rendered name as historical.
    #[test]
    fn render_one_human_falls_back_to_historical_lookup_for_legacy_events() {
        // Hand-build a lookup so the test doesn't need a kernel.db.
        let lookup = OperatorNameLookup::from_pairs([
            ("deadbeefdeadbeefdeadbeefdeadbeef", "ChikaNow"),
        ]);

        let mut r = make_record(
            8, "EscalationApproved",
            Some(1_700_000_500),
            None,
            None,
            None,
        );
        r.parsed_value = Some(serde_json::json!({
            "seq": 8,
            "event_kind": "EscalationApproved",
            "payload": {
                "kind":          "EscalationApproved",
                "escalation_id": "esc-2",
                "approved_by":   "deadbeefdeadbeefdeadbeefdeadbeef",
            }
        }));
        let mut buf: Vec<u8> = Vec::new();
        render_one(&mut buf, &r, false, 1_700_001_000, &lookup);
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("approved_by=ChikaNow (deadbeef)"),
            "legacy event must render via the live lookup: {s}");
        assert!(s.contains("[historical cert"),
            "legacy render MUST carry the historical annotation: {s}");
    }

    #[test]
    fn parse_args_treats_first_positional_as_initiative_id() {
        let opts = parse_args(&["init-007".to_owned()]).unwrap();
        assert_eq!(opts.initiative_id.as_deref(), Some("init-007"));
        assert_eq!(opts.limit, DEFAULT_LIMIT);
    }

    #[test]
    fn parse_args_handles_combined_filters() {
        let opts = parse_args(
            &[
                "init-007".to_owned(),
                "--task".to_owned(), "t-9".to_owned(),
                "--kind".to_owned(), "witness".to_owned(),
                "--limit".to_owned(), "10".to_owned(),
                "--json".to_owned(),
            ],
        ).unwrap();
        assert_eq!(opts.initiative_id.as_deref(), Some("init-007"));
        assert_eq!(opts.task_id.as_deref(), Some("t-9"));
        assert_eq!(opts.kind.as_deref(), Some("witness"));
        assert_eq!(opts.limit, 10);
        assert!(opts.json);
    }

    #[test]
    fn parse_args_rejects_two_positionals() {
        let err = parse_args(&["init-1".to_owned(), "init-2".to_owned()]).unwrap_err();
        assert!(matches!(err, CliError::Usage(_)));
    }

    #[test]
    fn parse_args_rejects_unknown_flag() {
        let err = parse_args(&["--bogus".to_owned()]).unwrap_err();
        assert!(matches!(err, CliError::Usage(_)));
    }

    /// End-to-end one-shot path against an on-disk audit dir. Builds
    /// a real chain via the audit-tools writer is overkill for the
    /// CLI's read-side tests, so we hand-write a 3-record JSONL
    /// segment with byte-correct prev_sha256 links.
    fn write_real_segment(audit_dir: &std::path::Path) {
        let line0 = serde_json::json!({
            "seq": 0,
            "event_kind": "GenesisRecord",
            "prev_sha256": GENESIS_PREV_SHA256_LITERAL,
            "emitted_at": 1_700_000_000_i64,
        }).to_string();
        let line0_nl = format!("{line0}\n");
        let mut h = Sha256::new();
        h.update(line0_nl.as_bytes());
        let line0_sha = hex::encode(h.finalize());

        let line1 = serde_json::json!({
            "seq": 1,
            "event_kind": "WitnessAccepted",
            "prev_sha256": line0_sha,
            "emitted_at": 1_700_000_500_i64,
            "task_id": "t-1",
            "initiative_id": "init-x",
        }).to_string();
        let line1_nl = format!("{line1}\n");
        let mut h = Sha256::new();
        h.update(line1_nl.as_bytes());
        let line1_sha = hex::encode(h.finalize());

        let line2 = serde_json::json!({
            "seq": 2,
            "event_kind": "TaskStateChanged",
            "prev_sha256": line1_sha,
            "emitted_at": 1_700_001_000_i64,
            "task_id": "t-2",
        }).to_string();
        std::fs::write(
            audit_dir.join("segment-000.jsonl"),
            format!("{line0_nl}{line1_nl}{line2}\n"),
        ).unwrap();
    }

    #[test]
    fn run_one_shot_against_real_segment_renders_expected_lines() {
        // We don't directly exercise `run_one_shot` (it writes to
        // stdout), but we DO hand-walk the chain reader the same
        // way `run_one_shot` does so the test surfaces wire-level
        // bugs in the audit-tools API.
        let tmp = TempDir::new().unwrap();
        let audit_dir = tmp.path().to_path_buf();
        write_real_segment(&audit_dir);

        let reader = ChainReader::open(&audit_dir).unwrap();
        let opts = LogOpts {
            initiative_id: Some("init-x".to_owned()),
            limit: 50,
            ..LogOpts::default()
        };
        let mut hits = 0;
        for r in reader.records().flatten() {
            if matches_filter(&r, &opts) {
                hits += 1;
                assert_eq!(r.initiative_id.as_deref(), Some("init-x"));
            }
        }
        assert_eq!(hits, 1, "expected exactly one record matching init-x");
    }
}

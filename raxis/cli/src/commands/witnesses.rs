//! `raxis witnesses <task_id>` — list every witness recorded for a task.
//!
//! Normative reference: cli-readonly.md §5.5.9.
//!
//! # Why a dedicated command
//!
//! `raxis inspect <task_id>` already shows witnesses, but it is the
//! "one task, lots of context" view. Operators chasing a verifier
//! regression or comparing gate outcomes across rerun attempts want
//! a focused, single-table render — and `raxis witnesses` is what the
//! spec calls out for that case. We share `views::witnesses::for_task`
//! so the data shape matches inspect's "Witnesses (N):" block exactly.
//!
//! # Data sources (all read-only, no kernel IPC)
//!
//! * `<data_dir>/kernel.db` opened READ-ONLY via `raxis_store::open_ro`.
//!   - `views::witnesses::for_task` ordered by `recorded_at DESC`.
//!
//! # Filters
//!
//! * `--gate <gate_type>` — exact-match filter on `gate_type`.
//! * `--result <Pass|Fail|Inconclusive>` — case-insensitive match on
//!   `result_class`.
//! * `--limit N` — keep newest N rows (default: 50).
//!
//! # Exit code
//!
//! `0` on success; `4` when `task_id` does not appear in
//! `witness_records` at all (script-friendly distinction from
//! "task exists but no witnesses yet" via the human renderer).

use std::io::Write;

use raxis_store::open_ro;
use raxis_store::views::witnesses::{for_task, WitnessRow};

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

    let mut rows = for_task(&conn, &opts.task_id)
        .map_err(|e| CliError::Policy(format!("witnesses::for_task failed: {e}")))?;
    let total_for_task = rows.len();

    rows.retain(|r| filter_match(r, &opts));
    if rows.len() > opts.limit {
        let drop = rows.len() - opts.limit;
        rows.drain(opts.limit..);
        // We dropped from the END since the source is already sorted
        // newest-first; the operator sees the most recent rows.
        let _ = drop;
    }

    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    if opts.json {
        render_json(&mut out, &opts.task_id, &rows);
    } else {
        render_human(&mut out, &opts.task_id, &rows);
    }
    let _ = out.flush();

    if total_for_task == 0 {
        // Distinct exit code so scripts can branch.
        std::process::exit(4);
    }
    Ok(())
}

// ────────────────────────────────────────────────────────────────────
// Argument parsing
// ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct WitnessesOpts {
    task_id:       String,
    gate_filter:   Option<String>,
    result_filter: Option<String>,
    limit:         usize,
    json:          bool,
}

fn parse_args(args: &[String]) -> Result<WitnessesOpts, CliError> {
    let mut task_id:       Option<String> = None;
    let mut gate_filter:   Option<String> = None;
    let mut result_filter: Option<String> = None;
    let mut limit:         usize          = DEFAULT_LIMIT;
    let mut json:          bool           = false;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--gate" => {
                i += 1;
                gate_filter = Some(arg_value(args, i, "--gate")?.to_owned());
            }
            "--result" => {
                i += 1;
                let v = arg_value(args, i, "--result")?;
                // Validate against the spec's three result_class values.
                let canonical = match v.to_ascii_lowercase().as_str() {
                    "pass"         => "Pass",
                    "fail"         => "Fail",
                    "inconclusive" => "Inconclusive",
                    other => {
                        return Err(CliError::Usage(format!(
                            "--result must be Pass|Fail|Inconclusive, got {other:?}"
                        )));
                    }
                };
                result_filter = Some(canonical.to_owned());
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
                limit = n;
            }
            "--json" => json = true,
            "-h" | "--help" => {
                print_help();
                std::process::exit(0);
            }
            other if !other.starts_with('-') && task_id.is_none() => {
                task_id = Some(other.to_owned());
            }
            other => {
                return Err(CliError::Usage(format!(
                    "unknown witnesses flag: {other:?} \
                     (try --gate G, --result Pass|Fail|Inconclusive, --limit N, --json)"
                )));
            }
        }
        i += 1;
    }

    let task_id = task_id.ok_or_else(|| {
        CliError::Usage("usage: raxis witnesses <task_id> [flags]".to_owned())
    })?;

    Ok(WitnessesOpts { task_id, gate_filter, result_filter, limit, json })
}

fn arg_value<'a>(args: &'a [String], idx: usize, flag: &str) -> Result<&'a str, CliError> {
    args.get(idx)
        .map(|s| s.as_str())
        .ok_or_else(|| CliError::Usage(format!("{flag} requires a value")))
}

fn print_help() {
    println!(
        "raxis witnesses — list witness records for a task\n\
         \n\
         USAGE:\n\
         \traxis witnesses <task_id> [--gate G] [--result Pass|Fail|Inconclusive] \\\n\
         \t                            [--limit N] [--json]\n\
         \n\
         EXIT CODES:\n\
         \t0   at least one witness exists for <task_id>\n\
         \t4   no witnesses found for <task_id> (task may not exist)\n\
         "
    );
}

// ────────────────────────────────────────────────────────────────────
// Filter
// ────────────────────────────────────────────────────────────────────

fn filter_match(row: &WitnessRow, opts: &WitnessesOpts) -> bool {
    if let Some(g) = &opts.gate_filter {
        if &row.gate_type != g {
            return false;
        }
    }
    if let Some(r) = &opts.result_filter {
        if &row.result_class != r {
            return false;
        }
    }
    true
}

// ────────────────────────────────────────────────────────────────────
// Rendering — human
// ────────────────────────────────────────────────────────────────────

fn render_human<W: Write>(out: &mut W, task_id: &str, rows: &[WitnessRow]) {
    let _ = writeln!(
        out,
        "Witnesses for task {task_id} ({n} row{plural}):",
        task_id = task_id,
        n       = rows.len(),
        plural  = if rows.len() == 1 { "" } else { "s" },
    );
    if rows.is_empty() {
        let _ = writeln!(out, "  (no matching rows)");
        return;
    }
    let _ = writeln!(
        out,
        "  {run:<24} {gate:<16} {result:<14} {recorded:>12}  blob_sha256",
        run      = "verifier_run_id",
        gate     = "gate_type",
        result   = "result_class",
        recorded = "recorded_at",
    );
    for r in rows {
        let _ = writeln!(
            out,
            "  {run:<24} {gate:<16} {result:<14} {recorded:>12}  {blob}",
            run      = truncate(&r.verifier_run_id, 24),
            gate     = truncate(&r.gate_type, 16),
            result   = truncate(&r.result_class, 14),
            recorded = r.recorded_at,
            blob     = truncate(&r.blob_sha256, 64),
        );
    }
}

// ────────────────────────────────────────────────────────────────────
// Rendering — JSON
// ────────────────────────────────────────────────────────────────────

fn render_json<W: Write>(out: &mut W, task_id: &str, rows: &[WitnessRow]) {
    let v = serde_json::json!({
        "task_id":  task_id,
        "count":    rows.len(),
        "rows":     rows.iter().map(|r| serde_json::json!({
            "verifier_run_id": r.verifier_run_id,
            "task_id":         r.task_id,
            "gate_type":       r.gate_type,
            "result_class":    r.result_class,
            "evaluation_sha":  r.evaluation_sha,
            "blob_sha256":     r.blob_sha256,
            "recorded_at":     r.recorded_at,
        })).collect::<Vec<_>>(),
    });
    let _ = serde_json::to_writer(&mut *out, &v);
    let _ = writeln!(out);
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

// ────────────────────────────────────────────────────────────────────
// Tests
// ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn row(run: &str, gate: &str, result: &str, recorded: u64) -> WitnessRow {
        WitnessRow {
            verifier_run_id: run.to_owned(),
            task_id:         "t-1".to_owned(),
            gate_type:       gate.to_owned(),
            result_class:    result.to_owned(),
            evaluation_sha:  "eval-sha".to_owned(),
            blob_sha256:     format!("blob-{run}"),
            recorded_at:     recorded,
        }
    }

    #[test]
    fn parse_args_requires_task_id() {
        let err = parse_args(&[]).unwrap_err();
        assert!(matches!(err, CliError::Usage(_)));
    }

    #[test]
    fn parse_args_accepts_task_id_and_filters() {
        let o = parse_args(&[
            "task-1".to_owned(),
            "--gate".to_owned(),
            "tests".to_owned(),
            "--result".to_owned(),
            "fail".to_owned(),
            "--limit".to_owned(),
            "3".to_owned(),
            "--json".to_owned(),
        ]).unwrap();
        assert_eq!(o.task_id, "task-1");
        assert_eq!(o.gate_filter.as_deref(), Some("tests"));
        assert_eq!(o.result_filter.as_deref(), Some("Fail"));
        assert_eq!(o.limit, 3);
        assert!(o.json);
    }

    #[test]
    fn parse_args_canonicalises_result_case() {
        let o = parse_args(&[
            "t-1".to_owned(),
            "--result".to_owned(),
            "INCONCLUSIVE".to_owned(),
        ]).unwrap();
        assert_eq!(o.result_filter.as_deref(), Some("Inconclusive"));
    }

    #[test]
    fn parse_args_rejects_unknown_result() {
        let err = parse_args(&[
            "t-1".to_owned(),
            "--result".to_owned(),
            "Maybe".to_owned(),
        ]).unwrap_err();
        assert!(matches!(err, CliError::Usage(_)));
    }

    #[test]
    fn parse_args_rejects_zero_limit() {
        let err = parse_args(&[
            "t-1".to_owned(),
            "--limit".to_owned(),
            "0".to_owned(),
        ]).unwrap_err();
        assert!(matches!(err, CliError::Usage(_)));
    }

    #[test]
    fn filter_match_passes_when_no_filters_configured() {
        let opts = WitnessesOpts {
            task_id:       "t-1".to_owned(),
            gate_filter:   None,
            result_filter: None,
            limit:         100,
            json:          false,
        };
        assert!(filter_match(&row("r1", "tests", "Pass", 1), &opts));
    }

    #[test]
    fn filter_match_drops_rows_failing_gate_or_result() {
        let opts = WitnessesOpts {
            task_id:       "t-1".to_owned(),
            gate_filter:   Some("tests".to_owned()),
            result_filter: Some("Pass".to_owned()),
            limit:         100,
            json:          false,
        };
        assert!(filter_match(&row("r1", "tests", "Pass", 1), &opts));
        assert!(!filter_match(&row("r2", "tests", "Fail", 1), &opts));
        assert!(!filter_match(&row("r3", "coverage", "Pass", 1), &opts));
    }

    #[test]
    fn render_human_with_no_rows_uses_no_matching_label() {
        let mut buf: Vec<u8> = Vec::new();
        render_human(&mut buf, "t-1", &[]);
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("Witnesses for task t-1 (0 rows)"), "got: {s}");
        assert!(s.contains("(no matching rows)"), "got: {s}");
    }

    #[test]
    fn render_json_emits_task_id_and_rows() {
        let mut buf: Vec<u8> = Vec::new();
        let rows = vec![row("r1", "tests", "Pass", 100)];
        render_json(&mut buf, "t-1", &rows);
        let v: serde_json::Value = serde_json::from_slice(&buf).unwrap();
        assert_eq!(v["task_id"], "t-1");
        assert_eq!(v["count"], 1);
        assert_eq!(v["rows"][0]["result_class"], "Pass");
    }
}

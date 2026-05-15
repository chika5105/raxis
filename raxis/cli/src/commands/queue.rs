//! `raxis queue` — DAG scheduler state.
//!
//! Normative reference: cli-readonly.md §5.5.3.
//!
//! Two tables:
//!   * READY (state IN Admitted, GatesPending) — picked from
//!     `views::tasks::ready_set` ordered oldest-waiting first.
//!   * BLOCKED (state == BlockedRecoveryPending) — one row per
//!     unsatisfied predecessor edge from
//!     `views::tasks::blocking_edges`. v1 only has one `Blocked*`
//!     state; v2 will add `BlockedGate` and similar variants.
//!
//! Optional third section: pending verifier spawn queue, sourced
//! from `heartbeat.json::queued_spawns`. Marked "(approximate; from
//! heartbeat at <age> ago)" to set operator expectations.

use std::io::Write;
use std::path::Path;

use raxis_store::open_ro;
use raxis_store::views::tasks::{blocking_edges, ready_set, BlockingEdgeRow, ReadyTaskRow};

use crate::errors::CliError;
use crate::GlobalFlags;

/// Default render limit per section. Operators with more queue depth
/// should use `raxis log` for full history; the queue command is
/// designed for one-screen rendering.
const DEFAULT_LIMIT: usize = 50;

pub fn run(flags: &GlobalFlags, args: &[String]) -> Result<(), CliError> {
    let opts = parse_args(args)?;
    let conn = open_ro(flags.data_dir())
        .map_err(|e| CliError::Policy(format!("kernel.db open failed: {e}")))?;

    let stdout = std::io::stdout();
    let mut out = stdout.lock();

    if opts.blocked_only {
        let edges = blocking_edges(&conn)
            .map_err(|e| CliError::Policy(format!("blocking_edges read failed: {e}")))?;
        render_blocked(&mut out, &edges, opts.limit);
    } else {
        let ready = ready_set(&conn, opts.lane.as_deref(), opts.limit)
            .map_err(|e| CliError::Policy(format!("ready_set read failed: {e}")))?;
        let edges = blocking_edges(&conn)
            .map_err(|e| CliError::Policy(format!("blocking_edges read failed: {e}")))?;
        render_ready(&mut out, &ready, opts.lane.as_deref());
        let _ = writeln!(out);
        render_blocked(&mut out, &edges, opts.limit);
    }

    // Pending-spawn-queue from heartbeat (approximate; spec-mandated).
    let _ = writeln!(out);
    render_pending_spawn_queue(&mut out, flags.data_dir());

    let _ = out.flush();
    Ok(())
}

// ────────────────────────────────────────────────────────────────────
// Rendering
// ────────────────────────────────────────────────────────────────────

fn render_ready<W: Write>(out: &mut W, rows: &[ReadyTaskRow], lane_filter: Option<&str>) {
    let header = if let Some(lane) = lane_filter {
        format!("READY (lane={lane}, {n}):", n = rows.len())
    } else {
        format!("READY ({n}):", n = rows.len())
    };
    let _ = writeln!(out, "{header}");
    if rows.is_empty() {
        let _ = writeln!(out, "  (no ready tasks)");
        return;
    }
    let _ = writeln!(
        out,
        "  {task_id:<22} {init_id:<22} {lane:<10} admitted_at",
        task_id = "task_id",
        init_id = "initiative_id",
        lane = "lane",
    );
    for r in rows {
        let _ = writeln!(
            out,
            "  {task_id:<22} {init_id:<22} {lane:<10} {ts}",
            task_id = truncate(&r.task_id, 22),
            init_id = truncate(&r.initiative_id, 22),
            lane = truncate(&r.lane_id, 10),
            ts = r.admitted_at,
        );
    }
}

fn render_blocked<W: Write>(out: &mut W, rows: &[BlockingEdgeRow], limit: usize) {
    // Group by blocked_task_id so the spec's example (one task with
    // multiple `waiting_on` lines) renders as the operator expects.
    let _ = writeln!(out, "BLOCKED ({n}):", n = rows.len());
    if rows.is_empty() {
        let _ = writeln!(out, "  (no blocked tasks)");
        return;
    }
    let _ = writeln!(
        out,
        "  {task_id:<22} {wait:<22} {reason}",
        task_id = "task_id",
        wait = "waiting_on",
        reason = "reason",
    );
    for r in rows.iter().take(limit) {
        let _ = writeln!(
            out,
            "  {task_id:<22} {wait:<22} {reason}",
            task_id = truncate(&r.blocked_task_id, 22),
            wait = format!(
                "{} ({})",
                truncate(&r.waiting_on_task, 16),
                truncate(&r.waiting_on_state, 12)
            ),
            reason = r.blocked_state,
        );
    }
    if rows.len() > limit {
        let _ = writeln!(
            out,
            "  ... {n} more (use --limit to expand)",
            n = rows.len() - limit
        );
    }
}

fn render_pending_spawn_queue<W: Write>(out: &mut W, data_dir: &Path) {
    let _ = writeln!(out, "PENDING VERIFIER SPAWNS:");
    match raxis_runtime::read(data_dir) {
        Ok(snap) => {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let age = now.saturating_sub(snap.last_heartbeat_at);
            let _ = writeln!(
                out,
                "  queued_spawns={n} (approximate; from heartbeat {age}s ago)",
                n = snap.queued_spawns,
            );
        }
        Err(e) => {
            // Spec is explicit: a missing/stale heartbeat is operator-
            // visible info, NOT a hard fail. Fold the error into the
            // output and keep going.
            let _ = writeln!(out, "  (heartbeat unavailable: {e})");
        }
    }
}

/// Right-pad a field to width N; if too long, replace the tail with
/// `…` so columns stay aligned. Used over `format!("{:<22}", x)`
/// because the latter doesn't truncate.
fn truncate(s: &str, width: usize) -> String {
    if s.chars().count() <= width {
        s.to_owned()
    } else if width <= 1 {
        "…".to_owned()
    } else {
        let mut out: String = s.chars().take(width.saturating_sub(1)).collect();
        out.push('…');
        out
    }
}

// ────────────────────────────────────────────────────────────────────
// Argument parsing
// ────────────────────────────────────────────────────────────────────

#[derive(Debug, Default, Clone)]
struct QueueOpts {
    lane: Option<String>,
    blocked_only: bool,
    limit: usize,
}

fn parse_args(args: &[String]) -> Result<QueueOpts, CliError> {
    let mut opts = QueueOpts {
        limit: DEFAULT_LIMIT,
        ..QueueOpts::default()
    };
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--lane" => {
                i += 1;
                let v = args
                    .get(i)
                    .ok_or_else(|| CliError::Usage("--lane requires a lane id".to_owned()))?;
                opts.lane = Some(v.clone());
            }
            "--blocked-only" => opts.blocked_only = true,
            "--limit" => {
                i += 1;
                let v = args.get(i).ok_or_else(|| {
                    CliError::Usage("--limit requires a non-negative integer".to_owned())
                })?;
                opts.limit = v.parse().map_err(|_| {
                    CliError::Usage(format!("--limit expects an integer; got {v:?}"))
                })?;
            }
            "-h" | "--help" => {
                print_help();
                std::process::exit(0);
            }
            other => {
                return Err(CliError::Usage(format!(
                    "unknown queue flag: {other:?} (try --lane, --blocked-only, --limit, --help)"
                )));
            }
        }
        i += 1;
    }
    Ok(opts)
}

fn print_help() {
    println!(
        "raxis queue — DAG scheduler state\n\
         \n\
         USAGE:\n\
         \tlraxis queue [--lane <id>] [--blocked-only] [--limit <N>]\n\
         \n\
         FLAGS:\n\
         \t--lane <id>      Filter the READY table to a single lane.\n\
         \t--blocked-only   Skip the READY table; only show blocked tasks.\n\
         \t--limit <N>      Cap rows per section (default 50)."
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncate_preserves_short_strings() {
        assert_eq!(truncate("init-1", 22), "init-1");
    }

    #[test]
    fn truncate_inserts_ellipsis_for_long_strings() {
        let s = "01234567890123456789012345"; // 26 chars
        assert_eq!(truncate(s, 10), "012345678…");
    }

    #[test]
    fn truncate_collapses_to_ellipsis_at_width_one() {
        assert_eq!(truncate("anything-long", 1), "…");
    }

    #[test]
    fn parse_args_default_has_no_lane_no_blocked_only() {
        let opts = parse_args(&[]).unwrap();
        assert_eq!(opts.lane, None);
        assert!(!opts.blocked_only);
        assert_eq!(opts.limit, DEFAULT_LIMIT);
    }

    #[test]
    fn parse_args_accepts_lane_blocked_only_limit() {
        let opts = parse_args(&[
            "--lane".to_owned(),
            "default".to_owned(),
            "--blocked-only".to_owned(),
            "--limit".to_owned(),
            "5".to_owned(),
        ])
        .unwrap();
        assert_eq!(opts.lane.as_deref(), Some("default"));
        assert!(opts.blocked_only);
        assert_eq!(opts.limit, 5);
    }

    #[test]
    fn parse_args_rejects_unknown_flag() {
        let err = parse_args(&["--bogus".to_owned()]).unwrap_err();
        assert!(matches!(err, CliError::Usage(_)));
    }

    #[test]
    fn render_ready_handles_empty_set() {
        let mut buf: Vec<u8> = Vec::new();
        render_ready(&mut buf, &[], None);
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("READY (0):"), "got: {s}");
        assert!(s.contains("no ready tasks"), "got: {s}");
    }

    #[test]
    fn render_blocked_handles_empty_set() {
        let mut buf: Vec<u8> = Vec::new();
        render_blocked(&mut buf, &[], 50);
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("BLOCKED (0):"), "got: {s}");
        assert!(s.contains("no blocked tasks"), "got: {s}");
    }

    #[test]
    fn render_blocked_truncates_with_summary_when_over_limit() {
        let rows: Vec<BlockingEdgeRow> = (0..10)
            .map(|i| BlockingEdgeRow {
                blocked_task_id: format!("t-{i}"),
                blocked_state: "BlockedRecoveryPending".to_owned(),
                waiting_on_task: format!("t-pred-{i}"),
                waiting_on_state: "Running".to_owned(),
            })
            .collect();
        let mut buf: Vec<u8> = Vec::new();
        render_blocked(&mut buf, &rows, 3);
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("BLOCKED (10):"), "got: {s}");
        assert!(s.contains("7 more"), "got: {s}");
    }

    #[test]
    fn render_ready_includes_header_row_when_non_empty() {
        let rows = vec![ReadyTaskRow {
            task_id: "t-1".to_owned(),
            initiative_id: "init-1".to_owned(),
            lane_id: "default".to_owned(),
            admitted_at: 100,
        }];
        let mut buf: Vec<u8> = Vec::new();
        render_ready(&mut buf, &rows, None);
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("task_id"), "got: {s}");
        assert!(s.contains("initiative_id"), "got: {s}");
        assert!(s.contains("default"), "got: {s}");
    }
}

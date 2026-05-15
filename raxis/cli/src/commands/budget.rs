//! `raxis budget` — per-lane budget pressure overview.
//!
//! Normative reference: cli-readonly.md §5.5.10.
//!
//! # Data sources (all read-only, no kernel IPC)
//!
//! * `<data_dir>/policy/policy.toml` — parsed via
//!   `raxis_policy::load_policy` to obtain each lane's
//!   `max_cost_per_epoch`. Lanes with no reservations still appear in
//!   the report so an operator can see "lane defined but idle".
//! * `<data_dir>/kernel.db` opened READ-ONLY:
//!   - `views::budget::per_lane` → reserved_cost SUM + task COUNT.
//!   - `views::budget::reservations_for_lane` when the operator
//!     passes `<lane_id>` for a lane-detail drill-down.
//!
//! # Pressure calculation
//!
//! `pressure_pct = round(100 * reserved_cost / max_cost_per_epoch)`,
//! computed in CLI not SQL because the policy lives in TOML, not a
//! kernel.db row. A lane with `max_cost_per_epoch == 0` reports
//! `pressure_pct = "n/a"` rather than dividing by zero.
//!
//! # Exit code
//!
//! `0` on success. Lane-detail mode exits `4` when the requested
//! lane is not declared in the policy bundle (typo guard).

use std::collections::HashMap;
use std::io::Write;

use raxis_policy::{load_policy, LaneEntry};
use raxis_store::open_ro;
use raxis_store::views::budget::{per_lane, reservations_for_lane, LaneBudgetRow, ReservationRow};

use crate::errors::CliError;
use crate::GlobalFlags;

const POLICY_FILE_NAME: &str = "policy.toml";
const DEFAULT_LIMIT: usize = 50;

// ────────────────────────────────────────────────────────────────────
// Entry point
// ────────────────────────────────────────────────────────────────────

pub fn run(flags: &GlobalFlags, args: &[String]) -> Result<(), CliError> {
    let opts = parse_args(args)?;

    let policy_path = flags.data_dir().join("policy").join(POLICY_FILE_NAME);
    let (bundle, _, _) = load_policy(&policy_path).map_err(|e| {
        CliError::Policy(format!(
            "failed to load active policy from {:?}: {e}",
            policy_path,
        ))
    })?;

    let conn = open_ro(flags.data_dir())
        .map_err(|e| CliError::Policy(format!("kernel.db open failed: {e}")))?;

    if let Some(lane_id) = &opts.lane_id {
        // Lane-detail drill-down. Validate the lane exists in policy
        // FIRST so an operator typo fails before we hit SQLite.
        if !bundle.lanes().iter().any(|l| &l.lane_id == lane_id) {
            eprintln!("budget: lane {lane_id:?} is not declared in the active policy bundle");
            std::process::exit(4);
        }
        let rows = reservations_for_lane(&conn, lane_id, opts.limit)
            .map_err(|e| CliError::Policy(format!("budget::reservations_for_lane: {e}")))?;
        let stdout = std::io::stdout();
        let mut out = stdout.lock();
        if opts.json {
            render_json_lane(&mut out, lane_id, &rows);
        } else {
            render_human_lane(&mut out, lane_id, &rows);
        }
        let _ = out.flush();
        return Ok(());
    }

    // Top-level "all lanes" mode.
    let agg = per_lane(&conn).map_err(|e| CliError::Policy(format!("budget::per_lane: {e}")))?;

    let lanes_index: HashMap<&str, &LaneEntry> = bundle
        .lanes()
        .iter()
        .map(|l| (l.lane_id.as_str(), l))
        .collect();
    let agg_index: HashMap<&str, &LaneBudgetRow> =
        agg.iter().map(|r| (r.lane_id.as_str(), r)).collect();

    // Build the union of lane ids: every lane in the bundle plus any
    // unexpected lane_id observed in lane_budget_reservations (these
    // would indicate either a stale row from a previous policy or a
    // kernel bug — we want them surfaced, not hidden).
    let mut lane_ids: Vec<String> = bundle.lanes().iter().map(|l| l.lane_id.clone()).collect();
    for r in &agg {
        if !lanes_index.contains_key(r.lane_id.as_str()) {
            lane_ids.push(r.lane_id.clone());
        }
    }

    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    if opts.json {
        render_json_all(&mut out, &lane_ids, &lanes_index, &agg_index);
    } else {
        render_human_all(&mut out, &lane_ids, &lanes_index, &agg_index);
    }
    let _ = out.flush();
    Ok(())
}

// ────────────────────────────────────────────────────────────────────
// Argument parsing
// ────────────────────────────────────────────────────────────────────

#[derive(Debug, Default, Clone)]
struct BudgetOpts {
    lane_id: Option<String>,
    limit: usize,
    json: bool,
}

fn parse_args(args: &[String]) -> Result<BudgetOpts, CliError> {
    let mut opts = BudgetOpts {
        lane_id: None,
        limit: DEFAULT_LIMIT,
        json: false,
    };
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--json" => opts.json = true,
            "--limit" => {
                i += 1;
                let raw = args
                    .get(i)
                    .ok_or_else(|| CliError::Usage("--limit requires a value".to_owned()))?;
                let n = raw.parse::<usize>().map_err(|_| {
                    CliError::Usage(format!("--limit must be a positive integer, got {raw:?}"))
                })?;
                if n == 0 {
                    return Err(CliError::Usage("--limit must be greater than 0".to_owned()));
                }
                opts.limit = n;
            }
            "-h" | "--help" => {
                print_help();
                std::process::exit(0);
            }
            other if !other.starts_with('-') && opts.lane_id.is_none() => {
                opts.lane_id = Some(other.to_owned());
            }
            other => {
                return Err(CliError::Usage(format!(
                    "unknown budget flag: {other:?} (try [<lane_id>], --limit N, --json)"
                )));
            }
        }
        i += 1;
    }
    Ok(opts)
}

fn print_help() {
    println!(
        "raxis budget — per-lane budget pressure overview\n\
         \n\
         USAGE:\n\
         \traxis budget [<lane_id>] [--limit N] [--json]\n\
         \n\
         FLAGS:\n\
         \t<lane_id>   Drill into one lane's reservations.\n\
         \t--limit N   Cap drill-down rows (default: {DEFAULT_LIMIT}).\n\
         \t--json      Emit one JSON object instead of a human table.\n\
         "
    );
}

// ────────────────────────────────────────────────────────────────────
// Pressure helper
// ────────────────────────────────────────────────────────────────────

fn pressure_pct(reserved: u64, max_cost: u64) -> Option<u64> {
    if max_cost == 0 {
        return None;
    }
    // u128 to avoid overflow on theoretical max budgets.
    let pct = (reserved as u128 * 100) / max_cost as u128;
    Some(pct.min(u64::MAX as u128) as u64)
}

// ────────────────────────────────────────────────────────────────────
// Rendering — human (all lanes)
// ────────────────────────────────────────────────────────────────────

fn render_human_all<W: Write>(
    out: &mut W,
    lane_ids: &[String],
    lanes_idx: &HashMap<&str, &LaneEntry>,
    agg_idx: &HashMap<&str, &LaneBudgetRow>,
) {
    let _ = writeln!(
        out,
        "Lane budgets ({n} lane{plural}):",
        n = lane_ids.len(),
        plural = if lane_ids.len() == 1 { "" } else { "s" },
    );
    if lane_ids.is_empty() {
        let _ = writeln!(out, "  (no lanes defined in policy and no reservations)");
        return;
    }
    let _ = writeln!(
        out,
        "  {lane:<24} {tasks:>6} {reserved:>12} {cap:>12} {pct:>8}",
        lane = "lane_id",
        tasks = "tasks",
        reserved = "reserved",
        cap = "cap",
        pct = "pressure",
    );
    for id in lane_ids {
        let agg = agg_idx.get(id.as_str());
        let lane = lanes_idx.get(id.as_str());
        let reserved = agg.map(|a| a.reserved_cost).unwrap_or(0);
        let count = agg.map(|a| a.task_count).unwrap_or(0);
        let cap = lane.map(|l| l.max_cost_per_epoch).unwrap_or(0);
        let pct = match pressure_pct(reserved, cap) {
            Some(p) => format!("{p}%"),
            None => "n/a".to_owned(),
        };
        let suffix = if lane.is_none() {
            "  (orphan: not in policy)"
        } else {
            ""
        };
        let _ = writeln!(
            out,
            "  {lane:<24} {tasks:>6} {reserved:>12} {cap:>12} {pct:>8}{suffix}",
            lane = truncate(id, 24),
            tasks = count,
            reserved = reserved,
            cap = cap,
            pct = pct,
            suffix = suffix,
        );
    }
}

// ────────────────────────────────────────────────────────────────────
// Rendering — human (one lane)
// ────────────────────────────────────────────────────────────────────

fn render_human_lane<W: Write>(out: &mut W, lane_id: &str, rows: &[ReservationRow]) {
    let _ = writeln!(
        out,
        "Reservations for lane {lane_id} ({n} row{plural}):",
        lane_id = lane_id,
        n = rows.len(),
        plural = if rows.len() == 1 { "" } else { "s" },
    );
    if rows.is_empty() {
        let _ = writeln!(out, "  (no active reservations)");
        return;
    }
    let _ = writeln!(
        out,
        "  {task:<24} {cost:>10}  reserved_at",
        task = "task_id",
        cost = "cost",
    );
    for r in rows {
        let _ = writeln!(
            out,
            "  {task:<24} {cost:>10}  {at}",
            task = truncate(&r.task_id, 24),
            cost = r.reserved_cost,
            at = r.reserved_at,
        );
    }
}

// ────────────────────────────────────────────────────────────────────
// Rendering — JSON
// ────────────────────────────────────────────────────────────────────

fn render_json_all<W: Write>(
    out: &mut W,
    lane_ids: &[String],
    lanes_idx: &HashMap<&str, &LaneEntry>,
    agg_idx: &HashMap<&str, &LaneBudgetRow>,
) {
    let lanes: Vec<serde_json::Value> = lane_ids
        .iter()
        .map(|id| {
            let lane = lanes_idx.get(id.as_str());
            let agg = agg_idx.get(id.as_str());
            let reserved = agg.map(|a| a.reserved_cost).unwrap_or(0);
            let count = agg.map(|a| a.task_count).unwrap_or(0);
            let cap = lane.map(|l| l.max_cost_per_epoch).unwrap_or(0);
            serde_json::json!({
                "lane_id":            id,
                "task_count":         count,
                "reserved_cost":      reserved,
                "max_cost_per_epoch": cap,
                "pressure_pct":       pressure_pct(reserved, cap),
                "in_policy":          lane.is_some(),
            })
        })
        .collect();
    let v = serde_json::json!({
        "count": lanes.len(),
        "lanes": lanes,
    });
    let _ = serde_json::to_writer(&mut *out, &v);
    let _ = writeln!(out);
}

fn render_json_lane<W: Write>(out: &mut W, lane_id: &str, rows: &[ReservationRow]) {
    let v = serde_json::json!({
        "lane_id": lane_id,
        "count":   rows.len(),
        "rows":    rows.iter().map(|r| serde_json::json!({
            "task_id":       r.task_id,
            "reserved_cost": r.reserved_cost,
            "reserved_at":   r.reserved_at,
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

// ────────────────────────────────────────────────────────────────────
// Tests
// ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_args_defaults_to_top_level_mode() {
        let o = parse_args(&[]).unwrap();
        assert_eq!(o.lane_id, None);
        assert_eq!(o.limit, DEFAULT_LIMIT);
    }

    #[test]
    fn parse_args_accepts_lane_id_positional() {
        let o = parse_args(&["high-prio".to_owned()]).unwrap();
        assert_eq!(o.lane_id.as_deref(), Some("high-prio"));
    }

    #[test]
    fn parse_args_rejects_zero_limit() {
        let err = parse_args(&["--limit".to_owned(), "0".to_owned()]).unwrap_err();
        assert!(matches!(err, CliError::Usage(_)));
    }

    #[test]
    fn pressure_pct_handles_zero_cap() {
        assert_eq!(pressure_pct(10, 0), None);
    }

    #[test]
    fn pressure_pct_caps_at_huge_inputs() {
        assert_eq!(pressure_pct(50, 100), Some(50));
        assert_eq!(pressure_pct(150, 100), Some(150)); // overflow ok
    }

    fn sample_lane(id: &str, max_cost: u64) -> LaneEntry {
        LaneEntry {
            lane_id: id.to_owned(),
            max_concurrent_tasks: 10,
            max_cost_per_epoch: max_cost,
            priority: 100,
        }
    }

    #[test]
    fn render_human_all_includes_every_policy_lane_even_without_reservations() {
        let lane_a = sample_lane("alpha", 100);
        let lane_b = sample_lane("beta", 200);
        let lanes_idx: HashMap<&str, &LaneEntry> = [("alpha", &lane_a), ("beta", &lane_b)]
            .into_iter()
            .collect();
        let agg = LaneBudgetRow {
            lane_id: "alpha".to_owned(),
            reserved_cost: 50,
            task_count: 3,
        };
        let agg_idx: HashMap<&str, &LaneBudgetRow> = std::iter::once(("alpha", &agg)).collect();
        let lane_ids = vec!["alpha".to_owned(), "beta".to_owned()];

        let mut buf: Vec<u8> = Vec::new();
        render_human_all(&mut buf, &lane_ids, &lanes_idx, &agg_idx);
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("alpha"), "got: {s}");
        assert!(s.contains("50"), "got: {s}");
        assert!(s.contains("100"), "got: {s}");
        assert!(s.contains("50%"), "got: {s}");
        assert!(s.contains("beta"), "got: {s}");
        assert!(s.contains("0%"), "got: {s}");
    }

    #[test]
    fn render_human_all_marks_orphan_lane_not_in_policy() {
        // No lanes in policy index, but reservations reference "ghost".
        let lanes_idx: HashMap<&str, &LaneEntry> = HashMap::new();
        let agg = LaneBudgetRow {
            lane_id: "ghost".to_owned(),
            reserved_cost: 10,
            task_count: 1,
        };
        let agg_idx: HashMap<&str, &LaneBudgetRow> = std::iter::once(("ghost", &agg)).collect();
        let lane_ids = vec!["ghost".to_owned()];
        let mut buf: Vec<u8> = Vec::new();
        render_human_all(&mut buf, &lane_ids, &lanes_idx, &agg_idx);
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("orphan"), "got: {s}");
    }

    #[test]
    fn render_human_lane_with_no_rows_says_so() {
        let mut buf: Vec<u8> = Vec::new();
        render_human_lane(&mut buf, "default", &[]);
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("(no active reservations)"), "got: {s}");
    }

    #[test]
    fn render_json_all_emits_per_lane_struct() {
        let lane_a = sample_lane("alpha", 200);
        let lanes_idx: HashMap<&str, &LaneEntry> = std::iter::once(("alpha", &lane_a)).collect();
        let agg = LaneBudgetRow {
            lane_id: "alpha".to_owned(),
            reserved_cost: 50,
            task_count: 2,
        };
        let agg_idx: HashMap<&str, &LaneBudgetRow> = std::iter::once(("alpha", &agg)).collect();
        let lane_ids = vec!["alpha".to_owned()];
        let mut buf: Vec<u8> = Vec::new();
        render_json_all(&mut buf, &lane_ids, &lanes_idx, &agg_idx);
        let v: serde_json::Value = serde_json::from_slice(&buf).unwrap();
        assert_eq!(v["count"], 1);
        let row = &v["lanes"][0];
        assert_eq!(row["lane_id"], "alpha");
        assert_eq!(row["task_count"], 2);
        assert_eq!(row["reserved_cost"], 50);
        assert_eq!(row["max_cost_per_epoch"], 200);
        assert_eq!(row["pressure_pct"], 25);
        assert_eq!(row["in_policy"], true);
    }
}

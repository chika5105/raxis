//! `raxis inspect-initiative <initiative_id>` — forensic
//! deep-dive into a single initiative.
//!
//! Companion read-only surface to `raxis inspect <task_id>`.
//! Where `inspect` answers "tell me everything about this task",
//! `inspect-initiative` answers "tell me everything about this
//! initiative" by joining four read views in a single one-shot
//! snapshot:
//!
//!   * `views::initiatives::by_id` — base row (state, plan
//!     sha, created/approved/completed timestamps).
//!   * `views::signed_plan_artifacts::header_by_initiative` —
//!     the operator who signed the plan + when the kernel
//!     sealed it. Header-only — `plan_bytes` and `plan_sig` are
//!     deliberately NOT exposed (cli-readonly.md §5.4.2 forbids
//!     leaking sealed plan contents through `inspect`).
//!   * `views::initiative_quarantines::get_by_initiative_id` —
//!     quarantine status + the operator who issued it.
//!   * `views::tasks::list_by_initiative` — every task under the
//!     initiative, oldest-first by `admitted_at`.
//!
//! Operator-bearing fields (`signed_by_fingerprint`,
//! `quarantined_by`) are routed through `operator_display` so
//! the rendered identity is consistent with `raxis log`,
//! `raxis inbox`, and `raxis policy show --history` per
//! `kernel-store.md` §2.5.2 "Operator display-name fields".

use std::io::Write;

use raxis_store::open_ro;
use raxis_store::views::initiative_quarantines::{
    get_by_initiative_id as quarantine_for_initiative, InitiativeQuarantineRow,
};
use raxis_store::views::initiatives::{by_id as initiative_by_id, InitiativeRow};
use raxis_store::views::signed_plan_artifacts::{
    header_by_initiative, SignedPlanArtifactHeader,
};
use raxis_store::views::tasks::{list_by_initiative, TaskRow};

use crate::errors::CliError;
use crate::operator_display::{
    fingerprint_prefix, format_operator_with_lookup, OperatorNameLookup,
};
use crate::GlobalFlags;

/// Default cap for the per-initiative task table. v1 plans are
/// well below this; the cap exists so a degenerate plan with
/// thousands of tasks (or a query against a misbehaving DB)
/// cannot make the CLI page through unbounded rows.
const DEFAULT_TASK_LIMIT: usize = 100;

pub fn run(flags: &GlobalFlags, args: &[String]) -> Result<(), CliError> {
    let opts = parse_args(args)?;

    let conn = open_ro(flags.data_dir()).map_err(|e| {
        CliError::Policy(format!("kernel.db open failed: {e}"))
    })?;

    let initiative = initiative_by_id(&conn, &opts.initiative_id)
        .map_err(|e| CliError::Policy(format!("initiatives::by_id failed: {e}")))?
        .ok_or_else(|| CliError::KernelError {
            code:   "INITIATIVE_NOT_FOUND".to_owned(),
            detail: format!("no initiative with id {:?}", opts.initiative_id),
        })?;

    let plan_header = header_by_initiative(&conn, &opts.initiative_id)
        .map_err(|e| CliError::Policy(format!(
            "signed_plan_artifacts::header_by_initiative failed: {e}"
        )))?;

    let quarantine = quarantine_for_initiative(&conn, &opts.initiative_id)
        .map_err(|e| CliError::Policy(format!(
            "initiative_quarantines::get_by_initiative_id failed: {e}"
        )))?;

    let tasks = list_by_initiative(&conn, &opts.initiative_id, opts.task_limit)
        .map_err(|e| CliError::Policy(format!("tasks::list_by_initiative failed: {e}")))?;

    // Drop the read-only handle BEFORE we open the operator-name
    // lookup (it opens its own RoConn). They wouldn't collide,
    // but releasing the WAL snapshot early keeps the hot path
    // crisp for any concurrent kernel writer. Same discipline
    // as `inspect.rs`.
    drop(conn);

    // Lookup is built once per invocation so every operator
    // fingerprint resolution is served from memory. See
    // `operator_display` module docstring for the perf rationale.
    let name_lookup = OperatorNameLookup::load_from_data_dir(flags.data_dir())
        .unwrap_or_else(|_| OperatorNameLookup::empty());

    let stdout = std::io::stdout();
    let mut out = stdout.lock();

    if opts.json {
        render_json(
            &mut out, &initiative, plan_header.as_ref(),
            quarantine.as_ref(), &tasks, &name_lookup,
        );
    } else {
        render_human(
            &mut out, &initiative, plan_header.as_ref(),
            quarantine.as_ref(), &tasks, opts.with_tasks, &name_lookup,
        );
    }
    let _ = out.flush();
    Ok(())
}

// ────────────────────────────────────────────────────────────────────
// Rendering — human
// ────────────────────────────────────────────────────────────────────

fn render_human<W: Write>(
    out:         &mut W,
    initiative:  &InitiativeRow,
    plan:        Option<&SignedPlanArtifactHeader>,
    quarantine:  Option<&InitiativeQuarantineRow>,
    tasks:       &[TaskRow],
    with_tasks:  bool,
    name_lookup: &OperatorNameLookup,
) {
    let _ = writeln!(out, "Initiative {}", initiative.initiative_id);
    let _ = writeln!(out, "  state:               {}", initiative.state);
    let _ = writeln!(out, "  plan_sha256:         {}", initiative.plan_artifact_sha256);
    let _ = writeln!(out, "  created_at:          {}", initiative.created_at);
    if let Some(t) = initiative.approved_at {
        let _ = writeln!(out, "  approved_at:         {t}");
    }
    if let Some(t) = initiative.completed_at {
        let _ = writeln!(out, "  completed_at:        {t}");
    }

    let _ = writeln!(out);
    let _ = writeln!(out, "Plan signature:");
    render_plan_header(out, plan, name_lookup);

    let _ = writeln!(out);
    render_quarantine_block(out, quarantine, name_lookup);

    let _ = writeln!(out);
    if with_tasks {
        render_task_table(out, tasks);
    } else {
        let _ = writeln!(
            out,
            "Tasks ({n}): use --with-tasks to expand the per-task table",
            n = tasks.len(),
        );
    }
}

/// Render the `signed_plan_artifacts` header. Three branches:
/// (a) no row at all (extremely rare — would only happen if a
/// CreateInitiative crashed mid-transaction), (b) row with NULL
/// signed_by (legacy pre-migration-3 row), (c) full row.
fn render_plan_header<W: Write>(
    out:         &mut W,
    plan:        Option<&SignedPlanArtifactHeader>,
    name_lookup: &OperatorNameLookup,
) {
    match plan {
        None => {
            let _ = writeln!(
                out,
                "  (no signed_plan_artifacts row — initiative created but plan never sealed)",
            );
        }
        Some(h) => {
            match h.signed_by_fingerprint.as_deref() {
                Some(fp) => {
                    let rendered = format_operator_with_lookup(fp, None, name_lookup);
                    let _ = writeln!(out, "  signed_by:           {rendered}");
                }
                None => {
                    let _ = writeln!(
                        out,
                        "  signed_by:           (legacy: pre-migration-3 row, fingerprint not recorded)",
                    );
                }
            }
            let _ = writeln!(out, "  stored_at:           {}", h.stored_at);
        }
    }
}

fn render_quarantine_block<W: Write>(
    out:         &mut W,
    quarantine:  Option<&InitiativeQuarantineRow>,
    name_lookup: &OperatorNameLookup,
) {
    match quarantine {
        None => {
            let _ = writeln!(out, "Quarantine:            NO");
        }
        Some(q) => {
            let by = format_operator_with_lookup(&q.quarantined_by, None, name_lookup);
            let _ = writeln!(out, "Quarantine:            YES");
            let _ = writeln!(out, "  quarantined_at:      {}", q.quarantined_at);
            let _ = writeln!(out, "  quarantined_by:      {by}");
            if let Some(reason) = &q.reason {
                let _ = writeln!(out, "  reason:              {reason}");
            }
            if let Some(target) = &q.sweep_target {
                let target_rendered =
                    format_operator_with_lookup(target, None, name_lookup);
                let _ = writeln!(out, "  sweep_target:        {target_rendered}");
            }
        }
    }
}

fn render_task_table<W: Write>(out: &mut W, tasks: &[TaskRow]) {
    let _ = writeln!(out, "Tasks ({n}):", n = tasks.len());
    if tasks.is_empty() {
        let _ = writeln!(out, "  (no tasks under this initiative)");
        return;
    }
    let _ = writeln!(
        out,
        "  {tid:<24} {state:<24} {lane:<14} {ts:<12} {actor}",
        tid   = "task_id",
        state = "state",
        lane  = "lane",
        ts    = "transitioned_at",
        actor = "actor",
    );
    for t in tasks {
        let _ = writeln!(
            out,
            "  {tid:<24} {state:<24} {lane:<14} {ts:<12} {actor}",
            tid   = truncate(&t.task_id, 24),
            state = truncate(&t.state, 24),
            lane  = truncate(&t.lane_id, 14),
            ts    = t.transitioned_at,
            actor = truncate(&t.actor, 16),
        );
    }
}

// ────────────────────────────────────────────────────────────────────
// Rendering — JSON
// ────────────────────────────────────────────────────────────────────

fn render_json<W: Write>(
    out:         &mut W,
    initiative:  &InitiativeRow,
    plan:        Option<&SignedPlanArtifactHeader>,
    quarantine:  Option<&InitiativeQuarantineRow>,
    tasks:       &[TaskRow],
    name_lookup: &OperatorNameLookup,
) {
    let v = serde_json::json!({
        "initiative_id":        initiative.initiative_id,
        "state":                initiative.state,
        "plan_artifact_sha256": initiative.plan_artifact_sha256,
        "created_at":           initiative.created_at,
        "approved_at":          initiative.approved_at,
        "completed_at":         initiative.completed_at,
        "plan_signature":       serialize_plan_header(plan, name_lookup),
        "quarantine":           serialize_quarantine(quarantine, name_lookup),
        "tasks":                tasks.iter().map(serialize_task).collect::<Vec<_>>(),
    });
    let _ = serde_json::to_writer(&mut *out, &v);
    let _ = writeln!(out);
}

fn serialize_plan_header(
    plan:        Option<&SignedPlanArtifactHeader>,
    name_lookup: &OperatorNameLookup,
) -> serde_json::Value {
    match plan {
        None => serde_json::json!(null),
        Some(h) => {
            let signed_by = h.signed_by_fingerprint.as_deref().map(|fp| {
                serde_json::json!({
                    "fingerprint":  fp,
                    "fingerprint_prefix": fingerprint_prefix(fp),
                    "display":      format_operator_with_lookup(fp, None, name_lookup),
                })
            });
            serde_json::json!({
                "signed_by":  signed_by,
                "stored_at":  h.stored_at,
            })
        }
    }
}

fn serialize_quarantine(
    q:           Option<&InitiativeQuarantineRow>,
    name_lookup: &OperatorNameLookup,
) -> serde_json::Value {
    match q {
        None => serde_json::json!({ "quarantined": false }),
        Some(q) => serde_json::json!({
            "quarantined":     true,
            "quarantined_at":  q.quarantined_at,
            "quarantined_by":  {
                "fingerprint":        q.quarantined_by,
                "fingerprint_prefix": fingerprint_prefix(&q.quarantined_by),
                "display": format_operator_with_lookup(
                    &q.quarantined_by, None, name_lookup,
                ),
            },
            "reason":          q.reason,
            "sweep_target":    q.sweep_target.as_ref().map(|t| serde_json::json!({
                "fingerprint":        t,
                "fingerprint_prefix": fingerprint_prefix(t),
                "display": format_operator_with_lookup(t, None, name_lookup),
            })),
        }),
    }
}

fn serialize_task(t: &TaskRow) -> serde_json::Value {
    serde_json::json!({
        "task_id":          t.task_id,
        "state":            t.state,
        "lane_id":          t.lane_id,
        "actor":            t.actor,
        "policy_epoch":     t.policy_epoch,
        "admitted_at":      t.admitted_at,
        "transitioned_at":  t.transitioned_at,
        "block_reason":     t.block_reason,
        "session_id":       t.session_id,
        "evaluation_sha":   t.evaluation_sha,
        "base_sha":         t.base_sha,
        "actual_cost":      t.actual_cost,
    })
}

// ────────────────────────────────────────────────────────────────────
// Helpers
// ────────────────────────────────────────────────────────────────────

/// Right-truncate with `…` so column widths stay stable. Same
/// helper shape as `commands::inspect::truncate`.
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

#[derive(Debug, Clone)]
struct InspectInitiativeOpts {
    initiative_id: String,
    json:          bool,
    with_tasks:    bool,
    task_limit:    usize,
}

impl Default for InspectInitiativeOpts {
    fn default() -> Self {
        Self {
            initiative_id: String::new(),
            json:          false,
            with_tasks:    false,
            task_limit:    DEFAULT_TASK_LIMIT,
        }
    }
}

fn parse_args(args: &[String]) -> Result<InspectInitiativeOpts, CliError> {
    let mut opts = InspectInitiativeOpts::default();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--json" => opts.json = true,
            "--with-tasks" => opts.with_tasks = true,
            "--task-limit" => {
                i += 1;
                let v = args.get(i).ok_or_else(|| {
                    CliError::Usage("--task-limit requires an argument".to_owned())
                })?;
                opts.task_limit = v.parse::<usize>().map_err(|_| {
                    CliError::Usage(format!(
                        "--task-limit must be a non-negative integer (got {v:?})"
                    ))
                })?;
            }
            "-h" | "--help" => {
                print_help();
                std::process::exit(0);
            }
            other if !other.starts_with('-') => {
                if !opts.initiative_id.is_empty() {
                    return Err(CliError::Usage(format!(
                        "unexpected positional argument {other:?} (initiative_id already set)"
                    )));
                }
                opts.initiative_id = other.to_owned();
            }
            other => {
                return Err(CliError::Usage(format!(
                    "unknown inspect-initiative flag: {other:?}"
                )));
            }
        }
        i += 1;
    }
    if opts.initiative_id.is_empty() {
        return Err(CliError::Usage(
            "raxis inspect-initiative <initiative_id> requires an initiative_id positional argument".to_owned(),
        ));
    }
    Ok(opts)
}

fn print_help() {
    println!(
        "raxis inspect-initiative — forensic deep-dive into a single initiative\n\
         \n\
         USAGE:\n\
         \traxis inspect-initiative <initiative_id> [--json] [--with-tasks] [--task-limit N]\n\
         \n\
         FLAGS:\n\
         \t--json              emit a single JSON object\n\
         \t--with-tasks        expand the per-task table (default: count only)\n\
         \t--task-limit N      cap the per-task table at N rows (default: 100)\n\
         \n\
         JOINS the following read views in one snapshot:\n\
         \t• initiatives.by_id            — state + plan sha + timestamps\n\
         \t• signed_plan_artifacts        — signed_by + stored_at (header only;\n\
         \t                                  plan_bytes is NEVER surfaced)\n\
         \t• initiative_quarantines       — quarantine status + issuing operator\n\
         \t• tasks.list_by_initiative     — every task, oldest-first by admitted_at\n\
         \n\
         Operator fingerprints (signed_by, quarantined_by) are rendered with\n\
         their display names per `kernel-store.md` §2.5.2."
    );
}

// ────────────────────────────────────────────────────────────────────
// Tests
// ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_initiative() -> InitiativeRow {
        InitiativeRow {
            initiative_id:        "init-abc-123".to_owned(),
            state:                "Executing".to_owned(),
            plan_artifact_sha256: "deadbeef".to_owned(),
            created_at:           1_700_000_000,
            approved_at:          Some(1_700_000_010),
            completed_at:         None,
        }
    }

    fn sample_plan_header() -> SignedPlanArtifactHeader {
        SignedPlanArtifactHeader {
            initiative_id:         "init-abc-123".to_owned(),
            signed_by_fingerprint: Some("abcd1234abcd1234abcd1234abcd1234".to_owned()),
            stored_at:             1_700_000_005,
        }
    }

    fn sample_task() -> TaskRow {
        TaskRow {
            task_id:                  "task-alpha".to_owned(),
            initiative_id:            "init-abc-123".to_owned(),
            initiative_state:         "Executing".to_owned(),
            lane_id:                  "default".to_owned(),
            state:                    "Running".to_owned(),
            block_reason:             None,
            actor:                    "planner".to_owned(),
            policy_epoch:             1,
            admitted_at:              1_700_000_020,
            transitioned_at:          1_700_000_030,
            session_id:               Some("s-1".to_owned()),
            evaluation_sha:           Some("abc123".to_owned()),
            base_sha:                 Some("def456".to_owned()),
            admission_reserved_units: Some(5),
            actual_cost:              3,
        }
    }

    fn sample_quarantine() -> InitiativeQuarantineRow {
        InitiativeQuarantineRow {
            initiative_id:  "init-abc-123".to_owned(),
            quarantined_at: 1_700_000_040,
            quarantined_by: "abcd1234abcd1234abcd1234abcd1234".to_owned(),
            reason:         Some("compromised key suspected".to_owned()),
            sweep_target:   None,
        }
    }

    fn lookup_with_chika() -> OperatorNameLookup {
        OperatorNameLookup::from_pairs([
            ("abcd1234abcd1234abcd1234abcd1234", "Chika"),
        ])
    }

    // ── argument parsing ─────────────────────────────────────────

    #[test]
    fn parse_args_requires_initiative_id() {
        let err = parse_args(&[]).unwrap_err();
        assert!(matches!(err, CliError::Usage(_)));
    }

    #[test]
    fn parse_args_accepts_initiative_id_and_flags() {
        let opts = parse_args(&[
            "init-007".to_owned(),
            "--json".to_owned(),
            "--with-tasks".to_owned(),
            "--task-limit".to_owned(),
            "42".to_owned(),
        ]).unwrap();
        assert_eq!(opts.initiative_id, "init-007");
        assert!(opts.json);
        assert!(opts.with_tasks);
        assert_eq!(opts.task_limit, 42);
    }

    #[test]
    fn parse_args_rejects_two_positionals() {
        let err = parse_args(&[
            "init-1".to_owned(),
            "init-2".to_owned(),
        ]).unwrap_err();
        assert!(matches!(err, CliError::Usage(_)));
    }

    #[test]
    fn parse_args_rejects_unknown_flag() {
        let err = parse_args(&[
            "init-1".to_owned(),
            "--bogus".to_owned(),
        ]).unwrap_err();
        assert!(matches!(err, CliError::Usage(_)));
    }

    #[test]
    fn parse_args_rejects_non_numeric_task_limit() {
        let err = parse_args(&[
            "init-1".to_owned(),
            "--task-limit".to_owned(),
            "not-a-number".to_owned(),
        ]).unwrap_err();
        assert!(matches!(err, CliError::Usage(_)));
    }

    #[test]
    fn parse_args_default_task_limit_is_one_hundred() {
        let opts = parse_args(&["init-1".to_owned()]).unwrap();
        assert_eq!(opts.task_limit, DEFAULT_TASK_LIMIT);
        assert_eq!(opts.task_limit, 100);
    }

    // ── human render ─────────────────────────────────────────────

    #[test]
    fn render_human_includes_state_plan_sha_and_quarantine_no() {
        let init = sample_initiative();
        let lookup = OperatorNameLookup::empty();
        let mut buf: Vec<u8> = Vec::new();
        render_human(&mut buf, &init, None, None, &[], false, &lookup);
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("Initiative init-abc-123"), "got: {s}");
        assert!(s.contains("state:               Executing"), "got: {s}");
        assert!(s.contains("plan_sha256:         deadbeef"), "got: {s}");
        assert!(
            s.contains("Quarantine:            NO"),
            "Quarantine:NO line MUST be present when no quarantine row exists; got: {s}",
        );
        assert!(
            s.contains("approved_at:         1700000010"),
            "approved_at MUST be surfaced when set; got: {s}",
        );
        assert!(
            !s.contains("completed_at:"),
            "completed_at MUST be omitted when None to keep terse output: {s}",
        );
    }

    #[test]
    fn render_human_resolves_signed_by_with_lookup() {
        let init = sample_initiative();
        let plan = sample_plan_header();
        let lookup = lookup_with_chika();
        let mut buf: Vec<u8> = Vec::new();
        render_human(
            &mut buf, &init, Some(&plan), None, &[], false, &lookup,
        );
        let s = String::from_utf8(buf).unwrap();
        // Lookup hit means the name is rendered with the
        // historical-cert annotation (the audit-event-style
        // snapshot is not available for plan rows; the live
        // lookup is the only source). Pinning the prefix
        // formatting here pins the §2.5.2 contract.
        assert!(
            s.contains("Chika (abcd1234)"),
            "signed_by MUST render as 'Chika (abcd1234)' when the lookup resolves; got: {s}",
        );
    }

    #[test]
    fn render_human_handles_legacy_plan_row_with_null_signed_by() {
        let init = sample_initiative();
        let plan = SignedPlanArtifactHeader {
            initiative_id:         "init-abc-123".to_owned(),
            signed_by_fingerprint: None,
            stored_at:             1_700_000_005,
        };
        let lookup = OperatorNameLookup::empty();
        let mut buf: Vec<u8> = Vec::new();
        render_human(
            &mut buf, &init, Some(&plan), None, &[], false, &lookup,
        );
        let s = String::from_utf8(buf).unwrap();
        assert!(
            s.contains("(legacy: pre-migration-3 row, fingerprint not recorded)"),
            "legacy NULL signed_by MUST surface a clear explanation; got: {s}",
        );
        assert!(
            s.contains("stored_at:           1700000005"),
            "stored_at MUST always render even when signed_by is NULL: {s}",
        );
    }

    #[test]
    fn render_human_includes_quarantine_block_when_present() {
        let init = sample_initiative();
        let q    = sample_quarantine();
        let lookup = lookup_with_chika();
        let mut buf: Vec<u8> = Vec::new();
        render_human(
            &mut buf, &init, None, Some(&q), &[], false, &lookup,
        );
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("Quarantine:            YES"), "got: {s}");
        assert!(s.contains("compromised key suspected"), "reason MUST surface: {s}");
        assert!(
            s.contains("quarantined_by:      Chika (abcd1234)"),
            "quarantined_by MUST resolve through the operator lookup: {s}",
        );
    }

    #[test]
    fn render_human_shows_count_only_without_with_tasks() {
        let init = sample_initiative();
        let lookup = OperatorNameLookup::empty();
        let tasks = vec![sample_task()];
        let mut buf: Vec<u8> = Vec::new();
        render_human(
            &mut buf, &init, None, None, &tasks, false, &lookup,
        );
        let s = String::from_utf8(buf).unwrap();
        assert!(
            s.contains("Tasks (1): use --with-tasks to expand"),
            "default render MUST surface the count + the --with-tasks hint: {s}",
        );
        assert!(
            !s.contains("task-alpha"),
            "without --with-tasks, task ids MUST NOT be rendered: {s}",
        );
    }

    #[test]
    fn render_human_with_tasks_expands_table() {
        let init = sample_initiative();
        let lookup = OperatorNameLookup::empty();
        let tasks = vec![sample_task()];
        let mut buf: Vec<u8> = Vec::new();
        render_human(
            &mut buf, &init, None, None, &tasks, true, &lookup,
        );
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("Tasks (1):"), "got: {s}");
        assert!(s.contains("task-alpha"), "task_id MUST surface: {s}");
        assert!(s.contains("Running"),    "state MUST surface: {s}");
        assert!(s.contains("default"),    "lane MUST surface: {s}");
    }

    #[test]
    fn render_human_with_tasks_handles_empty_list() {
        let init = sample_initiative();
        let lookup = OperatorNameLookup::empty();
        let mut buf: Vec<u8> = Vec::new();
        render_human(
            &mut buf, &init, None, None, &[], true, &lookup,
        );
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("Tasks (0):"), "got: {s}");
        assert!(
            s.contains("(no tasks under this initiative)"),
            "empty task list MUST surface an explicit no-rows message: {s}",
        );
    }

    // ── JSON render ──────────────────────────────────────────────

    #[test]
    fn render_json_emits_every_top_level_key() {
        let init   = sample_initiative();
        let plan   = sample_plan_header();
        let q      = sample_quarantine();
        let lookup = lookup_with_chika();
        let tasks  = vec![sample_task()];
        let mut buf: Vec<u8> = Vec::new();
        render_json(
            &mut buf, &init, Some(&plan), Some(&q), &tasks, &lookup,
        );
        let v: serde_json::Value =
            serde_json::from_slice(&buf).expect("json render must parse back");
        for k in [
            "initiative_id", "state", "plan_artifact_sha256", "created_at",
            "approved_at", "completed_at", "plan_signature", "quarantine", "tasks",
        ] {
            assert!(v.get(k).is_some(), "missing key {k}; got {v}");
        }
        // Nested plan_signature shape.
        assert_eq!(
            v["plan_signature"]["signed_by"]["fingerprint"],
            serde_json::json!("abcd1234abcd1234abcd1234abcd1234"),
        );
        assert_eq!(
            v["plan_signature"]["signed_by"]["fingerprint_prefix"],
            serde_json::json!("abcd1234"),
        );
        assert!(v["plan_signature"]["signed_by"]["display"]
            .as_str().unwrap_or("").contains("Chika"));
        // Quarantine projection — `quarantined: true` discriminator.
        assert_eq!(v["quarantine"]["quarantined"], serde_json::json!(true));
        assert_eq!(v["quarantine"]["reason"], serde_json::json!("compromised key suspected"));
        // Task list — exactly one row, with the expected task_id.
        assert_eq!(v["tasks"][0]["task_id"], serde_json::json!("task-alpha"));
        assert_eq!(v["tasks"][0]["state"],   serde_json::json!("Running"));
    }

    #[test]
    fn render_json_quarantine_false_when_no_quarantine_row() {
        let init   = sample_initiative();
        let lookup = OperatorNameLookup::empty();
        let mut buf: Vec<u8> = Vec::new();
        render_json(
            &mut buf, &init, None, None, &[], &lookup,
        );
        let v: serde_json::Value = serde_json::from_slice(&buf).unwrap();
        assert_eq!(
            v["quarantine"],
            serde_json::json!({ "quarantined": false }),
            "quarantine block MUST surface a discriminated `quarantined: false` shape; got: {v}",
        );
        assert_eq!(
            v["plan_signature"], serde_json::json!(null),
            "plan_signature MUST be null when no signed_plan_artifacts row exists",
        );
        assert_eq!(v["tasks"], serde_json::json!([]),
            "tasks key MUST always be an array, even when empty");
    }

    #[test]
    fn truncate_helper_stays_pinned_to_inspect_semantics() {
        // Sanity check — same shape as commands::inspect::truncate.
        assert_eq!(truncate("short", 10), "short");
        assert_eq!(truncate("very-long-task-id-name", 10), "very-long…");
        assert_eq!(truncate("x", 1), "x");
        assert_eq!(truncate("ab", 1), "…");
    }
}

//! `raxis inspect <task_id>` — forensic deep-dive into a single task.
//!
//! Normative reference: cli-readonly.md §5.5.6.
//!
//! Joins:
//!   * `tasks` (via `views::tasks::by_id`) — base row
//!   * `task_dag_edges` (via `views::tasks::dag_edges_for_task`) —
//!     upstream + downstream dependencies
//!   * `witness_records` (via `views::witnesses::for_task`) — every
//!     witness for the task, newest-first
//!
//! Spec sections deferred to a future commit (cli-readonly.md
//! §5.5.6 v1 ↗ v1.x):
//!   * `task_intent_ranges` — kernel-internal; no CLI-visible
//!     query path yet.
//!   * `verifier_run_tokens` outstanding/consumed counts — would
//!     require `views::verifier_tokens::for_task`. We render
//!     witness counts in lieu and call out the gap.
//!   * `--reveal-paths` / `path_allowlist` reveal — requires the
//!     kernel to emit `PathReadAccessed` audit events through
//!     operator IPC. The current CLI does NOT have a write
//!     channel for that; v1.x adds it as part of the audit-write
//!     IPC handler. Today `--reveal-paths` returns an explicit
//!     "not implemented in v1" error rather than silently leaking
//!     paths.
//!
//! These deferrals are intentional and make the v1 surface a
//! complete forensic tool for the OBSERVABLE state — the
//! deferred bits are all about kernel-internal data the operator
//! cannot mutate based on without the corresponding IPC handler.

use std::io::Write;

use raxis_store::open_ro;
use raxis_store::views::tasks::{
    by_id, dag_edges_for_task, DagEdgeRow, EdgeDirection, TaskRow,
};
use raxis_store::views::witnesses::{for_task as witnesses_for_task, WitnessRow};

use crate::errors::CliError;
use crate::GlobalFlags;

pub fn run(flags: &GlobalFlags, args: &[String]) -> Result<(), CliError> {
    let opts = parse_args(args)?;

    if opts.reveal_paths {
        return Err(CliError::Usage(
            "--reveal-paths is reserved per cli-readonly.md §5.5.6 but not yet \
             implemented in v1 (requires the kernel-side PathReadAccessed audit \
             handler, deferred to v1.x)"
                .to_owned(),
        ));
    }

    let conn = open_ro(flags.data_dir()).map_err(|e| {
        CliError::Policy(format!("kernel.db open failed: {e}"))
    })?;

    let row = by_id(&conn, &opts.task_id)
        .map_err(|e| CliError::Policy(format!("tasks::by_id failed: {e}")))?
        .ok_or_else(|| {
            CliError::KernelError {
                code: "TASK_NOT_FOUND".to_owned(),
                detail: format!("no task with id {:?}", opts.task_id),
            }
        })?;

    let upstream = dag_edges_for_task(&conn, &opts.task_id, EdgeDirection::Upstream)
        .map_err(|e| CliError::Policy(format!("dag_edges_for_task(up) failed: {e}")))?;
    let downstream = dag_edges_for_task(&conn, &opts.task_id, EdgeDirection::Downstream)
        .map_err(|e| CliError::Policy(format!("dag_edges_for_task(down) failed: {e}")))?;
    let witnesses = witnesses_for_task(&conn, &opts.task_id)
        .map_err(|e| CliError::Policy(format!("witnesses::for_task failed: {e}")))?;

    let stdout = std::io::stdout();
    let mut out = stdout.lock();

    if opts.json {
        render_json(&mut out, &row, &upstream, &downstream, &witnesses);
    } else if opts.gates_only {
        render_gates_only(&mut out, &row.task_id, &witnesses);
    } else {
        render_full(
            &mut out,
            &row,
            &upstream,
            &downstream,
            &witnesses,
            opts.with_deps,
        );
    }
    let _ = out.flush();
    Ok(())
}

// ────────────────────────────────────────────────────────────────────
// Rendering
// ────────────────────────────────────────────────────────────────────

fn render_full<W: Write>(
    out: &mut W,
    row: &TaskRow,
    upstream: &[DagEdgeRow],
    downstream: &[DagEdgeRow],
    witnesses: &[WitnessRow],
    with_deps: bool,
) {
    let _ = writeln!(out, "Task {}", row.task_id);
    let _ = writeln!(out, "  initiative:        {}", row.initiative_id);
    let _ = writeln!(out, "  initiative_state:  {}", row.initiative_state);
    let _ = writeln!(out, "  state:             {}", row.state);
    let _ = writeln!(out, "  lane:              {}", row.lane_id);
    let _ = writeln!(out, "  actor:             {}", row.actor);
    let _ = writeln!(out, "  policy_epoch:      {}", row.policy_epoch);
    let _ = writeln!(out, "  admitted_at:       {}", row.admitted_at);
    let _ = writeln!(out, "  transitioned_at:   {}", row.transitioned_at);
    if let Some(b) = &row.block_reason {
        let _ = writeln!(out, "  block_reason:      {b}");
    }
    if let Some(s) = &row.session_id {
        let _ = writeln!(out, "  session_id:        {s}");
    }
    if let Some(s) = &row.evaluation_sha {
        let _ = writeln!(out, "  evaluation_sha:    {s}");
    }
    if let Some(s) = &row.base_sha {
        let _ = writeln!(out, "  base_sha:          {s}");
    }
    if let Some(u) = row.admission_reserved_units {
        let _ = writeln!(out, "  reserved_units:    {u}");
    }
    let _ = writeln!(out, "  actual_cost:       {}", row.actual_cost);

    let _ = writeln!(out);
    let _ = writeln!(out, "Plan fields:");
    let _ = writeln!(
        out,
        "  path_allowlist:           <reserved; --reveal-paths in v1.x>"
    );
    let _ = writeln!(
        out,
        "  path_export_to_successors: <reserved; --reveal-paths in v1.x>"
    );

    if with_deps {
        let _ = writeln!(out);
        render_deps(out, upstream, downstream);
    } else {
        let _ = writeln!(out);
        let _ = writeln!(
            out,
            "Dependencies:        upstream={u} downstream={d}  (use --with-deps to expand)",
            u = upstream.len(),
            d = downstream.len(),
        );
    }

    let _ = writeln!(out);
    render_witnesses(out, witnesses);

    let _ = writeln!(out);
    let _ = writeln!(out, "Verifier tokens (v1):");
    let _ = writeln!(
        out,
        "  Witness records: {n}   (pending tokens — Phase B2.5)",
        n = witnesses.len()
    );
}

fn render_gates_only<W: Write>(out: &mut W, task_id: &str, witnesses: &[WitnessRow]) {
    let _ = writeln!(out, "Task {task_id} — gate witnesses:");
    render_witnesses(out, witnesses);
}

fn render_witnesses<W: Write>(out: &mut W, witnesses: &[WitnessRow]) {
    let _ = writeln!(out, "Witnesses ({n}):", n = witnesses.len());
    if witnesses.is_empty() {
        let _ = writeln!(out, "  (no witnesses recorded)");
        return;
    }
    let _ = writeln!(
        out,
        "  {run_id:<22} {gate:<14} {result:<13} recorded_at",
        run_id = "verifier_run_id",
        gate = "gate_type",
        result = "result_class",
    );
    for w in witnesses {
        let _ = writeln!(
            out,
            "  {run_id:<22} {gate:<14} {result:<13} {ts}",
            run_id = truncate(&w.verifier_run_id, 22),
            gate = truncate(&w.gate_type, 14),
            result = truncate(&w.result_class, 13),
            ts = w.recorded_at,
        );
    }
}

fn render_deps<W: Write>(out: &mut W, upstream: &[DagEdgeRow], downstream: &[DagEdgeRow]) {
    let _ = writeln!(out, "Dependencies:");
    let _ = writeln!(out, "  upstream ({n}):", n = upstream.len());
    if upstream.is_empty() {
        let _ = writeln!(out, "    (none)");
    }
    for e in upstream {
        let satisfied = if e.predecessor_satisfied { "satisfied" } else { "PENDING" };
        let _ = writeln!(
            out,
            "    {tid:<22} {state:<22} {satisfied}",
            tid = truncate(&e.other_task_id, 22),
            state = truncate(&e.other_task_state, 22),
        );
    }
    let _ = writeln!(out, "  downstream ({n}):", n = downstream.len());
    if downstream.is_empty() {
        let _ = writeln!(out, "    (none)");
    }
    for e in downstream {
        // For downstream edges, `predecessor_satisfied` reflects whether the
        // CURRENT task (the predecessor) has satisfied this dependency for the
        // downstream successor. `false` => the successor is still waiting on
        // us. We surface this as PENDING so operators can immediately spot
        // tasks that other work is blocked on.
        let waiting = if e.predecessor_satisfied { "released" } else { "PENDING" };
        let _ = writeln!(
            out,
            "    {tid:<22} {state:<22} {waiting}",
            tid = truncate(&e.other_task_id, 22),
            state = truncate(&e.other_task_state, 22),
        );
    }
}

fn render_json<W: Write>(
    out: &mut W,
    row: &TaskRow,
    upstream: &[DagEdgeRow],
    downstream: &[DagEdgeRow],
    witnesses: &[WitnessRow],
) {
    let v = serde_json::json!({
        "task_id":           row.task_id,
        "initiative_id":     row.initiative_id,
        "initiative_state":  row.initiative_state,
        "state":             row.state,
        "lane_id":           row.lane_id,
        "actor":             row.actor,
        "policy_epoch":      row.policy_epoch,
        "admitted_at":       row.admitted_at,
        "transitioned_at":   row.transitioned_at,
        "block_reason":      row.block_reason,
        "session_id":        row.session_id,
        "evaluation_sha":    row.evaluation_sha,
        "base_sha":          row.base_sha,
        "admission_reserved_units": row.admission_reserved_units,
        "actual_cost":       row.actual_cost,
        "plan_fields":       {
            "redacted_in_v1": [
                "path_allowlist",
                "path_export_to_successors",
                "path_export_globs",
                "path_scope_override",
            ],
        },
        "dependencies": {
            "upstream":   upstream.iter().map(serialize_edge).collect::<Vec<_>>(),
            "downstream": downstream.iter().map(serialize_edge).collect::<Vec<_>>(),
        },
        "witnesses": witnesses.iter().map(serialize_witness).collect::<Vec<_>>(),
    });
    let _ = serde_json::to_writer(&mut *out, &v);
    let _ = writeln!(out);
}

fn serialize_edge(e: &DagEdgeRow) -> serde_json::Value {
    serde_json::json!({
        "task_id":               e.other_task_id,
        "state":                 e.other_task_state,
        "predecessor_satisfied": e.predecessor_satisfied,
    })
}

fn serialize_witness(w: &WitnessRow) -> serde_json::Value {
    serde_json::json!({
        "verifier_run_id": w.verifier_run_id,
        "task_id":         w.task_id,
        "gate_type":       w.gate_type,
        "result_class":    w.result_class,
        "evaluation_sha":  w.evaluation_sha,
        "blob_sha256":     w.blob_sha256,
        "recorded_at":     w.recorded_at,
    })
}

/// Right-truncate with `…` so column widths stay stable. Same helper
/// shape as `commands::queue::truncate`.
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
struct InspectOpts {
    task_id: String,
    json: bool,
    gates_only: bool,
    with_deps: bool,
    reveal_paths: bool,
}

fn parse_args(args: &[String]) -> Result<InspectOpts, CliError> {
    let mut opts = InspectOpts::default();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--json" => opts.json = true,
            "--gates-only" => opts.gates_only = true,
            "--with-deps" => opts.with_deps = true,
            "--reveal-paths" => opts.reveal_paths = true,
            "-h" | "--help" => {
                print_help();
                std::process::exit(0);
            }
            other if !other.starts_with('-') => {
                if !opts.task_id.is_empty() {
                    return Err(CliError::Usage(format!(
                        "unexpected positional argument {other:?} (task_id already set)"
                    )));
                }
                opts.task_id = other.to_owned();
            }
            other => {
                return Err(CliError::Usage(format!(
                    "unknown inspect flag: {other:?}"
                )));
            }
        }
        i += 1;
    }
    if opts.task_id.is_empty() {
        return Err(CliError::Usage(
            "raxis inspect <task_id> requires a task_id positional argument".to_owned(),
        ));
    }
    Ok(opts)
}

fn print_help() {
    println!(
        "raxis inspect — forensic deep-dive into a single task\n\
         \n\
         USAGE:\n\
         \tlraxis inspect <task_id> [--json] [--gates-only] [--with-deps]\n\
         \n\
         FLAGS:\n\
         \t--json           emit a single JSON object\n\
         \t--gates-only     show only the witnesses section\n\
         \t--with-deps      expand the upstream + downstream tables\n\
         \t--reveal-paths   reserved (v1.x; emits PathReadAccessed audit event)"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_row() -> TaskRow {
        TaskRow {
            task_id: "t-1".to_owned(),
            initiative_id: "init-1".to_owned(),
            initiative_state: "Executing".to_owned(),
            lane_id: "default".to_owned(),
            state: "Running".to_owned(),
            block_reason: None,
            actor: "op".to_owned(),
            policy_epoch: 1,
            admitted_at: 100,
            transitioned_at: 200,
            session_id: Some("s-1".to_owned()),
            evaluation_sha: Some("abc123".to_owned()),
            base_sha: Some("def456".to_owned()),
            admission_reserved_units: Some(5),
            actual_cost: 3,
        }
    }

    fn sample_witness() -> WitnessRow {
        WitnessRow {
            verifier_run_id: "run-1".to_owned(),
            task_id: "t-1".to_owned(),
            gate_type: "tests".to_owned(),
            result_class: "Pass".to_owned(),
            evaluation_sha: "abc123".to_owned(),
            blob_sha256: "def456".to_owned(),
            recorded_at: 250,
        }
    }

    #[test]
    fn parse_args_requires_task_id() {
        let err = parse_args(&[]).unwrap_err();
        assert!(matches!(err, CliError::Usage(_)));
    }

    #[test]
    fn parse_args_accepts_task_id_and_flags() {
        let opts = parse_args(&[
            "t-007".to_owned(),
            "--with-deps".to_owned(),
            "--gates-only".to_owned(),
        ]).unwrap();
        assert_eq!(opts.task_id, "t-007");
        assert!(opts.with_deps);
        assert!(opts.gates_only);
    }

    #[test]
    fn parse_args_rejects_two_positionals() {
        let err = parse_args(&["t-1".to_owned(), "t-2".to_owned()]).unwrap_err();
        assert!(matches!(err, CliError::Usage(_)));
    }

    #[test]
    fn parse_args_rejects_unknown_flag() {
        let err = parse_args(&["t-1".to_owned(), "--bogus".to_owned()]).unwrap_err();
        assert!(matches!(err, CliError::Usage(_)));
    }

    #[test]
    fn render_full_includes_all_fields() {
        let mut buf: Vec<u8> = Vec::new();
        let row = sample_row();
        let w = vec![sample_witness()];
        render_full(&mut buf, &row, &[], &[], &w, false);
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("Task t-1"), "got: {s}");
        assert!(s.contains("initiative_id" /* unused but defensive */) || s.contains("initiative:"),
            "got: {s}");
        assert!(s.contains("state:             Running"), "got: {s}");
        assert!(s.contains("Witnesses (1)"), "got: {s}");
        assert!(s.contains("(use --with-deps to expand)"), "got: {s}");
    }

    #[test]
    fn render_full_with_deps_expands_dependency_table() {
        let upstream = vec![DagEdgeRow {
            other_task_id: "t-up".to_owned(),
            other_task_state: "Completed".to_owned(),
            predecessor_satisfied: true,
        }];
        let downstream = vec![DagEdgeRow {
            other_task_id: "t-dn".to_owned(),
            other_task_state: "Admitted".to_owned(),
            predecessor_satisfied: false,
        }];
        let mut buf: Vec<u8> = Vec::new();
        render_full(&mut buf, &sample_row(), &upstream, &downstream, &[], true);
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("upstream (1)"), "got: {s}");
        assert!(s.contains("downstream (1)"), "got: {s}");
        assert!(s.contains("t-up"), "got: {s}");
        assert!(s.contains("t-dn"), "got: {s}");
        assert!(s.contains("satisfied"), "got: {s}");
        assert!(s.contains("PENDING"), "got: {s}");
    }

    #[test]
    fn render_gates_only_omits_task_metadata() {
        let mut buf: Vec<u8> = Vec::new();
        render_gates_only(&mut buf, "t-1", &[sample_witness()]);
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("Task t-1 — gate witnesses:"), "got: {s}");
        assert!(s.contains("Witnesses (1)"), "got: {s}");
        assert!(!s.contains("policy_epoch"), "must omit task header: {s}");
    }

    #[test]
    fn render_witnesses_handles_empty() {
        let mut buf: Vec<u8> = Vec::new();
        render_witnesses(&mut buf, &[]);
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("Witnesses (0)"), "got: {s}");
        assert!(s.contains("no witnesses recorded"), "got: {s}");
    }

    #[test]
    fn render_json_emits_object_with_expected_keys() {
        let mut buf: Vec<u8> = Vec::new();
        render_json(&mut buf, &sample_row(), &[], &[], &[sample_witness()]);
        let v: serde_json::Value =
            serde_json::from_slice(&buf).expect("json render must parse back");
        for k in [
            "task_id", "initiative_id", "initiative_state", "state",
            "lane_id", "policy_epoch", "plan_fields", "dependencies", "witnesses",
        ] {
            assert!(v.get(k).is_some(), "missing key {k}; got {v}");
        }
        assert_eq!(v["witnesses"][0]["gate_type"], serde_json::json!("tests"));
        assert!(v["plan_fields"]["redacted_in_v1"].is_array());
    }

    #[test]
    fn truncate_reuses_queue_helper_semantics() {
        // Sanity check — same shape as commands::queue::truncate.
        assert_eq!(truncate("short", 10), "short");
        assert_eq!(truncate("very-long-task-id-name", 10), "very-long…");
        assert_eq!(truncate("x", 1), "x");
        assert_eq!(truncate("ab", 1), "…");
    }
}

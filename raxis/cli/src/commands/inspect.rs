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
//!   * `signed_plan_artifacts.plan_bytes` (via
//!     `views::plan_fields::reveal_for_task`, behind `--reveal-paths`)
//!     — the §2.5.8 path-scope fields, with a `PathReadAccessed`
//!     audit record appended before the data is rendered.
//!
//! Spec sections deferred to a future commit (cli-readonly.md
//! §5.5.6 v1 ↗ v2):
//!   * `task_intent_ranges` — kernel-internal; no CLI-visible
//!     query path yet.
//!   * `verifier_run_tokens` outstanding/consumed counts — would
//!     require `views::verifier_tokens::for_task`. We render
//!     witness counts in lieu and call out the gap.
//!
//! These deferrals are intentional and make the v1 surface a
//! complete forensic tool for the OBSERVABLE state — the
//! deferred bits are all about kernel-internal data the operator
//! cannot mutate based on without the corresponding IPC handler.

use std::io::Write;

use raxis_store::open_ro;
use raxis_store::views::plan_fields::PlanPathFields;
use raxis_store::views::tasks::{by_id, dag_edges_for_task, DagEdgeRow, EdgeDirection, TaskRow};
use raxis_store::views::witnesses::{for_task as witnesses_for_task, WitnessRow};

use crate::errors::CliError;
use crate::reveal::reveal_path_fields;
use crate::GlobalFlags;

pub fn run(flags: &GlobalFlags, args: &[String]) -> Result<(), CliError> {
    let opts = parse_args(args)?;

    let conn = open_ro(flags.data_dir())
        .map_err(|e| CliError::Policy(format!("kernel.db open failed: {e}")))?;

    let row = by_id(&conn, &opts.task_id)
        .map_err(|e| CliError::Policy(format!("tasks::by_id failed: {e}")))?
        .ok_or_else(|| CliError::KernelError {
            code: "TASK_NOT_FOUND".to_owned(),
            detail: format!("no task with id {:?}", opts.task_id),
        })?;

    let upstream = dag_edges_for_task(&conn, &opts.task_id, EdgeDirection::Upstream)
        .map_err(|e| CliError::Policy(format!("dag_edges_for_task(up) failed: {e}")))?;
    let downstream = dag_edges_for_task(&conn, &opts.task_id, EdgeDirection::Downstream)
        .map_err(|e| CliError::Policy(format!("dag_edges_for_task(down) failed: {e}")))?;
    let witnesses = witnesses_for_task(&conn, &opts.task_id)
        .map_err(|e| CliError::Policy(format!("witnesses::for_task failed: {e}")))?;

    // Drop the read-only handle BEFORE we open the audit writer
    // (`reveal_path_fields` opens its own `RoConn`). They wouldn't
    // collide, but releasing the WAL snapshot early keeps the hot
    // path crisp for any concurrent kernel writer.
    drop(conn);

    // §5.4.2 / §5.7.2 — when `--reveal-paths` is set we must emit a
    // `PathReadAccessed` audit event BEFORE returning the data to
    // the renderer. `reveal_path_fields` enforces both halves of
    // the contract (lookup + audit append) so the inspect command
    // never has to care about ordering.
    let revealed: Option<PlanPathFields> = if opts.reveal_paths {
        Some(reveal_path_fields(flags, &opts.task_id, "inspect")?)
    } else {
        None
    };

    let stdout = std::io::stdout();
    let mut out = stdout.lock();

    if opts.json {
        render_json(
            &mut out,
            &row,
            &upstream,
            &downstream,
            &witnesses,
            revealed.as_ref(),
        );
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
            revealed.as_ref(),
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
    revealed: Option<&PlanPathFields>,
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
    render_plan_fields(out, revealed);

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

/// Render the §2.5.8 path-scope block. When `revealed` is `None`
/// (no `--reveal-paths` flag) we surface the same "pass --reveal-paths
/// to show" hint the spec sample uses (cli-readonly.md §5.5.6 sample
/// output, lines 461-464). When `revealed` is `Some`, we dump the
/// values verbatim — the audit event has already been emitted by
/// `reveal::reveal_path_fields` before this function runs.
fn render_plan_fields<W: Write>(out: &mut W, revealed: Option<&PlanPathFields>) {
    match revealed {
        None => {
            let _ = writeln!(
                out,
                "  path_allowlist:            <pass --reveal-paths to show \
                 (writes a PathReadAccessed audit event)>"
            );
            let _ = writeln!(
                out,
                "  path_export_to_successors: <pass --reveal-paths to show>"
            );
            let _ = writeln!(
                out,
                "  path_export_globs:         <pass --reveal-paths to show>"
            );
            let _ = writeln!(
                out,
                "  path_scope_override:       <pass --reveal-paths to show>"
            );
            let _ = writeln!(
                out,
                "  session_agent_type:        <pass --reveal-paths to show>"
            );
            let _ = writeln!(
                out,
                "  model_chain:               <pass --reveal-paths to show>"
            );
        }
        Some(fields) => {
            render_path_list(out, "path_allowlist", &fields.path_allowlist);
            let _ = writeln!(
                out,
                "  path_export_to_successors: {}",
                fields.path_export_to_successors,
            );
            render_path_list(out, "path_export_globs", &fields.path_export_globs);
            let _ = writeln!(
                out,
                "  path_scope_override:       {}",
                fields.path_scope_override,
            );
            let _ = writeln!(
                out,
                "  session_agent_type:        {}",
                fields.session_agent_type,
            );
            render_path_list(out, "model_chain", &fields.model_chain);
        }
    }
}

/// Pretty-print a `Vec<String>` path list. Empty → `[]` on one
/// line; non-empty → header line with the count, then one entry
/// per indented line. Keeps the output `grep`-friendly while still
/// reading like a forensic report.
fn render_path_list<W: Write>(out: &mut W, label: &str, entries: &[String]) {
    if entries.is_empty() {
        let _ = writeln!(out, "  {label:<26} []");
        return;
    }
    let _ = writeln!(out, "  {label:<26} ({n} entries):", n = entries.len());
    for entry in entries {
        let _ = writeln!(out, "    - {entry}");
    }
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
        let satisfied = if e.predecessor_satisfied {
            "satisfied"
        } else {
            "PENDING"
        };
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
        let waiting = if e.predecessor_satisfied {
            "released"
        } else {
            "PENDING"
        };
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
    revealed: Option<&PlanPathFields>,
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
        "plan_fields":       serialize_plan_fields(revealed),
        "dependencies": {
            "upstream":   upstream.iter().map(serialize_edge).collect::<Vec<_>>(),
            "downstream": downstream.iter().map(serialize_edge).collect::<Vec<_>>(),
        },
        "witnesses": witnesses.iter().map(serialize_witness).collect::<Vec<_>>(),
    });
    let _ = serde_json::to_writer(&mut *out, &v);
    let _ = writeln!(out);
}

/// JSON projection of the `plan_fields` block. When `--reveal-paths`
/// is unset we emit a `redacted: true` marker (cli-readonly.md
/// §5.5.6 "Output (--json): single JSON object with the same fields;
/// redacted fields are emitted as `{redacted: true, len: 12}`"). When
/// the operator opted in via `--reveal-paths`, we emit the full
/// values plus `revealed: true` so consumers can tell the two
/// shapes apart.
fn serialize_plan_fields(revealed: Option<&PlanPathFields>) -> serde_json::Value {
    match revealed {
        None => serde_json::json!({
            "revealed": false,
            "redacted_fields": [
                "path_allowlist",
                "path_export_to_successors",
                "path_export_globs",
                "path_scope_override",
                "session_agent_type",
                "model_chain",
            ],
            "hint": "pass --reveal-paths to expand (writes PathReadAccessed audit event)",
        }),
        Some(f) => serde_json::json!({
            "revealed":                  true,
            "path_allowlist":            f.path_allowlist,
            "path_export_to_successors": f.path_export_to_successors,
            "path_export_globs":         f.path_export_globs,
            "path_scope_override":       f.path_scope_override,
            "session_agent_type":        f.session_agent_type,
            "model_chain":               f.model_chain,
        }),
    }
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
                return Err(CliError::Usage(format!("unknown inspect flag: {other:?}")));
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
         \traxis inspect <task_id> [--json] [--gates-only] [--with-deps] [--reveal-paths]\n\
         \n\
         FLAGS:\n\
         \t--json           emit a single JSON object\n\
         \t--gates-only     show only the witnesses section\n\
         \t--with-deps      expand the upstream + downstream tables\n\
         \t--reveal-paths   show task path_allowlist + path_export_globs in full\n\
         \t                 AND append a PathReadAccessed audit event\n\
         \t                 (cli-readonly.md §5.4.2 / §5.7.2)"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_row() -> TaskRow {
        TaskRow {
            task_id: "t-1".to_owned(),
            task_name: Some("sample-task".to_owned()),
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
        ])
        .unwrap();
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

    fn sample_revealed_fields() -> PlanPathFields {
        PlanPathFields {
            path_allowlist: vec!["src/**".to_owned(), "README.md".to_owned()],
            path_export_to_successors: true,
            path_export_globs: vec!["src/ipc/**".to_owned()],
            path_scope_override: false,
            session_agent_type: "Executor".to_owned(),
            max_review_rejections: 2,
            max_crash_retries: 1,
            ..Default::default()
        }
    }

    #[test]
    fn render_full_includes_all_fields_and_redaction_hint_by_default() {
        let mut buf: Vec<u8> = Vec::new();
        let row = sample_row();
        let w = vec![sample_witness()];
        render_full(&mut buf, &row, &[], &[], &w, false, None);
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("Task t-1"), "got: {s}");
        assert!(
            s.contains("initiative_id" /* unused but defensive */) || s.contains("initiative:"),
            "got: {s}"
        );
        assert!(s.contains("state:             Running"), "got: {s}");
        assert!(s.contains("Witnesses (1)"), "got: {s}");
        assert!(s.contains("(use --with-deps to expand)"), "got: {s}");
        // §5.5.6 sample output — when --reveal-paths is NOT set, we
        // render a short "pass --reveal-paths to show" hint instead
        // of the full path lists.
        assert!(
            s.contains("pass --reveal-paths to show"),
            "redacted state must hint --reveal-paths; got: {s}"
        );
        // No path data must escape into the default render.
        assert!(
            !s.contains("src/**"),
            "path data leaked without --reveal-paths: {s}"
        );
    }

    #[test]
    fn render_full_with_revealed_fields_shows_full_path_lists() {
        let mut buf: Vec<u8> = Vec::new();
        render_full(
            &mut buf,
            &sample_row(),
            &[],
            &[],
            &[],
            false,
            Some(&sample_revealed_fields()),
        );
        let s = String::from_utf8(buf).unwrap();
        // Both array entries surface verbatim.
        assert!(s.contains("src/**"), "got: {s}");
        assert!(s.contains("README.md"), "got: {s}");
        // Booleans render as `true`/`false` literals.
        assert!(s.contains("path_export_to_successors: true"), "got: {s}");
        assert!(s.contains("path_scope_override:       false"), "got: {s}");
        // The redaction hint must be GONE — once revealed, no hint.
        assert!(!s.contains("pass --reveal-paths"), "got: {s}");
    }

    #[test]
    fn render_full_revealed_empty_allowlist_uses_compact_brackets() {
        let mut buf: Vec<u8> = Vec::new();
        let revealed = PlanPathFields::default(); // all-empty / lockdown
        render_full(
            &mut buf,
            &sample_row(),
            &[],
            &[],
            &[],
            false,
            Some(&revealed),
        );
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("path_allowlist             []"), "got: {s}");
        assert!(s.contains("path_export_globs          []"), "got: {s}");
        assert!(s.contains("path_export_to_successors: false"), "got: {s}");
        assert!(s.contains("path_scope_override:       false"), "got: {s}");
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
        render_full(
            &mut buf,
            &sample_row(),
            &upstream,
            &downstream,
            &[],
            true,
            None,
        );
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
    fn render_json_default_marks_plan_fields_as_redacted_with_hint() {
        let mut buf: Vec<u8> = Vec::new();
        render_json(&mut buf, &sample_row(), &[], &[], &[sample_witness()], None);
        let v: serde_json::Value =
            serde_json::from_slice(&buf).expect("json render must parse back");
        for k in [
            "task_id",
            "initiative_id",
            "initiative_state",
            "state",
            "lane_id",
            "policy_epoch",
            "plan_fields",
            "dependencies",
            "witnesses",
        ] {
            assert!(v.get(k).is_some(), "missing key {k}; got {v}");
        }
        assert_eq!(v["witnesses"][0]["gate_type"], serde_json::json!("tests"));
        // Default branch: redacted projection.
        assert_eq!(v["plan_fields"]["revealed"], serde_json::json!(false));
        let redacted = v["plan_fields"]["redacted_fields"].as_array().unwrap();
        assert!(redacted.iter().any(|x| x == "path_allowlist"));
        assert!(v["plan_fields"]["hint"]
            .as_str()
            .unwrap_or("")
            .contains("--reveal-paths"));
    }

    #[test]
    fn render_json_revealed_inlines_full_path_lists_with_revealed_true() {
        let mut buf: Vec<u8> = Vec::new();
        let revealed = sample_revealed_fields();
        render_json(&mut buf, &sample_row(), &[], &[], &[], Some(&revealed));
        let v: serde_json::Value = serde_json::from_slice(&buf).unwrap();
        let pf = &v["plan_fields"];
        assert_eq!(pf["revealed"], serde_json::json!(true));
        assert_eq!(
            pf["path_allowlist"],
            serde_json::json!(["src/**", "README.md"])
        );
        assert_eq!(pf["path_export_to_successors"], serde_json::json!(true));
        assert_eq!(pf["path_export_globs"], serde_json::json!(["src/ipc/**"]));
        assert_eq!(pf["path_scope_override"], serde_json::json!(false));
        // Once revealed, the hint key MUST be absent — readers
        // distinguish the two shapes by `revealed` boolean.
        assert!(
            pf.get("hint").is_none(),
            "hint must not appear in revealed json"
        );
        assert!(
            pf.get("redacted_fields").is_none(),
            "redacted_fields must not appear in revealed json"
        );
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

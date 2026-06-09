//! `raxis explain <task_id>` — explain why a task is in its current state.
//!
//! Normative reference: cli-readonly.md §5.5.14.
//!
//! # What this command answers
//!
//! "Why is task X in state Y?" by joining the task row, its blocking
//! upstream edges, its witness records, and the most recent audit
//! events that mention the task. The output is a deliberate
//! decision-tree, NOT a free-form explanation; every step cites the
//! exact spec branch (path violation, gate failure, predecessor
//! pending, budget exhaustion, etc.) so an operator can reason about
//! a stuck task without reading kernel source.
//!
//! # Data sources (all read-only, no kernel IPC)
//!
//! * `<data_dir>/kernel.db` opened READ-ONLY:
//!   - `views::tasks::by_id`
//!   - `views::tasks::dag_edges_for_task` (Upstream)
//!   - `views::witnesses::for_task`
//! * `<data_dir>/audit/segment-NNN.jsonl` walked via
//!   `raxis_audit_tools::ChainReader` to surface the last N events
//!   tagged with this `task_id`.
//!
//! # Decision tree (in order)
//!
//! 1. Task does not exist → exit 4.
//! 2. Task is in a terminal state (Completed | Aborted | Failed | Rejected)
//!    → "no further action; final witnesses and audit events follow."
//! 3. Task is BlockedRecoveryPending → list the unsatisfied predecessors.
//! 4. Task is GatesPending → list witnesses; classify the most recent
//!    result_class for each gate_type.
//! 5. Task is Running / Admitted → no further explanation needed beyond
//!    the most-recent audit events.
//! 6. Always trail with the last 5 audit events scoped to this task_id.
//!
//! # Exit code
//!
//! `0` on success; `4` when the task does not exist.

use std::io::Write;
use std::path::Path;

use raxis_audit_tools::{ChainReader, ChainRecord};
use raxis_store::open_ro;
use raxis_store::views::tasks::{by_id, dag_edges_for_task, DagEdgeRow, EdgeDirection, TaskRow};
use raxis_store::views::witnesses::for_task;
use raxis_store::views::WitnessRow;

use crate::errors::CliError;
use crate::GlobalFlags;

const AUDIT_DIR_NAME: &str = "audit";
const RECENT_AUDIT_EVENTS: usize = 5;

// ────────────────────────────────────────────────────────────────────
// Entry point
// ────────────────────────────────────────────────────────────────────

pub fn run(flags: &GlobalFlags, args: &[String]) -> Result<(), CliError> {
    let opts = parse_args(args)?;

    let conn = open_ro(flags.data_dir())
        .map_err(|e| CliError::Policy(format!("kernel.db open failed: {e}")))?;

    let task = by_id(&conn, &opts.task_id)
        .map_err(|e| CliError::Policy(format!("tasks::by_id failed: {e}")))?;

    let task = match task {
        Some(t) => t,
        None => {
            eprintln!("explain: task {:?} not found", opts.task_id);
            std::process::exit(4);
        }
    };

    let upstream = dag_edges_for_task(&conn, &opts.task_id, EdgeDirection::Upstream)
        .map_err(|e| CliError::Policy(format!("dag_edges_for_task(up) failed: {e}")))?;
    let witnesses = for_task(&conn, &opts.task_id)
        .map_err(|e| CliError::Policy(format!("witnesses::for_task failed: {e}")))?;
    let audit_dir = flags.data_dir().join(AUDIT_DIR_NAME);
    let recent = collect_recent_audit_events(&audit_dir, &opts.task_id, RECENT_AUDIT_EVENTS);

    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    if opts.json {
        render_json(&mut out, &task, &upstream, &witnesses, &recent);
    } else {
        render_human(&mut out, &task, &upstream, &witnesses, &recent);
    }
    let _ = out.flush();
    Ok(())
}

// ────────────────────────────────────────────────────────────────────
// Argument parsing
// ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct ExplainOpts {
    task_id: String,
    json: bool,
}

fn parse_args(args: &[String]) -> Result<ExplainOpts, CliError> {
    let mut task_id: Option<String> = None;
    let mut json: bool = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
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
                    "unknown explain flag: {other:?} (try <task_id> --json --help)"
                )));
            }
        }
        i += 1;
    }
    let task_id = task_id
        .ok_or_else(|| CliError::Usage("usage: raxis explain <task_id> [--json]".to_owned()))?;
    Ok(ExplainOpts { task_id, json })
}

fn print_help() {
    println!(
        "raxis explain — explain why a task is in its current state\n\
         \n\
         USAGE:\n\
         \traxis explain <task_id> [--json]\n\
         \n\
         EXIT CODES:\n\
         \t0   task found and explanation rendered\n\
         \t4   task does not exist\n\
         "
    );
}

// ────────────────────────────────────────────────────────────────────
// Audit tail
// ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct RecentEvent {
    seq: u64,
    event_kind: String,
    emitted_at: Option<i64>,
}

/// Best-effort read of the last `limit` audit events tagged with
/// `task_id`. Failures (missing audit dir, broken chain) are silently
/// downgraded to an empty Vec — we are explaining a task, not
/// auditing the chain. `raxis verify-chain` is the authoritative tool
/// for that.
fn collect_recent_audit_events(audit_dir: &Path, task_id: &str, limit: usize) -> Vec<RecentEvent> {
    let reader = match ChainReader::open(audit_dir) {
        Ok(r) => r,
        Err(_) => return Vec::new(),
    };
    let mut keep: Vec<RecentEvent> = Vec::new();
    for rec in reader.records() {
        let Ok(rec) = rec else { continue };
        if !record_matches_task(&rec, task_id) {
            continue;
        }
        keep.push(RecentEvent {
            seq: rec.seq,
            event_kind: rec.event_kind,
            emitted_at: rec.emitted_at,
        });
    }
    if keep.len() > limit {
        let drop = keep.len() - limit;
        keep.drain(0..drop);
    }
    keep
}

fn record_matches_task(rec: &ChainRecord, task_id: &str) -> bool {
    rec.task_id.as_deref() == Some(task_id)
}

// ────────────────────────────────────────────────────────────────────
// Rendering — human (the decision tree)
// ────────────────────────────────────────────────────────────────────

fn render_human<W: Write>(
    out: &mut W,
    task: &TaskRow,
    upstream: &[DagEdgeRow],
    witnesses: &[WitnessRow],
    recent: &[RecentEvent],
) {
    let _ = writeln!(out, "raxis explain {task_id}", task_id = task.task_id);
    let _ = writeln!(out, "  initiative_id:    {}", task.initiative_id);
    let _ = writeln!(out, "  state:            {}", task.state);
    let _ = writeln!(out, "  lane:             {}", task.lane_id);
    let _ = writeln!(out, "  policy_epoch:     {}", task.policy_epoch);
    let _ = writeln!(out, "  admitted_at:      {}", task.admitted_at);
    let _ = writeln!(out, "  transitioned_at:  {}", task.transitioned_at);
    let _ = writeln!(out);

    match task.state.as_str() {
        "Completed" | "Aborted" | "Failed" | "Rejected" => {
            let _ = writeln!(
                out,
                "Why: task is in TERMINAL state {state} — no further \
                 transitions are possible. The witnesses below are the \
                 final gate outcomes; the audit tail is the post-\
                 transition record.",
                state = task.state,
            );
        }
        "BlockedRecoveryPending" => {
            let pending: Vec<&DagEdgeRow> = upstream
                .iter()
                .filter(|e| !e.predecessor_satisfied)
                .collect();
            let _ = writeln!(
                out,
                "Why: BlockedRecoveryPending is set when an upstream \
                 task has not yet satisfied its DAG predecessor edge \
                 (kernel-store.md §2.5.7). Unsatisfied predecessors:",
            );
            if pending.is_empty() {
                let _ = writeln!(
                    out,
                    "  (none observed in views::tasks — possible kernel bug?)"
                );
            } else {
                for e in &pending {
                    let _ = writeln!(
                        out,
                        "  - {tid}  (state={state})",
                        tid = e.other_task_id,
                        state = e.other_task_state,
                    );
                }
            }
        }
        "GatesPending" => {
            let _ = writeln!(
                out,
                "Why: GatesPending → at least one verifier gate has \
                 not yet returned Pass. Most recent witness per gate:",
            );
            render_witness_summary_per_gate(out, witnesses);
        }
        "Admitted" | "Running" => {
            let _ = writeln!(
                out,
                "Why: task is {state} — admitted to the scheduler and \
                 awaiting the next intent or verifier round-trip. See \
                 the audit tail below for the most recent activity.",
                state = task.state,
            );
        }
        other => {
            let _ = writeln!(
                out,
                "Why: state {other:?} is not in the v1 explanation \
                 vocabulary. Audit tail below:",
            );
        }
    }

    let _ = writeln!(out);
    render_audit_tail(out, recent);
}

fn render_witness_summary_per_gate<W: Write>(out: &mut W, witnesses: &[WitnessRow]) {
    if witnesses.is_empty() {
        let _ = writeln!(
            out,
            "  (no witnesses recorded yet — verifier may still be running)"
        );
        return;
    }
    // Group by gate_type, keep newest only (witnesses come ordered
    // newest-first from the view).
    let mut seen: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
    for w in witnesses {
        if seen.insert(w.gate_type.as_str()) {
            let _ = writeln!(
                out,
                "  - gate {gate:<24} most_recent={result:<14} run_id={run}",
                gate = truncate(&w.gate_type, 24),
                result = w.result_class,
                run = truncate(&w.verifier_run_id, 24),
            );
        }
    }
}

fn render_audit_tail<W: Write>(out: &mut W, recent: &[RecentEvent]) {
    let _ = writeln!(out, "Recent audit events (last {n}):", n = recent.len());
    if recent.is_empty() {
        let _ = writeln!(
            out,
            "  (none — audit dir missing, chain broken, or task untagged)"
        );
        return;
    }
    for e in recent {
        let _ = writeln!(
            out,
            "  seq={seq:<6} kind={kind:<32} emitted_at={at}",
            seq = e.seq,
            kind = truncate(&e.event_kind, 32),
            at = match e.emitted_at {
                Some(t) => t.to_string(),
                None => "<unset>".to_owned(),
            },
        );
    }
}

// ────────────────────────────────────────────────────────────────────
// Rendering — JSON
// ────────────────────────────────────────────────────────────────────

fn render_json<W: Write>(
    out: &mut W,
    task: &TaskRow,
    upstream: &[DagEdgeRow],
    witnesses: &[WitnessRow],
    recent: &[RecentEvent],
) {
    let v = serde_json::json!({
        "task_id":          task.task_id,
        "initiative_id":    task.initiative_id,
        "state":            task.state,
        "lane_id":          task.lane_id,
        "policy_epoch":     task.policy_epoch,
        "admitted_at":      task.admitted_at,
        "transitioned_at":  task.transitioned_at,
        "verdict":          state_verdict(&task.state),
        "blocking_predecessors":
            upstream
                .iter()
                .filter(|e| !e.predecessor_satisfied)
                .map(|e| serde_json::json!({
                    "task_id": e.other_task_id,
                    "state":   e.other_task_state,
                }))
                .collect::<Vec<_>>(),
        "witnesses_summary":
            witnesses.iter().map(|w| serde_json::json!({
                "gate_type":       w.gate_type,
                "result_class":    w.result_class,
                "verifier_run_id": w.verifier_run_id,
                "recorded_at":     w.recorded_at,
            })).collect::<Vec<_>>(),
        "recent_audit_events":
            recent.iter().map(|e| serde_json::json!({
                "seq":        e.seq,
                "event_kind": e.event_kind,
                "emitted_at": e.emitted_at,
            })).collect::<Vec<_>>(),
    });
    let _ = serde_json::to_writer(&mut *out, &v);
    let _ = writeln!(out);
}

fn state_verdict(state: &str) -> &'static str {
    match state {
        "Completed" => "terminal_pass",
        "Aborted" | "Rejected" => "terminal_operator",
        "Failed" => "terminal_fail",
        "BlockedRecoveryPending" => "blocked_predecessors",
        "GatesPending" => "blocked_witnesses",
        "Admitted" | "Running" => "in_flight",
        _ => "unknown",
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

// ────────────────────────────────────────────────────────────────────
// Tests
// ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_task(state: &str) -> TaskRow {
        TaskRow {
            task_id: "t-1".to_owned(),
            task_name: Some("sample-task".to_owned()),
            initiative_id: "init-1".to_owned(),
            initiative_state: "Executing".to_owned(),
            lane_id: "default".to_owned(),
            state: state.to_owned(),
            block_reason: None,
            actor: "op".to_owned(),
            policy_epoch: 1,
            admitted_at: 100,
            transitioned_at: 200,
            session_id: Some("sess-1".to_owned()),
            evaluation_sha: Some("sha".to_owned()),
            base_sha: Some("base".to_owned()),
            admission_reserved_units: Some(5),
            actual_cost: 3,
        }
    }

    fn sample_witness(gate: &str, result: &str, recorded: u64) -> WitnessRow {
        WitnessRow {
            verifier_run_id: format!("run-{recorded}"),
            task_id: "t-1".to_owned(),
            gate_type: gate.to_owned(),
            result_class: result.to_owned(),
            evaluation_sha: "eval".to_owned(),
            blob_sha256: "blob".to_owned(),
            recorded_at: recorded,
        }
    }

    #[test]
    fn parse_args_requires_task_id() {
        let err = parse_args(&[]).unwrap_err();
        assert!(matches!(err, CliError::Usage(_)));
    }

    #[test]
    fn state_verdict_classifies_each_known_state() {
        assert_eq!(state_verdict("Completed"), "terminal_pass");
        assert_eq!(state_verdict("Aborted"), "terminal_operator");
        assert_eq!(state_verdict("Failed"), "terminal_fail");
        assert_eq!(
            state_verdict("BlockedRecoveryPending"),
            "blocked_predecessors"
        );
        assert_eq!(state_verdict("GatesPending"), "blocked_witnesses");
        assert_eq!(state_verdict("Running"), "in_flight");
        assert_eq!(state_verdict("FoobarPending"), "unknown");
    }

    #[test]
    fn render_human_terminal_state_says_no_further_transitions() {
        let mut buf: Vec<u8> = Vec::new();
        render_human(&mut buf, &sample_task("Completed"), &[], &[], &[]);
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("TERMINAL state Completed"), "got: {s}");
    }

    #[test]
    fn render_human_blocked_lists_unsatisfied_predecessors_only() {
        let upstream = vec![
            DagEdgeRow {
                other_task_id: "t-up-ok".to_owned(),
                other_task_state: "Completed".to_owned(),
                predecessor_satisfied: true,
            },
            DagEdgeRow {
                other_task_id: "t-up-pending".to_owned(),
                other_task_state: "Running".to_owned(),
                predecessor_satisfied: false,
            },
        ];
        let mut buf: Vec<u8> = Vec::new();
        render_human(
            &mut buf,
            &sample_task("BlockedRecoveryPending"),
            &upstream,
            &[],
            &[],
        );
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("BlockedRecoveryPending is set"), "got: {s}");
        assert!(s.contains("t-up-pending"), "got: {s}");
        assert!(
            !s.contains("t-up-ok"),
            "satisfied predecessors should be hidden: {s}"
        );
    }

    #[test]
    fn render_human_gates_pending_summarises_per_gate_newest() {
        let witnesses = vec![
            sample_witness("tests", "Fail", 300),
            sample_witness("coverage", "Inconclusive", 200),
            sample_witness("tests", "Pass", 100), // older — must be ignored
        ];
        let mut buf: Vec<u8> = Vec::new();
        render_human(&mut buf, &sample_task("GatesPending"), &[], &witnesses, &[]);
        let s = String::from_utf8(buf).unwrap();
        assert!(
            s.contains("most_recent=Fail"),
            "tests gate must report newest=Fail: {s}"
        );
        assert!(
            s.contains("most_recent=Inconclusive"),
            "coverage report must include: {s}"
        );
        // The older Pass row must NOT appear.
        let pass_lines: Vec<&str> = s
            .lines()
            .filter(|l| l.contains("most_recent=Pass"))
            .collect();
        assert!(
            pass_lines.is_empty(),
            "older Pass should be hidden: {pass_lines:?}"
        );
    }

    #[test]
    fn render_human_running_state_falls_through_to_audit_tail() {
        let mut buf: Vec<u8> = Vec::new();
        render_human(
            &mut buf,
            &sample_task("Running"),
            &[],
            &[],
            &[RecentEvent {
                seq: 5,
                event_kind: "TaskAdmitted".to_owned(),
                emitted_at: Some(123),
            }],
        );
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("task is Running"), "got: {s}");
        assert!(s.contains("seq=5"), "got: {s}");
        assert!(s.contains("TaskAdmitted"), "got: {s}");
    }

    #[test]
    fn render_json_includes_verdict_and_blocking_arrays() {
        let upstream = vec![
            DagEdgeRow {
                other_task_id: "t-blk".to_owned(),
                other_task_state: "Running".to_owned(),
                predecessor_satisfied: false,
            },
            DagEdgeRow {
                other_task_id: "t-ok".to_owned(),
                other_task_state: "Completed".to_owned(),
                predecessor_satisfied: true,
            },
        ];
        let witnesses = vec![sample_witness("tests", "Pass", 100)];
        let recent = vec![RecentEvent {
            seq: 7,
            event_kind: "TaskAdmitted".to_owned(),
            emitted_at: Some(10),
        }];

        let mut buf: Vec<u8> = Vec::new();
        render_json(
            &mut buf,
            &sample_task("BlockedRecoveryPending"),
            &upstream,
            &witnesses,
            &recent,
        );
        let v: serde_json::Value = serde_json::from_slice(&buf).unwrap();
        assert_eq!(v["task_id"], "t-1");
        assert_eq!(v["verdict"], "blocked_predecessors");
        let blocking = v["blocking_predecessors"].as_array().unwrap();
        assert_eq!(blocking.len(), 1);
        assert_eq!(blocking[0]["task_id"], "t-blk");
        assert_eq!(v["witnesses_summary"][0]["gate_type"], "tests");
        assert_eq!(v["recent_audit_events"][0]["seq"], 7);
    }
}

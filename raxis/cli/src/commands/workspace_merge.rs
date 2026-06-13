// raxis-cli::commands::workspace_merge — operator workspace-merge recovery.
//
// `task_kind = "workspace_merge"` is the explicit fan-in primitive for
// Executor tasks that need multiple predecessor artifacts in one worktree. The
// kernel handles clean merges automatically. When Git reports conflicts, RAXIS
// preserves the conflicted worktree and records a workspace_merge_attempt row.
// The operator can inspect/resolve with normal Git commands, then submit or
// reset through authenticated operator IPC.

use raxis_store::Table;
use raxis_types::operator_wire::OperatorRequest;
use serde::Serialize;

use crate::commands::plan::{handle_response, open_conn, to_wire};
use crate::errors::CliError;
use crate::GlobalFlags;

const WORKSPACE_MERGE_ATTEMPTS: &str = Table::WorkspaceMergeAttempts.as_str();

#[derive(Debug, Serialize)]
struct WorkspaceMergeAttemptView {
    attempt_id: String,
    initiative_id: String,
    task_id: String,
    state: String,
    on_conflict: String,
    worktree_root: String,
    base_sha: String,
    predecessor_shas: Vec<String>,
    output_sha: Option<String>,
    conflict_paths: Vec<String>,
    failure_reason: Option<String>,
    created_at: i64,
    updated_at: i64,
    resolved_at: Option<i64>,
}

pub fn run_list(flags: &GlobalFlags, args: &[String]) -> Result<(), CliError> {
    if args.iter().any(|a| a == "-h" || a == "--help") {
        println!("usage: raxis workspace-merge list [--json] [--all]");
        return Ok(());
    }
    let json = args.iter().any(|a| a == "--json");
    let all = args.iter().any(|a| a == "--all");
    reject_unknown_flags("workspace-merge list", args, &["--json", "--all"])?;
    let attempts = load_attempts(flags, None, all)?;
    render_attempts(&attempts, json)
}

pub fn run_status(flags: &GlobalFlags, args: &[String]) -> Result<(), CliError> {
    if args.iter().any(|a| a == "-h" || a == "--help") {
        println!("usage: raxis workspace-merge status <attempt_id> [--json]");
        return Ok(());
    }
    let mut attempt_id: Option<String> = None;
    let mut json = false;
    for arg in args {
        match arg.as_str() {
            "--json" => json = true,
            other if other.starts_with('-') => {
                return Err(CliError::Usage(format!(
                    "workspace-merge status: unknown flag {other:?}"
                )));
            }
            other => {
                if attempt_id.replace(other.to_owned()).is_some() {
                    return Err(CliError::Usage(
                        "workspace-merge status accepts exactly one <attempt_id>".to_owned(),
                    ));
                }
            }
        }
    }
    let attempt_id = attempt_id.ok_or_else(|| {
        CliError::Usage("workspace-merge status requires <attempt_id>".to_owned())
    })?;
    let attempts = load_attempts(flags, Some(&attempt_id), true)?;
    let Some(attempt) = attempts.first() else {
        return Err(CliError::Usage(format!(
            "workspace merge attempt {attempt_id:?} was not found"
        )));
    };
    render_attempt_detail(attempt, json)
}

pub fn run_submit(flags: &GlobalFlags, args: &[String]) -> Result<(), CliError> {
    if args.iter().any(|a| a == "-h" || a == "--help") {
        println!("usage: raxis workspace-merge submit <attempt_id>");
        return Ok(());
    }
    let attempt_id = single_attempt_id("workspace-merge submit", args)?;
    let (mut conn, _) = open_conn(flags)?;
    let req = OperatorRequest::WorkspaceMergeSubmit {
        attempt_id: attempt_id.clone(),
    };
    let resp = conn.send_request(&to_wire(&req)?)?;
    handle_response(resp, |ok| {
        println!(
            "{}",
            ok["message"]
                .as_str()
                .unwrap_or("workspace merge submitted")
        );
    })
}

pub fn run_reset(flags: &GlobalFlags, args: &[String]) -> Result<(), CliError> {
    if args.iter().any(|a| a == "-h" || a == "--help") {
        println!("usage: raxis workspace-merge reset <attempt_id>");
        return Ok(());
    }
    let attempt_id = single_attempt_id("workspace-merge reset", args)?;
    let (mut conn, _) = open_conn(flags)?;
    let req = OperatorRequest::WorkspaceMergeReset {
        attempt_id: attempt_id.clone(),
    };
    let resp = conn.send_request(&to_wire(&req)?)?;
    handle_response(resp, |ok| {
        println!(
            "{}",
            ok["message"].as_str().unwrap_or("workspace merge reset")
        );
    })
}

fn load_attempts(
    flags: &GlobalFlags,
    attempt_id: Option<&str>,
    include_terminal: bool,
) -> Result<Vec<WorkspaceMergeAttemptView>, CliError> {
    let db_path = flags.data_dir().join(raxis_store::KERNEL_DB_FILE);
    let store = raxis_store::Store::open(&db_path).map_err(|e| {
        CliError::Usage(format!(
            "cannot open kernel.db at {}: {e}",
            db_path.display()
        ))
    })?;
    let conn = store.lock_sync();
    let mut query = format!(
        "SELECT attempt_id, initiative_id, task_id, state, on_conflict,
                worktree_root, base_sha, predecessor_shas_json, output_sha,
                conflict_paths_json, failure_reason, created_at, updated_at,
                resolved_at
           FROM {WORKSPACE_MERGE_ATTEMPTS}"
    );
    let mut params: Vec<String> = Vec::new();
    if let Some(attempt_id) = attempt_id {
        query.push_str(" WHERE attempt_id = ?1");
        params.push(attempt_id.to_owned());
    } else if !include_terminal {
        query.push_str(
            " WHERE state IN ('Running','ConflictPendingOrchestrator','ConflictPendingOperator')",
        );
    }
    query.push_str(" ORDER BY updated_at DESC, created_at DESC");

    let mut stmt = conn
        .prepare(&query)
        .map_err(|e| CliError::Usage(format!("workspace merge query failed: {e}")))?;
    let mut rows = if params.is_empty() {
        stmt.query([]).map_err(sql_usage)?
    } else {
        stmt.query(rusqlite::params![params[0].as_str()])
            .map_err(sql_usage)?
    };
    let mut attempts = Vec::new();
    while let Some(row) = rows.next().map_err(sql_usage)? {
        let predecessor_json: String = row.get(7).map_err(sql_usage)?;
        let conflict_json: Option<String> = row.get(9).map_err(sql_usage)?;
        attempts.push(WorkspaceMergeAttemptView {
            attempt_id: row.get(0).map_err(sql_usage)?,
            initiative_id: row.get(1).map_err(sql_usage)?,
            task_id: row.get(2).map_err(sql_usage)?,
            state: row.get(3).map_err(sql_usage)?,
            on_conflict: row.get(4).map_err(sql_usage)?,
            worktree_root: row.get(5).map_err(sql_usage)?,
            base_sha: row.get(6).map_err(sql_usage)?,
            predecessor_shas: serde_json::from_str(&predecessor_json).unwrap_or_default(),
            output_sha: row.get(8).map_err(sql_usage)?,
            conflict_paths: conflict_json
                .as_deref()
                .and_then(|s| serde_json::from_str(s).ok())
                .unwrap_or_default(),
            failure_reason: row.get(10).map_err(sql_usage)?,
            created_at: row.get(11).map_err(sql_usage)?,
            updated_at: row.get(12).map_err(sql_usage)?,
            resolved_at: row.get(13).map_err(sql_usage)?,
        });
    }
    Ok(attempts)
}

fn render_attempts(attempts: &[WorkspaceMergeAttemptView], json: bool) -> Result<(), CliError> {
    if json {
        println!("{}", serde_json::to_string_pretty(attempts)?);
        return Ok(());
    }
    if attempts.is_empty() {
        println!("No open workspace merge attempts.");
        return Ok(());
    }
    for attempt in attempts {
        println!(
            "{}  {}  task={}  {}",
            attempt.attempt_id, attempt.state, attempt.task_id, attempt.worktree_root
        );
        if !attempt.conflict_paths.is_empty() {
            println!("    conflicts: {}", attempt.conflict_paths.join(", "));
        }
        println!(
            "    inspect:   raxis workspace-merge status {}",
            attempt.attempt_id
        );
        if attempt.state.starts_with("ConflictPending") {
            println!("    resolve:   cd {}", attempt.worktree_root);
            println!("               git status");
            println!("               # resolve files, then git add ...");
            println!(
                "               raxis workspace-merge submit {}",
                attempt.attempt_id
            );
            println!(
                "    reset:     raxis workspace-merge reset {}",
                attempt.attempt_id
            );
        }
    }
    Ok(())
}

fn render_attempt_detail(attempt: &WorkspaceMergeAttemptView, json: bool) -> Result<(), CliError> {
    if json {
        println!("{}", serde_json::to_string_pretty(attempt)?);
        return Ok(());
    }
    println!("Attempt:      {}", attempt.attempt_id);
    println!("State:        {}", attempt.state);
    println!("Task:         {}", attempt.task_id);
    println!("Initiative:   {}", attempt.initiative_id);
    println!("Worktree:     {}", attempt.worktree_root);
    println!("Base SHA:     {}", attempt.base_sha);
    if let Some(output_sha) = attempt.output_sha.as_deref() {
        println!("Output SHA:   {output_sha}");
    }
    if !attempt.predecessor_shas.is_empty() {
        println!("Predecessors:");
        for sha in &attempt.predecessor_shas {
            println!("  - {sha}");
        }
    }
    if !attempt.conflict_paths.is_empty() {
        println!("Conflicts:");
        for path in &attempt.conflict_paths {
            println!("  - {path}");
        }
    }
    if let Some(reason) = attempt.failure_reason.as_deref() {
        println!("Reason:       {reason}");
    }
    println!("Created:      {}", attempt.created_at);
    println!("Updated:      {}", attempt.updated_at);
    if let Some(resolved_at) = attempt.resolved_at {
        println!("Resolved:     {resolved_at}");
    }
    if attempt.state.starts_with("ConflictPending") {
        println!();
        println!("Manual resolution:");
        println!("  cd {}", attempt.worktree_root);
        println!("  git status");
        println!("  # resolve conflict markers");
        println!("  git add <resolved-files>");
        println!("  raxis workspace-merge submit {}", attempt.attempt_id);
        println!();
        println!("Undo local resolution edits:");
        println!("  raxis workspace-merge reset {}", attempt.attempt_id);
    }
    Ok(())
}

fn single_attempt_id(command: &str, args: &[String]) -> Result<String, CliError> {
    let mut attempt_id: Option<String> = None;
    for arg in args {
        if arg.starts_with('-') {
            return Err(CliError::Usage(format!("{command}: unknown flag {arg:?}")));
        }
        if attempt_id.replace(arg.clone()).is_some() {
            return Err(CliError::Usage(format!(
                "{command} accepts exactly one <attempt_id>"
            )));
        }
    }
    attempt_id.ok_or_else(|| CliError::Usage(format!("{command} requires <attempt_id>")))
}

fn reject_unknown_flags(command: &str, args: &[String], allowed: &[&str]) -> Result<(), CliError> {
    for arg in args {
        if arg.starts_with('-') && !allowed.iter().any(|known| known == arg) {
            return Err(CliError::Usage(format!("{command}: unknown flag {arg:?}")));
        }
    }
    Ok(())
}

fn sql_usage(e: rusqlite::Error) -> CliError {
    CliError::Usage(format!("workspace merge sqlite error: {e}"))
}

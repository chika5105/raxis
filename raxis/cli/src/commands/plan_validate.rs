// raxis-cli::commands::plan_validate — `raxis plan validate <plan.toml>`.
//
// Normative reference: `specs/v2/operator-ergonomics.md §6` (the
// CLI surface for plan iteration). This command is the local-only
// pre-flight: it catches the operator's common mistakes before the
// signed-bundle round-trip to the kernel admission handler.
//
// The check set deliberately mirrors the kernel's `approve_plan`
// validators in `kernel/src/initiatives/lifecycle.rs` so an operator
// who runs `plan validate` cleanly can rely on `submit plan` not
// rejecting on the same grounds. The kernel remains the source of
// truth — anything the CLI misses is still caught at admission.
//
// Coverage (in evaluation order, deterministic):
//
//   1. TOML parse              — operator-typed syntax errors
//   2. Required sections       — `[workspace]`, `[[tasks]]`
//   3. `[workspace] lane_id`   — present + non-empty
//   4. Per-task fields:
//        - `task_id` required
//        - no `lane_id` override (single-lane propagation per V2 §28)
//        - no `session_agent_type = "Orchestrator"` (V2 §27 rule 1)
//        - valid `clone_strategy` ∈ {`full`, `blobless`, `sparse`}
//          (V2 §27 typed clone strategy)
//        - valid `session_agent_type` ∈ {`Executor`, `Reviewer`} when
//          declared
//   5. DAG family:
//        - duplicate `task_id`
//        - self-loop (`task.predecessors` lists itself)
//        - dangling predecessor (id not declared in this plan)
//        - cyclic dependency (DFS over the predecessor graph)
//   6. Cross-cutting artifacts (`[orchestrator] cross_cutting_artifacts`):
//        - empty entry, leading `!`, leading or trailing `/`,
//          `..` segments, embedded `/`, glob characters
//
// Output format (stable wire shape; tests pin the leading line):
//
//   Plan validation: ./plan.toml
//     [OK] TOML parses
//     [OK] required sections present
//     ...
//
// On success the command exits 0. On any failure it exits 2 (CLI usage)
// and writes the offending line to stderr in the same operator-facing
// format the kernel returns.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use crate::errors::CliError;
use crate::GlobalFlags;

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

pub fn run(_flags: &GlobalFlags, args: &[String]) -> Result<(), CliError> {
    let plan_path = args
        .first()
        .ok_or_else(|| {
            CliError::Usage(
                "plan validate requires <plan.toml> (e.g. `raxis plan validate ./plan.toml`)"
                    .to_owned(),
            )
        })
        .map(PathBuf::from)?;

    let bytes = std::fs::read(&plan_path).map_err(|e| CliError::Io {
        path:   plan_path.display().to_string(),
        source: e,
    })?;

    let text = std::str::from_utf8(&bytes).map_err(|e| {
        CliError::Usage(format!("plan.toml is not valid UTF-8: {e}"))
    })?;

    println!("Plan validation: {}", plan_path.display());
    let report = validate_plan_text(text);
    for line in &report.lines {
        println!("  {line}");
    }

    if let Some(err) = report.first_error {
        return Err(CliError::Usage(err));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Pure validation core (no I/O, fully testable)
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
pub struct ValidationReport {
    pub lines:       Vec<String>,
    pub first_error: Option<String>,
}

impl ValidationReport {
    fn ok(&mut self, label: &str) {
        self.lines.push(format!("[OK] {label}"));
    }
    fn fail(&mut self, label: &str, detail: String) {
        self.lines.push(format!("[FAIL] {label}: {detail}"));
        if self.first_error.is_none() {
            self.first_error = Some(format!("{label}: {detail}"));
        }
    }
}

pub fn validate_plan_text(text: &str) -> ValidationReport {
    let mut r = ValidationReport::default();

    // ── Step 1: TOML parse ────────────────────────────────────────────────
    let doc: toml::Value = match toml::from_str(text) {
        Ok(v)  => { r.ok("TOML parses"); v }
        Err(e) => { r.fail("TOML parse", e.to_string()); return r; }
    };

    // ── Step 2: required sections ─────────────────────────────────────────
    let workspace = doc.get("workspace").and_then(|v| v.as_table());
    let tasks_arr = doc.get("tasks").and_then(|v| v.as_array());
    if workspace.is_none() {
        r.fail("required sections", "missing [workspace]".to_owned());
    }
    if tasks_arr.is_none() {
        r.fail("required sections", "missing [[tasks]]".to_owned());
    }
    if r.first_error.is_some() {
        return r;
    }
    r.ok("required sections present");

    // ── Step 3: [workspace] lane_id ───────────────────────────────────────
    let workspace = workspace.unwrap();
    let lane_id = match workspace.get("lane_id").and_then(|v| v.as_str()) {
        None | Some("") => {
            r.fail(
                "[workspace] lane_id",
                "missing or empty; V2 requires a single workspace-root lane \
                 declared as `[workspace] lane_id = \"<lane>\"` so the initiative \
                 budget ceiling propagates to every session"
                    .to_owned(),
            );
            return r;
        }
        Some(s) => s.to_owned(),
    };
    r.ok(&format!("[workspace] lane_id = \"{lane_id}\""));

    // ── Step 4: per-task fields ───────────────────────────────────────────
    let mut tasks: Vec<ParsedTask> = Vec::new();
    for (i, entry) in tasks_arr.unwrap().iter().enumerate() {
        let task_id = match entry.get("task_id").and_then(|v| v.as_str()) {
            Some(s) if !s.is_empty() => s.to_owned(),
            _ => {
                r.fail(
                    "[[tasks]] task_id",
                    format!("tasks[{i}] missing task_id"),
                );
                return r;
            }
        };

        if let Some(per_task_lane) = entry.get("lane_id").and_then(|v| v.as_str()) {
            if !per_task_lane.is_empty() {
                r.fail(
                    "single-lane propagation",
                    format!(
                        "task `{task_id}` declares `lane_id = \"{per_task_lane}\"`; \
                         V2 forbids per-task lane overrides — declare the lane once \
                         at `[workspace] lane_id` and let the kernel propagate it"
                    ),
                );
                return r;
            }
        }

        if let Some(agent) = entry.get("session_agent_type").and_then(|v| v.as_str()) {
            if !matches!(agent, "Executor" | "Reviewer") {
                if agent == "Orchestrator" {
                    r.fail(
                        "Orchestrator declaration",
                        format!(
                            "task `{task_id}` declares `session_agent_type = \"Orchestrator\"`; \
                             V2 auto-creates exactly one Orchestrator session per initiative \
                             from the kernel-bundled `raxis-orchestrator-core` image — \
                             operators only declare Executor (and optionally Reviewer) tasks"
                        ),
                    );
                    return r;
                }
                r.fail(
                    "session_agent_type",
                    format!(
                        "task `{task_id}` has invalid `session_agent_type = \"{agent}\"`; \
                         valid values: Executor, Reviewer"
                    ),
                );
                return r;
            }
        }

        let clone_strategy = entry.get("clone_strategy").and_then(|v| v.as_str());
        if let Some(s) = clone_strategy {
            if !matches!(s, "full" | "blobless" | "sparse") {
                r.fail(
                    "clone_strategy",
                    format!(
                        "task `{task_id}` has invalid `clone_strategy = \"{s}\"`; \
                         valid values: full, blobless, sparse (V2 default: blobless)"
                    ),
                );
                return r;
            }
        }

        let predecessors: Vec<String> = entry
            .get("predecessors")
            .and_then(|v| v.as_array())
            .map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_owned)).collect())
            .unwrap_or_default();

        tasks.push(ParsedTask { task_id, predecessors });
    }
    r.ok(&format!("{} task(s) declared", tasks.len()));

    // ── Step 5: DAG family ────────────────────────────────────────────────
    if let Err(e) = validate_dag(&tasks) {
        r.fail("plan DAG", e);
        return r;
    }
    r.ok("plan DAG is acyclic; no duplicates / self-loops / dangling deps");

    // ── Step 6: cross-cutting artifacts ──────────────────────────────────
    if let Some(orch) = doc.get("orchestrator").and_then(|v| v.as_table()) {
        if let Some(arr) = orch.get("cross_cutting_artifacts").and_then(|v| v.as_array()) {
            for v in arr {
                let s = v.as_str().unwrap_or("");
                if let Err(reason) = check_cross_cutting_entry(s) {
                    r.fail(
                        "cross_cutting_artifacts",
                        format!("entry `{s}`: {reason}"),
                    );
                    return r;
                }
            }
            r.ok(&format!("cross_cutting_artifacts: {} entry/entries OK", arr.len()));
        }
    }

    // ── Step 7: path_allowlist V2-format syntax ──────────────────────────
    // Per `v2-deep-spec.md §Step 19`: entries are exact filenames
    // (`Cargo.toml`) or directory prefixes (`src/`); no globs, no
    // negation, no `..` traversal, no leading `/`. Mirrors the kernel's
    // `validate_path_allowlist_v2_format`.
    if let Err(e) = validate_path_allowlists_in_doc(&doc) {
        r.fail("path_allowlist", e);
        return r;
    }
    r.ok("path_allowlist entries pass V2-format syntax checks");

    r
}

#[derive(Debug)]
struct ParsedTask {
    task_id:      String,
    predecessors: Vec<String>,
}

fn validate_dag(tasks: &[ParsedTask]) -> Result<(), String> {
    let mut seen: HashMap<&str, usize> = HashMap::with_capacity(tasks.len());
    for (i, t) in tasks.iter().enumerate() {
        if let Some(prev_i) = seen.insert(t.task_id.as_str(), i) {
            return Err(format!(
                "duplicate task_id `{0}` declared at tasks[{prev_i}] and tasks[{i}]; \
                 every task must have a unique task_id",
                t.task_id,
            ));
        }
    }
    let known: HashSet<&str> = seen.keys().copied().collect();

    for t in tasks {
        for p in &t.predecessors {
            if p == &t.task_id {
                return Err(format!(
                    "task `{0}` lists itself in `predecessors`; \
                     a task cannot depend on itself",
                    t.task_id,
                ));
            }
            if !known.contains(p.as_str()) {
                return Err(format!(
                    "task `{0}` lists predecessor `{p}` which is not declared in this plan; \
                     remove the dangling reference or add the missing [[tasks]] block",
                    t.task_id,
                ));
            }
        }
    }

    // Cycle detection — iterative DFS, three-color marking.
    enum Color { White, Gray, Black }
    let mut color: HashMap<&str, Color> = tasks
        .iter()
        .map(|t| (t.task_id.as_str(), Color::White))
        .collect();
    let pred_map: HashMap<&str, &[String]> = tasks
        .iter()
        .map(|t| (t.task_id.as_str(), t.predecessors.as_slice()))
        .collect();

    for t in tasks {
        if matches!(color[t.task_id.as_str()], Color::Black) {
            continue;
        }
        let mut stack: Vec<(&str, usize)> = vec![(t.task_id.as_str(), 0)];
        while let Some(&(node, idx)) = stack.last() {
            match color.get(node).unwrap() {
                Color::Black => { stack.pop(); continue; }
                Color::White => { color.insert(node, Color::Gray); }
                Color::Gray  => { /* fall through to child walk */ }
            }
            let preds = pred_map.get(node).copied().unwrap_or(&[]);
            if idx < preds.len() {
                let next = preds[idx].as_str();
                let last = stack.len() - 1;
                stack[last].1 = idx + 1;
                match color.get(next) {
                    Some(Color::Gray) => {
                        return Err(format!(
                            "cycle detected: task `{node}` -> `{next}` closes a cycle; \
                             V2 plans are required to be DAGs"
                        ));
                    }
                    Some(Color::White) => stack.push((next, 0)),
                    _ => { /* Black or unknown — already validated */ }
                }
            } else {
                color.insert(node, Color::Black);
                stack.pop();
            }
        }
    }
    Ok(())
}

fn check_cross_cutting_entry(entry: &str) -> Result<(), &'static str> {
    if entry.is_empty() { return Err("empty entry"); }
    if entry.starts_with('!') { return Err("leading `!` (negation marker not permitted)"); }
    if entry.starts_with('/') { return Err("absolute path not permitted"); }
    if entry.ends_with('/') { return Err("trailing `/` not permitted (must be exact filename)"); }
    if entry.split('/').any(|seg| seg == "..") { return Err("`..` path-escape segment"); }
    if entry.contains('/') { return Err("must be an exact filename (no `/`)"); }
    if entry.chars().any(|c| matches!(c, '*' | '?' | '[' | ']' | '{' | '}')) {
        return Err("glob character not permitted");
    }
    Ok(())
}

fn validate_path_allowlists_in_doc(doc: &toml::Value) -> Result<(), String> {
    let Some(tasks) = doc.get("tasks").and_then(|v| v.as_array()) else {
        return Ok(());
    };
    for entry in tasks {
        let task_id = entry.get("task_id").and_then(|v| v.as_str()).unwrap_or("?");
        let Some(arr) = entry.get("path_allowlist").and_then(|v| v.as_array()) else {
            continue;
        };
        for v in arr {
            let s = v.as_str().unwrap_or("");
            if let Err(reason) = check_path_allowlist_entry(s) {
                return Err(format!("task `{task_id}` path_allowlist entry `{s}`: {reason}"));
            }
        }
    }
    Ok(())
}

fn check_path_allowlist_entry(entry: &str) -> Result<(), &'static str> {
    if entry.is_empty() { return Err("empty entry"); }
    if entry.starts_with('!') { return Err("leading `!` (negation marker not permitted)"); }
    if entry.starts_with('/') { return Err("absolute path not permitted"); }
    // Glob characters are rejected — V2 path_allowlist uses exact
    // filenames or directory prefixes only.
    if entry.chars().any(|c| matches!(c, '*' | '?' | '[' | ']' | '{' | '}')) {
        return Err("glob character not permitted (use exact filenames or directory prefixes)");
    }
    // `..` segments at any position. Note: `..` as part of a filename
    // (e.g. `foo..bar`) is allowed; only standalone segments are rejected.
    if entry.split('/').any(|seg| seg == "..") {
        return Err("`..` path-escape segment");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Smoke checks for the operator-facing message text
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn passing_plan() -> &'static str {
        r#"
[workspace]
lane_id = "default"

[[tasks]]
task_id = "build"
session_agent_type = "Executor"

[[tasks]]
task_id = "test"
session_agent_type = "Executor"
predecessors = ["build"]
"#
    }

    #[test]
    fn happy_path_passes_validation() {
        let r = validate_plan_text(passing_plan());
        assert!(r.first_error.is_none(), "report: {:#?}", r.lines);
        assert!(r.lines.iter().any(|l| l.contains("[OK] TOML parses")));
        assert!(r.lines.iter().any(|l| l.contains("[OK] 2 task(s) declared")));
    }

    #[test]
    fn missing_workspace_section_is_rejected() {
        let r = validate_plan_text(r#"
[[tasks]]
task_id = "a"
"#);
        assert!(r.first_error.as_ref().unwrap().contains("[workspace]"));
    }

    #[test]
    fn missing_workspace_lane_is_rejected() {
        let r = validate_plan_text(r#"
[workspace]

[[tasks]]
task_id = "a"
"#);
        let err = r.first_error.unwrap();
        assert!(err.contains("[workspace] lane_id"), "err = {err}");
    }

    #[test]
    fn orchestrator_task_declaration_is_rejected_with_v2_hint() {
        let r = validate_plan_text(r#"
[workspace]
lane_id = "default"

[[tasks]]
task_id = "orch"
session_agent_type = "Orchestrator"
"#);
        let err = r.first_error.unwrap();
        assert!(err.contains("Orchestrator"), "err = {err}");
        assert!(err.contains("auto-create"), "err = {err}");
    }

    #[test]
    fn invalid_clone_strategy_is_rejected() {
        let r = validate_plan_text(r#"
[workspace]
lane_id = "default"

[[tasks]]
task_id = "a"
clone_strategy = "shallow"
"#);
        let err = r.first_error.unwrap();
        assert!(err.contains("clone_strategy"), "err = {err}");
        assert!(err.contains("full, blobless, sparse"), "err = {err}");
    }

    #[test]
    fn per_task_lane_id_override_is_rejected() {
        let r = validate_plan_text(r#"
[workspace]
lane_id = "default"

[[tasks]]
task_id = "a"
lane_id = "other"
"#);
        let err = r.first_error.unwrap();
        assert!(err.contains("single-lane propagation"), "err = {err}");
    }

    #[test]
    fn duplicate_task_ids_are_rejected() {
        let r = validate_plan_text(r#"
[workspace]
lane_id = "default"

[[tasks]]
task_id = "a"
[[tasks]]
task_id = "a"
"#);
        let err = r.first_error.unwrap();
        assert!(err.contains("duplicate"), "err = {err}");
    }

    #[test]
    fn self_loop_is_rejected() {
        let r = validate_plan_text(r#"
[workspace]
lane_id = "default"

[[tasks]]
task_id = "a"
predecessors = ["a"]
"#);
        let err = r.first_error.unwrap();
        assert!(err.contains("itself"), "err = {err}");
    }

    #[test]
    fn dangling_predecessor_is_rejected() {
        let r = validate_plan_text(r#"
[workspace]
lane_id = "default"

[[tasks]]
task_id = "a"
predecessors = ["ghost"]
"#);
        let err = r.first_error.unwrap();
        assert!(err.contains("ghost"), "err = {err}");
    }

    #[test]
    fn cycle_is_detected() {
        let r = validate_plan_text(r#"
[workspace]
lane_id = "default"

[[tasks]]
task_id = "a"
predecessors = ["b"]

[[tasks]]
task_id = "b"
predecessors = ["a"]
"#);
        let err = r.first_error.unwrap();
        assert!(err.contains("cycle"), "err = {err}");
    }

    #[test]
    fn cross_cutting_artifact_globs_are_rejected() {
        let r = validate_plan_text(r#"
[workspace]
lane_id = "default"

[orchestrator]
cross_cutting_artifacts = ["Cargo.lock", "*.toml"]

[[tasks]]
task_id = "a"
"#);
        let err = r.first_error.unwrap();
        assert!(err.contains("glob"), "err = {err}");
    }

    #[test]
    fn path_allowlist_glob_is_rejected() {
        let r = validate_plan_text(r#"
[workspace]
lane_id = "default"

[[tasks]]
task_id = "a"
path_allowlist = ["src/*.rs"]
"#);
        let err = r.first_error.unwrap();
        assert!(err.contains("glob"), "err = {err}");
    }

    #[test]
    fn empty_plan_with_zero_tasks_passes() {
        let r = validate_plan_text(r#"
[workspace]
lane_id = "default"

[[tasks]]
task_id = "noop"
"#);
        assert!(r.first_error.is_none(), "report: {:#?}", r.lines);
    }

    fn _unused_warns_to_silence_compiler(p: &Path) {
        let _ = p;
    }
}

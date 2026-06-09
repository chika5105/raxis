// raxis-cli::commands::plan_validate — `raxis plan validate <plan.toml>`.
// Normative reference: `specs/v2/operator-ergonomics.md §6` (the
// CLI surface for plan iteration). This command is the local-only
// pre-flight: it catches the operator's common mistakes before the
// signed-bundle round-trip to the kernel admission handler.
// The check set deliberately mirrors the kernel's `approve_plan`
// validators in `kernel/src/initiatives/lifecycle.rs` so an operator
// who runs `plan validate` cleanly can rely on `submit plan` not
// rejecting on the same grounds. The kernel remains the source of
// truth — anything the CLI misses is still caught at admission.
// Coverage (in evaluation order, deterministic):
//   1. TOML parse              — operator-typed syntax errors
//   2. Required sections       — `[plan.initiative]`, `[workspace]`, `[[tasks]]`
//   3. `[workspace] name` —
//      present + non-empty + single-line + ≤ 64 characters
//   4. `[plan.initiative] description` —
//      present + non-empty + ≤ 64 KiB
//   5. `[workspace] lane_id`   — present + non-empty
//   6. `[workspace] repository` — optional; defaults to `main`, must
//      be a single path-safe managed repository id when present
//   7. Per-task fields:
//        - `task_name` required
//        - `description` — present + non-empty + ≤ 64 KiB
//        - `prompt` — optional, but when present must be non-empty +
//          ≤ 64 KiB; `context` is rejected as the old ignored field
//        - no `lane_id` override (single-lane propagation per V2 §28)
//        - no `session_agent_type = "Orchestrator"` (V2 §27 rule 1)
//        - valid `clone_strategy` ∈ {`full`, `blobless`, `sparse`}
//          (V2 §27 typed clone strategy)
//        - valid `session_agent_type` ∈ {`Executor`, `Reviewer`} when
//          declared
//   7. DAG family:
//        - duplicate `task_name`
//        - self-loop (`task.predecessors` lists itself)
//        - dangling predecessor (id not declared in this plan)
//        - cyclic dependency (DFS over the predecessor graph)
//   8. Cross-cutting artifacts (`[orchestrator] cross_cutting_artifacts`):
//        - empty entry, leading `!`, leading or trailing `/`,
//          `..` segments, embedded `/`, glob characters
// Output format (stable wire shape; tests pin the leading line):
//   Plan validation: ./plan.toml
//     [OK] TOML parses
//     [OK] required sections present
//     ...
// On success the command exits 0. On any failure it exits 2 (CLI usage)
// and writes the offending line to stderr in the same operator-facing
// format the kernel returns.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

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
        path: plan_path.display().to_string(),
        source: e,
    })?;

    let text = std::str::from_utf8(&bytes)
        .map_err(|e| CliError::Usage(format!("plan.toml is not valid UTF-8: {e}")))?;

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
    pub lines: Vec<String>,
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
        Ok(v) => {
            r.ok("TOML parses");
            v
        }
        Err(e) => {
            r.fail("TOML parse", e.to_string());
            return r;
        }
    };

    // ── Step 2: required sections ─────────────────────────────────────────
    let plan_initiative = doc
        .get("plan")
        .and_then(|v| v.as_table())
        .and_then(|t| t.get("initiative"))
        .and_then(|v| v.as_table());
    let workspace = doc.get("workspace").and_then(|v| v.as_table());
    let tasks_arr = doc.get("tasks").and_then(|v| v.as_array());
    if plan_initiative.is_none() {
        r.fail(
            "required sections",
            "missing [plan.initiative] (V2 §1.1: declare \
             `[plan.initiative]\\ndescription = \"...\"` \
             to seed the orchestrator agent)"
                .to_owned(),
        );
    }
    if workspace.is_none() {
        r.fail(
            "required sections",
            "missing [workspace] (declare `name` for dashboard display and \
             `lane_id` for budget/session propagation)"
                .to_owned(),
        );
    }
    if tasks_arr.is_none() {
        r.fail("required sections", "missing [[tasks]]".to_owned());
    }
    if r.first_error.is_some() {
        return r;
    }
    r.ok("required sections present");

    // ── Step 3: [workspace] name ───────────────────────────────────────
    const MAX_WORKSPACE_NAME_CHARS: usize = 64;
    let workspace = workspace.unwrap();
    match workspace.get("name") {
        Some(toml::Value::String(s)) => {
            let trimmed = s.trim();
            if trimmed.is_empty() {
                r.fail(
                    "[workspace] name",
                    "is empty; declare a short dashboard label".to_owned(),
                );
                return r;
            }
            if trimmed.chars().any(|c| c.is_control()) {
                r.fail(
                    "[workspace] name",
                    "must be a single line with no control characters".to_owned(),
                );
                return r;
            }
            let count = trimmed.chars().count();
            if count > MAX_WORKSPACE_NAME_CHARS {
                r.fail(
                    "[workspace] name",
                    format!(
                        "is {count} characters, exceeds {MAX_WORKSPACE_NAME_CHARS} character cap"
                    ),
                );
                return r;
            }
            r.ok(&format!("[workspace] name = \"{trimmed}\""));
        }
        Some(_) => {
            r.fail("[workspace] name", "must be a TOML string".to_owned());
            return r;
        }
        None => {
            r.fail(
                "[workspace] name",
                "is missing; declare `[workspace] name = \"<short label>\"".to_owned(),
            );
            return r;
        }
    }

    let plan_initiative = plan_initiative.unwrap();
    // ── Step 4: [plan.initiative] description (V2 §1.1) ──────────────────
    // Mirrors the kernel `parse_plan_orchestrator` validator. Same
    // 64 KiB cap so an operator catches `execve(2)` `ARG_MAX` issues
    // client-side instead of after the round-trip.
    const MAX_DESCRIPTION_BYTES: usize = 64 * 1024;
    match plan_initiative.get("description") {
        Some(toml::Value::String(s)) => {
            let trimmed = s.trim_end();
            if trimmed.is_empty() {
                r.fail(
                    "[plan.initiative] description",
                    "is empty; V2 §1.1 requires a non-empty initiative \
                     description so the orchestrator agent has a concrete \
                     seed prompt"
                        .to_owned(),
                );
                return r;
            }
            if trimmed.len() > MAX_DESCRIPTION_BYTES {
                r.fail(
                    "[plan.initiative] description",
                    format!(
                        "is {} bytes, exceeds 64 KiB cap; trim to fit \
                         execve(2) ARG_MAX",
                        trimmed.len(),
                    ),
                );
                return r;
            }
            r.ok(&format!(
                "[plan.initiative] description ({} byte(s))",
                trimmed.len(),
            ));
        }
        Some(_) => {
            r.fail(
                "[plan.initiative] description",
                "must be a TOML string".to_owned(),
            );
            return r;
        }
        None => {
            r.fail(
                "[plan.initiative] description",
                "is missing; V2 §1.1 requires `[plan.initiative]\\n\
                 description = \"<what is this initiative about?>\"`"
                    .to_owned(),
            );
            return r;
        }
    }

    // ── Step 5: [workspace] lane_id ───────────────────────────────────────
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

    // ── Step 6: [workspace] repository ───────────────────────────────────
    let repository_id = match workspace.get("repository") {
        None => "main",
        Some(toml::Value::String(s)) => s.trim(),
        Some(_) => {
            r.fail(
                "[workspace] repository",
                "must be a TOML string such as `repository = \"main\"`".to_owned(),
            );
            return r;
        }
    };
    if let Err(reason) = validate_repository_id(repository_id) {
        r.fail(
            "[workspace] repository",
            format!("{reason}; omit the field to use the default `main` repository"),
        );
        return r;
    }
    r.ok(&format!("[workspace] repository = \"{repository_id}\""));

    // ── Step 7: per-task fields ───────────────────────────────────────────
    let mut tasks: Vec<ParsedTask> = Vec::new();
    for (i, entry) in tasks_arr.unwrap().iter().enumerate() {
        if entry.get("task_id").is_some() {
            r.fail(
                "[[tasks]] task_id",
                format!(
                    "tasks[{i}] declares forbidden `task_id`; task IDs are \
                     generated by the kernel. Use `task_name` for the plan label."
                ),
            );
            return r;
        }
        if entry.get("name").is_some() {
            r.fail(
                "[[tasks]] name",
                format!("tasks[{i}] declares deprecated `name`; use `task_name`"),
            );
            return r;
        }
        let task_name = match entry.get("task_name") {
            Some(toml::Value::String(s)) if !s.trim().is_empty() => s.trim().to_owned(),
            Some(toml::Value::String(_)) => {
                r.fail(
                    "[[tasks]] task_name",
                    format!("tasks[{i}] has empty task_name"),
                );
                return r;
            }
            Some(_) => {
                r.fail(
                    "[[tasks]] task_name",
                    format!("tasks[{i}] task_name must be a TOML string"),
                );
                return r;
            }
            None => {
                r.fail(
                    "[[tasks]] task_name",
                    format!("tasks[{i}] missing required task_name"),
                );
                return r;
            }
        };

        if entry.get("context").is_some() {
            r.fail(
                "[[tasks]] context",
                format!(
                    "task `{task_name}` uses deprecated `context`; use `prompt` \
                     for executor/reviewer instructions. Keep `description` \
                     as the short human summary."
                ),
            );
            return r;
        }

        // Every `[[tasks]]` block must declare a non-empty
        // `description`. `prompt` is the preferred primary model
        // instruction in 0.2.0, but old plans that omit it still use
        // `description` as the instruction. Mirrors the kernel
        // `parse_plan_tasks` validator.
        match entry.get("description") {
            Some(toml::Value::String(s)) => {
                let trimmed = s.trim_end();
                if trimmed.is_empty() {
                    r.fail(
                        "[[tasks]] description",
                        format!(
                            "task `{task_name}` has empty `description`; \
                             declare a short human summary for the task"
                        ),
                    );
                    return r;
                }
                if trimmed.len() > MAX_DESCRIPTION_BYTES {
                    r.fail(
                        "[[tasks]] description",
                        format!(
                            "task `{task_name}` description is {} bytes, \
                             exceeds 64 KiB cap; trim to fit execve(2) \
                             ARG_MAX",
                            trimmed.len(),
                        ),
                    );
                    return r;
                }
            }
            Some(_) => {
                r.fail(
                    "[[tasks]] description",
                    format!("task `{task_name}` `description` must be a TOML string"),
                );
                return r;
            }
            None => {
                r.fail(
                    "[[tasks]] description",
                    format!(
                        "task `{task_name}` is missing required `description` \
                         field — declare a short human summary for the task"
                    ),
                );
                return r;
            }
        }
        match entry.get("prompt") {
            Some(toml::Value::String(s)) => {
                let trimmed = s.trim_end();
                if trimmed.is_empty() {
                    r.fail(
                        "[[tasks]] prompt",
                        format!(
                            "task `{task_name}` has empty `prompt`; provide the primary \
                             executor/reviewer instruction"
                        ),
                    );
                    return r;
                }
                if trimmed.len() > MAX_DESCRIPTION_BYTES {
                    r.fail(
                        "[[tasks]] prompt",
                        format!(
                            "task `{task_name}` prompt is {} bytes, exceeds 64 KiB \
                             cap; trim to fit execve(2) ARG_MAX",
                            trimmed.len(),
                        ),
                    );
                    return r;
                }
            }
            Some(_) => {
                r.fail(
                    "[[tasks]] prompt",
                    format!("task `{task_name}` `prompt` must be a TOML string"),
                );
                return r;
            }
            None => {
                r.fail(
                    "[[tasks]] prompt",
                    format!("task `{task_name}` is missing required `prompt`"),
                );
                return r;
            }
        }

        if let Some(per_task_lane) = entry.get("lane_id").and_then(|v| v.as_str()) {
            if !per_task_lane.is_empty() {
                r.fail(
                    "single-lane propagation",
                    format!(
                        "task `{task_name}` declares `lane_id = \"{per_task_lane}\"`; \
                         V2 forbids per-task lane overrides — declare the lane once \
                         at `[workspace] lane_id` and let the kernel propagate it"
                    ),
                );
                return r;
            }
        }

        let agent_type = match entry.get("session_agent_type") {
            Some(toml::Value::String(agent)) => {
                if !matches!(agent.as_str(), "Executor" | "Reviewer") {
                    if agent == "Orchestrator" {
                        r.fail(
                            "Orchestrator declaration",
                            format!(
                            "task `{task_name}` declares `session_agent_type = \"Orchestrator\"`; \
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
                            "task `{task_name}` has invalid `session_agent_type = \"{agent}\"`; \
                         valid values: Executor, Reviewer"
                        ),
                    );
                    return r;
                }
                agent.to_owned()
            }
            Some(_) => {
                r.fail(
                    "session_agent_type",
                    format!("task `{task_name}` session_agent_type must be a TOML string"),
                );
                return r;
            }
            None => {
                r.fail(
                    "session_agent_type",
                    format!("task `{task_name}` is missing required session_agent_type"),
                );
                return r;
            }
        };

        match entry.get("clone_strategy") {
            Some(toml::Value::String(s)) => {
                if !matches!(s.as_str(), "full" | "blobless" | "sparse") {
                    r.fail(
                        "clone_strategy",
                        format!(
                            "task `{task_name}` has invalid `clone_strategy = \"{s}\"`; \
                         valid values: full, blobless, sparse"
                        ),
                    );
                    return r;
                }
            }
            Some(_) => {
                r.fail(
                    "clone_strategy",
                    format!("task `{task_name}` clone_strategy must be a TOML string"),
                );
                return r;
            }
            None => {
                r.fail(
                    "clone_strategy",
                    format!("task `{task_name}` is missing required clone_strategy"),
                );
                return r;
            }
        }

        let predecessors = toml_string_array(entry, "predecessors");
        let path_allowlist = toml_string_array(entry, "path_allowlist");
        let path_export_globs = toml_string_array(entry, "path_export_globs");
        let path_export_to_successors = entry
            .get("path_export_to_successors")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        tasks.push(ParsedTask {
            task_name,
            agent_type,
            predecessors,
            path_allowlist,
            path_export_to_successors,
            path_export_globs,
        });
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
        if let Some(arr) = orch
            .get("cross_cutting_artifacts")
            .and_then(|v| v.as_array())
        {
            for v in arr {
                let s = v.as_str().unwrap_or("");
                if let Err(reason) = check_cross_cutting_entry(s) {
                    r.fail("cross_cutting_artifacts", format!("entry `{s}`: {reason}"));
                    return r;
                }
            }
            r.ok(&format!(
                "cross_cutting_artifacts: {} entry/entries OK",
                arr.len()
            ));
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

    add_reviewer_export_visibility_warnings(&tasks, &mut r);

    // ── Step 8: custom tools and profile attachments ─────────────────────
    let tool_report = raxis_tool_authoring::validate_plan_tools(text);
    for warning in tool_report.warnings {
        r.lines.push(format!("[WARN] custom tools: {warning}"));
    }
    if let Some(error) = tool_report.errors.first() {
        r.fail("custom tools", error.clone());
        return r;
    }
    r.ok(&format!(
        "custom tools: {} declaration(s) pass authoring checks",
        tool_report.tool_count
    ));

    r
}

#[derive(Debug)]
struct ParsedTask {
    task_name: String,
    agent_type: String,
    predecessors: Vec<String>,
    path_allowlist: Vec<String>,
    path_export_to_successors: bool,
    path_export_globs: Vec<String>,
}

fn toml_string_array(entry: &toml::Value, field: &str) -> Vec<String> {
    entry
        .get(field)
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(str::trim))
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

fn validate_dag(tasks: &[ParsedTask]) -> Result<(), String> {
    let mut seen: HashMap<&str, usize> = HashMap::with_capacity(tasks.len());
    for (i, t) in tasks.iter().enumerate() {
        if let Some(prev_i) = seen.insert(t.task_name.as_str(), i) {
            return Err(format!(
                "duplicate task_name `{0}` declared at tasks[{prev_i}] and tasks[{i}]; \
                 every task must have a unique task_name within the initiative",
                t.task_name,
            ));
        }
    }
    let known: HashSet<&str> = seen.keys().copied().collect();

    for t in tasks {
        for p in &t.predecessors {
            if p == &t.task_name {
                return Err(format!(
                    "task `{0}` lists itself in `predecessors`; \
                     a task cannot depend on itself",
                    t.task_name,
                ));
            }
            if !known.contains(p.as_str()) {
                return Err(format!(
                    "task `{0}` lists predecessor `{p}` which is not declared in this plan; \
                     remove the dangling reference or add the missing [[tasks]] block",
                    t.task_name,
                ));
            }
        }
    }

    // Cycle detection — iterative DFS, three-color marking.
    enum Color {
        White,
        Gray,
        Black,
    }
    let mut color: HashMap<&str, Color> = tasks
        .iter()
        .map(|t| (t.task_name.as_str(), Color::White))
        .collect();
    let pred_map: HashMap<&str, &[String]> = tasks
        .iter()
        .map(|t| (t.task_name.as_str(), t.predecessors.as_slice()))
        .collect();

    for t in tasks {
        if matches!(color[t.task_name.as_str()], Color::Black) {
            continue;
        }
        let mut stack: Vec<(&str, usize)> = vec![(t.task_name.as_str(), 0)];
        while let Some(&(node, idx)) = stack.last() {
            match color.get(node).unwrap() {
                Color::Black => {
                    stack.pop();
                    continue;
                }
                Color::White => {
                    color.insert(node, Color::Gray);
                }
                Color::Gray => { /* fall through to child walk */ }
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

fn add_reviewer_export_visibility_warnings(tasks: &[ParsedTask], report: &mut ValidationReport) {
    let by_name: HashMap<&str, &ParsedTask> = tasks
        .iter()
        .map(|task| (task.task_name.as_str(), task))
        .collect();

    for reviewer in tasks.iter().filter(|task| task.agent_type == "Reviewer") {
        for predecessor_name in &reviewer.predecessors {
            let Some(predecessor) = by_name.get(predecessor_name.as_str()) else {
                continue;
            };
            if !predecessor.path_export_to_successors {
                continue;
            }
            if predecessor.path_export_globs.is_empty() {
                report.lines.push(format!(
                    "[WARN] reviewer path scope: reviewer `{}` depends on `{}`, which exports its full touched set. Add `path_export_globs` to `{}` and make sure the reviewer path_allowlist covers the review artifacts.",
                    reviewer.task_name, predecessor.task_name, predecessor.task_name
                ));
                continue;
            }
            for exported in &predecessor.path_export_globs {
                if !export_pattern_covered_by_allowlist(exported, &reviewer.path_allowlist) {
                    report.lines.push(format!(
                        "[WARN] reviewer path scope: reviewer `{}` may not be able to read predecessor `{}` export `{}`. Add `{}` or a covering directory prefix to the reviewer path_allowlist, or remove the export if the reviewer should not inspect it.",
                        reviewer.task_name,
                        predecessor.task_name,
                        exported,
                        suggested_allowlist_entry(exported),
                    ));
                }
            }
        }
    }
}

fn export_pattern_covered_by_allowlist(pattern: &str, allowlist: &[String]) -> bool {
    if contains_glob_meta(pattern) {
        let prefix = literal_directory_prefix(pattern);
        !prefix.is_empty()
            && allowlist
                .iter()
                .any(|allow| allow_covers_path(allow, prefix))
    } else {
        allowlist
            .iter()
            .any(|allow| allow_covers_path(allow, pattern))
    }
}

fn allow_covers_path(allow: &str, path: &str) -> bool {
    if allow.ends_with('/') {
        path.starts_with(allow)
    } else {
        path == allow
    }
}

fn contains_glob_meta(value: &str) -> bool {
    value
        .chars()
        .any(|c| matches!(c, '*' | '?' | '[' | ']' | '{' | '}'))
}

fn literal_directory_prefix(pattern: &str) -> &str {
    let first_meta = pattern
        .char_indices()
        .find_map(|(idx, c)| matches!(c, '*' | '?' | '[' | ']' | '{' | '}').then_some(idx))
        .unwrap_or(pattern.len());
    let literal = &pattern[..first_meta];
    literal.rfind('/').map(|idx| &literal[..=idx]).unwrap_or("")
}

fn suggested_allowlist_entry(pattern: &str) -> String {
    if contains_glob_meta(pattern) {
        let prefix = literal_directory_prefix(pattern);
        if prefix.is_empty() {
            "<covering-directory-prefix>/".to_owned()
        } else {
            prefix.to_owned()
        }
    } else if pattern.ends_with('/') {
        pattern.to_owned()
    } else {
        pattern
            .rfind('/')
            .map(|idx| pattern[..=idx].to_owned())
            .unwrap_or_else(|| pattern.to_owned())
    }
}

fn check_cross_cutting_entry(entry: &str) -> Result<(), &'static str> {
    if entry.is_empty() {
        return Err("empty entry");
    }
    if entry.starts_with('!') {
        return Err("leading `!` (negation marker not permitted)");
    }
    if entry.starts_with('/') {
        return Err("absolute path not permitted");
    }
    if entry.ends_with('/') {
        return Err("trailing `/` not permitted (must be exact filename)");
    }
    if entry.split('/').any(|seg| seg == "..") {
        return Err("`..` path-escape segment");
    }
    if entry.contains('/') {
        return Err("must be an exact filename (no `/`)");
    }
    if entry
        .chars()
        .any(|c| matches!(c, '*' | '?' | '[' | ']' | '{' | '}'))
    {
        return Err("glob character not permitted");
    }
    Ok(())
}

fn validate_path_allowlists_in_doc(doc: &toml::Value) -> Result<(), String> {
    let Some(tasks) = doc.get("tasks").and_then(|v| v.as_array()) else {
        return Ok(());
    };
    for entry in tasks {
        let task_name = entry
            .get("task_name")
            .and_then(|v| v.as_str())
            .unwrap_or("?");
        let Some(arr) = entry.get("path_allowlist").and_then(|v| v.as_array()) else {
            continue;
        };
        for v in arr {
            let s = v.as_str().unwrap_or("");
            if let Err(reason) = check_path_allowlist_entry(s) {
                return Err(format!(
                    "task `{task_name}` path_allowlist entry `{s}`: {reason}"
                ));
            }
        }
    }
    Ok(())
}

fn check_path_allowlist_entry(entry: &str) -> Result<(), &'static str> {
    if entry.is_empty() {
        return Err("empty entry");
    }
    if entry.starts_with('!') {
        return Err("leading `!` (negation marker not permitted)");
    }
    if entry.starts_with('/') {
        return Err("absolute path not permitted");
    }
    // Glob characters are rejected — V2 path_allowlist uses exact
    // filenames or directory prefixes only.
    if entry
        .chars()
        .any(|c| matches!(c, '*' | '?' | '[' | ']' | '{' | '}'))
    {
        return Err("glob character not permitted (use exact filenames or directory prefixes)");
    }
    // `..` segments at any position. Note: `..` as part of a filename
    // (e.g. `foo..bar`) is allowed; only standalone segments are rejected.
    if entry.split('/').any(|seg| seg == "..") {
        return Err("`..` path-escape segment");
    }
    Ok(())
}

fn validate_repository_id(id: &str) -> Result<(), String> {
    if id.is_empty() {
        return Err("repository id is empty".to_owned());
    }
    if id.len() > 64 {
        return Err(format!(
            "repository id is {} bytes, exceeds cap 64",
            id.len()
        ));
    }
    let mut chars = id.chars();
    let first = chars.next().unwrap();
    if !first.is_ascii_alphanumeric() {
        return Err("repository id must start with an ASCII letter or digit".to_owned());
    }
    if id == "." || id == ".." || id.contains('/') || id.contains('\\') {
        return Err("repository id must be a single path-safe segment".to_owned());
    }
    if !chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_')) {
        return Err(
            "repository id may contain only ASCII letters, digits, '.', '-' and '_'".to_owned(),
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Smoke checks for the operator-facing message text
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Standard test plan: every required field present, two tasks
    /// with descriptions, deterministic DAG. Extend tests using
    /// `passing_plan_with(...)` when a single field needs to vary.
    fn passing_plan() -> &'static str {
        r#"
[plan.initiative]
description = "Add a healthz endpoint"

[workspace]
name = "fixture"
lane_id = "default"

[[tasks]]
task_name            = "build"
description        = "Compile the new endpoint and supporting modules"
prompt             = "Compile the new endpoint and supporting modules"
session_agent_type = "Executor"
clone_strategy     = "blobless"

[[tasks]]
task_name            = "test"
description        = "Run the integration test against /healthz"
prompt             = "Run the integration test against /healthz"
session_agent_type = "Executor"
clone_strategy     = "blobless"
predecessors       = ["build"]
"#
    }

    #[test]
    fn happy_path_passes_validation() {
        let r = validate_plan_text(passing_plan());
        assert!(r.first_error.is_none(), "report: {:#?}", r.lines);
        assert!(r.lines.iter().any(|l| l.contains("[OK] TOML parses")));
        assert!(r
            .lines
            .iter()
            .any(|l| l.contains("[OK] 2 task(s) declared")));
    }

    #[test]
    fn missing_workspace_section_is_rejected() {
        let r = validate_plan_text(
            r#"
[plan.initiative]
description = "fixture"

[[tasks]]
task_name     = "a"
description = "do thing"
prompt = "do thing"
session_agent_type = "Executor"
clone_strategy = "blobless"
"#,
        );
        assert!(r.first_error.as_ref().unwrap().contains("[workspace]"));
    }

    #[test]
    fn missing_workspace_lane_is_rejected() {
        let r = validate_plan_text(
            r#"
[plan.initiative]
description = "fixture"

[workspace]
name = "fixture"

[[tasks]]
task_name     = "a"
description = "do thing"
prompt = "do thing"
session_agent_type = "Executor"
clone_strategy = "blobless"
"#,
        );
        let err = r.first_error.unwrap();
        assert!(err.contains("[workspace] lane_id"), "err = {err}");
    }

    #[test]
    fn orchestrator_task_declaration_is_rejected_with_v2_hint() {
        let r = validate_plan_text(
            r#"
[plan.initiative]
description = "fixture"

[workspace]
name = "fixture"
lane_id = "default"

[[tasks]]
task_name            = "orch"
description        = "do thing"
prompt             = "do thing"
session_agent_type = "Orchestrator"
"#,
        );
        let err = r.first_error.unwrap();
        assert!(err.contains("Orchestrator"), "err = {err}");
        assert!(err.contains("auto-create"), "err = {err}");
    }

    #[test]
    fn invalid_clone_strategy_is_rejected() {
        let r = validate_plan_text(
            r#"
[plan.initiative]
description = "fixture"

[workspace]
name = "fixture"
lane_id = "default"

[[tasks]]
task_name        = "a"
description    = "do thing"
prompt         = "do thing"
session_agent_type = "Executor"
clone_strategy = "shallow"
"#,
        );
        let err = r.first_error.unwrap();
        assert!(err.contains("clone_strategy"), "err = {err}");
        assert!(err.contains("full, blobless, sparse"), "err = {err}");
    }

    #[test]
    fn deprecated_context_is_rejected_with_prompt_hint() {
        let r = validate_plan_text(
            r#"
[plan.initiative]
description = "fixture"

[workspace]
name = "fixture"
lane_id = "default"

[[tasks]]
task_name     = "a"
description = "Create a greeting"
context     = "Write HELLO.md"
"#,
        );
        let err = r.first_error.unwrap();
        assert!(err.contains("context"), "err = {err}");
        assert!(err.contains("prompt"), "err = {err}");
    }

    #[test]
    fn task_prompt_is_validated_when_present() {
        let r = validate_plan_text(
            r#"
[plan.initiative]
description = "fixture"

[workspace]
name = "fixture"
lane_id = "default"

[[tasks]]
task_name     = "a"
description = "Create a greeting"
prompt      = """
Write HELLO.md with the exact text: hello from alex.
"""
session_agent_type = "Executor"
clone_strategy = "blobless"
"#,
        );
        assert!(r.first_error.is_none(), "report: {:#?}", r.lines);
    }

    #[test]
    fn workspace_repository_is_validated_when_present() {
        let r = validate_plan_text(
            r#"
[plan.initiative]
description = "fixture"

[workspace]
name = "fixture"
lane_id = "default"
repository = "api-service"

[[tasks]]
task_name     = "a"
description = "Create a greeting"
prompt = "Create a greeting"
session_agent_type = "Executor"
clone_strategy = "blobless"
"#,
        );
        assert!(r.first_error.is_none(), "report: {:#?}", r.lines);
        assert!(r
            .lines
            .iter()
            .any(|l| l.contains("[workspace] repository = \"api-service\"")));
    }

    #[test]
    fn unsafe_workspace_repository_is_rejected() {
        let r = validate_plan_text(
            r#"
[plan.initiative]
description = "fixture"

[workspace]
name = "fixture"
lane_id = "default"
repository = "api/foo"

[[tasks]]
task_name     = "a"
description = "Create a greeting"
"#,
        );
        let err = r.first_error.unwrap();
        assert!(err.contains("repository"), "err = {err}");
        assert!(err.contains("path-safe"), "err = {err}");
    }

    #[test]
    fn empty_task_prompt_is_rejected() {
        let r = validate_plan_text(
            r#"
[plan.initiative]
description = "fixture"

[workspace]
name = "fixture"
lane_id = "default"

[[tasks]]
task_name     = "a"
description = "Create a greeting"
prompt      = "   "
"#,
        );
        let err = r.first_error.unwrap();
        assert!(err.contains("prompt"), "err = {err}");
    }

    #[test]
    fn per_task_lane_id_override_is_rejected() {
        let r = validate_plan_text(
            r#"
[plan.initiative]
description = "fixture"

[workspace]
name = "fixture"
lane_id = "default"

[[tasks]]
task_name     = "a"
description = "do thing"
prompt = "do thing"
session_agent_type = "Executor"
clone_strategy = "blobless"
lane_id     = "other"
"#,
        );
        let err = r.first_error.unwrap();
        assert!(err.contains("single-lane propagation"), "err = {err}");
    }

    #[test]
    fn duplicate_task_names_are_rejected() {
        let r = validate_plan_text(
            r#"
[plan.initiative]
description = "fixture"

[workspace]
name = "fixture"
lane_id = "default"

[[tasks]]
task_name     = "a"
description = "do thing"
prompt = "do thing"
session_agent_type = "Executor"
clone_strategy = "blobless"
[[tasks]]
task_name     = "a"
description = "do thing again"
prompt = "do thing again"
session_agent_type = "Executor"
clone_strategy = "blobless"
"#,
        );
        let err = r.first_error.unwrap();
        assert!(err.contains("duplicate"), "err = {err}");
    }

    #[test]
    fn self_loop_is_rejected() {
        let r = validate_plan_text(
            r#"
[plan.initiative]
description = "fixture"

[workspace]
name = "fixture"
lane_id = "default"

[[tasks]]
task_name      = "a"
description  = "do thing"
prompt = "do thing"
session_agent_type = "Executor"
clone_strategy = "blobless"
predecessors = ["a"]
"#,
        );
        let err = r.first_error.unwrap();
        assert!(err.contains("itself"), "err = {err}");
    }

    #[test]
    fn dangling_predecessor_is_rejected() {
        let r = validate_plan_text(
            r#"
[plan.initiative]
description = "fixture"

[workspace]
name = "fixture"
lane_id = "default"

[[tasks]]
task_name      = "a"
description  = "do thing"
prompt = "do thing"
session_agent_type = "Executor"
clone_strategy = "blobless"
predecessors = ["ghost"]
"#,
        );
        let err = r.first_error.unwrap();
        assert!(err.contains("ghost"), "err = {err}");
    }

    #[test]
    fn cycle_is_detected() {
        let r = validate_plan_text(
            r#"
[plan.initiative]
description = "fixture"

[workspace]
name = "fixture"
lane_id = "default"

[[tasks]]
task_name      = "a"
description  = "do thing"
prompt = "do thing"
session_agent_type = "Executor"
clone_strategy = "blobless"
predecessors = ["b"]

[[tasks]]
task_name      = "b"
description  = "do other thing"
prompt = "do other thing"
session_agent_type = "Executor"
clone_strategy = "blobless"
predecessors = ["a"]
"#,
        );
        let err = r.first_error.unwrap();
        assert!(err.contains("cycle"), "err = {err}");
    }

    #[test]
    fn cross_cutting_artifact_globs_are_rejected() {
        let r = validate_plan_text(
            r#"
[plan.initiative]
description = "fixture"

[workspace]
name = "fixture"
lane_id = "default"

[orchestrator]
cross_cutting_artifacts = ["Cargo.lock", "*.toml"]

[[tasks]]
task_name     = "a"
description = "do thing"
prompt = "do thing"
session_agent_type = "Executor"
clone_strategy = "blobless"
"#,
        );
        let err = r.first_error.unwrap();
        assert!(err.contains("glob"), "err = {err}");
    }

    #[test]
    fn path_allowlist_glob_is_rejected() {
        let r = validate_plan_text(
            r#"
[plan.initiative]
description = "fixture"

[workspace]
name = "fixture"
lane_id = "default"

[[tasks]]
task_name        = "a"
description    = "do thing"
prompt = "do thing"
session_agent_type = "Executor"
clone_strategy = "blobless"
path_allowlist = ["src/*.rs"]
"#,
        );
        let err = r.first_error.unwrap();
        assert!(err.contains("glob"), "err = {err}");
    }

    #[test]
    fn reviewer_export_visibility_mismatch_warns_without_failing() {
        let r = validate_plan_text(
            r#"
[plan.initiative]
description = "fixture"

[workspace]
name = "fixture"
lane_id = "default"

[[tasks]]
task_name = "produce-report"
description = "Write the report"
prompt = "Write the report"
session_agent_type = "Executor"
clone_strategy = "blobless"
path_allowlist = ["reports/"]
path_export_to_successors = true
path_export_globs = ["reports/generated/summary.md"]

[[tasks]]
task_name = "review-report"
description = "Review the report"
prompt = "Review the report"
session_agent_type = "Reviewer"
clone_strategy = "blobless"
path_allowlist = ["src/"]
predecessors = ["produce-report"]
"#,
        );
        assert!(r.first_error.is_none(), "report: {:#?}", r.lines);
        assert!(
            r.lines
                .iter()
                .any(|line| line.contains("[WARN] reviewer path scope")
                    && line.contains("reports/generated/summary.md")),
            "report: {:#?}",
            r.lines
        );
    }

    #[test]
    fn reviewer_export_visibility_covered_by_directory_has_no_warning() {
        let r = validate_plan_text(
            r#"
[plan.initiative]
description = "fixture"

[workspace]
name = "fixture"
lane_id = "default"

[[tasks]]
task_name = "produce-report"
description = "Write the report"
prompt = "Write the report"
session_agent_type = "Executor"
clone_strategy = "blobless"
path_allowlist = ["reports/"]
path_export_to_successors = true
path_export_globs = ["reports/generated/*.md"]

[[tasks]]
task_name = "review-report"
description = "Review the report"
prompt = "Review the report"
session_agent_type = "Reviewer"
clone_strategy = "blobless"
path_allowlist = ["reports/generated/"]
predecessors = ["produce-report"]
"#,
        );
        assert!(r.first_error.is_none(), "report: {:#?}", r.lines);
        assert!(
            r.lines
                .iter()
                .all(|line| !line.contains("[WARN] reviewer path scope")),
            "report: {:#?}",
            r.lines
        );
    }

    #[test]
    fn single_task_plan_passes() {
        let r = validate_plan_text(
            r#"
[plan.initiative]
description = "fixture"

[workspace]
name = "fixture"
lane_id = "default"

[[tasks]]
task_name     = "noop"
description = "do thing"
prompt = "do thing"
session_agent_type = "Executor"
clone_strategy = "blobless"
"#,
        );
        assert!(r.first_error.is_none(), "report: {:#?}", r.lines);
    }

    // ── initiative metadata checks ────────────────

    #[test]
    fn missing_plan_initiative_section_is_rejected() {
        let r = validate_plan_text(
            r#"
[workspace]
name = "fixture"
lane_id = "default"

[[tasks]]
task_name     = "a"
description = "do thing"
prompt = "do thing"
session_agent_type = "Executor"
clone_strategy = "blobless"
"#,
        );
        let err = r.first_error.unwrap();
        assert!(err.contains("[plan.initiative]"), "err = {err}");
        assert!(err.contains("§1.1"), "err = {err}");
    }

    #[test]
    fn missing_workspace_name_is_rejected() {
        let r = validate_plan_text(
            r#"
[plan.initiative]
description = "fixture"

[workspace]
lane_id = "default"

[[tasks]]
task_name     = "a"
description = "do thing"
prompt = "do thing"
session_agent_type = "Executor"
clone_strategy = "blobless"
"#,
        );
        let err = r.first_error.unwrap();
        assert!(err.contains("[workspace] name"), "err = {err}");
        assert!(err.contains("missing"), "err = {err}");
    }

    #[test]
    fn empty_workspace_name_is_rejected() {
        let r = validate_plan_text(
            r#"
[plan.initiative]
description = "fixture"

[workspace]
name = "   "
lane_id = "default"

[[tasks]]
task_name     = "a"
description = "do thing"
prompt = "do thing"
session_agent_type = "Executor"
clone_strategy = "blobless"
"#,
        );
        let err = r.first_error.unwrap();
        assert!(err.contains("[workspace] name"), "err = {err}");
        assert!(err.contains("empty"), "err = {err}");
    }

    #[test]
    fn oversized_workspace_name_is_rejected() {
        let name = "x".repeat(65);
        let plan = format!(
            r#"
[plan.initiative]
description = "fixture"

[workspace]
name = "{name}"
lane_id = "default"

[[tasks]]
task_name     = "a"
description = "do thing"
prompt = "do thing"
session_agent_type = "Executor"
clone_strategy = "blobless"
"#
        );
        let r = validate_plan_text(&plan);
        let err = r.first_error.unwrap();
        assert!(err.contains("[workspace] name"), "err = {err}");
        assert!(err.contains("64"), "err = {err}");
    }

    #[test]
    fn missing_plan_initiative_description_is_rejected() {
        let r = validate_plan_text(
            r#"
[plan.initiative]
[workspace]
name = "fixture"
lane_id = "default"

[[tasks]]
task_name     = "a"
description = "do thing"
prompt = "do thing"
session_agent_type = "Executor"
clone_strategy = "blobless"
"#,
        );
        let err = r.first_error.unwrap();
        assert!(err.contains("[plan.initiative] description"), "err = {err}");
        assert!(err.contains("missing"), "err = {err}");
    }

    #[test]
    fn empty_plan_initiative_description_is_rejected() {
        let r = validate_plan_text(
            r#"
[plan.initiative]
description = "   "

[workspace]
name = "fixture"
lane_id = "default"

[[tasks]]
task_name     = "a"
description = "do thing"
prompt = "do thing"
session_agent_type = "Executor"
clone_strategy = "blobless"
"#,
        );
        let err = r.first_error.unwrap();
        assert!(err.contains("[plan.initiative] description"), "err = {err}");
        assert!(err.contains("empty"), "err = {err}");
    }

    #[test]
    fn missing_task_description_is_rejected() {
        let r = validate_plan_text(
            r#"
[plan.initiative]
description = "fixture"

[workspace]
name = "fixture"
lane_id = "default"

[[tasks]]
task_name = "a"
"#,
        );
        let err = r.first_error.unwrap();
        assert!(err.contains("[[tasks]] description"), "err = {err}");
        assert!(err.contains("missing"), "err = {err}");
        assert!(err.contains("`a`"), "err = {err}");
    }

    #[test]
    fn empty_task_description_is_rejected() {
        let r = validate_plan_text(
            r#"
[plan.initiative]
description = "fixture"

[workspace]
name = "fixture"
lane_id = "default"

[[tasks]]
task_name     = "a"
description = "   "
"#,
        );
        let err = r.first_error.unwrap();
        assert!(err.contains("[[tasks]] description"), "err = {err}");
        assert!(err.contains("empty"), "err = {err}");
    }

    #[test]
    fn oversized_task_description_is_rejected() {
        let huge = "x".repeat(65 * 1024);
        let plan = format!(
            r#"
[plan.initiative]
description = "fixture"

[workspace]
name = "fixture"
lane_id = "default"

[[tasks]]
task_name     = "a"
description = "{huge}"
"#
        );
        let r = validate_plan_text(&plan);
        let err = r.first_error.unwrap();
        assert!(err.contains("64 KiB"), "err = {err}");
    }

    fn _unused_warns_to_silence_compiler(p: &std::path::Path) {
        let _ = p;
    }
}

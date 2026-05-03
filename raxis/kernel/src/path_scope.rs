// raxis-kernel::path_scope — VCS path-scope enforcement (INV-TASK-PATH-01/02).
//
// Normative reference: kernel-store.md §2.5.8 — "VCS Path Scope Enforcement"
// (the *sole* normative source). This module is a 1:1 implementation of the
// pseudocode in §2.5.8 `effective_allow(task_id)` and `check_paths(...)`,
// composed against the in-memory `PlanRegistry` (signed-plan fields) and
// `task_exported_path_snapshots` (predecessor exports persisted at
// completion time).
//
// What this module is and is not
// ------------------------------
// IS:
//   * The compound-allow-set type (`AllowSet` = glob patterns ∪ exact paths).
//   * The `effective_allow(task_id, ...)` algorithm, with the two-layer
//     semantics: task's own `path_allowlist` plus completed-direct-predecessor
//     exports filtered by `path_export_to_successors`.
//   * The `check_paths(touched_paths, task_id, ...)` predicate that returns
//     a `PathPolicyViolation` listing the offending paths (used internally
//     for logs only — INV-08 says the wire response is the opaque code
//     `FAIL_PATH_POLICY_VIOLATION` with no path list).
//
// IS NOT:
//   * The IPC handler integration. That lives in `handlers/intent.rs`
//     (steps 3A and the CompleteTask branch).
//   * The TOML parser for the four plan fields. That lives in
//     `initiatives/lifecycle.rs::parse_plan_tasks`.
//   * The exported-paths snapshot writer. That lives in
//     `handlers/intent.rs` CompleteTask branch (under the same SQLite
//     transaction as the `Running → Completed` UPDATE).
//
// Glob semantics
// --------------
// Per §2.5.8 "Glob rules: `*` does not cross `/`, `**` crosses directory
// boundaries". The `glob` crate's `Pattern` matches this when called with
// `MatchOptions { require_literal_separator: true, .. }`. Other wildcards
// (`?`, character classes, negation) are still accepted by the parser
// silently — the spec forbids them at sign time but the kernel does not
// re-validate. This is intentional: the signing tool is the gate.

use std::collections::BTreeSet;
use std::path::Path;

use glob::{MatchOptions, Pattern};
use raxis_store::{Store, Table};

use crate::initiatives::{PlanRegistry, TaskKey, TaskPlanFields};

const TASK_DAG_EDGES:               &str = Table::TaskDagEdges.as_str();
const TASKS:                        &str = Table::Tasks.as_str();
const TASK_EXPORTED_PATH_SNAPSHOTS: &str = Table::TaskExportedPathSnapshots.as_str();

// ---------------------------------------------------------------------------
// AllowSet — glob patterns ∪ exact paths, with override flag
// ---------------------------------------------------------------------------

/// The compound allow-set for one task, as defined in §2.5.8:
///
/// ```text
/// matches_allow(p, E) := E.universal
///                    || E.glob_patterns.any(g -> glob_match(g, p))
///                    || E.exact_paths.contains(p)
/// ```
///
/// Construction is fallible (an unparseable glob in the signed plan is a
/// configuration error caught at sign time, but the kernel still has to
/// handle it without panicking; we surface it as
/// `PathScopeError::InvalidGlob`).
#[derive(Debug, Default)]
pub struct AllowSet {
    /// `path_scope_override = true` short-circuits all checks. When set,
    /// `glob_patterns` and `exact_paths` are ignored. `PathScopeOverrideApplied`
    /// has already been emitted at `approve_plan` time per §2.5.8.
    pub universal:     bool,
    /// Compiled glob patterns from the task's signed `path_allowlist`.
    pub glob_patterns: Vec<Pattern>,
    /// Concrete literal paths inherited from completed-predecessor
    /// exports. These are NOT compiled as globs — see §2.5.8 "Why the
    /// compound type matters".
    pub exact_paths:   BTreeSet<String>,
}

impl AllowSet {
    /// Universal/override singleton — every check passes.
    pub fn universal() -> Self {
        Self { universal: true, ..Default::default() }
    }

    /// Test whether one path is allowed.
    ///
    /// Glob match uses `require_literal_separator = true` so `*` does not
    /// cross `/` (matching the §2.5.8 normative glob rules).
    pub fn matches(&self, path: &str) -> bool {
        if self.universal {
            return true;
        }
        let opts = MatchOptions {
            case_sensitive:              true,
            require_literal_separator:   true,
            require_literal_leading_dot: false,
        };
        let p = Path::new(path);
        if self.glob_patterns.iter().any(|g| g.matches_path_with(p, opts)) {
            return true;
        }
        self.exact_paths.contains(path)
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors raised by `effective_allow` / `check_paths`.
#[derive(Debug, thiserror::Error)]
pub enum PathScopeError {
    /// The task has no entry in the in-memory `PlanRegistry`. This is a
    /// fail-closed marker: the intent handler treats it as
    /// `FAIL_PATH_POLICY_VIOLATION` rather than silently widening to
    /// "deny everything by accident allowed everything".
    #[error("no plan-registry entry for task `{task_id}` (initiative `{initiative_id}`)")]
    NoPlanEntry { initiative_id: String, task_id: String },

    /// A glob pattern in the signed plan failed to parse. The signing
    /// tool is supposed to validate these; this is a defense-in-depth
    /// branch.
    #[error("invalid glob pattern in plan: `{pattern}`: {reason}")]
    InvalidGlob { pattern: String, reason: String },

    #[error("store error while computing effective_allow: {0}")]
    Store(#[from] rusqlite::Error),
}

/// Returned by `check_paths` when one or more paths fall outside the
/// computed `AllowSet`. The IPC layer collapses this to the opaque
/// `PlannerErrorCode::FailPathPolicyViolation` (INV-08); the path list
/// is for kernel-side logging only and never crosses the IPC boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathPolicyViolation {
    pub paths: Vec<String>,
}

// ---------------------------------------------------------------------------
// effective_allow — §2.5.8 normative algorithm
// ---------------------------------------------------------------------------

/// Compute the `AllowSet` for `task_id` per §2.5.8.
///
/// Steps (mirror of the spec pseudocode):
/// 1. Load the task's signed plan fields from the registry. Missing →
///    `NoPlanEntry` (fail-closed).
/// 2. If `path_scope_override` → return `AllowSet::universal()` and stop.
/// 3. Compile the task's own `path_allowlist` into `glob_patterns`.
/// 4. For each direct DAG predecessor: if `Completed` AND
///    `path_export_to_successors`, fold its `task_exported_path_snapshots`
///    rows into `exact_paths`.
///
/// Caller responsibility: re-invoke on every intent admission and at
/// CompleteTask. The spec forbids caching across calls — a predecessor's
/// completion between two intents must immediately widen the set.
pub fn effective_allow(
    initiative_id: &str,
    task_id:       &str,
    registry:      &PlanRegistry,
    store:         &Store,
) -> Result<AllowSet, PathScopeError> {
    let key = TaskKey::new(initiative_id, task_id);
    let fields = registry
        .get(&key)
        .ok_or_else(|| PathScopeError::NoPlanEntry {
            initiative_id: initiative_id.to_owned(),
            task_id:       task_id.to_owned(),
        })?;

    if fields.path_scope_override {
        return Ok(AllowSet::universal());
    }

    let glob_patterns = compile_globs(&fields.path_allowlist)?;
    let exact_paths   = collect_predecessor_exports(initiative_id, task_id, registry, store)?;

    Ok(AllowSet { universal: false, glob_patterns, exact_paths })
}

/// Compile a list of glob strings into `glob::Pattern`s, surfacing the
/// first parse failure as `InvalidGlob`.
fn compile_globs(globs: &[String]) -> Result<Vec<Pattern>, PathScopeError> {
    let mut out = Vec::with_capacity(globs.len());
    for raw in globs {
        let pat = Pattern::new(raw).map_err(|e| PathScopeError::InvalidGlob {
            pattern: raw.clone(),
            reason:  e.to_string(),
        })?;
        out.push(pat);
    }
    Ok(out)
}

/// Walk direct (`depends_on`) predecessors of `task_id` and union together
/// their `task_exported_path_snapshots` rows whenever the predecessor is
/// `Completed` AND its plan has `path_export_to_successors = true`.
///
/// A predecessor missing from the registry is **silently skipped** —
/// it almost certainly belongs to a different initiative or has already
/// been pruned, and §2.5.8 explicitly says the grant "activates on
/// `Completed` only" with no obligation to error out otherwise. (Contrast
/// with the *successor's* missing-registry case, which is a hard
/// `NoPlanEntry` because the successor IS the subject of the check.)
fn collect_predecessor_exports(
    initiative_id: &str,
    task_id:       &str,
    registry:      &PlanRegistry,
    store:         &Store,
) -> Result<BTreeSet<String>, PathScopeError> {
    let conn = store.lock_sync();

    // Direct predecessors only. §2.5.8: "Direct deps only controls which
    // predecessor ROWS are queried — not what those rows CONTAIN. Path
    // sets propagate transitively through exports by construction."
    let mut stmt = conn.prepare_cached(&format!(
        "SELECT predecessor_task_id FROM {TASK_DAG_EDGES} WHERE successor_task_id = ?1",
    ))?;
    let predecessors: Vec<String> = stmt
        .query_map(rusqlite::params![task_id], |r| r.get::<_, String>(0))?
        .collect::<Result<_, _>>()?;

    if predecessors.is_empty() {
        return Ok(BTreeSet::new());
    }

    let mut out = BTreeSet::new();

    for pred_id in predecessors {
        // 1. Predecessor's run state must be `Completed`. Aborted /
        //    Failed / Running / GatesPending all skip silently per spec
        //    "grant activates on Completed only".
        let state: String = conn.query_row(
            &format!("SELECT state FROM {TASKS} WHERE task_id = ?1"),
            rusqlite::params![pred_id],
            |r| r.get(0),
        )?;
        if state != "Completed" {
            continue;
        }

        // 2. Predecessor's plan must opt-in to export. Default is `false`
        //    (zero-blast-radius); silent skip when absent or off.
        let pred_fields = registry.get(&TaskKey::new(initiative_id, &pred_id));
        let opts_in = pred_fields
            .as_ref()
            .map(|f: &TaskPlanFields| f.path_export_to_successors)
            .unwrap_or(false);
        if !opts_in {
            continue;
        }

        // 3. Drain the persisted snapshot. Rows here were written
        //    inside the predecessor's `Running → Completed` transaction
        //    by the CompleteTask branch.
        let mut sn = conn.prepare_cached(&format!(
            "SELECT path FROM {TASK_EXPORTED_PATH_SNAPSHOTS} WHERE task_id = ?1",
        ))?;
        for row in sn.query_map(rusqlite::params![pred_id], |r| r.get::<_, String>(0))? {
            out.insert(row?);
        }
    }

    Ok(out)
}

// ---------------------------------------------------------------------------
// check_paths — §2.5.8 path-coverage predicate
// ---------------------------------------------------------------------------

/// Run `check_paths(touched_paths, task_id)` per §2.5.8.
///
/// Returns:
///   * `Ok(())` on full coverage (including the trivial empty-input case).
///   * `Err(PathPolicyViolation)` listing every offending path on miss
///     (the IPC handler discards the list and returns the opaque code).
///   * `Err(PathScopeError::NoPlanEntry)` if the task has no registry row;
///     the caller maps this to `FAIL_PATH_POLICY_VIOLATION` to stay
///     fail-closed.
pub fn check_paths(
    touched_paths: &[std::path::PathBuf],
    initiative_id: &str,
    task_id:       &str,
    registry:      &PlanRegistry,
    store:         &Store,
) -> Result<Result<(), PathPolicyViolation>, PathScopeError> {
    let allow = effective_allow(initiative_id, task_id, registry, store)?;

    let mut violations: Vec<String> = Vec::new();
    for p in touched_paths {
        let s = p.to_string_lossy();
        if !allow.matches(&s) {
            violations.push(s.into_owned());
        }
    }

    Ok(if violations.is_empty() {
        Ok(())
    } else {
        // Sort for determinism (audit/log output).
        violations.sort();
        Err(PathPolicyViolation { paths: violations })
    })
}

// ---------------------------------------------------------------------------
// Tests — pure logic + a small set of store-backed integration tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    use std::path::PathBuf;

    fn pat(s: &str) -> Pattern {
        Pattern::new(s).unwrap_or_else(|e| panic!("test glob `{s}` failed: {e}"))
    }

    // ── AllowSet::matches — pure semantics ────────────────────────────────

    #[test]
    fn universal_matches_everything() {
        let s = AllowSet::universal();
        assert!(s.matches("anything/at/all.rs"));
        assert!(s.matches(""));
        assert!(s.matches("../escape"));
    }

    #[test]
    fn empty_allowset_denies_everything() {
        let s = AllowSet::default();
        assert!(!s.matches("src/lib.rs"));
        assert!(!s.matches(""));
    }

    #[test]
    fn single_star_does_not_cross_path_separator() {
        // §2.5.8: "* does not cross /".
        let s = AllowSet {
            glob_patterns: vec![pat("src/*")],
            ..Default::default()
        };
        assert!(s.matches("src/lib.rs"));
        assert!(!s.matches("src/sub/lib.rs"), "* must not cross /");
    }

    #[test]
    fn double_star_crosses_path_separator() {
        let s = AllowSet {
            glob_patterns: vec![pat("src/**")],
            ..Default::default()
        };
        assert!(s.matches("src/lib.rs"));
        assert!(s.matches("src/sub/lib.rs"));
        assert!(s.matches("src/a/b/c/d.rs"));
        assert!(!s.matches("other/lib.rs"));
    }

    #[test]
    fn exact_paths_match_only_literally() {
        let mut exact = BTreeSet::new();
        exact.insert("src/ipc/handlers/new.rs".to_owned());
        let s = AllowSet { exact_paths: exact, ..Default::default() };
        assert!(s.matches("src/ipc/handlers/new.rs"));
        assert!(!s.matches("src/ipc/handlers/other.rs"));
        // Glob-looking literal must NOT be interpreted as a glob —
        // §2.5.8 explicitly warns against type confusion here.
        assert!(!s.matches("src/ipc/handlers/anything.rs"));
    }

    #[test]
    fn glob_or_exact_either_path_passes() {
        let mut exact = BTreeSet::new();
        exact.insert("README.md".to_owned());
        let s = AllowSet {
            glob_patterns: vec![pat("src/**")],
            exact_paths:   exact,
            ..Default::default()
        };
        assert!(s.matches("src/lib.rs"), "glob layer");
        assert!(s.matches("README.md"), "exact layer");
        assert!(!s.matches("docs/intro.md"), "neither layer");
    }

    #[test]
    fn compile_globs_propagates_first_failure() {
        let bad = vec!["src/**".to_owned(), "src/[unclosed".to_owned()];
        let err = compile_globs(&bad).expect_err("bad glob must fail");
        match err {
            PathScopeError::InvalidGlob { pattern, .. } => {
                assert_eq!(pattern, "src/[unclosed");
            }
            other => panic!("wrong error: {other:?}"),
        }
    }

    // ── effective_allow / check_paths against a real Store ────────────────
    //
    // These tests build a tiny in-memory state graph and exercise the
    // §2.5.8 layering rules end to end. They use the real DDL via
    // `Store::open_in_memory`, so any drift between the schema and the
    // SQL in this module breaks them.

    use raxis_store::Store;

    fn seed_initiative(store: &Store, init_id: &str) {
        let conn = store.lock_sync();
        conn.execute(
            "INSERT INTO initiatives
                (initiative_id, state, terminal_criteria_json,
                 plan_artifact_sha256, created_at)
             VALUES (?1, 'Executing', '{}', 'deadbeef', 0)",
            rusqlite::params![init_id],
        ).unwrap();
    }

    fn seed_task(store: &Store, init_id: &str, task_id: &str, state: &str) {
        let conn = store.lock_sync();
        conn.execute(
            "INSERT INTO tasks
                (task_id, initiative_id, lane_id, state, actor,
                 policy_epoch, admitted_at, transitioned_at, actual_cost)
             VALUES (?1, ?2, 'default', ?3, 'kernel', 1, 0, 0, 0)",
            rusqlite::params![task_id, init_id, state],
        ).unwrap();
    }

    fn seed_edge(store: &Store, init_id: &str, pred: &str, succ: &str) {
        let conn = store.lock_sync();
        conn.execute(
            "INSERT INTO task_dag_edges
                (initiative_id, predecessor_task_id, successor_task_id,
                 predecessor_satisfied)
             VALUES (?1, ?2, ?3, 0)",
            rusqlite::params![init_id, pred, succ],
        ).unwrap();
    }

    fn seed_exported(store: &Store, task_id: &str, paths: &[&str]) {
        let conn = store.lock_sync();
        for p in paths {
            conn.execute(
                "INSERT INTO task_exported_path_snapshots (task_id, path)
                 VALUES (?1, ?2)",
                rusqlite::params![task_id, p],
            ).unwrap();
        }
    }

    fn registry_with(entries: &[(&str, &str, TaskPlanFields)]) -> PlanRegistry {
        let r = PlanRegistry::new();
        for (init, task, fields) in entries {
            r.insert(TaskKey::new(*init, *task), fields.clone());
        }
        r
    }

    #[test]
    fn no_plan_entry_is_fail_closed() {
        let store = Store::open_in_memory().unwrap();
        let registry = PlanRegistry::new();

        let err = effective_allow("init-x", "task-x", &registry, &store)
            .expect_err("missing entry must error");
        match err {
            PathScopeError::NoPlanEntry { task_id, .. } => assert_eq!(task_id, "task-x"),
            other => panic!("wrong error: {other:?}"),
        }
    }

    #[test]
    fn override_returns_universal_set() {
        let store = Store::open_in_memory().unwrap();
        let registry = registry_with(&[(
            "init-A", "t1",
            TaskPlanFields { path_scope_override: true, ..Default::default() },
        )]);
        let allow = effective_allow("init-A", "t1", &registry, &store).unwrap();
        assert!(allow.universal);
        assert!(allow.matches("/any/escape/path"));
    }

    #[test]
    fn task_with_no_predecessors_uses_only_layer_one() {
        let store = Store::open_in_memory().unwrap();
        seed_initiative(&store, "init-A");
        seed_task(&store, "init-A", "t1", "Admitted");
        let registry = registry_with(&[(
            "init-A", "t1",
            TaskPlanFields {
                path_allowlist: vec!["src/**".into(), "README.md".into()],
                ..Default::default()
            },
        )]);

        let allow = effective_allow("init-A", "t1", &registry, &store).unwrap();
        assert!(allow.exact_paths.is_empty());
        assert_eq!(allow.glob_patterns.len(), 2);
        assert!(allow.matches("src/lib.rs"));
        assert!(allow.matches("README.md"));
        assert!(!allow.matches("Cargo.toml"));
    }

    #[test]
    fn completed_predecessor_with_export_widens_allow_set() {
        // pred (Completed, exports) → succ (Admitted)
        // pred contributes exported_paths (exact); succ keeps its own globs.
        let store = Store::open_in_memory().unwrap();
        seed_initiative(&store, "init-A");
        seed_task(&store, "init-A", "pred", "Completed");
        seed_task(&store, "init-A", "succ", "Admitted");
        seed_edge(&store, "init-A", "pred", "succ");
        seed_exported(&store, "pred", &["src/predout/x.rs", "src/predout/y.rs"]);

        let registry = registry_with(&[
            ("init-A", "pred", TaskPlanFields {
                path_export_to_successors: true,
                ..Default::default()
            }),
            ("init-A", "succ", TaskPlanFields {
                path_allowlist: vec!["docs/**".into()],
                ..Default::default()
            }),
        ]);

        let allow = effective_allow("init-A", "succ", &registry, &store).unwrap();
        assert_eq!(allow.exact_paths.len(), 2);
        assert!(allow.matches("src/predout/x.rs"));
        assert!(allow.matches("src/predout/y.rs"));
        assert!(allow.matches("docs/intro.md"));
        assert!(!allow.matches("src/predout/z.rs"), "exact match only — not a glob");
    }

    #[test]
    fn aborted_predecessor_grant_never_activates() {
        let store = Store::open_in_memory().unwrap();
        seed_initiative(&store, "init-A");
        seed_task(&store, "init-A", "pred", "Aborted");
        seed_task(&store, "init-A", "succ", "Admitted");
        seed_edge(&store, "init-A", "pred", "succ");
        seed_exported(&store, "pred", &["src/predout/x.rs"]);
        let registry = registry_with(&[
            ("init-A", "pred", TaskPlanFields {
                path_export_to_successors: true,
                ..Default::default()
            }),
            ("init-A", "succ", TaskPlanFields {
                path_allowlist: vec!["docs/**".into()],
                ..Default::default()
            }),
        ]);

        let allow = effective_allow("init-A", "succ", &registry, &store).unwrap();
        assert!(allow.exact_paths.is_empty(),
                "aborted predecessor must not contribute exports");
        assert!(!allow.matches("src/predout/x.rs"));
    }

    #[test]
    fn predecessor_without_export_optin_is_skipped() {
        let store = Store::open_in_memory().unwrap();
        seed_initiative(&store, "init-A");
        seed_task(&store, "init-A", "pred", "Completed");
        seed_task(&store, "init-A", "succ", "Admitted");
        seed_edge(&store, "init-A", "pred", "succ");
        seed_exported(&store, "pred", &["src/predout/x.rs"]);
        // Default `path_export_to_successors = false` — even though rows
        // exist in `task_exported_path_snapshots` (they shouldn't, in
        // production, but defense-in-depth), the registry opt-in gate
        // says "skip".
        let registry = registry_with(&[
            ("init-A", "pred", TaskPlanFields::default()),
            ("init-A", "succ", TaskPlanFields {
                path_allowlist: vec!["docs/**".into()],
                ..Default::default()
            }),
        ]);

        let allow = effective_allow("init-A", "succ", &registry, &store).unwrap();
        assert!(allow.exact_paths.is_empty());
    }

    #[test]
    fn check_paths_passes_on_full_coverage() {
        let store = Store::open_in_memory().unwrap();
        seed_initiative(&store, "init-A");
        seed_task(&store, "init-A", "t1", "Admitted");
        let registry = registry_with(&[(
            "init-A", "t1",
            TaskPlanFields {
                path_allowlist: vec!["src/**".into()],
                ..Default::default()
            },
        )]);

        let touched = vec![PathBuf::from("src/a.rs"), PathBuf::from("src/sub/b.rs")];
        let result = check_paths(&touched, "init-A", "t1", &registry, &store).unwrap();
        assert!(result.is_ok());
    }

    #[test]
    fn check_paths_collects_violations() {
        let store = Store::open_in_memory().unwrap();
        seed_initiative(&store, "init-A");
        seed_task(&store, "init-A", "t1", "Admitted");
        let registry = registry_with(&[(
            "init-A", "t1",
            TaskPlanFields {
                path_allowlist: vec!["src/**".into()],
                ..Default::default()
            },
        )]);

        let touched = vec![
            PathBuf::from("src/a.rs"),       // covered
            PathBuf::from("docs/intro.md"),  // violation
            PathBuf::from("Cargo.toml"),     // violation
        ];
        let result = check_paths(&touched, "init-A", "t1", &registry, &store).unwrap();
        let violation = result.expect_err("must collect violations");
        // Sorted: Cargo.toml < docs/intro.md
        assert_eq!(violation.paths, vec!["Cargo.toml", "docs/intro.md"]);
    }

    #[test]
    fn check_paths_passes_vacuously_on_empty_input() {
        // §2.5.8 edge-case table: "First intent, base_sha == head_sha"
        // → touched_paths = {} → "Path check passes vacuously at admission."
        let store = Store::open_in_memory().unwrap();
        seed_initiative(&store, "init-A");
        seed_task(&store, "init-A", "t1", "Admitted");
        let registry = registry_with(&[(
            "init-A", "t1",
            TaskPlanFields::default(),  // empty allowlist on purpose
        )]);

        let touched: Vec<PathBuf> = vec![];
        let result = check_paths(&touched, "init-A", "t1", &registry, &store).unwrap();
        assert!(result.is_ok(), "empty input must pass even with empty allowlist");
    }

    #[test]
    fn check_paths_with_override_passes_everything() {
        let store = Store::open_in_memory().unwrap();
        seed_initiative(&store, "init-A");
        seed_task(&store, "init-A", "t1", "Admitted");
        let registry = registry_with(&[(
            "init-A", "t1",
            TaskPlanFields { path_scope_override: true, ..Default::default() },
        )]);

        let touched = vec![
            PathBuf::from("/etc/passwd"),
            PathBuf::from("../escape"),
        ];
        let result = check_paths(&touched, "init-A", "t1", &registry, &store).unwrap();
        assert!(result.is_ok());
    }
}

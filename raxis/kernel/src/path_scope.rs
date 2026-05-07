// raxis-kernel::path_scope — VCS path-scope enforcement (INV-TASK-PATH-01/02).
//
// Normative references:
//   * V1: `kernel-store.md §2.5.8` — "VCS Path Scope Enforcement"
//   * V2: `v2-deep-spec.md §6` table 4 (`Step 19`) — trailing-slash
//     discipline for `path_allowlist`; replaces the V1 glob matcher with
//     an exact / starts-with matcher on V2-syntax entries.
//
// This module is the 1:1 implementation of the §2.5.8 `effective_allow`
// and `check_paths` pseudocode, refined for V2 path syntax. The TOML
// parser lives in `initiatives/lifecycle.rs::parse_plan_tasks`; the V2
// syntax validator (gate at `approve_plan`) lives in the same file as
// `validate_path_allowlist_v2_format`.
//
// What this module is and is not
// ------------------------------
// IS:
//   * The compound-allow-set type (`AllowSet` = V2 path entries ∪
//     exact predecessor exports), with `path_scope_override` short-circuit.
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
//   * The V2 syntax validator. That lives in
//     `initiatives/lifecycle.rs::validate_path_allowlist_v2_format` and
//     runs at `approve_plan` time, before any task is admitted.
//   * The exported-paths snapshot writer. That lives in
//     `handlers/intent.rs` CompleteTask branch (under the same SQLite
//     transaction as the `Running → Completed` UPDATE).
//
// V2 path-allowlist semantics (Step 19 / `v2-deep-spec.md §6` table 4)
// --------------------------------------------------------------------
// A `path_allowlist` entry is one of two well-formed shapes:
//
//   * **Exact filename** — repo-relative path that does NOT end with `/`
//     (e.g., `src/api/handler.rs`). Matches by string equality.
//   * **Directory prefix** — repo-relative path that ends with `/`
//     (e.g., `src/api/`). Matches by `starts_with`, so every path
//     under that directory (recursively) is admitted.
//
// Glob characters (`*`, `?`, `[`, `]`, `{`, `}`), absolute paths, and
// `..` segments are rejected at sign time by `plan prepare` and at
// admission by `validate_path_allowlist_v2_format`. The kernel does
// **not** invoke a glob library here — V2 path matching is a single
// linear scan of (exact || prefix) checks, with no special characters
// or escaping rules. This makes containment provably correct without
// taking a position on POSIX vs gitignore vs Bash extglob semantics.

use std::collections::BTreeSet;

use raxis_store::{Store, Table};

use crate::initiatives::{OrchestratorPlanFields, PlanRegistry, TaskKey, TaskPlanFields};

// INV-STORE-03 (kernel-store.md §2.5.1): no raw SQL table-name literals
// in `kernel/src`; the constants below are interpolated into every query.
const TASK_DAG_EDGES:               &str = Table::TaskDagEdges.as_str();
const TASKS:                        &str = Table::Tasks.as_str();
const TASK_EXPORTED_PATH_SNAPSHOTS: &str = Table::TaskExportedPathSnapshots.as_str();
#[cfg(test)]
const INITIATIVES:                  &str = Table::Initiatives.as_str();

// ---------------------------------------------------------------------------
// AllowSet — glob patterns ∪ exact paths, with override flag
// ---------------------------------------------------------------------------

/// One V2 `path_allowlist` entry, parsed into its kernel-side shape.
///
/// Constructed by `PathEntry::parse`, which **assumes the input has
/// already passed `validate_path_allowlist_v2_format`** (Step 19's
/// admission gate). At runtime we trust that invariant: every entry
/// reaching this module came from a signed-and-admitted plan.
///
/// The two shapes are disjoint by construction (a directory entry
/// always has a trailing `/`; a filename never does), so containment
/// is a single match-on-suffix per check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathEntry {
    /// Exact filename, e.g. `src/api/handler.rs`. Matched by `==`.
    Exact(String),
    /// Directory prefix including the trailing `/`, e.g. `src/api/`.
    /// Matched by `starts_with`. The trailing `/` is preserved verbatim
    /// so `src/`.starts_with(`src`) does NOT spuriously admit `srcfoo/x`.
    DirectoryPrefix(String),
}

impl PathEntry {
    /// Parse one V2 entry. Returns `None` only for the empty string —
    /// `validate_path_allowlist_v2_format` rejects that case at admission,
    /// so reaching `None` here would indicate registry corruption. We
    /// fail-closed by returning `None` and letting the caller propagate
    /// the surrounding error.
    pub fn parse(entry: &str) -> Option<Self> {
        if entry.is_empty() {
            return None;
        }
        Some(if entry.ends_with('/') {
            PathEntry::DirectoryPrefix(entry.to_owned())
        } else {
            PathEntry::Exact(entry.to_owned())
        })
    }

    /// Test whether this entry admits `path`. The argument is a
    /// `to_string_lossy`'d repo-relative path from the touched-paths
    /// list (see `IntentExt::touched_paths` and the CompleteTask
    /// branch in `handlers/intent.rs`).
    pub fn matches(&self, path: &str) -> bool {
        match self {
            PathEntry::Exact(p)           => p == path,
            PathEntry::DirectoryPrefix(p) => path.starts_with(p.as_str()),
        }
    }
}

/// The compound allow-set for one task, as defined in §2.5.8 (V1) and
/// refined by V2 Step 19:
///
/// ```text
/// matches_allow(p, E) := E.universal
///                     || E.path_entries.any(e -> e.matches(p))
///                     || E.exact_paths.contains(p)
/// ```
///
/// Construction is fallible only if a registry row contains an
/// unparseable entry — i.e., an empty string that somehow bypassed
/// `validate_path_allowlist_v2_format`. We surface that as
/// `PathScopeError::InvalidPathEntry` so the caller stays fail-closed.
#[derive(Debug, Default)]
pub struct AllowSet {
    /// `path_scope_override = true` short-circuits all checks. When set,
    /// `path_entries` and `exact_paths` are ignored. `PathScopeOverrideApplied`
    /// has already been emitted at `approve_plan` time per §2.5.8.
    pub universal:    bool,
    /// V2 path-allowlist entries from the task's signed plan
    /// (Step 19: exact filename or trailing-slash directory).
    pub path_entries: Vec<PathEntry>,
    /// Concrete literal paths inherited from completed-predecessor
    /// exports. These are NOT pattern-matched — see §2.5.8 "Why the
    /// compound type matters". Equality only.
    pub exact_paths:  BTreeSet<String>,
}

impl AllowSet {
    /// Universal/override singleton — every check passes.
    pub fn universal() -> Self {
        Self { universal: true, ..Default::default() }
    }

    /// Test whether one path is allowed.
    ///
    /// V2 semantics (Step 19): each `path_entries` element matches by
    /// either equality (exact filename) or `starts_with` (directory
    /// prefix). No glob library is consulted; there are no wildcards.
    pub fn matches(&self, path: &str) -> bool {
        if self.universal {
            return true;
        }
        if self.path_entries.iter().any(|e| e.matches(path)) {
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

    /// A V2 path-allowlist entry from the registry could not be parsed
    /// into a `PathEntry`. Under the V2 admission gate
    /// (`validate_path_allowlist_v2_format`) this should never happen
    /// in practice — empty strings are rejected at sign time and at
    /// approve time. This branch is defense-in-depth: if a row in the
    /// registry IS empty, fail closed with this error rather than
    /// silently treating it as "match everything".
    #[error("invalid path-allowlist entry in plan registry: `{entry}`")]
    InvalidPathEntry { entry: String },

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
/// 3. Parse the task's own `path_allowlist` into V2 `path_entries`.
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

    let path_entries = parse_v2_entries(&fields.path_allowlist)?;
    let exact_paths  = collect_predecessor_exports(initiative_id, task_id, registry, store)?;

    Ok(AllowSet { universal: false, path_entries, exact_paths })
}

/// V2 §Step 11 — Compute the `hybrid_effective_allow` for an
/// `IntentKind::IntegrationMerge` admission.
///
/// Spec form (`v2-deep-spec.md §Step 11`):
///
/// ```text
/// hybrid_effective_allow =
///     UNION(all subtask path_allowlists for this initiative)
///     ∪ cross_cutting_artifacts (from `[orchestrator]`)
/// ```
///
/// The Orchestrator's per-task `path_allowlist` is NOT consulted here.
/// At `IntegrationMerge` admission the Orchestrator's authority comes
/// from being the union of all sub-task owners plus the operator-
/// declared cross-cutting list — its own allowlist would be either a
/// strict subset of the union (redundant) or a superset (a covert
/// widening, which Step 11 specifically forbids).
///
/// **Predecessor exports are intentionally NOT folded in** here: at
/// `IntegrationMerge` time, the Orchestrator is operating on the merged
/// HEAD of every sub-task's branch, not on a single sub-task's
/// `effective_allow`. The export channel exists to grant downstream
/// sub-tasks the right to touch artifacts another sub-task wrote; an
/// integration merge is a different relation (it owns the post-merge
/// state of the whole graph).
///
/// **`path_scope_override` per sub-task** is honoured by widening that
/// sub-task's contribution to "match everything" — a single overriding
/// sub-task makes the hybrid set universal. This is consistent with the
/// V1 `effective_allow` semantics for an overriding task.
///
/// Returns `Ok(AllowSet::universal())` when ANY sub-task in the
/// initiative has `path_scope_override = true`. Otherwise returns a
/// non-universal `AllowSet` whose `path_entries` are the parsed union
/// and whose `exact_paths` are the cross-cutting artifacts.
///
/// Errors only on `InvalidPathEntry` (a registry row with an empty
/// path entry, defense-in-depth — Step 19's admission gate prevents
/// this). The "no tasks in this initiative" case is reported as the
/// empty allow set; the IntegrationMerge handler is responsible for
/// rejecting an `IntegrationMerge` against an unknown initiative on
/// other grounds (initiative quarantine / not found / not Executing).
pub fn compute_hybrid_effective_allow(
    initiative_id: &str,
    registry:      &PlanRegistry,
) -> Result<AllowSet, PathScopeError> {
    let task_snapshot = registry.tasks_in_initiative(initiative_id);

    // §Step 11 universal-override propagation: a single override
    // makes the entire IntegrationMerge unrestricted. This is rare in
    // production (override is the operator-quarantine bypass; spec
    // §2.5.8) but we handle it for symmetry with `effective_allow`.
    if task_snapshot.iter().any(|(_, f)| f.path_scope_override) {
        return Ok(AllowSet::universal());
    }

    // Fold every sub-task's `path_allowlist` into one parsed list.
    // De-duplication is implicit in the matcher (any redundant prefix
    // costs an O(1) extra check; not worth the BTreeSet overhead in
    // the inner loop). Order is preserved per the per-task insertion
    // order returned by `tasks_in_initiative`.
    let mut entries = Vec::new();
    for (_, fields) in &task_snapshot {
        for raw in &fields.path_allowlist {
            let entry = PathEntry::parse(raw)
                .ok_or_else(|| PathScopeError::InvalidPathEntry { entry: raw.clone() })?;
            entries.push(entry);
        }
    }

    // `cross_cutting_artifacts` join. Operator-declared exact filenames
    // (validated by `validate_cross_cutting_artifacts` in `lifecycle.rs`
    // at admission time). We materialise them into `exact_paths` —
    // semantically the same as a `PathEntry::Exact`, but the
    // §2.5.8 type model puts operator-declared concretes in
    // `exact_paths` for parallel symmetry with predecessor exports.
    let exact_paths: BTreeSet<String> = registry
        .orchestrator(initiative_id)
        .map(|o: OrchestratorPlanFields| o.cross_cutting_artifacts.into_iter().collect())
        .unwrap_or_default();

    Ok(AllowSet { universal: false, path_entries: entries, exact_paths })
}

/// V2 §Step 11 — `check_paths` analog for `IntentKind::IntegrationMerge`.
///
/// Same return shape as `check_paths` (the inner `Result<(),
/// PathPolicyViolation>` distinguishes coverage success from per-path
/// rejections). Composes `compute_hybrid_effective_allow` with the
/// linear scan over `touched_paths`.
pub fn check_paths_hybrid(
    touched_paths: &[std::path::PathBuf],
    initiative_id: &str,
    registry:      &PlanRegistry,
) -> Result<Result<(), PathPolicyViolation>, PathScopeError> {
    let allow = compute_hybrid_effective_allow(initiative_id, registry)?;

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
        violations.sort();
        Err(PathPolicyViolation { paths: violations })
    })
}

/// Parse a list of V2-syntax `path_allowlist` entries into `PathEntry`s.
/// The empty-string branch fails closed via `InvalidPathEntry` — see
/// the type-level docstring on `PathEntry::parse`.
fn parse_v2_entries(entries: &[String]) -> Result<Vec<PathEntry>, PathScopeError> {
    let mut out = Vec::with_capacity(entries.len());
    for raw in entries {
        let entry = PathEntry::parse(raw)
            .ok_or_else(|| PathScopeError::InvalidPathEntry { entry: raw.clone() })?;
        out.push(entry);
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

    fn dir(s: &str) -> PathEntry {
        PathEntry::parse(s).unwrap_or_else(|| panic!("test entry `{s}` parse failed"))
    }

    // ── PathEntry::parse — V2 syntax round-trip ───────────────────────────

    #[test]
    fn path_entry_parse_recognizes_directory_prefix_by_trailing_slash() {
        // Step 19: "trailing `/` ⇒ directory prefix". The trailing slash
        // is preserved verbatim so `starts_with` cannot bleed past a
        // segment boundary (e.g., `srcfoo/` matching under `src`).
        match PathEntry::parse("src/").unwrap() {
            PathEntry::DirectoryPrefix(p) => assert_eq!(p, "src/"),
            other => panic!("expected DirectoryPrefix, got {other:?}"),
        }
    }

    #[test]
    fn path_entry_parse_recognizes_exact_filename_when_no_trailing_slash() {
        match PathEntry::parse("src/lib.rs").unwrap() {
            PathEntry::Exact(p) => assert_eq!(p, "src/lib.rs"),
            other => panic!("expected Exact, got {other:?}"),
        }
    }

    #[test]
    fn path_entry_parse_returns_none_on_empty_string() {
        // Empty entry is the one fail-closed branch — never produced by
        // a validated plan, but parser must not silently turn it into a
        // "match-everything" prefix.
        assert!(PathEntry::parse("").is_none());
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
    fn directory_prefix_admits_recursive_descent() {
        // V2 directory prefix (`src/`) admits every path under `src/`,
        // including arbitrarily deep nesting. This is the common-case
        // ergonomic for a task that "owns the src/ subtree".
        let s = AllowSet {
            path_entries: vec![dir("src/")],
            ..Default::default()
        };
        assert!(s.matches("src/lib.rs"));
        assert!(s.matches("src/sub/lib.rs"));
        assert!(s.matches("src/a/b/c/d.rs"));
        assert!(!s.matches("other/lib.rs"));
    }

    #[test]
    fn directory_prefix_does_not_bleed_past_trailing_slash() {
        // Pin the segment-boundary property: `src/` must NOT admit
        // `srcfoo/x.rs`. The trailing-slash preservation in
        // `PathEntry::DirectoryPrefix` is what guarantees this.
        let s = AllowSet {
            path_entries: vec![dir("src/")],
            ..Default::default()
        };
        assert!(!s.matches("srcfoo/lib.rs"));
        assert!(!s.matches("src.rs"));
    }

    #[test]
    fn exact_filename_matches_only_literally() {
        let s = AllowSet {
            path_entries: vec![dir("README.md")],
            ..Default::default()
        };
        assert!(s.matches("README.md"));
        assert!(!s.matches("README.md.bak"));
        assert!(!s.matches("docs/README.md"));
    }

    #[test]
    fn exact_paths_inherited_from_predecessors_match_only_literally() {
        let mut exact = BTreeSet::new();
        exact.insert("src/ipc/handlers/new.rs".to_owned());
        let s = AllowSet { exact_paths: exact, ..Default::default() };
        assert!(s.matches("src/ipc/handlers/new.rs"));
        assert!(!s.matches("src/ipc/handlers/other.rs"));
        // Glob-looking literal must NOT be interpreted as a pattern —
        // §2.5.8 explicitly warns against type confusion here.
        assert!(!s.matches("src/ipc/handlers/anything.rs"));
    }

    #[test]
    fn either_layer_admits_independently() {
        let mut exact = BTreeSet::new();
        exact.insert("README.md".to_owned());
        let s = AllowSet {
            path_entries: vec![dir("src/")],
            exact_paths:  exact,
            ..Default::default()
        };
        assert!(s.matches("src/lib.rs"),     "directory-prefix layer");
        assert!(s.matches("README.md"),      "exact-paths layer");
        assert!(!s.matches("docs/intro.md"), "neither layer");
    }

    #[test]
    fn parse_v2_entries_propagates_empty_string_as_invalid() {
        // Defense-in-depth branch: an empty entry slipping past the
        // admission validator must be surfaced, not silently widened.
        let bad = vec!["src/".to_owned(), String::new()];
        let err = parse_v2_entries(&bad).expect_err("empty entry must fail");
        match err {
            PathScopeError::InvalidPathEntry { entry } => assert_eq!(entry, ""),
            other => panic!("wrong error: {other:?}"),
        }
    }

    #[test]
    fn parse_v2_entries_round_trips_exact_and_directory_shapes() {
        let raw = vec![
            "src/".to_owned(),
            "README.md".to_owned(),
            "tests/integration/".to_owned(),
            ".github/workflows/ci.yml".to_owned(),
        ];
        let parsed = parse_v2_entries(&raw).unwrap();
        assert_eq!(parsed.len(), 4);
        assert!(matches!(parsed[0], PathEntry::DirectoryPrefix(ref p) if p == "src/"));
        assert!(matches!(parsed[1], PathEntry::Exact(ref p)           if p == "README.md"));
        assert!(matches!(parsed[2], PathEntry::DirectoryPrefix(ref p) if p == "tests/integration/"));
        assert!(matches!(parsed[3], PathEntry::Exact(ref p)           if p == ".github/workflows/ci.yml"));
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
            &format!(
                "INSERT INTO {INITIATIVES}
                    (initiative_id, state, terminal_criteria_json,
                     plan_artifact_sha256, created_at)
                 VALUES (?1, ?2, '{{}}', 'deadbeef', 0)"
            ),
            rusqlite::params![
                init_id,
                raxis_types::InitiativeState::Executing.as_sql_str(),
            ],
        ).unwrap();
    }

    /// Take a typed `TaskState` rather than a free `&str` so a typo in
    /// the test doesn't slip past the SQL CHECK constraint silently.
    fn seed_task(store: &Store, init_id: &str, task_id: &str, state: raxis_types::TaskState) {
        let conn = store.lock_sync();
        conn.execute(
            &format!(
                "INSERT INTO {TASKS}
                    (task_id, initiative_id, lane_id, state, actor,
                     policy_epoch, admitted_at, transitioned_at, actual_cost)
                 VALUES (?1, ?2, 'default', ?3, 'kernel', 1, 0, 0, 0)"
            ),
            rusqlite::params![task_id, init_id, state.as_sql_str()],
        ).unwrap();
    }

    fn seed_edge(store: &Store, init_id: &str, pred: &str, succ: &str) {
        let conn = store.lock_sync();
        conn.execute(
            &format!(
                "INSERT INTO {TASK_DAG_EDGES}
                    (initiative_id, predecessor_task_id, successor_task_id,
                     predecessor_satisfied)
                 VALUES (?1, ?2, ?3, 0)"
            ),
            rusqlite::params![init_id, pred, succ],
        ).unwrap();
    }

    fn seed_exported(store: &Store, task_id: &str, paths: &[&str]) {
        let conn = store.lock_sync();
        for p in paths {
            conn.execute(
                &format!(
                    "INSERT INTO {TASK_EXPORTED_PATH_SNAPSHOTS} (task_id, path)
                     VALUES (?1, ?2)"
                ),
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
        seed_task(&store, "init-A", "t1", raxis_types::TaskState::Admitted);
        let registry = registry_with(&[(
            "init-A", "t1",
            TaskPlanFields {
                // V2 syntax: directory prefix `src/` (recursive) plus
                // exact filename `README.md`.
                path_allowlist: vec!["src/".into(), "README.md".into()],
                ..Default::default()
            },
        )]);

        let allow = effective_allow("init-A", "t1", &registry, &store).unwrap();
        assert!(allow.exact_paths.is_empty());
        assert_eq!(allow.path_entries.len(), 2);
        assert!(allow.matches("src/lib.rs"));
        assert!(allow.matches("README.md"));
        assert!(!allow.matches("Cargo.toml"));
    }

    #[test]
    fn completed_predecessor_with_export_widens_allow_set() {
        // pred (Completed, exports) → succ (Admitted)
        // pred contributes exported_paths (exact); succ keeps its own
        // V2 directory-prefix entries.
        let store = Store::open_in_memory().unwrap();
        seed_initiative(&store, "init-A");
        seed_task(&store, "init-A", "pred", raxis_types::TaskState::Completed);
        seed_task(&store, "init-A", "succ", raxis_types::TaskState::Admitted);
        seed_edge(&store, "init-A", "pred", "succ");
        seed_exported(&store, "pred", &["src/predout/x.rs", "src/predout/y.rs"]);

        let registry = registry_with(&[
            ("init-A", "pred", TaskPlanFields {
                path_export_to_successors: true,
                ..Default::default()
            }),
            ("init-A", "succ", TaskPlanFields {
                path_allowlist: vec!["docs/".into()],
                ..Default::default()
            }),
        ]);

        let allow = effective_allow("init-A", "succ", &registry, &store).unwrap();
        assert_eq!(allow.exact_paths.len(), 2);
        assert!(allow.matches("src/predout/x.rs"));
        assert!(allow.matches("src/predout/y.rs"));
        assert!(allow.matches("docs/intro.md"));
        assert!(!allow.matches("src/predout/z.rs"), "exact match only — not a prefix");
    }

    #[test]
    fn aborted_predecessor_grant_never_activates() {
        let store = Store::open_in_memory().unwrap();
        seed_initiative(&store, "init-A");
        seed_task(&store, "init-A", "pred", raxis_types::TaskState::Aborted);
        seed_task(&store, "init-A", "succ", raxis_types::TaskState::Admitted);
        seed_edge(&store, "init-A", "pred", "succ");
        seed_exported(&store, "pred", &["src/predout/x.rs"]);
        let registry = registry_with(&[
            ("init-A", "pred", TaskPlanFields {
                path_export_to_successors: true,
                ..Default::default()
            }),
            ("init-A", "succ", TaskPlanFields {
                path_allowlist: vec!["docs/".into()],
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
        seed_task(&store, "init-A", "pred", raxis_types::TaskState::Completed);
        seed_task(&store, "init-A", "succ", raxis_types::TaskState::Admitted);
        seed_edge(&store, "init-A", "pred", "succ");
        seed_exported(&store, "pred", &["src/predout/x.rs"]);
        // Default `path_export_to_successors = false` — even though rows
        // exist in `task_exported_path_snapshots` (they shouldn't, in
        // production, but defense-in-depth), the registry opt-in gate
        // says "skip".
        let registry = registry_with(&[
            ("init-A", "pred", TaskPlanFields::default()),
            ("init-A", "succ", TaskPlanFields {
                path_allowlist: vec!["docs/".into()],
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
        seed_task(&store, "init-A", "t1", raxis_types::TaskState::Admitted);
        let registry = registry_with(&[(
            "init-A", "t1",
            TaskPlanFields {
                path_allowlist: vec!["src/".into()],
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
        seed_task(&store, "init-A", "t1", raxis_types::TaskState::Admitted);
        let registry = registry_with(&[(
            "init-A", "t1",
            TaskPlanFields {
                path_allowlist: vec!["src/".into()],
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
        seed_task(&store, "init-A", "t1", raxis_types::TaskState::Admitted);
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
        seed_task(&store, "init-A", "t1", raxis_types::TaskState::Admitted);
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

    // ── compute_hybrid_effective_allow / check_paths_hybrid (Step 11) ────

    #[test]
    fn hybrid_unions_subtask_allowlists_in_initiative_scope_only() {
        // Two tasks in init-A, one in init-B. The hybrid allow for
        // init-A must contain both A-tasks' entries and NOTHING from
        // init-B (cross-initiative leakage would be a security bug).
        let registry = registry_with(&[
            ("init-A", "t1", TaskPlanFields {
                path_allowlist: vec!["src/api/".to_owned()],
                ..Default::default()
            }),
            ("init-A", "t2", TaskPlanFields {
                path_allowlist: vec!["src/db/".to_owned()],
                ..Default::default()
            }),
            ("init-B", "x1", TaskPlanFields {
                path_allowlist: vec!["should/not/leak/".to_owned()],
                ..Default::default()
            }),
        ]);

        let allow = compute_hybrid_effective_allow("init-A", &registry).unwrap();
        assert!(!allow.universal);
        assert!(allow.matches("src/api/handler.rs"));
        assert!(allow.matches("src/db/migrate.rs"));
        assert!(!allow.matches("should/not/leak/x.rs"),
            "init-B's entries must NOT leak into init-A's hybrid allow");
        assert!(!allow.matches("README.md"),
            "no entry, no admission");
    }

    #[test]
    fn hybrid_adds_cross_cutting_artifacts_as_exact_matches() {
        let registry = registry_with(&[
            ("init-A", "t1", TaskPlanFields {
                path_allowlist: vec!["src/".to_owned()],
                ..Default::default()
            }),
        ]);
        registry.insert_orchestrator("init-A", OrchestratorPlanFields {
            cross_cutting_artifacts: vec![
                "Cargo.lock".to_owned(),
                "package-lock.json".to_owned(),
            ],
        });

        let allow = compute_hybrid_effective_allow("init-A", &registry).unwrap();
        // Sub-task allowlist still admits.
        assert!(allow.matches("src/lib.rs"));
        // Cross-cutting artifacts admit by EXACT match — not by prefix.
        assert!(allow.matches("Cargo.lock"));
        assert!(allow.matches("package-lock.json"));
        // A path that begins with a cross-cutting filename but is NOT
        // exactly that name must NOT match (the entries are exact, not
        // prefix). This pins the no-prefix-bleed semantic.
        assert!(!allow.matches("Cargo.lock.bak"));
        assert!(!allow.matches("not/Cargo.lock"));
    }

    #[test]
    fn hybrid_with_no_orchestrator_section_uses_only_subtask_union() {
        // V1 backward compat: an initiative with no `[orchestrator]`
        // entry in the registry produces a hybrid allow that's just
        // the union of sub-task allowlists, with NO cross-cutting.
        let registry = registry_with(&[
            ("init-A", "t1", TaskPlanFields {
                path_allowlist: vec!["src/".to_owned()],
                ..Default::default()
            }),
        ]);

        let allow = compute_hybrid_effective_allow("init-A", &registry).unwrap();
        assert!(allow.matches("src/x.rs"));
        // Cargo.lock NOT admitted (no cross-cutting declared).
        assert!(!allow.matches("Cargo.lock"));
    }

    #[test]
    fn hybrid_universalizes_when_any_subtask_overrides() {
        // §Step 11 + §2.5.8 override propagation: if any sub-task
        // carries `path_scope_override = true`, the hybrid allow is
        // universal. Pin this so an audit/forensics review of an
        // override doesn't quietly miss the IntegrationMerge widening.
        let registry = registry_with(&[
            ("init-A", "t1", TaskPlanFields {
                path_allowlist: vec!["src/".to_owned()],
                ..Default::default()
            }),
            ("init-A", "t2", TaskPlanFields {
                path_scope_override: true,
                ..Default::default()
            }),
        ]);

        let allow = compute_hybrid_effective_allow("init-A", &registry).unwrap();
        assert!(allow.universal);
        assert!(allow.matches("/etc/passwd"));
        assert!(allow.matches("../escape"));
    }

    #[test]
    fn hybrid_with_no_tasks_returns_empty_allowlist() {
        // Step 11 spec edge-case: an initiative with no `[[tasks]]`
        // entries (e.g., admit-time recovery from a corrupted plan
        // bundle) yields an empty allow set. The IntegrationMerge
        // handler must reject EVERY non-empty `touched_paths` against
        // such an initiative — fail-closed.
        let registry = PlanRegistry::new();
        let allow = compute_hybrid_effective_allow("init-no-tasks", &registry).unwrap();
        assert!(!allow.universal);
        assert!(allow.path_entries.is_empty());
        assert!(allow.exact_paths.is_empty());
        assert!(!allow.matches("anything"));
    }

    #[test]
    fn hybrid_invalid_path_entry_propagates_as_error() {
        // Defense in depth: a registry row containing an empty
        // `path_allowlist` entry (impossible under Step 19's
        // admission gate, but defensively guarded here) surfaces as
        // `InvalidPathEntry`. The handler maps this to the opaque
        // `FailPathPolicyViolation` per INV-08.
        let registry = registry_with(&[
            ("init-A", "t1", TaskPlanFields {
                path_allowlist: vec!["".to_owned()],  // <-- malformed
                ..Default::default()
            }),
        ]);

        let err = compute_hybrid_effective_allow("init-A", &registry)
            .expect_err("empty entry must surface InvalidPathEntry");
        match err {
            PathScopeError::InvalidPathEntry { entry } => assert!(entry.is_empty()),
            other => panic!("expected InvalidPathEntry, got {other:?}"),
        }
    }

    #[test]
    fn check_paths_hybrid_passes_when_every_path_admitted() {
        let registry = registry_with(&[
            ("init-A", "t1", TaskPlanFields {
                path_allowlist: vec!["src/".to_owned()],
                ..Default::default()
            }),
        ]);
        registry.insert_orchestrator("init-A", OrchestratorPlanFields {
            cross_cutting_artifacts: vec!["Cargo.lock".to_owned()],
        });
        let touched = vec![
            PathBuf::from("src/lib.rs"),
            PathBuf::from("Cargo.lock"),
        ];
        let result = check_paths_hybrid(&touched, "init-A", &registry).unwrap();
        assert!(result.is_ok(), "all paths admitted by hybrid allow");
    }

    #[test]
    fn check_paths_hybrid_collects_violations() {
        let registry = registry_with(&[
            ("init-A", "t1", TaskPlanFields {
                path_allowlist: vec!["src/".to_owned()],
                ..Default::default()
            }),
        ]);
        registry.insert_orchestrator("init-A", OrchestratorPlanFields {
            cross_cutting_artifacts: vec!["Cargo.lock".to_owned()],
        });
        let touched = vec![
            PathBuf::from("src/lib.rs"),       // admitted (sub-task)
            PathBuf::from("Cargo.lock"),       // admitted (cross-cutting)
            PathBuf::from("docs/intro.md"),    // VIOLATION
            PathBuf::from("Cargo.lock.bak"),   // VIOLATION (no prefix bleed)
        ];
        let result = check_paths_hybrid(&touched, "init-A", &registry).unwrap();
        let violation = result.expect_err("violations expected");
        assert_eq!(violation.paths, vec!["Cargo.lock.bak", "docs/intro.md"]);
    }

    #[test]
    fn check_paths_hybrid_passes_vacuously_on_empty_input() {
        let registry = PlanRegistry::new();
        let touched: Vec<PathBuf> = vec![];
        let result = check_paths_hybrid(&touched, "init-A", &registry).unwrap();
        assert!(result.is_ok(),
            "empty touched_paths trivially passes regardless of allow set");
    }
}

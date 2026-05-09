// raxis-kernel::initiatives::plan_registry — In-memory plan field registry.
//
// Normative reference: kernel-store.md §2.5.8 "Plan fields are loaded from the
// signed plan artifact, not from the `tasks` table." (lines 1911-ish).
//
// Why this lives in memory, not in `kernel.db`
// --------------------------------------------
// `path_allowlist`, `path_export_to_successors`, `path_export_globs`, and
// `path_scope_override` are properties of the *signed plan*, not of the
// task row. They are written *once* by the operator at sign time and never
// mutated thereafter. The kernel reads them from the parsed plan TOML at
// `approve_plan` time and stashes them keyed by `(initiative_id, task_id)`
// so the intent handler and CompleteTask path-closure check can look them
// up without re-parsing the (immutable) plan blob from
// `signed_plan_artifacts` on every intent.
//
// The on-disk authority remains `signed_plan_artifacts.plan_bytes` — every
// kernel boot re-parses every non-terminal initiative's plan and refills
// the registry via `repopulate_from_store(...)`. A registry miss in the
// hot path is fail-closed: the intent handler treats "no plan fields"
// as `path_allowlist = []` (deny everything) so a corrupted or missing
// plan can never silently widen `effective_allow`.
//
// Concurrency model
// -----------------
// Reads dominate (one read per intent). Writes happen only at
// `approve_plan` time (rare) and at kernel boot. We use `std::sync::RwLock`
// behind a single map, intentionally keeping the dependency footprint
// minimal — `parking_lot` is not in the workspace, and `tokio::sync::RwLock`
// is async-only and would force every intent-handler caller to await on
// what is effectively a microsecond lookup.

use std::sync::RwLock;

use rustc_hash::FxHashMap;

use raxis_types::{CloneStrategy, SessionAgentType};

// ---------------------------------------------------------------------------
// TaskKey — composite (initiative_id, task_id) for registry lookup
// ---------------------------------------------------------------------------

/// Composite key — a task ID is unique per initiative, but the same task ID
/// could in principle reappear across initiatives. We key by both to keep
/// the registry independent of cross-initiative ID conventions.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TaskKey {
    pub initiative_id: String,
    pub task_id:       String,
}

impl TaskKey {
    pub fn new(initiative_id: impl Into<String>, task_id: impl Into<String>) -> Self {
        Self {
            initiative_id: initiative_id.into(),
            task_id:       task_id.into(),
        }
    }
}

// ---------------------------------------------------------------------------
// TaskPlanFields — the four §2.5.8 plan fields for one task
// ---------------------------------------------------------------------------

/// The four path-scope-relevant fields parsed from a `[[tasks]]` stanza
/// in the signed plan artifact.
///
/// Defaults match the spec: `path_allowlist = []` (deny everything),
/// `path_export_to_successors = false` (zero export blast radius),
/// `path_export_globs = []` (full touched set when export is on; ignored
/// when export is off), `path_scope_override = false` (no bypass).
///
/// **V2 §Step 27 fields:**
///   * `clone_strategy` — typed clone strategy (`full | blobless | sparse`).
///     Default `Blobless` matches the V2 spec rationale: uniformly safe for
///     every agent type, strictly cheaper than `full` for repos with binary
///     blobs.
///   * `session_agent_type` — agent kind for this plan-declared task.
///     Default `Executor`. The Orchestrator is *not* operator-declared in
///     V2 (auto-created at admission per `planner-harness.md §4.8`); this
///     field is kept on the per-task surface as defense-in-depth so the
///     `validate_sparse_orchestrator_exclusion` rule still fires if a
///     hand-edited plan or a future spec change ever puts an
///     `Orchestrator` task in `[[tasks]]`.
///
/// Cloned (cheap — `Vec<String>` is heap-shared on Arc nowhere; this is a
/// regular owning clone) on every `effective_allow` call so the lock is
/// dropped immediately after lookup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskPlanFields {
    pub path_allowlist:            Vec<String>,
    pub path_export_to_successors: bool,
    pub path_export_globs:         Vec<String>,
    pub path_scope_override:       bool,

    // V2 §Step 27 — typed clone strategy.
    pub clone_strategy:            CloneStrategy,
    // V2 §Step 6 / §Step 27 check #6 — agent type for this task.
    pub session_agent_type:        SessionAgentType,

    /// V2.5 §13 — `[[plan.tasks.X]] vm_image` resolved at admission
    /// against the operator-published `[[vm_images]]` registry.
    /// Empty `""` when:
    ///
    /// * The plan omits `vm_image` (legacy V1 behaviour — spawn
    ///   uses the canonical starter image).
    /// * The task is a Reviewer (which is structurally forbidden
    ///   from declaring an alias per `INV-PLANNER-HARNESS-02`).
    ///
    /// The activation handler reads this through
    /// [`PlanRegistry::get`] to decide whether to spawn the
    /// canonical starter image or an operator-published one. The
    /// alias is the trust anchor the operator signed; the kernel
    /// re-resolves it against the *current* policy at activation
    /// (re-checking `oci_digest` and `linux_kernel_version_min`)
    /// so a credential rotation between admission and activation
    /// does not silently drift the image bytes.
    pub vm_image:                  String,
}

impl Default for TaskPlanFields {
    fn default() -> Self {
        Self {
            path_allowlist:            Vec::new(),
            path_export_to_successors: false,
            path_export_globs:         Vec::new(),
            path_scope_override:       false,
            clone_strategy:            CloneStrategy::Blobless,
            session_agent_type:        SessionAgentType::Executor,
            vm_image:                  String::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// OrchestratorPlanFields — V2 §Step 11 per-initiative orchestrator plan stanza
// ---------------------------------------------------------------------------

/// The orchestrator-scoped plan fields parsed from the optional
/// `[orchestrator]` section of the signed plan TOML.
///
/// Step 11 introduces `cross_cutting_artifacts`: an exact-filename-only
/// allowlist of files the Orchestrator may touch during
/// `IntentKind::IntegrationMerge` even when no sub-task owns them
/// (e.g. `Cargo.lock`, `package-lock.json`, `go.sum`). The field is
/// operator-declared at sign time and sealed in the plan artifact.
///
/// **Format constraint (validated at admission).** Each entry MUST be
/// an exact filename (no globs, no slashes — i.e., not a directory
/// prefix and not a multi-segment path). The validator
/// `validate_cross_cutting_artifacts` (in `lifecycle.rs`) enforces this
/// at `approve_plan` time before the registry is populated.
///
/// **Default.** V1 plans (no `[orchestrator]` section) and V2 plans
/// that omit the section default to an empty list, which means the
/// hybrid allowlist degenerates to the union of sub-task allowlists.
/// This matches the V1 behaviour exactly — V1 plans are
/// forward-compatible with the Step 11 enforcement path.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OrchestratorPlanFields {
    /// Exact filenames the Orchestrator may touch on
    /// `IntegrationMerge`, in addition to the union of every sub-task's
    /// `path_allowlist`. Validated to contain no `/`, no glob
    /// metacharacters, no `..`, and no empty entries at admission time.
    pub cross_cutting_artifacts: Vec<String>,
}

// ---------------------------------------------------------------------------
// PlanRegistry — process-wide map keyed by TaskKey
// ---------------------------------------------------------------------------

/// In-memory registry of per-task plan fields. Single instance per kernel
/// process, owned by `HandlerContext` behind `Arc`.
///
/// Two orthogonal projections live here:
/// * `tasks` — keyed by `(initiative_id, task_id)`, holds per-task
///   `TaskPlanFields`. Populated by `approve_plan` from `[[tasks]]`.
/// * `orchestrators` — keyed by `initiative_id`, holds the per-initiative
///   `OrchestratorPlanFields` (Step 11). Populated by `approve_plan`
///   from `[orchestrator]`. Missing entries default to empty
///   `cross_cutting_artifacts` so V1 plans need no schema bump.
#[derive(Debug, Default)]
pub struct PlanRegistry {
    inner:         RwLock<FxHashMap<TaskKey, TaskPlanFields>>,
    orchestrators: RwLock<FxHashMap<String, OrchestratorPlanFields>>,
}

impl PlanRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert or replace the plan fields for one task.
    ///
    /// Idempotent. Re-inserting the same key with identical fields is a
    /// no-op from the caller's perspective; with different fields it
    /// overwrites (the latest call wins). In normal operation `approve_plan`
    /// inserts each task exactly once per kernel lifetime; a re-insert
    /// would only happen if `repopulate_from_store` were called twice,
    /// which is itself idempotent since it reads the immutable
    /// `signed_plan_artifacts` row.
    pub fn insert(&self, key: TaskKey, fields: TaskPlanFields) {
        let mut guard = self
            .inner
            .write()
            .expect("PlanRegistry RwLock poisoned — kernel must abort");
        guard.insert(key, fields);
    }

    /// Look up the plan fields for one task. Returns `None` if the task
    /// has no entry — callers must treat that as "deny everything"
    /// (`path_allowlist = []`), never as "allow everything".
    pub fn get(&self, key: &TaskKey) -> Option<TaskPlanFields> {
        let guard = self
            .inner
            .read()
            .expect("PlanRegistry RwLock poisoned — kernel must abort");
        guard.get(key).cloned()
    }

    /// Return `true` iff the registry has any entry for a given
    /// `(initiative_id, task_id)`.
    pub fn contains(&self, key: &TaskKey) -> bool {
        let guard = self
            .inner
            .read()
            .expect("PlanRegistry RwLock poisoned — kernel must abort");
        guard.contains_key(key)
    }

    /// Number of entries (test-only diagnostic).
    pub fn len(&self) -> usize {
        let guard = self
            .inner
            .read()
            .expect("PlanRegistry RwLock poisoned — kernel must abort");
        guard.len()
    }

    /// Whether the registry is empty (test-only diagnostic).
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    // ── V2 Step 11 — orchestrator-scoped fields ──────────────────────────

    /// Insert or replace the orchestrator plan fields for one initiative.
    ///
    /// Idempotent. In normal operation `approve_plan` calls this once
    /// per initiative; a re-insert (e.g. from `repopulate_from_store`)
    /// overwrites with identical bytes since the signed plan artifact
    /// is immutable.
    pub fn insert_orchestrator(&self, initiative_id: impl Into<String>, fields: OrchestratorPlanFields) {
        let mut guard = self.orchestrators.write()
            .expect("PlanRegistry orchestrators RwLock poisoned — kernel must abort");
        guard.insert(initiative_id.into(), fields);
    }

    /// Look up the orchestrator plan fields for one initiative. Returns
    /// `None` when the initiative has no `[orchestrator]` section in
    /// its signed plan; callers MUST treat that as "no cross-cutting
    /// artifacts" (the empty-list default), never as "match
    /// everything".
    pub fn orchestrator(&self, initiative_id: &str) -> Option<OrchestratorPlanFields> {
        let guard = self.orchestrators.read()
            .expect("PlanRegistry orchestrators RwLock poisoned — kernel must abort");
        guard.get(initiative_id).cloned()
    }

    /// Snapshot every `(task_id, fields)` for the given initiative.
    ///
    /// Used by Step 11's `compute_hybrid_effective_allow` to fold every
    /// sub-task's `path_allowlist` into the union before adding
    /// `cross_cutting_artifacts`. Returns an owned Vec so the caller
    /// can release the lock immediately.
    pub fn tasks_in_initiative(&self, initiative_id: &str) -> Vec<(String, TaskPlanFields)> {
        let guard = self.inner.read()
            .expect("PlanRegistry RwLock poisoned — kernel must abort");
        guard
            .iter()
            .filter(|(k, _)| k.initiative_id == initiative_id)
            .map(|(k, v)| (k.task_id.clone(), v.clone()))
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn fields_with_allowlist(globs: &[&str]) -> TaskPlanFields {
        TaskPlanFields {
            path_allowlist: globs.iter().map(|s| (*s).to_owned()).collect(),
            ..Default::default()
        }
    }

    #[test]
    fn empty_registry_returns_none_for_any_lookup() {
        let r = PlanRegistry::new();
        assert!(r.is_empty());
        assert_eq!(r.len(), 0);
        let key = TaskKey::new("init-1", "task-1");
        assert!(r.get(&key).is_none());
        assert!(!r.contains(&key));
    }

    #[test]
    fn insert_then_get_round_trips() {
        let r = PlanRegistry::new();
        let k = TaskKey::new("init-A", "task-1");
        let f = fields_with_allowlist(&["src/**"]);

        r.insert(k.clone(), f.clone());

        assert_eq!(r.len(), 1);
        assert!(r.contains(&k));
        let got = r.get(&k).expect("just inserted");
        assert_eq!(got, f);
    }

    #[test]
    fn task_keys_are_scoped_per_initiative() {
        // Two initiatives both define a task called "build" — they are
        // distinct keys with independent plan fields.
        let r = PlanRegistry::new();
        let k1 = TaskKey::new("init-A", "build");
        let k2 = TaskKey::new("init-B", "build");
        r.insert(k1.clone(), fields_with_allowlist(&["src/a/**"]));
        r.insert(k2.clone(), fields_with_allowlist(&["src/b/**"]));

        assert_eq!(r.get(&k1).unwrap().path_allowlist, vec!["src/a/**"]);
        assert_eq!(r.get(&k2).unwrap().path_allowlist, vec!["src/b/**"]);
        assert_eq!(r.len(), 2);
    }

    #[test]
    fn re_insert_overwrites_in_place() {
        let r = PlanRegistry::new();
        let k = TaskKey::new("init-A", "t");
        r.insert(k.clone(), fields_with_allowlist(&["a"]));
        r.insert(k.clone(), fields_with_allowlist(&["b"]));
        assert_eq!(r.len(), 1, "re-insert must not duplicate");
        assert_eq!(r.get(&k).unwrap().path_allowlist, vec!["b"]);
    }

    #[test]
    fn defaults_are_locked_down() {
        // The default for an entry is "deny everything, no exports, no
        // override" — matches the spec's defaults exactly. This test pins
        // the contract because a regression here would silently widen
        // the path scope of any task that omits these fields in TOML.
        let f = TaskPlanFields::default();
        assert!(f.path_allowlist.is_empty(), "default path_allowlist must deny");
        assert!(!f.path_export_to_successors, "default export must be off");
        assert!(f.path_export_globs.is_empty(), "default export globs must be empty");
        assert!(!f.path_scope_override, "default override must be false");
        // V2 §Step 27 defaults — `Blobless` is uniformly safe for every
        // agent type and uniformly cheaper than `Full` for repos with
        // binary blobs.
        assert_eq!(f.clone_strategy, CloneStrategy::Blobless,
            "default clone_strategy must be Blobless (V2 §Step 27)");
        // Plan-declared tasks default to Executor; the Orchestrator
        // is auto-created at admission per `planner-harness.md §4.8`.
        assert_eq!(f.session_agent_type, SessionAgentType::Executor,
            "default session_agent_type must be Executor (V2 §Step 6)");
    }

    #[test]
    fn missing_lookup_returns_none_not_default() {
        // Critical invariant: the registry must NOT auto-fill defaults on
        // miss — callers need to distinguish "task has empty allowlist"
        // (TaskPlanFields::default with explicit insert) from "task has
        // no plan entry at all" (corrupted state, should fail closed).
        let r = PlanRegistry::new();
        r.insert(
            TaskKey::new("init", "present"),
            TaskPlanFields::default(),
        );
        assert!(r.get(&TaskKey::new("init", "present")).is_some());
        assert!(r.get(&TaskKey::new("init", "absent")).is_none());
    }

    // ── V2 §Step 11 — orchestrator-scoped fields ────────────────────────

    #[test]
    fn orchestrator_lookup_returns_none_for_unknown_initiative() {
        // V1 plans (no `[orchestrator]` section) and brand-new
        // initiatives must surface as `None`, never as the default
        // (empty list) — callers that need the empty-list semantic
        // can `.unwrap_or_default()` explicitly.
        let r = PlanRegistry::new();
        assert!(r.orchestrator("init-no-such").is_none());
    }

    #[test]
    fn orchestrator_insert_then_lookup_round_trips() {
        let r = PlanRegistry::new();
        let f = OrchestratorPlanFields {
            cross_cutting_artifacts: vec![
                "Cargo.lock".to_owned(),
                "package-lock.json".to_owned(),
            ],
        };
        r.insert_orchestrator("init-1", f.clone());
        let got = r.orchestrator("init-1").expect("just inserted");
        assert_eq!(got, f);
    }

    #[test]
    fn orchestrator_re_insert_overwrites_in_place() {
        let r = PlanRegistry::new();
        r.insert_orchestrator("init-1", OrchestratorPlanFields {
            cross_cutting_artifacts: vec!["old.lock".to_owned()],
        });
        r.insert_orchestrator("init-1", OrchestratorPlanFields {
            cross_cutting_artifacts: vec!["new.lock".to_owned()],
        });
        let got = r.orchestrator("init-1").unwrap();
        assert_eq!(got.cross_cutting_artifacts, vec!["new.lock"]);
    }

    #[test]
    fn orchestrators_are_scoped_per_initiative() {
        let r = PlanRegistry::new();
        r.insert_orchestrator("init-A", OrchestratorPlanFields {
            cross_cutting_artifacts: vec!["a.lock".to_owned()],
        });
        r.insert_orchestrator("init-B", OrchestratorPlanFields {
            cross_cutting_artifacts: vec!["b.lock".to_owned()],
        });
        assert_eq!(r.orchestrator("init-A").unwrap().cross_cutting_artifacts,
                   vec!["a.lock"]);
        assert_eq!(r.orchestrator("init-B").unwrap().cross_cutting_artifacts,
                   vec!["b.lock"]);
    }

    #[test]
    fn orchestrator_default_has_empty_artifacts() {
        // Pin the V1 backward-compat default: an explicitly-inserted
        // empty `OrchestratorPlanFields` must mean "no cross-cutting
        // artifacts" (degenerate hybrid → pure union of sub-task
        // allowlists), never "match everything".
        let f = OrchestratorPlanFields::default();
        assert!(f.cross_cutting_artifacts.is_empty());
    }

    // ── tasks_in_initiative — Step 11 enumeration ──────────────────────

    #[test]
    fn tasks_in_initiative_returns_only_matching_initiative() {
        let r = PlanRegistry::new();
        r.insert(TaskKey::new("init-A", "t1"), fields_with_allowlist(&["a/"]));
        r.insert(TaskKey::new("init-A", "t2"), fields_with_allowlist(&["b/"]));
        r.insert(TaskKey::new("init-B", "t1"), fields_with_allowlist(&["c/"]));

        let mut a_tasks: Vec<String> = r.tasks_in_initiative("init-A")
            .into_iter().map(|(id, _)| id).collect();
        a_tasks.sort();
        assert_eq!(a_tasks, vec!["t1".to_owned(), "t2".to_owned()]);

        let b_tasks: Vec<String> = r.tasks_in_initiative("init-B")
            .into_iter().map(|(id, _)| id).collect();
        assert_eq!(b_tasks, vec!["t1".to_owned()]);
    }

    #[test]
    fn tasks_in_initiative_returns_empty_for_unknown_initiative() {
        let r = PlanRegistry::new();
        r.insert(TaskKey::new("init-A", "t1"), TaskPlanFields::default());
        assert!(r.tasks_in_initiative("init-no-such").is_empty());
    }

    #[test]
    fn tasks_in_initiative_carries_full_fields() {
        let r = PlanRegistry::new();
        let f = TaskPlanFields {
            path_allowlist:            vec!["src/a.rs".to_owned()],
            path_export_to_successors: true,
            path_export_globs:         vec!["src/**".to_owned()],
            path_scope_override:       false,
            clone_strategy:            CloneStrategy::Sparse,
            session_agent_type:        SessionAgentType::Executor,
            vm_image:                  String::new(),
        };
        r.insert(TaskKey::new("init-A", "t1"), f.clone());
        let snapshot = r.tasks_in_initiative("init-A");
        assert_eq!(snapshot.len(), 1);
        assert_eq!(snapshot[0].0, "t1");
        assert_eq!(snapshot[0].1, f);
    }
}

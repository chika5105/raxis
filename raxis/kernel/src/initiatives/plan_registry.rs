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
/// Cloned (cheap — `Vec<String>` is heap-shared on Arc nowhere; this is a
/// regular owning clone) on every `effective_allow` call so the lock is
/// dropped immediately after lookup.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TaskPlanFields {
    pub path_allowlist:            Vec<String>,
    pub path_export_to_successors: bool,
    pub path_export_globs:         Vec<String>,
    pub path_scope_override:       bool,
}

// ---------------------------------------------------------------------------
// PlanRegistry — process-wide map keyed by TaskKey
// ---------------------------------------------------------------------------

/// In-memory registry of per-task plan fields. Single instance per kernel
/// process, owned by `HandlerContext` behind `Arc`.
#[derive(Debug, Default)]
pub struct PlanRegistry {
    inner: RwLock<FxHashMap<TaskKey, TaskPlanFields>>,
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
}

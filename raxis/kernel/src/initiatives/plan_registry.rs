// raxis-kernel::initiatives::plan_registry — In-memory plan field registry.
// Normative reference: kernel-store.md §2.5.8 "Plan fields are loaded from the
// signed plan artifact, not from the `tasks` table." (lines 1911-ish).
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
// The on-disk authority remains `signed_plan_artifacts.plan_bytes` — every
// kernel boot re-parses every non-terminal initiative's plan and refills
// the registry via `repopulate_from_store(...)`. A registry miss in the
// hot path is fail-closed: the intent handler treats "no plan fields"
// as `path_allowlist = []` (deny everything) so a corrupted or missing
// plan can never silently widen `effective_allow`.
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
    pub task_id: String,
}

impl TaskKey {
    pub fn new(initiative_id: impl Into<String>, task_id: impl Into<String>) -> Self {
        Self {
            initiative_id: initiative_id.into(),
            task_id: task_id.into(),
        }
    }
}

// ---------------------------------------------------------------------------
// TaskPlanFields — the four §2.5.8 plan fields for one task
// ---------------------------------------------------------------------------

/// The four path-scope-relevant fields parsed from a `[[tasks]]` stanza
/// in the signed plan artifact.
/// Defaults match the spec: `path_allowlist = []` (deny everything),
/// `path_export_to_successors = false` (zero export blast radius),
/// `path_export_globs = []` (full touched set when export is on; ignored
/// when export is off), `path_scope_override = false` (no bypass).
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
///     Cloned (cheap — `Vec<String>` is heap-shared on Arc nowhere; this is a
///     regular owning clone) on every `effective_allow` call so the lock is
///     dropped immediately after lookup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskPlanFields {
    pub path_allowlist: Vec<String>,
    pub path_export_to_successors: bool,
    pub path_export_globs: Vec<String>,
    pub path_scope_override: bool,

    // V2 §Step 27 — typed clone strategy.
    pub clone_strategy: CloneStrategy,
    // V2 §Step 6 / §Step 27 check #6 — agent type for this task.
    pub session_agent_type: SessionAgentType,

    /// V2.5 §13 — `[[plan.tasks.X]] vm_image` resolved at admission
    /// against the operator-published `[[vm_images]]` registry.
    /// Empty `""` when:
    /// * The plan omits `vm_image` (legacy V1 behaviour — spawn
    ///   uses the canonical starter image).
    /// * The task is a Reviewer (which is structurally forbidden
    ///   from declaring an alias per `INV-PLANNER-HARNESS-02`).
    ///   The activation handler reads this through
    ///   [`PlanRegistry::get`] to decide whether to spawn the
    ///   canonical starter image or an operator-published one. The
    ///   alias is the trust anchor the operator signed; the kernel
    ///   re-resolves it against the *current* policy at activation
    ///   (re-checking `oci_digest` and `linux_kernel_version_min`)
    ///   so a credential rotation between admission and activation
    ///   does not silently drift the image bytes.
    pub vm_image: String,

    /// Operator-authored seed prompt
    /// for the executor / reviewer agent. Lives inside the signed
    /// plan artifact (`[[tasks]] description`); the kernel stamps it
    /// into the spawned planner binary's env as
    /// `RAXIS_PLANNER_TASK_PROMPT` so the dispatch loop has a
    /// concrete user message to seed the model with.
    /// **Always non-empty in production.** The plan validator
    /// (`parse_plan_tasks` in `lifecycle.rs`) rejects any
    /// `[[tasks]]` row whose `description` is missing, empty, or
    /// non-string with `LifecycleError::PlanInvalid`. The
    /// `Default` impl yields `""` purely as a test-fixture
    /// convenience (`..Default::default()` spreads in unit tests);
    /// every production `TaskPlanFields` reaches the registry
    /// through the parser, which guarantees a non-empty value.
    /// **Trust origin.** Comes from the operator-signed plan TOML;
    /// the agent never sees the prompt before it is rendered into
    /// the system / user messages by the role-binary's dispatch
    /// driver. The kernel does not interpret the prompt text in
    /// any way (no template substitution, no command parsing) — it
    /// is opaque bytes the model receives.
    pub description: String,

    /// JSON-encoded custom-tool bundle resolved from this task's
    /// `profiles = [...]` declaration. `None` means the task has no
    /// operator tool profiles or those profiles have no effective tools.
    /// The session-spawn path stamps this only into Executor
    /// sessions; Reviewer and Orchestrator sessions never receive
    /// operator-defined custom tools.
    pub custom_tools_json: Option<String>,

    /// Canonical `[[tasks.verifiers]]` declarations sourced from the
    /// signed plan. These are per-task checks that run against this
    /// task's evaluation commit, distinct from policy-wide gates and
    /// plan-level integration merge verifiers.
    pub task_verifiers: Vec<raxis_policy::TaskVerifierEntry>,

    /// V2 `v2-deep-spec.md §Step 12` — operator-declared ceiling on
    /// **VM-crash retries** for this sub-task. Read by
    /// `handle_retry_sub_task` against `subtask_activations.crash_retry_count`
    /// to decide whether a planner-issued `RetrySubTask` is admissible.
    /// **Semantics.**
    /// * `Some(c)` — strict ceiling: the kernel admits a `RetrySubTask`
    ///   only while `crash_retry_count < c`. Once the counter reaches
    ///   `c`, every subsequent `RetrySubTask` returns
    ///   `FAIL_INVALID_REQUEST` (INV-08 — coarse code, no detail leak).
    /// * `None` — operator omitted the field. The kernel substitutes
    ///   the conservative default [`DEFAULT_MAX_CRASH_RETRIES`] so a
    ///   silent omission cannot widen the ceiling beyond a few
    ///   transient hypervisor failures.
    ///   **Crash classification.** `crash_retry_count` is bumped by the
    ///   kernel on:
    ///   * SIGCHLD / non-zero VM exit (recovery sweep);
    ///   * `SecurityViolation` revocation per v2-deep-spec.md §Step 14;
    ///   * `ReportFailure` from an Executor (V2.5 — see
    ///     [`crate::handlers::intent::bump_executor_crash_retry_count_in_tx`]
    ///     for the spec-extension rationale: an LLM that loops on
    ///     `report_failure` is operationally indistinguishable from
    ///     a crash loop, and the V2 ops contract bounds every
    ///     unsuccessful attempt against an Executor under the
    ///     same per-task ceiling).
    ///     The retry handler reads it at counter-check time only.
    pub max_crash_retries: Option<u32>,

    /// V2 `v2-deep-spec.md §Step 12` — operator-declared ceiling on
    /// **review-rejection retries** for this sub-task. Read by
    /// `handle_retry_sub_task` against
    /// `subtask_activations.review_reject_count` to decide whether
    /// a planner-issued `RetrySubTask` against an Executor whose
    /// reviewers rejected can be re-spawned.
    /// **Semantics.**
    /// * `Some(c)` — strict ceiling: the kernel admits a `RetrySubTask`
    ///   only while `review_reject_count < c`. Once the counter reaches
    ///   `c`, every subsequent `RetrySubTask` returns
    ///   `FAIL_INVALID_REQUEST`.
    /// * `None` — operator omitted the field. The kernel substitutes
    ///   the conservative default [`DEFAULT_MAX_REVIEW_REJECTIONS`]
    ///   so a plan with no explicit budget still rate-limits
    ///   review-loop oscillation (v2-deep-spec.md §Step 12 rationale:
    ///   review-fail typically signals planner / spec mismatch and
    ///   benefits from human escalation rather than unbounded retry).
    ///   **Counter substrate.** `review_reject_count` is bumped exactly
    ///   once per terminal-rejected aggregation round
    ///   (`handle_submit_review` → `compute_aggregate_review_outcome`
    ///   transitions to `AtLeastOneRejected`). The retry handler
    ///   reads the latest active activation row's value.
    pub max_review_rejections: Option<u32>,

    /// V2.7 — operator-declared per-task hard turn ceiling for the
    /// planner dispatch loop running inside the spawned VM. The
    /// ceiling is enforced inside the VM by
    /// `raxis_planner_core::dispatch::Dispatcher::run` (`for turn in
    /// 0..config.max_turns`); on hit the loop terminates with
    /// `Outcome::TurnsExceeded` and the VM exits clean (the kernel
    /// observes the exit and treats it as a deliberate ceiling
    /// surfacing per `INV-PLANNER-HARNESS-04`).
    /// **Resolution precedence** (`INV-PLANNER-MAX-TURNS-PRECEDENCE-01`):
    /// 1. `Some(c)` here ⇒ this exact ceiling, NO matter what the
    ///    policy or compiled default say. Operators can pin a TIGHT
    ///    budget for trivial Reviewer / single-edit tasks (e.g. `5`)
    ///    or a LARGER budget for known-heavy Executor work
    ///    (e.g. `150` for the `materialize-records` task).
    /// 2. `None` here ⇒ fall through to
    ///    `policy.gateway.planner_max_turns_default`.
    /// 3. Policy default `None` ⇒ fall through to the compiled
    ///    `raxis_planner_core::DEFAULT_PLANNER_MAX_TURNS` (100).
    ///    The kernel (`session_spawn_orchestrator::resolve_planner_max_turns`)
    ///    performs this resolution at session-spawn time and stamps the
    ///    result into the spawned VM's env table as
    ///    [`raxis_types::planner_env::PLANNER_MAX_TURNS_ENV`]
    ///    (`RAXIS_PLANNER_MAX_TURNS`). The driver
    ///    (`raxis_planner_core::driver::run_role_session_with_env_fn`)
    ///    reads it at boot and hands it to `DispatchConfig::max_turns`.
    ///    **Validation.** `Some(0)` is rejected at plan-parse time with
    ///    `LifecycleError::PlanInvalid` because a 0-turn budget is never
    ///    useful and almost always indicates a typo (the agent would
    ///    terminate before issuing its first model call). `Some(n)` for
    ///    any `n >= 1` is admitted verbatim.
    pub max_turns: Option<u32>,

    /// V3 `INV-PLANNER-MAX-TURNS-PROGRESSIVE-ON-RETRY-01` —
    /// operator-declared per-task scaling step applied to each
    /// crash-retry attempt. The kernel resolves the effective budget
    /// for attempt `N` (1-indexed) as
    /// `min(base + (N - 1) * step, hard_ceiling)` where `base` is
    /// the per-task / per-policy / compiled `max_turns`
    /// (see [`Self::max_turns`] and
    /// `INV-PLANNER-MAX-TURNS-PRECEDENCE-01`).
    /// **Resolution precedence** (mirrors `max_turns`):
    /// 1. `Some(s)` here ⇒ `s` (policy default ignored).
    /// 2. `None` here + `Some(d)` on
    ///    `GatewaySection::planner_max_turns_step_default` ⇒ `d`.
    /// 3. Neither set ⇒ derived default
    ///    `max(round_up_to_5(base / 2), 10)` so cold-start retries
    ///    get a useful step even for plans that never declared one.
    ///    **Validation.** `Some(0)` is rejected at plan-parse time with
    ///    `LifecycleError::PlanInvalid` — a zero step degenerates the
    ///    progressive resolver back to a constant budget and would mask
    ///    the cold-start retry-tax this knob exists to absorb. If an
    ///    operator actually wants the constant-budget behaviour they
    ///    should pin `max_turns` to a higher value rather than zeroing
    ///    the step.
    pub max_turns_step: Option<u32>,

    // ── V2 elastic-vm-scaling.md §2.2 — per-task elastic knobs ─────
    /// Operator-declared toggle for upward VM-resource scaling on
    /// this task. `None` ⇒ inherit from
    /// `OrchestratorPlanFields::elastic` (initiative-level), which
    /// in turn falls back to `policy.[elastic].enabled`. Reviewer
    /// tasks MUST leave this `None` (the validator rejects any
    /// declaration with `FAIL_REVIEWER_ELASTIC_NOT_ALLOWED`).
    /// Resolution precedence (`elastic-vm-scaling.md §2.2`):
    /// task-level explicit value beats initiative-level
    /// explicit value, which beats the policy `enabled` flag.
    /// Plan-narrows-policy (INV-ELASTIC-01): `Some(true)` is
    /// rejected at admission when policy `enabled = false`;
    /// `Some(false)` is always admissible (a plan can always be
    /// MORE restrictive than policy).
    pub elastic: Option<bool>,

    /// Operator-declared floor on vCPU count for any spawn /
    /// scale-down event for this task. `None` ⇒ kernel uses the
    /// role baseline from `policy.[isolation]`. Validated against
    /// the policy ceiling `policy.[elastic].max_vcpus_per_session`
    /// at admission time.
    pub min_vcpus: Option<u32>,

    /// Operator-declared ceiling on vCPU count for any scale-up
    /// event for this task. `None` ⇒ kernel uses the policy
    /// ceiling. Plans MAY narrow below the policy ceiling but
    /// MAY NOT exceed it (INV-ELASTIC-01).
    pub max_vcpus: Option<u32>,

    /// Operator-declared floor on memory MiB for any spawn /
    /// scale-down event. Same resolution + INV-ELASTIC-01 rule
    /// as `min_vcpus`.
    pub min_memory_mb: Option<u32>,

    /// Operator-declared ceiling on memory MiB for any scale-up
    /// event. Same resolution + INV-ELASTIC-01 rule as
    /// `max_vcpus`.
    pub max_memory_mb: Option<u32>,
}

/// V2 `v2-deep-spec.md §Step 12` — kernel default `max_crash_retries`
/// applied when the plan omits the field.
/// Three retries is enough to absorb a transient hypervisor eviction
/// or noisy-neighbour OOM without unbounded retry loops, and matches
/// the V2 ops guidance that crash retries are environmental noise
/// (not quality regressions).
pub const DEFAULT_MAX_CRASH_RETRIES: u32 = 3;

/// V2 `v2-deep-spec.md §Step 12` — kernel default `max_review_rejections`
/// applied when the plan omits the field.
/// Two rejections is the spec's recommended budget before human
/// escalation: the planner gets the original attempt plus two
/// chances to incorporate Reviewer critique before the operator
/// must intervene. Higher budgets typically indicate a planner /
/// spec mismatch better resolved out-of-band.
pub const DEFAULT_MAX_REVIEW_REJECTIONS: u32 = 2;

/// V2.7 — kernel-side compiled fallback for `max_turns` resolution
/// when **both** the per-task plan field AND the
/// `[gateway].planner_max_turns_default` policy field are absent.
/// **Synchronisation contract.** This constant MUST equal
/// `raxis_planner_core::DEFAULT_PLANNER_MAX_TURNS`. The kernel cannot
/// `pub use` the planner-core constant directly because the kernel
/// crate cannot depend on `raxis-planner-core` (that crate pulls in
/// `reqwest` and the HTTP-tier deps the kernel deliberately keeps
/// out of its tree). The
/// `inv_planner_max_turns_compiled_default_matches_planner_core`
/// witness test in `kernel/src/session_spawn_orchestrator.rs::tests`
/// asserts the two constants are bit-equal at compile-time, so any
/// future bump of one fails CI until both are bumped in lock-step.
/// Current value: `100`. Historical bumps documented in
/// `guides/recipes/env/11-planner-env-vars.md` (20 → 50 → 100 across
/// live-e2e iter25 / iter31).
pub const DEFAULT_PLANNER_MAX_TURNS: u32 = 100;

impl Default for TaskPlanFields {
    fn default() -> Self {
        Self {
            path_allowlist: Vec::new(),
            path_export_to_successors: false,
            path_export_globs: Vec::new(),
            path_scope_override: false,
            clone_strategy: CloneStrategy::Blobless,
            session_agent_type: SessionAgentType::Executor,
            vm_image: String::new(),
            description: String::new(),
            custom_tools_json: None,
            task_verifiers: Vec::new(),
            max_crash_retries: None,
            max_review_rejections: None,
            max_turns: None,
            max_turns_step: None,
            elastic: None,
            min_vcpus: None,
            max_vcpus: None,
            min_memory_mb: None,
            max_memory_mb: None,
        }
    }
}

impl TaskPlanFields {
    /// Resolve [`Self::max_crash_retries`] against the kernel default
    /// [`DEFAULT_MAX_CRASH_RETRIES`]. Always returns a concrete value
    /// the retry handler can compare counters against; the `Option`
    /// surface exists to distinguish "operator chose 0" from
    /// "operator omitted the field".
    pub fn effective_max_crash_retries(&self) -> u32 {
        self.max_crash_retries.unwrap_or(DEFAULT_MAX_CRASH_RETRIES)
    }

    /// Resolve [`Self::max_review_rejections`] against the kernel
    /// default [`DEFAULT_MAX_REVIEW_REJECTIONS`]. Always returns a
    /// concrete value the retry handler can compare counters against.
    pub fn effective_max_review_rejections(&self) -> u32 {
        self.max_review_rejections
            .unwrap_or(DEFAULT_MAX_REVIEW_REJECTIONS)
    }

    /// Resolve [`Self::max_turns`] against the policy-level default
    /// (`[gateway].planner_max_turns_default`) and the compiled
    /// fallback [`DEFAULT_PLANNER_MAX_TURNS`].
    /// **Precedence** (`INV-PLANNER-MAX-TURNS-PRECEDENCE-01`):
    /// 1. `Some(c)` on the per-task field ⇒ `c` (policy default
    ///    ignored).
    /// 2. `None` on the per-task field + `Some(d)` policy default ⇒
    ///    `d` (compiled default ignored).
    /// 3. `None` on both ⇒ [`DEFAULT_PLANNER_MAX_TURNS`].
    ///    Returns `(resolved_value, source_label)` so the
    ///    `session_spawn_orchestrator` callsite can emit a structured
    ///    `PlannerMaxTurnsResolved` log line whose `source` field names
    ///    the resolution arm verbatim.
    pub fn effective_max_turns(&self, policy_default: Option<u32>) -> (u32, &'static str) {
        if let Some(c) = self.max_turns {
            (c, "task")
        } else if let Some(d) = policy_default {
            (d, "policy")
        } else {
            (DEFAULT_PLANNER_MAX_TURNS, "compiled-default")
        }
    }
}

// ---------------------------------------------------------------------------
// OrchestratorPlanFields — V2 §Step 11 per-initiative orchestrator plan stanza
// ---------------------------------------------------------------------------

/// The orchestrator-scoped plan fields parsed from the optional
/// `[orchestrator]` section of the signed plan TOML.
/// Step 11 introduces `cross_cutting_artifacts`: an exact-filename-only
/// allowlist of files the Orchestrator may touch during
/// `IntentKind::IntegrationMerge` even when no sub-task owns them
/// (e.g. `Cargo.lock`, `package-lock.json`, `go.sum`). The field is
/// operator-declared at sign time and sealed in the plan artifact.
/// **Format constraint (validated at admission).** Each entry MUST be
/// an exact filename (no globs, no slashes — i.e., not a directory
/// prefix and not a multi-segment path). The validator
/// `validate_cross_cutting_artifacts` (in `lifecycle.rs`) enforces this
/// at `approve_plan` time before the registry is populated.
/// **Default.** V1 plans (no `[orchestrator]` section) and V2 plans
/// that omit the section default to an empty list, which means the
/// hybrid allowlist degenerates to the union of sub-task allowlists.
/// This matches the V1 behaviour exactly — V1 plans are
/// forward-compatible with the Step 11 enforcement path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrchestratorPlanFields {
    /// Exact filenames the Orchestrator may touch on
    /// `IntegrationMerge`, in addition to the union of every sub-task's
    /// `path_allowlist`. Validated to contain no `/`, no glob
    /// metacharacters, no `..`, and no empty entries at admission time.
    pub cross_cutting_artifacts: Vec<String>,

    /// Initiative-scoped seed prompt for
    /// the orchestrator agent. Sourced from the plan TOML's
    /// `[plan.initiative] description` field at `approve_plan` time
    /// (the same field that `kernel-mechanics-prompt.md §3.2`
    /// renders into the orchestrator's
    /// `[KERNEL: INITIATIVE GUIDANCE]` block) and stamped into the
    /// orchestrator session's spawn env as
    /// `RAXIS_PLANNER_TASK_PROMPT`. **REQUIRED** by the parser:
    /// reaching this struct with an empty `description` indicates a
    /// validator regression.
    pub description: String,

    /// V2 `integration-merge.md §1.2` — fully-qualified ref name that
    /// this initiative's `IntegrationMerge` advances. Sourced from the
    /// required plan-side `[workspace] target_ref`; `[git]
    /// target_ref_locked` can restrict that explicit value to the policy
    /// default at admission time.
    /// Always non-empty after `approve_plan`. The integration-merge
    /// handler reads this verbatim into
    /// `commit_merge_to_target_ref(...)` so the host-side
    /// fast-forward advances the operator-configured branch instead
    /// of always touching `refs/heads/main`.
    /// **Default `"refs/heads/main"`.** Used only by `Default`-spread
    /// unit fixtures and defensive in-memory construction. Production
    /// admission rejects plans that omit `[workspace] target_ref`.
    pub target_ref: String,

    /// Raxis 0.2 managed repository id selected by required
    /// `[workspace] repository`. The lifecycle parser validates this as
    /// a single path-safe segment at admission time, so spawn / merge
    /// paths can derive the source repo without stringly path
    /// manipulation.
    pub repository_id: String,

    /// Plan-source `[[plan.integration_merge_verifiers]]` entries
    /// sealed with the initiative. These run at `IntegrationMerge`
    /// time against the orchestrator's candidate merged tree and are
    /// distinct from policy-source `[[integration_merge_verifiers]]`.
    pub integration_merge_verifiers: Vec<raxis_policy::IntegrationMergeVerifierEntry>,

    /// V2 `elastic-vm-scaling.md §2.2` — initiative-level toggle
    /// for upward VM-resource scaling. Sourced from
    /// `[plan.initiative] elastic`. `None` ⇒ field omitted ⇒
    /// inherit from `policy.[elastic].enabled`. Resolution
    /// precedence: task-level explicit > initiative-level
    /// explicit > policy `enabled` flag.
    /// Plan-narrows-policy (INV-ELASTIC-01): `Some(true)` is
    /// rejected at admission when policy `enabled = false`;
    /// `Some(false)` is always admissible. Reviewer tasks may
    /// not opt back into elastic at the task level even when
    /// the initiative declares `true` — Reviewer scaling is
    /// structurally forbidden by `INV-PLANNER-HARNESS-02`.
    pub elastic: Option<bool>,

    /// V3 iter69 — `INV-ORCH-BOUNDED-CONCURRENCY-01`.
    ///
    /// Initiative-level cap on how many sub-task activations
    /// (`subtask_activations.activation_state = 'Active'`) can be
    /// in flight at the same time inside this initiative. The
    /// post-exit orchestrator-respawn hook in
    /// `kernel/src/session_spawn_orchestrator.rs` consults this
    /// value so the orchestrator can fan out admissible
    /// independent work in parallel — until iter69 the gate was
    /// the binary `!active_exists` predicate, which serialised
    /// every DAG node inside one initiative even when the tasks
    /// had no edges between them.
    ///
    /// **Sourced from `[workspace] max_concurrent_admissions`** in
    /// `plan.toml`; defaults to
    /// [`Self::DEFAULT_MAX_CONCURRENT_ADMISSIONS`] (`3`) when the
    /// field is absent. Validated `1..=Self::MAX_MAX_CONCURRENT_ADMISSIONS`
    /// (`1..=20`) at admission time —
    /// [`crate::initiatives::lifecycle::parse_plan_workspace_max_concurrent_admissions`]
    /// surfaces a `LifecycleError::PlanInvalid` for out-of-range
    /// or non-integer values so the operator sees the malformed
    /// section immediately.
    ///
    /// **Why this lives on the orchestrator plan fields** (and
    /// not on a new `initiatives` table column): the registry is
    /// repopulated at boot from `plan_bundles_v2` (which stores
    /// the signed plan TOML verbatim), so the value survives a
    /// kernel restart without a schema migration. The
    /// in-memory read on the hot path (post-exit hook fires once
    /// per orchestrator exit) is also cheaper than a SQL round
    /// trip per decision.
    ///
    /// **Why 3 is the default.** Three is the smallest cap that
    /// permits the realistic-scenario primary plan to dispatch
    /// its three structurally-independent root executors
    /// (`materialize-records`, `xfile-refactor`,
    /// `dep-fetch-evidence`) in parallel without re-introducing
    /// the iter7 respawn-storm pathology (an LLM session
    /// loop-rejecting `activate_subtask` intents). Plans that
    /// know their DAG is wider can opt up to 20; plans that
    /// want serial dispatch can opt down to 1 (the pre-iter69
    /// behaviour).
    pub max_concurrent_admissions: u32,
}

impl OrchestratorPlanFields {
    /// `Default`-impl target ref for unit fixtures and defensive
    /// in-memory construction. Production plan admission requires an
    /// explicit `[workspace] target_ref`.
    pub const DEFAULT_TARGET_REF: &'static str = "refs/heads/main";

    /// `Default`-impl managed repository id for unit fixtures and
    /// defensive in-memory construction. Production plan admission
    /// requires an explicit `[workspace] repository`.
    pub const DEFAULT_REPOSITORY_ID: &'static str =
        crate::managed_repositories::DEFAULT_REPOSITORY_ID;

    /// V3 iter69 — `INV-ORCH-BOUNDED-CONCURRENCY-01`. Default cap
    /// on simultaneous `Active` sub-task activations per
    /// initiative when the plan does not declare a
    /// `[workspace] max_concurrent_admissions` override. See the
    /// field-level doc on [`Self::max_concurrent_admissions`]
    /// for the rationale.
    pub const DEFAULT_MAX_CONCURRENT_ADMISSIONS: u32 = 3;

    /// V3 iter69 — upper bound on a plan-declared
    /// `[workspace] max_concurrent_admissions`. Twenty is well
    /// above any realistic plan width and keeps the validator
    /// behind a structural ceiling so a malformed plan can't
    /// declare `max_concurrent_admissions = 2 ** 31 - 1` and
    /// effectively disable the safety net.
    pub const MAX_MAX_CONCURRENT_ADMISSIONS: u32 = 20;
}

impl Default for OrchestratorPlanFields {
    fn default() -> Self {
        Self {
            cross_cutting_artifacts: Vec::new(),
            description: String::new(),
            target_ref: Self::DEFAULT_TARGET_REF.to_owned(),
            repository_id: Self::DEFAULT_REPOSITORY_ID.to_owned(),
            integration_merge_verifiers: Vec::new(),
            elastic: None,
            max_concurrent_admissions: Self::DEFAULT_MAX_CONCURRENT_ADMISSIONS,
        }
    }
}

// ---------------------------------------------------------------------------
// PlanRegistry — process-wide map keyed by TaskKey
// ---------------------------------------------------------------------------

/// In-memory registry of per-task plan fields. Single instance per kernel
/// process, owned by `HandlerContext` behind `Arc`.
/// Two orthogonal projections live here:
/// * `tasks` — keyed by `(initiative_id, task_id)`, holds per-task
///   `TaskPlanFields`. Populated by `approve_plan` from `[[tasks]]`.
/// * `orchestrators` — keyed by `initiative_id`, holds the per-initiative
///   `OrchestratorPlanFields` (Step 11). Populated by `approve_plan`
///   from `[orchestrator]`. Missing entries default to empty
///   `cross_cutting_artifacts` so V1 plans need no schema bump.
#[derive(Debug, Default)]
pub struct PlanRegistry {
    inner: RwLock<FxHashMap<TaskKey, TaskPlanFields>>,
    orchestrators: RwLock<FxHashMap<String, OrchestratorPlanFields>>,
}

impl PlanRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert or replace the plan fields for one task.
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
    /// Idempotent. In normal operation `approve_plan` calls this once
    /// per initiative; a re-insert (e.g. from `repopulate_from_store`)
    /// overwrites with identical bytes since the signed plan artifact
    /// is immutable.
    pub fn insert_orchestrator(
        &self,
        initiative_id: impl Into<String>,
        fields: OrchestratorPlanFields,
    ) {
        let mut guard = self
            .orchestrators
            .write()
            .expect("PlanRegistry orchestrators RwLock poisoned — kernel must abort");
        guard.insert(initiative_id.into(), fields);
    }

    /// Look up the orchestrator plan fields for one initiative. Returns
    /// `None` when the initiative has no `[orchestrator]` section in
    /// its signed plan; callers MUST treat that as "no cross-cutting
    /// artifacts" (the empty-list default), never as "match
    /// everything".
    pub fn orchestrator(&self, initiative_id: &str) -> Option<OrchestratorPlanFields> {
        let guard = self
            .orchestrators
            .read()
            .expect("PlanRegistry orchestrators RwLock poisoned — kernel must abort");
        guard.get(initiative_id).cloned()
    }

    /// V3 iter69 — `INV-ORCH-BOUNDED-CONCURRENCY-01`.
    ///
    /// Resolve the cap on simultaneously-`Active` sub-task
    /// activations for a given initiative. Used by the post-exit
    /// orchestrator-respawn hook in
    /// `session_spawn_orchestrator::spawn_planner_dispatcher`:
    ///
    /// > respawn-eligible iff
    /// >   `pending_exists && active_count < orchestrator_concurrency_cap(...)`.
    ///
    /// Falls back to
    /// [`OrchestratorPlanFields::DEFAULT_MAX_CONCURRENT_ADMISSIONS`]
    /// (`3`) when:
    ///
    ///   * the initiative is unknown to the registry (a regressed
    ///     `repopulate_from_store` would otherwise wedge the gate
    ///     at zero — fail-OPEN to the operator default rather than
    ///     dead-locking the initiative), OR
    ///   * the plan omitted `[workspace] max_concurrent_admissions`
    ///     (the typical operator-friendly default).
    pub fn orchestrator_concurrency_cap(&self, initiative_id: &str) -> u32 {
        self.orchestrator(initiative_id)
            .map(|f| f.max_concurrent_admissions)
            .unwrap_or(OrchestratorPlanFields::DEFAULT_MAX_CONCURRENT_ADMISSIONS)
    }

    /// Snapshot every `(task_id, fields)` for the given initiative.
    /// Used by Step 11's `compute_hybrid_effective_allow` to fold every
    /// sub-task's `path_allowlist` into the union before adding
    /// `cross_cutting_artifacts`. Returns an owned Vec so the caller
    /// can release the lock immediately.
    pub fn tasks_in_initiative(&self, initiative_id: &str) -> Vec<(String, TaskPlanFields)> {
        let guard = self
            .inner
            .read()
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
        assert!(
            f.path_allowlist.is_empty(),
            "default path_allowlist must deny"
        );
        assert!(!f.path_export_to_successors, "default export must be off");
        assert!(
            f.path_export_globs.is_empty(),
            "default export globs must be empty"
        );
        assert!(!f.path_scope_override, "default override must be false");
        // `Default` fixtures use Blobless because it is uniformly safe
        // for every agent type and cheaper than Full for repos with
        // binary blobs. Production plan admission still requires the
        // field explicitly.
        assert_eq!(
            f.clone_strategy,
            CloneStrategy::Blobless,
            "default clone_strategy must be Blobless (V2 §Step 27)"
        );
        // Test fixtures default to Executor; production plan admission
        // requires `session_agent_type` explicitly.
        assert_eq!(
            f.session_agent_type,
            SessionAgentType::Executor,
            "default session_agent_type must be Executor (V2 §Step 6)"
        );
        // `Default` MUST yield an
        // empty `description`. Production NEVER reaches the spawn
        // path with a default-constructed `TaskPlanFields`: every
        // entry in the registry is built by `parse_plan_tasks`,
        // which rejects empty / missing descriptions at admission
        // time. The `Default` impl is exclusively a test convenience
        // (e.g. `..Default::default()` spreads in unit fixtures);
        // pinning the empty default here guarantees that callers
        // who accidentally rely on it cannot smuggle a non-empty
        // prompt past the parser.
        assert!(f.description.is_empty(),
            "default description must be empty so test fixtures cannot smuggle a non-parser-validated prompt");
        // V2 §Step 12 — `max_crash_retries` / `max_review_rejections`
        // default to `None` (operator-omitted). The kernel substitutes
        // a conservative ceiling at `RetrySubTask` admission time
        // (`DEFAULT_MAX_CRASH_RETRIES = 3`,
        //  `DEFAULT_MAX_REVIEW_REJECTIONS = 2`). Pin both invariants:
        // the `Option` shape (so a 0-value test fixture is
        // distinguishable from omission) and the resolved kernel
        // defaults.
        assert_eq!(
            f.max_crash_retries, None,
            "default max_crash_retries must be None so the kernel default applies"
        );
        assert_eq!(
            f.max_review_rejections, None,
            "default max_review_rejections must be None so the kernel default applies"
        );
        assert_eq!(
            f.effective_max_crash_retries(),
            DEFAULT_MAX_CRASH_RETRIES,
            "kernel default max_crash_retries pin (V2 §Step 12)"
        );
        assert_eq!(
            f.effective_max_review_rejections(),
            DEFAULT_MAX_REVIEW_REJECTIONS,
            "kernel default max_review_rejections pin (V2 §Step 12)"
        );
    }

    #[test]
    fn explicit_zero_max_retries_overrides_kernel_default() {
        // `Some(0)` means "the operator explicitly forbids retries"
        // distinct from `None` (omitted, default applies). The
        // retry handler must observe the explicit zero rather than
        // the conservative default.
        let f = TaskPlanFields {
            max_crash_retries: Some(0),
            max_review_rejections: Some(0),
            ..Default::default()
        };
        assert_eq!(f.effective_max_crash_retries(), 0);
        assert_eq!(f.effective_max_review_rejections(), 0);
    }

    #[test]
    fn explicit_max_retries_round_trips_through_registry() {
        let r = PlanRegistry::new();
        let key = TaskKey::new("init-1", "task-A");
        let f = TaskPlanFields {
            max_crash_retries: Some(7),
            max_review_rejections: Some(11),
            ..Default::default()
        };
        r.insert(key.clone(), f);
        let got = r.get(&key).expect("just inserted");
        assert_eq!(got.max_crash_retries, Some(7));
        assert_eq!(got.max_review_rejections, Some(11));
        assert_eq!(got.effective_max_crash_retries(), 7);
        assert_eq!(got.effective_max_review_rejections(), 11);
    }

    #[test]
    fn missing_lookup_returns_none_not_default() {
        // Critical invariant: the registry must NOT auto-fill defaults on
        // miss — callers need to distinguish "task has empty allowlist"
        // (TaskPlanFields::default with explicit insert) from "task has
        // no plan entry at all" (corrupted state, should fail closed).
        let r = PlanRegistry::new();
        r.insert(TaskKey::new("init", "present"), TaskPlanFields::default());
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
            cross_cutting_artifacts: vec!["Cargo.lock".to_owned(), "package-lock.json".to_owned()],
            ..Default::default()
        };
        r.insert_orchestrator("init-1", f.clone());
        let got = r.orchestrator("init-1").expect("just inserted");
        assert_eq!(got, f);
    }

    #[test]
    fn orchestrator_re_insert_overwrites_in_place() {
        let r = PlanRegistry::new();
        r.insert_orchestrator(
            "init-1",
            OrchestratorPlanFields {
                cross_cutting_artifacts: vec!["old.lock".to_owned()],
                ..Default::default()
            },
        );
        r.insert_orchestrator(
            "init-1",
            OrchestratorPlanFields {
                cross_cutting_artifacts: vec!["new.lock".to_owned()],
                ..Default::default()
            },
        );
        let got = r.orchestrator("init-1").unwrap();
        assert_eq!(got.cross_cutting_artifacts, vec!["new.lock"]);
    }

    #[test]
    fn orchestrators_are_scoped_per_initiative() {
        let r = PlanRegistry::new();
        r.insert_orchestrator(
            "init-A",
            OrchestratorPlanFields {
                cross_cutting_artifacts: vec!["a.lock".to_owned()],
                ..Default::default()
            },
        );
        r.insert_orchestrator(
            "init-B",
            OrchestratorPlanFields {
                cross_cutting_artifacts: vec!["b.lock".to_owned()],
                ..Default::default()
            },
        );
        assert_eq!(
            r.orchestrator("init-A").unwrap().cross_cutting_artifacts,
            vec!["a.lock"]
        );
        assert_eq!(
            r.orchestrator("init-B").unwrap().cross_cutting_artifacts,
            vec!["b.lock"]
        );
    }

    #[test]
    fn orchestrator_default_has_empty_artifacts() {
        // Pin the defensive in-memory default: an explicitly-inserted
        // empty `OrchestratorPlanFields` means "no cross-cutting
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

        let mut a_tasks: Vec<String> = r
            .tasks_in_initiative("init-A")
            .into_iter()
            .map(|(id, _)| id)
            .collect();
        a_tasks.sort();
        assert_eq!(a_tasks, vec!["t1".to_owned(), "t2".to_owned()]);

        let b_tasks: Vec<String> = r
            .tasks_in_initiative("init-B")
            .into_iter()
            .map(|(id, _)| id)
            .collect();
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
            path_allowlist: vec!["src/a.rs".to_owned()],
            path_export_to_successors: true,
            path_export_globs: vec!["src/**".to_owned()],
            path_scope_override: false,
            clone_strategy: CloneStrategy::Sparse,
            session_agent_type: SessionAgentType::Executor,
            vm_image: String::new(),
            description: "Refactor parser to handle UTF-16".to_owned(),
            custom_tools_json: None,
            max_crash_retries: None,
            max_review_rejections: None,
            max_turns: None,
            max_turns_step: None,
            elastic: None,
            min_vcpus: None,
            max_vcpus: None,
            min_memory_mb: None,
            max_memory_mb: None,
            task_verifiers: Vec::new(),
        };
        r.insert(TaskKey::new("init-A", "t1"), f.clone());
        let snapshot = r.tasks_in_initiative("init-A");
        assert_eq!(snapshot.len(), 1);
        assert_eq!(snapshot[0].0, "t1");
        assert_eq!(snapshot[0].1, f);
    }

    // ── task description plumbing ────

    #[test]
    fn description_round_trips_through_registry() {
        let r = PlanRegistry::new();
        let key = TaskKey::new("init-1", "task-A");
        let f = TaskPlanFields {
            description: "Create hello.txt with greeting".to_owned(),
            ..Default::default()
        };
        r.insert(key.clone(), f.clone());
        assert_eq!(
            r.get(&key).unwrap().description,
            "Create hello.txt with greeting",
            "task description must round-trip verbatim through the registry",
        );
    }

    #[test]
    fn orchestrator_default_description_is_empty() {
        // Same rationale as the per-task variant above: `Default` is
        // exclusively for test fixtures (and `..Default::default()`
        // spreads). Production builds the orchestrator entry through
        // `parse_plan_orchestrator`, which rejects missing / empty
        // `[plan.initiative] description` at admission time.
        let f = OrchestratorPlanFields::default();
        assert!(f.description.is_empty(),
            "default orchestrator description must be empty so test fixtures cannot smuggle a non-parser-validated prompt");
    }

    #[test]
    fn orchestrator_description_round_trips_through_registry() {
        let r = PlanRegistry::new();
        let f = OrchestratorPlanFields {
            description: "Coordinate the migration".to_owned(),
            ..Default::default()
        };
        r.insert_orchestrator("init-1", f.clone());
        let got = r.orchestrator("init-1").expect("just inserted");
        assert_eq!(got.description, "Coordinate the migration");
    }

    // ── V3 iter69 — `INV-ORCH-BOUNDED-CONCURRENCY-01` registry tests
    //
    // These tests pin three contracts the post-exit hook relies on:
    //
    //   1. The struct-level `Default` carries the documented `3`
    //      cap. A test fixture that spreads `..Default::default()`
    //      must therefore inherit the operator default, not `0`.
    //   2. An unknown initiative resolves to the default — the
    //      hook fails OPEN to keep an unknown initiative from
    //      dead-locking, never zero (which would silently wedge the
    //      gate).
    //   3. An inserted override round-trips through the
    //      `orchestrator_concurrency_cap` helper.

    #[test]
    fn default_orchestrator_fields_carry_documented_concurrency_cap() {
        let f = OrchestratorPlanFields::default();
        assert_eq!(
            f.max_concurrent_admissions,
            OrchestratorPlanFields::DEFAULT_MAX_CONCURRENT_ADMISSIONS,
        );
        // Pin the public constant so a future change cannot silently
        // shift the operator-facing default — any tweak must update
        // this test AND the `[workspace] max_concurrent_admissions`
        // operator docs together.
        assert_eq!(OrchestratorPlanFields::DEFAULT_MAX_CONCURRENT_ADMISSIONS, 3);
        assert_eq!(OrchestratorPlanFields::MAX_MAX_CONCURRENT_ADMISSIONS, 20);
    }

    #[test]
    fn orchestrator_concurrency_cap_unknown_initiative_falls_back_to_default() {
        let r = PlanRegistry::new();
        // The post-exit hook may resolve the cap for an initiative
        // whose registry entry was never populated (e.g. a regressed
        // `repopulate_from_store`, or a unit test that exercises the
        // hook against a partially-seeded registry). Fail OPEN to
        // the operator default rather than collapse the gate.
        let cap = r.orchestrator_concurrency_cap("unknown-initiative");
        assert_eq!(
            cap,
            OrchestratorPlanFields::DEFAULT_MAX_CONCURRENT_ADMISSIONS,
        );
    }

    #[test]
    fn orchestrator_concurrency_cap_round_trips_per_initiative_override() {
        let r = PlanRegistry::new();
        r.insert_orchestrator(
            "init-low",
            OrchestratorPlanFields {
                max_concurrent_admissions: 1,
                ..Default::default()
            },
        );
        r.insert_orchestrator(
            "init-high",
            OrchestratorPlanFields {
                max_concurrent_admissions: 12,
                ..Default::default()
            },
        );
        assert_eq!(r.orchestrator_concurrency_cap("init-low"), 1);
        assert_eq!(r.orchestrator_concurrency_cap("init-high"), 12);
        // Sibling initiatives must not share state — a per-initiative
        // override applies ONLY to its own initiative.
        assert_eq!(
            r.orchestrator_concurrency_cap("init-unrelated"),
            OrchestratorPlanFields::DEFAULT_MAX_CONCURRENT_ADMISSIONS,
        );
    }
}

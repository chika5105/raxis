// raxis-kernel::gates — Gate evaluation pipeline.
//
// Normative reference: kernel-core.md §2.3 `src/gates/mod.rs`.
//
// Public entry points:
//   - evaluate_claims() — recheck path, spawns missing verifiers immediately.
//   - evaluate_claims_defer_verifier_spawn() — initial intent path, returns
//     missing gates so the caller can commit GatesPending before spawn.
// Called by handlers/intent.rs after VCS path derivation.
// Never called by the dispatcher directly.
//
// Boundary rule (kernel-core.md Part 2.1):
//   Gates never import raxis-store directly for SQL.
//   All state access goes through facades:
//     authority  — delegation::check_capability, delegation::record_capability_use
//     policy     — policy_lookup::required_claims, check_claim_scope
//     witness_index — witness::lookup
//   raxis_store::Store is used only as a pass-through type (received via ctx).

pub mod claim;
pub mod policy_lookup;
pub mod verifier_runner;
// === iter62 verifier-runtime D8: VerifierVm* audit-emission helpers ===
//
// Builder/emission helpers for the six new `AuditEventKind::Verifier*`
// variants the iter62 verifier runtime emits at the kernel-side
// verifier-VM lifecycle sites. Lives next to `verifier_runner` so
// the call sites and the helpers stay co-located. See
// `verifier_audit.rs` module-level comment for the wiring contract.
pub mod verifier_audit;
pub mod witness;

use std::path::{Path, PathBuf};
use std::sync::Arc;

use raxis_policy::{GateEntry, PolicyBundle};
use raxis_store::{Store, Table};
use raxis_types::{SessionId, SubmittedClaim};
use rusqlite::OptionalExtension;

use crate::authority::delegation;
use crate::ipc::context::HandlerContext;
use crate::witness_index::ResultClass;

// ---------------------------------------------------------------------------
// GateError
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum GateError {
    #[error("policy misconfigured: {0}")]
    PolicyMisconfigured(String),

    #[error("authority error: {0}")]
    AuthorityError(String),

    #[error("witness error: {0}")]
    WitnessError(String),

    #[error("verifier cap exceeded for task {task_id} gate {gate_type}")]
    VerifierCapExceeded { task_id: String, gate_type: String },

    #[error("verifier already active for task {task_id} gate {gate_type} evaluation {evaluation_sha}: {verifier_run_id}")]
    VerifierAlreadyActive {
        task_id: String,
        gate_type: String,
        evaluation_sha: String,
        verifier_run_id: String,
    },

    /// iter63-followups.md Item 2 #3 — the task's cumulative
    /// verifier wall-time has already crossed
    /// `task_verifier_total_budget_seconds`; the kernel refuses to
    /// spawn another verifier and the gate is failed with
    /// `WitnessRejected { reason: TimeBudgetExhausted }` upstream.
    /// Pinned by `INV-VERIFIER-CUMULATIVE-BUDGET-01`.
    #[error("verifier budget exhausted for task {task_id} ({cumulative_seconds}s spent, budget {budget_seconds}s)")]
    VerifierBudgetExhausted {
        task_id: String,
        cumulative_seconds: u64,
        budget_seconds: u64,
    },

    #[error("verifier spawn failed for gate {gate_type}: {reason}")]
    SpawnFailed { gate_type: String, reason: String },

    #[error("store error: {0}")]
    Store(String),
}

// ---------------------------------------------------------------------------
// GateEvalResult
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub enum GateEvalResult {
    /// All gates satisfied.
    /// `delegate_renewal_required = true` means StaleOnNextUse grace use was
    /// consumed — record_capability_use was called for each stale capability.
    Pass { delegate_renewal_required: bool },

    /// Break-glass activation is in effect — gate enforcement bypassed.
    BreakglassPass { activation_id: String },

    /// Claims insufficient (delegation, scope, or missing submission).
    /// Contains a planner-facing reason string.
    ClaimInsufficient { reason: String },

    /// One or more gate types are unsatisfied. Depending on the caller,
    /// verifiers may already be spawned or may be deliberately deferred
    /// until the task's `GatesPending` transition commits.
    PendingWitness { missing_gates: Vec<String> },
}

// ---------------------------------------------------------------------------
// evaluate_claims — 5-step pipeline per spec §2.3 gates/mod.rs
// ---------------------------------------------------------------------------

/// Evaluate claims for a task intent.
///
/// Signature per spec: takes `ctx: &HandlerContext` so gates access all
/// facades without importing raxis-store or raxis-crypto directly.
///
/// Steps:
///   1. Break-glass check (bypass if active).
///   2. Policy lookup → required claim types.
///   3. Claim evaluation (delegation + submission + scope).
///   4. Witness check per gate type. On full pass: record_capability_use for stale caps.
///   5. Spawn verifiers for missing gates.
pub async fn evaluate_claims(
    session_id: &SessionId,
    evaluation_sha: &str,
    task_id: &str,
    touched_paths: &[PathBuf],
    // Intentionally unused — see `evaluate_pre_spawn` Step 2.5 below. The
    // kernel auto-derives claims from its own witness records;
    // planner-submitted claims are discarded as a security property (the
    // untrusted agent has zero influence on the claim pipeline). The
    // parameter is kept on the signature so the caller's wire shape does
    // not bifurcate between the kernel-auto-derived path and a
    // hypothetical V3 mode where the planner regains submission rights —
    // a contract change of that scope deserves a real PR rather than a
    // silent restoration.
    _submitted_claims_discarded: &[SubmittedClaim],
    worktree_root: &Path,
    ctx: &HandlerContext,
) -> Result<GateEvalResult, GateError> {
    evaluate_claims_impl(
        session_id,
        evaluation_sha,
        task_id,
        touched_paths,
        worktree_root,
        ctx,
        true,
    )
    .await
}

/// Evaluate gate state without spawning missing mechanical verifiers.
///
/// This is the initial intent-admission path used by
/// `handlers::intent`: a missing gate must first be persisted as a
/// `GatesPending` FSM transition. Only after that transaction commits
/// may the kernel spawn a verifier, otherwise a fast verifier can submit
/// its witness while `tasks.state` is still `Admitted` and the witness
/// handler correctly rejects it as `TaskNotGatesPending`.
pub async fn evaluate_claims_defer_verifier_spawn(
    session_id: &SessionId,
    evaluation_sha: &str,
    task_id: &str,
    touched_paths: &[PathBuf],
    // Kept intentionally absent, matching `evaluate_claims`: planner-
    // submitted claims are discarded by the kernel-owned claim pipeline.
    worktree_root: &Path,
    ctx: &HandlerContext,
) -> Result<GateEvalResult, GateError> {
    evaluate_claims_impl(
        session_id,
        evaluation_sha,
        task_id,
        touched_paths,
        worktree_root,
        ctx,
        false,
    )
    .await
}

async fn evaluate_claims_impl(
    session_id: &SessionId,
    evaluation_sha: &str,
    task_id: &str,
    touched_paths: &[PathBuf],
    worktree_root: &Path,
    ctx: &HandlerContext,
    spawn_missing_verifiers: bool,
) -> Result<GateEvalResult, GateError> {
    // Pin one snapshot of the policy bundle for the duration of this
    // gate evaluation. INV-POLICY-01: an in-process epoch advance must
    // not tear an in-flight enforcement decision (kernel-store.md
    // §INV-POLICY-01); binding to a single `Arc<PolicyBundle>` keeps
    // every claim/witness/proof check on the same epoch.
    let policy_snapshot = ctx.policy.load_full();

    // ── Step 1: Break-glass ───────────────────────────────────────────────
    //
    // V1 Tier 4 — emergency operator override (kernel-core.md §2.3
    // src/breakglass.rs). When an unexpired two-operator activation is
    // on disk, gate enforcement is bypassed and the caller
    // (handlers/intent.rs) is expected to emit a `BreakglassAction`
    // audit event for every admission carried under that activation
    // (see `breakglass::log_action`).
    //
    // Kept on the async path because `Breakglass::check()` is pure
    // in-memory (`Arc<RwLock<...>>` read with a timestamp compare) and
    // does NOT touch SQLite — it is async-runtime-safe by construction.
    if let crate::breakglass::BreakglassStatus::Active { activation_id, .. } =
        ctx.breakglass.check()
    {
        return Ok(GateEvalResult::BreakglassPass {
            activation_id: activation_id.to_string(),
        });
    }

    // ── Steps 2 + 2.5 + 3 + 4 — `evaluate_pre_spawn` on the blocking pool ─
    //
    // INV-GATES-EVALUATE-CLAIMS-ASYNC-SAFE-01.
    //
    // Every sync `Store::lock_sync()` site reached transitively from
    // here — `witness::lookup` (Step 2.5 + Step 4),
    // `claim::evaluate` → `authority::delegation::check_capability`
    // (Step 3), `authority::delegation::record_capability_use`
    // (Step 4, on terminal Pass) — would panic with "Cannot block the
    // current thread from within a runtime" if invoked directly from
    // this async fn (it runs on a tokio runtime worker, called from
    // `handlers::intent::handle_inner`). iter63
    // `extended_e2e_realistic_scenario` hit the panic on the first
    // `IntegrationMerge` planner intent (`witness_index::lookup` →
    // `Store::lock_sync` → `tokio::sync::Mutex::blocking_lock`); the
    // kernel daemon crashed mid-stream, plans never completed, and the
    // dashboard at `:19820` went unreachable. Wrapping the entire sync
    // pre-spawn block in a single `spawn_blocking` (a) makes every
    // transitive `lock_sync` call legal, (b) keeps the runtime worker
    // free to drive other tasks while the SQLite work runs on the
    // blocking pool, and (c) matches the Phase-A pattern already
    // established in `handlers::intent::handle_inner` (one hop, not
    // N).
    let session_id_owned = session_id.clone();
    let evaluation_sha_owned = evaluation_sha.to_owned();
    let task_id_owned = task_id.to_owned();
    let touched_paths_owned: Vec<PathBuf> = touched_paths.to_vec();
    let policy_arc: Arc<PolicyBundle> = Arc::clone(&policy_snapshot);
    let store_arc: Arc<Store> = Arc::clone(&ctx.store);
    let pre_spawn = tokio::task::spawn_blocking(move || {
        evaluate_pre_spawn(
            &session_id_owned,
            &evaluation_sha_owned,
            &task_id_owned,
            &touched_paths_owned,
            &policy_arc,
            &store_arc,
        )
    })
    .await
    .map_err(|e| GateError::Store(format!("evaluate_pre_spawn join failed: {e}")))??;

    let missing_gates = match pre_spawn {
        PreSpawnDecision::Pass {
            delegate_renewal_required,
        } => {
            return Ok(GateEvalResult::Pass {
                delegate_renewal_required,
            });
        }
        PreSpawnDecision::ClaimInsufficient { reason } => {
            return Ok(GateEvalResult::ClaimInsufficient { reason });
        }
        PreSpawnDecision::NeedsVerifierSpawn { missing_gates } => missing_gates,
    };

    if spawn_missing_verifiers {
        spawn_verifiers_for_missing_gates(
            task_id,
            evaluation_sha,
            &missing_gates,
            worktree_root,
            &policy_snapshot,
            ctx,
        )
        .await;
    }

    Ok(GateEvalResult::PendingWitness { missing_gates })
}

/// Spawn mechanical verifiers for gates known to be missing.
///
/// Genuinely async — `tokio::process::Command` spawn. MUST run on the
/// tokio runtime worker, not on the blocking pool (a blocking-pool thread
/// cannot drive child-process I/O readiness). Per kernel-core.md §2.3
/// `verifier_runner.rs`, spawn errors are intentionally non-fatal: the
/// missing gate remains missing and the planner is told to wait. But
/// "non-fatal" does NOT mean "silently swallowed": each error variant
/// is logged with the operational meaning an operator needs.
pub async fn spawn_verifiers_for_missing_gates(
    task_id: &str,
    evaluation_sha: &str,
    missing_gates: &[String],
    worktree_root: &Path,
    policy: &PolicyBundle,
    ctx: &HandlerContext,
) {
    let store = ctx.store.as_ref();
    for gate_type in missing_gates {
        let vconfig =
            verifier_runner::VerifierConfig::from_policy(policy, gate_type, &ctx.data_dir);
        let Some(vconfig) = vconfig else { continue };

        match verifier_runner::spawn_verifier_with_audit(
            task_id,
            gate_type,
            evaluation_sha,
            worktree_root,
            &vconfig,
            store,
            Some(ctx.audit.clone()),
        )
        .await
        {
            Ok(_) => {}
            Err(GateError::VerifierCapExceeded { .. }) => {
                eprintln!(
                    "{{\"level\":\"info\",\"event\":\"VerifierCapExceeded\",\
                     \"task_id\":\"{task_id}\",\"gate_type\":\"{gate_type}\"}}",
                );
            }
            Err(GateError::VerifierAlreadyActive {
                verifier_run_id,
                evaluation_sha,
                ..
            }) => {
                eprintln!(
                    "{{\"level\":\"info\",\"event\":\"VerifierAlreadyActive\",\
                     \"task_id\":\"{task_id}\",\"gate_type\":\"{gate_type}\",\
                     \"evaluation_sha\":\"{evaluation_sha}\",\
                     \"verifier_run_id\":\"{verifier_run_id}\"}}",
                );
            }
            Err(GateError::VerifierBudgetExhausted {
                cumulative_seconds,
                budget_seconds,
                ..
            }) => {
                // iter63-followups.md Item 2 #3 —
                // INV-VERIFIER-CUMULATIVE-BUDGET-01. The spawn was
                // refused because the task already burnt through its
                // cumulative budget; surface a structured stderr
                // entry mirroring the audit emit on the spawn side.
                eprintln!(
                    "{{\"level\":\"warn\",\"event\":\"VerifierBudgetExhausted\",\
                     \"task_id\":\"{task_id}\",\"gate_type\":\"{gate_type}\",\
                     \"cumulative_seconds\":{cumulative_seconds},\
                     \"budget_seconds\":{budget_seconds}}}",
                );
            }
            Err(GateError::SpawnFailed { gate_type, reason }) => {
                eprintln!(
                    "{{\"level\":\"error\",\"event\":\"VerifierSpawnFailed\",\
                     \"task_id\":\"{task_id}\",\"gate_type\":\"{gate_type}\",\
                     \"reason\":\"{reason}\"}}",
                );
            }
            Err(GateError::AuthorityError(reason)) => {
                eprintln!(
                    "{{\"level\":\"error\",\"event\":\"VerifierTokenIssueFailed\",\
                     \"task_id\":\"{task_id}\",\"gate_type\":\"{gate_type}\",\
                     \"reason\":\"{reason}\"}}",
                );
            }
            Err(other) => {
                eprintln!(
                    "{{\"level\":\"error\",\"event\":\"VerifierSpawnUnexpectedError\",\
                     \"task_id\":\"{task_id}\",\"gate_type\":\"{gate_type}\",\
                     \"error\":\"{other}\"}}",
                );
            }
        }
    }
}

/// Spawn plan-declared per-task verifiers after `CompleteTask` parks the task
/// in `GatesPending`.
pub async fn spawn_task_verifiers_for_task(
    initiative_id: &str,
    task_id: &str,
    evaluation_sha: &str,
    worktree_root: &Path,
    policy: &PolicyBundle,
    ctx: &HandlerContext,
) {
    spawn_task_verifiers_for_task_filtered(
        initiative_id,
        task_id,
        evaluation_sha,
        worktree_root,
        policy,
        ctx,
        true,
        true,
    )
    .await;
}

/// Spawn only plan-declared warn-only task verifiers. Used after a task has
/// completed normally: warning evidence should still land in audit/UI, but it
/// must not hold the task in `GatesPending` or trigger repair feedback.
pub async fn spawn_warn_only_task_verifiers_for_task(
    initiative_id: &str,
    task_id: &str,
    evaluation_sha: &str,
    worktree_root: &Path,
    policy: &PolicyBundle,
    ctx: &HandlerContext,
) {
    spawn_task_verifiers_for_task_filtered(
        initiative_id,
        task_id,
        evaluation_sha,
        worktree_root,
        policy,
        ctx,
        false,
        true,
    )
    .await;
}

#[derive(Debug, Clone)]
pub struct IntegrationMergeVerifierSpec {
    pub entry: raxis_policy::IntegrationMergeVerifierEntry,
    pub gate_source: &'static str,
}

pub fn integration_merge_verifier_specs_for(
    initiative_id: &str,
    policy: &PolicyBundle,
    ctx: &HandlerContext,
) -> Vec<IntegrationMergeVerifierSpec> {
    let mut out = Vec::new();
    if let Some(orch) = ctx.plan_registry.orchestrator(initiative_id) {
        out.extend(orch.integration_merge_verifiers.into_iter().map(|entry| {
            IntegrationMergeVerifierSpec {
                entry,
                gate_source: "plan_integration_verifier",
            }
        }));
    }
    out.extend(
        policy
            .integration_merge_verifiers()
            .iter()
            .cloned()
            .map(|entry| IntegrationMergeVerifierSpec {
                entry,
                gate_source: "policy_integration_verifier",
            }),
    );
    out
}

/// Spawn plan/policy integration-merge verifiers after an `IntegrationMerge`
/// intent parks the synthetic coordinator in `GatesPending`.
pub async fn spawn_integration_merge_verifiers_for_task(
    initiative_id: &str,
    task_id: &str,
    evaluation_sha: &str,
    worktree_root: &Path,
    missing_gates: &[String],
    policy: &PolicyBundle,
    ctx: &HandlerContext,
) {
    let missing: std::collections::HashSet<&str> =
        missing_gates.iter().map(String::as_str).collect();
    for spec in integration_merge_verifier_specs_for(initiative_id, policy, ctx) {
        if !missing.contains(spec.entry.name.as_str()) {
            continue;
        }
        let vconfig = match verifier_runner::VerifierConfig::from_integration_merge_verifier(
            policy,
            &spec.entry,
            &ctx.data_dir,
            spec.gate_source,
        ) {
            Ok(cfg) => cfg,
            Err(e) => {
                eprintln!(
                    "{{\"level\":\"error\",\"event\":\"IntegrationMergeVerifierConfigInvalid\",\
                     \"initiative_id\":\"{initiative_id}\",\"task_id\":\"{task_id}\",\
                     \"gate_type\":\"{}\",\"gate_source\":\"{}\",\"error\":\"{e}\"}}",
                    spec.entry.name, spec.gate_source,
                );
                continue;
            }
        };
        match verifier_runner::spawn_verifier_with_audit(
            task_id,
            &spec.entry.name,
            evaluation_sha,
            worktree_root,
            &vconfig,
            ctx.store.as_ref(),
            Some(ctx.audit.clone()),
        )
        .await
        {
            Ok(_) => {}
            Err(e) => {
                eprintln!(
                    "{{\"level\":\"error\",\"event\":\"IntegrationMergeVerifierSpawnFailed\",\
                     \"initiative_id\":\"{initiative_id}\",\"task_id\":\"{task_id}\",\
                     \"gate_type\":\"{}\",\"gate_source\":\"{}\",\"error\":\"{e}\"}}",
                    spec.entry.name, spec.gate_source,
                );
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn spawn_task_verifiers_for_task_filtered(
    initiative_id: &str,
    task_id: &str,
    evaluation_sha: &str,
    worktree_root: &Path,
    policy: &PolicyBundle,
    ctx: &HandlerContext,
    include_blocking: bool,
    include_warn_only: bool,
) {
    let key = crate::initiatives::TaskKey::new(initiative_id, task_id);
    let fields = ctx.plan_registry.get(&key);
    let Some(fields) = fields else {
        return;
    };

    for verifier in fields.task_verifiers {
        let include = match verifier.on_failure {
            raxis_policy::TaskVerifierOnFailure::BlockReview => include_blocking,
            raxis_policy::TaskVerifierOnFailure::WarnOnly => include_warn_only,
        };
        if !include {
            continue;
        }
        let vconfig = match verifier_runner::VerifierConfig::from_task_verifier(
            policy,
            &verifier,
            &ctx.data_dir,
        ) {
            Ok(cfg) => cfg,
            Err(e) => {
                eprintln!(
                    "{{\"level\":\"error\",\"event\":\"TaskVerifierConfigInvalid\",\
                         \"task_id\":\"{task_id}\",\"gate_type\":\"{}\",\
                         \"error\":\"{e}\"}}",
                    verifier.name,
                );
                continue;
            }
        };
        match verifier_runner::spawn_verifier_with_audit(
            task_id,
            &verifier.name,
            evaluation_sha,
            worktree_root,
            &vconfig,
            ctx.store.as_ref(),
            Some(ctx.audit.clone()),
        )
        .await
        {
            Ok(_) => {}
            Err(e) => {
                eprintln!(
                    "{{\"level\":\"error\",\"event\":\"TaskVerifierSpawnFailed\",\
                     \"task_id\":\"{task_id}\",\"gate_type\":\"{}\",\
                     \"error\":\"{e}\"}}",
                    verifier.name,
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// evaluate_pre_spawn — sync DB-touching block of `evaluate_claims`.
// ---------------------------------------------------------------------------

/// Outcome of `evaluate_pre_spawn` — the sync DB-touching pre-Step-5
/// portion of `evaluate_claims`. Sits between `gates::evaluate_claims`
/// (async, runs Steps 1 + 5) and the per-step facades
/// (`witness::lookup`, `claim::evaluate`, `delegation::*`).
#[derive(Debug)]
enum PreSpawnDecision {
    /// All gates satisfied; verifier spawn not needed.
    Pass { delegate_renewal_required: bool },
    /// Claims insufficient; caller turns this into
    /// `GateEvalResult::ClaimInsufficient` and returns to the planner
    /// without spawning verifiers.
    ClaimInsufficient { reason: String },
    /// One or more gates lack a passing witness; caller runs Step 5
    /// (spawn_verifier) for each `missing_gates` entry on the async
    /// runtime.
    NeedsVerifierSpawn { missing_gates: Vec<String> },
}

#[derive(Debug, Clone, Default)]
struct GateRuntimeContext {
    initiative_id: Option<String>,
    workspace_name: Option<String>,
    lane_id: Option<String>,
    task_agent_type: Option<String>,
    environment: Option<String>,
    hook: &'static str,
}

fn read_gate_runtime_context(store: &Store, task_id: &str) -> GateRuntimeContext {
    let mut out = GateRuntimeContext {
        hook: "complete_task",
        ..GateRuntimeContext::default()
    };
    let conn = store.lock_sync();

    let task_row: rusqlite::Result<Option<(String, String)>> = conn
        .query_row(
            &format!(
                "SELECT initiative_id, lane_id FROM {} WHERE task_id = ?1",
                Table::Tasks.as_str()
            ),
            rusqlite::params![task_id],
            |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
        )
        .optional();
    let Some((initiative_id, lane_id)) = task_row.ok().flatten() else {
        return out;
    };
    out.initiative_id = Some(initiative_id.clone());
    out.lane_id = Some(lane_id);

    let plan_bytes = lookup_plan_bytes_for_gate_context(&conn, &initiative_id)
        .ok()
        .flatten();
    let Some(plan_bytes) = plan_bytes else {
        return out;
    };
    let plan_toml = String::from_utf8_lossy(&plan_bytes);
    let Ok(doc) = toml::from_str::<toml::Value>(&plan_toml) else {
        return out;
    };

    out.workspace_name = doc
        .get("workspace")
        .and_then(|v| v.as_table())
        .and_then(|t| t.get("name"))
        .and_then(|v| v.as_str())
        .map(str::to_owned);

    out.environment = doc
        .get("workspace")
        .and_then(|v| v.as_table())
        .and_then(|t| t.get("environment"))
        .and_then(|v| v.as_str())
        .map(str::to_owned);

    out.task_agent_type = doc
        .get("tasks")
        .and_then(|v| v.as_array())
        .and_then(|tasks| {
            tasks
                .iter()
                .find(|entry| entry.get("task_id").and_then(|v| v.as_str()) == Some(task_id))
        })
        .and_then(|entry| entry.get("session_agent_type"))
        .and_then(|v| v.as_str())
        .map(str::to_owned)
        .or_else(|| Some("Executor".to_owned()));

    out
}

fn lookup_plan_bytes_for_gate_context(
    conn: &rusqlite::Connection,
    initiative_id: &str,
) -> rusqlite::Result<Option<Vec<u8>>> {
    let v1: Option<Vec<u8>> = conn
        .query_row(
            &format!(
                "SELECT plan_bytes FROM {} WHERE initiative_id = ?1",
                Table::SignedPlanArtifacts.as_str()
            ),
            rusqlite::params![initiative_id],
            |r| r.get::<_, Vec<u8>>(0),
        )
        .optional()?;
    if v1.is_some() {
        return Ok(v1);
    }

    conn.query_row(
        &format!(
            "SELECT pba.artifact_bytes \
             FROM {init} AS i \
             JOIN {pba} AS pba ON pba.bundle_sha256 = i.plan_bundle_sha256 \
             WHERE i.initiative_id = ?1 AND pba.artifact_name = 'plan.toml' \
             LIMIT 1",
            init = Table::Initiatives.as_str(),
            pba = Table::PlanBundleArtifacts.as_str(),
        ),
        rusqlite::params![initiative_id],
        |r| r.get::<_, Vec<u8>>(0),
    )
    .optional()
}

fn gate_satisfies_claim(gate: &GateEntry, claim: &str) -> bool {
    gate.gate_type == claim
        || gate.claim_type.as_deref() == Some(claim)
        || gate.satisfies.iter().any(|v| v == claim)
}

fn gate_applies(gate: &GateEntry, ctx: &GateRuntimeContext, touched_paths: &[PathBuf]) -> bool {
    let selectors = &gate.selectors;
    selector_matches(&selectors.workspaces, ctx.workspace_name.as_deref())
        && selector_matches(&selectors.lane_ids, ctx.lane_id.as_deref())
        && selector_matches(&selectors.task_agent_types, ctx.task_agent_type.as_deref())
        && selector_matches(&selectors.environments, ctx.environment.as_deref())
        && selector_matches(&selectors.hooks, Some(ctx.hook))
        && path_selector_matches(&selectors.path_globs, touched_paths)
}

fn selector_matches(values: &[String], runtime_value: Option<&str>) -> bool {
    if values.is_empty() {
        return true;
    }
    let Some(runtime_value) = runtime_value else {
        // Fail closed: if the kernel cannot resolve the selector
        // dimension, the gate remains active rather than silently
        // disappearing.
        return true;
    };
    values.iter().any(|v| v == runtime_value)
}

fn path_selector_matches(path_globs: &[String], touched_paths: &[PathBuf]) -> bool {
    if path_globs.is_empty() {
        return true;
    }
    if touched_paths.is_empty() {
        // Empty touched set cannot prove non-applicability, so keep
        // the gate active.
        return true;
    }
    touched_paths.iter().any(|path| {
        let path_str = path.to_string_lossy();
        path_globs
            .iter()
            .any(|glob| policy_lookup::glob_matches(glob, &path_str))
    })
}

/// Synchronous pre-Step-5 portion of `evaluate_claims`. Encapsulates
/// Steps 2 (policy lookup), 2.5 (witness-backed claim auto-derivation),
/// 3 (claim evaluation), and 4 (per-gate witness check +
/// `record_capability_use` on terminal Pass).
///
/// **INV-GATES-EVALUATE-CLAIMS-ASYNC-SAFE-01.** Every Store-touching
/// callee here (`witness::lookup`,
/// `claim::evaluate → delegation::check_capability`,
/// `delegation::record_capability_use`) acquires the store mutex via
/// `Store::lock_sync()`. Calling this fn from a tokio runtime worker
/// would panic; it is therefore **only ever invoked inside
/// `tokio::task::spawn_blocking`** from `evaluate_claims`. The
/// blocking-pool worker is allowed to `blocking_lock` the tokio mutex
/// because it is not driving async tasks. Do NOT call this fn from any
/// async context directly — add a `spawn_blocking` hop instead.
fn evaluate_pre_spawn(
    session_id: &SessionId,
    evaluation_sha: &str,
    task_id: &str,
    touched_paths: &[PathBuf],
    policy: &PolicyBundle,
    store: &Store,
) -> Result<PreSpawnDecision, GateError> {
    // ── Step 2: Policy lookup ─────────────────────────────────────────────
    let required_claims = policy_lookup::required_claims(touched_paths, policy)?;
    let runtime_ctx = read_gate_runtime_context(store, task_id);
    let applicable_gates: Vec<&GateEntry> = policy
        .gates()
        .iter()
        .filter(|gate| gate_applies(gate, &runtime_ctx, touched_paths))
        .collect();

    // Fast path: no claims required and no gates configured.
    if required_claims.is_empty() && applicable_gates.is_empty() {
        return Ok(PreSpawnDecision::Pass {
            delegate_renewal_required: false,
        });
    }

    // ── Step 2.5: Auto-derive claims from witness records ────────────────
    //
    // Gap fix (claims_explained.md §"Current Implementation Gap").
    // The spec assumed the planner would actively populate
    // `submitted_claims` referencing witness blobs. The planner driver
    // hardcodes `submitted_claims: vec![]` and has no mechanism to
    // discover which claims are required or which witnesses have
    // landed. Rather than wiring planner-side claim awareness (which
    // would ask the untrusted agent to self-report), the kernel
    // auto-synthesises claims from its own witness records. For each
    // required claim type that maps to a gate type with a passing
    // witness for this (task_id, evaluation_sha), the kernel injects a
    // synthetic `SubmittedClaim` with `evidence_ref` pointing to the
    // witness blob hash.
    //
    // This is strictly more secure than planner-submitted claims:
    //   - The witness is kernel-verified (verifier token + blob hash)
    //   - The planner cannot fabricate a passing witness
    //   - The kernel already has the data; asking the planner is redundant
    let mut effective_claims: Vec<SubmittedClaim> = Vec::new();

    for req in &required_claims {
        let claim_type_str = req.as_str();
        if claim_type_str == "StrictDefault" {
            continue; // No witness can satisfy StrictDefault — handled by claim::evaluate
        }

        for gate in &applicable_gates {
            if !gate_satisfies_claim(gate, claim_type_str) {
                continue;
            }
            // Check if a passing witness exists for this gate type + task + sha.
            let witness = witness::lookup(evaluation_sha, task_id, &gate.gate_type, None, store)?;
            if let Some(ref rec) = witness {
                if rec.result_class == ResultClass::Pass {
                    effective_claims.push(SubmittedClaim {
                        claim_type: claim_type_str.to_owned(),
                        evidence_ref: Some(rec.blob_sha256.clone()),
                    });
                    break;
                }
            }
        }

        // Compatibility fallback for existing policies whose claim
        // type was already equal to the persisted witness gate_type
        // but whose gate row is absent (or selector-filtered away).
        if !effective_claims
            .iter()
            .any(|claim| claim.claim_type == claim_type_str)
        {
            let witness = witness::lookup(evaluation_sha, task_id, claim_type_str, None, store)?;
            if let Some(ref rec) = witness {
                if rec.result_class == ResultClass::Pass {
                    effective_claims.push(SubmittedClaim {
                        claim_type: claim_type_str.to_owned(),
                        evidence_ref: Some(rec.blob_sha256.clone()),
                    });
                }
            }
        }
    }

    // ── Step 3: Claim evaluation ──────────────────────────────────────────
    let claim_result = claim::evaluate(
        session_id,
        &required_claims,
        &effective_claims,
        touched_paths,
        policy,
        store,
    )?;

    let stale_capabilities: Vec<raxis_types::CapabilityClass>;
    let delegate_renewal_required: bool;

    use claim::ClaimCheckResult;
    match claim_result {
        ClaimCheckResult::Sufficient => {
            stale_capabilities = vec![];
            delegate_renewal_required = false;
        }
        ClaimCheckResult::SufficientStale {
            stale_capabilities: caps,
        } => {
            stale_capabilities = caps;
            delegate_renewal_required = true;
        }
        ClaimCheckResult::Insufficient { failing_claims } => {
            return Ok(PreSpawnDecision::ClaimInsufficient {
                reason: format!("missing submitted claims: {}", failing_claims.join(", ")),
            });
        }
        ClaimCheckResult::DelegationInsufficient { claim_type } => {
            return Ok(PreSpawnDecision::ClaimInsufficient {
                reason: format!("delegation insufficient for claim type: {claim_type}"),
            });
        }
        ClaimCheckResult::ScopeInsufficient {
            claim_type,
            uncovered_paths,
        } => {
            return Ok(PreSpawnDecision::ClaimInsufficient {
                reason: format!(
                    "scope insufficient for {claim_type}: {} path(s) uncovered",
                    uncovered_paths.len()
                ),
            });
        }
    }

    // ── Step 4: Witness check per gate type ───────────────────────────────
    let gate_types: Vec<String> = applicable_gates
        .iter()
        .map(|g| g.gate_type.clone())
        .collect();
    let mut missing_gates: Vec<String> = Vec::new();

    for gate_type in &gate_types {
        let record = witness::lookup(evaluation_sha, task_id, gate_type, None, store)?;
        let satisfied = matches!(record, Some(r) if r.result_class == ResultClass::Pass);
        if !satisfied {
            missing_gates.push(gate_type.clone());
        }
    }

    // All gates satisfied → record_capability_use for each stale cap (sole call site).
    if missing_gates.is_empty() {
        if delegate_renewal_required {
            for cap in &stale_capabilities {
                delegation::record_capability_use(session_id, cap, store)
                    .map_err(|e| GateError::AuthorityError(e.to_string()))?;
            }
        }
        return Ok(PreSpawnDecision::Pass {
            delegate_renewal_required,
        });
    }

    Ok(PreSpawnDecision::NeedsVerifierSpawn { missing_gates })
}

// ---------------------------------------------------------------------------
// Unit tests — witness-backed claim auto-derivation.
//
// These tests exercise the core gap fix: a passing witness record for a
// (task_id, evaluation_sha, gate_type) triple satisfies the corresponding
// claim requirement without the planner submitting anything.
//
// Each test builds an in-memory Store, seeds a witness record (or not),
// and calls the derivation logic extracted into a testable helper.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod auto_claim_tests {
    use raxis_store::Table;
    use raxis_types::SubmittedClaim;

    use crate::gates::policy_lookup::ClaimType;
    use crate::gates::witness;
    use crate::witness_index::{self, ResultClass, WitnessRecord};

    use raxis_crypto::token::sha256_hex;
    use raxis_test_support::mem_store;

    /// Helper: seed an `initiatives` + `tasks` + `verifier_run_tokens`
    /// chain so the FK-enforced `witness_records` insert succeeds, then
    /// insert one witness record. The witness_records table FK-references
    /// both `tasks(task_id)` and `verifier_run_tokens(verifier_run_id)`
    /// (see `crates/store/migrations/0001_v1_baseline_kernel_db.sql`),
    /// and the production `Store::open_with_clock` enables
    /// `PRAGMA foreign_keys = ON`, so an unfettered insert violates
    /// the constraint. Rather than thread the parent-table insert APIs
    /// through every test (the witness logic doesn't exercise them),
    /// we issue minimal raw-SQL INSERTs covering exactly the columns
    /// each schema requires.
    fn seed_witness(
        store: &raxis_store::Store,
        task_id: &str,
        evaluation_sha: &str,
        gate_type: &str,
        result_class: ResultClass,
    ) -> String {
        let blob = b"test-witness-blob";
        let blob_sha = sha256_hex(blob);
        let run_id = format!("run-{}", uuid::Uuid::new_v4().simple());

        let conn = store.lock_sync();

        // Seed the FK-parent rows. We use INSERT OR IGNORE so the same
        // task_id/initiative_id can be re-seeded across test calls
        // without exploding (the test layer is `#[cfg(test)]` only —
        // production code never reaches here).
        let initiative_id = format!("init-{}", task_id);
        let initiatives = Table::Initiatives.as_str();
        conn.execute(
            &format!(
                "INSERT OR IGNORE INTO {initiatives} (initiative_id, state, \
             terminal_criteria_json, plan_artifact_sha256, created_at) \
             VALUES (?, ?, ?, ?, ?)"
            ),
            rusqlite::params![
                initiative_id,
                "ApprovedPlan",
                "{}",           // terminal_criteria_json
                "0".repeat(64), // plan_artifact_sha256
                0_i64,          // created_at
            ],
        )
        .expect("seed_witness initiatives insert");

        let tasks = Table::Tasks.as_str();
        conn.execute(
            &format!(
                "INSERT OR IGNORE INTO {tasks} (task_id, initiative_id, lane_id, state, \
             actor, policy_epoch, admitted_at, transitioned_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
            ),
            rusqlite::params![
                task_id,
                initiative_id,
                "default",
                "Admitted",
                "test-actor",
                0_i64,
                0_i64,
                0_i64,
            ],
        )
        .expect("seed_witness tasks insert");

        let verifier_tokens = Table::VerifierRunTokens.as_str();
        conn.execute(
            &format!(
                "INSERT INTO {verifier_tokens} (verifier_run_id, task_id, gate_type, \
             evaluation_sha, token_hash, issued_at, expires_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?)"
            ),
            rusqlite::params![
                run_id,
                task_id,
                gate_type,
                evaluation_sha,
                "0".repeat(64),
                0_i64,
                i64::MAX,
            ],
        )
        .expect("seed_witness verifier_run_tokens insert");

        let record = WitnessRecord {
            verifier_run_id: run_id.clone(),
            evaluation_sha: evaluation_sha.to_owned(),
            task_id: task_id.to_owned(),
            gate_type: gate_type.to_owned(),
            result_class,
            blob_sha256: blob_sha.clone(),
            blob_path: blob_sha.clone(),
            recorded_at: 0,
        };

        witness_index::insert_witness_index_in_tx(&conn, &record, raxis_types::unix_now_secs())
            .expect("seed_witness insert");

        blob_sha
    }

    /// Reproduce the auto-derivation logic from evaluate_claims Step 2.5.
    /// This is a focused test helper that mirrors the kernel's runtime path
    /// without needing the full HandlerContext/PolicyBundle/async machinery.
    ///
    /// Planner-submitted claims are intentionally discarded (matches
    /// production code). The `_submitted` parameter is kept in the
    /// signature so callers can document what the planner would have
    /// sent, but it is never read.
    fn auto_derive_claims(
        required: &[ClaimType],
        _submitted: &[SubmittedClaim],
        task_id: &str,
        evaluation_sha: &str,
        store: &raxis_store::Store,
    ) -> Vec<SubmittedClaim> {
        // Planner claims discarded — kernel is the sole claim source.
        let mut effective: Vec<SubmittedClaim> = Vec::new();

        for req in required {
            let claim_type_str = req.as_str();
            if claim_type_str == "StrictDefault" {
                continue;
            }

            let w = witness::lookup(evaluation_sha, task_id, claim_type_str, None, store)
                .expect("witness lookup");

            if let Some(ref rec) = w {
                if rec.result_class == ResultClass::Pass {
                    effective.push(SubmittedClaim {
                        claim_type: claim_type_str.to_owned(),
                        evidence_ref: Some(rec.blob_sha256.clone()),
                    });
                }
            }
        }

        effective
    }

    #[test]
    fn passing_witness_auto_derives_claim() {
        let store = mem_store();
        let task_id = "task-1";
        let eval_sha = "abcd1234abcd1234abcd1234abcd1234abcd1234";

        let blob_sha = seed_witness(&store, task_id, eval_sha, "TestSuite", ResultClass::Pass);

        let required = vec![ClaimType::Named("TestSuite".to_owned())];
        let submitted: Vec<SubmittedClaim> = vec![];

        let effective = auto_derive_claims(&required, &submitted, task_id, eval_sha, &store);

        assert_eq!(effective.len(), 1, "should auto-derive exactly one claim");
        assert_eq!(effective[0].claim_type, "TestSuite");
        assert_eq!(
            effective[0].evidence_ref.as_deref(),
            Some(blob_sha.as_str())
        );
    }

    #[test]
    fn failing_witness_does_not_auto_derive() {
        let store = mem_store();
        let task_id = "task-2";
        let eval_sha = "beef1234beef1234beef1234beef1234beef1234";

        seed_witness(&store, task_id, eval_sha, "TestSuite", ResultClass::Fail);

        let required = vec![ClaimType::Named("TestSuite".to_owned())];
        let submitted: Vec<SubmittedClaim> = vec![];

        let effective = auto_derive_claims(&required, &submitted, task_id, eval_sha, &store);

        assert!(
            effective.is_empty(),
            "failing witness must not produce a claim"
        );
    }

    #[test]
    fn inconclusive_witness_does_not_auto_derive() {
        let store = mem_store();
        let task_id = "task-3";
        let eval_sha = "dead1234dead1234dead1234dead1234dead1234";

        seed_witness(
            &store,
            task_id,
            eval_sha,
            "TestSuite",
            ResultClass::Inconclusive,
        );

        let required = vec![ClaimType::Named("TestSuite".to_owned())];
        let submitted: Vec<SubmittedClaim> = vec![];

        let effective = auto_derive_claims(&required, &submitted, task_id, eval_sha, &store);

        assert!(
            effective.is_empty(),
            "inconclusive witness must not produce a claim"
        );
    }

    #[test]
    fn planner_submitted_claims_are_discarded() {
        let store = mem_store();
        let task_id = "task-4";
        let eval_sha = "cafe1234cafe1234cafe1234cafe1234cafe1234";

        // Auto-derivable: TestSuite has a Pass witness
        seed_witness(&store, task_id, eval_sha, "TestSuite", ResultClass::Pass);

        let required = vec![
            ClaimType::Named("TestSuite".to_owned()),
            ClaimType::Named("WriteCode".to_owned()),
        ];

        // Planner explicitly submitted WriteCode — kernel must IGNORE it
        let submitted = vec![SubmittedClaim {
            claim_type: "WriteCode".to_owned(),
            evidence_ref: None,
        }];

        let effective = auto_derive_claims(&required, &submitted, task_id, eval_sha, &store);

        // Only TestSuite should appear (auto-derived from witness).
        // WriteCode is NOT present — no witness exists for it, and
        // the planner's assertion is discarded.
        assert_eq!(
            effective.len(),
            1,
            "only witness-backed claims should appear"
        );
        assert_eq!(effective[0].claim_type, "TestSuite");
        assert!(
            !effective.iter().any(|c| c.claim_type == "WriteCode"),
            "planner-submitted WriteCode must be discarded"
        );
    }

    #[test]
    fn planner_claim_ignored_kernel_derives_from_witness() {
        let store = mem_store();
        let task_id = "task-5";
        let eval_sha = "f00d1234f00d1234f00d1234f00d1234f00d1234";

        let blob_sha = seed_witness(&store, task_id, eval_sha, "TestSuite", ResultClass::Pass);

        let required = vec![ClaimType::Named("TestSuite".to_owned())];

        // Planner submitted TestSuite with a bogus evidence_ref —
        // kernel must ignore it and use the real witness blob hash.
        let submitted = vec![SubmittedClaim {
            claim_type: "TestSuite".to_owned(),
            evidence_ref: Some("planner-fabricated-ref".to_owned()),
        }];

        let effective = auto_derive_claims(&required, &submitted, task_id, eval_sha, &store);

        assert_eq!(effective.len(), 1);
        assert_eq!(
            effective[0].evidence_ref.as_deref(),
            Some(blob_sha.as_str()),
            "evidence_ref must come from the kernel's witness, not the planner's fabrication"
        );
    }

    #[test]
    fn strict_default_never_auto_derived() {
        let store = mem_store();
        let task_id = "task-6";
        let eval_sha = "1111111111111111111111111111111111111111";

        // Even if someone made a gate named "StrictDefault" (they shouldn't)
        seed_witness(
            &store,
            task_id,
            eval_sha,
            "StrictDefault",
            ResultClass::Pass,
        );

        let required = vec![ClaimType::StrictDefault];
        let submitted: Vec<SubmittedClaim> = vec![];

        let effective = auto_derive_claims(&required, &submitted, task_id, eval_sha, &store);

        assert!(
            effective.is_empty(),
            "StrictDefault must never be auto-derived"
        );
    }

    #[test]
    fn no_witness_at_all_leaves_claims_empty() {
        let store = mem_store();
        let task_id = "task-7";
        let eval_sha = "2222222222222222222222222222222222222222";

        // No witness seeded — table is empty for this task
        let required = vec![ClaimType::Named("TestSuite".to_owned())];
        let submitted: Vec<SubmittedClaim> = vec![];

        let effective = auto_derive_claims(&required, &submitted, task_id, eval_sha, &store);

        assert!(effective.is_empty(), "no witness → no auto-derived claim");
    }

    #[test]
    fn wrong_evaluation_sha_does_not_auto_derive() {
        let store = mem_store();
        let task_id = "task-8";

        // Witness exists for a DIFFERENT evaluation_sha
        seed_witness(
            &store,
            task_id,
            "old_sha_old_sha_old_sha_old_sha_old_sha_",
            "TestSuite",
            ResultClass::Pass,
        );

        let required = vec![ClaimType::Named("TestSuite".to_owned())];
        let submitted: Vec<SubmittedClaim> = vec![];

        // Query against a different sha
        let effective = auto_derive_claims(
            &required,
            &submitted,
            task_id,
            "new_sha_new_sha_new_sha_new_sha_new_sha_",
            &store,
        );

        assert!(
            effective.is_empty(),
            "witness for different SHA must not satisfy this intent"
        );
    }
}

// ---------------------------------------------------------------------------
// Async-runtime safety witnesses — INV-GATES-EVALUATE-CLAIMS-ASYNC-SAFE-01.
// ---------------------------------------------------------------------------
//
// iter63 realistic_session_lifecycle crashed the kernel daemon on the
// first `IntegrationMerge` planner intent with:
//
//   thread 'tokio-rt-worker' panicked at crates/store/src/db.rs:125:
//   Cannot block the current thread from within a runtime.
//      ...
//      witness_index::lookup
//      gates::witness::lookup
//      gates::evaluate_claims::{{closure}}
//      handlers::intent::handle_inner::{{closure}}
//
// Root cause: `evaluate_claims` (async, runs on a tokio runtime worker)
// inlined sync DB-touching steps — `witness::lookup` (Step 2.5 + Step
// 4), `claim::evaluate` → `delegation::check_capability` (Step 3),
// `delegation::record_capability_use` (Step 4 on terminal Pass) — each
// of which calls `Store::lock_sync()` →
// `tokio::sync::Mutex::blocking_lock`. `blocking_lock` panics by
// design when the calling thread is a runtime worker.
//
// Fix: extracted Steps 2/2.5/3/4 into `evaluate_pre_spawn` and hop
// the entire block onto the blocking pool via a single
// `tokio::task::spawn_blocking` (matches the Phase-A pattern in
// `handlers::intent::handle_inner`). Step 5 (verifier spawn) stays
// async because `tokio::process::Command` requires the runtime.
//
// The tests below pin the invariant at two layers:
//
//   1. `evaluate_pre_spawn_direct_call_from_runtime_panics` —
//      `#[should_panic]` test that reproduces the iter63 panic shape
//      at the helper boundary. If a future refactor merges
//      `evaluate_pre_spawn` back into `evaluate_claims` without
//      preserving the `spawn_blocking` hop, this test would go green
//      (silently — it asserts the panic) but the production code
//      would crash; we therefore pair it with #2 which fires
//      green-then-red if the wrap is dropped.
//
//   2. `evaluate_pre_spawn_via_spawn_blocking_is_async_safe` —
//      drives `evaluate_pre_spawn` from a `#[tokio::test]` runtime
//      via the canonical `spawn_blocking` hop and asserts the call
//      returns Ok (no panic). This is the positive regression
//      witness for the invariant.

#[cfg(test)]
mod async_runtime_safety {
    use std::path::PathBuf;
    use std::sync::Arc;

    use raxis_policy::PolicyBundle;
    use raxis_store::Store;
    use raxis_test_support::mem_store;
    use raxis_types::SessionId;

    use super::{evaluate_pre_spawn, PreSpawnDecision};

    /// Build a minimal valid `PolicyBundle` with one `[[gates]]` entry
    /// (`TestGate`). The gate forces `evaluate_pre_spawn` to traverse
    /// Step 4 (per-gate witness lookup) — the exact code site whose
    /// `Store::lock_sync` call panicked in iter63 when reached from
    /// the async runtime worker.
    ///
    /// We render the genesis-shaped policy via
    /// `raxis_genesis_tools::render_genesis_policy_toml` (so every
    /// `[meta]`/`[authority]`/`[sessions]` invariant the validator
    /// enforces is satisfied) and append a `[[gates]]` table by
    /// string concatenation; the TOML parser is tolerant of trailing
    /// tables because `[[gates]]` is `#[serde(default)]` in
    /// `raxis_policy::RawPolicy`.
    fn policy_with_one_gate(allowed_worktree_root: &std::path::Path) -> Arc<PolicyBundle> {
        let key = raxis_test_support::ephemeral_signing_key([0x42u8; 32]);
        let pk = raxis_test_support::pubkey_hex(&key);
        let fp = raxis_genesis_tools::pubkey_fingerprint(&hex::decode(&pk).unwrap());
        let cert = raxis_test_support::ephemeral_cert_with_key(
            &key,
            raxis_test_support::CertOpts {
                display_name: "gates-async-safety".to_owned(),
                permitted_ops: raxis_genesis_tools::PERMITTED_OPS
                    .iter()
                    .map(|s| (*s).to_owned())
                    .collect(),
                ..raxis_test_support::CertOpts::default()
            },
        );
        let root_str = allowed_worktree_root.display().to_string();
        let mut policy_toml = raxis_genesis_tools::render_genesis_policy_toml(
            raxis_genesis_tools::GenesisPolicyInputs {
                authority_pubkey_hex:
                    "0000000000000000000000000000000000000000000000000000000000000000",
                quality_pubkey_hex:
                    "1111111111111111111111111111111111111111111111111111111111111111",
                operator_pubkey_hex: &pk,
                operator_fingerprint: &fp,
                signed_at_unix_secs: 1_700_000_000,
                allowed_worktree_roots: &[root_str.as_str()],
                operator_cert: &cert,
            },
        );
        policy_toml.push_str(
            "
[[gates]]
             gate_type        = \"TestGate\"
             verifier_command = \"/usr/local/bin/raxis-verify-testgate\"
             max_wall_seconds = 60
             max_memory_bytes = 268435456
             network_allowed  = false
",
        );

        let tmp = tempfile::NamedTempFile::new().expect("tempfile");
        std::fs::write(tmp.path(), &policy_toml).expect("write policy");
        let (bundle, _bytes, _sha) =
            raxis_policy::load_policy(tmp.path()).expect("load_policy on async-safety policy");
        Arc::new(bundle)
    }

    /// **INV-GATES-EVALUATE-CLAIMS-ASYNC-SAFE-01** witness (positive).
    ///
    /// Drives `evaluate_pre_spawn` from a `#[tokio::test]` async
    /// runtime via the canonical `tokio::task::spawn_blocking` hop —
    /// the production wrapping that `evaluate_claims` now applies.
    /// Asserts the call returns `Ok(NeedsVerifierSpawn)` (the seeded
    /// policy has one `TestGate` and the in-memory store has no
    /// witness rows ⇒ the gate is missing ⇒ the caller would spawn
    /// a verifier in Step 5).
    ///
    /// Before the fix: `evaluate_claims` inlined this body and
    /// panicked at the first `witness::lookup → Store::lock_sync`
    /// site. After the fix: `evaluate_claims` wraps this body in
    /// `spawn_blocking`, which is exactly what this test mimics.
    #[tokio::test]
    async fn evaluate_pre_spawn_via_spawn_blocking_is_async_safe() {
        let tmp_root = tempfile::tempdir().expect("tempdir");
        let policy = policy_with_one_gate(tmp_root.path());
        let store = Arc::new(mem_store());

        let session_id = SessionId::new_v4();
        let evaluation_sha = "abcdef0123456789abcdef0123456789abcdef01".to_owned();
        let task_id = "task-gates-async-safety".to_owned();
        let touched_paths: Vec<PathBuf> = vec![tmp_root.path().join("src/lib.rs")];

        let decision = tokio::task::spawn_blocking({
            let policy = Arc::clone(&policy);
            let store = Arc::clone(&store);
            move || {
                evaluate_pre_spawn(
                    &session_id,
                    &evaluation_sha,
                    &task_id,
                    &touched_paths,
                    &policy,
                    &store,
                )
            }
        })
        .await
        .expect("spawn_blocking join")
        .expect("evaluate_pre_spawn must not error");

        match decision {
            PreSpawnDecision::NeedsVerifierSpawn { missing_gates } => {
                assert_eq!(
                    missing_gates,
                    vec!["TestGate".to_owned()],
                    "the single seeded gate has no witness ⇒ it must be reported missing",
                );
            }
            other => panic!(
                "expected NeedsVerifierSpawn (no witness seeded for TestGate); got {other:?}",
            ),
        }
    }

    /// **INV-GATES-EVALUATE-CLAIMS-ASYNC-SAFE-01** witness (end-to-end).
    ///
    /// Drives the public async `gates::evaluate_claims` from a
    /// `#[tokio::test]` runtime worker — the exact call shape the
    /// iter63 stack trace showed crashing
    /// (`handlers::intent::handle_inner::{{closure}}` →
    /// `gates::evaluate_claims::{{closure}}` → …). Constructs a
    /// minimal `HandlerContext` with the cfg-gated test builders so
    /// the full `evaluate_claims` body executes (Step 1 break-glass
    /// → `spawn_blocking { Steps 2 + 2.5 + 3 + 4 }` → Step 5 verifier
    /// spawn). Asserts the call returns `Ok(_)` instead of
    /// propagating the `Cannot block the current thread from within
    /// a runtime` panic.
    ///
    /// The seeded policy contains a single `[[gates]]` entry whose
    /// `verifier_command` points at a non-existent binary; Step 5
    /// will attempt to spawn it, fail with `SpawnFailed`, log the
    /// non-fatal `VerifierSpawnFailed` event, and return
    /// `PendingWitness { missing_gates: ["TestGate"] }`. That outcome
    /// is the success case for this test — what we are pinning is
    /// "no panic", not "verifier spawn succeeds".
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn evaluate_claims_end_to_end_from_runtime_is_async_safe() {
        use std::path::Path;

        use arc_swap::ArcSwap;
        use raxis_audit_tools::AuditSink;
        use raxis_test_support::FakeAuditSink;

        use crate::initiatives::PlanRegistry;
        use crate::ipc::context;

        let data_dir = tempfile::tempdir().expect("data tempdir");
        let worktree_root = tempfile::tempdir().expect("worktree tempdir");

        let policy = policy_with_one_gate(worktree_root.path());
        let store: Arc<Store> = Arc::new(mem_store());
        let audit: Arc<dyn AuditSink> = Arc::new(FakeAuditSink::new());
        let registry = Arc::new(crate::authority::keys::KeyRegistry::stub_for_tests());
        let plan_registry = Arc::new(PlanRegistry::new());
        let credentials =
            context::build_default_test_credentials(data_dir.path(), Arc::clone(&audit));
        let isolation = context::build_fail_closed_test_isolation();
        let orchestrator_spawn = context::build_test_orchestrator_spawn();
        let executor_spawn = context::build_test_executor_spawn();
        let domain = context::build_default_test_domain(data_dir.path());

        let ctx = Arc::new(context::HandlerContext::new(
            Arc::new(ArcSwap::new(Arc::clone(&policy))),
            registry,
            store,
            audit,
            data_dir.path().to_path_buf(),
            plan_registry,
            Arc::new(crate::gateway::client::GatewayClient::new()),
            Arc::new(crate::prompt::EpochBinding::new()),
            credentials,
            isolation,
            orchestrator_spawn,
            executor_spawn,
            domain,
        ));

        let session_id = SessionId::new_v4();
        let evaluation_sha = "cafe0123cafe0123cafe0123cafe0123cafe0123";
        let task_id = "task-evaluate-claims-async-safety";
        let touched_paths: Vec<PathBuf> = vec![worktree_root.path().join("src/lib.rs")];

        let result = super::evaluate_claims(
            &session_id,
            evaluation_sha,
            task_id,
            &touched_paths,
            &[],
            Path::new(worktree_root.path()),
            &ctx,
        )
        .await;

        // The point of the test: `evaluate_claims` returned at all.
        // Pre-fix, the call would have unwound via the iter63
        // panic ("Cannot block the current thread from within a
        // runtime") instead of reaching this assertion.
        let outcome = result.expect("evaluate_claims must return Ok, not panic");
        match outcome {
            super::GateEvalResult::PendingWitness { missing_gates } => {
                assert_eq!(
                    missing_gates,
                    vec!["TestGate".to_owned()],
                    "no witness seeded ⇒ TestGate must be reported missing",
                );
            }
            super::GateEvalResult::Pass { .. } => {
                // Acceptable if the empty path-rules table makes
                // `required_claims` empty AND the spawn_blocking hop
                // still succeeded; the invariant under test is "no
                // panic", not the specific gate-state semantics.
            }
            other => panic!("expected PendingWitness or Pass from evaluate_claims; got {other:?}",),
        }
    }

    /// **INV-GATES-VERIFY-AFTER-GATES-PENDING-COMMIT-01.**
    ///
    /// Initial intent admission must not spawn mechanical verifiers while
    /// the task row is still durably `Admitted`. A fast verifier can run
    /// to completion before Phase C commits `Admitted → GatesPending`;
    /// the witness handler then rejects the otherwise-valid witness as
    /// `TaskNotGatesPending`, stranding the synthetic integration task.
    ///
    /// This pins the new split: the deferred entry point reports missing
    /// gates but writes no verifier token, proving no verifier process was
    /// launched before the caller has a chance to commit the FSM state.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn deferred_gate_eval_reports_missing_without_spawning_verifier_token() {
        use std::path::Path;

        use arc_swap::ArcSwap;
        use raxis_audit_tools::AuditSink;
        use raxis_store::Table;
        use raxis_test_support::FakeAuditSink;

        use crate::initiatives::PlanRegistry;
        use crate::ipc::context;

        let data_dir = tempfile::tempdir().expect("data tempdir");
        let worktree_root = tempfile::tempdir().expect("worktree tempdir");

        let policy = policy_with_one_gate(worktree_root.path());
        let store: Arc<Store> = Arc::new(mem_store());
        let audit: Arc<dyn AuditSink> = Arc::new(FakeAuditSink::new());
        let registry = Arc::new(crate::authority::keys::KeyRegistry::stub_for_tests());
        let plan_registry = Arc::new(PlanRegistry::new());
        let credentials =
            context::build_default_test_credentials(data_dir.path(), Arc::clone(&audit));
        let isolation = context::build_fail_closed_test_isolation();
        let orchestrator_spawn = context::build_test_orchestrator_spawn();
        let executor_spawn = context::build_test_executor_spawn();
        let domain = context::build_default_test_domain(data_dir.path());

        let ctx = Arc::new(context::HandlerContext::new(
            Arc::new(ArcSwap::new(Arc::clone(&policy))),
            registry,
            Arc::clone(&store),
            audit,
            data_dir.path().to_path_buf(),
            plan_registry,
            Arc::new(crate::gateway::client::GatewayClient::new()),
            Arc::new(crate::prompt::EpochBinding::new()),
            credentials,
            isolation,
            orchestrator_spawn,
            executor_spawn,
            domain,
        ));

        let session_id = SessionId::new_v4();
        let evaluation_sha = "face0123face0123face0123face0123face0123";
        let task_id = "task-deferred-gate-spawn";
        let touched_paths: Vec<PathBuf> = vec![worktree_root.path().join("src/lib.rs")];

        let result = super::evaluate_claims_defer_verifier_spawn(
            &session_id,
            evaluation_sha,
            task_id,
            &touched_paths,
            Path::new(worktree_root.path()),
            &ctx,
        )
        .await
        .expect("deferred gate evaluation must return");

        match result {
            super::GateEvalResult::PendingWitness { missing_gates } => {
                assert_eq!(missing_gates, vec!["TestGate".to_owned()]);
            }
            other => panic!("expected PendingWitness from deferred gate eval, got {other:?}"),
        }

        let token_rows = tokio::task::spawn_blocking(move || {
            let conn = store.lock_sync();
            conn.query_row(
                &format!("SELECT COUNT(*) FROM {}", Table::VerifierRunTokens.as_str()),
                [],
                |r| r.get::<_, i64>(0),
            )
            .expect("count verifier_run_tokens")
        })
        .await
        .expect("count join");

        assert_eq!(
            token_rows, 0,
            "deferred gate eval must not mint verifier tokens before GatesPending commits"
        );
    }

    /// **INV-GATES-EVALUATE-CLAIMS-ASYNC-SAFE-01** witness (negative).
    ///
    /// Reproduces the iter63 panic shape at the
    /// `evaluate_pre_spawn` boundary: invoking the helper **directly**
    /// from a tokio runtime worker (no `spawn_blocking` hop) hits
    /// `witness::lookup → witness_index::lookup → Store::lock_sync →
    /// blocking_lock` and panics with "Cannot block the current
    /// thread from within a runtime". This test pins the bug shape
    /// so a future refactor that removes the `spawn_blocking` wrap
    /// in `evaluate_claims` cannot quietly land — the production
    /// invariant is "all sync DB work goes through `spawn_blocking`",
    /// and this `#[should_panic]` documents exactly why.
    #[tokio::test]
    #[should_panic(expected = "Cannot block the current thread from within a runtime")]
    async fn evaluate_pre_spawn_direct_call_from_runtime_panics() {
        let tmp_root = tempfile::tempdir().expect("tempdir");
        let policy = policy_with_one_gate(tmp_root.path());
        let store: Arc<Store> = Arc::new(mem_store());

        let session_id = SessionId::new_v4();
        let evaluation_sha = "abcdef0123456789abcdef0123456789abcdef01".to_owned();
        let task_id = "task-gates-async-unsafe".to_owned();
        let touched_paths: Vec<PathBuf> = vec![tmp_root.path().join("src/lib.rs")];

        // Direct call, no spawn_blocking — this is the iter63 call shape
        // that crashed the kernel daemon. The `let _ =` binding is
        // intentional: the panic fires inside `evaluate_pre_spawn`
        // before the call site can observe the return value.
        let _ = evaluate_pre_spawn(
            &session_id,
            &evaluation_sha,
            &task_id,
            &touched_paths,
            &policy,
            &store,
        );
    }
}

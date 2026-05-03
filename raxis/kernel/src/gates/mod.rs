// raxis-kernel::gates — Gate evaluation pipeline.
//
// Normative reference: kernel-core.md §2.3 `src/gates/mod.rs`.
//
// Single public entry point: evaluate_claims().
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
pub mod witness;

use std::path::{Path, PathBuf};

use raxis_store::Store;
use raxis_types::{SessionId, SubmittedClaim};

use crate::authority::delegation;
use crate::witness_index::ResultClass;
use crate::ipc::context::HandlerContext;

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

    /// One or more gate types are unsatisfied — verifiers are spawned/pending.
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
    session_id:       &SessionId,
    evaluation_sha:   &str,
    task_id:          &str,
    touched_paths:    &[PathBuf],
    submitted_claims: &[SubmittedClaim],
    worktree_root:    &Path,
    ctx:              &HandlerContext,
) -> Result<GateEvalResult, GateError> {
    // Pin one snapshot of the policy bundle for the duration of this
    // gate evaluation. INV-POLICY-01: an in-process epoch advance must
    // not tear an in-flight enforcement decision (kernel-store.md
    // §INV-POLICY-01); binding to a single `Arc<PolicyBundle>` keeps
    // every claim/witness/proof check on the same epoch.
    let policy_snapshot = ctx.policy.load_full();
    let policy: &raxis_policy::PolicyBundle = &policy_snapshot;
    let store  = ctx.store.as_ref();

    // ── Step 1: Break-glass ────────────────────────────────────────────────
    // v1 Tier 4 not yet implemented — breakglass always Inactive.
    let breakglass_active = false;
    if breakglass_active {
        return Ok(GateEvalResult::BreakglassPass { activation_id: String::new() });
    }

    // ── Step 2: Policy lookup ─────────────────────────────────────────────
    let required_claims = policy_lookup::required_claims(touched_paths, policy)?;

    // Fast path: no claims required and no gates configured.
    if required_claims.is_empty() && policy.gates().is_empty() {
        return Ok(GateEvalResult::Pass { delegate_renewal_required: false });
    }

    // ── Step 3: Claim evaluation ──────────────────────────────────────────
    let claim_result = claim::evaluate(
        session_id,
        &required_claims,
        submitted_claims,
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
        ClaimCheckResult::SufficientStale { stale_capabilities: caps } => {
            stale_capabilities = caps;
            delegate_renewal_required = true;
        }
        ClaimCheckResult::Insufficient { failing_claims } => {
            return Ok(GateEvalResult::ClaimInsufficient {
                reason: format!("missing submitted claims: {}", failing_claims.join(", ")),
            });
        }
        ClaimCheckResult::DelegationInsufficient { claim_type } => {
            return Ok(GateEvalResult::ClaimInsufficient {
                reason: format!("delegation insufficient for claim type: {claim_type}"),
            });
        }
        ClaimCheckResult::ScopeInsufficient { claim_type, uncovered_paths } => {
            return Ok(GateEvalResult::ClaimInsufficient {
                reason: format!(
                    "scope insufficient for {claim_type}: {} path(s) uncovered",
                    uncovered_paths.len()
                ),
            });
        }
    }

    // ── Step 4: Witness check per gate type ───────────────────────────────
    let gate_types: Vec<String> = policy.gates().iter().map(|g| g.gate_type.clone()).collect();
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
        return Ok(GateEvalResult::Pass { delegate_renewal_required });
    }

    // ── Step 5: Spawn verifiers for missing gates ─────────────────────────
    //
    // Per kernel-core.md §2.3 `verifier_runner.rs`, spawn errors are
    // intentionally non-fatal at this point — the missing gate stays in
    // `missing_gates` and the planner is told to wait. But "non-fatal"
    // does NOT mean "silently swallowed": each error variant carries
    // different operational meaning, and operators need to see them in
    // structured logs so a permanently-broken verifier binary or an
    // exhausted concurrent-verifier cap surfaces at telemetry time
    // instead of being invisible.
    //
    //   - `Ok(_)`                    → verifier spawned, run_id reserved.
    //   - `Err(VerifierCapExceeded)` → backpressure, expected under load.
    //   - `Err(SpawnFailed)`         → the verifier binary is missing or
    //                                  unexecutable — operator action.
    //   - `Err(AuthorityError)`      → token issuance failed — likely a
    //                                  store-level fault.
    //   - `Err(_other)`              → defensive catch-all.
    for gate_type in &missing_gates {
        let vconfig = verifier_runner::VerifierConfig::from_policy(
            policy,
            gate_type,
            &ctx.data_dir,
        );
        let Some(vconfig) = vconfig else { continue };

        match verifier_runner::spawn_verifier(
            task_id,
            gate_type,
            evaluation_sha,
            worktree_root,
            &vconfig,
            store,
        ).await {
            Ok(_) => {}
            Err(GateError::VerifierCapExceeded { .. }) => {
                eprintln!(
                    "{{\"level\":\"info\",\"event\":\"VerifierCapExceeded\",\
                     \"task_id\":\"{task_id}\",\"gate_type\":\"{gate_type}\"}}",
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

    Ok(GateEvalResult::PendingWitness { missing_gates })
}

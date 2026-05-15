// raxis-kernel::gates::claim — Per-claim delegation + scope check.
//
// Normative reference: kernel-core.md §2.3 `src/gates/claim.rs`.
//
// Evaluates whether a session's submitted claims are sufficient for the
// required set, given its delegation status. Pure function — no writes.
// record_capability_use is NOT called here; it is called exclusively by
// gates/mod.rs step 4 after all gate types are satisfied.
//
// Boundary rule: this file uses authority (delegation check) and
// policy_lookup (scope check) facades only. No SQL directly.

use std::path::PathBuf;

use raxis_policy::PolicyBundle;
use raxis_store::Store;
use raxis_types::{CapabilityClass, DelegationStatus, SessionId, SubmittedClaim};

use super::policy_lookup::{check_claim_scope, ClaimType};
use super::GateError;
use crate::authority::delegation;

// ---------------------------------------------------------------------------
// ClaimCheckResult — matches spec §2.3 claim.rs variant mapping exactly.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub enum ClaimCheckResult {
    /// All required claims satisfied, no stale delegations.
    Sufficient,

    /// All required claims satisfied, but one or more delegations were StaleOnNextUse.
    /// `stale_capabilities` carries the CapabilityClass values for each stale delegation.
    /// gates/mod.rs calls record_capability_use for each on terminal Pass.
    SufficientStale {
        stale_capabilities: Vec<CapabilityClass>,
    },

    /// One or more required claim types have no matching submitted claim.
    /// Collected across all claim types (useful for planner diagnostics).
    Insufficient { failing_claims: Vec<String> },

    /// A required claim type's delegation is NotGranted, Expired, or RenewalRequired.
    /// Evaluation stops at the first delegation failure (fail-first per spec §2.3 step A).
    DelegationInsufficient { claim_type: String },

    /// A submitted claim's scope does not cover all touched paths (first encountered).
    ScopeInsufficient {
        claim_type: String,
        uncovered_paths: Vec<PathBuf>,
    },
}

// ---------------------------------------------------------------------------
// evaluate
// ---------------------------------------------------------------------------

/// Evaluate whether the session's submitted claims are sufficient.
///
/// Takes `raxis_types::SubmittedClaim` directly (the canonical wire type).
///
/// Steps per spec (kernel-core.md §2.3 `claim.rs`):
///   A. Delegation check via `authority::check_capability` (pure read).
///      - NotGranted / Expired / RenewalRequired → DelegationInsufficient (fail-first, stop).
///      - StaleOnNextUse → record in stale_capabilities, mark any_stale = true.
///      - Active → proceed.
///   B. Find matching submitted claim by claim_type string.
///      - None found → record Insufficient for this type (collected).
///   C. Scope check via policy_lookup::check_claim_scope.
///      - Fails → ScopeInsufficient (first encountered, stops further scope checks for this type).
///
/// Failure precedence: DelegationInsufficient > ScopeInsufficient > Insufficient.
pub fn evaluate(
    session_id: &SessionId,
    required: &[ClaimType],
    submitted: &[SubmittedClaim],
    touched_paths: &[PathBuf],
    policy: &PolicyBundle,
    store: &Store,
) -> Result<ClaimCheckResult, GateError> {
    let mut failing_claims: Vec<String> = Vec::new();
    let mut scope_failure: Option<(String, Vec<PathBuf>)> = None;
    let mut stale_capabilities: Vec<CapabilityClass> = Vec::new();
    let mut any_stale = false;

    for req in required {
        let claim_type_str = match req {
            // StrictDefault: path matched no policy rule under default-deny.
            // No claim can satisfy this — treat as DelegationInsufficient (hard stop).
            ClaimType::StrictDefault => {
                return Ok(ClaimCheckResult::DelegationInsufficient {
                    claim_type: "StrictDefault".to_owned(),
                });
            }
            ClaimType::Named(s) => s.clone(),
        };

        // Step A: delegation check (pure read, no write).
        let capability = CapabilityClass::parse_persisted(&claim_type_str);

        // If the claim type doesn't map to a CapabilityClass, no delegation needed.
        if let Some(cap) = capability {
            match delegation::check_capability(session_id, &cap, store)
                .map_err(|e| GateError::AuthorityError(e.to_string()))?
            {
                DelegationStatus::Active => {
                    // Proceed to B.
                }
                DelegationStatus::StaleOnNextUse => {
                    // Grace use — collect for record_capability_use after full pass.
                    any_stale = true;
                    stale_capabilities.push(cap);
                    // Proceed to B.
                }
                // Hard delegation failures — fail-first, stop evaluating all remaining claims.
                DelegationStatus::NotGranted
                | DelegationStatus::Expired
                | DelegationStatus::RenewalRequired => {
                    return Ok(ClaimCheckResult::DelegationInsufficient {
                        claim_type: claim_type_str,
                    });
                }
            }
        }

        // Step B: find matching submitted claim by claim_type.
        let submitted_claim = match submitted.iter().find(|s| s.claim_type == claim_type_str) {
            Some(c) => c,
            None => {
                failing_claims.push(claim_type_str);
                continue;
            }
        };

        // Step C: scope superset check (first failure wins, does not stop collection
        // of B failures for other claims).
        if scope_failure.is_none() {
            let uncovered = check_claim_scope(submitted_claim, touched_paths, policy);
            if !uncovered.is_empty() {
                scope_failure = Some((claim_type_str, uncovered));
            }
        }
    }

    // Apply failure precedence: Delegation (caught above) > Scope > Insufficient.
    if let Some((ct, uncovered)) = scope_failure {
        return Ok(ClaimCheckResult::ScopeInsufficient {
            claim_type: ct,
            uncovered_paths: uncovered,
        });
    }
    if !failing_claims.is_empty() {
        return Ok(ClaimCheckResult::Insufficient { failing_claims });
    }
    if any_stale {
        return Ok(ClaimCheckResult::SufficientStale { stale_capabilities });
    }
    Ok(ClaimCheckResult::Sufficient)
}

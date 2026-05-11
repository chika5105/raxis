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
    // Intentionally unused — see Step 2.5 below. The kernel auto-
    // derives claims from its own witness records; planner-submitted
    // claims are discarded as a security property (the untrusted
    // agent has zero influence on the claim pipeline). The parameter
    // is kept on the signature so the caller's wire shape does not
    // bifurcate between the kernel-auto-derived path and a
    // hypothetical V3 mode where the planner regains submission
    // rights — a contract change of that scope deserves a real PR
    // rather than a silent restoration.
    _submitted_claims_discarded: &[SubmittedClaim],
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
    // V1 Tier 4 — emergency operator override (kernel-core.md §2.3
    // src/breakglass.rs). When an unexpired two-operator activation
    // is on disk, gate enforcement is bypassed and the caller
    // (handlers/intent.rs) is expected to emit a `BreakglassAction`
    // audit event for every admission carried under that activation
    // (see `breakglass::log_action`).
    if let crate::breakglass::BreakglassStatus::Active { activation_id, .. } =
        ctx.breakglass.check()
    {
        return Ok(GateEvalResult::BreakglassPass {
            activation_id: activation_id.to_string(),
        });
    }

    // ── Step 2: Policy lookup ─────────────────────────────────────────────
    let required_claims = policy_lookup::required_claims(touched_paths, policy)?;

    // Fast path: no claims required and no gates configured.
    if required_claims.is_empty() && policy.gates().is_empty() {
        return Ok(GateEvalResult::Pass { delegate_renewal_required: false });
    }

    // ── Step 2.5: Auto-derive claims from witness records ───────────────
    //
    // Gap fix (claims_explained.md §"Current Implementation Gap"):
    //
    // The spec assumed the planner would actively populate
    // `submitted_claims` referencing witness blobs. The planner driver
    // hardcodes `submitted_claims: vec![]` and has no mechanism to
    // discover which claims are required or which witnesses have landed.
    //
    // Rather than wiring planner-side claim awareness (which would ask
    // the untrusted agent to self-report), the kernel auto-synthesises
    // claims from its own witness records. For each required claim type
    // that maps to a gate type with a passing witness for this
    // (task_id, evaluation_sha), the kernel injects a synthetic
    // `SubmittedClaim` with `evidence_ref` pointing to the witness
    // blob hash.
    //
    // This is strictly more secure than planner-submitted claims:
    //   - The witness is kernel-verified (verifier token + blob hash)
    //   - The planner cannot fabricate a passing witness
    //   - The kernel already has the data; asking the planner is redundant
    //
    // Planner-submitted claims are intentionally discarded. The kernel
    // is the sole claim source — the agent has zero influence on the
    // claim pipeline. All claims are auto-derived from kernel-verified
    // witness records below.
    let mut effective_claims: Vec<SubmittedClaim> = Vec::new();

    for req in &required_claims {
        let claim_type_str = req.as_str();
        if claim_type_str == "StrictDefault" {
            continue; // No witness can satisfy StrictDefault — handled by claim::evaluate
        }

        // Check if a passing witness exists for this gate type + task + sha.
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
    use raxis_types::SubmittedClaim;

    use crate::witness_index::{self, WitnessRecord, ResultClass};
    use crate::gates::witness;
    use crate::gates::policy_lookup::ClaimType;

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
        conn.execute(
            "INSERT OR IGNORE INTO initiatives (initiative_id, state, \
             terminal_criteria_json, plan_artifact_sha256, created_at) \
             VALUES (?, ?, ?, ?, ?)",
            rusqlite::params![
                initiative_id,
                "ApprovedPlan",
                "{}",                  // terminal_criteria_json
                "0".repeat(64),         // plan_artifact_sha256
                0_i64,                  // created_at
            ],
        ).expect("seed_witness initiatives insert");

        conn.execute(
            "INSERT OR IGNORE INTO tasks (task_id, initiative_id, lane_id, state, \
             actor, policy_epoch, admitted_at, transitioned_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
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
        ).expect("seed_witness tasks insert");

        conn.execute(
            "INSERT INTO verifier_run_tokens (verifier_run_id, task_id, gate_type, \
             evaluation_sha, token_hash, issued_at, expires_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?)",
            rusqlite::params![
                run_id,
                task_id,
                gate_type,
                evaluation_sha,
                "0".repeat(64),
                0_i64,
                i64::MAX,
            ],
        ).expect("seed_witness verifier_run_tokens insert");

        let record = WitnessRecord {
            verifier_run_id: run_id.clone(),
            evaluation_sha:  evaluation_sha.to_owned(),
            task_id:         task_id.to_owned(),
            gate_type:       gate_type.to_owned(),
            result_class,
            blob_sha256:     blob_sha.clone(),
            blob_path:       blob_sha.clone(),
            recorded_at:     0,
        };

        witness_index::insert_witness_index_in_tx(
            &conn, &record, raxis_types::unix_now_secs(),
        ).expect("seed_witness insert");

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

            let w = witness::lookup(
                evaluation_sha, task_id, claim_type_str, None, store,
            ).expect("witness lookup");

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

        let blob_sha = seed_witness(
            &store, task_id, eval_sha, "TestSuite", ResultClass::Pass,
        );

        let required = vec![ClaimType::Named("TestSuite".to_owned())];
        let submitted: Vec<SubmittedClaim> = vec![];

        let effective = auto_derive_claims(
            &required, &submitted, task_id, eval_sha, &store,
        );

        assert_eq!(effective.len(), 1, "should auto-derive exactly one claim");
        assert_eq!(effective[0].claim_type, "TestSuite");
        assert_eq!(effective[0].evidence_ref.as_deref(), Some(blob_sha.as_str()));
    }

    #[test]
    fn failing_witness_does_not_auto_derive() {
        let store = mem_store();
        let task_id = "task-2";
        let eval_sha = "beef1234beef1234beef1234beef1234beef1234";

        seed_witness(
            &store, task_id, eval_sha, "TestSuite", ResultClass::Fail,
        );

        let required = vec![ClaimType::Named("TestSuite".to_owned())];
        let submitted: Vec<SubmittedClaim> = vec![];

        let effective = auto_derive_claims(
            &required, &submitted, task_id, eval_sha, &store,
        );

        assert!(effective.is_empty(), "failing witness must not produce a claim");
    }

    #[test]
    fn inconclusive_witness_does_not_auto_derive() {
        let store = mem_store();
        let task_id = "task-3";
        let eval_sha = "dead1234dead1234dead1234dead1234dead1234";

        seed_witness(
            &store, task_id, eval_sha, "TestSuite", ResultClass::Inconclusive,
        );

        let required = vec![ClaimType::Named("TestSuite".to_owned())];
        let submitted: Vec<SubmittedClaim> = vec![];

        let effective = auto_derive_claims(
            &required, &submitted, task_id, eval_sha, &store,
        );

        assert!(effective.is_empty(), "inconclusive witness must not produce a claim");
    }

    #[test]
    fn planner_submitted_claims_are_discarded() {
        let store = mem_store();
        let task_id = "task-4";
        let eval_sha = "cafe1234cafe1234cafe1234cafe1234cafe1234";

        // Auto-derivable: TestSuite has a Pass witness
        seed_witness(
            &store, task_id, eval_sha, "TestSuite", ResultClass::Pass,
        );

        let required = vec![
            ClaimType::Named("TestSuite".to_owned()),
            ClaimType::Named("WriteCode".to_owned()),
        ];

        // Planner explicitly submitted WriteCode — kernel must IGNORE it
        let submitted = vec![SubmittedClaim {
            claim_type: "WriteCode".to_owned(),
            evidence_ref: None,
        }];

        let effective = auto_derive_claims(
            &required, &submitted, task_id, eval_sha, &store,
        );

        // Only TestSuite should appear (auto-derived from witness).
        // WriteCode is NOT present — no witness exists for it, and
        // the planner's assertion is discarded.
        assert_eq!(effective.len(), 1, "only witness-backed claims should appear");
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

        let blob_sha = seed_witness(
            &store, task_id, eval_sha, "TestSuite", ResultClass::Pass,
        );

        let required = vec![ClaimType::Named("TestSuite".to_owned())];

        // Planner submitted TestSuite with a bogus evidence_ref —
        // kernel must ignore it and use the real witness blob hash.
        let submitted = vec![SubmittedClaim {
            claim_type: "TestSuite".to_owned(),
            evidence_ref: Some("planner-fabricated-ref".to_owned()),
        }];

        let effective = auto_derive_claims(
            &required, &submitted, task_id, eval_sha, &store,
        );

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
            &store, task_id, eval_sha, "StrictDefault", ResultClass::Pass,
        );

        let required = vec![ClaimType::StrictDefault];
        let submitted: Vec<SubmittedClaim> = vec![];

        let effective = auto_derive_claims(
            &required, &submitted, task_id, eval_sha, &store,
        );

        assert!(effective.is_empty(), "StrictDefault must never be auto-derived");
    }

    #[test]
    fn no_witness_at_all_leaves_claims_empty() {
        let store = mem_store();
        let task_id = "task-7";
        let eval_sha = "2222222222222222222222222222222222222222";

        // No witness seeded — table is empty for this task
        let required = vec![ClaimType::Named("TestSuite".to_owned())];
        let submitted: Vec<SubmittedClaim> = vec![];

        let effective = auto_derive_claims(
            &required, &submitted, task_id, eval_sha, &store,
        );

        assert!(effective.is_empty(), "no witness → no auto-derived claim");
    }

    #[test]
    fn wrong_evaluation_sha_does_not_auto_derive() {
        let store = mem_store();
        let task_id = "task-8";

        // Witness exists for a DIFFERENT evaluation_sha
        seed_witness(
            &store, task_id, "old_sha_old_sha_old_sha_old_sha_old_sha_", "TestSuite", ResultClass::Pass,
        );

        let required = vec![ClaimType::Named("TestSuite".to_owned())];
        let submitted: Vec<SubmittedClaim> = vec![];

        // Query against a different sha
        let effective = auto_derive_claims(
            &required, &submitted, task_id, "new_sha_new_sha_new_sha_new_sha_new_sha_", &store,
        );

        assert!(effective.is_empty(), "witness for different SHA must not satisfy this intent");
    }
}

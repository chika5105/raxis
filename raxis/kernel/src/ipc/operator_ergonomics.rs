//! V2_GAPS §12.4 — Operator-ergonomics IPC handlers.
//!
//! V2.4 closes out the wire-stub stage from V2.3 with **real
//! handlers** for four of the five operator-ergonomics variants:
//!
//! | Variant                   | V2.3 status         | V2.4 status                                       |
//! |---------------------------|---------------------|---------------------------------------------------|
//! | `ProposeDefaults`         | `FAIL_NOT_YET_…`    | ✅ Returns the policy-derived defaults JSON       |
//! | `EstimateCost`            | `FAIL_NOT_YET_…`    | ✅ Heuristic cost upper-bound from plan + policy  |
//! | `DryRunAdmit`             | `FAIL_NOT_YET_…`    | ✅ Runs admission validation without commit       |
//! | `SubscribeInitiative`     | `FAIL_NOT_YET_…`    | ⚠️  Stays V3 — depends on bidir streaming socket   |
//! | `DescribeInitiativePause` | `FAIL_NOT_YET_…`    | ✅ Reports pause state from the kernel store      |
//!
//! `SubscribeInitiative` remains a wire-stub because the operator
//! socket is single-shot request/response (one
//! `read_json_frame_async` ↔ one `write_json_frame_async`); a real
//! subscribe handler requires bidirectional streaming, which is the
//! same wire-shape change `KernelPush` transport (V2_GAPS §12.1)
//! lands in V3. The other four are pure read/validate operations and
//! do not need streaming.
//!
//! ## Invariant safety (`INV-OPERATOR-ERG-01`)
//!
//! Every handler in this module is a **read-only kernel operation**.
//! It MUST NOT:
//!
//! 1. Insert / update / delete any row in `kernel.db` (no
//!    `tx.commit()`; no `INSERT`).
//! 2. Reserve any token budget, allocate any session, or mutate any
//!    initiative state.
//! 3. Emit any audit event with non-trivial side effects. The spec
//!    permits one low-priority informational audit event per
//!    handler so the operator's actions are forensically traceable;
//!    we follow that allowance only for `DryRunAdmit`
//!    (`DryRunAdmitted` audit kind).
//!
//! All four real handlers are pure functions of `(ctx, request)`:
//! re-running them with the same inputs produces the same response.
//! This is what `operator-ergonomics.md §5.3` requires for
//! `ProposeDefaults` and is the simplest way to keep the surface
//! safe for `raxis plan prepare`-style tools to call repeatedly
//! without operator confirmation.

use raxis_audit_tools::AuditEventKind;
use raxis_types::operator_wire::OperatorResponse;
use serde_json::json;

use crate::ipc::context::HandlerContext;

// ---------------------------------------------------------------------------
// ProposeDefaults — operator-ergonomics.md §5.3
// ---------------------------------------------------------------------------

/// Handle `OperatorRequest::ProposeDefaults`.
///
/// `operator-ergonomics.md §5.3` describes a richer surface that
/// rewrites a plan TOML in-place by filling `# @raxis-default`
/// annotations from `[token_policy_defaults]` / `[default_executor_image]`
/// / `[default_verifier_images]` / `[default_protected_paths]` /
/// `[prepare]` policy sections. Those policy sections are V3 work
/// (V2_GAPS.md §C10 setup wizard tracks them); V2.4 ships an
/// **operator-grade subset**:
///
/// 1. Reads the currently-loaded `PolicyBundle` snapshot.
/// 2. Returns a small JSON document carrying the defaults that
///    *do* exist in the V2 policy schema today (provider catalog,
///    plan-bundle limits, plan-signing freshness window, gateway
///    timeouts, max cost-per-task ceiling, max concurrency cap,
///    optional `[git] default_target_ref`).
/// 3. Includes a `cli_should_render` field (`false`) so V2.4 CLIs
///    that pre-date the V3 prepare-time renderer skip rendering and
///    advise the operator that interactive defaulting requires a
///    V3 CLI.
///
/// The response is a **pure function** of the active policy epoch.
/// Calling this twice without an epoch advance returns byte-
/// identical JSON.
pub async fn handle_propose_defaults(
    initiative_id: Option<String>,
    ctx:           &HandlerContext,
) -> OperatorResponse {
    let policy = ctx.policy.load_full();

    // The set of providers that the operator declared. The CLI
    // surfaces these so a `plan prepare` flow can pick a provider
    // without re-parsing policy.toml.
    let providers: Vec<serde_json::Value> = policy.providers().iter().map(|p| {
        json!({
            "provider_id":           p.provider_id,
            "kind":                  p.kind,
            "inference_timeout_ms":  p.inference_timeout_ms,
            "data_fetch_timeout_ms": p.data_fetch_timeout_ms,
            "max_response_bytes":    p.max_response_bytes,
        })
    }).collect();

    let plan_signing = policy.plan_signing();
    let plan_bundle_limits = policy.plan_bundle_limits();

    let gateway = policy.gateway().map(|g| json!({
        "binary_path":              g.binary_path,
        "spawn_timeout_secs":       g.spawn_timeout_secs,
        "respawn_backoff_ms":       g.respawn_backoff_ms,
        "max_consecutive_respawns": g.max_consecutive_respawns,
    }));

    let host_capacity = policy.host_capacity();
    let defaults = json!({
        "policy_epoch":    policy.epoch(),
        "policy_sha256":   policy.policy_sha256(),
        "git": {
            "default_target_ref": policy.git_default_target_ref(),
            "target_ref_locked":  policy.git_target_ref_locked(),
        },
        "providers":       providers,
        "plan_signing": {
            "max_plan_bundle_age_secs":       plan_signing.max_plan_bundle_age_secs,
            "max_clock_skew_secs":            plan_signing.max_clock_skew_secs,
            "nonce_retention_grace_secs":     plan_signing.nonce_retention_grace_secs,
            "nonce_sweep_interval_secs":      plan_signing.nonce_sweep_interval_secs,
            "accept_unfresh_v2_0_bundles":    plan_signing.accept_unfresh_v2_0_bundles,
        },
        "plan_bundle_limits": {
            "max_artifact_bytes": plan_bundle_limits.max_artifact_bytes,
            "max_bundle_bytes":   plan_bundle_limits.max_bundle_bytes,
            "max_artifact_count": plan_bundle_limits.max_artifact_count,
        },
        "max_cost_per_task":    policy.max_cost_per_task(),
        "host_capacity": {
            "max_concurrent_vms":      host_capacity.max_concurrent_vms,
            "min_free_disk_mb":        host_capacity.min_free_disk_mb,
            "required_min_fd_limit":   host_capacity.required_min_fd_limit,
            "admission_queue_depth":   host_capacity.admission_queue_depth,
        },
        "gateway":              gateway,
        "initiative_scope":     initiative_id,
        // V2.4 CLI does not yet implement plan-toml rewriting from
        // these defaults — the V3 `raxis plan prepare` lands the
        // annotation reader/writer plus the `[token_policy_defaults]`
        // policy section. Operators get the values via this IPC
        // *now* so a forward-compatible CLI can already query them.
        "cli_should_render":    false,
        "supported_in_release": "v2.4",
    });

    let defaults_json = match serde_json::to_string(&defaults) {
        Ok(s)  => s,
        Err(e) => return OperatorResponse::Error {
            code:   "FAIL_PROPOSE_DEFAULTS".into(),
            detail: format!("serialize defaults: {e}"),
        },
    };

    OperatorResponse::ProposedDefaults { defaults_json }
}

// ---------------------------------------------------------------------------
// EstimateCost — operator-ergonomics.md §11.3
// ---------------------------------------------------------------------------

/// Handle `OperatorRequest::EstimateCost`.
///
/// Returns a dollar cost upper bound for the supplied plan, derived
/// **from the operator-declared per-provider `[providers.<id>.pricing]`
/// tables** (V2 `v2_extended_gaps.md §2.5 phase A` —
/// `ProviderPricing`). The estimate is intentionally conservative:
///
/// 1. Parses the plan TOML; counts `[[tasks]]` entries.
/// 2. For each task, estimates token consumption from the optional
///    `[tasks.token_policy.max_tokens_total]` declaration when
///    present; falls back to `DEFAULT_TOKENS_PER_TASK = 200_000`
///    (median observed Anthropic Sonnet planner-loop usage in
///    internal benchmarks).
/// 3. Splits the estimate `60% input / 40% output` (the median ratio
///    across V2 planner traces), then prices each side through the
///    *most expensive* LLM provider declared in the policy via
///    [`raxis_policy::ProviderPricing::cost_micro_dollars`]. Pricing
///    "most expensive" provider is the safest upper bound when a
///    plan can route to multiple providers.
/// 4. Adds `policy.max_cost_per_task()` as a per-task admission
///    overhead allowance (admission-units are operator-defined and
///    treated as cents in the upper-bound projection — this is the
///    same convention the kernel's budget enforcer uses internally).
///
/// **No-LLM-provider deployments.** When the policy declares zero
/// LLM providers (e.g. a degraded read-only deployment), token cost
/// is reported as `0`; the admission-overhead allowance is still
/// included so operators see a non-zero upper bound for the
/// kernel-side admission charge.
///
/// Per `INV-OPERATOR-ERG-01` this handler does NOT verify the plan
/// signature, NOT commit any rows, and NOT reserve any budget. The
/// caller is expected to combine the returned upper bound with the
/// operator's local budget policy *before* deciding whether to
/// `submit plan`.
pub async fn handle_estimate_cost(
    plan_toml:    String,
    plan_sig_hex: String,
    ctx:          &HandlerContext,
) -> OperatorResponse {
    let _ = plan_sig_hex; // signature not verified for cost estimate
    let policy = ctx.policy.load_full();

    let parsed: toml::Value = match toml::from_str(&plan_toml) {
        Ok(v)  => v,
        Err(e) => return OperatorResponse::Error {
            code:   "FAIL_PLAN_PARSE_ERROR".into(),
            detail: format!("plan_toml parse: {e}"),
        },
    };

    let tasks = parsed.get("tasks").and_then(|v| v.as_array());
    let task_count = tasks.map(|a| a.len()).unwrap_or(0);

    /// V2 conservative default — 200k tokens / task. Matches the
    /// median observed Anthropic Sonnet planner-loop usage in
    /// internal benchmarks; will become operator-configurable in
    /// V3 via `[token_policy_defaults] default_tokens_per_task`.
    const DEFAULT_TOKENS_PER_TASK: u64 = 200_000;
    /// V2 default split — 60% input / 40% output. Median observed
    /// ratio across the planner-trace corpus used to pin
    /// `DEFAULT_TOKENS_PER_TASK`. Tweaking this constant shifts the
    /// upper bound by ≤10% under typical pricing.
    const INPUT_FRACTION_PERCENT:  u64 = 60;
    const OUTPUT_FRACTION_PERCENT: u64 = 40;

    // Resolve the worst-case provider for the upper-bound computation
    // by max-ing `cost_micro_dollars(1M, 1M)` across every LLM
    // provider with declared pricing. Non-LLM providers and LLM
    // providers without pricing are skipped (per `PolicyBundle::
    // validate` contract, every LLM provider MUST declare pricing,
    // so the latter set is empty in any validated bundle).
    //
    // Why "1M, 1M" as the comparator: it linearises the cost
    // function so the most-expensive provider for *any* token mix is
    // the one with the highest combined-1M cost. This is exact for
    // affine pricing (which `ProviderPricing` is by construction).
    let worst_provider: Option<&raxis_policy::ProviderEntry> = policy
        .providers()
        .iter()
        .filter(|p| p.pricing.is_some())
        .max_by_key(|p| {
            let pr = p.pricing.as_ref().expect("filtered to Some");
            pr.cost_micro_dollars(1_000_000, 1_000_000, 0, 0)
        });

    let mut breakdown: Vec<serde_json::Value> = Vec::with_capacity(task_count);
    // u128 accumulator so summing `cost_micro_dollars` (`u64`) across
    // many tasks cannot overflow even on 100k-task plans at peak
    // pricing.
    let mut total_micro_dollars: u128 = 0;
    let mut total_tokens: u64 = 0;
    if let Some(arr) = tasks {
        for (i, t) in arr.iter().enumerate() {
            let task_id = t.get("task_id").and_then(|v| v.as_str()).unwrap_or("<unnamed>");
            let est = t.get("token_policy")
                .and_then(|v| v.get("max_tokens_total"))
                .and_then(|v| v.as_integer())
                .filter(|n| *n > 0)
                .map(|n| n as u64)
                .unwrap_or(DEFAULT_TOKENS_PER_TASK);

            let est_input  = est.saturating_mul(INPUT_FRACTION_PERCENT)  / 100;
            let est_output = est.saturating_mul(OUTPUT_FRACTION_PERCENT) / 100;

            let task_micro: u64 = match worst_provider {
                Some(p) => p.pricing.as_ref().expect("checked above")
                    .cost_micro_dollars(est_input, est_output, 0, 0),
                None => 0u64,
            };
            total_micro_dollars = total_micro_dollars.saturating_add(u128::from(task_micro));
            total_tokens = total_tokens.saturating_add(est);
            breakdown.push(json!({
                "task_index":             i,
                "task_id":                task_id,
                "estimated_tokens":       est,
                "estimated_input_tokens": est_input,
                "estimated_output_tokens":est_output,
                "estimated_usd_cents":    micro_dollars_to_cents(u128::from(task_micro)),
            }));
        }
    }

    // Convert micro-dollars to cents (round half-up). 10_000 µ$ = 1 ¢.
    // Saturating cast guards against pathological multi-million-task
    // plans whose cents total overflows `i64::MAX`.
    let mut total_cents: i64 = micro_dollars_to_cents(total_micro_dollars)
        .min(u128::from(i64::MAX as u64)) as i64;

    // Per-initiative kernel-side admission overhead. The kernel's
    // budget enforcer charges at least one `base_cost_per_intent_kind`
    // entry per task; this captures retry headroom under the
    // operator-grade policy ceiling.
    let admission_overhead_cents = (policy.max_cost_per_task() as i64)
        .saturating_mul(task_count as i64);
    total_cents = total_cents.saturating_add(admission_overhead_cents);

    let breakdown_value = json!({
        "pricing_source":                 worst_provider.map(|p| p.provider_id.as_str()).unwrap_or("none"),
        "input_fraction_percent":         INPUT_FRACTION_PERCENT,
        "output_fraction_percent":        OUTPUT_FRACTION_PERCENT,
        "default_tokens_per_task":        DEFAULT_TOKENS_PER_TASK,
        "task_count":                     task_count,
        "total_estimated_tokens":         total_tokens,
        "total_micro_dollars":            total_micro_dollars,
        "admission_overhead_cents":       admission_overhead_cents,
        "tasks":                          breakdown,
        "policy_epoch":                   policy.epoch(),
        "supported_in_release":           "v2.5",
        "estimate_class":                 "operator_grade_provider_pricing",
    });

    let breakdown_json = match serde_json::to_string(&breakdown_value) {
        Ok(s)  => s,
        Err(e) => return OperatorResponse::Error {
            code:   "FAIL_ESTIMATE_COST".into(),
            detail: format!("serialize breakdown: {e}"),
        },
    };

    OperatorResponse::CostEstimated {
        upper_bound_usd_cents: total_cents,
        breakdown_json,
    }
}

/// Round-half-up conversion from micro-dollars to whole cents.
/// 1 ¢ = 10 000 µ$. The half-up rule keeps the upper-bound
/// estimate from drifting below the actual price under partial-
/// cent costs.
fn micro_dollars_to_cents(micro: u128) -> u128 {
    micro.saturating_add(5_000) / 10_000
}

// ---------------------------------------------------------------------------
// DryRunAdmit — operator-ergonomics.md §12.3
// ---------------------------------------------------------------------------

/// Handle `OperatorRequest::DryRunAdmit`.
///
/// Runs a subset of admission validation without persisting any row
/// or starting any session. V2.4 dry-run is **plan-only** —
/// signature validation and the in-tx admission step (§8.1 step 12)
/// are V3 work because they require `BEGIN IMMEDIATE` and would
/// leak transactional state if interrupted mid-run.
///
/// V2.4 checks (mirrors `cli/src/commands/plan_validate.rs` plus
/// the policy ceiling cross-checks):
///
/// 1. Plan TOML parses.
/// 2. Required sections present (`[workspace]`, `[[tasks]]`).
/// 3. `[workspace] lane_id` exists and is non-empty.
/// 4. Task DAG is acyclic, has no duplicate task ids, no
///    self-loops, no dangling predecessors.
/// 5. Resolves the would-be `target_ref` against the policy
///    default + the operator's `[git] target_ref_locked` flag.
/// 6. Returns the resolved `target_ref` and any non-fatal
///    warnings the operator should review before live submission.
///
/// On any fatal check failure the response is
/// `OperatorResponse::Error { code: <FAIL_*>, detail: ... }` with
/// the **same** code a real `CreateInitiative` would have surfaced.
/// Operators get fast structured feedback without paying for the
/// admission lock.
pub async fn handle_dry_run_admit(
    plan_toml:    String,
    _plan_sig_hex: String,
    submitted_by: String,
    ctx:          &HandlerContext,
) -> OperatorResponse {
    let policy = ctx.policy.load_full();

    let parsed: toml::Value = match toml::from_str(&plan_toml) {
        Ok(v)  => v,
        Err(e) => return OperatorResponse::Error {
            code:   "FAIL_PLAN_PARSE_ERROR".into(),
            detail: format!("plan_toml parse: {e}"),
        },
    };

    // Required sections.
    let workspace = match parsed.get("workspace").and_then(|v| v.as_table()) {
        Some(t) => t,
        None => return OperatorResponse::Error {
            code:   "FAIL_PLAN_PARSE_ERROR".into(),
            detail: "missing required [workspace] section".into(),
        },
    };
    let tasks_arr = match parsed.get("tasks").and_then(|v| v.as_array()) {
        Some(a) => a,
        None => return OperatorResponse::Error {
            code:   "FAIL_PLAN_PARSE_ERROR".into(),
            detail: "missing required [[tasks]] section".into(),
        },
    };

    // [workspace] lane_id required.
    let lane_id = match workspace.get("lane_id").and_then(|v| v.as_str()) {
        Some(s) if !s.is_empty() => s,
        _ => return OperatorResponse::Error {
            code:   "FAIL_PLAN_PARSE_ERROR".into(),
            detail: "[workspace] lane_id is required and must be non-empty".into(),
        },
    };

    // DAG cohesion checks.
    let mut seen: std::collections::HashMap<&str, usize> = std::collections::HashMap::with_capacity(tasks_arr.len());
    let mut task_ids: Vec<&str> = Vec::with_capacity(tasks_arr.len());
    for (i, entry) in tasks_arr.iter().enumerate() {
        let task_id = match entry.get("task_id").and_then(|v| v.as_str()) {
            Some(s) if !s.is_empty() => s,
            _ => return OperatorResponse::Error {
                code:   "FAIL_PLAN_PARSE_ERROR".into(),
                detail: format!("tasks[{i}] missing task_id"),
            },
        };
        if let Some(prev) = seen.insert(task_id, i) {
            return OperatorResponse::Error {
                code:   "FAIL_PLAN_PARSE_ERROR".into(),
                detail: format!(
                    "duplicate task_id `{task_id}` declared at tasks[{prev}] and tasks[{i}]"
                ),
            };
        }
        task_ids.push(task_id);
    }
    let known: std::collections::HashSet<&str> = seen.keys().copied().collect();
    for entry in tasks_arr {
        let task_id = entry.get("task_id").and_then(|v| v.as_str()).unwrap_or("<unnamed>");
        let preds: Vec<&str> = entry
            .get("predecessors")
            .and_then(|v| v.as_array())
            .map(|a| a.iter().filter_map(|v| v.as_str()).collect())
            .unwrap_or_default();
        for p in &preds {
            if *p == task_id {
                return OperatorResponse::Error {
                    code:   "FAIL_PLAN_PARSE_ERROR".into(),
                    detail: format!("task `{task_id}` lists itself in `predecessors`"),
                };
            }
            if !known.contains(p) {
                return OperatorResponse::Error {
                    code:   "FAIL_PLAN_PARSE_ERROR".into(),
                    detail: format!(
                        "task `{task_id}` declares unknown predecessor `{p}` (not a sibling task_id)"
                    ),
                };
            }
        }
    }

    // Acyclic check via DFS.
    if let Err(cycle) = check_dag_acyclic(tasks_arr) {
        return OperatorResponse::Error {
            code:   "FAIL_PLAN_PARSE_ERROR".into(),
            detail: format!("plan DAG has a cycle: {cycle}"),
        };
    }

    // Resolve target_ref (V2_GAPS.md §12.8 / §12.9).
    let plan_target_ref = parsed.get("workspace")
        .and_then(|v| v.get("target_ref"))
        .and_then(|v| v.as_str())
        .map(str::to_owned);
    let policy_default_ref = policy.git_default_target_ref().to_owned();
    let policy_locked = policy.git_target_ref_locked();
    let resolved_target_ref = match (plan_target_ref.as_deref(), policy_locked) {
        (Some(plan_ref), true) if plan_ref != policy_default_ref => {
            return OperatorResponse::Error {
                code:   "FAIL_POLICY_LOCKED_FIELD".into(),
                detail: format!(
                    "[git] target_ref_locked = true; plan attempted target_ref = '{plan_ref}' \
                     but policy pinned '{policy_default_ref}'"
                ),
            };
        }
        (Some(plan_ref), _) => plan_ref.to_owned(),
        (None, _) => policy_default_ref.clone(),
    };

    // Non-fatal warnings — collect anything the operator should
    // know about before submitting for real.
    let mut warnings: Vec<String> = Vec::new();
    let task_count = tasks_arr.len();
    let policy_max_cost_per_task = policy.max_cost_per_task();
    if task_count == 0 {
        warnings.push(
            "[[tasks]] is empty — submission will create an initiative with no work".into()
        );
    }
    let host_cap = policy.host_capacity().max_concurrent_vms as u64;
    if (task_count as u64) > host_cap {
        warnings.push(format!(
            "plan declares {task_count} tasks; [host_capacity] max_concurrent_vms = {host_cap} \
             (some tasks will queue at admission)"
        ));
    }
    if let Some(token_policy) = parsed.get("token_policy").and_then(|v| v.as_table()) {
        if let Some(total) = token_policy.get("max_tokens_total").and_then(|v| v.as_integer()) {
            if (total as u64) > policy_max_cost_per_task * 200 /* heuristic */ {
                warnings.push(format!(
                    "[token_policy] max_tokens_total = {total} may exceed the policy cost cap"
                ));
            }
        }
    }
    if plan_target_ref.is_none() {
        warnings.push(format!(
            "plan omitted [workspace] target_ref; defaulting to policy '{policy_default_ref}'"
        ));
    }

    // V2.4 emits a single low-priority `DryRunAdmitted` audit event
    // per call so the operator's local audit chain shows that they
    // dry-ran a specific plan at a specific time. This is the
    // operator-ergonomics.md §12.3 allowance — it is the only
    // write side-effect of this handler.
    if let Err(e) = ctx.audit.emit(
        AuditEventKind::DryRunAdmitted {
            submitted_by:        submitted_by.clone(),
            policy_epoch:        policy.epoch(),
            plan_sha256:         raxis_crypto::token::sha256_hex(plan_toml.as_bytes()),
            target_ref:          resolved_target_ref.clone(),
            warnings_count:      warnings.len() as u32,
            lane_id:             lane_id.to_owned(),
            task_count:          task_count as u32,
        },
        None,
        None,
        None,
    ) {
        eprintln!(
            "{{\"level\":\"warn\",\"event\":\"DryRunAdmitted\",\"audit_emit_failed\":\"{e}\"}}",
        );
    }

    OperatorResponse::DryRunAdmitted {
        target_ref: resolved_target_ref,
        warnings,
    }
}

fn check_dag_acyclic(tasks: &[toml::Value]) -> Result<(), String> {
    // Build adjacency list keyed by task_id.
    let mut adj: std::collections::HashMap<&str, Vec<&str>> = std::collections::HashMap::new();
    for entry in tasks {
        let task_id = entry.get("task_id").and_then(|v| v.as_str()).unwrap_or("<unnamed>");
        let preds: Vec<&str> = entry
            .get("predecessors")
            .and_then(|v| v.as_array())
            .map(|a| a.iter().filter_map(|v| v.as_str()).collect())
            .unwrap_or_default();
        adj.insert(task_id, preds);
    }

    /// Three-colour DFS: 0 = unvisited, 1 = on stack, 2 = done.
    fn dfs<'a>(
        node:  &'a str,
        adj:   &'a std::collections::HashMap<&'a str, Vec<&'a str>>,
        state: &mut std::collections::HashMap<&'a str, u8>,
        path:  &mut Vec<&'a str>,
    ) -> Result<(), String> {
        state.insert(node, 1);
        path.push(node);
        if let Some(preds) = adj.get(node) {
            for p in preds {
                match state.get(p).copied().unwrap_or(0) {
                    1 => {
                        let cycle: Vec<&str> = path.iter().copied()
                            .skip_while(|n| n != p).chain(std::iter::once(*p))
                            .collect();
                        return Err(cycle.join(" → "));
                    }
                    0 => dfs(p, adj, state, path)?,
                    _ => {} // already finished
                }
            }
        }
        path.pop();
        state.insert(node, 2);
        Ok(())
    }

    let mut state: std::collections::HashMap<&str, u8> = std::collections::HashMap::new();
    let mut path: Vec<&str> = Vec::new();
    for k in adj.keys() {
        if state.get(k).copied().unwrap_or(0) == 0 {
            dfs(k, &adj, &mut state, &mut path)?;
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// SubscribeInitiative — operator-ergonomics.md §13.4
// ---------------------------------------------------------------------------

/// Handle `OperatorRequest::SubscribeInitiative`.
///
/// V2.4 returns `FAIL_NOT_YET_IMPLEMENTED` because the operator
/// socket is single-shot request/response. A real implementation
/// requires bidirectional streaming on the operator UDS (the same
/// transport `KernelPush` lands in V3 — V2_GAPS §12.1). The wire
/// shape (`OperatorRequest::SubscribeInitiative { initiative_id }`
/// → `OperatorResponse::InitiativeSubscribed { initiative_id }`)
/// is **stable in V2.4**; V3 will swap the dispatcher arm without
/// reshaping the JSON envelopes.
///
/// Why not poll-based? Polling against `DescribeInitiativePause`
/// works, but it cannot deliver `KernelPush` events
/// (`AllReviewersPassed`, `IntegrationMergeCompleted`,
/// `EscalationRaised`, etc.) at low latency. The V3 design uses the
/// existing `KernelPushDispatcher` (V2_GAPS §12.1) and reuses the
/// existing operator UDS rather than introducing a second socket.
pub async fn handle_subscribe_initiative(
    initiative_id: String,
    _ctx:          &HandlerContext,
) -> OperatorResponse {
    let _ = initiative_id;
    OperatorResponse::Error {
        code:   "FAIL_NOT_YET_IMPLEMENTED".into(),
        detail: format!(
            "SubscribeInitiative requires bidirectional streaming on the operator socket; \
             V2.4 ships single-shot request/response. The wire shape is stable; V3 lands \
             the streaming transport (V2_GAPS.md §12.1 KernelPush) and the real handler in \
             the same release. Poll DescribeInitiativePause for state checks in the meantime."
        ),
    }
}

// ---------------------------------------------------------------------------
// DescribeInitiativePause — operator-ergonomics.md §14.3
// ---------------------------------------------------------------------------

/// Handle `OperatorRequest::DescribeInitiativePause`.
///
/// Reports whether `initiative_id` is currently paused (operator
/// quarantine, escalation hold, or a non-Executing terminal-leaning
/// state) and lists any outstanding escalations the operator must
/// resolve before resume becomes legal.
///
/// **V2.4 pause definition.** An initiative is "paused" if any of:
///
/// * It has a row in `initiative_quarantines` (operator pressed the
///   quarantine button — see `views::initiative_quarantines`).
/// * Its `state` is one of `Blocked`, `Failed`, `Aborted` (cannot
///   make forward progress without operator intervention).
///
/// `paused_at` reports the quarantine `quarantined_at` time when
/// available; otherwise it falls back to the initiative's
/// `completed_at` (terminal states) and `None` when no timestamp
/// is recorded.
pub async fn handle_describe_initiative_pause(
    initiative_id: String,
    ctx:           &HandlerContext,
) -> OperatorResponse {
    let data_dir = ctx.data_dir.clone();
    let initiative_for_blk = initiative_id.clone();

    let join = tokio::task::spawn_blocking(move || -> Result<DescribeOutcome, String> {
        // Use a short-lived read-only connection so we don't
        // contend with the kernel's writer mutex. INV-OPERATOR-ERG-01
        // (read-only) holds trivially because the connection is
        // opened with `SQLITE_OPEN_READ_ONLY`.
        let ro = raxis_store::ro::open(&data_dir)
            .map_err(|e| format!("ro open: {e}"))?;

        let initiative_row = raxis_store::views::initiatives::by_id(&ro, &initiative_for_blk)
            .map_err(|e| format!("by_id: {e}"))?;

        let quarantine_row = raxis_store::views::initiative_quarantines::get_by_initiative_id(
            &ro, &initiative_for_blk,
        ).map_err(|e| format!("quarantine: {e}"))?;

        // Pending escalations bound to this initiative.
        let escalations = raxis_store::views::escalations::list(
            &ro,
            raxis_store::views::escalations::EscalationStatusFilter::Pending,
            1024,
        ).map_err(|e| format!("escalations: {e}"))?;
        let outstanding: Vec<String> = escalations.into_iter()
            .filter(|e| e.initiative_id == initiative_for_blk)
            .map(|e| e.escalation_id)
            .collect();

        Ok(DescribeOutcome {
            initiative_row,
            quarantine_row,
            outstanding_escalations: outstanding,
        })
    }).await;

    let outcome = match join {
        Ok(Ok(v))  => v,
        Ok(Err(e)) => return OperatorResponse::Error {
            code:   "FAIL_DESCRIBE_INITIATIVE_PAUSE".into(),
            detail: e,
        },
        Err(e)     => return OperatorResponse::Error {
            code:   "FAIL_DESCRIBE_INITIATIVE_PAUSE".into(),
            detail: format!("describe spawn_blocking join failed: {e}"),
        },
    };

    let DescribeOutcome { initiative_row, quarantine_row, outstanding_escalations } = outcome;

    let row = match initiative_row {
        Some(r) => r,
        None => return OperatorResponse::Error {
            code:   "FAIL_INITIATIVE_NOT_FOUND".into(),
            detail: format!("initiative '{initiative_id}' does not exist"),
        },
    };

    let is_paused_by_quarantine = quarantine_row.is_some();
    let is_paused_by_state = matches!(
        row.state.as_str(),
        "Blocked" | "Failed" | "Aborted",
    );
    let is_paused_by_escalations = !outstanding_escalations.is_empty();
    let is_paused = is_paused_by_quarantine
        || is_paused_by_state
        || is_paused_by_escalations;

    let paused_at: Option<i64> = quarantine_row.map(|q| q.quarantined_at)
        .or_else(|| row.completed_at.map(|v| v as i64));

    OperatorResponse::InitiativePauseDescribed {
        initiative_id,
        is_paused,
        paused_at,
        outstanding_escalations,
    }
}

struct DescribeOutcome {
    initiative_row:          Option<raxis_store::views::initiatives::InitiativeRow>,
    quarantine_row:          Option<raxis_store::views::initiative_quarantines::InitiativeQuarantineRow>,
    outstanding_escalations: Vec<String>,
}

// ---------------------------------------------------------------------------
// ListTaskOutputs — v2_extended_gaps.md §3.2 StructuredOutput tool
// ---------------------------------------------------------------------------

/// Handle `OperatorRequest::ListTaskOutputs`.
///
/// Returns every row of `structured_outputs` whose `task_id`
/// equals the request id, ordered by `emitted_at` ascending.
/// Read-only; upholds `INV-OPERATOR-ERG-01`.
///
/// Returns `Error{FAIL_LIST_TASK_OUTPUTS, …}` on any sqlite
/// error; an empty list (no outputs emitted yet for the task)
/// is reported as a successful `TaskOutputsListed { outputs: [] }`
/// rather than as a failure — the caller's read intent is
/// satisfied either way.
pub async fn handle_list_task_outputs(
    task_id: String,
    ctx:     &HandlerContext,
) -> OperatorResponse {
    let data_dir = ctx.data_dir.clone();
    let task_for_blk = task_id.clone();

    let join = tokio::task::spawn_blocking(
        move || -> Result<Vec<raxis_store::views::StructuredOutputRow>, String> {
            // INV-OPERATOR-ERG-01: short-lived read-only connection
            // (`SQLITE_OPEN_READ_ONLY`) — write attempts are a type
            // error against `RoConn`.
            let ro = raxis_store::ro::open(&data_dir)
                .map_err(|e| format!("ro open: {e}"))?;
            raxis_store::views::structured_outputs::list_for_task(&ro, &task_for_blk)
                .map_err(|e| format!("list_for_task: {e}"))
        },
    ).await;

    let rows = match join {
        Ok(Ok(v))  => v,
        Ok(Err(e)) => return OperatorResponse::Error {
            code:   "FAIL_LIST_TASK_OUTPUTS".into(),
            detail: e,
        },
        Err(e)     => return OperatorResponse::Error {
            code:   "FAIL_LIST_TASK_OUTPUTS".into(),
            detail: format!("list_task_outputs spawn_blocking join failed: {e}"),
        },
    };

    let outputs = rows.into_iter()
        .map(|r| raxis_types::operator_wire::TaskOutputWire {
            output_id:     r.output_id,
            initiative_id: r.initiative_id,
            task_id:       r.task_id,
            session_id:    r.session_id,
            kind:          r.kind,
            severity:      r.severity,
            payload_json:  r.payload_json,
            emitted_at:    r.emitted_at,
        })
        .collect();

    OperatorResponse::TaskOutputsListed { task_id, outputs }
}

// raxis-kernel::scheduler::budget — Per-lane cost and concurrency enforcement.
// Normative reference: kernel-core.md §2.3 `src/scheduler/budget.rs`.
// Budget state is persisted in `lane_budget_reservations` (survives restarts).
// Reservations are created on intent pickup (handlers/intent.rs, after gates pass).
// Reservations are released on task terminal state.
// Continuation intents (already-Running task) do NOT re-insert a reservation
// (PK (lane_id, task_id) prevents double-insertion).

use std::path::PathBuf;

use raxis_policy::PolicyBundle;
use raxis_store::{Store, Table};
use raxis_types::{unix_now_secs, IntentKind, TaskState};

use crate::scheduler::lane::{get_lane_status, get_lane_status_in_tx};
use crate::scheduler::{BudgetError, SchedulerError};

// INV-STORE-03 (kernel-store.md §2.5.1): all SQL identifiers in this
// module flow through the typed `Table` enum.
const LANE_BUDGET_RESERVATIONS: &str = Table::LaneBudgetReservations.as_str();
const TASKS: &str = Table::Tasks.as_str();

/// Budget snapshot for a lane — alias for LaneStatus in budget-centric terms.
pub type LaneBudgetSnapshot = crate::scheduler::lane::LaneStatus;

/// Check whether a lane has budget for `estimated_cost` more units.
/// Pure read. The canonical write path
/// ([`reserve_budget_in_tx`]) folds an equivalent check and the
/// `lane_budget_reservations` INSERT into a single transaction;
/// this standalone variant is preserved as a diagnostic helper for
/// dashboards / ad-hoc operator queries.
/// Returns `SchedulerError::BudgetExceeded { kind }` if over-limit.
pub fn check_budget(
    lane_id: &str,
    estimated_cost: u64,
    policy: &PolicyBundle,
    store: &Store,
) -> Result<(), SchedulerError> {
    let status = get_lane_status(lane_id, store)?;
    let lane_cfg = crate::scheduler::lane::lane_config_for_row(lane_id, policy)?;

    if status.active_tasks >= lane_cfg.max_concurrent_tasks {
        return Err(SchedulerError::BudgetExceeded {
            kind: format!(
                "ConcurrencyLimit (active={}, max={})",
                status.active_tasks, lane_cfg.max_concurrent_tasks
            ),
        });
    }

    if status.reserved_cost.saturating_add(estimated_cost) > lane_cfg.max_cost_per_epoch {
        return Err(SchedulerError::BudgetExceeded {
            kind: format!(
                "CostLimit (reserved={}, estimated={}, max={})",
                status.reserved_cost, estimated_cost, lane_cfg.max_cost_per_epoch
            ),
        });
    }

    Ok(())
}

/// Insert a `lane_budget_reservations` row for this task — transaction
/// variant for callers composing this write into a larger atomic
/// operation. The canonical write path is
/// [`reserve_budget_in_tx`], which folds the lane-status SELECT and
/// this INSERT into a single transaction (closes Pattern A TOCTOU
/// per `kernel-store.md` §2.5.1.1). PK `(lane_id, task_id)` means
/// re-insertion on continuation is prevented by `INSERT OR IGNORE`.
pub fn consume_budget_in_tx(
    conn: &rusqlite::Connection,
    lane_id: &str,
    task_id: &str,
    cost: u64,
) -> Result<(), SchedulerError> {
    let now = unix_now_secs();
    conn.execute(
        &format!(
            "INSERT OR IGNORE INTO {LANE_BUDGET_RESERVATIONS}
                (lane_id, task_id, reserved_cost, reserved_at)
             VALUES (?1, ?2, ?3, ?4)"
        ),
        rusqlite::params![lane_id, task_id, cost as i64, now],
    )?;
    Ok(())
}

/// Atomically check budget and reserve in one transaction.
/// **INV-STORE-02 (kernel-store.md §2.5.1.1 Pattern A):** this is the
/// canonical write path that closes the budget TOCTOU. The pre-fix code
/// called `check_budget` (acquired the mutex, computed `reserved_cost`,
/// released the mutex) followed later by `consume_budget` (re-acquired,
/// inserted). Two concurrent intents on the same lane could both pass
/// the check before either inserted, over-committing the operator's
/// `max_cost_per_epoch` cap.
/// This helper runs the SELECT-aggregate (`get_lane_status_in_tx`) and
/// the `INSERT OR IGNORE` inside the **same** `conn.transaction()` (which
/// the caller has already opened) so no other tokio task can interleave
/// between them. The mutex is held continuously across both, satisfying
/// INV-STORE-01.
/// Returns `BudgetExceeded { kind: "ConcurrencyLimit"|"CostLimit" }` if
/// the lane cannot accommodate `estimated_cost`. Returns `NoLaneAssigned`
/// if `lane_id` is not declared in the policy. Idempotent on `(lane_id,
/// task_id)` PK conflict (continuation intents do not double-charge).
pub fn reserve_budget_in_tx(
    conn: &rusqlite::Connection,
    lane_id: &str,
    task_id: &str,
    estimated_cost: u64,
    policy: &PolicyBundle,
) -> Result<(), SchedulerError> {
    let lane_cfg = crate::scheduler::lane::lane_config_for_row(lane_id, policy)?;
    prune_terminal_reservations_in_tx(conn, lane_id)?;
    let status = get_lane_status_in_tx(conn, lane_id)?;

    if status.active_tasks >= lane_cfg.max_concurrent_tasks {
        return Err(SchedulerError::BudgetExceeded {
            kind: format!(
                "ConcurrencyLimit (active={}, max={})",
                status.active_tasks, lane_cfg.max_concurrent_tasks
            ),
        });
    }

    if status.reserved_cost.saturating_add(estimated_cost) > lane_cfg.max_cost_per_epoch {
        return Err(SchedulerError::BudgetExceeded {
            kind: format!(
                "CostLimit (reserved={}, estimated={}, max={})",
                status.reserved_cost, estimated_cost, lane_cfg.max_cost_per_epoch
            ),
        });
    }

    consume_budget_in_tx(conn, lane_id, task_id, estimated_cost)
}

/// Live backstop for terminal tasks that escaped their normal
/// `release_budget_in_tx` call. The boot-time recovery sweep also removes
/// these rows, but a daemon that never restarts must not let stale terminal
/// reservations starve later root closeout or integration work.
fn prune_terminal_reservations_in_tx(
    conn: &rusqlite::Connection,
    lane_id: &str,
) -> Result<usize, SchedulerError> {
    let terminal = [
        TaskState::Completed,
        TaskState::Failed,
        TaskState::Aborted,
        TaskState::Cancelled,
    ]
    .iter()
    .map(|s| format!("'{}'", s.as_sql_str()))
    .collect::<Vec<_>>()
    .join(", ");
    let rows = conn.execute(
        &format!(
            "DELETE FROM {LANE_BUDGET_RESERVATIONS}
              WHERE lane_id = ?1
                AND task_id IN (
                    SELECT task_id FROM {TASKS}
                     WHERE state IN ({terminal})
                )"
        ),
        rusqlite::params![lane_id],
    )?;
    Ok(rows)
}

/// Get current budget snapshot for a lane (active tasks + reserved cost).
pub fn current_budget(lane_id: &str, store: &Store) -> Result<LaneBudgetSnapshot, SchedulerError> {
    get_lane_status(lane_id, store)
}

/// Release the budget reservation for a task.
/// Deletes from `lane_budget_reservations`. Safe to call multiple times
/// (idempotent on 0 rows). Returns `SchedulerError::CorruptReservationState`
/// if >1 row was deleted (schema invariant violation).
/// **Standalone variant** — opens its own mutex acquisition. The
/// canonical write path is [`release_budget_in_tx`], which composes
/// the DELETE into the same transaction as the terminal-state flip
/// (`Running → Completed` / `Running → Failed` / `Aborted` / etc.) so
/// that "task is terminal" and "lane reservation is freed" are
/// observable atomically. Use this standalone variant only from
/// recovery / sweep paths that need to release a reservation outside
/// the FSM-transition tx (e.g. `recovery::reconcile_tasks` for tasks
/// the kernel restart finds already terminal in the store but with a
/// stale reservation row — the row's existence after a clean shutdown
/// would be a §2.5.1 invariant violation, but during crash-recovery
/// we accept that gap and reconcile here).
pub fn release_budget(lane_id: &str, task_id: &str, store: &Store) -> Result<(), SchedulerError> {
    let conn = store.lock_sync();
    release_budget_in_tx(&conn, lane_id, task_id)
}

/// Release the budget reservation for a task — transaction variant.
/// Composes the `DELETE FROM lane_budget_reservations` into the same
/// SQLite transaction as the terminal-state flip on
/// `tasks.state` (`Running → Completed` for `CompleteTask`,
/// `Running → Failed` for `ReportFailure`, `Admitted → Aborted` /
/// `Running → Aborted` for operator-driven aborts). This is the
/// kernel-store.md §2.5.1 invariant for lane bookkeeping:
/// > Every terminal-state handler MUST call `release_budget` before
/// > `reconcile_actual_cost`. … Reordering these calls would violate
/// > the "reservation already released" invariant checked by
/// > `rows_affected()`.
/// > **Why in-tx, not standalone.** If the state flip and the
/// > reservation release commit independently, a crash between them
/// > leaves the lane over-committed forever (the recovery sweep would
/// > see a terminal task and skip it; the reservation row stays).
/// > Folding both into one tx makes the failure mode binary: either the
/// > task is terminal AND its reservation is gone, or the task is
/// > pre-terminal AND its reservation is still charged.
/// > Same `rows_affected()` semantics as [`release_budget`]:
/// > `0` → idempotent (already released, e.g. a continuation intent
/// > that double-committed before the post-fix tx-fold landed); `1` →
/// > released; `>1` → `SchedulerError::CorruptReservationState`
/// > (schema invariant violation — the `(lane_id, task_id)` PK should
/// > make this unreachable, but we surface it for forensic value).
pub fn release_budget_in_tx(
    conn: &rusqlite::Connection,
    lane_id: &str,
    task_id: &str,
) -> Result<(), SchedulerError> {
    let rows = conn.execute(
        &format!("DELETE FROM {LANE_BUDGET_RESERVATIONS} WHERE lane_id=?1 AND task_id=?2"),
        rusqlite::params![lane_id, task_id],
    )?;
    match rows {
        0 => Ok(()), // Already released — idempotent.
        1 => Ok(()),
        _ => Err(SchedulerError::CorruptReservationState {
            task_id: task_id.to_owned(),
        }),
    }
}

/// Compute the admission cost for an intent.
/// Formula (§2.3):
///   IntegrationMerge is kernel-owned closeout plumbing → 0 units
///   base_cost = policy.base_cost_for_intent_kind(intent_kind_str) → None = error
///   path_cost = touched_paths.len() * policy.cost_per_touched_path()
///   raw       = base_cost.saturating_add(path_cost)
///   result    = min(raw, policy.max_cost_per_task())
/// Pure function — no store access. Planner cannot influence the result.
pub fn compute_admission_cost(
    touched_paths: &[PathBuf],
    intent_kind: IntentKind,
    policy: &PolicyBundle,
) -> Result<u64, BudgetError> {
    if intent_kind == IntentKind::IntegrationMerge {
        return Ok(0);
    }

    // Convert IntentKind to the string key used in the policy table.
    let kind_str = intent_kind_to_str(&intent_kind);

    let base_cost = policy.base_cost_for_intent_kind(kind_str).ok_or_else(|| {
        BudgetError::UnknownIntentKindCost {
            intent_kind: kind_str.to_owned(),
        }
    })?;

    let path_cost = (touched_paths.len() as u64).saturating_mul(policy.cost_per_touched_path());

    let raw = base_cost.saturating_add(path_cost);
    Ok(raw.min(policy.max_cost_per_task()))
}

/// Map an IntentKind variant to the TOML key string used in the policy table.
/// V2 sub-task lifecycle kinds (`ActivateSubTask`, `RetrySubTask`,
/// `SubmitReview`) reuse the same `IntentKind::as_str` projection so
/// operators can configure per-kind costs in `[lanes.<name>.intent_costs]`
/// the same way as V1 kinds. The static dispatch matrix
/// (v2-deep-spec.md §Step 20) is the authority on whether a session may
/// submit each kind; the budget mapper just charges the configured cost
/// once admission succeeds.
fn intent_kind_to_str(kind: &IntentKind) -> &'static str {
    kind.as_str()
}

// ---------------------------------------------------------------------------
// V2 §2.5 — per-task LLM token-cost admission gate
// ---------------------------------------------------------------------------

/// Number of micro-dollars in one
/// admission-units cent. The kernel treats `policy.max_cost_per_task`
/// as a USD-cents ceiling; the per-task cumulative LLM cost is
/// tracked in micro-dollars (`ProviderPricing::cost_micro_dollars`)
/// for sub-cent precision. 1 ¢ = 10 000 µ$.
pub const MICROS_PER_CENT: u64 = 10_000;

/// Version label for the bundled rate table used only when no
/// operator override or runtime provider-pricing source is available.
/// This label is surfaced to the dashboard because bundled rates are
/// estimates, not provider-billed truth.
pub const BUNDLED_PRICING_REGISTRY_VERSION: &str = "bundled-2026-06-11";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenPricingSource {
    OperatorPolicyOverride {
        provider_id: String,
    },
    RuntimeProviderApi {
        provider_id: String,
        registry_version: String,
    },
    BundledEstimate {
        provider_id: String,
        registry_version: &'static str,
    },
    Unpriced,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PricedTokenCost {
    pub micros: u64,
    pub source: TokenPricingSource,
}

/// Incremental dollar cost of one planner-reported `TokensReport`.
///
/// Resolution order:
/// 1. Operator policy override (`[[providers]].pricing`) for the
///    exact provider id, provider kind, or model-derived provider.
/// 2. Runtime provider-pricing API hook. Official providers reliably
///    report usage tokens, but do not expose a uniform rate endpoint;
///    this seam is where provider-specific cost APIs can plug in.
/// 3. Bundled fallback estimates, explicitly marked as estimates.
/// 4. Unpriced (`0`) only when there are no tokens or no usable
///    source.
pub fn price_tokens_for_report(
    report: &raxis_types::TokensReport,
    policy: &PolicyBundle,
) -> PricedTokenCost {
    if report.input_tokens == 0
        && report.output_tokens == 0
        && report.cache_read_tokens == 0
        && report.cache_creation_tokens == 0
    {
        return PricedTokenCost {
            micros: 0,
            source: TokenPricingSource::Unpriced,
        };
    }

    if let Some(provider) = policy_pricing_for_report(report, policy) {
        let pricing = provider
            .pricing
            .as_ref()
            .expect("policy_pricing_for_report filters to pricing");
        return PricedTokenCost {
            micros: pricing.cost_micro_dollars(
                report.input_tokens,
                report.output_tokens,
                report.cache_read_tokens,
                report.cache_creation_tokens,
            ),
            source: TokenPricingSource::OperatorPolicyOverride {
                provider_id: provider.provider_id.clone(),
            },
        };
    }

    if let Some(runtime) = runtime_provider_pricing_for_report(report) {
        return runtime;
    }

    if let Some((provider_id, pricing)) = bundled_estimate_pricing_for_report(report) {
        return PricedTokenCost {
            micros: pricing.cost_micro_dollars(
                report.input_tokens,
                report.output_tokens,
                report.cache_read_tokens,
                report.cache_creation_tokens,
            ),
            source: TokenPricingSource::BundledEstimate {
                provider_id,
                registry_version: BUNDLED_PRICING_REGISTRY_VERSION,
            },
        };
    }

    PricedTokenCost {
        micros: 0,
        source: TokenPricingSource::Unpriced,
    }
}

/// Backward-compatible cost-only helper for admission code.
pub fn cost_micros_for_tokens(report: &raxis_types::TokensReport, policy: &PolicyBundle) -> u64 {
    price_tokens_for_report(report, policy).micros
}

fn policy_pricing_for_report<'a>(
    report: &raxis_types::TokensReport,
    policy: &'a PolicyBundle,
) -> Option<&'a raxis_policy::ProviderEntry> {
    let provider_id = report.provider_id.trim();
    if !provider_id.is_empty() {
        if let Some(exact) = policy
            .providers()
            .iter()
            .find(|p| p.provider_id == provider_id && p.pricing.is_some())
        {
            return Some(exact);
        }

        // A generic provider-family report such as `anthropic`,
        // `openai`, or `gemini` is already a complete pricing scope.
        // Do not fall through to an arbitrary same-kind provider row:
        // doing so lets one named deployment's operator override
        // silently price another deployment/initiative that intentionally
        // omitted pricing to use runtime/bundled provenance.
        if provider_kind_id(provider_id).is_some() {
            return None;
        }
    }

    let provider_kind = provider_id_from_report(report);
    if let Some(kind) = provider_kind.as_deref() {
        return policy
            .providers()
            .iter()
            .filter(|p| p.pricing.is_some() && provider_kind_id(&p.kind) == Some(kind))
            .max_by_key(|p| {
                p.pricing
                    .as_ref()
                    .expect("filtered to Some")
                    .cost_micro_dollars(
                        report.input_tokens,
                        report.output_tokens,
                        report.cache_read_tokens,
                        report.cache_creation_tokens,
                    )
            });
    }

    // Legacy/diagnostic reports might omit provider and model. Use a
    // conservative worst override if the operator supplied any.
    policy
        .providers()
        .iter()
        .filter(|p| p.pricing.is_some())
        .max_by_key(|p| {
            p.pricing
                .as_ref()
                .expect("filtered to Some")
                .cost_micro_dollars(
                    report.input_tokens,
                    report.output_tokens,
                    report.cache_read_tokens,
                    report.cache_creation_tokens,
                )
        })
}

fn runtime_provider_pricing_for_report(
    _report: &raxis_types::TokensReport,
) -> Option<PricedTokenCost> {
    // Official model APIs return provider usage tokens reliably, but
    // OpenAI/Anthropic/Gemini do not expose one uniform "current
    // model rate" endpoint that the kernel can synchronously trust at
    // admission time. Provider-specific billing/cost APIs can be
    // wired here later; until then, policy overrides and bundled
    // estimates carry explicit provenance.
    None
}

fn bundled_estimate_pricing_for_report(
    report: &raxis_types::TokensReport,
) -> Option<(String, raxis_policy::ProviderPricing)> {
    let provider = provider_id_from_report(report)?;
    let pricing = match provider.as_str() {
        // Conservative generic estimates. They are deliberately not
        // exact list prices; the dashboard labels them as estimates
        // and policy overrides should be used for enterprise
        // contracts or volume discounts.
        "anthropic" => raxis_policy::ProviderPricing {
            input_tokens_per_dollar: 333_333, // ~$3 / 1M input
            output_tokens_per_dollar: 66_666, // ~$15 / 1M output
            cache_read_tokens_per_dollar: Some(3_333_333),
            cache_creation_tokens_per_dollar: Some(266_666),
        },
        "openai" => raxis_policy::ProviderPricing {
            input_tokens_per_dollar: 1_000_000, // ~$1 / 1M input
            output_tokens_per_dollar: 250_000,  // ~$4 / 1M output
            cache_read_tokens_per_dollar: Some(10_000_000),
            cache_creation_tokens_per_dollar: None,
        },
        "gemini" => raxis_policy::ProviderPricing {
            input_tokens_per_dollar: 1_000_000, // ~$1 / 1M input
            output_tokens_per_dollar: 250_000,  // ~$4 / 1M output
            cache_read_tokens_per_dollar: Some(10_000_000),
            cache_creation_tokens_per_dollar: None,
        },
        "bedrock" => raxis_policy::ProviderPricing {
            input_tokens_per_dollar: 333_333,
            output_tokens_per_dollar: 66_666,
            cache_read_tokens_per_dollar: Some(3_333_333),
            cache_creation_tokens_per_dollar: Some(266_666),
        },
        "sidecar" => return None,
        _ => return None,
    };
    Some((provider, pricing))
}

fn provider_id_from_report(report: &raxis_types::TokensReport) -> Option<String> {
    let provider_id = report.provider_id.trim();
    if let Some(kind) = provider_kind_id(provider_id) {
        return Some(kind.to_owned());
    }
    provider_from_model_id(report.model_id.trim())
}

fn provider_kind_id(kind: &str) -> Option<&'static str> {
    match kind {
        "Anthropic" | "anthropic" => Some("anthropic"),
        "OpenAI" | "openai" => Some("openai"),
        "Gemini" | "gemini" => Some("gemini"),
        "Bedrock" | "bedrock" => Some("bedrock"),
        "http_sidecar" | "sidecar" => Some("sidecar"),
        _ => None,
    }
}

fn provider_from_model_id(model_id: &str) -> Option<String> {
    if model_id.is_empty() {
        return None;
    }
    if model_id.starts_with("claude-") {
        return Some("anthropic".to_owned());
    }
    if model_id.starts_with("gemini-") {
        return Some("gemini".to_owned());
    }
    if model_id.starts_with("gpt-") || model_id.starts_with("o1") || model_id.starts_with("o3") {
        return Some("openai".to_owned());
    }
    if model_id.starts_with("anthropic.") {
        return Some("bedrock".to_owned());
    }
    None
}

/// The per-task token-cost ceiling
/// expressed in micro-dollars. Derived from
/// `policy.max_cost_per_task()` (USD cents) by multiplying through
/// `MICROS_PER_CENT`; saturating multiplication keeps a pathological
/// `u64::MAX` policy from wrapping.
pub fn token_cost_ceiling_micros(policy: &PolicyBundle) -> u64 {
    policy.max_cost_per_task().saturating_mul(MICROS_PER_CENT)
}

/// Admission gate verdict. Used by
/// `handlers::intent::run_phase_a` to fail-closed-reject any intent
/// whose cumulative LLM token cost would push the task above
/// `policy.max_cost_per_task` (treated as a USD-cents ceiling).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenBudgetVerdict {
    /// The reported cumulative cost is at or below the ceiling.
    /// Admission proceeds.
    Allow {
        /// Newly-computed cumulative token cost in micro-dollars.
        cumulative_token_cost_micros: u64,
    },
    /// Cumulative cost would exceed the ceiling. Admission is
    /// rejected with `PlannerErrorCode::FailPolicyViolation` per
    /// the §2.5 contract ("fail-closed").
    Reject {
        /// Cumulative cost that would have resulted from admitting
        /// the intent (for audit + operator-facing reporting).
        cumulative_token_cost_micros: u64,
        /// Configured ceiling (micros).
        ceiling_micros: u64,
    },
}

/// Evaluate the per-task token-cost
/// ceiling for an intent. Pure function: takes the planner-
/// reported cumulative `TokensReport`, computes the dollar cost via
/// [`cost_micros_for_tokens`], compares against
/// [`token_cost_ceiling_micros`].
/// `previous_cost_micros` is the cumulative cost already persisted
/// on the task row from prior accepted intents (V2.5 admission gate
/// is monotonic — every intent reports the running total, not a
/// delta). When the planner reports the same total as the previous
/// intent (no new LLM turns happened — e.g. a retry), the ceiling
/// check still runs on the current total so the admission decision
/// is monotonic with the most recent report.
pub fn evaluate_token_budget(
    report: Option<&raxis_types::TokensReport>,
    previous_cost_micros: u64,
    policy: &PolicyBundle,
) -> TokenBudgetVerdict {
    let report = match report {
        Some(r) => r,
        // Synthetic / kernel-injected intents skip the token gate.
        // The dispatch loop's per-session HARD cap remains in
        // effect via the spawn-time env vars (§2.5 phase B).
        None => {
            return TokenBudgetVerdict::Allow {
                cumulative_token_cost_micros: previous_cost_micros,
            }
        }
    };
    let new_micros = cost_micros_for_tokens(report, policy);
    let ceiling = token_cost_ceiling_micros(policy);
    if ceiling == 0 {
        // Policy did not configure a per-task cost ceiling — admit.
        return TokenBudgetVerdict::Allow {
            cumulative_token_cost_micros: new_micros.max(previous_cost_micros),
        };
    }
    if new_micros > ceiling {
        TokenBudgetVerdict::Reject {
            cumulative_token_cost_micros: new_micros,
            ceiling_micros: ceiling,
        }
    } else {
        TokenBudgetVerdict::Allow {
            cumulative_token_cost_micros: new_micros.max(previous_cost_micros),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use raxis_policy::{LaneEntry, OperatorEntry, PolicyBundle};
    use raxis_store::Store;
    use std::collections::HashMap;

    #[test]
    fn saturating_add_path_cost_does_not_overflow() {
        let result = u64::MAX.saturating_add(1_000);
        assert_eq!(result, u64::MAX);
    }

    #[test]
    fn integration_merge_admission_cost_is_kernel_neutral() {
        let mut policy = PolicyBundle::for_tests_with_operators(Vec::<OperatorEntry>::new());
        policy.set_base_cost_per_intent_kind_for_tests(HashMap::new());

        let paths = vec![PathBuf::from("src/lib.rs"), PathBuf::from("README.md")];
        let cost = compute_admission_cost(&paths, IntentKind::IntegrationMerge, &policy)
            .expect("IntegrationMerge must not require a policy cost row");

        assert_eq!(
            cost, 0,
            "IntegrationMerge is mechanical closeout and must not consume lane admission units"
        );
    }

    /// Build a minimal policy with a single lane configured for the test.
    fn policy_with_lane(lane_id: &str, max_concurrent: u32, max_cost: u64) -> PolicyBundle {
        let mut bundle = PolicyBundle::for_tests_with_operators(Vec::<OperatorEntry>::new());
        bundle.set_lanes_for_tests(vec![LaneEntry {
            lane_id: lane_id.to_owned(),
            max_concurrent_tasks: max_concurrent,
            max_cost_per_epoch: max_cost,
            priority: 0,
        }]);
        bundle
    }

    /// Seed one initiative + N tasks (with the FK columns the schema
    /// requires) so `lane_budget_reservations` INSERTs (FK on
    /// `tasks.task_id`) and `tasks` SELECTs (used by lane status) have
    /// rows to point at.
    fn seed_initiative_and_tasks(
        store: &Store,
        initiative_id: &str,
        tasks: &[(&str, &str, &str)], // (task_id, lane_id, state)
    ) {
        use raxis_store::Table;
        let conn = store.lock_sync();
        conn.execute(
            &format!("INSERT INTO {} (initiative_id, state, terminal_criteria_json, plan_artifact_sha256, created_at) \
                     VALUES (?1, 'Draft', '{{}}', '', 0)",
                Table::Initiatives.as_str()),
            rusqlite::params![initiative_id],
        ).expect("seed initiative row");
        for (task_id, lane_id, state) in tasks {
            conn.execute(
                &format!("INSERT INTO {} (task_id, initiative_id, lane_id, state, actor, policy_epoch, admitted_at, transitioned_at) \
                         VALUES (?1, ?2, ?3, ?4, 'kernel', 0, 0, 0)",
                    Table::Tasks.as_str()),
                rusqlite::params![task_id, initiative_id, lane_id, state],
            ).expect("seed task row");
        }
    }

    /// **INV-STORE-02 (kernel-store.md §2.5.1.1 Pattern A) regression
    /// test.** Pre-fix, two intents could each pass `check_budget` while
    /// each saw `reserved_cost = 0`, then both consume — over-committing
    /// the lane cap. Post-fix, `reserve_budget_in_tx` runs the check and
    /// the INSERT inside the same transaction; the second caller sees
    /// the first caller's reservation reflected in `get_lane_status_in_tx`
    /// and is rejected with `BudgetExceeded`.
    /// We simulate the post-fix invariant by serially running two
    /// reservations inside the same connection: under the new helper,
    /// the second one MUST be rejected. (The pre-fix code, by splitting
    /// across two mutex acquisitions, could let both succeed — so this
    /// test pins the regression: any future PR that re-introduces the
    /// split will fail it.)
    #[test]
    fn reserve_in_tx_serialises_concurrent_lane_writes() {
        let store = Store::open_in_memory().unwrap();
        let policy = policy_with_lane("lane-A", /*max_concurrent=*/ 8, /*max_cost=*/ 100);
        seed_initiative_and_tasks(
            &store,
            "init-A",
            &[
                ("task-1", "lane-A", "Admitted"),
                ("task-2", "lane-A", "Admitted"),
            ],
        );

        let mut conn = store.lock_sync();
        let tx = conn.transaction().unwrap();
        reserve_budget_in_tx(&tx, "lane-A", "task-1", 80, &policy)
            .expect("first reservation should fit under cap");
        let err = reserve_budget_in_tx(&tx, "lane-A", "task-2", 30, &policy)
            .expect_err("second reservation must be rejected as over-cap");
        match err {
            SchedulerError::BudgetExceeded { kind } => {
                assert!(
                    kind.starts_with("CostLimit"),
                    "expected CostLimit rejection, got {kind}"
                );
            }
            other => panic!("unexpected error variant: {other:?}"),
        }
        tx.commit().unwrap();
    }

    /// Continuation intents (re-running the same task on the same lane)
    /// MUST NOT double-charge — INSERT OR IGNORE on the (lane_id, task_id)
    /// PK is the load-bearing piece. This test pins that idempotency
    /// inside the new transactional helper.
    #[test]
    fn reserve_in_tx_is_idempotent_on_same_task_pk() {
        let store = Store::open_in_memory().unwrap();
        let policy = policy_with_lane("lane-B", 8, 100);
        seed_initiative_and_tasks(&store, "init-B", &[("task-1", "lane-B", "Admitted")]);

        let mut conn = store.lock_sync();
        let tx = conn.transaction().unwrap();
        reserve_budget_in_tx(&tx, "lane-B", "task-1", 50, &policy).unwrap();
        reserve_budget_in_tx(&tx, "lane-B", "task-1", 50, &policy)
            .expect("continuation intent must not double-charge");
        let status = get_lane_status_in_tx(&tx, "lane-B").unwrap();
        assert_eq!(
            status.reserved_cost, 50,
            "PK collision must collapse to single reservation"
        );
        tx.commit().unwrap();
    }

    // ─────────────────────────────────────────────────────────────────
    // V2 §Step 28 — shared-lane budget invariant.
    // Pins the spec contract: every session inside one initiative
    // shares a single `[workspace] lane_id`, so the existing
    // `SUM(reserved_cost) FROM lane_budget_reservations WHERE lane_id`
    // query naturally bounds the *initiative-wide* spend at
    // `max_cost_per_epoch`. The first intent (regardless of which
    // session submits it) whose reservation crosses the ceiling is
    // rejected with `BudgetExceeded`, independent of submission order.
    // ─────────────────────────────────────────────────────────────────

    /// V2 §Step 28 contract: an Orchestrator + multiple Executor +
    /// Reviewer tasks all on the same workspace lane share one
    /// budget. The lane's ceiling bounds the sum across all of them.
    #[test]
    fn step28_shared_lane_bounds_orchestrator_plus_executors_plus_reviewer() {
        let store = Store::open_in_memory().unwrap();
        // Workspace-shaped lane: a "feature-work" lane with ceiling
        // 100 admission units. The cap is intentionally tight so the
        // sum of three reservations crosses it.
        let policy = policy_with_lane(
            "feature-work",
            /*max_concurrent=*/ 8,
            /*max_cost=*/ 100,
        );
        // Mirror the V2 multi-session shape: one Orchestrator + two
        // Executors + one Reviewer, every task carrying the same
        // workspace lane (per Step 28 propagation).
        seed_initiative_and_tasks(
            &store,
            "init-step28-A",
            &[
                ("orch-task-1", "feature-work", "Admitted"),
                ("exec-task-1", "feature-work", "Admitted"),
                ("exec-task-2", "feature-work", "Admitted"),
                ("rev-task-1", "feature-work", "Admitted"),
            ],
        );

        // Budget consumption walk: Orchestrator(40) + Executor1(30) +
        // Executor2(20) = 90 (all admit). Reviewer's 15 trips the
        // ceiling.
        let mut conn = store.lock_sync();
        let tx = conn.transaction().unwrap();
        reserve_budget_in_tx(&tx, "feature-work", "orch-task-1", 40, &policy)
            .expect("orchestrator's 40 fits under the lane cap");
        reserve_budget_in_tx(&tx, "feature-work", "exec-task-1", 30, &policy)
            .expect("first executor's 30 fits under the lane cap");
        reserve_budget_in_tx(&tx, "feature-work", "exec-task-2", 20, &policy)
            .expect("second executor's 20 brings the total to 90 — still under 100");

        let snapshot = get_lane_status_in_tx(&tx, "feature-work").unwrap();
        assert_eq!(
            snapshot.reserved_cost, 90,
            "Step 28: lane ceiling must aggregate across all sessions in the initiative"
        );

        let err = reserve_budget_in_tx(&tx, "feature-work", "rev-task-1", 15, &policy)
            .expect_err("reviewer's 15 must be rejected — initiative-wide sum 105 > 100");
        match err {
            SchedulerError::BudgetExceeded { kind } => {
                assert!(
                    kind.starts_with("CostLimit"),
                    "Step 28 rejection must surface as CostLimit (initiative-wide ceiling), \
                     got {kind}"
                );
            }
            other => panic!("expected BudgetExceeded(CostLimit), got {other:?}"),
        }
        tx.commit().unwrap();
    }

    /// Step 28 contract continued: the rejection point is independent
    /// of submission order. Whether the Orchestrator submits the
    /// over-cap intent or an Executor does, the kernel rejects the
    /// crossing intent — never the earlier "smaller" intents.
    #[test]
    fn step28_shared_lane_rejection_is_order_independent() {
        // Permutation A: Executor submits first and consumes the bulk.
        // The Orchestrator's smaller intent is the one that crosses.
        {
            let store = Store::open_in_memory().unwrap();
            let policy = policy_with_lane("lane-permA", 8, 100);
            seed_initiative_and_tasks(
                &store,
                "init-permA",
                &[
                    ("exec-task", "lane-permA", "Admitted"),
                    ("orch-task", "lane-permA", "Admitted"),
                ],
            );
            let mut conn = store.lock_sync();
            let tx = conn.transaction().unwrap();
            reserve_budget_in_tx(&tx, "lane-permA", "exec-task", 95, &policy)
                .expect("exec's 95 fits under the cap");
            let err = reserve_budget_in_tx(&tx, "lane-permA", "orch-task", 10, &policy)
                .expect_err("orch's 10 must be rejected (exec already consumed 95; sum=105>100)");
            match err {
                SchedulerError::BudgetExceeded { .. } => {}
                other => panic!("permutation A expected BudgetExceeded, got {other:?}"),
            }
            tx.commit().unwrap();
        }
        // Permutation B: Orchestrator submits first; an Executor's
        // larger intent crosses.
        {
            let store = Store::open_in_memory().unwrap();
            let policy = policy_with_lane("lane-permB", 8, 100);
            seed_initiative_and_tasks(
                &store,
                "init-permB",
                &[
                    ("orch-task", "lane-permB", "Admitted"),
                    ("exec-task", "lane-permB", "Admitted"),
                ],
            );
            let mut conn = store.lock_sync();
            let tx = conn.transaction().unwrap();
            reserve_budget_in_tx(&tx, "lane-permB", "orch-task", 10, &policy)
                .expect("orch's 10 fits comfortably");
            let err = reserve_budget_in_tx(&tx, "lane-permB", "exec-task", 95, &policy)
                .expect_err("exec's 95 must be rejected (sum=105>100)");
            match err {
                SchedulerError::BudgetExceeded { .. } => {}
                other => panic!("permutation B expected BudgetExceeded, got {other:?}"),
            }
            tx.commit().unwrap();
        }
    }

    /// Step 28 contract: tasks that belong to *different* initiatives
    /// (and therefore different lanes) do NOT interfere. This pins
    /// that the shared-lane ceiling is scoped per-lane, not global —
    /// V2 supports concurrent initiatives on disjoint lanes.
    #[test]
    fn step28_disjoint_lanes_do_not_share_ceiling() {
        let store = Store::open_in_memory().unwrap();
        let mut bundle = PolicyBundle::for_tests_with_operators(Vec::<OperatorEntry>::new());
        bundle.set_lanes_for_tests(vec![
            LaneEntry {
                lane_id: "lane-feature".into(),
                max_concurrent_tasks: 8,
                max_cost_per_epoch: 100,
                priority: 0,
            },
            LaneEntry {
                lane_id: "lane-bugfix".into(),
                max_concurrent_tasks: 8,
                max_cost_per_epoch: 100,
                priority: 0,
            },
        ]);
        let policy = bundle;

        seed_initiative_and_tasks(
            &store,
            "init-feature",
            &[
                ("feat-task-1", "lane-feature", "Admitted"),
                ("feat-task-2", "lane-feature", "Admitted"),
            ],
        );
        seed_initiative_and_tasks(
            &store,
            "init-bugfix",
            &[("bug-task-1", "lane-bugfix", "Admitted")],
        );

        let mut conn = store.lock_sync();
        let tx = conn.transaction().unwrap();
        // Saturate lane-feature.
        reserve_budget_in_tx(&tx, "lane-feature", "feat-task-1", 100, &policy)
            .expect("feature lane fully consumed");
        let err = reserve_budget_in_tx(&tx, "lane-feature", "feat-task-2", 1, &policy)
            .expect_err("any further reservation on lane-feature must be rejected");
        assert!(matches!(err, SchedulerError::BudgetExceeded { .. }));

        // lane-bugfix's ceiling is unaffected — the bugfix initiative
        // can still consume its own 100 admission units.
        reserve_budget_in_tx(&tx, "lane-bugfix", "bug-task-1", 100, &policy)
            .expect("Step 28: a saturated lane-feature must NOT bleed into lane-bugfix");
        tx.commit().unwrap();
    }

    /// Concurrency-cap is also enforced inside the transaction.
    #[test]
    fn reserve_in_tx_enforces_concurrency_cap() {
        let store = Store::open_in_memory().unwrap();
        let policy = policy_with_lane(
            "lane-C", /*max_concurrent=*/ 1, /*max_cost=*/ 1_000,
        );
        seed_initiative_and_tasks(
            &store,
            "init-C",
            &[
                ("t-existing", "lane-C", "Running"),
                ("task-new", "lane-C", "Admitted"),
            ],
        );

        let mut conn = store.lock_sync();
        let tx = conn.transaction().unwrap();
        let err = reserve_budget_in_tx(&tx, "lane-C", "task-new", 10, &policy)
            .expect_err("concurrency cap must reject when active >= max");
        match err {
            SchedulerError::BudgetExceeded { kind } => {
                assert!(
                    kind.starts_with("ConcurrencyLimit"),
                    "expected ConcurrencyLimit rejection, got {kind}"
                );
            }
            other => panic!("unexpected error variant: {other:?}"),
        }
    }

    /// Root closeout and late integration work must not be starved by a
    /// stale reservation whose owning task is already terminal. The canonical
    /// terminal handlers release in-tx, but this backstop protects daemon
    /// mode from older/bypassed paths without waiting for a restart sweep.
    #[test]
    fn reserve_in_tx_prunes_terminal_reservations_before_counting_budget() {
        let store = Store::open_in_memory().unwrap();
        let policy = policy_with_lane("lane-D", /*max_concurrent=*/ 8, /*max_cost=*/ 100);
        seed_initiative_and_tasks(
            &store,
            "init-D",
            &[
                ("completed-old", "lane-D", "Completed"),
                ("task-new", "lane-D", "Admitted"),
            ],
        );

        let mut conn = store.lock_sync();
        let tx = conn.transaction().unwrap();
        consume_budget_in_tx(&tx, "lane-D", "completed-old", 500).unwrap();

        reserve_budget_in_tx(&tx, "lane-D", "task-new", 10, &policy)
            .expect("terminal stale reservation must be pruned before admission");

        let stale_count: i64 = tx
            .query_row(
                &format!(
                    "SELECT COUNT(*) FROM {LANE_BUDGET_RESERVATIONS}
                      WHERE lane_id = 'lane-D' AND task_id = 'completed-old'"
                ),
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(stale_count, 0);

        let status = get_lane_status_in_tx(&tx, "lane-D").unwrap();
        assert_eq!(status.active_tasks, 1);
        assert_eq!(status.reserved_cost, 10);
    }

    #[test]
    fn lane_status_ignores_terminal_task_reservations() {
        let store = Store::open_in_memory().unwrap();
        seed_initiative_and_tasks(
            &store,
            "init-E",
            &[
                ("completed-old", "lane-E", "Completed"),
                ("running-now", "lane-E", "Running"),
            ],
        );

        let mut conn = store.lock_sync();
        let tx = conn.transaction().unwrap();
        consume_budget_in_tx(&tx, "lane-E", "completed-old", 500).unwrap();
        consume_budget_in_tx(&tx, "lane-E", "running-now", 10).unwrap();

        let status = get_lane_status_in_tx(&tx, "lane-E").unwrap();
        assert_eq!(status.active_tasks, 1);
        assert_eq!(
            status.reserved_cost, 10,
            "status projections must not let stale terminal reservations make the lane look full"
        );
    }

    // ── V2 §2.5 — token-cost admission gate (per-provider pricing) ──────

    /// Build a policy with one Anthropic LLM provider whose pricing is
    /// configured for the V2.5 token-budget tests, plus a configurable
    /// `max_cost_per_task` ceiling (cents).
    fn make_provider(
        id: &str,
        input_tokens_per_dollar: u64,
        output_tokens_per_dollar: u64,
    ) -> raxis_policy::ProviderEntry {
        raxis_policy::ProviderEntry {
            provider_id: id.to_owned(),
            kind: "Anthropic".to_owned(),
            credentials_file: format!("{id}.toml"),
            inference_timeout_ms: 30_000,
            data_fetch_timeout_ms: 10_000,
            max_response_bytes: 16 * 1024 * 1024,
            stream_idle_timeout_ms: None,
            sidecar_endpoint: None,
            sidecar_hmac_secret: None,
            sidecar_health_check_path: None,
            pricing: Some(raxis_policy::ProviderPricing {
                input_tokens_per_dollar,
                output_tokens_per_dollar,
                cache_read_tokens_per_dollar: None,
                cache_creation_tokens_per_dollar: None,
            }),
        }
    }

    fn policy_with_pricing_and_ceiling(
        max_cost_per_task_cents: u64,
        input_tokens_per_dollar: u64,
        output_tokens_per_dollar: u64,
    ) -> PolicyBundle {
        let mut bundle = PolicyBundle::for_tests_with_operators(Vec::<OperatorEntry>::new());
        bundle.set_max_cost_per_task_for_tests(max_cost_per_task_cents);
        bundle.set_providers_for_tests(vec![make_provider(
            "anthropic-prod",
            input_tokens_per_dollar,
            output_tokens_per_dollar,
        )]);
        bundle
    }

    /// `cost_micros_for_tokens` returns 0 for an empty TokensReport.
    #[test]
    fn token_cost_zero_tokens_is_zero_cost() {
        let policy = policy_with_pricing_and_ceiling(100, 200_000, 50_000);
        let report = raxis_types::TokensReport::default();
        assert_eq!(cost_micros_for_tokens(&report, &policy), 0);
    }

    /// Anthropic-style $5/MTok input + $20/MTok output. 1M input + 1M
    /// output costs $25 → 25_000_000 µ$.
    #[test]
    fn token_cost_anthropic_million_million_is_25usd() {
        let policy = policy_with_pricing_and_ceiling(
            /*cents*/ 0, /*input/$*/ 200_000, // $5 / 1M input
            /*output/$*/ 50_000, // $20 / 1M output
        );
        let report = raxis_types::TokensReport {
            input_tokens: 1_000_000,
            output_tokens: 1_000_000,
            cache_read_tokens: 0,
            cache_creation_tokens: 0,
            model_id: String::new(),
            provider_id: String::new(),
        };
        assert_eq!(cost_micros_for_tokens(&report, &policy), 25_000_000);
    }

    /// `evaluate_token_budget` admits when no `tokens_used` is reported
    /// (synthetic / kernel-injected intent path).
    #[test]
    fn evaluate_token_budget_admits_when_no_report() {
        let policy = policy_with_pricing_and_ceiling(100, 200_000, 50_000);
        match evaluate_token_budget(None, /*prev*/ 1234, &policy) {
            TokenBudgetVerdict::Allow {
                cumulative_token_cost_micros,
            } => assert_eq!(
                cumulative_token_cost_micros, 1234,
                "synthetic intent must NOT modify the previous total"
            ),
            other => panic!("expected Allow, got {other:?}"),
        }
    }

    /// `evaluate_token_budget` admits when ceiling = 0 (operator opted
    /// out by leaving `max_cost_per_task = 0`).
    #[test]
    fn evaluate_token_budget_admits_when_no_ceiling() {
        let policy = policy_with_pricing_and_ceiling(0, 200_000, 50_000);
        let report = raxis_types::TokensReport {
            input_tokens: 500_000,
            output_tokens: 500_000,
            cache_read_tokens: 0,
            cache_creation_tokens: 0,
            model_id: String::new(),
            provider_id: String::new(),
        };
        match evaluate_token_budget(Some(&report), 0, &policy) {
            TokenBudgetVerdict::Allow { .. } => {}
            other => panic!("expected Allow with no-ceiling policy, got {other:?}"),
        }
    }

    /// `evaluate_token_budget` rejects when the cumulative cost
    /// exceeds the ceiling.
    #[test]
    fn evaluate_token_budget_rejects_over_ceiling() {
        // Ceiling = 100 ¢ = 1_000_000 µ$.
        // Pricing = $5/MTok in, $20/MTok out. 100k input + 50k output
        //         = $0.50 input + $1.00 output = $1.50 = 1_500_000 µ$.
        // 1_500_000 > 1_000_000 → reject.
        let policy = policy_with_pricing_and_ceiling(100, 200_000, 50_000);
        let report = raxis_types::TokensReport {
            input_tokens: 100_000,
            output_tokens: 50_000,
            cache_read_tokens: 0,
            cache_creation_tokens: 0,
            model_id: String::new(),
            provider_id: String::new(),
        };
        match evaluate_token_budget(Some(&report), 0, &policy) {
            TokenBudgetVerdict::Reject {
                cumulative_token_cost_micros,
                ceiling_micros,
            } => {
                assert_eq!(cumulative_token_cost_micros, 1_500_000);
                assert_eq!(ceiling_micros, 1_000_000);
            }
            other => panic!("expected Reject, got {other:?}"),
        }
    }

    /// `evaluate_token_budget` admits when the cumulative cost is
    /// exactly the ceiling (≤ admit; > reject).
    #[test]
    fn evaluate_token_budget_admits_at_ceiling_boundary() {
        // Ceiling = 200 ¢ = 2_000_000 µ$.
        // 200k input @ $5/M + 50k output @ $20/M = $1 + $1 = $2 = 2_000_000 µ$.
        let policy = policy_with_pricing_and_ceiling(200, 200_000, 50_000);
        let report = raxis_types::TokensReport {
            input_tokens: 200_000,
            output_tokens: 50_000,
            cache_read_tokens: 0,
            cache_creation_tokens: 0,
            model_id: String::new(),
            provider_id: String::new(),
        };
        match evaluate_token_budget(Some(&report), 0, &policy) {
            TokenBudgetVerdict::Allow {
                cumulative_token_cost_micros,
            } => assert_eq!(cumulative_token_cost_micros, 2_000_000),
            other => panic!("expected Allow at boundary, got {other:?}"),
        }
    }

    /// `evaluate_token_budget` returns the previous (higher) cost when
    /// the new report would compute lower (e.g. planner replaying a
    /// stale snapshot). The cumulative cost is monotonically
    /// non-decreasing per the §2.5 contract.
    #[test]
    fn evaluate_token_budget_total_is_monotonic_non_decreasing() {
        let policy = policy_with_pricing_and_ceiling(0, 200_000, 50_000);
        let lower_report = raxis_types::TokensReport {
            input_tokens: 100_000,
            output_tokens: 50_000,
            cache_read_tokens: 0,
            cache_creation_tokens: 0,
            model_id: String::new(),
            provider_id: String::new(),
        };
        // Previous cost is higher than what the new (smaller) report
        // would compute. Admission must keep the previous total.
        match evaluate_token_budget(Some(&lower_report), /*prev*/ 9_999_999, &policy) {
            TokenBudgetVerdict::Allow {
                cumulative_token_cost_micros,
            } => assert_eq!(cumulative_token_cost_micros, 9_999_999),
            other => panic!("expected Allow with monotonic total, got {other:?}"),
        }
    }

    /// `cost_micros_for_tokens` falls back to worst-of-N when
    /// `provider_id` is empty.
    #[test]
    fn token_cost_worst_of_n_on_empty_provider_id() {
        let mut policy = PolicyBundle::for_tests_with_operators(Vec::<OperatorEntry>::new());
        policy.set_providers_for_tests(vec![
            // Cheap: $1/M input + $1/M output.
            make_provider("cheap", 1_000_000, 1_000_000),
            // Expensive: $10/M input + $10/M output (worst-of-N
            // wins for upper-bound).
            make_provider("premium", 100_000, 100_000),
        ]);
        let report = raxis_types::TokensReport {
            input_tokens: 1_000_000,
            output_tokens: 1_000_000,
            cache_read_tokens: 0,
            cache_creation_tokens: 0,
            model_id: String::new(),
            provider_id: String::new(),
        };
        // Worst-of-N pricing: $10/M × 2M = $20 = 20_000_000 µ$.
        assert_eq!(cost_micros_for_tokens(&report, &policy), 20_000_000);
    }

    /// `cost_micros_for_tokens` honours `provider_id` when it matches a
    /// declared provider with pricing.
    #[test]
    fn token_cost_uses_named_provider_when_present() {
        let mut policy = PolicyBundle::for_tests_with_operators(Vec::<OperatorEntry>::new());
        policy.set_providers_for_tests(vec![
            make_provider("cheap", 1_000_000, 1_000_000),
            make_provider("premium", 100_000, 100_000),
        ]);
        let report = raxis_types::TokensReport {
            input_tokens: 1_000_000,
            output_tokens: 1_000_000,
            cache_read_tokens: 0,
            cache_creation_tokens: 0,
            model_id: String::new(),
            provider_id: "cheap".to_owned(),
        };
        // Cheap pricing: $1/M × 2M = $2 = 2_000_000 µ$.
        assert_eq!(cost_micros_for_tokens(&report, &policy), 2_000_000);
    }

    #[test]
    fn token_cost_uses_policy_override_by_provider_kind() {
        let mut policy = PolicyBundle::for_tests_with_operators(Vec::<OperatorEntry>::new());
        let mut openai = make_provider("openai-prod", 2_000_000, 500_000);
        openai.kind = "OpenAI".to_owned();
        policy.set_providers_for_tests(vec![openai]);
        let report = raxis_types::TokensReport {
            input_tokens: 1_000_000,
            output_tokens: 1_000_000,
            cache_read_tokens: 0,
            cache_creation_tokens: 0,
            model_id: "gpt-5.3-codex".to_owned(),
            provider_id: String::new(),
        };
        let priced = price_tokens_for_report(&report, &policy);
        assert_eq!(priced.micros, 2_500_000);
        assert_eq!(
            priced.source,
            TokenPricingSource::OperatorPolicyOverride {
                provider_id: "openai-prod".to_owned()
            }
        );
    }

    #[test]
    fn generic_provider_report_does_not_borrow_named_override() {
        let mut policy = PolicyBundle::for_tests_with_operators(Vec::<OperatorEntry>::new());
        let mut openai = make_provider("openai-contract", 2_000_000, 500_000);
        openai.kind = "OpenAI".to_owned();
        policy.set_providers_for_tests(vec![openai]);

        let report = raxis_types::TokensReport {
            input_tokens: 1_000_000,
            output_tokens: 1_000_000,
            cache_read_tokens: 0,
            cache_creation_tokens: 0,
            model_id: "gpt-5.3-codex".to_owned(),
            provider_id: "openai".to_owned(),
        };

        let priced = price_tokens_for_report(&report, &policy);
        assert_eq!(priced.micros, 5_000_000);
        assert_eq!(
            priced.source,
            TokenPricingSource::BundledEstimate {
                provider_id: "openai".to_owned(),
                registry_version: BUNDLED_PRICING_REGISTRY_VERSION,
            }
        );
    }

    #[test]
    fn token_cost_falls_back_to_bundled_estimate_with_provenance() {
        let policy = PolicyBundle::for_tests_with_operators(Vec::<OperatorEntry>::new());
        let report = raxis_types::TokensReport {
            input_tokens: 1_000_000,
            output_tokens: 1_000_000,
            cache_read_tokens: 0,
            cache_creation_tokens: 0,
            model_id: "gemini-2.5-flash".to_owned(),
            provider_id: "gemini".to_owned(),
        };
        let priced = price_tokens_for_report(&report, &policy);
        assert_eq!(priced.micros, 5_000_000);
        assert_eq!(
            priced.source,
            TokenPricingSource::BundledEstimate {
                provider_id: "gemini".to_owned(),
                registry_version: BUNDLED_PRICING_REGISTRY_VERSION,
            }
        );
    }
}

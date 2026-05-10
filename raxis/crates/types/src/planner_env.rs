// raxis-types::planner_env — the env-var names the kernel stamps
// into spawned planner-VM env tables and the planner-core driver
// reads at boot.
//
// Why these live in `raxis-types` rather than `raxis-planner-core`:
// the kernel (writer) and `raxis-planner-core` (reader) form the two
// halves of the contract. Both crates already depend on
// `raxis-types` (the shared "no-I/O, no-async, pure data" boundary
// per `philosophy.md §1.5`), but `raxis-planner-core` pulls in
// `reqwest` and other HTTP-tier deps that the kernel does not need.
// Co-locating the env-name constants here keeps the contract DRY
// without dragging the planner-core dep tree into the kernel.
//
// **Stable wire.** Renaming any constant in this file is a breaking
// change for every spawned planner VM that consumed the previous
// name. Treat each rename as a wire-protocol bump and update the
// spec (`v2_extended_gaps.md §1.1` / `§2.4` / `§2.5`) in lockstep.

/// V2 `v2_extended_gaps.md §1.1` — operator-authored seed prompt
/// for the spawned planner agent. Kernel stamps this from
/// `[plan.initiative].description` (orchestrator) /
/// `[[tasks]].description` (executor / reviewer); the planner
/// driver reads it as the first user-message turn. Admission
/// rejects empty / missing values with `FAIL_PLAN_PARSE_ERROR`, so
/// by construction this var is always present and non-empty when
/// the planner boots.
pub const PLANNER_TASK_PROMPT_ENV: &str = "RAXIS_PLANNER_TASK_PROMPT";

/// V2 `v2_extended_gaps.md §2.4` — JSON-encoded
/// `raxis_ksb::KsbSnapshot` carrying the per-turn kernel state
/// block. Kernel assembles via `crate::initiatives::ksb_assembly`;
/// driver deserialises and folds into the system prompt via
/// `raxis_ksb::assemble_system_prompt`. Mirrors
/// `raxis_ksb::PLANNER_KSB_ENV` — both constants are required to
/// stay in lock-step (a `debug_assert_eq!` in `raxis-ksb` tests
/// pins this).
pub const PLANNER_KSB_ENV: &str = "RAXIS_PLANNER_KSB";

/// V2 `v2_extended_gaps.md §2.5` — per-session cumulative *input*
/// token cap. Kernel stamps from
/// `policy.budget.token_caps.max_input_tokens_per_session` when the
/// operator declared it; absent ⇒ uncapped on this axis.
/// In-VM dispatch loop folds into
/// `DispatchConfig::max_tokens_input_total`.
pub const PLANNER_MAX_TOKENS_INPUT_TOTAL_ENV:  &str = "RAXIS_PLANNER_MAX_TOKENS_INPUT_TOTAL";

/// V2 `v2_extended_gaps.md §2.5` — per-session cumulative *output*
/// token cap. Kernel stamps from
/// `policy.budget.token_caps.max_output_tokens_per_session`.
pub const PLANNER_MAX_TOKENS_OUTPUT_TOTAL_ENV: &str = "RAXIS_PLANNER_MAX_TOKENS_OUTPUT_TOTAL";

/// V2 `v2_extended_gaps.md §2.5` — per-session cumulative
/// *combined* (input + output) token cap. Kernel stamps from
/// `policy.budget.token_caps.max_total_tokens_per_session`.
pub const PLANNER_MAX_TOKENS_TOTAL_ENV:        &str = "RAXIS_PLANNER_MAX_TOKENS_TOTAL";

/// V2 `v2_extended_gaps.md §3.1` — per-call ceiling for the `sleep`
/// planner tool. Kernel stamps from
/// `policy.budget.sleep_caps.max_seconds_per_call`. Absent ⇒ tool
/// is registered as `SleepTool::disabled()` and refuses every
/// invocation with `FAIL_SLEEP_DISABLED`.
pub const PLANNER_MAX_SLEEP_PER_CALL_ENV:      &str = "RAXIS_PLANNER_MAX_SLEEP_SECONDS_PER_CALL";

/// V2 `v2_extended_gaps.md §3.1` — cumulative ceiling across the
/// session for the `sleep` planner tool. Kernel stamps from
/// `policy.budget.sleep_caps.max_cumulative_seconds`. MUST be ≥
/// `PLANNER_MAX_SLEEP_PER_CALL_ENV` (validated at policy load time).
pub const PLANNER_MAX_SLEEP_CUMULATIVE_ENV:    &str = "RAXIS_PLANNER_MAX_CUMULATIVE_SLEEP_SECONDS";

#[cfg(test)]
mod tests {
    use super::*;

    /// Pins the wire-stable string values of every env constant in
    /// this module. Renaming any of them is a breaking change for
    /// every spawned planner VM that consumed the previous name —
    /// this test fails on every rename so the change author is
    /// forced to update the spec (`v2_extended_gaps.md §§1.1, 2.4,
    /// 2.5, 3.1`) and the planner-core mirror constants in lockstep.
    #[test]
    fn env_names_are_stable_wire() {
        assert_eq!(PLANNER_TASK_PROMPT_ENV,            "RAXIS_PLANNER_TASK_PROMPT");
        assert_eq!(PLANNER_KSB_ENV,                    "RAXIS_PLANNER_KSB");
        assert_eq!(PLANNER_MAX_TOKENS_INPUT_TOTAL_ENV, "RAXIS_PLANNER_MAX_TOKENS_INPUT_TOTAL");
        assert_eq!(PLANNER_MAX_TOKENS_OUTPUT_TOTAL_ENV,"RAXIS_PLANNER_MAX_TOKENS_OUTPUT_TOTAL");
        assert_eq!(PLANNER_MAX_TOKENS_TOTAL_ENV,       "RAXIS_PLANNER_MAX_TOKENS_TOTAL");
        assert_eq!(PLANNER_MAX_SLEEP_PER_CALL_ENV,
                   "RAXIS_PLANNER_MAX_SLEEP_SECONDS_PER_CALL");
        assert_eq!(PLANNER_MAX_SLEEP_CUMULATIVE_ENV,
                   "RAXIS_PLANNER_MAX_CUMULATIVE_SLEEP_SECONDS");
    }
}

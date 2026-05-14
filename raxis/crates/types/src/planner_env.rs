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

/// V2 `v2_extended_gaps.md §1.1` — guest-visible absolute path of a
/// virtiofs sidecar file containing the operator-authored seed
/// prompt (the same byte-shape [`PLANNER_TASK_PROMPT_ENV`] would
/// carry inline).
///
/// Why a sidecar exists. The Apple-VZ substrate has no
/// `Command::env` analogue and folds [`raxis_isolation::VmSpec::env`]
/// into the Linux `/proc/cmdline` as a single base64-encoded token
/// (`raxis.envb64=<base64>`). Linux's `COMMAND_LINE_SIZE` ceiling on
/// aarch64 (default 2048 bytes) means a task prompt of more than
/// ~1 KiB can push the cmdline past the boot loader's truncation
/// point — which silently drops the trailing
/// `-- --task-id <ID> --initiative-id <ID>` argv tail and produces
/// a guest-side `bad-env-token: base64 decode: Invalid padding`
/// followed by `missing value for flag: --initiative-id`. The
/// realistic-scenario executor prompts (`materializer.md`,
/// `service_round_trip.md`, …) are 2–7 KiB which after base64
/// expansion (4/3) reliably exceeds the budget.
///
/// The sidecar shifts the prompt out of the cmdline into the same
/// per-session virtiofs mount that already carries the KSB
/// snapshot ([`PLANNER_KSB_PATH_ENV`] / [`raxis_ksb::
/// PLANNER_KSB_GUEST_MOUNT`]). The driver reads from the path when
/// present and falls back to [`PLANNER_TASK_PROMPT_ENV`] when only
/// the env var is set, so legacy callers (subprocess-isolation
/// tests with `data_dir = None`, older kernel revisions) keep
/// working.
pub const PLANNER_TASK_PROMPT_PATH_ENV: &str = "RAXIS_PLANNER_TASK_PROMPT_PATH";

/// V2 `v2_extended_gaps.md §2.4` — JSON-encoded
/// `raxis_ksb::KsbSnapshot` carrying the per-turn kernel state
/// block. Kernel assembles via `crate::initiatives::ksb_assembly`;
/// driver deserialises and folds into the system prompt via
/// `raxis_ksb::assemble_system_prompt`. Mirrors
/// `raxis_ksb::PLANNER_KSB_ENV` — both constants are required to
/// stay in lock-step (a `debug_assert_eq!` in `raxis-ksb` tests
/// pins this).
pub const PLANNER_KSB_ENV: &str = "RAXIS_PLANNER_KSB";

/// V2 `v2_extended_gaps.md §2.5` (planner-harness ceiling) — per-session
/// hard turn ceiling for the in-VM planner dispatch loop. Kernel stamps
/// the value resolved by the per-task `max_turns` precedence chain
/// (per-task → `[gateway].planner_max_turns_default` → compiled
/// [`raxis_planner_core::DEFAULT_PLANNER_MAX_TURNS`]). The driver reads
/// it at boot and folds into `DispatchConfig::max_turns`; the dispatch
/// loop terminates with `Outcome::TurnsExceeded` on hit.
///
/// Per `INV-PLANNER-MAX-TURNS-PRECEDENCE-01`: this stamp MUST be
/// explicit (the kernel resolves the per-task value and writes the
/// resolved integer into the spawned VM's env table). Pre-V2.7
/// kernel revisions inherited the value from the parent process env;
/// the explicit stamp closes that drift channel so a per-task
/// override is mechanically guaranteed.
pub const PLANNER_MAX_TURNS_ENV:               &str = "RAXIS_PLANNER_MAX_TURNS";

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

/// V2_GAPS §C5 + `extensibility-traits.md §9A.5` — base URL of the
/// operator-run sidecar process when the resolved model maps to a
/// `policy.toml [[providers]] kind = "http_sidecar"` row. Kernel
/// stamps verbatim from `ProviderEntry::sidecar_endpoint`. Empty
/// or absent ⇒ planner refuses to boot a sidecar provider with
/// `DriverError::SidecarEnvMissing`.
pub const PLANNER_SIDECAR_ENDPOINT_ENV:        &str = "RAXIS_PLANNER_SIDECAR_ENDPOINT";

/// V2_GAPS §C5 — logical sidecar provider id (matches the policy
/// `[[providers]] provider_id` row). The sidecar HMAC handshake
/// stamps this value into the request body so the sidecar can
/// disambiguate per-deployment routing keys.
pub const PLANNER_SIDECAR_PROVIDER_ID_ENV:     &str = "RAXIS_PLANNER_SIDECAR_PROVIDER_ID";

/// V2_GAPS §C5 + `extensibility-traits.md §9A.7A` — 32-byte HMAC
/// shared secret in lowercase hex (64 chars). Kernel stamps from
/// `ProviderEntry::sidecar_hmac_secret`. **Operator MUST rotate
/// per-spawn** (the kernel mints fresh material each time so a
/// compromised planner cannot replay across spawns). NEVER logged.
pub const PLANNER_SIDECAR_HMAC_SECRET_ENV:     &str = "RAXIS_PLANNER_SIDECAR_HMAC_SECRET";

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
        assert_eq!(PLANNER_TASK_PROMPT_PATH_ENV,       "RAXIS_PLANNER_TASK_PROMPT_PATH");
        assert_eq!(PLANNER_KSB_ENV,                    "RAXIS_PLANNER_KSB");
        assert_eq!(PLANNER_MAX_TURNS_ENV,              "RAXIS_PLANNER_MAX_TURNS");
        assert_eq!(PLANNER_MAX_TOKENS_INPUT_TOTAL_ENV, "RAXIS_PLANNER_MAX_TOKENS_INPUT_TOTAL");
        assert_eq!(PLANNER_MAX_TOKENS_OUTPUT_TOTAL_ENV,"RAXIS_PLANNER_MAX_TOKENS_OUTPUT_TOTAL");
        assert_eq!(PLANNER_MAX_TOKENS_TOTAL_ENV,       "RAXIS_PLANNER_MAX_TOKENS_TOTAL");
        assert_eq!(PLANNER_MAX_SLEEP_PER_CALL_ENV,
                   "RAXIS_PLANNER_MAX_SLEEP_SECONDS_PER_CALL");
        assert_eq!(PLANNER_MAX_SLEEP_CUMULATIVE_ENV,
                   "RAXIS_PLANNER_MAX_CUMULATIVE_SLEEP_SECONDS");
        assert_eq!(PLANNER_SIDECAR_ENDPOINT_ENV,
                   "RAXIS_PLANNER_SIDECAR_ENDPOINT");
        assert_eq!(PLANNER_SIDECAR_PROVIDER_ID_ENV,
                   "RAXIS_PLANNER_SIDECAR_PROVIDER_ID");
        assert_eq!(PLANNER_SIDECAR_HMAC_SECRET_ENV,
                   "RAXIS_PLANNER_SIDECAR_HMAC_SECRET");
    }
}

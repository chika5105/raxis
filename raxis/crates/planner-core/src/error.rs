//! Planner-harness error taxonomy.
//! Each variant maps to a structured exit code in the binary's
//! `main`. The convention is:
//!   * exit-code `0`  — clean shutdown signalled by the kernel
//!   * exit-code `2`  — argv contract violation
//!     ([`PlannerError::BadArg`], [`PlannerError::MissingValue`],
//!     [`PlannerError::EmptyValue`], [`PlannerError::DuplicateFlag`],
//!     [`PlannerError::UnknownFlag`], [`PlannerError::UnexpectedFlag`])
//!   * exit-code `3`  — environment contract violation
//!     ([`PlannerError::MissingEnv`], [`PlannerError::EmptyEnv`])
//!   * exit-code `4`  — dispatch loop hit `MaxTurnsExceeded`
//!     (`planner-harness.md INV-PLANNER-HARNESS-04`)
//!   * exit-code `5`  — dispatch loop terminated with `Idle` for a
//!     role that requires a terminal action
//!     (orchestrator/executor — reviewer Idle is allowed via
//!     scaffold path)
//!   * exit-code `6`  — cumulative token ceiling tripped
//!   * exit-code `7`  — driver failure (transport, model, intent
//!     submission). Stderr carries the structured detail.
//! These exit codes are chosen so the kernel-side `SessionVmExited`
//! audit event carries enough information to distinguish a planner
//! crash from a kernel-substrate-supplied bad spec without having
//! to parse the guest's stderr.

use thiserror::Error;

/// Errors a planner-role binary can surface during the boot pre-amble.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum PlannerError {
    /// Generic argv decoding failure (non-UTF-8 etc.).
    #[error("bad argument: {0}")]
    BadArg(&'static str),

    /// A flag was supplied without a value (e.g. `--initiative-id`
    /// at end of argv).
    #[error("missing value for flag: {0}")]
    MissingValue(&'static str),

    /// A flag's value was the empty string.
    #[error("empty value for flag: {0}")]
    EmptyValue(&'static str),

    /// The same flag was supplied twice.
    #[error("duplicate flag: {0}")]
    DuplicateFlag(&'static str),

    /// An unknown flag was supplied. Unlike `getopts`-style parsers
    /// we do not silently ignore — the kernel-side argv stamping is
    /// fully under our control, so any unknown flag is a kernel bug
    /// we want to surface loudly.
    #[error("unknown flag: {0}")]
    UnknownFlag(String),

    /// A flag was supplied that this role does not accept (e.g.
    /// `--task-id` to the orchestrator binary).
    #[error("unexpected flag: {0}")]
    UnexpectedFlag(&'static str),

    /// A required environment variable was missing.
    #[error("missing required environment variable: {0}")]
    MissingEnv(&'static str),

    /// A required environment variable was set to the empty string.
    #[error("empty value for required environment variable: {0}")]
    EmptyEnv(&'static str),

    /// V2.4 — dispatch loop hit `max_turns`. Mirrors
    /// [`crate::dispatch::DispatchOutcome::MaxTurnsExceeded`].
    #[error("dispatch loop exceeded max_turns: {turns}")]
    MaxTurnsExceeded {
        /// Configured max turns ceiling.
        turns: u32,
    },

    /// V2.4 — dispatch loop returned `Idle` (model said it was
    /// done with no tool_use blocks) for a role where that is a
    /// failure condition (orchestrator / executor).
    #[error("dispatch loop terminated with Idle (no terminal tool fired)")]
    DispatchIdle,

    /// V2.4 — cumulative session token total exceeded a configured
    /// ceiling. Mirrors
    /// [`crate::dispatch::DispatchOutcome::TokensExceeded`].
    #[error("dispatch loop tripped token ceiling \"{which}\" at {ceiling}")]
    TokensExceeded {
        /// Stable wire short-string: `"input"` / `"output"` /
        /// `"total"` (matches the spec's
        /// `token-limit-enforcement.md §2 Coarse table`).
        which: &'static str,
        /// The configured ceiling that was hit.
        ceiling: u64,
    },

    /// V2.4 — driver pre-/post-loop failure (transport setup,
    /// model client error, intent submission). The stderr detail
    /// is the `crate::driver::DriverError::to_string` output.
    #[error("driver failure: {0}")]
    DriverFailure(String),
}

impl PlannerError {
    /// Process exit code matching the conventions above.
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::BadArg(_)
            | Self::MissingValue(_)
            | Self::EmptyValue(_)
            | Self::DuplicateFlag(_)
            | Self::UnknownFlag(_)
            | Self::UnexpectedFlag(_) => 2,
            Self::MissingEnv(_) | Self::EmptyEnv(_) => 3,
            Self::MaxTurnsExceeded { .. } => 4,
            Self::DispatchIdle => 5,
            Self::TokensExceeded { .. } => 6,
            Self::DriverFailure(_) => 7,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn argv_errors_map_to_exit_code_2() {
        assert_eq!(PlannerError::BadArg("x").exit_code(), 2);
        assert_eq!(PlannerError::MissingValue("--x").exit_code(), 2);
        assert_eq!(PlannerError::EmptyValue("--x").exit_code(), 2);
        assert_eq!(PlannerError::DuplicateFlag("--x").exit_code(), 2);
        assert_eq!(PlannerError::UnknownFlag("x".into()).exit_code(), 2);
        assert_eq!(PlannerError::UnexpectedFlag("--x").exit_code(), 2);
    }

    #[test]
    fn env_errors_map_to_exit_code_3() {
        assert_eq!(PlannerError::MissingEnv("FOO").exit_code(), 3);
        assert_eq!(PlannerError::EmptyEnv("FOO").exit_code(), 3);
    }

    #[test]
    fn dispatch_outcome_errors_map_to_distinct_exit_codes() {
        assert_eq!(PlannerError::MaxTurnsExceeded { turns: 20 }.exit_code(), 4);
        assert_eq!(PlannerError::DispatchIdle.exit_code(), 5);
        assert_eq!(
            PlannerError::TokensExceeded {
                which: "total",
                ceiling: 1000
            }
            .exit_code(),
            6,
        );
        assert_eq!(PlannerError::DriverFailure("any".to_owned()).exit_code(), 7);
    }
}

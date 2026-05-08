//! Planner-harness error taxonomy.
//!
//! Each variant maps to a structured exit code in the binary's
//! `main`. The convention is:
//!
//!   * exit-code `0`  — clean shutdown signalled by the kernel
//!   * exit-code `2`  — argv contract violation
//!     ([`PlannerError::BadArg`], [`PlannerError::MissingValue`],
//!     [`PlannerError::EmptyValue`], [`PlannerError::DuplicateFlag`],
//!     [`PlannerError::UnknownFlag`], [`PlannerError::UnexpectedFlag`])
//!   * exit-code `3`  — environment contract violation
//!     ([`PlannerError::MissingEnv`], [`PlannerError::EmptyEnv`])
//!
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
}

impl PlannerError {
    /// Process exit code matching the conventions above.
    pub const fn exit_code(&self) -> i32 {
        match self {
            Self::BadArg(_)
            | Self::MissingValue(_)
            | Self::EmptyValue(_)
            | Self::DuplicateFlag(_)
            | Self::UnknownFlag(_)
            | Self::UnexpectedFlag(_) => 2,
            Self::MissingEnv(_)
            | Self::EmptyEnv(_)       => 3,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn argv_errors_map_to_exit_code_2() {
        assert_eq!(PlannerError::BadArg("x").exit_code(),         2);
        assert_eq!(PlannerError::MissingValue("--x").exit_code(), 2);
        assert_eq!(PlannerError::EmptyValue("--x").exit_code(),   2);
        assert_eq!(PlannerError::DuplicateFlag("--x").exit_code(),2);
        assert_eq!(PlannerError::UnknownFlag("x".into()).exit_code(), 2);
        assert_eq!(PlannerError::UnexpectedFlag("--x").exit_code(), 2);
    }

    #[test]
    fn env_errors_map_to_exit_code_3() {
        assert_eq!(PlannerError::MissingEnv("FOO").exit_code(), 3);
        assert_eq!(PlannerError::EmptyEnv("FOO").exit_code(),   3);
    }
}

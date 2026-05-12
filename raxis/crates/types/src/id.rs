// raxis-types::id — Newtype wrappers for all identifiers in RAXIS.
//
// Normative reference: kernel-store.md §2.5.1 (DDL column types and TEXT
// invariants), peripherals.md §3.1 (wire field rules).
//
// Every identifier is a validated newtype. Construction via `::new()` or
// `::parse()` validates the invariant; direct field access is prevented by
// the private inner field. This means a `CommitSha` in any function signature
// is guaranteed to be a valid 40-char lowercase hex string — no runtime checks
// needed at use sites.

use serde::{Deserialize, Serialize};
use std::fmt;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Macro: define a newtype wrapping a String with a private field.
// ---------------------------------------------------------------------------
macro_rules! string_id {
    (
        $(#[$attr:meta])*
        $name:ident
    ) => {
        $(#[$attr])*
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            /// Wrap an already-validated string. Callers inside this crate only.
            #[allow(dead_code)]
            pub(crate) fn from_string_unchecked(s: String) -> Self {
                Self(s)
            }

            /// Return the inner string slice.
            pub fn as_str(&self) -> &str {
                &self.0
            }

            /// Consume into the inner String.
            pub fn into_inner(self) -> String {
                self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                &self.0
            }
        }
    };
}

// ---------------------------------------------------------------------------
// UUID-based identifiers
// Invariant: hyphenated UUID v4 string (36 ASCII chars).
// DDL: TEXT (kernel-store.md §2.5.1 Tables 2, 4, 5, 7, 9, 12, etc.)
// ---------------------------------------------------------------------------

macro_rules! uuid_id {
    (
        $(#[$attr:meta])*
        $name:ident
    ) => {
        string_id! {
            $(#[$attr])*
            $name
        }

        impl $name {
            /// Generate a new random UUID v4 identifier.
            pub fn new_v4() -> Self {
                Self(Uuid::new_v4().hyphenated().to_string())
            }

            /// Parse from a hyphenated UUID string. Returns an error if the
            /// input is not a valid UUID.
            pub fn parse(s: &str) -> Result<Self, uuid::Error> {
                let u = Uuid::parse_str(s)?;
                Ok(Self(u.hyphenated().to_string()))
            }
        }

        impl TryFrom<String> for $name {
            type Error = uuid::Error;
            fn try_from(s: String) -> Result<Self, Self::Error> {
                Self::parse(&s)
            }
        }

        impl TryFrom<&str> for $name {
            type Error = uuid::Error;
            fn try_from(s: &str) -> Result<Self, Self::Error> {
                Self::parse(s)
            }
        }
    };
}

uuid_id! {
    /// Unique identifier for a kernel session (planner, gateway, or verifier).
    /// kernel-store.md §2.5.1 Table 4 `sessions.session_id TEXT NOT NULL`.
    SessionId
}

uuid_id! {
    /// Unique identifier for an initiative (the lifecycle unit that wraps a
    /// signed plan). kernel-store.md §2.5.1 Table 2 `initiatives.initiative_id`.
    InitiativeId
}

uuid_id! {
    /// Unique identifier for a capability delegation row.
    /// kernel-store.md §2.5.1 Table 7 `delegations.delegation_id`.
    DelegationId
}

uuid_id! {
    /// Unique identifier for a pending or resolved escalation.
    /// kernel-store.md §2.5.1 Table 9 `escalations.escalation_id`.
    EscalationId
}

uuid_id! {
    /// Unique identifier for a single verifier subprocess run.
    /// kernel-store.md §2.5.1 Table 12 `verifier_run_tokens.verifier_run_id`.
    VerifierRunId
}

uuid_id! {
    /// Lineage identifier — stable across sessions of the same logical agent.
    /// Rate-limiting and quarantine key on this value.
    /// kernel-store.md §2.5.1 Table 4 `sessions.lineage_id TEXT NOT NULL`.
    LineageId
}

// ---------------------------------------------------------------------------
// TaskId — text identifier from the signed plan, not a UUID.
// Invariant: non-empty string, max 128 chars, validated at plan-load time.
// DDL: TEXT NOT NULL (kernel-store.md §2.5.1 Table 5 `tasks.task_id`).
// ---------------------------------------------------------------------------
string_id! {
    /// A task identifier as declared in the signed plan.toml.
    /// Not a UUID — operator-chosen string (e.g. "task-alpha", "task-1-foundation").
    TaskId
}

impl TaskId {
    /// Validate and wrap a task ID string.
    /// Rule: non-empty, max 128 bytes of UTF-8, no control characters.
    pub fn parse(s: &str) -> Result<Self, TaskIdError> {
        if s.is_empty() {
            return Err(TaskIdError::Empty);
        }
        if s.len() > 128 {
            return Err(TaskIdError::TooLong(s.len()));
        }
        if s.chars().any(|c| c.is_control()) {
            return Err(TaskIdError::InvalidChar);
        }
        Ok(Self(s.to_owned()))
    }
}

impl TryFrom<String> for TaskId {
    type Error = TaskIdError;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::parse(&s)
    }
}

impl TryFrom<&str> for TaskId {
    type Error = TaskIdError;
    fn try_from(s: &str) -> Result<Self, Self::Error> {
        Self::parse(s)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TaskIdError {
    #[error("task_id must not be empty")]
    Empty,
    #[error("task_id is {0} bytes, exceeds 128-byte limit")]
    TooLong(usize),
    #[error("task_id contains a control character")]
    InvalidChar,
}

// ---------------------------------------------------------------------------
// CommitSha — 40-char lowercase hex Git commit OID.
// Invariant: exactly 40 lowercase hex chars.
// Normative: peripherals.md §3.1 field rules for `base_sha` / `head_sha`.
// ---------------------------------------------------------------------------
string_id! {
    /// A validated Git commit OID (40 lowercase hex characters).
    CommitSha
}

impl CommitSha {
    /// Parse and validate a 40-char lowercase hex string.
    pub fn parse(s: &str) -> Result<Self, CommitShaError> {
        if s.len() != 40 {
            return Err(CommitShaError::WrongLength(s.len()));
        }
        if !s.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f')) {
            return Err(CommitShaError::InvalidHex);
        }
        Ok(Self(s.to_owned()))
    }
}

impl TryFrom<String> for CommitSha {
    type Error = CommitShaError;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::parse(&s)
    }
}

impl TryFrom<&str> for CommitSha {
    type Error = CommitShaError;
    fn try_from(s: &str) -> Result<Self, Self::Error> {
        Self::parse(s)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CommitShaError {
    #[error("commit SHA must be exactly 40 hex chars, got {0}")]
    WrongLength(usize),
    #[error("commit SHA contains non-lowercase-hex character")]
    InvalidHex,
}

// ---------------------------------------------------------------------------
// GateType — string name of a gate type, matching [[gates]].gate_type in policy.
// Invariant: non-empty, ≤64 chars, Rust-identifier-safe chars only.
// Normative: kernel-store.md §2.5.6 `gate_type` column.
// ---------------------------------------------------------------------------
string_id! {
    /// The string name of a gate type as declared in `[[gates]].gate_type`.
    /// Examples: "TestCoverage", "LintClean", "RustBuild_Linux".
    GateType
}

impl GateType {
    pub fn parse(s: &str) -> Result<Self, GateTypeError> {
        if s.is_empty() {
            return Err(GateTypeError::Empty);
        }
        if s.len() > 64 {
            return Err(GateTypeError::TooLong(s.len()));
        }
        if !s
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        {
            return Err(GateTypeError::InvalidChar);
        }
        Ok(Self(s.to_owned()))
    }
}

impl TryFrom<String> for GateType {
    type Error = GateTypeError;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::parse(&s)
    }
}

impl TryFrom<&str> for GateType {
    type Error = GateTypeError;
    fn try_from(s: &str) -> Result<Self, Self::Error> {
        Self::parse(s)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GateTypeError {
    #[error("gate_type must not be empty")]
    Empty,
    #[error("gate_type is {0} bytes, exceeds 64-byte limit")]
    TooLong(usize),
    #[error("gate_type contains a character that is not alphanumeric, '_', or '-'")]
    InvalidChar,
}

// ---------------------------------------------------------------------------
// UnixSeconds — i64 Unix timestamp (seconds since epoch, UTC).
// DDL: INTEGER NOT NULL in all timestamp columns.
// ---------------------------------------------------------------------------

/// A Unix timestamp in whole seconds (UTC). Stored as i64 to handle
/// pre-epoch values in test fixtures without special-casing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct UnixSeconds(pub i64);

impl UnixSeconds {
    /// Wall-clock "now" as a `UnixSeconds`. A host whose clock is set
    /// to before 1970-01-01 (no-RTC / pre-NTP boot) yields `Err` from
    /// `duration_since(UNIX_EPOCH)`; this method saturates to 0 rather
    /// than panic, matching the documented contract of
    /// `crate::clock::unix_now_secs` (the workspace's canonical wall
    /// clock helper). The relative-time invariants RAXIS depends on
    /// (TTLs, deadlines, cooldown windows) compare two reads from the
    /// same `Clock` instance, so both reads being `0` together still
    /// preserves the ordering contract.
    pub fn now() -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};
        Self(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0),
        )
    }

    pub fn as_i64(self) -> i64 {
        self.0
    }
}

impl fmt::Display for UnixSeconds {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

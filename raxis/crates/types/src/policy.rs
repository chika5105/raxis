// raxis-types::policy — Policy-related types shared across the workspace.
//
// Normative reference:
//   - philosophy.md §1.6 (Role enum)
//   - kernel-store.md §2.5.1 Table 4 `sessions.role`
//   - cli-ceremony.md §`session create` (`--role planner`)
//
// Full policy artifact schema (TOML) lives in kernel-store.md §2.5.3 and is
// parsed by `raxis-policy`. This module only carries the shared enum types
// that other crates need without importing `raxis-policy`.

use serde::{Deserialize, Serialize};
use std::fmt;

// ---------------------------------------------------------------------------
// Role
// kernel-store.md §2.5.1 Table 4: CHECK (role IN ('Planner','Gateway','Verifier'))
// ---------------------------------------------------------------------------

/// The role of an authenticated session.
///
/// - Planner: an LLM session running the RAXIS planner loop.
/// - Gateway: the provider gateway subprocess (one per kernel instance).
/// - Verifier: a short-lived verifier subprocess (one per gate evaluation).
///
/// Only Planner sessions are operator-creatable via `session create`.
/// Gateway and Verifier sessions are minted by the kernel spawn paths.
/// kernel-core.md `handle_create_session` step 1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum Role {
    Planner,
    Gateway,
    Verifier,
}

impl Role {
    pub fn as_sql_str(self) -> &'static str {
        match self {
            Self::Planner => "Planner",
            Self::Gateway => "Gateway",
            Self::Verifier => "Verifier",
        }
    }

    pub fn from_sql_str(s: &str) -> Option<Self> {
        match s {
            "Planner" => Some(Self::Planner),
            "Gateway" => Some(Self::Gateway),
            "Verifier" => Some(Self::Verifier),
            _ => None,
        }
    }

    /// Only Planner sessions are operator-creatable.
    /// kernel-core.md handle_create_session step 1.
    pub fn is_operator_creatable(self) -> bool {
        self == Self::Planner
    }

    /// Planner sessions require a non-None worktree_root.
    /// Gateway and Verifier sessions require worktree_root = None.
    /// kernel-core.md §`authority/session.rs` `create_session` invariant.
    pub fn requires_worktree(self) -> bool {
        self == Self::Planner
    }
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_sql_str())
    }
}

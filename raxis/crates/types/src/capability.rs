// raxis-types::capability — CapabilityClass and DelegationStatus.
//
// Normative reference:
//   - kernel-core.md §`authority/delegation.rs` (`CapabilityClass`, `DelegationStatus`)
//   - cli-ceremony.md §`delegation grant` (`--capability` flag description)
//   - kernel-store.md §2.5.1 Table 7 `delegations.capability_class TEXT NOT NULL`
//   - philosophy.md §1.6 escalation types (`EscalationClass::CapabilityUpgrade`)
//
// GateType (operator-defined string) is separate from CapabilityClass (kernel-
// defined enum). A gate *requires* a CapabilityClass; a delegation *grants* one.

use serde::{Deserialize, Serialize};
use std::fmt;

// ---------------------------------------------------------------------------
// CapabilityClass
// ---------------------------------------------------------------------------

/// A named capability that can be delegated to a planner session.
///
/// The full enum is defined in `raxis-types/src/capability.rs` and referenced
/// by the kernel at delegation-grant time (policy ceiling check) and at gate-
/// evaluation time (capability check per `gates/claim.rs`).
///
/// v1 canonical variants — operators reference these by their exact string name
/// in `--capability` and `policy.role_ceilings`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum CapabilityClass {
    /// Read from or write to secrets storage (e.g. Vault, AWS SSM).
    WriteSecrets,
    /// Make network requests to domains beyond the policy allowlist.
    NetworkEgress,
    /// Execute break-glass operator-level operations (two-operator required).
    /// philosophy.md §1.6 breakglass.rs.
    BreakGlass,
    /// Read infrastructure state (cloud describe, kubectl get, etc.).
    InfraRead,
    /// Mutate infrastructure (terraform apply, kubectl apply, etc.).
    InfraMutate,
    /// Deploy artefacts to a staging environment.
    DeployStaging,
    /// Deploy artefacts to a production environment (higher barrier).
    DeployProduction,
}

impl CapabilityClass {
    /// The at-rest TEXT form used in DDL CHECK constraints and signing domains.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::WriteSecrets => "WriteSecrets",
            Self::NetworkEgress => "NetworkEgress",
            Self::BreakGlass => "BreakGlass",
            Self::InfraRead => "InfraRead",
            Self::InfraMutate => "InfraMutate",
            Self::DeployStaging => "DeployStaging",
            Self::DeployProduction => "DeployProduction",
        }
    }

    /// Parse from the at-rest TEXT form. Returns None on unknown variant.
    /// The handler maps None to `OperatorErrorCode::FAIL_UNKNOWN_CAPABILITY_CLASS`.
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "WriteSecrets" => Some(Self::WriteSecrets),
            "NetworkEgress" => Some(Self::NetworkEgress),
            "BreakGlass" => Some(Self::BreakGlass),
            "InfraRead" => Some(Self::InfraRead),
            "InfraMutate" => Some(Self::InfraMutate),
            "DeployStaging" => Some(Self::DeployStaging),
            "DeployProduction" => Some(Self::DeployProduction),
            _ => None,
        }
    }
}

impl fmt::Display for CapabilityClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// DelegationStatus
// DDL: CHECK (status IN ('Active','StaleOnNextUse','RenewalRequired','Expired'))
// kernel-store.md §2.5.1 Table 7, kernel-core.md §`authority/delegation.rs`
// ---------------------------------------------------------------------------

/// Current status of a capability delegation row.
///
/// State machine:
///   Active → StaleOnNextUse (policy epoch advance, mark_stale_on_epoch_advance)
///   StaleOnNextUse → Active (one gated intent passes, warn_delegation_stale=true
///                            then renewed — no longer stale; OR renewed before use)
///   StaleOnNextUse → RenewalRequired (enforcement hook: record_capability_use
///                                     called while row is StaleOnNextUse and not renewed)
///   Any → Expired (TTL elapsed, detected lazily by check_capability)
///
/// Additionally: `NotGranted` is a synthetic variant returned by `check_capability`
/// when no row exists for the (session_id, capability) pair. It is NOT stored
/// in the DDL (the row simply does not exist).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum DelegationStatus {
    Active,
    StaleOnNextUse,
    RenewalRequired,
    Expired,
    /// Synthetic: no row exists. Not stored in SQL.
    NotGranted,
}

impl DelegationStatus {
    pub fn as_sql_str(self) -> Option<&'static str> {
        match self {
            Self::Active => Some("Active"),
            Self::StaleOnNextUse => Some("StaleOnNextUse"),
            Self::RenewalRequired => Some("RenewalRequired"),
            Self::Expired => Some("Expired"),
            Self::NotGranted => None, // synthetic, not stored
        }
    }

    pub fn from_sql_str(s: &str) -> Option<Self> {
        match s {
            "Active" => Some(Self::Active),
            "StaleOnNextUse" => Some(Self::StaleOnNextUse),
            "RenewalRequired" => Some(Self::RenewalRequired),
            "Expired" => Some(Self::Expired),
            _ => None,
        }
    }

    /// A delegation in one of these states allows the current gated intent to
    /// proceed. StaleOnNextUse passes once (grace use).
    pub fn allows_use(self) -> bool {
        matches!(self, Self::Active | Self::StaleOnNextUse)
    }

    /// True when this status means the delegation was stale on use and the
    /// `warn_delegation_stale = true` flag should be set in IntentResponse.
    pub fn is_stale_use(self) -> bool {
        self == Self::StaleOnNextUse
    }
}

impl fmt::Display for DelegationStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.as_sql_str() {
            Some(s) => f.write_str(s),
            None => f.write_str("NotGranted"),
        }
    }
}

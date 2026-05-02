// raxis-store::table — Canonical DDL table name enum.
//
// Normative reference: kernel-store.md §2.5.1 "Canonical DDL Parts 1–4".
//
// Rules:
//   - Every SQL string that references a table MUST use `Table::X.as_str()`
//     rather than a raw string literal. This ensures a single point of truth
//     for table names; a rename in the DDL requires only one code change here.
//   - `as_str()` returns the exact string used in the migration DDL and must
//     stay in bijection with it. The unit test `all_variants_have_nonempty_str`
//     guards against empty returns.
//   - This enum is not serialized over the wire; it is a compile-time constant.

/// All 19 kernel.db tables defined in kernel-store.md §2.5.1 migration 1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Table {
    // ── Core schema ───────────────────────────────────────────────────────
    SchemaVersion,
    // ── Initiative / task lifecycle ───────────────────────────────────────
    Initiatives,
    SignedPlanArtifacts,
    Tasks,
    TaskDagEdges,
    // ── Session / auth ────────────────────────────────────────────────────
    Sessions,
    Delegations,
    NonceCache,
    // ── Escalation pipeline ───────────────────────────────────────────────
    Escalations,
    ApprovalTokens,
    ApprovalProofs,
    ApprovalTokenNonces,
    // ── Verifier / witness ────────────────────────────────────────────────
    VerifierRunTokens,
    WitnessRecords,
    // ── Budget / lane ─────────────────────────────────────────────────────
    LaneBudgetReservations,
    LineageRateLimits,
    // ── VCS / path tracking ───────────────────────────────────────────────
    TaskIntentRanges,
    TaskExportedPathSnapshots,
    // ── Policy ────────────────────────────────────────────────────────────
    PolicyEpochHistory,
}

impl Table {
    /// Returns the exact table name used in the migration DDL.
    ///
    /// Matches kernel-store.md §2.5.1 table names verbatim.
    ///
    /// `const fn` so callers can write `const TASKS: &str = Table::Tasks.as_str();`
    /// at module top-level — see kernel-store.md §2.5.1 INV-STORE-03 ("no raw SQL
    /// table-name literals in raxis/kernel/src; use Table enum + .as_str()").
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SchemaVersion             => "schema_version",
            Self::Initiatives               => "initiatives",
            Self::SignedPlanArtifacts       => "signed_plan_artifacts",
            Self::Tasks                     => "tasks",
            Self::TaskDagEdges              => "task_dag_edges",
            Self::Sessions                  => "sessions",
            Self::Delegations               => "delegations",
            Self::NonceCache                => "nonce_cache",
            Self::Escalations               => "escalations",
            Self::ApprovalTokens            => "approval_tokens",
            Self::ApprovalProofs            => "approval_proofs",
            Self::ApprovalTokenNonces       => "approval_token_nonces",
            Self::VerifierRunTokens         => "verifier_run_tokens",
            Self::WitnessRecords            => "witness_records",
            Self::LaneBudgetReservations    => "lane_budget_reservations",
            Self::LineageRateLimits         => "lineage_rate_limits",
            Self::TaskIntentRanges          => "task_intent_ranges",
            Self::TaskExportedPathSnapshots => "task_exported_path_snapshots",
            Self::PolicyEpochHistory        => "policy_epoch_history",
        }
    }
}

impl std::fmt::Display for Table {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_variants_have_nonempty_str() {
        let all = [
            Table::SchemaVersion, Table::Initiatives, Table::SignedPlanArtifacts,
            Table::Tasks, Table::TaskDagEdges, Table::Sessions, Table::Delegations,
            Table::NonceCache, Table::Escalations, Table::ApprovalTokens,
            Table::ApprovalProofs, Table::ApprovalTokenNonces, Table::VerifierRunTokens,
            Table::WitnessRecords, Table::LaneBudgetReservations, Table::LineageRateLimits,
            Table::TaskIntentRanges, Table::TaskExportedPathSnapshots, Table::PolicyEpochHistory,
        ];
        for t in all {
            assert!(!t.as_str().is_empty(), "Table::{t:?} returned empty string");
        }
    }

    #[test]
    fn display_equals_as_str() {
        for t in [Table::Tasks, Table::Sessions, Table::VerifierRunTokens] {
            assert_eq!(t.to_string(), t.as_str());
        }
    }
}

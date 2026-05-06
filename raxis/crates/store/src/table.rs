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

/// All kernel.db tables. v1 baseline = 19 tables (kernel-store.md §2.5.1
/// migration 1); v1.x extensions append below.
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
    // ── v1.x: Operator certificates (kernel-store.md §2.5.7) ─────────────
    /// Denormalised view of `[[operators.entries.cert]]` from the
    /// currently-installed `policy.toml`. Repopulated on every
    /// `advance_epoch` (truncate + insert in the same transaction
    /// that updates `policy_epoch_history`). The cert artefact in
    /// the policy bundle remains the canonical source of truth;
    /// this table exists for the kernel's `cert_check` runtime
    /// path which must do `WHERE expires_at < ?` sweeps and per-
    /// fingerprint lookups without re-parsing the policy bundle on
    /// every operator IPC dispatch.
    OperatorCertificates,

    // ── v1.x: Initiative quarantine (kernel-store.md §2.5.8) ─────────────
    /// Quarantine markers for individual initiatives. A row in this
    /// table means the initiative is frozen — the planner intent path
    /// rejects any subsequent `IntentRequest` against it with
    /// `FAIL_INITIATIVE_QUARANTINED`. Created either by
    /// `raxis initiative quarantine <id>` (single-initiative) or by
    /// `raxis operator quarantine-plans-by <fingerprint>` (sweeps every
    /// initiative whose plan was signed by the named operator). The
    /// table is append-only: there is no operator command to lift a
    /// quarantine in v1; the operator removes the initiative entirely
    /// via `raxis initiative abort` and creates a fresh one if the
    /// underlying compromise is resolved.
    InitiativeQuarantines,

    // ── v2: Hierarchical orchestration (v2-deep-spec.md §Step 5) ─────────
    /// Per-(initiative, sub-task) activation FSM rows. One row per
    /// activation attempt — a retry inserts a NEW row, never updates
    /// the prior one. State machine: `PendingActivation → Active →
    /// Completed | Failed`.
    ///
    /// **Why a separate table from `tasks`.** `tasks.state` is the V1
    /// operational FSM (Admitted → Running → ...). V2 adds a
    /// pre-activation state ("declared in plan, no VM yet") whose
    /// presence in the V1 FSM would force every V1 state-machine
    /// handler — including `recovery::reconcile_tasks` — to be aware
    /// of a state with no VM, no session token, and no scheduling row.
    /// The separate table lets the V2 sub-task layer carry its own
    /// retry counters (`crash_retry_count`, `review_reject_count`),
    /// VirtioFS staging refs, and `evaluation_sha` (Reviewer activations)
    /// without polluting the V1 contract.
    ///
    /// **Atomicity.** Inserted by `approve_plan → admit_in_tx` in the
    /// SAME transaction that inserts the `tasks` row (INV-STORE-02).
    /// This guarantees that an initiative cannot exist in a state where
    /// the operator-signed plan has a sub-task but the activation row
    /// is missing.
    ///
    /// Only Executor and Reviewer tasks have rows here; the Orchestrator
    /// task is activated by the Kernel itself at initiative start
    /// (no `subtask_activations` row for it).
    SubtaskActivations,
}

impl Table {
    /// Returns the exact table name used in the migration DDL.
    ///
    /// Matches kernel-store.md §2.5.1 table names verbatim.
    ///
    /// `const fn` so callers can write `const TASKS: &str = Table::Tasks.as_str();`
    /// at module top-level — see kernel-store.md §2.5.1 INV-STORE-03 ("no raw
    /// SQL table-name literals in **any workspace crate that touches
    /// `kernel.db`** — production *or* test code: `raxis-kernel`, `raxis-store`,
    /// `raxis-cli`, `raxis-test-support`, …; use `Table` enum + `.as_str()`").
    /// The `#[cfg(test)]` modules of any of those crates that hand-roll
    /// `INSERT`/`UPDATE` fixtures MUST resolve their table names through this
    /// method as well, so renaming a table propagates at compile time.
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
            Self::OperatorCertificates      => "operator_certificates",
            Self::InitiativeQuarantines     => "initiative_quarantines",
            Self::SubtaskActivations        => "subtask_activations",
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
            Table::OperatorCertificates, Table::InitiativeQuarantines,
            Table::SubtaskActivations,
        ];
        for t in all {
            assert!(!t.as_str().is_empty(), "Table::{t:?} returned empty string");
        }
    }

    /// V2 sub-task activation table name is wire-stable (it is queried
    /// directly by audit/forensic tools after kernel restart). Pinning
    /// the literal here surfaces any rename in code review.
    #[test]
    fn subtask_activations_table_name_is_pinned() {
        assert_eq!(Table::SubtaskActivations.as_str(), "subtask_activations");
    }

    #[test]
    fn display_equals_as_str() {
        for t in [Table::Tasks, Table::Sessions, Table::VerifierRunTokens] {
            assert_eq!(t.to_string(), t.as_str());
        }
    }
}

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
//
// ── Invariant: kernel.db never stores credential VALUES ───────────────────
//
// `kernel.db` is the kernel's metadata store. It records WHICH credentials
// each task wants bound (see `Table::TaskCredentialProxies`) but it never
// records the credential bytes themselves. Bytes — postgres URLs with
// passwords, bearer tokens, kubeconfig YAML, SMTP passwords, etc. — live
// behind the `CredentialBackend` trait (the reference `FileCredentialBackend`
// stores them with `0600` perms in `~/.config/raxis/credentials/<name>.env`;
// production deployments may swap in `VaultBackend`,
// `AwsSecretsManagerBackend`, `Pkcs11HsmBackend`, etc. — see
// `extensibility-traits.md §4`).
//
// Adding a column or table that would persist a credential VALUE is
// forbidden by `credential-proxy.md §1.1`. Reviewers MUST reject such a
// change.

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

    // ── v2: Plan Bundle Sealing (plan-bundle-sealing.md §8.2) ─────────────
    /// Content-addressed store of every operator-signed plan bundle
    /// admitted under V2. One row per distinct `bundle_sha256`. Holds
    /// the canonical-encoded bundle bytes (`canonical_input` per
    /// `plan-bundle-sealing.md §3.2`), the Ed25519 signature, the
    /// signing operator's fingerprint, and (for schema_version >= 2)
    /// the `signed_at_unix_secs` + `bundle_nonce` envelope fields.
    ///
    /// Retained **indefinitely** per `plan-bundle-sealing.md §10` (D8):
    /// the bundle is the foundational cryptographic input to the
    /// initiative state machine; deleting it destroys forensic
    /// reproducibility. Audit-chain replay, post-compromise
    /// `quarantine-plans-by` sweeps, and operator dispute resolution
    /// all join through `bundle_sha256`.
    PlanBundles,

    /// Per-artifact rows for each `plan_bundles` row. `artifact_seq = 0`
    /// is always `plan.toml`; subsequent rows are operator-declared
    /// host-path artifacts (forward-compatibility hook —
    /// `plan-bundle-sealing.md §5.4` notes V2 ships zero plan.toml
    /// fields that take host-side paths, so well-formed V2 bundles
    /// have exactly one row in this table per `bundle_sha256`).
    ///
    /// Composite primary key `(bundle_sha256, artifact_seq)` keeps the
    /// per-artifact ordering stable for canonical decode and lets
    /// kernel-side `plan_bundle::read_artifact` join in O(1) without
    /// a secondary index.
    PlanBundleArtifacts,

    /// Replay-protection state for V2.1 plan bundles
    /// (`plan-bundle-sealing.md §3.5` + §8.2). One row per
    /// `bundle_nonce` that has been consumed by an admission attempt
    /// (`outcome = 'Admitted'`) or terminally rejected
    /// (`outcome = 'TerminallyRejected'`). The kernel's §8.1 admission
    /// sequence inserts into this table inside the same `BEGIN
    /// IMMEDIATE` transaction that decides admission, so a concurrent
    /// re-submission of the same nonce cannot race past the check.
    ///
    /// **Sweepable.** Unlike `plan_bundles` / `plan_bundle_artifacts`,
    /// this table participates in periodic GC: rows older than
    /// `max_plan_bundle_age_secs + max_clock_skew_secs +
    /// nonce_retention_grace_secs` are inert (the freshness window
    /// in step 10a fails before step 10b queries the table) and are
    /// reaped by the kernel's maintenance loop
    /// (`plan-bundle-sealing.md §8.4`).
    PlanBundleNoncesSeen,

    // ── v2: Per-task credential-proxy declarations
    //        (credential-proxy.md §3) ─────────────────────────────────────
    /// **Per-task credential-proxy declarations** parsed out of
    /// `[[tasks.credentials]]` at `approve_plan` time. One row per
    /// declared proxy per task.
    ///
    /// # ⚠ This table does NOT store credential values.
    ///
    /// Each row is **proxy metadata only**:
    ///
    /// * `credential_name` — the policy-declared *name* of the
    ///   credential (e.g. `"db-prod"`); the actual secret bytes
    ///   resolve through the kernel's `CredentialBackend`.
    /// * `mount_as` — the env-var the proxy will inject into the
    ///   agent VM (e.g. `"DB_URL"`).
    /// * `proxy_type` — `postgres | http | k8s | smtp`.
    /// * `proxy_json` — the per-proxy restriction blob (allow-lists,
    ///   upstream URL, etc.).
    ///
    /// The credential **bytes themselves** (postgres URL with
    /// password, bearer tokens, kubeconfig YAML, …) are NEVER
    /// persisted in `kernel.db`. They live with the
    /// `CredentialBackend` (the reference `FileCredentialBackend`
    /// stores them in `~/.config/raxis/credentials/<name>.env` with
    /// `0600` perms enforced; production deployments may swap in a
    /// `VaultBackend`, `AwsSecretsManagerBackend`, etc.).
    ///
    /// # Why a JSON column for `proxy_json`
    ///
    /// (vs. a normalised per-proxy-type column set): the
    /// per-proxy-type schemas drift independently —
    ///
    /// * postgres has `allow_only_select`;
    /// * http has `auth_mode`, `upstream_url`, allowed_methods,
    ///   allowed_path_prefixes;
    /// * k8s reuses http restrictions but is auditing-distinct;
    /// * future smtp adds rate-limit fields —
    ///
    /// and the kernel never writes to this column outside of the
    /// approve_plan transaction. It is read once at session-spawn
    /// time and re-deserialised back into
    /// `raxis_plan_credentials::TaskCredentialDecl`. JSON keeps the
    /// schema flat while preserving per-proxy fidelity. The
    /// `proxy_type` column is projected out of the JSON for
    /// index/query convenience and CHECK-clause pinning.
    ///
    /// # Atomicity
    ///
    /// Inserted by `approve_plan` in the SAME transaction that
    /// admits the parent `tasks` row (INV-STORE-02). Foreign key on
    /// `task_id` references `tasks(task_id)`.
    TaskCredentialProxies,

    // ── v2: Pre-Integration-Merge attempt tracking
    //        (verifier-processes.md §16, integration-merge.md §11.10) ─
    /// **Pre-merge verifier attempt rows** for the `IntegrationMerge`
    /// candidate-merge-tree → pre-merge-verifier → main-advance
    /// pipeline. One row per `IntegrationMerge` intent that reaches
    /// Check 5d.
    ///
    /// Distinct from `initiatives.git_apply_pending` (which gates the
    /// SQLite-intent → git-apply boundary for the actual main advance
    /// per `integration-merge.md §11.1`); this table governs the
    /// *strictly earlier* candidate-merge-tree → pre-merge-verifier
    /// boundary in `integration-merge.md §11.10`.
    ///
    /// **State machine.**
    /// ```text
    ///   AwaitingPreMergeVerifiers ─┬─→ PreMergeVerifiersPassed ─→ CompletedAdvanceApplied
    ///                              ├─→ BlockedByPreMergeVerifier  (terminal, candidate discarded)
    ///                              ├─→ DiscardedCandidateOnly      (Check 5d.2 failed; candidate never spawned)
    ///                              └─→ DiscardedCrashRecovery      (kernel restart sweep)
    /// ```
    ///
    /// **Crash recovery.** The recovery sweep at boot scans this
    /// table for non-terminal rows (`AwaitingPreMergeVerifiers` /
    /// `PreMergeVerifiersPassed`) per
    /// `integration-merge.md §11.10.4`. Rows whose
    /// `candidate_merge_sha` worktree is missing are folded to
    /// `DiscardedCrashRecovery`.
    ///
    /// **Atomicity.** Inserted at Check 5d.1 inside the same
    /// `BEGIN IMMEDIATE` transaction that records the
    /// `IntegrationMerge` intent acceptance, so a concurrent
    /// re-submission of the same merge cannot race past the check.
    /// Foreign key on `initiative_id` references `initiatives(id)`.
    IntegrationMergeAttempts,

    /// **V2 `v2_extended_gaps.md §3.2`** — typed mid-session
    /// outputs (progress reports, diagnostic flags, task summaries)
    /// emitted by executor / orchestrator agents via the
    /// `structured_output` planner tool. Read-only from CLI +
    /// dashboard; write path is the kernel intent handler at
    /// `handlers::intent::handle_structured_output` exclusively.
    ///
    /// Schema: `(output_id, initiative_id, task_id, session_id,
    ///           kind, severity, payload_json, emitted_at)`.
    StructuredOutputs,

    // ── v2: Kernel-owned notification store ──────────────────────────────
    /// **Kernel-owned notification store.** Every notification the
    /// kernel generates is written here unconditionally — regardless
    /// of which delivery channels (Shell, File, Email, Sidecar) the
    /// operator configured. This table is the ground truth for
    /// "what notifications were generated" and backs `raxis inbox`,
    /// the dashboard notification view, and read/unread state.
    ///
    /// The inbox.jsonl file is also always appended to as a durable
    /// fallback, but the SQLite table is the queryable, indexed,
    /// authoritative store.
    ///
    /// Schema: `(notification_id, event_kind, initiative_id,
    ///           task_id, session_id, summary, payload_json, read,
    ///           source_event_id, created_at)`.
    Notifications,
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
            Self::PlanBundles               => "plan_bundles",
            Self::PlanBundleArtifacts       => "plan_bundle_artifacts",
            Self::PlanBundleNoncesSeen      => "plan_bundle_nonces_seen",
            Self::TaskCredentialProxies     => "task_credential_proxies",
            Self::IntegrationMergeAttempts  => "integration_merge_attempts",
            Self::StructuredOutputs         => "structured_outputs",
            Self::Notifications             => "notifications",
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
            Table::PlanBundles, Table::PlanBundleArtifacts, Table::PlanBundleNoncesSeen,
            Table::TaskCredentialProxies,
            Table::IntegrationMergeAttempts,
            Table::StructuredOutputs,
            Table::Notifications,
        ];
        for t in all {
            assert!(!t.as_str().is_empty(), "Table::{t:?} returned empty string");
        }
    }

    /// V2 §3.2 structured outputs table name is wire-stable (the
    /// CLI `raxis task outputs` and the dashboard read this table
    /// using its literal name in production SQL).
    #[test]
    fn structured_outputs_table_name_is_pinned() {
        assert_eq!(Table::StructuredOutputs.as_str(), "structured_outputs");
    }

    /// V2 plan-bundle-sealing table names are wire-stable (the kernel's
    /// audit & forensic tools join across them by literal name in the
    /// CLI's read-only path). Pinning the literals here surfaces any
    /// rename in code review.
    #[test]
    fn plan_bundle_sealing_table_names_are_pinned() {
        assert_eq!(Table::PlanBundles.as_str(),          "plan_bundles");
        assert_eq!(Table::PlanBundleArtifacts.as_str(),  "plan_bundle_artifacts");
        assert_eq!(Table::PlanBundleNoncesSeen.as_str(), "plan_bundle_nonces_seen");
    }

    /// V2 sub-task activation table name is wire-stable (it is queried
    /// directly by audit/forensic tools after kernel restart). Pinning
    /// the literal here surfaces any rename in code review.
    #[test]
    fn subtask_activations_table_name_is_pinned() {
        assert_eq!(Table::SubtaskActivations.as_str(), "subtask_activations");
    }

    /// V2 per-task credential-proxy declaration table name is
    /// wire-stable (the `CredentialProxyManager` will read this
    /// table at session-spawn time using its literal name in
    /// production SQL). Pinning the literal here surfaces any
    /// rename in code review. See `credential-proxy.md §3`.
    ///
    /// **Naming note.** The table is `task_credential_proxies`,
    /// NOT `task_credentials`. The latter would falsely imply that
    /// credential bytes are persisted in `kernel.db`; they are
    /// not — see the `Table::TaskCredentialProxies` doc for the
    /// authoritative list of what each row contains.
    #[test]
    fn task_credential_proxies_table_name_is_pinned() {
        assert_eq!(
            Table::TaskCredentialProxies.as_str(),
            "task_credential_proxies",
        );
    }

    /// V2 pre-merge verifier attempt table name is wire-stable
    /// (read by the recovery sweep using its literal name in
    /// production SQL — see `integration-merge.md §11.10.4`).
    /// Pinning the literal here surfaces any rename in code review.
    #[test]
    fn integration_merge_attempts_table_name_is_pinned() {
        assert_eq!(
            Table::IntegrationMergeAttempts.as_str(),
            "integration_merge_attempts",
        );
    }

    /// Kernel-owned notification store table name is wire-stable
    /// (the CLI `raxis inbox` and the dashboard read this table
    /// using its literal name in production SQL).
    #[test]
    fn notifications_table_name_is_pinned() {
        assert_eq!(Table::Notifications.as_str(), "notifications");
    }

    #[test]
    fn display_equals_as_str() {
        for t in [Table::Tasks, Table::Sessions, Table::VerifierRunTokens] {
            assert_eq!(t.to_string(), t.as_str());
        }
    }
}

// raxis-policy::bundle — PolicyBundle: the in-memory representation of
// a validated, loaded policy artifact.
//
// Normative references:
//   - kernel-store.md §2.5.5 "[[operators.entries]]" and "permitted_ops"
//   - kernel-core.md §2.3 policy_manager.rs escalation_policy fields
//   - kernel-core.md §2.3 authority/delegation.rs (role_ceilings)
//   - kernel-store.md §2.5.6 "[[gates]]" normative schema
//   - kernel-core.md §2.3 scheduler (lane/budget config)
//   - kernel-core.md §2.2 startup step 3 (authority_pubkey, quality_pubkey)
//
// Policy is loaded from `<data_dir>/policy/policy.toml` at boot and wrapped
// in ArcSwap<PolicyBundle> by the kernel. This file owns only the TOML-mapped
// types and their accessor methods. I/O and signature verification live in
// loader.rs.
//
// All fields are `pub(crate)` — external callers use the accessor methods,
// which apply business-rule validation and return well-typed values rather
// than raw TOML scalars.

use raxis_credentials::CredentialBackendKind;
use raxis_types::operator_cert::{CertKind, OperatorCert};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;

use crate::PolicyError;

// ---------------------------------------------------------------------------
// Top-level TOML-mapped structs (serde shapes)
// ---------------------------------------------------------------------------

/// The raw TOML-mapped policy artifact, before semantic validation.
/// Parsed by `toml::from_str`; then converted to `PolicyBundle` by
/// `PolicyBundle::validate`.
#[derive(Debug, Deserialize)]
pub(crate) struct RawPolicy {
    pub(crate) meta: PolicyMeta,
    pub(crate) authority: AuthoritySection,
    pub(crate) escalation_policy: EscalationPolicySection,
    pub(crate) sessions: SessionsSection,
    pub(crate) delegations: DelegationsSection,
    pub(crate) budget: BudgetSection,

    #[serde(rename = "operators")]
    pub(crate) operators_block: OperatorsBlock,

    #[serde(default)]
    pub(crate) gates: Vec<GateEntry>,

    #[serde(default)]
    pub(crate) roles: Vec<RoleEntry>,

    #[serde(default)]
    pub(crate) lanes: Vec<LaneEntry>,

    #[serde(default)]
    pub(crate) claim_requirements: ClaimRequirementsSection,

    #[serde(default)]
    pub(crate) egress: EgressSection,

    /// `[gateway]` — supervisor config for the kernel-spawned `raxis-gateway`
    /// subprocess. **Optional** in v1: a kernel without a `[gateway]` section
    /// boots and serves operator IPC, but no `FetchRequest` can be dispatched
    /// (any planner asking for an inference call will receive a deferred
    /// failure). Operators who run RAXIS without an LLM workflow (audit-only,
    /// or with a planner that talks to providers via some out-of-band path)
    /// can omit this section entirely.
    #[serde(default)]
    pub(crate) gateway: Option<GatewaySection>,

    /// `[[providers]]` — declarative catalogue of model / data providers the
    /// gateway is permitted to forward requests to. Provider credentials
    /// (API keys) are stored separately under `<data_dir>/providers/<name>.toml`
    /// — never in this policy artifact, so policy.toml can be checked into
    /// version control without leaking secrets.
    #[serde(default)]
    pub(crate) providers: Vec<ProviderEntry>,

    /// `[notifications]` — per-event-kind delivery routing for operator-
    /// facing channels. Optional: a kernel without this section gets the
    /// implicit `shell` channel pointing at `<data_dir>/notifications/inbox.jsonl`
    /// and an empty route table (everything falls through to
    /// `default_channels = ["shell"]`).
    ///
    /// Normative reference: `cli-readonly.md` §5.6.
    #[serde(default)]
    pub(crate) notifications: NotificationsSection,

    /// `[plan_signing]` — V2.1 plan-bundle freshness / replay-protection
    /// configuration. **Optional**: a kernel that omits the section
    /// boots with the spec defaults from `plan-bundle-sealing.md §7.4`.
    /// All five fields have field-level defaults; the structural
    /// invariants (`max_clock_skew_secs ≤ max_plan_bundle_age_secs / 4`,
    /// hard ceilings) are checked at validate time.
    #[serde(default)]
    pub(crate) plan_signing: Option<PlanSigningSection>,

    /// `[plan_bundle_limits]` — V2 plan-bundle size discipline.
    /// **Optional**: a kernel that omits the section boots with the
    /// spec defaults from `plan-bundle-sealing.md §7.4` (1 MiB / 10 MiB
    /// / 200). All three fields have defaults; the hard ceilings
    /// (`max_artifact_bytes ≤ 64 MiB`, `max_bundle_bytes ≤ 128 MiB`,
    /// `max_artifact_count ≤ 1024`) plus the coherence rule
    /// (`max_artifact_bytes ≤ max_bundle_bytes`) are checked at
    /// validate time.
    #[serde(default)]
    pub(crate) plan_bundle_limits: Option<PlanBundleLimitsSection>,

    /// `[credential_backend]` — V2 selector for the active
    /// `CredentialBackend` impl. **Optional**: a kernel that omits
    /// the section boots with `kind = "file"` (the V2 reference
    /// `FileCredentialBackend`). Future Vault / AWS-SM / Azure-KV /
    /// PKCS#11 backends are selected by setting `kind` to one of
    /// `"vault"`, `"aws_secrets_manager"`, `"azure_key_vault"`,
    /// `"pkcs11"`; `extensibility-traits.md §4.4`.
    #[serde(default)]
    pub(crate) credential_backend: Option<CredentialBackendSection>,

    /// `[[integration_merge_verifiers]]` — V2 operator-side pre-merge
    /// verifier gates per `policy-plan-authority.md §4
    /// [[integration_merge_verifiers]]`. **Optional**: omitted
    /// section means "operator declares no global pre-merge
    /// verifiers" (the typical default). Validation enforces the
    /// operator-side discipline (`on_failure = "block_merge"` only,
    /// name uniqueness, `applies_to ∈ {all, task_set, last}`, and
    /// the structural caps shared with the plan-side parser); see
    /// `PolicyBundle::validate`.
    #[serde(default, rename = "integration_merge_verifiers")]
    pub(crate) integration_merge_verifiers: Vec<IntegrationMergeVerifierEntry>,

    /// `[git]` — operator-side defaults for git-domain configuration.
    /// **Optional**: a kernel that omits the section gets the
    /// hardcoded defaults (`default_target_ref = "refs/heads/main"`,
    /// `target_ref_locked = false`). See `V2_GAPS.md §12.8`.
    #[serde(default)]
    pub(crate) git: Option<GitSection>,
}

/// `[git]` — operator default + lock for the per-initiative
/// `target_ref` field declared in `plan.toml [workspace] target_ref`.
/// Resolution at admission time follows
/// `INV-PLAN-POLICY-PRECEDENCE-01` (`V2_GAPS.md §12.9`):
///
/// * If the plan declares `target_ref`, it wins **unless**
///   `target_ref_locked = true`, in which case the kernel rejects
///   admission with `FAIL_POLICY_LOCKED_FIELD`.
/// * If the plan omits `target_ref`, `default_target_ref` applies.
/// * If the operator omits the whole section, the hardcoded fallback
///   `"refs/heads/main"` applies and `target_ref_locked` defaults to
///   `false` (i.e., plans may freely override).
#[derive(Debug, Clone, Deserialize, Default)]
pub(crate) struct GitSection {
    /// Default value the kernel applies when the plan omits its own
    /// `[workspace] target_ref` field. Validated at policy-load to
    /// be a fully-qualified `refs/heads/...` ref.
    #[serde(default)]
    pub(crate) default_target_ref: Option<String>,

    /// When `true`, plans MAY NOT override `target_ref`. Any plan
    /// whose `[workspace] target_ref` differs from `default_target_ref`
    /// is rejected at admission with `FAIL_POLICY_LOCKED_FIELD` (see
    /// `INV-PLAN-POLICY-PRECEDENCE-01`).
    #[serde(default)]
    pub(crate) target_ref_locked: bool,
}

/// `[credential_backend]` — selector for the active credential
/// store. The `kind` discriminator picks one of the registered
/// backends; non-file backends will eventually carry their own
/// per-backend configuration sub-table here, but V2 ships only
/// the `kind = "file"` selector and ignores anything else with a
/// validation error.
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct CredentialBackendSection {
    pub(crate) kind: CredentialBackendKind,
}

// ---------------------------------------------------------------------------
// Policy meta
// ---------------------------------------------------------------------------

/// `[meta]` — policy artifact metadata.
///
/// ```toml
/// [meta]
/// epoch     = 1
/// signed_by = "<fingerprint>"
/// signed_at = 1714500000
/// ```
#[derive(Debug, Deserialize)]
pub(crate) struct PolicyMeta {
    pub(crate) epoch: u64,
    /// Optional: SHA-256 of the policy.toml bytes embedded by the signing tool.
    /// Accepted during TOML parse for forward-compatibility with policy files
    /// that include it, but intentionally never read after parsing: verifying it
    /// would require a self-referential fixed-point hash (unsolvable), and the
    /// Ed25519 signature over the raw bytes is the actual integrity check.
    /// The loader computes the SHA-256 independently from the raw bytes.
    #[serde(default)]
    #[allow(dead_code)]
    pub(crate) policy_sha256: Option<String>,
    /// SHA-256[:16] fingerprint of the signing operator's Ed25519 public key.
    pub(crate) signed_by: String,
    pub(crate) signed_at: i64,
}

// ---------------------------------------------------------------------------
// Authority section
// ---------------------------------------------------------------------------

/// `[authority]` — kernel key fingerprints.
///
/// ```toml
/// [authority]
/// authority_pubkey = "<64-char hex: raw 32-byte Ed25519 public key>"
/// quality_pubkey   = "<64-char hex: raw 32-byte Ed25519 public key>"
/// ```
#[derive(Debug, Deserialize)]
pub(crate) struct AuthoritySection {
    /// Raw 32-byte Ed25519 authority public key, hex-encoded (64 chars).
    /// Used to verify ApprovalProof signatures and policy artifact signatures.
    pub(crate) authority_pubkey: String,
    /// Raw 32-byte Ed25519 quality keypair public key, hex-encoded (64 chars).
    /// Loaded but unused in v1 — reserved for v2 witness-record signing.
    /// kernel-store.md §2.5.4: failure to load → BOOT_ERR_KEY_LOAD.
    pub(crate) quality_pubkey: String,
}

// ---------------------------------------------------------------------------
// Escalation policy
// ---------------------------------------------------------------------------

/// `[escalation_policy]` — per-lineage rate limiting parameters.
///
/// All four fields are required; any missing field → PolicyError::MalformedArtifact.
///
/// ```toml
/// [escalation_policy]
/// timeout_secs         = 3600
/// window_secs          = 300
/// max_per_window       = 5
/// quarantine_threshold = 3
/// ```
#[derive(Debug, Deserialize)]
pub(crate) struct EscalationPolicySection {
    pub(crate) timeout_secs: u64,
    pub(crate) window_secs: u64,
    pub(crate) max_per_window: u32,
    pub(crate) quarantine_threshold: u32,
}

// ---------------------------------------------------------------------------
// Sessions section
// ---------------------------------------------------------------------------

/// `[sessions]` — session creation policy.
///
/// ```toml
/// [sessions]
/// default_ttl_secs       = 86400
/// max_ttl_secs           = 604800
/// allowed_worktree_roots = ["/home/operator/worktrees"]
/// ```
#[derive(Debug, Deserialize)]
pub(crate) struct SessionsSection {
    pub(crate) default_ttl_secs: u64,
    pub(crate) max_ttl_secs: u64,
    /// Operator-specified path prefixes under which planner worktree_root
    /// values are allowed. At least one entry required.
    pub(crate) allowed_worktree_roots: Vec<String>,
}

// ---------------------------------------------------------------------------
// Delegations section
// ---------------------------------------------------------------------------

/// `[delegations]` — delegation TTL policy.
///
/// ```toml
/// [delegations]
/// max_ttl_secs = 86400
/// ```
#[derive(Debug, Deserialize)]
pub(crate) struct DelegationsSection {
    pub(crate) max_ttl_secs: u64,
}

// ---------------------------------------------------------------------------
// Budget section
// ---------------------------------------------------------------------------

/// `[budget]` — lane budget and per-intent-kind base costs.
///
/// ```toml
/// [budget]
/// cost_per_touched_path = 1
/// max_cost_per_task     = 10000
/// [budget.base_cost_per_intent_kind]
/// SingleCommit       = 10
/// MultiBranchCommit  = 25
/// IntegrationMerge   = 50
/// PrGateEvaluation   = 15
/// ```
#[derive(Debug, Deserialize)]
pub(crate) struct BudgetSection {
    pub(crate) base_cost_per_intent_kind: HashMap<String, u64>,
    /// Cost per touched file in the VCS diff range. Default 1.
    #[serde(default = "default_cost_per_touched_path")]
    pub(crate) cost_per_touched_path: u64,
    /// Cap on per-task admission cost before lane enforcement. Default 10000.
    #[serde(default = "default_max_cost_per_task")]
    pub(crate) max_cost_per_task: u64,
}

fn default_cost_per_touched_path() -> u64 { 1 }
fn default_max_cost_per_task() -> u64 { 10_000 }

/// A `[[lanes]]` entry defining one execution lane.
///
/// ```toml
/// [[lanes]]
/// lane_id              = "default"
/// max_concurrent_tasks = 4
/// max_cost_per_epoch   = 10000
/// priority             = 100
/// ```
#[derive(Debug, Clone, Deserialize)]
pub struct LaneEntry {
    pub lane_id: String,
    #[serde(default = "default_max_concurrent")]
    pub max_concurrent_tasks: u32,
    #[serde(default = "default_max_cost")]
    pub max_cost_per_epoch: u64,
    #[serde(default = "default_priority")]
    pub priority: u8,
}

fn default_max_concurrent() -> u32 { 4 }
fn default_max_cost() -> u64 { 10_000 }
fn default_priority() -> u8 { 100 }

// ---------------------------------------------------------------------------
// Operators block
// ---------------------------------------------------------------------------

/// `[operators]` containing `[[operators.entries]]`.
///
/// ```toml
/// [operators]
/// [[operators.entries]]
/// pubkey_fingerprint = "abcd1234..."
/// display_name       = "Chika"
/// pubkey_hex         = "<64-char hex raw Ed25519 public key>"
/// permitted_ops      = ["CreateInitiative", ...]
/// ```
#[derive(Debug, Deserialize)]
pub(crate) struct OperatorsBlock {
    pub(crate) entries: Vec<OperatorEntry>,
}

/// A single operator entry in `[[operators.entries]]`.
///
/// **Cert is mandatory (INV-CERT-01).** Every operator entry MUST embed
/// a self-signed `OperatorCert`. There is no cert-less / "legacy" path:
/// a TOML missing the `[operators.entries.cert]` sub-table fails serde
/// deserialisation with a clear error before the bundle even reaches
/// validation. The cert carries the operator's metadata (`display_name`,
/// expiry window, `permitted_ops`, contact info) and is self-signed by
/// the operator's private key. The `pubkey_hex` on the entry MUST
/// agree with the embedded cert; mismatches fail loud at validate
/// time. The entry's `permitted_ops` is IGNORED — the cert is the
/// authority.
///
/// **Misconfiguration policy.** Structural problems with the embedded
/// cert (inverted validity window, emergency cert with extra ops, etc.)
/// fail policy load by default. Operators who NEED to deploy a known-
/// inconsistent entry can set `force_misconfig_bypass = true` per
/// entry; the bypass is captured into [`PolicyBundle::bypassed_cert_misconfigs`]
/// so the kernel boot can emit an `OperatorCertMisconfigBypassed`
/// audit event for each one. **Self-signature failures are NEVER
/// bypassable** — a forged cert is always rejected.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct OperatorEntry {
    /// SHA-256[:16] fingerprint of the operator's Ed25519 public key (32 hex chars).
    pub pubkey_fingerprint: String,
    pub display_name: String,
    /// Raw 32-byte Ed25519 public key, hex-encoded (64 hex chars).
    pub pubkey_hex: String,
    /// The subset of operator IPC operations this operator is allowed
    /// to invoke. Canonical v1 set: 13 operations listed in
    /// kernel-store.md §2.5.5.
    ///
    /// **This field is mirrored from `cert.permitted_ops` at validate
    /// time.** Whatever value the operator typed in TOML is overwritten
    /// by `validate_operator_certs` so the cert is always the single
    /// source of truth. We retain the entry-level field so existing
    /// downstream lookups (`is_permitted`, `cert_check::permitted_ops`)
    /// don't have to learn the cert protocol.
    pub permitted_ops: Vec<String>,
    /// Embedded operator certificate. **Required.** The cert drives
    /// `permitted_ops`, expiry semantics, and audit metadata; the
    /// entry's loose fields exist only as a denormalised view for
    /// fast lookups.
    pub cert: OperatorCert,
    /// Operator-acknowledged misconfig bypass. Defaults to `false`.
    ///
    /// When `true`, structural cert validation errors do NOT block
    /// policy load — they are captured into
    /// [`PolicyBundle::bypassed_cert_misconfigs`] for the kernel boot
    /// to audit. Self-signature errors and pubkey-mismatch errors
    /// are still fatal (no bypass).
    ///
    /// Operators set this when they need to deploy a known-broken
    /// cert (e.g. emergency cert with extra metadata for
    /// documentation), accepting that the kernel will pin the
    /// structural invariants regardless and that the bypass shows
    /// up in the audit chain.
    #[serde(default)]
    pub force_misconfig_bypass: bool,
}

/// One bypassed cert misconfiguration recorded at policy load.
///
/// Emitted into [`PolicyBundle::bypassed_cert_misconfigs`] when an
/// `OperatorEntry` had `force_misconfig_bypass = true` AND its
/// embedded cert tripped at least one structural invariant. The
/// kernel boot consumes this list and emits one
/// `OperatorCertMisconfigBypassed` audit event per entry so the
/// chain of custody is visible.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BypassedCertMisconfig {
    /// SHA-256[:16] of the operator's pubkey — matches the
    /// `pubkey_fingerprint` field on the originating entry.
    pub operator_fingerprint: String,
    /// Operator display name as declared on the entry (NOT the cert,
    /// since the cert may itself be the source of the mismatch).
    pub display_name:         String,
    pub kind:                 CertKind,
    /// The structural validation errors the operator chose to bypass.
    /// Stored as their `Display` strings so the audit event captures
    /// the exact wording the operator saw at validate time.
    pub violations:           Vec<String>,
}

// ---------------------------------------------------------------------------
// Gate entries
// ---------------------------------------------------------------------------

/// A single `[[gates]]` entry.
///
/// ```toml
/// [[gates]]
/// gate_type        = "TestCoverage"
/// verifier_command = "/usr/local/bin/raxis-verify-coverage"
/// max_wall_seconds = 120
/// max_memory_bytes = 536870912
/// network_allowed  = false
/// ```
#[derive(Debug, Clone, Deserialize)]
pub struct GateEntry {
    pub gate_type: String,
    pub verifier_command: String,
    pub max_wall_seconds: u32,
    pub max_memory_bytes: u64,
    /// Advisory only in v1 — not enforced at the OS level (kernel-store.md §2.5.6).
    pub network_allowed: bool,
}

// ---------------------------------------------------------------------------
// Pre-merge verifier entries (V2 — operator-side surface)
// ---------------------------------------------------------------------------

/// Scope filter for an `[[integration_merge_verifiers]]` entry.
/// Documented in `verifier-processes.md §16.3` and consumed at
/// `integration-merge.md §4 Check 5d.1`.
///
/// `Last` is the singular sentinel for "the FINAL IntegrationMerge of
/// the DAG"; `TaskSet` constrains the verifier to merges whose
/// `merged_task_ids` intersect a specific set; `All` (the default)
/// fires on every merge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IntegrationMergeVerifierAppliesTo {
    /// `applies_to = "all"` — fires on every IntegrationMerge.
    All,
    /// `applies_to = "task_set"` — fires only when this merge's
    /// `merged_task_ids` intersects the verifier's `task_set`.
    TaskSet,
    /// `applies_to = "last"` — fires only on the merge that drains
    /// the final remaining `Completed` task in the plan.
    Last,
}

impl Default for IntegrationMergeVerifierAppliesTo {
    fn default() -> Self {
        Self::All
    }
}

/// Failure routing for an `[[integration_merge_verifiers]]` entry.
/// Documented in `verifier-processes.md §5 (block_merge / warn_only)`.
///
/// Operator-side declarations MUST be `BlockMerge` (the operator path
/// cannot downgrade to `warn_only`; that is enforced at validate
/// time). Plan-side declarations may freely choose either; the plan
/// parser reuses this enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IntegrationMergeVerifierOnFailure {
    /// `on_failure = "block_merge"` — non-passing verdict discards
    /// the candidate merged tree; main is NOT advanced; Orchestrator
    /// receives `FAIL_INTEGRATION_MERGE_VERIFIER_BLOCKED`.
    BlockMerge,
    /// `on_failure = "warn_only"` — non-passing verdict surfaces in
    /// audit but the merge proceeds. Plan-side only; rejected at
    /// validate time on the operator surface.
    WarnOnly,
}

/// One declared `[[integration_merge_verifiers]]` entry.
///
/// **Schema parity.** Mirrors the `policy.toml` operator-side schema
/// in `policy-plan-authority.md §4 [[integration_merge_verifiers]]`
/// and the plan-side `[[plan.integration_merge_verifiers]]` schema in
/// `verifier-processes.md §15.1` — both use this struct so the
/// downstream Check 5d dispatcher (per `integration-merge.md §4
/// Check 5d.1`) operates on a single typed surface.
///
/// **Operator-only fields.** `required_for_environments` is
/// operator-side only per `policy-plan-authority.md §4
/// [[integration_merge_verifiers]]`; the plan-side parser sets it to
/// `None` and the cross-source validator rejects any plan-side entry
/// that populates it.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct IntegrationMergeVerifierEntry {
    /// Identifier for the verifier within the (plan-source ∪
    /// policy-source) union. Validated at policy/plan load to be
    /// non-empty `[a-z][a-z0-9_]{0,31}`.
    pub name: String,

    /// VM image alias resolving against `[[vm_images]]`. Validated
    /// at policy load to point at an image whose `role_restriction`
    /// contains `"Verifier"` (cross-spec, deferred to the kernel
    /// admission step).
    pub image: String,

    /// Shell command run inside the verifier VM by the
    /// `raxis-verifier` PID-1 via `sh -lc`.
    pub command: String,

    /// Wall-clock timeout duration string (`"30s"`, `"10m"`, `"1h"`).
    /// Validated at load time against the kernel hard cap
    /// (`max_verifier_timeout_seconds`).
    pub timeout: String,

    /// Failure routing per `verifier-processes.md §5`. Operator-side
    /// declarations MUST be `BlockMerge`; plan-side declarations may
    /// be either `BlockMerge` or `WarnOnly`.
    pub on_failure: IntegrationMergeVerifierOnFailure,

    /// Scope filter per `verifier-processes.md §16.3`. Defaults to
    /// `All` when the operator omits the field.
    #[serde(default)]
    pub applies_to: IntegrationMergeVerifierAppliesTo,

    /// Required iff `applies_to = TaskSet`. Each entry is validated
    /// to be a declared `[[plan.tasks]] task_id` at `approve_plan`
    /// time (cross-source — the policy load itself cannot validate
    /// against tasks because tasks live in the plan, not the
    /// policy bundle).
    #[serde(default)]
    pub task_set: Vec<String>,

    /// Optional artifact path that the kernel stages into
    /// `staging/merge/<integration_merge_id>/<verifier_name>/` after
    /// a passing run. Must start with `/raxis/` per
    /// `verifier-processes.md §6`.
    #[serde(default)]
    pub artifact: Option<String>,

    /// Optional cap on staged artifact bytes. Validated against the
    /// kernel hard cap (`max_artifact_bytes`).
    #[serde(default)]
    pub artifact_max_bytes: Option<u64>,

    /// Optional environment variables exposed to the verifier
    /// command. Operator-side validation rejects keys starting with
    /// `RAXIS_` (reserved for kernel-injected scope keys) and caps
    /// the count and total size.
    #[serde(default)]
    pub env: HashMap<String, String>,

    /// Optional per-verifier egress allowlist. Empty by default per
    /// `INV-VERIFIER-11`. Operator-side egress entries are stored as
    /// raw strings here; the egress-admission crate validates the
    /// shape at policy load time (cross-spec; the policy bundle
    /// keeps the strings opaque so the egress vocabulary can evolve
    /// without churning this struct).
    #[serde(default)]
    pub allowed_egress: Vec<String>,

    /// Operator-only: bind the verifier to a subset of declared
    /// `[environments.<label>]` entries per
    /// `environment-access-control.md §5b`. Plan-side parsers MUST
    /// reject any plan-source entry that populates this field; the
    /// policy validator additionally checks that every entry resolves
    /// to a declared environment label.
    #[serde(default)]
    pub required_for_environments: Option<Vec<String>>,
}

// ---------------------------------------------------------------------------
// Role entries
// ---------------------------------------------------------------------------

/// A `[[roles]]` entry establishing the capability ceiling for a role.
///
/// ```toml
/// [[roles]]
/// role_id   = "planner-standard"
/// ceiling   = ["WriteCode", "ReadSecrets"]
/// ```
#[derive(Debug, Clone, Deserialize)]
pub struct RoleEntry {
    pub role_id: String,
    /// The set of CapabilityClass variant names this role is permitted to
    /// delegate. authority::delegation::grant_delegation enforces this.
    pub ceiling: Vec<String>,
}

// ---------------------------------------------------------------------------
// Claim requirements
// ---------------------------------------------------------------------------

/// `[claim_requirements]` — maps path globs to required claim types.
///
/// ```toml
/// [claim_requirements]
/// default_action = "deny"   # or "permit"
/// [[claim_requirements.rules]]
/// path_glob    = "src/**"
/// claim_types  = ["WriteCode"]
/// ```
#[derive(Debug, Deserialize)]
pub struct ClaimRequirementsSection {
    /// "permit" → default allow (no claim needed for unmatched paths).
    /// "deny"   → StrictDefault (any unmatched path requires explicit claim).
    #[serde(default = "default_claim_action")]
    pub default_action: String,
    #[serde(default)]
    pub rules: Vec<ClaimRule>,
}

impl Default for ClaimRequirementsSection {
    fn default() -> Self {
        Self {
            default_action: default_claim_action(),
            rules: Vec::new(),
        }
    }
}

fn default_claim_action() -> String { "permit".to_owned() }

/// One rule in `[[claim_requirements.rules]]`.
#[derive(Debug, Clone, Deserialize)]
pub struct ClaimRule {
    /// Glob pattern matched against relative file paths (e.g. `src/**`).
    pub path_glob: String,
    /// Claim type names that satisfy the requirement for matched paths.
    pub claim_types: Vec<String>,
}

// ---------------------------------------------------------------------------
// Egress allowlist
// ---------------------------------------------------------------------------

/// `[egress]` — domain allowlist for outbound HTTP fetches.
///
/// ```toml
/// [egress]
/// max_fetches_per_window = 100
/// domains  = ["api.openai.com"]
/// patterns = ["*.github.com"]
/// ```
#[derive(Debug, Default, Deserialize)]
pub struct EgressSection {
    #[serde(default = "default_max_fetches")]
    pub max_fetches_per_window: u32,
    #[serde(default)]
    pub domains: Vec<String>,
    #[serde(default)]
    pub patterns: Vec<String>,
}

fn default_max_fetches() -> u32 { 100 }

// ---------------------------------------------------------------------------
// Gateway supervisor config — `[gateway]`
//
// Spec ref: peripherals.md §3.2 "Spawn model" — the kernel spawns one
// `raxis-gateway` subprocess at boot and supervises it (respawns on crash;
// new gateway_process_token issued on each spawn). The single-gateway
// model is justified by tokio's async multiplexing: one process can fan
// out to thousands of concurrent HTTP requests over the gateway UDS. No
// pool needed.
// ---------------------------------------------------------------------------

/// `[gateway]` — gateway subprocess supervisor parameters.
///
/// ```toml
/// [gateway]
/// binary_path             = "/usr/local/bin/raxis-gateway"
/// spawn_timeout_secs      = 5     # how long the kernel waits for GatewayReady
/// respawn_backoff_ms      = 1000  # initial back-off between respawns; doubles
/// max_consecutive_respawns = 5    # circuit-breaker: too many crashes → quarantine
/// ```
///
/// All fields except `binary_path` have defaults so most operators only
/// need `binary_path = "..."`. The kernel re-validates `binary_path` at
/// spawn time (not at policy validate time), since the binary file may
/// be added or replaced after the policy artifact is signed.
#[derive(Debug, Clone, Deserialize)]
pub struct GatewaySection {
    /// Absolute path to the `raxis-gateway` binary. The kernel
    /// `Command::new(binary_path)` at boot. MUST be absolute (validated at
    /// PolicyBundle::validate time) so PATH-based hijacks are impossible.
    pub binary_path: String,

    /// Maximum seconds to wait for `GatewayMessage::GatewayReady` after
    /// spawning. If the gateway does not handshake in time, the kernel
    /// terminates the child and treats it as a crash for the respawn loop.
    /// Default: 5 seconds.
    #[serde(default = "default_gateway_spawn_timeout_secs")]
    pub spawn_timeout_secs: u64,

    /// Initial back-off (in milliseconds) between respawn attempts after a
    /// crash. Doubles each consecutive crash up to a hard cap of 60 s.
    /// Default: 1000 ms.
    #[serde(default = "default_gateway_respawn_backoff_ms")]
    pub respawn_backoff_ms: u64,

    /// After this many consecutive respawns within the back-off window the
    /// kernel quarantines the gateway slot — no further respawns until the
    /// operator either restarts the kernel OR triggers a manual respawn via
    /// `raxis-cli gateway restart` (planned for v2). FetchRequests issued
    /// while quarantined return `error: "GatewayUnavailable"`.
    /// Default: 5 respawns.
    #[serde(default = "default_gateway_max_consecutive_respawns")]
    pub max_consecutive_respawns: u32,
}

fn default_gateway_spawn_timeout_secs() -> u64 { 5 }
fn default_gateway_respawn_backoff_ms() -> u64 { 1000 }
fn default_gateway_max_consecutive_respawns() -> u32 { 5 }

// ---------------------------------------------------------------------------
// Plan-signing freshness / replay-protection — `[plan_signing]`
// ---------------------------------------------------------------------------

/// Hard ceiling on `[plan_signing].max_plan_bundle_age_secs`. 30 days.
/// Per `plan-bundle-sealing.md §7.4`: operators with longer review
/// cycles MAY raise the freshness window up to this ceiling. Above this
/// the storage cost of `plan_bundle_nonces_seen` rises faster than the
/// operational benefit (the sweep window is `age + skew + grace`).
pub const PLAN_BUNDLE_MAX_AGE_HARD_CEILING_SECS: u64 = 30 * 24 * 60 * 60;

/// Hard ceiling on `[plan_signing].nonce_sweep_interval_secs`. Once
/// per day. The sweep is a single SQL DELETE on a small (typically
/// <100 KiB) table — it is essentially free. The hard ceiling exists
/// only to keep the table from growing without bound under operator
/// misconfiguration: with the default 25h freshness window and a 1d
/// sweep cadence, steady-state growth is bounded by twice the daily
/// admission rate.
pub const PLAN_SIGNING_NONCE_SWEEP_INTERVAL_HARD_CEILING_SECS: u64 = 24 * 60 * 60;

/// `[plan_signing]` — replay-protection and freshness configuration
/// for the V2.1 plan-bundle admission path.
///
/// ```toml
/// [plan_signing]
/// max_plan_bundle_age_secs    = 86_400   # 24 h freshness window
/// max_clock_skew_secs         = 300      # 5 min future tolerance
/// nonce_retention_grace_secs  = 3_600    # 1 h sweep grace beyond age+skew
/// nonce_sweep_interval_secs   = 3_600    # how often the kernel sweeps
/// accept_unfresh_v2_0_bundles = false    # transitional: accept legacy schema-1 bundles
/// ```
///
/// All five fields have defaults so a kernel that omits the section
/// boots with the spec defaults — a deliberate forward-compat choice
/// while §7.4 / §8.4 incrementally lands. The structural invariants
/// from `plan-bundle-sealing.md §7.4` are checked at policy validate
/// time:
///
///   * `max_plan_bundle_age_secs ≤ PLAN_BUNDLE_MAX_AGE_HARD_CEILING_SECS`
///   * `max_clock_skew_secs ≤ max_plan_bundle_age_secs / 4`
///   * `nonce_retention_grace_secs ≤ max_plan_bundle_age_secs`
///     *(grace beyond the freshness window is bounded by the window
///     itself — a longer grace would just store dead rows)*
///   * `1 ≤ nonce_sweep_interval_secs ≤ PLAN_SIGNING_NONCE_SWEEP_INTERVAL_HARD_CEILING_SECS`
///
/// Failures map to `FAIL_POLICY_PLAN_SIGNING_INVALID` at policy load
/// (`plan-bundle-sealing.md §9`).
///
/// `nonce_sweep_interval_secs` is a V2.1 implementation field not
/// present in the original `plan-bundle-sealing.md §7.4` table. It is
/// the cadence on which the kernel runs the §8.4 nonce-table DELETE
/// query. The spec previously left this implicit ("default once per
/// hour"); making it operator-tunable lets large deployments lengthen
/// the cadence without touching the freshness window. Documented
/// in-spec at §7.4 / §8.4 to keep implementation and spec aligned.
#[derive(Debug, Clone, Deserialize)]
pub struct PlanSigningSection {
    /// How long a signed bundle remains submittable before
    /// `FAIL_PLAN_BUNDLE_EXPIRED`. Default: 24 h. Hard ceiling: 30 d.
    #[serde(default = "default_max_plan_bundle_age_secs")]
    pub max_plan_bundle_age_secs: u64,

    /// Future-clock tolerance: `signed_at_unix_secs - now() > this`
    /// triggers `FAIL_PLAN_BUNDLE_FROM_FUTURE`. MUST be
    /// ≤ `max_plan_bundle_age_secs / 4` so the freshness window cannot
    /// invert under operator clock drift. Default: 5 min.
    #[serde(default = "default_max_clock_skew_secs")]
    pub max_clock_skew_secs: u64,

    /// Grace term added to the §8.4 sweep cutoff: a nonce is reaped
    /// once `now() - first_seen_at_unix_secs >
    ///   max_plan_bundle_age_secs + max_clock_skew_secs + this`.
    /// Default: 1 h. MUST be ≤ `max_plan_bundle_age_secs` (a longer
    /// grace just stores dead rows).
    #[serde(default = "default_nonce_retention_grace_secs")]
    pub nonce_retention_grace_secs: u64,

    /// Cadence on which the kernel runs the §8.4 sweep DELETE query.
    /// Default: 1 h. Hard floor: 1 second. Hard ceiling: 24 h.
    #[serde(default = "default_nonce_sweep_interval_secs")]
    pub nonce_sweep_interval_secs: u64,

    /// Transitional knob (§3.1): accept schema-1 / V2.0 bundles
    /// without a freshness envelope. Default: `false`. Setting to
    /// `true` is operator-acknowledged legacy bypass; documented as
    /// transitional only in §3.1.
    #[serde(default)]
    pub accept_unfresh_v2_0_bundles: bool,
}

impl Default for PlanSigningSection {
    fn default() -> Self {
        Self {
            max_plan_bundle_age_secs:    default_max_plan_bundle_age_secs(),
            max_clock_skew_secs:         default_max_clock_skew_secs(),
            nonce_retention_grace_secs:  default_nonce_retention_grace_secs(),
            nonce_sweep_interval_secs:   default_nonce_sweep_interval_secs(),
            accept_unfresh_v2_0_bundles: false,
        }
    }
}

impl PlanSigningSection {
    /// Total span of time during which a nonce row is considered live
    /// for replay-protection purposes. Used by the kernel's §8.4 sweep
    /// loop: rows older than `now() - nonce_live_window_secs` are
    /// safe to delete because their associated `signed_at_unix_secs`
    /// is, by construction, outside the freshness window already.
    pub fn nonce_live_window_secs(&self) -> u64 {
        self.max_plan_bundle_age_secs
            .saturating_add(self.max_clock_skew_secs)
            .saturating_add(self.nonce_retention_grace_secs)
    }

    /// Apply the §7.4 structural invariants. Returns the field name
    /// and a one-line explanation on failure so the loader can wrap
    /// it in `FAIL_POLICY_PLAN_SIGNING_INVALID`.
    pub(crate) fn validate(&self) -> Result<(), String> {
        if self.max_plan_bundle_age_secs == 0 {
            return Err(
                "[plan_signing].max_plan_bundle_age_secs must be > 0".to_owned(),
            );
        }
        if self.max_plan_bundle_age_secs > PLAN_BUNDLE_MAX_AGE_HARD_CEILING_SECS {
            return Err(format!(
                "[plan_signing].max_plan_bundle_age_secs ({}) exceeds the hard \
                 ceiling of {} seconds (30 days)",
                self.max_plan_bundle_age_secs,
                PLAN_BUNDLE_MAX_AGE_HARD_CEILING_SECS,
            ));
        }
        if self.max_clock_skew_secs > self.max_plan_bundle_age_secs / 4 {
            return Err(format!(
                "[plan_signing].max_clock_skew_secs ({}) must be <= \
                 max_plan_bundle_age_secs / 4 ({})",
                self.max_clock_skew_secs,
                self.max_plan_bundle_age_secs / 4,
            ));
        }
        if self.nonce_retention_grace_secs > self.max_plan_bundle_age_secs {
            return Err(format!(
                "[plan_signing].nonce_retention_grace_secs ({}) must be <= \
                 max_plan_bundle_age_secs ({})",
                self.nonce_retention_grace_secs,
                self.max_plan_bundle_age_secs,
            ));
        }
        if self.nonce_sweep_interval_secs == 0 {
            return Err(
                "[plan_signing].nonce_sweep_interval_secs must be > 0".to_owned(),
            );
        }
        if self.nonce_sweep_interval_secs > PLAN_SIGNING_NONCE_SWEEP_INTERVAL_HARD_CEILING_SECS {
            return Err(format!(
                "[plan_signing].nonce_sweep_interval_secs ({}) exceeds the hard \
                 ceiling of {} seconds (24 hours)",
                self.nonce_sweep_interval_secs,
                PLAN_SIGNING_NONCE_SWEEP_INTERVAL_HARD_CEILING_SECS,
            ));
        }
        Ok(())
    }
}

fn default_max_plan_bundle_age_secs()    -> u64 { 24 * 60 * 60 } // 24 h
fn default_max_clock_skew_secs()         -> u64 { 5 * 60 }       // 5 min
fn default_nonce_retention_grace_secs()  -> u64 { 60 * 60 }      // 1 h
fn default_nonce_sweep_interval_secs()   -> u64 { 60 * 60 }      // 1 h

// ---------------------------------------------------------------------------
// Plan-bundle size limits — `[plan_bundle_limits]`
// ---------------------------------------------------------------------------

/// Hard ceiling on `[plan_bundle_limits].max_artifact_bytes`. 64 MiB
/// per `plan-bundle-sealing.md §7.4`. The kernel's SQLite write path
/// can absorb one 64 MiB blob without touching paging behaviour; above
/// this, the per-bundle commit cost rises non-linearly under WAL
/// pressure. Operators who legitimately need bigger artifacts SHOULD
/// move the data out-of-bundle (e.g. into a side-channel content
/// store) rather than raising this ceiling.
pub const PLAN_BUNDLE_MAX_ARTIFACT_BYTES_HARD_CEILING: u64 = 64 * 1024 * 1024;

/// Hard ceiling on `[plan_bundle_limits].max_bundle_bytes`. 128 MiB
/// per `plan-bundle-sealing.md §7.4`. With the per-artifact ceiling
/// at 64 MiB this leaves room for two near-max artifacts plus
/// canonical-encoding overhead. The kernel's bundle SHA-256 + Ed25519
/// verify path is bounded linearly in bundle size; even the worst
/// case completes in well under 100 ms on commodity hardware.
pub const PLAN_BUNDLE_MAX_BUNDLE_BYTES_HARD_CEILING: u64 = 128 * 1024 * 1024;

/// Hard ceiling on `[plan_bundle_limits].max_artifact_count`. 1024
/// per `plan-bundle-sealing.md §7.4`. With one artifact in V2.0
/// (always `plan.toml`) and a small handful in early V2.1, this
/// ceiling is two orders of magnitude above realistic usage; it
/// exists to bound the per-row cost in `plan_bundle_artifacts` and
/// prevent a misconfigured policy from greenlighting a bundle that
/// would individually overwhelm the SQLite write path (one row per
/// artifact, one INSERT per row inside the admission tx).
pub const PLAN_BUNDLE_MAX_ARTIFACT_COUNT_HARD_CEILING: u32 = 1024;

/// `[plan_bundle_limits]` — V2 plan-bundle size discipline.
///
/// ```toml
/// [plan_bundle_limits]
/// max_artifact_bytes  = 1_048_576       # 1 MiB
/// max_bundle_bytes    = 10_485_760      # 10 MiB
/// max_artifact_count  = 200
/// ```
///
/// All three fields default per `plan-bundle-sealing.md §7.4` so a
/// kernel that omits the section boots cleanly. Operators MAY lower
/// the caps below the defaults but MUST NOT raise them above the
/// hard ceilings:
///
///   * `max_artifact_bytes ≤ PLAN_BUNDLE_MAX_ARTIFACT_BYTES_HARD_CEILING` (64 MiB)
///   * `max_bundle_bytes ≤ PLAN_BUNDLE_MAX_BUNDLE_BYTES_HARD_CEILING` (128 MiB)
///   * `max_artifact_count ≤ PLAN_BUNDLE_MAX_ARTIFACT_COUNT_HARD_CEILING` (1024)
///
/// In addition, structural coherence is enforced at validate time:
///
///   * `max_artifact_bytes ≤ max_bundle_bytes` (a single artifact
///     cannot exceed the total bundle cap, since the bundle contains
///     at least that artifact)
///   * `max_bundle_bytes ≥ 1` and `max_artifact_count ≥ 1` (a bundle
///     with zero artifacts cannot satisfy `artifacts[0] = plan.toml`)
///
/// Failures map to `FAIL_POLICY_PLAN_BUNDLE_LIMIT_ABOVE_CEILING` at
/// policy load (`plan-bundle-sealing.md §9`).
#[derive(Debug, Clone, Deserialize)]
pub struct PlanBundleLimitsSection {
    /// Maximum bytes for any single artifact (including `plan.toml`).
    /// Enforced both CLI-side (§7.2) and kernel-side (§7.3).
    /// Default: 1 MiB.
    #[serde(default = "default_max_artifact_bytes")]
    pub max_artifact_bytes: u64,

    /// Maximum total bytes for the bundle, summed over artifact bytes.
    /// Canonical-encoding overhead is negligible (a few hundred bytes
    /// per artifact); the cap covers payload bytes only.
    /// Default: 10 MiB.
    #[serde(default = "default_max_bundle_bytes")]
    pub max_bundle_bytes: u64,

    /// Maximum number of artifacts in the bundle. `plan.toml` itself
    /// counts as one artifact — so this is the cap on
    /// `bundle.artifacts.len()`, not on referenced auxiliary files.
    /// Default: 200.
    #[serde(default = "default_max_artifact_count")]
    pub max_artifact_count: u32,
}

impl Default for PlanBundleLimitsSection {
    fn default() -> Self {
        Self {
            max_artifact_bytes: default_max_artifact_bytes(),
            max_bundle_bytes:   default_max_bundle_bytes(),
            max_artifact_count: default_max_artifact_count(),
        }
    }
}

impl PlanBundleLimitsSection {
    /// Apply the §7.4 ceiling + coherence invariants. Returns the
    /// field name and a one-line explanation on failure so the
    /// loader can wrap it in `FAIL_POLICY_PLAN_BUNDLE_LIMIT_ABOVE_CEILING`.
    pub(crate) fn validate(&self) -> Result<(), String> {
        if self.max_artifact_bytes == 0 {
            return Err(
                "[plan_bundle_limits].max_artifact_bytes must be > 0".to_owned(),
            );
        }
        if self.max_artifact_bytes > PLAN_BUNDLE_MAX_ARTIFACT_BYTES_HARD_CEILING {
            return Err(format!(
                "[plan_bundle_limits].max_artifact_bytes ({}) exceeds the hard \
                 ceiling of {} bytes (64 MiB)",
                self.max_artifact_bytes,
                PLAN_BUNDLE_MAX_ARTIFACT_BYTES_HARD_CEILING,
            ));
        }
        if self.max_bundle_bytes == 0 {
            return Err(
                "[plan_bundle_limits].max_bundle_bytes must be > 0".to_owned(),
            );
        }
        if self.max_bundle_bytes > PLAN_BUNDLE_MAX_BUNDLE_BYTES_HARD_CEILING {
            return Err(format!(
                "[plan_bundle_limits].max_bundle_bytes ({}) exceeds the hard \
                 ceiling of {} bytes (128 MiB)",
                self.max_bundle_bytes,
                PLAN_BUNDLE_MAX_BUNDLE_BYTES_HARD_CEILING,
            ));
        }
        if self.max_artifact_count == 0 {
            return Err(
                "[plan_bundle_limits].max_artifact_count must be > 0".to_owned(),
            );
        }
        if self.max_artifact_count > PLAN_BUNDLE_MAX_ARTIFACT_COUNT_HARD_CEILING {
            return Err(format!(
                "[plan_bundle_limits].max_artifact_count ({}) exceeds the hard \
                 ceiling of {}",
                self.max_artifact_count,
                PLAN_BUNDLE_MAX_ARTIFACT_COUNT_HARD_CEILING,
            ));
        }
        if self.max_artifact_bytes > self.max_bundle_bytes {
            return Err(format!(
                "[plan_bundle_limits].max_artifact_bytes ({}) must be <= \
                 max_bundle_bytes ({}) — a single artifact cannot exceed the \
                 total bundle cap",
                self.max_artifact_bytes,
                self.max_bundle_bytes,
            ));
        }
        Ok(())
    }
}

fn default_max_artifact_bytes() -> u64 { 1 * 1024 * 1024 }       // 1 MiB
fn default_max_bundle_bytes()   -> u64 { 10 * 1024 * 1024 }      // 10 MiB
fn default_max_artifact_count() -> u32 { 200 }

// ---------------------------------------------------------------------------
// Provider entries — `[[providers]]`
// ---------------------------------------------------------------------------

/// One `[[providers]]` table entry.
///
/// ```toml
/// [[providers]]
/// provider_id           = "anthropic-prod"
/// kind                  = "Anthropic"
/// credentials_file      = "anthropic-prod.toml"
/// inference_timeout_ms  = 30000
/// data_fetch_timeout_ms = 10000
/// max_response_bytes    = 16777216   # 16 MiB
/// ```
///
/// `credentials_file` is resolved relative to `<data_dir>/providers/`. The
/// resolved path MUST exist with mode 0600 (kernel uid only) at gateway
/// startup; the gateway loads it and injects the API key into outbound
/// requests. The kernel never reads provider credentials directly
/// (peripherals.md §3.2 "Provider credential storage").
#[derive(Debug, Clone, Deserialize)]
pub struct ProviderEntry {
    /// Short opaque identifier referenced by the kernel's
    /// `provider/` adapter (e.g. "anthropic-prod"). Must be unique across
    /// the whole `[[providers]]` array; PolicyBundle::validate enforces.
    pub provider_id: String,

    /// String discriminator for the provider's wire format. v1 known
    /// values: `"Anthropic"`, `"OpenAI"`. Unknown values are accepted at
    /// policy-validate time (forward-compat) but the gateway will reject
    /// any FetchRequest routed to an unknown kind at dispatch time with
    /// `error: "UnknownProviderKind"`.
    pub kind: String,

    /// Filename (no path components) under `<data_dir>/providers/`.
    /// Validated by PolicyBundle::validate to contain no `/` or `..` so
    /// it cannot escape the providers dir.
    pub credentials_file: String,

    /// Per-FetchRequest hard timeout for `fetch_kind: "Inference"`.
    /// Capped at 120000 ms (peripherals.md §3.2). Default: 30000 ms.
    #[serde(default = "default_inference_timeout_ms")]
    pub inference_timeout_ms: u32,

    /// Per-FetchRequest hard timeout for `fetch_kind: "DataFetch"`.
    /// Capped at 60000 ms. Default: 10000 ms.
    #[serde(default = "default_data_fetch_timeout_ms")]
    pub data_fetch_timeout_ms: u32,

    /// Maximum response body size before the gateway returns
    /// `error: "ResponseTooLarge"`. Capped at 64 MiB. Default: 16 MiB.
    #[serde(default = "default_max_response_bytes")]
    pub max_response_bytes: u64,
}

fn default_inference_timeout_ms() -> u32 { 30_000 }
fn default_data_fetch_timeout_ms() -> u32 { 10_000 }
fn default_max_response_bytes() -> u64 { 16 * 1024 * 1024 }

/// Hard cap on inference timeout, normative per peripherals.md §3.2.
pub const MAX_INFERENCE_TIMEOUT_MS: u32 = 120_000;
/// Hard cap on data-fetch timeout, normative per peripherals.md §3.2.
pub const MAX_DATA_FETCH_TIMEOUT_MS: u32 = 60_000;
/// Hard cap on response body size, normative per peripherals.md §3.2
/// ("v1 constraint: 16 MiB ... configurable in `[[providers]]`"). The
/// configurable knob has its own ceiling so a malicious or misconfigured
/// policy cannot turn the gateway into a DoS amplifier.
pub const MAX_RESPONSE_BYTES_CEILING: u64 = 64 * 1024 * 1024;

// ---------------------------------------------------------------------------
// Notification channels — `[notifications]`
//
// Normative reference: cli-readonly.md §5.6.
//
// v1 ships handlers for `Shell` and `File` only; `Email` and `Webhook`
// are accepted at policy-validate time so operators can stage their v2
// channel config but each one emits a one-line warning at boot
// ("declared but its handler is not implemented in v1").
// ---------------------------------------------------------------------------

/// Channel-kind discriminator. v1 implements Shell + File only;
/// Email and Webhook are forward-compat schema slots (per spec §5.6.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
pub enum NotificationChannelKind {
    Shell,
    File,
    Email,
    Webhook,
}

/// One `[[notifications.channels]]` entry.
///
/// ```toml
/// [[notifications.channels]]
/// id     = "shell"
/// kind   = "Shell"
/// target = "<data_dir>/notifications/inbox.jsonl"
/// ```
#[derive(Debug, Clone, Deserialize)]
pub struct NotificationChannel {
    /// Operator-chosen short identifier referenced from `[[notifications.routes]].channels`.
    /// Must be unique across the channels array; PolicyBundle::validate enforces.
    pub id:     String,
    pub kind:   NotificationChannelKind,
    /// For `Shell`/`File`: an absolute filesystem path the kernel will
    /// `O_APPEND | O_CREAT` (the `Shell` channel's default target —
    /// `<data_dir>/notifications/inbox.jsonl` — is filled in at runtime
    /// when the operator omits the explicit channel entry, see
    /// `PolicyBundle::shell_inbox_path_for`).
    /// For `Email`: the recipient address (validated only as non-empty in v1).
    /// For `Webhook`: the destination URL (validated only as non-empty in v1).
    pub target: String,
}

/// One `[[notifications.routes]]` entry: which channels receive
/// notifications for a given audit event-kind.
///
/// ```toml
/// [[notifications.routes]]
/// event_kind = "EscalationApproved"
/// channels   = ["shell"]
/// ```
///
/// An empty `channels` list is the canonical "silenced" form for that
/// event kind (per spec §5.6.2 rule 2).
#[derive(Debug, Clone, Deserialize)]
pub struct NotificationRoute {
    /// MUST match a real `AuditEventKind` discriminant string. Validated
    /// against [`KNOWN_AUDIT_EVENT_KINDS`] at policy load time.
    pub event_kind: String,
    pub channels:   Vec<String>,
}

/// `[notifications]` raw TOML shape. Consumed by `PolicyBundle::validate`.
#[derive(Debug, Clone, Default, Deserialize)]
pub(crate) struct NotificationsSection {
    /// Channel ids dispatched to when an event kind has no explicit
    /// route. If empty, an unrouted event is silently dropped (the
    /// caller-side "no route" fast-path).
    #[serde(default)]
    pub default_channels: Vec<String>,

    #[serde(default, rename = "channels")]
    pub channels_raw: Vec<NotificationChannel>,

    #[serde(default, rename = "routes")]
    pub routes_raw: Vec<NotificationRoute>,
}

/// Implicit channel id used by the spec's "always-on Shell channel"
/// (cli-readonly.md §5.6.2: "always present implicitly; explicit entry
/// overrides target"). The kernel synthesises this entry at validate
/// time when the operator does not declare it.
pub const IMPLICIT_SHELL_CHANNEL_ID: &str = "shell";

/// Filename appended to `<data_dir>/notifications/` for the implicit
/// Shell channel target (cli-readonly.md §5.6.2).
pub const IMPLICIT_SHELL_INBOX_FILENAME: &str = "inbox.jsonl";

/// Every `AuditEventKind` discriminant string the kernel currently
/// emits. `PolicyBundle::validate` rejects routes whose `event_kind`
/// is not in this list (preventing a typo from silently dropping
/// every notification for that kind).
///
/// Kept in lockstep with `raxis-audit-tools::AuditEventKind::as_str`.
/// A unit test in this crate cross-checks the two lists.
pub const KNOWN_AUDIT_EVENT_KINDS: &[&str] = &[
    // lifecycle
    "KernelStarted", "KernelStopped",
    // V2 agent-runtime substrate (extensibility-traits.md §3.8)
    "IsolationSubstrateSelected", "IsolationFallbackBypass",
    "IsolationSubstrateRefused",
    // V2 per-session VM lifecycle (extensibility-traits.md §3.5,
    // credential-proxy.md §2; paired-class — see audit-paired-writes.md §4.1).
    "SessionVmSpawned", "SessionVmExited",
    // initiative
    "InitiativeCreated", "PlanApproved", "PlanRejected",
    "PathScopeOverrideApplied", "InitiativeStateChanged", "InitiativeAborted",
    // task
    "TaskAdmitted", "TaskStateChanged",
    // intent
    "IntentAccepted", "IntentRejected",
    "IntegrationMergeCompleted",
    // session
    "SessionCreated", "SessionRevoked",
    // delegation
    "DelegationGranted", "DelegationMarkedStale",
    // witness/gate
    "WitnessAccepted", "WitnessRejected", "VerifierProcessFailed",
    // escalation
    "EscalationSubmitted", "EscalationApproved", "EscalationDenied",
    "EscalationTimedOut", "EscalationConsumed", "LineageQuarantined",
    "EscalationRateLimitExceeded",
    // policy
    "PolicyEpochAdvanced", "PolicyAdvanceRejected", "PolicyAdvanceFailed",
    // ipc
    "ReplayRejected",
    // recovery
    "ReconciliationGap", "TaskBlockedForRecovery",
    "DelegationSignatureUnverifiable",
    // gateway
    "GatewaySpawned", "GatewayCrashed", "GatewayQuarantined",
    "GatewaySignalFailed",
    // notifications (self-reflective)
    "NotificationDeliveryFailed",
    // operator certificates (kernel-store.md §2.5.7, security-model.md §cert-lifecycle)
    "OperatorCertInstalled",
    "OperatorCertMisconfigBypassed", "OperatorCertExpiringSoon",
    "OperatorCertInGracePeriod", "OperatorCertExpiredOpDenied",
    "EmergencyOperatorUsed",
    // read-only CLI redaction reveal (cli-readonly.md §5.4.2 / §5.7.2)
    "PathReadAccessed",
    // initiative quarantine (kernel-store.md §2.5.8)
    "InitiativeQuarantined", "OperatorQuarantineSwept",
];

/// Validate the raw `[notifications]` section and produce the final
/// `(channels, routes, default_channels)` triple for `PolicyBundle`.
///
/// Rules enforced (mirroring `cli-readonly.md` §5.6.2):
///
/// 1. **Channel ids are unique.** Duplicate `id` values fail loudly.
/// 2. **Implicit Shell is always present.** If the operator does not
///    declare a channel with `id="shell"`, we synthesise one with
///    `kind=Shell, target=""`. The empty target is interpreted by the
///    Shell handler as "use the default `<data_dir>/notifications/inbox.jsonl`"
///    (resolved at runtime via `PolicyBundle::shell_inbox_path_for`).
/// 3. **Default channels reference declared ids.** Every entry in
///    `default_channels` MUST resolve to a channel id (the implicit
///    `"shell"` counts).
/// 4. **Route channel ids resolve.** Every channel id in a route's
///    `channels` array MUST resolve to a declared id.
/// 5. **Route event_kind is real.** The event_kind MUST appear in
///    [`KNOWN_AUDIT_EVENT_KINDS`] (defence against typo-silenced
///    routes).
/// 6. **Default channels default to `["shell"]`** when the operator
///    omits the field — never empty, so an event kind with no route
///    is dispatched to the implicit Shell channel rather than silently
///    dropped.
/// 7. **For Email/Webhook channels**, validate target is non-empty;
///    the kernel emits a one-line warning at boot per spec §5.6.2.

// ---------------------------------------------------------------------------
// `[[integration_merge_verifiers]]` operator-side validator (V2).
// ---------------------------------------------------------------------------

/// Operator-side environment-key reservation prefix. Mirrors the
/// per-task verifier validator's discipline (`policy-plan-authority.md
/// §4 step 3.6 / 3.7`): keys starting with `RAXIS_` are reserved for
/// kernel-injected scope keys (`RAXIS_VERIFIER_HOOK_KIND`,
/// `RAXIS_INTEGRATION_MERGE_ID`, …) and operator declarations MUST
/// NOT collide.
///
/// Exposed `pub` so the kernel-side plan validator
/// (`approve_plan` Step 2) can apply the same rule to plan-source
/// `[[plan.integration_merge_verifiers]]` entries without
/// duplicating the literal.
pub const RAXIS_RESERVED_ENV_PREFIX: &str = "RAXIS_";

/// Hard cap on `[[integration_merge_verifiers.env]]` entry count.
/// Matches per-task verifier discipline; `policy-plan-authority.md §4
/// [[integration_merge_verifiers]] env`. `pub` for kernel re-use
/// (see `RAXIS_RESERVED_ENV_PREFIX`).
pub const VERIFIER_ENV_MAX_ENTRIES: usize = 32;

/// Hard cap on the combined size of every `key=value` byte-pair in
/// `[[integration_merge_verifiers.env]]`. 16 KiB is the operator-
/// ergonomic ceiling agreed in `policy-plan-authority.md §4
/// [[integration_merge_verifiers]] env`. `pub` for kernel re-use
/// (see `RAXIS_RESERVED_ENV_PREFIX`).
pub const VERIFIER_ENV_MAX_TOTAL_BYTES: usize = 16 * 1024;

/// Hard cap on a `[[integration_merge_verifiers]] artifact` path.
/// Pinned to 256 chars per `verifier-processes.md §6` (mirrors the
/// per-task verifier limit). `pub` for kernel re-use (see
/// `RAXIS_RESERVED_ENV_PREFIX`).
pub const VERIFIER_ARTIFACT_MAX_PATH_CHARS: usize = 256;

/// Lower bound on `timeout` strings, in seconds. Below this the
/// kernel cannot reliably distinguish a verifier from a startup
/// glitch. Mirrors the per-task verifier floor in
/// `verifier-processes.md §3 [[plan.tasks.<id>.verifiers]] timeout`.
/// `pub` for kernel re-use (see `RAXIS_RESERVED_ENV_PREFIX`).
pub const VERIFIER_TIMEOUT_MIN_SECS: u64 = 5;

/// Validate an operator-side `[[integration_merge_verifiers]]` array.
///
/// **Operator-side discipline.** This validator enforces every rule
/// that does NOT require cross-spec context (vm_images resolution,
/// host_capacity hard cap, environment-label resolution, plan-side
/// task_id intersection). Cross-spec checks land in `approve_plan`
/// (Step 2 of the pre-merge-verifier track) once the relevant
/// surfaces are stitched together.
///
/// ### Rules enforced here
///
/// 1. `name` non-empty, `[a-z][a-z0-9_]{0,31}`, unique across the
///    section.
/// 2. `image` and `command` non-empty.
/// 3. `timeout` parses as a duration string (`"30s"`, `"10m"`, …)
///    that resolves to ≥ 5 seconds. The full upper-bound check
///    (`max_verifier_timeout_seconds` from `[host_capacity]`) is
///    deferred to admission time per `verifier-processes.md §17.5`.
/// 4. `on_failure = "block_merge"` only — the operator surface
///    cannot be downgraded to `warn_only` per
///    `policy-plan-authority.md §4 [[integration_merge_verifiers]]`.
/// 5. `applies_to = "task_set"` ⇒ `task_set` is non-empty;
///    `applies_to ∈ {"all", "last"}` ⇒ `task_set` is empty (any
///    operator entry that mixes the two is rejected with a clear
///    diagnostic).
/// 6. `artifact` (when set) starts with `/raxis/` and is ≤ 256 chars.
/// 7. `env` cap: ≤ 32 entries, total key+value bytes ≤ 16 KiB, no
///    key starts with `RAXIS_`.
/// 8. `required_for_environments` (when set) is non-empty and has
///    no duplicate entries; resolution against the
///    `[environments.<label>]` section is deferred (the bundle does
///    not yet hold an environments map — that section lands with the
///    environment-access-control step).
///
/// ### Returned slice
///
/// Returns the validated entries unchanged. The caller stores the
/// `Vec<IntegrationMergeVerifierEntry>` on the `PolicyBundle`.
fn validate_integration_merge_verifiers_operator_side(
    raw: &[IntegrationMergeVerifierEntry],
) -> Result<(), PolicyError> {
    use std::collections::HashSet;

    let mut seen_names: HashSet<&str> = HashSet::with_capacity(raw.len());

    for entry in raw {
        // Rule 1 — name shape + uniqueness.
        if !is_valid_verifier_name(&entry.name) {
            return Err(PolicyError::MalformedArtifact(format!(
                "FAIL_POLICY_INTEGRATION_MERGE_VERIFIER_NAME_INVALID: \
                 [[integration_merge_verifiers]] entry name `{}` must \
                 match `[a-z][a-z0-9_]{{0,31}}` (operator surface; \
                 mirrors verifier-processes.md §3 schema).",
                entry.name,
            )));
        }
        if !seen_names.insert(entry.name.as_str()) {
            return Err(PolicyError::MalformedArtifact(format!(
                "FAIL_POLICY_INTEGRATION_MERGE_VERIFIER_NAME_COLLISION: \
                 duplicate [[integration_merge_verifiers]] name `{}` \
                 within the operator-side section (cross-source \
                 collision against plan-side is checked at \
                 approve_plan).",
                entry.name,
            )));
        }

        // Rule 2 — image / command non-empty.
        if entry.image.trim().is_empty() {
            return Err(PolicyError::MalformedArtifact(format!(
                "FAIL_POLICY_INTEGRATION_MERGE_VERIFIER_IMAGE_REQUIRED: \
                 [[integration_merge_verifiers]] `{}` must declare a \
                 non-empty `image` (resolved against [[vm_images]] at \
                 admission time).",
                entry.name,
            )));
        }
        if entry.command.trim().is_empty() {
            return Err(PolicyError::MalformedArtifact(format!(
                "FAIL_POLICY_INTEGRATION_MERGE_VERIFIER_COMMAND_REQUIRED: \
                 [[integration_merge_verifiers]] `{}` must declare a \
                 non-empty `command`.",
                entry.name,
            )));
        }

        // Rule 3 — timeout parses and is ≥ 5s.
        let timeout_secs = parse_verifier_timeout_secs(&entry.timeout)
            .ok_or_else(|| {
                PolicyError::MalformedArtifact(format!(
                    "FAIL_POLICY_INTEGRATION_MERGE_VERIFIER_TIMEOUT_INVALID: \
                     [[integration_merge_verifiers]] `{}` has unparseable \
                     `timeout = {:?}` — expected a duration string like \
                     \"30s\", \"10m\", or \"1h\".",
                    entry.name, entry.timeout,
                ))
            })?;
        if timeout_secs < VERIFIER_TIMEOUT_MIN_SECS {
            return Err(PolicyError::MalformedArtifact(format!(
                "FAIL_POLICY_INTEGRATION_MERGE_VERIFIER_TIMEOUT_TOO_SHORT: \
                 [[integration_merge_verifiers]] `{}` has \
                 `timeout = {}s`, must be ≥ {} seconds.",
                entry.name, timeout_secs, VERIFIER_TIMEOUT_MIN_SECS,
            )));
        }

        // Rule 4 — on_failure = block_merge (operator-side only).
        if entry.on_failure != IntegrationMergeVerifierOnFailure::BlockMerge {
            return Err(PolicyError::MalformedArtifact(format!(
                "FAIL_VERIFIER_INVALID_ON_FAILURE: \
                 [[integration_merge_verifiers]] `{}` declared \
                 `on_failure = \"warn_only\"`; operator-side \
                 declarations cannot be downgraded \
                 (policy-plan-authority.md §4 \
                 [[integration_merge_verifiers]]).",
                entry.name,
            )));
        }

        // Rule 5 — applies_to / task_set coherence.
        match entry.applies_to {
            IntegrationMergeVerifierAppliesTo::TaskSet => {
                if entry.task_set.is_empty() {
                    return Err(PolicyError::MalformedArtifact(format!(
                        "FAIL_VERIFIER_TASK_SET_EMPTY: \
                         [[integration_merge_verifiers]] `{}` declared \
                         `applies_to = \"task_set\"` but `task_set` is \
                         empty (must list at least one task id; \
                         resolution against declared tasks is checked \
                         at approve_plan).",
                        entry.name,
                    )));
                }
            }
            IntegrationMergeVerifierAppliesTo::All
            | IntegrationMergeVerifierAppliesTo::Last => {
                if !entry.task_set.is_empty() {
                    return Err(PolicyError::MalformedArtifact(format!(
                        "FAIL_POLICY_INTEGRATION_MERGE_VERIFIER_TASK_SET_INCONSISTENT: \
                         [[integration_merge_verifiers]] `{}` populated \
                         `task_set` but `applies_to = {:?}` does not \
                         consume it; either set `applies_to = \"task_set\"` \
                         or drop the `task_set = [...]` field.",
                        entry.name, entry.applies_to,
                    )));
                }
            }
        }

        // Rule 6 — artifact path shape.
        if let Some(path) = entry.artifact.as_ref() {
            if !path.starts_with("/raxis/") {
                return Err(PolicyError::MalformedArtifact(format!(
                    "FAIL_POLICY_INTEGRATION_MERGE_VERIFIER_ARTIFACT_PATH_INVALID: \
                     [[integration_merge_verifiers]] `{}` declared \
                     `artifact = {:?}`; path must start with `/raxis/` \
                     (verifier-processes.md §6).",
                    entry.name, path,
                )));
            }
            if path.chars().count() > VERIFIER_ARTIFACT_MAX_PATH_CHARS {
                return Err(PolicyError::MalformedArtifact(format!(
                    "FAIL_POLICY_INTEGRATION_MERGE_VERIFIER_ARTIFACT_PATH_TOO_LONG: \
                     [[integration_merge_verifiers]] `{}` `artifact` \
                     path exceeds {} chars.",
                    entry.name, VERIFIER_ARTIFACT_MAX_PATH_CHARS,
                )));
            }
        }

        // Rule 7 — env cap + reserved-prefix.
        if entry.env.len() > VERIFIER_ENV_MAX_ENTRIES {
            return Err(PolicyError::MalformedArtifact(format!(
                "FAIL_POLICY_INTEGRATION_MERGE_VERIFIER_ENV_TOO_MANY_ENTRIES: \
                 [[integration_merge_verifiers]] `{}` declared {} env \
                 entries; max is {}.",
                entry.name, entry.env.len(), VERIFIER_ENV_MAX_ENTRIES,
            )));
        }
        let mut env_byte_total = 0usize;
        for (k, v) in &entry.env {
            if k.starts_with(RAXIS_RESERVED_ENV_PREFIX) {
                return Err(PolicyError::MalformedArtifact(format!(
                    "FAIL_CUSTOM_TOOL_ENV_RESERVED_KEY: \
                     [[integration_merge_verifiers]] `{}` env key \
                     `{}` collides with the reserved `{}*` prefix \
                     (kernel-injected scope keys).",
                    entry.name, k, RAXIS_RESERVED_ENV_PREFIX,
                )));
            }
            env_byte_total = env_byte_total
                .saturating_add(k.len())
                .saturating_add(v.len());
        }
        if env_byte_total > VERIFIER_ENV_MAX_TOTAL_BYTES {
            return Err(PolicyError::MalformedArtifact(format!(
                "FAIL_POLICY_INTEGRATION_MERGE_VERIFIER_ENV_TOO_LARGE: \
                 [[integration_merge_verifiers]] `{}` env entries sum \
                 to {} bytes; max is {} bytes.",
                entry.name, env_byte_total, VERIFIER_ENV_MAX_TOTAL_BYTES,
            )));
        }

        // Rule 8 — required_for_environments coherence (resolution
        // deferred until the environments-section lands).
        if let Some(envs) = entry.required_for_environments.as_ref() {
            if envs.is_empty() {
                return Err(PolicyError::MalformedArtifact(format!(
                    "FAIL_POLICY_INTEGRATION_MERGE_VERIFIER_REQUIRED_ENVS_EMPTY: \
                     [[integration_merge_verifiers]] `{}` declared an \
                     empty `required_for_environments = []`; either \
                     drop the field or list at least one environment \
                     label.",
                    entry.name,
                )));
            }
            let mut seen_envs: HashSet<&str> = HashSet::with_capacity(envs.len());
            for label in envs {
                if !seen_envs.insert(label.as_str()) {
                    return Err(PolicyError::MalformedArtifact(format!(
                        "FAIL_POLICY_INTEGRATION_MERGE_VERIFIER_REQUIRED_ENVS_DUPLICATE: \
                         [[integration_merge_verifiers]] `{}` lists \
                         `{}` twice in `required_for_environments`.",
                        entry.name, label,
                    )));
                }
            }
        }
    }

    Ok(())
}

/// Validate a verifier `name` against the operator-ergonomic
/// `[a-z][a-z0-9_]{0,31}` shape pinned in
/// `policy-plan-authority.md §4 [[integration_merge_verifiers]] name`.
///
/// `pub` so the kernel-side plan validator
/// (`approve_plan` Step 2) can apply the same shape rule to
/// plan-source `[[plan.integration_merge_verifiers]]` entries
/// without duplicating the literal.
pub fn is_valid_verifier_name(s: &str) -> bool {
    let bytes = s.as_bytes();
    if bytes.is_empty() || bytes.len() > 32 {
        return false;
    }
    if !bytes[0].is_ascii_lowercase() {
        return false;
    }
    bytes[1..]
        .iter()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'_')
}

/// V2_GAPS.md §12.8 — fully-qualified target-ref name validator
/// shared by `[git] default_target_ref` (operator-side) and
/// `[workspace] target_ref` (plan-side).
///
/// Approximates `git-check-ref-format(1) --refspec-pattern --branch`:
///
/// * MUST start with `refs/heads/` (only branch refs are advanceable
///   targets — tag refs are immutable, remote-tracking refs are
///   mirrors, `HEAD` is symbolic).
/// * The ref name following `refs/heads/` MUST be 1..=240 bytes
///   (kernel-side total ≤ 256 bytes including the `refs/heads/`
///   prefix, well below libgit2 / gix limits).
/// * Each `/`-separated path component MUST be non-empty and MUST
///   NOT start with `-`, `.`, or end with `.lock` or `.`.
/// * The whole ref name MUST NOT contain any of: ` ` (space),
///   `~`, `^`, `:`, `?`, `*`, `[`, `\\`, control chars (< 0x20 or
///   0x7F), `..`, `@{`, `//`.
/// * Bytes outside ASCII printable are rejected (UTF-8 ref names
///   are theoretically allowed by git but our enforcement table
///   does not yet cover them; reject to fail-closed).
///
/// Returns `Ok(())` on success and `Err(reason)` describing the
/// first violation (used by the loader to construct
/// `FAIL_POLICY_TARGET_REF_INVALID` /
/// `FAIL_WORKSPACE_TARGET_REF_INVALID` diagnostics).
pub fn validate_target_ref_format(target_ref: &str) -> Result<(), String> {
    const PREFIX: &str = "refs/heads/";
    if !target_ref.starts_with(PREFIX) {
        return Err(format!(
            "must start with `{PREFIX}` (only branch refs may be advanced; \
             got prefix-mismatch on {target_ref:?})"
        ));
    }
    if target_ref.len() > 256 {
        return Err(format!(
            "exceeds 256-byte ref-name limit (got {} bytes)",
            target_ref.len()
        ));
    }
    let suffix = &target_ref[PREFIX.len()..];
    if suffix.is_empty() {
        return Err("branch name following `refs/heads/` is empty".to_owned());
    }
    if suffix.contains("//") {
        return Err("contains empty path component (`//`)".to_owned());
    }
    if suffix.contains("..") {
        return Err("contains forbidden `..` sequence".to_owned());
    }
    if suffix.contains("@{") {
        return Err("contains forbidden `@{` sequence".to_owned());
    }
    for &b in suffix.as_bytes() {
        if b < 0x20 || b == 0x7F {
            return Err(format!(
                "contains control character 0x{b:02X}"
            ));
        }
        match b {
            b' ' | b'~' | b'^' | b':' | b'?' | b'*' | b'[' | b'\\' => {
                return Err(format!(
                    "contains forbidden character {:?}", b as char
                ));
            }
            _ => {}
        }
        if !b.is_ascii() {
            return Err(format!(
                "contains non-ASCII byte 0x{b:02X}"
            ));
        }
    }
    for component in suffix.split('/') {
        if component.is_empty() {
            return Err("contains empty path component".to_owned());
        }
        if component.starts_with('-') {
            return Err(format!(
                "path component {component:?} starts with `-`"
            ));
        }
        if component.starts_with('.') {
            return Err(format!(
                "path component {component:?} starts with `.`"
            ));
        }
        if component.ends_with('.') {
            return Err(format!(
                "path component {component:?} ends with `.`"
            ));
        }
        if component.ends_with(".lock") {
            return Err(format!(
                "path component {component:?} ends with `.lock`"
            ));
        }
    }
    Ok(())
}

/// Parse a verifier `timeout = "Ns"|"Nm"|"Nh"` shape into seconds.
/// Returns `None` for unparseable strings or for values that
/// overflow a `u64` second count.
///
/// `pub` so the kernel-side plan validator
/// (`approve_plan` Step 2) can parse plan-source
/// `[[plan.integration_merge_verifiers]] timeout` strings against
/// the same rules without duplicating the helper.
pub fn parse_verifier_timeout_secs(s: &str) -> Option<u64> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    let (num_str, unit) = if let Some(stripped) = s.strip_suffix('s') {
        (stripped, 1u64)
    } else if let Some(stripped) = s.strip_suffix('m') {
        (stripped, 60u64)
    } else if let Some(stripped) = s.strip_suffix('h') {
        (stripped, 3_600u64)
    } else {
        return None;
    };
    let n: u64 = num_str.parse().ok()?;
    n.checked_mul(unit)
}

fn validate_notifications(
    raw: &NotificationsSection,
) -> Result<
    (Vec<NotificationChannel>, HashMap<String, Vec<String>>, Vec<String>),
    PolicyError,
> {
    use std::collections::HashSet;

    let mut channels: Vec<NotificationChannel> = raw.channels_raw.clone();
    let mut seen: HashSet<&str> = HashSet::new();
    for ch in &channels {
        if ch.id.trim().is_empty() {
            return Err(PolicyError::MalformedArtifact(
                "[[notifications.channels]] id must be a non-empty string".to_owned(),
            ));
        }
        if !seen.insert(ch.id.as_str()) {
            return Err(PolicyError::MalformedArtifact(format!(
                "[[notifications.channels]] id={:?} is duplicated; ids must be unique",
                ch.id
            )));
        }
        // Per-kind target validation.
        match ch.kind {
            NotificationChannelKind::Shell | NotificationChannelKind::File => {
                // Empty target on an explicit Shell entry means "use
                // default" (implicit-channel behaviour). For File
                // channels the target is operator-supplied so empty
                // is a misconfiguration.
                if matches!(ch.kind, NotificationChannelKind::File)
                    && ch.target.trim().is_empty()
                {
                    return Err(PolicyError::MalformedArtifact(format!(
                        "[[notifications.channels]] id={:?} kind=File requires a non-empty target",
                        ch.id
                    )));
                }
            }
            NotificationChannelKind::Email | NotificationChannelKind::Webhook => {
                if ch.target.trim().is_empty() {
                    return Err(PolicyError::MalformedArtifact(format!(
                        "[[notifications.channels]] id={:?} kind={:?} requires a non-empty target",
                        ch.id, ch.kind
                    )));
                }
                // The handler is unimplemented in v1; the kernel
                // emits a one-line warning at boot per spec §5.6.2.
                // We do NOT short-circuit validation here — operators
                // can stage v2 channel config in v1 without blocking
                // boot.
                eprintln!(
                    "{{\"level\":\"warn\",\"event\":\"notification_channel_v2_only\",\
                     \"channel_id\":\"{}\",\"kind\":\"{:?}\"}}",
                    ch.id, ch.kind,
                );
            }
        }
    }

    // Synthesise the implicit Shell channel if the operator did not
    // declare one. Empty target is the runtime sentinel for "use
    // <data_dir>/notifications/inbox.jsonl" — resolved by
    // `PolicyBundle::shell_inbox_path_for(data_dir)`.
    if !seen.contains(IMPLICIT_SHELL_CHANNEL_ID) {
        channels.push(NotificationChannel {
            id:     IMPLICIT_SHELL_CHANNEL_ID.to_owned(),
            kind:   NotificationChannelKind::Shell,
            target: String::new(),
        });
    }

    // Build the channel-id index AFTER synthesis so route validation
    // can resolve `"shell"` regardless of whether it was declared.
    let declared_ids: HashSet<&str> = channels.iter().map(|c| c.id.as_str()).collect();

    // Default channels: validate every id resolves; default to ["shell"]
    // when omitted.
    let default_channels: Vec<String> = if raw.default_channels.is_empty() {
        vec![IMPLICIT_SHELL_CHANNEL_ID.to_owned()]
    } else {
        for cid in &raw.default_channels {
            if !declared_ids.contains(cid.as_str()) {
                return Err(PolicyError::MalformedArtifact(format!(
                    "[notifications] default_channels references unknown channel id={:?}",
                    cid
                )));
            }
        }
        raw.default_channels.clone()
    };

    // Validate every route: event_kind is a real audit kind, channels
    // resolve. An empty channels list is the spec's silenced form;
    // we keep it (the dispatcher reads it as "drop on the floor").
    let known_kinds: HashSet<&str> =
        KNOWN_AUDIT_EVENT_KINDS.iter().copied().collect();
    let mut routes: HashMap<String, Vec<String>> = HashMap::new();
    for r in &raw.routes_raw {
        if !known_kinds.contains(r.event_kind.as_str()) {
            return Err(PolicyError::MalformedArtifact(format!(
                "[[notifications.routes]] event_kind={:?} is not a known AuditEventKind \
                 — see crates/audit/src/event.rs::AuditEventKind for the canonical list",
                r.event_kind
            )));
        }
        for cid in &r.channels {
            if !declared_ids.contains(cid.as_str()) {
                return Err(PolicyError::MalformedArtifact(format!(
                    "[[notifications.routes]] event_kind={:?} references unknown channel id={:?}",
                    r.event_kind, cid
                )));
            }
        }
        // Last-write-wins on duplicate event_kind — operators with two
        // entries for the same kind almost certainly want the second.
        // We log so the operator notices the override.
        if routes.insert(r.event_kind.clone(), r.channels.clone()).is_some() {
            eprintln!(
                "{{\"level\":\"warn\",\"event\":\"notification_route_overridden\",\
                 \"event_kind\":\"{}\"}}",
                r.event_kind,
            );
        }
    }

    Ok((channels, routes, default_channels))
}

// ---------------------------------------------------------------------------
// PolicyBundle — the validated in-memory policy
// ---------------------------------------------------------------------------

/// The validated, loaded policy artifact. Constructed by `loader::load_policy`
/// and held behind `Arc<PolicyBundle>` (or `ArcSwap<PolicyBundle>` in the
/// kernel binary) for concurrent read access.
///
/// All fields are private; callers use the typed accessor methods below.
#[derive(Debug)]
pub struct PolicyBundle {
    epoch: u64,
    authority_pubkey_hex: String,
    quality_pubkey_hex: String,
    operators: Vec<OperatorEntry>,
    gates: Vec<GateEntry>,
    lanes: Vec<LaneEntry>,
    /// Validated `[[roles]]` flattened into a `role_id → ceiling` lookup.
    /// Built from `RawPolicy::roles` at validate time. The raw `Vec<RoleEntry>`
    /// is intentionally dropped after the lookup is built — every consumer in
    /// the codebase (delegation, session minting) goes through `role_ceilings`.
    role_ceilings: HashMap<String, Vec<String>>,
    escalation_timeout: Duration,
    escalation_window: Duration,
    escalation_max_per_window: u32,
    escalation_quarantine_threshold: u32,
    default_session_ttl: Duration,
    max_session_ttl: Duration,
    allowed_worktree_roots: Vec<String>,
    max_delegation_ttl: Duration,
    base_cost_per_intent_kind: HashMap<String, u64>,
    cost_per_touched_path: u64,
    max_cost_per_task: u64,
    /// SHA-256 of the raw policy.toml bytes. Set by the loader after computing
    /// from actual file bytes (not from the meta field). Used for storage in
    /// policy_epoch_history. Initially empty; populated by loader via with_sha256().
    policy_sha256: String,
    signed_by: String,
    signed_at: i64,
    claim_rules: Vec<ClaimRule>,
    claim_default_action: String,
    egress_domains: Vec<String>,
    egress_patterns: Vec<String>,
    egress_max_fetches_per_window: u32,

    /// Optional `[gateway]` config. `None` = kernel runs without a
    /// gateway subprocess (no inference / fetch capability).
    gateway: Option<GatewaySection>,

    /// `[[providers]]` entries, validated for unique IDs and per-field
    /// caps. Empty `Vec` is permitted (matches `gateway = None`).
    providers: Vec<ProviderEntry>,

    /// `[plan_signing]` config — V2.1 plan-bundle freshness window,
    /// clock-skew tolerance, nonce retention grace, and sweep cadence.
    /// `None` means "operator omitted the section; use spec defaults"
    /// — `plan_signing()` materialises a `Cow::Owned` default in that
    /// case. The bundle stores `Option` rather than always-Some so the
    /// validator can distinguish "operator declared values" (validated)
    /// from "no section at all" (defaults already validated by spec).
    plan_signing: Option<PlanSigningSection>,

    /// `[plan_bundle_limits]` config — V2 plan-bundle size discipline
    /// (`max_artifact_bytes`, `max_bundle_bytes`, `max_artifact_count`).
    /// Same `None`-means-defaults pattern as `plan_signing`. Read by
    /// the kernel admission path (§7.3 / §8.1 step 3) via
    /// [`PolicyBundle::plan_bundle_limits`].
    plan_bundle_limits: Option<PlanBundleLimitsSection>,

    /// Validated notification channels. ALWAYS contains the implicit
    /// `"shell"` channel — synthesised at validate time when the
    /// operator does not declare it (cli-readonly.md §5.6.2). Channels
    /// declared explicitly with id="shell" override the implicit
    /// target.
    notification_channels: Vec<NotificationChannel>,

    /// Validated routes: `event_kind → [channel_id]`. Empty channel
    /// list is the spec's "silenced" form. Event kinds with no entry
    /// fall through to `default_notification_channels`.
    notification_routes: HashMap<String, Vec<String>>,

    /// Channel ids dispatched to when an event kind has no explicit
    /// route (cli-readonly.md §5.6.2). Always at least `["shell"]`
    /// when the operator does not override.
    default_notification_channels: Vec<String>,

    /// Operator entries whose embedded cert tripped at least one
    /// structural invariant AND had `force_misconfig_bypass = true`
    /// set on the entry. The kernel boot consumes this list and
    /// emits one `OperatorCertMisconfigBypassed` audit event per
    /// item so the bypass cannot happen silently.
    ///
    /// This list is INTENTIONALLY exposed as a public accessor — the
    /// kernel boot reads it during the audit-chain warm-up. Tests
    /// that care about misconfig handling (step 3 unit tests) read
    /// it through [`PolicyBundle::bypassed_cert_misconfigs`].
    bypassed_cert_misconfigs:      Vec<BypassedCertMisconfig>,

    /// V2 selector for the active `CredentialBackend` impl. Defaults
    /// to [`CredentialBackendKind::File`] when `policy.toml` omits the
    /// `[credential_backend]` section. Read at kernel boot
    /// (`kernel/src/main.rs`) to construct the
    /// `Arc<dyn CredentialBackend>` injected into `HandlerContext`.
    credential_backend: CredentialBackendKind,

    /// V2 operator-side pre-merge verifier gates per
    /// `policy-plan-authority.md §4 [[integration_merge_verifiers]]`.
    /// Each entry passed structural validation in
    /// `validate_integration_merge_verifiers_operator_side`. Read at
    /// `IntegrationMerge` admission (Check 5d) by the kernel; the
    /// plan-side `[[plan.integration_merge_verifiers]]` is unioned
    /// with this list at dispatch time per
    /// `verifier-processes.md §15`. Empty when the operator omits
    /// the section (the default).
    integration_merge_verifiers: Vec<IntegrationMergeVerifierEntry>,

    /// Resolved `[git] default_target_ref` — the fully-qualified ref
    /// the kernel's IntegrationMerge handler advances when the plan
    /// omits `[workspace] target_ref`. Always non-empty; defaults to
    /// `"refs/heads/main"` when the operator omits the `[git]`
    /// section. Validated at policy-load to start with `refs/heads/`
    /// and pass `git-check-ref-format`-style structural rules. See
    /// `V2_GAPS.md §12.8` and `INV-PLAN-POLICY-PRECEDENCE-01`.
    git_default_target_ref: String,

    /// Resolved `[git] target_ref_locked`. When `true`, plans MAY
    /// NOT override `target_ref`. Any plan whose
    /// `[workspace] target_ref` differs from `git_default_target_ref`
    /// is rejected at admission with `FAIL_POLICY_LOCKED_FIELD`.
    git_target_ref_locked: bool,
}

/// Test-only escalation rate-limit / quarantine / timeout overrides for
/// [`PolicyBundle::for_tests_with_operators_and_escalation_policy`].
///
/// Mirrors the four `[escalation_policy]` TOML fields that the kernel's
/// planner-side EscalationRequest handler reads. Defaults to all-zero
/// so callers that build via [`PolicyBundle::for_tests_with_operators`]
/// keep their previous semantics.
#[cfg(any(debug_assertions, test))]
#[derive(Debug, Clone, Copy)]
pub struct EscalationPolicyForTests {
    pub timeout:               Duration,
    pub window:                Duration,
    pub max_per_window:        u32,
    pub quarantine_threshold:  u32,
}

#[cfg(any(debug_assertions, test))]
impl Default for EscalationPolicyForTests {
    fn default() -> Self {
        Self {
            timeout:              Duration::from_secs(0),
            window:               Duration::from_secs(0),
            max_per_window:       0,
            quarantine_threshold: 0,
        }
    }
}

impl PolicyBundle {
    /// Validate and build a `PolicyBundle` from a `RawPolicy` parsed from TOML.
    ///
    /// Returns `PolicyError::MalformedArtifact` if any required constraint fails.
    pub(crate) fn validate(raw: RawPolicy) -> Result<Self, PolicyError> {
        // Require at least one operator entry.
        if raw.operators_block.entries.is_empty() {
            return Err(PolicyError::MalformedArtifact(
                "[[operators.entries]] is empty — at least one operator required".to_owned(),
            ));
        }

        // Per-entry cert validation. Mutates `entries` in place to:
        //   - Apply structural pinning to emergency certs (force
        //     `permitted_ops = ["RotateEpoch"]` regardless of TOML).
        //   - Mirror the cert's `permitted_ops` onto the entry-level
        //     field (the cert is the authority — entry-level ops
        //     would otherwise drift).
        // Returns `bypassed` — the set of entries whose structural
        // errors were swallowed via `force_misconfig_bypass = true`,
        // audited at boot.
        //
        // Cert is mandatory (INV-CERT-01); cert-less entries can't
        // even reach here because TOML deserialization fails first.
        // Hard failures (signature invalid, pubkey/fingerprint
        // mismatch) are NEVER bypassable and short-circuit here.
        let mut entries = raw.operators_block.entries;
        let bypassed_cert_misconfigs = validate_operator_certs(&mut entries)?;

        // Require at least one allowed worktree root.
        if raw.sessions.allowed_worktree_roots.is_empty() {
            return Err(PolicyError::MalformedArtifact(
                "sessions.allowed_worktree_roots is empty".to_owned(),
            ));
        }

        // Validate TTL ordering.
        if raw.sessions.default_ttl_secs > raw.sessions.max_ttl_secs {
            return Err(PolicyError::MalformedArtifact(format!(
                "sessions.default_ttl_secs ({}) > max_ttl_secs ({})",
                raw.sessions.default_ttl_secs, raw.sessions.max_ttl_secs
            )));
        }

        // Build role_ceilings lookup.
        let role_ceilings: HashMap<String, Vec<String>> = raw
            .roles
            .iter()
            .map(|r| (r.role_id.clone(), r.ceiling.clone()))
            .collect();

        // Validate `[gateway]` if present.
        if let Some(g) = &raw.gateway {
            if !std::path::Path::new(&g.binary_path).is_absolute() {
                return Err(PolicyError::MalformedArtifact(format!(
                    "[gateway] binary_path must be absolute (got {:?}); \
                     relative paths are rejected to prevent PATH-based hijacks",
                    g.binary_path
                )));
            }
            if g.spawn_timeout_secs == 0 {
                return Err(PolicyError::MalformedArtifact(
                    "[gateway] spawn_timeout_secs must be > 0".to_owned(),
                ));
            }
            if g.respawn_backoff_ms == 0 {
                return Err(PolicyError::MalformedArtifact(
                    "[gateway] respawn_backoff_ms must be > 0".to_owned(),
                ));
            }
            if g.max_consecutive_respawns == 0 {
                return Err(PolicyError::MalformedArtifact(
                    "[gateway] max_consecutive_respawns must be > 0 — set to 1 \
                     to disable auto-respawn rather than 0"
                        .to_owned(),
                ));
            }
        }

        // Validate `[[providers]]` entries.
        let mut seen_provider_ids: std::collections::HashSet<&str> =
            std::collections::HashSet::new();
        for p in &raw.providers {
            if p.provider_id.trim().is_empty() {
                return Err(PolicyError::MalformedArtifact(
                    "[[providers]] provider_id must be a non-empty string".to_owned(),
                ));
            }
            if !seen_provider_ids.insert(&p.provider_id) {
                return Err(PolicyError::MalformedArtifact(format!(
                    "[[providers]] provider_id={:?} is duplicated; IDs must be unique",
                    p.provider_id
                )));
            }
            // credentials_file MUST be a bare filename (no path components).
            // This prevents `../../etc/shadow` and absolute-path tricks at
            // policy-validate time. The actual filesystem existence check
            // happens at gateway-spawn time, since policy.toml may travel
            // separately from the credentials directory.
            let cf = &p.credentials_file;
            if cf.is_empty() {
                return Err(PolicyError::MalformedArtifact(format!(
                    "[[providers]] {:?} credentials_file is empty",
                    p.provider_id
                )));
            }
            if cf.contains('/') || cf.contains('\\') || cf == "." || cf == ".." {
                return Err(PolicyError::MalformedArtifact(format!(
                    "[[providers]] {:?} credentials_file={:?} must be a bare filename \
                     (no path separators or `.`/`..`); resolved against \
                     <data_dir>/providers/",
                    p.provider_id, cf
                )));
            }
            if p.inference_timeout_ms == 0 {
                return Err(PolicyError::MalformedArtifact(format!(
                    "[[providers]] {:?} inference_timeout_ms must be > 0",
                    p.provider_id
                )));
            }
            if p.inference_timeout_ms > MAX_INFERENCE_TIMEOUT_MS {
                return Err(PolicyError::MalformedArtifact(format!(
                    "[[providers]] {:?} inference_timeout_ms ({}) exceeds normative cap {} \
                     (peripherals.md §3.2)",
                    p.provider_id, p.inference_timeout_ms, MAX_INFERENCE_TIMEOUT_MS
                )));
            }
            if p.data_fetch_timeout_ms == 0 {
                return Err(PolicyError::MalformedArtifact(format!(
                    "[[providers]] {:?} data_fetch_timeout_ms must be > 0",
                    p.provider_id
                )));
            }
            if p.data_fetch_timeout_ms > MAX_DATA_FETCH_TIMEOUT_MS {
                return Err(PolicyError::MalformedArtifact(format!(
                    "[[providers]] {:?} data_fetch_timeout_ms ({}) exceeds normative cap {}",
                    p.provider_id, p.data_fetch_timeout_ms, MAX_DATA_FETCH_TIMEOUT_MS
                )));
            }
            if p.max_response_bytes == 0 {
                return Err(PolicyError::MalformedArtifact(format!(
                    "[[providers]] {:?} max_response_bytes must be > 0",
                    p.provider_id
                )));
            }
            if p.max_response_bytes > MAX_RESPONSE_BYTES_CEILING {
                return Err(PolicyError::MalformedArtifact(format!(
                    "[[providers]] {:?} max_response_bytes ({}) exceeds ceiling {}",
                    p.provider_id, p.max_response_bytes, MAX_RESPONSE_BYTES_CEILING
                )));
            }
        }

        // ── Validate `[notifications]` ───────────────────────────────
        let (notification_channels, notification_routes, default_notification_channels) =
            validate_notifications(&raw.notifications)?;

        validate_integration_merge_verifiers_operator_side(
            &raw.integration_merge_verifiers,
        )?;

        Ok(Self {
            epoch: raw.meta.epoch,
            authority_pubkey_hex: raw.authority.authority_pubkey,
            quality_pubkey_hex: raw.authority.quality_pubkey,
            operators: entries,
            gates: raw.gates,
            lanes: raw.lanes,
            role_ceilings,
            escalation_timeout: Duration::from_secs(raw.escalation_policy.timeout_secs),
            escalation_window: Duration::from_secs(raw.escalation_policy.window_secs),
            escalation_max_per_window: raw.escalation_policy.max_per_window,
            escalation_quarantine_threshold: raw.escalation_policy.quarantine_threshold,
            default_session_ttl: Duration::from_secs(raw.sessions.default_ttl_secs),
            max_session_ttl: Duration::from_secs(raw.sessions.max_ttl_secs),
            allowed_worktree_roots: raw.sessions.allowed_worktree_roots,
            max_delegation_ttl: Duration::from_secs(raw.delegations.max_ttl_secs),
            base_cost_per_intent_kind: raw.budget.base_cost_per_intent_kind,
            cost_per_touched_path: raw.budget.cost_per_touched_path,
            max_cost_per_task: raw.budget.max_cost_per_task,
            policy_sha256: String::new(),
            signed_by: raw.meta.signed_by,
            signed_at: raw.meta.signed_at,
            claim_rules: raw.claim_requirements.rules,
            claim_default_action: raw.claim_requirements.default_action,
            egress_domains: raw.egress.domains,
            egress_patterns: raw.egress.patterns,
            egress_max_fetches_per_window: raw.egress.max_fetches_per_window,
            gateway: raw.gateway,
            providers: raw.providers,
            plan_signing: {
                if let Some(section) = raw.plan_signing.as_ref() {
                    section.validate().map_err(|reason| {
                        PolicyError::MalformedArtifact(format!(
                            "FAIL_POLICY_PLAN_SIGNING_INVALID: {reason}"
                        ))
                    })?;
                }
                raw.plan_signing
            },
            plan_bundle_limits: {
                if let Some(section) = raw.plan_bundle_limits.as_ref() {
                    section.validate().map_err(|reason| {
                        PolicyError::MalformedArtifact(format!(
                            "FAIL_POLICY_PLAN_BUNDLE_LIMIT_ABOVE_CEILING: {reason}"
                        ))
                    })?;
                }
                raw.plan_bundle_limits
            },
            notification_channels,
            notification_routes,
            default_notification_channels,
            bypassed_cert_misconfigs,
            credential_backend: raw
                .credential_backend
                .map(|s| s.kind)
                .unwrap_or_default(),
            integration_merge_verifiers: raw.integration_merge_verifiers,
            git_default_target_ref: {
                let raw_value = raw
                    .git
                    .as_ref()
                    .and_then(|g| g.default_target_ref.as_deref())
                    .unwrap_or("refs/heads/main");
                validate_target_ref_format(raw_value).map_err(|reason| {
                    PolicyError::MalformedArtifact(format!(
                        "FAIL_POLICY_TARGET_REF_INVALID: \
                         [git] default_target_ref={raw_value:?} {reason}"
                    ))
                })?;
                raw_value.to_owned()
            },
            git_target_ref_locked: raw
                .git
                .as_ref()
                .map(|g| g.target_ref_locked)
                .unwrap_or(false),
        })
    }

    // ── Epoch ──────────────────────────────────────────────────────────────

    /// Current policy epoch number. Monotonically increasing across all
    /// `policy_epoch_history` rows (kernel-store.md §2.5.1 Table 19).
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// V2 selector for the active `CredentialBackend` impl. Read at
    /// kernel boot to decide which `Arc<dyn CredentialBackend>` to
    /// inject into `HandlerContext`. Defaults to
    /// [`CredentialBackendKind::File`] when `policy.toml` omits the
    /// `[credential_backend]` section.
    pub fn credential_backend_kind(&self) -> CredentialBackendKind {
        self.credential_backend
    }

    /// Operator-side `[[integration_merge_verifiers]]` entries, in
    /// declaration order. Empty when the operator omits the section
    /// (the typical default — most operators don't run any
    /// pre-merge gates).
    ///
    /// The kernel's IntegrationMerge admission step (Check 5d, per
    /// `integration-merge.md §4`) UNIONs this slice with the
    /// plan-side `[[plan.integration_merge_verifiers]]` array at
    /// dispatch time and applies the per-merge `applies_to` filter.
    /// Cross-source name collisions are caught at `approve_plan`
    /// (Step 2 of the pre-merge-verifier track); this accessor
    /// surfaces only operator-side entries.
    pub fn integration_merge_verifiers(&self) -> &[IntegrationMergeVerifierEntry] {
        &self.integration_merge_verifiers
    }

    /// V2_GAPS.md §12.8 — operator-side `[git] default_target_ref`.
    /// Always non-empty; defaults to `"refs/heads/main"` when the
    /// operator omits the `[git]` section. The plan-admission code
    /// path resolves the per-initiative `target_ref` as
    /// `plan_value || policy_default || "refs/heads/main"`,
    /// subject to [`git_target_ref_locked`].
    ///
    /// [`git_target_ref_locked`]: PolicyBundle::git_target_ref_locked
    pub fn git_default_target_ref(&self) -> &str {
        &self.git_default_target_ref
    }

    /// V2_GAPS.md §12.8 — operator-side `[git] target_ref_locked`.
    /// When `true`, plans whose `[workspace] target_ref` differs from
    /// [`git_default_target_ref`] are rejected at admission with
    /// `FAIL_POLICY_LOCKED_FIELD` per `INV-PLAN-POLICY-PRECEDENCE-01`.
    ///
    /// [`git_default_target_ref`]: PolicyBundle::git_default_target_ref
    pub fn git_target_ref_locked(&self) -> bool {
        self.git_target_ref_locked
    }

    // ── Key accessors ───────────────────────────────────────────────────────

    /// Authority Ed25519 public key bytes (32 bytes).
    /// Returns `PolicyError::HexDecode` if the stored hex is malformed
    /// (caught at load time by `loader`; this should not occur in practice).
    pub fn authority_pubkey_bytes(&self) -> Result<Vec<u8>, PolicyError> {
        Ok(hex::decode(&self.authority_pubkey_hex)?)
    }

    /// Quality Ed25519 public key bytes (32 bytes). Reserved for v2.
    pub fn quality_pubkey_bytes(&self) -> Result<Vec<u8>, PolicyError> {
        Ok(hex::decode(&self.quality_pubkey_hex)?)
    }

    // ── Operator entries ────────────────────────────────────────────────────

    /// All registered operator entries.
    pub fn operators(&self) -> &[OperatorEntry] {
        &self.operators
    }

    /// Look up an operator by pubkey fingerprint (the `signed_by` field from
    /// plan.sig / policy.sig). Returns `None` if no entry matches.
    pub fn operator_entry(&self, fingerprint: &str) -> Option<&OperatorEntry> {
        self.operators
            .iter()
            .find(|op| op.pubkey_fingerprint == fingerprint)
    }

    /// Convenience around [`operator_entry`] for the (very common)
    /// audit-emit + log-line lookup of "what is this fingerprint's
    /// human-readable display name?". Returns `None` when the
    /// fingerprint is not in this bundle (e.g. the operator was
    /// removed in an earlier rotation, or the fingerprint belongs
    /// to a different deployment entirely).
    ///
    /// Cheap allocation: callers typically need the display name
    /// for an `Option<String>` field on an `AuditEventKind` or for
    /// a JSON-stderr line, both of which want owned strings, so
    /// returning `String` is the right shape (no `&str` lifetime
    /// surfaced into call sites that span `tokio::spawn_blocking`).
    pub fn operator_display_name(&self, fingerprint: &str) -> Option<String> {
        self.operator_entry(fingerprint)
            .map(|e| e.display_name.clone())
    }

    /// Operator entries whose embedded cert tripped at least one
    /// structural invariant AND were marked `force_misconfig_bypass = true`.
    /// The kernel boot reads this list and emits one
    /// `OperatorCertMisconfigBypassed` audit event per item.
    ///
    /// Empty in normal deployments. Operators see this list grow only
    /// when they explicitly opt into a known-broken cert (e.g. for
    /// staged migration or v2 forward-compat experimentation).
    pub fn bypassed_cert_misconfigs(&self) -> &[BypassedCertMisconfig] {
        &self.bypassed_cert_misconfigs
    }

    /// Test-only constructor that builds a minimal bundle whose only
    /// populated field is `operators`. Every other field gets a
    /// zero/empty default. Use this when a unit test only needs
    /// `operator_entry()` lookups (e.g. signature verification on
    /// the operator IPC handlers) and not budgets, lanes, gates, etc.
    /// For tests that also need escalation rate-limit configuration
    /// see [`for_tests_with_operators_and_escalation_policy`].
    ///
    /// Gated on `debug_assertions || cfg(test)` — disappears in
    /// release builds, mirroring the convention used by
    /// `KeyRegistry::stub_for_tests` and the `raxis-test-support`
    /// public surface.
    #[cfg(any(debug_assertions, test))]
    pub fn for_tests_with_operators(operators: Vec<OperatorEntry>) -> Self {
        Self::for_tests_with_operators_and_escalation_policy(
            operators,
            EscalationPolicyForTests::default(),
        )
    }

    /// Like `for_tests_with_operators` but also lets a test override
    /// the escalation rate-limit / quarantine / timeout fields. Useful
    /// for the planner-side EscalationRequest handler tests in
    /// `kernel/src/handlers/escalation.rs` which need to drive the
    /// rate-limit and quarantine paths deterministically without
    /// relying on real wall-clock budgets.
    #[cfg(any(debug_assertions, test))]
    pub fn for_tests_with_operators_and_escalation_policy(
        operators:         Vec<OperatorEntry>,
        escalation_policy: EscalationPolicyForTests,
    ) -> Self {
        Self {
            epoch: 0,
            authority_pubkey_hex: String::new(),
            quality_pubkey_hex: String::new(),
            operators,
            gates: Vec::new(),
            lanes: Vec::new(),
            role_ceilings: HashMap::new(),
            escalation_timeout: escalation_policy.timeout,
            escalation_window: escalation_policy.window,
            escalation_max_per_window: escalation_policy.max_per_window,
            escalation_quarantine_threshold: escalation_policy.quarantine_threshold,
            default_session_ttl: Duration::from_secs(0),
            max_session_ttl: Duration::from_secs(0),
            allowed_worktree_roots: Vec::new(),
            max_delegation_ttl: Duration::from_secs(0),
            gateway: None,
            providers: Vec::new(),
            plan_signing: None,
            plan_bundle_limits: None,
            base_cost_per_intent_kind: HashMap::new(),
            cost_per_touched_path: 0,
            max_cost_per_task: 0,
            policy_sha256: String::new(),
            signed_by: String::new(),
            signed_at: 0,
            claim_rules: Vec::new(),
            claim_default_action: String::new(),
            egress_domains: Vec::new(),
            egress_patterns: Vec::new(),
            egress_max_fetches_per_window: 0,
            // Tests get the same implicit-Shell defaults a real
            // policy.toml would synthesise.
            notification_channels: vec![NotificationChannel {
                id:     IMPLICIT_SHELL_CHANNEL_ID.to_owned(),
                kind:   NotificationChannelKind::Shell,
                target: String::new(),
            }],
            notification_routes: HashMap::new(),
            default_notification_channels: vec![IMPLICIT_SHELL_CHANNEL_ID.to_owned()],
            bypassed_cert_misconfigs: Vec::new(),
            credential_backend: CredentialBackendKind::default(),
            integration_merge_verifiers: Vec::new(),
            git_default_target_ref: "refs/heads/main".to_owned(),
            git_target_ref_locked: false,
        }
    }

    // ── Gate config ─────────────────────────────────────────────────────────

    /// All gate definitions from `[[gates]]`.
    pub fn gates(&self) -> &[GateEntry] {
        &self.gates
    }

    /// Look up a gate definition by gate_type name.
    pub fn gate_config(&self, gate_type: &str) -> Option<&GateEntry> {
        self.gates.iter().find(|g| g.gate_type == gate_type)
    }

    // ── Role ceilings ───────────────────────────────────────────────────────

    /// The capability ceiling for a role — the set of CapabilityClass names
    /// the role is permitted to delegate. Returns `None` if the role is unknown.
    pub fn role_ceiling(&self, role_id: &str) -> Option<&[String]> {
        self.role_ceilings.get(role_id).map(|v| v.as_slice())
    }

    /// Returns true if `capability_class` is within the ceiling for `role_id`.
    pub fn capability_within_ceiling(&self, role_id: &str, capability_class: &str) -> bool {
        self.role_ceiling(role_id)
            .map(|ceiling| ceiling.iter().any(|c| c == capability_class))
            .unwrap_or(false)
    }

    // ── Escalation policy ───────────────────────────────────────────────────

    /// How long a Pending escalation waits before TimedOut.
    pub fn escalation_timeout(&self) -> Duration {
        self.escalation_timeout
    }

    /// Rolling window for per-lineage rate limiting.
    pub fn escalation_window(&self) -> Duration {
        self.escalation_window
    }

    /// Max escalation submissions per lineage per window.
    pub fn escalation_max_per_window(&self) -> u32 {
        self.escalation_max_per_window
    }

    /// Rate-limit trigger count before lineage quarantine.
    pub fn escalation_quarantine_threshold(&self) -> u32 {
        self.escalation_quarantine_threshold
    }

    // ── Session policy ──────────────────────────────────────────────────────

    pub fn default_session_ttl(&self) -> Duration {
        self.default_session_ttl
    }

    pub fn max_session_ttl(&self) -> Duration {
        self.max_session_ttl
    }

    /// Operator-specified absolute path prefixes for worktree_root validation.
    pub fn allowed_worktree_roots(&self) -> &[String] {
        &self.allowed_worktree_roots
    }

    /// Returns true if `path` is at — or under — at least one allowed
    /// worktree root.
    ///
    /// **Component-aware comparison.** A naive `path.starts_with(root)` is
    /// unsafe: if the operator allows `/srv/work`, a planner-supplied
    /// `/srv/work_secret` would also pass because the literal byte prefix
    /// matches. We require either exact equality OR a directory-separator
    /// boundary right after the root, so `/srv/work_secret` is rejected
    /// while `/srv/work` and `/srv/work/sub/dir` are accepted.
    ///
    /// We also tolerate operators writing the root with or without a
    /// trailing slash (`/srv/work` vs `/srv/work/`) — the trailing slash
    /// is stripped before comparison.
    pub fn worktree_root_allowed(&self, path: &str) -> bool {
        self.allowed_worktree_roots.iter().any(|raw_root| {
            let root = raw_root.trim_end_matches('/');
            if path == root {
                return true;
            }
            // Require a path-separator boundary after the root prefix to
            // prevent the `/srv/work` ⊃ `/srv/work_secret` false positive.
            path.len() > root.len()
                && path.starts_with(root)
                && path.as_bytes()[root.len()] == b'/'
        })
    }

    // ── Delegation policy ───────────────────────────────────────────────────

    pub fn max_delegation_ttl(&self) -> Duration {
        self.max_delegation_ttl
    }

    // ── Budget policy ───────────────────────────────────────────────────────

    /// Base cost for an intent kind. Returns `None` if the intent kind is not
    /// in the policy table (maps to `BudgetError::UnknownIntentKindCost`
    /// in the kernel's budget subsystem).
    pub fn base_cost_for_intent_kind(&self, intent_kind: &str) -> Option<u64> {
        self.base_cost_per_intent_kind.get(intent_kind).copied()
    }

    /// Cost to add per touched file in the VCS diff.
    pub fn cost_per_touched_path(&self) -> u64 {
        self.cost_per_touched_path
    }

    /// Per-task admission cost cap (before lane enforcement).
    pub fn max_cost_per_task(&self) -> u64 {
        self.max_cost_per_task
    }

    /// Lane configuration for a named lane. Returns `None` if not found.
    pub fn lane_config(&self, lane_id: &str) -> Option<&LaneEntry> {
        self.lanes.iter().find(|l| l.lane_id == lane_id)
    }

    /// All lane definitions.
    pub fn lanes(&self) -> &[LaneEntry] {
        &self.lanes
    }

    /// Replace the lane definitions on a test bundle.
    ///
    /// Gated on `debug_assertions || cfg(test)` — disappears in production
    /// builds. Used by kernel-side tests (e.g.
    /// `scheduler::budget::tests::reserve_in_tx_serialises_concurrent_lane_writes`)
    /// that need to seed a non-empty lane table on top of the
    /// `for_tests_with_operators` skeleton without going through a full
    /// `policy.toml` round-trip.
    #[cfg(any(debug_assertions, test))]
    pub fn set_lanes_for_tests(&mut self, lanes: Vec<LaneEntry>) {
        self.lanes = lanes;
    }

    /// Test-only setter for `[plan_signing].accept_unfresh_v2_0_bundles`.
    /// Used by the kernel V2 admission tests (`v2_admission::tests`) to
    /// flip the V2.0 transitional knob without round-tripping a full
    /// policy.toml. The production loader path is still gated on the
    /// `[plan_signing]` validation in `validate_plan_signing`.
    #[cfg(any(debug_assertions, test))]
    pub fn set_plan_signing_accept_unfresh_v2_0_for_tests(&mut self, accept: bool) {
        let mut section = self.plan_signing.clone().unwrap_or_default();
        section.accept_unfresh_v2_0_bundles = accept;
        self.plan_signing = Some(section);
    }

    // ── Artifact metadata ───────────────────────────────────────────────────

    /// Set the SHA-256 of the raw policy.toml bytes. Called by the loader
    /// after computing the hash from actual file bytes.
    pub(crate) fn with_sha256(mut self, sha256: String) -> Self {
        self.policy_sha256 = sha256;
        self
    }

    /// SHA-256 of the raw policy.toml bytes.
    /// Used to cross-reference against `policy_epoch_history.policy_sha256`.
    pub fn policy_sha256(&self) -> &str {
        &self.policy_sha256
    }

    /// Fingerprint of the operator who signed this policy artifact.
    pub fn signed_by(&self) -> &str {
        &self.signed_by
    }

    pub fn signed_at(&self) -> i64 {
        self.signed_at
    }

    // ── Claim requirements ──────────────────────────────────────────────────

    /// Ordered claim rules (declaration order = match priority per spec).
    pub fn claim_rules(&self) -> &[ClaimRule] {
        &self.claim_rules
    }

    /// Default action for paths that match no rule: "permit" or "deny".
    pub fn claim_default_action(&self) -> &str {
        &self.claim_default_action
    }

    // ── Egress allowlist ─────────────────────────────────────────────────────

    /// Exact-match domain list for egress allowlist.
    pub fn egress_domains(&self) -> &[String] {
        &self.egress_domains
    }

    /// Glob-match pattern list for egress allowlist.
    pub fn egress_patterns(&self) -> &[String] {
        &self.egress_patterns
    }

    /// Max fetches per session per window.
    pub fn egress_max_fetches_per_window(&self) -> u32 {
        self.egress_max_fetches_per_window
    }

    // ── Gateway supervisor config ───────────────────────────────────────────

    /// Optional `[gateway]` config. `None` if the policy omits the section
    /// (kernel runs without a gateway subprocess; no inference dispatch).
    pub fn gateway(&self) -> Option<&GatewaySection> {
        self.gateway.as_ref()
    }

    // ── Plan-signing freshness / replay-protection ──────────────────────────

    /// Effective `[plan_signing]` config — operator-declared values if
    /// present, otherwise the spec defaults from
    /// `plan-bundle-sealing.md §7.4`. Always returns a fully-populated
    /// `PlanSigningSection`, so the kernel sweep loop and the §8.1
    /// admission step can read fields without an `Option` dance.
    ///
    /// Cloning the section is cheap (six u64s + one bool) and lets the
    /// caller (heartbeat / sweep loops) move it into a long-lived
    /// `tokio::spawn` without holding a borrow on the `ArcSwap` snapshot.
    pub fn plan_signing(&self) -> PlanSigningSection {
        self.plan_signing
            .clone()
            .unwrap_or_else(PlanSigningSection::default)
    }

    /// V2 plan-bundle size limits — `[plan_bundle_limits]`. Returns
    /// the operator's section if declared, else the spec defaults
    /// from `plan-bundle-sealing.md §7.4` (1 MiB per artifact, 10 MiB
    /// total bundle, 200 artifacts). Read by the kernel admission
    /// path (§7.3 / §8.1 step 3) when re-checking caps against the
    /// wire bundle.
    pub fn plan_bundle_limits(&self) -> PlanBundleLimitsSection {
        self.plan_bundle_limits
            .clone()
            .unwrap_or_else(PlanBundleLimitsSection::default)
    }

    // ── Provider catalogue ──────────────────────────────────────────────────

    /// All `[[providers]]` entries in declaration order. Empty `&[]` if the
    /// policy declares no providers (paired with `gateway() == None` in the
    /// degraded "no-LLM" deployment).
    pub fn providers(&self) -> &[ProviderEntry] {
        &self.providers
    }

    /// Look up a provider by `provider_id`. Returns `None` if no entry
    /// matches. Used by the kernel's `provider/` adapter when constructing
    /// a `FetchRequest` and by the gateway to resolve the credentials path.
    pub fn provider(&self, provider_id: &str) -> Option<&ProviderEntry> {
        self.providers.iter().find(|p| p.provider_id == provider_id)
    }

    // ── Notification channels ──────────────────────────────────────────

    /// All declared notification channels (always includes the implicit
    /// `shell` channel synthesised by validate). cli-readonly.md §5.6.
    pub fn notification_channels(&self) -> &[NotificationChannel] {
        &self.notification_channels
    }

    /// Look up a notification channel by id.
    pub fn notification_channel(&self, id: &str) -> Option<&NotificationChannel> {
        self.notification_channels.iter().find(|c| c.id == id)
    }

    /// Channel ids the dispatcher MUST send to when an event has no
    /// explicit route (cli-readonly.md §5.6.2). Always non-empty —
    /// defaults to `["shell"]` if the operator omits the field.
    pub fn default_notification_channels(&self) -> &[String] {
        &self.default_notification_channels
    }

    /// Resolve `event_kind` to its dispatched-to channel ids. Returns:
    ///
    /// - `Some(&[])` — explicit silenced route (operator wrote
    ///   `channels = []` for this event_kind).
    /// - `Some(&[...])` — explicit route; dispatch to these channels.
    /// - `None` — no explicit route; caller falls back to
    ///   `default_notification_channels()`.
    ///
    /// The three-state return lets callers distinguish "operator
    /// silenced" from "operator forgot to route" — important because
    /// the second case fires the default channels.
    pub fn notification_route(&self, event_kind: &str) -> Option<&[String]> {
        self.notification_routes.get(event_kind).map(|v| v.as_slice())
    }

    /// Resolve the absolute filesystem path the implicit Shell channel
    /// writes to, given a `data_dir`. Equivalent to
    /// `<data_dir>/notifications/inbox.jsonl` (cli-readonly.md §5.6.2).
    /// Used by the Shell handler when the channel's `target` is empty.
    pub fn shell_inbox_path_for(data_dir: &std::path::Path) -> std::path::PathBuf {
        data_dir.join("notifications").join(IMPLICIT_SHELL_INBOX_FILENAME)
    }
}

// ---------------------------------------------------------------------------
// validate_operator_certs — fail-loud cert validation with audited bypass.
//
// Called by `PolicyBundle::validate` for every entry in
// `[[operators.entries]]`. Mutates `entries` in place to apply
// structural pinning (e.g. emergency cert `permitted_ops` overridden
// to `["RotateEpoch"]`) and to mirror the cert's `permitted_ops` onto
// the entry-level field. Cert is mandatory — INV-CERT-01 — so there
// is no cert-less path.
//
// Returns `bypassed` — entries whose embedded cert tripped at least
// one structural invariant AND were marked `force_misconfig_bypass =
// true`. The kernel boot will audit each as
// `OperatorCertMisconfigBypassed`.
//
// **Hard failures (NEVER bypassable):**
//   - Self-signature verification failure → `PolicyError::CertValidation`.
//     A forged cert MUST never be installed; the bypass flag does not
//     extend to signature-level claims.
//   - Pubkey mismatch between entry and embedded cert →
//     `PolicyError::CertPubkeyMismatch`. The two MUST agree so the
//     audit chain has a single canonical operator identity per
//     fingerprint.
//   - Fingerprint mismatch between entry's pubkey_hex and its
//     declared pubkey_fingerprint → `PolicyError::FingerprintMismatch`.
//     Bypassing this would let an operator declare arbitrary
//     fingerprints for an existing key, breaking the operator-by-fp
//     lookup contract.
//
// **Soft failures (bypassable):**
//   - Structural invariants from `validate_cert_structurally`:
//     - InvertedValidityWindow
//     - WarnWindowExceedsValidity
//     - DisplayNameLength
//     - StandardCertHasNoPermissions
//     - EmergencyHasWrongPermissions   ← STRUCTURAL OVERRIDE applied
//     - EmergencyHasValidityWindow     ← STRUCTURAL OVERRIDE applied
//     - MalformedPubkey / MalformedSelfSig
// ---------------------------------------------------------------------------

fn validate_operator_certs(
    entries: &mut [OperatorEntry],
) -> Result<Vec<BypassedCertMisconfig>, PolicyError> {
    use raxis_crypto::cert::{
        validate_cert_structurally, verify_cert_self_signature,
    };
    use sha2::{Digest, Sha256};

    let mut bypassed = Vec::new();

    for entry in entries.iter_mut() {
        // ── Always-on: entry pubkey_hex ↔ pubkey_fingerprint check ──
        //
        // `pubkey_fingerprint` is denormalised on the entry for cheap
        // O(1) lookups; if the operator hand-edits it out of sync with
        // `pubkey_hex` the lookup contract breaks. Pin both halves.
        // (NEVER bypassable.)
        let computed_fp = {
            let raw = hex::decode(&entry.pubkey_hex)?;
            let mut h = Sha256::new();
            h.update(&raw);
            hex::encode(&h.finalize()[..16])
        };
        if computed_fp != entry.pubkey_fingerprint {
            return Err(PolicyError::FingerprintMismatch {
                fingerprint:          entry.pubkey_fingerprint.clone(),
                entry_pubkey_hex:     entry.pubkey_hex.clone(),
                computed_fingerprint: computed_fp,
            });
        }

        let cert = entry.cert.clone();

        // ── Pubkey consistency between entry and cert (NEVER bypassable) ──
        if cert.pubkey_hex != entry.pubkey_hex {
            return Err(PolicyError::CertPubkeyMismatch {
                fingerprint:      entry.pubkey_fingerprint.clone(),
                entry_pubkey_hex: entry.pubkey_hex.clone(),
                cert_pubkey_hex:  cert.pubkey_hex.clone(),
            });
        }

        // ── Self-signature verification (NEVER bypassable) ─────────
        //
        // We run this BEFORE structural validation: a forged cert
        // could otherwise dress itself up as "well-structured" and
        // get into the bypass path. Signature first, structure second.
        if let Err(sig_err) = verify_cert_self_signature(&cert) {
            return Err(PolicyError::CertValidation {
                fingerprint:  entry.pubkey_fingerprint.clone(),
                display_name: entry.display_name.clone(),
                errors:       format!("  - {sig_err}"),
            });
        }

        // ── Structural invariants (BYPASSABLE) ─────────────────────
        let violations = validate_cert_structurally(&cert);
        if !violations.is_empty() {
            if !entry.force_misconfig_bypass {
                let joined = violations
                    .iter()
                    .map(|e| format!("  - {e}"))
                    .collect::<Vec<_>>()
                    .join("\n");
                return Err(PolicyError::CertValidation {
                    fingerprint:  entry.pubkey_fingerprint.clone(),
                    display_name: entry.display_name.clone(),
                    errors:       joined,
                });
            }
            // Bypass path: capture the violations for audit AND log
            // a structured warning so the operator sees what just
            // got swallowed (the boot audit event is the canonical
            // record; this stderr line is a redundant safety net).
            let violation_strs: Vec<String> =
                violations.iter().map(|e| e.to_string()).collect();
            eprintln!(
                "{{\"level\":\"warn\",\"event\":\"operator_cert_misconfig_bypassed\",\
                 \"operator_fp\":\"{}\",\"display_name\":\"{}\",\
                 \"kind\":\"{}\",\"violations\":[{}]}}",
                entry.pubkey_fingerprint,
                entry.display_name.replace('"', "\\\""),
                cert.kind.as_str(),
                violation_strs
                    .iter()
                    .map(|v| format!("\"{}\"", v.replace('"', "\\\"").replace('\n', " ")))
                    .collect::<Vec<_>>()
                    .join(","),
            );
            bypassed.push(BypassedCertMisconfig {
                operator_fingerprint: entry.pubkey_fingerprint.clone(),
                display_name:         entry.display_name.clone(),
                kind:                 cert.kind,
                violations:           violation_strs,
            });
        }

        // ── Apply structural pinning to the in-memory entry ────────
        //
        // Even on the bypass path, the kernel structurally pins
        // emergency cert permissions to {"RotateEpoch"} so the
        // bypass cannot widen the blast radius. The audit event
        // emitted at boot makes the override visible.
        let pinned_cert = match cert.kind {
            CertKind::EmergencyRecovery => OperatorCert {
                permitted_ops: vec!["RotateEpoch".to_owned()],
                ..cert
            },
            CertKind::Standard => cert,
        };

        // The cert is the authority for permitted_ops; mirror it
        // onto the entry-level field so all downstream lookups (which
        // currently consult `entry.permitted_ops`) get the right
        // answer without each call site having to learn the cert
        // protocol.
        entry.permitted_ops = pinned_cert.permitted_ops.clone();
        entry.cert = pinned_cert;
    }

    Ok(bypassed)
}

// ---------------------------------------------------------------------------
// Tests — worktree_root_allowed component-aware comparison.
// ---------------------------------------------------------------------------
//
// These tests guard against the v1-review finding "bundle.worktree_root_allowed
// uses raw `starts_with`, allowing path-prefix collisions like
// `/srv/work_secret` to satisfy a `/srv/work` policy".
//
// We construct a `PolicyBundle` directly via its private fields so the
// test does not need a full TOML round-trip — the only thing under test
// here is the `worktree_root_allowed` predicate.

#[cfg(test)]
mod tests {
    use super::*;

    fn bundle_with_roots(roots: Vec<&str>) -> PolicyBundle {
        // We bypass `PolicyBundle::validate` because the only thing under
        // test here is the `worktree_root_allowed` predicate. All other
        // fields are populated with empty/zero values that don't matter.
        PolicyBundle {
            epoch: 0,
            authority_pubkey_hex: String::new(),
            quality_pubkey_hex: String::new(),
            operators: Vec::new(),
            gates: Vec::new(),
            lanes: Vec::new(),
            role_ceilings: HashMap::new(),
            escalation_timeout: Duration::from_secs(0),
            escalation_window: Duration::from_secs(0),
            escalation_max_per_window: 0,
            escalation_quarantine_threshold: 0,
            default_session_ttl: Duration::from_secs(0),
            max_session_ttl: Duration::from_secs(0),
            allowed_worktree_roots: roots.into_iter().map(str::to_owned).collect(),
            max_delegation_ttl: Duration::from_secs(0),
            gateway: None,
            providers: Vec::new(),
            plan_signing: None,
            plan_bundle_limits: None,
            base_cost_per_intent_kind: HashMap::new(),
            cost_per_touched_path: 0,
            max_cost_per_task: 0,
            policy_sha256: String::new(),
            signed_by: String::new(),
            signed_at: 0,
            claim_rules: Vec::new(),
            claim_default_action: String::new(),
            egress_domains: Vec::new(),
            egress_patterns: Vec::new(),
            egress_max_fetches_per_window: 0,
            notification_channels: vec![NotificationChannel {
                id:     IMPLICIT_SHELL_CHANNEL_ID.to_owned(),
                kind:   NotificationChannelKind::Shell,
                target: String::new(),
            }],
            notification_routes: HashMap::new(),
            default_notification_channels: vec![IMPLICIT_SHELL_CHANNEL_ID.to_owned()],
            bypassed_cert_misconfigs: Vec::new(),
            credential_backend: CredentialBackendKind::default(),
            integration_merge_verifiers: Vec::new(),
            git_default_target_ref: "refs/heads/main".to_owned(),
            git_target_ref_locked: false,
        }
    }

    #[test]
    fn exact_match_is_accepted() {
        let b = bundle_with_roots(vec!["/srv/work"]);
        assert!(b.worktree_root_allowed("/srv/work"));
    }

    #[test]
    fn path_under_root_is_accepted() {
        let b = bundle_with_roots(vec!["/srv/work"]);
        assert!(b.worktree_root_allowed("/srv/work/repo"));
        assert!(b.worktree_root_allowed("/srv/work/repo/subdir/file"));
    }

    /// Regression guard: literal byte prefix without a separator boundary
    /// MUST NOT count as "under the root".
    #[test]
    fn sibling_with_byte_prefix_is_rejected() {
        let b = bundle_with_roots(vec!["/srv/work"]);
        assert!(!b.worktree_root_allowed("/srv/work_secret"),
                "/srv/work_secret must NOT match /srv/work");
        assert!(!b.worktree_root_allowed("/srv/work_secret/repo"),
                "subdir of /srv/work_secret must NOT match /srv/work");
        assert!(!b.worktree_root_allowed("/srv/working"),
                "/srv/working must NOT match /srv/work");
    }

    /// Operator-supplied trailing slash is normalised away so both forms work.
    #[test]
    fn trailing_slash_in_root_is_tolerated() {
        let b = bundle_with_roots(vec!["/srv/work/"]);
        assert!(b.worktree_root_allowed("/srv/work"),       "exact root, no trailing /");
        assert!(b.worktree_root_allowed("/srv/work/repo"),  "subdir under root with trailing /");
        assert!(!b.worktree_root_allowed("/srv/work_secret"),
                "trailing-slash root must STILL reject the byte-prefix sibling");
    }

    #[test]
    fn empty_allowlist_rejects_everything() {
        let b = bundle_with_roots(vec![]);
        assert!(!b.worktree_root_allowed("/srv/work"));
        assert!(!b.worktree_root_allowed(""));
    }

    #[test]
    fn multiple_roots_any_match() {
        let b = bundle_with_roots(vec!["/srv/a", "/srv/b"]);
        assert!(b.worktree_root_allowed("/srv/a/x"));
        assert!(b.worktree_root_allowed("/srv/b"));
        assert!(!b.worktree_root_allowed("/srv/c/x"));
        // Sibling collisions still rejected on every root in the list.
        assert!(!b.worktree_root_allowed("/srv/a_other"));
    }

    #[test]
    fn shorter_path_than_root_is_rejected() {
        let b = bundle_with_roots(vec!["/srv/work"]);
        assert!(!b.worktree_root_allowed("/srv"));
        assert!(!b.worktree_root_allowed(""));
    }
}

// ---------------------------------------------------------------------------
// Tests — `[gateway]` and `[[providers]]` validation (Phase A.3 / T0.3).
// ---------------------------------------------------------------------------
//
// These cover every fail-closed branch in the gateway / providers
// validation block of `PolicyBundle::validate`. Each test constructs a
// minimal-but-loadable TOML document, mutates the gateway/providers
// section, and asserts the expected outcome via the public `load_policy`
// (since we want the *whole* parse + validate path under test, not just
// individual field checks).

#[cfg(test)]
mod gateway_providers_tests {
    use crate::load_policy;

    /// Minimal valid policy.toml — exactly the sections REQUIRED by
    /// `PolicyBundle::validate`, plus an empty `[budget]` and the default
    /// lane. Inlined (rather than calling `raxis_genesis_tools`) to avoid
    /// a dev-dep cycle and to keep these tests focused: any drift between
    /// this fixture and the real emitter is a separate problem caught by
    /// `genesis-tools::tests::output_round_trips_through_load_policy`.
    ///
    /// `pub(super)` so sibling test modules (notably `notifications_tests`)
    /// can reuse this fixture without code duplication.
    pub(super) fn minimal_policy_toml_for_tests() -> String {
        minimal_policy_toml()
    }

    fn minimal_policy_toml() -> String {
        // Cert-mandatory (INV-CERT-01): the loader's
        // `validate_operator_certs` step rejects any
        // `[[operators.entries]]` block missing a self-signed cert
        // whose `pubkey_hex` matches the entry's. We mint that cert
        // here from a deterministic operator key so every gateway /
        // providers / notifications fixture in this module loads
        // through the strict-deserialise + self-sig path.
        let op_key = raxis_test_support::ephemeral_signing_key([0xCCu8; 32]);
        let op_pk_hex = raxis_test_support::pubkey_hex(&op_key);
        let op_fp = crate::loader::operator_pubkey_fingerprint(&op_pk_hex).unwrap();
        let cert = raxis_test_support::ephemeral_cert_with_key(
            &op_key,
            raxis_test_support::CertOpts {
                display_name: "operator-1".to_owned(),
                permitted_ops: vec!["CreateInitiative".into()],
                ..raxis_test_support::CertOpts::default()
            },
        );
        let cert_subtable = ::toml::to_string(&cert).unwrap();
        format!(
            r#"[meta]
epoch     = 1
signed_by = "{op_fp}"
signed_at = 1700000000

[authority]
authority_pubkey = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
quality_pubkey   = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

[escalation_policy]
timeout_secs         = 3600
window_secs          = 300
max_per_window       = 5
quarantine_threshold = 3

[sessions]
default_ttl_secs       = 86400
max_ttl_secs           = 604800
allowed_worktree_roots = ["/tmp/raxis-policy-test"]

[delegations]
max_ttl_secs = 86400

[budget]
cost_per_touched_path = 1
max_cost_per_task     = 10000

[budget.base_cost_per_intent_kind]
SingleCommit     = 10
IntegrationMerge = 50
CompleteTask     = 5
ReportFailure    = 1

[[operators.entries]]
pubkey_fingerprint = "{op_fp}"
display_name       = "operator-1"
pubkey_hex         = "{op_pk_hex}"
permitted_ops      = ["CreateInitiative"]

[operators.entries.cert]
{cert_subtable}

[[lanes]]
lane_id              = "default"
max_concurrent_tasks = 4
max_cost_per_epoch   = 10000
priority             = 100
"#)
    }

    fn write_and_load(
        toml_str: &str,
    ) -> Result<crate::PolicyBundle, crate::PolicyError> {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), toml_str).unwrap();
        load_policy(tmp.path()).map(|(b, _, _)| b)
    }

    // ── No-section happy path ─────────────────────────────────────────────

    #[test]
    fn policy_without_gateway_or_providers_loads_cleanly() {
        // Genesis policy template has both sections COMMENTED OUT. The
        // kernel must boot fine without them — operators who don't need
        // an LLM workflow ship like this.
        let bundle = write_and_load(&minimal_policy_toml())
            .expect("genesis-template policy must load even without [gateway]");
        assert!(bundle.gateway().is_none(), "no [gateway] section → None");
        assert!(bundle.providers().is_empty(), "no [[providers]] → empty slice");
    }

    // ── [gateway] happy path + accessor ───────────────────────────────────

    #[test]
    fn gateway_section_with_defaults_round_trips_through_loader() {
        let mut t = minimal_policy_toml();
        t.push_str("\n[gateway]\nbinary_path = \"/usr/local/bin/raxis-gateway\"\n");
        let bundle = write_and_load(&t).expect("valid [gateway] must load");
        let g = bundle.gateway().expect("gateway() returns Some after [gateway]");
        assert_eq!(g.binary_path, "/usr/local/bin/raxis-gateway");
        // Defaults applied:
        assert_eq!(g.spawn_timeout_secs, 5);
        assert_eq!(g.respawn_backoff_ms, 1000);
        assert_eq!(g.max_consecutive_respawns, 5);
    }

    // ── [gateway] negative cases ──────────────────────────────────────────

    #[test]
    fn relative_gateway_binary_path_is_rejected() {
        // Defence-in-depth: a relative path would let `Command::new` resolve
        // via $PATH, opening a hijack window. The validator MUST reject.
        let mut t = minimal_policy_toml();
        t.push_str("\n[gateway]\nbinary_path = \"raxis-gateway\"\n");
        let err = write_and_load(&t).expect_err("relative path must fail");
        assert!(format!("{err}").contains("must be absolute"),
            "error must explain WHY rejected; got: {err}");
    }

    #[test]
    fn zero_spawn_timeout_is_rejected() {
        let mut t = minimal_policy_toml();
        t.push_str(
            "\n[gateway]\n\
             binary_path        = \"/usr/local/bin/raxis-gateway\"\n\
             spawn_timeout_secs = 0\n",
        );
        let err = write_and_load(&t).expect_err("zero spawn_timeout must fail");
        assert!(format!("{err}").contains("spawn_timeout_secs"));
    }

    #[test]
    fn zero_max_consecutive_respawns_is_rejected_with_explicit_one_hint() {
        // We require ≥ 1 because a "0" would silently disable supervision —
        // operators who want that should set 1, not 0. The error spells
        // this out so the operator gets the right answer in one read.
        let mut t = minimal_policy_toml();
        t.push_str(
            "\n[gateway]\n\
             binary_path              = \"/usr/local/bin/raxis-gateway\"\n\
             max_consecutive_respawns = 0\n",
        );
        let err = write_and_load(&t).expect_err("zero respawn cap must fail");
        let s = format!("{err}");
        assert!(s.contains("max_consecutive_respawns"));
        assert!(s.contains("set to 1"),
            "error should hint operator to use 1, not 0; got: {s}");
    }

    // ── [[providers]] happy path + accessor + defaults ───────────────────

    #[test]
    fn provider_entry_with_only_required_fields_uses_defaults() {
        let mut t = minimal_policy_toml();
        t.push_str(
            "\n[[providers]]\n\
             provider_id      = \"anthropic-prod\"\n\
             kind             = \"Anthropic\"\n\
             credentials_file = \"anthropic-prod.toml\"\n",
        );
        let bundle = write_and_load(&t).expect("minimal provider entry must load");
        assert_eq!(bundle.providers().len(), 1);
        let p = bundle.provider("anthropic-prod").expect("lookup by id works");
        assert_eq!(p.kind, "Anthropic");
        assert_eq!(p.credentials_file, "anthropic-prod.toml");
        // Defaults from `default_*_ms` and `default_max_response_bytes`:
        assert_eq!(p.inference_timeout_ms, 30_000);
        assert_eq!(p.data_fetch_timeout_ms, 10_000);
        assert_eq!(p.max_response_bytes, 16 * 1024 * 1024);
    }

    #[test]
    fn provider_lookup_returns_none_for_unknown_id() {
        let mut t = minimal_policy_toml();
        t.push_str(
            "\n[[providers]]\n\
             provider_id      = \"anthropic-prod\"\n\
             kind             = \"Anthropic\"\n\
             credentials_file = \"anthropic-prod.toml\"\n",
        );
        let bundle = write_and_load(&t).unwrap();
        assert!(bundle.provider("openai-prod").is_none());
    }

    // ── [[providers]] negative cases ─────────────────────────────────────

    #[test]
    fn duplicate_provider_id_is_rejected() {
        let mut t = minimal_policy_toml();
        for _ in 0..2 {
            t.push_str(
                "\n[[providers]]\n\
                 provider_id      = \"dup\"\n\
                 kind             = \"Anthropic\"\n\
                 credentials_file = \"x.toml\"\n",
            );
        }
        let err = write_and_load(&t).expect_err("dup ids must fail");
        assert!(format!("{err}").contains("duplicated"));
    }

    #[test]
    fn empty_provider_id_is_rejected() {
        let mut t = minimal_policy_toml();
        t.push_str(
            "\n[[providers]]\n\
             provider_id      = \"\"\n\
             kind             = \"Anthropic\"\n\
             credentials_file = \"x.toml\"\n",
        );
        let err = write_and_load(&t).expect_err("empty id must fail");
        assert!(format!("{err}").contains("non-empty"));
    }

    #[test]
    fn credentials_file_with_path_separator_is_rejected() {
        // `../etc/shadow`-style payloads must be rejected at validate time,
        // before the gateway opens the file.
        for evil in &["../etc/shadow", "subdir/file.toml", "/etc/shadow", "..", "."] {
            let mut t = minimal_policy_toml();
            t.push_str(&format!(
                "\n[[providers]]\n\
                 provider_id      = \"p1\"\n\
                 kind             = \"Anthropic\"\n\
                 credentials_file = \"{evil}\"\n",
            ));
            let err = write_and_load(&t).err().unwrap_or_else(|| {
                panic!("expected Err for credentials_file={evil:?}, got Ok");
            });
            let s = format!("{err}");
            assert!(s.contains("bare filename"),
                "credentials_file={evil:?} should be rejected as path-traversal; \
                 got error: {s}");
        }
    }

    #[test]
    fn inference_timeout_above_normative_cap_is_rejected() {
        let cap = crate::MAX_INFERENCE_TIMEOUT_MS;
        let mut t = minimal_policy_toml();
        t.push_str(&format!(
            "\n[[providers]]\n\
             provider_id          = \"p1\"\n\
             kind                 = \"Anthropic\"\n\
             credentials_file     = \"p1.toml\"\n\
             inference_timeout_ms = {}\n",
            cap + 1,
        ));
        let err = write_and_load(&t).expect_err("timeout > cap must fail");
        assert!(format!("{err}").contains("inference_timeout_ms"));
    }

    #[test]
    fn data_fetch_timeout_above_normative_cap_is_rejected() {
        let cap = crate::MAX_DATA_FETCH_TIMEOUT_MS;
        let mut t = minimal_policy_toml();
        t.push_str(&format!(
            "\n[[providers]]\n\
             provider_id           = \"p1\"\n\
             kind                  = \"Anthropic\"\n\
             credentials_file      = \"p1.toml\"\n\
             data_fetch_timeout_ms = {}\n",
            cap + 1,
        ));
        let err = write_and_load(&t).expect_err("timeout > cap must fail");
        assert!(format!("{err}").contains("data_fetch_timeout_ms"));
    }

    #[test]
    fn response_bytes_above_ceiling_is_rejected() {
        let ceil = crate::MAX_RESPONSE_BYTES_CEILING;
        let mut t = minimal_policy_toml();
        t.push_str(&format!(
            "\n[[providers]]\n\
             provider_id        = \"p1\"\n\
             kind               = \"Anthropic\"\n\
             credentials_file   = \"p1.toml\"\n\
             max_response_bytes = {}\n",
            ceil + 1,
        ));
        let err = write_and_load(&t).expect_err("body > ceiling must fail");
        assert!(format!("{err}").contains("max_response_bytes"));
    }

    #[test]
    fn zero_inference_timeout_is_rejected() {
        let mut t = minimal_policy_toml();
        t.push_str(
            "\n[[providers]]\n\
             provider_id          = \"p1\"\n\
             kind                 = \"Anthropic\"\n\
             credentials_file     = \"p1.toml\"\n\
             inference_timeout_ms = 0\n",
        );
        let err = write_and_load(&t).expect_err("zero timeout must fail");
        assert!(format!("{err}").contains("must be > 0"));
    }

    #[test]
    fn forward_compat_unknown_provider_kind_loads_at_validate_time() {
        // peripherals.md §3.2: unknown kinds are accepted at policy-validate
        // time (forward-compat); they will be rejected by the gateway at
        // dispatch time. This test pins the validate-time accept side.
        let mut t = minimal_policy_toml();
        t.push_str(
            "\n[[providers]]\n\
             provider_id      = \"future-vendor\"\n\
             kind             = \"NotAValidKindYet\"\n\
             credentials_file = \"future.toml\"\n",
        );
        let bundle = write_and_load(&t).expect("unknown kind must load");
        assert_eq!(bundle.providers()[0].kind, "NotAValidKindYet");
    }
}

// ---------------------------------------------------------------------------
// Tests — `[plan_signing]` validation (plan-bundle-sealing.md §7.4).
// ---------------------------------------------------------------------------
//
// These cover the §7.4 invariants (hard ceilings, clock-skew ratio,
// nonce-grace bound, sweep cadence bounds), the all-defaults path
// for kernels that omit `[plan_signing]`, and the round-trip through
// `PolicyBundle::plan_signing()`.

#[cfg(test)]
mod plan_signing_tests {
    use super::*;
    use crate::load_policy;

    fn minimal_with_plan_signing(extra: &str) -> String {
        let mut t = super::gateway_providers_tests::minimal_policy_toml_for_tests();
        t.push_str(extra);
        t
    }

    fn write_and_load(
        toml_str: &str,
    ) -> Result<crate::PolicyBundle, crate::PolicyError> {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), toml_str).unwrap();
        load_policy(tmp.path()).map(|(b, _, _)| b)
    }

    #[test]
    fn omitted_plan_signing_section_yields_spec_defaults() {
        let bundle = write_and_load(
            &super::gateway_providers_tests::minimal_policy_toml_for_tests(),
        )
        .expect("policy without [plan_signing] must load");
        let p = bundle.plan_signing();
        assert_eq!(p.max_plan_bundle_age_secs,    24 * 60 * 60);
        assert_eq!(p.max_clock_skew_secs,         5 * 60);
        assert_eq!(p.nonce_retention_grace_secs,  60 * 60);
        assert_eq!(p.nonce_sweep_interval_secs,   60 * 60);
        assert!(!p.accept_unfresh_v2_0_bundles);
    }

    #[test]
    fn empty_plan_signing_section_uses_field_level_defaults() {
        let bundle = write_and_load(&minimal_with_plan_signing("\n[plan_signing]\n"))
            .expect("[plan_signing] with no fields must inherit field defaults");
        let p = bundle.plan_signing();
        assert_eq!(p.max_plan_bundle_age_secs,   24 * 60 * 60);
        assert_eq!(p.nonce_sweep_interval_secs,  60 * 60);
    }

    #[test]
    fn explicit_values_round_trip_via_accessor() {
        let bundle = write_and_load(&minimal_with_plan_signing(
            "\n[plan_signing]\n\
             max_plan_bundle_age_secs    = 3600\n\
             max_clock_skew_secs         = 60\n\
             nonce_retention_grace_secs  = 300\n\
             nonce_sweep_interval_secs   = 120\n\
             accept_unfresh_v2_0_bundles = true\n",
        ))
        .expect("explicit values must validate cleanly");
        let p = bundle.plan_signing();
        assert_eq!(p.max_plan_bundle_age_secs,   3600);
        assert_eq!(p.max_clock_skew_secs,        60);
        assert_eq!(p.nonce_retention_grace_secs, 300);
        assert_eq!(p.nonce_sweep_interval_secs,  120);
        assert!(p.accept_unfresh_v2_0_bundles);
    }

    #[test]
    fn nonce_live_window_secs_is_age_plus_skew_plus_grace() {
        let bundle = write_and_load(&minimal_with_plan_signing(
            "\n[plan_signing]\n\
             max_plan_bundle_age_secs    = 3600\n\
             max_clock_skew_secs         = 60\n\
             nonce_retention_grace_secs  = 300\n",
        ))
        .expect("explicit values must validate cleanly");
        assert_eq!(bundle.plan_signing().nonce_live_window_secs(), 3600 + 60 + 300);
    }

    #[test]
    fn zero_max_age_is_rejected() {
        let err = write_and_load(&minimal_with_plan_signing(
            "\n[plan_signing]\nmax_plan_bundle_age_secs = 0\n",
        ))
        .expect_err("zero freshness window must fail policy load");
        let s = format!("{err}");
        assert!(s.contains("FAIL_POLICY_PLAN_SIGNING_INVALID"), "got: {s}");
        assert!(s.contains("max_plan_bundle_age_secs"), "got: {s}");
    }

    #[test]
    fn max_age_above_30_day_ceiling_is_rejected() {
        let above = PLAN_BUNDLE_MAX_AGE_HARD_CEILING_SECS + 1;
        let err = write_and_load(&minimal_with_plan_signing(&format!(
            "\n[plan_signing]\nmax_plan_bundle_age_secs = {above}\n",
        )))
        .expect_err("ceiling overshoot must fail policy load");
        let s = format!("{err}");
        assert!(s.contains("FAIL_POLICY_PLAN_SIGNING_INVALID"), "got: {s}");
        assert!(s.contains("hard ceiling"), "error must mention ceiling; got: {s}");
    }

    #[test]
    fn skew_above_quarter_of_max_age_is_rejected() {
        let err = write_and_load(&minimal_with_plan_signing(
            "\n[plan_signing]\n\
             max_plan_bundle_age_secs = 3600\n\
             max_clock_skew_secs      = 901\n", // > 3600 / 4 = 900
        ))
        .expect_err("skew > age/4 must fail policy load");
        let s = format!("{err}");
        assert!(s.contains("FAIL_POLICY_PLAN_SIGNING_INVALID"), "got: {s}");
        assert!(s.contains("max_clock_skew_secs"), "got: {s}");
    }

    #[test]
    fn skew_at_quarter_boundary_is_accepted() {
        let bundle = write_and_load(&minimal_with_plan_signing(
            "\n[plan_signing]\n\
             max_plan_bundle_age_secs = 3600\n\
             max_clock_skew_secs      = 900\n", // == 3600 / 4
        ))
        .expect("skew == age/4 must be accepted (boundary inclusive)");
        assert_eq!(bundle.plan_signing().max_clock_skew_secs, 900);
    }

    #[test]
    fn grace_above_max_age_is_rejected() {
        let err = write_and_load(&minimal_with_plan_signing(
            "\n[plan_signing]\n\
             max_plan_bundle_age_secs   = 3600\n\
             nonce_retention_grace_secs = 3601\n",
        ))
        .expect_err("grace > age must fail policy load");
        let s = format!("{err}");
        assert!(s.contains("FAIL_POLICY_PLAN_SIGNING_INVALID"), "got: {s}");
        assert!(s.contains("nonce_retention_grace_secs"), "got: {s}");
    }

    #[test]
    fn zero_sweep_interval_is_rejected() {
        let err = write_and_load(&minimal_with_plan_signing(
            "\n[plan_signing]\nnonce_sweep_interval_secs = 0\n",
        ))
        .expect_err("zero sweep interval must fail policy load");
        let s = format!("{err}");
        assert!(s.contains("FAIL_POLICY_PLAN_SIGNING_INVALID"), "got: {s}");
        assert!(s.contains("nonce_sweep_interval_secs"), "got: {s}");
    }

    #[test]
    fn sweep_interval_above_24h_ceiling_is_rejected() {
        let above = PLAN_SIGNING_NONCE_SWEEP_INTERVAL_HARD_CEILING_SECS + 1;
        let err = write_and_load(&minimal_with_plan_signing(&format!(
            "\n[plan_signing]\nnonce_sweep_interval_secs = {above}\n",
        )))
        .expect_err("sweep interval ceiling overshoot must fail policy load");
        let s = format!("{err}");
        assert!(s.contains("FAIL_POLICY_PLAN_SIGNING_INVALID"), "got: {s}");
    }

    #[test]
    fn ceiling_at_max_is_accepted() {
        let max_age = PLAN_BUNDLE_MAX_AGE_HARD_CEILING_SECS;
        let max_sweep = PLAN_SIGNING_NONCE_SWEEP_INTERVAL_HARD_CEILING_SECS;
        let bundle = write_and_load(&minimal_with_plan_signing(&format!(
            "\n[plan_signing]\n\
             max_plan_bundle_age_secs   = {max_age}\n\
             nonce_sweep_interval_secs  = {max_sweep}\n",
        )))
        .expect("ceiling exact-match must be accepted");
        let p = bundle.plan_signing();
        assert_eq!(p.max_plan_bundle_age_secs,  max_age);
        assert_eq!(p.nonce_sweep_interval_secs, max_sweep);
    }
}

// ---------------------------------------------------------------------------
// Tests — `[plan_bundle_limits]` validation (plan-bundle-sealing.md §7.4).
// ---------------------------------------------------------------------------
//
// These cover the same shape as the `plan_signing_tests` module above:
// (a) accessor returns spec defaults when the section is omitted;
// (b) accessor returns spec defaults when the section is present but
//     empty;
// (c) explicit values round-trip;
// (d) every field-level invariant is rejected with
//     `FAIL_POLICY_PLAN_BUNDLE_LIMIT_ABOVE_CEILING`;
// (e) ceiling-exact-match values are accepted (boundary inclusivity).

#[cfg(test)]
mod plan_bundle_limits_tests {
    use super::*;
    use crate::load_policy;

    fn minimal_with_plan_bundle_limits(extra: &str) -> String {
        let mut t = super::gateway_providers_tests::minimal_policy_toml_for_tests();
        t.push_str(extra);
        t
    }

    fn write_and_load(
        toml_str: &str,
    ) -> Result<crate::PolicyBundle, crate::PolicyError> {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), toml_str).unwrap();
        load_policy(tmp.path()).map(|(b, _, _)| b)
    }

    #[test]
    fn omitted_plan_bundle_limits_section_yields_spec_defaults() {
        let bundle = write_and_load(
            &super::gateway_providers_tests::minimal_policy_toml_for_tests(),
        )
        .expect("policy without [plan_bundle_limits] must load");
        let p = bundle.plan_bundle_limits();
        assert_eq!(p.max_artifact_bytes, 1 * 1024 * 1024);
        assert_eq!(p.max_bundle_bytes,   10 * 1024 * 1024);
        assert_eq!(p.max_artifact_count, 200);
    }

    #[test]
    fn empty_plan_bundle_limits_section_uses_field_level_defaults() {
        let bundle = write_and_load(&minimal_with_plan_bundle_limits(
            "\n[plan_bundle_limits]\n",
        ))
        .expect("[plan_bundle_limits] with no fields must inherit field defaults");
        let p = bundle.plan_bundle_limits();
        assert_eq!(p.max_artifact_bytes, 1 * 1024 * 1024);
        assert_eq!(p.max_bundle_bytes,   10 * 1024 * 1024);
        assert_eq!(p.max_artifact_count, 200);
    }

    #[test]
    fn explicit_values_round_trip_via_accessor() {
        let bundle = write_and_load(&minimal_with_plan_bundle_limits(
            "\n[plan_bundle_limits]\n\
             max_artifact_bytes  = 524288\n\
             max_bundle_bytes    = 5242880\n\
             max_artifact_count  = 50\n",
        ))
        .expect("explicit values must validate cleanly");
        let p = bundle.plan_bundle_limits();
        assert_eq!(p.max_artifact_bytes, 524_288);
        assert_eq!(p.max_bundle_bytes,   5_242_880);
        assert_eq!(p.max_artifact_count, 50);
    }

    #[test]
    fn zero_max_artifact_bytes_is_rejected() {
        let err = write_and_load(&minimal_with_plan_bundle_limits(
            "\n[plan_bundle_limits]\nmax_artifact_bytes = 0\n",
        ))
        .expect_err("zero artifact cap must fail policy load");
        let s = format!("{err}");
        assert!(s.contains("FAIL_POLICY_PLAN_BUNDLE_LIMIT_ABOVE_CEILING"), "got: {s}");
        assert!(s.contains("max_artifact_bytes"), "got: {s}");
    }

    #[test]
    fn artifact_bytes_above_64mib_ceiling_is_rejected() {
        let above = PLAN_BUNDLE_MAX_ARTIFACT_BYTES_HARD_CEILING + 1;
        let err = write_and_load(&minimal_with_plan_bundle_limits(&format!(
            "\n[plan_bundle_limits]\nmax_artifact_bytes = {above}\n",
        )))
        .expect_err("artifact cap above hard ceiling must fail policy load");
        let s = format!("{err}");
        assert!(s.contains("FAIL_POLICY_PLAN_BUNDLE_LIMIT_ABOVE_CEILING"), "got: {s}");
        assert!(s.contains("hard ceiling"), "error must mention ceiling; got: {s}");
    }

    #[test]
    fn zero_max_bundle_bytes_is_rejected() {
        let err = write_and_load(&minimal_with_plan_bundle_limits(
            "\n[plan_bundle_limits]\nmax_bundle_bytes = 0\n",
        ))
        .expect_err("zero bundle cap must fail policy load");
        let s = format!("{err}");
        assert!(s.contains("FAIL_POLICY_PLAN_BUNDLE_LIMIT_ABOVE_CEILING"), "got: {s}");
        assert!(s.contains("max_bundle_bytes"), "got: {s}");
    }

    #[test]
    fn bundle_bytes_above_128mib_ceiling_is_rejected() {
        let above = PLAN_BUNDLE_MAX_BUNDLE_BYTES_HARD_CEILING + 1;
        let err = write_and_load(&minimal_with_plan_bundle_limits(&format!(
            "\n[plan_bundle_limits]\nmax_bundle_bytes = {above}\n",
        )))
        .expect_err("bundle cap above hard ceiling must fail policy load");
        let s = format!("{err}");
        assert!(s.contains("FAIL_POLICY_PLAN_BUNDLE_LIMIT_ABOVE_CEILING"), "got: {s}");
    }

    #[test]
    fn zero_max_artifact_count_is_rejected() {
        let err = write_and_load(&minimal_with_plan_bundle_limits(
            "\n[plan_bundle_limits]\nmax_artifact_count = 0\n",
        ))
        .expect_err("zero artifact count must fail policy load");
        let s = format!("{err}");
        assert!(s.contains("FAIL_POLICY_PLAN_BUNDLE_LIMIT_ABOVE_CEILING"), "got: {s}");
        assert!(s.contains("max_artifact_count"), "got: {s}");
    }

    #[test]
    fn artifact_count_above_1024_ceiling_is_rejected() {
        let above = PLAN_BUNDLE_MAX_ARTIFACT_COUNT_HARD_CEILING + 1;
        let err = write_and_load(&minimal_with_plan_bundle_limits(&format!(
            "\n[plan_bundle_limits]\nmax_artifact_count = {above}\n",
        )))
        .expect_err("artifact count above hard ceiling must fail policy load");
        let s = format!("{err}");
        assert!(s.contains("FAIL_POLICY_PLAN_BUNDLE_LIMIT_ABOVE_CEILING"), "got: {s}");
    }

    #[test]
    fn artifact_bytes_above_bundle_bytes_is_rejected() {
        // Coherence rule: a single artifact cannot exceed the total bundle cap.
        let err = write_and_load(&minimal_with_plan_bundle_limits(
            "\n[plan_bundle_limits]\n\
             max_artifact_bytes = 2_000_000\n\
             max_bundle_bytes   = 1_500_000\n",
        ))
        .expect_err("artifact > bundle cap must fail policy load");
        let s = format!("{err}");
        assert!(s.contains("FAIL_POLICY_PLAN_BUNDLE_LIMIT_ABOVE_CEILING"), "got: {s}");
        assert!(s.contains("must be <="), "got: {s}");
    }

    #[test]
    fn ceiling_at_max_is_accepted() {
        // Boundary-inclusive: exactly-at-ceiling values are accepted.
        let max_artifact = PLAN_BUNDLE_MAX_ARTIFACT_BYTES_HARD_CEILING;
        let max_bundle   = PLAN_BUNDLE_MAX_BUNDLE_BYTES_HARD_CEILING;
        let max_count    = PLAN_BUNDLE_MAX_ARTIFACT_COUNT_HARD_CEILING;
        let bundle = write_and_load(&minimal_with_plan_bundle_limits(&format!(
            "\n[plan_bundle_limits]\n\
             max_artifact_bytes  = {max_artifact}\n\
             max_bundle_bytes    = {max_bundle}\n\
             max_artifact_count  = {max_count}\n",
        )))
        .expect("ceiling exact-match must be accepted");
        let p = bundle.plan_bundle_limits();
        assert_eq!(p.max_artifact_bytes, max_artifact);
        assert_eq!(p.max_bundle_bytes,   max_bundle);
        assert_eq!(p.max_artifact_count, max_count);
    }
}

// ---------------------------------------------------------------------------
// Tests — `[notifications]` validation (cli-readonly.md §5.6).
// ---------------------------------------------------------------------------
//
// These cover every fail-closed branch in `validate_notifications`,
// the implicit-Shell synthesis, the default_channels fallback, and the
// silenced-route semantics.

#[cfg(test)]
mod notifications_tests {
    use super::*;
    use crate::load_policy;

    fn minimal_with_notifications(extra: &str) -> String {
        let mut t = super::gateway_providers_tests::minimal_policy_toml_for_tests();
        t.push_str(extra);
        t
    }

    fn write_and_load(t: &str) -> Result<crate::PolicyBundle, crate::PolicyError> {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), t).unwrap();
        load_policy(tmp.path()).map(|(b, _, _)| b)
    }

    // ── Implicit-Shell synthesis ─────────────────────────────────────

    #[test]
    fn no_notifications_section_synthesises_implicit_shell_channel() {
        // Genesis policies that omit [notifications] still get a working
        // Shell channel so escalation notifications are visible from
        // day one (cli-readonly.md §5.6.2).
        let bundle = write_and_load(&minimal_with_notifications(""))
            .expect("policy without [notifications] must load cleanly");

        let chans = bundle.notification_channels();
        assert_eq!(chans.len(), 1, "exactly the implicit shell channel");
        assert_eq!(chans[0].id, IMPLICIT_SHELL_CHANNEL_ID);
        assert_eq!(chans[0].kind, NotificationChannelKind::Shell);
        assert!(chans[0].target.is_empty(),
            "implicit Shell target is empty (resolved at runtime)");

        let defaults = bundle.default_notification_channels();
        assert_eq!(defaults, &["shell".to_owned()],
            "default_channels falls back to [\"shell\"] when omitted");

        assert!(bundle.notification_route("EscalationApproved").is_none(),
            "no explicit routes ⇒ None ⇒ caller uses default channels");
    }

    #[test]
    fn explicit_shell_channel_overrides_implicit_target() {
        // Operators who run two RAXIS instances on the same host can
        // point the Shell channel at a non-default file by declaring
        // an explicit `id="shell"` entry.
        let toml = minimal_with_notifications("
[[notifications.channels]]
id     = \"shell\"
kind   = \"Shell\"
target = \"/var/log/raxis-alt-inbox.jsonl\"
");
        let bundle = write_and_load(&toml).expect("override must load");
        let shell = bundle.notification_channel("shell").expect("shell channel exists");
        assert_eq!(shell.target, "/var/log/raxis-alt-inbox.jsonl",
            "explicit entry overrides the implicit target");
        assert_eq!(bundle.notification_channels().len(), 1,
            "no synthesised duplicate when operator declared shell explicitly");
    }

    #[test]
    fn shell_inbox_path_for_data_dir_is_canonical_path() {
        // The runtime resolves an empty Shell target to this path.
        let p = PolicyBundle::shell_inbox_path_for(std::path::Path::new("/tmp/raxis"));
        assert!(p.ends_with("notifications/inbox.jsonl"),
            "got {p:?}");
    }

    // ── default_channels validation ──────────────────────────────────

    #[test]
    fn default_channels_referencing_unknown_id_is_rejected() {
        let toml = minimal_with_notifications("
[notifications]
default_channels = [\"does-not-exist\"]
");
        let err = write_and_load(&toml).expect_err("unknown id must fail");
        assert!(format!("{err}").contains("unknown channel id"),
            "error must explain WHY rejected; got: {err}");
    }

    #[test]
    fn default_channels_can_reference_implicit_shell() {
        // The implicit Shell channel is always available — even if it
        // was not declared explicitly. default_channels = ["shell"]
        // must validate cleanly.
        let toml = minimal_with_notifications("
[notifications]
default_channels = [\"shell\"]
");
        let bundle = write_and_load(&toml).expect("must load");
        assert_eq!(bundle.default_notification_channels(), &["shell".to_owned()]);
    }

    // ── route validation ─────────────────────────────────────────────

    #[test]
    fn route_with_unknown_event_kind_is_rejected() {
        let toml = minimal_with_notifications("
[[notifications.routes]]
event_kind = \"NotARealAuditEventKind\"
channels   = [\"shell\"]
");
        let err = write_and_load(&toml).expect_err("typo must fail");
        let s = format!("{err}");
        assert!(s.contains("not a known AuditEventKind"),
            "error must mention the AuditEventKind list; got: {s}");
    }

    #[test]
    fn route_with_unknown_channel_id_is_rejected() {
        let toml = minimal_with_notifications("
[[notifications.routes]]
event_kind = \"EscalationApproved\"
channels   = [\"ghost\"]
");
        let err = write_and_load(&toml).expect_err("unknown id must fail");
        assert!(format!("{err}").contains("unknown channel id"));
    }

    #[test]
    fn route_with_empty_channels_list_is_silenced_form() {
        // Spec §5.6.2 rule 2: empty list is the canonical "silenced"
        // form. We accept it and surface it as Some(&[]) so the
        // dispatcher distinguishes "no route" (None → fall through to
        // default_channels) from "explicit silence" (Some(&[]) → drop).
        let toml = minimal_with_notifications("
[[notifications.routes]]
event_kind = \"TaskStateChanged\"
channels   = []
");
        let bundle = write_and_load(&toml).expect("silenced route must load");
        let route = bundle.notification_route("TaskStateChanged");
        assert!(matches!(route, Some(slice) if slice.is_empty()),
            "silenced ⇒ Some(empty), got {route:?}");
    }

    #[test]
    fn duplicate_channel_id_is_rejected() {
        let toml = minimal_with_notifications("
[[notifications.channels]]
id     = \"file-mirror\"
kind   = \"File\"
target = \"/var/log/raxis.jsonl\"

[[notifications.channels]]
id     = \"file-mirror\"
kind   = \"File\"
target = \"/var/log/raxis-2.jsonl\"
");
        let err = write_and_load(&toml).expect_err("dup ids must fail");
        assert!(format!("{err}").contains("duplicated"));
    }

    #[test]
    fn file_channel_with_empty_target_is_rejected() {
        let toml = minimal_with_notifications("
[[notifications.channels]]
id     = \"file-mirror\"
kind   = \"File\"
target = \"\"
");
        let err = write_and_load(&toml).expect_err("File channel needs target");
        assert!(format!("{err}").contains("non-empty target"));
    }

    // ── full happy path ──────────────────────────────────────────────

    #[test]
    fn full_routing_example_round_trips() {
        // Mirrors the example in cli-readonly.md §5.6.2.
        let toml = minimal_with_notifications("
[notifications]
default_channels = [\"shell\"]

[[notifications.channels]]
id     = \"audit-mirror\"
kind   = \"File\"
target = \"/var/log/raxis-notifications.jsonl\"

[[notifications.routes]]
event_kind = \"EscalationSubmitted\"
channels   = [\"shell\", \"audit-mirror\"]

[[notifications.routes]]
event_kind = \"EscalationApproved\"
channels   = [\"shell\"]

[[notifications.routes]]
event_kind = \"TaskStateChanged\"
channels   = []
");
        let bundle = write_and_load(&toml).expect("must load");

        // Implicit shell + audit-mirror = 2 channels.
        assert_eq!(bundle.notification_channels().len(), 2);

        // Routes are accessible.
        let submitted = bundle.notification_route("EscalationSubmitted").unwrap();
        assert_eq!(submitted, &["shell".to_owned(), "audit-mirror".to_owned()]);
        let approved = bundle.notification_route("EscalationApproved").unwrap();
        assert_eq!(approved, &["shell".to_owned()]);
        let task = bundle.notification_route("TaskStateChanged").unwrap();
        assert!(task.is_empty(), "silenced");

        // No explicit route for EscalationDenied → caller uses defaults.
        assert!(bundle.notification_route("EscalationDenied").is_none());
    }

    // ── KNOWN_AUDIT_EVENT_KINDS drift guard ──────────────────────────

    /// Cross-check `KNOWN_AUDIT_EVENT_KINDS` against the live
    /// `AuditEventKind::as_str` enumeration. Any kind we add to the
    /// audit crate without also adding it here would silently allow
    /// typo-bypass — pin both lists with the same fixture.
    #[test]
    fn known_event_kinds_list_is_in_lockstep_with_audit_crate() {
        // Hand-built list of every variant the audit crate's
        // `as_str()` returns. We can't reflect this at runtime
        // (Rust does not expose enum variants) so the contract is
        // "every variant must appear in BOTH places". A new kind
        // added to AuditEventKind will fail this test until the
        // policy crate's KNOWN_AUDIT_EVENT_KINDS is updated.
        use raxis_audit_tools::AuditEventKind;
        let probes: Vec<&'static str> = vec![
            AuditEventKind::KernelStarted { data_dir: "x".into(), policy_epoch: 0, schema_version: 0 }.as_str(),
            AuditEventKind::KernelStopped { reason: "x".into() }.as_str(),
            AuditEventKind::IsolationSubstrateSelected { backend_id: "x".into(), tier: "x".into(), fallback_bypass: false }.as_str(),
            AuditEventKind::IsolationFallbackBypass { reason: "x".into(), backend_id: "x".into() }.as_str(),
            AuditEventKind::InitiativeCreated { initiative_id: "x".into(), plan_hash: "x".into(), signed_by: "x".into(), signed_at: 0 }.as_str(),
            AuditEventKind::PlanApproved { initiative_id: "x".into(), task_count: 0 }.as_str(),
            AuditEventKind::PlanRejected { initiative_id: "x".into() }.as_str(),
            AuditEventKind::PathScopeOverrideApplied { initiative_id: "x".into(), task_id: "x".into(), approving_operator: "x".into(), approving_operator_display_name: None }.as_str(),
            AuditEventKind::InitiativeStateChanged { initiative_id: "x".into(), from_state: "x".into(), to_state: "x".into() }.as_str(),
            AuditEventKind::InitiativeAborted { initiative_id: "x".into(), triggered_by_operator: None, triggered_by_operator_display_name: None }.as_str(),
            AuditEventKind::TaskAdmitted { task_id: "x".into(), initiative_id: "x".into(), lane_id: "x".into() }.as_str(),
            AuditEventKind::TaskStateChanged { task_id: "x".into(), from_state: "x".into(), to_state: "x".into(), actor: "x".into(), policy_epoch: 0 }.as_str(),
            AuditEventKind::IntentAccepted { task_id: "x".into(), session_id: "x".into(), intent_kind: "x".into(), base_sha: None, head_sha: None, sequence_number: 0, remaining_units: 0 }.as_str(),
            AuditEventKind::IntentRejected { task_id: "x".into(), session_id: "x".into(), intent_kind: "x".into(), error_code: "x".into(), sequence_number: 0 }.as_str(),
            AuditEventKind::IntegrationMergeCompleted { initiative_id: "x".into(), session_id: "x".into(), commit_sha: "x".into(), previous_sha: "x".into(), operator_assisted: false, escalation_id: None }.as_str(),
            AuditEventKind::SessionCreated { session_id: "x".into(), role: "x".into(), lineage_id: "x".into(), worktree_root: None, initiative_id: None, plan_bundle_sha256: None, policy_epoch: None, session_agent_type: None }.as_str(),
            AuditEventKind::SessionRevoked { session_id: "x".into(), revoked_by: "x".into(), revoked_by_display_name: None }.as_str(),
            AuditEventKind::DelegationGranted { delegation_id: "x".into(), session_id: "x".into(), capability_class: "x".into(), expires_at: 0, granted_by: "x".into(), granted_by_display_name: None }.as_str(),
            AuditEventKind::DelegationMarkedStale { delegation_id: "x".into(), session_id: "x".into(), capability_class: "x".into(), reason: "x".into() }.as_str(),
            AuditEventKind::WitnessAccepted { verifier_run_id: "x".into(), task_id: "x".into(), gate_type: "x".into(), result_class: "x".into(), evaluation_sha: "x".into() }.as_str(),
            AuditEventKind::WitnessRejected { verifier_run_id: "x".into(), task_id: "x".into(), reason: "x".into() }.as_str(),
            AuditEventKind::VerifierProcessFailed { task_id: "x".into(), exit_code: None, gate_type: "x".into() }.as_str(),
            AuditEventKind::EscalationSubmitted { escalation_id: "x".into(), task_id: "x".into(), class: "x".into(), lineage_id: "x".into() }.as_str(),
            AuditEventKind::EscalationApproved { escalation_id: "x".into(), approved_by: "x".into(), approved_by_display_name: None }.as_str(),
            AuditEventKind::EscalationDenied { escalation_id: "x".into(), denied_by: "x".into(), reason: None, denied_by_display_name: None }.as_str(),
            AuditEventKind::EscalationTimedOut { escalation_id: "x".into() }.as_str(),
            AuditEventKind::EscalationConsumed { escalation_id: "x".into(), approval_token_id: "x".into(), action_hash: "x".into(), policy_epoch: 0 }.as_str(),
            AuditEventKind::LineageQuarantined { lineage_id: "x".into(), trigger_count: 0 }.as_str(),
            AuditEventKind::EscalationRateLimitExceeded { lineage_id: "x".into(), attempted_count: 0, window_start: 0 }.as_str(),
            AuditEventKind::PolicyEpochAdvanced { new_epoch_id: 0, policy_sha256: "x".into(), triggered_by: "x".into(), delegations_marked_stale: 0, sessions_invalidated: 0, triggered_by_display_name: None }.as_str(),
            AuditEventKind::PolicyAdvanceRejected { reason: "x".into(), artifact_epoch: None, current_epoch: 0 }.as_str(),
            AuditEventKind::PolicyAdvanceFailed { reason: "x".into(), new_epoch_id: 0 }.as_str(),
            AuditEventKind::ReplayRejected { session_id: "x".into(), sequence_num: 0, reason: "x".into() }.as_str(),
            AuditEventKind::ReconciliationGap { missing_seq: 0, reconstructed_event: "x".into(), reconstructed: false }.as_str(),
            AuditEventKind::TaskBlockedForRecovery { task_id: "x".into(), block_reason: "x".into() }.as_str(),
            AuditEventKind::DelegationSignatureUnverifiable { delegation_id: "x".into(), expected_signer_unknown_in_current_policy: false }.as_str(),
            AuditEventKind::GatewaySpawned { token_prefix: "x".into(), binary_path: "x".into(), attempt: 0 }.as_str(),
            AuditEventKind::GatewayCrashed { token_prefix: "x".into(), exit_code: None, attempt: 0 }.as_str(),
            AuditEventKind::GatewayQuarantined { reason: "x".into(), total_attempts: 0 }.as_str(),
            AuditEventKind::GatewaySignalFailed { signal: "x".into(), new_epoch_id: None, reason: "x".into() }.as_str(),
            AuditEventKind::NotificationDeliveryFailed { channel_id: "x".into(), event_kind: "x".into(), reason: "x".into() }.as_str(),
            AuditEventKind::OperatorCertInstalled { pubkey_fingerprint: "x".into(), epoch_id: 0, cert_kind: "x".into(), display_name: "x".into(), not_before: 0, not_after: 0, permitted_ops: vec![], force_misconfig_bypass: false, previous_fingerprint: None }.as_str(),
            AuditEventKind::OperatorCertMisconfigBypassed { pubkey_fingerprint: "x".into(), epoch_id: 0, cert_kind: "x".into(), display_name: "x".into(), violations: vec![] }.as_str(),
            AuditEventKind::OperatorCertExpiringSoon { pubkey_fingerprint: "x".into(), epoch_id: 0, op: "x".into(), not_after: 0, days_remaining: 0 }.as_str(),
            AuditEventKind::OperatorCertInGracePeriod { pubkey_fingerprint: "x".into(), epoch_id: 0, op: "x".into(), not_after: 0, grace_ends_at: 0 }.as_str(),
            AuditEventKind::OperatorCertExpiredOpDenied { pubkey_fingerprint: "x".into(), epoch_id: 0, op: "x".into(), not_after: 0, expired_at: 0 }.as_str(),
            AuditEventKind::EmergencyOperatorUsed { pubkey_fingerprint: "x".into(), epoch_id: 0, op: "x".into() }.as_str(),
            AuditEventKind::PathReadAccessed { actor: "x".into(), table: "x".into(), column: "x".into(), task_id: "x".into(), command: "x".into() }.as_str(),
            AuditEventKind::InitiativeQuarantined { initiative_id: "x".into(), quarantined_by: "x".into(), reason: None, quarantined_by_display_name: None }.as_str(),
            AuditEventKind::OperatorQuarantineSwept { target_fingerprint: "x".into(), quarantined_by: "x".into(), count: 0, reason: None, quarantined_by_display_name: None, target_display_name: None }.as_str(),
            // V2 isolation-substrate refusal at boot. Single-class
            // observability event (no SQLite row mutates); listed in
            // `audit-paired-writes.md §4.3` single-class roster.
            AuditEventKind::IsolationSubstrateRefused { reason: "x".into() }.as_str(),
            // V2 per-session VM lifecycle. Paired class — every
            // SessionVmSpawned must be matched by a SessionVmExited
            // somewhere in the chain (`audit-paired-writes.md §4.1`).
            AuditEventKind::SessionVmSpawned {
                session_id:         "x".into(),
                task_id:            None,
                initiative_id:      "x".into(),
                backend_id:         "x".into(),
                egress_tier:        "x".into(),
                admission_loopback: "x".into(),
                credential_proxies: 0,
            }.as_str(),
            AuditEventKind::SessionVmExited {
                session_id:    "x".into(),
                signal_class:  "x".into(),
                exit_code:     0,
                backend_error: None,
            }.as_str(),
        ];

        let policy_kinds: std::collections::HashSet<&str> =
            KNOWN_AUDIT_EVENT_KINDS.iter().copied().collect();
        for k in &probes {
            assert!(policy_kinds.contains(*k),
                "AuditEventKind::{k} is missing from KNOWN_AUDIT_EVENT_KINDS \
                 in policy/src/bundle.rs — operator routes for that kind would \
                 be silently rejected. Add it to the const array.");
        }
        // Reverse direction: every entry in KNOWN_AUDIT_EVENT_KINDS must be a real
        // variant. The probe list above is exhaustive, so any extra entry would
        // be unreachable. Pinning the cardinality keeps drift loud.
        assert_eq!(probes.len(), KNOWN_AUDIT_EVENT_KINDS.len(),
            "KNOWN_AUDIT_EVENT_KINDS has {} entries but probe list has {}; \
             the two lists must be in 1:1 correspondence (cli-readonly.md §5.6.2)",
            KNOWN_AUDIT_EVENT_KINDS.len(), probes.len());
    }
}

// ---------------------------------------------------------------------------
// Tests — `validate_operator_certs` cert-flow validation.
// ---------------------------------------------------------------------------
//
// Covers the three branches of the cert validation logic:
//
//   1. **Hard failures (NEVER bypassable):**
//      - FingerprintMismatch (entry pubkey_hex vs declared fingerprint)
//      - CertPubkeyMismatch (entry pubkey_hex vs cert pubkey_hex)
//      - CertValidation on signature failure
//
//   2. **Soft failures (bypassable with `force_misconfig_bypass = true`):**
//      - Structural invariants from raxis-crypto::validate_cert_structurally
//      - Bypass produces a `BypassedCertMisconfig` entry, audit-bound at boot
//
//   3. **Structural pinning:**
//      - EmergencyRecovery cert with `permitted_ops = ["X", "Y"]` MUST end up
//        with `permitted_ops = ["RotateEpoch"]` at the entry level after
//        validation, regardless of the bypass path
//
//   4. **Cert is mandatory (INV-CERT-01):** a TOML missing
//      `[operators.entries.cert]` fails to deserialise — the cert-less
//      "legacy" path was removed deliberately so cert-bound auth is
//      enforced at the type level rather than at runtime.

#[cfg(test)]
mod cert_validation_tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use raxis_crypto::cert::sign_cert;
    use raxis_test_support::{ephemeral_signing_key, ephemeral_cert_with_key, pubkey_hex, CertOpts};
    use raxis_types::operator_cert::{CertKind, OperatorCert};

    // Deterministic seed → same pubkey + signatures across test runs.
    const TEST_SEED: [u8; 32] = [0x42u8; 32];

    fn test_signing_key() -> SigningKey { ephemeral_signing_key(TEST_SEED) }

    fn test_pubkey_hex() -> String { pubkey_hex(&test_signing_key()) }

    fn test_fingerprint() -> String {
        use sha2::{Digest, Sha256};
        let raw = hex::decode(test_pubkey_hex()).unwrap();
        let mut h = Sha256::new();
        h.update(&raw);
        hex::encode(&h.finalize()[..16])
    }

    fn signed_standard_cert(now: i64, perms: Vec<&str>) -> OperatorCert {
        ephemeral_cert_with_key(
            &test_signing_key(),
            CertOpts {
                kind:                    CertKind::Standard,
                display_name:            "Chika".to_owned(),
                now_unix_secs:           now,
                warn_before_expiry_days: 30,
                grace_period_days:       7,
                permitted_ops:           perms.into_iter().map(str::to_owned).collect(),
                contact_info:            None,
            },
        )
    }

    fn signed_emergency_cert(perms: Vec<&str>) -> OperatorCert {
        // The helper auto-pins emergency permitted_ops to ["RotateEpoch"]
        // (ephemeral_cert_with_opts contract). To exercise the misconfig
        // path with extra ops, we mint via the helper then mutate +
        // re-sign so the test fixture matches what an operator-typed
        // misconfigured TOML would produce.
        let mut c = ephemeral_cert_with_key(
            &test_signing_key(),
            CertOpts {
                kind:         CertKind::EmergencyRecovery,
                display_name: "break-glass".to_owned(),
                ..CertOpts::default()
            },
        );
        let owned: Vec<String> = perms.into_iter().map(str::to_owned).collect();
        if owned != c.permitted_ops {
            c.permitted_ops = owned;
            c.self_sig_hex = sign_cert(&c, &test_signing_key());
        }
        c
    }

    fn entry_with_cert(cert: OperatorCert, force_bypass: bool) -> OperatorEntry {
        OperatorEntry {
            pubkey_fingerprint:    test_fingerprint(),
            display_name:          "Chika".to_owned(),
            pubkey_hex:            test_pubkey_hex(),
            permitted_ops:         vec!["CreateInitiative".to_owned()],
            cert,
            force_misconfig_bypass: force_bypass,
        }
    }

    // ── Cert is mandatory (INV-CERT-01) ───────────────────────────────

    #[test]
    fn policy_toml_missing_cert_block_fails_to_deserialise() {
        // The cert-mandatory invariant is enforced at the *type* level:
        // serde rejects a TOML that omits the `[operators.entries.cert]`
        // sub-table because OperatorEntry::cert is non-Option. There is
        // no runtime cert-less branch the operator can fall into.
        let toml_text = format!(
            r#"[meta]
epoch     = 1
signed_by = "{fp}"
signed_at = 1700000000

[authority]
authority_pubkey = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
quality_pubkey   = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

[escalation_policy]
timeout_secs         = 3600
window_secs          = 300
max_per_window       = 5
quarantine_threshold = 3

[sessions]
default_ttl_secs       = 86400
max_ttl_secs           = 604800
allowed_worktree_roots = ["/tmp/raxis-no-cert"]

[delegations]
max_ttl_secs = 86400

[budget]
[budget.base_cost_per_intent_kind]
SingleCommit = 10

[[operators.entries]]
pubkey_fingerprint = "{fp}"
display_name       = "Chika"
pubkey_hex         = "{pk}"
permitted_ops      = ["CreateInitiative"]
"#,
            fp = test_fingerprint(),
            pk = test_pubkey_hex(),
        );

        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), &toml_text).unwrap();
        let err = crate::load_policy(tmp.path())
            .expect_err("policy.toml without [operators.entries.cert] MUST fail to load");
        let s = format!("{err}");
        // The exact serde error wording isn't pinned, but the absence
        // must be visible in the failure message — operators have to
        // be able to grep for it.
        assert!(
            s.contains("cert") || s.contains("missing") || s.contains("MalformedArtifact"),
            "expected a failure that names the missing cert; got: {s}"
        );
    }

    // ── Cert-bound happy path ─────────────────────────────────────────

    #[test]
    fn well_formed_standard_cert_passes_and_overrides_entry_permitted_ops() {
        let cert = signed_standard_cert(1_700_000_000, vec!["AbortTask", "ApprovePlan"]);
        let mut entries = vec![entry_with_cert(cert, false)];
        let bypassed = validate_operator_certs(&mut entries).unwrap();
        assert!(bypassed.is_empty());
        // Cert is the authority for permitted_ops — entry-level field is
        // overridden during validation so downstream lookups are consistent.
        assert_eq!(
            entries[0].permitted_ops,
            vec!["AbortTask".to_owned(), "ApprovePlan".to_owned()],
            "entry.permitted_ops must mirror cert.permitted_ops"
        );
    }

    #[test]
    fn well_formed_emergency_cert_passes_and_pins_permitted_ops_to_rotate_epoch() {
        let cert = signed_emergency_cert(vec!["RotateEpoch"]);
        let mut entries = vec![entry_with_cert(cert, false)];
        let bypassed = validate_operator_certs(&mut entries).unwrap();
        assert!(bypassed.is_empty(), "emergency cert with correct ops should not bypass");
        assert_eq!(entries[0].permitted_ops, vec!["RotateEpoch".to_owned()]);
        assert_eq!(
            entries[0].cert.permitted_ops,
            vec!["RotateEpoch".to_owned()],
        );
    }

    // ── Hard failures (NEVER bypassable) ──────────────────────────────

    /// Fingerprint mismatch: entry's pubkey_fingerprint does not equal
    /// SHA-256[:16] of pubkey_hex. NEVER bypassable.
    #[test]
    fn fingerprint_mismatch_is_a_hard_failure() {
        let mut entry = entry_with_cert(
            signed_standard_cert(1_700_000_000, vec!["CreateInitiative"]),
            true, // force_bypass MUST NOT save us — this is a hard failure
        );
        entry.pubkey_fingerprint = "0".repeat(32);
        let mut entries = vec![entry];
        let err = validate_operator_certs(&mut entries).expect_err("must fail");
        assert!(
            matches!(err, PolicyError::FingerprintMismatch { .. }),
            "expected FingerprintMismatch, got: {err:?}"
        );
    }

    /// Cert pubkey ≠ entry pubkey: the entry and the cert must agree on
    /// the operator identity. NEVER bypassable.
    #[test]
    fn cert_pubkey_mismatch_is_a_hard_failure() {
        let mut cert = signed_standard_cert(1_700_000_000, vec!["CreateInitiative"]);
        cert.pubkey_hex = "ee".repeat(32);
        // Re-sign so we don't ALSO trip on signature verification.
        cert.self_sig_hex = sign_cert(&cert, &test_signing_key());
        // The cert is now signed by THIS key but advertises a DIFFERENT
        // pubkey — the self-sig will fail first. To isolate the
        // pubkey-mismatch path we'd need a cert signed by a different
        // key; we test the signature path separately. Here we expect
        // EITHER PolicyError::CertValidation (sig fail) or
        // PolicyError::CertPubkeyMismatch — both are hard failures.
        let mut entries = vec![entry_with_cert(cert, true)];
        let err = validate_operator_certs(&mut entries).expect_err("must fail");
        assert!(
            matches!(
                err,
                PolicyError::CertValidation { .. } | PolicyError::CertPubkeyMismatch { .. }
            ),
            "expected hard cert failure, got: {err:?}"
        );
    }

    /// Forged cert (signed by a DIFFERENT private key than the one the
    /// cert advertises) is REJECTED even with the bypass flag.
    #[test]
    fn forged_self_signature_is_a_hard_failure_even_with_bypass() {
        let mut cert = signed_standard_cert(1_700_000_000, vec!["CreateInitiative"]);
        let imposter = SigningKey::from_bytes(&[0xCDu8; 32]);
        cert.self_sig_hex = sign_cert(&cert, &imposter);
        let mut entries = vec![entry_with_cert(cert, true)];
        let err = validate_operator_certs(&mut entries).expect_err("must fail");
        assert!(
            matches!(err, PolicyError::CertValidation { .. }),
            "forged sig must produce CertValidation, got: {err:?}"
        );
        // The error message must mention self-signature so the
        // operator can debug.
        let s = format!("{err}");
        assert!(s.to_lowercase().contains("self-sig") || s.contains("signature"),
            "error must describe signature failure; got: {s}");
    }

    // ── Soft failures: bypass path ────────────────────────────────────

    #[test]
    fn structural_misconfig_without_bypass_is_rejected() {
        // EmergencyRecovery cert with extra ops = misconfig.
        let cert = signed_emergency_cert(vec!["RotateEpoch", "AbortInitiative"]);
        let mut entries = vec![entry_with_cert(cert, false)];
        let err = validate_operator_certs(&mut entries).expect_err("must fail");
        let s = format!("{err}");
        assert!(matches!(err, PolicyError::CertValidation { .. }));
        assert!(s.contains("EmergencyRecovery") || s.contains("RotateEpoch"),
            "error must explain WHICH structural rule was violated; got: {s}");
    }

    #[test]
    fn structural_misconfig_with_bypass_is_recorded_for_audit_and_pinned() {
        let cert = signed_emergency_cert(vec!["RotateEpoch", "AbortInitiative"]);
        let mut entries = vec![entry_with_cert(cert, true)];
        let bypassed = validate_operator_certs(&mut entries).unwrap();
        assert_eq!(bypassed.len(), 1, "bypass must produce exactly one audit record");

        let bp = &bypassed[0];
        assert_eq!(bp.operator_fingerprint, test_fingerprint());
        assert_eq!(bp.display_name, "Chika");
        assert_eq!(bp.kind, CertKind::EmergencyRecovery);
        assert!(!bp.violations.is_empty(),
            "violations list must be non-empty (operator sees what they bypassed)");
        // The violation strings must include the full Display message.
        let joined = bp.violations.join("\n");
        assert!(joined.contains("EmergencyRecovery") || joined.contains("RotateEpoch"),
            "violation Display strings must be preserved verbatim; got:\n{joined}");

        // Crucially: structural pinning still happened. The kernel
        // ENFORCES emergency_cert.permitted_ops = ["RotateEpoch"] even
        // when the operator bypassed the misconfig check — bypass means
        // "I accept the audit", not "I get to widen the blast radius".
        assert_eq!(entries[0].permitted_ops, vec!["RotateEpoch".to_owned()]);
        assert_eq!(
            entries[0].cert.permitted_ops,
            vec!["RotateEpoch".to_owned()],
            "cert in-memory must reflect the structurally pinned op set",
        );
    }

    #[test]
    fn standard_cert_with_inverted_validity_window_without_bypass_is_rejected() {
        let mut cert = signed_standard_cert(1_700_000_000, vec!["CreateInitiative"]);
        cert.not_before = cert.not_after + 1;
        cert.self_sig_hex = sign_cert(&cert, &test_signing_key());
        let mut entries = vec![entry_with_cert(cert, false)];
        let err = validate_operator_certs(&mut entries).expect_err("must fail");
        let s = format!("{err}");
        assert!(matches!(err, PolicyError::CertValidation { .. }));
        assert!(s.contains("not_before") || s.contains("InvertedValidityWindow") ||
                s.contains("not_after"),
            "error must mention the inverted-window violation; got: {s}");
    }

    #[test]
    fn standard_cert_with_inverted_validity_window_with_bypass_succeeds() {
        let mut cert = signed_standard_cert(1_700_000_000, vec!["CreateInitiative"]);
        cert.not_before = cert.not_after + 1;
        cert.self_sig_hex = sign_cert(&cert, &test_signing_key());
        let mut entries = vec![entry_with_cert(cert, true)];
        let bypassed = validate_operator_certs(&mut entries).unwrap();
        assert_eq!(bypassed.len(), 1);
        assert_eq!(bypassed[0].kind, CertKind::Standard);
    }

    // ── PolicyBundle integration: end-to-end TOML round-trip ──────────

    #[test]
    fn policy_with_cert_bound_operator_loads_and_overrides_entry_permitted_ops() {
        // Build a policy.toml with the operator cert embedded inline.
        // The cert TOML is generated by serialising a freshly-signed
        // cert and inlining it under the operator entry.
        let cert = signed_standard_cert(1_700_000_000, vec!["CreateInitiative"]);
        let cert_toml = toml::to_string(&cert).unwrap();
        let cert_subtable = cert_toml
            .lines()
            .map(|l| l.to_owned())
            .collect::<Vec<_>>()
            .join("\n");

        let toml_text = format!(
            r#"[meta]
epoch     = 1
signed_by = "{fp}"
signed_at = 1700000000

[authority]
authority_pubkey = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
quality_pubkey   = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

[escalation_policy]
timeout_secs         = 3600
window_secs          = 300
max_per_window       = 5
quarantine_threshold = 3

[sessions]
default_ttl_secs       = 86400
max_ttl_secs           = 604800
allowed_worktree_roots = ["/tmp/raxis-cert-test"]

[delegations]
max_ttl_secs = 86400

[budget]
[budget.base_cost_per_intent_kind]
SingleCommit = 10

[[operators.entries]]
pubkey_fingerprint = "{fp}"
display_name       = "Chika"
pubkey_hex         = "{pk}"
permitted_ops      = ["AbortTask"]   # ignored — cert is the authority

[operators.entries.cert]
{cert_subtable}
"#,
            fp = test_fingerprint(),
            pk = test_pubkey_hex(),
            cert_subtable = cert_subtable,
        );

        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), &toml_text).unwrap();
        let bundle = crate::load_policy(tmp.path())
            .expect("cert-bound policy must load")
            .0;

        assert!(bundle.bypassed_cert_misconfigs().is_empty());

        // Cert overrides entry-level permitted_ops.
        let op = &bundle.operators()[0];
        assert_eq!(op.permitted_ops, vec!["CreateInitiative".to_owned()],
            "cert-driven permitted_ops must be installed (entry's AbortTask discarded)");
        assert_eq!(op.cert.pubkey_hex, test_pubkey_hex(),
            "cert pubkey must round-trip through TOML intact");
    }
}

// ---------------------------------------------------------------------------
// Pre-merge verifier validator tests (V2 — operator surface only).
//
// Step 1 of the pre-merge-verifier track: the typed config has landed
// in PolicyBundle. These tests pin every rule the operator-side
// validator enforces TODAY (cross-spec checks — vm_image resolution,
// host-capacity timeout cap, environment-label resolution, plan-side
// task_id intersection — land in Step 2 / Step 4).
// ---------------------------------------------------------------------------
#[cfg(test)]
mod integration_merge_verifiers_tests {
    use super::*;

    fn entry(name: &str) -> IntegrationMergeVerifierEntry {
        IntegrationMergeVerifierEntry {
            name:                       name.to_owned(),
            image:                      "operator/deploy-smoke@sha256:aaaa".to_owned(),
            command:                    "./scripts/smoke.sh".to_owned(),
            timeout:                    "10m".to_owned(),
            on_failure:                 IntegrationMergeVerifierOnFailure::BlockMerge,
            applies_to:                 IntegrationMergeVerifierAppliesTo::All,
            task_set:                   Vec::new(),
            artifact:                   None,
            artifact_max_bytes:         None,
            env:                        HashMap::new(),
            allowed_egress:             Vec::new(),
            required_for_environments:  None,
        }
    }

    /// Empty operator surface is the typical default — must validate.
    #[test]
    fn empty_section_is_valid() {
        validate_integration_merge_verifiers_operator_side(&[])
            .expect("empty section must be valid");
    }

    /// Happy path — single canonical entry passes.
    #[test]
    fn single_entry_with_canonical_fields_is_valid() {
        let entries = vec![entry("production_deploy_smoke")];
        validate_integration_merge_verifiers_operator_side(&entries)
            .expect("single canonical entry must validate");
    }

    /// Names must match `[a-z][a-z0-9_]{0,31}`.
    #[test]
    fn name_with_uppercase_is_rejected() {
        let entries = vec![entry("Bad_Name")];
        let err = validate_integration_merge_verifiers_operator_side(&entries)
            .expect_err("uppercase name must be rejected");
        let msg = format!("{err}");
        assert!(msg.contains("FAIL_POLICY_INTEGRATION_MERGE_VERIFIER_NAME_INVALID"),
            "diagnostic must surface the failure code, got: {msg}");
    }

    #[test]
    fn name_starting_with_digit_is_rejected() {
        let entries = vec![entry("9foo")];
        let err = validate_integration_merge_verifiers_operator_side(&entries)
            .expect_err("digit-leading name must be rejected");
        assert!(format!("{err}").contains("FAIL_POLICY_INTEGRATION_MERGE_VERIFIER_NAME_INVALID"));
    }

    #[test]
    fn empty_name_is_rejected() {
        let entries = vec![entry("")];
        let err = validate_integration_merge_verifiers_operator_side(&entries)
            .expect_err("empty name must be rejected");
        assert!(format!("{err}").contains("FAIL_POLICY_INTEGRATION_MERGE_VERIFIER_NAME_INVALID"));
    }

    #[test]
    fn duplicate_names_within_section_are_rejected() {
        let entries = vec![entry("smoke"), entry("smoke")];
        let err = validate_integration_merge_verifiers_operator_side(&entries)
            .expect_err("duplicate name must be rejected");
        assert!(format!("{err}").contains("FAIL_POLICY_INTEGRATION_MERGE_VERIFIER_NAME_COLLISION"));
    }

    #[test]
    fn empty_image_is_rejected() {
        let mut e = entry("smoke");
        e.image = "  ".to_owned();
        let err = validate_integration_merge_verifiers_operator_side(&[e])
            .expect_err("blank image must be rejected");
        assert!(format!("{err}").contains("FAIL_POLICY_INTEGRATION_MERGE_VERIFIER_IMAGE_REQUIRED"));
    }

    #[test]
    fn empty_command_is_rejected() {
        let mut e = entry("smoke");
        e.command = String::new();
        let err = validate_integration_merge_verifiers_operator_side(&[e])
            .expect_err("blank command must be rejected");
        assert!(format!("{err}").contains("FAIL_POLICY_INTEGRATION_MERGE_VERIFIER_COMMAND_REQUIRED"));
    }

    /// Operator surface MUST NOT downgrade to `warn_only`.
    #[test]
    fn warn_only_on_failure_is_rejected_on_operator_surface() {
        let mut e = entry("smoke");
        e.on_failure = IntegrationMergeVerifierOnFailure::WarnOnly;
        let err = validate_integration_merge_verifiers_operator_side(&[e])
            .expect_err("warn_only must be rejected on operator surface");
        assert!(format!("{err}").contains("FAIL_VERIFIER_INVALID_ON_FAILURE"),
            "must surface the canonical FAIL_VERIFIER_INVALID_ON_FAILURE code");
    }

    /// `applies_to = "task_set"` requires a non-empty `task_set`.
    #[test]
    fn task_set_applies_with_empty_task_set_is_rejected() {
        let mut e = entry("smoke");
        e.applies_to = IntegrationMergeVerifierAppliesTo::TaskSet;
        e.task_set   = Vec::new();
        let err = validate_integration_merge_verifiers_operator_side(&[e])
            .expect_err("empty task_set must be rejected");
        assert!(format!("{err}").contains("FAIL_VERIFIER_TASK_SET_EMPTY"));
    }

    /// `applies_to = "all"` MUST NOT carry a populated `task_set`.
    #[test]
    fn all_applies_with_populated_task_set_is_rejected() {
        let mut e = entry("smoke");
        e.applies_to = IntegrationMergeVerifierAppliesTo::All;
        e.task_set   = vec!["task-a".to_owned()];
        let err = validate_integration_merge_verifiers_operator_side(&[e])
            .expect_err("populated task_set with applies_to=all must be rejected");
        assert!(format!("{err})").contains("INTEGRATION_MERGE_VERIFIER_TASK_SET_INCONSISTENT")
            || format!("{err}").contains("INTEGRATION_MERGE_VERIFIER_TASK_SET_INCONSISTENT"));
    }

    /// Timeout strings must be parseable into the `Ns|Nm|Nh` shape.
    #[test]
    fn timeout_unparseable_is_rejected() {
        let mut e = entry("smoke");
        e.timeout = "10minutes".to_owned();
        let err = validate_integration_merge_verifiers_operator_side(&[e])
            .expect_err("unparseable timeout must be rejected");
        assert!(format!("{err}").contains("FAIL_POLICY_INTEGRATION_MERGE_VERIFIER_TIMEOUT_INVALID"));
    }

    /// Timeout below 5 seconds is rejected.
    #[test]
    fn timeout_too_short_is_rejected() {
        let mut e = entry("smoke");
        e.timeout = "4s".to_owned();
        let err = validate_integration_merge_verifiers_operator_side(&[e])
            .expect_err("4s timeout must be rejected");
        assert!(format!("{err}").contains("FAIL_POLICY_INTEGRATION_MERGE_VERIFIER_TIMEOUT_TOO_SHORT"));
    }

    /// Timeout exactly at the floor (5s) is accepted.
    #[test]
    fn timeout_at_floor_is_accepted() {
        let mut e = entry("smoke");
        e.timeout = "5s".to_owned();
        validate_integration_merge_verifiers_operator_side(&[e])
            .expect("5s timeout must be accepted");
    }

    /// Artifact paths must start with `/raxis/`.
    #[test]
    fn artifact_path_outside_raxis_is_rejected() {
        let mut e = entry("smoke");
        e.artifact = Some("/var/run/secrets/x".to_owned());
        let err = validate_integration_merge_verifiers_operator_side(&[e])
            .expect_err("non-/raxis artifact path must be rejected");
        assert!(format!("{err}").contains("FAIL_POLICY_INTEGRATION_MERGE_VERIFIER_ARTIFACT_PATH_INVALID"));
    }

    #[test]
    fn artifact_path_too_long_is_rejected() {
        let mut e = entry("smoke");
        e.artifact = Some(format!("/raxis/{}", "x".repeat(VERIFIER_ARTIFACT_MAX_PATH_CHARS)));
        let err = validate_integration_merge_verifiers_operator_side(&[e])
            .expect_err("oversize artifact path must be rejected");
        assert!(format!("{err}").contains("FAIL_POLICY_INTEGRATION_MERGE_VERIFIER_ARTIFACT_PATH_TOO_LONG"));
    }

    #[test]
    fn env_with_raxis_prefix_key_is_rejected() {
        let mut e = entry("smoke");
        e.env.insert("RAXIS_VERIFIER_HOOK_KIND".to_owned(), "spoof".to_owned());
        let err = validate_integration_merge_verifiers_operator_side(&[e])
            .expect_err("RAXIS_-prefixed env key must be rejected");
        assert!(format!("{err}").contains("FAIL_CUSTOM_TOOL_ENV_RESERVED_KEY"));
    }

    #[test]
    fn env_with_too_many_entries_is_rejected() {
        let mut e = entry("smoke");
        for i in 0..(VERIFIER_ENV_MAX_ENTRIES + 1) {
            e.env.insert(format!("KEY_{i}"), "v".to_owned());
        }
        let err = validate_integration_merge_verifiers_operator_side(&[e])
            .expect_err("too many env entries must be rejected");
        assert!(format!("{err}").contains("FAIL_POLICY_INTEGRATION_MERGE_VERIFIER_ENV_TOO_MANY_ENTRIES"));
    }

    #[test]
    fn env_total_size_above_cap_is_rejected() {
        let mut e = entry("smoke");
        e.env.insert("BIG".to_owned(), "x".repeat(VERIFIER_ENV_MAX_TOTAL_BYTES));
        let err = validate_integration_merge_verifiers_operator_side(&[e])
            .expect_err("env total above 16 KiB must be rejected");
        assert!(format!("{err}").contains("FAIL_POLICY_INTEGRATION_MERGE_VERIFIER_ENV_TOO_LARGE"));
    }

    #[test]
    fn empty_required_for_environments_is_rejected() {
        let mut e = entry("smoke");
        e.required_for_environments = Some(Vec::new());
        let err = validate_integration_merge_verifiers_operator_side(&[e])
            .expect_err("empty required_for_environments must be rejected");
        assert!(format!("{err}").contains("FAIL_POLICY_INTEGRATION_MERGE_VERIFIER_REQUIRED_ENVS_EMPTY"));
    }

    #[test]
    fn duplicate_required_for_environments_is_rejected() {
        let mut e = entry("smoke");
        e.required_for_environments = Some(vec!["prod".to_owned(), "prod".to_owned()]);
        let err = validate_integration_merge_verifiers_operator_side(&[e])
            .expect_err("duplicate environments entry must be rejected");
        assert!(format!("{err}").contains("FAIL_POLICY_INTEGRATION_MERGE_VERIFIER_REQUIRED_ENVS_DUPLICATE"));
    }

    /// End-to-end TOML round-trip exercising every accepted shape:
    /// applies_to=all (default), applies_to=task_set with task_set
    /// populated, and applies_to=last; required_for_environments
    /// populated.
    #[test]
    fn toml_round_trip_validates_three_canonical_entries() {
        let toml = r#"
[[integration_merge_verifiers]]
name        = "production_deploy_smoke"
image       = "operator/deploy-smoke@sha256:aaaa"
command     = "./scripts/prod_smoke.sh"
timeout     = "20m"
on_failure  = "block_merge"
required_for_environments = ["production"]

[[integration_merge_verifiers]]
name        = "auth_integration"
image       = "operator/auth-it@sha256:bbbb"
command     = "./scripts/auth_smoke.sh"
timeout     = "15m"
on_failure  = "block_merge"
applies_to  = "task_set"
task_set    = ["implement_auth", "implement_session"]

[[integration_merge_verifiers]]
name        = "deploy_smoke_last_only"
image       = "operator/deploy-smoke@sha256:cccc"
command     = "./scripts/deploy_smoke.sh"
timeout     = "10m"
on_failure  = "block_merge"
applies_to  = "last"
"#;
        let parsed: HashMap<String, Vec<IntegrationMergeVerifierEntry>> =
            toml::from_str(toml).expect("toml parse");
        let entries = parsed.get("integration_merge_verifiers")
            .expect("section present");
        assert_eq!(entries.len(), 3);
        validate_integration_merge_verifiers_operator_side(entries)
            .expect("all three canonical entries must validate");

        // Per-entry sanity checks.
        assert_eq!(entries[0].applies_to, IntegrationMergeVerifierAppliesTo::All);
        assert_eq!(
            entries[0].required_for_environments.as_deref(),
            Some(&["production".to_owned()][..]),
        );
        assert_eq!(entries[1].applies_to, IntegrationMergeVerifierAppliesTo::TaskSet);
        assert_eq!(entries[1].task_set,
            vec!["implement_auth".to_owned(), "implement_session".to_owned()]);
        assert_eq!(entries[2].applies_to, IntegrationMergeVerifierAppliesTo::Last);
    }
}

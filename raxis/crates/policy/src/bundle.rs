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
/// display_name       = "Alice"
/// pubkey_hex         = "<64-char hex raw Ed25519 public key>"
/// permitted_ops      = ["CreateInitiative", ...]
/// ```
#[derive(Debug, Deserialize)]
pub(crate) struct OperatorsBlock {
    pub(crate) entries: Vec<OperatorEntry>,
}

/// A single operator entry in `[[operators.entries]]`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct OperatorEntry {
    /// SHA-256[:16] fingerprint of the operator's Ed25519 public key (32 hex chars).
    pub pubkey_fingerprint: String,
    pub display_name: String,
    /// Raw 32-byte Ed25519 public key, hex-encoded (64 hex chars).
    pub pubkey_hex: String,
    /// The subset of operator IPC operations this operator is allowed to invoke.
    /// Canonical v1 set: 13 operations listed in kernel-store.md §2.5.5.
    pub permitted_ops: Vec<String>,
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

        Ok(Self {
            epoch: raw.meta.epoch,
            authority_pubkey_hex: raw.authority.authority_pubkey,
            quality_pubkey_hex: raw.authority.quality_pubkey,
            operators: raw.operators_block.entries,
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
        })
    }

    // ── Epoch ──────────────────────────────────────────────────────────────

    /// Current policy epoch number. Monotonically increasing across all
    /// `policy_epoch_history` rows (kernel-store.md §2.5.1 Table 19).
    pub fn epoch(&self) -> u64 {
        self.epoch
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

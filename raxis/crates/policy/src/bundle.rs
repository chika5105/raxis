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
            gateway: raw.gateway,
            providers: raw.providers,
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

    /// Test-only constructor that builds a minimal bundle whose only
    /// populated field is `operators`. Every other field gets a
    /// zero/empty default. Use this when a unit test only needs
    /// `operator_entry()` lookups (e.g. signature verification on
    /// the operator IPC handlers) and not budgets, lanes, gates, etc.
    ///
    /// Gated on `debug_assertions || cfg(test)` — disappears in
    /// release builds, mirroring the convention used by
    /// `KeyRegistry::stub_for_tests` and the `raxis-test-support`
    /// public surface.
    #[cfg(any(debug_assertions, test))]
    pub fn for_tests_with_operators(operators: Vec<OperatorEntry>) -> Self {
        Self {
            epoch: 0,
            authority_pubkey_hex: String::new(),
            quality_pubkey_hex: String::new(),
            operators,
            gates: Vec::new(),
            lanes: Vec::new(),
            role_ceilings: HashMap::new(),
            escalation_timeout: Duration::from_secs(0),
            escalation_window: Duration::from_secs(0),
            escalation_max_per_window: 0,
            escalation_quarantine_threshold: 0,
            default_session_ttl: Duration::from_secs(0),
            max_session_ttl: Duration::from_secs(0),
            allowed_worktree_roots: Vec::new(),
            max_delegation_ttl: Duration::from_secs(0),
            gateway: None,
            providers: Vec::new(),
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

    // ── Gateway supervisor config ───────────────────────────────────────────

    /// Optional `[gateway]` config. `None` if the policy omits the section
    /// (kernel runs without a gateway subprocess; no inference dispatch).
    pub fn gateway(&self) -> Option<&GatewaySection> {
        self.gateway.as_ref()
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
    fn minimal_policy_toml() -> String {
        r#"[meta]
epoch     = 1
signed_by = "deadbeefdeadbeefdeadbeefdeadbeef"
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
pubkey_fingerprint = "deadbeefdeadbeefdeadbeefdeadbeef"
display_name       = "operator-1"
pubkey_hex         = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
permitted_ops      = ["CreateInitiative"]

[[lanes]]
lane_id              = "default"
max_concurrent_tasks = 4
max_cost_per_epoch   = 10000
priority             = 100
"#.to_owned()
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


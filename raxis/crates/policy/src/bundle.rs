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
    // initiative
    "InitiativeCreated", "PlanApproved", "PlanRejected",
    "PathScopeOverrideApplied", "InitiativeStateChanged", "InitiativeAborted",
    // task
    "TaskAdmitted", "TaskStateChanged",
    // intent
    "IntentAccepted", "IntentRejected",
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
            notification_channels,
            notification_routes,
            default_notification_channels,
            bypassed_cert_misconfigs,
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
            AuditEventKind::InitiativeCreated { initiative_id: "x".into(), plan_hash: "x".into(), signed_by: "x".into(), signed_at: 0 }.as_str(),
            AuditEventKind::PlanApproved { initiative_id: "x".into(), task_count: 0 }.as_str(),
            AuditEventKind::PlanRejected { initiative_id: "x".into() }.as_str(),
            AuditEventKind::PathScopeOverrideApplied { initiative_id: "x".into(), task_id: "x".into(), approving_operator: "x".into() }.as_str(),
            AuditEventKind::InitiativeStateChanged { initiative_id: "x".into(), from_state: "x".into(), to_state: "x".into() }.as_str(),
            AuditEventKind::InitiativeAborted { initiative_id: "x".into(), triggered_by_operator: None }.as_str(),
            AuditEventKind::TaskAdmitted { task_id: "x".into(), initiative_id: "x".into(), lane_id: "x".into() }.as_str(),
            AuditEventKind::TaskStateChanged { task_id: "x".into(), from_state: "x".into(), to_state: "x".into(), actor: "x".into(), policy_epoch: 0 }.as_str(),
            AuditEventKind::IntentAccepted { task_id: "x".into(), session_id: "x".into(), intent_kind: "x".into(), base_sha: None, head_sha: None, sequence_number: 0, remaining_units: 0 }.as_str(),
            AuditEventKind::IntentRejected { task_id: "x".into(), session_id: "x".into(), intent_kind: "x".into(), error_code: "x".into(), sequence_number: 0 }.as_str(),
            AuditEventKind::SessionCreated { session_id: "x".into(), role: "x".into(), lineage_id: "x".into(), worktree_root: None }.as_str(),
            AuditEventKind::SessionRevoked { session_id: "x".into(), revoked_by: "x".into() }.as_str(),
            AuditEventKind::DelegationGranted { delegation_id: "x".into(), session_id: "x".into(), capability_class: "x".into(), expires_at: 0, granted_by: "x".into() }.as_str(),
            AuditEventKind::DelegationMarkedStale { delegation_id: "x".into(), session_id: "x".into(), capability_class: "x".into(), reason: "x".into() }.as_str(),
            AuditEventKind::WitnessAccepted { verifier_run_id: "x".into(), task_id: "x".into(), gate_type: "x".into(), result_class: "x".into(), evaluation_sha: "x".into() }.as_str(),
            AuditEventKind::WitnessRejected { verifier_run_id: "x".into(), task_id: "x".into(), reason: "x".into() }.as_str(),
            AuditEventKind::VerifierProcessFailed { task_id: "x".into(), exit_code: None, gate_type: "x".into() }.as_str(),
            AuditEventKind::EscalationSubmitted { escalation_id: "x".into(), task_id: "x".into(), class: "x".into(), lineage_id: "x".into() }.as_str(),
            AuditEventKind::EscalationApproved { escalation_id: "x".into(), approved_by: "x".into() }.as_str(),
            AuditEventKind::EscalationDenied { escalation_id: "x".into(), denied_by: "x".into(), reason: None }.as_str(),
            AuditEventKind::EscalationTimedOut { escalation_id: "x".into() }.as_str(),
            AuditEventKind::EscalationConsumed { escalation_id: "x".into(), approval_token_id: "x".into(), action_hash: "x".into(), policy_epoch: 0 }.as_str(),
            AuditEventKind::LineageQuarantined { lineage_id: "x".into(), trigger_count: 0 }.as_str(),
            AuditEventKind::EscalationRateLimitExceeded { lineage_id: "x".into(), attempted_count: 0, window_start: 0 }.as_str(),
            AuditEventKind::PolicyEpochAdvanced { new_epoch_id: 0, policy_sha256: "x".into(), triggered_by: "x".into(), delegations_marked_stale: 0, sessions_invalidated: 0 }.as_str(),
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
            AuditEventKind::InitiativeQuarantined { initiative_id: "x".into(), quarantined_by: "x".into(), reason: None }.as_str(),
            AuditEventKind::OperatorQuarantineSwept { target_fingerprint: "x".into(), quarantined_by: "x".into(), count: 0, reason: None }.as_str(),
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
                display_name:            "Alice".to_owned(),
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
            display_name:          "Alice".to_owned(),
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
display_name       = "Alice"
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
        assert_eq!(bp.display_name, "Alice");
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
display_name       = "Alice"
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

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

    /// `[host_capacity]` — V2_GAPS §D2 host-capacity caps and
    /// watchdog config. **Optional**: omitted section means
    /// "kernel uses the spec defaults" (16 concurrent VMs, 5 GiB
    /// disk headroom, 4096 FD floor, halt_admit behavior). The
    /// V2 MVP only enforces a subset of the full
    /// `host-capacity.md` surface; see [`HostCapacityConfig`].
    #[serde(default)]
    pub(crate) host_capacity: Option<HostCapacitySection>,

    /// `[environments.<label>]` — V2_GAPS §E1 environment-binding
    /// declarations per `environment-access-control.md §5b.1`.
    /// **Optional**: omitting the entire `[environments]` table
    /// (zero declared environments) keeps the environment model
    /// inert — no per-task INV-ENV-01 check fires (§1.5.2
    /// activation gate). The map key is the environment label
    /// (validated against `^[a-z][a-z0-9_-]{0,31}$`); the value
    /// carries the per-environment knobs.
    #[serde(default)]
    pub(crate) environments: HashMap<String, EnvironmentSection>,

    /// `[[permitted_credentials]]` — V2_GAPS §E1 policy-side
    /// allowlist of credential names per
    /// `environment-access-control.md §5.2`. Each entry MAY
    /// declare an `environment` label; that label MUST resolve to
    /// a declared `[environments.<label>]`. **Optional**: an
    /// omitted section keeps existing behaviour where credential
    /// names are not pre-declared in policy. When the section IS
    /// present and non-empty, every plan-task credential reference
    /// MUST resolve into it (INV-CRED-01 in V3 — V2 keeps the
    /// existing per-task validation pathway). For V2 the section
    /// is consumed by the INV-ENV-01 binding algorithm only.
    #[serde(default, rename = "permitted_credentials")]
    pub(crate) permitted_credentials: Vec<PermittedCredentialEntry>,

    /// `[[vm_images]]` — V2_GAPS §13 Cat-4 + V2.5 BLOCKER per
    /// `policy-plan-authority.md §4`. Operator-published
    /// declarations of OCI-pinned VM images plan tasks may
    /// reference. **Optional**: an omitted section keeps the
    /// V2.4 behaviour where every Executor activation resolves
    /// to the kernel-bundled `raxis-executor-starter-<v>.img` and
    /// every Reviewer/Orchestrator to its kernel-canonical image.
    /// When the section IS present, plan tasks' `vm_image` field
    /// MUST resolve into it (`FAIL_VM_IMAGE_NOT_REGISTERED`) and
    /// the image's `role_restriction` MUST permit the task's role
    /// (`FAIL_VM_IMAGE_ROLE_RESTRICTION_VIOLATION`).
    ///
    /// V2.5 invariants this section enforces:
    /// * `INV-PLANNER-HARNESS-03` — `kernel_version_min ≥ "5.14"`
    ///   is required (operator-declared; full OCI introspection
    ///   remains a V3 deferral, recorded in V2_GAPS §13).
    /// * `INV-PLANNER-HARNESS-02` — Reviewer images cannot be
    ///   operator-published; any entry with `role_restriction`
    ///   containing `"Reviewer"` is rejected at policy load with
    ///   `FAIL_REVIEWER_VM_IMAGE_NOT_ALLOWED`.
    /// * `INV-PLANNER-HARNESS-05` — Orchestrator images cannot
    ///   be operator-published; same rejection shape under
    ///   `FAIL_ORCHESTRATOR_VM_IMAGE_NOT_ALLOWED`.
    /// * `INV-VERIFIER-12` — the alias `"raxis-verifier-symbol-index"`
    ///   is reserved for the kernel-canonical symbol-index image
    ///   and rejected at policy load with
    ///   `FAIL_POLICY_RESERVED_VM_IMAGE_NAME`.
    #[serde(default, rename = "vm_images")]
    pub(crate) vm_images: Vec<VmImageEntry>,

    /// `[default_executor_image]` — V2.5 per `operator-ergonomics.md
    /// §3 D1`. When present, `alias` is the `[[vm_images]]` name
    /// the kernel uses as the implicit executor image for any
    /// `[[tasks]]` whose `vm_image` field is omitted (the operator-
    /// ergonomics defaulting target). **Optional**: an omitted
    /// section keeps the V2.4 hardcoded fallback to
    /// `raxis-executor-starter-<v>.img`. The `alias` MUST resolve
    /// to a `[[vm_images]]` entry whose `role_restriction`
    /// includes `"Executor"`; mismatch surfaces
    /// `FAIL_POLICY_DEFAULT_EXECUTOR_IMAGE_UNRESOLVABLE` at
    /// policy load.
    #[serde(default, rename = "default_executor_image")]
    pub(crate) default_executor_image: Option<DefaultExecutorImageSection>,
}

/// `[environments.<label>]` — operator-declared environment
/// definition per `environment-access-control.md §5b`. V2 honours
/// `description` (required) and `same_cluster_acknowledged`
/// (default `false`); the §5b.4 reserved fields parse into
/// `_reserved` and are tolerated as no-op. The kernel emits a
/// single audit-trail warning at policy load if any reserved
/// field is set (handled in `validate_environments`).
#[derive(Debug, Clone, Deserialize, Default)]
pub(crate) struct EnvironmentSection {
    /// Required. Human-readable description; surfaced in
    /// `raxis-cli plan explain` and audit-log inspectors.
    #[serde(default)]
    pub(crate) description: Option<String>,

    /// Operator opt-in for the same-cluster/same-host conflation
    /// scenario (`environment-access-control.md §11.4`). When
    /// `true`, URL gates whose conflation involves THIS
    /// environment do not contribute environment labels to the
    /// per-task consistency check. Default `false`. V2 MVP parses
    /// the field but the URL-gate runtime path itself is V3 (only
    /// the per-task credential coherence check fires in V2).
    #[serde(default)]
    pub(crate) same_cluster_acknowledged: bool,

    /// V2.x reserved fields per §5b.4. Captured as raw TOML so
    /// the policy parser tolerates their presence and the
    /// validator can emit a single warning per occurrence.
    #[serde(flatten)]
    pub(crate) extras: HashMap<String, toml::Value>,
}

/// `[[permitted_credentials]]` — single allowlist entry for a
/// policy-permitted credential name. V2 honours the `name`
/// (required) and `environment` (optional, must resolve to a
/// declared `[environments.<label>]` when non-empty) fields.
/// `description` is parsed for forward-compat surfacing in
/// `raxis-cli plan explain` and audit-log inspectors.
#[derive(Debug, Clone, Deserialize, Default)]
pub(crate) struct PermittedCredentialEntry {
    /// Required. Credential name (matches the file under
    /// `<data_dir>/credentials/<name>.env`).
    pub(crate) name: String,

    /// Optional environment binding. Empty/absent means the
    /// credential is **neutral** (`environment-access-control.md
    /// §1.5.4`) and contributes nothing to the per-task
    /// environment set.
    #[serde(default)]
    pub(crate) environment: Option<String>,

    /// Optional human-readable description (forward-compat).
    #[serde(default)]
    pub(crate) description: Option<String>,
}

/// `[[vm_images]]` — raw TOML mapping for a single operator-
/// declared OCI-pinned VM image. Validated by
/// [`validate_vm_images`] into [`VmImageConfig`].
#[derive(Debug, Clone, Deserialize, Default)]
pub(crate) struct VmImageEntry {
    /// Required. Operator-chosen alias used by plan tasks'
    /// `vm_image` field. Matches `^[a-z][a-z0-9-]{0,63}$`.
    pub(crate) name: String,

    /// Required. `sha256:<64-hex>`-shape digest of the bundled
    /// rootfs erofs image bytes. The kernel verifies the digest
    /// at every spawn (defense-in-depth against a tampered image
    /// on disk; matches the existing canonical-image preflight
    /// shape).
    pub(crate) oci_digest: String,

    /// Required. Non-empty list of role names this image is
    /// authorised to back. Each entry MUST be one of
    /// `"Executor"`, `"Verifier"`. Per V2 invariants, `"Reviewer"`
    /// and `"Orchestrator"` are NOT allowed in operator-published
    /// `[[vm_images]]` (those images are kernel-canonical and
    /// hardcoded; any operator entry attempting to back them is
    /// rejected at policy load).
    #[serde(default, rename = "role_restriction")]
    pub(crate) role_restriction: Vec<String>,

    /// Required. Operator-declared minimum **Linux** guest kernel
    /// version, shape `"<major>.<minor>"`. Validated to be ≥ `"5.14"`
    /// per `INV-PLANNER-HARNESS-03` (cgroup v2 guest kernel floor).
    /// Renamed from `kernel_version_min` to disambiguate from the
    /// RAXIS kernel binary. The RAXIS kernel does **not** introspect
    /// the image bytes to verify this declaration in V2.5 — that's
    /// the V3 OCI introspection PR; until then the trust boundary
    /// is the operator's signature on `policy.toml` (which is the
    /// same trust boundary as `oci_digest`).
    #[serde(default, rename = "linux_kernel_version_min")]
    pub(crate) linux_kernel_version_min: Option<String>,

    /// Optional human-readable description; surfaced in
    /// `raxis-cli plan explain` / audit-log inspectors. Not
    /// security-sensitive.
    #[serde(default)]
    pub(crate) description: Option<String>,
}

/// `[default_executor_image]` — raw TOML mapping for the
/// operator-ergonomics defaulting target. Validated against the
/// `[[vm_images]]` registry (alias must resolve, role must
/// include `"Executor"`).
#[derive(Debug, Clone, Deserialize, Default)]
pub(crate) struct DefaultExecutorImageSection {
    /// Required. Alias of a `[[vm_images]]` entry.
    pub(crate) alias: String,
}

/// V2.5 — validated, public-API shape of a `[[vm_images]]` entry.
/// Returned by [`PolicyBundle::vm_images`] for admission-time
/// alias resolution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmImageConfig {
    /// Operator-declared alias.
    pub name:               String,
    /// `sha256:<64-hex>` digest. Lower-case, validated.
    pub oci_digest:         String,
    /// Roles this image may back. Always non-empty after
    /// validation; never contains `"Reviewer"` or `"Orchestrator"`.
    pub role_restriction:   Vec<String>,
    /// `(major, minor)` parsed from `linux_kernel_version_min`.
    /// Always ≥ `(5, 14)` after validation per
    /// `INV-PLANNER-HARNESS-03`. Refers to the **Linux** kernel
    /// inside the guest VM, not the RAXIS kernel.
    pub linux_kernel_version_min: (u32, u32),
    /// Operator description, trimmed; empty when omitted.
    pub description:        String,
}

impl VmImageConfig {
    /// Whether this image's `role_restriction` includes the
    /// requested role token. Comparison is case-sensitive
    /// (`"Executor"`, `"Verifier"`); a non-canonical token never
    /// matches because [`validate_vm_images`] already rejects
    /// such entries at policy load.
    pub fn permits_role(&self, role: &str) -> bool {
        self.role_restriction.iter().any(|r| r == role)
    }
}

/// V2.5 — validated `[default_executor_image]` shape. Returned by
/// [`PolicyBundle::default_executor_image`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DefaultExecutorImageConfig {
    /// `[[vm_images]]` alias the policy wants
    /// `[[tasks]]` blocks without an explicit `vm_image` to bind
    /// to. Validated to resolve and to permit `"Executor"`.
    pub alias: String,
}

/// Validate the operator-supplied `[[vm_images]]` array. Mirrors
/// `validate_environments` / `validate_permitted_credentials` for
/// shape; emits stable `FAIL_*` codes per §13 / §INV-VM-CAP-03.
fn validate_vm_images(
    raw: &[VmImageEntry],
) -> Result<Vec<VmImageConfig>, PolicyError> {
    use std::collections::HashSet;
    let mut seen: HashSet<&str> = HashSet::new();
    let mut out = Vec::with_capacity(raw.len());
    for entry in raw {
        let name = entry.name.trim();
        if !is_valid_vm_image_name(name) {
            return Err(PolicyError::MalformedArtifact(format!(
                "FAIL_POLICY_VM_IMAGE_NAME_INVALID: \
                 [[vm_images]] name {:?} does not match \
                 ^[a-z][a-z0-9-]{{0,63}}$ \
                 (policy-plan-authority.md §4)",
                entry.name,
            )));
        }
        // Reserved alias for kernel-canonical symbol-index image
        // (INV-VERIFIER-12). Any operator entry with this alias
        // is structurally ambiguous — refuse it shift-left.
        if name == RESERVED_SYMBOL_INDEX_VM_IMAGE_NAME {
            return Err(PolicyError::MalformedArtifact(format!(
                "FAIL_POLICY_RESERVED_VM_IMAGE_NAME: \
                 [[vm_images]] name {:?} is reserved for the \
                 kernel-canonical symbol-index image \
                 (INV-VERIFIER-12)",
                entry.name,
            )));
        }
        if !seen.insert(name) {
            return Err(PolicyError::MalformedArtifact(format!(
                "FAIL_POLICY_VM_IMAGE_DUPLICATE: \
                 [[vm_images]] name {name:?} declared more than once"
            )));
        }
        let oci_digest = entry.oci_digest.trim();
        if !is_valid_oci_digest(oci_digest) {
            return Err(PolicyError::MalformedArtifact(format!(
                "FAIL_POLICY_VM_IMAGE_DIGEST_INVALID: \
                 [[vm_images]] name = {name:?} oci_digest must \
                 match `sha256:<64 lower-hex>`; got {:?}",
                entry.oci_digest,
            )));
        }
        if entry.role_restriction.is_empty() {
            return Err(PolicyError::MalformedArtifact(format!(
                "FAIL_POLICY_VM_IMAGE_ROLE_RESTRICTION_REQUIRED: \
                 [[vm_images]] name = {name:?} role_restriction must \
                 be a non-empty array of role tokens"
            )));
        }
        for role in &entry.role_restriction {
            match role.as_str() {
                "Executor" | "Verifier" => {}
                "Reviewer" => {
                    return Err(PolicyError::MalformedArtifact(format!(
                        "FAIL_REVIEWER_VM_IMAGE_NOT_ALLOWED: \
                         [[vm_images]] name = {name:?} declares \
                         role_restriction = \"Reviewer\"; the \
                         Reviewer image is kernel-canonical and \
                         cannot be operator-published \
                         (INV-PLANNER-HARNESS-02)"
                    )));
                }
                "Orchestrator" => {
                    return Err(PolicyError::MalformedArtifact(format!(
                        "FAIL_ORCHESTRATOR_VM_IMAGE_NOT_ALLOWED: \
                         [[vm_images]] name = {name:?} declares \
                         role_restriction = \"Orchestrator\"; the \
                         Orchestrator image is kernel-canonical and \
                         cannot be operator-published \
                         (INV-PLANNER-HARNESS-05)"
                    )));
                }
                other => {
                    return Err(PolicyError::MalformedArtifact(format!(
                        "FAIL_POLICY_INVALID_ROLE_RESTRICTION: \
                         [[vm_images]] name = {name:?} declares \
                         unknown role {other:?}; expected \
                         \"Executor\" or \"Verifier\""
                    )));
                }
            }
        }
        let linux_kernel_version_min = match entry.linux_kernel_version_min.as_deref() {
            Some(v) => parse_and_check_linux_kernel_version_min(name, v)?,
            None => {
                return Err(PolicyError::MalformedArtifact(format!(
                    "FAIL_POLICY_VM_IMAGE_LINUX_KERNEL_VERSION_MIN_REQUIRED: \
                     [[vm_images]] name = {name:?} linux_kernel_version_min \
                     is required (INV-PLANNER-HARNESS-03)"
                )));
            }
        };
        out.push(VmImageConfig {
            name: name.to_owned(),
            oci_digest: oci_digest.to_owned(),
            role_restriction: entry.role_restriction.clone(),
            linux_kernel_version_min,
            description: entry
                .description
                .as_deref()
                .map(|s| s.trim().to_owned())
                .unwrap_or_default(),
        });
    }
    Ok(out)
}

/// Validate the operator-supplied `[default_executor_image]`
/// section against the `[[vm_images]]` registry. Returns
/// `Ok(None)` when omitted, `Ok(Some(config))` when it resolves
/// to an Executor-permitted entry, and a typed
/// `FAIL_POLICY_DEFAULT_EXECUTOR_IMAGE_UNRESOLVABLE` otherwise.
fn validate_default_executor_image(
    raw:        Option<&DefaultExecutorImageSection>,
    vm_images:  &[VmImageConfig],
) -> Result<Option<DefaultExecutorImageConfig>, PolicyError> {
    let Some(section) = raw else {
        return Ok(None);
    };
    let alias = section.alias.trim();
    if alias.is_empty() {
        return Err(PolicyError::MalformedArtifact(
            "FAIL_POLICY_DEFAULT_EXECUTOR_IMAGE_UNRESOLVABLE: \
             [default_executor_image] alias must be non-empty \
             (operator-ergonomics.md §3 D1)".to_owned(),
        ));
    }
    let entry = vm_images.iter().find(|e| e.name == alias).ok_or_else(|| {
        PolicyError::MalformedArtifact(format!(
            "FAIL_POLICY_DEFAULT_EXECUTOR_IMAGE_UNRESOLVABLE: \
             [default_executor_image] alias = {alias:?} does not \
             resolve to any [[vm_images]] entry"
        ))
    })?;
    if !entry.permits_role("Executor") {
        return Err(PolicyError::MalformedArtifact(format!(
            "FAIL_POLICY_DEFAULT_EXECUTOR_IMAGE_UNRESOLVABLE: \
             [default_executor_image] alias = {alias:?} resolves \
             to a [[vm_images]] entry whose role_restriction = \
             {restriction:?} does not include \"Executor\" \
             (INV-VM-CAP-03)",
            restriction = entry.role_restriction,
        )));
    }
    Ok(Some(DefaultExecutorImageConfig {
        alias: alias.to_owned(),
    }))
}

/// Reserved alias for the kernel-canonical symbol-index verifier
/// image (`INV-VERIFIER-12`). Any `[[vm_images]]` entry attempting
/// to use this name is rejected at policy load.
pub const RESERVED_SYMBOL_INDEX_VM_IMAGE_NAME: &str = "raxis-verifier-symbol-index";

/// Minimum Linux guest kernel version pinned by
/// `INV-PLANNER-HARNESS-03` (cgroup v2 controller availability).
/// Surfaced as a constant so the `validate_vm_images` rejection
/// message names the floor and `system-requirements.md §2.5`
/// references stay in sync. Refers to the Linux kernel inside the
/// guest VM, not the RAXIS kernel binary.
pub const MIN_GUEST_LINUX_KERNEL_MAJOR: u32 = 5;
pub const MIN_GUEST_LINUX_KERNEL_MINOR: u32 = 14;

/// Maximum length of a `[[vm_images]]` alias. Matches the docker /
/// OCI repo-name length conventions; long enough for
/// `raxis-executor-starter`-style aliases but bounded.
const VM_IMAGE_NAME_MAX_LEN: usize = 64;

fn is_valid_vm_image_name(s: &str) -> bool {
    if s.is_empty() || s.len() > VM_IMAGE_NAME_MAX_LEN {
        return false;
    }
    let mut chars = s.chars();
    let first = match chars.next() {
        Some(c) => c,
        None    => return false,
    };
    if !first.is_ascii_lowercase() {
        return false;
    }
    chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

fn is_valid_oci_digest(s: &str) -> bool {
    let Some(hex) = s.strip_prefix("sha256:") else {
        return false;
    };
    hex.len() == 64 && hex.chars().all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
}

fn parse_and_check_linux_kernel_version_min(
    image_name: &str,
    raw:        &str,
) -> Result<(u32, u32), PolicyError> {
    let trimmed = raw.trim();
    let (maj_str, min_str) = trimmed.split_once('.').ok_or_else(|| {
        PolicyError::MalformedArtifact(format!(
            "FAIL_POLICY_VM_IMAGE_LINUX_KERNEL_VERSION_MIN_INVALID: \
             [[vm_images]] name = {image_name:?} linux_kernel_version_min \
             must match `<major>.<minor>`; got {raw:?}"
        ))
    })?;
    let parse_u32 = |label: &str, s: &str| -> Result<u32, PolicyError> {
        s.parse::<u32>().map_err(|_| {
            PolicyError::MalformedArtifact(format!(
                "FAIL_POLICY_VM_IMAGE_LINUX_KERNEL_VERSION_MIN_INVALID: \
                 [[vm_images]] name = {image_name:?} linux_kernel_version_min \
                 {label} segment {s:?} is not a non-negative integer"
            ))
        })
    };
    let major = parse_u32("major", maj_str.trim())?;
    let minor = parse_u32("minor", min_str.trim())?;
    if (major, minor) < (MIN_GUEST_LINUX_KERNEL_MAJOR, MIN_GUEST_LINUX_KERNEL_MINOR) {
        return Err(PolicyError::MalformedArtifact(format!(
            "FAIL_VM_GUEST_LINUX_KERNEL_TOO_OLD: \
             [[vm_images]] name = {image_name:?} linux_kernel_version_min = \
             \"{major}.{minor}\" is below the floor \
             \"{MIN_GUEST_LINUX_KERNEL_MAJOR}.{MIN_GUEST_LINUX_KERNEL_MINOR}\" \
             (INV-PLANNER-HARNESS-03)"
        )));
    }
    Ok((major, minor))
}

/// `[host_capacity]` — operator-side host-capacity configuration.
/// V2 MVP scope per `V2_GAPS.md §D2`: the kernel enforces strict
/// VM concurrency caps, polls free disk every 5 seconds, and
/// refuses to boot when the FD limit is below floor. Memory caps,
/// per-initiative caps, round-robin fairness, per-operator queue
/// overrides, WAL pressure, and audit-reserve tracking are
/// deferred to V3.
#[derive(Debug, Clone, Deserialize, Default)]
pub(crate) struct HostCapacitySection {
    /// Maximum number of microVMs that can be active at once
    /// (`host-capacity.md §4`). Default 16.
    #[serde(default)]
    pub(crate) max_concurrent_vms: Option<u32>,

    /// Free-disk floor in MiB. Below this the watchdog enters
    /// `DiskFullHalt` and refuses new write-class admissions
    /// (`host-capacity.md §7.1`). Default 5120 (5 GiB).
    #[serde(default)]
    pub(crate) min_free_disk_mb: Option<u64>,

    /// Behavior on disk full. V2 only accepts `"halt_admit"`;
    /// `"gc_then_retry"` and `"halt_all"` parse but produce a
    /// validation error (`FAIL_HOST_CAPACITY_BEHAVIOR_V3_ONLY`)
    /// because their machinery is V3.
    #[serde(default)]
    pub(crate) disk_full_behavior: Option<String>,

    /// FD-limit floor checked at kernel boot
    /// (`host-capacity.md §12.1`). Default 4096; values below
    /// 1024 are rejected at policy load.
    #[serde(default)]
    pub(crate) required_min_fd_limit: Option<u32>,

    /// Global admission-queue depth — the V2 MVP rejects beyond
    /// this with `FAIL_ADMISSION_QUEUE_FULL` (the queue itself
    /// is V3; V2 returns the cap immediately so the operator
    /// can size). Default 64.
    #[serde(default)]
    pub(crate) admission_queue_depth: Option<u32>,

    /// `disk_root` — the path the watchdog statvfs's. Defaults
    /// to the kernel's data directory if omitted. The kernel
    /// resolves it at boot via `HostCapacityConfig::disk_root`.
    #[serde(default)]
    pub(crate) disk_root: Option<String>,
}

/// V2 effective host-capacity config. Mirrors the policy-side
/// `HostCapacitySection` but with every field resolved to a
/// concrete value (defaults applied) and validated. Read by the
/// kernel at intent admission and at the disk-watchdog poll.
#[derive(Debug, Clone)]
pub struct HostCapacityConfig {
    /// Strict cap — enforced at admission per
    /// `host-capacity.md §4.2`. INV-CAPACITY-01.
    pub max_concurrent_vms: u32,

    /// Free-disk floor in MiB (`host-capacity.md §7.1`).
    /// INV-CAPACITY-02.
    pub min_free_disk_mb: u64,

    /// Always `"halt_admit"` in V2.
    pub disk_full_behavior: String,

    /// Boot-time FD limit floor (`host-capacity.md §12.1`).
    pub required_min_fd_limit: u32,

    /// V2 MVP admission cap (no real queue; rejection beyond is
    /// `FAIL_ADMISSION_QUEUE_FULL`).
    pub admission_queue_depth: u32,

    /// Optional override for the path the watchdog polls. When
    /// `None`, the kernel uses its `data_dir`.
    pub disk_root: Option<String>,
}

impl Default for HostCapacityConfig {
    fn default() -> Self {
        Self {
            max_concurrent_vms:    16,
            min_free_disk_mb:      5120,
            disk_full_behavior:    "halt_admit".to_owned(),
            required_min_fd_limit: 4096,
            admission_queue_depth: 64,
            disk_root:             None,
        }
    }
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

    /// V2_GAPS §C6 — auto-push to upstream remote after a successful
    /// `IntegrationMerge` Phase 3. Default `false`; the kernel never
    /// pushes unless the operator opts in.
    #[serde(default)]
    pub(crate) auto_push: bool,

    /// V2_GAPS §C6 — remote name to push to (e.g. `"origin"`).
    /// Required when `auto_push = true`; the policy validator
    /// rejects an empty value as `FAIL_GIT_PUSH_REMOTE_REQUIRED`.
    #[serde(default)]
    pub(crate) push_remote: Option<String>,
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
///
/// # v2_extended_gaps.md §2.5 — per-session LLM token ceilings.
/// # All three are optional; absent ⇒ uncapped on that axis.
/// [budget.token_caps]
/// max_input_tokens_per_session  = 200_000   # ≈ Claude 3.5 Sonnet context
/// max_output_tokens_per_session = 100_000
/// max_total_tokens_per_session  = 250_000   # input + output combined
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

    /// V2 `v2_extended_gaps.md §2.5` — `[budget.token_caps]`.
    /// Per-session cumulative LLM token ceilings stamped into the
    /// planner-VM env at spawn time and enforced by the in-VM
    /// dispatch loop. `None` ⇒ section omitted ⇒ uncapped on every
    /// axis (matches today's behaviour for unmigrated policies).
    #[serde(default)]
    pub(crate) token_caps: Option<TokenCapsSection>,

    /// V2 `v2_extended_gaps.md §3.1` — `[budget.sleep_caps]`.
    /// Per-call and cumulative ceilings for the `sleep` planner tool
    /// (executor + orchestrator only; reviewer NEVER has it). `None`
    /// ⇒ section omitted ⇒ the in-VM tool itself is registered with
    /// `max_per_call = 0`, which causes every `sleep` invocation to
    /// fail with `FAIL_SLEEP_DISABLED`. Operators who want the tool
    /// MUST opt in by declaring this section.
    #[serde(default)]
    pub(crate) sleep_caps: Option<SleepCapsSection>,
}

/// **`v2_extended_gaps.md §3.1` — per-session `sleep` tool budgets.**
///
/// ```toml
/// [budget.sleep_caps]
/// max_seconds_per_call         = 60      # hard ceiling per Sleep call
/// max_cumulative_seconds       = 300     # total over the session
/// ```
///
/// Both fields default to 0 when absent, which causes the in-VM
/// Sleep tool to refuse every invocation (`FAIL_SLEEP_DISABLED`).
/// This makes the §3.1 spec's "operators must opt in" requirement
/// the codified default.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct SleepCapsSection {
    /// Maximum allowed `seconds` argument on any single `sleep` call.
    /// 0 ⇒ tool disabled. Hard upper bound: 600s (10 minutes) — the
    /// dispatch loop will reject larger values regardless of policy
    /// to keep one runaway agent from monopolising a VM slot.
    #[serde(default)]
    pub max_seconds_per_call:    u32,

    /// Cumulative cap across the session. Once the running total of
    /// previously-completed `sleep` calls hits this value, every
    /// subsequent `sleep` invocation fails with
    /// `FAIL_SLEEP_BUDGET_EXCEEDED`. 0 ⇒ disabled (forces every
    /// `sleep` to fail; same as `max_seconds_per_call = 0`).
    #[serde(default)]
    pub max_cumulative_seconds:  u32,
}

/// **`v2_extended_gaps.md §2.5` — per-session LLM token ceilings.**
///
/// ```toml
/// [budget.token_caps]
/// max_input_tokens_per_session  = 200_000
/// max_output_tokens_per_session = 100_000
/// max_total_tokens_per_session  = 250_000
/// ```
///
/// Every field is optional and counts cumulative tokens across the
/// session. The kernel stamps each present cap into the spawned
/// planner VM's env (`RAXIS_PLANNER_MAX_TOKENS_INPUT_TOTAL`,
/// `RAXIS_PLANNER_MAX_TOKENS_OUTPUT_TOTAL`,
/// `RAXIS_PLANNER_MAX_TOKENS_TOTAL`); the in-VM dispatch loop enforces
/// the caps via `DispatchOutcome::TokensExceeded`. This is mid-session
/// abort defense-in-depth — the kernel-side §2.5 cost ceiling is the
/// authoritative spend gate; the in-VM ceiling stops the agent
/// burning more tokens between intent submissions.
#[derive(Debug, Clone, Deserialize)]
pub struct TokenCapsSection {
    /// Cumulative *input* tokens (Anthropic `input_tokens` +
    /// `cache_creation_input_tokens` + `cache_read_input_tokens`)
    /// allowed across a single session. Cumulative across every turn.
    /// `None` ⇒ uncapped on this axis.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_input_tokens_per_session: Option<u64>,

    /// Cumulative *output* tokens (Anthropic `output_tokens`) allowed
    /// across a single session. `None` ⇒ uncapped on this axis.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_output_tokens_per_session: Option<u64>,

    /// Cumulative *combined* tokens (input + output) allowed across
    /// a single session. Cheaper to set when an operator only cares
    /// about total spend rather than the input/output split.
    /// `None` ⇒ uncapped on this axis.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_total_tokens_per_session: Option<u64>,
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

    /// **V2_GAPS §C9 — per-provider streaming idle timeout.**
    ///
    /// Per-chunk silence deadline applied to inference requests that
    /// return `text/event-stream` bodies. A provider that opens the
    /// connection but stalls mid-body fails fast at this boundary
    /// rather than dragging out to `inference_timeout_ms`.
    ///
    /// **Why per-provider.** The 30-second default is correct for
    /// generation-tier models (Claude 3.5/4, GPT-4) where inter-chunk
    /// gaps are sub-second. Reasoning-tier models (OpenAI o1/o3) emit
    /// no SSE chunks for the full chain-of-thought duration —
    /// observed silent gaps of 30–120 seconds are normal. Setting a
    /// 30-second cap on those providers triggers spurious aborts
    /// every time the model starts thinking.
    ///
    /// **Validation.** When set, must parse as a duration in
    /// `[5_000, 600_000]` ms. The kernel-side `PolicyBundle::validate`
    /// rejects anything outside the band (5s lower bound prevents
    /// pathologically tight values that flake under network jitter;
    /// 600s upper bound is the same outer ceiling as the
    /// `inference_timeout_ms` cap).
    ///
    /// **Default.** `None` ⇒ the gateway falls back to its
    /// hard-coded `STREAM_IDLE_TIMEOUT` (30 s).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stream_idle_timeout_ms: Option<u32>,

    // ── V2_GAPS §C5 sidecar fields ──────────────────────────────────────
    //
    // Extended set used only when `kind = "http_sidecar"` per
    // `extensibility-traits.md §9A.4`. Validation enforces every
    // sidecar provider declares both `sidecar_endpoint` and
    // `sidecar_hmac_secret`; non-sidecar providers MUST leave both
    // unset (PolicyBundle::validate rejects anything else).

    /// **Sidecar only.** Base URL of the operator-run sidecar process
    /// (e.g. `"http://127.0.0.1:9100"`). Plumbed to
    /// `SidecarModelClient::new` at planner-binary boot. Unset for
    /// every other provider kind.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sidecar_endpoint: Option<String>,

    /// **Sidecar only.** 32-byte hex (64 hex chars) HMAC-SHA256
    /// shared secret. Stored verbatim in the operator-signed
    /// `policy.toml` so the planner cannot read it (R-2). The
    /// gateway resolves the same secret from the policy bundle and
    /// stamps it into every outbound request to the sidecar
    /// (`extensibility-traits.md §9A.7A`). Validated at policy-load
    /// time: must be non-empty and an even hex length when
    /// `kind = "http_sidecar"`.
    ///
    /// **NEVER** logged through `ProviderEntry`'s `Debug` output
    /// (the field is plain `Option<String>` but operator tooling
    /// MUST redact it before printing — same convention as
    /// `[[credentials]]` rows).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sidecar_hmac_secret: Option<String>,

    /// **Sidecar only.** Health-check path appended to
    /// `sidecar_endpoint` for `raxis doctor sidecar` and the C2
    /// circuit-breaker probe. Default: `"/health"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sidecar_health_check_path: Option<String>,

    /// **`v2_extended_gaps.md §2.5` — per-provider pricing table.**
    ///
    /// Required for every model-bearing provider kind (`Anthropic`,
    /// `OpenAI`, `Gemini`, `Bedrock`, `http_sidecar`); MUST be unset
    /// for non-LLM providers (kernel rejects with
    /// `MalformedArtifact` either way).
    ///
    /// ```toml
    /// [[providers]]
    /// provider_id      = "anthropic-prod"
    /// kind             = "Anthropic"
    /// credentials_file = "anthropic-prod.toml"
    ///
    ///   # Inline-dotted form keeps the array-of-tables boundary
    ///   # unambiguous (TOML's `[providers.pricing]` would close the
    ///   # `[[providers]]` row, which is not what we want).
    ///   pricing.input_tokens_per_dollar         = 200_000   # $5  / 1M input
    ///   pricing.output_tokens_per_dollar        = 50_000    # $20 / 1M output
    ///   pricing.cache_read_tokens_per_dollar    = 2_000_000 # $0.50 / 1M cache hit
    /// ```
    ///
    /// All three rates are *tokens per US dollar* — operators
    /// declare the inverse of the published per-million price so the
    /// kernel can compute cost via integer division
    /// (`tokens * 1_000_000 / tokens_per_dollar` → micro-dollars)
    /// with no floating-point drift in the audit chain.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pricing: Option<ProviderPricing>,
}

fn default_inference_timeout_ms() -> u32 { 30_000 }
fn default_data_fetch_timeout_ms() -> u32 { 10_000 }
fn default_max_response_bytes() -> u64 { 16 * 1024 * 1024 }

/// **`v2_extended_gaps.md §2.5` — per-provider pricing table.**
///
/// Operators declare model rates as *tokens per US dollar* (the
/// inverse of the conventional per-million pricing) so the kernel
/// computes cost via integer division and the audit chain carries no
/// floating-point drift. The kernel stores cost in **micro-dollars**
/// (1 USD = 1_000_000 µ$) so a $0.000001 charge is the smallest
/// representable increment — finer than any current provider's
/// per-token unit cost.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ProviderPricing {
    /// Tokens of *input* (prompt) you can send per US dollar.
    /// e.g. `200_000` ⇒ $5 / 1M input tokens.
    pub input_tokens_per_dollar: u64,

    /// Tokens of *output* (completion / reasoning) you can receive
    /// per US dollar. e.g. `50_000` ⇒ $20 / 1M output tokens.
    pub output_tokens_per_dollar: u64,

    /// Tokens of *cache-read* input (Anthropic prompt-caching)
    /// you can re-use per US dollar. Defaults to
    /// `input_tokens_per_dollar` (no discount) when omitted.
    /// e.g. `2_000_000` ⇒ $0.50 / 1M cache hits (typical Anthropic
    /// 90% discount on cached prompt prefixes).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_read_tokens_per_dollar: Option<u64>,

    /// Tokens of *cache-creation* input (Anthropic prompt-caching
    /// write surcharge) you can write per US dollar. Defaults to
    /// `input_tokens_per_dollar` when omitted (no surcharge).
    /// e.g. `160_000` ⇒ $6.25 / 1M cache writes (typical Anthropic
    /// 25% write premium).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_creation_tokens_per_dollar: Option<u64>,
}

impl ProviderPricing {
    /// Compute the dollar cost of a usage record in **micro-dollars**
    /// (`1 USD = 1_000_000 µ$`). Pure integer math — no floating-point
    /// drift in the audit chain.
    ///
    /// All four token kinds are summed independently:
    /// * `input_tokens` and `output_tokens` always at the base rate.
    /// * `cache_read_tokens` at the cache-read rate (defaulting to
    ///   `input_tokens_per_dollar` when the operator did not declare
    ///   a discount).
    /// * `cache_creation_tokens` at the cache-creation rate
    ///   (defaulting to `input_tokens_per_dollar`).
    ///
    /// Returns `0` when *every* rate is zero — that case can only
    /// occur in unit tests; `PolicyBundle::validate` rejects any
    /// real `[[providers]]` entry with a zero `input_tokens_per_dollar`
    /// or `output_tokens_per_dollar`.
    ///
    /// Token counts are widened to `u128` internally to absorb the
    /// `tokens * 1_000_000` multiplication without overflow even at
    /// the (absurd) maximum of `u64::MAX` tokens; the final result
    /// is saturated back into `u64` so callers never see overflow
    /// panics.
    pub fn cost_micro_dollars(
        &self,
        input_tokens:           u64,
        output_tokens:          u64,
        cache_read_tokens:      u64,
        cache_creation_tokens:  u64,
    ) -> u64 {
        const SCALE: u128 = 1_000_000;

        fn quotient(tokens: u64, rate: u64) -> u128 {
            if rate == 0 { return 0; }
            (tokens as u128 * SCALE) / rate as u128
        }

        let cache_read_rate = self
            .cache_read_tokens_per_dollar
            .unwrap_or(self.input_tokens_per_dollar);
        let cache_creation_rate = self
            .cache_creation_tokens_per_dollar
            .unwrap_or(self.input_tokens_per_dollar);

        let total: u128 = quotient(input_tokens,          self.input_tokens_per_dollar)
                        + quotient(output_tokens,         self.output_tokens_per_dollar)
                        + quotient(cache_read_tokens,     cache_read_rate)
                        + quotient(cache_creation_tokens, cache_creation_rate);

        u64::try_from(total).unwrap_or(u64::MAX)
    }
}

/// `[[providers]] kind` values that reach a model provider and
/// therefore MUST declare `pricing`. Anything outside this list is
/// treated as a non-LLM provider (e.g. a future `"DataFetch"` kind)
/// and MUST leave `pricing` unset; mismatches are rejected at
/// `PolicyBundle::validate` time.
pub(crate) const LLM_PROVIDER_KINDS: &[&str] = &[
    "Anthropic",
    "OpenAI",
    "Gemini",
    "Bedrock",
    "http_sidecar",
];

/// Hard cap on inference timeout, normative per peripherals.md §3.2.
pub const MAX_INFERENCE_TIMEOUT_MS: u32 = 120_000;
/// Hard cap on data-fetch timeout, normative per peripherals.md §3.2.
pub const MAX_DATA_FETCH_TIMEOUT_MS: u32 = 60_000;
/// V2_GAPS §C9 — minimum value (in ms) for the per-provider
/// `stream_idle_timeout_ms`. Anything below 5 s flakes on a busy
/// provider's first chunk after TLS handshake.
pub const STREAM_IDLE_TIMEOUT_FLOOR_MS: u32 = 5_000;
/// V2_GAPS §C9 — maximum value (in ms) for the per-provider
/// `stream_idle_timeout_ms`. Anything above 600 s defeats the
/// purpose; the per-request `inference_timeout_ms` is the outer
/// ceiling and dragging the idle deadline above that boundary
/// merely waits for the request-level cap to fire.
pub const STREAM_IDLE_TIMEOUT_CEILING_MS: u32 = 600_000;
/// Hard cap on response body size, normative per peripherals.md §3.2
/// ("v1 constraint: 16 MiB ... configurable in `[[providers]]`"). The
/// configurable knob has its own ceiling so a malicious or misconfigured
/// policy cannot turn the gateway into a DoS amplifier.
pub const MAX_RESPONSE_BYTES_CEILING: u64 = 64 * 1024 * 1024;

// ---------------------------------------------------------------------------
// Notification channels — `[notifications]`
//
// Normative reference: cli-readonly.md §5.6 +
// `email-and-notification-channels.md`.
//
// V2 surface (forward-only, no V1 backward-compat shims):
//
//   * `File`           — local JSONL append to operator-supplied path.
//   * `Email`          — direct SMTP submission with STARTTLS or
//                        implicit TLS, AUTH PLAIN.
//   * `Sidecar`        — HTTP POST to an operator-run sidecar
//                        process that translates to the target
//                        platform's API (Slack, PagerDuty, Teams,
//                        Discord, Opsgenie, ...).
//
// The legacy `Webhook` channel kind was removed in V2.5: it
// duplicated `Sidecar` (both are "HTTP POST a JSON payload to a
// URL"), shipped without HMAC signing, lacked the per-channel
// concurrency cap + circuit breaker, and only existed for V1
// backward-compat.  Operators with existing webhook URLs put the
// URL behind a `Sidecar` (the URL stays a one-hop translator).
// ---------------------------------------------------------------------------

/// Channel-kind discriminator.
///
/// V2 surface:
/// * `File` — local JSONL append to an operator-supplied path.
/// * `Email` — direct SMTP submission with STARTTLS or implicit
///   TLS, AUTH PLAIN.
/// * `Sidecar` — HTTP POST a structured `NotificationPayload`
///   (see `notifications/sidecar_protocol.rs`) to an operator-run
///   sidecar process which translates to the target platform's API
///   and returns `2xx` with an opaque `upstream_trace_id`.
///   Localhost-only by convention; the sidecar handles its own auth.
///   The dispatcher wraps every Sidecar call in a per-channel
///   semaphore + 3-state circuit breaker so a hanging upstream
///   never wedges the kernel.
///
/// Note: the kernel unconditionally writes every notification to
/// `<data_dir>/notifications/inbox.jsonl` AND the SQLite
/// `notifications` table before fanning out to these channels.
/// There is no longer a `Shell` variant — inbox.jsonl is always
/// written by `dispatch()`, not by a channel handler.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
pub enum NotificationChannelKind {
    /// Append a JSON line to the operator-supplied path.
    File,
    /// Submit the notification by SMTP (STARTTLS or implicit TLS,
    /// AUTH PLAIN).
    Email,
    /// V2 — HTTP sidecar (`email-and-notification-channels.md` +
    /// V2_GAPS.md §C4).  The kernel POSTs a structured payload to
    /// `target` and the sidecar converts to the platform's API.
    Sidecar,
}

/// One `[[notifications.channels]]` entry.
///
/// ```toml
/// [[notifications.channels]]
/// id     = "audit-mirror"
/// kind   = "File"
/// target = "/var/log/raxis-audit.jsonl"
/// ```
#[derive(Debug, Clone, Deserialize)]
pub struct NotificationChannel {
    /// Operator-chosen short identifier referenced from `[[notifications.routes]].channels`.
    /// Must be unique across the channels array; PolicyBundle::validate enforces.
    pub id:     String,
    pub kind:   NotificationChannelKind,
    /// For `File`: an absolute filesystem path the kernel will
    /// `O_APPEND | O_CREAT`.
    /// For `Email`: the recipient address (validated only as non-empty in v1).
    /// For `Sidecar`: the HTTP endpoint URL the kernel POSTs the
    ///   structured payload to (e.g. `http://localhost:9200/notify`).
    pub target: String,

    /// V2.4 — `Sidecar` channels: maximum concurrent in-flight
    /// dispatches per channel. When all permits are held, further
    /// notifications drop immediately with
    /// `DeliveryFailed{Backpressure}`. Bounded resource ceiling
    /// per channel = `max_in_flight × per_attempt_timeout × max_attempts`.
    /// Default 8 (per V2_GAPS.md §C4 worst-case table). Ignored for
    /// non-Sidecar kinds.
    #[serde(default = "default_max_in_flight")]
    pub max_in_flight: u32,
}

fn default_max_in_flight() -> u32 { 8 }

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

/// Filename appended to `<data_dir>/notifications/` for the kernel's
/// unconditional inbox JSONL log.
///
/// Every notification is written here by `dispatch()` regardless of
/// which operator channels are configured. Historically this was
/// owned by an implicit "Shell" channel; it is now a kernel primitive.
pub const INBOX_FILENAME: &str = "inbox.jsonl";

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
    // V2_GAPS §C6 — kernel push protocol
    "PushAttempted", "PushCompleted", "PushFailed",
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
    // V2_GAPS §C7 — credential CLI ceremony events
    "CredentialRegistered", "CredentialRemoved", "CredentialVerified",
    // V2_GAPS §D1 — operator-cert revocation ceremony events
    "OperatorCertRevoked", "OperatorCertRevokedOpDenied",
    // V2_GAPS §D2 — host-capacity admission + watchdogs
    "AdmissionDeferredAtCap", "AdmissionQueueFull",
    "DiskFullHaltEntered", "DiskHealthyAfterFull",
    "OperatorAttentionRequired",
    "KernelPushEnqueued",
    // V2_GAPS §12.4 — operator-ergonomics IPC dry-run audit event.
    "DryRunAdmitted",
];

/// Validate the raw `[notifications]` section and produce the final
/// `(channels, routes, default_channels)` triple for `PolicyBundle`.
///
/// Rules enforced:
///
/// 1. **Channel ids are unique.** Duplicate `id` values fail loudly.
/// 2. **No implicit channel synthesis.** The kernel unconditionally
///    writes every notification to `inbox.jsonl` + the SQLite
///    `notifications` table. Channels are purely operator-configured
///    additional delivery routes (File, Email, Sidecar).
/// 3. **Default channels reference declared ids.** Every entry in
///    `default_channels` MUST resolve to a channel id. An empty
///    `default_channels` is valid — it means events with no explicit
///    route go only to the kernel-owned stores.
/// 4. **Route channel ids resolve.** Every channel id in a route's
///    `channels` array MUST resolve to a declared id.
/// 5. **Route event_kind is real.** The event_kind MUST appear in
///    [`KNOWN_AUDIT_EVENT_KINDS`] (defence against typo-silenced
///    routes).
/// 6. **Per-kind validation.** File channels require non-empty
///    target. Email channels require non-empty target. Sidecar
///    channels require a valid HTTP(S) URL and non-zero
///    `max_in_flight`.

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

/// V2_GAPS §D2 — validate `[host_capacity]` and produce the
/// effective `HostCapacityConfig`. Defaults apply for any field
/// the operator omits (or for the whole section). V2 only
/// accepts `disk_full_behavior = "halt_admit"`; the other two
/// variants from the spec are V3.
fn validate_host_capacity_section(
    raw: &Option<HostCapacitySection>,
) -> Result<HostCapacityConfig, PolicyError> {
    let mut cfg = HostCapacityConfig::default();
    let Some(s) = raw else { return Ok(cfg); };

    if let Some(v) = s.max_concurrent_vms {
        if v == 0 {
            return Err(PolicyError::MalformedArtifact(
                "FAIL_HOST_CAPACITY_INVALID: \
                 [host_capacity] max_concurrent_vms must be ≥ 1 \
                 (host-capacity.md §4)".to_owned(),
            ));
        }
        cfg.max_concurrent_vms = v;
    }

    if let Some(v) = s.min_free_disk_mb {
        cfg.min_free_disk_mb = v;
    }

    if let Some(b) = s.disk_full_behavior.as_deref() {
        match b {
            "halt_admit" => cfg.disk_full_behavior = "halt_admit".to_owned(),
            "gc_then_retry" | "halt_all" => {
                return Err(PolicyError::MalformedArtifact(format!(
                    "FAIL_HOST_CAPACITY_BEHAVIOR_V3_ONLY: \
                     [host_capacity] disk_full_behavior = {b:?} is V3-only; \
                     V2 ships only \"halt_admit\" (host-capacity.md §7.2; \
                     V2_GAPS.md §D2)"
                )));
            }
            other => {
                return Err(PolicyError::MalformedArtifact(format!(
                    "FAIL_HOST_CAPACITY_INVALID: \
                     [host_capacity] disk_full_behavior must be \"halt_admit\" \
                     in V2; got {other:?}"
                )));
            }
        }
    }

    if let Some(v) = s.required_min_fd_limit {
        if v < 1024 {
            return Err(PolicyError::MalformedArtifact(format!(
                "FAIL_HOST_CAPACITY_INVALID: \
                 [host_capacity] required_min_fd_limit = {v} is below the \
                 hard floor of 1024 (host-capacity.md §12.1)"
            )));
        }
        cfg.required_min_fd_limit = v;
    }

    if let Some(v) = s.admission_queue_depth {
        if v == 0 {
            return Err(PolicyError::MalformedArtifact(
                "FAIL_HOST_CAPACITY_INVALID: \
                 [host_capacity] admission_queue_depth must be ≥ 1".to_owned(),
            ));
        }
        cfg.admission_queue_depth = v;
    }

    if let Some(d) = s.disk_root.as_deref() {
        let trimmed = d.trim();
        if trimmed.is_empty() {
            return Err(PolicyError::MalformedArtifact(
                "FAIL_HOST_CAPACITY_INVALID: \
                 [host_capacity] disk_root must be a non-empty path \
                 when present".to_owned(),
            ));
        }
        if !std::path::Path::new(trimmed).is_absolute() {
            return Err(PolicyError::MalformedArtifact(format!(
                "FAIL_HOST_CAPACITY_INVALID: \
                 [host_capacity] disk_root = {trimmed:?} must be an \
                 absolute path"
            )));
        }
        cfg.disk_root = Some(trimmed.to_owned());
    }

    Ok(cfg)
}

/// V2_GAPS §E1 — environment label syntax per §5b.3. Lowercase
/// ASCII letters, digits, hyphens, underscores; 1–32 characters;
/// must start with a letter.
fn is_valid_env_label(label: &str) -> bool {
    let bytes = label.as_bytes();
    if bytes.is_empty() || bytes.len() > 32 {
        return false;
    }
    let first = bytes[0];
    if !first.is_ascii_lowercase() {
        return false;
    }
    bytes.iter().all(|&b| {
        b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_'
    })
}

/// V2_GAPS §E1 — list of fields the parser TOLERATES on
/// `[environments.<label>]` per §5b.4 ("reserved for V2.x").
/// Operators MAY set them; the V2 kernel ignores them and emits
/// no kernel-side effect. (V3 will graduate them to normative
/// fields.) Anything not on this list and not consumed by V2 is
/// `FAIL_POLICY_ENV_UNKNOWN_FIELD`.
const RESERVED_ENV_FIELDS: &[&str] = &[
    "require_review_signoff",
    "blast_radius",
    "audit_retention_days",
    "require_two_party_sign",
    "escalation_default_class",
    "override_reviewer_alias",
];

/// V2_GAPS §E1 (`environment-access-control.md §5b.3`).
/// Validate every `[environments.<label>]` table:
/// - Label syntax `^[a-z][a-z0-9_-]{0,31}$` (§5b.3 rule 4).
/// - `description` is required and non-empty.
/// - Unknown fields are rejected unless they appear in the
///   §5b.4 reserved list, in which case they are tolerated.
fn validate_environments(
    raw: &HashMap<String, EnvironmentSection>,
) -> Result<HashMap<String, EnvironmentConfig>, PolicyError> {
    let mut out = HashMap::with_capacity(raw.len());
    for (label, section) in raw {
        if !is_valid_env_label(label) {
            return Err(PolicyError::MalformedArtifact(format!(
                "FAIL_POLICY_ENV_LABEL_INVALID: \
                 [environments.{label}] label does not match \
                 ^[a-z][a-z0-9_-]{{0,31}}$ (environment-access-control.md §5b.3)"
            )));
        }
        let description = match section.description.as_deref() {
            Some(d) if !d.trim().is_empty() => d.trim().to_owned(),
            _ => {
                return Err(PolicyError::MalformedArtifact(format!(
                    "FAIL_POLICY_ENV_UNKNOWN_FIELD: \
                     [environments.{label}] missing required `description` \
                     (environment-access-control.md §5b.2)"
                )));
            }
        };
        for unknown in section.extras.keys() {
            if !RESERVED_ENV_FIELDS.contains(&unknown.as_str()) {
                return Err(PolicyError::MalformedArtifact(format!(
                    "FAIL_POLICY_ENV_UNKNOWN_FIELD: \
                     [environments.{label}] unknown field {unknown:?} \
                     (environment-access-control.md §5b.3 / §5b.4)"
                )));
            }
        }
        out.insert(label.clone(), EnvironmentConfig {
            description,
            same_cluster_acknowledged: section.same_cluster_acknowledged,
        });
    }
    Ok(out)
}

/// V2_GAPS §E1 (`environment-access-control.md §5.2 / §5b.5`).
/// Validate `[[permitted_credentials]]`:
/// - `name` is required and non-empty.
/// - Names are unique across the section.
/// - Every non-empty `environment` field resolves to a declared
///   `[environments.<label>]` (`FAIL_POLICY_ENV_LABEL_UNDECLARED`).
fn validate_permitted_credentials(
    raw: &[PermittedCredentialEntry],
    declared_envs: &HashMap<String, EnvironmentSection>,
) -> Result<Vec<PermittedCredentialConfig>, PolicyError> {
    let mut seen: std::collections::HashSet<&str> = std::collections::HashSet::new();
    let mut out = Vec::with_capacity(raw.len());
    for entry in raw {
        let name = entry.name.trim();
        if name.is_empty() {
            return Err(PolicyError::MalformedArtifact(
                "FAIL_POLICY_PERMITTED_CRED_INVALID: \
                 [[permitted_credentials]] name must be non-empty \
                 (environment-access-control.md §5.2)".to_owned(),
            ));
        }
        if !seen.insert(name) {
            return Err(PolicyError::MalformedArtifact(format!(
                "FAIL_POLICY_PERMITTED_CRED_INVALID: \
                 [[permitted_credentials]] duplicate name {name:?}"
            )));
        }
        let env = match entry.environment.as_deref() {
            Some(e) if !e.trim().is_empty() => {
                let trimmed = e.trim();
                if !declared_envs.contains_key(trimmed) {
                    return Err(PolicyError::MalformedArtifact(format!(
                        "FAIL_POLICY_ENV_LABEL_UNDECLARED: \
                         [[permitted_credentials]] name = {name:?} references \
                         environment {trimmed:?} which has no \
                         [environments.{trimmed}] declaration \
                         (environment-access-control.md §5b.3)"
                    )));
                }
                Some(trimmed.to_owned())
            }
            _ => None,
        };
        out.push(PermittedCredentialConfig {
            name:        name.to_owned(),
            environment: env,
            description: entry.description.clone(),
        });
    }
    Ok(out)
}

fn validate_notifications(
    raw: &NotificationsSection,
) -> Result<
    (Vec<NotificationChannel>, HashMap<String, Vec<String>>, Vec<String>),
    PolicyError,
> {
    use std::collections::HashSet;

    let channels: Vec<NotificationChannel> = raw.channels_raw.clone();
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
            NotificationChannelKind::File => {
                if ch.target.trim().is_empty() {
                    return Err(PolicyError::MalformedArtifact(format!(
                        "[[notifications.channels]] id={:?} kind=File requires a non-empty target",
                        ch.id
                    )));
                }
            }
            NotificationChannelKind::Email => {
                if ch.target.trim().is_empty() {
                    return Err(PolicyError::MalformedArtifact(format!(
                        "[[notifications.channels]] id={:?} kind=Email requires a non-empty target",
                        ch.id,
                    )));
                }
            }
            NotificationChannelKind::Sidecar => {
                // V2.4 §C4 — the sidecar endpoint URL must be
                // present and look like an HTTP(S) URL. Localhost
                // is the convention but not required (some
                // operators run sidecars on a private VPC IP
                // reachable from the kernel host).
                if ch.target.trim().is_empty() {
                    return Err(PolicyError::MalformedArtifact(format!(
                        "[[notifications.channels]] id={:?} kind=Sidecar requires a non-empty target URL",
                        ch.id
                    )));
                }
                let t = ch.target.trim();
                if !t.starts_with("http://") && !t.starts_with("https://") {
                    return Err(PolicyError::MalformedArtifact(format!(
                        "[[notifications.channels]] id={:?} kind=Sidecar target must be http:// or https://",
                        ch.id
                    )));
                }
                if ch.max_in_flight == 0 {
                    return Err(PolicyError::MalformedArtifact(format!(
                        "[[notifications.channels]] id={:?} kind=Sidecar max_in_flight must be >= 1",
                        ch.id
                    )));
                }
            }
        }
    }

    // No implicit Shell synthesis — inbox.jsonl is now written
    // unconditionally by dispatch(). Operator channels are purely
    // explicit.

    // Build the channel-id index for route validation.
    let declared_ids: HashSet<&str> = channels.iter().map(|c| c.id.as_str()).collect();

    // Default channels: validate every id resolves. When omitted,
    // defaults to empty — inbox.jsonl + SQLite are unconditional,
    // so "no channels" means "only the kernel-owned stores."
    let default_channels: Vec<String> = if raw.default_channels.is_empty() {
        vec![]
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

    /// V2 `v2_extended_gaps.md §2.5` — `[budget.token_caps]`.
    /// Per-session LLM token ceilings. `None` ⇒ section omitted ⇒
    /// uncapped on every axis (today's behaviour). The kernel
    /// `session_spawn_orchestrator` projects the present caps into
    /// `RAXIS_PLANNER_MAX_TOKENS_*` env vars.
    token_caps: Option<TokenCapsSection>,

    /// V2 `v2_extended_gaps.md §3.1` — `[budget.sleep_caps]`.
    /// Per-session `sleep` tool budgets. `None` ⇒ section omitted ⇒
    /// the in-VM Sleep tool refuses every invocation
    /// (`FAIL_SLEEP_DISABLED`). Operators MUST opt in by declaring
    /// the section.
    sleep_caps: Option<SleepCapsSection>,

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

    /// V2_GAPS §C6 — operator-side `[git] auto_push`. When `true`,
    /// the kernel pushes to [`git_push_remote`] after every
    /// successful `IntegrationMerge` Phase 3. Default `false`.
    ///
    /// [`git_push_remote`]: PolicyBundle::git_push_remote
    git_auto_push: bool,

    /// V2_GAPS §C6 — operator-side `[git] push_remote`. Required when
    /// [`git_auto_push`] is `true`. Empty string when auto-push is
    /// disabled (the kernel reads [`git_auto_push`] first and
    /// short-circuits without consulting this field).
    ///
    /// [`git_auto_push`]: PolicyBundle::git_auto_push
    git_push_remote: String,

    /// V2_GAPS §D2 — host-capacity caps and watchdog config.
    /// Always populated; spec defaults apply when the operator
    /// omits `[host_capacity]` from `policy.toml`.
    host_capacity: HostCapacityConfig,

    /// V2_GAPS §E1 — declared environment labels and their
    /// per-env knobs (`environment-access-control.md §5b`). The
    /// map is empty when the operator declares no
    /// `[environments.<label>]` tables (the activation gate per
    /// §1.5.2). Cardinality on this map drives whether
    /// `INV-ENV-01` runs at plan-approve time.
    environments: HashMap<String, EnvironmentConfig>,

    /// V2_GAPS §E1 — declared `[[permitted_credentials]]`
    /// entries (`environment-access-control.md §5.2`). Empty when
    /// the operator omits the section. When non-empty, every
    /// `name` is unique and every non-empty `environment` field
    /// resolves to an [`environments`] key.
    permitted_credentials: Vec<PermittedCredentialConfig>,

    /// V2.5 — validated `[[vm_images]]` registry. Empty when the
    /// operator omits the section (the V2.4 hardcoded-canonical
    /// behaviour applies to every spawn). When non-empty, every
    /// `name` is unique, `oci_digest` is shape-valid,
    /// `role_restriction` contains only `"Executor"` /
    /// `"Verifier"`, and `kernel_version_min ≥ 5.14`. Reviewer
    /// and Orchestrator roles are structurally rejected per
    /// `INV-PLANNER-HARNESS-02` / `INV-PLANNER-HARNESS-05`.
    vm_images: Vec<VmImageConfig>,

    /// V2.5 — validated `[default_executor_image]` section.
    /// `None` means the operator omits the section (the kernel
    /// uses the canonical `raxis-executor-starter` for tasks
    /// without an explicit `vm_image`). `Some` carries an alias
    /// guaranteed to resolve to an `[[vm_images]]` entry whose
    /// `role_restriction` includes `"Executor"`.
    default_executor_image: Option<DefaultExecutorImageConfig>,
}

/// V2 effective `[environments.<label>]` config. Validated mirror
/// of the policy-side `EnvironmentSection`.
#[derive(Debug, Clone)]
pub struct EnvironmentConfig {
    /// Human-readable description.
    pub description: String,

    /// `same_cluster_acknowledged` flag (§5b.2). When `true`,
    /// URL gates whose conflation involves this environment do
    /// not contribute env labels to the per-task consistency
    /// check. The V2 MVP only consumes this from the
    /// (V3-deferred) URL-gate handler; the per-task credential
    /// coherence check is unaffected by it.
    pub same_cluster_acknowledged: bool,
}

/// V2 effective `[[permitted_credentials]]` entry. Mirror of the
/// policy-side `PermittedCredentialEntry`, with `environment`
/// guaranteed to resolve to a declared environment when present.
#[derive(Debug, Clone)]
pub struct PermittedCredentialConfig {
    /// Credential name (matches `<data_dir>/credentials/<name>.env`).
    pub name: String,

    /// Resolved environment binding. `None` ⇒ neutral.
    pub environment: Option<String>,

    /// Optional human-readable description.
    pub description: Option<String>,
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

        // V2.5 — pre-validate `[[vm_images]]` once so the
        // `[default_executor_image]` resolver can borrow it and
        // the struct-init block reuses the same validated list.
        let vm_images_validated = validate_vm_images(&raw.vm_images)?;
        let default_executor_image_validated = validate_default_executor_image(
            raw.default_executor_image.as_ref(),
            &vm_images_validated,
        )?;

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

            // V2_GAPS §C9 — `stream_idle_timeout_ms` band check.
            //
            // The 5-second floor prevents pathologically tight values
            // that flake on a busy provider's first chunk after TLS
            // setup. The 600-second ceiling matches the same outer
            // ceiling we use for `inference_timeout_ms` — anything
            // above that defeats the purpose (the per-request
            // ceiling is the meaningful boundary).
            if let Some(ms) = p.stream_idle_timeout_ms {
                if !(STREAM_IDLE_TIMEOUT_FLOOR_MS..=STREAM_IDLE_TIMEOUT_CEILING_MS)
                    .contains(&ms)
                {
                    return Err(PolicyError::MalformedArtifact(format!(
                        "[[providers]] {:?} stream_idle_timeout_ms ({}) must be in \
                         [{}, {}] ms (V2_GAPS §C9)",
                        p.provider_id, ms,
                        STREAM_IDLE_TIMEOUT_FLOOR_MS, STREAM_IDLE_TIMEOUT_CEILING_MS,
                    )));
                }
            }

            // V2_GAPS §C5 — `kind = "http_sidecar"` validation.
            //
            // `extensibility-traits.md §9A.4` requires sidecar
            // providers declare `sidecar_endpoint` (the localhost
            // base URL) and `sidecar_hmac_secret` (the 32-byte hex
            // shared secret). Non-sidecar providers MUST leave both
            // unset so a typo on `kind` cannot accidentally activate
            // sidecar codepaths.
            let is_sidecar = p.kind == "http_sidecar";
            if is_sidecar {
                let endpoint = p.sidecar_endpoint.as_deref().unwrap_or("");
                if endpoint.is_empty() {
                    return Err(PolicyError::MalformedArtifact(format!(
                        "[[providers]] {:?} kind=\"http_sidecar\" but sidecar_endpoint \
                         is empty/missing — required by extensibility-traits.md §9A.4",
                        p.provider_id
                    )));
                }
                if !(endpoint.starts_with("http://") || endpoint.starts_with("https://")) {
                    return Err(PolicyError::MalformedArtifact(format!(
                        "[[providers]] {:?} sidecar_endpoint={:?} must start with \
                         `http://` or `https://`",
                        p.provider_id, endpoint
                    )));
                }
                let secret = p.sidecar_hmac_secret.as_deref().unwrap_or("");
                if secret.is_empty() {
                    return Err(PolicyError::MalformedArtifact(format!(
                        "[[providers]] {:?} kind=\"http_sidecar\" but sidecar_hmac_secret \
                         is empty/missing — operators MUST mint a 32-byte hex secret \
                         (use `raxis policy generate-sidecar-secret`)",
                        p.provider_id
                    )));
                }
                if secret.len() % 2 != 0 || !secret.chars().all(|c| c.is_ascii_hexdigit()) {
                    return Err(PolicyError::MalformedArtifact(format!(
                        "[[providers]] {:?} sidecar_hmac_secret must be even-length \
                         lowercase hex (got {} chars)",
                        p.provider_id, secret.len()
                    )));
                }
                // Recommend (but do not require) ≥32 bytes (64 hex
                // chars) for operator-grade HMAC security. We only
                // *reject* < 16 bytes; everything else is the
                // operator's call.
                if secret.len() < 32 {
                    return Err(PolicyError::MalformedArtifact(format!(
                        "[[providers]] {:?} sidecar_hmac_secret is {} hex chars; \
                         minimum is 32 (16 bytes) for HMAC-SHA256 security. \
                         Operator-grade is 64 hex chars (32 bytes).",
                        p.provider_id, secret.len()
                    )));
                }
            } else {
                // Non-sidecar providers MUST NOT carry sidecar fields.
                if p.sidecar_endpoint.is_some() {
                    return Err(PolicyError::MalformedArtifact(format!(
                        "[[providers]] {:?} declares sidecar_endpoint but kind={:?}; \
                         sidecar fields are valid only when kind=\"http_sidecar\"",
                        p.provider_id, p.kind
                    )));
                }
                if p.sidecar_hmac_secret.is_some() {
                    return Err(PolicyError::MalformedArtifact(format!(
                        "[[providers]] {:?} declares sidecar_hmac_secret but kind={:?}; \
                         sidecar fields are valid only when kind=\"http_sidecar\"",
                        p.provider_id, p.kind
                    )));
                }
                if p.sidecar_health_check_path.is_some() {
                    return Err(PolicyError::MalformedArtifact(format!(
                        "[[providers]] {:?} declares sidecar_health_check_path but kind={:?}",
                        p.provider_id, p.kind
                    )));
                }
            }

            // V2 `v2_extended_gaps.md §2.5` — `pricing` is REQUIRED
            // for every model-bearing provider kind and FORBIDDEN
            // for everything else. The kernel needs the rate table
            // to convert per-intent `Usage` into a dollar cost; a
            // missing rate would silently bypass the per-task cost
            // ceiling.
            let is_llm_kind = LLM_PROVIDER_KINDS.iter().any(|k| *k == p.kind);
            match (&p.pricing, is_llm_kind) {
                (None, true) => {
                    return Err(PolicyError::MalformedArtifact(format!(
                        "[[providers]] {:?} kind={:?} is a model provider but has no \
                         `pricing` table — operators MUST declare \
                         `pricing.input_tokens_per_dollar` and \
                         `pricing.output_tokens_per_dollar` (v2_extended_gaps.md §2.5)",
                        p.provider_id, p.kind
                    )));
                }
                (Some(_), false) => {
                    return Err(PolicyError::MalformedArtifact(format!(
                        "[[providers]] {:?} kind={:?} is not a model provider but \
                         declares `pricing`; remove the `pricing` table",
                        p.provider_id, p.kind
                    )));
                }
                (Some(pricing), true) => {
                    if pricing.input_tokens_per_dollar == 0 {
                        return Err(PolicyError::MalformedArtifact(format!(
                            "[[providers]] {:?} pricing.input_tokens_per_dollar must \
                             be > 0 (declares the inverse of $/token)",
                            p.provider_id
                        )));
                    }
                    if pricing.output_tokens_per_dollar == 0 {
                        return Err(PolicyError::MalformedArtifact(format!(
                            "[[providers]] {:?} pricing.output_tokens_per_dollar must \
                             be > 0",
                            p.provider_id
                        )));
                    }
                    if let Some(r) = pricing.cache_read_tokens_per_dollar {
                        if r == 0 {
                            return Err(PolicyError::MalformedArtifact(format!(
                                "[[providers]] {:?} pricing.cache_read_tokens_per_dollar \
                                 must be > 0 when declared (omit to inherit \
                                 input_tokens_per_dollar)",
                                p.provider_id
                            )));
                        }
                    }
                    if let Some(r) = pricing.cache_creation_tokens_per_dollar {
                        if r == 0 {
                            return Err(PolicyError::MalformedArtifact(format!(
                                "[[providers]] {:?} pricing.cache_creation_tokens_per_dollar \
                                 must be > 0 when declared (omit to inherit \
                                 input_tokens_per_dollar)",
                                p.provider_id
                            )));
                        }
                    }
                }
                (None, false) => { /* non-LLM provider, no pricing — OK */ }
            }
        }

        // ── V2 `v2_extended_gaps.md §2.5` — `[budget.token_caps]` ───────
        //
        // Each cap is optional, but when present MUST be > 0 (a cap of
        // zero would terminate the dispatch loop before the first
        // model call, which is never useful and is almost certainly
        // an operator typo). When all three caps are unset we leave
        // the section as `None` so the kernel can distinguish "no
        // caps" (skip env stamping) from "explicit caps".
        if let Some(caps) = raw.budget.token_caps.as_ref() {
            for (name, value) in [
                ("max_input_tokens_per_session",  caps.max_input_tokens_per_session),
                ("max_output_tokens_per_session", caps.max_output_tokens_per_session),
                ("max_total_tokens_per_session",  caps.max_total_tokens_per_session),
            ] {
                if let Some(0) = value {
                    return Err(PolicyError::MalformedArtifact(format!(
                        "[budget.token_caps] {name} = 0 is never useful; \
                         omit the key to leave the cap unset (v2_extended_gaps.md §2.5)"
                    )));
                }
            }
        }

        // ── V2 `v2_extended_gaps.md §3.1` — `[budget.sleep_caps]` ───────
        //
        // Both `max_seconds_per_call` and `max_cumulative_seconds` must
        // be > 0 when the section is present (a 0 cap means "tool
        // disabled" and the operator should just omit the entire
        // section instead). The hard upper bounds (`max_seconds_per_call
        // ≤ 600`, `max_cumulative_seconds ≤ 3 * max_seconds_per_call`)
        // are advisory ceilings — the in-VM `SleepTool` implementation
        // also clamps `seconds` at 600 regardless of the policy value
        // so an operator typo can't pin a VM slot for hours.
        if let Some(caps) = raw.budget.sleep_caps.as_ref() {
            if caps.max_seconds_per_call == 0 {
                return Err(PolicyError::MalformedArtifact(
                    "[budget.sleep_caps] max_seconds_per_call = 0 is never useful; \
                     omit the entire section to disable the Sleep tool \
                     (v2_extended_gaps.md §3.1)".to_owned()
                ));
            }
            if caps.max_cumulative_seconds == 0 {
                return Err(PolicyError::MalformedArtifact(
                    "[budget.sleep_caps] max_cumulative_seconds = 0 is never useful; \
                     omit the entire section to disable the Sleep tool \
                     (v2_extended_gaps.md §3.1)".to_owned()
                ));
            }
            if caps.max_seconds_per_call > 600 {
                return Err(PolicyError::MalformedArtifact(format!(
                    "[budget.sleep_caps] max_seconds_per_call = {} exceeds the hard \
                     ceiling of 600 (v2_extended_gaps.md §3.1)",
                    caps.max_seconds_per_call,
                )));
            }
            if caps.max_cumulative_seconds < caps.max_seconds_per_call {
                return Err(PolicyError::MalformedArtifact(format!(
                    "[budget.sleep_caps] max_cumulative_seconds ({}) MUST be \
                     >= max_seconds_per_call ({}) (v2_extended_gaps.md §3.1)",
                    caps.max_cumulative_seconds,
                    caps.max_seconds_per_call,
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
            token_caps: raw.budget.token_caps,
            sleep_caps: raw.budget.sleep_caps,
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
            git_auto_push: raw
                .git
                .as_ref()
                .map(|g| g.auto_push)
                .unwrap_or(false),
            git_push_remote: {
                let auto = raw.git.as_ref().map(|g| g.auto_push).unwrap_or(false);
                let remote = raw
                    .git
                    .as_ref()
                    .and_then(|g| g.push_remote.as_deref())
                    .unwrap_or("");
                if auto && remote.trim().is_empty() {
                    return Err(PolicyError::MalformedArtifact(
                        "[git] auto_push = true requires a non-empty \
                         [git] push_remote (V2_GAPS §C6)".to_owned(),
                    ));
                }
                if !auto {
                    String::new()
                } else {
                    remote.trim().to_owned()
                }
            },
            git_target_ref_locked: raw
                .git
                .as_ref()
                .map(|g| g.target_ref_locked)
                .unwrap_or(false),
            host_capacity: validate_host_capacity_section(&raw.host_capacity)?,
            environments: validate_environments(&raw.environments)?,
            permitted_credentials: validate_permitted_credentials(
                &raw.permitted_credentials,
                &raw.environments,
            )?,
            // V2.5 — pre-validated above so this is a move, not
            // a re-walk of the input array.
            vm_images: vm_images_validated,
            default_executor_image: default_executor_image_validated,
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

    /// V2_GAPS §C6 — operator-side `[git] auto_push`. The kernel
    /// pushes to [`git_push_remote`] after every successful
    /// `IntegrationMerge` Phase 3 when this is `true`.
    ///
    /// [`git_push_remote`]: PolicyBundle::git_push_remote
    pub fn git_auto_push(&self) -> bool {
        self.git_auto_push
    }

    /// V2_GAPS §D2 — host-capacity caps and watchdog config.
    /// Always populated; spec defaults apply when the operator
    /// omits `[host_capacity]`.
    pub fn host_capacity(&self) -> &HostCapacityConfig {
        &self.host_capacity
    }

    /// V2_GAPS §E1 — declared `[environments.<label>]` entries.
    /// Empty when the operator omits the entire section
    /// (`environment-access-control.md §1.5.2` activation gate);
    /// every key is a validated label (per §5b.3) and every
    /// value carries the per-env knobs.
    pub fn environments(&self) -> &HashMap<String, EnvironmentConfig> {
        &self.environments
    }

    /// V2_GAPS §E1 — declared `[[permitted_credentials]]`
    /// entries. Empty when the operator omits the section. When
    /// present, names are unique and every `environment` field
    /// resolves to a key in [`environments`].
    pub fn permitted_credentials(&self) -> &[PermittedCredentialConfig] {
        &self.permitted_credentials
    }

    /// V2_GAPS §E1 — convenience lookup. Returns the resolved
    /// environment label for the given credential name (or
    /// `None` for both "credential is neutral" and "credential
    /// is not declared in `[[permitted_credentials]]`"). The
    /// caller MUST distinguish those two cases via
    /// [`permitted_credential`] when policy semantics require
    /// it. The V2 INV-ENV-01 binding algorithm
    /// (`environment-access-control.md §11.3`) treats both
    /// cases as "contributes nothing to the env set", which
    /// matches the §1.5.4 neutral-credential rule.
    ///
    /// [`permitted_credential`]: PolicyBundle::permitted_credential
    pub fn credential_environment(&self, name: &str) -> Option<&str> {
        self.permitted_credentials
            .iter()
            .find(|c| c.name == name)
            .and_then(|c| c.environment.as_deref())
    }

    /// V2_GAPS §E1 — full lookup of a `[[permitted_credentials]]`
    /// entry by name. Returns `None` when no entry matches; the
    /// V2 plan-admission path treats absence as "neutral" (per
    /// §1.5.4), but the V3 INV-CRED-01 promotion will turn
    /// absence into `FAIL_CREDENTIAL_NOT_PERMITTED`.
    pub fn permitted_credential(&self, name: &str) -> Option<&PermittedCredentialConfig> {
        self.permitted_credentials.iter().find(|c| c.name == name)
    }

    /// V2_GAPS §C6 — operator-side `[git] push_remote`. Empty string
    /// when [`git_auto_push`] is `false`.
    ///
    /// [`git_auto_push`]: PolicyBundle::git_auto_push
    pub fn git_push_remote(&self) -> &str {
        &self.git_push_remote
    }

    // ── V2.5 `[[vm_images]]` accessors ──────────────────────────────────────

    /// V2_GAPS §13 (V2.5 BLOCKER) — declared `[[vm_images]]` entries.
    /// Empty when the operator omits the entire section, in which case
    /// admission relies on per-task `vm_image` paths only (legacy V1
    /// behavior — see `paradigm.md §10` and `INV-PLANNER-HARNESS-03`).
    pub fn vm_images(&self) -> &[VmImageConfig] {
        &self.vm_images
    }

    /// V2_GAPS §13 (V2.5 BLOCKER) — alias resolution for an admitted
    /// task's `vm_image` field. Returns `None` when the alias is not
    /// declared in `[[vm_images]]`. Callers in the admission path
    /// MUST translate `None` into `FAIL_PLAN_VM_IMAGE_UNKNOWN` so
    /// operators get a deterministic rejection rather than a
    /// silent fallback to whatever path the planner produced.
    pub fn vm_image_by_name(&self, name: &str) -> Option<&VmImageConfig> {
        self.vm_images.iter().find(|img| img.name == name)
    }

    /// V2_GAPS §13 (V2.5 BLOCKER) — declared `[default_executor_image]`,
    /// or `None` when the section is omitted. The kernel falls back
    /// to the per-task `vm_image` field when this returns `None`.
    pub fn default_executor_image(&self) -> Option<&DefaultExecutorImageConfig> {
        self.default_executor_image.as_ref()
    }

    /// V2_GAPS §13 (V2.5 BLOCKER) — convenience: resolves the
    /// `[default_executor_image] alias` (when present) against
    /// `[[vm_images]]`. Returns `None` if the section is absent. The
    /// `Some` case always points at a real entry because the
    /// `[default_executor_image]` validator already proved the alias
    /// resolves at policy load time.
    pub fn default_executor_image_resolved(&self) -> Option<&VmImageConfig> {
        self.default_executor_image
            .as_ref()
            .and_then(|d| self.vm_image_by_name(&d.alias))
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
            token_caps: None,
            sleep_caps: None,
            policy_sha256: String::new(),
            signed_by: String::new(),
            signed_at: 0,
            claim_rules: Vec::new(),
            claim_default_action: String::new(),
            egress_domains: Vec::new(),
            egress_patterns: Vec::new(),
            egress_max_fetches_per_window: 0,
            // No default channels — inbox.jsonl + SQLite are
            // unconditional. Tests that need explicit channels
            // configure them individually.
            notification_channels: vec![],
            notification_routes: HashMap::new(),
            default_notification_channels: vec![],
            bypassed_cert_misconfigs: Vec::new(),
            credential_backend: CredentialBackendKind::default(),
            integration_merge_verifiers: Vec::new(),
            git_default_target_ref: "refs/heads/main".to_owned(),
            git_target_ref_locked: false,
            git_auto_push:          false,
            git_push_remote:        String::new(),
            host_capacity:          HostCapacityConfig::default(),
            environments:           HashMap::new(),
            permitted_credentials:  Vec::new(),
            vm_images:              Vec::new(),
            default_executor_image: None,
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

    /// V2 `v2_extended_gaps.md §2.5` — per-session LLM token caps
    /// (`[budget.token_caps]`). `None` ⇒ section omitted ⇒ uncapped
    /// on every axis. The kernel's `session_spawn_orchestrator`
    /// projects the present caps into `RAXIS_PLANNER_MAX_TOKENS_*`
    /// env vars at spawn time; the in-VM dispatch loop enforces them
    /// via `DispatchOutcome::TokensExceeded`.
    pub fn token_caps(&self) -> Option<&TokenCapsSection> {
        self.token_caps.as_ref()
    }

    /// V2 `v2_extended_gaps.md §3.1` — per-session `sleep` tool
    /// budgets (`[budget.sleep_caps]`). `None` ⇒ section omitted ⇒
    /// the in-VM Sleep tool refuses every invocation
    /// (`FAIL_SLEEP_DISABLED`); operators MUST opt in by declaring
    /// the section.
    pub fn sleep_caps(&self) -> Option<&SleepCapsSection> {
        self.sleep_caps.as_ref()
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
    /// Test-only override for `[sessions].allowed_worktree_roots`.
    ///
    /// Used by the dashboard kernel-glue integration tests
    /// (`raxis-dashboard-kernel`) which need to surface real on-disk
    /// git worktrees through the dashboard API without going through
    /// a full `policy.toml` round-trip. Production code MUST NOT
    /// call this — it bypasses the validator's
    /// `allowed_worktree_roots is empty` rejection.
    #[cfg(any(debug_assertions, test))]
    pub fn set_allowed_worktree_roots_for_tests(&mut self, roots: Vec<String>) {
        self.allowed_worktree_roots = roots;
    }

    #[cfg(any(debug_assertions, test))]
    pub fn set_lanes_for_tests(&mut self, lanes: Vec<LaneEntry>) {
        self.lanes = lanes;
    }

    /// Test-only setter for `[budget].max_cost_per_task`. Used by the
    /// kernel V2.5 token-budget tests
    /// (`scheduler::budget::evaluate_token_budget_*`) to swing the
    /// admission ceiling without round-tripping a full `policy.toml`.
    #[cfg(any(debug_assertions, test))]
    pub fn set_max_cost_per_task_for_tests(&mut self, cents: u64) {
        self.max_cost_per_task = cents;
    }

    /// Test-only setter for `[[providers]]`. Used by the kernel V2.5
    /// token-budget tests to install pricing tables without
    /// round-tripping a full `policy.toml`.
    #[cfg(any(debug_assertions, test))]
    pub fn set_providers_for_tests(&mut self, providers: Vec<ProviderEntry>) {
        self.providers = providers;
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

    /// Resolve the absolute filesystem path for the kernel's
    /// unconditional notification inbox, given a `data_dir`.
    /// Equivalent to `<data_dir>/notifications/inbox.jsonl`.
    ///
    /// Used by `dispatch()` to write every notification before
    /// channel fan-out, and by `raxis inbox` to read the log.
    pub fn inbox_path_for(data_dir: &std::path::Path) -> std::path::PathBuf {
        data_dir.join("notifications").join(INBOX_FILENAME)
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
            token_caps: None,
            sleep_caps: None,
            policy_sha256: String::new(),
            signed_by: String::new(),
            signed_at: 0,
            claim_rules: Vec::new(),
            claim_default_action: String::new(),
            egress_domains: Vec::new(),
            egress_patterns: Vec::new(),
            egress_max_fetches_per_window: 0,
            notification_channels: vec![],
            notification_routes: HashMap::new(),
            default_notification_channels: vec![],
            bypassed_cert_misconfigs: Vec::new(),
            credential_backend: CredentialBackendKind::default(),
            integration_merge_verifiers: Vec::new(),
            git_default_target_ref: "refs/heads/main".to_owned(),
            git_target_ref_locked: false,
            git_auto_push:          false,
            git_push_remote:        String::new(),
            host_capacity:          HostCapacityConfig::default(),
            environments:           HashMap::new(),
            permitted_credentials:  Vec::new(),
            vm_images:              Vec::new(),
            default_executor_image: None,
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
    use super::ProviderPricing;
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

    /// V2 `v2_extended_gaps.md §2.5` — minimal pricing block for
    /// LLM-bearing provider fixtures. Operators MUST declare
    /// `pricing.input_tokens_per_dollar` and
    /// `pricing.output_tokens_per_dollar` for every model provider;
    /// `PolicyBundle::validate` rejects entries that omit them.
    /// These rates mirror Anthropic's published Sonnet pricing
    /// ($5 / 1M input, $20 / 1M output) so the fixture is realistic
    /// without being load-bearing on any specific provider.
    const LLM_PRICING_BLOCK: &str =
        "  pricing.input_tokens_per_dollar  = 200000\n\
          pricing.output_tokens_per_dollar = 50000\n";

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
        t.push_str(&format!(
            "\n[[providers]]\n\
             provider_id      = \"anthropic-prod\"\n\
             kind             = \"Anthropic\"\n\
             credentials_file = \"anthropic-prod.toml\"\n\
             {LLM_PRICING_BLOCK}",
        ));
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
        t.push_str(&format!(
            "\n[[providers]]\n\
             provider_id      = \"anthropic-prod\"\n\
             kind             = \"Anthropic\"\n\
             credentials_file = \"anthropic-prod.toml\"\n\
             {LLM_PRICING_BLOCK}",
        ));
        let bundle = write_and_load(&t).unwrap();
        assert!(bundle.provider("openai-prod").is_none());
    }

    // ── [[providers]] negative cases ─────────────────────────────────────

    #[test]
    fn duplicate_provider_id_is_rejected() {
        let mut t = minimal_policy_toml();
        for _ in 0..2 {
            t.push_str(&format!(
                "\n[[providers]]\n\
                 provider_id      = \"dup\"\n\
                 kind             = \"Anthropic\"\n\
                 credentials_file = \"x.toml\"\n\
                 {LLM_PRICING_BLOCK}",
            ));
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

    /// V2_GAPS §C9 — pin the lower bound of the per-provider
    /// `stream_idle_timeout_ms` band. 4 999 is one ms below the
    /// 5_000 floor; the validator MUST reject it so a typo can't
    /// accidentally produce sub-second flake-on-jitter behaviour.
    #[test]
    fn stream_idle_timeout_below_floor_is_rejected() {
        let mut t = minimal_policy_toml();
        t.push_str(
            "\n[[providers]]\n\
             provider_id            = \"p1\"\n\
             kind                   = \"Anthropic\"\n\
             credentials_file       = \"p1.toml\"\n\
             stream_idle_timeout_ms = 4999\n",
        );
        let err = write_and_load(&t).expect_err("idle < 5s must fail");
        let msg = format!("{err}");
        assert!(msg.contains("stream_idle_timeout_ms"), "msg = {msg}");
        assert!(msg.contains("4999"), "msg = {msg}");
    }

    /// Pin the upper bound of the per-provider
    /// `stream_idle_timeout_ms` band. 600_001 is one ms above the
    /// 600_000 ceiling.
    #[test]
    fn stream_idle_timeout_above_ceiling_is_rejected() {
        let mut t = minimal_policy_toml();
        t.push_str(
            "\n[[providers]]\n\
             provider_id            = \"p1\"\n\
             kind                   = \"Anthropic\"\n\
             credentials_file       = \"p1.toml\"\n\
             stream_idle_timeout_ms = 600001\n",
        );
        let err = write_and_load(&t).expect_err("idle > 600s must fail");
        let msg = format!("{err}");
        assert!(msg.contains("stream_idle_timeout_ms"), "msg = {msg}");
        assert!(msg.contains("600001"), "msg = {msg}");
    }

    /// 120 s (typical OpenAI o1/o3 reasoning-tier setting) MUST
    /// load cleanly — it's the central use case for this knob.
    #[test]
    fn stream_idle_timeout_120s_loads_cleanly_for_reasoning_models() {
        let mut t = minimal_policy_toml();
        t.push_str(&format!(
            "\n[[providers]]\n\
             provider_id            = \"openai-o1\"\n\
             kind                   = \"OpenAI\"\n\
             credentials_file       = \"openai.toml\"\n\
             stream_idle_timeout_ms = 120000\n\
             {LLM_PRICING_BLOCK}",
        ));
        let bundle = write_and_load(&t)
            .expect("120s must load — primary o1/o3 use case");
        assert_eq!(
            bundle.providers()[0].stream_idle_timeout_ms,
            Some(120_000),
        );
    }

    /// Absent field MUST default to `None` (gateway-side fallback
    /// to the 30s constant). A future refactor that flipped the
    /// default to `Some(30_000)` would silently change behaviour
    /// for every existing policy.toml in the wild.
    #[test]
    fn stream_idle_timeout_absent_field_is_none() {
        let mut t = minimal_policy_toml();
        t.push_str(&format!(
            "\n[[providers]]\n\
             provider_id      = \"p1\"\n\
             kind             = \"Anthropic\"\n\
             credentials_file = \"p1.toml\"\n\
             {LLM_PRICING_BLOCK}",
        ));
        let bundle = write_and_load(&t).expect("default policy must load");
        assert!(
            bundle.providers()[0].stream_idle_timeout_ms.is_none(),
            "absent field MUST surface as None (V2_GAPS §C9)",
        );
    }

    #[test]
    fn forward_compat_unknown_provider_kind_loads_at_validate_time() {
        // peripherals.md §3.2: unknown kinds are accepted at policy-validate
        // time (forward-compat); they will be rejected by the gateway at
        // dispatch time. This test pins the validate-time accept side.
        // NOTE: unknown kinds are NOT in `LLM_PROVIDER_KINDS`, so they
        // MUST NOT carry a pricing block (validator rejects pricing on
        // non-LLM kinds — see §2.5).
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

    // ── V2_GAPS §C5 sidecar provider validation ───────────────────────────

    /// 32-byte hex secret used by the sidecar tests.
    const SIDECAR_TEST_SECRET: &str =
        "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";

    #[test]
    fn sidecar_provider_with_required_fields_loads() {
        let mut t = minimal_policy_toml();
        t.push_str(&format!(
            "\n[[providers]]\n\
             provider_id              = \"kombai\"\n\
             kind                     = \"http_sidecar\"\n\
             credentials_file         = \"kombai.toml\"\n\
             sidecar_endpoint         = \"http://127.0.0.1:9100\"\n\
             sidecar_hmac_secret      = \"{SIDECAR_TEST_SECRET}\"\n\
             sidecar_health_check_path = \"/health\"\n\
             {LLM_PRICING_BLOCK}",
        ));
        let bundle = write_and_load(&t).expect("valid sidecar provider must load");
        let p = bundle.provider("kombai").expect("lookup by id works");
        assert_eq!(p.kind, "http_sidecar");
        assert_eq!(p.sidecar_endpoint.as_deref(), Some("http://127.0.0.1:9100"));
        assert_eq!(p.sidecar_hmac_secret.as_deref(), Some(SIDECAR_TEST_SECRET));
        assert_eq!(p.sidecar_health_check_path.as_deref(), Some("/health"));
    }

    #[test]
    fn sidecar_provider_missing_endpoint_is_rejected() {
        let mut t = minimal_policy_toml();
        t.push_str(&format!(
            "\n[[providers]]\n\
             provider_id         = \"kombai\"\n\
             kind                = \"http_sidecar\"\n\
             credentials_file    = \"kombai.toml\"\n\
             sidecar_hmac_secret = \"{SIDECAR_TEST_SECRET}\"\n",
        ));
        let err = write_and_load(&t).expect_err("missing endpoint must fail");
        let s = format!("{err}");
        assert!(s.contains("sidecar_endpoint"), "got: {s}");
    }

    #[test]
    fn sidecar_provider_missing_secret_is_rejected() {
        let mut t = minimal_policy_toml();
        t.push_str(
            "\n[[providers]]\n\
             provider_id      = \"kombai\"\n\
             kind             = \"http_sidecar\"\n\
             credentials_file = \"kombai.toml\"\n\
             sidecar_endpoint = \"http://127.0.0.1:9100\"\n",
        );
        let err = write_and_load(&t).expect_err("missing secret must fail");
        let s = format!("{err}");
        assert!(s.contains("sidecar_hmac_secret"), "got: {s}");
    }

    #[test]
    fn sidecar_endpoint_without_http_scheme_is_rejected() {
        let mut t = minimal_policy_toml();
        t.push_str(&format!(
            "\n[[providers]]\n\
             provider_id         = \"kombai\"\n\
             kind                = \"http_sidecar\"\n\
             credentials_file    = \"kombai.toml\"\n\
             sidecar_endpoint    = \"127.0.0.1:9100\"\n\
             sidecar_hmac_secret = \"{SIDECAR_TEST_SECRET}\"\n",
        ));
        let err = write_and_load(&t).expect_err("scheme-less endpoint must fail");
        let s = format!("{err}");
        assert!(s.contains("http://"), "got: {s}");
    }

    #[test]
    fn sidecar_secret_too_short_is_rejected() {
        let mut t = minimal_policy_toml();
        t.push_str(
            "\n[[providers]]\n\
             provider_id         = \"kombai\"\n\
             kind                = \"http_sidecar\"\n\
             credentials_file    = \"kombai.toml\"\n\
             sidecar_endpoint    = \"http://127.0.0.1:9100\"\n\
             sidecar_hmac_secret = \"deadbeef\"\n",
        );
        let err = write_and_load(&t).expect_err("short secret must fail");
        let s = format!("{err}");
        assert!(s.contains("sidecar_hmac_secret"), "got: {s}");
    }

    #[test]
    fn sidecar_secret_with_non_hex_is_rejected() {
        let mut t = minimal_policy_toml();
        t.push_str(
            "\n[[providers]]\n\
             provider_id         = \"kombai\"\n\
             kind                = \"http_sidecar\"\n\
             credentials_file    = \"kombai.toml\"\n\
             sidecar_endpoint    = \"http://127.0.0.1:9100\"\n\
             sidecar_hmac_secret = \"GGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG\"\n",
        );
        let err = write_and_load(&t).expect_err("non-hex secret must fail");
        let s = format!("{err}");
        assert!(s.contains("hex"), "got: {s}");
    }

    #[test]
    fn non_sidecar_provider_with_sidecar_fields_is_rejected() {
        // Defence-in-depth: a typo on `kind` (e.g. `Anthropic` instead
        // of `http_sidecar`) MUST NOT silently accept the sidecar
        // fields and let the planner skip the sidecar codepath.
        let mut t = minimal_policy_toml();
        t.push_str(&format!(
            "\n[[providers]]\n\
             provider_id         = \"oops\"\n\
             kind                = \"Anthropic\"\n\
             credentials_file    = \"oops.toml\"\n\
             sidecar_endpoint    = \"http://127.0.0.1:9100\"\n\
             sidecar_hmac_secret = \"{SIDECAR_TEST_SECRET}\"\n",
        ));
        let err = write_and_load(&t).expect_err("non-sidecar with sidecar fields must fail");
        let s = format!("{err}");
        assert!(s.contains("sidecar_endpoint"), "got: {s}");
    }

    // ── V2 §2.5 provider pricing — validation + cost math ──────────────

    /// Anthropic / OpenAI / Gemini / Bedrock / http_sidecar all
    /// land in `LLM_PROVIDER_KINDS`. Omitting `pricing` on ANY of
    /// them MUST fail at policy-validate time with a clear message
    /// pointing at §2.5.
    #[test]
    fn llm_provider_without_pricing_is_rejected() {
        for kind in &["Anthropic", "OpenAI", "Gemini", "Bedrock"] {
            let mut t = minimal_policy_toml();
            t.push_str(&format!(
                "\n[[providers]]\n\
                 provider_id      = \"prov-{kind}\"\n\
                 kind             = \"{kind}\"\n\
                 credentials_file = \"creds.toml\"\n",
            ));
            let err = write_and_load(&t).expect_err(&format!(
                "{kind} without pricing must be rejected (§2.5)"
            ));
            let s = format!("{err}");
            assert!(s.contains("pricing"), "[{kind}] msg = {s}");
            assert!(s.contains("v2_extended_gaps.md §2.5"),
                "[{kind}] error must cite the spec; got: {s}");
        }
    }

    /// A non-LLM `kind` MUST NOT carry a `pricing` table — the
    /// validator rejects so a typo on `kind` cannot accidentally
    /// silence pricing enforcement.
    #[test]
    fn non_llm_provider_with_pricing_is_rejected() {
        let mut t = minimal_policy_toml();
        t.push_str(&format!(
            "\n[[providers]]\n\
             provider_id      = \"future-vendor\"\n\
             kind             = \"NotAValidKindYet\"\n\
             credentials_file = \"future.toml\"\n\
             {LLM_PRICING_BLOCK}",
        ));
        let err = write_and_load(&t).expect_err(
            "non-LLM kind with pricing must be rejected (§2.5)"
        );
        let s = format!("{err}");
        assert!(s.contains("pricing"), "msg = {s}");
        assert!(s.contains("not a model provider"), "msg = {s}");
    }

    /// `pricing.input_tokens_per_dollar = 0` is a divide-by-zero
    /// landmine. The validator rejects so the kernel never has to
    /// guard against it at cost-computation time.
    #[test]
    fn llm_provider_with_zero_input_pricing_is_rejected() {
        let mut t = minimal_policy_toml();
        t.push_str(
            "\n[[providers]]\n\
             provider_id      = \"anthropic-prod\"\n\
             kind             = \"Anthropic\"\n\
             credentials_file = \"a.toml\"\n  \
             pricing.input_tokens_per_dollar  = 0\n  \
             pricing.output_tokens_per_dollar = 50000\n",
        );
        let err = write_and_load(&t).expect_err("zero input rate must be rejected");
        let s = format!("{err}");
        assert!(s.contains("input_tokens_per_dollar"), "msg = {s}");
    }

    #[test]
    fn llm_provider_with_zero_output_pricing_is_rejected() {
        let mut t = minimal_policy_toml();
        t.push_str(
            "\n[[providers]]\n\
             provider_id      = \"anthropic-prod\"\n\
             kind             = \"Anthropic\"\n\
             credentials_file = \"a.toml\"\n  \
             pricing.input_tokens_per_dollar  = 200000\n  \
             pricing.output_tokens_per_dollar = 0\n",
        );
        let err = write_and_load(&t).expect_err("zero output rate must be rejected");
        let s = format!("{err}");
        assert!(s.contains("output_tokens_per_dollar"), "msg = {s}");
    }

    /// Optional cache rates default to inheriting `input_tokens_per_dollar`
    /// (no surcharge / no discount) when omitted. When provided, they
    /// MUST be > 0.
    #[test]
    fn llm_provider_with_zero_cache_read_rate_is_rejected() {
        let mut t = minimal_policy_toml();
        t.push_str(
            "\n[[providers]]\n\
             provider_id      = \"anthropic-prod\"\n\
             kind             = \"Anthropic\"\n\
             credentials_file = \"a.toml\"\n  \
             pricing.input_tokens_per_dollar       = 200000\n  \
             pricing.output_tokens_per_dollar      = 50000\n  \
             pricing.cache_read_tokens_per_dollar  = 0\n",
        );
        let err = write_and_load(&t).expect_err("zero cache_read rate must be rejected");
        let s = format!("{err}");
        assert!(s.contains("cache_read_tokens_per_dollar"), "msg = {s}");
    }

    /// Round-trip a realistic Anthropic-Sonnet rate set and assert
    /// `provider().pricing` decodes verbatim.
    #[test]
    fn llm_provider_with_full_pricing_decodes_round_trip() {
        let mut t = minimal_policy_toml();
        t.push_str(
            "\n[[providers]]\n\
             provider_id      = \"anthropic-prod\"\n\
             kind             = \"Anthropic\"\n\
             credentials_file = \"a.toml\"\n  \
             pricing.input_tokens_per_dollar          = 200000\n  \
             pricing.output_tokens_per_dollar         = 50000\n  \
             pricing.cache_read_tokens_per_dollar     = 2000000\n  \
             pricing.cache_creation_tokens_per_dollar = 160000\n",
        );
        let bundle = write_and_load(&t).expect("full pricing must load");
        let p = bundle.provider("anthropic-prod").unwrap();
        let pricing = p.pricing.as_ref().expect("pricing decoded");
        assert_eq!(pricing.input_tokens_per_dollar,         200_000);
        assert_eq!(pricing.output_tokens_per_dollar,        50_000);
        assert_eq!(pricing.cache_read_tokens_per_dollar,     Some(2_000_000));
        assert_eq!(pricing.cache_creation_tokens_per_dollar, Some(160_000));
    }

    // ── ProviderPricing::cost_micro_dollars unit math ──────────────────

    fn anthropic_sonnet_pricing() -> ProviderPricing {
        ProviderPricing {
            input_tokens_per_dollar:           200_000,   // $5  / 1M input
            output_tokens_per_dollar:          50_000,    // $20 / 1M output
            cache_read_tokens_per_dollar:      Some(2_000_000),  // $0.50 / 1M
            cache_creation_tokens_per_dollar:  Some(160_000),    // $6.25 / 1M
        }
    }

    #[test]
    fn cost_micro_dollars_input_only() {
        let p = anthropic_sonnet_pricing();
        // 200 input tokens at $5/1M = $0.001 = 1000 µ$.
        assert_eq!(p.cost_micro_dollars(200, 0, 0, 0), 1_000);
    }

    #[test]
    fn cost_micro_dollars_output_only() {
        let p = anthropic_sonnet_pricing();
        // 50 output tokens at $20/1M = $0.001 = 1000 µ$.
        assert_eq!(p.cost_micro_dollars(0, 50, 0, 0), 1_000);
    }

    #[test]
    fn cost_micro_dollars_combined_input_output_cache() {
        let p = anthropic_sonnet_pricing();
        // 200 in @ 5/1M + 50 out @ 20/1M + 200 cache_read @ 0.5/1M
        //   + 200 cache_creation @ 6.25/1M
        // = 1000 + 1000 + 100 + 1250 = 3350 µ$.
        assert_eq!(p.cost_micro_dollars(200, 50, 200, 200), 3_350);
    }

    /// Omitting cache rates inherits `input_tokens_per_dollar`
    /// (no surcharge / no discount).
    #[test]
    fn cost_micro_dollars_cache_rates_default_to_input_rate() {
        let p = ProviderPricing {
            input_tokens_per_dollar:           200_000,
            output_tokens_per_dollar:          50_000,
            cache_read_tokens_per_dollar:      None,  // ← inherit
            cache_creation_tokens_per_dollar:  None,  // ← inherit
        };
        // 200 cache_read at the inherited input rate ($5/1M) =
        // $0.001 = 1000 µ$.
        assert_eq!(p.cost_micro_dollars(0, 0, 200, 0), 1_000);
        assert_eq!(p.cost_micro_dollars(0, 0, 0, 200), 1_000);
    }

    /// Saturate-not-panic for absurd inputs: u64::MAX tokens against
    /// any positive rate would overflow `tokens * 1_000_000` if we
    /// stayed in u64; the implementation widens to u128 and then
    /// saturates back into u64 on the way out.
    #[test]
    fn cost_micro_dollars_saturates_on_extreme_input() {
        let p = ProviderPricing {
            input_tokens_per_dollar:           1, // 1 token per dollar
            output_tokens_per_dollar:          1,
            cache_read_tokens_per_dollar:      None,
            cache_creation_tokens_per_dollar:  None,
        };
        let _ = p.cost_micro_dollars(u64::MAX, 0, 0, 0);
        let _ = p.cost_micro_dollars(0, u64::MAX, 0, 0);
        let _ = p.cost_micro_dollars(u64::MAX, u64::MAX, u64::MAX, u64::MAX);
    }

    // ── V2 §2.5 [budget.token_caps] — schema + accessor + validation ──

    /// Omitting the `[budget.token_caps]` table leaves `token_caps()`
    /// as `None` — that's how the kernel knows to skip env stamping.
    /// This MUST be byte-for-byte equivalent to today's behaviour
    /// (no kernel regression for unmigrated policies).
    #[test]
    fn token_caps_section_absent_is_none() {
        let bundle = write_and_load(&minimal_policy_toml())
            .expect("minimal policy without token_caps must load");
        assert!(bundle.token_caps().is_none(),
            "absent [budget.token_caps] MUST surface as None");
    }

    /// All three caps round-trip verbatim into the accessor.
    #[test]
    fn token_caps_section_all_fields_round_trip() {
        let mut t = minimal_policy_toml();
        t.push_str(
            "\n[budget.token_caps]\n\
             max_input_tokens_per_session  = 200000\n\
             max_output_tokens_per_session = 100000\n\
             max_total_tokens_per_session  = 250000\n",
        );
        let bundle = write_and_load(&t).expect("token_caps must load");
        let caps = bundle.token_caps().expect("token_caps decoded");
        assert_eq!(caps.max_input_tokens_per_session,  Some(200_000));
        assert_eq!(caps.max_output_tokens_per_session, Some(100_000));
        assert_eq!(caps.max_total_tokens_per_session,  Some(250_000));
    }

    /// Partial table — operators can declare only one axis.
    #[test]
    fn token_caps_section_partial_round_trip() {
        let mut t = minimal_policy_toml();
        t.push_str(
            "\n[budget.token_caps]\n\
             max_total_tokens_per_session  = 50000\n",
        );
        let bundle = write_and_load(&t).expect("partial token_caps must load");
        let caps = bundle.token_caps().expect("token_caps decoded");
        assert_eq!(caps.max_input_tokens_per_session,  None);
        assert_eq!(caps.max_output_tokens_per_session, None);
        assert_eq!(caps.max_total_tokens_per_session,  Some(50_000));
    }

    /// `cap = 0` is rejected: it would terminate the dispatch loop
    /// before the first model call. Always an operator typo.
    #[test]
    fn token_caps_zero_input_is_rejected() {
        let mut t = minimal_policy_toml();
        t.push_str(
            "\n[budget.token_caps]\n\
             max_input_tokens_per_session = 0\n",
        );
        let err = write_and_load(&t).expect_err("zero input cap must be rejected");
        let s = format!("{err}");
        assert!(s.contains("max_input_tokens_per_session"), "msg = {s}");
        assert!(s.contains("never useful"), "msg = {s}");
    }

    #[test]
    fn token_caps_zero_output_is_rejected() {
        let mut t = minimal_policy_toml();
        t.push_str(
            "\n[budget.token_caps]\n\
             max_output_tokens_per_session = 0\n",
        );
        let err = write_and_load(&t).expect_err("zero output cap must be rejected");
        let s = format!("{err}");
        assert!(s.contains("max_output_tokens_per_session"), "msg = {s}");
    }

    #[test]
    fn token_caps_zero_total_is_rejected() {
        let mut t = minimal_policy_toml();
        t.push_str(
            "\n[budget.token_caps]\n\
             max_total_tokens_per_session = 0\n",
        );
        let err = write_and_load(&t).expect_err("zero total cap must be rejected");
        let s = format!("{err}");
        assert!(s.contains("max_total_tokens_per_session"), "msg = {s}");
    }

    // ── V2 §3.1 [budget.sleep_caps] — schema + accessor + validation ──

    /// Omitting `[budget.sleep_caps]` leaves the accessor as `None` —
    /// the kernel uses that to register `SleepTool::disabled()`.
    #[test]
    fn sleep_caps_section_absent_is_none() {
        let bundle = write_and_load(&minimal_policy_toml())
            .expect("minimal policy without sleep_caps must load");
        assert!(bundle.sleep_caps().is_none(),
            "absent [budget.sleep_caps] MUST surface as None");
    }

    #[test]
    fn sleep_caps_section_round_trip() {
        let mut t = minimal_policy_toml();
        t.push_str(
            "\n[budget.sleep_caps]\n\
             max_seconds_per_call   = 60\n\
             max_cumulative_seconds = 300\n",
        );
        let bundle = write_and_load(&t).expect("sleep_caps must load");
        let caps = bundle.sleep_caps().expect("sleep_caps decoded");
        assert_eq!(caps.max_seconds_per_call,   60);
        assert_eq!(caps.max_cumulative_seconds, 300);
    }

    #[test]
    fn sleep_caps_zero_per_call_is_rejected() {
        let mut t = minimal_policy_toml();
        t.push_str(
            "\n[budget.sleep_caps]\n\
             max_seconds_per_call   = 0\n\
             max_cumulative_seconds = 60\n",
        );
        let err = write_and_load(&t).expect_err("zero per-call MUST be rejected");
        let s = format!("{err}");
        assert!(s.contains("max_seconds_per_call"), "msg = {s}");
    }

    #[test]
    fn sleep_caps_zero_cumulative_is_rejected() {
        let mut t = minimal_policy_toml();
        t.push_str(
            "\n[budget.sleep_caps]\n\
             max_seconds_per_call   = 60\n\
             max_cumulative_seconds = 0\n",
        );
        let err = write_and_load(&t).expect_err("zero cumulative MUST be rejected");
        let s = format!("{err}");
        assert!(s.contains("max_cumulative_seconds"), "msg = {s}");
    }

    #[test]
    fn sleep_caps_per_call_above_hard_ceiling_is_rejected() {
        let mut t = minimal_policy_toml();
        t.push_str(
            "\n[budget.sleep_caps]\n\
             max_seconds_per_call   = 700\n\
             max_cumulative_seconds = 7000\n",
        );
        let err = write_and_load(&t).expect_err("700 > 600 hard ceiling MUST reject");
        let s = format!("{err}");
        assert!(s.contains("hard ceiling of 600"), "msg = {s}");
    }

    #[test]
    fn sleep_caps_cumulative_below_per_call_is_rejected() {
        let mut t = minimal_policy_toml();
        t.push_str(
            "\n[budget.sleep_caps]\n\
             max_seconds_per_call   = 60\n\
             max_cumulative_seconds = 30\n",
        );
        let err = write_and_load(&t).expect_err(
            "cumulative < per-call MUST be rejected as nonsensical",
        );
        let s = format!("{err}");
        assert!(s.contains("max_cumulative_seconds"), "msg = {s}");
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

    // ── No implicit channel synthesis ─────────────────────────────────

    #[test]
    fn no_notifications_section_produces_empty_channels_and_defaults() {
        // inbox.jsonl + SQLite are unconditional — omitting
        // [notifications] produces zero channels and empty defaults.
        let bundle = write_and_load(&minimal_with_notifications(""))
            .expect("policy without [notifications] must load cleanly");

        let chans = bundle.notification_channels();
        assert!(chans.is_empty(), "no channels when section is omitted; got {chans:?}");

        let defaults = bundle.default_notification_channels();
        assert!(defaults.is_empty(),
            "default_channels is empty when omitted (inbox is unconditional)");

        assert!(bundle.notification_route("EscalationApproved").is_none(),
            "no explicit routes ⇒ None ⇒ caller uses default channels");
    }

    #[test]
    fn inbox_path_for_data_dir_is_canonical_path() {
        let p = PolicyBundle::inbox_path_for(std::path::Path::new("/tmp/raxis"));
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

    // ── route validation ─────────────────────────────────────────────

    #[test]
    fn route_with_unknown_event_kind_is_rejected() {
        let toml = minimal_with_notifications("
[[notifications.channels]]
id     = \"audit-mirror\"
kind   = \"File\"
target = \"/tmp/audit.jsonl\"

[[notifications.routes]]
event_kind = \"NotARealAuditEventKind\"
channels   = [\"audit-mirror\"]
");
        let err = write_and_load(&toml).expect_err("typo must fail");
        let s = format!("{err}");
        assert!(s.contains("not a known AuditEventKind"),
            "error must mention the AuditEventKind list; got: {s}");
    }

    #[test]
    fn route_with_unknown_channel_id_is_rejected() {
        let toml = minimal_with_notifications("
[[notifications.channels]]
id     = \"audit-mirror\"
kind   = \"File\"
target = \"/tmp/audit.jsonl\"

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
            AuditEventKind::IntegrationMergeCompleted { initiative_id: "x".into(), session_id: "x".into(), commit_sha: "x".into(), previous_sha: "x".into(), operator_assisted: false, escalation_id: None, target_ref: "refs/heads/main".into() }.as_str(),
            AuditEventKind::PushAttempted { initiative_id: "x".into(), commit_sha: "x".into(), remote: "x".into(), refspec: "x".into() }.as_str(),
            AuditEventKind::PushCompleted { initiative_id: "x".into(), commit_sha: "x".into(), remote: "x".into(), refspec: "x".into(), summary: "x".into() }.as_str(),
            AuditEventKind::PushFailed    { initiative_id: "x".into(), commit_sha: "x".into(), remote: "x".into(), refspec: "x".into(), category: "x".into(), reason: "x".into() }.as_str(),
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
            // V2_GAPS §C7 — credential CLI ceremony events.
            AuditEventKind::CredentialRegistered {
                name:               "x".into(),
                proxy_type:         "x".into(),
                environment:        "x".into(),
                actor_fingerprint:  "x".into(),
                backend_kind:       "x".into(),
            }.as_str(),
            AuditEventKind::CredentialRemoved {
                name:               "x".into(),
                actor_fingerprint:  "x".into(),
                backend_kind:       "x".into(),
                forced:             false,
            }.as_str(),
            AuditEventKind::CredentialVerified {
                name:               "x".into(),
                proxy_type:         "x".into(),
                success:            false,
                latency_ms:         0,
                actor_fingerprint:  "x".into(),
                backend_kind:       "x".into(),
            }.as_str(),
            // V2_GAPS §D1 — cert-revocation ceremony events.
            AuditEventKind::OperatorCertRevoked {
                subject_pubkey_fingerprint:    "x".into(),
                subject_display_name:          None,
                reason:                        "Rotation".into(),
                revoked_at:                    0,
                reference:                     "x".into(),
                revoked_by_pubkey_fingerprint: "x".into(),
            }.as_str(),
            AuditEventKind::OperatorCertRevokedOpDenied {
                pubkey_fingerprint: "x".into(),
                epoch_id:           0,
                op:                 "x".into(),
                reason:             "Rotation".into(),
                revoked_at:         0,
            }.as_str(),
            // V2_GAPS §D2 — host-capacity admission + watchdogs.
            AuditEventKind::AdmissionDeferredAtCap {
                cap_kind:        "VmCount".into(),
                current_running: 0,
                cap:             0,
                initiative_id:   None,
                task_id:         None,
            }.as_str(),
            AuditEventKind::AdmissionQueueFull {
                intent_kind:        "x".into(),
                operator:           None,
                rejected_at_depth:  0,
            }.as_str(),
            AuditEventKind::DiskFullHaltEntered {
                free_mb:  0,
                cap_mb:   0,
                behavior: "halt_admit".into(),
            }.as_str(),
            AuditEventKind::DiskHealthyAfterFull {
                previous_free_mb:      0,
                current_free_mb:       0,
                halt_duration_seconds: 0,
            }.as_str(),
            AuditEventKind::OperatorAttentionRequired {
                attention_kind: "DiskFull".into(),
                details:        "x".into(),
            }.as_str(),
            AuditEventKind::KernelPushEnqueued {
                session_id:    "sess-1".into(),
                push_id:       1,
                push_kind:     "SubTaskActivated".into(),
                initiative_id: None,
                task_id:       None,
            }.as_str(),
            // V2_GAPS §12.4 — operator-ergonomics IPC dry-run audit event.
            AuditEventKind::DryRunAdmitted {
                submitted_by:   "x".into(),
                policy_epoch:   0,
                plan_sha256:    "x".into(),
                target_ref:     "x".into(),
                warnings_count: 0,
                lane_id:        "x".into(),
                task_count:     0,
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

// ─────────────────────────────────────────────────────────────────────────────
// V2_GAPS §E1 — environment-binding validation tests
// (`environment-access-control.md §5b.3`).
// ─────────────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod environment_tests {
    use super::*;

    fn env_section(description: &str, ack: bool) -> EnvironmentSection {
        EnvironmentSection {
            description:               Some(description.to_owned()),
            same_cluster_acknowledged: ack,
            extras:                    HashMap::new(),
        }
    }

    fn env_section_with_extras(
        description: &str, ack: bool, extras: Vec<(&str, toml::Value)>,
    ) -> EnvironmentSection {
        let mut e = HashMap::new();
        for (k, v) in extras { e.insert(k.to_owned(), v); }
        EnvironmentSection {
            description:               Some(description.to_owned()),
            same_cluster_acknowledged: ack,
            extras:                    e,
        }
    }

    #[test]
    fn label_syntax_accepts_canonical_labels() {
        for ok in &["beta", "prod-1", "staging_us", "x", "a0123456789"] {
            assert!(is_valid_env_label(ok), "expected `{ok}` to be valid");
        }
    }

    #[test]
    fn label_syntax_rejects_uppercase_and_long_labels() {
        for bad in &["", "Beta", "PROD", "1prod", "-prod",
                     "a234567890123456789012345678901234"] {
            assert!(!is_valid_env_label(bad), "expected `{bad}` to be rejected");
        }
    }

    #[test]
    fn validate_environments_accepts_minimal_section() {
        let mut raw = HashMap::new();
        raw.insert("beta".to_owned(), env_section("beta cluster", false));
        let out = validate_environments(&raw).expect("must validate");
        assert_eq!(out.len(), 1);
        let beta = out.get("beta").unwrap();
        assert_eq!(beta.description, "beta cluster");
        assert!(!beta.same_cluster_acknowledged);
    }

    #[test]
    fn validate_environments_rejects_invalid_label() {
        let mut raw = HashMap::new();
        raw.insert("Beta".to_owned(), env_section("beta cluster", false));
        let err = validate_environments(&raw)
            .expect_err("uppercase label must be rejected");
        let msg = err.to_string();
        assert!(msg.contains("FAIL_POLICY_ENV_LABEL_INVALID"), "{msg}");
    }

    #[test]
    fn validate_environments_rejects_missing_description() {
        let mut raw = HashMap::new();
        raw.insert("beta".to_owned(), EnvironmentSection {
            description: None, same_cluster_acknowledged: false,
            extras: HashMap::new(),
        });
        let err = validate_environments(&raw)
            .expect_err("missing description must be rejected");
        assert!(err.to_string().contains("FAIL_POLICY_ENV_UNKNOWN_FIELD"));
    }

    #[test]
    fn validate_environments_tolerates_reserved_extra_fields() {
        let mut raw = HashMap::new();
        raw.insert("beta".to_owned(), env_section_with_extras(
            "beta cluster", false,
            vec![("blast_radius", toml::Value::String("high".into()))],
        ));
        validate_environments(&raw)
            .expect("reserved fields must be tolerated (V2.x forward-compat)");
    }

    #[test]
    fn validate_environments_rejects_unknown_extra_field() {
        let mut raw = HashMap::new();
        raw.insert("beta".to_owned(), env_section_with_extras(
            "beta cluster", false,
            vec![("frobnitz", toml::Value::String("x".into()))],
        ));
        let err = validate_environments(&raw)
            .expect_err("unknown field must be rejected");
        assert!(err.to_string().contains("FAIL_POLICY_ENV_UNKNOWN_FIELD"));
    }

    #[test]
    fn validate_permitted_credentials_resolves_known_environment() {
        let mut envs = HashMap::new();
        envs.insert("beta".to_owned(), env_section("beta", false));
        let raw = vec![PermittedCredentialEntry {
            name:        "k8s-beta".to_owned(),
            environment: Some("beta".to_owned()),
            description: None,
        }];
        let out = validate_permitted_credentials(&raw, &envs).expect("must validate");
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].environment.as_deref(), Some("beta"));
    }

    #[test]
    fn validate_permitted_credentials_rejects_undeclared_environment() {
        let envs = HashMap::new();
        let raw = vec![PermittedCredentialEntry {
            name:        "k8s-prod".to_owned(),
            environment: Some("production".to_owned()),
            description: None,
        }];
        let err = validate_permitted_credentials(&raw, &envs).expect_err("must reject");
        assert!(err.to_string().contains("FAIL_POLICY_ENV_LABEL_UNDECLARED"));
    }

    #[test]
    fn validate_permitted_credentials_accepts_neutral_credential() {
        let envs = HashMap::new();
        let raw = vec![PermittedCredentialEntry {
            name:        "npm-registry".to_owned(),
            environment: None,
            description: Some("public npm read token".to_owned()),
        }];
        let out = validate_permitted_credentials(&raw, &envs).expect("must validate");
        assert_eq!(out.len(), 1);
        assert!(out[0].environment.is_none());
    }

    #[test]
    fn validate_permitted_credentials_rejects_duplicate_names() {
        let envs = HashMap::new();
        let raw = vec![
            PermittedCredentialEntry {
                name: "tok".to_owned(), environment: None, description: None,
            },
            PermittedCredentialEntry {
                name: "tok".to_owned(), environment: None, description: None,
            },
        ];
        let err = validate_permitted_credentials(&raw, &envs).expect_err("must reject");
        assert!(err.to_string().contains("FAIL_POLICY_PERMITTED_CRED_INVALID"));
    }

    // ── V2.5 `[[vm_images]]` tests ──────────────────────────────────────────

    fn vm_image_entry(
        name:                     &str,
        digest_hex:               &str,
        roles:                    &[&str],
        linux_kernel_version_min: Option<&str>,
    ) -> VmImageEntry {
        VmImageEntry {
            name: name.to_owned(),
            oci_digest: format!("sha256:{digest_hex}"),
            role_restriction: roles.iter().map(|r| (*r).to_owned()).collect(),
            linux_kernel_version_min: linux_kernel_version_min.map(|s| s.to_owned()),
            description: None,
        }
    }

    /// 64-char lowercase-hex stub used by the validator tests so they
    /// don't depend on real image digests.
    const STUB_DIGEST_HEX: &str =
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn validate_vm_images_accepts_minimal_entry() {
        let raw = vec![vm_image_entry(
            "raxis-executor-starter",
            STUB_DIGEST_HEX,
            &["Executor"],
            Some("5.14"),
        )];
        let out = validate_vm_images(&raw).expect("must validate");
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].name, "raxis-executor-starter");
        assert_eq!(out[0].linux_kernel_version_min, (5, 14));
        assert!(out[0].permits_role("Executor"));
        assert!(!out[0].permits_role("Verifier"));
    }

    #[test]
    fn validate_vm_images_rejects_uppercase_name() {
        let raw = vec![vm_image_entry(
            "Executor-Starter",
            STUB_DIGEST_HEX,
            &["Executor"],
            Some("5.14"),
        )];
        let err = validate_vm_images(&raw).expect_err("must reject");
        assert!(
            err.to_string().contains("FAIL_POLICY_VM_IMAGE_NAME_INVALID"),
            "{err}"
        );
    }

    #[test]
    fn validate_vm_images_rejects_reserved_alias() {
        let raw = vec![vm_image_entry(
            RESERVED_SYMBOL_INDEX_VM_IMAGE_NAME,
            STUB_DIGEST_HEX,
            &["Verifier"],
            Some("5.14"),
        )];
        let err = validate_vm_images(&raw).expect_err("must reject");
        assert!(
            err.to_string()
                .contains("FAIL_POLICY_RESERVED_VM_IMAGE_NAME"),
            "{err}"
        );
    }

    #[test]
    fn validate_vm_images_rejects_duplicate_names() {
        let raw = vec![
            vm_image_entry("img-a", STUB_DIGEST_HEX, &["Executor"], Some("5.14")),
            vm_image_entry("img-a", STUB_DIGEST_HEX, &["Verifier"], Some("5.14")),
        ];
        let err = validate_vm_images(&raw).expect_err("must reject");
        assert!(
            err.to_string().contains("FAIL_POLICY_VM_IMAGE_DUPLICATE"),
            "{err}"
        );
    }

    #[test]
    fn validate_vm_images_rejects_invalid_digest() {
        let mut entry = vm_image_entry(
            "img-a", STUB_DIGEST_HEX, &["Executor"], Some("5.14"),
        );
        entry.oci_digest = "sha256:NOTHEX".to_owned();
        let err = validate_vm_images(&[entry]).expect_err("must reject");
        assert!(
            err.to_string()
                .contains("FAIL_POLICY_VM_IMAGE_DIGEST_INVALID"),
            "{err}"
        );
    }

    #[test]
    fn validate_vm_images_rejects_missing_role_restriction() {
        let raw = vec![vm_image_entry(
            "img-a", STUB_DIGEST_HEX, &[], Some("5.14"),
        )];
        let err = validate_vm_images(&raw).expect_err("must reject");
        assert!(
            err.to_string()
                .contains("FAIL_POLICY_VM_IMAGE_ROLE_RESTRICTION_REQUIRED"),
            "{err}"
        );
    }

    #[test]
    fn validate_vm_images_rejects_reviewer_role_restriction() {
        let raw = vec![vm_image_entry(
            "img-rev", STUB_DIGEST_HEX, &["Reviewer"], Some("5.14"),
        )];
        let err = validate_vm_images(&raw).expect_err("must reject");
        assert!(
            err.to_string()
                .contains("FAIL_REVIEWER_VM_IMAGE_NOT_ALLOWED"),
            "{err}"
        );
    }

    #[test]
    fn validate_vm_images_rejects_orchestrator_role_restriction() {
        let raw = vec![vm_image_entry(
            "img-orch", STUB_DIGEST_HEX, &["Orchestrator"], Some("5.14"),
        )];
        let err = validate_vm_images(&raw).expect_err("must reject");
        assert!(
            err.to_string()
                .contains("FAIL_ORCHESTRATOR_VM_IMAGE_NOT_ALLOWED"),
            "{err}"
        );
    }

    #[test]
    fn validate_vm_images_rejects_unknown_role() {
        let raw = vec![vm_image_entry(
            "img-x", STUB_DIGEST_HEX, &["Frobnitz"], Some("5.14"),
        )];
        let err = validate_vm_images(&raw).expect_err("must reject");
        assert!(
            err.to_string()
                .contains("FAIL_POLICY_INVALID_ROLE_RESTRICTION"),
            "{err}"
        );
    }

    #[test]
    fn validate_vm_images_rejects_kernel_version_below_floor() {
        let raw = vec![vm_image_entry(
            "img-a", STUB_DIGEST_HEX, &["Executor"], Some("5.4"),
        )];
        let err = validate_vm_images(&raw).expect_err("must reject");
        assert!(
            err.to_string().contains("FAIL_VM_GUEST_LINUX_KERNEL_TOO_OLD"),
            "{err}"
        );
    }

    #[test]
    fn validate_vm_images_rejects_missing_kernel_version() {
        let raw = vec![vm_image_entry(
            "img-a", STUB_DIGEST_HEX, &["Executor"], None,
        )];
        let err = validate_vm_images(&raw).expect_err("must reject");
        assert!(
            err.to_string().contains(
                "FAIL_POLICY_VM_IMAGE_LINUX_KERNEL_VERSION_MIN_REQUIRED"
            ),
            "{err}"
        );
    }

    #[test]
    fn validate_default_executor_image_returns_none_when_omitted() {
        let out = validate_default_executor_image(None, &[])
            .expect("must accept omission");
        assert!(out.is_none());
    }

    #[test]
    fn validate_default_executor_image_resolves_alias() {
        let registry = validate_vm_images(&[vm_image_entry(
            "primary-exec", STUB_DIGEST_HEX, &["Executor"], Some("5.14"),
        )])
        .expect("registry must validate");
        let section = DefaultExecutorImageSection {
            alias: "primary-exec".to_owned(),
        };
        let out = validate_default_executor_image(Some(&section), &registry)
            .expect("must validate")
            .expect("must be Some");
        assert_eq!(out.alias, "primary-exec");
    }

    #[test]
    fn validate_default_executor_image_rejects_unknown_alias() {
        let registry = validate_vm_images(&[vm_image_entry(
            "primary-exec", STUB_DIGEST_HEX, &["Executor"], Some("5.14"),
        )])
        .expect("registry must validate");
        let section = DefaultExecutorImageSection {
            alias: "missing".to_owned(),
        };
        let err = validate_default_executor_image(Some(&section), &registry)
            .expect_err("must reject");
        assert!(
            err.to_string()
                .contains("FAIL_POLICY_DEFAULT_EXECUTOR_IMAGE_UNRESOLVABLE"),
            "{err}"
        );
    }

    #[test]
    fn validate_default_executor_image_rejects_non_executor_alias() {
        let registry = validate_vm_images(&[vm_image_entry(
            "ver-only", STUB_DIGEST_HEX, &["Verifier"], Some("5.14"),
        )])
        .expect("registry must validate");
        let section = DefaultExecutorImageSection {
            alias: "ver-only".to_owned(),
        };
        let err = validate_default_executor_image(Some(&section), &registry)
            .expect_err("must reject");
        assert!(
            err.to_string()
                .contains("FAIL_POLICY_DEFAULT_EXECUTOR_IMAGE_UNRESOLVABLE"),
            "{err}"
        );
    }
}

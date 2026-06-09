# RAXIS V2 — Environment-Scoped Access Control

> **Status:** V2 Specified
> **Cross-references:**
> - [`policy-plan-authority.md §INV-POLICY-01`](policy-plan-authority.md) — Policy as immutable floor
> - [`v2-deep-spec.md §INV-VM-CAP-04`](v2-deep-spec.md) — VirtioFS mounts hardcoded; credentials/ never mounted
> - [`integration-merge.md §12`](integration-merge.md) — Escalation-as-amendment pattern
> - [`kernel-mediated-egress.md`](kernel-mediated-egress.md) — Two-level egress allowlist baseline
> - `invariants.md §Environment` — `INV-ENV-01` Task Environment Consistency
> - [`operator-ergonomics.md`](operator-ergonomics.md) — environments are an opt-in compliance feature; default deployments do not declare any

---

## 1. Problem Statement

An operator wants an agent to create a k8s Deployment in staging but not in production.
This single requirement cuts across three independent control layers in RAXIS:

1. **Network** — which URLs the agent can reach (egress allowlist)
2. **Credentials** — which service account keys are injected into the VM
3. **Policy gates** — categorical restrictions that survive plan misconfiguration

Each layer protects against a different failure mode. No single layer is sufficient alone.
This document specifies all three layers, the tensions between them, and how they are resolved.

---

## 1.5 Opt-In Activation Model

### 1.5.1 Default: no environments declared, no environment binding

A fresh-install `policy.toml` ships with **zero** `[environments.<label>]`
declarations, **zero** `[[environment_gates]]`, and **zero**
`environment` fields on any `[[permitted_credentials]]` entry. In this
configuration:

- The Layer-1 plan-level egress allowlist (`§2 Layer 1`) operates exactly
  as it does in V1.
- Layer 2 credential injection (`§2 Layer 2`) operates exactly as it
  does in V1; the `environment` field on `[[permitted_credentials]]`
  is absent and not consulted.
- Layer 3 environment gates (`§2 Layer 3`) and the per-task consistency
  check (`§11 INV-ENV-01`) are inert — they fire on zero plan tasks
  because there is no environment to bind to.

A solo developer running RAXIS for personal coding tasks, a small team
prototyping the system, or any deployment that does not need
multi-environment compliance separation can use the system without
ever encountering the environment model.

### 1.5.2 Activation trigger

The environment model becomes **active** the moment the operator's
signed `policy.toml` declares **at least one** `[environments.<label>]`
section. From that policy epoch forward:

1. Every `[[environment_gates]]` `label` field MUST resolve to a
   declared `[environments.<label>]` (per `§5b §11.2`); typos that
   silently mis-bind a credential are caught at policy load with
   `FAIL_POLICY_ENV_LABEL_UNDECLARED`.
2. Every `[[permitted_credentials]]` `environment` field (when present)
   MUST resolve similarly.
3. The per-task environment-consistency check (`§11 INV-ENV-01`) runs
   at `approve_plan` for every admitted plan; tasks whose
   environment-bound resources resolve to more than one label are
   rejected with `FAIL_TASK_ENVIRONMENT_INCONSISTENT`.

### 1.5.3 Why opt-in, not opt-out

Environments are a **compliance feature**, not a baseline security
gate. The baseline security gates (kernel-mediated egress, credential
injection by name, `INV-VM-CAP-04` no-credentials-mount, the planner
harness `INV-PLANNER-HARNESS-*` family, the Plan Bundle Sealing
chain) protect every operator regardless of whether they think in
environments. Environments add a *labelling* layer on top so that the
kernel can mechanically enforce "no single agent simultaneously holds
beta and prod credentials" — but most deployments don't have that
problem because they have only one environment, or because they
decompose work across operators rather than across environment labels.

**Alternatives considered and rejected:**

- **Opt-out (environments on by default; declare an empty policy to
  disable):** Forces every new operator to learn the environment model
  during their first 10 minutes with the system, in direct conflict
  with the operator-ergonomics goal. Adds a "what does the empty
  default mean?" cliff to the schema.
- **Always-on with a single implicit "default" environment:** Saves
  one declaration but injects an opinion (every credential is
  implicitly `environment = "default"`) that compounds with future
  per-environment policy knobs (audit retention, blast radius). The
  operator either has to override the implicit `default` everywhere
  or accept the kernel making compliance decisions on their behalf.
  Both outcomes are worse than keeping the model entirely silent
  until the operator opts in.
- **Opt-in via a separate `[features] environments_enabled = true`
  flag:** Adds a redundant gate. The presence of any
  `[environments.<label>]` declaration is itself unambiguous opt-in
  signal; a separate boolean flag is one more thing to forget to set
  and one more failure mode (declared envs but feature flag off →
  silent ignore? hard error?).

### 1.5.4 Partial adoption: neutral credentials and neutral egress

Once the environment model is active, operators are NOT required to
bind every credential or every egress URL to an environment. A
credential or gate that omits its environment field is **neutral** —
usable from any task regardless of the task's environment binding,
and contributing zero environment labels to the per-task consistency
check.

The neutral-credential pattern handles the real-world cases that
don't fit a clean environment taxonomy:

- **Public package registries** (`registry.npmjs.org`, `pypi.org`,
  `crates.io`) — same registry serves beta and prod tasks; binding
  to a single environment forces operators to either duplicate the
  credential per environment or invent a fake "shared" environment.
- **Read-only public APIs** (`api.github.com` for repository
  metadata) — used by tasks across all environments without
  environment-specific scoping.
- **Internal observability endpoints** (metrics, error reporting)
  — same endpoint receives data from all environments.

**The full rule:**

| Resource declaration | Treated as |
|---|---|
| `[[permitted_credentials]]` with `environment = "beta"` | Bound to `beta`. Contributes `beta` to any using task's env set. |
| `[[permitted_credentials]]` with no `environment` field | **Neutral.** Usable from any task. Contributes nothing to env set. |
| `[[environment_gates]]` with `label = "beta"` (URL gate) | Bound to `beta`. Tasks whose `allowed_egress` matches this URL contribute `beta` to their env set. |
| `allowed_egress` URL not matching ANY environment gate | **Neutral.** Contributes nothing to env set. |

Tasks with cardinality-zero environment binding (no
environment-bound credentials, no environment-bound egress matches)
are **environment-neutral by default** and pass `INV-ENV-01`
trivially.

**Alternatives considered and rejected:**

- **Require every credential / gate to declare an environment when
  any environment exists:** Forces operators to invent a fake
  "shared" or "neutral" environment label and remember to bind
  every npm-registry-style credential to it. Adds schema bloat and
  invites typos. Doesn't actually improve safety because the
  "shared" label would be granted to every task, defeating the
  purpose of the environment binding for the intentionally-shared
  resource.
- **Implicit "shared" label assigned by the kernel when env field
  is omitted:** Re-introduces a kernel-side opinion the operator
  may not want. Saves one keyword (`environment = "shared"` or
  similar) at the cost of obscuring what's bound where in the
  audit log.

---

## 2. The Three Control Layers

### Layer 1 — Egress URL Allowlist (Plan-level)

Already exists. The `allowed_egress` section in `plan.toml` per-task declares which URL
prefixes and HTTP methods the agent may call. Any URL not in the allowlist returns
`FAIL_EGRESS_NOT_PERMITTED` before the request leaves the Kernel.

**For environment separation:**
```toml
# Staging task — can create resources in staging
[[tasks.allowed_egress]]
url_prefix = "https://k8s-api.staging.company.com/"
methods    = ["GET", "POST", "PUT", "PATCH", "DELETE"]

# Production URL is simply absent.
# Any POST to k8s-api.prod.company.com → FAIL_EGRESS_NOT_PERMITTED
```

**What this protects against:** An agent that correctly follows its task scope. If the
plan is correctly written, the agent can never reach prod.

**What this does NOT protect against:** A plan that is incorrectly written — where an
operator accidentally includes the prod URL in the staging task's allowlist.

---

### Layer 2 — Credential Scoping (Kernel-injected at VM boot)

`$RAXIS_DATA_DIR/credentials/` is never mounted into VMs (INV-VM-CAP-04). The Kernel
reads from it at VM boot time and injects specific credentials as environment variables
based on what the plan declares the task needs.

**For environment separation:**
```toml
# plan.toml
[[tasks]]
task_name = "deploy-staging"

[[tasks.credentials]]
name    = "k8s-staging"      # references credentials/k8s-staging.env on the Kernel host
env_var = "KUBECONFIG"       # injected as this env var inside the VM at boot
```

The prod kubeconfig (`credentials/k8s-prod.env`) is never referenced in the staging
task's credential list — the Kernel never injects it. The agent inside the VM only
has what the Kernel explicitly injected.

**What this protects against:** An agent that attempts to authenticate to prod using
credentials it shouldn't have. Even if the egress URL were somehow reachable, a
staging-only kubeconfig authenticates only to the staging cluster.

**What this does NOT protect against:** A staging kubeconfig that has been misconfigured
with cluster-admin access across both clusters. RAXIS injects what the plan declares —
it cannot validate the scope of the credentials at inject time.

---

### Layer 3 — Policy Environment Gates (Policy-level, categorical)

New. Declared in `policy.toml`. A categorical restriction on certain URL prefixes that
survives plan misconfiguration. Even if an operator accidentally writes a plan that
includes the prod URL, the environment gate fires at admission.

```toml
# policy.toml

[[environment_gates]]
label    = "production"
url_prefixes = [
  "https://k8s-api.prod.company.com/",
  "https://db.prod.company.com/",
]
block_all                = false   # if true: no egress ever, regardless of plan
write_requires_approval  = true    # POST/PUT/PATCH/DELETE require ProtectedEgressApproval
read_methods             = ["GET", "HEAD"]   # these are always permitted if in plan allowlist
# How strictly the kernel canonicalizes the URL when comparing the
# in-flight EgressRequest against a previously approved escalation
# (`ProtectedEgressApproval`).  See §6.1 for the full canonicalization
# pipeline and the rationale for `keys` as the default.
approval_match_mode      = "keys"  # one of: path_only | keys | exact (default: keys)
```

**What this protects against:** Plan misconfiguration. An incorrectly written plan that
lists the prod URL in `allowed_egress` with write methods will be caught by the gate —
write operations require escalation before execution.

**What this does NOT protect against:** A compromised or colluding operator who
explicitly approves the escalation. Policy gates require operator intent — they do not
protect against an operator deliberately choosing to allow prod writes.

---

## 3. Tensions — Step by Step

### Tension T1 — Same Cluster, Different Namespaces

**Scenario:** Staging and prod are in different namespaces on the same k8s cluster.
The API server URL is identical: `https://k8s-api.company.com/`. Only the path differs:
- Staging: `.../namespaces/staging/deployments`
- Prod: `.../namespaces/production/deployments`

**The problem:** `url_prefix = "https://k8s-api.company.com/"` covers BOTH namespaces.
A `url_prefix`-only allowlist cannot distinguish them.

**Attempted solutions and why they fail or have limitations:**
- **URL path matching with deeper prefix:** `url_prefix = "https://k8s-api.company.com/apis/apps/v1/namespaces/staging/"` — works for some resources but k8s APIs are not consistently namespace-prefixed (cluster-scoped resources like `ClusterRoleBinding` have no namespace in the path).
- **Glob support in url_prefix:** `url_prefix = "https://k8s-api.company.com/*/namespaces/staging/*"` — adds complexity to the egress matcher; glob evaluation is harder to audit.

**Resolution:** RAXIS's strong recommendation is **cluster-level isolation** — staging and prod should be on separate clusters with separate API server URLs. This is the architectural norm in production k8s deployments. When same-cluster multi-tenancy is used, RAXIS provides defense-in-depth through credential scoping (staging service account has RBAC permissions only in the staging namespace) but cannot enforce namespace separation at the URL level alone.

This is documented as a known limitation. `FAIL_SAME_CLUSTER_NAMESPACE_ISOLATION` (V2; promoted from `WARN_SAME_CLUSTER_NAMESPACE_ISOLATION`) is emitted at `approve_plan` when a task declares a url_prefix that matches two or more environment gate labels on the same hostname. The only escape hatch is `[environments.<label>] same_cluster_acknowledged = true` on every conflated environment (§5b.2, §11.4); see §7 for the full failure-code spec.

---

### Tension T2 — Credential Over-Privilege

**Scenario:** The staging kubeconfig (`credentials/k8s-staging.env`) contains a token
for a service account that was accidentally granted `cluster-admin` on both clusters.

**The problem:** RAXIS injects credentials by name — it cannot inspect the credential
value to verify its actual scope. The plan says `name = "k8s-staging"` and RAXIS
injects whatever bytes are in that file.

**Why RAXIS cannot solve this alone:** Credential validation requires understanding the
semantics of the credential format (kubeconfig, AWS credentials, JWT, etc.) and making
a live API call to validate the scope — which requires network access RAXIS doesn't
have at inject time, and which is provider-specific.

**Resolution:** Defense-in-depth. RAXIS's credential injection is the second layer;
proper cloud RBAC is the first:
1. **Cloud RBAC (operator responsibility):** The staging service account has RBAC
   permissions only in the staging namespace/cluster.
2. **RAXIS credential injection (second layer):** Only the staging credential is
   injected into the staging task's VM.
3. **RAXIS egress allowlist (third layer):** Even with over-privileged credentials,
   egress to the prod cluster URL is blocked if it's not in the plan allowlist.
4. **Policy environment gates (fourth layer):** Even if prod URL is in the allowlist,
   write operations require escalation.

The credential audit event records the credential name, not the value. An auditor can
identify which credentials were injected per session and correlate with any prod access
incidents.

---

### Tension T3 — Plan Declares Prod URL Despite Environment Gate

**Scenario:** A plan's `allowed_egress` includes `https://k8s-api.prod.company.com/`
with methods `["POST"]`, but the policy has an environment gate with
`write_requires_approval = true` for that URL prefix.

**The problem:** The plan appears to grant POST access to prod, but the environment gate
requires escalation. The operator writing the plan may not know about the gate.

**Resolution:** `approve_plan` detects this and emits `WARN_ENVIRONMENT_GATE_WRITE_REQUIRES_APPROVAL`.
The warning explains exactly: "your plan declares POST to prod k8s API, but policy
requires operator approval for each write. At runtime, write EgressRequests to this
URL will trigger a ProtectedEgressApproval escalation."

With `--strict` (default): plan is rejected. The operator must either:
a) Remove the write methods from the prod URL in `allowed_egress`
b) Accept the escalation flow and run with `--no-strict`
c) If they genuinely need unrestricted prod writes: request a policy bundle update to
   change or remove the environment gate (requires a signed `raxis epoch advance`)

---

### Tension T4 — Plan Declares Prod URL When gate has `block_all = true`

**Scenario:** Policy has `block_all = true` for the prod URL prefix, but the plan
includes that URL in `allowed_egress`.

**Resolution:** This is a **hard error at `approve_plan`**, not a warning.
`FAIL_ENVIRONMENT_BLOCKED` — plan is rejected regardless of `--no-strict`. The
operator cannot override a `block_all` gate by running with `--no-strict`. To access
prod, the policy bundle must be updated (new epoch, operator signature). This is
consistent with the protection dimension of INV-POLICY-01: policy floors cannot be
overridden by plan configuration.

---

### Tension T5 — Credentials Declared for Environments the Task Can't Reach

**Scenario:** A plan declares `[[tasks.credentials]] name = "k8s-prod"` (the prod
kubeconfig) for a task whose `allowed_egress` only includes staging URLs.

**The problem:** The agent has the prod credential but cannot reach the prod API server
via egress. The credential is injected but useless. This is probably a copy-paste error.

**Resolution:** `WARN_CREDENTIAL_UNREACHABLE_ENVIRONMENT` at `approve_plan`. The Kernel
checks: for each declared credential, does any `allowed_egress` URL match the
credential's associated environment (if the credential is named after an environment
gate label)? If no egress URL matches, the credential is injected but can never be
used — which is suspicious.

With `--strict` (default): plan is rejected. The credential should be removed.

---

### Tension T6 — Environment Gates and INV-POLICY-01

**Does the environment gate system follow the same Policy as immutable floor model?**

Yes. Applying INV-POLICY-01 to environment gates:
- `block_all = true` → **hard policy floor.** Plan cannot override. `approve_plan`
  hard rejects any plan declaring egress to a blocked URL. No escalation can override
  `block_all` — the operator would need to update the policy bundle to change this.
- `write_requires_approval = true` → **protection dimension.** Plan CAN declare write
  methods for the URL (they're in `egress_hosts`), but each write triggers escalation.
  The plan cannot disable the escalation requirement. This is UNION semantics —
  the gate adds a requirement; the plan cannot remove it.
- Plan can add its OWN environment-level restrictions (narrower than policy) but cannot
  remove policy-level gates. A plan that declares `block_all_methods = ["POST"]` for
  a URL that policy only requires approval for is more restrictive — that's fine.

---

## 4. Admission Order — EgressRequest

Every `EgressRequest` passes these checks in order. Failure at any step stops processing.

```text
EgressRequest { url, method, headers, body } arrives at Kernel

Step 1 — Policy egress_hosts (hostname check):
  Is the hostname in policy [[egress_hosts]]?
  NO → FAIL_EGRESS_HOST_NOT_PERMITTED (policy floor; no plan override possible)

Step 2 — Policy environment_gates (block_all check):
  Does the URL match any [[environment_gates]] entry with block_all = true?
  YES → FAIL_ENVIRONMENT_BLOCKED (policy floor; no plan override possible)

Step 3 — Plan allowed_egress (task-level allowlist):
  Is the URL covered by the task's allowed_egress url_prefix?
  Is the method in the task's allowed methods?
  NO → FAIL_EGRESS_NOT_PERMITTED or FAIL_EGRESS_METHOD_NOT_PERMITTED

Step 4 — Policy environment_gates (write_requires_approval check):
  Does the URL match an [[environment_gates]] with write_requires_approval?
  AND is the method a write method (POST/PUT/PATCH/DELETE)?
  YES (no existing approval) →
    Auto-create ProtectedEgressApproval escalation
    Return FAIL_ENVIRONMENT_WRITE_REQUIRES_APPROVAL { escalation_id }
  YES (approval_id present and Consumed) →
    Verify escalation is Consumed, session matches, URL matches
    → Proceed to Step 5
  NO → Proceed to Step 5

Step 5 — Admit: forward to raxis-egress proxy
```

**Why environment gate block_all (Step 2) comes before plan allowlist (Step 3):**
A `block_all` gate is a categorical policy decision. Checking the plan allowlist first
would allow the plan to "partially pass" before hitting the gate — creating confusion
about whether the URL is "allowed by plan" even though it's categorically blocked.
The policy floor is checked before the plan-level narrowing.

**Why write_requires_approval (Step 4) comes after plan allowlist (Step 3):**
The approval gate only matters if the URL and method are already in the plan allowlist.
If the plan doesn't allow POST to prod at all, Step 3 already fails — Step 4 is never
reached. This avoids creating spurious escalations for requests that would fail anyway.

---

## 5. Credential Injection Specification

### 5.1 — plan.toml Configuration

```toml
[[tasks]]
task_name = "deploy-staging"

# Credentials this task needs — Kernel injects these at VM boot
[[tasks.credentials]]
name    = "k8s-staging"    # references $RAXIS_DATA_DIR/credentials/k8s-staging.env
env_var = "KUBECONFIG"     # environment variable name inside the VM

[[tasks.credentials]]
name    = "aws-staging"    # AWS credentials for staging account
env_var = "AWS_SHARED_CREDENTIALS_FILE"

# Credential names must be declared in policy [[permitted_credentials]]
# An undeclared credential name is FAIL_CREDENTIAL_NOT_PERMITTED at approve_plan
```

### 5.2 — Policy Bundle Configuration

Policy declares which credential names exist and which environments they are associated
with. This allows the Kernel to detect mismatches at `approve_plan` time:

```toml
# policy.toml

[[permitted_credentials]]
name        = "k8s-staging"
environment = "staging"        # matches [[environment_gates]] label
description = "Staging k8s service account kubeconfig"

[[permitted_credentials]]
name        = "k8s-prod"
environment = "production"
description = "Production k8s service account kubeconfig"

[[permitted_credentials]]
name        = "aws-staging"
environment = "staging"
description = "AWS credentials for staging account"
```

If a task declares a credential whose `environment` label matches an environment gate
that blocks egress for that task, `WARN_CREDENTIAL_UNREACHABLE_ENVIRONMENT` fires.

### 5.3 — Kernel Injection at VM Boot

```rust
// kernel/src/vm/credential_injection.rs

pub fn inject_credentials(
    task: &PlanTask,
    policy: &PolicyBundle,
    session_id: Uuid,
) -> Result<Vec<EnvVar>, KernelError> {
    let mut env_vars = Vec::new();

    for cred_decl in &task.credentials {
        // Verify credential is in policy permitted list
        let permitted = policy.permitted_credentials
            .iter()
            .find(|c| c.name == cred_decl.name)
            .ok_or(KernelError::CredentialNotPermitted { name: cred_decl.name.clone() })?;

        // Read from credentials/ directory (not mounted in VM — read by Kernel only)
        let cred_path = format!("{}/credentials/{}.env",
                                 RAXIS_DATA_DIR, cred_decl.name);
        let cred_value = fs::read_to_string(&cred_path)?;

        env_vars.push(EnvVar {
            key:   cred_decl.env_var.clone(),
            value: cred_value,
        });

        // Audit: record name only, never value
        emit_audit(CredentialInjected {
            session_id,
            task_id:         task.task_id.clone(),
            credential_name: cred_decl.name.clone(),
            env_var_name:    cred_decl.env_var.clone(),
            // NO credential_value field — value never enters audit chain
        });
    }

    Ok(env_vars)
}
```

### 5.4 — Credential Audit Events

```rust
AuditEventKind::CredentialInjected {
    session_id:       Uuid,
    task_id:          String,
    credential_name:  String,   // "k8s-staging" — the name, never the value
    env_var_name:     String,   // "KUBECONFIG"
    injected_at:      u64,      // Unix timestamp
}
```

**What is auditable:** Which credentials were injected into which session, and when.
An auditor can determine exactly what key material a session had access to.

**What is NOT auditable:** The credential value itself. This is intentional — storing
secret values in the audit chain would make the audit chain a secret store, which is
a worse security outcome than not auditing the value.

---

## 5b. Environment Declaration Schema

### 5b.1 The `[environments.<label>]` table

Environment definitions live under `[environments.<label>]` in
`policy.toml`. The label is the canonical identifier referenced by
`[[environment_gates]] label`, `[[permitted_credentials]] environment`,
and (in V2.x and beyond) any per-environment policy knob.

```toml
# policy.toml — V2 schema for environment declarations

[environments.beta]
description               = "Beta cluster — non-customer-facing"
same_cluster_acknowledged = false   # default; declaring `true` opts the operator
                                    # into the same-cluster pattern (§7
                                    # FAIL_SAME_CLUSTER_NAMESPACE_ISOLATION)

# Reserved for V2.x — inert in this release. Listed here so operators
# can see the future schema growth and so the kernel parser can
# tolerate (and warn on) their presence in older releases. Setting any
# of these in V2.0 has zero effect; the kernel emits one
# WARN_ENVIRONMENT_RESERVED_FIELD_SET per declaration at policy load.

# require_review_signoff   = false                          # Reserved for V2.x — per-env Reviewer mandate
# blast_radius             = "low"                           # Reserved for V2.x — per-env risk classification (low|medium|high)
# audit_retention_days     = 365                             # Reserved for V2.x — per-env retention override
# require_two_party_sign   = false                           # Reserved for V2.x — per-env operator co-signing requirement
# escalation_default_class = "..."                           # Reserved for V2.x — per-env escalation class default
# override_reviewer_alias  = "reviewer_production_strict"    # Reserved for V2.x — per-env Reviewer model override

[environments.production]
description               = "Production cluster — customer-facing"
same_cluster_acknowledged = false
```

### 5b.2 Field reference

| Field | Type | Default | Purpose |
|---|---|---|---|
| `description` | string | required | Human-readable description; surfaced in `raxis-cli plan explain` and audit-log inspectors. |
| `same_cluster_acknowledged` | bool | `false` | Operator opt-in for the `§7 FAIL_SAME_CLUSTER_NAMESPACE_ISOLATION` case where multiple environments share a hostname. When `true`, URL gates whose conflation involves THIS environment do not contribute environment labels to the per-task consistency check (`§11 INV-ENV-01`); the operator is taking responsibility for namespace separation via credential/RBAC scoping rather than URL-level isolation. |
| `# require_review_signoff` etc. | reserved | n/a | Reserved for V2.x. See §5b.4. |

### 5b.3 Validation at policy load

When the policy bundle is admitted ([`policy-plan-authority.md §INV-POLICY-01`](policy-plan-authority.md)):

1. Each `[environments.<label>]` table parses with the schema above.
   Unknown fields fail with `FAIL_POLICY_ENV_UNKNOWN_FIELD` unless they
   match one of the V2.x reserved field names listed in §5b.4 (which
   produce `WARN_ENVIRONMENT_RESERVED_FIELD_SET`).
2. Every `label` field on every `[[environment_gates]]` MUST resolve
   to a declared `[environments.<label>]`. Otherwise:
   `FAIL_POLICY_ENV_LABEL_UNDECLARED { label, source: "environment_gates" }`.
3. Every non-empty `environment` field on every `[[permitted_credentials]]`
   MUST similarly resolve. Otherwise:
   `FAIL_POLICY_ENV_LABEL_UNDECLARED { label, source: "permitted_credentials" }`.
4. Environment label syntax: lowercase ASCII letters, digits, hyphens,
   underscores; 1–32 characters; matches `^[a-z][a-z0-9_-]{0,31}$`.
   Otherwise: `FAIL_POLICY_ENV_LABEL_INVALID`.

These validations make typos surface at policy epoch advance (signed, deliberate,
audited) rather than silently mis-binding a credential at plan
submission (where the operator would never notice the binding fell
through).

### 5b.4 Reserved fields (V2.x)

The fields commented out in §5b.1 are **reserved** for future V2.x
releases. Listing them in V2.0 documentation serves three purposes:

1. **Operator forward-compat awareness.** Operators reading the schema
   today see what's coming and can structure their policy templates
   accordingly.
2. **Schema-fight prevention.** A future RAXIS release that adds
   `blast_radius` does not collide with operator extensions or
   forks that may have used the same name for unrelated semantics.
3. **Parser tolerance.** The V2.0 parser emits one
   `WARN_ENVIRONMENT_RESERVED_FIELD_SET` per reserved field that an
   operator sets, rather than a hard `FAIL_POLICY_ENV_UNKNOWN_FIELD`.
   This lets operators experiment with their own templates; the
   warning makes it explicit that the field has no kernel-side
   effect in this release.

The canonical list of reserved field names in V2.0:

| Reserved field | Anticipated V2.x semantics |
|---|---|
| `require_review_signoff` | Per-environment Reviewer mandate; tasks bound to this env are silently upgraded to require Reviewer approval before merge. |
| `blast_radius` | Per-environment risk classification (`low` / `medium` / `high`); future scheduler / token-budget knobs key off this. |
| `audit_retention_days` | Per-environment audit-retention override; satisfies regulated-environment retention windows (HIPAA, SOC 2). |
| `require_two_party_sign` | Per-environment two-operator co-signing requirement on submitted plans. |
| `escalation_default_class` | Per-environment default escalation class for ambiguous escalations. |
| `override_reviewer_alias` | Per-environment Reviewer model override. When a task's binding (per `§11 INV-ENV-01`) resolves to this environment, the Reviewer activated for that task uses this `[provider_aliases.<alias>]` chain instead of the plan's `[provider_aliases.reviewer]`. Lets operators upgrade Reviewer reasoning specifically for production-bound tasks (e.g., `claude-opus-4.7-thinking-high`) without inflating cost on beta-bound tasks ([`provider-model-selection.md §6.1`](provider-model-selection.md)). The alias name on the right MUST resolve to a `[provider_aliases.<alias>]` block in the plan or the deployment-wide policy; resolution failures will be caught at admission once V2.x lands the field. |

V2.0 implementations MUST treat any of these names in a
`[environments.<label>]` table as parseable but inert, with a
`WARN_ENVIRONMENT_RESERVED_FIELD_SET` per occurrence. Future RAXIS
releases will move individual fields out of "reserved" and into
"normative"; operators upgrading across those releases are responsible
for verifying the values they set match the new normative semantics
before advancing the policy bundle again.

### 5b.5 Permitted-credentials neutrality

Per `§1.5.4`, the `environment` field on `[[permitted_credentials]]` is
**optional**. A credential without it is **neutral** and contributes
nothing to the per-task environment-consistency check. The schema
makes this explicit:

```toml
# Neutral credential (used by tasks of any environment binding)
[[permitted_credentials]]
name        = "npm-registry"
description = "Read-only npm registry token; same registry serves all envs"
# No `environment` field → neutral.

# Environment-bound credential
[[permitted_credentials]]
name        = "k8s-prod"
environment = "production"
description = "Production k8s service account kubeconfig"
```

The kernel does not infer environment binding from the credential's
name (e.g., `k8s-prod` does NOT auto-bind to `"production"`). Binding
is exclusively the `environment` field. This avoids name-shape coupling
that would make rename refactors a security risk.

---

## 6. Environment Gate — Write Approval Escalation Flow

When `write_requires_approval = true` fires (Step 4 of admission):

```text
1. Agent submits:
   EgressRequest { url: "https://k8s-api.prod.company.com/apis/.../pods",
                   method: "POST", ... }

2. Kernel Step 4: write gate fires
   → Auto-creates ProtectedEgressApproval escalation:
     { id: esc-77, class: ProtectedEgressApproval,
       state: Pending, url: <url>, method: "POST",
       environment_label: "production", session_id, task_id }
   → Emits EgressApprovalRequired audit event
   → Returns FAIL_ENVIRONMENT_WRITE_REQUIRES_APPROVAL { escalation_id: esc-77 }
   → KernelPush::EgressApprovalRequired { escalation_id, url, method, environment }

3. Operator reviews:
   raxis egress diff esc-77      # shows URL, method, request body SHA-256
   raxis egress approve esc-77   # or: raxis egress reject esc-77

4a. On approve:
    → escalations SET state = 'Consumed', resolved_by = 'operator_alice'
    → Emits EscalationConsumed { class: ProtectedEgressApproval }
    → KernelPush::EscalationResolved { escalation_id: esc-77 }
    → Agent re-submits with approval_id = esc-77
    → Kernel Step 4: Consumed approval verified → Admit

4b. On reject:
    → escalations SET state = 'Rejected'
    → Emits EscalationRejected
    → KernelPush::EgressApprovalRejected
    → Agent receives rejection; must escalate PlanViolation or stop
```

**Approval is URL-and-method specific** (same SHA-specificity as ProtectedPathMerge):
The approval records a canonicalized form of the URL (per §6.1) along with the method.
If the agent tries to reuse `esc-77` for a different URL canonicalization or a different
method, `FAIL_APPROVAL_URL_MISMATCH` is returned.

---

### 6.1 URL canonicalization for approval comparison (`approval_match_mode`)

The naive choice — "compare the full URL string byte-for-byte" — is
hostile to every realistic write API:

- **Idempotency tokens vary per request.** Kubernetes appends
  `?fieldManager=raxis&resourceVersion=12345`. The
  `resourceVersion` value is different on every call. Byte-exact
  matching forces the operator to re-approve every single write,
  defeating the purpose of pre-approval.
- **Pagination is value-variant.** `?page=1` vs `?page=2` are the
  same semantic operation. An operator who approved
  "list deployments" should not have to re-approve every page.
- **The security-relevant signal is the key SET, not the values.**
  An endpoint whose semantics change with `?action=delete` vs
  `?action=list` is poorly designed — the operation belongs in
  the path or HTTP method. Well-designed APIs encode operation
  in the path; query parameters are *modifiers*. Matching on the
  key set catches "this request uses a parameter I didn't expect"
  without over-restricting.

But not every API is well-designed. A URL like
`https://legacy.example.com/cmd?do=destroy_database` does carry
operational meaning in a query *value*. The kernel must offer an
opt-in for this case.

**Three modes are supported, declared per environment-gate:**

```toml
# policy.toml
[[environment_gates]]
label   = "production"
# … other fields …
approval_match_mode = "keys"   # default; see table below
```

| Mode | What is canonicalized into the comparison key | Use when |
|---|---|---|
| `path_only` | `scheme + lowercased host + normalized path` (query and fragment dropped entirely) | The operator wants to approve an API endpoint *as a unit* and accept any query parameters as effectively-equivalent. Common for read endpoints with extensive optional filters. |
| `keys` (DEFAULT) | `scheme + lowercased host + normalized path + sorted query KEY set` (values dropped; duplicate keys collapsed) | Most write APIs: the operator wants to detect "this request uses a parameter the approval did not contemplate" without re-approving on every request. |
| `exact` | `scheme + lowercased host + normalized path + full sorted query string with values` (RFC 3986 percent-encoding normalized) | Poorly-designed APIs whose query *values* carry operation semantics. Opt-in only. |

**Path normalization (all three modes).** RFC 3986 normalization:
collapse repeated slashes (`//` → `/`), resolve `.` and `..`
segments lexically, lowercase the scheme and host, drop default
ports (`https:443`, `http:80`). Fragments (`#…`) are ALWAYS
dropped — fragments are client-side and never traverse the wire.

**Query normalization (`keys` mode).** Parse the query string
with `application/x-www-form-urlencoded` rules (per the
URL Standard). Percent-decode keys. Sort keys lexicographically.
Collapse duplicate keys to a single entry (the comparison
ignores how many times a key appears — `?a&a&b` and `?a&b`
canonicalize identically). Discard all values.

**Query normalization (`exact` mode).** Same parse, same sort.
Re-encode keys *and* values with the URL-standard
percent-encoding (the canonical 2-uppercase-hex form: `%2f` →
`%2F`). Duplicate keys are NOT collapsed in `exact` mode — they
are sorted lexicographically by `(key, value)` together. Order
within a duplicate-key cluster is determined by sorted values.
Empty values are kept (`?a=` is distinct from `?a` in `exact`
mode — the former has an explicit empty string, the latter
elides the `=`).

**The canonicalized key is what the kernel hashes** and stores
on the `escalations` row at `EgressApprovalRequired` enqueue
time, and what it re-derives from the agent's follow-up
`EgressRequest` to compare. The hash function is SHA-256 over
the UTF-8 bytes of the canonicalized form; the digest is the
column the kernel matches.

#### Audit and operator UX

- The `EgressApprovalRequired` audit event records BOTH the raw
  URL the agent submitted AND the canonicalized form, so an
  auditor can see exactly what the operator approved.
- The operator's `raxis egress diff <esc-id>` CLI surfaces
  `match_mode = keys`, the raw URL, and the canonicalized key.
  This makes the matching strictness visible to the human in the
  loop.
- A mismatch on follow-up emits `FAIL_APPROVAL_URL_MISMATCH`
  with both the canonicalized-approved key and the
  canonicalized-attempted key in the structured failure detail
  (helpful when an operator wonders why a "matching" URL was
  rejected — usually a mode mismatch between operator
  expectation and policy default).

#### Validation at policy load

- `approval_match_mode` must be one of `path_only`, `keys`,
  `exact`. Otherwise: `FAIL_POLICY_APPROVAL_MATCH_MODE_INVALID`.
- A gate with `block_all = true` MUST NOT declare
  `approval_match_mode` (block-all gates never produce
  approvals; declaring a match mode would be misleading);
  emits `WARN_POLICY_APPROVAL_MATCH_MODE_IGNORED_ON_BLOCK_ALL`.
- A gate with `write_requires_approval = false` AND no
  `block_all = true` (i.e. an environment that exists for
  binding purposes but never produces approvals) similarly
  emits `WARN_POLICY_APPROVAL_MATCH_MODE_IGNORED_ON_NO_APPROVAL`
  if `approval_match_mode` is set.

#### Migration

V2.0 shipped with implicit `exact` matching (full byte
comparison after lowercasing). V2.1 changes the default to
`keys`. Operators who depended on the V2.0 byte-exact behavior
must explicitly set `approval_match_mode = "exact"` on the
relevant `[[environment_gates]]`. The new default is logged at
policy-load time as a single `PolicyMigration { from:
"V2.0_implicit_exact", to: "V2.1_default_keys", affected_gates:
[…] }` audit event, listing every gate whose match mode was
upgraded by the default change. Operators reviewing the audit
chain will see exactly which gates they are using the new
default for.

---

## 7. approve_plan Warnings and Errors

### FAIL_ENVIRONMENT_BLOCKED (hard error)

**Trigger:** A task's `allowed_egress` declares a URL prefix that matches a policy
`[[environment_gates]]` entry with `block_all = true`.

**Behavior:** Plan rejected regardless of `--no-strict`. The `block_all` gate is a
categorical policy floor — it cannot be overridden by plan configuration or `--no-strict`.

**Fix:** Remove the blocked URL from `allowed_egress`, or update the policy bundle to
change or remove the `block_all` gate (requires a signed `raxis epoch advance`).

---

### FAIL_CREDENTIAL_NOT_PERMITTED (hard error)

**Trigger:** A task declares `[[tasks.credentials]] name = "k8s-prod"` but `k8s-prod`
does not appear in policy `[[permitted_credentials]]`.

**Behavior:** Plan rejected regardless of `--no-strict`. Credentials must be explicitly
declared in the policy bundle before any plan can reference them. This prevents plans
from referencing arbitrary files in `credentials/`.

**Fix:** Add the credential to policy `[[permitted_credentials]]` via a signed
`raxis epoch advance`.

---

### WARN_ENVIRONMENT_GATE_WRITE_REQUIRES_APPROVAL

**Trigger:** A task declares write methods (POST/PUT/PATCH/DELETE) for a URL matching
a `[[environment_gates]]` entry with `write_requires_approval = true`.

**Kernel behavior:** The task will run, but each write EgressRequest to this URL will
trigger a `ProtectedEgressApproval` escalation at runtime.

**Plan value:** `methods = ["GET", "POST", "PUT"]` for prod URL
**Kernel behavior:** Only GET admitted freely; POST/PUT trigger escalation each time

**With `--strict` (default):** Plan rejected. The operator must either:
- Remove write methods from the prod URL `allowed_egress` entry
- Run with `--no-strict` to acknowledge the escalation flow

**With `--no-strict`:** Plan approved with warning recorded in `InitiativeCreated`.

---

### WARN_CREDENTIAL_UNREACHABLE_ENVIRONMENT

**Trigger:** A task declares a credential whose `environment` label (from policy
`[[permitted_credentials]]`) matches an environment that the task has no `allowed_egress`
to reach.

**Example:** Task declares `credentials = ["k8s-prod"]` (environment: "production") but
`allowed_egress` only includes staging URLs. The prod credential is injected but can
never authenticate to any reachable URL.

**Kernel behavior:** Credential is injected as declared. At runtime it simply goes unused.

**With `--strict` (default):** Plan rejected. Injecting unused credentials is a security
hygiene violation — the agent shouldn't hold keys it cannot use.

**With `--no-strict`:** Plan approved with warning.

---

### FAIL_SAME_CLUSTER_NAMESPACE_ISOLATION

> **V2 status:** Promoted from `WARN_SAME_CLUSTER_NAMESPACE_ISOLATION`
> (V1 / pre-INV-ENV-01) to a hard failure. Mirrors the `INV-ENV-01`
> "fail loud" posture for environment binding inconsistencies. The
> only escape hatch is per-environment opt-in via
> `[environments.<label>] same_cluster_acknowledged = true` (§5b.2,
> §11.4).

**Trigger:** A task's `allowed_egress` URL prefix matches **two or
more** `[[environment_gates]]` entries from distinct environment
labels (the canonical case: same hostname covers both staging and
production namespaces on a shared cluster). The matching algorithm
is the URL/gate matcher used by `handle_egress_request` (per §4
Step 2).

**Example:** Policy declares `[environments.beta]` and
`[environments.production]`, with gates:

```toml
[[environment_gates]]
label        = "beta"
url_prefixes = ["https://k8s-api.company.com/"]

[[environment_gates]]
label        = "production"
url_prefixes = ["https://k8s-api.company.com/"]
```

A task that declares
`url_prefix = "https://k8s-api.company.com/"` in its `allowed_egress`
hits both gates. The URL prefix cannot mechanically distinguish the
namespace.

**Behavior (default — neither environment acknowledges):**

- `approve_plan` returns
  `FAIL_SAME_CLUSTER_NAMESPACE_ISOLATION { task, url_prefix,
  conflated_environments: ["beta", "production"], unacknowledged:
  ["beta", "production"] }`.
- The plan is **rejected regardless of `--no-strict`**. This is a
  structural protection like `FAIL_ENVIRONMENT_BLOCKED`; it cannot
  be downgraded by a CLI flag.
- The kernel emits no audit-chain side effect (the rejection is
  pre-admission).

**Behavior (escape hatch — every conflated environment acknowledges):**

- Operator updates `policy.toml` to set
  `same_cluster_acknowledged = true` on every conflated environment
  (per §11.4 — "all conflated envs", not "any single env"):

  ```toml
  [environments.beta]
  description               = "Beta cluster — non-customer-facing"
  same_cluster_acknowledged = true   # ack: shares hostname with production

  [environments.production]
  description               = "Production cluster — customer-facing"
  same_cluster_acknowledged = true   # ack: shares hostname with beta
  ```

- Operator re-signs the policy bundle and advances the epoch with
  `raxis epoch advance --policy <policy.toml> --sig <policy.sig>`.
- On the next `approve_plan` for this task, the same-cluster handler
  (§11.4) returns `TaskEnvBinding::SameClusterAcknowledged`; the URL
  contributes ZERO labels to the task's environment set.
- The task's environment binding is then determined purely by its
  credentials. If the credentials still resolve to two environments,
  `FAIL_TASK_ENVIRONMENT_INCONSISTENT` (per §11.7) fires next; the
  acknowledgment does not help with credential-level mixing.
- Acknowledgment is recorded in the policy bundle (which is signed
  and indefinitely retained per `audit-retention.md`); a forensic
  auditor can reconstruct exactly when the operator opted into the
  same-cluster pattern and which environments it covered.

**Why "all conflated envs must acknowledge":** see §11.4 for the
rationale. The short version: requiring acknowledgment on each
environment definition forces operators to mark each side
deliberately and surfaces the same-cluster pattern in policy diffs
and `raxis-cli plan explain` output.

**Recommended fix (preferred over acknowledgment):** Use separate
clusters with distinct hostnames for each environment. This
eliminates the namespace-level ambiguity at the network layer and
keeps Layer 1 / Layer 3 enforcement crisp. Acknowledgment is the
"I know what I'm doing" path for deployments where separating
clusters is operationally infeasible.

**Alternatives considered and rejected (for the WARN → FAIL
promotion itself):**

- **Keep as WARN with policy-level "treat as error" knob:** Adds
  a knob (`policy.toml [strict_modes] same_cluster = "fail"`) that
  effectively duplicates the user's "fail loud" posture as an
  optional setting. Operators who need the WARN behavior get it
  via `same_cluster_acknowledged = true`, which is more explicit
  about *what* is being acknowledged.
- **Promote to FAIL but allow `--no-strict` to downgrade:** Mirrors
  the existing pattern for some warnings, but conflates two ideas:
  `--no-strict` is for "I accept the risk on this specific plan";
  same-cluster acknowledgment is "this deployment topology is what
  it is, for every plan." The acknowledgment belongs in policy,
  not in a CLI flag.

---

### approve_plan Check Order (Updated with Environment Checks)

```text
1. Verify Ed25519 plan signature
2. Verify policy bundle epoch
3. For each task:
   a. vm_image in policy vm_images? → hard error if not
   b. For each allowed_egress entry:
      - hostname in policy egress_hosts? → hard error if not
      - URL matches environment_gate with block_all? → FAIL_ENVIRONMENT_BLOCKED (hard)
      - methods within policy egress_hosts methods? → WARN_EGRESS_METHOD_RESTRICTED
      - URL matches environment_gate with write_requires_approval?
        AND write methods declared? → WARN_ENVIRONMENT_GATE_WRITE_REQUIRES_APPROVAL
      - URL matches ≥ 2 distinct environment_gate labels (same-cluster
        conflation per §11.4)?
        → handle_same_cluster_conflation():
            all conflated envs declare same_cluster_acknowledged = true?
              YES → URL contributes 0 labels; continue
              NO  → FAIL_SAME_CLUSTER_NAMESPACE_ISOLATION (hard;
                    not bypassable by --no-strict; per §11.4)
   c. For each credentials entry:
      - name in policy permitted_credentials? → FAIL_CREDENTIAL_NOT_PERMITTED (hard)
      - credential environment matches any allowed_egress environment? If no match
        → WARN_CREDENTIAL_UNREACHABLE_ENVIRONMENT
   d. (only when at least one [environments.<label>] is declared per §1.5.2)
      Per-task environment consistency (§11.3 algorithm):
      - Compute task_envs = SET of labels contributed by env-bound creds
        and env-bound gate matches (excluding same-cluster-acknowledged URLs).
      - task_envs.len() ≤ 1 ?
          YES → record TaskEnvironmentBinding (Neutral / Bound(label))
          NO  → FAIL_TASK_ENVIRONMENT_INCONSISTENT (hard; not bypassable
                by --no-strict; per §11.7)
4. integration_merge_gates checks → WARN_PROTECTION_OVERRIDDEN etc.
5. require_push_approval vs. policy minimum → WARN_PUSH_APPROVAL_DOWNGRADED
6. token_policy uncapped fields → WARN_UNCAPPED_TOKEN_LIMIT
7. estimated_cost vs. lane ceiling → hard error if exceeds
8. Collect all warnings
9. If strict → reject on any warning; else approve with warnings in audit event
```

**Note on step 3d ordering.** The per-task consistency check runs
*after* per-egress and per-credential individual checks (steps 3b
and 3c) so that a credential typo (`FAIL_CREDENTIAL_NOT_PERMITTED`)
or a hostname omission (`FAIL_EGRESS_HOST_NOT_PERMITTED`) surfaces
before the higher-level invariant. This gives operators the most
specific message first.

**Note on Reviewer / Orchestrator tasks.** Steps 3b–3d are no-ops for
these roles by structure (`§11.6`): Reviewer and Orchestrator tasks
declare no credentials and no `allowed_egress`, so their `task_envs`
is always empty and they always record as Neutral.

---

## 8. Precedence Summary

| Layer | Where declared | Overridable by plan? | Override mechanism |
|---|---|---|---|
| Policy egress_hosts (hostname) | policy.toml | No | Policy update (new epoch) |
| Environment gate `block_all` | policy.toml | No | Policy update (new epoch) |
| Policy egress_hosts (methods ceiling) | policy.toml | Plan can only narrow | N/A |
| Plan `allowed_egress` (URL + methods) | plan.toml | N/A (plan-declared) | Re-approve new plan |
| Environment gate `write_requires_approval` | policy.toml | Cannot disable; plan acknowledges | `--no-strict` at approve_plan |
| Credential injection | plan.toml + policy permitted_credentials | Plan selects from permitted set | N/A |
| **Environment binding consistency (`INV-ENV-01`, §11)** | derived from policy + plan | **No.** Cannot be downgraded by `--no-strict`. | Refactor plan: split cross-env tasks per §11.5 |
| **Same-cluster acknowledgment (§11.4)** | `policy.toml [environments.<label>] same_cluster_acknowledged` | No | Policy update (new epoch) |
| **Per-environment reserved knobs (§5b.4)** | `policy.toml [environments.<label>]` | No (when normative in V2.x) | Policy update (new epoch) |

---

## 9. Defense-in-Depth Model

For the specific case of "agent creates k8s resource in staging, blocked from prod":

```text
Prod cluster protection depth:
  Layer 1 (Cloud RBAC):       Staging service account has no prod cluster RBAC
  Layer 2 (Credentials):      Kernel injects only k8s-staging credential into VM
  Layer 3 (Egress allowlist): Prod API URL absent from staging task's allowed_egress
  Layer 4 (Environment gate): Policy blocks prod write without approval
  Layer 5 (Audit chain):      Every credential injection and egress call recorded
```

Any single layer failing does not compromise prod:
- RBAC misconfigured? → Egress URL not in allowlist (Layer 3) stops the call
- Egress allowlist misconfigured? → Environment gate (Layer 4) requires approval
- Environment gate bypassed? → Audit chain (Layer 5) records the escalation and approval

An attacker needs to compromise multiple independent layers simultaneously.

---

## 10. Implementation Checklist

- [ ] Add `[[environment_gates]]` section to `PolicyBundle` struct
- [ ] Add `[[permitted_credentials]]` section to `PolicyBundle` struct
- [ ] Add `[[tasks.credentials]]` section to `PlanTask` struct
- [ ] Add Step 2 (environment_gates block_all) to `handle_egress_request` admission
- [ ] Add Step 4 (write_requires_approval) to `handle_egress_request` admission
- [ ] Add `ProtectedEgressApproval` variant to `EscalationClass` enum
- [ ] Add `url` and `environment_label` fields to `escalations` DDL
- [ ] Implement `kernel/src/vm/credential_injection.rs` (Kernel reads and injects)
- [ ] Add `CredentialInjected` audit event (name only, never value)
- [ ] Add `FAIL_ENVIRONMENT_BLOCKED` to `KernelError`
- [ ] Add `FAIL_CREDENTIAL_NOT_PERMITTED` to `KernelError`
- [ ] Add `FAIL_ENVIRONMENT_WRITE_REQUIRES_APPROVAL` to `KernelError`
- [ ] Add `FAIL_APPROVAL_URL_MISMATCH` to `KernelError`
- [ ] Add `FAIL_POLICY_APPROVAL_MATCH_MODE_INVALID` to `KernelError` (policy load)
- [ ] Add `WARN_POLICY_APPROVAL_MATCH_MODE_IGNORED_ON_BLOCK_ALL` and `WARN_POLICY_APPROVAL_MATCH_MODE_IGNORED_ON_NO_APPROVAL` warnings (policy load)
- [ ] Implement URL canonicalizer per §6.1 with three modes (`path_only` | `keys` | `exact`); unit-test each mode against the URL-Standard test corpus
- [ ] Store canonicalized-key SHA-256 on `escalations` row at `EgressApprovalRequired` enqueue; re-derive from follow-up `EgressRequest` for comparison
- [ ] Persist `approval_match_mode` field on the resolved environment-gate for forensics; surface it in `raxis egress diff <esc-id>`
- [ ] Emit `PolicyMigration { from: "V2.0_implicit_exact", to: "V2.1_default_keys", affected_gates }` exactly once at the first policy-load event after upgrade
- [ ] Add `KernelPush::EgressApprovalRequired` and `EgressApprovalRejected` variants
- [ ] Implement `WARN_ENVIRONMENT_GATE_WRITE_REQUIRES_APPROVAL` at `approve_plan`
- [ ] Implement `WARN_CREDENTIAL_UNREACHABLE_ENVIRONMENT` at `approve_plan`
- [ ] Implement `WARN_SAME_CLUSTER_NAMESPACE_ISOLATION` at `approve_plan`
- [ ] Implement `FAIL_ENVIRONMENT_BLOCKED` at `approve_plan` (hard error)
- [ ] Implement `FAIL_CREDENTIAL_NOT_PERMITTED` at `approve_plan` (hard error)
- [ ] Implement `raxis egress diff/approve/reject` CLI commands
- [ ] Add environment gate admission checks to `approve_plan` check order (step 3b)
- [ ] Tests (V1 + V2 baseline):
      - Block_all gate: plan with prod URL → FAIL_ENVIRONMENT_BLOCKED at approve_plan
      - Write_requires_approval: POST to prod URL → escalation created
      - Write approval: consumed approval → request admitted
      - Write approval: wrong URL → FAIL_APPROVAL_URL_MISMATCH
      - **`approval_match_mode = "keys"` (default):** approve `https://api/x?a=1&b=2`; agent re-issues `https://api/x?a=99&b=99` → admitted (key set `{a, b}` matches; values ignored). Agent re-issues `https://api/x?a=1&c=3` → `FAIL_APPROVAL_URL_MISMATCH` (key `c` was not in the approval).
      - **`approval_match_mode = "keys"`:** duplicate key collapsing — approve `https://api/x?a=1&a=2`; agent re-issues `https://api/x?a=99` → admitted (both canonicalize to key set `{a}`).
      - **`approval_match_mode = "path_only"`:** approve `https://api/x?secret=abc`; agent re-issues `https://api/x?totally=different` → admitted (query dropped from canonical key entirely).
      - **`approval_match_mode = "exact"`:** approve `https://api/x?a=1&b=2`; agent re-issues `https://api/x?a=99&b=2` → `FAIL_APPROVAL_URL_MISMATCH` (value of `a` differs).
      - **`approval_match_mode = "exact"`:** percent-encoding normalization — approve `https://api/x?q=hello%20world`; agent re-issues `https://api/x?q=hello+world` → admitted (both canonicalize to the same RFC-3986 form). `%2f` and `%2F` canonicalize identically. Empty value preservation: approve `https://api/x?a=`; agent re-issues `https://api/x?a` → `FAIL_APPROVAL_URL_MISMATCH` (`exact` mode preserves the explicit-empty distinction).
      - **Path normalization (all modes):** approve `https://api/x/`; agent re-issues `https://api/x///./y/../` → admitted (RFC 3986 normalization collapses to the same path). Default-port stripping: approve `https://api:443/x`; agent re-issues `https://api/x` → admitted.
      - **`approval_match_mode = "exact"` opt-in for poorly-designed APIs:** policy declares `[[environment_gates]] approval_match_mode = "exact"`; agent submits `https://legacy/cmd?do=destroy_database` → operator approves; agent re-issues `https://legacy/cmd?do=list_databases` → `FAIL_APPROVAL_URL_MISMATCH` (value-sensitive matching catches the operation change).
      - **Mode-mismatch invalid value:** policy declares `approval_match_mode = "fuzzy"` → policy load fails `FAIL_POLICY_APPROVAL_MATCH_MODE_INVALID`.
      - **Mode set on `block_all = true` gate:** policy declares both `block_all = true` and `approval_match_mode = "exact"` → policy load emits `WARN_POLICY_APPROVAL_MATCH_MODE_IGNORED_ON_BLOCK_ALL` once.
      - **V2.0 → V2.1 migration:** policy.toml from V2.0 with `write_requires_approval = true` and no `approval_match_mode` field → policy-load audit chain has exactly one `PolicyMigration { from: "V2.0_implicit_exact", to: "V2.1_default_keys", affected_gates: [...] }` event listing every upgraded gate; subsequent admissions match per `keys` semantics.
      - Credential injection: staging task gets staging kubeconfig only
      - Undeclared credential: FAIL_CREDENTIAL_NOT_PERMITTED at approve_plan
      - Unreachable credential: WARN_CREDENTIAL_UNREACHABLE_ENVIRONMENT at approve_plan
      - Defense-in-depth: all 4 layers present, each independently blocks prod access

- [ ] V2 environment-binding additions (per §1.5, §5b, §11):
      - Add `[environments.<label>]` table parsing to `PolicyBundle` per §5b.1
      - `same_cluster_acknowledged: bool` field with default `false`
      - V2.x reserved fields recognized and warning-only per §5b.4 (one `WARN_ENVIRONMENT_RESERVED_FIELD_SET` per occurrence; no kernel-side effect)
      - Environment label syntax validation per §5b.3 — `^[a-z][a-z0-9_-]{0,31}$` → `FAIL_POLICY_ENV_LABEL_INVALID`
      - Cross-reference validation: every `[[environment_gates]] label` and every non-empty `[[permitted_credentials]] environment` resolves to a declared `[environments.<label>]` → otherwise `FAIL_POLICY_ENV_LABEL_UNDECLARED { label, source }`
      - Activation gate per §1.5.2: per-task consistency check (§11.3) is a no-op when zero `[environments.<label>]` declared; activates the moment one is declared
      - Implement `compute_task_envs` per §11.3 algorithm; record `TaskEnvironmentBinding` per §11.9
      - Implement `handle_same_cluster_conflation` per §11.4; require ALL conflated envs to declare `same_cluster_acknowledged = true` to suppress
      - Promote `WARN_SAME_CLUSTER_NAMESPACE_ISOLATION` → `FAIL_SAME_CLUSTER_NAMESPACE_ISOLATION` per §7
      - Add `FAIL_TASK_ENVIRONMENT_INCONSISTENT { task, environments, sources }` per §11.7
      - Add `FAIL_POLICY_ENV_LABEL_UNDECLARED { label, source }` per §5b.3
      - Add `FAIL_POLICY_ENV_UNKNOWN_FIELD { field }` per §5b.3
      - Add `FAIL_POLICY_ENV_LABEL_INVALID { label }` per §5b.3
      - Add `WARN_ENVIRONMENT_RESERVED_FIELD_SET { field, env }` per §5b.4
      - Add `TaskEnvironmentBinding` field to `InitiativeCreated` audit event per §11.9
      - Reviewer / Orchestrator schema continues to forbid `[[plan.tasks.credentials]]` and `allowed_egress` declarations per [`planner-harness.md §3`](planner-harness.md) (no change required for INV-ENV-01; the structural prohibition makes the consistency check a no-op for these roles per §11.6)
      - `raxis-cli plan explain` ([`operator-ergonomics.md §9`](operator-ergonomics.md)) renders per-task environment binding ("Bound: production" / "Neutral" / "SameClusterAcknowledged")

- [ ] V2 environment-binding tests:
      - **Inert default.** Policy with zero `[environments.<label>]` declared → all V2 environment checks are no-ops; admitted plans get `TaskEnvironmentBinding::Neutral` for every task without any binding consideration.
      - **Activation transition.** Policy A (no envs) → Policy B (one env declared); same plan submitted under both → admitted under A as Neutral; admitted under B as Bound or rejected.
      - **Single-env happy path.** Plan with one Executor task whose credentials all bind to "beta" and whose egress URLs all match a "beta" gate → admitted; binding recorded as Bound("beta").
      - **Cross-env credentials.** Plan with one Executor task holding both `registry-beta-read` (env: "beta") and `registry-prod-write` (env: "production") → `FAIL_TASK_ENVIRONMENT_INCONSISTENT { task, environments: ["beta", "production"], sources: [...] }`.
      - **Cross-env URL.** Plan with one Executor task whose `allowed_egress` includes one URL matching a "beta" gate and another matching a "production" gate → `FAIL_TASK_ENVIRONMENT_INCONSISTENT`.
      - **Mixed credential + URL.** Credential bound to "beta", URL matches "production" gate → `FAIL_TASK_ENVIRONMENT_INCONSISTENT` (sources include both).
      - **Neutral-credential pass-through.** Task with one env-bound credential ("beta") and one neutral credential ("npm-registry") → admitted as Bound("beta"); neutral credential contributes nothing.
      - **Neutral-egress pass-through.** Task with one env-bound credential ("beta") and one allowed_egress URL matching no gate at all → admitted as Bound("beta").
      - **All-neutral task.** Task with only neutral credentials and only neutral egress → admitted as Neutral even when policy declares envs.
      - **DAG split (§11.5).** Two-task plan: `fetch_from_beta` (Bound("beta")) → `publish_to_prod` (Bound("production")); kernel admits both; artifact handoff via task-output store records the SHA-256 in audit chain.
      - **Reviewer in DAG.** Adding a Reviewer task between the two halves of the §11.5 split: Reviewer is recorded as Neutral (cardinality 0); admission proceeds.
      - **Same-cluster, no acknowledgment.** Two `[[environment_gates]]` ("beta", "production") sharing hostname; task URL matches both; neither environment declares `same_cluster_acknowledged = true` → `FAIL_SAME_CLUSTER_NAMESPACE_ISOLATION { task, conflated_environments: ["beta", "production"], unacknowledged: ["beta", "production"] }`.
      - **Same-cluster, partial acknowledgment.** Same scenario but only `[environments.beta] same_cluster_acknowledged = true` → still fails because `production` did not acknowledge; FAIL message lists `unacknowledged: ["production"]`.
      - **Same-cluster, full acknowledgment.** Both envs declare `same_cluster_acknowledged = true`; task has only "beta" credential → admitted as Bound("beta") (URL contributed 0; credential contributed "beta"). The same-cluster conflation no longer fails.
      - **Same-cluster, full acknowledgment + cross-env credentials.** Both envs acknowledge same-cluster; task has both "beta" and "production" credentials → still `FAIL_TASK_ENVIRONMENT_INCONSISTENT` (acknowledgment helps with URL conflation, not credential mixing).
      - **Label resolution failure.** `[[environment_gates]] label = "produciton"` (typo) and no `[environments.produciton]` declared → policy load fails with `FAIL_POLICY_ENV_LABEL_UNDECLARED { label: "produciton", source: "environment_gates" }`.
      - **Reserved field tolerance.** Policy declares `[environments.beta] blast_radius = "high"` → policy loads with `WARN_ENVIRONMENT_RESERVED_FIELD_SET { field: "blast_radius", env: "beta" }`; field has no kernel-side effect.
      - **Unknown field rejection.** Policy declares `[environments.beta] frobnitz = "x"` (not a reserved name) → `FAIL_POLICY_ENV_UNKNOWN_FIELD { field: "frobnitz" }`.
      - **Label syntax rejection.** `[environments.Beta]` (uppercase) → `FAIL_POLICY_ENV_LABEL_INVALID`.
      - **Reviewer cannot declare credentials.** Plan with `[[plan.tasks.credentials]]` on a Reviewer task → existing `FAIL_REVIEWER_CREDENTIALS_NOT_ALLOWED` (per [`planner-harness.md`](planner-harness.md)); test that this fires before any environment-binding logic so Reviewers never participate in INV-ENV-01.
      - **Orchestrator declarations rejected.** Operator attempts to declare an Orchestrator task in `plan.toml` → existing `FAIL_ORCHESTRATOR_TASK_NOT_ALLOWED` per INV-PLANNER-HARNESS-06.1; environment-binding logic never reached.
      - **`--no-strict` does not bypass.** Plan with cross-env credentials submitted with `--no-strict` → `FAIL_TASK_ENVIRONMENT_INCONSISTENT` still fires (structural invariant; not a warning-class check).
      - **`--no-strict` does not bypass same-cluster.** Plan with same-cluster conflation, no acknowledgment, `--no-strict` → `FAIL_SAME_CLUSTER_NAMESPACE_ISOLATION` still fires.
      - **Audit attribution.** `InitiativeCreated` audit event includes `task_environment_bindings: [{task, binding, bound_via}, ...]` per §11.9 for every admitted task.

---

## 11. Task Environment Consistency (`INV-ENV-01`)

> **Canonical home for `INV-ENV-01`.** The invariant statement also
> appears in `invariants.md §Environment`. This section is the
> normative behavioral specification; `invariants.md` is the
> short-form catalog entry. If the two ever conflict, this section
> wins.

### 11.1 Why this invariant exists

Without an explicit consistency rule, an operator could write a single
task that holds credentials for both `beta` and `production` and have
egress allowlists that match both environments' URL gates. The kernel
would inject both credentials into the same VM, Layer-1 / Layer-2 /
Layer-3 would all admit it, and a confused (or compromised) agent
inside that VM could authenticate to either environment from the same
process at the same time. That is the canonical "blast radius" failure
mode — credentials and reach for two compliance boundaries colocated
in one execution context.

The fix is structural: forbid environment mixing within a single task.
A task is bound to **at most one** environment for the lifetime of its
session(s). Cross-environment data flows are expressed at the DAG
level (§11.5), where the kernel mediates the artifact handoff and
each task only ever holds credentials for one environment.

### 11.2 The invariant

`INV-ENV-01` — **Task Environment Consistency.**

> **When activated** (per §1.5.2 — at least one `[environments.<label>]`
> declared in the loaded policy), every admitted task in every plan
> bundle binds to AT MOST ONE environment. The set of environments
> a task binds to is computed by walking the task's environment-bound
> resources per the §11.3 algorithm; if the resulting set contains
> more than one label, admission fails with
> `FAIL_TASK_ENVIRONMENT_INCONSISTENT`.

Tasks whose computed set is empty (cardinality 0) are
**environment-neutral** and pass trivially. Tasks whose computed set
has exactly one element are bound to that environment for audit and
for any future per-environment policy knob. No other cardinality is
admissible.

### 11.3 The binding algorithm

Pseudocode for the per-task check (runs once per task at
`approve_plan`, after Layer-1 / Layer-2 / Layer-3 individual checks
have passed):

```rust
fn compute_task_envs(task: &PlanTask, policy: &PolicyBundle) -> Result<TaskEnvBinding> {
    let mut envs: BTreeSet<EnvLabel> = BTreeSet::new();
    let mut sources: Vec<(EnvLabel, EnvSource)> = Vec::new();

    // Step A — environment-bound credentials
    for cred_decl in &task.credentials {
        let permitted = policy.permitted_credentials
            .iter()
            .find(|c| c.name == cred_decl.name)
            .ok_or(FAIL_CREDENTIAL_NOT_PERMITTED)?;
        if let Some(env) = &permitted.environment {
            envs.insert(env.clone());
            sources.push((env.clone(), EnvSource::Credential(cred_decl.name.clone())));
        }
        // No `environment` field → neutral; contributes nothing.
    }

    // Step B — environment-bound egress (URL ↔ gate matching)
    for egress in &task.allowed_egress {
        let matching_gates = policy.environment_gates
            .iter()
            .filter(|g| egress_url_matches_gate(&egress.url_prefix, g))
            .collect::<Vec<_>>();

        if matching_gates.len() == 1 {
            let label = matching_gates[0].label.clone();
            envs.insert(label.clone());
            sources.push((label, EnvSource::EgressUrl(egress.url_prefix.clone())));
        } else if matching_gates.len() > 1 {
            // Same-cluster conflation case (§11.4).
            return handle_same_cluster_conflation(task, egress, matching_gates, policy);
        }
        // Zero matches → neutral egress; contributes nothing.
    }

    // Step C — cardinality enforcement
    match envs.len() {
        0 => Ok(TaskEnvBinding::Neutral),
        1 => Ok(TaskEnvBinding::Bound(envs.into_iter().next().unwrap())),
        _ => Err(FAIL_TASK_ENVIRONMENT_INCONSISTENT {
            task: task.task_id.clone(),
            environments: envs.into_iter().collect(),
            sources,
        }),
    }
}
```

The check is **per task, not per session**. A task that fans out
across three sessions (Executor scaling) inherits the task's binding
on every session; the kernel does not allow per-session environment
override. This is enforced at admission, not at runtime, so the
validation is one-shot and cheap.

### 11.4 Same-cluster conflation interaction

When a single egress URL prefix matches two or more environment gates
(the `§3 Tension T1` same-cluster scenario), the algorithm hands off
to the same-cluster handler:

```rust
fn handle_same_cluster_conflation(
    task: &PlanTask,
    egress: &EgressDecl,
    matching_gates: Vec<&EnvironmentGate>,
    policy: &PolicyBundle,
) -> Result<TaskEnvBinding> {
    let conflated_envs: Vec<EnvLabel> =
        matching_gates.iter().map(|g| g.label.clone()).collect();

    // For each conflated env, look up its [environments.<label>] entry
    // and check same_cluster_acknowledged.
    let acknowledgments: Vec<(EnvLabel, bool)> = conflated_envs.iter()
        .map(|label| {
            let env_def = policy.environments.get(label)
                .expect("§5b.3 ensures every gate label resolves");
            (label.clone(), env_def.same_cluster_acknowledged)
        })
        .collect();

    let all_acknowledged = acknowledgments.iter().all(|(_, ack)| *ack);

    if !all_acknowledged {
        return Err(FAIL_SAME_CLUSTER_NAMESPACE_ISOLATION {
            task: task.task_id.clone(),
            url_prefix: egress.url_prefix.clone(),
            conflated_environments: conflated_envs,
            unacknowledged: acknowledgments.into_iter()
                .filter(|(_, ack)| !ack)
                .map(|(label, _)| label)
                .collect(),
        });
    }

    // All conflated envs declared `same_cluster_acknowledged = true`.
    // The URL gate contributes ZERO labels to the task's env set; the
    // operator is taking responsibility for namespace separation via
    // credential / cloud RBAC scoping rather than URL-level isolation.
    // Return success with no contribution; the caller continues
    // processing other egress entries and credentials.
    Ok(TaskEnvBinding::SameClusterAcknowledged)
}
```

**Why "all conflated envs must acknowledge", not "any single env":**

A same-cluster pattern between `beta` and `production` is a property
of *both* environments. Requiring acknowledgment on each forces the
operator (or operators, in a future two-party signing world) to mark
each environment definition deliberately. A single junior operator
cannot "acknowledge away" the pattern from the staging side without
the production environment definition also bearing the mark — which
shows up in the policy diff and in `raxis-cli plan explain`.

**Alternatives considered and rejected:**

- **Acknowledgment on the gate, not the environment:** Spreads the
  acknowledgment across N gates for a hostname; harder to inspect
  ("is this whole environment same-cluster?"). Putting the
  acknowledgment on the environment definition makes it a property
  of the environment, queryable in one place.
- **A single global `[policy] same_cluster_warnings = "off"`:** Too
  blunt; operators who want acknowledgment for one specific case
  end up suppressing it everywhere.
- **Acknowledgment on the plan task instead of the policy:** Lets
  the operator (or a compromised plan signer) bypass the policy
  floor without a policy update. INV-POLICY-01 says floors live in
  policy; same-cluster acknowledgment is a floor exception so it
  belongs in policy.

### 11.5 Cross-environment workflows: the DAG split pattern

Operators sometimes legitimately need to move data across environment
boundaries — promoting a verified artifact from `beta` to `production`,
hydrating staging from a sanitized prod snapshot, etc. Under
`INV-ENV-01` this CANNOT be expressed as a single task with both
environments' credentials. The canonical pattern is:

```toml
# WRONG — rejected with FAIL_TASK_ENVIRONMENT_INCONSISTENT.

[[plan.tasks]]
task_name = "promote_artifact"
role    = "Executor"

[[plan.tasks.credentials]]
name = "registry-beta-read"          # → bound to "beta"

[[plan.tasks.credentials]]
name = "registry-prod-write"         # → bound to "production"

# At approve_plan: compute_task_envs() returns {beta, production} →
# FAIL_TASK_ENVIRONMENT_INCONSISTENT { task: "promote_artifact",
#   environments: ["beta", "production"],
#   sources: [
#     (Credential("registry-beta-read"), "beta"),
#     (Credential("registry-prod-write"), "production"),
#   ] }
```

```toml
# RIGHT — split into two DAG-connected tasks; the kernel mediates the
# handoff via the artifact mechanism (verifier-processes.md §6 or the
# task-output store, depending on workflow).

[[plan.tasks]]
task_name = "fetch_from_beta"
role    = "Executor"

[[plan.tasks.credentials]]
name = "registry-beta-read"          # bound to "beta" — task is bound to "beta"

# This task fetches the artifact, computes its SHA-256, writes it to the
# task-output store under a stable key, and exits. It NEVER holds prod
# credentials.

[[plan.tasks]]
task_name    = "publish_to_prod"
role       = "Executor"
depends_on = ["fetch_from_beta"]

[[plan.tasks.credentials]]
name = "registry-prod-write"         # bound to "production" — task is bound to "production"

# This task reads the artifact via the kernel-mediated handoff (the
# kernel furnishes the bytes from the prior task's output, computing
# and verifying the SHA-256 against what fetch_from_beta recorded),
# then publishes to prod. It NEVER holds beta credentials.
```

**What this pattern buys:**

- The `beta`-credentialed VM and the `production`-credentialed VM are
  **separate processes** with separate kernels, separate filesystems,
  separate VirtioFS mounts. There is no execution context that holds
  both credentials simultaneously.
- The kernel mediates the artifact handoff. Both tasks' SHA-256
  records appear in the audit chain. A forensic auditor can answer
  "what bytes flowed from beta to prod?" by reading two task IDs.
- Adding a Reviewer between the two tasks (`review_promotion` task,
  Reviewer role, depends on `fetch_from_beta`, gates
  `publish_to_prod`) is a pure additive DAG edit. Neither side of
  the handoff has to change.
- A future per-environment two-party-sign requirement
  (§5b.4 reserved field) can land on `production` without affecting
  `beta`'s authoring flow.

**Anti-patterns this rules out:**

- A single VM that holds both credentials and "carefully" scopes its
  own access. There's no kernel-side enforcement that the agent
  actually does this; it's a code-review property at best, and the
  audit log can't tell you the agent didn't accidentally fan out a
  beta credential into a prod-bound HTTP request.
- Manual sneakernet (operator copies bytes from a beta task's output
  into a prod task's input out-of-band). The audit chain has no
  record of the handoff, so the prod write looks like it materialized
  from nowhere.

**Cross-references:**

- [`verifier-processes.md §6`](verifier-processes.md) — artifact mechanism for handing
  structured data between tasks.
- [`kernel-mechanics-prompt.md §3.2`](kernel-mechanics-prompt.md) — Orchestrator sees the DAG
  topology when sequencing tasks.
- [`operator-ergonomics.md §9`](operator-ergonomics.md) (`raxis-cli plan explain`) — renders
  the DAG and per-task environment binding so the operator can
  inspect the handoff structure at authoring time.

### 11.6 Reviewer and Orchestrator are environment-neutral by structure

Reviewer and Orchestrator tasks have **cardinality 0** for
environment-bound resources by structural prohibition, not by operator
choice:

| Role | Operator credentials? | Operator-controlled egress? | Cardinality | INV-ENV-01 status |
|---|---|---|---|---|
| Executor | Yes (`[[plan.tasks.credentials]]`) | Yes (`allowed_egress`) | 0..N | Must resolve to 0 or 1 environment. |
| Reviewer | **No** (`INV-PLANNER-HARNESS-01`: pure-static, no `bash`) — read-only filesystem; no credentials are injected because no network call would consume them | **No** (`INV-PLANNER-HARNESS-04`: no operator-egress) | **0** | **Always neutral by structure.** |
| Orchestrator | **No** (`INV-PLANNER-HARNESS-06.1`: Orchestrator tasks are not declarable in `plan.toml`; the kernel auto-creates them and owns the configuration) | **No** (`INV-PLANNER-HARNESS-06`: no operator-controlled egress) | **0** | **Always neutral by structure.** |

This means:

1. **An operator never declares an environment binding on a Reviewer
   or Orchestrator task.** The schema for those roles forbids
   `[[plan.tasks.credentials]]` and `allowed_egress` declarations
   already (per [`planner-harness.md §3`](planner-harness.md) role table); the
   environment-consistency check is a no-op for them.
2. **A cross-environment DAG (§11.5) where the Reviewer gates the
   handoff between a beta task and a prod task is well-defined**:
   the Reviewer reads the artifact from the kernel store (no
   credentials, no egress, no environment binding), produces a
   `ReviewSubmission`, and the Orchestrator (also environment-neutral)
   sequences the gated `publish_to_prod` task.
3. **Forensic attribution.** The audit chain records each task's
   binding (Bound("beta"), Bound("production"), or Neutral). Reviewer
   and Orchestrator tasks always show as Neutral, which matches their
   structural lack of authority over environment-scoped resources.

This is a natural question because the obvious operator instinct is
"my Reviewer will inspect a beta task's output before I let it merge
into prod — does the Reviewer somehow span beta and prod?" The answer
is no: the Reviewer holds no credentials and reaches no URLs in either
environment. It is a pure-static analyzer acting on bytes; the
environment binding is meaningless for it.

### 11.7 Failure code: `FAIL_TASK_ENVIRONMENT_INCONSISTENT`

| Field | Description |
|---|---|
| `task` | Task ID that failed the check. |
| `environments` | Sorted list of distinct labels that the task's resources resolved to. Always size ≥ 2 when this code fires. |
| `sources` | Per-label list of `(EnvSource, label)` pairs. Each `EnvSource` is one of `Credential(name)` or `EgressUrl(url_prefix)`. Lets the operator pinpoint exactly which credential or which URL caused the binding. |

CLI rendering (per the [`operator-ergonomics.md §20`](operator-ergonomics.md) failure-code
display contract):

```yaml
✗ FAIL_TASK_ENVIRONMENT_INCONSISTENT
   task: promote_artifact
   environments: beta, production

   bound to "beta" via:
     - credential "registry-beta-read"

   bound to "production" via:
     - credential "registry-prod-write"

   per INV-ENV-01: a task may bind to AT MOST ONE environment.
   recommended fix: split into two DAG-connected tasks; see
   environment-access-control.md §11.5.
```

**Behavior is `--strict`-irrelevant.** This failure is NOT downgraded
by `--no-strict`. INV-ENV-01 is a structural invariant, not a
warning-class hygiene check. Operators who genuinely need a
cross-environment workflow refactor the plan per §11.5; there is no
escape hatch on the consistency check itself.

### 11.8 Interaction with existing checks

| Existing check | Interaction with INV-ENV-01 |
|---|---|
| Layer 1 — plan `allowed_egress` (`§2`) | Runs first, per task. If the URL hostname isn't in `policy.egress_hosts` at all, the task fails before INV-ENV-01 ever computes a binding. |
| Layer 2 — credential injection (`§5`) | `FAIL_CREDENTIAL_NOT_PERMITTED` runs before INV-ENV-01; an undeclared credential never participates in the binding computation. |
| Layer 3 — environment gate `block_all` (`§7 FAIL_ENVIRONMENT_BLOCKED`) | Runs first per egress URL; URLs blocked here never participate in the binding computation. |
| `WARN_CREDENTIAL_UNREACHABLE_ENVIRONMENT` (`§7`) | Compatible. After INV-ENV-01 confirms a single-environment binding, the unreachable-credential warning may still fire if the credential's environment doesn't match any *reachable* egress URL inside the binding. |
| `FAIL_SAME_CLUSTER_NAMESPACE_ISOLATION` (`§7`, promoted from WARN — see §11.4) | INV-ENV-01 invokes the same-cluster handler when its URL-matching loop sees multi-gate matches. They share an algorithm, not separate codepaths. |
| `WARN_ENVIRONMENT_GATE_WRITE_REQUIRES_APPROVAL` (`§7`) | Compatible. Independent of binding cardinality. |

### 11.9 Audit and forensic attribution

Every `InitiativeCreated` audit event records, per task, the resolved
binding:

```rust
TaskEnvironmentBinding {
    task_id:     String,
    binding:     "Neutral" | "Bound(<label>)" | "SameClusterAcknowledged",
    bound_via:   Vec<(EnvSource, EnvLabel)>,   // empty for Neutral
}
```

This makes the post-hoc question "which initiatives ever ran in
production?" answerable by indexing the audit chain on
`InitiativeCreated.task_environment_bindings[].binding`, no separate
inference required.

V2.x audit-retention policies (the reserved
`audit_retention_days` field per §5b.4) will key off this binding; an
initiative whose tasks all bound to `production` would, in a future
release, retain audit records longer than one whose tasks all bound
to `beta`.

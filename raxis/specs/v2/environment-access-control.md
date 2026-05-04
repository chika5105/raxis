# RAXIS V2 — Environment-Scoped Access Control

> **Status:** V2 Specified
> **Cross-references:**
> - `policy-plan-authority.md §INV-POLICY-01` — Policy as immutable floor
> - `v2-deep-spec.md §INV-VM-CAP-04` — VirtioFS mounts hardcoded; credentials/ never mounted
> - `integration-merge.md §12` — Escalation-as-amendment pattern
> - `kernel-mediated-egress.md` — Two-level egress allowlist baseline

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
task_id = "deploy-staging"

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

This is documented as a known limitation. `WARN_SAME_CLUSTER_NAMESPACE_ISOLATION` is emitted at `approve_plan` when a task declares a url_prefix that matches both a staging and prod environment gate prefix on the same hostname.

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
   change or remove the environment gate (requires `raxis policy push` with new epoch)

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

```
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
task_id = "deploy-staging"

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

## 6. Environment Gate — Write Approval Escalation Flow

When `write_requires_approval = true` fires (Step 4 of admission):

```
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
The approval records the exact URL. If the agent tries to reuse `esc-77` for a different
URL or a different method, `FAIL_APPROVAL_URL_MISMATCH` is returned.

---

## 7. approve_plan Warnings and Errors

### FAIL_ENVIRONMENT_BLOCKED (hard error)

**Trigger:** A task's `allowed_egress` declares a URL prefix that matches a policy
`[[environment_gates]]` entry with `block_all = true`.

**Behavior:** Plan rejected regardless of `--no-strict`. The `block_all` gate is a
categorical policy floor — it cannot be overridden by plan configuration or `--no-strict`.

**Fix:** Remove the blocked URL from `allowed_egress`, or update the policy bundle to
change or remove the `block_all` gate (requires `raxis policy push`, new epoch).

---

### FAIL_CREDENTIAL_NOT_PERMITTED (hard error)

**Trigger:** A task declares `[[tasks.credentials]] name = "k8s-prod"` but `k8s-prod`
does not appear in policy `[[permitted_credentials]]`.

**Behavior:** Plan rejected regardless of `--no-strict`. Credentials must be explicitly
declared in the policy bundle before any plan can reference them. This prevents plans
from referencing arbitrary files in `credentials/`.

**Fix:** Add the credential to policy `[[permitted_credentials]]` via `raxis policy push`.

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

### WARN_SAME_CLUSTER_NAMESPACE_ISOLATION

**Trigger:** A task declares `allowed_egress` for a URL that matches the same hostname
as a policy `[[environment_gates]]` label, but the URL prefix cannot distinguish between
namespaces on that cluster (same hostname covers both staging and prod namespaces).

**Example:** Policy has environment gate for `https://k8s-api.company.com/` labeled
"production". Task declares `url_prefix = "https://k8s-api.company.com/"` — this URL
covers both staging and production namespaces on the same cluster.

**Kernel behavior:** Environment gate fires based on URL prefix match. All write methods
to this URL require approval (if `write_requires_approval = true`), including staging
namespace writes. The agent cannot distinguish namespaces at the egress layer alone.

**Fix (recommended):** Use separate clusters for staging and prod with distinct hostnames.
This eliminates the namespace-level ambiguity at the network layer.

**With `--strict` (default):** Plan rejected.

---

### approve_plan Check Order (Updated with Environment Checks)

```
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
      - URL matches environment_gate label (same hostname, namespace ambiguity)?
        → WARN_SAME_CLUSTER_NAMESPACE_ISOLATION
   c. For each credentials entry:
      - name in policy permitted_credentials? → FAIL_CREDENTIAL_NOT_PERMITTED (hard)
      - credential environment matches any allowed_egress environment? If no match
        → WARN_CREDENTIAL_UNREACHABLE_ENVIRONMENT
4. integration_merge_gates checks → WARN_PROTECTION_OVERRIDDEN etc.
5. require_push_approval vs. policy minimum → WARN_PUSH_APPROVAL_DOWNGRADED
6. token_policy uncapped fields → WARN_UNCAPPED_TOKEN_LIMIT
7. estimated_cost vs. lane ceiling → hard error if exceeds
8. Collect all warnings
9. If strict → reject on any warning; else approve with warnings in audit event
```

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

---

## 9. Defense-in-Depth Model

For the specific case of "agent creates k8s resource in staging, blocked from prod":

```
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
- [ ] Add `KernelPush::EgressApprovalRequired` and `EgressApprovalRejected` variants
- [ ] Implement `WARN_ENVIRONMENT_GATE_WRITE_REQUIRES_APPROVAL` at `approve_plan`
- [ ] Implement `WARN_CREDENTIAL_UNREACHABLE_ENVIRONMENT` at `approve_plan`
- [ ] Implement `WARN_SAME_CLUSTER_NAMESPACE_ISOLATION` at `approve_plan`
- [ ] Implement `FAIL_ENVIRONMENT_BLOCKED` at `approve_plan` (hard error)
- [ ] Implement `FAIL_CREDENTIAL_NOT_PERMITTED` at `approve_plan` (hard error)
- [ ] Implement `raxis egress diff/approve/reject` CLI commands
- [ ] Add environment gate admission checks to `approve_plan` check order (step 3b)
- [ ] Tests:
      - Block_all gate: plan with prod URL → FAIL_ENVIRONMENT_BLOCKED at approve_plan
      - Write_requires_approval: POST to prod URL → escalation created
      - Write approval: consumed approval → request admitted
      - Write approval: wrong URL → FAIL_APPROVAL_URL_MISMATCH
      - Credential injection: staging task gets staging kubeconfig only
      - Undeclared credential: FAIL_CREDENTIAL_NOT_PERMITTED at approve_plan
      - Unreachable credential: WARN_CREDENTIAL_UNREACHABLE_ENVIRONMENT at approve_plan
      - Same-cluster namespace: WARN_SAME_CLUSTER_NAMESPACE_ISOLATION at approve_plan
      - Defense-in-depth: all 4 layers present, each independently blocks prod access

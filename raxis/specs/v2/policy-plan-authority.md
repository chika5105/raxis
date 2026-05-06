# RAXIS V2 — Policy-Plan Authority Hierarchy

> **Status:** V2 Specified
> **Cross-references:**
> - `integration-merge.md §12` — Protected path approval gate
> - `integration-merge.md §12.b` — Plan-level integration merge gates (additive)
> - `integration-merge.md §13` — Git push approval gate
> - `vm-network-isolation.md` — Tier-1 (public) egress via tproxy SNI allowlist
> - `credential-proxy.md` — Tier-2 (authenticated) egress via per-credential URL/method allowlist
> - ~~`kernel-mediated-egress.md`~~ — DEPRECATED in V2 in favor of unified two-tier egress (see above)
> - `v2-deep-spec.md §INV-VM-CAP-03` — VM image policy bundle validation
> - `planner-harness.md §4.5` — Canonical Reviewer image (`INV-PLANNER-HARNESS-02`); the basis for `FAIL_REVIEWER_VM_IMAGE_NOT_ALLOWED` and `FAIL_REVIEWER_IMAGE_DIGEST_MISMATCH`
> - `planner-harness.md §4.7` — Canonical Orchestrator image (`INV-PLANNER-HARNESS-05`); the basis for `FAIL_ORCHESTRATOR_VM_IMAGE_NOT_ALLOWED` and `FAIL_ORCHESTRATOR_IMAGE_DIGEST_MISMATCH`
> - `planner-harness.md §4.8` — Orchestrator not operator-configurable (`INV-PLANNER-HARNESS-06`); the basis for `FAIL_ORCHESTRATOR_PROFILE_NOT_ALLOWED`, `FAIL_ORCHESTRATOR_TASK_NOT_ALLOWED`, `FAIL_PROFILE_ROLE_NOT_CONFIGURABLE`, and the new `[orchestrator]` policy section
> - `planner-harness.md §10.2` — Linux 5.14+ VM guest kernel (`INV-PLANNER-HARNESS-03`); the basis for `FAIL_VM_GUEST_KERNEL_TOO_OLD`
> - `verifier-processes.md §3` — V2 task verifier schema; the basis for `FAIL_VERIFIER_*` codes
> - `verifier-processes.md §6.3` — Artifact validation; the basis for `FAIL_DECLARED_ARTIFACT_MISSING`
> - `custom-tools.md` — Operator-defined custom tools; the basis for `WARN_CUSTOM_TOOL_SCHEMA_BUDGET_HIGH` and the `FAIL_CUSTOM_TOOL_*` family. `INV-PLANNER-HARNESS-04` (Reviewer Custom Tool Prohibition) is the basis for `FAIL_REVIEWER_CUSTOM_TOOL_NOT_ALLOWED`.

---

## 1. The Core Invariant — INV-POLICY-01

> **INV-POLICY-01: The policy bundle is the immutable security floor. The plan operates
> within the policy envelope. Plans may only add protections; they may never remove or
> weaken protections established by the policy bundle.**

This invariant applies uniformly across all features. For each configurable dimension:

### Why Approach A Has the Strongest Security Model

Of the four approaches considered (see §8), Approach A provides the strongest security
posture for three reasons:

**1. The security floor is unconditional.** Policy protections cannot be removed,
weakened, or worked around by any plan — regardless of how the plan is constructed.
This is a structural property, not a runtime check. An attacker who gains the ability
to write arbitrary plan files still cannot disable deployment-level security controls
because the Kernel's enforcement of the policy floor is not predicated on the plan
being well-behaved.

**2. The failure mode is safe.** When policy and plan conflict, the more restrictive
interpretation always wins. There is no scenario where a conflict produces weaker
security than either policy or plan alone. This means the system degrades gracefully:
a misconfigured plan produces more security, not less.

**3. Strict-by-default closes the warning gap.** Approach A combined with `--strict`
as the default means policy-plan divergences never silently reach production. Every
divergence that reaches the Kernel has been explicitly acknowledged by the operator
(by running `--no-strict`), which is recorded in the `InitiativeCreated` audit event.
Auditors can query all initiatives approved with `approved_strict = false` and review
the specific warnings that were acknowledged.

Approaches B, C, and D all introduce mechanisms that complicate the enforcement model
(strict field separation, overridability flags, key hierarchy) without adding security
properties beyond what Approach A achieves through the simpler UNION/INTERSECTION rule
and strict-by-default approval.

| Dimension | Policy role | Plan role | Conflict resolution |
|---|---|---|---|
| VM images | Defines the permitted set + OCI digests | Selects one from the permitted set | Plan outside set → `FAIL_VM_IMAGE_NOT_PERMITTED` at `approve_plan` |
| Egress hosts | Defines permitted hostnames + methods | Declares per-task URL prefixes + methods | Plan methods beyond policy methods → Warning + runtime enforcement at policy ceiling |
| Protected merge paths | Always-required approval prefixes | Additive per-initiative extra gates | Plan `require_approval = false` for policy-protected path → Warning (policy enforced regardless) |
| Push approval | Minimum requirement (`require_push_approval_minimum`) | Per-initiative on/off | Plan `false` below policy minimum → Warning (policy enforced regardless) |
| Budget / lane ceiling | Hard ceiling values | `estimated_cost` estimate | Estimate exceeds ceiling → `FAIL_BUDGET_EXCEEDED` at admission |

**Permission dimensions** (egress, VM images, providers) follow INTERSECTION:
the effective permission is `policy ∩ plan`. The plan can only narrow, never expand.

**Protection dimensions** (protected paths, push approval) follow UNION:
the effective protection is `policy ∪ plan`. The plan can only add, never remove.

---

## 2. The `approve_plan` Warning System

### Philosophy

When a plan field conflicts with the policy bundle in a way that INV-POLICY-01 resolves
deterministically (the policy wins), the Kernel does not silently ignore the plan field
and it does not reject the plan. Instead it:

1. **Approves the plan** — the conflict is resolvable, the initiative can proceed
2. **Issues a warning** — explaining precisely what the plan field said and what the
   Kernel will actually do instead
3. **Lets the operator decide** — if the divergence is intentional (the operator knows),
   they proceed. If it was a mistake, they fix the plan.

This is the correct ergonomic trade-off: silent downgrade hides real mistakes; hard rejection
blocks legitimate workflows. The warning makes the Kernel's behavior fully transparent
without preventing the initiative from running.

### CLI Behavior

```bash
# Default: strict mode — any warning is a rejection
raxis plan approve plan.toml

# Lenient mode: approve with warnings displayed (opt-out from strict)
raxis plan approve --no-strict plan.toml

# Suppress warning output (strict mode still applies — only suppresses stdout display)
raxis plan approve --no-warnings plan.toml
```

**Why `--strict` is the default:**
Approach A is the strongest security model because the policy bundle is the immutable
floor. Approving a plan that silently diverges from policy — even with a warning — means
the initiative runs with operator expectations that don't match Kernel behavior. In a
production deployment this is a subtle but real risk: an operator believes they configured
X, the Kernel enforces Y, and the difference only becomes apparent at runtime. Strict
mode as default ensures every policy-plan divergence is a conscious, explicit operator
decision — not a mistake that was waved through.

**`--no-strict` use cases:**
- Deployments where the operator is aware of the divergence and accepts it
- Iterative plan development where the operator is prototyping and wants to run despite
  known policy gaps
- Plans that include intentionally redundant gate declarations for documentation clarity

**`--no-warnings` use cases:**
- Suppresses warning stdout output; strict mode behavior is unchanged
- Use when piping `raxis plan approve` output to a structured log collector that
  expects clean output; warnings are still recorded in the `InitiativeCreated` audit event

### Warning Output Format

```
raxis plan approve plan.toml

Validating plan against policy bundle (epoch 7)...

⚠ WARN [WARN_PROTECTION_OVERRIDDEN] plan.toml line 24
  [[integration_merge_gates]] declares require_approval = false for "src/payments/"
  This path is already protected by policy.toml [[protected_paths]].
  ─ Plan field value:   require_approval = false
  ─ Kernel behavior:   policy protection enforced; approval will be required regardless
  ─ Effect:            the plan field has no effect for this path prefix

⚠ WARN [WARN_PUSH_APPROVAL_DOWNGRADED] plan.toml line 8
  [plan] require_push_approval = false
  Policy bundle sets require_push_approval_minimum = true
  ─ Plan field value:   require_push_approval = false
  ─ Kernel behavior:   push approval will be required for this initiative
  ─ Effect:            plan field silently upgraded to true by policy floor

2 warning(s). Plan rejected (strict mode is default). Use --no-strict to approve with warnings.

Initiative ID: 3f7a9c2e
Plan SHA-256:  a4b8c1d3...
Policy epoch:  7
```

**With `--no-strict`:**
```
raxis plan approve --no-strict plan.toml

Validating plan against policy bundle (epoch 7)...

⚠ WARN [WARN_PROTECTION_OVERRIDDEN] plan.toml line 24
  ...

2 warning(s). Plan approved (--no-strict). Warnings recorded in audit chain.
Initiative ID: 3f7a9c2e
```

### Warning record in audit chain

Warnings are recorded in the `InitiativeCreated` audit event:

```rust
AuditEventKind::InitiativeCreated {
    initiative_id:    Uuid,
    plan_sha256:      String,
    policy_epoch:     u64,
    approve_warnings: Vec<ApproveWarning>,   // empty if no warnings
    approved_strict:  bool,                  // true if --strict was used and passed
}

pub struct ApproveWarning {
    pub code:          String,   // e.g., "WARN_PROTECTION_OVERRIDDEN"
    pub plan_location: String,   // e.g., "plan.toml line 24"
    pub description:   String,
    pub plan_value:    String,   // what the plan said
    pub kernel_value:  String,   // what the Kernel will actually do
}
```

Auditors can query initiatives that were approved with warnings — useful for compliance
review of any initiative that had a policy-plan mismatch.

---

## 3. Warning Catalog

### WARN_PROTECTION_OVERRIDDEN

**Trigger:** A `[[integration_merge_gates]]` entry in `plan.toml` declares
`require_approval = false` for a path prefix that is already covered by a
`[[protected_paths]]` entry in `policy.toml`.

**Kernel behavior:** The policy-level protection is enforced. The plan field has no
effect. The path will require operator approval on `IntegrationMerge`.

**Why a warning, not an error:** The operator may have included this entry by mistake
(copy-paste from a template that included the field), or may be aware that the policy
protects this path and explicitly wants to confirm no additional requirement — i.e., the
`false` was intentional as a "no further action needed." The warning surfaces the
discrepancy without blocking the initiative.

**Recommended fix:** Remove the `[[integration_merge_gates]]` entry for paths already
protected by policy. It is redundant and misleading.

---

### WARN_PUSH_APPROVAL_DOWNGRADED

**Trigger:** `plan.toml` sets `require_push_approval = false` (or omits the field,
defaulting to `false`), but `policy.toml` sets `require_push_approval_minimum = true`.

**Kernel behavior:** Push approval will be required for this initiative. The plan field
is silently upgraded to `true` by the policy floor.

**Why a warning, not an error:** `false` is the default. An operator who did not set
`require_push_approval` explicitly in their plan may not know the deployment policy
requires it. The warning informs them that push approval will apply even though they
didn't configure it.

**Recommended fix:** Explicitly set `require_push_approval = true` in `plan.toml` to
match the enforced behavior, eliminating the warning.

---

### WARN_EGRESS_METHOD_RESTRICTED

**Trigger:** A `[[tasks.allowed_egress]]` entry in `plan.toml` declares a method
(e.g., `"POST"`) that is not permitted by the corresponding `[[egress_hosts]]` entry in
`policy.toml` for that hostname.

**Kernel behavior:** At `EgressRequest` admission (Check E4), only policy-permitted
methods are accepted. The plan's declared method is effectively restricted to the
policy ceiling.

**Why a warning, not an error:** The plan declares *intent* for what methods a task
wants. The policy decides what is *permitted*. The warning surfaces that the task's
declared method capability will be narrower than planned — it may affect the agent's
ability to complete its work, which the operator should know about before running.

**Recommended fix:** Either (a) update `policy.toml` to permit the needed method for
the hostname, or (b) remove the method from `plan.toml` allowed_egress to match reality.

---

### WARN_INTEGRATION_MERGE_GATE_REDUNDANT

**Trigger:** A `[[integration_merge_gates]]` entry in `plan.toml` declares
`require_approval = true` for a path prefix that is already covered by a
`[[protected_paths]]` entry in `policy.toml`. This is a redundant (but harmless)
duplicate declaration.

**Kernel behavior:** The UNION operation deduplicates the entry. No change in
enforcement — the path already required approval via the policy.

**Why a warning, not an error:** Strictly harmless. The warning surfaces that the plan
entry is redundant and can be cleaned up.

**Recommended fix:** Remove the redundant `[[integration_merge_gates]]` entry. The
policy-level protection already covers it.

---

### WARN_UNCAPPED_TOKEN_LIMIT

**Trigger:** A `[[tasks.token_policy]]` section is present in `plan.toml` but one or
more limit fields are omitted (defaulting to `TokenLimit::Uncapped` implicitly). Or a
plan has no `[tasks.token_policy]` section at all, meaning all limits are implicitly
uncapped for that task.

**Kernel behavior:** The session runs with no ceiling on token consumption for the
uncapped limit types. A session with `TokenLimit::Uncapped` on `max_tokens_total` can
consume unlimited tokens — constrained only by the budget lane ceiling (which is
token-blind in the current spec unless `token_proportional` weights are configured).

**Why a warning, not an error:** Some tasks are genuinely exploratory and the operator
may not know an appropriate limit in advance. The warning surfaces the risk consciously:
the operator must either set a limit OR explicitly declare `"uncapped"` to suppress it.

**Suppressing the warning:** Explicitly declare `"uncapped"` in the plan:

```toml
[tasks.token_policy]
max_tokens_input_per_request  = "uncapped"   # explicit — warning suppressed
max_tokens_output_per_request = "uncapped"   # explicit — warning suppressed
max_tokens_total              = 2_000_000    # capped — no warning
```

An implicit omission generates the warning. An explicit `"uncapped"` does not — the
operator has consciously acknowledged the choice.

**With `--strict` (default):** Plan rejected. The operator must either set limits or
explicitly declare `"uncapped"` for each uncapped dimension.

**With `--no-strict`:** Plan approved with warning. Uncapped limits are recorded in the
`InitiativeCreated` audit event's `approve_warnings`.

**Recommended fix:** Set explicit limits appropriate to the task's expected complexity.
If the task is genuinely unbounded, declare `"uncapped"` explicitly.

---

### WARN_REVIEWER_MISSING_SYMBOL_INDEX

**Trigger:** A `[[plan.tasks.X]]` with `role = "Reviewer"` does NOT have at least
one verifier (declared either at task scope under
`[[plan.tasks.<evaluation_target>.verifiers]]` for the Reviewer's evaluation
target, or at the Reviewer's task scope itself) that produces an artifact at
`/raxis/symbol_index.json` per `verifier-processes.md §6`.

**Kernel behavior:** The Reviewer is activated normally with no symbol index in
its `/raxis/`. The Reviewer LLM falls back to `grep_search` for symbol resolution
(slower; higher token cost; less precise on overloaded names).

**Why a warning, not an error:** Many tasks do not need symbol-index-grade
review (small isolated changes, doc updates, config edits). Mandating a symbol
index for every Reviewer would (a) burden plan authors with verifier
declarations they don't need, (b) add wall-clock latency to every Reviewer
activation, (c) consume verifier-VM capacity unnecessarily. The warning
surfaces the trade-off so the operator decides whether to add the verifier
for cost/latency vs. review quality.

**Performance note (operator-facing):** Without a symbol index, the Reviewer
LLM consumes substantially more input tokens performing symbol resolution
across larger codebases. For tasks reviewing changes in codebases of >50 KLOC,
operators commonly observe 2–4× the input-token consumption relative to
runs with the symbol index present. Operators concerned about token cost
should consider declaring a symbol-index verifier; the kernel does NOT make
this decision on the operator's behalf.

**Suppressing the warning:** Either (a) declare a symbol-index verifier per
`verifier-processes.md §6.1`:

```toml
[[plan.tasks.web_implementer.verifiers]]
name        = "symbol_index"
image       = "raxis/parsers:1"
command     = "ctags --output-format=json -R -f /raxis/symbol_index.json /workspace"
timeout     = "2m"
on_failure  = "warn_only"     # if symbol indexing fails, Reviewer still activates
artifact    = "/raxis/symbol_index.json"
```

OR (b) add `[plan.tasks.<reviewer_task_id>.review] symbol_index = "not_needed"`
to acknowledge that this Reviewer does NOT need a symbol index. The explicit
"not_needed" silences the warning by recording the operator's conscious choice.

**With `--strict` (default):** Plan rejected as `FAIL_REVIEWER_MISSING_SYMBOL_INDEX`.
The operator must either declare the verifier or set `symbol_index = "not_needed"`.

**With `--no-strict`:** Plan approved; Reviewer activations produce an audit-side
`reviewer_no_symbol_index = true` field in `SessionCreated`.

**Recommended fix:** For codebases > 50 KLOC, declare the symbol-index verifier.
For smaller codebases or doc/config-only review tasks, set
`symbol_index = "not_needed"` to acknowledge.

---

### WARN_CUSTOM_TOOL_SCHEMA_BUDGET_HIGH

**Trigger:** A profile's effective custom-tool set (after the
inheritance merge per `custom-tools.md §8`) renders to a tool-schema
JSON payload whose token count, when tokenized for the smallest
context window across the profile's `[provider_aliases]` chain,
occupies between 10% (inclusive) and 25% (exclusive) of that context
window.

**Kernel behavior:** Plan admission emits the warning with
`{ profile, share, total_tokens, smallest_context_window }`. The
plan is admitted under default behavior; under `--strict` it is
rejected (warnings become errors).

**Why a warning, not an error:** A 10% custom-tool share is
operationally significant (it crowds out user data, system prompt,
KSB, and conversation history) but not catastrophic. Some workflows
legitimately need many tools (a "Frontend Engineer" with 15 niche
utilities). The warning surfaces the cost without blocking;
operators who consider it acceptable run with `--no-strict` or
explicitly acknowledge.

**Suppressing the warning:** Either (a) reduce the number or verbosity
of custom tools (shorter `description` fields, fewer `examples` blocks
in schemas), (b) split the profile into two narrower archetypes with
disjoint tool sets, OR (c) raise the smallest-context-window in the
profile's alias chain (use a larger-context model).

**Recommended fix:** When a profile's custom-tool share exceeds 10%,
audit the descriptions for verbosity. The `raxis admin plan
custom-tool-budget <plan_file>` CLI breaks down the projection per
tool to identify the largest contributors.

**Canonical home:** `custom-tools.md §9.3`.

---

## 3b. V2 Failure Catalog (Always-Reject Errors)

The errors in this section are V2 additions to the plan-admission and runtime
failure surface. Unlike `WARN_*` codes, these are NEVER suppressible by strict
mode — they indicate a configuration that cannot run correctly. Operator
remediation is required.

Each entry below has the canonical home for full remediation guidance noted;
the brief description here is the spec-side definition of when the error fires.

### FAIL_REVIEWER_VM_IMAGE_NOT_ALLOWED

**Phase:** `approve_plan`.

**Trigger:** A `[[plan.tasks.X]]` with `role = "Reviewer"` declares ANY of:
`vm_image`, `image`, `image_name`, or any other field that attempts to specify
the Reviewer's VM image.

**Kernel behavior:** Plan rejected. The Reviewer image is kernel-bundled and
not operator-customizable per `INV-PLANNER-HARNESS-02`. There is no override
mechanism — this is a structural ban, not a permission check.

**Recommended fix:** Remove the field from the Reviewer task. The kernel will
boot the canonical `raxis-reviewer-core` image automatically. See
`planner-harness.md §4.5` for the rationale.

**Canonical home:** `planner-harness.md §4.5`, `INV-PLANNER-HARNESS-02`.

---

### FAIL_REVIEWER_PATH_ALLOWLIST_NOT_ALLOWED

**Phase:** `approve_plan`.

**Trigger:** A `[[plan.tasks.X]]` with `role = "Reviewer"` declares the
`path_allowlist` field at all (any value, including the empty array `[]`).

**Kernel behavior:** Plan rejected. The Reviewer's `/workspace` is mounted
read-only per `planner-harness.md §3` (role table); the Reviewer harness has
no commit-pathway intent (no `SingleCommit`, no `IntegrationMerge`, no
`edit_file`, no `bash`); the path-allowlist field is therefore **structurally
meaningless** for Reviewer tasks, not just unused. The kernel never silently
mutates an operator-signed plan field — including stripping it — so the
operator must remove the field themselves. This mirrors the existing
`FAIL_REVIEWER_VM_IMAGE_NOT_ALLOWED` (above) and
`FAIL_REVIEWER_CUSTOM_TOOL_NOT_ALLOWED` discipline.

**Recommended fix:** Delete the `path_allowlist` line(s) from the Reviewer
task. `raxis-cli plan prepare` (per `operator-ergonomics.md §4.5` and §5.2)
emits the equivalent warning at prepare-time so this rarely surfaces at
`submit plan`.

**Canonical home:** `planner-harness.md §3` (role table), `§4.2` (Pure-Static
Reviewer), `INV-PLANNER-HARNESS-01`.

---

### FAIL_PLAN_REQUIRES_EXPLICIT_PATH_ALLOWLIST

**Phase:** `approve_plan`.

**Trigger:** A `[[plan.tasks.X]]` with `role = "Executor"` (or any
non-Reviewer, non-Orchestrator role) does NOT declare `path_allowlist` at
all (the TOML key is absent).

**Kernel behavior:** Plan rejected. The kernel does not infer a default
value for `path_allowlist` because there is no safe default: defaulting to
"all paths" violates the fail-closed posture established by
`INV-TASK-PATH-01`/`INV-TASK-PATH-02`; defaulting to `[]` silently ships a
no-write Executor that the operator likely did not intend (every commit
would be hard-rejected with `FAIL_PATH_POLICY_VIOLATION` at intent
admission, producing a confusing failure mode for a task the operator
believed they had authored correctly).

**Recommended fix:** Run `raxis-cli plan prepare` (per
`operator-ergonomics.md §5.2`) — `plan prepare` inserts a commented-out
`path_allowlist` template with a required-annotation marker into the
Executor task, optionally accompanied by deterministic top-level-directory
suggestions sourced from the operator's local worktree (per
`operator-ergonomics.md §4.5.2`). The operator uncomments and customizes
the template, then resubmits. If the operator genuinely intends a no-write
Executor (rare; e.g., a task that produces only `/raxis/` artifacts for a
successor task to consume), they declare `path_allowlist = []` with the
explicit acknowledgement annotation per `FAIL_EXECUTOR_EMPTY_PATH_ALLOWLIST_UNACKNOWLEDGED`
below.

**Canonical home:** `operator-ergonomics.md §4.5`,
`v2-deep-spec.md §6` (path-allowlist syntax).

---

### FAIL_EXECUTOR_EMPTY_PATH_ALLOWLIST_UNACKNOWLEDGED

**Phase:** `approve_plan`.

**Trigger:** A `[[plan.tasks.X]]` with `role = "Executor"` declares
`path_allowlist = []` (the literal empty array) AND does NOT carry the
required acknowledgement annotation `# @raxis-explicit no-write-acknowledged`
on the empty-array line or the line immediately above it (per
`operator-ergonomics.md §4.5.4`).

**Kernel behavior:** Plan rejected. Empty allowlist on an Executor is
structurally suspicious in the common case — the Executor's harness has
the full write surface (`bash`, `edit_file`, `bash run` with backgrounding
per `planner-harness.md §3`), but no commit it produces will admit. Without
the explicit annotation the operator has no way to signal "this is
intentional" versus "I forgot to populate this." The annotation is the
binary acknowledgement (no value, no version stamp; it is a structural
opt-in akin to `same_cluster_acknowledged = true` in
`environment-access-control.md §11.4`).

**Recommended fix:** Either populate `path_allowlist` with the directories
the Executor needs to touch, OR add the annotation. `plan prepare` will
not auto-add the annotation — that defeats the acknowledgement's purpose
of being an explicit operator decision.

When admitted with the annotation, the kernel records
`TaskWriteScope::NoWriteAcknowledged` in the `InitiativeCreated` audit
event so reviewers and auditors can see the operator explicitly opted into
the no-write Executor.

**Canonical home:** `operator-ergonomics.md §4.5.4`.

---

### FAIL_PATH_ALLOWLIST_INVALID_SYNTAX

**Phase:** `approve_plan`.

**Trigger:** A `[[plan.tasks.X]]` `path_allowlist` entry violates the
trailing-slash discipline canonical to `v2-deep-spec.md §6` table 4.
Specific reasons:

- `"glob_character_in_path"` — entry contains `*`, `?`, `[`, `]`, or
  `{`; arbitrary glob syntax is not supported.
- `"absolute_path"` — entry begins with `/`; entries are repo-relative.
- `"path_escape"` — entry contains `..` segments.
- `"missing_trailing_slash_for_directory"` — entry resolves to a known
  directory in the operator's worktree at policy-load time when the CLI
  has run `raxis-cli plan validate` (this check is best-effort and does
  not fire at kernel-side admission, which lacks operator-worktree
  visibility — included here for symmetry with the operator-side warning).

**Kernel behavior:** Plan rejected. The kernel's path-matching is the
prefix-or-exact discipline mandated by `INV-TASK-PATH-01`; admitting glob
syntax would require the kernel to take a position on glob semantics
(POSIX vs gitignore vs Bash extglob), all of which have edge cases the
admission gate cannot mechanically resolve in a way that matches the
operator's mental model.

**Recommended fix:** For directory entries, append `/` (e.g.,
`"src/components/"`). For exact files, omit the trailing slash. For
multi-directory needs, declare each directory as a separate entry. See
`v2-deep-spec.md §6` table 4 for the full syntax.

**Canonical home:** `v2-deep-spec.md §6` table 4, `INV-TASK-PATH-01`.

---

### FAIL_REVIEWER_IMAGE_DIGEST_MISMATCH

**Phase:** Runtime, at every Reviewer activation (Step 24 in `v2-deep-spec.md`).

**Trigger:** The on-disk SHA-256 of `$RAXIS_INSTALL_DIR/images/raxis-reviewer-core-<version>.img`
does not match the kernel-binary's compiled-in expected digest.

**Kernel behavior:** Reviewer activation aborted. `SecurityViolationDetected
{ kind: "ReviewerImageDigestMismatch", expected_sha256, observed_sha256 }`
audit event written. Initiative state: the corresponding Reviewer task
transitions to `Aborted` per the V1 FSM. Operator notification is required;
the kernel does NOT silently retry.

**Recommended fix:** Reinstall RAXIS from a verified source matching the running
kernel version. Do NOT attempt to "fix" by replacing the image with a custom
build — that is exactly what `INV-PLANNER-HARNESS-02` prohibits.

**Canonical home:** `planner-harness.md §4.5`, `system-requirements.md §11.2`
(`raxis doctor canonical-images` check).

---

### FAIL_ORCHESTRATOR_PROFILE_NOT_ALLOWED

**Phase:** `approve_plan`.

**Trigger:** A `[[profiles.<name>]]` block declares (directly or via
`inherits_from` chain) an effective role of `Orchestrator`. Per
`INV-PLANNER-HARNESS-06.1` operators do not declare Orchestrator
profiles in V2 — the kernel auto-creates the Orchestrator session at
initiative admission.

**Kernel behavior:** Plan rejected. The Orchestrator role is
kernel-managed invisible infrastructure. There is no override
mechanism — this is a structural ban, not a permission check.

**Recommended fix:** Remove the offending profile. Per-initiative
guidance to the Orchestrator can be supplied via the
`[plan.initiative] description` free-form field, which is rendered
into the Orchestrator's KSB as `[KERNEL: INITIATIVE GUIDANCE]` per
`kernel-mechanics-prompt.md §3.2`. Deployment-wide Orchestrator
behavior is tuned via `policy.toml [orchestrator]` (this spec §4.5).
See `planner-harness.md §4.8` for the rationale.

**Canonical home:** `planner-harness.md §4.8`, `INV-PLANNER-HARNESS-06`.

---

### FAIL_ORCHESTRATOR_TASK_NOT_ALLOWED

**Phase:** `approve_plan`.

**Trigger:** A `[[plan.tasks.<id>]]` declares `role = "Orchestrator"`
explicitly. Per `INV-PLANNER-HARNESS-06.1` operators do not declare
Orchestrator tasks in V2 — the kernel auto-creates the single
Orchestrator session per initiative as soon as `approve_plan`
succeeds.

**Kernel behavior:** Plan rejected. There is no Orchestrator
*task* concept in V2 (the Orchestrator session is initiative-scoped,
not task-scoped). This rejection fires before
`FAIL_ORCHESTRATOR_PROFILE_NOT_ALLOWED` so that operators encountering
this error get the more specific message about per-task vs. per-profile
declaration.

**Recommended fix:** Remove the task. If the operator's intent was
"a sub-task that performs coordination work" (a unit of work, not
the kernel's coordination role), declare it as an Executor task with
the relevant `path_allowlist` / `acceptance_criteria` and let the
kernel-managed Orchestrator handle inter-task DAG coordination.

**Canonical home:** `planner-harness.md §4.8`, `INV-PLANNER-HARNESS-06`.

---

### FAIL_PROFILE_ROLE_NOT_CONFIGURABLE

**Phase:** `approve_plan`.

**Trigger:** A `[[profiles.<name>]]` declares `inherits_from =
"Orchestrator"`. Per `INV-PLANNER-HARNESS-06.2` and `custom-tools.md
§8.1`, inheritance from `Orchestrator` is rejected because the
Orchestrator is not an operator-extensible role root in V2.
(Inheritance from `Reviewer` IS permitted, since Reviewer is an
operator-configurable role with a fixed tool surface — see
`FAIL_REVIEWER_CUSTOM_TOOL_NOT_ALLOWED` for the post-inheritance
custom-tool check.)

**Kernel behavior:** Plan rejected at the inheritance graph
construction stage, before any custom-tool validation runs.

**Recommended fix:** Remove the `inherits_from = "Orchestrator"`
declaration. If the operator is trying to add deployment-wide
constraints on Orchestrator behavior, those go in `policy.toml
[orchestrator]` (this spec §4.5).

**Canonical home:** `planner-harness.md §4.8`, `INV-PLANNER-HARNESS-06`,
`custom-tools.md §8.1`.

---

### FAIL_ORCHESTRATOR_VM_IMAGE_NOT_ALLOWED

**Phase:** Policy load (rejected on `epoch advance`) — and
defensively, `approve_plan` (in the unlikely case a plan references
an image name that points to an Orchestrator-restricted entry in a
loosened policy).

**Trigger:** A `[[vm_images]]` entry's `role_restriction` array
contains `"Orchestrator"`. Per `INV-PLANNER-HARNESS-05` operators do
not supply Orchestrator images in V2 — the kernel uses
`raxis-orchestrator-core-<kernel_version>.img` from
`$RAXIS_INSTALL_DIR/images/`.

**Kernel behavior:** Policy bundle rejected at `epoch advance` via
the broader `FAIL_POLICY_INVALID_ROLE_RESTRICTION`; the explicit
Orchestrator-specific subcategory `FAIL_ORCHESTRATOR_VM_IMAGE_NOT_ALLOWED`
provides clearer remediation messaging when the operator's intent
was specifically Orchestrator-targeted.

**Recommended fix:** Remove `"Orchestrator"` from the entry's
`role_restriction` array. (Note: `"Reviewer"` is similarly forbidden
in `role_restriction` per `INV-PLANNER-HARNESS-02`.)

**Canonical home:** `planner-harness.md §4.7`, `INV-PLANNER-HARNESS-05`.

---

### FAIL_ORCHESTRATOR_IMAGE_DIGEST_MISMATCH

**Phase:** Runtime, at every Orchestrator activation (kernel boots
the Orchestrator session at initiative admission per
`v2-deep-spec.md`).

**Trigger:** The on-disk SHA-256 of
`$RAXIS_INSTALL_DIR/images/raxis-orchestrator-core-<version>.img`
does not match the kernel-binary's compiled-in
`EXPECTED_ORCHESTRATOR_IMAGE_DIGEST`.

**Kernel behavior:** Orchestrator activation aborted.
`SecurityViolationDetected { kind: "OrchestratorImageDigestMismatch",
expected_sha256, observed_sha256 }` audit event written. Initiative
admission fails (the Orchestrator session is required for any
initiative to make progress); the operator is notified, the kernel
does NOT silently retry.

**Recommended fix:** Reinstall RAXIS from a verified source matching
the running kernel version. Do NOT attempt to "fix" by replacing the
image with a custom build — that is exactly what
`INV-PLANNER-HARNESS-05` prohibits.

**Canonical home:** `planner-harness.md §4.7`, `system-requirements.md §11.2`
(`raxis doctor canonical-images` check).

---

### FAIL_VM_IMAGE_ROLE_RESTRICTION_MISMATCH

**Phase:** `approve_plan`.

**Trigger:** A `[[plan.tasks.X]]` declares `vm_image = "<name>"`, the named
image is registered in `policy.toml [[vm_images]]`, but the image's
`role_restriction` field does NOT include the task's role.

Example: task is `role = "Executor"`, image's `role_restriction = ["Verifier"]`.

**Kernel behavior:** Plan rejected. Even though the image is permitted per
`policy.toml`, the operator's `role_restriction` declaration explicitly
prohibits this image from booting in the requested role.

**Recommended fix:** Either (a) extend the image's `role_restriction` in
`policy.toml` to include the role (and re-sign the policy), or (b) point
the plan task at a different image whose `role_restriction` permits the
role.

**Canonical home:** `policy-plan-authority.md §4.4` (this spec, §4.4 below).

---

### FAIL_VM_GUEST_KERNEL_TOO_OLD

**Phase:** `approve_plan` (when the operator's `policy.toml` includes per-image
manifest data) OR at first activation of an image not previously inspected
(when no manifest data is available).

**Trigger:** A `[[vm_images]]` entry whose introspection (via `raxis doctor`'s
`vm-images` category at install time, or at first activation) reports a Linux
guest kernel version below 5.14.

**Kernel behavior:** Plan rejected at `approve_plan`, OR — if the image was
not pre-validated — first activation aborted with `SecurityViolationDetected
{ kind: "VmGuestKernelTooOld", image, observed_kernel_version }`.

**Recommended fix:** Rebuild the image with a kernel ≥ 5.14, or switch to a
distribution base that ships ≥ 5.14 (Ubuntu 22.04+, Debian 12+, RHEL 9+,
Fedora 36+, Alpine 3.18+).

**Canonical home:** `system-requirements.md §2.5`, `planner-harness.md §10.2`,
`INV-PLANNER-HARNESS-03`.

---

### FAIL_REVIEWER_MISSING_SYMBOL_INDEX

**Phase:** `approve_plan`, when `--strict` is active and the
`WARN_REVIEWER_MISSING_SYMBOL_INDEX` warning fires (per §3
above, "WARN_REVIEWER_MISSING_SYMBOL_INDEX" entry).

**Trigger:** Same as the warning. In strict mode, the warning is promoted to
a hard failure.

**Recommended fix:** Either declare a symbol-index verifier or explicitly
acknowledge `symbol_index = "not_needed"`. See the warning entry for the
operator-side decision context.

**Canonical home:** This file, §3 `WARN_REVIEWER_MISSING_SYMBOL_INDEX`.

---

### FAIL_DECLARED_ARTIFACT_MISSING

**Phase:** Runtime, at verifier completion (per `verifier-processes.md §6.3`).

**Trigger:** A V2 task verifier completes (exit 0) with `artifact` declared
in the plan, but at exit time the artifact file is missing, empty, or
exceeds `artifact_max_bytes`. Combined with `on_failure = "block_review"`,
the Reviewer activation is blocked.

**Returned to:** The Executor whose `CompleteTask` was rolled into `Failed`.

**Kernel behavior:** Reviewer not activated. Task transitions to Failed per
`agent-disagreement.md §3`. Counted as a review round toward
`INV-CONVERGENCE-01`. Audit: `VerifierArtifactMissing` event with
`declared_artifact_path` and `observed_artifact_size_bytes`.

**Recommended fix (Executor):** Investigate why the verifier did not produce
the expected artifact (read the verifier's stderr_tail in the next activation's
KSB). Typical causes: command silently changed working directory, command
wrote to a wrong path, or the artifact file was correctly produced but
exceeded the declared cap.

**Canonical home:** `verifier-processes.md §6.3`, `INV-VERIFIER-05`.

---

### FAIL_VERIFIER_BLOCKED

**Phase:** Runtime, returned to the Executor on its next intent after a
`block_review` verifier failure (per `verifier-processes.md §5.2`).

**Trigger:** The Executor's `CompleteTask` was admitted, V1 policy gates
passed, but a V2 verifier with `on_failure = "block_review"` produced
`final_status ≠ "passed"`. The kernel rolled the task into `Failed` and
the Executor's next intent receives this code.

**Returned to:** The Executor.

**Kernel behavior:** Reviewer not activated. Task transitions to Failed per
`agent-disagreement.md §3`. Counted as a review round toward
`INV-CONVERGENCE-01`. The Executor may revise the task (within the
`max_review_rounds` cap) by addressing the verifier failure and submitting
a new `CompleteTask`.

**Recommended fix (Executor):** Read the verifier's `stderr_tail` and
`structured_counters` in the next activation's KSB. Address the root cause
(failing tests, build error, missing artifact). Submit a new `CompleteTask`.

**Canonical home:** `verifier-processes.md §5.2`, `INV-VERIFIER-04`.

---

### FAIL_VERIFIER_TIMEOUT_EXCEEDS_HARD_CAP

**Phase:** `approve_plan`.

**Trigger:** A `[[plan.tasks.X.verifiers]]` declares `timeout` exceeding
`policy.toml [host_capacity] max_verifier_timeout_seconds` (default 1800 / 30
minutes).

**Recommended fix:** Either (a) reduce the verifier's declared timeout, or
(b) raise the policy hard cap (operator decision; longer verifier wall-clock
holds verifier-VM capacity).

**Canonical home:** `verifier-processes.md §3`, `host-capacity.md` (pending
amendment to add `max_verifier_timeout_seconds`).

---

### FAIL_VERIFIER_ARTIFACT_CAP_EXCEEDS_HARD_CAP

**Phase:** `approve_plan`.

**Trigger:** A `[[plan.tasks.X.verifiers]]` declares `artifact_max_bytes`
exceeding `policy.toml [host_capacity] max_artifact_bytes` (default 64 MiB).

**Recommended fix:** Either reduce the declared cap, or raise the policy
hard cap.

**Canonical home:** `verifier-processes.md §3`, `host-capacity.md`.

---

### FAIL_VERIFIER_NAME_COLLISION

**Phase:** `approve_plan`.

**Trigger:** Two or more `[[verifiers]]` entries within the same task
declare the same `name`.

**Recommended fix:** Rename one. Verifier names must be unique within a
task (they key the `witness_records` row and the staging directory).

**Canonical home:** `verifier-processes.md §3`.

---

### FAIL_VERIFIER_COMMAND_REQUIRED

**Phase:** `approve_plan`.

**Trigger:** A `[[verifiers]]` entry has missing or empty `command`.

**Recommended fix:** Provide a non-empty `command` string. The kernel does
not infer a default command.

**Canonical home:** `verifier-processes.md §3`.

---

### FAIL_REVIEWER_CUSTOM_TOOL_NOT_ALLOWED

**Phase:** `approve_plan`.

**Trigger:** A profile whose effective role (the role at the root of
the `inherits_from` chain) is `Reviewer` declares one or more
`[[profiles.<name>.custom_tool]]` blocks (directly or transitively
through inheritance).

**Recommended fix:** Either (a) move the tool to an Executor- or
Orchestrator-inheriting profile if the use case is execution-time, or
(b) declare it as a verifier (`verifier-processes.md`) if the intent
is to influence Reviewer judgment. Verifier output reaches the
Reviewer via `verifier_witnesses` in the KSB and properly gates
review activation.

**Canonical home:** `custom-tools.md §10` (`INV-PLANNER-HARNESS-04`).

---

### FAIL_CUSTOM_TOOL_TASK_LEVEL_NOT_ALLOWED

**Phase:** `approve_plan`.

**Trigger:** Plan declares `[[plan.tasks.<id>.custom_tool]]` (a
custom tool on a task rather than on a profile).

**Recommended fix:** Move the custom tool to the profile assigned to
the task. Custom tools are profile-level only — a profile defines an
archetype's capability surface; tasks are tickets assigned to that
archetype.

**Canonical home:** `custom-tools.md §3.4`.

---

### FAIL_CUSTOM_TOOL_NAME_RESERVED

**Phase:** `approve_plan`.

**Trigger:** A `[[profiles.<name>.custom_tool]]` declares a `name`
that collides with a kernel-reserved tool or intent name (the closed
list maintained in the kernel binary; exposed by
`raxis admin reserved-tool-names`).

**Recommended fix:** Rename. Reserved names cover all base tools
(`read_file`, `bash`, etc.) and all kernel-mediated intent names
(`SingleCommit`, `IntegrationMerge`, etc.).

**Canonical home:** `custom-tools.md §5.1`.

---

### FAIL_CUSTOM_TOOL_NAME_COLLISION

**Phase:** `approve_plan`.

**Trigger:** Two or more `[[profiles.<name>.custom_tool]]` blocks
within a profile's effective set (after inheritance merge) declare the
same `name`. May arise within a single profile or across the
inheritance chain.

**Recommended fix:** Rename one. The expert design discussion
converged on error-on-collision (rather than silent child-overrides-
parent) precisely to prevent silent capability drift across profile
hierarchies. If the child legitimately needs a variant tool, name it
descriptively (e.g., `lint_frontend` instead of overriding `lint`).

**Canonical home:** `custom-tools.md §5.2`, `§8.3`.

---

### FAIL_CUSTOM_TOOL_SCHEMA_INVALID

**Phase:** `approve_plan`.

**Trigger:** A custom-tool input schema is not a syntactically valid
JSON Schema (parser error) or violates basic well-formedness rules
(e.g., `type` field missing, `required` references a nonexistent
property).

**Recommended fix:** Fix the schema per the Draft-07 vocabulary
accepted in `custom-tools.md §4.1`. The error message names the JSON
pointer into the offending schema location.

**Canonical home:** `custom-tools.md §4.3`.

---

### FAIL_CUSTOM_TOOL_SCHEMA_UNSUPPORTED_FEATURE

**Phase:** `approve_plan`.

**Trigger:** A custom-tool schema uses a JSON Schema keyword in the
rejected list (`$ref`, `oneOf`, `anyOf`, `allOf`, `not`, `if`/`then`/
`else`, `patternProperties`, `dependencies`, `propertyNames`,
`contains`, or `format` outside the four-element accepted subset).

**Recommended fix:** Restructure the schema to use only the accepted
keywords. The accepted vocabulary is the intersection of Anthropic's
and OpenAI's tool-schema validators; using rejected keywords would
ship plans that pass admission but fail at first inference.

**Canonical home:** `custom-tools.md §4.2`.

---

### FAIL_CUSTOM_TOOL_SCHEMA_NOT_OBJECT_ROOT

**Phase:** `approve_plan`.

**Trigger:** A custom-tool schema's top-level `type` is not
`"object"`. The LLM tool-call protocol passes inputs as an object;
non-object roots are unrepresentable.

**Recommended fix:** Wrap the input in an object schema. For a tool
that conceptually takes a single string, declare
`{ "type": "object", "properties": { "input": { "type": "string" } }, "required": ["input"] }`.

**Canonical home:** `custom-tools.md §4.3`.

---

### FAIL_CUSTOM_TOOL_SCHEMA_ADDITIONALPROPERTIES_TRUE

**Phase:** `approve_plan`.

**Trigger:** A custom-tool schema's top-level `additionalProperties`
is `true` or omitted. V2 requires `false` for input-shape
determinism.

**Recommended fix:** Add `additionalProperties = false` to the schema
root. If the operator legitimately needs an open-ended input, declare
a `properties.payload` of type `string` and parse JSON inside the
script.

**Canonical home:** `custom-tools.md §4.3`.

---

### FAIL_CUSTOM_TOOL_SCHEMA_BUDGET_EXCEEDED

**Phase:** `approve_plan`.

**Trigger:** A profile's effective custom-tool set occupies ≥ 25% of
the smallest context window across the profile's `[provider_aliases]`
chain (per `custom-tools.md §9.3`).

**Recommended fix:** Reduce the number or verbosity of custom tools,
or migrate to a larger-context model. The `raxis admin plan
custom-tool-budget <plan_file>` CLI shows per-tool token costs.

**Canonical home:** `custom-tools.md §9.3`.

---

### FAIL_CUSTOM_TOOL_COUNT_EXCEEDED

**Phase:** `approve_plan`.

**Trigger:** A profile's effective custom-tool set (after inheritance
merge) contains more than 25 tools.

**Recommended fix:** Split the profile into narrower archetypes with
disjoint tool sets. The 25-tool cap pushes operators toward
composition (multiple profiles, multiple tasks in the DAG) rather
than mega-agents with 100 tools each.

**Canonical home:** `custom-tools.md §9.1`.

---

### FAIL_CUSTOM_TOOL_TIMEOUT_EXCEEDS_HARD_CAP

**Phase:** `approve_plan`.

**Trigger:** A `[[profiles.<name>.custom_tool]]` declares
`timeout_seconds` > policy `max_custom_tool_timeout_seconds` (default
`300`).

**Recommended fix:** Lower the per-tool timeout, OR raise the policy
hard cap (operator decision; a higher cap allows longer synchronous
stalls of the LLM inference loop, which `custom-tools.md §3.2`
discourages — operations expected to exceed 5 minutes should run as
backgrounded `bash` per `planner-harness.md §5` or as a separate task
in the DAG).

**Canonical home:** `custom-tools.md §3.2`.

---

### FAIL_CUSTOM_TOOL_ENV_RESERVED_KEY

**Phase:** `approve_plan`.

**Trigger:** A `[[profiles.<name>.custom_tool]] env` table declares a
key that collides with a kernel-supplied environment variable
(`RAXIS_*`, `PATH`, `HOME`, `LANG`, `RAXIS_CREDENTIAL_PROXY_*`).

**Recommended fix:** Rename the operator's variable. The kernel-
supplied variables are reserved to provide stable correlation IDs and
proxy endpoints to the script.

**Canonical home:** `custom-tools.md §6.6`.

---

### FAIL_PLAN_PROFILE_INHERITANCE_CYCLE

**Phase:** `approve_plan`.

**Trigger:** The `inherits_from` graph across declared profiles
contains a cycle.

**Recommended fix:** Restructure the inheritance graph to be a DAG
(typical inheritance chains are linear: `frontend_dev` →
`web_executor` → `Executor`).

**Canonical home:** `custom-tools.md §8.1`.

---

### Plan Bundle Sealing failure codes

The `FAIL_PLAN_BUNDLE_*` family is enforced by **Plan Bundle Sealing**
(`v2/plan-bundle-sealing.md`). Most are CLI-side rejections that
fire before any IPC is sent to the kernel; the kernel re-enforces
the size caps defensively against non-canonical CLIs. Each code's
canonical semantics live in `plan-bundle-sealing.md §9`; this
catalog is the failure-code index.

| Code | Phase | One-line trigger | Canonical home |
|---|---|---|---|
| `FAIL_PLAN_BUNDLE_INVALID_PATH` | CLI resolve | Path field is empty / null / wrong type. | `plan-bundle-sealing.md §5.2` |
| `FAIL_PLAN_BUNDLE_ABSOLUTE_PATH` | CLI resolve | Path begins with `/`. | `plan-bundle-sealing.md §5.2` |
| `FAIL_PLAN_BUNDLE_PATH_ESCAPE` | CLI resolve | Path contains `..` segments OR resolves outside the plan-root tree (after symlink follow). | `plan-bundle-sealing.md §5.2` |
| `FAIL_PLAN_BUNDLE_SYMLINK_LOOP` | CLI resolve | `realpath` returned `ELOOP` for a referenced path. | `plan-bundle-sealing.md §5.2` |
| `FAIL_PLAN_BUNDLE_ARTIFACT_UNREADABLE` | CLI bundle | Resolved path is not a regular file or is unreadable. | `plan-bundle-sealing.md §5.2` |
| `FAIL_PLAN_BUNDLE_NAME_COLLISION` | CLI bundle | Two declared paths produce the same bundle name with different bytes. | `plan-bundle-sealing.md §3.3` |
| `FAIL_PLAN_BUNDLE_ARTIFACT_TOO_LARGE` | CLI / Kernel | Artifact byte length exceeds `[plan_bundle_limits].max_artifact_bytes`. | `plan-bundle-sealing.md §7.1` |
| `FAIL_PLAN_BUNDLE_TOO_LARGE` | CLI / Kernel | Total bundle byte length exceeds `[plan_bundle_limits].max_bundle_bytes`. | `plan-bundle-sealing.md §7.1` |
| `FAIL_PLAN_BUNDLE_TOO_MANY_ARTIFACTS` | CLI / Kernel | Artifact count exceeds `[plan_bundle_limits].max_artifact_count`. | `plan-bundle-sealing.md §7.1` |
| `FAIL_PLAN_BUNDLE_DECODE_FAILED` | Kernel | IPC envelope failed to decode. | `plan-bundle-sealing.md §8.1` |
| `FAIL_PLAN_BUNDLE_SHA256_MISMATCH` | Kernel | Wire `bundle_sha256` does not match `SHA-256(plan_bundle)`. | `plan-bundle-sealing.md §3.4` |
| `FAIL_PLAN_BUNDLE_CANONICAL_DECODE_FAILED` | Kernel | Bundle bytes failed to parse against the canonical encoding. | `plan-bundle-sealing.md §3.2` |
| `FAIL_PLAN_BUNDLE_ARTIFACT_HASH_MISMATCH` | Kernel | A per-artifact `sha256` field does not match `SHA-256(artifact.bytes)`. | `plan-bundle-sealing.md §8.1` |
| `FAIL_PLAN_BUNDLE_FIRST_ARTIFACT_NOT_PLAN_TOML` | Kernel | `artifacts[0].name != "plan.toml"`. | `plan-bundle-sealing.md §3.3` |
| `FAIL_PLAN_BUNDLE_INVALID_NAME` | Kernel | An artifact name violates the §3.3 naming rules (leading `/`, `..` segment, NUL byte, non-NFC). | `plan-bundle-sealing.md §3.3` |
| `FAIL_POLICY_PLAN_BUNDLE_LIMIT_ABOVE_CEILING` | Policy load | A `[plan_bundle_limits]` value exceeds the implementation hard ceiling. | `plan-bundle-sealing.md §7.4` |

`FAIL_PLAN_SIGNATURE_INVALID` (V1, retained) covers signature
verification failure; in V2 the signing input is the bundle hash,
not the bare `plan.toml` hash, but the FAIL code is unchanged.

---

### Environment-binding failure codes (V2)

The `FAIL_TASK_ENVIRONMENT_INCONSISTENT` and
`FAIL_SAME_CLUSTER_NAMESPACE_ISOLATION` codes enforce `INV-ENV-01`
(`invariants.md §11.5`). Both fire at `approve_plan` and are not
downgradable by `--no-strict` — they are structural invariants, not
warning-class hygiene checks. Each code's canonical semantics live in
`environment-access-control.md`; this catalog is the failure-code
index. The whole subsystem is opt-in per
`environment-access-control.md §1.5` — none of these codes can fire
in a deployment whose policy declares zero `[environments.<label>]`.

| Code | Phase | One-line trigger | Canonical home |
|---|---|---|---|
| `FAIL_TASK_ENVIRONMENT_INCONSISTENT { task, environments, sources }` | `approve_plan` step 3d | A task's environment-bound credentials and/or environment-bound egress URLs resolve to more than one environment label. | `environment-access-control.md §11.7` |
| `FAIL_SAME_CLUSTER_NAMESPACE_ISOLATION { task, url_prefix, conflated_environments, unacknowledged }` | `approve_plan` step 3b (handler) | A task's `allowed_egress` URL prefix matches two or more `[[environment_gates]]` from distinct environment labels, and at least one of those environments does not declare `same_cluster_acknowledged = true`. Promoted from `WARN_SAME_CLUSTER_NAMESPACE_ISOLATION` in V2. | `environment-access-control.md §7` |
| `FAIL_POLICY_ENV_LABEL_UNDECLARED { label, source }` | Policy load | A `[[environment_gates]] label` or a `[[permitted_credentials]] environment` references a label that has no `[environments.<label>]` declaration. | `environment-access-control.md §5b.3` |
| `FAIL_POLICY_ENV_UNKNOWN_FIELD { field }` | Policy load | An `[environments.<label>]` table contains a field that is neither normative nor in the V2.x reserved-field set. | `environment-access-control.md §5b.3` |
| `FAIL_POLICY_ENV_LABEL_INVALID { label }` | Policy load | An `[environments.<label>]` table is keyed with a label that violates the syntax `^[a-z][a-z0-9_-]{0,31}$`. | `environment-access-control.md §5b.3` |
| `WARN_ENVIRONMENT_RESERVED_FIELD_SET { field, env }` | Policy load | An `[environments.<label>]` table sets a V2.x-reserved-but-inert field; the field is parsed, ignored, and recorded in the audit chain so future audits can spot deployments that pre-set knobs. | `environment-access-control.md §5b.4` |

`FAIL_TASK_ENVIRONMENT_INCONSISTENT` and
`FAIL_SAME_CLUSTER_NAMESPACE_ISOLATION` are **structural** in the same
sense as `FAIL_ENVIRONMENT_BLOCKED`: they cannot be downgraded by
`--no-strict`. The operator's escape hatch is either a plan refactor
(per `environment-access-control.md §11.5` DAG-split pattern) or a
policy-bundle update (declaring `same_cluster_acknowledged = true` on
all conflated environments, per `environment-access-control.md §11.4`).
This mirrors the user's "fail loud" posture for environment binding.

---

### Operator-ergonomics failure codes

The `FAIL_PLAN_REQUIRES_PREPARE` family is enforced by the
operator-ergonomics layer (`v2/operator-ergonomics.md`). Most fire at
either `OperatorRequest::ProposeDefaults` (during `raxis-cli plan
prepare`) or at `OperatorRequest::CreateInitiative` (when the operator
submitted a plan without running `plan prepare` first). Each code's
canonical semantics live in `operator-ergonomics.md §20`; this catalog
is the failure-code index.

| Code | Phase | One-line trigger | Canonical home |
|---|---|---|---|
| `FAIL_PLAN_REQUIRES_PREPARE { missing_fields }` | `submit plan` admission | The plan omits at least one defaultable field whose policy default is set; the operator did not run `plan prepare` first. | `operator-ergonomics.md §20` |
| `FAIL_PREPARE_DEFAULT_UPGRADE_REQUIRED { fields }` | `plan prepare` IPC | At least one annotated field's policy-default value has drifted; `--upgrade-defaults` not passed. | `operator-ergonomics.md §5.4` |
| `FAIL_PLAN_FIELD_NOT_DEFAULTABLE { field }` | `plan prepare` IPC | The operator placed a `# @raxis-default` annotation on a field NOT in the defaultable set. | `operator-ergonomics.md §4.2` |
| `FAIL_POLICY_DEFAULT_UNRESOLVABLE { field }` | `plan prepare` IPC | A defaultable field requires a policy value the policy doesn't declare. | `operator-ergonomics.md §5.4` |
| `FAIL_POLICY_DEFAULT_EXECUTOR_IMAGE_UNRESOLVABLE` | Policy load | `[default_executor_image] alias` doesn't resolve to a `[[vm_images]]` entry whose `role_restriction` includes `"Executor"`. | `operator-ergonomics.md §18.1` |
| `FAIL_DEFAULT_EXECUTOR_IMAGE_DIGEST_MISMATCH` | Runtime / `raxis doctor` | The kernel-bundled `raxis-executor-starter` image's digest does not match the manifest. Hard error if any in-flight session is using it; non-fatal warning otherwise. | `planner-harness.md §10.6` |
| `FAIL_PLAN_INIT_TEMPLATE_NOT_FOUND { name }` | `plan init` (CLI-local; never IPC) | Template name not in CLI-bundled set. | `operator-ergonomics.md §6.4` |
| `FAIL_COST_ESTIMATE_PROVIDER_RATE_MISSING { provider }` | `plan cost-estimate` IPC | Policy doesn't declare rates for a configured provider. | `operator-ergonomics.md §11.4` |
| `FAIL_INITIATIVE_NOT_PAUSED { state }` | `initiative resume` | Initiative is not in a paused state; nothing to resume. | `operator-ergonomics.md §14.5` |

`FAIL_PLAN_REQUIRES_PREPARE` is the only one of these that can fire on
`submit plan` admission. Its `missing_fields` array names the §4.2
fields the plan omitted, giving the operator an actionable next step
(run `plan prepare`).

### Verifier and pre-merge failure codes (V2)

The mechanical-witness layer (`verifier-processes.md`) and the
pre-`IntegrationMerge` verifier hook (`integration-merge.md §4
Check 5d`) introduce the following failure codes. All `FAIL_POLICY_*`
codes prevent the policy from loading; in-flight initiatives keep
running on the previously-loaded policy until the operator fixes
and re-pushes.

| Code | Phase | One-line trigger | Canonical home |
|---|---|---|---|
| `FAIL_VERIFIER_INVALID_ON_FAILURE { verifier_name, declared, allowed }` | `approve_plan` | A per-task verifier declares `on_failure = "block_merge"`, OR a pre-merge verifier declares `on_failure = "block_review"`. Per-task verifiers gate Reviewer activation only; pre-merge verifiers gate IntegrationMerge advancement only. | `verifier-processes.md §10.3` |
| `FAIL_VERIFIER_TASK_SET_EMPTY { verifier_name }` | `approve_plan` | A pre-merge verifier declares `applies_to = "task_set"` but provides an empty `task_set` array. | `verifier-processes.md §10.3` |
| `FAIL_VERIFIER_TASK_SET_UNKNOWN_TASK { verifier_name, unknown_task }` | `approve_plan` | A pre-merge verifier's `task_set` references a task ID that is not declared in `[[plan.tasks]]`. | `verifier-processes.md §10.3` |
| `FAIL_INTEGRATION_MERGE_VERIFIER_BLOCKED { verifier_names, primary_witness_summary, candidate_merge_sha }` | `IntegrationMerge` Check 5d | Any matching `block_merge` pre-merge verifier reported `final_status ≠ "passed"`. Candidate merged tree is discarded; master is NOT advanced; Orchestrator routes to operator escalation per `verifier-processes.md §16.6`. | `integration-merge.md §4 Check 5d.6` |
| `FAIL_CANDIDATE_MERGE_COMPUTATION_FAILED { reason }` | `IntegrationMerge` Check 5d.2 | The candidate merged tree could not be materialized (malformed `commit_sha`, merge conflict the kernel can't represent as an orphan, disk-full at `candidate_merges/` staging area). | `integration-merge.md §4 Check 5d.6` |
| `FAIL_CANONICAL_VERIFIER_IMAGE_DIGEST_MISMATCH { expected, actual }` | Verifier-VM spawn | At spawn time, the on-disk `raxis-verifier-symbol-index-<kernel_version>.img` does not match the kernel-binary-embedded canonical digest. Spawn aborted; halts further verifier spawns until `raxis doctor canonical-images` succeeds. Defense-in-depth analog of `FAIL_REVIEWER_IMAGE_DIGEST_MISMATCH`. | `verifier-processes.md §14.4` |
| `FAIL_POLICY_RESERVED_VM_IMAGE_NAME { name }` | Policy load | A `[[vm_images]]` entry uses a reserved alias (`"raxis-verifier-symbol-index"`). The alias is reserved per `INV-VERIFIER-12` so plan-side references resolve unambiguously to the kernel-bundled image. | `verifier-processes.md §14.3` |
| `FAIL_POLICY_DEFAULT_VERIFIER_IMAGE_UNRESOLVABLE { language, alias }` | Policy load | A `[default_verifier_images].<language>` value doesn't resolve to a `[[vm_images]]` entry whose `role_restriction` includes `"Verifier"`. | `policy-plan-authority.md §4 [default_verifier_images]` |
| `WARN_DEFAULT_VERIFIER_IMAGE_UNKNOWN_LANGUAGE { language }` | Policy load | `[default_verifier_images].<language>` declares a language other than the V2 recognized set (`rust`, `node`, `python`, `go`). Non-fatal; the `@<language>` shortcut for that language won't resolve. | `policy-plan-authority.md §4 [default_verifier_images]` |

The `WitnessSubmission` and `witness_records` schemas no longer
carry V1/V2 discriminators (per `verifier-processes.md §7`); all
witness rows for a given initiative use the same schema regardless
of which authoring source produced them.

---

### Provider-alias-defaults failure codes (V2)

The defaultable per-role alias chains live in
`[provider_aliases_defaults]` (§4) and are validated at policy load
per `provider-model-selection.md §7.2`. All `FAIL_POLICY_*` codes
below prevent the policy from loading; in-flight initiatives are
unaffected because the previous-loaded policy stays active until the
operator fixes and re-pushes.

| Code | Phase | One-line trigger | Canonical home |
|---|---|---|---|
| `FAIL_POLICY_PROVIDER_ALIAS_DEFAULT_REFERENCES_NONPERMITTED_MODEL { role, missing_models }` | Policy load | A `[provider_aliases_defaults.<role>] chain` entry references a model not in `[providers] permitted_models`. | `provider-model-selection.md §10` |
| `FAIL_POLICY_PROVIDER_ALIAS_DEFAULT_MISSING_CREDENTIAL { role, missing_provider }` | Policy load | A `[provider_aliases_defaults.<role>] chain` entry references a provider with no `[[providers.credentials]]` entry. | `provider-model-selection.md §10` |
| `FAIL_POLICY_PROVIDER_ALIAS_DEFAULT_EMPTY_CHAIN { role }` | Policy load | A declared `[provider_aliases_defaults.<role>]` has an empty `chain`. | `provider-model-selection.md §10` |
| `FAIL_POLICY_PROVIDER_ALIAS_DEFAULT_UNKNOWN_FALLBACK_BEHAVIOR { role, value }` | Policy load | `fallback_behavior` is not `"attempt_in_order"`. | `provider-model-selection.md §10` |
| `WARN_PROVIDER_ALIAS_DEFAULT_UNKNOWN_ROLE { role }` | Policy load | `[provider_aliases_defaults.<role>]` declares a role name other than `executor` or `reviewer`. Non-fatal; the orphan section is silently ignored. | `provider-model-selection.md §10` |
| `WARN_PROVIDER_ALIAS_PRIMARY_NO_FAILOVER { alias }` | Policy load | An alias chain has length 1 in a deployment with 2+ configured providers. Suggests the operator missed the diversification benefit (`provider-model-selection.md §5`). Non-fatal. | `provider-model-selection.md §10` |
| `WARN_ORCHESTRATOR_DEFAULT_ALIAS_RENAMED { alias }` | Policy load | `[orchestrator] provider_alias` resolves to `"fast_low_cost"` (the V1 default name). Recommends rename to `"orchestrator_default"` per §4 `[orchestrator]`. Non-fatal V1 → V2 migration aid. | `provider-model-selection.md §10` |

---

## 4. Policy Bundle — New Fields for INV-POLICY-01

### `require_push_approval_minimum`

```toml
# policy.toml

[push_policy]
require_push_approval_minimum = false   # default

# Set to true to mandate push approval for ALL initiatives in this deployment.
# Plans with require_push_approval = false will be warned and silently upgraded.
```

This field does not exist in V1. It is a V2 addition. Its absence (or `false`) means
no deployment-wide push approval mandate — plan-level `require_push_approval` is
honored as-is.

### `approve_plan_strict_by_default`

```toml
# policy.toml

[approve_policy]
approve_plan_strict_by_default = true   # default — strict mode is always on

# Set to false only for deployments where operators explicitly want lenient
# approval (warnings do not block). Not recommended for production deployments.
approve_plan_strict_by_default = false
```

`--strict` is the Kernel default. This policy field allows a deployment to explicitly
configure lenient mode as the default, removing the need for operators to pass
`--no-strict` on every invocation. Setting this to `false` is a conscious security
trade-off: it means plans with policy-plan divergences will be approved without explicit
operator acknowledgment. Not recommended for production.

### `[[vm_images]] role_restriction` (V2 addition)

V2 makes the existing `[[vm_images]]` schema's `role_restriction` field
load-bearing for plan admission. Each operator-published image declares
which planner / verifier roles may use it:

```toml
# policy.toml — V2 schema for [[vm_images]]

[[vm_images]]
name             = "raxis/rust-build:1.87"
oci_digest       = "sha256:e3b0c44298fc1c149afbf4c8996fb924..."
role_restriction = ["Executor", "Orchestrator"]   # required field; non-empty array

[[vm_images]]
name             = "raxis/parsers:1"
oci_digest       = "sha256:c057a3e7ea75c2aef3c1cd95fa1aac84..."
role_restriction = ["Verifier"]                   # only usable for V2 task verifiers

[[vm_images]]
name             = "raxis/multipurpose:2"
oci_digest       = "sha256:..."
role_restriction = ["Executor", "Orchestrator", "Verifier"]   # acceptable; useful when image
                                                              # truly serves multiple roles
```

**Permitted values in `role_restriction`:**

| Value | Meaning |
|---|---|
| `"Orchestrator"` | Image may boot for an Orchestrator task |
| `"Executor"` | Image may boot for an Executor task |
| `"Verifier"` | Image may boot for a V2 task verifier (per `verifier-processes.md`) |
| `"Reviewer"` | **Disallowed.** The Reviewer role uses the kernel-bundled `raxis-reviewer-core` image only (`INV-PLANNER-HARNESS-02`); operator-published Reviewer images are explicitly prohibited. Any `[[vm_images]]` entry whose `role_restriction` contains `"Reviewer"` is REJECTED at policy load with `FAIL_POLICY_INVALID_ROLE_RESTRICTION` and a remediation message. |

**Migration from V1:** V1 policies without `role_restriction` are migrated by
the `epoch advance` flow with a permissive default of
`["Executor", "Orchestrator", "Verifier"]`, recording a one-time
`PolicyMigrationApplied { kind: "VmImageDefaultRoleRestriction" }` audit event.
Operators are advised to tighten the field on their next policy push.
This permissive migration is V2-only; V3 may require explicit declaration.

**Why this is in `policy.toml`, not `plan.toml`:** Image safety boundaries are
operator policy. Plan authors choose WHICH image to use; operators decide
WHAT roles each image is safe for. A plan author cannot widen the role
boundary by amending plan.toml — only the operator can amend policy.toml
(and re-sign).

### `[custom_tool_limits]` (V2 addition)

Operator-side hard caps and tunable thresholds for the operator-defined
custom tools surface (canonical home `custom-tools.md`).

```toml
# policy.toml — V2 schema for [custom_tool_limits]

[custom_tool_limits]
max_custom_tool_timeout_seconds  = 300       # default; ceiling on per-tool timeout_seconds
max_concurrent_custom_tool_invocations = 4   # per planner VM
max_queued_custom_tool_invocations     = 8   # per planner VM
# Wall-clock cap on how long a queued invocation may wait before
# the harness gives up and surfaces `CustomToolQueueTimeout` to
# the LLM (distinct from `Timeout` and `ConcurrencyExhausted`).
# See custom-tools.md §7.3 for mechanism and audit semantics.
# Validation: must be in [1_000, max_custom_tool_timeout_seconds * 1000].
max_queue_wait_ms                = 30000     # default 30 s
schema_budget_warn_share         = 0.10      # WARN_CUSTOM_TOOL_SCHEMA_BUDGET_HIGH threshold
schema_budget_fail_share         = 0.25      # FAIL_CUSTOM_TOOL_SCHEMA_BUDGET_EXCEEDED threshold
```

**Tightening only.** Setting `schema_budget_warn_share` or
`schema_budget_fail_share` ABOVE the V2 defaults (0.10 / 0.25) has no
effect — the kernel takes the more restrictive of (V2 default, policy).
This prevents a misconfigured policy from loosening the kernel's
fail-closed posture.

**Why this is in `policy.toml`, not `plan.toml`:** the cap is an
operator-side resource boundary, not a plan-author choice. Plan
authors declare individual tool timeouts and counts; the operator's
policy decides the absolute ceiling.

### `[audit.custom_tools]` (V2 addition)

Optional per-deployment audit configuration for custom-tool payloads
(canonical home `custom-tools.md §13.2`).

```toml
# policy.toml — V2 schema for [audit.custom_tools]

[audit.custom_tools]
archive_full_payloads        = false         # default; only digests are persisted
archive_payload_max_bytes    = 1_048_576     # 1 MiB cap when archive_full_payloads = true
```

When `archive_full_payloads = true`, the kernel persists the full
stdin / stdout / stderr bytes of every custom-tool invocation in a
content-addressed payload store, alongside the digest-only
`CustomToolInvoked` audit event. Payloads beyond
`archive_payload_max_bytes` are truncated and the truncation is
recorded as a separate `CustomToolPayloadTruncated` event.

V2 retains payloads indefinitely; V3 audit-retention lifecycle
(`audit-retention.md`) will introduce time-bounded GC.

### `[orchestrator]` (V2 addition)

The Orchestrator role is kernel-managed invisible infrastructure per
`INV-PLANNER-HARNESS-06` (`planner-harness.md §4.8`). Operators
**cannot** declare Orchestrator profiles, tasks, NNSPs, custom tools,
or images. The only operator-controlled inputs to Orchestrator
behavior are three orthogonal knobs in this policy section.

```toml
# policy.toml — V2 schema for [orchestrator]

[orchestrator]
provider_alias                  = "orchestrator_default"   # default; an alias from [provider_aliases]
max_token_budget_per_initiative = 1_000_000                 # default; ceiling on Orchestrator session inference for one initiative
all_merges_require_approval     = false                     # default; when true, every IntegrationMerge escalates for human approval

# The default chain is a mid-tier reasoning model with cross-provider
# fallback (when 2+ providers are configured). The Orchestrator's
# canonical workload analysis lives in `provider-model-selection.md
# §3.1`; the short version is: low token volume, high-leverage
# decisions, latency-sensitive — picking a reasoning-tier model is
# the right call even though the Orchestrator's reasoning bursts are
# short.
[provider_aliases.orchestrator_default]
chain = [
    "anthropic:claude-4.6-sonnet-medium-thinking",   # primary
    "openai:gpt-5.5-medium",                         # cross-provider fallback (omit if single-provider)
]
fallback_behavior = "attempt_in_order"
```

| Field | Default | Purpose |
|---|---|---|
| `provider_alias` | `"orchestrator_default"` (must resolve to an entry in `[provider_aliases]`) | Selects which provider chain the Orchestrator uses for inference. The default name was renamed from V1 `"fast_low_cost"` after the workload analysis in `provider-model-selection.md §3.1` showed the historical "cheap-and-fast" framing was wrong on both axes — the Orchestrator's per-initiative cost saving from a haiku-tier model is dwarfed by the cost of one botched merge sequencing decision. V1 policies using the old name still load with `WARN_ORCHESTRATOR_DEFAULT_ALIAS_RENAMED` recommending rename. Operators who want a frontier model for Orchestrator reasoning (large-DAG initiatives, complex semantic merges) override per `provider-model-selection.md §6.2`. |
| `max_token_budget_per_initiative` | `1_000_000` | Hard ceiling on cumulative tokens consumed by the Orchestrator session for a single initiative. When reached, the Orchestrator session pauses with a `TokenLimitApproaching` alert and waits for operator action (operator may grant additional budget via the existing escalation mechanism). |
| `all_merges_require_approval` | `false` | When `true`, every `IntegrationMerge` submitted by the Orchestrator must be paired with an operator-approved `EscalationRequest:MergeAuthorization` (a new escalation class that exists solely for this knob). Useful for high-trust deployments that want a human in the loop on all main-branch advances even when `[plan.protected_paths]` does not require it. |

**Tightening only.** Setting `max_token_budget_per_initiative` ABOVE
the V2 default (1,000,000) is permitted (Orchestrator is a kernel
component, not an untrusted agent — operators are trusted to size
its budget). Setting `all_merges_require_approval = true` is
strictly tighter than the default and is always honored.

**No `[plan.orchestrator]` section.** A symmetric block in `plan.toml`
does NOT exist; per-initiative Orchestrator tuning is impossible by
design. Per-initiative *guidance* (free-form prose) is supplied via
`[plan.initiative] description`, which the Orchestrator reads via
its KSB as `[KERNEL: INITIATIVE GUIDANCE]` (per
`kernel-mechanics-prompt.md §3.2`). This is the only operator-controlled
instruction surface available within an Orchestrator session.

---

### `[plan_bundle_limits]` (V2 addition)

Plan Bundle Sealing (`v2/plan-bundle-sealing.md`) caps the size and
artifact count of the signed plan bundle the operator submits. The
caps are policy-configurable, with hard ceilings that protect the
SQLite write path from any single misconfigured policy.

```toml
# policy.toml — V2 schema for [plan_bundle_limits]

[plan_bundle_limits]
max_artifact_bytes  = 1_048_576       # default 1 MiB; hard ceiling 64 MiB
max_bundle_bytes    = 10_485_760      # default 10 MiB; hard ceiling 128 MiB
max_artifact_count  = 200             # default; hard ceiling 1024
```

| Field | Default | Hard ceiling | Purpose |
|---|---|---|---|
| `max_artifact_bytes` | `1_048_576` (1 MiB) | `67_108_864` (64 MiB) | Maximum byte length of a single bundle artifact. `plan.toml` itself is one artifact; any future host-path-typed field contributes additional artifacts. Exceeding the cap → `FAIL_PLAN_BUNDLE_ARTIFACT_TOO_LARGE`. |
| `max_bundle_bytes` | `10_485_760` (10 MiB) | `134_217_728` (128 MiB) | Maximum total byte length across all artifacts in a single bundle. The bundle is stored verbatim as an immutable SQLite blob (`plan-bundle-sealing.md §8.2`); this cap bounds the per-initiative kernel-store footprint. Exceeding → `FAIL_PLAN_BUNDLE_TOO_LARGE`. |
| `max_artifact_count` | `200` | `1024` | Maximum number of artifacts in a single bundle. Bounds the SQL-side per-initiative row count in `plan_bundle_artifacts`. Exceeding → `FAIL_PLAN_BUNDLE_TOO_MANY_ARTIFACTS`. |

**Lowering vs. raising.** Operators MAY lower any cap below the
default to tighten admission for their deployment (e.g., a
single-team operator running ~50 KiB plans may set
`max_bundle_bytes = 524_288` to catch oversize plans early).
Operators MAY raise caps up to but NOT above the hard ceiling;
attempts to set a value above the ceiling are rejected at policy
load with `FAIL_POLICY_PLAN_BUNDLE_LIMIT_ABOVE_CEILING`.

**Why hard ceilings exist.** SQLite handles individual blobs up to
~2 GiB in principle, but the kernel performs full-bundle reads on
every `approve_plan` and recovery cycle. Beyond ~128 MiB per bundle,
the read latency starts to dominate admission time and audit replay
time. The ceiling is conservative; raising it requires a kernel
release, not a policy change.

**Defensive kernel-side enforcement.** The CLI is the normative
enforcement point — a well-behaved CLI never sends an oversize
bundle. The kernel re-checks all three caps on
`OperatorRequest::CreateInitiative` (`plan-bundle-sealing.md §7.3`)
to defend against custom or malicious CLIs that bypass the
client-side checks.

**Why this is in `policy.toml`, not `plan.toml`:** Orchestrator
behavior is a deployment-wide property (every initiative on this
deployment uses the same provider, the same budget ceiling, the same
approval policy). Per-initiative tuning would re-create the
operator-Orchestrator coupling that `INV-PLANNER-HARNESS-06`
deliberately removes.

---

### `[provider_aliases_defaults]` (V2 addition)

The defaultable per-role alias chains consumed by `raxis-cli plan
prepare` per `operator-ergonomics.md §5` and
`provider-model-selection.md §7`. Each `[provider_aliases_defaults.<role>]`
entry tells `plan prepare` what to fill into `plan.toml
[provider_aliases.<role>]` when the operator omits the section.

```toml
# policy.toml — V2 schema for [provider_aliases_defaults]

[provider_aliases_defaults.reviewer]
chain             = [
    "openai:gpt-5.3-codex",                          # primary on a DIFFERENT provider for cross-role diversification (provider-model-selection.md §5)
    "anthropic:claude-opus-4.7-thinking-medium",     # fallback
]
fallback_behavior = "attempt_in_order"

[provider_aliases_defaults.executor]
chain             = [
    "anthropic:claude-4.6-sonnet-medium-thinking",
    "openai:gpt-5.5-medium",
]
fallback_behavior = "attempt_in_order"
```

| Field | Default | Purpose |
|---|---|---|
| `[provider_aliases_defaults.<role>] chain` | (none; absence disables defaulting for that role) | The fallback chain `plan prepare` fills into `plan.toml [provider_aliases.<role>]` when the operator's plan omits the section. Recognized role names in V2 are `reviewer` and `executor`; other names produce `WARN_PROVIDER_ALIAS_DEFAULT_UNKNOWN_ROLE`. |
| `[provider_aliases_defaults.<role>] fallback_behavior` | `"attempt_in_order"` | Same semantics as `plan.toml [provider_aliases.<name>] fallback_behavior` per `provider-failure-handling.md §3.2`. Only `"attempt_in_order"` is valid in V2. |

**Validation at policy load** (per `provider-model-selection.md §7.2`):

1. Every model in `chain` must appear in `[providers] permitted_models` (per `INV-PROVIDER-01`); otherwise `FAIL_POLICY_PROVIDER_ALIAS_DEFAULT_REFERENCES_NONPERMITTED_MODEL`.
2. Every distinct provider referenced in `chain` must have at least one `[[providers.credentials]]` entry; otherwise `FAIL_POLICY_PROVIDER_ALIAS_DEFAULT_MISSING_CREDENTIAL`. The rationale: a chain entry whose provider has no configured credential will be silently skipped at every alias resolution (per `provider-failure-handling.md §4.1`), so declaring it as a default just delays the failure to a confusing place.
3. `chain` must be non-empty; otherwise `FAIL_POLICY_PROVIDER_ALIAS_DEFAULT_EMPTY_CHAIN`.
4. `fallback_behavior` must be `"attempt_in_order"`; otherwise `FAIL_POLICY_PROVIDER_ALIAS_DEFAULT_UNKNOWN_FALLBACK_BEHAVIOR`.

**Why the Orchestrator is NOT in this schema.** The Orchestrator's
alias lives in `[orchestrator] provider_alias` (operator-pinned via
policy, never via plan, per `INV-PLANNER-HARNESS-06`). It has its
own authoring path; defaulting it through the
`[provider_aliases_defaults]` mechanism would create two paths to
the same target and invite drift. The Orchestrator's chain is
declared inline in `policy.toml [provider_aliases.orchestrator_default]`
(or whatever alias name the operator picked); the `setup wizard`
generates this directly per `provider-model-selection.md §9.3`.

**Why this is in `policy.toml`, not `plan.toml`:** alias defaults
are a deployment-wide property (every plan on this deployment
benefits from the same default chain). Per-plan flexibility is
preserved — operators who want a per-plan override declare their
own `[provider_aliases.<role>]` in `plan.toml` and `plan prepare`
leaves it alone. The defaulting layer just removes the redundant
authoring of the chain in every plan.

---

### `[default_executor_image]` (V2 addition)

The defaulting target consumed by `raxis-cli plan prepare` per
`operator-ergonomics.md §4` and `§18.1`. When an operator omits
`vm_image` on an Executor task, `plan prepare` fills it with the OCI
digest of the `[[vm_images]]` entry resolved from this alias.

```toml
# policy.toml — V2 schema for [default_executor_image]

[default_executor_image]
alias    = "raxis-executor-starter"   # the canonical starter image alias
fallback = "skip"                     # what plan prepare does if the alias is absent:
                                       #   "skip"  — leave vm_image unfilled; submit fails with FAIL_PLAN_REQUIRES_PREPARE
                                       #   "error" — plan prepare itself fails with FAIL_POLICY_DEFAULT_UNRESOLVABLE
```

| Field | Default | Purpose |
|---|---|---|
| `alias` | (none; section absent → no defaulting) | The `[[vm_images]] name` of the image to use as the Executor default. The image's `role_restriction` MUST include `"Executor"`. |
| `fallback` | `"skip"` | Behaviour when the alias does not resolve to a valid `[[vm_images]]` entry. |

**Validation at policy load.** `[default_executor_image] alias` MUST
resolve to a `[[vm_images]]` entry whose `role_restriction` contains
`"Executor"`. Otherwise → `FAIL_POLICY_DEFAULT_EXECUTOR_IMAGE_UNRESOLVABLE`
(hard error). This guarantees the CLI's `plan prepare` will succeed
when it consults this field.

**Absence is permitted.** If the section is omitted entirely,
defaulting of `vm_image` is disabled. Operators must declare
`vm_image` explicitly on every Executor task; submission of a task
omitting `vm_image` fails with the existing `FAIL_VM_IMAGE_NOT_PERMITTED`
(or its V2 equivalent). This matches the V1 behavior and preserves it
for operators who never want kernel-side image defaulting.

**Cross-reference:** `planner-harness.md §10.6` describes the
canonical `raxis-executor-starter` image manifest that the typical
deployment will reference here.

---

### `[token_policy_defaults]` (V2 addition)

Per-role default token budgets consumed by `raxis-cli plan prepare`
per `operator-ergonomics.md §4.2` and `§18.2`. When an operator omits
`[plan.tasks.<id>.token_policy]` on a task, `plan prepare` fills it
with the per-role defaults from this section.

```toml
# policy.toml — V2 schema for [token_policy_defaults]

[token_policy_defaults.executor]
input_tokens_per_session  = 500_000
output_tokens_per_session = 50_000

[token_policy_defaults.reviewer]
input_tokens_per_session  = 200_000
output_tokens_per_session = 20_000
```

| Field | Default | Purpose |
|---|---|---|
| `[token_policy_defaults.<role>] input_tokens_per_session` | (none) | Per-session input-token cap for tasks of this role that omit an explicit `token_policy`. |
| `[token_policy_defaults.<role>] output_tokens_per_session` | (none) | Per-session output-token cap for tasks of this role that omit an explicit `token_policy`. |

Roles for which no defaults are declared get **no defaulting**. Tasks
of that role that omit `token_policy` continue to fire the existing
`WARN_UNCAPPED_TOKEN_LIMIT` (or, post-prepare with the operator
acknowledging defaults are absent, `FAIL_PLAN_REQUIRES_PREPARE` per
the operator-ergonomics check chain).

**Why per-role.** Different roles have radically different token
profiles: an Executor running `npm test` needs a wide window for tool
output; a Reviewer reading code into context needs a narrower one;
the Orchestrator's reasoning is mostly DAG bookkeeping and its
budget is governed by `[orchestrator] max_token_budget_per_initiative`
rather than a per-session cap. Defaulting one number across roles
would either over-provision Reviewers (wasting paid context) or
under-provision Executors (causing premature `TokenLimitApproaching`
alerts on routine tasks).

---

### `[default_protected_paths]` (V2 addition)

Default paths protected from agent-driven edits, consumed by
`raxis-cli plan prepare` per `operator-ergonomics.md §4.2` and `§18.3`.
`plan prepare` takes the union of this list and the operator's
`[plan.protected_paths]`, deduplicated.

```toml
# policy.toml — V2 schema for [default_protected_paths]

[default_protected_paths]
paths = [
  ".git/",
  ".raxis/",
  "node_modules/",
  "package-lock.json",
  "yarn.lock",
  "pnpm-lock.yaml",
  "Cargo.lock",
  ".env",
  ".env.*",
  "secrets/",
]
```

| Field | Default | Purpose |
|---|---|---|
| `paths` | (none; section absent → no defaulting) | Path patterns to protect on every initiative unless the operator explicitly removes them. Patterns are exact paths or simple glob (`*`, `?`); regex is NOT supported. |

**Removing a default protected path requires acknowledgment.** An
operator whose initiative legitimately needs to manipulate one of
these paths (e.g., a repo-migration task that edits `.git/`) must
both:
1. Declare an explicit `[plan.protected_paths]` block in `plan.toml`
   that omits the path.
2. Pass `--ignore-policy-protected-paths` to `plan prepare`.

This is a deliberate friction point: removing a default protected
path is a policy-floor exception that should require operator
acknowledgment rather than silently being permitted by omission.

**Cross-reference.** Existing `[[plan.protected_paths]]` semantics
(per the master `protected_paths` mechanism) are unchanged; this
section just contributes additional default entries.

---

### `[prepare]` (V2 addition)

Operator-ergonomics CLI behavior knobs.

```toml
# policy.toml — V2 schema for [prepare]

[prepare]
auto_upgrade_defaults     = false   # default; production-safe
                                     # when true, plan prepare silently updates
                                     # default-value drift without requiring
                                     # --upgrade-defaults; useful for dev environments
auto_inject_symbol_index  = true    # default; structural fix for the Pure-Static Reviewer
                                     # when true, plan prepare auto-injects a symbol_index
                                     # verifier into every Executor task whose touched
                                     # paths include source files (per
                                     # operator-ergonomics.md §4.2 + verifier-processes.md §14)
```

| Field | Default | Purpose |
|---|---|---|
| `auto_upgrade_defaults` | `false` | When `true`, `raxis-cli plan prepare` silently updates default-value drift instead of failing with `FAIL_PREPARE_DEFAULT_UPGRADE_REQUIRED`. The annotation version stamp is bumped to the current CLI version. Production deployments leave this `false`; dev deployments may set it `true` for frictionless iteration. |
| `auto_inject_symbol_index` | `true` | When `true`, `raxis-cli plan prepare` auto-injects a `symbol_index` verifier (using the kernel-canonical `raxis-verifier-symbol-index` image per `verifier-processes.md §14`) into every Executor task whose touched paths include source files. Operators who want a different symbol-extraction tool, or who don't want auto-inject, set `false`. The plan-author can suppress per-task with `[plan.tasks.<id>.review] symbol_index = "not_needed"` (existing knob from `planner-harness.md §4.1`); this policy knob controls the *default* behavior. Per `verifier-processes.md §14.2`, the symbol-index image is structural for the Pure-Static Reviewer; the default is `true` to convert `WARN_REVIEWER_MISSING_SYMBOL_INDEX` from a default-state warning into "yes, by default." |

**Why a policy knob, not a CLI flag.** The decision "should
default-value drift be silent or loud?" is a deployment-wide policy
decision, not a per-invocation CLI choice. Tying it to policy makes
the behavior consistent across operators on the same deployment and
auditable as a policy property. CLI users who want one-off silent
upgrades pass `--upgrade-defaults` to `plan prepare` directly.

---

### `[default_verifier_images]` (V2 addition)

Per-language verifier-image alias mapping consumed by `raxis-cli plan
prepare` for the `image = "@<lang>"` shortcut (per
`verifier-processes.md §14.5`). Lets plan authors write
`image = "@rust"` instead of the full image alias; `plan prepare`
resolves through this table at prepare-time, getting the operator's
preferred image alias filled in with a `# @raxis-default v0.4.0`
annotation.

```toml
# policy.toml — V2 schema for [default_verifier_images]

[default_verifier_images]
rust   = "raxis-verifier-rust-starter"
node   = "raxis-verifier-node-starter"
python = "raxis-verifier-python-starter"
go     = "raxis-verifier-go-starter"
```

| Field | Type | Default | Purpose |
|---|---|---|---|
| `[default_verifier_images].<language>` | string (image alias resolving to `[[vm_images]]`) | `setup wizard` populates per the language stacks the operator selected at install (per `operator-ergonomics.md §16.3`) | When a verifier declaration writes `image = "@<language>"`, `plan prepare` substitutes the alias from this table. Operators who want to use their own custom image for a language (e.g., a fork of `raxis-verifier-rust-starter` with extra crates) override the value here. |

**Validation at policy load:**

1. Each value must resolve to a `[[vm_images]]` entry whose
   `role_restriction` includes `"Verifier"`. Otherwise:
   `FAIL_POLICY_DEFAULT_VERIFIER_IMAGE_UNRESOLVABLE { language,
   alias }`.
2. Recognized language keys in V2: `rust`, `node`, `python`, `go`.
   Unknown languages produce
   `WARN_DEFAULT_VERIFIER_IMAGE_UNKNOWN_LANGUAGE { language }`
   (non-fatal; the `@<language>` shortcut for that language simply
   won't resolve).

**Why this is a policy concern, not a plan concern.** The image
alias is a deployment-wide property (every plan on this deployment
uses the same Rust verifier starter, modulo per-plan overrides).
Per-plan flexibility is preserved — plan authors who want a
specific image continue to write the full alias verbatim; the
`@<language>` shortcut is a convenience for the common case.

---

### `[[integration_merge_verifiers]]` (V2 addition)

Operator-global pre-`IntegrationMerge` verifier gates per
`verifier-processes.md §15.2`. Mirrors `[[plan.integration_merge_verifiers]]`
in `plan.toml` but is operator-authored and operator-signed; cannot
be downgraded to `warn_only` by any plan; composes with environment
binding via `required_for_environments`.

```toml
# policy.toml — V2 schema for [[integration_merge_verifiers]]

[[integration_merge_verifiers]]
name                      = "production_deploy_smoke"
image                     = "operator/deploy-smoke@sha256:..."
command                   = "./scripts/prod_smoke.sh"
timeout                   = "20m"
on_failure                = "block_merge"                  # operator declarations: must be "block_merge"
applies_to                = "all"                          # all | task_set | last; default "all"
required_for_environments = ["production"]                 # composes with environment-access-control.md INV-ENV-01
# task_set = ["..."]                                       # required if applies_to = "task_set"
# artifact = "/raxis/smoke_report.json"                    # optional
# artifact_max_bytes = 1048576                             # optional
# env = { TARGET = "prod" }                                # optional; RAXIS_* keys forbidden
# allowed_egress = [{ host = "...", method = "GET" }]      # optional; default air-gapped per INV-VERIFIER-11
```

| Field | Required? | Purpose | Validation at policy load |
|---|---|---|---|
| `name` | Required | Identifier within the policy bundle; used for `verifier_witnesses` row keying and audit | Non-empty; `[a-z][a-z0-9_]{0,31}`; unique within `[[integration_merge_verifiers]]` |
| `image` | Required | OCI image used to boot the verifier VM | Must resolve to a `[[vm_images]]` entry whose `role_restriction` includes `"Verifier"`; image must satisfy `INV-VERIFIER-06` |
| `command` | Required | Shell command executed by `raxis-verifier` PID-1 via `sh -lc` inside the verifier VM | Non-empty |
| `timeout` | Required | Wall-clock timeout, parsed as a duration string | ≥ 5 seconds and ≤ kernel hard cap (`max_verifier_timeout_seconds`) |
| `on_failure` | Required | Failure routing | MUST be `"block_merge"` (operator-side declarations cannot be downgraded to `warn_only`); `"block_review"` is rejected per `FAIL_VERIFIER_INVALID_ON_FAILURE` |
| `applies_to` | Optional | Scope filter per `verifier-processes.md §16.3` | `"all"` (default) \| `"task_set"` \| `"last"` |
| `task_set` | Required if `applies_to = "task_set"` | Array of task IDs whose presence in `merged_task_ids` triggers this verifier | All entries must be syntactically valid task IDs (resolution against the plan happens at runtime, since policy is plan-agnostic) |
| `required_for_environments` | Optional | Bind to environment-access-control framework | All entries must resolve to declared `[environments.<label>]` per `environment-access-control.md §5b`; otherwise `FAIL_POLICY_ENV_LABEL_UNDECLARED` |
| `artifact` | Optional | Absolute path inside verifier VM whose contents stage into `staging/merge/<integration_merge_id>/<verifier_name>/` | Must start with `/raxis/`; max 256 chars |
| `artifact_max_bytes` | Optional | Cap on staged artifact size | Default 1 MiB; max 64 MiB |
| `env` | Optional | Additional environment variables | `RAXIS_*` keys forbidden; max 32 entries; max 16 KiB total |
| `allowed_egress` | Optional | Per-verifier network egress allowlist | Empty by default per `INV-VERIFIER-11`; same schema as Executor `allowed_egress` |

**Authority semantics.** `[[integration_merge_verifiers]]` are
operator-declared (signed in the policy bundle). They cannot be
downgraded by any plan. A plan-author who wants to add their own
pre-merge gates uses `[[plan.integration_merge_verifiers]]` in
`plan.toml` (per `verifier-processes.md §15.1`). Both surfaces fire
on the same merge attempt; the union is evaluated by Check 5d.

**Why operator-side declarations are `block_merge` only.**
`warn_only` semantics let the merge proceed despite a non-passing
witness. Allowing operator-side gates to be `warn_only` would
require reasoning about whether an operator's `warn_only` should
be downgradable by a `warn_only` plan-author entry of the same name
(answer: ambiguous; both are warning-level), and the kernel would
have to surface those warnings in some channel that the operator
actually reads. Restricting operator-side to `block_merge`
eliminates the ambiguity and matches the existing pattern that
operator policy is "tighter or equal" — never "looser" — than plan.

**Composition with `[[plan.integration_merge_verifiers]]`.** Both
sources fire on the same `IntegrationMerge` attempt. If both
declare a verifier with the same `name`, the plan-side one is
rejected at `approve_plan` with `FAIL_VERIFIER_NAME_COLLISION`
(operator-side wins; plan-author renames). All matching verifiers
spawn in parallel subject to `[host_capacity] max_concurrent_verifier_vms`.

---

## 5. `approve_plan` Shift-Left Check Order (Updated)

The full admission validation chain runs in this order. Steps 0–0d
are the **Plan Bundle Sealing pre-checks** that fire on
`OperatorRequest::CreateInitiative` before any plan-content parsing
begins; steps 1–onwards run on `OperatorRequest::ApprovePlan` (which
in V2 may be coalesced with `CreateInitiative` for single-step
admission, but conceptually they remain distinct gates):

```
0. Policy load (runs at `epoch advance`, not `approve_plan` per se, but
   gates every subsequent `approve_plan`):
   - Any [[vm_images]] entry's role_restriction contains "Reviewer"?
     → FAIL_POLICY_INVALID_ROLE_RESTRICTION (hard error;
       INV-PLANNER-HARNESS-02)
   - Any [[vm_images]] entry's role_restriction contains "Orchestrator"?
     → FAIL_POLICY_INVALID_ROLE_RESTRICTION (hard error;
       INV-PLANNER-HARNESS-05) — alternately surfaced as
       FAIL_ORCHESTRATOR_VM_IMAGE_NOT_ALLOWED for clearer messaging
   - [orchestrator] provider_alias resolves to a [provider_aliases] entry?
     → No: FAIL_POLICY_ORCHESTRATOR_PROVIDER_ALIAS_UNRESOLVED (hard error)
   - [plan_bundle_limits] values within hard ceilings (per
     plan-bundle-sealing.md §7.4)?
     → Above ceiling: FAIL_POLICY_PLAN_BUNDLE_LIMIT_ABOVE_CEILING (hard error)

0a. Plan Bundle Sealing — IPC envelope decode (runs on
    OperatorRequest::CreateInitiative, before any plan-content parsing):
    - IPC envelope decodes per plan-bundle-sealing.md §3.4?
      → No: FAIL_PLAN_BUNDLE_DECODE_FAILED
    - SHA-256(plan_bundle) == wire bundle_sha256?
      → No: FAIL_PLAN_BUNDLE_SHA256_MISMATCH
    - Bundle within all three [plan_bundle_limits] caps (defensive
      re-check; CLI is the normative enforcement point)?
      → No: FAIL_PLAN_BUNDLE_TOO_LARGE / TOO_MANY_ARTIFACTS / ARTIFACT_TOO_LARGE
0b. Plan Bundle Sealing — canonical decode:
    - Bundle bytes parse against the canonical encoding (plan-bundle-sealing.md §3.2)?
      → No: FAIL_PLAN_BUNDLE_CANONICAL_DECODE_FAILED
    - Per-artifact SHA-256s match recorded values?
      → No: FAIL_PLAN_BUNDLE_ARTIFACT_HASH_MISMATCH
    - artifacts[0].name == "plan.toml"?
      → No: FAIL_PLAN_BUNDLE_FIRST_ARTIFACT_NOT_PLAN_TOML
    - All artifact names valid per §3.3 (no leading /, no .., NFC, no NUL)?
      → No: FAIL_PLAN_BUNDLE_INVALID_NAME
0c. Plan Bundle Sealing — operator authentication:
    - signed_by fingerprint resolves to a policy.operators entry?
      → No: FAIL_UNKNOWN_SIGNER
    - Ed25519 verification of signing_input per plan-bundle-sealing.md §3.2?
      → No: FAIL_PLAN_SIGNATURE_INVALID
    - Operator key revocation state per key-revocation.md?
      → Compromised: FAIL_KEY_COMPROMISED
      → Retired (with signed_at > retired_at): FAIL_KEY_RETIRED
0d. Plan Bundle Sealing — sealing:
    - Insert plan_bundles row keyed by bundle_sha256.
    - Insert plan_bundle_artifacts rows for each artifact.
    - Set initiatives.plan_bundle_sha256 and transition initiative
      to Draft.
    - From this point forward, INV-INIT-06 (post-admission read
      discipline) applies: the host filesystem is NEVER consulted
      for plan files for this initiative again.

0e. Operator-ergonomics — defaultable-fields pre-check (runs only
    when at least one [default_*] policy section declares a value;
    if no defaulting is configured, this step is a no-op):
    - For each defaultable field in operator-ergonomics.md §4.2:
      - Did the policy declare a default for this field
        ([default_executor_image] / [token_policy_defaults.<role>] /
        [default_protected_paths] / etc.)?
      - Did the operator omit the field in the submitted plan?
      - If both: collect the field path into missing_fields.
    - missing_fields non-empty?
      → FAIL_PLAN_REQUIRES_PREPARE { missing_fields: [...] } (hard
        error; not bypassable by --no-strict). Message points the
        operator to `raxis-cli plan prepare`.
    The kernel does NOT silently auto-default. The operator's
    signature must cover the post-default plan, which means the
    operator must have run `plan prepare` and reviewed the result
    before signing.

1. Re-verify Ed25519 plan-bundle signature against the operator's
   currently-loaded public key (defends against key rotation between
   create_initiative and approve_plan; identical mechanism to V1).
2. Verify policy bundle epoch matches current Kernel epoch
3. For each task:
   a0. If role = "Orchestrator":
       → FAIL_ORCHESTRATOR_TASK_NOT_ALLOWED (hard error;
         INV-PLANNER-HARNESS-06.1) — runs before role = "Reviewer"
         check so operators get the most specific message.
   a. If role = "Reviewer":
      - vm_image / image / image_name field present?
        → FAIL_REVIEWER_VM_IMAGE_NOT_ALLOWED (hard error; per §3b)
      - path_allowlist field present (non-null, regardless of value)?
        → FAIL_REVIEWER_PATH_ALLOWLIST_NOT_ALLOWED (hard error; per §3b,
          INV-PLANNER-HARNESS-01) — Reviewer's /workspace mount is RO
          and the harness has no commit-pathway intent (no SingleCommit,
          no IntegrationMerge, no edit_file, no bash); the field is
          structurally meaningless. Operator deletes the field manually
          (the kernel never silently mutates an operator-signed plan
          field). plan prepare emits the equivalent warning pre-signing
          per operator-ergonomics.md §4.5 so this rarely surfaces at
          submit time.
   b. If role ≠ "Reviewer" AND role ≠ "Orchestrator" (i.e., Executor):
      - Resolve vm_image → policy vm_images list
        → Not found: FAIL_VM_IMAGE_NOT_PERMITTED (hard error)
      - vm_images entry's role_restriction contains task.role?
        → Not contained: FAIL_VM_IMAGE_ROLE_RESTRICTION_MISMATCH (hard error; per §3b, §4.4)
      - vm_images entry's introspected guest kernel version (per system-requirements.md
        §2.5 / raxis doctor vm-images category) ≥ 5.14?
        → No: FAIL_VM_GUEST_KERNEL_TOO_OLD (hard error; per §3b)
      - path_allowlist field absent (key not present in TOML at all)?
        → FAIL_PLAN_REQUIRES_EXPLICIT_PATH_ALLOWLIST { task_id } (hard
          error; per §3b) — Executor tasks MUST declare path_allowlist
          explicitly; the kernel does not infer a default because there
          is no safe default value (defaulting to "all paths" violates
          fail-closed; defaulting to "[]" silently ships a no-write
          Executor that the operator probably did not intend). Operator
          runs `raxis-cli plan prepare`, which inserts a commented-out
          template with a required-annotation per operator-ergonomics.md
          §4.5 + §5.2; operator uncomments and customizes; resubmit.
      - path_allowlist field is the literal empty array []?
        - WITH per-line annotation `# @raxis-explicit no-write-acknowledged`
          on or immediately above the empty-array line?
            → Allowed; record TaskWriteScope::NoWriteAcknowledged in
              the InitiativeCreated audit event so reviewers and
              auditors can see the operator explicitly opted into the
              no-write Executor.
        - WITHOUT the annotation?
            → FAIL_EXECUTOR_EMPTY_PATH_ALLOWLIST_UNACKNOWLEDGED { task_id }
              (hard error; per §3b) — empty allowlist on an Executor is
              suspicious in 99% of cases; mirrors the
              `same_cluster_acknowledged` pattern from
              environment-access-control.md §11.4. Operator either
              populates the array OR adds the explicit annotation if
              they really intend a no-write Executor (per
              operator-ergonomics.md §4.5).
      - Each path_allowlist entry conforms to the trailing-slash
        discipline per `v2-deep-spec.md §6` table 4 (exact filename OR
        directory with trailing `/`; no `**`/`*` glob syntax)?
        → No: FAIL_PATH_ALLOWLIST_INVALID_SYNTAX { task_id, entry,
          reason } (hard error; per §3b) — the kernel's path-matching
          mathematics depend on the prefix-or-exact discipline (per
          INV-TASK-PATH-01); glob parsers introduce ambiguity the
          admission gate cannot mechanically resolve. Reasons include
          `"glob_character_in_path"`, `"missing_trailing_slash_for_directory"`
          (when a known directory matches and trailing slash is absent),
          `"absolute_path"` (entries must be repo-relative), `"path_escape"`
          (entries cannot contain `..`).
   c. For each allowed_egress entry:
      - hostname in policy egress_hosts?
        → Not found: FAIL_EGRESS_HOST_NOT_PERMITTED (hard error)
      - methods subset of policy egress_hosts methods?
        → Not subset: WARN_EGRESS_METHOD_RESTRICTED (warning)
   d. For each [[verifiers]] entry (per verifier-processes.md §3):
      - command empty or missing?
        → FAIL_VERIFIER_COMMAND_REQUIRED (hard error)
      - name unique within this task's [[verifiers]]?
        → No: FAIL_VERIFIER_NAME_COLLISION (hard error)
      - declared timeout > policy max_verifier_timeout_seconds?
        → Yes: FAIL_VERIFIER_TIMEOUT_EXCEEDS_HARD_CAP (hard error)
      - declared artifact_max_bytes > policy max_artifact_bytes?
        → Yes: FAIL_VERIFIER_ARTIFACT_CAP_EXCEEDS_HARD_CAP (hard error)
      - vm_images entry's role_restriction contains "Verifier"?
        → No: FAIL_VM_IMAGE_ROLE_RESTRICTION_MISMATCH (hard error)
   e. If role = "Reviewer":
      - At least one verifier on this Reviewer's evaluation_target produces
        artifact path /raxis/symbol_index.json?
        - OR the Reviewer task explicitly declares
          [plan.tasks.<id>.review] symbol_index = "not_needed"?
        → No to both: WARN_REVIEWER_MISSING_SYMBOL_INDEX (warning;
          promoted to FAIL_REVIEWER_MISSING_SYMBOL_INDEX in --strict mode per §3b)
   f. If task declares [[plan.tasks.<id>.custom_tool]] (task-level):
        → FAIL_CUSTOM_TOOL_TASK_LEVEL_NOT_ALLOWED (hard error; per §3b,
          custom-tools.md §3.4)
3b. Build the profile graph. For each declared profile (depth-first):
    - inherits_from = "Orchestrator"?
        → FAIL_PROFILE_ROLE_NOT_CONFIGURABLE (hard error;
          INV-PLANNER-HARNESS-06.2 — runs first so the operator gets
          the specific Orchestrator-not-configurable message rather
          than a downstream generic error)
    - Detect inherits_from cycle?
        → Yes: FAIL_PLAN_PROFILE_INHERITANCE_CYCLE (hard error)
    - Compute effective role (root of inheritance chain).
    - Effective role == "Orchestrator"?
        → FAIL_ORCHESTRATOR_PROFILE_NOT_ALLOWED (hard error;
          INV-PLANNER-HARNESS-06.1 — catches the case where an
          operator declares `[profiles.X] role = "Orchestrator"`
          directly without using inherits_from)
    - Compute effective custom-tool set (additive union per custom-tools.md §8.2).
    - For each effective custom_tool:
      - name matches reserved list (raxis admin reserved-tool-names)?
        → FAIL_CUSTOM_TOOL_NAME_RESERVED (hard error)
      - name matches naming convention ^[a-z][a-z0-9_]{0,47}$?
        → No: FAIL_CUSTOM_TOOL_SCHEMA_INVALID (hard error; with field=name)
      - schema is well-formed JSON Schema (draft-07 subset per custom-tools.md §4)?
        → No: FAIL_CUSTOM_TOOL_SCHEMA_INVALID (hard error)
      - schema uses any rejected keyword (custom-tools.md §4.2)?
        → Yes: FAIL_CUSTOM_TOOL_SCHEMA_UNSUPPORTED_FEATURE (hard error)
      - schema top-level type == "object"?
        → No: FAIL_CUSTOM_TOOL_SCHEMA_NOT_OBJECT_ROOT (hard error)
      - schema top-level additionalProperties == false?
        → No: FAIL_CUSTOM_TOOL_SCHEMA_ADDITIONALPROPERTIES_TRUE (hard error)
      - timeout_seconds > policy max_custom_tool_timeout_seconds?
        → Yes: FAIL_CUSTOM_TOOL_TIMEOUT_EXCEEDS_HARD_CAP (hard error)
      - env table key collides with kernel-reserved (RAXIS_*, PATH, HOME, LANG, ...)?
        → Yes: FAIL_CUSTOM_TOOL_ENV_RESERVED_KEY (hard error)
    - Effective set name uniqueness (across direct + inherited)?
      → No: FAIL_CUSTOM_TOOL_NAME_COLLISION (hard error)
    - Effective set count > 25?
      → Yes: FAIL_CUSTOM_TOOL_COUNT_EXCEEDED (hard error)
    - If effective role == "Reviewer" AND effective set non-empty?
      → FAIL_REVIEWER_CUSTOM_TOOL_NOT_ALLOWED (hard error; per §3b,
        INV-PLANNER-HARNESS-04)
    - Project token cost: tokenize the rendered tool-list payload using the
      smallest context window across the profile's [provider_aliases] chain.
      - share = total_tokens / smallest_context_window
      - share ≥ policy schema_budget_fail_share (default 0.25)?
        → FAIL_CUSTOM_TOOL_SCHEMA_BUDGET_EXCEEDED (hard error)
      - share ≥ policy schema_budget_warn_share (default 0.10)?
        → WARN_CUSTOM_TOOL_SCHEMA_BUDGET_HIGH (warning; promoted to error
          in --strict)
3.5 Environment-binding consistency (V2; runs only when at least one
    [environments.<label>] is declared in the loaded policy per
    environment-access-control.md §1.5.2; if no environments are
    declared, this step is a no-op):
    - For each task in plan.tasks (in declaration order):
      - For each allowed_egress URL: run handle_same_cluster_conflation
        per environment-access-control.md §11.4 against
        [[environment_gates]]:
          → URL matches ≥ 2 gate labels AND any conflated env does NOT
            declare same_cluster_acknowledged = true:
              FAIL_SAME_CLUSTER_NAMESPACE_ISOLATION { task, url_prefix,
                conflated_environments, unacknowledged }
              (hard; not bypassable by --no-strict)
          → URL matches ≥ 2 gate labels AND every conflated env
            declares same_cluster_acknowledged = true: URL contributes
            0 labels to task_envs; continue.
          → URL matches exactly 1 gate label: contribute that label.
          → URL matches 0 gates: neutral; contribute nothing.
      - Run compute_task_envs per environment-access-control.md §11.3:
          - Walk env-bound credentials (those whose
            [[permitted_credentials]] entry has a non-empty environment
            field): contribute their labels.
          - Combine with the URL-derived labels above.
      - Cardinality check on task_envs:
          - 0 labels: record TaskEnvironmentBinding::Neutral.
          - 1 label: record TaskEnvironmentBinding::Bound(label).
          - ≥ 2 labels: FAIL_TASK_ENVIRONMENT_INCONSISTENT { task,
            environments, sources }
            (hard; not bypassable by --no-strict; INV-ENV-01 is
            structural per invariants.md §11.5)
    - Reviewer and Orchestrator tasks are processed but always record
      as Neutral by structural prohibition
      (per environment-access-control.md §11.6 — INV-PLANNER-HARNESS-01,
      -04, -06 forbid the operator from declaring credentials or
      allowed_egress on these roles, so cardinality is always 0).
    - The TaskEnvironmentBinding for every task is included in the
      InitiativeCreated audit event per
      environment-access-control.md §11.9.

3.6 Per-task verifier validation (V2; runs once per declared
    [[plan.tasks.<id>.verifiers]] entry):
    - name uniqueness within the task → FAIL_VERIFIER_NAME_COLLISION
    - command non-empty → FAIL_VERIFIER_COMMAND_REQUIRED
    - image resolves to [[vm_images]] with role_restriction containing
      "Verifier" → otherwise FAIL_VM_IMAGE_NOT_REGISTERED or
      FAIL_VM_IMAGE_ROLE_RESTRICTION_MISMATCH
    - timeout ≤ [host_capacity] max_verifier_timeout_seconds
      → FAIL_VERIFIER_TIMEOUT_EXCEEDS_HARD_CAP
    - artifact_max_bytes ≤ [host_capacity] max_artifact_bytes
      → FAIL_VERIFIER_ARTIFACT_CAP_EXCEEDS_HARD_CAP
    - on_failure ∈ {"block_review", "warn_only"} (NOT "block_merge"
      — that's pre-merge-only) → FAIL_VERIFIER_INVALID_ON_FAILURE
    - env keys do not start with RAXIS_ → FAIL_CUSTOM_TOOL_ENV_RESERVED_KEY
      (shared with custom-tools.md)

3.7 Pre-merge verifier validation (V2; runs once per declared
    [[plan.integration_merge_verifiers]] entry, plus per-policy-bundle
    validation of [[integration_merge_verifiers]] entries at policy load):
    - name uniqueness within the (plan-source ∪ policy-source) union;
      collision rejects the plan-side entry with FAIL_VERIFIER_NAME_COLLISION
      (operator-side wins per `policy-plan-authority.md §4 [[integration_merge_verifiers]]`)
    - command non-empty → FAIL_VERIFIER_COMMAND_REQUIRED
    - image resolves and has Verifier role_restriction (same as 3.6)
    - timeout ≤ kernel hard cap (same as 3.6)
    - artifact_max_bytes ≤ kernel hard cap (same as 3.6)
    - on_failure ∈ {"block_merge", "warn_only"} for plan-source;
      MUST be "block_merge" for policy-source (operator declarations
      cannot downgrade) → FAIL_VERIFIER_INVALID_ON_FAILURE
    - applies_to ∈ {"all", "task_set", "last"} → schema validation
    - if applies_to = "task_set":
        - task_set non-empty → FAIL_VERIFIER_TASK_SET_EMPTY
        - every entry resolves to a declared [[plan.tasks.<id>]]
          (plan-source only; policy-source defers to runtime since
          policy is plan-agnostic) → FAIL_VERIFIER_TASK_SET_UNKNOWN_TASK
    - required_for_environments (policy-source only) entries resolve
      to declared [environments.<label>] →
      FAIL_POLICY_ENV_LABEL_UNDECLARED (per
      environment-access-control.md §5b.3)
    - env keys do not start with RAXIS_ → FAIL_CUSTOM_TOOL_ENV_RESERVED_KEY

4. For each [[plan.protected_path_gates]] entry (renamed from
   [[integration_merge_gates]] in V2 per integration-merge.md §13.b
   to disambiguate from the new pre-merge verifier mechanism):
   - require_approval = true AND path already in policy protected_paths?
     → WARN_PROTECTION_OVERRIDDEN (warning) — note the rename;
     the existing WARN_INTEGRATION_MERGE_GATE_REDUNDANT code is
     repurposed as WARN_PROTECTED_PATH_GATE_REDUNDANT for clarity
     in V2 (no behavioral change; the warning still fires under the
     same conditions).
   - require_approval = false AND path already in policy protected_paths?
     → WARN_PROTECTION_OVERRIDDEN (warning)
5. Check plan.require_push_approval vs policy.push_policy.require_push_approval_minimum:
   - plan = false AND policy_min = true?
     → WARN_PUSH_APPROVAL_DOWNGRADED (warning)
6. For each task with a token_policy section (or no token_policy section):
   - Any limit field omitted (not explicitly "uncapped" and not a Count)?
     → WARN_UNCAPPED_TOKEN_LIMIT { task_id, uncapped_fields: [...] } (warning)
   - No token_policy section at all?
     → WARN_UNCAPPED_TOKEN_LIMIT { task_id, uncapped_fields: ["all"] } (warning)
7. Check plan.estimated_cost vs lane budget ceiling:
   - estimated_cost > ceiling? → FAIL_ESTIMATED_COST_EXCEEDS_CEILING (hard error)
8. Collect all warnings
9. If policy.approve_plan_strict_by_default = false AND --no-strict flag:
   - Approve plan, emit all warnings to stdout
   - Record warnings in InitiativeCreated audit event (approved_strict = false)
9. Else (default — strict mode):
   - Any warnings? → Reject plan, emit all warnings as errors
   - No warnings? → Approve plan (approved_strict = true)
```

**Hard errors** (`FAIL_*`) always reject the plan regardless of `--strict`.
**Warnings** (`WARN_*`) allow the plan to proceed unless `--strict` is active.

The distinction is: hard errors indicate a configuration that *cannot run correctly*
(plan references an unpermitted image — the VM will never boot). Warnings indicate
a configuration that *will run*, but not exactly as the plan declared — the Kernel's
behavior diverges from the plan's stated intent.

---

## 6. Implementation Checklist

- [ ] Add `ApproveWarning` struct to `crates/types/src/operator_wire.rs`
- [ ] Add `approve_warnings: Vec<ApproveWarning>` to `InitiativeCreated` audit event
- [ ] Add `approved_strict: bool` to `InitiativeCreated` audit event
- [ ] Implement warning collection in `kernel/src/handlers/approve_plan.rs`:
      - `WARN_PROTECTION_OVERRIDDEN`
      - `WARN_PUSH_APPROVAL_DOWNGRADED`
      - `WARN_EGRESS_METHOD_RESTRICTED`
      - `WARN_INTEGRATION_MERGE_GATE_REDUNDANT`
- [ ] Add `--strict` flag to `raxis plan approve` CLI command
- [ ] Add `--no-warnings` flag to `raxis plan approve` CLI command
- [ ] Add `[push_policy]` section to `PolicyBundle` struct with `require_push_approval_minimum`
- [ ] Add `[approve_policy]` section to `PolicyBundle` struct with `approve_plan_strict_by_default`
- [ ] Implement policy-floor enforcement for push approval in initiative activation:
      effective_require_push_approval = plan.require_push_approval || policy.require_push_approval_minimum
- [ ] Update `raxis plan approve` output format: warning blocks with plan_value / kernel_value
- [ ] V2 plan-admission additions (per `planner-harness.md §11.2` + `verifier-processes.md §14.1`):
      - Reject Reviewer tasks with any image field → `FAIL_REVIEWER_VM_IMAGE_NOT_ALLOWED`
      - Reject Reviewer tasks declaring `path_allowlist` (any value) → `FAIL_REVIEWER_PATH_ALLOWLIST_NOT_ALLOWED` (per `INV-PLANNER-HARNESS-01` extension)
      - Reject Executor tasks with no `path_allowlist` field at all → `FAIL_PLAN_REQUIRES_EXPLICIT_PATH_ALLOWLIST` (per `operator-ergonomics.md §4.5`)
      - Reject Executor tasks with `path_allowlist = []` and no `# @raxis-explicit no-write-acknowledged` annotation → `FAIL_EXECUTOR_EMPTY_PATH_ALLOWLIST_UNACKNOWLEDGED`
      - Reject `path_allowlist` entries containing glob characters, absolute paths, or `..` → `FAIL_PATH_ALLOWLIST_INVALID_SYNTAX { task_id, entry, reason }` (per `v2-deep-spec.md §6` table 4)
      - Annotation parser MUST scan trailing comments on the value line AND the comment line immediately above the value line (operator may write either form); the comment-detection logic is the same one `plan prepare` uses for `# @raxis-default vX.Y.Z` annotations per `operator-ergonomics.md §4.3`
      - Reject tasks whose vm_image's `role_restriction` lacks the task's role → `FAIL_VM_IMAGE_ROLE_RESTRICTION_MISMATCH`
      - Reject tasks whose vm_image's introspected guest kernel < 5.14 → `FAIL_VM_GUEST_KERNEL_TOO_OLD`
      - Reject `[[verifiers]]` with empty `command` → `FAIL_VERIFIER_COMMAND_REQUIRED`
      - Reject `[[verifiers]]` with `name` collision within a task → `FAIL_VERIFIER_NAME_COLLISION`
      - Reject `[[verifiers]]` with `timeout > max_verifier_timeout_seconds` → `FAIL_VERIFIER_TIMEOUT_EXCEEDS_HARD_CAP`
      - Reject `[[verifiers]]` with `artifact_max_bytes > max_artifact_bytes` → `FAIL_VERIFIER_ARTIFACT_CAP_EXCEEDS_HARD_CAP`
      - Reject per-task `[[verifiers]]` with `on_failure = "block_merge"` → `FAIL_VERIFIER_INVALID_ON_FAILURE` (per-task verifiers gate Reviewer activation only; pre-merge gating uses `[[plan.integration_merge_verifiers]]` per `verifier-processes.md §15.1`)
      - Reject `[[vm_images]]` whose `role_restriction` includes `"Reviewer"` at policy load → `FAIL_POLICY_INVALID_ROLE_RESTRICTION`
      - Reject `[[vm_images]]` whose alias is `"raxis-verifier-symbol-index"` (reserved per `INV-VERIFIER-12`) → `FAIL_POLICY_RESERVED_VM_IMAGE_NAME`
      - Implement `[[vm_images]] role_restriction` schema field (required; non-empty array)
      - Implement V1-policy migration to permissive `["Executor", "Orchestrator", "Verifier"]` default with `PolicyMigrationApplied` audit
      - Implement `WARN_REVIEWER_MISSING_SYMBOL_INDEX` and its `--strict` promotion to `FAIL_*`
      - Implement `[plan.tasks.<id>.review] symbol_index = "not_needed"` parse path for the silencing override
- [ ] V2 runtime additions:
      - Implement runtime check for canonical Reviewer image SHA-256 at every Reviewer activation → `FAIL_REVIEWER_IMAGE_DIGEST_MISMATCH` + `SecurityViolationDetected` audit
      - Implement runtime check for canonical Orchestrator image SHA-256 at every Orchestrator activation (per initiative) → `FAIL_ORCHESTRATOR_IMAGE_DIGEST_MISMATCH` + `SecurityViolationDetected` audit
      - Implement runtime check for canonical `raxis-verifier-symbol-index` image SHA-256 at every symbol-index verifier activation → `FAIL_CANONICAL_VERIFIER_IMAGE_DIGEST_MISMATCH` + `SecurityViolationDetected` audit; halts further verifier spawns until `raxis doctor canonical-images` succeeds (per `verifier-processes.md §14.4`)
      - Implement `FAIL_DECLARED_ARTIFACT_MISSING` runtime path per `verifier-processes.md §6.3`
      - Implement `FAIL_VERIFIER_BLOCKED` Executor-facing return on `block_review` failure per `verifier-processes.md §5.2`
- [ ] V2 pre-`IntegrationMerge` verifier additions (per `verifier-processes.md §15` + `integration-merge.md §4 Check 5d`):
      - Add `[[integration_merge_verifiers]]` operator-global section to `PolicyBundle` struct per `policy-plan-authority.md §4 [[integration_merge_verifiers]]`
      - Validation at policy load: enforce all field constraints (name uniqueness, image resolution + `Verifier` role_restriction, timeout and artifact-cap bounds, `on_failure = "block_merge"` only)
      - Add `[[plan.integration_merge_verifiers]]` plan-side section to `PlanBundle` struct
      - Validation at `approve_plan` (admission step 3.7): plan-source `on_failure ∈ {"block_merge", "warn_only"}`; cross-source name collision rejects plan-side with `FAIL_VERIFIER_NAME_COLLISION`
      - `applies_to` parsing: `"all"` (default) | `"task_set"` (with `task_set` validated against declared `[[plan.tasks]]`) | `"last"`
      - `required_for_environments` (operator-side only) entries resolve to declared `[environments.<label>]` per `environment-access-control.md §5b`
      - Implement matching algorithm at Check 5d.1 per `integration-merge.md §4 Check 5d.1` (cross-spec)
      - Implement candidate-merge-tree materialization at Check 5d.2 per `integration-merge.md §11.10`
      - Implement gating algorithm at Check 5d.4; emit `FAIL_INTEGRATION_MERGE_VERIFIER_BLOCKED` and `FAIL_CANDIDATE_MERGE_COMPUTATION_FAILED`
      - Add `FAIL_VERIFIER_INVALID_ON_FAILURE`, `FAIL_VERIFIER_TASK_SET_EMPTY`, `FAIL_VERIFIER_TASK_SET_UNKNOWN_TASK`, `FAIL_INTEGRATION_MERGE_VERIFIER_BLOCKED`, `FAIL_CANDIDATE_MERGE_COMPUTATION_FAILED`, `FAIL_CANONICAL_VERIFIER_IMAGE_DIGEST_MISMATCH`, `FAIL_POLICY_RESERVED_VM_IMAGE_NAME` to `raxis-types::PlannerErrorCode`
- [ ] V2 `[default_verifier_images]` additions (per `policy-plan-authority.md §4`):
      - Add `[default_verifier_images]` policy section to `PolicyBundle` struct
      - Validation at policy load: each value resolves to a `[[vm_images]]` entry with `role_restriction` containing `"Verifier"` → otherwise `FAIL_POLICY_DEFAULT_VERIFIER_IMAGE_UNRESOLVABLE`; unrecognized language keys → `WARN_DEFAULT_VERIFIER_IMAGE_UNKNOWN_LANGUAGE`
      - `setup wizard` populates entries per detected language stacks (per `operator-ergonomics.md §16.3` phase 6)
      - `raxis-cli plan prepare` resolves `image = "@<language>"` shortcuts in `[[plan.tasks.<id>.verifiers]]` and `[[plan.integration_merge_verifiers]]` against this table; substitutes the alias with `# @raxis-default v0.4.0` annotation
- [ ] V2 `[prepare]` policy knob additions (per `policy-plan-authority.md §4 [prepare]`):
      - Add `auto_inject_symbol_index: bool` field to `[prepare]` table; default `true`
      - `raxis-cli plan prepare` reads the knob; when `true`, auto-injects a `symbol_index` verifier (using `image = "raxis-verifier-symbol-index"`) into every Executor task whose touched paths include source files
      - Suppression hook: `[plan.tasks.<id>.review] symbol_index = "not_needed"` (existing knob from `planner-harness.md §4.1`) prevents auto-inject for that task
      - `raxis doctor canonical-images` (per `system-requirements.md §11`) verifies the `raxis-verifier-symbol-index-<kernel_version>.img` digest matches the kernel-binary-embedded canonical digest
- [ ] V2 Orchestrator admission additions (per `planner-harness.md §4.7`, §4.8):
      - Reject `[[plan.tasks.<id>]] role = "Orchestrator"` → `FAIL_ORCHESTRATOR_TASK_NOT_ALLOWED`
      - Reject `[[profiles.<name>]] inherits_from = "Orchestrator"` → `FAIL_PROFILE_ROLE_NOT_CONFIGURABLE`
      - Reject `[[profiles.<name>]]` whose effective role is `Orchestrator` → `FAIL_ORCHESTRATOR_PROFILE_NOT_ALLOWED`
      - Reject `[[vm_images]]` whose `role_restriction` includes `"Orchestrator"` at policy load → `FAIL_POLICY_INVALID_ROLE_RESTRICTION` (alias `FAIL_ORCHESTRATOR_VM_IMAGE_NOT_ALLOWED` for messaging)
      - Reject `[orchestrator] provider_alias` not resolving to an entry in `[provider_aliases]` at policy load → `FAIL_POLICY_ORCHESTRATOR_PROVIDER_ALIAS_UNRESOLVED`
      - Add `[orchestrator]` section to `PolicyBundle` struct with fields `provider_alias`, `max_token_budget_per_initiative`, `all_merges_require_approval`
      - Implement Orchestrator session auto-creation at initiative admission (no operator-declared profile required)
      - Implement `[KERNEL: INITIATIVE GUIDANCE]` injection from `[plan.initiative].description` into the kernel-pinned Orchestrator NNSP per `kernel-mechanics-prompt.md §3.2`
      - When `[orchestrator] all_merges_require_approval = true`, every `IntegrationMerge` admitted by the kernel paths through the existing escalation mechanism (new escalation class `MergeAuthorization`); the Orchestrator NNSP §3.2 IntegrationMerge protocol is unchanged — the escalation requirement is enforced at kernel admission, not in-VM
- [ ] V2 custom-tools admission additions (per `custom-tools.md §3`, §4, §5, §8, §9, §10):
      - Plan parser accepts `[[profiles.<name>.custom_tool]]` array-of-tables under each profile
      - Plan parser rejects `[[plan.tasks.<id>.custom_tool]]` → `FAIL_CUSTOM_TOOL_TASK_LEVEL_NOT_ALLOWED`
      - Vendored Draft-07 schema validator implementing the accepted-keyword set in `custom-tools.md §4.1` and rejecting all keywords in §4.2
      - Reserved-name list mirrored from kernel binary; `raxis admin reserved-tool-names` CLI exposes it
      - Inheritance walker computes effective custom-tool set; emits `FAIL_PLAN_PROFILE_INHERITANCE_CYCLE`, `FAIL_CUSTOM_TOOL_NAME_COLLISION`, `FAIL_CUSTOM_TOOL_NAME_RESERVED` as appropriate
      - Reviewer-rooted profiles with non-empty effective set → `FAIL_REVIEWER_CUSTOM_TOOL_NOT_ALLOWED` (`INV-PLANNER-HARNESS-04`)
      - Schema validation: `FAIL_CUSTOM_TOOL_SCHEMA_INVALID`, `FAIL_CUSTOM_TOOL_SCHEMA_UNSUPPORTED_FEATURE`, `FAIL_CUSTOM_TOOL_SCHEMA_NOT_OBJECT_ROOT`, `FAIL_CUSTOM_TOOL_SCHEMA_ADDITIONALPROPERTIES_TRUE`
      - Per-tool timeout cap → `FAIL_CUSTOM_TOOL_TIMEOUT_EXCEEDS_HARD_CAP` against `policy.toml [custom_tool_limits].max_custom_tool_timeout_seconds`
      - Operator `env` collision against kernel-reserved keys → `FAIL_CUSTOM_TOOL_ENV_RESERVED_KEY`
      - Effective set count > 25 → `FAIL_CUSTOM_TOOL_COUNT_EXCEEDED`
      - Token-budget projection via `raxis-gateway` `tokenize` admin interface; emit `WARN_CUSTOM_TOOL_SCHEMA_BUDGET_HIGH` and `FAIL_CUSTOM_TOOL_SCHEMA_BUDGET_EXCEEDED` per `custom-tools.md §9.3`
      - Add `[custom_tool_limits]` and `[audit.custom_tools]` sections to `PolicyBundle` struct
- [ ] V2 custom-tools runtime additions:
      - Per-invocation cgroup `/sys/fs/cgroup/raxis/customtool-<seq>/` lifecycle in the planner harness
      - Schema-validate LLM input before script invocation; canonical-JSON stdin write
      - Stdout / stderr cap enforcement with truncation sentinels per `custom-tools.md §6.4`, §6.5
      - Timeout via `cgroup.kill` per `custom-tools.md §7.2`
      - `CustomToolInvoked` audit event per `custom-tools.md §12.1`
      - `[audit.custom_tools].archive_full_payloads` payload store path
      - `raxis log --filter kind=CustomToolInvoked` view per `custom-tools.md §12.3`
- [ ] V2 environment-binding additions (per `environment-access-control.md`):
      - Implement `[environments.<label>]` table parsing and validation per `environment-access-control.md §5b`; emit `FAIL_POLICY_ENV_LABEL_INVALID`, `FAIL_POLICY_ENV_UNKNOWN_FIELD`, `FAIL_POLICY_ENV_LABEL_UNDECLARED`, `WARN_ENVIRONMENT_RESERVED_FIELD_SET` at policy load
      - Implement `compute_task_envs` per `environment-access-control.md §11.3` and `handle_same_cluster_conflation` per `§11.4`
      - Add admission step 3.5 (env-binding consistency) per §5; runs only when the loaded policy declares at least one `[environments.<label>]`; no-op otherwise per `environment-access-control.md §1.5`
      - Promote `WARN_SAME_CLUSTER_NAMESPACE_ISOLATION` → `FAIL_SAME_CLUSTER_NAMESPACE_ISOLATION` per `environment-access-control.md §7`; the only escape hatch is per-environment `same_cluster_acknowledged = true` (§11.4)
      - Emit `FAIL_TASK_ENVIRONMENT_INCONSISTENT { task, environments, sources }` per `environment-access-control.md §11.7`; not bypassable by `--no-strict`
      - Add `TaskEnvironmentBinding { task_id, binding, bound_via }` to `InitiativeCreated` audit event per `environment-access-control.md §11.9`
      - All `FAIL_TASK_ENVIRONMENT_INCONSISTENT`, `FAIL_SAME_CLUSTER_NAMESPACE_ISOLATION`, `FAIL_POLICY_ENV_*`, `WARN_ENVIRONMENT_RESERVED_FIELD_SET` codes registered in `raxis-types::PlannerErrorCode`
      - `raxis-cli plan explain` (per `operator-ergonomics.md §9`) renders per-task binding ("Bound: production" / "Neutral" / "SameClusterAcknowledged")
- [ ] V2 operator-ergonomics additions (per `operator-ergonomics.md`):
      - Implement `[default_executor_image]` policy section per `operator-ergonomics.md §18.1`; validate at policy load → `FAIL_POLICY_DEFAULT_EXECUTOR_IMAGE_UNRESOLVABLE`
      - Implement `[token_policy_defaults.<role>]` policy section per §18.2
      - Implement `[default_protected_paths]` policy section per §18.3; union with operator-declared `[plan.protected_paths]` at `plan prepare` time
      - Implement `[prepare] auto_upgrade_defaults` policy knob per §18.4
      - Implement `OperatorRequest::ProposeDefaults` IPC handler per `operator-ergonomics.md §5.3`; read-only on kernel state
      - Implement `OperatorRequest::EstimateCost` IPC handler per `operator-ergonomics.md §11.3`
      - Implement `OperatorRequest::DryRunAdmit` IPC handler per `operator-ergonomics.md §12.3`; runs full admission chain but does NOT seal the bundle
      - Implement `OperatorRequest::SubscribeInitiative` and `KernelPush::InitiativeEvent` per `operator-ergonomics.md §13`
      - Implement `OperatorRequest::DescribeInitiativePause` per `operator-ergonomics.md §14`
      - Add admission step 0e (defaultable-fields pre-check) per §5; emit `FAIL_PLAN_REQUIRES_PREPARE { missing_fields }` when defaultable fields are omitted AND policy declares defaults for them
      - Implement `DefaultsProposed` and `DryRunAdmitted` audit events per `operator-ergonomics.md §19.2`; rate-limited per operator fingerprint
      - All `FAIL_PLAN_REQUIRES_PREPARE`, `FAIL_PREPARE_DEFAULT_UPGRADE_REQUIRED`, `FAIL_POLICY_DEFAULT_*`, `FAIL_COST_ESTIMATE_*`, `FAIL_INITIATIVE_NOT_PAUSED` codes registered in `raxis-types::PlannerErrorCode`
- [ ] V2 provider-model-selection additions (per `provider-model-selection.md`):
      - Implement `[provider_aliases_defaults.<role>]` policy section parsing and validation per `provider-model-selection.md §7`
      - Validation chain at policy load: `FAIL_POLICY_PROVIDER_ALIAS_DEFAULT_REFERENCES_NONPERMITTED_MODEL`, `FAIL_POLICY_PROVIDER_ALIAS_DEFAULT_MISSING_CREDENTIAL`, `FAIL_POLICY_PROVIDER_ALIAS_DEFAULT_EMPTY_CHAIN`, `FAIL_POLICY_PROVIDER_ALIAS_DEFAULT_UNKNOWN_FALLBACK_BEHAVIOR`, `WARN_PROVIDER_ALIAS_DEFAULT_UNKNOWN_ROLE`, `WARN_PROVIDER_ALIAS_PRIMARY_NO_FAILOVER`
      - Rename `[orchestrator] provider_alias` default value from V1 `"fast_low_cost"` to `"orchestrator_default"`; emit `WARN_ORCHESTRATOR_DEFAULT_ALIAS_RENAMED` for V1-style policies that still use the old name
      - Update `[orchestrator]` recommended chain to a mid-tier reasoning model with cross-provider fallback per `provider-model-selection.md §4`
      - Extend `OperatorRequest::ProposeDefaults` handler (`operator-ergonomics.md §5.3`) to consume `[provider_aliases_defaults.<role>]` and fill `[provider_aliases.<role>]` entries into the augmented plan when absent (and when the corresponding profile does NOT declare its own `provider_alias`)
      - All new `FAIL_POLICY_PROVIDER_ALIAS_DEFAULT_*` and `WARN_PROVIDER_ALIAS_*` codes registered in `raxis-types::PlannerErrorCode`
      - `raxis-cli setup wizard` phases 2–4 per `provider-model-selection.md §9`; per-key smoke test, on-disk credential write to `<data_dir>/providers/<provider>.toml` chmod 0600, auto-population of `[[providers.credentials]]`, `[providers] permitted_models`, `[orchestrator] provider_alias`, and `[provider_aliases_defaults.{reviewer,executor}]` per the §5.2 `auto_diversify` algorithm
      - `raxis-cli setup wizard --no-diversify` and `--reset-chains` flags
      - `raxis-cli setup wizard --add-provider <id>` re-runs phases 2 + 4 only
- [ ] V2 Plan Bundle Sealing additions (per `plan-bundle-sealing.md`):
      - CLI: implement `raxis-cli submit plan <plan.toml> [--initiative-id <id>]` per `plan-bundle-sealing.md §4`
      - CLI: remove `raxis-cli plan sign` command; reject the V1 `plan submit <id> <dir>` invocation at arg parse with hint
      - CLI: streaming artifact reads with `max_artifact_bytes + 1` cap to avoid OOM on oversize files
      - CLI: path-resolution visitor with V2-empty host-path field set (forward-compatibility hook)
      - CLI: canonical encoding per `plan-bundle-sealing.md §3.2`; pin via `cli/tests/plan_bundle_canonical_roundtrip.rs`
      - CLI: failure messages include the **declared path** for path-related failures
      - Kernel: `OperatorRequest::CreateInitiative` decoder accepts ONLY the V2 wire shape; V1 shape rejected at decode
      - Kernel: full §5 admission sequence (steps 0a–0d) implemented in order with short-circuit on failure
      - Kernel: `plan_bundles` and `plan_bundle_artifacts` SQL tables; `initiatives.plan_bundle_sha256` column
      - Kernel: `raxis-kernel::store::plan_bundle::read_artifact` is the SOLE API for initiative-execution code to read plan-derived bytes; lint-guard against any kernel module opening a file under the plan root for an admitted initiative
      - Kernel: `approve_plan` re-verification reads bundle bytes from SQLite, never disk
      - Kernel: crash recovery replays exclusively from `plan_bundles` / `plan_bundle_artifacts`
      - Kernel: KSB rendering reads `plan.toml` from `artifacts[0]` via `read_artifact`
      - Policy: `[plan_bundle_limits]` section parsed and validated per §4 hard ceilings; out-of-range → `FAIL_POLICY_PLAN_BUNDLE_LIMIT_ABOVE_CEILING`
      - All `FAIL_PLAN_BUNDLE_*` codes registered in `raxis-types::PlannerErrorCode` and surfaced through the operator socket
      - `raxis-cli initiative show <id> --bundle` emits the stored bundle for forensic inspection
      - `raxis log --filter kind=InitiativeAdmissionFailed` shows `bundle_sha256`, `cap_violated`, `signed_by`
- [ ] Tests:
      - Plan with WARN_PROTECTION_OVERRIDDEN → approved with warning (default)
      - Plan with WARN_PROTECTION_OVERRIDDEN + --strict → rejected
      - Plan with WARN_PUSH_APPROVAL_DOWNGRADED → push approval enforced at runtime
      - Plan with WARN_EGRESS_METHOD_RESTRICTED → method blocked at egress (tproxy SNI / Credential Proxy URL allowlist) admission
      - policy.approve_plan_strict_by_default = true → warnings become errors without --strict flag
      - Plan with no warnings → clean approval output, empty approve_warnings in audit
      - V2: Plan with `vm_image` field on a Reviewer task → rejected with `FAIL_REVIEWER_VM_IMAGE_NOT_ALLOWED`
      - V2: Plan referencing image whose `role_restriction` lacks task's role → rejected
      - V2: Plan with verifier `name` collision → rejected
      - V2: Plan with verifier `timeout` > policy hard cap → rejected
      - V2: Reviewer activation with tampered canonical image → aborted with `FAIL_REVIEWER_IMAGE_DIGEST_MISMATCH`
      - V2: Verifier with `on_failure = block_review` failing → Executor receives `FAIL_VERIFIER_BLOCKED`
      - V2: Plan with no symbol-index verifier and no `symbol_index = "not_needed"` → `WARN_REVIEWER_MISSING_SYMBOL_INDEX`
      - V2: Plan with no symbol-index verifier and `symbol_index = "not_needed"` → no warning
      - V2: V1 policy bundle (no `role_restriction` field) on `epoch advance` → permissive migration with audit
      - V2: Profile with custom tool inheriting from Reviewer → rejected with `FAIL_REVIEWER_CUSTOM_TOOL_NOT_ALLOWED`
      - V2: Plan with `[[plan.tasks.<id>.custom_tool]]` → rejected with `FAIL_CUSTOM_TOOL_TASK_LEVEL_NOT_ALLOWED`
      - V2: Custom tool with reserved name (`read_file`) → rejected with `FAIL_CUSTOM_TOOL_NAME_RESERVED`
      - V2: Custom tool name collision across inheritance chain → rejected with `FAIL_CUSTOM_TOOL_NAME_COLLISION`
      - V2: Custom tool schema with `$ref` → rejected with `FAIL_CUSTOM_TOOL_SCHEMA_UNSUPPORTED_FEATURE`
      - V2: Custom tool schema with `oneOf` → rejected with `FAIL_CUSTOM_TOOL_SCHEMA_UNSUPPORTED_FEATURE`
      - V2: Custom tool schema with `additionalProperties: true` at root → rejected with `FAIL_CUSTOM_TOOL_SCHEMA_ADDITIONALPROPERTIES_TRUE`
      - V2: Profile with 26 custom tools → rejected with `FAIL_CUSTOM_TOOL_COUNT_EXCEEDED`
      - V2: Profile schema budget at 12% of context window → `WARN_CUSTOM_TOOL_SCHEMA_BUDGET_HIGH` (or fail under `--strict`)
      - V2: Profile schema budget at 27% of context window → `FAIL_CUSTOM_TOOL_SCHEMA_BUDGET_EXCEEDED`
      - V2: Custom tool with `timeout_seconds` > policy hard cap → rejected with `FAIL_CUSTOM_TOOL_TIMEOUT_EXCEEDS_HARD_CAP`
      - V2: Custom tool with operator `env.RAXIS_TASK_ID = "x"` → rejected with `FAIL_CUSTOM_TOOL_ENV_RESERVED_KEY`
      - V2: Profile inheritance cycle → rejected with `FAIL_PLAN_PROFILE_INHERITANCE_CYCLE`
      - V2: Custom tool exits non-zero → `tool_result.is_error = true`; `CustomToolInvoked.outcome = NonZeroExit`
      - V2: Custom tool exceeds timeout → `cgroup.kill` atomic teardown; outcome `Timeout`
      - V2: Custom tool double-fork daemonization → cgroup.kill catches both processes on timeout
      - V2: Plan with `[plan.tasks.X] role = "Orchestrator"` → rejected with `FAIL_ORCHESTRATOR_TASK_NOT_ALLOWED`
      - V2: Plan with `[profiles.coordinator] role = "Orchestrator"` → rejected with `FAIL_ORCHESTRATOR_PROFILE_NOT_ALLOWED`
      - V2: Plan with `[profiles.coordinator] inherits_from = "Orchestrator"` → rejected with `FAIL_PROFILE_ROLE_NOT_CONFIGURABLE`
      - V2: Profile inheriting from a profile whose root is Orchestrator (transitive) → rejected at the immediate-parent check with `FAIL_PROFILE_ROLE_NOT_CONFIGURABLE`
      - V2: Policy with `[[vm_images]] role_restriction = ["Orchestrator"]` → rejected at policy load with `FAIL_POLICY_INVALID_ROLE_RESTRICTION`
      - V2: Policy with `[orchestrator] provider_alias = "nonexistent"` → rejected at policy load with `FAIL_POLICY_ORCHESTRATOR_PROVIDER_ALIAS_UNRESOLVED`
      - V2: Orchestrator activation with tampered canonical image → aborted with `FAIL_ORCHESTRATOR_IMAGE_DIGEST_MISMATCH` + `SecurityViolationDetected`
      - V2: Initiative admission with valid plan and policy → kernel auto-creates Orchestrator session; no operator-declared profile required
      - V2: `[plan.initiative] description = "<text>"` → rendered into Orchestrator KSB `[KERNEL: INITIATIVE GUIDANCE]` block verbatim
      - V2: `[orchestrator] all_merges_require_approval = true` → every IntegrationMerge attempt requires a paired `EscalationRequest:MergeAuthorization` resolution
      - V2: `[orchestrator] max_token_budget_per_initiative` reached → Orchestrator session pauses with `TokenLimitApproaching` alert
      - V2 Plan Bundle Sealing: round-trip (CLI builds bundle, kernel seals, kernel reads back via `plan_bundle::read_artifact`) yields byte-identical `plan.toml` content
      - V2 Plan Bundle Sealing: plan field referencing `../escape.md` → CLI rejects with `FAIL_PLAN_BUNDLE_PATH_ESCAPE`; no IPC sent
      - V2 Plan Bundle Sealing: plan field referencing a symlink whose target is outside plan root → CLI rejects with `FAIL_PLAN_BUNDLE_PATH_ESCAPE`
      - V2 Plan Bundle Sealing: plan field referencing a symlink whose target is inside plan root → admitted; bundle name is the declared (relative) path, not the symlink target
      - V2 Plan Bundle Sealing: symlink loop → CLI rejects with `FAIL_PLAN_BUNDLE_SYMLINK_LOOP`
      - V2 Plan Bundle Sealing: absolute path field → CLI rejects with `FAIL_PLAN_BUNDLE_ABSOLUTE_PATH`
      - V2 Plan Bundle Sealing: artifact at `max_artifact_bytes + 1` → CLI rejects with `FAIL_PLAN_BUNDLE_ARTIFACT_TOO_LARGE`; no OOM observed
      - V2 Plan Bundle Sealing: bundle exceeding `max_bundle_bytes` → `FAIL_PLAN_BUNDLE_TOO_LARGE`
      - V2 Plan Bundle Sealing: bundle with > `max_artifact_count` artifacts → `FAIL_PLAN_BUNDLE_TOO_MANY_ARTIFACTS`
      - V2 Plan Bundle Sealing: wire `bundle_sha256` mismatched → kernel rejects with `FAIL_PLAN_BUNDLE_SHA256_MISMATCH`; no SQLite write
      - V2 Plan Bundle Sealing: per-artifact `sha256` mismatched → kernel rejects with `FAIL_PLAN_BUNDLE_ARTIFACT_HASH_MISMATCH`
      - V2 Plan Bundle Sealing: tampered first artifact name → `FAIL_PLAN_BUNDLE_FIRST_ARTIFACT_NOT_PLAN_TOML`
      - V2 Plan Bundle Sealing: signature minted by operator A; submission claims operator B → `FAIL_PLAN_SIGNATURE_INVALID`
      - V2 Plan Bundle Sealing: signed by revoked key → `FAIL_KEY_COMPROMISED` (per `key-revocation.md`)
      - V2 Plan Bundle Sealing: V1-shape `CreateInitiative` IPC arrives → rejected at decode (`FAIL_PLAN_BUNDLE_DECODE_FAILED`)
      - V2 Plan Bundle Sealing: after admission, the operator deletes `plan.toml` from disk → `approve_plan` succeeds; KSB rendering succeeds; recovery succeeds; audit reconstruction succeeds (INV-INIT-06 strengthening)
      - V2 Plan Bundle Sealing: two initiatives with byte-identical bundles share a single `plan_bundles` row
      - V2 Plan Bundle Sealing: policy with `max_artifact_bytes = 100 GiB` → policy load fails with `FAIL_POLICY_PLAN_BUNDLE_LIMIT_ABOVE_CEILING`
      - V2 Plan Bundle Sealing: initiative termination → `plan_bundles` and `plan_bundle_artifacts` rows remain (no GC; D8)
      - V2 operator-ergonomics: plan with omitted `vm_image` on Executor task AND `[default_executor_image] alias` set in policy → `submit plan` fails with `FAIL_PLAN_REQUIRES_PREPARE { missing_fields: ["plan.tasks.<id>.vm_image"] }`
      - V2 operator-ergonomics: same plan after `raxis-cli plan prepare` → `submit plan` succeeds; bundle bytes include the defaulted `vm_image` value
      - V2 operator-ergonomics: `[default_executor_image] alias = "missing-image"` (no `[[vm_images]]` entry resolves) → policy load fails with `FAIL_POLICY_DEFAULT_EXECUTOR_IMAGE_UNRESOLVABLE`
      - V2 operator-ergonomics: `[default_executor_image] alias = "x"` where `[[vm_images]] x` has `role_restriction = ["Reviewer"]` → policy load fails with `FAIL_POLICY_DEFAULT_EXECUTOR_IMAGE_UNRESOLVABLE`
      - V2 operator-ergonomics: plan with omitted `[plan.tasks.<id>.token_policy]` for an Executor task AND `[token_policy_defaults.executor]` configured → `plan prepare` fills both fields with annotations; `submit plan` succeeds
      - V2 operator-ergonomics: plan with omitted `[plan.tasks.<id>.token_policy]` for a role with NO `[token_policy_defaults]` configured → `plan prepare` does not fill; `submit plan` proceeds to existing `WARN_UNCAPPED_TOKEN_LIMIT` path
      - V2 operator-ergonomics: `plan prepare` writes `# @raxis-default v0.4.0` annotations; bundle bytes include the annotations verbatim; kernel parser treats them as TOML comments
      - V2 operator-ergonomics: re-running `plan prepare` on a prepared plan with no policy drift → no-op; file unchanged byte-for-byte
      - V2 operator-ergonomics: re-running `plan prepare` on a prepared plan where the policy default changed → `FAIL_PREPARE_DEFAULT_UPGRADE_REQUIRED { fields }`
      - V2 operator-ergonomics: same scenario with `--upgrade-defaults` → `plan prepare` updates values and bumps annotation versions
      - V2 operator-ergonomics: same scenario with `[prepare] auto_upgrade_defaults = true` in policy → silent upgrade
      - V2 operator-ergonomics: `submit plan --dry-run` runs full admission chain; on success, `plan_bundles` table is unchanged
      - V2 operator-ergonomics: `submit plan --dry-run` on a plan that would FAIL admission → returns the FAIL code with `[DRY-RUN]` prefix; no audit event of admission failure
      - V2 operator-ergonomics: `[default_protected_paths]` configured; operator's plan omits `[plan.protected_paths]` → `plan prepare` fills with the policy defaults; resulting plan's effective protected paths = policy defaults
      - V2 operator-ergonomics: same scenario; operator declares `[plan.protected_paths] paths = [...]` with some entries → `plan prepare` produces the union of operator and policy defaults
      - V2 operator-ergonomics: operator wants to remove `.git/` from protected paths; declares `[plan.protected_paths]` excluding it AND passes `--ignore-policy-protected-paths` → `plan prepare` honors the operator's narrower set
      - V2 operator-ergonomics: `OperatorRequest::ProposeDefaults` does NOT insert any row into `kernel.db` (read-only invariant)
      - V2 operator-ergonomics: `initiative resume` on an `Executing` initiative → `FAIL_INITIATIVE_NOT_PAUSED { state: "Executing" }`
      - V2 operator-ergonomics: `setup wizard` end-to-end against a fresh install completes in under 5 minutes including smoke-test
      - V2 operator-ergonomics: tampered `raxis-executor-starter` image detected at `raxis doctor canonical-images` → `FAIL_DEFAULT_EXECUTOR_IMAGE_DIGEST_MISMATCH`
      - V2 environment-binding: policy with zero `[environments.<label>]` declared → step 3.5 no-op; every admitted task records as Neutral by trivial cardinality
      - V2 environment-binding: policy with one `[environments.beta]` declared; plan task with `[[plan.tasks.credentials]] name = "registry-beta-read"` (env: "beta") → admitted as Bound("beta")
      - V2 environment-binding: policy with `[environments.beta]` and `[environments.production]`; plan task with both env-bound credentials → `FAIL_TASK_ENVIRONMENT_INCONSISTENT { task, environments: ["beta", "production"], sources: [...] }`
      - V2 environment-binding: same scenario with `--no-strict` → still fails (structural per INV-ENV-01)
      - V2 environment-binding: plan task with one env-bound credential and one neutral credential (no `environment` field on its `[[permitted_credentials]]` entry) → admitted as Bound(env); neutral credential contributes nothing
      - V2 environment-binding: cross-env DAG split per `environment-access-control.md §11.5` (fetch_from_beta → publish_to_prod) → both tasks admitted; bindings recorded as Bound("beta") and Bound("production"); audit chain shows both
      - V2 environment-binding: same-cluster (two `[[environment_gates]]` sharing hostname); neither env declares `same_cluster_acknowledged = true` → `FAIL_SAME_CLUSTER_NAMESPACE_ISOLATION`
      - V2 environment-binding: same-cluster, only one env declares `same_cluster_acknowledged = true` → still fails; FAIL message lists the unacknowledged env(s)
      - V2 environment-binding: same-cluster, all conflated envs declare `same_cluster_acknowledged = true` → URL contributes 0 labels; task binding determined by credentials alone
      - V2 environment-binding: `[[environment_gates]] label = "produciton"` (typo) and no `[environments.produciton]` declared → policy load fails with `FAIL_POLICY_ENV_LABEL_UNDECLARED`
      - V2 environment-binding: `[environments.beta] blast_radius = "high"` (reserved-for-V2.x) → policy loads with `WARN_ENVIRONMENT_RESERVED_FIELD_SET`; field has no kernel-side effect
      - V2 environment-binding: `[environments.beta] frobnitz = "x"` (unknown-not-reserved) → `FAIL_POLICY_ENV_UNKNOWN_FIELD`
      - V2 environment-binding: `[environments.Beta]` (uppercase) → `FAIL_POLICY_ENV_LABEL_INVALID`
      - V2 environment-binding: Reviewer task → step 3.5 records Neutral; INV-ENV-01 trivially passes (cardinality 0 by structural prohibition per `environment-access-control.md §11.6`)
      - V2 environment-binding: Orchestrator tasks (auto-created per `INV-PLANNER-HARNESS-06`) record Neutral; never bind to any environment
      - V2 environment-binding: `InitiativeCreated` audit event includes `task_environment_bindings: [...]` for every admitted task per `environment-access-control.md §11.9`
      - V2 provider-model-selection: policy with `[provider_aliases_defaults.reviewer] chain = ["unpermitted:model"]` → policy load fails with `FAIL_POLICY_PROVIDER_ALIAS_DEFAULT_REFERENCES_NONPERMITTED_MODEL`
      - V2 provider-model-selection: policy default chain references `"google:gemini-2.5-pro"` but no `[[providers.credentials]] provider_id = "google"` → `FAIL_POLICY_PROVIDER_ALIAS_DEFAULT_MISSING_CREDENTIAL`
      - V2 provider-model-selection: `[provider_aliases_defaults.reviewer] chain = []` → `FAIL_POLICY_PROVIDER_ALIAS_DEFAULT_EMPTY_CHAIN`
      - V2 provider-model-selection: `[provider_aliases_defaults.summarizer] chain = [...]` (unknown role) → `WARN_PROVIDER_ALIAS_DEFAULT_UNKNOWN_ROLE`; policy still loads
      - V2 provider-model-selection: two-provider deployment with single-element default chain → `WARN_PROVIDER_ALIAS_PRIMARY_NO_FAILOVER`
      - V2 provider-model-selection: V1 policy with `[orchestrator] provider_alias = "fast_low_cost"` → loads with `WARN_ORCHESTRATOR_DEFAULT_ALIAS_RENAMED`
      - V2 provider-model-selection: plan with no `[provider_aliases.reviewer]` → `plan prepare` fills it from policy default; bundle bytes include the filled chain with `# @raxis-default v0.4.0` annotations
      - V2 provider-model-selection: re-running `plan prepare` on an already-prepared plan with unchanged policy default → no-op (idempotency)
      - V2 provider-model-selection: bumping `[provider_aliases_defaults.reviewer] chain` in policy → re-running `plan prepare` on previously-prepared plan → `FAIL_PREPARE_DEFAULT_UPGRADE_REQUIRED { fields: ["provider_aliases.reviewer.chain"] }`
      - V2 provider-model-selection: profile declares `provider_alias = "frontend_dev"` → `plan prepare` does NOT fill `[provider_aliases.executor]` for tasks using that profile
      - V2 provider-model-selection: `setup wizard` with single Anthropic key → generated chains match `provider-model-selection.md §4.1` exactly
      - V2 provider-model-selection: `setup wizard` with two providers → cross-role diversification per §4.2; Reviewer primary on the SECOND provider
      - V2 provider-model-selection: `setup wizard --no-diversify` with two providers → all primaries on the FIRST provider
      - V2 provider-model-selection: `setup wizard --add-provider openai` on existing single-Anthropic deployment → chains regenerate to two-provider layout

---

## 7. Tensions Identified During Design

Before arriving at INV-POLICY-01, the following specific conflict scenarios were analyzed.
Each reveals a case where `policy.toml` and `plan.toml` can disagree, and where the
resolution must be unambiguous.

### Tension 1 — Push Approval Mandate

**Scenario:** The deployment policy mandates push approval for all initiatives
(`require_push_approval_minimum = true`), but an operator writes a plan with
`require_push_approval = false` (or simply omits the field, accepting the default).

**What happens without a rule:** The plan's `false` silently overrides the policy
mandate. Push happens automatically. The compliance requirement is invisible — no error,
no warning.

**Resolution:** Protection dimension → UNION. Policy's `true` floor is always enforced.
Plan's `false` triggers `WARN_PUSH_APPROVAL_DOWNGRADED`. Operator is informed; initiative
still runs with push approval enforced.

---

### Tension 2 — Duplicate Protected Paths

**Scenario:** Policy protects `src/payments/`. An operator writes a plan with
`[[integration_merge_gates]] { path_prefix = "src/payments/", require_approval = true }`.
The plan is adding what the policy already requires.

**What happens without a rule:** UNION dedupes cleanly. No double escalation. The entry
is redundant but harmless.

**Resolution:** `WARN_INTEGRATION_MERGE_GATE_REDUNDANT`. The plan is approved; the
operator is told the entry is redundant and can be cleaned up. No behavioral change.

---

### Tension 3 — Plan Attempts to Remove a Policy Protection

**Scenario:** Policy protects `src/payments/`. An operator writes a plan with
`[[integration_merge_gates]] { path_prefix = "src/payments/", require_approval = false }`.
The intent (possibly accidental) is to declare "no gate needed for this path."

**What happens without a rule:** With a naive UNION, `false` entries are ignored —
the policy protection stands. But silently. The operator doesn't know their entry was
overridden.

**Resolution:** `WARN_PROTECTION_OVERRIDDEN`. The plan is approved; the operator is
explicitly told that the policy-level protection is enforced regardless of the plan field.
With `--strict`: plan rejected. This catches operators who genuinely believe they've
disabled the gate when they haven't.

---

### Tension 4 — Egress Method Expansion

**Scenario:** Policy permits `api.github.com GET` only. An operator writes a plan with
`allowed_egress = [{ url_prefix = "https://api.github.com/", methods = ["GET", "POST"] }]`.
The plan requests a method the policy does not permit.

**What happens without a rule:** At `EgressRequest` admission, the Kernel enforces
policy's `GET` ceiling. A `POST` request fails at runtime with `FAIL_EGRESS_METHOD_NOT_PERMITTED`.
The operator doesn't know the plan was over-specified until a task fails mid-run.

**Resolution:** Permission dimension → INTERSECTION. Detected at `approve_plan` shift-left
as `WARN_EGRESS_METHOD_RESTRICTED`. Operator is informed before any VM boots: "your task
declared POST but the Kernel will only permit GET." With `--strict`: plan rejected.

---

### Tension 5 — Two-Operator Model (Infra vs. Dev)

**Scenario:** In a larger organization, `policy.toml` is written and signed by the
infrastructure/security team (platform operator), while `plan.toml` is written and signed
by the engineer running the initiative (task operator). These are different people with
different keys and different intentions.

**Why this creates risk:** The task operator may write a plan that disagrees with
platform policy — not maliciously, but because they don't know the full policy
configuration. Or because the policy changed since they last looked.

**Resolution:** INV-POLICY-01 makes the platform operator (policy) always win on
protection dimensions. The task operator can only add gates; they cannot remove the
platform operator's gates. The warning system makes divergences visible — the task
operator sees exactly where their plan conflicts with platform policy before the initiative
runs.

This also means the `--strict` flag is useful as a platform-enforced default
(`policy.approve_policy.approve_plan_strict_by_default = true`) — the infra team can
require that all plan submissions in their deployment must resolve all policy-plan
conflicts before proceeding.

---

## 8. Approaches Considered and Rejected

### Approach B — Strict Separation (Policy and Plan Cover Distinct Fields)

**Description:** Policy and plan cover entirely different configuration fields. Any
field that appears in policy cannot appear in plan. No overlap, no ambiguity.

**Why rejected:** Eliminates per-initiative flexibility that is both legitimate and
necessary. Egress allowlists, protected path gates, and push approval requirements are
all things operators need to configure differently per initiative. Moving all of this to
the policy level means the ops/infra team must be involved in every initiative — which
destroys the operational model. Additionally, it makes the policy file enormous and hard
to reason about: it would need to enumerate every possible initiative's configuration.

---

### Approach C — Explicit Override Flags (`operator_overridable = true | false`)

**Description:** Each policy section declares whether it can be overridden by the plan.
If `operator_overridable = true`, the plan can set the field. If `false`, the plan cannot
touch it at all.

**Why rejected:** Introduces a new meta-concept (overridability) into the policy schema
that itself requires specification, tooling, and testing. The complexity of specifying
what "override" means for each section (full replacement? additive? UNION? INTERSECTION?)
replicates the same design problem one level up. Additionally, it requires the plan
parser to check the policy's overridability declarations before accepting plan fields —
a tight coupling between policy parsing and plan parsing that complicates both.

The implicit model of INV-POLICY-01 (protection = UNION, permission = INTERSECTION) is
simpler to implement and reason about than explicit overridability flags.

---

### Approach D — Signing Authority Hierarchy (Two Key Types)

**Description:** `policy.toml` is signed by a platform key (HSM-held, infra team).
`plan.toml` is signed by an initiative key (individual operator). When both keys are
valid but the documents conflict, the platform key (policy) wins.

**Why rejected:** Introduces real key management complexity. Two operator key types means
two key issuance procedures, two revocation procedures, two audit trails for key usage.
An operator who writes both `policy.toml` and `plan.toml` (common in small deployments)
must manage two separate keys — significant operational overhead for no additional
security benefit.

More fundamentally: the signing hierarchy doesn't resolve the _semantic_ conflict — it
only declares which document wins. INV-POLICY-01 already declares that policy wins.
The key hierarchy adds mechanism without adding clarity.

**Note:** A future version of RAXIS that supports multi-tenant deployments — where a
platform operator and tenant operators are genuinely different organizations — may need
to revisit this. In that context, key separation between platform and tenant is a
meaningful security property, not just operational overhead.

---

### The Silent Downgrade (Rejected in Favor of Warning System)

**Description:** When a plan field conflicts with policy (e.g., `require_push_approval = false`
against a policy that mandates push approval), silently upgrade the plan field to match
policy and proceed without any notification to the operator.

**Why rejected:** Silent downgrades hide real mistakes. An operator who set
`require_push_approval = false` believing it would take effect will be surprised when
their initiative requires push approval. Worse: they may believe the push gate was
working as they intended and not investigate when push approval fires. The warning system
makes the Kernel's actual behavior transparent: the operator knows what they configured,
what the Kernel will do instead, and why.

**Why the warning + strict-by-default is correct:**
A hard `FAIL_*` error and a warning-with-strict-default produce the same outcome in
practice: the plan is rejected unless the operator explicitly acknowledges the divergence.
The difference is in the error message: `FAIL_*` gives a binary "wrong or right" signal;
the warning system gives a precise "what you said vs. what the Kernel will do" explanation.
The warning form is more actionable — it tells the operator exactly how to fix the plan.
Strict mode as default means no plan silently diverges from policy in production.
`--no-strict` is an explicit, audited opt-out.

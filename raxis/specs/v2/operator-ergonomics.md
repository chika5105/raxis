# Operator Ergonomics — V2

> **Status.** Normative for V2.
> **Cross-references:**
> - [`plan-bundle-sealing.md`](plan-bundle-sealing.md) (atomic sign+submit; bundle bytes are post-prepare bytes)
> - [`planner-harness.md §10.6`](planner-harness.md) (canonical Executor starter image; the defaulting target)
> - [`policy-plan-authority.md`](policy-plan-authority.md) ([token_policy_defaults], [default_protected_paths], [default_executor_image], [prepare] policy sections; FAIL_PLAN_REQUIRES_PREPARE)
> - [`custom-tools.md`](custom-tools.md) (custom-tool defaulting is out of scope — operators declare their own custom tools explicitly)
> - [`system-requirements.md`](system-requirements.md) (raxis-executor-starter image is a bundled artifact)
> - `v1/cli-ceremony.md` (V1 CLI surface; operator-ergonomics.md is the V2 supersession for the authoring lifecycle)

---

## §1 — Why this spec

### 1.1 The problem

A new operator standing up RAXIS for the first time hits friction the moment they author a plan:

- They must declare a `vm_image` for every Executor task, but they don't yet have a custom image to pin.
- They must declare `[plan.tasks.<id>.token_policy]` to avoid `WARN_UNCAPPED_TOKEN_LIMIT`, but they don't yet know what budgets are reasonable.
- They must enumerate `protected_paths`, but they haven't yet thought through which paths are sensitive in their repo.
- They must construct a profile graph, declare per-task acceptance criteria, configure the Reviewer's symbol-index plumbing, and so on.

Each of these is a defensible field on its own. Together they create a 100-line plan.toml the new operator must author from scratch before they can run a single initiative. The result is a steep on-ramp that filters out exactly the operators we want — small teams, individual developers, and evaluators trying out the system.

### 1.2 The fix: defaults you opt into

V2 introduces a **deliberate defaulting layer**. The kernel ships with sensible defaults for the most ergonomically-painful fields. The CLI provides a `plan prepare` command that fills the operator's omitted fields with the policy-resolved defaults, writing the augmented plan back to disk for operator review. The operator then signs and submits the augmented plan via the normal Plan Bundle Sealing flow.

This is **opt-in defaulting**: the operator omits a field; `plan prepare` proposes a default; the operator reviews, accepts (by signing), or overrides. At no point does the kernel admit a plan whose bytes the operator did not consciously authorize.

The 10-minute new-operator path looks like:

```bash
$ raxis-cli setup wizard          # generates keys, minimum policy, smoke-tests kernel
$ raxis-cli plan init -t feature  # scaffolds plan.toml with sensible structure
$ vim plan.toml                   # operator edits to describe their work
$ raxis-cli plan prepare plan.toml      # CLI fills in defaults; writes back to disk
$ raxis-cli plan explain plan.toml      # human-readable summary of what will happen
$ raxis-cli submit plan plan.toml --operator-key ~/raxis/op.key   # atomic sign + submit
```

### 1.3 The boundary trade-off (acknowledged explicitly)

Defaults invert a small slice of the boundary we hardened in [`custom-tools.md`](custom-tools.md) and [`plan-bundle-sealing.md`](plan-bundle-sealing.md). "Everything inside the operator's VM image is the operator's responsibility" gets a footnote: *unless the operator opts into the kernel-canonical Executor starter image, in which case the kernel co-owns the bytes inside it.* "The operator signs every byte the kernel admits" remains literally true (the operator signs the prepared plan), but the operator's review workload includes "did I read the defaults the CLI wrote in?" alongside "did I read what I typed?"

We accept this trade because:

1. The **structural authority chain is preserved**. The kernel never sees a "raw operator plan" and a "defaulted plan" — it sees one signed bundle. From the kernel's perspective there is no concept of "defaulted vs operator-typed"; the operator signed the bytes, and that's the only thing the kernel attests to. The annotation comments `plan prepare` writes are pure operator-side metadata for CLI re-run idempotency and human-readable diff; the kernel does not parse them, does not store them specially, and does not surface them in audit events.
2. The **defaults are surface-area-bounded**. Each defaultable field is enumerated in §4.2 of this spec; adding a new defaultable field is a deliberate spec change, not a one-line CLI patch. Operators can audit the entire defaulting surface from one document.
3. The **opt-out path is always available**. Every default the CLI writes is a value the operator can edit before signing. Production deployments that want zero kernel-side tooling assumptions pin their own VM images, declare their own token budgets, and treat `plan prepare` as a no-op.

If you want zero defaulting, write a fully-explicit plan and skip `plan prepare`. Submission will succeed exactly as it does without this spec. The defaulting layer is purely additive.

---

## §2 — Scope and Non-Scope

### In scope

- The default-resolution model: what fields are defaultable, how defaults are resolved against the loaded policy, the operator-signs-everything posture, the annotation-as-operator-metadata convention (§3, §4).
- The `raxis-cli plan prepare` command: the canonical pre-submit step that fills defaults into the operator's plan.toml (§5).
- The full V2 operator CLI surface: `plan init`, `plan validate`, `plan diff`, `plan explain`, `plan fmt`, `plan cost-estimate`, `submit plan --dry-run`, `initiative watch`, `initiative resume`, `setup wizard`, `doctor` extensions (§6 – §17). **Note:** `initiative list` is an exception — its v1 baseline already ships in `cli-readonly.md §5.5.6b`; §15 below documents only the v2 *extensions* on top of that baseline.
- Policy schema additions: `[token_policy_defaults]`, `[default_protected_paths]`, `[default_executor_image]`, `[prepare]` (§18).
- IPC schema additions: read-only `ProposeDefaults` operator-socket request, `DryRunAdmit`, etc. (§19).
- Failure codes: `FAIL_PLAN_REQUIRES_PREPARE`, `FAIL_PREPARE_DEFAULT_UPGRADE_REQUIRED`, `FAIL_PLAN_INIT_TEMPLATE_NOT_FOUND` (§20).

### Out of scope (explicit)

- **Custom-tool defaulting.** Custom tools are operator-specific by definition; the kernel cannot default what scripts an operator wants to expose. `plan prepare` does not invent custom tools; it preserves the operator's `[[profiles.<name>.custom_tool]]` declarations verbatim. This is per [`custom-tools.md`](custom-tools.md) §3.
- **Per-environment defaulting.** Environment-specific defaults (e.g., "all production tasks default to `require_review_signoff = true`") will land alongside the per-environment policy knobs reserved in [`environment-access-control.md`](environment-access-control.md) follow-on work; V2 ergonomics does not anticipate the schema for this.
- **Multi-operator approval workflows for the prepared plan.** The prepared plan is signed by a single operator. Two-party approval flows (operator A prepares, operator B signs) are deferred to V3.
- **Default Reviewer or Orchestrator configuration.** Reviewer and Orchestrator are kernel-canonical roles per `INV-PLANNER-HARNESS-02` and `INV-PLANNER-HARNESS-06`. They have no defaultable surface — the kernel manages them entirely. `plan prepare` never writes Reviewer or Orchestrator defaults into the operator's plan.

---

## §3 — Foundational Decisions

The decisions below are normative. Section labels (D1–D9) preserve cross-reference labels used during design discussion.

| # | Decision | Rationale |
|---|----------|-----------|
| **D1** | **The kernel ships an opt-in canonical Executor starter image.** `raxis-executor-starter` is a kernel-bundled image with general dev tooling (Node, Python, Rust, Go, common Unix). It is **opt-in**: an operator's task that omits `vm_image` gets this image filled in by `plan prepare`. Operators in production typically pin their own digest-pinned image and never use the starter. Manifest: [`planner-harness.md §10.6`](planner-harness.md). | Eliminates the "I don't have an image yet" blocker for new operators while preserving the operator-pins-their-own-image path for production deployments. The starter image is parallel to the kernel-canonical Reviewer (`INV-PLANNER-HARNESS-02`) and Orchestrator (`INV-PLANNER-HARNESS-05`) images, but unlike them it is **not** a structural requirement — operators can ignore it entirely. |
| **D2** | **`raxis-cli plan prepare` is the canonical pre-submit step.** It reads the operator's plan, computes policy-resolved defaults via a read-only kernel IPC, writes the augmented plan back to disk in place, and exits. The operator reviews the augmented file, then signs and submits via `raxis-cli submit plan`. | Puts the operator squarely in the loop: defaults are visible before signing, never silently inserted at submission time. The kernel is consulted for policy-resolved defaults (so deployments with different policies get different defaults from the same raw plan), but performs no state-mutating work. |
| **D3** | **`raxis-cli submit plan` fails loud on missing required-but-defaultable fields.** A plan that omits a defaultable field and is submitted **without** running `plan prepare` first is rejected at admission with `FAIL_PLAN_REQUIRES_PREPARE { missing_fields: [...] }`. The CLI does NOT silently auto-default during submit. | Authority chain integrity. The operator must consciously accept defaults by running `plan prepare` and signing the result. Auto-defaulting at submission would mean the operator signed a plan they did not see in its post-default form. |
| **D4** | **The kernel has no concept of "defaulted vs operator-typed".** `plan prepare` writes `# @raxis-default v0.4.0` annotation comments next to defaulted fields as a courtesy for the operator (CLI re-run idempotency, human-readable diff). The kernel does NOT parse these annotations, does NOT store them specially, and does NOT surface them in audit events. From the kernel's perspective the operator signed the bytes; everything else is operator-side metadata. | The signed bundle is the audit-of-record; the bundle is bytes; bytes are bytes. Treating annotations as kernel-attested would invent a phantom authority distinction the audit chain cannot enforce. The operator's signature attests to the entire prepared plan, defaults included. |
| **D5** | **`plan prepare` is read-only on the kernel.** The corresponding IPC request `OperatorRequest::ProposeDefaults { plan_bytes }` does NOT create an initiative, reserve budget, or write to the kernel store. It returns the proposed augmented plan bytes for the CLI to write to disk. | A planning-time computation must not have admission-time side effects. Operators iterate on `plan prepare` freely without touching kernel state. |
| **D6** | **Defaulting is policy-driven, not CLI-hardcoded.** Every defaultable value comes from `policy.toml` (the canonical Executor image alias, the default token budgets, the default protected paths, the default acceptance criteria, etc.). The CLI carries zero hardcoded defaults; it only knows how to ask the kernel what the policy says. | The same raw plan submitted against deployment A and deployment B will produce different prepared plans if the deployments have different policies. Defaults are a **deployment** characteristic, not a **CLI** characteristic. |
| **D7** | **Idempotency under default upgrades is opt-in.** When `raxis` upgrades from v0.4.0 to v0.5.0 and a default value changes, re-running `plan prepare` on a previously-prepared plan does NOT silently update the value. It rejects with `FAIL_PREPARE_DEFAULT_UPGRADE_REQUIRED` and requires `plan prepare --upgrade-defaults` to acknowledge the change. The annotation `# @raxis-default v0.4.0` is the version stamp the CLI compares against. A `[prepare] auto_upgrade_defaults = true` policy knob exists as a dev-mode escape hatch. | Production operators must explicitly acknowledge default-value drift; their signed plan is otherwise stable across CLI upgrades. Dev environments that want frictionless upgrades opt in via policy. |
| **D8** | **Setting up a fresh deployment is a one-command path.** `raxis-cli setup wizard` is the canonical first-run experience: generates the operator keypair, walks the operator through a minimum-viable `policy.toml`, configures provider credentials, smoke-tests the kernel, and submits a "hello world" initiative. Zero hand-editing of TOML required to reach a working RAXIS install. | The 10-minute target. Without this, operators read three specs before producing their first signed plan. |
| **D9** | **CLI templates are CLI-shipped, not kernel-shipped.** `plan init -t <template>` reads templates from CLI-bundled assets, NOT from a kernel artifact. New templates ship with new CLI releases independent of kernel releases. | Keeps the kernel's responsibility surface minimal. Templates are authoring conveniences; the kernel admits the prepared bytes whether they came from a template or not. |

---

## §4 — Default-Resolution Model

### 4.1 The pipeline

```text
operator-authored plan.toml
            |
            v
[1] CLI reads plan.toml, parses TOML, retains comments.
            |
            v
[2] CLI opens operator socket; sends OperatorRequest::ProposeDefaults
    { plan_bytes, current_cli_version }.
            |
            v
[3] Kernel loads current policy; for each defaultable field in the
    parsed plan that the operator omitted, the kernel resolves the
    default value from policy. Returns OperatorResponse::DefaultsProposed
    { augmented_plan_bytes, defaulted_fields: [...] }.
            |
            v
[4] CLI writes augmented_plan_bytes back to plan.toml (in place,
    preserving operator comments outside the defaulted regions).
    Each defaulted field gets a trailing `# @raxis-default v<cli_version>`
    annotation comment.
            |
            v
[5] CLI exits. Operator reviews plan.toml, edits if desired, then
    runs `submit plan` per plan-bundle-sealing.md §4.
```

The kernel never writes to the host filesystem during this flow. The CLI is the only filesystem mutator. The kernel is a pure function: `(plan_bytes, policy) → augmented_plan_bytes`.

### 4.2 The defaultable field set (V2)

This is the **complete** list of fields `plan prepare` will fill in. Adding a field to this list is a deliberate spec amendment; field additions in future RAXIS releases ship in clearly-numbered annotation versions so operators can diff "what defaults did v0.5.0 add that v0.4.0 didn't?"

| Path in `plan.toml` | Default source | Default value (V2) |
|---|---|---|
| `[plan.tasks.<id>] vm_image` (Executor tasks only) | `policy.toml [default_executor_image] alias` | The OCI digest of the policy-pinned canonical Executor starter image alias (typically `raxis-executor-starter@sha256:...`). |
| `[plan.tasks.<id>] token_policy.input_tokens_per_session` | `policy.toml [token_policy_defaults.<role>] input_tokens_per_session` | Per-role default; e.g., 500_000 for Executor, 200_000 for Reviewer. |
| `[plan.tasks.<id>] token_policy.output_tokens_per_session` | `policy.toml [token_policy_defaults.<role>] output_tokens_per_session` | Per-role default; e.g., 50_000 for Executor, 20_000 for Reviewer. |
| `[provider_aliases.reviewer]` | `policy.toml [provider_aliases_defaults.reviewer]` | The role-canonical Reviewer alias chain. Filled when the operator's plan does not declare `[provider_aliases.reviewer]` AND policy declares `[provider_aliases_defaults.reviewer]`. Default chain shipped by `setup wizard` per [`provider-model-selection.md §4`](provider-model-selection.md). |
| `[provider_aliases.executor]` | `policy.toml [provider_aliases_defaults.executor]` | The role-canonical Executor alias chain. Same conditions as `reviewer`. Tasks whose profile declares its own `provider_alias` continue to use the profile-named alias and are unaffected by this default (per [`provider-model-selection.md §7.4`](provider-model-selection.md)). |
| `[plan.tasks.<id>] acceptance_criteria` | hardcoded enum | `"all_verifiers_pass"` if the task declares ≥ 1 verifier; `"manual_completion"` if it declares zero verifiers. |
| `[plan.protected_paths]` (initiative-level) | `policy.toml [default_protected_paths] paths` | Union of operator-declared paths and policy-declared defaults (e.g., `.git/`, `.raxis/`, `node_modules/`, lockfiles, `.env*`). |
| `[plan.tasks.<id>] allowed_egress` | hardcoded | `[]` (empty allowlist; operators must explicitly add hosts; egress is **never** defaulted permissive). |
| `[[plan.tasks.<id>.verifiers]]` symbol-index entry (Executor tasks only) | hardcoded structural injection — see "Symbol-index auto-injection" below | `name = "symbol_index"`, `image = "raxis-verifier-symbol-index"`, `command = "/usr/local/bin/raxis-symbol-index --workspace /workspace --out /raxis/symbol_index.json"`, `timeout = "60s"`, `on_failure = "warn_only"`, `artifact = "/raxis/symbol_index.json"`. Auto-injected into **every** Executor task whose touched paths include source files when `policy.toml [prepare] auto_inject_symbol_index = true` (default per [`policy-plan-authority.md §4 [prepare]`](policy-plan-authority.md)) AND the task does not declare `[plan.tasks.<id>.review] symbol_index = "not_needed"`. The injected entry carries an extended annotation: `# @raxis-default v0.4.0 symbol-index-auto-inject` so operators can grep specifically for this auto-inject case. Removing the annotation locks the operator into the verifier explicitly; deleting the verifier entirely re-triggers auto-injection on next `plan prepare` unless the operator silences it via the `symbol_index = "not_needed"` knob. |
| `[[plan.tasks.<id>.verifiers]] image` shortcut resolution | `policy.toml [default_verifier_images].<lang>` | When a verifier declares `image = "@<language>"` (e.g., `image = "@rust"`), `plan prepare` substitutes the alias from `[default_verifier_images].<lang>`. The substitution writes the resolved alias verbatim into the file, with annotation `# @raxis-default v0.4.0 image-shortcut-resolved`. Operators wanting to lock the resolved alias permanently delete the annotation; subsequent runs leave the literal alias in place. Subject to the same drift logic as other annotated defaults per §4.4. |
| `[[plan.integration_merge_verifiers]] image` shortcut resolution | `policy.toml [default_verifier_images].<lang>` | Same `@<language>` shortcut mechanism as per-task verifiers above; also resolved by `plan prepare` against `[default_verifier_images]`. |

**Symbol-index auto-injection — design rationale.** The Pure-Static
Reviewer is structurally dependent on a symbol-index witness (per
[`planner-harness.md §4.1`](planner-harness.md) — `WARN_REVIEWER_MISSING_SYMBOL_INDEX`).
Before this V2 amendment, every operator had to *remember* to declare
a `symbol_index` verifier in every Executor task; the warning fired
silently otherwise. Auto-injection inverts the default: by writing
the verifier into the plan automatically (with a clear annotation),
the operator's signed plan is structurally complete by default.
Operators retain full control:
- **Per-task suppression:** declare `[plan.tasks.<id>.review] symbol_index = "not_needed"` (existing knob from [`planner-harness.md §4.1`](planner-harness.md)); `plan prepare` honors it and skips injection for that task.
- **Per-task override:** declare a `symbol_index` verifier explicitly with custom `image`/`command`; `plan prepare` honors the existing entry and skips auto-injection.
- **Deployment-wide opt-out:** set `policy.toml [prepare] auto_inject_symbol_index = false`; `plan prepare` skips injection globally and `WARN_REVIEWER_MISSING_SYMBOL_INDEX` reverts to its V1 behavior of silent warning per Reviewer activation.

The `@language` shortcut surface (rows above) is a pure
operator-ergonomics convenience: instead of writing
`image = "raxis-verifier-rust-starter"` (a 28-character alias the
operator must remember and that varies across deployments with
`[default_verifier_images]` overrides), the operator writes
`image = "@rust"` (5 characters, language-only). `plan prepare`
expands the shortcut against the deployment's policy, so the signed
plan still contains the full alias — the kernel never sees the
shortcut, preserving the existing signed-plan-is-complete invariant.

Fields explicitly **NOT** defaulted in V2:

- `[plan.tasks.<id>] role` — operator must declare; we don't infer roles.
- `[plan.tasks.<id>] description` — operator-authored; cannot be guessed.
- `[plan.tasks.<id>] depends_on` — DAG topology is operator intent.
- `[plan.tasks.<id>] credentials` — credential bindings are environment-specific; defaulting them risks inadvertent over-privileging.
- `[plan.tasks.<id>] verifiers` — verifier scripts are operator-specific.
- `[plan.tasks.<id>.review]` — Reviewer configuration; operator decides whether their task needs review.
- `[[profiles.<name>.custom_tool]]` — custom tools are operator-specific by definition.
- `[plan.initiative] description` — operator-authored.

### 4.3 The annotation format

When `plan prepare` writes a defaulted value, it appends a trailing comment on the same line:

```toml
[plan.tasks.implement_feature]
role     = "Executor"
vm_image = "raxis-executor-starter@sha256:abcd1234..."   # @raxis-default v0.4.0

[plan.tasks.implement_feature.token_policy]
input_tokens_per_session  = 500000      # @raxis-default v0.4.0
output_tokens_per_session = 50000       # @raxis-default v0.4.0
```

The annotation `# @raxis-default v<X.Y.Z>` serves four operator-side purposes:

1. **Human signal:** the operator immediately sees "this wasn't my explicit choice."
2. **Idempotency marker:** re-running `plan prepare` reads the marker; if the policy default has not changed since `vX.Y.Z`, the field is left untouched; if it has changed, prepare requires `--upgrade-defaults`.
3. **Authoring discipline:** when the operator wants to lock the current value permanently (so future `plan prepare` runs don't touch it), they delete the annotation. The value becomes operator-owned.
4. **Diff readability:** when an operator reviews their CI diff after a `plan prepare` run, they can immediately scan for "what did the CLI fill in?" by grepping for `@raxis-default`.

The annotation is **not parsed by the kernel**. It is stripped from no byte stream — it is part of the signed plan.toml content because comments are bytes — but the kernel's plan parser treats it as a TOML comment and ignores it. The annotation has zero authority semantics; it is operator-side metadata that happens to live inside a signed file. From the kernel's perspective, the operator signed a `plan.toml` with comments in it, the same way they would have signed any plan with comments.

### 4.4 The version stamp semantics

The `vX.Y.Z` in the annotation is the CLI version that wrote the annotation. The kernel never validates it. The CLI uses it during `plan prepare` re-runs:

```text
For each annotated field in the parsed plan:
  let stamped_version = parse "@raxis-default vX.Y.Z" comment
  let current_default = kernel.resolve_default(field_path, current_policy)
  let stamped_default = field's current value
  if stamped_default == current_default:
    leave alone (no-op)
  elif stamped_default != current_default and not --upgrade-defaults:
    FAIL_PREPARE_DEFAULT_UPGRADE_REQUIRED { field, stamped_version, current_version, stamped_value, proposed_value }
  elif stamped_default != current_default and --upgrade-defaults:
    update value to current_default; bump annotation version stamp
```

Operators see a clean diff in their version control: `vm_image` digest changed from `sha256:abcd...` to `sha256:efgh...`, annotation bumped from `v0.4.0` to `v0.5.0`. They consciously accept the upgrade by re-signing.

---

## §4.5 — Explicit-Required Fields (V2)

A second class of fields exists alongside the §4.2 defaultable set:
**explicit-required fields** — fields where the operator MUST author the
value themselves and the kernel cannot pick a safe default for them. These
fields use a different annotation namespace (`# @raxis-explicit`) and a
different `plan prepare` UX (template insertion instead of value
substitution).

The driving distinction:

| Property | Defaultable (§4.2) | Explicit-required (§4.5) |
|---|---|---|
| Safe kernel-side default exists? | Yes | No |
| `plan prepare` writes a value? | Yes (with `# @raxis-default vX.Y.Z`) | No (writes a commented-out template with `# @raxis-required`) |
| `submit plan` allows omission? | Allows when policy declares the default; else `FAIL_PLAN_REQUIRES_PREPARE` | Always rejects with the spec-side `FAIL_PLAN_REQUIRES_EXPLICIT_*` |
| Annotation namespace | `# @raxis-default` (kernel suggested, operator co-signs) | `# @raxis-required` (template marker) and `# @raxis-explicit <reason>` (operator acknowledges a structural opt-in) |
| Idempotency on re-run | Drift detection per §4.4 | Template re-insertion is a no-op when the template marker is present and the field is uncommented |

The V2 explicit-required fields are listed in §4.5.1.

### 4.5.1 The explicit-required field set (V2)

| Path in `plan.toml` | Applies to | Acknowledgement annotation when intentionally empty | Canonical home of the FAIL |
|---|---|---|---|
| `[plan.tasks.<id>] path_allowlist` (Executor tasks; absent field) | Executor (and any non-Reviewer, non-Orchestrator role) | n/a — absent field is `FAIL_PLAN_REQUIRES_EXPLICIT_PATH_ALLOWLIST` regardless of annotation | [`policy-plan-authority.md §3b FAIL_PLAN_REQUIRES_EXPLICIT_PATH_ALLOWLIST`](policy-plan-authority.md) |
| `[plan.tasks.<id>] path_allowlist = []` (Executor tasks; literal empty) | Executor | `# @raxis-explicit no-write-acknowledged` on the empty-array line OR the comment line immediately above it | [`policy-plan-authority.md §3b FAIL_EXECUTOR_EMPTY_PATH_ALLOWLIST_UNACKNOWLEDGED`](policy-plan-authority.md) |

Future V2.x additions to this table follow the same pattern: a structural
constraint that has no safe default, an acknowledgement annotation when an
edge-case "yes really, this is intentional" value is the operator's choice.

### 4.5.2 Why `path_allowlist` is explicit-required (not defaultable)

The kernel cannot pick a safe default for `path_allowlist` because both
plausible defaults are wrong:

- **`path_allowlist = ["/"]` (or some "all paths" sentinel) is wrong because**
  it violates the fail-closed posture of `INV-TASK-PATH-01`/`02`. An
  Executor with effective access to every path turns every commit into a
  permission grant; the path-scope discipline that makes RAXIS auditable
  collapses into a no-op.
- **`path_allowlist = []` is wrong because** it silently ships a no-write
  Executor whose every commit hard-rejects with `FAIL_PATH_POLICY_VIOLATION`
  at intent admission. The operator believed they had authored a working
  task; they instead get a confusing failure mode at runtime that requires
  reading multiple specs to diagnose.

Neither default carries the operator's intent. The path scope is task-
specific authoring information ("this task implements OAuth2 → it touches
`src/auth/`") that a kernel-side defaulting mechanism could not infer
without inferring from the task's prose description (which would import
LLM bias into the operator's signed plan — explicitly out of scope per
§2). Therefore `path_allowlist` is explicit-required.

### 4.5.3 The `# @raxis-required` template format

When `plan prepare` encounters an Executor task missing `path_allowlist`,
it inserts a commented-out template directly under the role declaration:

```toml
[plan.tasks.implement_oauth2]
role = "Executor"
# @raxis-required path_allowlist must be explicitly declared for Executor tasks.
# @raxis-required Empty array is permitted only with an explicit
# @raxis-required `# @raxis-explicit no-write-acknowledged` annotation.
# @raxis-required See operator-ergonomics.md §4.5 for the full rationale and
# @raxis-required v2-deep-spec.md §6 table 4 for the trailing-slash syntax.
# path_allowlist = [
#   "src/",                 # uncomment and customize before submitting
#   # "tests/",
#   # "src/auth/",
# ]
```

The four `# @raxis-required` lines are a marker block that `plan prepare`
recognizes on subsequent runs to avoid re-inserting the template. Once
the operator uncomments and edits the actual `path_allowlist = [...]`
block, `plan prepare` next-run detects the populated field, removes the
`# @raxis-required` marker block (because the requirement is satisfied),
and leaves the operator's edits untouched.

If the operator runs `plan prepare` again *without* editing the template,
the marker block is preserved verbatim and `plan prepare` exits zero with
a non-fatal warning:

```text
WARN: 1 task still has the @raxis-required template for path_allowlist:
  - implement_oauth2
Submit plan will fail until you uncomment and customize the template.
```

`submit plan` still hard-rejects with `FAIL_PLAN_REQUIRES_EXPLICIT_PATH_ALLOWLIST`
because the actual TOML field is still absent (commented-out lines do not
parse as TOML keys).

### 4.5.4 The `# @raxis-explicit no-write-acknowledged` annotation

Operators who genuinely intend a no-write Executor (rare but legitimate —
e.g., a task that runs a verification script and produces only `/raxis/`
artifacts for a successor task to consume) declare:

```toml
[plan.tasks.run_smoke_check]
role            = "Executor"
path_allowlist  = []          # @raxis-explicit no-write-acknowledged
```

Or equivalently:

```toml
[plan.tasks.run_smoke_check]
role            = "Executor"
# @raxis-explicit no-write-acknowledged
path_allowlist  = []
```

Both forms are accepted by the admission parser per
[`policy-plan-authority.md §5 step 3.b`](policy-plan-authority.md). The annotation has no value and
no version stamp — it is a binary structural opt-in akin to
`same_cluster_acknowledged = true` in [`environment-access-control.md §11.4`](environment-access-control.md).

`plan prepare` will NEVER auto-insert this annotation. Inserting it is
the operator's affirmative acknowledgement that the no-write Executor is
intentional; auto-inserting would defeat the safety property the
acknowledgement is meant to provide.

The kernel records `TaskWriteScope::NoWriteAcknowledged` in the
`InitiativeCreated` audit event for every task admitted under this
annotation, so reviewers and auditors can see the operator's explicit
opt-in in the audit chain.

### 4.5.5 Reviewer's path_allowlist is structurally forbidden

For tasks with `role = "Reviewer"`, declaring `path_allowlist` (any value,
including `[]`) is rejected at `approve_plan` with
`FAIL_REVIEWER_PATH_ALLOWLIST_NOT_ALLOWED` per
[`policy-plan-authority.md §3b`](policy-plan-authority.md). This mirrors the existing
`FAIL_REVIEWER_VM_IMAGE_NOT_ALLOWED` and
`FAIL_REVIEWER_CUSTOM_TOOL_NOT_ALLOWED` discipline: structural bans that
the operator MUST resolve by deleting the offending field themselves.
The kernel never silently mutates an operator-signed plan.

`plan prepare` surfaces the issue pre-signing as a hard refusal:

```text
FAIL: 1 Reviewer task declares path_allowlist:
  - oauth2_review (path_allowlist = ["src/"])
Reviewer's /workspace mount is read-only and the harness has no
commit-pathway intent (planner-harness.md §3, §4.2). The path_allowlist
field is structurally meaningless for Reviewer tasks.
Action: delete the path_allowlist field from these Reviewer tasks and
re-run `plan prepare`.
```

`plan prepare` does NOT auto-strip the field. The operator owns every
byte of the signed plan; if the kernel's eventual rejection of the field
is going to be a hard FAIL, the CLI surfaces the same hard-refusal at
prepare-time so the issue is caught before signing.

### 4.5.6 Top-level directory suggestions in the template (CLI-local)

When the operator runs `plan prepare` from inside a git worktree, the
CLI augments the §4.5.3 template with deterministic top-level-directory
suggestions sourced from the worktree at HEAD:

```bash
$ cd ~/work/myproject
$ raxis-cli plan prepare plan.toml
INFO: detected git worktree at ~/work/myproject
INFO: top-level directories at HEAD: src/, tests/, docs/, scripts/, examples/
INFO: inserted @raxis-required path_allowlist template into 2 Executor tasks
      with directory suggestions
INFO: 0 tasks already have path_allowlist declared

WARN: 2 tasks still have the @raxis-required template:
  - implement_oauth2
  - frontend_feature
Edit plan.toml to uncomment the relevant directory entries; re-run when ready.
```

The augmented template:

```toml
# path_allowlist = [
#   "src/",                 # detected at worktree HEAD
#   "tests/",               # detected at worktree HEAD
#   "docs/",                # detected at worktree HEAD
#   "scripts/",             # detected at worktree HEAD
#   "examples/",            # detected at worktree HEAD
# ]
```

The mechanism is **fully CLI-local** — no IPC to the kernel, no new
policy or plan field. The CLI:

1. Identifies the worktree root via `git -C $PWD rev-parse --show-toplevel`
   (POSIX exit code 128 means "not in a worktree" — fall back to plain
   template).
2. Lists top-level entries via `git -C <root> ls-tree --name-only HEAD .`,
   filtered to directories (entries reported as `tree` mode, not `blob`).
3. Optionally cross-references against `policy.toml [default_protected_paths]`:
   any suggested directory that matches a protected-path prefix gets a
   `# DO-NOT-UNCOMMENT (matches protected path: <pattern>)` comment
   appended on the same line, so the operator doesn't accidentally grant
   write to a protected path.
4. Skips suggestion entirely (just the bare template) if the operator's
   `$PWD` is not inside a git worktree, OR if the operator passes
   `--no-suggest`.

Operators can override the auto-detected worktree with
`--suggest-from <path>`:

```bash
$ raxis-cli plan prepare plan.toml --suggest-from ~/work/myproject
```

This is useful when the operator is editing the plan file from a
different directory than the target worktree (e.g., editing in a deploy
config repo while the actual code lives elsewhere).

The suggestion mechanism is intentionally limited to **structural**
information from the operator's filesystem (top-level directories at
HEAD). It does NOT:

- Read the operator's task description and "guess" relevant directories
  (would require LLM inference; explicitly rejected).
- Walk subdirectories (would explode the suggestion list; the
  trailing-slash discipline naturally encourages directory-prefix
  declarations like `src/` over leaf-file declarations).
- Consult the RAXIS managed repository mirror
  (`<data_dir>/repositories/<repo_id>/`). That mirror is used for
  governed execution and publishing, not for local authoring-time
  path suggestions; the operator's worktree at `$PWD` remains the
  canonical source for `plan prepare` suggestions.

### 4.5.7 Worktree concept clarification

There are three conceptually distinct git locations operators can confuse:

| Location | Owned by | Purpose | Operator-configurable? |
|---|---|---|---|
| **operator worktree** (e.g., `~/work/myproject/`) | Operator | Where the operator authors code, runs `raxis-cli`, and edits `plan.toml`. | Yes — the operator's filesystem; identified to the CLI via `$PWD` or `--suggest-from`. Bound to a session at session-creation time and validated against `policy.toml [sessions] allowed_worktree_roots`. |
| **external repository** (GitHub, GitLab, local bare repo, etc.) | Operator/team | Source of record outside RAXIS. This is what humans and CI/CD systems normally use. | Yes — registered with `raxis repo adopt <repo_id> <path-or-git-url>`. |
| **RAXIS managed repository mirror** (`<data_dir>/repositories/<repo_id>/`) | Kernel | Governed working mirror. Plans select it with `[workspace] repository = "<repo_id>"`. Initiatives pin a base SHA from it. `IntegrationMerge` advances its `target_ref` first; publishing back to the external repository is a separate explicit state. | Yes by repository id, not by arbitrary path. The path is kernel-owned and exact-root validated. |
| **session worktree** (`<data_dir>/worktrees/<session_id>/`) | Kernel | Per-session worktree/clone mounted into a planner, executor, reviewer, or verifier VM. It is derived from the managed mirror and may be garbage-collected after session completion. | No — selected by task/session scheduling. |

The §4.5.6 suggestion mechanism reads from the **operator worktree**.
The RAXIS managed repository mirror is never inspected by `plan prepare`
(it would require IPC and kernel-side plan-author authority, both of
which would violate the boundary between authoring and admission).

### 4.5.8 Adopted repository lifecycle

The external repository is the source of record. The RAXIS managed
repository is the governed working mirror. Initiatives run against the
managed mirror, and `IntegrationMerge` lands there before anything is
published back to the external repository.

The durable metadata for each adopted repository lives in the
`managed_repositories` store table:

| Field | Meaning |
|---|---|
| `repository_id` | Stable id used by `[workspace] repository`. |
| `managed_path` | Kernel-owned exact Git root under `<data_dir>/repositories/<repo_id>`. |
| `source_url` | External repository path or URL originally adopted. |
| `default_remote` | Remote used for fetch/publish, normally `origin`. |
| `default_target_ref` | Ref plans normally target, normally `refs/heads/main`. |
| `tracking_ref` | Remote-tracking ref used to compute ahead/behind/diverged state. |
| `last_fetch_at`, `last_push_at`, `last_status_at` | Operator-facing freshness/provenance timestamps. |
| `lifecycle_state` | Current mirror state (`clean`, `dirty`, `ahead`, `behind`, `diverged`, `local_only`, `remote_unreachable`, `missing`, `not_a_git_root`, or `unknown`). |
| `publish_state` | Last known publish state (`pending`, `published`, `failed`, `local_only`, or `unknown`). |

Repository commands:

```bash
raxis repo adopt <repo_id> <path-or-git-url>
raxis repo status [repo_id] [--remote]
raxis repo fetch [repo_id]
raxis repo sync [repo_id]
raxis repo publish [repo_id] [--remote origin] [--ref refs/heads/main]
raxis repo repair
```

Lifecycle semantics:

- `clean`: managed mirror is clean and aligned with its tracking ref.
- `dirty`: managed mirror has uncommitted local changes; plan approval
  fails until repaired or intentionally resolved.
- `ahead`: managed mirror contains local IntegrationMerge output that is
  not published yet.
- `behind`: external source advanced; run `raxis repo sync` before
  approving a new plan unless doing an explicitly pinned/offline run.
- `diverged`: both managed mirror and external source moved; operator
  intervention is required.
- `local_only`: no remote is configured; valid for local-only use.
- `remote_unreachable`: fetch/publish failed; operator should diagnose
  credentials/network before approving production work.
- `missing` / `not_a_git_root`: metadata points at a path that is gone
  or is not the exact Git root; run `raxis repo repair` or re-adopt.

Plan approval performs a pre-run repository check. If the store contains
managed repository metadata, `[workspace] repository` must refer to a
known adopted repository and its lifecycle must be `clean` or
`local_only`. Plans may narrow the target ref inside policy bounds, but
they cannot silently run on a dirty/stale/diverged mirror.

After `IntegrationMerge`, the managed mirror's `publish_state` becomes
`pending`. If policy enables direct auto-push and the push succeeds,
`publish_state` becomes `published`. If auto-push is disabled, rejected
by branch protection, or fails for credentials/network reasons, the
state remains `pending` or becomes `failed` with `last_error` populated.
The dashboard surfaces this state next to the repository row and offers
copyable follow-up commands.

**Exact-root rule.** RAXIS never treats "any directory where `git
rev-parse` succeeds" as a repository. `git rev-parse --show-toplevel`
must equal the candidate path (after canonicalization), or the candidate
is ignored/rejected. This prevents parent-walk bugs where
`<data_dir>/repositories/main` accidentally resolves to a parent checkout
such as `/opt/homebrew/.git`.

---

## §5 — `raxis-cli plan prepare`

### 5.1 Invocation

```bash
raxis-cli plan prepare <plan.toml> [--upgrade-defaults] [--keep-original]
                                    [--dry-run] [--suggest-from <path>]
                                    [--no-suggest]
```

| Flag | Default | Effect |
|---|---|---|
| `--upgrade-defaults` | off | Permits `plan prepare` to update annotated default values when the policy default has changed since the annotation was written. Without this flag, default-value drift fails with `FAIL_PREPARE_DEFAULT_UPGRADE_REQUIRED`. |
| `--keep-original` | off | Before mutating `plan.toml`, write a sidecar `plan.toml.raxis-original.bak` containing the pre-prepare bytes. Useful for operators who don't use version control. The backup is NOT bundled, NOT signed, and NOT consumed by any other RAXIS command. |
| `--dry-run` | off | Compute the augmented plan in memory; print the diff to stdout; do NOT write to disk. Equivalent to `raxis-cli plan diff <plan.toml>` (§8) but with the diff computation done by the kernel rather than locally. |
| `--suggest-from <path>` | auto-detect from `$PWD` via `git rev-parse --show-toplevel` | Override the worktree root used for path-allowlist top-level-directory suggestions per §4.5.6. Useful when editing `plan.toml` from a different directory than the target worktree. Pass an absolute path; the CLI validates it is a git worktree (running `git -C <path> rev-parse --git-dir`) and aborts with a clear error if not. |
| `--no-suggest` | off | Disable path-allowlist directory suggestions entirely; insert the bare §4.5.3 template with no detected-at-HEAD comments. Useful in CI environments where `$PWD` happens to be a git worktree but is not the target worktree, AND the operator does not want to pass `--suggest-from`. Has no effect on tasks whose `path_allowlist` is already declared. |
| `--offline` | off | Skip phase 3+ (IPC + defaultable-field resolution); run phase 2 (§4.5 template insertions) only and persist the result to `plan.toml` with a `# @raxis-prepare-partial offline=true …` marker prepended (§5.4.2). Exit code `4`. Useful for laptop editing when the kernel daemon is unreachable. Without `--offline`, phase 3 failure produces exit code `4` but does NOT write phase-2 changes to disk (refuses the half-prepared state). See §5.7 for the full offline-mode semantics. |

### 5.2 Phases

```text
1. parse:      Read plan.toml bytes from disk; parse as TOML, retaining
               comments and field positions.

2. local-pre:  CLI-local pass over Executor and Reviewer tasks per §4.5
               (no IPC yet — these checks/edits are pure operator-side):
               a. For each Reviewer task declaring path_allowlist (any
                  value), abort with the §4.5.5 hard-refusal message
                  (mirrors what approve_plan would emit; surfaced
                  pre-signing for ergonomic reasons).
               b. For each Executor task missing path_allowlist:
                  - If the task already carries the §4.5.3 marker block
                    (`# @raxis-required path_allowlist must be ...`),
                    leave it alone — operator hasn't completed the
                    requirement yet; emit the §4.5.3 non-fatal warning.
                  - Otherwise, insert the §4.5.3 commented-out template.
                    Augment with §4.5.6 directory suggestions if a
                    worktree is auto-detected (or --suggest-from was
                    passed), unless --no-suggest is set. Annotate any
                    suggestion that matches a [default_protected_paths]
                    pattern with the DO-NOT-UNCOMMENT comment.
               c. For each Executor task carrying the marker block AND
                  a populated `path_allowlist = [...]` field (operator
                  has uncommented and edited): remove the marker block
                  (the requirement is satisfied; no need to nag).
               d. For each Executor task with `path_allowlist = []`
                  and the `# @raxis-explicit no-write-acknowledged`
                  annotation present: leave alone (the operator's
                  explicit acknowledgement is structurally distinct
                  from a defaultable field).
               e. For each Executor task with `path_allowlist = []`
                  and no acknowledgement annotation: emit a non-fatal
                  warning explaining FAIL_EXECUTOR_EMPTY_PATH_ALLOWLIST_UNACKNOWLEDGED
                  with both remediation paths (populate the array OR
                  add the annotation). plan prepare does NOT auto-add
                  the annotation per §4.5.4.
               f. For each path_allowlist entry violating the §6
                  table-4 syntax (glob characters, absolute paths, ..),
                  emit a non-fatal warning citing
                  FAIL_PATH_ALLOWLIST_INVALID_SYNTAX and the specific
                  reason. submit plan will hard-reject; warning here is
                  to catch it pre-signing.

3. ipc:        Open operator socket; perform challenge-response handshake;
               send OperatorRequest::ProposeDefaults { plan_bytes,
               cli_version, upgrade_defaults_flag }.

4. resolve:    Kernel loads current policy; walks the parsed plan; for each
               defaultable field per §4.2 that the operator omitted, resolves
               the policy-default value. For each previously-annotated field,
               applies the §4.4 idempotency rule.

5. respond:    Kernel returns OperatorResponse::DefaultsProposed
               { augmented_plan_bytes, defaulted_fields: [...] } on success,
               or OperatorResponse::Error with FAIL_PREPARE_DEFAULT_UPGRADE_REQUIRED
               (or another FAIL_*) on failure.

6. write:      CLI writes augmented_plan_bytes back to plan.toml. If
               --keep-original, the pre-prepare bytes are first written to
               plan.toml.raxis-original.bak.

7. report:     CLI prints a summary: which fields were filled (defaultable),
               which §4.5 templates were inserted, which were left alone,
               which require --upgrade-defaults, which Reviewer-path-allowlist
               aborts fired, and which Executor-empty-allowlist warnings
               surfaced. Exits zero only if no §4.5.5 hard refusals fired
               (template-insertion warnings are non-fatal at prepare time;
               submit plan is the hard gate).
```

**Why phase 2 is local-only and runs before IPC.** The §4.5 mechanics
operate purely on the operator's own bytes (template insertion, marker
block detection, annotation parsing) and on the operator's own filesystem
(worktree directory listing). None of this requires kernel knowledge —
the policy doesn't need to be loaded, no audit event needs to fire, no
admission decision needs to be made. Doing this work locally:
- Keeps the kernel's `OperatorRequest::ProposeDefaults` handler purely
  about defaultable values (matches the existing handler contract per
  §5.3).
- Preserves the property that `plan prepare` does useful work even when
  the kernel daemon is down (a partial-utility offline mode for
  operators editing on a laptop disconnected from their RAXIS host).
- Avoids cross-spec coupling — [`policy-plan-authority.md §4`](policy-plan-authority.md) doesn't
  need a new kernel handler for path-allowlist concerns.

### 5.3 IPC contract: `OperatorRequest::ProposeDefaults`

```rust
OperatorRequest::ProposeDefaults {
    plan_bytes:           Vec<u8>,           // raw TOML bytes of the operator's plan
    cli_version:          String,            // semver of the CLI; embedded in new annotations
    upgrade_defaults:     bool,              // mirrors --upgrade-defaults flag
}

OperatorResponse::DefaultsProposed {
    augmented_plan_bytes: Vec<u8>,           // raw TOML bytes with defaults filled
    defaulted_fields:     Vec<DefaultedField>,
    upgraded_fields:      Vec<UpgradedField>,    // populated when --upgrade-defaults applied changes
    drift_pending_fields: Vec<DriftField>,       // populated when not --upgrade-defaults but drift detected
}

struct DefaultedField {
    path:              String,        // e.g., "plan.tasks.implement_feature.vm_image"
    value_summary:     String,        // human-readable; e.g., "raxis-executor-starter@sha256:abcd... (truncated)"
    annotation_added:  String,        // e.g., "@raxis-default v0.4.0"
}

struct UpgradedField {
    path:              String,
    previous_value:    String,
    new_value:         String,
    previous_version:  String,        // from the prior annotation
    new_version:       String,        // current CLI version
}

struct DriftField {
    path:              String,
    stamped_value:     String,
    proposed_value:    String,
    stamped_version:   String,
    current_version:   String,
}
```

`ProposeDefaults` is a **read-only** kernel operation. It must NOT:
- Insert any row into `kernel.db`.
- Reserve any token budget.
- Allocate any session or VM resource.
- Emit any audit event with non-trivial side effects (a single low-priority `DefaultsProposed` audit event for traceability is allowed; see §5.5).

It MAY:
- Read the currently-loaded policy.
- Read the currently-loaded `[default_*]` policy sections.
- Read the canonical Executor starter image manifest to resolve its OCI digest.

The response is always pure-function-of-inputs: same `(plan_bytes, current_policy_epoch, cli_version)` → same `augmented_plan_bytes`.

### 5.4 Failure modes

| Failure | Trigger | Operator action |
|---|---|---|
| `FAIL_PREPARE_DEFAULT_UPGRADE_REQUIRED { fields }` | At least one annotated field's policy-default value has drifted since the annotation was written, and `--upgrade-defaults` was not passed. | Review the proposed changes (CLI prints the diff); re-run with `--upgrade-defaults` to accept the new defaults. |
| `FAIL_PLAN_PARSE_ERROR { detail }` | The provided `plan.toml` is not valid TOML, or violates plan schema. | Fix the TOML error. |
| `FAIL_PLAN_FIELD_NOT_DEFAULTABLE { field }` | The operator placed a `# @raxis-default` annotation on a field NOT in §4.2. | Remove the annotation; the field is operator-owned. |
| `FAIL_POLICY_DEFAULT_UNRESOLVABLE { field }` | A defaultable field requires a policy value (e.g., `[default_executor_image] alias` for `vm_image`) but the policy does not declare one. | Add the missing policy entry; advance the policy epoch again. |
| `FAIL_PREPARE_KERNEL_UNREACHABLE { socket_path, errno }` | Phase 3 (IPC) could not establish a connection to the operator socket: socket file does not exist, connection refused, permission denied, or the handshake timed out. Phase 2 (local-pre) MAY have already written §4.5 template insertions to disk per `--offline` semantics below. | Start the kernel daemon; or pass `--offline` to suppress phase 3+ entirely (see §5.7). |

#### 5.4.1 Distinct exit codes

`plan prepare` distinguishes seven outcomes via POSIX exit code so
shell pipelines and CI scripts can react precisely without
parsing stdout:

| Exit code | Meaning | Phase 2 disk write | Phase 4 defaults filled |
|---|---|---|---|
| `0` | Full success: phase 2 ran, phase 3 + 4 + 5 succeeded, the augmented plan was written to disk. | yes | yes |
| `2` | Local-pre warnings only: phase 2 emitted non-fatal warnings (e.g. §4.5.3 template insertion, unused-acknowledgement notice), phase 3-5 succeeded; the augmented plan was written. Distinct from `0` so CI can detect "review the warnings" without conflating them with hard failures. | yes | yes |
| `3` | Phase 2 hard refusal (e.g. §4.5.5 Reviewer-path-allowlist abort): the CLI refuses to proceed; no disk write; the original `plan.toml` is untouched. | no | no |
| `4` | Phase 2 success, **kernel unreachable** (`FAIL_PREPARE_KERNEL_UNREACHABLE`): phase 2's §4.5 template insertions ARE persisted IF AND ONLY IF the operator passed `--offline` (see §5.7). Without `--offline`, the CLI does NOT write phase-2 changes — refusing to leave a file in a half-prepared state where defaultable fields are missing. | only with `--offline` | no |
| `5` | Phase 4-5 IPC error from the kernel (`FAIL_PREPARE_DEFAULT_UPGRADE_REQUIRED`, `FAIL_POLICY_DEFAULT_UNRESOLVABLE`, `FAIL_PLAN_FIELD_NOT_DEFAULTABLE`, `FAIL_PLAN_PARSE_ERROR` from the kernel-side parser): the kernel rejected the prepare. No disk write. | no | no |
| `64` | CLI usage error (invalid flag combination, e.g. `--suggest-from <path>` where `<path>` is not a git worktree, or unknown flag). | no | no |
| `1` | Catch-all for unexpected internal errors (panic, I/O error reading `plan.toml`, etc.). | no | no |

The choice of `64` for usage error matches BSD `sysexits.h` so
RAXIS-CLI integrates with standard Unix error-handling conventions.
Operators implementing wrappers should treat anything `>= 64` as an
unrecoverable usage problem, `0..=2` as success-like, and
`3..=5` as actionable failure paths.

#### 5.4.2 Marker comment for partial preparation

When phase 2 successfully writes §4.5 template insertions to
disk but phase 3+ did not run (`--offline` mode, exit code `4`),
the CLI prepends an OFFLINE marker to `plan.toml` so a subsequent
`submit plan` invocation can detect the half-prepared state and
fail loudly rather than silently submitting a plan with missing
defaultable fields:

```toml
# @raxis-prepare-partial offline=true cli_version="<semver>" prepared_at="<RFC3339-utc>"
# This plan was prepared with `raxis-cli plan prepare --offline` and
# has had local §4.5 templates inserted, but defaultable fields
# (per operator-ergonomics.md §4.2) were NOT filled because the
# kernel daemon was unreachable. Re-run `raxis-cli plan prepare`
# (without --offline) before signing and submitting.

# (rest of plan.toml follows)
```

`submit plan` parses this marker BEFORE TOML parsing (line-prefix
match for `# @raxis-prepare-partial offline=true`) and fails with
`FAIL_PLAN_PARTIAL_PREPARE_DETECTED { prepared_at, cli_version }`.
The operator must re-run `plan prepare` (which detects and removes
the marker after a successful full run, per §5.6 idempotency) or
explicitly delete the marker line if they intend to submit
without further preparation.

The marker is plain comment lines so existing TOML parsers
(including operator hand-edits) ignore it. The CLI's marker writer
uses byte-exact strings so the parser can scan for the prefix
without invoking a TOML parser.

### 5.5 Audit

`plan prepare` emits exactly one low-priority audit event per successful invocation:

```rust
AuditEventKind::DefaultsProposed {
    proposed_at:           u64,
    operator_fingerprint:  OperatorFingerprint,
    plan_bytes_sha256:     [u8; 32],            // SHA-256 of the input plan
    augmented_bytes_sha256: [u8; 32],           // SHA-256 of the proposed augmented plan
    defaulted_field_count: u32,
    upgraded_field_count:  u32,
}
```

This event is **informational only**. It records that an operator queried for defaults; it does NOT bind the operator to those defaults (no signature is involved). The augmented plan only becomes authoritative when the operator signs the bundle and submits via `submit plan`. Forensic auditors can correlate `DefaultsProposed.augmented_bytes_sha256` against later `InitiativeCreated.plan_bundle_sha256` (after the operator computes the bundle hash; the comparison is incidental and not authoritative — there is no kernel-side check that what was proposed matches what was eventually signed).

The audit event is rate-limited per operator fingerprint to prevent DoS via repeated prepare calls.

### 5.6 Idempotency guarantee

Two consecutive `plan prepare` invocations on the same input plan, against the same policy epoch and same CLI version, produce byte-identical output plans. The CLI uses this to detect "no-op prepare" runs and exit with a one-line `plan already prepared; no changes` message rather than rewriting the file with identical bytes (which would dirty the operator's git index).

### 5.7 Offline mode (`--offline`)

Phase 2 of `plan prepare` is structurally local-only (§5.2 phase 2
rationale): template insertions, marker-block detection, annotation
parsing, and worktree directory listing all operate on the
operator's own bytes and filesystem. Phase 3+ requires the kernel
to be reachable via the operator socket.

Two distinct disconnection scenarios deserve different handling:

1. **The operator intentionally edits offline** (e.g., on a laptop
   on a plane, or in an air-gapped network segment). They want
   the §4.5 ergonomics work persisted now, plan to re-run
   `plan prepare` later when the kernel is reachable, and
   accept that the file is *partially* prepared in the
   meantime. They pass `--offline`.
2. **The operator did NOT realize the kernel is down.** They
   expect a full prepare; phase 3 unexpectedly fails. Persisting
   phase-2 changes silently in this case would leave the
   operator with a half-prepared `plan.toml` that fails at
   `submit plan` later in a confusing way ("but I just ran
   prepare!"). Better: refuse the disk write, surface the kernel
   unreachability clearly, and leave the original file untouched.

The default (no `--offline`) implements scenario 2: phase 3 IPC
failure produces `FAIL_PREPARE_KERNEL_UNREACHABLE`, exit code 4,
and the original `plan.toml` is preserved. The CLI's stderr
message is:

```text
error: kernel daemon unreachable on socket /var/run/raxis/operator.sock
       (connection refused: errno=111)

       phase 2 of `plan prepare` ran successfully but its changes
       were NOT persisted, because phase 3 (defaults resolution)
       could not run.

       to start the daemon: raxis daemon start
       to persist phase 2's §4.5 template insertions despite
       the kernel being unreachable, re-run with --offline.
```

`--offline` implements scenario 1: phase 2 runs, the augmented
bytes are written to disk WITH the §5.4.2 marker prepended, and
the CLI exits with code 4 (so script callers know the plan is
NOT fully prepared). The marker MUST be the very first line of
the file (or, if a `# @plan-toml` magic-line marker is present,
the line immediately after it — preserving the convention where
the magic line is always line 1).

#### Re-running prepare after offline

A subsequent `raxis-cli plan prepare` (without `--offline`) on a
file carrying the `# @raxis-prepare-partial offline=true` marker:

1. Phase 2 re-runs: idempotent per §5.6 (template marker blocks
   are detected and not duplicated).
2. Phase 3 IPC connects.
3. Phase 4-5 fill defaultable fields per §4.2.
4. Phase 6 (write) **removes** the partial-prepare marker as
   part of the write — the augmented bytes no longer have the
   half-prepared property, so the marker is no longer
   accurate. The CLI's report (phase 7) explicitly notes the
   marker removal: `[plan prepare] removed offline marker
   (file is now fully prepared as of <RFC3339>)`.

Re-running `plan prepare --offline` on an already-marked file is
idempotent: phase 2 re-runs (no-op for already-templated tasks);
the marker is rewritten with the latest CLI version and timestamp.

#### Operator-side warning when re-running --offline on a fully prepared plan

If `--offline` is passed against a `plan.toml` that has NO
partial-prepare marker AND no §4.5 template insertions are
needed (phase 2 produces no changes), the CLI emits:

```text
warning: --offline was passed but plan.toml has no pending
         §4.5 template work; phase 2 is a no-op. The kernel
         was NOT contacted; defaultable fields per §4.2 were
         NOT verified. Re-run without --offline to fully
         prepare.
```

Exit code `2` (warning, not failure). This catches the case
where an operator habitually passes `--offline` and forgets
that defaults still need a kernel round-trip.

---

## §6 — `raxis-cli plan init`

### 6.1 Purpose

Scaffold a new `plan.toml` from a built-in template. Templates ship with the CLI (D9) and embed sensible defaults already as `@raxis-default` annotations, so the new operator's first `plan prepare` is mostly a no-op.

### 6.2 Invocation

```bash
raxis-cli plan init [--template <name>] [--output <path>] [--name <text>]
```

| Flag | Default | Effect |
|---|---|---|
| `--template`, `-t` | `feature` | Template name. List available templates with `raxis-cli plan init --list-templates`. |
| `--output`, `-o` | `./plan.toml` | Where to write the scaffolded file. Refuses to overwrite an existing file unless `--force` is passed. |
| `--name` | (prompted interactively) | Human-readable initiative label, embedded into `[workspace].name` and used as the initial `[plan.initiative].description` placeholder. |

### 6.3 Templates (V2)

| Template | DAG shape | Suited for |
|---|---|---|
| `feature` | `plan → implement → review → merge` | Adding a new feature to a project. Includes one Executor task with a Reviewer gate before integration. |
| `bugfix` | `reproduce → fix → regression-test → merge` | Fixing a reported bug. The reproduce task generates a failing test; the fix task makes it pass. |
| `dependency-upgrade` | `upgrade → test → merge` | Bumping a dependency version with regression-test verification. |
| `migration` | `plan → migrate → rollback-test → merge` | Schema or configuration migrations; rollback-test verifies that a prepared rollback plan succeeds. |
| `experiment` | `setup → run → cleanup` | Time-bounded exploratory work that does not produce a merge. |

Each template embeds:
- A minimum-viable profile graph.
- One or more Executor tasks with sensible default verifiers (lint, test, build per the project type the template targets).
- A Reviewer task where appropriate, with `symbol_index = "not_needed"` declared for templates whose DAG shape doesn't require static analysis.
- Inline comments explaining what each section does and how to customize.

### 6.4 Failure modes

| Failure | Trigger |
|---|---|
| `FAIL_PLAN_INIT_TEMPLATE_NOT_FOUND { name }` | Template name not in the CLI-bundled set. |
| `FAIL_PLAN_INIT_OUTPUT_EXISTS { path }` | Output path already exists; operator did not pass `--force`. |

### 6.5 Cross-references

The scaffolded plan is suitable for direct submission via `plan prepare → submit plan`. Operators with custom requirements edit the scaffold before preparing.

---

## §7 — `raxis-cli plan validate`

### 7.1 Purpose

Local-only static validation of a `plan.toml` without IPC and without an operator key. Catches schema errors, profile cycles, custom-tool name collisions, NFC violations, and other plan-only issues. Suitable for pre-commit hooks and editor integrations.

### 7.2 Invocation

```bash
raxis-cli plan validate <plan.toml> [--with-kernel] [--explain-environment]
```

| Flag | Default | Effect |
|---|---|---|
| `--with-kernel` | off | Open the operator socket and run a full admission dry-run via `submit plan --dry-run` (§13). Catches policy-dependent issues that local validation cannot. Requires the operator key. |
| `--explain-environment` | off | (Cross-reference: [`environment-access-control.md`](environment-access-control.md) follow-on work.) Walks every task and prints its resolved environment binding (or "neutral"). Exits non-zero if any task has an inconsistent environment binding. |

### 7.3 Validation surface

Local-only (no `--with-kernel`) checks:

- TOML parsing and schema conformance.
- Profile inheritance graph: cycles, name collisions per [`custom-tools.md §8.2`](custom-tools.md).
- Custom-tool reserved-name conflicts (the reserved-name list ships with the CLI and is mirrored from the kernel binary; minor drift between CLI and kernel is acceptable since the kernel re-validates at admission).
- Per-task field consistency: e.g., a task declaring `[plan.tasks.<id>.review] symbol_index = "not_needed"` but no Reviewer in the DAG.
- Bundle size pre-check against `policy.toml [plan_bundle_limits]` (CLI uses the most-recent locally-cached policy bundle if available; otherwise uses defaults).

`--with-kernel` adds:

- Policy-dependent admission checks per [`policy-plan-authority.md §5`](policy-plan-authority.md).
- Kernel-resolved default proposals (informational; doesn't write to disk).
- Bundle-size enforcement against the live policy.

### 7.4 Output

```bash
$ raxis-cli plan validate ./plan.toml
plan.toml: 4 tasks, 1 profile, 0 custom tools
  ✓ TOML schema
  ✓ Profile inheritance graph (acyclic)
  ✓ Custom-tool name uniqueness
  ⚠ Task "implement_feature" omits vm_image (will be defaulted by `plan prepare`)
  ⚠ Task "implement_feature" omits token_policy (will be defaulted by `plan prepare`)
  ✓ Bundle size pre-check (estimated 4 KiB; cap 1 MiB per artifact)

Summary: 0 errors, 2 advisories. Run `raxis-cli plan prepare` to apply defaults.
```

Exit code 0 on success (advisories don't fail), non-zero on any error.

### 7.4a Implementation reference (local-only checks)

The first-pass `plan validate` lands as
`cli/src/commands/plan_validate.rs` and is wired through the existing
`plan` sub-command dispatcher in `cli/src/main.rs::PLAN_SUBCOMMANDS`.
The validator runs against the on-disk `plan.toml` bytes and returns
a `ValidationReport` whose `lines` are emitted as `[OK]` or `[FAIL]`
rows. The pure validator (`validate_plan_text`) is unit-tested in
the same file and is the API future host-side tooling (`plan
explain`, `plan diff`) will reuse.

Coverage shipped in V2:

- TOML parse (line/col diagnostic from the `toml` crate).
- Required sections: `[workspace]`, `[[tasks]]`.
- `[workspace] lane_id` non-empty.
- Per-task: `task_id` required, no `lane_id` per-task override
  (V2 §28 single-lane propagation), no
  `session_agent_type = "Orchestrator"` (V2 §27 rule 1), valid
  `clone_strategy` ∈ {`full`, `blobless`, `sparse`}, valid
  `session_agent_type` ∈ {`Executor`, `Reviewer`}.
- DAG family (mirrors `kernel/src/initiatives/lifecycle.rs::validate_plan_dag`):
  duplicate `task_id`, self-loop, dangling predecessor, cyclic
  dependency (iterative DFS with three-color marking).
- `cross_cutting_artifacts` syntax (mirrors
  `validate_cross_cutting_artifacts`): empty entry, leading `!`,
  leading or trailing `/`, `..` segment, embedded `/`, glob
  characters.
- `path_allowlist` syntax (V2 §19 entry shape): empty, leading
  `!`, leading `/`, glob characters, `..` segment.

Deferred to follow-up landings:

- Profile inheritance graph ([`custom-tools.md §8.2`](custom-tools.md)) — requires
  custom-tools profile resolver.
- Custom-tool reserved-name conflicts — requires CLI-side mirror of
  the kernel's reserved-name list.
- Per-task field consistency advisories (e.g., `review.symbol_index =
  "not_needed"` without a Reviewer in the DAG).
- Bundle size pre-check against `[plan_bundle_limits]`.
- `--with-kernel` admission dry-run (depends on the operator-socket
  `ProposeDefaults` / `DryRunAdmit` IPCs, which are sequenced after
  the credential-proxy and egress-proxy landings).
- `--explain-environment` (depends on
  [`environment-access-control.md`](environment-access-control.md) follow-on work).

The kernel admission handler remains the single source of truth;
anything `plan validate` misses is still rejected by `submit plan`,
so a clean `plan validate` is necessary-but-not-sufficient.

### 7.5 Failure modes

`plan validate` exits non-zero on any `FAIL_PLAN_*` issue. The full failure code set is the union of [`policy-plan-authority.md §3b`](policy-plan-authority.md) (admission failures) plus [`plan-bundle-sealing.md §9`](plan-bundle-sealing.md) (bundle-format failures). With `--with-kernel`, the failure set additionally includes policy-dependent codes.

---

## §8 — `raxis-cli plan diff`

### 8.1 Purpose

Show the diff between the operator's raw plan and what `plan prepare` would produce, **without writing anything to disk**.

### 8.2 Invocation

```bash
raxis-cli plan diff <plan.toml> [--format unified|json]
```

| Flag | Default | Effect |
|---|---|---|
| `--format` | `unified` | `unified` produces a `diff -u`-style text diff with per-line annotations. `json` produces a structured array of `DefaultedField` entries (per §5.3 IPC schema). |

### 8.3 Behavior

Identical to `plan prepare --dry-run` (§5.1) but framed as a read operation rather than a "would-be-write" operation. Emits no audit event; sends the same `ProposeDefaults` IPC; never mutates the file.

The unified-diff output highlights:

- Newly-added fields (green `+`).
- Annotation comments added (gray; informational).
- Default-value drift relative to existing annotations (yellow; flagged with `[upgrade required]`).

### 8.4 Failure modes

Same as `plan prepare` (§5.4), except `FAIL_PREPARE_DEFAULT_UPGRADE_REQUIRED` is informational rather than fatal — the diff is shown anyway, with the drift fields highlighted.

---

## §9 — `raxis-cli plan explain`

### 9.1 Purpose

Render the plan in plain English: ASCII DAG diagram, per-task summary, and a final "this initiative will request approval for: [...]" section. Aimed at operators who can't read TOML at a glance and at non-author reviewers (the second human in a two-eyes-on-plan deployment).

### 9.2 Invocation

```bash
raxis-cli plan explain <plan.toml> [--task <id>] [--format text|markdown|html]
```

### 9.3 Output structure

```text
INITIATIVE: <plan.initiative.description>
SUBMITTING OPERATOR: (resolved at submit time, not plan time)

DAG:
    [implement_feature] ──→ [review_feature] ──→ [merge_feature]
         (Executor)            (Reviewer)         (Orchestrator)

────────────────────────────────────────────────────────────────
TASK: implement_feature  (Executor)
  Image:           raxis-executor-starter@sha256:abcd1234...   [defaulted]
  Workspace:       Read-write clone of branch main
  Egress:          (none — no network access)
  Credentials:     (none)
  Custom tools:    (none)
  Verifiers:       lint, test, build
  Token budget:    500K input / 50K output per session  [defaulted]
  Will produce:    one commit on branch impl-feature
────────────────────────────────────────────────────────────────
TASK: review_feature  (Reviewer)
  Image:           raxis-reviewer-core   [kernel-canonical]
  Workspace:       Read-only view of impl-feature branch
  Custom tools:    (banned for Reviewer per INV-PLANNER-HARNESS-04)
  Symbol index:    declared not_needed
  Will produce:    one ReviewSubmission (approve / reject / request-changes)
────────────────────────────────────────────────────────────────
TASK: merge_feature  (Orchestrator)
  Image:           raxis-orchestrator-core   [kernel-canonical]
  Will produce:    one IntegrationMerge into branch main, gated by review_feature approval

ESCALATION SURFACE:
  - ProtectedPathMerge       (if merge_feature touches .git/ or other protected paths)
  - MergeAuthorization       (if policy.orchestrator.all_merges_require_approval = true)

ESTIMATED COST:
  Run `raxis-cli plan cost-estimate ./plan.toml` for a token/dollar projection.
```

### 9.4 Cross-references

Read-only on plan.toml. Calls `ProposeDefaults` (§5.3) under the hood to resolve any `[defaulted]` annotations not yet written to the file.

---

## §10 — `raxis-cli plan fmt`

### 10.1 Purpose

Canonicalize a `plan.toml` file's formatting: indentation, field ordering within each table, quoting style, comment placement. Analogous to `gofmt`. Diff-friendly for code review and stable across operator editing styles.

### 10.2 Invocation

```bash
raxis-cli plan fmt <plan.toml> [--check] [--stdout]
```

| Flag | Default | Effect |
|---|---|---|
| `--check` | off | Do not modify the file; exit non-zero if the file is not in canonical form (suitable for CI gates). |
| `--stdout` | off | Write the canonical output to stdout instead of mutating the file in place. |

### 10.3 Canonical form

- 2-space indentation.
- Field order within tables: `description` first, then schema fields in spec-declared order.
- Strings: double-quoted unless multi-line (then triple-double-quoted).
- Comments preserved (including `@raxis-default` annotations) at their original line positions.
- Trailing whitespace removed; final newline ensured.

### 10.4 Integration with `plan prepare`

`plan prepare` runs `plan fmt` automatically as its final step (§5.2 phase 5), so the prepared file is always in canonical form. This makes the post-prepare diff cleaner for review.

Operators editing `plan.toml` between `plan prepare` runs may produce non-canonical output; the next `plan prepare` re-canonicalizes.

---

## §11 — `raxis-cli plan cost-estimate`

### 11.1 Purpose

Pre-submission projection of token usage and provider cost. Decision support before the operator commits to an initiative.

### 11.2 Invocation

```bash
raxis-cli plan cost-estimate <plan.toml> [--scenario typical|worst-case]
```

| Flag | Default | Effect |
|---|---|---|
| `--scenario` | `typical` | `typical` assumes ~50% of declared token budgets are consumed; `worst-case` assumes 100% of declared budgets across all tasks fire to the configured `max_token_budget`. |

### 11.3 Behavior

Calls a new IPC `OperatorRequest::EstimateCost { plan_bytes }`; the kernel:
1. Parses the plan; resolves defaults per §4.
2. For each task, projects the token cost using the same `tokenize` admin interface used by custom-tool budget projection ([`custom-tools.md §9.2`](custom-tools.md)).
3. Multiplies by the configured provider rates from `policy.toml [provider_rates.<provider>]`.
4. Returns a per-task and per-initiative cost breakdown.

Output:

```text
Initiative: <plan.initiative.description>

Per-task projection (typical scenario):
  implement_feature   ~  250K input ~ 25K output  → $0.45
  review_feature      ~  100K input ~ 10K output  → $0.18
  merge_feature       ~   50K input ~  5K output  → $0.09

Initiative total (typical):       $0.72
Initiative total (worst-case):    $1.44

Run `submit plan --dry-run` to verify admission against current policy.
```

### 11.4 Failure modes

`FAIL_COST_ESTIMATE_PROVIDER_RATE_MISSING { provider }` — the policy doesn't declare rates for one of the configured providers. The estimate is approximate without rates; the operator can pass `--ignore-missing-rates` to get a token-only projection.

---

## §12 — `raxis-cli submit plan --dry-run`

### 12.1 Purpose

Run the full admission check chain ([`plan-bundle-sealing.md §8.1`](plan-bundle-sealing.md) + [`policy-plan-authority.md §5`](policy-plan-authority.md)) but do NOT seal anything to the store and do NOT create an initiative. Free iteration loop.

### 12.2 Invocation

```bash
raxis-cli submit plan <plan.toml> --dry-run [--initiative-id <id>]
```

`--dry-run` is the differentiator. Without it, `submit plan` is the canonical Plan Bundle Sealing entry point per [`plan-bundle-sealing.md §4`](plan-bundle-sealing.md).

### 12.3 Behavior

Identical to `submit plan` through phase 9 (IPC submit), but the IPC envelope is `OperatorRequest::DryRunAdmit { plan_bundle, signature, ... }` instead of `CreateInitiative`. The kernel runs every admission check (steps 0a–0d Plan Bundle Sealing + step 1+ profile/role/image), but on success it does NOT insert into `plan_bundles`, does NOT create the initiative row, and does NOT charge any quota. On failure, the same FAIL codes are returned as a real submission would produce.

The bundle is still signed with the operator key (so the kernel can verify the operator's authority to dry-run against this policy, which prevents random callers from probing admission rules). The signature is otherwise discarded after the dry-run completes.

### 12.4 Output

On success:

```text
✓ Admission check passed.
  Bundle SHA-256:     abcd1234...
  Resolved DAG:       3 tasks, 2 edges
  Estimated cost:     $0.72 typical / $1.44 worst-case
  Would create initiative: <generated id>

This was a dry-run. No state was modified. Run `submit plan` (without --dry-run) to actually create the initiative.
```

On failure: same output as a real submission failure, with `[DRY-RUN]` prefix on the FAIL line.

### 12.5 Audit

A single low-priority `DryRunAdmitted` audit event is emitted per call (rate-limited per operator). Recording it lets operators correlate "I dry-ran this exact plan at time T" against later live submissions.

---

## §13 — `raxis-cli initiative watch`

### 13.1 Purpose

Live tail of an initiative. Operator's pane of glass for active work.

### 13.2 Invocation

```bash
raxis-cli initiative watch <initiative_id> [--follow] [--task <id>] [--format pretty|json]
```

| Flag | Default | Effect |
|---|---|---|
| `--follow`, `-f` | on | Keep the connection open and stream new events. Pass `--no-follow` to print the current snapshot and exit. |
| `--task` | (none) | Filter to events for a specific task. |
| `--format` | `pretty` | `pretty` is the human-friendly TUI rendering; `json` is one event per line for tooling integration. |

### 13.3 Pretty output

```text
Initiative: <id>  ─  Status: Executing  ─  Started: 12 minutes ago

DAG STATUS:
  ✓ implement_feature   Completed (8m32s)   1 commit
  ▸ review_feature      Active     (2m14s)  1 review submitted
  ◌ merge_feature       Queued

LIVE ACTIVITY:
  [review_feature]  T+02:14  reading src/feature.rs (lines 120-180)
  [review_feature]  T+02:18  invoking lookup_symbol("FeatureHandler")
  [review_feature]  T+02:24  composing review submission

PENDING ESCALATIONS:
  (none)

Press 'a' to approve all pending escalations, 'q' to quit, '?' for help.
```

### 13.4 IPC

Subscribes to `KernelPush::InitiativeEvent { initiative_id, event }` for the targeted initiative. The kernel filters its push stream server-side to avoid sending unrelated initiative events to the operator.

---

## §14 — `raxis-cli initiative resume`

### 14.1 Purpose

Single command to resume a paused initiative. The pause cause (token-limit exceeded, escalation pending, etc.) is auto-detected; the appropriate kernel IPC is sent.

### 14.2 Invocation

```bash
raxis-cli initiative resume <initiative_id> [--reason <text>]
```

### 14.3 Behavior

```text
1. Open operator socket.
2. Send OperatorRequest::DescribeInitiativePause { initiative_id }.
3. Kernel responds with the pause cause (TokenBudgetExceeded, EscalationPending,
   PolicyEpochDriftHalt, etc.) and the recommended remediation IPC.
4. CLI prompts the operator (interactively, or accepts via flags) to confirm
   the remediation:
   - For TokenBudgetExceeded: prompt to grant additional budget.
   - For EscalationPending: print the escalation; prompt to approve / reject.
   - For PolicyEpochDriftHalt: print the drifted fields; prompt to acknowledge
     and proceed under the current epoch.
5. Send the corresponding IPC; await confirmation.
6. Report new initiative state.
```

### 14.4 Why a single command

Today an operator faced with a paused initiative must look up the pause cause, find the right `raxis-cli` subcommand for that cause, construct the right arguments, and invoke it. `initiative resume` collapses this into one decision tree and one prompt flow.

### 14.5 Failure modes

`FAIL_INITIATIVE_NOT_PAUSED { state }` — the initiative is not in a paused state; nothing to resume.

---

## §15 — `raxis-cli initiative list`

### 15.1 Purpose

Operator overview of in-flight and recent work. The **v1 baseline** ships a four-bucket read-only listing — see `cli-readonly.md §5.5.6b` for the canonical v1 spec. **V2 strictly extends** the v1 surface: it adds flags (`--mine`, `--since`, `--format`), adds per-row columns (operator, task progress, description), and accepts a richer set of `--state` values (canonical FSM states + `paused` once `initiative resume` is wired in §14). It NEVER removes or changes the meaning of any v1 flag — a v1-style invocation `raxis initiative list --state active` continues to work unchanged on a v2 deployment.

### 15.2 Invocation

```bash
raxis-cli initiative list [--state <s>] [--mine] [--limit <n>] [--since <duration>] [--format table|json] [--json]
```

| Flag | Default | Effect | Origin |
|---|---|---|---|
| `--state` | `active` (v1 default; v2 keeps it) | v1 buckets: `active`, `completed`, `quarantined`, `all`. **v2 additions**: also accept the canonical FSM states `Draft`, `ApprovedPlan`, `Executing`, `Blocked`, `Paused`, `Completed`, `Failed`, `Aborted`, comma-separated. The four v1 buckets are sugar that expands to the underlying state set. | v1 + v2 ext. |
| `--limit` | `50` (v1) / `20` (v2 default after §15.4 migration) | Maximum rows. v2 lowers the default after the description column lands so the table fits one screen. | v1 + v2 tweak |
| `--json` | off | Emit one JSON object instead of the human table. v1 alias for `--format json`. | v1 |
| `--mine` | off | **v2 only.** Filter to initiatives whose plan was signed by the currently-loaded operator key (`signed_plan_artifacts.signed_by_fingerprint == <my fingerprint>`). | v2 |
| `--since` | (none) | **v2 only.** Filter to initiatives created since the given duration (e.g. `24h`, `7d`). Parsed via the v1 duration grammar in `cli-readonly.md §5.5.4 (raxis log)`. | v2 |
| `--format` | `table` | **v2 only.** `table` for human reading, `json` for tooling. Mutually exclusive with `--json`; combining the two is a usage error. `--json` remains supported for v1-script compatibility. | v2 |

### 15.3 Output

**v1 baseline** (the `cli-readonly.md §5.5.6b` table; ships today):

```text
Initiatives (state=active, 3 rows):
  initiative_id              state          [Q]  created (rel) plan_sha256
  01J8…init-x                Executing           12m           abc123…
  01J8…init-y                Blocked        [Q]  1h            def456…
  01J8…init-z                Draft               2h            beef00…
```

**v2 extension** (adds `OPERATOR`, `TASKS`, `DESCRIPTION` columns; the `[Q]` flag remains):

```text
ID                                    STATE       OPERATOR        AGE     TASKS    DESCRIPTION
01H8Q7K2J9...                         Executing   alice:f3a2...   12m     2/4      Add dark mode toggle
01H8P4R3M1...                         Completed   bob:91cd...     2h      4/4      Bump axum to 0.7
01H8M2X8N5...                         Paused      alice:f3a2...   1d      1/3      Refactor auth flow (escalation pending)
```

The v2 columns require:

- **OPERATOR** column → `signed_plan_artifacts::header_by_initiative` joined into the listing query, then routed through `cli/src/operator_display::format_operator_with_lookup` (same convention as `raxis initiative show`, `raxis log`, `raxis inbox`).
- **TASKS** column → a `views::tasks::counts_by_initiative(initiative_id) -> (terminal: u32, total: u32)` per-row aggregate. The aggregate must be a single SQL query over the row set (a `GROUP BY initiative_id` against `tasks`), NOT a per-row `COUNT(*)`, so the listing remains O(1) DB round-trips.
- **DESCRIPTION** column → reads `signed_plan_artifacts.plan_bytes`, parses the TOML, and surfaces the top-level `description = "..."` field. Truncated to 80 chars in the human render. Behind a TODO until `plan prepare` writes a canonical `description` field per §5.

### 15.4 Implementation plan (v2)

1. **Reuse the v1 store seam.** `views::initiatives::list_filtered` already accepts the v1 `InitiativeListFilter`. Add a richer `InitiativeListFilterV2` enum (or extend the existing one with a `Custom { states: Vec<&'static str> }` variant) that supports comma-separated FSM-state values and the v2 `--since` predicate. The v1 buckets desugar to v2 state sets so the v1 path stays unchanged.
2. **Extend the row shape.** Add `InitiativeListRowV2 { v1: InitiativeListRow, signed_by: Option<OperatorFingerprint>, task_counts: TaskCounts, description: Option<String> }` so the new render columns are populated by a single round-trip. Keep `InitiativeListRow` (v1) as the narrower projection — the v1 CLI never pays for the v2 joins.
3. **Wire the new flags.** `cli/src/commands/initiatives.rs` gains a `parse_args_v2` path that accepts the v2 flag set, with a mutual-exclusion check between `--json` and `--format json`. Keep the v1 parser as the authoritative one for the v1 binary; v2 is a shim that delegates back when only v1-known flags are present.
4. **Tests.** Mirror `cli-readonly.md §5.9` — one golden fixture per render variant (table v2, JSON v2), plus a "v1 invocation on v2 binary" round-trip that pins forward compatibility.

---

## §16 — `raxis-cli setup wizard`

### 16.1 Purpose

Interactive first-run setup. Generates the operator's keypair, walks through a minimum-viable `policy.toml`, configures provider credentials, smoke-tests the kernel, and submits a "hello world" initiative.

### 16.2 Invocation

```bash
raxis-cli setup wizard [--non-interactive --config <path>]
```

`--non-interactive` reads inputs from a YAML config file; suitable for CI-driven deployments that want to script the wizard.

### 16.3 Phases

```yaml
1. Greeting + sanity checks:
   - Verify the kernel daemon is reachable on the operator socket.
   - Verify the data directory is writable.
   - Verify the host meets requirements per system-requirements.md
     (Linux 5.14+, cgroup v2, AVF or KVM available).

2. Operator key generation:
   - Prompt for a key passphrase.
   - Generate Ed25519 keypair; write to ~/raxis/op.key (chmod 0600).
   - Print the public key fingerprint for the operator to record.

3. Provider credential entry (per provider-model-selection.md §9.1):
   - Prompt for credentials for each supported provider:
     [1] Anthropic API key  (sk-ant-...)
     [2] OpenAI API key     (sk-...)
     [3] Google API key     (AIza...)
     [4] Custom provider via [[providers]] schema (advanced)
   - Press enter to skip any provider; at least one MUST be entered.
   - Recommend 2+ for cross-provider failover.
   - Ask: "Auto-diversify across providers when 2+ are configured? [Y/n]"

   For each entered key:
     a. Smoke-test against the provider's lightest authenticated endpoint
        (e.g., models.list); reject and re-prompt on 401.
     b. Write key to <data_dir>/providers/<provider>.toml (chmod 0600,
        owner: kernel OS user). This is the canonical on-disk location;
        the gateway loads from here at startup. The key NEVER lands in
        the operator-readable plan or policy bundle in plaintext —
        only the key_ref (a SHA-256-derived label) appears in policy.
     c. Compute the artifact-store key_ref per v1/peripherals.md §3.
     d. Append [[providers.credentials]] entry to in-progress
        policy.toml:
            [[providers.credentials]]
            provider_id = "anthropic"
            key_ref     = "anthropic-prod-2026-q1"

4. Permitted models (per provider-model-selection.md §9.2):
   - Show recommended set covering the §4 default chains for the
     configured-provider count:
       [✓] anthropic:claude-4.6-sonnet-medium-thinking
       [✓] anthropic:claude-opus-4.7-thinking-medium
       [✓] openai:gpt-5.3-codex
       [ ] google:gemini-2.5-pro     (auto-checked if Google configured)
       [ ] google:gemini-2.5-flash   (auto-checked if Google configured)
       [+] Add more...
   - "Use the recommended set? [Y/n/customize]"
   - Selected set lands in policy.toml [providers] permitted_models
     (INV-PROVIDER-01).

5. Per-role inference chain generation (per provider-model-selection.md §9.3):
   - Run the §5.2 auto_diversify algorithm against configured providers.
   - For 2+ providers + auto-diversification accepted:
       Orchestrator primary on providers[0] (Anthropic in the typical
                          two-provider example); fallback on providers[1].
       Reviewer primary on providers[1] (a DIFFERENT provider for
                          cross-role diversification under outage);
                          fallback on providers[0].
       Executor follows Orchestrator (high-volume role co-located on
                          the same provider as Orchestrator to keep
                          steady-state load distribution sensible).
   - Generated lands in policy.toml as:
       [orchestrator] provider_alias = "orchestrator_default"
       [provider_aliases.orchestrator_default] chain = [...]
       [provider_aliases_defaults.reviewer]    chain = [...]
       [provider_aliases_defaults.executor]    chain = [...]
   - Display the generated chains; ask "Customize chains? [N/y]"

6. Language-stack selection (per verifier-processes.md §14.5
   tiered language starters):
   - Detect available canonical images on disk:
     scan $RAXIS_INSTALL_DIR/images/ for raxis-verifier-{rust,node,
     python,go}-starter-<kernel_version>.img and the kernel-canonical
     raxis-verifier-symbol-index-<kernel_version>.img.
   - Show the available languages and ask which the deployment
     targets:
       Symbol-index verifier (always required for full Reviewer
                              fidelity per INV-VERIFIER-12)
         [✓] raxis-verifier-symbol-index           (12 MiB, kernel-canonical)
       Tiered language starters (verifier images for common test/lint
                                  workflows; pick what your plans use)
         [ ] raxis-verifier-rust-starter           (450 MiB)
         [ ] raxis-verifier-node-starter           (380 MiB)
         [ ] raxis-verifier-python-starter         (290 MiB)
         [ ] raxis-verifier-go-starter             (210 MiB)
       Custom verifier images (advanced — declare in policy after
                               wizard completes)
   - For each starter the operator selects, the wizard reads the
     image's release-notes-published digest from a manifest shipped
     alongside the kernel binary (release-notes-digests.toml), then:
       a. Verify the on-disk image SHA-256 matches the manifest's
          digest. Mismatch → re-download the image; retry up to 2x;
          on persistent failure print a hard error and abort the
          wizard with actionable mitigations (re-install RAXIS, etc.).
       b. Append a [[vm_images]] entry to in-progress policy.toml:
            [[vm_images]]
            alias            = "raxis-verifier-rust-starter"
            oci_digest       = "sha256:..."
            role_restriction = ["Verifier"]
       c. Append the alias to [default_verifier_images]:
            [default_verifier_images]
            rust = "raxis-verifier-rust-starter"
       d. Inform the operator: "Plan authors can now write
          `image = \"@rust\"` in [[plan.tasks.<id>.verifiers]] and
          `plan prepare` will substitute the alias automatically per
          operator-ergonomics.md §4.2."
   - The symbol-index image is always installed (not opt-out) when
     [prepare] auto_inject_symbol_index = true (default), since it is
     structural for Reviewer correctness per INV-VERIFIER-12. The
     wizard explicitly tells the operator: "Symbol-index verifier is
     required for full Reviewer fidelity. Disable auto-injection
     later via policy.toml [prepare] auto_inject_symbol_index = false
     if you need to (e.g., for image-bundle size constraints in
     air-gapped deployments)."
   - Set policy.toml [prepare] auto_inject_symbol_index = true
     (this is the V2 default per policy-plan-authority.md §4 [prepare];
     the wizard makes it explicit so the operator sees it in the
     generated policy file).

7. Policy bootstrap (final assembly):
   - Combine outputs from phases 2-6 with hardcoded defaults to produce
     a complete policy.toml:
     - The operator's public key in [[operators.entries]].
     - The provider credentials and permitted models from phases 3-4.
     - The per-role alias chains from phase 5.
     - The selected verifier-image [[vm_images]] entries and
       [default_verifier_images] table from phase 6.
     - [prepare] auto_inject_symbol_index = true (from phase 6).
     - Default token budgets per role ([token_policy_defaults.<role>]).
     - The kernel-canonical Executor starter image as
       [default_executor_image] (only if the operator opted into it
       earlier; setup wizard flow defaults to opt-in but offers
       --no-executor-starter for slim deployments).
     - Default protected paths ([default_protected_paths]).
   - Sign the policy bundle with the operator key.
   - Advance the policy epoch with
     `raxis epoch advance --policy <policy.toml> --sig <policy.sig>`.

8. Canonical image verification:
   - Run `raxis doctor canonical-images` (§17.4) to verify that all
     bundled canonical images (Reviewer, Orchestrator, Executor starter,
     symbol-index verifier, and any selected language starters) are
     present and digest-verified per system-requirements.md §11.1.

9. Smoke test:
   - Generate a tiny "hello world" plan: one Executor task that prints
     a greeting. The plan omits [provider_aliases.executor]; plan
     prepare fills it from policy default. The plan touches no source
     files, so the symbol-index auto-injection is a no-op — confirming
     the no-op path is correct.
   - If the operator selected at least one language starter in phase 6,
     ALSO run a second smoke plan: one Executor task that touches a
     trivial source file in the selected language plus a per-task
     verifier with `image = "@<lang>"`. Confirms the @-shortcut
     resolution path AND the symbol-index auto-injection path both
     work end-to-end.
   - Run `plan prepare`, `submit plan`, then poll for completion.
   - Verify the audit chain shows the expected events including
     InferenceRequest naming the actual_model_used from the operator's
     chain, plus VerifierActivated and VerifierCompleted events for
     both the symbol-index verifier and the @-shortcut verifier.

10. Done:
    - Print a summary: operator fingerprint, data directory, policy epoch,
      configured providers, generated alias chains, selected language
      stacks, smoke-test result.
    - Surface the on-disk credential paths so the operator knows where
      keys live (<data_dir>/providers/<provider>.toml).
    - Suggest next commands: `plan init`, `plan validate`, `submit plan`,
      `setup wizard --add-provider <id>` (to add a provider later),
      `setup wizard --add-language <lang>` (to add a verifier language
      starter later).
```

**Two-credential-system note.** Phase 3 above writes **provider
credentials** (System 1 per `paradigm.md §5.1` and
[`provider-model-selection.md §8.1`](provider-model-selection.md)) — the LLM API keys consumed by
the gateway subprocess for inference. **Operator credentials**
(System 2 — kubeconfig, AWS keys, registry tokens injected into
agent VMs as env vars) are NOT touched by this wizard. They are
configured separately via `raxis-cli credentials add` per
`v1/cli-ceremony.md`, and they live in the entirely separate store
`<data_dir>/credentials/<name>.env`. The wizard intentionally keeps
the two systems' first-time configuration paths apart so operators
build the right mental model from day one.

### 16.4 Idempotency

Re-running the wizard on an already-set-up deployment offers to skip phases that are already complete (e.g., "operator key already exists at ~/raxis/op.key — skip key generation? [Y/n]").

---

## §17 — `raxis-cli doctor` (Extensions)

### 17.1 Existing categories

`raxis-cli doctor canonical-images` already exists per [`system-requirements.md §11.1`](system-requirements.md) and covers Reviewer + Orchestrator (and is extended in this spec to include the Executor starter image).

### 17.2 New categories

| Category | What it checks |
|---|---|
| `policy` | Currently-loaded policy bundle parses, signature verifies against a known operator key, schema is current. |
| `providers` | Each configured provider in `policy.providers` is reachable; sends a one-token completion to verify credentials are valid. |
| `host` | OS version, kernel version, cgroup v2 mounted at expected path, AVF/KVM availability, disk capacity in `data_dir`. |
| `network` | Reachability of every distinct hostname in the policy's `[[egress_hosts]]` list (TCP connect; no actual HTTP). |
| `keys` | Operator key trust state per [`key-revocation.md`](key-revocation.md); lists each key's fingerprint, state (Active/Rotated/Compromised), and admission scope. |
| `bundles` | Storage utilization of `plan_bundles` and `plan_bundle_artifacts` tables; flags any bundles approaching the SQLite blob ceiling. |

### 17.3 Invocation

```bash
raxis-cli doctor [<category>] [--all] [--json]
```

`raxis-cli doctor all` runs every category and prints a consolidated report.

### 17.4 Canonical-images extension

Updated category covers the V2 set:

```bash
$ raxis-cli doctor canonical-images
Reviewer image:           ✓ raxis-reviewer-core@sha256:abcd... (matches manifest)
Orchestrator image:       ✓ raxis-orchestrator-core@sha256:efgh... (matches manifest)
Executor starter:         ✓ raxis-executor-starter@sha256:ijkl... (matches manifest)
Symbol-index verifier:    ✓ raxis-verifier-symbol-index@sha256:mnop... (matches kernel-embedded digest)
Rust starter (verifier):  ✓ raxis-verifier-rust-starter@sha256:qrst... (matches policy [[vm_images]] oci_digest)
Node starter (verifier):  ✓ raxis-verifier-node-starter@sha256:uvwx... (matches policy [[vm_images]] oci_digest)
Python starter (verifier): ⓘ not installed (policy does not reference [default_verifier_images].python)
Go starter (verifier):    ⓘ not installed (policy does not reference [default_verifier_images].go)
```

A digest mismatch on any canonical image fails the category and surfaces the corresponding `FAIL_*_IMAGE_DIGEST_MISMATCH` from [`policy-plan-authority.md §3b`](policy-plan-authority.md). Canonical-image trust model differs by image:

- **Kernel-embedded** (Reviewer, Orchestrator, symbol-index verifier): kernel binary contains a compiled-in `EXPECTED_*_IMAGE_DIGEST`; mismatch is `FAIL_*_IMAGE_DIGEST_MISMATCH` and the corresponding role/verifier cannot run until resolved.
- **Operator-pinned** (Executor starter, language verifier starters): kernel verifies against the policy's `[[vm_images]] oci_digest`; mismatch is `WARN_DEFAULT_*_IMAGE_DIGEST_DRIFT` (no in-flight session) or `FAIL_DEFAULT_*_IMAGE_DIGEST_MISMATCH` (in-flight session). Operators can rotate the policy to pin a new digest without reinstalling the kernel.

---

## §18 — Policy Schema Additions

The following sections are added to `policy.toml` per [`policy-plan-authority.md §4`](policy-plan-authority.md). All are optional; absence means "no defaulting for that field."

### 18.1 `[default_executor_image]`

```toml
[default_executor_image]
alias       = "raxis-executor-starter"   # the canonical starter image alias
fallback    = "skip"                     # what `plan prepare` does when the alias is missing:
                                          #   "skip" — leave vm_image unfilled; submission fails
                                          #            with FAIL_PLAN_REQUIRES_PREPARE
                                          #   "error" — `plan prepare` itself fails with
                                          #            FAIL_POLICY_DEFAULT_UNRESOLVABLE
```

The alias must resolve to a `[[vm_images]]` entry with `role_restriction` containing `"Executor"`. Absent or non-resolvable → `FAIL_POLICY_DEFAULT_EXECUTOR_IMAGE_UNRESOLVABLE` at policy load.

### 18.2 `[token_policy_defaults]`

```toml
[token_policy_defaults.executor]
input_tokens_per_session  = 500_000
output_tokens_per_session = 50_000

[token_policy_defaults.reviewer]
input_tokens_per_session  = 200_000
output_tokens_per_session = 20_000
```

Per-role defaults consumed by `plan prepare` for tasks that omit `[plan.tasks.<id>.token_policy]`. Roles not declared get no default (the field stays unfilled; submission fails with `WARN_UNCAPPED_TOKEN_LIMIT` or `FAIL_PLAN_REQUIRES_PREPARE` depending on `--strict` mode).

Orchestrator and Reviewer roles also declare defaults; the kernel's existing per-role budget mechanisms (e.g., `[orchestrator] max_token_budget_per_initiative`) are unaffected — those are runtime ceilings, not authoring defaults.

### 18.3 `[default_protected_paths]`

```toml
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

`plan prepare` takes the union of this list and the operator-declared `[plan.protected_paths]`, deduplicated. Operators who explicitly want one of these paths to be unprotected (e.g., a task whose purpose is to manipulate `.git/` for repo migration) must declare an explicit `[plan.protected_paths]` that omits the path AND pass `--ignore-policy-protected-paths` to `plan prepare`. This is a deliberate friction point: removing a default protected path is a policy-floor exception that should require operator acknowledgment.

### 18.4 `[prepare]`

```toml
[prepare]
auto_upgrade_defaults = false   # default; production-safe
                                 # when true, `plan prepare` silently updates
                                 # default-value drift without requiring
                                 # --upgrade-defaults; useful for dev environments
```

This is the dev-mode escape hatch from D7. Production policies leave it `false`; dev policies may enable it for frictionless iteration.

---

## §19 — IPC Schema Additions

### 19.1 New operator-socket requests

```rust
// §5: plan prepare
OperatorRequest::ProposeDefaults {
    plan_bytes:        Vec<u8>,
    cli_version:       String,
    upgrade_defaults:  bool,
}

OperatorResponse::DefaultsProposed {
    augmented_plan_bytes: Vec<u8>,
    defaulted_fields:     Vec<DefaultedField>,
    upgraded_fields:      Vec<UpgradedField>,
    drift_pending_fields: Vec<DriftField>,
}

// §11: plan cost-estimate
OperatorRequest::EstimateCost {
    plan_bytes: Vec<u8>,
    scenario:   CostScenario,         // Typical | WorstCase
}

OperatorResponse::CostEstimated {
    per_task: Vec<TaskCost>,
    total:    InitiativeCost,
}

// §12: submit plan --dry-run
OperatorRequest::DryRunAdmit {
    plan_bundle:     Vec<u8>,
    bundle_sha256:   [u8; 32],
    signature:       [u8; 64],
    signed_by:       OperatorFingerprint,
}

OperatorResponse::DryRunAdmitted {
    bundle_sha256:    [u8; 32],
    resolved_dag:     DagSummary,
    estimated_cost:   Option<InitiativeCost>,
}

// §13: initiative watch
OperatorRequest::SubscribeInitiative {
    initiative_id: InitiativeId,
}
// Response: stream of KernelPush::InitiativeEvent

// §14: initiative resume
OperatorRequest::DescribeInitiativePause {
    initiative_id: InitiativeId,
}
OperatorResponse::InitiativePauseDescribed {
    cause:                InitiativePauseCause,
    recommended_action:   RecommendedAction,
}
```

All new IPC requests MUST go through the existing operator-socket challenge-response handshake; no new authentication path is introduced.

### 19.2 New audit events

```rust
AuditEventKind::DefaultsProposed {
    proposed_at:           u64,
    operator_fingerprint:  OperatorFingerprint,
    plan_bytes_sha256:     [u8; 32],
    augmented_bytes_sha256: [u8; 32],
    defaulted_field_count: u32,
    upgraded_field_count:  u32,
}

AuditEventKind::DryRunAdmitted {
    dryrun_at:             u64,
    operator_fingerprint:  OperatorFingerprint,
    bundle_sha256:         [u8; 32],
    outcome:               DryRunOutcome,    // Success | Rejected { code }
}
```

Both events are rate-limited per operator fingerprint to prevent DoS via repeated calls.

---

## §20 — Failure Codes

| Code | Phase | Trigger |
|---|---|---|
| `FAIL_PLAN_REQUIRES_PREPARE { missing_fields }` | `submit plan` admission | The plan omits at least one defaultable field whose policy default is set, indicating the operator did not run `plan prepare` first. |
| `FAIL_PREPARE_DEFAULT_UPGRADE_REQUIRED { fields }` | `plan prepare` IPC | At least one annotated field's policy-default value has drifted; `--upgrade-defaults` not passed. |
| `FAIL_PLAN_FIELD_NOT_DEFAULTABLE { field }` | `plan prepare` IPC | The operator placed `# @raxis-default` on a field NOT in §4.2's defaultable set. |
| `FAIL_POLICY_DEFAULT_UNRESOLVABLE { field }` | `plan prepare` IPC | A defaultable field requires a policy value the policy doesn't declare (e.g., `[default_executor_image] alias` is set but the alias doesn't resolve to a `[[vm_images]]` entry). |
| `FAIL_POLICY_DEFAULT_EXECUTOR_IMAGE_UNRESOLVABLE` | Policy load | `[default_executor_image] alias` doesn't resolve to a `[[vm_images]]` entry whose `role_restriction` includes `"Executor"`. |
| `FAIL_PLAN_INIT_TEMPLATE_NOT_FOUND { name }` | `plan init` (CLI-local) | Template not in CLI-bundled set. |
| `FAIL_PLAN_INIT_OUTPUT_EXISTS { path }` | `plan init` (CLI-local) | Output path already exists; `--force` not passed. |
| `FAIL_COST_ESTIMATE_PROVIDER_RATE_MISSING { provider }` | `plan cost-estimate` IPC | Policy doesn't declare rates for a configured provider. |
| `FAIL_INITIATIVE_NOT_PAUSED { state }` | `initiative resume` | Initiative is not in a paused state; nothing to resume. |
<!-- spec-graph:cross-ref-row -->
| `FAIL_POLICY_PROVIDER_ALIAS_DEFAULT_REFERENCES_NONPERMITTED_MODEL { role, missing_models }` | Policy load (cross-reference) | A `[provider_aliases_defaults.<role>] chain` entry references a model not in `[providers] permitted_models`. Canonical home: [`provider-model-selection.md §10`](provider-model-selection.md). |
<!-- spec-graph:cross-ref-row -->
| `FAIL_POLICY_PROVIDER_ALIAS_DEFAULT_MISSING_CREDENTIAL { role, missing_provider }` | Policy load (cross-reference) | A `[provider_aliases_defaults.<role>] chain` entry references a provider with no `[[providers.credentials]]` entry. Canonical home: [`provider-model-selection.md §10`](provider-model-selection.md). |
<!-- spec-graph:cross-ref-row -->
| `FAIL_POLICY_PROVIDER_ALIAS_DEFAULT_EMPTY_CHAIN { role }` | Policy load (cross-reference) | A declared `[provider_aliases_defaults.<role>]` has an empty `chain`. Canonical home: [`provider-model-selection.md §10`](provider-model-selection.md). |
<!-- spec-graph:cross-ref-row -->
| `FAIL_POLICY_PROVIDER_ALIAS_DEFAULT_UNKNOWN_FALLBACK_BEHAVIOR { role, value }` | Policy load (cross-reference) | `fallback_behavior` is not `"attempt_in_order"`. Canonical home: [`provider-model-selection.md §10`](provider-model-selection.md). |
<!-- spec-graph:cross-ref-row -->
| `WARN_PROVIDER_ALIAS_DEFAULT_UNKNOWN_ROLE { role }` | Policy load (cross-reference) | `[provider_aliases_defaults.<role>]` declares a role name other than `executor` or `reviewer`. Non-fatal. Canonical home: [`provider-model-selection.md §10`](provider-model-selection.md). |
<!-- spec-graph:cross-ref-row -->
| `WARN_PROVIDER_ALIAS_PRIMARY_NO_FAILOVER { alias }` | Policy load (cross-reference) | Single-element chain in a deployment with 2+ configured providers. Non-fatal. Canonical home: [`provider-model-selection.md §10`](provider-model-selection.md). |
<!-- spec-graph:cross-ref-row -->
| `WARN_ORCHESTRATOR_DEFAULT_ALIAS_RENAMED { alias }` | Policy load (cross-reference) | V1 default name `"fast_low_cost"` still in use; recommends rename to `"orchestrator_default"`. Non-fatal V1→V2 migration aid. Canonical home: [`provider-model-selection.md §10`](provider-model-selection.md). |
<!-- spec-graph:cross-ref-row -->
| `FAIL_POLICY_DEFAULT_VERIFIER_IMAGE_UNRESOLVABLE { language, alias }` | Policy load (cross-reference) | A `[default_verifier_images].<language>` value doesn't resolve to a `[[vm_images]]` entry whose `role_restriction` includes `"Verifier"`. Canonical home: [`policy-plan-authority.md §3b`](policy-plan-authority.md). |
<!-- spec-graph:cross-ref-row -->
| `WARN_DEFAULT_VERIFIER_IMAGE_UNKNOWN_LANGUAGE { language }` | Policy load (cross-reference) | `[default_verifier_images].<language>` declares a language other than the V2 recognized set (`rust`, `node`, `python`, `go`). Non-fatal. Canonical home: [`policy-plan-authority.md §3b`](policy-plan-authority.md). |
| `FAIL_PLAN_VERIFIER_IMAGE_SHORTCUT_UNRESOLVABLE { task_id, verifier_name, shortcut }` | `plan prepare` IPC | Plan declares `image = "@<lang>"` but `[default_verifier_images].<lang>` is not configured. Operator either sets the policy entry (typical fix) or replaces the shortcut with the literal alias. |
<!-- spec-graph:cross-ref-row -->
| `FAIL_POLICY_RESERVED_VM_IMAGE_NAME { name }` | Policy load (cross-reference) | A `[[vm_images]]` entry uses a reserved alias (`"raxis-verifier-symbol-index"`). Reserved per `INV-VERIFIER-12`. Canonical home: [`policy-plan-authority.md §3b`](policy-plan-authority.md). |
| `FAIL_REVIEWER_PATH_ALLOWLIST_NOT_ALLOWED { task_id }` | `approve_plan` (cross-reference) | A Reviewer task declares `path_allowlist`. Reviewer's `/workspace` is RO and the harness has no commit-pathway intent; the field is structurally meaningless. `plan prepare` aborts with the §4.5.5 hard-refusal pre-signing. Canonical home: [`policy-plan-authority.md §3b`](policy-plan-authority.md). |
| `FAIL_PLAN_REQUIRES_EXPLICIT_PATH_ALLOWLIST { task_id }` | `approve_plan` (cross-reference) | An Executor task omits `path_allowlist` entirely. Run `plan prepare` to insert the §4.5.3 template; uncomment and customize. Canonical home: [`policy-plan-authority.md §3b`](policy-plan-authority.md). |
| `FAIL_EXECUTOR_EMPTY_PATH_ALLOWLIST_UNACKNOWLEDGED { task_id }` | `approve_plan` (cross-reference) | An Executor task declares `path_allowlist = []` without the `# @raxis-explicit no-write-acknowledged` annotation. Either populate the array or add the annotation per §4.5.4. Canonical home: [`policy-plan-authority.md §3b`](policy-plan-authority.md). |
| `FAIL_PATH_ALLOWLIST_INVALID_SYNTAX { task_id, entry, reason }` | `approve_plan` (cross-reference) | A `path_allowlist` entry violates the §6 table-4 syntax (glob characters, absolute path, `..`, missing trailing slash for known directory). Canonical home: [`policy-plan-authority.md §3b`](policy-plan-authority.md). `plan prepare` surfaces the same warning at phase 2.f pre-signing. |

`FAIL_PLAN_REQUIRES_PREPARE` is the only one that fires during `submit plan`. Its `missing_fields` array is populated with the §4.2 fields that the plan omitted; the operator runs `plan prepare` to fill them.

`FAIL_PLAN_REQUIRES_EXPLICIT_PATH_ALLOWLIST` and `FAIL_REVIEWER_PATH_ALLOWLIST_NOT_ALLOWED` are conceptually parallel to `FAIL_PLAN_REQUIRES_PREPARE` but for the §4.5 explicit-required-fields class — the kernel cannot default the value, so the operator must author it themselves; `plan prepare` provides the template-and-suggestion ergonomic surface.

The `FAIL_POLICY_PROVIDER_ALIAS_DEFAULT_*` and `WARN_PROVIDER_ALIAS_*` codes fire at policy load and prevent the new policy bytes from being adopted; in-flight initiatives keep running on the previously-loaded policy until the operator fixes the policy and advances the epoch again.

---

## §21 — Cross-Spec Impacts

| Spec | Change |
|---|---|
| [`planner-harness.md`](planner-harness.md) | New §10.6 "Canonical Executor Starter Image Manifest" parallel to the Reviewer/Orchestrator manifests. No new invariant — the starter image is a defaulting target, not a structural constraint (operators can omit it entirely by pinning their own image). |
| [`policy-plan-authority.md`](policy-plan-authority.md) | New `[default_executor_image]`, `[token_policy_defaults]`, `[default_protected_paths]`, `[prepare]`, `[provider_aliases_defaults]` sections in §4. New `FAIL_PLAN_REQUIRES_PREPARE`, `FAIL_POLICY_PROVIDER_ALIAS_DEFAULT_*`, `WARN_PROVIDER_ALIAS_*`, and related codes in §3b failure catalog. Admission check chain unchanged; the new check is one new pre-step that fires only if the policy declares any defaults. |
| [`provider-model-selection.md`](provider-model-selection.md) | Canonical home for the model-selection guidance and the `[provider_aliases_defaults]` policy schema. The `[provider_aliases.<role>]` rows in §4.2 above are populated from this schema. The setup wizard phases 3-5 (this spec §16.3) implement the §9 wizard surface from [`provider-model-selection.md`](provider-model-selection.md). |
| [`plan-bundle-sealing.md`](plan-bundle-sealing.md) | Adds `FAIL_PLAN_REQUIRES_PREPARE` to §9 failure catalog cross-reference (this spec is the canonical home). Bundle bytes are explicitly post-prepare bytes — the operator signs the prepared plan, not the pre-default plan. From the kernel's perspective there is no "pre-default" bytes; only what's signed in the bundle. |
| [`system-requirements.md`](system-requirements.md) | `raxis-executor-starter-<kernel_version>.img` added to §8.1 bundled artifacts (strongly recommended). `raxis-verifier-symbol-index-<kernel_version>.img` added to §8.1 (kernel-canonical per `INV-VERIFIER-12`). Four `raxis-verifier-{rust,node,python,go}-starter-<kernel_version>.img` added to §8.1 (opt-in; trust is operator-pinned via `[[vm_images]] oci_digest`). `raxis doctor canonical-images` (§11) extended to cover all six new images. |
| [`verifier-processes.md`](verifier-processes.md) | This spec's §4.2 symbol-index auto-injection consumes the canonical `raxis-verifier-symbol-index` image specified there (§14). The `@<language>` shortcut in §4.2 resolves against `[default_verifier_images]` — verifier-processes.md §14.5 owns the tiered language starter image manifests. The setup wizard phase 6 (this spec §16.3) implements the verifier-processes.md §14.5 wizard surface. |
| [`policy-plan-authority.md`](policy-plan-authority.md) (further) | Adds `[default_verifier_images]` and `[prepare] auto_inject_symbol_index` knob to the policy schema. New `FAIL_POLICY_DEFAULT_VERIFIER_IMAGE_UNRESOLVABLE`, `FAIL_POLICY_RESERVED_VM_IMAGE_NAME`, `WARN_DEFAULT_VERIFIER_IMAGE_UNKNOWN_LANGUAGE` codes registered there. |
| [`policy-plan-authority.md`](policy-plan-authority.md) (path-allowlist) | Adds the §3.b admission sub-checks for `FAIL_REVIEWER_PATH_ALLOWLIST_NOT_ALLOWED`, `FAIL_PLAN_REQUIRES_EXPLICIT_PATH_ALLOWLIST`, `FAIL_EXECUTOR_EMPTY_PATH_ALLOWLIST_UNACKNOWLEDGED`, `FAIL_PATH_ALLOWLIST_INVALID_SYNTAX` per [`policy-plan-authority.md §5 step 3.a/3.b`](policy-plan-authority.md). The annotation parser must scan trailing comments on the value line AND the comment line immediately above (same logic as `# @raxis-default`). The kernel records `TaskWriteScope::NoWriteAcknowledged` in `InitiativeCreated` audit events for tasks admitted under the explicit acknowledgement annotation. |
| [`planner-harness.md`](planner-harness.md) (path-allowlist) | `INV-PLANNER-HARNESS-01` extended in its statement to include the structural prohibition of `path_allowlist` on Reviewer tasks — Reviewer's RO `/workspace` and absent commit-pathway intent make the field structurally meaningless. §3 role table cross-references the new §4.5.5 rejection at `plan prepare`. |
| [`integration-merge.md`](integration-merge.md) | Pre-merge verifier hook (Check 5d) is invisible to this spec — the wizard does not configure pre-merge verifiers (out of scope; operators add them later via direct policy edits or per-plan `[[plan.integration_merge_verifiers]]`). The wizard's smoke test does NOT exercise the pre-merge path. |
| `v1/cli-ceremony.md` | V2 supersession notice points to this spec for the V2 authoring/lifecycle CLI surface. The V1 spec retains commands not in this spec's scope. |
| [`custom-tools.md`](custom-tools.md) | No change. Custom tools are not defaulted (out of scope per §2). |
| [`kernel-mechanics-prompt.md`](kernel-mechanics-prompt.md) | No change. The KSB and NNSP rendering are based on the prepared plan bytes; defaulting is invisible to the runtime layer. |
| [`kernel-lifecycle.md`](kernel-lifecycle.md) | The `setup wizard` CLI flow assumes the kernel daemon is already running; daemon startup is [`kernel-lifecycle.md`](kernel-lifecycle.md)'s concern. |
| [`v2-deep-spec.md`](v2-deep-spec.md) | The §6 table 4 path-allowlist syntax (trailing-slash discipline, no globs) is the canonical syntax. This spec's §4.5.6 suggestion mechanism honors it (suggestions always emit trailing slashes for directories). The new §4.5.5 hard refusal for Reviewer-path-allowlist is consistent with the §6 role-asymmetry framing. |

---

## §22 — Implementation Checklist

### CLI side

- [ ] `raxis-cli plan prepare <plan.toml>` per §5. **Status: deferred.** The full surface depends on (a) the kernel-side `OperatorRequest::ProposeDefaults` handler (§5.3, listed below in "Kernel side"), (b) the `[token_policy_defaults]`, `[default_executor_image]`, `[default_verifier_images]`, `[default_protected_paths]`, and `[prepare]` policy sections, and (c) the `@raxis-default` annotation reader/writer (§4.3, §4.4). None of those prerequisites have landed. Until they do, `plan prepare` is intentionally unimplemented; operators write fully-explicit plans and rely on `plan validate` + `plan fmt`. Plans submitted that *would have* required prepare-time defaulting are rejected at admission with `FAIL_PLAN_REQUIRES_PREPARE { missing_fields: [...] }` — a hard-fail that points the operator at this deferred work, never silently filled. The `plan fmt` canonicalizer (above, shipped) is ready to be invoked as `plan prepare`'s final phase the moment the kernel handler lands.
- [ ] `raxis-cli plan init -t <template>` per §6; templates bundled with the CLI binary.
- [ ] `raxis-cli plan validate [--with-kernel] [--explain-environment]` per §7.
- [ ] `raxis-cli plan diff [--format unified|json]` per §8.
- [ ] `raxis-cli plan explain [--task <id>] [--format text|markdown|html]` per §9.
- [x] `raxis-cli plan fmt [--check] [--stdout]` per §10. **Implementation reference:** `raxis/cli/src/commands/plan_fmt.rs`; canonicalizer is `toml_edit`-backed (preserves comments including `@raxis-default` annotations) with a deterministic post-process pass (trailing-whitespace strip, ≤ 1 blank line between rows, single trailing newline). Tests: 7 unit tests + 8 subprocess integration tests in `raxis/cli/tests/plan_fmt_cli.rs`. Will be invoked as `plan prepare`'s final phase once `plan prepare` lands; today operators run it standalone.
- [ ] `raxis-cli plan cost-estimate [--scenario typical|worst-case]` per §11.
- [ ] `raxis-cli submit plan --dry-run` per §12 (extends the existing `submit plan` command).
- [ ] `raxis-cli initiative watch <id> [--follow] [--task]` per §13.
- [ ] `raxis-cli initiative resume <id>` per §14.
- [x] `raxis-cli initiative list [--state] [--limit] [--json]` v1 baseline per `cli-readonly.md §5.5.6b` — landed in v1, not deferred to v2.
- [ ] `raxis-cli initiative list [--mine] [--since] [--format table|json]` v2 extensions per §15 — strictly extend the v1 baseline (added flags + columns; never removes a v1 flag).
- [ ] `raxis-cli setup wizard [--non-interactive --config <path>]` per §16.
- [ ] `raxis-cli doctor [policy|providers|host|network|keys|bundles|all]` per §17.
- [ ] CLI's TOML formatter produces canonical output per §10.3; `plan prepare` invokes it as final phase.
- [ ] Annotation comment writer per §4.3; idempotency reader per §4.4.

### Kernel side

- [ ] `OperatorRequest::ProposeDefaults` handler per §5.3; read-only; does not mutate any kernel state except low-priority audit emission.
- [ ] `OperatorRequest::EstimateCost` handler per §11.3; uses `tokenize` admin interface.
- [ ] `OperatorRequest::DryRunAdmit` handler per §12.3; runs full admission check chain but does NOT seal the bundle.
- [ ] `OperatorRequest::SubscribeInitiative` and `KernelPush::InitiativeEvent` per §13.
- [ ] `OperatorRequest::DescribeInitiativePause` per §14.
- [ ] `[default_executor_image]` policy section parsed and validated; `FAIL_POLICY_DEFAULT_EXECUTOR_IMAGE_UNRESOLVABLE` at policy load.
- [ ] `[default_verifier_images]` policy section parsed and validated; `FAIL_POLICY_DEFAULT_VERIFIER_IMAGE_UNRESOLVABLE`, `WARN_DEFAULT_VERIFIER_IMAGE_UNKNOWN_LANGUAGE` at policy load (per [`policy-plan-authority.md §4 [default_verifier_images]`](policy-plan-authority.md)).
- [ ] `[token_policy_defaults.<role>]` policy section parsed.
- [ ] `[default_protected_paths]` policy section parsed; defaults applied at `plan prepare` time.
- [ ] `[prepare] auto_upgrade_defaults` policy knob respected.
- [ ] `[prepare] auto_inject_symbol_index` policy knob respected; `plan prepare` consults at injection time per §4.2 "Symbol-index auto-injection".
- [ ] `plan prepare` reserved-alias check: rejects any `[[vm_images]]` entry whose alias is `"raxis-verifier-symbol-index"` with `FAIL_POLICY_RESERVED_VM_IMAGE_NAME` (per `INV-VERIFIER-12`); the check fires at policy load, not at `plan prepare` time, but `plan prepare` MUST refuse to operate against a deployment that loaded such a policy successfully (defense-in-depth).
- [ ] `plan prepare` symbol-index auto-injection per §4.2: walk every Executor task; for tasks whose touched paths include source files AND no existing `symbol_index` verifier AND `[plan.tasks.<id>.review] symbol_index ≠ "not_needed"`, inject the canonical entry with annotation `# @raxis-default v0.4.0 symbol-index-auto-inject`.
- [ ] `plan prepare` `@<language>` shortcut resolution per §4.2: walk every `[[plan.tasks.<id>.verifiers]]` and `[[plan.integration_merge_verifiers]]` entry; for entries whose `image` starts with `@`, resolve against `[default_verifier_images].<lang>` and substitute the alias with annotation `# @raxis-default v0.4.0 image-shortcut-resolved`. Unresolvable shortcuts → `FAIL_PLAN_VERIFIER_IMAGE_SHORTCUT_UNRESOLVABLE`.
- [ ] `submit plan` admission gains the `FAIL_PLAN_REQUIRES_PREPARE` pre-check that fires when defaultable fields are omitted AND `[default_*]` policy declares values for them.
- [ ] All §20 FAIL codes registered in `raxis-types::PlannerErrorCode`.
- [ ] `DefaultsProposed` and `DryRunAdmitted` audit events; rate-limiting per operator fingerprint.

### CLI side (path-allowlist ergonomics — §4.5)

- [ ] `plan prepare` phase 2 (local-pre) per §5.2: runs entirely client-side before IPC; covers all §4.5 mechanics.
- [ ] `plan prepare` phase 2.a: detects Reviewer tasks with `path_allowlist` (any value) and aborts with the §4.5.5 hard-refusal message; returns non-zero exit; does not write to disk.
- [ ] `plan prepare` phase 2.b: detects Executor tasks missing `path_allowlist`; inserts the §4.5.3 `# @raxis-required` template; idempotent on re-run when the template marker block is present.
- [ ] `plan prepare` phase 2.b template injection augments with §4.5.6 directory suggestions when a worktree is auto-detected (`git -C $PWD rev-parse --show-toplevel`) OR when `--suggest-from <path>` is passed; falls back to bare template when neither is available OR when `--no-suggest` is set.
- [ ] `plan prepare` phase 2.b suggestion: cross-references `policy.toml [default_protected_paths]`; suggestions matching a protected-path prefix carry the `# DO-NOT-UNCOMMENT (matches protected path: <pattern>)` comment.
- [ ] `plan prepare` phase 2.c: detects when an operator has uncommented and populated the `path_allowlist` array in a task previously carrying the `# @raxis-required` marker block; removes the marker block (the requirement is satisfied).
- [ ] `plan prepare` phase 2.d: detects `path_allowlist = []` with the `# @raxis-explicit no-write-acknowledged` annotation (on the value line OR the comment line immediately above); leaves alone with informational log line.
- [ ] `plan prepare` phase 2.e: detects `path_allowlist = []` WITHOUT the annotation; emits a non-fatal warning explaining `FAIL_EXECUTOR_EMPTY_PATH_ALLOWLIST_UNACKNOWLEDGED` with both remediation paths; does NOT auto-add the annotation per §4.5.4.
- [ ] `plan prepare` phase 2.f: detects `path_allowlist` entries violating §6 table-4 syntax (glob characters `*`/`?`/`[`/`]`/`{`, absolute paths starting with `/`, `..` segments); emits a non-fatal warning per `FAIL_PATH_ALLOWLIST_INVALID_SYNTAX` reasons; submit plan will hard-reject.
- [ ] `--suggest-from <path>` flag per §5.1: validates the path is a git worktree via `git -C <path> rev-parse --git-dir`; errors clearly if not.
- [ ] `--no-suggest` flag per §5.1: skips the §4.5.6 suggestion mechanism entirely; bare template only.
- [ ] Annotation parser shared with `# @raxis-default` (per §4.3): scans trailing comment on the value line AND the comment line immediately above the value line; accepts both forms for `# @raxis-explicit no-write-acknowledged` per §4.5.4.

### Kernel side (path-allowlist ergonomics — §4.5)

- [ ] `approve_plan` admission step 3.a (per [`policy-plan-authority.md §5`](policy-plan-authority.md)) extended to detect Reviewer-task `path_allowlist` and emit `FAIL_REVIEWER_PATH_ALLOWLIST_NOT_ALLOWED`.
- [ ] `approve_plan` admission step 3.b extended with the four new path-allowlist checks (`FAIL_PLAN_REQUIRES_EXPLICIT_PATH_ALLOWLIST`, `FAIL_EXECUTOR_EMPTY_PATH_ALLOWLIST_UNACKNOWLEDGED`, `FAIL_PATH_ALLOWLIST_INVALID_SYNTAX`).
- [ ] Annotation parser kernel-side mirrors the CLI-side parser per §4.3 and §4.5.4: scans trailing comment on the value line AND the comment line immediately above; the `# @raxis-explicit no-write-acknowledged` annotation is the binary opt-in for empty-allowlist Executor tasks.
- [ ] `InitiativeCreated` audit event extended with `task_write_scopes: Vec<TaskWriteScope>` where `TaskWriteScope` is `Bound { paths } | NoWriteAcknowledged | NotApplicable` (the third case for Reviewer/Orchestrator). Schema additive — V1 audit consumers reading the event ignore the new field.
- [ ] All §20 path-allowlist FAIL codes registered in `raxis-types::PlannerErrorCode` (cross-reference [`policy-plan-authority.md §3b`](policy-plan-authority.md) as the canonical home).

### Tests

- [ ] `plan prepare` on a fresh plan with no defaults → all defaultable fields filled with annotations.
- [ ] `plan prepare` on an already-prepared plan with no policy drift → no-op (file unchanged); CLI prints "no changes".
- [ ] `plan prepare` on an already-prepared plan with policy drift → `FAIL_PREPARE_DEFAULT_UPGRADE_REQUIRED` listing drifted fields.
- [ ] `plan prepare --upgrade-defaults` on a drifted plan → values updated, annotation versions bumped.
- [ ] `plan prepare` with `[prepare] auto_upgrade_defaults = true` → silent upgrade (no FAIL).
- [ ] `plan prepare --keep-original` writes `plan.toml.raxis-original.bak`; the backup is NOT bundled at submit time.
- [ ] `plan prepare --dry-run` does not mutate the file; prints diff to stdout.
- [ ] `submit plan` on an unprepared plan with omitted defaultable fields → `FAIL_PLAN_REQUIRES_PREPARE { missing_fields: [...] }`.
- [ ] `submit plan` on a prepared plan → succeeds; bundle is sealed; from the kernel's perspective, there is no concept of "defaulted vs explicit" (the operator signed the bytes).
- [ ] Annotation `# @raxis-default v0.4.0` is preserved verbatim in the signed bundle (it's part of plan.toml bytes).
- [ ] `plan init -t feature` produces a plan that passes `plan validate`, `plan prepare` (no-op or trivial), and `submit plan --dry-run`.
- [ ] `plan validate` rejects plans with profile cycles, name collisions, etc., without IPC.
- [ ] `plan validate --with-kernel` invokes `submit plan --dry-run` under the hood.
- [ ] `plan diff` produces unified output identical to a `diff -u` of the pre-prepare and post-prepare files.
- [ ] `plan explain` produces a non-empty plain-English summary.
- [ ] `plan fmt --check` exits non-zero when the file is not canonical; zero when it is.
- [ ] `plan cost-estimate` returns a non-empty per-task projection for a plan with declared providers.
- [ ] `submit plan --dry-run` runs the full admission chain; on success, the kernel's `plan_bundles` table is unchanged.
- [ ] `initiative watch` streams events for the targeted initiative only (not other operators' initiatives).
- [ ] `initiative resume` on an Active initiative → `FAIL_INITIATIVE_NOT_PAUSED { state: Executing }`.
- [ ] `setup wizard` end-to-end: produces a working install with passing smoke test in under 5 minutes on a fresh host.
- [ ] `setup wizard` phase 6: no language starters selected → wizard skips writing `[default_verifier_images]`; smoke test still passes (symbol-index auto-injection no-op on the trivial plan).
- [ ] `setup wizard` phase 6: at least one language starter selected → wizard writes the `[[vm_images]]` entry with the release-notes-published `oci_digest`; the second smoke plan (per phase 9) exercises the @-shortcut resolution path AND the auto-injected symbol-index verifier; both `VerifierActivated` and `VerifierCompleted` audit events fire for both verifiers.
- [ ] `setup wizard` phase 6: image SHA-256 mismatch against the manifest → wizard re-downloads up to 2x; persistent failure aborts the wizard with actionable mitigations.
- [ ] `setup wizard --add-language <lang>`: re-runs phase 6 only against the named language; appends `[[vm_images]]` entry + `[default_verifier_images].<lang>` row; re-signs the policy; advances the epoch; subsequent plans' `image = "@<lang>"` shortcuts resolve.
- [ ] `setup wizard` phase 8: detects a missing canonical image (e.g., operator deleted `raxis-verifier-symbol-index-<kver>.img` from `/usr/local/lib/raxis/images/`) → wizard fails with `FAIL_CANONICAL_IMAGE_MISSING { image }` and an actionable mitigation.
- [ ] `plan prepare` symbol-index auto-injection: Executor task touching source files → verifier injected with the §4.2 canonical entry and annotation; re-running `plan prepare` is a no-op.
- [ ] `plan prepare` symbol-index auto-injection: Executor task touching ONLY non-source files (e.g., docs-only diff) → no verifier injected.
- [ ] `plan prepare` symbol-index auto-injection: task with `[plan.tasks.<id>.review] symbol_index = "not_needed"` → no verifier injected; subsequent `plan prepare` runs honor the suppression.
- [ ] `plan prepare` symbol-index auto-injection: deployment with `policy.toml [prepare] auto_inject_symbol_index = false` → no verifier injected anywhere; `WARN_REVIEWER_MISSING_SYMBOL_INDEX` fires at Reviewer activation per [`planner-harness.md §4.1`](planner-harness.md).
- [ ] `plan prepare` `@<language>` shortcut: `image = "@rust"` with `[default_verifier_images].rust = "raxis-verifier-rust-starter"` → expanded to literal alias with annotation; the bundle's plan bytes contain the literal alias (the kernel never sees `@rust`).
- [ ] `plan prepare` `@<language>` shortcut: `image = "@unconfigured"` with no matching policy entry → `FAIL_PLAN_VERIFIER_IMAGE_SHORTCUT_UNRESOLVABLE`.
- [ ] `doctor policy` detects an unsigned policy bundle.
- [ ] `doctor providers` detects an invalid provider credential.
- [ ] `doctor canonical-images` detects a tampered canonical image (Reviewer / Orchestrator / Executor starter / symbol-index verifier / language starter).
- [ ] `doctor canonical-images` correctly distinguishes kernel-embedded-digest images (FAIL on mismatch) from operator-pinned images (WARN drift / FAIL only on in-flight digest mismatch).
- [ ] Defaultable-field annotation `# @raxis-default vX.Y.Z` is treated as a TOML comment by the kernel parser; bundle hash is byte-stable across CLI version stamp changes when the actual values match.
- [ ] Auto-inject annotation `# @raxis-default v0.4.0 symbol-index-auto-inject` and shortcut annotation `# @raxis-default v0.4.0 image-shortcut-resolved` are byte-preserved through bundle sealing; `raxis log --format json` shows them in the bundle's plan-bytes audit dump.

### Tests (path-allowlist ergonomics — §4.5)

- [ ] `plan prepare` on a plan with one Executor task missing `path_allowlist` → §4.5.3 template inserted; CLI exit zero with WARN; `submit plan` hard-rejects with `FAIL_PLAN_REQUIRES_EXPLICIT_PATH_ALLOWLIST { task_id }`.
- [ ] `plan prepare` on the same plan after operator uncomments `# path_allowlist = [\n#   "src/",\n# ]` → marker block removed; populated array preserved; CLI exit zero with no warnings; `submit plan` admits.
- [ ] `plan prepare` re-run on the unmodified template (operator forgot to uncomment) → marker block preserved verbatim; CLI exit zero with WARN; idempotent — no duplicate template insertion.
- [ ] `plan prepare` with operator inside a git worktree at `~/work/myproject` → §4.5.6 directory suggestions populated from `git -C ~/work/myproject ls-tree --name-only HEAD .`; only directories included (not blob entries); each suggestion ends with `/`.
- [ ] `plan prepare` with operator NOT inside a git worktree (`$PWD = /tmp`) → bare §4.5.3 template inserted; informational log line "no git worktree detected; suggestions skipped"; CLI exit zero.
- [ ] `plan prepare --suggest-from ~/work/myproject` → suggestions sourced from the override path regardless of `$PWD`; validates path is a git worktree.
- [ ] `plan prepare --suggest-from /tmp/not-a-repo` → CLI hard-errors with "path is not a git worktree"; does NOT fall back to auto-detect; does NOT modify `plan.toml`.
- [ ] `plan prepare --no-suggest` → bare §4.5.3 template; `--suggest-from` and `--no-suggest` are mutually exclusive (CLI hard-errors when both passed).
- [ ] `plan prepare` suggestions cross-referenced with `policy.toml [default_protected_paths]` containing `.git/`, `node_modules/` → those entries (if present in the worktree) get the `# DO-NOT-UNCOMMENT (matches protected path: <pattern>)` comment appended on the same line.
- [ ] `plan prepare` on a Reviewer task with `path_allowlist = ["src/"]` → CLI hard-aborts with the §4.5.5 hard-refusal message; no template insertion; non-zero exit; `plan.toml` NOT modified.
- [ ] `plan prepare` on a Reviewer task with `path_allowlist = []` → CLI hard-aborts (any value triggers the rejection, including `[]`).
- [ ] `submit plan` on an operator-edited plan that smuggled past `plan prepare` (operator hand-edited Reviewer to add `path_allowlist = ["src/"]`) → kernel hard-rejects with `FAIL_REVIEWER_PATH_ALLOWLIST_NOT_ALLOWED { task_id }`. Defense-in-depth: the kernel does the check independent of `plan prepare`.
- [ ] `plan prepare` on an Executor task with `path_allowlist = []` and no annotation → WARN explaining both remediation paths; `submit plan` hard-rejects with `FAIL_EXECUTOR_EMPTY_PATH_ALLOWLIST_UNACKNOWLEDGED { task_id }`.
- [ ] `plan prepare` on the same task after operator adds `# @raxis-explicit no-write-acknowledged` on the empty-array line → no WARN; `submit plan` admits; `InitiativeCreated` audit shows `task_write_scopes: [..., { task: "X", scope: NoWriteAcknowledged }, ...]`.
- [ ] `plan prepare` on the same task with the annotation on the comment line immediately ABOVE the empty-array line → equivalent: no WARN; `submit plan` admits; audit identical.
- [ ] `plan prepare` does NOT auto-add the `# @raxis-explicit no-write-acknowledged` annotation on its own (per §4.5.4); operator authoring discipline is preserved.
- [ ] `submit plan` on an Executor task with `path_allowlist = ["src/**/*.rs"]` → kernel hard-rejects with `FAIL_PATH_ALLOWLIST_INVALID_SYNTAX { task_id, entry: "src/**/*.rs", reason: "glob_character_in_path" }`.
- [ ] `submit plan` on an Executor task with `path_allowlist = ["/etc/secrets/"]` → `FAIL_PATH_ALLOWLIST_INVALID_SYNTAX { reason: "absolute_path" }`.
- [ ] `submit plan` on an Executor task with `path_allowlist = ["../escape/"]` → `FAIL_PATH_ALLOWLIST_INVALID_SYNTAX { reason: "path_escape" }`.
- [ ] `plan prepare` warns about `FAIL_PATH_ALLOWLIST_INVALID_SYNTAX` reasons pre-signing per phase 2.f; warning is non-fatal at `plan prepare` (operator may still want to write the bytes for a different deployment); `submit plan` is the hard gate.
- [ ] `plan prepare` (no `--offline`, kernel down): phase 2 (local-pre) completes IN MEMORY; phase 3 (IPC) fails with `FAIL_PREPARE_KERNEL_UNREACHABLE`; CLI exits `4`; the original `plan.toml` is left untouched (no disk write — the operator did not opt in to the half-prepared state).
- [ ] `plan prepare --offline` (kernel down): phase 2 runs and writes augmented bytes to `plan.toml` with the `# @raxis-prepare-partial offline=true cli_version=… prepared_at=…` marker prepended (§5.4.2); CLI exits `4`; subsequent `submit plan` on the same file fails fast with `FAIL_PLAN_PARTIAL_PREPARE_DETECTED` BEFORE invoking the TOML parser (line-prefix scan).
- [ ] `plan prepare` (no `--offline`, kernel UP) on a `plan.toml` carrying the partial-prepare marker: phase 2 idempotently re-runs (no template duplication per §5.6); phase 3-5 succeed; phase 6 writes augmented bytes WITHOUT the marker (full prepare); phase 7 reports `removed offline marker`. Re-running once more is a no-op (§5.6).
- [ ] `plan prepare --offline` on a `plan.toml` already fully prepared (no §4.5 work pending, no marker): phase 2 produces no changes; CLI emits the §5.7 warning ("--offline was passed but no §4.5 template work pending") and exits `2`. The file is unchanged on disk (no marker added if no changes were made).
- [ ] Distinct exit codes per §5.4.1: `0` (full success), `2` (warnings), `3` (phase-2 hard refusal e.g. §4.5.5), `4` (kernel unreachable, with or without `--offline`), `5` (phase 4-5 IPC error), `64` (CLI usage error), `1` (catch-all). Each path has a dedicated CLI test asserting the exit code.
- [ ] `submit plan` parses the partial-prepare marker BEFORE TOML parsing (line-prefix match, no TOML invocation) so a malformed plan with the marker still emits the partial-prepare error rather than the parse error.
- [ ] `TaskWriteScope::Bound { paths }` audit: paths array is the operator's declared `path_allowlist` verbatim (not a normalized form); auditors see the operator's exact intent.
- [ ] `TaskWriteScope::NotApplicable` audit fires for every Reviewer and Orchestrator task in the plan; auditors can grep `task_write_scopes` and see at a glance which tasks have write authority.

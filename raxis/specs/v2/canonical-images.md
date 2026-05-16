# RAXIS V2 — Canonical Images & Operator-Published (BYO) Images

> **Companion specs.**
>
> - [`image-cache.md`](image-cache.md) — on-disk cache layout (`<data_dir>/oci-cache/`),
>   the `ImageResolver` trait surface, pull-and-verify pipeline, GC,
>   and failure-mode taxonomy. This document treats `ImageResolver`
>   as a black box and only specifies how the kernel binds the
>   resolved bytes to a particular role-trust contract.
> - [`release-and-distribution.md §4.2`](release-and-distribution.md) — how the canonical
>   `<role>.manifest.toml` files get signed by the kernel signing
>   key and shipped alongside the kernel binary.
> - [`planner-harness.md §4.7`](planner-harness.md) (Reviewer) and `§4.8` (Orchestrator) —
>   the per-role harness contracts that anchor
>   `INV-PLANNER-HARNESS-02` and `INV-PLANNER-HARNESS-05`.
> - `invariants.md §10.5` — the three normative trust contracts
>   (`INV-IMAGE-RESOLUTION-PER-ROLE-01`,
>   `INV-OPERATOR-CUSTOM-IMAGE-01`, `INV-OPERATOR-CUSTOM-IMAGE-02`).
> - [`audit-paired-writes.md §4.3`](audit-paired-writes.md) — the single-class roster that
>   classifies `VmImageResolved` and `SecurityViolationDetected`.
> - `kernel/src/canonical_images_preflight.rs` — the
>   compiled-in-digest preflight invoked by Reviewer / Orchestrator
>   activations.
> - `kernel/src/handlers/intent.rs::resolve_vm_image_override` —
>   the operator-image resolution path invoked by Executor
>   activations.

---

## §1 — Why this spec exists

A RAXIS deployment boots VM rootfs images for four agent roles
(Orchestrator, Reviewer, Executor, Verifier). Two of those roles
(Orchestrator, Reviewer) are kernel-canonical: the rootfs is
shipped as part of the RAXIS release, the expected SHA-256 is
compiled into the kernel binary at build time
(`crates/canonical-images/build.rs`), and the operator cannot
substitute a different image without rebuilding the kernel from
source. The other two roles (Executor, Verifier) are
**operator-publishable**: the operator can declare arbitrary
`[[vm_images]]` entries in `policy.toml`, pin each to a specific
`oci_digest`, and target them per-task or wire one to the default
Executor / Verifier slot.

Several places in the tree ([`audit-paired-writes.md §4.3`](audit-paired-writes.md),
[`release-and-distribution.md §9.2`](release-and-distribution.md), `cli/src/commands/setup.rs`,
the new `INV-IMAGE-*` / `INV-OPERATOR-CUSTOM-IMAGE-*`
invariants) cross-reference "the canonical images spec" for the
trust contract that binds operator-declared digests to the
substrate-spawned bytes. This document IS that spec. It exists to
codify, in one place:

1. **What "canonical" means** for a RAXIS image (kernel-bundled,
   digest pinned at build time, manifest signature chains to
   `EXPECTED_KERNEL_SIGNING_KEY_BYTES`).
2. **Per-role binding** — which roles can be operator-published
   and which cannot, plus the structural rejection rules that
   prevent cross-binding (`INV-IMAGE-RESOLUTION-PER-ROLE-01`).
3. **The Bring-Your-Own-Image (BYO) flow** — how an operator
   ships a custom Executor / Verifier image and how the kernel
   re-verifies it at every spawn
   (`INV-OPERATOR-CUSTOM-IMAGE-01`).
4. **Plumbing uniformity** — the same audit-event surface and
   fail-closed semantics govern canonical and BYO paths
   (`INV-OPERATOR-CUSTOM-IMAGE-02`).
5. **The end-to-end test surface** that pins (1)–(4) against
   kernel regressions
   (`extended_e2e_byo_executor_image.rs` and the harness helpers
   in `extended_e2e_support/byo_image.rs`).

What this spec does NOT cover:

* The on-disk cache layout, the OCI pull pipeline, and the
  `ImageResolver` trait surface — those live in [`image-cache.md`](image-cache.md).
* The release pipeline that bakes the canonical kernel signing
  key and produces `<role>.manifest.toml` — that lives in
  [`release-and-distribution.md`](release-and-distribution.md).
* The Reviewer and Orchestrator harness contracts (no-egress,
  no-code-exec) — those live in [`planner-harness.md`](planner-harness.md).

---

## §2 — Per-role image binding

### §2.1 — Role inventory

| Role         | Bundled? | Operator-publishable? | Trust pin                                         | Preflight                                              |
| ------------ | -------- | --------------------- | ------------------------------------------------- | ------------------------------------------------------ |
| Orchestrator | yes      | no                    | `EXPECTED_ORCHESTRATOR_IMAGE_DIGEST` (kernel bin) | `canonical_images_preflight.rs`                        |
| Reviewer     | yes      | no                    | `EXPECTED_REVIEWER_IMAGE_DIGEST` (kernel bin)     | `canonical_images_preflight.rs`                        |
| Executor     | yes\*    | yes                   | `[[vm_images]] oci_digest` in `policy.toml`       | `handlers/intent.rs::resolve_vm_image_override`        |
| Verifier     | yes\*    | yes                   | `[[vm_images]] oci_digest` in `policy.toml`       | (verifier-side, see [`verifier-processes.md §13`](verifier-processes.md))       |

\* The kernel ships a canonical `executor-starter` and
`verifier-starter` image as a default; operators who want a richer
toolchain bind their own `[[vm_images]]` and either reference it
per-task (`[[plan.tasks]] vm_image = "..."`) or wire it as
`[default_executor_image] name = "..."`. The starter is the
kernel-canonical fallback if neither override is present.

### §2.2 — Per-role image binding is non-substitutable
(`INV-IMAGE-RESOLUTION-PER-ROLE-01`)

The kernel REFUSES, at three independent layers, to bind a
`[[vm_images]]` entry to a role its `role_restriction` field does
not permit. The three layers are:

1. **Policy load** (`crates/policy/src/bundle.rs::validate_vm_images`).
   Every `[[vm_images]]` entry MUST declare a non-empty
   `role_restriction: Vec<String>` admit-list. The valid tokens
   are `"Executor"` and `"Verifier"`. Any entry containing
   `"Reviewer"` is rejected with
   `FAIL_REVIEWER_VM_IMAGE_NOT_ALLOWED`; any entry containing
   `"Orchestrator"` is rejected with
   `FAIL_ORCHESTRATOR_VM_IMAGE_NOT_ALLOWED`. The operator cannot
   load a policy bundle that even attempts to substitute a
   custom image for the kernel-canonical roles.
2. **Plan admission** (`validate_task_vm_images`,
   `validate_default_executor_image`). Plan tasks with
   `session_agent_type = "Reviewer"` and a non-empty `vm_image`
   field are rejected with `reviewer_image_not_allowed` +
   remediation. The `[default_executor_image]` block is only
   resolved if its `name` references a `[[vm_images]]` entry
   whose `role_restriction` admits `"Executor"`; otherwise
   `FAIL_POLICY_DEFAULT_EXECUTOR_IMAGE_UNRESOLVABLE`.
3. **Activation** (`handlers/intent.rs::handle_activate_sub_task`).
   Orchestrator and Reviewer activations route through
   `canonical_images_preflight::verify_canonical_image_via_manifest`
   which checks the compiled-in
   `EXPECTED_{ORCHESTRATOR,REVIEWER}_IMAGE_DIGEST` against the
   on-disk rootfs. There is no code path that substitutes a
   `[[vm_images]]`-resolved blob for a canonical-role activation —
   the canonical preflight runs BEFORE the activation handler
   ever consults `[[vm_images]]`, and the substitute would be
   silently invisible to the audit chain.

There is **no stub-fallback substitute**. The `VmImageResolved`
audit event's `agent_role` field is therefore normatively
constrained to the string `"Executor"` (Verifier activations,
once landed, will use `"Verifier"`). An audit-replay reader that
observes any other value is observing a kernel bug. This
constraint is what lets `INV-IMAGE-RESOLUTION-PER-ROLE-01`
publish a single audit-event surface that distinguishes "BYO
image was bound to an Executor" from "BYO image was bound to
something else" without ambiguity.

### §2.3 — Why per-role pinning is non-negotiable

The four roles carry distinct trust scopes:

* **Orchestrator** plans the initiative; it has the kernel's full
  KSB read view and can revoke / mutate sessions. Code execution
  inside an Orchestrator VM would let a planner LLM mutate the
  initiative graph through escape hatches its harness contract
  forbids.
* **Reviewer** evaluates plans and grants approvals (per
  `INV-PLANNER-HARNESS-01`). The Reviewer contract structurally
  forbids tool execution. A toolchain-rich image bound to a
  Reviewer activation would surface the entire build-toolchain
  attack surface inside the role that gates approvals.
* **Executor** runs operator code. Tool execution is the point.
  This is the only role where operator-published toolchains make
  sense.
* **Verifier** runs gates against witness submissions. The
  Verifier image is a more constrained Executor — it sees
  witness inputs but never the initiative repo's writeable
  worktree.

A silent cross-bind (e.g. a Reviewer activation that booted from
the operator's `executor-rust-v1` BYO image) would either (a)
defeat `INV-PLANNER-HARNESS-01` by surfacing a Bash toolchain in
the Reviewer's VM, or (b) fail noisily ("the Reviewer has no
language tooling") — the latter is a correctness regression no
operator should hit, and the former is an irrecoverable security
failure. Fail-closed at admission AND activation closes both
directions of cross-binding before the substrate boots.

---

## §3 — Bring-Your-Own-Image (BYO) flow

### §3.1 — Operator-side authoring

An operator who wants to ship a custom Executor (or Verifier)
toolchain authors:

1. **A Containerfile** (sample:
   `live-e2e/seed/byoi-executor/Containerfile`). Any container
   build tool that produces an OCI image works
   (`docker build`, `podman build`, `buildah bud`); the kernel
   does not depend on the build pipeline.
2. **A signed `policy.toml`** with two new blocks:
   ```toml
   [[vm_images]]
   name                     = "byo-executor-py312-node22"
   oci_digest               = "sha256:<64 lower-hex>"
   role_restriction         = ["Executor"]
   linux_kernel_version_min = "5.14"

   [default_executor_image]
   name = "byo-executor-py312-node22"
   ```
   The `oci_digest` is the SHA-256 of the rootfs blob the
   operator stages on the host. The `name` is the alias plans /
   `[default_executor_image]` use to reference this image.
   `role_restriction` is the admit-list (§2.2 layer 1);
   `linux_kernel_version_min` is the floor below which the
   substrate refuses to boot this image.
3. **An on-disk staging step** that places the rootfs + sidecar
   manifests under
   `<data_dir>/oci-cache/images/sha256/<aa>/<full>/` per
   [`image-cache.md §4`](image-cache.md). The harness helper
   `extended_e2e_support/byo_image.rs::stage_byo_image_in_oci_cache`
   demonstrates the layout (`rootfs.img`, synthesised
   `manifest.json`, synthesised `config.json`).

The operator's signing key on `policy.toml` is the trust anchor
for this entire flow. The kernel verifies (a) the policy bundle's
signature chains to an active operator certificate, then (b) the
declared `oci_digest` matches the rootfs the substrate is about
to boot from.

### §3.2 — Kernel-side resolution
(`INV-OPERATOR-CUSTOM-IMAGE-01`)

When `handle_activate_sub_task` admits an Executor task whose
activation row carries a non-empty `vm_image_alias` (from either
`[[plan.tasks]] vm_image = "..."` or
`[default_executor_image] name = "..."`), it calls
`resolve_vm_image_override(policy, alias, ctx)`. That function:

1. Looks up the `[[vm_images]]` entry by `name`. A missing alias
   returns `VmImageResolveError::AliasDropped` and fails the
   activation with `FAIL_POLICY_VIOLATION` (the bundle was
   re-signed without the entry while the activation was
   in-flight).
2. Parses the entry's `oci_digest` as a `raxis_image_cache::OciDigest`.
   Malformed digests return `VmImageResolveError::MalformedDigest`
   (this is also gated at policy load by
   `FAIL_POLICY_VM_IMAGE_DIGEST_INVALID`; the activation-side
   check is a defence-in-depth re-validation).
3. Calls `ImageResolver::resolve(&oci_digest, registry_hint)`. The
   resolver implementation
   (`PrePopulatedResolver` for offline-staged caches;
   `ProductionResolver` for registry-backed pulls per
   [`image-cache.md §6`](image-cache.md)) stream-hashes the on-disk rootfs and
   compares against `oci_digest`. A divergence returns
   `ImageResolverError::DigestMismatch { expected, actual, path }`.
4. Maps the resolver error to `VmImageResolveError::DigestMismatch`
   (carrying `expected`, `actual`, `path`) and returns it.

The activation handler pattern-matches the result:

* **Success.** Emits
  `AuditEventKind::VmImageResolved { session_id, task_id,
  initiative_id, alias, oci_digest, agent_role: "Executor" }`
  and proceeds to spawn. The audit event fires BEFORE the spawn
  step, so the chain records "which bytes booted this session"
  independent of whether the spawn ultimately succeeds.
* **`DigestMismatch`.** Emits
  `AuditEventKind::SecurityViolationDetected { violation_kind:
  "OperatorImageDigestMismatch", expected, actual, path }` and
  returns `(FAIL_POLICY_VIOLATION, TaskState::Admitted)`. The
  activation row stays in `PendingActivation`. The substrate
  never boots from the tampered bytes. The dashboard's
  `notification_priority` classifies every
  `SecurityViolationDetected` variant as `Critical` —
  operators are paged immediately.
* **Other variants** (`AliasDropped`, `MalformedDigest`,
  `ResolverFailure`). Logged to stderr with the alias / task-id
  context; activation fails with `FAIL_POLICY_VIOLATION`. These
  are configuration errors, not security violations, so they
  do NOT emit `SecurityViolationDetected`.

### §3.3 — Plumbing uniformity
(`INV-OPERATOR-CUSTOM-IMAGE-02`)

The same trust contract that pins the canonical Reviewer and
Orchestrator images (compiled-in digest, re-verified at every
spawn, fail-closed on mismatch with `SecurityViolationDetected`)
ALSO governs every operator-published `[[vm_images]]` entry.
There are NOT two distinct plumbing paths. The differences are
WHERE the expected digest lives (kernel binary vs. signed
`policy.toml`) and WHICH `violation_kind` taxonomy the failure
event carries. The verification mechanism, the failure shape,
the success shape, the activation gating, and the
forward-compatibility for V3 registry pulls are all uniform.

| Axis                       | Canonical (Orchestrator / Reviewer)              | BYO (Executor / Verifier)                                |
| -------------------------- | ------------------------------------------------ | -------------------------------------------------------- |
| Expected-digest source     | `EXPECTED_*_IMAGE_DIGEST` (compiled into kernel) | `[[vm_images]] oci_digest` (signed `policy.toml`)        |
| Hashing implementation     | `raxis_canonical_images::compute_image_digest`   | `raxis_image_cache::compute_image_sha256` (resolver)     |
| Comparison semantics       | constant-time byte-equality                       | constant-time byte-equality                              |
| Failure event              | `SecurityViolationDetected { ReviewerImageDigestMismatch / OrchestratorImageDigestMismatch }` | `SecurityViolationDetected { OperatorImageDigestMismatch }` |
| Failure event severity     | `Critical`                                       | `Critical`                                               |
| Success event              | preflight log line `canonical_image_ok`           | `VmImageResolved { agent_role: "Executor" }`             |
| Activation gating          | activation refused, row stays `PendingActivation`| activation refused, row stays `PendingActivation`        |
| Future registry-pull path  | n/a (kernel-bundled blob)                        | `ProductionResolver` (per [`image-cache.md §6`](image-cache.md))           |

Adding a new role in V3 (e.g. a dedicated `Auditor` image) only
requires extending the `SecurityViolationDetected` `violation_kind`
taxonomy AND the `VmImageResolved` `agent_role` enum — not a new
trust contract surface. That extensibility shape is what
`INV-OPERATOR-CUSTOM-IMAGE-02` makes normative.

---

## §4 — Test surface

### §4.1 — Smoke mode (always-on)

`raxis/kernel/tests/extended_e2e_byo_executor_image.rs` runs in
two modes. The default mode runs unconditionally on every
`cargo test` against `raxis-kernel`. It:

1. Bakes a small synthetic rootfs with a deterministic SHA-256
   via `byo_image::bake_byo_executor_image_synthetic`.
2. Stages the rootfs in the OCI cache layout
   (`<data_dir>/oci-cache/images/sha256/<aa>/<full>/...`) via
   `byo_image::stage_byo_image_in_oci_cache`.
3. Verifies the SHA-256 the staging step computed equals the
   SHA-256 the bake step asserted — closes the
   bake-vs-stage drift loop that BYO trust depends on
   (`INV-OPERATOR-CUSTOM-IMAGE-01`).
4. Constructs the policy snippet
   `inject_byo_executor_image_in_policy` writes and asserts:
   * `[[vm_images]] name = "byo-executor-py312-node22"
     oci_digest = "sha256:..." role_restriction = ["Executor"]
     linux_kernel_version_min = "5.14"`.
   * `[default_executor_image] name = "byo-executor-py312-node22"`.
5. Constructs an `AuditEventKind::VmImageResolved` and asserts
   `notification_priority` returns `None` (routine event, not
   surfaced in the operator inbox).
6. Constructs an `AuditEventKind::SecurityViolationDetected
   { violation_kind: "OperatorImageDigestMismatch", … }` and
   asserts `notification_priority` returns `Critical`.
7. Asserts `live-e2e/seed/byoi-executor/Containerfile` exists,
   so a downstream live-mode invocation can find it.

The smoke mode requires no Docker daemon, no LLM, no kernel
process — it exercises the harness primitives and the audit
contract surface directly.

### §4.2 — Live mode (gated)

When `RAXIS_LIVE_E2E=1` AND `RAXIS_LIVE_E2E_BYO=1` are both
set, the test escalates to a full live-e2e invocation:

1. **Bake.** `byo_image::bake_byo_executor_image_full`
   `docker build --platform linux/<arch> -f
   live-e2e/seed/byoi-executor/Containerfile` and exports the
   rootfs to a tempdir. Computes the SHA-256 of the exported
   rootfs.
2. **Stage.** `stage_byo_image_in_oci_cache` copies the rootfs
   into the live-e2e harness's `<data_dir>/oci-cache/...`
   layout.
3. **Inject.** `inject_byo_executor_image_in_policy` amends
   the harness-generated `policy.toml` with the `[[vm_images]]`
   and `[default_executor_image]` blocks.
4. **Boot.** Spin up the live-e2e stack (kernel + LLM +
   isolation backend) per `extended_e2e_realistic_scenario`'s
   pattern.
5. **Submit.** Submit a one-task initiative whose Executor task
   runs `bash -c 'python3.12 --version && node --version'`.
6. **Poll.** Wait for completion; collect BashTool stdout from
   the worktree.
7. **Assert (Tier 1, mechanical witness).** The audit
   directory contains a `VmImageResolved` event with
   `agent_role = "Executor"` and `oci_digest = sha256:<...>`
   matching the bake step's SHA-256.
8. **Assert (Tier 2, semantic witness).** BashTool stdout
   contains `Python 3.12.` AND `v22.`.
9. **Assert (Tier 3, artefact paths).** On either success or
   failure, print the kernel log path, the audit directory
   path, the worktree path, and the dashboard URL per the
   standing live-e2e structure.

A separate gated test exercises the negative path:
`stage_byo_image_in_oci_cache(tamper = true)` flips the last
byte of the rootfs after staging, causing the on-disk SHA-256
to diverge from the policy-declared digest. The activation
attempt fires
`SecurityViolationDetected { OperatorImageDigestMismatch, … }`,
the activation stays in `PendingActivation`, and the test
asserts the audit-event taxonomy.

### §4.3 — What this test pins

The test surface above is the mechanical witness for all three
new invariants:

* `INV-IMAGE-RESOLUTION-PER-ROLE-01` — the smoke test asserts
  `VmImageResolved.agent_role = "Executor"`; the live test
  observes the same event and asserts the policy declared
  `role_restriction = ["Executor"]`. The cross-wiring rejection
  is pinned by `crates/policy`'s existing
  `validate_vm_images` tests
  (`FAIL_REVIEWER_VM_IMAGE_NOT_ALLOWED` /
  `FAIL_ORCHESTRATOR_VM_IMAGE_NOT_ALLOWED`).
* `INV-OPERATOR-CUSTOM-IMAGE-01` — the negative-path live test
  is the digest-mismatch witness; the smoke test pins the
  `notification_priority = Critical` classification of the
  resulting `SecurityViolationDetected` event.
* `INV-OPERATOR-CUSTOM-IMAGE-02` — the smoke test asserts the
  uniform audit-event shape (canonical preflight emits
  `canonical_image_ok` + on mismatch
  `SecurityViolationDetected { ReviewerImageDigestMismatch }`;
  BYO emits `VmImageResolved` + on mismatch
  `SecurityViolationDetected { OperatorImageDigestMismatch }`).

---

## §5 — Operator recipes

For copy-pasteable end-to-end recipes, see:

* `guides/recipes/ops/10-publish-executor-image.md` — declaring a
  `[[vm_images]]` entry and computing its digest.
* `guides/recipes/ops/17-bring-your-own-image.md` — full BYO
  walkthrough (Containerfile authoring, `docker build`, digest
  computation, `oci-cache/` staging, policy declaration), with
  the BYO live-e2e test cited as a worked example.
* `guides/recipes/setup/09-default-executor-image.md` — wiring
  a BYO image as the `[default_executor_image]`.

---

## §6 — In-VM capability discovery (`vm_capabilities`)

This section anchors `INV-EXEC-DISCOVERY-01`
(`invariants.md §10.4a`).

### §6.1 — Why this exists

The Executor LLM runs inside an airgapped VM. Egress is gated by
the kernel's allowlist (`INV-VM-EGRESS-01`); the credential
proxies (`DATABASE_URL`, `MONGO_URL`, `REDIS_URL`, `SMTP_URL`)
proxy DB / SMTP traffic only — they do NOT proxy package
mirrors. So `pip install`, `npm install`, `cargo install`, and
`go get` will all fail. If the LLM doesn't know what is
**already baked in** to the image, it will either (a) write a
script importing a missing module and fail at runtime, or (b)
try to install the package and waste a turn on a tproxy block.

This applies BOTH to the canonical `raxis-executor-starter`
image (where the kernel team controls what is pre-installed,
per [`planner-harness.md §10.6`](planner-harness.md)) AND to operator-published BYO
images (where the operator's `Containerfile` controls what is
pre-installed, per `INV-OPERATOR-CUSTOM-IMAGE-01`). The LLM
needs an **image-agnostic** way to discover what its specific
VM has.

### §6.2 — Two coherent surfaces, one in-guest probe

`INV-EXEC-DISCOVERY-01` mandates **two surfaces**, both backed
by the **same** in-guest introspection probe
(`crates/planner-core/src/vm_capabilities.rs`):

1. **System-prompt capability hint.** At session start, the
   planner driver
   (`crates/planner-core/src/driver.rs::run_role_session_with_connected_transport`)
   calls `cached_capabilities()` once per process, renders the
   manifest into a `## VM Environment` paragraph via
   `build_capability_hint()`, and folds it into the role NNSP
   before the KSB delimiter block. The LLM sees this on its
   first turn — no tool call required.
2. **`vm_capabilities` LLM tool.** Registered in every role
   registry (executor, reviewer, orchestrator — see
   `crates/planner-core/src/tools.rs::build_*_registry`); the
   LLM can call it on any subsequent turn for a finer query
   (e.g. "is `numpy` available?", "what's the workdir's git
   HEAD?").

Both surfaces read from the **same** memoized
`OnceLock<Arc<CapabilityManifest>>`. For a given `(image
digest, session env)` pair the manifest is byte-deterministic,
which is what makes prompt caching across turns correct.

### §6.3 — Manifest schema

The probe returns a `CapabilityManifest` (defined in
`vm_capabilities.rs`):

```jsonc
{
  "image_role": "executor" | "reviewer" | "orchestrator" | "byo",
  "image_digest": "sha256:..." | null,
  "binaries": [
    { "name": "bash",    "path": "/bin/bash",    "version": "5.2.15" },
    { "name": "python3", "path": "/usr/bin/python3", "version": "3.11.2" },
    { "name": "node",    "path": "/usr/bin/node",    "version": "20.18.0" },
    // ... curated allowlist: bash, sh, git, gh, jq, ripgrep, fd,
    //     curl, wget, make, gcc, g++, python3, node, npm, rustc,
    //     cargo, go, sqlite3, psql, mongosh, redis-cli, mysql, ...
  ],
  "python":   { "interpreter": "...", "version": "...",
                "site_packages": "...",
                "packages": [ { "name": "...", "version": "...",
                               "importable": true }, ... ] }
              | null,
  "node":     { "interpreter": "...", "version": "...",
                "global_packages": [ { "name": "...", "version": "..." } ] }
              | null,
  "rust":     { "rustc": "1.x.x", "cargo": "1.x.x" } | null,
  "go":       { "go": "1.22.0" }                      | null,
  "env":      { "DATABASE_URL": "postgres://...",
                "MONGO_URL":    "mongodb://...",
                "REDIS_URL":    "redis://...",
                "SMTP_URL":     "smtp://..." },
  "filesystem": {
    "workdir":                   "/workspace/repo",
    "workdir_languages_detected": ["rust", "python"],
    "git_initialized":           true,
    "head_commit":               "<sha>" | null
  }
}
```

### §6.4 — Tool input schema

```jsonc
{
  "type": "object",
  "properties": {
    "categories": {
      "type": "array",
      "items": {
        "enum": ["binaries", "python", "node", "rust", "go",
                 "env", "filesystem", "all"]
      }
    },
    "filter": {
      "type": "object",
      "properties": {
        "binary_name":    { "type": "string" },
        "python_package": { "type": "string" },
        "node_package":   { "type": "string" },
        "env_var":        { "type": "string" }
      }
    }
  }
}
```

`categories` defaults to `["all"]`; an empty `filter` returns
the unprojected sections.

### §6.5 — Redaction (kernel-private env vars)

The `env` section MUST exclude **kernel-private** variables.
The exact predicate is `vm_capabilities::is_kernel_private_env`
and covers:

* The named set: `RAXIS_VSOCK_LOOPBACK_PLAN`,
  `RAXIS_SESSION_TOKEN`, `RAXIS_PLANNER_KSB`,
  `RAXIS_PLANNER_KSB_PATH`, `RAXIS_PLANNER_TASK_PROMPT`,
  `RAXIS_PLANNER_TASK_PROMPT_PATH`,
  `RAXIS_PLANNER_SIDECAR_HMAC_SECRET`,
  `RAXIS_PLANNER_SIDECAR_PROVIDER_ID`,
  `RAXIS_PLANNER_SIDECAR_ENDPOINT`.
* Heuristic patterns (case-insensitive): `*SECRET*`,
  `*PASSWORD*`, `*PASSWD*`, `*API_KEY*`, `*APIKEY*`,
  `*PRIVATE_KEY*`, `*_TOKEN`.

Credential-proxy URLs (`DATABASE_URL`, `MONGO_URL`,
`REDIS_URL`, `SMTP_URL`) and harmless `RAXIS_*` plumbing surface
intentionally so the LLM can write scripts that connect through
the proxies. The kernel-stamped loopback-plan base64 / sidecar
HMAC secret never surface.

### §6.6 — Performance & cost

The probe is sub-second on a warm VM:

* PATH walk + `--version` for the curated binary allowlist
  (~20 binaries) — cap each subprocess at 250 ms.
* Direct `dist-info` reads under each Python `site-packages`
  dir (NO `pip list` subprocess — pip startup is >100 ms).
* `npm list -g --json --depth=0` — capped at 500 ms.
* `git rev-parse HEAD` — capped at 100 ms.
* No recursive filesystem walks (`workdir_languages_detected`
  uses depth=1 globs only).

The probe runs **once** per process; subsequent
`cached_capabilities()` calls are O(1) Arc clones.

### §6.7 — Image-agnosticism

The probe is **image-agnostic** by construction: it reads the
process's actual PATH / Python interpreter / Node interpreter /
filesystem state. It does NOT consult a kernel-side static
catalog. This is normative, not just descriptive: a kernel-side
catalog would drift the moment an operator pins a BYO image
with a different package set, breaking BYO compatibility per
`INV-OPERATOR-CUSTOM-IMAGE-01`.

### §6.8 — Compatibility with the BashTool architecture

The `vm_capabilities` tool is **compatible** with — and
complementary to — the "LLM writes scripts and runs them via
`BashTool`" architecture. It tells the LLM **what scripts to
write**; it does NOT execute on the LLM's behalf. It does
NOT reintroduce the reverted narrow per-DB tools
(`postgres_query` / `mongo_query` / `redis_query` /
`smtp_send` — reverted at `12afc38`).

---

## §7 — Image-build pipeline (operator-side)

> **Cross-references.** `v2/planner-harness.md §14.4 / §14.4a` is
> the kernel-side image-build pipeline spec (production EROFS
> path + dev-host cpio.gz path; manifest signing; trust chain).
> This section pins the **operator-facing surface**: which
> command to run, what inputs it consumes, and what artefacts it
> produces.

### §7.1 — Single-command bake (`cargo xtask images bake`)

`cargo xtask images bake [--role <ROLE>]... [--install-dir <P>]
[--signing-key <P>] [--builder <B>] [--kernel-from-file <P>]
[--force] [--no-cache]` is the one command operators run to
produce a complete, bootable set of canonical images from a
fresh checkout. It wraps the three-step `bake-rootfs →
dev-stage → build-all` pipeline plus the guest-kernel staging
step that used to live in the live-e2e harness's auto-bake
workaround. The driver:

1. **Preflights every required input** (read-only). Container
   builder + daemon, signing key, musl linker (macOS),
   guest-kernel binary, per-role `Containerfile` and
   `manifest.toml` fixtures, Containerfile graph acyclicity. Any
   missing input bails with the literal token
   `INV-IMAGE-BAKE-PREFLIGHT-FAIL-CLOSED-01` and a remediation
   message naming the missing piece **before any artefact is
   produced**. Operators replaying a failure observe no partial
   state in the install dir.
2. **Stages `vmlinux`** at `<install_dir>/kernel/vmlinux`.
   Resolution order, first source wins:
   `--kernel-from-file <PATH>` → `$RAXIS_DEV_KERNEL_SOURCE` →
   already-staged file → canonical
   `/usr/local/lib/raxis/kernel/vmlinux`. The bake records the
   resulting SHA-256 in every per-role integrity manifest so a
   kernel rotation forces a full rebake.
   (`INV-IMAGE-BAKE-VMLINUX-STAGED-01`.)
3. **Bakes every selected role.** Per role:
   `bake-rootfs` (only for roles whose `Containerfile` carries
   an OS-tooling stack — today, `executor-starter`) →
   `dev-stage` → `build-all`. Roles whose prior integrity
   manifest agrees with the current input SHAs AND whose on-disk
   `.img` + `.manifest.toml` still match the recorded output
   SHAs are short-circuited with a `bake_role_no_op` log line.
   Re-running bake on an unchanged tree is a fast no-op.
   (`INV-IMAGE-BAKE-MANIFEST-INTEGRITY-01`.)
4. **Writes the per-role integrity manifest** at
   `<install_dir>/images/<artefact_stem>-<kver>.bake.json`. The
   manifest records every input SHA (Containerfile,
   `manifest.toml`, staged planner binary, signing-key
   fingerprint prefix, vmlinux) and every output SHA
   (`.img`, `.manifest.toml`) so a CI gate can verify
   bake-to-on-disk integrity without re-running the bake. The
   on-disk shape is pretty-printed JSON with a pinned
   `schema_version`; a future-version manifest is treated as
   "unknown" so a stale xtask never trusts a newer manifest's
   no-op decision.

The four legacy subcommands (`dev-kernel`, `bake-rootfs`,
`dev-stage`, `build-all`) remain available unchanged for
operators who want fine-grained control or are scripting CI.
`bake` is a strict superset.

### §7.2 — Outputs per role

```
<install_dir>/kernel/vmlinux                                 (one global guest kernel)
<install_dir>/images/raxis-<role>-<kver>.img                 (signed cpio.gz initramfs)
<install_dir>/images/raxis-<role>-<kver>.manifest.toml       (Ed25519-signed image manifest)
<install_dir>/images/raxis-<role>-<kver>.bake.json           (integrity manifest)
```

`raxis-<role>-<kver>.img` and `.manifest.toml` keep their
existing names + bytes (no schema change to the
`raxis-image-manifest` shape downstream consumers parse).
`.bake.json` is new; it is operator-visible and pretty-printed
so a manual `cat` is instructive. Example:

```jsonc
{
  "schema_version": 1,
  "role": "raxis-planner-reviewer",
  "artefact_stem": "raxis-reviewer-core",
  "kernel_version": "0.1.0",
  "built_at_unix": 1747280123,
  "host": {
    "os": "macos",
    "arch": "aarch64",
    "target_triple": "aarch64-unknown-linux-musl",
    "container_builder": null
  },
  "inputs": {
    "containerfile_sha256":    "5c0e...",
    "inputs_manifest_sha256":  "a113...",
    "staged_binary_sha256":    "9d72...",
    "signing_key_fp_prefix":   "deadbeef00112233",
    "vmlinux_sha256":          "4a8f..."
  },
  "outputs": {
    "img_sha256":               "82c4...",
    "img_size_bytes":           2343705,
    "manifest_toml_sha256":     "1f9d...",
    "manifest_toml_size_bytes": 761
  }
}
```

### §7.3 — Preflight

The bake driver runs the same `preflight_bake_inputs` host-tool
check before producing any artefact (container builder + daemon,
Rust musl cross-target + linker, signing key, vmlinux). On a
missing input it exits non-zero with the
`INV-IMAGE-BAKE-PREFLIGHT-FAIL-CLOSED-01` remediation text
*before* touching the filesystem. There is no standalone
`preflight` subcommand any more; the check is structurally part
of `bake`.

### §7.4 — Containerfile dependency graph

Every in-tree `images/<role>/Containerfile` must declare its
base layer (`FROM <image>`) as either an upstream public image
(`debian:bookworm-slim`, `scratch`, ...) or a multi-stage local
alias defined earlier in the same Containerfile. A `FROM`
operand naming another in-tree role's bake tag —
`raxis-rootfs-<subdir>:dev` — is rejected at preflight time
with the token
`INV-IMAGE-BAKE-NO-CIRCULAR-CONTAINERFILE-01 VIOLATED`. This is
the structural guard against the pre-migration
`Containerfile.dev` shape — `Containerfile.dev` files lived as
untracked diffs in the pre-migration `aegis-ai` checkout but
were cleaned out by the `chika5105/raxis` migration sweep.
Adding them back under any filename trips the guard.

The contract is **conservative**: any `FROM` operand the parser
does not recognise as an in-tree bake tag (a registry URL, a
multi-stage alias, a `--platform=$BUILDPLATFORM` prefix) is
accepted. Comments and blank lines are ignored. `FROM` is
recognised case-insensitively.

### §7.5 — Initramfs determinism + multi-archive contract

`pack_initramfs` (in `xtask/src/images.rs`, wrapping
`raxis_initramfs_builder::InitramfsBuilder::finalise_to_cpio_gz`)
emits a single deterministic cpio.gz archive per role. The byte
stream carries exactly one `TRAILER!!!` entry; multi-archive
concatenation (gzip multi-member, the early-initrd shape the
Linux kernel's `init/initramfs.c` supports) preserves each
constituent archive's bytes byte-for-byte.
`INV-IMAGE-CPIO-MULTI-ARCHIVE-PRESERVED-01` is the witness
contract pinning the structural property: a future change that
adds early-initrd support cannot regress into the truncation
shape historical iterations chased without tripping the
witness tests.

### §7.6 — Live-e2e harness integration

The live-e2e harness's
`extended_e2e_support/kernel_driver.rs::require_canonical_images`
asserts every input it needs is present at test-start time. The
harness does not bake on the operator's behalf; if an input is
missing it points the operator at
`cargo xtask images bake --kernel-from-file <PATH>`. The bake
driver is the canonical producer of vmlinux + every role image,
so an operator who runs `bake` upstream of the harness gets a
self-contained install dir.

---

## §8 — Open questions / future work

* **V3 registry-pull resolver.** The current `PrePopulatedResolver`
  requires the operator to stage the rootfs on every host
  out-of-band. [`image-cache.md §6`](image-cache.md) sketches the
  `ProductionResolver` that pulls from a registry. This spec's
  trust contract is forward-compatible: the resolver-side
  digest re-hash and the activation-side audit-event surface
  do not change. The only new surface is the registry-side
  authentication / TLS contract, which [`image-cache.md`](image-cache.md) owns.
* **Verifier-side BYO.** Verifier activations currently route
  through [`verifier-processes.md §13`](verifier-processes.md)'s gate-runner harness,
  not through `handle_activate_sub_task`. A Verifier-side BYO
  flow would emit `VmImageResolved { agent_role: "Verifier" }`
  from the verifier-runner activation path; this spec's per-role
  contract already admits the `"Verifier"` value but the audit
  emit-site does not exist yet.
* **Operator-image GC.** [`image-cache.md §8`](image-cache.md)'s GC walks the
  set of digests referenced by the live policy bundle. When the
  operator rotates a BYO image (re-signs `policy.toml` with a
  new digest), the old rootfs becomes GC-eligible after the
  policy epoch carrying the old digest is fully drained. The
  current `prune_unreferenced` implementation handles this; a
  future stress-test should pin the no-double-free contract.

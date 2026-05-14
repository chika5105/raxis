# RAXIS V2 — Planner Harness Specification

> **Status:** V2 Specified
>
> **Scope:** This spec is the canonical reference for the `raxis-planner`
> binary's tool surface, role-asymmetric capability boundaries, claw-code
> integration verdicts, in-VM backgrounded execution model, KSB alert
> classes, and per-role image requirements. It consolidates and extends
> the *Integration & Harness Decisions* originally drafted in
> `v2-deep-spec.md §Part 7`.
>
> **Cross-references (canonical homes for adjacent material):**
>
> - `v2-deep-spec.md §Part 7` — `ApiClient` trait, `RaxisKernelApiClient`
>   wrapping, `raxis-gateway` provider routing, in-VM capability model
>   (`INV-VM-CAP-01..05`), VirtioFS mount table.
> - `vm-network-isolation.md` — transport-layer egress enforcement
>   (`raxis-tproxy`).
> - `credential-proxy.md` — HTTP/protocol-layer egress enforcement
>   (per-session `localhost:<port>` proxies).
> - `agent-disagreement.md` — non-convergence bounds, two-tier escalation,
>   `INV-CONVERGENCE-*`.
> - `host-capacity.md` — VM-aggregate CPU/memory/disk caps.
> - `kernel-mechanics-prompt.md` — KSB schema, role-specific system
>   prompts, prompt assembler rules. The KSB Alert Classes section of
>   this spec (§9) is the source for the alert-rendering subsection of
>   that file.
> - `system-requirements.md` — host & VM kernel version requirements.
>   This spec mandates Linux 5.14+ as the guest VM kernel (see §10.2).
> - `custom-tools.md` — operator-defined custom tools, the third tool
>   category alongside base tools (this spec) and kernel-mediated
>   intents. Canonical home for `INV-PLANNER-HARNESS-04` (Reviewer
>   Custom Tool Prohibition); cross-listed in this spec's §13
>   invariants index.
> - `verifier-processes.md` — operator-declared task-level verifier
>   subsystem; the supported answer to "I want operator code to
>   influence Reviewer judgment" since `INV-PLANNER-HARNESS-04`
>   prohibits Reviewer custom tools.
> - `agent-transcripts/876809ec-7c88-4f71-b2a2-c94e1f7386de` — design
>   discussion threads that produced the verdicts in §4–§6.

---

## §1 — Why a Standalone Spec

The `raxis-planner` harness is the in-VM agent runtime: PID 1 inside every
microVM, the implementation of the LLM turn loop, the surface area that
defines what an agent can and cannot do at the tool level. As V2 has
matured, the role-asymmetric capability decisions, claw-code integration
verdicts, and in-VM execution primitives have grown from a handful of
sub-decisions into a cohesive subsystem with its own invariants
(`INV-PLANNER-HARNESS-*`), its own configuration surface in `plan.toml`,
its own KSB sections, and its own cross-spec dependencies.

`v2-deep-spec.md §Part 7` originally housed all of this material inline.
That arrangement made sense when the integration map was a few tables and
one or two decisions; it stopped making sense as the design accreted to
six full decisions, multiple invariants, the `cgroup`-based execution
substrate, the canonical Reviewer image, and the KSB alert taxonomy. Part 7
now retains the `ApiClient` trait + gateway architecture (which spans
planner *and* gateway concerns) and points here for the rest.

**This spec is normative.** Where it conflicts with earlier drafts in Part 7,
this spec wins. Cross-references in other specs that point at Part 7 for
planner-harness-specific material should be migrated to point here.

---

## §2 — Scope and Non-Scope

**In scope.**

- The complete tool set exposed to each agent role (Orchestrator, Executor,
  Reviewer) at the LLM layer.
- Verdicts on every claw-code runtime module and tool primitive: borrowed
  as-is, wrapped, or excluded.
- The in-VM execution substrate: `cgroup` v2 containment, CPU priority,
  process-tree teardown.
- Backgrounded shell execution semantics (`run_in_background`, lifecycle,
  KSB surfacing).
- Per-role VM image requirements, including the canonical Reviewer image.
- KSB alert classes and their rendering rules (asynchronous events from
  the Kernel that interrupt the agent's reasoning).
- The `INV-PLANNER-HARNESS-*` invariant family.

**Out of scope (covered by other specs).**

- The `ApiClient` trait, `RaxisKernelApiClient` implementation, and
  `raxis-gateway` provider routing — `v2-deep-spec.md §Part 7`.
- Per-call admission of intents (dispatch matrix, error codes, audit
  emission) — `kernel-store.md`, `planner-api.md`.
- Network-layer egress enforcement — `vm-network-isolation.md`.
- HTTP-layer egress enforcement — `credential-proxy.md`.
- Verifier-process VM lifecycle, witness schema, `on_failure` rules — a
  follow-up `verifier-processes.md` spec to be created (this spec
  references the architectural concept and the `artifact` extension).
- VM aggregate resource caps — `host-capacity.md`.
- Plan/policy authority hierarchy — `policy-plan-authority.md`.

---

## §3 — Tool Surface by Role

The complete tool surface, role by role. Tools listed are exposed to the
LLM at the harness layer; the Kernel dispatch matrix remains the
authoritative enforcement layer for any tool that produces an `IntentKind`.

| Tool | Orchestrator | Executor | Reviewer | Source / Notes |
|---|---|---|---|---|
| `read_file` | ✅ | ✅ | ✅ | claw-code `file_ops` |
| `write_file` | ✅ | ✅ | ❌ | claw-code `file_ops` |
| `edit_file` | ✅ | ✅ | ❌ | claw-code `file_ops` |
| `glob_search` | ✅ | ✅ | ✅ | claw-code `file_ops`; Reviewer impl uses direct `execvp` (no shell) |
| `grep_search` | ✅ | ✅ | ✅ | claw-code `file_ops`; Reviewer impl uses direct `execvp` of `ripgrep` (no shell) |
| `bash` (synchronous) | ✅ | ✅ | ❌ | claw-code `bash`; Orchestrator gets bash for semantic conflict resolution per §4.8; Reviewer build target excludes the `bash` module entirely (§4.2) |
| `bash` (`run_in_background`) | ❌ | ✅ | ❌ | New harness primitive (§5); cgroup-contained. Orchestrator excluded per §4.8 — semantic merge work is synchronous; no legitimate use case for long-lived processes in an Orchestrator session. |
| `bash bg_status` | ❌ | ✅ | ❌ | New harness primitive (§5); Orchestrator excluded per §4.8 |
| `bash bg_logs` | ❌ | ✅ | ❌ | New harness primitive (§5); Orchestrator excluded per §4.8 |
| `bash bg_kill` | ❌ | ✅ | ❌ | New harness primitive (§5); Orchestrator excluded per §4.8 |
| `bash bg_acknowledge` | ❌ | ✅ | ❌ | New harness primitive (§5.5); Orchestrator excluded per §4.8 |
| `TodoWrite` | ✅ | ✅ | ✅ | claw-code; in-VM scratchpad, no kernel intent |
| LSP (any language server) | ❌ | ✅ | ❌ | Reviewer exclusion (§4.1); Orchestrator does not write code, no use case; Executor full LSP per its image |
| `WebFetch`, `WebSearch` | ❌ | ❌ | ❌ | Replaced by unified egress (§7); use standard tools through `raxis-tproxy` or Credential Proxy |
| `StructuredOutput` | ❌ | ❌ | ❌ | Excluded — no DAG consumer (§6.1) |
| `Sleep` | ⚠ pending | ⚠ pending | ❌ | Hole still under review |
| `branch_lock` | ❌ | ❌ | ❌ | Pending review; preliminary verdict: dead code in synchronous-LLM-loop model |
| MCP tools (any) | ❌ | ❌ | ❌ | MCP rejected as authority bypass (`design-decisions.md`) |
| `oauth`, `remote`, `trust_resolver`, `hooks`, `worker_boot`, `sandbox` | ❌ | ❌ | ❌ | Per-module exclusions (§4.1 borrowed-module table) |
| `Agent` (claw-code sub-agent spawn) | ✅ via `ActivateSubTask` | ❌ | ❌ | Replaced by kernel-mediated DAG; Orchestrator delegates only |
| Kernel-mediated intents (`SingleCommit`, `InferenceRequest`, `EscalationRequest`, etc.) | per `kernel-store.md` dispatch matrix | per dispatch matrix | per dispatch matrix | Authoritative enforcement at the kernel layer regardless of harness exposure |
| Operator-defined custom tools (`[[profiles.<name>.custom_tool]]`) | ❌ | ✅ | ❌ | Third tool category alongside base tools and kernel intents; canonical home `custom-tools.md`. Reviewer prohibition is `INV-PLANNER-HARNESS-04` (§4.6); Orchestrator prohibition is `INV-PLANNER-HARNESS-06` (§4.8) — operators do not declare Orchestrator profiles at all, so there is no surface on which to declare custom tools. |

**Plan-side authoring surface (not tools, but role-asymmetric):**

| Field | Orchestrator | Executor | Reviewer | Notes |
|---|---|---|---|---|
| `[plan.tasks.<id>] path_allowlist` | n/a (Orchestrator is not operator-configurable per §4.8 + `INV-PLANNER-HARNESS-06`) | required (explicit, no kernel default per `operator-ergonomics.md §4.5`) | **forbidden** — declaring the field in any form, including `[]`, hard-fails admission with `FAIL_REVIEWER_PATH_ALLOWLIST_NOT_ALLOWED` | Structural ban: Reviewer's `/workspace` is RO and the Reviewer harness has no commit-pathway intent (no `SingleCommit`, no `IntegrationMerge`, no `edit_file`, no `bash`); the field is structurally meaningless. Mirrors the `vm_image` ban (§4.5, `INV-PLANNER-HARNESS-02`) and custom-tool ban (§4.6, `INV-PLANNER-HARNESS-04`). The `INV-PLANNER-HARNESS-01` invariant statement is extended to enumerate this prohibition explicitly. |

**The asymmetric defense pattern.** Reviewer's tool surface is intentionally
the smallest. The argument (§4) is structural: the Reviewer is the backstop
against deception of the Executor's richer toolchain. If the Executor's
LSP is poisoned by a malicious `build.rs`, the Reviewer reads the diff on
raw bytes and is structurally incapable of being deceived by the same
vector. Removing capabilities from the Reviewer is *load-bearing*, not
just defense-in-depth.

The same load-bearing logic extends from runtime tools to plan-side
authoring fields: any plan field whose semantics presuppose a capability
the Reviewer lacks is structurally meaningless on a Reviewer task and is
hard-rejected at admission, not silently stripped. The kernel never
mutates an operator-signed plan; the operator owns every byte they sign.
The role-asymmetric authoring surface above lists the V2 fields where this
asymmetry is enforced.

---

## §4 — Role-Asymmetric Tooling Decisions

This section consolidates the four sub-decisions that defined the Reviewer
role's capability boundary, plus the new decision (§4.5) that makes the
Reviewer's runtime environment kernel-owned.

### 4.1 Decision — Reviewer Role Excludes LSP Tooling

**Context.** A Reviewer evaluates an Executor's `evaluation_sha` and emits
a `SubmitReview { approved, critique }` verdict. The harness question is:
does the Reviewer's planner expose Language Server Protocol (LSP) tools
(`rust-analyzer`, `tsserver`, `pyright`, `gopls`, etc.) to the LLM, or
only text-search primitives (`read_file`, `glob_search`, `grep_search`)?

LSPs provide structured semantic access (go-to-definition,
find-all-references, hover-types). They also routinely execute project code
as part of indexing — `rust-analyzer` runs `build.rs` and procedural
macros, older Python tooling imports modules to extract types, JS tooling
resolves `package.json` `postinstall` scripts. Not all LSPs are
configurable to disable this; among those that are, every LSP exposes a
different config surface, and operator-side policy to keep that surface
safe across language ecosystems and tool versions is operationally
infeasible.

**Threat being defended against.** A compromised Executor commits a
malicious build script (`build.rs`, `setup.py`, `package.json` postinstall
hook). If the Reviewer's LSP processes that file as part of opening the
project, the script runs inside the Reviewer VM and can poison LSP
responses — the LSP returns fabricated semantic data ("no callers of this
sensitive function exist", "this type matches the expected signature")
that the Reviewer LLM trusts. The Reviewer's verdict is delivered with the
same confidence as an honest verdict; the audit chain records
`SubmitReview { approved: true }` with no signal that the verdict was
contaminated. The VM's hardware isolation (no egress, RO mount) contains
the blast radius to "Reviewer's verdict for this session is wrong" — but
that single failure mode defeats the review gate categorically, since
approved work flows on into `IntegrationMerge`.

**Two architecturally viable options were considered.**

*Option A — Accept the deception risk.* Run LSPs in the Reviewer VM
without attempting to lock down their config. Rely on hardware isolation
to prevent exfiltration and repo mutation. Accept that a malicious build
script can deceive the Reviewer LLM into approving backdoored code; treat
the Reviewer's verdict as "honest given the inputs, where the inputs may
be weaponized."

*Option B — Exclude LSP for the Reviewer role.* Reviewers operate on raw
text only — `read_file`, `glob_search`, `grep_search`. No LSP, no
compilers, no tool that executes code from the worktree. The LLM performs
semantic analysis from text the same way a human PR reviewer reads a
GitHub diff. Test execution and other code-running verification is
performed by separate kernel-spawned verifier processes whose output is
surfaced to the Reviewer via witnesses and the KSB, never by the Reviewer
running code itself.

**Decision: Option B.** Three converging reasons:

1. **Failure-mode shape.** Option A's failure mode is *confident wrongness*
   delivered through the audit chain with no detectable signal. Option B's
   failure mode is *less precision* — the Reviewer may miss subtle bugs
   but cannot be deceived into fabricated approvals. For a system whose
   value proposition is structurally enforced trust in verdicts, confident
   wrongness is categorically worse than less precision. Option A cannot
   be reconciled with the fail-closed posture: it produces confident
   `approve` on weaponized data.

2. **Configuration surface impossibility.** Per-LSP, per-language,
   per-version safe-config matrices cannot be maintained at operator
   scale. A categorical "Reviewer cannot execute project code" rule
   survives operator drift, version upgrades, and ecosystem changes. A
   "Reviewer's LSP is hardened against most known build-script attacks"
   rule does not.

3. **Load-bearing asymmetry.** The Executor role still has full LSP access
   to write code. The Executor's LSP can itself be deceived by the same
   malicious build script. The Reviewer's lack of LSP is the structural
   backstop: when the deceived Executor commits, the Reviewer reads the
   diff on raw text and sees the malicious `build.rs` literally — bytes,
   not LSP-mediated semantics — and can flag it. Removing LSP from the
   Reviewer is not just "the Reviewer doesn't need this capability"; it
   is the mechanism by which Executor-LSP deception is caught downstream.
   This is asymmetric defense by design.

**Counter-arguments considered and rejected.**

- *"Some LSPs (pyright, ruff) are pure static analysis and cannot execute
  code."* True for the current version of each. False as a stable property
  over time — any LSP can add a plugin system, dynamic resolution mode, or
  build-script invocation in a future release. A categorical rule is the
  only configuration that survives these changes without operator action.

- *"Sandboxed LSP-VM (LSP runs in its own isolated VM, talks to Reviewer
  over VSock)."* Considered. Does not solve the problem. The LSP-VM still
  mounts the worktree, still runs project code, still produces semantic
  data the Reviewer trusts. The deception attack moves location but is not
  eliminated; isolation between LSP and Reviewer processes does not help
  when the LSP's *output* is the attack vector.

- *"TypeScript / generic-heavy code is genuinely hard to review without
  type info."* Conceded as a real precision loss. Mitigation: `tsc` is run
  by the verifier and type errors populate witness records — the Reviewer
  sees "this PR introduces 3 type errors" via the KSB without an LSP. For
  semantic understanding of the diff, raw text + grep is sufficient for
  the majority of cases; the residual cases that genuinely need expanded
  type information are exactly the cases the Reviewer should escalate
  rather than approve.

- *"Operators will perceive this as missing modern tooling."* This is
  positioning, not a security argument. Operators choosing RAXIS over
  claw-code-direct are choosing structural guarantees over tool
  convenience; the marketing claim "Reviewers cannot execute code from
  the codebase under review" is a feature, not a deficiency.

**Verifier-process implications.** Excluding LSP from the Reviewer
concentrates the "untrusted code execution" risk in the verifier processes
(where `cargo test`, `npm test`, etc. run). This is the correct place to
concentrate that risk: verifier output is binary pass/fail and counter
aggregates, not semantic data the Reviewer trusts for nuanced decisions.
A malicious build script in a verifier VM can flip a test result (a
coarse, often-detectable attack), but it cannot poison a "find all
references to this auth function" query (the fine-grained attack class
that retaining LSP in the Reviewer would enable). See §8 for the
verifier-process architecture overview.

**Operator note — token cost.** Reviewer sessions under this decision
typically consume 2–3× the per-review tokens of an LSP-equipped Reviewer
(more `grep_search` calls, more `read_file` reads, longer search windows).
This is a real but bounded cost. The Kernel has no opinion about which
model a Reviewer uses — model choice is operator policy, declared in the
plan via the provider-aliases mechanism (`provider-failure-handling.md`).
When authoring plans, operators should consider routing Reviewer roles to
a cheaper/faster model alias than Executor roles if their plan-level
economics make the increased token volume material; adjusting per-task
token caps and wall-clock budgets (`agent-disagreement.md`
`INV-CONVERGENCE-03`) for large-codebase reviews; and pre-computing a
`symbol_index.json` artifact via a parser-only verifier (see §8 and
`verifier-processes.md`) so the Reviewer can resolve symbols without
scanning the worktree.

**V2 amendment — symbol-index auto-injection.** The third bullet above
is no longer purely operator-DIY. By default
(`policy.toml [prepare] auto_inject_symbol_index = true` per
`policy-plan-authority.md §4 [prepare]`), `raxis-cli plan prepare`
auto-injects a `symbol_index` verifier into every Executor task whose
touched paths include source files, using the kernel-canonical
`raxis-verifier-symbol-index` image (per `verifier-processes.md §14`
and `INV-VERIFIER-12`). The injected verifier produces
`/raxis/symbol_index.json` per `§8.3`, which the Reviewer reads via
`read_file`. The auto-injection is a structural fix for the Pure-Static
Reviewer's symbol-resolution gap — it converts
`WARN_REVIEWER_MISSING_SYMBOL_INDEX` from a default-state warning into
a "yes, by default" guarantee. Operators who want to opt out per-task
declare `[plan.tasks.<id>.review] symbol_index = "not_needed"` (this
existing knob silences the warning); operators who want to opt out
deployment-wide set the policy knob to `false`. The annotation
`# @raxis-default v0.4.0 symbol-index-auto-inject` makes the injected
entry visibly operator-owned in the signed plan bytes (per
`operator-ergonomics.md §4.2`).

The first two bullets remain operator-DIY: model selection is operator
policy, and per-task token caps are operator authoring choices. RAXIS
does not silently substitute models or inflate budgets on the
operator's behalf — every configuration that affects cost or behavior
is explicit in `plan.toml` / `policy.toml` and signed. Auto-injection
of the symbol-index verifier is the **single** exception to this, and
it is a structural exception (the Pure-Static Reviewer is structurally
dependent on the artifact for full symbol-resolution fidelity); the
operator can still see and audit the injected entry in their signed
plan, and the policy knob makes opt-out a single flip.

### 4.2 Decision — Pure-Static Reviewer (Remove `bash` from Reviewer; Verifiers Are Out-of-VM)

**Context.** The original "Borrowed As-Is" claw-code integration map
includes the `bash` module — `runtime/src/bash.rs`, `sh -lc` execution via
tokio async — for all roles. Excluding LSP (§4.1) does not by itself
exclude `bash`. Without an explicit exclusion, the Reviewer would retain
a fully general code-execution primitive even with no LSP, defeating the
purpose of the LSP exclusion: a compromised Executor could commit a
script that the Reviewer's LLM is socially-engineered into running via
`bash::run` (e.g., "to verify the fix, please run `./reproduce.sh`"), and
the malicious script executes with all the same risks the LSP exclusion
was meant to eliminate.

The corollary question is what mechanism *does* run tests, linters, type
checkers, and other code-aware verification under the new design, since
the Reviewer can no longer run them itself. The answer is the
verifier-process architecture (§8): code-running verification is performed
by separate Kernel-spawned verifier VMs, distinct from the Reviewer VM,
whose binary pass/fail outputs are written to `witness_records` and
surfaced to the Reviewer via the KSB.

**Decision: remove `bash` from the Reviewer role's tool set entirely;
ship the Reviewer with an image that contains no shell at all; perform
all code-running verification in separate Kernel-spawned verifier
processes.** The Reviewer becomes a pure read-only static-analysis engine:
its only operations on the worktree are `read_file`, `glob_search`,
`grep_search`, none of which can execute worktree code.

**Rationale.**

1. **Shells are general-purpose code-execution vectors, not "safe glue."**
   Even with LSP excluded, the presence of `bash::run` would let any
   sufficiently-crafted critique or commit message socially-engineer the
   Reviewer LLM into executing worktree contents. The phrase "a malicious
   PR cannot attack a Reviewer that lacks the tools to run it" captures
   this precisely: capability removal is more robust than capability
   restriction plus prompt-engineering hope.

2. **The Reviewer has no legitimate need for shell execution under the
   verifier architecture.** Test runs, lint runs, type checks, build
   attempts — every code-aware check the Reviewer might want — happens
   in a separate verifier VM whose output is in `witness_records` before
   the Reviewer is even activated (per `v2-deep-spec.md §Step 23`,
   sequential activation). The Reviewer reads witnesses from its KSB; it
   does not re-run tests. Removing `bash` therefore removes a capability
   with no legitimate consumer, leaving only the attack surface.

3. **Strongest form of the asymmetric defense pattern.** The Executor has
   full `bash` and full LSP — convenience and capability. The Reviewer has
   neither. When a deceived Executor commits subtly-malicious code, the
   shell-free Reviewer reads the diff on raw bytes and is structurally
   incapable of being deceived by the same vector. With both LSP and
   shell excluded for the Reviewer, the structural backstop covers both
   the build-script and the social-engineering attack classes.

4. **Verifier-process concentration is the right risk model.** Removing
   in-Reviewer shell execution concentrates the "untrusted code
   execution" risk in verifier VMs, where the threat model is
   structurally narrower: verifier output is binary pass/fail and counter
   aggregates (test counts, error counts, exit codes), not semantic data
   the Reviewer trusts for nuanced decisions.

**Counter-arguments considered and rejected.**

- *"What if the Reviewer needs to run `git diff` or `git log` to
  understand the change?"* The diff is pre-computed by the kernel and
  written to `/raxis/diff.patch` at session activation. The commit log
  relevant to the evaluation SHA is similarly pre-computed and written
  to `/raxis/log.txt`. The Reviewer reads these via `read_file`. No live
  `git` invocation is needed.

- *"What if the Reviewer wants to grep for a regex that ripgrep doesn't
  support?"* `ripgrep` supports the full Rust regex grammar, which covers
  the cases the Reviewer's LLM realistically needs. If a future need
  emerges for a different search backend, the harness can swap `ripgrep`
  for that backend (still invoked via direct `execvp`, never through a
  shell). The decision is shell-exclusion, not ripgrep-specifically.

- *"This forces operators to maintain a separate Reviewer image."* Not
  under the canonical-image decision (§4.3) — the Reviewer image is
  RAXIS-built and kernel-enforced. Operators do not maintain it.

- *"What about Reviewers that need to consult external context (e.g.,
  organization style guide, design docs)?"* Static reference material
  pulled from operator-controlled sources is provided through the system
  prompt at session activation (`kernel-mechanics-prompt.md`), which the
  kernel writes into `/raxis/system_prompt.txt` before VM boot. The
  Reviewer reads the prompt at startup; no runtime fetch is needed. If
  large reference corpora are required, the kernel can additionally
  pre-populate `/raxis/reference/` (read-only) with operator-curated
  documents — a future enhancement, not required for V2 GA.

- *"Test harness output is sometimes non-binary — coverage maps,
  property-based-testing counterexamples, fuzzing seed corpora."* The
  verifier-process design accommodates this: structured outputs from the
  verifier (when the verifier's command emits a parseable format such as
  JUnit XML, `cargo test --message-format=json`, LCOV) are parsed by
  `raxis-verifier` and persisted as structured columns / blobs in
  `witness_records`. The Reviewer's KSB exposes these as structured
  fields, not as opaque blobs.

**Plan-side authoring corollary: `path_allowlist` is forbidden on
Reviewer tasks.** The decisions in this section (no `bash`, no
`edit_file`, no `write_file`, RO `/workspace` mount) collectively make
the `path_allowlist` field structurally meaningless on a Reviewer task —
there is no commit-pathway intent for the kernel to enforce a write-scope
against, and the harness has no write capability the operator could
mistakenly believe `path_allowlist` would constrain. Declaring the field
in any form (including `path_allowlist = []`) hard-fails admission with
`FAIL_REVIEWER_PATH_ALLOWLIST_NOT_ALLOWED` per `policy-plan-authority.md
§3b` and `INV-PLANNER-HARNESS-01`. `raxis-cli plan prepare` surfaces the
same hard-refusal pre-signing per `operator-ergonomics.md §4.5.5` so the
operator catches the issue before bundle sealing. The kernel does NOT
silently strip the field — every byte the operator signed is the operator's
responsibility, including the bytes that are now structurally invalid.

### 4.3 Decision — Canonical Reviewer Image (Kernel-Owned, Operator-Inaccessible)

**Context.** The previous two decisions (§4.1, §4.2) reduce the Reviewer's
tool set to `read_file`, `glob_search`, `grep_search`, `TodoWrite`,
`SubmitReview`. This means the Reviewer image needs **no language
toolchain, no LSP, no compiler, no shell, no `git`, no curl, no editor,
no package manager**. Its sole runtime contents are: `raxis-planner` (PID
1), `ripgrep` (called by the harness via direct `execvp`), the Linux
kernel and its cgroup v2 substrate, and the dynamic loader / libc
required to execute the planner binary.

This is a small, fixed, language-agnostic environment. There is no
operator customization that benefits the Reviewer's job. Yet under
`INV-VM-CAP-03` as originally specified, the operator publishes the image
and the policy bundle pins it by OCI digest. This shifts a meaningful
supply-chain decision (what binaries does the Reviewer trust?) from RAXIS
to the operator, with no upside.

**Threat being defended against.** Two distinct threat classes both
solved by the same change:

1. *Operator supply-chain risk.* An operator publishes a Reviewer image
   that contains a tampered `libc`, a backdoored `ripgrep`, or any other
   binary that selectively misreports file contents to the harness — a
   `grep` that hides specific malicious strings, a `read_file` syscall
   intercepted by an LD_PRELOAD shim, etc. The Reviewer LLM, trusting its
   tools, approves backdoored code based on selectively-filtered
   evidence. The audit chain records `SubmitReview { approved: true }`
   with no signal that the toolchain itself was the attack vector.

2. *Operator mental-burden risk.* Maintaining a Reviewer image is
   pure overhead with no benefit — the Reviewer doesn't use language
   toolchains, doesn't run tests, doesn't compile. Every operator who
   builds their first Reviewer image makes a series of irrelevant
   decisions (which base distro? which `ripgrep` version? which
   libc?) that have no productive consequence but each carries
   non-zero security risk if mishandled. Operators in practice will
   either reuse their Executor image (massively over-provisioned, full
   toolchain in the Reviewer environment, defeating §4.2's image-layer
   enforcement), or build a minimal image incorrectly (missing cgroup
   v2 setup, missing `ripgrep`, wrong libc ABI), producing
   hard-to-diagnose runtime failures.

**Decision: the Reviewer image is RAXIS-built, kernel-bundled,
kernel-digest-verified, and operators cannot specify a Reviewer image at
all.** The `plan.toml` schema rejects any `vm_image` field on Reviewer
tasks; the `policy.toml` `[[vm_images]]` table does not require a
Reviewer entry; the kernel hardcodes the path to its bundled
`raxis-reviewer-core.img` and the expected OCI digest. At session
activation the kernel boots Reviewer VMs from this image unconditionally.

**Rationale.**

1. **The Reviewer's runtime contents are a kernel concern, not an
   operator concern.** The Reviewer enforces a security boundary
   (`INV-PLANNER-HARNESS-01`); its environment must be under the same
   trust root as the kernel that enforces the rest of the boundary.
   Operators do not get to choose the kernel binary either — the
   Reviewer image is in the same category.

2. **Eliminates an entire supply-chain attack surface for zero
   functionality loss.** No legitimate operator workflow benefits from
   per-operator Reviewer images. Removing the option closes the
   supply-chain risk class without removing any capability the operator
   actually wants.

3. **Reduces operator burden categorically.** Operators no longer need
   to know that Reviewer images exist, much less how to build one.
   "Operators publish toolchain images for Executor tasks only; the
   Reviewer and Orchestrator images are the kernel's responsibility"
   is a clean one-line operator-facing summary (since the Orchestrator
   image is also kernel-canonical per `INV-PLANNER-HARNESS-05`, §4.7).

4. **Composes cleanly with §4.1 and §4.2.** The image-layer enforcement
   of `INV-PLANNER-HARNESS-01` is no longer "operator-responsibility,
   verified by digest you provided" but "kernel-built and kernel-pinned"
   — strictly stronger.

**Image specification (`raxis-reviewer-core.img`).**

| Component | Present? | Rationale |
|---|---|---|
| Linux kernel ≥ 5.14 | ✅ | Needed for `cgroup.kill` (§5.3); RAXIS V2 baseline |
| cgroup v2 mounted at `/sys/fs/cgroup/`, `cpu` + `memory` + `pids` controllers in `cgroup.subtree_control` | ✅ | Required for the harness's per-call cgroup containment, even though the Reviewer cannot itself create bash sessions (the harness uses cgroups internally to reap `ripgrep` subprocesses on timeout) |
| `raxis-planner` binary (PID 1, statically linked with `bash` module **excluded** at link time, `grep_search`/`glob_search` using direct `execvp` rather than `sh -lc` wrapper) | ✅ | The agent runtime |
| `ripgrep` binary (statically linked, called by `raxis-planner` via `execvp` for `grep_search` backend) | ✅ | Backend for text search |
| Dynamic loader, libc | ✅ if `raxis-planner` and `ripgrep` are dynamically linked. **Recommended to ship both fully static**, eliminating libc ABI from the trust surface entirely. | Either is acceptable; static is preferred |
| `/bin/sh`, `/bin/bash`, `busybox`, any other shell | ❌ | No shell of any kind |
| Any LSP server (`rust-analyzer`, `tsserver`, `pyright`, `gopls`, `clangd`, …) | ❌ | Excluded under §4.1 |
| Any compiler or language runtime (`rustc`, `cargo`, `node`, `npm`, `python`, `pip`, `go`, `ruby`, …) | ❌ | Tests run in verifier VMs; not the Reviewer |
| `git` CLI | ❌ | Worktree pre-populated host-side; Reviewer never invokes git |
| Network utilities (`curl`, `wget`, `ssh`, `nc`, `dig`, …) | ❌ | Reviewer has no egress (no tproxy interface, no Credential Proxy interfaces); nothing to reach |
| Editors, file managers (`vi`, `nano`, `less`, …) | ❌ | Reviewer reads files programmatically via `read_file`; no interactive tooling |
| `ctags` or other symbol indexers | ❌ | Symbol indexing is performed by an operator-declared verifier (see §8 and the symbol-index decision in §6.2 once that lands); the Reviewer reads the resulting `symbol_index.json` artifact via `read_file` |

**Distribution mechanism.** The canonical image bytes are bundled with the
RAXIS kernel release as `$RAXIS_INSTALL_DIR/images/raxis-reviewer-core-<version>.img`
(or platform-equivalent). The kernel binary contains a compiled-in
constant `EXPECTED_REVIEWER_IMAGE_DIGEST: [u8; 32]` that names the
SHA-256 digest of the image bundled with that kernel version. At kernel
startup the path is checked for existence; at session activation for any
Reviewer task, the kernel re-verifies the on-disk digest against the
compiled-in constant before boot.

This binds **kernel version and Reviewer image version together
1-to-1**: there is no scenario in which a kernel runs against a Reviewer
image it did not ship with. Kernel security updates that change the
Reviewer image require a kernel re-release; operators cannot independently
update the Reviewer image, and conversely cannot accidentally run a stale
Reviewer image against a newer kernel.

**No registry dependency.** The image is a local file on disk. Air-gapped
operators (per `system-requirements.md`) can run RAXIS Reviewers without
any registry access. The kernel does not pull from any OCI registry for
the Reviewer image.

**Schema enforcement at `approve_plan` time.**

```
FAIL_REVIEWER_VM_IMAGE_NOT_ALLOWED
  task_id:           "security_reviewer"
  session_agent_type: "Reviewer"
  declared_field:     vm_image = "my-org/reviewer:1"

  reason:
    Reviewer-role tasks MUST NOT specify a vm_image. The Reviewer image
    is kernel-owned and kernel-verified per INV-PLANNER-HARNESS-02; any
    operator-supplied vm_image for a Reviewer task is rejected at plan
    admission.

  remediation:
    Remove the `vm_image` field from this Reviewer task. The kernel will
    boot the Reviewer VM from the bundled raxis-reviewer-core image
    automatically.
```

This is a hard `FAIL_*` (not a warning) — there is no scenario in which an
operator-supplied Reviewer image is acceptable, so a warning with strict-mode
escalation would just delay the inevitable rejection.

**Digest mismatch at activation time.**

```
FAIL_REVIEWER_IMAGE_DIGEST_MISMATCH
  expected_digest:    sha256:e3b0c44298fc1c149afbf4c8996fb924...
  observed_digest:    sha256:c057a3e7ea75c2aef3c1cd95fa1aac84...
  image_path:         /usr/local/lib/raxis/images/raxis-reviewer-core-2.0.4.img

  reason:
    The bundled Reviewer image's SHA-256 digest does not match the value
    compiled into this kernel binary (sha256:e3b0c44298fc1c149afbf4c8996fb924...).
    This indicates either (a) the kernel binary and the image bundle are
    from different releases, (b) the on-disk image has been modified
    after install, or (c) the install was incomplete.

  remediation:
    Reinstall RAXIS from a verified source. Verify the on-disk image
    SHA-256 matches the published release digest. Do not attempt to
    activate Reviewer tasks until the digest mismatch is resolved.

  audit:
    SecurityViolationDetected { kind: "ReviewerImageDigestMismatch", ... }
```

The kernel refuses to activate any Reviewer task with this error; the
initiative is not failed (other roles continue), but Reviewer tasks
are blocked until the operator resolves the install state.

### 4.4 `INV-PLANNER-HARNESS-01` — Reviewer Code Execution Prohibition

> A planner session whose `session_agent_type = 'Reviewer'` MUST NOT have
> access to any tool capable of executing code, where "executing code"
> means transferring control to instructions whose contents are derived
> from the worktree under review or from any file the agent can write or
> influence. This explicitly includes:
>
> - **Shells of any kind** (`bash`, `sh`, `dash`, `zsh`, `busybox sh`,
>   etc.). Shells are general-purpose code-execution vectors: even if
>   the shell itself is innocuous, the `bash::run` claw-code primitive
>   and any equivalent give the agent the ability to invoke arbitrary
>   binaries, including build tools, language runtimes, and
>   worktree-resident scripts.
> - **Language Server Protocol clients/servers** (per §4.1).
> - **Compilers, interpreters, and language runtimes** invoked either
>   directly or as inspection tools (`rustc`, `python`, `node`, `ruby`,
>   `cargo run`, `npm run`, etc.).
> - **Debuggers, REPLs, package-manager scripts, and any wrapper that
>   internally invokes the above.**
>
> The Reviewer's tool set is restricted to: read-only file inspection
> (`read_file`), text search (`glob_search`, `grep_search` — implemented
> via direct `execvp` of a parser-only search binary such as `ripgrep`,
> never through a shell), self-organization (`TodoWrite`), verdict
> submission (`SubmitReview`), and any other tools explicitly authorized
> by the Kernel dispatch matrix for the Reviewer role that satisfy the
> above prohibition. Code-running verification (test execution, linting
> that requires resolution, type checking that requires module loading)
> is performed by separate Kernel-spawned verifier processes whose
> output is surfaced to the Reviewer via `witness_records` and the KSB.
>
> Enforcement is three-layer:
>
> 1. **Image layer** — the Reviewer VM image is the kernel-bundled,
>    kernel-digest-verified `raxis-reviewer-core` (per
>    `INV-PLANNER-HARNESS-02`, §4.5). Operators cannot specify a
>    Reviewer image. The image contains no shells, no LSPs, no
>    compilers, no language runtimes, no `git`, no network utilities;
>    only `raxis-planner` and `ripgrep`.
> 2. **Harness layer** — the Reviewer-role planner harness MUST filter
>    forbidden tool names out of the LLM's available-tools list
>    (`PermissionPolicy` for pre-prompt filtering). The `bash`
>    claw-code module is not linked into the Reviewer build target.
>    The `file_ops` module's `grep_search` and `glob_search`
>    implementations MUST use direct `execvp` of the search binary (no
>    `sh -lc` wrapper), so that no code path inside the planner can
>    spawn a shell even if a future tool addition mistakenly wires one
>    in.
> 3. **Kernel dispatch layer** — the Kernel's intent-dispatch matrix
>    remains the authoritative enforcement layer; any intent forbidden
>    for the Reviewer role is rejected at admission regardless of
>    whether the harness or image leaked the capability. Image and
>    harness enforcement are defense-in-depth that prevent the LLM
>    from wasting turns on tools that would be rejected anyway.
>
> **Plan-side authoring corollary (V2).** The Reviewer's tool-execution
> prohibition extends to the plan-side authoring surface: any plan field
> whose semantics presuppose a capability the Reviewer lacks is
> structurally meaningless on a Reviewer task and MUST be rejected at
> admission. The V2 enumeration:
>
> - **`[plan.tasks.<id>] vm_image`** (and any image-specifying field on
>   a Reviewer task) — covered by `INV-PLANNER-HARNESS-02` (§4.5);
>   admission FAIL `FAIL_REVIEWER_VM_IMAGE_NOT_ALLOWED`.
> - **`[[profiles.<name>.custom_tool]]` blocks** on a Reviewer-rooted
>   profile-inheritance chain — covered by `INV-PLANNER-HARNESS-04`
>   (§4.6); admission FAIL `FAIL_REVIEWER_CUSTOM_TOOL_NOT_ALLOWED`.
> - **`[plan.tasks.<id>] path_allowlist`** (any value, including `[]`) —
>   the Reviewer's `/workspace` is mounted read-only and the harness has
>   no commit-pathway intent (`SingleCommit`, `IntegrationMerge`,
>   `edit_file`, `bash`); the field is structurally meaningless;
>   admission FAIL `FAIL_REVIEWER_PATH_ALLOWLIST_NOT_ALLOWED` per
>   `policy-plan-authority.md §3b` and §3 role table above. The kernel
>   never silently mutates an operator-signed plan; the operator must
>   delete the field themselves (`raxis-cli plan prepare` surfaces the
>   hard-refusal pre-signing per `operator-ergonomics.md §4.5.5`).
>
> Future V2.x additions to this enumeration MUST follow the same
> discipline: (a) document why the field is structurally meaningless on
> a Reviewer task; (b) add the corresponding `FAIL_REVIEWER_*` admission
> code in `policy-plan-authority.md §3b`; (c) extend `plan prepare`'s
> §4.5 surface in `operator-ergonomics.md` to surface the rejection
> pre-signing; (d) update this corollary block.

### 4.5 `INV-PLANNER-HARNESS-02` — Reviewer Image Is Kernel-Owned

> The Reviewer VM image is RAXIS-built and kernel-bundled. Operators MUST
> NOT specify a Reviewer image at any layer:
>
> - The `plan.toml` schema rejects `vm_image` on any task whose
>   `session_agent_type = 'Reviewer'` with `FAIL_REVIEWER_VM_IMAGE_NOT_ALLOWED`
>   at `approve_plan` time. There is no operator override.
> - The `policy.toml` `[[vm_images]]` table does not require a Reviewer
>   entry; if one is present with `role_restriction` including
>   `Reviewer`, it is silently ignored for Reviewer task activation
>   (the kernel does not consult `[[vm_images]]` for Reviewer images).
> - The kernel binary contains a compiled-in constant
>   `EXPECTED_REVIEWER_IMAGE_DIGEST: [u8; 32]` (SHA-256). At session
>   activation for any Reviewer task, the kernel re-computes the SHA-256
>   of the on-disk `raxis-reviewer-core` image and refuses to boot the
>   VM with `FAIL_REVIEWER_IMAGE_DIGEST_MISMATCH` on any mismatch,
>   emitting `SecurityViolationDetected { kind:
>   "ReviewerImageDigestMismatch" }`.
>
> The image bytes are distributed with the RAXIS kernel release at a
> known local path (`$RAXIS_INSTALL_DIR/images/raxis-reviewer-core-<version>.img`).
> Kernel and Reviewer image are version-locked: a kernel release ships
> with exactly one Reviewer image whose digest the kernel knows. There
> is no registry dependency for Reviewer activation; air-gapped
> deployments work without modification.
>
> This invariant exists because the Reviewer enforces a security
> boundary (`INV-PLANNER-HARNESS-01`) and its runtime environment must
> live under the same trust root as the kernel. Operators retain full
> control over the Executor image via the existing `INV-VM-CAP-03`
> mechanism; the Reviewer is one of two structural exceptions (the
> other being the Orchestrator per `INV-PLANNER-HARNESS-05`, §4.7).
>
> **Composition with `INV-VM-CAP-03`.** `INV-VM-CAP-03` continues to
> govern Executor image pinning unchanged: operator publishes the
> image, policy pins by OCI digest, kernel verifies the pulled image
> matches the policy-pinned digest. Both the Reviewer (this invariant)
> AND the Orchestrator (`INV-PLANNER-HARNESS-05`) are categorical
> exceptions: the kernel owns the image, the kernel pins the digest,
> the operator has no role.

---

### 4.6 `INV-PLANNER-HARNESS-04` — Reviewer Custom Tool Prohibition

> **Statement (canonical home: `custom-tools.md` §10).** A profile
> whose effective role is `Reviewer` MUST NOT declare any
> `[[profiles.<name>.custom_tool]]` blocks (directly or via
> `inherits_from`-chain ancestor profiles). Plan admission walks the
> inheritance graph, computes the effective custom-tool set for each
> profile, and rejects with `FAIL_REVIEWER_CUSTOM_TOOL_NOT_ALLOWED
> { profile, declaring_profiles: [...] }` if the effective role is
> `Reviewer` AND the effective custom-tool set is non-empty. Custom
> tools may be declared on any profile inheriting from `Executor` or
> `Orchestrator`; the structural ban applies only to Reviewer-rooted
> inheritance chains.

This invariant is the natural extension of `INV-PLANNER-HARNESS-01`
(no Reviewer code execution) into the operator-extension surface
introduced by `custom-tools.md`. A custom tool is, by definition,
arbitrary code execution: a forked subprocess running operator-defined
argv with operator-defined input. Permitting custom tools on a
Reviewer profile would re-introduce exactly the attack class
`INV-PLANNER-HARNESS-01` was designed to eliminate — a malicious
build script could exfiltrate code through the operator's custom tool
just as easily as it could through a built-in `bash`.

The kernel-bundled `raxis-reviewer-core` image
(`INV-PLANNER-HARNESS-02`) lacks the runtimes (`python3`, `node`,
shell, compilers) most operator-declared scripts would require, so
most violations would fail at runtime regardless. But "fails at
runtime" produces partial audit trails, surfaces failure to the LLM
mid-loop, and leaks the misconfiguration into a live session.
Catching the declaration at admission, with a clear remediation
message, is the correct fail-closed posture.

**The supported alternative for operators who want operator code to
influence Reviewer judgment:** declare a verifier
(`verifier-processes.md`). Verifier output reaches the Reviewer via
`verifier_witnesses` in the KSB and properly gates review activation
per `INV-VERIFIER-04`, all while keeping the Reviewer's tool surface
pure-static. The decision tree in `custom-tools.md §11` makes this
choice explicit.

**Three-layer composition with prior `INV-PLANNER-HARNESS-*`:**

- `INV-PLANNER-HARNESS-01` — Reviewer harness build excludes the
  `bash` module entirely (no built-in code-execution capability in
  the binary).
- `INV-PLANNER-HARNESS-02` — Reviewer image is kernel-canonical; even
  if a code-execution path existed in the binary, the image lacks the
  runtimes to execute most operator scripts.
- `INV-PLANNER-HARNESS-04` — admission rejects operator-declared
  custom tools on Reviewer profiles before any session is created.

The three layers compose to a Reviewer that is provably incapable of
executing operator-defined code, with the failure mode caught at the
earliest possible point in each scenario.

---

### 4.7 `INV-PLANNER-HARNESS-05` — Canonical Orchestrator Image

> **Statement.** A V2 Orchestrator session boots from a kernel-bundled,
> kernel-digest-verified image — `raxis-orchestrator-core` — distributed
> alongside the kernel binary at
> `$RAXIS_INSTALL_DIR/images/raxis-orchestrator-core-<kernel_version>.img`.
> The kernel binary contains a compiled-in constant
> `EXPECTED_ORCHESTRATOR_IMAGE_DIGEST: [u8; 32]` (SHA-256). At every
> Orchestrator activation the kernel re-computes the SHA-256 of the
> on-disk image bytes and refuses to boot the VM with
> `FAIL_ORCHESTRATOR_IMAGE_DIGEST_MISMATCH` on any mismatch, emitting
> `SecurityViolationDetected { kind: "OrchestratorImageDigestMismatch" }`.
>
> Operators MUST NOT supply a custom Orchestrator image; the
> `policy.toml` `[[vm_images]]` table's `role_restriction` field
> rejects any entry containing `"Orchestrator"` at policy load with
> `FAIL_POLICY_INVALID_ROLE_RESTRICTION`. The plan parser rejects any
> profile that resolves to the `Orchestrator` role with
> `FAIL_ORCHESTRATOR_PROFILE_NOT_ALLOWED` (per `INV-PLANNER-HARNESS-06`,
> §4.8) — there is no surface in `plan.toml` on which an operator could
> reference a custom Orchestrator image even if one were permitted.
>
> The kernel-bundled image is version-locked with the kernel binary: a
> kernel release ships with exactly one Orchestrator image whose digest
> the kernel knows. There is no registry dependency for Orchestrator
> activation; air-gapped deployments work without modification.

**The architectural reason.** The Orchestrator is **invisible
infrastructure** in the V2 architecture. From the operator's perspective,
there is no Orchestrator to configure — they declare Executors and
tasks, and the kernel transparently runs an Orchestrator session per
initiative to multiplex the parallel branches. This gives the operator
the *illusion of independent parallelizable agents* while preserving
the *simplicity of hierarchy* and the *rigor of the kernel state
machine*. The Orchestrator is the kernel's mechanism for fanning out
work; operator surface area for misconfiguration is exactly zero.

This invisible-infrastructure model collapses to fiction the moment the
operator can substitute their own Orchestrator image, because that
image's contents (binary versions, NNSP if shipped via the image,
prompt-injection vectors via shell rc files, etc.) become an operator
responsibility. The structural answer: the Orchestrator's image is part
of the kernel just like the Reviewer's image is.

**Image manifest (mirrors `raxis-reviewer-core` shape, with additional
binaries for semantic conflict resolution):**

- Linux 5.14+ guest kernel (per `INV-PLANNER-HARNESS-03`)
- cgroup v2 mounted with `cpu`, `memory`, `pids` controllers in
  `subtree_control`
- `raxis-planner` binary (Orchestrator build target — includes `bash`,
  `read_file`, `write_file`, `edit_file`, `glob_search`, `grep_search`,
  `TodoWrite`, plus the Orchestrator-only intent set; explicitly
  excludes `bash bg_*`, custom-tool dispatch, the Reviewer-only
  `SubmitReview`, and the Executor-only commit intents)
- `git` (≥ 2.30, for semantic conflict resolution; the Orchestrator
  uses `git merge`, `git diff`, `git log`, `edit_file` to fix conflict
  markers, then submits `IntegrationMerge`)
- `bash` (≥ 5.0)
- Standard POSIX coreutils (`cat`, `head`, `tail`, `diff`, `patch`,
  `awk`, `sed`, `grep`, `sort`)
- `ripgrep` (for `grep_search`)
- A minimal CA certificate bundle (no network is exposed to the
  Orchestrator, but `git`'s sanity checks expect one)

**Explicitly absent (verified by `raxis doctor canonical-images`):**

- Language runtimes (`python3`, `node`, `ruby`, `perl`, `lua`)
- Compilers (`rustc`, `gcc`, `clang`, `tsc`, `go`)
- Package managers (`npm`, `cargo`, `pip`, `gem`)
- LSPs / language servers
- Network utilities (`curl`, `wget`, `ssh`, `nc`)
- Editors (`vim`, `nano`, `emacs`)
- Build systems (`make`, `bazel`)

The image is exactly large enough to perform 3-way semantic git merges
with bash + git + edit_file, and nothing more.

**Composition with `INV-PLANNER-HARNESS-02`.** `INV-PLANNER-HARNESS-02`
established the canonical-image pattern for the Reviewer (the
*evaluative* gate). `INV-PLANNER-HARNESS-05` extends the same pattern
to the Orchestrator (the *coordination* role). The operator-published
`INV-VM-CAP-03` image-pinning model now applies exclusively to the
**Executor** role — the only role for which operator-controlled
toolchains are genuinely necessary (because Executors compile, test,
and produce code in the operator's specific language ecosystem).

---

### 4.8 `INV-PLANNER-HARNESS-06` — Orchestrator Is Not Operator-Configurable

> **Statement.** The Orchestrator role's complete behavior surface is
> kernel-owned and version-locked with the kernel binary. Specifically:
>
> 1. **No operator-declared Orchestrator profiles.** `plan.toml` MUST
>    NOT contain a profile whose effective role is `Orchestrator` and
>    MUST NOT contain a task whose `role` field is `"Orchestrator"`.
>    Plan admission rejects with `FAIL_ORCHESTRATOR_PROFILE_NOT_ALLOWED`
>    or `FAIL_ORCHESTRATOR_TASK_NOT_ALLOWED` respectively. The
>    Orchestrator session is auto-created by the kernel at initiative
>    admission.
> 2. **No `inherits_from = "Orchestrator"`.** Profile inheritance can
>    only target operator-extensible role roots, which in V2 is
>    exclusively `"Executor"`. Profiles attempting `inherits_from =
>    "Reviewer"` or `inherits_from = "Orchestrator"` are rejected at
>    admission with `FAIL_PROFILE_ROLE_NOT_CONFIGURABLE`.
> 3. **No operator-modifiable NNSP.** The Orchestrator's
>    Non-Negotiable System Prompt is compiled into the kernel binary
>    as a versioned constant (`ORCHESTRATOR_NNSP_BYTES`) and is
>    version-locked with the Orchestrator image per
>    `INV-PLANNER-HARNESS-05`. Operators cannot edit it; the spec text
>    in `kernel-mechanics-prompt.md §3.2` is illustrative, the kernel
>    binary is normative.
> 4. **No operator-declared custom tools.** The Orchestrator surface
>    has no `[[profiles.<name>.custom_tool]]` declaration path — there
>    is no operator-declared profile to attach them to. This is a
>    structural consequence of (1), not an additional check.
> 5. **No backgrounded `bash`.** The Orchestrator harness build
>    excludes `bash run --background` and the `bash bg_*` family of
>    operations; the Orchestrator's `bash` is foreground-only. Semantic
>    merge work is synchronous; long-lived processes have no role in
>    the Orchestrator's job.
>
> Operator policy MAY tune three orthogonal knobs in
> `policy.toml [orchestrator]`: `provider_alias` (which model
> family / alias chain), `max_token_budget_per_initiative` (a ceiling
> on the Orchestrator session's inference consumption), and
> `all_merges_require_approval` (force the Orchestrator to escalate
> every `IntegrationMerge` for human approval rather than admitting it
> directly when path-allowlist and protected-paths checks pass). These
> three knobs control *what the Orchestrator does*, not *how it
> reasons*. There are no other Orchestrator-tunable controls in V2.

**The "Invisible Infrastructure" framing.** The user-facing surface of
RAXIS is Executors and tasks. The kernel runs an Orchestrator
underneath to multiplex the DAG, resolve trivial syntactic conflicts
semantically (so a forest of import collisions does not become a flood
of operator escalations), and finalize merges. The operator does not
think about the Orchestrator the same way a Kubernetes operator does
not think about the Kubelet — it is part of the runtime, not part of
the workload definition.

This produces three concrete properties the prior operator-Orchestrator
model could not:

1. **Configuration surface area for the Orchestrator: zero.** Operators
   cannot misconfigure what they cannot configure. The class of bugs
   "the operator's Orchestrator profile contradicts the operator's
   policy" simply does not exist.
2. **Behavior consistency across deployments.** Every RAXIS deployment
   running kernel version `X` has byte-identical Orchestrator
   behavior. Bug reports are tractable; reproducible incidents are
   actually reproducible.
3. **Upgrade atomicity.** Kernel upgrades ship a new Orchestrator
   image AND a new Orchestrator NNSP atomically. Rollback restores
   both. The operator never experiences "kernel binary X with
   Orchestrator NNSP from version Y."

**The trade-off the operator accepts.** Operators relinquish the
ability to:

- Add operator-specific instructions to the Orchestrator's prompt
  (e.g., "in this deployment, prefer cautious merges").
- Substitute a custom Orchestrator image with bespoke tooling.
- Declare custom tools the Orchestrator can call.
- Run long-lived background processes from the Orchestrator session.

In exchange, they get an Orchestrator that just works. The
operator-tunable knobs in `policy.toml [orchestrator]` cover the
genuine cases where deployment-wide policy needs to bind the
Orchestrator's behavior; per-initiative quirks flow through the
existing initiative description field in `plan.toml`, surfaced into
the Orchestrator's KSB as plan-level guidance the universal NNSP
explicitly instructs the Orchestrator to consider.

**Composition with prior `INV-PLANNER-HARNESS-*`:**

- `INV-PLANNER-HARNESS-02` — kernel-canonical Reviewer image; the
  Reviewer is invisible at the runtime layer (image is kernel-owned)
  but its activation is still triggered by an operator-declared
  Reviewer task. The Reviewer is *role-invisible at the image layer*.
- `INV-PLANNER-HARNESS-05` — kernel-canonical Orchestrator image;
  same pattern.
- `INV-PLANNER-HARNESS-06` — Orchestrator is invisible at the
  configuration layer entirely: no operator-declared profile, no
  task, no inheritance, no NNSP override, no custom tools, no
  background processes. The Orchestrator is *role-invisible at the
  configuration layer*. This is the strongest invisibility statement
  among V2 roles.

---

## §5 — Backgrounded Shell Execution (Executor only)

### 5.1 Why Backgrounded Shells Are Necessary

The `bash` tool is borrowed from claw-code and wired through the
Executor harness build (Reviewer excluded per §4.2; Orchestrator gets
foreground `bash` only per §4.8 / `INV-PLANNER-HARNESS-06` — semantic
merge work is synchronous and the Orchestrator has no legitimate need
for long-lived processes).
The original sketch in the design discussion considered making `bash`
synchronous-only — every call blocks until the shell exits — to avoid
process-lifecycle complexity. That sketch breaks the dominant
in-development iteration loop **for Executors**, who are the only role
that backgrounded shells now apply to:

| Workflow | Sync-only behavior | What we need |
|---|---|---|
| `npm run dev` then `curl localhost:3000/api/foo` | First call blocks forever (dev server never exits) | Server runs in background; agent makes synchronous curl calls |
| `cargo watch -x check` to observe compile errors while editing | Same — blocking forever | Watcher runs in background; agent reads its log on demand |
| Run `postgres` locally for integration tests | Same | DB runs in background; tests run synchronously |

Pushing all of these through verifier VMs (the path that runs at commit
time, not in development) adds 30–60 seconds per iteration cycle.
Multiply by 30–50 iterations on a typical feature and the sync-only
restriction adds 15–50 minutes of per-feature latency for no
corresponding security gain — backgrounded processes are bound by the
VM, the VM has no NIC, the VM is reaped at session end.

The decision is to **support backgrounded shell execution**, but with
explicit harness primitives (not opaque `cmd &` shell tricks),
cgroup-based containment that survives POSIX daemonization, CPU-priority
guarantees that protect the harness control loop, and proactive crash
surfacing in the KSB.

### 5.2 Tool Surface

Five operations on the existing `bash` tool, four of them new:

```
bash run {
    command:           string,
    run_in_background: bool = false,
    name:              string?,            // friendly label, optional
    timeout_ms:        int?,               // foreground only; default 30s, max from plan
}
  -> Sync       { stdout, stderr, exit_code, runtime_ms }
   | Background { bg_id, name }

bash bg_status { bg_id: string? }
  -> { processes: [{ bg_id, name, state: Running | Exited(code) | Killed(signal),
                     runtime_ms, stdout_bytes_captured, stderr_bytes_captured,
                     started_at, ended_at? }] }
  // bg_id omitted = list all in this session

bash bg_logs { bg_id, stream: stdout | stderr | both, tail_bytes: int? }
  -> string
  // tail_bytes default 4096; max 65536

bash bg_kill { bg_id, signal: SIGTERM | SIGKILL = SIGTERM }
  -> { final_exit }
  // SIGTERM grace 5s before forced cgroup.kill

bash bg_acknowledge { bg_id }
  -> { acknowledged: true }
  // Removes the bg_id from the "Recently Exited" KSB section.
  // Crash callout for this bg_id is suppressed in subsequent KSBs.
  // No effect on Running processes (use bg_kill instead).
```

This is one extension to the existing `bash run` (the `run_in_background`
parameter and the new `Background { bg_id, name }` return variant) plus
four new bg-management operations. The harness's tool registry exposes
all five names to the LLM as a single coherent set; the system prompt
explains the backgrounding model and the KSB surfaces bg state on every
turn.

### 5.3 cgroup-Based Containment (`INV-PLANNER-HARNESS-03`)

The challenge with any backgrounded shell execution model is that POSIX
provides multiple mechanisms for a process to escape its parent's reach:

- `nohup cmd &` — backgrounds the process, ignores SIGHUP.
- `(cmd &)` or `setsid cmd` — creates a new session, escapes the
  controlling terminal and the process group of the parent shell.
- Double-fork daemonization (`fork(); fork(); setsid()`) — the canonical
  POSIX recipe for becoming PID-1-reparented background daemon.

**Walking `/proc` for descendants of the spawning shell PID is
fundamentally insufficient.** A double-forked daemon is reparented to PID 1
(the planner itself, in the microVM); its PPID is 1, not the shell's PID;
a `/proc` walker rooted at the shell PID will not find it. **PGID-based
containment (`kill(-pgid, SIGKILL)`) is also insufficient.** `setsid()`
creates a new session AND a new process group, escaping any PGID
inherited from the spawning shell.

**The only Unix primitive that genuinely contains a process tree against
arbitrary fork tricks is the cgroup.** Membership in a cgroup is set by
the kernel via `cgroup.procs`; a child of a cgrouped process is born into
the parent's cgroup; explicit migration out requires write access to the
target cgroup's `cgroup.procs` file, which the agent does not have.
cgroup v2's `cgroup.kill` operation (Linux ≥ 5.14) sends SIGKILL atomically
to every process in the cgroup, in-kernel, race-free against new forks
happening concurrently.

> **`INV-PLANNER-HARNESS-03` — In-VM Process Containment via cgroup v2.**
> Every shell command spawned by the `bash` tool — synchronous or
> backgrounded — MUST be placed in a dedicated cgroup v2 (subdirectory
> under `/sys/fs/cgroup/raxis/`) before `exec()`. The cgroup is created
> with the calling process (the planner-spawned shell child) as its sole
> initial member; all descendants inherit membership by kernel
> construction.
>
> Termination of any shell process tree MUST be performed via
> `cgroup.kill` (writing `"1"` to the cgroup's `cgroup.kill` file), not
> by signal-iteration over walked PIDs. Implementations MUST NOT rely on
> `/proc` walking, PGID-based signaling, or any mechanism that can be
> defeated by `fork()`, `setsid()`, `setpgid()`, or POSIX double-fork
> daemonization.
>
> Cgroups are arranged as:
>
> - `/sys/fs/cgroup/raxis/planner/` — the harness itself (`raxis-planner`
>   PID 1 places itself here at boot)
> - `/sys/fs/cgroup/raxis/bash-sync-<call_id>/` — per synchronous bash
>   call, transient (created at spawn, removed after `cgroup.kill` and
>   PID drain)
> - `/sys/fs/cgroup/raxis/bash-bg-<bg_id>/` — per backgrounded bash
>   process, persistent (created at spawn, removed at `bg_kill`,
>   session end, or session-end kernel-side teardown)
>
> Synchronous-bash teardown sequence:
> 1. Wait for the shell to exit (or hit foreground timeout).
> 2. Drain stdout/stderr buffers.
> 3. Send SIGTERM to all PIDs in `cgroup.procs` (well-behaved cleanup).
> 4. Wait up to 5 seconds for `cgroup.events` `populated=0`.
> 5. Write `"1"` to `cgroup.kill` (forced SIGKILL of any survivors).
> 6. Remove the cgroup once `cgroup.procs` is empty.
>
> Background-process teardown sequence (on `bash bg_kill { signal: SIGTERM }`):
> 1. Send SIGTERM to all PIDs in `cgroup.procs`.
> 2. Wait up to 5 seconds for `cgroup.events` `populated=0`.
> 3. Write `"1"` to `cgroup.kill` (forced SIGKILL of any survivors).
> 4. Remove the cgroup.
>
> Background-process teardown (on `bash bg_kill { signal: SIGKILL }`):
> 1. Write `"1"` to `cgroup.kill` immediately.
> 2. Remove the cgroup.
>
> Session-end teardown is universal: kernel SIGTERMs the planner (PID 1
> in VM) per `kernel-lifecycle.md` shutdown; the planner has 5s grace
> within which it iterates all `bash-bg-*` cgroups and writes `"1"` to
> each `cgroup.kill`. Whether or not the planner completes this within
> grace, the kernel's subsequent VM-stop reaps every PID at the
> hypervisor level.

This invariant, combined with `INV-VM-CAP-03` (image must mount cgroup
v2 with required controllers in `subtree_control`) and the kernel
version requirement (§10.2), guarantees that no in-VM process can survive
beyond its session.

### 5.4 cgroup-Based CPU Priority

VM-aggregate CPU caps from `host-capacity.md` bound the entire VM's
share of host CPU. They say nothing about how that share is distributed
inside the VM. A backgrounded compiler or test loop that pegs the VM's
allocated CPU at 100% can starve the planner itself: VSock keepalives
to the kernel get delayed, intent-dispatch latency rises, the next
bash call blocks waiting for the CPU-starved harness to schedule the
spawning code.

A starved harness cannot kill the runaway process. The starvation
becomes self-reinforcing.

**Mechanism: cgroup v2 `cpu.weight` priority.**

| Cgroup | `cpu.weight` | Notes |
|---|---|---|
| `/sys/fs/cgroup/raxis/planner/` (the harness) | **1000** (hardcoded; not operator-tunable) | The harness itself. Hardcoded high weight ensures harness scheduling priority is not subject to operator misconfiguration. |
| `/sys/fs/cgroup/raxis/bash-sync-*/` | 100 (default; not currently operator-tunable for sync calls) | Per synchronous bash call. Equal weight among synchronous calls (rarely contended — only one sync call active at a time per session). |
| `/sys/fs/cgroup/raxis/bash-bg-*/` | 100 (default; operator-tunable via `[plan.tasks.X.bash] bg_cpu_weight`) | Per backgrounded process. Operators can raise for compute-heavy bg work. |

Under contention, the Linux scheduler divides CPU time proportionally to
weight. Concrete consequences:

- Harness alone: 100% of CPU available, no contention.
- Harness + 1 bg process: harness gets 1000/(1000+100) ≈ **91%**.
- Harness + 4 bg processes (default `max_background_processes` cap):
  harness gets 1000/(1000+400) ≈ **71%**.
- Harness + 4 bg processes at maximum operator-tunable
  `bg_cpu_weight = 500` each: harness gets 1000/(1000+2000) ≈ **33%** —
  still adequate for VSock keepalives and intent dispatch but consumed
  entirely by the bg pool under sustained contention. Operators raising
  `bg_cpu_weight` above default should accept this trade-off.

When the harness is idle (waiting on inference, waiting on operator
intent), the scheduler gives 100% of CPU to bg processes — no idle
waste. Weights are *relative under contention only*.

**Why `cpu.weight` rather than `nice` or hard `cpu.max`:**

- `nice` is per-process and inherited by children, but the bash command
  can override its own niceness via `nice -n 0 cmd`. cgroup-based
  weight is uncircumventable from inside the cgroup.
- Hard `cpu.max` caps on bg cgroups would waste cycles when the harness
  is idle. Weights deliver priority under contention only.

### 5.5 Proactive Crash Surfacing in the KSB

The agent does not poll `bash bg_status` between every command — LLMs
are reactive, and an agent that backgrounded a dev server will assume
the server is running until something contradicts that assumption. A
silent crash (server died on startup with a syntax error) followed by
a `curl localhost:3000` produces "connection refused", and the LLM
typically wastes 3–5 turns debugging the curl call (firewall? wrong
port? wrong host? proxy?) before suspecting the server.

This is a known token-burn pathology. The harness solves it by surfacing
bg state changes in the KSB *proactively*, not on demand.

**Mechanism.** The harness maintains per-bg state records:

```
{
    bg_id:                  string,
    name:                   string?,
    state:                  Running | Exited(code) | Killed(signal),
    runtime_ms:             int,
    started_at:             int,        // unix ts
    ended_at:               int?,       // unix ts, set on state change away from Running
    stdout_bytes_captured:  int,
    stderr_bytes_captured:  int,
    last_512_stdout:        bytes,      // ring-buffered tail
    last_512_stderr:        bytes,      // ring-buffered tail
    state_changed_since_last_inference: bool,
    acknowledged:           bool,       // set true by bash bg_acknowledge
}
```

Between every inference call (i.e., between every LLM turn), the harness:

1. For each bg cgroup, reads `cgroup.events` (cgroup v2 surfaces
   `populated` transitions atomically).
2. For any newly-unpopulated cgroup, the harness `wait()`s on the
   original shell PID to collect the exit code, drains the last 512
   bytes of stderr from the per-bg log file, and updates the state
   record.
3. Sets `state_changed_since_last_inference = true` for any record
   whose state changed.

The KSB rendering for the bg block becomes (when at least one record
exists):

```
Background Processes:

  ⚠️ State Changes Since Last Turn:
  • bg_2 (dev_server): EXITED with code 1 at T+12.4s
    last 512 bytes of stderr:
    ┃ /workspace/src/server.js:23
    ┃   const config = JSON.parse(rawConfig);
    ┃                  ^
    ┃ SyntaxError: Unexpected token { in JSON at position 142
    ┃     at JSON.parse (<anonymous>)

  Currently Running:
  • bg_4 (tsc_watch): runtime 47s, 12 KiB stdout, 0 KiB stderr

  Recently Exited (still queryable via bash bg_logs; dismiss via bash bg_acknowledge):
  • bg_2 (dev_server): EXITED code 1 at T+12.4s [shown above]
  • bg_3 (postgres):   KILLED by SIGTERM at T+38.1s (operator triggered)
```

**The "⚠️ State Changes Since Last Turn" callout** appears at the **top
of the KSB** (above any other dynamic state — token budget, escalation
status, etc.) when at least one bg record has
`state_changed_since_last_inference = true`. After the inference, the
flags are cleared. The callout reappears on the next genuine state
change.

**The "Recently Exited" section** persists every exited-but-not-yet-
acknowledged bg record across turns. The agent dismisses entries by
calling `bash bg_acknowledge { bg_id }`, after which the entry no longer
appears in subsequent KSBs. This solves the "crash callout shown once
then disappears" problem: the historical record remains visible until
the agent has actively engaged with it, preventing repeated retry
attempts against a dead server.

**Aging.** Acknowledged exited records are dropped from the KSB but
remain queryable via `bash bg_status { bg_id }` for the rest of the
session. Unacknowledged exited records remain visible indefinitely until
session end. There is no automatic time-based aging — the agent's
responsibility to acknowledge handled crashes is explicit.

**Plan-level caps on KSB content** (rendered, not stored):

- Maximum 5 entries in "⚠️ State Changes Since Last Turn"
- Maximum 5 entries in "Recently Exited"
- Maximum 512 bytes of stderr tail per entry shown in callout
- If more than 5 state changes occurred between turns, the rendered
  callout shows the most recent 5 with a footer:
  `... and 3 more state changes; query bash bg_status for full list.`

### 5.6 Session-End Teardown

When the planner session ends — `CompleteTask`, crash, kill, deadline
exceeded — the kernel's existing VM-teardown sequence (`kernel-lifecycle.md`)
sends SIGTERM to PID 1 (the planner) with a 5-second grace period before
SIGKILL.

Within that 5s grace:

1. Planner iterates all `bash-bg-*` cgroups.
2. For each, sends SIGTERM to all PIDs in `cgroup.procs`.
3. Plus a brief wait (~500ms total budget across all bg cgroups), then
   writes `"1"` to each cgroup's `cgroup.kill`.
4. Emits `SessionTerminated { background_processes_killed: N, ... }`
   audit event with the count of bg processes that were running at
   teardown.

Whether or not the planner completes step 3 within grace, the kernel's
subsequent hypervisor-level VM stop reaps every PID. Background
processes cannot survive a session — the VM boundary is the universal
guarantee.

### 5.7 `plan.toml` Configuration

```toml
[plan.tasks.web_implementer.bash]
max_background_processes = 4         # default 4, hard kernel cap 16
default_timeout_ms       = 30_000    # foreground bash timeout default; 30s
max_timeout_ms           = 600_000   # max foreground timeout an agent can request; 10min
bg_cpu_weight            = 100       # cgroup cpu.weight for bg processes; 100 default,
                                     # max 1000 (matches harness weight = max equality, never priority)
```

| Field | Default | Hard kernel cap | Notes |
|---|---|---|---|
| `max_background_processes` | 4 | 16 | Per-session cap on concurrent bg processes. Exceeding the cap returns a synchronous error to `bash run --background`. |
| `default_timeout_ms` | 30,000 (30s) | — | Default for foreground `bash run` calls when the agent omits `timeout_ms`. |
| `max_timeout_ms` | 600,000 (10min) | 3,600,000 (1h, hard kernel cap) | Maximum the agent can request for a single foreground `bash run` call. |
| `bg_cpu_weight` | 100 | 1000 | cgroup `cpu.weight` for bg processes. Hard cap at 1000 equals the harness weight; the harness MUST always be ≥ bg priority. |

**Operator note — capacity composition.** These caps interact with
`host-capacity.md`'s VM-aggregate CPU and memory caps. A plan that
permits 16 background processes and raises `bg_cpu_weight` to 1000 each
will compete with the harness for CPU under contention; under aggregate
VM CPU pressure, the harness's responsiveness degrades. Operators
raising both caps simultaneously should explicitly accept this
trade-off; the kernel does not warn about plan configurations that
remain within hard caps.

### 5.8 Decision Summary

The complete backgrounded-shell decision summary, with the three Unix
realities that shaped it:

| Concern | Naive solution | Why it fails | Adopted solution |
|---|---|---|---|
| Containment against POSIX daemonization | `/proc` walk for descendants of shell PID; iterate kill(2) | Double-fork daemons reparent to PID 1; `/proc` walk misses them. PGID-based kill defeated by `setsid()`. Race conditions between walk and new forks. | cgroup v2 with `cgroup.kill` (atomic, in-kernel, fork-race-free) |
| Silent bg crashes burning agent tokens | Agent polls `bg_status` periodically | LLMs are reactive; they don't poll; the burn happens before the agent suspects the bg process | Proactive KSB injection between every turn, persisting "Recently Exited" until agent acknowledges |
| Bg processes starving the harness control loop | VM-aggregate cgroup caps from `host-capacity.md` | VM-aggregate caps say nothing about in-VM scheduling; runaway bg can pin the harness | cgroup `cpu.weight = 1000` for harness, `cpu.weight = 100` (default) for bg; harness always has priority under contention |

---

### 5.9 Per-Session Hard Turn Ceiling (V2.7, cross-ref)

The dispatch loop's hard turn ceiling — the **liveness** bound that
caps how many tool-call cycles a single planner session may run
before the kernel terminates it with `Outcome::TurnsExceeded` — is
resolved at session-spawn time per
`INV-PLANNER-MAX-TURNS-PRECEDENCE-01` and projected into the
in-VM env as `RAXIS_PLANNER_MAX_TURNS=N`. The same value also
appears on the KSB capabilities envelope as
`role=<role> session=<id> planner_max_turns=N` per
`INV-KSB-MAX-TURNS-VISIBILITY-01`, giving the in-VM agent
visibility into its own budget without an extra IPC round-trip.

The ceiling is **independent** from the token-cap envelope (the
`RAXIS_PLANNER_MAX_TOKENS_*` family) — token caps are the cost-side
bound, the turn ceiling is the liveness bound. A wedged tool-call
loop that emits one tiny tool call per turn would exhaust the turn
ceiling long before the token cap; a single very-long final
synthesis would exhaust the token cap long before the turn ceiling.
Both bounds fire independently.

Per-task (`[[tasks]] max_turns = N` in the plan TOML) and policy
(`[gateway].planner_max_turns_default = N` in `policy.toml`)
overrides exist for plans that mix Reviewer (~5 turns) and
materializer-Executor (~150 turns) tasks in one initiative. See
`v2-deep-spec.md §Step 12` for the full precedence chain and
`guides/recipes/env/11-planner-env-vars.md` for the operator
recipe.

---

## §6 — Tool Exclusions

Tool primitives from claw-code or candidate additions to the RAXIS
harness that have been ruled out, with rationale.

### 6.1 `StructuredOutput` — No DAG Consumer

**Context.** claw-code's `StructuredOutput` tool emits a JSON document
to the agent process's stdout, intended for downstream consumption by a
shell pipeline (`claw-code … | jq '.result'`) or by a human reading
terminal output. In claw-code's interactive CLI usage model this is
meaningful — the operator's terminal *is* the consumer.

**The problem in RAXIS.** A `raxis-planner` session has no stdout
consumer. The planner is PID 1 in a microVM; its stdout is captured by
the kernel into `transcript/<session_uuid>/stdout.log` (an audit-side
artifact for post-hoc forensic inspection), not piped to any process
that interprets it. The DAG's structured data flows are all
kernel-mediated and already have their own dedicated channels:

| What the agent wants to communicate | Where it goes in RAXIS | Why `StructuredOutput` is wrong |
|---|---|---|
| Structured result to the Orchestrator | `IntentKind::CompleteTask` payload — already kernel-validated, already audit-captured | Bypasses the kernel; the Orchestrator never reads stdout from peer VMs |
| Status / progress signal to the operator | Kernel audit events (`SubTaskCompleted`, `ReviewSubmitted`, `EscalationRequest`, …) — signed, schema-validated, surfaced via `raxis log` | Operator tooling reads the audit chain, not raw stdout |
| Intermediate scratch for the agent's own multi-turn reasoning | Conversation context (the LLM's own working memory, persisted in transcript) | A `StructuredOutput` call to "remember this for later" is just `TodoWrite` or a comment; no separate primitive needed |
| Critique / verdict from a Reviewer | `IntentKind::SubmitReview { approved, critique }` payload | Same as `CompleteTask`: kernel-mediated, schema-validated |

**Decision: exclude `StructuredOutput` from the planner harness for all
roles.** The harness's `PermissionPolicy` denies the tool for
Orchestrator, Executor, and Reviewer alike; the kernel dispatch matrix
has no corresponding `IntentKind` (and never had one); the claw-code
tool definition is not registered with the harness's tool registry at
build time.

**Counter-arguments rejected.** "Internal-reasoning scratchpad" — the
LLM's own conversation context already serves; no new primitive needed.
"Future verifier might consume structured stdout" — if so, the right
shape is a kernel-validated `IntentKind` with a defined consumer and
audit semantics, not a pre-installed raw-stdout channel. "Harmless,
just writes a log file" — harm is the agent believing it accomplished
communication that did not happen, training systematically misleading
behavior over multi-turn sessions.

### 6.2 Pending Verdicts

The following claw-code primitives have preliminary verdicts pending
final design discussion; they are listed here for traceability and will
be promoted to dedicated subsections when resolved:

- **`Sleep`** — preliminary verdict: exclude. A `Sleep(N)` call holds
  the VSock connection open and consumes a microVM slot for N seconds
  while doing zero work; under `INV-CONVERGENCE-03` it also burns
  wall-clock budget. If an agent needs to wait for an external
  asynchronous event, the right primitive is a kernel-mediated
  `Yield`/`PauseSession` intent (deferred to V3) that lets the kernel
  suspend the VM and free capacity. A dumb thread-sleep is operationally
  hostile.

  **What "external async event" means concretely.** The motivating case
  is: an Executor agent triggers a GitHub Actions workflow via the GitHub
  API, then needs to wait for that workflow's result before deciding what
  to do next. With `Sleep`, the agent calls `Sleep(600)` — holding a
  live microVM slot and a VSock connection open for 10 minutes while doing
  nothing. With `Yield`/`PauseSession` (V3), the agent instead emits a
  `YieldUntil` intent naming the expected event source; the kernel
  suspends and snapshots the VM (freeing the compute slot), and resumes
  the VM when the event arrives — injecting the payload into the next
  Kernel State Block so the agent continues with the CI result as context.
  The same pattern applies to any external async signal: a queue message,
  a rate-limit reset, a polling HTTP endpoint, a deployment health check.
  None of these are solvable by `Sleep` without burning capacity; all of
  them are solvable by a kernel that can suspend and resume on an event.

  **V3 open question — inbound event delivery.** How the kernel *receives*
  the external event is a design decision deferred to the V3 spec. Two
  options exist: (A) operator-mediated — the operator runs a webhook
  receiver that verifies the external auth (e.g. GitHub HMAC-SHA256) and
  forwards the payload to the kernel as an `ExternalEventNotification`
  message via the existing `OperatorTransport`; (B) a new
  `InboundEventBus` extensibility trait giving the kernel a dedicated HTTP
  listener or queue consumer. Option A is more consistent with RAXIS's
  principle of keeping the kernel surface minimal and routing all trust
  through operator authority. Option B is more ergonomic for production
  deployments. `OperatorTransport` is NOT an inbound event bus in its
  current V2 design — it is the operator-authenticated IPC channel for
  synchronous operator commands; routing async machine-initiated events
  through it without a V3 design decision would conflate two distinct
  trust models.
- **`branch_lock`** — preliminary verdict: exclude. claw-code's
  in-process git concurrency primitive assumes intra-process
  concurrency. RAXIS's planner LLM loop is strictly synchronous
  (one tool call, wait for stdout, next tool call), so there is zero
  concurrency inside a single VM's agent loop. Concurrency in RAXIS
  exists across different VMs (Orchestrator vs. Executor) operating on
  fully isolated worktrees. In-VM concurrency primitives are dead code
  for a synchronous LLM harness.

These will be promoted to formal decisions following the same
template as §6.1.

---

## §7 — Unified Egress (Pointer)

Egress is unified into a two-tier model with no per-request kernel
intent. The full design lives in `vm-network-isolation.md` (transport
layer) and `credential-proxy.md` (HTTP / protocol layer); the
historical `kernel-mediated-egress.md` design (with `IntentKind::EgressRequest`
and the `raxis-egress` proxy) is **deprecated** — see the *Decision —
Unified Egress* recorded in `v2-deep-spec.md §Part 7` for the rationale
and the deprecation history.

Brief recap:

- **Public / unauthenticated egress** (curl, npm, cargo, pip, git, …):
  transport-layer SNI allowlist via `raxis-tproxy`. Standard developer
  tools work unmodified.
- **Authenticated / sensitive egress** (APIs, k8s, cloud, DB protocols):
  HTTP / protocol-layer URL+method allowlist via per-session
  `localhost:<port>` Credential Proxy. The agent never sees the
  credential.
- **Dynamic exception requests** (URL not in either allowlist): operator
  amendment via `IntentKind::EscalationRequest` (per
  `agent-disagreement.md §6`). On approval, plan/policy widening
  through normal amendment flow. There is no per-request RPC primitive
  for "fetch this URL with kernel approval."

The Reviewer has no egress allowlist of any kind: no tproxy interface
provisioned, no Credential Proxy interfaces. There is nothing for the
Reviewer to reach, and the Reviewer image (§4.5) ships no network
utilities anyway.

---

## §8 — Verifier Process Architecture (Overview)

This section is an overview. The full specification lives in
`specs/v2/verifier-processes.md`; the key architectural properties,
and the way they compose with the Pure-Static Reviewer (§4.2) and the
Canonical Reviewer Image (§4.5), are recorded here so the
planner-harness model is complete.

**V2 unified runtime.** As of V2, the verifier subsystem has a
single runtime model (per `verifier-processes.md §7` — no V1/V2 split,
no legacy `policy.toml` claim-based gates parallel path). One
`raxis-verifier` PID-1 binary, one `WitnessSubmission` IPC frame, one
`witness_records` SQLite schema, one set of audit events. Three
authoring sources fan into the unified runtime, each fired at the
right lifecycle hook (per `verifier-processes.md §15`):

| Authoring source | Lifecycle hook | Default `on_failure` | Authority |
|---|---|---|---|
| `policy.toml [[gates]]` (claim-based) | `CompleteTask` admission | `block_review` (implicit) | Operator-signed |
| `[[plan.tasks.<id>.verifiers]]` | `CompleteTask` admission | `block_review` (operator's plan choice) | Plan-author-signed |
| `[[plan.integration_merge_verifiers]]` and `policy.toml [[integration_merge_verifiers]]` | `IntegrationMerge` admission (Check 5d per `integration-merge.md §4`) | `block_merge` (operator-side: required; plan-side: defaults to `block_merge` but `warn_only` permitted) | Plan-author-signed (plan side) or operator-signed (policy side) |

The pre-`IntegrationMerge` hook is new in V2 and is the operator's
mechanism for "regression gating": tests that should pass at the
final integration boundary, not just inside individual tasks. See
`integration-merge.md §4 Check 5d` for the kernel-side admission flow
and `verifier-processes.md §15` for the schema and `applies_to`
semantics (`"all"` | `"task_set"` | `"last"`).

### 8.1 Why Verifier Processes Exist

Removing in-Reviewer shell execution and code-running tools (§4.2)
created the question: where do tests, type checks, linters, and
build-attempt verification actually run, given that the Reviewer can no
longer run them itself?

The answer is **separate Kernel-spawned verifier VMs**. These are
single-purpose, plan-declared, kernel-managed VMs that run a specific
command (`cargo test`, `npm run lint`, `tsc --noEmit`, etc.) against a
fresh clone of the Executor's `evaluation_sha`, capture binary
pass/fail and structured output, and write `witness_records` that the
Kernel surfaces to the dependent Reviewer's KSB.

Verifier VMs are different from agent VMs in three structural ways:

1. **No LLM, no harness.** A verifier VM runs `raxis-verifier` (a
   small wrapper PID 1) that executes a single declared command and
   exits. No turn loop, no inference, no tool dispatch.
2. **Output is structured + binary, not semantic.** Verifier output
   is `{ exit_code, stdout_tail, stderr_tail, structured_counters }`.
   It is a coarse signal a malicious build script can flip (test
   pass/fail), but it cannot poison a "find references to this
   function" query that the Reviewer might consult. The threat surface
   is structurally narrower than retaining LSPs in the Reviewer would
   be (per §4.1's verifier-process-implications discussion).
3. **No commits enter the audit chain via the verifier.** Verifier
   VMs may write to `/workspace` (build artifacts, `.cargo/`,
   `node_modules/`, etc.) but those mutations are dropped at VM exit.
   `SingleCommit` is not invoked. Verifier outputs enter the chain via
   `witness_records`, not via `IntegrationMerge`.

### 8.2 Plan Declaration

```toml
[[plan.tasks.web_implementer.verifiers]]
name        = "node_test"
image       = "raxis/node:20"
command     = "npm test --silent"
timeout     = "10m"
on_failure  = "block_review"      # or "warn_only"
artifact    = "/raxis/test_report.json"   # optional; staged into dependent Reviewer's /raxis/
```

Multiple verifiers can be declared per task; they run in parallel
where the kernel has capacity (subject to `host-capacity.md` caps),
and the Reviewer is activated only after all of them have written
their witnesses.

`on_failure` rules:

- `block_review`: failed verifier prevents Reviewer activation; the
  Executor's `CompleteTask` is rolled into a Failed task with the
  verifier output surfaced as the failure reason (similar to
  `FAIL_REVIEW_LOOP_EXCEEDED` handling in `agent-disagreement.md §3`).
- `warn_only`: failed verifier does not block Reviewer activation;
  the Reviewer's KSB carries the witness summary including the
  failure as a flagged item.

### 8.3 The `artifact` Extension

Verifier declarations can optionally include an `artifact` field
naming a path inside the verifier VM whose contents are copied into
dependent tasks' `/raxis/` mount post-success. This is the mechanism
by which a parser-only symbol indexer (e.g., `ctags`) produces a
`symbol_index.json` that the Reviewer reads via `read_file` (per the
LSP-decision operator note in §4.1).

The kernel:

1. Spawns the verifier VM with `/workspace` mounted from a fresh
   clone of `evaluation_sha` and `/raxis/` mounted RW (verifier-only;
   Reviewer's mount is RO).
2. Runs the command. On exit-code-zero, validates the declared
   `artifact` path exists and is non-empty.
3. Copies the artifact bytes from the verifier VM's `/raxis/` to the
   kernel-owned per-session staging directory.
4. When the dependent Reviewer activates, mounts `/raxis/` (RO)
   including the staged artifact.
5. If artifact doesn't exist post-success → records
   `MISSING_DECLARED_ARTIFACT` in the witness; treats as verifier
   failure per `on_failure`.

Multiple verifiers can declare different artifacts; each is staged
independently. The artifact mechanism is general — symbol-index is
the first concrete consumer, but pre-rendered API documentation,
JSON-formatted lint reports, dependency graphs, coverage maps, and
similar Reviewer-consumed artifacts all use the same machinery.

### 8.4 KSB Surfacing

The Reviewer's KSB carries a `verifier_witnesses` first-class section
listing each verifier's name, pass/fail status, exit code, structured
counters (when present), and a short stdout/stderr tail. The Reviewer
LLM reads this directly from the KSB; there is no `read_witness` tool
because the Reviewer does not choose which witnesses to inspect —
every witness for the Executor's `evaluation_sha` is in the KSB by
construction.

The Reviewer's KSB carries witnesses from BOTH the policy claim-based
gates AND the per-task verifier declarations (the two `CompleteTask`
sources from §8's table); pre-`IntegrationMerge` verifier witnesses
do NOT appear in the Reviewer's KSB because they fire at a strictly
later lifecycle hook (Reviewer activation has already happened by the
time `IntegrationMerge` is admitted). Pre-merge witnesses surface in
the operator's audit log (`VerifierActivated` and `VerifierCompleted`
events with `hook_kind = "pre_merge"`) and in the operator-facing
`FAIL_INTEGRATION_MERGE_VERIFIER_BLOCKED` failure payload that the
Orchestrator routes to operator escalation per
`verifier-processes.md §16.6`.

The full schema and the verifier VM lifecycle, audit events, and
`raxis-verifier` PID-1 binary specification live in
`verifier-processes.md`.

---

## §9 — KSB Alert Classes

The KSB (Kernel State Block, prepended to every inference request per
`token-limit-enforcement.md`) carries dynamic state from the kernel
into the agent's prompt. Some of that state is **alerts** — events
that occurred between the previous turn and this one and that should
override the agent's planned next action. As the design has accreted,
several distinct alert types have emerged with overlapping rendering
needs; this section standardizes them as a single taxonomy.

### 9.1 Alert Classes (V2)

| Alert class | Source | Trigger | Canonical home |
|---|---|---|---|
| `TokenLimitApproaching` | Token budget enforcement | Per-task or per-session token usage crosses warning thresholds (e.g., 80% / 95% of limit) | `token-limit-enforcement.md` |
| `EscalationRequestStatus` | Escalation lifecycle | `EscalationResolved` / `EscalationRejected` / `EscalationTimedOut` / `SubEscalationResolutionRequired` events become available since last turn | `kernel-push-protocol.md`, `agent-disagreement.md` |
| `BackgroundProcessExited` | bg lifecycle (this spec) | A backgrounded shell process changes state from `Running` to `Exited` or `Killed` between turns | this spec, §5.5 |

The deprecated `EgressApprovalRequired` class is retired with the
unified-egress decision (§7); its functionality is subsumed under
`EscalationRequestStatus` for dynamic egress widening requests.

### 9.2 Rendering Rules

All alert classes share the same rendering envelope so the LLM can
recognize them as a category:

```
[ALERT: <ClassName>]
<one-line summary>
<optional structured detail block>
```

For example:

```
[ALERT: BackgroundProcessExited]
bg_2 (dev_server) EXITED with code 1 at T+12.4s
last 512 bytes of stderr:
┃ /workspace/src/server.js:23
┃ SyntaxError: Unexpected token { in JSON at position 142

[ALERT: TokenLimitApproaching]
Current usage 82,400 / 100,000 tokens (82.4%) on this task. 17,600 tokens remaining
before FAIL_TOKEN_LIMIT_EXCEEDED. Per-request limit unaffected; this is the cumulative
task limit.

[ALERT: EscalationRequestStatus]
EscalationRequest esc_4f3a (PathAllowlistAmendment) RESOLVED by operator at T+143s.
Resolution: amendment approved with restrictions. Re-issue your CompleteTask intent
to retry path-allowlist enforcement under the amended policy.
```

The agent's training is straightforward: blocks formatted as
`[ALERT: <CLASS_NAME>]` represent asynchronous FSM events from the
Kernel that override the current line of reasoning and should be
attended to before continuing planned work.

### 9.3 Placement

Alerts render at the **top** of the KSB, above the standard dynamic
state (token budget, escalation queue, witness summary, etc.) and
above any per-role context block. This ordering is deliberate: the
alerts are the most urgent, time-sensitive content the LLM should
attend to.

When multiple alert classes have content for a single turn, they
render in a fixed order:

1. `BackgroundProcessExited` (most operationally urgent — agent likely
   to retry against a dead process otherwise)
2. `EscalationRequestStatus` (state transition affects
   what the agent should do next)
3. `TokenLimitApproaching` (informational; agent should plan for
   limit pressure but is not blocked)

### 9.4 Aging and Acknowledgement

Different alert classes have different aging semantics:

| Class | Lifetime in KSB | Acknowledgement mechanism |
|---|---|---|
| `BackgroundProcessExited` | Until acknowledged or session ends | `bash bg_acknowledge { bg_id }` (per §5.5) |
| `EscalationRequestStatus` | Single turn (not re-rendered) | Implicit on first delivery; subsequent KSBs do not repeat |
| `TokenLimitApproaching` | Re-rendered every turn while threshold is crossed | None; resolved by reducing usage or operator amending limit |

**Why `BackgroundProcessExited` requires explicit acknowledgement:**
the agent might not act on a crash in the same turn it sees the
alert. Without persistent rendering, the next turn's KSB would omit
the alert and the agent would forget the crash, retrying its original
plan against a dead process. Explicit acknowledgement makes the
agent's awareness of the crash a positive action in the audit trail.

**Why `EscalationRequestStatus` does not require acknowledgement:**
the underlying `KernelPush` delivery already has at-least-once
semantics with idempotent application (per `kernel-push-protocol.md`);
the KSB rendering is just a one-time "this happened since last turn"
notification. Subsequent decisions about how to handle the resolution
are tracked through the FSM, not through KSB persistence.

### 9.5 Plan-Level Caps

```toml
[plan.tasks.X.ksb_alerts]
max_bg_state_changes_per_turn   = 5      # default 5
max_bg_recently_exited          = 5      # default 5
max_bg_stderr_tail_bytes        = 512    # default 512; max 4096
max_escalation_status_per_turn  = 3      # default 3
```

Caps protect the KSB from being overwhelmed by alerts when many
events occur between turns. Counts that exceed caps are summarized
with a `... and N more` footer pointing the agent at the appropriate
status query (`bash bg_status`, the kernel push history, etc.) for
full detail.

---

## §10 — Image Requirements

### 10.1 cgroup v2 Setup (All Roles)

Every planner VM image — Orchestrator, Executor, Reviewer — MUST
satisfy the following for `INV-PLANNER-HARNESS-03` to function:

- cgroup v2 mounted at `/sys/fs/cgroup/`
- `cpu`, `memory`, `pids` controllers enabled in
  `/sys/fs/cgroup/cgroup.subtree_control` (writable by PID 1 at boot)
- `/sys/fs/cgroup/raxis/` writable by `raxis-planner` (PID 1 in the
  VM has `CAP_SYS_ADMIN` by default; this is sufficient)

`raxis-planner` performs cgroup setup at boot:

1. Verifies cgroup v2 is mounted; aborts with `FAIL_CGROUP_V2_NOT_MOUNTED`
   if not.
2. Creates `/sys/fs/cgroup/raxis/planner/`, writes its own PID to
   `cgroup.procs`, sets `cpu.weight = 1000`.
3. Writes `+cpu +memory +pids` to `/sys/fs/cgroup/raxis/cgroup.subtree_control`
   to enable controllers in the raxis subtree.

Any verification failure at this stage is fatal and bubbles up to the
kernel as a session-activation error before any inference happens.

### 10.2 Linux Kernel Version (5.14+)

`INV-PLANNER-HARNESS-03` mandates use of `cgroup.kill`, which requires
Linux ≥ 5.14 (released August 2021). RAXIS V2 requires Linux 5.14+ as
the **VM guest kernel** for any planner image.

This is a stricter requirement than `system-requirements.md`'s baseline
of Linux 5.10+ for the host kernel. The host can run any 5.10+ kernel;
the VM guest kernel must be 5.14+.

`raxis doctor` MUST verify the VM guest kernel version of every
operator-published image at image-build time or at first-use, and
warn / fail per operator preference if the kernel is below 5.14. In
V2, "operator-published images" means Executor images and verifier
images only — the Orchestrator image (§4.7) and Reviewer image (§4.5)
are kernel-canonical and ship with a RAXIS-pinned kernel version that
is always ≥ 5.14 by construction.

Earlier alternatives considered:

- *Fall back to `cgroup.procs` iteration with manual signal-iteration
  on kernels 5.0–5.13.* Rejected. Suffers from race conditions when new
  forks happen during the iteration loop. The race window is small but
  exists, and we deliberately chose `cgroup.kill` precisely to
  eliminate that class. Maintaining a fallback path doubles the
  containment-tear-down code paths and keeps the race-prone version
  reachable. Better to require a kernel version that gives us the
  atomic primitive.
- *Synthesize atomic teardown by SIGSTOP-ing the cgroup before
  iterating.* Requires `freezer` cgroup controller, which adds yet
  another dependency, and SIGSTOP'd processes can still hold kernel
  resources. Marginal improvement over plain iteration; not worth the
  code path.

### 10.3 Per-Role Image Specifications

| Role | Image source | Tooling | Operator declares in `plan.toml`? |
|---|---|---|---|
| **Orchestrator** | **Kernel-bundled, kernel-digest-verified `raxis-orchestrator-core`** | `raxis-planner` (Orchestrator build target), `bash` (foreground only), `git`, standard POSIX coreutils, `ripgrep`. **No language runtimes, no compilers, no package managers, no curl/wget, no editors** | ❌ **Not declared.** Operator-supplied `vm_image` for Orchestrator tasks is rejected with `FAIL_ORCHESTRATOR_VM_IMAGE_NOT_ALLOWED` (and `[plan.tasks.<id>] role = "Orchestrator"` is rejected entirely with `FAIL_ORCHESTRATOR_TASK_NOT_ALLOWED` per `INV-PLANNER-HARNESS-06`, §4.8). |
| **Executor** | Operator-published, policy-pinned by OCI digest (`INV-VM-CAP-03`) | Full language toolchain (cargo, npm, python, go, …), full LSP, `bash` (foreground + backgrounded per §5), `git`, all standard developer utilities | ✅ `vm_image = "raxis/rust-node:1.87-20"` (or operator-named) |
| **Reviewer** | **Kernel-bundled, kernel-digest-verified `raxis-reviewer-core`** | `raxis-planner`, `ripgrep`, libc/loader. **No shell, no LSP, no compilers, no `git`, no curl, no editors** | ❌ **Not declared.** Operator-supplied `vm_image` for Reviewer tasks is rejected with `FAIL_REVIEWER_VM_IMAGE_NOT_ALLOWED` at `approve_plan`. |

**The asymmetry, restated.** Of the three V2 planner roles, only the
**Executor** has an operator-published image. The Reviewer
(`INV-PLANNER-HARNESS-02`) and Orchestrator (`INV-PLANNER-HARNESS-05`)
both run kernel-canonical, kernel-digest-verified images. The operator's
configuration surface for the agent runtime collapses to exactly one
image declaration per Executor profile.

### 10.4 Canonical Reviewer Image Manifest

Distribution path:
`$RAXIS_INSTALL_DIR/images/raxis-reviewer-core-<kernel_version>.img`

The image is a minimal OCI bundle containing:

```
/                   (rootfs)
├── /sbin/init      → /raxis-planner   (symlink, raxis-planner is PID 1)
├── /raxis-planner  (statically-linked binary, with bash module
│                    excluded at link time, grep_search using direct
│                    execvp)
├── /usr/bin/rg     (statically-linked ripgrep)
├── /lib/           (only if raxis-planner / ripgrep are dynamically
│                    linked; recommended to ship both fully static)
└── /sys/fs/cgroup/ (mountpoint, populated by raxis-planner at boot)
```

Notably absent:

- `/bin/sh`, `/bin/bash`, `/usr/bin/busybox`
- `/usr/bin/git`, `/usr/bin/curl`, `/usr/bin/wget`, `/usr/bin/ssh`
- `/usr/bin/vi`, `/usr/bin/nano`, `/usr/bin/less`
- Any compiler, interpreter, or language runtime
- Any LSP server

The image's SHA-256 digest is published in the RAXIS release notes for
operator verification. The kernel's compiled-in
`EXPECTED_REVIEWER_IMAGE_DIGEST` matches this digest.

`raxis doctor` runs a content-inspection check on the on-disk Reviewer
image (verifies presence of `/raxis-planner`, `/usr/bin/rg`, absence of
shells and compilers, correct cgroup v2 mountpoint) in addition to the
digest check. This catches the case where the image file has been
replaced wholesale by a same-size attacker bundle with a coincidentally
matching… (no, that's a SHA-256 collision, not realistic) — actually
catches the case where the digest somehow mismatches a manifest the
operator was expecting, providing diagnostic output for what's wrong
with the image, not just a digest mismatch error.

### 10.5 Canonical Orchestrator Image Manifest

Distribution path:
`$RAXIS_INSTALL_DIR/images/raxis-orchestrator-core-<kernel_version>.img`

The image is a minimal OCI bundle containing:

```
/                   (rootfs)
├── /sbin/init      → /raxis-planner   (symlink, raxis-planner is PID 1)
├── /raxis-planner  (statically-linked binary, Orchestrator build
│                    target — bash module included foreground-only
│                    (bg_* paths excluded at link time), custom-tool
│                    dispatch excluded, SubmitReview / SingleCommit
│                    excluded)
├── /bin/bash       (≥ 5.0)
├── /bin/sh         → /bin/bash
├── /usr/bin/git    (≥ 2.30)
├── /usr/bin/rg     (statically-linked ripgrep)
├── /usr/bin/{cat,head,tail,diff,patch,awk,sed,grep,sort,wc,find,xargs,test,echo,printf,tr,cut,uniq}
├── /usr/lib/git-core/  (git's helper binaries)
├── /etc/ssl/certs/ca-certificates.crt   (minimal CA bundle for git's
│                    sanity checks; no network is exposed regardless)
├── /lib/           (loader + libc)
└── /sys/fs/cgroup/ (mountpoint, populated by raxis-planner at boot)
```

Notably absent:

- `/usr/bin/python3`, `/usr/bin/node`, `/usr/bin/ruby`, `/usr/bin/perl`,
  `/usr/bin/lua`
- `/usr/bin/rustc`, `/usr/bin/gcc`, `/usr/bin/clang`, `/usr/bin/tsc`,
  `/usr/bin/go`
- `/usr/bin/npm`, `/usr/bin/cargo`, `/usr/bin/pip`, `/usr/bin/gem`
- `/usr/bin/curl`, `/usr/bin/wget`, `/usr/bin/ssh`, `/usr/bin/nc`
- `/usr/bin/vi`, `/usr/bin/nano`, `/usr/bin/emacs`, `/usr/bin/less`
- Any LSP server
- Any build system (`make`, `bazel`, `meson`, `ninja`)

**The image is exactly large enough to perform 3-way semantic git
merges with bash + git + edit_file, and nothing more.**

The image's SHA-256 digest is published in the RAXIS release notes for
operator verification. The kernel's compiled-in
`EXPECTED_ORCHESTRATOR_IMAGE_DIGEST` matches this digest, and the
compiled-in `ORCHESTRATOR_NNSP_BYTES` carries the version-locked NNSP
that the Orchestrator harness will be initialized with on every
session activation (per `INV-PLANNER-HARNESS-06.3`).

`raxis doctor canonical-images` runs the same content-inspection check
against the Orchestrator image as it does against the Reviewer image:
verifies presence of `raxis-planner`, `bash`, `git`, `ripgrep`, and the
expected coreutils; verifies absence of every disallowed binary listed
above; verifies cgroup v2 mountpoint and Linux ≥ 5.14 guest kernel.

### 10.6 Canonical Executor Starter Image Manifest

> **This image is opt-in, not structural.** Unlike the Reviewer
> (`INV-PLANNER-HARNESS-02`) and Orchestrator (`INV-PLANNER-HARNESS-05`)
> canonical images — which are mandatory and operator-inaccessible —
> the Executor starter image is a **defaulting target** consumed by the
> operator-ergonomics layer (`operator-ergonomics.md §3` D1, §4.2). An
> operator's task that omits `vm_image` gets this image filled in by
> `raxis-cli plan prepare`. Operators in production typically pin their
> own digest-pinned Executor image and never use the starter; the
> defaulting machinery silently leaves their explicit value alone.
> No new invariant is introduced: the starter image does not
> structurally constrain the Executor role (which remains
> operator-configurable per the role-asymmetry table in §3); it is just
> one of many possible images the operator can elect via the policy's
> `[default_executor_image]` alias.

Distribution path:
`$RAXIS_INSTALL_DIR/images/raxis-executor-starter-<kernel_version>.img`

The image is a general-purpose Executor rootfs containing the four
mainstream language ecosystems plus the Unix tooling Executor agents
typically reach for. It is intentionally larger than the Reviewer and
Orchestrator images (~2 GiB compressed) because its job is to support
the breadth of work an Executor can do, not the narrow surface of
static review or merge:

```
/                   (rootfs)
├── /sbin/init      → /raxis-planner   (symlink, raxis-planner is PID 1)
├── /raxis-planner  (statically-linked binary, Executor build target —
│                    full tool surface enabled per §3 role table:
│                    foreground bash, backgrounded bash with cgroup.kill,
│                    custom-tool dispatch, edit_file, file_ops, etc.)
├── /bin/bash       (≥ 5.0)
├── /bin/sh         → /bin/bash
├── /usr/bin/{node, npm, npx, yarn, pnpm}    (Node 20 LTS)
├── /usr/bin/{python3, pip, pip3}            (Python 3.11)
├── /usr/bin/{cargo, rustc}                  (Rust stable)
├── /usr/bin/{go, gofmt}                     (Go 1.22)
├── /usr/bin/{git, gh}                       (git ≥ 2.30, GitHub CLI)
├── /usr/bin/{rg, fd, jq, yq}                (modern Unix tooling)
├── /usr/bin/{curl, wget}                    (HTTP clients; gated by tproxy)
├── /usr/bin/{make, gcc, g++, clang, ld, ar} (build toolchain)
├── /usr/bin/{cat,head,tail,diff,patch,awk,sed,grep,sort,wc,find,xargs,test,echo,printf,tr,cut,uniq,less,cmp,tee}
├── /usr/lib/git-core/                       (git's helper binaries)
├── /etc/ssl/certs/ca-certificates.crt
├── /lib/                                    (loader + libc)
└── /sys/fs/cgroup/                          (mountpoint, populated by raxis-planner at boot)
```

Notably absent (deliberately):

- Long-running daemons / background services (`systemd`, `dbus`, `cron`).
- LSP servers — agents inspect code via grep/ripgrep/git, not LSP.
- Editors (`vi`, `nano`, `emacs`) — agents use `edit_file` via the planner
  harness, not interactive editors.
- Cloud-provider CLIs (`aws`, `gcloud`, `kubectl`) — these are
  operator-specific; operators who need them pin their own image with
  the appropriate CLI baked in.

**Egress posture.** The starter image ships with **no preconfigured
egress allowlist**. A task whose `vm_image` was defaulted to the starter
image AND omits `allowed_egress` is admitted with `allowed_egress = []`
(empty allowlist; no network access). Operators who want network access
declare egress hosts explicitly in their plan; `plan prepare` does NOT
auto-default egress hosts even if the starter image is selected
(`operator-ergonomics.md §4.2`). This keeps the dangerous axes (network,
custom tools) opt-in even when the image-pin axis is defaulted.

**Image digest.** The image's SHA-256 digest is published in the RAXIS
release notes. The policy bundle that selects this image as
`[default_executor_image] alias` MUST also declare the corresponding
`[[vm_images]]` entry with `oci_digest = "sha256:..."` matching the
release-notes digest. The kernel verifies the digest at every Executor
session activation that uses this image (per the existing
`vm_images.oci_digest` enforcement; no new invariant is needed).

**Updates.** New starter image versions ship with new RAXIS releases.
The policy bundle's `[[vm_images]]` digest pin determines which version
operators are using; upgrading the starter image is an operator-driven
policy bundle update, not a silent kernel-side action. This preserves
the operator-signs-everything authority chain — even though the image's
bytes are kernel-built, the operator's policy signature attests to the
specific digest.

`raxis doctor canonical-images` extends the existing Reviewer +
Orchestrator check to also verify the starter image when
`[default_executor_image]` is configured: digest match against the
release manifest; presence of the language toolchains and Unix tooling
listed above. A digest mismatch surfaces as
`FAIL_DEFAULT_EXECUTOR_IMAGE_DIGEST_MISMATCH` (a non-fatal warning if no
admitted plan currently uses this image; a hard error if any in-flight
session was activated under the now-mismatched image).

**Pre-installed Python DB clients (canonical-only).** The starter
image bakes in the small set of Python DB clients that the
canonical credential proxies (`DATABASE_URL` / `MONGO_URL` /
`REDIS_URL` / `SMTP_URL`) target, so the LLM never needs to
`pip install` (which would fail the egress gate): `psycopg2-binary`
(Postgres), `pymongo` (MongoDB), `redis` (Redis), `PyMySQL`
(MySQL/MariaDB), `pymssql` (SQL Server), plus stdlib `smtplib`
for SMTP. Operators pinning a BYO image are NOT bound to this
list — the in-VM discovery surface (next paragraph) is what
the LLM consults.

**LLM discovery of pre-installed surface (`INV-EXEC-DISCOVERY-01`).**
Because the LLM cannot trial-and-error `pip install` /
`npm install` (no egress; `INV-VM-EGRESS-01`), every Executor /
Reviewer / Orchestrator session receives a **capability
manifest** at session start describing the binaries, language
runtimes, pre-installed packages, credential-proxy env vars,
and workdir state of its specific VM. The manifest is surfaced
through TWO coherent channels backed by the SAME in-guest probe
(`crates/planner-core/src/vm_capabilities.rs`):

1. A `## VM Environment` block prepended to the role NNSP
   before the KSB delimiter block, so the LLM's first turn
   knows what is pre-installed.
2. The `vm_capabilities` LLM tool (registered in every role
   registry) for finer queries (e.g. "is `numpy` available?").

Both surfaces read from a per-process
`OnceLock<Arc<CapabilityManifest>>`, so for a given `(image
digest, session env)` pair the manifest is byte-deterministic
(prompt-cacheable). Kernel-private env vars
(`RAXIS_VSOCK_LOOPBACK_PLAN`, `RAXIS_SESSION_TOKEN`, sidecar
HMAC secrets, anything matching `*SECRET*` / `*PASSWORD*` /
`*API_KEY*` / `*_TOKEN`) are redacted; credential-proxy URLs
(`DATABASE_URL` / `MONGO_URL` / `REDIS_URL` / `SMTP_URL`)
surface intentionally so the LLM can write scripts that use
the proxies. The discovery surface is **image-agnostic** —
identical mechanism for the canonical starter image and for
operator-pinned BYO images per `INV-OPERATOR-CUSTOM-IMAGE-01`.
Full schema and redaction rules: `canonical-images.md §6`.

### 10.7 Canonical Verifier Symbol-Index Image Manifest

> **This image IS structural**, in contrast to the Executor starter
> image (§10.6). The Pure-Static Reviewer (§4.2) is structurally
> dependent on a symbol-index witness for full symbol-resolution
> fidelity (per the `WARN_REVIEWER_MISSING_SYMBOL_INDEX` mechanism in
> §4.1 and the operator note added there). The kernel-canonical
> `raxis-verifier-symbol-index` image is the structural answer:
> trusted, kernel-built, kernel-bound digest-checked, auto-injected
> by `raxis-cli plan prepare` (per
> `operator-ergonomics.md §4.2` and `policy-plan-authority.md §4
> [prepare]`). This is enforced by **`INV-VERIFIER-12`** in
> `verifier-processes.md` (Pure-Static Reviewer's symbol-index witness
> source MUST be a kernel-canonical image when auto-injected;
> operator-published images MAY produce alternate symbol indexes only
> when auto-injection is disabled or per-task suppressed).

Distribution path:
`$RAXIS_INSTALL_DIR/images/raxis-verifier-symbol-index-<kernel_version>.img`

The image is intentionally tiny (~12 MiB compressed) — the symbol-index
verifier needs only a structural symbol extractor (`ctags`) and the
unified `raxis-verifier` PID-1 binary. It carries no language
toolchains, no shells beyond a minimal `/bin/sh` for `command`
execution, and no network utilities:

```
/                   (rootfs — Alpine Linux base)
├── /sbin/init      → /raxis-verifier   (symlink, raxis-verifier is PID 1)
├── /raxis-verifier (statically-linked binary, the unified verifier
│                    PID-1 per verifier-processes.md §4.1 — no LLM,
│                    no harness, no IntentKind dispatch)
├── /usr/local/bin/raxis-symbol-index   (tiny wrapper script: walks
│                                        /workspace, invokes ctags with
│                                        the canonical flag set, emits
│                                        normalized JSON to
│                                        /raxis/symbol_index.json)
├── /usr/bin/ctags  (universal-ctags 6.0+; the structural symbol
│                    extractor, parser-only, never executes the
│                    indexed code)
├── /bin/sh         (busybox, minimal POSIX; for `sh -lc <command>`
│                    execution per verifier-processes.md §4.2)
├── /etc/ssl/certs/ca-certificates.crt   (for cert validation if a
│                                          future variant adds egress;
│                                          unused in the canonical
│                                          symbol-index command)
├── /lib/                                (loader + musl libc)
└── /sys/fs/cgroup/                      (mountpoint, populated by
                                          raxis-verifier at boot)
```

Notably absent (deliberately):

- `bash`, additional shells beyond `/bin/sh`.
- Any language compilers or runtimes (`rustc`, `cargo`, `node`,
  `python3`, `go`, `gcc`, `clang`).
- Any package managers (`npm`, `cargo`, `pip`, `gem`).
- Network utilities (`curl`, `wget`, `ssh`, `nc`).
- Editors (`vi`, `nano`, `emacs`).
- LSP servers — symbol indexing uses parser-only `ctags`, not LSP
  (consistent with the Reviewer's exclusion in §4.1).
- `git` — the verifier reads from a fresh checkout the kernel mounts
  at `/workspace`; it does not invoke git.
- All daemons / background services.

**Canonical command.** The verifier's command is fixed by the kernel
(operators do not declare it):

```
/usr/local/bin/raxis-symbol-index --workspace /workspace --out /raxis/symbol_index.json
```

This is the command auto-injected by `raxis-cli plan prepare` per
`operator-ergonomics.md §4.2`. Operators who want a different
symbol-extraction command must (a) opt out of auto-injection
(`policy.toml [prepare] auto_inject_symbol_index = false`) and (b)
declare a custom verifier in their plan with their own image. The
canonical image accepts no command override — it is wired to the
`raxis-symbol-index` wrapper for predictability and audit clarity.

**Image digest.** The image's SHA-256 digest is **compiled into the
kernel binary** (`EXPECTED_SYMBOL_INDEX_VERIFIER_IMAGE_DIGEST`),
mirroring the Reviewer and Orchestrator manifests. The kernel
verifies the on-disk digest at every symbol-index verifier spawn and
refuses to boot the VM with `FAIL_CANONICAL_VERIFIER_IMAGE_DIGEST_MISMATCH`
on any mismatch (per `verifier-processes.md §14.4`). Unlike the
Executor starter image, the symbol-index image's digest is NOT
operator-pinnable — operators have no `[[vm_images]] oci_digest`
entry for it, because the alias `"raxis-verifier-symbol-index"` is
**reserved at policy load** (`FAIL_POLICY_RESERVED_VM_IMAGE_NAME` per
`verifier-processes.md §14.3` and `policy-plan-authority.md §3b`).
Plan-side references to the alias resolve to the kernel-bound
canonical image.

**Updates.** New symbol-index image versions ship with new RAXIS
releases. Operators have no per-deployment override path; the only
way to change the image is to upgrade the kernel binary (which
brings the new compiled-in digest with it). This matches the
Reviewer/Orchestrator pattern.

`raxis doctor canonical-images` covers the image per
`system-requirements.md §11.1`: presence (required when `[prepare]
auto_inject_symbol_index = true` AND any plan touches source files),
digest match against `EXPECTED_SYMBOL_INDEX_VERIFIER_IMAGE_DIGEST`,
content sanity (`raxis-verifier` PID 1, `ctags` resolves to
universal-ctags, no shells beyond `/bin/sh`, no language toolchains).
A digest mismatch surfaces as
`FAIL_CANONICAL_VERIFIER_IMAGE_DIGEST_MISMATCH` and halts further
symbol-index verifier spawns until resolved.

### 10.8 Tiered Language Starter Verifier Images (Pointer)

The four `raxis-verifier-{rust,node,python,go}-starter-<kernel_version>.img`
images bundled with the kernel release are NOT structural to any
invariant in this spec — they are operator-ergonomics conveniences
for the common case of `cargo test` / `npm test` / `pytest` /
`go test` verifiers. Their full content specification lives in
`verifier-processes.md §14.5`. The trust model for them is
**operator-pinned** (not kernel-canonical): the operator's policy
declares `[[vm_images]] oci_digest` for each starter they want to
use, and the kernel verifies the per-plan digest at every verifier
spawn (existing mechanism from §10.5 / §10.6, not a new invariant).
The `setup wizard` (per `operator-ergonomics.md §16.3` phase 6)
auto-populates these `[[vm_images]]` entries for any starter the
operator selects.

---

## §11 — Cross-Spec Impacts

This spec implies amendments and follow-up work in several adjacent
specs. Items already applied are marked ✅; items pending application
are marked ⏳; items deferred to post-V2-GA are marked 🔮.

### 11.1 Already Applied

- ✅ `v2-deep-spec.md §Part 7` — original *Integration & Harness Decisions*
  section now contains a pointer to this spec (per §11.2 below).
- ✅ `v2-deep-spec.md` Related Specifications table — `planner-harness.md`
  row added (per §11.2 below).
- ✅ `v2-deep-spec.md` In-VM capability table — egress rows split per
  unified-egress decision; bash row qualified for Executor/Orchestrator
  only.
- ✅ `kernel-mediated-egress.md` — marked DEPRECATED with redirect
  header (Unified Egress, §7).

### 11.2 Pending Application (Follow-up Amendments)

- ⏳ `v2-deep-spec.md §Step 24` (Reviewer Clone Provisioning) — amend
  to specify host-side worktree pre-population at `evaluation_sha` via
  the kernel's `gix` library before VM boot; the Reviewer VM contains
  no `git` binary and runs no `git` bootstrap inside the VM. The
  `/raxis/diff.patch` and `/raxis/log.txt` pre-computed artifacts are
  written here.
- ⏳ `kernel-mechanics-prompt.md` — amend the KSB schema to add the
  `verifier_witnesses` first-class field and the `BackgroundProcessExited`
  alert class. Adopt the rendering envelope and ordering from §9. The
  Reviewer's non-negotiable system prompt must state plainly that the
  Reviewer cannot run shell commands, cannot run tests, cannot run
  linters, that `verifier_witnesses` in the KSB is the authoritative
  source for code-running verification outcomes, and that
  `[ALERT: <ClassName>]` blocks are asynchronous FSM events that
  override the current line of reasoning.
- ⏳ `policy-plan-authority.md` — add `FAIL_REVIEWER_VM_IMAGE_NOT_ALLOWED`
  to the warning catalog (as a hard `FAIL_*`, not a warning, per §4.3).
  Add `WARN_REVIEWER_MISSING_SYMBOL_INDEX` and its strict-mode variant
  `FAIL_REVIEWER_MISSING_SYMBOL_INDEX` (per the symbol-index decision
  to be folded in here once finalized). Add
  `FAIL_DECLARED_ARTIFACT_MISSING` for runtime artifact verification.
- ✅ `policy-plan-authority.md §3b` + `§5 step 3.a/3.b` — admission
  pipeline rejects Reviewer-task `path_allowlist` with
  `FAIL_REVIEWER_PATH_ALLOWLIST_NOT_ALLOWED`; rejects Executor-task
  missing `path_allowlist` with `FAIL_PLAN_REQUIRES_EXPLICIT_PATH_ALLOWLIST`;
  rejects Executor-task `path_allowlist = []` without
  `# @raxis-explicit no-write-acknowledged` annotation with
  `FAIL_EXECUTOR_EMPTY_PATH_ALLOWLIST_UNACKNOWLEDGED`; rejects entries
  with glob characters / absolute paths / `..` with
  `FAIL_PATH_ALLOWLIST_INVALID_SYNTAX`. The Reviewer-side rejection is
  the structural enforcement of `INV-PLANNER-HARNESS-01`'s plan-side
  authoring corollary (§4.4).
- ✅ `operator-ergonomics.md §4.5` — explicit-required-fields surface
  for `path_allowlist`: `# @raxis-required` template injection,
  `# @raxis-explicit no-write-acknowledged` annotation taxonomy,
  CLI-local worktree directory suggestions via `git rev-parse
  --show-toplevel` or `--suggest-from <path>`, Reviewer-side hard
  refusal pre-signing per §4.5.5.
- ⏳ `system-requirements.md` — bump VM guest kernel requirement from
  Linux 5.10+ to Linux 5.14+ (host kernel can remain 5.10+). Add
  cgroup v2 + required controllers as image-conformance check items
  for `raxis doctor`.
- ⏳ `crates/types/src/operator_wire.rs` — Reviewer `PermissionPolicy`
  adds `Bash → Deny`, `LSP → Deny`, `WebFetch → Deny`, `WebSearch → Deny`,
  `StructuredOutput → Deny`. Kernel dispatch matrix rejects shell-execution
  intents from Reviewer sessions. `IntentKind::EgressRequest` removed
  entirely (per §7). `IntentKind::StructuredOutput` not added. New
  `bash bg_*` operations registered as harness-local tools (no
  `IntentKind` since they're in-VM, not kernel-mediated).
- ⏳ `raxis-planner` build configuration — Reviewer build target excludes
  `bash` claw-code module at link time. Reviewer's `grep_search` /
  `glob_search` use direct `execvp` (no `sh -lc` wrapper). One binary
  with runtime branching is rejected because shell code remains
  linked-in and reachable.
- ⏳ `policy.toml` `[[vm_images]]` — `role_restriction` field becomes
  load-bearing for Executor/Orchestrator images: a plan that points an
  Executor/Orchestrator task at an image whose `role_restriction` does
  not include the appropriate role is rejected at `approve_plan`. The
  Reviewer image is not registered in `[[vm_images]]` at all (it is
  kernel-internal); any `[[vm_images]]` entry with `role_restriction`
  including `Reviewer` is silently ignored for Reviewer activation.
- ⏳ `kernel-lifecycle.md` — amend session-end teardown to specify the
  bg-cgroup grace-period sweep described in §5.6.

### 11.3 New Specs (Status)

- ✅ [`specs/v2/verifier-processes.md`](verifier-processes.md) — V2
  unified verifier runtime: `raxis-verifier` PID-1 binary, single
  `WitnessSubmission` frame and `witness_records` schema (no V1/V2
  split), three authoring sources (policy claim-based gates,
  per-task plan verifiers, pre-`IntegrationMerge` plan verifiers),
  `on_failure` rules (`block_review` | `block_merge` | `warn_only`),
  the `artifact` mechanism, kernel-bundled verifier images
  (kernel-canonical `raxis-verifier-symbol-index` and four
  operator-pinned tiered language starters), audit events,
  `INV-VERIFIER-01..13`.
- ⏳ `specs/v2/symbol-index-schema.md` — JSON schema for the
  `symbol_index.json` artifact (field definitions, `schema_version`
  field, ctags-json mapping table). Now that the symbol-index
  auto-injection decision has landed (§4.1 amendment +
  `verifier-processes.md §14`), this schema spec is required so that
  the canonical `/usr/local/bin/raxis-symbol-index` wrapper output is
  contractually stable across kernel releases for the Reviewer's
  consumption side.

### 11.4 Deferred to V3 / Post-V2-GA

- 🔮 `Yield` / `PauseSession` intent — addresses the legitimate use
  case Sleep was trying to serve (waiting on external async events
  without burning microVM slots). Defers to V3 because the kernel-side
  resume-on-event mechanism is non-trivial. Canonical motivating example:
  an Executor triggers a GitHub Actions workflow via the GitHub API and
  needs the workflow result before continuing; with `Yield`/`PauseSession`
  the kernel suspends the VM (freeing the slot) and resumes it when the
  event arrives, injecting the CI result into the next KSB. Without this
  primitive, agents must either busy-poll (worse than `Sleep`) or
  structure all external-CI interactions as fire-and-forget with a
  separate follow-up task activation.

  **Why "non-trivial" — the six load-bearing problems:**

  1. **VM snapshot/restore is not free.** Suspending a microVM means
     serializing its entire memory state to disk — CPU registers, RAM
     pages, device emulation state, VSock device state — atomically
     while the VM is mid-execution. Firecracker has a snapshot API but
     the RAXIS kernel must orchestrate it: pause the VM cleanly, flush
     the VSock frame buffer, write the snapshot, update the session row
     in SQLite, all transactionally. On resume the sequence runs in
     reverse. Any crash between those steps leaves the session in an
     indeterminate state the existing recovery path does not handle.

  2. **A new event-registration subsystem inside the kernel.** The kernel
     currently has no concept of "I am waiting for an inbound signal
     addressed to session X." That requires a new registration table
     `(session_id, event_source, event_filter, timeout_at)`, an inbound
     routing layer that matches arriving events to registrations, and a
     wake-up path that restores the VM snapshot and resumes the session.
     How events are delivered to the kernel is itself an open V3 design
     question: (A) operator-mediated — operator tooling verifies external
     auth (e.g. GitHub HMAC-SHA256) and forwards the payload via the
     existing `OperatorTransport`; or (B) a new `InboundEventBus`
     extensibility trait. `OperatorTransport` in its current V2 form is
     the operator-authenticated IPC channel for synchronous operator
     commands — it is not an inbound event bus and must not be treated
     as one without an explicit V3 design decision.

  3. **The session FSM grows significantly.** Adding a `Yielded` state
     requires answering: What happens if the policy epoch advances while
     the session is suspended — does the admitted plan still satisfy
     current policy? What happens if the operator key is revoked during
     the yield window? What is the yield timeout — if the expected event
     never fires, when does the kernel transition to
     `YieldTimeout → Abandoned`? Can a session yield multiple times
     across its lifetime, and does the wall-clock TTL pause during yield
     or keep counting? Each answer is a new invariant with audit
     implications.

  4. **KSB assembly on resume.** The event payload must appear in the
     next Kernel State Block so the agent has context when it wakes up.
     The kernel must store the raw payload in SQLite while the session is
     suspended, the KSB assembler must be extended with a "resume
     context" block, and the planner binary must handle resuming
     mid-loop without re-executing its previous tool calls.

  5. **Audit paired writes.** `SessionYielded` is a paired-class event —
     every yield must be paired with exactly one `SessionResumed` or
     `SessionYieldTimeout`. These variants must be added to the
     `audit-paired-writes.md §4.1` classification table and the
     standalone `raxis-audit-verify` binary must understand them. Small
     in isolation, but the audit chain is the most invariant-sensitive
     surface in the kernel.

  6. **Durability across kernel restarts.** If the kernel crashes while
     sessions are yielded, on reboot it must find all `Yielded` sessions
     in SQLite, locate their VM snapshots on disk, and re-register their
     event registrations with the inbound delivery subsystem. Without
     this, a kernel restart silently drops every suspended session — an
     unacceptable data-loss failure mode for a system with cryptographic
     chain-of-custody guarantees.

  Net: it is not one hard problem — it is six medium problems that must
  all be correct simultaneously, touching the session FSM, audit chain,
  KSB assembler, policy epoch semantics, VM lifecycle, and an
  as-yet-unspecified inbound event delivery mechanism. That composition
  cost is why this is V3.
- 🔮 Multi-arch Reviewer image — RAXIS V2 ships single-arch (x86_64);
  arm64 Reviewer image follows in V3 once arm64 host support is
  prioritized.
- 🔮 Multi-arch symbol-index verifier image — same x86_64-only
  constraint as the Reviewer; arm64 follows in V3.

---

## §12 — Out of V2 Scope

Explicitly noted as out of scope so future amendments don't re-litigate:

- **Operator-customizable Reviewer images.** The Reviewer image is
  kernel-owned (`INV-PLANNER-HARNESS-02`). If an operator believes
  they need a different Reviewer environment, the path forward is a
  PR against the RAXIS distribution's canonical image, not a per-plan
  override. This is intentional friction.
- **Multiple Reviewer images per plan.** All Reviewers in all
  initiatives use the same kernel-bundled image. There is no "Reviewer
  image variant" mechanism. If a future need genuinely emerges (e.g.,
  Reviewers for plans in different security domains needing different
  pre-staged artifacts), the artifact mechanism (§8.3) handles the
  per-plan customization without changing the image.
- **In-VM agent-to-agent IPC.** No mechanism for two agent VMs to
  communicate directly. All inter-agent coordination is kernel-mediated
  via `git bundle` and `KernelPush`.
- **Hot-swap of harness modules.** The harness binary is fixed at VM
  boot; there is no runtime module loading (consistent with the
  exclusion of `hooks` and `worker_boot`).
- **Operator-defined alert classes.** The KSB alert taxonomy (§9) is
  fixed at the kernel layer; operators cannot inject custom alert
  classes. New alert classes require a kernel release.

---

## §13 — Invariants Index

Invariants introduced or strengthened by this spec:

| Invariant | Statement (one-line) | Section |
|---|---|---|
| `INV-PLANNER-HARNESS-01` | Reviewer Code Execution Prohibition: no shells, LSPs, compilers, runtimes, debuggers, REPLs, or wrappers thereof in the Reviewer's tool surface; three-layer enforcement (image, harness, kernel dispatch). Plan-side authoring corollary: any plan field whose semantics presuppose a capability the Reviewer lacks (`vm_image`, custom tools, `path_allowlist`) is structurally meaningless on a Reviewer task and is hard-rejected at admission, never silently stripped. | §4.4 (plus enumeration in the corollary block) |
| `INV-PLANNER-HARNESS-02` | Reviewer Image Is Kernel-Owned: no operator-supplied Reviewer image; kernel-bundled, kernel-digest-verified `raxis-reviewer-core`; `plan.toml` schema rejects `vm_image` on Reviewer tasks. | §4.5 |
| `INV-PLANNER-HARNESS-03` | In-VM Process Containment via cgroup v2: every shell command (sync or backgrounded) placed in a dedicated cgroup; teardown via `cgroup.kill`, not `/proc` walking or PGID-based signaling; survives POSIX double-fork daemonization. | §5.3 |
| `INV-PLANNER-HARNESS-04` | Reviewer Custom Tool Prohibition: profiles whose effective role is `Reviewer` MUST NOT declare any `[[profiles.<name>.custom_tool]]` blocks (directly or via inheritance). Plan admission rejects with `FAIL_REVIEWER_CUSTOM_TOOL_NOT_ALLOWED`. Canonical home `custom-tools.md §10`; mirrored here as §4.6. | §4.6 |
| `INV-PLANNER-HARNESS-05` | Canonical Orchestrator Image: the Orchestrator role boots from a kernel-bundled, kernel-digest-verified `raxis-orchestrator-core` image; operator-supplied images are categorically prohibited (parallel to the Reviewer pattern in `INV-PLANNER-HARNESS-02`). Runtime mismatch → `FAIL_ORCHESTRATOR_IMAGE_DIGEST_MISMATCH` + `SecurityViolationDetected`. | §4.7 |
| `INV-PLANNER-HARNESS-06` | Orchestrator Is Not Operator-Configurable: the Orchestrator's complete behavior surface is kernel-owned and version-locked with the kernel binary. `plan.toml` cannot declare an Orchestrator profile, an Orchestrator task, `inherits_from = "Orchestrator"`, custom tools for the Orchestrator, or NNSP overrides. Operator policy MAY tune three orthogonal knobs in `policy.toml [orchestrator]` (`provider_alias`, `max_token_budget_per_initiative`, `all_merges_require_approval`). | §4.8 |

These compose with adjacent invariants whose canonical homes are
elsewhere:

- `INV-VM-CAP-01..05` (`v2-deep-spec.md §Part 7`) — in-VM capability
  model, image policy, mount table.
- `INV-NETISO-01` (`vm-network-isolation.md`) — air-gapped VM model.
- `INV-CONVERGENCE-01..06` (`agent-disagreement.md`) — non-convergence
  bounds.
- `INV-DISPATCH` (Kernel dispatch matrix authoritative) — referenced
  throughout §3 and §4.4.
- `INV-VM-CAP-03` (operator-published image OCI digest pinning) — the
  Executor and Orchestrator path; `INV-PLANNER-HARNESS-02` is the
  Reviewer-specific exception.

---
## §14 — Implementation Plan

This section enumerates every crate, binary, source file, image artefact, and test surface required to ship the planner harness as specified in §3–§10. An implementer reading §14 alone (plus §3 for the role tool surface and §10 for image manifests) MUST have enough information to land V2 in their first pass without making architectural decisions.

> **Trait-boundary preconditions.** `raxis-planner` is the agent-side binary that boots inside an isolated VM via `IsolationBackend::spawn` (`extensibility-traits.md §3`) and operates on a `WorkspaceMount` provisioned by `DomainAdapter::provision_workspace` (`extensibility-traits.md §2`). `§14.2`–`§14.3` therefore assume the V2 trait extraction in `extensibility-traits.md §10` Phase A and Phase B has landed; the planner harness changes themselves are scheduled in Phase D's per-handler PR sequence.

### §14.1 Crate layout

V2 introduces three planner role binaries built from one shared workspace, plus two new image-build helpers. Final `raxis/Cargo.toml` `[workspace] members` additions:

> **Implementation status (minimum-bootable scaffold landed).** The
> three role binaries and `raxis-planner-core` exist in the workspace
> as of the current iteration:
>
> - `raxis/crates/planner-core/` — `Role` enum, `BootArgs`, `BootEnv`,
>   `BootContext`, `PlannerError` with structured exit codes,
>   `render_boot_log` (session-token-redacting). 21 unit tests pin
>   the argv contract, env contract, role-shortname mapping, and the
>   exact `binary_path()` strings the kernel session-spawn path stamps
>   into `VmSpec.entrypoint_argv`.
> - `raxis/crates/planner-orchestrator/` — `[bin] raxis-orchestrator`
>   at `/usr/local/bin/raxis-orchestrator`. Parses
>   `--initiative-id <ID>`, emits `step:"planner-boot"`, parks on
>   SIGTERM/SIGINT.
> - `raxis/crates/planner-executor/` — `[bin] raxis-executor` at
>   `/usr/local/bin/raxis-executor`. Parses `--task-id <ID>
>   --initiative-id <ID>`, emits `step:"planner-boot"`, parks on
>   SIGTERM/SIGINT.
> - `raxis/crates/planner-reviewer/` — `[bin] raxis-reviewer` at
>   `/usr/local/bin/raxis-reviewer`. Parses `--task-id <ID>
>   --initiative-id <ID>`, emits `step:"planner-boot"`, parks on
>   SIGTERM/SIGINT.
>
> What is **not** yet in this iteration (all deferred to subsequent
> milestones): `raxis-planner-tools`, `raxis-planner-reviewer-tools`,
> the `loop_engine` / `KsbRenderer` / `alert_pump` modules, the
> NNSP loader, the VSock control plane, the build-time feature mutex
> guard, and the `trybuild` / `ksb_golden` test fixtures. The current
> iteration deliberately ships the **wire shape only** (argv, env,
> exit codes, binary paths) so that the kernel session-spawn path has
> a real binary to hand control to inside the guest.

| Crate path                                     | Kind          | Status         | Purpose                                                                                                                                       |
| ---------------------------------------------- | ------------- | -------------- | --------------------------------------------------------------------------------------------------------------------------------------------- |
| `crates/raxis-planner-core/`                   | `[lib]`       | NEW            | Shared infrastructure: the claw-code execution loop, KSB renderer, alert pump, IPC framing on top of `IsolatedSession`, common tool registry. |
| `crates/raxis-planner-tools/`                  | `[lib]`       | NEW            | Concrete tool implementations: `read_file`, `write_file` (Executor-only), `edit_file`, `grep_search`, `glob_search`, `bash` (Executor + Orchestrator only), background-process bookkeeping (`bg_start`, `bg_status`, `bg_kill`). One implementation per tool; the role-specific subsetting happens at link time per §14.3. |
| `binaries/raxis-planner-executor/`             | `[bin]`       | NEW            | Executor role binary; depends on `raxis-planner-core` + `raxis-planner-tools` with feature `executor`. Runs PID 1 in the canonical Executor starter image (`§10.6`) or in an operator-pinned image (`INV-VM-CAP-03`). |
| `binaries/raxis-planner-reviewer/`             | `[bin]`       | NEW            | Reviewer role binary; depends on `raxis-planner-core` only (`raxis-planner-tools` is excluded entirely at link time per `INV-PLANNER-HARNESS-01`). Bundled into `raxis-reviewer-core` (`§10.5`). |
| `binaries/raxis-planner-orchestrator/`         | `[bin]`       | NEW            | Orchestrator role binary; depends on `raxis-planner-core` + `raxis-planner-tools` with feature `orchestrator` (which sets `bash`, `edit_file`, `grep_search`, `glob_search`, but NOT `write_file` — orchestrator manipulates files via `edit_file` and `git apply` per §4.7). Bundled into `raxis-orchestrator-core` (`§10.7`). |
| `crates/raxis-image-builder/`                  | `[bin]`       | NEW            | Reproducible builder for the kernel-canonical Reviewer image (`raxis-reviewer-core`), the kernel-canonical Orchestrator image (`raxis-orchestrator-core`), and the opt-in Executor starter (`raxis-executor-starter`). Output is an OCI image + an EROFS rootfs blob; signed with the kernel signing key per `system-requirements.md §11.2`. |
| `crates/raxis-image-manifest/`                 | `[lib]`       | NEW            | Typed `ImageManifest` struct + verifier (sha256 every file, recompute the bundle hash, signature-check). Used both by the kernel boot path (to admit a registered image) and by `cargo test` in CI to assert determinism of the canonical images. |

Cross-cutting compile-time guard: `crates/raxis-planner-core/build.rs` emits a `compile_error!` if both the `executor` and `reviewer` features are enabled simultaneously, so a misconfigured downstream crate cannot accidentally link Bash into a Reviewer binary. Tested by a `trybuild` UI test in `crates/raxis-planner-core/tests/role_features.rs`.

### §14.2 Files to create

`crates/raxis-planner-core/`:

- `crates/raxis-planner-core/Cargo.toml` — feature flags `executor`, `reviewer`, `orchestrator` (mutually exclusive; build.rs enforces this).
- `crates/raxis-planner-core/src/lib.rs` — public re-exports + the `PlannerHarness` trait.
- `crates/raxis-planner-core/src/loop_engine.rs` — the claw-code-style execution loop:
  - `pub async fn run<H: PlannerHarness>(harness: H, transport: Box<dyn IsolatedSession>) -> ExitCode`
  - Manages the `KernelPush → tool dispatch → IntentRequest` cycle, alert-class pre-emption, deterministic seed handling.
- `crates/ksb/src/lib.rs` — KSB rendering envelope per `kernel-mechanics-prompt.md §4`:
  - `pub struct KsbRenderer { template: KsbTemplate, sections: Vec<KsbSection> }`
  - `pub fn render(&self, frame: &KernelPush, history: &SessionHistory) -> String`
  - Renders sections in the canonical order (system prompt header → policy epoch banner → witness witnesses → alerts → conversation → cursor) defined in §9.
- `crates/raxis-planner-core/src/alert_pump.rs` — async alert-class FIFO + pre-emption logic:
  - Six alert classes from `§9` (`VsockSilent`, `BashCgroupKilled`, `BackgroundProcessExited`, `ToolBudgetExceeded`, `WallClockBudgetExceeded`, `PolicyEpochAdvanced`).
  - `pub fn drain_pending(&mut self) -> Vec<RenderedAlert>` returns alerts that MUST appear at the top of the next KSB.
- `crates/raxis-planner-core/src/transport.rs` — wraps the `IsolatedSession::push` / `recv_intent` traits from `extensibility-traits.md §3.3` with the planner-side framing (length-prefixed bincode `IpcMessage`).
- `crates/raxis-planner-core/src/system_prompt.rs` — loads the role-specific NNSP from a kernel-pinned bytes blob (`include_bytes!`) per `INV-PLANNER-HARNESS-06`.
- `crates/raxis-planner-core/src/role.rs` — `pub enum Role { Executor, Reviewer, Orchestrator }` + role-aware tool-registry construction (`pub fn tools_for(role: Role) -> ToolRegistry`).
- `crates/raxis-planner-core/build.rs` — feature-mutex guard described in §14.1.
- `crates/raxis-planner-core/tests/role_features.rs` — `trybuild` UI tests asserting `--features executor,reviewer` rejects compilation.
- `crates/raxis-planner-core/tests/ksb_golden.rs` — table-driven golden test: 24 recorded `(KernelPush, history) → expected KSB string` pairs, byte-equal compare, regenerated under `cargo test --features regen-golden`.

`crates/raxis-planner-tools/`:

- `crates/raxis-planner-tools/Cargo.toml` — features `bash`, `edit_file`, `grep_search`, `glob_search`, `read_file`, `write_file`. `executor` enables all of them; `orchestrator` enables `bash`, `edit_file`, `grep_search`, `glob_search`, `read_file` (no `write_file` — see §4.7); the `reviewer` role does NOT depend on this crate at all.
- `crates/raxis-planner-tools/src/lib.rs` — public `Tool` trait:
  - `trait Tool: Send + Sync { fn name(&self) -> &'static str; fn schema(&self) -> ToolSchema; async fn invoke(&self, args: ToolArgs, ctx: &ToolCtx) -> ToolResult; }`
- `crates/raxis-planner-tools/src/read_file.rs` — `read_file(path, offset, limit)` honoring path-allowlist semantics.
- `crates/raxis-planner-tools/src/write_file.rs` — `write_file(path, contents)` (Executor only); refuses paths outside the workspace mount root.
- `crates/raxis-planner-tools/src/edit_file.rs` — `edit_file(path, old, new, replace_all)`; rejects edits to files outside the workspace.
- `crates/raxis-planner-tools/src/grep_search.rs` — wrapper around `ripgrep` invoked via `execvp` (no shell). Uniformly available to Executor/Orchestrator.
- `crates/raxis-planner-tools/src/glob_search.rs` — wrapper around `globwalk`; no shell.
- `crates/raxis-planner-tools/src/bash/mod.rs` — synchronous `bash(cmd)` tool gated by `[cfg(feature = "bash")]`.
- `crates/raxis-planner-tools/src/bash/cgroup.rs` — `pub fn launch_in_cgroup(cmd: &str, cg_path: &Path) -> std::io::Result<Child>` per `INV-PLANNER-HARNESS-03`. Uses cgroup v2 `cgroup.threads`/`cgroup.procs` semantics; teardown via `echo 1 > cgroup.kill`.
- `crates/raxis-planner-tools/src/bash/bg.rs` — `bg_start`, `bg_status`, `bg_kill` tools per §5. Maintains `BgRegistry` keyed by `bg_id` (a UUIDv7); on session-end the harness invokes `BgRegistry::shutdown_all` which writes `1` into every bg-cgroup's `cgroup.kill` and waits up to `bg_grace_period_seconds` (default 5s) for processes to exit.
- `crates/raxis-planner-tools/tests/bash_cgroup.rs` — integration test using `tokio::process::Command` to spawn a child that double-forks; assert the cgroup teardown reaps the grandchild. (Skipped on macOS; cgroup v2 is Linux-only.)
- `crates/raxis-planner-tools/tests/edit_file_safety.rs` — fuzz test asserting `edit_file` rejects all path traversal attempts (`../`, absolute paths, symlinks pointing outside root).

Three planner binaries:

- `binaries/raxis-planner-executor/Cargo.toml`, `src/main.rs` — ~30 LoC: load NNSP, construct `Role::Executor` registry, call `raxis_planner_core::loop_engine::run`.
- `binaries/raxis-planner-reviewer/Cargo.toml`, `src/main.rs` — same shape but with `Role::Reviewer`. The dependency graph **excludes** `raxis-planner-tools` entirely; instead it depends on a much smaller `crates/raxis-planner-reviewer-tools/` crate that only provides `read_file`, `glob_search`, and `grep_search` (no `bash`, no `write_file`, no `edit_file` — Reviewer cannot mutate state per §4.4).
- `binaries/raxis-planner-orchestrator/Cargo.toml`, `src/main.rs` — same shape as Executor, with `Role::Orchestrator`.

`crates/raxis-planner-reviewer-tools/`:

- `crates/raxis-planner-reviewer-tools/Cargo.toml` — minimal: `read_file`, `grep_search`, `glob_search` only. No `bash`, no `edit_file`, no `write_file`. Compile-time guard via `#![forbid(unsafe_code)]` plus a `cargo deny` rule that bans transitive deps containing the `nix::sys::wait::waitpid` symbol (heuristic for forking).
- `crates/raxis-planner-reviewer-tools/src/lib.rs` — three tool impls + the `verifier_witnesses` consumer (the Reviewer's only authoritative source for code-running outcomes per §4.2).
- `crates/raxis-planner-reviewer-tools/tests/no_exec.rs` — runtime test that scans the linker output of `raxis-planner-reviewer` for the symbols `execve`, `execvp`, `posix_spawn`, `system`, `popen` and asserts none are present in any reachable code path. Uses `nm` + `cargo-call-stack` style analysis; if either tool is unavailable the test is skipped with a warning logged into the test report.

`crates/raxis-image-builder/`:

- `crates/raxis-image-builder/Cargo.toml` — depends on `raxis-image-manifest`, `oci-spec`, `tar`, `zstd`.
- `crates/raxis-image-builder/src/main.rs` — `raxis-image-builder build {reviewer|orchestrator|executor-starter}` — reads a manifest from `images/<role>/manifest.toml`, performs hermetic build (no network access; fails closed if attempted), produces:
  - `out/<role>.oci/` — OCI image directory
  - `out/<role>.erofs` — EROFS rootfs blob mounted into the VM
  - `out/<role>.manifest.json` — typed `ImageManifest` (per-file sha256 + bundle hash + signing-key fingerprint).
- `crates/raxis-image-builder/src/erofs.rs` — wraps `mkfs.erofs` invocations; pinned to the version in `images/<role>/manifest.toml [build] erofs_version`.
- `crates/raxis-image-builder/src/sign.rs` — Ed25519 signature over the manifest's bundle hash using the kernel signing key loaded from `RAXIS_IMAGE_SIGNING_KEY` env var (refuses to sign if the key file is not chmod-0600).
- `crates/raxis-image-builder/tests/determinism.rs` — runs the builder twice in parallel against the canonical Reviewer manifest and asserts byte-identical output (catches non-determinism in `mkfs.erofs`, tarball ordering, `SOURCE_DATE_EPOCH` propagation).
- `crates/raxis-image-builder/tests/manifest_signing.rs` — round-trip: sign → verify with the matching public key.

`crates/raxis-image-manifest/`:

- `crates/raxis-image-manifest/Cargo.toml` — no_std-compatible; the kernel boot path uses this in a hot-path admission check.
- `crates/raxis-image-manifest/src/lib.rs` — `pub struct ImageManifest { schema_version: u32, role: Role, bundle_hash: [u8;32], files: Vec<ManifestFile>, kernel_signing_key_fp: [u8;32], signature: [u8;64] }`.
- `crates/raxis-image-manifest/src/verify.rs` — `pub fn verify(manifest: &ImageManifest, expected_signing_key: &[u8;32]) -> Result<(), VerifyError>`.

### §14.3 Files to change

`raxis/Cargo.toml`:

- Add `binaries/raxis-planner-executor`, `binaries/raxis-planner-reviewer`, `binaries/raxis-planner-orchestrator`, `crates/raxis-planner-core`, `crates/raxis-planner-tools`, `crates/raxis-planner-reviewer-tools`, `crates/raxis-image-builder`, `crates/raxis-image-manifest` to `[workspace] members`.
- Workspace lints: add `[workspace.lints.rust] non_exhaustive_omitted_patterns = "warn"` for the role enum.

`raxis/kernel/Cargo.toml`:

- Add dependency `raxis-image-manifest = { path = "../crates/raxis-image-manifest" }` (used by the boot-time image-admission check).

`raxis/kernel/src/handlers/intent.rs`:

- The intent dispatch matrix (the role × intent-kind table referenced from `INV-DISPATCH`) gains explicit row-level rejection for the seven Reviewer-disallowed intents per §6:
  - `Reviewer + ProposedHandoff` → `FAIL_DISPATCH_DISALLOWED { reason: "ReviewerCannotHandoff" }`
  - `Reviewer + IntegrationMerge` → `FAIL_DISPATCH_DISALLOWED { reason: "ReviewerCannotMerge" }`
  - `Reviewer + EgressRequest` → unreachable (intent kind removed entirely from the wire schema; see `crates/raxis-types/src/intent.rs` change below).
  - `Reviewer + FetchRequest` → `FAIL_DISPATCH_DISALLOWED { reason: "ReviewerCannotFetch" }`
  - `Reviewer + InferenceRequest` with provider profile referencing `Bash` tool → `FAIL_DISPATCH_DISALLOWED { reason: "ReviewerCannotShell" }`.
- Three new dispatch rows for the bg_* tools (Executor + Orchestrator only; in-VM, no kernel mediation): added not as new `IntentKind` variants but as recognised harness-local tools in the per-role tool registry described in §14.2.

`raxis/kernel/src/handlers/session.rs`:

- `start_planner_session()` (or the equivalent function in the V2 refactor) now does:
  1. Resolves the role-appropriate image: kernel-canonical `raxis-reviewer-core` for Reviewer (refuses any operator-supplied image) and `raxis-orchestrator-core` for Orchestrator (same), per `INV-PLANNER-HARNESS-02` and `INV-PLANNER-HARNESS-05`. Executor uses operator-pinned image, falling back to `raxis-executor-starter` if the plan omitted `vm_image` and `policy.toml [prepare] starter_image_enabled = true`.
  2. Calls `kernel-image-admit` (new helper in `kernel/src/initiatives/image_admission.rs`) which loads the image manifest via `raxis_image_manifest::verify`, checks `policy.toml [vm_images]` admit list for Executor/Orchestrator images, and emits `ImageAdmitted { image_digest, role, signing_key_fp, manifest_schema }` to the audit chain.
  3. Calls `ctx.domain.provision_workspace(...)` per `extensibility-traits.md §2.2.A` to obtain a `WorkspaceMount`. Reviewer gets a read-only mount at `evaluation_sha`; Executor/Orchestrator get read-write mounts.
  4. Calls `ctx.isolation.spawn(image, workspace, vm_spec)` per `extensibility-traits.md §3.3` and stores the returned `Box<dyn IsolatedSession>` in `SessionRuntime`.

`raxis/kernel/src/initiatives/image_admission.rs` (NEW):

- `pub fn admit_image(role: Role, image_id: ImageId, policy: &PolicyBundle, audit: &dyn AuditSink) -> Result<AdmittedImage, ImageAdmissionError>` — see step 2 above.

`raxis/kernel/src/prompt/assembler.rs`:

- The role-specific NNSP loader gains a hard-coded `match role { Role::Reviewer => include_bytes!("../../prompts/reviewer.nnsp"), Role::Orchestrator => include_bytes!("../../prompts/orchestrator.nnsp"), Role::Executor => include_bytes!("../../prompts/executor.nnsp") }`. Operator policy is NOT consulted for Reviewer or Orchestrator (per `INV-PLANNER-HARNESS-06`).
- A unit test (`kernel/src/prompt/tests/nnsp_immutability.rs`) asserts the sha256 of each pinned NNSP matches the value in `kernel/prompts/digests.toml`. CI fails on any unintentional NNSP edit.

`raxis/kernel/prompts/`:

- New directory shipping `executor.nnsp`, `reviewer.nnsp`, `orchestrator.nnsp`, and `digests.toml`. The bytes are kernel-version-locked and changing them is a breaking-version event per `INV-PLANNER-HARNESS-06`.

`raxis/crates/types/src/intent.rs` (the canonical home of `IntentKind`):

- `enum IntentKind` — REMOVE the `EgressRequest` variant entirely (per §7 unified-egress); fetches go through the V2 unified `FetchRequest` path. Confirm no other spec carries forward an `EgressRequest` cross-reference (the `kernel-mediated-egress.md` file is already marked DEPRECATED per §11.1).

`raxis/crates/types/src/operator_wire.rs`:

- `enum PermissionPolicy` — `Reviewer` profile gains explicit `Bash → Deny`, `LSP → Deny`, `WebFetch → Deny`, `WebSearch → Deny`, `StructuredOutput → Deny`. (Per §11.2 follow-up amendment, now landed.)
- `struct VmImage` — `role_restriction: Vec<Role>` becomes mandatory on Executor and Orchestrator entries; admission of an Executor task pointing at an image whose `role_restriction` excludes `Role::Executor` returns `FAIL_VM_IMAGE_ROLE_RESTRICTION_VIOLATION`.

`raxis/crates/store/src/migration.rs`:

- New migration `0009_planner_session_role.sql` adds:
  ```sql
  ALTER TABLE sessions ADD COLUMN planner_role TEXT NOT NULL DEFAULT 'Executor'
      CHECK (planner_role IN ('Executor','Reviewer','Orchestrator'));
  ALTER TABLE sessions ADD COLUMN admitted_image_digest BLOB;
  ALTER TABLE sessions ADD COLUMN admitted_image_signing_key_fp BLOB;
  CREATE INDEX idx_sessions_role ON sessions(planner_role);
  ```
  Default `'Executor'` is correct for backfill: V1 had no other role.

`raxis/crates/audit/src/event.rs`:

- New variant `AuditEventKind::ImageAdmitted { role, image_digest, signing_key_fp, manifest_schema_version }`.
- New variant `AuditEventKind::ReviewerCustomToolRejected { plan_path, profile_name }` for plans declaring `[[profiles.<reviewer>.custom_tool]]` per `INV-PLANNER-HARNESS-04`.
- New variant `AuditEventKind::BgProcessHarvest { session_id, bg_id, exit_status, killed_by }` per §5.6 — emitted by `kernel/src/handlers/session.rs::end_session` after `BgRegistry::shutdown_all` returns.

`raxis/cli/src/commands/doctor.rs`:

- New checks per §14.7 below.

`raxis/specs/v1/planner-api.md`:

- Add a footnote to the §3 error-code table noting the V2 additions (`FAIL_REVIEWER_VM_IMAGE_NOT_ALLOWED`, `FAIL_VM_GUEST_KERNEL_TOO_OLD`, `FAIL_REVIEWER_CUSTOM_TOOL_NOT_ALLOWED`, `FAIL_VM_IMAGE_ROLE_RESTRICTION_VIOLATION`). The wire schema is not changed; the codes are added to the enum and surface through the existing rejection envelope.

### §14.4 Image-build pipeline

Three images live in-tree (built reproducibly by `crates/raxis-image-builder`):

| Image                      | Source dir                  | Manifest file                       | Trust boundary                         | Distribution                                            |
| -------------------------- | --------------------------- | ----------------------------------- | -------------------------------------- | ------------------------------------------------------- |
| `raxis-reviewer-core`      | `images/reviewer-core/`     | `images/reviewer-core/manifest.toml` | Kernel-bundled, kernel-signed; `INV-PLANNER-HARNESS-02` | Embedded into the kernel binary as `include_bytes!`     |
| `raxis-orchestrator-core`  | `images/orchestrator-core/` | `images/orchestrator-core/manifest.toml` | Kernel-bundled, kernel-signed; `INV-PLANNER-HARNESS-05` | Embedded into the kernel binary as `include_bytes!`     |
| `raxis-executor-starter`   | `images/executor-starter/`  | `images/executor-starter/manifest.toml`  | Kernel-bundled but **operator opt-in** | Distributed alongside the kernel binary; not embedded   |

Each `images/<role>/` directory contains:

- `manifest.toml` — pinned versions of every package, the EROFS version, and the `SOURCE_DATE_EPOCH` value used for reproducibility.
- `Containerfile` — the build recipe (BuildKit-style; no `latest` tags; every `RUN` ends with package-cache cleanup so the resulting layer is deterministic).
- `assets/` — any static configuration files (passwd, nsswitch, ldconfig caches) needed for offline boot.
- `verify.sh` — tooling-side smoke test the builder runs after image creation; checks that `/init`, `/usr/local/bin/raxis-planner-{role}`, and required tools are present and executable.

The Reviewer image manifest (canonical home `§10.5`) lists exactly:
- BusyBox 1.36 (no shell built-in usable from raxis-planner-reviewer per §4.4).
- The `raxis-planner-reviewer` binary at `/usr/local/bin/raxis-planner-reviewer`.
- An init wrapper at `/init` that mounts `/proc`, `/sys`, the workspace, then `execve`s the planner with no shell.
- No `bash`, no `sh`, no compilers, no `git`, no `node`, no `python`, no LSP servers (per §6).

The Orchestrator image manifest (canonical home `§10.7`) lists exactly:
- BusyBox 1.36 + `bash` 5.2 + `git` 2.45 + `ripgrep` 14.1.
- The `raxis-planner-orchestrator` binary at `/usr/local/bin/raxis-planner-orchestrator`.
- The same init wrapper.
- No compilers, no test runners, no LSP servers — Orchestrator does NOT run code; it only runs `git` and `ripgrep` per §4.7.

The Executor starter manifest (canonical home `§10.6`) lists a generalist development environment: Node, Python, Rust, Go, plus Unix base. Operators in production typically pin their own image; the starter is the new-operator-onboarding default.

Build-time CI:

- A new GitHub Actions workflow `.github/workflows/build-images.yml` runs `cargo run -p raxis-image-builder -- build {reviewer,orchestrator,executor-starter}` on every PR. Output `out/<role>.manifest.json` files are compared against the previous main-branch artefacts; non-determinism (different bundle hash for unchanged inputs) fails CI.
- A separate workflow `.github/workflows/release-sign-images.yml` runs only on tagged releases and uses the production kernel signing key (held in GitHub-managed-secrets-only) to sign the bundle hash.
- The matching **public** half of the kernel signing keypair is embedded in the kernel binary at `EXPECTED_KERNEL_SIGNING_KEY_BYTES` (`raxis-canonical-images`). Population is handled by `raxis/crates/canonical-images/build.rs`, which reads either `RAXIS_KERNEL_SIGNING_KEY_HEX` (64 lowercase hex chars) or `RAXIS_KERNEL_SIGNING_KEY_BYTES_PATH` (32-byte raw file) from the release pipeline and emits the constant into `$OUT_DIR/trust_anchor.rs`. Developer builds with neither variable set default to the all-zero placeholder; the boot-path verifier (`verify_canonical_image_via_manifest`) detects the placeholder and surfaces `CanonicalImageError::SigningKeyFpNotPopulated` so "I forgot to set the env var" is loud and obvious in production. Validation failure (length or hex-alphabet) is a hard `cargo build` error so a mistyped value never silently degrades to the placeholder branch. **The release pipeline owns the secret half** (HSM / GitHub Secrets); only the public half ever crosses the build-time trust boundary into the kernel binary.
- The same `build.rs` also emits the V1-fallback per-role image digests (`EXPECTED_REVIEWER_IMAGE_DIGEST`, `EXPECTED_ORCHESTRATOR_IMAGE_DIGEST`) from `RAXIS_EXPECTED_REVIEWER_IMAGE_DIGEST_HEX` and `RAXIS_EXPECTED_ORCHESTRATOR_IMAGE_DIGEST_HEX` respectively (each 64 lowercase hex chars). These are not consulted by the V2 boot path (the manifest is) but are surfaced by `verify_canonical_image_pinned`, by `raxis doctor` audits, and as the stable kind-tagged digest in `CanonicalImageKind::expected_digest()` audit payloads — populating them turns "all-zero placeholder" telemetry into real values without touching the V2 manifest-trust path.

> **End-to-end release-pipeline structure** for these env vars (the
> `release.yml` workflow, the GitHub-Secrets layout, the macOS
> notarization gate that lets the resulting kernel actually call
> `Virtualization.framework`, and the developer-facing local-build
> signing flow) is captured in
> [`release-and-distribution.md`](release-and-distribution.md). This
> section pins only the `build.rs` contract (which env vars exist,
> what they mean, what failure modes they surface); how those vars
> get populated is the release spec's concern.

Kernel boot-time admission:

- `kernel/src/main.rs` calls `raxis_image_manifest::verify(&embedded_reviewer_manifest, &kernel_signing_pubkey)?` and `verify(&embedded_orchestrator_manifest, ...)?` immediately after `IsolationBackend::verify_isolation_guarantee` (boot-order step 6a per `extensibility-traits.md §9.1`). A signature failure aborts boot with `BootError::ImageManifestSignatureMismatch { role }`.

### §14.4a Dev-host bake / stage / build pipeline (macOS-hermetic)

The production EROFS pipeline (§14.4) requires `mkfs.erofs`, which is
not available on macOS dev hosts (per `e2e-live-test-gap.md`). To
unblock local AVF demos and the realistic-scenario live-e2e harness,
`cargo xtask images` exposes a **three-step dev-host pipeline** that
emits the same signed-manifest shape but with
`image_format = RootfsInitramfsCpio` instead of `Erofs`. The kernel
boot path verifies both shapes via the same
`read_verified_image_format` helper, so dev-built images and
prod-built images cannot be confused at boot.

The three steps land separately so an operator can rebuild only the
layer that changed:

1. **`cargo xtask images bake-rootfs --role <ROLE> [--builder <B>]
   [--platform <PLAT>] [--keep]`** (`4860c1b`).
   Executes `images/<role>/Containerfile` against a container builder
   (auto-detect order `docker → podman → buildah`; override with
   `--builder`), exports the resulting OCI image's filesystem, and
   unpacks it into `images/<role>/rootfs/`. The Containerfile IS the
   source of truth for the rootfs content; this subcommand is what
   `images/README.md` calls "populates `rootfs/`". Without this step,
   the staging tree would contain only the cross-compiled planner
   binary — every `BashTool` invocation inside the executor VM would
   return ENOENT (iter-12's storm).

2. **`cargo xtask images dev-stage --role <ROLE> [--target <TRIPLE>]
   [--allow-stub]`** (`50537a5` fail-fast guard).
   Cross-compiles `raxis-planner-<role>` for the guest target and
   overlays it at `images/<role>-core/rootfs/init`. After the
   cross-compile lands, the **stub-detection guard** walks a
   per-role `required_os_binaries` allowlist and fails with a clear
   remediation hint if any are missing:

   | Role               | Required binaries                                  |
   | ------------------ | -------------------------------------------------- |
   | `ExecutorStarter`  | `bin/bash`, `usr/bin/python3`, `usr/bin/git`       |
   | `Orchestrator`     | — (intentionally binary-only per `INV-PLANNER-HARNESS-02`) |
   | `Reviewer`         | — (intentionally binary-only per `INV-PLANNER-HARNESS-02`) |

   The guard treats both regular files and symlinks-to-files as
   satisfied (real Linux rootfs trees use both:
   `/usr/bin/python3 → python3.11`). The escape hatch
   `--allow-stub` exists for intentional binary-only debug builds
   (e.g., the post-`8a26540` AVF demo path) but is forbidden for
   live-e2e runs because the iter-12 stub-rootfs regression is
   exactly the failure mode the guard catches.

3. **`cargo xtask images build-all [--role <ROLE>] [--install-dir
   <PATH>] [--no-auto-stage]`**.
   Walks `images/<role>-core/rootfs/`, packs it into cpio.gz via
   `raxis-initramfs-builder`, and calls `raxis-image-builder` to
   emit the signed manifest with `image_format =
   RootfsInitramfsCpio`. Drops:
   ```
   $RAXIS_INSTALL_DIR/images/raxis-<role>-core-<kver>.img
   $RAXIS_INSTALL_DIR/images/raxis-<role>-core-<kver>.manifest.toml
   ```

   Before packing each role, build-all runs the **stale-cache
   freshness check** (`INV-IMAGE-BAKE-NO-STALE-CACHE-01`): it
   compares the staged planner binary's mtime against the newest
   regular-file mtime under both `crates/planner-<role>/src/**`
   and `crates/planner-core/src/**`. If a source file is newer,
   build-all auto-invokes `dev-stage` for that role (emitting a
   structured `build_all_auto_stage_invoked` warn line with the
   exact file pair) and then proceeds with the freshly-staged
   binary. The `--no-auto-stage` flag flips this to fail-closed:
   build-all bails with `INV-IMAGE-BAKE-NO-STALE-CACHE-01
   VIOLATED` and the per-role `dev-stage` remediation command.
   This guard closes the iter53 reviewer-VM spawn failure shape
   (operator ran `dev-stage` for orchestrator + executor but not
   reviewer after a `planner-core` edit; build-all then packed
   the stale reviewer binary into a signed cpio.gz; the guest
   planner dropped into scaffold mode because its env-contract
   surface was behind the kernel's).

**Live-e2e auto-bake (`7fbd2e1`).** The `extended_e2e_*`
realistic-scenario harnesses call `require_canonical_images()` before
the kernel boots; if any required image is missing OR is detected as
a stub via the cpio-walk preflight (next bullet), the harness
automatically runs the three-step pipeline before proceeding. This
removes the manual `cargo xtask images …` step from the live-e2e
contributor workflow.

**Per-role required-binary cpio-walk preflight (`680ea62` +
`da6e8de`).** The live-e2e support code
(`kernel/tests/extended_e2e_support/cpio_inspect.rs` +
`kernel_driver::required_binaries_for_canonical_role`) walks the
resulting cpio.gz archive entries before the kernel mounts the image
and asserts a per-role required-binary list. The preflight runs every
time a live-e2e test calls `require_canonical_images`, so a stub
rootfs that slipped past the dev-stage guard (e.g., via
`--allow-stub`) is caught at test-harness layer rather than at
ENOENT-storm time inside the booted VM. Mismatches surface a
deterministic remediation hint pointing the developer at
`cargo xtask images bake-rootfs --role <ROLE>`.

**Path-shape divergence between the two preflights (see L-3 in
`known-latent-issues.md`).** The dev-stage guard runs against the
staging tree on the host filesystem and uses `Path::exists()`, which
follows symlinks; on a `usrmerge` tree (`bin -> usr/bin`) the staging
guard's `bin/bash` lookup resolves through the symlink. The cpio
walker is a literal `BTreeMap` lookup over the entry table the
initramfs producer emits, and the producer
(`raxis-initramfs-builder`) walks
`walkdir::WalkDir::follow_links(false)` to preserve symlink
semantics — the cpio archive encodes the usrmerge `bin` directory as
ONE `S_IFLNK` entry and never emits `bin/<file>` entries. The cpio
preflight therefore uses the **canonical post-usrmerge paths**
(`usr/bin/bash`, `usr/bin/python3`, `usr/bin/git`,
`usr/local/bin/raxis-executor`) where the dev-stage guard uses the
short staging-tree paths (`bin/bash`, `usr/bin/python3`,
`usr/bin/git`). The intentional divergence is recorded inline in
both call sites; unifying them by teaching the cpio walker to chase
`S_IFLNK` entries is deferred to the final-cleanup-sweep when a
non-usrmerge base image (e.g. an Alpine reviewer-core variant) makes
the divergence non-hypothetical.

**Why the dev-stage guard, the build-all freshness check, and the
cpio-walk preflight are all load-bearing.** The dev-stage guard
runs against the **staging tree** (post-bake, pre-cpio) and asserts
the Containerfile-promised OS binaries (`bin/bash`, `usr/bin/git`,
`usr/bin/python3` for executor-starter) are present. The build-all
freshness check (`INV-IMAGE-BAKE-NO-STALE-CACHE-01`, iter53) runs
against the **staged planner binary's mtime** (pre-cpio) and
asserts the binary is at least as new as the role's planner
source tree, auto-rebaking by default or failing closed under
`--no-auto-stage`. The cpio-walk preflight runs against the
**packed cpio.gz archive** (post-`build-all`) and asserts the
per-role required-binary list is present in the resulting image.
The three layers catch different regressions:

* dev-stage catches "the operator skipped `bake-rootfs`" (missing
  OS tooling in the staging tree).
* build-all freshness catches "the operator skipped `dev-stage`
  after a `planner-core` edit" (iter53 reviewer skew).
* cpio-walk catches "the operator ran `build-all` with a stale
  staging tree or `--allow-stub`" (post-pack invariant).

The dev-stage and cpio-walk preflights are fail-fast and not
overridable from inside a live-e2e run; the build-all freshness
guard fails closed only under `--no-auto-stage` and otherwise
auto-recovers via dev-stage, removing the manual remediation
step from the common case.

Normative pins: `raxis/xtask/src/images.rs` (the three subcommands),
`raxis/kernel/tests/extended_e2e_support/cpio_inspect.rs` (per-role
required-binary cpio walk), `raxis/kernel/tests/extended_e2e_support/
kernel_driver.rs::require_canonical_images` (auto-bake call site),
`raxis/images/executor-starter/Containerfile` (the source of truth
for executor-starter rootfs content; cross-arch + ca-certificates +
build-essential per L-2 in `known-latent-issues.md`).

### §14.5 Test fixtures and test-support helpers

`crates/test-support/src/planner_harness/` (NEW module):

- `mod.rs` — re-exports.
- `fake_planner.rs` — `pub struct FakePlanner { intents: VecDeque<IntentRequest>, expected_pushes: VecDeque<KernelPush> }` driven from a recorded session (`fixtures/planner-sessions/<test_name>.jsonl`). Used by kernel handler tests to replace a real `IsolatedSession` with a deterministic transcript player.
- `mock_workspace.rs` — `pub struct MockWorkspace { tmp: TempDir, files: HashMap<PathBuf, Vec<u8>> }` provides a workspace-mount-shaped tempdir for integration tests; on `drop` snapshots the final state for fixture comparison.
- `mock_isolation.rs` — re-exports `MockIsolation` from `crates/raxis-isolation/src/mock.rs` (per `extensibility-traits.md §3`); the test crate adds a higher-level builder `MockIsolationBuilder::with_planner(FakePlanner) -> Arc<MockIsolation>`.
- `image_fixtures.rs` — small, hermetic image manifests (single-file rootfs) used by image-admission tests; signed by a fixture signing key in `crates/test-support/data/test-signing-key.bin`.
- `ksb_fixture.rs` — tools to capture and replay `(KernelPush stream, expected response)` pairs.

`crates/test-support/data/planner-sessions/`:

- One `.jsonl` per scripted scenario: `executor_happy_path.jsonl`, `executor_circular_revision.jsonl`, `reviewer_blocks_merge.jsonl`, `orchestrator_resolves_conflict.jsonl`, `bg_double_fork_reaped.jsonl`, `policy_epoch_advance_alert.jsonl`, etc.

`crates/raxis-planner-core/tests/fixtures/ksb-golden/`:

- 24 KSB rendering golden files. File layout: `ksb-golden/<scenario>.input.json` + `ksb-golden/<scenario>.expected.txt`.

### §14.6 Integration tests

Per the level-of-detail benchmark from `raxis/specs/v1/cli-ceremony.md §4.3` (Integration Test Fixtures), every behavioural commitment in §3–§9 needs an integration test, and the spec MUST name the test file. The matrix:

| Test file (NEW)                                                                    | Asserts                                                                                                                                  | Spec section |
| ---------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------- | ------------ |
| `raxis/kernel/tests/planner_harness/role_dispatch_matrix.rs`                       | Each role × intent-kind cell rejects or admits per §3 (16 admit cases, 12 reject cases, all named by reject-code).                       | §3, §6       |
| `raxis/kernel/tests/planner_harness/reviewer_image_lockdown.rs`                    | A plan declaring `vm_image` on a Reviewer task is rejected at `approve_plan` with `FAIL_REVIEWER_VM_IMAGE_NOT_ALLOWED`.                   | §4.5         |
| `raxis/kernel/tests/planner_harness/orchestrator_immutable.rs`                     | A plan declaring `[[profiles.Orchestrator]]` or `[[plan.tasks.<orch_id>]]` is rejected with `FAIL_ORCHESTRATOR_PROFILE_NOT_ALLOWED`.       | §4.8         |
| `raxis/kernel/tests/planner_harness/reviewer_no_exec.rs`                           | The Reviewer binary contains no reachable `execve`/`posix_spawn`/`system`/`popen`/`fork` symbol; uses `nm` + `cargo-call-stack`.         | §4.4         |
| `raxis/kernel/tests/planner_harness/reviewer_custom_tool_rejected.rs`              | A plan declaring a Reviewer-effective profile with `[[profiles.<n>.custom_tool]]` is rejected with `FAIL_REVIEWER_CUSTOM_TOOL_NOT_ALLOWED`. | §4.6         |
| `raxis/kernel/tests/planner_harness/bg_lifecycle.rs`                               | Spawn a backgrounded shell command via `bg_start`; confirm `bg_status` reports running; trigger session-end; assert `BgProcessHarvest` audit event recorded with `killed_by = "session_end"`. | §5           |
| `raxis/kernel/tests/planner_harness/bg_double_fork_reaped.rs`                      | Spawn a backgrounded process that does POSIX double-fork; confirm cgroup teardown reaps the orphan grandchild within `bg_grace_period_seconds + 1s`.                                          | §5.3         |
| `raxis/kernel/tests/planner_harness/ksb_alert_pump.rs`                             | All six alert classes (`§9`) appear in deterministic order at the top of the next KSB after their triggering condition; alerts are not duplicated.                                            | §9           |
| `raxis/kernel/tests/planner_harness/policy_epoch_alert.rs`                         | A `PolicyEpochAdvanced` alert is delivered to active sessions on epoch rollover; a session that ignores it is killed at next intent admission with `FAIL_STALE_POLICY_EPOCH`.                | §9, `policy-epoch-diffing.md` |
| `raxis/kernel/tests/planner_harness/image_admission_signature.rs`                  | A tampered Reviewer image manifest causes kernel boot to fail with `BootError::ImageManifestSignatureMismatch { role: Role::Reviewer }`.                                                       | §10, §14.4   |
| `raxis/kernel/tests/planner_harness/image_role_restriction.rs`                     | An Executor task pointing at a `[[vm_images]]` entry whose `role_restriction = ["Reviewer"]` (which would never normally exist; constructed in test) is rejected with `FAIL_VM_IMAGE_ROLE_RESTRICTION_VIOLATION`. | §14.3        |
| `raxis/crates/raxis-image-builder/tests/determinism.rs`                            | Two parallel builds of the canonical Reviewer image produce byte-identical EROFS blobs.                                                  | §14.4        |
| `raxis/binaries/raxis-planner-executor/tests/full_session_smoke.rs`                | End-to-end against `MockIsolation`: 5-turn agent session emits all expected `IntentRequest`s, observes all expected `KernelPush`es; asserts no symbols from §6 exclusion list are reachable. | §3, §6       |
| `raxis/binaries/raxis-planner-orchestrator/tests/conflict_resolution_protocol.rs`  | The Orchestrator's pinned `[KERNEL: CONFLICT RESOLUTION PROTOCOL]` NNSP block fires on a synthesized merge conflict; the Orchestrator emits `IntegrationMerge` with the expected resolved tree sha within `wall_clock_limit_seconds`.                                                                               | §4.7, `integration-merge.md §8` |

All integration tests use `MockIsolation` + the `FakePlanner` harness so they run in CI without `/dev/kvm`. Real Firecracker tests live in `raxis/tests/e2e/firecracker_planner.rs` and run only on the `[ci-firecracker]` Linux runner.

### §14.7 `raxis doctor` checks specific to the planner harness

Per `system-requirements.md §11`, the doctor surfaces image-admission state. New checks added to `raxis/cli/src/commands/doctor.rs`:

- `[CHECK] planner-harness.image.reviewer` — confirms the embedded Reviewer manifest's `bundle_hash` matches the live binary; `[FAIL]` on tamper.
- `[CHECK] planner-harness.image.orchestrator` — same for the Orchestrator manifest.
- `[CHECK] planner-harness.image.executor-starter` — `[INFO]` (not a hard fail) reporting whether the optional starter image is installed.
- `[CHECK] planner-harness.guest-kernel` — for the candidate Executor image (if pinned), confirms guest kernel version is ≥ 5.14 per `INV-PLANNER-HARNESS-03`.
- `[CHECK] planner-harness.cgroup-v2` — host capability check for cgroup v2 with `cpu`, `memory`, and `pids` controllers.

Each check has a short `--explain` text linking back to `planner-harness.md §<section>` and the relevant invariant.

### §14.8 Phased migration

The work lands in five mergeable phases; each phase is a single PR.

- **Phase 1 — Trait wiring (depends on `extensibility-traits.md §10` Phase A + B).** Add `Role` enum, `IsolatedSession`/`DomainAdapter` plumbing into `kernel/src/handlers/session.rs`. No image-build changes; canonical Reviewer/Orchestrator images replaced by zero-byte placeholders. Existing planner code compiles unchanged but now boots through the trait. ~3 days.
- **Phase 2 — `raxis-planner-core` extraction.** Move the existing planner loop into `crates/raxis-planner-core/`. Existing `kernel/src/planner/*` is deleted in this PR. Featureless single-binary `raxis-planner-executor` produced; Reviewer + Orchestrator binaries land but are bit-for-bit copies of Executor (role-asymmetry comes in Phase 3). ~3 days.
- **Phase 3 — Reviewer feature-cut + custom-tool rejection.** Land `crates/raxis-planner-reviewer-tools/`, the `executor`/`reviewer`/`orchestrator` mutex feature flags, and the `nm`-based no-exec test. `INV-PLANNER-HARNESS-04` admission rejection for Reviewer custom tools lands here. ~2 days.
- **Phase 4 — Backgrounded shell + KSB alert pump.** Land `bash::bg`, the `BgRegistry`, the cgroup teardown, and all six `§9` alert classes. ~3 days.
- **Phase 5 — Image build + signing pipeline.** Land `crates/raxis-image-builder/`, the canonical Reviewer + Orchestrator + opt-in Executor starter images, the `[CHECK] planner-harness.image.*` doctor checks, the kernel boot-time signature-verification step, and the CI workflows. After this PR, kernel boot refuses unsigned/tampered images. ~4 days.

Total budget: ~15 engineer-days. Each phase ships independently; the kernel binary keeps compiling and the existing test suite keeps passing through every intermediate state.

---

*Spec complete. Per the standing rule for `INV-PLANNER-HARNESS-*`: when
this file is wrong (i.e., when an implementation choice contradicts a
statement here), the implementation MUST be amended to conform OR a
follow-up amendment to this spec MUST land in the same PR. Silent
divergence between code and this spec is a process failure.*
